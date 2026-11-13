"""The Ansible workspace: the playbooks, inventory, files/ and ansible.cfg that ulmo owns.

They live as plain files under WORKSPACE_DIR (ansible needs real files: `{{ playbook_dir }}/../files/x`,
ansible.cfg, binaries), edited and uploaded through the Files page. There is no git here; the one-time
import from a git repo is in git_import.py.

Rules every write follows, under one lock:
  * the whole workspace is read-only while a playbook run is active (begin_run/end_run, called by the
    runner), so a run never sees files change under it, and a write and a run start never interleave;
  * a path is a relative path of real directories and files: no "..", no ".git", no symlinks;
  * an edit carries the version (a digest) of the file it started from, and is refused if the file
    changed since, so two tabs or an upload cannot silently overwrite each other;
  * the old contents are kept as a saved copy (WORKSPACE_HISTORY_DIR, one folder per file) for Restore;
  * the new contents are written to a temp file, fsynced, then swapped in, so a crash leaves the old or
    the new file, never half of one.

After a change the tag cache, host cache and (for requirements.yaml) collections are refreshed in a
background thread, coalescing bursts into one pass.
"""
import hashlib
import io
import logging
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

import yaml

from app.config import COLLECTIONS_DIR, LEGACY_REPO_DIR, WORKSPACE_DIR, WORKSPACE_HISTORY_DIR
from app.services import fileio, inventory, playbook_tags, settings_store

logger = logging.getLogger("ulmo.workspace")

SKIP_PLAYBOOK_DIRS = {"old", ".git"}
EXCLUDE_FILES = {"requirements.yaml", "requirements.yml"}
MAX_EDIT_BYTES = 1024 * 1024  # bigger or non-text files are upload/download only
MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_ZIP_ENTRIES = 5000
MAX_ZIP_BYTES = 200 * 1024 * 1024
TMP_PREFIX = ".ulmo-"
VERSION_RE = re.compile(r"^\d{8}T\d{12}Z$")

LOCK = threading.RLock()  # held by anything that must check the lock and then act on the workspace as one step
_active_runs: dict[int, str] = {}  # run id -> playbook, while it runs
_listeners: list = []


class Locked(ValueError):
    """A playbook run is active, so the workspace is read-only."""


class Conflict(ValueError):
    """The file changed since the version the caller started from."""


# --- the run lock ---------------------------------------------------------------------------------


def begin_run(run_id: int, playbook: str = "") -> None:
    """Mark a run active. Call with LOCK held, in the same step that checks the playbook exists."""
    with LOCK:
        _active_runs[run_id] = playbook


def end_run(run_id: int) -> None:
    with LOCK:
        _active_runs.pop(run_id, None)


def active_runs() -> list[dict]:
    with LOCK:
        return [{"run_id": rid, "playbook": pb} for rid, pb in sorted(_active_runs.items())]


def require_unlocked() -> None:
    with LOCK:
        if _active_runs:
            first = min(_active_runs)
            more = f" (and {len(_active_runs) - 1} more)" if len(_active_runs) > 1 else ""
            raise Locked(f"Run #{first}{more} is in progress, so the files can't be changed until it finishes.")


def on_listing_change(callback) -> None:
    """Call `callback()` after a file is created or deleted (the playbook list may have changed)."""
    if callback not in _listeners:
        _listeners.append(callback)


# --- paths ------------------------------------------------------------------------------------------


def clean(rel: str) -> str:
    """A normalised workspace-relative path, or ValueError."""
    rel = (rel or "").replace("\\", "/").strip().strip("/")
    if not rel:
        raise ValueError("Give a file path.")
    if "\0" in rel or len(rel) > 300:
        raise ValueError("That path is not valid.")
    parts = rel.split("/")
    for part in parts:
        if part in ("", ".", "..") or part == ".git" or part.startswith(TMP_PREFIX):
            raise ValueError(f"That path is not allowed: {rel!r}")
    return "/".join(parts)


def _path(rel: str) -> tuple[str, Path]:
    rel = clean(rel)
    cur = WORKSPACE_DIR
    for part in rel.split("/"):
        cur = cur / part
        if cur.is_symlink():
            raise ValueError("Symlinks are not allowed in the workspace.")
    return rel, cur


def resolve_within(rel: str) -> Path | None:
    """For a configured setting (inventory path, requirements path): the path if it stays inside
    the workspace, else None. "." is the root."""
    root = WORKSPACE_DIR.resolve()
    resolved = (WORKSPACE_DIR / rel).resolve() if rel != "." else root
    if resolved != root and root not in resolved.parents:
        return None
    return resolved


version_of = fileio.digest


def _is_text(data: bytes) -> bool:
    if b"\0" in data:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


# --- reading ----------------------------------------------------------------------------------------


def _iter_files():
    if not WORKSPACE_DIR.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(WORKSPACE_DIR):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d != ".git")  # os.walk does not follow symlinked folders
        for name in sorted(filenames):
            path = here / name
            if name.startswith(TMP_PREFIX) or path.is_symlink():
                continue
            yield {"rel_path": path.relative_to(WORKSPACE_DIR).as_posix(), "name": name, "size": path.stat().st_size}


def list_files() -> list[dict]:
    return sorted(_iter_files(), key=lambda f: f["rel_path"])


def has_files() -> bool:
    return next(_iter_files(), None) is not None


def read_file(rel: str) -> dict:
    """{rel_path, size, version, text}. text is None for a binary or very large file."""
    rel, path = _path(rel)
    if not path.is_file():
        raise ValueError("That file doesn't exist.")
    data = path.read_bytes()
    text = data.decode("utf-8") if len(data) <= MAX_EDIT_BYTES and _is_text(data) else None
    return {"rel_path": rel, "size": len(data), "version": version_of(data), "text": text}


def file_bytes(rel: str) -> bytes:
    rel, path = _path(rel)
    if not path.is_file():
        raise ValueError("That file doesn't exist.")
    return path.read_bytes()


def list_playbooks() -> list[dict]:
    subdir = settings_store.get("playbooks_subdir").strip("/") or "."
    base = resolve_within(subdir)
    if base is None or not base.is_dir():
        return []
    root = WORKSPACE_DIR.resolve()
    playbooks = []
    for path in sorted(base.glob("*.yaml")) + sorted(base.glob("*.yml")):
        if path.name in EXCLUDE_FILES or path.is_symlink() or not path.is_file():
            continue
        if any(part in SKIP_PLAYBOOK_DIRS for part in path.relative_to(root).parts):
            continue
        playbooks.append({"name": path.name, "rel_path": str(path.relative_to(root))})
    return playbooks


def read_playbook(rel_path: str) -> str:
    """Raw content of a playbook, for display. Only paths list_playbooks() itself would surface, the
    same allowlist a run request is checked against."""
    if rel_path not in {p["rel_path"] for p in list_playbooks()}:
        raise ValueError("Unknown playbook.")
    return (WORKSPACE_DIR / rel_path).read_text(errors="replace")


# --- saved copies -----------------------------------------------------------------------------------


def _history_dir(rel: str) -> Path:
    # Named by a hash of the path: a path of up to 300 characters, percent-encoded, would not fit in
    # a 255-byte file name. The PATH file inside says which file the folder belongs to.
    return WORKSPACE_HISTORY_DIR / hashlib.sha256(rel.encode()).hexdigest()[:32]


def _history_keep() -> int:
    try:
        return max(1, int(settings_store.get("workspace_history_keep")))
    except ValueError:
        return 20


def _copies(folder: Path) -> list[Path]:
    return [p for p in folder.iterdir() if VERSION_RE.match(p.name)]


def _keep_copy(rel: str, data: bytes) -> None:
    folder = _history_dir(rel)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "PATH").write_text(rel)
    (folder / fileio.stamp()).write_bytes(data)
    fileio.keep_newest(_copies(folder), _history_keep())


def list_versions(rel: str) -> list[dict]:
    """Saved copies of one file, newest first: {id, at, size}."""
    rel = clean(rel)
    folder = _history_dir(rel)
    if not folder.is_dir():
        return []
    out = []
    for p in sorted(_copies(folder), reverse=True):
        out.append({"id": p.name, "at": datetime.strptime(p.name, "%Y%m%dT%H%M%S%fZ").replace(tzinfo=timezone.utc), "size": p.stat().st_size})
    return out


def version_bytes(rel: str, version_id: str) -> bytes:
    rel = clean(rel)
    if not VERSION_RE.match(version_id or ""):
        raise ValueError("Unknown saved copy.")
    path = _history_dir(rel) / version_id
    if not path.is_file():
        raise ValueError("Unknown saved copy.")
    return path.read_bytes()


def restore(rel: str, version_id: str, base: str | None) -> str:
    """Put a saved copy back as the current contents (the current ones become a saved copy)."""
    return store(rel, version_bytes(rel, version_id), base)


def deleted_files() -> list[str]:
    """Paths that have saved copies but no current file."""
    if not WORKSPACE_HISTORY_DIR.is_dir():
        return []
    out = []
    for d in WORKSPACE_HISTORY_DIR.iterdir():
        try:
            rel = (d / "PATH").read_text()
            _, path = _path(rel)
        except (OSError, ValueError):
            continue
        if not path.exists() and _copies(d):
            out.append(rel)
    return sorted(out)


# --- writing ----------------------------------------------------------------------------------------


def _check_base(rel: str, path: Path, base: str | None) -> bytes | None:
    """The current bytes (None if absent), after checking them against `base`: None = do not
    check, "" = the file must not exist yet, else the version the caller started from."""
    if path.exists() and not path.is_file():
        raise ValueError(f"{rel} is a folder.")
    old = path.read_bytes() if path.is_file() else None
    if base is not None:
        if base == "" and old is not None:
            raise Conflict(f"{rel} already exists.")
        if base != "" and (old is None or version_of(old) != base):
            raise Conflict(f"{rel} changed since you opened it.")
    return old


def _store_one(rel: str, data: bytes, base: str | None, mode: int | None = None) -> str:
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"{rel} is over {MAX_FILE_BYTES // (1024 * 1024)} MB.")
    rel, path = _path(rel)
    old = _check_base(rel, path, base)
    if old == data:
        return version_of(data)
    if old is not None:
        _keep_copy(rel, old)
    if mode is None:  # an edit keeps the file's mode (a script stays executable); a new file is 0644
        mode = stat.S_IMODE(path.stat().st_mode) if old is not None else 0o644
    try:
        fileio.write_atomic(path, data, mode, tmp_prefix=TMP_PREFIX)
    except (NotADirectoryError, FileExistsError) as exc:
        raise ValueError(f"{rel}: a part of that path is already a file.") from exc
    return version_of(data)


def store(rel: str, data: bytes, base: str | None = None) -> str:
    """Write one file. Returns its new version. Raises Locked, Conflict or ValueError."""
    with LOCK:
        require_unlocked()
        new = _check_exists_before(rel)
        version = _store_one(rel, data, base)
    _after_change([clean(rel)], listing_changed=new)
    return version


def _check_exists_before(rel: str) -> bool:
    """True if this path does not exist yet (the write creates it)."""
    _, path = _path(rel)
    return not path.exists()


def _check_collisions(rels: list[str]) -> None:
    """Refuse an upload where one path needs another to be a folder, whether the other is in the
    same upload or already in the workspace, so it fails before anything is written."""
    paths = set(rels)
    for rel in rels:
        parts = rel.split("/")
        for i in range(1, len(parts)):
            parent = "/".join(parts[:i])
            if parent in paths or (WORKSPACE_DIR / parent).exists() and not (WORKSPACE_DIR / parent).is_dir():
                raise ValueError(f"{parent} is a file, so {rel} can't go inside it.")


def store_many(items: list[tuple]) -> list[str]:
    """Write several files as one change. Items are (path, bytes) or (path, bytes, mode). Every path,
    size and collision is checked before the first write. If a write still fails part-way, what was
    written is refreshed like any other change."""
    written: list[tuple[str, bool]] = []
    try:
        with LOCK:
            require_unlocked()
            checked = []
            for rel, data, *rest in items:
                rel, path = _path(rel)
                if len(data) > MAX_FILE_BYTES:
                    raise ValueError(f"{rel} is over {MAX_FILE_BYTES // (1024 * 1024)} MB.")
                if path.exists() and not path.is_file():
                    raise ValueError(f"{rel} is a folder.")
                checked.append((rel, data, rest[0] if rest else None, not path.exists()))
            _check_collisions([c[0] for c in checked])
            for rel, data, mode, new in checked:
                _store_one(rel, data, None, mode)
                written.append((rel, new))
    finally:
        if written:
            _after_change([rel for rel, _ in written], listing_changed=any(new for _, new in written))
    return [rel for rel, _ in written]


def delete(rel: str, base: str | None) -> None:
    with LOCK:
        require_unlocked()
        rel, path = _path(rel)
        if not path.is_file():
            raise ValueError("That file doesn't exist.")
        old = _check_base(rel, path, base if base is not None else version_of(path.read_bytes()))
        _keep_copy(rel, old)
        path.unlink()
        parent = path.parent
        while parent != WORKSPACE_DIR and parent.is_dir() and not any(parent.iterdir()):
            parent.rmdir()
            parent = parent.parent
    _after_change([rel], listing_changed=True)


def unpack_zip(data: bytes, into: str = "") -> list[str]:
    """Extract a zip into the workspace (under folder `into`, if given). All-or-nothing on validation:
    a bad entry (escaping path, symlink, oversize) rejects the whole archive. Mac junk is skipped."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ValueError("That is not a valid zip file.") from exc
    prefix = clean(into) + "/" if into.strip().strip("/") else ""
    items: list[tuple[str, bytes, int | None]] = []
    total = 0
    with zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > MAX_ZIP_ENTRIES:
            raise ValueError(f"The zip has more than {MAX_ZIP_ENTRIES} files.")
        for info in infos:
            name = info.filename.replace("\\", "/")
            if name.split("/")[0] == "__MACOSX" or name.rsplit("/", 1)[-1] == ".DS_Store":
                continue
            if stat.S_ISLNK(info.external_attr >> 16):
                raise ValueError(f"{info.filename} is a symlink, which the workspace does not allow.")
            try:
                with zf.open(info) as f:
                    body = f.read(MAX_FILE_BYTES + 1)
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError, zlib.error) as exc:
                # a password, a damaged member or a compression method Python lacks
                raise ValueError(f"{info.filename} can't be read from the zip: {exc}") from exc
            total += len(body)
            if total > MAX_ZIP_BYTES:
                raise ValueError(f"The zip unpacks to more than {MAX_ZIP_BYTES // (1024 * 1024)} MB.")
            perm = info.external_attr >> 16  # unix mode from the zip, 0 when it came from Windows
            mode = (0o755 if perm & 0o111 else 0o644) if perm else None
            items.append((prefix + info.filename, body, mode))  # store_many() checks every path before writing any
    if not items:
        raise ValueError("The zip has no files in it.")
    return store_many(items)


def export_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in list_files():
            path = WORKSPACE_DIR / f["rel_path"]
            info = zipfile.ZipInfo(f["rel_path"], date_time=datetime.fromtimestamp(path.stat().st_mtime).timetuple()[:6])
            info.external_attr = (stat.S_IMODE(path.stat().st_mode) | stat.S_IFREG) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, path.read_bytes())
    return buf.getvalue()


# --- replacing everything (git import, startup migration) -----------------------------------------


def copy_tree(src: Path, dest: Path) -> int:
    """Copy regular files from src to dest, skipping .git and anything that is not a regular file
    (symlinks are never followed: an imported repo must not pull in files from elsewhere on disk)."""
    count = 0
    for dirpath, dirnames, filenames in os.walk(src):
        here = Path(dirpath)
        dirnames[:] = [d for d in dirnames if d != ".git"]  # os.walk does not follow symlinked folders
        for name in filenames:
            path = here / name
            if path.is_symlink() or not path.is_file() or name.startswith(TMP_PREFIX):
                continue
            target = dest / path.relative_to(src)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            count += 1
    return count


def replace_from(src: Path) -> int:
    """Make the workspace a copy of `src`. The old workspace is kept next to it as
    ansible.before-import-<time> (the newest two are kept). Each call stages in its own folder, so two
    at once cannot trample each other."""
    WORKSPACE_DIR.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="ansible.incoming-", dir=WORKSPACE_DIR.parent))
    try:
        count = copy_tree(src, staging)
        if not count:
            raise ValueError("There were no files to import.")
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    backup = None
    with LOCK:
        try:
            require_unlocked()
            if WORKSPACE_DIR.exists():
                backup = WORKSPACE_DIR.parent / f"ansible.before-import-{fileio.stamp()}"
                os.rename(WORKSPACE_DIR, backup)
            os.rename(staging, WORKSPACE_DIR)
        except BaseException:
            if backup is not None and not WORKSPACE_DIR.exists():
                os.rename(backup, WORKSPACE_DIR)  # the swap failed half-way: put the old files back
            shutil.rmtree(staging, ignore_errors=True)
            raise
    for stale in sorted(WORKSPACE_DIR.parent.glob("ansible.before-import-*"))[:-2]:
        shutil.rmtree(stale, ignore_errors=True)
    _after_change([], listing_changed=True, install=True)
    return count


def migrate_legacy_repo() -> bool:
    """At startup: if this install still has a git checkout in ./data/repo and no workspace yet, copy
    its files across (without .git). The checkout is left in place; it is no longer used. The copy is
    staged and renamed into place, so a restart mid-copy leaves no workspace (and the next start tries
    again) rather than a half-filled one that would never be retried."""
    if WORKSPACE_DIR.exists() or not LEGACY_REPO_DIR.is_dir():
        return False
    try:
        count = replace_from(LEGACY_REPO_DIR)
    except (OSError, ValueError) as exc:
        logger.error("Could not copy the old git checkout %s into %s: %s", LEGACY_REPO_DIR, WORKSPACE_DIR, exc)
        return False
    logger.info("Copied %d files from the old git checkout %s into %s", count, LEGACY_REPO_DIR, WORKSPACE_DIR)
    return True


def clean_leftovers() -> None:
    """At startup nothing is importing, so staging and clone folders a killed import or migration left
    behind can go."""
    for pattern in ("ansible.incoming-*", "ansible-import-*"):
        for stale in WORKSPACE_DIR.parent.glob(pattern):
            shutil.rmtree(stale, ignore_errors=True)


# --- YAML check -------------------------------------------------------------------------------------


class _AnsibleLoader(yaml.SafeLoader):
    """Safe YAML that also accepts Ansible's own tags (!vault, !unsafe): they are not errors."""


_AnsibleLoader.add_multi_constructor("!", lambda loader, suffix, node: None)


def check_syntax(rel: str, text: str) -> str | None:
    """A warning if a .yaml/.yml file does not parse, else None. A save is never blocked by it: a
    half-finished edit is normal, but the next run or inventory read would fail with a worse message."""
    if not rel.lower().endswith((".yaml", ".yml")):
        return None
    try:
        list(yaml.load_all(text, Loader=_AnsibleLoader))
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}" if mark else ""
        return f"{rel} is not valid YAML{where}: {getattr(exc, 'problem', None) or exc}"
    return None


# --- after a change ---------------------------------------------------------------------------------

_refresh_lock = threading.Lock()
_refresh = {"running": False, "again": False, "install": False}


def _find_requirements_file() -> Path | str | None:
    """Locate requirements.yaml. A Path if found, a warning string if the configured requirements_path
    is invalid, None if unconfigured and nothing was found."""
    configured = settings_store.get("requirements_path").strip("/")
    if configured:
        path = resolve_within(configured)
        if path is None:
            return f"WARNING: requirements_path '{configured}' resolves outside the workspace; skipping collection install."
        if not path.is_file():
            return f"WARNING: requirements_path '{configured}' does not exist or is not a file; skipping collection install."
        return path

    subdir = settings_store.get("playbooks_subdir").strip("/") or "."
    subdir_path = resolve_within(subdir)
    if subdir_path is None:
        return "WARNING: playbooks_subdir resolves outside the workspace; skipping collection install at that path."
    candidates = [
        WORKSPACE_DIR / "requirements.yaml",
        WORKSPACE_DIR / "requirements.yml",
        subdir_path / "requirements.yaml",
        subdir_path / "requirements.yml",
    ]
    return next((p for p in candidates if p.is_file()), None)


def install_collections() -> str | None:
    """Install collections from requirements.yaml, if any. Best effort: returns the output or a
    warning rather than raising."""
    req_file = _find_requirements_file()
    if req_file is None:
        return None
    if isinstance(req_file, str):
        return req_file
    COLLECTIONS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            ["ansible-galaxy", "collection", "install", "-r", str(req_file), "-p", str(COLLECTIONS_DIR)],
            cwd=WORKSPACE_DIR, capture_output=True, text=True, timeout=300,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return f"WARNING: collection install from {req_file.name} failed:\n{exc}"
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    if result.returncode != 0:
        return f"WARNING: collection install from {req_file.name} failed:\n{output}"
    return output


def refresh_derived(install: bool = False) -> list[str]:
    """Recompute the slow things derived from the files (collections, playbook tags). Returns
    warnings/log lines. The host list is not here: it is recomputed on next use, after invalidation."""
    lines = []
    if install:
        out = install_collections()
        if out:
            lines.append(out)
    warning = playbook_tags.refresh_cache(list_playbooks())
    if warning:
        lines.append(warning)
    return lines


def _refresh_loop() -> None:
    while True:
        with _refresh_lock:
            install = _refresh["install"]
            _refresh["install"] = _refresh["again"] = False
        try:
            for line in refresh_derived(install):
                logger.warning("%s", line)
        except Exception:  # noqa: BLE001
            logger.exception("Refreshing playbook tags and hosts failed")
        with _refresh_lock:
            if not _refresh["again"]:
                _refresh["running"] = False
                return


def schedule_refresh(install: bool = False) -> None:
    """Refresh derived data in a background thread; changes that arrive meanwhile cost one more pass."""
    with _refresh_lock:
        _refresh["install"] = _refresh["install"] or install
        if _refresh["running"]:
            _refresh["again"] = True
            return
        _refresh["running"] = True
    threading.Thread(target=_refresh_loop, daemon=True, name="workspace-refresh").start()


def _is_requirements(rel: str) -> bool:
    configured = settings_store.get("requirements_path").strip("/")
    return rel == configured or rel.rsplit("/", 1)[-1] in EXCLUDE_FILES


def _after_change(changed: list[str], listing_changed: bool, install: bool = False) -> None:
    inventory.invalidate_hosts_cache()  # now, not in the background: the next read must see the new files
    if listing_changed:
        for callback in list(_listeners):
            try:
                callback()
            except Exception:  # noqa: BLE001
                logger.exception("Workspace listener failed")
    schedule_refresh(install or any(_is_requirements(rel) for rel in changed))
