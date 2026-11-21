import logging
import os
import re
import subprocess
from pathlib import Path

from app.config import SSH_KEY_LINK_HOMES, SSH_STORAGE_DIR

logger = logging.getLogger("ulmo.ssh_keys")

# Files that aren't user-managed keys, even though they live alongside them.
RESERVED_FILENAMES = {"known_hosts", "known_hosts.old", "config"}
FILENAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")

# Warnings from the most recent ensure_symlinks() run. Populated at startup
# (see main.lifespan); the Settings page reads these instead of redoing the
# mkdir/chmod/symlink work on every render.
_last_link_warnings: list[str] = []


def ensure_symlinks() -> list[str]:
    """Make SSH_STORAGE_DIR reachable as "<home>/.ssh" for each configured home.

    Returns a list of human-readable warnings for any home that couldn't be
    linked (e.g. no permission to create it outside a container). The app
    keeps running either way — key upload still works, it just won't be
    visible to ansible-playbook until the link exists.
    """
    warnings: list[str] = []
    try:
        SSH_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        SSH_STORAGE_DIR.chmod(0o700)
    except OSError as exc:
        warnings.append(f"Could not create {SSH_STORAGE_DIR}: {exc}")
        return warnings

    for home in SSH_KEY_LINK_HOMES:
        ssh_dir = Path(home) / ".ssh"
        try:
            if ssh_dir.is_symlink():
                if ssh_dir.resolve() == SSH_STORAGE_DIR.resolve():
                    continue
                ssh_dir.unlink()
            elif ssh_dir.exists():
                warnings.append(
                    f"{ssh_dir} already exists and is not managed by ulmo — "
                    "remove it or change ULMO_SSH_LINK_HOMES."
                )
                continue
            ssh_dir.parent.mkdir(parents=True, exist_ok=True)
            ssh_dir.symlink_to(SSH_STORAGE_DIR)
        except OSError as exc:
            warnings.append(f"Could not link {ssh_dir} -> {SSH_STORAGE_DIR}: {exc}")

    if warnings:
        for w in warnings:
            logger.warning(w)

    global _last_link_warnings
    _last_link_warnings = warnings
    return warnings


def accepted_paths() -> list[str]:
    """The paths an inventory's ansible_ssh_private_key_file may use to name a key saved here: under each
    linked home's .ssh, or with ~ (Ansible expands it to the user's home, which is one of those)."""
    return [f"{home.rstrip('/')}/.ssh/<name>" for home in SSH_KEY_LINK_HOMES] + ["~/.ssh/<name>"]


def check_inventory_key(path: str, saved: set[str]) -> dict:
    """What to tell the user about one key path from the inventory: {path, name, status, message}, where
    status is "ok" (a saved key has that name), "missing" (it is under a linked home but no key of that
    name is saved) or "other" (somewhere ulmo does not manage, or a templated value it cannot read)."""
    homes = [f"{h.rstrip('/')}/.ssh/" for h in SSH_KEY_LINK_HOMES] + ["~/.ssh/"]
    for prefix in homes:
        if path.startswith(prefix):
            name = path[len(prefix):]
            if "/" in name or not name:
                break  # a subfolder: not one of the saved keys
            if name in saved:
                return {"path": path, "name": name, "status": "ok", "message": "saved"}
            return {"path": path, "name": name, "status": "missing", "message": f'no key named "{name}" is saved: add one with that name'}
    if "{{" in path:
        return {"path": path, "name": "", "status": "other", "message": "a templated value; ulmo cannot check it"}
    return {"path": path, "name": "", "status": "other", "message": "not one of the saved keys: the file must exist inside the container (a mounted volume, say)"}


def inventory_key_report(saved_names: list[str], key_files: dict[str, list[str]]) -> list[dict]:
    """check_inventory_key for every key path the inventory names, with the hosts that use it."""
    saved = set(saved_names)
    return [{**check_inventory_key(path, saved), "hosts": hosts} for path, hosts in key_files.items()]


def link_warnings() -> list[str]:
    """Warnings from the most recent ensure_symlinks() call (run at startup),
    for the Settings page — reading this isn't a filesystem operation."""
    return _last_link_warnings


def _validate_filename(filename: str) -> str:
    filename = Path(filename).name.strip()
    if not filename or not FILENAME_PATTERN.match(filename):
        raise ValueError(
            "Key name can only contain letters, numbers, dots, dashes and underscores."
        )
    if filename.startswith(".") or filename in RESERVED_FILENAMES:
        raise ValueError(f'"{filename}" is a reserved name — choose a different one.')
    if filename.endswith(".pub"):  # "<name>.pub" is where the public key of "<name>" is kept
        raise ValueError(f'"{filename}" ends in .pub, the name of a public key file — choose a different name.')
    return filename


def list_keys() -> list[dict]:
    if not SSH_STORAGE_DIR.exists():
        return []
    keys = []
    for path in sorted(SSH_STORAGE_DIR.iterdir()):
        if not path.is_file() or path.name in RESERVED_FILENAMES or path.suffix == ".pub" or path.name.startswith("."):
            continue
        keys.append({"filename": path.name, "hint": _fingerprint_hint(path)})
    return keys


def _pub_path(path: Path) -> Path:
    return path.with_name(path.name + ".pub")


def _derive_public(path: Path) -> tuple[str, str | None]:
    """(the public key line, None), or ("", why ssh-keygen could not make it)."""
    try:
        # -P "" so a key with a passphrase fails here instead of waiting for someone to type it;
        # errors="replace" because a key's comment can be any bytes
        done = subprocess.run(
            ["ssh-keygen", "-y", "-P", "", "-f", str(path)],
            capture_output=True, text=True, errors="replace", timeout=10, stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return "", f"ssh-keygen did not run ({exc})"
    public = (done.stdout.strip().splitlines() or [""])[0]
    if done.returncode == 0 and public:
        return public, None
    if "passphrase" in done.stderr:
        return "", "the key has a passphrase"
    lines = [line.strip() for line in done.stderr.splitlines() if line.strip()]
    return "", "ssh-keygen: " + (lines[-1][:200] if lines else "it could not read the key")


def _key_material(text: str) -> list[str]:
    """The type and the base64 body of a public key line: what has to match, not the comment."""
    return text.split()[:2]


def _forget(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _sync_public_key(path: Path, replaced: bool = False) -> tuple[bool, str | None]:
    """Make <path>.pub hold the public key of the private key at <path> (playbooks read it, for
    ansible.posix.authorized_key and the like). Returns (changed, reason): reason is None, or why it could not
    be done. A .pub that already holds this key, whatever its comment, is left alone; one that holds another
    key or nothing is replaced. When no public key can be made, a .pub that is there is removed only if
    `replaced` (the private key was just saved, so the old file is the old key's); otherwise it stays, since
    ssh-keygen may have failed for a reason that has nothing to do with the file (a timeout, no ssh-keygen).
    Never raises for a file problem; the file is written whole or not at all."""
    pub = _pub_path(path)
    public, reason = _derive_public(path)
    if reason:
        if replaced:
            _forget(pub)
        return False, reason
    try:
        if _key_material(pub.read_text(errors="replace")) == _key_material(public):
            return False, None
    except OSError:
        pass  # missing, or not a file: written below
    tmp = pub.with_name("." + pub.name + ".tmp")  # a dot name is never listed as a key
    try:
        tmp.write_text(public + "\n", encoding="utf-8")
        tmp.chmod(0o644)
        os.replace(tmp, pub)
    except OSError as exc:
        _forget(tmp)
        return False, f"could not write {pub.name}: {exc.strerror or exc}"
    return True, None


def ensure_public_keys() -> list[str]:
    """Bring the .pub of every saved key in line (keys saved before ulmo made them have none; one may hold
    another key or be empty). Returns the names changed. Run at startup, so nothing here may raise."""
    try:
        keys = list_keys()
    except OSError as exc:
        logger.warning("Could not list the saved SSH keys to make their public keys: %s", exc)
        return []
    made = []
    for key in keys:
        changed, reason = _sync_public_key(SSH_STORAGE_DIR / key["filename"])
        if reason:
            logger.warning("No public key made for %s: %s", key["filename"], reason)
        elif changed:
            made.append(key["filename"])
    if made:
        logger.info("Made the public key of: %s", ", ".join(made))
    return made


def save_key(filename: str, key_text: str) -> tuple[str, str | None]:
    """Store the private key and write its public key next to it. Returns (the name it was saved under,
    None or the reason the public key could not be made); the private key is saved either way."""
    filename = _validate_filename(filename)
    # Browsers normalize <textarea> form submissions to CRLF line endings,
    # which breaks OpenSSH/PEM's base64 parser ("error in libcrypto").
    key_text = key_text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not key_text.startswith("-----BEGIN"):
        raise ValueError("That doesn't look like a private key (expected a -----BEGIN ... block).")
    SSH_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    SSH_STORAGE_DIR.chmod(0o700)
    path = SSH_STORAGE_DIR / filename
    path.write_text(key_text + "\n")
    path.chmod(0o600)
    return filename, _sync_public_key(path, replaced=True)[1]


def delete_key(filename: str) -> None:
    filename = _validate_filename(filename)
    path = SSH_STORAGE_DIR / filename
    path.unlink(missing_ok=True)
    _pub_path(path).unlink(missing_ok=True)


def _fingerprint_hint(path: Path) -> str | None:
    """First line of the PEM/OpenSSH header, without revealing the key body."""
    try:
        first_line = path.read_text().splitlines()[0]
    except (OSError, IndexError):
        return None
    return first_line.replace("-----BEGIN ", "").replace("-----", "").strip()
