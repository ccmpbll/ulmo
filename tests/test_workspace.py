"""Self-check for the Ansible workspace (app/services/workspace.py, app/routers/files.py).

Rejections first: everything the workspace must refuse (escaping paths, symlinks, .git, a stale
edit, a write during a run, hostile zips), then the writes that must work (atomic swap, saved
copies and Restore, uploads, zip, delete, replace-from-a-directory, startup migration), then the
run lock through the runner and the Files page through HTTP.

Run directly: python3 tests/test_workspace.py
"""
import io
import os
import re
import shutil
import stat
import sys
import tempfile
import threading
import time
import zipfile
from pathlib import Path

DATA_DIR = tempfile.mkdtemp(prefix="ulmo-test-")
os.environ["ULMO_DATA_DIR"] = DATA_DIR
os.environ.pop("ULMO_DISABLE_AUTH", None)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session  # noqa: E402

import app.auth as auth_module  # noqa: E402
from app.config import LEGACY_REPO_DIR, WORKSPACE_DIR, WORKSPACE_HISTORY_DIR  # noqa: E402
from app.database import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import RunHistory  # noqa: E402
from app.routers import files as files_module  # noqa: E402
from app.services import runner, settings_store, workspace  # noqa: E402
import ansible_runner  # noqa: E402

_real_schedule_refresh = workspace.schedule_refresh
workspace.schedule_refresh = lambda install=False: None  # the background refresh shells out to ansible

admin = TestClient(app)


def raises(exc, fn, *args, **kw):
    try:
        fn(*args, **kw)
    except exc as e:
        return e
    raise AssertionError(f"expected {exc.__name__} from {fn.__name__}{args}")


def reset():
    for rid in [r["run_id"] for r in workspace.active_runs()]:
        workspace.end_run(rid)
    shutil.rmtree(WORKSPACE_DIR, ignore_errors=True)
    shutil.rmtree(WORKSPACE_HISTORY_DIR, ignore_errors=True)


def tree():
    return sorted(f["rel_path"] for f in workspace.list_files())


# --- refusals -------------------------------------------------------------------------------------


def test_bad_paths_are_refused():
    reset()
    for bad in ("", "  ", "/", "..", "../x", "a/../../x", "a/./b", "a//b", ".git/config", "a/.git/x", ".ulmo-x.tmp", "a\0b", "x" * 301):
        raises(ValueError, workspace.store, bad, b"x")
    raises(ValueError, workspace.read_file, "../etc/passwd")
    assert not WORKSPACE_DIR.exists() or tree() == [], "a refused write left nothing behind"
    # a backslash is a separator, so it cannot smuggle ".." either
    raises(ValueError, workspace.store, "a\\..\\..\\x", b"x")
    # leading slashes are stripped, not honoured: "/etc/x" is workspace/etc/x
    workspace.store("/etc/x", b"x")
    assert tree() == ["etc/x"] and not Path("/etc/x").exists()


def test_symlinks_are_not_followed():
    reset()
    workspace.store("playbooks/a.yaml", b"a")
    outside = Path(DATA_DIR) / "outside.txt"
    outside.write_text("secret")
    os.symlink(outside, WORKSPACE_DIR / "link.txt")
    os.symlink(Path(DATA_DIR), WORKSPACE_DIR / "dirlink")
    (WORKSPACE_DIR / ".git").mkdir()
    (WORKSPACE_DIR / ".git" / "config").write_text("x")
    assert tree() == ["playbooks/a.yaml"], "symlinked files and folders, and a .git folder, are not listed"
    raises(ValueError, workspace.read_file, "link.txt")
    raises(ValueError, workspace.store, "link.txt", b"overwritten")
    raises(ValueError, workspace.store, "dirlink/new.txt", b"x")
    assert outside.read_text() == "secret" and not (Path(DATA_DIR) / "new.txt").exists()
    raises(ValueError, workspace.delete, "link.txt", None)


def test_stale_edit_is_refused():
    reset()
    v1 = workspace.store("a.yaml", b"one", base="")
    raises(workspace.Conflict, workspace.store, "a.yaml", b"again", base="")  # "must not exist yet"
    raises(workspace.Conflict, workspace.store, "missing.yaml", b"x", base="deadbeef")  # editing a file that is gone
    v2 = workspace.store("a.yaml", b"two", base=v1)
    assert v2 != v1
    raises(workspace.Conflict, workspace.store, "a.yaml", b"three", base=v1)  # a second tab holding the old version
    assert (WORKSPACE_DIR / "a.yaml").read_bytes() == b"two"
    raises(workspace.Conflict, workspace.delete, "a.yaml", v1)
    assert tree() == ["a.yaml"]
    workspace.store("a.yaml", b"anything", base=None)  # None = an upload, no check


def test_folder_and_file_collisions():
    reset()
    workspace.store("dir/file.txt", b"x")
    raises(ValueError, workspace.store, "dir", b"x")  # a folder is not a file
    raises(ValueError, workspace.store, "dir/file.txt/child", b"x")  # a file is not a folder
    assert tree() == ["dir/file.txt"]


def test_size_cap():
    reset()
    real = workspace.MAX_FILE_BYTES
    workspace.MAX_FILE_BYTES = 10
    try:
        raises(ValueError, workspace.store, "big", b"x" * 11)
        workspace.store("ok", b"x" * 10)
        # one oversize file refuses the whole upload: nothing is written
        raises(ValueError, workspace.store_many, [("first", b"1"), ("big", b"x" * 11)])
        assert tree() == ["ok"]
    finally:
        workspace.MAX_FILE_BYTES = real


def _zip(entries, symlink=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries:
            zf.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink[0])
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, symlink[1])
    return buf.getvalue()


def test_hostile_zips_are_refused_whole():
    reset()
    workspace.store("keep.txt", b"keep")
    for entries, symlink, why in (
        ([("good.txt", "1"), ("../evil.txt", "2")], None, "escaping path"),
        ([("good.txt", "1"), ("a/../../evil.txt", "2")], None, "escape in the middle"),
        ([("good.txt", "1"), (".git/config", "2")], None, ".git"),
        ([("good.txt", "1")], ("link", "/etc/passwd"), "symlink"),
        ([], None, "empty"),
    ):
        raises(ValueError, workspace.unpack_zip, _zip(entries, symlink))
        assert tree() == ["keep.txt"], f"{why}: nothing was unpacked"
    raises(ValueError, workspace.unpack_zip, b"not a zip")
    real = workspace.MAX_ZIP_ENTRIES, workspace.MAX_ZIP_BYTES
    workspace.MAX_ZIP_ENTRIES = 2
    try:
        raises(ValueError, workspace.unpack_zip, _zip([("a", "1"), ("b", "2"), ("c", "3")]))
    finally:
        workspace.MAX_ZIP_ENTRIES = real[0]
    workspace.MAX_ZIP_BYTES = 5
    try:
        raises(ValueError, workspace.unpack_zip, _zip([("a", "123"), ("b", "456")]))  # 6 bytes unpacked
    finally:
        workspace.MAX_ZIP_BYTES = real[1]
    assert tree() == ["keep.txt"]


def test_workspace_is_read_only_during_a_run():
    reset()
    v = workspace.store("a.yaml", b"one")
    workspace.begin_run(7, "playbooks/a.yaml")
    try:
        assert workspace.active_runs() == [{"run_id": 7, "playbook": "playbooks/a.yaml"}]
        raises(workspace.Locked, workspace.store, "a.yaml", b"two", base=v)
        raises(workspace.Locked, workspace.store, "new.yaml", b"x")
        raises(workspace.Locked, workspace.store_many, [("n.yaml", b"x")])
        raises(workspace.Locked, workspace.delete, "a.yaml", v)
        raises(workspace.Locked, workspace.unpack_zip, _zip([("z", "1")]))
        raises(workspace.Locked, workspace.replace_from, WORKSPACE_DIR)
        assert workspace.read_file("a.yaml")["text"] == "one", "reading stays open"
        assert tree() == ["a.yaml"]
    finally:
        workspace.end_run(7)
    workspace.end_run(7)  # ending twice is harmless (the start-failure test calls _execute directly)
    workspace.store("a.yaml", b"two", base=v)


def test_lock_names_the_first_run_and_counts_the_rest():
    reset()
    workspace.begin_run(3)
    workspace.begin_run(9)
    try:
        msg = str(raises(workspace.Locked, workspace.store, "a", b"x"))
        assert "Run #3" in msg and "1 more" in msg, msg
    finally:
        workspace.end_run(3)
        workspace.end_run(9)


# --- writes that must work --------------------------------------------------------------------------


def test_save_keeps_a_copy_and_restore_puts_it_back():
    reset()
    settings_store.set_many({"workspace_history_keep": "3"})
    v = workspace.store("playbooks/a.yaml", b"v1")
    assert workspace.list_versions("playbooks/a.yaml") == [], "a new file has no saved copy"
    for n in range(2, 7):
        v = workspace.store("playbooks/a.yaml", f"v{n}".encode(), base=v)
        time.sleep(0.002)
    versions = workspace.list_versions("playbooks/a.yaml")
    assert len(versions) == 3, "only the newest three copies are kept"
    assert [workspace.version_bytes("playbooks/a.yaml", x["id"]) for x in versions] == [b"v5", b"v4", b"v3"]
    # saving identical contents is not a change and makes no copy
    workspace.store("playbooks/a.yaml", b"v6", base=v)
    assert len(workspace.list_versions("playbooks/a.yaml")) == 3
    # restore: the current contents become a copy too
    cur = workspace.read_file("playbooks/a.yaml")["version"]
    workspace.restore("playbooks/a.yaml", versions[-1]["id"], cur)
    assert workspace.read_file("playbooks/a.yaml")["text"] == "v3"
    assert workspace.list_versions("playbooks/a.yaml")[0]["size"] == 2
    raises(ValueError, workspace.version_bytes, "playbooks/a.yaml", "../../ulmo.db")
    raises(ValueError, workspace.version_bytes, "playbooks/a.yaml", "20200101T000000000000Z")
    raises(workspace.Conflict, workspace.restore, "playbooks/a.yaml", versions[0]["id"], "stale")
    settings_store.set_many({"workspace_history_keep": "20"})


def test_atomic_write_leaves_no_temp_files_and_keeps_the_mode():
    reset()
    workspace.store("files/run.sh", b"#!/bin/sh\n")
    os.chmod(WORKSPACE_DIR / "files/run.sh", 0o755)
    v = workspace.read_file("files/run.sh")["version"]
    workspace.store("files/run.sh", b"#!/bin/sh\necho hi\n", base=v)
    assert stat.S_IMODE((WORKSPACE_DIR / "files/run.sh").stat().st_mode) == 0o755, "an edit keeps the executable bit"
    assert [p.name for p in (WORKSPACE_DIR / "files").iterdir()] == ["run.sh"]
    # a failed write cleans up its temp file and leaves the old contents
    real = os.replace
    def boom(*a, **k):
        raise OSError("disk full")
    os.replace = boom
    try:
        raises(OSError, workspace.store, "files/run.sh", b"new", base=workspace.read_file("files/run.sh")["version"])
    finally:
        os.replace = real
    assert (WORKSPACE_DIR / "files/run.sh").read_bytes() == b"#!/bin/sh\necho hi\n"
    assert [p.name for p in (WORKSPACE_DIR / "files").iterdir()] == ["run.sh"], "no temp file left"


def test_delete_keeps_a_copy_and_prunes_empty_folders():
    reset()
    workspace.store("a/b/c.txt", b"c")
    workspace.store("keep.txt", b"k")
    v = workspace.read_file("a/b/c.txt")["version"]
    workspace.delete("a/b/c.txt", v)
    assert tree() == ["keep.txt"] and not (WORKSPACE_DIR / "a").exists(), "empty parents go, the root stays"
    assert WORKSPACE_DIR.is_dir()
    assert workspace.deleted_files() == ["a/b/c.txt"]
    vid = workspace.list_versions("a/b/c.txt")[0]["id"]
    workspace.restore("a/b/c.txt", vid, "")
    assert tree() == ["a/b/c.txt", "keep.txt"] and workspace.deleted_files() == []
    raises(ValueError, workspace.delete, "nope.txt", None)


def test_binary_and_large_files_are_not_editable_text():
    reset()
    workspace.store("bin", b"\x00\x01\x02")
    workspace.store("latin", "caf\xe9".encode("latin-1"))
    assert workspace.read_file("bin")["text"] is None and workspace.read_file("latin")["text"] is None
    real = workspace.MAX_EDIT_BYTES
    workspace.MAX_EDIT_BYTES = 4
    try:
        workspace.store("long.txt", b"12345")
        assert workspace.read_file("long.txt")["text"] is None and workspace.read_file("long.txt")["size"] == 5
    finally:
        workspace.MAX_EDIT_BYTES = real
    assert workspace.file_bytes("bin") == b"\x00\x01\x02"


def test_zip_unpacks_skips_mac_junk_and_round_trips():
    reset()
    z = _zip([("playbooks/a.yaml", "a"), ("files/x.conf", "x"), ("__MACOSX/playbooks/._a.yaml", "junk"), ("playbooks/.DS_Store", "junk")])
    assert sorted(workspace.unpack_zip(z, "")) == ["files/x.conf", "playbooks/a.yaml"]
    assert tree() == ["files/x.conf", "playbooks/a.yaml"]
    assert workspace.unpack_zip(_zip([("b.yaml", "b")]), "extra/dir") == ["extra/dir/b.yaml"]
    out = zipfile.ZipFile(io.BytesIO(workspace.export_zip()))
    assert sorted(out.namelist()) == tree() and out.read("playbooks/a.yaml") == b"a"


def test_playbook_list_and_requirements_discovery():
    reset()
    settings_store.set_many({"playbooks_subdir": "playbooks", "requirements_path": ""})
    for rel in ("playbooks/b.yaml", "playbooks/a.yml", "playbooks/old/x.yaml", "playbooks/requirements.yaml", "playbooks/notes.txt", "site.yaml"):
        workspace.store(rel, b"- hosts: all\n")
    assert [p["rel_path"] for p in workspace.list_playbooks()] == ["playbooks/b.yaml", "playbooks/a.yml"]
    assert workspace.read_playbook("playbooks/b.yaml").startswith("- hosts")
    raises(ValueError, workspace.read_playbook, "site.yaml")  # outside the playbooks folder
    raises(ValueError, workspace.read_playbook, "../ulmo.db")
    assert workspace._find_requirements_file().resolve() == (WORKSPACE_DIR / "playbooks/requirements.yaml").resolve()
    settings_store.set_many({"requirements_path": "../x"})
    assert isinstance(workspace._find_requirements_file(), str)
    settings_store.set_many({"requirements_path": ""})


def test_listener_fires_on_create_and_delete_only():
    reset()
    calls = []
    cb = lambda: calls.append(1)  # noqa: E731
    workspace.on_listing_change(cb)
    try:
        v = workspace.store("p.yaml", b"1")
        assert len(calls) == 1
        workspace.store("p.yaml", b"2", base=v)
        assert len(calls) == 1, "an edit does not change the list of playbooks"
        workspace.delete("p.yaml", None)
        assert len(calls) == 2
    finally:
        workspace._listeners.remove(cb)


def test_replace_from_keeps_the_old_workspace_and_skips_symlinks_and_git():
    reset()
    workspace.store("old.txt", b"old")
    src = Path(tempfile.mkdtemp(prefix="src-", dir=DATA_DIR))
    (src / ".git").mkdir()
    (src / ".git" / "config").write_text("x")
    (src / "playbooks").mkdir()
    (src / "playbooks" / "n.yaml").write_text("new")
    secret = Path(DATA_DIR) / "secret.txt"
    secret.write_text("secret")
    os.symlink(secret, src / "leak.txt")
    os.symlink(DATA_DIR, src / "leakdir")
    assert workspace.replace_from(src) == 1
    assert tree() == ["playbooks/n.yaml"], tree()
    backups = list(Path(DATA_DIR).glob("ansible.before-import-*"))
    assert len(backups) == 1 and (backups[0] / "old.txt").read_text() == "old"
    empty = Path(tempfile.mkdtemp(prefix="empty-", dir=DATA_DIR))
    raises(ValueError, workspace.replace_from, empty)
    assert tree() == ["playbooks/n.yaml"], "an empty source changes nothing"
    assert not list(Path(DATA_DIR).glob("ansible.incoming-*"))
    for b in backups:
        shutil.rmtree(b)


def test_startup_copies_the_old_git_checkout_once():
    reset()
    shutil.rmtree(LEGACY_REPO_DIR, ignore_errors=True)
    assert workspace.migrate_legacy_repo() is False, "no checkout, nothing to do"
    (LEGACY_REPO_DIR / ".git").mkdir(parents=True)
    (LEGACY_REPO_DIR / ".git" / "HEAD").write_text("ref")
    (LEGACY_REPO_DIR / "playbooks").mkdir()
    (LEGACY_REPO_DIR / "playbooks" / "a.yaml").write_text("a")
    (LEGACY_REPO_DIR / "inventory.yaml").write_text("all:\n")
    assert workspace.migrate_legacy_repo() is True
    assert tree() == ["inventory.yaml", "playbooks/a.yaml"]
    (LEGACY_REPO_DIR / "late.txt").write_text("late")
    workspace.store("inventory.yaml", b"edited", base=None)
    assert workspace.migrate_legacy_repo() is False, "an existing workspace is never overwritten"
    assert tree() == ["inventory.yaml", "playbooks/a.yaml"] and (LEGACY_REPO_DIR / "playbooks/a.yaml").exists(), "the checkout is left alone"
    shutil.rmtree(LEGACY_REPO_DIR)


# --- the run lock through the runner ---------------------------------------------------------------


def test_a_started_run_locks_the_files_until_it_ends():
    reset()
    workspace.store("playbooks/a.yaml", b"- hosts: all\n")
    release = threading.Event()
    seen = {}

    class FakeRunner:
        rc, status = 0, "successful"

    def fake_run_async(**kwargs):
        seen["project_dir"] = kwargs["project_dir"]
        t = threading.Thread(target=release.wait, daemon=True)
        t.start()
        return t, FakeRunner()

    real = ansible_runner.run_async
    ansible_runner.run_async = fake_run_async
    try:
        record = runner.start_run("playbooks/a.yaml", triggered_by="test")
        assert [r["run_id"] for r in workspace.active_runs()] == [record.id], "registered before start_run returns"
        raises(workspace.Locked, workspace.store, "playbooks/a.yaml", b"changed")
        assert seen.get("project_dir") is None or seen["project_dir"] == str(WORKSPACE_DIR)
        release.set()
        for _ in range(200):
            if not workspace.active_runs():
                break
            time.sleep(0.02)
        assert workspace.active_runs() == [], "the lock is released when the run ends"
        workspace.store("playbooks/a.yaml", b"changed")
        assert seen["project_dir"] == str(WORKSPACE_DIR)
        with Session(engine) as session:
            assert session.get(RunHistory, record.id).status == "success"
    finally:
        ansible_runner.run_async = real
        release.set()


def test_a_failed_run_start_releases_the_lock():
    reset()
    workspace.store("playbooks/a.yaml", b"- hosts: all\n")
    real = threading.Thread.start
    def no_start(self):
        raise RuntimeError("can't start new thread")
    threading.Thread.start = no_start
    try:
        raises(RuntimeError, runner.start_run, "playbooks/a.yaml")
    finally:
        threading.Thread.start = real
    assert workspace.active_runs() == [], "a run that never started must not lock the files forever"
    raises(ValueError, runner.start_run, "playbooks/nope.yaml")
    assert workspace.active_runs() == [], "an unknown playbook registers nothing"


def test_a_save_and_a_run_start_never_interleave():
    """start_run checks and registers under the same lock a save holds, so with a save in flight the
    run waits for it, and after the run registers the save is refused."""
    reset()
    workspace.store("playbooks/a.yaml", b"- hosts: all\n")
    entered, finish = threading.Event(), threading.Event()
    real_store_one = workspace._store_one
    def slow_store_one(rel, data, base):
        entered.set()
        finish.wait(5)
        return real_store_one(rel, data, base)
    workspace._store_one = slow_store_one
    ansible_runner_real = ansible_runner.run_async
    ansible_runner.run_async = lambda **kw: (threading.Thread(target=lambda: None), type("R", (), {"rc": 0, "status": "successful"})())
    started = {}
    try:
        saver = threading.Thread(target=lambda: workspace.store("playbooks/a.yaml", b"new", base=None))
        saver.start()
        assert entered.wait(5)
        starter = threading.Thread(target=lambda: started.update(rec=runner.start_run("playbooks/a.yaml")))
        starter.start()
        time.sleep(0.2)
        assert "rec" not in started, "the run start waits for the save in flight"
        finish.set()
        saver.join(5)
        starter.join(5)
        assert "rec" in started
        assert (WORKSPACE_DIR / "playbooks/a.yaml").read_bytes() == b"new", "the save landed before the run began"
    finally:
        workspace._store_one = real_store_one
        ansible_runner.run_async = ansible_runner_real
        finish.set()
        time.sleep(0.2)


def test_a_playbook_deleted_mid_start_is_not_run():
    """start_run checks the playbook exists and registers the run in one step under the workspace
    lock, so a delete in flight is seen: the run is refused instead of started for a missing file."""
    reset()
    workspace.store("playbooks/a.yaml", b"- hosts: all\n")
    entered, finish = threading.Event(), threading.Event()
    real_keep = workspace._keep_copy
    def slow_keep(rel, data):
        entered.set()
        finish.wait(5)
        return real_keep(rel, data)
    workspace._keep_copy = slow_keep
    outcome = {}
    def start():
        try:
            outcome["rec"] = runner.start_run("playbooks/a.yaml")
        except ValueError as exc:
            outcome["err"] = str(exc)
    try:
        deleter = threading.Thread(target=lambda: workspace.delete("playbooks/a.yaml", None))
        deleter.start()
        assert entered.wait(5)
        starter = threading.Thread(target=start)
        starter.start()
        time.sleep(0.2)
        finish.set()
        deleter.join(5)
        starter.join(5)
    finally:
        workspace._keep_copy = real_keep
        finish.set()
    assert "err" in outcome and "rec" not in outcome, outcome
    assert workspace.active_runs() == []


# --- the Files page ---------------------------------------------------------------------------------


def test_files_pages_and_forms():
    reset()
    assert "No files yet" in admin.get("/files").text
    assert "No files yet" in admin.get("/ansible").text
    r = admin.post("/files/upload", data={"folder": "playbooks"}, files=[("uploads", ("site.yaml", b"- hosts: all\n")), ("uploads", ("x.yaml", b"x"))], follow_redirects=False)
    assert r.status_code == 303 and "Saved+2" in r.headers["location"].replace("%20", "+"), r.headers["location"]
    assert tree() == ["playbooks/site.yaml", "playbooks/x.yaml"]
    assert "playbooks/site.yaml" in admin.get("/files").text
    page = admin.get("/files/edit?path=playbooks/site.yaml")
    assert page.status_code == 200 and "- hosts: all" in page.text
    base = workspace.read_file("playbooks/site.yaml")["version"]
    assert f'name="base" value="{base}"' in page.text

    # save: CRLF from the browser becomes LF
    r = admin.post("/files/save", data={"path": "playbooks/site.yaml", "text": "- hosts: web\r\n  tasks: []\r\n", "base": base}, follow_redirects=False)
    assert r.status_code == 303 and workspace.file_bytes("playbooks/site.yaml") == b"- hosts: web\n  tasks: []\n"
    # a stale save: 409, the user's text is shown back, the file is untouched
    r = admin.post("/files/save", data={"path": "playbooks/site.yaml", "text": "MY EDIT", "base": base})
    assert r.status_code == 409 and "changed since you opened it" in r.text and "MY EDIT" in r.text
    assert workspace.file_bytes("playbooks/site.yaml").startswith(b"- hosts: web")
    # a bad path: 400
    r = admin.post("/files/save", data={"path": "../x", "text": "x", "base": ""})
    assert r.status_code == 400 and not (Path(DATA_DIR) / "x").exists()
    assert admin.get("/files/edit?path=../x", follow_redirects=False).status_code == 303

    # a run is active: banner, 423, text kept, buttons disabled
    workspace.begin_run(41, "playbooks/site.yaml")
    try:
        cur = workspace.read_file("playbooks/site.yaml")["version"]
        r = admin.post("/files/save", data={"path": "playbooks/site.yaml", "text": "DURING RUN", "base": cur})
        assert r.status_code == 423 and "Run #41" in r.text and "DURING RUN" in r.text
        page = admin.get("/files/edit?path=playbooks/site.yaml").text
        assert "Read-only while a playbook runs" in page and "Cancel run #41" in page and "readonly" in page
        assert 'type="submit" disabled>Save' in page.replace("\n", "").replace("  ", " ") or "disabled>Save" in page
        assert "Read-only while a playbook runs" in admin.get("/files").text and "Read-only while a playbook runs" in admin.get("/ansible").text
        r = admin.post("/files/upload", files=[("uploads", ("n.yaml", b"n"))], follow_redirects=False)
        assert "error=" in r.headers["location"] and "Run%20%2341" in r.headers["location"], r.headers["location"]
        r = admin.post("/files/delete", data={"path": "playbooks/site.yaml", "base": cur})
        assert r.status_code == 423
        r = admin.post("/files/upload-zip", files={"zip_file": ("a.zip", _zip([("z", "1")]))}, follow_redirects=False)
        assert "error=" in r.headers["location"]
        assert admin.get("/files/raw?path=playbooks/site.yaml").status_code == 200, "downloads stay open"
        assert admin.get("/files/download.zip").status_code == 200
    finally:
        workspace.end_run(41)
    assert "DURING RUN" not in workspace.file_bytes("playbooks/site.yaml").decode() and "n.yaml" not in " ".join(tree())

    # history page and restore
    vid = workspace.list_versions("playbooks/site.yaml")[0]["id"]
    ver = admin.get(f"/files/version?path=playbooks/site.yaml&version={vid}")
    assert ver.status_code == 200 and "What restoring it would change" in ver.text and "- hosts: all" in ver.text
    assert admin.get("/files/version?path=playbooks/site.yaml&version=20200101T000000000000Z", follow_redirects=False).status_code == 303
    cur = workspace.read_file("playbooks/site.yaml")["version"]
    r = admin.post("/files/restore", data={"path": "playbooks/site.yaml", "version": vid, "base": cur}, follow_redirects=False)
    assert r.status_code == 303 and workspace.file_bytes("playbooks/site.yaml") == b"- hosts: all\n"

    # zip upload, raw download name, delete, deleted list
    r = admin.post("/files/upload-zip", data={"folder": "z"}, files={"zip_file": ("a.zip", _zip([("one.txt", "1")]))}, follow_redirects=False)
    assert r.status_code == 303 and "z/one.txt" in tree()
    r = admin.post("/files/upload-zip", files={"zip_file": ("a.zip", _zip([("../evil", "1")]))}, follow_redirects=False)
    assert "error=" in r.headers["location"] and not (Path(DATA_DIR) / "evil").exists()
    raw = admin.get("/files/raw?path=z/one.txt")
    assert raw.content == b"1" and 'filename="one.txt"' in raw.headers["content-disposition"]
    base = workspace.read_file("z/one.txt")["version"]
    assert admin.post("/files/delete", data={"path": "z/one.txt", "base": base}, follow_redirects=False).status_code == 303
    assert "z/one.txt" in admin.get("/files").text and "Deleted files" in admin.get("/files").text

    # an unauthenticated client gets nothing
    anon = TestClient(app)
    for method, url in (("get", "/files"), ("get", "/files/edit?path=a"), ("get", "/files/raw?path=a"), ("get", "/files/download.zip"), ("post", "/files/save"), ("post", "/files/upload"), ("post", "/files/delete"), ("post", "/files/restore")):
        r = getattr(anon, method)(url, follow_redirects=False)
        assert r.status_code in (303, 307, 401, 403) and "/login" in r.headers.get("location", "/login"), (url, r.status_code)


def test_editing_is_off_without_a_login():
    """ULMO_DISABLE_AUTH: reading and downloading work, every write is refused."""
    reset()
    workspace.store("a.yaml", b"one")
    real = files_module.AUTH_DISABLED
    files_module.AUTH_DISABLED = True
    try:
        base = workspace.read_file("a.yaml")["version"]
        page = admin.get("/files/edit?path=a.yaml").text
        assert "Editing is off" in page and "readonly" in page
        assert "Editing is off" in admin.get("/files").text and "Upload files" not in admin.get("/files").text
        assert admin.post("/files/save", data={"path": "a.yaml", "text": "x", "base": base}).status_code == 403
        assert admin.post("/files/delete", data={"path": "a.yaml", "base": base}).status_code == 403
        assert admin.post("/files/move", data={"path": "a.yaml", "to": "old/a.yaml", "base": base}).status_code == 403
        for url, kw in (("/files/upload", {"files": [("uploads", ("b", b"b"))]}), ("/files/upload-zip", {"files": {"zip_file": ("a.zip", _zip([("z", "1")]))}}),
                        ("/files/restore", {"data": {"path": "a.yaml", "version": "20200101T000000000000Z", "base": base}})):
            r = admin.post(url, follow_redirects=False, **kw)
            assert "ULMO_DISABLE_AUTH" in r.headers["location"].replace("%20", " ").replace("+", " "), url
        assert admin.get("/files/raw?path=a.yaml").status_code == 200
    finally:
        files_module.AUTH_DISABLED = real
    assert workspace.file_bytes("a.yaml") == b"one" and tree() == ["a.yaml"]


def test_settings_import_needs_confirmation_and_the_old_routes_are_gone():
    reset()
    r = admin.post("/settings/import-git", data={"git_repo_url": "https://example.invalid/x.git", "git_branch": "main"}, follow_redirects=False)
    assert "error=" in r.headers["location"] and "confirm" in r.headers["location"], "no tick, no import"
    r = admin.post("/settings/import-git", data={"git_repo_url": "", "confirm": "yes"}, follow_redirects=False)
    assert "error=" in r.headers["location"], "no URL is a failed import, recorded"
    r = admin.post("/settings/import-git", data={"git_repo_url": "--upload-pack=touch /tmp/pwned", "confirm": "yes"}, follow_redirects=False)
    assert "error=" in r.headers["location"] and not Path("/tmp/pwned").exists(), "an option-looking URL is refused"
    workspace.begin_run(5)
    try:
        r = admin.post("/settings/import-git", data={"git_repo_url": "https://example.invalid/x.git", "confirm": "yes"}, follow_redirects=False)
        assert "error=" in r.headers["location"] and "in+progress" in r.headers["location"].replace("%20", "+"), r.headers["location"]
    finally:
        workspace.end_run(5)
    assert admin.post("/sync", follow_redirects=False).status_code in (404, 405)


def test_git_clone_command_cannot_take_options_from_the_url():
    """Checked on the command itself (git would fail on its own for a bad value, which proves nothing):
    an option-looking URL never reaches git, and a real one comes after "--"."""
    from app.services import git_import
    reset()
    calls = []
    real = git_import.subprocess.run
    class Done:
        returncode, stdout, stderr = 1, "", "stop here"
    git_import.subprocess.run = lambda argv, **kw: calls.append(argv) or Done()
    try:
        rec = git_import.import_now("--upload-pack=touch /tmp/x", "main", "t")
        assert rec.status == "failed" and calls == [], "refused before running git"
        rec = git_import.import_now("https://example.invalid/r.git", "main", "t")
        assert rec.status == "failed" and len(calls) == 1
        argv = calls[0]
        assert argv[argv.index("https://example.invalid/r.git") - 1] == "--", argv
    finally:
        git_import.subprocess.run = real


def test_git_import_end_to_end():
    """A real clone of a throwaway local repo (git is needed for this one: skip if absent)."""
    import subprocess
    if not shutil.which("git"):
        print("skipped: no git binary")
        return
    reset()
    repo = Path(tempfile.mkdtemp(prefix="repo-", dir=DATA_DIR))
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    def git(*a):
        subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, env=env)
    git("init", "-q", "-b", "main")
    (repo / "playbooks").mkdir()
    (repo / "playbooks" / "a.yaml").write_text("- hosts: all\n")
    (repo / "inventory.yaml").write_text("all:\n")
    git("add", "-A")
    git("commit", "-q", "-m", "x")
    workspace.store("mine.txt", b"mine")
    r = admin.post("/settings/import-git", data={"git_repo_url": f"file://{repo}", "git_branch": "main", "confirm": "yes"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/files?ok="), r.headers["location"]
    assert tree() == ["inventory.yaml", "playbooks/a.yaml"], tree()
    assert not (WORKSPACE_DIR / ".git").exists()
    r = admin.post("/settings/import-git", data={"git_repo_url": f"file://{repo}", "git_branch": "nope", "confirm": "yes"}, follow_redirects=False)
    assert "error=" in r.headers["location"] and tree() == ["inventory.yaml", "playbooks/a.yaml"], "a failed clone leaves the files alone"
    from sqlmodel import select
    from app.models import SyncHistory
    with Session(engine) as session:
        rows = session.exec(select(SyncHistory)).all()
    assert len(rows) >= 2 and not any(row.status == "running" for row in rows), "each import is recorded and settled"
    for b in Path(DATA_DIR).glob("ansible.before-import-*"):
        shutil.rmtree(b)
    assert not list(Path(DATA_DIR).glob("ansible-import-*")), "the clone's temp folder is removed"


# --- found in review ----------------------------------------------------------------------------


def test_a_file_name_cannot_break_out_of_the_delete_confirm():
    """The name sits in a data- attribute, never inside the JS of the onsubmit handler: entities in an
    attribute are decoded before the handler runs, so a quote in a name would end its string."""
    import re
    reset()
    # the editor (text file) and the download-only card (binary file) each have a delete form
    for body in (b"a: 1\n", b"\x00\x01"):
        name = "x');alert(document.domain);('.bin"
        workspace.store(name, body, base=None)
        html = admin.get("/files/edit", params={"path": name}).text
        handlers = re.findall(r'onsubmit="([^"]*)"', html)
        assert len(handlers) == 1 and "alert" not in handlers[0] and "x&#39;" not in handlers[0] and "this.dataset.name" in handlers[0], handlers
        assert html.count('data-name="x&#39;);alert(document.domain);(&#39;.bin"') == 1, "the name is escaped in the data attribute"


def test_uploads_do_their_work_off_the_event_loop():
    """Blocking work (fsyncs, the workspace lock, decompressing up to 200 MB) must not run on the loop
    that also serves the live run-log streams. The first call each route makes is the one checked:
    unpack_zip calls store_many itself, from its own worker thread."""
    import asyncio
    reset()
    seen = []
    def watch(real):
        def wrapper(*a, **k):
            try:
                asyncio.get_running_loop()
                seen.append(True)
            except RuntimeError:
                seen.append(False)
            return real(*a, **k)
        return wrapper
    real = workspace.store_many, workspace.unpack_zip
    try:
        workspace.store_many = watch(real[0])
        r = admin.post("/files/upload", files=[("uploads", ("a.txt", b"a"))], follow_redirects=False)
        assert r.headers["location"].startswith("/files?ok="), r.headers["location"]
        assert seen == [False], "upload: store_many ran on the event loop"
        seen.clear()
        workspace.store_many, workspace.unpack_zip = real[0], watch(real[1])
        r = admin.post("/files/upload-zip", files={"zip_file": ("a.zip", _zip([("b.txt", "b")]))}, follow_redirects=False)
        assert r.headers["location"].startswith("/files?ok="), r.headers["location"]
        assert seen == [False], "upload-zip: unpack_zip ran on the event loop"
    finally:
        workspace.store_many, workspace.unpack_zip = real


def test_clone_url_credentials_are_never_stored_or_shown():
    import subprocess
    from app.models import SyncHistory
    from app.services import git_import
    reset()
    url = "https://deploy:s3cr3tT0ken@git.example.invalid/Home/Ansible.git"
    class Failed:
        returncode, stdout = 128, ""
        stderr = f"fatal: unable to access '{url}/': Could not resolve host"
    real = git_import.subprocess.run
    try:
        git_import.subprocess.run = lambda argv, **kw: Failed()
        r = admin.post("/settings/import-git", data={"git_repo_url": url, "confirm": "yes"}, follow_redirects=False)
        def boom(argv, **kw):
            raise subprocess.TimeoutExpired(argv, 300)
        git_import.subprocess.run = boom
        r2 = admin.post("/settings/import-git", data={"git_repo_url": url, "confirm": "yes"}, follow_redirects=False)
    finally:
        git_import.subprocess.run = real
    for resp in (r, r2):
        assert "error=" in resp.headers["location"] and "s3cr3t" not in resp.headers["location"], resp.headers["location"]
    from sqlmodel import select
    with Session(engine) as session:
        rows = session.exec(select(SyncHistory).order_by(SyncHistory.id.desc()).limit(2)).all()
    assert len(rows) == 2 and all("s3cr3t" not in row.message and "deploy:" not in row.message for row in rows), [row.message for row in rows]
    assert any("***@" in row.message for row in rows), "the host stays readable, the credentials do not"
    assert not any("s3cr3t" in admin.get(f"/logs/{row.id}").text for row in rows)
    # a token in the query string is not something _redact can find, so the URL is simply never logged
    class Failed2:
        returncode, stdout, stderr = 128, "", "fatal: repository not found"
    try:
        git_import.subprocess.run = lambda argv, **kw: Failed2()
        admin.post("/settings/import-git", data={"git_repo_url": "https://git.example.invalid/x.git?token=qT0k3n", "confirm": "yes"}, follow_redirects=False)
    finally:
        git_import.subprocess.run = real
    with Session(engine) as session:
        last = session.exec(select(SyncHistory).order_by(SyncHistory.id.desc()).limit(1)).one()
    assert "qT0k3n" not in last.message and "git.example.invalid" not in last.message, last.message
    # a password that appears on its own (not as user:pass@) is blanked too
    assert "***" in git_import._redact("remote: password s3cr3tT0ken rejected", url) and "s3cr3tT0ken" not in git_import._redact("remote: password s3cr3tT0ken rejected", url)
    # a URL without credentials is untouched
    assert git_import._redact("fatal: https://git.example/x.git", "https://git.example/x.git") == "fatal: https://git.example/x.git"


def test_an_upload_that_collides_is_refused_before_anything_is_written():
    reset()
    workspace.store("keep.txt", b"keep")
    calls = []
    workspace.on_listing_change(lambda: calls.append(1))
    try:
        raises(ValueError, workspace.store_many, [("d/f", b"1"), ("d", b"2")])  # a file and a folder of the same name
        raises(ValueError, workspace.store_many, [("d", b"2"), ("d/f", b"1")])
        raises(ValueError, workspace.store_many, [("other", b"2"), ("keep.txt/inside", b"1")])  # parent is an existing file
        raises(ValueError, workspace.unpack_zip, _zip([("d/f", "1"), ("d", "2")]))
        assert tree() == ["keep.txt"] and calls == [], "nothing written, nothing refreshed"
        assert not (WORKSPACE_DIR / "d").exists()
    finally:
        workspace._listeners.clear()


def test_a_write_that_fails_midway_still_refreshes_what_was_written():
    reset()
    calls, refreshes = [], []
    workspace.on_listing_change(lambda: calls.append(1))
    real_store_one, real_refresh = workspace._store_one, workspace.schedule_refresh
    n = {"i": 0}
    def flaky(rel, data, base, mode=None):
        n["i"] += 1
        if n["i"] == 2:
            raise OSError("disk full")
        return real_store_one(rel, data, base, mode)
    workspace._store_one = flaky
    workspace.schedule_refresh = lambda install=False: refreshes.append(install)
    try:
        raises(OSError, workspace.store_many, [("one.txt", b"1"), ("two.txt", b"2")])
    finally:
        workspace._store_one, workspace.schedule_refresh = real_store_one, real_refresh
        workspace._listeners.clear()
    assert tree() == ["one.txt"] and calls == [1] and refreshes == [False], (tree(), calls, refreshes)


def test_long_and_non_ascii_paths_have_saved_copies():
    reset()
    settings_store.set_many({"workspace_history_keep": "2"})
    deep = "/".join(["d" * 20] * 10) + "/" + "é" * 60 + ".txt"  # ~ 330 bytes once percent-encoded
    assert len(deep) <= 300
    v = workspace.store(deep, b"1")
    for n in (2, 3, 4):
        v = workspace.store(deep, str(n).encode(), base=v)
        time.sleep(0.002)
    assert [workspace.version_bytes(deep, x["id"]) for x in workspace.list_versions(deep)] == [b"3", b"2"], "newest two kept, the PATH file is not counted"
    workspace.delete(deep, v)
    assert workspace.deleted_files() == [deep]
    workspace.restore(deep, workspace.list_versions(deep)[0]["id"], "")
    assert workspace.read_file(deep)["text"] == "4", "the delete kept the last contents, and pruned to two copies"
    assert workspace.deleted_files() == []
    # a stray folder in the history area is ignored, not a crash
    (WORKSPACE_HISTORY_DIR / "junk").mkdir()
    assert workspace.deleted_files() == []
    settings_store.set_many({"workspace_history_keep": "20"})


def test_the_host_list_is_dropped_when_files_change():
    import json
    from app.services import inventory
    reset()
    inventory.HOSTS_CACHE_PATH.write_text(json.dumps({"ts": time.time(), "hosts": ["old"], "groups": [], "conn": {}}))
    workspace.store("inventory.yaml", b"all:\n")
    assert not inventory.HOSTS_CACHE_PATH.exists(), "invalidated before store() returned, not by the background thread"
    # a recompute that began before a change must not save its (stale) answer afterwards
    real = inventory._run_ansible_inventory
    def slow_then_changed():
        workspace.store("inventory.yaml", b"all:\n  hosts: {b: {}}\n")
        return {"hosts": ["a"], "groups": [], "conn": {}}
    inventory._run_ansible_inventory = slow_then_changed
    try:
        data = inventory.refresh_hosts_cache()
    finally:
        inventory._run_ansible_inventory = real
    assert data["hosts"] == ["a"] and not inventory.HOSTS_CACHE_PATH.exists(), "stale facts are returned once, never cached"
    inventory._run_ansible_inventory = lambda: {"hosts": ["b"], "groups": [], "conn": {}}
    try:
        assert inventory.refresh_hosts_cache()["hosts"] == ["b"] and inventory.HOSTS_CACHE_PATH.exists(), "an uninterrupted recompute is cached"
    finally:
        inventory._run_ansible_inventory = real
        inventory.HOSTS_CACHE_PATH.unlink(missing_ok=True)


def test_a_failed_swap_puts_the_old_files_back():
    reset()
    workspace.store("old.txt", b"old")
    src = Path(tempfile.mkdtemp(prefix="src-", dir=DATA_DIR))
    (src / "n.txt").write_text("new")
    real = os.rename
    def fail_second(a, b):
        if "ansible.incoming-" in str(a):
            raise OSError("busy")
        return real(a, b)
    os.rename = fail_second
    try:
        raises(OSError, workspace.replace_from, src)
    finally:
        os.rename = real
    assert tree() == ["old.txt"] and workspace.read_file("old.txt")["text"] == "old", "the workspace is back, not missing"
    assert not list(Path(DATA_DIR).glob("ansible.before-import-*")) and not list(Path(DATA_DIR).glob("ansible.incoming-*"))


def test_has_files():
    reset()
    assert workspace.has_files() is False, "no folder yet"
    WORKSPACE_DIR.mkdir()
    assert workspace.has_files() is False, "an empty folder"
    (WORKSPACE_DIR / ".git").mkdir()
    (WORKSPACE_DIR / ".git" / "HEAD").write_text("x")
    os.symlink(Path(DATA_DIR) / "outside.txt", WORKSPACE_DIR / "link")
    (WORKSPACE_DIR / ".ulmo-x.tmp").write_text("x")
    assert workspace.has_files() is False, ".git, symlinks and temp files do not count"
    workspace.store("a/b.txt", b"x")
    assert workspace.has_files() is True


def test_one_digest_for_both_stores():
    from app.services import command_library
    assert command_library.version_of("hello\n") == workspace.version_of(b"hello\n")


# --- second review ---------------------------------------------------------------------------------


def test_import_and_ansible_settings_are_refused_without_a_login():
    """ULMO_DISABLE_AUTH: the Files page writes are off, so the other two ways to change what runs
    (importing a repository, and the Ansible settings that include extra ansible-playbook arguments)
    must be off too."""
    from app.routers import settings as settings_module
    from app.models import SyncHistory
    from app.services import git_import
    from sqlmodel import select
    reset()
    workspace.store("keep.txt", b"keep")
    settings_store.set_many({"extra_args": "", "playbooks_subdir": "playbooks"})
    with Session(engine) as session:
        rows_before = len(session.exec(select(SyncHistory)).all())
    real, real_run = settings_module.AUTH_DISABLED, git_import.subprocess.run
    def must_not_run(*a, **k):
        raise AssertionError("git ran without a login")
    settings_module.AUTH_DISABLED = True
    git_import.subprocess.run = must_not_run
    try:
        r = admin.post("/settings/import-git", data={"git_repo_url": "https://example.invalid/x.git", "confirm": "yes"}, follow_redirects=False)
        assert "error=" in r.headers["location"] and "ULMO_DISABLE_AUTH" in r.headers["location"].replace("%20", " ").replace("+", " ")
        r = admin.post("/settings", data={"extra_args": "-e @/etc/passwd", "playbooks_subdir": "x"}, follow_redirects=False)
        assert "error=" in r.headers["location"]
    finally:
        settings_module.AUTH_DISABLED, git_import.subprocess.run = real, real_run
    with Session(engine) as session:
        assert len(session.exec(select(SyncHistory)).all()) == rows_before, "a refused import is not even recorded"
    assert settings_store.get("extra_args") == "" and settings_store.get("playbooks_subdir") == "playbooks" and tree() == ["keep.txt"]
    # and with a login both work again
    r = admin.post("/settings", data={"extra_args": "--check", "playbooks_subdir": "playbooks"}, follow_redirects=False)
    assert "ok=" in r.headers["location"] and settings_store.get("extra_args") == "--check"
    settings_store.set_many({"extra_args": ""})


def test_a_yaml_typo_is_saved_with_a_warning():
    reset()
    ok = admin.post("/files/save", data={"path": "playbooks/a.yaml", "text": "- hosts: all\n  tasks: []\n", "base": ""}, follow_redirects=False)
    assert "warn=" not in ok.headers["location"] and "ok=Saved" in ok.headers["location"]
    base = workspace.read_file("playbooks/a.yaml")["version"]
    bad = admin.post("/files/save", data={"path": "playbooks/a.yaml", "text": "- hosts: all\n  tasks: [\n", "base": base}, follow_redirects=False)
    assert bad.status_code == 303 and "ok=Saved" in bad.headers["location"] and "warn=" in bad.headers["location"], bad.headers["location"]
    assert workspace.file_bytes("playbooks/a.yaml") == b"- hosts: all\n  tasks: [\n", "the broken text is saved, not refused"
    page = admin.get(bad.headers["location"]).text
    assert "Saved, but playbooks/a.yaml is not valid YAML at line" in page
    # not a warning: Ansible's own tags, several documents, an empty file, non-YAML files
    assert workspace.check_syntax("a.yml", "password: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6162\nx: !unsafe '{{ y }}'\n") is None
    assert workspace.check_syntax("a.yaml", "a: 1\n---\nb: 2\n") is None and workspace.check_syntax("a.yaml", "") is None
    assert workspace.check_syntax("script.sh", "not: [valid yaml") is None and workspace.check_syntax("ansible.cfg", "[defaults\n") is None
    # a real error that Ansible would also reject
    assert "line 2" in workspace.check_syntax("a.yaml", "a: 1\n  b: 2\n")
    assert workspace.check_syntax("a.yaml", "a: !!python/object/apply:os.system ['id']\n"), "unsafe tags are still an error"


def test_a_broken_inventory_keeps_the_last_good_host_list():
    import json
    from app.services import inventory
    reset()
    good = {"_meta": {"hostvars": {"web1": {"ansible_host": "10.0.0.1"}}}, "all": {"children": ["ungrouped"]}, "ungrouped": {"hosts": ["web1"]}}
    class Result:
        def __init__(self, rc, out=""):
            self.returncode, self.stdout, self.stderr = rc, out, "ERROR: could not parse"
    outputs = []
    real = inventory.subprocess.run
    inventory.subprocess.run = lambda *a, **k: outputs.pop(0)
    inventory._last_good = None
    try:
        workspace.store("inventory.yaml", b"all:\n")
        outputs.append(Result(0, json.dumps(good)))
        assert inventory.refresh_hosts_cache()["hosts"] == ["web1"]
        outputs.append(Result(1))  # saved half-way through an edit
        data = inventory.refresh_hosts_cache()
        assert data["hosts"] == ["web1"] and data["conn"]["web1"]["ansible_host"] == "10.0.0.1", "last good facts, not an empty list"
        outputs.append(Result(0, "not json"))
        assert inventory.refresh_hosts_cache()["hosts"] == ["web1"], "unparseable output is a failure too"
        outputs.append(Exception)
        inventory.subprocess.run = lambda *a, **k: (_ for _ in ()).throw(OSError("no ansible-inventory"))
        assert inventory.refresh_hosts_cache()["hosts"] == ["web1"], "a missing binary is a failure too"
    finally:
        inventory.subprocess.run = real
    # no inventory file at all is a real answer: no hosts
    workspace.delete("inventory.yaml", None)
    assert inventory.refresh_hosts_cache()["hosts"] == [], "deleting the inventory empties the list"
    inventory._last_good = None
    inventory.HOSTS_CACHE_PATH.unlink(missing_ok=True)


def test_a_killed_migration_is_retried_not_kept():
    reset()
    shutil.rmtree(LEGACY_REPO_DIR, ignore_errors=True)
    (LEGACY_REPO_DIR / "playbooks").mkdir(parents=True)
    for name in ("a.yaml", "b.yaml", "c.yaml"):
        (LEGACY_REPO_DIR / "playbooks" / name).write_text(name)
    real = shutil.copy2
    n = {"i": 0}
    def die_on_second(src, dst, **kw):
        n["i"] += 1
        if n["i"] == 2:
            raise OSError("killed")
        return real(src, dst, **kw)
    shutil.copy2 = die_on_second
    workspace.logger.disabled = True  # the failure is logged on purpose
    try:
        assert workspace.migrate_legacy_repo() is False, "a failed copy is reported, not raised into startup"
    finally:
        shutil.copy2 = real
        workspace.logger.disabled = False
    assert not WORKSPACE_DIR.exists(), "no half-filled workspace is left to block the retry"
    assert not list(Path(DATA_DIR).glob("ansible.incoming-*"))
    assert workspace.migrate_legacy_repo() is True and len(tree()) == 3, "the next start copies everything"
    shutil.rmtree(LEGACY_REPO_DIR)
    # an empty checkout is not a migration
    reset()
    LEGACY_REPO_DIR.mkdir()
    (LEGACY_REPO_DIR / ".git").mkdir()
    workspace.logger.disabled = True  # the refusal is logged on purpose
    try:
        assert workspace.migrate_legacy_repo() is False and not WORKSPACE_DIR.exists()
    finally:
        workspace.logger.disabled = False
    shutil.rmtree(LEGACY_REPO_DIR)


def test_leftovers_of_a_killed_import_are_removed_at_startup():
    reset()
    junk = [Path(DATA_DIR) / "ansible.incoming-abc123", Path(DATA_DIR) / "ansible-import-xyz789"]
    for j in junk:
        (j / "sub").mkdir(parents=True)
        (j / "sub" / "f").write_text("x")
    workspace.store("keep.txt", b"keep")
    (Path(DATA_DIR) / "ansible.before-import-20260101T000000000000Z").mkdir()
    workspace.clean_leftovers()
    assert not any(j.exists() for j in junk) and tree() == ["keep.txt"]
    assert (Path(DATA_DIR) / "ansible.before-import-20260101T000000000000Z").exists(), "a backup is never cleaned here"
    shutil.rmtree(Path(DATA_DIR) / "ansible.before-import-20260101T000000000000Z")


def test_two_imports_at_once_do_not_trample_each_other():
    """The first import is paused after copying; a second runs to the end; the first then finishes.
    A shared staging folder would have been deleted from under it."""
    reset()
    a, b = (Path(tempfile.mkdtemp(prefix=f"src-{n}-", dir=DATA_DIR)) for n in "ab")
    for n, src in (("a", a), ("b", b)):
        for i in (1, 2, 3):
            (src / f"{n}{i}.txt").write_text(n)
    paused, resume = threading.Event(), threading.Event()
    real = workspace.copy_tree
    calls = {"n": 0}
    def pausing(src, dest):
        count = real(src, dest)
        calls["n"] += 1
        if calls["n"] == 1:
            paused.set()
            resume.wait(5)
        return count
    workspace.copy_tree = pausing
    outcome = {}
    def run_a():
        try:
            outcome["a"] = workspace.replace_from(a)
        except Exception as exc:  # noqa: BLE001
            outcome["a"] = exc
    try:
        ta = threading.Thread(target=run_a)
        ta.start()
        assert paused.wait(5)
        assert workspace.replace_from(b) == 3
        resume.set()
        ta.join(10)
    finally:
        workspace.copy_tree = real
        resume.set()
    assert outcome["a"] == 3, outcome
    assert tree() == ["a1.txt", "a2.txt", "a3.txt"], "the last import wins, whole"
    assert not list(Path(DATA_DIR).glob("ansible.incoming-*"))
    backups = list(Path(DATA_DIR).glob("ansible.before-import-*"))
    assert len(backups) == 1 and sorted(p.name for p in backups[0].iterdir()) == ["b1.txt", "b2.txt", "b3.txt"], "the first import's files were kept, whole"
    for stale in Path(DATA_DIR).glob("ansible.before-import-*"):
        shutil.rmtree(stale)


def test_imports_in_quick_succession_each_keep_a_backup():
    reset()
    srcs = []
    for n in "abc":
        d = Path(tempfile.mkdtemp(prefix=f"src-{n}-", dir=DATA_DIR))
        (d / f"{n}.txt").write_text(n)
        srcs.append(d)
    for d in srcs:  # all within the same second: backup names must not collide
        workspace.replace_from(d)
    assert tree() == ["c.txt"]
    kept = sorted(p / n for p in Path(DATA_DIR).glob("ansible.before-import-*") for n in os.listdir(p))
    assert [k.name for k in kept] == ["a.txt", "b.txt"], kept
    for stale in Path(DATA_DIR).glob("ansible.before-import-*"):
        shutil.rmtree(stale)


def test_the_background_refresh_coalesces_and_survives_errors():
    reset()
    workspace.logger.disabled = True  # the failing pass below is logged on purpose
    real_derived = workspace.refresh_derived
    passes = []
    def slow(install=False):
        passes.append(install)
        time.sleep(0.15)
        if len(passes) == 1:
            raise RuntimeError("boom")  # the first pass fails: the loop must go on and reset itself
        return []
    workspace.refresh_derived = slow
    def settle():
        for _ in range(200):
            with workspace._refresh_lock:
                if not workspace._refresh["running"]:
                    return
            time.sleep(0.02)
        raise AssertionError("the refresh never finished")
    try:
        _real_schedule_refresh(False)
        time.sleep(0.03)
        for _ in range(5):  # a burst while the first pass runs
            _real_schedule_refresh(False)
        _real_schedule_refresh(True)  # the last asks for collections too
        settle()
        assert len(passes) == 2 and passes == [False, True], passes
        passes.clear()
        _real_schedule_refresh(False)  # the loop reset itself after the error and the burst
        settle()
        assert passes == [False]
    finally:
        workspace.refresh_derived = real_derived
        workspace.logger.disabled = False


def test_refresh_derived_and_the_collections_install():
    from app.services import playbook_tags
    reset()
    settings_store.set_many({"playbooks_subdir": "playbooks", "requirements_path": ""})
    workspace.store("playbooks/a.yaml", b"- hosts: all\n")
    calls = []
    real = playbook_tags.refresh_cache, workspace.install_collections
    playbook_tags.refresh_cache = lambda pbs: calls.append(("tags", [p["rel_path"] for p in pbs])) or "WARNING: tag cache"
    workspace.install_collections = lambda: calls.append(("install",)) or "installed"
    try:
        assert workspace.refresh_derived(False) == ["WARNING: tag cache"] and calls == [("tags", ["playbooks/a.yaml"])], "no install unless asked"
        calls.clear()
        assert workspace.refresh_derived(True) == ["installed", "WARNING: tag cache"] and calls[0] == ("install",)
    finally:
        playbook_tags.refresh_cache, workspace.install_collections = real
    # the install itself
    real_run = workspace.subprocess.run
    class Out:
        def __init__(self, rc, out="", err=""):
            self.returncode, self.stdout, self.stderr = rc, out, err
    seen = []
    try:
        assert workspace.install_collections() is None, "no requirements file, nothing to do"
        workspace.store("requirements.yaml", b"collections: []\n")
        workspace.subprocess.run = lambda argv, **kw: seen.append((argv, kw["cwd"])) or Out(0, "Nothing to do.")
        assert workspace.install_collections() == "Nothing to do." and seen[0][0][:4] == ["ansible-galaxy", "collection", "install", "-r"]
        workspace.subprocess.run = lambda argv, **kw: Out(1, "", "no such collection")
        assert workspace.install_collections().startswith("WARNING: collection install from requirements.yaml failed") and "no such collection" in workspace.install_collections()
        def timeout(argv, **kw):
            raise workspace.subprocess.TimeoutExpired(argv, 300)
        workspace.subprocess.run = timeout
        assert workspace.install_collections().startswith("WARNING")
        workspace.subprocess.run = lambda argv, **kw: (_ for _ in ()).throw(FileNotFoundError("ansible-galaxy"))
        assert workspace.install_collections().startswith("WARNING"), "no ansible-galaxy binary is a warning, not a crash"
    finally:
        workspace.subprocess.run = real_run


def test_a_bad_zip_is_a_message_not_a_crash():
    reset()
    enc = bytearray(_zip([("a.txt", "hello")]))
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        enc[enc.find(sig) + off] |= 1  # flag the member as password-protected
    bad = bytearray(_zip([("a.txt", "hello hello hello")], ))
    bad[bad.find(b"hello")] ^= 0xFF  # damage the data
    for data in (bytes(enc), bytes(bad)):
        e = raises(ValueError, workspace.unpack_zip, data)
        assert "a.txt" in str(e), e
        r = admin.post("/files/upload-zip", files={"zip_file": ("a.zip", data)}, follow_redirects=False)
        assert r.status_code == 303 and "error=" in r.headers["location"], r.headers["location"]
    assert tree() == []


def test_a_zip_keeps_the_executable_bit():
    reset()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, mode in (("files/run.sh", 0o755), ("files/plain.conf", 0o600), ("files/none.txt", 0)):
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFREG | mode) << 16 if mode else 0
            zf.writestr(info, "x")
    workspace.unpack_zip(buf.getvalue())
    def mode(rel):
        return stat.S_IMODE((WORKSPACE_DIR / rel).stat().st_mode)
    assert (mode("files/run.sh"), mode("files/plain.conf"), mode("files/none.txt")) == (0o755, 0o644, 0o644)
    # round trip: export, wipe, unpack
    exported = workspace.export_zip()
    reset()
    workspace.unpack_zip(exported)
    assert mode("files/run.sh") == 0o755 and mode("files/plain.conf") == 0o644
    # an edit through the editor keeps it, an upload without a mode on an existing file keeps it too
    workspace.store("files/run.sh", b"#!/bin/sh\n", base=None)
    assert mode("files/run.sh") == 0o755


def test_the_editor_leaves_a_file_you_did_not_change_alone():
    import re
    reset()
    for name, body in (("crlf.conf", b"a=1\r\nb=2\r\n"), ("blank-first.txt", b"\n\nstarts blank\n"), ("lf.txt", b"x\ny\n"), ("mixed.txt", b"a\r\nb\nc\n")):
        workspace.store(name, body)
        page = admin.get("/files/edit", params={"path": name}).text
        base = workspace.read_file(name)["version"]
        # what a browser would submit for an untouched textarea: the value with CRLF line breaks, minus
        # the single newline the HTML parser drops right after <textarea>
        shown = re.search(r'<textarea[^>]*>(.*?)</textarea>', page, re.S).group(1)
        assert shown.startswith("\n"), "an extra newline after the tag, which the parser drops"
        value = shown[1:].replace("&#34;", '"').replace("&#39;", "'").replace("&amp;", "&")
        submitted = value.replace("\r\n", "\n").replace("\n", "\r\n")
        copies_before = len(workspace.list_versions(name))
        r = admin.post("/files/save", data={"path": name, "text": submitted, "base": base}, follow_redirects=False)
        assert r.status_code == 303, name
        assert workspace.file_bytes(name) == body, (name, workspace.file_bytes(name))
        assert len(workspace.list_versions(name)) == copies_before, f"{name}: an unchanged save made a saved copy"
    # a real edit to a CRLF file stays CRLF; a new file is LF
    base = workspace.read_file("crlf.conf")["version"]
    admin.post("/files/save", data={"path": "crlf.conf", "text": "a=1\r\nb=3\r\n", "base": base})
    assert workspace.file_bytes("crlf.conf") == b"a=1\r\nb=3\r\n"
    admin.post("/files/save", data={"path": "new.txt", "text": "one\r\ntwo\r\n", "base": ""})
    assert workspace.file_bytes("new.txt") == b"one\ntwo\n"


def test_move():
    reset()
    workspace.store("playbooks/a.yaml", b"- hosts: all\n", base="")
    workspace.store("playbooks/run.sh", b"#!/bin/sh\n", base="")
    (Path(DATA_DIR) / "ansible" / "playbooks" / "run.sh").chmod(0o755)
    base = workspace.read_file("playbooks/a.yaml")["version"]
    # the edit page offers a move into old/ next to the file
    page = admin.get("/files/edit?path=playbooks/a.yaml").text
    assert 'action="/files/move"' in page and 'value="playbooks/old/a.yaml"' in page
    r = admin.post("/files/move", data={"path": "playbooks/a.yaml", "to": "playbooks/old/a.yaml", "base": base}, follow_redirects=False)
    assert r.status_code == 303 and "Moved" in r.headers["location"], r.headers["location"]
    assert tree() == ["playbooks/old/a.yaml", "playbooks/run.sh"] and workspace.file_bytes("playbooks/old/a.yaml") == b"- hosts: all\n"
    assert workspace.deleted_files() == [], "a moved file does not turn up as deleted"
    # saved copies move with the file (and merge into the target's, if it had any)
    base2 = workspace.read_file("playbooks/old/a.yaml")["version"]
    workspace.store("playbooks/old/a.yaml", b"- hosts: web\n", base=base2)
    assert len(workspace.list_versions("playbooks/old/a.yaml")) == 1
    workspace.move("playbooks/old/a.yaml", "playbooks/a.yaml")
    assert len(workspace.list_versions("playbooks/a.yaml")) == 1 and workspace.list_versions("playbooks/old/a.yaml") == []
    assert workspace.deleted_files() == []
    workspace.move("playbooks/a.yaml", "playbooks/old/a.yaml")
    assert len(workspace.list_versions("playbooks/old/a.yaml")) == 1 and workspace.list_versions("playbooks/a.yaml") == []
    assert workspace.deleted_files() == []
    workspace.store("playbooks/old/a.yaml", b"- hosts: all\n")  # back to the original for the checks below
    # a file already in an old/ folder is offered no further old/
    assert 'value="playbooks/old/a.yaml"' in admin.get("/files/edit?path=playbooks/old/a.yaml").text
    # moving is not editing: the last-edited date stays
    target = Path(DATA_DIR) / "ansible" / "playbooks" / "old" / "a.yaml"
    os.utime(target, (1_600_000_000, 1_600_000_000))
    workspace.move("playbooks/old/a.yaml", "playbooks/a.yaml")
    assert int((Path(DATA_DIR) / "ansible" / "playbooks" / "a.yaml").stat().st_mtime) == 1_600_000_000
    workspace.move("playbooks/a.yaml", "playbooks/old/a.yaml")
    # the exec bit travels; an empty folder left behind is removed
    workspace.move("playbooks/run.sh", "bin/old/run.sh")
    assert stat.S_IMODE((Path(DATA_DIR) / "ansible" / "bin" / "old" / "run.sh").stat().st_mode) == 0o755
    assert "playbooks/run.sh" not in tree()
    workspace.move("bin/old/run.sh", "run.sh")
    assert not (Path(DATA_DIR) / "ansible" / "bin").exists() and (Path(DATA_DIR) / "ansible" / "run.sh").is_file()
    # refusals: an existing target (both files untouched), the same path, a missing file, a bad path,
    # a stale version, a target under a file
    workspace.store("playbooks/b.yaml", b"b", base="")
    for src, dst, base_, want in [
        ("playbooks/b.yaml", "playbooks/old/a.yaml", None, 409),
        ("playbooks/b.yaml", "playbooks/b.yaml", None, 400),
        ("playbooks/nope.yaml", "playbooks/old/n.yaml", None, 400),
        ("playbooks/b.yaml", "../x.yaml", None, 400),
        ("playbooks/b.yaml", "playbooks/old/b.yaml", "0123456789abcdef", 409),
        ("playbooks/b.yaml", "playbooks/b.yaml/inner.yaml", None, 400),
    ]:
        r = admin.post("/files/move", data={"path": src, "to": dst, "base": base_ or ""})
        assert r.status_code == want, (src, dst, r.status_code)
    assert workspace.file_bytes("playbooks/b.yaml") == b"b" and workspace.file_bytes("playbooks/old/a.yaml") == b"- hosts: all\n"
    assert not (Path(DATA_DIR) / "x.yaml").exists()
    # locked while a run is active
    workspace.begin_run(77, "playbooks/b.yaml")
    try:
        assert admin.post("/files/move", data={"path": "playbooks/b.yaml", "to": "playbooks/old/b.yaml"}).status_code == 423
        assert "playbooks/b.yaml" in tree()
        assert 'action="/files/move"' not in admin.get("/files/edit?path=playbooks/b.yaml").text
    finally:
        workspace.end_run(77)


def test_editor_language():
    from app.routers.files import _language
    for rel, text, want in [("playbooks/a.yaml", "", "yaml"), ("a.YML", "", "yaml"), ("files/x.sh", "", "bash"), ("t.conf.j2", "", "ini"), ("ansible.cfg", "", "ini"),
                            ("x.service", "", "ini"), ("files/tool", "#!/bin/bash\n", "bash"), ("files/tool", "#!/usr/bin/env python3\n", "python"),
                            ("files/Caddyfile", "a {\n}\n", ""), ("files/50unattended-upgrades", "x", ""), (".gitignore", "x", ""), ("x.bin", "#!\n", ""), ("README", "", "")]:
        assert _language(rel, text) == want, (rel, _language(rel, text), want)
    reset()
    workspace.store("playbooks/a.yaml", b"- hosts: all\n", base="")
    workspace.store("files/Caddyfile", b"a {\n}\n", base="")
    page = admin.get("/files/edit?path=playbooks/a.yaml").text
    assert 'data-lang="yaml"' in page and "highlight.min.js" in page
    plain = admin.get("/files/edit?path=files/Caddyfile").text
    assert 'data-lang=""' in plain and "highlight.min.js" not in plain
    assert 'data-lang="yaml"' in admin.get("/files/edit?path=playbooks/new.yaml").text, "a new file is coloured by the name typed"


def test_line_numbers():
    reset()
    workspace.store("playbooks/three.yaml", b"- hosts: all\n  tasks: []\n# end\n", base="")
    workspace.store("playbooks/nonl.yaml", b"- hosts: all\n# no newline at the end", base="")
    workspace.store("playbooks/empty.yaml", b"", base="")

    def nums(name):
        m = re.search(r'<pre class="code-nums" aria-hidden="true">(.*?)</pre>', admin.get(f"/playbooks/view?rel_path=playbooks/{name}").text, re.S)
        assert m, f"{name}: no line numbers on the viewer"
        return m.group(1).split("\n")
    assert nums("three.yaml") == ["1", "2", "3"], "a trailing newline does not make a fourth line"
    assert nums("nonl.yaml") == ["1", "2"]
    assert nums("empty.yaml") == ["1"]
    # the editor has the gutter for coloured and plain files alike (the numbers themselves are drawn by the page's script)
    for path in ("playbooks/three.yaml", "playbooks/new.yaml"):
        assert 'id="file-gutter"' in admin.get(f"/files/edit?path={path}").text, path
    workspace.store("files/plain", b"x\n", base="")
    assert 'id="file-gutter"' in admin.get("/files/edit?path=files/plain").text


def test_files_page_groups():
    reset()
    for rel in ["inventory.yaml", "ansible.cfg", "zeta/z.txt", "alpha/a.txt", "files/b.conf", "files/old/c.conf", "files/old/deep/d.conf", "playbooks/site.yaml", "playbooks/old/o.yaml"]:
        workspace.store(rel, b"x", base="")
    groups = workspace.group_files(workspace.list_files(), "playbooks")
    # the top level, the playbooks folder, files, then the rest by name
    assert [g["name"] for g in groups] == ["", "playbooks", "files", "alpha", "zeta"], [g["name"] for g in groups]
    by = {g["name"]: g for g in groups}
    assert [f["label"] for f in by[""]["direct"]] == ["ansible.cfg", "inventory.yaml"] and by[""]["count"] == 2
    assert by["playbooks"]["runs_here"] and not by["files"]["runs_here"] and not by[""]["runs_here"]
    assert [f["label"] for f in by["playbooks"]["direct"]] == ["site.yaml"] and by["playbooks"]["count"] == 2
    old = by["files"]["subs"]
    assert [s["name"] for s in old] == ["old"] and [f["label"] for f in old[0]["files"]] == ["c.conf", "deep/d.conf"]
    assert by["files"]["count"] == 3
    # a different playbooks folder moves the badge; "." means no badge and nothing reordered
    assert [g["name"] for g in workspace.group_files(workspace.list_files(), "zeta")][:3] == ["", "zeta", "files"]
    assert not any(g["runs_here"] for g in workspace.group_files(workspace.list_files(), "."))
    assert [g["name"] for g in workspace.group_files(workspace.list_files(), ".")] == ["", "files", "alpha", "playbooks", "zeta"]
    assert workspace.group_files([], "playbooks") == []
    # the page shows them in that order, with the badge and the collapsed subfolder
    page = admin.get("/files").text
    assert page.index("Top level") < page.index(">playbooks/") < page.index(">files/") < page.index(">alpha/"), "order on the page"
    shown = {f["rel_path"]: f["modified"] for f in workspace.list_files()}
    assert shown["inventory.yaml"].tzinfo is not None and abs(time.time() - shown["inventory.yaml"].timestamp()) < 60
    assert page.count('data-label="Last edited"') == len(shown) and 'class="local-time"' in page, "every file row shows when it was last edited"
    assert page.count("<th>Last edited</th>") == len(workspace.group_files(workspace.list_files()))  # one header row per group
    assert "runs from here" in page and "<summary>old/" in page and "deep/d.conf" in page
    assert "No files yet" not in page
    reset()
    assert "No files yet" in admin.get("/files").text and "Top level" not in admin.get("/files").text


def main():
    init_db()
    auth_module.create_user("admin", "pw-for-tests")
    r = admin.post("/login", data={"username": "admin", "password": "pw-for-tests"}, follow_redirects=False)
    assert r.status_code == 303, "test login failed"
    tests = [v for k, v in sorted(globals().items(), key=lambda kv: list(globals()).index(kv[0])) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print(f"OK: workspace — {len(tests)} checks.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
