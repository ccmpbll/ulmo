"""Self-check for the public key ulmo writes next to every private key it stores.

Playbooks read the public key from the control node (a `file` lookup of `<key>.pub` for
ansible.posix.authorized_key), and the Settings page only ever took the private half, so that lookup
failed. Now saving a key also writes `<name>.pub`, and:

  1. It is made from the private key with ssh-keygen, for OpenSSH and PEM keys, also when the browser
     sent CRLF line endings; the private key stays 0600 and the .pub is 0644.
  2. A key that cannot be read (a passphrase, garbage) is still saved, with a reason, and no .pub is
     left behind; saving a key under an old name replaces or removes the old .pub, never leaves a
     public key that belongs to the previous private key.
  3. Deleting a key deletes its .pub; a key cannot be named "x.pub" (that is another key's public file).
  4. At startup, keys saved before this had no .pub get one; a .pub that holds a different key (or is empty)
     is replaced, one that holds the same key (with its own comment, say) is left alone, in the backfill and
     when a key is saved again.
  5. Nothing in that work can stop the app starting or the upload: a folder in the way, a comment that is not
     UTF-8, a key that cannot be read all come back as a reason. The file is written whole or not at all.
  6. The upload route says whether the public key was created, under the name the key was saved as.

Run directly: python3 tests/test_ssh_public_key.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DATA_DIR = str(Path(tempfile.mkdtemp(prefix="ulmo-test-")).resolve())
os.environ["ULMO_DATA_DIR"] = DATA_DIR
os.environ["ULMO_DISABLE_AUTH"] = "true"  # the login check short-circuits; the upload route has no other guard
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from app.config import SSH_STORAGE_DIR  # noqa: E402
from app.main import app  # noqa: E402
from app.services import scheduler, ssh_keys, workspace  # noqa: E402

workspace.schedule_refresh = lambda install=False: None  # the background refresh is tested in test_workspace.py

client = TestClient(app)
GEN = Path(tempfile.mkdtemp(prefix="ulmo-keygen-"))


def make_key(name: str, *args: str, comment: bytes | None = None) -> str:
    """A real private key made by ssh-keygen, as text (with the CRLF-free newline the file has)."""
    path = GEN / name
    path.unlink(missing_ok=True)
    subprocess.run(["ssh-keygen", "-q", "-f", str(path), "-C", comment if comment is not None else f"{name}@test".encode(), *args], check=True)
    return path.read_text()


def save(name: str, text: str):
    """save_key, giving back only the reason the public key could not be made (None = it was)."""
    return ssh_keys.save_key(name, text)[1]


def public_of(text: str) -> str:
    path = GEN / "probe"
    path.write_text(text)
    path.chmod(0o600)
    return subprocess.run(["ssh-keygen", "-y", "-f", str(path)], check=True, capture_output=True, text=True, errors="replace").stdout


def pub(name: str) -> Path:
    return SSH_STORAGE_DIR / f"{name}.pub"


def mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_public_key_is_written_next_to_the_private_key():
    ed = make_key("ed", "-t", "ed25519", "-N", "")
    assert save("ansible-ed25519", ed) is None, "no warning when the public key was made"
    assert pub("ansible-ed25519").read_text() == public_of(ed)
    assert pub("ansible-ed25519").read_text().startswith("ssh-ed25519 ")
    assert mode(SSH_STORAGE_DIR / "ansible-ed25519") == 0o600 and mode(pub("ansible-ed25519")) == 0o644

    rsa = make_key("rsa", "-t", "rsa", "-b", "2048", "-m", "PEM", "-N", "")
    assert rsa.startswith("-----BEGIN RSA PRIVATE KEY-----")
    assert save("old-rsa", rsa) is None
    assert pub("old-rsa").read_text().startswith("ssh-rsa ") and pub("old-rsa").read_text() == public_of(rsa)

    # a browser posts a textarea with CRLF line endings
    crlf = make_key("crlf", "-t", "ed25519", "-N", "")
    assert save("from-browser", crlf.replace("\n", "\r\n")) is None
    assert pub("from-browser").read_text() == public_of(crlf)

    assert [k["filename"] for k in ssh_keys.list_keys()] == ["ansible-ed25519", "from-browser", "old-rsa"], "the .pub files are not listed as keys"


def test_unreadable_key_is_saved_with_a_reason_and_leaves_no_public_key():
    locked = make_key("locked", "-t", "ed25519", "-N", "correct horse")
    started = time.monotonic()
    warning = save("with-passphrase", locked)
    assert time.monotonic() - started < 8, "ssh-keygen must not wait for a passphrase"
    assert warning and "passphrase" in warning, warning
    assert (SSH_STORAGE_DIR / "with-passphrase").exists() and not pub("with-passphrase").exists()

    junk = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
    warning = save("junk", junk)
    assert warning and "correct horse" not in warning and "ssh-keygen" in warning and "invalid format" in warning, warning  # the cause, not a bare "could not read"
    assert (SSH_STORAGE_DIR / "junk").exists() and not pub("junk").exists()


def test_saving_again_never_leaves_the_old_public_key():
    first = make_key("one", "-t", "ed25519", "-N", "")
    second = make_key("two", "-t", "ed25519", "-N", "")
    assert public_of(first) != public_of(second)
    ssh_keys.save_key("swap", first)
    ssh_keys.save_key("swap", second)
    assert pub("swap").read_text() == public_of(second), "the .pub must follow the new private key"

    ssh_keys.save_key("swap", make_key("locked2", "-t", "ed25519", "-N", "pw"))  # no public key can be made now
    assert not pub("swap").exists(), "a .pub of the previous private key must not stay behind"


def test_delete_and_names():
    ssh_keys.save_key("gone", make_key("gone", "-t", "ed25519", "-N", ""))
    assert pub("gone").exists()
    ssh_keys.delete_key("gone")
    assert not (SSH_STORAGE_DIR / "gone").exists() and not pub("gone").exists()

    try:
        ssh_keys.save_key("shadow.pub", make_key("shadow", "-t", "ed25519", "-N", ""))
    except ValueError as exc:
        assert ".pub" in str(exc)
    else:
        raise AssertionError('a key named "x.pub" would collide with the public key of "x"')


def test_ssh_keygen_failing_to_run_is_reported_and_leaves_no_stale_public_key():
    ssh_keys.save_key("flaky", make_key("fl", "-t", "ed25519", "-N", ""))
    assert pub("flaky").exists()
    replacement = make_key("fl2", "-t", "ed25519", "-N", "")  # made before subprocess.run is replaced
    real, seen = subprocess.run, []

    def broken(args, **kw):
        seen.append((args, kw))
        raise subprocess.TimeoutExpired(args, 10)

    subprocess.run = broken
    try:
        warning = save("flaky", replacement)
    finally:
        subprocess.run = real
    assert warning and "did not run" in warning, warning
    assert not pub("flaky").exists(), "a .pub of the previous private key must not stay behind"
    args, kw = seen[0]
    assert args[:2] == ["ssh-keygen", "-y"] and args[args.index("-P") + 1] == "" and kw["stdin"] == subprocess.DEVNULL, \
        "an empty -P and no stdin, so a key with a passphrase fails at once instead of prompting on a terminal"
    assert kw["timeout"] <= 30


def test_startup_backfill():
    ed = make_key("legacy", "-t", "ed25519", "-N", "")
    (SSH_STORAGE_DIR / "legacy").write_text(ed)  # stored by an older release: no .pub
    (SSH_STORAGE_DIR / "legacy").chmod(0o600)
    (SSH_STORAGE_DIR / "locked-legacy").write_text(make_key("ll", "-t", "ed25519", "-N", "pw"))
    (SSH_STORAGE_DIR / "locked-legacy").chmod(0o600)

    # a .pub the operator made by hand: the same key with their own comment stays as it is
    mine = make_key("mine", "-t", "ed25519", "-N", "")
    ssh_keys.save_key("kept", mine)
    own = public_of(mine).split()[0] + " " + public_of(mine).split()[1] + " operator@laptop\n"
    pub("kept").write_text(own)
    # a .pub that holds another key (the private key was replaced under an older release) or nothing is replaced
    ssh_keys.save_key("stale", mine)
    pub("stale").write_text(public_of(make_key("other", "-t", "ed25519", "-N", "")))
    ssh_keys.save_key("hollow", mine)
    pub("hollow").write_text("")

    import logging

    records: list = []
    handler = logging.Handler()
    handler.emit = records.append
    logging.getLogger("ulmo.ssh_keys").addHandler(handler)
    logging.getLogger("ulmo.ssh_keys").setLevel(logging.INFO)
    try:
        made = ssh_keys.ensure_public_keys()
    finally:
        logging.getLogger("ulmo.ssh_keys").removeHandler(handler)
    said = [r.getMessage() for r in records]
    assert any(m.startswith("Made the public key of:") and "legacy" in m for m in said), f"startup should say what it made: {said}"
    assert {"hollow", "legacy", "stale"} <= set(made) and "kept" not in made and "locked-legacy" not in made, made
    assert pub("legacy").read_text() == public_of(ed)
    assert pub("kept").read_text() == own, "the same key with the operator's comment is not rewritten"
    assert pub("stale").read_text() == public_of(mine), "a public key of another private key must go"
    assert pub("hollow").read_text() == public_of(mine), "an empty file is not 'done'"
    assert not pub("locked-legacy").exists()
    assert ssh_keys.ensure_public_keys() == [], "nothing left to do the second time"

    # saving a key again follows the same rule
    ssh_keys.save_key("kept", mine)
    assert pub("kept").read_text() == own


def test_startup_never_removes_a_public_key_because_ssh_keygen_failed():
    # the private key did not change, so a .pub that is there may well be right: only a save may remove it
    hand_made = "ssh-ed25519 AAAAmadebyhand operator@laptop\n"
    (SSH_STORAGE_DIR / "protected").write_text(make_key("pr", "-t", "ed25519", "-N", "pw"))
    (SSH_STORAGE_DIR / "protected").chmod(0o600)
    pub("protected").write_text(hand_made)  # made by hand with the passphrase
    (SSH_STORAGE_DIR / "slow").write_text(make_key("sl", "-t", "ed25519", "-N", ""))
    (SSH_STORAGE_DIR / "slow").chmod(0o600)
    ssh_keys._sync_public_key(SSH_STORAGE_DIR / "slow")
    slow_pub = pub("slow").read_text()

    real = subprocess.run

    def timing_out(args, **kw):
        raise subprocess.TimeoutExpired(args, 10)

    subprocess.run = timing_out  # a busy host, or no ssh-keygen at all
    try:
        made = ssh_keys.ensure_public_keys()
    finally:
        subprocess.run = real
    assert made == [], made
    assert pub("protected").read_text() == hand_made and pub("slow").read_text() == slow_pub, "a good .pub was deleted at startup"
    ssh_keys.ensure_public_keys()
    assert pub("protected").read_text() == hand_made, "and not for a key with a passphrase either"

    # saving is different: the private key has just changed, so a .pub that is left would be the old key's
    assert ssh_keys.save_key("protected", make_key("pr2", "-t", "ed25519", "-N", "pw"))[1]
    assert not pub("protected").exists()


def test_a_key_that_cannot_be_read_says_why():
    key = SSH_STORAGE_DIR / "loose"
    key.write_text(make_key("loose", "-t", "ed25519", "-N", ""))
    key.chmod(0o644)  # a restored backup: ssh refuses a private key others can read
    changed, reason = ssh_keys._sync_public_key(key)
    assert not changed and reason and "ssh-keygen" in reason and "permissions" in reason.lower(), reason
    assert ssh_keys.ensure_public_keys() == [], "a key that cannot be read is skipped, not fatal"
    assert not pub("loose").exists()


def test_failures_in_the_public_key_step_never_escape():
    good = make_key("good", "-t", "ed25519", "-N", "")
    # a folder where the .pub should go: the write fails, and says so
    pub("blocked").mkdir()
    name, reason = ssh_keys.save_key("blocked", good)
    assert name == "blocked" and reason and "blocked.pub" in reason, reason
    assert (SSH_STORAGE_DIR / "blocked").exists(), "the private key is saved anyway"
    (SSH_STORAGE_DIR / "blocked-too").write_text(good)
    (SSH_STORAGE_DIR / "blocked-too").chmod(0o600)
    pub("blocked-too").mkdir()
    (SSH_STORAGE_DIR / "after").write_text(good)  # sorts after the failing ones: still made
    (SSH_STORAGE_DIR / "after").chmod(0o600)
    made = ssh_keys.ensure_public_keys()  # must not raise
    assert "after" in made and "blocked-too" not in made, made
    shutil.rmtree(pub("blocked"))
    shutil.rmtree(pub("blocked-too"))

    # a comment that is not UTF-8 (the byte is a Latin-1 e-acute)
    latin = make_key("latin", "-t", "ed25519", "-N", "", comment=b"caf\xe9@laptop")
    assert save("latin-comment", latin) is None
    written = pub("latin-comment").read_text()
    assert written.startswith("ssh-ed25519 ") and written.split()[1] == public_of(latin).split()[1]

    # the folder itself cannot be listed
    real_list = ssh_keys.list_keys

    def denied():
        raise PermissionError("simulated")

    ssh_keys.list_keys = denied
    try:
        assert ssh_keys.ensure_public_keys() == []
    finally:
        ssh_keys.list_keys = real_list


def test_the_public_key_is_written_whole_or_not_at_all():
    good = make_key("atomic", "-t", "ed25519", "-N", "")
    save("atomic", good)
    assert sorted(p.name for p in SSH_STORAGE_DIR.iterdir() if "atomic" in p.name) == ["atomic", "atomic.pub"], "no temporary file is left"

    # the temporary file of a write that was cut short is not a key, and the real .pub is untouched
    leftover = SSH_STORAGE_DIR / ".atomic.pub.tmp"
    leftover.write_text("ssh-ed25519 AAAA")
    assert ".atomic.pub.tmp" not in [k["filename"] for k in ssh_keys.list_keys()]
    leftover.unlink()

    # the file is replaced in one step: a failure while writing leaves the old one as it was
    old = pub("atomic").read_text()
    real_replace, calls = os.replace, []

    def failing(src, dst):
        calls.append((Path(src).name, Path(dst).name))
        raise PermissionError("simulated")

    other = make_key("atomic2", "-t", "ed25519", "-N", "")
    os.replace = failing
    try:
        (SSH_STORAGE_DIR / "atomic").write_text(other)
        changed, reason = ssh_keys._sync_public_key(SSH_STORAGE_DIR / "atomic")
    finally:
        os.replace = real_replace
    assert not changed and reason and calls == [(".atomic.pub.tmp", "atomic.pub")], (reason, calls)
    assert pub("atomic").read_text() == old, "a failed write must leave the old file, not a half-written one"
    assert not (SSH_STORAGE_DIR / ".atomic.pub.tmp").exists(), "and clean up after itself"


def test_startup_makes_missing_public_keys():
    ed = make_key("boot", "-t", "ed25519", "-N", "")
    (SSH_STORAGE_DIR / "from-last-release").write_text(ed)
    (SSH_STORAGE_DIR / "from-last-release").chmod(0o600)
    real_start, real_shutdown, real_links = scheduler.start, scheduler.scheduler.shutdown, ssh_keys.ensure_symlinks
    scheduler.start = lambda: None
    scheduler.scheduler.shutdown = lambda wait=False: None
    ssh_keys.ensure_symlinks = lambda: []  # the real one repoints /root/.ssh, which is live when the tests run inside the container
    try:
        with TestClient(app):  # runs the app's startup
            pass
    finally:
        scheduler.start, scheduler.scheduler.shutdown, ssh_keys.ensure_symlinks = real_start, real_shutdown, real_links
    assert pub("from-last-release").read_text() == public_of(ed)


def test_upload_route_says_what_happened():
    def post(text, name):
        resp = client.post("/settings/ssh-key", data={"filename": name, "private_key": text}, follow_redirects=False)
        assert resp.status_code == 303
        return parse_qs(urlparse(resp.headers["location"]).query)

    ok = post(make_key("r1", "-t", "ed25519", "-N", ""), "via-route")
    assert 'SSH key "via-route" saved' in ok["ok"][0] and "via-route.pub" in ok["ok"][0], ok
    assert pub("via-route").exists()

    # the message names the file that was written, not what was typed
    typed = post(make_key("r4", "-t", "ed25519", "-N", ""), "  keys/typed  ")
    assert 'SSH key "typed" saved' in typed["ok"][0] and "typed.pub" in typed["ok"][0] and "keys/" not in typed["ok"][0], typed
    assert pub("typed").exists()

    # a public key that could not be made is a problem, not a success bar
    warn = post(make_key("r2", "-t", "ed25519", "-N", "pw"), "via-route-locked")
    assert "ok" not in warn and 'SSH key "via-route-locked" saved' in warn["error"][0], warn
    assert "public key could not be created" in warn["error"][0] and "passphrase" in warn["error"][0], warn
    assert not pub("via-route-locked").exists()

    refused = post(make_key("r3", "-t", "ed25519", "-N", ""), "bad.pub")
    assert "error" in refused and ".pub" in refused["error"][0]


def main():
    assert shutil.which("ssh-keygen"), "these tests need ssh-keygen (openssh-client)"
    SSH_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    SSH_STORAGE_DIR.chmod(0o700)
    test_public_key_is_written_next_to_the_private_key()
    test_unreadable_key_is_saved_with_a_reason_and_leaves_no_public_key()
    test_saving_again_never_leaves_the_old_public_key()
    test_delete_and_names()
    test_ssh_keygen_failing_to_run_is_reported_and_leaves_no_stale_public_key()
    test_startup_backfill()
    test_startup_never_removes_a_public_key_because_ssh_keygen_failed()
    test_a_key_that_cannot_be_read_says_why()
    test_failures_in_the_public_key_step_never_escape()
    test_the_public_key_is_written_whole_or_not_at_all()
    test_startup_makes_missing_public_keys()
    test_upload_route_says_what_happened()
    print("OK: every saved SSH key gets a matching public key file, and it never goes stale.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
        shutil.rmtree(GEN, ignore_errors=True)
