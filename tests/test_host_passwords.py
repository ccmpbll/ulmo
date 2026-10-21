"""Self-check for hosts that sign in with a password instead of an SSH key.

  1. A host's sign-in mode (key or password) is validated; a password host has no key.
  2. A password is kept in the database only: never in commands.yml, its saved copies or its
     download, never in a page, the change log, the request log or an API answer.
  3. Saving is safe: a new password host must have a password, a blank field keeps the saved one,
     switching to a key forgets it, deleting the host forgets it, and nothing changes while login
     is disabled.
  4. ssh is run through `sshpass -e` with the password in its environment, never in its
     arguments, with the right options; key hosts are unchanged; a missing password, a missing
     sshpass and a rejected password each give a clear message.

Run directly: python3 tests/test_host_passwords.py
"""
import json
import os
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace

DATA_DIR = tempfile.mkdtemp(prefix="ulmo-test-")
os.environ["ULMO_DATA_DIR"] = DATA_DIR
os.environ.pop("ULMO_DISABLE_AUTH", None)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

import app.auth as auth_module  # noqa: E402
from app.config import SSH_STORAGE_DIR  # noqa: E402
from app.database import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import AdminAudit, AgentAudit, HostPassword  # noqa: E402
from app.routers import command_admin  # noqa: E402
from app.services import agents, command_library as cl, commands, host_secrets  # noqa: E402

SSH_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
(SSH_STORAGE_DIR / "k1").write_text("not a real key")
PW = "p@ss w0rd $HOME 'q' \"dq\" \\ ; |&`x`#é"  # spaces and everything a shell would eat

client = TestClient(app)
admin = TestClient(app)


class FakeStdout:
    def __init__(self, proc):
        self.proc, self.pos = proc, 0

    def read(self, n):
        data = self.proc.behavior.get("output", b"ok\n")
        chunk = data[self.pos : self.pos + n]
        self.pos += len(chunk)
        return chunk

    def close(self):
        pass


class FakePopen:
    instances: list = []
    behavior: dict = {}

    def __init__(self, cmd, **kw):
        self.cmd, self.kw, self.behavior = cmd, kw, dict(FakePopen.behavior)
        self.killed = threading.Event()
        self.stdout = FakeStdout(self)
        FakePopen.instances.append(self)

    def kill(self):
        self.killed.set()

    def poll(self):
        return None

    def wait(self):
        return self.behavior.get("rc", 0)


commands.subprocess = SimpleNamespace(Popen=FakePopen, PIPE=-1, STDOUT=-2, DEVNULL=-3)
commands.shutil = SimpleNamespace(which=lambda name: f"/usr/bin/{name}")  # pretend sshpass is installed
commands.KILL_GRACE = 0


def _form(c, url, **data):
    return c.post(url, data=data, follow_redirects=False)


def _base():
    return cl.current_version()


def _host_form(**kw):
    data = dict(name="gandalf", address="10.42.11.10", port="22", user="root", auth="password", password=PW, original="", base=_base())
    data.update(kw)
    return data


def _secrets_everywhere() -> str:
    """Everything the password must not appear in, as one string."""
    parts = [cl.LIBRARY_PATH.read_text() if cl.LIBRARY_PATH.exists() else ""]
    for f in (cl.HISTORY_DIR.glob("*.yml") if cl.HISTORY_DIR.exists() else []):
        parts.append(f.read_text())
    for path in ("/commands", "/commands/download", "/agents", "/activity?tab=changes", "/activity?tab=requests", "/activity?tab=commands"):
        parts.append(admin.get(path).text)
    with Session(engine) as session:
        parts += [f"{a.action} {a.detail}" for a in session.exec(select(AdminAudit)).all()]
        parts += [f"{a.path} {a.detail}" for a in session.exec(select(AgentAudit)).all()]
    return "\n".join(parts)


def _reset():
    cl.LIBRARY_PATH.unlink(missing_ok=True)
    shutil.rmtree(cl.HISTORY_DIR, ignore_errors=True)
    cl._state.update(fingerprint=None, library=cl.Library(), error="")
    with Session(engine) as session:
        for row in session.exec(select(HostPassword)).all():
            session.delete(row)
        session.commit()


def _raises(fn, *args, contains=""):
    try:
        fn(*args)
    except (ValueError, commands.CommandError) as exc:
        assert contains in str(exc), f"{contains!r} not in {exc}"
        return
    raise AssertionError(f"accepted: {args}")


# --- the library ----------------------------------------------------------------------


def test_sign_in_mode_is_validated():
    base = {"address": "10.0.0.1", "user": "root"}
    assert cl.parse_host("a", base, set()).auth == "key"
    assert cl.parse_host("a", {**base, "auth": "password"}, set()).auth == "password"
    assert cl.parse_host("a", {**base, "auth": "key", "ssh_key": "k1"}, set()).ssh_key == "k1"
    for bad, contains in [({"auth": "kerberos"}, "key or password"), ({"auth": ""}, "key or password"), ({"auth": None}, "key or password"),
                          ({"auth": "password", "ssh_key": "k1"}, "not both"), ({"auth": True}, "key or password")]:
        _raises(cl.parse_host, "a", {**base, **bad}, set(), contains=contains)
    _raises(cl.parse_host, "a", {**base, "password": "x"}, set(), contains="unknown keys")  # the secret has no place in the file


# --- keeping the password out of everything else ------------------------------------------


def test_password_is_stored_only_in_the_database():
    _reset()
    cl.save_command("uptime", {"description": "d", "argv": ["uptime"]})
    r = _form(admin, "/commands/hosts", **_host_form(commands="uptime"))
    assert r.status_code == 303, admin.get("/commands").text[:300]
    host = cl.load()[0].hosts["gandalf"]
    assert host.auth == "password" and host.ssh_key == "" and host.commands == ["uptime"]
    assert "auth: password" in cl.LIBRARY_PATH.read_text()
    assert host_secrets.get("gandalf") == PW, "kept exactly as typed"

    # Change the host so there are saved copies that could have leaked it, then look everywhere.
    _form(admin, "/commands/hosts", **_host_form(original="gandalf", password="", commands="uptime", port="2222"))
    cl.save_command("other", {"description": "d2", "argv": ["df"]})
    everything = _secrets_everywhere()
    for piece in (PW, "w0rd", "p@ss"):
        assert piece not in everything, f"password fragment {piece!r} leaked"
    assert "password" in everything and cl.list_versions(), "(there are saved copies to have leaked it)"

    page = admin.get("/commands?host=gandalf").text
    assert "saved: leave blank to keep it" in page and 'name="password"' in page and "value=" + '"' + PW not in page
    assert 'type="password"' in page
    assert "<td class=\"muted\">password" in page and "none saved" not in page


def test_saving_rules():
    _reset()
    cl.save_command("uptime", {"description": "d", "argv": ["uptime"]})
    # A new password host must come with a password.
    r = _form(admin, "/commands/hosts", **_host_form(password=""))
    assert r.status_code == 400 and "Enter the password" in r.text and "gandalf" not in cl.load()[0].hosts
    for bad in ("line\nbreak", "carriage\rreturn", "nul\0byte", "x" * 257):
        r = _form(admin, "/commands/hosts", **_host_form(password=bad))
        assert r.status_code == 400 and "one line" in r.text, repr(bad)[:30]
        assert "gandalf" not in cl.load()[0].hosts and host_secrets.get("gandalf") is None
    assert _form(admin, "/commands/hosts", **_host_form(auth="kerberos")).status_code == 400
    assert _form(admin, "/commands/hosts", **_host_form(ssh_key="k1")).status_code == 303, "an ignored key field does not block a password host"
    assert cl.load()[0].hosts["gandalf"].ssh_key == "" and host_secrets.get("gandalf") == PW

    # Editing: blank keeps, a new value replaces.
    r = _form(admin, "/commands/hosts", **_host_form(original="gandalf", password="", port="2200"))
    assert r.status_code == 303, "a blank password on an existing password host is not an error"
    assert cl.load()[0].hosts["gandalf"].port == 2200 and host_secrets.get("gandalf") == PW
    r = _form(admin, "/commands/hosts", **_host_form(original="gandalf", password="new-pw"))
    assert r.status_code == 303 and host_secrets.get("gandalf") == "new-pw"

    # Rejected saves leave the stored password alone.
    r = _form(admin, "/commands/hosts", **_host_form(original="gandalf", password="other", address="-oProxy"))
    assert r.status_code == 400 and host_secrets.get("gandalf") == "new-pw", "a refused save must not change the secret"
    r = _form(admin, "/commands/hosts", **_host_form(original="gandalf", password="other", base="stale"))
    assert r.status_code == 400 and host_secrets.get("gandalf") == "new-pw"

    # Switching to a key forgets the password; the page then says so.
    r = _form(admin, "/commands/hosts", **_host_form(original="gandalf", auth="key", ssh_key="k1", password=""))
    assert r.status_code == 303
    host = cl.load()[0].hosts["gandalf"]
    assert host.auth == "key" and host.ssh_key == "k1" and host_secrets.get("gandalf") is None
    assert "auth:" not in cl.LIBRARY_PATH.read_text(), "key hosts stay as they were written before"
    # A password host with no password saved shows it.
    cl.save_host("nopw", {"address": "10.0.0.5", "user": "root", "auth": "password"})
    assert "none saved" in admin.get("/commands").text

    # Deleting the host forgets the password.
    _form(admin, "/commands/hosts", **_host_form(name="doomed", original="", password="to-delete"))
    assert host_secrets.get("doomed") == "to-delete"
    assert _form(admin, "/commands/hosts/doomed/delete").status_code == 303
    assert host_secrets.get("doomed") is None

    # Nothing changes while login is disabled.
    command_admin.AUTH_DISABLED = True
    try:
        before = (cl.LIBRARY_PATH.read_text(), host_secrets.get("gandalf"))
        r = _form(admin, "/commands/hosts", **_host_form(name="locked", password="sneaky"))
        assert r.status_code == 400 and "ULMO_DISABLE_AUTH" in r.text
        r = _form(admin, "/commands/hosts", **_host_form(original="gandalf", auth="password", password="sneaky"))
        assert r.status_code == 400
    finally:
        command_admin.AUTH_DISABLED = False
    assert (cl.LIBRARY_PATH.read_text(), host_secrets.get("gandalf")) == before and host_secrets.get("locked") is None

    # An agent token reaches none of it.
    _, token = agents.create_agent("pw-intruder")
    r = client.post("/commands/hosts", data=_host_form(name="evil", password="x"), headers={"Authorization": f"Bearer {token}"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login") and host_secrets.get("evil") is None
    assert host_secrets.hosts_with_password() <= {"nopw"} | {"gandalf"}


def test_secret_store():
    _reset()
    host_secrets.set_password("h", "one")
    host_secrets.set_password("h", "two")
    assert host_secrets.get("h") == "two" and host_secrets.hosts_with_password() == {"h"}
    host_secrets.clear("h")
    host_secrets.clear("h")  # clearing twice is fine
    assert host_secrets.get("h") is None and host_secrets.hosts_with_password() == set()
    for bad in ("", "a\nb", "x" * 257):
        _raises(host_secrets.set_password, "h", bad, contains="")
    assert host_secrets.check("x" * 256) == "x" * 256


# --- ssh ---------------------------------------------------------------------------------------


def test_ssh_uses_sshpass_with_the_password_in_the_environment():
    host = cl.Host("gandalf", "10.42.11.10", 2222, "root", "", ["uptime"], "password")
    host_secrets.set_password("gandalf", PW)
    cmd, env = commands.ssh_command(host, ["uptime"], 30), commands.ssh_env(host)
    assert cmd[:3] == ["sshpass", "-e", "ssh"], cmd[:4]
    for option in ("BatchMode=no", "PreferredAuthentications=password,keyboard-interactive", "PubkeyAuthentication=no", "NumberOfPasswordPrompts=1",
                   "StrictHostKeyChecking=accept-new", "LogLevel=ERROR"):
        assert option in cmd, option
    assert "-i" not in cmd and "IdentitiesOnly=yes" not in cmd and "BatchMode=yes" not in cmd
    assert cmd[cmd.index("-p") + 1] == "2222" and cmd[-3:-1] == ["root@10.42.11.10", "--"]
    assert not any(PW in part or "w0rd" in part for part in cmd), "the password must never be an argument"
    assert env["SSHPASS"] == PW and env["PATH"] == os.environ["PATH"], "exactly as typed, alongside the normal environment"

    # Key hosts are as before: no sshpass, no environment change.
    key_host = cl.Host("k", "10.0.0.1", 22, "ansible", "k1", [], "key")
    kcmd = commands.ssh_command(key_host, ["uptime"], 30)
    assert kcmd[0] == "ssh" and "BatchMode=yes" in kcmd and "IdentitiesOnly=yes" in kcmd and commands.ssh_env(key_host) is None

    # Clear messages for the three ways it can fail.
    _raises(commands.ssh_env, cl.Host("nopw", "10.0.0.2", 22, "root", "", [], "password"), contains="no password has been saved")
    real = commands.shutil
    commands.shutil = SimpleNamespace(which=lambda name: None)
    try:
        _raises(commands.ssh_command, host, ["uptime"], 30, contains="needs sshpass")
        ok, detail = commands.probe(host)
        assert not ok and "needs sshpass" in detail
        assert commands.ssh_command(key_host, ["uptime"], 30)[0] == "ssh", "key hosts do not need sshpass"
    finally:
        commands.shutil = real
    ok, detail = commands.probe(cl.Host("nopw", "10.0.0.2", 22, "root", "", [], "password"))
    assert not ok and "no password has been saved" in detail

    FakePopen.instances.clear()
    FakePopen.behavior = {"output": b"Permission denied, please try again.\n", "rc": 5}
    ok, detail = commands.probe(host)
    assert not ok and "password was rejected" in detail and PW not in detail
    assert FakePopen.instances[-1].kw["env"]["SSHPASS"] == PW and FakePopen.instances[-1].cmd[0] == "sshpass"
    FakePopen.behavior = {"output": b"ulmo-ok\n", "rc": 0}
    assert commands.probe(host) == (True, "ulmo-ok")
    FakePopen.behavior = {}


def test_running_a_command_on_a_password_host():
    _reset()
    cl.save_command("say", {"description": "d", "argv": ["echo", "{text}"], "params": {"text": {"type": "regex", "pattern": ".+", "max_length": 100}}})
    _form(admin, "/commands/hosts", **_host_form(commands="say"))
    _form(admin, "/commands/hosts", **_host_form(name="withkey", address="10.0.0.7", auth="key", ssh_key="k1", password="", commands="say"))
    role = agents.create_role("pw-role")
    agents.set_role_commands(role.id, ["say"])
    agent, token = agents.create_agent("pw-agent")
    agents.assign_role(agent.id, role.id)
    h = {"Authorization": f"Bearer {token}"}

    FakePopen.instances.clear()
    FakePopen.behavior = {"output": b"hello\n", "rc": 0}
    r = client.post("/api/v1/commands?wait=5", json={"command": "say", "host": "gandalf", "params": {"text": "hi"}}, headers=h)
    assert r.status_code == 200 and r.json()["status"] == "success" and r.json()["output"] == "hello\n", r.text
    proc = FakePopen.instances[-1]
    assert proc.cmd[:3] == ["sshpass", "-e", "ssh"] and proc.kw["env"]["SSHPASS"] == PW
    assert not any(PW in str(part) for part in proc.cmd)
    for text in (r.text, client.get(f"/api/v1/commands/{r.json()['id']}", headers=h).text, client.get("/api/v1/catalog", headers=h).text):
        assert PW not in text and "w0rd" not in text, "an API answer must never carry the password"

    r = client.post("/api/v1/commands?wait=5", json={"command": "say", "host": "withkey", "params": {"text": "hi"}}, headers=h)
    assert r.status_code == 200 and FakePopen.instances[-1].cmd[0] == "ssh" and FakePopen.instances[-1].kw.get("env") is None

    # No password saved: refused before anything runs.
    host_secrets.clear("gandalf")
    n = len(FakePopen.instances)
    r = client.post("/api/v1/commands?wait=5", json={"command": "say", "host": "gandalf", "params": {"text": "hi"}}, headers=h)
    assert r.status_code == 502 and "no password has been saved" in r.json()["detail"] and len(FakePopen.instances) == n
    FakePopen.behavior = {}
    assert PW not in _secrets_everywhere()


def main():
    init_db()
    auth_module.create_user("admin", "pw-for-tests")
    r = admin.post("/login", data={"username": "admin", "password": "pw-for-tests"}, follow_redirects=False)
    assert r.status_code == 303 and admin.get("/commands").status_code == 200, "test login failed"
    test_sign_in_mode_is_validated()
    test_password_is_stored_only_in_the_database()
    test_saving_rules()
    test_secret_store()
    test_ssh_uses_sshpass_with_the_password_in_the_environment()
    test_running_a_command_on_a_password_host()
    print("OK: password hosts keep the password out of the file, the pages and the logs, and run through sshpass -e.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
