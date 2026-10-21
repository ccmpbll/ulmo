"""Self-check for running library commands over SSH (executor, API, roles).

  1. The ssh command is a list (never a local shell), takes address/port/user/key
     from the host entry, sends the remote command as one quoted string after
     `--` under the host's own `timeout`, and refuses a key that was not uploaded.
  2. POST /api/v1/commands is default-deny: the agent's role must include the
     command AND the chosen host must offer it. Parameters are validated, the
     kill switch and caps apply, and an agent reads only its own runs.
  3. Output is capped without losing the exit status, failures and timeouts are
     recorded, stale rows are settled, the result write is retried, history is bounded.
  4. Roles hold command names; deleting a command removes it from roles so a
     re-created name is not silently allowed; missing names are flagged.
  5. Everything is admin-controlled, audited and locked while ULMO_DISABLE_AUTH is set.

Run directly: python3 tests/test_agent_commands.py
"""
import json
import os
import shlex
import shutil
import sys
import tempfile
import threading
import time
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

DATA_DIR = tempfile.mkdtemp(prefix="ulmo-test-")
os.environ["ULMO_DATA_DIR"] = DATA_DIR
os.environ.pop("ULMO_DISABLE_AUTH", None)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

import app.auth as auth_module  # noqa: E402
from app.config import SSH_STORAGE_DIR  # noqa: E402
from app.database import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import AdminAudit, Agent, CommandRun, RoleCommand, utcnow  # noqa: E402
from app.routers import agents as agents_router  # noqa: E402
from app.routers import api as api_module  # noqa: E402
from app.services import agents, command_library as cl, commands  # noqa: E402

SSH_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
for key in ("unraid-key", "ansible-ed25519"):
    (SSH_STORAGE_DIR / key).write_text("not a real key")

LIBRARY = {
    "commands": {
        "restart": {
            "description": "Restart a Docker container",
            "argv": ["docker", "restart", "{container}"],
            "params": {"container": {"type": "enum", "values": ["sonarr", "radarr"]}},
            "risk": "medium",
        },
        "logs": {
            "description": "Show container logs",
            "argv": ["docker", "logs", "--tail={n}", "{container}"],
            "params": {"n": {"type": "int", "min": 1, "max": 500}, "container": {"type": "regex", "pattern": "[a-z0-9_-]+", "max_length": 40}},
        },
        "say": {"description": "Echo", "argv": ["echo", "{text}"], "params": {"text": {"type": "regex", "pattern": ".+", "max_length": 100}}},
        "status": {
            "description": "Service status",
            "argv": ["systemctl", "status", "{unit}"],
            "params": {"unit": {"type": "regex", "pattern": "[a-z0-9@._-]+", "max_length": 60}},
            "sudo": True,
        },
        "hang": {"description": "Takes too long", "argv": ["sleep", "9"], "timeout": 1},
    },
    "hosts": {
        "gandalf": {"address": "10.42.11.10", "port": 22, "user": "root", "ssh_key": "unraid-key", "commands": ["restart", "logs", "say", "hang"]},
        "frodo": {"address": "frodo.lan", "port": 2222, "user": "ansible", "ssh_key": "ansible-ed25519", "commands": ["logs", "say", "status", "hang"]},
        "bare": {"address": "10.0.0.9", "user": "ansible", "commands": ["say"]},
    },
}


def _set_library(data):
    cl.LIBRARY_PATH.write_text(yaml.safe_dump(data, sort_keys=False))
    assert not cl.load()[1], cl.load()[1]


_set_library(LIBRARY)

client = TestClient(app)
admin = TestClient(app)


class FakeStdout:
    def __init__(self, proc):
        self.proc = proc
        self.pos = 0

    def read(self, n):
        if self.proc.behavior.get("hang"):
            self.proc.killed.wait(5)
            return b""
        if self.proc.behavior.get("delay") and self.pos == 0:
            time.sleep(self.proc.behavior["delay"])
        data = self.proc.behavior.get("output", b"done\n")
        chunk = data[self.pos : self.pos + n]
        self.pos += len(chunk)
        return chunk

    def close(self):
        pass


class FakePopen:
    instances: list = []
    behavior: dict = {}

    def __init__(self, cmd, **kw):
        self.cmd, self.kw = cmd, kw
        self.behavior = dict(FakePopen.behavior)
        self.killed = threading.Event()
        self.stdout = FakeStdout(self)
        FakePopen.instances.append(self)

    def kill(self):
        self.killed.set()

    def poll(self):
        return -9 if self.killed.is_set() else self.behavior.get("poll")

    def wait(self):
        return -9 if self.killed.is_set() else self.behavior.get("rc", 0)


commands.subprocess = SimpleNamespace(Popen=FakePopen, PIPE=-1, STDOUT=-2, DEVNULL=-3)
commands.KILL_GRACE = 0  # tests let the local timer be the one that ends a hung fake process


def _remote(cmd):
    """The argument list the host will run, without the timeout wrapper."""
    words = shlex.split(cmd[-1])
    assert words[:3] == ["timeout", "-k", "5"], words
    return words[4:]


def _h(token):
    return {"Authorization": f"Bearer {token}"}


def _post(token, command, host, params=None):
    return client.post("/api/v1/commands", json={"command": command, "host": host, "params": params or {}}, headers=_h(token))


def _wait(run_id):
    for _ in range(300):
        with Session(engine) as session:
            run = session.get(CommandRun, run_id)
        if run.status != "running":
            return run
        time.sleep(0.02)
    raise AssertionError("command run never finished")


def _agent(name, command_names):
    role = agents.create_role(f"role-{name}")
    agents.set_role_commands(role.id, command_names)
    agent, token = agents.create_agent(name)
    agents.assign_role(agent.id, role.id)
    return agent, token, role


def _raises(fn, *args, contains=""):
    try:
        fn(*args)
    except (ValueError, commands.CommandError) as exc:
        assert contains in str(exc), f"{contains!r} not in {exc}"
        return
    raise AssertionError(f"accepted: {args}")


# --- the ssh command ----------------------------------------------------------------------


def test_ssh_command():
    lib = cl.load()[0]
    cmd = commands.ssh_command(lib.hosts["gandalf"], ["docker", "restart", "sonarr"], 30)
    assert cmd[0] == "ssh" and isinstance(cmd, list)
    assert "LogLevel=ERROR" in cmd and "BatchMode=yes" in cmd and "IdentitiesOnly=yes" in cmd
    assert cmd[cmd.index("-p") + 1] == "22" and cmd[cmd.index("-i") + 1] == str(SSH_STORAGE_DIR / "unraid-key")
    assert cmd[-3:] == ["root@10.42.11.10", "--", "timeout -k 5 30 docker restart sonarr"], "the host must enforce the deadline too"

    cmd = commands.ssh_command(lib.hosts["frodo"], ["echo", "a b; id"], 12)
    assert cmd[cmd.index("-p") + 1] == "2222" and cmd[-3:-1] == ["ansible@frodo.lan", "--"]
    assert _remote(cmd) == ["echo", "a b; id"] and cmd[-1].startswith("timeout -k 5 12 ")

    cmd = commands.ssh_command(lib.hosts["bare"], ["uptime"], 5)
    assert "-i" not in cmd and "IdentitiesOnly=yes" not in cmd, "no key named: ssh's own default"

    ghost = cl.Host("ghost", "10.0.0.1", 22, "root", "never-uploaded", [])
    _raises(commands.ssh_command, ghost, ["x"], 5, contains="has not been uploaded")


def test_probe():
    lib = cl.load()[0]
    FakePopen.behavior = {"output": b"ulmo-ok\n", "rc": 0}
    assert commands.probe(lib.hosts["gandalf"]) == (True, "ulmo-ok")
    FakePopen.behavior = {"output": b"root@10.42.11.10: Permission denied (publickey).\n", "rc": 255}
    ok, detail = commands.probe(lib.hosts["gandalf"])
    assert not ok and "Permission denied" in detail
    FakePopen.behavior = {"output": b"", "rc": 255}
    assert not commands.probe(lib.hosts["gandalf"])[0]
    FakePopen.behavior = {}
    ok, detail = commands.probe(cl.Host("ghost", "10.0.0.1", 22, "root", "never-uploaded", []))
    assert not ok and "not been uploaded" in detail


# --- permission ------------------------------------------------------------------------------


def test_default_deny_and_validation():
    FakePopen.instances.clear()
    _, nobody = agents.create_agent("no-role")
    assert _post(nobody, "restart", "gandalf", {"container": "sonarr"}).status_code == 403

    _, token, _ = _agent("limited", ["restart", "logs"])
    for command, host, params, status, contains in [
        ("say", "gandalf", {"text": "x"}, 403, "no permission"),                          # not in the role
        ("restart", "frodo", {"container": "sonarr"}, 403, "frodo does not offer"),        # role has it, host does not
        ("restart", "bare", {"container": "sonarr"}, 403, "bare does not offer"),
        ("restart", "nowhere", {"container": "sonarr"}, 403, "unknown host"),
        ("restart", "all", {"container": "sonarr"}, 403, "unknown host"),
        ("nope", "gandalf", {}, 403, "no permission"),
        ("restart", "gandalf", {"container": "plex"}, 400, "one of"),
        ("restart", "gandalf", {}, 400, "missing parameters"),
        ("restart", "gandalf", {"container": "sonarr", "x": 1}, 400, "unknown parameters"),
        ("logs", "gandalf", {"n": 5, "container": "--all"}, 400, "may not start with '-'"),
        ("logs", "gandalf", {"n": 9999, "container": "a"}, 400, "from 1 to 500"),
    ]:
        r = _post(token, command, host, params)
        assert r.status_code == status and contains in r.json()["detail"], f"{command} {host} {params}: {r.status_code} {r.text}"
    assert client.post("/api/v1/commands", json={"command": "restart"}, headers=_h(token)).status_code == 422
    assert client.post("/api/v1/commands", json={"command": "x" * 61, "host": "gandalf"}, headers=_h(token)).status_code == 422
    assert client.post("/api/v1/commands", json={"command": "restart", "host": "gandalf", "params": {"container": "sonarr"}}).status_code == 401
    assert not FakePopen.instances, "a denied request reached ssh"


def test_changes_to_the_library_take_effect_immediately():
    _, token, _ = _agent("moving", ["restart"])
    assert _post(token, "restart", "gandalf", {"container": "sonarr"}).status_code == 202
    _wait(max(r.id for r in _runs()))

    # The host stops offering the command: the very next call is refused.
    changed = json.loads(json.dumps(LIBRARY))
    changed["hosts"]["gandalf"]["commands"] = ["logs"]
    _set_library(changed)
    try:
        r = _post(token, "restart", "gandalf", {"container": "sonarr"})
        assert r.status_code == 403 and "does not offer" in r.json()["detail"]
        # And a command removed from the library is refused, not a 500.
        changed["hosts"]["gandalf"]["commands"] = []
        del changed["commands"]["restart"]
        _set_library(changed)
        r = _post(token, "restart", "gandalf", {"container": "sonarr"})
        assert r.status_code == 403 and "no longer exists" in r.json()["detail"], r.text
    finally:
        _set_library(LIBRARY)

    # Removed between the permission check and use (an edit lands in the gap).
    real = cl.load
    seen = {"n": 0}

    def load_once():
        seen["n"] += 1
        return real() if seen["n"] == 1 else (cl.Library(), "")

    cl.load = load_once
    try:
        r = _post(token, "restart", "gandalf", {"container": "sonarr"})
    finally:
        cl.load = real
    assert r.status_code == 403 and "just changed" in r.json()["detail"], f"{r.status_code} {r.text}"


def _runs():
    with Session(engine) as session:
        return session.exec(select(CommandRun)).all()


def test_catalog_is_role_intersect_hosts():
    _, token, _ = _agent("cataloged", ["restart", "logs", "status"])
    cat = client.get("/api/v1/catalog", headers=_h(token)).json()
    by_name = {c["command"]: c for c in cat["commands"]}
    assert set(by_name) == {"restart", "logs", "status"}
    assert by_name["restart"]["hosts"] == ["gandalf"]
    assert by_name["logs"]["hosts"] == ["frodo", "gandalf"]
    assert by_name["status"]["hosts"] == ["frodo"]
    assert by_name["restart"]["params"] == {"container": {"type": "enum", "values": ["sonarr", "radarr"]}}
    assert by_name["restart"]["risk"] == "medium" and "argv" not in by_name["restart"], "the command line is not part of the catalog"
    _, none = agents.create_agent("catless")
    assert client.get("/api/v1/catalog", headers=_h(none)).json()["commands"] == []


# --- running ------------------------------------------------------------------------------------


def test_run_success_failure_timeout_truncation():
    _, token, _ = _agent("runner", ["restart", "say", "hang", "status"])
    FakePopen.instances.clear()
    FakePopen.behavior = {"output": b"restarted sonarr\n", "rc": 0}
    r = _post(token, "restart", "gandalf", {"container": "sonarr"})
    assert r.status_code == 202, r.text
    run = _wait(r.json()["id"])
    assert run.status == "success" and run.return_code == 0 and run.output == "restarted sonarr\n"
    proc = FakePopen.instances[-1]
    assert isinstance(proc.cmd, list) and _remote(proc.cmd) == ["docker", "restart", "sonarr"] and "shell" not in proc.kw
    assert proc.kw["stdin"] == -3, "ssh must not be able to read stdin"
    assert "root@10.42.11.10" in proc.cmd
    assert run.triggered_by == "agent:runner" and json.loads(run.params) == {"container": "sonarr"}

    detail = client.get(f"/api/v1/commands/{run.id}", headers=_h(token)).json()
    assert detail["output"] == "restarted sonarr\n" and detail["status"] == "success" and detail["host"] == "gandalf"
    assert detail["command"] == "restart" and detail["line"] == "docker restart sonarr" and detail["started_at"].endswith("+00:00")

    # An injection attempt reaches the remote shell as one quoted word.
    r = _post(token, "say", "gandalf", {"text": "x; touch /tmp/pwned $(id)"})
    _wait(r.json()["id"])
    assert _remote(FakePopen.instances[-1].cmd) == ["echo", "x; touch /tmp/pwned $(id)"]

    FakePopen.behavior = {"output": b"no such container\n", "rc": 3}
    run = _wait(_post(token, "restart", "gandalf", {"container": "radarr"}).json()["id"])
    assert run.status == "failed" and run.return_code == 3

    FakePopen.behavior = {"hang": True}
    start = time.time()
    run = _wait(_post(token, "hang", "gandalf").json()["id"])
    assert run.status == "timeout" and time.time() - start < 4, "timeout should kill the process"
    assert FakePopen.instances[-1].killed.is_set()

    # Big output is truncated, but the command still gets its real exit status.
    FakePopen.behavior = {"output": b"x" * (commands.OUTPUT_CAP * 3 + 500), "rc": 0}
    run = _wait(_post(token, "restart", "gandalf", {"container": "sonarr"}).json()["id"])
    assert len(run.output) < commands.OUTPUT_CAP + 100 and run.output.endswith("[output truncated]")
    assert run.status == "success" and run.return_code == 0, f"large output must not turn success into {run.status}"
    assert not FakePopen.instances[-1].killed.is_set(), "the process must be allowed to finish"
    FakePopen.behavior = {"output": b"y" * (commands.OUTPUT_CAP + 10), "rc": 2}
    run = _wait(_post(token, "restart", "gandalf", {"container": "sonarr"}).json()["id"])
    assert run.status == "failed" and run.return_code == 2

    # The host's own `timeout` ending the command (124 / 137) is a timeout, not a plain failure.
    for rc in (124, 137):
        FakePopen.behavior = {"output": b"", "rc": rc}
        run = _wait(_post(token, "restart", "gandalf", {"container": "sonarr"}).json()["id"])
        assert run.status == "timeout" and run.return_code == rc

    # A key that was never uploaded fails before anything is recorded.
    bad = json.loads(json.dumps(LIBRARY))
    bad["hosts"]["gandalf"]["ssh_key"] = "missing-key"
    _set_library(bad)
    try:
        n, recorded = len(FakePopen.instances), len(_runs())
        r = _post(token, "restart", "gandalf", {"container": "sonarr"})
        assert r.status_code == 502 and "has not been uploaded" in r.json()["detail"]
        assert len(FakePopen.instances) == n and len(_runs()) == recorded
    finally:
        _set_library(LIBRARY)

    # sudo, and the connection details of another host.
    FakePopen.behavior = {"output": b"ok", "rc": 0}
    run = _wait(_post(token, "status", "frodo", {"unit": "ssh"}).json()["id"])
    cmd = FakePopen.instances[-1].cmd
    assert "ansible@frodo.lan" in cmd and cmd[cmd.index("-p") + 1] == "2222"
    assert _remote(cmd) == ["sudo", "-n", "systemctl", "status", "ssh"]
    FakePopen.behavior = {}


def test_runs_are_private_to_their_agent():
    _, mine, _ = _agent("owner-cmd", ["restart"])
    _, other, _ = _agent("other-cmd", ["restart"])
    run_id = _post(mine, "restart", "gandalf", {"container": "sonarr"}).json()["id"]
    _wait(run_id)
    assert client.get(f"/api/v1/commands/{run_id}", headers=_h(other)).status_code == 404
    assert client.get("/api/v1/commands/999999", headers=_h(mine)).status_code == 404

    # Deleting an agent detaches its history, so a reused id inherits nothing.
    with Session(engine) as session:
        agent = session.exec(select(Agent).where(Agent.name == "owner-cmd")).one()
    agents.delete_agent(agent.id)
    with Session(engine) as session:
        assert session.get(CommandRun, run_id).agent_id is None


def test_kill_switch_and_caps():
    _, token, _ = _agent("capped", ["restart", "hang"])
    agents.set_runs_enabled(False)
    try:
        assert _post(token, "restart", "gandalf", {"container": "sonarr"}).status_code == 503
        assert client.get("/api/v1/runs", headers=_h(token)).status_code == 200
    finally:
        agents.set_runs_enabled(True)

    FakePopen.behavior = {"hang": True}
    hang = cl.load()[0].commands["hang"]
    hang.timeout = 60  # keep the runs "running" while we count them
    saved = (api_module.MAX_COMMAND_RUNS, api_module.MAX_COMMANDS_PER_HOST)
    api_module.MAX_COMMAND_RUNS, api_module.MAX_COMMANDS_PER_HOST = 3, 2
    held = []
    try:
        for _ in range(2):
            r = _post(token, "hang", "gandalf")
            assert r.status_code == 202, r.text
            held.append(r.json()["id"])
        assert _post(token, "hang", "gandalf").status_code == 429, "per-host cap"
        r = _post(token, "hang", "frodo")
        assert r.status_code == 202
        held.append(r.json()["id"])
        assert _post(token, "hang", "frodo").status_code == 429, "global cap"
    finally:
        api_module.MAX_COMMAND_RUNS, api_module.MAX_COMMANDS_PER_HOST = saved
        for proc in FakePopen.instances:
            proc.killed.set()
        hang.timeout = 1
        FakePopen.behavior = {}
    for run_id in held:
        _wait(run_id)


def test_executor_housekeeping():
    # Stuck rows are settled and stop counting against the caps.
    with Session(engine) as session:
        old = CommandRun(command="restart", host="stuckhost", status="running", started_at=utcnow() - commands.STALE_AFTER - timedelta(minutes=1))
        fresh = CommandRun(command="restart", host="stuckhost", status="running")
        session.add(old)
        session.add(fresh)
        session.commit()
        session.refresh(old)
        session.refresh(fresh)
    assert commands.running("stuckhost") == 1
    with Session(engine) as session:
        assert session.get(CommandRun, old.id).status == "error" and session.get(CommandRun, fresh.id).status == "running"
        row = session.get(CommandRun, fresh.id)
        row.status = "success"
        session.add(row)
        session.commit()
    with Session(engine) as session:
        run = CommandRun(command="restart", host="gandalf", status="running")
        session.add(run)
        session.commit()
        session.refresh(run)
    commands.settle_stale(timedelta(0), "ulmo restarted while this was running")
    with Session(engine) as session:
        r = session.get(CommandRun, run.id)
        assert r.status == "error" and r.finished_at is not None and "restarted" in r.output

    # The result write is retried; only the newest rows are kept.
    with Session(engine) as session:
        run = CommandRun(command="restart", host="gandalf")
        session.add(run)
        session.commit()
        session.refresh(run)
    real, calls = commands.Session, {"n": 0}

    def flaky(*a, **kw):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise RuntimeError("database is locked")
        return real(*a, **kw)

    commands.Session = flaky
    sleep = commands.time.sleep
    commands.time.sleep = lambda s: None
    try:
        commands._finish(run.id, "success", 0, "fine")
    finally:
        commands.Session = real
        commands.time.sleep = sleep
    with Session(engine) as session:
        assert session.get(CommandRun, run.id).status == "success"

    keep = commands.KEEP_RUNS
    commands.KEEP_RUNS = 3
    try:
        ids = []
        for _ in range(6):
            with Session(engine) as session:
                r = CommandRun(command="restart", host="gandalf")
                session.add(r)
                session.commit()
                session.refresh(r)
                ids.append(r.id)
            commands._finish(ids[-1], "success", 0, "z" * 100)
    finally:
        commands.KEEP_RUNS = keep
    left = {r.id for r in _runs()}
    assert set(ids[-3:]) <= left and not set(ids[:2]) & left

    # A timer that fires after the process already exited does not overrule it.
    with Session(engine) as session:
        run = CommandRun(command="restart", host="gandalf")
        session.add(run)
        session.commit()
        session.refresh(run)
    FakePopen.behavior = {"poll": 0, "delay": 0.8, "output": b"ok\n", "rc": 0}
    try:
        commands._execute(run.id, ["ssh", "x"], 0.2)
    finally:
        FakePopen.behavior = {}
    with Session(engine) as session:
        done = session.get(CommandRun, run.id)
    assert done.status == "success" and not FakePopen.instances[-1].killed.is_set()


# --- roles and the Agents page -------------------------------------------------------------------


def test_roles_hold_command_names():
    role = agents.create_role("namer")
    assert agents.set_role_commands(role.id, ["say", "restart", "say", " "]) == ["restart", "say"]
    assert agents.role_commands(role.id) == ["restart", "say"]
    _raises(agents.set_role_commands, role.id, ["ghost"], contains="Not in the command library")
    _raises(agents.set_role_commands, 999999, ["say"], contains="Unknown role")
    assert agents.role_commands(role.id) == ["restart", "say"], "a rejected change must not apply"
    assert agents.set_role_commands(role.id, []) == [] and agents.role_commands(role.id) == []

    # Deleting a command removes it from roles, so a new command with that name is not allowed to them.
    agent, token, role = _agent("renamed", ["say"])
    assert _post(token, "say", "bare", {"text": "x"}).status_code == 202
    _wait(max(r.id for r in _runs()))
    agents.forget_command("say")
    assert agents.role_commands(role.id) == []
    assert _post(token, "say", "bare", {"text": "x"}).status_code == 403
    agents.delete_role(role.id)
    with Session(engine) as session:
        assert session.exec(select(RoleCommand).where(RoleCommand.role_id == role.id)).first() is None


def test_agents_page_roles_ui():
    role = agents.create_role("ui-role")
    r = admin.post(f"/roles/{role.id}/commands", data={"commands": ["restart", "logs"]}, follow_redirects=False)
    assert r.status_code == 303 and agents.role_commands(role.id) == ["logs", "restart"]
    page = admin.get("/agents").text
    assert "Commands this role may use (2)" in page and "runs on gandalf" in page
    assert "frodo, gandalf" in page, "where logs runs"

    r = admin.post(f"/roles/{role.id}/commands", data={"commands": ["ghost"]})
    assert r.status_code == 400 and "Not in the command library" in r.text

    # A command that vanished from the library is flagged, and saving drops it.
    with Session(engine) as session:
        session.add(RoleCommand(role_id=role.id, command="vanished"))
        session.commit()
    assert "vanished is no longer in the command library" in admin.get("/agents").text
    admin.post(f"/roles/{role.id}/commands", data={"commands": ["logs"]})
    assert agents.role_commands(role.id) == ["logs"]

    with Session(engine) as session:
        actions = [a.action for a in session.exec(select(AdminAudit)).all()]
    assert "set role commands" in actions

    agents_router.AUTH_DISABLED = True
    try:
        r = admin.post(f"/roles/{role.id}/commands", data={"commands": ["restart"]})
        assert r.status_code == 400 and "ULMO_DISABLE_AUTH" in r.text
    finally:
        agents_router.AUTH_DISABLED = False
    assert agents.role_commands(role.id) == ["logs"]

    _, token = agents.create_agent("cmd-intruder")
    r = client.post(f"/roles/{role.id}/commands", data={"commands": ["restart"]}, headers=_h(token), follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert agents.role_commands(role.id) == ["logs"]


def main():
    init_db()
    auth_module.create_user("admin", "pw-for-tests")
    r = admin.post("/login", data={"username": "admin", "password": "pw-for-tests"}, follow_redirects=False)
    assert r.status_code == 303 and admin.get("/agents").status_code == 200, "test login failed"
    test_ssh_command()
    test_probe()
    test_default_deny_and_validation()
    test_changes_to_the_library_take_effect_immediately()
    test_catalog_is_role_intersect_hosts()
    test_run_success_failure_timeout_truncation()
    test_runs_are_private_to_their_agent()
    test_kill_switch_and_caps()
    test_executor_housekeeping()
    test_roles_hold_command_names()
    test_agents_page_roles_ui()
    print("OK: library commands run over a quoted ssh argv, need role AND host, and are default-deny.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
