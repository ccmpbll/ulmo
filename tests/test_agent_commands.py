"""Self-check for command templates and the SSH executor (phase 3).

  1. Template files are validated strictly: every malformed shape is rejected
     with a reason, and a file that stops parsing keeps its last good version.
  2. An agent's parameter values are checked against their declared types, and
     can never become shell syntax or an extra option: values stay one literal
     element of the argument list, survive shlex round-tripping, and cannot
     start with "-" unless the template allows it.
  3. The ssh command is a list (never a local shell), takes address/port/user/
     key from the inventory (or the template's overrides), sends the remote
     command as one quoted string after `--`, and refuses unsafe inventory values.
  4. POST /api/v1/commands is default-deny, validates parameters, honours the
     kill switch and the concurrency caps, and an agent can read only its own
     command runs.
  5. Output is capped, failures and timeouts are recorded, and orphaned runs are
     settled on startup.
  6. Command grants are managed on the Agents page, audited, locked while
     ULMO_DISABLE_AUTH is set, and removed with their role.

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
from pathlib import Path
from types import SimpleNamespace

DATA_DIR = tempfile.mkdtemp(prefix="ulmo-test-")
os.environ["ULMO_DATA_DIR"] = DATA_DIR
os.environ.pop("ULMO_DISABLE_AUTH", None)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

import app.auth as auth_module  # noqa: E402
from app.config import REPO_DIR, SSH_STORAGE_DIR  # noqa: E402
from app.database import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import AdminAudit, Agent, CommandGrant, CommandRun  # noqa: E402
from app.routers import agents as agents_router  # noqa: E402
from app.routers import api as api_module  # noqa: E402
from app.services import agents, command_templates as ct, commands, inventory  # noqa: E402

HOSTS = ["web1", "web2", "db1"]
CONN = {
    "web1": {"address": "10.0.0.1", "port": "22", "user": "ansible", "key": "/home/ansible/.ssh/ansible-ed25519"},
    "web2": {"address": "10.0.0.2", "port": "22", "user": "ansible", "key": "/home/ansible/.ssh/ansible-ed25519"},
    "db1": {"address": "db1.lan", "port": "2222", "user": "dba", "key": ""},
    "evil1": {"address": "-oProxyCommand=touch_pwned", "port": "22", "user": "ansible", "key": ""},
    "evil2": {"address": "10.0.0.9", "port": "22", "user": "{{ lookup('pipe','id') }}", "key": ""},
    "evil3": {"address": "10.0.0.9 -v", "port": "22", "user": "ansible", "key": ""},
    "evil4": {"address": "10.0.0.9", "port": "22; id", "user": "ansible", "key": ""},
}
inventory.list_hosts = lambda: HOSTS
inventory.list_groups = lambda: ["all", "ungrouped"]
inventory.host_conn = lambda h: CONN.get(h)

TEMPLATES = REPO_DIR / ct.TEMPLATES_REL
TEMPLATES.mkdir(parents=True)
FILES = {
    "restart.yml": """
description: Restart a Docker container
argv: [docker, restart, "{container}"]
params:
  container: {type: enum, values: [sonarr, radarr]}
risk: medium
""",
    "logs.yml": """
description: Show container logs
argv: [docker, logs, "--tail={n}", "{container}"]
params:
  n: {type: int, min: 1, max: 500}
  container: {type: regex, pattern: "[a-z0-9_-]+", max_length: 40}
""",
    "say.yml": """
description: Echo some text
argv: [echo, "{text}"]
params:
  text: {type: regex, pattern: ".+", max_length: 100}
""",
    "status.yml": """
description: Service status
argv: [systemctl, status, "{unit}"]
params:
  unit: {type: regex, pattern: "[a-z0-9@._-]+", max_length: 60}
sudo: true
ssh_user: svc
ssh_key: svc-key
""",
    "hang.yml": """
description: Takes too long
argv: [sleep, "9"]
timeout: 1
""",
    "broken.yml": "description: x\nargv: []\n",
}
for name, text in FILES.items():
    (TEMPLATES / name).write_text(text)

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


def _post(token, template, host, params=None):
    return client.post("/api/v1/commands", json={"template": template, "host": host, "params": params or {}}, headers=_h(token))


def _wait(run_id):
    for _ in range(300):
        with Session(engine) as session:
            run = session.get(CommandRun, run_id)
        if run.status != "running":
            return run
        time.sleep(0.02)
    raise AssertionError("command run never finished")


def _agent(name, grants):
    """grants: {template: [hosts]}"""
    role = agents.create_role(f"role-{name}")
    for template, hosts in grants.items():
        agents.add_command_grant(role.id, template, hosts)
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


# --- templates -----------------------------------------------------------------


def test_parse_accepts_good_and_rejects_bad_templates():
    t = ct.parse("ok", FILES["logs.yml"])
    assert t.argv == ["docker", "logs", "--tail={n}", "{container}"] and t.timeout == 30 and not t.sudo
    assert ct.parse("s", FILES["status.yml"]).ssh_key == "svc-key"

    base = "description: d\nargv: [echo, hi]\n"
    for text, why in [
        ("- not a mapping", "not a mapping"),
        (base + "surprise: 1\n", "unknown key"),
        ("argv: [echo]\n", "description required"),
        ("description: d\nargv: []\n", "empty argv"),
        ("description: d\nargv: echo hi\n", "argv as a string"),
        ("description: d\nargv: [echo, 5]\n", "non-string token"),
        ("description: d\nargv: ['{cmd}', x]\nparams: {cmd: {type: enum, values: [a]}}\n", "placeholder as the command"),
        ("description: d\nargv: [echo, '{x']\n", "stray brace"),
        ("description: d\nargv: [echo, '}{']\n", "stray brace 2"),
        ("description: d\nargv: [echo, '{undeclared}']\n", "undeclared param"),
        ("description: d\nargv: [echo]\nparams: {x: {type: enum, values: [a]}}\n", "unused param"),
        ("description: d\nargv: [echo, '{x}']\nparams: {x: {type: nope}}\n", "unknown type"),
        ("description: d\nargv: [echo, '{x}']\nparams: {x: {type: enum, values: []}}\n", "empty enum"),
        ("description: d\nargv: [echo, '{x}']\nparams: {x: {type: enum, values: [a, a]}}\n", "duplicate enum"),
        ("description: d\nargv: [echo, '{x}']\nparams: {x: {type: enum, values: [a], extra: 1}}\n", "unknown param key"),
        ("description: d\nargv: [echo, '{x}']\nparams: {x: {type: int, min: 1}}\n", "int without max"),
        ("description: d\nargv: [echo, '{x}']\nparams: {x: {type: int, min: 5, max: 1}}\n", "min > max"),
        ("description: d\nargv: [echo, '{x}']\nparams: {x: {type: int, min: true, max: 3}}\n", "bool bound"),
        ("description: d\nargv: [echo, '{x}']\nparams: {x: {type: regex}}\n", "regex without pattern"),
        ("description: d\nargv: [echo, '{x}']\nparams: {x: {type: regex, pattern: '['}}\n", "bad regex"),
        ("description: d\nargv: [echo, '{x}']\nparams: {x: {type: regex, pattern: a, max_length: 9999}}\n", "huge max_length"),
        (base + "timeout: 0\n", "timeout 0"),
        (base + "timeout: 301\n", "timeout too big"),
        (base + "timeout: true\n", "timeout bool"),
        (base + "sudo: yes please\n", "sudo not bool"),
        (base + "risk: extreme\n", "bad risk"),
        (base + "ssh_user: 'a b'\n", "bad ssh_user"),
        (base + "ssh_key: ../../etc/passwd\n", "ssh_key path"),
        (base + "ssh_key: a/b\n", "ssh_key with slash"),
        (base + "ssh_key: ..\n", "ssh_key dotdot"),
    ]:
        try:
            ct.parse("t", text)
        except ValueError:
            continue
        raise AssertionError(f"template accepted: {why}")
    try:
        ct.parse("bad name!", base)
    except ValueError:
        pass
    else:
        raise AssertionError("bad template id accepted")


def test_parameter_validation():
    logs = ct.parse("logs", FILES["logs.yml"])
    assert ct.validate_params(logs, {"n": 50, "container": "sonarr"}) == {"n": "50", "container": "sonarr"}
    for params, contains in [
        ({"n": 50}, "missing parameters: container"),
        ({"n": 50, "container": "a", "extra": 1}, "unknown parameters: extra"),
        ({"n": "50", "container": "a"}, "whole number"),
        ({"n": True, "container": "a"}, "whole number"),
        ({"n": 50.0, "container": "a"}, "whole number"),
        ({"n": 0, "container": "a"}, "from 1 to 500"),
        ({"n": 501, "container": "a"}, "from 1 to 500"),
        ({"n": 5, "container": ""}, "non-empty"),
        ({"n": 5, "container": 7}, "non-empty"),
        ({"n": 5, "container": "x" * 41}, "at most 40"),
        ({"n": 5, "container": "UPPER"}, "pattern"),
        ({"n": 5, "container": "a b"}, "pattern"),
        ({"n": 5, "container": "a;b"}, "pattern"),
        ({"n": 5, "container": "a\n"}, "pattern"),
        ({"n": 5, "container": "-rf"}, "may not start with '-'"),  # the pattern allows it; the dash rule stops it
    ]:
        _raises(ct.validate_params, logs, params, contains=contains)
    _raises(ct.validate_params, logs, ["not", "a", "dict"], contains="object")

    restart = ct.parse("restart", FILES["restart.yml"])
    assert ct.validate_params(restart, {"container": "radarr"}) == {"container": "radarr"}
    for bad in ("plex", "sonarr ", ["sonarr"], None, 1):
        _raises(ct.validate_params, restart, {"container": bad}, contains="one of")

    numeric = ct.parse("n", "description: d\nargv: [echo, '{x}']\nparams: {x: {type: enum, values: ['1', '2']}}\n")
    assert ct.validate_params(numeric, {"x": "1"}) == {"x": "1"}
    for wrong_type in (1, 1.0, True, ["1"]):
        _raises(ct.validate_params, numeric, {"x": wrong_type}, contains="one of")

    # Option injection: a free-text value may not start with "-" unless the template says so.
    say = ct.parse("say", FILES["say.yml"])
    _raises(ct.validate_params, say, {"text": "--privileged"}, contains="may not start with '-'")
    _raises(ct.validate_params, say, {"text": "bad\nline"}, contains="pattern")
    dash_ok = ct.parse("d", "description: d\nargv: [echo, '{t}']\nparams: {t: {type: regex, pattern: '.+', allow_leading_dash: true}}\n")
    assert ct.validate_params(dash_ok, {"t": "-n"}) == {"t": "-n"}

    # Anchoring: the pattern must match the whole value, not a prefix.
    _raises(ct.validate_params, logs, {"n": 5, "container": "ok!"}, contains="pattern")


def test_values_stay_one_literal_argument():
    say = ct.parse("say", FILES["say.yml"])
    evil = ["; rm -rf /", "$(id)", "`id`", "a && b", "x | y", "it's", 'say "hi"', "a\\b", "*", "~", "a b  c", "${HOME}", "#comment", "é ü 日本"]
    for value in evil:
        values = ct.validate_params(say, {"text": value})
        argv = ct.build_argv(say, values)
        assert argv == ["echo", value], argv
        assert shlex.split(shlex.join(argv)) == argv, f"{value!r} does not survive quoting"

    logs = ct.parse("logs", FILES["logs.yml"])
    assert ct.build_argv(logs, ct.validate_params(logs, {"n": 7, "container": "plex"})) == ["docker", "logs", "--tail=7", "plex"]
    status = ct.parse("status", FILES["status.yml"])
    assert ct.build_argv(status, {"unit": "ssh"}) == ["sudo", "-n", "systemctl", "status", "ssh"]


def test_loader_keeps_last_good_version():
    templates, errors = ct.load()
    assert {"restart", "logs", "say", "status", "hang"} <= set(templates)
    assert "broken" not in templates and "broken.yml" in errors

    (TEMPLATES / "restart.yml").write_text("description: x\nargv: []\n")  # now invalid
    templates, errors = ct.load()
    assert templates["restart"].argv == ["docker", "restart", "{container}"], "last good version should stay"
    assert "restart.yml" in errors

    (TEMPLATES / "restart.yml").write_text(FILES["restart.yml"].replace("medium", "high"))
    templates, errors = ct.load()
    assert templates["restart"].risk == "high" and "restart.yml" not in errors

    (TEMPLATES / "extra.yml").write_text("description: new\nargv: [uptime]\n")
    assert "extra" in ct.load()[0]
    (TEMPLATES / "extra.yml").unlink()
    assert "extra" not in ct.load()[0]

    (TEMPLATES / "huge.yml").write_text("description: " + "x" * 30000 + "\nargv: [uptime]\n")
    templates, errors = ct.load()
    assert "huge" not in templates and "huge.yml" in errors
    (TEMPLATES / "huge.yml").unlink()
    ct.load()


# --- the ssh command -----------------------------------------------------------


def test_ssh_command():
    restart = ct.parse("restart", FILES["restart.yml"])
    cmd = commands.ssh_command(restart, "web1", ["docker", "restart", "sonarr"])
    assert cmd[0] == "ssh" and isinstance(cmd, list)
    assert "LogLevel=ERROR" in cmd, "ssh's own notices must not end up in the command output"
    assert "BatchMode=yes" in cmd and "-p" in cmd and cmd[cmd.index("-p") + 1] == "22"
    assert cmd[cmd.index("-i") + 1] == "/home/ansible/.ssh/ansible-ed25519"
    assert cmd[-3:] == ["ansible@10.0.0.1", "--", "timeout -k 5 30 docker restart sonarr"], "the host must enforce the deadline too"

    cmd = commands.ssh_command(restart, "db1", ["echo", "a b; id"])
    assert "-i" not in cmd and cmd[cmd.index("-p") + 1] == "2222"
    assert cmd[-3:] == ["dba@db1.lan", "--", "timeout -k 5 30 echo 'a b; id'"], cmd[-3:]
    assert _remote(cmd) == ["echo", "a b; id"]

    status = ct.parse("status", FILES["status.yml"])  # overrides user and key
    cmd = commands.ssh_command(status, "web1", ["systemctl", "status", "ssh"])
    assert cmd[-3].startswith("svc@") and cmd[cmd.index("-i") + 1] == str(SSH_STORAGE_DIR / "svc-key")

    _raises(commands.ssh_command, restart, "ghost", ["x"], contains="not in the inventory")
    for host in ("evil1", "evil2", "evil3", "evil4"):
        _raises(commands.ssh_command, restart, host, ["x"], contains="unusable")


# --- the API ---------------------------------------------------------------------


def test_default_deny_and_validation():
    FakePopen.instances.clear()
    _, nobody = agents.create_agent("no-grants")
    assert _post(nobody, "restart", "web1", {"container": "sonarr"}).status_code == 403

    _, token, _ = _agent("limited", {"restart": ["web1"], "logs": ["web1", "web2"]})
    for template, host, params, status, contains in [
        ("say", "web1", {"text": "x"}, 403, "no grant"),
        ("restart", "web2", {"container": "sonarr"}, 403, "host not granted"),
        ("restart", "db1", {"container": "sonarr"}, 403, "host not granted"),
        ("restart", "all", {"container": "sonarr"}, 403, "host not granted"),
        ("restart", "web1", {"container": "plex"}, 400, "one of"),
        ("restart", "web1", {}, 400, "missing parameters"),
        ("restart", "web1", {"container": "sonarr", "x": 1}, 400, "unknown parameters"),
        ("logs", "web1", {"n": 5, "container": "--all"}, 400, "may not start with '-'"),
        ("logs", "web1", {"n": 9999, "container": "a"}, 400, "from 1 to 500"),
    ]:
        r = _post(token, template, host, params)
        assert r.status_code == status and contains in r.json()["detail"], f"{template} {host} {params}: {r.status_code} {r.text}"
    assert client.post("/api/v1/commands", json={"template": "restart"}, headers=_h(token)).status_code == 422
    assert client.post("/api/v1/commands", json={"template": "x" * 61, "host": "web1"}, headers=_h(token)).status_code == 422
    assert client.post("/api/v1/commands", json={"template": "restart", "host": "web1", "params": {"container": "sonarr"}}).status_code == 401
    assert not FakePopen.instances, "a denied request reached ssh"

    # A grant for a template whose file was later broken/removed stops working.
    (TEMPLATES / "say.yml").unlink()
    ct.load()
    _, token2, _ = _agent("orphan", {"logs": ["web1"]})
    (TEMPLATES / "logs.yml").unlink()
    try:
        r = _post(token2, "logs", "web1", {"n": 5, "container": "a"})
        assert r.status_code == 403 and "not loaded" in r.json()["detail"]
    finally:
        (TEMPLATES / "logs.yml").write_text(FILES["logs.yml"])
        (TEMPLATES / "say.yml").write_text(FILES["say.yml"])
        ct.load()


def test_run_success_failure_timeout_truncation():
    _, token, _ = _agent("runner", {"restart": ["web1"], "say": ["web1"], "hang": ["web1"], "status": ["web1"]})
    FakePopen.instances.clear()
    FakePopen.behavior = {"output": b"restarted sonarr\n", "rc": 0}
    r = _post(token, "restart", "web1", {"container": "sonarr"})
    assert r.status_code == 202, r.text
    run = _wait(r.json()["id"])
    assert run.status == "success" and run.return_code == 0 and run.output == "restarted sonarr\n"
    proc = FakePopen.instances[-1]
    assert isinstance(proc.cmd, list) and _remote(proc.cmd) == ["docker", "restart", "sonarr"] and "shell" not in proc.kw
    assert proc.kw["stdin"] == -3, "ssh must not be able to read stdin"
    assert run.triggered_by == "agent:runner" and json.loads(run.params) == {"container": "sonarr"}

    detail = client.get(f"/api/v1/commands/{run.id}", headers=_h(token)).json()
    assert detail["output"] == "restarted sonarr\n" and detail["status"] == "success" and detail["host"] == "web1"
    assert detail["command"] == "docker restart sonarr" and detail["started_at"].endswith("+00:00")
    listed = client.get("/api/v1/commands", headers=_h(token)).json()["commands"]
    assert listed and "output" not in listed[0]

    # An injection attempt reaches the remote shell as one quoted word.
    r = _post(token, "say", "web1", {"text": "x; touch /tmp/pwned $(id)"})
    _wait(r.json()["id"])
    assert _remote(FakePopen.instances[-1].cmd) == ["echo", "x; touch /tmp/pwned $(id)"]

    FakePopen.behavior = {"output": b"no such container\n", "rc": 3}
    run = _wait(_post(token, "restart", "web1", {"container": "radarr"}).json()["id"])
    assert run.status == "failed" and run.return_code == 3

    FakePopen.behavior = {"hang": True}
    start = time.time()
    run = _wait(_post(token, "hang", "web1").json()["id"])
    assert run.status == "timeout" and time.time() - start < 4, "timeout should kill the process"
    assert FakePopen.instances[-1].killed.is_set()

    # Big output is truncated, but the command still gets its real exit status.
    FakePopen.behavior = {"output": b"x" * (commands.OUTPUT_CAP * 3 + 500), "rc": 0}
    run = _wait(_post(token, "restart", "web1", {"container": "sonarr"}).json()["id"])
    assert len(run.output) < commands.OUTPUT_CAP + 100 and run.output.endswith("[output truncated]")
    assert run.status == "success" and run.return_code == 0, f"large output must not turn success into {run.status}"
    assert not FakePopen.instances[-1].killed.is_set(), "the process must be allowed to finish"
    FakePopen.behavior = {"output": b"y" * (commands.OUTPUT_CAP + 10), "rc": 2}
    run = _wait(_post(token, "restart", "web1", {"container": "sonarr"}).json()["id"])
    assert run.status == "failed" and run.return_code == 2
    FakePopen.behavior = {}

    # The host's own `timeout` ending the command (124 / 137) is a timeout, not a plain failure.
    for rc in (124, 137):
        FakePopen.behavior = {"output": b"", "rc": rc}
        run = _wait(_post(token, "restart", "web1", {"container": "sonarr"}).json()["id"])
        assert run.status == "timeout" and run.return_code == rc
    FakePopen.behavior = {}

    # A broken inventory entry fails before anything is recorded.
    CONN["web2"]["user"] = "{{ oops }}"
    try:
        _, t2, _ = _agent("badinv", {"restart": ["web2"]})
        n = len(FakePopen.instances)
        r = _post(t2, "restart", "web2", {"container": "sonarr"})
        assert r.status_code == 502 and "unusable" in r.json()["detail"] and len(FakePopen.instances) == n
    finally:
        CONN["web2"]["user"] = "ansible"

    # Per-template ssh overrides arrive in the command.
    FakePopen.behavior = {"output": b"ok", "rc": 0}
    run = _wait(_post(token, "status", "web1", {"unit": "ssh"}).json()["id"])
    cmd = FakePopen.instances[-1].cmd
    assert "svc@10.0.0.1" in cmd and _remote(cmd) == ["sudo", "-n", "systemctl", "status", "ssh"] and str(SSH_STORAGE_DIR / "svc-key") in cmd
    FakePopen.behavior = {}


def test_runs_are_private_to_their_agent():
    _, mine, _ = _agent("owner-cmd", {"restart": ["web1"]})
    _, other, _ = _agent("other-cmd", {"restart": ["web1"]})
    run_id = _post(mine, "restart", "web1", {"container": "sonarr"}).json()["id"]
    _wait(run_id)
    assert client.get(f"/api/v1/commands/{run_id}", headers=_h(other)).status_code == 404
    assert client.get("/api/v1/commands/999999", headers=_h(mine)).status_code == 404
    assert run_id not in [c["id"] for c in client.get("/api/v1/commands", headers=_h(other)).json()["commands"]]
    assert run_id in [c["id"] for c in client.get("/api/v1/commands", headers=_h(mine)).json()["commands"]]

    # Deleting an agent detaches its history, so a reused id inherits nothing.
    with Session(engine) as session:
        agent = session.exec(select(Agent).where(Agent.name == "owner-cmd")).one()
    agents.delete_agent(agent.id)
    with Session(engine) as session:
        assert session.get(CommandRun, run_id).agent_id is None


def test_kill_switch_and_caps():
    _, token, _ = _agent("capped", {"restart": ["web1", "web2"], "hang": ["web1", "web2", "db1"]})
    agents.set_runs_enabled(False)
    try:
        assert _post(token, "restart", "web1", {"container": "sonarr"}).status_code == 503
        assert client.get("/api/v1/commands", headers=_h(token)).status_code == 200
    finally:
        agents.set_runs_enabled(True)

    FakePopen.behavior = {"hang": True}
    # hang.yml has a 1 s timeout; raise it so the runs stay "running" while we count them.
    hang = ct.load()[0]["hang"]
    hang.timeout = 60
    saved = (api_module.MAX_COMMAND_RUNS, api_module.MAX_COMMANDS_PER_HOST)
    api_module.MAX_COMMAND_RUNS, api_module.MAX_COMMANDS_PER_HOST = 3, 2
    held = []
    try:
        for _ in range(2):
            r = _post(token, "hang", "web1")
            assert r.status_code == 202, r.text
            held.append(r.json()["id"])
        r = _post(token, "hang", "web1")
        assert r.status_code == 429, "per-host cap"
        r = _post(token, "hang", "web2")
        assert r.status_code == 202
        held.append(r.json()["id"])
        r = _post(token, "hang", "db1")
        assert r.status_code == 429, "global cap"
    finally:
        api_module.MAX_COMMAND_RUNS, api_module.MAX_COMMANDS_PER_HOST = saved
        for proc in FakePopen.instances:
            proc.killed.set()
        hang.timeout = 1
        FakePopen.behavior = {}
    for run_id in held:
        _wait(run_id)


def test_catalog_lists_commands():
    _, token, _ = _agent("cataloged", {"restart": ["web1"], "logs": ["web1", "web2"]})
    cat = client.get("/api/v1/catalog", headers=_h(token)).json()
    by_name = {c["template"]: c for c in cat["commands"]}
    assert set(by_name) == {"restart", "logs"}
    assert by_name["restart"]["params"] == {"container": {"type": "enum", "values": ["sonarr", "radarr"]}}
    assert by_name["logs"]["hosts"] == ["web1", "web2"] and by_name["restart"]["risk"] == "high"
    assert "argv" not in by_name["restart"], "the command line itself is not part of the catalog"
    _, none = agents.create_agent("catless")
    assert client.get("/api/v1/catalog", headers=_h(none)).json()["commands"] == []


def test_orphaned_runs_are_settled():
    with Session(engine) as session:
        run = CommandRun(template="restart", host="web1", status="running")
        session.add(run)
        session.commit()
        session.refresh(run)
    commands.reconcile_orphaned()
    with Session(engine) as session:
        r = session.get(CommandRun, run.id)
        assert r.status == "error" and r.finished_at is not None


def test_template_regex_cannot_backtrack_exponentially():
    base = "description: d\nargv: [echo, '{x}']\nparams: {x: {type: regex, pattern: %s}}\n"
    for bad in ("'(a+)+$'", "'([a-z]+)*x'", "'(x+x+)+y'", "'(a*)*'", "'(a{1,9})+'", "'((ab)+)+'", "'(?:\\w+\\s?)+$'"):
        try:
            ct.parse("t", base % bad)
        except ValueError as exc:
            assert "exponential" in str(exc), (bad, exc)
        else:
            raise AssertionError(f"accepted a backtracking pattern: {bad}")
    for good in ("'[a-z0-9_-]+'", "'(foo|bar)+'", "'a?b*c+'", "'(ab?)+'", "'.+'", "'[a-z]+(\\.[a-z]+)?'"):
        ct.parse("t", base % good)


def test_stuck_runs_do_not_hold_the_caps_forever():
    from datetime import timedelta

    from app.models import utcnow

    with Session(engine) as session:
        old = CommandRun(template="restart", host="stuckhost", status="running", started_at=utcnow() - commands.STALE_AFTER - timedelta(minutes=1))
        fresh = CommandRun(template="restart", host="stuckhost", status="running")
        session.add(old)
        session.add(fresh)
        session.commit()
        session.refresh(old)
        session.refresh(fresh)
    assert commands.running("stuckhost") == 1, "only the recent run still counts"
    with Session(engine) as session:
        assert session.get(CommandRun, old.id).status == "error" and session.get(CommandRun, fresh.id).status == "running"
        row = session.get(CommandRun, fresh.id)
        row.status = "success"
        session.add(row)
        session.commit()


def test_result_write_is_retried_and_history_is_pruned():
    with Session(engine) as session:
        run = CommandRun(template="restart", host="web1")
        session.add(run)
        session.commit()
        session.refresh(run)

    real = commands.Session
    calls = {"n": 0}

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
        assert session.get(CommandRun, run.id).status == "success", "the write should have been retried"

    keep = commands.KEEP_RUNS
    commands.KEEP_RUNS = 3
    try:
        ids = []
        for _ in range(6):
            with Session(engine) as session:
                r = CommandRun(template="restart", host="web1")
                session.add(r)
                session.commit()
                session.refresh(r)
                ids.append(r.id)
            commands._finish(ids[-1], "success", 0, "z" * 100)
    finally:
        commands.KEEP_RUNS = keep
    with Session(engine) as session:
        left = {r.id for r in session.exec(select(CommandRun)).all()}
    assert set(ids[-3:]) <= left and not set(ids[:2]) & left, "old runs should be pruned, newest kept"


def test_timeout_timer_does_not_overrule_a_finished_command():
    with Session(engine) as session:
        run = CommandRun(template="restart", host="web1")
        session.add(run)
        session.commit()
        session.refresh(run)
    # ssh has already exited (poll() == 0) when the timer fires during the final read.
    FakePopen.behavior = {"poll": 0, "delay": 0.8, "output": b"ok\n", "rc": 0}
    try:
        commands._execute(run.id, ["ssh", "x"], 0.2)
    finally:
        FakePopen.behavior = {}
    with Session(engine) as session:
        done = session.get(CommandRun, run.id)
    assert done.status == "success" and done.return_code == 0
    assert not FakePopen.instances[-1].killed.is_set()


def test_template_removed_between_check_and_use():
    _, token, _ = _agent("racy", {"restart": ["web1"]})
    real = ct.load
    seen = {"n": 0}

    def load_once():
        seen["n"] += 1
        return real() if seen["n"] == 1 else ({}, {})

    ct.load = load_once
    try:
        r = _post(token, "restart", "web1", {"container": "sonarr"})
    finally:
        ct.load = real
    assert r.status_code == 403 and "not loaded" in r.json()["detail"], f"{r.status_code} {r.text}"


def test_agents_page_does_not_read_command_output():
    from sqlalchemy import event

    statements = []

    def spy(conn, cursor, statement, *a):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", spy)
    try:
        assert admin.get("/agents").status_code == 200
    finally:
        event.remove(engine, "before_cursor_execute", spy)
    reads = [s for s in statements if "FROM commandrun" in s]
    assert reads and not any("commandrun.output" in s for s in reads), reads


def test_granting_looks_up_the_inventory_once():
    role = agents.create_role("lookups")
    calls = {"n": 0}
    real = inventory.list_hosts

    def counted():
        calls["n"] += 1
        return real()

    inventory.list_hosts = counted
    try:
        agents.add_command_grant(role.id, "restart", ["web1", "web2", "db1"])
    finally:
        inventory.list_hosts = real
    assert calls["n"] == 1, calls


# --- admin -------------------------------------------------------------------------


def test_admin_command_grants():
    admin.post("/roles", data={"name": "cmd-role"})
    with Session(engine) as session:
        from app.models import Role

        role = session.exec(select(Role).where(Role.name == "cmd-role")).one()
    r = admin.post(f"/roles/{role.id}/command-grants", data={"template": "restart", "hosts": ["web1", "db1"]}, follow_redirects=False)
    assert r.status_code == 303
    page = admin.get("/agents").text
    assert "command: restart" in page and "db1, web1" in page
    assert "Restart a Docker container" in page and "broken.yml" in page, "templates and load errors are listed"
    assert "docker restart {container}" in page

    for template, hosts, contains in [
        ("nope", ["web1"], "Unknown command template"),
        ("restart", ["ghost"], "Not in the inventory"),
        ("restart", [], "at least one host"),
    ]:
        r = admin.post(f"/roles/{role.id}/command-grants", data={"template": template, "hosts": hosts})
        assert r.status_code == 400 and contains in r.text, (template, hosts, r.text[:200])

    with Session(engine) as session:
        actions = [a.action for a in session.exec(select(AdminAudit)).all()]
    assert "add command grant" in actions

    agents_router.AUTH_DISABLED = True
    try:
        r = admin.post(f"/roles/{role.id}/command-grants", data={"template": "restart", "hosts": ["web2"]})
        assert r.status_code == 400 and "ULMO_DISABLE_AUTH" in r.text
    finally:
        agents_router.AUTH_DISABLED = False

    # An agent token reaches none of it.
    _, token = agents.create_agent("cmd-intruder")
    r = client.post(f"/roles/{role.id}/command-grants", data={"template": "restart", "hosts": ["web2"]}, headers=_h(token), follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"

    with Session(engine) as session:
        grant_id = session.exec(select(CommandGrant).where(CommandGrant.role_id == role.id)).one().id
    admin.post(f"/command-grants/{grant_id}/delete", follow_redirects=False)
    with Session(engine) as session:
        assert session.get(CommandGrant, grant_id) is None

    agents.add_command_grant(role.id, "restart", ["web1"])
    agents.delete_role(role.id)
    with Session(engine) as session:
        assert session.exec(select(CommandGrant).where(CommandGrant.role_id == role.id)).first() is None


def main():
    init_db()
    auth_module.create_user("admin", "pw-for-tests")
    r = admin.post("/login", data={"username": "admin", "password": "pw-for-tests"}, follow_redirects=False)
    assert r.status_code == 303 and admin.get("/agents").status_code == 200, "test login failed"
    test_parse_accepts_good_and_rejects_bad_templates()
    test_parameter_validation()
    test_values_stay_one_literal_argument()
    test_loader_keeps_last_good_version()
    test_ssh_command()
    test_default_deny_and_validation()
    test_run_success_failure_timeout_truncation()
    test_runs_are_private_to_their_agent()
    test_kill_switch_and_caps()
    test_catalog_lists_commands()
    test_orphaned_runs_are_settled()
    test_template_regex_cannot_backtrack_exponentially()
    test_stuck_runs_do_not_hold_the_caps_forever()
    test_result_write_is_retried_and_history_is_pruned()
    test_timeout_timer_does_not_overrule_a_finished_command()
    test_template_removed_between_check_and_use()
    test_granting_looks_up_the_inventory_once()
    test_admin_command_grants()
    test_agents_page_does_not_read_command_output()
    print("OK: command templates validate strictly, run over a quoted ssh argv, and are default-deny.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
