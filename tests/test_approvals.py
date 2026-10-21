"""Self-check for approvals: a role can make a command or playbook grant wait for an admin.

  1. A flagged call is recorded as pending and nothing runs; an unflagged one runs at once.
     The catalog says which is which.
  2. Only a signed-in admin decides (an agent token cannot), once, and approving runs exactly
     what was requested. An agent sees only its own requests.
  3. Approving repeats every check: kill switch, disabled agent, role, host, a changed command.
  4. Requests expire, are capped per agent, and approving is locked while ULMO_DISABLE_AUTH is set.
  5. Playbook grants union: one grant that does not ask covers its hosts.
  6. Saving a role's commands keeps their approval flags; the role page can set them.
  7. The notification names the agent and what it wants, with a link when a public URL is set.
  8. A page opened from a link returns to itself after sign-in, never to another site.
  9. The new columns are added to databases created before this feature.

Run directly: python3 tests/test_approvals.py
"""
import os
import shutil
import sqlite3
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

import ansible_runner  # noqa: E402
import yaml  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlmodel import Session, SQLModel, select  # noqa: E402

import app.auth as auth_module  # noqa: E402
from app import database  # noqa: E402
from app.config import SSH_STORAGE_DIR  # noqa: E402
from app.database import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import AdminAudit, Agent, Approval, CommandRun, RoleCommand, RunHistory, utcnow  # noqa: E402
from app.routers import approvals as approvals_router  # noqa: E402
from app.services import agents, approvals, command_library as cl, commands, git_sync, inventory, notifier, settings_store  # noqa: E402

SSH_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
(SSH_STORAGE_DIR / "k").write_text("not a real key")

LIBRARY = {
    "commands": {
        "restart": {"description": "Restart", "argv": ["docker", "restart", "{container}"], "params": {"container": {"type": "enum", "values": ["sonarr", "radarr"]}}, "risk": "medium"},
        "uptime": {"description": "Uptime", "argv": ["uptime"], "risk": "low"},
        "logs": {"description": "Log tail", "argv": ["tail", "-n", "{lines}", "/var/log/x"], "params": {"lines": {"type": "int", "min": 1, "max": 500}}},
        "find": {"description": "Find a domain", "argv": ["pihole", "-q", "{domain}"], "params": {"domain": {"type": "regex", "pattern": "[a-z0-9.-]+", "max_length": 100}}},
    },
    "hosts": {"frodo": {"address": "10.0.0.7", "port": 22, "user": "ansible", "ssh_key": "k", "commands": ["restart", "uptime", "logs", "find"]}},
}


def _set_library(data):
    cl.LIBRARY_PATH.write_text(yaml.safe_dump(data, sort_keys=False))
    assert not cl.load()[1], cl.load()[1]


_set_library(LIBRARY)

git_sync.list_playbooks = lambda: [{"name": "frodo.yaml", "rel_path": "playbooks/frodo.yaml"}]
inventory.list_hosts = lambda: ["frodo", "cirdan"]
inventory.list_groups = lambda: ["all", "ungrouped"]
ansible_calls: list[dict] = []


def fake_run_async(**kw):
    ansible_calls.append(kw)
    return SimpleNamespace(join=lambda: None), SimpleNamespace(rc=0, status="successful")


ansible_runner.run_async = fake_run_async

ssh_calls: list[list] = []


class FakeStdout:
    def __init__(self):
        self.sent = False

    def read(self, n):
        if self.sent:
            return b""
        self.sent = True
        return b"ok\n"

    def close(self):
        pass


class FakePopen:
    def __init__(self, cmd, **kw):
        ssh_calls.append(cmd)
        self.stdout = FakeStdout()

    def poll(self):
        return 0

    def wait(self):
        return 0

    def kill(self):
        pass


commands.subprocess = SimpleNamespace(Popen=FakePopen, PIPE=-1, STDOUT=-2, DEVNULL=-3)

client = TestClient(app)
admin = TestClient(app)
sent: list[tuple] = []  # what the notifier would have pushed
notifier._send_pushover = lambda token, user, title, message, url="": sent.append((title, message, url))
notifier._send_ntfy = lambda url, title, message, click="": None


def _h(token):
    return {"Authorization": f"Bearer {token}"}


def _agent(name, asking=(), commands_=("restart", "uptime", "logs", "find")):
    role = agents.create_role(f"role-{name}")
    agents.set_role_commands(role.id, list(commands_))
    agents.set_commands_needing_approval(role.id, list(asking))
    agent, token = agents.create_agent(name)
    agents.assign_role(agent.id, role.id)
    return agent, token, role


def _ask(token, command="restart", host="frodo", params=None):
    return client.post("/api/v1/commands?wait=0", json={"command": command, "host": host, "params": params if params is not None else {"container": "sonarr"}}, headers=_h(token))


def _asking(role):
    return sorted(approvals.commands_needing(SimpleNamespace(role_id=role.id)))


def _notified(count):
    for _ in range(100):
        if len(sent) >= count:
            break
        time.sleep(0.02)
    time.sleep(0.1)


def _wait_ssh(count):
    for _ in range(200):
        if len(ssh_calls) >= count:
            return
        time.sleep(0.02)
    raise AssertionError("ssh was never called")


def _approval(approval_id):
    with Session(engine) as session:
        return session.get(Approval, approval_id)


def test_flagged_call_waits_unflagged_runs():
    agent, token, role = _agent("n8n", asking=["restart"])
    before = len(ssh_calls)

    r = _ask(token)
    assert r.status_code == 202 and r.json()["status"] == "pending_approval", r.text
    aid = r.json()["approval_id"]
    time.sleep(0.2)
    assert len(ssh_calls) == before, "nothing may run before an admin approves"
    with Session(engine) as session:
        assert session.exec(select(CommandRun).where(CommandRun.agent_id == agent.id)).first() is None
    a = _approval(aid)
    assert a.status == "pending" and a.line == "docker restart sonarr" and a.host == "frodo" and a.kind == "command"

    r = client.post("/api/v1/commands?wait=5", json={"command": "uptime", "host": "frodo", "params": {}}, headers=_h(token))
    assert r.status_code == 200 and r.json()["status"] == "success", "an unflagged command runs at once"

    cat = {c["command"]: c["requires_approval"] for c in client.get("/api/v1/catalog", headers=_h(token)).json()["commands"]}
    assert cat == {"restart": True, "uptime": False, "logs": False, "find": False}, cat

    # bad parameters are refused as before, not turned into a request
    r = _ask(token, params={"container": "nope"})
    assert r.status_code == 400
    with Session(engine) as session:
        assert len(session.exec(select(Approval).where(Approval.agent_id == agent.id)).all()) == 1


def test_only_an_admin_decides_and_approval_runs_what_was_asked():
    _, token, _ = _agent("decider", asking=["restart"])
    _, other_token, _ = _agent("bystander", asking=["restart"])
    aid = _ask(token).json()["approval_id"]

    for url in (f"/approvals/{aid}/approve", f"/approvals/{aid}/deny"):
        r = client.post(url, headers=_h(token), follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/login"), "a token is not a login"
    assert _approval(aid).status == "pending"

    assert client.get(f"/api/v1/approvals/{aid}", headers=_h(other_token)).status_code == 404, "agents see only their own"
    mine = client.get(f"/api/v1/approvals/{aid}", headers=_h(token)).json()
    assert mine["status"] == "pending" and mine["line"] == "docker restart sonarr" and "run_id" in mine and mine["run_id"] is None

    before = len(ssh_calls)
    r = admin.post(f"/approvals/{aid}/approve", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/approvals/{aid}"
    _wait_ssh(before + 1)
    assert ssh_calls[-1][-1].endswith("docker restart sonarr") and ssh_calls[-1][-3] == "ansible@10.0.0.7"
    a = _approval(aid)
    assert a.status == "approved" and a.decided_by == "admin" and a.run_id
    done = client.get(f"/api/v1/approvals/{aid}", headers=_h(token)).json()
    assert done["status"] == "approved" and done["result_url"] == f"/api/v1/commands/{a.run_id}"
    assert client.get(done["result_url"], headers=_h(token)).status_code == 200, "the agent can follow it to the output"

    # deciding twice runs it once
    r = admin.post(f"/approvals/{aid}/approve", follow_redirects=True)
    assert "already approved" in r.text and len(ssh_calls) == before + 1
    r = admin.post(f"/approvals/{aid}/deny", follow_redirects=True)
    assert "already approved" in r.text and _approval(aid).status == "approved"

    with Session(engine) as session:
        audit = session.exec(select(AdminAudit).where(AdminAudit.action == "approve request")).all()
    assert audit and "docker restart sonarr" in audit[-1].detail and audit[-1].admin == "admin"


def test_deny_runs_nothing():
    _, token, _ = _agent("denied", asking=["restart"])
    aid = _ask(token).json()["approval_id"]
    before = len(ssh_calls)
    admin.post(f"/approvals/{aid}/deny")
    time.sleep(0.2)
    a = _approval(aid)
    assert a.status == "denied" and a.run_id is None and len(ssh_calls) == before
    assert "already denied" in admin.post(f"/approvals/{aid}/approve", follow_redirects=True).text
    assert client.get(f"/api/v1/approvals/{aid}", headers=_h(token)).json()["status"] == "denied"


def test_approving_repeats_the_checks():
    before = len(ssh_calls)

    def pending(name):
        agent, token, role = _agent(name, asking=["restart"])
        return agent, role, _ask(token).json()["approval_id"]

    # kill switch
    _, _, aid = pending("late-kill")
    agents.set_runs_enabled(False)
    try:
        admin.post(f"/approvals/{aid}/approve")
    finally:
        agents.set_runs_enabled(True)
    a = _approval(aid)
    assert a.status == "failed" and "switched off" in a.note and a.run_id is None

    # agent disabled meanwhile
    agent, _, aid = pending("late-off")
    agents.toggle_enabled(agent.id)
    admin.post(f"/approvals/{aid}/approve")
    assert _approval(aid).status == "failed" and "disabled" in _approval(aid).note

    # role lost the command meanwhile
    _, role, aid = pending("late-role")
    agents.set_role_commands(role.id, ["uptime"])
    admin.post(f"/approvals/{aid}/approve")
    assert _approval(aid).status == "failed" and "no permission" in _approval(aid).note

    # the host stopped offering it
    _, _, aid = pending("late-host")
    changed = yaml.safe_load(cl.LIBRARY_PATH.read_text())
    changed["hosts"]["frodo"]["commands"] = ["uptime"]
    _set_library(changed)
    try:
        admin.post(f"/approvals/{aid}/approve")
    finally:
        _set_library(LIBRARY)
    assert _approval(aid).status == "failed" and "does not offer" in _approval(aid).note

    # the command line changed meanwhile: what the admin saw is not what would run
    _, _, aid = pending("late-edit")
    changed = yaml.safe_load(cl.LIBRARY_PATH.read_text())
    changed["commands"]["restart"]["argv"] = ["docker", "stop", "{container}"]
    _set_library(changed)
    try:
        admin.post(f"/approvals/{aid}/approve")
    finally:
        _set_library(LIBRARY)
    a = _approval(aid)
    assert a.status == "failed" and "changed since" in a.note
    time.sleep(0.2)
    assert len(ssh_calls) == before, "none of these may have run"
    assert "changed since" in admin.get(f"/approvals/{aid}").text, "the admin is told why"


def test_expiry_cap_and_locked_while_auth_is_disabled():
    _, token, _ = _agent("slow", asking=["restart"])
    aid = _ask(token).json()["approval_id"]
    with Session(engine) as session:
        row = session.get(Approval, aid)
        row.expires_at = utcnow() - timedelta(seconds=1)
        session.add(row)
        session.commit()
    assert client.get(f"/api/v1/approvals/{aid}", headers=_h(token)).json()["status"] == "expired"
    assert "already expired" in admin.post(f"/approvals/{aid}/approve", follow_redirects=True).text
    assert approvals.pending() == [a for a in approvals.pending() if a.status == "pending"]

    _, capped, _ = _agent("flood", asking=["logs"])
    for n in range(approvals.MAX_PENDING_PER_AGENT):
        assert _ask(capped, "logs", params={"lines": n + 1}).status_code == 202
    r = _ask(capped, "logs", params={"lines": 99})
    assert r.status_code == 429 and "waiting for approval" in r.json()["detail"]

    _, locked_token, _ = _agent("lockwait", asking=["restart"])
    aid = _ask(locked_token).json()["approval_id"]
    approvals_router.AUTH_DISABLED = True
    try:
        before = len(ssh_calls)
        page = admin.post(f"/approvals/{aid}/approve", follow_redirects=True)
        assert "ULMO_DISABLE_AUTH" in page.text and _approval(aid).status == "pending" and len(ssh_calls) == before
        admin.post(f"/approvals/{aid}/deny")
        assert _approval(aid).status == "denied", "saying no is always allowed"
    finally:
        approvals_router.AUTH_DISABLED = False


def test_playbook_grants_union_and_run_through_approval():
    role = agents.create_role("pb-role")
    agent, token = agents.create_agent("pb-agent")
    agents.assign_role(agent.id, role.id)
    with Session(engine) as session:
        agent = session.get(Agent, agent.id)  # the copy from create_agent predates the role
    asks = agents.add_grant(role.id, "playbooks/frodo.yaml", ["frodo", "cirdan"], requires_approval=True)
    assert approvals.playbook_needs(agent, "playbooks/frodo.yaml", ["frodo"])
    free = agents.add_grant(role.id, "playbooks/frodo.yaml", ["frodo"])
    assert not approvals.playbook_needs(agent, "playbooks/frodo.yaml", ["frodo"]), "the grant that does not ask covers frodo"
    assert approvals.playbook_needs(agent, "playbooks/frodo.yaml", ["frodo", "cirdan"]), "cirdan is only covered by the one that asks"
    agents.delete_grant(free.id)

    cat = client.get("/api/v1/catalog", headers=_h(token)).json()
    assert cat["playbooks"] == [{"playbook": "playbooks/frodo.yaml", "hosts": ["cirdan", "frodo"], "requires_approval": True}]

    calls = len(ansible_calls)
    r = client.post("/api/v1/runs", json={"playbook": "playbooks/frodo.yaml", "limit": ["frodo"]}, headers=_h(token))
    assert r.status_code == 202 and r.json()["status"] == "pending_approval", r.text
    aid = r.json()["approval_id"]
    assert len(ansible_calls) == calls and _approval(aid).line == "ansible-playbook playbooks/frodo.yaml --limit frodo"

    # a host outside the grant is refused outright, not queued
    assert client.post("/api/v1/runs", json={"playbook": "playbooks/frodo.yaml", "limit": ["web9"]}, headers=_h(token)).status_code == 403

    admin.post(f"/approvals/{aid}/approve")
    a = _approval(aid)
    assert a.status == "approved" and a.run_id
    for _ in range(100):
        if len(ansible_calls) > calls:
            break
        time.sleep(0.02)
    assert len(ansible_calls) == calls + 1
    with Session(engine) as session:
        run = session.get(RunHistory, a.run_id)
    assert run.triggered_by == "agent:pb-agent" and run.limit == "frodo"
    done = client.get(f"/api/v1/approvals/{aid}", headers=_h(token)).json()
    assert done["result_url"] == f"/api/v1/runs/{a.run_id}" and client.get(done["result_url"], headers=_h(token)).status_code == 200

    # toggling from the admin side
    assert agents.toggle_grant_approval(asks.id) is False and agents.toggle_grant_approval(asks.id) is True


def test_role_page_keeps_and_sets_flags():
    _, _, role = _agent("flags", asking=["restart"])
    assert _asking(role) == ["restart"]
    agents.set_role_commands(role.id, ["restart", "uptime"])  # saving the list again
    assert _asking(role) == ["restart"]
    agents.set_role_commands(role.id, ["uptime"])
    assert _asking(role) == []
    try:
        agents.set_commands_needing_approval(role.id, ["restart"])
    except ValueError as exc:
        assert "Not commands of this role" in str(exc)
    else:
        raise AssertionError("flagged a command the role does not have")

    r = admin.post(f"/roles/{role.id}/approval-commands", data={"commands": ["uptime"]}, follow_redirects=False)
    assert r.status_code == 303 and _asking(role) == ["uptime"]
    assert "Commands that need your approval" in admin.get("/agents").text
    r = client.post(f"/roles/{role.id}/approval-commands", data={"commands": []}, headers=_h(_agent("sneaky")[1]), follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")
    assert _asking(role) == ["uptime"]


def test_notification_names_the_request():
    settings_store.set_many({"public_url": ""})
    _, token, _ = _agent("pinger", asking=["restart"])
    sent.clear()
    aid = _ask(token).json()["approval_id"]
    for _ in range(100):
        if sent:
            break
        time.sleep(0.02)
    title, message, url = sent[-1]
    assert "pinger" in title and "docker restart sonarr" in message and "frodo" in message and url == "", "no link without a public URL"

    settings_store.set_many({"public_url": "https://ulmo.example.com/"})
    sent.clear()
    aid = _ask(token, params={"container": "radarr"}).json()["approval_id"]
    _notified(1)
    assert sent[-1][2] == f"https://ulmo.example.com/approvals/{aid}", sent[-1]
    settings_store.set_many({"public_url": ""})


def test_page_and_nav():
    _, token, _ = _agent("shown", asking=["restart"])
    aid = _ask(token).json()["approval_id"]
    page = admin.get("/approvals").text
    assert "shown wants to run restart" in page and "docker restart sonarr" in page and f"/approvals/{aid}/approve" in page
    assert "Approvals <span" in admin.get("/agents").text, "the nav shows how many are waiting"
    detail = admin.get(f"/approvals/{aid}").text
    assert "Approve" in detail and "Deny" in detail
    assert admin.get("/approvals/999999", follow_redirects=False).headers["location"] == "/approvals", "an unknown request goes back to the list"


def test_login_returns_to_the_page_and_never_to_another_site():
    anon = TestClient(app)
    r = anon.get("/approvals/7", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login?next=%2Fapprovals%2F7", r.headers["location"]
    assert anon.get("/agents", follow_redirects=False).headers["location"] == "/login?next=%2Fagents"
    assert anon.get("/", follow_redirects=False).headers["location"] == "/login"
    assert anon.post("/approvals/7/approve", follow_redirects=False).headers["location"] == "/login", "a form post does not come back"

    form = anon.get("/login?next=/approvals/7").text
    assert 'name="next" value="/approvals/7"' in form
    r = anon.post("/login", data={"username": "admin", "password": "pw-for-tests", "next": "/approvals/7"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/approvals/7"
    for evil in ("https://evil.example", "//evil.example", "/\\evil.example", "evil", "/ok\r\nX-Injected: 1"):
        other = TestClient(app)
        r = other.post("/login", data={"username": "admin", "password": "pw-for-tests", "next": evil}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/", f"{evil!r} -> {r.headers['location']}"
    bad = TestClient(app).post("/login", data={"username": "admin", "password": "wrong", "next": "/approvals/7"})
    assert 'name="next" value="/approvals/7"' in bad.text, "a wrong password keeps the destination"


def test_int_and_regex_params_survive_approval():
    _, token, _ = _agent("typed", asking=["logs", "find"])
    before = len(ssh_calls)
    lid = _ask(token, "logs", params={"lines": 50}).json()["approval_id"]
    fid = _ask(token, "find", params={"domain": "example.com"}).json()["approval_id"]
    assert client.get(f"/api/v1/approvals/{lid}", headers=_h(token)).json()["params"] == {"lines": 50}, "shown as the agent sent it"
    admin.post(f"/approvals/{lid}/approve")
    admin.post(f"/approvals/{fid}/approve")
    assert _approval(lid).status == "approved" and _approval(fid).status == "approved", (_approval(lid).note, _approval(fid).note)
    _wait_ssh(before + 2)
    tails = sorted(c[-1] for c in ssh_calls[before:])
    assert any(t.endswith("tail -n 50 /var/log/x") for t in tails) and any(t.endswith("pihole -q example.com") for t in tails), tails


def test_a_retry_does_not_pile_up_requests():
    agent, token, _ = _agent("retrier", asking=["restart"])
    sent.clear()
    first = _ask(token).json()["approval_id"]
    again = _ask(token).json()
    assert again["approval_id"] == first and again["status"] == "pending_approval", "the same request is the same approval"
    other = _ask(token, params={"container": "radarr"}).json()["approval_id"]
    assert other != first
    _notified(2)
    assert len(sent) == 2, "one notification per distinct request, none for the retry"
    with Session(engine) as session:
        assert len(session.exec(select(Approval).where(Approval.agent_id == agent.id)).all()) == 2
    # once decided, the same request can be made again
    admin.post(f"/approvals/{first}/deny")
    assert _ask(token).json()["approval_id"] not in (first, other)


def test_the_cap_holds_under_concurrent_requests():
    agent, _, _ = _agent("burst", asking=["logs"])
    gate = threading.Barrier(30)
    results = []

    def go(n):
        gate.wait()
        try:
            results.append(approvals.create(agent, "command", "logs", "frodo", {"lines": n}, f"tail -n {n}")[1])
        except approvals.TooManyPending:
            results.append(None)

    threads = [threading.Thread(target=go, args=(n + 1,)) for n in range(30)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    with Session(engine) as session:
        waiting = session.exec(select(Approval).where(Approval.agent_id == agent.id, Approval.status == "pending")).all()
    assert len(waiting) == approvals.MAX_PENDING_PER_AGENT == results.count(True), (len(waiting), results.count(True))


def test_deleting_an_agent_removes_its_requests():
    agent, token, _ = _agent("leaver", asking=["restart"])
    aid = _ask(token).json()["approval_id"]
    agents.delete_agent(agent.id)
    assert _approval(aid) is None, "nothing left for an agent that reuses the id to inherit"
    assert approvals.get(aid) is None


def test_the_nav_count_is_a_read():
    _, token, _ = _agent("counted", asking=["restart"])
    aid = _ask(token).json()["approval_id"]
    n = approvals.pending_count()
    assert n >= 1
    with Session(engine) as session:
        row = session.get(Approval, aid)
        row.expires_at = utcnow() - timedelta(seconds=1)
        session.add(row)
        session.commit()
    assert approvals.pending_count() == n - 1, "an expired request is not counted"
    with Session(engine) as session:
        assert session.get(Approval, aid).status == "pending", "counting does not write; the approvals page settles it"
    approvals.expire_stale()
    assert _approval(aid).status == "expired"


def test_the_refusal_comes_from_the_session_not_the_link():
    _, token, _ = _agent("quiet", asking=["restart"])
    aid = _ask(token).json()["approval_id"]
    assert "FAKE-INSTRUCTION" not in admin.get(f"/approvals/{aid}?error=FAKE-INSTRUCTION").text
    admin.post(f"/approvals/{aid}/deny")
    admin.post(f"/approvals/{aid}/approve", follow_redirects=False)  # refused: already denied
    shown = admin.get(f"/approvals/{aid}").text
    assert "already denied" in shown
    assert "already denied" not in admin.get(f"/approvals/{aid}").text, "shown once"


def test_public_url_must_be_a_web_address():
    settings_store.set_many({"public_url": ""})
    r = admin.post("/settings/notifications", data={"public_url": "ulmo.example.com"}, follow_redirects=False)
    assert r.status_code == 303 and "must+start+with" in r.headers["location"] and settings_store.get("public_url") == ""
    r = admin.post("/settings/notifications", data={"public_url": " https://ulmo.example.com/ "}, follow_redirects=False)
    assert settings_store.get("public_url") == "https://ulmo.example.com"
    settings_store.set_many({"public_url": ""})


def test_old_databases_get_the_new_columns():
    path = Path(DATA_DIR) / "old.db"
    SQLModel.metadata.create_all(create_engine(f"sqlite:///{path}"))
    con = sqlite3.connect(path)
    con.execute('DROP TABLE "grant"')
    con.execute("DROP TABLE rolecommand")
    con.execute('CREATE TABLE "grant" (id INTEGER PRIMARY KEY, role_id INTEGER, playbook TEXT, hosts TEXT)')
    con.execute("CREATE TABLE rolecommand (id INTEGER PRIMARY KEY, role_id INTEGER, command TEXT)")
    con.execute('INSERT INTO "grant" VALUES (1, 1, \'p.yml\', \'a\')')
    con.execute("INSERT INTO rolecommand VALUES (1, 1, 'x')")
    con.commit()
    con.close()
    real = database.engine
    database.engine = create_engine(f"sqlite:///{path}")
    try:
        database._apply_column_migrations()
        database._apply_column_migrations()  # and again: nothing to add
        with database.engine.connect() as conn:
            assert conn.exec_driver_sql('SELECT requires_approval FROM "grant"').all() == [(0,)], "existing grants keep running at once"
            assert conn.exec_driver_sql("SELECT requires_approval FROM rolecommand").all() == [(0,)]
    finally:
        database.engine = real


def main():
    init_db()
    settings_store.set_many({"notify_pushover_token": "t", "notify_pushover_user": "u"})
    auth_module.create_user("admin", "pw-for-tests")
    r = admin.post("/login", data={"username": "admin", "password": "pw-for-tests"}, follow_redirects=False)
    assert r.status_code == 303 and admin.get("/agents").status_code == 200, "test login failed"
    test_flagged_call_waits_unflagged_runs()
    test_only_an_admin_decides_and_approval_runs_what_was_asked()
    test_deny_runs_nothing()
    test_approving_repeats_the_checks()
    test_expiry_cap_and_locked_while_auth_is_disabled()
    test_playbook_grants_union_and_run_through_approval()
    test_role_page_keeps_and_sets_flags()
    test_notification_names_the_request()
    test_int_and_regex_params_survive_approval()
    test_a_retry_does_not_pile_up_requests()
    test_the_cap_holds_under_concurrent_requests()
    test_deleting_an_agent_removes_its_requests()
    test_the_nav_count_is_a_read()
    test_the_refusal_comes_from_the_session_not_the_link()
    test_public_url_must_be_a_web_address()
    test_page_and_nav()
    test_login_returns_to_the_page_and_never_to_another_site()
    test_old_databases_get_the_new_columns()
    print("OK: flagged calls wait for an admin, run exactly as asked once approved, and every check is repeated.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
