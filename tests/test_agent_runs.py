"""Self-check for playbook runs through the agent API (phase 2).

  1. Default deny: no role, no grant for the playbook, or a host outside the
     grant is a 403 and nothing reaches ansible. Hosts are matched exactly, so
     wildcards, groups and `a:b` patterns are refused.
  2. A granted request starts the run through the unchanged runner.start_run:
     same ansible-runner arguments as the UI (playbook + --limit), nothing
     extra (no tags, extra vars or check mode), recorded as agent:<name>.
  3. The kill switch refuses new runs (503) but not reads or cancels.
  4. An agent can cancel only its own runs, and only while they are running.
  5. Deleting a role takes the ability to run away from its agents.
  6. Grants are validated against the real playbook and host lists.
  7. The admin side: roles, grants and role assignment need a login and are
     locked while ULMO_DISABLE_AUTH is set (switching runs OFF stays allowed).
  8. The role_id column is added to an existing agent table.
  9. A name that is also an inventory group (or no longer a host, or an
     unreadable inventory) cannot be used to widen a grant.
 10. Agent-supplied text is bounded; overlapping and excess runs are refused;
     cancel ownership comes from AgentRun, not a username string; cancel
     right after start waits for the run to register; admin changes are
     audited; the kill switch is not part of settings backup/restore.

Run directly: python3 tests/test_agent_runs.py
"""
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

import ansible_runner  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

import app.auth as auth_module  # noqa: E402
from app import database  # noqa: E402
from app.database import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import AdminAudit, Agent, AgentAudit, AgentRun, Grant, Role, RunHistory  # noqa: E402
from app.routers import agents as agents_router  # noqa: E402
from app.routers import api as api_module  # noqa: E402
from app.services import settings_store  # noqa: E402
from app.services import agent_runs, agents, git_sync, inventory  # noqa: E402

PLAYBOOKS = [
    {"name": "restart.yml", "rel_path": "playbooks/restart.yml"},
    {"name": "other.yml", "rel_path": "playbooks/other.yml"},
]
HOSTS = ["web1", "web2", "db1"]
GROUPS = ["all", "ungrouped", "webservers"]  # ansible --limit reads a name as host OR group
git_sync.list_playbooks = lambda: PLAYBOOKS
inventory.list_hosts = lambda: HOSTS
inventory.list_groups = lambda: GROUPS

calls: list[dict] = []  # kwargs of every ansible_runner.run_async call
hold = {"on": False}  # when on, a run stays "running" until it is cancelled


def fake_run_async(**kw):
    calls.append(kw)
    result = SimpleNamespace(rc=0, status="successful")

    class _Thread:
        def join(self):
            if not hold["on"]:
                return
            for _ in range(250):
                if kw["cancel_callback"]():
                    result.rc, result.status = -1, "canceled"
                    return
                time.sleep(0.02)

    return _Thread(), result


ansible_runner.run_async = fake_run_async

client = TestClient(app)  # an API caller
admin = TestClient(app)  # a logged-in browser


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _run(token: str, playbook: str, limit):
    body = {"playbook": playbook}
    if limit is not None:
        body["limit"] = limit
    return client.post("/api/v1/runs", json=body, headers=_h(token))


def _last_audit() -> AgentAudit:
    with Session(engine) as session:
        return session.exec(select(AgentAudit).order_by(AgentAudit.id.desc())).first()


def _wait_done(run_id: int) -> RunHistory:
    for _ in range(250):
        with Session(engine) as session:
            run = session.get(RunHistory, run_id)
        if run.status != "running":
            return run
        time.sleep(0.02)
    raise AssertionError(f"run {run_id} never finished")


def _wait_running(run_id: int) -> None:
    for _ in range(250):
        if runner_active(run_id):
            return
        time.sleep(0.02)
    raise AssertionError(f"run {run_id} never started")


def runner_active(run_id: int) -> bool:
    from app.services import runner

    return run_id in runner._cancel_events


def _agent_with_grant(name: str, playbook="playbooks/restart.yml", hosts=("web1", "web2")):
    role = agents.create_role(f"role-{name}")
    agents.add_grant(role.id, playbook, list(hosts))
    agent, token = agents.create_agent(name)
    agents.assign_role(agent.id, role.id)
    return agent, token, role


def test_default_deny():
    _, no_role = agents.create_agent("norole")
    before = len(calls)
    r = _run(no_role, "playbooks/restart.yml", ["web1"])
    assert r.status_code == 403 and "no grant" in r.json()["detail"], r.text
    assert _last_audit().status_code == 403 and "no grant" in _last_audit().detail
    assert client.get("/api/v1/catalog", headers=_h(no_role)).json()["playbooks"] == []

    _, token, _ = _agent_with_grant("denied")
    for playbook, limit, why in [
        ("playbooks/other.yml", ["web1"], "other playbook"),
        ("playbooks/restart.yml", ["db1"], "host outside grant"),
        ("playbooks/restart.yml", ["web1", "db1"], "one host outside grant"),
        ("playbooks/restart.yml", ["all"], "group keyword"),
        ("playbooks/restart.yml", ["*"], "wildcard"),
        ("playbooks/restart.yml", ["web1:db1"], "union pattern"),
        ("playbooks/restart.yml", ["web1,db1"], "comma smuggled in one entry"),
        ("playbooks/restart.yml", ["!db1"], "negation"),
        ("playbooks/nope.yml", ["web1"], "playbook that does not exist"),
    ]:
        r = _run(token, playbook, limit)
        assert r.status_code == 403, f"{why}: expected 403, got {r.status_code} {r.text}"
    assert len(calls) == before, "a denied request reached ansible"

    assert _run(token, "playbooks/restart.yml", None).status_code == 422, "limit is required"
    assert _run(token, "playbooks/restart.yml", []).status_code == 422, "empty limit"
    assert client.post("/api/v1/runs", json={}, headers=_h(token)).status_code == 422
    assert client.post("/api/v1/runs", json={"playbook": "x", "limit": ["web1"]}).status_code == 401
    assert len(calls) == before

    # Second layer behind the request model: an empty or blank limit must never pass,
    # because ansible-playbook with no --limit runs on every host.
    agent = Agent(name="x", token_hash="x", role_id=_role_id_of("denied"))
    assert agents.check_run(agent, "playbooks/restart.yml", []) == "limit is required"
    assert agents.check_run(agent, "playbooks/restart.yml", [""]) != ""
    assert agents.check_run(agent, "playbooks/restart.yml", ["web1"]) == ""


def _role_id_of(agent_name: str) -> int:
    with Session(engine) as session:
        return session.exec(select(Agent).where(Agent.name == agent_name)).one().role_id


def test_granted_run_uses_the_runner_unchanged():
    agent, token, _ = _agent_with_grant("runner1")
    before = len(calls)
    r = _run(token, "playbooks/restart.yml", ["web2", "web1"])
    assert r.status_code == 202, r.text
    body = r.json()
    run = _wait_done(body["id"])
    assert run.status == "success"
    assert run.triggered_by == "agent:runner1"
    assert run.limit == "web2,web1" and run.tags is None
    assert "started run" in _last_audit().detail and _last_audit().status_code == 202

    kw = calls[before]
    assert kw["playbook"] == "playbooks/restart.yml" and kw["limit"] == "web2,web1"
    assert kw["tags"] is None and kw["ident"] == str(body["id"])
    assert not {"extravars", "check", "extra_vars"} & set(kw), f"unexpected runner args: {sorted(kw)}"
    assert len(calls) == before + 1

    cat = client.get("/api/v1/catalog", headers=_h(token)).json()
    assert cat == {"runs_enabled": True, "commands": [], "playbooks": [{"playbook": "playbooks/restart.yml", "hosts": ["web1", "web2"], "requires_approval": False}]}
    assert client.get(f"/api/v1/runs/{body['id']}", headers=_h(token)).json()["triggered_by"] == "agent:runner1"


def test_kill_switch():
    _, token, _ = _agent_with_grant("killable")
    before = len(calls)
    agents.set_runs_enabled(False)
    try:
        r = _run(token, "playbooks/restart.yml", ["web1"])
        assert r.status_code == 503, r.text
        assert _last_audit().status_code == 503
        assert len(calls) == before
        assert client.get("/api/v1/runs", headers=_h(token)).status_code == 200, "reads stay on"
        assert client.get("/api/v1/catalog", headers=_h(token)).json()["runs_enabled"] is False
    finally:
        agents.set_runs_enabled(True)
    assert _run(token, "playbooks/restart.yml", ["web1"]).status_code == 202


def test_cancel_only_your_own_running_runs():
    _, mine, _ = _agent_with_grant("canceller")
    _, other, _ = _agent_with_grant("bystander")
    hold["on"] = True
    try:
        run_id = _run(mine, "playbooks/restart.yml", ["web1"]).json()["id"]
        _wait_running(run_id)

        r = client.post(f"/api/v1/runs/{run_id}/cancel", headers=_h(other))
        assert r.status_code == 404, "another agent must not see or cancel it"
        assert client.post("/api/v1/runs/999999/cancel", headers=_h(mine)).status_code == 404

        agents.set_runs_enabled(False)  # cancelling must work with the kill switch on
        try:
            r = client.post(f"/api/v1/runs/{run_id}/cancel", headers=_h(mine))
        finally:
            agents.set_runs_enabled(True)
        assert r.status_code == 200, r.text
        assert _wait_done(run_id).status == "cancelled"
    finally:
        hold["on"] = False
    assert client.post(f"/api/v1/runs/{run_id}/cancel", headers=_h(mine)).status_code == 409, "already finished"

    ui_run = RunHistory(playbook="playbooks/restart.yml", status="running", triggered_by="alice")
    with Session(engine) as session:
        session.add(ui_run)
        session.commit()
        session.refresh(ui_run)
    assert client.post(f"/api/v1/runs/{ui_run.id}/cancel", headers=_h(mine)).status_code == 404, "UI runs are not the agent's"
    with Session(engine) as session:  # a lingering "running" UI run would now block agent runs of that playbook
        done = session.get(RunHistory, ui_run.id)
        done.status = "success"
        session.add(done)
        session.commit()


def test_deleting_a_role_removes_the_ability():
    agent, token, role = _agent_with_grant("orphaned")
    assert _run(token, "playbooks/restart.yml", ["web1"]).status_code == 202
    agents.delete_role(role.id)
    assert _run(token, "playbooks/restart.yml", ["web1"]).status_code == 403
    with Session(engine) as session:
        assert session.get(Agent, agent.id).role_id is None
        assert session.exec(select(Grant).where(Grant.role_id == role.id)).first() is None


def test_grant_validation():
    role = agents.create_role("validation")
    for playbook, hosts, why in [
        ("playbooks/restart.yml", [], "no hosts"),
        ("playbooks/restart.yml", ["  "], "blank host"),
        ("playbooks/restart.yml", ["ghost"], "host not in inventory"),
        ("playbooks/restart.yml", ["web*"], "wildcard"),
        ("playbooks/missing.yml", ["web1"], "unknown playbook"),
    ]:
        try:
            agents.add_grant(role.id, playbook, hosts)
        except ValueError:
            continue
        raise AssertionError(f"grant accepted: {why}")
    try:
        agents.add_grant(999999, "playbooks/restart.yml", ["web1"])
    except ValueError:
        pass
    else:
        raise AssertionError("grant accepted for unknown role")
    try:
        agents.create_role("validation")
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate role accepted")


def test_admin_side():
    r = admin.post("/roles", data={"name": "ui-role"}, follow_redirects=False)
    assert r.status_code == 303
    with Session(engine) as session:
        role = session.exec(select(Role).where(Role.name == "ui-role")).one()
    r = admin.post(
        f"/roles/{role.id}/grants",
        data={"playbook": "playbooks/restart.yml", "hosts": ["web1", "db1"]},
        follow_redirects=False,
    )
    assert r.status_code == 303
    page = admin.get("/agents").text
    assert "ui-role" in page and "playbooks/restart.yml" in page and "db1, web1" in page

    r = admin.post(f"/roles/{role.id}/grants", data={"playbook": "playbooks/restart.yml", "hosts": ["ghost"]})
    assert r.status_code == 400 and "inventory" in r.text

    r = admin.post("/agents", data={"name": "ui-agent", "role_id": str(role.id)})
    assert r.status_code == 200
    token = next(w for w in r.text.replace("<", " ").replace(">", " ").split() if w.startswith("ulmo_"))
    assert _run(token, "playbooks/restart.yml", ["db1"]).status_code == 202

    with Session(engine) as session:
        agent = session.exec(select(Agent).where(Agent.name == "ui-agent")).one()
    admin.post(f"/agents/{agent.id}/role", data={"role_id": ""}, follow_redirects=False)
    assert _run(token, "playbooks/restart.yml", ["db1"]).status_code == 403
    admin.post(f"/agents/{agent.id}/role", data={"role_id": str(role.id)}, follow_redirects=False)
    assert _run(token, "playbooks/restart.yml", ["db1"]).status_code == 202

    # Kill switch from the UI.
    admin.post("/agent-runs/toggle", data={}, follow_redirects=False)
    assert not agents.runs_enabled()
    admin.post("/agent-runs/toggle", data={"enable": "1"}, follow_redirects=False)
    assert agents.runs_enabled()

    # An agent token reaches none of the admin routes.
    for method, url in [("post", "/roles"), ("post", f"/roles/{role.id}/grants"), ("post", f"/agents/{agent.id}/role"),
                        ("post", "/agent-runs/toggle"), ("post", f"/grants/1/delete"), ("post", f"/roles/{role.id}/delete")]:
        r = getattr(client, method)(url, data={"name": "x", "enable": "1"}, headers=_h(token), follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/login"), f"{url}: {r.status_code}"
    assert agents.runs_enabled()
    with Session(engine) as session:
        assert session.get(Role, role.id) is not None


def test_admin_locked_without_login():
    role = agents.create_role("locked")
    agent, token = agents.create_agent("lockee")
    agents_router.AUTH_DISABLED = True
    try:
        r = admin.post(f"/roles/{role.id}/grants", data={"playbook": "playbooks/restart.yml", "hosts": ["web1"]})
        assert r.status_code == 400 and "ULMO_DISABLE_AUTH" in r.text
        admin.post(f"/agents/{agent.id}/role", data={"role_id": str(role.id)})
        admin.post(f"/agents/{agent.id}/toggle")
        assert admin.post("/agents", data={"name": "nope"}).status_code == 400
        # Switching OFF is always allowed; switching back ON is not.
        admin.post("/agent-runs/toggle", data={}, follow_redirects=False)
        assert not agents.runs_enabled()
        admin.post("/agent-runs/toggle", data={"enable": "1"}, follow_redirects=False)
        assert not agents.runs_enabled(), "re-enabling needs a login"
    finally:
        agents_router.AUTH_DISABLED = False
        agents.set_runs_enabled(True)
    with Session(engine) as session:
        a = session.get(Agent, agent.id)
        assert a.role_id is None and a.enabled is True
        assert session.exec(select(Grant).where(Grant.role_id == role.id)).first() is None
        assert session.exec(select(Agent).where(Agent.name == "nope")).first() is None


def test_role_id_column_is_added_to_an_existing_table():
    with engine.connect() as conn:
        conn.exec_driver_sql("DROP INDEX IF EXISTS ix_agent_role_id")
        conn.exec_driver_sql("ALTER TABLE agent DROP COLUMN role_id")
        conn.commit()
    database._apply_column_migrations()
    with engine.connect() as conn:
        cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(agent)")}
    assert "role_id" in cols


def test_group_names_cannot_widen_a_grant():
    role = agents.create_role("groups")
    # A grant cannot be written for a name that is also a group...
    GROUPS.append("web2")  # a group called web2 exists as well as the host web2
    try:
        try:
            agents.add_grant(role.id, "playbooks/restart.yml", ["web2"])
        except ValueError as exc:
            assert "group" in str(exc)
        else:
            raise AssertionError("grant accepted for a host that is also a group")

        # ...and a grant written before the group appeared stops working.
        GROUPS.remove("web2")
        agent, token = agents.create_agent("shadowed")
        agents.assign_role(agent.id, role.id)
        agents.add_grant(role.id, "playbooks/restart.yml", ["web1", "web2"])
        assert _run(token, "playbooks/restart.yml", ["web2"]).status_code == 202
        _wait_all_done()
        GROUPS.append("web2")
        r = _run(token, "playbooks/restart.yml", ["web2"])
        assert r.status_code == 403 and "plain inventory host" in r.json()["detail"], r.text
    finally:
        if "web2" in GROUPS:
            GROUPS.remove("web2")

    # A host that left the inventory, or an unreadable inventory, fails closed.
    _, token, _ = _agent_with_grant("gone")
    HOSTS.remove("web1")
    try:
        assert _run(token, "playbooks/restart.yml", ["web1"]).status_code == 403
        saved = HOSTS[:]
        HOSTS.clear()
        assert "unavailable" in _run(token, "playbooks/restart.yml", ["web2"]).json()["detail"]
        HOSTS.extend(saved)
    finally:
        if "web1" not in HOSTS:
            HOSTS.insert(0, "web1")


def _wait_all_done():
    for _ in range(250):
        with Session(engine) as session:
            if not session.exec(select(RunHistory).where(RunHistory.status == "running")).first():
                return
        time.sleep(0.02)
    raise AssertionError("runs still going")


def test_grants_for_one_playbook_are_unioned():
    role = agents.create_role("union")
    agents.add_grant(role.id, "playbooks/restart.yml", ["web1"])
    agents.add_grant(role.id, "playbooks/restart.yml", ["web2"])
    agent, token = agents.create_agent("unioned")
    agents.assign_role(agent.id, role.id)
    r = _run(token, "playbooks/restart.yml", ["web1", "web2"])
    assert r.status_code == 202, r.text
    _wait_all_done()
    assert _run(token, "playbooks/restart.yml", ["web1", "db1"]).status_code == 403


def test_agent_text_is_bounded():
    _, token, _ = _agent_with_grant("verbose")
    assert _run(token, "p" * 201, ["web1"]).status_code == 422
    assert _run(token, "playbooks/restart.yml", ["h" * 101]).status_code == 422
    assert _run(token, "playbooks/restart.yml", ["web1"] * 51).status_code == 422
    agents.audit("x", "POST", "/api/v1/runs", 403, "d" * 5000)
    assert len(_last_audit().detail) == agents.AUDIT_DETAIL_MAX
    r = _run(token, "playbooks/restart.yml", ["h" * 100] * 50)
    assert r.status_code == 403 and len(_last_audit().detail) <= agents.AUDIT_DETAIL_MAX


def test_overlapping_and_excess_runs_are_refused():
    role = agents.create_role("busy")
    agents.add_grant(role.id, "playbooks/restart.yml", ["web1", "web2", "db1"])
    agents.add_grant(role.id, "playbooks/other.yml", ["web1"])
    agent, token = agents.create_agent("busybee")
    agents.assign_role(agent.id, role.id)
    before = len(calls)
    cap = agent_runs.MAX_AGENT_RUNS
    agent_runs.MAX_AGENT_RUNS = 2
    hold["on"] = True
    try:
        first = _run(token, "playbooks/restart.yml", ["web1"])
        assert first.status_code == 202
        _wait_running(first.json()["id"])

        r = _run(token, "playbooks/restart.yml", ["web1", "web2"])
        assert r.status_code == 409 and str(first.json()["id"]) in r.json()["detail"], r.text
        assert _run(token, "playbooks/restart.yml", ["web1"]).status_code == 409, "identical request"

        second = _run(token, "playbooks/restart.yml", ["web2"])  # same playbook, other host: fine
        assert second.status_code == 202, second.text
        _wait_running(second.json()["id"])
        assert len(calls) == before + 2

        r = _run(token, "playbooks/other.yml", ["web1"])  # different playbook, but the cap is 2
        assert r.status_code == 429, r.text
        assert len(calls) == before + 2

        for rid in (first.json()["id"], second.json()["id"]):
            client.post(f"/api/v1/runs/{rid}/cancel", headers=_h(token))
        _wait_done(first.json()["id"])
        _wait_done(second.json()["id"])
        # A UI run with no --limit covers every host, so it blocks the agent too.
        with Session(engine) as session:
            ui = RunHistory(playbook="playbooks/restart.yml", status="running", triggered_by="alice")
            session.add(ui)
            session.commit()
            session.refresh(ui)
        r = _run(token, "playbooks/restart.yml", ["db1"])
        assert r.status_code == 409, r.text
        with Session(engine) as session:
            ui = session.get(RunHistory, ui.id)
            ui.status = "success"
            session.add(ui)
            session.commit()
    finally:
        hold["on"] = False
        agent_runs.MAX_AGENT_RUNS = cap
    _wait_all_done()


def test_cancel_ownership_and_startup_race():
    agent, mine, _ = _agent_with_grant("owner")
    hold["on"] = True
    try:
        run_id = _run(mine, "playbooks/restart.yml", ["web1"]).json()["id"]
        _wait_running(run_id)
        with Session(engine) as session:
            assert session.get(AgentRun, run_id).agent_id == agent.id

        # A user whose name looks like the agent's does not make a UI run the agent's.
        with Session(engine) as session:
            ui = RunHistory(playbook="playbooks/restart.yml", status="running", triggered_by="agent:owner")
            session.add(ui)
            session.commit()
            session.refresh(ui)
        assert client.post(f"/api/v1/runs/{ui.id}/cancel", headers=_h(mine)).status_code == 404

        # Deleting an agent and creating another with the same name (or reused id) inherits nothing.
        agents.delete_agent(agent.id)
        _, again = agents.create_agent("owner")
        assert client.post(f"/api/v1/runs/{run_id}/cancel", headers=_h(again)).status_code == 404
        with Session(engine) as session:
            assert session.get(AgentRun, run_id) is None
            ui = session.get(RunHistory, ui.id)
            ui.status = "failed"
            session.add(ui)
            session.commit()
        from app.services import runner
        runner.cancel_run(run_id)
        _wait_done(run_id)
    finally:
        hold["on"] = False

    # A run is 'running' in the database a moment before its thread registers a cancel handle.
    from app.services import runner

    agent2, token2, _ = _agent_with_grant("racer")
    with Session(engine) as session:
        run = RunHistory(playbook="playbooks/restart.yml", status="running", triggered_by="agent:racer")
        session.add(run)
        session.commit()
        session.refresh(run)
    agents.record_agent_run(run.id, agent2.id)
    event = threading.Event()
    threading.Timer(0.3, lambda: runner._cancel_events.__setitem__(run.id, event)).start()
    r = client.post(f"/api/v1/runs/{run.id}/cancel", headers=_h(token2))
    assert r.status_code == 200 and event.is_set(), r.text
    runner._cancel_events.pop(run.id, None)
    with Session(engine) as session:
        row = session.get(RunHistory, run.id)
        row.status = "cancelled"
        session.add(row)
        session.commit()
    assert client.post(f"/api/v1/runs/{run.id}/cancel", headers=_h(token2)).status_code == 409


def test_create_agent_validates_the_role_first():
    with Session(engine) as session:
        n_agents = len(session.exec(select(Agent)).all())
    for bad_role in ("abc", "999999"):
        r = admin.post("/agents", data={"name": "norole-yet", "role_id": bad_role})
        assert r.status_code == 400, f"role_id={bad_role!r}: {r.status_code}"
        assert "ulmo_" not in r.text
    with Session(engine) as session:
        assert len(session.exec(select(Agent)).all()) == n_agents, "an agent was created with a bad role"
        agent = session.exec(select(Agent).where(Agent.name == "ui-agent")).first()
    r = admin.post(f"/agents/{agent.id}/role", data={"role_id": "999999"})
    assert r.status_code == 400 and "Unknown role" in r.text
    r = admin.post("/agents/999999/role", data={"role_id": ""})
    assert r.status_code == 400 and "Unknown agent" in r.text


def test_admin_changes_are_audited():
    with Session(engine) as session:
        actions = [c.action for c in session.exec(select(AdminAudit).order_by(AdminAudit.id)).all()]
        who = {c.admin for c in session.exec(select(AdminAudit)).all()}
    for expected in ("create role", "add grant", "create agent", "set agent role", "agent runs off", "agent runs on"):
        assert expected in actions, f"{expected!r} not audited: {actions}"
    assert who == {"admin"}
    assert "set agent role" in admin.get("/activity?tab=changes").text

    # An API flood prunes AgentAudit but never the admin trail.
    keep = agents.AUDIT_KEEP
    agents.AUDIT_KEEP = 5
    try:
        for _ in range(20):
            client.get("/api/v1/hosts")
    finally:
        agents.AUDIT_KEEP = keep
    with Session(engine) as session:
        assert len(session.exec(select(AdminAudit)).all()) >= len(actions)


def test_kill_switch_is_not_a_restorable_setting():
    agents.set_runs_enabled(False)
    try:
        assert "agent_runs_disabled" not in settings_store.export_yaml()
        applied, ignored = settings_store.import_yaml("agent_runs_disabled: ''\nrun_timeout_minutes: '61'\n")
        assert "agent_runs_disabled" in ignored and not agents.runs_enabled(), "restore flipped the kill switch"
        settings_store.set_many({"run_timeout_minutes": "60"})
    finally:
        agents.set_runs_enabled(True)


def main():
    init_db()
    auth_module.create_user("admin", "pw-for-tests")
    r = admin.post("/login", data={"username": "admin", "password": "pw-for-tests"}, follow_redirects=False)
    assert r.status_code == 303 and admin.get("/agents").status_code == 200, "test login failed"
    test_default_deny()
    test_granted_run_uses_the_runner_unchanged()
    test_kill_switch()
    test_cancel_only_your_own_running_runs()
    test_deleting_a_role_removes_the_ability()
    test_grant_validation()
    test_admin_side()
    test_admin_locked_without_login()
    test_role_id_column_is_added_to_an_existing_table()
    test_group_names_cannot_widen_a_grant()
    test_grants_for_one_playbook_are_unioned()
    test_agent_text_is_bounded()
    test_overlapping_and_excess_runs_are_refused()
    test_cancel_ownership_and_startup_race()
    test_create_agent_validates_the_role_first()
    test_admin_changes_are_audited()
    test_kill_switch_is_not_a_restorable_setting()
    print("OK: agent playbook runs are default-deny, go through the unchanged runner, and are admin-controlled.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
