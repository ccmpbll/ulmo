"""Self-check for the admin proposals API: scripts propose changes to commands and roles, a signed-in admin decides.

  1. A proposer token is its own kind of credential: agent tokens are refused on /api/v1/admin and
     proposer tokens on the agent routes; neither reaches an admin page, and a proposer cannot decide.
  2. Reads: commands.yml as text, roles with their commands and approval flags.
  3. A proposal changes nothing. It is checked like the UI checks it (the whole file, the Preview
     string), shown as a diff, and notified.
  4. Approving applies it through the locked save path (one saved copy, audit naming the proposer and
     the admin) and only if the admin approves exactly what the page showed (`seen`).
  5. Bad proposals are rejected up front: bad commands, unknown names, stale deltas, no-op changes,
     a role command added without saying whether it needs approval.
  6. A change that went stale before approval fails instead of applying; deny applies nothing.
  7. Expiry, a cap per token, retries do not pile up, a proposer sees only its own, notes are
     escaped, approving is locked while ULMO_DISABLE_AUTH is set.

Run directly: python3 tests/test_admin_proposals.py
"""
import copy
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import urllib.parse
from datetime import timedelta
from pathlib import Path

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
from app.models import AdminAudit, AdminToken, AgentAudit, Grant, Proposal, RoleCommand, utcnow  # noqa: E402
from app.routers import agents as agents_router  # noqa: E402
from app.routers import proposals as proposals_router  # noqa: E402
from app.services import agents, command_library as cl, git_sync, inventory, notifier, proposals, settings_store  # noqa: E402

SSH_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
(SSH_STORAGE_DIR / "k").write_text("not a real key")

LIBRARY = {
    "commands": {
        "restart": {"description": "Restart", "argv": ["docker", "restart", "{container}"], "params": {"container": {"type": "enum", "values": ["sonarr", "radarr"]}}, "risk": "medium"},
        "uptime": {"description": "Uptime", "argv": ["uptime"], "risk": "low"},
        "spare": {"description": "Unused", "argv": ["true"]},
    },
    "hosts": {
        "frodo": {"address": "10.0.0.7", "port": 22, "user": "ansible", "ssh_key": "k", "commands": ["restart", "uptime"]},
        "ecth": {"address": "10.0.0.9", "port": 22, "user": "admin", "ssh_key": "k", "commands": ["uptime"]},
    },
}
PF = {"description": "pfSense update check", "argv": ["pfSense-upgrade", "-c"], "timeout": 60, "risk": "low"}

git_sync.list_playbooks = lambda: [{"name": "frodo.yaml", "rel_path": "playbooks/frodo.yaml"}]
inventory.list_hosts = lambda: ["frodo", "cirdan"]
inventory.list_groups = lambda: ["all", "ungrouped"]

client = TestClient(app)  # no login: scripts and agents
admin = TestClient(app)   # signed in


def get_all(path, tabs):
    """GET every tab of a page and join them: the page's content is split into tabs now, and most of
    these checks care that a piece of text is on the page somewhere, not which tab holds it."""
    from types import SimpleNamespace
    pages = [admin.get(f"{path}?tab={t}") for t in tabs]
    return SimpleNamespace(text="".join(p.text for p in pages), status_code=pages[0].status_code)

sent: list[tuple] = []


def _fake_post(url, data, name, headers=None):
    if name == "Pushover":
        f = dict(urllib.parse.parse_qsl(data.decode()))
        sent.append((f["title"], f["message"], f.get("url", "")))


notifier._post = _fake_post


def _h(token):
    return {"Authorization": f"Bearer {token}"}


def _reset(library=LIBRARY):
    """Back to a known library and roles; nothing pending."""
    cl.LIBRARY_PATH.write_text(yaml.safe_dump(copy.deepcopy(library), sort_keys=False))
    assert not cl.load()[1], cl.load()[1]
    with Session(engine) as session:
        for row in session.exec(select(Proposal)).all():
            session.delete(row)
        for row in session.exec(select(RoleCommand)).all():
            session.delete(row)
        session.commit()
    n8n = _role("n8n")
    agents.set_role_commands(n8n.id, ["restart", "uptime"])
    agents.set_commands_needing_approval(n8n.id, ["restart"])
    viewer = _role("viewer")
    agents.set_role_commands(viewer.id, ["uptime"])
    shutil.rmtree(cl.HISTORY_DIR, ignore_errors=True)
    sent.clear()


def _role(name):
    with Session(engine) as session:
        from app.models import Role
        existing = session.exec(select(Role).where(Role.name == name)).first()
        if existing:
            return existing
    return agents.create_role(name)


def _token(name):
    r = admin.post("/admin-tokens", data={"name": name})
    assert r.status_code == 200, r.text
    return re.search(r"(ulmo_admin_[A-Za-z0-9_-]+)", r.text).group(1)


def _propose(token, ops, note=None, dry_run=False):
    body = {"ops": ops}
    if note is not None:
        body["note"] = note
    return client.post("/api/v1/admin/proposals" + ("?dry_run=true" if dry_run else ""), json=body, headers=_h(token))


PF_OPS = [
    {"op": "save_command", "name": "pfsense-update-check", "body": PF},
    {"op": "host_offer", "host": "ecth", "add": ["pfsense-update-check"]},
    {"op": "role_allow", "role": "n8n", "add": [{"command": "pfsense-update-check", "needs_approval": False}]},
]


def _seen(proposal_id):
    page = admin.get(f"/proposals/{proposal_id}").text
    found = re.search(r'name="seen" value="([0-9a-f]+)"', page)
    assert found, page
    return found.group(1)


def _approve(proposal_id, seen=None):
    return admin.post(f"/proposals/{proposal_id}/approve", data={"seen": _seen(proposal_id) if seen is None else seen}, follow_redirects=True)


def _row(proposal_id):
    with Session(engine) as session:
        return session.get(Proposal, proposal_id)


def _role_cmds(name):
    role = _role(name)
    with Session(engine) as session:
        return {c.command: c.requires_approval for c in session.exec(select(RoleCommand).where(RoleCommand.role_id == role.id)).all()}


def _file():
    return yaml.safe_load(cl.read_text())


def _saved_copies():
    return len(list(cl.HISTORY_DIR.glob("*.yml"))) if cl.HISTORY_DIR.is_dir() else 0


def _library_unchanged():
    assert _file() == LIBRARY, "the library must not change"


# --- 1. credentials ------------------------------------------------------------------


def test_tokens_are_separate_credentials():
    _reset()
    token = _token("scripts")
    with Session(engine) as session:
        row = session.exec(select(AdminToken).where(AdminToken.name == "scripts")).one()
    assert row.token_hash == agents.hash_token(token) and token not in row.token_hash and token not in str(row.__dict__.values())

    agent, agent_token = agents.create_agent("n8n-agent")
    for path in ("/api/v1/admin/commands.yml", "/api/v1/admin/roles", "/api/v1/admin/proposals"):
        assert client.get(path, headers=_h(agent_token)).status_code == 401, "an agent token must not reach the admin API"
        assert client.get(path).status_code == 401
        assert client.get(path, headers=_h(token)).status_code == 200
    r = client.post("/api/v1/admin/proposals", json={"ops": PF_OPS}, headers=_h(agent_token))
    assert r.status_code == 401
    for path in ("/api/v1/catalog", "/api/v1/runs", "/api/v1/hosts"):
        assert client.get(path, headers=_h(token)).status_code == 401, "a proposer token must not act as an agent"
    r = client.post("/api/v1/commands", json={"command": "uptime", "host": "frodo"}, headers=_h(token))
    assert r.status_code == 401

    # neither is a login
    for method, url in (("get", "/proposals/1"), ("post", "/proposals/1/approve"), ("post", "/proposals/1/deny"), ("post", "/admin-tokens"),
                        ("post", "/commands/save"), ("get", "/approvals")):
        r = getattr(client, method)(url, headers=_h(token), follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/login"), (url, r.status_code)

    # disabled and expired tokens are refused; the audit log says why
    admin.post(f"/admin-tokens/{row.id}/toggle")
    assert client.get("/api/v1/admin/roles", headers=_h(token)).status_code == 401
    admin.post(f"/admin-tokens/{row.id}/toggle")
    assert client.get("/api/v1/admin/roles", headers=_h(token)).status_code == 200
    with Session(engine) as session:
        t = session.get(AdminToken, row.id)
        t.expires_at = utcnow() - timedelta(days=1)
        session.add(t)
        session.commit()
    assert client.get("/api/v1/admin/roles", headers=_h(token)).status_code == 401
    with Session(engine) as session:
        t = session.get(AdminToken, row.id)
        t.expires_at = None
        session.add(t)
        session.commit()
        why = [a.detail for a in session.exec(select(AgentAudit).where(AgentAudit.agent_name == "admin:scripts")).all()]
    assert "token disabled" in why and "token expired" in why, why


def test_token_creation_page():
    r = admin.post("/admin-tokens", data={"name": "pagetoken", "expires_days": "30"})
    assert r.status_code == 200 and "ulmo_admin_" in r.text and r.headers["cache-control"] == "no-store"
    assert "pagetoken" in get_all("/agents", ("agents", "roles", "tokens")).text and "ulmo_admin_" not in get_all("/agents", ("agents", "roles", "tokens")).text, "the token is shown once"
    assert admin.post("/admin-tokens", data={"name": "pagetoken"}).status_code == 400, "names are unique"
    assert admin.post("/admin-tokens", data={"name": "bad name!"}).status_code == 400
    assert admin.post("/admin-tokens", data={"name": "x", "expires_days": "soon"}).status_code == 400
    with Session(engine) as session:
        row = session.exec(select(AdminToken).where(AdminToken.name == "pagetoken")).one()
        assert row.expires_at is not None
        audit = [a.detail for a in session.exec(select(AdminAudit).where(AdminAudit.action == "create change token")).all()]
    assert any("pagetoken" in d for d in audit)


# --- 2. reads ------------------------------------------------------------------------------


def test_reads():
    _reset()
    token = _token("reader")
    r = client.get("/api/v1/admin/commands.yml", headers=_h(token))
    assert r.status_code == 200 and r.text == cl.read_text() and yaml.safe_load(r.text) == LIBRARY
    assert r.headers["content-type"].startswith("text/plain") or "yaml" in r.headers["content-type"]
    roles = {r["name"]: r for r in client.get("/api/v1/admin/roles", headers=_h(token)).json()["roles"]}
    assert roles["n8n"]["commands"] == [{"command": "restart", "needs_approval": True}, {"command": "uptime", "needs_approval": False}]
    assert roles["viewer"]["commands"] == [{"command": "uptime", "needs_approval": False}]
    assert roles["n8n"]["playbooks"] == []
    with Session(engine) as session:
        session.add(Grant(role_id=_role("n8n").id, playbook="playbooks/frodo.yaml", hosts="frodo", requires_approval=True))
        session.commit()
    roles = {r["name"]: r for r in client.get("/api/v1/admin/roles", headers=_h(token)).json()["roles"]}
    assert roles["n8n"]["playbooks"] == [{"playbook": "playbooks/frodo.yaml", "hosts": ["frodo"], "requires_approval": True}]
    with Session(engine) as session:
        for g in session.exec(select(Grant)).all():
            session.delete(g)
        session.commit()


# --- 3. a proposal changes nothing -------------------------------------------------------------


def test_proposal_changes_nothing_and_is_shown_and_notified():
    _reset()
    settings_store.set_many({"public_url": "https://ulmo.example"})
    token = _token("proposer")
    copies = _saved_copies()
    r = _propose(token, PF_OPS, note="pfSense update check for the nightly sweep")
    assert r.status_code == 202, r.text
    body = r.json()
    pid = body["id"]
    assert body["status"] == "pending" and body["poll"] == f"/api/v1/admin/proposals/{pid}"
    assert re.search(r"^\+\s+pfsense-update-check:", body["diff"], re.M), "the library diff shows the new command"
    assert "\n+  pfsense-update-check\n" in "\n" + body["diff"] + "\n", "the roles diff shows who gets it"
    assert any(p["command"] == "pfsense-update-check" and p["line"] == "timeout -k 5 60 pfSense-upgrade -c" for p in body["previews"]), body["previews"]

    _library_unchanged()
    assert _role_cmds("n8n") == {"restart": True, "uptime": False}, "nothing applies before an admin approves"
    assert _saved_copies() == copies

    for _ in range(100):
        if sent:
            break
        time.sleep(0.02)
    assert sent and "proposer" in sent[0][0] and "pfsense-update-check" in sent[0][1] and sent[0][2] == f"https://ulmo.example/proposals/{pid}", sent
    settings_store.set_many({"public_url": ""})

    page = get_all("/approvals", ("waiting", "history")).text
    assert "Change proposals" in page and f"/proposals/{pid}" in page and "proposer" in page
    assert "Approvals <span" in get_all("/agents", ("agents", "roles", "tokens")).text, "the nav counts waiting proposals"
    detail = admin.get(f"/proposals/{pid}").text
    assert "pfsense-update-check" in detail and "The host would receive: timeout -k 5 60 pfSense-upgrade -c" in detail
    assert "pfSense update check for the nightly sweep" in detail and f"/proposals/{pid}/approve" in detail

    audit = [a for a in _admin_audit("propose change")]
    assert audit and audit[-1].admin == "admin:proposer" and "pfsense-update-check" in audit[-1].detail
    got = client.get(f"/api/v1/admin/proposals/{pid}", headers=_h(token)).json()
    assert got["status"] == "pending" and got["ops"] == PF_OPS and got["note"].startswith("pfSense")


def _admin_audit(action):
    with Session(engine) as session:
        return list(session.exec(select(AdminAudit).where(AdminAudit.action == action).order_by(AdminAudit.id)).all())


def test_dry_run_records_nothing():
    _reset()
    token = _token("dry")
    r = _propose(token, PF_OPS, dry_run=True)
    assert r.status_code == 200 and r.json()["valid"] is True and "pfsense-update-check" in r.json()["diff"]
    with Session(engine) as session:
        assert session.exec(select(Proposal)).first() is None
    assert not sent
    r = _propose(token, [{"op": "delete_command", "name": "nope"}], dry_run=True)
    assert r.status_code == 400


# --- 4. approving ---------------------------------------------------------------------------------


def test_approve_applies_exactly_what_was_shown():
    _reset()
    token = _token("applier")
    pid = _propose(token, PF_OPS, note="go").json()["id"]
    before_copies = _saved_copies()

    r = admin.post(f"/proposals/{pid}/approve", data={}, follow_redirects=True)
    assert "changed since you opened" in r.text or "Reload" in r.text, "no `seen` means nothing was reviewed"
    r = admin.post(f"/proposals/{pid}/approve", data={"seen": "0" * 64}, follow_redirects=True)
    assert "changed since you opened" in r.text
    assert _row(pid).status == "pending" and "pfsense-update-check" not in _file()["commands"]

    r = _approve(pid)
    assert r.status_code == 200
    row = _row(pid)
    assert row.status == "applied" and row.decided_by == "admin" and row.decided_at
    data = _file()
    assert data["commands"]["pfsense-update-check"] == PF
    assert data["hosts"]["ecth"]["commands"] == ["uptime", "pfsense-update-check"]
    assert data["hosts"]["frodo"] == LIBRARY["hosts"]["frodo"], "other hosts are untouched"
    assert _role_cmds("n8n") == {"restart": True, "uptime": False, "pfsense-update-check": False}
    assert _role_cmds("viewer") == {"uptime": False}
    assert _saved_copies() == before_copies + 1, "several library changes make one saved copy, restorable"
    assert not cl.load()[1]
    audit = _admin_audit("approve change proposal")
    assert audit[-1].admin == "admin" and "admin:applier" in audit[-1].detail and "pfsense-update-check" in audit[-1].detail

    # a role can now use it
    agent, agent_token = agents.create_agent("n8n-user")
    agents.assign_role(agent.id, _role("n8n").id)
    cat = client.get("/api/v1/catalog", headers=_h(agent_token)).json()["commands"]
    assert {c["command"]: c["requires_approval"] for c in cat}["pfsense-update-check"] is False
    assert [c for c in cat if c["command"] == "pfsense-update-check"][0]["hosts"] == ["ecth"]

    # approving again does nothing more
    r = admin.post(f"/proposals/{pid}/approve", data={"seen": "x"}, follow_redirects=True)
    assert "already applied" in r.text and _saved_copies() == before_copies + 1
    assert client.get(f"/api/v1/admin/proposals/{pid}", headers=_h(token)).json()["status"] == "applied"

    # and the saved copy restores it
    newest = cl.list_versions()[0]["id"]
    cl.restore(newest)
    assert _file() == LIBRARY


def test_only_a_login_decides():
    _reset()
    token = _token("nodecide")
    pid = _propose(token, PF_OPS).json()["id"]
    seen = _seen(pid)
    for url, data in ((f"/proposals/{pid}/approve", {"seen": seen}), (f"/proposals/{pid}/deny", {})):
        r = client.post(url, data=data, headers=_h(token), follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/login")
        r = client.post(url, data=data, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/login")
    assert _row(pid).status == "pending"
    _library_unchanged()


def test_deny_applies_nothing():
    _reset()
    token = _token("denied")
    pid = _propose(token, PF_OPS).json()["id"]
    admin.post(f"/proposals/{pid}/deny")
    assert _row(pid).status == "denied" and _row(pid).decided_by == "admin"
    _library_unchanged()
    assert _role_cmds("n8n") == {"restart": True, "uptime": False}
    r = admin.post(f"/proposals/{pid}/approve", data={"seen": "x"}, follow_redirects=True)
    assert "already denied" in r.text and _row(pid).status == "denied"
    assert _admin_audit("deny change proposal")


def test_delete_a_command_shows_what_roles_lose():
    _reset()
    token = _token("deleter")
    ops = [{"op": "host_offer", "host": "frodo", "remove": ["restart"]}, {"op": "delete_command", "name": "restart"}]
    r = _propose(token, ops)
    assert r.status_code == 202, r.text
    assert "\n-  restart [needs approval]\n" in "\n" + r.json()["diff"] + "\n", "the role that loses the command is in the diff"
    pid = r.json()["id"]
    _approve(pid)
    assert _row(pid).status == "applied"
    assert "restart" not in _file()["commands"] and _file()["hosts"]["frodo"]["commands"] == ["uptime"]
    assert _role_cmds("n8n") == {"uptime": False}


def test_role_and_flag_changes():
    _reset()
    token = _token("roler")
    ops = [
        {"op": "role_allow", "role": "viewer", "add": [{"command": "restart", "needs_approval": True}], "remove": ["uptime"]},
        {"op": "role_set_approval", "role": "n8n", "command": "uptime", "needs_approval": True},
        {"op": "role_set_approval", "role": "n8n", "command": "restart", "needs_approval": False},
    ]
    r = _propose(token, ops)
    assert r.status_code == 202, r.text
    _approve(r.json()["id"])
    assert _role_cmds("viewer") == {"restart": True}
    assert _role_cmds("n8n") == {"restart": False, "uptime": True}
    _library_unchanged()
    assert _saved_copies() == 0, "a role-only change writes no library copy"


def test_updating_a_command_shows_old_and_new():
    _reset()
    token = _token("updater")
    new = {**LIBRARY["commands"]["uptime"], "description": "Uptime and load"}
    r = _propose(token, [{"op": "save_command", "name": "uptime", "body": new}])
    assert r.status_code == 202, r.text
    assert re.search(r"^-\s+description: Uptime$", r.json()["diff"], re.M) and re.search(r"^\+\s+description: Uptime and load$", r.json()["diff"], re.M)
    _approve(r.json()["id"])
    assert _file()["commands"]["uptime"]["description"] == "Uptime and load"


def test_samples_drive_the_preview():
    _reset()
    token = _token("sampler")
    body = {"description": "Show a unit", "argv": ["systemctl", "status", "{unit}"], "params": {"unit": {"type": "regex", "pattern": "[a-z0-9@._-]+", "max_length": 60}}}
    ops = [{"op": "save_command", "name": "unit-status", "body": body, "samples": {"unit": "nginx"}}]
    r = _propose(token, ops)
    assert r.status_code == 202, r.text
    assert r.json()["previews"] == [{"command": "unit-status", "line": "timeout -k 5 30 systemctl status nginx"}]
    r = _propose(token, [{**ops[0], "samples": {"unit": "-x; rm"}}])
    assert r.status_code == 400 and "unit" in r.text, "a sample that the command would refuse is a rejected proposal"
    r = _propose(token, [{**ops[0], "samples": {"unit": "a", "extra": "b"}}])
    assert r.status_code == 400
    r = _propose(token, [{k: v for k, v in ops[0].items() if k != "samples"}])
    assert r.status_code == 202 and r.json()["previews"] == [], "no samples and required blanks: no preview, not an error"


# --- 5. rejected up front --------------------------------------------------------------------------------


def test_bad_proposals_are_rejected_and_record_nothing():
    _reset()
    token = _token("badone")
    PFB = dict(PF)
    audited = len(_admin_audit("propose change"))

    def bad(ops, why=None):
        r = _propose(token, ops)
        assert r.status_code in (400, 422), (ops, r.status_code, r.text)
        if why:
            assert why in r.text, (why, r.text)
        with Session(engine) as session:
            assert session.exec(select(Proposal)).first() is None, ops

    bad([], None)
    bad([{"op": "nope"}], "unknown operation")
    bad([{"op": "save_command", "name": "x", "body": PFB, "surprise": 1}], "unknown keys")
    bad([{"op": "save_command", "name": "bad name", "body": PFB}], "command name")
    bad([{"op": "save_command", "name": "x", "body": {**PFB, "surprise": 1}}], "unknown keys")
    bad([{"op": "save_command", "name": "x", "body": {**PFB, "argv": ["a", "{undeclared}"]}}], "undeclared")
    bad([{"op": "save_command", "name": "x", "body": {**PFB, "argv": ["a", "{"]}}], "stray brace")
    bad([{"op": "save_command", "name": "x", "body": {**PFB, "timeout": 9999}}], "timeout")
    bad([{"op": "save_command", "name": "x", "body": {**PFB, "argv": ["a", "{p}"], "params": {"p": {"type": "regex", "pattern": "(", "max_length": 5}}}}], "bad pattern")
    bad([{"op": "save_command", "name": "x", "body": "not a mapping"}], "mapping")
    bad([{"op": "save_command", "name": "x"}], "body")
    bad([{"op": "delete_command", "name": "nope"}], "no such command")
    bad([{"op": "delete_command", "name": "uptime"}], "still offered by")
    bad([{"op": "host_offer", "host": "nope", "add": ["uptime"]}], "no such host")
    bad([{"op": "host_offer", "host": "ecth", "add": ["nope"]}], "do not exist")
    bad([{"op": "host_offer", "host": "ecth", "add": ["uptime"]}], "already offered")
    bad([{"op": "host_offer", "host": "ecth", "remove": ["restart"]}], "not offered")
    bad([{"op": "host_offer", "host": "ecth"}], "add or remove")
    bad([{"op": "host_offer", "host": "ecth", "add": "uptime"}], None)
    bad([{"op": "role_allow", "role": "nope", "add": [{"command": "uptime", "needs_approval": False}]}], "no such role")
    bad([{"op": "role_allow", "role": "n8n", "add": [{"command": "spare"}]}], "needs_approval")
    bad([{"op": "role_allow", "role": "n8n", "add": [{"command": "spare", "needs_approval": "no"}]}], "needs_approval")
    bad([{"op": "role_allow", "role": "n8n", "add": [{"command": "nope", "needs_approval": False}]}], "not in the command library")
    bad([{"op": "role_allow", "role": "n8n", "add": [{"command": "uptime", "needs_approval": False}]}], "already")
    bad([{"op": "role_allow", "role": "n8n", "remove": ["spare"]}], "does not have")
    bad([{"op": "role_allow", "role": "n8n"}], "add or remove")
    bad([{"op": "role_set_approval", "role": "n8n", "command": "spare", "needs_approval": True}], "does not have")
    bad([{"op": "role_set_approval", "role": "n8n", "command": "uptime"}], "needs_approval")
    bad([{"op": "role_allow", "role": "n8n", "add": [{"command": "spare", "needs_approval": False, "extra": 1}]}], "unknown keys")
    bad([{"op": "delete_command", "name": "spare"}, {"op": "role_allow", "role": "n8n", "add": [{"command": "spare", "needs_approval": False}]}], "not in the command library")
    bad([{"op": "save_command", "name": f"c{i}", "body": PFB} for i in range(21)], None)
    # a change that changes nothing is not a proposal
    bad([{"op": "save_command", "name": "uptime", "body": LIBRARY["commands"]["uptime"]}], "changes nothing")
    bad([{"op": "role_set_approval", "role": "n8n", "command": "uptime", "needs_approval": False}], "changes nothing")
    # each of these is whole-or-nothing: a good op next to a bad one records nothing
    bad([{"op": "save_command", "name": "fine", "body": PFB}, {"op": "delete_command", "name": "nope"}], "op 2")
    r = client.post("/api/v1/admin/proposals", json={"ops": "x"}, headers=_h(token))
    assert r.status_code in (400, 422)
    r = client.post("/api/v1/admin/proposals", json={"ops": PF_OPS, "note": "x" * 501}, headers=_h(token))
    assert r.status_code in (400, 422)
    _library_unchanged()
    assert len(_admin_audit("propose change")) == audited, "a rejected proposal leaves no trace in the admin log"


def test_a_broken_file_blocks_proposals():
    _reset()
    token = _token("brokenfile")
    good = cl.LIBRARY_PATH.read_text()
    cl.LIBRARY_PATH.write_text("commands: [this is: not valid")
    try:
        r = _propose(token, PF_OPS)
        assert r.status_code == 409 and "commands.yml" in r.text, (r.status_code, r.text)
    finally:
        cl.LIBRARY_PATH.write_text(good)
        assert not cl.load()[1]


# --- 6. stale ---------------------------------------------------------------------------------------------------


def test_a_change_made_after_the_page_loaded_is_not_applied_unseen():
    _reset()
    token = _token("stale")
    pid = _propose(token, [{"op": "save_command", "name": "pfsense-update-check", "body": PF}]).json()["id"]
    seen = _seen(pid)
    cl.save_command("spare", {"description": "Changed meanwhile", "argv": ["true"]})  # an unrelated edit, still a change
    r = admin.post(f"/proposals/{pid}/approve", data={"seen": seen}, follow_redirects=True)
    assert "changed since you opened" in r.text
    assert _row(pid).status == "pending" and "pfsense-update-check" not in _file()["commands"]
    _approve(pid)  # a fresh page, a fresh look
    assert _row(pid).status == "applied" and _file()["commands"]["spare"]["description"] == "Changed meanwhile"


def test_a_proposal_that_went_stale_fails_instead_of_applying():
    _reset()
    token = _token("stale2")
    pid = _propose(token, [{"op": "host_offer", "host": "ecth", "add": ["restart"]}]).json()["id"]
    cl.save_host("ecth", {**LIBRARY["hosts"]["ecth"], "commands": ["uptime", "restart"]})  # someone did the same by hand
    r = admin.post(f"/proposals/{pid}/approve", data={"seen": "x"}, follow_redirects=True)
    row = _row(pid)
    assert row.status == "failed" and "already offered" in row.result, (row.status, row.result)
    assert _file()["hosts"]["ecth"]["commands"] == ["uptime", "restart"]
    assert "already offered" in admin.get(f"/proposals/{pid}").text
    # the page of a stale pending proposal explains instead of offering Approve
    pid2 = _propose(token, [{"op": "host_offer", "host": "frodo", "remove": ["uptime"]}]).json()["id"]
    cl.save_host("frodo", {**LIBRARY["hosts"]["frodo"], "commands": ["restart"]})
    page = admin.get(f"/proposals/{pid2}").text
    assert "not offered" in page and f"/proposals/{pid2}/approve" not in page and f"/proposals/{pid2}/deny" in page


# --- 7. limits and hygiene -------------------------------------------------------------------------------------------


def test_expiry_cap_and_retries():
    _reset()
    token = _token("limits")
    other = _token("limits-other")
    r1 = _propose(token, PF_OPS)
    r2 = _propose(token, PF_OPS)
    assert r1.status_code == r2.status_code == 202 and r1.json()["id"] == r2.json()["id"], "a retry returns the waiting proposal"
    reordered = [dict(reversed(list(op.items()))) for op in PF_OPS]
    assert _propose(token, reordered).json()["id"] == r1.json()["id"], "the same proposal with its keys in another order is still a retry"
    time.sleep(0.2)
    assert len(sent) == 1, "and does not notify again"
    pid = r1.json()["id"]
    left = _row(pid).expires_at.replace(tzinfo=None) - utcnow().replace(tzinfo=None)
    assert timedelta(hours=23) < left <= timedelta(hours=24), "a proposal waits a day for a human"

    assert client.get(f"/api/v1/admin/proposals/{pid}", headers=_h(other)).status_code == 404, "a proposer sees only its own"
    assert client.get("/api/v1/admin/proposals", headers=_h(other)).json()["proposals"] == []
    assert [p["id"] for p in client.get("/api/v1/admin/proposals", headers=_h(token)).json()["proposals"]] == [pid]

    for i in range(proposals.MAX_PENDING_PER_TOKEN - 1):
        assert _propose(token, [{"op": "save_command", "name": f"c{i}", "body": PF}]).status_code == 202
    r = _propose(token, [{"op": "save_command", "name": "one-too-many", "body": PF}])
    assert r.status_code == 429, r.text
    assert _propose(other, [{"op": "save_command", "name": "one-too-many", "body": PF}]).status_code == 202, "the cap is per token"

    with Session(engine) as session:
        row = session.get(Proposal, pid)
        row.expires_at = utcnow() - timedelta(minutes=1)
        session.add(row)
        session.commit()
    assert client.get(f"/api/v1/admin/proposals/{pid}", headers=_h(token)).json()["status"] == "expired"
    r = admin.post(f"/proposals/{pid}/approve", data={"seen": "x"}, follow_redirects=True)
    assert "already expired" in r.text
    _library_unchanged()
    r = _propose(token, [{"op": "save_command", "name": "after-expiry", "body": PF}])
    assert r.status_code == 202, "an expired proposal frees a slot"


def test_note_is_escaped_and_cleaned():
    _reset()
    token = _token("noter")
    pid = _propose(token, PF_OPS, note="<script>alert(1)</script>‮evil​  text\n\n here").json()["id"]
    note = _row(pid).note
    assert "‮" not in note and "​" not in note and "  " not in note and "\n" not in note
    page = admin.get(f"/proposals/{pid}").text
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page
    # the diff is untrusted too: command text with markup is shown escaped
    body = {**PF, "description": "<img src=x onerror=alert(1)>"}
    pid2 = _propose(token, [{"op": "save_command", "name": "html", "body": body}]).json()["id"]
    assert "<img src=x" not in admin.get(f"/proposals/{pid2}").text
    assert "<img src=x" not in get_all("/approvals", ("waiting", "history")).text


def test_locked_while_auth_is_disabled():
    _reset()
    token = _token("locked")
    pid = _propose(token, PF_OPS).json()["id"]
    seen = _seen(pid)
    agents_router.AUTH_DISABLED = proposals_router.AUTH_DISABLED = True
    try:
        r = admin.post(f"/proposals/{pid}/approve", data={"seen": seen}, follow_redirects=True)
        assert "ULMO_DISABLE_AUTH" in r.text
        assert _row(pid).status == "pending"
        r = admin.post("/admin-tokens", data={"name": "newone"})
        assert r.status_code == 400 and "ULMO_DISABLE_AUTH" in r.text
        admin.post(f"/proposals/{pid}/deny")
        assert _row(pid).status == "denied", "saying no is always allowed"
    finally:
        agents_router.AUTH_DISABLED = proposals_router.AUTH_DISABLED = False
    _library_unchanged()


def test_deleting_a_token_removes_its_proposals():
    _reset()
    token = _token("gone")
    pid = _propose(token, PF_OPS).json()["id"]
    with Session(engine) as session:
        tid = session.exec(select(AdminToken).where(AdminToken.name == "gone")).one().id
    admin.post(f"/admin-tokens/{tid}/delete")
    assert _row(pid) is None
    assert client.get("/api/v1/admin/roles", headers=_h(token)).status_code == 401
    new = _token("gone2")  # a new token must not inherit the old one's proposals
    assert client.get("/api/v1/admin/proposals", headers=_h(new)).json()["proposals"] == []


def test_requests_are_audited():
    _reset()
    token = _token("audited")
    _propose(token, PF_OPS)
    client.get("/api/v1/admin/roles", headers=_h(token))
    client.get("/api/v1/admin/roles", headers=_h("ulmo_admin_wrong"))
    with Session(engine) as session:
        rows = session.exec(select(AgentAudit).where(AgentAudit.path.like("/api/v1/admin%")).order_by(AgentAudit.id.desc())).all()
    names = [(r.agent_name, r.method, r.status_code) for r in rows]
    assert (None, "GET", 401) in names and ("admin:audited", "GET", 200) in names and ("admin:audited", "POST", 202) in names, names


# --- 8. review fixes ----------------------------------------------------------------------------------------------


def test_hidden_characters_are_refused():
    _reset()
    token = _token("hidden")
    for where, op in (
        ("description", {"op": "save_command", "name": "h1", "body": {**PF, "description": "ok\u202etxt"}}),
        ("argv", {"op": "save_command", "name": "h2", "body": {**PF, "argv": ["echo", "a\u200bb"]}}),
        ("samples", {"op": "save_command", "name": "h3", "body": {**PF, "argv": ["echo", "{x}"], "params": {"x": {"type": "regex", "pattern": ".*", "max_length": 9}}}, "samples": {"x": "a\u2066"}}),
        ("a name", {"op": "host_offer", "host": "ecth\u200b", "add": ["uptime"]}),
    ):
        r = _propose(token, [op])
        assert r.status_code == 400 and "direction-override" in r.text, (where, r.status_code, r.text)
    r = _propose(token, [{"op": "save_command", "name": "multi", "body": {**PF, "description": "two\nlines\tand é and 日本"}}])
    assert r.status_code == 202, r.text


def test_one_command_cannot_exceed_the_editors_limit():
    _reset()
    token = _token("big")
    r = _propose(token, [{"op": "save_command", "name": "big", "body": {**PF, "description": "x" * (cl.MAX_COMMAND_BYTES + 100)}}])
    assert r.status_code == 400 and "limited to 20 KB" in r.text, r.text
    assert _propose(token, [{"op": "save_command", "name": "ok", "body": {**PF, "description": "x" * 5000}}]).status_code == 202


def test_a_disabled_or_expired_token_cannot_have_its_proposals_applied():
    _reset()
    token = _token("revoked")
    with Session(engine) as session:
        tid = session.exec(select(AdminToken).where(AdminToken.name == "revoked")).one().id
    pid = _propose(token, PF_OPS).json()["id"]
    seen = _seen(pid)
    admin.post(f"/admin-tokens/{tid}/toggle")
    page = admin.get(f"/proposals/{pid}").text
    assert "can no longer be applied" in page and "disabled" in page and f"/proposals/{pid}/approve" not in page and f"/proposals/{pid}/deny" in page
    admin.post(f"/proposals/{pid}/approve", data={"seen": seen})
    row = _row(pid)
    assert row.status == "failed" and "disabled" in row.result, (row.status, row.result)
    _library_unchanged()
    admin.post(f"/admin-tokens/{tid}/toggle")

    pid = _propose(token, [{"op": "save_command", "name": "later", "body": PF}]).json()["id"]
    with Session(engine) as session:
        t = session.get(AdminToken, tid)
        t.expires_at = utcnow() - timedelta(days=1)
        session.add(t)
        session.commit()
    assert "has expired" in admin.get(f"/proposals/{pid}").text
    admin.post(f"/proposals/{pid}/approve", data={"seen": "x"})
    assert _row(pid).status == "failed" and "expired" in _row(pid).result
    _library_unchanged()


def test_a_file_being_fixed_by_hand_does_not_use_up_the_proposal():
    _reset()
    token = _token("patient")
    pid = _propose(token, PF_OPS).json()["id"]
    good = cl.LIBRARY_PATH.read_text()
    cl.LIBRARY_PATH.write_text("commands: [this is: not valid")
    try:
        r = admin.post(f"/proposals/{pid}/approve", data={"seen": "x"}, follow_redirects=True)
        assert "does not parse" in r.text and _row(pid).status == "pending"
    finally:
        cl.LIBRARY_PATH.write_text(good)
    assert not cl.load()[1]
    _approve(pid)
    assert _row(pid).status == "applied" and "pfsense-update-check" in _file()["commands"]


def test_applying_is_all_or_nothing():
    _reset()
    token = _token("atomic")
    real = proposals._write_roles

    # the role step fails: the library must not have changed, and no saved copy is made
    pid = _propose(token, PF_OPS).json()["id"]
    seen = _seen(pid)

    def boom(*a):
        raise ValueError("boom")

    proposals._write_roles = boom
    try:
        admin.post(f"/proposals/{pid}/approve", data={"seen": seen})
    finally:
        proposals._write_roles = real
    row = _row(pid)
    assert row.status == "failed" and "boom" in row.result
    _library_unchanged()
    assert _saved_copies() == 0 and _role_cmds("n8n") == {"restart": True, "uptime": False}

    # the library write is refused (the file changed under it): the roles are put back
    pid = _propose(token, PF_OPS).json()["id"]
    seen = _seen(pid)
    real_apply = cl.apply_data
    cl.apply_data = lambda data, base: real_apply(data, "stale-version")
    try:
        admin.post(f"/proposals/{pid}/approve", data={"seen": seen})
    finally:
        cl.apply_data = real_apply
    row = _row(pid)
    assert row.status == "failed" and "changed since" in row.result, (row.status, row.result)
    _library_unchanged()
    assert _role_cmds("n8n") == {"restart": True, "uptime": False}, "the roles went back when the library write was refused"

    # the swap fails after the roles were written: they are put back
    pid = _propose(token, [{"op": "delete_command", "name": "spare"}, {"op": "role_allow", "role": "viewer", "add": [{"command": "restart", "needs_approval": True}]}]).json()["id"]
    seen = _seen(pid)
    real_replace = os.replace

    def broken(*a, **k):
        raise OSError("disk full")

    os.replace = broken
    try:
        admin.post(f"/proposals/{pid}/approve", data={"seen": seen})
    finally:
        os.replace = real_replace
    row = _row(pid)
    assert row.status == "failed" and "disk full" in row.result, (row.status, row.result)
    _library_unchanged()
    assert _role_cmds("viewer") == {"uptime": False}, "the roles went back with the failed swap"

    # the new file was swapped in and only the folder sync failed: the write landed, so the roles stay with it
    pid = _propose(token, PF_OPS).json()["id"]
    seen = _seen(pid)
    real_open = os.open

    def sync_fails(path, flags, *a, **k):
        if str(path) == str(cl.LIBRARY_PATH.parent) and flags == os.O_RDONLY:
            raise OSError("sync failed")
        return real_open(path, flags, *a, **k)

    os.open = sync_fails
    try:
        admin.post(f"/proposals/{pid}/approve", data={"seen": seen})
    finally:
        os.open = real_open
    row = _row(pid)
    assert row.status == "failed" and "sync failed" in row.result, (row.status, row.result)
    assert "pfsense-update-check" in _file()["commands"], "the file was swapped in"
    assert _role_cmds("n8n") == {"restart": True, "uptime": False, "pfsense-update-check": False}, "so the roles stay in step with it"
    cl.restore(cl.list_versions()[0]["id"])
    agents.set_role_commands(_role("n8n").id, ["restart", "uptime"])
    agents.set_commands_needing_approval(_role("n8n").id, ["restart"])
    _library_unchanged()

    # a role edited on the Agents page after the plan was made is not overwritten
    plan = proposals.plan(PF_OPS)
    agents.set_role_commands(_role("n8n").id, ["uptime"])
    try:
        proposals._write_roles(plan.roles_after, plan.roles_before)
        raise AssertionError("a changed role must stop the write")
    except ValueError as exc:
        assert "changed meanwhile" in str(exc)
    assert _role_cmds("n8n") == {"uptime": False}


def test_planning_is_rate_limited_per_token():
    _reset()
    first, second = _token("busy"), _token("calm")
    proposals.MAX_CALLS_PER_HOUR = 3
    try:
        for _ in range(3):
            assert _propose(first, PF_OPS, dry_run=True).status_code == 200
        r = _propose(first, PF_OPS, dry_run=True)
        assert r.status_code == 429 and "rate limit" in r.text
        assert _propose(first, PF_OPS).status_code == 429, "a real proposal counts too"
        assert _propose(second, PF_OPS, dry_run=True).status_code == 200, "the allowance is per token"
        assert client.get("/api/v1/admin/roles", headers=_h(first)).status_code == 200, "reads are not limited"
    finally:
        proposals.MAX_CALLS_PER_HOUR = 60
    with Session(engine) as session:
        tid = session.exec(select(AdminToken).where(AdminToken.name == "busy")).one().id
    admin.post(f"/admin-tokens/{tid}/delete")
    assert tid not in proposals._calls, "a new token with a reused id starts with a clean allowance"


def test_the_nav_count_is_one_read_that_covers_both():
    _reset()
    token = _token("counted")
    from app.services import approvals
    from app.models import Approval
    with Session(engine) as session:
        session.add(Approval(agent_id=1, agent_name="a", kind="command", target="uptime", host="frodo", line="uptime", expires_at=utcnow() + timedelta(minutes=15)))
        session.commit()
    base = proposals.waiting_total()
    assert base == len(approvals.pending()) + len(proposals.pending()) and len(approvals.pending()) >= 1, "approvals count too"
    pid = _propose(token, PF_OPS).json()["id"]
    assert proposals.waiting_total() == base + 1
    with Session(engine) as session:
        row = session.get(Proposal, pid)
        row.expires_at = utcnow() - timedelta(minutes=1)
        session.add(row)
        session.commit()
    assert proposals.waiting_total() == base, "an expired proposal is not counted"
    assert _row(pid).status == "pending", "and counting wrote nothing"
    with Session(engine) as session:
        for a in session.exec(select(Approval).where(Approval.agent_name == "a")).all():
            session.delete(a)
        session.commit()


def test_only_the_newest_proposals_are_kept():
    _reset()
    token = _token("pruned")
    proposals.KEEP = 3
    try:
        ids = [_propose(token, [{"op": "save_command", "name": f"p{i}", "body": PF}]).json()["id"] for i in range(5)]
    finally:
        proposals.KEEP = 200
    with Session(engine) as session:
        kept = sorted(p.id for p in session.exec(select(Proposal)).all())
    assert kept == ids[-3:], kept


def test_invisible_characters_are_refused_and_non_ascii_is_flagged():
    _reset()
    token = _token("lookalike")
    for ch in ("\u3164", "\u2800", "\ufe0f", "\u034f", "\u115f"):
        r = _propose(token, [{"op": "save_command", "name": "inv", "body": {**PF, "description": f"a{ch}b"}}])
        assert r.status_code == 400 and "invisible" in r.text, (hex(ord(ch)), r.status_code)
    plain = _propose(token, [{"op": "save_command", "name": "ascii", "body": PF}])
    assert plain.status_code == 202 and plain.json()["warnings"] == []
    r = _propose(token, [{"op": "save_command", "name": "cyr", "body": {**PF, "argv": ["d\u043eсker", "ps"]}}])  # Cyrillic o and s
    assert r.status_code == 202, r.text
    warn = r.json()["warnings"]
    assert len(warn) == 1 and "U+043E" in warn[0] and "U+0441" in warn[0], warn
    page = admin.get(f"/proposals/{r.json()['id']}").text
    assert "adds non-ASCII characters" in page and "U+043E" in page
    assert "non-ASCII" not in admin.get(f"/proposals/{plain.json()['id']}").text
    # text that was already in the file is not flagged again: only what the change adds
    accented = {**LIBRARY["commands"]["uptime"], "description": "Uptime caf\u00e9"}
    _approve(_propose(token, [{"op": "save_command", "name": "uptime", "body": accented}]).json()["id"])
    again = _propose(token, [{"op": "save_command", "name": "uptime", "body": {**accented, "risk": "medium"}}])  # the café line is context in this diff
    assert again.status_code == 202, again.text
    page_plan = proposals.plan(json.loads(_row(again.json()["id"]).ops))
    assert again.json()["diff"] == page_plan.diff, "the diff returned when proposing is the diff the page shows"
    assert "caf\u00e9" in again.json()["diff"] and again.json()["warnings"] == []


def test_two_admins_approving_at_once():
    token = _token("racer")
    other = TestClient(app)
    assert other.post("/login", data={"username": "admin", "password": "pw-for-tests"}, follow_redirects=False).status_code == 303

    def together(first, second):
        out, barrier = [], threading.Barrier(2)

        def go(client, pid, seen):
            barrier.wait()
            out.append(client.post(f"/proposals/{pid}/approve", data={"seen": seen}, follow_redirects=True).text)

        threads = [threading.Thread(target=go, args=(c, p, sn)) for c, p, sn in (first, second)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        return out

    for _ in range(5):  # the same proposal, approved twice at the same moment: applied once
        _reset()
        pid = _propose(token, PF_OPS).json()["id"]
        seen, audited = _seen(pid), len(_admin_audit("approve change proposal"))
        out = together((admin, pid, seen), (other, pid, seen))
        assert _row(pid).status == "applied" and _saved_copies() == 1
        assert sum("already applied" in t for t in out) == 1, "one of the two clicks is told it was already done"
        assert len(_admin_audit("approve change proposal")) == audited + 1
        assert _role_cmds("n8n") == {"restart": True, "uptime": False, "pfsense-update-check": False}

    for _ in range(5):  # two different proposals, each reviewed before the other was applied: only the first goes through
        _reset()
        a = _propose(token, [{"op": "save_command", "name": "first", "body": PF}]).json()["id"]
        b = _propose(token, [{"op": "save_command", "name": "second", "body": PF}]).json()["id"]
        sa, sb = _seen(a), _seen(b)
        out = together((admin, a, sa), (other, b, sb))
        states = sorted((_row(a).status, _row(b).status))
        assert states == ["applied", "pending"], states
        assert sum("changed since you opened" in t for t in out) == 1
        assert _saved_copies() == 1 and len({"first", "second"} & set(_file()["commands"])) == 1


def main():
    init_db()
    settings_store.set_many({"notify_pushover_token": "t", "notify_pushover_user": "u"})
    auth_module.create_user("admin", "pw-for-tests")
    r = admin.post("/login", data={"username": "admin", "password": "pw-for-tests"}, follow_redirects=False)
    assert r.status_code == 303 and get_all("/agents", ("agents", "roles", "tokens")).status_code == 200, "test login failed"
    test_tokens_are_separate_credentials()
    test_token_creation_page()
    test_reads()
    test_proposal_changes_nothing_and_is_shown_and_notified()
    test_dry_run_records_nothing()
    test_approve_applies_exactly_what_was_shown()
    test_only_a_login_decides()
    test_deny_applies_nothing()
    test_delete_a_command_shows_what_roles_lose()
    test_role_and_flag_changes()
    test_updating_a_command_shows_old_and_new()
    test_samples_drive_the_preview()
    test_bad_proposals_are_rejected_and_record_nothing()
    test_a_broken_file_blocks_proposals()
    test_a_change_made_after_the_page_loaded_is_not_applied_unseen()
    test_a_proposal_that_went_stale_fails_instead_of_applying()
    test_expiry_cap_and_retries()
    test_note_is_escaped_and_cleaned()
    test_locked_while_auth_is_disabled()
    test_deleting_a_token_removes_its_proposals()
    test_requests_are_audited()
    test_hidden_characters_are_refused()
    test_one_command_cannot_exceed_the_editors_limit()
    test_a_disabled_or_expired_token_cannot_have_its_proposals_applied()
    test_a_file_being_fixed_by_hand_does_not_use_up_the_proposal()
    test_applying_is_all_or_nothing()
    test_planning_is_rate_limited_per_token()
    test_the_nav_count_is_one_read_that_covers_both()
    test_only_the_newest_proposals_are_kept()
    test_invisible_characters_are_refused_and_non_ascii_is_flagged()
    test_two_admins_approving_at_once()
    print("OK: proposers can only propose; an admin applies exactly what the page showed, through the locked save path.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
