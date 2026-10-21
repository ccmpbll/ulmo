"""Self-check for the agent API (app/routers/api.py, app/services/agents.py).

Covers the security contract of the bearer-token plane:

  1. Only the sha256 of a token is stored, never the token.
  2. Missing, malformed, unknown, disabled, expired and deleted tokens are all
     rejected with the same generic 401, and each is audited with its reason.
  3. A valid token works and is audited with the status code actually returned
     (a 404 or 422 is not logged as a success). last_used_at is not rewritten
     on every request.
  4. The API ignores the cookie-session plane: ULMO_DISABLE_AUTH does not open
     it, and an agent token cannot open an admin page.
  5. Tokens never appear in the audit log; paths are truncated and the table is
     pruned, so unauthenticated callers cannot grow it without limit.
  6. The read-only endpoints return the shapes agents rely on (ANSI stripped
     from logs, log read from the tail and capped, recap included, 404 for an
     unknown run).
  7. The admin form shows a new token once (uncacheable), validates names and
     expiry, and refuses to mint tokens when login is disabled.

Run directly: python3 tests/test_agent_api.py
"""
import os
import shutil
import sys
import tempfile
from datetime import timedelta
from pathlib import Path

DATA_DIR = tempfile.mkdtemp(prefix="ulmo-test-")
os.environ["ULMO_DATA_DIR"] = DATA_DIR
os.environ.pop("ULMO_DISABLE_AUTH", None)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

import app.auth as auth_module  # noqa: E402
from app.database import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Agent, AgentAudit, RunHistory, utcnow  # noqa: E402
from app.routers import agents as agents_router  # noqa: E402
from app.routers import api as api_module  # noqa: E402
from app.services import agents, runner  # noqa: E402

client = TestClient(app)  # an API caller: no cookies
admin = TestClient(app)  # a logged-in browser


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _audit_rows() -> list[AgentAudit]:
    with Session(engine) as session:
        return list(session.exec(select(AgentAudit).order_by(AgentAudit.id)).all())


def _last_audit() -> AgentAudit:
    return _audit_rows()[-1]


def test_token_is_stored_hashed():
    agent, token = agents.create_agent("hashcheck")
    assert token.startswith(agents.TOKEN_PREFIX)
    with Session(engine) as session:
        row = session.get(Agent, agent.id)
    assert row.token_hash == agents.hash_token(token)
    assert token not in row.token_hash and token not in str(row.model_dump())


def test_rejections_are_generic_and_audited():
    _, good = agents.create_agent("rejects")
    cases = [
        ("no header", {}, "missing bearer token"),
        ("basic scheme", {"Authorization": "Basic abc"}, "missing bearer token"),
        ("empty bearer", {"Authorization": "Bearer "}, "missing bearer token"),
        ("unknown token", _bearer("ulmo_nope"), "unknown token"),
    ]
    for label, headers, reason in cases:
        r = client.get("/api/v1/hosts", headers=headers)
        assert r.status_code == 401, f"{label}: expected 401, got {r.status_code}"
        assert r.json() == {"detail": "Unauthorized"}, f"{label}: leaked detail {r.json()}"
        assert r.headers["www-authenticate"] == "Bearer"
        row = _last_audit()
        assert row.status_code == 401 and row.detail == reason, f"{label}: audit {row}"
        assert row.agent_name is None

    # The good token still works afterwards (rejections change nothing).
    assert client.get("/api/v1/hosts", headers=_bearer(good)).status_code == 200


def test_disabled_expired_and_deleted_agents_are_rejected():
    agent, token = agents.create_agent("lifecycle")
    assert client.get("/api/v1/hosts", headers=_bearer(token)).status_code == 200

    agents.toggle_enabled(agent.id)
    r = client.get("/api/v1/hosts", headers=_bearer(token))
    assert r.status_code == 401 and r.json() == {"detail": "Unauthorized"}
    row = _last_audit()
    assert (row.agent_name, row.status_code, row.detail) == ("lifecycle", 401, "agent disabled")

    agents.toggle_enabled(agent.id)
    assert client.get("/api/v1/hosts", headers=_bearer(token)).status_code == 200

    with Session(engine) as session:
        a = session.get(Agent, agent.id)
        a.expires_at = utcnow() - timedelta(seconds=1)
        session.add(a)
        session.commit()
    r = client.get("/api/v1/hosts", headers=_bearer(token))
    assert r.status_code == 401
    assert _last_audit().detail == "token expired"

    agents.delete_agent(agent.id)
    assert client.get("/api/v1/hosts", headers=_bearer(token)).status_code == 401


def test_valid_token_audits_real_status_and_throttles_last_used():
    agent, token = agents.create_agent("happy", expires_days=30)
    assert agent.last_used_at is None
    h = _bearer(token)

    assert client.get("/api/v1/hosts", headers=h).status_code == 200
    row = _last_audit()
    assert (row.agent_name, row.method, row.path, row.status_code) == ("happy", "GET", "/api/v1/hosts", 200)
    with Session(engine) as session:
        first_used = session.get(Agent, agent.id).last_used_at
    assert first_used is not None

    # A second call inside the refresh window does not rewrite last_used_at.
    client.get("/api/v1/hosts", headers=h)
    with Session(engine) as session:
        assert session.get(Agent, agent.id).last_used_at == first_used

    # Errors raised after auth are logged as what they were, not as successes.
    assert client.get("/api/v1/runs/999999", headers=h).status_code == 404
    assert _last_audit().status_code == 404 and _last_audit().agent_name == "happy"
    assert client.get("/api/v1/runs?limit=0", headers=h).status_code == 422
    assert _last_audit().status_code == 422


def test_api_ignores_the_cookie_plane():
    # Even with login switched off globally, the API gives a caller with no token nothing.
    auth_module.AUTH_DISABLED = True
    try:
        assert client.get("/api/v1/hosts").status_code == 401
        assert client.get("/api/v1/runs").status_code == 401
    finally:
        auth_module.AUTH_DISABLED = False

    # With login enforced, an agent token does not open an admin page either.
    _, token = agents.create_agent("not-admin")
    r = client.get("/agents", headers=_bearer(token), follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login"), r.status_code
    r = client.post("/agents", data={"name": "sneaky"}, headers=_bearer(token), follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")
    with Session(engine) as session:
        assert session.exec(select(Agent).where(Agent.name == "sneaky")).first() is None


def test_audit_is_bounded_and_token_free():
    _, token = agents.create_agent("secretive")
    client.get("/api/v1/hosts", headers=_bearer(token))
    client.get("/api/v1/hosts", headers=_bearer(token + "x"))
    for row in _audit_rows():
        assert token not in f"{row.path}{row.detail}{row.agent_name}"

    # A huge path is truncated before it is stored.
    client.get("/api/v1/" + "a" * 5000)
    assert len(_last_audit().path) == agents.AUDIT_PATH_MAX

    # Unauthenticated callers cannot grow the table past AUDIT_KEEP.
    keep = agents.AUDIT_KEEP
    agents.AUDIT_KEEP = 5
    try:
        for _ in range(20):
            client.get("/api/v1/hosts")
        assert len(_audit_rows()) == 5, len(_audit_rows())
    finally:
        agents.AUDIT_KEEP = keep


def test_read_endpoints():
    _, token = agents.create_agent("reader")
    h = _bearer(token)

    # Empty repo: lists are empty, not errors.
    assert client.get("/api/v1/playbooks", headers=h).json() == {"playbooks": []}
    assert client.get("/api/v1/hosts", headers=h).json() == {"hosts": []}

    with Session(engine) as session:
        ok_run = RunHistory(playbook="a.yml", status="success", triggered_by="alice", return_code=0)
        bad_run = RunHistory(playbook="b.yml", status="failed", return_code=2, limit="web1")
        session.add(ok_run)
        session.add(bad_run)
        session.commit()
        session.refresh(ok_run)
        session.refresh(bad_run)

    listed = client.get("/api/v1/runs", headers=h).json()["runs"]
    assert {r["playbook"] for r in listed} >= {"a.yml", "b.yml"}
    assert client.get("/api/v1/runs?limit=0", headers=h).status_code == 422
    assert client.get("/api/v1/runs?limit=101", headers=h).status_code == 422
    assert len(client.get("/api/v1/runs?limit=1", headers=h).json()["runs"]) == 1

    big = "\x1b[0;32mok: [web1]\x1b[0m\n" + "x" * (api_module.LOG_TAIL_CHARS + 10)
    log = runner.log_path(ok_run.id)
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(big)
    detail = client.get(f"/api/v1/runs/{ok_run.id}", headers=h).json()
    assert detail["id"] == ok_run.id and detail["triggered_by"] == "alice"
    assert "\x1b" not in detail["log"]
    assert len(detail["log"]) == api_module.LOG_TAIL_CHARS
    assert detail["started_at"].endswith("+00:00")
    assert detail["recap"] is None

    small = client.get(f"/api/v1/runs/{bad_run.id}", headers=h).json()
    assert small["log"] == "" and small["limit"] == "web1"

    assert client.get("/api/v1/runs/999999", headers=h).status_code == 404


def test_log_tail_reads_only_the_end_of_a_big_log():
    with Session(engine) as session:
        run = RunHistory(playbook="long.yml", status="success")
        session.add(run)
        session.commit()
        session.refresh(run)
    lines = [f"\x1b[0;32mline {i:06d} — ok\x1b[0m\n" for i in range(40000)]  # multi-byte, coloured, ~1.3 MB
    log = runner.log_path(run.id)
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("".join(lines), encoding="utf-8")

    tail = api_module._log_tail(run.id)
    assert "\x1b" not in tail and "�" not in tail, "partial escape or character at the seam"
    assert len(tail) <= api_module.LOG_TAIL_CHARS
    assert tail.endswith("line 039999 — ok\n")
    assert "[0;3" not in tail and "[0m" not in tail, "half an escape code survived at the cut"

    # It really is a bounded read from the end, not the whole file sliced afterwards.
    window = api_module.LOG_READ_BYTES
    api_module.LOG_READ_BYTES = 2000
    try:
        assert len(api_module._log_tail(run.id)) <= 2000
    finally:
        api_module.LOG_READ_BYTES = window


def test_admin_form():
    r = admin.post("/agents", data={"name": "formed", "expires_days": "7"})
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    assert "ulmo_" in r.text, "new token should be shown once"
    token = next(w for w in r.text.replace("<", " ").replace(">", " ").split() if w.startswith("ulmo_"))
    assert client.get("/api/v1/hosts", headers=_bearer(token)).status_code == 200
    assert token not in admin.get("/agents").text, "token must not be shown again"

    # The Disable/Enable button flips the agent, and the token follows it.
    with Session(engine) as session:
        agent_id = session.exec(select(Agent).where(Agent.name == "formed")).one().id
    admin.post(f"/agents/{agent_id}/toggle", follow_redirects=False)
    assert client.get("/api/v1/hosts", headers=_bearer(token)).status_code == 401
    admin.post(f"/agents/{agent_id}/toggle", follow_redirects=False)
    assert client.get("/api/v1/hosts", headers=_bearer(token)).status_code == 200

    for bad in ("", "has space", "x" * 41, "semi;colon"):
        r = admin.post("/agents", data={"name": bad})
        assert r.status_code in (400, 422), f"{bad!r} should be rejected, got {r.status_code}"
    assert admin.post("/agents", data={"name": "formed"}).status_code == 400, "duplicate name"
    for bad_days in ("0", "-3", "soon", "99999999999", str(agents.MAX_EXPIRY_DAYS + 1)):
        r = admin.post("/agents", data={"name": "badexp", "expires_days": bad_days})
        assert r.status_code == 400, f"expires_days={bad_days!r} should be a form error, got {r.status_code}"
    assert admin.post("/agents", data={"name": "maxexp", "expires_days": str(agents.MAX_EXPIRY_DAYS)}).status_code == 200


def test_no_tokens_when_login_is_disabled():
    agents_router.AUTH_DISABLED = True
    try:
        r = admin.post("/agents", data={"name": "openhouse"})
    finally:
        agents_router.AUTH_DISABLED = False
    assert r.status_code == 400 and "ulmo_" not in r.text
    with Session(engine) as session:
        assert session.exec(select(Agent).where(Agent.name == "openhouse")).first() is None


def main():
    init_db()
    auth_module.create_user("admin", "pw-for-tests")
    r = admin.post("/login", data={"username": "admin", "password": "pw-for-tests"}, follow_redirects=False)
    assert r.status_code == 303 and admin.get("/agents").status_code == 200, "test login failed"
    test_token_is_stored_hashed()
    test_rejections_are_generic_and_audited()
    test_disabled_expired_and_deleted_agents_are_rejected()
    test_valid_token_audits_real_status_and_throttles_last_used()
    test_api_ignores_the_cookie_plane()
    test_audit_is_bounded_and_token_free()
    test_read_endpoints()
    test_log_tail_reads_only_the_end_of_a_big_log()
    test_admin_form()
    test_no_tokens_when_login_is_disabled()
    print("OK: agent API auth, audit and read-only endpoints behave.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
