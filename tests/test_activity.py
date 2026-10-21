"""Self-check for the Activity page (app/routers/activity.py).

  1. Five views (Playbook runs, Command runs, Syncs, API requests, Changes), newest first, 50
     per page, with the page number clamped and a clear "Showing a to b of n". Playbook runs is
     the default. The old Run History and Sync Logs addresses redirect here.
  2. Filters narrow each view (by agent, refused-only, admin, host, status) and combine; unknown
     filter values give an empty list rather than an error or an injection.
  3. It is login-only and read-only, escapes what it shows, and never shows command output
     (nor even reads the output column).
  4. The Agents and Commands pages no longer carry their own copies of these logs.
  5. The change log is bounded like the request log, and run and sync history is pruned (newest
     kept, runs in progress spared, a run's files go with it).

Run directly: python3 tests/test_activity.py
"""
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

DATA_DIR = tempfile.mkdtemp(prefix="ulmo-test-")
os.environ["ULMO_DATA_DIR"] = DATA_DIR
os.environ.pop("ULMO_DISABLE_AUTH", None)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import event  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

import app.auth as auth_module  # noqa: E402
from app.database import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.config import RUNNER_DATA_DIR  # noqa: E402
from app.models import AdminAudit, AgentAudit, AgentRun, CommandRun, RunHistory, SyncHistory  # noqa: E402
from app.routers import activity as activity_module  # noqa: E402
from app.services import agents, retention, scheduler  # noqa: E402

client = TestClient(app)
admin = TestClient(app)


def _rows(html: str) -> int:
    """Body rows of the main table (header excluded, "no ... " placeholder rows counted as 0)."""
    body = html.split("<tbody>")[-1].split("</tbody>")[0]
    return len([r for r in re.findall(r"<tr>(.*?)</tr>", body, re.S) if 'colspan' not in r])


def _showing(html: str) -> str:
    m = re.search(r"Showing (\d+) to (\d+) of (\d+)|Nothing to show", html)
    return m.group(0) if m else ""


def _seed():
    for i in range(120):
        agents.audit("n8n" if i % 3 else "scripty", "GET", f"/api/v1/runs/{i}", 200 if i % 5 else 403, "ok" if i % 5 else "no grant")
    agents.audit(None, "GET", "/api/v1/hosts", 401, "unknown token")
    agents.audit("n8n", "POST", "/api/v1/commands", 404, "<script>alert(1)</script>")
    for i in range(7):
        agents.admin_audit("admin" if i % 2 else "alice", "save command", f"c{i}: uptime")
    with Session(engine) as session:
        for i in range(60):
            session.add(CommandRun(command="disk-usage", host="frodo" if i % 2 else "gandalf", line="df -h", params="{}",
                                   status=["success", "failed", "timeout"][i % 3], return_code=0 if i % 3 == 0 else 1,
                                   triggered_by="agent:n8n" if i % 4 else "agent:scripty", output="SECRET-OUTPUT-" + str(i)))
        for i in range(70):
            session.add(RunHistory(playbook=["playbooks/os-update.yaml", "playbooks/frodo.yaml", "playbooks/<b>x</b>.yaml"][i % 3],
                                   status=["success", "failed", "timeout", "cancelled"][i % 4],
                                   triggered_by=["manual", "schedule", "admin", "agent:n8n"][i % 4],
                                   tags="updates" if i % 5 == 0 else None, limit="web1,web2" if i % 7 == 0 else None))
        for i in range(55):
            session.add(SyncHistory(status=["success", "failed"][i % 2], triggered_by="schedule" if i % 3 else "admin", message="x"))
        session.commit()


def test_views_and_paging():
    page = admin.get("/activity?tab=requests")
    assert page.status_code == 200 and "API requests" in page.text
    assert _rows(page.text) == 50 and _showing(page.text) == "Showing 1 to 50 of 122", _showing(page.text)
    assert "Older" in page.text and "Newer" not in page.text and "Page 1 of 3" in page.text
    assert "POST /api/v1/commands" in page.text.split("<tbody>")[1].split("</tr>")[0], "newest first"

    p2 = admin.get("/activity?tab=requests&page=2")
    assert _rows(p2.text) == 50 and _showing(p2.text) == "Showing 51 to 100 of 122" and "Newer" in p2.text and "Older" in p2.text
    p3 = admin.get("/activity?tab=requests&page=3")
    assert _rows(p3.text) == 22 and "Older" not in p3.text
    for odd in ("99", "0", "-4", "abc", ""):
        r = admin.get(f"/activity?tab=requests&page={odd}")
        assert r.status_code == 200 and _rows(r.text) in (22, 50), (odd, _rows(r.text))
    assert admin.get("/activity?tab=nonsense").status_code == 200, "an unknown tab falls back to the default"
    assert _showing(admin.get("/activity?tab=requests&agent=nobody").text) == "Nothing to show"

    ch = admin.get("/activity?tab=changes")
    assert _rows(ch.text) == 7 and "save command" in ch.text and _showing(ch.text) == "Showing 1 to 7 of 7"
    runs = admin.get("/activity?tab=commands")
    assert _rows(runs.text) == 50 and _showing(runs.text) == "Showing 1 to 50 of 60"
    assert "rc 1" in runs.text and ">success<" in runs.text and ">failed<" in runs.text and ">timeout<" in runs.text


def test_filters():
    refused = admin.get("/activity?tab=requests&problems=1")
    assert re.search(r"of (\d+)", _showing(refused.text)).group(1) == "26"  # 24 refused (i % 5 == 0) + 401 + 404
    assert ">200<" not in refused.text

    only_scripty = admin.get("/activity?tab=requests&agent=scripty")
    assert _showing(only_scripty.text) == "Showing 1 to 40 of 40" and "n8n" not in only_scripty.text.split("<tbody>")[1]
    combined = admin.get("/activity?tab=requests&agent=scripty&problems=1")
    assert re.search(r"of (\d+)", _showing(combined.text)).group(1) == "8"
    unknown = admin.get("/activity?tab=requests&agent=(unknown)")
    assert _showing(unknown.text) == "Showing 1 to 1 of 1" and "unknown token" in unknown.text
    for evil in ("' OR 1=1 --", "%27%20OR%201%3D1%20--", "x\" onfocus=\"alert(1)", "<script>"):
        r = admin.get("/activity", params={"tab": "requests", "agent": evil})
        assert r.status_code == 200 and "Nothing to show" in r.text, evil
        assert "<script>alert" not in r.text and "onfocus=" not in r.text, f"{evil!r} must not come back as markup"

    assert _showing(admin.get("/activity?tab=changes&admin=alice").text) == "Showing 1 to 4 of 4"
    assert _showing(admin.get("/activity?tab=changes&admin=admin").text) == "Showing 1 to 3 of 3"
    assert "Nothing to show" in admin.get("/activity?tab=changes&admin=ghost").text

    failed = admin.get("/activity?tab=commands&status=failed")
    assert _showing(failed.text) == "Showing 1 to 20 of 20"
    assert ">success<" not in failed.text.split("<tbody>")[1], "only failed runs in the table"
    frodo = admin.get("/activity?tab=commands&host=frodo&status=timeout")
    assert re.search(r"of (\d+)", _showing(frodo.text)).group(1) == "10" and "<td>gandalf</td>" not in frodo.text
    by_agent = admin.get("/activity?tab=commands&by=agent:scripty")
    assert re.search(r"of (\d+)", _showing(by_agent.text)).group(1) == "15"
    assert _showing(admin.get("/activity?tab=commands&status=exploded").text).endswith("of 60"), "an unknown status is ignored, not an error"
    # Filters survive paging.
    page = admin.get("/activity?tab=requests&agent=n8n")  # 81 rows: two pages
    assert 'href="/activity?tab=requests&page=2&agent=n8n"' in page.text
    older = admin.get("/activity?tab=requests&page=2&agent=n8n")
    assert _showing(older.text) == "Showing 51 to 81 of 81" and 'href="/activity?tab=requests&page=1&agent=n8n"' in older.text
    assert "Reset" in page.text and "Reset" not in admin.get("/activity?tab=requests").text


def test_security_and_privacy():
    _, token = agents.create_agent("activity-intruder")
    for url in ("/activity", "/activity?tab=changes", "/activity?tab=commands"):
        r = client.get(url, headers={"Authorization": f"Bearer {token}"}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/login"), url
        assert client.get(url, follow_redirects=False).status_code == 303
    assert client.post("/activity", follow_redirects=False).status_code in (303, 405)

    page = admin.get("/activity?tab=requests").text
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page, "agent-supplied text is escaped"

    # Command output never reaches this page, and the output column is not even read.
    statements = []
    spy = lambda conn, cursor, statement, *a: statements.append(statement)
    event.listen(engine, "before_cursor_execute", spy)
    try:
        runs = admin.get("/activity?tab=commands").text
    finally:
        event.remove(engine, "before_cursor_execute", spy)
    assert "SECRET-OUTPUT" not in runs
    reads = [s for s in statements if "FROM commandrun" in s and "count(" not in s.lower()]
    assert reads and not any("commandrun.output" in s for s in reads), reads


def test_other_pages_do_not_repeat_the_logs():
    agents_page = admin.get("/agents").text
    commands_page = admin.get("/commands").text
    for title in ("Recent changes", "Recent API requests", "Recent command runs"):
        assert title not in agents_page and title not in commands_page, f"{title!r} lives on the Activity page now"
    assert '<a href="/activity">Activity</a>' in agents_page and '<a href="/activity">Activity</a>' in commands_page, "reachable from the top bar"

    # And those pages no longer read the log tables at all.
    statements = []
    spy = lambda conn, cursor, statement, *a: statements.append(statement)
    event.listen(engine, "before_cursor_execute", spy)
    try:
        admin.get("/agents")
        admin.get("/commands")
    finally:
        event.remove(engine, "before_cursor_execute", spy)
    touched = [s for s in statements if re.search(r"FROM (agentaudit|adminaudit|commandrun)", s)]
    assert not touched, touched


def test_change_log_is_bounded():
    keep = agents.ADMIN_AUDIT_KEEP
    agents.ADMIN_AUDIT_KEEP = 10
    try:
        for i in range(25):
            agents.admin_audit("admin", "bounded", f"n{i}")
    finally:
        agents.ADMIN_AUDIT_KEEP = keep
    with Session(engine) as session:
        rows = session.exec(select(AdminAudit).order_by(AdminAudit.id)).all()
    assert len(rows) == 10 and rows[-1].detail == "n24" and rows[0].detail == "n15", [r.detail for r in rows]
    assert agents.ADMIN_AUDIT_KEEP == 5000


def test_playbook_and_sync_tabs():
    page = admin.get("/activity")
    assert page.status_code == 200
    assert 'class="btn " href="/activity?tab=playbooks"' in page.text, "Playbook runs is the default tab and shown as active"
    labels = ["Playbook runs", "Command runs", "Syncs", "API requests", "Changes"]
    positions = [page.text.index(f">{label}</a>") for label in labels]
    assert positions == sorted(positions), "tab order"
    assert _rows(page.text) == 50 and _showing(page.text) == "Showing 1 to 50 of 70"
    assert _rows(admin.get("/activity?tab=playbooks&page=2").text) == 20
    newest_id = max(r.id for r in _all(RunHistory))
    assert f'href="/runs/{newest_id}"' in page.text and ">View<" in page.text, "rows open the run's own page"
    assert "tags: updates" in page.text and "limit: web1,web2" in page.text
    assert 'class="badge success"' in page.text and 'class="badge failed"' in page.text

    def count(url):
        return re.search(r"of (\d+)", _showing(admin.get(url).text))
    assert count("/activity?tab=playbooks&status=failed").group(1) == "18"
    assert count("/activity?tab=playbooks&playbook=playbooks/frodo.yaml").group(1) == "23"
    assert count("/activity?tab=playbooks&by=agent:n8n").group(1) == "17"
    assert count("/activity?tab=playbooks&playbook=playbooks/frodo.yaml&by=agent:n8n").group(1) == "6"
    assert _showing(admin.get("/activity?tab=playbooks&status=failed&by=manual").text) == "Nothing to show"
    assert _showing(admin.get("/activity?tab=playbooks&status=exploded").text).endswith("of 70"), "unknown status is ignored"
    assert "&lt;b&gt;x&lt;/b&gt;" in page.text and "<b>x</b>" not in page.text, "playbook names are escaped"
    assert _showing(admin.get("/activity", params={"tab": "playbooks", "playbook": "' OR 1=1 --"}).text) == "Nothing to show"
    filtered = admin.get("/activity?tab=playbooks&status=success&playbook=playbooks/os-update.yaml")
    assert 'href="/activity?tab=playbooks&page=2' not in filtered.text, "a short filtered list has no pager"

    syncs = admin.get("/activity?tab=syncs")
    assert _rows(syncs.text) == 50 and _showing(syncs.text) == "Showing 1 to 50 of 55"
    assert _rows(admin.get("/activity?tab=syncs&page=2").text) == 5
    newest_sync = max(r.id for r in _all(SyncHistory))
    assert f'href="/logs/{newest_sync}"' in syncs.text and ">View<" in syncs.text
    assert count("/activity?tab=syncs&status=failed").group(1) == "27"
    assert count("/activity?tab=syncs&by=admin").group(1) == "19"
    assert count("/activity?tab=syncs&by=admin&status=failed").group(1) == "9"
    assert "x</td>" not in syncs.text and 'class="log"' not in syncs.text, "a sync's output stays on its own page"
    paged = admin.get("/activity?tab=syncs&by=schedule")
    assert _showing(paged.text) == "Showing 1 to 36 of 36"
    # Runs that have not finished show no duration.
    with Session(engine) as session:
        session.add(RunHistory(playbook="playbooks/still-going.yaml", status="running", triggered_by="manual"))
        session.commit()
    going = admin.get("/activity?tab=playbooks&playbook=playbooks/still-going.yaml").text
    assert ">running<" in going and '<td class="muted">-</td>' in going


def test_runs_are_listed_by_start_time():
    from datetime import timedelta

    from app.models import utcnow
    now = utcnow()
    # Created A, B, C (so row numbers rise), but started A first, then C, then B most recently.
    starts = {"A": now - timedelta(days=30), "B": now - timedelta(days=1), "C": now - timedelta(days=10)}
    took = {"A": 3, "B": 5, "C": 7}  # a different duration each, so rows can be told apart
    with Session(engine) as session:
        for key in "ABC":
            session.add(RunHistory(playbook=f"playbooks/order-{key}.yaml", status="success", triggered_by="order-test",
                                   started_at=starts[key], finished_at=starts[key] + timedelta(seconds=took[key])))
            session.add(SyncHistory(status="success", triggered_by="order-test", started_at=starts[key],
                                    finished_at=starts[key] + timedelta(seconds=took[key])))
            session.add(CommandRun(command="x", host="h", line="x", status="success", triggered_by="agent:order-test", started_at=starts[key],
                                   finished_at=starts[key] + timedelta(seconds=took[key])))
        session.commit()

    def order(url):
        body = admin.get(url).text.split("<tbody>")[-1]
        return re.findall(r"(\d+)\.0 s", body)

    expected = ["5", "7", "3"]  # B (1 day ago), C (10 days ago), A (30 days ago): newest start first
    assert order("/activity?tab=playbooks&by=order-test") == expected
    assert order("/activity?tab=syncs&by=order-test") == expected
    assert order("/activity?tab=commands&by=agent:order-test") == expected


def _all(model):
    with Session(engine) as session:
        return session.exec(select(model)).all()


def test_old_list_pages_redirect_and_detail_pages_stay():
    r = admin.get("/runs", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/activity?tab=playbooks"
    r = admin.get("/logs", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/activity?tab=syncs"
    for url in ("/runs", "/logs"):
        anon = client.get(url, follow_redirects=False)
        assert anon.status_code == 303 and anon.headers["location"].startswith("/login"), "still login-only"

    run = _all(RunHistory)[0]
    assert admin.get(f"/runs/{run.id}").status_code == 200
    sync = _all(SyncHistory)[0]
    detail = admin.get(f"/logs/{sync.id}")
    assert detail.status_code == 200 and 'href="/activity?tab=syncs"' in detail.text and "Back to activity" in detail.text
    r = admin.get("/runs/99999999", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/activity?tab=playbooks"
    r = admin.get("/logs/99999999", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/activity?tab=syncs"

    nav = admin.get("/activity").text.split("</header>")[0]
    assert ">Run History<" not in nav and ">Sync Logs<" not in nav, "both live under Activity now"
    assert '<a href="/activity">Activity</a>' in nav


def test_history_is_pruned():
    keep = retention.RUN_KEEP, retention.SYNC_KEEP
    retention.RUN_KEEP, retention.SYNC_KEEP = 20, 10
    try:
        with Session(engine) as session:
            ids = [r.id for r in session.exec(select(RunHistory).where(RunHistory.status != "running").order_by(RunHistory.id)).all()]
            running = [r.id for r in session.exec(select(RunHistory).where(RunHistory.status == "running")).all()]
        assert len(ids) > 40 and running, (len(ids), running)
        old_ids, new_ids = ids[:-20], ids[-20:]
        artifacts = RUNNER_DATA_DIR / "artifacts"
        for rid in (old_ids[0], old_ids[-1], new_ids[0], new_ids[-1], running[0]):
            (artifacts / str(rid)).mkdir(parents=True, exist_ok=True)
            (artifacts / str(rid) / "stdout").write_text("log")
        with Session(engine) as session:
            session.add(AgentRun(run_id=old_ids[0], agent_id=1))
            session.add(AgentRun(run_id=new_ids[-1], agent_id=1))
            session.commit()

        assert retention.prune_runs() == len(old_ids)
        with Session(engine) as session:
            left = [r.id for r in session.exec(select(RunHistory).order_by(RunHistory.id)).all()]
            owners = [a.run_id for a in session.exec(select(AgentRun)).all()]
        assert set(new_ids) <= set(left) and not set(old_ids) & set(left), "the newest 20 stay, older ones go"
        assert set(running) <= set(left), "a run in progress is never pruned"
        assert not (artifacts / str(old_ids[0])).exists() and not (artifacts / str(old_ids[-1])).exists(), "its files go with it"
        assert (artifacts / str(new_ids[0])).exists() and (artifacts / str(new_ids[-1])).exists() and (artifacts / str(running[0])).exists()
        assert old_ids[0] not in owners and new_ids[-1] in owners, "ownership rows follow their run"
        assert retention.prune_runs() == 0, "nothing more to do"

        with Session(engine) as session:  # a sync still in progress that is now older than the newest ten
            busy = SyncHistory(status="running", triggered_by="admin")
            session.add(busy)
            session.commit()
            session.refresh(busy)
            busy_id = busy.id
            session.add_all([SyncHistory(status="success", triggered_by="schedule") for _ in range(15)])
            session.commit()
        before = sorted(r.id for r in _all(SyncHistory) if r.status != "running")
        assert retention.prune_syncs() == len(before) - 10
        left = sorted(r.id for r in _all(SyncHistory))
        assert [i for i in left if i != busy_id] == before[-10:], "the newest ten finished syncs are the ones kept"
        assert busy_id in left, "a sync in progress is never pruned"
        assert retention.prune_syncs() == 0

        # Many rows at once (the delete is done in chunks).
        with Session(engine) as session:
            session.add_all([RunHistory(playbook="bulk.yaml", status="success") for _ in range(1000)])
            session.commit()
        assert retention.prune_runs() == 1000
        assert len([r for r in _all(RunHistory) if r.status != "running"]) == 20

        # Housekeeping never raises.
        import logging
        real, logger = retention.prune_runs, logging.getLogger("ulmo.retention")
        retention.prune_runs, logger.disabled = (lambda: (_ for _ in ()).throw(RuntimeError("database is locked"))), True  # (it logs the failure; keep the test output clean)
        try:
            retention.prune()
        finally:
            retention.prune_runs, logger.disabled = real, False
    finally:
        retention.RUN_KEEP, retention.SYNC_KEEP = keep
    assert (retention.RUN_KEEP, retention.SYNC_KEEP) == (500, 500)

    # It runs every few hours as well as at start-up.
    scheduler.schedule_retention()
    jobs = [j for j in scheduler.scheduler.get_jobs() if j.id == scheduler.RETENTION_JOB_ID]
    assert len(jobs) == 1 and jobs[0].trigger.interval.total_seconds() == 6 * 3600 and jobs[0].func is retention.prune
    scheduler.scheduler.remove_job(scheduler.RETENTION_JOB_ID)


def main():
    init_db()
    auth_module.create_user("admin", "pw-for-tests")
    r = admin.post("/login", data={"username": "admin", "password": "pw-for-tests"}, follow_redirects=False)
    assert r.status_code == 303 and admin.get("/activity").status_code == 200, "test login failed"
    _seed()
    test_views_and_paging()
    test_filters()
    test_security_and_privacy()
    test_other_pages_do_not_repeat_the_logs()
    test_playbook_and_sync_tabs()
    test_runs_are_listed_by_start_time()
    test_old_list_pages_redirect_and_detail_pages_stay()
    test_change_log_is_bounded()
    test_history_is_pruned()
    print("OK: the Activity page pages, filters, escapes and hides command output.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
