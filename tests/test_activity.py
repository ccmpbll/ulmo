"""Self-check for the Activity page (app/routers/activity.py).

  1. Three views (API requests, Changes, Command runs), newest first, 50 per page, with the
     page number clamped and a clear "Showing a to b of n".
  2. Filters narrow each view (by agent, refused-only, admin, host, status) and combine; unknown
     filter values give an empty list rather than an error or an injection.
  3. It is login-only and read-only, escapes what it shows, and never shows command output
     (nor even reads the output column).
  4. The Agents and Commands pages show only the newest five and link here.
  5. The change log is bounded like the request log.

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
from app.models import AdminAudit, AgentAudit, CommandRun  # noqa: E402
from app.routers import activity as activity_module  # noqa: E402
from app.services import agents  # noqa: E402

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
        session.commit()


def test_views_and_paging():
    page = admin.get("/activity")
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
    assert admin.get("/activity?tab=nonsense").status_code == 200, "an unknown tab falls back to the first"
    assert _showing(admin.get("/activity?tab=requests&agent=nobody").text) == "Nothing to show"

    ch = admin.get("/activity?tab=changes")
    assert _rows(ch.text) == 7 and "save command" in ch.text and _showing(ch.text) == "Showing 1 to 7 of 7"
    runs = admin.get("/activity?tab=runs")
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

    failed = admin.get("/activity?tab=runs&status=failed")
    assert _showing(failed.text) == "Showing 1 to 20 of 20"
    assert ">success<" not in failed.text.split("<tbody>")[1], "only failed runs in the table"
    frodo = admin.get("/activity?tab=runs&host=frodo&status=timeout")
    assert re.search(r"of (\d+)", _showing(frodo.text)).group(1) == "10" and "<td>gandalf</td>" not in frodo.text
    by_agent = admin.get("/activity?tab=runs&agent=agent:scripty")
    assert re.search(r"of (\d+)", _showing(by_agent.text)).group(1) == "15"
    assert _showing(admin.get("/activity?tab=runs&status=exploded").text).endswith("of 60"), "an unknown status is ignored, not an error"
    # Filters survive paging.
    page = admin.get("/activity?tab=requests&agent=n8n")  # 81 rows: two pages
    assert 'href="/activity?tab=requests&page=2&agent=n8n"' in page.text
    older = admin.get("/activity?tab=requests&page=2&agent=n8n")
    assert _showing(older.text) == "Showing 51 to 81 of 81" and 'href="/activity?tab=requests&page=1&agent=n8n"' in older.text
    assert "Reset" in page.text and "Reset" not in admin.get("/activity?tab=requests").text


def test_security_and_privacy():
    _, token = agents.create_agent("activity-intruder")
    for url in ("/activity", "/activity?tab=changes", "/activity?tab=runs"):
        r = client.get(url, headers={"Authorization": f"Bearer {token}"}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login", url
        assert client.get(url, follow_redirects=False).status_code == 303
    assert client.post("/activity", follow_redirects=False).status_code in (303, 405)

    page = admin.get("/activity?tab=requests").text
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page, "agent-supplied text is escaped"

    # Command output never reaches this page, and the output column is not even read.
    statements = []
    spy = lambda conn, cursor, statement, *a: statements.append(statement)
    event.listen(engine, "before_cursor_execute", spy)
    try:
        runs = admin.get("/activity?tab=runs").text
    finally:
        event.remove(engine, "before_cursor_execute", spy)
    assert "SECRET-OUTPUT" not in runs
    reads = [s for s in statements if "FROM commandrun" in s and "count(" not in s.lower()]
    assert reads and not any("commandrun.output" in s for s in reads), reads


def test_teasers_and_nav():
    agents_page = admin.get("/agents").text
    sections = agents_page.split("Recent changes")[1]
    changes_block = sections.split("Recent API requests")[0]
    requests_block = sections.split("Recent API requests")[1]
    assert changes_block.count("<tr><td>") == 5, "only the newest five changes"
    assert len([r for r in re.findall(r"<tr>(.*?)</tr>", requests_block, re.S) if "colspan" not in r and "<th>" not in r]) == 5
    assert 'href="/activity?tab=changes"' in agents_page and 'href="/activity?tab=requests"' in agents_page
    commands_page = admin.get("/commands").text
    runs_block = commands_page.split("Recent command runs")[1]
    assert len([r for r in re.findall(r"<tr>(.*?)</tr>", runs_block, re.S) if "colspan" not in r and "<th>" not in r]) == 5
    assert 'href="/activity?tab=runs"' in commands_page
    assert '<a href="/activity">Activity</a>' in agents_page, "in the top bar"


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


def main():
    init_db()
    auth_module.create_user("admin", "pw-for-tests")
    r = admin.post("/login", data={"username": "admin", "password": "pw-for-tests"}, follow_redirects=False)
    assert r.status_code == 303 and admin.get("/activity").status_code == 200, "test login failed"
    _seed()
    test_views_and_paging()
    test_filters()
    test_security_and_privacy()
    test_teasers_and_nav()
    test_change_log_is_bounded()
    print("OK: the Activity page pages, filters, escapes and hides command output.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
