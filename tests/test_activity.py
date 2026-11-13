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
from datetime import timedelta
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
from app.models import AdminAudit, AgentAudit, AgentRun, Approval, CommandRun, Proposal, RunHistory, SyncHistory, utcnow  # noqa: E402
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
    assert re.search(r"of (\d+)", _showing(frodo.text)).group(1) == "10" and ">gandalf</td>" not in frodo.text
    by_agent = admin.get("/activity?tab=commands&by=agent:scripty")
    assert re.search(r"of (\d+)", _showing(by_agent.text)).group(1) == "15"
    assert _showing(admin.get("/activity?tab=commands&status=exploded").text).endswith("of 60"), "an unknown status is ignored, not an error"
    # Filters survive paging.
    page = admin.get("/activity?tab=requests&agent=n8n")  # 81 rows: two pages
    assert 'href="/?tab=requests&page=2&agent=n8n"' in page.text
    older = admin.get("/activity?tab=requests&page=2&agent=n8n")
    assert _showing(older.text) == "Showing 51 to 81 of 81" and 'href="/?tab=requests&page=1&agent=n8n"' in older.text
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
    assert '<a href="/">Overview</a>' in agents_page and '<a href="/">Overview</a>' in commands_page, "reachable from the top bar"

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
    page = admin.get("/?tab=playbooks")
    assert page.status_code == 200
    assert 'href="/?tab=playbooks" class="active" aria-current="page">Playbook runs</a>' in page.text, "the chosen tab is shown as active"
    labels = ["All", "Playbook runs", "Command runs", "Syncs", "API requests", "Changes"]
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
    assert 'href="/?tab=playbooks&page=2' not in filtered.text, "a short filtered list has no pager"

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
    assert ">running<" in going and '<td data-label="Took" class="muted">-</td>' in going


def test_top_bar():
    """Settings and Log out live in the user menu, the nav has no Settings link, and the
    switched-off banner shows on every page while agent runs are off."""
    page = admin.get("/activity").text
    head = page.split("</header>")[0]
    nav = head.split("<nav>")[1].split("</nav>")[0]
    assert "Settings" not in nav, "Settings is in the user menu, not the nav"
    assert re.findall(r">([A-Za-z]+)(?: <span[^>]*>\d+</span>)?</a>", nav) == ["Overview", "Approvals", "Ansible", "Commands", "Agents"]
    menu = head.split('id="user-menu"')[1]
    assert '<a href="/settings">Settings</a>' in menu and 'action="/logout"' in menu, "the menu has Settings and Log out"
    assert 'class="killbar"' not in page, "no banner while agent runs are on"
    admin.post("/agent-runs/toggle", data={})
    try:
        for path in ("/activity", "/agents", "/"):
            assert 'class="killbar"' in admin.get(path).text, f"banner on {path} while agent runs are off"
    finally:
        admin.post("/agent-runs/toggle", data={"enable": "1"})
    assert 'class="killbar"' not in admin.get("/activity").text, "banner gone once they are back on"
    settings_head = admin.get("/settings").text.split("</header>")[0]
    assert 'class="usermenu-btn active"' in settings_head, "the user menu is marked while you are in Settings"


def _times(html: str) -> list[str]:
    """The timestamps of the main table's rows, in page order."""
    body = html.split("<tbody>")[-1].split("</tbody>")[0]
    return re.findall(r'<time class="local-time" datetime="([^"]+)"', body)


def test_overview_all_tab():
    """/ is the Overview; its log defaults to All: the five logs merged, newest first."""
    r = admin.get("/activity?tab=requests&page=2&agent=n8n", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/?tab=requests&page=2&agent=n8n", "the old address keeps its query"
    assert client.get("/", follow_redirects=False).headers["location"] == "/login", "login-only"

    page = admin.get("/")
    assert page.status_code == 200 and "<h1>Overview</h1>" in page.text
    assert 'href="/?tab=all" class="active" aria-current="page">All</a>' in page.text, "All is the default tab"
    total = sum(len(_all(m)) for m in (AgentAudit, AdminAudit, CommandRun, RunHistory, SyncHistory))
    assert total >= 314, "the seeded rows are all counted"
    assert _rows(page.text) == 50 and _showing(page.text) == f"Showing 1 to 50 of {total}"
    times = _times(page.text)
    assert times == sorted(times, reverse=True), "newest first across all five logs"
    kinds = set(re.findall(r'<span class="kind (\w+)">', "".join(admin.get(f"/?page={n}").text for n in range(1, 8))))
    assert kinds == {"playbook", "command", "sync", "request", "change"}, "every kind of row appears and says what it is"
    assert _showing(admin.get("/?page=7").text) == f"Showing 301 to {total} of {total}" and _rows(admin.get("/?page=7").text) == total - 300
    assert _showing(admin.get("/?page=999").text) == f"Showing 301 to {total} of {total}", "a page past the end is clamped"
    assert 'href="/?tab=all&page=2"' in page.text and "Reset" not in page.text and 'class="filters"' not in page.text, "All has a pager and no filters"
    # Every row on page 1..7 appears exactly once.
    seen = sum(_rows(admin.get(f"/?page={n}").text) for n in range(1, 8))
    assert seen == total, "the merge neither drops nor repeats rows"
    # Rows from different logs interleave by time: a request and then a change made after everything seeded lead the list.
    agents.audit("n8n", "GET", "/api/v1/newest-marker", 200, "")
    agents.admin_audit("admin", "newest-change-marker", "")
    first = re.findall(r"<tr>(.*?)</tr>", admin.get("/").text.split("<tbody>")[-1], re.S)[:2]
    assert "newest-change-marker" in first[0] and "newest-marker" in first[1] and "newest-change-marker" not in first[1], "the merge orders rows across logs"
    total += 2
    assert "SECRET-OUTPUT" not in page.text, "command output stays out of the log"
    assert "<script>alert(1)</script>" not in admin.get("/").text and "<b>x</b>" not in page.text, "what rows show is escaped"
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in "".join(admin.get(f"/?page={n}").text for n in range(1, 8))
    for tab in ("playbooks", "commands", "syncs", "requests", "changes"):
        assert admin.get(f"/?tab={tab}").status_code == 200
    assert admin.get("/?tab=nonsense").text.count('class="active" aria-current="page">All</a>') == 1, "an unknown tab falls back to All"


def _wait(kind="command", target="docker-restart", host="gandalf", note="Jellyfin stopped answering."):
    with Session(engine) as session:
        row = Approval(agent_id=1, agent_name="n8n", kind=kind, target=target, host=host, line="docker restart jellyfin", agent_note=note,
                       expires_at=utcnow() + timedelta(minutes=15))
        session.add(row)
        session.commit()
        session.refresh(row)
        return row.id


def test_overview_needs_you_and_running():
    quiet = admin.get("/").text
    assert "Nothing needs you right now" in quiet and 'class="card flush needs"' not in quiet and 'href="/approvals">View approval history' in quiet

    aid = _wait(note="<img src=x onerror=alert(1)>")
    with Session(engine) as session:
        prop = Proposal(token_id=1, token_name="n8n-changes", note="add gravity", expires_at=utcnow() + timedelta(hours=24))
        session.add(prop)
        session.commit()
        session.refresh(prop)
        pid = prop.id
    page = admin.get("/").text
    assert 'class="card flush needs"' in page and "Nothing needs you right now" not in page and "2 waiting" in page
    assert "n8n wants to run docker-restart" in page and "docker restart jellyfin" in page and "on gandalf" in page
    assert "<img src=x" not in page and "&lt;img src=x" in page, "the agent's note is shown escaped"
    assert f'action="/approvals/{aid}/approve"' in page and f'action="/approvals/{aid}/deny"' in page and 'name="back" value="overview"' in page
    assert f'href="/proposals/{pid}">Review the diff' in page and f"/proposals/{pid}/approve" not in page, "a proposal is only decided on its own page, after the diff"
    assert 'href="/approvals">View approval history' not in page
    nav = page.split("</header>")[0]
    assert 'href="/approvals" data-attn' in nav and "Approvals <span" in nav, "the nav is lit too"

    # Deciding from the Overview comes back to it with a one-line result; elsewhere it stays on the request's page.
    r = admin.post(f"/approvals/{aid}/deny", data={"back": "overview"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    after = admin.get("/").text
    assert "Denied: n8n docker-restart on gandalf" in after and f"/approvals/{aid}/deny" not in after
    assert "Denied: n8n" not in admin.get("/").text, "the result is shown once"
    other = _wait()
    for bad in ("", "elsewhere", "https://evil.example/", "//evil.example"):
        r = admin.post(f"/approvals/{other}/deny", data={"back": bad}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == f"/approvals/{other}", f"back={bad!r} is ignored"
        other = _wait()
    admin.post(f"/approvals/{other}/deny", data={"back": "overview"})  # leave nothing pending
    with Session(engine) as session:
        session.delete(session.get(Proposal, pid))
        session.commit()
    assert "Nothing needs you right now" in admin.get("/").text

    # Running now: an unfinished run shows under the log's heading, linked to its own page.
    with Session(engine) as session:
        run = RunHistory(playbook="playbooks/still-going-overview.yaml", status="running", triggered_by="admin")
        session.add(run)
        session.commit()
        session.refresh(run)
    page = admin.get("/").text
    assert 'class="running-strip"' in page and f'href="/runs/{run.id}"><strong>playbooks/still-going-overview.yaml' in page
    with Session(engine) as session:
        session.delete(session.get(RunHistory, run.id))
        session.commit()
    assert "still-going-overview" not in admin.get("/").text, "a finished or removed run leaves the strip"


def test_ansible_page_moved():
    page = admin.get("/ansible")
    assert page.status_code == 200 and "<h1>Ansible</h1>" in page.text and 'href="/ansible" class="active"' in page.text.split("</header>")[0]
    inv = admin.get("/inventory").text
    assert 'href="/ansible" class="active"' in inv.split("</header>")[0], "Inventory is part of Ansible in the nav"
    assert 'href="/ansible"' in inv and 'class="active" aria-current="page">Inventory</a>' in inv


def test_page_tabs():
    """Agents, Commands, Settings and Approvals are split into tabs (?tab=...): the default tab
    shows its own sections only, an unknown tab falls back to it, and every action returns to the
    tab it was done on."""
    def active(html):
        return re.findall(r'class="active" aria-current="page">([^<]+)</a>', html.split("</header>")[1])

    # Agents
    a = admin.get("/agents").text
    assert active(a) == ["Agents"] and "API agents" in a and "Agent runs" in a and "New role" not in a and "Create a change token" not in a
    r = admin.get("/agents?tab=roles").text
    assert active(r) == ["Roles"] and "New role" in r and "API agents" not in r
    t = admin.get("/agents?tab=tokens").text
    assert active(t) == ["Change tokens"] and "Create a change token" in t and "New role" not in t
    assert active(admin.get("/agents?tab=nonsense").text) == ["Agents"], "an unknown tab shows the default"
    resp = admin.post("/roles", data={"name": "tabbed"}, follow_redirects=False)
    assert resp.status_code == 303 and resp.headers["location"] == "/agents?tab=roles", "making a role returns to Roles"
    resp = admin.post("/roles", data={"name": "tabbed"}, follow_redirects=False)  # a duplicate is refused on the same tab
    assert resp.status_code == 400 and active(resp.text) == ["Roles"]
    made = admin.post("/admin-tokens", data={"name": "tab-token"})
    assert made.status_code == 200 and active(made.text) == ["Change tokens"] and "ulmo_admin_" in made.text, "a new token is shown on its own tab"
    from app.services import proposals as proposal_service
    token_id = proposal_service.list_tokens()[0].id
    assert admin.post(f"/admin-tokens/{token_id}/toggle", follow_redirects=False).headers["location"] == "/agents?tab=tokens"
    assert admin.post("/agent-runs/toggle", data={"enable": "1"}, follow_redirects=False).headers["location"] == "/agents"

    # Commands
    c = admin.get("/commands").text
    assert active(c) == ["SSH hosts"] and "Add a host" in c and "Command library" not in c.split("</nav>")[-1] and "New command" not in c
    assert active(admin.get("/commands?tab=commands").text) == ["Commands"] and "New command" in admin.get("/commands?tab=commands").text
    assert active(admin.get("/commands?tab=copies").text) == ["Saved copies"]
    assert active(admin.get("/commands?tab=nonsense").text) == ["SSH hosts"]
    assert "Add a host" not in admin.get("/commands?tab=commands").text

    # Settings
    g = admin.get("/settings").text
    assert active(g) == ["Git sync"] and "Git repository URL" in g and "Pushover" not in g and "Add key" not in g
    assert active(admin.get("/settings?tab=ssh").text) == ["SSH keys"] and "Add key" in admin.get("/settings?tab=ssh").text
    n = admin.get("/settings?tab=notify").text
    assert active(n) == ["Notifications"] and "Pushover" in n and "Git repository URL" not in n
    assert "Download backup" in admin.get("/settings?tab=backup").text
    acct = admin.get("/settings?tab=account").text
    assert active(acct) == ["Account &amp; users"] and "Change your password" in acct and "Users" in acct and "Git repository URL" not in acct
    assert active(admin.get("/settings?tab=nonsense").text) == ["Git sync"]
    resp = admin.post("/settings/notifications", data={"public_url": "ftp://nope"}, follow_redirects=False)
    assert resp.headers["location"].startswith("/settings?tab=notify&error="), "a refused notification setting shows on its tab"
    resp = admin.post("/settings", data={"git_sync_cron": "not a cron"}, follow_redirects=False)
    assert resp.headers["location"].startswith("/settings?tab=git&"), "the git form returns to its tab"
    resp = admin.post("/settings/users/password", data={"current_password": "wrong", "new_password": "x", "new_password_confirm": "x"}, follow_redirects=False)
    assert resp.headers["location"] == "/settings?tab=account&error=Current+password+is+incorrect"

    # Approvals
    w = admin.get("/approvals").text
    assert active(w)[0].startswith("Waiting") and "Waiting for you" in w and "Recent decisions" not in w
    h = admin.get("/approvals?tab=history").text
    assert active(h) == ["History"] and "Recent decisions" in h and "Recent proposals" in h and "Waiting for you" not in h
    assert active(admin.get("/approvals?tab=nonsense").text)[0].startswith("Waiting")
    aid = _wait()
    assert "Waiting (1)" in admin.get("/approvals").text, "the Waiting tab counts what is waiting"
    admin.post(f"/approvals/{aid}/deny")
    assert "Waiting (" not in admin.get("/approvals").text


def test_times_carry_their_timezone():
    """The database returns UTC timestamps without a zone; the <time> tag must say UTC, or a browser
    reads the digits as its own local time (hours off). A relative one is flagged for the script."""
    from datetime import datetime, timezone as tz
    from app.templating import local_ago, local_time
    naive = datetime(2026, 1, 2, 3, 4, 5)
    assert 'datetime="2026-01-02T03:04:05+00:00"' in local_time(naive), "a naive timestamp is UTC"
    east = datetime(2026, 1, 2, 3, 4, 5, tzinfo=tz(timedelta(hours=-5)))
    assert 'datetime="2026-01-02T08:04:05+00:00"' in local_time(east), "an aware one is converted to UTC"
    assert "data-relative" in local_ago(naive) and "data-relative" not in local_time(naive)
    assert local_time(None) == "-" and local_ago(None) == "-"
    page = admin.get("/").text
    assert re.search(r'<time class="local-time" datetime="[^"]+\+00:00" data-relative>', page), "the Overview's When column is relative"
    js = Path(__file__).resolve().parent.parent / "app" / "static" / "local-time.js"
    assert 'hasAttribute("data-relative")' in js.read_text() and "htmx" not in js.read_text()


def test_nothing_loads_from_the_internet():
    """highlight.js and ansi_up are served from /static/vendor and htmx (unused) is gone, so the
    pages work on a network with no outside access."""
    templates = Path(__file__).resolve().parent.parent / "app" / "templates"
    for f in templates.glob("*.html"):
        text = f.read_text()
        assert not re.search(r'<(script|link)[^>]+(src|href)="https?://', text), f"{f.name} loads from another site"
    for name in ("highlight.min.js", "atom-one-dark.min.css", "ansi_up.js"):
        r = admin.get(f"/static/vendor/{name}")
        assert r.status_code == 200 and len(r.content) > 500, name
    assert "htmx" not in admin.get("/").text


def test_ansible_rows():
    """Each playbook shows its last run and schedule and is scheduled in place; the old Recent Runs
    table and the schedule form under Settings are gone."""
    from app.routers import playbooks as playbooks_module  # noqa: F401
    from app.services import git_sync, inventory
    real = (git_sync.list_playbooks, git_sync.repo_synced, inventory.list_hosts)
    git_sync.list_playbooks = lambda: [{"name": "rowtest.yml", "rel_path": "playbooks/rowtest.yml"}, {"name": "unrun.yml", "rel_path": "playbooks/unrun.yml"}]
    git_sync.repo_synced = lambda: True
    inventory.list_hosts = lambda: ["web1"]
    scheduler.scheduler.start()
    try:
        with Session(engine) as session:
            run = RunHistory(playbook="playbooks/rowtest.yml", status="success", triggered_by="admin")
            session.add(run)
            session.commit()
            session.refresh(run)
        page = admin.get("/ansible").text
        assert "Recent Runs" not in page and ">Playbooks</a>" in page and ">Inventory</a>" in page
        assert f'href="/runs/{run.id}"><span class="badge success">success</span></a>' in page and "Never run" in page and "Not scheduled" in page
        assert page.count('action="/settings/playbook-schedule"') == 2 and ">Schedule</summary>" in page
        # Run sits beside the name, outside the form that holds the tag and host boxes, tied to it by id.
        for n in (1, 2):
            assert f'<button type="submit" form="run-{n}" class="run-btn">Run</button>' in page and f'<form method="post" action="/playbooks/run" class="playbook-run-form" id="run-{n}">' in page
        assert page.count('name="rel_path" value="playbooks/rowtest.yml"') == 2, "the run form and the schedule form each name the playbook"

        r = admin.post("/settings/playbook-schedule", data={"rel_path": "playbooks/rowtest.yml", "cron": "0 3 * * *"}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/ansible?ok=Schedule%20enabled"), "back on the Ansible page"
        page = admin.get("/ansible").text
        assert "<code>0 3 * * *</code>" in page and "· next <time" in page and ">Edit schedule</summary>" in page
        nxt = scheduler.next_run("playbooks/rowtest.yml")
        assert nxt is not None and nxt.utcoffset() == timedelta(0) and nxt > utcnow(), "the next run is a UTC time in the future"
        assert scheduler.next_run("playbooks/unrun.yml") is None
        r = admin.post("/settings/playbook-schedule", data={"rel_path": "playbooks/rowtest.yml", "cron": "nope"}, follow_redirects=False)
        assert r.headers["location"].startswith("/ansible?error="), "a bad schedule is refused where it was typed"
        assert "<code>0 3 * * *</code>" in admin.get("/ansible").text, "and the old one is kept"
        r = admin.post("/settings/playbook-schedule", data={"rel_path": "playbooks/rowtest.yml", "cron": ""}, follow_redirects=False)
        assert r.headers["location"].startswith("/ansible?ok=Schedule%20disabled") and "<code>" not in admin.get("/ansible").text.split("playbook-row", 2)[1]
        assert scheduler.next_run("playbooks/rowtest.yml") is None

        settings_page = admin.get("/settings?tab=git").text
        assert "Playbook Schedules" not in settings_page and "schedules" not in admin.get("/settings").text.split("</nav>")[0]
        # Sync is on both tabs and returns to the tab it was pressed on.
        assert 'name="back" value="inventory"' in admin.get("/inventory").text
        for back, where in (("", "/ansible?"), ("inventory", "/inventory?"), ("anything-else", "/ansible?")):
            r = admin.post("/sync", data={"back": back}, follow_redirects=False)
            assert r.status_code == 303 and r.headers["location"].startswith(where), (back, r.headers["location"])
        with Session(engine) as session:
            session.delete(session.get(RunHistory, run.id))
            session.commit()
    finally:
        scheduler.scheduler.shutdown(wait=False)
        git_sync.list_playbooks, git_sync.repo_synced, inventory.list_hosts = real


def test_settings_forms_are_separate():
    """Git sync and Run limits are two forms with two handlers; saving one never touches the other."""
    page = admin.get("/settings").text
    assert 'action="/settings"' in page and 'action="/settings/limits"' in page and "recent_runs_count" not in page
    git_form = page.split('action="/settings"')[1].split("</form>")[0]
    assert "run_timeout_minutes" not in git_form and "command_history_keep" not in git_form and "git_repo_url" in git_form
    limits_form = page.split('action="/settings/limits"')[1].split("</form>")[0]
    assert "run_timeout_minutes" in limits_form and "git_repo_url" not in limits_form
    from app.services import settings_store
    assert admin.post("/settings/limits", data={"run_timeout_minutes": "11", "command_history_keep": "12"}).status_code == 200
    admin.post("/settings", data={"git_repo_url": "https://git.example/x.git", "git_branch": "dev"})
    assert settings_store.get("run_timeout_minutes") == "11" and settings_store.get("command_history_keep") == "12", "saving git settings leaves the limits alone"
    admin.post("/settings/limits", data={"run_timeout_minutes": "30", "command_history_keep": "13"})
    assert settings_store.get("git_repo_url") == "https://git.example/x.git" and settings_store.get("git_branch") == "dev", "saving limits leaves git settings alone"
    for bad in ("-1", "x"):
        r = admin.post("/settings/limits", data={"run_timeout_minutes": bad, "command_history_keep": "5"}, follow_redirects=False)
        assert "error=" in r.headers["location"] and settings_store.get("run_timeout_minutes") == "30", bad
    settings_store.set_many({"git_repo_url": "", "git_branch": "main", "run_timeout_minutes": "60", "command_history_keep": "20"})


def test_approve_is_hidden_without_a_login():
    """While ULMO_DISABLE_AUTH is set nobody is signed in, so the Overview offers Deny and the
    request's own page, not Approve."""
    aid = _wait()
    real = activity_module.AUTH_DISABLED
    activity_module.AUTH_DISABLED = True
    try:
        page = admin.get("/").text
        assert f'action="/approvals/{aid}/deny"' in page and f'action="/approvals/{aid}/approve"' not in page
    finally:
        activity_module.AUTH_DISABLED = real
    assert f'action="/approvals/{aid}/approve"' in admin.get("/").text
    admin.post(f"/approvals/{aid}/deny")


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
    assert r.status_code == 303 and r.headers["location"] == "/?tab=playbooks"
    r = admin.get("/logs", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/?tab=syncs"
    for url in ("/runs", "/logs"):
        anon = client.get(url, follow_redirects=False)
        assert anon.status_code == 303 and anon.headers["location"].startswith("/login"), "still login-only"

    run = _all(RunHistory)[0]
    assert admin.get(f"/runs/{run.id}").status_code == 200
    sync = _all(SyncHistory)[0]
    detail = admin.get(f"/logs/{sync.id}")
    assert detail.status_code == 200 and 'href="/?tab=syncs"' in detail.text and "Back to activity" in detail.text
    r = admin.get("/runs/99999999", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/?tab=playbooks"
    r = admin.get("/logs/99999999", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/?tab=syncs"

    nav = admin.get("/activity").text.split("</header>")[0]
    assert ">Run History<" not in nav and ">Sync Logs<" not in nav, "both live under Activity now"
    assert '<a href="/" class="active" aria-current="page">Overview</a>' in nav, "the page you are on is marked"


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
    test_top_bar()
    test_overview_all_tab()
    test_overview_needs_you_and_running()
    test_ansible_page_moved()
    test_page_tabs()
    test_times_carry_their_timezone()
    test_nothing_loads_from_the_internet()
    test_ansible_rows()
    test_settings_forms_are_separate()
    test_approve_is_hidden_without_a_login()
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
