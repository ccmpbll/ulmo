"""Self-check for editing workspace files (phase 2 of moving Ansible off Git).

  1. Agents may read the playbooks (and only those) and cannot write anything; every edit needs a change token.
  2. A change token reads every text file and proposes edits to any of them (`save_file`): checked up front
     (scope, stale version, no change, hidden characters, size, binary, a path that escapes), recorded as a
     pending proposal, and written only when an admin approves it on a page that shows the diff with line
     numbers and the roles granted that playbook.
  3. Approving saves through the Files page's locked, version-checked write (saved copy, CRLF kept), all
     files or none, and waits while a playbook runs; a file that changed since it was read fails it.
  4. Moving a playbook takes its grants and schedule along; moving it out of the playbooks folder does not.
  5. A run records the playbook's version and the workspace's revision, and the run page says where that
     version is now.
  6. ansible-playbook --syntax-check warns on a saved or approved playbook that does not parse as a play.
  7. The new columns are added to databases created before this feature.

Run directly: python3 tests/test_agent_files.py
"""
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

DATA_DIR = tempfile.mkdtemp(prefix="ulmo-test-")
os.environ["ULMO_DATA_DIR"] = DATA_DIR
os.environ.pop("ULMO_DISABLE_AUTH", None)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ansible_runner  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlmodel import Session, SQLModel, select  # noqa: E402

import app.auth as auth_module  # noqa: E402
from app import database  # noqa: E402
from app.database import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import AdminToken, Agent, Approval, Grant, PlaybookSchedule, Proposal, RunHistory  # noqa: E402
from app.services import agents, inventory, notifier, proposals, runner, scheduler, workspace  # noqa: E402

inventory.list_hosts = lambda: ["web1", "web2"]
inventory.list_groups = lambda: ["all", "ungrouped"]
workspace.on_listing_change(scheduler.reap_orphaned_schedules)  # start() registers it; the scheduler itself is not started here
workspace.schedule_refresh = lambda install=False: None  # the background refresh is tested in test_workspace.py
sent: list[tuple] = []
notifier._post = lambda url, data, name, headers=None: sent.append((name, data.decode()))
ansible_calls: list[dict] = []
ansible_runner.run_async = lambda **kw: (ansible_calls.append(kw), (SimpleNamespace(join=lambda: None), SimpleNamespace(rc=0, status="successful")))[1]

client = TestClient(app)
admin = TestClient(app)
WS = Path(DATA_DIR) / "ansible"


def h(token):
    return {"Authorization": f"Bearer {token}"}


def reset():
    shutil.rmtree(WS, ignore_errors=True)
    shutil.rmtree(Path(DATA_DIR) / "ansible.history", ignore_errors=True)
    with Session(engine) as session:
        for model in (Approval, Grant, PlaybookSchedule, Proposal):
            for row in session.exec(select(model)).all():
                session.delete(row)
        session.commit()
    sent.clear()


def put(rel, text, mode=None):
    data = text if isinstance(text, bytes) else text.encode()
    workspace.store(rel, data, base=None)


def new_agent(name):
    return agents.create_agent(name)


def version(rel):
    return workspace.read_file(rel)["version"]


def admin_token(name="scripts"):
    row, token = proposals.create_token(name)
    return row, token


def send(token, ops, note=None, dry_run=False):
    body = {"ops": ops}
    if note:
        body["note"] = note
    return client.post("/api/v1/admin/proposals" + ("?dry_run=true" if dry_run else ""), json=body, headers=h(token))


def edit(path, text, base):
    return {"op": "save_file", "path": path, "text": text, "base": base}


def proposal(proposal_id):
    with Session(engine) as session:
        return session.get(Proposal, proposal_id)


def digest_of(proposal_id):
    plan, problem = proposals.view(proposal(proposal_id))
    assert plan is not None, problem
    return plan.digest


def approve(proposal_id):
    return admin.post(f"/proposals/{proposal_id}/approve", data={"seen": digest_of(proposal_id)}, follow_redirects=False)


def test_agents_can_read_playbooks_and_nothing_else():
    reset()
    put("playbooks/site.yaml", "- hosts: all\n")
    put("playbooks/old/gone.yaml", "- hosts: all\n")
    put("playbooks/requirements.yaml", "collections: []\n")
    put("files/wg.conf", "PrivateKey = secret\n")
    put("ansible.cfg", "[defaults]\n")
    _, token = new_agent("reader")
    r = client.get("/api/v1/playbooks/content?path=playbooks/site.yaml", headers=h(token))
    assert r.status_code == 200 and r.json() == {"path": "playbooks/site.yaml", "version": version("playbooks/site.yaml"), "text": "- hosts: all\n"}, r.text
    for path in ("files/wg.conf", "ansible.cfg", "playbooks/old/gone.yaml", "playbooks/requirements.yaml", "../x", "playbooks/missing.yaml", "inventory.yaml"):
        assert client.get(f"/api/v1/playbooks/content?path={path}", headers=h(token)).status_code == 404, path
    assert client.get("/api/v1/playbooks/content?path=playbooks/site.yaml", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.get("/api/v1/playbooks/content?path=playbooks/site.yaml").status_code == 401
    # an agent cannot propose or write anything to files: no such endpoint, and the change API refuses its token
    for method, url in (("post", "/api/v1/files/edits"), ("put", "/api/v1/files/content"), ("post", "/api/v1/playbooks/content")):
        assert client.request(method, url, json={"path": "playbooks/site.yaml", "text": "x", "base": ""}, headers=h(token)).status_code in (404, 405), url
    assert client.post("/api/v1/admin/proposals", json={"ops": [edit("playbooks/site.yaml", "x\n", version("playbooks/site.yaml"))]}, headers=h(token)).status_code in (401, 403)
    assert client.get("/api/v1/admin/files", headers=h(token)).status_code in (401, 403)
    assert workspace.file_bytes("playbooks/site.yaml") == b"- hosts: all\n"
    assert not hasattr(agents.create_agent("x")[0], "file_access"), "no per-agent file setting"


def test_the_change_token_reads_every_file():
    reset()
    put("playbooks/site.yaml", "- hosts: all\n")
    put("files/wg.conf", "PrivateKey = secret\n")
    put("ansible.cfg", "[defaults]\n")
    put("files/blob.bin", b"\x00\x01\x02binary")
    _, token = admin_token("reader")
    listed = client.get("/api/v1/admin/files", headers=h(token)).json()["files"]
    assert sorted(f["path"] for f in listed) == ["ansible.cfg", "files/blob.bin", "files/wg.conf", "playbooks/site.yaml"]
    r = client.get("/api/v1/admin/files/content?path=files/wg.conf", headers=h(token)).json()
    assert r == {"path": "files/wg.conf", "version": version("files/wg.conf"), "text": "PrivateKey = secret\n"}
    assert client.get("/api/v1/admin/files/content?path=files/blob.bin", headers=h(token)).status_code == 415
    for path in ("missing.yaml", "../x", ".git/config"):
        assert client.get(f"/api/v1/admin/files/content?path={path}", headers=h(token)).status_code == 404, path
    assert client.get("/api/v1/admin/files").status_code == 401


def test_file_proposals_are_checked_up_front():
    reset()
    put("playbooks/site.yaml", "- hosts: all\n  tasks: []\n")
    put("files/wg.conf", "a=1\n")
    put("ansible.cfg", "[defaults]\n")
    put("files/blob.bin", b"\x00\x01")
    base = version("playbooks/site.yaml")
    _, token = admin_token("checks")

    # a dry run says what would change and records nothing
    r = send(token, [edit("playbooks/site.yaml", "- hosts: web1\n  tasks: []\n", base)], dry_run=True)
    assert r.status_code == 200 and r.json()["valid"] and "-- hosts: all" in r.json()["diff"]
    assert "+- hosts: web1" in r.json()["diff"] and "playbooks/site.yaml (current)" in r.json()["diff"], r.json()["diff"]
    with Session(engine) as session:
        assert session.exec(select(Proposal)).all() == []
    # a real one is pending and writes nothing
    r = send(token, [edit("playbooks/site.yaml", "- hosts: web1\n  tasks: []\n", base)], note="narrow it")
    assert r.status_code == 202 and r.json()["status"] == "pending", r.text
    assert workspace.file_bytes("playbooks/site.yaml") == b"- hosts: all\n  tasks: []\n"
    pid = r.json()["id"]
    assert proposal(pid).note == "narrow it" and (proposal(pid).expires_at - proposal(pid).created_at).total_seconds() > 3600 * 23
    assert send(token, [edit("playbooks/site.yaml", "- hosts: web1\n  tasks: []\n", base)]).json()["id"] == pid, "the same proposal again is the same proposal"
    # any file, not only playbooks
    assert send(token, [edit("files/wg.conf", "a=2\n", version("files/wg.conf"))], dry_run=True).status_code == 200
    assert send(token, [edit("ansible.cfg", "[defaults]\nforks = 5\n", version("ansible.cfg"))], dry_run=True).status_code == 200
    assert send(token, [edit("files/new/deep/thing.conf", "x\n", "")], dry_run=True).status_code == 200, "a new file in a new folder"
    assert send(token, [edit("playbooks/fresh.yaml", "- hosts: all\n", "")], dry_run=True).status_code == 200

    long = "x" * (proposals.MAX_FILE_TEXT + 10)
    refused = [
        ([edit("../escape.yaml", "x", "")], "op 1 (save_file)"),
        ([edit(".git/config", "x", "")], ".git"),
        ([edit("files/.ulmo-tmp", "x", "")], "op 1"),
        ([edit("playbooks/site.yaml", "changed\n", "0000000000000000")], "changed since it was read"),
        ([edit("playbooks/site.yaml", "- hosts: all\n  tasks: []\n", base)], "changes nothing"),
        ([edit("playbooks/site.yaml", "- hosts: all\n  tasks: []\r\n", base)], "changes nothing"),
        ([edit("playbooks/site.yaml", "evil\u202egnp.yaml\n", base)], "direction-override"),
        ([edit("playbooks/site.yaml", "zero\u200bwidth\n", base)], "zero-width"),
        ([edit("playbooks/site.yaml", long, base)], "limited to"),
        ([edit("playbooks/fresh.yaml", "x\n", "abc")], "does not exist"),
        ([edit("playbooks/site.yaml", "x\n", "")], "already exists"),
        ([edit("files/blob.bin", "x\n", version("files/blob.bin"))], "binary"),
        ([edit("playbooks/site.yaml", "a\n", base), edit("playbooks/site.yaml", "b\n", base)], "edited twice"),
        ([edit("playbooks/site.yaml", "a\n", base), {"op": "delete_command", "name": "x"}], "cannot be mixed"),
        ([{"op": "save_file", "path": "playbooks/site.yaml", "text": 5, "base": base}], "must be text"),
        ([{"op": "save_file", "path": "playbooks/site.yaml", "text": "x"}], "missing keys: base"),
        ([{"op": "save_file", "path": "playbooks/site.yaml", "text": "x", "base": base, "mode": "0755"}], "unknown keys: mode"),
        ([edit("files/a.txt", "x\n", ""), edit("files/a.txt/b.txt", "x\n", "")], "can't go inside"),
    ]
    for ops, expect in refused:
        r = send(token, ops, dry_run=True)
        assert r.status_code == 400 and expect in r.json()["detail"], (expect, r.status_code, r.text)
    total = [edit(f"files/big{i}.txt", "y" * (proposals.MAX_FILE_TEXT - 1), "") for i in range(5)]
    r = send(token, total, dry_run=True)
    assert r.status_code == 400 and "limited to 1024 KB" in r.json()["detail"], r.text
    # 413 for bytes over the cap even when the character count is under it
    wide = "\u00e9" * (proposals.MAX_FILE_TEXT // 2 + 5)
    assert send(token, [edit("playbooks/site.yaml", wide, base)], dry_run=True).status_code == 400
    assert os.listdir(WS / "playbooks") == ["site.yaml"], "still nothing written"


def test_the_proposal_page_and_approving():
    reset()
    put("playbooks/site.yaml", "".join(f"line {i}\n" for i in range(1, 31)))
    base = version("playbooks/site.yaml")
    _, token = admin_token("editor")
    role = agents.create_role("deployers")
    agents.add_grant(role.id, "playbooks/site.yaml", ["web1", "web2"], requires_approval=True)
    new_text = "".join(f"line {i}\n" if i != 15 else "line fifteen, edited\n" for i in range(1, 31)) + "added \u0430\n"  # a Cyrillic \u0430
    pid = send(token, [edit("playbooks/site.yaml", new_text, base), edit("files/extra.conf", "<script>alert(1)</script>\n", "")], note="fix line 15").json()["id"]

    html = admin.get(f"/proposals/{pid}").text
    assert "editor proposes a change" in html and "fix line 15" in html and "+2 -1 lines" in html and "New file" in html
    assert '<tr class="del"><td class="no">15</td><td class="no"></td>' in html and '<tr class="add"><td class="no"></td><td class="no">15</td>' in html
    assert 'class="gap"' in html and "unchanged line" in html, "lines far from the change are folded"
    assert "Roles can run this playbook" in html and "deployers on web1, web2 (asks first)" in html
    assert "non-ASCII" in html and "U+0430" in html
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html, "what a script wrote cannot add markup"
    assert "all of them, or none" in html or "or none of them" in html
    assert "/proposals/%d/approve" % pid in html and 'name="seen"' in html
    assert "proposes" in admin.get("/approvals").text

    before = len(workspace.list_versions("playbooks/site.yaml"))
    r = approve(pid)
    assert r.status_code == 303
    row = proposal(pid)
    assert row.status == "applied" and row.decided_by == "admin", row.result
    assert workspace.file_bytes("playbooks/site.yaml").decode() == new_text
    assert workspace.file_bytes("files/extra.conf") == b"<script>alert(1)</script>\n"
    assert len(workspace.list_versions("playbooks/site.yaml")) == before + 1, "the old version is a saved copy"
    done = admin.get(f"/proposals/{pid}").text
    assert "Saved." in done and 'href="/files"' in done and "commands?tab=copies" not in done
    assert client.get(f"/api/v1/admin/proposals/{pid}", headers=h(token)).json()["status"] == "applied"
    # the token now reads the new version, and the old base is stale
    assert client.get("/api/v1/admin/files/content?path=playbooks/site.yaml", headers=h(token)).json()["text"] == new_text
    assert send(token, [edit("playbooks/site.yaml", "x\n", base)], dry_run=True).status_code == 400

    # deny writes nothing
    other = send(token, [edit("playbooks/site.yaml", "denied text\n", version("playbooks/site.yaml"))]).json()["id"]
    assert admin.post(f"/proposals/{other}/deny", follow_redirects=False).status_code == 303
    assert proposal(other).status == "denied" and workspace.file_bytes("playbooks/site.yaml").decode() == new_text
    # a token cannot approve its own proposal
    third = send(token, [edit("playbooks/site.yaml", "third\n", version("playbooks/site.yaml"))]).json()["id"]
    assert client.post(f"/proposals/{third}/approve", headers=h(token), data={"seen": "x"}, follow_redirects=False).status_code in (303, 401, 403)
    assert proposal(third).status == "pending"


def test_a_crlf_file_stays_crlf():
    reset()
    put("playbooks/win.yaml", b"- hosts: all\r\n  tasks: []\r\n")
    _, token = admin_token("crlf")
    base = version("playbooks/win.yaml")
    pid = send(token, [edit("playbooks/win.yaml", "- hosts: web1\n  tasks: []\n", base)]).json()["id"]
    approve(pid)
    assert workspace.file_bytes("playbooks/win.yaml") == b"- hosts: web1\r\n  tasks: []\r\n"
    # text sent with CRLF is accepted too
    base = version("playbooks/win.yaml")
    assert send(token, [edit("playbooks/win.yaml", "- hosts: web2\r\n  tasks: []\r\n", base)], dry_run=True).status_code == 200


def test_approving_waits_for_a_run_and_fails_when_things_changed():
    reset()
    put("playbooks/site.yaml", "- hosts: all\n  tasks: []\n")
    row, token = admin_token("blocked")
    base = version("playbooks/site.yaml")
    pid = send(token, [edit("playbooks/site.yaml", "- hosts: web1\n  tasks: []\n", base)]).json()["id"]

    workspace.begin_run(901, "playbooks/site.yaml")
    try:
        assert "Read-only while a playbook runs" in admin.get(f"/proposals/{pid}").text
        r = admin.post(f"/proposals/{pid}/approve", data={"seen": digest_of(pid)}, follow_redirects=False)
        assert r.status_code == 303
        assert proposal(pid).status == "pending", "a refused approval is not used up"
        assert "read-only while run #901" in admin.get(f"/proposals/{pid}").text.lower()
    finally:
        workspace.end_run(901)
    # the file changed after the token read it: the page says so, and approving fails the proposal
    put("playbooks/site.yaml", "- hosts: all\n  tasks:\n    - debug: {}\n")
    assert "can no longer be applied" in admin.get(f"/proposals/{pid}").text
    admin.post(f"/proposals/{pid}/approve", data={"seen": "whatever"})
    assert proposal(pid).status == "failed" and "changed since it was read" in proposal(pid).result, proposal(pid).result
    assert workspace.file_bytes("playbooks/site.yaml") == b"- hosts: all\n  tasks:\n    - debug: {}\n"

    # a disabled token revokes what it queued
    base = version("playbooks/site.yaml")
    second = send(token, [edit("playbooks/site.yaml", "- hosts: web2\n", base)]).json()["id"]
    proposals.toggle_token(row.id)
    admin.post(f"/proposals/{second}/approve", data={"seen": "x"})
    assert proposal(second).status == "failed" and "disabled" in proposal(second).result and workspace.file_bytes("playbooks/site.yaml") != b"- hosts: web2\n"
    proposals.toggle_token(row.id)


def test_a_file_proposal_is_all_or_nothing():
    reset()
    put("playbooks/a.yaml", "a\n")
    put("files/b.conf", "b\n")
    _, token = admin_token("atomic")
    ops = [edit("playbooks/a.yaml", "a2\n", version("playbooks/a.yaml")), edit("files/b.conf", "b2\n", version("files/b.conf")), edit("files/c.conf", "c\n", "")]
    pid = send(token, ops).json()["id"]
    digest = digest_of(pid)
    real = workspace._store_one
    calls = []

    def flaky(rel, data, base, mode=None):
        calls.append(rel)
        if len(calls) == 3:
            raise OSError("disk full")
        return real(rel, data, base, mode)

    workspace._store_one = flaky
    try:
        admin.post(f"/proposals/{pid}/approve", data={"seen": digest})
    finally:
        workspace._store_one = real
    assert proposal(pid).status == "failed" and "disk full" in proposal(pid).result
    assert workspace.file_bytes("playbooks/a.yaml") == b"a\n" and workspace.file_bytes("files/b.conf") == b"b\n", "the first two were put back"
    assert not (WS / "files" / "c.conf").exists()
    # and a plain success writes all three
    pid = send(token, ops).json()["id"]
    approve(pid)
    assert proposal(pid).status == "applied"
    assert [workspace.file_bytes(p) for p in ("playbooks/a.yaml", "files/b.conf", "files/c.conf")] == [b"a2\n", b"b2\n", b"c\n"]
    # the write itself refuses what the planning would have: a file under a file, and a running playbook
    try:
        workspace.store_checked([("files/p.txt", b"x", ""), ("files/p.txt/q.txt", b"x", "")])
        raise AssertionError("a path under a file must be refused")
    except ValueError as exc:
        assert "can't go inside" in str(exc) and not (WS / "files" / "p.txt").exists()
    workspace.begin_run(902, "playbooks/a.yaml")
    try:
        workspace.store_checked([("files/z.txt", b"x", "")])
        raise AssertionError("a running playbook must refuse")
    except workspace.Locked:
        assert not (WS / "files" / "z.txt").exists()
    finally:
        workspace.end_run(902)
    # what the admin saw is what is applied: a digest for other text, or another proposal's, is refused
    a = send(token, [edit("files/d.txt", "one\n", "")]).json()["id"]
    b = send(token, [edit("files/d.txt", "two\n", "")]).json()["id"]
    assert digest_of(a) != digest_of(b), "the digest covers the text"
    r = admin.post(f"/proposals/{a}/approve", data={"seen": digest_of(b)}, follow_redirects=False)
    assert proposal(a).status == "pending" and not (WS / "files" / "d.txt").exists(), "a digest for other text is refused"
    # a stale base on the second file leaves the first alone too
    put("files/b.conf", "changed behind your back\n")
    stale = [edit("playbooks/a.yaml", "a3\n", version("playbooks/a.yaml")), edit("files/b.conf", "b3\n", "0000000000000000")]
    assert send(token, stale, dry_run=True).status_code == 400
    try:
        workspace.store_checked([(r, d.encode(), b) for r, d, b in (("playbooks/a.yaml", "a3\n", version("playbooks/a.yaml")), ("files/b.conf", "b3\n", "0000000000000000"))])
        raise AssertionError("a stale base must refuse")
    except workspace.Conflict:
        pass
    assert workspace.file_bytes("playbooks/a.yaml") == b"a2\n"


def test_a_moved_playbook_takes_its_grants_and_schedule():
    reset()
    put("playbooks/site.yaml", "- hosts: all\n")
    role = agents.create_role("movers")
    agents.add_grant(role.id, "playbooks/site.yaml", ["web1"])
    with Session(engine) as session:
        session.add(PlaybookSchedule(rel_path="playbooks/site.yaml", cron="0 3 * * *"))
        session.commit()
    scheduler.reschedule_playbook("playbooks/site.yaml", "0 3 * * *")

    workspace.move("playbooks/site.yaml", "playbooks/web.yaml")
    with Session(engine) as session:
        assert [g.playbook for g in session.exec(select(Grant).where(Grant.role_id == role.id)).all()] == ["playbooks/web.yaml"]
        assert [(s.rel_path, s.cron) for s in session.exec(select(PlaybookSchedule)).all()] == [("playbooks/web.yaml", "0 3 * * *")]
    job = lambda rel: scheduler.scheduler.get_job(scheduler.PLAYBOOK_JOB_PREFIX + rel)  # noqa: E731  (the scheduler is not started here)
    assert job("playbooks/web.yaml") is not None and job("playbooks/site.yaml") is None, "the job moved too"

    # into old/: no longer a playbook, so the schedule goes (as for any orphan) and the grant is not carried
    workspace.move("playbooks/web.yaml", "playbooks/old/web.yaml")
    with Session(engine) as session:
        assert session.exec(select(PlaybookSchedule)).all() == []
        assert [g.playbook for g in session.exec(select(Grant)).all()] == ["playbooks/web.yaml"]
    assert job("playbooks/web.yaml") is None and job("playbooks/old/web.yaml") is None
    # a file that was never a playbook moves without touching anything
    put("files/x.conf", "x")
    workspace.move("files/x.conf", "files/y.conf")


def _stub_execute():
    real = runner._execute
    runner._execute = lambda run_id, *a: workspace.end_run(run_id)
    return real


def test_runs_record_what_they_ran():
    reset()
    put("playbooks/site.yaml", "- hosts: all\n  tasks: []\n")
    put("files/a.conf", "one\n")
    rev0 = workspace.revision()
    assert rev0 == workspace.revision() and len(rev0) == 16
    put("files/a.conf", "two\n")
    assert workspace.revision() != rev0, "a change to any file changes the revision"
    put("files/a.conf", "one\n")
    assert workspace.revision() == rev0, "and putting it back changes it back"
    workspace.move("files/a.conf", "files/b.conf")
    assert workspace.revision() != rev0, "a file with the same contents under another name is another workspace"
    workspace.move("files/b.conf", "files/a.conf")
    assert workspace.revision() == rev0
    inventory_file = WS / "inventory.yaml"
    assert not inventory_file.exists()

    real = _stub_execute()
    try:
        record = runner.start_run("playbooks/site.yaml", triggered_by="test")
    finally:
        runner._execute = real
    assert record.playbook_rev == version("playbooks/site.yaml") and record.workspace_rev == rev0
    api = Session(engine)
    with api:
        row = api.get(RunHistory, record.id)
    assert row.playbook_rev == record.playbook_rev and row.workspace_rev == rev0

    page = admin.get(f"/runs/{record.id}").text
    assert f"Playbook version <code>{record.playbook_rev}</code>" in page and "the file has not changed since" in page
    assert "unchanged since." in page
    old_text = workspace.file_bytes("playbooks/site.yaml").decode()
    put("playbooks/site.yaml", "- hosts: web1\n  tasks: []\n")
    changed = admin.get(f"/runs/{record.id}").text
    assert "the file has changed since; that version is the" in changed and "saved copy from" in changed
    copy_id = workspace.list_versions("playbooks/site.yaml")[0]["id"]
    assert f"/files/version?path=playbooks/site.yaml&amp;version={copy_id}" in changed or f"/files/version?path=playbooks/site.yaml&version={copy_id}" in changed
    assert "something in the workspace has changed since" in changed
    assert workspace.version_of(workspace.version_bytes("playbooks/site.yaml", copy_id)) == record.playbook_rev and old_text.startswith("- hosts: all")
    # a version nobody kept
    with Session(engine) as session:
        row = session.get(RunHistory, record.id)
        row.playbook_rev = "ffffffffffffffff"
        session.add(row)
        session.commit()
    assert "no saved copy of that version is left" in admin.get(f"/runs/{record.id}").text
    # an old run, from before this was recorded, says nothing about it
    with Session(engine) as session:
        old = RunHistory(playbook="playbooks/site.yaml", status="success")
        session.add(old)
        session.commit()
        session.refresh(old)
    assert "Playbook version" not in admin.get(f"/runs/{old.id}").text
    # an agent sees it in the run's JSON
    _, token = new_agent("runwatcher")
    run_json = client.get(f"/api/v1/runs/{record.id}", headers=h(token)).json()
    assert run_json["playbook_rev"] == "ffffffffffffffff" and run_json["workspace_rev"] == rev0


def test_syntax_check_warns():
    reset()
    if shutil.which("ansible-playbook") is None:
        print("   (skipped: ansible-playbook is not installed)")
        return
    put("playbooks/good.yaml", "- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.debug:\n        msg: hi\n")
    put("playbooks/bad.yaml", "- hosts: all\n  tasks:\n    - this_module_does_not_exist_xyz: {}\n")
    put("playbooks/notaplay.yaml", "just: a mapping\n")
    put("files/data.yaml", "key: value\n")
    assert workspace.check_playbook("playbooks/good.yaml") is None
    bad = workspace.check_playbook("playbooks/bad.yaml")
    assert bad and bad.startswith("ansible-playbook --syntax-check failed:") and "this_module_does_not_exist_xyz" in bad, bad
    assert workspace.check_playbook("playbooks/notaplay.yaml"), "a mapping is not a play"
    assert workspace.check_playbook("files/data.yaml") is None, "only playbooks are checked"
    # on the edit page, a save shows it (and still saves)
    base = version("playbooks/good.yaml")
    r = admin.post("/files/save", data={"path": "playbooks/good.yaml", "text": "- hosts: all\n  tasks:\n    - this_module_does_not_exist_xyz: {}\n", "base": base}, follow_redirects=False)
    assert r.status_code == 303 and "warn=" in r.headers["location"] and "syntax-check" in re_unquote(r.headers["location"]), r.headers["location"]
    assert b"this_module_does_not_exist_xyz" in workspace.file_bytes("playbooks/good.yaml")
    # an approved proposal carries the warning in its result, and still saves
    _, token = admin_token("syntax")
    pid = send(token, [edit("playbooks/good.yaml", "- hosts: all\n  tasks:\n    - another_missing_module_xyz: {}\n", version("playbooks/good.yaml"))]).json()["id"]
    approve(pid)
    row = proposal(pid)
    assert row.status == "applied" and "syntax-check failed" in row.result and b"another_missing_module_xyz" in workspace.file_bytes("playbooks/good.yaml")
    assert "syntax-check failed" in admin.get(f"/proposals/{pid}").text
    # without ansible-playbook on the path, nothing is said
    real = shutil.which
    workspace.shutil.which = lambda name: None
    try:
        assert workspace.check_playbook("playbooks/bad.yaml") is None
    finally:
        workspace.shutil.which = real


def re_unquote(url):
    from urllib.parse import unquote
    return unquote(url)


def test_old_databases_get_the_new_columns():
    path = Path(DATA_DIR) / "old.db"
    SQLModel.metadata.create_all(create_engine(f"sqlite:///{path}"))
    con = sqlite3.connect(path)
    con.execute("DROP TABLE runhistory")
    con.execute("CREATE TABLE runhistory (id INTEGER PRIMARY KEY, playbook TEXT, status TEXT, triggered_by TEXT, return_code INTEGER, tags TEXT, \"limit\" TEXT, started_at TIMESTAMP, finished_at TIMESTAMP)")
    con.execute("INSERT INTO runhistory (id, playbook, status) VALUES (1, 'p.yml', 'success')")
    con.commit()
    con.close()
    real = database.engine
    database.engine = create_engine(f"sqlite:///{path}")
    try:
        database._apply_column_migrations()
        database._apply_column_migrations()
        with database.engine.connect() as conn:
            assert conn.exec_driver_sql("SELECT playbook_rev, workspace_rev FROM runhistory").all() == [(None, None)]
    finally:
        database.engine = real


def main():
    init_db()
    auth_module.create_user("admin", "pw-for-tests")
    r = admin.post("/login", data={"username": "admin", "password": "pw-for-tests"}, follow_redirects=False)
    assert r.status_code == 303, "test login failed"
    tests = [v for k, v in sorted(globals().items(), key=lambda kv: list(globals()).index(kv[0])) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print(f"OK: agents and workspace files — {len(tests)} checks.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
