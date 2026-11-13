"""Self-check for the tag summary on a finished run's page.

  1. task_outline reads a playbook's named tasks and the tags each ends up with (play, block and task
     tags, as a list or a comma string); it leaves out handlers, roles, nameless and templated names.
  2. ran_task_names reads the tasks a run started from its log, colour codes and all.
  3. A finished run that used --tags says how many tasks ran and lists the ones left out, from the
     playbook as it was when the run started (a later edit changes nothing), and escapes the names.
  4. Nothing is said for a run without tags, a run still going, or a playbook with nothing to list.

Run directly: python3 tests/test_run_tag_summary.py
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path

DATA_DIR = tempfile.mkdtemp(prefix="ulmo-test-")
os.environ["ULMO_DATA_DIR"] = DATA_DIR
os.environ.pop("ULMO_DISABLE_AUTH", None)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session  # noqa: E402

import app.auth as auth_module  # noqa: E402
from app.database import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import RunHistory  # noqa: E402
from app.services import playbook_tags, runner, workspace  # noqa: E402

workspace.schedule_refresh = lambda install=False: None
admin = TestClient(app)

PLAYBOOK = """- name: Frodo
  hosts: frodo
  tags: [site]
  pre_tasks:
    - name: Before everything
      debug: {msg: hi}
  tasks:
    - name: Install packages
      tags: [packages, docker]
    - name: Install rsyslog
      tags: packages, syslog
    - name: Pi-hole update
      tags: pihole
    - name: A named block
      block:
        - name: Inside a block
          tags: [inner]
      rescue:
        - name: In the rescue
      always:
        - name: In the always
      tags: [outer]
    - name: "Templated {{ item }}"
      tags: [x]
    - debug: {msg: no name}
    - name: Untagged task
  post_tasks:
    - name: After everything
      tags: [pihole]
  handlers:
    - name: Restart something
      tags: [syslog]
- name: Roles only
  hosts: all
  roles:
    - common
"""

LOG = (
    "\x1b[0;32mPLAY [Frodo] ***\x1b[0m\n\n\x1b[1;35mTASK [Gathering Facts] ***\x1b[0m\nok: [frodo]\n\n"
    "TASK [Install packages] ***\n\x1b[0;33mchanged: [frodo]\x1b[0m\n\nTASK [Install rsyslog] ***\nok: [frodo]\n\n"
    "TASK [Pi-hole update] ***\nskipping: [frodo]\n\nTASK [After everything] ***\nok: [frodo]\n"
)


def test_outline():
    outline = playbook_tags.task_outline(PLAYBOOK)
    names = [t["name"] for t in outline]
    assert names == ["Before everything", "Install packages", "Install rsyslog", "Pi-hole update", "Inside a block", "In the rescue", "In the always", "Untagged task", "After everything"], names
    tags = {t["name"]: t["tags"] for t in outline}
    assert tags["Before everything"] == ["site"], "a play's tags pass down"
    assert tags["Install packages"] == ["site", "packages", "docker"]
    assert tags["Install rsyslog"] == ["site", "packages", "syslog"], "a comma string is a list"
    assert tags["Inside a block"] == ["site", "outer", "inner"], "a block's tags pass down"
    assert tags["Untagged task"] == ["site"]
    assert "Restart something" not in names and "Templated {{ item }}" not in names
    assert "A named block" not in names, "a block is not a task of its own"
    assert tags["In the rescue"] == ["site", "outer"] and tags["In the always"] == ["site", "outer"]
    assert playbook_tags.task_outline("not: [a playbook") == [] and playbook_tags.task_outline("a: b") == [] and playbook_tags.task_outline("") == []


def test_ran_names():
    assert playbook_tags.ran_task_names(LOG) == {"Gathering Facts", "Install packages", "Install rsyslog", "Pi-hole update", "After everything"}
    assert playbook_tags.ran_task_names("") == set()


def _run(tags, status="success", playbook="playbooks/frodo.yaml", rev="current", log=LOG):
    with Session(engine) as session:
        row = RunHistory(playbook=playbook, status=status, tags=tags, playbook_rev=workspace.file_version(playbook) if rev == "current" else rev)
        session.add(row)
        session.commit()
        session.refresh(row)
    path = runner.log_path(row.id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(log)
    return row.id


def test_summary_on_the_run_page():
    workspace.store("playbooks/frodo.yaml", PLAYBOOK.encode(), base=None)
    rid = _run("packages,pihole")
    page = admin.get(f"/runs/{rid}").text
    assert "4 of 9 tasks ran, 5 left out because no tag matched" in page, page[page.find("Tags"):page.find("Tags") + 300]
    assert "<code>packages, pihole</code>" in page
    for left_out in ("Before everything", "Inside a block", "In the rescue", "In the always", "Untagged task"):
        assert f"<li>{left_out}" in page, left_out
    assert "<li>Install packages" not in page and "<li>After everything" not in page
    assert "<code>site, outer, inner</code>" in page, "each skipped task shows its tags"
    assert "<span>(no tags)</span>" not in page and "<code>site</code>" in page

    # an edit afterwards does not change what that run says: the playbook as it was is used
    old_rev = workspace.file_version("playbooks/frodo.yaml")
    workspace.store("playbooks/frodo.yaml", b"- hosts: all\n  tasks:\n    - name: Only this\n", base=None)
    assert "4 of 9 tasks ran, 5 left out" in admin.get(f"/runs/{rid}").text
    # a run whose playbook version is gone has nothing to compare, so it keeps the plain tags line
    gone = _run("packages", rev="ffffffffffffffff")
    page = admin.get(f"/runs/{gone}").text
    assert "tasks ran" not in page and "tags: <code>packages</code>" in page

    # a name an agent or a file puts in a task cannot add markup
    workspace.store("playbooks/evil.yaml", b"- hosts: all\n  tasks:\n    - name: <script>alert(1)</script>\n      tags: [a]\n", base=None)
    evil = _run("b", playbook="playbooks/evil.yaml", log="TASK [Gathering Facts]\n")
    page = admin.get(f"/runs/{evil}").text
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page and "0 of 1 tasks ran, 1 left out" in page


def test_nothing_to_say():
    workspace.store("playbooks/frodo.yaml", PLAYBOOK.encode(), base=None)
    assert "tasks ran" not in admin.get(f"/runs/{_run(None)}").text, "no tags"
    assert "tasks ran" not in admin.get(f"/runs/{_run('', )}").text
    running = admin.get(f"/runs/{_run('packages', status='running')}").text
    assert "tasks ran" not in running and "tags: <code>packages</code>" in running, "a run still going"
    workspace.store("playbooks/roles.yaml", b"- hosts: all\n  roles:\n    - common\n", base=None)
    page = admin.get(f"/runs/{_run('x', playbook='playbooks/roles.yaml')}").text
    assert "tasks ran" not in page and "tags: <code>x</code>" in page, "a playbook with no tasks of its own"
    # the run is listed with every task ran: nothing left out is not mentioned as left out
    all_ran = "".join(f"TASK [{n}]\n" for n in ("Before everything", "Install packages", "Install rsyslog", "Pi-hole update", "Inside a block", "In the rescue", "In the always", "Untagged task", "After everything"))
    page = admin.get(f"/runs/{_run('all', log=all_ran)}").text
    assert "9 of 9 tasks ran</summary>" in page and "left out" not in page


def main():
    init_db()
    auth_module.create_user("admin", "pw-for-tests")
    r = admin.post("/login", data={"username": "admin", "password": "pw-for-tests"}, follow_redirects=False)
    assert r.status_code == 303, "test login failed"
    tests = [v for k, v in sorted(globals().items(), key=lambda kv: list(globals()).index(kv[0])) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print(f"OK: tag summary — {len(tests)} checks.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
