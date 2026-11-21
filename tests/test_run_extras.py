"""Self-check for the per-run "Additional options": --extra-vars and an SSH password (--ask-pass).

Covers: what check_run_options() rejects, the arguments _execute() hands to ansible-runner (and
that --ask-pass is never added without a password, which would hang the run), and, with a fake
`ansible-playbook` that really prompts on a terminal, that the password reaches the prompt without
landing in the run's log, its command file or the database; that leftover env files from an older
release are not replayed but an operator's own env/extravars is kept; that start_run() stores and
forwards both options; that the POST route validates them and refuses extra vars while
ULMO_DISABLE_AUTH is set; and that the Ansible page, run page, Overview, Activity and the
notification show them.

Run directly: python3 tests/test_run_extras.py
"""
import os
import shutil
import stat
import sys
import tempfile
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DATA_DIR = tempfile.mkdtemp(prefix="ulmo-test-")
os.environ["ULMO_DATA_DIR"] = DATA_DIR
os.environ["ULMO_DISABLE_AUTH"] = "true"  # the routes' login check short-circuits; each test sets the routers' own flag
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, func, select  # noqa: E402

from app.config import RUNNER_DATA_DIR  # noqa: E402
from app.database import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import RunHistory  # noqa: E402
from app.routers import playbooks as playbooks_router  # noqa: E402
from app.services import inventory, notifier, runner, settings_store, workspace  # noqa: E402
from app.templating import templates  # noqa: E402
import ansible_runner  # noqa: E402

inventory.list_hosts = lambda: ["web1"]
workspace.schedule_refresh = lambda install=False: None  # the background refresh is tested in test_workspace.py
client = TestClient(app)

SECRET = "s3cr3t-pa55 w0rd"


def _new_run(**fields) -> int:
    with Session(engine) as session:
        record = RunHistory(playbook="fake.yml", **fields)
        session.add(record)
        session.commit()
        session.refresh(record)
        return record.id


def _captured_kwargs(**execute_args) -> dict:
    """Run _execute() against a fake ansible_runner.run_async and return what it was called with."""
    seen = {}

    def fake_run_async(**kwargs):
        seen.update(kwargs)

        class _Thread:
            def join(self):
                pass

        class _Result:
            rc = 0
            status = "successful"

        return _Thread(), _Result()

    original = ansible_runner.run_async
    ansible_runner.run_async = fake_run_async
    try:
        runner._execute(_new_run(), "fake.yml", **execute_args)
    finally:
        ansible_runner.run_async = original
    return seen


def test_check_rejects_bad_input():
    bad_vars = ["a=1\nb=2", "a=1\rb=2", "a=1\0b", "x" * (runner.MAX_EXTRA_VARS + 1), "@/etc/passwd", "  @vars.yml"]
    for value in bad_vars:
        try:
            runner.check_run_options(value, "")
        except ValueError:
            pass
        else:
            raise AssertionError(f"extra vars {value!r} should be rejected")

    for value in ["pw\nline2", "pw\0", "x" * 300]:
        try:
            runner.check_run_options("", value)
        except ValueError as exc:
            assert value not in str(exc), "the error message must not echo the password"
        else:
            raise AssertionError(f"password {value!r} should be rejected")


def test_check_accepts_normal_input():
    assert runner.check_run_options("  ansible_ssh_user=root  ", SECRET) == "ansible_ssh_user=root"
    assert runner.check_run_options('{"a": "b c"}', "") == '{"a": "b c"}'
    assert runner.check_run_options("", "") == ""


def test_no_extras_changes_nothing():
    kw = _captured_kwargs()
    assert kw["cmdline"] is None, kw["cmdline"]
    assert "passwords" not in kw


def test_extra_vars_only_never_asks_for_a_password():
    kw = _captured_kwargs(extra_vars="ansible_ssh_user=root")
    assert kw["cmdline"] == "--extra-vars=ansible_ssh_user=root", kw["cmdline"]
    assert "--ask-pass" not in kw["cmdline"]
    assert "passwords" not in kw


def test_extra_vars_are_one_argument():
    import shlex

    nasty = "a=1; touch /tmp/pwned $(id) 'q' \"d\""
    kw = _captured_kwargs(extra_vars=nasty)
    assert shlex.split(kw["cmdline"]) == ["--extra-vars=" + nasty], kw["cmdline"]

    # one argument, so ansible cannot read a value that starts with "-" as an option of its own
    kw = _captured_kwargs(extra_vars="-x=1")
    assert shlex.split(kw["cmdline"]) == ["--extra-vars=-x=1"], kw["cmdline"]


def test_password_answers_the_ask_pass_prompt():
    kw = _captured_kwargs(extra_vars="ansible_ssh_user=root", ssh_password=SECRET)
    assert kw["cmdline"].endswith("--ask-pass"), kw["cmdline"]
    assert SECRET not in kw["cmdline"], "the password must not be on the command line"
    ((pattern, answer),) = kw["passwords"].items()
    assert answer == SECRET
    import re

    assert re.search(pattern, "SSH password: ", re.M), "pattern must match ansible's prompt"


def test_real_prompt_gets_password_and_it_is_not_kept():
    bindir = Path(tempfile.mkdtemp(prefix="ulmo-fakebin-"))
    got = bindir / "got.txt"
    fake = bindir / "ansible-playbook"
    fake.write_text(
        "#!/bin/bash\n"
        f'printf "%s\\n" "$*" > {got}\n'
        'case " $* " in *" --ask-pass "*) read -r -s -t 5 -p "SSH password: " pw; echo;\n'
        f'  printf "%s" "$pw" > {got}.pw;; esac\n'
        'echo "PLAY RECAP"\n'
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    old_path = os.environ["PATH"]
    os.environ["PATH"] = f"{bindir}:{old_path}"
    try:
        run_id = _new_run(extra_vars="ansible_ssh_user=root", used_password=True)
        runner._execute(run_id, "fake.yml", extra_vars="ansible_ssh_user=root", ssh_password=SECRET)
    finally:
        os.environ["PATH"] = old_path

    assert got.with_suffix(".txt.pw").read_text() == SECRET, "the prompt did not receive the password"
    assert "--ask-pass" in got.read_text() and "--extra-vars=ansible_ssh_user=root" in got.read_text()

    with Session(engine) as session:
        assert session.get(RunHistory, run_id).status == "success"

    leaked = []
    for root in (Path(DATA_DIR),):
        for path in root.rglob("*"):
            if path.is_file() and SECRET.encode() in path.read_bytes():
                leaked.append(str(path))
    assert not leaked, f"the password was written to disk: {leaked}"

    # A later run with no extras must not replay this run's arguments from a leftover env file.
    got.unlink()
    os.environ["PATH"] = f"{bindir}:{old_path}"
    try:
        runner._execute(_new_run(), "fake.yml")
    finally:
        os.environ["PATH"] = old_path
    again = got.read_text()
    assert "--ask-pass" not in again and "--extra-vars" not in again, f"stale arguments replayed: {again!r}"

    # ...including a leftover file from an older release that wrote them to env/
    env_dir = RUNNER_DATA_DIR / "env"
    env_dir.mkdir(parents=True, exist_ok=True)
    (env_dir / "cmdline").write_text("--ask-pass --extra-vars stale=1")
    (env_dir / "passwords").write_text('{"^SSH password:\\s*?$": "' + SECRET + '"}')
    got.unlink()
    os.environ["PATH"] = f"{bindir}:{old_path}"
    try:
        runner._execute(_new_run(), "fake.yml")
    finally:
        os.environ["PATH"] = old_path
    again = got.read_text()
    assert "--ask-pass" not in again and "stale=1" not in again, f"old env file replayed: {again!r}"
    assert not (env_dir / "cmdline").exists() and not (env_dir / "passwords").exists()

    # a file the operator put there is theirs: ulmo never wrote extravars, settings or ssh_key
    for name in ("extravars", "settings", "ssh_key"):
        (env_dir / name).write_text("{}")
    runner._clear_stale_env_files()
    kept = [name for name in ("extravars", "settings", "ssh_key") if (env_dir / name).exists()]
    assert kept == ["extravars", "settings", "ssh_key"], f"operator-provided env files were deleted: {kept}"
    shutil.rmtree(bindir, ignore_errors=True)


def _run_count() -> int:
    with Session(engine) as session:
        return session.exec(select(func.count()).select_from(RunHistory)).one()


def _row(run_id: int) -> RunHistory:
    with Session(engine) as session:
        return session.get(RunHistory, run_id)


def _stub_execute(seen: list):
    """Replace runner._execute with a stub that records its arguments and frees the workspace lock."""
    real = runner._execute
    done = threading.Event()

    def stub(run_id, *args):
        seen.append(args)
        workspace.end_run(run_id)
        done.set()

    runner._execute = stub
    return real, done


def test_start_run_stores_and_forwards_the_options():
    workspace.store("playbooks/site.yaml", b"- hosts: all\n  tasks: []\n", base=None)
    seen: list = []
    real, done = _stub_execute(seen)
    try:
        record = runner.start_run("playbooks/site.yaml", tags="a", limit="web1", extra_vars="  ansible_ssh_user=root  ", ssh_password=SECRET)
        assert done.wait(5)
        done.clear()
        plain = runner.start_run("playbooks/site.yaml")
        assert done.wait(5)
        before = _run_count()
        for bad in ({"extra_vars": "a=1\nb=2"}, {"extra_vars": "@x.yml"}, {"ssh_password": "x\ny"}):
            try:
                runner.start_run("playbooks/site.yaml", **bad)
            except ValueError:
                pass
            else:
                raise AssertionError(f"start_run accepted {bad!r}")
        assert _run_count() == before, "a refused run must not leave a row behind"
    finally:
        runner._execute = real
    assert seen[0] == ("playbooks/site.yaml", "a", "web1", "ansible_ssh_user=root", SECRET), seen[0]
    assert seen[1] == ("playbooks/site.yaml", "", "", "", ""), seen[1]
    row = _row(record.id)
    assert row.extra_vars == "ansible_ssh_user=root" and row.used_password is True
    assert SECRET not in repr(row.model_dump()), "the password must not be in the row"
    row = _row(plain.id)
    assert row.extra_vars is None and row.used_password is False


def test_route_validates_and_locks_extra_vars_without_a_login():
    seen: list = []
    real, done = _stub_execute(seen)
    form = {"rel_path": "playbooks/site.yaml", "extra_vars": "ansible_ssh_user=root", "ssh_password": SECRET}

    def post(**changes):
        return client.post("/playbooks/run", data={**form, **changes}, follow_redirects=False)

    def error_of(resp) -> str:
        assert resp.status_code == 303 and resp.headers["location"].startswith("/ansible?"), resp.headers
        return parse_qs(urlparse(resp.headers["location"]).query)["error"][0]

    try:
        playbooks_router.AUTH_DISABLED = False
        resp = post()
        assert resp.status_code == 303 and resp.headers["location"].startswith("/runs/"), resp.headers
        assert done.wait(5)
        assert seen[-1][3:] == ("ansible_ssh_user=root", SECRET)

        before = _run_count()
        assert "one line" in error_of(post(extra_vars="a=1\nb=2"))
        assert "cannot load a file" in error_of(post(extra_vars="@/etc/passwd"))
        message = error_of(post(ssh_password="x" * 300))
        assert "password" in message and "x" * 20 not in message
        assert error_of(post(rel_path="playbooks/nope.yaml")).startswith("Unknown playbook")
        assert _run_count() == before, "a refused form must not start a run"

        playbooks_router.AUTH_DISABLED = True  # no login: extra vars could set connection variables, i.e. run code
        assert "ULMO_DISABLE_AUTH" in error_of(post())
        assert _run_count() == before
        done.clear()
        assert post(extra_vars="").headers["location"].startswith("/runs/"), "a password alone is not a way to run code"
        assert done.wait(5) and seen[-1][3:] == ("", SECRET)
    finally:
        runner._execute = real
        playbooks_router.AUTH_DISABLED = False


def test_ansible_page_form():
    real = templates.env.globals["AUTH_DISABLED"]
    try:
        templates.env.globals["AUTH_DISABLED"] = False
        page = client.get("/ansible").text
        assert "Additional options" in page and 'name="extra_vars"' in page and 'name="ssh_password"' in page
        tag = page[page.index('name="extra_vars"'):].split(">", 1)[0]
        assert " disabled" not in tag
        for field in ("extra_vars", "ssh_password"):
            tag = page[page.index(f'name="{field}"'):].split(">", 1)[0]
            assert "preventDefault" in tag, f"Enter in {field} must not submit the form and start a run"
        tag = page[page.index('name="ssh_password"'):].split(">", 1)[0]
        assert 'type="password"' in page[page.index('name="ssh_password"') - 40:page.index('name="ssh_password"')] + tag
        assert 'autocomplete="new-password"' not in tag and 'data-1p-ignore' in tag

        templates.env.globals["AUTH_DISABLED"] = True
        locked = client.get("/ansible").text
        assert " disabled" in locked[locked.index('name="extra_vars"'):].split(">", 1)[0], "extra vars are locked without a login"
        assert " disabled" not in locked[locked.index('name="ssh_password"'):].split(">", 1)[0]
    finally:
        templates.env.globals["AUTH_DISABLED"] = real


def test_the_options_show_wherever_a_run_is_listed():
    with Session(engine) as session:
        both = RunHistory(playbook="playbooks/site.yaml", status="failed", extra_vars="ansible_ssh_user=root", used_password=True)
        none = RunHistory(playbook="playbooks/other.yaml", status="success")
        session.add(both)
        session.add(none)
        session.commit()
        session.refresh(both)
        session.refresh(none)

    page = client.get(f"/runs/{both.id}").text
    assert "extra vars: <code>ansible_ssh_user=root</code>" in page and "SSH password: supplied for this run (not stored)" in page
    page = client.get(f"/runs/{none.id}").text
    assert "extra vars:" not in page and "SSH password:" not in page

    for url in ("/", "/activity", "/activity?tab=playbooks"):
        page = client.get(url).text
        assert "extra vars · SSH password" in page, f"{url} does not say the run had extra vars and a password"
        assert "ansible_ssh_user=root" not in page, f"{url} must not print the extra vars themselves"

    sent: list = []
    real_post = notifier._post
    notifier._post = lambda url, data, name, headers=None: sent.append(data.decode())
    settings_store.set_many({"notify_on": "all", "notify_ntfy_url": "http://ntfy.invalid/ulmo"})
    try:
        notifier.notify_run_complete(_row(both.id))
        notifier.notify_run_complete(_row(none.id))
    finally:
        notifier._post = real_post
        settings_store.set_many({"notify_on": "", "notify_ntfy_url": ""})
    assert sent[0] == "ulmo: playbooks/site.yaml FAILED (extra vars, SSH password)", sent[0]
    assert sent[1] == "ulmo: playbooks/other.yaml succeeded", sent[1]


def main():
    init_db()
    RUNNER_DATA_DIR.mkdir(parents=True, exist_ok=True)
    test_check_rejects_bad_input()
    test_check_accepts_normal_input()
    test_no_extras_changes_nothing()
    test_extra_vars_only_never_asks_for_a_password()
    test_extra_vars_are_one_argument()
    test_password_answers_the_ask_pass_prompt()
    test_real_prompt_gets_password_and_it_is_not_kept()
    test_start_run_stores_and_forwards_the_options()
    test_route_validates_and_locks_extra_vars_without_a_login()
    test_ansible_page_form()
    test_the_options_show_wherever_a_run_is_listed()
    print("OK: per-run extra vars and SSH password reach ansible-playbook and are not kept.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
