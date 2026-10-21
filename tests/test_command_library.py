"""Self-check for the command library (app/services/command_library.py) and the
Commands page.

  1. Commands are validated strictly: every malformed shape is rejected with a
     reason, parameter values are checked by type, can never become shell syntax
     or an extra option, and a regex gets a short time budget so a slow one cannot stall ulmo.
  2. Hosts are validated (address, port, user, key name, offered commands), and a
     host can only offer commands that exist.
  3. The file is changed only by validated, whole-file read-modify-write: the old
     copy goes to history (bounded by a setting), the new one is swapped in
     atomically, a stale editor is refused, and restore works.
  4. A hand edit that no longer parses keeps the last good library in service.
  5. The Commands page edits commands and hosts, previews without running
     anything, refuses unsafe deletes, tests connections, audits every change,
     and is locked while ULMO_DISABLE_AUTH is set.

Run directly: python3 tests/test_command_library.py
"""
import os
import shlex
import shutil
import sys
import tempfile
import time
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
from app.models import AdminAudit  # noqa: E402
from app.routers import command_admin  # noqa: E402
from app.services import agents, command_library as cl, commands, settings_store  # noqa: E402

SSH_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
for key in ("unraid-key", "ansible-ed25519"):
    (SSH_STORAGE_DIR / key).write_text("not a real key")

client = TestClient(app)
admin = TestClient(app)

RESTART = {
    "description": "Restart a Docker container",
    "argv": ["docker", "restart", "{container}"],
    "params": {"container": {"type": "enum", "values": ["sonarr", "radarr"]}},
    "risk": "medium",
}
LOGS = {
    "description": "Show container logs",
    "argv": ["docker", "logs", "--tail={n}", "{container}"],
    "params": {"n": {"type": "int", "min": 1, "max": 500}, "container": {"type": "regex", "pattern": "[a-z0-9_-]+", "max_length": 40}},
}
SAY = {"description": "Echo", "argv": ["echo", "{text}"], "params": {"text": {"type": "regex", "pattern": ".+", "max_length": 100}}}
GANDALF = {"address": "10.42.11.10", "port": 22, "user": "root", "ssh_key": "unraid-key", "commands": ["restart"]}


def _reset():
    """Empty library, no history."""
    cl.LIBRARY_PATH.unlink(missing_ok=True)
    shutil.rmtree(cl.HISTORY_DIR, ignore_errors=True)
    cl._state.update(fingerprint=None, library=cl.Library(), error="")


def _write(data):
    cl.LIBRARY_PATH.write_text(yaml.safe_dump(data, sort_keys=False))


def _raises(fn, *args, contains=""):
    try:
        fn(*args)
    except ValueError as exc:
        assert contains in str(exc), f"{contains!r} not in {exc}"
        return
    raise AssertionError(f"accepted: {args}")


# --- commands ------------------------------------------------------------------------


def test_commands_are_validated_strictly():
    assert cl.parse_command("restart", RESTART).risk == "medium"
    assert cl.parse_command("logs", LOGS).timeout == 30

    base = {"description": "d", "argv": ["echo", "hi"]}
    cases = [
        (["not", "a", "mapping"], "not a mapping"),
        ({**base, "surprise": 1}, "unknown key"),
        ({"argv": ["echo"]}, "description required"),
        ({"description": "d", "argv": []}, "empty argv"),
        ({"description": "d", "argv": "echo hi"}, "argv as a string"),
        ({"description": "d", "argv": ["echo", 5]}, "non-string token"),
        ({"description": "d", "argv": ["{cmd}", "x"], "params": {"cmd": {"type": "enum", "values": ["a"]}}}, "placeholder as the command"),
        ({"description": "d", "argv": ["echo", "{x"]}, "stray brace"),
        ({"description": "d", "argv": ["echo", "}{"]}, "stray brace 2"),
        ({"description": "d", "argv": ["echo", "{undeclared}"]}, "undeclared param"),
        ({"description": "d", "argv": ["echo"], "params": {"x": {"type": "enum", "values": ["a"]}}}, "unused param"),
        ({"description": "d", "argv": ["echo", "{x}"], "params": {"x": {"type": "nope"}}}, "unknown type"),
        ({"description": "d", "argv": ["echo", "{x}"], "params": {"x": {"type": "enum", "values": []}}}, "empty enum"),
        ({"description": "d", "argv": ["echo", "{x}"], "params": {"x": {"type": "enum", "values": ["a", "a"]}}}, "duplicate enum"),
        ({"description": "d", "argv": ["echo", "{x}"], "params": {"x": {"type": "enum", "values": ["a"], "extra": 1}}}, "unknown param key"),
        ({"description": "d", "argv": ["echo", "{x}"], "params": {"x": {"type": "int", "min": 1}}}, "int without max"),
        ({"description": "d", "argv": ["echo", "{x}"], "params": {"x": {"type": "int", "min": 5, "max": 1}}}, "min > max"),
        ({"description": "d", "argv": ["echo", "{x}"], "params": {"x": {"type": "int", "min": True, "max": 3}}}, "bool bound"),
        ({"description": "d", "argv": ["echo", "{x}"], "params": {"x": {"type": "regex"}}}, "regex without pattern"),
        ({"description": "d", "argv": ["echo", "{x}"], "params": {"x": {"type": "regex", "pattern": "["}}}, "bad regex"),
        ({"description": "d", "argv": ["echo", "{x}"], "params": {"x": {"type": "regex", "pattern": "a", "max_length": 9999}}}, "huge max_length"),
        ({**base, "timeout": 0}, "timeout 0"),
        ({**base, "timeout": 301}, "timeout too big"),
        ({**base, "timeout": True}, "timeout bool"),
        ({**base, "sudo": "yes please"}, "sudo not bool"),
        ({**base, "risk": "extreme"}, "bad risk"),
        ({**base, "ssh_user": "x"}, "ssh_user is no longer a command key"),
    ]
    for data, why in cases:
        try:
            cl.parse_command("t", data)
        except ValueError:
            continue
        raise AssertionError(f"command accepted: {why}")
    _raises(cl.parse_command, "bad name!", base, contains="command name")
    _raises(cl.parse_command_text, "t", "{not: [valid", contains="YAML")
    _raises(cl.parse_command_text, "t", "description: " + "x" * 30000, contains="limited")


def test_parameter_validation():
    logs = cl.parse_command("logs", LOGS)
    assert cl.validate_params(logs, {"n": 50, "container": "sonarr"}) == {"n": "50", "container": "sonarr"}
    for params, contains in [
        ({"n": 50}, "missing parameters: container"),
        ({"n": 50, "container": "a", "extra": 1}, "unknown parameters: extra"),
        ({"n": "50", "container": "a"}, "whole number"),
        ({"n": True, "container": "a"}, "whole number"),
        ({"n": 50.0, "container": "a"}, "whole number"),
        ({"n": 0, "container": "a"}, "from 1 to 500"),
        ({"n": 501, "container": "a"}, "from 1 to 500"),
        ({"n": 5, "container": ""}, "non-empty"),
        ({"n": 5, "container": 7}, "non-empty"),
        ({"n": 5, "container": "x" * 41}, "at most 40"),
        ({"n": 5, "container": "UPPER"}, "pattern"),
        ({"n": 5, "container": "a b"}, "pattern"),
        ({"n": 5, "container": "a;b"}, "pattern"),
        ({"n": 5, "container": "a\n"}, "pattern"),
        ({"n": 5, "container": "-rf"}, "may not start with '-'"),
        ({"n": 5, "container": "ok!"}, "pattern"),
    ]:
        _raises(cl.validate_params, logs, params, contains=contains)
    _raises(cl.validate_params, logs, ["not", "a", "dict"], contains="object")

    restart = cl.parse_command("restart", RESTART)
    assert cl.validate_params(restart, {"container": "radarr"}) == {"container": "radarr"}
    for bad in ("plex", "sonarr ", ["sonarr"], None, 1):
        _raises(cl.validate_params, restart, {"container": bad}, contains="one of")
    numeric = cl.parse_command("n", {"description": "d", "argv": ["echo", "{x}"], "params": {"x": {"type": "enum", "values": ["1", "2"]}}})
    assert cl.validate_params(numeric, {"x": "1"}) == {"x": "1"}
    for wrong in (1, 1.0, True, ["1"]):
        _raises(cl.validate_params, numeric, {"x": wrong}, contains="one of")

    say = cl.parse_command("say", SAY)
    _raises(cl.validate_params, say, {"text": "--privileged"}, contains="may not start with '-'")
    _raises(cl.validate_params, say, {"text": "bad\nline"}, contains="pattern")
    dash_ok = cl.parse_command("d", {"description": "d", "argv": ["echo", "{t}"], "params": {"t": {"type": "regex", "pattern": ".+", "allow_leading_dash": True}}})
    assert cl.validate_params(dash_ok, {"t": "-n"}) == {"t": "-n"}


def test_values_stay_one_literal_argument():
    say = cl.parse_command("say", SAY)
    for value in ["; rm -rf /", "$(id)", "`id`", "a && b", "x | y", "it's", 'say "hi"', "a\\b", "*", "~", "a b  c", "${HOME}", "#comment", "é ü 日本"]:
        argv = cl.build_argv(say, cl.validate_params(say, {"text": value}))
        assert argv == ["echo", value], argv
        assert shlex.split(shlex.join(argv)) == argv, f"{value!r} does not survive quoting"
    logs = cl.parse_command("logs", LOGS)
    assert cl.build_argv(logs, cl.validate_params(logs, {"n": 7, "container": "plex"})) == ["docker", "logs", "--tail=7", "plex"]
    sudo = cl.parse_command("s", {"description": "d", "argv": ["systemctl", "status", "{u}"], "sudo": True, "params": {"u": {"type": "enum", "values": ["ssh"]}}})
    assert cl.build_argv(sudo, {"u": "ssh"}) == ["sudo", "-n", "systemctl", "status", "ssh"]

    # The Preview box: name=value lines, typed by the parameter.
    assert cl.sample_values(logs, "n=5\ncontainer=plex\n") == {"n": 5, "container": "plex"}
    assert cl.sample_values(logs, "n=abc\ncontainer=x")["n"] == "abc"  # not a number: validate_params will say so
    _raises(cl.sample_values, logs, "no equals sign", contains="name=value")


def test_regex_parameters_are_checked_and_time_limited():
    base = {"description": "d", "argv": ["echo", "{x}"]}
    for good in ("[a-z0-9_-]+", "(foo|bar)+", "a?b*c+", "(ab?)+", ".+", "[a-z]+(\\.[a-z]+)?"):
        cl.parse_command("t", {**base, "params": {"x": {"type": "regex", "pattern": good}}})
    for bad in ("[", "(unclosed", "*start", "a{2,1}"):
        _raises(cl.parse_command, "t", {**base, "params": {"x": {"type": "regex", "pattern": bad}}}, contains="bad pattern")

    # Patterns that can backtrack exponentially are saved (no guessing about shapes), but every
    # match has a time budget, so the slow value is rejected instead of stalling ulmo.
    # (The engine happens to dodge some classic shapes; whatever it does, the call must end quickly.)
    for pattern, value in [("(a+)+$", "a" * 80 + "b"), ("([a-z]+)*x", "a" * 80), ("(a|aa)+$", "a" * 150 + "b"),
                           ("(a?a?)+$", "a" * 80 + "b"), ("(x|xy)*z$", "xy" * 60 + "b")]:
        tricky = cl.parse_command("t", {**base, "params": {"x": {"type": "regex", "pattern": pattern, "max_length": 200}}})
        start = time.time()
        _raises(cl.validate_params, tricky, {"x": value})
        assert time.time() - start < 3, f"{pattern}: the match must be abandoned, not run to completion"
    slow = cl.parse_command("t", {**base, "params": {"x": {"type": "regex", "pattern": "(a|aa)+$", "max_length": 200}}})
    _raises(cl.validate_params, slow, {"x": "a" * 150 + "b"}, contains="too slow")
    ok = cl.parse_command("t", {**base, "params": {"x": {"type": "regex", "pattern": "(a|aa)+$", "max_length": 200}}})
    assert cl.validate_params(ok, {"x": "aaaa"}) == {"x": "aaaa"}, "ordinary values still pass"


# --- hosts -----------------------------------------------------------------------------


def test_hosts_are_validated():
    names = {"restart"}
    h = cl.parse_host("gandalf", GANDALF, names)
    assert (h.address, h.port, h.user, h.ssh_key, h.commands) == ("10.42.11.10", 22, "root", "unraid-key", ["restart"])
    assert cl.parse_host("bare", {"address": "frodo.lan", "user": "ansible"}, names).port == 22

    good = {"address": "10.0.0.1", "user": "ansible"}
    for data, contains in [
        ({**good, "address": "-oProxyCommand=x"}, "address"),
        ({**good, "address": "a b"}, "address"),
        ({**good, "address": "a;id"}, "address"),
        ({**good, "address": "{{ lookup('pipe','id') }}"}, "address"),
        ({**good, "address": ""}, "address"),
        ({**good, "address": None}, "address"),
        ({**good, "port": 0}, "port"),
        ({**good, "port": 70000}, "port"),
        ({**good, "port": "22"}, "port"),
        ({**good, "port": True}, "port"),
        ({**good, "user": "Root"}, "user"),
        ({**good, "user": "a b"}, "user"),
        ({**good, "user": ""}, "user"),
        ({"address": "x"}, "user"),
        ({**good, "ssh_key": "../k"}, "ssh_key"),
        ({**good, "ssh_key": "a/b"}, "ssh_key"),
        ({**good, "ssh_key": ".."}, "ssh_key"),
        ({**good, "commands": "restart"}, "commands"),
        ({**good, "commands": ["restart", "restart"]}, "unique"),
        ({**good, "commands": ["ghost"]}, "do not exist"),
        ({**good, "extra": 1}, "unknown keys"),
        (["x"], "mapping"),
    ]:
        _raises(cl.parse_host, "h", data, names, contains=contains)
    _raises(cl.parse_host, "bad name!", good, names, contains="host name")


# --- the file ------------------------------------------------------------------------------


def test_file_changes_are_whole_file_validated_and_versioned():
    _reset()
    library, error = cl.load()
    assert not library.commands and not library.hosts and error == ""

    cl.save_command("restart", RESTART)
    cl.save_host("gandalf", GANDALF)
    library, error = cl.load()
    assert set(library.commands) == {"restart"} and set(library.hosts) == {"gandalf"} and not error
    assert library.hosts_offering("restart") == ["gandalf"]

    # Cross references are checked on every change.
    _raises(cl.save_host, "frodo", {"address": "10.0.0.2", "user": "ansible", "commands": ["ghost"]}, contains="do not exist")
    _raises(cl.save_command, "bad", {"description": "d", "argv": []}, contains="command bad")
    assert set(cl.load()[0].hosts) == {"gandalf"}, "a rejected change must not be written"
    _raises(cl.delete_command, "restart", contains="Remove it from those hosts first")
    _raises(cl.delete_command, "restart", contains="gandalf")
    cl.save_host("gandalf", {**GANDALF, "commands": []})
    cl.delete_command("restart")
    assert not cl.load()[0].commands
    _raises(cl.delete_command, "restart", contains="no such command")
    _raises(cl.delete_host, "nope", contains="no such host")

    # History: every change keeps the previous copy; the number is a setting.
    assert len(cl.list_versions()) >= 3
    settings_store.set_many({"command_history_keep": "2"})
    try:
        for i in range(5):
            cl.save_command(f"c{i}", {"description": f"n{i}", "argv": ["uptime"]})
        assert len(cl.list_versions()) == 2, cl.list_versions()
    finally:
        settings_store.set_many({"command_history_keep": "20"})

    # The write is atomic: no temp files left, and the file always parses.
    assert not list(cl.LIBRARY_PATH.parent.glob(".commands-*.tmp"))
    assert yaml.safe_load(cl.LIBRARY_PATH.read_text())["commands"]["c4"]["description"] == "n4"

    # Restore brings an old copy back as a new version.
    old = cl.list_versions()[-1]["id"]
    before = cl.current_version()
    cl.restore(old)
    assert cl.current_version() != before
    assert cl.list_versions(), "the copy replaced by a restore is kept too"
    _raises(cl.restore, "../../etc/passwd", contains="unknown version")
    _raises(cl.restore, "20990101T000000000000Z", contains="unknown version")
    _raises(cl.version_text, "..%2f..%2fetc", contains="unknown version")
    assert cl.LIBRARY_PATH.is_file()
    for sneaky in ("../commands", "../../commands", "../commands.history/" + cl.list_versions()[0]["id"], "/etc/hostname", cl.list_versions()[0]["id"] + "/../.."):
        _raises(cl.version_text, sneaky, contains="unknown version")
        _raises(cl.restore, sneaky, contains="unknown version")
    assert cl.version_text(cl.list_versions()[0]["id"]), "a real version still reads"


def test_stale_editor_is_refused():
    _reset()
    cl.save_command("restart", RESTART)
    opened = cl.current_version()
    cl.save_command("logs", LOGS)  # someone else saves
    for change in (
        lambda: cl.save_command("restart", {**RESTART, "description": "mine"}, opened),
        lambda: cl.save_host("gandalf", GANDALF, opened),
        lambda: cl.delete_command("logs", opened),
        lambda: cl.restore(cl.list_versions()[0]["id"], opened),
    ):
        try:
            change()
        except cl.Conflict:
            continue
        raise AssertionError("a stale editor was allowed to save")
    assert cl.load()[0].commands["restart"].description == "Restart a Docker container"
    cl.save_command("restart", {**RESTART, "description": "fresh"}, cl.current_version())
    assert cl.load()[0].commands["restart"].description == "fresh"


def test_hand_edits_that_break_keep_the_last_good_library():
    _reset()
    cl.save_command("restart", RESTART)
    cl.save_host("gandalf", GANDALF)
    assert not cl.load()[1]  # the service has seen (and so remembers) a good library
    good = cl.LIBRARY_PATH.read_text()

    cl.LIBRARY_PATH.write_text(good + "\nhosts: [broken\n")  # not YAML
    library, error = cl.load()
    assert "restart" in library.commands and "gandalf" in library.hosts and error
    cl.LIBRARY_PATH.write_text("commands:\n  x: {description: d, argv: []}\n")  # parses, invalid
    library, error = cl.load()
    assert "gandalf" in library.hosts and "command x" in error
    cl.LIBRARY_PATH.write_text("commands: {}\nhosts: {}\nsurprise: 1\n")
    assert "gandalf" in cl.load()[0].hosts and cl.load()[1]
    cl.LIBRARY_PATH.write_text("x" * (cl.MAX_FILE_BYTES + 10))
    assert "gandalf" in cl.load()[0].hosts and "over" in cl.load()[1]

    cl.LIBRARY_PATH.write_text(good.replace("Restart a Docker container", "Edited by hand"))
    library, error = cl.load()
    assert not error and library.commands["restart"].description == "Edited by hand"

    # The UI will not write on top of a file it cannot read.
    cl.LIBRARY_PATH.write_text("- just\n- a list\n")
    _raises(cl.save_command, "x", {"description": "d", "argv": ["uptime"]}, contains="not a mapping")


def test_roles_lose_commands_that_leave_the_library():
    _reset()
    cl.save_command("restart", RESTART)
    cl.save_command("logs", LOGS)
    cl.load()
    role = agents.create_role("purge-role")
    agents.set_role_commands(role.id, ["restart", "logs"])
    good = cl.LIBRARY_PATH.read_text()

    # A broken file removes nothing: the role keeps its entries until a file that parses says otherwise.
    cl.LIBRARY_PATH.write_text("commands: [broken\n")
    cl.load()
    assert agents.role_commands(role.id) == ["logs", "restart"]

    # A restore that drops a command (or a hand edit) takes it out of the role...
    cl.LIBRARY_PATH.write_text(good.replace("restart:", "restart2:", 1))
    cl.load()
    assert agents.role_commands(role.id) == ["logs"]
    # ...so a command that later gets the old name is not inherited.
    cl.LIBRARY_PATH.write_text(good)
    cl.load()
    assert agents.role_commands(role.id) == ["logs"], "the role must not get 'restart' back by itself"

    cl.save_command("restart3", RESTART)
    cl.delete_command("restart3")
    cl.restore(cl.list_versions()[-1]["id"])
    assert set(cl.load()[0].commands) <= {"restart", "logs", "restart3"}


def test_saves_are_durable_and_the_log_says_what_changed():
    _reset()
    calls = []
    real = os.fsync
    os.fsync = lambda fd: (calls.append(fd), real(fd))[1]
    try:
        cl.save_command("restart", RESTART)
    finally:
        os.fsync = real
    assert len(calls) >= 2, "the new file and its directory must both be flushed"

    text = yaml.safe_dump({**RESTART, "sudo": True, "timeout": 60}, sort_keys=False)
    r = _form(admin, "/commands/save", name="restart", text=text, base=cl.current_version())
    assert r.status_code == 303
    with Session(engine) as session:
        detail = [a.detail for a in session.exec(select(AdminAudit).where(AdminAudit.action == "save command")).all()][-1]
    assert "docker restart" in detail and "{container}" in detail and "sudo" in detail and "timeout 60s" in detail and "container" in detail, detail


def test_preview_shows_what_the_host_receives():
    text = yaml.safe_dump(RESTART, sort_keys=False)
    r = _form(admin, "/commands/preview", name="restart", text=text, samples="container=sonarr")
    assert "timeout -k 5 30 docker restart sonarr" in r.text, "the host-side timeout wrapper must be visible"
    sudo = yaml.safe_dump({**RESTART, "sudo": True, "timeout": 7}, sort_keys=False)
    r = _form(admin, "/commands/preview", name="restart", text=sudo, samples="container=sonarr")
    assert "timeout -k 5 7 sudo -n docker restart sonarr" in r.text


def test_restore_recovers_from_an_unreadable_file():
    _reset()
    cl.save_command("restart", RESTART)
    cl.save_command("logs", LOGS)
    cl.load()
    keep = cl.list_versions()[0]["id"]
    cl.LIBRARY_PATH.write_text("- just\n- a list\n")  # nothing else can write over this
    _raises(cl.save_command, "x", {"description": "d", "argv": ["uptime"]}, contains="not a mapping")
    stale = cl.current_version()
    cl.LIBRARY_PATH.write_text("- still\n- not valid\n")
    try:
        cl.restore(keep, stale)
    except cl.Conflict:
        pass
    else:
        raise AssertionError("restore ignored a stale editor")
    cl.restore(keep, cl.current_version())
    assert "restart" in cl.load()[0].commands and not cl.load()[1]


def test_saved_copies_have_readable_times():
    _reset()
    cl.save_command("restart", RESTART)
    cl.save_command("logs", LOGS)
    versions = cl.list_versions()
    assert versions and versions[0]["at"].tzinfo is not None and versions[0]["at"].year >= 2026
    page = admin.get("/commands").text
    assert '<time class="local-time"' in page.split("Saved copies")[1], "times go through the local_time filter"


# --- the page ---------------------------------------------------------------------------------


def _form(client_, url, **data):
    return client_.post(url, data=data, follow_redirects=False)


def test_commands_page():
    _reset()
    page = admin.get("/commands")
    assert page.status_code == 200 and "No hosts yet" in page.text and "No commands yet" in page.text

    # New command: starter text, then save.
    r = admin.get("/commands/edit")
    assert r.status_code == 200 and "description:" in r.text and "uptime" in r.text
    base = cl.current_version()
    text = yaml.safe_dump(RESTART, sort_keys=False)
    r = _form(admin, "/commands/save", name="restart", text=text, base=base, is_new="1")
    assert r.status_code == 303 and "restart" in cl.load()[0].commands

    # The saved command opens for editing, and changes round-trip.
    r = admin.get("/commands/edit?name=restart")
    assert r.status_code == 200 and "docker" in r.text and "readonly" in r.text
    assert admin.get("/commands/edit?name=ghost").status_code == 400

    # Errors keep the text and say why; nothing is written.
    bad = text.replace("{container}", "{nope}")
    r = _form(admin, "/commands/save", name="restart", text=bad, base=cl.current_version())
    assert r.status_code == 400 and "undeclared parameters: nope" in r.text and "{nope}" in r.text
    assert cl.load()[0].commands["restart"].argv == ["docker", "restart", "{container}"]
    r = _form(admin, "/commands/save", name="restart", text=text, base=cl.current_version(), is_new="1")
    assert r.status_code == 400 and "already exists" in r.text
    r = _form(admin, "/commands/save", name="restart", text=text, base="stale")
    assert r.status_code == 400 and "changed since" in r.text

    # Preview runs nothing and shows exactly what an agent's call would produce.
    r = _form(admin, "/commands/preview", name="restart", text=text, samples="container=sonarr")
    assert r.status_code == 200 and "docker restart sonarr" in r.text
    r = _form(admin, "/commands/preview", name="restart", text=text, samples="container=plex")
    assert "one of: sonarr, radarr" in r.text
    r = _form(admin, "/commands/preview", name="restart", text="description: x\nargv: []\n", samples="")
    assert "argv must be" in r.text
    sneaky = yaml.safe_dump(SAY, sort_keys=False)
    r = _form(admin, "/commands/preview", name="say", text=sneaky, samples="text=x; $(id)")
    assert "echo 'x; $(id)'" in r.text.replace("&#39;", "'")

    # Hosts.
    base = cl.current_version()
    r = _form(admin, "/commands/hosts", name="gandalf", address="10.42.11.10", port="22", user="root", ssh_key="unraid-key", commands="restart", original="", base=base)
    assert r.status_code == 303
    host = cl.load()[0].hosts["gandalf"]
    assert (host.user, host.ssh_key, host.commands) == ("root", "unraid-key", ["restart"])
    page = admin.get("/commands")
    assert "root@10.42.11.10:22" in page.text and "unraid-key" in page.text
    edit = admin.get("/commands?host=gandalf")
    assert "Edit host gandalf" in edit.text and "10.42.11.10" in edit.text

    for kwargs, contains in [
        (dict(name="gandalf", address="x", port="22", user="root", original=""), "already exists"),
        (dict(name="renamed", address="x", port="22", user="root", original="gandalf"), "cannot be renamed"),
        (dict(name="h", address="-oProxy", port="22", user="root", original=""), "address"),
        (dict(name="h", address="a", port="99999", user="root", original=""), "port"),
        (dict(name="h", address="a", port="abc", user="root", original=""), "port"),
        (dict(name="h", address="a", port="22", user="", original=""), "user"),
        (dict(name="h", address="a", port="22", user="root", commands="ghost", original=""), "do not exist"),
        (dict(name="h", address="a", port="22", user="root", ssh_key="../k", original=""), "ssh_key"),
    ]:
        r = _form(admin, "/commands/hosts", base=cl.current_version(), **kwargs)
        assert r.status_code == 400 and contains in r.text, (kwargs, r.status_code, contains)
    assert set(cl.load()[0].hosts) == {"gandalf"}

    # Editing a host keeps its place; a command cannot be deleted while a host offers it.
    r = _form(admin, "/commands/hosts", name="gandalf", address="10.42.11.11", port="2222", user="root", ssh_key="unraid-key", commands="restart", original="gandalf", base=cl.current_version())
    assert r.status_code == 303 and cl.load()[0].hosts["gandalf"].port == 2222
    r = _form(admin, "/commands/restart/delete")
    assert r.status_code == 400 and "gandalf" in r.text and "restart" in cl.load()[0].commands

    # Test connection.
    seen = []
    real = commands.probe
    commands.probe = lambda host: (seen.append(host.name) or True, "ulmo-ok")
    try:
        r = _form(admin, "/commands/hosts/gandalf/test")
        assert r.status_code == 200 and "connection works" in r.text and seen == ["gandalf"]
        commands.probe = lambda host: (False, "Permission denied (publickey).")
        r = _form(admin, "/commands/hosts/gandalf/test")
        assert "Permission denied" in r.text
        assert _form(admin, "/commands/hosts/ghost/test").status_code == 400
    finally:
        commands.probe = real

    # Download and history.
    r = admin.get("/commands/download")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"] and "gandalf" in r.text
    versions = cl.list_versions()
    assert versions
    assert admin.get(f"/commands/history/{versions[0]['id']}").status_code in (404, 405), "no per-copy download route"
    before = cl.current_version()
    r = _form(admin, f"/commands/history/{versions[-1]['id']}/restore", base=before)
    assert r.status_code == 303 and cl.current_version() != before
    r = _form(admin, f"/commands/history/{versions[-1]['id']}/restore", base="stale")
    assert r.status_code == 400 and "changed since" in r.text

    # Hosts and commands can be deleted once nothing depends on them, and a deleted
    # command leaves every role (a new command with the same name is not inherited).
    role = agents.create_role("lib-role")
    agents.set_role_commands(role.id, ["restart"])
    cl.save_host("gandalf", {**GANDALF, "commands": []})
    assert _form(admin, "/commands/restart/delete").status_code == 303
    assert agents.role_commands(role.id) == []
    assert _form(admin, "/commands/hosts/gandalf/delete").status_code == 303
    assert not cl.load()[0].hosts and not cl.load()[0].commands

    with Session(engine) as session:
        actions = {a.action for a in session.exec(select(AdminAudit)).all()}
    for expected in ("save command", "save host", "delete command", "delete host", "test host", "restore command library"):
        assert expected in actions, f"{expected!r} not audited: {actions}"


def test_page_is_admin_only_and_locked_without_login():
    _reset()
    cl.save_command("restart", RESTART)
    cl.save_host("gandalf", {**GANDALF, "commands": []})
    _, token = agents.create_agent("cmd-visitor")
    h = {"Authorization": f"Bearer {token}"}
    text = yaml.safe_dump(SAY, sort_keys=False)
    for method, url, data in [
        ("get", "/commands", None), ("get", "/commands/edit", None), ("post", "/commands/save", {"name": "x", "text": text}),
        ("post", "/commands/restart/delete", {}), ("post", "/commands/hosts", {"name": "h", "address": "a", "user": "root"}),
        ("post", "/commands/hosts/gandalf/delete", {}), ("post", "/commands/hosts/gandalf/test", {}),
        ("get", "/commands/download", None), ("post", "/commands/history/x/restore", {}),
    ]:
        r = getattr(client, method)(url, headers=h, **({"data": data} if data is not None else {}), follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login", f"{url}: {r.status_code}"
    assert "x" not in cl.load()[0].commands and "h" not in cl.load()[0].hosts

    command_admin.AUTH_DISABLED = True
    try:
        base = cl.current_version()
        for r in (
            _form(admin, "/commands/save", name="x", text=text, base=base, is_new="1"),
            _form(admin, "/commands/restart/delete"),
            _form(admin, "/commands/hosts", name="h", address="a", port="22", user="root", original="", base=base),
            _form(admin, "/commands/hosts/gandalf/delete"),
            _form(admin, "/commands/hosts/gandalf/test"),
            _form(admin, f"/commands/history/{(cl.list_versions() or [{'id': 'x'}])[0]['id']}/restore", base=base),
        ):
            assert r.status_code == 400 and "ULMO_DISABLE_AUTH" in r.text, r.text[:200]
    finally:
        command_admin.AUTH_DISABLED = False
    assert cl.current_version() == base, "nothing may change while login is disabled"


def test_history_setting():
    r = admin.post("/settings", data={"git_repo_url": "", "git_branch": "main", "playbooks_subdir": "playbooks", "inventory_path": "inventory.yaml",
                                      "requirements_path": "", "git_sync_cron": "", "extra_args": "", "recent_runs_count": "5",
                                      "run_timeout_minutes": "60", "command_history_keep": "7"}, follow_redirects=False)
    assert r.status_code == 303 and settings_store.get("command_history_keep") == "7"
    for bad in ("0", "501", "abc", "-3", "2.5"):
        r = admin.post("/settings", data={"git_repo_url": "", "git_branch": "main", "playbooks_subdir": "playbooks", "inventory_path": "inventory.yaml",
                                          "requirements_path": "", "git_sync_cron": "", "extra_args": "", "recent_runs_count": "5",
                                          "run_timeout_minutes": "60", "command_history_keep": bad}, follow_redirects=False)
        assert "error=" in r.headers["location"] and settings_store.get("command_history_keep") == "7", bad
    settings_store.set_many({"command_history_keep": "20"})
    assert "command_history_keep" in settings_store.export_yaml()


def main():
    init_db()
    auth_module.create_user("admin", "pw-for-tests")
    r = admin.post("/login", data={"username": "admin", "password": "pw-for-tests"}, follow_redirects=False)
    assert r.status_code == 303 and admin.get("/commands").status_code == 200, "test login failed"
    test_commands_are_validated_strictly()
    test_parameter_validation()
    test_values_stay_one_literal_argument()
    test_regex_parameters_are_checked_and_time_limited()
    test_hosts_are_validated()
    test_file_changes_are_whole_file_validated_and_versioned()
    test_stale_editor_is_refused()
    test_hand_edits_that_break_keep_the_last_good_library()
    test_roles_lose_commands_that_leave_the_library()
    test_saves_are_durable_and_the_log_says_what_changed()
    test_restore_recovers_from_an_unreadable_file()
    test_saved_copies_have_readable_times()
    test_commands_page()
    test_preview_shows_what_the_host_receives()
    test_page_is_admin_only_and_locked_without_login()
    test_history_setting()
    print("OK: the command library validates strictly, versions every change, and is edited safely from the Commands page.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
