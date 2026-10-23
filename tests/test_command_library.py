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


def test_optional_parameters():
    ps = cl.parse_command("ps", {
        "description": "d", "argv": ["docker", "ps", "-a", "--filter={f}"],
        "params": {"f": {"type": "regex", "pattern": "(id|name)=[a-z0-9]+", "max_length": 40, "optional": True}},
    })
    assert ps.params["f"]["optional"] is True
    assert cl.validate_params(ps, {}) == {}, "left out is fine"
    assert cl.build_argv(ps, {}) == ["docker", "ps", "-a"], "the element holding the placeholder is dropped"
    values = cl.validate_params(ps, {"f": "id=ab12"})
    assert cl.build_argv(ps, values) == ["docker", "ps", "-a", "--filter=id=ab12"]
    for bad in ("id=AB", "x=1", "id=a b", "", 5, "id=" + "a" * 40):  # a supplied value is checked like a required one
        _raises(cl.validate_params, ps, {"f": bad})
    _raises(cl.validate_params, ps, {"g": "x"}, contains="unknown parameters")

    # Required ones stay required next to an optional one; a mixed element goes when the optional part is absent.
    mixed = cl.parse_command("m", {
        "description": "d", "argv": ["echo", "{a}", "{b}", "{a}-{b}"],
        "params": {"a": {"type": "enum", "values": ["x"]}, "b": {"type": "enum", "values": ["y"], "optional": True}},
    })
    _raises(cl.validate_params, mixed, {}, contains="missing parameters: a")
    assert cl.build_argv(mixed, cl.validate_params(mixed, {"a": "x"})) == ["echo", "x"]
    assert cl.build_argv(mixed, cl.validate_params(mixed, {"a": "x", "b": "y"})) == ["echo", "x", "y", "x-y"]
    assert "optional" not in cl.parse_command("restart", RESTART).params["container"], "required params look as before"
    _raises(cl.parse_command, "bad", {"description": "d", "argv": ["echo", "{a}"], "params": {"a": {"type": "enum", "values": ["x"], "optional": "yes"}}}, contains="optional must be true or false")
    sudo = cl.parse_command("s", {"description": "d", "argv": ["ls", "{p}"], "sudo": True, "params": {"p": {"type": "enum", "values": ["/"], "optional": True}}})
    assert cl.build_argv(sudo, {}) == ["sudo", "-n", "ls"]

    # The Preview box: leave the line out to see the command without it.
    assert cl.sample_values(ps, "") == {} and cl.sample_values(ps, "f=name=plex") == {"f": "name=plex"}


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


def test_yaml_keeps_the_way_you_write_it():
    _reset()
    text = "description: Disk usage\nrisk: low\nargv: [df, -h]\nparams: {}\n"
    base = cl.current_version()
    assert _form(admin, "/commands/save", name="disk-usage", text="description: Disk usage\nrisk: low\nargv: [df, -h]\n", base=base, is_new="1").status_code == 303
    editor = admin.get("/commands/edit?name=disk-usage").text
    assert "argv: [df, -h]" in editor and "- df" not in editor, editor
    assert "description: Disk usage" in editor and "risk: low" in editor
    on_disk = cl.LIBRARY_PATH.read_text()
    assert "argv: [df, -h]" in on_disk and "- df" not in on_disk, on_disk

    # Parameters stay readable too, and the text survives a trip through the editor unchanged.
    cl.save_command("restart", RESTART)
    cl.save_host("gandalf", GANDALF)
    text = cl.LIBRARY_PATH.read_text()
    assert "values: [sonarr, radarr]" in text and "commands: [restart]" in text, text
    assert yaml.safe_load(text)["commands"]["restart"] == RESTART
    again = cl.dump_yaml(yaml.safe_load(text))
    assert again == text, "dumping what we dumped must not change it"
    assert cl.dump_yaml(cl.command_body("restart")) == cl.dump_yaml(RESTART)
    # Long descriptions are not folded across lines.
    long_desc = "word " * 60
    cl.save_command("wordy", {"description": long_desc.strip(), "argv": ["uptime"]})
    assert long_desc.strip() in cl.LIBRARY_PATH.read_text()
    # Awkward strings are still quoted so they read back the same.
    cl.save_command("tricky", {"description": "yes", "argv": ["echo", "no", "on", "{x}", "- dash", "a: b"], "params": {"x": {"type": "enum", "values": ["1", "true", "null"]}}})
    assert cl.load()[0].commands["tricky"].argv == ["echo", "no", "on", "{x}", "- dash", "a: b"]
    assert cl.load()[0].commands["tricky"].params["x"]["values"] == ["1", "true", "null"]


def test_saved_copies_say_what_changed():
    old = {"commands": {"a": {"description": "x", "argv": ["uptime"]}}, "hosts": {}}
    def d(new, o=old):
        return cl.describe_changes(yaml.safe_dump(o), yaml.safe_dump(new))
    assert d(old) == "no change to commands or hosts"
    assert d({"commands": {"a": {"description": "x", "argv": ["uptime"]}, "b": {"description": "y", "argv": ["df"]}}, "hosts": {}}) == "added command b"
    assert d({"commands": {}, "hosts": {}}) == "removed command a"
    assert d({"commands": {"a": {"description": "changed", "argv": ["uptime"]}}, "hosts": {}}) == "changed command a"
    assert d({"commands": {"c": {"description": "x", "argv": ["uptime"]}}, "hosts": {}}) == "renamed command a to c"
    assert d({"commands": {"a": old["commands"]["a"]}, "hosts": {"h": {"address": "x", "user": "u"}}}) == "added host h"
    many = {"commands": {n: {"description": n, "argv": ["uptime"]} for n in "abcdef"}, "hosts": {}}
    assert d(many) == "added command b; added command c; added command d; and 3 more"
    assert "could not read" in cl.describe_changes("a: [broken", yaml.safe_dump(old))

    _reset()
    cl.save_command("restart", RESTART)
    cl.save_host("gandalf", GANDALF)
    cl.save_host("gandalf", {**GANDALF, "port": 2222})
    cl.save_command("restart", {**RESTART, "description": "edited"})
    cl.save_command("restart", {**RESTART, "description": "edited"}, rename_from=None)
    versions = cl.list_versions()
    changes = [v["change"] for v in versions]
    assert changes[0] == "no change to commands or hosts" or changes[0] == "changed command restart", changes
    assert "changed command restart" in changes and "changed host gandalf" in changes and "added host gandalf" in changes, changes
    assert changes[-1] == "added host gandalf", "no copy is kept of the file that did not exist yet, so the oldest is after the first save"

    # The page lists the summaries and links to a viewer.
    page = admin.get("/commands").text
    assert "added host gandalf" in page and "changed command restart" in page
    assert f'/commands/history/{versions[0]["id"]}"' in page

    # The viewer shows what restoring would undo, and the whole copy.
    oldest = versions[-1]
    r = admin.get(f"/commands/history/{oldest['id']}")
    assert r.status_code == 200 and "What restoring it would change" in r.text
    diff = cl.diff_with_current(oldest["id"])
    assert any(line.startswith("-") and "gandalf" in line for line in diff), diff
    assert any(line.startswith("-") and "gandalf" in line for line in r.text.replace("&#34;", '"').splitlines()) or "gandalf" in r.text
    mid = next(v for v in versions if v["change"] == "added host gandalf")
    body = admin.get(f"/commands/history/{mid['id']}").text
    assert "- " in body and "gandalf" in body, "the host that was added later shows as something restore would remove"
    assert "Restore this copy" in body and "disabled" not in body.split("Restore this copy")[0].rsplit("<button", 1)[1]
    r = _form(admin, f"/commands/history/{mid['id']}/restore", base=cl.current_version())
    assert r.status_code == 303 and "gandalf" not in cl.load()[0].hosts

    # Bad ids are 404, never a file read.
    for bad in ("..%2fcommands", "nope", "20990101T000000000000Z", "../../etc/hostname"):
        assert admin.get(f"/commands/history/{bad}").status_code in (404, 405), bad
    assert admin.get("/commands/history/20990101T000000000000Z").status_code == 404
    _, token = agents.create_agent("viewer-intruder")
    r = client.get(f"/commands/history/{versions[0]['id']}", headers={"Authorization": f"Bearer {token}"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")

    command_admin.AUTH_DISABLED = True
    try:
        assert "disabled" in admin.get(f"/commands/history/{versions[0]['id']}").text, "restore button is greyed out while login is disabled"
    finally:
        command_admin.AUTH_DISABLED = False


def test_rename_a_command_in_use():
    _reset()
    cl.save_command("restart", RESTART)
    cl.save_command("logs", LOGS)
    cl.save_host("gandalf", {**GANDALF, "commands": ["restart", "logs"]})
    cl.save_host("frodo", {"address": "10.0.0.2", "user": "ansible", "commands": ["logs"]})
    cl.load()
    role = agents.create_role("rename-role")
    agents.set_role_commands(role.id, ["restart", "logs"])
    agent, token = agents.create_agent("rename-agent")
    agents.assign_role(agent.id, role.id)
    base = cl.current_version()
    text = yaml.safe_dump(RESTART, sort_keys=False)

    # Rename through the page: library key, hosts and roles all follow, in one step.
    r = _form(admin, "/commands/save", name="restart-container", text=text, base=base, original="restart")
    assert r.status_code == 303 and "Renamed" in r.headers["location"], r.headers.get("location")
    library = cl.load()[0]
    assert "restart" not in library.commands and "restart-container" in library.commands
    assert list(library.commands) == ["restart-container", "logs"], "order is kept"
    assert library.hosts["gandalf"].commands == ["restart-container", "logs"] and library.hosts["frodo"].commands == ["logs"]
    assert agents.role_commands(role.id) == ["logs", "restart-container"]
    with Session(engine) as session:
        agent = session.get(type(agent), agent.id)
    assert agents.check_command(agent, "restart-container", "gandalf") == ""
    assert "no permission" in agents.check_command(agent, "restart", "gandalf"), "the old name no longer works"
    assert not cl.load()[1]
    with Session(engine) as session:
        entry = [a for a in session.exec(select(AdminAudit).where(AdminAudit.action == "rename command")).all()][-1]
    assert "restart -> restart-container" in entry.detail

    # The editor opens under the new name; renaming and editing can happen together.
    assert "restart-container" in admin.get("/commands/edit?name=restart-container").text
    edited = yaml.safe_dump({**RESTART, "description": "Restart it"}, sort_keys=False)
    r = _form(admin, "/commands/save", name="bounce", text=edited, base=cl.current_version(), original="restart-container")
    assert r.status_code == 303
    assert cl.load()[0].commands["bounce"].description == "Restart it" and cl.load()[0].hosts["gandalf"].commands == ["bounce", "logs"]
    assert agents.role_commands(role.id) == ["bounce", "logs"]
    summaries = " | ".join(v["change"] for v in cl.list_versions())
    assert "renamed command restart to restart-container" in summaries, summaries
    assert "added command bounce; removed command restart-container" in summaries, "renamed AND edited reads as a replacement"

    # Refusals leave everything exactly as it was.
    before = (cl.LIBRARY_PATH.read_text(), agents.role_commands(role.id))
    for kwargs, contains in [
        (dict(name="logs", original="bounce", text=edited), "already exists"),
        (dict(name="bad name!", original="bounce", text=edited), "command name"),
        (dict(name="", original="bounce", text=edited), None),
        (dict(name="ghost2", original="no-such", text=edited), "no such command"),
    ]:
        r = _form(admin, "/commands/save", base=cl.current_version(), **kwargs)
        assert r.status_code in (400, 422), (kwargs, r.status_code)
        if contains:
            assert contains in r.text, (kwargs, r.text[:300])
    r = _form(admin, "/commands/save", name="stale-rename", text=edited, base="stale", original="bounce")
    assert r.status_code == 400 and "changed since" in r.text
    assert (cl.LIBRARY_PATH.read_text(), agents.role_commands(role.id)) == before

    # If the file cannot be written after the roles were moved, the roles move back.
    real = os.replace
    def boom(*a, **kw):
        raise OSError("disk full")
    os.replace = boom
    try:
        try:
            _form(admin, "/commands/save", name="never", text=edited, base=cl.current_version(), original="bounce")
        except OSError:
            pass
    finally:
        os.replace = real
    assert agents.role_commands(role.id) == ["bounce", "logs"], "role entries must follow the file, not run ahead of it"
    assert "bounce" in cl.load()[0].commands and "never" not in cl.load()[0].commands

    # Hand-renaming in the file is not a rename: roles lose it (nothing says it is the same command).
    cl.LIBRARY_PATH.write_text(cl.LIBRARY_PATH.read_text().replace("bounce", "hand-renamed"))
    assert not cl.load()[1] and "hand-renamed" in cl.load()[0].commands
    assert agents.role_commands(role.id) == ["logs"]

    # Locked while login is disabled.
    command_admin.AUTH_DISABLED = True
    try:
        r = _form(admin, "/commands/save", name="locked-name", text=edited, base=cl.current_version(), original="hand-renamed")
        assert r.status_code == 400 and "ULMO_DISABLE_AUTH" in r.text
    finally:
        command_admin.AUTH_DISABLED = False
    assert "locked-name" not in cl.load()[0].commands


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
    assert r.status_code == 200 and "docker" in r.text and "readonly" not in r.text, "the name can be changed"
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

    # An optional parameter: shown as such in the list, and Preview with the line left out drops its element.
    opt = yaml.safe_dump({"description": "d", "argv": ["docker", "ps", "--filter={f}"], "params": {"f": {"type": "enum", "values": ["name=a"], "optional": True}}}, sort_keys=False)
    r = _form(admin, "/commands/preview", name="ps", text=opt, samples="")
    assert r.status_code == 200 and "would receive: timeout -k 5 30 docker ps<" in r.text, r.text
    r = _form(admin, "/commands/preview", name="ps", text=opt, samples="f=name=a")
    assert "--filter=name=a" in r.text
    assert _form(admin, "/commands/save", name="ps", text=opt, base=cl.current_version(), is_new="1").status_code == 303
    assert "f (enum, optional)" in admin.get("/commands").text
    cl.delete_command("ps")
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
    assert admin.get(f"/commands/history/{versions[0]['id']}").status_code == 200, "a saved copy can be viewed"
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
        assert r.status_code == 303 and r.headers["location"].startswith("/login"), f"{url}: {r.status_code}"
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


def test_checklist_pieces():
    css = Path("app/static/style.css").read_text()
    assert ".check-item[hidden]" in css and "display: none" in css.split(".check-item[hidden]")[1].split("}")[0], \
        "a rule that keeps filtered rows hidden (display:flex on .check-item would otherwise win)"
    for needed in (".actions", ".checklist", ".panel", ".form-grid"):
        assert needed in css, needed
    import re
    assert re.search(r"a\.btn[^{]*\{[^}]*display:\s*inline-block", css), "links styled as buttons must be laid out like buttons"
    base = admin.get("/commands").text
    assert '/static/filter.js?v=' in base, "the filter script is loaded on every page"
    assert admin.get("/static/filter.js").status_code == 200
    node = shutil.which("node")
    if node:  # the script must at least parse (this environment has no browser to run it in)
        import subprocess
        assert subprocess.run([node, "--check", "app/static/filter.js"], capture_output=True).returncode == 0
    # A long list of commands gets a filter box; a short one does not.
    _reset()
    for i in range(8):
        cl.save_command(f"c{i}", {"description": f"d{i}", "argv": ["uptime"]})
    page = admin.get("/commands").text
    assert 'data-filter="#host-commands"' in page and 'placeholder="Filter 8 items"' in page
    _reset()
    cl.save_command("only", {"description": "d", "argv": ["uptime"]})
    assert "data-filter=" not in admin.get("/commands").text
    # Actions are buttons, not bare links.
    cl.save_host("h", {"address": "10.0.0.1", "user": "root", "commands": ["only"]})
    page = admin.get("/commands").text
    for label in ("Edit", "New command", "Download commands.yml"):
        assert f'class="btn' in page and label in page
    import re
    assert not re.findall(r'<a href="/commands[^"]*">(?:Edit|View|New command|Back|Cancel)</a>', page), "no plain-link actions"
    # The other pages' actions are buttons too: the editor, and a saved copy's page.
    editor = admin.get("/commands/edit?name=only").text
    assert editor.count('class="btn secondary" href="/commands"') == 2, "Back to commands and Cancel"
    cl.save_command("only", {"description": "d2", "argv": ["uptime"]})
    version = cl.list_versions()[0]["id"]
    viewer = admin.get(f"/commands/history/{version}").text
    assert viewer.count('class="btn secondary" href="/commands"') == 2, "Back to commands and Back"
    for html in (editor, viewer):
        assert not re.findall(r'<a href="/commands"[^>]*>(?:Back|Cancel|Back to commands)</a>', html), "no plain-link Back/Cancel"
    # A long Offers list is folded; a short one is shown.
    cl.save_host("busy", {"address": "10.0.0.2", "user": "root", "commands": ["only"]})
    for i in range(8):
        cl.save_command(f"x{i}", {"description": "d", "argv": ["uptime"]})
    cl.save_host("busy", {"address": "10.0.0.2", "user": "root", "commands": [f"x{i}" for i in range(8)]})
    page = admin.get("/commands").text
    assert "<summary>8 commands</summary>" in page


def test_select_all_markup():
    _reset()
    for i in range(3):
        cl.save_command(f"c{i}", {"description": f"d{i}", "argv": ["uptime"]})
    cl.save_host("h", {"address": "10.0.0.1", "user": "root", "commands": ["c1"]})
    page = admin.get("/commands?host=h").text
    assert page.count('data-check="all" data-target="#host-commands"') == 1 and page.count('data-check="none" data-target="#host-commands"') == 1
    assert 'type="button" class="secondary" data-check="all"' in page, "must not submit the form"
    assert ">1 of 3 selected<" in page, "the count starts from what is already ticked"
    assert 'class="empty check-none"' in page and "hidden>Nothing matches that filter." in page, "a no-match line exists, hidden"
    assert "data-filter=" not in page, "three items need no filter box, but still get Select all"
    # One item (or none) needs no toolbar.
    _reset()
    cl.save_command("only", {"description": "d", "argv": ["uptime"]})
    assert "data-check=" not in admin.get("/commands").text
    # The Agents page gets the same controls on every role's list.
    for i in range(3):
        cl.save_command(f"c{i}", {"description": f"d{i}", "argv": ["uptime"]})
    role = agents.create_role("select-all-role")
    agents.set_role_commands(role.id, ["c0", "c2"])
    agents_page = admin.get("/agents").text
    assert f'data-target="#role-commands-{role.id}"' in agents_page and ">2 of 4 selected<" in agents_page.split(f'id="role-commands-{role.id}"')[0].rsplit('check-tools', 1)[1]


def test_select_all_script_behaviour():
    node = shutil.which("node")
    if not node:
        print("  (node not found: skipping the script behaviour check)")
        return
    import subprocess
    harness = r"""
const fs = require("fs"), assert = require("assert");
const handlers = {};
const names = ["disk-usage", "disk-inodes", "docker-ps", "uptime"];
const items = names.map((n, i) => ({ hidden: false, textContent: n.toUpperCase() + " Some Description", input: { checked: n === "docker-ps" },
                                      querySelector() { return this.input; } }));
const countEl = { textContent: "" };
const noneEl = { hidden: true };
const list = { id: "L", querySelectorAll(sel) { return sel === ".check-item" ? items : sel === "input:checked" ? items.map(i => i.input).filter(i => i.checked) : []; },
               closest(sel) { return sel === ".checklist" ? this : null; } };
const box = { value: "", getAttribute() { return "#L"; } };
const document = {
  addEventListener(type, fn) { (handlers[type] = handlers[type] || []).push(fn); },
  querySelector(sel) { return sel === "#L" ? list : sel === '[data-count-for="#L"]' ? countEl : sel === "#L .check-none" ? noneEl : null; },
  querySelectorAll(sel) { return sel === "#L .check-item" ? items : []; },
};
new Function("document", fs.readFileSync("app/static/filter.js", "utf8"))(document);
const fire = (type, target) => handlers[type].forEach(h => h({ target }));
const typeFilter = v => { box.value = v; fire("input", { closest: s => (s === "[data-filter]" ? box : null) }); };
const press = what => fire("click", { closest: s => (s === "[data-check]" ? { getAttribute: n => (n === "data-check" ? what : "#L") } : null) });
const state = () => items.map(i => (i.input.checked ? 1 : 0)).join("");
const shown = () => items.map(i => (i.hidden ? 0 : 1)).join("");

typeFilter("disk");
assert.strictEqual(shown(), "1100", "filter hides non-matching rows");
assert.strictEqual(noneEl.hidden, true, "the no-match line stays hidden while something matches");
typeFilter("zzz");
assert.strictEqual(shown(), "0000");
assert.strictEqual(noneEl.hidden, false, "a filter that matches nothing says so");
typeFilter("disk");
assert.strictEqual(noneEl.hidden, true);
press("all");
assert.strictEqual(state(), "1110", "Select all ticks the shown rows and leaves hidden ones alone");
assert.strictEqual(countEl.textContent, "3 of 4 selected");
press("none");
assert.strictEqual(state(), "0010", "Clear unticks only the shown rows; the hidden ticked one stays");
assert.strictEqual(countEl.textContent, "1 of 4 selected");
typeFilter("");
assert.strictEqual(shown(), "1111", "clearing the filter shows everything again");
press("all");
assert.strictEqual(state(), "1111");
assert.strictEqual(countEl.textContent, "4 of 4 selected");
items[1].input.checked = false;
fire("change", { closest: s => (s === ".checklist" ? list : null) });
assert.strictEqual(countEl.textContent, "3 of 4 selected", "ticking by hand updates the count");
press("none");
assert.strictEqual(state(), "0000");
typeFilter("DoCkEr");
assert.strictEqual(shown(), "0010", "the filter ignores case (rows are upper case here, the typed text is mixed)");
fire("click", { closest: () => null });  // clicks elsewhere do nothing
fire("input", { closest: () => null });
console.log("script ok");
"""
    r = subprocess.run([node, "-e", harness], capture_output=True, text=True)
    assert r.returncode == 0 and "script ok" in r.stdout, r.stdout + r.stderr


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
    test_optional_parameters()
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
    test_yaml_keeps_the_way_you_write_it()
    test_saved_copies_say_what_changed()
    test_rename_a_command_in_use()
    test_preview_shows_what_the_host_receives()
    test_page_is_admin_only_and_locked_without_login()
    test_checklist_pieces()
    test_select_all_markup()
    test_select_all_script_behaviour()
    test_history_setting()
    print("OK: the command library validates strictly, versions every change, and is edited safely from the Commands page.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
