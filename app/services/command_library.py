"""The command library: what agents may run over SSH, and where.

Everything lives in one YAML file, /data/commands.yml, edited from the
Commands page (and safe to edit by hand):

    commands:                         # the library: what exists
      restart-container:
        description: Restart a Docker container
        argv: [docker, restart, "{container}"]
        params:
          container: {type: enum, values: [sonarr, radarr]}
        timeout: 30                   # seconds, 1-300 (default 30)
        sudo: false                   # run as `sudo -n <argv>`
        risk: medium                  # label only: low | medium | high
    list-containers:
      description: List containers, optionally filtered
      argv: [docker, ps, -a, "--filter={filter}"]
      params:
        filter: {type: regex, pattern: "(id|name)=[a-z0-9_.-]+", optional: true}

An optional parameter may be left out. Its value is then absent and every argv
element that holds its placeholder is dropped, so write a flag and its value as one
element ("--filter={filter}", not "--filter", "{filter}"). Supplied values are
checked exactly like required ones.
    hosts:                            # where each one may run
      gandalf:
        address: 10.42.11.10
        port: 22
        user: root
        ssh_key: unraid-key           # a key uploaded under Settings -> SSH Key
        commands: [restart-container]

An agent never sends a command line. It names a command and a host and gives
parameter values; every value is checked against its declared type and
substituted into one argv element. The list is later joined with shlex.join, so
a value can never become shell syntax, and a value cannot start with "-"
(option injection) unless the parameter says allow_leading_dash.

Every change goes through one validated read-modify-write: the whole file is
re-checked, the previous copy is kept as history, and the new one is swapped in
atomically. A hand edit that no longer parses keeps the last good library in
service and shows the error.
"""
import difflib
import hashlib
import os
import re
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone

import regex as _regex  # same syntax as re, but a match can be given a time budget
import yaml

from app.config import DATA_DIR
from app.services import settings_store

LIBRARY_PATH = DATA_DIR / "commands.yml"
HISTORY_DIR = DATA_DIR / "commands.history"
ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,60}$")
PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
MAX_COMMAND_BYTES = 20 * 1024
MAX_FILE_BYTES = 200 * 1024
MAX_TOKEN_CHARS = 500
MAX_VALUE_CHARS = 200
MATCH_BUDGET = 0.25  # seconds a regex parameter may spend matching one value
COMMAND_KEYS = {"description", "argv", "params", "timeout", "sudo", "risk"}
HOST_KEYS = {"address", "port", "user", "auth", "ssh_key", "commands"}
AUTH_MODES = ("key", "password")
PARAM_KEYS = {
    "enum": {"type", "values", "optional"},
    "int": {"type", "min", "max", "optional"},
    "regex": {"type", "pattern", "max_length", "allow_leading_dash", "optional"},
}
ADDRESS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
SSH_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
KEY_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


class Conflict(ValueError):
    """The file changed since the editor was opened."""


@dataclass
class Template:
    id: str
    description: str
    argv: list[str]
    params: dict[str, dict] = field(default_factory=dict)
    timeout: int = 30
    sudo: bool = False
    risk: str = ""

    def schema(self) -> dict:
        """What an agent needs to call it: parameter names and constraints."""
        return {"command": self.id, "description": self.description, "risk": self.risk, "params": self.params}


@dataclass
class Host:
    name: str
    address: str
    port: int = 22
    user: str = ""
    ssh_key: str = ""
    commands: list[str] = field(default_factory=list)
    auth: str = "key"  # "password": the password is kept in the database, never in the file


@dataclass
class Library:
    commands: dict[str, Template] = field(default_factory=dict)
    hosts: dict[str, Host] = field(default_factory=dict)

    def hosts_offering(self, command: str) -> list[str]:
        return sorted(h.name for h in self.hosts.values() if command in h.commands)


def _bad(msg: str):
    raise ValueError(msg)


# --- one command ---------------------------------------------------------------


def parse_command(name: str, data) -> Template:
    """Validate one command's mapping, or raise ValueError saying what is wrong."""
    if not ID_RE.match(name):
        _bad("command name must be 1-60 characters: letters, digits, '.', '_' or '-'")
    if not isinstance(data, dict):
        _bad("expected a YAML mapping")
    if set(data) - COMMAND_KEYS:
        _bad(f"unknown keys: {', '.join(sorted(map(str, set(data) - COMMAND_KEYS)))}")

    description = data.get("description")
    if not isinstance(description, str) or not description.strip():
        _bad("description is required")

    argv = data.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(t, str) and t for t in argv):
        _bad("argv must be a non-empty list of non-empty strings")
    for token in argv:
        if "\0" in token or len(token) > MAX_TOKEN_CHARS:
            _bad("argv contains a NUL byte or a token over 500 characters")
        rest = PLACEHOLDER_RE.sub("", token)
        if "{" in rest or "}" in rest:
            _bad(f"stray brace in {token!r}: only {{name}} placeholders are allowed")
    if PLACEHOLDER_RE.search(argv[0]):
        _bad("the command itself (argv[0]) cannot be a parameter")

    params = data.get("params") or {}
    if not isinstance(params, dict):
        _bad("params must be a mapping")
    used = {m for token in argv for m in PLACEHOLDER_RE.findall(token)}
    if used - set(params):
        _bad(f"argv uses undeclared parameters: {', '.join(sorted(used - set(params)))}")
    if set(params) - used:
        _bad(f"parameters never used in argv: {', '.join(sorted(set(params) - used))}")
    clean = {pname: _parse_param(pname, spec) for pname, spec in params.items()}

    timeout = data.get("timeout", 30)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 300:
        _bad("timeout must be a whole number of seconds from 1 to 300")
    if not isinstance(data.get("sudo", False), bool):
        _bad("sudo must be true or false")
    risk = data.get("risk", "")
    if risk not in ("", "low", "medium", "high"):
        _bad("risk must be low, medium or high")

    return Template(name, description.strip(), argv, clean, timeout, data.get("sudo", False), risk)


def parse_command_text(name: str, text: str) -> Template:
    if len(text.encode()) > MAX_COMMAND_BYTES:
        _bad(f"a command is limited to {MAX_COMMAND_BYTES // 1024} KB")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        _bad(f"not valid YAML: {str(exc).splitlines()[0]}")
    return parse_command(name, data)


def _parse_param(name: str, spec) -> dict:
    if not isinstance(spec, dict) or spec.get("type") not in PARAM_KEYS:
        _bad(f"parameter {name}: type must be one of {', '.join(sorted(PARAM_KEYS))}")
    kind = spec["type"]
    if set(spec) - PARAM_KEYS[kind]:
        _bad(f"parameter {name}: unknown keys {', '.join(sorted(map(str, set(spec) - PARAM_KEYS[kind])))}")
    if not isinstance(spec.get("optional", False), bool):
        _bad(f"parameter {name}: optional must be true or false")
    clean = _parse_param_type(name, spec, kind)
    return {**clean, "optional": True} if spec.get("optional") else clean


def _parse_param_type(name: str, spec: dict, kind: str) -> dict:
    if kind == "enum":
        values = spec.get("values")
        if not isinstance(values, list) or not values or not all(isinstance(v, str) and v and "\0" not in v for v in values):
            _bad(f"parameter {name}: values must be a non-empty list of strings")
        if len(set(values)) != len(values) or any(len(v) > MAX_VALUE_CHARS for v in values):
            _bad(f"parameter {name}: values must be unique and under {MAX_VALUE_CHARS} characters")
        return {"type": "enum", "values": values}
    if kind == "int":
        lo, hi = spec.get("min"), spec.get("max")
        if any(isinstance(x, bool) or not isinstance(x, int) for x in (lo, hi)) or lo > hi:
            _bad(f"parameter {name}: min and max are required whole numbers with min <= max")
        return {"type": "int", "min": lo, "max": hi}
    pattern = spec.get("pattern")
    max_length = spec.get("max_length", 100)
    if not isinstance(pattern, str) or not pattern:
        _bad(f"parameter {name}: pattern is required")
    try:
        _regex.compile(pattern)
    except _regex.error as exc:
        _bad(f"parameter {name}: bad pattern ({exc})")
    if isinstance(max_length, bool) or not isinstance(max_length, int) or not 1 <= max_length <= MAX_VALUE_CHARS:
        _bad(f"parameter {name}: max_length must be 1-{MAX_VALUE_CHARS}")
    dash = spec.get("allow_leading_dash", False)
    if not isinstance(dash, bool):
        _bad(f"parameter {name}: allow_leading_dash must be true or false")
    return {"type": "regex", "pattern": pattern, "max_length": max_length, "allow_leading_dash": dash}


def validate_params(template: Template, given) -> dict[str, str]:
    """Check an agent's values against the command; return them as strings.
    Raises ValueError with a message safe to show the agent."""
    if not isinstance(given, dict):
        _bad("params must be an object")
    extra = set(given) - set(template.params)
    missing = {n for n, spec in template.params.items() if not spec.get("optional")} - set(given)
    if extra:
        _bad(f"unknown parameters: {', '.join(sorted(map(str, extra)))}")
    if missing:
        _bad(f"missing parameters: {', '.join(sorted(missing))}")
    out = {}
    for name, spec in template.params.items():
        if name not in given:  # an optional parameter left out
            continue
        value = given[name]
        if spec["type"] == "enum":
            if not isinstance(value, str) or value not in spec["values"]:
                _bad(f"{name} must be one of: {', '.join(spec['values'])}")
            out[name] = value
        elif spec["type"] == "int":
            if isinstance(value, bool) or not isinstance(value, int) or not spec["min"] <= value <= spec["max"]:
                _bad(f"{name} must be a whole number from {spec['min']} to {spec['max']}")
            out[name] = str(value)
        else:
            if not isinstance(value, str) or not value or len(value) > spec["max_length"]:
                _bad(f"{name} must be a non-empty string of at most {spec['max_length']} characters")
            try:
                matched = _regex.fullmatch(spec["pattern"], value, timeout=MATCH_BUDGET)
            except TimeoutError:
                _bad(f"{name}: the pattern is too slow on this value")
            if not matched or "\0" in value or "\n" in value:
                _bad(f"{name} does not match the allowed pattern")
            if value.startswith("-") and not spec["allow_leading_dash"]:
                _bad(f"{name} may not start with '-'")
            out[name] = value
    return out


def build_argv(template: Template, values: dict[str, str]) -> list[str]:
    """The exact argument list to run. Each value lands inside one element; an
    element holding the placeholder of an optional parameter that was left out is dropped."""
    argv = [
        PLACEHOLDER_RE.sub(lambda m: values[m.group(1)], token)
        for token in template.argv
        if all(name in values for name in PLACEHOLDER_RE.findall(token))
    ]
    return ["sudo", "-n", *argv] if template.sudo else argv


def sample_values(template: Template, lines: str) -> dict:
    """Turn 'name=value' lines (the Preview box) into typed values for validate_params."""
    given = {}
    for line in lines.splitlines():
        if not line.strip():
            continue
        key, sep, value = line.partition("=")
        if not sep:
            _bad(f"expected name=value, got {line.strip()!r}")
        key = key.strip()
        spec = template.params.get(key)
        given[key] = int(value) if spec and spec["type"] == "int" and re.fullmatch(r"-?\d+", value.strip()) else value
    return given


# --- one host --------------------------------------------------------------------


def parse_host(name: str, data, command_names: set[str]) -> Host:
    if not ID_RE.match(name):
        _bad("host name must be 1-60 characters: letters, digits, '.', '_' or '-'")
    if not isinstance(data, dict):
        _bad("expected a mapping")
    if set(data) - HOST_KEYS:
        _bad(f"unknown keys: {', '.join(sorted(map(str, set(data) - HOST_KEYS)))}")
    address = data.get("address")
    if not isinstance(address, str) or not ADDRESS_RE.match(address) or len(address) > 253:
        _bad("address must be a host name or IP address")
    port = data.get("port", 22)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        _bad("port must be a number from 1 to 65535")
    user = data.get("user")
    if not isinstance(user, str) or not SSH_USER_RE.match(user):
        _bad("user must be a valid account name")
    key = data.get("ssh_key", "")
    if key and not (isinstance(key, str) and KEY_NAME_RE.match(key) and key not in (".", "..")):
        _bad("ssh_key must be the name of an uploaded key file, not a path")
    auth = data.get("auth", "key")
    if auth not in AUTH_MODES:
        _bad("auth must be key or password")
    if auth == "password" and key:
        _bad("a host signs in with a key or a password, not both")
    commands = data.get("commands") or []
    if not isinstance(commands, list) or not all(isinstance(c, str) for c in commands) or len(set(commands)) != len(commands):
        _bad("commands must be a list of unique command names")
    unknown = sorted(set(commands) - command_names)
    if unknown:
        _bad(f"commands that do not exist: {', '.join(unknown)}")
    return Host(name, address, port, user, key or "", list(commands), auth)


# --- the file ----------------------------------------------------------------------

_lock = threading.RLock()
_state = {"fingerprint": None, "library": Library(), "error": ""}
_on_valid_load = []


def on_valid_load(callback) -> None:
    """Call callback(library) whenever the file on disk changes and parses. Used to
    drop role entries for commands that no longer exist; never called for a file
    that fails to parse, so a typo cannot wipe anything."""
    _on_valid_load.append(callback)


def _blank() -> dict:
    return {"commands": {}, "hosts": {}}


def validate(data) -> Library:
    """Check a whole file's contents, cross-references included."""
    if not isinstance(data, dict) or set(data) - {"commands", "hosts"}:
        _bad("the file must be a mapping with only 'commands' and 'hosts'")
    commands = data.get("commands") or {}
    hosts = data.get("hosts") or {}
    if not isinstance(commands, dict) or not isinstance(hosts, dict):
        _bad("'commands' and 'hosts' must be mappings")
    library = Library()
    for name, body in commands.items():
        try:
            library.commands[str(name)] = parse_command(str(name), body)
        except ValueError as exc:
            _bad(f"command {name}: {exc}")
    for name, body in hosts.items():
        try:
            library.hosts[str(name)] = parse_host(str(name), body, set(library.commands))
        except ValueError as exc:
            _bad(f"host {name}: {exc}")
    return library


def dump_yaml(obj) -> str:
    """YAML as a person would write it: lists and mappings of plain values stay on
    one line (argv: [df, -h]) instead of becoming a dash list."""
    return yaml.safe_dump(obj, sort_keys=False, default_flow_style=None, allow_unicode=True, width=10000)


def version_of(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def read_text() -> str:
    try:
        return LIBRARY_PATH.read_text()
    except FileNotFoundError:
        return ""


def current_version() -> str:
    return version_of(read_text())


def load() -> tuple[Library, str]:
    """The current library and, if the file on disk no longer parses, why (the
    last good library stays in service meanwhile)."""
    with _lock:
        try:
            st = LIBRARY_PATH.stat()
            fingerprint = (st.st_mtime_ns, st.st_size)
        except FileNotFoundError:
            fingerprint = None
        if fingerprint == _state["fingerprint"]:
            return _state["library"], _state["error"]
        text = read_text()
        try:
            if len(text.encode()) > MAX_FILE_BYTES:
                _bad(f"the file is over {MAX_FILE_BYTES // 1024} KB")
            library, error = validate(yaml.safe_load(text) or _blank()), ""
        except (ValueError, yaml.YAMLError) as exc:
            library, error = _state["library"], str(exc).splitlines()[0][:400]
        _state.update(fingerprint=fingerprint, library=library, error=error)
        if not error:
            for callback in _on_valid_load:
                callback(library)
        return library, error


def _raw() -> dict:
    """The file as a plain dict, to modify and write back."""
    data = yaml.safe_load(read_text()) or _blank()
    if not isinstance(data, dict):
        _bad("commands.yml on disk is not a mapping; fix or restore it first")
    data.setdefault("commands", {})
    data.setdefault("hosts", {})
    data["commands"] = data["commands"] or {}
    data["hosts"] = data["hosts"] or {}
    return data


def _history_keep() -> int:
    try:
        return max(1, int(settings_store.get("command_history_keep")))
    except ValueError:
        return 20


def _write(data: dict, before_write=None) -> None:
    """Validate everything, keep the old copy, swap the new one in. `before_write`
    runs once the new contents are known to be valid, just before the swap."""
    validate(data)
    text = dump_yaml(data)
    if len(text.encode()) > MAX_FILE_BYTES:
        _bad(f"the file would be over {MAX_FILE_BYTES // 1024} KB")
    if before_write:
        before_write()
    old = read_text()
    if old and old != text:
        HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        (HISTORY_DIR / f"{stamp}.yml").write_text(old)
        for stale in sorted(HISTORY_DIR.glob("*.yml"))[: -_history_keep()]:
            stale.unlink()
    LIBRARY_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=LIBRARY_PATH.parent, prefix=".commands-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())  # a power cut must not leave an empty commands.yml after the swap
        os.replace(tmp, LIBRARY_PATH)
        dir_fd = os.open(LIBRARY_PATH.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    load()  # pick up the new file now, so listeners (role cleanup) run straight away


def _modify(base: str | None, change, start: dict | None = None, before_write=None) -> None:
    """Read, change, validate, write, under one lock. `start` replaces the current
    contents as the thing to change (restore uses it, so a file that no longer
    parses can still be recovered)."""
    with _lock:
        if base is not None and base != current_version():
            raise Conflict("The library changed since you opened this. Reload and try again.")
        data = _raw() if start is None else start
        change(data)
        _write(data, before_write)


def save_command(name: str, body: dict, base: str | None = None, rename_from: str | None = None, before_write=None) -> None:
    """Save a command. With rename_from, the command is renamed in the same step: the
    library key and every host that offers it move together, in one validated write
    (before_write lets the caller move role entries too)."""

    def change(data):
        if rename_from and rename_from != name:
            if rename_from not in data["commands"]:
                _bad("no such command")
            if name in data["commands"]:
                _bad(f"A command named {name!r} already exists.")
            data["commands"] = {(name if k == rename_from else k): v for k, v in data["commands"].items()}
            for host in data["hosts"].values():
                if isinstance(host, dict) and isinstance(host.get("commands"), list):
                    host["commands"] = [name if c == rename_from else c for c in host["commands"]]
        data["commands"][name] = body

    _modify(base, change, before_write=before_write)


def delete_command(name: str, base: str | None = None) -> None:
    def change(data):
        if name not in data["commands"]:
            _bad("no such command")
        users = sorted(h for h, v in data["hosts"].items() if name in (v or {}).get("commands", []))
        if users:
            _bad(f"still offered by: {', '.join(users)}. Remove it from those hosts first.")
        del data["commands"][name]

    _modify(base, change)


def save_host(name: str, body: dict, base: str | None = None) -> None:
    _modify(base, lambda d: d["hosts"].__setitem__(name, body))


def delete_host(name: str, base: str | None = None) -> None:
    def change(data):
        if name not in data["hosts"]:
            _bad("no such host")
        del data["hosts"][name]

    _modify(base, change)


def command_body(name: str) -> dict:
    """The stored mapping for a command, for the editor."""
    return dict(_raw()["commands"].get(name) or {})


def describe_changes(old_text: str, new_text: str) -> str:
    """One line on what differs between two copies, by command and host name."""
    try:
        old, new = (yaml.safe_load(t) or {} for t in (old_text, new_text))
        parts = []
        for kind in ("commands", "hosts"):
            before, after = old.get(kind) or {}, new.get(kind) or {}
            added = [n for n in after if n not in before]
            removed = [n for n in before if n not in after]
            for gone in list(removed):  # same contents under another name: a rename
                twin = next((a for a in added if after[a] == before[gone]), None)
                if twin:
                    parts.append(f"renamed {kind[:-1]} {gone} to {twin}")
                    removed.remove(gone)
                    added.remove(twin)
            parts += [f"added {kind[:-1]} {n}" for n in added] + [f"removed {kind[:-1]} {n}" for n in removed]
            parts += [f"changed {kind[:-1]} {n}" for n in before if n in after and before[n] != after[n]]
    except (yaml.YAMLError, AttributeError, TypeError):
        return "(could not read this copy)"
    if not parts:
        return "no change to commands or hosts"
    return "; ".join(parts[:3]) + (f"; and {len(parts) - 3} more" if len(parts) > 3 else "")


def list_versions(describe: int = 50) -> list[dict]:
    """Saved copies, newest first. Each copy is the file as it was BEFORE a change;
    `change` says what that change was (for the newest `describe` copies)."""
    if not HISTORY_DIR.is_dir():
        return []
    paths = sorted(HISTORY_DIR.glob("*.yml"), reverse=True)
    newer = read_text()  # the state that replaced the newest copy
    out = []
    for i, p in enumerate(paths):
        text = p.read_text() if i < describe else ""
        out.append(
            {
                "id": p.stem,
                "bytes": p.stat().st_size,
                "at": datetime.strptime(p.stem, "%Y%m%dT%H%M%S%fZ").replace(tzinfo=timezone.utc),
                "change": describe_changes(text, newer) if i < describe else "",
            }
        )
        newer = text
    return out


def diff_with_current(version_id: str) -> list[str]:
    """Unified diff from the current file to a saved copy: what restoring it would change
    (lines starting with - go away, lines starting with + come back)."""
    return list(
        difflib.unified_diff(read_text().splitlines(), version_text(version_id).splitlines(), "current", "this copy", lineterm="", n=2)
    )


def version_text(version_id: str) -> str:
    if not re.fullmatch(r"[0-9TZ]{10,30}", version_id):
        _bad("unknown version")
    path = HISTORY_DIR / f"{version_id}.yml"
    if not path.is_file():
        _bad("unknown version")
    return path.read_text()


def restore(version_id: str, base: str | None = None) -> None:
    """Make an older copy current again (as a new version, so nothing is lost)."""
    text = version_text(version_id)
    try:
        data = yaml.safe_load(text) or _blank()
    except yaml.YAMLError as exc:
        _bad(f"that copy is not valid YAML: {exc}")
    _modify(base, lambda d: None, start=data)
