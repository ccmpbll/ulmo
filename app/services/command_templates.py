"""Command templates: the only commands an agent can run over SSH.

A template is one YAML file in the synced repo (ulmo/templates/<id>.yml):

    description: Restart a Docker container
    argv: [docker, restart, "{container}"]
    params:
      container: {type: enum, values: [sonarr, radarr]}
    timeout: 30          # seconds, 1-300 (default 30)
    sudo: false          # run as `sudo -n <argv>`
    risk: low            # label only: low | medium | high
    ssh_user: ansible    # optional; default is the host's ansible user
    ssh_key: my-key      # optional; a key file name uploaded under Settings -> SSH Key

The agent never sends a command line. It names a template and gives parameter
values; every value is checked against its declared type and substituted into
one argv element. The argument list is later joined with shlex.join, so a value
can never become shell syntax, and a value cannot start with "-" (option
injection) unless the parameter says allow_leading_dash.

Loading is per file: a broken file is reported and the last good version of
that template, if any, stays in service.
"""
import re
import re._constants as _sre_const
import re._parser as _sre_parser
import threading
from dataclasses import dataclass, field

import yaml

from app.config import REPO_DIR

TEMPLATES_REL = "ulmo/templates"
ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,60}$")
PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
MAX_FILE_BYTES = 20 * 1024
MAX_TOKEN_CHARS = 500
MAX_VALUE_CHARS = 200
KEYS = {"description", "argv", "params", "timeout", "sudo", "risk", "ssh_user", "ssh_key"}
PARAM_KEYS = {
    "enum": {"type", "values"},
    "int": {"type", "min", "max"},
    "regex": {"type", "pattern", "max_length", "allow_leading_dash"},
}
SSH_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
KEY_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


@dataclass
class Template:
    id: str
    description: str
    argv: list[str]
    params: dict[str, dict] = field(default_factory=dict)
    timeout: int = 30
    sudo: bool = False
    risk: str = ""
    ssh_user: str = ""
    ssh_key: str = ""

    def schema(self) -> dict:
        """What an agent needs to call it: parameter names and constraints."""
        return {"template": self.id, "description": self.description, "risk": self.risk, "params": self.params}


def _bad(msg: str):
    raise ValueError(msg)


def parse(template_id: str, text: str) -> Template:
    """Turn one file's text into a Template, or raise ValueError saying what is wrong."""
    if not ID_RE.match(template_id):
        _bad("file name must be 1-60 characters: letters, digits, '.', '_' or '-'")
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        _bad("expected a YAML mapping")
    if set(data) - KEYS:
        _bad(f"unknown keys: {', '.join(sorted(map(str, set(data) - KEYS)))}")

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
    clean = {name: _parse_param(name, spec) for name, spec in params.items()}

    timeout = data.get("timeout", 30)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 300:
        _bad("timeout must be a whole number of seconds from 1 to 300")
    if not isinstance(data.get("sudo", False), bool):
        _bad("sudo must be true or false")
    risk = data.get("risk", "")
    if risk not in ("", "low", "medium", "high"):
        _bad("risk must be low, medium or high")
    ssh_user = data.get("ssh_user", "")
    if ssh_user and not (isinstance(ssh_user, str) and SSH_USER_RE.match(ssh_user)):
        _bad("ssh_user is not a valid user name")
    ssh_key = data.get("ssh_key", "")
    if ssh_key and not (isinstance(ssh_key, str) and KEY_NAME_RE.match(ssh_key) and ssh_key not in (".", "..")):
        _bad("ssh_key must be the name of an uploaded key file, not a path")

    return Template(template_id, description.strip(), argv, clean, timeout, data.get("sudo", False), risk, ssh_user, ssh_key)


def _subpatterns(x):
    if isinstance(x, _sre_parser.SubPattern):
        yield x
    elif isinstance(x, (tuple, list)):
        for item in x:
            yield from _subpatterns(item)


def _nested_repeat(tree, inside: bool = False) -> bool:
    """True for patterns like (a+)+ or ([a-z]+)*x: a repeat nested in a repeat can
    backtrack exponentially, and Python's re has no timeout."""
    for op, av in tree:
        if op in (_sre_const.MAX_REPEAT, _sre_const.MIN_REPEAT):
            _lo, hi, body = av
            repeats = hi > 1
            if (inside and repeats) or _nested_repeat(body, inside or repeats):
                return True
        else:
            for sub in _subpatterns(av):
                if _nested_repeat(sub, inside):
                    return True
    return False


def _parse_param(name: str, spec) -> dict:
    if not isinstance(spec, dict) or spec.get("type") not in PARAM_KEYS:
        _bad(f"parameter {name}: type must be one of {', '.join(sorted(PARAM_KEYS))}")
    kind = spec["type"]
    if set(spec) - PARAM_KEYS[kind]:
        _bad(f"parameter {name}: unknown keys {', '.join(sorted(map(str, set(spec) - PARAM_KEYS[kind])))}")
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
        tree = _sre_parser.parse(pattern)
    except re.error as exc:
        _bad(f"parameter {name}: bad pattern ({exc})")
    if _nested_repeat(tree):
        _bad(f"parameter {name}: pattern repeats a repeated group, which can take exponential time to match")
    if isinstance(max_length, bool) or not isinstance(max_length, int) or not 1 <= max_length <= MAX_VALUE_CHARS:
        _bad(f"parameter {name}: max_length must be 1-{MAX_VALUE_CHARS}")
    dash = spec.get("allow_leading_dash", False)
    if not isinstance(dash, bool):
        _bad(f"parameter {name}: allow_leading_dash must be true or false")
    return {"type": "regex", "pattern": pattern, "max_length": max_length, "allow_leading_dash": dash}


def validate_params(template: Template, given) -> dict[str, str]:
    """Check an agent's values against the template; return them as strings.
    Raises ValueError with a message safe to show the agent."""
    if not isinstance(given, dict):
        _bad("params must be an object")
    extra, missing = set(given) - set(template.params), set(template.params) - set(given)
    if extra:
        _bad(f"unknown parameters: {', '.join(sorted(map(str, extra)))}")
    if missing:
        _bad(f"missing parameters: {', '.join(sorted(missing))}")
    out = {}
    for name, spec in template.params.items():
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
            if not re.fullmatch(spec["pattern"], value) or "\0" in value or "\n" in value:
                _bad(f"{name} does not match the allowed pattern")
            if value.startswith("-") and not spec["allow_leading_dash"]:
                _bad(f"{name} may not start with '-'")
            out[name] = value
    return out


def build_argv(template: Template, values: dict[str, str]) -> list[str]:
    """The exact argument list to run. Each value lands inside one element."""
    argv = [PLACEHOLDER_RE.sub(lambda m: values[m.group(1)], token) for token in template.argv]
    return ["sudo", "-n", *argv] if template.sudo else argv


# --- loading -----------------------------------------------------------------

_lock = threading.Lock()
_state = {"fingerprint": None, "templates": {}, "errors": {}}


def _files():
    base = REPO_DIR / TEMPLATES_REL
    if not base.is_dir():
        return []
    return sorted(p for p in base.iterdir() if p.is_file() and p.suffix in (".yml", ".yaml"))


def load() -> tuple[dict[str, Template], dict[str, str]]:
    """Current templates and per-file errors. Re-reads the folder only when a
    file changed; a file that no longer parses keeps its last good version."""
    files = _files()
    fingerprint = tuple((p.name, p.stat().st_mtime_ns, p.stat().st_size) for p in files)
    with _lock:
        if fingerprint == _state["fingerprint"]:
            return _state["templates"], _state["errors"]
        previous, templates, errors = _state["templates"], {}, {}
        for path in files:
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    _bad(f"file is over {MAX_FILE_BYTES // 1024} KB")
                templates[path.stem] = parse(path.stem, path.read_text())
            except (ValueError, yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
                errors[path.name] = str(exc).splitlines()[0][:300]
                if path.stem in previous:
                    templates[path.stem] = previous[path.stem]
        if len({p.stem for p in files}) != len(files):  # x.yml and x.yaml
            errors["(duplicate ids)"] = "two files share a name; the later one wins"
        _state.update(fingerprint=fingerprint, templates=templates, errors=errors)
        return templates, errors
