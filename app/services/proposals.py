"""Change proposals: how a script asks for commands or roles to change, and how an admin says yes.

A proposer token (not an agent token) can read commands.yml and the roles and send a proposal:
a list of operations that are applied together or not at all. Nothing is applied until a signed-in
admin approves it on its page. That page shows the diff, and the Approve button carries a digest of
what was shown; if anything it covers changed since, the approval is refused. Applying goes through
the same locked, validated write as the Commands page (one saved copy, restorable) and the same
role tables as the Agents page.

Operations (library changes are applied first, in order, then role changes, in order):

    save_command       {name, body, samples?}          create or replace one command
    delete_command     {name}                          not while a host still offers it
    host_offer         {host, add?, remove?}           commands a host offers (delta, strict)
    role_allow         {role, add?: [{command, needs_approval}], remove?}
    role_set_approval  {role, command, needs_approval}
    save_file          {path, text, base}              create or replace one workspace file (any file, not only a playbook)

File edits are their own kind of proposal: a proposal that has a save_file operation has only save_file
operations (a file and a command are applied by different code, and mixing them could leave one done and
the other not). `text` is the whole new file; `base` is the version the file was read at, "" to create
it, so an edit made against a file that has since changed is refused. They are applied together or not
at all, through the same locked, version-checked write the Files page uses, and not while a playbook runs.

Deltas are strict: adding what is already there or removing what is not fails, so a stale
proposal fails instead of silently doing something else. Hosts' addresses, users, keys and
passwords, agents, tokens, playbook grants and limits cannot be touched from here.
"""
import copy
import difflib
import hashlib
import hmac
import json
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import timedelta

from sqlmodel import Session, delete, func, select, update

from app.database import engine
from app.models import AdminToken, Approval, Grant, Proposal, Role, RoleCommand, utcnow
from app.services import agents, approvals, command_library as cl, commands, textcheck, workspace

TOKEN_PREFIX = "ulmo_admin_"
EXPIRY = timedelta(hours=24)  # a human reads these, so a day, not minutes
MAX_PENDING_PER_TOKEN = 10
MAX_OPS = 20
MAX_CALLS_PER_HOUR = 60  # proposals and dry runs per token: each one plans against the whole library
KEEP = 200  # newest proposals kept

SPECS = {  # operation -> (required keys, optional keys)
    "save_command": (("name", "body"), ("samples",)),
    "delete_command": (("name",), ()),
    "host_offer": (("host",), ("add", "remove")),
    "role_allow": (("role",), ("add", "remove")),
    "role_set_approval": (("role", "command", "needs_approval"), ()),
    "save_file": (("path", "text", "base"), ()),
}
LIBRARY_OPS = ("save_command", "delete_command", "host_offer")
FILE_OPS = ("save_file",)
MAX_FILE_TEXT = 256 * 1024  # a file an admin must read through, per file
MAX_FILE_TOTAL = 1024 * 1024  # and per proposal


class Unavailable(ValueError):
    """commands.yml on disk does not parse, so nothing can be planned against it."""


def _bad(msg: str):
    raise ValueError(msg)


# --- tokens -------------------------------------------------------------------------------------


def create_token(name: str, expires_days: int | None = None) -> tuple[AdminToken, str]:
    """Create a proposer token and return it with its plaintext (shown once, never stored)."""
    name = agents.check_token_args(name, expires_days)
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    with Session(engine) as session:
        if session.exec(select(AdminToken).where(AdminToken.name == name)).first():
            _bad(f"A token named {name!r} already exists.")
        row = AdminToken(
            name=name, token_hash=agents.hash_token(token),
            expires_at=utcnow() + timedelta(days=expires_days) if expires_days else None,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return row, token


def authenticate(token: str) -> tuple[AdminToken | None, str]:
    """(token row, "") for an enabled, unexpired token; otherwise (row or None, reason for the audit log only)."""
    with Session(engine) as session:
        row = session.exec(select(AdminToken).where(AdminToken.token_hash == agents.hash_token(token))).first()
        if row is None:
            return None, "unknown token"
        return row, agents.token_state(session, row, "token disabled")


def _token_problem(token_id: int) -> str:
    """Why a proposal's token can no longer stand behind it: a proposal from a token that was
    disabled, has expired or is gone is not applied, so disabling a leaked token revokes what it queued."""
    with Session(engine) as session:
        row = session.get(AdminToken, token_id)
        if row is None:
            return "its change token was deleted"
        reason = agents.token_state(session, row, "its change token is disabled", touch=False)
    return reason and ("its change token has expired" if reason == "token expired" else reason)


def list_tokens() -> list[AdminToken]:
    with Session(engine) as session:
        return list(session.exec(select(AdminToken).order_by(AdminToken.name)).all())


def toggle_token(token_id: int) -> None:
    agents.toggle_enabled(token_id, AdminToken)


def delete_token(token_id: int) -> None:
    with Session(engine) as session:
        row = session.get(AdminToken, token_id)
        if row is not None:
            # SQLite reuses the id of a deleted last row; a new token must not inherit old proposals.
            session.exec(delete(Proposal).where(Proposal.token_id == token_id))
            session.delete(row)
            session.commit()
    _calls.pop(token_id, None)


# --- operations ---------------------------------------------------------------------------------


def _plain_text(value) -> None:
    """Refuse control, zero-width and direction-override characters anywhere in an operation: they
    would make the diff an admin reads differ from what is saved and run (the note is cleaned the
    same way). Newlines and tabs are fine, the YAML dump shows them as escapes."""
    if isinstance(value, str):
        bad = textcheck.bad_char(value)
        if bad:
            _bad(f"contains a control, zero-width, invisible or direction-override character (U+{ord(bad):04X})")
    elif isinstance(value, dict):
        for key, item in value.items():
            _plain_text(key)
            _plain_text(item)
    elif isinstance(value, list):
        for item in value:
            _plain_text(item)


def _check_op(op) -> dict:
    if not isinstance(op, dict):
        _bad("each operation must be an object")
    kind = op.get("op")
    if kind not in SPECS:
        _bad(f"unknown operation {kind!r}; use one of: {', '.join(SPECS)}")
    required, optional = SPECS[kind]
    _keys(op, required, optional + ("op",))
    if kind in FILE_OPS:
        if not all(isinstance(op[k], str) for k in required):
            _bad("path, text and base must be text")
        op = {**op, "text": op["text"].replace("\r\n", "\n")}  # a browser or a Windows script sends CRLF; the file keeps its own endings
    _plain_text(op)
    return op


def _keys(obj: dict, required: tuple, allowed: tuple) -> None:
    unknown = sorted(map(str, set(obj) - set(required) - set(allowed)))
    if unknown:
        _bad(f"unknown keys: {', '.join(unknown)}")
    missing = [k for k in required if k not in obj]
    if missing:
        _bad(f"missing keys: {', '.join(missing)}")


def _name(value, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _bad(f"{what} must be a name")
    return value.strip()


def _names(value, what: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        _bad(f"{what} must be a list of names")
    names = [v.strip() for v in value]
    if len(set(names)) != len(names):
        _bad(f"{what} lists a name twice")
    return names


def _flag(value) -> bool:
    if not isinstance(value, bool):
        _bad("needs_approval must be true or false")
    return value


def _apply_library_op(data: dict, op: dict) -> None:
    """Change `data` (the file's contents) the way the Commands page would."""
    kind = op["op"]
    if kind == "save_command":
        name = _name(op["name"], "name")
        if len(cl.dump_yaml(op["body"]).encode()) > cl.MAX_COMMAND_BYTES:  # the editor's per-command limit
            _bad(f"a command is limited to {cl.MAX_COMMAND_BYTES // 1024} KB")
        # The rest of the editor's checks run on the whole file below.
        data["commands"][name] = copy.deepcopy(op["body"])
    elif kind == "delete_command":
        name = _name(op["name"], "name")
        if name not in data["commands"]:
            _bad(f"no such command: {name}")
        users = sorted(h for h, v in data["hosts"].items() if name in (v or {}).get("commands", []))
        if users:
            _bad(f"still offered by: {', '.join(users)}. Remove it from those hosts first.")
        del data["commands"][name]
    else:  # host_offer
        host = _name(op["host"], "host")
        if host not in data["hosts"]:
            _bad(f"no such host: {host}")
        add, remove = _names(op.get("add"), "add"), _names(op.get("remove"), "remove")
        if not add and not remove:
            _bad("give add or remove (or both)")
        offered = list(data["hosts"][host].get("commands") or [])
        missing = [c for c in add if c not in data["commands"]]
        if missing:
            _bad(f"commands that do not exist: {', '.join(missing)}")
        already = [c for c in add if c in offered]
        if already:
            _bad(f"already offered by {host}: {', '.join(already)}")
        absent = [c for c in remove if c not in offered]
        if absent:
            _bad(f"not offered by {host}: {', '.join(absent)}")
        data["hosts"][host]["commands"] = [c for c in offered if c not in remove] + add


def _apply_role_op(roles: dict, op: dict, library: cl.Library) -> None:
    """Change `roles` (role name -> {command: needs_approval}) the way the Agents page would."""
    role = _name(op["role"], "role")
    if role not in roles:
        _bad(f"no such role: {role}")
    held = roles[role]
    if op["op"] == "role_set_approval":
        command = _name(op["command"], "command")
        if command not in held:
            _bad(f"{role} does not have: {command}")
        held[command] = _flag(op["needs_approval"])
        return
    add, remove = op.get("add") or [], _names(op.get("remove"), "remove")
    if not isinstance(add, list):
        _bad("add must be a list of {command, needs_approval}")
    if not add and not remove:
        _bad("give add or remove (or both)")
    entries = {}
    for entry in add:
        if not isinstance(entry, dict):
            _bad("add must be a list of {command, needs_approval}")
        _keys(entry, ("command", "needs_approval"), ())
        command = _name(entry["command"], "command")
        if command in entries:
            _bad(f"add lists {command} twice")
        entries[command] = _flag(entry["needs_approval"])
    unknown = sorted(set(entries) - set(library.commands))
    if unknown:
        _bad(f"not in the command library: {', '.join(unknown)}")
    already = sorted(set(entries) & set(held))
    if already:
        _bad(f"{role} already has: {', '.join(already)}")
    absent = sorted(set(remove) - set(held))
    if absent:
        _bad(f"{role} does not have: {', '.join(absent)}")
    for command in remove:
        del held[command]
    held.update(entries)


def summarize(ops: list[dict]) -> str:
    """A short line naming what the operations touch, for the audit log and the notification."""
    parts = []
    for op in ops:
        target = op.get("name") or op.get("host") or op.get("role") or op.get("path") or "?"
        parts.append(f"{op.get('op')} {target}" + (f" ({op['command']})" if op.get("op") == "role_set_approval" else ""))
    return "; ".join(parts)


# --- planning -----------------------------------------------------------------------------------


@dataclass
class Plan:
    data_after: dict
    roles_before: dict
    roles_after: dict
    library_diff: str
    roles_diff: str
    previews: list = field(default_factory=list)
    digest: str = ""
    base: str = ""
    warnings: list = field(default_factory=list)

    @property
    def diff(self) -> str:
        return "\n".join(part for part in (self.library_diff, self.roles_diff) if part)


@dataclass
class FilePlan:
    """What applying a file proposal would do: one entry per file, and the writes that make it so."""
    edits: list
    writes: list  # (path, bytes, base)
    diff: str
    digest: str
    previews: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    kind: str = "files"


def count_changes(old: str, new: str) -> tuple[int, int]:
    added = removed = 0
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, old.splitlines(), new.splitlines(), autojunk=False).get_opcodes():
        removed += i2 - i1 if tag in ("replace", "delete") else 0
        added += j2 - j1 if tag in ("replace", "insert") else 0
    return added, removed


def diff_rows(old: str, new: str, context: int = 3) -> list[dict]:
    """A diff for the proposal page, with line numbers: rows of {kind: ctx|add|del|gap, old_no, new_no, text}.
    A gap row stands for lines left out because nothing near them changed."""
    a, b = old.splitlines(), new.splitlines()
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    rows: list[dict] = []
    seen_a = 0  # lines of `a` shown or skipped so far
    for group in matcher.get_grouped_opcodes(context):
        first = group[0]
        if first[1] > seen_a:
            rows.append({"kind": "gap", "skipped": first[1] - seen_a})
        for tag, i1, i2, j1, j2 in group:
            if tag == "equal":
                rows += [{"kind": "ctx", "old_no": i + 1, "new_no": j + 1, "text": a[i]} for i, j in zip(range(i1, i2), range(j1, j2))]
            else:
                rows += [{"kind": "del", "old_no": i + 1, "new_no": None, "text": a[i]} for i in range(i1, i2)]
                rows += [{"kind": "add", "old_no": None, "new_no": j + 1, "text": b[j]} for j in range(j1, j2)]
        seen_a = group[-1][2]
    if rows and seen_a < len(a):
        rows.append({"kind": "gap", "skipped": len(a) - seen_a})
    return rows


def _plan_files(ops: list) -> FilePlan:
    """Plan a proposal of save_file operations against the files as they are now."""
    checked = []
    for i, op in enumerate(ops, 1):
        try:
            checked.append(_check_op(op))
        except ValueError as exc:
            raise ValueError(f"op {i}: {exc}") from None
    if any(op["op"] not in FILE_OPS for op in checked):
        _bad("file edits cannot be mixed with command or role changes: send them as separate proposals")
    edits, writes, seen, total = [], [], set(), 0
    for i, op in enumerate(checked, 1):
        try:
            rel = workspace.clean(op["path"])
            if rel in seen:
                _bad(f"{rel} is edited twice")
            seen.add(rel)
            text = op["text"]
            if len(text.encode()) > MAX_FILE_TEXT:
                _bad(f"{rel}: a file edit is limited to {MAX_FILE_TEXT // 1024} KB")
            total += len(text.encode())
            if total > MAX_FILE_TOTAL:
                _bad(f"a proposal is limited to {MAX_FILE_TOTAL // 1024} KB of file text")
            try:
                current = workspace.read_file(rel)
            except ValueError:
                current = None
            if current is not None and current["text"] is None:
                _bad(f"{rel} is binary or too large to edit as text")
            if op["base"] != (current["version"] if current else ""):
                if current is None:
                    _bad(f"{rel} does not exist; send base as an empty string to create it")
                if op["base"] == "":
                    _bad(f"{rel} already exists; read it and send its version as base")
                _bad(f"{rel} changed since it was read, so this edit no longer fits")
            body = workspace.keep_line_endings(rel, text)
            if current is not None and body == current["text"]:
                _bad(f"{rel}: this changes nothing")
        except ValueError as exc:
            raise ValueError(f"op {i} (save_file): {exc}") from None
        old = None if current is None else current["text"]
        added, removed = count_changes(old or "", text)
        with Session(engine) as session:
            grants = session.exec(select(Grant).where(Grant.playbook == rel)).all()
            role_names = {r.id: r.name for r in session.exec(select(Role)).all()}
        edits.append({
            "path": rel, "is_new": current is None, "rows": diff_rows(old or "", text), "added": added, "removed": removed,
            "grants": [{"role": role_names.get(g.role_id, "?"), "hosts": g.hosts.split(","), "requires_approval": g.requires_approval} for g in grants],
            "is_playbook": workspace.is_playbook_path(rel),
        })
        writes.append((rel, body.encode(), op["base"]))
    try:
        workspace.check_collisions([w[0] for w in writes])
    except ValueError as exc:
        _bad(f"op (save_file): {exc}")
    diff = "\n".join(
        _diff("" if e["is_new"] else (workspace.read_file(e["path"])["text"] or ""), t, e["path"], 2)
        for e, t in ((e, o["text"]) for e, o in zip(edits, checked))
    )
    shown = json.dumps([[e["path"], w[2], o["text"]] for e, w, o in zip(edits, writes, checked)], sort_keys=True)
    added_text = "".join(o["text"] for o in checked)
    odd = sorted({c for c in added_text if ord(c) > 127})
    warnings = [f"The new text has non-ASCII characters, which can look like plain letters: {', '.join(f'{c} (U+{ord(c):04X})' for c in odd[:20])}"] if odd else []
    return FilePlan(edits, writes, diff, hashlib.sha256(shown.encode()).hexdigest(), [], warnings)


def roles_state() -> dict[str, dict[str, bool]]:
    """role name -> {command: needs approval}."""
    with Session(engine) as session:
        roles = session.exec(select(Role)).all()
        rows = session.exec(select(RoleCommand)).all()
    return {r.name: {c.command: c.requires_approval for c in rows if c.role_id == r.id} for r in roles}


def _roles_text(state: dict) -> str:
    lines = []
    for name in sorted(state):
        lines.append(name)
        lines += [f"  {c}" + (" [needs approval]" if state[name][c] else "") for c in sorted(state[name])]
    return "\n".join(lines) + "\n"


def _diff(old: str, new: str, label: str, context: int) -> str:
    return "\n".join(difflib.unified_diff(old.splitlines(), new.splitlines(), f"{label} (current)", f"{label} (proposed)", lineterm="", n=context))


def plan(ops: list) -> Plan:
    """Work out what applying `ops` would do, changing nothing. Raises ValueError saying which
    operation is wrong (Unavailable if commands.yml does not parse)."""
    if not isinstance(ops, list) or not 1 <= len(ops) <= MAX_OPS:
        _bad(f"send between 1 and {MAX_OPS} operations")
    if any(isinstance(op, dict) and op.get("op") in FILE_OPS for op in ops):
        return _plan_files(ops)
    with cl.LOCK:
        library, error = cl.load()
        if error:
            raise Unavailable(f"commands.yml on disk does not parse ({error}); fix or restore it on the Commands page first")
        base, before = cl.current_version(), cl.raw_data()
        after = copy.deepcopy(before)
        roles_before = roles_state()
    checked = []
    for i, op in enumerate(ops, 1):
        try:
            checked.append(_check_op(op))
        except ValueError as exc:
            raise ValueError(f"op {i}: {exc}") from None

    def run(selected, apply):
        for i, op in selected:
            try:
                apply(op)
            except ValueError as exc:
                raise ValueError(f"op {i} ({op['op']}): {exc}") from None

    numbered = list(enumerate(checked, 1))
    run([(i, o) for i, o in numbered if o["op"] in LIBRARY_OPS], lambda o: _apply_library_op(after, o))
    try:
        new_library = cl.validate(after)
    except ValueError as exc:
        raise ValueError(f"the library would not be valid: {exc}") from None
    after_text = cl.dump_yaml(after)
    if len(after_text.encode()) > cl.MAX_FILE_BYTES:
        _bad(f"the file would be over {cl.MAX_FILE_BYTES // 1024} KB")

    roles_after = {name: {c: f for c, f in held.items() if c in new_library.commands} for name, held in roles_before.items()}  # a deleted command leaves every role
    run([(i, o) for i, o in numbered if o["op"] not in LIBRARY_OPS], lambda o: _apply_role_op(roles_after, o, new_library))

    previews = []
    for i, op in numbered:
        if op["op"] == "save_command":
            try:
                line = _preview(new_library.commands[op["name"].strip()], op.get("samples"))
            except ValueError as exc:
                raise ValueError(f"op {i} (save_command): samples: {exc}") from None
            if line is not None:
                previews.append({"command": op["name"].strip(), "line": line})

    before_text = cl.dump_yaml(before)
    library_diff = _diff(before_text, after_text, "commands.yml", 2) if before_text != after_text else ""
    roles_diff = _diff(_roles_text(roles_before), _roles_text(roles_after), "roles", 1) if roles_before != roles_after else ""
    if not library_diff and not roles_diff:
        _bad("this changes nothing")
    shown = json.dumps([before_text, after_text, _roles_text(roles_before), _roles_text(roles_after), previews], sort_keys=True)
    added = "\n".join(line[1:] for line in f"{library_diff}\n{roles_diff}".splitlines() if line.startswith("+") and not line.startswith("+++"))
    odd = sorted({c for c in added if ord(c) > 127})
    warnings = [f"The change adds non-ASCII characters, which can look like plain letters: {', '.join(f'{c} (U+{ord(c):04X})' for c in odd)}"] if odd else []
    return Plan(after, roles_before, roles_after, library_diff, roles_diff, previews, hashlib.sha256(shown.encode()).hexdigest(), base, warnings)


def _preview(template: cl.Template, samples) -> str | None:
    """The Preview line from the Commands page: what the host would receive. None when no sample
    values were given and the command has blanks that need them."""
    if samples is None:
        if any(not spec.get("optional") for spec in template.params.values()):
            return None
        samples = {}
    values = cl.validate_params(template, samples)
    return commands.remote_command(cl.build_argv(template, values), template.timeout)


def _write_roles(target: dict, current: dict) -> None:
    """Make the roles whose entries differ between `target` and `current` match `target`, in one
    transaction, after checking the database still holds `current` for them (a role edited on the
    Agents page since the plan was made is not overwritten)."""
    try:
        with Session(engine) as session:
            for name, wanted in target.items():
                if wanted == current.get(name):
                    continue
                role = session.exec(select(Role).where(Role.name == name)).first()
                if role is None:
                    _bad(f"no such role: {name}")
                rows = session.exec(select(RoleCommand).where(RoleCommand.role_id == role.id)).all()
                if {r.command: r.requires_approval for r in rows} != current.get(name, {}):
                    _bad(f"role {name} was changed meanwhile")
                session.exec(delete(RoleCommand).where(RoleCommand.role_id == role.id))
                for command in sorted(wanted):
                    session.add(RoleCommand(role_id=role.id, command=command, requires_approval=wanted[command]))
            session.commit()
    except ValueError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"the roles could not be updated: {exc}") from None


def _apply_files(plan_: FilePlan) -> str:
    """Write a file plan, all or nothing. Returns a warning for the admin (a playbook that does not
    parse or pass --syntax-check), or "". The write is refused while a playbook runs."""
    try:
        workspace.store_checked(plan_.writes)
    except workspace.Locked as exc:
        raise ValueError(str(exc)) from None
    warnings = []
    for rel, data, _base in plan_.writes:
        text = data.decode("utf-8", errors="replace")
        warning = workspace.check_syntax(rel, text) or workspace.check_playbook(rel)
        if warning:
            warnings.append(warning)
    return " ".join(warnings)


def _apply(plan_: Plan) -> None:
    """Write a plan, all or nothing. The caller holds cl.LOCK and has just built the plan under it.
    The roles go first (one transaction, so if they fail nothing has changed); if the library write
    then fails, they are put back. A write that fails after the new file was already swapped in (the
    folder sync) did land: the roles stay, so the two agree."""
    if plan_.roles_diff:
        _write_roles(plan_.roles_after, plan_.roles_before)
    if not plan_.library_diff:
        return
    try:
        cl.apply_data(plan_.data_after, plan_.base)  # one saved copy for every library operation
    except BaseException:
        if plan_.roles_diff and cl.current_version() == plan_.base:  # the file is unchanged: the write did not happen
            _write_roles(plan_.roles_before, plan_.roles_after)
        raise


# --- proposals ----------------------------------------------------------------------------------


def expire_stale() -> None:
    with Session(engine) as session:
        session.exec(update(Proposal).where(Proposal.status == "pending", Proposal.expires_at < utcnow()).values(status="expired"))
        session.commit()


def propose(token: AdminToken, ops: list, note: str | None = None, dry_run: bool = False) -> tuple[Proposal | None, Plan, bool]:
    """Check the operations against the current state; unless `dry_run`, record the proposal.
    Returns (proposal or None, plan, created). An identical proposal already waiting is returned
    as it is, so a retrying script does not pile up copies."""
    _admit_call(token)
    result = plan(ops)
    if dry_run:
        return None, result, False
    ops_json = json.dumps(ops)  # as sent, key order included: a command's keys are saved in the order given
    canonical = json.dumps(ops, sort_keys=True)
    expire_stale()
    row, created = approvals.enqueue(
        Proposal, Proposal.token_id, token.id, lambda row: json.dumps(json.loads(row.ops), sort_keys=True) == canonical,
        MAX_PENDING_PER_TOKEN, f"{MAX_PENDING_PER_TOKEN} proposals from this token are already waiting", KEEP,
        lambda: Proposal(token_id=token.id, token_name=token.name, ops=ops_json, note=approvals.clean_note(note), expires_at=utcnow() + EXPIRY),
    )
    return row, result, created


_calls: dict[int, deque] = {}
_calls_lock = threading.Lock()


def _admit_call(token: AdminToken) -> None:
    """Count one propose or dry-run call against the token's hourly allowance, or refuse it (429)."""
    now = time.monotonic()
    with _calls_lock:
        recent = _calls.setdefault(token.id, deque())
        while recent and now - recent[0] > 3600:
            recent.popleft()
        if len(recent) >= MAX_CALLS_PER_HOUR:
            raise approvals.TooManyPending(f"rate limit: {MAX_CALLS_PER_HOUR} proposals per hour")
        recent.append(now)


def get(proposal_id: int) -> Proposal | None:
    expire_stale()
    with Session(engine) as session:
        return session.get(Proposal, proposal_id)


def pending() -> list[Proposal]:
    expire_stale()
    with Session(engine) as session:
        return list(session.exec(select(Proposal).where(Proposal.status == "pending").order_by(Proposal.id)).all())


def recent() -> list[Proposal]:
    expire_stale()
    with Session(engine) as session:
        return list(session.exec(select(Proposal).where(Proposal.status != "pending").order_by(Proposal.id.desc()).limit(50)).all())


def for_token(token_id: int) -> list[Proposal]:
    expire_stale()
    with Session(engine) as session:
        return list(session.exec(select(Proposal).where(Proposal.token_id == token_id).order_by(Proposal.id.desc()).limit(50)).all())


def waiting_total() -> int:
    """Approvals and proposals waiting, for the top bar on every page: one statement, no write (an
    expired one is simply not counted)."""
    now = utcnow()

    def count(model):
        return select(func.count()).select_from(model).where(model.status == "pending", model.expires_at >= now).scalar_subquery()

    with Session(engine) as session:
        return session.exec(select(count(Approval) + count(Proposal))).one()


def view(proposal: Proposal) -> tuple[Plan | None, str]:
    """The current plan of a proposal for its page, or the reason it can no longer be applied."""
    problem = _token_problem(proposal.token_id)
    if problem:
        return None, problem
    try:
        return plan(json.loads(proposal.ops)), ""
    except ValueError as exc:
        return None, str(exc)


def decide(proposal_id: int, approve: bool, admin: str, seen: str = "") -> Proposal:
    """Deny, or apply, a pending proposal. Applying re-plans against the state as it is now and
    only goes ahead if that is exactly what the admin saw (`seen`). A proposal that can no longer
    be applied is marked failed. Raises ValueError if it is not pending or what was seen is stale."""
    expire_stale()
    with cl.LOCK:
        row = get(proposal_id)
        if row is None:
            _bad("No such proposal.")
        if row.status != "pending":
            _bad(f"This proposal is already {row.status}.")
        status, result = "denied", ""
        if approve:
            try:
                problem = _token_problem(row.token_id)
                if problem:
                    _bad(problem)
                current = plan(json.loads(row.ops))
            except Unavailable:
                raise  # commands.yml is being fixed by hand: nothing is wrong with the proposal, so it is not used up
            except ValueError as exc:
                status, result = "failed", str(exc)
            else:
                if not hmac.compare_digest(current.digest.encode(), (seen or "").encode()):
                    _bad("This proposal, commands.yml, the roles or the files changed since you opened it. Reload the page and look again.")
                if isinstance(current, FilePlan) and workspace.active_runs():
                    # Not decided: it stays pending, to approve again once the run is over.
                    _bad(f"The files are read-only while run #{workspace.active_runs()[0]['run_id']} is going. Try again when it finishes.")
                try:
                    if isinstance(current, FilePlan):
                        status, result = "applied", _apply_files(current)
                    else:
                        _apply(current)
                        status = "applied"
                except Exception as exc:  # noqa: BLE001 - whatever stopped it is shown to the admin; nothing was half-applied
                    status, result = "failed", str(exc)
        with Session(engine) as session:
            session.exec(update(Proposal).where(Proposal.id == proposal_id).values(status=status, result=result[:500], decided_by=admin, decided_at=utcnow()))
            session.commit()
    return get(proposal_id)
