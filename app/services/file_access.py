"""What an agent may do with the workspace files, and how an edit it proposes is checked and applied.

Each agent has a setting, `file_access`:

    none        no file access (the default)
    playbooks   read the playbooks, and propose edits to them (the .yaml/.yml files in the playbooks folder)
    all         read and propose edits to any file in the workspace

An agent never writes a file. A proposed edit is recorded as an Approval of kind "file" and waits for an
admin, who sees the diff (with line numbers) and the grants that point at the playbook. Approving writes
it through the same locked, version-checked save the Files page uses, so it is refused while a playbook
runs and if the file changed after the agent read it. Reads are never limited by the kill switch.
"""
import difflib
import json

from sqlmodel import Session, select

from app.database import engine
from app.models import Agent, Approval, Grant, Role, utcnow
from app.services import agent_runs, textcheck, workspace

MODES = ("none", "playbooks", "all")
MODE_LABELS = {"none": "no files", "playbooks": "playbooks only", "all": "all files"}
MAX_TEXT_BYTES = 256 * 1024  # an edit an admin must read through, so well under the editor's limit
Refused = agent_runs.Refused


def clean_mode(value: str) -> str:
    value = (value or "").strip()
    if value not in MODES:
        raise ValueError(f"File access must be one of: {', '.join(MODES)}.")
    return value


def mode_of(agent: Agent) -> str:
    return agent.file_access if agent.file_access in MODES else "none"


def _require(agent: Agent) -> str:
    mode = mode_of(agent)
    if mode == "none":
        raise Refused(403, "this agent has no file access")
    return mode


def in_scope(agent: Agent, rel: str) -> bool:
    mode = mode_of(agent)
    return mode == "all" or (mode == "playbooks" and workspace.is_playbook_path(rel))


def list_for(agent: Agent) -> list[dict]:
    """The files this agent may read: {path, size, modified}."""
    _require(agent)
    return [
        {"path": f["rel_path"], "size": f["size"], "modified": f["modified"]}
        for f in workspace.list_files() if in_scope(agent, f["rel_path"])
    ]


def read_for(agent: Agent, path: str) -> dict:
    """{path, version, text} for a file in scope, or Refused."""
    _require(agent)
    try:
        rel = workspace.clean(path)
    except ValueError as exc:
        raise Refused(400, str(exc))
    if not in_scope(agent, rel):
        raise Refused(403, "this agent may not read that file")
    try:
        info = workspace.read_file(rel)
    except ValueError:
        raise Refused(404, "no such file")
    if info["text"] is None:
        raise Refused(415, "that file is binary or too large to read as text")
    return {"path": rel, "version": info["version"], "text": info["text"]}


def check_edit(agent: Agent, path: str, text: str, base: str) -> tuple[str, str]:
    """Everything that can refuse a proposed edit; returns (rel path, text with LF line breaks)."""
    _require(agent)
    try:
        rel = workspace.clean(path)
    except ValueError as exc:
        raise Refused(400, str(exc))
    if not in_scope(agent, rel):
        raise Refused(403, "this agent may only edit playbooks" if mode_of(agent) == "playbooks" else "this agent may not edit that file")
    text = text.replace("\r\n", "\n")
    if len(text.encode()) > MAX_TEXT_BYTES:
        raise Refused(413, f"an edit is limited to {MAX_TEXT_BYTES // 1024} KB")
    bad = textcheck.bad_char(text)
    if bad:
        raise Refused(400, f"the text contains a control, zero-width, invisible or direction-override character (U+{ord(bad):04X})")
    try:
        current = workspace.read_file(rel)
    except ValueError:
        current = None
    if current is not None and current["text"] is None:
        raise Refused(415, "that file is binary or too large to edit as text")
    if base != (current["version"] if current else ""):
        raise Refused(409, "the file changed since you read it; read it again" if current else "that file does not exist; send base as an empty string to create it" if base else "that file already exists; read it and send its version as base")
    if current is not None and workspace.keep_line_endings(rel, text) == current["text"]:
        raise Refused(400, "this changes nothing")
    return rel, text


def line_for(rel: str, old: str | None, new: str) -> str:
    """The one-line summary shown in lists: what is edited and how much."""
    added, removed = count_changes(old or "", new)
    return f"{'create' if old is None else 'edit'} {rel} (+{added} -{removed})"


def count_changes(old: str, new: str) -> tuple[int, int]:
    added = removed = 0
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, old.splitlines(), new.splitlines(), autojunk=False).get_opcodes():
        removed += i2 - i1 if tag in ("replace", "delete") else 0
        added += j2 - j1 if tag in ("replace", "insert") else 0
    return added, removed


def diff_rows(old: str, new: str, context: int = 3) -> list[dict]:
    """A diff for the approval page, with line numbers: rows of {kind: ctx|add|del|gap, old_no, new_no, text}.
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


def view(approval: Approval) -> dict:
    """What the approval page shows for a pending edit: the diff against the file as it is now, whether
    the edit can still be applied, which roles are granted this playbook, and anything odd in the text."""
    params = json.loads(approval.params)
    rel, new, base = approval.target, params.get("text", ""), params.get("base", "")
    try:
        current = workspace.read_file(rel)
    except ValueError:
        current = None
    old = None if current is None else current["text"]
    problem = ""
    if current is not None and current["text"] is None:
        problem = "the file is binary or too large to edit as text"
    elif base != (current["version"] if current else ""):
        problem = "the file changed after the agent read it, so this edit can no longer be applied. Deny it and let the agent read the file again."
    with Session(engine) as session:
        grants = session.exec(select(Grant).where(Grant.playbook == rel)).all()
        roles = {r.id: r.name for r in session.exec(select(Role)).all()}
    odd = sorted({c for c in new if ord(c) > 127})
    return {
        "path": rel,
        "is_new": current is None,
        "rows": diff_rows(old or "", new),
        "added": count_changes(old or "", new)[0], "removed": count_changes(old or "", new)[1],
        "problem": problem,
        "grants": [{"role": roles.get(g.role_id, "?"), "hosts": g.hosts.split(","), "requires_approval": g.requires_approval} for g in grants],
        "odd": [f"{c} (U+{ord(c):04X})" for c in odd][:20],
        "locked_by": workspace.active_runs(),
    }


def apply(approval: Approval) -> str:
    """Write an approved edit, repeating the checks a proposal gets (the agent, its access and the file
    may have changed while it waited). Returns a warning to show the admin, or "". Raises Refused."""
    with Session(engine) as session:
        agent = session.get(Agent, approval.agent_id)
    if agent is None or not agent.enabled or (agent.expires_at is not None and agent.expires_at <= utcnow().replace(tzinfo=None)):
        raise Refused(403, "the agent is disabled, expired or deleted")
    params = json.loads(approval.params)
    rel, text = check_edit(agent, approval.target, params["text"], params["base"])
    try:
        workspace.store(rel, workspace.keep_line_endings(rel, text).encode(), base=params["base"])
    except workspace.Locked as exc:
        raise Refused(423, str(exc))
    except workspace.Conflict as exc:
        raise Refused(409, str(exc))
    except ValueError as exc:
        raise Refused(400, str(exc))
    return workspace.check_syntax(rel, text) or workspace.check_playbook(rel) or ""
