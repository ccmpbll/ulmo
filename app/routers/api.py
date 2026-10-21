import json
import re
import threading
import time
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.database import engine
from app.deps import require_agent
from app.models import Agent, Approval, CommandRun, RunHistory
from app.services import agent_runs, agents, approvals, command_library, commands, git_sync, inventory, notifier, playbook_tags, runner

# JSON API for agents (n8n, scripts). It can read playbooks, hosts and runs,
# and start playbooks its role has a grant for (see agents.check_run). Runs go
# through runner.start_run exactly as the UI's Run button does.
router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_agent)])

LOG_TAIL_CHARS = 64 * 1024
# Read twice the cap from the end of the file: colour codes are stripped after
# reading, so some of the window disappears.
LOG_READ_BYTES = 2 * LOG_TAIL_CHARS
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def _log_tail(run_id: int) -> str:
    """Last LOG_TAIL_CHARS of a run's log, colours stripped, without loading a
    multi-MB file per call."""
    path = runner.log_path(run_id)
    if not path.exists():
        return ""
    with path.open("rb") as f:
        size = f.seek(0, 2)
        start = max(0, size - LOG_READ_BYTES)
        f.seek(start)
        raw = f.read()
    if start:  # began mid-line (maybe mid-escape or mid-character): drop the partial line
        raw = raw.partition(b"\n")[2]
    return ANSI_RE.sub("", raw.decode("utf-8", errors="replace"))[-LOG_TAIL_CHARS:]


def _iso(ts: datetime | None) -> str | None:
    # SQLite returns naive datetimes; everything stored is UTC.
    return ts.replace(tzinfo=timezone.utc).isoformat() if ts else None


def _run_json(run: RunHistory) -> dict:
    return {
        "id": run.id,
        "playbook": run.playbook,
        "status": run.status,
        "triggered_by": run.triggered_by,
        "return_code": run.return_code,
        "tags": run.tags,
        "limit": run.limit,
        "started_at": _iso(run.started_at),
        "finished_at": _iso(run.finished_at),
    }


@router.get("/playbooks")
def playbooks():
    cache = playbook_tags.load_cache()
    return {
        "playbooks": [
            {
                "rel_path": pb["rel_path"],
                "name": pb["name"],
                "tags": cache.get(pb["rel_path"], playbook_tags.EMPTY_RESULT)["tags"],
            }
            for pb in git_sync.list_playbooks()
        ]
    }


@router.get("/hosts")
def hosts():
    return {"hosts": inventory.list_hosts()}


@router.get("/runs")
def runs(limit: int = Query(20, ge=1, le=100)):
    query = select(RunHistory).order_by(RunHistory.started_at.desc()).limit(limit)
    with Session(engine) as session:
        return {"runs": [_run_json(r) for r in session.exec(query).all()]}


@router.get("/runs/{run_id}")
def run_detail(run_id: int):
    with Session(engine) as session:
        run = session.get(RunHistory, run_id)
    if run is None:
        raise HTTPException(404, "Run not found")
    return {**_run_json(run), "recap": runner.get_recap(run_id), "log": _log_tail(run_id)}


DEFAULT_WAIT = 20  # seconds POST /commands waits for the result before answering "still running"
MAX_WAIT = 60


class RunRequest(BaseModel):
    playbook: str = Field(max_length=200)
    # Host names, matched exactly against the grants. Bounded because they are echoed in errors and the audit log.
    limit: list[Annotated[str, Field(max_length=100)]] = Field(min_length=1, max_length=50)
    note: str | None = Field(None, max_length=500)  # shown to the admin if the run needs approval


def _deny(request: Request, agent: Agent, status: int, reason: str):
    request.state.audit = (agent.name, reason)  # picked up by the audit middleware
    raise HTTPException(status, reason)


def _approval_json(a: Approval) -> dict:
    out = {
        "id": a.id, "status": a.status, "kind": a.kind, "target": a.target, "host": a.host, "line": a.line,
        "created_at": _iso(a.created_at), "expires_at": _iso(a.expires_at), "decided_at": _iso(a.decided_at),
        "run_id": a.run_id, "note": a.note,
    }
    if a.kind == "command":
        out["params"] = json.loads(a.params)
    if a.run_id:
        out["result_url"] = f"/api/v1/{'commands' if a.kind == 'command' else 'runs'}/{a.run_id}"
    return out


def _request_approval(request: Request, response: Response, agent: Agent, kind: str, target: str, host: str, params: dict, line: str, note: str | None) -> dict:
    """`params` is what the agent sent: approving validates it again, exactly as a direct call would."""
    try:
        approval, created = approvals.create(agent, kind, target, host, params, line, " ".join((note or "").split()))
    except approvals.TooManyPending as exc:
        _deny(request, agent, 429, str(exc))
    request.state.audit = (agent.name, f"{'requested' if created else 'repeated'} approval {approval.id}: {line}")
    if created:  # a retry of a request that is already waiting must not notify again
        threading.Thread(target=notifier.notify_approval, args=(approval,), daemon=True).start()
    response.status_code = 202
    return {"status": "pending_approval", "approval_id": approval.id, "expires_at": _iso(approval.expires_at), "poll": f"/api/v1/approvals/{approval.id}"}


@router.get("/approvals/{approval_id}")
def approval_detail(approval_id: int, request: Request, agent: Agent = Depends(require_agent)):
    """An agent sees only its own requests: the status, and once approved the run to poll."""
    approval = approvals.get(approval_id)
    if approval is None or approval.agent_id != agent.id:
        _deny(request, agent, 404, "Approval not found")
    return _approval_json(approval)


@router.get("/catalog")
def catalog(agent: Agent = Depends(require_agent)):
    """What this agent may run, so it can discover it instead of guessing."""
    library = command_library.load()[0]
    needing = approvals.commands_needing(agent)
    return {
        "runs_enabled": agents.runs_enabled(),
        "playbooks": [
            {"playbook": g.playbook, "hosts": g.hosts.split(","), "requires_approval": g.requires_approval}
            for g in agents.grants_for(agent)
        ],
        "commands": [
            {**library.commands[name].schema(), "hosts": hosts, "requires_approval": name in needing}
            for name, hosts in agents.commands_for(agent).items()
        ],
    }


@router.post("/runs", status_code=202)
def start_run(body: RunRequest, request: Request, response: Response, agent: Agent = Depends(require_agent)):
    try:
        agent_runs.precheck_run(agent, body.playbook, body.limit)
        agent_runs.check_rate(agent)
        if approvals.playbook_needs(agent, body.playbook, body.limit):
            line = f"ansible-playbook {body.playbook} --limit {','.join(body.limit)}"
            return _request_approval(request, response, agent, "playbook", body.playbook, ",".join(body.limit), {}, line, body.note)
        record = agent_runs.launch_run(agent, body.playbook, body.limit)
    except agent_runs.Refused as exc:
        _deny(request, agent, exc.status, exc.reason)
    request.state.audit = (agent.name, f"started run {record.id}: {body.playbook} on {record.limit}")
    return _run_json(record)


@router.post("/runs/{run_id}/cancel")
def cancel_run(run_id: int, request: Request, agent: Agent = Depends(require_agent)):
    """An agent can cancel only its own runs. Works even with the kill switch on."""
    if not agents.owns_run(agent, run_id):
        _deny(request, agent, 404, "Run not found")
    # A run is 'running' in the database a moment before its thread registers a
    # cancel handle, so retry briefly instead of reporting a live run as finished.
    for _ in range(20):
        if runner.cancel_run(run_id):
            return {"id": run_id, "cancelling": True}
        with Session(engine) as session:
            if session.get(RunHistory, run_id).status != "running":
                break
        time.sleep(0.05)
    _deny(request, agent, 409, "run is not running")


class CommandRequest(BaseModel):
    command: str = Field(max_length=60)
    host: str = Field(max_length=100)
    params: dict = Field(default_factory=dict, max_length=20)
    note: str | None = Field(None, max_length=500)  # shown to the admin if the call needs approval


def _command_json(run: CommandRun, with_output: bool = False) -> dict:
    out = {
        "id": run.id,
        "command": run.command,
        "host": run.host,
        "params": json.loads(run.params),
        "line": run.line,
        "status": run.status,
        "return_code": run.return_code,
        "started_at": _iso(run.started_at),
        "finished_at": _iso(run.finished_at),
    }
    if with_output:
        out["output"] = run.output
    return out


@router.post("/commands", status_code=202)
def start_command(
    body: CommandRequest,
    request: Request,
    response: Response,
    wait: float = Query(DEFAULT_WAIT, ge=0, le=MAX_WAIT),
    agent: Agent = Depends(require_agent),
):
    """Run a library command on one host over SSH. Waits up to `wait` seconds for it
    to finish and, if it does, answers 200 with the status and output. Otherwise 202
    ("running"): poll GET /commands/{id}. The command keeps running either way. A command
    the role marks as needing approval answers 202 "pending_approval" instead and runs
    only once an admin approves it: poll GET /approvals/{id}."""
    try:
        template, host, values = agent_runs.precheck_command(agent, body.command, body.host, body.params)
        agent_runs.check_rate(agent)
        if template.id in approvals.commands_needing(agent):
            return _request_approval(request, response, agent, "command", template.id, host.name, body.params, agent_runs.command_line(template, values), body.note)
        run = agent_runs.launch_command(agent, template, host, values)
    except agent_runs.Refused as exc:
        _deny(request, agent, exc.status, exc.reason)
    request.state.audit = (agent.name, f"started command {run.id}: {template.id} on {body.host}")
    deadline = time.monotonic() + wait
    while run.status == "running" and time.monotonic() < deadline:
        time.sleep(0.1)
        with Session(engine) as session:
            run = session.get(CommandRun, run.id)
    if run.status != "running":
        response.status_code = 200
    return _command_json(run, with_output=run.status != "running")


@router.get("/commands/{run_id}")
def command_detail(run_id: int, request: Request, agent: Agent = Depends(require_agent)):
    """A command's output can hold anything the host printed, so an agent sees only its own."""
    with Session(engine) as session:
        run = session.get(CommandRun, run_id)
    if run is None or run.agent_id != agent.id:
        _deny(request, agent, 404, "Command run not found")
    return _command_json(run, with_output=True)
