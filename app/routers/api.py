import re
import threading
import time
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.database import engine
from app.deps import require_agent
from app.models import Agent, RunHistory
from app.services import agents, git_sync, inventory, playbook_tags, runner

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


MAX_AGENT_RUNS = 5  # agent runs going at once, across all agents
_start_lock = threading.Lock()  # makes "any conflicting run?" and "start it" one step


class RunRequest(BaseModel):
    playbook: str = Field(max_length=200)
    # Host names, matched exactly against the grants. Bounded because they are echoed in errors and the audit log.
    limit: list[Annotated[str, Field(max_length=100)]] = Field(min_length=1, max_length=50)


def _deny(request: Request, agent: Agent, status: int, reason: str):
    request.state.audit = (agent.name, reason)  # picked up by the audit middleware
    raise HTTPException(status, reason)


@router.get("/catalog")
def catalog(agent: Agent = Depends(require_agent)):
    """What this agent may run, so it can discover it instead of guessing."""
    return {
        "runs_enabled": agents.runs_enabled(),
        "playbooks": [{"playbook": g.playbook, "hosts": g.hosts.split(",")} for g in agents.grants_for(agent)],
    }


@router.post("/runs", status_code=202)
def start_run(body: RunRequest, request: Request, agent: Agent = Depends(require_agent)):
    if not agents.runs_enabled():
        _deny(request, agent, 503, "agent runs are switched off")
    reason = agents.check_run(agent, body.playbook, body.limit)
    if reason:
        _deny(request, agent, 403, reason)
    with _start_lock:
        busy = agents.running_conflict(body.playbook, body.limit)
        if busy:
            _deny(request, agent, 409, f"run {busy.id} of this playbook is still running on overlapping hosts")
        if agents.running_agent_runs() >= MAX_AGENT_RUNS:
            _deny(request, agent, 429, f"{MAX_AGENT_RUNS} agent runs are already in progress")
        try:
            record = runner.start_run(
                body.playbook, triggered_by=f"agent:{agent.name}", limit=",".join(body.limit)
            )
        except ValueError:  # granted, but the playbook has since left the repo
            _deny(request, agent, 404, "playbook no longer exists")
        agents.record_agent_run(record.id, agent.id)
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
