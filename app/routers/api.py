import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select

from app.database import engine
from app.deps import require_agent
from app.models import Agent, RunHistory
from app.services import git_sync, inventory, playbook_tags, runner

# JSON API for agents (n8n, scripts). Read-only for now: it can look at
# playbooks, hosts and runs but cannot start or change anything.
router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_agent)])

LOG_TAIL_CHARS = 64 * 1024
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


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


@router.get("/me")
def me(agent: Agent = Depends(require_agent)):
    return {"name": agent.name, "expires_at": _iso(agent.expires_at)}


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
def runs(limit: int = Query(20, ge=1, le=100), status: str | None = None):
    query = select(RunHistory).order_by(RunHistory.started_at.desc()).limit(limit)
    if status:
        query = query.where(RunHistory.status == status)
    with Session(engine) as session:
        return {"runs": [_run_json(r) for r in session.exec(query).all()]}


@router.get("/runs/{run_id}")
def run_detail(run_id: int):
    with Session(engine) as session:
        run = session.get(RunHistory, run_id)
    if run is None:
        raise HTTPException(404, "Run not found")
    log, _ = runner.read_log(run_id)
    log = ANSI_RE.sub("", log)
    return {
        **_run_json(run),
        "recap": runner.get_recap(run_id),
        "log": log[-LOG_TAIL_CHARS:],
        "log_truncated": len(log) > LOG_TAIL_CHARS,
    }
