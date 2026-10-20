import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select

from app.database import engine
from app.deps import require_agent
from app.models import RunHistory
from app.services import git_sync, inventory, playbook_tags, runner

# JSON API for agents (n8n, scripts). Read-only for now: it can look at
# playbooks, hosts and runs but cannot start or change anything.
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
