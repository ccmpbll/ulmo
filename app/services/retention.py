"""Keeps the run and sync history from growing without end.

Same idea as the other logs: the newest rows are kept, older ones go. Playbook runs also
carry their log and events on disk, so those files go with the row. Runs still in progress
are never touched. Done from here (at start-up and every few hours) rather than from the
runner, which stays as it is.
"""
import logging
import shutil

from sqlmodel import Session, delete, select

from app.config import RUNNER_DATA_DIR
from app.database import engine
from app.models import AgentRun, RunHistory, SyncHistory

logger = logging.getLogger("ulmo.retention")

RUN_KEEP = 500  # newest playbook runs kept (each has a log on disk)
SYNC_KEEP = 500  # newest git syncs kept (each stores its output)
CHUNK = 400  # ids per DELETE, well under SQLite's limit on bound parameters


def _chunks(ids):
    for i in range(0, len(ids), CHUNK):
        yield ids[i : i + CHUNK]


def prune_runs() -> int:
    with Session(engine) as session:
        old = list(
            session.exec(
                select(RunHistory.id).where(RunHistory.status != "running").order_by(RunHistory.id.desc()).offset(RUN_KEEP)
            ).all()
        )
        for chunk in _chunks(old):
            session.exec(delete(AgentRun).where(AgentRun.run_id.in_(chunk)))
            session.exec(delete(RunHistory).where(RunHistory.id.in_(chunk)))
        session.commit()
    for run_id in old:
        shutil.rmtree(RUNNER_DATA_DIR / "artifacts" / str(run_id), ignore_errors=True)
    return len(old)


def prune_syncs() -> int:
    with Session(engine) as session:
        old = list(
            session.exec(
                select(SyncHistory.id).where(SyncHistory.status != "running").order_by(SyncHistory.id.desc()).offset(SYNC_KEEP)
            ).all()
        )
        for chunk in _chunks(old):
            session.exec(delete(SyncHistory).where(SyncHistory.id.in_(chunk)))
        session.commit()
    return len(old)


def prune() -> None:
    try:
        runs, syncs = prune_runs(), prune_syncs()
        if runs or syncs:
            logger.info("Pruned %d old playbook runs and %d old syncs", runs, syncs)
    except Exception:  # noqa: BLE001 - housekeeping must never stop ulmo from starting or running
        logger.exception("History pruning failed")
