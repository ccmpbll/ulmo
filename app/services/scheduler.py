import logging
from datetime import timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlmodel import Session, select

from app.services import retention, workspace

logger = logging.getLogger("ulmo.scheduler")

scheduler = BackgroundScheduler()
PLAYBOOK_JOB_PREFIX = "playbook:"
RETENTION_JOB_ID = "retention"


def reschedule_playbook(rel_path: str, cron: str) -> None:
    from app.services import runner

    job_id = PLAYBOOK_JOB_PREFIX + rel_path
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

    cron = (cron or "").strip()
    if not cron:
        return

    try:
        trigger = CronTrigger.from_crontab(cron)
    except ValueError:
        logger.warning("Invalid cron for playbook %r: %r", rel_path, cron)
        return

    path_copy = rel_path

    def _run():
        try:
            runner.start_run(path_copy, triggered_by="schedule")
        except ValueError:
            # Playbook was removed since this job was scheduled.
            # reap_orphaned_schedules() clears the job itself when the file is
            # deleted; until then, skip quietly instead of crashing the job.
            logger.warning("Scheduled run skipped: playbook %r no longer exists", path_copy)
        except Exception:
            # e.g. a transient DB lock while reading settings or the playbook
            # list — log it and let the next scheduled fire retry, instead of
            # letting the exception kill this APScheduler job thread.
            logger.exception("Scheduled run for %r failed unexpectedly", path_copy)

    scheduler.add_job(_run, trigger, id=job_id, replace_existing=True)


def next_run(rel_path: str):
    """When this playbook's schedule fires next, as a UTC datetime, or None if it has no live job."""
    job = scheduler.get_job(PLAYBOOK_JOB_PREFIX + rel_path)
    when = getattr(job, "next_run_time", None) if job else None
    return when.astimezone(timezone.utc) if when else None


def reschedule_all_playbooks() -> None:
    from app.database import engine
    from app.models import PlaybookSchedule

    with Session(engine) as session:
        schedules = session.exec(select(PlaybookSchedule)).all()
    for s in schedules:
        reschedule_playbook(s.rel_path, s.cron)


def reap_orphaned_schedules() -> None:
    """Remove PlaybookSchedule rows (and their APScheduler jobs) for
    playbooks no longer in the workspace. Called when a file is created or
    deleted, when the playbook list is authoritative — never at startup, since
    the workspace may not be populated yet and every schedule would look orphaned."""
    from app.database import engine
    from app.models import PlaybookSchedule

    valid_paths = {p["rel_path"] for p in workspace.list_playbooks()}
    with Session(engine) as session:
        schedules = session.exec(select(PlaybookSchedule)).all()
        for s in schedules:
            if s.rel_path in valid_paths:
                continue
            job_id = PLAYBOOK_JOB_PREFIX + s.rel_path
            if scheduler.get_job(job_id):
                scheduler.remove_job(job_id)
            session.delete(s)
        session.commit()


def schedule_retention() -> None:
    scheduler.add_job(retention.prune, "interval", hours=6, id=RETENTION_JOB_ID, replace_existing=True)


def start() -> None:
    if not scheduler.running:
        scheduler.start()
    schedule_retention()
    reschedule_all_playbooks()
    workspace.on_listing_change(reap_orphaned_schedules)
