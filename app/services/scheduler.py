import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlmodel import Session, select

from app.services import git_sync, settings_store

logger = logging.getLogger("ulmo.scheduler")

scheduler = BackgroundScheduler()
GIT_SYNC_JOB_ID = "git-sync"
PLAYBOOK_JOB_PREFIX = "playbook:"


def _run_scheduled_sync() -> None:
    logger.info("Running scheduled git sync")
    git_sync.sync_now(triggered_by="schedule")


def reschedule(cron_expression: str | None = None) -> None:
    cron_expression = cron_expression if cron_expression is not None else settings_store.get(
        "git_sync_cron"
    )

    if scheduler.get_job(GIT_SYNC_JOB_ID):
        scheduler.remove_job(GIT_SYNC_JOB_ID)

    cron_expression = (cron_expression or "").strip()
    if not cron_expression:
        return

    try:
        trigger = CronTrigger.from_crontab(cron_expression)
    except ValueError:
        logger.warning("Invalid git_sync_cron expression: %r", cron_expression)
        return

    scheduler.add_job(_run_scheduled_sync, trigger, id=GIT_SYNC_JOB_ID, replace_existing=True)


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
        runner.start_run(path_copy, triggered_by="schedule")

    scheduler.add_job(_run, trigger, id=job_id, replace_existing=True)


def reschedule_all_playbooks() -> None:
    from app.database import engine
    from app.models import PlaybookSchedule

    with Session(engine) as session:
        schedules = session.exec(select(PlaybookSchedule)).all()
    for s in schedules:
        reschedule_playbook(s.rel_path, s.cron)


def start() -> None:
    if not scheduler.running:
        scheduler.start()
    reschedule()
    reschedule_all_playbooks()
