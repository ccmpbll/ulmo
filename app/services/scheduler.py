import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from app.services import git_sync, settings_store

logger = logging.getLogger("homelab-deck.scheduler")

scheduler = BackgroundScheduler()
JOB_ID = "git-sync"


def _run_scheduled_sync() -> None:
    logger.info("Running scheduled git sync")
    git_sync.sync_now(triggered_by="schedule")


def reschedule(cron_expression: str | None = None) -> None:
    cron_expression = cron_expression if cron_expression is not None else settings_store.get(
        "git_sync_cron"
    )

    if scheduler.get_job(JOB_ID):
        scheduler.remove_job(JOB_ID)

    cron_expression = (cron_expression or "").strip()
    if not cron_expression:
        return

    try:
        trigger = CronTrigger.from_crontab(cron_expression)
    except ValueError:
        logger.warning("Invalid git_sync_cron expression: %r", cron_expression)
        return

    scheduler.add_job(_run_scheduled_sync, trigger, id=JOB_ID, replace_existing=True)


def start() -> None:
    if not scheduler.running:
        scheduler.start()
    reschedule()
