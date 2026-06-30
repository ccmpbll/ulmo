import threading
from pathlib import Path

import ansible_runner
from sqlmodel import Session

from app.config import COLLECTIONS_DIR, REPO_DIR, RUNNER_DATA_DIR
from app.database import engine
from app.models import RunHistory, utcnow
from app.services import settings_store

_cancel_events: dict[int, threading.Event] = {}
_lock = threading.Lock()


def log_path(run_id: int) -> Path:
    return RUNNER_DATA_DIR / "artifacts" / str(run_id) / "stdout"


def start_run(
    playbook_rel_path: str,
    triggered_by: str = "manual",
    tags: str = "",
    limit: str = "",
) -> RunHistory:
    tags = tags.strip()
    limit = limit.strip()
    with Session(engine) as session:
        record = RunHistory(
            playbook=playbook_rel_path,
            triggered_by=triggered_by,
            tags=tags or None,
            limit=limit or None,
        )
        session.add(record)
        session.commit()
        session.refresh(record)
        run_id = record.id

    thread = threading.Thread(
        target=_execute, args=(run_id, playbook_rel_path, tags, limit), daemon=True
    )
    thread.start()

    with Session(engine) as session:
        return session.get(RunHistory, run_id)


def cancel_run(run_id: int) -> bool:
    with _lock:
        event = _cancel_events.get(run_id)
    if event is None:
        return False
    event.set()
    return True


def _execute(run_id: int, playbook_rel_path: str, tags: str = "", limit: str = "") -> None:
    from app.services import notifier

    settings = settings_store.get_all()
    extra_args = settings.get("extra_args", "").strip() or None

    envvars = {
        "ANSIBLE_FORCE_COLOR": "true",
        "ANSIBLE_COLLECTIONS_PATH": str(COLLECTIONS_DIR),
    }

    cancel_event = threading.Event()
    with _lock:
        _cancel_events[run_id] = cancel_event

    ar_thread, runner = ansible_runner.run_async(
        private_data_dir=str(RUNNER_DATA_DIR),
        project_dir=str(REPO_DIR),
        playbook=playbook_rel_path,
        tags=tags or None,
        limit=limit or None,
        envvars=envvars,
        cmdline=extra_args,
        ident=str(run_id),
        quiet=True,
        cancel_callback=cancel_event.is_set,
    )

    ar_thread.join()

    with _lock:
        _cancel_events.pop(run_id, None)

    if cancel_event.is_set():
        status = "failed"
    elif runner.status == "successful":
        status = "success"
    else:
        status = "failed"
    return_code = runner.rc if runner.rc is not None else -1

    with Session(engine) as session:
        record = session.get(RunHistory, run_id)
        record.status = status
        record.return_code = return_code
        record.finished_at = utcnow()
        session.add(record)
        session.commit()
        session.refresh(record)

    notifier.notify_run_complete(record)


def read_log(run_id: int) -> str:
    path = log_path(run_id)
    if not path.exists():
        return ""
    return path.read_text(errors="replace")
