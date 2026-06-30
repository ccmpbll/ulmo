import threading
from pathlib import Path
from typing import Any

import ansible_runner
from sqlmodel import Session

from app.config import COLLECTIONS_DIR, REPO_DIR, RUNNER_DATA_DIR
from app.database import engine
from app.models import RunHistory, utcnow
from app.services import settings_store

_active_runners: dict[int, Any] = {}
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
        runner = _active_runners.get(run_id)
    if runner is None:
        return False
    runner.cancel()
    return True


def _execute(run_id: int, playbook_rel_path: str, tags: str = "", limit: str = "") -> None:
    from app.services import notifier

    settings = settings_store.get_all()
    extra_args = settings.get("extra_args", "").strip() or None

    envvars = {
        "ANSIBLE_FORCE_COLOR": "true",
        "ANSIBLE_COLLECTIONS_PATH": str(COLLECTIONS_DIR),
    }

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
    )

    with _lock:
        _active_runners[run_id] = runner

    ar_thread.join()

    with _lock:
        _active_runners.pop(run_id, None)

    if runner.status == "successful":
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
