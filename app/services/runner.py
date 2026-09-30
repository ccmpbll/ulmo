import json
import threading
from pathlib import Path

import ansible_runner
from sqlmodel import Session, select

from app.config import COLLECTIONS_DIR, REPO_DIR, RUNNER_DATA_DIR
from app.database import engine
from app.models import RunHistory, utcnow
from app.services import git_sync, settings_store

_cancel_events: dict[int, threading.Event] = {}
_progress: dict[int, dict] = {}
_lock = threading.Lock()

# Once a host hits one of these, later "good" events on that host (e.g. a
# rescue/always block continuing after a failure) don't overwrite it — the
# point of the live status is to flag trouble, not get optimistic about it.
_STICKY_STATUSES = {"failed", "unreachable"}


def log_path(run_id: int) -> Path:
    return RUNNER_DATA_DIR / "artifacts" / str(run_id) / "stdout"


def get_progress(run_id: int) -> dict | None:
    """Live in-memory state for a currently-running playbook: current task
    and a per-host status. Only populated while a run is active — gone once
    it finishes, by design (see get_recap() for the durable equivalent)."""
    with _lock:
        prog = _progress.get(run_id)
        if prog is None:
            return None
        return {
            "phase": prog["phase"],
            "current_task": prog["current_task"],
            "hosts": dict(prog["hosts"]),
        }


def get_recap(run_id: int) -> dict | None:
    """Final per-host PLAY RECAP stats (ok/changed/failed/unreachable/skipped
    counts), read from ansible-runner's persisted job_events for this run.
    Works for both a just-finished live run and an old run reloaded after a
    container restart — nothing in-memory to lose. Returns None if the run
    never reached a playbook_on_stats event (e.g. cancelled before any task
    ran, or hasn't gotten there yet for a still-running playbook)."""
    job_events_dir = RUNNER_DATA_DIR / "artifacts" / str(run_id) / "job_events"
    if not job_events_dir.exists():
        return None
    for path in job_events_dir.glob("*.json"):
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("event") == "playbook_on_stats":
            return data.get("event_data")
    return None


def _set_host_status(prog: dict, host: str, status: str) -> None:
    if prog["hosts"].get(host) in _STICKY_STATUSES:
        return
    prog["hosts"][host] = status


def reconcile_orphaned_runs() -> None:
    """Mark any RunHistory row stuck at status='running' as failed. A row can
    only be in that state if the process managing it (this one) died before
    finishing — call once at startup before the scheduler starts firing new
    runs."""
    with Session(engine) as session:
        orphaned = session.exec(select(RunHistory).where(RunHistory.status == "running")).all()
        for record in orphaned:
            record.status = "failed"
            record.return_code = -1
            record.finished_at = utcnow()
            session.add(record)
        session.commit()


def start_run(
    playbook_rel_path: str,
    triggered_by: str = "manual",
    tags: str = "",
    limit: str = "",
) -> RunHistory:
    tags = tags.strip()
    limit = limit.strip()

    valid_paths = {p["rel_path"] for p in git_sync.list_playbooks()}
    if playbook_rel_path not in valid_paths:
        raise ValueError(f"Unknown playbook: {playbook_rel_path}")

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

    cancel_event = threading.Event()
    with _lock:
        _cancel_events[run_id] = cancel_event
        _progress[run_id] = {"phase": "starting", "current_task": None, "hosts": {}}

    def event_handler(event_data: dict) -> bool:
        event = event_data.get("event", "")
        ed = event_data.get("event_data", {})
        host = ed.get("host")
        with _lock:
            prog = _progress.get(run_id)
            if prog is None:
                return True
            if event == "runner_on_start":
                prog["current_task"] = ed.get("task")
                if host:
                    _set_host_status(prog, host, "running")
            elif event == "runner_on_ok" and host:
                changed = ed.get("res", {}).get("changed", False)
                _set_host_status(prog, host, "changed" if changed else "ok")
            elif event == "runner_on_failed" and host:
                _set_host_status(prog, host, "failed")
            elif event == "runner_on_unreachable" and host:
                _set_host_status(prog, host, "unreachable")
            elif event == "runner_on_skipped" and host:
                _set_host_status(prog, host, "skipped")
        # Returning falsy here stops ansible-runner from persisting the event
        # to job_events/ at all — get_recap() depends on those files existing,
        # so this must always return True.
        return True

    def status_handler(status_data: dict, runner_config=None) -> None:
        with _lock:
            prog = _progress.get(run_id)
            if prog is not None:
                prog["phase"] = status_data.get("status", prog["phase"])

    # Everything from here down — including reading settings — is inside the
    # try. A row is created as status="running" in start_run() before this
    # thread ever runs; if anything here raises uncaught, the thread dies
    # silently and the row is stuck at "running" forever (only the final
    # `with Session` block below would clear it, but it'd never be reached).
    return_code = -1
    run_status = None
    try:
        settings = settings_store.get_all()
        extra_args = settings.get("extra_args", "").strip() or None
        try:
            timeout_minutes = int(settings.get("run_timeout_minutes", "60") or "0")
        except ValueError:
            timeout_minutes = 60
        timeout_seconds = timeout_minutes * 60 if timeout_minutes > 0 else None

        envvars = {
            "ANSIBLE_FORCE_COLOR": "true",
            "ANSIBLE_COLLECTIONS_PATH": str(COLLECTIONS_DIR),
        }

        run_kwargs = dict(
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
            event_handler=event_handler,
            status_handler=status_handler,
        )
        if timeout_seconds:
            run_kwargs["timeout"] = timeout_seconds

        ar_thread, run_result = ansible_runner.run_async(**run_kwargs)
        ar_thread.join()
        return_code = run_result.rc if run_result.rc is not None else -1
        run_status = run_result.status
    except Exception as exc:  # noqa: BLE001
        log_path(run_id).parent.mkdir(parents=True, exist_ok=True)
        log_path(run_id).write_text(f"ulmo: failed to start run: {exc}\n")
        status = "failed"
    else:
        if cancel_event.is_set():
            status = "cancelled"
        elif run_status == "timeout":
            status = "timeout"
        elif run_status == "successful":
            status = "success"
        else:
            status = "failed"
    finally:
        with _lock:
            _cancel_events.pop(run_id, None)
            _progress.pop(run_id, None)

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
