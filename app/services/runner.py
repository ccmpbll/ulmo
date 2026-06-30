import shlex
import subprocess
import threading

from sqlmodel import Session

from app.config import REPO_DIR, RUNS_DIR
from app.database import engine
from app.models import RunHistory, utcnow
from app.services import settings_store


def log_path(run_id: int):
    return RUNS_DIR / f"{run_id}.log"


def start_run(playbook_rel_path: str, triggered_by: str = "manual") -> RunHistory:
    with Session(engine) as session:
        record = RunHistory(playbook=playbook_rel_path, triggered_by=triggered_by)
        session.add(record)
        session.commit()
        session.refresh(record)
        run_id = record.id

    thread = threading.Thread(target=_execute, args=(run_id, playbook_rel_path), daemon=True)
    thread.start()

    with Session(engine) as session:
        return session.get(RunHistory, run_id)


def _execute(run_id: int, playbook_rel_path: str) -> None:
    settings = settings_store.get_all()
    extra_args = shlex.split(settings.get("extra_args", "") or "")
    cmd = ["ansible-playbook", playbook_rel_path, *extra_args]

    out_path = log_path(run_id)
    with open(out_path, "w") as log_file:
        log_file.write(f"$ {' '.join(cmd)}\n(cwd: {REPO_DIR})\n\n")
        log_file.flush()
        try:
            process = subprocess.Popen(
                cmd,
                cwd=REPO_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for line in process.stdout:
                log_file.write(line)
                log_file.flush()
            return_code = process.wait()
            status = "success" if return_code == 0 else "failed"
        except Exception as exc:  # noqa: BLE001
            log_file.write(f"\n[homelab-deck] failed to launch ansible-playbook: {exc}\n")
            return_code = -1
            status = "failed"

    with Session(engine) as session:
        record = session.get(RunHistory, run_id)
        record.status = status
        record.return_code = return_code
        record.finished_at = utcnow()
        session.add(record)
        session.commit()


def read_log(run_id: int) -> str:
    path = log_path(run_id)
    if not path.exists():
        return ""
    return path.read_text()
