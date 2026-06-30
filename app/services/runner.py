import os
import shlex
import subprocess
import threading

from sqlmodel import Session

from app.config import COLLECTIONS_DIR, REPO_DIR, RUNS_DIR
from app.database import engine
from app.models import RunHistory, utcnow
from app.services import settings_store


def log_path(run_id: int):
    return RUNS_DIR / f"{run_id}.log"


def start_run(playbook_rel_path: str, triggered_by: str = "manual", tags: str = "") -> RunHistory:
    tags = tags.strip()
    with Session(engine) as session:
        record = RunHistory(playbook=playbook_rel_path, triggered_by=triggered_by, tags=tags or None)
        session.add(record)
        session.commit()
        session.refresh(record)
        run_id = record.id

    thread = threading.Thread(
        target=_execute, args=(run_id, playbook_rel_path, tags), daemon=True
    )
    thread.start()

    with Session(engine) as session:
        return session.get(RunHistory, run_id)


def _execute(run_id: int, playbook_rel_path: str, tags: str = "") -> None:
    settings = settings_store.get_all()
    extra_args = shlex.split(settings.get("extra_args", "") or "")
    cmd = ["ansible-playbook", playbook_rel_path, *extra_args]
    if tags:
        cmd += ["--tags", tags]

    env = os.environ.copy()
    env["ANSIBLE_FORCE_COLOR"] = "true"
    # Ansible only auto-detects collections under ~/.ansible/collections (not
    # persisted across container restarts); point it at the volume-backed
    # location collections get installed into during git sync.
    env["ANSIBLE_COLLECTIONS_PATH"] = str(COLLECTIONS_DIR)

    out_path = log_path(run_id)
    with open(out_path, "w") as log_file:
        log_file.write(f"$ {' '.join(cmd)}\n(cwd: {REPO_DIR})\n\n")
        log_file.flush()
        try:
            process = subprocess.Popen(
                cmd,
                cwd=REPO_DIR,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            timed_out = False

            def _kill():
                nonlocal timed_out
                timed_out = True
                try:
                    process.kill()
                except OSError:
                    pass

            killer = threading.Timer(3600, _kill)
            killer.daemon = True
            killer.start()
            try:
                for line in process.stdout:
                    log_file.write(line)
                    log_file.flush()
                return_code = process.wait()
            finally:
                killer.cancel()

            if timed_out:
                log_file.write("\n[ulmo] killed after 1h timeout\n")
                status = "failed"
            else:
                status = "success" if return_code == 0 else "failed"
        except Exception as exc:  # noqa: BLE001
            log_file.write(f"\n[ulmo] failed to launch ansible-playbook: {exc}\n")
            return_code = -1
            status = "failed"

        if status == "success":
            log_file.write("\n\033[1;32m=== DONE! ===\033[0m\n")
        else:
            log_file.write(f"\n\033[1;31m=== FAILED (exit code {return_code}) ===\033[0m\n")
        log_file.flush()

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
