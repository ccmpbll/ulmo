"""Self-check for app/services/runner.py's start-failure handling.

Simulates ansible_runner.run_async() raising before returning a thread (e.g.
a permissions error on the runner data dir) and asserts the run is marked
failed instead of getting stuck at status="running" forever.

Run directly: python3 tests/test_runner_start_failure.py
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path

DATA_DIR = tempfile.mkdtemp(prefix="ulmo-test-")
os.environ["ULMO_DATA_DIR"] = DATA_DIR
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlmodel import Session  # noqa: E402

from app.database import engine, init_db  # noqa: E402
from app.models import RunHistory  # noqa: E402
from app.services import runner  # noqa: E402
import ansible_runner  # noqa: E402


def fake_run_async(**kwargs):
    raise PermissionError("simulated: cannot mkdir runner data dir")


def main():
    init_db()

    with Session(engine) as session:
        record = RunHistory(playbook="fake.yml")
        session.add(record)
        session.commit()
        session.refresh(record)
        run_id = record.id

    original_run_async = ansible_runner.run_async
    ansible_runner.run_async = fake_run_async
    try:
        runner._execute(run_id, "fake.yml")
    finally:
        ansible_runner.run_async = original_run_async

    with Session(engine) as session:
        record = session.get(RunHistory, run_id)
        assert record.status == "failed", f"expected failed, got {record.status!r}"
        assert record.return_code == -1, f"expected -1, got {record.return_code!r}"
        assert record.finished_at is not None, "finished_at should be set"

    log_text = runner.log_path(run_id).read_text()
    assert "simulated: cannot mkdir" in log_text, f"log missing error text: {log_text!r}"

    assert run_id not in runner._cancel_events, "_cancel_events leaked"
    assert run_id not in runner._progress, "_progress leaked"

    print("OK: stuck-run bug fixed — start failure marks the run failed and cleans up.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
