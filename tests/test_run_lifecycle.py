"""Self-check for the run-lifecycle fixes in app/services/runner.py.

Covers: startup reconciliation of rows stuck at status="running", the
start_run() playbook allowlist check, and that a cancelled/timed-out run is
recorded as such instead of being lumped in with "failed".

Run directly: python3 tests/test_run_lifecycle.py
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


def _new_run() -> int:
    with Session(engine) as session:
        record = RunHistory(playbook="fake.yml")
        session.add(record)
        session.commit()
        session.refresh(record)
        return record.id


def test_reconcile_orphaned_runs():
    with Session(engine) as session:
        record = RunHistory(playbook="stuck.yml", status="running")
        session.add(record)
        session.commit()
        session.refresh(record)
        run_id = record.id

    runner.reconcile_orphaned_runs()

    with Session(engine) as session:
        record = session.get(RunHistory, run_id)
        assert record.status == "failed", f"expected failed, got {record.status!r}"
        assert record.finished_at is not None


def test_start_run_rejects_unknown_playbook():
    try:
        runner.start_run("does/not-exist.yml")
    except ValueError:
        pass
    else:
        raise AssertionError("expected start_run to reject an unknown playbook")


def test_cancelled_run_is_not_recorded_as_failed():
    run_id = _new_run()

    def fake_run_async(**kwargs):
        class _Thread:
            def join(self):
                pass

        class _Result:
            rc = -1
            status = "canceled"

        runner.cancel_run(int(kwargs["ident"]))
        return _Thread(), _Result()

    original = ansible_runner.run_async
    ansible_runner.run_async = fake_run_async
    try:
        runner._execute(run_id, "fake.yml")
    finally:
        ansible_runner.run_async = original

    with Session(engine) as session:
        record = session.get(RunHistory, run_id)
        assert record.status == "cancelled", f"expected cancelled, got {record.status!r}"


def test_timed_out_run_is_not_recorded_as_failed():
    run_id = _new_run()

    def fake_run_async(**kwargs):
        class _Thread:
            def join(self):
                pass

        class _Result:
            rc = -1
            status = "timeout"

        return _Thread(), _Result()

    original = ansible_runner.run_async
    ansible_runner.run_async = fake_run_async
    try:
        runner._execute(run_id, "fake.yml")
    finally:
        ansible_runner.run_async = original

    with Session(engine) as session:
        record = session.get(RunHistory, run_id)
        assert record.status == "timeout", f"expected timeout, got {record.status!r}"


def main():
    init_db()
    test_reconcile_orphaned_runs()
    test_start_run_rejects_unknown_playbook()
    test_cancelled_run_is_not_recorded_as_failed()
    test_timed_out_run_is_not_recorded_as_failed()
    print("OK: run-lifecycle statuses (reconciled/cancelled/timeout) are correct.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
