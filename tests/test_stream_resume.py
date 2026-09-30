"""Self-check for the resumable log stream in app/routers/runs.py.

The run-detail page reconnects its EventSource at the last byte offset it
consumed instead of re-receiving the whole log. That handshake is a contract
between the browser and the server, and this is the half of it that can be
tested without a browser:

  1. Resuming at offset N returns only the bytes AFTER N — no gap, no repeat.
  2. The SSE `id:` on each chunk is the byte offset actually consumed, so the
     value a client stores and later passes back is trustworthy.
  3. Log content is delivered BEFORE `done`, including when the run finished
     while the client was disconnected — a reconnect after completion must
     still drain the tail, or the log silently stops mid-run forever.
  4. `Last-Event-ID` (the browser's native auto-reconnect) is honored as well
     as the `?offset=` query param the page actually uses.

Multi-byte characters are included in the fixture on purpose: the whole point
of LogTailer's incremental decoder is that a character straddling a read
boundary survives, and a resume must not reintroduce that corruption.

Run directly: python3 tests/test_stream_resume.py
"""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

DATA_DIR = tempfile.mkdtemp(prefix="ulmo-test-")
os.environ["ULMO_DATA_DIR"] = DATA_DIR
# The stream route sits behind require_login. With auth disabled the check
# short-circuits to a stand-in user, so the test needs no session/password.
os.environ["ULMO_DISABLE_AUTH"] = "true"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session  # noqa: E402

from app.database import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import RunHistory  # noqa: E402
from app.services import runner  # noqa: E402

# Deliberately includes a 3-byte em-dash and a 2-byte en-dash, so an offset
# that lands mid-character is detectable rather than silently plausible.
LOG_TEXT = (
    "PLAY [webservers] *************************************\n"
    "TASK [Gathering Facts] *********************************\n"
    "ok: [web1]\n"
    "changed: [web2] — em dash, 3 bytes\n"
    "skipping: [db1] – en dash, 2 bytes\n"
    "PLAY RECAP *********************************************\n"
)
RECAP = {
    "ok": {"web1": 3},
    "changed": {"web2": 1},
    "dark": {},
    "failures": {},
    "skipped": {"db1": 1},
    "processed": {"web1": 3, "web2": 1, "db1": 1},
}


def _make_finished_run(status: str = "success") -> int:
    """A run that is already in a terminal state, so the stream generator
    drains the tail and then returns instead of polling forever."""
    with Session(engine) as session:
        record = RunHistory(playbook="fake.yml", status=status)
        session.add(record)
        session.commit()
        session.refresh(record)
        return record.id


def _write_log(run_id: int, text: str) -> int:
    path = runner.log_path(run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path.stat().st_size


def _write_recap(run_id: int) -> None:
    events = runner.log_path(run_id).parent / "job_events"
    events.mkdir(parents=True, exist_ok=True)
    (events / "1.json").write_text(
        json.dumps({"event": "playbook_on_stats", "event_data": RECAP})
    )


def _read_stream(client: TestClient, run_id: int, **kwargs) -> list[dict]:
    """Drive /runs/{id}/stream to completion and return parsed SSE events as
    {"id": str|None, "event": str|None, "data": str} dicts, in wire order."""
    events: list[dict] = []
    current: dict = {"id": None, "event": None, "data": ""}
    with client.stream("GET", f"/runs/{run_id}/stream", **kwargs) as response:
        assert response.status_code == 200, response.status_code
        for line in response.iter_lines():
            if line == "":
                if current["data"]:
                    events.append(current)
                current = {"id": None, "event": None, "data": ""}
            elif line.startswith("id:"):
                current["id"] = line[3:].strip()
            elif line.startswith("event:"):
                current["event"] = line[6:].strip()
            elif line.startswith("data:"):
                current["data"] += line[5:].strip()
    if current["data"]:
        events.append(current)
    return events


def _log_chunks(events: list[dict]) -> list[dict]:
    return [json.loads(e["data"]) for e in events if e["event"] is None]


def test_full_read_from_zero():
    init_db()
    run_id = _make_finished_run()
    size = _write_log(run_id, LOG_TEXT)
    _write_recap(run_id)

    client = TestClient(app)
    events = _read_stream(client, run_id)

    chunks = _log_chunks(events)
    assert len(chunks) == 1, f"expected one log chunk, got {len(chunks)}"
    assert chunks[0]["text"] == LOG_TEXT, "offset 0 must return the whole log"
    assert chunks[0]["pos"] == size, f"pos should be file size {size}, got {chunks[0]['pos']}"


def test_resume_returns_only_the_tail():
    init_db()
    run_id = _make_finished_run()
    size = _write_log(run_id, LOG_TEXT)
    _write_recap(run_id)

    # Resume from a boundary that lands just before the em-dash line.
    resume_at = len(LOG_TEXT.encode("utf-8")[: LOG_TEXT.index("changed:")])
    client = TestClient(app)
    events = _read_stream(client, run_id, params={"offset": resume_at})

    chunks = _log_chunks(events)
    text = "".join(c["text"] for c in chunks)
    assert text == LOG_TEXT[resume_at:], (
        f"resume mismatch:\n got {text!r}\nwant {LOG_TEXT[resume_at:]!r}"
    )
    assert "PLAY [webservers]" not in text, "resume re-sent already-seen content"
    assert "—" in text, "multi-byte character was lost or mangled across the resume"
    assert chunks[-1]["pos"] == size, f"final pos should be {size}, got {chunks[-1]['pos']}"


def test_last_event_id_header_is_honored():
    init_db()
    run_id = _make_finished_run()
    _write_log(run_id, LOG_TEXT)
    _write_recap(run_id)

    resume_at = len("PLAY [webservers]".encode("utf-8"))
    client = TestClient(app)
    events = _read_stream(client, run_id, headers={"Last-Event-ID": str(resume_at)})

    text = "".join(c["text"] for c in _log_chunks(events))
    assert text == LOG_TEXT[resume_at:], "Last-Event-ID must be honored like ?offset="


def test_log_precedes_recap_and_done():
    """The ordering that makes a reconnect-after-completion work: even though
    the run is no longer running, the tail is drained before done is sent."""
    init_db()
    run_id = _make_finished_run(status="cancelled")
    _write_log(run_id, LOG_TEXT)
    _write_recap(run_id)

    client = TestClient(app)
    events = _read_stream(client, run_id)

    names = [e["event"] for e in events if e["event"] is not None]
    assert names == ["recap", "done"], f"unexpected event order: {names}"
    assert events[0]["event"] is None, "log chunk must come before recap/done"

    done = [e for e in events if e["event"] == "done"][0]
    assert done["data"] == "cancelled", f"done should carry the status, got {done['data']!r}"

    recap = json.loads([e for e in events if e["event"] == "recap"][0]["data"])
    assert recap["processed"] == RECAP["processed"]


def test_offset_beyond_eof_yields_nothing():
    """A client whose offset is past the end (log truncated, rotated) must get
    a clean empty stream ending in done — not an error, not a hang."""
    init_db()
    run_id = _make_finished_run()
    _write_log(run_id, LOG_TEXT)
    _write_recap(run_id)

    client = TestClient(app)
    events = _read_stream(client, run_id, params={"offset": 10_000_000})

    assert _log_chunks(events) == [], "nothing should be sent past EOF"
    assert [e["event"] for e in events] == ["recap", "done"]


def main():
    init_db()
    test_full_read_from_zero()
    test_resume_returns_only_the_tail()
    test_last_event_id_header_is_honored()
    test_log_precedes_recap_and_done()
    test_offset_beyond_eof_yields_nothing()
    print("OK: log stream resumes at a byte offset, drains before done, honors Last-Event-ID.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
