"""Self-check for app/services/log_tail.py.

Covers the two properties the stream depends on:
  1. Multi-byte UTF-8 characters that span read boundaries are carried
     correctly (no U+FFFD loss) — the chunked reader must not drop the tail
     bytes of a character cut off by an active write.
  2. Starting from a byte offset resumes at exactly that point, the basis of
     the stream's reconnect-handshake.

Run directly: python3 tests/test_log_tail.py
"""
import os
import shutil
import tempfile
from pathlib import Path

DATA_DIR = tempfile.mkdtemp(prefix="ulmo-test-")
os.environ["ULMO_DATA_DIR"] = DATA_DIR

from app.services.log_tail import LogTailer  # noqa: E402


def test_multibyte_chars_survive_chunk_boundaries():
    path = Path(DATA_DIR) / "stdout"
    # \u2014 is a 3-byte em-dash; cut the file after its first byte.
    full = "ab\u2014cd"
    raw = full.encode("utf-8")
    assert raw[2] == 0xE2 and raw[3] == 0x80 and raw[4] == 0x94  # sanity: 3-byte char at idx 2

    with open(path, "wb") as f:
        f.write(raw[:3])  # "ab" + first byte of the em-dash

    tailer = LogTailer(path)
    chunk1 = tailer.read()
    assert chunk1 == "ab", f"expected a clean ASCII prefix, got {chunk1!r}"

    with open(path, "ab") as f:
        f.write(raw[3:])  # remainder of the em-dash + "cd"

    chunk2 = tailer.read()
    combined = chunk1 + chunk2
    assert "\ufffd" not in combined, f"replacement char lost bytes: {combined!r}"
    assert combined == full, f"mismatch:\n{combined!r}\nvs\n{full!r}"


def test_resume_from_offset():
    path = Path(DATA_DIR) / "stdout2"
    text = "line one\nline two\nline three\n"
    raw = text.encode("utf-8")
    with open(path, "wb") as f:
        f.write(raw)

    resume_at = len("line one\n".encode("utf-8"))
    tailer = LogTailer(path, offset=resume_at)
    assert tailer.read() == "line two\nline three\n", "resume offset must pick up from that byte"


def test_missing_file_reads_empty():
    tailer = LogTailer(Path(DATA_DIR) / "does-not-exist")
    assert tailer.read() == ""


if __name__ == "__main__":
    try:
        test_multibyte_chars_survive_chunk_boundaries()
        test_resume_from_offset()
        test_missing_file_reads_empty()
        print("OK: LogTailer carries multi-byte chars across reads and resumes from an offset.")
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)