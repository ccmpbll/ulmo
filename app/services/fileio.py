"""File helpers shared by the command library and the Ansible workspace: the same crash-safe write,
saved-copy names and version digest, so a fix to one reaches both."""
import hashlib
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def digest(data: bytes) -> str:
    """The version of some contents: edits carry it so a stale one can be refused."""
    return hashlib.sha256(data).hexdigest()[:16]


def stamp() -> str:
    """A sortable UTC time to name a saved copy with."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def keep_newest(paths: list[Path], keep: int) -> None:
    """Delete all but the newest `keep` saved copies (names sort by their stamp)."""
    for stale in sorted(paths)[:-keep]:
        stale.unlink()


def write_atomic(path: Path, data: bytes, mode: int | None = None, tmp_prefix: str = ".tmp-") -> None:
    """Write to a temp file in the same folder, fsync, then swap it in, so a crash leaves the old
    file or the new one, never half of one (and never an empty file after a power cut). `mode`
    None keeps mkstemp's owner-only permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=tmp_prefix, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
