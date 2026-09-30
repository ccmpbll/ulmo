import codecs
from pathlib import Path


class LogTailer:
    """Tail an append-only log file, correctly carrying multi-byte UTF-8
    characters that span read boundaries.

    A plain decode(errors="replace") on each chunk burns any partial character
    at its tail, and the next read starts after the discarded bytes — so a
    multi-byte char written across two reads renders as U+FFFD. The
    incremental decoder buffers the incomplete sequence until a later read
    completes it, then emits the whole character once.

    Also forms the basis of the stream's resume behavior: the SSE loop keeps
    one LogTailer per connection, and a reconnecting client passes its last
    consumed byte offset to pick up where it left off instead of re-reading
    (and re-sending) the whole log.
    """

    def __init__(self, path: Path, offset: int = 0):
        self.path = path
        self.pos = max(0, offset)
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    def read(self) -> str:
        """Read everything appended to the file since the last call (or since
        `offset`), decoded incrementally. Returns "" if the file doesn't exist
        or can't be read — the caller keeps polling and will pick up the bytes
        the next time around."""
        if not self.path.exists():
            return ""
        try:
            with open(self.path, "rb") as f:
                f.seek(self.pos)
                data = f.read()
                self.pos = f.tell()
        except OSError:
            return ""
        return self._decoder.decode(data)