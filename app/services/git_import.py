"""One-time import of a git repository into the workspace.

This is the only place ulmo still runs git. It clones to a temp directory, then swaps the files in as
the new workspace (the old one is kept beside it, see workspace.replace_from). Nothing is synced:
after an import, ulmo owns the files.
"""
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from sqlmodel import Session, select

from app.config import DATA_DIR
from app.database import engine
from app.models import SyncHistory, utcnow
from app.services import workspace


class ImportFailed(Exception):
    pass


def _redact(text: str, repo_url: str) -> str:
    """A URL can carry a token (https://user:token@host/...). Git, a timeout message or an error
    can repeat it, and the text is saved to the database, shown on the log page and put in a
    redirect: blank the credentials wherever they appear."""
    netloc = urlsplit(repo_url).netloc
    if "@" not in netloc:
        return text
    userinfo = netloc.rsplit("@", 1)[0]
    text = text.replace(userinfo + "@", "***@")
    password = userinfo.partition(":")[2]
    return text.replace(password, "***") if password else text


def _clone(repo_url: str, branch: str, dest: Path) -> str:
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--branch", branch, "--", repo_url, str(dest)],
        capture_output=True, text=True, timeout=300,
    )
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    if result.returncode != 0:
        raise ImportFailed(output or "git clone failed")
    return output


def import_now(repo_url: str, branch: str, triggered_by: str) -> SyncHistory:
    """Replace the workspace with the files of `repo_url` at `branch`. Always returns the history
    row (status success or failed)."""
    repo_url, branch = repo_url.strip(), branch.strip() or "main"
    with Session(engine) as session:
        record = SyncHistory(triggered_by=triggered_by)
        session.add(record)
        session.commit()
        session.refresh(record)
        record_id = record.id

    lines = []
    tmp = Path(tempfile.mkdtemp(prefix="ansible-import-", dir=DATA_DIR))  # same filesystem as the workspace
    try:
        if not repo_url:
            raise ImportFailed("Give a git repository URL.")
        if repo_url.startswith("-"):
            raise ImportFailed("That is not a repository URL.")
        workspace.require_unlocked()  # fail before the clone, not after
        lines.append(f"Cloning branch {branch}")
        lines.append(_clone(repo_url, branch, tmp / "repo"))
        count = workspace.replace_from(tmp / "repo")
        lines.append(f"Imported {count} files. The previous files are kept as ansible.before-import-* under the data folder.")
        status = "success"
    except (ImportFailed, workspace.Locked, ValueError) as exc:
        lines.append(str(exc))
        status = "failed"
    except Exception as exc:  # noqa: BLE001
        lines.append(f"Unexpected error: {exc}")
        status = "failed"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    with Session(engine) as session:
        record = session.get(SyncHistory, record_id)
        record.status = status
        record.message = _redact("\n".join(line for line in lines if line), repo_url)
        record.finished_at = utcnow()
        session.add(record)
        session.commit()
        session.refresh(record)
        return record


def reconcile_orphaned_imports() -> None:
    """Mark any SyncHistory row stuck at status='running' as failed. Only reachable if the process
    died mid-import (container restart) — call once at startup."""
    with Session(engine) as session:
        for record in session.exec(select(SyncHistory).where(SyncHistory.status == "running")).all():
            record.status = "failed"
            record.message = "The import did not finish — the app restarted while it was running."
            record.finished_at = utcnow()
            session.add(record)
        session.commit()
