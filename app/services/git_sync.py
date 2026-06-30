import subprocess
from pathlib import Path

from sqlmodel import Session

from app.config import COLLECTIONS_DIR, REPO_DIR
from app.database import engine
from app.models import SyncHistory
from app.services import playbook_tags, settings_store

SKIP_DIRS = {"old", ".git"}
EXCLUDE_FILES = {"requirements.yaml", "requirements.yml"}


class SyncError(Exception):
    pass


def _run(cmd: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=300
    )
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0:
        raise SyncError(output.strip() or f"command failed: {' '.join(cmd)}")
    return output.strip()


def _find_requirements_file() -> Path | None:
    subdir = settings_store.get("playbooks_subdir").strip("/") or "."
    candidates = [
        REPO_DIR / subdir / "requirements.yaml",
        REPO_DIR / subdir / "requirements.yml",
        REPO_DIR / "requirements.yaml",
        REPO_DIR / "requirements.yml",
    ]
    return next((p for p in candidates if p.exists()), None)


def _install_collections() -> str | None:
    """Install collections from the repo's requirements.yaml, if any.

    Best-effort: failures here are appended as a warning rather than failing
    the whole sync, since the git sync itself already succeeded.
    """
    req_file = _find_requirements_file()
    if req_file is None:
        return None
    COLLECTIONS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        return _run(
            ["ansible-galaxy", "collection", "install", "-r", str(req_file), "-p", str(COLLECTIONS_DIR)],
            cwd=REPO_DIR,
        )
    except SyncError as exc:
        return f"WARNING: collection install from {req_file.name} failed:\n{exc}"


def sync_now(triggered_by: str = "manual") -> SyncHistory:
    settings = settings_store.get_all()
    repo_url = settings["git_repo_url"]
    branch = settings["git_branch"] or "main"

    with Session(engine) as session:
        record = SyncHistory(triggered_by=triggered_by)
        session.add(record)
        session.commit()
        session.refresh(record)
        record_id = record.id

    log_lines = []
    try:
        if not repo_url:
            raise SyncError("No git repo URL configured. Set one in Settings first.")

        if (REPO_DIR / ".git").exists():
            log_lines.append(_run(["git", "fetch", "origin", branch], cwd=REPO_DIR))
            log_lines.append(_run(["git", "checkout", branch], cwd=REPO_DIR))
            log_lines.append(_run(["git", "reset", "--hard", f"origin/{branch}"], cwd=REPO_DIR))
        else:
            REPO_DIR.parent.mkdir(parents=True, exist_ok=True)
            log_lines.append(
                _run(["git", "clone", "--branch", branch, repo_url, str(REPO_DIR)])
            )

        collections_output = _install_collections()
        if collections_output:
            log_lines.append(collections_output)

        playbook_tags.refresh_cache(list_playbooks())

        message = "\n".join(line for line in log_lines if line)
        status = "success"
    except SyncError as exc:
        message = str(exc)
        status = "failed"
    except Exception as exc:  # noqa: BLE001
        message = f"Unexpected error: {exc}"
        status = "failed"

    from app.models import utcnow

    with Session(engine) as session:
        record = session.get(SyncHistory, record_id)
        record.status = status
        record.message = message
        record.finished_at = utcnow()
        session.add(record)
        session.commit()
        session.refresh(record)
        return record


def list_playbooks() -> list[dict]:
    settings = settings_store.get_all()
    subdir = settings["playbooks_subdir"].strip("/") or "."
    repo_resolved = REPO_DIR.resolve()
    base = (REPO_DIR / subdir).resolve() if subdir != "." else repo_resolved
    if base != repo_resolved and repo_resolved not in base.parents:
        return []
    if not base.exists():
        return []

    playbooks = []
    for path in sorted(base.glob("*.yaml")) + sorted(base.glob("*.yml")):
        if path.name in EXCLUDE_FILES:
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(repo_resolved).parts):
            continue
        playbooks.append(
            {
                "name": path.name,
                "rel_path": str(path.relative_to(repo_resolved)),
            }
        )
    return playbooks


def repo_synced() -> bool:
    return (REPO_DIR / ".git").exists()
