from pathlib import Path

from app.config import REPO_DIR
from app.services import settings_store

INVENTORY_EXTENSIONS = {".yaml", ".yml", ".ini", ".cfg"}
SKIP_DIRS = {".git", "old"}
MAX_DISPLAY_BYTES = 512 * 1024  # cap what we load into the browser


def _inventory_root() -> Path | None:
    rel = settings_store.get("inventory_path").strip("/") or "inventory.yaml"
    root = (REPO_DIR / rel).resolve()
    repo_root = REPO_DIR.resolve()
    if root != repo_root and repo_root not in root.parents:
        return None
    return root


def list_files() -> list[dict]:
    root = _inventory_root()
    if root is None or not root.exists():
        return []

    if root.is_file():
        return [{"rel_path": str(root.relative_to(REPO_DIR)), "name": root.name}]

    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(REPO_DIR).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if path.suffix and path.suffix not in INVENTORY_EXTENSIONS:
            continue
        files.append({"rel_path": str(path.relative_to(REPO_DIR)), "name": path.name})
    return files


def read_file(rel_path: str) -> dict:
    repo_root = REPO_DIR.resolve()
    candidate = (REPO_DIR / rel_path).resolve()
    if repo_root != candidate and repo_root not in candidate.parents:
        raise ValueError("Invalid inventory file path.")
    if not candidate.is_file():
        raise ValueError("That file doesn't exist (try syncing from git again).")

    root = _inventory_root()
    if root is None:
        raise ValueError("Invalid inventory path configured in Settings.")
    is_within_root = root.is_file() and candidate == root
    is_within_root = is_within_root or (root.is_dir() and root in candidate.parents)
    if not is_within_root:
        raise ValueError("That file is outside the configured inventory path.")

    size = candidate.stat().st_size
    content = candidate.read_text(errors="replace")
    truncated = len(content) > MAX_DISPLAY_BYTES
    if truncated:
        content = content[:MAX_DISPLAY_BYTES]
    return {"rel_path": rel_path, "content": content, "truncated": truncated, "size": size}
