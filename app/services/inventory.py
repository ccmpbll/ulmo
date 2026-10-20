import json
import subprocess
import time
from pathlib import Path

from app.config import DATA_DIR, REPO_DIR
from app.services import settings_store

INVENTORY_EXTENSIONS = {".yaml", ".yml", ".ini", ".cfg"}
SKIP_DIRS = {".git", "old"}
MAX_DISPLAY_BYTES = 512 * 1024  # cap what we load into the browser

# Running `ansible-inventory --list` is a subprocess + full parse of the
# inventory — too expensive to do on every dashboard load. Cache the host
# list and refresh it after each successful git sync; the TTL is a safety
# net so the list also refreshes without a sync (e.g. a hand-edited
# inventory), trading one subprocess call per minute for dozens per minute.
HOSTS_CACHE_PATH = DATA_DIR / "inventory_hosts.json"
HOSTS_CACHE_TTL_SECONDS = 60


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


def _fresh_cache() -> dict | None:
    cached = _read_hosts_cache()
    if cached is not None and "groups" in cached and time.time() - cached["ts"] < HOSTS_CACHE_TTL_SECONDS:
        return cached
    return None


def list_hosts() -> list[str]:
    cached = _fresh_cache()
    return cached["hosts"] if cached else _refresh()[0]


def list_groups() -> list[str]:
    """Group names, including the implicit `all` and `ungrouped`. ansible's
    --limit treats a name as a host OR a group, so callers that need a name to
    mean one host only must refuse names that are also groups."""
    cached = _fresh_cache()
    return cached["groups"] if cached else _refresh()[1]


def refresh_hosts_cache() -> list[str]:
    return _refresh()[0]


def _refresh() -> tuple[list[str], list[str]]:
    """Recompute hosts and groups and persist them. Returns them even if the
    write fails (that's a cache problem, not a data problem)."""
    hosts, groups = _run_ansible_inventory()
    try:
        HOSTS_CACHE_PATH.write_text(json.dumps({"ts": time.time(), "hosts": hosts, "groups": groups}))
    except OSError:
        pass
    return hosts, groups


def _read_hosts_cache() -> dict | None:
    if not HOSTS_CACHE_PATH.exists():
        return None
    try:
        return json.loads(HOSTS_CACHE_PATH.read_text())
    except (OSError, json.JSONDecodeError, TypeError):
        return None


def _run_ansible_inventory() -> tuple[list[str], list[str]]:
    root = _inventory_root()
    if root is None or not root.exists():
        return [], []
    try:
        result = subprocess.run(
            ["ansible-inventory", "-i", str(root), "--list"],
            cwd=REPO_DIR,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return [], []
        data = json.loads(result.stdout)
        hosts = sorted(data.get("_meta", {}).get("hostvars", {}).keys())
        return hosts, sorted(k for k in data if k != "_meta")
    except Exception:
        return [], []


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
