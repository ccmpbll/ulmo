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


CONN_VARS = ("ansible_host", "ansible_port", "ansible_user", "ansible_ssh_user", "ansible_ssh_private_key_file")


def _data() -> dict:
    cached = _read_hosts_cache()
    if cached is not None and "conn" in cached and time.time() - cached["ts"] < HOSTS_CACHE_TTL_SECONDS:
        return cached
    return refresh_hosts_cache()


def list_hosts() -> list[str]:
    return _data()["hosts"]


def list_groups() -> list[str]:
    """Group names, including the implicit `all` and `ungrouped`. ansible's
    --limit treats a name as a host OR a group, so callers that need a name to
    mean one host only must refuse names that are also groups."""
    return _data()["groups"]


def host_conn(host: str) -> dict | None:
    """How to reach a host over SSH, from its inventory variables:
    {"address", "port", "user", "key"} (key may be empty), or None if the host
    is not in the inventory."""
    raw = _data()["conn"].get(host)
    if raw is None:
        return None
    return {
        "address": str(raw.get("ansible_host") or host),
        "port": str(raw.get("ansible_port") or "22"),
        "user": str(raw.get("ansible_user") or raw.get("ansible_ssh_user") or ""),
        "key": str(raw.get("ansible_ssh_private_key_file") or ""),
    }


def refresh_hosts_cache() -> dict:
    """Recompute the inventory facts and persist them. Returns them even if the
    write fails (that's a cache problem, not a data problem)."""
    data = {"ts": time.time(), **_run_ansible_inventory()}
    try:
        HOSTS_CACHE_PATH.write_text(json.dumps(data))
    except OSError:
        pass
    return data


def _read_hosts_cache() -> dict | None:
    if not HOSTS_CACHE_PATH.exists():
        return None
    try:
        return json.loads(HOSTS_CACHE_PATH.read_text())
    except (OSError, json.JSONDecodeError, TypeError):
        return None


def _run_ansible_inventory() -> dict:
    empty = {"hosts": [], "groups": [], "conn": {}}
    root = _inventory_root()
    if root is None or not root.exists():
        return empty
    try:
        result = subprocess.run(
            ["ansible-inventory", "-i", str(root), "--list"],
            cwd=REPO_DIR,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return empty
        data = json.loads(result.stdout)
        hostvars = data.get("_meta", {}).get("hostvars", {})
        return {
            "hosts": sorted(hostvars),
            "groups": sorted(k for k in data if k != "_meta"),
            "conn": {h: {k: v[k] for k in CONN_VARS if k in v} for h, v in hostvars.items()},
        }
    except Exception:
        return empty


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
