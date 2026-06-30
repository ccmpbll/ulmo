import json
import os
import re
import subprocess

from app.config import COLLECTIONS_DIR, DATA_DIR, REPO_DIR

TAG_LINE_RE = re.compile(r"TASK TAGS:\s*\[(.*?)\]")
CACHE_PATH = DATA_DIR / "playbook_tags.json"
EMPTY_RESULT = {"tags": [], "error": None}


def list_tags(rel_path: str) -> dict:
    """Discover tags in a playbook via `ansible-playbook --list-tags`.

    This doesn't connect to any hosts — it just parses the playbook (and any
    roles/includes it pulls in) locally, so it's safe to call speculatively.
    """
    env = os.environ.copy()
    env["ANSIBLE_COLLECTIONS_PATH"] = str(COLLECTIONS_DIR)

    try:
        result = subprocess.run(
            ["ansible-playbook", rel_path, "--list-tags"],
            cwd=REPO_DIR,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"tags": [], "error": str(exc)}

    output = result.stdout + result.stderr
    if result.returncode != 0:
        return {"tags": [], "error": output.strip()[-1000:] or "ansible-playbook --list-tags failed"}

    tags = set()
    for match in TAG_LINE_RE.finditer(output):
        for tag in match.group(1).split(","):
            tag = tag.strip()
            if tag:
                tags.add(tag)
    return {"tags": sorted(tags), "error": None}


def refresh_cache(playbooks: list[dict]) -> None:
    """Recompute and persist tags for every playbook. Called after git sync —
    keeps dashboard loads fast (no per-request subprocess calls)."""
    cache = {pb["rel_path"]: list_tags(pb["rel_path"]) for pb in playbooks}
    CACHE_PATH.write_text(json.dumps(cache))


def load_cache() -> dict:
    if not CACHE_PATH.exists():
        return {}
    try:
        return json.loads(CACHE_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def get_cached_tags(rel_path: str) -> dict:
    return load_cache().get(rel_path, EMPTY_RESULT)
