import json
import os
import re
import subprocess

import yaml

from app.config import COLLECTIONS_DIR, DATA_DIR, WORKSPACE_DIR

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
            cwd=WORKSPACE_DIR,
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


def refresh_cache(playbooks: list[dict]) -> str | None:
    """Recompute and persist tags for every playbook. Called after the workspace changes —
    keeps dashboard loads fast (no per-request subprocess calls).

    Best-effort: a failure writing the cache file doesn't mean the save
    failed (the files were saved) — return a warning string instead of raising.
    """
    cache = {pb["rel_path"]: list_tags(pb["rel_path"]) for pb in playbooks}
    try:
        CACHE_PATH.write_text(json.dumps(cache))
    except OSError as exc:
        return f"WARNING: could not write playbook tag cache: {exc}"
    return None


def load_cache() -> dict:
    if not CACHE_PATH.exists():
        return {}
    try:
        return json.loads(CACHE_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _tag_list(value) -> list[str]:
    if isinstance(value, str):
        return [t.strip() for t in value.split(",") if t.strip()]
    if isinstance(value, list):
        return [str(t).strip() for t in value if str(t).strip()]
    return []


def task_outline(text: str) -> list[dict]:
    """The named tasks of a playbook, read from its text (no ansible, nothing connects): [{name, tags}] in
    order, with the tags a play and its blocks pass down. Handlers are left out (they run only when
    notified), as are tasks without a name, with a templated name, or inside roles and includes."""
    try:
        plays = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    out: list[dict] = []

    def walk(tasks, inherited):
        for task in tasks if isinstance(tasks, list) else []:
            if not isinstance(task, dict):
                continue
            tags = inherited + [t for t in _tag_list(task.get("tags")) if t not in inherited]
            for key in ("block", "rescue", "always"):
                if key in task:
                    walk(task[key], tags)
            name = task.get("name")
            if "block" not in task and isinstance(name, str) and name.strip() and "{{" not in name:
                out.append({"name": name.strip(), "tags": tags})

    for play in plays if isinstance(plays, list) else []:
        if isinstance(play, dict):
            for key in ("pre_tasks", "tasks", "post_tasks"):
                walk(play.get(key), _tag_list(play.get("tags")))
    return out


TASK_RE = re.compile(r"^TASK \[(.*?)\]", re.M)
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def ran_task_names(log: str) -> set[str]:
    """Names of the tasks a run started, from its log."""
    return {m.group(1).strip() for m in TASK_RE.finditer(ANSI_RE.sub("", log))}
