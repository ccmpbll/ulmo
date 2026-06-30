import yaml
from sqlmodel import Session, select

from app.database import engine
from app.models import Settings

DEFAULTS = {
    "git_repo_url": "",
    "git_branch": "main",
    "playbooks_subdir": "playbooks",
    "git_sync_cron": "",  # empty = scheduled sync disabled
    "extra_args": "",  # extra ansible-playbook CLI args, e.g. --tags foo
    "inventory_path": "inventory.yaml",  # relative to repo root; file or directory
    "recent_runs_count": "5",  # how many rows to show in the dashboard's Recent Runs table
}


def get_all() -> dict:
    with Session(engine) as session:
        rows = session.exec(select(Settings)).all()
        values = {row.key: row.value for row in rows}
    return {**DEFAULTS, **values}


def get(key: str) -> str:
    with Session(engine) as session:
        row = session.get(Settings, key)
        if row is not None:
            return row.value
    return DEFAULTS.get(key, "")


def set_many(values: dict) -> None:
    with Session(engine) as session:
        for key, value in values.items():
            row = session.get(Settings, key)
            if row is None:
                row = Settings(key=key, value=value or "")
            else:
                row.value = value or ""
            session.add(row)
        session.commit()


def export_yaml() -> str:
    """Dump known settings as YAML. Deliberately excludes SSH keys and user
    accounts — those are credentials, not config, and shouldn't end up in a
    casually-shared backup file."""
    data = {key: get(key) for key in DEFAULTS}
    return yaml.safe_dump(data, sort_keys=False, default_flow_style=False)


def import_yaml(text: str) -> tuple[dict, list[str]]:
    """Restore settings from a YAML backup. Returns (applied, ignored_keys).
    Only known setting keys are applied — anything else in the file is
    reported back as ignored rather than silently stored."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML: {exc}") from exc

    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ValueError("Expected a YAML mapping of setting names to values.")

    applied = {}
    ignored = []
    for key, value in data.items():
        if key not in DEFAULTS:
            ignored.append(str(key))
            continue
        applied[key] = "" if value is None else str(value)

    set_many(applied)
    return applied, ignored
