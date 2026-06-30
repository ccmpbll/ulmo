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
