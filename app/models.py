from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    password_hash: str
    created_at: datetime = Field(default_factory=utcnow)


class Settings(SQLModel, table=True):
    key: str = Field(primary_key=True)
    value: str = ""


class RunHistory(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    playbook: str
    status: str = "running"  # running | success | failed
    triggered_by: str = "manual"  # manual | schedule | username
    return_code: Optional[int] = None
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: Optional[datetime] = None


class SyncHistory(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    status: str = "running"  # running | success | failed
    triggered_by: str = "manual"  # manual | schedule
    message: str = ""
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: Optional[datetime] = None
