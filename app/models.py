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
    status: str = "running"  # running | success | failed | timeout | cancelled
    triggered_by: str = "manual"  # manual | schedule | username
    return_code: Optional[int] = None
    tags: Optional[str] = None  # comma-separated --tags used for this run, if any
    limit: Optional[str] = None  # comma-separated --limit hosts, if any
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: Optional[datetime] = None


class Agent(SQLModel, table=True):
    """A non-human caller of the /api/v1 API (n8n, a script, an AI agent).
    Only the sha256 of the bearer token is stored; the token itself is shown
    once, when the agent is created."""

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)
    token_hash: str = Field(unique=True, index=True)
    enabled: bool = True
    expires_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utcnow)
    last_used_at: Optional[datetime] = None


class AgentAudit(SQLModel, table=True):
    """One row per /api/v1 request, allowed or denied."""

    id: Optional[int] = Field(default=None, primary_key=True)
    at: datetime = Field(default_factory=utcnow, index=True)
    agent_name: Optional[str] = None  # None when the token did not identify an agent
    method: str = ""
    path: str = ""
    outcome: str = "ok"  # ok | denied
    detail: str = ""


class PlaybookSchedule(SQLModel, table=True):
    rel_path: str = Field(primary_key=True)
    cron: str = ""  # empty = disabled


class SyncHistory(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    status: str = "running"  # running | success | failed
    triggered_by: str = "manual"  # manual | schedule
    message: str = ""
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: Optional[datetime] = None
