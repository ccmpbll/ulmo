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
    role_id: Optional[int] = Field(default=None, index=True)  # None = may read, may not run anything
    expires_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utcnow)
    last_used_at: Optional[datetime] = None


class Role(SQLModel, table=True):
    """A named set of grants that agents can be assigned to."""

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)


class Grant(SQLModel, table=True):
    """Lets a role run one playbook against a fixed set of hosts. An agent's
    --limit must be a subset of `hosts`; there is no wildcard or group syntax,
    so a request can never widen what the grant names."""

    id: Optional[int] = Field(default=None, primary_key=True)
    role_id: int = Field(index=True)
    playbook: str  # rel_path, as listed by git_sync.list_playbooks()
    hosts: str  # comma-separated inventory host names

class AgentAudit(SQLModel, table=True):
    """One row per /api/v1 request, allowed or denied."""

    id: Optional[int] = Field(default=None, primary_key=True)
    at: datetime = Field(default_factory=utcnow, index=True)
    agent_name: Optional[str] = None  # None when the token did not identify an agent
    method: str = ""
    path: str = ""
    status_code: int = 0  # HTTP status returned; 401 = rejected before reaching a handler
    detail: str = ""  # why a 401/403/503 happened, or what a run request started


class CommandGrant(SQLModel, table=True):
    """Lets a role run one command template on specific inventory hosts."""

    id: Optional[int] = Field(default=None, primary_key=True)
    role_id: int = Field(index=True)
    template: str  # template id (file name without extension)
    hosts: str  # comma-separated inventory host names


class CommandRun(SQLModel, table=True):
    """One execution of a command template over SSH."""

    id: Optional[int] = Field(default=None, primary_key=True)
    template: str
    host: str
    params: str = "{}"  # JSON of the validated values
    command: str = ""  # the argument list that ran, shell-quoted, for display
    status: str = "running"  # running | success | failed | timeout | error
    return_code: Optional[int] = None
    output: str = ""  # combined stdout/stderr, capped
    triggered_by: str = ""  # agent:<name>
    agent_id: Optional[int] = Field(default=None, index=True)
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: Optional[datetime] = None


class AgentRun(SQLModel, table=True):
    """Which agent started which run. Cancel ownership is decided here, not by
    parsing RunHistory.triggered_by (a username can look like "agent:x")."""

    run_id: int = Field(primary_key=True)
    agent_id: int = Field(index=True)


class AdminAudit(SQLModel, table=True):
    """Changes made on the Agents page (agents, roles, grants, kill switch).
    Kept apart from AgentAudit so an API flood, which prunes that table, can
    never push the record of who widened access out."""

    id: Optional[int] = Field(default=None, primary_key=True)
    at: datetime = Field(default_factory=utcnow)
    admin: str = ""
    action: str = ""
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
