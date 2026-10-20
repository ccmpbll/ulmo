import hashlib
import re
import secrets
from datetime import timedelta

from sqlmodel import Session, delete, select

from app.database import engine
from app.models import Agent, AgentAudit, utcnow

TOKEN_PREFIX = "ulmo_"
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
MAX_EXPIRY_DAYS = 3650
AUDIT_KEEP = 5000  # newest audit rows kept; unauthenticated callers can write rows too
AUDIT_PATH_MAX = 200
LAST_USED_REFRESH = timedelta(minutes=1)


def hash_token(token: str) -> str:
    # Tokens are 256 bits of randomness, so a plain sha256 is enough (unlike a
    # password there is nothing to brute-force); it also lets us look the agent
    # up by hash instead of scanning and comparing.
    return hashlib.sha256(token.encode()).hexdigest()


def create_agent(name: str, expires_days: int | None = None) -> tuple[Agent, str]:
    """Create an agent and return it with its plaintext token (the only time
    the token exists outside the caller's hands)."""
    name = name.strip()
    if not NAME_RE.match(name):
        raise ValueError("Name must be 1-40 characters: letters, digits, '.', '_' or '-'.")
    if expires_days is not None and not 1 <= expires_days <= MAX_EXPIRY_DAYS:
        raise ValueError(f"Expiry must be between 1 and {MAX_EXPIRY_DAYS} days.")

    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    with Session(engine) as session:
        if session.exec(select(Agent).where(Agent.name == name)).first():
            raise ValueError(f"An agent named {name!r} already exists.")
        agent = Agent(
            name=name,
            token_hash=hash_token(token),
            expires_at=utcnow() + timedelta(days=expires_days) if expires_days else None,
        )
        session.add(agent)
        session.commit()
        session.refresh(agent)
        return agent, token


def authenticate(token: str) -> tuple[Agent | None, str]:
    """Resolve a bearer token to an enabled, unexpired agent. Returns
    (agent, "") on success or (None, reason) — the reason is for the audit log
    only and is never sent to the caller."""
    with Session(engine) as session:
        agent = session.exec(select(Agent).where(Agent.token_hash == hash_token(token))).first()
        if agent is None:
            return None, "unknown token"
        if not agent.enabled:
            return agent, "agent disabled"
        now = utcnow().replace(tzinfo=None)  # SQLite hands datetimes back naive; they are UTC
        if agent.expires_at is not None and agent.expires_at <= now:
            return agent, "token expired"
        # Not on every request: that would be a second write per call.
        if agent.last_used_at is None or now - agent.last_used_at > LAST_USED_REFRESH:
            agent.last_used_at = now
            session.add(agent)
            session.commit()
            session.refresh(agent)
        return agent, ""


def audit(agent_name: str | None, method: str, path: str, status_code: int, detail: str = "") -> None:
    with Session(engine) as session:
        row = AgentAudit(
            agent_name=agent_name,
            method=method,
            path=path[:AUDIT_PATH_MAX],
            status_code=status_code,
            detail=detail,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        session.exec(delete(AgentAudit).where(AgentAudit.id <= row.id - AUDIT_KEEP))
        session.commit()


def toggle_enabled(agent_id: int) -> None:
    with Session(engine) as session:
        agent = session.get(Agent, agent_id)
        if agent is not None:
            agent.enabled = not agent.enabled
            session.add(agent)
            session.commit()


def delete_agent(agent_id: int) -> None:
    with Session(engine) as session:
        agent = session.get(Agent, agent_id)
        if agent is not None:
            session.delete(agent)
            session.commit()
