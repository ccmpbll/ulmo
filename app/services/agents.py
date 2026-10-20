import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone

from sqlmodel import Session, select

from app.database import engine
from app.models import Agent, AgentAudit, utcnow

TOKEN_PREFIX = "ulmo_"
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")


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
    if expires_days is not None and expires_days < 1:
        raise ValueError("Expiry must be at least 1 day.")

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
        if agent.expires_at is not None:
            expires = agent.expires_at
            if expires.tzinfo is None:  # SQLite hands datetimes back naive; they are UTC
                expires = expires.replace(tzinfo=timezone.utc)
            if expires <= utcnow():
                return agent, "token expired"
        agent.last_used_at = utcnow()
        session.add(agent)
        session.commit()
        session.refresh(agent)
        return agent, ""


def audit(agent_name: str | None, method: str, path: str, outcome: str, detail: str = "") -> None:
    with Session(engine) as session:
        session.add(
            AgentAudit(
                agent_name=agent_name, method=method, path=path, outcome=outcome, detail=detail
            )
        )
        session.commit()


def set_enabled(agent_id: int, enabled: bool) -> None:
    with Session(engine) as session:
        agent = session.get(Agent, agent_id)
        if agent is not None:
            agent.enabled = enabled
            session.add(agent)
            session.commit()


def delete_agent(agent_id: int) -> None:
    with Session(engine) as session:
        agent = session.get(Agent, agent_id)
        if agent is not None:
            session.delete(agent)
            session.commit()
