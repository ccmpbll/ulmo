import hashlib
import re
import secrets
from datetime import timedelta

from sqlmodel import Session, delete, select

from app.database import engine
from app.models import AdminAudit, Agent, AgentAudit, AgentRun, Grant, Role, RunHistory, utcnow
from app.services import git_sync, inventory, settings_store

TOKEN_PREFIX = "ulmo_"
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
MAX_EXPIRY_DAYS = 3650
AUDIT_KEEP = 5000  # newest audit rows kept; unauthenticated callers can write rows too
AUDIT_PATH_MAX = 200
AUDIT_DETAIL_MAX = 300  # detail can carry agent-supplied text (denial reasons)
LAST_USED_REFRESH = timedelta(minutes=1)


def hash_token(token: str) -> str:
    # Tokens are 256 bits of randomness, so a plain sha256 is enough (unlike a
    # password there is nothing to brute-force); it also lets us look the agent
    # up by hash instead of scanning and comparing.
    return hashlib.sha256(token.encode()).hexdigest()


def create_agent(name: str, expires_days: int | None = None, role_id: int | None = None) -> tuple[Agent, str]:
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
        if role_id is not None and session.get(Role, role_id) is None:
            raise ValueError("Unknown role.")
        agent = Agent(
            name=name,
            role_id=role_id,
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
            detail=detail[:AUDIT_DETAIL_MAX],
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
            # SQLite reuses the id of a deleted last row; a new agent must not inherit old runs.
            session.exec(delete(AgentRun).where(AgentRun.agent_id == agent_id))
            session.delete(agent)
            session.commit()


# --- roles and grants ---------------------------------------------------------


def runs_enabled() -> bool:
    return not settings_store.get("agent_runs_disabled")


def set_runs_enabled(enabled: bool) -> None:
    settings_store.set_many({"agent_runs_disabled": "" if enabled else "1"})


def create_role(name: str) -> Role:
    name = name.strip()
    if not NAME_RE.match(name):
        raise ValueError("Name must be 1-40 characters: letters, digits, '.', '_' or '-'.")
    with Session(engine) as session:
        if session.exec(select(Role).where(Role.name == name)).first():
            raise ValueError(f"A role named {name!r} already exists.")
        role = Role(name=name)
        session.add(role)
        session.commit()
        session.refresh(role)
        return role


def delete_role(role_id: int) -> None:
    """Agents on the role lose it (and with it the ability to run anything)."""
    with Session(engine) as session:
        for agent in session.exec(select(Agent).where(Agent.role_id == role_id)).all():
            agent.role_id = None
            session.add(agent)
        session.exec(delete(Grant).where(Grant.role_id == role_id))
        session.exec(delete(Role).where(Role.id == role_id))
        session.commit()


def add_grant(role_id: int, playbook: str, hosts: list[str]) -> Grant:
    hosts = sorted({h.strip() for h in hosts if h.strip()})
    if not hosts:
        raise ValueError("Pick at least one host.")
    if playbook not in {p["rel_path"] for p in git_sync.list_playbooks()}:
        raise ValueError("Unknown playbook.")
    known = set(inventory.list_hosts())
    unknown = [h for h in hosts if h not in known]
    if unknown:
        raise ValueError(f"Not in the inventory: {', '.join(unknown)}")
    groups = set(inventory.list_groups())
    shadowed = [h for h in hosts if h in groups]
    if shadowed:
        raise ValueError(
            f"Also a group name, so --limit would match the whole group: {', '.join(shadowed)}"
        )
    with Session(engine) as session:
        if session.get(Role, role_id) is None:
            raise ValueError("Unknown role.")
        grant = Grant(role_id=role_id, playbook=playbook, hosts=",".join(hosts))
        session.add(grant)
        session.commit()
        session.refresh(grant)
        return grant


def delete_grant(grant_id: int) -> None:
    with Session(engine) as session:
        session.exec(delete(Grant).where(Grant.id == grant_id))
        session.commit()


def assign_role(agent_id: int, role_id: int | None) -> None:
    with Session(engine) as session:
        agent = session.get(Agent, agent_id)
        if agent is None:
            raise ValueError("Unknown agent.")
        if role_id is not None and session.get(Role, role_id) is None:
            raise ValueError("Unknown role.")
        agent.role_id = role_id
        session.add(agent)
        session.commit()


def grants_for(agent: Agent) -> list[Grant]:
    if agent.role_id is None:
        return []
    with Session(engine) as session:
        return list(session.exec(select(Grant).where(Grant.role_id == agent.role_id)).all())


def check_run(agent: Agent, playbook: str, hosts: list[str]) -> str:
    """Why this agent may not run `playbook` on `hosts`, or "" if it may.
    Default deny: needs grants for the playbook that together name every
    requested host, matched exactly. ansible's --limit would also read a name
    as a group, so a name that is (or has become) a group, or that is no
    longer in the inventory, is refused, and so is everything when the
    inventory cannot be read."""
    if not hosts:
        return "limit is required"
    mine = [g for g in grants_for(agent) if g.playbook == playbook]
    if not mine:
        return f"no grant for playbook {playbook!r}"
    allowed = {h for g in mine for h in g.hosts.split(",")}
    missing = sorted(set(hosts) - allowed)
    if missing:
        return f"hosts not granted: {', '.join(missing)}"
    known = set(inventory.list_hosts())
    if not known:
        return "inventory unavailable"
    groups = set(inventory.list_groups())
    bad = sorted(h for h in set(hosts) if h not in known or h in groups)
    if bad:
        return f"not a plain inventory host: {', '.join(bad)}"
    return ""


# --- who started what, and the admin trail ------------------------------------


def record_agent_run(run_id: int, agent_id: int) -> None:
    with Session(engine) as session:
        session.add(AgentRun(run_id=run_id, agent_id=agent_id))
        session.commit()


def owns_run(agent: Agent, run_id: int) -> bool:
    with Session(engine) as session:
        row = session.get(AgentRun, run_id)
    return row is not None and row.agent_id == agent.id


def running_conflict(playbook: str, hosts: list[str]) -> RunHistory | None:
    """A run of the same playbook that is still going and overlaps these hosts.
    A run with no --limit (started from the UI) covers every host."""
    with Session(engine) as session:
        running = session.exec(
            select(RunHistory).where(RunHistory.status == "running", RunHistory.playbook == playbook)
        ).all()
    for run in running:
        if not run.limit or set(run.limit.split(",")) & set(hosts):
            return run
    return None


def running_agent_runs() -> int:
    with Session(engine) as session:
        return len(
            session.exec(
                select(AgentRun.run_id).join(RunHistory, RunHistory.id == AgentRun.run_id).where(
                    RunHistory.status == "running"
                )
            ).all()
        )


def admin_audit(admin: str, action: str, detail: str = "") -> None:
    with Session(engine) as session:
        session.add(AdminAudit(admin=admin, action=action, detail=detail[:AUDIT_DETAIL_MAX]))
        session.commit()
