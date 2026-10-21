import hashlib
import re
import secrets
from datetime import timedelta

from sqlalchemy.exc import OperationalError
from sqlmodel import Session, delete, select, update

from app.database import engine
from app.models import (
    AdminAudit,
    Agent,
    AgentAudit,
    AgentRun,
    Approval,
    CommandRun,
    Grant,
    Role,
    RoleCommand,
    RunHistory,
    utcnow,
)
from app.services import command_library, git_sync, inventory, settings_store

TOKEN_PREFIX = "ulmo_"
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
MAX_EXPIRY_DAYS = 3650
AUDIT_KEEP = 5000  # newest audit rows kept; unauthenticated callers can write rows too
ADMIN_AUDIT_KEEP = 5000  # newest admin changes kept
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
            session.exec(delete(Approval).where(Approval.agent_id == agent_id))
            session.exec(update(CommandRun).where(CommandRun.agent_id == agent_id).values(agent_id=None))
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
        session.exec(update(Agent).where(Agent.role_id == role_id).values(role_id=None))
        session.exec(delete(Grant).where(Grant.role_id == role_id))
        session.exec(delete(RoleCommand).where(RoleCommand.role_id == role_id))
        session.exec(delete(Role).where(Role.id == role_id))
        session.commit()


def _checked_hosts(hosts: list[str]) -> list[str]:
    """Cleaned, sorted host names, all of which exist in the inventory."""
    hosts = sorted({h.strip() for h in hosts if h.strip()})
    if not hosts:
        raise ValueError("Pick at least one host.")
    known = set(inventory.list_hosts())
    unknown = [h for h in hosts if h not in known]
    if unknown:
        raise ValueError(f"Not in the inventory: {', '.join(unknown)}")
    return hosts


def add_grant(role_id: int, playbook: str, hosts: list[str], requires_approval: bool = False) -> Grant:
    hosts = _checked_hosts(hosts)
    if playbook not in {p["rel_path"] for p in git_sync.list_playbooks()}:
        raise ValueError("Unknown playbook.")
    groups = set(inventory.list_groups())
    shadowed = [h for h in hosts if h in groups]
    if shadowed:
        raise ValueError(
            f"Also a group name, so --limit would match the whole group: {', '.join(shadowed)}"
        )
    with Session(engine) as session:
        if session.get(Role, role_id) is None:
            raise ValueError("Unknown role.")
        grant = Grant(role_id=role_id, playbook=playbook, hosts=",".join(hosts), requires_approval=requires_approval)
        session.add(grant)
        session.commit()
        session.refresh(grant)
        return grant


def set_role_commands(role_id: int, commands: list[str]) -> list[str]:
    """Replace the set of library commands a role may use. Returns the new set."""
    names = sorted({c.strip() for c in commands if c.strip()})
    unknown = sorted(set(names) - set(command_library.load()[0].commands))
    if unknown:
        raise ValueError(f"Not in the command library: {', '.join(unknown)}")
    with Session(engine) as session:
        if session.get(Role, role_id) is None:
            raise ValueError("Unknown role.")
        asking = set(  # saving the list again must not quietly drop "needs approval"
            session.exec(select(RoleCommand.command).where(RoleCommand.role_id == role_id, RoleCommand.requires_approval == True)).all()  # noqa: E712
        )
        session.exec(delete(RoleCommand).where(RoleCommand.role_id == role_id))
        for name in names:
            session.add(RoleCommand(role_id=role_id, command=name, requires_approval=name in asking))
        session.commit()
    return names


def set_commands_needing_approval(role_id: int, commands: list[str]) -> list[str]:
    """Mark which of the role's commands wait for an admin's approval (all others run at once)."""
    names = sorted({c.strip() for c in commands if c.strip()})
    with Session(engine) as session:
        if session.get(Role, role_id) is None:
            raise ValueError("Unknown role.")
        held = set(session.exec(select(RoleCommand.command).where(RoleCommand.role_id == role_id)).all())
        outside = sorted(set(names) - held)
        if outside:
            raise ValueError(f"Not commands of this role: {', '.join(outside)}")
        for row in session.exec(select(RoleCommand).where(RoleCommand.role_id == role_id)).all():
            row.requires_approval = row.command in names
            session.add(row)
        session.commit()
    return names


def toggle_grant_approval(grant_id: int) -> bool:
    with Session(engine) as session:
        grant = session.get(Grant, grant_id)
        if grant is None:
            raise ValueError("Unknown grant.")
        grant.requires_approval = not grant.requires_approval
        session.add(grant)
        session.commit()
        return grant.requires_approval


def rename_role_command(old: str, new: str) -> None:
    """A command renamed on purpose keeps the roles that held it."""
    with Session(engine) as session:
        session.exec(update(RoleCommand).where(RoleCommand.command == old).values(command=new))
        session.commit()


def purge_missing_commands(library) -> None:
    """A command that is gone from the library must leave every role, or a new
    command later given the same name would silently be allowed to them. Runs
    whenever a library that parses is loaded, so a delete, a restore and a hand
    edit are all covered."""
    try:
        with Session(engine) as session:
            names = set(session.exec(select(RoleCommand.command)).all()) - set(library.commands)
            if names:
                session.exec(delete(RoleCommand).where(RoleCommand.command.in_(names)))
                session.commit()
    except OperationalError:  # the tables do not exist yet (first start): no roles to clean
        pass


command_library.on_valid_load(purge_missing_commands)


def role_commands(role_id: int | None) -> list[str]:
    if role_id is None:
        return []
    with Session(engine) as session:
        rows = session.exec(select(RoleCommand.command).where(RoleCommand.role_id == role_id)).all()
    return sorted(rows)


def commands_for(agent: Agent) -> dict[str, list[str]]:
    """What this agent can run: command name -> hosts that offer it, for the
    commands its role includes that still exist."""
    library = command_library.load()[0]
    out = {}
    for name in role_commands(agent.role_id):
        if name in library.commands:
            out[name] = library.hosts_offering(name)
    return out


def check_command(agent: Agent, command: str, host: str) -> str:
    """Why this agent may not run `command` on `host`, or "" if it may. Both
    must hold: the role includes the command AND the host offers it."""
    if command not in role_commands(agent.role_id):
        return f"no permission for command {command!r}"
    library = command_library.load()[0]
    if command not in library.commands:
        return "that command no longer exists"
    if host not in library.hosts:
        return f"unknown host: {host}"
    if command not in library.hosts[host].commands:
        return f"{host} does not offer {command}"
    return ""


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
        row = AdminAudit(admin=admin, action=action, detail=detail[:AUDIT_DETAIL_MAX])
        session.add(row)
        session.commit()
        session.refresh(row)
        session.exec(delete(AdminAudit).where(AdminAudit.id <= row.id - ADMIN_AUDIT_KEEP))
        session.commit()
