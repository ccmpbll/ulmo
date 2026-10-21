"""Approvals: a role can mark a command or a playbook grant as "needs approval".

A call that needs it is recorded as a pending Approval and nothing runs. An admin
decides on the Approvals page (cookie login only; no agent token reaches it). On
approval the run starts through the same path a direct call uses, with every check
repeated, so a role, host or command that changed while the request waited is
refused rather than trusted. The agent can only look at its own requests.
"""
import json
import threading
from datetime import timedelta
from typing import Callable

from sqlmodel import Session, delete, func, select, update

from app.database import engine
from app.models import Agent, Approval, Grant, RoleCommand, utcnow
from app.services import agent_runs

EXPIRY = timedelta(minutes=15)  # a request nobody decided on this long is dropped
MAX_PENDING_PER_AGENT = 10  # so a stuck workflow cannot bury the real requests
KEEP = 500  # newest approvals kept


_create_lock = threading.Lock()  # the cap and the duplicate check look, then write


class TooManyPending(ValueError):
    pass


def commands_needing(agent: Agent) -> set[str]:
    """The command names this agent's role marks as needing approval."""
    if agent.role_id is None:
        return set()
    with Session(engine) as session:
        return set(
            session.exec(
                select(RoleCommand.command).where(RoleCommand.role_id == agent.role_id, RoleCommand.requires_approval == True)  # noqa: E712
            ).all()
        )


def playbook_needs(agent: Agent, playbook: str, hosts: list[str]) -> bool:
    """A playbook run needs approval unless the grants that do not ask for it already
    cover every requested host (grants for one playbook add up, so the freest path wins)."""
    if agent.role_id is None:
        return True
    with Session(engine) as session:
        mine = session.exec(select(Grant).where(Grant.role_id == agent.role_id, Grant.playbook == playbook)).all()
    free = {h for g in mine if not g.requires_approval for h in g.hosts.split(",")}
    return not set(hosts) <= free


def expire_stale() -> None:
    with Session(engine) as session:
        session.exec(
            update(Approval).where(Approval.status == "pending", Approval.expires_at < utcnow()).values(status="expired")
        )
        session.commit()


def _key(row: Approval) -> tuple:
    return (row.kind, row.target, row.host, row.params)


def clean_note(note: str | None) -> str:
    """The agent's own words, made safe to show next to Approve: no control, zero-width or
    direction-override characters (they could make the text read differently from what was sent),
    and whitespace collapsed."""
    return " ".join("".join(c for c in (note or "") if c.isprintable() or c.isspace()).split())


def create(agent: Agent, kind: str, target: str, host: str, params: dict, line: str, agent_note: str = "", before_new: Callable[[], None] | None = None) -> tuple[Approval, bool]:
    """Record a request, or return the identical one already waiting (a workflow that retries
    must not pile up copies, each of which could run). `before_new` runs only when a new row
    is about to be made (the hourly allowance goes there, so a retry costs nothing).
    Returns (approval, created)."""
    params_json = json.dumps(params, sort_keys=True)
    expire_stale()
    with _create_lock, Session(engine) as session:
        waiting = session.exec(select(Approval).where(Approval.agent_id == agent.id, Approval.status == "pending")).all()
        same = next((row for row in waiting if _key(row) == (kind, target, host, params_json)), None)
        if same is not None:
            return same, False
        if len(waiting) >= MAX_PENDING_PER_AGENT:
            raise TooManyPending(f"{MAX_PENDING_PER_AGENT} requests from this agent are already waiting for approval")
        if before_new is not None:
            before_new()
        row = Approval(
            agent_id=agent.id, agent_name=agent.name, kind=kind, target=target, host=host, params=params_json, line=line, agent_note=agent_note,
            expires_at=utcnow() + EXPIRY,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        session.exec(delete(Approval).where(Approval.id <= row.id - KEEP))
        session.commit()
        session.refresh(row)  # the commit expired it, and the caller reads it after the session closes
        return row, True


def get(approval_id: int) -> Approval | None:
    expire_stale()
    with Session(engine) as session:
        return session.get(Approval, approval_id)


def pending() -> list[Approval]:
    expire_stale()
    with Session(engine) as session:
        return list(session.exec(select(Approval).where(Approval.status == "pending").order_by(Approval.id)).all())


def recent() -> list[Approval]:
    expire_stale()
    with Session(engine) as session:
        return list(
            session.exec(select(Approval).where(Approval.status != "pending").order_by(Approval.id.desc()).limit(50)).all()
        )


def pending_count() -> int:
    """For the top bar on every page: one COUNT, and no write (an expired request is simply not counted)."""
    with Session(engine) as session:
        return session.exec(
            select(func.count()).select_from(Approval).where(Approval.status == "pending", Approval.expires_at >= utcnow())
        ).one()


def decide(approval_id: int, approve: bool, admin: str) -> Approval:
    """Record the decision, once, and on approval start the run (agent_runs repeats every check a
    direct call gets). Raises ValueError if the request is not pending."""
    expire_stale()
    with Session(engine) as session:
        # One conditional UPDATE: two admins (or two taps) cannot both decide the same request.
        result = session.exec(
            update(Approval)
            .where(Approval.id == approval_id, Approval.status == "pending")
            .values(status="approved" if approve else "denied", decided_by=admin, decided_at=utcnow())
        )
        session.commit()
        row = session.get(Approval, approval_id)
        if result.rowcount != 1:
            raise ValueError("No such request." if row is None else f"This request is already {row.status}.")
        session.expunge(row)
    if not approve:
        return row
    try:
        run_id = agent_runs.start_approved(row)
        update_values = {"run_id": run_id}
    except Exception as exc:  # noqa: BLE001 - whatever stopped it is shown to the admin
        update_values = {"status": "failed", "note": str(getattr(exc, "reason", exc))[:300]}
    with Session(engine) as session:
        session.exec(update(Approval).where(Approval.id == approval_id).values(**update_values))
        session.commit()
        return session.get(Approval, approval_id)
