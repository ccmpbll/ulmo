from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func
from sqlalchemy.orm import defer
from sqlmodel import Session, select

from app.database import engine
from app.deps import require_login
from app.models import AdminAudit, Agent, AgentAudit, CommandRun, RunHistory, SyncHistory
from app.templating import templates

# Everything that happened, newest first: playbook runs, command runs, git syncs, API requests
# (allowed and denied) and changes made on the Agents and Commands pages. Read-only and
# login-only. Command output is deliberately not shown here; a run's or sync's own page has its log.
router = APIRouter(dependencies=[Depends(require_login)])

PAGE_SIZE = 50
TABS = (
    ("playbooks", "Playbook runs"),
    ("commands", "Command runs"),
    ("syncs", "Syncs"),
    ("requests", "API requests"),
    ("changes", "Changes"),
)
DEFAULT_TAB = "playbooks"
PLAYBOOK_STATUSES = ("running", "success", "failed", "timeout", "cancelled")
COMMAND_STATUSES = ("running", "success", "failed", "timeout", "error")
SYNC_STATUSES = ("running", "success", "failed")


def _int(value: str, default: int = 1) -> int:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


def _distinct(session, column) -> list:
    return list(session.exec(select(column).distinct().order_by(column)).all())


@router.get("/activity", response_class=HTMLResponse)
def activity(
    request: Request,
    tab: str = DEFAULT_TAB,
    page: str = "1",
    agent: str = "",
    problems: str = "",
    admin: str = "",
    by: str = "",
    host: str = "",
    status: str = "",
    playbook: str = "",
):
    tab = tab if tab in dict(TABS) else DEFAULT_TAB
    options = []
    with Session(engine) as session:
        if tab == "playbooks":
            query, order = select(RunHistory), (RunHistory.started_at.desc(), RunHistory.id.desc())
            if by:
                query = query.where(RunHistory.triggered_by == by)
            if playbook:
                query = query.where(RunHistory.playbook == playbook)
            status = status if status in PLAYBOOK_STATUSES else ""
            if status:
                query = query.where(RunHistory.status == status)
            filters = {"by": by, "playbook": playbook, "status": status}
            choices = {"who": _distinct(session, RunHistory.triggered_by), "playbooks": _distinct(session, RunHistory.playbook), "statuses": PLAYBOOK_STATUSES}
        elif tab == "commands":
            query, order, options = select(CommandRun), (CommandRun.started_at.desc(), CommandRun.id.desc()), [defer(CommandRun.output)]
            if by:
                query = query.where(CommandRun.triggered_by == by)
            if host:
                query = query.where(CommandRun.host == host)
            status = status if status in COMMAND_STATUSES else ""
            if status:
                query = query.where(CommandRun.status == status)
            filters = {"by": by, "host": host, "status": status}
            choices = {"who": _distinct(session, CommandRun.triggered_by), "hosts": _distinct(session, CommandRun.host), "statuses": COMMAND_STATUSES}
        elif tab == "syncs":
            query, order = select(SyncHistory), (SyncHistory.started_at.desc(), SyncHistory.id.desc())
            if by:
                query = query.where(SyncHistory.triggered_by == by)
            status = status if status in SYNC_STATUSES else ""
            if status:
                query = query.where(SyncHistory.status == status)
            filters = {"by": by, "status": status}
            choices = {"who": _distinct(session, SyncHistory.triggered_by), "statuses": SYNC_STATUSES}
        elif tab == "requests":
            query, order = select(AgentAudit), (AgentAudit.id.desc(),)
            if agent == "(unknown)":
                query = query.where(AgentAudit.agent_name.is_(None))
            elif agent:
                query = query.where(AgentAudit.agent_name == agent)
            if problems:
                query = query.where(AgentAudit.status_code >= 400)
            filters = {"agent": agent, "problems": problems}
            choices = {"agents": list(session.exec(select(Agent.name).order_by(Agent.name)).all())}
        else:
            query, order = select(AdminAudit), (AdminAudit.id.desc(),)
            if admin:
                query = query.where(AdminAudit.admin == admin)
            filters = {"admin": admin}
            choices = {"admins": _distinct(session, AdminAudit.admin)}
        total = session.exec(select(func.count()).select_from(query.subquery())).one()
        pages = max(1, -(-total // PAGE_SIZE))
        current = min(_int(page), pages)
        rows = session.exec(query.options(*options).order_by(*order).offset((current - 1) * PAGE_SIZE).limit(PAGE_SIZE)).all()
    return templates.TemplateResponse(
        request,
        "activity.html",
        {
            "tabs": TABS,
            "tab": tab,
            "rows": rows,
            "page": current,
            "pages": pages,
            "total": total,
            "first": 0 if not total else (current - 1) * PAGE_SIZE + 1,
            "last": (current - 1) * PAGE_SIZE + len(rows),
            "filters": {k: v for k, v in filters.items() if v},
            "values": filters,
            "choices": choices,
        },
    )
