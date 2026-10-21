from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func
from sqlalchemy.orm import defer
from sqlmodel import Session, select

from app.database import engine
from app.deps import require_login
from app.models import AdminAudit, Agent, AgentAudit, CommandRun
from app.templating import templates

# Everything that happened, newest first: API requests (allowed and denied), changes made on
# the Agents and Commands pages, and command runs. Read-only and login-only. Command output is
# deliberately not shown here.
router = APIRouter(dependencies=[Depends(require_login)])

PAGE_SIZE = 50
TABS = ("requests", "changes", "runs")
RUN_STATUSES = ("running", "success", "failed", "timeout", "error")


def _int(value: str, default: int = 1) -> int:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


@router.get("/activity", response_class=HTMLResponse)
def activity(
    request: Request,
    tab: str = "requests",
    page: str = "1",
    agent: str = "",
    problems: str = "",
    admin: str = "",
    host: str = "",
    status: str = "",
):
    tab = tab if tab in TABS else "requests"
    filters = {}
    with Session(engine) as session:
        if tab == "requests":
            query = select(AgentAudit)
            if agent == "(unknown)":
                query = query.where(AgentAudit.agent_name.is_(None))
            elif agent:
                query = query.where(AgentAudit.agent_name == agent)
            if problems:
                query = query.where(AgentAudit.status_code >= 400)
            order, options = AgentAudit.id.desc(), []
            filters = {"agent": agent, "problems": problems}
            choices = {"agents": [a for a in session.exec(select(Agent.name).order_by(Agent.name)).all()]}
        elif tab == "changes":
            query = select(AdminAudit)
            if admin:
                query = query.where(AdminAudit.admin == admin)
            order, options = AdminAudit.id.desc(), []
            filters = {"admin": admin}
            choices = {"admins": list(session.exec(select(AdminAudit.admin).distinct().order_by(AdminAudit.admin)).all())}
        else:
            query = select(CommandRun)
            if agent:
                query = query.where(CommandRun.triggered_by == agent)
            if host:
                query = query.where(CommandRun.host == host)
            if status in RUN_STATUSES:
                query = query.where(CommandRun.status == status)
            order, options = CommandRun.id.desc(), [defer(CommandRun.output)]
            filters = {"agent": agent, "host": host, "status": status if status in RUN_STATUSES else ""}
            choices = {
                "who": list(session.exec(select(CommandRun.triggered_by).distinct().order_by(CommandRun.triggered_by)).all()),
                "hosts": list(session.exec(select(CommandRun.host).distinct().order_by(CommandRun.host)).all()),
                "statuses": RUN_STATUSES,
            }
        total = session.exec(select(func.count()).select_from(query.subquery())).one()
        pages = max(1, -(-total // PAGE_SIZE))
        current = min(_int(page), pages)
        rows = session.exec(query.options(*options).order_by(order).offset((current - 1) * PAGE_SIZE).limit(PAGE_SIZE)).all()
    return templates.TemplateResponse(
        request,
        "activity.html",
        {
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
