from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import defer
from sqlmodel import Session, select

from app.database import engine
from app.config import AUTH_DISABLED
from app.deps import require_login
from app.models import AdminAudit, Agent, AgentAudit, CommandRun, RunHistory, SyncHistory
from app.services import approvals, proposals
from app.templating import templates

# The Overview page, the landing page: what is waiting on the admin, what is running now, and
# below that everything that happened, newest first (playbook runs, command runs, git syncs, API
# requests (allowed and denied) and changes made on the Agents and Commands pages). Login-only. The
# only action here is deciding a waiting request, which goes through the Approvals routes. Command
# output is deliberately not shown; a run's or sync's own page has its log.
router = APIRouter(dependencies=[Depends(require_login)])

PAGE_SIZE = 50
TABS = (
    ("all", "All"),
    ("playbooks", "Playbook runs"),
    ("commands", "Command runs"),
    ("syncs", "Syncs"),
    ("requests", "API requests"),
    ("changes", "Changes"),
)
DEFAULT_TAB = "all"
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


def _row(kind, at, label, detail, by, status, status_text, started=None, finished=None, href=""):
    return {"kind": kind, "at": at, "label": label, "detail": detail, "by": by, "status": status, "status_text": status_text, "started_at": started, "finished_at": finished, "href": href}


def _newest(session, model, time_column, limit, options=()):
    return session.exec(select(model).options(*options).order_by(time_column.desc(), model.id.desc()).limit(limit)).all()


def _feed(session, page: str):
    """The All tab: the five logs merged, newest first. Each log is read only as far as this page
    reaches (page * PAGE_SIZE rows) and the merge is sorted in Python, so a deep page costs more
    but the logs are bounded by retention."""
    total = sum(session.exec(select(func.count()).select_from(m)).one() for m in (RunHistory, CommandRun, SyncHistory, AgentAudit, AdminAudit))
    pages = max(1, -(-total // PAGE_SIZE))
    current = min(_int(page), pages)
    reach = current * PAGE_SIZE
    rows = []
    for r in _newest(session, RunHistory, RunHistory.started_at, reach):
        detail = " · ".join(x for x in (f"tags: {r.tags}" if r.tags else "", f"limit: {r.limit}" if r.limit else "") if x)
        rows.append(_row("playbook", r.started_at, r.playbook, detail, r.triggered_by, r.status, r.status, r.started_at, r.finished_at, f"/runs/{r.id}"))
    for c in _newest(session, CommandRun, CommandRun.started_at, reach, [defer(CommandRun.output)]):
        status = "success" if c.status == "success" else ("running" if c.status == "running" else "failed")
        rows.append(_row("command", c.started_at, c.command, c.host, c.triggered_by, status, c.status, c.started_at, c.finished_at))
    for r in _newest(session, SyncHistory, SyncHistory.started_at, reach):
        rows.append(_row("sync", r.started_at, "Git sync", "", r.triggered_by, r.status, r.status, r.started_at, r.finished_at, f"/logs/{r.id}"))
    for e in _newest(session, AgentAudit, AgentAudit.at, reach):
        rows.append(_row("request", e.at, f"{e.method} {e.path}", e.detail, e.agent_name or "-", "success" if e.status_code < 400 else "failed", str(e.status_code)))
    for c in _newest(session, AdminAudit, AdminAudit.at, reach):
        rows.append(_row("change", c.at, c.action, c.detail, c.admin, "", ""))
    rows.sort(key=lambda r: r["at"], reverse=True)
    return rows[(current - 1) * PAGE_SIZE : reach], total, pages, current


def _running(session) -> list[dict]:
    """What is executing right now, for the strip under "Needs you"."""
    out = []
    for r in session.exec(select(RunHistory).where(RunHistory.status == "running").order_by(RunHistory.started_at.desc()).limit(5)).all():
        out.append({"kind": "Playbook", "label": r.playbook, "by": r.triggered_by, "at": r.started_at, "href": f"/runs/{r.id}"})
    for c in session.exec(select(CommandRun).options(defer(CommandRun.output)).where(CommandRun.status == "running").order_by(CommandRun.started_at.desc()).limit(5)).all():
        out.append({"kind": "Command", "label": f"{c.command} on {c.host}", "by": c.triggered_by, "at": c.started_at, "href": ""})
    for r in session.exec(select(SyncHistory).where(SyncHistory.status == "running").order_by(SyncHistory.started_at.desc()).limit(5)).all():
        out.append({"kind": "Sync", "label": "Git sync", "by": r.triggered_by, "at": r.started_at, "href": f"/logs/{r.id}"})
    return sorted(out, key=lambda x: x["at"], reverse=True)[:5]


@router.get("/activity")
def activity_moved(request: Request):
    """The log used to live here; it is the lower half of the Overview now."""
    query = request.url.query
    return RedirectResponse("/" + (f"?{query}" if query else ""), status_code=303)


@router.get("/", response_class=HTMLResponse)
def overview(
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
        running = _running(session)
        if tab == "all":
            rows, total, pages, current = _feed(session, page)
            filters, choices = {}, {}
        elif tab == "playbooks":
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
        if tab != "all":
            total = session.exec(select(func.count()).select_from(query.subquery())).one()
            pages = max(1, -(-total // PAGE_SIZE))
            current = min(_int(page), pages)
            rows = session.exec(query.options(*options).order_by(*order).offset((current - 1) * PAGE_SIZE).limit(PAGE_SIZE)).all()
    return templates.TemplateResponse(
        request,
        "overview.html",
        {
            "ask_approvals": approvals.pending(),
            "ask_proposals": proposals.pending(),
            "locked": AUTH_DISABLED,
            "running": running,
            "flash": request.session.pop("flash", ""),
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
