from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from app.config import AUTH_DISABLED
from app.database import engine
from app.deps import require_login
from app.models import AdminAudit, Agent, AgentAudit, CommandGrant, CommandRun, Grant, Role
from app.services import agents, command_templates, git_sync, inventory
from app.templating import templates

# Admin side of the agent API: cookie-session login only. Tokens, roles and
# grants are created and changed here and nowhere else, and every change is
# recorded in AdminAudit.
router = APIRouter(dependencies=[Depends(require_login)])

LOGIN_REQUIRED = "Turn off ULMO_DISABLE_AUTH first: without a login anyone who can reach this page could widen what agents may do."


def _page(request: Request, error: str | None = None, new_token: tuple[str, str] | None = None):
    with Session(engine) as session:
        rows = session.exec(select(Agent).order_by(Agent.name)).all()
        roles = session.exec(select(Role).order_by(Role.name)).all()
        grants = session.exec(select(Grant).order_by(Grant.playbook)).all()
        audit = session.exec(select(AgentAudit).order_by(AgentAudit.id.desc()).limit(50)).all()
        changes = session.exec(select(AdminAudit).order_by(AdminAudit.id.desc()).limit(20)).all()
        command_grants = session.exec(select(CommandGrant).order_by(CommandGrant.template)).all()
        command_runs = session.exec(select(CommandRun).order_by(CommandRun.id.desc()).limit(20)).all()
    templates_loaded, template_errors = command_templates.load()
    return templates.TemplateResponse(
        request,
        "agents.html",
        {
            "agents": rows,
            "roles": roles,
            "grants": {r.id: [g for g in grants if g.role_id == r.id] for r in roles},
            "command_grants": {r.id: [g for g in command_grants if g.role_id == r.id] for r in roles},
            "command_templates": sorted(templates_loaded.values(), key=lambda t: t.id),
            "template_errors": template_errors,
            "command_runs": command_runs,
            "playbooks": git_sync.list_playbooks(),
            "hosts": inventory.list_hosts(),
            "runs_enabled": agents.runs_enabled(),
            "audit": audit,
            "changes": changes,
            "error": error,
            "new_token": new_token,
        },
        status_code=400 if error else 200,
        # The page holding a plaintext token must not be kept by a browser or proxy cache.
        headers={"Cache-Control": "no-store"} if new_token else None,
    )


def _back():
    return RedirectResponse("/agents", status_code=303)


def _role_id(value: str) -> int | None:
    return int(value) if value.strip() else None


@router.get("/agents", response_class=HTMLResponse)
def agents_page(request: Request):
    return _page(request)


@router.post("/agents", response_class=HTMLResponse)
def create_agent(
    request: Request,
    name: str = Form(...),
    expires_days: str = Form(""),
    role_id: str = Form(""),
    user=Depends(require_login),
):
    if AUTH_DISABLED:
        # Without a login anyone who can reach this page could mint a token.
        return _page(request, error=LOGIN_REQUIRED)
    try:
        days = int(expires_days) if expires_days.strip() else None
        agent, token = agents.create_agent(name, days, _role_id(role_id))
    except ValueError as exc:
        return _page(request, error=str(exc))
    agents.admin_audit(user.username, "create agent", f"{agent.name}, role id {agent.role_id}")
    # Rendered directly (not redirected) so the token is shown exactly once and
    # never ends up in a URL, history entry or log line.
    return _page(request, new_token=(agent.name, token))


@router.post("/agents/{agent_id}/toggle")
def toggle_agent(request: Request, agent_id: int, user=Depends(require_login)):
    if AUTH_DISABLED:
        return _page(request, error=LOGIN_REQUIRED)
    agents.toggle_enabled(agent_id)
    agents.admin_audit(user.username, "toggle agent", f"agent id {agent_id}")
    return _back()


@router.post("/agents/{agent_id}/delete")
def delete_agent(agent_id: int, user=Depends(require_login)):
    agents.delete_agent(agent_id)
    agents.admin_audit(user.username, "delete agent", f"agent id {agent_id}")
    return _back()


@router.post("/agents/{agent_id}/role")
def set_agent_role(request: Request, agent_id: int, role_id: str = Form(""), user=Depends(require_login)):
    if AUTH_DISABLED:
        return _page(request, error=LOGIN_REQUIRED)
    try:
        agents.assign_role(agent_id, _role_id(role_id))
    except ValueError as exc:
        return _page(request, error=str(exc))
    agents.admin_audit(user.username, "set agent role", f"agent id {agent_id} -> role id {role_id or 'none'}")
    return _back()


@router.post("/agent-runs/toggle")
def toggle_agent_runs(enable: str = Form(""), user=Depends(require_login)):
    # Kill switch. Switching OFF is always allowed; switching back ON needs a login like any widening.
    if enable and AUTH_DISABLED:
        return _back()
    agents.set_runs_enabled(bool(enable))
    agents.admin_audit(user.username, "agent runs " + ("on" if enable else "off"))
    return _back()


@router.post("/roles", response_class=HTMLResponse)
def create_role(request: Request, name: str = Form(...), user=Depends(require_login)):
    try:
        role = agents.create_role(name)
    except ValueError as exc:
        return _page(request, error=str(exc))
    agents.admin_audit(user.username, "create role", role.name)
    return _back()


@router.post("/roles/{role_id}/delete")
def delete_role(role_id: int, user=Depends(require_login)):
    agents.delete_role(role_id)
    agents.admin_audit(user.username, "delete role", f"role id {role_id}")
    return _back()


@router.post("/roles/{role_id}/grants", response_class=HTMLResponse)
def add_grant(
    request: Request,
    role_id: int,
    playbook: str = Form(...),
    hosts: list[str] = Form([]),
    user=Depends(require_login),
):
    if AUTH_DISABLED:
        return _page(request, error=LOGIN_REQUIRED)
    try:
        grant = agents.add_grant(role_id, playbook, hosts)
    except ValueError as exc:
        return _page(request, error=str(exc))
    agents.admin_audit(user.username, "add grant", f"role id {role_id}: {grant.playbook} on {grant.hosts}")
    return _back()


@router.post("/roles/{role_id}/command-grants", response_class=HTMLResponse)
def add_command_grant(
    request: Request,
    role_id: int,
    template: str = Form(...),
    hosts: list[str] = Form([]),
    user=Depends(require_login),
):
    if AUTH_DISABLED:
        return _page(request, error=LOGIN_REQUIRED)
    try:
        grant = agents.add_command_grant(role_id, template, hosts)
    except ValueError as exc:
        return _page(request, error=str(exc))
    agents.admin_audit(user.username, "add command grant", f"role id {role_id}: {grant.template} on {grant.hosts}")
    return _back()


@router.post("/command-grants/{grant_id}/delete")
def delete_command_grant(grant_id: int, user=Depends(require_login)):
    agents.delete_command_grant(grant_id)
    agents.admin_audit(user.username, "delete command grant", f"command grant id {grant_id}")
    return _back()


@router.post("/grants/{grant_id}/delete")
def delete_grant(grant_id: int, user=Depends(require_login)):
    agents.delete_grant(grant_id)
    agents.admin_audit(user.username, "delete grant", f"grant id {grant_id}")
    return _back()
