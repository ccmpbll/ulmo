from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from app.config import AUTH_DISABLED
from app.database import engine
from app.deps import require_login
from app.models import Agent, Grant, Role, RoleCommand
from app.services import agents, command_library, git_sync, inventory
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
        role_commands = session.exec(select(RoleCommand)).all()
    library = command_library.load()[0]
    return templates.TemplateResponse(
        request,
        "agents.html",
        {
            "agents": rows,
            "roles": roles,
            "grants": {r.id: [g for g in grants if g.role_id == r.id] for r in roles},
            "library_commands": sorted(library.commands),
            "command_items": [
                (name, f"runs on {', '.join(library.hosts_offering(name))}" if library.hosts_offering(name) else "no host offers this yet")
                for name in sorted(library.commands)
            ],
            "role_commands": {r.id: sorted(c.command for c in role_commands if c.role_id == r.id) for r in roles},
            "role_command_items": {r.id: [(c.command, "") for c in sorted(role_commands, key=lambda c: c.command) if c.role_id == r.id] for r in roles},
            "role_needing": {r.id: sorted(c.command for c in role_commands if c.role_id == r.id and c.requires_approval) for r in roles},
            "offered_by": {name: library.hosts_offering(name) for name in library.commands},
            "playbooks": git_sync.list_playbooks(),
            "hosts": inventory.list_hosts(),
            "host_items": [(h, "") for h in inventory.list_hosts()],
            "runs_enabled": agents.runs_enabled(),
            "default_per_hour": agents.DEFAULT_MAX_PER_HOUR,
            "used_last_hour": {a.id: agents.requests_last_hour(a) for a in rows},
            "error": error,
            "new_token": new_token,
        },
        status_code=400 if error else 200,
        # The page holding a plaintext token must not be kept by a browser or proxy cache.
        headers={"Cache-Control": "no-store"} if new_token else None,
    )


def _back():
    return RedirectResponse("/agents", status_code=303)


def _whole_number(value: str, what: str) -> int | None:
    """A form number that may be left blank (None); anything else must be a whole number."""
    value = value.strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        raise ValueError(f"{what} must be a whole number.") from None


@router.get("/agents", response_class=HTMLResponse)
def agents_page(request: Request):
    return _page(request)


@router.post("/agents", response_class=HTMLResponse)
def create_agent(
    request: Request,
    name: str = Form(...),
    expires_days: str = Form(""),
    role_id: str = Form(""),
    max_per_hour: str = Form(""),
    user=Depends(require_login),
):
    if AUTH_DISABLED:
        # Without a login anyone who can reach this page could mint a token.
        return _page(request, error=LOGIN_REQUIRED)
    try:
        agent, token = agents.create_agent(
            name, _whole_number(expires_days, "Expiry"), _whole_number(role_id, "Role"), _whole_number(max_per_hour, "The hourly limit")
        )
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


@router.post("/agents/{agent_id}/limit")
def set_agent_limit(request: Request, agent_id: int, max_per_hour: str = Form(""), user=Depends(require_login)):
    # A higher limit is a widening, so it is locked like the rest while auth is disabled.
    if AUTH_DISABLED:
        return _page(request, error=LOGIN_REQUIRED)
    try:
        agents.set_hourly_limit(agent_id, _whole_number(max_per_hour, "The hourly limit"))
    except ValueError as exc:
        return _page(request, error=str(exc))
    agents.admin_audit(user.username, "set agent limit", f"agent id {agent_id}: {max_per_hour.strip() or 'default'} per hour")
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
        agents.assign_role(agent_id, _whole_number(role_id, "Role"))
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
    requires_approval: str = Form(""),
    user=Depends(require_login),
):
    if AUTH_DISABLED:
        return _page(request, error=LOGIN_REQUIRED)
    try:
        grant = agents.add_grant(role_id, playbook, hosts, bool(requires_approval))
    except ValueError as exc:
        return _page(request, error=str(exc))
    agents.admin_audit(user.username, "add grant", f"role id {role_id}: {grant.playbook} on {grant.hosts}" + (" (needs approval)" if grant.requires_approval else ""))
    return _back()


@router.post("/roles/{role_id}/commands", response_class=HTMLResponse)
def set_role_commands(
    request: Request,
    role_id: int,
    commands: list[str] = Form([]),
    user=Depends(require_login),
):
    if AUTH_DISABLED:
        return _page(request, error=LOGIN_REQUIRED)
    try:
        names = agents.set_role_commands(role_id, commands)
    except ValueError as exc:
        return _page(request, error=str(exc))
    agents.admin_audit(user.username, "set role commands", f"role id {role_id}: {', '.join(names) or 'none'}")
    return _back()


@router.post("/roles/{role_id}/approval-commands", response_class=HTMLResponse)
def set_approval_commands(
    request: Request,
    role_id: int,
    commands: list[str] = Form([]),
    user=Depends(require_login),
):
    # Turning approval OFF for a command is a widening, so it is locked like the rest while auth is disabled.
    if AUTH_DISABLED:
        return _page(request, error=LOGIN_REQUIRED)
    try:
        names = agents.set_commands_needing_approval(role_id, commands)
    except ValueError as exc:
        return _page(request, error=str(exc))
    agents.admin_audit(user.username, "set commands needing approval", f"role id {role_id}: {', '.join(names) or 'none'}")
    return _back()


@router.post("/grants/{grant_id}/approval")
def toggle_grant_approval(request: Request, grant_id: int, user=Depends(require_login)):
    if AUTH_DISABLED:
        return _page(request, error=LOGIN_REQUIRED)
    try:
        now = agents.toggle_grant_approval(grant_id)
    except ValueError as exc:
        return _page(request, error=str(exc))
    agents.admin_audit(user.username, "grant approval", f"grant id {grant_id}: " + ("needs approval" if now else "runs at once"))
    return _back()


@router.post("/grants/{grant_id}/delete")
def delete_grant(grant_id: int, user=Depends(require_login)):
    agents.delete_grant(grant_id)
    agents.admin_audit(user.username, "delete grant", f"grant id {grant_id}")
    return _back()
