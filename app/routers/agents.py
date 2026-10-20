from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.deps import require_login
from app.services import agents
from app.templating import templates

# Admin side of the agent API: cookie-session login only. Tokens are minted
# and revoked here and nowhere else.
router = APIRouter(dependencies=[Depends(require_login)])


def _page(request: Request, error: str | None = None, new_token: tuple[str, str] | None = None):
    return templates.TemplateResponse(
        request,
        "agents.html",
        {
            "agents": agents.list_agents(),
            "audit": agents.recent_audit(),
            "error": error,
            "new_token": new_token,
        },
        status_code=400 if error else 200,
    )


@router.get("/agents", response_class=HTMLResponse)
def agents_page(request: Request):
    return _page(request)


@router.post("/agents", response_class=HTMLResponse)
def create_agent(request: Request, name: str = Form(...), expires_days: str = Form("")):
    try:
        days = int(expires_days) if expires_days.strip() else None
        agent, token = agents.create_agent(name, days)
    except ValueError as exc:
        return _page(request, error=str(exc))
    # Rendered directly (not redirected) so the token is shown exactly once and
    # never ends up in a URL, history entry or log line.
    return _page(request, new_token=(agent.name, token))


@router.post("/agents/{agent_id}/toggle")
def toggle_agent(agent_id: int, enabled: str = Form("")):
    agents.set_enabled(agent_id, enabled == "1")
    return RedirectResponse("/agents", status_code=303)


@router.post("/agents/{agent_id}/delete")
def delete_agent(agent_id: int):
    agents.delete_agent(agent_id)
    return RedirectResponse("/agents", status_code=303)
