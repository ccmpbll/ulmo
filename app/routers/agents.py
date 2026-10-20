from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from app.config import AUTH_DISABLED
from app.database import engine
from app.deps import require_login
from app.models import Agent, AgentAudit
from app.services import agents
from app.templating import templates

# Admin side of the agent API: cookie-session login only. Tokens are minted
# and revoked here and nowhere else.
router = APIRouter(dependencies=[Depends(require_login)])


def _page(request: Request, error: str | None = None, new_token: tuple[str, str] | None = None):
    with Session(engine) as session:
        rows = session.exec(select(Agent).order_by(Agent.name)).all()
        audit = session.exec(select(AgentAudit).order_by(AgentAudit.id.desc()).limit(50)).all()
    return templates.TemplateResponse(
        request,
        "agents.html",
        {"agents": rows, "audit": audit, "error": error, "new_token": new_token},
        status_code=400 if error else 200,
        # The page holding a plaintext token must not be kept by a browser or proxy cache.
        headers={"Cache-Control": "no-store"} if new_token else None,
    )


@router.get("/agents", response_class=HTMLResponse)
def agents_page(request: Request):
    return _page(request)


@router.post("/agents", response_class=HTMLResponse)
def create_agent(request: Request, name: str = Form(...), expires_days: str = Form("")):
    if AUTH_DISABLED:
        # Without a login anyone who can reach this page could mint a token.
        return _page(request, error="Turn off ULMO_DISABLE_AUTH to create agents: tokens need a real login behind them.")
    try:
        days = int(expires_days) if expires_days.strip() else None
        agent, token = agents.create_agent(name, days)
    except ValueError as exc:
        return _page(request, error=str(exc))
    # Rendered directly (not redirected) so the token is shown exactly once and
    # never ends up in a URL, history entry or log line.
    return _page(request, new_token=(agent.name, token))


@router.post("/agents/{agent_id}/toggle")
def toggle_agent(agent_id: int):
    agents.toggle_enabled(agent_id)
    return RedirectResponse("/agents", status_code=303)


@router.post("/agents/{agent_id}/delete")
def delete_agent(agent_id: int):
    agents.delete_agent(agent_id)
    return RedirectResponse("/agents", status_code=303)
