from urllib.parse import quote

from fastapi import HTTPException, Request

from app.auth import current_user
from app.models import Agent
from app.services import agents, proposals


def require_login(request: Request):
    user = current_user(request)
    if user is None:
        # A page opened from a link (a notification) comes back to itself after signing in.
        dest = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        back = f"/login?next={quote(dest, safe='')}" if request.method == "GET" and dest != "/" else "/login"
        raise HTTPException(status_code=303, headers={"Location": back})
    return user


def _bearer_token(request: Request) -> str:
    """The bearer token of the request, or a generic 401 (the reason goes to the audit log only)."""
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        request.state.audit = (None, "missing bearer token")
        raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Bearer"})
    return token


def require_agent(request: Request) -> Agent:
    """Bearer-token auth for /api/v1. Separate from the cookie session on
    purpose: a token can never reach an admin page, and a logged-in browser
    session is not accepted here (and ULMO_DISABLE_AUTH does not apply). The
    caller only ever sees a generic 401; who it was and why it failed is left
    on request.state for the audit middleware in main.py, which logs every
    /api/v1 request once, with the status code actually returned."""
    agent, reason = agents.authenticate(_bearer_token(request))
    request.state.audit = (agent.name if agent else None, reason)
    if reason:
        raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Bearer"})
    return agent


def require_proposer(request: Request):
    """Bearer-token auth for /api/v1/admin: a proposer token, which is not an agent token. An
    agent's token is unknown here and a proposer's is unknown to require_agent, so neither
    reaches the other's routes. Like require_agent, the caller sees a generic 401 and the
    reason goes to the audit log."""
    row, reason = proposals.authenticate(_bearer_token(request))
    request.state.audit = (f"admin:{row.name}" if row else None, reason)
    if reason:
        raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Bearer"})
    return row
