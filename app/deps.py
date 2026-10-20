from fastapi import HTTPException, Request

from app.auth import current_user
from app.models import Agent
from app.services import agents


def require_login(request: Request):
    user = current_user(request)
    if user is None:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


def require_agent(request: Request) -> Agent:
    """Bearer-token auth for /api/v1. Separate from the cookie session on
    purpose: a token can never reach an admin page, and a logged-in browser
    session is not accepted here (and ULMO_DISABLE_AUTH does not apply). The
    caller only ever sees a generic 401; who it was and why it failed is left
    on request.state for the audit middleware in main.py, which logs every
    /api/v1 request once, with the status code actually returned."""
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        request.state.audit = (None, "missing bearer token")
        raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Bearer"})

    agent, reason = agents.authenticate(token)
    request.state.audit = (agent.name if agent else None, reason)
    if reason:
        raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Bearer"})
    return agent
