from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.config import AUTH_DISABLED
from app.deps import require_login
from app.routers.api import start_approved
from app.services import agents, approvals
from app.templating import templates

# Where an admin decides what agents asked to run. Cookie-session login only, so an agent
# token cannot approve itself. While ULMO_DISABLE_AUTH is set nobody is signed in, so
# approving is refused (denying is not).
router = APIRouter(dependencies=[Depends(require_login)])

LOGIN_REQUIRED = "Turn off ULMO_DISABLE_AUTH first: without a login anyone who can reach this page could approve a request."


@router.get("/approvals", response_class=HTMLResponse)
def approvals_page(request: Request):
    return templates.TemplateResponse(request, "approvals.html", {"pending": approvals.pending(), "recent": approvals.recent()})


@router.get("/approvals/{approval_id}", response_class=HTMLResponse)
def approval_page(request: Request, approval_id: int, error: str = ""):
    approval = approvals.get(approval_id)
    if approval is None:
        return templates.TemplateResponse(request, "approvals.html", {"pending": approvals.pending(), "recent": approvals.recent(), "error": "No such request."}, status_code=404)
    return templates.TemplateResponse(request, "approval.html", {"a": approval, "error": error, "locked": AUTH_DISABLED})


def _decide(approval_id: int, approve: bool, user):
    if approve and AUTH_DISABLED:
        return RedirectResponse(f"/approvals/{approval_id}?error=" + LOGIN_REQUIRED.replace(" ", "+"), status_code=303)
    try:
        row = approvals.decide(approval_id, approve, user.username, start_approved)
    except ValueError as exc:
        return RedirectResponse(f"/approvals/{approval_id}?error={str(exc).replace(' ', '+')}", status_code=303)
    detail = f"{row.agent_name}: {row.line} on {row.host}" + (f" (could not start: {row.note})" if row.status == "failed" else "")
    agents.admin_audit(user.username, "approve request" if approve else "deny request", f"request {row.id}, {detail}")
    return RedirectResponse(f"/approvals/{approval_id}", status_code=303)


@router.post("/approvals/{approval_id}/approve")
def approve(approval_id: int, user=Depends(require_login)):
    return _decide(approval_id, True, user)


@router.post("/approvals/{approval_id}/deny")
def deny(approval_id: int, user=Depends(require_login)):
    return _decide(approval_id, False, user)
