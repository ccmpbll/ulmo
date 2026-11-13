from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.config import AUTH_DISABLED
from app.deps import require_login
from app.services import agents, approvals, file_access, proposals
from app.templating import templates

# Where an admin decides what agents asked to run. Cookie-session login only, so an agent
# token cannot approve itself. While ULMO_DISABLE_AUTH is set nobody is signed in, so
# approving is refused (denying is not).
router = APIRouter(dependencies=[Depends(require_login)])

LOGIN_REQUIRED = "Turn off ULMO_DISABLE_AUTH first: without a login anyone who can reach this page could approve a request."


@router.get("/approvals", response_class=HTMLResponse)
def approvals_page(request: Request, tab: str = "waiting"):
    return templates.TemplateResponse(request, "approvals.html", {"tab": tab if tab == "history" else "waiting", "pending": approvals.pending(), "recent": approvals.recent(), "proposals_pending": proposals.pending(), "proposals_recent": proposals.recent()})


@router.get("/approvals/{approval_id}", response_class=HTMLResponse)
def approval_page(request: Request, approval_id: int):
    approval = approvals.get(approval_id)
    if approval is None:
        return RedirectResponse("/approvals", status_code=303)
    # The reason for a refused decision comes from the session, not the URL, so a link cannot put its own text on this page.
    edit = file_access.view(approval) if approval.kind == "file" and approval.status == "pending" else None
    return templates.TemplateResponse(request, "approval.html", {"a": approval, "edit": edit, "error": request.session.pop("approval_error", ""), "locked": AUTH_DISABLED})


def _decide(request: Request, approval_id: int, approve: bool, user, back: str = ""):
    if approve and AUTH_DISABLED:
        request.session["approval_error"] = LOGIN_REQUIRED
        return RedirectResponse(f"/approvals/{approval_id}", status_code=303)
    try:
        row = approvals.decide(approval_id, approve, user.username)
    except ValueError as exc:
        request.session["approval_error"] = str(exc)
        return RedirectResponse(f"/approvals/{approval_id}", status_code=303)
    detail = f"{row.agent_name}: {row.line} on {row.host}" + (f" (could not start: {row.note})" if row.status == "failed" else "")
    agents.admin_audit(user.username, "approve request" if approve else "deny request", f"request {row.id}, {detail}")
    if back == "overview":  # decided from the Overview: go back to it with a one-line result
        request.session["flash"] = f"{'Approved' if approve else 'Denied'}: {row.agent_name} {row.target}" + (f" on {row.host}" if row.kind == "command" else "") + (f" (could not start: {row.note})" if row.status == "failed" else "")
        return RedirectResponse("/", status_code=303)
    return RedirectResponse(f"/approvals/{approval_id}", status_code=303)


@router.post("/approvals/{approval_id}/approve")
def approve(request: Request, approval_id: int, back: str = Form(""), user=Depends(require_login)):
    return _decide(request, approval_id, True, user, back)


@router.post("/approvals/{approval_id}/deny")
def deny(request: Request, approval_id: int, back: str = Form(""), user=Depends(require_login)):
    return _decide(request, approval_id, False, user, back)
