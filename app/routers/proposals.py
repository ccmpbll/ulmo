import json

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.config import AUTH_DISABLED
from app.deps import require_login
from app.services import agents, proposals
from app.templating import templates

# Where an admin decides what a script proposed to change in commands and roles. Cookie-session login
# only, so a token cannot approve its own proposal. While ULMO_DISABLE_AUTH is set nobody is
# signed in, so approving is refused (denying is not).
router = APIRouter(dependencies=[Depends(require_login)])

LOGIN_REQUIRED = "Turn off ULMO_DISABLE_AUTH first: without a login anyone who can reach this page could change what agents may run."


@router.get("/proposals/{proposal_id}", response_class=HTMLResponse)
def proposal_page(request: Request, proposal_id: int):
    row = proposals.get(proposal_id)
    if row is None:
        return RedirectResponse("/approvals", status_code=303)
    plan, problem = proposals.view(row) if row.status == "pending" else (None, "")
    # The reason for a refused decision comes from the session, not the URL, so a link cannot put its own text on this page.
    return templates.TemplateResponse(
        request, "proposal.html",
        {"p": row, "plan": plan, "problem": problem, "error": request.session.pop("proposal_error", ""), "locked": AUTH_DISABLED},
    )


def _decide(request: Request, proposal_id: int, approve: bool, seen: str, user):
    if approve and AUTH_DISABLED:
        request.session["proposal_error"] = LOGIN_REQUIRED
        return RedirectResponse(f"/proposals/{proposal_id}", status_code=303)
    try:
        row = proposals.decide(proposal_id, approve, user.username, seen)
    except ValueError as exc:
        request.session["proposal_error"] = str(exc)
        return RedirectResponse(f"/proposals/{proposal_id}", status_code=303)
    action = {"applied": "approve change proposal", "denied": "deny change proposal"}.get(row.status, "approve change proposal (failed)")
    summary = proposals.summarize(json.loads(row.ops))
    agents.admin_audit(user.username, action, f"proposal {row.id} from admin:{row.token_name}: {summary}" + (f" ({row.result})" if row.result else ""))
    return RedirectResponse(f"/proposals/{proposal_id}", status_code=303)


@router.post("/proposals/{proposal_id}/approve")
def approve(request: Request, proposal_id: int, seen: str = Form(""), user=Depends(require_login)):
    return _decide(request, proposal_id, True, seen, user)


@router.post("/proposals/{proposal_id}/deny")
def deny(request: Request, proposal_id: int, user=Depends(require_login)):
    return _decide(request, proposal_id, False, "", user)
