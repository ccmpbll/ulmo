import json
import threading
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.database import engine
from app.deps import require_proposer
from app.models import AdminToken, Grant, Proposal, Role, RoleCommand
from app.services import agents, approvals, command_library, notifier, proposals

# Proposals API for scripts (Claude Code, n8n, curl) holding a proposer token. It can read commands.yml
# and the roles and propose changes. It cannot apply anything: an admin approves each proposal on its
# page after seeing the diff (see app/services/proposals.py).
router = APIRouter(prefix="/api/v1/admin", dependencies=[Depends(require_proposer)])


def _iso(ts: datetime | None) -> str | None:
    return ts.replace(tzinfo=timezone.utc).isoformat() if ts else None


def _refuse(request: Request, token: AdminToken, status: int, reason: str):
    request.state.audit = (f"admin:{token.name}", reason)
    raise HTTPException(status, reason)


def _proposal_json(p: Proposal) -> dict:
    return {
        "id": p.id, "status": p.status, "note": p.note, "ops": json.loads(p.ops), "result": p.result,
        "created_at": _iso(p.created_at), "expires_at": _iso(p.expires_at), "decided_at": _iso(p.decided_at), "decided_by": p.decided_by,
    }


@router.get("/commands.yml")
def commands_yml():
    """The file as it is on disk: commands, and the hosts with the commands each offers."""
    return PlainTextResponse(command_library.read_text(), media_type="application/x-yaml")


@router.get("/roles")
def roles():
    with Session(engine) as session:
        rows = session.exec(select(Role).order_by(Role.name)).all()
        role_commands = session.exec(select(RoleCommand)).all()
        grants = session.exec(select(Grant).order_by(Grant.playbook)).all()
    return {
        "roles": [
            {
                "name": r.name,
                "commands": [{"command": c.command, "needs_approval": c.requires_approval} for c in sorted(role_commands, key=lambda c: c.command) if c.role_id == r.id],
                # Playbook grants are shown for context; they cannot be changed from here.
                "playbooks": [{"playbook": g.playbook, "hosts": g.hosts.split(","), "requires_approval": g.requires_approval} for g in grants if g.role_id == r.id],
            }
            for r in rows
        ]
    }


class ProposalRequest(BaseModel):
    ops: list[dict] = Field(min_length=1, max_length=proposals.MAX_OPS)
    note: str | None = Field(None, max_length=500)  # shown to the admin, labelled as the proposer's words


@router.post("/proposals", status_code=202)
def propose(body: ProposalRequest, request: Request, response: Response, dry_run: bool = Query(False), token: AdminToken = Depends(require_proposer)):
    """Check the operations like the Commands and Agents pages would, and record them as a pending
    proposal. Nothing changes until an admin approves it. With ?dry_run=true: check only, record nothing."""
    try:
        row, plan, created = proposals.propose(token, body.ops, body.note, dry_run)
    except approvals.TooManyPending as exc:
        _refuse(request, token, 429, str(exc))
    except proposals.Unavailable as exc:
        _refuse(request, token, 409, str(exc))
    except ValueError as exc:
        _refuse(request, token, 400, str(exc))
    previews = plan.previews
    if dry_run:
        request.state.audit = (f"admin:{token.name}", "dry run ok")
        response.status_code = 200
        return {"valid": True, "diff": plan.diff, "previews": previews, "warnings": plan.warnings}
    summary = proposals.summarize(body.ops)
    request.state.audit = (f"admin:{token.name}", f"{'proposed' if created else 'repeated'} {row.id}: {summary}")
    if created:  # a retry of a proposal that is already waiting must not notify or audit again
        agents.admin_audit(f"admin:{token.name}", "propose change", f"proposal {row.id}: {summary}")
        threading.Thread(target=notifier.notify_proposal, args=(row, summary), daemon=True).start()
    return {"id": row.id, "status": row.status, "expires_at": _iso(row.expires_at), "poll": f"/api/v1/admin/proposals/{row.id}", "diff": plan.diff, "previews": previews, "warnings": plan.warnings}


@router.get("/proposals")
def list_proposals(token: AdminToken = Depends(require_proposer)):
    return {"proposals": [_proposal_json(p) for p in proposals.for_token(token.id)]}


@router.get("/proposals/{proposal_id}")
def proposal_detail(proposal_id: int, request: Request, token: AdminToken = Depends(require_proposer)):
    """A proposer sees only its own proposals."""
    row = proposals.get(proposal_id)
    if row is None or row.token_id != token.id:
        _refuse(request, token, 404, "Proposal not found")
    return _proposal_json(row)
