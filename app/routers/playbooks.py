from urllib.parse import quote_plus

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from app.config import AUTH_DISABLED
from app.database import engine
from app.deps import require_login
from app.models import PlaybookSchedule, RunHistory
from app.routers.files import LOGIN_REQUIRED
from app.services import inventory, playbook_tags, runner, scheduler, workspace
from app.templating import templates

router = APIRouter(dependencies=[Depends(require_login)])


@router.get("/ansible", response_class=HTMLResponse)
def dashboard(request: Request):
    playbooks = workspace.list_playbooks()
    tag_cache = playbook_tags.load_cache()
    for pb in playbooks:
        result = tag_cache.get(pb["rel_path"], playbook_tags.EMPTY_RESULT)
        pb["tags"] = result["tags"]
        pb["tag_error"] = result["error"]
    with Session(engine) as session:
        crons = {s.rel_path: s.cron for s in session.exec(select(PlaybookSchedule)).all()}
        for pb in playbooks:
            pb["last_run"] = session.exec(
                select(RunHistory).where(RunHistory.playbook == pb["rel_path"]).order_by(RunHistory.started_at.desc(), RunHistory.id.desc()).limit(1)
            ).first()
            pb["cron"] = crons.get(pb["rel_path"], "")
            pb["next_run"] = scheduler.next_run(pb["rel_path"]) if pb["cron"] else None
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "playbooks": playbooks,
            "has_files": workspace.has_files(),
            "locked_by": workspace.active_runs(),
            "hosts": inventory.list_hosts(),
        },
    )


@router.get("/playbooks/view", response_class=HTMLResponse)
def view_playbook(request: Request, rel_path: str, _user=Depends(require_login)):
    try:
        content = workspace.read_playbook(rel_path)
    except ValueError:
        return RedirectResponse("/ansible?error=Unknown+playbook", status_code=303)
    return templates.TemplateResponse(
        request, "playbook_view.html", {"rel_path": rel_path, "content": content, "line_numbers": "\n".join(str(i) for i in range(1, content.count("\n") + (0 if content.endswith("\n") else 1) + 1))}
    )


@router.post("/playbooks/run")
def run_playbook(
    request: Request,
    user=Depends(require_login),
    rel_path: str = Form(...),
    tags: list[str] = Form([]),
    limit: list[str] = Form([]),
    extra_vars: str = Form(""),
    ssh_password: str = Form(""),
):
    if AUTH_DISABLED and extra_vars.strip():  # extra vars can set connection variables, which is a way to run code
        return RedirectResponse(f"/ansible?error={quote_plus(LOGIN_REQUIRED)}", status_code=303)
    try:
        record = runner.start_run(
            rel_path,
            triggered_by=user.username,
            tags=",".join(tags),
            limit=",".join(limit),
            extra_vars=extra_vars,
            ssh_password=ssh_password,
        )
    except ValueError as exc:  # unknown playbook, or extra vars / password refused by check_run_options
        return RedirectResponse(f"/ansible?error={quote_plus(str(exc))}", status_code=303)
    return RedirectResponse(f"/runs/{record.id}", status_code=303)
