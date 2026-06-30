from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from app.database import engine
from app.deps import require_login
from app.models import RunHistory
from app.services import git_sync, playbook_tags, runner
from app.templating import templates

router = APIRouter(dependencies=[Depends(require_login)])


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    playbooks = git_sync.list_playbooks()
    for pb in playbooks:
        result = playbook_tags.get_cached_tags(pb["rel_path"])
        pb["tags"] = result["tags"]
        pb["tag_error"] = result["error"]
    with Session(engine) as session:
        recent_runs = session.exec(
            select(RunHistory).order_by(RunHistory.started_at.desc()).limit(5)
        ).all()
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "playbooks": playbooks,
            "recent_runs": recent_runs,
            "repo_synced": git_sync.repo_synced(),
        },
    )


@router.post("/sync")
def sync(request: Request):
    user = require_login(request)
    record = git_sync.sync_now(triggered_by=user.username)
    if record.status == "failed":
        return RedirectResponse(f"/?error={quote(record.message[:200])}", status_code=303)
    return RedirectResponse("/?ok=Sync+complete", status_code=303)


@router.post("/playbooks/run")
def run_playbook(request: Request, rel_path: str = Form(...), tags: list[str] = Form([])):
    user = require_login(request)
    valid_paths = {p["rel_path"] for p in git_sync.list_playbooks()}
    if rel_path not in valid_paths:
        return RedirectResponse("/?error=Unknown+playbook", status_code=303)
    record = runner.start_run(rel_path, triggered_by=user.username, tags=",".join(tags))
    return RedirectResponse(f"/runs/{record.id}", status_code=303)
