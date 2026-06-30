from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from app.database import engine
from app.deps import require_login
from app.models import RunHistory
from app.services import git_sync, inventory, playbook_tags, runner, settings_store
from app.templating import templates

router = APIRouter(dependencies=[Depends(require_login)])


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    playbooks = git_sync.list_playbooks()
    tag_cache = playbook_tags.load_cache()
    for pb in playbooks:
        result = tag_cache.get(pb["rel_path"], playbook_tags.EMPTY_RESULT)
        pb["tags"] = result["tags"]
        pb["tag_error"] = result["error"]
    try:
        recent_runs_count = max(1, int(settings_store.get("recent_runs_count")))
    except ValueError:
        recent_runs_count = 5

    with Session(engine) as session:
        recent_runs = session.exec(
            select(RunHistory).order_by(RunHistory.started_at.desc()).limit(recent_runs_count)
        ).all()
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "playbooks": playbooks,
            "recent_runs": recent_runs,
            "repo_synced": git_sync.repo_synced(),
            "hosts": inventory.list_hosts(),
        },
    )


@router.get("/playbooks/view", response_class=HTMLResponse)
def view_playbook(request: Request, rel_path: str, _user=Depends(require_login)):
    try:
        content = git_sync.read_playbook(rel_path)
    except ValueError:
        return RedirectResponse("/?error=Unknown+playbook", status_code=303)
    return templates.TemplateResponse(
        request, "playbook_view.html", {"rel_path": rel_path, "content": content}
    )


@router.post("/sync")
def sync(request: Request, user=Depends(require_login)):
    record = git_sync.sync_now(triggered_by=user.username)
    if record.status == "failed":
        return RedirectResponse(f"/?error={quote(record.message[:200])}", status_code=303)
    return RedirectResponse("/?ok=Sync+complete", status_code=303)


@router.post("/playbooks/run")
def run_playbook(
    request: Request,
    user=Depends(require_login),
    rel_path: str = Form(...),
    tags: list[str] = Form([]),
    limit: list[str] = Form([]),
):
    valid_paths = {p["rel_path"] for p in git_sync.list_playbooks()}
    if rel_path not in valid_paths:
        return RedirectResponse("/?error=Unknown+playbook", status_code=303)
    record = runner.start_run(
        rel_path,
        triggered_by=user.username,
        tags=",".join(tags),
        limit=",".join(limit),
    )
    return RedirectResponse(f"/runs/{record.id}", status_code=303)
