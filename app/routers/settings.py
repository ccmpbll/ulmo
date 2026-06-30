from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from app.database import engine
from app.deps import require_login
from app.models import User
from app.services import scheduler, settings_store
from app.templating import templates

router = APIRouter(dependencies=[Depends(require_login)])


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, error: str | None = None, ok: str | None = None):
    with Session(engine) as session:
        users = session.exec(select(User).order_by(User.username)).all()
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "settings": settings_store.get_all(),
            "users": users,
            "error": error,
            "ok": ok,
        },
    )


@router.post("/settings")
def update_settings(
    request: Request,
    git_repo_url: str = Form(""),
    git_branch: str = Form("main"),
    playbooks_subdir: str = Form("playbooks"),
    git_sync_cron: str = Form(""),
    extra_args: str = Form(""),
):
    settings_store.set_many(
        {
            "git_repo_url": git_repo_url.strip(),
            "git_branch": git_branch.strip() or "main",
            "playbooks_subdir": playbooks_subdir.strip(),
            "git_sync_cron": git_sync_cron.strip(),
            "extra_args": extra_args.strip(),
        }
    )
    scheduler.reschedule(git_sync_cron.strip())
    return RedirectResponse("/settings?ok=Settings+saved", status_code=303)
