from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from app.database import engine
from app.deps import require_login
from app.models import User
from app.services import scheduler, settings_store, ssh_keys
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
            "ssh_keys": ssh_keys.list_keys(),
            "ssh_link_warnings": ssh_keys.ensure_symlinks(),
        },
    )


@router.post("/settings")
def update_settings(
    request: Request,
    git_repo_url: str = Form(""),
    git_branch: str = Form("main"),
    playbooks_subdir: str = Form("playbooks"),
    inventory_path: str = Form("inventory.yaml"),
    git_sync_cron: str = Form(""),
    extra_args: str = Form(""),
):
    settings_store.set_many(
        {
            "git_repo_url": git_repo_url.strip(),
            "git_branch": git_branch.strip() or "main",
            "playbooks_subdir": playbooks_subdir.strip(),
            "inventory_path": inventory_path.strip() or "inventory.yaml",
            "git_sync_cron": git_sync_cron.strip(),
            "extra_args": extra_args.strip(),
        }
    )
    scheduler.reschedule(git_sync_cron.strip())
    return RedirectResponse("/settings?ok=Settings+saved", status_code=303)


@router.post("/settings/ssh-key")
async def upload_ssh_key(
    request: Request,
    filename: str = Form(""),
    private_key: str = Form(""),
    key_file: UploadFile | None = File(None),
):
    try:
        if key_file is not None and key_file.filename:
            content = (await key_file.read()).decode("utf-8", errors="replace")
            filename = filename.strip() or key_file.filename
        else:
            content = private_key

        if not filename.strip():
            raise ValueError("Give the key a name, or upload a file (its filename will be used).")

        ssh_keys.save_key(filename, content)
    except ValueError as exc:
        return RedirectResponse(f"/settings?error={quote(str(exc))}", status_code=303)
    return RedirectResponse(f"/settings?ok=SSH+key+%22{quote(filename)}%22+saved", status_code=303)


@router.post("/settings/ssh-key/{filename}/delete")
def remove_ssh_key(request: Request, filename: str):
    try:
        ssh_keys.delete_key(filename)
    except ValueError as exc:
        return RedirectResponse(f"/settings?error={quote(str(exc))}", status_code=303)
    return RedirectResponse(f"/settings?ok=SSH+key+%22{quote(filename)}%22+removed", status_code=303)
