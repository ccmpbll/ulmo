from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlmodel import Session, select

from app.config import AUTH_DISABLED
from app.database import engine
from app.deps import require_login
from app.models import PlaybookSchedule, User
from app.services import git_sync, scheduler, settings_store, ssh_keys
from app.templating import templates

router = APIRouter(dependencies=[Depends(require_login)])


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, error: str | None = None, ok: str | None = None):
    with Session(engine) as session:
        users = session.exec(select(User).order_by(User.username)).all()
    playbooks = git_sync.list_playbooks()
    with Session(engine) as session:
        schedules = {
            s.rel_path: s.cron
            for s in session.exec(select(PlaybookSchedule)).all()
        }
    for pb in playbooks:
        pb["cron"] = schedules.get(pb["rel_path"], "")

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
            "auth_disabled": AUTH_DISABLED,
            "playbooks": playbooks,
        },
    )


@router.post("/settings")
def update_settings(
    request: Request,
    git_repo_url: str = Form(""),
    git_branch: str = Form("main"),
    playbooks_subdir: str = Form("playbooks"),
    inventory_path: str = Form("inventory.yaml"),
    requirements_path: str = Form(""),
    git_sync_cron: str = Form(""),
    extra_args: str = Form(""),
    recent_runs_count: str = Form("5"),
    run_timeout_minutes: str = Form("60"),
):
    try:
        recent_runs_count_int = int(recent_runs_count.strip())
        if recent_runs_count_int < 1:
            raise ValueError
    except ValueError:
        return RedirectResponse(
            "/settings?error=Recent+runs+to+show+must+be+a+positive+number", status_code=303
        )

    try:
        run_timeout_minutes_int = int(run_timeout_minutes.strip())
        if run_timeout_minutes_int < 0:
            raise ValueError
    except ValueError:
        return RedirectResponse(
            "/settings?error=Run+timeout+must+be+0+or+a+positive+number", status_code=303
        )

    settings_store.set_many(
        {
            "git_repo_url": git_repo_url.strip(),
            "git_branch": git_branch.strip() or "main",
            "playbooks_subdir": playbooks_subdir.strip(),
            "inventory_path": inventory_path.strip() or "inventory.yaml",
            "requirements_path": requirements_path.strip(),
            "git_sync_cron": git_sync_cron.strip(),
            "extra_args": extra_args.strip(),
            "recent_runs_count": str(recent_runs_count_int),
            "run_timeout_minutes": str(run_timeout_minutes_int),
        }
    )
    scheduler.reschedule(git_sync_cron.strip())
    return RedirectResponse("/settings?ok=Settings+saved", status_code=303)


@router.get("/settings/backup")
def download_backup(request: Request):
    content = settings_store.export_yaml()
    return Response(
        content=content,
        media_type="application/x-yaml",
        headers={"Content-Disposition": "attachment; filename=ulmo-settings.yaml"},
    )


@router.post("/settings/restore")
async def restore_backup(request: Request, backup_file: UploadFile = File(...)):
    try:
        text = (await backup_file.read()).decode("utf-8", errors="replace")
        applied, ignored = settings_store.import_yaml(text)
    except ValueError as exc:
        return RedirectResponse(f"/settings?error={quote(str(exc))}", status_code=303)

    scheduler.reschedule(settings_store.get("git_sync_cron"))

    message = f"Restored {len(applied)} setting(s)"
    if ignored:
        message += f"; ignored unknown keys: {', '.join(ignored)}"
    return RedirectResponse(f"/settings?ok={quote(message)}", status_code=303)


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


@router.post("/settings/notifications")
def update_notifications(
    request: Request,
    notify_on: str = Form(""),
    notify_pushover_token: str = Form(""),
    notify_pushover_user: str = Form(""),
    notify_ntfy_url: str = Form(""),
):
    settings_store.set_many(
        {
            "notify_on": notify_on.strip(),
            "notify_pushover_token": notify_pushover_token.strip(),
            "notify_pushover_user": notify_pushover_user.strip(),
            "notify_ntfy_url": notify_ntfy_url.strip(),
        }
    )
    return RedirectResponse("/settings?ok=Notification+settings+saved", status_code=303)


@router.post("/settings/playbook-schedule")
def update_playbook_schedule(
    request: Request,
    rel_path: str = Form(...),
    cron: str = Form(""),
):
    cron = cron.strip()
    if cron:
        from apscheduler.triggers.cron import CronTrigger
        try:
            CronTrigger.from_crontab(cron)
        except ValueError:
            return RedirectResponse(
                f"/settings?error={quote(f'Invalid cron expression for {rel_path}')}",
                status_code=303,
            )
    with Session(engine) as session:
        row = session.get(PlaybookSchedule, rel_path)
        if row is None:
            row = PlaybookSchedule(rel_path=rel_path, cron=cron)
        else:
            row.cron = cron
        session.add(row)
        session.commit()
    scheduler.reschedule_playbook(rel_path, cron)
    action = "enabled" if cron else "disabled"
    return RedirectResponse(
        f"/settings?ok={quote(f'Schedule {action} for {rel_path}')}",
        status_code=303,
    )
