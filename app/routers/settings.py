from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlmodel import Session, select

from app.config import AUTH_DISABLED, SSH_KEY_LINK_HOMES
from app.database import engine
from app.deps import require_login
from app.routers.files import LOGIN_REQUIRED
from app.models import PlaybookSchedule, User
from app.services import git_import, inventory, scheduler, settings_store, ssh_keys
from app.templating import templates

router = APIRouter(dependencies=[Depends(require_login)])


TABS = (
    ("ansible", "Ansible"),
    ("ssh", "SSH keys"),
    ("notify", "Notifications"),
    ("backup", "Backup & restore"),
    ("account", "Account & users"),
)


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, error: str | None = None, ok: str | None = None, tab: str = "ansible"):
    with Session(engine) as session:
        users = session.exec(select(User).order_by(User.username)).all()
    keys = ssh_keys.list_keys()
    inventory_keys = []
    if tab == "ssh":  # reads the inventory (cached), so only where it is shown
        inventory_keys = ssh_keys.inventory_key_report([k["filename"] for k in keys], inventory.key_files())
        for key in keys:
            key["hosts"] = sorted({h for r in inventory_keys if r["name"] == key["filename"] for h in r["hosts"]})
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "tabs": TABS,
            "tab": tab if tab in dict(TABS) else "ansible",
            "settings": settings_store.get_all(),
            "users": users,
            "error": error,
            "ok": ok,
            "ssh_keys": keys,
            "ssh_link_warnings": ssh_keys.link_warnings(),
            "ssh_homes": [f"{h.rstrip('/')}/.ssh" for h in SSH_KEY_LINK_HOMES],
            "key_paths": ssh_keys.accepted_paths(),  # the same list the Inventory page shows
            "inventory_keys": inventory_keys,
            "auth_disabled": AUTH_DISABLED,
        },
    )


@router.post("/settings")
def update_settings(
    request: Request,
    playbooks_subdir: str = Form("playbooks"),
    inventory_path: str = Form("inventory.yaml"),
    requirements_path: str = Form(""),
    extra_args: str = Form(""),
):
    if AUTH_DISABLED:  # extra_args is passed to ansible-playbook, so this is a way to run code
        return RedirectResponse(f"/settings?tab=ansible&error={quote(LOGIN_REQUIRED)}", status_code=303)
    settings_store.set_many(
        {
            "playbooks_subdir": playbooks_subdir.strip(),
            "inventory_path": inventory_path.strip() or "inventory.yaml",
            "requirements_path": requirements_path.strip(),
            "extra_args": extra_args.strip(),
        }
    )
    return RedirectResponse("/settings?tab=ansible&ok=Ansible+settings+saved", status_code=303)


@router.post("/settings/import-git")
def import_git(
    request: Request,
    user=Depends(require_login),
    git_repo_url: str = Form(""),
    git_branch: str = Form("main"),
    confirm: str = Form(""),
):
    """One-time: replace the Ansible files with a git repository's. Not a sync."""
    if AUTH_DISABLED:
        return RedirectResponse(f"/settings?tab=ansible&error={quote(LOGIN_REQUIRED)}", status_code=303)
    if confirm != "yes":
        return RedirectResponse("/settings?tab=ansible&error=Tick+the+box+to+confirm+that+the+current+files+are+replaced", status_code=303)
    record = git_import.import_now(git_repo_url, git_branch, triggered_by=user.username)
    if record.status == "failed":
        return RedirectResponse(f"/settings?tab=ansible&error={quote(record.message[-300:])}", status_code=303)
    return RedirectResponse("/files?ok=Imported+from+Git", status_code=303)


@router.post("/settings/limits")
def update_limits(
    request: Request,
    run_timeout_minutes: str = Form("60"),
    command_history_keep: str = Form("20"),
    workspace_history_keep: str = Form("20"),
):
    try:
        run_timeout_minutes_int = int(run_timeout_minutes.strip())
        if run_timeout_minutes_int < 0:
            raise ValueError
    except ValueError:
        return RedirectResponse(
            "/settings?tab=ansible&error=Run+timeout+must+be+0+or+a+positive+number", status_code=303
        )

    try:
        command_history_keep_int = int(command_history_keep.strip())
        if not 1 <= command_history_keep_int <= 500:
            raise ValueError
    except ValueError:
        return RedirectResponse(
            "/settings?tab=ansible&error=Saved+command+library+copies+must+be+a+number+from+1+to+500", status_code=303
        )

    try:
        workspace_history_keep_int = int(workspace_history_keep.strip())
        if not 1 <= workspace_history_keep_int <= 500:
            raise ValueError
    except ValueError:
        return RedirectResponse(
            "/settings?tab=ansible&error=Saved+copies+per+Ansible+file+must+be+a+number+from+1+to+500", status_code=303
        )

    settings_store.set_many(
        {
            "run_timeout_minutes": str(run_timeout_minutes_int),
            "command_history_keep": str(command_history_keep_int),
            "workspace_history_keep": str(workspace_history_keep_int),
        }
    )
    return RedirectResponse("/settings?tab=ansible&ok=Run+limits+saved", status_code=303)


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
        return RedirectResponse(f"/settings?tab=backup&error={quote(str(exc))}", status_code=303)

    message = f"Restored {len(applied)} setting(s)"
    if ignored:
        message += f"; ignored unknown keys: {', '.join(ignored)}"
    return RedirectResponse(f"/settings?tab=backup&ok={quote(message)}", status_code=303)


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
        return RedirectResponse(f"/settings?tab=ssh&error={quote(str(exc))}", status_code=303)
    return RedirectResponse(f"/settings?tab=ssh&ok=SSH+key+%22{quote(filename)}%22+saved", status_code=303)


@router.post("/settings/ssh-key/{filename}/delete")
def remove_ssh_key(request: Request, filename: str):
    try:
        ssh_keys.delete_key(filename)
    except ValueError as exc:
        return RedirectResponse(f"/settings?tab=ssh&error={quote(str(exc))}", status_code=303)
    return RedirectResponse(f"/settings?tab=ssh&ok=SSH+key+%22{quote(filename)}%22+removed", status_code=303)


@router.post("/settings/notifications")
def update_notifications(
    request: Request,
    notify_on: str = Form(""),
    notify_pushover_token: str = Form(""),
    notify_pushover_user: str = Form(""),
    notify_ntfy_url: str = Form(""),
    public_url: str = Form(""),
):
    public_url = public_url.strip().rstrip("/")
    if public_url and not public_url.lower().startswith(("http://", "https://")):
        return RedirectResponse("/settings?tab=notify&error=Public+URL+must+start+with+http%3A%2F%2F+or+https%3A%2F%2F", status_code=303)
    settings_store.set_many(
        {
            "notify_on": notify_on.strip(),
            "notify_pushover_token": notify_pushover_token.strip(),
            "notify_pushover_user": notify_pushover_user.strip(),
            "notify_ntfy_url": notify_ntfy_url.strip(),
            "public_url": public_url,
        }
    )
    return RedirectResponse("/settings?tab=notify&ok=Notification+settings+saved", status_code=303)


@router.post("/settings/playbook-schedule")
def update_playbook_schedule(
    request: Request,
    rel_path: str = Form(...),
    cron: str = Form(""),
):
    """Edited on the Ansible page, next to the playbook it belongs to."""
    cron = cron.strip()
    if cron:
        from apscheduler.triggers.cron import CronTrigger
        try:
            CronTrigger.from_crontab(cron)
        except ValueError:
            return RedirectResponse(
                f"/ansible?error={quote(f'Invalid cron expression for {rel_path}')}",
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
        f"/ansible?ok={quote(f'Schedule {action} for {rel_path}')}",
        status_code=303,
    )
