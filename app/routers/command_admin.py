import shlex

import yaml
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from sqlalchemy.orm import defer
from sqlmodel import Session, select

from app.config import AUTH_DISABLED
from app.database import engine
from app.deps import require_login
from app.models import CommandRun
from app.services import agents, command_library, commands, ssh_keys
from app.templating import templates

# The Commands page: hosts, the command library, history. Cookie-session login
# only; every change is validated as a whole file, kept in history and written
# to the change log. Locked while ULMO_DISABLE_AUTH is set, because defining what
# can run (and where) is the same kind of change as granting it.
router = APIRouter(dependencies=[Depends(require_login)])

LOGIN_REQUIRED = "Turn off ULMO_DISABLE_AUTH first: without a login anyone who can reach this page could change what agents can run."
STARTER = """description: What this does, in a sentence
risk: low
argv: [uptime]
timeout: 30
# params:
#   container: {type: enum, values: [sonarr, radarr]}
#   lines: {type: int, min: 1, max: 500}
#   unit: {type: regex, pattern: "[a-z0-9@._-]+", max_length: 60}
"""


def _page(request: Request, error: str | None = None, ok: str | None = None, host: str = "", status_code: int | None = None):
    library, load_error = command_library.load()
    with Session(engine) as session:
        runs = session.exec(select(CommandRun).options(defer(CommandRun.output)).order_by(CommandRun.id.desc()).limit(20)).all()
    return templates.TemplateResponse(
        request,
        "commands.html",
        {
            "library": library,
            "commands": sorted(library.commands.values(), key=lambda t: t.id),
            "command_items": [
                (t.id, t.description + (f" · risk {t.risk}" if t.risk else ""))
                for t in sorted(library.commands.values(), key=lambda t: t.id)
            ],
            "hosts": sorted(library.hosts.values(), key=lambda h: h.name),
            "offered_by": {n: library.hosts_offering(n) for n in library.commands},
            "editing_host": library.hosts.get(host),
            "keys": [k["filename"] for k in ssh_keys.list_keys()],
            "load_error": load_error,
            "versions": command_library.list_versions(),
            "base": command_library.current_version(),
            "runs": runs,
            "error": error,
            "ok": ok,
            "locked": AUTH_DISABLED,
        },
        status_code=status_code or (400 if error else 200),
    )


def _editor(request: Request, name: str, text: str, is_new: bool, error=None, preview=None, samples="", status_code=None, original=None):
    return templates.TemplateResponse(
        request,
        "command_edit.html",
        {"name": name, "original": name if original is None else original, "text": text, "is_new": is_new,
         "base": command_library.current_version(), "error": error, "preview": preview, "samples": samples},
        status_code=status_code or (400 if error else 200),
    )


@router.get("/commands", response_class=HTMLResponse)
def commands_page(request: Request, host: str = "", ok: str | None = None):
    return _page(request, host=host, ok=ok)


@router.get("/commands/edit", response_class=HTMLResponse)
def edit_command(request: Request, name: str = ""):
    if not name:
        return _editor(request, "", STARTER, True)
    try:
        body = command_library.command_body(name)
    except ValueError as exc:
        return _page(request, error=str(exc))
    if not body:
        return _page(request, error=f"No command named {name!r}.")
    return _editor(request, name, command_library.dump_yaml(body), False)


@router.post("/commands/preview", response_class=HTMLResponse)
def preview_command(request: Request, name: str = Form(""), text: str = Form(""), is_new: str = Form(""), samples: str = Form(""), original: str = Form("")):
    try:
        template = command_library.parse_command_text(name or "preview", text)
        values = command_library.validate_params(template, command_library.sample_values(template, samples))
        line = commands.remote_command(command_library.build_argv(template, values), template.timeout)
        preview = {"ok": True, "text": f"The host would receive: {line}"}
    except ValueError as exc:
        preview = {"ok": False, "text": str(exc)}
    return _editor(request, name, text, bool(is_new), preview=preview, samples=samples, status_code=200, original=original)


@router.post("/commands/save", response_class=HTMLResponse)
def save_command(
    request: Request,
    name: str = Form(...),
    text: str = Form(""),
    base: str = Form(""),
    is_new: str = Form(""),
    original: str = Form(""),
    user=Depends(require_login),
):
    name, original = name.strip(), original.strip()
    renaming = bool(original) and not is_new and name != original
    if AUTH_DISABLED:
        return _editor(request, name, text, bool(is_new), error=LOGIN_REQUIRED, original=original)
    moved = []
    try:
        template = command_library.parse_command_text(name, text)
        if is_new and name in command_library.load()[0].commands:
            raise ValueError(f"A command named {name!r} already exists.")

        def move_roles():  # runs once the new library is known to be valid, just before the swap
            agents.rename_role_command(original, name)
            moved.append(True)

        try:
            command_library.save_command(
                name, yaml.safe_load(text), base,
                rename_from=original if renaming else None, before_write=move_roles if renaming else None,
            )
        except Exception:
            if moved:  # the swap itself failed after the roles were moved: put them back
                agents.rename_role_command(name, original)
            raise
    except ValueError as exc:
        return _editor(request, name, text, bool(is_new), error=str(exc), original=original)
    what = shlex.join(template.argv) + (" (sudo)" if template.sudo else "") + f", timeout {template.timeout}s, params: {', '.join(template.params) or 'none'}"
    if renaming:
        agents.admin_audit(user.username, "rename command", f"{original} -> {name}: {what}")
        return RedirectResponse(f"/commands?ok=Renamed+{original}+to+{name}", status_code=303)
    agents.admin_audit(user.username, "save command", f"{name}: {what}")
    return RedirectResponse(f"/commands?ok=Saved+{name}", status_code=303)


@router.post("/commands/{name}/delete", response_class=HTMLResponse)
def delete_command(request: Request, name: str, user=Depends(require_login)):
    if AUTH_DISABLED:
        return _page(request, error=LOGIN_REQUIRED)
    try:
        command_library.delete_command(name)
    except ValueError as exc:
        return _page(request, error=f"Cannot delete {name}: {exc}")
    agents.admin_audit(user.username, "delete command", name)
    return RedirectResponse(f"/commands?ok=Deleted+{name}", status_code=303)


@router.post("/commands/hosts", response_class=HTMLResponse)
def save_host(
    request: Request,
    name: str = Form(...),
    address: str = Form(""),
    port: str = Form("22"),
    user_name: str = Form("", alias="user"),
    ssh_key: str = Form(""),
    offered: list[str] = Form([], alias="commands"),
    original: str = Form(""),
    base: str = Form(""),
    user=Depends(require_login),
):
    name = name.strip()
    if AUTH_DISABLED:
        return _page(request, error=LOGIN_REQUIRED, host=original)
    try:
        if original and name != original:
            raise ValueError("A host cannot be renamed: add a new one and delete this one.")
        if not original and name in command_library.load()[0].hosts:
            raise ValueError(f"A host named {name!r} already exists.")
        body = {"address": address.strip(), "port": int(port) if port.strip().isdigit() else port, "user": user_name.strip(), "commands": sorted(set(offered))}
        if ssh_key:
            body["ssh_key"] = ssh_key
        command_library.save_host(name, body, base)
    except ValueError as exc:
        return _page(request, error=str(exc), host=original)
    agents.admin_audit(user.username, "save host", f"{name} ({address.strip()}): {', '.join(sorted(set(offered))) or 'no commands'}")
    return RedirectResponse(f"/commands?ok=Saved+host+{name}", status_code=303)


@router.post("/commands/hosts/{name}/delete", response_class=HTMLResponse)
def delete_host(request: Request, name: str, user=Depends(require_login)):
    if AUTH_DISABLED:
        return _page(request, error=LOGIN_REQUIRED)
    try:
        command_library.delete_host(name)
    except ValueError as exc:
        return _page(request, error=f"Cannot delete {name}: {exc}")
    agents.admin_audit(user.username, "delete host", name)
    return RedirectResponse(f"/commands?ok=Deleted+host+{name}", status_code=303)


@router.post("/commands/hosts/{name}/test", response_class=HTMLResponse)
def test_host(request: Request, name: str, user=Depends(require_login)):
    if AUTH_DISABLED:
        return _page(request, error=LOGIN_REQUIRED)
    host = command_library.load()[0].hosts.get(name)
    if host is None:
        return _page(request, error=f"No host named {name!r}.")
    ok, detail = commands.probe(host)
    agents.admin_audit(user.username, "test host", f"{name}: {'ok' if ok else 'failed'}")
    if ok:
        return _page(request, ok=f"{name}: connection works.")
    return _page(request, error=f"{name}: {detail}", status_code=200)


@router.get("/commands/download")
def download_library():
    return PlainTextResponse(
        command_library.read_text(),
        media_type="application/x-yaml",
        headers={"Content-Disposition": "attachment; filename=commands.yml"},
    )


@router.get("/commands/history/{version_id}", response_class=HTMLResponse)
def view_version(request: Request, version_id: str):
    try:
        text = command_library.version_text(version_id)
    except ValueError:
        return _page(request, error="No such saved copy.", status_code=404)
    version = next((v for v in command_library.list_versions() if v["id"] == version_id), None)
    return templates.TemplateResponse(
        request,
        "command_version.html",
        {"version": version, "text": text, "diff": command_library.diff_with_current(version_id), "base": command_library.current_version(), "locked": AUTH_DISABLED},
    )


@router.post("/commands/history/{version_id}/restore", response_class=HTMLResponse)
def restore_version(request: Request, version_id: str, base: str = Form(""), user=Depends(require_login)):
    if AUTH_DISABLED:
        return _page(request, error=LOGIN_REQUIRED)
    try:
        command_library.restore(version_id, base)
    except ValueError as exc:
        return _page(request, error=f"Cannot restore: {exc}")
    agents.admin_audit(user.username, "restore command library", version_id)
    return RedirectResponse("/commands?ok=Restored", status_code=303)
