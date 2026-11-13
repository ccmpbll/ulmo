import difflib
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from app.config import AUTH_DISABLED
from app.deps import require_login
from app.services import settings_store, workspace
from app.templating import templates

# The Files page: browse, edit, upload and delete the Ansible workspace. Cookie-session login only,
# and read-only while ULMO_DISABLE_AUTH is set (a playbook is code that runs on your hosts, so
# changing one is a bigger thing than running one). Every write goes through services/workspace.py:
# locked while a run is active, checked against the version the form was opened at, kept as a
# saved copy.
router = APIRouter(dependencies=[Depends(require_login)])

LOGIN_REQUIRED = "Turn off ULMO_DISABLE_AUTH first: without a login anyone who can reach this page could change what runs on your hosts."


def _status_for(exc: Exception) -> int:
    if isinstance(exc, workspace.Locked):
        return 423
    if isinstance(exc, workspace.Conflict):
        return 409
    return 400


_LANGUAGES = {"yaml": "yaml", "yml": "yaml", "sh": "bash", "bash": "bash", "json": "json", "xml": "xml", "py": "python", "md": "markdown",
              "ini": "ini", "cfg": "ini", "conf": "ini", "toml": "ini", "service": "ini", "timer": "ini", "local": "ini"}


def _language(rel: str, text: str) -> str:
    """The highlight.js language for the editor ("" = leave it plain): by extension (a .j2 template by
    what is under it), else by a #! line."""
    name = rel.rsplit("/", 1)[-1].lower()
    if name.endswith(".j2"):
        name = name[:-3]
    ext = name.rsplit(".", 1)[-1] if "." in name else ""
    if ext in _LANGUAGES:
        return _LANGUAGES[ext]
    first = text.split("\n", 1)[0]
    if first.startswith("#!"):
        return "python" if "python" in first else "bash" if "sh" in first else ""
    return ""


def _editor(request: Request, rel: str, text: str | None = None, base: str | None = None, error: str | None = None,
            ok: str | None = None, status_code: int = 200, warn: str | None = None):
    """The edit page. `text`/`base` given = redisplay what the user had (after a refused save)."""
    current = None
    try:
        current = workspace.read_file(rel)
    except ValueError:
        pass  # a new file (or a bad path, caught on save)
    is_new = current is None
    if base is None:
        base = "" if is_new else current["version"]
    if text is None:
        text = "" if is_new else (current["text"] or "")
    try:
        versions = workspace.list_versions(rel)
    except ValueError:
        versions = []
    return templates.TemplateResponse(
        request,
        "file_edit.html",
        {
            "rel_path": rel,
            "is_new": is_new,
            "file": current,
            "text": text,
            "base": base,
            "versions": versions,
            "error": error,
            "ok": ok,
            "warn": warn,
            "hl_lang": _language(rel, text),
            "move_suggestion": rel if "old" in rel.split("/")[:-1] else (rel.rsplit("/", 1)[0] + "/" if "/" in rel else "") + "old/" + rel.rsplit("/", 1)[-1],
            "locked_by": workspace.active_runs(),
            "read_only": AUTH_DISABLED,
        },
        status_code=status_code,
    )


@router.get("/files", response_class=HTMLResponse)
def files_page(request: Request, error: str | None = None, ok: str | None = None):
    files = workspace.list_files()
    return templates.TemplateResponse(
        request,
        "files.html",
        {
            "groups": workspace.group_files(files, settings_store.get("playbooks_subdir")),
            "has_files": bool(files),
            "deleted": workspace.deleted_files(),
            "locked_by": workspace.active_runs(),
            "read_only": AUTH_DISABLED,
            "error": error,
            "ok": ok,
        },
    )


@router.get("/files/edit", response_class=HTMLResponse)
def edit_page(request: Request, path: str, ok: str | None = None, error: str | None = None, warn: str | None = None):
    try:
        rel = workspace.clean(path)
    except ValueError as exc:
        return RedirectResponse(f"/files?error={quote(str(exc))}", status_code=303)
    return _editor(request, rel, ok=ok, error=error, warn=warn)


@router.post("/files/save")
def save(request: Request, path: str = Form(...), text: str = Form(""), base: str = Form("")):
    if AUTH_DISABLED:
        return _editor(request, path.strip(), text, base, error=LOGIN_REQUIRED, status_code=403)
    text = text.replace("\r\n", "\n")  # browsers submit a textarea with CRLF
    try:
        rel = workspace.clean(path)
        body = workspace.keep_line_endings(rel, text)
        workspace.store(rel, body.encode(), base=base)
    except ValueError as exc:  # Locked, Conflict and bad paths are all ValueErrors
        return _editor(request, path.strip(), text, base, error=str(exc), status_code=_status_for(exc))
    warning = workspace.check_syntax(rel, text) or workspace.check_playbook(rel)
    return RedirectResponse(f"/files/edit?path={quote(rel)}&ok=Saved" + (f"&warn={quote(warning)}" if warning else ""), status_code=303)


@router.post("/files/delete")
def delete(request: Request, path: str = Form(...), base: str = Form("")):
    if AUTH_DISABLED:
        return _editor(request, path.strip(), error=LOGIN_REQUIRED, status_code=403)
    try:
        workspace.delete(path, base or None)
    except ValueError as exc:
        return _editor(request, path.strip(), error=str(exc), status_code=_status_for(exc))
    return RedirectResponse(f"/files?ok={quote('Deleted ' + path.strip())}", status_code=303)


@router.post("/files/move")
def move(request: Request, path: str = Form(...), to: str = Form(...), base: str = Form("")):
    if AUTH_DISABLED:
        return _editor(request, path.strip(), error=LOGIN_REQUIRED, status_code=403)
    try:
        dst = workspace.move(path, to, base or None)
    except ValueError as exc:
        return _editor(request, path.strip(), error=str(exc), status_code=_status_for(exc))
    return RedirectResponse(f"/files?ok={quote('Moved ' + path.strip() + ' to ' + dst)}", status_code=303)


@router.get("/files/raw")
def raw(path: str):
    try:
        data = workspace.file_bytes(path)
    except ValueError as exc:
        return RedirectResponse(f"/files?error={quote(str(exc))}", status_code=303)
    name = workspace.clean(path).rsplit("/", 1)[-1]
    return Response(content=data, media_type="application/octet-stream", headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/files/download.zip")
def download_zip():
    return Response(content=workspace.export_zip(), media_type="application/zip", headers={"Content-Disposition": "attachment; filename=ansible.zip"})


def _refuse(message: str, status_code: int = 303):
    return RedirectResponse(f"/files?error={quote(message)}", status_code=status_code)


@router.post("/files/upload")
async def upload(request: Request, folder: str = Form(""), uploads: list[UploadFile] = File(default=[])):
    if AUTH_DISABLED:
        return _refuse(LOGIN_REQUIRED)
    prefix = workspace.clean(folder) + "/" if folder.strip().strip("/") else ""
    items = []
    for up in uploads:
        if not up.filename:
            continue
        items.append((prefix + up.filename.replace("\\", "/").lstrip("/"), await up.read(workspace.MAX_FILE_BYTES + 1)))
    if not items:
        return _refuse("Choose at least one file.")
    try:
        saved = await run_in_threadpool(workspace.store_many, items)  # fsyncs and the workspace lock: not on the event loop
    except ValueError as exc:
        return _refuse(str(exc))
    return RedirectResponse(f"/files?ok={quote(f'Saved {len(saved)} file(s)')}", status_code=303)


@router.post("/files/upload-zip")
async def upload_zip(request: Request, folder: str = Form(""), zip_file: UploadFile = File(...)):
    if AUTH_DISABLED:
        return _refuse(LOGIN_REQUIRED)
    try:
        saved = await run_in_threadpool(workspace.unpack_zip, await zip_file.read(workspace.MAX_ZIP_BYTES + 1), folder)  # decompressing: not on the event loop
    except ValueError as exc:
        return _refuse(str(exc))
    return RedirectResponse(f"/files?ok={quote(f'Unpacked {len(saved)} file(s)')}", status_code=303)


@router.get("/files/version", response_class=HTMLResponse)
def version_page(request: Request, path: str, version: str):
    try:
        rel = workspace.clean(path)
        old = workspace.version_bytes(rel, version)
    except ValueError as exc:
        return RedirectResponse(f"/files?error={quote(str(exc))}", status_code=303)
    try:
        current = workspace.read_file(rel)
    except ValueError:
        current = None
    old_text = old.decode("utf-8", errors="replace")
    diff = None
    if current is not None and current["text"] is not None:
        # current -> saved copy, so "-" lines would go away on restore and "+" lines would come back
        diff = list(difflib.unified_diff(current["text"].splitlines(True), old_text.splitlines(True), "current", "this saved copy", n=3)) or None
    return templates.TemplateResponse(
        request,
        "file_version.html",
        {
            "rel_path": rel,
            "version": version,
            "text": old_text,
            "diff": diff,
            "same": current is not None and workspace.version_of(old) == current["version"],
            "base": current["version"] if current else "",
            "exists": current is not None,
            "locked_by": workspace.active_runs(),
            "read_only": AUTH_DISABLED,
        },
    )


@router.post("/files/restore")
def restore(request: Request, path: str = Form(...), version: str = Form(...), base: str = Form("")):
    if AUTH_DISABLED:
        return _refuse(LOGIN_REQUIRED)
    try:
        workspace.restore(path, version, base)
    except ValueError as exc:
        return _refuse(str(exc), 303)
    return RedirectResponse(f"/files/edit?path={quote(workspace.clean(path))}&ok=Restored", status_code=303)
