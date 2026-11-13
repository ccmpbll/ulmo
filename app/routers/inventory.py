from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from app.deps import require_login
from app.services import inventory, settings_store, ssh_keys, workspace
from app.templating import templates

router = APIRouter(dependencies=[Depends(require_login)])


@router.get("/inventory", response_class=HTMLResponse)
def inventory_page(request: Request, file: str | None = None):
    files = inventory.list_files()
    selected = file or (files[0]["rel_path"] if files else None)

    content = None
    error = None
    if selected:
        try:
            content = inventory.read_file(selected)
        except ValueError as exc:
            error = str(exc)

    report = ssh_keys.inventory_key_report([k["filename"] for k in ssh_keys.list_keys()], inventory.key_files()) if files else []
    return templates.TemplateResponse(
        request,
        "inventory.html",
        {
            "key_paths": ssh_keys.accepted_paths(),
            "missing_keys": [r for r in report if r["status"] == "missing"],
            "files": files,
            "selected": selected,
            "content": content,
            "error": error,
            "has_files": workspace.has_files(),
            "settings_inventory_path": settings_store.get("inventory_path"),
        },
    )
