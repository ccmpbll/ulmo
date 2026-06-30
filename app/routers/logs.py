from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from app.database import engine
from app.deps import require_login
from app.models import SyncHistory
from app.templating import templates

router = APIRouter(dependencies=[Depends(require_login)])


@router.get("/logs", response_class=HTMLResponse)
def sync_logs(request: Request):
    with Session(engine) as session:
        logs = session.exec(select(SyncHistory).order_by(SyncHistory.started_at.desc())).all()
    return templates.TemplateResponse(request, "sync_logs.html", {"logs": logs})


@router.get("/logs/{log_id}", response_class=HTMLResponse)
def sync_log_detail(request: Request, log_id: int):
    with Session(engine) as session:
        log = session.get(SyncHistory, log_id)
    if log is None:
        return RedirectResponse("/logs", status_code=303)
    return templates.TemplateResponse(request, "sync_log_detail.html", {"log": log})
