import asyncio
import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from sqlmodel import Session, select

from app.database import engine
from app.deps import require_login
from app.models import RunHistory
from app.services import runner
from app.services.log_tail import LogTailer
from app.templating import templates

router = APIRouter(dependencies=[Depends(require_login)])


@router.get("/runs", response_class=HTMLResponse)
def run_history(request: Request):
    with Session(engine) as session:
        runs = session.exec(select(RunHistory).order_by(RunHistory.started_at.desc())).all()
    return templates.TemplateResponse(request, "runs.html", {"runs": runs})


@router.get("/runs/{run_id}", response_class=HTMLResponse)
def run_detail(request: Request, run_id: int):
    with Session(engine) as session:
        run = session.get(RunHistory, run_id)
    if run is None:
        return RedirectResponse("/runs", status_code=303)
    log = runner.read_log(run_id)
    recap = runner.get_recap(run_id)
    return templates.TemplateResponse(
        request, "run_detail.html", {"run": run, "log": log, "recap": recap}
    )


@router.get("/runs/{run_id}/stream")
async def run_stream(request: Request, run_id: int, offset: int = 0):
    async def event_source():
        # Resume point: the client's manually-reopened connections pass the
        # byte offset it last consumed (?offset=...); a native EventSource
        # auto-reconnect sends it as Last-Event-ID instead. Prefer the header,
        # fall back to the query param, else start at 0. The log is
        # append-only and durable on disk, so resuming is always correct.
        start = max(0, offset)
        last_event_id = (request.headers.get("last-event-id") or "").strip()
        if last_event_id.isdigit():
            start = int(last_event_id)

        tailer = LogTailer(runner.log_path(run_id), offset=start)
        last_progress_json = None
        while True:
            with Session(engine) as session:
                run = session.get(RunHistory, run_id)
            if run is None:
                yield "event: error\ndata: not found\n\n"
                return

            chunk = tailer.read()
            if chunk:
                # Embed the byte offset we've now consumed so the client can
                # resume from exactly this point on reconnect, and use it as
                # the SSE id so even the browser's native reconnect (which
                # echoes Last-Event-ID) lands at the right place.
                yield f"id: {tailer.pos}\ndata: {json.dumps({'pos': tailer.pos, 'text': chunk})}\n\n"

            progress = runner.get_progress(run_id)
            if progress is not None:
                progress_json = json.dumps(progress)
                if progress_json != last_progress_json:
                    last_progress_json = progress_json
                    yield f"event: progress\ndata: {progress_json}\n\n"

            if run.status != "running":
                recap = runner.get_recap(run_id)
                if recap is not None:
                    yield f"event: recap\ndata: {json.dumps(recap)}\n\n"
                yield f"event: done\ndata: {run.status}\n\n"
                return

            await asyncio.sleep(1)

    return StreamingResponse(
        event_source(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            # Reverse proxies (nginx, etc.) otherwise buffer the response
            # instead of relaying each chunk as it's written, which silently
            # defeats the live log view.
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/runs/{run_id}/cancel")
def cancel_run(run_id: int):
    runner.cancel_run(run_id)
    return RedirectResponse(f"/runs/{run_id}", status_code=303)
