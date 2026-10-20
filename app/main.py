from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.config import SECRET_KEY, SECURE_COOKIES
from app.database import init_db
from app.routers import agents, api, auth, inventory, logs, playbooks, runs, settings
from app.services import agents as agent_service
from app.services import commands, git_sync, runner, scheduler, ssh_keys


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Any row still "running" here means the process died mid-run/mid-sync
    # last time (crash, container restart) — settle those before anything
    # else touches them.
    runner.reconcile_orphaned_runs()
    commands.reconcile_orphaned()
    git_sync.reconcile_orphaned_syncs()
    ssh_keys.ensure_symlinks()
    scheduler.start()
    yield
    scheduler.scheduler.shutdown(wait=False)


app = FastAPI(title="ulmo", lifespan=lifespan)


@app.middleware("http")
async def audit_api(request: Request, call_next):
    """One audit row per /api/v1 request, written after the handler so it
    carries the real status code (a 404 or 500 is not logged as a success)."""
    if not request.url.path.startswith("/api/v1"):
        return await call_next(request)
    status = 500  # if the handler raises, call_next re-raises and this stands
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        name, detail = getattr(request.state, "audit", (None, ""))
        await run_in_threadpool(agent_service.audit, name, request.method, request.url.path, status, detail)


app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, https_only=SECURE_COOKIES)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(agents.router)
app.include_router(api.router)
app.include_router(auth.router)
app.include_router(inventory.router)
app.include_router(logs.router)
app.include_router(playbooks.router)
app.include_router(runs.router)
app.include_router(settings.router)
