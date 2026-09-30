from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.config import SECRET_KEY, SECURE_COOKIES
from app.database import init_db
from app.routers import auth, inventory, logs, playbooks, runs, settings
from app.services import git_sync, runner, scheduler, ssh_keys


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Any row still "running" here means the process died mid-run/mid-sync
    # last time (crash, container restart) — settle those before anything
    # else touches them.
    runner.reconcile_orphaned_runs()
    git_sync.reconcile_orphaned_syncs()
    ssh_keys.ensure_symlinks()
    scheduler.start()
    yield
    scheduler.scheduler.shutdown(wait=False)


app = FastAPI(title="ulmo", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, https_only=SECURE_COOKIES)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(auth.router)
app.include_router(inventory.router)
app.include_router(logs.router)
app.include_router(playbooks.router)
app.include_router(runs.router)
app.include_router(settings.router)
