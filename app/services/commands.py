"""Runs a command template on one inventory host over SSH.

The argument list comes from command_templates.build_argv and is sent as ONE
shlex-quoted string after `--`, so the remote login shell sees each value as a
single literal word. Nothing an agent supplies is interpreted by a local shell
(subprocess gets a list), and the connection details come from the inventory,
not from the request.
"""
import json
import re
import shlex
import subprocess
import threading
import time
from datetime import timedelta

from sqlmodel import Session, delete, select, update

from app.config import SSH_STORAGE_DIR
from app.database import engine
from app.models import CommandRun, utcnow
from app.services import command_templates, inventory

OUTPUT_CAP = 64 * 1024
CONNECT_TIMEOUT = 10
KILL_GRACE = 15  # seconds the local ssh gets past the template timeout before we kill it
REMOTE_KILL_AFTER = 5  # `timeout -k`: seconds between TERM and KILL on the host
STALE_AFTER = timedelta(minutes=10)  # longer than any timeout (300 s) plus grace; older "running" rows are lost
KEEP_RUNS = 500  # newest command runs kept; each can hold 64 KB of output
SAFE_WORD = re.compile(r"^[A-Za-z0-9._:-]+$")


class CommandError(Exception):
    """The command cannot be run (as opposed to ran and failed)."""


def ssh_command(template: command_templates.Template, host: str, argv: list[str]) -> list[str]:
    conn = inventory.host_conn(host)
    if conn is None:
        raise CommandError(f"{host} is not in the inventory")
    user = template.ssh_user or conn["user"]
    key = str(SSH_STORAGE_DIR / template.ssh_key) if template.ssh_key else conn["key"]
    for label, value in (("address", conn["address"]), ("port", conn["port"]), ("user", user)):
        if "{{" in value or not SAFE_WORD.match(value) or value.startswith("-"):
            raise CommandError(f"{host}: unusable ssh {label} {value!r} in the inventory")
    cmd = [
        "ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={CONNECT_TIMEOUT}",
        "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",  # no "added to known hosts" banner in the output
        "-p", conn["port"],
    ]
    if key:
        cmd += ["-i", key, "-o", "IdentitiesOnly=yes"]
    # The host's own `timeout` ends the command at the deadline; killing only the
    # local ssh would leave it running there while ulmo reports it finished.
    remote = ["timeout", "-k", str(REMOTE_KILL_AFTER), str(template.timeout), *argv]
    return cmd + [f"{user}@{conn['address']}", "--", shlex.join(remote)]


def start(template: command_templates.Template, host: str, values: dict[str, str], triggered_by: str, agent_id: int | None) -> CommandRun:
    """Record the run and execute it in a background thread. Raises CommandError
    before anything is recorded if the host cannot be reached by ssh at all."""
    argv = command_templates.build_argv(template, values)
    cmd = ssh_command(template, host, argv)
    with Session(engine) as session:
        run = CommandRun(
            template=template.id, host=host, params=json.dumps(values), command=shlex.join(argv),
            triggered_by=triggered_by, agent_id=agent_id,
        )
        session.add(run)
        session.commit()
        session.refresh(run)
    threading.Thread(target=_execute, args=(run.id, cmd, template.timeout + KILL_GRACE), daemon=True).start()
    return run


def _execute(run_id: int, cmd: list[str], local_timeout: float) -> None:
    status, rc, output = "error", None, ""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        timed_out = threading.Event()

        def _kill():
            if proc.poll() is None:  # it may have just finished on its own
                timed_out.set()
                proc.kill()

        timer = threading.Timer(local_timeout, _kill)
        timer.start()
        try:
            raw = proc.stdout.read(OUTPUT_CAP + 1)
            truncated = len(raw) > OUTPUT_CAP
            if truncated:  # keep draining so the real exit code is known; the timer bounds it
                while proc.stdout.read(65536):
                    pass
            proc.stdout.close()
            rc = proc.wait()
        finally:
            timer.cancel()
        output = raw[:OUTPUT_CAP].decode("utf-8", errors="replace")
        if truncated:
            output += "\n[output truncated]"
        # 124/137 are what the host's `timeout` returns when it ends the command.
        if timed_out.is_set() or rc in (124, 137):
            status = "timeout"
        else:
            status = "success" if rc == 0 else "failed"
    except Exception as exc:  # noqa: BLE001 - the run must always end in a final state
        output = f"ulmo: could not run ssh: {exc}"
    _finish(run_id, status, rc, output)


def _finish(run_id: int, status: str, rc: int | None, output: str) -> None:
    """Write the result, retrying: a row left 'running' counts against the caps."""
    for attempt in range(5):
        try:
            with Session(engine) as session:
                run = session.get(CommandRun, run_id)
                run.status, run.return_code, run.output, run.finished_at = status, rc, output, utcnow()
                session.add(run)
                session.commit()
                session.exec(delete(CommandRun).where(CommandRun.id <= run_id - KEEP_RUNS))
                session.commit()
            return
        except Exception:  # noqa: BLE001
            time.sleep(0.2 * (attempt + 1))


def reconcile_orphaned() -> None:
    """Runs still marked running after a restart will never finish."""
    with Session(engine) as session:
        for run in session.exec(select(CommandRun).where(CommandRun.status == "running")).all():
            run.status, run.output, run.finished_at = "error", "ulmo restarted while this was running", utcnow()
            session.add(run)
        session.commit()


def settle_stale() -> None:
    """A row still 'running' long after any timeout lost its thread (or its final write)."""
    with Session(engine) as session:
        session.exec(
            update(CommandRun)
            .where(CommandRun.status == "running", CommandRun.started_at < utcnow() - STALE_AFTER)
            .values(status="error", output="ulmo lost track of this run", finished_at=utcnow())
        )
        session.commit()


def running(host: str | None = None) -> int:
    settle_stale()
    with Session(engine) as session:
        query = select(CommandRun.id).where(CommandRun.status == "running")
        if host:
            query = query.where(CommandRun.host == host)
        return len(session.exec(query).all())
