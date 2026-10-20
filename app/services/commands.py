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

from sqlmodel import Session, select

from app.config import SSH_STORAGE_DIR
from app.database import engine
from app.models import CommandRun, utcnow
from app.services import command_templates, inventory

OUTPUT_CAP = 64 * 1024
CONNECT_TIMEOUT = 10
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
        "-o", "StrictHostKeyChecking=accept-new", "-p", conn["port"],
    ]
    if key:
        cmd += ["-i", key, "-o", "IdentitiesOnly=yes"]
    return cmd + [f"{user}@{conn['address']}", "--", shlex.join(argv)]


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
    threading.Thread(target=_execute, args=(run.id, cmd, template.timeout), daemon=True).start()
    return run


def _execute(run_id: int, cmd: list[str], timeout: int) -> None:
    status, rc, output = "error", None, ""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        timed_out = threading.Event()

        def _kill():
            timed_out.set()
            proc.kill()

        timer = threading.Timer(timeout, _kill)
        timer.start()
        try:
            raw = proc.stdout.read(OUTPUT_CAP + 1)
            if len(raw) > OUTPUT_CAP:
                proc.kill()
            proc.stdout.close()
            rc = proc.wait()
        finally:
            timer.cancel()
        output = raw[:OUTPUT_CAP].decode("utf-8", errors="replace")
        if len(raw) > OUTPUT_CAP:
            output += "\n[output truncated]"
        status = "timeout" if timed_out.is_set() else ("success" if rc == 0 else "failed")
    except Exception as exc:  # noqa: BLE001 - the run must always end in a final state
        output = f"ulmo: could not run ssh: {exc}"
    with Session(engine) as session:
        run = session.get(CommandRun, run_id)
        run.status, run.return_code, run.output, run.finished_at = status, rc, output, utcnow()
        session.add(run)
        session.commit()


def reconcile_orphaned() -> None:
    """Runs still marked running after a restart will never finish."""
    with Session(engine) as session:
        for run in session.exec(select(CommandRun).where(CommandRun.status == "running")).all():
            run.status, run.output, run.finished_at = "error", "ulmo restarted while this was running", utcnow()
            session.add(run)
        session.commit()


def running(host: str | None = None) -> int:
    with Session(engine) as session:
        query = select(CommandRun.id).where(CommandRun.status == "running")
        if host:
            query = query.where(CommandRun.host == host)
        return len(session.exec(query).all())
