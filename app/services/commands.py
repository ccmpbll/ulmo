"""Runs a library command on one host over SSH.

The argument list comes from command_library.build_argv and is sent as ONE
shlex-quoted string after `--`, so the remote login shell sees each value as a
single literal word. Nothing an agent supplies is interpreted by a local shell
(subprocess gets a list), and the connection details (address, port, user, key)
come from the host entry in the library, not from the request.
"""
import json
import shlex
import subprocess
import threading
import time
from datetime import timedelta

from sqlmodel import Session, delete, select, update

from app.config import SSH_STORAGE_DIR
from app.database import engine
from app.models import CommandRun, utcnow
from app.services import command_library

OUTPUT_CAP = 64 * 1024
CONNECT_TIMEOUT = 10
KILL_GRACE = 15  # seconds the local ssh gets past the command timeout before we kill it
REMOTE_KILL_AFTER = 5  # `timeout -k`: seconds between TERM and KILL on the host
STALE_AFTER = timedelta(minutes=10)  # longer than any timeout (300 s) plus grace; older "running" rows are lost
KEEP_RUNS = 500  # newest command runs kept; each can hold 64 KB of output


class CommandError(Exception):
    """The command cannot be run (as opposed to ran and failed)."""


def remote_command(argv: list[str], timeout: int) -> str:
    """What the host's shell receives. The host's own `timeout` ends the command at
    the deadline; killing only the local ssh would leave it running there while
    ulmo reports it finished."""
    return shlex.join(["timeout", "-k", str(REMOTE_KILL_AFTER), str(timeout), *argv])


def ssh_command(host: command_library.Host, argv: list[str], timeout: int) -> list[str]:
    key = SSH_STORAGE_DIR / host.ssh_key if host.ssh_key else None
    if key is not None and not key.is_file():
        raise CommandError(f"{host.name}: SSH key {host.ssh_key!r} has not been uploaded (Settings -> SSH Key)")
    cmd = [
        "ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={CONNECT_TIMEOUT}",
        "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",  # no "added to known hosts" banner in the output
        "-p", str(host.port),
    ]
    if key is not None:
        cmd += ["-i", str(key), "-o", "IdentitiesOnly=yes"]
    return cmd + [f"{host.user}@{host.address}", "--", remote_command(argv, timeout)]


def start(template: command_library.Template, host: command_library.Host, values: dict[str, str], triggered_by: str, agent_id: int | None) -> CommandRun:
    """Record the run and execute it in a background thread. Raises CommandError
    before anything is recorded if ssh cannot even be set up for the host."""
    argv = command_library.build_argv(template, values)
    cmd = ssh_command(host, argv, template.timeout)
    with Session(engine) as session:
        run = CommandRun(
            command=template.id, host=host.name, params=json.dumps(values), line=shlex.join(argv),
            triggered_by=triggered_by, agent_id=agent_id,
        )
        session.add(run)
        session.commit()
        session.refresh(run)
    threading.Thread(target=_execute, args=(run.id, cmd, template.timeout + KILL_GRACE), daemon=True).start()
    return run


def _run(cmd: list[str], timeout: float, cap: int) -> tuple[int, bytes, bool, bool]:
    """Run ssh, keep at most `cap` bytes of output, and kill it after `timeout`
    seconds. Returns (exit code, output, output was cut, we killed it). Output past
    the cap is drained and dropped so the real exit code is known."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    killed = threading.Event()

    def _kill():
        if proc.poll() is None:  # it may have just finished on its own
            killed.set()
            proc.kill()

    timer = threading.Timer(timeout, _kill)
    timer.start()
    try:
        raw = proc.stdout.read(cap + 1)
        cut = len(raw) > cap
        if cut:
            while proc.stdout.read(65536):
                pass
        proc.stdout.close()
        rc = proc.wait()
    finally:
        timer.cancel()
    return rc, raw[:cap], cut, killed.is_set()


def probe(host: command_library.Host) -> tuple[bool, str]:
    """Try the connection with a harmless command (the Test connection button)."""
    try:
        cmd = ssh_command(host, ["echo", "ulmo-ok"], 10)
    except CommandError as exc:
        return False, str(exc)
    try:
        rc, raw, _, _ = _run(cmd, CONNECT_TIMEOUT + 15, 2000)
    except Exception as exc:  # noqa: BLE001
        return False, f"could not run ssh: {exc}"
    out = raw.decode("utf-8", errors="replace").strip()
    return rc == 0 and "ulmo-ok" in out, out or f"ssh exited with {rc}"


def _execute(run_id: int, cmd: list[str], local_timeout: float) -> None:
    status, rc, output = "error", None, ""
    try:
        rc, raw, cut, killed = _run(cmd, local_timeout, OUTPUT_CAP)
        output = raw.decode("utf-8", errors="replace") + ("\n[output truncated]" if cut else "")
        # 124/137 are what the host's `timeout` returns when it ends the command.
        if killed or rc in (124, 137):
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


def settle_stale(max_age: timedelta = STALE_AFTER, note: str = "ulmo lost track of this run") -> None:
    """Mark 'running' rows older than max_age as errored: their thread (or final
    write) is gone. At startup, max_age 0 settles everything that was in flight."""
    with Session(engine) as session:
        session.exec(
            update(CommandRun)
            .where(CommandRun.status == "running", CommandRun.started_at < utcnow() - max_age)
            .values(status="error", output=note, finished_at=utcnow())
        )
        session.commit()


def running(host: str | None = None) -> int:
    settle_stale()
    with Session(engine) as session:
        query = select(CommandRun.id).where(CommandRun.status == "running")
        if host:
            query = query.where(CommandRun.host == host)
        return len(session.exec(query).all())
