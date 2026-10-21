"""Starting what an agent asked for: the checks, the caps and the launch.

A direct API call and an approved request both go through these functions, so an approval
can never start something a direct call would refuse. Each raises Refused with the HTTP
status the API answers with."""
import json
import shlex
import threading

from sqlmodel import Session

from app.database import engine
from app.models import Agent, Approval, CommandRun, RunHistory, utcnow
from app.services import agents, command_library, commands, runner

MAX_AGENT_RUNS = 5  # agent playbook runs going at once, across all agents
MAX_COMMAND_RUNS = 5  # command runs going at once, across all agents
MAX_COMMANDS_PER_HOST = 2
_start_lock = threading.Lock()  # makes "any conflicting run?" and "start it" one step


class Refused(Exception):
    """A request that may not start, with the HTTP status to answer it with. Raised by the
    helpers below so a direct call and an approved request go through the same checks."""

    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status, self.reason = status, reason


def precheck_run(agent: Agent, playbook: str, limit: list[str]) -> None:
    if not agents.runs_enabled():
        raise Refused(503, "agent runs are switched off")
    reason = agents.check_run(agent, playbook, limit)
    if reason:
        raise Refused(403, reason)


def launch_run(agent: Agent, playbook: str, limit: list[str]) -> RunHistory:
    with _start_lock:
        busy = agents.running_conflict(playbook, limit)
        if busy:
            raise Refused(409, f"run {busy.id} of this playbook is still running on overlapping hosts")
        if agents.running_agent_runs() >= MAX_AGENT_RUNS:
            raise Refused(429, f"{MAX_AGENT_RUNS} agent runs are already in progress")
        try:
            record = runner.start_run(playbook, triggered_by=f"agent:{agent.name}", limit=",".join(limit))
        except ValueError:  # granted, but the playbook has since left the repo
            raise Refused(404, "playbook no longer exists")
        agents.record_agent_run(record.id, agent.id)
    return record


def precheck_command(agent: Agent, command: str, host: str, params: dict):
    """Everything that can refuse a command call before it starts; returns (template, host, values)."""
    if not agents.runs_enabled():
        raise Refused(503, "agent runs are switched off")
    reason = agents.check_command(agent, command, host)
    if reason:
        raise Refused(403, reason)
    library = command_library.load()[0]
    template, library_host = library.commands.get(command), library.hosts.get(host)
    if template is None or library_host is None:  # edited away since the check above
        raise Refused(403, "that command or host was just changed; try again")
    try:
        values = command_library.validate_params(template, params)
    except ValueError as exc:
        raise Refused(400, str(exc))
    return template, library_host, values


def launch_command(agent: Agent, template, host, values) -> CommandRun:
    with _start_lock:
        if commands.running() >= MAX_COMMAND_RUNS or commands.running(host.name) >= MAX_COMMANDS_PER_HOST:
            raise Refused(429, "too many commands are already running")
        try:
            return commands.start(template, host, values, f"agent:{agent.name}", agent.id)
        except commands.CommandError as exc:
            raise Refused(502, str(exc))


def command_line(template, values) -> str:
    return shlex.join(command_library.build_argv(template, values))


def start_approved(approval: Approval) -> int:
    """Start what an admin just approved, repeating every check a direct call gets: the agent,
    its role, the host and the command may all have changed while it waited."""
    with Session(engine) as session:
        agent = session.get(Agent, approval.agent_id)
    if agent is None or not agent.enabled or (agent.expires_at is not None and agent.expires_at <= utcnow().replace(tzinfo=None)):
        raise Refused(403, "the agent is disabled, expired or deleted")
    if approval.kind == "command":
        template, host, values = precheck_command(agent, approval.target, approval.host, json.loads(approval.params))
        if command_line(template, values) != approval.line:
            raise Refused(409, "the command changed since it was requested")
        return launch_command(agent, template, host, values).id
    limit = approval.host.split(",")
    precheck_run(agent, approval.target, limit)
    return launch_run(agent, approval.target, limit).id
