<img src="app/static/logo.png" alt="ulmo logo" width="265">

# ulmo

![Build Status](https://img.shields.io/github/actions/workflow/status/ccmpbll/ulmo/docker.yml) ![Tests](https://img.shields.io/github/actions/workflow/status/ccmpbll/ulmo/tests.yml) ![Docker Image Size](https://img.shields.io/docker/image-size/ccmpbll/ulmo/latest) ![Docker Pulls](https://img.shields.io/docker/pulls/ccmpbll/ulmo.svg) ![License](https://img.shields.io/badge/License-MIT-blue.svg)

A small web dashboard for running Ansible playbooks from a git repo, with manual or scheduled git sync,
plus an API that lets scripts and AI agents run allowlisted playbooks and SSH commands under tight limits.

## Features

- Lists playbooks from the synced repo with inline tag (`--tags`) and host (`--limit`)
  selection; live colorized log streaming, cancel, and a configurable run timeout (default 60 min)
- Live per-task progress and a structured Play Recap on completion
- An **Overview** landing page: what is waiting on you (approve or deny agent requests right there), what is
  running now, and the activity log of playbook runs, command runs, git syncs, API requests and changes: newest first,
  paged, filterable (the All tab merges them). History is pruned: the newest 500 playbook runs and 500 syncs are kept (a run's log
  goes with it; runs in progress are never touched), 500 command runs, 500 approvals and 5,000 each of requests and changes.
- **Ansible** (top bar): the playbooks and the inventory as two tabs; view their YAML, syntax highlighted (read-only)
- Per-playbook cron schedules, independent of the git sync schedule
- Run notifications via Pushover and/or [ntfy](https://ntfy.sh) — every run or failures only
- "Sync from Git" installs collections from the repo's `requirements.yaml`; each sync's full output is
  under Overview -> Syncs
- Settings backup/restore as YAML
- **Commands**: a separate allowlist of fixed SSH commands with typed blanks and the hosts that offer
  them, edited in the UI with saved copies. A host signs in with an SSH key or a password (see below)
- JSON API for scripts and automation (n8n etc.): per-agent bearer tokens, roles that say which
  playbooks on which hosts, and which commands, an agent may run, optional approval by you before a
  call runs, an hourly request limit per agent, a kill switch, and an audit log (see below)
- **Change proposals**: scripts (Claude Code, n8n, curl) can read `commands.yml` and the roles and
  *propose* changes to commands and roles through a separate token; you approve each one with a diff
  (see "Proposing changes" below)
- SQLite-backed login (first run creates the admin account), or `ULMO_DISABLE_AUTH=true` to skip it

## Running

```bash
curl -O https://raw.githubusercontent.com/ccmpbll/ulmo/main/docker-compose.yml
docker compose up -d
```

Open http://localhost:8000, create the first user, then in **Settings** set the git repo URL,
branch, and (optionally) sync schedule. Click **Sync from Git** to do the first clone.

## Repo layout

Expected at the **root** of your synced repo — `ansible.cfg` (required there, no override),
`inventory.yaml`, `requirements.yaml`. All three paths are configurable in Settings if named or
placed differently; playbooks themselves live in a subdirectory (`playbooks/` by default):

```
.
├── ansible.cfg
├── inventory.yaml
├── requirements.yaml
└── playbooks/
    └── site.yaml
```

## Agent API

**Agents** (top bar) creates API agents. Each gets a token, shown once; only its hash is stored.
Send it as `Authorization: Bearer <token>`. Tokens can be disabled, given an expiry, or deleted at
any time, and every request (allowed or denied, with the reason) is listed on the same page.

```
GET  /api/v1/playbooks         playbooks and their tags
GET  /api/v1/hosts             inventory hosts
GET  /api/v1/runs?limit=       recent runs
GET  /api/v1/runs/{id}         one run: status, recap, log tail (ANSI stripped, last 64 KB)
GET  /api/v1/catalog           what this agent may run
POST /api/v1/runs              start a playbook: {"playbook": "playbooks/x.yml", "limit": ["web1"]}
POST /api/v1/runs/{id}/cancel  cancel a run this agent started
GET  /api/v1/approvals/{id}    a request of this agent waiting for approval (see Approvals)
```

**Running playbooks.** Agents can read by default and run nothing. To let one run a playbook,
create a **role**, add a **grant** (one playbook plus the hosts it may target), and assign the
role to the agent. `limit` is required and every host must be named in the role's grants for
that playbook; matching is exact, so wildcards, groups and `a:b` patterns are refused. ansible
reads a name as a host *or* a group, so a host that shares its name with a group cannot be
granted or used, and everything is refused while the inventory cannot be read. Runs go through
the same code as the Run button (same `ansible-runner` call, no extra variables or check mode)
and show up under Overview -> Playbook runs as `agent:<name>`.

Guard rails: a run is refused (409) while another run of the same playbook is going on any of
the same hosts (a UI run with no limit counts as all hosts), and at most 5 agent runs go at
once (429). **Agent runs** on the page is a kill switch: when off, no agent can start a run
(reading and cancelling still work); it is deliberately not part of Settings backup/restore.
Every change made on the Agents and Commands pages, and every API request and command run, is listed on the **Overview** page (paged, with filters).

**Running commands over SSH.** This is a separate construct from Ansible: its own hosts and its
own commands, managed on the **Commands** page and stored in one file, `commands.yml` in the data
volume (hand-editable too). A *command* is a fixed command line with typed blanks, and each
*host* lists the commands it offers:

```yaml
commands:
  logs:
    description: Show container logs
    argv: [docker, logs, "--tail={n}", "{container}"]
    params:
      n: {type: int, min: 1, max: 500}
      container: {type: regex, pattern: "[a-z0-9_-]+", max_length: 40}
    timeout: 30          # seconds, 1-300
    sudo: false          # run as `sudo -n ...`
    risk: low            # label shown to humans: low | medium | high
hosts:
  gandalf:
    address: 10.42.11.10
    port: 22
    user: root
    ssh_key: unraid-key  # a key uploaded under Settings -> SSH Key
    commands: [logs]
```

A host signs in with an SSH key (the default, and the better choice) or with a username and
password (`auth: password`, picked on the host form). The password is kept in ulmo's database, never
in `commands.yml`, the download, the saved copies, the pages, the change log or run output; it is
handed to `ssh` through `sshpass -e` in the child's environment, not on the command line. Anyone who
can read `./data` can read it, so use a key where you can, and an account that is not root. Leaving
the password blank when editing keeps the saved one; switching a host back to a key or deleting it
removes the password.

Parameter types are `enum` (a list of allowed strings), `int` (required min and max) and `regex`
(must match in full; may not start with `-` unless `allow_leading_dash: true`). Every match has a short
time budget, so a pattern that is slow on some value (for example `(a|aa)+$`) rejects that value
instead of hanging ulmo.

Add `optional: true` to any parameter to let a caller leave it out. The `argv` element that holds its
placeholder is then dropped, so write a flag and its value as one element: `argv: [docker, ps, -a,
"--filter={filter}"]` runs `docker ps -a` with no filter and `docker ps -a --filter=name=plex` with one.
A value that is supplied is checked exactly like a required one. Saving is refused when an optional
placeholder shares an element with another placeholder (dropping it would lose the other value) or
stands alone right after a flag (`"--filter", "{filter}"` would leave a bare `--filter`). The catalog
marks optional parameters with `"optional": true`, and the Commands page lists them as optional.

The Commands page edits one command at a time (YAML, with a **Preview** that shows the exact
command a set of sample values would produce, without running anything) and hosts through a form
with a **Test connection** button. A command can be renamed even while it is in use: the hosts that
offer it and the roles that hold it follow the new name in the same step (anything outside ulmo that
calls it by the old name, such as n8n, has to be updated). Every change validates the whole file,
keeps the previous copy (the number kept is a setting, 20 by default), lists each copy with what
changed after it, lets you **View** what restoring it would undo, and **Restore** it, refuses to save over a change made
elsewhere, and is written to the change log (with what the command now runs). A hand edit that no longer parses keeps the last good
version in use and shows the error.

A role lists which commands an agent may use (Agents page). A call is allowed only when the role
includes the command **and** the chosen host offers it. The agent names a command, a host and
values; ulmo checks every value, builds the argument list itself, and sends it to the host as one
shell-quoted string, so a value is always a single literal argument and never shell syntax.

```
POST /api/v1/commands[?wait=20]  {"command": "logs", "host": "gandalf", "params": {"n": 100, "container": "sonarr"}}
GET  /api/v1/commands/{id}       status, return code, output (capped at 64 KB); only the agent's own runs
```

`POST` waits for the result: up to `wait` seconds (default 20, `0` to 60). If the command finishes
in time the answer is `200` with the status, return code and output; if not it is `202` with
`"status": "running"` and you poll `GET /commands/{id}`. The command keeps running either way.
Use `?wait=0` to fire and forget.

The host runs the command under its own `timeout` (coreutils or busybox must be installed there),
so a timeout stops it on the host as well as in ulmo. Output beyond 64 KB is dropped but the real
exit status is kept. At most 5 commands run at once and 2 per host; the newest 500 runs are kept.
The kill switch covers commands too. Commands do not use the Ansible inventory, and playbook
grants do not use these hosts.

**Approvals.** A role can mark a command (under "Commands that need your approval") or a playbook
grant ("Needs approval") as one that waits for you. A call to it answers `202` with
`{"status": "pending_approval", "approval_id": N}` and nothing runs. Open **Approvals** (top bar,
with a count of what is waiting) and approve or deny; each request has its own link, so a
notification can open it directly, and signing in sends you back to it. Approving starts the run
exactly as shown, after repeating every check a direct call gets, so a command that changed, a
role that lost it or a switched-off kill switch makes it fail instead of run. The agent polls
`GET /api/v1/approvals/{id}`: `pending`, then `approved` with a `result_url` to follow, or `denied`,
`expired` (nobody decided in 15 minutes) or `failed`. At most 10 requests per agent wait at once, and asking again for something already waiting returns the same approval instead of a new one.
A request can carry a short `note` (up to 500 characters, in the same JSON body), for example
what the sweep found; it is shown on the Approvals page, labelled as the agent's words and
escaped, stripped of control and direction-override characters, and included in the notification. It is ignored when the call needs no approval, and a
repeat of a request that is already waiting keeps the first note.
Only a signed-in admin can decide: an agent token cannot, and while `ULMO_DISABLE_AUTH` is set
approving is refused. A new request sends a Pushover/ntfy notification (whatever "Notify on" says);
set **Public URL of ulmo** under Settings -> Notifications to include the link.

**Rate limit.** Each agent may make a limited number of requests per hour: playbook runs, commands
and approval requests together, each counted once when it is accepted (an approval you give is not
counted again, and neither is a retry of a request that is already waiting). A request refused for
bad parameters or missing permission costs nothing. The default is 60; set another number on the
agent (0 is no limit), and the Agents page shows how many it has used in the last hour. Past the
limit, a new request answers `429 rate limit: N requests per hour`. Raising a limit is locked while
`ULMO_DISABLE_AUTH` is set.

### Proposing changes (commands and roles)

Commands and roles are edited on the Commands and Agents pages, and scripts can ask for the same
edits through the proposals API. A script **cannot change anything itself**: it sends a proposal,
ulmo checks it, and it waits on the **Approvals** page (section "Change proposals") for you to
approve it after reading the diff.

Create a **change token** under Agents -> Change tokens (shown once; only its hash is stored; it can
have an expiry). It is not an agent token: an agent token is refused on `/api/v1/admin`, a change
token is refused on every agent route, and neither is a login. A change token can read, and propose;
it cannot run a command, cannot approve its own proposal, and cannot reach any admin page. What it
can read is the whole of `commands.yml`: host addresses, SSH user names and key file names (not key
contents or passwords), so hand one only to a tool you would trust with that.

```
GET  /api/v1/admin/commands.yml        the file as it is on disk
GET  /api/v1/admin/roles               each role's commands (with needs_approval) and, read-only, its playbook grants
POST /api/v1/admin/proposals[?dry_run=true]   {"note": "why", "ops": [ ... ]}  -> 202 {"id", "diff", "previews"}
GET  /api/v1/admin/proposals[/{id}]    this token's proposals: pending | applied | denied | expired | failed
```

A proposal is up to 20 operations applied together or not at all (library operations first, in the
order given, then role operations). Each is a change of one thing, not a replacement of a list:

```
{"op": "save_command", "name": "pfsense-update-check", "body": {description, argv, timeout, ...}, "samples": {"unit": "nginx"}}
{"op": "delete_command", "name": "x"}                       refused while a host still offers it
{"op": "host_offer", "host": "ecth", "add": ["x"], "remove": ["y"]}
{"op": "role_allow", "role": "n8n", "add": [{"command": "x", "needs_approval": false}], "remove": ["y"]}
{"op": "role_set_approval", "role": "n8n", "command": "x", "needs_approval": true}
```

- `save_command` creates or replaces one command, checked exactly as the Commands page checks it (the
  whole file is validated). With `samples` (values for its blanks) the answer and the approval page
  show the same `The host would receive: ...` line as the editor's Preview, and a sample the command
  would refuse rejects the proposal.
- `needs_approval` must always be stated when a command is added to a role: there is no default, so a
  proposal cannot quietly add a command that runs unattended.
- Control, zero-width, direction-override and other invisible characters are refused anywhere in an
  operation (they could make the diff read differently from what is saved), and one command is limited
  to 20 KB, as in the editor. Names are letters, digits, `.`, `_` and `-` only. Any other non-ASCII
  character a proposal adds (a Cyrillic "o" in a command line, say) is allowed but listed in
  `warnings` and in a red notice on the approval page, with its code point.
- Adding something already there, or removing something that is not, is an error. A proposal that
  changes nothing is an error. `?dry_run=true` checks a proposal and records nothing.
- Not available from the API, on purpose: hosts' addresses, users, keys and passwords, agents,
  tokens, roles' existence, playbook grants, limits and the kill switch.

Approving. The proposal's page (`/proposals/{id}`, linked from the notification when **Public URL**
is set) shows the diff of `commands.yml`, the diff of the roles it touches (a deleted command also
leaves every role that held it) and each Preview line. **Approve** applies it through the same
locked, validated write as the Commands page: one saved copy for the library part (restorable from
the Commands page) and a change-log entry naming both the token and you. Approve carries a digest of
what you were shown; if the proposal, `commands.yml` or the roles changed since you opened the page,
it is refused and you look again. Applying is all or nothing: the roles and the library are written
together, and if either fails the other is put back. A proposal that can no longer be applied
(someone made the same change by hand, or a role was edited meanwhile) is marked `failed`. If
`commands.yml` does not parse at that moment, Approve answers with the error and the proposal stays
pending. A proposal whose change token was disabled, has expired or was deleted cannot be applied, so
disabling a leaked token revokes what it queued. Proposals expire after 24 hours, at most 10 per
token wait at once, a token may make 60 proposal or dry-run calls an hour (then `429`), and asking
again for one already waiting returns the same proposal. The
proposer's note is shown escaped and labelled as its words. While `ULMO_DISABLE_AUTH` is set,
change tokens cannot be created and proposals cannot be approved (denying always works).

The API is separate from the login session: `ULMO_DISABLE_AUTH` does not open it, and a token
cannot reach any admin page. While `ULMO_DISABLE_AUTH=true` the Agents page will not create
agents or widen what they may do (anyone reaching the page could), though it will still switch
runs off. Requests are audited with the status code returned; the newest 5000 rows are kept.
Serve ulmo over HTTPS so tokens are not sent in clear.

## SSH access to target hosts

**Settings → SSH Keys** (first section on the page) — paste the private key(s) used to connect to managed
hosts, for Ansible and for the Commands page. Symlinked
into the container at `/home/ansible/.ssh` and `/root/.ssh` to match the common
`ansible_ssh_private_key_file: /home/ansible/.ssh/ansible-ed25519` inventory convention, so no
inventory changes are needed. Set `ULMO_SSH_LINK_HOMES` if yours points elsewhere. Keys must be
unencrypted. A private git remote needing its own key can mount one directly in
`docker-compose.yml`.

## Environment variables

- `ULMO_DISABLE_AUTH=true` — skip login entirely; only if ulmo already sits behind your own
  access control (reverse proxy, VPN)
- `ULMO_DATA_DIR` — where ulmo keeps everything (db, synced repo, SSH keys, command library, run logs);
  `/data` in the container, which `docker-compose.yml` mounts from `./data`
- `ULMO_SECURE_COOKIES=true` — mark the session cookie Secure (HTTPS-only). Set it when ulmo is
  served over TLS; leave off for plain-HTTP/localhost deployments
- `ULMO_SECRET_KEY` — pin the session-signing key; otherwise one is generated and persisted to
  `./data/secret_key` automatically
- `ULMO_SSH_LINK_HOMES` — comma-separated home dirs to symlink SSH keys into, if not
  `/home/ansible` or `/root`

## Data

Everything lives under `./data` (db, synced repo, SSH keys, command library, run logs, installed collections) —
back that whole directory up (it also holds `commands.yml` and the passwords of password hosts).
Settings backup/restore covers settings only: not SSH keys, user accounts, agents and roles, the
command library or host passwords.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
ULMO_DATA_DIR=./data uvicorn app.main:app --reload
```

### Tests

Self-checks, no pytest — each file in `tests/` is a standalone script. They run in CI on every
push to `main` and pull request.

```bash
./tests/run_all.sh              # all of them, one pass/fail summary
PYTHON=/path/to/python3.12 ./tests/run_all.sh   # pick an interpreter
```

Python 3.10+ is required (the app uses `X | None` annotations). `run_all.sh` also works inside the
container, since the image ships `tests/` and the dependencies:

```bash
docker exec ulmo /app/tests/run_all.sh
```

Coverage is deliberately narrow — these guard specific regressions, not the whole feature surface.
Anything client-side still needs a real browser to verify; `test_stream_resume.py` only checks that
the run-detail page's inline script parses.

