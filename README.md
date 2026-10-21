<img src="app/static/logo.png" alt="ulmo logo" width="265">

# ulmo

![Build Status](https://img.shields.io/github/actions/workflow/status/ccmpbll/ulmo/docker.yml) ![Tests](https://img.shields.io/github/actions/workflow/status/ccmpbll/ulmo/tests.yml) ![Docker Image Size](https://img.shields.io/docker/image-size/ccmpbll/ulmo/latest) ![Docker Pulls](https://img.shields.io/docker/pulls/ccmpbll/ulmo.svg) ![License](https://img.shields.io/badge/License-MIT-blue.svg)

A small web dashboard for running Ansible playbooks from a git repo, with manual or scheduled git sync.

## Features

- Lists playbooks from the synced repo with inline tag (`--tags`) and host (`--limit`)
  selection; live colorized log streaming, cancel, and a configurable run timeout (default 60 min)
- Live per-task progress and a structured Play Recap on completion
- One **Activity** page for playbook runs, command runs, git syncs, API requests and changes: newest first,
  paged, filterable. History is pruned: the newest 500 playbook runs and 500 syncs are kept (a run's log
  goes with it; runs in progress are never touched), 500 command runs and 5,000 each of requests and changes.
- View playbook/inventory YAML, syntax highlighted (read-only)
- Per-playbook cron schedules, independent of the git sync schedule
- Run notifications via Pushover and/or [ntfy](https://ntfy.sh) — every run or failures only
- "Sync from Git" installs collections from the repo's `requirements.yaml`; each sync's full output is
  under Activity -> Syncs
- Settings backup/restore as YAML
- JSON API for scripts and automation (n8n etc.): per-agent bearer tokens, roles and grants that
  say which playbooks on which hosts an agent may run, a kill switch, and an audit log (see below)
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
```

**Running playbooks.** Agents can read by default and run nothing. To let one run a playbook,
create a **role**, add a **grant** (one playbook plus the hosts it may target), and assign the
role to the agent. `limit` is required and every host must be named in the role's grants for
that playbook; matching is exact, so wildcards, groups and `a:b` patterns are refused. ansible
reads a name as a host *or* a group, so a host that shares its name with a group cannot be
granted or used, and everything is refused while the inventory cannot be read. Runs go through
the same code as the Run button (same `ansible-runner` call, no extra variables or check mode)
and show up under Activity -> Playbook runs as `agent:<name>`.

Guard rails: a run is refused (409) while another run of the same playbook is going on any of
the same hosts (a UI run with no limit counts as all hosts), and at most 5 agent runs go at
once (429). **Agent runs** on the page is a kill switch: when off, no agent can start a run
(reading and cancelling still work); it is deliberately not part of Settings backup/restore.
Every change made on the Agents and Commands pages, and every API request and command run, is listed on the **Activity** page (paged, with filters).

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

The API is separate from the login session: `ULMO_DISABLE_AUTH` does not open it, and a token
cannot reach any admin page. While `ULMO_DISABLE_AUTH=true` the Agents page will not create
agents or widen what they may do (anyone reaching the page could), though it will still switch
runs off. Requests are audited with the status code returned; the newest 5000 rows are kept.
Serve ulmo over HTTPS so tokens are not sent in clear.

## SSH access to target hosts

**Settings → SSH Key** — paste the private key(s) used to connect to managed hosts. Symlinked
into the container at `/home/ansible/.ssh` and `/root/.ssh` to match the common
`ansible_ssh_private_key_file: /home/ansible/.ssh/ansible-ed25519` inventory convention, so no
inventory changes are needed. Set `ULMO_SSH_LINK_HOMES` if yours points elsewhere. Keys must be
unencrypted. A private git remote needing its own key can mount one directly in
`docker-compose.yml`.

## Environment variables

- `ULMO_DISABLE_AUTH=true` — skip login entirely; only if ulmo already sits behind your own
  access control (reverse proxy, VPN)
- `ULMO_SECURE_COOKIES=true` — mark the session cookie Secure (HTTPS-only). Set it when ulmo is
  served over TLS; leave off for plain-HTTP/localhost deployments
- `ULMO_SECRET_KEY` — pin the session-signing key; otherwise one is generated and persisted to
  `./data/secret_key` automatically
- `ULMO_SSH_LINK_HOMES` — comma-separated home dirs to symlink SSH keys into, if not
  `/home/ansible` or `/root`

## Data

Everything lives under `./data` (db, synced repo, SSH keys, run logs, installed collections) —
back that whole directory up. Settings backup/restore covers everything except SSH keys and user
accounts.

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

