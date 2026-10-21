<img src="app/static/logo.png" alt="ulmo logo" width="265">

# ulmo

![Build Status](https://img.shields.io/github/actions/workflow/status/ccmpbll/ulmo/docker.yml) ![Tests](https://img.shields.io/github/actions/workflow/status/ccmpbll/ulmo/tests.yml) ![Docker Image Size](https://img.shields.io/docker/image-size/ccmpbll/ulmo/latest) ![Docker Pulls](https://img.shields.io/docker/pulls/ccmpbll/ulmo.svg) ![License](https://img.shields.io/badge/License-MIT-blue.svg)

A small web dashboard for running Ansible playbooks from a git repo, with manual or scheduled git sync.

## Features

- Lists playbooks from the synced repo with inline tag (`--tags`) and host (`--limit`)
  selection; live colorized log streaming, cancel, and a configurable run timeout (default 60 min)
- Live per-task progress and a structured Play Recap on completion
- View playbook/inventory YAML, syntax highlighted (read-only)
- Per-playbook cron schedules, independent of the git sync schedule
- Run notifications via Pushover and/or [ntfy](https://ntfy.sh) — every run or failures only
- "Sync from Git" installs collections from the repo's `requirements.yaml`; Sync Logs tab shows
  full output
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
and show up in Run History as `agent:<name>`.

Guard rails: a run is refused (409) while another run of the same playbook is going on any of
the same hosts (a UI run with no limit counts as all hosts), and at most 5 agent runs go at
once (429). **Agent runs** on the page is a kill switch: when off, no agent can start a run
(reading and cancelling still work); it is deliberately not part of Settings backup/restore.
Every change made on the Agents page is listed under **Recent changes**.

**Running commands over SSH.** A *command template* is a fixed command with typed blanks, kept as
a YAML file in the synced repo (`ulmo/templates/<id>.yml`, edit it there and Sync):

```yaml
description: Show container logs
argv: [docker, logs, "--tail={n}", "{container}"]
params:
  n: {type: int, min: 1, max: 500}
  container: {type: regex, pattern: "[a-z0-9_-]+", max_length: 40}
timeout: 30          # seconds, 1-300
sudo: false          # run as `sudo -n ...`
risk: low            # label shown to humans: low | medium | high
ssh_user: ansible    # optional; default is the host's ansible user from the inventory
ssh_key: my-key      # optional; a key uploaded under Settings -> SSH Key
```

Parameter types are `enum` (a list of allowed strings), `int` (required min and max) and `regex`
(must match in full; may not start with `-` unless `allow_leading_dash: true`; patterns that repeat a repeated group, like `(a+)+`, are refused because they can take exponential time). The agent names
a template, a host and values; ulmo checks every value, builds the argument list itself, and
sends it to the host as one shell-quoted string, so a value is always a single literal argument
and never shell syntax. Host address, port, user and key come from the inventory. A role gets a
*command grant* (template plus hosts) next to its playbook grants.

```
POST /api/v1/commands          {"template": "logs", "host": "frodo", "params": {"n": 100, "container": "sonarr"}}
GET  /api/v1/commands/{id}     status, return code, output (capped at 64 KB); only the agent's own runs
```

The host runs the command under its own `timeout` (coreutils or busybox must be installed there), so a timeout stops it on the host as well as in ulmo. Output beyond 64 KB is dropped but the real exit status is kept. At most 5 commands run at once and 2 per host; the newest 500 runs are kept. The kill switch covers commands too. A template
file that fails to parse is listed on the Agents page and keeps its last good version.

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

