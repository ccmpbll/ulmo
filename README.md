# ulmo

![Build Status](https://img.shields.io/github/actions/workflow/status/ccmpbll/ulmo/docker.yml) ![Docker Image Size](https://img.shields.io/docker/image-size/ccmpbll/ulmo/latest) ![Docker Pulls](https://img.shields.io/docker/pulls/ccmpbll/ulmo.svg) ![License](https://img.shields.io/badge/License-MIT-blue.svg)

A small web dashboard for running Ansible playbooks from a git repo, with manual or scheduled git sync.

## Features

- Lists playbooks from the synced repo with inline tag checkboxes (`--tags`); live colorized log
  streaming
- View a playbook's or the inventory's raw YAML, syntax highlighted (read-only)
- `--limit` host selection per run, sourced from your inventory
- Live per-task progress (current task, per-host status chip) and a structured Play Recap on
  completion
- Cancel a running playbook; runs auto-killed after a configurable timeout (default 60 min)
- Per-playbook cron schedules, independent of the git sync schedule
- Run notifications via Pushover and/or [ntfy](https://ntfy.sh) — every run or failures only
- Manual "Sync from Git" — also installs collections from the repo's `requirements.yaml`
- Sync Logs tab — full output of every git sync
- Settings: git repo URL/branch, playbooks subdirectory, inventory path, requirements path, sync
  cron, extra `ansible-playbook` args, recent-runs count, run timeout
- Settings backup/restore as YAML
- Upload one or more named SSH keys (file or paste) for connecting to managed hosts
- SQLite-backed login (first run creates the admin account), or `ULMO_DISABLE_AUTH=true` to skip it

## Running

```bash
curl -O https://raw.githubusercontent.com/ccmpbll/ulmo/main/docker-compose.yml
docker compose up -d
```

Open http://localhost:8000 — you'll be redirected to a setup page to create the first user.

Then in **Settings**, set the git repository URL, branch, and (optionally) sync schedule, then
click **Sync from Git** on the dashboard to do the first clone.

## Repo layout

Expected at the **root** of your synced repo:

| File | Notes |
|---|---|
| `ansible.cfg` | Required at root — every `ansible`/`ansible-galaxy` call runs with the repo root as cwd; no Settings override. |
| `inventory.yaml` | Default for the **Inventory path** setting; change it if yours lives elsewhere or is named differently. |
| `requirements.yaml` | Collections to install on every sync. Auto-discovered at root, then inside the playbooks subdir; override with **Requirements path**. |

```
.
├── ansible.cfg
├── inventory.yaml
├── requirements.yaml
└── playbooks/       # configurable via "Playbooks subdirectory"
    └── site.yaml
```

## Session secret key

`ULMO_SECRET_KEY` signs session cookies. Unset by default — a random key is generated and
persisted to `./data/secret_key` on first run. Set it explicitly only if you need a stable key
independent of `./data` (wiping data but keeping sessions, or multiple replicas sharing one key).

## Disabling login

Set `ULMO_DISABLE_AUTH=true` (uncomment in `docker-compose.yml`) to skip the login screen if ulmo
already sits behind your own access control (reverse proxy auth, VPN-only network). Every request
becomes a single anonymous user; only enable if you trust everything that can reach the port.

## SSH access to target hosts

**Settings → SSH Key** — paste the private key used to connect to managed hosts. Written to
`./data/ssh_home/.ssh/<name>` (0600) and symlinked into the container at:

- `/home/ansible/.ssh` — matches the common `ansible_ssh_private_key_file:
  /home/ansible/.ssh/ansible-ed25519` inventory convention, so no inventory changes needed
- `/root/.ssh` — persists `known_hosts` across restarts

If your inventory points elsewhere, set `ULMO_SSH_LINK_HOMES` (comma-separated home dirs) instead
of editing the inventory. Keys must be unencrypted (no passphrase) for unattended runs.

For a private git remote needing its own key, mount it directly:

```yaml
volumes:
  - ./data:/data
  - ~/.ssh/git_deploy_key:/root/.ssh/git_deploy_key:ro
```

## Settings backup & restore

**Settings → Backup & Restore** — download/restore every Settings-page value as YAML, including
notification secrets (Pushover token, ntfy URL). Restore only applies known keys; anything else
is reported as ignored. SSH keys and user accounts are **not** included — back those up
separately (`./data/ssh_home/`, user list).

## How playbook runs work

Tags come from `ansible-playbook --list-tags` (no host connection), computed once per sync and
cached to `./data/playbook_tags.json` — re-sync after changing a playbook's tags in git. Checked
tags run via `--tags`; none checked runs the whole playbook. Host limiting works the same way via
`ansible-inventory --list` and `--limit`.

Runs go through [`ansible-runner`](https://ansible-runner.readthedocs.io/) with the synced repo as
`project_dir`, so the repo's own `ansible.cfg` is used as-is. Cancel (Run detail → Cancel) and the
configurable **Run timeout** (default 60 min, 0 disables) both stop the run mid-flight.

While running, ansible-runner's structured per-task events drive a live progress panel (current
task, per-host status chip). A host that hits `failed`/`unreachable` keeps that status even if a
later `rescue`/`always` block succeeds — the panel flags trouble, it doesn't paper over it. On
completion the same data renders as a **Play Recap** table, read back from `job_events/` artifacts
on disk (works for old runs too, survives restarts).

`ANSIBLE_FORCE_COLOR=true` and `ANSIBLE_COLLECTIONS_PATH=/data/collections` are set for every run
and sync, so colored log output renders correctly and installed collections persist across
restarts.

## Per-playbook schedules

**Settings → Playbook Schedules** — a cron field per playbook, independent of the git sync
schedule. Blank disables it. Scheduled runs show `triggered_by: schedule` in Run History.

## Notifications

**Settings → Notifications** — ping [Pushover](https://pushover.net) and/or
[ntfy](https://ntfy.sh) on run completion ("Every run" or "Failures only"). Both can be
configured independently. Pushover needs an app token + user key; ntfy needs the full topic URL.

## Data persistence

Everything lives under `/data` (mounted to `./data`):

- `ulmo.db` — SQLite database
- `repo/` — the synced git repo
- `runner/` — ansible-runner's data dir (`runner/artifacts/<run_id>/stdout` per run's live log)
- `ssh_home/.ssh/` — uploaded SSH keys + `known_hosts`
- `collections/` — installed collections
- `playbook_tags.json` — cached tags, refreshed on each sync
- `secret_key` — auto-generated session key (only if `ULMO_SECRET_KEY` isn't set)

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
ULMO_DATA_DIR=./data uvicorn app.main:app --reload
```
