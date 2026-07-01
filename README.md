# ulmo

![Build Status](https://img.shields.io/github/actions/workflow/status/ccmpbll/ulmo/docker.yml) ![Docker Image Size](https://img.shields.io/docker/image-size/ccmpbll/ulmo/latest) ![Docker Pulls](https://img.shields.io/docker/pulls/ccmpbll/ulmo.svg) ![License](https://img.shields.io/badge/License-MIT-blue.svg)

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
