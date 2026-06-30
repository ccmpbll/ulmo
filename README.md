# homelab-deck

A small web dashboard for running Ansible playbooks from a git repo, with manual or scheduled git sync.

## Features

- Lists playbooks found in a synced git repo (`playbooks/` subdirectory by default)
- Click a playbook to run it; live log streaming in the browser
- Manual "Sync from git" button
- Settings page: git repo URL/branch, playbooks subdirectory, sync cron schedule, extra `ansible-playbook` args
- Simple login with SQLite-backed users (first run prompts you to create an admin account)

## Running

```bash
cp docker-compose.yml docker-compose.override.yml  # optional, for local tweaks
docker compose up -d --build
```

Open http://localhost:8000 — you'll be redirected to a setup page to create the first user.

Then go to **Settings** and set:
- **Git repository URL** — e.g. `https://git.example.com/Home/Ansible.git` or an `ssh://` URL
- **Branch** — defaults to `main`
- **Playbooks subdirectory** — defaults to `playbooks` (relative to the repo root)
- **Sync schedule** — a standard 5-field cron expression (e.g. `*/30 * * * *`), or leave blank to only sync manually

Click **Sync from git** on the dashboard to do the first clone.

## SSH access to target hosts / private git repos

The container needs:
- SSH access to the hosts your playbooks manage (mount your SSH key, e.g. the `ansible` user's key)
- Optionally, SSH access to your git remote if it's a private repo over SSH

Uncomment and adjust the volume mounts in `docker-compose.yml`:

```yaml
volumes:
  - ./data:/data
  - ~/.ssh/id_ed25519:/root/.ssh/id_ed25519:ro
  - ~/.ssh/known_hosts:/root/.ssh/known_hosts:ro
```

## How playbook runs work

Runs invoke `ansible-playbook <playbook> [extra args]` with the synced repo root as the working directory, so a repo's own `ansible.cfg` (inventory path, roles path, SSH settings, etc.) is respected as-is — no special configuration needed in homelab-deck itself.

## Data persistence

Everything lives under `/data` in the container (mounted to `./data` by the compose file):

- `homelab-deck.db` — SQLite database (users, settings, run/sync history)
- `repo/` — the synced git repo
- `runs/` — per-run log files

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
HOMELAB_DECK_DATA_DIR=./data uvicorn app.main:app --reload
```
