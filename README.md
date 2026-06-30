# homelab-deck

A small web dashboard for running Ansible playbooks from a git repo, with manual or scheduled git sync.

## Features

- Lists playbooks found in a synced git repo (`playbooks/` subdirectory by default)
- Click a playbook to see its tags and optionally run only specific ones (`--tags`), or run it in
  full; live, colorized log streaming in the browser
- Read-only inventory viewer
- Manual "Sync from git" button — also installs any collections listed in the repo's
  `requirements.yaml`
- Settings page: git repo URL/branch, playbooks subdirectory, inventory path, sync cron schedule,
  extra `ansible-playbook` args
- Upload one or more named SSH keys (file or paste) for connecting to managed hosts
- Simple login with SQLite-backed users (first run prompts you to create an admin account), or
  disable login entirely with `HOMELAB_DECK_DISABLE_AUTH=true`

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

## Session secret key

`HOMELAB_DECK_SECRET_KEY` signs login session cookies. You don't need to set it — if it's unset,
a random key is generated on first startup and persisted to `./data/secret_key`, reused on every
restart. Only set it explicitly if you want a stable key independent of `./data` (e.g. you wipe
`./data` but want existing sessions to survive, or you run multiple replicas that need to share
one key).

## Disabling login

If homelab-deck already sits behind your own access control (a reverse proxy with auth, a
VPN-only network, etc.) you can skip the login screen entirely by setting
`HOMELAB_DECK_DISABLE_AUTH=true` (uncomment the line in `docker-compose.yml`) and restarting the
container. Every request is then treated as a single anonymous user — `/login` and `/setup`
redirect to the dashboard, and password/user management is hidden from Settings. This is off by
default; only enable it if you trust everything that can reach the container's port.

## SSH access to target hosts

Go to **Settings → SSH Key** and paste the private key used to connect to the hosts your
playbooks manage. It's written to `./data/ssh_home/.ssh/ansible-ed25519` (0600, never shown
back in the UI) and symlinked into the container at the literal paths your inventory already
expects:

- `/home/ansible/.ssh` — matches `ansible_ssh_private_key_file: /home/ansible/.ssh/ansible-ed25519`
  in `inventory.yaml`'s group vars, so **no inventory changes are required**.
- `/root/.ssh` — so `known_hosts` (auto-accepted per `ansible.cfg`'s
  `StrictHostKeyChecking=accept-new`) persists across container restarts too.

If your inventory's `ansible_ssh_private_key_file` points somewhere else, set
`HOMELAB_DECK_SSH_LINK_HOMES` (comma-separated list of home directories whose `.ssh` should be
linked) instead of editing the inventory. The key must be unencrypted — passphrase-protected
keys can't be used for unattended runs.

If your git remote is private and needs its own SSH key (separate from the one above), mount it
directly in `docker-compose.yml`:

```yaml
volumes:
  - ./data:/data
  - ~/.ssh/git_deploy_key:/root/.ssh/git_deploy_key:ro
```

## How playbook runs work

Clicking a playbook opens a run-options page listing its tags, discovered by running
`ansible-playbook <playbook> --list-tags` — this only parses the playbook (and any roles/includes
it pulls in) locally, it never connects to a host. Check any tags you want and only matching tasks
run (`--tags a,b`); leave everything unchecked to run the whole playbook.

Runs invoke `ansible-playbook <playbook> [extra args] [--tags ...]` with the synced repo root as the working directory, so a repo's own `ansible.cfg` (inventory path, roles path, SSH settings, etc.) is respected as-is — no special configuration needed in homelab-deck itself.

Two environment variables are set for every run (and for the collection install during sync):

- `ANSIBLE_FORCE_COLOR=true` — ansible-playbook disables color by default when stdout isn't a
  TTY (which it never is, running as a subprocess); this forces it back on so the log viewer can
  render real colors via [ansi_up](https://github.com/drudru/ansi_up).
- `ANSIBLE_COLLECTIONS_PATH=/data/collections` — points at the persistent location collections get
  installed into during sync, since Ansible only auto-discovers `~/.ansible/collections` by
  default, which doesn't survive container restarts.

Each "Sync from git" also runs `ansible-galaxy collection install -r <requirements.yaml>` if the
repo has one (checked in the playbooks subdirectory first, then the repo root) — this is what
provides things like the `timer`/`profile_tasks` callback plugins your `ansible.cfg` may enable;
those moved out of `ansible-core` into `ansible.posix`/`community.general` in recent versions.

## Data persistence

Everything lives under `/data` in the container (mounted to `./data` by the compose file):

- `homelab-deck.db` — SQLite database (users, settings, run/sync history)
- `repo/` — the synced git repo
- `runs/` — per-run log files
- `ssh_home/.ssh/` — uploaded SSH private keys + `known_hosts`
- `collections/` — collections installed from the repo's `requirements.yaml`
- `secret_key` — auto-generated session signing key (only created if `HOMELAB_DECK_SECRET_KEY`
  isn't set)

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
HOMELAB_DECK_DATA_DIR=./data uvicorn app.main:app --reload
```
