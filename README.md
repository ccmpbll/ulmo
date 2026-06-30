# ulmo

![Build Status](https://img.shields.io/github/actions/workflow/status/ccmpbll/ulmo/docker.yml) ![Docker Image Size](https://img.shields.io/docker/image-size/ccmpbll/ulmo/latest) ![Docker Pulls](https://img.shields.io/docker/pulls/ccmpbll/ulmo.svg) ![License](https://img.shields.io/badge/License-MIT-blue.svg)

A small web dashboard for running Ansible playbooks from a git repo, with manual or scheduled git sync.

## Features

- Lists playbooks found in a synced git repo (`playbooks/` subdirectory by default), each with its
  tags shown inline — check any to run only matching tasks (`--tags`), or leave unchecked to run
  in full; live, colorized log streaming in the browser
- `--limit` host selection per run — check which host(s) a playbook should target, sourced from
  your inventory, without editing it
- Live per-task progress while a run is active (current task name, a status chip per host), plus
  a structured Play Recap table (ok/changed/unreachable/failed/skipped per host) once it finishes
- Cancel a running playbook from its run detail page; runs are also auto-killed after a
  configurable timeout (default 60 minutes) so a hung playbook can't run forever
- Per-playbook cron schedules (independent of the git sync schedule) — set in Settings, run
  unattended
- Run notifications via Pushover and/or [ntfy](https://ntfy.sh) — on every run or failures only
- Read-only inventory viewer
- Manual "Sync from git" button — also installs any collections listed in the repo's
  `requirements.yaml`
- Settings page: git repo URL/branch, playbooks subdirectory, inventory path, sync cron schedule,
  extra `ansible-playbook` args, number of recent runs shown on the dashboard, run timeout
- Download/restore Settings as a YAML backup file
- Upload one or more named SSH keys (file or paste) for connecting to managed hosts
- Simple login with SQLite-backed users (first run prompts you to create an admin account), or
  disable login entirely with `ULMO_DISABLE_AUTH=true`

## Running

```bash
curl -O https://raw.githubusercontent.com/ccmpbll/ulmo/main/docker-compose.yml
docker compose up -d
```

Open http://localhost:8000 — you'll be redirected to a setup page to create the first user.

Then go to **Settings** and set:
- **Git repository URL** — e.g. `https://git.example.com/Home/Ansible.git` or an `ssh://` URL
- **Branch** — defaults to `main`
- **Playbooks subdirectory** — defaults to `playbooks` (relative to the repo root)
- **Sync schedule** — a standard 5-field cron expression (e.g. `*/30 * * * *`), or leave blank to only sync manually

Click **Sync from git** on the dashboard to do the first clone.

## Session secret key

`ULMO_SECRET_KEY` signs login session cookies. You don't need to set it — if it's unset,
a random key is generated on first startup and persisted to `./data/secret_key`, reused on every
restart. Only set it explicitly if you want a stable key independent of `./data` (e.g. you wipe
`./data` but want existing sessions to survive, or you run multiple replicas that need to share
one key).

## Disabling login

If ulmo already sits behind your own access control (a reverse proxy with auth, a
VPN-only network, etc.) you can skip the login screen entirely by setting
`ULMO_DISABLE_AUTH=true` (uncomment the line in `docker-compose.yml`) and restarting the
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
`ULMO_SSH_LINK_HOMES` (comma-separated list of home directories whose `.ssh` should be
linked) instead of editing the inventory. The key must be unencrypted — passphrase-protected
keys can't be used for unattended runs.

If your git remote is private and needs its own SSH key (separate from the one above), mount it
directly in `docker-compose.yml`:

```yaml
volumes:
  - ./data:/data
  - ~/.ssh/git_deploy_key:/root/.ssh/git_deploy_key:ro
```

## Settings backup & restore

**Settings → Backup & Restore** lets you download the settings above (git repo, branch,
playbooks subdirectory, inventory path, sync schedule, extra args, recent-runs count) as a YAML
file, and restore from one later. Restoring only applies known setting keys — anything else in
the file is reported back as ignored rather than silently applied, so a backup edited by hand
(or from a future version with different keys) fails safe.

SSH keys and user accounts are **not** included in this backup — those are credentials, not
config. Back up `./data/ssh_home/` and your user list separately if you need them.

## How playbook runs work

Each playbook's tags are discovered by running `ansible-playbook <playbook> --list-tags` — this
only parses the playbook (and any roles/includes it pulls in) locally, it never connects to a
host. Tags are computed once per **sync**, not on every dashboard load, and cached to
`./data/playbook_tags.json` — edit a playbook's tags in git, then click "Sync from git" to see
the change reflected. Check any tags on a playbook's row and only matching tasks run
(`--tags a,b`); leave everything unchecked to run the whole playbook.

Hosts to limit a run to are listed from `ansible-inventory --list` against your configured
inventory — check any host under "Limit hosts" on a playbook's row to pass `--limit a,b`; leave
unchecked to target the whole inventory.

Runs are executed via [`ansible-runner`](https://ansible-runner.readthedocs.io/), with the synced
repo as `project_dir` so a repo's own `ansible.cfg` (inventory path, roles path, SSH settings,
etc.) is respected as-is — no special configuration needed in ulmo itself. ansible-runner gives
the run a cancel button (Run detail → Cancel) that stops `ansible-playbook` mid-run, rather than
ulmo needing to manage the subprocess itself. It's also auto-killed if it runs longer than the
**Run timeout** configured in Settings (default 60 minutes; 0 disables it).

While a run is active, ansible-runner's structured per-task events (not just raw stdout) drive a
small live progress panel above the log — current task name, and a status chip per host
(`running` / `ok` / `changed` / `skipped` / `failed` / `unreachable`). Once a host hits
`failed`/`unreachable` its chip stays that way even if a later task on it reports something
better (e.g. a `rescue`/`always` block continuing) — the point is to flag trouble, not paper over
it. When the playbook finishes, the same structured data renders as a **Play Recap** table
(ok/changed/unreachable/failed/skipped per host) — the exact PLAY RECAP you'd see at a terminal,
just structured instead of parsed from colored text. Revisiting an old run later shows the same
table, read back from ansible-runner's `job_events/` artifacts on disk (no separate database
record needed, and it survives a container restart).

Two environment variables are set for every run (and for the collection install during sync):

- `ANSIBLE_FORCE_COLOR=true` — ansible-playbook disables color by default when stdout isn't a
  TTY (which it never is, running under ansible-runner); this forces it back on so the log viewer
  can render real colors via [ansi_up](https://github.com/drudru/ansi_up).
- `ANSIBLE_COLLECTIONS_PATH=/data/collections` — points at the persistent location collections get
  installed into during sync, since Ansible only auto-discovers `~/.ansible/collections` by
  default, which doesn't survive container restarts.

Each "Sync from git" also runs `ansible-galaxy collection install -r <requirements.yaml>` if the
repo has one (checked in the playbooks subdirectory first, then the repo root) — this is what
provides things like the `timer`/`profile_tasks` callback plugins your `ansible.cfg` may enable;
those moved out of `ansible-core` into `ansible.posix`/`community.general` in recent versions.

## Per-playbook schedules

**Settings → Playbook Schedules** lists every playbook found in the synced repo with a cron-
expression field next to it. Set a 5-field cron expression and save to run that playbook
unattended on its own schedule, independent of the git sync schedule — useful for things like a
nightly `os-update.yaml`. Leave the field blank and save to disable a playbook's schedule.
Scheduled runs show up in Run History with `triggered_by: schedule`, same as scheduled git syncs.

## Notifications

**Settings → Notifications** can ping [Pushover](https://pushover.net) and/or
[ntfy](https://ntfy.sh) when a run finishes — choose "Every run" or "Failures only", or leave
disabled (the default). Both can be configured at once; either fires independently if its
fields are filled in. Pushover needs an app token + user key; ntfy needs the full topic URL
(e.g. `https://ntfy.sh/my-topic`).

## Data persistence

Everything lives under `/data` in the container (mounted to `./data` by the compose file):

- `ulmo.db` — SQLite database (users, settings, run/sync history, playbook schedules)
- `repo/` — the synced git repo
- `runner/` — ansible-runner's private data dir; `runner/artifacts/<run_id>/stdout` is each run's
  live log
- `ssh_home/.ssh/` — uploaded SSH private keys + `known_hosts`
- `collections/` — collections installed from the repo's `requirements.yaml`
- `playbook_tags.json` — cached per-playbook tags, refreshed on each sync
- `secret_key` — auto-generated session signing key (only created if `ULMO_SECRET_KEY` isn't set)

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
ULMO_DATA_DIR=./data uvicorn app.main:app --reload
```
