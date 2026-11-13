<img src="app/static/logo.png" alt="ulmo logo" width="265">

# ulmo

![Build Status](https://img.shields.io/github/actions/workflow/status/ccmpbll/ulmo/docker.yml) ![Tests](https://img.shields.io/github/actions/workflow/status/ccmpbll/ulmo/tests.yml) ![Docker Image Size](https://img.shields.io/docker/image-size/ccmpbll/ulmo/latest) ![Docker Pulls](https://img.shields.io/docker/pulls/ccmpbll/ulmo.svg) ![License](https://img.shields.io/badge/License-MIT-blue.svg)

A small web dashboard for running Ansible playbooks you upload and edit in the browser (no git needed),
plus an API that lets scripts and AI agents run allowlisted playbooks and SSH commands under tight limits.

## Features

- **Playbooks:** pick tags (`--tags`) and hosts (`--limit`), watch a live colourised log with per-task
  progress and a Play Recap, cancel, set a run timeout (60 min default) and a cron schedule per playbook.
  A finished run that used tags lists the tasks no tag matched. Each run records the playbook's version and
  a revision of all files, and links to the saved copy it ran if the file has changed since.
- **Files** (Ansible → Files): ulmo keeps your Ansible files (playbooks, inventory, `ansible.cfg`,
  `files/`). Browse them by folder, edit with syntax colours and line numbers, upload files or a zip,
  create, move, delete, or download everything as a zip. Every save keeps the old contents as a saved
  copy you can compare and Restore, and an edit from a stale page is refused, not merged. **The files are
  read-only while a playbook runs.** A file that does not parse, or a playbook that fails
  `ansible-playbook --syntax-check`, is saved with a warning. Moving a playbook takes its grants and
  schedule with it. Editing, Import from Git and the Ansible settings (which include extra
  `ansible-playbook` arguments) are off while `ULMO_DISABLE_AUTH` is set.
- **Import from Git** (Settings → Ansible): a one-time copy of a repository into ulmo, not a sync; the
  previous files are kept as `ansible.before-import-*`. An old `./data/repo` checkout is copied across at
  first start and left in place.
- **Overview:** what is waiting on you (approve or deny there), what is running, and the activity log of
  runs, command runs, imports, API requests and changes, paged and filterable. History is pruned (newest
  500 playbook runs, imports, command runs and approvals; 5,000 requests and changes).
- **Commands:** a separate allowlist of fixed SSH commands with typed blanks and the hosts that offer them.
- **API for scripts and agents** (n8n etc.): per-agent bearer tokens, roles that say which playbooks and
  commands an agent may run, optional approval by you before a call runs, an hourly limit, a kill switch
  and an audit log.
- **Change proposals:** scripts (Claude Code, n8n, curl) can read `commands.yml`, the roles and the
  workspace files, and *propose* changes to commands, roles and any file through a separate token. You
  approve each one with a diff. Agents can read playbooks but never write a file.
- Notifications via Pushover and/or [ntfy](https://ntfy.sh), every run or failures only. Collections from
  `requirements.yaml` are installed when it changes. Settings backup/restore as YAML. No outside network
  needed. SQLite-backed login (first run creates the admin), or `ULMO_DISABLE_AUTH=true` to skip it.

## Running

```bash
curl -O https://raw.githubusercontent.com/ccmpbll/ulmo/main/docker-compose.yml
docker compose up -d
```

Open http://localhost:8000, create the first user, then open **Ansible → Files** and upload your
playbooks, inventory and `ansible.cfg` (or a zip of them), or use **Settings → Ansible → Import from
Git** once.

## Files layout

`ansible.cfg` (required at the top level) sits next to `inventory.yaml` and `requirements.yaml` (their
paths are configurable in Settings). Playbooks live in `playbooks/` by default:

```
.
├── ansible.cfg
├── inventory.yaml
├── requirements.yaml
└── playbooks/
    └── site.yaml
```

## Agent API

**Agents** (top bar) creates API agents. Each gets a token, shown once; only its hash is stored. Send it
as `Authorization: Bearer <token>`. Tokens can be disabled, expire or be deleted, and every request
(allowed or denied) is audited.

```
GET  /api/v1/playbooks         playbooks and their tags
GET  /api/v1/playbooks/content?path=...   a playbook's text and version (read only)
GET  /api/v1/hosts             inventory hosts
GET  /api/v1/runs?limit=       recent runs
GET  /api/v1/runs/{id}         one run: status, recap, log tail (ANSI stripped, last 64 KB)
GET  /api/v1/catalog           what this agent may run
POST /api/v1/runs              start a playbook: {"playbook": "playbooks/x.yml", "limit": ["web1"]}
POST /api/v1/runs/{id}/cancel  cancel a run this agent started
GET  /api/v1/approvals/{id}    one of this agent's requests waiting for approval
```

Agents can read only the playbooks (not `files/`, `ansible.cfg` or the inventory) and cannot change a
file: editing needs a change token (below).

**Running playbooks.** An agent runs nothing by default. Create a **role**, add a **grant** (one playbook
plus the hosts it may target) and assign the role to the agent. `limit` is required and every host must
be named in the grants for that playbook; matching is exact (no wildcards, groups or `a:b`, and a host
named like a group cannot be granted). Runs use the same code as the Run button (no extra variables or
check mode) and show up as `agent:<name>`. A run is refused (409) while another run of the same playbook
is going on any of the same hosts, and at most 5 agent runs go at once (429). **Agent runs** on the
Agents page is a kill switch: off, no agent can start a run (reading and cancelling still work).

**Running commands over SSH.** Separate from Ansible, with its own hosts and commands, edited on the
**Commands** page and stored in `commands.yml` in the data volume. A *command* is a fixed command line with
typed blanks; each *host* lists the commands it offers:

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

- **Sign-in:** a host uses an SSH key (better) or a password (`auth: password`). The password is kept in
  ulmo's database, never in `commands.yml`, downloads, saved copies, pages or logs, and reaches `ssh` via
  `sshpass -e`. Anyone who can read `./data` can read it, so prefer a key and a non-root account.
- **Parameters:** `enum`, `int` (min and max required) or `regex` (full match; no leading `-` unless
  `allow_leading_dash: true`). A slow pattern rejects the value instead of hanging ulmo. `optional: true`
  lets a caller leave one out: its `argv` element is dropped, so write a flag and value as one element
  (`"--filter={filter}"`).
- **Editing:** one command at a time as YAML, with a **Preview** of the exact command a set of sample
  values produces, and hosts through a form with **Test connection**. A renamed command keeps its hosts
  and roles. Every change validates the whole
  file, keeps a saved copy (20 by default) you can View and Restore, refuses to overwrite a change made
  elsewhere, and is logged. A hand edit that no longer parses keeps the last good version in use.
- **Roles:** a call is allowed only if the agent's role has the command **and** the host offers it. ulmo
  checks each value and builds the argument list itself, so a value is always one literal argument,
  never shell syntax.

```
POST /api/v1/commands[?wait=20]  {"command": "logs", "host": "gandalf", "params": {"n": 100, "container": "sonarr"}}
GET  /api/v1/commands/{id}       status, return code, output (capped at 64 KB); only the agent's own runs
```

`POST` waits up to `wait` seconds (default 20, max 60): `200` with the result if it finishes, else `202`
and you poll `GET /commands/{id}`. The host runs it under its own `timeout` (coreutils or busybox must be
installed). At most 5 commands run at once and 2 per host. The kill switch covers commands. Commands do
not use the Ansible inventory, and playbook grants do not use these hosts.

**Approvals.** A role can mark a command or a playbook grant "needs approval". A call to it answers `202`
`{"status": "pending_approval", "approval_id": N}` and nothing runs until you decide on the **Approvals**
page (each request has its own link, which a notification can open). Approving starts it as shown, after
repeating every check a direct call gets. The agent polls `GET /api/v1/approvals/{id}`: `pending`, then
`approved` (with a `result_url`), `denied`, `expired` (15 minutes) or `failed`. At most 10 requests per
agent wait at once, and repeating one returns the same approval. A request may carry a `note` (500
characters), shown escaped as the agent's words. Only a signed-in admin can decide; approving is refused
while `ULMO_DISABLE_AUTH` is set. A new request sends a Pushover/ntfy notification; set **Public URL of
ulmo** under Settings → Notifications to include the link.

**Rate limit.** Each agent gets 60 requests an hour by default (set it per agent on the Agents page; 0 is
no limit): runs, commands and approval requests together, counted once when accepted. A request refused for bad parameters or missing
permission costs nothing, and neither does your approval. Past the limit a request answers `429`.

### Proposing changes (commands, roles and files)

Scripts can ask for the same edits you make on the Commands, Agents and Files pages. A script **cannot
change anything itself**: it sends a proposal, ulmo checks it, and it waits on the **Approvals** page
("Change proposals") for you to approve after reading the diff.

Create a **change token** under Agents → Change tokens (shown once, optional expiry). It is not an agent
token: agent tokens are refused on `/api/v1/admin`, change tokens on every agent route, and neither is a
login. A change token can read and propose; it cannot run a command, approve its own proposal or reach any
admin page. It can read `commands.yml` (host addresses, SSH user names and key file names, not keys or
passwords) and every text file in the workspace, including `files/`, where keys may be, so hand one only
to a tool you trust with that.

```
GET  /api/v1/admin/commands.yml        the file as it is on disk
GET  /api/v1/admin/roles               each role's commands (with needs_approval) and, read-only, its playbook grants
GET  /api/v1/admin/files               every file in the workspace: path, size, last edited
GET  /api/v1/admin/files/content?path= one text file with its version (send it back as `base`)
POST /api/v1/admin/proposals[?dry_run=true]   {"note": "why", "ops": [ ... ]}  -> 202 {"id", "diff", "previews"}
GET  /api/v1/admin/proposals[/{id}]    this token's proposals: pending | applied | denied | expired | failed
```

A dry run returns the diff and records nothing:

```
curl -s -H "Authorization: Bearer $CHANGE_TOKEN" -H 'Content-Type: application/json' \
  'https://ulmo.example.com/api/v1/admin/proposals?dry_run=true' \
  -d '{"note": "why", "ops": [{"op": "save_command", "name": "kernel-log",
       "body": {"description": "Kernel warnings and errors", "argv": ["dmesg", "-T", "--level=err,warn"], "risk": "low"}}]}'
```

A proposal is up to 20 operations, applied together or not at all. Each changes one thing, not a list:

```
{"op": "save_command", "name": "pfsense-update-check", "body": {description, argv, timeout, ...}, "samples": {"unit": "nginx"}}
{"op": "delete_command", "name": "x"}                       refused while a host still offers it; the roles lose it with it
{"op": "host_offer", "host": "ecth", "add": ["x"], "remove": ["y"]}
{"op": "role_allow", "role": "n8n", "add": [{"command": "x", "needs_approval": false}], "remove": ["y"]}
{"op": "role_set_approval", "role": "n8n", "command": "x", "needs_approval": true}
{"op": "save_file", "path": "playbooks/site.yaml", "text": "<the whole new file>", "base": "<version from the read>"}
```

- `save_command` is checked as the Commands page checks it. With `samples` the approval page shows the
  `The host would receive` line (the same as Preview), and a sample the command would refuse rejects it.
- `needs_approval` must be stated when adding a command to a role, so a proposal cannot quietly add one
  that runs unattended.
- `save_file` creates or replaces any workspace file. `base` is the file's `version` when read, or `""`
  to create one: an edit against a file that has since changed is refused. A proposal with a `save_file`
  has only `save_file` operations (saved together or not at all). `text` is the whole file, up to 256 KB
  per file and 1 MB per proposal, never binary. Approving saves through the Files page's write (old
  version kept, CRLF kept), waits while a playbook runs, and warns if `--syntax-check` fails.
- Control, zero-width and direction-override characters are refused anywhere. Other non-ASCII characters
  are allowed but flagged in `warnings` and on the approval page. One command is limited to 20 KB.
- Adding what is already there, removing what is not, or changing nothing is an error. Deleting a command
  takes it out of every role, so take it off the host first (`host_offer` `remove`) in the same proposal.
  A role must already exist for `role_allow` and `role_set_approval`.
- Not available from the API: hosts' addresses, users, keys and passwords, agents, tokens, roles'
  existence, playbook grants, limits and the kill switch.

**Approving.** The proposal's page (`/proposals/{id}`) shows the diff of `commands.yml`, of the roles it
touches, or of each file with line numbers (flagging roles granted a playbook you change). **Approve**
applies it through the same locked, validated write as the Commands or Files page and logs it with the
token and your name. It carries a digest of what you saw: if the proposal, `commands.yml`, the roles or
the files changed since, it is refused and you look again. A proposal that can no longer be applied is
`failed`; if `commands.yml` does not parse or a playbook is running, Approve answers with the reason and
the proposal stays pending. Disabling, expiring or deleting a token cancels what it queued. Proposals
expire after 24 hours, at most 10 per token wait, and a token may make 60 proposal or dry-run calls an
hour (then `429`). While `ULMO_DISABLE_AUTH` is set, change tokens cannot be created and proposals cannot
be approved (denying always works).

The API is separate from the login session: `ULMO_DISABLE_AUTH` does not open it. While it is set the
Agents page will not create agents or widen what they may do, though it will still switch runs off. Serve
ulmo over HTTPS so tokens are not sent in clear.

## SSH access to target hosts

**Settings → SSH keys:** paste the private key(s) used to connect to managed hosts, for Ansible and the
Commands page. They are symlinked into the container at `/home/ansible/.ssh` and `/root/.ssh` to match the
common `ansible_ssh_private_key_file: /home/ansible/.ssh/ansible-ed25519` convention (set
`ULMO_SSH_LINK_HOMES` if yours differs). Keys must be unencrypted. A private git remote needing its own
key (for Import from Git) can mount one in `docker-compose.yml`.

## Environment variables

- `ULMO_DISABLE_AUTH=true`: skip login entirely; only if ulmo already sits behind your own access control
- `ULMO_DATA_DIR`: where ulmo keeps everything; `/data` in the container, mounted from `./data`
- `ULMO_SECURE_COOKIES=true`: mark the session cookie Secure; set it when served over TLS
- `ULMO_SECRET_KEY`: pin the session-signing key; otherwise one is generated in `./data/secret_key`
- `ULMO_SSH_LINK_HOMES`: comma-separated home dirs to symlink SSH keys into, if not `/home/ansible` or `/root`

## Data

Everything lives under `./data`: the database, Ansible files in `ansible/` (saved copies in
`ansible.history/`), SSH keys, the command library, run logs and installed collections. Back up that whole
directory; it also holds `commands.yml` and host passwords. Settings backup/restore covers settings only,
not SSH keys, users, agents and roles, the command library or host passwords.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
ULMO_DATA_DIR=./data uvicorn app.main:app --reload
```

### Tests

Self-checks, no pytest: each file in `tests/` is a standalone script, run in CI on every push to `main`
and pull request. Python 3.10+ is required.

```bash
./tests/run_all.sh                              # all of them, one pass/fail summary
PYTHON=/path/to/python3.12 ./tests/run_all.sh   # pick an interpreter
docker exec ulmo /app/tests/run_all.sh          # inside the container
```

Coverage is deliberately narrow: these guard specific regressions, not the whole feature surface. Anything
client-side still needs a real browser; `test_stream_resume.py` only checks that the run-detail page's
inline script parses.
