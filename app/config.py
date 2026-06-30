import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("HOMELAB_DECK_DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

REPO_DIR = DATA_DIR / "repo"
RUNS_DIR = DATA_DIR / "runs"
RUNS_DIR.mkdir(parents=True, exist_ok=True)

# Persistent install location for collections pulled from a repo's
# requirements.yaml, so they survive container restarts/rebuilds without
# needing to be reinstalled from Galaxy every time.
COLLECTIONS_DIR = DATA_DIR / "collections"

DB_PATH = DATA_DIR / "homelab-deck.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

SECRET_KEY = os.environ.get("HOMELAB_DECK_SECRET_KEY", "dev-secret-change-me")

# Persistent storage for SSH private keys used by ansible-playbook runs. Each
# uploaded key is its own file here (named to match what an inventory's
# ansible_ssh_private_key_file expects, e.g. "ansible-ed25519"). This directory
# is symlinked onto SSH_KEY_LINK_HOMES so the keys are reachable without
# needing to edit the inventory itself.
SSH_STORAGE_DIR = DATA_DIR / "ssh_home" / ".ssh"

# Absolute paths whose ".ssh" directory should be symlinked to SSH_STORAGE_DIR.
# Defaults match this project's existing inventory.yaml convention
# (ansible_ssh_private_key_file: /home/ansible/.ssh/ansible-ed25519) plus root,
# so SSH also persists known_hosts across container restarts. Override with a
# comma-separated list via HOMELAB_DECK_SSH_LINK_HOMES if your inventory uses a
# different path.
SSH_KEY_LINK_HOMES = [
    p.strip()
    for p in os.environ.get("HOMELAB_DECK_SSH_LINK_HOMES", "/home/ansible,/root").split(",")
    if p.strip()
]
