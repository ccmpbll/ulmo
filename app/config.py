import os
import secrets
from pathlib import Path

VERSION = os.environ.get("ULMO_VERSION", "dev")

DATA_DIR = Path(os.environ.get("ULMO_DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

REPO_DIR = DATA_DIR / "repo"
RUNS_DIR = DATA_DIR / "runs"
RUNS_DIR.mkdir(parents=True, exist_ok=True)

# Persistent install location for collections pulled from a repo's
# requirements.yaml, so they survive container restarts/rebuilds without
# needing to be reinstalled from Galaxy every time.
COLLECTIONS_DIR = DATA_DIR / "collections"

DB_PATH = DATA_DIR / "ulmo.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

def _resolve_secret_key() -> str:
    env_value = os.environ.get("ULMO_SECRET_KEY", "").strip()
    if env_value:
        return env_value
    # No key provided — generate one and persist it so sessions survive restarts
    # instead of silently falling back to a shared, predictable default.
    key_path = DATA_DIR / "secret_key"
    if key_path.exists():
        existing = key_path.read_text().strip()
        if existing:
            return existing
    generated = secrets.token_hex(32)
    key_path.write_text(generated)
    key_path.chmod(0o600)
    return generated


SECRET_KEY = _resolve_secret_key()

# When set, login is skipped entirely and every request is treated as a fixed
# anonymous user. Off by default — only enable this if ulmo sits behind its
# own access control (e.g. a reverse proxy, VPN-only network).
AUTH_DISABLED = os.environ.get("ULMO_DISABLE_AUTH", "").strip().lower() in (
    "1",
    "true",
    "yes",
)

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
# comma-separated list via ULMO_SSH_LINK_HOMES if your inventory uses a
# different path.
SSH_KEY_LINK_HOMES = [
    p.strip()
    for p in os.environ.get("ULMO_SSH_LINK_HOMES", "/home/ansible,/root").split(",")
    if p.strip()
]
