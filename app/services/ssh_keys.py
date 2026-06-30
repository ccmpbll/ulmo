import logging
from pathlib import Path

from app.config import SSH_KEY_FILENAME, SSH_KEY_LINK_HOMES, SSH_STORAGE_DIR

logger = logging.getLogger("homelab-deck.ssh_keys")

KEY_PATH = SSH_STORAGE_DIR / SSH_KEY_FILENAME


def ensure_symlinks() -> list[str]:
    """Make SSH_STORAGE_DIR reachable as "<home>/.ssh" for each configured home.

    Returns a list of human-readable warnings for any home that couldn't be
    linked (e.g. no permission to create it outside a container). The app
    keeps running either way — key upload still works, it just won't be
    visible to ansible-playbook until the link exists.
    """
    warnings: list[str] = []
    try:
        SSH_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        SSH_STORAGE_DIR.chmod(0o700)
    except OSError as exc:
        warnings.append(f"Could not create {SSH_STORAGE_DIR}: {exc}")
        return warnings

    for home in SSH_KEY_LINK_HOMES:
        ssh_dir = Path(home) / ".ssh"
        try:
            if ssh_dir.is_symlink():
                if ssh_dir.resolve() == SSH_STORAGE_DIR.resolve():
                    continue
                ssh_dir.unlink()
            elif ssh_dir.exists():
                warnings.append(
                    f"{ssh_dir} already exists and is not managed by homelab-deck — "
                    "remove it or change HOMELAB_DECK_SSH_LINK_HOMES."
                )
                continue
            ssh_dir.parent.mkdir(parents=True, exist_ok=True)
            ssh_dir.symlink_to(SSH_STORAGE_DIR)
        except OSError as exc:
            warnings.append(f"Could not link {ssh_dir} -> {SSH_STORAGE_DIR}: {exc}")

    if warnings:
        for w in warnings:
            logger.warning(w)
    return warnings


def key_configured() -> bool:
    return KEY_PATH.exists() and KEY_PATH.stat().st_size > 0


def save_key(key_text: str) -> None:
    key_text = key_text.strip()
    if not key_text.startswith("-----BEGIN"):
        raise ValueError("That doesn't look like a private key (expected a -----BEGIN ... block).")
    SSH_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    SSH_STORAGE_DIR.chmod(0o700)
    KEY_PATH.write_text(key_text + "\n")
    KEY_PATH.chmod(0o600)


def delete_key() -> None:
    KEY_PATH.unlink(missing_ok=True)


def key_fingerprint_hint() -> str | None:
    """Last line-ish bit of metadata to show without revealing the key itself."""
    if not key_configured():
        return None
    try:
        first_line = KEY_PATH.read_text().splitlines()[0]
    except (OSError, IndexError):
        return None
    return first_line.replace("-----BEGIN ", "").replace("-----", "").strip()
