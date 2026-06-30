import logging
import re
from pathlib import Path

from app.config import SSH_KEY_LINK_HOMES, SSH_STORAGE_DIR

logger = logging.getLogger("ulmo.ssh_keys")

# Files that aren't user-managed keys, even though they live alongside them.
RESERVED_FILENAMES = {"known_hosts", "known_hosts.old", "config"}
FILENAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")


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
                    f"{ssh_dir} already exists and is not managed by ulmo — "
                    "remove it or change ULMO_SSH_LINK_HOMES."
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


def _validate_filename(filename: str) -> str:
    filename = Path(filename).name.strip()
    if not filename or not FILENAME_PATTERN.match(filename):
        raise ValueError(
            "Key name can only contain letters, numbers, dots, dashes and underscores."
        )
    if filename.startswith(".") or filename in RESERVED_FILENAMES:
        raise ValueError(f'"{filename}" is a reserved name — choose a different one.')
    return filename


def list_keys() -> list[dict]:
    if not SSH_STORAGE_DIR.exists():
        return []
    keys = []
    for path in sorted(SSH_STORAGE_DIR.iterdir()):
        if not path.is_file() or path.name in RESERVED_FILENAMES or path.suffix == ".pub":
            continue
        keys.append({"filename": path.name, "hint": _fingerprint_hint(path)})
    return keys


def save_key(filename: str, key_text: str) -> None:
    filename = _validate_filename(filename)
    # Browsers normalize <textarea> form submissions to CRLF line endings,
    # which breaks OpenSSH/PEM's base64 parser ("error in libcrypto").
    key_text = key_text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not key_text.startswith("-----BEGIN"):
        raise ValueError("That doesn't look like a private key (expected a -----BEGIN ... block).")
    SSH_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    SSH_STORAGE_DIR.chmod(0o700)
    path = SSH_STORAGE_DIR / filename
    path.write_text(key_text + "\n")
    path.chmod(0o600)


def delete_key(filename: str) -> None:
    filename = _validate_filename(filename)
    (SSH_STORAGE_DIR / filename).unlink(missing_ok=True)


def _fingerprint_hint(path: Path) -> str | None:
    """First line of the PEM/OpenSSH header, without revealing the key body."""
    try:
        first_line = path.read_text().splitlines()[0]
    except (OSError, IndexError):
        return None
    return first_line.replace("-----BEGIN ", "").replace("-----", "").strip()
