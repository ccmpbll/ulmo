"""Self-check for requirements-path resolution in app/services/git_sync.py.

The configured requirements_path is already guarded against escaping the repo;
this covers the auto-discovery branch, which builds candidates from the
configured playbooks_subdir. A subdir like ".." must resolve inside the repo
(or be skipped), never point at a file outside it.

Run directly: python3 tests/test_requirements_traversal.py
"""
import os
import shutil
import tempfile

DATA_DIR = tempfile.mkdtemp(prefix="ulmo-test-")
os.environ["ULMO_DATA_DIR"] = DATA_DIR

from pathlib import Path  # noqa: E402

from app.config import REPO_DIR  # noqa: E402
from app.database import init_db  # noqa: E402
from app.services import git_sync, settings_store  # noqa: E402


def test_escaping_subdir_is_not_honored():
    init_db()
    settings_store.set_many({"playbooks_subdir": "..", "requirements_path": ""})

    # A requirements.yaml sitting one level above the repo must NOT be picked
    # up by auto-discovery.
    outside = Path(DATA_DIR) / "requirements.yaml"
    outside.write_text("---\ncollections: []\n")

    result = git_sync._find_requirements_file()
    # An escaping subdir must never resolve to a file outside the repo — it's
    # skipped and surfaces as a warning string (like a bad configured path).
    assert result is None or (
        isinstance(result, str) and "outside the repo" in result
    ), f"auto-discovery escaped the repo: {result!r}"
    outside.unlink()


def test_valid_subdir_candidate_is_found():
    settings_store.set_many({"playbooks_subdir": "playbooks", "requirements_path": ""})
    subdir = REPO_DIR / "playbooks"
    subdir.mkdir(parents=True, exist_ok=True)
    (subdir / "requirements.yaml").write_text("---\ncollections: []\n")

    result = git_sync._find_requirements_file()
    assert isinstance(result, Path), f"expected a Path, got {result!r}"
    assert result.resolve() == (subdir / "requirements.yaml").resolve()


if __name__ == "__main__":
    try:
        test_escaping_subdir_is_not_honored()
        test_valid_subdir_candidate_is_found()
        print("OK: requirements auto-discovery stays inside the repo.")
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)