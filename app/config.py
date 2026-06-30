import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("HOMELAB_DECK_DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

REPO_DIR = DATA_DIR / "repo"
RUNS_DIR = DATA_DIR / "runs"
RUNS_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "homelab-deck.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

SECRET_KEY = os.environ.get("HOMELAB_DECK_SECRET_KEY", "dev-secret-change-me")
