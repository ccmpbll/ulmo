from pathlib import Path

from fastapi.templating import Jinja2Templates

from app.auth import current_user
from app.config import AUTH_DISABLED

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.globals["current_user"] = current_user
templates.env.globals["AUTH_DISABLED"] = AUTH_DISABLED
