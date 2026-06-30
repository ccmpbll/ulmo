import hashlib
from pathlib import Path

from fastapi.templating import Jinja2Templates

from app.auth import current_user
from app.config import AUTH_DISABLED, VERSION

templates_dir = Path(__file__).parent / "templates"
static_dir = Path(__file__).parent / "static"

templates = Jinja2Templates(directory=str(templates_dir))
templates.env.globals["current_user"] = current_user
templates.env.globals["AUTH_DISABLED"] = AUTH_DISABLED
templates.env.globals["APP_VERSION"] = VERSION

# Cache-busting token for static assets, so a browser that already cached
# style.css picks up changes after a deploy without needing a hard refresh.
# Content hash rather than mtime, since COPY in the Docker build doesn't
# reliably preserve source file mtimes.
_style_css = static_dir / "style.css"
templates.env.globals["STATIC_VERSION"] = (
    hashlib.sha256(_style_css.read_bytes()).hexdigest()[:10] if _style_css.exists() else "0"
)
