import hashlib
from datetime import datetime
from pathlib import Path

from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape

from app.auth import current_user
from app.config import AUTH_DISABLED, VERSION

templates_dir = Path(__file__).parent / "templates"
static_dir = Path(__file__).parent / "static"

templates = Jinja2Templates(directory=str(templates_dir))
templates.env.globals["current_user"] = current_user
templates.env.globals["AUTH_DISABLED"] = AUTH_DISABLED
templates.env.globals["APP_VERSION"] = VERSION


def local_time(ts: datetime | None) -> Markup:
    """Render a UTC timestamp as a <time> tag; local-time.js fills in the
    viewer's own timezone client-side, falling back to UTC text if JS is
    off."""
    if ts is None:
        return Markup("-")
    utc_text = ts.strftime("%Y-%m-%d %H:%M:%S")
    return Markup(f'<time class="local-time" datetime="{escape(ts.isoformat())}">{escape(utc_text)} UTC</time>')


templates.env.filters["local_time"] = local_time

# Cache-busting token for static assets, so a browser that already cached
# style.css/local-time.js/logo.png picks up changes after a deploy without
# needing a hard refresh. Content hash rather than mtime, since COPY in the
# Docker build doesn't reliably preserve source file mtimes.
_static_assets = [static_dir / "style.css", static_dir / "local-time.js", static_dir / "logo.png"]
_hash = hashlib.sha256()
for _asset in _static_assets:
    if _asset.exists():
        _hash.update(_asset.read_bytes())
templates.env.globals["STATIC_VERSION"] = _hash.hexdigest()[:10]
