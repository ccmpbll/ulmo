import hashlib
from datetime import datetime, timezone
from pathlib import Path

from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape

from app.auth import current_user
from app.config import AUTH_DISABLED, VERSION
from app.services import agents, proposals

templates_dir = Path(__file__).parent / "templates"
static_dir = Path(__file__).parent / "static"

templates = Jinja2Templates(directory=str(templates_dir))
templates.env.globals["current_user"] = current_user
templates.env.globals["AUTH_DISABLED"] = AUTH_DISABLED
templates.env.globals["APP_VERSION"] = VERSION


templates.env.globals["pending_approvals"] = proposals.waiting_total
templates.env.globals["agent_runs_on"] = agents.runs_enabled


def _utc(ts: datetime) -> datetime:
    """The database hands timestamps back without a timezone, but they are all UTC. Without an offset
    in the <time> tag a browser would read the digits as its own local time."""
    return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)


def local_time(ts: datetime | None, relative: bool = False) -> Markup:
    """Render a UTC timestamp as a <time> tag; local-time.js fills in the
    viewer's own timezone client-side, falling back to UTC text if JS is
    off. With relative=True the script shows "5 min ago" / "in 2 h" instead and keeps the full
    time as the hover text."""
    if ts is None:
        return Markup("-")
    ts = _utc(ts)
    utc_text = ts.strftime("%Y-%m-%d %H:%M:%S")
    flag = " data-relative" if relative else ""
    return Markup(f'<time class="local-time" datetime="{escape(ts.isoformat())}"{flag}>{escape(utc_text)} UTC</time>')


def local_ago(ts: datetime | None) -> Markup:
    return local_time(ts, relative=True)


templates.env.filters["local_time"] = local_time
templates.env.filters["local_ago"] = local_ago

# Cache-busting token for static assets, so a browser that already cached
# style.css/local-time.js/logo.png picks up changes after a deploy without
# needing a hard refresh. Content hash rather than mtime, since COPY in the
# Docker build doesn't reliably preserve source file mtimes.
_static_assets = [static_dir / "style.css", static_dir / "local-time.js", static_dir / "filter.js", static_dir / "menu.js", static_dir / "logo.png"]
_hash = hashlib.sha256()
for _asset in _static_assets:
    if _asset.exists():
        _hash.update(_asset.read_bytes())
templates.env.globals["STATIC_VERSION"] = _hash.hexdigest()[:10]
