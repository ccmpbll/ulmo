import urllib.parse
import urllib.request

from app.models import RunHistory
from app.services import settings_store


def notify_run_complete(run: RunHistory) -> None:
    settings = settings_store.get_all()
    notify_on = settings.get("notify_on", "")
    if not notify_on:
        return
    if notify_on == "failure" and run.status != "failed":
        return

    status_word = "succeeded" if run.status == "success" else "FAILED"
    title = f"ulmo: {run.playbook} {status_word}"
    parts = []
    if run.tags:
        parts.append(f"tags: {run.tags}")
    if run.limit:
        parts.append(f"limit: {run.limit}")
    message = title + (f" ({', '.join(parts)})" if parts else "")

    pushover_token = settings.get("notify_pushover_token", "").strip()
    pushover_user = settings.get("notify_pushover_user", "").strip()
    ntfy_url = settings.get("notify_ntfy_url", "").strip()

    if pushover_token and pushover_user:
        _send_pushover(pushover_token, pushover_user, title, message)
    if ntfy_url:
        _send_ntfy(ntfy_url, title, message)


def _send_pushover(token: str, user: str, title: str, message: str) -> None:
    data = urllib.parse.urlencode(
        {"token": token, "user": user, "title": title, "message": message}
    ).encode()
    req = urllib.request.Request("https://api.pushover.net/1/messages.json", data=data)
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception:
        pass


def _send_ntfy(url: str, title: str, message: str) -> None:
    req = urllib.request.Request(url, data=message.encode(), method="POST")
    req.add_header("Title", title)
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception:
        pass
