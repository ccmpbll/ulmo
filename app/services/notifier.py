import logging
import urllib.parse
import urllib.request

from app.models import Approval, RunHistory
from app.services import settings_store

logger = logging.getLogger("ulmo.notifier")


def notify_run_complete(run: RunHistory) -> None:
    settings = settings_store.get_all()
    notify_on = settings.get("notify_on", "")
    if not notify_on:
        return
    # A cancel is a deliberate user action, not a failure — never let it fire
    # a "failure" alert. It still notifies under notify_on="all".
    if notify_on == "failure" and run.status in ("success", "cancelled"):
        return

    status_words = {
        "success": "succeeded",
        "cancelled": "cancelled",
        "timeout": "TIMED OUT",
    }
    status_word = status_words.get(run.status, "FAILED")
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


def notify_approval(approval: Approval) -> None:
    """Tell the admin a request is waiting. Sent whatever "Notify on" is set to, because a request
    nobody hears about just expires. The link opens the request on the Approvals page (sign-in
    applies); it is left out when no public URL is set, since ulmo cannot know its own address."""
    settings = settings_store.get_all()
    base = settings.get("public_url", "").strip().rstrip("/")
    url = f"{base}/approvals/{approval.id}" if base else ""
    title = f"ulmo: {approval.agent_name} needs approval"
    message = f"{approval.agent_name} wants to run: {approval.line}" + (f" on {approval.host}" if approval.kind == "command" else "")
    if approval.agent_note:
        message += f"\n{approval.agent_name} says: {approval.agent_note[:300]}"
    pushover_token = settings.get("notify_pushover_token", "").strip()
    pushover_user = settings.get("notify_pushover_user", "").strip()
    ntfy_url = settings.get("notify_ntfy_url", "").strip()
    if pushover_token and pushover_user:
        _send_pushover(pushover_token, pushover_user, title, message, url)
    if ntfy_url:
        _send_ntfy(ntfy_url, title, message, url)


def _send_pushover(token: str, user: str, title: str, message: str, url: str = "") -> None:
    fields = {"token": token, "user": user, "title": title, "message": message}
    if url:
        fields.update(url=url, url_title="Review request")
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request("https://api.pushover.net/1/messages.json", data=data)
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception:
        logger.exception("Pushover notification failed")


def _send_ntfy(url: str, title: str, message: str, click: str = "") -> None:
    req = urllib.request.Request(url, data=message.encode(), method="POST")
    req.add_header("Title", title)
    if click:
        req.add_header("Click", click)
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception:
        logger.exception("ntfy notification failed")
