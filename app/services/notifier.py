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

    _send(settings, title, message)


def notify_approval(approval: Approval) -> None:
    """Tell the admin a request is waiting. Sent whatever "Notify on" is set to, because a request
    nobody hears about just expires. The link opens the request on the Approvals page (sign-in
    applies); it is left out when no public URL is set, since ulmo cannot know its own address."""
    settings = settings_store.get_all()
    base = settings.get("public_url", "").strip().rstrip("/")
    url = f"{base}/approvals/{approval.id}" if base else ""
    title = f"ulmo: {approval.agent_name} needs approval"
    message = (f"{approval.agent_name} wants to {approval.line}" if approval.kind == "file" else f"{approval.agent_name} wants to run: {approval.line}") + (f" on {approval.host}" if approval.kind == "command" else "")
    if approval.agent_note:
        message += f"\n{approval.agent_name} says: {approval.agent_note[:300]}"
    _send(settings, title, message, url)


def notify_proposal(proposal, summary: str) -> None:
    """Tell the admin a script proposed a change. Like approvals: sent whatever "Notify on" says,
    with a link to the proposal when a public URL is set."""
    settings = settings_store.get_all()
    base = settings.get("public_url", "").strip().rstrip("/")
    url = f"{base}/proposals/{proposal.id}" if base else ""
    message = f"{proposal.token_name} proposes: {summary}"
    if proposal.note:
        message += f"\n{proposal.token_name} says: {proposal.note[:300]}"
    _send(settings, f"ulmo: {proposal.token_name} proposes a change", message, url)


def _send(settings: dict, title: str, message: str, url: str = "") -> None:
    token = settings.get("notify_pushover_token", "").strip()
    user = settings.get("notify_pushover_user", "").strip()
    if token and user:
        fields = {"token": token, "user": user, "title": title, "message": message}
        if url:
            fields.update(url=url, url_title="Review request")
        _post("https://api.pushover.net/1/messages.json", urllib.parse.urlencode(fields).encode(), "Pushover")
    ntfy_url = settings.get("notify_ntfy_url", "").strip()
    if ntfy_url:
        _post(ntfy_url, message.encode(), "ntfy", {"Title": title, **({"Click": url} if url else {})})


def _post(url: str, data: bytes, name: str, headers: dict | None = None) -> None:
    req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception:
        logger.exception("%s notification failed", name)
