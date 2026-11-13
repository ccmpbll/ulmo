"""Self-check for the SSH key hints on the Settings and Inventory pages.

  1. The accepted key paths are the linked homes' .ssh plus ~/.ssh, and each inventory key path is
     classified: saved, missing (under a linked home, no key of that name) or not managed.
  2. Settings -> SSH keys says what the name has to be, shows where each saved key is available and
     which hosts use it, and lists every key path the inventory names with its status.
  3. The Inventory page tells users the acceptable paths and warns about a path with no saved key.

Run directly: python3 tests/test_ssh_key_hints.py
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path

DATA_DIR = str(Path(tempfile.mkdtemp(prefix="ulmo-test-")).resolve())  # macOS temp is a symlink; the inventory code resolves paths
os.environ["ULMO_DATA_DIR"] = DATA_DIR
os.environ.pop("ULMO_DISABLE_AUTH", None)
os.environ.pop("ULMO_SSH_LINK_HOMES", None)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

import app.auth as auth_module  # noqa: E402
from app.database import init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.services import inventory, ssh_keys, workspace  # noqa: E402

workspace.schedule_refresh = lambda install=False: None
admin = TestClient(app)
KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
calls = {"n": 0}
FILES: dict = {}


def fake_key_files():
    calls["n"] += 1
    return FILES


real_key_files = inventory.key_files
inventory.key_files = fake_key_files


def test_classification():
    assert ssh_keys.accepted_paths() == ["/home/ansible/.ssh/<name>", "/root/.ssh/<name>", "~/.ssh/<name>"]
    saved = {"ansible-ed25519", "chris-ed25519"}
    check = lambda p: ssh_keys.check_inventory_key(p, saved)  # noqa: E731
    assert check("/home/ansible/.ssh/ansible-ed25519")["status"] == "ok"
    assert check("/root/.ssh/chris-ed25519")["status"] == "ok"
    assert check("~/.ssh/ansible-ed25519")["status"] == "ok"
    miss = check("/home/ansible/.ssh/old-rsa")
    assert miss["status"] == "missing" and miss["name"] == "old-rsa" and 'no key named "old-rsa"' in miss["message"]
    assert check("~/.ssh/nope")["status"] == "missing"
    assert check("/home/ansible/.ssh/sub/ansible-ed25519")["status"] == "other", "a subfolder is not a saved key"
    assert check("/home/ansible/.ssh/")["status"] == "other"
    assert check("/home/other/.ssh/ansible-ed25519")["status"] == "other", "a home that is not linked"
    assert check("/keys/mounted")["status"] == "other" and "inside the container" in check("/keys/mounted")["message"]
    assert check("{{ key_dir }}/id")["status"] == "other" and "templated" in check("{{ key_dir }}/id")["message"]
    report = ssh_keys.inventory_key_report(["a"], {"/home/ansible/.ssh/a": ["h1", "h2"], "/home/ansible/.ssh/b": ["h3"]})
    assert [(r["name"], r["status"], r["hosts"]) for r in report] == [("a", "ok", ["h1", "h2"]), ("b", "missing", ["h3"])]


def test_key_files_come_from_the_inventory():
    real_data = inventory._data
    inventory._data = lambda: {"conn": {
        "frodo": {"ansible_ssh_private_key_file": "/home/ansible/.ssh/a"}, "gandalf": {"ansible_ssh_private_key_file": " /home/ansible/.ssh/a "},
        "cirdan": {"ansible_ssh_private_key_file": "/root/.ssh/b"}, "bare": {"ansible_host": "10.0.0.1"}, "empty": {"ansible_ssh_private_key_file": ""}}}
    try:
        assert real_key_files() == {"/home/ansible/.ssh/a": ["frodo", "gandalf"], "/root/.ssh/b": ["cirdan"]}
    finally:
        inventory._data = real_data


def test_the_settings_page():
    ssh_keys.save_key("ansible-ed25519", KEY)
    FILES.clear()
    FILES.update({"/home/ansible/.ssh/ansible-ed25519": ["frodo", "gandalf"], "/home/ansible/.ssh/old-rsa": ["cirdan"], "/mnt/keys/special": ["feanor"]})
    calls["n"] = 0
    page = admin.get("/settings?tab=ssh").text
    assert "<h3>How keys are found</h3>" in page and "So the name must match the file name in the inventory path" in page
    assert "<li><code>/home/ansible/.ssh/&lt;name&gt;</code></li>" in page and "<li><code>/root/.ssh/&lt;name&gt;</code></li>" in page
    assert "<li><code>~/.ssh/&lt;name&gt;</code></li>" in page, "every path the inventory page lists"
    assert "<h3 style=\"margin-top: 20px;\">Saved keys</h3>" in page and "<h3>Add a key</h3>" in page
    assert "<code>ansible-ed25519</code>" in page and "at /home/ansible/.ssh/ansible-ed25519" in page
    assert "used by frodo, gandalf" in page
    assert "Keys your inventory names" in page
    assert page.count('class="badge success"') >= 1 and ">saved</span>" in page
    assert ">missing</span>" in page and 'no key named &#34;old-rsa&#34; is saved' in page
    assert ">not managed</span>" in page and "must exist inside the container" in page
    assert calls["n"] == 1
    # a key nothing uses says so; the inventory is not read on the other tabs
    ssh_keys.save_key("spare", KEY)
    assert "no inventory host uses it" in admin.get("/settings?tab=ssh").text
    calls["n"] = 0
    for tab in ("ansible", "notify", "backup", "account"):
        assert admin.get(f"/settings?tab={tab}").status_code == 200
    assert calls["n"] == 0, "only the SSH tab reads the inventory"
    FILES.clear()
    page = admin.get("/settings?tab=ssh").text
    assert "Keys your inventory names" not in page, "nothing to list"


def test_both_pages_list_the_same_paths():
    import re
    items = lambda html: re.findall(r"<li><code>(.*?)</code></li>", html.split('class="key-paths"')[1].split("</ul>")[0])  # noqa: E731
    FILES.clear()
    settings = items(admin.get("/settings?tab=ssh").text)
    inv = items(admin.get("/inventory").text)
    assert settings == inv and len(settings) == 3, (settings, inv)


def test_the_inventory_page():
    FILES.clear()
    # no inventory file: the help is there, nothing is read, nothing is warned about
    calls["n"] = 0
    page = admin.get("/inventory").text
    assert "<h3>SSH key paths</h3>" in page
    for path in ("/home/ansible/.ssh/&lt;name&gt;", "/root/.ssh/&lt;name&gt;", "~/.ssh/&lt;name&gt;"):
        assert f"<li><code>{path}</code></li>" in page, path
    assert "Settings → SSH keys" in page and "Any other path must exist inside the container" in page
    assert calls["n"] == 0 and "has no saved key" not in page
    workspace.store("inventory.yaml", b"all:\n  hosts:\n    frodo: {}\n", base=None)
    FILES.update({"/home/ansible/.ssh/ansible-ed25519": ["frodo"]})
    page = admin.get("/inventory").text
    assert "has no saved key" not in page, "a saved key is not a problem"
    FILES.update({"/home/ansible/.ssh/old-rsa": ["cirdan", "feanor"], "/keys/x": ["h"]})
    page = admin.get("/inventory").text
    assert '<code>/home/ansible/.ssh/old-rsa</code> has no saved key named "old-rsa" (used by cirdan, feanor)' in page
    assert "/keys/x" not in page.split("has no saved key")[1].split("</p>")[0], "a path ulmo does not manage is not nagged about here"
    assert 'href="/settings?tab=ssh">Add it in Settings' in page


def main():
    init_db()
    auth_module.create_user("admin", "pw-for-tests")
    r = admin.post("/login", data={"username": "admin", "password": "pw-for-tests"}, follow_redirects=False)
    assert r.status_code == 303, "test login failed"
    tests = [v for k, v in sorted(globals().items(), key=lambda kv: list(globals()).index(kv[0])) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print(f"OK: SSH key hints — {len(tests)} checks.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(DATA_DIR, ignore_errors=True)
