# api/dashboard_session.py
# The dashboard's browser session. The page no longer carries the API key:
# the app opens the browser on a one-time link, the server answers it with a
# session token, and the page sends that in a header the API accepts as well
# as X-API-Key. Not a cookie: browsers send a cookie for 127.0.0.1 to every
# port there, while the page's own storage stays with this port.

import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
import time
from html import escape

HEADER = "X-Agental-Session"
STORAGE_KEY = "agental_session"
LINK_TTL = 120
SESSION_TTL = 30 * 86400

_used = {}
_used_lock = threading.Lock()


def _mac(api_key: str, purpose: str, body: str) -> str:
    return hmac.new(api_key.encode("utf-8", "surrogateescape"),
                    f"{purpose}:{body}".encode(), hashlib.sha256).hexdigest()


def _token(api_key: str, purpose: str, now) -> str:
    body = f"{int(now if now is not None else time.time())}.{secrets.token_hex(8)}"
    return f"{body}.{_mac(api_key, purpose, body)}"


def _check(api_key: str, purpose: str, value, ttl: int, now):
    """The token's timestamp when value is a genuine, unexpired token."""
    if not api_key or not isinstance(value, str) or value.count(".") != 2:
        return None
    ts, nonce, mac = value.split(".")
    if not ts.isdigit() or not hmac.compare_digest(
            mac.encode("ascii", "replace"),
            _mac(api_key, purpose, f"{ts}.{nonce}").encode()):
        return None
    now = time.time() if now is None else now
    age = now - int(ts)
    return int(ts) if -60 <= age <= ttl else None


def open_link_token(api_key: str, now=None) -> str:
    return _token(api_key, "open", now)


def redeem_link(api_key: str, token, now=None) -> bool:
    """True once per genuine link, inside LINK_TTL."""
    if _check(api_key, "open", token, LINK_TTL, now) is None:
        return False
    now = time.time() if now is None else now
    with _used_lock:
        for old in [t for t, at in _used.items() if now - at > LINK_TTL * 2]:
            del _used[old]
        if token in _used:
            return False
        _used[token] = now
    return True


def new_session(api_key: str, now=None) -> str:
    return _token(api_key, "session", now)


def session_valid(api_key: str, value, now=None) -> bool:
    return _check(api_key, "session", value, SESSION_TTL, now) is not None


def handoff_page(session: str, nonce: str) -> str:
    """The answer to a good link: store the session in this port's storage
    and go to the dashboard, replacing the link in the tab's history."""
    value = json.dumps(session).replace("</", "<\\/")
    key = json.dumps(STORAGE_KEY)
    return ('<!doctype html><meta charset="utf-8"><title>AgentalSec</title>'
            f'<script nonce="{nonce}">try {{ localStorage.setItem({key}, '
            f'{value}); }} catch (e) {{}} location.replace("/");</script>\n')


def write_opener(url: str, owner_uid=None) -> str:
    """A private page that forwards the browser to url. A browser started
    with the link itself would show it in ps to every account here."""
    run_dir = os.environ.get("XDG_RUNTIME_DIR")
    if owner_uid is not None and os.path.isdir(f"/run/user/{owner_uid}"):
        run_dir = f"/run/user/{owner_uid}"
    if not (run_dir and os.path.isdir(run_dir)):
        run_dir = None
    fd, path = tempfile.mkstemp(prefix="agentalsec-open-", suffix=".html",
                                dir=run_dir)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        u = escape(url, quote=True)
        fh.write('<!doctype html><meta charset="utf-8">'
                 f'<meta http-equiv="refresh" content="0;url={u}">'
                 f'<title>AgentalSec</title><a href="{u}">Open AgentalSec</a>\n')
    if owner_uid is not None and os.geteuid() == 0:
        import pwd
        os.chown(path, owner_uid, pwd.getpwuid(owner_uid).pw_gid)
    timer = threading.Timer(LINK_TTL, _remove, args=(path,))
    timer.daemon = True
    timer.start()
    return path


def _remove(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass
