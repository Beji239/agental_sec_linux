# modules/remote/service.py
# The Remote module's process. Started by the app only while its switch is
# on; it stops by itself when the app closes its stdin. Three threads: the
# Telegram poll, the alert check, and the tab's routes on a private socket.

import hmac
import json
import logging
import os
import re
import signal
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from bot import Bot, Feed
from store import Store, phones_match, digits
from tg_api import Telegram, TelegramError

logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                    format="%(asctime)s remote %(levelname)s %(message)s")
logger = logging.getLogger("remote")

ALERT_EVERY = int(os.environ.get("AGENTAL_REMOTE_ALERT_EVERY") or 30)
RETRY_MAX = 300

TOKEN = os.environ.get("AGENTAL_MODULE_TOKEN", "")
DATA = Path(os.environ.get("AGENTAL_MODULE_DATA", "."))
SOCKET = os.environ.get("AGENTAL_MODULE_SOCKET", str(DATA / "module.sock"))
HOST = os.environ.get("AGENTAL_MODULE_HOST", "http://127.0.0.1:5000")
BOT_TOKEN = os.environ.get("AGENTAL_REMOTE_BOT_TOKEN", "").strip()
# Tests point this at a fake Telegram on this machine.
TG_BASE = os.environ.get("AGENTAL_REMOTE_TG_BASE") or None

stopping = threading.Event()


def _clean_name(text) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()[:40]


def poll_loop(bot: Bot) -> None:
    wait = 5
    while not stopping.is_set():
        try:
            if not bot.state.get("username"):
                bot.identify()
                bot.store.event("connected", None,
                                f"Connected to Telegram as @{bot.state['username']}.")
            bot.poll_once()
            wait = 5
        except TelegramError as e:
            if e.status == 401:
                why = "Telegram refused the bot token. Check it with @BotFather."
            elif e.status == 409:
                why = ("Another program is reading this bot's messages (a second "
                       "copy, or a webhook). Only one may.")
            else:
                why = f"Telegram answered {e.status}: {e.description}"
            if bot.state.get("last_error") != why:
                bot.store.event("telegram_error", None, why)
            bot.state.update(connected=False, last_error=why)
            wait = min(RETRY_MAX, wait * 2)
        except Exception as e:                          # noqa: BLE001
            why = f"Could not reach Telegram: {type(e).__name__}"
            bot.state.update(connected=False, last_error=why)
            bot.tg.close()
            wait = min(RETRY_MAX, wait * 2)
        if wait > 5:
            stopping.wait(wait)


def alert_loop(bot: Bot) -> None:
    while not stopping.is_set():
        try:
            bot.check_alerts()
            bot.state["feed_error"] = None
        except Exception as e:                          # noqa: BLE001
            bot.state["feed_error"] = f"Could not read the app's alerts: {e}"
        stopping.wait(ALERT_EVERY)


class Routes(BaseHTTPRequestHandler):
    bot = None
    server_version = "AgentalSecRemote"

    def log_message(self, fmt, *args):
        pass

    def _reply(self, status: int, data: dict) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _allowed(self) -> bool:
        got = self.headers.get("X-Module-Token", "")
        return bool(TOKEN) and hmac.compare_digest(got.encode("utf-8", "replace"),
                                                   TOKEN.encode())

    def _body(self) -> dict:
        try:
            n = min(int(self.headers.get("Content-Length") or 0), 65536)
            data = json.loads(self.rfile.read(n) or b"{}")
            return data if isinstance(data, dict) else {}
        except ValueError:
            return {}

    def do_GET(self):
        if not self._allowed():
            return self._reply(401, {"error": "Unauthorized"})
        path, _, query = self.path.partition("?")
        args = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
        b = self.bot
        if path == "/state":
            return self._reply(200, {
                "bot": dict(b.state),
                "settings": b.store.settings(),
                "people": b.store.people(),
                "alerts": {"sent_today": int(b.store.get("sent_today") or 0)
                           if b.store.get("day") == time.strftime("%Y-%m-%d") else 0,
                           "last_sent_at": b.last_sent_at,
                           "waiting": len(b.held),
                           "quiet_now": b._in_quiet()},
            })
        if path == "/events":
            try:
                limit = int(args.get("limit", 100))
            except ValueError:
                limit = 100
            return self._reply(200, {"events": b.store.events(limit)})
        return self._reply(404, {"error": "No such route."})

    def do_POST(self):
        if not self._allowed():
            return self._reply(401, {"error": "Unauthorized"})
        b = self.bot
        body = self._body()
        path = self.path.partition("?")[0]

        if path == "/people/add":
            name, phone = _clean_name(body.get("name")), str(body.get("phone") or "").strip()
            if not name:
                return self._reply(400, {"ok": False, "reason": "Give the person a name."})
            if not 6 <= len(digits(phone)) <= 16:
                return self._reply(400, {"ok": False,
                                         "reason": "That does not look like a phone number."})
            for p in b.store.people():
                if phones_match(p["phone"], phone):
                    return self._reply(400, {"ok": False,
                                             "reason": f"{p['name']} already has that number."})
            pid, code = b.store.add_person(name, phone[:24])
            b.store.event("person_added", name, "Added at the computer; pairing code made.")
            return self._reply(200, {"ok": True, "id": pid, "code": code,
                                     "username": b.state.get("username")})

        if path == "/people/new-code":
            person = b.store.person(body.get("id") or 0)
            if not person:
                return self._reply(404, {"ok": False, "reason": "No such person."})
            if person["state"] == "paired" and person.get("chat_id"):
                b.say(person["chat_id"], "Your pairing was reset at the computer. "
                                         "Alerts stop until you pair again.")
            code = b.store.new_code(person["id"])
            b.store.event("code_made", person["name"], "New pairing code made at the computer.")
            return self._reply(200, {"ok": True, "id": person["id"], "code": code,
                                     "username": b.state.get("username")})

        if path == "/people/remove":
            person = b.store.person(body.get("id") or 0)
            if not person:
                return self._reply(404, {"ok": False, "reason": "No such person."})
            b.tell_and_remove(person, "You were removed from AgentalSec Remote at "
                                      "the computer. No more alerts will come here.")
            b.store.event("removed", person["name"], "Removed at the computer.")
            return self._reply(200, {"ok": True})

        if path == "/settings":
            changes = {}
            floor = body.get("floor")
            if floor is not None:
                if floor not in ("medium", "high", "critical"):
                    return self._reply(400, {"ok": False, "reason": "Unknown level."})
                changes["floor"] = floor
            if "quiet_on" in body:
                changes["quiet_on"] = "1" if body.get("quiet_on") else "0"
            for key in ("quiet_start", "quiet_end"):
                if key in body:
                    val = str(body.get(key) or "")
                    if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", val):
                        return self._reply(400, {"ok": False,
                                                 "reason": "Times are written like 23:00."})
                    changes[key] = val
            for key, val in changes.items():
                b.store.put(key, val)
            if changes:
                b.store.event("settings", None, "Alert choices changed: " +
                              ", ".join(f"{k} {v}" for k, v in changes.items()))
            return self._reply(200, {"ok": True, "settings": b.store.settings()})

        if path == "/test":
            result = b.send_test()
            return self._reply(200 if result.get("ok") else 400, result)

        if path == "/revoke":
            everyone = b.store.remove_everyone()
            for p in everyone:
                if p["state"] == "paired" and p.get("chat_id"):
                    b.say(p["chat_id"], "Remote access to AgentalSec was revoked at "
                                        "the computer. No more alerts will come here.",
                          {"remove_keyboard": True})
            b.store.event("revoked", None,
                          f"Remote revoked at the computer; {len(everyone)} person(s) removed.")
            return self._reply(200, {"ok": True, "removed": len(everyone)})

        return self._reply(404, {"error": "No such route."})


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main() -> int:
    DATA.mkdir(mode=0o700, parents=True, exist_ok=True)
    store = Store(DATA / "remote.db")
    tg = Telegram(BOT_TOKEN, TG_BASE) if BOT_TOKEN else None
    bot = Bot(store, tg, Feed(HOST, TOKEN))
    store.event("started", None, "Module started." if tg else
                "Module started; waiting for a bot token.")

    try:
        os.unlink(SOCKET)
    except OSError:
        pass
    old = os.umask(0o177)
    try:
        server = UnixServer(SOCKET, Routes)
    finally:
        os.umask(old)
    Routes.bot = bot

    threads = [threading.Thread(target=server.serve_forever, name="routes", daemon=True),
               threading.Thread(target=alert_loop, args=(bot,), name="alerts", daemon=True)]
    if tg:
        threads.append(threading.Thread(target=poll_loop, args=(bot,), name="poll",
                                        daemon=True))
    for t in threads:
        t.start()
    logger.info(f"Remote module running, pid {os.getpid()}")

    def on_term(sig, frame):
        stopping.set()
    signal.signal(signal.SIGTERM, on_term)

    # The app holds the other end of stdin; when it closes, we stop.
    def watch_stdin():
        try:
            while sys.stdin.buffer.read(1024):
                pass
        except (OSError, ValueError):
            pass
        stopping.set()
    threading.Thread(target=watch_stdin, name="stdin", daemon=True).start()

    stopping.wait()
    server.shutdown()
    server.server_close()
    try:
        os.unlink(SOCKET)
    except OSError:
        pass
    store.event("stopped", None, "Module stopped.")
    logger.info("Remote module stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
