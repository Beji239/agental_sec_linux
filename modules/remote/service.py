# modules/remote/service.py
# The Remote module's process. Started by the app only while its switch is
# on; it stops by itself when the app closes its stdin. Three threads: the
# Telegram poll, the alert and session check, and the tab's routes on a
# private socket.

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

import control
import qr
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
            bot.tick_sessions()
        except Exception as e:                          # noqa: BLE001
            logger.warning(f"session check failed: {e}")
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
                "control": {"available": b.box is not None,
                            "panic": b.store.get("panic") == "1",
                            "panic_by": b.store.get("panic_by"),
                            "panic_at": float(b.store.get("panic_at") or 0) or None},
                "alerts": {"sent_today": int(b.store.get("sent_today") or 0)
                           if b.store.get("day") == time.strftime("%Y-%m-%d") else 0,
                           "last_sent_at": b.last_sent_at,
                           "waiting": len(b.held),
                           "quiet_now": b._in_quiet()},
                "chat": {"on": b.store.get("chat_on") == "1",
                         "limit": b.chat_limit(),
                         "used_today": b.store.chat_used(),
                         "busy": b.chat_busy.locked()},
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
                b.say(person["chat_id"], "\U0001F504 Your pairing was reset at the computer. "
                                         "Alerts stop until you pair again.")
            code = b.store.new_code(person["id"])
            b.store.event("code_made", person["name"], "New pairing code made at the computer.")
            return self._reply(200, {"ok": True, "id": person["id"], "code": code,
                                     "username": b.state.get("username")})

        if path == "/people/remove":
            person = b.store.person(body.get("id") or 0)
            if not person:
                return self._reply(404, {"ok": False, "reason": "No such person."})
            b.tell_and_remove(person, "\U0001F6AB You were removed from AgentalSec Remote at "
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
            chat = {}
            if "chat_on" in body:
                chat["chat_on"] = "1" if body.get("chat_on") else "0"
            if "chat_limit" in body:
                try:
                    limit = int(body.get("chat_limit"))
                except (TypeError, ValueError):
                    limit = -1
                if not 1000 <= limit <= 5000000:
                    return self._reply(400, {"ok": False, "reason": "The daily allowance "
                                             "is 1,000 to 5,000,000 tokens."})
                chat["chat_limit"] = str(limit)
            for key, val in {**changes, **chat}.items():
                b.store.put(key, val)
            if changes:
                b.store.event("settings", None, "Alert choices changed: " +
                              ", ".join(f"{k} {v}" for k, v in changes.items()))
            if chat:
                b.store.event("settings", None, "Chat choices changed: " + ", ".join(
                    f"{'on' if v == '1' else 'off'}" if k == "chat_on"
                    else f"{int(v):,} tokens a day" for k, v in chat.items()))
            return self._reply(200, {"ok": True, "settings": b.store.settings()})

        if path.startswith("/control/"):
            return self._control(path, body)

        if path == "/test":
            result = b.send_test()
            return self._reply(200 if result.get("ok") else 400, result)

        if path == "/revoke":
            everyone = b.store.remove_everyone()
            for p in everyone:
                if p["state"] == "paired" and p.get("chat_id"):
                    b.say(p["chat_id"], "\U0001F6AB Remote access to AgentalSec was revoked at "
                                        "the computer. No more alerts will come here.",
                          {"remove_keyboard": True})
            b.store.event("revoked", None,
                          f"Remote revoked at the computer; {len(everyone)} person(s) removed.")
            return self._reply(200, {"ok": True, "removed": len(everyone)})

        return self._reply(404, {"error": "No such route."})


    def _control(self, path: str, body: dict):
        b = self.bot
        if path == "/control/resume":
            if b.store.get("panic") != "1":
                return self._reply(200, {"ok": True})
            b.store.put("panic", "0")
            b.store.event("resumed", None, "Control from the phone turned back on at "
                                           "the computer.")
            b._to_all(b.store.enrolled(), "\u2705 Control from the phone was turned back "
                                          "on at the computer.")
            return self._reply(200, {"ok": True})

        person = b.store.person(body.get("id") or 0)
        if not person:
            return self._reply(404, {"ok": False, "reason": "No such person."})
        chat = person.get("chat_id") if person["state"] == "paired" else None

        if path == "/control/enrol":
            if not chat:
                return self._reply(400, {"ok": False,
                                         "reason": "Pair the person first; control comes after."})
            if not b.box:
                return self._reply(400, {"ok": False,
                                         "reason": "The secrets cannot be encrypted here: the "
                                                   "cryptography package is missing."})
            pin, pin2 = str(body.get("pin") or ""), str(body.get("pin2") or "")
            word = str(body.get("word") or "")
            why = control.pin_problem(pin)
            if not why and pin != pin2:
                why = "The two PINs are not the same."
            why = why or control.word_problem(word, pin)
            if why:
                return self._reply(400, {"ok": False, "reason": why})
            secret = control.new_totp_secret()
            b.store.enrol_start(person["id"], control.hash_pin(pin),
                                control.hash_word(word), b.box.seal(secret))
            b.challenges.pop(person["tg_user_id"], None)
            b.store.event("enrol_started", person["name"],
                          "PIN and panic word set at the computer; waiting for the "
                          "authenticator's first code.")
            uri = control.otpauth_uri(person["name"], secret)
            return self._reply(200, {"ok": True, "key": control.spaced(secret),
                                     "svg": qr.svg(uri, 5)})

        if path == "/control/confirm":
            sealed = b.store.person(person["id"]).get("totp_pending")
            if not sealed or not b.box:
                return self._reply(400, {"ok": False, "reason": "Start the setup again."})
            try:
                secret = b.box.open(sealed)
            except Exception:                           # noqa: BLE001
                return self._reply(400, {"ok": False, "reason": "Start the setup again."})
            step = control.code_step(secret, str(body.get("code") or ""))
            if step is None:
                return self._reply(400, {"ok": False,
                                         "reason": "That code does not match. Check that the "
                                                   "phone's clock is set automatically, and "
                                                   "type the code the app shows now."})
            b.store.enrol_finish(person["id"], step)
            b.store.event("enrolled", person["name"], "Control from the phone set up.")
            if chat:
                b.say(chat, "\U0001F510 <b>Control from the phone is set up</b> for you. "
                            "When a decision waits, press <b>Take control</b> or send "
                            "/control; it asks for your PIN and the code from your "
                            "authenticator app. Your panic word, sent here any time, turns "
                            "control off for everyone.", {"inline_keyboard": [
                                [{"text": "Take control", "callback_data": "ctl"}]]})
            return self._reply(200, {"ok": True})

        if path == "/control/remove":
            b.store.clear_control(person["id"])
            b.challenges.pop(person["tg_user_id"], None)
            b.awaiting.pop(person["tg_user_id"], None)
            b.store.event("control_removed", person["name"],
                          "Control from the phone removed at the computer.")
            if chat:
                b.say(chat, "\U0001F510 Control from the phone was removed for you at the "
                            "computer. Alerts still come.")
            return self._reply(200, {"ok": True})

        if path == "/control/unlock":
            b.store.unlock(person["id"])
            b.store.event("unlocked", person["name"], "Control unlocked at the computer.")
            if chat:
                b.say(chat, "\U0001F513 Control was unlocked for you at the computer.")
            return self._reply(200, {"ok": True})

        return self._reply(404, {"error": "No such route."})


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main() -> int:
    DATA.mkdir(mode=0o700, parents=True, exist_ok=True)
    store = Store(DATA / "remote.db")
    tg = Telegram(BOT_TOKEN, TG_BASE) if BOT_TOKEN else None
    try:
        box = control.SecretBox(DATA)
    except Exception as e:                              # noqa: BLE001
        logger.warning(f"control secrets cannot be encrypted: {e}")
        box = None
    bot = Bot(store, tg, Feed(HOST, TOKEN), box)
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
