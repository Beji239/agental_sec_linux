# modules/remote/bot.py
# What the bot does with a message, and how alerts go out. Only paired
# people get answers; everyone else is ignored and written to the history.
# Deciding and chatting with the agent need a control session: PIN plus
# authenticator code, 30 minutes. With private messages set up, details go
# sealed behind a Read button (reader.py).

import hashlib
import html
import http.client
import json
import logging
import re
import threading
import time
import urllib.parse
from datetime import datetime, timezone

import control
import reader
from store import clean_code, phones_match, CODE_LEN, CODE_ALPHABET
from tg_api import TelegramError

logger = logging.getLogger("remote")

RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
STRANGER_LOG_GAP = 3600
STRANGERS_LOGGED_PER_HOUR = 20
BAD_CODE_LIMIT = 5
BAD_CODE_BLOCK = 3600
SESSION_SECONDS = 30 * 60
WARN_BEFORE = 5 * 60
CONFIRM_SECONDS = 120
ANSWER_SECONDS = 10 * 60
BAD_TRY_LIMIT = 3
CHAT_TIMEOUT = 360
CHAT_IDLE = 30 * 60
CHAT_KEPT = 8

DOT = {"critical": "\U0001F534", "high": "\U0001F7E0", "medium": "\U0001F7E1",
       "low": "\u26AA", "info": "\u26AA"}
SHIELD = "\U0001F6E1"

VIEW_ROW = [{"text": "Status", "callback_data": "status"},
            {"text": "What's waiting", "callback_data": "pending"}]
VIEW_BUTTONS = {"inline_keyboard": [VIEW_ROW]}
CONTROL_BUTTONS = {"inline_keyboard": [VIEW_ROW, [{"text": "Take control",
                                                   "callback_data": "ctl"}]]}
SESSION_BUTTONS = {"inline_keyboard": [[{"text": "What's waiting", "callback_data": "pending"},
                                        {"text": "End session", "callback_data": "end"}],
                                       [{"text": "Checks", "callback_data": "checks"}]]}

# Ready-made questions for the agent. Each one is a chat turn and uses tokens.
CHECKS = {
    "sensors": ("Sensors", "Are all the sensors running and healthy? Name any that "
                           "are not, and why, in a few lines."),
    "incidents": ("Open incidents", "Go through the open incidents, worst first. One "
                                    "line each: what it is and whether it needs me."),
    "devices": ("Devices", "Are there devices on the network nobody has named, or new "
                           "ones since yesterday? List them briefly."),
    "ports": ("Listening ports", "What on this computer listens for connections, and "
                                 "which program holds each port? Point out anything "
                                 "unusual."),
    "router": ("Router", "How is the router doing, and did it see anything today that "
                         "needs my attention?"),
}
CHECK_BUTTONS = {"inline_keyboard": [
    [{"text": CHECKS["sensors"][0], "callback_data": "k:sensors"},
     {"text": CHECKS["incidents"][0], "callback_data": "k:incidents"}],
    [{"text": CHECKS["devices"][0], "callback_data": "k:devices"},
     {"text": CHECKS["ports"][0], "callback_data": "k:ports"}],
    [{"text": CHECKS["router"][0], "callback_data": "k:router"}]]}

COMMANDS = [{"command": "status", "description": "How the computer is doing"},
            {"command": "pending", "description": "What waits for your decision"},
            {"command": "control", "description": "Take control for 30 minutes"},
            {"command": "done", "description": "End the control session"},
            {"command": "check", "description": "Ready-made checks by the agent"},
            {"command": "new", "description": "Start a fresh chat with the agent"},
            {"command": "help", "description": "What this bot can do"}]
DESCRIPTION = ("Alerts from AgentalSec, the security app on your computer. "
               "Only people paired at the computer get answers.")
SHORT_DESCRIPTION = "Alerts from AgentalSec on your computer."

HELP = (f"{SHIELD} <b>AgentalSec Remote</b>\n"
        "Urgent alerts from your computer come here.\n\n"
        "/status  how the computer is doing\n"
        "/pending  what waits for your decision\n"
        "/control  take control for 30 minutes (PIN and authenticator code)\n"
        "/done  end the control session\n"
        "/check  ready-made checks by the agent\n"
        "/new  start a fresh chat with the agent\n"
        "/help  this list\n\n"
        "Inside a control session, anything you write goes to the agent, "
        "if chat is turned on at the computer.\n\n"
        "<i>Deciding and chatting need control, set up at the computer in the "
        "Remote tab. Your panic word turns control off for everyone.</i>")


def e(text) -> str:
    """Outside text made safe for Telegram's HTML."""
    return html.escape(str(text if text is not None else ""), quote=False)


def _short_time(stamp) -> str:
    """The app stores UTC; the phone shows this computer's local time."""
    if not stamp:
        return "unknown"
    text = str(stamp).strip().replace("T", " ").rstrip("Z")[:19]
    try:
        when = datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc).astimezone()
    except ValueError:
        return text[:16]
    if when.date() == datetime.now().astimezone().date():
        return when.strftime("%H:%M")
    return when.strftime("%b %d, %H:%M")


def _dot(severity) -> str:
    return DOT.get(str(severity or "").lower(), "\u26AA")


def _mac_ref(mac: str) -> str:
    return hashlib.sha256(str(mac).lower().encode()).hexdigest()[:12]


def _plain(text: str) -> str:
    """Telegram HTML back to plain text, for sealing."""
    return html.unescape(re.sub(r"<[^>]+>", "", str(text or "")))


def phone_html(text: str) -> str:
    """The agent's answer for Telegram: escaped, with its **bold** and
    `code` kept."""
    out = e(text)
    out = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", out)
    out = re.sub(r"`([^`\n]+)`", r"<code>\1</code>", out)
    return out


class Feed:
    """The app's module feed on this machine, with this run's token."""

    def __init__(self, base: str, token: str):
        url = urllib.parse.urlsplit(base)
        if url.scheme != "http" or not url.hostname:
            raise ValueError(f"the app's address is not plain http: {base!r}")
        self.host, self.port = url.hostname, url.port or 80
        self.token = token

    def get(self, path: str, params: dict = None) -> dict:
        query = ""
        if params:
            query = "?" + urllib.parse.urlencode(
                {k: v for k, v in params.items() if v is not None})
        conn = http.client.HTTPConnection(self.host, self.port, timeout=15)
        try:
            conn.request("GET", f"/api/module-feed/{path}{query}",
                         headers={"X-Module-Token": self.token})
            resp = conn.getresponse()
            body = resp.read()
            if resp.status != 200:
                raise RuntimeError(f"the app answered {resp.status}")
            return json.loads(body or b"{}")
        finally:
            conn.close()

    def post(self, path: str, body: dict, timeout: float = 30) -> tuple:
        """(status, json). A refusal is an answer, not an error."""
        conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        try:
            conn.request("POST", f"/api/module-feed/{path}", body=json.dumps(body),
                         headers={"X-Module-Token": self.token,
                                  "Content-Type": "application/json"})
            resp = conn.getresponse()
            raw = resp.read()
            try:
                return resp.status, json.loads(raw or b"{}")
            except ValueError:
                return resp.status, {"detail": "the app answered something that is not JSON"}
        finally:
            conn.close()


class Bot:
    def __init__(self, store, telegram, feed, box=None):
        self.store = store
        self.tg = telegram
        self.feed = feed
        self.box = box
        # A PIN and code being asked for, and a typed answer being waited
        # for, by Telegram user id. Kept in memory: a restart just asks again.
        self.challenges = {}
        self.awaiting = {}
        # Chat with the agent: recent turns by Telegram user id, a question
        # waiting for control to open, and one turn at a time.
        self.chats = {}
        self.chat_waiting = {}
        self.chat_busy = threading.Lock()
        self.state = {"connected": False, "username": None, "last_ok_at": None,
                      "last_error": None, "token_present": telegram is not None,
                      "started_at": time.time()}
        self.held = []
        self.last_sent_at = None

    # Telegram side

    def say(self, chat_id: int, text: str, markup: dict = None) -> bool:
        """One message, in Telegram's HTML; callers escape outside text."""
        if not self.tg:
            return False
        try:
            self.tg.send(chat_id, text, markup)
            return True
        except TelegramError as e:
            self.store.event("send_failed", None, f"Telegram refused a message: {e.description}")
        except Exception as e:                          # noqa: BLE001
            self.store.event("send_failed", None, f"Could not reach Telegram: {e}")
        return False

    def handle(self, update: dict) -> None:
        if update.get("callback_query"):
            self._button(update["callback_query"])
            return
        msg = update.get("message") or {}
        sender = msg.get("from") or {}
        chat = msg.get("chat") or {}
        user_id = sender.get("id")
        if not user_id or sender.get("is_bot"):
            return
        if chat.get("type") != "private":
            self._stranger(sender, "wrote from a group, which the bot ignores")
            return

        person = self.store.by_user(user_id)
        if person:
            self._message(person, msg)
            return

        row = self.store.stranger(user_id)
        if row.get("blocked_until") and row["blocked_until"] > time.time():
            return

        if msg.get("contact"):
            self._contact(sender, chat["id"], msg["contact"])
            return

        text = (msg.get("text") or "").strip()
        if text.startswith("/start"):
            text = text[len("/start"):].strip()
        code = clean_code(text)
        if len(code) == CODE_LEN and all(c in CODE_ALPHABET for c in code):
            self._code(sender, chat["id"], code, row)
            return
        self._stranger(sender, "sent a message and is not paired")

    def _button(self, query: dict) -> None:
        sender = query.get("from") or {}
        chat = (query.get("message") or {}).get("chat") or {}
        try:
            self.tg.answer_button(query.get("id"))
        except Exception:                               # noqa: BLE001
            logger.debug("button answer failed")
        person = self.store.by_user(sender.get("id") or 0)
        if person and not chat.get("id"):
            return
        if not person or chat.get("type") != "private":
            if sender.get("id"):
                self._stranger(sender, "pressed a button and is not paired")
            return
        data = str(query.get("data") or "")
        if data == "status":
            self.private(person, chat["id"], self._status_text(), "<b>Status</b>",
                         "Status", self._buttons(person), "status")
        elif data == "pending":
            self._pending(person, chat["id"])
        elif data == "ctl":
            self._take_control(person, chat["id"], "pending")
        elif data == "ctlc":
            self._take_control(person, chat["id"], "chat")
        elif data == "checks":
            self._checks_menu(person, chat["id"])
        elif data.startswith("k:") and data[2:] in CHECKS:
            label, question = CHECKS[data[2:]]
            self._chat(person, chat["id"], question, label)
        elif data == "end":
            self._end_session(person, chat["id"])
        elif data[:2] in ("a:", "q:", "v:", "r:"):
            self._decision(person, chat["id"], data)

    def _name_of(self, sender: dict) -> str:
        name = " ".join(p for p in (sender.get("first_name"), sender.get("last_name")) if p)
        handle = f" @{sender['username']}" if sender.get("username") else ""
        return f"{name or 'no name'}{handle} (Telegram id {sender.get('id')})"

    def _stranger(self, sender: dict, what: str) -> None:
        row = self.store.stranger(sender["id"])
        now = time.time()
        if not row.get("last_logged") or now - row["last_logged"] > STRANGER_LOG_GAP:
            row["last_logged"] = now
            self.store.save_stranger(row)
            # Many strangers at once must not push real history out of the log.
            hour = time.strftime("%Y-%m-%d %H")
            if self.store.get("stranger_hour") != hour:
                self.store.put("stranger_hour", hour)
                self.store.put("stranger_count", 0)
            count = int(self.store.get("stranger_count") or 0) + 1
            self.store.put("stranger_count", count)
            if count <= STRANGERS_LOGGED_PER_HOUR:
                self.store.event("stranger", self._name_of(sender), f"Ignored: {what}.")
            elif count == STRANGERS_LOGGED_PER_HOUR + 1:
                self.store.event("stranger", None,
                                 f"More than {STRANGERS_LOGGED_PER_HOUR} strangers wrote "
                                 f"to the bot this hour; the rest are ignored without "
                                 f"being listed one by one.")

    def _code(self, sender: dict, chat_id: int, code: str, row: dict) -> None:
        person = self.store.match_code(code)
        if not person:
            row["bad_codes"] = int(row.get("bad_codes") or 0) + 1
            if row["bad_codes"] >= BAD_CODE_LIMIT:
                row["blocked_until"] = time.time() + BAD_CODE_BLOCK
                row["bad_codes"] = 0
                self.store.event("code_refused", self._name_of(sender),
                                 f"{BAD_CODE_LIMIT} wrong pairing codes; ignored for an hour.")
            else:
                self.store.event("code_refused", self._name_of(sender),
                                 "Sent a pairing code that is wrong or has run out.")
            self.store.save_stranger(row)
            return
        if person["pairing_user_id"] and person["pairing_user_id"] != sender["id"] \
                and person["pairing_until"] and person["pairing_until"] > time.time():
            self.store.event("code_refused", self._name_of(sender),
                             f"Sent {person['name']}'s code while someone else "
                             f"was already using it.")
            return
        self.store.start_pairing(person["id"], sender["id"])
        self.store.event("code_used", person["name"],
                         f"Code sent by {self._name_of(sender)}; waiting for the phone number.")
        self.say(chat_id,
                 f"\U0001F44B Hello <b>{e(person['name'])}</b>.\n"
                 f"To finish pairing, press <b>Share my phone number</b> below to "
                 f"share your phone number. It has to be the number entered at "
                 f"the computer.",
                 {"keyboard": [[{"text": "Share my phone number",
                                 "request_contact": True}]],
                  "one_time_keyboard": True, "resize_keyboard": True})

    def _contact(self, sender: dict, chat_id: int, contact: dict) -> None:
        person = self.store.pairing_for(sender["id"])
        if not person:
            self._stranger(sender, "shared a phone number without a pairing code")
            return
        remove = {"remove_keyboard": True}
        if contact.get("user_id") != sender["id"]:
            self.store.event("phone_refused", person["name"],
                             "Shared someone else's contact, not their own. "
                             "The code still works for a few minutes.")
            self.say(chat_id, "\u26A0\uFE0F That is someone else's contact. Use the "
                              "button to share your own number.")
            return
        if not phones_match(person["phone"], contact.get("phone_number", "")):
            self.store.burn_code(person["id"])
            self.store.event("phone_refused", person["name"],
                             f"Shared a number that does not match the one entered "
                             f"({self._name_of(sender)}). The code is spent.")
            self.say(chat_id, "\u26D4 That number does not match the one entered at "
                              "the computer, so pairing stopped. Ask for a new code there.",
                     remove)
            return
        self.store.finish_pairing(person["id"], sender["id"], chat_id,
                                  sender.get("username"))
        self.store.event("paired", person["name"], f"Paired as {self._name_of(sender)}.")
        self.say(chat_id,
                 "\u2705 <b>Paired.</b> Urgent alerts from AgentalSec will come here.\n\n"
                 "\U0001F510 Please turn on Telegram's <b>Two-Step Verification</b> "
                 "(Settings, Privacy and Security), so nobody can take this account "
                 "with an SMS code.\n\n" + HELP, remove)
        self.say(chat_id, "Tap a button any time:", VIEW_BUTTONS)

    def _message(self, person: dict, msg: dict) -> None:
        chat_id = msg["chat"]["id"]
        text = (msg.get("text") or "").strip()
        cmd = text.split()[0].lower().split("@")[0] if text.startswith("/") else ""
        uid = person["tg_user_id"]

        if not cmd and not text.isdigit() and person.get("word_hash") \
                and control.word_ok(text, person["word_hash"]):
            self._forget(chat_id, msg)
            self._panic(person)
            return
        if uid in self.challenges and not cmd:
            self._forget(chat_id, msg)
            if not text:
                self.say(chat_id, "Send the PIN or the code as a message; nothing else "
                                  "counts here, and nothing was counted.")
                return
            self._answer_challenge(person, chat_id, text)
            return
        self.challenges.pop(uid, None)
        if uid in self.awaiting and not cmd and text:
            self._typed_answer(person, chat_id, text)
            return
        self.awaiting.pop(uid, None)

        if cmd == "/status":
            self.private(person, chat_id, self._status_text(), "<b>Status</b>",
                         "Status", self._buttons(person), "status")
        elif cmd == "/pending":
            self._pending(person, chat_id)
        elif cmd == "/control":
            self._take_control(person, chat_id, "pending")
        elif cmd == "/done":
            self._end_session(person, chat_id)
        elif cmd == "/check":
            self._checks_menu(person, chat_id)
        elif cmd == "/new":
            self.chats.pop(uid, None)
            self.say(chat_id, "\U0001F4AC Fresh chat. The agent no longer sees the earlier "
                              "messages.", self._buttons(person))
        elif cmd == "/cancel":
            self.say(chat_id, "Nothing is waiting for you to type now.", self._buttons(person))
        elif cmd in ("/help", "/start"):
            self.say(chat_id, HELP, self._buttons(person))
        elif cmd or not text:
            self.say(chat_id, "I know /status, /pending, /control, /done, /check, /new "
                              "and /help.", self._buttons(person))
        elif re.fullmatch(r"[\d\s]{4,16}", text):
            # A PIN or code typed when nothing asked for one never reaches the model.
            self._forget(chat_id, msg)
            self.say(chat_id, "That looked like a PIN or a code, and nothing was asking "
                              "for one, so I deleted it.", self._buttons(person))
        else:
            self._chat(person, chat_id, text)

    def _buttons(self, person: dict) -> dict:
        return SESSION_BUTTONS if self._in_session(person) else CONTROL_BUTTONS

    def _status_text(self) -> str:
        try:
            s = self.feed.get("status")
        except Exception as ex:                         # noqa: BLE001
            return f"\u26A0\uFE0F Could not read the app's status: {e(ex)}"
        inc = s.get("incidents") or {}
        acts, qs = s.get("actions_waiting", 0), s.get("questions_open", 0)
        lines = [f"{SHIELD} <b>AgentalSec {e(s.get('version') or '')}</b>".strip(), "",
                 f"Open incidents: <b>{e(inc.get('open', 'unknown'))}</b>"
                 f" ({e(inc.get('new', 0))} nobody looked at yet)",
                 f"Waiting for you: <b>{e(acts)}</b> action(s), <b>{e(qs)}</b> question(s)",
                 f"Devices held: <b>{e(s.get('devices_held', 0))}</b>"]
        worst = s.get("worst_open") or []
        lines.append("")
        if worst:
            lines.append("<b>Worst open</b>")
            for w in worst:
                lines.append(f"{_dot(w.get('severity'))} {e(w.get('title'))}")
        else:
            lines.append("\u2705 Nothing open.")
        if s.get("last_incident_at"):
            lines.append(f"\n<i>Last incident activity {e(_short_time(s['last_incident_at']))}</i>")
        return "\n".join(lines)

    def _pending_text(self, p: dict = None) -> str:
        try:
            p = p if p is not None else self.feed.get("pending")
        except Exception as ex:                         # noqa: BLE001
            return f"\u26A0\uFE0F Could not read the open decisions: {e(ex)}"
        parts = []
        if p.get("actions"):
            parts.append("<b>Actions</b>")
            parts += [f"\u2022 #{e(a['id'])} {e(a['what'])}" for a in p["actions"]]
        if p.get("questions"):
            parts.append("<b>Questions</b>")
            parts += [f"\u2022 #{e(q['id'])} {e(q['question'][:300])}" for q in p["questions"]]
        if p.get("devices"):
            parts.append("<b>Held devices</b>")
            parts += [f"\u2022 {e(d.get('hostname') or d.get('vendor') or 'a device')} "
                      f"<code>{e(d.get('ip') or d.get('mac') or '')}</code>" for d in p["devices"]]
        if not parts:
            return "\u2705 Nothing is waiting for a decision."
        return ("\U0001F4CB <b>Waiting for your decision</b>\n\n" + "\n".join(parts)
                + "\n\n<i>Press Decide now; it asks for your PIN and code first.</i>")

    # Polling Telegram

    def poll_once(self) -> None:
        offset = self.store.get("tg_offset")
        updates = self.tg.get_updates(int(offset) if offset else None)
        self.state.update(connected=True, last_ok_at=time.time(), last_error=None)
        for up in updates or []:
            self.store.put("tg_offset", int(up["update_id"]) + 1)
            try:
                self.handle(up)
            except Exception as e:                      # noqa: BLE001
                logger.exception("message handling failed")
                self.store.event("error", None, f"A message could not be handled: {e}")

    def identify(self) -> bool:
        me = self.tg.get_me()
        self.state.update(username=me.get("username"), connected=True,
                          last_ok_at=time.time(), last_error=None)
        # The command menu and the text in an empty chat. Not needed to work.
        try:
            self.tg.call("setMyCommands", {"commands": COMMANDS})
            self.tg.call("setMyDescription", {"description": DESCRIPTION})
            self.tg.call("setMyShortDescription", {"short_description": SHORT_DESCRIPTION})
        except Exception as ex:                         # noqa: BLE001
            logger.warning(f"bot menu and description not set: {ex}")
        return True

    # Alerts

    def _in_quiet(self, now: datetime = None) -> bool:
        if self.store.get("quiet_on") != "1":
            return False
        now = now or datetime.now()

        def minutes(text):
            h, m = (int(x) for x in str(text).split(":"))
            return h * 60 + m
        try:
            start, end = minutes(self.store.get("quiet_start")), minutes(self.store.get("quiet_end"))
        except (TypeError, ValueError):
            return False
        cur = now.hour * 60 + now.minute
        if start == end:
            return False
        return start <= cur < end if start < end else (cur >= start or cur < end)

    def check_alerts(self) -> None:
        floor = self.store.get("floor") or "high"
        cursor = self.store.get("alert_cursor")
        if cursor is None:
            first = self.feed.get("alerts", {"floor": floor})
            self.store.put("alert_cursor", first.get("max_id") or 0)
            self.store.put("alert_baseline", first.get("max_id") or 0)
            self.store.put("alert_since", first.get("max_seen") or "")
            return
        data = self.feed.get("alerts", {"after": cursor, "floor": floor,
                                        "since": self.store.get("alert_since") or None})
        baseline = int(self.store.get("alert_baseline") or 0)
        for inc in data.get("incidents") or []:
            rank = int(inc.get("severity_rank") or RANK.get(inc.get("severity"), 0))
            before = self.store.sent_rank(inc["id"])
            if before is not None and before >= rank:
                continue
            if before is None and inc["id"] <= baseline:
                # Open before Remote was on: noted, sent only if it rises later.
                self.store.mark_sent(inc["id"], rank, silent=True)
                continue
            self.store.mark_sent(inc["id"], rank)
            self.held.append(dict(inc, raised=before is not None or
                                  inc["id"] <= int(cursor)))
        self.store.put("alert_cursor", data.get("max_id") or cursor)
        if data.get("max_seen"):
            self.store.put("alert_since", data["max_seen"])
        self.flush()

    def _today_count(self) -> int:
        today = datetime.now().date().isoformat()
        if self.store.get("day") != today:
            self.store.put("day", today)
            self.store.put("sent_today", 0)
            self.store.put("cap_noticed", 0)
        return int(self.store.get("sent_today") or 0)

    def flush(self) -> None:
        if not self.held:
            return
        quiet = self._in_quiet()
        if quiet and not any(i.get("severity") == "critical" for i in self.held):
            return
        try:
            gap = int(self.store.get("gap_minutes") or 10) * 60
        except ValueError:
            gap = 600
        if self.last_sent_at and time.time() - self.last_sent_at < gap \
                and not any(i.get("severity") == "critical" for i in self.held):
            return
        people = self.store.paired()
        if not people:
            self.held = []
            return
        sent_today = self._today_count()
        try:
            cap = int(self.store.get("daily_cap") or 20)
        except ValueError:
            cap = 20
        batch, self.held = self.held, []
        if sent_today >= cap:
            if self.store.get("cap_noticed") != "1":
                self.store.put("cap_noticed", 1)
                self._to_all(people, f"\u23F8 <b>{cap} alerts were sent today.</b> "
                                     f"Further ones are on the computer only, "
                                     f"until tomorrow.")
            self.store.event("alert_held", None,
                             f"{len(batch)} alert(s) not sent: the daily cap of {cap} was reached.")
            return
        text = self._alert_text(batch)
        if len(batch) == 1:
            iid = batch[0]["id"]
            markup = {"inline_keyboard": [
                [{"text": "False alarm", "callback_data": f"v:{iid}:fa"},
                 {"text": "Real", "callback_data": f"v:{iid}:real"},
                 {"text": "Not sure", "callback_data": f"v:{iid}:ns"}], VIEW_ROW]}
        else:
            markup = CONTROL_BUTTONS
        head = self._alert_head(batch)
        sent = False
        for p in people:
            sent = self.private(p, p["chat_id"], text, head, _plain(head), markup,
                                "alert") or sent
        if sent:
            self.last_sent_at = time.time()
            self.store.put("sent_today", sent_today + 1)
            self.store.event("alert_sent", None,
                             f"{len(batch)} alert(s) to {len(people)} person(s): "
                             f"{batch[0].get('title')}"[:400])

    def _alert_head(self, batch: list) -> str:
        """What a sealed alert shows in the clear: how urgent, not what."""
        if len(batch) == 1:
            i = batch[0]
            sev = str(i.get("severity") or "").upper()
            head = f"Raised to {sev}" if i.get("raised") else f"{sev}: new incident"
            return f"{_dot(i.get('severity'))} <b>{e(head)}</b>"
        return f"\U0001F6A8 <b>{len(batch)} urgent incidents</b>"

    def _alert_text(self, batch: list) -> str:
        if len(batch) == 1:
            i = batch[0]
            sev = str(i.get("severity") or "").upper()
            head = f"Raised to {sev}" if i.get("raised") else f"{sev}: new incident"
            return (f"{_dot(i.get('severity'))} <b>{e(head)}</b>\n"
                    f"{e(i.get('title'))}\n"
                    f"{e(i.get('entity_type'))} <code>{e(i.get('entity_value'))}</code>\n"
                    f"<i>Seen {e(_short_time(i.get('last_seen_at')))}</i>")
        lines = [f"\U0001F6A8 <b>{len(batch)} urgent incidents</b>"]
        for i in batch[:6]:
            lines.append(f"{_dot(i.get('severity'))} {e(i.get('title'))}")
        if len(batch) > 6:
            lines.append(f"<i>{len(batch) - 6} more on the computer</i>")
        return "\n".join(lines)

    def _to_all(self, people: list, text: str, markup: dict = None) -> bool:
        ok = False
        for p in people:
            ok = self.say(p["chat_id"], text, markup) or ok
        return ok

    def send_test(self) -> dict:
        people = self.store.paired()
        if not people:
            return {"ok": False, "reason": "Nobody is paired yet."}
        if not self.tg:
            return {"ok": False, "reason": "There is no bot token yet."}
        n = sum(1 for p in people if self.say(
            p["chat_id"], "\u2705 <b>Test message</b> from the computer. Alerts reach "
                          "you here.", VIEW_BUTTONS))
        self.store.event("test_sent", None, f"Test message reached {n} of {len(people)}.")
        return {"ok": n > 0, "reached": n, "of": len(people)}

    def tell_and_remove(self, person: dict, why: str) -> None:
        if person.get("state") == "paired" and person.get("chat_id"):
            self.say(person["chat_id"], why, {"remove_keyboard": True})
        self.store.remove_person(person["id"])

    # Control from the phone

    def _in_session(self, person: dict) -> bool:
        until = person.get("session_until")
        return bool(until and until > time.time() and not person.get("locked_at")
                    and self.store.get("panic") != "1")

    def _forget(self, chat_id: int, msg: dict) -> None:
        """A PIN, code or panic word does not stay in the chat."""
        if not self.tg or not msg.get("message_id"):
            return
        try:
            self.tg.delete(chat_id, msg["message_id"])
        except Exception:                               # noqa: BLE001
            logger.debug("message not deleted")

    def _secret(self, person: dict) -> str | None:
        if not self.box or not person.get("totp_sealed"):
            return None
        try:
            return self.box.open(person["totp_sealed"])
        except Exception:                               # noqa: BLE001
            return None

    def _cannot_control(self, person: dict) -> str | None:
        if self.store.get("panic") == "1":
            return ("\U0001F6D1 Control from the phone is off since the panic word. "
                    "It can be turned back on at the computer, in the Remote tab.")
        if not person.get("enrolled_at"):
            return ("\U0001F510 Control needs a PIN and an authenticator app, set up at "
                    "the computer in the Remote tab. Until then alerts and /status work.")
        if person.get("locked_at"):
            return ("\U0001F512 Control is locked for you after wrong tries. It can be "
                    "unlocked at the computer. Alerts still come.")
        if not self._secret(person):
            return ("⚠️ Your authenticator could not be read on this computer. "
                    "Set control up again in the Remote tab.")
        return None

    def _take_control(self, person: dict, chat_id: int, then: str = "pending") -> None:
        why = self._cannot_control(person)
        if why:
            self.say(chat_id, why, VIEW_BUTTONS)
            return
        if self._in_session(person):
            self._after_control(person, chat_id, then)
            return
        self._ask(person, chat_id, "session", then)

    def _ask(self, person: dict, chat_id: int, purpose: str, then: str) -> None:
        """Only ever after the person pressed a button or sent a command."""
        self.awaiting.pop(person["tg_user_id"], None)
        self.challenges[person["tg_user_id"]] = {
            "purpose": purpose, "step": "pin", "then": then,
            "expires": time.time() + CONFIRM_SECONDS}
        self.say(chat_id, "\U0001F510 Send your <b>PIN</b>. I delete it from the chat "
                          "once read. This runs out in 2 minutes.")

    def _answer_challenge(self, person: dict, chat_id: int, text: str) -> None:
        uid = person["tg_user_id"]
        ch = self.challenges.get(uid)
        if not ch or ch["expires"] < time.time():
            self.challenges.pop(uid, None)
            self.say(chat_id, "⌛ That confirmation ran out. Nothing was decided; "
                              "press the button again for a fresh one.", self._buttons(person))
            return
        why = self._cannot_control(person)
        if why:
            self.challenges.pop(uid, None)
            self.say(chat_id, why, VIEW_BUTTONS)
            return
        if ch["step"] == "pin":
            if not control.pin_ok(text, person["pin_hash"]):
                self._bad_try(person, chat_id, "PIN")
                return
            ch.update(step="code", expires=time.time() + CONFIRM_SECONDS)
            self.say(chat_id, "Now the <b>6-digit code</b> from your authenticator app.")
            return
        secret = self._secret(person)
        step = control.code_step(secret, text, person.get("last_step") or 0)
        if step is None:
            if control.code_step(secret, text, 0) is not None:
                self.say(chat_id, "That code was already used. Each code works once; "
                                  "send the next one when your app shows it.")
                return
            self._bad_try(person, chat_id, "code")
            return
        self.store.used_step(person["id"], step)
        self.challenges.pop(uid, None)
        person = self.store.person(person["id"])
        if ch["purpose"] == "session":
            until = time.time() + SESSION_SECONDS
            self.store.open_session(person["id"], until)
            self.store.event("control_on", person["name"], "Took control from the phone "
                             f"until {time.strftime('%H:%M', time.localtime(until))}.")
            self.say(chat_id, f"✅ <b>Control is on</b> until "
                              f"{time.strftime('%H:%M', time.localtime(until))}. Questions "
                              f"and decisions work with one tap now.", SESSION_BUTTONS)
            self._after_control(self.store.person(person["id"]), chat_id, ch["then"])
        else:
            self._decide(person, chat_id, ch["then"], confirmed=True)

    def _bad_try(self, person: dict, chat_id: int, what: str) -> None:
        tries = self.store.bad_try(person["id"])
        self.store.event("control_refused", person["name"],
                         f"Wrong {what} from the phone ({tries} of {BAD_TRY_LIMIT}).")
        if tries < BAD_TRY_LIMIT:
            left = BAD_TRY_LIMIT - tries
            self.say(chat_id, f"⛔ Wrong {e(what)}. {left} {'try' if left == 1 else 'tries'} "
                              f"left before control locks.")
            return
        self.challenges.pop(person["tg_user_id"], None)
        self.awaiting.pop(person["tg_user_id"], None)
        self.store.lock(person["id"])
        self.store.event("locked", person["name"],
                         f"{BAD_TRY_LIMIT} wrong tries; control locked until unlocked "
                         f"at the computer.")
        self.say(chat_id, "\U0001F512 <b>Control is locked</b> for you after "
                          f"{BAD_TRY_LIMIT} wrong tries. Alerts still come. It can be "
                          "unlocked at the computer.", VIEW_BUTTONS)
        for p in self.store.enrolled():
            if p["id"] != person["id"]:
                self.say(p["chat_id"], f"⚠️ Control for <b>{e(person['name'])}</b> "
                                       f"was locked after {BAD_TRY_LIMIT} wrong PIN or code "
                                       f"tries. If that was not them, revoke at the computer.")

    def _end_session(self, person: dict, chat_id: int) -> None:
        self.challenges.pop(person["tg_user_id"], None)
        self.awaiting.pop(person["tg_user_id"], None)
        if not person.get("session_until"):
            self.say(chat_id, "No control session is open.", self._buttons(person))
            return
        self.store.end_session(person["id"])
        self._forget_chat(person["tg_user_id"])
        self.store.event("control_off", person["name"], "Ended the control session.")
        self.say(chat_id, "\U0001F44C Control session ended. Anything undecided stays held.",
                 CONTROL_BUTTONS)

    def tick_sessions(self) -> None:
        """Ends sessions that ran out, with a notice 5 minutes before."""
        now = time.time()
        for p in self.store.sessions():
            left = p["session_until"] - now
            if left <= 0:
                self.store.end_session(p["id"])
                self._forget_chat(p["tg_user_id"])
                self.store.event("control_off", p["name"], "The 30 minute session ran out.")
                self.say(p["chat_id"], "⏱ Control session ended. Anything undecided "
                                       "stays held; /pending brings it back.", CONTROL_BUTTONS)
            elif left <= WARN_BEFORE and not p["session_warned"]:
                self.store.warned(p["id"])
                self.say(p["chat_id"], f"⏳ Control ends in {max(1, round(left / 60))} "
                                       f"minutes.", SESSION_BUTTONS)
        for uid, ch in list(self.challenges.items()):
            if ch["expires"] < now - 600:
                self.challenges.pop(uid, None)
        for uid, wait in list(self.awaiting.items()):
            if wait["expires"] < now:
                self.awaiting.pop(uid, None)
        for uid, talk in list(self.chats.items()):
            if talk["at"] < now - CHAT_IDLE:
                self.chats.pop(uid, None)
        for uid, wait in list(self.chat_waiting.items()):
            if wait["at"] < now - CONFIRM_SECONDS * 2:
                self.chat_waiting.pop(uid, None)

    def _panic(self, person: dict) -> None:
        self.store.put("panic", "1")
        self.store.put("panic_by", person["name"])
        self.store.put("panic_at", time.time())
        self.challenges.clear()
        self.awaiting.clear()
        self.chats.clear()
        self.chat_waiting.clear()
        for p in self.store.sessions():
            self.store.end_session(p["id"])
        self.store.event("panic", person["name"],
                         "Panic word from the phone; control off for everyone until "
                         "turned back on at the computer.")
        self._to_all(self.store.paired(),
                     f"\U0001F6D1 <b>Panic word received</b> from {e(person['name'])}. "
                     f"Control from the phone is off for everyone; alerts still come. "
                     f"It can be turned back on at the computer.", VIEW_BUTTONS)

    # Deciding

    def _pending(self, person: dict, chat_id: int) -> None:
        try:
            p = self.feed.get("pending")
        except Exception as ex:                         # noqa: BLE001
            self.say(chat_id, f"⚠️ Could not read the open decisions: {e(ex)}",
                     self._buttons(person))
            return
        empty = not (p.get("actions") or p.get("questions") or p.get("devices"))
        if empty or not self._in_session(person):
            markup = self._buttons(person)
            if not empty:
                markup = {"inline_keyboard": [[{"text": "Decide now", "callback_data": "ctl"}],
                                              VIEW_ROW]}
            if empty:
                self.say(chat_id, self._pending_text(p), markup)
            else:
                self.private(person, chat_id, self._pending_text(p),
                             "<b>Waiting for your decision</b>", "Waiting for your decision",
                             markup, "pending")
            return
        n = len(p.get("actions", [])) + len(p.get("questions", [])) + len(p.get("devices", []))
        self.say(chat_id, f"\U0001F4CB <b>{n} waiting for your decision</b>, one message each:")
        for a in p.get("actions", []):
            self._show_action(person, chat_id, a)
        for q in p.get("questions", []):
            self._show_question(person, chat_id, q)
        for d in p.get("devices", []):
            self._show_device(person, chat_id, d)

    def _show_action(self, person: dict, chat_id: int, a: dict) -> None:
        yes = "Approve (asks again)" if a.get("asks_again") else "Approve"
        head = f"⚙️ <b>Action #{e(a['id'])}</b>"
        self.private(person, chat_id, f"{head}\n{e(a['what'])}\n"
                                      f"<i>{e(a.get('reason') or 'no reason given')}</i>",
                     head, f"Action #{a['id']}",
                     {"inline_keyboard": [[{"text": yes, "callback_data": f"a:{a['id']}:y"},
                                           {"text": "Deny", "callback_data": f"a:{a['id']}:n"}]]},
                     "action")

    def _show_question(self, person: dict, chat_id: int, q: dict) -> None:
        qid = q["id"]
        head = f"❓ <b>Question #{e(qid)}</b>"
        self.private(person, chat_id, f"{head}\n{e(q['question'][:600])}", head,
                     f"Question #{qid}", {"inline_keyboard": [
                         [{"text": "Yes", "callback_data": f"q:{qid}:y"},
                          {"text": "No", "callback_data": f"q:{qid}:n"},
                          {"text": "I don't know", "callback_data": f"q:{qid}:dk"}],
                         [{"text": "Type an answer", "callback_data": f"q:{qid}:t"}]]},
                     "question")

    def _show_device(self, person: dict, chat_id: int, d: dict) -> None:
        name = d.get("hostname") or d.get("vendor") or "A new device"
        mac = d.get("mac") or ""
        # Button data is seen by Telegram, so a private one carries a stand-in.
        ref = _mac_ref(mac) if self._reader_key(person) else mac
        head = "\U0001F4F5 <b>Held device</b>"
        self.private(person, chat_id, f"{head}\n{e(name)} "
                                      f"<code>{e(d.get('ip') or '')}</code> <code>{e(mac)}</code>\n"
                                      f"<i>Kept off the network until someone lets it in.</i>",
                     head, "Held device",
                     {"inline_keyboard": [[{"text": "Let it in", "callback_data": f"r:{ref}"}]]},
                     "device")

    def _after_control(self, person: dict, chat_id: int, then: str) -> None:
        """After the PIN and code: show again what the person pressed, so the
        decision itself is still their own tap. A question they wrote before
        control goes to the agent now."""
        if then == "chat":
            wait = self.chat_waiting.pop(person["tg_user_id"], None)
            if wait:
                self._chat(person, chat_id, wait["text"], wait["label"])
            return
        if then.startswith("v:"):
            iid = then.split(":")[1]
            try:
                inc = self.feed.get(f"incident/{int(iid)}")
            except Exception:                           # noqa: BLE001
                inc = {}
            if inc:
                head = f"{_dot(inc.get('severity'))} <b>Incident #{e(iid)}</b>"
                self.private(person, chat_id, f"{head}\n{e(inc.get('title'))}\nWhat was it?",
                             head + "\nWhat was it?", f"Incident #{iid}",
                             {"inline_keyboard": [[
                                 {"text": "False alarm", "callback_data": f"v:{iid}:fa"},
                                 {"text": "Real", "callback_data": f"v:{iid}:real"},
                                 {"text": "Not sure", "callback_data": f"v:{iid}:ns"}]]},
                             "incident")
                return
        self._pending(person, chat_id)

    def _decision(self, person: dict, chat_id: int, data: str) -> None:
        if not self._in_session(person):
            self._take_control(person, chat_id, data)
            return
        self._decide(person, chat_id, data)

    def _find(self, kind: str, ref: str) -> dict | None:
        p = self.feed.get("pending", {"limit": 30})
        if kind == "a":
            return next((a for a in p.get("actions", []) if str(a["id"]) == ref), None)
        if kind == "q":
            return next((q for q in p.get("questions", []) if str(q["id"]) == ref), None)
        if kind == "r":
            return next((d for d in p.get("devices", [])
                         if ref in (str(d.get("mac")), _mac_ref(d.get("mac")))), None)
        return None

    def _decide(self, person: dict, chat_id: int, data: str, confirmed: bool = False) -> None:
        kind, _, rest = data.partition(":")
        ref, _, choice = rest.rpartition(":") if kind != "r" else (rest, "", "release")
        try:
            item = self._find(kind, ref) if kind in ("a", "q", "r") else {}
        except Exception as ex:                         # noqa: BLE001
            self.say(chat_id, f"⚠️ Could not read the open decisions: {e(ex)}")
            return
        if item is None:
            self.say(chat_id, "ℹ️ That one is already decided, or gone.",
                     SESSION_BUTTONS)
            return

        if kind == "a" and choice == "y" and item.get("asks_again") and not confirmed:
            d = item.get("detail") or {}
            lines = [f"⚠️ <b>This cannot be undone.</b> Action #{e(ref)}:",
                     e(item["what"])]
            for key, label in (("name", "Name"), ("file_path", "Path"), ("path", "Path"),
                               ("sha256", "Hash"), ("hash", "Hash")):
                if d.get(key):
                    lines.append(f"{label}: <code>{e(d[key])}</code>")
            lines.append(f"Reason: {e(item.get('reason') or 'none given')}")
            lines.append("\nTo go ahead, your PIN and a fresh code again.")
            self.private(person, chat_id, "\n".join(lines),
                         f"⚠️ <b>This cannot be undone.</b> Action #{e(ref)}",
                         f"Action #{ref} cannot be undone", None, "action")
            self._ask(person, chat_id, "again", data)
            return
        if kind == "q" and choice == "t":
            self.awaiting[person["tg_user_id"]] = {"qid": int(ref),
                                                   "expires": time.time() + ANSWER_SECONDS}
            self.say(chat_id, f"✍️ Type your answer to question #{e(ref)}. "
                              f"/cancel to leave it.")
            return

        body = {"person": person["name"], "text": None}
        if kind == "a":
            body.update(kind="action", ref=int(ref), choice="approve" if choice == "y" else "deny")
            label = f"{'Approved' if choice == 'y' else 'Denied'} action #{ref}: {item['what']}"
        elif kind == "q":
            body.update(kind="question", ref=int(ref),
                        choice={"y": "yes", "n": "no", "dk": "dont_know"}.get(choice, ""))
            said = {"y": "yes", "n": "no", "dk": "I do not know"}.get(choice, "")
            label = f"Answered question #{ref}: {said}"
        elif kind == "v":
            verdict = {"fa": "false_alarm", "real": "real", "ns": "not_sure"}.get(choice)
            if not verdict:
                return
            body.update(kind="verdict", ref=int(ref), choice=verdict)
            label = f"Incident #{ref}: {verdict.replace('_', ' ')}"
        else:
            body.update(kind="release", ref=item["mac"], choice="release")
            label = (f"Let in {item.get('hostname') or item.get('vendor') or 'a device'} "
                     f"{item.get('ip') or ''} ({item['mac']})")
        self._send_decision(person, chat_id, body, label)

    def _typed_answer(self, person: dict, chat_id: int, text: str) -> None:
        wait = self.awaiting.pop(person["tg_user_id"])
        if wait["expires"] < time.time() or not self._in_session(person):
            self.say(chat_id, "⌛ That ran out, so nothing was sent. Press Type an "
                              "answer again.", self._buttons(person))
            return
        self._send_decision(person, chat_id,
                            {"kind": "question", "ref": wait["qid"], "choice": "text",
                             "text": text[:1000], "person": person["name"]},
                            f"Answered question #{wait['qid']}: {text[:200]}")

    def _send_decision(self, person: dict, chat_id: int, body: dict, label: str) -> None:
        try:
            status, out = self.feed.post("decide", body)
        except Exception as ex:                         # noqa: BLE001
            self.say(chat_id, f"⚠️ Could not reach the app: {e(ex)}. Nothing changed.")
            return
        if status == 200 and out.get("ok"):
            self.store.event("decision", person["name"], label)
            self.private(person, chat_id, f"✅ {e(label)}", "✅ <b>Done</b>", "Done",
                         SESSION_BUTTONS, "decision")
        else:
            why = out.get("detail") or f"the app answered {status}"
            self.store.event("decision_refused", person["name"], f"{label}; refused: {why}")
            self.private(person, chat_id, f"⛔ Not done: {e(why)}", "⛔ <b>Not done</b>",
                         "Not done", SESSION_BUTTONS, "decision")

    # Chat with the agent

    def _forget_chat(self, uid) -> None:
        self.chats.pop(uid, None)
        self.chat_waiting.pop(uid, None)

    def chat_limit(self) -> int:
        try:
            return max(0, int(self.store.get("chat_limit") or 0))
        except ValueError:
            return 0

    def _cannot_chat(self) -> str | None:
        if self.store.get("chat_on") != "1":
            return ("\U0001F4AC Chat with the agent is off. It can be turned on at the "
                    "computer, in the Remote tab.")
        limit = self.chat_limit()
        if self.store.chat_used() >= limit:
            return (f"\u23F8 Today's chat allowance of {limit:,} tokens is used up. It "
                    f"starts again tomorrow, or can be raised at the computer.")
        return None

    def _checks_menu(self, person: dict, chat_id: int) -> None:
        why = self._cannot_chat()
        if why:
            self.say(chat_id, why, self._buttons(person))
            return
        self.say(chat_id, "\U0001F50E <b>Checks</b>\nEach one asks the agent, which looks "
                          "and answers here. It uses chat tokens like any question.",
                 CHECK_BUTTONS)

    def _chat(self, person: dict, chat_id: int, text: str, label: str = None) -> None:
        why = self._cannot_chat()
        if why:
            self.say(chat_id, why, self._buttons(person))
            return
        if not self._in_session(person):
            why = self._cannot_control(person)
            if why:
                self.say(chat_id, why, VIEW_BUTTONS)
                return
            self.chat_waiting[person["tg_user_id"]] = {"text": text[:2000], "label": label,
                                                       "at": time.time()}
            self.say(chat_id, "\U0001F510 Chatting with the agent needs control. Press "
                              "<b>Take control</b>; your question goes to the agent "
                              "right after.", {"inline_keyboard": [
                                  [{"text": "Take control", "callback_data": "ctlc"}]]})
            return
        if not self.chat_busy.acquire(blocking=False):
            self.say(chat_id, "\u23F3 The agent is still on the last question. One at a "
                              "time; ask again when it has answered.")
            return
        try:
            self.say(chat_id, f"\U0001F50E Checking: <b>{e(label)}</b>. This can take a "
                              f"minute." if label else
                              "\U0001F914 Asking the agent. This can take a minute.")
            threading.Thread(target=self._run_chat, args=(person, chat_id, text, label),
                             name="chat", daemon=True).start()
        except Exception:                               # noqa: BLE001
            self.chat_busy.release()
            raise

    def _typing(self, chat_id: int, done: threading.Event) -> None:
        while not done.is_set():
            try:
                self.tg.call("sendChatAction", {"chat_id": chat_id, "action": "typing"})
            except Exception:                           # noqa: BLE001
                return
            done.wait(4.5)

    def _run_chat(self, person: dict, chat_id: int, text: str, label: str) -> None:
        uid, name = person["tg_user_id"], person["name"]
        asked = label or text
        done = threading.Event()
        if self.tg:
            threading.Thread(target=self._typing, args=(chat_id, done), daemon=True).start()
        try:
            talk = self.chats.get(uid) or {"history": [], "at": time.time()}
            try:
                status, out = self.feed.post("chat", {"person": name, "text": text,
                                                      "history": talk["history"]},
                                             timeout=CHAT_TIMEOUT)
            except Exception as ex:                     # noqa: BLE001
                status, out = None, {"detail": f"the app did not answer: {ex}"}
            done.set()
            # The answer can take minutes. If the panic word, a revoke or the
            # end of control came in meanwhile, nothing more goes to this chat.
            fresh = self.store.person(person["id"])
            if not fresh or fresh.get("state") != "paired" or not self._in_session(fresh):
                self.store.event("chat_withheld", name,
                                 f"{asked[:200]}; the answer was not sent, because "
                                 f"control ended before it came back.")
                if fresh and fresh.get("state") == "paired" and not fresh.get("locked_at") \
                        and self.store.get("panic") != "1":
                    self.say(chat_id, "⏱ The agent's answer came back after control "
                                      "ended, so it was not sent. Take control and ask again.",
                             CONTROL_BUTTONS)
                return
            person = fresh
            if status is None:
                self.store.event("chat_failed", name, f"{asked[:200]}; {out['detail']}"[:400])
                self.say(chat_id, f"\u26A0\uFE0F Could not reach the app: {e(out['detail'])}",
                         self._buttons(person))
                return
            if status == 409:
                self.say(chat_id, "\u23F3 The agent is busy with another question from a "
                                  "phone. Ask again in a minute.", self._buttons(person))
                return
            tokens = int(out.get("tokens") or 0)
            used = self.store.add_chat_used(tokens)
            if status != 200 or not out.get("ok"):
                why = out.get("detail") or f"the app answered {status}"
                self.store.event("chat_failed", name, f"{asked[:200]}; {why}"[:400])
                self.say(chat_id, f"\u26A0\uFE0F The agent could not answer: {e(why)}",
                         self._buttons(person))
                return
            answer = out["answer"]
            talk["history"] = (talk["history"] + [{"role": "user", "content": text},
                                                  {"role": "assistant", "content": answer}]
                               )[-CHAT_KEPT:]
            talk["at"] = time.time()
            self.chats[uid] = talk
            limit = self.chat_limit()
            foot = (f"\n\n<i>{tokens:,} tokens{' (estimated)' if out.get('estimated') else ''}"
                    f"; {min(used, limit):,} of {limit:,} used today.</i>")
            markup = SESSION_BUTTONS
            if out.get("filed"):
                foot = ("\n\n\U0001F4CB The agent filed a request; <b>What's waiting</b> "
                        "shows it." + foot)
            if self._reader_key(person):
                self.private(person, chat_id, phone_html(answer),
                             "\U0001F4AC <b>The agent answered</b>" + foot,
                             label or "The agent's answer", markup, "chat")
            else:
                body = phone_html(answer)
                cut = len(answer)
                while len(body) > 3800:
                    # Cut the plain text, never the markup, so no tag is left open.
                    cut = cut * 3 // 4
                    body = e(answer[:cut]) + "\n[cut short]"
                self.say(chat_id, body + foot, markup)
            self.store.event("chat", name, f"Asked: {asked[:200]} ({tokens:,} tokens"
                                           f"{', filed a request' if out.get('filed') else ''})")
        finally:
            done.set()
            self.chat_busy.release()

    # Private messages

    def reader_base(self) -> str:
        return self.store.get("reader_url") or reader.DEFAULT_URL

    def _reader_key(self, person: dict) -> bytes | None:
        if not self.box or not person.get("reader_sealed"):
            return None
        try:
            return reader._unb64(self.box.open(person["reader_sealed"]))
        except Exception:                               # noqa: BLE001
            return None

    def private(self, person: dict, chat_id: int, text: str, head: str, title: str,
                markup: dict = None, kind: str = "") -> bool:
        """text as it is, or, for someone with private messages, sealed behind
        a Read button with only head in the clear."""
        key = self._reader_key(person)
        if not key:
            return self.say(chat_id, text, markup)
        body = _plain(text)
        rows = list((markup or {}).get("inline_keyboard") or [])
        base = self.reader_base()
        for cap in (None, 1500, 500):
            part = body if cap is None or len(body) <= cap else \
                body[:cap].rstrip() + "\n[cut short; the rest is on the computer]"
            url = reader.link(base, reader.seal(key, title, part, kind))
            if len(url) > reader.URL_MAX:
                continue
            if self.say(chat_id, f"\U0001F512 {head}",
                        {"inline_keyboard": [[{"text": "Read", "web_app": {"url": url}}]] + rows}):
                return True
        # Never fall back to plain text: the person chose private messages.
        self.store.event("private_failed", person.get("name"),
                         f"A private message ({kind or 'message'}) could not be delivered.")
        self.say(chat_id, f"\U0001F512 {head}\n<i>This message could not be delivered "
                          f"privately. It is on the computer, in the Remote tab's history.</i>",
                 markup if rows else None)
        return False
