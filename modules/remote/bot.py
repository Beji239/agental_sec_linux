# modules/remote/bot.py
# What the bot does with a message, and how alerts go out. Only paired
# people get answers; everyone else is ignored and written to the history.

import http.client
import json
import logging
import time
import urllib.parse
from datetime import datetime

from store import clean_code, phones_match, CODE_LEN, CODE_ALPHABET
from tg_api import TelegramError

logger = logging.getLogger("remote")

RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
STRANGER_LOG_GAP = 3600
BAD_CODE_LIMIT = 5
BAD_CODE_BLOCK = 3600

HELP = ("AgentalSec Remote, first version.\n"
        "You get urgent alerts here.\n"
        "/status  how the computer is doing\n"
        "/pending  decisions waiting for you\n"
        "/help  this list\n"
        "Decisions are still made at the computer.")


def _short_time(stamp) -> str:
    if not stamp:
        return "unknown"
    return str(stamp)[:16].replace("T", " ")


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


class Bot:
    def __init__(self, store, telegram, feed):
        self.store = store
        self.tg = telegram
        self.feed = feed
        self.state = {"connected": False, "username": None, "last_ok_at": None,
                      "last_error": None, "token_present": telegram is not None,
                      "started_at": time.time()}
        self.held = []
        self.last_sent_at = None

    # Telegram side

    def say(self, chat_id: int, text: str, markup: dict = None) -> bool:
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
            self._command(person, chat["id"], (msg.get("text") or "").strip())
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
            self.store.event("stranger", self._name_of(sender),
                             f"Ignored: {what}.")

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
                 f"Hello {person['name']}. To finish, press the button below to "
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
            self.say(chat_id, "That is someone else's contact. Use the button "
                              "to share your own number.")
            return
        if not phones_match(person["phone"], contact.get("phone_number", "")):
            self.store.burn_code(person["id"])
            self.store.event("phone_refused", person["name"],
                             f"Shared a number that does not match the one entered "
                             f"({self._name_of(sender)}). The code is spent.")
            self.say(chat_id, "That number does not match the one entered at the "
                              "computer, so pairing stopped. Ask for a new code there.",
                     remove)
            return
        self.store.finish_pairing(person["id"], sender["id"], chat_id,
                                  sender.get("username"))
        self.store.event("paired", person["name"], f"Paired as {self._name_of(sender)}.")
        self.say(chat_id,
                 "Paired. Urgent alerts from AgentalSec will come here.\n\n"
                 "Please turn on Telegram's Two-Step Verification (Settings, "
                 "Privacy and Security), so nobody can take this account with "
                 "an SMS code.\n\n" + HELP, remove)

    def _command(self, person: dict, chat_id: int, text: str) -> None:
        cmd = text.split()[0].lower().split("@")[0] if text else ""
        if cmd in ("/status",):
            self.say(chat_id, self._status_text())
        elif cmd in ("/pending",):
            self.say(chat_id, self._pending_text())
        elif cmd in ("/help", "/start"):
            self.say(chat_id, HELP)
        else:
            self.say(chat_id, "For now I know /status, /pending and /help.")

    def _status_text(self) -> str:
        try:
            s = self.feed.get("status")
        except Exception as e:                          # noqa: BLE001
            return f"Could not read the app's status: {e}"
        inc = s.get("incidents") or {}
        lines = [f"AgentalSec {s.get('version') or ''}".strip(),
                 f"Open incidents: {inc.get('open', 'unknown')} "
                 f"({inc.get('new', 0)} nobody looked at yet)",
                 f"Actions waiting for you: {s.get('actions_waiting', 0)}",
                 f"Questions waiting for you: {s.get('questions_open', 0)}",
                 f"Devices held: {s.get('devices_held', 0)}"]
        worst = s.get("worst_open") or []
        if worst:
            lines.append("")
            lines.append("Worst open:")
            for w in worst:
                lines.append(f"{str(w.get('severity')).upper()}  {w.get('title')}")
        if s.get("last_incident_at"):
            lines.append(f"\nLast incident activity: {_short_time(s['last_incident_at'])}")
        return "\n".join(lines)

    def _pending_text(self) -> str:
        try:
            p = self.feed.get("pending")
        except Exception as e:                          # noqa: BLE001
            return f"Could not read the open decisions: {e}"
        lines = []
        for a in p.get("actions") or []:
            lines.append(f"Action {a['id']}: {a['what']}")
        for q in p.get("questions") or []:
            lines.append(f"Question {q['id']}: {q['question'][:300]}")
        for d in p.get("devices") or []:
            lines.append(f"Held device: {d.get('hostname') or d.get('vendor') or ''} "
                         f"{d.get('ip') or ''} {d.get('mac') or ''}".strip())
        if not lines:
            return "Nothing is waiting for a decision."
        return ("Waiting for a decision (decide at the computer for now):\n\n"
                + "\n".join(lines))

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
                self._to_all(people, f"AgentalSec: {cap} alerts were sent today. "
                                     f"Further ones are on the computer only, "
                                     f"until tomorrow.")
            self.store.event("alert_held", None,
                             f"{len(batch)} alert(s) not sent: the daily cap of {cap} was reached.")
            return
        text = self._alert_text(batch)
        if self._to_all(people, text):
            self.last_sent_at = time.time()
            self.store.put("sent_today", sent_today + 1)
            self.store.event("alert_sent", None,
                             f"{len(batch)} alert(s) to {len(people)} person(s): "
                             f"{batch[0].get('title')}"[:400])

    def _alert_text(self, batch: list) -> str:
        if len(batch) == 1:
            i = batch[0]
            verb = "raised to" if i.get("raised") else "new,"
            return (f"AgentalSec: urgent incident ({verb} {str(i.get('severity')).upper()})\n"
                    f"{i.get('title')}\n"
                    f"{i.get('entity_type')}: {i.get('entity_value')}\n"
                    f"Seen {_short_time(i.get('last_seen_at'))}")
        lines = [f"AgentalSec: {len(batch)} urgent incidents"]
        for i in batch[:6]:
            lines.append(f"{str(i.get('severity')).upper()}  {i.get('title')}")
        if len(batch) > 6:
            lines.append(f"{len(batch) - 6} more on the computer")
        return "\n".join(lines)

    def _to_all(self, people: list, text: str) -> bool:
        ok = False
        for p in people:
            ok = self.say(p["chat_id"], text) or ok
        return ok

    def send_test(self) -> dict:
        people = self.store.paired()
        if not people:
            return {"ok": False, "reason": "Nobody is paired yet."}
        if not self.tg:
            return {"ok": False, "reason": "There is no bot token yet."}
        n = sum(1 for p in people if self.say(
            p["chat_id"], "AgentalSec: test message from the computer. Alerts reach you."))
        self.store.event("test_sent", None, f"Test message reached {n} of {len(people)}.")
        return {"ok": n > 0, "reached": n, "of": len(people)}

    def tell_and_remove(self, person: dict, why: str) -> None:
        if person.get("state") == "paired" and person.get("chat_id"):
            self.say(person["chat_id"], why, {"remove_keyboard": True})
        self.store.remove_person(person["id"])
