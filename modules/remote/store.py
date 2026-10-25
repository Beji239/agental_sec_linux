# modules/remote/store.py
# The Remote module's own database: people, history, settings and which
# alerts went out. It lives in the module's data folder, apart from the app's.

import hashlib
import os
import re
import secrets
import sqlite3
import threading
import time

CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
CODE_LEN = 8
CODE_TTL = 15 * 60
PAIRING_TTL = 10 * 60
EVENTS_KEPT = 1000

DEFAULTS = {
    "floor": "high",
    "quiet_on": "0",
    "quiet_start": "23:00",
    "quiet_end": "07:00",
    "gap_minutes": "10",
    "daily_cap": "20",
    "chat_on": "0",
    "chat_limit": "100000",
    "reader_url": "",
}

_DDL = """
CREATE TABLE IF NOT EXISTS people (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    phone           TEXT NOT NULL,
    phone_digits    TEXT NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('waiting', 'paired')),
    code_hash       TEXT,
    code_expires    REAL,
    pairing_user_id INTEGER,
    pairing_until   REAL,
    tg_user_id      INTEGER UNIQUE,
    chat_id         INTEGER,
    tg_username     TEXT,
    created_at      REAL NOT NULL,
    paired_at       REAL
);
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    at      REAL NOT NULL,
    kind    TEXT NOT NULL,
    person  TEXT,
    detail  TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key     TEXT PRIMARY KEY,
    value   TEXT
);
CREATE TABLE IF NOT EXISTS sent (
    incident_id INTEGER PRIMARY KEY,
    rank        INTEGER NOT NULL,
    at          REAL NOT NULL,
    silent      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS strangers (
    user_id       INTEGER PRIMARY KEY,
    last_logged   REAL,
    bad_codes     INTEGER NOT NULL DEFAULT 0,
    blocked_until REAL
);
"""


def digits(phone: str) -> str:
    """A phone number as digits only, without a 00 or + prefix."""
    d = re.sub(r"\D", "", phone or "")
    return d[2:] if d.startswith("00") else d


def phones_match(entered: str, shared: str) -> bool:
    """The number typed in the tab against the one Telegram shares. The tab
    may hold a local number (07700...) and Telegram the full one (447700...),
    so the shorter, without its leading zero, must end the longer."""
    a, b = digits(entered), digits(shared)
    if not a or not b:
        return False
    if a == b:
        return True
    short, long_ = sorted((a.lstrip("0"), b.lstrip("0")), key=len)
    return len(short) >= 8 and long_.endswith(short)


def clean_code(text: str) -> str:
    return re.sub(r"[\s\-]", "", text or "").upper()


def _hash(code: str) -> str:
    return hashlib.sha256(clean_code(code).encode()).hexdigest()


# Control from the phone, added after the first release, so older databases
# get the columns on start.
_CONTROL_COLUMNS = (
    ("pin_hash", "TEXT"), ("word_hash", "TEXT"), ("totp_sealed", "TEXT"),
    ("totp_pending", "TEXT"), ("enrolled_at", "REAL"),
    ("last_step", "INTEGER NOT NULL DEFAULT 0"),
    ("bad_tries", "INTEGER NOT NULL DEFAULT 0"), ("locked_at", "REAL"),
    ("session_until", "REAL"), ("session_warned", "INTEGER NOT NULL DEFAULT 0"),
)
# Private messages: the person's reader key, sealed, and one waiting for the
# phone's check code.
_READER_COLUMNS = (("reader_sealed", "TEXT"), ("reader_pending", "TEXT"),
                   ("reader_at", "REAL"))
_CLEAR_CONTROL = ("pin_hash = NULL, word_hash = NULL, totp_sealed = NULL, "
                  "totp_pending = NULL, enrolled_at = NULL, last_step = 0, "
                  "bad_tries = 0, locked_at = NULL, session_until = NULL, "
                  "session_warned = 0")


class Store:
    def __init__(self, path):
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), check_same_thread=False,
                                   isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_DDL)
        have = {r[1] for r in self._db.execute("PRAGMA table_info(people)")}
        for col, kind in _CONTROL_COLUMNS + _READER_COLUMNS:
            if col not in have:
                self._db.execute(f"ALTER TABLE people ADD COLUMN {col} {kind}")
        # Paired phones live here: owner only, like the main database.
        for p in (str(path), f"{path}-wal", f"{path}-shm"):
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass

    def _all(self, sql, params=()):
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, params).fetchall()]

    def _one(self, sql, params=()):
        rows = self._all(sql, params)
        return rows[0] if rows else None

    def _run(self, sql, params=()):
        with self._lock:
            cur = self._db.execute(sql, params)
            return cur.lastrowid

    # Settings

    def get(self, key: str, default=None):
        row = self._one("SELECT value FROM settings WHERE key = ?", (key,))
        if row is not None:
            return row["value"]
        return DEFAULTS.get(key, default)

    def put(self, key: str, value) -> None:
        self._run("INSERT INTO settings (key, value) VALUES (?, ?) "
                  "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                  (key, None if value is None else str(value)))

    def settings(self) -> dict:
        return {k: self.get(k) for k in DEFAULTS}

    # Chat tokens, counted per local day

    def chat_used(self) -> int:
        if self.get("chat_day") != time.strftime("%Y-%m-%d"):
            return 0
        try:
            return int(self.get("chat_used") or 0)
        except ValueError:
            return 0

    def add_chat_used(self, tokens: int) -> int:
        with self._lock:
            used = self.chat_used() + max(0, int(tokens or 0))
            self.put("chat_day", time.strftime("%Y-%m-%d"))
            self.put("chat_used", used)
        return used

    # History

    def event(self, kind: str, person: str = None, detail: str = None) -> None:
        self._run("INSERT INTO events (at, kind, person, detail) VALUES (?, ?, ?, ?)",
                  (time.time(), kind, person, (detail or "")[:500]))
        self._run("DELETE FROM events WHERE id <= "
                  "(SELECT MAX(id) FROM events) - ?", (EVENTS_KEPT,))

    def events(self, limit: int = 100) -> list:
        return self._all("SELECT * FROM events ORDER BY id DESC LIMIT ?",
                         (max(1, min(int(limit), 500)),))

    # People

    def people(self) -> list:
        """For the tab: never the hashes or the secrets."""
        rows = self._all("SELECT id, name, phone, state, code_expires, "
                         "tg_username, created_at, paired_at, enrolled_at, "
                         "locked_at, session_until, totp_pending IS NOT NULL "
                         "AS enrolling, reader_at, reader_pending IS NOT NULL "
                         "AS private_pending FROM people ORDER BY id")
        now = time.time()
        for r in rows:
            r["code_live"] = bool(r["state"] == "waiting" and r["code_expires"]
                                  and r["code_expires"] > now)
            r["enrolled"] = bool(r["enrolled_at"])
            r["locked"] = bool(r["locked_at"])
            r["enrolling"] = bool(r["enrolling"])
            r["private"] = bool(r["reader_at"])
            r["private_pending"] = bool(r["private_pending"])
            if not (r["session_until"] and r["session_until"] > now):
                r["session_until"] = None
        return rows

    def paired(self) -> list:
        return self._all("SELECT * FROM people WHERE state = 'paired'")

    def person(self, pid: int):
        return self._one("SELECT * FROM people WHERE id = ?", (int(pid),))

    def by_user(self, user_id: int):
        return self._one("SELECT * FROM people WHERE tg_user_id = ? "
                         "AND state = 'paired'", (int(user_id),))

    def add_person(self, name: str, phone: str) -> tuple:
        code = self._new_code()
        pid = self._run(
            "INSERT INTO people (name, phone, phone_digits, state, code_hash, "
            "code_expires, created_at) VALUES (?, ?, ?, 'waiting', ?, ?, ?)",
            (name, phone, digits(phone), _hash(code), time.time() + CODE_TTL,
             time.time()))
        return pid, code

    def new_code(self, pid: int) -> str:
        code = self._new_code()
        # Pairing again may bind another Telegram account, so control and
        # private messages are set up again too.
        self._run("UPDATE people SET state = 'waiting', code_hash = ?, "
                  "code_expires = ?, pairing_user_id = NULL, pairing_until = NULL, "
                  "tg_user_id = NULL, chat_id = NULL, paired_at = NULL, "
                  "reader_sealed = NULL, reader_pending = NULL, reader_at = NULL, "
                  f"{_CLEAR_CONTROL} WHERE id = ?",
                  (_hash(code), time.time() + CODE_TTL, int(pid)))
        return code

    def _new_code(self) -> str:
        return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LEN))

    def remove_person(self, pid: int) -> None:
        self._run("DELETE FROM people WHERE id = ?", (int(pid),))

    def remove_everyone(self) -> list:
        rows = self._all("SELECT * FROM people")
        self._run("DELETE FROM people")
        return rows

    def match_code(self, code: str):
        """The waiting person this code belongs to, while it is live."""
        return self._one("SELECT * FROM people WHERE state = 'waiting' AND "
                         "code_hash = ? AND code_expires > ?",
                         (_hash(code), time.time()))

    def start_pairing(self, pid: int, user_id: int) -> None:
        self._run("UPDATE people SET pairing_user_id = ?, pairing_until = ? "
                  "WHERE id = ?", (int(user_id), time.time() + PAIRING_TTL, int(pid)))

    def pairing_for(self, user_id: int):
        return self._one("SELECT * FROM people WHERE state = 'waiting' AND "
                         "pairing_user_id = ? AND pairing_until > ?",
                         (int(user_id), time.time()))

    def finish_pairing(self, pid: int, user_id: int, chat_id: int,
                       username: str) -> None:
        self._run("UPDATE people SET state = 'paired', code_hash = NULL, "
                  "code_expires = NULL, pairing_user_id = NULL, pairing_until = NULL, "
                  "tg_user_id = ?, chat_id = ?, tg_username = ?, paired_at = ? "
                  "WHERE id = ?",
                  (int(user_id), int(chat_id), username, time.time(), int(pid)))

    def burn_code(self, pid: int) -> None:
        self._run("UPDATE people SET code_hash = NULL, code_expires = NULL, "
                  "pairing_user_id = NULL, pairing_until = NULL WHERE id = ?",
                  (int(pid),))

    # Strangers

    def stranger(self, user_id: int) -> dict:
        row = self._one("SELECT * FROM strangers WHERE user_id = ?", (int(user_id),))
        return row or {"user_id": user_id, "last_logged": None, "bad_codes": 0,
                       "blocked_until": None}

    def save_stranger(self, row: dict) -> None:
        self._run("INSERT INTO strangers (user_id, last_logged, bad_codes, "
                  "blocked_until) VALUES (?, ?, ?, ?) ON CONFLICT(user_id) DO "
                  "UPDATE SET last_logged = excluded.last_logged, bad_codes = "
                  "excluded.bad_codes, blocked_until = excluded.blocked_until",
                  (int(row["user_id"]), row.get("last_logged"),
                   int(row.get("bad_codes") or 0), row.get("blocked_until")))

    # Alerts already handled

    def sent_rank(self, incident_id: int):
        row = self._one("SELECT rank FROM sent WHERE incident_id = ?",
                        (int(incident_id),))
        return row["rank"] if row else None

    def mark_sent(self, incident_id: int, rank: int, silent: bool = False) -> None:
        self._run("INSERT INTO sent (incident_id, rank, at, silent) VALUES "
                  "(?, ?, ?, ?) ON CONFLICT(incident_id) DO UPDATE SET "
                  "rank = excluded.rank, at = excluded.at, silent = excluded.silent",
                  (int(incident_id), int(rank), time.time(), int(silent)))

    # Control from the phone

    def enrol_start(self, pid: int, pin_hash: str, word_hash: str,
                    sealed_secret: str) -> None:
        """Waits for the first code from the authenticator before it counts."""
        self._run(f"UPDATE people SET {_CLEAR_CONTROL}, pin_hash = ?, "
                  "word_hash = ?, totp_pending = ? WHERE id = ?",
                  (pin_hash, word_hash, sealed_secret, int(pid)))

    def enrol_finish(self, pid: int, step: int) -> None:
        self._run("UPDATE people SET totp_sealed = totp_pending, totp_pending = NULL, "
                  "enrolled_at = ?, last_step = ?, bad_tries = 0, locked_at = NULL "
                  "WHERE id = ?", (time.time(), int(step), int(pid)))

    def clear_control(self, pid: int) -> None:
        self._run(f"UPDATE people SET {_CLEAR_CONTROL} WHERE id = ?", (int(pid),))

    def enrolled(self) -> list:
        return self._all("SELECT * FROM people WHERE state = 'paired' "
                         "AND enrolled_at IS NOT NULL")

    def used_step(self, pid: int, step: int) -> None:
        self._run("UPDATE people SET last_step = ?, bad_tries = 0 WHERE id = ?",
                  (int(step), int(pid)))

    def bad_try(self, pid: int) -> int:
        self._run("UPDATE people SET bad_tries = bad_tries + 1 WHERE id = ?", (int(pid),))
        row = self._one("SELECT bad_tries FROM people WHERE id = ?", (int(pid),))
        return int(row["bad_tries"]) if row else 0

    def lock(self, pid: int) -> None:
        self._run("UPDATE people SET locked_at = ?, session_until = NULL, "
                  "session_warned = 0 WHERE id = ?", (time.time(), int(pid)))

    def unlock(self, pid: int) -> None:
        self._run("UPDATE people SET locked_at = NULL, bad_tries = 0 WHERE id = ?",
                  (int(pid),))

    def open_session(self, pid: int, until: float) -> None:
        self._run("UPDATE people SET session_until = ?, session_warned = 0 "
                  "WHERE id = ?", (until, int(pid)))

    def end_session(self, pid: int) -> None:
        self._run("UPDATE people SET session_until = NULL, session_warned = 0 "
                  "WHERE id = ?", (int(pid),))

    def warned(self, pid: int) -> None:
        self._run("UPDATE people SET session_warned = 1 WHERE id = ?", (int(pid),))

    def reader_start(self, pid: int, sealed_key: str) -> None:
        self._run("UPDATE people SET reader_pending = ? WHERE id = ?",
                  (sealed_key, int(pid)))

    def reader_finish(self, pid: int) -> None:
        self._run("UPDATE people SET reader_sealed = reader_pending, reader_pending = NULL, "
                  "reader_at = ? WHERE id = ?", (time.time(), int(pid)))

    def reader_clear(self, pid: int) -> None:
        self._run("UPDATE people SET reader_sealed = NULL, reader_pending = NULL, "
                  "reader_at = NULL WHERE id = ?", (int(pid),))

    def sessions(self) -> list:
        return self._all("SELECT * FROM people WHERE session_until IS NOT NULL")
