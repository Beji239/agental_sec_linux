# core/rule_trials.py
# Rule trials. A rule that keeps raising false alarms gets a written fix, and
# the owner can try it for two weeks. Python counts the alarms before and
# after, replays the past ones through the fix, and checks that a listed name
# the fix does not cover still matches. No model tokens. At the end the owner
# keeps the fix or undoes it; nothing is kept on its own.

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from core import memory_engine as me

logger = logging.getLogger(__name__)

TRIAL_DAYS = 14
BEFORE_DAYS = 14
ACTIVE_CACHE_SECONDS = 60

# Hosts where feeds list one file's address (a script, a download), not the
# host. The app sees only the host name, so every visit to it matched.
FILE_HOSTS = frozenset({
    "jsdelivr.net", "cdn.jsdelivr.net", "fastly.jsdelivr.net",
    "gcore.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    "drive.google.com", "docs.google.com", "storage.googleapis.com",
    "dropbox.com", "dropboxusercontent.com", "onedrive.live.com", "1drv.ms",
    "mediafire.com", "mega.nz", "cdn.discordapp.com", "archive.org",
    "sourceforge.net", "bitbucket.io",
})

TUNINGS = {
    "fed_file_hosts": {
        "rules": ("FED-1002", "FED-1003"),
        "title": "Threat lists: leave out shared file hosts",
        "problem": "Threat feeds list one bad file on a shared host, such as "
                   "a script on cdn.jsdelivr.net or a download on github.com. "
                   "The app only sees the host name, so every visit to that "
                   "host raised an alarm.",
        "change": "A name on a shared file host no longer raises FED-1002 or "
                  "FED-1003. Every other listed name still does, and so do "
                  "listed addresses (FED-1001).",
    },
}

STATUSES = ("trial", "kept", "undone")

DDL = (
    """CREATE TABLE IF NOT EXISTS rule_trial (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tuning      TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('trial','kept','undone')),
    started_at  TEXT NOT NULL,
    ends_at     TEXT NOT NULL,
    ended_at    TEXT
)""",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_rule_trial_active "
    "ON rule_trial(tuning) WHERE status != 'undone'",
    # Hits a trial held back, one row per day, rule, device and name.
    """CREATE TABLE IF NOT EXISTS rule_trial_held (
    trial_id  INTEGER NOT NULL REFERENCES rule_trial(id),
    day       TEXT NOT NULL,
    rule      TEXT NOT NULL,
    entity    TEXT NOT NULL,
    name      TEXT NOT NULL,
    count     INTEGER NOT NULL DEFAULT 0,
    last_at   TEXT NOT NULL,
    PRIMARY KEY (trial_id, day, rule, entity, name)
)""",
)

_cache = {}
_cache_lock = threading.Lock()


def ensure_tables(conn) -> int:
    added = 0 if me._table_exists_ro(conn, "rule_trial") else 1
    for ddl in DDL:
        conn.execute(ddl)
    return added


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _sql(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _parse(value) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _day(dt: datetime) -> str:
    return dt.astimezone().strftime("%Y-%m-%d")


def is_file_host(name: str) -> bool:
    n = (name or "").lower().strip(".")
    return any(n == h or n.endswith("." + h) for h in FILE_HOSTS)


def _tuning_for(rule: str):
    return next((k for k, t in TUNINGS.items() if rule in t["rules"]), None)


def would_hold(rule: str, name: str) -> bool:
    """Would the fix for this rule hold back a hit on this name."""
    return _tuning_for(rule) == "fed_file_hosts" and is_file_host(name)


def _active_id(tuning: str):
    """The trial or kept fix in force for this tuning, cached a minute."""
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(tuning)
        if hit and now - hit[1] < ACTIVE_CACHE_SECONDS:
            return hit[0]
    tid = None
    with me._get_readonly_conn() as conn:
        if me._table_exists_ro(conn, "rule_trial"):
            row = conn.execute("SELECT id FROM rule_trial WHERE tuning = ? "
                               "AND status != 'undone'", (tuning,)).fetchone()
            tid = row["id"] if row else None
    with _cache_lock:
        _cache[tuning] = (tid, now)
    return tid


def holds_back(rule: str, name: str, entity: str, now: datetime = None) -> bool:
    """Called on a feed hit. True when a fix in force holds it back; the hold
    is counted so the page can show it."""
    if not would_hold(rule, name):
        return False
    tid = _active_id(_tuning_for(rule))
    if tid is None:
        return False
    now = now or datetime.now(timezone.utc)
    with me._get_conn() as conn:
        conn.execute(
            "INSERT INTO rule_trial_held (trial_id, day, rule, entity, name, "
            "count, last_at) VALUES (?, ?, ?, ?, ?, 1, ?) "
            "ON CONFLICT (trial_id, day, rule, entity, name) "
            "DO UPDATE SET count = count + 1, last_at = excluded.last_at",
            (tid, _day(now), rule, entity or "unknown", name.lower(),
             _iso(now)))
        conn.commit()
    logger.info(f"{rule}: {entity} and {name} held back by the trial fix")
    return True


def _forget():
    with _cache_lock:
        _cache.clear()


def start(tuning: str, now: datetime = None) -> dict:
    if tuning not in TUNINGS:
        return {"success": False, "error": f"no fix named {tuning!r}"}
    now = now or datetime.now(timezone.utc)
    with me._get_conn() as conn:
        ensure_tables(conn)
        if conn.execute("SELECT 1 FROM rule_trial WHERE tuning = ? AND "
                        "status != 'undone'", (tuning,)).fetchone():
            return {"success": False, "error": "This fix is already on."}
        cur = conn.execute(
            "INSERT INTO rule_trial (tuning, status, started_at, ends_at) "
            "VALUES (?, 'trial', ?, ?)",
            (tuning, _iso(now), _iso(now + timedelta(days=TRIAL_DAYS))))
        conn.commit()
        tid = cur.lastrowid
    _forget()
    _journal("rule_trial_started", tid, {"tuning": tuning})
    return {"success": True, "id": tid}


def end(tuning: str, keep: bool, now: datetime = None) -> dict:
    """Keep the fix (it stays on) or undo it (alarms come back)."""
    now = now or datetime.now(timezone.utc)
    with me._get_conn() as conn:
        ensure_tables(conn)
        row = conn.execute("SELECT id, status FROM rule_trial WHERE tuning = ? "
                           "AND status != 'undone'", (tuning,)).fetchone()
        if row is None:
            return {"success": False, "error": "This fix is not on."}
        if keep and row["status"] == "kept":
            return {"success": False, "error": "This fix is already kept."}
        conn.execute("UPDATE rule_trial SET status = ?, ended_at = ? "
                     "WHERE id = ?",
                     ("kept" if keep else "undone", _iso(now), row["id"]))
        conn.commit()
    _forget()
    _journal("rule_trial_ended", row["id"],
             {"tuning": tuning, "outcome": "kept" if keep else "undone"})
    return {"success": True, "id": row["id"],
            "status": "kept" if keep else "undone"}


def _journal(op, tid, payload):
    try:
        me._journal(op, "rule_trial", int(tid), payload)
    except Exception as e:                                  # noqa: BLE001
        logger.error(f"Could not journal {op} for trial {tid}: {e}")


# What the page shows

def _alarms(conn, rules, start: datetime, end: datetime) -> dict:
    """Alarms per local day, one dot per incident, with the names it matched
    and whether the fix would have held every one of them back."""
    if not me._table_exists_ro(conn, "findings"):
        return {}
    cols = ({r[1] for r in conn.execute("PRAGMA table_info(incident)")}
            if me._table_exists_ro(conn, "incident") else set())
    verdict = ("i.verdict" if "verdict" in cols else "NULL")
    join = ("LEFT JOIN incident i ON i.detection_id = f.detection_id "
            "AND i.entity_value = f.entity_value" if cols else "")
    rows = conn.execute(
        f"SELECT f.found_at, f.detection_id AS rule, f.entity_value AS entity, "
        f"COALESCE(json_extract(f.raw_data, '$.matched'), "
        f"json_extract(f.raw_data, '$.domain'), "
        f"json_extract(f.raw_data, '$.sni'), '') AS name, "
        # With MAX(), SQLite takes the bare column from the same row.
        f"{'MAX(i.id)' if cols else 'NULL'} AS incident, "
        f"{verdict if cols else 'NULL'} AS verdict "
        f"FROM findings f {join} "
        f"WHERE f.detection_id IN ({', '.join('?' * len(rules))}) "
        f"AND f.found_at >= ? AND f.found_at < ? GROUP BY f.id "
        f"ORDER BY f.found_at",
        (*rules, _sql(start), _sql(end))).fetchall()
    days = {}
    for r in rows:
        when = _parse(str(r["found_at"]).replace(" ", "T"))
        if when is None:
            continue
        key = r["incident"] or f"{r['rule']}:{r['entity']}"
        dot = days.setdefault(_day(when), {}).setdefault(key, {
            "incident": r["incident"], "rule": r["rule"],
            "entity": r["entity"], "verdict": r["verdict"], "names": set(),
            "held": True})
        dot["names"].add(r["name"])
        dot["held"] = dot["held"] and would_hold(r["rule"], r["name"])
    return {d: [dict(v, names=sorted(v["names"])) for v in dots.values()]
            for d, dots in days.items()}


def _held(conn, tid) -> dict:
    out = {}
    if tid is None or not me._table_exists_ro(conn, "rule_trial_held"):
        return out
    for r in conn.execute("SELECT day, SUM(count) AS n FROM rule_trial_held "
                          "WHERE trial_id = ? GROUP BY day", (tid,)):
        out[r["day"]] = r["n"]
    return out


def _held_names(conn, tid) -> list:
    if tid is None or not me._table_exists_ro(conn, "rule_trial_held"):
        return []
    return [r["name"] for r in conn.execute(
        "SELECT name, SUM(count) AS n FROM rule_trial_held WHERE trial_id = ? "
        "GROUP BY name ORDER BY n DESC LIMIT 5", (tid,))]


def self_check(conn, tuning: str) -> dict:
    """A listed name the fix does not cover must still match, and a listed
    file host must be held back. Run against the live feed table."""
    out = {"ran": False}
    if tuning != "fed_file_hosts" or not me._table_exists_ro(conn,
                                                             "threat_feed"):
        return out
    from tools import feed_matcher
    names = [r["indicator"] for r in conn.execute(
        "SELECT indicator FROM threat_feed WHERE indicator_type = 'domain' "
        "ORDER BY last_refreshed DESC LIMIT 200")]
    listed = next((n for n in names if not is_file_host(n)
                   and not feed_matcher._is_shared_host(n)), None)
    host = next((n for n in names if is_file_host(n)), None)
    if listed is None:
        out["reason"] = "The threat lists hold no name to check against yet."
        return out
    hit = feed_matcher._feed_hit_domain(conn, listed)
    out.update(ran=True, listed=listed,
               still_matches=bool(hit) and not would_hold("FED-1002", listed),
               file_host=host,
               file_host_held=(would_hold("FED-1002", host) if host else None))
    return out


def _days(start: datetime, n: int) -> list:
    return [_day(start + timedelta(days=i)) for i in range(n)]


def _count(days: dict, names: list, what) -> int:
    return sum(1 for d in names for dot in days.get(d, []) if what(dot))


def overview(now: datetime = None) -> dict:
    now = now or datetime.now(timezone.utc)
    out = {"trials": [], "trial_days": TRIAL_DAYS, "before_days": BEFORE_DAYS}
    with me._get_readonly_conn() as conn:
        have = me._table_exists_ro(conn, "rule_trial")
        for key, t in TUNINGS.items():
            row = conn.execute(
                "SELECT * FROM rule_trial WHERE tuning = ? ORDER BY "
                "status = 'undone', id DESC LIMIT 1", (key,)).fetchone() \
                if have else None
            row = dict(row) if row else None
            on = row and row["status"] != "undone"
            started = _parse(row["started_at"]) if on else None
            pivot = started or now
            before_start = (pivot.astimezone().replace(
                hour=0, minute=0, second=0, microsecond=0)
                - timedelta(days=BEFORE_DAYS - 1))
            before = _alarms(conn, t["rules"], before_start, pivot)
            bdays = _days(before_start, BEFORE_DAYS)
            entry = {
                "tuning": key, "title": t["title"], "rules": list(t["rules"]),
                "problem": t["problem"], "change": t["change"],
                "status": row["status"] if on else "off",
                "started_at": row["started_at"] if on else None,
                "ends_at": row["ends_at"] if on else None,
                "ended_at": row["ended_at"] if on else None,
                "before": [{"day": d, "dots": before.get(d, [])}
                           for d in bdays],
                "before_total": _count(before, bdays, lambda x: True),
                "before_false": _count(before, bdays, lambda x:
                                       x["verdict"] == "false_alarm"),
                "before_held": _count(before, bdays, lambda x: x["held"]),
                "before_false_held": _count(before, bdays, lambda x: x["held"]
                                            and x["verdict"] == "false_alarm"),
            }
            if on:
                tid = row["id"]
                first = started.astimezone().replace(hour=0, minute=0,
                                                     second=0, microsecond=0)
                span = TRIAL_DAYS + 1 if row["status"] == "trial" else min(
                    60, max(TRIAL_DAYS + 1, (now.astimezone() - first).days + 1))
                adays = _days(first, span)
                after = _alarms(conn, t["rules"], started, now)
                held = _held(conn, tid)
                today = _day(now)
                entry["after"] = [{"day": d, "dots": after.get(d, []),
                                   "held": held.get(d, 0), "future": d > today}
                                  for d in adays]
                entry.update(
                    after_total=_count(after, adays, lambda x: True),
                    after_false=_count(after, adays, lambda x:
                                       x["verdict"] == "false_alarm"),
                    after_real=_count(after, adays, lambda x:
                                      x["verdict"] == "real"),
                    held_total=sum(held.values()),
                    held_names=_held_names(conn, tid),
                    day_of_trial=min(TRIAL_DAYS, (now - started).days + 1),
                    over=now >= (_parse(row["ends_at"]) or now))
            try:
                entry["self_check"] = self_check(conn, key)
            except Exception as e:                          # noqa: BLE001
                entry["self_check"] = {"ran": False,
                                       "reason": f"The self-check failed: {e}"}
            entry["proposed"] = (not on and entry["before_false_held"] > 0)
            entry["sentence"] = _sentence(entry)
            out["trials"].append(entry)
    return out


def _n(k, word):
    return f"{k} {word}{'' if k == 1 else 's'}"


def _sentence(e: dict) -> str:
    """One plain sentence with the numbers, decided here, not by a model."""
    sc = e.get("self_check") or {}
    caught = (f" Self-check: {sc['listed']}, a listed name off the shared "
              f"hosts, still matches." if sc.get("still_matches") else
              " Self-check: a listed name off the shared hosts did NOT match. "
              "Undo the fix and look at the threat lists." if sc.get("ran")
              else "")
    before = (f"In the {BEFORE_DAYS} days before: "
              f"{_n(e['before_total'], 'alarm')}, "
              f"{e['before_false']} marked false, and the fix would have held "
              f"back {e['before_held']}.")
    if e["status"] == "off":
        if not e["before_total"]:
            return "No alarm from these rules in the last two weeks, so " \
                "there is nothing to try this fix on." + caught
        lead = ("Worth a trial. " if e["proposed"] else
                "Not proposed: none of the alarms the fix would hold back is "
                "marked false yet. ")
        return lead + before + caught
    since = (f"Since the start: {_n(e['after_total'], 'alarm')} raised "
             f"({e['after_false']} marked false, {e['after_real']} real) and "
             f"{_n(e['held_total'], 'hit')} held back on shared file hosts.")
    if e["status"] == "kept":
        return "The fix is kept. " + since + caught
    if e.get("over"):
        return ("The two weeks are up. " + before + " " + since + caught
                + " Keep the fix or undo it.")
    return (f"Day {e['day_of_trial']} of {TRIAL_DAYS}. " + before + " " + since
            + caught)
