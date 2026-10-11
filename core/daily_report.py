# core/daily_report.py
# The daily security report. One HTML page for each day the app ran, written
# at the day's last regular wake, or at the next start when the app was off
# then. Every fact is counted from the database; only the assessment is model
# text, from one call with no tools.

import html
import ipaddress
import json
import logging
import re
import socket
import threading
import time
from datetime import date, datetime, timedelta, timezone

from core import memory_engine as me

logger = logging.getLogger(__name__)

KEEP_DAYS = 30
# Duty run tags. A catch-up row must not use up a regular wake hour.
DAILY_TAG = "[daily report "
CATCH_UP_TAG = "[daily report catch-up "
CATCH_UP_EVERY_SECONDS = 3600
# Less watched time than this share of the window turns the status amber.
WATCHED_AMBER = 0.9
# The sensor watch needs its first check to record the time the app was off.
BOOT_WAIT_SECONDS = 300
TABLE_ROWS = 25
EPHEMERAL_FLOOR = 32768

_state = {"next_catch_up": 0.0, "started": time.time()}
_write_lock = threading.Lock()

INTO_HOST = ("LNX-1003",)
NEW_ACCESS = ("LNX-1009", "LNX-1011", "LNX-1017", "LNX-2002")
SCANS = ("LNX-1015",)
RETURNED = ("LAN-1011",)
MALWARE_AV = ("AV-1001",)
QUARANTINED = ("REM-1006",)
MASQUERADE = ("LNX-1102",)
ODD_PLACES = ("LNX-1101", "LNX-3001", "LNX-3002")
STARTUP = ("LNX-4001", "LNX-4002", "LNX-4003", "LNX-4004")
SYSTEM_FILES = ("LNX-2001", "LNX-2006", "LNX-2012")
NEW_DEVICES = ("LAN-1008", "NET-1001", "RTR-1001")
UPLOADS = ("LAN-1009",)
PLACES = ("GEO-1001", "GEO-1002")
THREAT_LIST = ("FED-1001", "FED-1002", "FED-1003", "LAN-1010")

VERDICT_TEXT = {"real": "real", "benign": "harmless",
                "no_action": "harmless", "needs_human": "needs your decision"}


# Time and wording

def _sql(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _parse(value) -> datetime | None:
    """A stored UTC time in either of the two shapes the tables use."""
    if not value:
        return None
    text = str(value).strip().replace("T", " ")
    text = re.sub(r"(Z|[+-]00:?00)$", "", text)[:19]
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc)
    except ValueError:
        return None


def day_bounds(day: date) -> tuple:
    """Local midnight to local midnight, as aware datetimes."""
    start = datetime(day.year, day.month, day.day).astimezone()
    nxt = day + timedelta(days=1)
    return start, datetime(nxt.year, nxt.month, nxt.day).astimezone()


def _local_day(dt: datetime) -> date:
    return dt.astimezone().date()


def _long_day(day: date) -> str:
    return f"{day:%A} {day.day} {day:%B %Y}"


def _short_day(day: date) -> str:
    return f"{day:%a} {day.day} {day:%b}"


def _hm(dt, day: date) -> str:
    """24-hour local time, with the day named when it is not the report day."""
    if dt is None:
        return "?"
    loc = dt.astimezone()
    if loc.date() == day:
        return f"{loc:%H:%M}"
    if loc.date() == day + timedelta(days=1) and loc.hour == 0 \
            and loc.minute == 0:
        return "24:00"
    return f"{_short_day(loc.date())} {loc:%H:%M}"


def _span(a, b, day: date) -> str:
    left, right = _hm(a, day), _hm(b, day)
    return left if left == right else f"{left} to {right}"


def _dur(seconds: float) -> str:
    minutes = int(round(max(0, seconds) / 60))
    days, rest = divmod(minutes, 1440)
    hours, mins = divmod(rest, 60)
    if days >= 365:
        years, days = divmod(days, 365)
        return (f"{years} year{'s' if years > 1 else ''}"
                + (f" {days} day{'s' if days != 1 else ''}" if days else ""))
    if days:
        return (f"{days} day{'s' if days > 1 else ''}"
                + (f" {hours} h" if hours else ""))
    if hours:
        return f"{hours} h" + (f" {mins} min" if mins else "")
    return f"{mins} min"


def _n(count: int, word: str, plural: str = None) -> str:
    return f"{count:,} {word if count == 1 else (plural or word + 's')}"


def plain(text: str) -> str:
    """The app's visible text rules: no dash or pipe used as punctuation."""
    text = str(text or "")
    text = re.sub(r"\s*[—–]\s*", ", ", text)
    text = re.sub(r"\s+--?\s+", ", ", text)
    text = re.sub(r"\s*\|\s*", ", ", text)
    return re.sub(r",\s*,", ",", text).strip()


def _first_sentence(text: str, limit: int = 220) -> str:
    text = " ".join(str(text or "").split())
    m = re.match(r"(.+?[.!?])(\s|$)", text)
    out = m.group(1) if m else text
    return out if len(out) <= limit else out[:limit - 3].rstrip() + "..."


# Counters a sensor keeps only in memory

def tally(name: str, add: int = 1, note: str = None, day: date = None) -> None:
    """Add to one of today's counters. Raises on a database error."""
    day = day or date.today()
    with me._get_conn() as conn:
        conn.execute(
            "INSERT INTO daily_tally (day, name, value, note, updated) "
            "VALUES (?,?,?,?,?) ON CONFLICT(day, name) DO UPDATE SET "
            "value = value + excluded.value, "
            "note = COALESCE(excluded.note, note), updated = excluded.updated",
            (day.isoformat(), name, int(add), note,
             _sql(datetime.now(timezone.utc))))


# Reading the day

def _has(conn, table: str) -> bool:
    return me._table_exists_ro(conn, table)


def ran_on(conn, start: datetime, end: datetime) -> bool:
    """Whether the app recorded anything in the window."""
    for table, col in (("watcher_run", "ran_at"), ("duty_run", "ran_at")):
        if _has(conn, table) and conn.execute(
                f"SELECT 1 FROM {table} WHERE {col} >= ? AND {col} < ? "
                f"LIMIT 1", (_sql(start), _sql(end))).fetchone():
            return True
    return False


def _last_activity_before(conn, before: datetime):
    best = None
    for table, col in (("watcher_run", "ran_at"), ("duty_run", "ran_at"),
                       ("daily_report", "window_end")):
        if not _has(conn, table):
            continue
        row = conn.execute(f"SELECT MAX({col}) FROM {table} WHERE {col} < ?",
                           (_sql(before),)).fetchone()
        t = _parse(row[0]) if row else None
        if t and (best is None or t > best):
            best = t
    return best


def _first_activity(conn, start: datetime, end: datetime):
    best = None
    for table in ("watcher_run", "duty_run"):
        if not _has(conn, table):
            continue
        row = conn.execute(f"SELECT MIN(ran_at) FROM {table} WHERE ran_at >= ? "
                           f"AND ran_at < ?", (_sql(start), _sql(end))).fetchone()
        t = _parse(row[0]) if row else None
        if t and (best is None or t < best):
            best = t
    return best


def _names(conn) -> dict:
    """Address or hardware address to the name the inventory gives it."""
    out = {}
    if not _has(conn, "known_devices"):
        return out
    for r in conn.execute("SELECT ip, mac, known_as, hostname FROM known_devices "
                          "WHERE merged_into IS NULL"):
        name = r["known_as"] or r["hostname"]
        if name:
            for key in (r["ip"], r["mac"]):
                if key:
                    out[str(key).lower()] = name
    return out


def _who(value, names: dict) -> str:
    value = str(value or "")
    name = names.get(value.lower())
    return f'"{name}" ({value})' if name else value


def _findings(conn, start, end, ids) -> list:
    if not _has(conn, "findings"):
        return []
    marks = ",".join("?" * len(ids))
    return [dict(r) for r in conn.execute(
        f"SELECT id, detection_id, severity, entity_value, title, found_at, "
        f"dismissed, dismissed_reason FROM findings WHERE found_at >= ? "
        f"AND found_at < ? AND detection_id IN ({marks}) ORDER BY found_at",
        (_sql(start), _sql(end), *ids)).fetchall()]


def _merge(intervals: list) -> list:
    out = []
    for a, b in sorted(i for i in intervals if i[1] > i[0]):
        if out and a <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def _coverage(start: datetime, end: datetime, day: date) -> dict:
    from core import sensor_watch
    gaps = sensor_watch.gaps(_sql(start), _sql(end))
    first = _parse(sensor_watch.watched_since())
    off, quiet = [], []
    for g in gaps:
        a, b = _parse(g["start"]), _parse(g["end"])
        if not a or not b or b <= a:
            continue
        item = {"label": g["label"], "reason": g.get("reason") or "",
                "start": a, "end": b, "open": g.get("open")}
        (off if g["sensor"] == sensor_watch.APP else quiet).append(item)
    # Before the next start records it, the time after the last check is
    # off time that no gap row holds yet.
    w = getattr(sensor_watch, "_watch", None)
    if not (w is not None and getattr(w, "_booted", False)):
        beat = sensor_watch._last_beat()
        last = datetime.fromtimestamp(beat, timezone.utc) if beat else None
        if last and last < end and not any(o["end"] >= end for o in off):
            off.append({"label": "AgentalSec", "open": True,
                        "reason": "AgentalSec was not running",
                        "start": max(last, start), "end": end})
    unchecked = []
    if first is None or first >= end:
        unchecked.append((start, end))
    elif first > start:
        unchecked.append((start, first))
    lost = _merge([(o["start"], o["end"]) for o in off] + unchecked)
    window = (end - start).total_seconds()
    watched = window - sum((b - a).total_seconds() for a, b in lost)
    return {"window_seconds": window, "watched_seconds": max(0, watched),
            "off": off, "quiet": quiet, "unchecked": unchecked}


def _incidents(conn, start, end, names, day) -> dict:
    if not _has(conn, "incident"):
        return {"rows": [], "older_open": 0}
    rows = [dict(r) for r in conn.execute(
        "SELECT id, detection_id, entity_value, severity, severity_rank, title, "
        "first_seen_at, last_seen_at, finding_count, status, assessment "
        "FROM incident WHERE last_seen_at >= ? AND first_seen_at < ? "
        "AND COALESCE(suppressed, 0) = 0 ORDER BY first_seen_at",
        (_sql(start), _sql(end))).fetchall()]
    older_open = conn.execute(
        "SELECT COUNT(*) FROM incident WHERE last_seen_at < ? "
        "AND status IN ('new','action_pending') "
        "AND COALESCE(suppressed, 0) = 0", (_sql(start),)).fetchone()[0]

    verdicts, pending, actions = {}, {}, {}
    ids = [r["id"] for r in rows]
    if ids and _has(conn, "duty_report"):
        marks = ",".join("?" * len(ids))
        for r in conn.execute(
                f"SELECT incident_id, verdict, hypothesis, body FROM duty_report "
                f"WHERE incident_id IN ({marks}) ORDER BY id", ids):
            verdicts[r["incident_id"]] = dict(r)
    if ids and _has(conn, "action_request"):
        marks = ",".join("?" * len(ids))
        for r in conn.execute(
                f"SELECT id, incident_id, verb, target, state, decided_at, "
                f"decided_by, executed_at FROM action_request "
                f"WHERE incident_id IN ({marks}) ORDER BY id", ids):
            actions.setdefault(r["incident_id"], []).append(dict(r))
            if r["state"] == "pending":
                pending[r["incident_id"]] = dict(r)

    out = []
    for r in rows:
        v = verdicts.get(r["id"]) or {}
        verdict = (v.get("verdict") or "").strip()
        # A real incident stays real after it was dealt with.
        handled = r["status"] == "resolved" or any(
            a["state"] == "executed" for a in actions.get(r["id"], []))
        if verdict == "real" and handled:
            kind, words = "real", "real, dealt with"
        elif r["status"] == "resolved":
            kind, words = "resolved", ("resolved, action taken" if handled
                                       else "resolved")
        elif r["status"] == "dismissed":
            kind, words = "harmless", "harmless, dismissed"
        elif r["id"] in pending or verdict == "needs_human" \
                or r["status"] == "action_pending":
            kind, words = "decision", "needs your decision"
        elif verdict == "real":
            kind, words = "real", "real"
        elif verdict in ("benign", "no_action"):
            kind, words = "harmless", "harmless"
        else:
            kind, words = "open", "still open"
        note = v.get("hypothesis") or r.get("assessment") or v.get("body")
        out.append({
            "id": r["id"], "detection_id": r["detection_id"],
            "severity": r["severity"], "rank": r["severity_rank"] or 0,
            "title": plain(r["title"]), "who": _who(r["entity_value"], names),
            "first": _parse(r["first_seen_at"]),
            "last": _parse(r["last_seen_at"]),
            "count": r["finding_count"] or 1, "kind": kind, "outcome": words,
            "handled": handled,
            "note": plain(_first_sentence(note)) if note else "",
            "pending": pending.get(r["id"]),
            "actions": actions.get(r["id"], []),
        })
    return {"rows": out, "older_open": older_open}


def _fold(rows: list) -> list:
    """Harmless repeats of one detection become one row with a count."""
    shown, groups = [], {}
    for r in rows:
        if r["kind"] == "harmless":
            key = r["detection_id"] or r["title"]
            if key in groups:
                g = groups[key]
                g["times"] += 1
                g["last"] = max(g["last"] or r["last"], r["last"] or g["last"])
                g["who_set"].add(r["who"])
                continue
            g = dict(r, times=1, who_set={r["who"]})
            groups[key] = g
            shown.append(g)
        else:
            shown.append(dict(r, times=1, who_set={r["who"]}))
    for g in shown:
        if g["times"] > 1:
            g["title"] = f"{g['title']}, {g['times']} times"
            if len(g["who_set"]) > 1:
                g["who"] = _n(len(g["who_set"]), "subject")
    order = {"real": 0, "decision": 1, "open": 2, "resolved": 3, "harmless": 4}
    shown.sort(key=lambda g: (order.get(g["kind"], 5), -g["rank"],
                              g["first"] or datetime.min.replace(
                                  tzinfo=timezone.utc)))
    return shown


SUCCESS_SKIP = ("cron:session", "systemd-user:session", "lightdm-greeter",
                "sudo:session", "sudo-i:session", "su:session", "su-l:session",
                "polkit", "gdm-launch-environment")


def _service(description: str) -> str:
    d = (description or "").lower()
    if "sshd" in d or "ssh" in d.split(":")[0]:
        return "SSH"
    if "sudo" in d:
        return "sudo"
    if any(w in d for w in ("lightdm", "gdm", "sddm", "xdm")):
        return "desktop"
    if re.search(r"\bsu\b|\bsu-l\b|\(su\b", d):
        return "su"
    if "login" in d:
        return "console"
    return "other"


def _local_address(ip: str) -> bool:
    ip = (ip or "").strip().lower()
    return (not ip or ip.startswith("127.") or ip in ("::1", "localhost")
            or ip.startswith("::ffff:127."))


def _private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _logins(conn, start, end) -> dict:
    out = {"failed": {}, "failed_total": 0, "failed_from": set(),
           "success": 0, "remote": {}}
    if not _has(conn, "events"):
        out["blind"] = True
        return out
    for r in conn.execute(
            "SELECT event_type, username, src_ip, description FROM events "
            "WHERE occurred_at >= ? AND occurred_at < ? AND event_type IN "
            "('failed_login','successful_login')", (_sql(start), _sql(end))):
        desc = r["description"] or ""
        if r["event_type"] == "failed_login":
            svc = _service(desc)
            out["failed"][svc] = out["failed"].get(svc, 0) + 1
            out["failed_total"] += 1
            if r["src_ip"]:
                out["failed_from"].add(r["src_ip"])
            continue
        if any(s in desc for s in SUCCESS_SKIP):
            continue
        out["success"] += 1
        if r["src_ip"] and not _local_address(r["src_ip"]):
            out["remote"][r["src_ip"]] = out["remote"].get(r["src_ip"], 0) + 1
    return out


def _new_ports(conn, start, end) -> list:
    if not _has(conn, "port_owner_change"):
        return []
    rows = conn.execute(
        "SELECT p.proto, p.local_port, p.local_address, p.comm, p.detected_at "
        "FROM port_owner_change p WHERE p.kind = 'appeared' "
        "AND p.detected_at >= ? AND p.detected_at < ? AND NOT EXISTS ("
        "SELECT 1 FROM port_owner_change q WHERE q.proto = p.proto "
        "AND q.local_port = p.local_port AND q.detected_at < ?) "
        "ORDER BY p.detected_at", (_sql(start), _sql(end), _sql(start)))
    seen, out = set(), []
    for r in rows:
        # A UDP socket on a high port is a client's, not a service.
        if _local_address(r["local_address"]) or (
                r["proto"] == "udp" and (r["local_port"] or 0) >= EPHEMERAL_FLOOR):
            continue
        key = (r["proto"], r["local_port"])
        if key not in seen:
            seen.add(key)
            out.append(dict(r))
    return out


def _tallies(conn, day: date) -> dict:
    if not _has(conn, "daily_tally"):
        return {}
    return {r["name"]: {"value": r["value"], "note": r["note"]}
            for r in conn.execute("SELECT name, value, note FROM daily_tally "
                                  "WHERE day = ?", (day.isoformat(),))}


def _hash_checks(conn, start, end) -> dict:
    out = {"checked": 0, "flagged": []}
    if not _has(conn, "enrichment"):
        return out
    for r in conn.execute(
            "SELECT indicator, fields_json FROM enrichment WHERE kind = 'hash' "
            "AND fetched_at >= ? AND fetched_at < ?", (_iso(start), _iso(end))):
        out["checked"] += 1
        try:
            fields = json.loads(r["fields_json"] or "{}")
        except ValueError:
            fields = {}
        if fields.get("known_malware"):
            out["flagged"].append(r["indicator"])
    return out


def _lan(conn, start, end, names) -> dict:
    out = {"devices": 0, "top": None}
    if not _has(conn, "lan_traffic_minute"):
        return out
    rows = conn.execute(
        "SELECT ip, SUM(up_bytes) AS up FROM lan_traffic_minute "
        "WHERE minute >= ? AND minute < ? GROUP BY ip ORDER BY up DESC",
        (_iso(start), _iso(end))).fetchall()
    out["devices"] = len(rows)
    if rows and rows[0]["up"]:
        out["top"] = {"who": _who(rows[0]["ip"], names),
                      "bytes": int(rows[0]["up"])}
    return out


def _bytes(n: int) -> str:
    for unit, size in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{n} bytes"


def _actions(conn, start, end) -> dict:
    out = {"taken": [], "pending": [], "refused": []}
    for f in _findings(conn, start, end, _rem_ids()):
        out["taken"].append({"at": _parse(f["found_at"]),
                             "text": plain(f["title"])})
    if _has(conn, "action_request"):
        for r in conn.execute(
                "SELECT id, verb, target, state, reason, decided_at, "
                "created_at FROM action_request WHERE state = 'pending' "
                "OR (decided_at >= ? AND decided_at < ? AND state IN "
                "('denied','failed','expired'))", (_sql(start), _sql(end))):
            item = {"verb": r["verb"].replace("_", " "), "target": r["target"],
                    "state": r["state"], "id": r["id"],
                    "at": _parse(r["decided_at"] or r["created_at"])}
            (out["pending"] if r["state"] == "pending"
             else out["refused"]).append(item)
    return out


def _rem_ids() -> tuple:
    return tuple(f"REM-{n}" for n in range(1001, 1030))


def _agent(conn, start, end) -> dict:
    if not _has(conn, "duty_run"):
        return {"runs": 0, "tokens": 0}
    r = conn.execute(
        "SELECT COUNT(*), COALESCE(SUM(tokens_spent), 0) FROM duty_run "
        "WHERE ran_at >= ? AND ran_at < ? AND COALESCE(model_calls, 0) > 0",
        (_sql(start), _sql(end))).fetchone()
    return {"runs": r[0], "tokens": r[1]}


def _alerts(conn, start, end) -> dict:
    if not _has(conn, "findings"):
        return {"raised": 0, "dismissed": 0}
    raised = conn.execute("SELECT COUNT(*) FROM findings WHERE found_at >= ? "
                          "AND found_at < ?", (_sql(start), _sql(end))
                          ).fetchone()[0]
    dismissed = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE dismissed = 1 AND dismissed_at >= ? "
        "AND dismissed_at < ?", (_sql(start), _sql(end))).fetchone()[0]
    return {"raised": raised, "dismissed": dismissed}


def window_for(conn, day: date, written: datetime) -> tuple:
    """From the end of the previous report when it ended the evening before,
    else local midnight; to the time of writing or the end of the day."""
    start, end = day_bounds(day)
    if _has(conn, "daily_report"):
        row = conn.execute(
            "SELECT window_end FROM daily_report WHERE day < ? "
            "ORDER BY day DESC LIMIT 1", (day.isoformat(),)).fetchone()
        prev = _parse(row[0]) if row else None
        if prev and start - timedelta(hours=12) <= prev < start:
            start = prev
    return start, min(written, end)


def collect(day: date, written: datetime = None) -> dict:
    """Every fact the report shows, counted from the database."""
    written = written or datetime.now(timezone.utc)
    with me._get_readonly_conn() as conn:
        start, end = window_for(conn, day, written)
        names = _names(conn)
        day_start = day_bounds(day)[0]
        last = _last_activity_before(conn, day_start)
        first = _first_activity(conn, day_start, end)
        off_before = None
        if last and first and (_local_day(first) - _local_day(last)).days > 1:
            skipped = (_local_day(last) + timedelta(days=1),
                       _local_day(first) - timedelta(days=1))
            off_before = {"from": last, "to": first, "skipped": skipped}
        facts = {
            "day": day, "start": start, "end": end, "written": written,
            "host": socket.gethostname() or "this computer",
            "off_before": off_before,
            "coverage": _coverage(start, end, day),
            "incidents": _incidents(conn, start, end, names, day),
            "logins": _logins(conn, start, end),
            "into_host": _findings(conn, start, end, INTO_HOST),
            "new_access": [f for f in _findings(conn, start, end, NEW_ACCESS)
                           if "known_hosts" not in (f["title"] or "")],
            "scans": _findings(conn, start, end, SCANS),
            "new_ports": _new_ports(conn, start, end),
            "returned": _findings(conn, start, end, RETURNED),
            "tally": _tallies(conn, day),
            "av_hits": _findings(conn, start, end, MALWARE_AV),
            "quarantined": _findings(conn, start, end, QUARANTINED),
            "hashes": _hash_checks(conn, start, end),
            "masquerade": _findings(conn, start, end, MASQUERADE),
            "odd_places": _findings(conn, start, end, ODD_PLACES),
            "startup": _findings(conn, start, end, STARTUP),
            "system_files": _findings(conn, start, end, SYSTEM_FILES),
            "new_devices": _findings(conn, start, end, NEW_DEVICES),
            "uploads": _findings(conn, start, end, UPLOADS),
            "places": _findings(conn, start, end, PLACES),
            "threat_list": _findings(conn, start, end, THREAT_LIST),
            "lan": _lan(conn, start, end, names),
            "actions": _actions(conn, start, end),
            "agent": _agent(conn, start, end),
            "alerts": _alerts(conn, start, end),
            "kept": (conn.execute("SELECT COUNT(*) FROM daily_report").fetchone()[0]
                     if _has(conn, "daily_report") else 0),
        }
    facts["folded"] = _fold(facts["incidents"]["rows"])
    facts["status"] = _status(facts)
    facts["brief"] = _brief(facts)
    facts["could_not_check"] = _could_not_check(facts)
    return facts


# Judgements made by code

def _distinct(rows: list) -> list:
    seen = []
    for r in rows:
        v = r.get("entity_value")
        if v and v not in seen:
            seen.append(v)
    return seen


def _watched_words(f: dict) -> str:
    cov = f["coverage"]
    if cov["watched_seconds"] >= cov["window_seconds"] - 60:
        return "the whole time"
    window = cov["window_seconds"]
    total = (f"{round(window / 3600)} h" if window <= 48 * 3600
             else _dur(window))
    return f"{_dur(cov['watched_seconds'])} of the {total}"


def _into_signs(f: dict) -> list:
    signs = []
    if f["into_host"]:
        signs.append("a run of failed logins was followed by a success")
    if f["new_access"]:
        signs.append(_n(len(f["new_access"]), "new account, group or key change",
                        "new accounts, groups or key changes"))
    if f["returned"]:
        signs.append("a blocked device came back")
    return signs


def _all_quarantined(f: dict) -> bool:
    hits = {r["entity_value"] for r in f["av_hits"]}
    return bool(hits) and hits <= {r["entity_value"] for r in f["quarantined"]}


def _status(f: dict) -> dict:
    rows = f["incidents"]["rows"]
    real = [r for r in rows if r["kind"] == "real"]
    open_real = [r for r in real if not r.get("handled")]
    decide = ([r for r in rows if r["kind"] == "decision"]
              + [p for p in f["actions"]["pending"]
                 if p["id"] not in {(r["pending"] or {}).get("id")
                                    for r in rows}])
    malware = bool(f["av_hits"] or f["hashes"]["flagged"])
    into = _into_signs(f)
    cov = f["coverage"]
    share = (cov["watched_seconds"] / cov["window_seconds"]
             if cov["window_seconds"] else 0)

    parts = []
    if real:
        parts.append(f"{_n(len(real), 'real problem')} found"
                     + (", and dealt with." if not open_real
                        else "." if len(open_real) == len(real)
                        else f", {len(real) - len(open_real)} dealt with."))
    if decide:
        parts.append("One thing needs your decision." if len(decide) == 1
                     else f"{len(decide)} things need your decision.")
    parts.append("Signs that someone may have got in, see below." if into
                 else "No sign that anyone got in.")
    av = f["tally"]
    if malware:
        parts.append("Malware found and quarantined." if _all_quarantined(f)
                     else "Malware found.")
    elif (av.get("av_passes") or {}).get("value"):
        parts.append("No malware found.")
    else:
        parts.append("No malware found by the checks that ran; the virus "
                     "scan did not run.")
    parts.append(f"The sensors were watching for {_watched_words(f)}.")

    if open_real or malware or f["into_host"]:
        level = "red"
    elif real or decide or into or share < WATCHED_AMBER or cov["quiet"]:
        level = "amber"
    else:
        level = "green"
    return {"level": level, "sentence": " ".join(parts),
            "decide": decide, "real": real}


def _brief(f: dict) -> list:
    lines = []
    day = f["day"]
    for r in f["status"]["real"]:
        lines.append(f"{r['title']} ({r['who']}), {_span(r['first'], r['last'], day)}. "
                     + ("Judged real and dealt with." if r.get("handled")
                        else "Judged real."))
    for d in f["status"]["decide"]:
        if "title" in d:
            lines.append(f"{d['title']} ({d['who']}), first seen "
                         f"{_hm(d['first'], day)}. It needs your decision.")
        else:
            lines.append(f"A card is waiting for you: {d['verb']} {d['target']}.")
    lg = f["logins"]
    if lg["failed_total"]:
        lines.append(f"{_n(lg['failed_total'], 'failed login')}"
                     + (f" from {_n(len(lg['failed_from']), 'address', 'addresses')}"
                        if lg["failed_from"] else "")
                     + ("; none was followed by a success." if not f["into_host"]
                        else "; one run was followed by a success."))
    harmless = [g for g in f["folded"] if g["kind"] == "harmless"]
    if harmless:
        total = sum(g["times"] for g in harmless)
        top = max(harmless, key=lambda g: g["times"])
        lines.append(f"{_n(total, 'incident')} judged harmless, the most common "
                     f"being {top['title'][0].lower() + top['title'][1:]}.")
    for o in f["coverage"]["off"]:
        lines.append(f"AgentalSec was off {_span(o['start'], o['end'], day)}.")
    if not lines:
        lines.append("A quiet day: no incidents, no failed logins, nothing "
                     "waiting for you.")
    return lines[:3]


def _could_not_check(f: dict) -> str:
    day = f["day"]
    cov = f["coverage"]
    parts = []
    for a, b in cov["unchecked"]:
        parts.append(f"whether the sensors were running {_span(a, b, day)}, "
                     f"before the sensor check started")
    for o in cov["off"]:
        parts.append(f"anything while the app was off ({_span(o['start'], o['end'], day)})")
    for q in cov["quiet"]:
        parts.append(f"what the {q['label']} would have seen "
                     f"{_span(q['start'], q['end'], day)}")
    av = f["tally"]
    if not (av.get("av_passes") or {}).get("value"):
        parts.append("files for viruses, because "
                     + ("ClamAV is not installed" if (av.get("av_missing") or {}).get("value")
                        else "the virus scanner did not run"))
    if not f["lan"]["devices"]:
        parts.append("traffic of the other devices on the network, because "
                     "Live LAN counted none")
    if not parts:
        return "Nothing: every sensor collected for the whole report."
    return "; ".join(parts[:6]) + "."


# The assessment, the only model text

ASSESS_SYSTEM = (
    "You write the assessment at the end of a home network's daily security "
    "report. The facts below were counted by code from the database and are "
    "correct; do not add facts, numbers or events that are not in them. Write "
    "as the agent, to the owner, in the first person: plain sentences, direct, "
    "no preamble, no drama, no hedging. Say what mattered today and why. Never "
    "use a dash or a vertical bar as punctuation; use commas. Use local 24-hour "
    "times as given. Answer with JSON only: {\"assessment\": \"2 to 4 "
    "sentences\", \"recommendations\": [\"up to 3 short actions, most "
    "important first\"]}. If nothing needs doing, one recommendation saying "
    "so is enough.")


def digest(f: dict) -> str:
    """The facts as short lines for the model."""
    day = f["day"]
    lines = [f"Report day: {_long_day(day)}, window {_span(f['start'], f['end'], day)}.",
             f"Status: {f['status']['level']}. {f['status']['sentence']}",
             "Coverage: " + f["could_not_check"]]
    for g in f["folded"][:15]:
        lines.append(f"Incident: {_span(g['first'], g['last'], day)}, "
                     f"{g['severity']}, {g['title']}, {g['who']}, outcome "
                     f"{g['outcome']}" + (f". Note: {g['note']}" if g["note"] else ""))
    if f["incidents"]["older_open"]:
        lines.append(f"Older incidents not looked at yet: {f['incidents']['older_open']}.")
    for label, value in _attempt_rows(f) + _malware_rows(f):
        lines.append(f"{label}: {value[0]}, {value[1]}")
    for line in _network_lines(f):
        lines.append("Network: " + line)
    acts = f["actions"]
    lines.append(f"Actions taken: {len(acts['taken'])}; cards waiting: "
                 f"{len(acts['pending'])}.")
    return "\n".join(lines)


def _parse_assessment(text: str) -> dict:
    m = re.search(r"\{.*\}", text or "", re.S)
    data = {}
    if m:
        try:
            data = json.loads(m.group(0))
        except ValueError:
            data = {}
    body = plain(data.get("assessment") or (text or "").strip())
    recs = [plain(r) for r in (data.get("recommendations") or [])
            if str(r).strip()][:3]
    return {"text": body, "recommendations": recs}


def assess(f: dict, may_spend: bool, why_not: str = "") -> dict:
    if not may_spend:
        return {"text": "", "recommendations": [], "usage": {},
                "error": why_not or "the token budget is spent"}
    from core import agent_loop
    from core import duty
    res = agent_loop.complete_once(ASSESS_SYSTEM + "\n\n" + duty.REPORT_VOICE,
                                   digest(f))
    if res.get("error") or not (res.get("text") or "").strip():
        return {"text": "", "recommendations": [], "usage": res.get("usage") or {},
                "error": res.get("error") or "the model gave no answer"}
    return dict(_parse_assessment(res["text"]), usage=res.get("usage") or {},
                error=None)


# Rendering

CSS = """
  :root { --bg:#ffffff; --text:#1d2330; --dim:#5d6676; --line:#dde2ea; --soft:#f5f7fa;
          --green:#1e8e5a; --amber:#b7791f; --red:#c0392b; --grey:#8a93a3; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text);
         font:14px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  .page { max-width:860px; margin:0 auto; padding:28px 20px 40px; }
  h1 { font-size:22px; margin:0 0 2px; }
  h2 { font-size:15px; text-transform:uppercase; letter-spacing:.06em; color:var(--dim);
       border-bottom:1px solid var(--line); padding-bottom:4px; margin:28px 0 10px; }
  h3 { font-size:14px; margin:0 0 4px; }
  .meta { color:var(--dim); font-size:13px; }
  .status { display:flex; gap:14px; align-items:center; margin:18px 0 6px; padding:14px 16px;
            border-radius:8px; background:var(--soft); border-left:6px solid var(--grey); }
  .status.green { border-left-color:var(--green); } .status.amber { border-left-color:var(--amber); }
  .status.red { border-left-color:var(--red); }
  .badge { font-weight:700; font-size:13px; padding:3px 10px; border-radius:20px; color:#fff; }
  .b-green{background:var(--green)} .b-amber{background:var(--amber)} .b-red{background:var(--red)} .b-grey{background:var(--grey)}
  ul { margin:6px 0; padding-left:20px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top;
           overflow-wrap:break-word; }
  td.nw { white-space:nowrap; }
  .tw { overflow-x:auto; }
  th { color:var(--dim); font-weight:600; font-size:12px; }
  .mono { font-family:ui-monospace, Menlo, Consolas, monospace; font-size:12px; }
  .card { border:1px solid var(--line); border-radius:8px; padding:12px 14px; margin:10px 0; }
  .card.red { border-left:5px solid var(--red); } .card.amber { border-left:5px solid var(--amber); }
  .kv { display:grid; grid-template-columns:130px 1fr; gap:2px 12px; font-size:13px; margin-top:6px; }
  .kv div:nth-child(odd) { color:var(--dim); }
  .bar { position:relative; height:16px; background:var(--green); border-radius:3px; margin:8px 0 2px; overflow:hidden; }
  .gap { position:absolute; top:0; bottom:0; }
  .axis { display:flex; justify-content:space-between; color:var(--dim); font-size:11px; }
  .ok { color:var(--green); font-weight:600; } .warn { color:var(--amber); font-weight:600; } .bad { color:var(--red); font-weight:600; }
  .foot { color:var(--dim); font-size:12px; margin-top:30px; border-top:1px solid var(--line); padding-top:10px; }
  .note { color:var(--dim); font-size:12px; }
  @media (max-width:600px) { .kv { grid-template-columns:1fr; } .kv div:nth-child(even) { margin-bottom:6px; }
    .status { flex-direction:column; align-items:flex-start; } th, td { padding:5px 4px; } }
  @media print { .page { padding:0; } h2 { break-after:avoid; } .card, tr { break-inside:avoid; } }
"""


def _e(text) -> str:
    return html.escape(str(text if text is not None else ""))


def _sev_class(sev: str) -> str:
    return {"critical": "bad", "high": "bad", "medium": "", "low": ""}.get(
        (sev or "").lower(), "")


def _out_class(kind: str) -> str:
    return {"real": "bad", "decision": "warn", "resolved": "ok"}.get(kind, "")


def _result(rows: list, none_text: str = "none") -> tuple:
    """(count text, result html) for a list of findings."""
    if not rows:
        return "0", f'<span class="ok">{_e(none_text)}</span>'
    subjects = _distinct(rows)
    dismissed = sum(1 for r in rows if r.get("dismissed"))
    text = ", ".join(subjects[:2]) + (f" and {len(subjects) - 2} more"
                                      if len(subjects) > 2 else "")
    if dismissed:
        text += f"; {dismissed} dismissed as harmless"
    return str(len(rows)), _e(text)


def _attempt_rows(f: dict) -> list:
    lg = f["logins"]
    if lg.get("blind"):
        failed = ("not checked", "the log reader has no events table")
    elif lg["failed_total"]:
        by = ", ".join(f"{n} {svc}" for svc, n in
                       sorted(lg["failed"].items(), key=lambda x: -x[1]))
        failed = (by, "a run was followed by a success" if f["into_host"]
                  else "none was followed by a success from the same address")
    else:
        failed = ("0", "none")
    if lg["remote"]:
        public = sorted(ip for ip in lg["remote"] if not _private(ip))
        who = ", ".join(public or sorted(lg["remote"]))
        success = (str(lg["success"]),
                   f"from the internet: {who}" if public
                   else f"from devices on your network: {who}")
    else:
        success = (str(lg["success"]), "all at this computer" if lg["success"]
                   else "none")
    ports = f["new_ports"]
    port_text = ", ".join(f"{p['proto']} {p['local_port']} ({p['comm'] or '?'})"
                          for p in ports[:4])
    return [
        ("Failed logins (SSH, desktop, sudo)", failed),
        ("Successful logins", success),
        ("Scans of this computer", (str(len(f["scans"])),
                                    "none seen" if not f["scans"]
                                    else ", ".join(_distinct(f["scans"])[:3]))),
        ("New open ports", (str(len(ports)), port_text or "none")),
        ("New users, groups, SSH keys", (str(len(f["new_access"])),
                                         "no change" if not f["new_access"]
                                         else ", ".join(_distinct(f["new_access"])[:3]))),
        ("Blocked devices that came back", (str(len(f["returned"])),
                                            "none" if not f["returned"]
                                            else ", ".join(_distinct(f["returned"])[:3]))),
    ]


def _malware_rows(f: dict) -> list:
    t = f["tally"]
    passes = (t.get("av_passes") or {}).get("value") or 0
    if passes:
        files = (t.get("av_files") or {}).get("value") or 0
        sig = (t.get("av_passes") or {}).get("note")
        av = (f"{_n(passes, 'pass', 'passes')}, {_n(files, 'file')}",
              (("match found, quarantined" if _all_quarantined(f)
                else "match found, NOT quarantined") if f["av_hits"]
               else "no match")
              + (f"; signatures dated {sig}" if sig else ""))
    elif (t.get("av_missing") or {}).get("value"):
        av = ("not checked", "ClamAV is not installed")
    else:
        av = ("not checked", "the virus scanner did not run")
    h = f["hashes"]
    return [
        ("Virus scans (ClamAV)", av),
        ("Program files looked up by hash (MalwareBazaar)",
         (str(h["checked"]), (f"{len(h['flagged'])} known malware"
                              if h["flagged"] else "no match"))),
        ("Programs pretending to be system files", _plain_result(f["masquerade"])),
        ("Programs running from odd places (/tmp, Downloads, caches)",
         _plain_result(f["odd_places"])),
        ("New startup entries and services", _plain_result(f["startup"])),
        ("Changed system files", _plain_result(f["system_files"],
                                               "all match their packages")),
    ]


def _plain_result(rows: list, none_text: str = "none") -> tuple:
    if not rows:
        return "0", none_text
    subjects = _distinct(rows)
    text = ", ".join(subjects[:2]) + (f" and {len(subjects) - 2} more"
                                      if len(subjects) > 2 else "")
    dismissed = sum(1 for r in rows if r.get("dismissed"))
    if dismissed:
        text += f"; {dismissed} dismissed as harmless"
    return str(len(rows)), text


def _network_lines(f: dict) -> list:
    lan = f["lan"]
    new = _distinct(f["new_devices"])
    out = []
    if lan["devices"]:
        out.append(f"Devices: {lan['devices']} sent traffic. "
                   f"{len(new)} new" + (f" ({', '.join(new[:3])})" if new else "")
                   + ".")
    else:
        out.append("Devices: Live LAN counted no traffic, so the other devices "
                   "were not measured."
                   + (f" {len(new)} new device(s) reported: {', '.join(new[:3])}."
                      if new else ""))
    if f["uploads"]:
        out.append(f"Unusual uploads: {len(f['uploads'])}, from "
                   f"{', '.join(_distinct(f['uploads'])[:3])}.")
    else:
        top = lan.get("top")
        out.append("Unusual uploads: none."
                   + (f" The largest was {top['who']}, {_bytes(top['bytes'])}."
                      if top else ""))
    places = _distinct(f["places"])
    out.append(f"New countries or networks: {len(f['places'])}"
               + (f" ({', '.join(places[:3])})" if places else "") + ".")
    tl = f["threat_list"]
    dismissed = sum(1 for r in tl if r.get("dismissed"))
    out.append(f"Threat list contacts: {len(tl)}"
               + (f", from {', '.join(_distinct(tl)[:3])}" if tl else "")
               + (f"; {dismissed} dismissed as harmless" if dismissed else "")
               + ".")
    return out


def _bar(f: dict) -> str:
    cov = f["coverage"]
    start, end = f["start"], f["end"]
    total = (end - start).total_seconds() or 1

    def seg(a, b, colour, title):
        left = max(0.0, (a - start).total_seconds() / total * 100)
        width = max(0.4, (b - a).total_seconds() / total * 100)
        return (f'<div class="gap" style="left:{left:.2f}%;width:{width:.2f}%;'
                f'background:var(--{colour})" title="{_e(title)}"></div>')

    parts = [seg(a, b, "line", "not checked") for a, b in cov["unchecked"]]
    parts += [seg(o["start"], o["end"], "grey", "AgentalSec was off")
              for o in cov["off"]]
    parts += [seg(q["start"], q["end"], "amber", f"{q['label']} quiet")
              for q in cov["quiet"]]
    ticks = [start + (end - start) * i / 4 for i in range(5)]
    axis = "".join(f"<span>{_e(_hm(t, f['day']))}</span>" for t in ticks)
    return (f'<div class="bar">{"".join(parts)}</div>'
            f'<div class="axis">{axis}</div>')


def render(f: dict, a: dict) -> str:
    day = f["day"]
    st = f["status"]
    cov = f["coverage"]
    tz = f["written"].astimezone().strftime("%z")
    tz = f"UTC{tz[0]}{int(tz[1:3])}" + (f":{tz[3:]}" if tz[3:] != "00" else "")
    w = f["written"].astimezone()
    out = []
    add = out.append

    add("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"<title>Daily security report, {_e(_long_day(day))}</title>\n"
        f"<style>{CSS}</style>\n</head>\n<body><div class=\"page\">\n")
    add("<h1>Daily security report</h1>\n<div class=\"meta\">")
    add(f"<b>{_e(_long_day(day))}</b>, {_e(_span(f['start'], f['end'], day))} "
        f"local time ({_e(tz)}).<br>Written {_e(_short_day(w.date()))} at "
        f"{w:%H:%M} by AgentalSec on <b>{_e(f['host'])}</b>. All times below are "
        f"local, 24-hour.</div>\n")
    ob = f["off_before"]
    if ob:
        a1, a2 = ob["skipped"]
        days = (_short_day(a1) if a1 == a2
                else f"{_short_day(a1)} to {_short_day(a2)}")
        add(f'<p class="note"><b>AgentalSec was off from {_e(_hm(ob["from"], day))} '
            f'to {_e(_hm(ob["to"], day))}</b> ({_e(_dur((ob["to"] - ob["from"]).total_seconds()))}), '
            f"so there is no report for {_e(days)}.</p>\n")
    add(f'<div class="status {st["level"]}"><span class="badge b-{st["level"]}">'
        f'{st["level"].upper()}</span><div>{_e(st["sentence"])}</div></div>\n')

    add("<h2>The day in brief</h2>\n<ul>")
    add("".join(f"<li>{_e(line)}</li>" for line in f["brief"]))
    add("</ul>\n")

    if st["decide"]:
        add("<h2>Needs your decision</h2>\n")
        for d in st["decide"]:
            if "title" in d:
                p = d.get("pending")
                options = (f"Approve or deny the waiting card on the Actions tab: "
                           f"{p['verb'].replace('_', ' ')} {p['target']}."
                           if p else "Dismiss it on the Incidents tab if it is "
                           "expected, or ask the agent about it.")
                add(f'<div class="card amber"><h3>{_e(d["title"])}</h3><div class="kv">'
                    f"<div>First seen</div><div>{_e(_hm(d['first'], day))}"
                    f"{', last ' + _e(_hm(d['last'], day)) if d['last'] != d['first'] else ''}</div>"
                    f"<div>Subject</div><div class=\"mono\">{_e(d['who'])}</div>"
                    f"<div>Seen</div><div>{_e(_n(d['count'], 'time'))}, "
                    f"severity {_e(d['severity'])}</div>"
                    + (f"<div>Agent's view</div><div>{_e(d['note'])}</div>"
                       if d["note"] else "")
                    + f"<div>Your options</div><div>{_e(options)}</div></div></div>\n")
            else:
                add(f'<div class="card amber"><h3>Waiting card: {_e(d["verb"])} '
                    f'{_e(d["target"])}</h3><div class="kv"><div>Filed</div>'
                    f"<div>{_e(_hm(d['at'], day))}</div><div>Your options</div>"
                    f"<div>Approve or deny it on the Actions tab.</div></div></div>\n")

    add("<h2>Coverage: how much of the day was watched</h2>\n")
    add(_bar(f))
    add("<ul>")
    for o in cov["off"]:
        add(f"<li><b>AgentalSec was off</b> {_e(_span(o['start'], o['end'], day))} "
            f"({_e(_dur((o['end'] - o['start']).total_seconds()))}). Nothing was "
            f"recorded then.</li>")
    for q in cov["quiet"]:
        add(f"<li><b>{_e(q['label'][0].upper() + q['label'][1:])} quiet</b> "
            f"{_e(_span(q['start'], q['end'], day))}"
            + (f": {_e(plain(q['reason']))}" if q["reason"] else "")
            + ".</li>")
    for a1, a2 in cov["unchecked"]:
        add(f"<li><b>Not checked</b> {_e(_span(a1, a2, day))}: the sensor check "
            f"had not started, so whether the sensors ran is not known.</li>")
    if cov["quiet"] or cov["off"] or cov["unchecked"]:
        add("<li>Every other sensor collected all the time the app was running.</li>")
    else:
        add("<li>Every sensor collected for the whole report.</li>")
    add("</ul>\n<p class=\"note\">Read every \"nothing found\" below with this in "
        "mind: it covers the watched hours only.</p>\n")

    add("<h2>Incidents</h2>\n")
    rows = f["folded"]
    if rows:
        add("<div class=\"tw\"><table><tr><th>Time</th><th>Severity</th><th>What happened</th>"
            "<th>Who</th><th>Outcome</th></tr>")
        for g in rows[:TABLE_ROWS]:
            add(f"<tr><td>{_e(_span(g['first'], g['last'], day))}</td>"
                f'<td class="nw {_sev_class(g["severity"])}">{_e(g["severity"])}</td>'
                f"<td>{_e(g['title'])}</td><td class=\"mono\">{_e(g['who'])}</td>"
                f'<td class="{_out_class(g["kind"])}">{_e(g["outcome"])}</td></tr>')
        add("</table></div>\n")
        if len(rows) > TABLE_ROWS:
            add(f'<p class="note">{len(rows) - TABLE_ROWS} more on the Incidents '
                f"tab.</p>\n")
    else:
        add("<p>No incident in this report.</p>\n")
    if f["incidents"]["older_open"]:
        add(f'<p class="note">{_e(_n(f["incidents"]["older_open"], "incident"))} '
            f"from earlier days not looked at yet, on the Incidents tab.</p>\n")
    for r in st["real"]:
        acts = "; ".join(f"{x['verb'].replace('_', ' ')} {x['target']}, {x['state']}"
                         for x in r["actions"]) or "none filed"
        add(f'<div class="card red"><h3>{_e(r["title"])}, '
            f'{_e(_span(r["first"], r["last"], day))}</h3><div class="kv">'
            f"<div>What</div><div>{_e(_n(r['count'], 'finding'))} about "
            f"<span class=\"mono\">{_e(r['who'])}</span>, severity "
            f"{_e(r['severity'])}.</div>"
            + (f"<div>Agent's note</div><div>{_e(r['note'])}</div>"
               if r["note"] else "")
            + f"<div>Action</div><div>{_e(acts)}</div></div></div>\n")

    add("<h2>Attempts to get in</h2>\n<div class=\"tw\"><table><tr><th>Check</th><th>In this report"
        "</th><th>Result</th></tr>")
    for label, (count, result) in _attempt_rows(f):
        cls = "ok" if result in ("none", "none seen", "no change") else ""
        add(f"<tr><td>{_e(label)}</td><td>{_e(count)}</td>"
            f'<td class="{cls}">{_e(result)}</td></tr>')
    add("</table></div>\n")
    signs = _into_signs(f)
    if signs:
        add(f"<p><b>Verdict: look at this</b>: {_e('; '.join(signs))}. "
            f"Watched: {_e(_watched_words(f))}.</p>\n")
    else:
        add(f"<p><b>Verdict: no sign that anyone got in.</b> "
            f"Watched: {_e(_watched_words(f))}.</p>\n")

    add("<h2>Malware and suspicious programs</h2>\n<div class=\"tw\"><table><tr><th>Check</th>"
        "<th>Today</th><th>Result</th></tr>")
    for label, (count, result) in _malware_rows(f):
        cls = ("ok" if result.startswith(("no match", "none", "all match"))
               else "bad" if "malware" in result or "match found" in result
               else "")
        add(f"<tr><td>{_e(label)}</td><td>{_e(count)}</td>"
            f'<td class="{cls}">{_e(result)}</td></tr>')
    add("</table></div>\n")

    add("<h2>Your network</h2>\n<ul>")
    for line in _network_lines(f):
        head, _, rest = line.partition(":")
        add(f"<li><b>{_e(head)}:</b>{_e(rest)}</li>")
    add("</ul>\n")

    acts = f["actions"]
    add("<h2>Actions</h2>\n<ul>")
    if acts["taken"]:
        add("<li>Taken: " + _e("; ".join(f"{x['text']} ({_hm(x['at'], day)})"
                                         for x in acts["taken"][:6])) + ".</li>")
    else:
        add("<li>Taken: none.</li>")
    if acts["refused"]:
        add("<li>Denied, failed or expired: " + _e("; ".join(
            f"{x['verb']} {x['target']}, {x['state']}" for x in acts["refused"][:6]))
            + ".</li>")
    add(f"<li>Waiting for you: {_e(_n(len(acts['pending']), 'card'))}"
        + (" (" + _e("; ".join(f"{x['verb']} {x['target']}"
                               for x in acts["pending"][:4])) + ")"
           if acts["pending"] else "") + ".</li>")
    add("</ul>\n")

    add("<h2>The agent's assessment</h2>\n")
    if a.get("text"):
        add(f"<p>{_e(a['text'])}</p>\n")
        if a.get("recommendations"):
            add("<ol>" + "".join(f"<li>{_e(r)}</li>" for r in a["recommendations"])
                + "</ol>\n")
    else:
        add(f"<p>Not written: {_e(plain(a.get('error') or 'no answer'))}. The facts "
            f"above stand on their own.</p>\n")
    add(f'<p class="note">What I could not check: {_e(f["could_not_check"])}</p>\n')

    al, ag = f["alerts"], f["agent"]
    tokens = ag["tokens"] + int((a.get("usage") or {}).get("total_tokens") or 0)
    add(f'<div class="foot">{_e(_n(al["raised"], "alert"))} raised, '
        f"{al['dismissed']:,} dismissed as harmless, "
        f"{_e(_n(len(acts['pending']), 'card'))} waiting. The agent ran "
        f"{_e(_n(ag['runs'], 'time'))} in this report and used about "
        f"{_e(_tokens(tokens))} tokens.<br>Report {f['kept'] + 1} of {KEEP_DAYS} "
        f"kept. Reports are deleted after {KEEP_DAYS} days. Facts in this report "
        f"are counted from the database; only \"The agent's assessment\" is "
        f"written by the model.</div>\n</div></body>\n</html>\n")
    return "".join(out)


def _tokens(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f} million"
    if n >= 1000:
        return f"{n / 1000:.0f} thousand"
    return str(n)


# Writing, keeping and finding the reports

def exists(day: date) -> bool:
    with me._get_readonly_conn() as conn:
        if not _has(conn, "daily_report"):
            return True
        return bool(conn.execute("SELECT 1 FROM daily_report WHERE day = ?",
                                 (day.isoformat(),)).fetchone())


def write(day: date, session_id: str = None, *, trigger: str = "regular",
          now: datetime = None, use_model: bool = True) -> dict:
    """Build, assess and store the report for one day. Never writes twice."""
    from core import duty
    now = now or datetime.now(timezone.utc)
    with _write_lock:
        if exists(day):
            return {"outcome": "exists", "day": day.isoformat()}
        started = time.time()
        f = collect(day, now)
        if use_model:
            budget = duty.budget_state()
            a = assess(f, budget.get("may_spend"),
                       "the agent's budget refused it ("
                       + "; ".join(budget.get("reasons") or []) + ")")
        else:
            a = assess(f, False, "written without a model call")
        body = render(f, a)
        usage = a.get("usage") or {}
        with me._get_conn() as conn:
            conn.execute(
                "INSERT INTO daily_report (day, window_start, window_end, "
                "created_at, status, headline, html, facts_json, assessed, "
                "tokens_spent, session_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (day.isoformat(), _sql(f["start"]), _sql(f["end"]), _sql(now),
                 f["status"]["level"], f["status"]["sentence"], body,
                 json.dumps({"brief": f["brief"],
                             "could_not_check": f["could_not_check"]}),
                 1 if a.get("text") else 0,
                 int(usage.get("total_tokens") or 0), session_id))
        tag = (CATCH_UP_TAG if trigger == "manual" else DAILY_TAG)
        duty._record_run(
            session_id or "daily-report", trigger, "reported", usage=usage,
            detail=(f"{tag}{day.isoformat()}] {f['status']['level']}: "
                    f"{f['status']['sentence']}"
                    + ("" if a.get("text") else
                       f" No assessment: {a.get('error')}.")),
            started=started, at=now)
        expire(now)
    logger.info("Daily report for %s written (%s).", day, f["status"]["level"])
    return {"outcome": "reported", "kind": "daily", "day": day.isoformat(),
            "status": f["status"]["level"], "assessed": bool(a.get("text"))}


def expire(now: datetime = None) -> int:
    now = now or datetime.now(timezone.utc)
    cutoff = (_local_day(now) - timedelta(days=KEEP_DAYS)).isoformat()
    with me._get_conn() as conn:
        if not _has(conn, "daily_report"):
            return 0
        n = conn.execute("DELETE FROM daily_report WHERE day < ?",
                         (cutoff,)).rowcount
        conn.execute("DELETE FROM daily_tally WHERE day < ?", (cutoff,))
    return n


def missing_days(now: datetime) -> list:
    """Past days the app ran with no report, oldest first. With no report at
    all yet, only the latest such day, so a first start does not write a
    month of them."""
    today = _local_day(now)
    with me._get_readonly_conn() as conn:
        if not _has(conn, "daily_report"):
            return []
        row = conn.execute("SELECT MAX(day) FROM daily_report").fetchone()
        last = date.fromisoformat(row[0]) if row and row[0] else None
        out = []
        for back in range(KEEP_DAYS - 1, 0, -1):
            day = today - timedelta(days=back)
            if last and day <= last:
                continue
            start, end = day_bounds(day)
            if ran_on(conn, start, end) and not conn.execute(
                    "SELECT 1 FROM daily_report WHERE day = ?",
                    (day.isoformat(),)).fetchone():
                out.append(day)
    return out if last else out[-1:]


def _sensor_watch_ready(now_ts: float) -> bool:
    """True once the sensor watch has recorded when the app was off."""
    try:
        from core import sensor_watch
        w = sensor_watch._watch
    except Exception:                                       # noqa: BLE001
        w = None
    if w is not None and getattr(w, "_booted", False):
        return True
    return now_ts - _state["started"] >= BOOT_WAIT_SECONDS


def tick(session_id: str, now: datetime, last_wake_hour: int) -> dict | None:
    """One duty poll's share of the daily report. None when nothing is due.

    Today's report is due at the last wake hour or later. Missed days are
    looked for once an hour."""
    local = now.astimezone()
    today = local.date()
    if not _sensor_watch_ready(time.time()):
        return None
    if local.hour >= last_wake_hour and not exists(today):
        trigger = "regular" if local.hour == last_wake_hour else "manual"
        missed = [d for d in missing_days(now) if d < today]
        for day in missed:
            write(day, session_id, trigger="manual", now=now)
        return write(today, session_id, trigger=trigger, now=now)
    if time.time() >= _state["next_catch_up"]:
        _state["next_catch_up"] = time.time() + CATCH_UP_EVERY_SECONDS
        results = [write(day, session_id, trigger="manual", now=now)
                   for day in missing_days(now)]
        written = [r for r in results if r.get("outcome") == "reported"]
        return written[-1] if written else None
    return None


def list_reports(include_older: bool = False,
                 dismissed: bool = False) -> list:
    """Newest first. Dismissed reports are hidden unless dismissed is set,
    which lists only them; the latest only unless include_older."""
    with me._get_readonly_conn() as conn:
        if not _has(conn, "daily_report"):
            return []
        rows = conn.execute(
            "SELECT id, day, window_start, window_end, created_at, status, "
            "headline, assessed, tokens_spent, dismissed, dismissed_at "
            "FROM daily_report WHERE dismissed = ? ORDER BY day DESC"
            + ("" if include_older or dismissed else " LIMIT 1"),
            (1 if dismissed else 0,)).fetchall()
    return [dict(r) for r in rows]


def dismiss(report_ids: list, restore: bool = False) -> dict:
    """Hide the given reports, or show them again. Nothing is deleted."""
    try:
        ids = sorted({int(i) for i in report_ids or []})
    except (TypeError, ValueError):
        return {"success": False, "error": "report ids must be numbers"}
    if not ids:
        return {"success": False, "error": "no report was ticked"}
    marks = ",".join("?" * len(ids))
    stamp = None if restore else _sql(datetime.now(timezone.utc))
    with me._get_conn() as conn:
        n = conn.execute(
            f"UPDATE daily_report SET dismissed = ?, dismissed_at = ? "
            f"WHERE id IN ({marks}) AND dismissed = ?",
            (0 if restore else 1, stamp, *ids, 1 if restore else 0)).rowcount
    return {"success": True, "changed": n, "restored" if restore
            else "dismissed": ids}


def get_html(report_id: int) -> str | None:
    with me._get_readonly_conn() as conn:
        if not _has(conn, "daily_report"):
            return None
        row = conn.execute("SELECT html FROM daily_report WHERE id = ?",
                           (report_id,)).fetchone()
    return row["html"] if row else None


def count(dismissed: bool = False) -> int:
    with me._get_readonly_conn() as conn:
        if not _has(conn, "daily_report"):
            return 0
        return conn.execute("SELECT COUNT(*) FROM daily_report WHERE "
                            "dismissed = ?", (1 if dismissed else 0,)
                            ).fetchone()[0]
