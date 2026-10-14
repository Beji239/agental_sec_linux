# core/expectations.py
# Expectations the app sets and checks itself, with no model tokens: each
# block holds, the same devices stay, DNS goes through the router, the gateway
# does not change, nights stay quiet, the network keeps to known countries,
# smart devices keep to their usual contacts.
# The router's records are the evidence, and a check the router cannot back
# says "could not check" rather than "held".
#
# States: holding, new (something new, nothing broken), broken, unknown.
# The network mood follows from them: Calm, Curious, Uncertain, Alarmed.

import ipaddress
import json
import logging
import statistics
import threading
import time
from datetime import datetime, timedelta, timezone

from core import memory_engine as me

logger = logging.getLogger(__name__)

DEFAULTS = {"enabled": True, "interval_seconds": 300, "window_hours": 24,
            "night_start_hour": 1, "night_end_hour": 6,
            "night_factor": 3.0, "night_floor_mb": 100,
            "learn_hours": 72, "min_coverage": 0.5, "accept_dns": [],
            # Device types (Network tab) held to their usual contacts. TVs
            # reach new streaming services daily, so they are left out.
            "simple_types": ["iot", "printer"]}
MIN_AGENT_VERSION = 9
# Version 10 counts the packets each block caught, for the block wall.
WALL_AGENT_VERSION = 10
KEEP_CHECK_DAYS = 14
CHECK_ROW_EVERY = 3600
BLOCK_GRACE_SECONDS = 60
NIGHTS_NEEDED = 3

# Public resolvers a device can reach over DNS over HTTPS on port 443.
DOH_RESOLVERS = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15",
    "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888",
    "2001:4860:4860::8844", "2620:fe::fe", "2620:fe::9",
}

NETWORK_KINDS = {
    "head_count": "The same devices stay on the network",
    "dns_via_router": "Every device looks up names through the router",
    "same_gateway": "The router and the address handout stay the same",
    "quiet_nights": "Upload stays near its usual level at night",
    "known_countries": "The network keeps talking to the same countries",
    "blocks_hold": "All blocks hold",
    "usual_contacts": "Smart devices and printers keep to their usual contacts",
}
STATES = ("holding", "new", "broken", "unknown")

DDL = (
    """CREATE TABLE IF NOT EXISTS expectation (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    kind             TEXT NOT NULL,
    subject          TEXT NOT NULL DEFAULT '',
    title            TEXT NOT NULL,
    state            TEXT NOT NULL DEFAULT 'unknown'
                     CHECK (state IN ('holding','new','broken','unknown')),
    detail           TEXT,
    evidence_json    TEXT,
    known_json       TEXT,
    since            TEXT NOT NULL,
    last_checked_at  TEXT,
    broken_at        TEXT,
    acknowledged_at  TEXT,
    ended_at         TEXT,
    source           TEXT NOT NULL DEFAULT 'app'
)""",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_expectation_active "
    "ON expectation(kind, subject) WHERE ended_at IS NULL",
    """CREATE TABLE IF NOT EXISTS expectation_check (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    expectation_id  INTEGER NOT NULL REFERENCES expectation(id),
    checked_at      TEXT NOT NULL,
    result          TEXT NOT NULL
                    CHECK (result IN ('holding','new','broken','unknown')),
    detail          TEXT,
    coverage        REAL
)""",
    "CREATE INDEX IF NOT EXISTS idx_expectation_check "
    "ON expectation_check(expectation_id, checked_at)",
    # The router's count of packets each block caught, read every check.
    """CREATE TABLE IF NOT EXISTS block_hit (
    subject  TEXT NOT NULL,
    read_at  TEXT NOT NULL,
    packets  INTEGER NOT NULL,
    bytes    INTEGER NOT NULL,
    PRIMARY KEY (subject, read_at)
)""",
)

_instance = None


def settings(config: dict) -> dict:
    out = dict(DEFAULTS)
    out.update((config or {}).get("expectations") or {})
    return out


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


def _human(value) -> str:
    """A stored time as people read it, in this machine's time zone."""
    dt = _parse(value)
    return dt.astimezone().strftime("%H:%M on %d %b") if dt else str(value)


LAN_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"))


def _lan_address(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in LAN_NETS)


def _public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


VERDICTS = ("false_alarm", "real", "not_sure")
VERDICT_COLUMNS = ("verdict", "verdict_by", "verdict_at", "verdict_note")


def ensure_tables(conn) -> int:
    added = 0 if me._table_exists_ro(conn, "expectation") else 1
    for ddl in DDL:
        conn.execute(ddl)
    if me._table_exists_ro(conn, "incident"):
        cols = {r[1] for r in conn.execute("PRAGMA table_info(incident)")}
        if "verdict" not in cols:
            for col in VERDICT_COLUMNS:
                conn.execute(f"ALTER TABLE incident ADD COLUMN {col} TEXT")
            # The owner's past dismissals, marked as such, not as a verdict.
            conn.execute(
                "UPDATE incident SET verdict = 'false_alarm', "
                "verdict_by = 'dismissal', verdict_at = status_at, "
                "verdict_note = assessment WHERE status = 'dismissed' "
                "AND status_by = 'user' AND verdict IS NULL")
            added = 1
    return added


# The router

def router_check(live) -> dict:
    """Can the router back a check right now, and if not, why not."""
    out = {"ok": False, "reasons": [], "agent_version": None,
           "firewall": None, "capabilities": [], "blocks": None,
           "wall": False, "wall_reason": None}
    if live is None:
        out["reasons"].append("The router is not set up, so nothing is "
                              "checked on it.")
        out["wall_reason"] = "The router can't confirm the blocks."
        return out
    with live._lock:
        status = live._read_status()
        probe = getattr(live.g, "probe_result", None) or {}
        blocked = sorted(live.blocked)
    if not status.get("ok"):
        out["reasons"].append(status.get("error")
                              or "The router could not be read.")
        out["wall_reason"] = "The router can't confirm the blocks."
        return out
    caps = probe.get("capabilities") or []
    out.update(capabilities=caps, firewall=probe.get("firewall"),
               blocks=blocked)
    try:
        out["agent_version"] = int(probe.get("agent_version") or 0)
    except ValueError:
        out["agent_version"] = 0
    if out["agent_version"] < MIN_AGENT_VERSION:
        out["reasons"].append(
            f"The router agent is version {out['agent_version'] or 'unknown'}, "
            f"version {MIN_AGENT_VERSION} or newer is needed. Run "
            f"./scripts/install_gateway_agent.sh again.")
    for cap, why in (("block", "it cannot block"),
                     ("conntrack", "it cannot list connections")):
        if cap not in caps:
            out["reasons"].append(f"The router agent reports that {why}.")
    out["ok"] = not out["reasons"]
    if not out["ok"]:
        out["wall_reason"] = "The router can't confirm the blocks: " + \
            out["reasons"][0]
    elif (out["agent_version"] < WALL_AGENT_VERSION
          or "blockhits" not in caps):
        out["wall_reason"] = (
            f"The router agent is version {out['agent_version']}; version "
            f"{WALL_AGENT_VERSION} counts what each block caught. Run "
            f"./scripts/install_gateway_agent.sh again to see the wall.")
    else:
        out["wall"] = True
    return out


_last_wall = {}


def _read_block_hits(conn, live, router, now) -> dict | None:
    """Store what each block caught. Leaves the wall off, with the reason,
    when the router cannot count."""
    if not router["wall"]:
        return None
    try:
        r = live.g.block_hits()
    except Exception as e:                                  # noqa: BLE001
        router.update(wall=False, wall_reason=f"The router did not say what "
                      f"the blocks caught: {e}")
        return None
    if not r.get("counted"):
        router.update(wall=False, wall_reason="This router's firewall keeps "
                      "no count per block, so the wall cannot be drawn.")
        return None
    hits = r.get("hits") or {}
    for subject in router["blocks"] or []:
        h = hits.get(subject.lower())
        if h is None:
            continue
        last = conn.execute(
            "SELECT read_at, packets FROM block_hit WHERE subject = ? "
            "ORDER BY read_at DESC LIMIT 1", (subject,)).fetchone()
        if (last is None or last["packets"] != h["packets"]
                or (now - (_parse(last["read_at"]) or now)).total_seconds()
                >= CHECK_ROW_EVERY):
            conn.execute("INSERT OR REPLACE INTO block_hit (subject, read_at, "
                         "packets, bytes) VALUES (?, ?, ?, ?)",
                         (subject, _iso(now), h["packets"], h["bytes"]))
    return hits


def _caught(conn, subject, now, fresh: bool) -> dict | None:
    """Packets a block caught in each of the last 24 hours. A drop in the
    count is a router restart, counted from zero. None before any reading."""
    if not me._table_exists_ro(conn, "block_hit"):
        return None
    end = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    start = end - timedelta(hours=24)
    base = conn.execute(
        "SELECT packets FROM block_hit WHERE subject = ? AND read_at < ? "
        "ORDER BY read_at DESC LIMIT 1", (subject, _iso(start))).fetchone()
    rows = conn.execute(
        "SELECT read_at, packets FROM block_hit WHERE subject = ? "
        "AND read_at >= ? ORDER BY read_at", (subject, _iso(start))).fetchall()
    if base is None and not rows:
        return None
    # Without an earlier reading the first one counts only for a new block.
    prev = base["packets"] if base else (0 if fresh else None)
    hours = [0] * 24
    for r in rows:
        p = r["packets"]
        if prev is not None:
            at = _parse(r["read_at"]) or now
            i = int((at - start).total_seconds() // 3600)
            if 0 <= i < 24:
                hours[i] += p - prev if p >= prev else p
        prev = p
    return {"hours": hours, "total": sum(hours), "start": _iso(start)}


def _coverage(conn, start: datetime, end: datetime) -> float:
    """Share of the window the router reader and the app were both running."""
    span = (end - start).total_seconds()
    if span <= 0:
        return 1.0
    rows = conn.execute(
        "SELECT started_at, ended_at FROM sensor_gaps "
        "WHERE sensor IN ('lan_live', 'agentalsec') "
        "AND started_at < ? AND (ended_at IS NULL OR ended_at > ?)",
        (_sql(end), _sql(start))).fetchall() if me._table_exists_ro(
            conn, "sensor_gaps") else []
    spans = []
    for a, b in rows:
        a = max(_parse(a) or start, start)
        b = min(_parse(b) or end, end)
        if b > a:
            spans.append((a, b))
    spans.sort()
    lost, cur = 0.0, None
    for a, b in spans:
        if cur and a <= cur[1]:
            cur = (cur[0], max(cur[1], b))
        else:
            if cur:
                lost += (cur[1] - cur[0]).total_seconds()
            cur = (a, b)
    if cur:
        lost += (cur[1] - cur[0]).total_seconds()
    return max(0.0, 1.0 - lost / span)


# The checks. Each returns (state, detail, evidence).

def _window_start(exp, now, hours):
    starts = [now - timedelta(hours=hours), _parse(exp["since"])]
    ack = _parse(exp["acknowledged_at"])
    if ack:
        starts.append(ack)
    return max(s for s in starts if s)


def _findings(conn, rules, start):
    return conn.execute(
        "SELECT detection_id, entity_value, title, found_at FROM findings "
        f"WHERE detection_id IN ({', '.join('?' * len(rules))}) "
        "AND found_at >= ? ORDER BY found_at",
        (*rules, _sql(start))).fetchall()


def _check_head_count(conn, exp, ctx):
    rows = _findings(conn, ("LAN-1008",), ctx["start"])
    count = ctx["device_count"]
    if rows:
        names = sorted({r["entity_value"] for r in rows})
        return ("new", f"{len(names)} new device(s) joined: "
                f"{', '.join(names[:5])}. {count} device(s) on the network now.",
                {"new": names})
    if not ctx["router"]["ok"]:
        return "unknown", "The router could not be read, so new devices " \
            "could not be counted.", {}
    return "holding", f"No new device. {count} device(s) on the network.", {}


def _dns_bypass(conn, start, cfg):
    """Devices that sent names to a public resolver of their own."""
    accept = set(cfg.get("accept_dns") or [])
    rows = conn.execute(
        "SELECT device_ip, device_mac, dst, dport, MAX(last_seen) AS last "
        "FROM lan_flow WHERE last_seen >= ? AND "
        "(dport IN (53, 853) OR (dport = 443 AND dst IN "
        f"({', '.join('?' * len(DOH_RESOLVERS))}))) "
        "GROUP BY device_ip, dst, dport",
        (_iso(start), *sorted(DOH_RESOLVERS))).fetchall()
    out = {}
    for r in rows:
        if not _public(r["dst"]) or r["dst"] in accept:
            continue
        key = r["device_mac"] or r["device_ip"]
        out.setdefault(key, set()).add(f"{r['dst']}:{r['dport']}")
    return {k: sorted(v) for k, v in out.items()}


def _check_dns(conn, exp, ctx):
    known = json.loads(exp["known_json"] or "null")
    if known is None:
        # First check: devices already doing it are recorded, not raised.
        seen = _dns_bypass(conn, ctx["now"] - timedelta(days=7), ctx["cfg"])
        conn.execute("UPDATE expectation SET known_json = ? WHERE id = ?",
                     (json.dumps(sorted(seen)), exp["id"]))
        known = sorted(seen)
    found = _dns_bypass(conn, ctx["start"], ctx["cfg"])
    fresh = {k: v for k, v in found.items() if k not in set(known)}
    if fresh:
        first = sorted(fresh)[:5]
        return ("broken", f"{len(fresh)} device(s) looked up names around the "
                f"router: {', '.join(f'{k} to {fresh[k][0]}' for k in first)}.",
                {"devices": fresh})
    if not ctx["router"]["ok"]:
        return "unknown", "The router could not be read.", {}
    tail = (f" {len(known)} device(s) did so before this was watched and "
            "are left as they are." if known else "")
    return "holding", "Every lookup went through the router." + tail, {}


def _check_gateway(conn, exp, ctx):
    rows = _findings(conn, ("LAN-1002", "LAN-1003"), ctx["start"])
    if rows:
        return ("broken", rows[-1]["title"] + ".",
                {"findings": [dict(r) for r in rows[-5:]]})
    base = conn.execute("SELECT value_json FROM lan_baseline WHERE name = ?",
                        ("gateway_mac",)).fetchone() if me._table_exists_ro(
                            conn, "lan_baseline") else None
    if base is None:
        return "unknown", "The gateway's hardware address has not been " \
            "learned yet, so a change could not be seen.", {}
    return "holding", "The gateway and the DHCP server did not change.", {}


def _night_bytes(conn, night_end_local: datetime, cfg) -> tuple:
    end = night_end_local
    start = end.replace(hour=cfg["night_start_hour"])
    row = conn.execute(
        "SELECT SUM(up_bytes), COUNT(DISTINCT minute) FROM lan_traffic_minute "
        "WHERE minute >= ? AND minute < ?",
        (_iso(start), _iso(end))).fetchone()
    return (row[0] or 0), (row[1] or 0), start, end


def _check_quiet_nights(conn, exp, ctx):
    cfg, now = ctx["cfg"], ctx["now"]
    local = now.astimezone()
    end = local.replace(hour=cfg["night_end_hour"], minute=0, second=0,
                        microsecond=0)
    if end > local:
        end -= timedelta(days=1)
    up, minutes, start, end = _night_bytes(conn, end, cfg)
    cover = _coverage(conn, start, end)
    if cover < ctx["cfg"]["min_coverage"]:
        return ("unknown", f"The router was watched for {cover:.0%} of last "
                "night, too little to judge it.", {"coverage": cover})
    prior = []
    for d in range(1, 15):
        b, m, s, e = _night_bytes(conn, end - timedelta(days=d), cfg)
        if m and _coverage(conn, s, e) >= ctx["cfg"]["min_coverage"]:
            prior.append(b)
    mb = up / 1e6
    if len(prior) < NIGHTS_NEEDED:
        return ("unknown", f"Still learning: {len(prior)} watched night(s) so "
                f"far, {NIGHTS_NEEDED} needed. Last night: {mb:.0f} MB up.",
                {"last_mb": round(mb, 1)})
    usual = statistics.median(prior) / 1e6
    ev = {"last_mb": round(mb, 1), "usual_mb": round(usual, 1),
          "nights": len(prior)}
    if mb > usual * cfg["night_factor"] and mb - usual > cfg["night_floor_mb"]:
        return ("broken", f"Last night the network sent {mb:.0f} MB up, the "
                f"usual is {usual:.0f} MB.", ev)
    return ("holding", f"Last night: {mb:.0f} MB up, usual {usual:.0f} MB.", ev)


def _check_countries(conn, exp, ctx):
    if not me._table_exists_ro(conn, "place_baseline"):
        return "unknown", "Place learning has not run yet.", {}
    first = conn.execute(
        "SELECT MIN(first_seen) FROM place_baseline WHERE place_type = 'country'"
    ).fetchone()[0]
    began = _parse(first)
    if began is None or ctx["now"] - began < timedelta(
            hours=ctx["cfg"]["learn_hours"]):
        return "unknown", "Still learning which countries are normal.", {}
    rows = conn.execute(
        "SELECT place, COALESCE(MAX(place_label), place) AS label, "
        "MIN(first_seen) AS first FROM place_baseline "
        "WHERE place_type = 'country' GROUP BY place HAVING first >= ?",
        (_iso(ctx["start"]),)).fetchall()
    total = conn.execute(
        "SELECT COUNT(DISTINCT place) FROM place_baseline "
        "WHERE place_type = 'country'").fetchone()[0]
    if rows:
        labels = [r["label"] for r in rows]
        return ("new", f"New for the network: {', '.join(labels[:6])}.",
                {"new": labels})
    return "holding", f"No new country; {total} known.", {}


def _base_name(name: str) -> str:
    """The name a service is known by: example.com, or example.co.uk."""
    p = (name or "").lower().strip(".").split(".")
    if len(p) >= 3 and len(p[-1]) == 2 and p[-2] in ("co", "com", "net", "org",
                                                      "gov", "ac"):
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def _check_contacts(conn, exp, ctx):
    types = [t for t in ctx["cfg"].get("simple_types") or [] if t]
    if not types or not me._table_exists_ro(conn, "lan_flow"):
        return "unknown", "No device type is held to its usual contacts.", {}
    devs = conn.execute(
        "SELECT ip, COALESCE(NULLIF(known_as, ''), hostname, ip) AS name "
        "FROM known_devices WHERE device_type IN "
        f"({', '.join('?' * len(types))}) AND retired_at IS NULL "
        "AND merged_into IS NULL AND COALESCE(ip, '') != ''",
        tuple(types)).fetchall() if me._table_exists_ro(
            conn, "known_devices") else []
    if not devs:
        return ("unknown", "No device is marked as a smart device or printer "
                "on the Network tab, so there is nothing to hold to.", {})
    learned = ctx["now"] - timedelta(hours=ctx["cfg"]["learn_hours"])
    fresh, learning, watched = {}, 0, 0
    for d in devs:
        began = _parse(conn.execute(
            "SELECT MIN(first_seen) FROM lan_flow WHERE device_ip = ?",
            (d["ip"],)).fetchone()[0])
        if began is None:
            continue
        if began > learned:
            learning += 1
            continue
        watched += 1
        firsts = {}
        for r in conn.execute(
                "SELECT dst_name, MIN(first_seen) AS first FROM lan_flow "
                "WHERE device_ip = ? AND dst_name IS NOT NULL GROUP BY dst_name",
                (d["ip"],)):
            b = _base_name(r["dst_name"])
            firsts[b] = min(firsts.get(b, r["first"]), r["first"])
        new = sorted(b for b, f in firsts.items()
                     if (_parse(f) or ctx["now"]) >= ctx["start"])
        if new:
            fresh[d["ip"]] = {"name": d["name"], "new": new[:10]}
    tail = f" {learning} still learning." if learning else ""
    if fresh:
        said = "; ".join(f"{v['name']} to {', '.join(v['new'][:3])}"
                         for v in list(fresh.values())[:4])
        return ("new", f"{len(fresh)} device(s) reached a service they never "
                f"used: {said}.{tail}", {"devices": fresh})
    if not ctx["router"]["ok"]:
        return "unknown", "The router could not be read.", {}
    if not watched:
        return "unknown", "Still learning what these devices usually reach." \
            + tail, {}
    return ("holding", f"{watched} device(s) kept to their usual contacts."
            + tail, {})


def _check_block(conn, exp, ctx):
    addr = exp["subject"]
    router = ctx["router"]
    if not router["ok"]:
        return ("unknown", "The router can't confirm this block: "
                + router["reasons"][0], {})
    if addr not in set(router["blocks"] or []):
        return ("broken", "This block is no longer on the router, and the "
                "app did not lift it. Set it again from the Network tab if "
                "it is still wanted.", {"missing": True})
    after = max(_parse(exp["since"]) + timedelta(seconds=BLOCK_GRACE_SECONDS),
                ctx["start"])
    rows = conn.execute(
        "SELECT device_ip, device_mac, dst, dport, packets_in, bytes_in, "
        "bytes_out, first_seen FROM lan_flow WHERE first_seen >= ? AND "
        "(dst = ? OR device_ip = ? OR device_mac = ?) AND packets_in > 0 "
        "ORDER BY first_seen LIMIT 20",
        (_iso(after), addr, addr, addr.lower())).fetchall()
    if rows:
        r = rows[0]
        return ("broken", f"The block leaked: {len(rows)} connection(s) got "
                f"an answer, the first at {_human(r['first_seen'])} "
                f"({r['device_ip']} with {r['dst']}).",
                {"leaks": [dict(x) for x in rows]})
    caught = None
    if ctx.get("hits") is not None:
        fresh = _parse(exp["since"]) >= ctx["now"] - timedelta(hours=24)
        caught = _caught(conn, addr, ctx["now"], fresh)
    if caught is None:
        return "holding", "No traffic got through since the block.", {}
    n = caught["total"]
    return ("holding", f"No traffic got through since the block. The router "
            f"caught {n} packet{'' if n == 1 else 's'} in the last 24 hours.",
            {"caught_24h": n})


CHECKS = {"head_count": _check_head_count, "dns_via_router": _check_dns,
          "same_gateway": _check_gateway, "quiet_nights": _check_quiet_nights,
          "known_countries": _check_countries, "block_holds": _check_block,
          "usual_contacts": _check_contacts}


# Keeping the list

def _active(conn):
    return {(r["kind"], r["subject"]): r for r in conn.execute(
        "SELECT * FROM expectation WHERE ended_at IS NULL")}


def _open(conn, kind, subject, title, now):
    conn.execute(
        "INSERT INTO expectation (kind, subject, title, since) "
        "VALUES (?, ?, ?, ?)", (kind, subject, title, _iso(now)))


def _lifted_by_app(conn, subject, since) -> bool:
    """Did the app itself lift this block (REM-1010, REM-1014)."""
    if not me._table_exists_ro(conn, "findings"):
        return False
    return conn.execute(
        "SELECT 1 FROM findings WHERE detection_id IN ('REM-1010', 'REM-1014') "
        "AND found_at >= ? AND (lower(json_extract(raw_data, '$.argument')) = ? "
        "OR entity_value = ?) LIMIT 1",
        (_sql(_parse(since)) if _parse(since) else "1970-01-01 00:00:00",
         subject.lower(), subject)).fetchone() is not None


def _sync(conn, router, now):
    """One expectation per network kind, one per block on the router. A block
    the app lifted ends; one that went missing stays, broken, until seen."""
    active = _active(conn)
    for kind, title in NETWORK_KINDS.items():
        if (kind, "") not in active:
            _open(conn, kind, "", title, now)
    if router["ok"]:
        on_router = set(router["blocks"] or [])
        for addr in on_router:
            if ("block_holds", addr) not in active:
                _open(conn, "block_holds", addr,
                      f"No traffic to or from {addr} while it is blocked", now)
        for (kind, subject), row in active.items():
            if kind != "block_holds" or subject in on_router:
                continue
            seen = (row["broken_at"] and row["acknowledged_at"]
                    and row["acknowledged_at"] >= row["broken_at"]
                    and '"missing"' in (row["evidence_json"] or ""))
            if _lifted_by_app(conn, subject, row["since"]):
                why = "Unblocked."
            elif seen:
                why = "Gone from the router; seen by the owner."
            else:
                continue
            conn.execute("UPDATE expectation SET ended_at = ?, detail = ? "
                         "WHERE id = ?", (_iso(now), why, row["id"]))


def _record(conn, exp, state, detail, evidence, cover, now, own_break=True):
    prev = conn.execute(
        "SELECT result, checked_at FROM expectation_check "
        "WHERE expectation_id = ? ORDER BY id DESC LIMIT 1",
        (exp["id"],)).fetchone()
    due = (prev is None or prev["result"] != state
           or (now - (_parse(prev["checked_at"]) or now)).total_seconds()
           >= CHECK_ROW_EVERY)
    if due:
        conn.execute(
            "INSERT INTO expectation_check (expectation_id, checked_at, "
            "result, detail, coverage) VALUES (?, ?, ?, ?, ?)",
            (exp["id"], _iso(now), state, detail, cover))
    broken_at = exp["broken_at"]
    ack = _parse(exp["acknowledged_at"])
    if own_break and state == "broken" and (broken_at is None
                              or (ack and _parse(broken_at) <= ack)):
        broken_at = _iso(now)
    conn.execute(
        "UPDATE expectation SET state = ?, detail = ?, evidence_json = ?, "
        "last_checked_at = ?, broken_at = ? WHERE id = ?",
        (state, detail, json.dumps(evidence, default=str)[:20000],
         _iso(now), broken_at, exp["id"]))


def check_once(config: dict = None, live=None, now: datetime = None) -> dict:
    """Run every check once. Returns the overview."""
    cfg = settings(config or {})
    now = now or datetime.now(timezone.utc)
    if live is None:
        try:
            from tools import lan_live
            live = lan_live.get()
        except Exception:                                   # noqa: BLE001
            live = None
    router = router_check(live)
    devices = 0
    if live is not None:
        with live._lock:
            devices = len(live.inventory)
    with me._get_conn() as conn:
        ensure_tables(conn)
        hits = _read_block_hits(conn, live, router, now)
        _last_wall.update(wall=router["wall"], wall_reason=router["wall_reason"])
        _sync(conn, router, now)
        rows = list(_active(conn).values())
        blocks = []
        for exp in sorted(rows, key=lambda r: r["kind"] != "block_holds"):
            if exp["kind"] == "blocks_hold":
                continue
            start = _window_start(exp, now, cfg["window_hours"])
            cover = _coverage(conn, start, now)
            ctx = {"now": now, "start": start, "cfg": cfg, "router": router,
                   "device_count": devices, "coverage": cover, "hits": hits}
            try:
                state, detail, ev = CHECKS[exp["kind"]](conn, exp, ctx)
            except Exception as e:                          # noqa: BLE001
                logger.warning(f"expectation {exp['kind']} failed: {e}")
                state, detail, ev = "unknown", f"The check failed: {e}", {}
            if (state == "holding" and exp["kind"] != "quiet_nights"
                    and cover < cfg["min_coverage"]):
                state = "unknown"
                detail = (f"The router was watched for only {cover:.0%} of "
                          "this window, so this could not be judged.")
            _record(conn, exp, state, detail, ev, cover, now)
            if exp["kind"] == "block_holds":
                blocks.append(state)
        agg = _active(conn).get(("blocks_hold", ""))
        if agg is not None:
            if "broken" in blocks:
                s, d = "broken", f"{blocks.count('broken')} block(s) leaked."
            elif not router["ok"] and (blocks or router["blocks"] is None):
                s, d = "unknown", "The router can't confirm the blocks."
            elif not blocks:
                s, d = "holding", "No block is set on the router."
            else:
                s, d = "holding", f"All {len(blocks)} block(s) held."
            # Mirrors its blocks; each block carries its own break.
            _record(conn, agg, s, d, {}, None, now, own_break=False)
        conn.execute("DELETE FROM expectation_check WHERE checked_at < ?",
                     (_iso(now - timedelta(days=KEEP_CHECK_DAYS)),))
        conn.execute("DELETE FROM block_hit WHERE read_at < ?",
                     (_iso(now - timedelta(days=KEEP_CHECK_DAYS)),))
        conn.commit()
    return overview(config, now=now, router=router, live=live)


# The mood

def mood(rows: list, router: dict, coverage: float, cfg: dict,
         now: datetime) -> dict:
    """Never more dramatic than the evidence: red only for a real break."""
    broken = [r for r in rows if r["broken_at"] and not (
        r["acknowledged_at"] and r["acknowledged_at"] >= r["broken_at"])]
    new = [r for r in rows if r["state"] == "new"]
    unknown = [r for r in rows if r["state"] == "unknown"]
    held = [r for r in rows if r["state"] == "holding"]
    counts = (f"{len(held)} of {len(rows)} expectations held. "
              f"Router watched {coverage:.0%} of the last "
              f"{cfg['window_hours']} hours.")
    if broken:
        return {"mood": "alarmed", "sentence":
                f"{broken[0]['title']}: broken. {broken[0]['detail'] or ''} "
                + counts}
    if not router["ok"] or coverage < 0.9:
        why = router["reasons"][0] if router["reasons"] else (
            f"The router was watched for only {coverage:.0%} of the window.")
        return {"mood": "uneasy", "sentence": f"Not everything could be "
                f"checked. {why} " + counts}
    if new:
        return {"mood": "curious", "sentence":
                f"Something new, nothing broken. {new[0]['detail']} " + counts}
    if unknown:
        return {"mood": "calm", "sentence": f"Nothing broken. {len(unknown)} "
                "expectation(s) are still learning or could not be checked. "
                + counts}
    return {"mood": "calm", "sentence": "Nothing new, nothing broken. " + counts}


_watch_cache = {"at": None, "data": None}
WATCH_CACHE_SECONDS = 600


def _watch_24h(conn, now: datetime) -> list:
    """Per hour, the share the router and the laptop capture were watching.
    Cached: the packet read takes seconds on a busy database."""
    at = _watch_cache["at"]
    if at and 0 <= (now - at).total_seconds() < WATCH_CACHE_SECONDS:
        return _watch_cache["data"]
    data = _read_watch_24h(conn, now)
    _watch_cache.update(at=now, data=data)
    return data


def _read_watch_24h(conn, now: datetime) -> list:
    end = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    hours = [end - timedelta(hours=24 - i) for i in range(24)]
    capture = {h: 0.0 for h in range(24)}
    rows = conn.execute(
        "SELECT session_id, strftime('%Y-%m-%d %H', captured_at) AS hour, "
        "MIN(captured_at) AS a, MAX(captured_at) AS b FROM packets "
        "WHERE captured_at >= ? AND captured_at < ? GROUP BY session_id, hour",
        (_sql(hours[0]), _sql(end))).fetchall()
    for r in rows:
        a, b = _parse(r["a"]), _parse(r["b"])
        if not a or not b:
            continue
        i = int((a.replace(minute=0, second=0) - hours[0]).total_seconds()
                // 3600)
        if 0 <= i < 24:
            capture[i] = min(1.0, capture[i] + (b - a).total_seconds() / 3600)
    out = []
    for i, h in enumerate(hours):
        stop = min(h + timedelta(hours=1), now)
        out.append({"hour": _iso(h),
                    "router": round(_coverage(conn, h, stop), 3)
                    if stop > h else None,
                    "capture": round(capture[i], 3) if stop > h else None})
    return out


def _given_names() -> tuple:
    """The names the owner gave in the Network tab, by hardware address and
    by address. Retired and merged rows are left out so an old name on a
    reused MAC does not win."""
    by_mac, by_ip = {}, {}
    try:
        with me._get_readonly_conn() as conn:
            for r in conn.execute(
                    "SELECT ip, mac, known_as FROM known_devices "
                    "WHERE COALESCE(known_as, '') != '' AND retired_at IS NULL "
                    "AND merged_into IS NULL ORDER BY last_seen"):
                if r["mac"]:
                    by_mac[r["mac"].lower()] = r["known_as"]
                if r["ip"]:
                    by_ip[r["ip"]] = r["known_as"]
    except Exception as e:                                  # noqa: BLE001
        logger.debug(f"expectations: device names unavailable: {e}")
    return by_mac, by_ip


def _name(names, ip, mac, hostname) -> str:
    by_mac, by_ip = names
    return (by_mac.get(mac) if mac else None) or by_ip.get(ip) or hostname or ip


def _devices(live, rows) -> list:
    """The devices for the mood ring, with what the expectations say of each."""
    if live is None:
        return []
    names = _given_names()
    with live._lock:
        inv = {ip: dict(v) for ip, v in live.inventory.items()}
        blocked = set(live.blocked)
    new, leaks, dns = set(), set(), set()
    for r in rows:
        ev = r.get("evidence") or {}
        if r["kind"] == "head_count" and r["state"] == "new":
            new |= set(ev.get("new") or [])
        if r["kind"] == "usual_contacts" and r["state"] == "new":
            new |= set((ev.get("devices") or {}).keys())
        if r["kind"] == "block_holds" and r["state"] == "broken":
            leaks |= {x.get("device_ip") for x in ev.get("leaks") or []}
        if r["kind"] == "dns_via_router" and r["state"] == "broken":
            dns |= set((ev.get("devices") or {}).keys())
    out = []
    for ip, v in sorted(inv.items(), key=lambda x: tuple(
            int(p) if p.isdigit() else 0 for p in x[0].split("."))):
        mac = (v.get("mac") or "").lower()
        state = ("broken" if ip in leaks or ip in dns or mac in dns
                 else "new" if ip in new
                 else "blocked" if ip in blocked or mac in blocked
                 else "holding")
        out.append({"ip": ip, "mac": mac,
                    "name": _name(names, ip, mac, v.get("hostname")),
                    "state": state})
    return out


def _walls(conn, live, rows, router, now) -> list:
    """One wall per block: who is on each side, what the router caught in
    each of the last 24 hours, and any leak. None unless the router counts."""
    if not router["wall"]:
        return []
    names = _given_names()
    inv = {}
    if live is not None:
        with live._lock:
            inv = {ip: dict(v) for ip, v in live.inventory.items()}
    by_mac = {(v.get("mac") or "").lower(): ip for ip, v in inv.items()}
    out = []
    for r in rows:
        if r["kind"] != "block_holds":
            continue
        subject = r["subject"]
        ev = r.get("evidence") or {}
        mac = subject.lower() if ":" in subject and subject.count(":") == 5 \
            else ""
        ip = by_mac.get(mac) if mac else subject
        device = bool(mac) or subject in inv or _lan_address(subject)
        caught = _caught(conn, subject, now, _parse(r["since"])
                         >= now - timedelta(hours=24))
        leaks = ev.get("leaks") or []
        out.append({
            "id": r["id"], "subject": subject, "state": r["state"],
            "side": "device" if device else "address",
            "name": _name(names, ip or "", mac or (inv.get(ip) or {}).get(
                "mac", ""), (inv.get(ip) or {}).get("hostname")) or subject,
            "hours": caught["hours"] if caught else None,
            "caught_24h": caught["total"] if caught else None,
            "hours_start": caught["start"] if caught else None,
            "leaks": len(leaks),
            "leak": ({k: leaks[0].get(k) for k in ("device_ip", "dst",
                                                   "dport", "first_seen")}
                     if leaks else None),
            "missing": bool(ev.get("missing"))})
    return out


def overview(config: dict = None, now: datetime = None, router=None,
             live=None) -> dict:
    cfg = settings(config or {})
    now = now or datetime.now(timezone.utc)
    if live is None:
        try:
            from tools import lan_live
            live = lan_live.get()
        except Exception:                                   # noqa: BLE001
            live = None
    if router is None:
        router = router_check(live)
        # The last check knows whether the router could count.
        if router["wall"] and _last_wall.get("wall") is False:
            router.update(_last_wall)
    with me._get_readonly_conn() as conn:
        if not me._table_exists_ro(conn, "expectation"):
            return {"mood": "uneasy", "sentence": "Expectations have not been "
                    "checked yet.", "expectations": [], "router": router}
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM expectation WHERE ended_at IS NULL "
            "ORDER BY kind = 'block_holds', id")]
        for r in rows:
            r["evidence"] = json.loads(r.pop("evidence_json") or "{}")
            r.pop("known_json", None)
            r["history"] = [dict(h) for h in conn.execute(
                "SELECT checked_at, result, coverage FROM expectation_check "
                "WHERE expectation_id = ? AND checked_at >= ? ORDER BY id",
                (r["id"], _iso(now - timedelta(days=7))))]
        cover = _coverage(conn, now - timedelta(hours=cfg["window_hours"]), now)
        watch = _watch_24h(conn, now)
        walls = _walls(conn, live, rows, router, now)
    out = mood(rows, router, cover, cfg, now)
    out.update(expectations=rows, router=router, coverage=round(cover, 3),
               watch_24h=watch, devices=_devices(live, rows), walls=walls,
               checked_at=max((r["last_checked_at"] or "" for r in rows),
                              default=None))
    return out


CONTACTS_USUAL = 16
CONTACTS_NEW = 12


def device_detail(ip: str, now: datetime = None, live=None) -> dict:
    """One device: its usual contacts, what is new in the last day, its
    countries, its blocks and the expectations it touched."""
    now = now or datetime.now(timezone.utc)
    try:
        ip = str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        return {"error": "not an address"}
    if live is None:
        try:
            from tools import lan_live
            live = lan_live.get()
        except Exception:                                   # noqa: BLE001
            live = None
    mac, hostname, blocked, apps = "", None, False, []
    if live is not None:
        with live._lock:
            inv = dict(live.inventory.get(ip) or {})
            mac = (inv.get("mac") or "").lower()
            hostname = inv.get("hostname")
            blocked = ip in live.blocked or bool(mac and mac in live.blocked)
            apps = list(live.app_blocks.get(mac) or [])
    name = _name(_given_names(), ip, mac, hostname)
    day = now - timedelta(hours=24)
    out = {"ip": ip, "mac": mac, "name": name, "blocked": blocked,
           "apps_blocked": apps, "usual": [], "new": [], "countries": [],
           "expectations": [], "learning": True}
    with me._get_readonly_conn() as conn:
        if me._table_exists_ro(conn, "lan_flow"):
            first = conn.execute(
                "SELECT MIN(first_seen) FROM lan_flow WHERE device_ip = ?",
                (ip,)).fetchone()[0]
            began = _parse(first)
            out["watched_since"] = first
            out["learning"] = began is None or began > day
            rows = conn.execute(
                "SELECT COALESCE(MAX(dst_name), dst) AS contact, "
                "MAX(dst) AS address, COUNT(*) AS connections, "
                "SUM(bytes_out + bytes_in) AS bytes, MIN(first_seen) AS first, "
                "MAX(last_seen) AS last FROM lan_flow "
                "WHERE device_ip = ? AND last_seen >= ? "
                "GROUP BY COALESCE(dst_name, dst) ORDER BY connections DESC",
                (ip, _iso(now - timedelta(days=7)))).fetchall()
            for r in rows:
                c = dict(r)
                fresh = (_parse(c["first"]) or now) >= day
                (out["new"] if fresh and not out["learning"]
                 else out["usual"]).append(c)
            out["usual_total"], out["new_total"] = len(out["usual"]), len(out["new"])
            out["usual"] = out["usual"][:CONTACTS_USUAL]
            out["new"] = out["new"][:CONTACTS_NEW]
        if me._table_exists_ro(conn, "place_baseline"):
            for r in conn.execute(
                    "SELECT COALESCE(place_label, place) AS label, first_seen, "
                    "hits FROM place_baseline WHERE place_type = 'country' "
                    "AND subject IN (?, ?) ORDER BY hits DESC LIMIT 20",
                    (ip, mac or ip)):
                out["countries"].append({
                    "label": r["label"], "hits": r["hits"],
                    "new": (_parse(r["first_seen"]) or now) >= day})
        if me._table_exists_ro(conn, "expectation"):
            for r in conn.execute(
                    "SELECT id, kind, subject, title, state, detail, "
                    "evidence_json FROM expectation WHERE ended_at IS NULL"):
                ev = r["evidence_json"] or ""
                own_block = r["kind"] == "block_holds" and r["subject"] in (
                    ip, mac)
                if own_block or (r["state"] in ("new", "broken") and (
                        f'"{ip}"' in ev or (mac and f'"{mac}"' in ev))):
                    out["expectations"].append(
                        {k: r[k] for k in ("id", "kind", "title", "state",
                                           "detail")})
    return out


RULE_FAMILY_ORDER = ("FED", "LAN", "GEO", "DNS", "PKT", "LNX", "AUD", "RTR")


def false_alarms(days: int = 14, now: datetime = None) -> dict:
    """Incidents that fired on each day, with their verdict, by rule.
    Counts incidents, not findings: one dismissal can cover hundreds."""
    now = now or datetime.now(timezone.utc)
    days = max(1, min(int(days), 60))
    local_today = now.astimezone().replace(hour=0, minute=0, second=0,
                                           microsecond=0)
    start = local_today - timedelta(days=days - 1)
    out = {"days": [], "rules": [], "unlabelled": [], "since": _iso(start)}
    with me._get_readonly_conn() as conn:
        if not me._table_exists_ro(conn, "incident"):
            return out
        cols = {r[1] for r in conn.execute("PRAGMA table_info(incident)")}
        if "verdict" not in cols:
            out["note"] = "Verdicts arrive with the next start of the app."
            return out
        rows = conn.execute(
            "SELECT i.id, i.detection_id, i.entity_value, i.title, i.severity, "
            "i.verdict, i.verdict_by, substr(f.found_at, 1, 13) AS hour "
            "FROM findings f JOIN incident i ON i.detection_id = f.detection_id "
            "AND i.entity_value = f.entity_value WHERE f.found_at >= ? "
            "GROUP BY i.id, hour", (_sql(start),)).fetchall()
    per_day, rules, seen = {}, {}, {}
    for r in rows:
        when = _parse(r["hour"].replace(" ", "T") + ":00:00+00:00")
        if when is None:
            continue
        day = when.astimezone().strftime("%Y-%m-%d")
        dots = per_day.setdefault(day, {})
        if r["id"] in dots:
            continue
        dot = {"id": r["id"], "rule": r["detection_id"],
               "entity": r["entity_value"], "title": r["title"],
               "verdict": r["verdict"], "verdict_by": r["verdict_by"]}
        dots[r["id"]] = dot
        seen[r["id"]] = dot
        t = rules.setdefault(r["detection_id"], {
            "rule": r["detection_id"], "false_alarm": 0, "real": 0,
            "not_sure": 0, "unlabelled": 0, "days": 0})
        t[r["verdict"] or "unlabelled"] += 1
        t["days"] += 1
    for i in range(days):
        day = (start + timedelta(days=i)).strftime("%Y-%m-%d")
        dots = sorted((per_day.get(day) or {}).values(),
                      key=lambda d: (d["rule"], d["id"]))
        out["days"].append({
            "day": day, "dots": dots,
            "false_alarms": sum(d["verdict"] == "false_alarm" for d in dots)})
    out["rules"] = sorted(rules.values(),
                          key=lambda t: (-t["false_alarm"], -t["days"]))
    out["unlabelled"] = sorted(
        (d for d in seen.values() if not d["verdict"]),
        key=lambda d: -d["id"])[:15]
    out["unlabelled_total"] = sum(1 for d in seen.values() if not d["verdict"])
    return out


def acknowledge_kind(kind: str, now: datetime = None) -> dict:
    """Mark the active expectation of one kind as seen, if it broke."""
    with me._get_readonly_conn() as conn:
        row = conn.execute("SELECT id FROM expectation WHERE kind = ? AND "
                           "subject = '' AND ended_at IS NULL", (kind,)
                           ).fetchone() if me._table_exists_ro(
                               conn, "expectation") else None
    return acknowledge(row["id"], now) if row else {"success": False}


def acknowledge(expectation_id: int, now: datetime = None) -> dict:
    """The owner has seen a break; the mood stops counting it."""
    with me._get_conn() as conn:
        cur = conn.execute(
            "UPDATE expectation SET acknowledged_at = ? WHERE id = ? "
            "AND broken_at IS NOT NULL",
            (_iso(now or datetime.now(timezone.utc)), int(expectation_id)))
        conn.commit()
    return {"success": cur.rowcount == 1}


# The loop

class ExpectationWatch:
    def __init__(self, config: dict):
        self.config = config
        self.cfg = settings(config)
        self._stop = threading.Event()
        self._thread = None
        self._started_at = None
        self._last_ok_at = None
        self.last_error = None

    def start(self) -> bool:
        if not self.cfg.get("enabled"):
            return False
        self._started_at = time.time()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="expectations")
        self._thread.start()
        return True

    def stop(self, wait: float = 5.0):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=wait)

    def liveness(self) -> dict:
        t = self._thread
        return {"started": t is not None,
                "thread_alive": bool(t is not None and t.is_alive()),
                "running": not self._stop.is_set(),
                "interval": int(self.cfg["interval_seconds"]),
                "started_at": self._started_at, "last_ok_at": self._last_ok_at,
                "consecutive_failures": 0, "last_error": self.last_error}

    def _loop(self):
        # The first pass waits for the router reader's first poll.
        wait = 60
        while not self._stop.wait(wait):
            wait = self.cfg["interval_seconds"]
            try:
                check_once(self.config)
                self._last_ok_at = time.time()
                self.last_error = None
            except Exception as e:                          # noqa: BLE001
                self.last_error = str(e)
                logger.error(f"expectations: pass failed: {e}", exc_info=True)


def get() -> "ExpectationWatch | None":
    return _instance


def start(config: dict) -> dict:
    global _instance
    _instance = ExpectationWatch(config)
    if not _instance.start():
        return {"started": False, "reason": "disabled in config"}
    return {"started": True, "interval": _instance.cfg["interval_seconds"]}
