# core/deviations.py
# Python's own check of a session against what each device, program and port
# did in the sessions before it. Runs at every rollup and writes deviations
# for the Baselines tab only: no finding, no alert, no model call.
#
# Judged only with enough history (the medium confidence threshold, in
# sessions). About 2 steps from usual is a note, 3 or more is far from usual,
# as the tab says. A device's history follows it across its addresses.

import logging
import statistics
from datetime import datetime, timedelta, timezone

from core import memory_engine as me

logger = logging.getLogger(__name__)

# key -> (entity type, kind)
KEYS = {
    "typical_parent":     ("process", "set"),
    "typical_paths":      ("process", "set"),
    "typical_process":    ("port", "set"),
    "typical_dest_ports": ("ip", "set"),
    "active_hours":       ("ip", "set"),
    "volume_per_hour":    ("ip", "num"),
    "connection_count":   ("ip", "num"),
}
# Ports at or above this are short-lived client ports, new every session.
HIGH_PORT = 32768
NOTE_STEPS, FAR_STEPS = 2.0, 3.0
# The smallest spread a number is judged with, so a device that always sends
# the same amount is not "far from usual" for a few kB more.
FLOORS = {"volume_per_hour": 1_000_000, "connection_count": 10}
# A device busy most hours, or using many ports, has no routine to break.
NARROW = {"active_hours": 12, "typical_dest_ports": 15}
MAX_PER_PASS = 20
MAX_PER_THING = 3
REPEAT_DAYS = 7


def _items(key: str, value) -> set:
    text = str(value if value is not None else "").strip()
    if key in ("typical_dest_ports", "active_hours"):
        out = set()
        for part in text.split(","):
            part = part.strip()
            if part.isdigit():
                n = int(part)
                if key == "active_hours" or n < HIGH_PORT:
                    out.add(str(n))
        return out
    return {text} if text else set()


def _number(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _bytes(n: float) -> str:
    for unit, size in (("GB", 1e9), ("MB", 1e6), ("kB", 1e3)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{n:.0f} bytes"


def _say(key: str, n: float) -> str:
    if key == "volume_per_hour":
        return f"{_bytes(n)} an hour"
    return f"{n:.0f} connections an hour"


def _thing(entity_type: str, value: str, devices: dict) -> str:
    """The key history is grouped by: a device for an address."""
    if entity_type == "ip" and value in devices:
        return devices[value]["key"]
    return f"{entity_type}:{value}"


def check(session_id: str, now: datetime = None) -> dict:
    """Compare this session's observations with every earlier session's.
    Never raises; returns what it wrote."""
    out = {"written": 0, "judged": 0, "skipped_history": 0}
    try:
        from core import baseline_text
        devices = baseline_text.device_map()
        need = int((me.confidence_thresholds() or {}).get("medium", 4))
        need_hours = int((me.confidence_thresholds() or {}).get("high", 6))
        with me._get_readonly_conn() as conn:
            rows = [r for r in conn.execute(
                "SELECT session_id, entity_type, entity_value, behavior_key, "
                "behavior_value FROM behavioral_session WHERE superseded_by "
                "IS NULL AND behavior_key IN (?, ?, ?, ?, ?, ?, ?)",
                tuple(KEYS)).fetchall()]
            since = ((now or datetime.now(timezone.utc))
                     - timedelta(days=REPEAT_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
            recent = {(r[0], r[1], r[2], r[3]) for r in conn.execute(
                "SELECT entity_type, entity_value, behavior_key, observed_value "
                "FROM behavioral_deviation WHERE detected_at >= ?", (since,))}
    except Exception as e:                              # noqa: BLE001
        logger.warning(f"Deviation check could not read its history: {e}")
        return out

    now_rows, past = {}, {}
    for sid, etype, value, key, val in rows:
        if KEYS[key][0] != etype:
            continue
        if etype == "port" and (not str(value).isdigit()
                                or int(value) >= HIGH_PORT):
            continue
        thing = _thing(etype, value, devices)
        if sid == session_id:
            cur = now_rows.setdefault((thing, key), {"value": value,
                                                    "type": etype, "vals": []})
            cur["vals"].append(val)
        else:
            past.setdefault((thing, key), {}).setdefault(sid, []).append(val)

    found = []
    for (thing, key), cur in now_rows.items():
        history = past.get((thing, key)) or {}
        if len(history) < (need_hours if key == "active_hours" else need):
            out["skipped_history"] += 1
            continue
        out["judged"] += 1
        etype, value = cur["type"], cur["value"]
        if KEYS[key][1] == "set":
            usual = set()
            for vals in history.values():
                for v in vals:
                    usual |= _items(key, v)
            seen = set()
            for v in cur["vals"]:
                seen |= _items(key, v)
            new = sorted(seen - usual)[:MAX_PER_THING]
            if not usual or not new or len(usual) > NARROW.get(key, 10 ** 6):
                continue
            shown = sorted(usual, key=lambda x: (int(x) if x.isdigit() else 0, x))
            expected = (", ".join(shown[:8]) + (f" and {len(shown) - 8} more"
                        if len(shown) > 8 else "")
                        + f" (in {len(history)} earlier sessions)")
            # A program or port holder changing is a stronger sign than a
            # device's new hour or port.
            score = (3.0 if etype != "ip" and len(history) >= need_hours
                     else 2.0)
            for item in new:
                found.append((etype, value, key, expected, item, score))
        else:
            per = [statistics.fmean(n for n in map(_number, vals) if n is not None)
                   for vals in history.values()
                   if any(_number(v) is not None for v in vals)]
            nowv = [n for n in map(_number, cur["vals"]) if n is not None]
            if len(per) < need or not nowv:
                continue
            mean, current = statistics.fmean(per), statistics.fmean(nowv)
            spread = max(statistics.pstdev(per), 0.25 * mean,
                         FLOORS.get(key, 1))
            steps = (current - mean) / spread
            if steps < NOTE_STEPS:
                continue
            expected = (f"about {_say(key, mean)}, up to about "
                        f"{_say(key, mean + spread)} in most sessions (in "
                        f"{len(per)} earlier sessions)")
            found.append((etype, value, key, expected, _say(key, current),
                          round(steps, 1)))

    found.sort(key=lambda f: -f[5])
    for etype, value, key, expected, observed, score in found:
        if out["written"] >= MAX_PER_PASS:
            break
        if (etype, value, key, observed) in recent:
            continue
        try:
            me.write_deviation(
                entity_type=etype, entity_value=value, behavior_key=key,
                session_id=session_id, expected_value=expected,
                observed_value=observed, deviation_score=score,
                model_assessment="", action_taken="logged",
                severity="medium" if score >= FAR_STEPS else "low")
            out["written"] += 1
        except Exception as e:                          # noqa: BLE001
            logger.warning(f"Deviation not written for {etype} {value}: {e}")
    out["found"] = len(found)
    return out


# The story the tab shows, and the question "Ask the agent" sends.

def story(row: dict, devices: dict = None) -> str:
    key = row.get("behavior_key")
    value = str(row.get("entity_value") or "")
    observed = row.get("observed_value") or "?"
    expected = row.get("expected_value") or "?"
    if row.get("entity_type") == "ip":
        dev = (devices or {}).get(value) or {}
        who = f"{dev['name']} ({value})" if dev.get("name") else value
    elif row.get("entity_type") == "port":
        who = f"Port {value}"
    else:
        who = value
    text = {
        "typical_parent": f"{who} was started by {observed}. Before, it was "
                          f"started by {expected}.",
        "typical_paths": f"{who} ran from {observed}. Before, it ran from "
                         f"{expected}.",
        "typical_process": f"{who} was opened by {observed}. Before, it was "
                           f"opened by {expected}.",
        "typical_dest_ports": f"{who} used port {observed}, which it had not "
                              f"used before. Its usual ports: {expected}.",
        "active_hours": f"{who} was active at {observed}:00, an hour it had "
                        f"not been active at before. Its usual hours: "
                        f"{expected}.",
        "volume_per_hour": f"{who} moved {observed}. Usually {expected}.",
        "connection_count": f"{who} made {observed}. Usually {expected}.",
    }.get(key)
    if text is None:
        text = f"{who}, {key}: {observed}, where {expected} was expected."
    if row.get("model_assessment"):
        text += f" The agent's reading: {row['model_assessment']}"
    return text


def for_page(days: int = REPEAT_DAYS) -> list:
    """Recent deviations nobody has answered, newest first, as stories."""
    from core import baseline_text
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime(
        "%Y-%m-%d %H:%M:%S")
    with me._get_readonly_conn() as conn:
        if not me._table_exists_ro(conn, "behavioral_deviation"):
            return []
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM behavioral_deviation WHERE detected_at >= ? AND "
            "COALESCE(user_responded, 0) = 0 AND (resolved_as IS NULL OR "
            "resolved_as = 'unreviewed') ORDER BY detected_at DESC LIMIT 100",
            (since,))]
    devices = baseline_text.device_map()
    for r in rows:
        r["story"] = story(r, devices)
        score = _number(r.get("deviation_score")) or 0
        r["level"] = "far from usual" if score >= FAR_STEPS else "worth a look"
    return rows


def mark_fine(deviation_id: int) -> dict:
    """The owner's answer from the tab. Recorded as the owner's."""
    with me._get_readonly_conn() as conn:
        if conn.execute("SELECT 1 FROM behavioral_deviation WHERE id = ?",
                        (int(deviation_id),)).fetchone() is None:
            return {"success": False, "error": "no such deviation"}
    return me.resolve_deviation(
        deviation_id=int(deviation_id), resolved_as="normal",
        user_response="This is fine (Baselines tab)", resolved_by="user")
