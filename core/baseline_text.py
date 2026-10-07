# core/baseline_text.py
# One plain sentence for each behavioural baseline, for the Behavioural tab.
# Built from the stored fields and the recent observations at display time,
# by a fixed template per behavior_key, so the wording does not depend on
# the model. Every key in memory_engine.VALID_BEHAVIOR_KEYS has a template;
# tests/test_baseline_text.py fails when one is missing.

import json
import re
from collections import Counter

from core import memory_engine as me


def _hours(values) -> str:
    hours = set()
    for v in values:
        for a, b in re.findall(r"(\d{1,2})\s*-\s*(\d{1,2})", str(v)):
            hours.update(range(int(a), int(b) + 1))
        for n in re.findall(r"\d{1,2}", re.sub(r"\d{1,2}\s*-\s*\d{1,2}", "", str(v))):
            hours.add(int(n))
    hours = sorted(h for h in hours if 0 <= h <= 23)
    if not hours:
        return "no particular hour yet"
    runs, start = [], hours[0]
    for prev, cur in zip(hours, hours[1:] + [None]):
        if cur != prev + 1:
            runs.append(f"{start}:00" if start == prev else f"{start}:00 to {prev}:59")
            if cur is not None:
                start = cur
    return ", ".join(runs)


def _parts(value) -> list:
    """The items in one stored value: a comma list, or a JSON list or object,
    which is how the model sometimes wrote them."""
    text = str(value).strip()
    if text[:1] in "[{":
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        if isinstance(data, dict):
            lists = [x for x in data.values() if isinstance(x, list)]
            data = lists[0] if lists else list(data.values())
        if isinstance(data, list):
            return [str(x).strip() for x in data if str(x).strip()]
    return [p.strip() for p in text.split(",") if p.strip()]


def _items(values, n=5):
    count = Counter()
    for v in values:
        for part in _parts(v):
            count[part] += 1
    top = [p for p, _ in count.most_common(n)]
    if not top:
        return None
    more = len(count) - len(top)
    return ", ".join(top) + (f" and {more} more" if more > 0 else "")


def _latest(values):
    return str(values[0]) if values else None


def _bytes(n):
    if n is None:
        return None
    n = float(n)
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024


def _mean(row, values):
    if row.get("value_mean") is not None:
        return float(row["value_mean"])
    nums = []
    for v in values:
        try:
            nums.append(float(v))
        except (TypeError, ValueError):
            pass
    return sum(nums) / len(nums) if nums else None


def _num(row, values, fmt="{:.0f}"):
    m = _mean(row, values)
    return fmt.format(m) if m is not None else None


def _say(value, sentence, missing):
    """The sentence with the value, or what is not known yet."""
    return sentence.format(value) if value is not None else missing


def _hours_or_none(values):
    text = _hours(values)
    return None if text == "no particular hour yet" else text


# key -> function(row, values) returning the sentence after the name.
TEMPLATES = {
    "beacon_interval":     lambda r, v: _say(_num(r, v), "checks in about every {} seconds", "has no measured check-in interval yet"),
    "beacon_destinations": lambda r, v: _say(_items(v), "checks in at regular intervals with {}", "has no regular check-ins recorded yet"),
    "connection_count":    lambda r, v: _say(_num(r, v), "opens about {} connections an hour", "has no connection count measured yet"),
    "avg_packet_size":     lambda r, v: _say(_num(r, v), "sends packets of about {} bytes", "has no packet size measured yet"),
    "active_hours":        lambda r, v: _say(_hours_or_none(v or [r.get("typical_hours") or ""]), "is usually active at {}", "has no usual hours yet"),
    "open_ports_inbound":  lambda r, v: _say(_items(v), "usually accepts connections on port {}", "has no inbound ports recorded yet"),
    "open_ports_outbound": lambda r, v: _say(_items(v), "usually connects out on port {}", "has no outbound ports recorded yet"),
    "typical_dest_ports":  lambda r, v: _say(_items(v), "usually talks to port {}", "has no usual ports recorded yet"),
    "typical_dest_ips":    lambda r, v: _say(_items(v), "usually talks to {}", "has no usual destinations recorded yet"),
    "volume_per_session":  lambda r, v: _say(_bytes(_mean(r, v)), "moves about {} per session", "has no traffic volume measured yet"),
    "volume_per_hour":     lambda r, v: _say(_bytes(_mean(r, v)), "moves about {} an hour", "has no traffic volume measured yet"),
    "first_seen":          lambda r, v: _say(str(r.get("first_seen") or "")[:10] or None, "was first noticed {}", "has no first-seen date recorded"),
    "user_action_history": lambda r, v: _say(_latest(v), "has been acted on by you before: {}", "has an action of yours on record"),
    "operator_answer":     lambda r, v: _say(_latest(v), "you told the app: {}", "has an answer of yours on record"),
    "typical_parent":      lambda r, v: _say(_items(v, 3), "is usually started by {}", "has no record yet of what starts it"),
    "typical_network_ports": lambda r, v: _say(_items(v), "usually uses network port {}", "has no network ports recorded yet"),
    "typical_paths":       lambda r, v: _say(_items(v, 3), "usually runs from {}", "has no file location recorded yet"),
    "spawn_frequency":     lambda r, v: _say(_num(r, v), "starts about {} times a session", "has no measured count of how often it starts"),
    "typical_process":     lambda r, v: _say(_items(v, 3), "is usually opened by {}", "has no record yet of which program opens it"),
    "open_frequency":      lambda r, v: _say(_num(r, v, "{:.0%}"), "is open in about {} of sessions", "has no measured share of sessions open"),
    "typical_direction":   lambda r, v: _say(_latest(v), "is usually used {}", "has no usual direction recorded yet"),
    "last_seen_open":      lambda r, v: _say(_latest(v), "was last seen open {}", "has not been seen open yet"),
    "login_hours":         lambda r, v: _say(_hours_or_none(v), "usually logs in at {}", "has no usual login hours yet"),
    "login_sources":       lambda r, v: _say(_items(v), "usually logs in from {}", "has no usual login sources yet"),
    "typical_processes":   lambda r, v: _say(_items(v), "usually runs {}", "has no usual programs recorded yet"),
    "failed_login_count":  lambda r, v: _say(_num(r, v), "fails to log in about {} times a session", "has no failed login count measured yet"),
}

TYPE_WORDS = {"ip": "device", "process": "program", "port": "port", "user": "account"}


def _recent_values() -> dict:
    """(type, value, key) -> newest first observation values."""
    out = {}
    with me._get_readonly_conn() as conn:
        rows = conn.execute(
            "SELECT entity_type, entity_value, behavior_key, behavior_value "
            "FROM behavioral_session WHERE superseded_by IS NULL "
            "ORDER BY id DESC LIMIT 20000").fetchall()
    for t, v, k, val in rows:
        lst = out.setdefault((t, v, k), [])
        if len(lst) < 20:
            lst.append(val)
    return out


def _device_names() -> tuple:
    """ip -> name, and the set of ips whose hardware now answers elsewhere."""
    names, stale = {}, set()
    try:
        rows = me.query_known_devices()
    except Exception:                                   # noqa: BLE001
        return names, stale
    newest = {}
    for r in rows:
        if r.get("ip"):
            names[r["ip"]] = r.get("known_as") or r.get("hostname")
        mac = (r.get("mac") or "").lower()
        if mac:
            newest.setdefault(mac, []).append((r.get("last_seen") or "", r["ip"]))
    for seen in newest.values():
        if len(seen) > 1:
            seen.sort(reverse=True)
            stale.update(ip for _, ip in seen[1:])
    return names, stale


def describe_all(rows: list) -> list:
    """The baseline rows with plain fields added: summary, display_name,
    stale, progress {seen, needed}. Unknown keys keep summary None."""
    values = _recent_values()
    names, stale = _device_names()
    needed = int((me.confidence_thresholds() or {}).get("high", 6))
    out = []
    for r in rows:
        r = dict(r)
        t, v, k = r.get("entity_type"), r.get("entity_value"), r.get("behavior_key")
        name = names.get(v) if t == "ip" else None
        r["display_name"] = (f"{name} ({v})" if name else v) + \
            (" (old address)" if t == "ip" and v in stale else "")
        r["stale"] = t == "ip" and v in stale
        r["type_word"] = TYPE_WORDS.get(t, t)
        fn = TEMPLATES.get(k)
        r["summary"] = fn(r, values.get((t, v, k), [])) if fn else None
        seen = int(r.get("sample_count") or r.get("distinct_sessions_measured") or 0)
        r["progress"] = {"seen": seen, "needed": needed}
        notes = (r.get("model_notes") or "").strip()
        r["agent_note"] = None if (not notes or notes.startswith("Rollup [")) else notes
        out.append(r)
    return out
