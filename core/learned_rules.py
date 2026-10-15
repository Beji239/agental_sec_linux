# core/learned_rules.py
# Quiet rules the model learns from false alarms. A rule names one detection
# and a pattern (entity, title or raw fields, as case-blind globs); a finding
# that matches is held back instead of written, and counted on the rule so the
# owner can see what it holds and undo it. Critical findings are never held.

import fnmatch
import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from core import memory_engine as me

logger = logging.getLogger(__name__)

CACHE_SECONDS = 30
REPLAY_DAYS = 30
MIN_LITERAL = 3          # characters a glob must carry besides wildcards
WIDE_FLOOR = 5           # a rule matching every one of at least this many
WIDE_ENTITIES = 3        # findings over this many entities turns the rule off
NEVER_HELD = ("critical",)
MAX_RAW_KEYS = 6

DDL = (
    """CREATE TABLE IF NOT EXISTS learned_rule (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id  TEXT NOT NULL,
    match_json    TEXT NOT NULL,
    reason        TEXT NOT NULL,
    evidence_json TEXT,
    created_by    TEXT NOT NULL CHECK (created_by IN ('model', 'owner')),
    created_at    TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'on' CHECK (status IN ('on', 'undone')),
    undone_at     TEXT,
    undone_by     TEXT,
    undone_reason TEXT,
    held_count    INTEGER NOT NULL DEFAULT 0,
    last_held_at  TEXT,
    last_example  TEXT
)""",
    "CREATE INDEX IF NOT EXISTS idx_learned_rule_det "
    "ON learned_rule(detection_id, status)",
    """CREATE TABLE IF NOT EXISTS learned_rule_held (
    rule_id  INTEGER NOT NULL REFERENCES learned_rule(id),
    day      TEXT NOT NULL,
    entity   TEXT NOT NULL,
    count    INTEGER NOT NULL DEFAULT 0,
    last_at  TEXT NOT NULL,
    PRIMARY KEY (rule_id, day, entity)
)""",
)

_cache = {"at": 0.0, "rules": None}
_lock = threading.Lock()


def ensure_tables(conn) -> int:
    added = 0 if me._table_exists_ro(conn, "learned_rule") else 1
    for ddl in DDL:
        conn.execute(ddl)
    return added


def _iso(dt: datetime = None) -> str:
    return (dt or datetime.now(timezone.utc)).astimezone(timezone.utc) \
        .strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _forget():
    with _lock:
        _cache.update(at=0.0, rules=None)


def _glob_ok(pattern: str) -> bool:
    literal = "".join(c for c in str(pattern) if c not in "*?[]")
    return len(literal.strip()) >= MIN_LITERAL


def _hit(pattern, value) -> bool:
    if value is None:
        return False
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True)
    return fnmatch.fnmatchcase(str(value).lower(), str(pattern).lower())


def matches(match: dict, entity_value, title, raw_data) -> bool:
    """Does a finding fit this pattern. Every field given must fit."""
    raw = raw_data
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = {}
    raw = raw if isinstance(raw, dict) else {}
    if "entity" in match and not _hit(match["entity"], entity_value):
        return False
    if "title" in match and not _hit(match["title"], title):
        return False
    for key, pattern in (match.get("raw") or {}).items():
        if not _hit(pattern, raw.get(key)):
            return False
    return True


def _clean_match(match) -> tuple[dict | None, str | None]:
    """The pattern, checked, or the reason it is refused."""
    if isinstance(match, str):
        try:
            match = json.loads(match)
        except ValueError:
            return None, "match must be an object with entity, title or raw"
    if not isinstance(match, dict):
        return None, "match must be an object with entity, title or raw"
    out = {}
    for key in ("entity", "title"):
        if match.get(key) not in (None, ""):
            out[key] = str(match[key])
    raw = match.get("raw") or {}
    if not isinstance(raw, dict):
        return None, "raw must be an object of field name to pattern"
    if len(raw) > MAX_RAW_KEYS:
        return None, f"at most {MAX_RAW_KEYS} raw fields"
    if raw:
        out["raw"] = {str(k): str(v) for k, v in raw.items()
                      if v not in (None, "")}
    patterns = [out.get("entity"), out.get("title"),
                *(out.get("raw") or {}).values()]
    patterns = [p for p in patterns if p]
    if not patterns:
        return None, ("a rule needs a pattern besides the detection id; "
                      "turning a whole rule off is the owner's call")
    if not any(_glob_ok(p) for p in patterns):
        return None, (f"every pattern is nearly all wildcards; give at least "
                      f"{MIN_LITERAL} real characters")
    return out, None


def _finding(conn, finding_id):
    row = conn.execute("SELECT id, detection_id, entity_type, entity_value, "
                       "title, raw_data, severity FROM findings WHERE id = ?",
                       (int(finding_id),)).fetchone()
    return dict(row) if row else None


def replay(conn, detection_id: str, match: dict, days: int = REPLAY_DAYS):
    """How many of this detection's recent findings the pattern covers."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)) \
        .strftime("%Y-%m-%d %H:%M:%S")
    total, hit, entities, all_entities, open_ids = 0, 0, set(), set(), []
    for r in conn.execute("SELECT id, entity_value, title, raw_data, "
                          "severity, dismissed FROM findings WHERE "
                          "detection_id = ? AND found_at >= ?",
                          (detection_id, since)):
        total += 1
        all_entities.add(r["entity_value"])
        if r["severity"] in NEVER_HELD:
            continue
        if matches(match, r["entity_value"], r["title"], r["raw_data"]):
            hit += 1
            entities.add(r["entity_value"])
            if not r["dismissed"]:
                open_ids.append((r["id"], r["entity_value"]))
    return {"days": days, "findings": total, "would_hold": hit,
            "entities_held": len(entities),
            "entities_seen": len(all_entities), "open_ids": open_ids}


def learn(detection_id: str, finding_id, match, reason: str,
          by: str = "model", clear_open: bool = True,
          example: dict = None) -> dict:
    """Make a quiet rule from one false alarm, a finding or (example) an
    alert the model reviewed before it was filed. Refuses rules that would
    silence a whole detection or that do not cover their own example."""
    from core import detections as det
    reason = (reason or "").strip()
    if not reason:
        return {"success": False, "error": "say why this is a false alarm"}
    if by not in ("model", "owner"):
        return {"success": False, "error": "by must be model or owner"}
    try:
        rule = det.get(detection_id)
    except Exception as e:                                  # noqa: BLE001
        return {"success": False, "error": str(e)}
    if getattr(rule, "retired", False):
        return {"success": False, "error": f"{detection_id} is retired"}
    clean, why = _clean_match(match)
    if clean is None:
        return {"success": False, "error": why}

    with me._get_conn() as conn:
        ensure_tables(conn)
        source = {"review_id": example.get("review_id")} if example else \
            {"finding_id": int(finding_id)}
        example = example or _finding(conn, finding_id)
        if example is None:
            return {"success": False, "error": f"no finding {finding_id}"}
        if example["detection_id"] != detection_id:
            return {"success": False,
                    "error": (f"the example is {example['detection_id']}, "
                              f"not {detection_id}")}
        if example["severity"] in NEVER_HELD:
            return {"success": False,
                    "error": "critical findings are never held back"}
        if not matches(clean, example["entity_value"], example["title"],
                       example["raw_data"]):
            return {"success": False,
                    "error": ("the pattern does not match its own example; "
                              "read the finding's fields again"),
                    "example": {k: example[k] for k in
                                ("entity_value", "title", "raw_data")}}
        rp = replay(conn, detection_id, clean)
        if (rp["findings"] >= WIDE_FLOOR and rp["would_hold"] == rp["findings"]
                and rp["entities_seen"] >= WIDE_ENTITIES):
            return {"success": False,
                    "error": (f"this would hold every {detection_id} finding "
                              f"of the last {rp['days']} days "
                              f"({rp['findings']} across "
                              f"{rp['entities_seen']} entities), which turns "
                              f"the detection off. Narrow it, or ask the "
                              f"owner."),
                    "replay": {k: v for k, v in rp.items() if k != "open_ids"}}
        dup = conn.execute("SELECT id FROM learned_rule WHERE detection_id = ? "
                           "AND match_json = ? AND status = 'on'",
                           (detection_id, json.dumps(clean, sort_keys=True))
                           ).fetchone()
        if dup:
            return {"success": False, "error": f"rule {dup[0]} already says "
                                               f"this", "rule_id": dup[0]}
        cur = conn.execute(
            "INSERT INTO learned_rule (detection_id, match_json, reason, "
            "evidence_json, created_by, created_at) VALUES (?,?,?,?,?,?)",
            (detection_id, json.dumps(clean, sort_keys=True), reason[:500],
             json.dumps(dict(source, title=example["title"])), by, _iso()))
        rid = cur.lastrowid
        cleared, entities = 0, set()
        if clear_open and rp["open_ids"]:
            note = f"learned rule {rid}: {reason[:200]}"
            for fid, entity in rp["open_ids"]:
                conn.execute("UPDATE findings SET dismissed = 1, "
                             "dismissed_at = datetime('now'), "
                             "dismissed_reason = ? WHERE id = ? AND "
                             "dismissed = 0", (note, fid))
                cleared += 1
                entities.add(entity)
    _forget()
    _journal("learned_rule_made", rid,
             {"detection_id": detection_id, "match": clean, "by": by,
              "reason": reason[:300], "cleared": cleared})
    if entities:
        _settle_incidents(detection_id, entities, rid, reason)
    return {"success": True, "rule_id": rid, "detection_id": detection_id,
            "match": clean, "cleared_open_findings": cleared,
            "replay": {k: v for k, v in rp.items() if k != "open_ids"}}


def _settle_incidents(detection_id, entities, rid, reason):
    """Open incidents left with no open finding are dismissed."""
    try:
        from core import incident
        with me._get_readonly_conn() as conn:
            if not me._table_exists_ro(conn, "incident"):
                return
            rows = conn.execute(
                "SELECT id, entity_value FROM incident WHERE detection_id = ? "
                "AND status IN ('new', 'triaged')", (detection_id,)).fetchall()
        for r in rows:
            if r["entity_value"] in entities and \
                    _open_count(detection_id, r["entity_value"]) == 0:
                incident.set_status(r["id"], "dismissed", by="model",
                                    note=f"learned rule {rid}: {reason[:200]}")
    except Exception as e:                                  # noqa: BLE001
        logger.warning(f"learned rule {rid}: incidents not settled: {e}")


def _open_count(detection_id, entity_value) -> int:
    with me._get_readonly_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM findings WHERE "
                            "detection_id = ? AND entity_value = ? AND "
                            "dismissed = 0", (detection_id, entity_value)
                            ).fetchone()[0]


def _active() -> dict:
    now = time.monotonic()
    with _lock:
        if _cache["rules"] is not None and now - _cache["at"] < CACHE_SECONDS:
            return _cache["rules"]
    rules = {}
    try:
        with me._get_readonly_conn() as conn:
            if me._table_exists_ro(conn, "learned_rule"):
                for r in conn.execute("SELECT id, detection_id, match_json, "
                                      "reason FROM learned_rule WHERE "
                                      "status = 'on'"):
                    rules.setdefault(r["detection_id"], []).append(
                        (r["id"], json.loads(r["match_json"]), r["reason"]))
    except Exception as e:                                  # noqa: BLE001
        logger.warning(f"learned rules not read, nothing held: {e}")
    with _lock:
        _cache.update(at=now, rules=rules)
    return rules


def holds(detection_id, entity_value, title, raw_data, severity):
    """The rule holding this finding back, as (id, reason), or None. A hold
    is counted on the rule. Any error lets the finding through."""
    if severity in NEVER_HELD:
        return None
    try:
        for rid, match, reason in _active().get(detection_id, ()):
            if matches(match, entity_value, title, raw_data):
                _count(rid, entity_value, title)
                return rid, reason
    except Exception as e:                                  # noqa: BLE001
        logger.warning(f"learned rule check failed, finding kept: {e}")
    return None


def _count(rid, entity_value, title):
    now = datetime.now(timezone.utc)
    with me._get_conn() as conn:
        conn.execute("UPDATE learned_rule SET held_count = held_count + 1, "
                     "last_held_at = ?, last_example = ? WHERE id = ?",
                     (_iso(now), (title or "")[:300], rid))
        conn.execute(
            "INSERT INTO learned_rule_held (rule_id, day, entity, count, "
            "last_at) VALUES (?, ?, ?, 1, ?) ON CONFLICT (rule_id, day, "
            "entity) DO UPDATE SET count = count + 1, last_at = excluded.last_at",
            (rid, now.astimezone().strftime("%Y-%m-%d"),
             str(entity_value or "unknown")[:200], _iso(now)))


def undo(rule_id: int, by: str = "owner", reason: str = None) -> dict:
    """Turn a rule off; its findings raise again from now on."""
    with me._get_conn() as conn:
        ensure_tables(conn)
        row = conn.execute("SELECT status FROM learned_rule WHERE id = ?",
                           (int(rule_id),)).fetchone()
        if row is None:
            return {"success": False, "error": f"no learned rule {rule_id}"}
        if row["status"] == "undone":
            return {"success": False, "error": "already undone"}
        conn.execute("UPDATE learned_rule SET status = 'undone', undone_at = ?, "
                     "undone_by = ?, undone_reason = ? WHERE id = ?",
                     (_iso(), by, (reason or "")[:300] or None, int(rule_id)))
    _forget()
    _journal("learned_rule_undone", int(rule_id), {"by": by,
                                                   "reason": (reason or "")[:300]})
    return {"success": True, "rule_id": int(rule_id), "status": "undone"}


def listing(include_undone: bool = False, limit: int = 200) -> dict:
    with me._get_readonly_conn() as conn:
        if not me._table_exists_ro(conn, "learned_rule"):
            return {"rules": [], "note": "no learned rules table yet"}
        rows = conn.execute(
            "SELECT * FROM learned_rule WHERE status = 'on' OR ? "
            "ORDER BY status = 'undone', id DESC LIMIT ?",
            (1 if include_undone else 0, int(limit))).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["match"] = json.loads(d.pop("match_json") or "{}")
            d["evidence"] = json.loads(d.pop("evidence_json") or "{}")
            d["held_last_7_days"] = conn.execute(
                "SELECT COALESCE(SUM(count), 0) FROM learned_rule_held WHERE "
                "rule_id = ? AND day >= ?", (r["id"], (
                    datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d"))
            ).fetchone()[0]
            out.append(d)
    return {"rules": out, "count": len(out)}


def _journal(op, rid, payload):
    try:
        me._journal(op, "learned_rule", int(rid), payload)
    except Exception as e:                                  # noqa: BLE001
        logger.error(f"Could not journal {op} for rule {rid}: {e}")
