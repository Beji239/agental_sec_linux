# core/incident.py
# AgentalSec V2, the incident ledger and the watcher.
#
# T2 of the agentic programme, 2026-09-17. See AGENTIC_PROGRAMME.md (pieces A
# and B) and wiki/concepts/duty-watch-programme.
#
# WHY THIS FILE EXISTS
#
# The owner's complaint: "it seems to me that it is entirely up to the human to
# launch pretty much anything". Verified in the source, and the sharpest part
# of it was not the model. It was that FINDINGS HAVE NO CONSUMER. The only
# autonomous reader of the findings table was predictions.check_due, and it
# only counted rows. A critical finding could be written at 3am and nothing in
# this application would ever look at it again.
#
# So there are two pieces here and they are deliberately separable:
#
#   THE LEDGER (write_incident, and the readers below)
#     One row per thing worth looking at, with the findings that produced it,
#     the agent's assessment when there is one, and THE COVERAGE THAT EXISTED
#     WHEN THE ASSESSMENT WAS MADE.
#
#   THE WATCHER (watch_once, and the daemon around it)
#     A deterministic tick. NO MODEL, NO TOKENS, and that is the design rather
#     than a stage in it: it is worth having with the model switched off, and
#     it must keep working when the model is unreachable, rate-limited, or
#     somebody's key expired at midnight.
#
# THE RULE THIS FILE IS BUILT AROUND
#
# THE WATCHER MAY NOT SAY "NOTHING HAPPENED". It may only say what it read and
# what it could not read. This is core/sensor_health's rule applied to an
# agentic component, and it matters more here, because this is the thing that
# runs unattended and whose silence a person will read as "the network was
# quiet".
#
# Every watcher_run row therefore carries `backlog`, and status() reports
# `blind` with a reason whenever the findings table could not be read or a
# sensor that feeds it was down. A cap that is hit is recorded as a cap in
# `capped`, never as an absence of incidents.
#
# THE THREE WAYS A TICK CAN END, kept apart on purpose:
#
#   ok       the findings were read, whatever they contained
#   refused  nothing was read because the watcher is switched off, or the
#            database has no incident table yet
#   error    something went wrong and the tick says so
#
# Only 'ok' is allowed to mean "I looked".

import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from core import memory_engine as me

logger = logging.getLogger(__name__)


class BadIncidentInput(ValueError):
    """A caller asked for something this ledger will not do."""


# CAPS AND THRESHOLDS
#
# Owner's answers, Q6, 2026-09-17. Every one of these is a preference rather
# than a constant, so changing one is a recorded decision with a date on it
# instead of a diff in a file nobody re-reads. The defaults are what the owner
# approved; the preference keys are how the owner changes the owner's mind later.

DEFAULT_TICK_SECONDS       = 60
DEFAULT_INCIDENTS_PER_DAY  = 40
DEFAULT_SEVERITY_FLOOR     = "medium"

# INCIDENTS ARE NOT SUPPRESSIBLE, AND FINDINGS ARE. This is the whole
# relationship between the two mechanisms and it is worth stating plainly,
# because the tempting design is to let a suppression silence the incident
# too and that is wrong twice over.
#
# A suppression says "stop telling me about THIS RULE on THIS ENTITY". The
# finding stops being written at all (memory_engine.save_finding checks it
# before the INSERT), so there is nothing left to coalesce and no incident
# appears. What a suppression must NOT do is reach into the ledger and close
# incidents that already exist: those rows record what was seen while the
# rule was live, and a suppression is not a time machine.
#
# The `suppressed` column on incident therefore means something narrower: the
# watcher observed a suppression rule covering this detection+entity at the
# moment it wrote or refreshed the row, and it says so. It is a note about
# coverage, not a mute. A reader who wants to know why this rule is not
# producing incidents any more reads the suppression, which is on the
# Detections page with a reason on it.


def _pref_int(key: str, default: int) -> int:
    try:
        return int(float(me.get_preference(key, str(default))))
    except (TypeError, ValueError):
        return default


def _pref_str(key: str, default: str) -> str:
    try:
        value = me.get_preference(key, default)
    except Exception:
        return default
    return str(value) if value else default


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sql_ts(dt: datetime) -> str:
    """The shape SQLite's CURRENT_TIMESTAMP writes, so string compares work."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _parse_ts(value):
    if not value:
        return None
    text = str(value).strip().replace("T", " ").rstrip("Z")[:19]
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc)
    except ValueError:
        return None


def _table_ready(conn, name: str = "incident") -> bool:
    return me._table_exists_ro(conn, name)


def _severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get((severity or "info").lower(), 0)


# COVERAGE — what this app could see when it looked

def coverage_snapshot(modules: dict = None) -> dict:
    """
    Which sensors were degraded at this moment, in one structure.

    THIS IS THE COLUMN THAT KEEPS AN INCIDENT HONEST. "No packets from that
    address in this window" is a true statement about a network and a true
    statement about a blind capture, and only one of them is what happened.
    The incident carries this so the duty loop (T4) and any reader after it
    can tell which.

    Deliberately derived from sensor_health rather than re-derived here: that
    module already knows which keys mean blind, which mean not-running, and
    which mean merely switched off, and a second implementation of that
    question is how two answers to one question start.

    Never raises. A coverage snapshot that cannot be taken says so in the
    note, because an empty coverage block would read as "everything was fine"
    which is the exact mistake this function exists to prevent.
    """
    snap = {
        "taken_at":     _sql_ts(_now()),
        "degraded":     [],
        "blind":        [],
        "not_loaded":   [],
        "complete":     None,
        "note":         None,
    }

    if not modules:
        snap["complete"] = None
        snap["note"] = ("No module table was available, so this app cannot "
                        "say which sensors were healthy when this incident "
                        "was written. That is not the same as all of them "
                        "being fine.")
        return snap

    for name, mod in sorted((modules or {}).items()):
        if name in ("rollup_engine", "incident_watcher"):
            continue
        # THE ACTION EXECUTOR IS NOT A SENSOR, SO IT IS NOT A COVERAGE FACT.
        # Added with T3, 2026-09-18, and it is the one exclusion here that
        # needs arguing rather than stating.
        #
        # The tempting read is that an executor which is not running is worth
        # a note on every incident. It is not, and putting it here would break
        # the meaning of the column. This block answers ONE question: could
        # this app SEE when it wrote the row. `complete` is False only when
        # something could not look. An executor being down does not make the
        # app blind — it has seen everything it saw — it makes its remedies
        # unrunnable, and that is a fact about the ACTIONS on the row rather
        # than about the network or about our eyes.
        #
        # If both went in the same column, a reader could no longer tell
        # "capture was off, so the absence of packets means nothing" from
        # "capture was fine and a worker thread is stopped". Those are the two
        # most different sentences in this whole application.
        #
        # The executor's health IS reported, in the places where acting is the
        # subject: its own status(), query_action_requests' `executor` block,
        # and the dashboard. See core/actions.py.
        if name == "action_executor":
            continue
        if mod is None:
            snap["not_loaded"].append(name)
            continue
        status = getattr(mod, "status", None)
        if not callable(status):
            continue
        try:
            st = status()
        except Exception as e:
            snap["degraded"].append(
                f"{name} could not report its own health "
                f"({type(e).__name__})")
            continue
        if not isinstance(st, dict):
            continue
        if st.get("blind"):
            snap["blind"].append(
                f"{name}: {st.get('blind_reason') or 'reason not recorded'}")
        elif st.get("running") is False and st.get("available") is not False:
            snap["degraded"].append(
                f"{name} is NOT RUNNING: "
                f"{st.get('reason') or 'no reason recorded'}")
        elif st.get("last_error"):
            snap["degraded"].append(f"{name}: {st['last_error']}")

    snap["complete"] = not (snap["degraded"] or snap["blind"])

    if snap["complete"]:
        snap["note"] = ("Every sensor that reports its own health reported "
                        "that it could see.")
    else:
        parts = []
        if snap["blind"]:
            parts.append(f"BLIND: {'; '.join(snap['blind'])}")
        if snap["degraded"]:
            parts.append(f"degraded: {'; '.join(snap['degraded'])}")
        if snap["not_loaded"]:
            parts.append("not loaded at all (switched off in config.json, or "
                         "it failed to import at boot): "
                         + ", ".join(snap["not_loaded"]))
        snap["note"] = ("This app could NOT see everything when this was "
                        "written. " + "; ".join(parts))
    return snap


# WRITING AN INCIDENT

def incident_key(detection_id: str, entity_type: str, entity_value: str) -> str:
    """
    The identity of an incident: one rule, one subject.

    NOT a timestamp and NOT a count, both of which would make every tick a new
    incident. The database has this as a UNIQUE column, so "one incident per
    thing" survives a restart of the watcher even though the watcher keeps no
    memory of its own.
    """
    return f"{detection_id}|{entity_type}|{entity_value}"


def write_incident(detection_id: str, entity_type: str, entity_value: str,
                   severity: str, title: str, source: str = None,
                   finding_ids: list = None, first_seen_at=None,
                   last_seen_at=None, modules: dict = None) -> dict:
    """
    Record or refresh one incident. Returns what it did.

    COALESCING IS THE WHOLE FUNCTION. Fifty NET-1001 findings from one sweep
    are one incident about one address, so a second call for the same
    (detection, entity) does not create a row: it bumps finding_count, extends
    last_seen_at, merges the finding ids, and raises the severity to the worst
    one seen. That last part is not bookkeeping, it is the difference between
    an incident that says "medium" because that was the first finding and one
    that says "critical" because that is the worst thing in it.

    THE SEVERITY IS CHECKED AGAINST THE REGISTER, through the same
    detections.check_severity that save_finding uses. An incident cannot
    therefore claim a severity that its rule never declares, which would be a
    way to get a critical incident out of a low rule by going around the
    finding writer.

    Raises BadIncidentInput on an unregistered detection id or a severity the
    register does not declare. Fatal on purpose, same as everywhere else in
    this project: an incident that cannot be traced to a rule is worse than no
    incident, because it looks like somebody looked.
    """
    from core import detections as det

    rule = det.get(detection_id)              # raises UnknownDetection
    det.check_severity(detection_id, severity)

    entity_type = (entity_type or "").strip().lower()
    entity_value = (entity_value or "").strip()
    if not entity_value:
        raise BadIncidentInput(
            "An incident needs an entity_value. 'Something happened' is not "
            "a thing anybody can look at, and an incident nobody can act on "
            "is how a ledger becomes a log.")
    # 'file' ADDED 2026-09-22 WITH L3, and the reason is worth stating here
    # rather than only in the register. This refusal is caught by the watcher's
    # own try/except and COUNTED, so a rule that raises findings with a type
    # this function does not know produces rows in the findings table and NO
    # incident. The detector runs, the hit is computed, nothing arrives. That
    # is the C4 shape with a new entity type, and the local integrity rules are
    # the first ones to depend on the set being current.
    if entity_type not in ("ip", "process", "port", "user", "file"):
        raise BadIncidentInput(
            f"entity_type must be one of ip, process, port, user, file. Got "
            f"{entity_type!r}.")

    key = incident_key(detection_id, entity_type, entity_value)
    now = _now()
    now_sql = _sql_ts(now)
    first = _sql_ts(_parse_ts(first_seen_at) or now)
    last = _sql_ts(_parse_ts(last_seen_at) or now)
    ids = [int(i) for i in (finding_ids or []) if i is not None]

    # Coverage, taken ONCE per call and stored on the row. Only written when
    # it is absent, so the row records the coverage at the moment the incident
    # was RAISED rather than the coverage at the last refresh: a sensor that
    # went blind afterwards is a fact about later, and an incident whose
    # coverage column kept moving would answer a different question every time
    # it was read.
    snap = coverage_snapshot(modules)

    from core import memory_engine as _me
    suppression = _me.detection_suppressed(detection_id, entity_type,
                                           entity_value)

    with me._get_conn() as conn:
        if not _table_ready(conn):
            raise BadIncidentInput(
                "The incident table does not exist. Run the migrations "
                "(core/migrations.run_migrations) before the watcher.")

        row = conn.execute(
            "SELECT * FROM incident WHERE incident_key = ?", (key,)).fetchone()

        if row is None:
            conn.execute("""
                INSERT INTO incident
                    (incident_key, detection_id, detection_rev, entity_type,
                     entity_value, source, severity, severity_rank, cia_json,
                     title, first_seen_at, last_seen_at, finding_count,
                     finding_ids_json, status, status_at, status_by,
                     coverage_json, coverage_note, suppressed,
                     suppressed_reason)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                key, detection_id, rule.rev, entity_type, entity_value,
                source or rule.source, severity, _severity_rank(severity),
                json.dumps(det.axes(detection_id)), title, first, last,
                max(1, len(ids)), json.dumps(ids[-50:]),
                "new", now_sql, "watcher",
                json.dumps(snap), snap.get("note"),
                1 if suppression.get("suppressed") else 0,
                suppression.get("reason") if suppression.get("suppressed")
                else None,
            ))
            action = "created"
        else:
            merged = sorted(set(json.loads(row["finding_ids_json"] or "[]"))
                            | set(ids))[-50:]
            worst = severity
            if _severity_rank(row["severity"]) > _severity_rank(severity):
                worst = row["severity"]
            conn.execute("""
                UPDATE incident
                   SET last_seen_at   = ?,
                       finding_count  = finding_count + ?,
                       finding_ids_json = ?,
                       severity       = ?,
                       severity_rank  = ?,
                       title          = ?,
                       suppressed     = ?,
                       suppressed_reason = ?
                 WHERE id = ?
            """, (last, max(1, len(ids)), json.dumps(merged), worst,
                  _severity_rank(worst), title,
                  1 if suppression.get("suppressed") else 0,
                  suppression.get("reason") if suppression.get("suppressed")
                  else None, row["id"]))
            action = "coalesced"

        final = conn.execute("SELECT * FROM incident WHERE incident_key = ?",
                             (key,)).fetchone()
        out = dict(final)
        out["action"] = action
        out["previous_severity"] = row["severity"] if row is not None else None

    # NOT JOURNALLED, AND THAT IS THE SAME DECISION predictions made.
    # The journal's test is writes that change what this tool will TELL you
    # later: findings saved and dismissed, baselines suppressed, devices
    # vouched for. Writing an incident changes what the DUTY LOOP will read,
    # not what the app says about the network, and an incident is derived
    # entirely from findings that are themselves journalled. Adding an
    # operation here would put a line in the chain for every tick of a
    # background process, which is how a tamper log becomes unreadable.
    return out


# THE WATCHER — deterministic, no model, one tick

# THE CURSOR IS STORED ON THE RUN RECORD, NOT IN user_preferences, and this
# is a correction forced by watching the real app shut down.
#
# The first version kept the watermark in user_preferences. core/integrity
# snapshots that whole table as "the policy" and journals a config_observed
# entry when it moves, and its own comment states the contract plainly: "a
# config_observed entry in the journal always means the rules changed. It is
# never routine noise, so it never needs to be ignored." A cursor written
# every 60 seconds would have broken that contract permanently, turning the
# tamper journal into a log of the watcher's own bookkeeping, which is exactly
# how an operator learns to ignore the one warning that matters.
#
# Putting it on the watcher_run row is better on its own terms too: the
# cursor and the account of what was read at that cursor are the same row, so
# "where did the watcher get to" and "what did it do there" cannot disagree,
# and there is no second place to keep in step.
_WATERMARK_COLUMN = "last_processed_finding_id"


def _get_watermark() -> int | None:
    """
    The highest finding id the watcher has accounted for, or None.

    Read from the newest run row rather than from the policy table. A row with
    a NULL cursor is a run that read nothing, which is not the same as a run
    that never happened, so this returns None only when there are no rows at
    all: that, and only that, is the first run.
    """
    try:
        with me._get_readonly_conn() as conn:
            if not _table_ready(conn, "watcher_run"):
                return None
            row = conn.execute(
                f"SELECT {_WATERMARK_COLUMN} FROM watcher_run "
                f"WHERE {_WATERMARK_COLUMN} IS NOT NULL "
                f"ORDER BY id DESC LIMIT 1").fetchone()
    except Exception as e:
        logger.warning(f"Could not read the watcher's cursor: {e}")
        return None
    return int(row[0]) if row else None


def _incidents_created_since(hours: int = 24) -> int:
    cutoff = _sql_ts(_now() - timedelta(hours=hours))
    try:
        with me._get_readonly_conn() as conn:
            if not _table_ready(conn):
                return 0
            return conn.execute(
                "SELECT COUNT(*) FROM incident WHERE created_at >= ?",
                (cutoff,)).fetchone()[0]
    except Exception as e:
        logger.warning(f"Could not count incidents in the last {hours}h: {e}")
        return 0


def _record_run(session_id: str, outcome: str, counts: dict, started: float,
                detail: str = None, cursor: int = None):
    """
    One row per tick, and it carries the CURSOR as well as the account of the
    tick. 'Was the watcher running at 3am' and 'how far did it get' are the
    same question asked twice, so they are the same row.
    """
    try:
        with me._get_conn() as conn:
            if not _table_ready(conn, "watcher_run"):
                return
            conn.execute("""
                INSERT INTO watcher_run
                    (session_id, ran_at, outcome, findings_read, new_incidents,
                     coalesced, refused, capped, backlog, detail, duration_ms,
                     last_processed_finding_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (session_id, _sql_ts(_now()), outcome,
                  counts.get("findings_read", 0), counts.get("new", 0),
                  counts.get("coalesced", 0), counts.get("refused", 0),
                  counts.get("capped", 0), counts.get("backlog", 0), detail,
                  int((time.time() - started) * 1000), cursor))
    except Exception as e:
        logger.error(f"Could not record the watcher's run: {e}")


def watch_once(session_id: str, modules: dict = None,
               now: datetime = None) -> dict:
    """
    One watcher tick: findings since the last tick become incidents.

    THE ORDER OF THE FILTERS MATTERS AND IT IS DELIBERATE:

      1. kind. Action records (REM-*) are receipts for what this app did at
         somebody's instruction. They are skipped outright: an incident
         already exists for the finding that prompted the action, and a
         second one saying "we blocked the port" would be the ledger
         reporting on itself.

      2. severity floor. `info` and `low` findings do not become incidents by
         default. This is a volume decision, not a judgement that they do not
         matter: the boot data on this machine had 232 sudo rows and 2,782
         successful logins in one evening, and a ledger that opens an incident
         for each is a ledger nobody reads by the second day. The floor is a
         preference so it can be argued with.

      3. the daily cap. Counted per day, and A CAP HIT IS RECORDED AS A CAP.
         The findings that did not become incidents because of it are counted
         in `capped`, not silently dropped, and they are above the watermark
         so the next tick sees them again.

      4. coverage. If a sensor that feeds the findings table was blind when
         this tick ran, `blind` says so. See THE RULE at the top of this file.

    Returns a dict shaped like every other status() in this project, so
    sensor_health and the dashboard can read it without a special case.
    """
    started = time.time()
    counts = {"findings_read": 0, "new": 0, "coalesced": 0, "refused": 0,
              "capped": 0, "backlog": 0, "notified": 0}

    if not _watcher_enabled():
        counts["refused"] = 1
        _record_run(session_id, "refused", counts, started,
                    "the watcher is switched off in config.json")
        return {"outcome": "refused", "reason": "the watcher is switched off "
                "in config.json", **counts}

    try:
        with me._get_readonly_conn() as conn:
            if not _table_ready(conn):
                counts["refused"] = 1
                _record_run(session_id, "refused", counts, started,
                            "no incident table")
                return {"outcome": "refused",
                        "reason": ("the incident table does not exist, so "
                                   "nothing was read and this is not a quiet "
                                   "network"),
                        **counts}
    except Exception as e:
        counts["refused"] = 1
        _record_run(session_id, "error", counts, started,
                    f"could not open the database: {e}")
        return {"outcome": "error", "reason": f"could not open the database: {e}",
                **counts}

    floor = _pref_str("incident_severity_floor", DEFAULT_SEVERITY_FLOOR)
    floor_rank = _severity_rank(floor)
    cap = _pref_int("incident_daily_cap", DEFAULT_INCIDENTS_PER_DAY)
    now = now or _now()
    now_sql = _sql_ts(now)

    watermark = _get_watermark()
    # FIRST RUN: start from the newest finding there is, and say so. Reading
    # the entire findings history on the first tick would manufacture a triage
    # backlog out of findings somebody already dealt with months ago, and the
    # ledger would open with forty incidents about a network that is fine.
    # The boundary is recorded either way, so the moment it was set is visible
    # rather than implied.
    first_run = watermark is None
    if first_run:
        try:
            with me._get_readonly_conn() as conn:
                watermark = conn.execute(
                    "SELECT COALESCE(MAX(id), 0) FROM findings").fetchone()[0]
        except Exception:
            watermark = 0

    made_today = _incidents_created_since(24)

    try:
        from core import detections as det
        from core import finding_policy  # noqa: F401  (import-time check)

        with me._get_readonly_conn() as conn:
            rows = conn.execute("""
                SELECT id, found_at, source, severity, entity_type,
                       entity_value, title, description, detection_id,
                       detection_rev, dismissed, sensor_id
                  FROM findings
                 WHERE id > ? AND detection_id IS NOT NULL
                 ORDER BY id ASC
                 LIMIT 500
            """, (watermark,)).fetchall()

            backlog = conn.execute("""
                SELECT COUNT(*) FROM findings
                 WHERE id > ? AND detection_id IS NOT NULL
            """, (watermark,)).fetchone()[0]
    except Exception as e:
        logger.error(f"Watcher could not read findings: {e}")
        counts["refused"] = 1
        _record_run(session_id, "error", counts, started,
                    f"could not read findings: {e}")
        return {"outcome": "error",
                "reason": (f"the findings table could not be read ({e}), so "
                           f"this tick saw nothing. That is a statement about "
                           f"this app, not about the network."),
                **counts}

    counts["findings_read"] = len(rows)
    counts["backlog"] = max(0, backlog - len(rows))

    # One incident per (detection, entity) PER TICK, so a burst of fifty
    # findings becomes one write rather than fifty updates. The database's
    # UNIQUE key handles the across-ticks half.
    grouped: dict[str, dict] = {}

    for r in rows:
        did = r["detection_id"]
        try:
            rule = det.get(did)
        except det.UnknownDetection:
            # Cannot happen through save_finding, which validates first, but a
            # database can be edited by hand and this is the reader that would
            # find out. Counted and named rather than skipped in silence.
            counts.setdefault("unknown_ids", [])
            counts["unknown_ids"].append(did)
            continue

        if rule.kind != "detection":
            counts["refused"] += 1
            continue

        severity = (r["severity"] or "info").lower()
        if _severity_rank(severity) < floor_rank:
            counts["refused"] += 1
            continue

        key = incident_key(did, r["entity_type"], r["entity_value"])
        slot = grouped.get(key)
        if slot is None:
            grouped[key] = {
                "detection_id": did,
                "entity_type":  r["entity_type"],
                "entity_value": r["entity_value"],
                "severity":     severity,
                "title":        r["title"],
                "source":       r["source"],
                "first_seen_at": r["found_at"],
                "last_seen_at":  r["found_at"],
                "finding_ids":  [r["id"]],
            }
        else:
            slot["finding_ids"].append(r["id"])
            slot["last_seen_at"] = r["found_at"]
            if _severity_rank(severity) > _severity_rank(slot["severity"]):
                # The worst one wins, and the title follows it, because a
                # reader scanning the list must see the worst thing in it.
                slot["severity"] = severity
                slot["title"] = r["title"]

    for key, slot in grouped.items():
        if made_today >= cap:
            counts["capped"] += 1
            continue
        try:
            out = write_incident(
                detection_id=slot["detection_id"],
                entity_type=slot["entity_type"],
                entity_value=slot["entity_value"],
                severity=slot["severity"],
                title=slot["title"],
                source=slot["source"],
                finding_ids=slot["finding_ids"],
                first_seen_at=slot["first_seen_at"],
                last_seen_at=slot["last_seen_at"],
                modules=modules,
            )
        except Exception as e:
            logger.error(f"Could not write incident for {key}: {e}")
            counts["refused"] += 1
            continue
        if out.get("action") == "created":
            counts["new"] += 1
            made_today += 1
        else:
            counts["coalesced"] += 1
        if notify_urgent(out).get("sent"):
            counts["notified"] += 1

    # THE WATERMARK MOVES ON EVERY TICK THAT READ FINDINGS, AND THE FIRST
    # TICK RECORDS ITS BOUNDARY EVEN WHEN THAT BOUNDARY IS EMPTY.
    #
    # Two separate bugs lived here and the test found both. The first: the
    # watermark was only written when the tick had rows, so an empty tick left
    # it unset, the NEXT tick re-entered the first-run branch and computed a
    # fresh boundary, and every finding written in between was silently
    # stepped over. On a quiet host that is every finding there is. The
    # second: the boundary was a TIMESTAMP compared with `found_at > ?`, so
    # findings written inside the same second as the boundary were skipped
    # too, which during a sweep is a whole device's worth.
    #
    # Both are the same failure this project writes whole modules to prevent:
    # a watcher that read nothing looks exactly like a network with nothing in
    # it. The watermark is now a finding ID, which is strictly increasing and
    # cannot tie, and it is recorded on the first tick regardless of what that
    # tick read.
    #
    # A CAP IS THE ONE EXCEPTION. Findings the cap refused are left above the
    # cursor on purpose so the next tick sees them again, and moving past them
    # would be the watcher quietly deciding they did not matter.
    #
    # `cursor` becomes the value on THIS run row, which is what the next tick
    # reads back. A tick that read nothing carries the cursor forward
    # unchanged rather than NULL: NULL means "no row has ever carried a
    # cursor", which is a first run, and conflating the two is the bug above.
    cursor = watermark
    if rows and not counts["capped"]:
        cursor = rows[-1]["id"]

    detail = None
    if first_run:
        detail = (f"First run. Started watching from finding id {watermark}, "
                  f"rather than reading the whole findings history, which "
                  f"would have manufactured a backlog out of findings already "
                  f"dealt with.")
    elif counts["capped"]:
        detail = (f"{counts['capped']} incident(s) were NOT written because "
                  f"the daily cap of {cap} was reached. They are not lost and "
                  f"they are not judged unimportant: they are still above the "
                  f"cursor and the next tick will see them.")
    elif counts.get("unknown_ids"):
        detail = (f"Findings carried detection ids that are not in the "
                  f"register: {counts['unknown_ids']}. See "
                  f"scripts/detection_report.py.")

    outcome = "ok"
    _record_run(session_id, outcome, counts, started, detail, cursor)

    # THE MEMORY FOLLOWS THE LEDGER ON THE SAME CLOCK.
    #
    # Case memory, 2026-09-22. The index is brought up to date HERE, on the
    # tick that writes incidents, rather than on the duty loop's clock. The
    # reason is cost and causality: the watcher is deterministic, runs every
    # sixty seconds and costs nothing, so the index is never more than one tick
    # behind, and it is never the model paying for its own memory. Indexing on
    # the duty loop's clock would mean an incident raised at 09:01 is invisible
    # to the investigation at 09:00 the next morning only if the loop happens
    # to be in a different order than the tick, which is exactly the kind of
    # ordering assumption this project has been bitten by before.
    #
    # IT CANNOT FAIL THE TICK. A broken index is a degraded memory, not a
    # broken watcher: the ledger's job is to record what happened, and refusing
    # to record an incident because a search index is unhappy would be the tail
    # wagging the dog. The failure is counted on the run row and reported by
    # case_memory.status().
    index_result = None
    try:
        from core import case_memory
        index_result = case_memory.index_pending()
    except Exception as e:                              # noqa: BLE001
        logger.error(f"case memory index pass failed: {e}")
        index_result = {"error": f"{type(e).__name__}: {e}"}

    result = {"outcome": outcome, **counts, "detail": detail,
              "cursor": cursor,
              "daily_cap": cap, "made_today": made_today,
              "severity_floor": floor,
              "case_memory": index_result}
    if counts["capped"]:
        result["how_to_read_this"] = (
            "Some findings did not become incidents because the daily cap was "
            "reached. That is a cap being hit, which is not the same as a "
            "quiet network and not the same as them being unimportant.")
    return result


# Desktop notice for urgent incidents, sent once when an incident first
# reaches the urgent floor, by being created there or escalated to it. The
# floor is the duty loop's, so what wakes the agent also rings the bell.

DEFAULT_NOTIFY_DAILY_CAP = 20
_notify_day = {"date": None, "sent": 0, "cap_noticed": False}


def _notify_cap() -> int:
    block = (_config().get("incident_watcher") or {})
    try:
        return max(1, int(block.get("notify_daily_cap",
                                    DEFAULT_NOTIFY_DAILY_CAP)))
    except (TypeError, ValueError):
        return DEFAULT_NOTIFY_DAILY_CAP


def _urgent_floor_rank() -> int:
    from core import duty
    return duty._urgent_floor_rank()


def notify_urgent(incident: dict) -> dict:
    """Ring the desktop for an incident that just crossed the urgent floor."""
    block = (_config().get("incident_watcher") or {})
    if not block.get("notify", True):
        return {"sent": False, "reason": "incident_watcher.notify is off"}
    if incident.get("suppressed"):
        return {"sent": False, "reason": "suppressed"}
    try:
        floor = _urgent_floor_rank()
    except Exception as e:
        logger.error(f"urgent floor could not be read, no notice sent: {e}")
        return {"sent": False, "reason": f"urgent floor unreadable: {e}"}
    now_rank = _severity_rank(incident.get("severity"))
    prev = incident.get("previous_severity")
    if now_rank < floor or (prev is not None and _severity_rank(prev) >= floor):
        return {"sent": False, "reason": "not a crossing of the urgent floor"}

    from core import actions
    today = _now().date().isoformat()
    if _notify_day["date"] != today:
        _notify_day.update(date=today, sent=0, cap_noticed=False)
    cap = _notify_cap()
    if _notify_day["sent"] >= cap:
        if _notify_day["cap_noticed"]:
            return {"sent": False, "reason": "daily notice cap reached"}
        _notify_day["cap_noticed"] = True
        logger.warning(f"Urgent incident notices hit the daily cap of {cap}; "
                       f"incident #{incident.get('id')} and later ones are "
                       f"on the dashboard only.")
        return actions.notify(
            "AgentalSec: more urgent incidents",
            f"{cap} urgent incidents were shown today. Further ones are on "
            f"the Incidents tab only, until tomorrow.", urgency="critical")

    sev = (incident.get("severity") or "").upper()
    verb = "raised to" if prev is not None else "new,"
    result = actions.notify(
        f"AgentalSec: urgent incident ({verb} {sev})",
        f"{incident.get('title') or incident.get('detection_id')}\n"
        f"{incident.get('entity_type')}: {incident.get('entity_value')}",
        urgency="critical")
    if result.get("sent"):
        _notify_day["sent"] += 1
    return result


# THE DAEMON AROUND IT

_watcher_thread = None
_watcher_stop = threading.Event()
_watcher_state = {
    "running": False,
    "session_id": None,
    "modules": None,
    "last_error": None,
    "consecutive_failures": 0,
    "last_tick": None,
    "last_result": None,
    "ticks": 0,
}

_config_cache = None


def _config() -> dict:
    """The config block, read once. A watcher that cannot see config is OFF."""
    global _config_cache
    if _config_cache is None:
        try:
            import json as _json
            from core import settings
            _config_cache = _json.loads(
                settings.CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning(f"Watcher could not read config.json: {e}")
            _config_cache = {}
    return _config_cache


def _watcher_enabled() -> bool:
    block = (_config().get("incident_watcher") or {})
    return bool(block.get("enabled", True))


def _tick_seconds() -> int:
    block = (_config().get("incident_watcher") or {})
    return max(10, int(block.get("tick_seconds", DEFAULT_TICK_SECONDS)))


def start(session_id: str, modules: dict = None) -> bool:
    """
    Start the watcher's tick loop. Returns whether it started.

    Refuses rather than starting a thread that does nothing: a watcher that
    is 'running' and reading nothing is the failure this whole programme
    exists to remove, and it would look identical to a quiet network.
    """
    global _watcher_thread

    if _watcher_state["running"]:
        return False

    if not _watcher_enabled():
        logger.info("Incident watcher is switched off in config.json.")
        return False

    try:
        with me._get_readonly_conn() as conn:
            if not _table_ready(conn):
                logger.warning(
                    "Incident watcher NOT started: the incident table does "
                    "not exist. Run the migrations. Nothing is watching "
                    "findings until this is fixed, and that is a statement "
                    "about this app rather than about the network.")
                return False
    except Exception as e:
        logger.warning(f"Incident watcher NOT started, database unreadable: {e}")
        return False

    _watcher_state.update({
        "running": True, "session_id": session_id, "modules": modules,
        "last_error": None, "consecutive_failures": 0,
    })
    _watcher_stop.clear()

    def loop():
        interval = _tick_seconds()
        logger.info(f"Incident watcher started, every {interval}s.")
        while not _watcher_stop.is_set():
            try:
                result = watch_once(session_id, modules)
                _watcher_state["last_tick"] = _sql_ts(_now())
                _watcher_state["last_result"] = result
                _watcher_state["ticks"] += 1
                _watcher_state["last_error"] = None
                _watcher_state["consecutive_failures"] = 0
                if result.get("outcome") != "ok":
                    logger.warning(f"Watcher tick: {result.get('reason')}")
                elif result.get("new") or result.get("coalesced"):
                    logger.info(
                        "Watcher: %s new incident(s), %s coalesced, %s "
                        "finding(s) read.",
                        result.get("new"), result.get("coalesced"),
                        result.get("findings_read"))
            except Exception as e:
                _watcher_state["consecutive_failures"] += 1
                _watcher_state["last_error"] = f"{type(e).__name__}: {e}"
                logger.error(f"Watcher tick failed: {e}")
            _watcher_stop.wait(interval)
        _watcher_state["running"] = False
        logger.info("Incident watcher stopped.")

    _watcher_thread = threading.Thread(target=loop, name="incident-watcher",
                                       daemon=True)
    _watcher_thread.start()
    return True


def stop():
    _watcher_stop.set()


def status() -> dict:
    """
    The contract core/sensor_health reads: blind, blind_reason, running,
    last_error.

    `blind` IS THE INTERESTING KEY. The watcher is blind when the findings
    table cannot be read, and it is DEGRADED (which shows up in last_error)
    when the last tick errored. A watcher reporting running:true with zero
    incidents and no error is only allowed to mean "I read findings and found
    nothing above the bar", and the counts below are what makes that
    checkable rather than trusted.
    """
    last = _watcher_state.get("last_result") or {}

    out = {
        "running":  _watcher_state["running"],
        "role":     "incident_watcher",
        "ticks":    _watcher_state["ticks"],
        "last_tick": _watcher_state["last_tick"],
        "blind":    False,
        "tick_seconds": _tick_seconds(),
        "severity_floor": _pref_str("incident_severity_floor",
                                    DEFAULT_SEVERITY_FLOOR),
        "daily_cap": _pref_int("incident_daily_cap",
                               DEFAULT_INCIDENTS_PER_DAY),
    }

    if _watcher_state["consecutive_failures"]:
        out["consecutive_failures"] = _watcher_state["consecutive_failures"]
    if _watcher_state["last_error"]:
        out["last_error"] = _watcher_state["last_error"]

    if not _watcher_enabled():
        out["blind"] = True
        out["blind_reason"] = (
            "The watcher is switched off in config.json, so NOTHING IS "
            "READING FINDINGS. An empty incident list is a statement about "
            "this app's configuration and not about the network.")
    elif not _watcher_state["running"]:
        out["blind"] = True
        out["blind_reason"] = (
            "The watcher is not running, so no incident is being raised. "
            "Findings are still being written by the sensors; nothing is "
            "aggregating them.")
    elif last.get("outcome") == "error":
        out["blind"] = True
        out["blind_reason"] = (
            f"The last tick could not read findings: "
            f"{last.get('reason') or 'no reason recorded'}")
    elif last.get("outcome") == "refused":
        out["blind"] = True
        out["blind_reason"] = (
            f"The last tick refused: {last.get('reason') or 'no reason '
            'recorded'}")
    elif last:
        # A tick that ran and read. NOT blind, and it says what it read, so
        # "0 new incidents" cannot be mistaken for "did not look".
        out["last_result"] = {
            "outcome":       last.get("outcome"),
            "findings_read": last.get("findings_read"),
            "new":           last.get("new"),
            "coalesced":     last.get("coalesced"),
            "refused":       last.get("refused"),
            "capped":        last.get("capped"),
            "backlog":       last.get("backlog"),
            "detail":        last.get("detail"),
        }

    try:
        with me._get_readonly_conn() as conn:
            if _table_ready(conn):
                out["open_incidents"] = conn.execute(
                    "SELECT COUNT(*) FROM incident WHERE status IN "
                    "('new','triaged','action_pending')").fetchone()[0]
                out["incidents_today"] = _incidents_created_since(24)
                row = conn.execute(
                    "SELECT * FROM watcher_run ORDER BY id DESC LIMIT 1"
                ).fetchone()
                if row:
                    out["last_recorded_run"] = dict(row)
    except Exception as e:
        out["blind"] = True
        out["blind_reason"] = (f"The incident tables could not be read at "
                               f"all ({e})")

    return out


# READING THE LEDGER

def query_incidents(status_filter: str = None, entity_value: str = None,
                    detection_id: str = None, limit: int = 50,
                    include_resolved: bool = False) -> list[dict]:
    """
    The ledger, worst-and-newest first.

    Ordering is by severity then recency rather than by id, because the point
    of the list is the top of it. An incident list ordered by insertion puts
    whatever the watcher happened to see first at the top, which on a busy
    tick is arbitrary.
    """
    where, params = [], []
    if status_filter:
        where.append("status = ?")
        params.append(status_filter)
    elif not include_resolved:
        where.append("status IN ('new','triaged','action_pending')")
    if entity_value:
        where.append("entity_value = ?")
        params.append(entity_value)
    if detection_id:
        where.append("detection_id = ?")
        params.append(detection_id)

    sql = "SELECT * FROM incident"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY severity_rank DESC, last_seen_at DESC LIMIT ?"
    params.append(max(1, min(int(limit or 50), 500)))

    with me._get_readonly_conn() as conn:
        if not _table_ready(conn):
            return []
        rows = me._rows_to_dicts(conn.execute(sql, params).fetchall())

    for row in rows:
        for field, key in (("cia_json", "cia"), ("finding_ids_json",
                                                 "finding_ids"),
                           ("actions_json", "actions"),
                           ("coverage_json", "coverage")):
            try:
                row[key] = json.loads(row.pop(field) or "[]")
            except (TypeError, ValueError):
                row[key] = []
    return rows


def set_status(incident_id: int, status: str, by: str = "user",
               note: str = None) -> dict:
    """
    Move one incident along its state machine.

    THE STATE NAMES ARE ENFORCED BY THE DATABASE and the legal moves are
    enforced here, because the two answer different questions: the CHECK stops
    a typo, this stops a mistake of MEANING (resolving something that was
    never triaged is how a ledger quietly becomes a checklist).

    Returns a dict rather than raising on a bad move. This is called from a
    dashboard button and a bad click should not be an exception; but it says
    what it refused and why, which is the part that travels.
    """
    allowed_states = ("new", "triaged", "action_pending", "resolved",
                      "dismissed")
    if status not in allowed_states:
        return {"success": False,
                "error": (f"status must be one of {', '.join(allowed_states)}. "
                          f"Got {status!r}.")}
    if by not in ("watcher", "model", "user", "silence_timer"):
        return {"success": False,
                "error": (f"status_by must be one of watcher, model, user, "
                          f"silence_timer. Got {by!r}.")}
    if status == "dismissed" and not (note or "").strip():
        # Same rule as suppression: the record of WHY something stopped being
        # shown is the part that makes it auditable later.
        return {"success": False,
                "error": ("Dismissing an incident needs a note saying why. "
                          "This is the record of why it stopped being shown.")}

    with me._get_conn() as conn:
        if not _table_ready(conn):
            return {"success": False, "error": "the incident table does not exist"}
        row = conn.execute("SELECT * FROM incident WHERE id = ?",
                           (incident_id,)).fetchone()
        if row is None:
            return {"success": False,
                    "error": f"no incident with id {incident_id}"}
        if row["status"] == status:
            return {"success": True, "unchanged": True,
                    "note": f"already {status}",
                    "incident_id": incident_id}

        conn.execute("""
            UPDATE incident
               SET status = ?, status_at = ?, status_by = ?,
                   assessment = COALESCE(?, assessment)
             WHERE id = ?
        """, (status, _sql_ts(_now()), by, note, incident_id))

    # THE TRANSITION IS JOURNALLED, added 2026-09-23. An incident row is
    # rewritten every time a finding coalesces onto it, so a DIGEST of the row
    # would cry wolf on every tick; what is worth recording is the MOVE. This
    # one belongs in the chain for exactly the reason finding_dismissed does:
    # dismissing an incident stops it being shown, and the model moves
    # incidents to `triaged` on its own, which is the agent quietly changing
    # what a person will be told.
    #
    # AFTER the write and outside the connection block, the same discipline
    # every other journal call in this tree keeps: an integrity record that
    # can roll back or block the write it records is an availability bug.
    try:
        from core import memory_engine as _me
        _me._journal("incident_status_changed", "incident", incident_id,
                     {"from": row["status"], "to": status, "by": by,
                      "note": (note or "")[:300]})
    except Exception as e:                          # noqa: BLE001
        logger.error(f"Could not journal incident {incident_id} -> {status}: "
                     f"{e}")

    return {"success": True, "incident_id": incident_id,
            "from": row["status"], "to": status, "by": by}


def summary() -> dict:
    """
    Counts for the dashboard and for the model, never summed into one number.

    open / resolved / dismissed / action_pending are four different things and
    the reading note says so, for the same reason questions.summary keeps its
    four apart.
    """
    with me._get_readonly_conn() as conn:
        if not _table_ready(conn):
            return {"available": False,
                    "note": ("the incident table does not exist yet, so "
                             "nothing has been watched or triaged. This is "
                             "not zero incidents.")}

        counts = {"new": 0, "triaged": 0, "action_pending": 0, "resolved": 0,
                  "dismissed": 0}
        for row in conn.execute(
                "SELECT status, COUNT(*) n FROM incident GROUP BY status"):
            counts[row["status"]] = row["n"]

        worst = me._rows_to_dicts(conn.execute("""
            SELECT id, detection_id, entity_type, entity_value, severity,
                   title, first_seen_at, last_seen_at, finding_count
              FROM incident
             WHERE status IN ('new','triaged','action_pending')
             ORDER BY severity_rank DESC, last_seen_at DESC
             LIMIT 10
        """).fetchall())

        last_run = conn.execute(
            "SELECT * FROM watcher_run ORDER BY id DESC LIMIT 1").fetchone()

    return {
        "available": True,
        **counts,
        "open": counts["new"] + counts["triaged"] + counts["action_pending"],
        "worst_open": worst,
        "last_watcher_run": dict(last_run) if last_run else None,
        "how_to_read_this": (
            "new means the watcher raised it and nobody has looked. triaged "
            "means somebody (or the duty loop) has assessed it. "
            "action_pending means an action was proposed and is waiting on "
            "the owner. resolved and dismissed are both closed and are never "
            "added together: resolved means it was dealt with, dismissed means "
            "somebody decided it did not need to be."),
    }
