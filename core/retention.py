# core/retention.py
# AgentalSec V2, retention. Keeping the database from eating the disk.
#
# WHY THIS EXISTS
#
# The packet table grows at roughly 100 MB a day on a machine that is only on
# part of the time, and it is 98.7% of the file. Nothing removed anything, so
# the only question was when the disk filled, not whether.
#
# THE DECISIONS, SETTLED IN TODO.md SECTION 23. DO NOT REOPEN THEM HERE.
#
#   * Retention triggers on DATABASE SIZE, not on the age of a row. Time-based
#     retention punishes the light user, who loses data they barely have, and
#     fails the heavy user, whose always-on homelab passes any size limit long
#     before the age limit matters. The constraint was never age. It was disk.
#
#   * Deletion happens by WHOLE CAPTURE SESSION, oldest first, never by
#     timestamp. Slicing "the oldest 40% by captured_at" cuts through the
#     middle of a run, and an interval recomputed from half a run is DISTORTED
#     rather than absent, which is the worse of the two failures. Deleting by
#     session_id cannot do that. It costs nothing extra, because
#     intervals._gaps_within_sessions already discards any gap that crosses a
#     session boundary, so every measurement this tool can make already lives
#     inside one run.
#
#   * MEASURE FIRST. The summary has to be on the baseline before the rows go,
#     or the prune is throwing away evidence that was never read.
#
#   * The model NEVER deletes. It may mark things worth keeping, which is
#     additive: the worst an injected model achieves is a larger database,
#     never a blinder one. See _protected_sessions and section 23.4.
#
# ON TIMEZONES, WHICH BIT US ONCE ALREADY
#
# TODO.md 23.9 warns that packets.captured_at is naive UTC and that a prune
# comparing it against a local now() deletes seven hours too much, silently.
# This module never makes that comparison. It orders sessions by their own
# MIN(captured_at) and compares those strings against EACH OTHER, all of them
# written by the same SQLite default in the same zone. There is no wall-clock
# cutoff anywhere in this file, and there should never be one. If somebody
# later adds a --since flag, that is where the bug comes back.
#
# RULE 2 HOLDS. Python decides nothing about what is interesting. It deletes
# the oldest whole run when the file is too big, and it skips whatever has
# been marked. Which runs matter is not a judgement this module makes.

import json
import logging
import os
import shutil
import sqlite3
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


# WHAT IS PRUNABLE, AND WHAT IS NOT
#
# Only raw observation tables keyed by session_id appear here. Each entry is
# (table, time_column). The time column is used ONLY to order sessions by age
# and to report what a session covered, never as a deletion cutoff.
#
# packets is the whole problem: 98.7% of the file. events and
# port_scan_results are included because they belong to the same capture run
# and leaving them behind produces a session that half exists, which is the
# partial-session failure wearing a different hat.

PRUNABLE = [
    ("packets",           "captured_at"),
    ("events",            "occurred_at"),
    ("port_scan_results", "scanned_at"),
]

# Everything else, and WHY, because the next person will want to add to the
# list above and this is the argument they need to have first.
#
#   behavioral_session, behavioral_baseline, behavioral_deviation,
#   baseline_session_seen
#       The summaries. Pruning these deletes the thing the raw rows were kept
#       in order to produce. Agreed never-prune since the baseline design.
#
#   integrity_journal
#       The tamper chain. Deleting entries BREAKS verification by design, so a
#       prune that touched it would manufacture the exact alarm the chain
#       exists to raise. Never.
#
#   findings, dismissed_findings
#       The record of what was raised and what a human said about it. Small,
#       and it is the audit trail for the review queue.
#
#   known_devices, sensors, user_preferences, runbook, rollup_log, probe_run,
#   presence_sweep, presence_observation, router_clients, router_config,
#   dns_queries, pcap_results
#       Inventory, configuration, and series that are cheap per row. The
#       presence series in particular is what answers "was this device here
#       last week", which is a question about the past by definition.
#
#   session_log
#       Already capped at 500 rows per session by a trigger in Schema.SQL.
#
#   enrichment, enrichment_queue
#       Added 2026-09-02 with TODO 40, and deliberately not prunable. These
#       rows EXPIRE ON THEIR OWN: every one carries expires_at, and a stale
#       row is re-run the next time somebody asks about that indicator. Adding
#       them here would mean two mechanisms deleting the same rows on
#       different rules, and the size argument does not apply anyway, one
#       row per indicator ever asked about, a few hundred bytes each, against
#       a budget measured in gigabytes.
NEVER_PRUNE_NOTE = "see the comment above PRUNABLE"


# PREFERENCES
#
# Both marks are preferences, not constants, because the answer for a business
# deployment is "set 20 GB and change no code". They live in user_preferences,
# which integrity.snapshot_config already journals on change, so an edit to
# either one leaves a trace.

PREF_TRIGGER = "retention_trigger_bytes"
PREF_FLOOR   = "retention_floor_bytes"
PREF_KEEP    = "retention_keep_sessions"
PREF_PARTIAL = "retention_partial_delete"

# 2026-09-01. Whether the app prunes itself at all.
#
# THREE STATES, NOT TWO, and the third is the point. Unset means nobody has
# been asked yet, which is different from "off". Unset gets the setup question
# from 23.5; "0" means a person said no and is not asked again.
#
# Default is unset, so an existing install upgrades into "ask", never into
# "start deleting". Deletion is the only irreversible thing here and it does
# not get to arrive in a patch note.
PREF_ENABLED = "retention_enabled"

DEFAULT_TRIGGER_BYTES = 2_000_000_000    # 2.0 GB
DEFAULT_FLOOR_BYTES   = 1_500_000_000    # 1.5 GB

# 23.5, THE SETUP CHOICES. Real numbers, measured, not invented.
#
# The measurement they come from: about 100 MB a day on a machine that is on
# part of the time, 1.6M packet rows over 12 days, packets are 98.7% of the
# file. The "roughly" column is that rate divided into the trigger, and it is
# stated as roughly because it moves with how busy the network is and how long
# the app is left running.
#
# The floor is 75% of the trigger throughout. That clears MIN_GAP_FRACTION
# with room to spare and means one prune buys back about a quarter of the
# budget rather than firing again next week.
#
# 2026-09-01. THE SMALLEST OPTION IS 2 GB, NOT 1. Owner's call, and the reason
# is worth keeping. The database is already about 1.6 GB on a machine that is
# used part time, so a 1 GB budget would have been over the line the moment
# somebody chose it, and the very first thing that option ever did would be to
# delete. An option you cannot pick without immediately losing data is not
# really an option, it is a trap with a label on it.
#
# 2 GB is also DEFAULT_TRIGGER_BYTES below, so the smallest choice and the
# unconfigured default are now the same number. Deliberate: somebody picking
# the smallest one should not land on a different limit than the one that was
# already quietly in force.
PRESETS = [
    {
        "key":     "occasional",
        "label":   "Occasional use, a few hours a week",
        "trigger": 2_000_000_000,
        "floor":  1_500_000_000,
        "roughly": "about 6 months of packets",
    },
    {
        "key":     "homelab",
        "label":   "Homelab, running most of the time",
        "trigger": 5_000_000_000,
        "floor":  3_750_000_000,
        "roughly": "about 7 weeks of packets",
    },
    {
        "key":     "business",
        "label":   "Business, always on",
        "trigger": 20_000_000_000,
        "floor":  15_000_000_000,
        "roughly": "about 7 months of packets, and 20 GB of disk to hold it",
    },
]

# THE TRADE, IN THE PROMPT ITSELF. 23.5 says do not make the user infer it,
# and 23.6 says the honest version of it is not what people expect.
TRADE_NOTE = (
    "A smaller database means a shorter memory. The tool cannot see a pattern "
    "slower than the data it kept.\n"
    "Worth knowing before you pick: keeping more days buys less than it looks "
    "like it should. This tool cannot measure anything slower than ONE capture "
    "run, so a six hour beacon never shows up in four hour runs no matter how "
    "many of them are on disk. What actually buys detection is leaving the app "
    "running longer, and that is your call, not the code's."
)

# The gap between the two marks is REQUIRED, not stylistic. Prune to 1.99 and
# the next check is over the line again and it fires forever. A floor within
# 10% of the trigger is refused rather than quietly widened, because silently
# changing an operator's number is how a tool ends up doing something nobody
# chose.
MIN_GAP_FRACTION = 0.10

# Rows per delete chunk. Small enough that the WAL does not balloon, large
# enough that a million-row session does not take a thousand round trips.
CHUNK = 50_000


def _pref_int(conn, key, default):
    row = conn.execute(
        "SELECT value FROM user_preferences WHERE key=?", (key,)
    ).fetchone()
    if not row or row[0] in (None, ""):
        return default
    try:
        value = int(float(row[0]))
    except (TypeError, ValueError):
        logger.warning(f"retention: preference {key}={row[0]!r} is not a "
                       f"number. Using the default {default}.")
        return default
    if value <= 0:
        logger.warning(f"retention: preference {key}={value} is not positive. "
                       f"Using the default {default}.")
        return default
    return value


def limits(conn) -> dict:
    """
    The trigger and floor in force, validated.

    An invalid pair is REFUSED, not corrected. The caller gets ok=False and a
    reason it can print. A retention job that silently invents its own limits
    is one that deletes an amount nobody agreed to.
    """
    trigger = _pref_int(conn, PREF_TRIGGER, DEFAULT_TRIGGER_BYTES)
    floor   = _pref_int(conn, PREF_FLOOR,   DEFAULT_FLOOR_BYTES)

    if floor >= trigger:
        return {"ok": False, "trigger": trigger, "floor": floor,
                "reason": (f"floor ({floor}) must be below trigger "
                           f"({trigger}). Nothing was pruned.")}

    if (trigger - floor) < (trigger * MIN_GAP_FRACTION):
        return {"ok": False, "trigger": trigger, "floor": floor,
                "reason": (f"floor ({floor}) is within "
                           f"{MIN_GAP_FRACTION:.0%} of trigger ({trigger}). "
                           f"That gap is too small and the prune would fire "
                           f"on every check. Nothing was pruned.")}

    return {"ok": True, "trigger": trigger, "floor": floor, "reason": None}


# SIZE ON DISK

def database_bytes(db_path) -> dict:
    """
    What the database actually occupies, as the filesystem sees it.

    The -wal file is counted. In WAL mode committed data can sit in the log
    for a long time before a checkpoint moves it into the main file, so a
    check that reads only the .db can be a hundred megabytes optimistic and
    then jump the moment a checkpoint runs. Counting both is the honest
    number and it is the one the trigger compares against.
    """
    path = Path(db_path)
    parts = {}
    total = 0
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(path) + suffix)
        size = p.stat().st_size if p.exists() else 0
        parts[p.name] = size
        total += size
    return {"total": total, "parts": parts, "main": parts.get(path.name, 0)}


def human_bytes(n) -> str:
    """
    DECIMAL units, deliberately, because the operator types decimal.

    prune_db.py parses "2GB" as 2,000,000,000. Printing that back in 1024-based
    units labelled GB reported it as "1.9 GB", so the tool answered a number
    the operator did not type and appeared to have rounded their limit down.
    Small, and exactly the kind of small that makes somebody distrust a number
    they cannot check. In and out are the same base now.
    """
    if n is None:
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1000 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1000.0


# WHAT EACH SESSION COSTS
#
# WHY THIS IS AN ESTIMATE AND WHY THAT IS FINE
#
# SQLite does not track bytes per row group. dbstat can give real page usage
# per table but not per session, and it is a compile-time option that is
# absent on plenty of builds, this project's Windows target included on some
# Python distributions.
#
# So the per-session number below is a MEASURED PAYLOAD SIZE, being the actual
# length of every value in the row plus a per-row overhead constant, and it is
# labelled an estimate everywhere it is printed. It is used to decide HOW MANY
# sessions to drop. It is never used to decide whether the job is done: that
# check reads the file size after the vacuum, per 23.3, because an estimate
# that drifts would otherwise turn into a prune loop that never terminates.

ROW_OVERHEAD_BYTES = 24


def _payload_expr(conn, table) -> str:
    """
    SUM of the on-disk length of every column in a row.

    Built from PRAGMA table_info rather than hardcoded, so a migration that
    adds a column does not silently make every estimate too small.
    """
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
    if not cols:
        return "0"
    # length() on an INTEGER returns its digit count, which understates the
    # 1 to 8 bytes SQLite actually stores. Close enough for a sizing estimate
    # and wrong in the safe direction: it under-reports, so the prune frees
    # slightly more than it predicted rather than slightly less.
    return " + ".join(f"COALESCE(LENGTH(CAST({c} AS BLOB)), 0)" for c in cols)


def session_inventory(conn, with_bytes: bool = True) -> list:
    """
    Every capture session that holds prunable rows, oldest first.

    Oldest is decided by the session's own earliest timestamp across the
    prunable tables. String comparison of naive UTC timestamps written by the
    same default, which is the only kind of time comparison this module makes.

    with_bytes=False skips the per-column size sum, which is most of the cost
    on a large store; bytes_estimate is then None (WS-1).
    """
    sessions = {}

    for table, time_col in PRUNABLE:
        expr = _payload_expr(conn, table) if with_bytes else "0"
        rows = conn.execute(
            f"SELECT session_id, COUNT(*) AS n, MIN({time_col}) AS first_at, "
            f"MAX({time_col}) AS last_at, "
            f"SUM({expr}) AS payload "
            f"FROM {table} GROUP BY session_id"
        ).fetchall()
        for sid, n, first_at, last_at, payload in rows:
            s = sessions.setdefault(sid, {
                "session_id": sid, "rows": 0, "bytes_estimate": 0,
                "first_at": None, "last_at": None, "tables": {},
            })
            s["rows"] += n or 0
            if with_bytes:
                s["bytes_estimate"] += ((payload or 0)
                                        + (n or 0) * ROW_OVERHEAD_BYTES)
            else:
                s["bytes_estimate"] = None
            s["tables"][table] = n or 0
            if first_at and (s["first_at"] is None
                             or first_at < s["first_at"]):
                s["first_at"] = first_at
            if last_at and (s["last_at"] is None or last_at > s["last_at"]):
                s["last_at"] = last_at

    out = list(sessions.values())
    # Sessions with no timestamp at all sort last, not first. A NULL is
    # unknown age, and deleting an unknown-age run before a known-old one is
    # a guess dressed up as an ordering.
    out.sort(key=lambda s: (s["first_at"] is None, s["first_at"] or ""))
    return out


def run_summary(conn) -> dict:
    """
    How many capture runs hold prunable rows, and the oldest and newest time.

    Index lookups only, so a page read stays fast on a large store (WS-1):
    session_inventory() reads every row and takes seconds.
    """
    sids, oldest, newest = set(), None, None
    for table, time_col in PRUNABLE:
        try:
            # Walks the distinct session ids through the index, one seek each.
            sids.update(x for (x,) in conn.execute(
                f"WITH RECURSIVE s(x) AS (SELECT MIN(session_id) FROM {table} "
                f"UNION ALL SELECT (SELECT MIN(session_id) FROM {table} "
                f"WHERE session_id > s.x) FROM s WHERE s.x IS NOT NULL) "
                f"SELECT x FROM s WHERE x IS NOT NULL"))
            if conn.execute(f"SELECT EXISTS(SELECT 1 FROM {table} "
                            f"WHERE session_id IS NULL)").fetchone()[0]:
                sids.add(None)
            lo, hi = conn.execute(
                f"SELECT (SELECT MIN({time_col}) FROM {table}), "
                f"(SELECT MAX({time_col}) FROM {table})").fetchone()
        except sqlite3.OperationalError:
            continue
        if lo and (oldest is None or lo < oldest):
            oldest = lo
        if hi and (newest is None or hi > newest):
            newest = hi
    return {"runs": len(sids), "oldest_at": oldest, "newest_at": newest}


# WHAT MUST NOT BE DELETED

def _protected_sessions(conn, current_session_id=None) -> dict:
    """
    session_id -> the reason it is protected. Reasons are printed verbatim.

    THE KEEP-LIST, AND WHAT IS DELIBERATELY NOT BUILT YET.

    23.4 settled that the model may MARK things worth keeping and that the
    prune skips them. It left one thing open: whether a mark lands on a
    SESSION or on an ENTITY. This function implements the session form only,
    read from a preference, because that form is unambiguous.

    The entity form is genuinely undecided and must not be guessed here.
    "Keep every session containing traffic involving the gateway" protects
    essentially every session ever captured, because the gateway is in all of
    them, and a keep-list that pins the whole database is a disk-full bug
    wearing the costume of a safety feature. Step 3 of 23.7 decides that,
    with a real answer for what an entity mark means. Until then this returns
    session marks and says so.
    """
    protected = {}

    if current_session_id:
        protected[current_session_id] = "the run that is happening right now"

    row = conn.execute(
        "SELECT value FROM user_preferences WHERE key=?", (PREF_KEEP,)
    ).fetchone()
    if row and row[0]:
        try:
            for sid in json.loads(row[0]):
                protected.setdefault(str(sid), "marked as worth keeping")
        except (TypeError, ValueError):
            logger.warning(f"retention: {PREF_KEEP} is not valid JSON. "
                           f"Treating the keep-list as EMPTY would silently "
                           f"delete protected runs, so nothing is pruned "
                           f"until it is fixed.")
            protected["__unreadable_keep_list__"] = "keep-list unreadable"

    return protected


# MEASURE FIRST

def measure_first(conn, write=True) -> dict:
    """
    Put the measured spacing on the baselines BEFORE any row is deleted.

    rollup_engine does this on every rollup, so in normal operation there is
    nothing left to do here and this returns measured=0. It exists for the
    case that actually loses data: a database carrying runs that no rollup
    ever revisited, which is exactly the state this project was in when
    retention was specified.

    Only fills value_mean / stddev / min / max and beacon_detail on
    beacon_destinations rows. Never touches confidence, sample_count,
    flagged_as_normal or alert_suppressed, for the reason
    backfill_intervals.py already gives: measuring something is not a reason
    to revisit a decision somebody made about it.
    """
    from datetime import datetime, timezone
    from core import intervals

    cols = {r[1] for r in
            conn.execute("PRAGMA table_info(behavioral_baseline)")}
    if "beacon_detail" not in cols:
        return {"ok": False, "measured": 0, "skipped": 0,
                "reason": ("behavioral_baseline.beacon_detail is missing, so "
                           "measurements cannot be stored. Start main.py once "
                           "to run the migration. NOTHING WAS PRUNED.")}

    rows = conn.execute(
        "SELECT id, entity_value FROM behavioral_baseline "
        "WHERE behavior_key='beacon_destinations' AND entity_type='ip'"
    ).fetchall()

    measured = skipped = 0
    for bid, ip in rows:
        try:
            res = intervals.contact_intervals(conn, ip)
        except Exception as e:
            logger.warning(f"retention: could not measure {ip}: {e}")
            skipped += 1
            continue
        mr = res.get("most_regular")
        if not mr:
            skipped += 1
            continue
        measured += 1
        if write:
            detail = json.dumps({
                "measured_at": datetime.now(timezone.utc).isoformat(),
                "unit": "seconds_between_contacts",
                "source": "measured before a retention prune",
                "most_regular": mr,
                "destinations": res.get("destinations", [])[:8],
                "note": intervals.describe(mr),
            })
            conn.execute(
                "UPDATE behavioral_baseline SET value_mean=?, value_stddev=?, "
                "value_min=?, value_max=?, beacon_detail=? WHERE id=?",
                (mr["mean_seconds"], mr["stddev_seconds"], mr["min_seconds"],
                 mr["max_seconds"], detail, bid))
    if write:
        conn.commit()
    return {"ok": True, "measured": measured, "skipped": skipped,
            "reason": None}


# THE PLAN

def plan(conn, db_path, current_session_id=None) -> dict:
    """
    What WOULD be deleted, and why. Changes nothing.

    Every path out of this function is printable. A prune that cannot explain
    itself before it runs is one nobody will trust enough to enable.
    """
    lim = limits(conn)
    size = database_bytes(db_path)
    protected = _protected_sessions(conn, current_session_id)

    result = {
        "size_now": size["total"], "size_parts": size["parts"],
        "trigger": lim["trigger"], "floor": lim["floor"],
        "protected": protected, "sessions": [], "to_delete": [],
        "would_free_estimate": 0, "triggered": False,
        "ok": lim["ok"], "reason": lim["reason"],
    }
    if not lim["ok"]:
        return result

    if "__unreadable_keep_list__" in protected:
        result["ok"] = False
        result["reason"] = (f"{PREF_KEEP} is not valid JSON. Fix or clear it. "
                            f"Refusing to prune while the keep-list cannot be "
                            f"read.")
        return result

    # The byte estimate is only needed once there is something to choose.
    over = size["total"] >= lim["trigger"]
    inventory = session_inventory(conn, with_bytes=over)
    result["sessions"] = inventory

    if not over:
        result["reason"] = (f"{human_bytes(size['total'])} is under the "
                            f"{human_bytes(lim['trigger'])} trigger. Nothing "
                            f"to do.")
        return result

    result["triggered"] = True

    # Never delete the newest run even when it is not the current one. It is
    # the only one whose measurements a rollup may not have finished with.
    newest = inventory[-1]["session_id"] if inventory else None
    if newest:
        protected.setdefault(newest, "the newest run on record")

    freed = 0
    for s in inventory:
        if size["total"] - freed <= lim["floor"]:
            break
        if s["session_id"] in protected:
            continue
        result["to_delete"].append(s)
        freed += s["bytes_estimate"]

    result["would_free_estimate"] = freed
    projected = size["total"] - freed

    if not result["to_delete"]:
        result["reason"] = ("Over the trigger, but every session on record is "
                            "protected. Nothing can be pruned. Raise the "
                            "trigger or clear a keep mark.")
    elif projected > lim["floor"]:
        result["reason"] = (
            f"Deleting every unprotected session is estimated to leave "
            f"{human_bytes(projected)}, still above the "
            f"{human_bytes(lim['floor'])} floor. Note the estimate counts row "
            f"PAYLOAD only, not indexes or page overhead, so the real saving "
            f"is larger than this and one pass may well be enough. If it is "
            f"not, run it again, or accept that the floor sits below what the "
            f"never-pruned tables occupy on their own.")
    return result


# THE DELETE

def _delete_session(conn, session_id) -> dict:
    """
    Remove one whole session from every prunable table.

    A crash partway through leaves half a session, which is the exact state
    23.2 says must never be measured from. So the session being deleted is
    recorded in user_preferences BEFORE the first delete and cleared after the
    last one. A later run reads that marker and finishes the job rather than
    measuring the wreckage. The marker is the difference between an
    interrupted delete and a corrupt record.
    """
    conn.execute(
        "INSERT INTO user_preferences(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
        "updated_at=CURRENT_TIMESTAMP",
        (PREF_PARTIAL, session_id))
    conn.commit()

    removed = {}
    for table, _ in PRUNABLE:
        n = 0
        while True:
            cur = conn.execute(
                f"DELETE FROM {table} WHERE id IN ("
                f"  SELECT id FROM {table} WHERE session_id=? LIMIT {CHUNK})",
                (session_id,))
            conn.commit()
            if not cur.rowcount:
                break
            n += cur.rowcount
        removed[table] = n

    conn.execute("DELETE FROM user_preferences WHERE key=?", (PREF_PARTIAL,))
    conn.commit()
    return removed


def resume_interrupted(conn) -> str | None:
    """
    Finish a delete that a crash interrupted. Returns the session id if there
    was one. Call this before measuring anything.
    """
    row = conn.execute(
        "SELECT value FROM user_preferences WHERE key=?", (PREF_PARTIAL,)
    ).fetchone()
    if not row or not row[0]:
        return None
    sid = row[0]
    logger.warning(f"retention: a previous delete of session {sid} did not "
                   f"finish. Completing it before anything else, because a "
                   f"half-deleted run must never be measured from.")
    _delete_session(conn, sid)
    return sid


# THE VACUUM
#
# THE DECISION, PER 23.3: FULL VACUUM AFTER PRUNING. Written down with the
# reason so it is not re-argued.
#
# The alternative was PRAGMA auto_vacuum=INCREMENTAL, which shrinks gradually
# and never takes a long lock. It has to be set BEFORE the data exists.
# Turning it on for an existing 1.4 GB database requires a full VACUUM anyway,
# so the incremental option costs one full VACUUM to avoid future full
# VACUUMs, and then adds a permanent per-commit cost plus pointer-map pages to
# every future write. For a database that is pruned rarely and written
# constantly, that is the wrong trade.
#
# The real cost of the choice is honest and stated: VACUUM needs free disk
# roughly equal to the database, and it holds an exclusive lock for the
# duration. Both are checked below rather than discovered.

VACUUM_HEADROOM = 1.15


def vacuum(db_path, dry_run=True) -> dict:
    """
    Rebuild the file so deleted pages are actually returned to the disk.

    SQLite does not shrink on DELETE. It marks pages free for reuse inside the
    same file. Without this step the size check reads the same number after a
    prune as before it, and the caller prunes again, and again, until the
    database is empty. That loop is the single most destructive thing this
    module could do, so the size check MUST read the file after the vacuum,
    never before.
    """
    path = Path(db_path)
    size = database_bytes(path)
    free = shutil.disk_usage(path.parent).free
    needed = int(size["main"] * VACUUM_HEADROOM)

    out = {"before": size["total"], "after": None, "freed": 0,
           "free_disk": free, "needed": needed, "ran": False, "reason": None}

    if free < needed:
        out["reason"] = (
            f"VACUUM needs about {human_bytes(needed)} of free disk and there "
            f"is {human_bytes(free)}. Refusing to start it. The rows are "
            f"deleted and the space will be reused by future writes, but the "
            f"FILE will not shrink until this runs. Free up space and run "
            f"the prune again with nothing to delete to vacuum alone.")
        return out

    if dry_run:
        out["reason"] = "dry run, VACUUM not executed"
        return out

    conn = sqlite3.connect(path, timeout=30)
    try:
        # WAL pages are folded in first so VACUUM sees all the free space.
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.isolation_level = None      # VACUUM cannot run inside a txn
        conn.execute("VACUUM")
        out["ran"] = True
        # In WAL mode VACUUM writes the rebuilt file into the -wal, so the
        # size read next is old file plus new copy until this checkpoint.
        busy = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]
    finally:
        conn.close()

    after = database_bytes(path)
    out["after"] = after["total"]
    out["freed"] = out["before"] - after["total"]
    if busy:
        out["reason"] = (
            f"Vacuumed, but another connection kept the rebuilt copy from "
            f"being moved out of the -wal file, so the size on disk "
            f"({human_bytes(after['total'])}) still counts it. It shrinks "
            f"at the next checkpoint.")
    return out


# THE WHOLE JOB

def run(db_path, current_session_id=None, dry_run=True, progress=None) -> dict:
    """
    Measure, prune whole sessions oldest first, vacuum, then read the real
    size. Dry run by default.

    Returns a dict a caller can print. Never raises for an ordinary refusal:
    a refusal is a result with ok=False and a reason, because a retention job
    that throws is a retention job somebody switches off.
    """
    say = progress or (lambda *_: None)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys=ON")

    report = {"dry_run": dry_run, "deleted_sessions": [], "rows_removed": {},
              "measure": None, "vacuum": None, "ok": True, "reason": None}
    try:
        if not dry_run:
            resumed = resume_interrupted(conn)
            if resumed:
                report["resumed_session"] = resumed
                say(f"Finished an interrupted delete of session {resumed}.")

        p = plan(conn, db_path, current_session_id)
        report["plan"] = p
        if not p["ok"] or not p["triggered"] or not p["to_delete"]:
            report["ok"] = p["ok"]
            report["reason"] = p["reason"]
            return report

        # An advisory reason from the plan must not be swallowed just because
        # the plan also found work to do. The "this will not reach the floor"
        # warning is exactly the case where there IS work to do and the
        # operator still needs to know it will not be enough.
        report["reason"] = p["reason"]

        say(f"Measuring before deleting anything.")
        m = measure_first(conn, write=not dry_run)
        report["measure"] = m
        if not m["ok"]:
            report["ok"] = False
            report["reason"] = m["reason"]
            return report
        say(f"  {m['measured']} baseline(s) carry measured spacing, "
            f"{m['skipped']} had too few contacts to measure.")

        for s in p["to_delete"]:
            say(f"{'WOULD DELETE' if dry_run else 'Deleting'} session "
                f"{s['session_id']}  {s['rows']} rows  "
                f"{s['first_at']} to {s['last_at']}  "
                f"about {human_bytes(s['bytes_estimate'])}")
            if not dry_run:
                removed = _delete_session(conn, s["session_id"])
                for t, n in removed.items():
                    report["rows_removed"][t] = (
                        report["rows_removed"].get(t, 0) + n)
            report["deleted_sessions"].append(s["session_id"])
    finally:
        conn.close()

    report["vacuum"] = vacuum(db_path, dry_run=dry_run)
    _freed = human_bytes(report["vacuum"]["freed"])
    say(report["vacuum"]["reason"] or f"Vacuumed. {_freed} returned to disk.")

    final = database_bytes(db_path)
    report["size_after"] = final["total"]

    # THE TERMINATION CHECK. This is the one that stops the loop 23.3 warns
    # about, and it reads the FILE, not the estimate.
    #
    # It deliberately does not retry. A prune that re-checks and goes again on
    # its own is one bad size reading away from emptying the database, and the
    # operator finds out afterwards. One pass, then a sentence saying where it
    # got to, and the decision to run it again belongs to a person.
    if not dry_run and final["total"] > report["plan"]["floor"]:
        report["reason"] = (
            f"Still {human_bytes(final['total'])} after pruning and "
            f"vacuuming, above the {human_bytes(report['plan']['floor'])} "
            f"floor. NOT retrying automatically. Run it again to take the "
            f"next oldest session, or raise the floor. If a second pass frees "
            f"nothing either, the floor is below what the never-pruned tables "
            f"occupy and no amount of pruning will reach it.")
    return report


# IS IT SWITCHED ON, AND WHAT WOULD IT DO
#
# Everything below this line is 2026-09-01. The engine above was built on
# 2026-08-31 and then nothing called it, so the app never pruned itself and the
# only way to reclaim disk was to remember a script existed. This part is the
# plumbing: a switch, a read-only summary, a first-run question, and the two
# hooks main.py uses.


def _write_pref(conn, key, value):
    conn.execute(
        "INSERT INTO user_preferences(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
        "updated_at=CURRENT_TIMESTAMP",
        (key, str(value)))
    conn.commit()


def _journal(conn, reason):
    """
    Record a preference change in the integrity journal, using the connection
    the change was made on.

    THE CONNECTION MATTERS AND IT COST US A BUG. Called with no conn,
    snapshot_config opens the DEFAULT database, so a setup run pointed at
    another file journals the change into a file it did not touch. It also
    only commits when it opened the connection itself, so passing one and
    forgetting to commit discards the entry silently. prune_db.py found that
    the same way, by counting rows instead of trusting the return value.

    Non-fatal. A missing journal entry is bad; refusing to save the setting
    over it would be worse.
    """
    try:
        from core import integrity
        integrity.snapshot_config(reason=reason, conn=conn)
        conn.commit()
    except Exception as e:
        logger.debug(f"Could not journal '{reason}': {e}")


def enabled(conn) -> bool:
    """True only if a person has switched it on. Unset is NOT on."""
    row = conn.execute(
        "SELECT value FROM user_preferences WHERE key=?", (PREF_ENABLED,)
    ).fetchone()
    return bool(row) and str(row[0]).strip() in ("1", "true", "True", "yes")


def configured(conn) -> bool:
    """Whether the setup question has been answered either way."""
    row = conn.execute(
        "SELECT value FROM user_preferences WHERE key=?", (PREF_ENABLED,)
    ).fetchone()
    return bool(row) and str(row[0]).strip() != ""


def status(db_path, current_session_id=None) -> dict:
    """
    Read-only. What the database costs and what retention would do about it.

    This is what the model's tool returns and what boot logs. It CHANGES
    NOTHING and it cannot: there is no code path from here to a delete. That
    is deliberate and 23.4 is the argument. Deletion is the only irreversible
    act in this application, and the blinding attack in its purest form is a
    model that gets to choose what disappears.
    """
    conn = sqlite3.connect(db_path)
    try:
        lim  = limits(conn)
        size = database_bytes(db_path)
        runs = run_summary(conn)
        prot = _protected_sessions(conn, current_session_id)
        is_on   = enabled(conn)
        is_set  = configured(conn)
    finally:
        conn.close()

    over = lim["ok"] and size["total"] >= lim["trigger"]

    if not lim["ok"]:
        note = f"Retention limits are not usable: {lim['reason']}"
    elif over and is_on:
        note = (f"{human_bytes(size['total'])} is at or over the "
                f"{human_bytes(lim['trigger'])} trigger. The oldest whole "
                f"capture runs will be pruned at the next clean shutdown.")
    elif over:
        note = (f"{human_bytes(size['total'])} is at or over the "
                f"{human_bytes(lim['trigger'])} trigger and automatic pruning "
                f"is OFF, so nothing will be deleted. The database will keep "
                f"growing until somebody prunes it.")
    else:
        left = lim["trigger"] - size["total"]
        note = (f"{human_bytes(size['total'])} of a "
                f"{human_bytes(lim['trigger'])} budget, "
                f"{human_bytes(left)} of headroom.")

    # THE DECLARED WINDOWS, 2026-09-23. EM-13.
    #
    # config.json has carried four windows since the port and NOT ONE was read
    # by any code. These three lines are the reading: the windows that apply to
    # raw observation rows are named, the two that are declared-only are named
    # as such, and what each would remove is counted. Counted, never deleted:
    # there is still no path from this function to a delete, which is 23.4's
    # rule and it is not being reopened.
    try:
        win = window_status(db_path, None, current_session_id)
    except Exception as e:                                    # noqa: BLE001
        win = {"applied": {}, "declared_only": {}, "unreadable": [str(e)],
               "would_remove": {}, "note": f"the windows could not be read: {e}"}

    return {
        "size_bytes":     size["total"],
        "size_human":     human_bytes(size["total"]),
        "size_parts":     size["parts"],
        "trigger_bytes":  lim["trigger"],
        "trigger_human":  human_bytes(lim["trigger"]),
        "floor_bytes":    lim["floor"],
        "floor_human":    human_bytes(lim["floor"]),
        "limits_ok":      lim["ok"],
        "limits_reason":  lim["reason"],
        "over_trigger":   over,
        "headroom_bytes": max(0, lim["trigger"] - size["total"]),
        "headroom_human": human_bytes(max(0, lim["trigger"] - size["total"])),
        "auto_prune":     is_on,
        "configured":     is_set,
        "capture_runs":   runs["runs"],
        "oldest_run_at":  runs["oldest_at"],
        "newest_run_at":  runs["newest_at"],
        "protected_runs": len([k for k in prot
                               if k != "__unreadable_keep_list__"]),
        # THE DECLARED WINDOWS, READ AT LAST.
        "windows":            win["applied"],
        "windows_declared_only": win["declared_only"],
        "windows_unreadable": win["unreadable"],
        "windows_would_remove": win["would_remove"],
        "windows_note":       win["note"],
        "note":           note,
        "measurement_limit": (
            "Nothing here can measure a pattern slower than a single capture "
            "run. Days of packets on disk do not substitute for having "
            "watched. If you want an accurate reading of your network, leave "
            "the app running for longer stretches, at least every now and "
            "then, even if you would rather not have it on all the time. A "
            "long run is the only way it can see traffic that is slow in "
            "transit or on a schedule."),
        "model_cannot_delete": True,
    }


# 23.5, THE SETUP QUESTION

def choice_lines(db_path=None) -> list:
    """The prompt text, as lines, so a caller can print or log it."""
    lines = ["", "How much disk should AgentalSec use for its database?", ""]
    for i, p in enumerate(PRESETS, start=1):
        lines.append(f"  {i}. {p['label']}")
        lines.append(f"     {human_bytes(p['trigger'])} budget, "
                     f"prunes back to {human_bytes(p['floor'])}, "
                     f"{p['roughly']}")
    lines.append("  4. Leave it alone, I will prune by hand")
    lines.append("")
    # The durations look wrong at a glance, 2 GB lasting longer than 5 GB, and
    # they are not. Each one assumes ITS OWN usage: a machine on a few hours a
    # week fills a gigabyte far more slowly than one that never sleeps. Said
    # out loud so nobody reads it as a typo, which is what happens to a number
    # that looks backwards and is not explained.
    lines.append("The rough durations assume the usage described on each line,")
    lines.append("so a bigger budget on a busier machine can still fill faster.")
    lines.append("")
    lines.extend(TRADE_NOTE.split("\n"))
    lines.append("")
    if db_path:
        try:
            lines.append(f"Right now the database is "
                         f"{human_bytes(database_bytes(db_path)['total'])}.")
        except Exception:
            pass
    return lines


# THE DECLARED WINDOWS, AND WHY THEY ARE NOW READ. EM-13, 2026-09-23.
#
# config.json has published these since the port:
#
#     "retention": {"packets_days": 7, "events_days": 30,
#                   "findings_days": 90, "baselines_days": 365}
#
# and NOT ONE OF THE FOUR was read by any code in the tree: a grep for all four
# names over every .py file returned zero hits outside config.json itself. So an
# operator who set events_days to 7 was told a window existed and it did not,
# which is worse than a missing feature because it is a control they believe
# they have.
#
# THE ENGINE'S OWN DECISION IS UNCHANGED AND IS NOT REOPENED HERE. Section 23
# settled that size, not age, is the constraint, and that deletion happens by
# WHOLE CAPTURE SESSION so an interval is never recomputed from half a run.
# Neither of those is touched. What the windows do now is the thing they can
# honestly do without breaking either: they are READ, REPORTED, and applied by
# a SEPARATE, EXPLICIT prune of raw observation rows whose session is older
# than the window, which is a different question from "the disk is full".
#
#   * it is OFF unless a person switches it on (the same PREF_ENABLED the size
#     engine uses: one switch, one meaning)
#   * it only touches the three raw observation tables in PRUNABLE. Findings,
#     baselines and the integrity journal are never touched by days.
#   * it refuses to delete rows belonging to the CURRENT session, so a prune
#     can never take the run in progress out from under the sensors.
#   * it reports what it WOULD do on every status read, so a window that has
#     never been applied is visible rather than assumed.
#
# A KEY THAT IS ABSENT OR UNREADABLE IS NOT SILENTLY ZERO: an unset window
# means "no age limit", which is the behaviour that was in force before this
# existed, and the status says so per key.

# table -> (time column, config key). The three are the PRUNABLE set, which is
# exactly the set this module already treats as raw observation.
RETENTION_WINDOWS = [
    ("packets",           "captured_at", "packets_days"),
    ("events",            "occurred_at", "events_days"),
    ("port_scan_results", "scanned_at",  "port_scan_results_days"),
    ("lan_flow",          "last_seen",   "lan_flow_days"),
    ("lan_traffic_minute", "minute",     "lan_traffic_days"),
]

# WHAT THIS HOST'S config.json CARRIES, named here so a reader can see what the
# keys look like rather than having to open the config. IT IS NOT A DEFAULT SET
# AND IT IS NOT APPLIED. Nothing in this module invents a window: if the
# operator declared none, none is applied and the status says so. Section 23's
# rule is the reason and it applies verbatim -- "Default is unset, so an
# existing install upgrades into 'ask', never into 'start deleting'" -- and a
# window this module chose for somebody would be exactly the arrival-by-patch
# that rule forbids.
DECLARED_WINDOW_EXAMPLE = {
    "packets_days": 7,
    "events_days": 30,
    "findings_days": 90,
    "baselines_days": 365,
}


def declared_windows(config: dict = None) -> dict:
    """
    The operator's windows, read, with the ones that apply named separately.

    Returns {key: days or None, "applied": {table: days}, "declared_only":
    {key: days}, "note": sentence}.

    `findings_days` and `baselines_days` are DECLARED ONLY and this function
    says so rather than applying them. The reasoning is in this module's own
    header: findings are the record of what was raised and what a human said
    about it, and the summaries the raw rows were kept in order to produce are
    never pruned. A window on those would be a retention rule that deletes the
    audit trail, and that is a decision for the owner rather than a tidy-up
    this round can make.
    """
    cfg = {}
    supplied = (config or {}).get("retention") if config else None
    if isinstance(supplied, dict):
        cfg = {k: v for k, v in supplied.items()}

    applied, declared_only, unreadable = {}, {}, []
    for table, _col, key in RETENTION_WINDOWS:
        if key not in cfg:
            # NOT DECLARED, so no window applies to this table. Reported as a
            # reading rather than as a complaint: an operator who never
            # mentioned port scans has not made a mistake.
            continue
        raw = cfg.get(key)
        try:
            days = int(raw)
        except (TypeError, ValueError):
            unreadable.append(f"{key} is {raw!r}, which is not a number "
                              f"of days, so {table} rows have no age limit")
            continue
        if days <= 0:
            unreadable.append(f"{key} is {days}, which is not a positive "
                              f"number of days")
            continue
        applied[table] = days

    # THE TWO DECLARED-ONLY WINDOWS
    #
    # Said out loud with the REASON, because a reader who set findings_days and
    # sees no note would conclude it was applied.
    for key, table in (("findings_days", "findings"),
                       ("baselines_days", "behavioral_baseline")):
        raw = cfg.get(key)
        if raw is None:
            continue
        try:
            declared_only[key] = int(raw)
        except (TypeError, ValueError):
            unreadable.append(f"{key} is {raw!r}, which is not a number of "
                              f"days")

    note = ("The windows on raw observation rows are applied by "
            "prune_by_windows(), which is OFF unless automatic pruning is "
            "on, and NOTHING IS DEFAULTED: a window the config does not "
            "declare is not applied. findings_days and baselines_days are "
            "DECLARED and NOT applied: findings are the audit trail of what "
            "was raised and what a human said about it, and baselines are the "
            "summaries the raw rows exist to produce. Neither is deleted by "
            "age.")
    return {"days": cfg, "applied": applied, "declared_only": declared_only,
            "unreadable": unreadable, "note": note}


def window_status(db_path, config: dict = None,
                  current_session_id: str = None) -> dict:
    """
    Read-only. What each declared window WOULD remove, per table.

    Counted, never deleted. This is what makes a window that is set and doing
    nothing visible: a row count of zero is a reading, and the current
    session's rows are excluded from the count for the same reason they are
    excluded from the delete.
    """
    win = declared_windows(config)
    out = {"applied": dict(win["applied"]),
           "declared_only": dict(win["declared_only"]),
           "unreadable": list(win["unreadable"]),
           "would_remove": {}, "note": win["note"]}
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.OperationalError as e:
        out["note"] = f"the database could not be read: {e}"
        return out
    try:
        for table, col, _key in RETENTION_WINDOWS:
            days = out["applied"].get(table)
            if not days:
                continue
            sql = (f"SELECT COUNT(*) FROM {table} "
                   f"WHERE {col} < datetime('now', ?)")
            params = [f"-{int(days)} days"]
            if current_session_id:
                sql += " AND (session_id IS NULL OR session_id != ?)"
                params.append(current_session_id)
            try:
                row = conn.execute(sql, params).fetchone()
                out["would_remove"][table] = int(row[0])
            except sqlite3.OperationalError as e:
                out["would_remove"][table] = f"unreadable: {e}"
    finally:
        conn.close()
    return out


def prune_by_windows(db_path, config: dict = None,
                     current_session_id: str = None, dry_run: bool = True,
                     log=None) -> dict:
    """
    Delete raw observation rows older than their declared window.

    Returns {ok, reason, removed, dry_run, windows}.

    NOT THE SAME JOB AS run(). That one deletes WHOLE SESSIONS when the FILE
    is too big, and its own header explains why it never compares a timestamp
    against a wall clock. This one does exactly that comparison, deliberately,
    for the three raw observation tables only, and it is a separate function so
    the two rules cannot be confused for one another.

    THE SESSION EXCLUSION IS THE SAFETY PROPERTY. A row belonging to the
    session that is running right now is never deleted, however old its own
    timestamp looks: a sensor that timestamps a record with the moment it read
    the log (which this app does for a line with no parseable time, see
    tools/event_monitor_linux's time_basis) can write a row whose occurred_at
    is older than the window the moment it lands.

    OFF UNLESS THE SAME SWITCH THE SIZE ENGINE USES IS ON. One switch, one
    meaning: "may this app delete its own raw rows".
    """
    log = log or logger
    win = declared_windows(config)
    report = {"ok": True, "reason": None, "removed": {}, "dry_run": dry_run,
              "windows": win["applied"], "declared_only": win["declared_only"]}
    if not win["applied"]:
        report["ok"] = False
        report["reason"] = ("no usable window was declared, so nothing would "
                            "be removed by age")
        return report

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        if not enabled(conn):
            report["ok"] = False
            report["reason"] = ("automatic pruning is off, so no window is "
                                "applied. The switch is retention_enabled, "
                                "the same one the size engine uses.")
            return report

        for table, col, _key in RETENTION_WINDOWS:
            days = win["applied"].get(table)
            if not days:
                continue
            sql = f"DELETE FROM {table} WHERE {col} < datetime('now', ?)"
            params = [f"-{int(days)} days"]
            if current_session_id:
                sql += " AND (session_id IS NULL OR session_id != ?)"
                params.append(current_session_id)
            if dry_run:
                count_sql = sql.replace("DELETE FROM", "SELECT COUNT(*) FROM")
                row = conn.execute(count_sql, params).fetchone()
                report["removed"][table] = int(row[0])
                continue
            cur = conn.execute(sql, params)
            report["removed"][table] = cur.rowcount
        if not dry_run:
            conn.commit()
            log.info(f"Retention: removed by age window: "
                     f"{report['removed']}")
    except Exception as e:                                    # noqa: BLE001
        report["ok"] = False
        report["reason"] = f"the window prune failed: {e}"
        log.error(report["reason"])
    finally:
        conn.close()
    return report


def apply_choice(db_path, key_or_index, turn_on=True) -> dict:
    """
    Store a preset. Also used by scripts/setup_retention.py.

    Refuses rather than corrects if the numbers do not validate, same as
    limits() does, because a tool that quietly picks its own limits is one
    that deletes an amount nobody agreed to.
    """
    preset = None
    try:
        idx = int(key_or_index)
        if 1 <= idx <= len(PRESETS):
            preset = PRESETS[idx - 1]
    except (TypeError, ValueError):
        for p in PRESETS:
            if p["key"] == str(key_or_index).strip().lower():
                preset = p
                break

    if preset is None:
        return {"ok": False, "reason": f"No such choice: {key_or_index!r}"}

    conn = sqlite3.connect(db_path)
    try:
        _write_pref(conn, PREF_TRIGGER, preset["trigger"])
        _write_pref(conn, PREF_FLOOR,   preset["floor"])
        _write_pref(conn, PREF_ENABLED, "1" if turn_on else "0")
        lim = limits(conn)
        _journal(conn, "retention setup")
    finally:
        conn.close()

    return {"ok": lim["ok"], "preset": preset["key"],
            "trigger": preset["trigger"], "floor": preset["floor"],
            "auto_prune": turn_on, "reason": lim["reason"]}


def decline(db_path) -> dict:
    """Record that the question was asked and answered with no."""
    conn = sqlite3.connect(db_path)
    try:
        _write_pref(conn, PREF_ENABLED, "0")
        _journal(conn, "retention declined")
    finally:
        conn.close()
    return {"ok": True, "auto_prune": False}


def first_run_prompt(db_path, stream=None, input_fn=None) -> dict:
    """
    Ask once, on a real terminal, and WAIT FOR THE ANSWER.

    THE HISTORY, BECAUSE THIS WENT WRONG TWICE IN ONE DAY.

    v1 had a 90 second timeout, on the reasoning that a scheduled start with a
    console but nobody watching would otherwise hang forever. The owner's
    answer: a question that expires is worse than no question. It gives up on
    you, and it teaches you that ignoring it is fine.

    v2 removed the prompt from boot altogether. That was an overcorrection and
    it was mine, from misreading "remove it to run the app" as "remove the
    question" rather than "remove the timeout". Booting with no question at all
    means a fresh install quietly never gets set up, and the whole point of
    23.5 is that first run should ASK.

    v3, this one: ask, and wait. No timer. If somebody is at a terminal they
    get the question and it sits there until they answer it. That is what a
    question is for.

    THE HEADLESS CASE IS STILL HANDLED, and it is handled by the tty check
    rather than by a timer. No terminal means no question, boot carries on, and
    boot_report names scripts/setup_retention.py instead. A service wrapper
    cannot hang on this because it never reaches the input call.

    Enter with nothing typed means "ask me again next time". That is the honest
    default for a question about deleting things: it is not an answer, so it is
    not recorded as one.
    """
    out = stream or sys.stdout
    ask = input_fn or input

    conn = sqlite3.connect(db_path)
    try:
        if configured(conn):
            return {"asked": False, "reason": "already answered"}
    finally:
        conn.close()

    interactive = bool(input_fn) or (
        hasattr(sys.stdin, "isatty") and sys.stdin.isatty())
    if not interactive:
        return {"asked": False, "reason": "not a terminal"}

    for line in choice_lines(db_path):
        print(line, file=out)

    try:
        # Plain input(). No thread, no timer, no default. It waits.
        answer = (ask("Pick 1 to 4, or press Enter to decide later: ")
                  or "").strip()
    except (EOFError, KeyboardInterrupt):
        print("", file=out)
        return {"asked": True, "answered": False, "reason": "interrupted"}

    if not answer:
        print("Left unset, nothing will be pruned. This will be asked again "
              "next start.", file=out)
        return {"asked": True, "answered": False, "reason": "deferred"}

    if answer == "4":
        decline(db_path)
        print("Automatic pruning stays off. Run scripts/prune_db.py when you "
              "want to reclaim disk.", file=out)
        return {"asked": True, "answered": True, "auto_prune": False}

    result = apply_choice(db_path, answer, turn_on=True)
    if not result["ok"]:
        print(f"Not saved: {result.get('reason')}", file=out)
        return {"asked": True, "answered": False,
                "reason": result.get("reason")}

    print(f"Set to {human_bytes(result['trigger'])}, pruning back to "
          f"{human_bytes(result['floor'])}. This happens at a clean shutdown, "
          f"never mid-session, and only ever by whole capture run.", file=out)
    return {"asked": True, "answered": True, "auto_prune": True, **result}


# THE TWO HOOKS main.py USES

def boot_report(db_path, log=None, current_session_id=None) -> dict:
    """
    Say the size out loud at startup. Deletes nothing, asks nothing, ever.

    Boot is the wrong moment to prune: sensors are about to start writing, and
    a VACUUM on a multi-gigabyte file would hold the boot for minutes. Boot
    reports, shutdown acts.

    It is also the wrong moment to ask anything. This writes lines to the log
    and returns. Nothing here can block the app from starting.
    """
    log = log or logger
    try:
        st = status(db_path, current_session_id)
    except Exception as e:
        log.error(f"Could not read the database size: {e}")
        return {"ok": False}

    log.info(f"Database: {st['size_human']}. {st['note']}")

    if not st["limits_ok"]:
        log.warning(f"Retention is misconfigured and will not run: "
                    f"{st['limits_reason']}")
    elif st["over_trigger"] and not st["auto_prune"]:
        log.warning("Over the retention budget with automatic pruning OFF. "
                    "Nothing is being deleted and the file will keep growing. "
                    "Run: python scripts/prune_db.py")
    elif not st["configured"]:
        # The only nudge there is, now that boot does not ask. One line, and it
        # names the command rather than describing it.
        log.info("Retention is not set up, so nothing will be pruned "
                 "automatically. To choose a limit: "
                 "python scripts/setup_retention.py")
    return st


def run_if_due(db_path, current_session_id=None, log=None) -> dict:
    """
    The shutdown hook. Prunes only if a person switched it on AND the file is
    over the trigger.

    WHY SHUTDOWN. The sensors have stopped and the final rollup has run, so
    nothing is writing and the measure-first step is reading a finished
    record. A VACUUM also wants the database quiet, and this is the only
    moment it reliably is.

    THE COST, SAID OUT LOUD BEFORE IT HAPPENS. On a multi-gigabyte file this
    can take a few minutes, and it starts right after somebody pressed
    Ctrl+C, which is the least patient moment there is. So it announces
    itself first. A second Ctrl+C during the prune is survivable:
    _delete_session works one whole session at a time and resume_interrupted
    finishes a half-done one on the next start, and SQLite's VACUUM either
    completes or leaves the original file alone.
    """
    log = log or logger
    conn = sqlite3.connect(db_path)
    try:
        if not enabled(conn):
            return {"ran": False, "reason": "automatic pruning is off"}
    finally:
        conn.close()

    try:
        st = status(db_path, current_session_id)
    except Exception as e:
        log.error(f"Retention could not read the database: {e}")
        return {"ran": False, "reason": str(e)}

    if not st["limits_ok"]:
        log.warning(f"Retention not run: {st['limits_reason']}")
        return {"ran": False, "reason": st["limits_reason"]}

    if not st["over_trigger"]:
        log.info(f"Retention: {st['size_human']} is under the "
                 f"{st['trigger_human']} trigger, nothing to prune.")
        return {"ran": False, "reason": "under the trigger"}

    log.warning(
        f"Retention: {st['size_human']} is over the {st['trigger_human']} "
        f"trigger. Pruning the oldest whole capture runs now, then vacuuming. "
        f"On a database this size that can take a few minutes. Please let it "
        f"finish; if it is interrupted it picks up where it left off next "
        f"start.")

    try:
        report = run(db_path, current_session_id=current_session_id,
                     dry_run=False, progress=log.info)
    except Exception as e:
        # A retention failure must never stop a clean shutdown. The rollup has
        # already been written by the time this runs.
        log.error(f"Retention failed, shutting down anyway: {e}")
        return {"ran": False, "reason": str(e)}

    if report.get("reason"):
        log.info(f"Retention: {report['reason']}")
    log.info(f"Retention: removed {len(report.get('deleted_sessions', []))} "
             f"capture run(s), database now "
             f"{human_bytes(report.get('size_after'))}.")
    report["ran"] = True
    return report
