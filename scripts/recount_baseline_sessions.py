#!/usr/bin/env python3
# scripts/recount_baseline_sessions.py
# AgentalSec V2, Rebuild session counts from evidence after the 2026-08-20
# session-filter bug.
#
# WHAT WENT WRONG
#
# memory_engine.query_behavioral_session accepted a session_id, documented it,
# had every caller pass it, and never applied it to the query. Every call
# returned the 500 most recent observations from EVERY session.
#
# rollup_engine then credited each returned group to the CURRENT session via
# record_baseline_session. So an entity observed once weeks ago earned a fresh
# session credit on every rollup, with no new observation behind it. Confidence
# is derived from that count, and high confidence drives suppression, so
# baselines were promoted and entities silenced by the passage of time.
#
# THE TABLE YOU WOULD NORMALLY TRUST IS ALSO WRONG. baseline_session_seen is
# where those false credits were written, so recomputing from it just launders
# the bug. The only clean source is behavioral_session, because observations
# carry the session_id they were actually written in and were never rewritten.
#
# WHAT THIS DOES
#
# For every (entity_type, entity_value, behavior_key), counts the DISTINCT
# session_ids in behavioral_session, rebuilds baseline_session_seen from that,
# and recomputes sample_count and confidence on behavioral_baseline.
#
# Reports first and changes nothing unless --apply is passed. Writes a backup
# copy before applying.
#
# IT DOES NOT UN-SUPPRESS ANYTHING. Lowering a confidence value is a statement
# about evidence; deciding what to do about a baseline that was suppressed on
# the strength of a false count is a judgement, and belongs to whoever reads
# the report. revert_suppression is ungated for exactly this reason.
#
# What it does do is NAME them. The report lists every suppressed baseline
# whose real evidence sits below 'high', every run, so the judgement has
# something to be exercised on instead of a Review tab and a good memory.

import argparse
import json
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_THRESHOLDS = {"low": 2, "medium": 4, "high": 6}


def _thresholds(conn) -> dict:
    row = conn.execute(
        "SELECT value FROM user_preferences WHERE key='confidence_session_thresholds'"
    ).fetchone()
    if not row or not row[0]:
        return dict(DEFAULT_THRESHOLDS)
    try:
        parsed = json.loads(row[0])
        return parsed if isinstance(parsed, dict) else dict(DEFAULT_THRESHOLDS)
    except (ValueError, TypeError):
        return dict(DEFAULT_THRESHOLDS)


def _confidence(count: int, thresholds: dict) -> str:
    if count >= thresholds.get("high", 6):
        return "high"
    if count >= thresholds.get("medium", 4):
        return "medium"
    return "low"


# WITHDRAWN OBSERVATIONS DO NOT COUNT
#
# query_behavioral_session excludes superseded rows by default, so the rollup
# engine has never credited a withdrawn observation toward confidence. This
# script has to agree with it. Counting them here would let a session whose
# only observation was later retracted as wrong keep earning a session credit,
# which is the same shape of error this whole repair exists to undo.
#
# The header above says the observations were "never rewritten". That is true
# of behavior_value and of session_id; it is not true of superseded_by, which
# is exactly how a retraction is recorded.

def _supersede_filter(conn) -> str:
    """WHERE fragment excluding withdrawn observations, empty if pre-migration."""
    try:
        conn.execute("SELECT superseded_by FROM behavioral_session LIMIT 1")
    except sqlite3.OperationalError:
        return ""          # pre-supersede database; nothing can be withdrawn
    return "WHERE superseded_by IS NULL"


def _withdrawn_count(conn) -> int:
    """How many observations this run is ignoring. Never let that be silent."""
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM behavioral_session WHERE superseded_by IS NOT NULL"
        ).fetchone()[0]
    except sqlite3.OperationalError:
        return 0


def analyse(conn) -> list[dict]:
    """True session counts from behavioral_session, against what is recorded."""
    thresholds = _thresholds(conn)
    where = _supersede_filter(conn)

    truth = {}
    for r in conn.execute(f"""
        SELECT entity_type, entity_value, behavior_key,
               COUNT(DISTINCT session_id) AS real_sessions
        FROM behavioral_session
        {where}
        GROUP BY entity_type, entity_value, behavior_key
    """):
        truth[(r["entity_type"], r["entity_value"], r["behavior_key"])] = r["real_sessions"]

    rows = []
    for b in conn.execute("""
        SELECT entity_type, entity_value, behavior_key, sample_count, confidence,
               alert_suppressed
        FROM behavioral_baseline
    """):
        key = (b["entity_type"], b["entity_value"], b["behavior_key"])
        # No observations at all means every credit this baseline holds was
        # manufactured. Reported rather than deleted; a baseline can also be
        # written directly by the model, which is legitimate.
        real = truth.get(key, 0)
        new_conf = _confidence(real, thresholds)
        rows.append({
            "entity_type":   b["entity_type"],
            "entity_value":  b["entity_value"],
            "behavior_key":  b["behavior_key"],
            "recorded_count": b["sample_count"] or 0,
            "real_count":     real,
            "recorded_confidence": b["confidence"],
            "new_confidence":      new_conf,
            "inflated": (b["sample_count"] or 0) > real,
            "demoted":  b["confidence"] != new_conf,
            "no_observations": real == 0,
            "suppressed": bool(b["alert_suppressed"]),
        })
    return rows


# WHAT IS STILL SILENT, AND ON WHAT EVIDENCE
#
# Reported whether or not this run would change anything, and that is the
# whole point of it. Once the counts are repaired nothing is "demoted" any
# more, so a list keyed on what this run altered goes empty, and the entities
# that were silenced on the strength of a count that no longer exists become
# invisible again the moment the repair succeeds.
#
# The question is not "what did this run change". It is "what is still quiet,
# and does the evidence justify it".

def _report_suppressed(silenced: list[dict]) -> None:
    if not silenced:
        return

    weak = [r for r in silenced if r["new_confidence"] != "high"]
    if not weak:
        print(f"\nAll {len(silenced)} suppressed baseline(s) still hold 'high' "
              f"on real session counts. Nothing to reconsider.")
        return

    print("\nSuppressed on evidence below 'high', weakest first:")
    print(f"{'entity':<24} {'behavior':<26} {'sessions':>8}  confidence")
    print("," * 82)
    for r in sorted(weak, key=lambda x: x["real_count"]):
        entity = f"{r['entity_type']}:{r['entity_value']}"[:23]
        print(f"{entity:<24} {r['behavior_key'][:25]:<26} "
              f"{r['real_count']:>8}  {r['new_confidence']}")

    # Not every one of these is wrong. alert_suppressed can only be set by an
    # affirmative signal, so some were silenced deliberately by a person or by
    # a gated tool call and the low count is beside the point. The rest were
    # carried to 'high' by the session-filter bug and silenced on the way.
    # Nothing in this script can tell those two apart, and it should not try.
    print(f"\n{len(weak)} suppressed baseline(s) sit below 'high' on real "
          f"evidence. Some of those were silenced deliberately and are fine. "
          f"The rest were silenced on a count that has since been withdrawn. "
          f"Only someone who knows this network can separate them. "
          f"revert_suppression is ungated, so undoing one costs nothing.")


def report(rows: list[dict]) -> None:
    inflated = [r for r in rows if r["inflated"]]
    demoted  = [r for r in rows if r["demoted"]]
    orphaned = [r for r in rows if r["no_observations"]]
    silenced = [r for r in rows if r["suppressed"]]

    print(f"Baselines examined:            {len(rows)}")
    print(f"Session count inflated:        {len(inflated)}")
    print(f"Confidence would change:       {len(demoted)}")
    print(f"No observations behind them:   {len(orphaned)}")
    print(f"Currently suppressed:          {len(silenced)}")

    if demoted:
        print("\nConfidence changes, worst first:")
        print(f"{'entity':<24} {'behavior':<26} {'was':>4} {'real':>5}  confidence")
        print("," * 82)
        for r in sorted(demoted, key=lambda x: x["recorded_count"] - x["real_count"],
                        reverse=True):
            entity = f"{r['entity_type']}:{r['entity_value']}"[:23]
            print(f"{entity:<24} {r['behavior_key'][:25]:<26} "
                  f"{r['recorded_count']:>4} {r['real_count']:>5}  "
                  f"{r['recorded_confidence']} -> {r['new_confidence']}"
                  + ("   SUPPRESSED" if r["suppressed"] else ""))

        dropping = [r for r in demoted if r["recorded_confidence"] == "high"]
        if dropping:
            print(f"\n{len(dropping)} baseline(s) leave 'high'. High confidence is "
                  f"what drives suppression, so these are the ones worth checking "
                  f"in the Review tab. This script does not un-suppress anything.")
    else:
        print("\nNothing would change. Either the bug never reached this "
              "database, or evidence has since caught up with the counts.")

    _report_suppressed(silenced)


def apply_fix(conn, rows: list[dict]) -> dict:
    """Rebuild baseline_session_seen from observations, then recount."""
    conn.execute("BEGIN")

    # baseline_session_seen holds the false credits, so it is rebuilt rather
    # than adjusted. behavioral_session is the evidence and is never touched.
    # The same supersede filter as analyse(), or the rebuilt table would
    # disagree with the counts that were just reported.
    where = _supersede_filter(conn)
    conn.execute("DELETE FROM baseline_session_seen")
    conn.execute(f"""
        INSERT OR IGNORE INTO baseline_session_seen
            (entity_type, entity_value, behavior_key, session_id, first_seen_at)
        SELECT entity_type, entity_value, behavior_key, session_id,
               MIN(observed_at)
        FROM behavioral_session
        {where}
        GROUP BY entity_type, entity_value, behavior_key, session_id
    """)

    changed = 0
    for r in rows:
        if not (r["inflated"] or r["demoted"]):
            continue
        conn.execute("""
            UPDATE behavioral_baseline
               SET sample_count = ?, confidence = ?
             WHERE entity_type = ? AND entity_value = ? AND behavior_key = ?
        """, (r["real_count"], r["new_confidence"], r["entity_type"],
              r["entity_value"], r["behavior_key"]))
        changed += 1

    conn.commit()
    seen = conn.execute("SELECT COUNT(*) FROM baseline_session_seen").fetchone()[0]
    return {"baselines_corrected": changed, "session_seen_rows": seen}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Rebuild baseline session counts from observations.")
    parser.add_argument("--apply", action="store_true",
                        help="Write the corrections. Without this, reports only.")
    parser.add_argument("--db", default=None, help="Path to agental_sec.db")
    args = parser.parse_args()

    db_path = Path(args.db) if args.db else PROJECT_ROOT / "agental_sec.db"
    if not db_path.exists():
        print(f"No database at {db_path}")
        return 1

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    # The agent holds this database open while it runs. Wait for a writer
    # rather than failing instantly on a lock.
    conn.execute("PRAGMA busy_timeout=15000")
    try:
        withdrawn = _withdrawn_count(conn)
        if withdrawn:
            print(f"Withdrawn observations excluded: {withdrawn}\n")

        rows = analyse(conn)
        report(rows)

        if not args.apply:
            print("\nDry run. Nothing was changed. Re-run with --apply to write.")
            return 0

        stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        backup = db_path.with_suffix(f".db.pre_recount_{stamp}")

        # WAL SAFE BACKUP
        #
        # The schema sets journal_mode=WAL, so copying the .db file on its own
        # is not a backup. Everything committed since the last checkpoint is
        # in the sidecar wal file beside it, and a copy of one without the other
        # restores a database missing its most recent transactions. That is
        # the worst kind of backup: it exists, it opens, and it is quietly
        # behind.
        #
        # sqlite3's own backup API reads through the WAL, produces a
        # consistent file, and is safe while the agent is still writing.
        needed_mb = db_path.stat().st_size // (1024 * 1024)
        free_mb   = shutil.disk_usage(db_path.parent).free // (1024 * 1024)
        if free_mb < needed_mb + 64:
            print(f"\nNot enough free disk for a backup. About {needed_mb} MB "
                  f"needed, {free_mb} MB free. Nothing was changed.")
            return 1

        print(f"\nBacking up to {backup.name} ({needed_mb} MB)...")
        dest = sqlite3.connect(backup)
        try:
            conn.backup(dest)
        finally:
            dest.close()
        print("Backup complete.")

        result = apply_fix(conn, rows)
        print(f"Corrected {result['baselines_corrected']} baseline(s). "
              f"baseline_session_seen rebuilt to {result['session_seen_rows']} rows.")
        print("Suppression state was NOT changed. Check the Review tab for "
              "anything that was silenced on a count that has just dropped.")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
