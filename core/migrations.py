# core/migrations.py
# AgentalSec V2, Idempotent schema migrations.
#
# Called by main.py before any module loads. Safe to run on every boot:
# each step checks current state first, and the applied version is recorded
# in user_preferences under 'schema_version'.
#
# Existing databases are migrated in place. A .bak copy is written once,
# before the first structural change, next to agental_sec.db.

import logging
import os
import shutil
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)

# v18, 2026-08-29: removes suppression_requires_user, a preference that was
# seeded twice and read by nothing. Bumped so the deletion actually reaches
# databases already sitting at v17.
# v19, 2026-08-29: strips stale "Sessions observed: N -> confidence X"
# sentences out of model_notes, and pulls stored confidence back down to what
# the measured session count actually supports.
# v20, 2026-08-29: beacon_detail on behavioral_baseline, so measured contact
# regularity survives the pruning of the packets it was measured from.
# v21, 2026-08-31: source_record_id on events plus a unique index, so a record
# the Windows log hands us twice is only stored once.
# v22, 2026-09-01: expected_always_on on known_devices, splitting availability
# away from membership so the absence finding stops firing on devices the user
# only ever said belonged here.
# v25, 2026-09-02: enrichment and enrichment_queue, tier 1 of the research
# worker. External intel is kept in its own tables rather than mixed into the
# observation tables, because a row from a registry is second-hand and the
# model has to be able to see that it is.
# v26, 2026-09-02: basis and basis_ref on behavioral_session. Says whether a
# baseline row is a measurement, a lookup, or the model's own reasoning. They
# used to be indistinguishable, which is how a wrong conclusion becomes a
# permanent fact.
# v32, 2026-09-14: the question queue, the popup log, and the performance
# axis. Also adds 'operator_stated' to the basis vocabulary, which is a
# Schema.SQL change only, see _migrate_operator_stated for why there is
# nothing to do on an existing database and why that is worth a function
# rather than silence.
# v31, 2026-09-14: the prediction table. The model writes down what it expects
# to happen, with a deadline, and Python checks it afterwards and records hit,
# miss, or could-not-check. Three outcomes, never summed, because a "no
# traffic" claim is trivially true on a window where the capture was off and
# scoring that as a hit builds a hit rate out of our own blind spots.
# v34, 2026-09-15: protocol on port_scan_results and protocols on
# port_scan_run. The scanner has always been TCP only and never said so, so
# every port row was an unqualified number that a reader had to guess at.
# v35, 2026-09-17, T2: the incident ledger and the watcher's run record.
# Two tables, no ALTERs, nothing backfilled. The incident table is the layer
# between "a finding happened" and "somebody should look", and it carries the
# COVERAGE that existed when each assessment was made, because an assessment
# of a network and an assessment of what this app could see are different
# claims and only one of them is ever true.
# v36, 2026-09-18, T3: the action queue. One table, no ALTERs, nothing
# backfilled. A gated action the agent wanted to take becomes a REQUEST with a
# row instead of a tool call that runs there and then, which is what makes an
# approval survive the process that asked for it. Unanswered never becomes
# executed: the only clock in the table retires a request as NOT APPROVED AND
# NOT DENIED, and a denial sticks until the evidence changes.
# v37, 2026-09-18, T4: the duty loop. Two tables, no ALTERs, nothing
# backfilled. duty_run is one row per tick (including the ones that did
# nothing, so "was anything awake at 3am" has an answer) and it carries every
# token the loop spent, because the daily ceiling is computed by SUMMING those
# rows rather than by keeping a counter that can drift. duty_report is what the
# Agents tab renders: the hypothesis, evidence, verdict and "what I saw" the
# model left behind, plus the coverage that existed when it wrote them.
#
# v38 to v41, 2026-09-21: THE WINDOWS-SIDE SCHEMA, PORTED. The owner's
# instruction for this pass was to take everything in the Windows tree's
# Schema.SQL that is possible to port, and this is that. Four things arrive:
#
#   v38  runbook.cvss_* and ransomware_use, so a row can carry a rating
#        fetched from a source that publishes one, kept apart from the feed's
#        own severity word. Plus tls_hello, where tools/tls_hello.py puts what
#        the ClientHello said.
#   v39  the repair of the KEV rows already in this database. It is a
#        migration and not a script because until the next sync succeeds those
#        rows are what the Runbook tab is showing.
#   v40  threat_feed, the local mirror of the known-bad lists that
#        tools/feed_matcher.py checks every outbound destination against.
#   v41  payload_capture, where a flushed ring buffer lands. THE ONLY TABLE IN
#        THIS DATABASE THAT CAN CONTAIN THE USER'S OWN PLAINTEXT, and the only
#        one whose retention is measured in days rather than never.
#
# The numbering is the Windows tree's on purpose rather than this tree's next
# free number. Same file name, same version, same shape, so the two trees can
# be compared version for version instead of by guessing which of v38 and v41
# came first on which side. Nothing was renumbered to get there because this
# tree had no v38 or later to collide with.
#
# THE LINUX-ONLY TABLES STAY. incident, watcher_run, action_request, duty_run
# and duty_report are this tree's T2, T3 and T4 and are wired into main.py, the
# routes, the UI and the verification scripts. Porting the schema was not a
# reason to delete a working design; it was a reason to stop the two trees
# from being unable to share one. Six Windows tables are NOT ported and are
# named with their reason in the header of _migrate_agent_runs below.
# v44, 2026-09-22, T6: the kernel camera. One table, no ALTERs, nothing
# backfilled. ebpf_camera_cursor is the reader's bookmark into a SIDECAR file
# written by a root-confined process, and it lives in this database rather than
# in that file because the one-way street between the two is the design: a
# reader running as the operator never writes to anything a root process owns.
#
# v45, 2026-09-22, L4: the kernel AUDIT log's cursor. Same shape and same
# argument as v44, for a different feed: auditd records syscalls, file watches
# and rule changes at kernel level, and this is the bookmark that makes a pass
# read only what arrived since the last one. THE TABLE IS CREATED ON HOSTS
# WHERE AUDITD IS NOT INSTALLED TOO, so that the day the operator runs the one
# command this app prints, the reader works without a migration first.
# v46, 2026-09-23: MISP and OTX join the threat feeds, and the matcher's
# bookmarks move OUT of user_preferences. feed_cursor is the fourth table of
# its kind and the argument is identical to v42/v44/v45: a cursor is a
# bookmark, user_preferences is THE POLICY, and core/integrity journals a
# warning whenever the policy moves. The cursor keys were measured producing a
# false config_observed entry before this step.
# v48, 2026-09-23, L4 audit: the audit log cursor gains last_inode. A byte
# offset cannot tell a GROWN file from a DIFFERENT one already past that byte,
# and auditd rotates by renaming audit.log to audit.log.1 -- measured: a
# rotated log that had outgrown the stored offset skipped 940 bytes of the new
# file with no note and never read the rotated one.
#
# v54, 2026-09-26, register section 15, dns: the DNS importer's and the DNS
# inspector's cursors leave user_preferences for a table of their own
# (dns_cursor), the SIXTH move of this shape. Measured: one _set_cursor call
# moved the policy digest core/integrity journals as THE POLICY and produced a
# config_observed row whose payload was {'dns_import_cursor_pihole': '1234'}.
# v55, 2026-09-27: background_change, the journal behind block, disable and
# undo on the Processes tab's background apps card.
# v56, 2026-09-28: tls_hello.transport ('tcp' or 'quic', since hellos are now
# read out of QUIC Initial packets too) and dns_answer, the names the
# captured DNS replies gave for each address.
# v57, 2026-10-01: lan_traffic_minute and lan_flow, what the live LAN monitor
# keeps from the router: per-device totals each minute, and one row per
# finished connection. Payloads are never stored.
# v58: autorun_baseline. v59, 2026-10-06: known_devices.merge_carried, what a
# merge moved to the target, so unmerge can give it back.
# v60, 2026-10-07: place_baseline and place_cursor, the countries and networks
# each program and device normally reaches (Threat Map place learning).
# v61: place_traffic, an hourly tally of where this machine's traffic went, so
# the Threat Map covers the last day without scanning the packets table.
# v62, 2026-10-09: sensor_gaps, the stretches a sensor or the app itself was
# not collecting, shaded on the Timeline.
SCHEMA_VERSION = 62


# HELPERS

def _table_exists(conn, name: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


def _columns(conn, table: str) -> set:
    if not _table_exists(conn, table):
        return set()
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _get_version(conn) -> int:
    if not _table_exists(conn, "user_preferences"):
        return 0
    row = conn.execute(
        "SELECT value FROM user_preferences WHERE key='schema_version'"
    ).fetchone()
    try:
        return int(row[0]) if row else 0
    except (TypeError, ValueError):
        return 0


def _set_version(conn, version: int):
    conn.execute(
        "INSERT INTO user_preferences(key, value) VALUES('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
        "updated_at=CURRENT_TIMESTAMP",
        (str(version),)
    )


def _backup_once(db_path: Path):
    """Write a one-time .bak beside the DB before the first structural change."""
    backup = db_path.with_suffix(".db.pre_v2_backup")
    if backup.exists():
        logger.info(f"Migration backup already present: {backup.name}")
        return
    try:
        # SQLite's own backup, not a file copy: a copy of a WAL database
        # misses every page still in the -wal file (CC-6). Owner-only.
        src = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        dst = sqlite3.connect(backup)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        os.chmod(backup, 0o600)
        logger.info(f"Migration backup written: {backup.name}")
    except Exception as e:
        # Non-fatal: a 226 MB copy can fail on a full disk. The migration
        # itself is transactional, so proceed but say so loudly.
        logger.warning(f"Could not write migration backup ({e}). Continuing.")


# MIGRATION 1, baseline_session_seen

def _migrate_baseline_sessions(conn):
    """
    Create the session-accounting table and backfill it from the
    observations already recorded in behavioral_session.
    """
    if _table_exists(conn, "baseline_session_seen"):
        return 0

    conn.execute("""
        CREATE TABLE baseline_session_seen (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type   TEXT NOT NULL,
            entity_value  TEXT NOT NULL,
            behavior_key  TEXT NOT NULL,
            session_id    TEXT NOT NULL,
            first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(entity_type, entity_value, behavior_key, session_id)
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_bss_entity
            ON baseline_session_seen(entity_type, entity_value, behavior_key)
    """)

    backfilled = 0
    if _table_exists(conn, "behavioral_session"):
        cur = conn.execute("""
            INSERT OR IGNORE INTO baseline_session_seen
                (entity_type, entity_value, behavior_key, session_id)
            SELECT DISTINCT entity_type, entity_value, behavior_key, session_id
            FROM behavioral_session
        """)
        backfilled = cur.rowcount or 0

    logger.info(f"Migration: baseline_session_seen created, {backfilled} rows backfilled.")
    return backfilled


# MIGRATION 2, behavioral_deviation: severity + 'unreviewed'

DEVIATION_TABLE_V2 = """
CREATE TABLE behavioral_deviation_v2 (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    detected_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    entity_type     TEXT NOT NULL,
    entity_value    TEXT NOT NULL,
    behavior_key    TEXT NOT NULL,

    expected_value  TEXT,
    observed_value  TEXT,
    deviation_score REAL,

    severity        TEXT DEFAULT 'low'
                    CHECK(severity IN ('critical','high','medium','low','info')),

    model_assessment TEXT,
    action_taken    TEXT CHECK(action_taken IN
                        ('alerted','logged','blocked','ignored','quarantined')),

    alerted_at      TIMESTAMP,
    user_responded  INTEGER DEFAULT 0,
    user_response   TEXT,
    silence_timeout_seconds INTEGER DEFAULT 150,

    resolved_as     TEXT CHECK(resolved_as IN
                        ('normal','threat','investigating','ignored',
                         'false_positive','unreviewed')),
    resolved_at     TIMESTAMP,

    -- IS NULL OR IN, not IN (..., NULL). The second form enforces nothing:
    -- `x IN (a, NULL)` is NULL rather than false for a value not in the list,
    -- and a CHECK passes on NULL. Corrected 2026-09-14 in Schema.SQL and
    -- here, so a table rebuilt by this migration gets the same real
    -- constraint a fresh database gets.
    user_feedback   TEXT CHECK(user_feedback IS NULL OR
                               user_feedback IN ('false_positive','correct',
                                                 'investigating'))
)
"""


def _migrate_deviation_table(conn):
    """
    Rebuild behavioral_deviation to add a severity column and to widen the
    resolved_as CHECK constraint to include 'unreviewed'.

    SQLite cannot ALTER a CHECK constraint, so this is a copy-and-swap.
    """
    if not _table_exists(conn, "behavioral_deviation"):
        return 0

    cols = _columns(conn, "behavioral_deviation")
    if "severity" in cols:
        return 0   # already migrated

    conn.execute("DROP TABLE IF EXISTS behavioral_deviation_v2")
    conn.execute(DEVIATION_TABLE_V2)

    # Derive severity for historical rows from deviation_score, matching
    # memory_engine._derive_severity so old and new rows rank consistently.
    conn.execute("""
        INSERT INTO behavioral_deviation_v2
            (id, session_id, detected_at, entity_type, entity_value,
             behavior_key, expected_value, observed_value, deviation_score,
             severity, model_assessment, action_taken, alerted_at,
             user_responded, user_response, silence_timeout_seconds,
             resolved_as, resolved_at, user_feedback)
        SELECT
            id, session_id, detected_at, entity_type, entity_value,
            behavior_key, expected_value, observed_value, deviation_score,
            CASE
                WHEN ABS(COALESCE(deviation_score,0)) >= 4.0 THEN 'critical'
                WHEN ABS(COALESCE(deviation_score,0)) >= 3.0 THEN 'high'
                WHEN ABS(COALESCE(deviation_score,0)) >= 2.0 THEN 'medium'
                ELSE 'low'
            END,
            model_assessment, action_taken, alerted_at,
            user_responded, user_response, silence_timeout_seconds,
            resolved_as, resolved_at, user_feedback
        FROM behavioral_deviation
    """)

    moved = conn.execute(
        "SELECT COUNT(*) FROM behavioral_deviation_v2"
    ).fetchone()[0]

    conn.execute("DROP TABLE behavioral_deviation")
    conn.execute("ALTER TABLE behavioral_deviation_v2 RENAME TO behavioral_deviation")

    conn.execute("CREATE INDEX IF NOT EXISTS idx_deviation_entity "
                 "ON behavioral_deviation(entity_type, entity_value)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_deviation_session "
                 "ON behavioral_deviation(session_id, detected_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_deviation_unresolved "
                 "ON behavioral_deviation(user_responded, alerted_at) "
                 "WHERE resolved_as IS NULL")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_deviation_review "
                 "ON behavioral_deviation(resolved_as, severity, detected_at)")

    logger.info(f"Migration: behavioral_deviation rebuilt ({moved} rows) "
                f"with severity + 'unreviewed' state.")
    return moved


# MIGRATION 3, recompute sample_count, clear unearned suppression

def _migrate_sample_counts(conn, high_threshold: int = 6):
    """
    Rewrite sample_count from distinct observed sessions, then clear
    alert_suppressed on any baseline that has not actually earned it.

    This is the corrective half of the silence-timer fix: rows suppressed by
    the old observation-counting bug start alerting again.
    """
    if not _table_exists(conn, "behavioral_baseline"):
        return (0, 0)

    conn.execute("""
        UPDATE behavioral_baseline
        SET sample_count = COALESCE((
                SELECT COUNT(*) FROM baseline_session_seen s
                WHERE s.entity_type  = behavioral_baseline.entity_type
                  AND s.entity_value = behavioral_baseline.entity_value
                  AND s.behavior_key = behavioral_baseline.behavior_key
            ), 0)
    """)
    recounted = conn.total_changes

    # Any row suppressed on fewer real sessions than the threshold was
    # suppressed by the bug, not by evidence.
    # NOTE: this note text must stay a single SQL string literal. Python's
    # implicit adjacent-string concatenation produces 'a' 'b' inside the SQL,
    # which SQLite rejects. If it ever needs splitting, join the pieces
    # with SQLite's own string-concatenation operator inside the SQL.
    note = (" [v2 migration: suppression cleared, was set by the "
            "observation-count bug, not by distinct-session evidence.]")

    cur = conn.execute("""
        UPDATE behavioral_baseline
        SET alert_suppressed = 0,
            confidence       = CASE WHEN sample_count >= ? THEN confidence ELSE 'low' END,
            model_notes      = COALESCE(model_notes,'') || ?,
            last_updated     = CURRENT_TIMESTAMP
        WHERE alert_suppressed = 1 AND sample_count < ?
    """, (high_threshold, note, high_threshold))
    unsuppressed = cur.rowcount or 0

    logger.info(f"Migration: sample_count recomputed from sessions; "
                f"{unsuppressed} baselines un-suppressed.")
    return (recounted, unsuppressed)


# MIGRATION 4, new default preferences

NEW_PREFERENCES = [
    ("silence_confidence_cap",    "medium"),
    ("silence_severity_floor",    "high"),
    ("log_process_launch_events", "0"),
    # v31. Seeded rather than left to the module default, so both knobs are
    # visible in the table an operator actually reads. A default that only
    # exists in Python is a setting nobody knows they have.
    ("prediction_daily_cap",      "12"),
    ("prediction_min_coverage",   "0.5"),
    # v32. The popup budget is an INTERRUPTION budget. Questions are
    # unlimited, one popup carries several, and there is deliberately no
    # urgency bypass: the model decides what is urgent, and a bypass becomes
    # the normal path the week after it is added.
    ("question_popup_daily_cap",   "3"),
    ("question_popup_min_gap_min", "120"),
    ("question_expiry_days",       "10"),
    ("perf_min_coverage_seconds",  "600"),
    ("perf_min_history_hours",     "12"),
]

# Preferences that were seeded once and turned out to control nothing. They
# are deleted rather than left in place, because an operator reading the table
# cannot tell a live control from a dead one, and a dead one reads as cover.
#
# suppression_requires_user, removed 2026-08-29: seeded here and in Schema.SQL
# and read by no code path. Suppression is gated by
# tool_registry.suppression_is_requested plus the permission card; the row
# never took part in that decision.
DEAD_PREFERENCES = [
    "suppression_requires_user",
]


def _migrate_preferences(conn):
    added = 0
    for key, value in NEW_PREFERENCES:
        cur = conn.execute(
            "INSERT OR IGNORE INTO user_preferences(key, value) VALUES(?,?)",
            (key, value)
        )
        added += cur.rowcount or 0

    for key in DEAD_PREFERENCES:
        conn.execute("DELETE FROM user_preferences WHERE key = ?", (key,))

    return added


# ENTRY POINT

def _migrate_runbook_qualifiers(conn) -> int:
    """
    Add entry_kind / applies_to / verify_hint to the runbook table.

    Without these a runbook row is just "port -> severity", which is how an
    open 445 on Windows 11 became a critical EternalBlue finding. The columns
    are additive, so plain ALTERs are enough, no table rebuild.

    The stale STATIC-* rows already in the database are not corrected here;
    tools/runbook.py upserts them with REPLACE on every boot, which is the
    single source of truth for those five entries.
    """
    if not _table_exists(conn, "runbook"):
        return 0

    existing = _columns(conn, "runbook")
    added = 0

    for col, ddl in (
        ("entry_kind",  "TEXT DEFAULT 'vulnerability'"),
        ("applies_to",  "TEXT"),
        ("verify_hint", "TEXT"),
    ):
        if col not in existing:
            conn.execute(f"ALTER TABLE runbook ADD COLUMN {col} {ddl}")
            added += 1

    # CISA KEV rows describe specific products and carry no port mapping, so
    # they were never the source of the port-match problem. Mark them so the
    # model can tell a feed entry from a hand-written prior.
    if added:
        conn.execute(
            "UPDATE runbook SET entry_kind = 'vulnerability' "
            "WHERE source = 'cisa_kev' AND entry_kind IS NULL"
        )

    return added


# THE WINDOWS-SIDE FEATURES, PORTED 2026-09-21, TODO 113.2 / 113.4 / 113.6
#
# These four came across with the schema port the owner asked for: take
# everything in Schema.SQL that is possible to port. They are v36, v38, v40
# and v41 in the Windows tree; this tree runs them as one step to v41 because
# it never had any of them and there is no install of this tree in the field
# that would need them separated.
#
# WHAT IS HERE AND WHY EACH ONE IS SEPARATE FROM THE OTHERS:
#
#   _migrate_kev_cvss         the runbook can hold a fetched CVSS score, kept
#                             apart from the feed's own severity word.
#   _migrate_kev_row_content  repairs the KEV rows already in the database,
#                             because the next sync needs CISA to be up.
#   _migrate_tls_hello        somewhere to put what the ClientHello said.
#   _migrate_threat_feed      somewhere to keep the known-bad lists.
#   _migrate_payload_capture  where a flushed ring buffer lands.
#
# Nothing is backfilled by any of them, and for three of the four nothing
# COULD be: the bytes were discarded at capture time, the feeds were never
# downloaded, the keys were never minted. An empty table on an existing
# database means the feature has not run since the upgrade, and every reader
# of every one of these says so rather than letting empty read as a fact.

def _migrate_kev_cvss(conn) -> int:
    """
    v36, 2026-09-17. The runbook can hold a real CVSS rating.

    The CISA KEV feed publishes no severity at all: no CVSS, no rating, no
    band. tools/runbook.py used to paper over that by writing 'high' on all
    ~1700 rows, fixed on 2026-09-16 so the column now says 'unknown' unless
    the feed flags ransomware use. That fix was right and it left the Runbook
    tab showing UNKNOWN on about 1400 rows, which reads as a broken sync.

    So these columns hold a score fetched from a source that publishes one,
    and, next to it, the state of the attempt:

        NULL          nobody has looked yet
        'ok'          a source answered with a score, it is in cvss_score
        'no_score'    a source has the record and publishes no base score
        'not_found'   the sources answered and have no record of this CVE
        'error'       we could not ask, or the answer never arrived, or the
                      answer arrived and could not be read

    Four separate outcomes with four separate names, because "nothing found"
    and "could not look" are different sentences and a column that merges them
    starts asserting something nobody established. cvss_checked_at is stamped
    on every attempt including the empty ones, so 'checked and came back empty'
    and 'never checked' stay distinguishable.

    THE FEED SEVERITY IS NOT TOUCHED. `severity` keeps meaning what it meant,
    which is what the feed itself states. A fetched score is a different claim
    from a different source and it gets its own field rather than overwriting
    the first one.

    ransomware_use comes along here too. knownRansomwareCampaignUse is the one
    severity-ish signal the feed does carry, it was being read into severity
    and then discarded, so a row could not show WHY it was rated.

    Additive ALTERs, O(1) in SQLite. Nothing is backfilled: no row gets a
    state it did not earn, and a row with no state is exactly what it looks
    like, a row nobody has looked up yet.
    """
    if not _table_exists(conn, "runbook"):
        return 0

    existing = _columns(conn, "runbook")
    added = 0

    for col, ddl in (
        ("cvss_score",      "REAL"),
        ("cvss_severity",   "TEXT"),
        ("cvss_vector",     "TEXT"),
        ("cvss_source",     "TEXT"),
        ("cvss_state",      "TEXT"),
        ("cvss_note",       "TEXT"),
        ("cvss_checked_at", "TEXT"),
        ("ransomware_use",  "TEXT"),
    ):
        if col not in existing:
            conn.execute(f"ALTER TABLE runbook ADD COLUMN {col} {ddl}")
            added += 1

    if added:
        logger.info(
            "v38: runbook can now hold a fetched CVSS score and the state of "
            "the lookup that fetched it. Every row starts with no state, which "
            "reads as 'nobody has looked', because nobody has."
        )
    return added


def _migrate_kev_row_content(conn) -> dict:
    """
    Repair the CISA KEV rows that are already in the database.

    _migrate_runbook_qualifiers added the three qualifier COLUMNS. It did not
    fill them for feed rows, because at the time the feed rows were not thought
    to be the problem: the note says "CISA KEV rows describe specific products
    and carry no port mapping, so they were never the source of the port-match
    problem". True as far as it goes, and it missed the other half. A row with
    applies_to NULL does not read as "scope unknown", it reads as an
    unqualified statement about a CVE, and on 2026-09-16 exactly that happened
    with a Cisco ISE entry on a network with no Cisco hardware in it.

    Two repairs, both on source = 'cisa_kev' only:

    SEVERITY. Every imported row was written 'high', hardcoded, never read
    from anywhere. So the word carried nothing. They go to 'unknown' here,
    which is what we actually know. The next sync re-rates the ones the feed
    gives a real signal for, the ransomware-campaign ones, back up to 'high'
    on a basis that exists.

    APPLIES_TO / VERIFY_HINT. Filled with the same sentences tools/runbook.py
    writes on insert, imported from there rather than copied, so the two
    cannot drift apart.

    Why bother, when the next sync would rewrite all of it anyway: the sync
    needs the network and CISA to both be up. Until then the rows sit in the
    database being read, and they should not be read as bare assertions in the
    meantime.
    """
    if not _table_exists(conn, "runbook"):
        return {"severity_cleared": 0, "qualifiers_filled": 0}

    cols = _columns(conn, "runbook")
    if "source" not in cols:
        return {"severity_cleared": 0, "qualifiers_filled": 0}

    severity_cleared = 0
    if "severity" in cols:
        cur = conn.execute(
            "UPDATE runbook SET severity = 'unknown' "
            "WHERE source = 'cisa_kev' AND severity = 'high'"
        )
        severity_cleared = cur.rowcount or 0

    qualifiers_filled = 0
    if {"applies_to", "verify_hint", "entry_kind"} <= cols:
        # Imported here rather than at module scope. tools/runbook.py imports
        # core.memory_engine at import time, and migrations run early, so a
        # top-level import would be asking for a cycle for no benefit.
        from tools.runbook import KEV_VERIFY_HINT, _kev_applies_to

        rows = conn.execute(
            "SELECT id, vendor, product FROM runbook "
            "WHERE source = 'cisa_kev' "
            "AND (applies_to IS NULL OR applies_to = '' "
            "     OR verify_hint IS NULL OR verify_hint = '')"
        ).fetchall()

        for r in rows:
            conn.execute(
                "UPDATE runbook SET entry_kind = 'vulnerability', "
                "applies_to = ?, verify_hint = ? WHERE id = ?",
                (_kev_applies_to(r["vendor"], r["product"]), KEV_VERIFY_HINT, r["id"]),
            )
            qualifiers_filled += 1

    return {"severity_cleared": severity_cleared,
            "qualifiers_filled": qualifiers_filled}


def _migrate_tls_hello(conn) -> int:
    """
    v38, 2026-09-18, TODO 113.2. Somewhere to put what the ClientHello said.

    WHY A NEW TABLE AND NOT COLUMNS ON packets. The packets table is one row
    per packet and it is already the biggest thing in this database. A TLS
    row is one per DISTINCT combination of client, destination, name and
    fingerprint, with a counter, which is a few thousand rows rather than a
    few million. Different grain, different lifetime, different table.

    NOTHING IS BACKFILLED AND NOTHING COULD BE. The ClientHello bytes were
    discarded at capture time, before this version, by the v34-era payload
    decision. An empty table on an existing database means the sniffer has
    not run since the upgrade, not that this machine speaks no TLS. The
    model's tool says so rather than letting an empty list read as a fact.

    THE UNIQUE KEY USES '' AND NOT NULL, and that is the v33 lesson rather
    than a style choice: SQLite allows duplicate NULLs through a UNIQUE index,
    so a nullable column in a key is not part of the key at all. Every key
    column here is NOT NULL with a '' default.
    """
    if _table_exists(conn, "tls_hello"):
        return 0

    conn.execute("""
        CREATE TABLE tls_hello (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            first_seen      TIMESTAMP NOT NULL,
            last_seen       TIMESTAMP NOT NULL,
            times_seen      INTEGER NOT NULL DEFAULT 1,
            src_ip          TEXT NOT NULL,
            dst_ip          TEXT NOT NULL,
            dst_port        INTEGER NOT NULL DEFAULT 0,
            sni             TEXT NOT NULL DEFAULT '',
            sni_state       TEXT NOT NULL
                            CHECK(sni_state IN ('present','absent','unreadable')),
            ja3             TEXT NOT NULL DEFAULT '',
            ja3_md5         TEXT NOT NULL DEFAULT '',
            alpn            TEXT NOT NULL DEFAULT '',
            legacy_version  TEXT NOT NULL DEFAULT '',
            cipher_count    INTEGER,
            ext_count       INTEGER,
            process_name    TEXT NOT NULL DEFAULT '',
            process_pid     INTEGER,
            parse_reason    TEXT NOT NULL DEFAULT '',
            session_id      TEXT,
            sensor_id       TEXT REFERENCES sensors(sensor_id),
            UNIQUE(src_ip, dst_ip, dst_port, sni, ja3_md5, process_name,
                   parse_reason)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tls_sni "
                 "ON tls_hello(sni)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tls_ja3 "
                 "ON tls_hello(ja3_md5)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tls_dst "
                 "ON tls_hello(dst_ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tls_seen "
                 "ON tls_hello(last_seen)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tls_process "
                 "ON tls_hello(process_name)")
    return 1


def _migrate_threat_feed(conn) -> int:
    """
    v40, 2026-09-20, TODO 113.4. Somewhere to keep the known-bad lists.

    WHY A LOCAL COPY AT ALL, when enrichment can already ask abuse.ch about an
    address. Because asking is a decision somebody has to make, and the point
    of this section is that nothing has to decide. Every outbound destination
    gets checked whether or not anybody was curious about it.

    THE TABLE DOES NOT GROW. A refresh deletes that feed's rows and writes the
    new ones, so the size tracks the live feed rather than the history of
    everything ever published. On a database this size that mattered more than
    keeping a record of retired indicators, and the enrichment path still
    answers "was this ever listed" for one address on demand.

    first_added IS CARRIED ACROSS A REFRESH, in tools/feed_matcher, so the
    "how long has this been listed" answer survives even though the row is
    rewritten. Without that every refresh would reset it to now and the column
    would quietly mean nothing.

    NO BACKFILL AND NONE POSSIBLE. An empty table means no refresh has
    succeeded yet, NOT that nothing is listed. feed_matcher.status reads the
    count and refuses to make a claim on zero, which is the whole reason the
    count is worth storing rather than recomputing.
    """
    if _table_exists(conn, "threat_feed"):
        return 0

    conn.execute("""
        CREATE TABLE threat_feed (
            indicator       TEXT NOT NULL,
            indicator_type  TEXT NOT NULL
                            CHECK(indicator_type IN ('ip','domain')),
            feed            TEXT NOT NULL,
            malware_family  TEXT NOT NULL DEFAULT '',
            first_added     TIMESTAMP NOT NULL,
            last_refreshed  TIMESTAMP NOT NULL,
            PRIMARY KEY (indicator, indicator_type, feed)
        )
    """)
    # The lookup index is the one that matters. Every packet, DNS row and TLS
    # row turns into a point query against it, so it is on the hot path rather
    # than being there for reporting.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_feed_lookup "
                 "ON threat_feed(indicator_type, indicator)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_feed_feed "
                 "ON threat_feed(feed)")
    return 1


def _migrate_payload_capture(conn) -> int:
    """
    v41, 2026-09-20, TODO 113.6. Where a flushed ring buffer lands.

    WHY THIS TABLE IS DIFFERENT FROM EVERY OTHER ONE HERE. The behavioural
    tables hold observations ABOUT traffic: addresses, ports, sizes, times.
    This one holds the traffic itself. It is the only place in this database
    that can contain the user's own plaintext, which is why it is the only
    table with a retention default measured in days rather than never.

    ROWS ARRIVE ONE WAY: a detector fired and flushed the flow that caused
    it. CORRECTED 2026-09-26 (register section 14): this sentence used to
    say "a detector fired and flushed the flow that caused it, or the user
    armed that destination by name", and MEASURED that second way does not
    exist -- arming gives an address a bigger memory buffer and writes
    nothing; there is no flush anywhere in either tree that runs because a
    destination was armed. The always-on part of 113.6 is a MEMORY ring
    that is never written to disk at all, and the sentence that used to end
    this paragraph ("If this table is large, something armed was left
    armed") was a conclusion drawn from the claim that was not true.

    was_armed IS STORED PER ROW rather than being looked up later, because the
    armed list changes and a row has to keep the reason it exists. A row
    flushed by a detection and a row captured because somebody asked are
    different things and the difference cannot be reconstructed afterwards.

    NO FOREIGN KEY TO findings. save_finding does not hand back a row id, and
    inventing one for this would have meant changing the write path that every
    sensor in the app uses. trigger_detection_id plus trigger_entity plus
    flushed_at is enough to pair a flush with the finding that caused it, and
    it does not put a schema change under the whole app to get there.

    AN EMPTY TABLE MEANS NOTHING WAS FLUSHED, NOT THAT NOTHING WAS SEEN. The
    coverage dict in tools/payload_ring is what tells those apart, and it has
    to be carried by anything that reads this table.
    """
    if _table_exists(conn, "payload_capture"):
        return 0

    conn.execute("""
        CREATE TABLE payload_capture (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      TEXT NOT NULL,
            -- When the ring was emptied into here.
            flushed_at      TIMESTAMP NOT NULL,
            -- When the frame was actually on the wire. These differ, and the
            -- gap between them is the point of the whole feature: the bytes
            -- predate the decision to keep them.
            captured_at     TIMESTAMP NOT NULL,
            src_ip          TEXT NOT NULL,
            dst_ip          TEXT NOT NULL,
            dst_port        INTEGER NOT NULL DEFAULT 0,
            protocol        TEXT NOT NULL DEFAULT '',
            direction       TEXT NOT NULL DEFAULT '',
            -- Order within one flush, so the conversation can be replayed.
            seq             INTEGER NOT NULL DEFAULT 0,
            data_hex        TEXT NOT NULL,
            was_armed       INTEGER NOT NULL DEFAULT 0,
            trigger_detection_id TEXT NOT NULL DEFAULT '',
            trigger_entity  TEXT NOT NULL DEFAULT ''
        )
    """)
    # flushed_at is first because the prune query is the one that runs most
    # often and it is the only query in the app that must stay fast on a
    # table nobody is reading.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_payload_flushed "
                 "ON payload_capture(flushed_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_payload_flow "
                 "ON payload_capture(src_ip, dst_ip, dst_port)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_payload_trigger "
                 "ON payload_capture(trigger_detection_id)")
    return 1


def _migrate_port_scan_origin(conn) -> int:
    """
    Add scan_origin to port_scan_results.

    Historical rows predate the distinction and were all produced by the
    scanner running on the machine it scanned, so they default to 'remote'
    but are stale in a way worth knowing about. The Ports tab shows the
    column, so old rows simply read as unqualified.
    """
    if not _table_exists(conn, "port_scan_results"):
        return 0
    if "scan_origin" in _columns(conn, "port_scan_results"):
        return 0

    # ALTER TABLE ADD COLUMN cannot carry a CHECK constraint in SQLite, so the
    # constraint lives on fresh databases from Schema.SQL and is enforced in
    # memory_engine.save_port_scan_result for everyone else.
    conn.execute("ALTER TABLE port_scan_results ADD COLUMN scan_origin TEXT DEFAULT 'remote'")
    return 1


def _migrate_port_protocol(conn) -> int:
    """
    v34. Say which protocol a port row is about.

    WHY. tools/port_scanner.py has only ever done one thing, a TCP connect
    through socket.create_connection. Nothing in the codebase has ever sent a
    UDP probe. Both facts were true and neither was written on the row, so the
    Ports tab, query_port_scan and the model all saw a bare number and had to
    supply the protocol themselves. The owner read the tool as covering UDP,
    which is a completely reasonable reading of "port 500 open" and is exactly
    the ambiguity this column removes.

    THE BACKFILL IS NOT A GUESS. Old rows get 'tcp' because TCP is the only
    thing that has ever written to this table. If a UDP prober is ever added,
    it writes 'udp' from its first row and no historical row is touched.

    ADD COLUMN twice, O(1) in SQLite whatever the table holds. No CHECK, same
    reason as scan_origin in v10: SQLite cannot attach one to ADD COLUMN, so
    the constraint lives in Schema.SQL for fresh databases and is enforced in
    memory_engine for everyone else.
    """
    added = 0

    if _table_exists(conn, "port_scan_results"):
        if "protocol" not in _columns(conn, "port_scan_results"):
            conn.execute(
                "ALTER TABLE port_scan_results "
                "ADD COLUMN protocol TEXT NOT NULL DEFAULT 'tcp'")
            added += 1

    if _table_exists(conn, "port_scan_run"):
        if "protocols" not in _columns(conn, "port_scan_run"):
            conn.execute(
                "ALTER TABLE port_scan_run "
                "ADD COLUMN protocols TEXT DEFAULT 'tcp'")
            added += 1

    if added:
        logger.info(
            "v34: protocol added to port_scan_results and protocols to "
            "port_scan_run. Existing rows read 'tcp', which is what they are: "
            "the connect scanner is the only writer this table has had.")
    return added


def _migrate_device_identity(conn) -> int:
    """
    Add identified_by, evidence and identified_at to known_devices.

    Historical rows have a known_as with no record of where it came from, so
    they are left null rather than backfilled to 'user'. A guessed source is
    the same defect the columns exist to prevent, and null reads honestly as
    "nobody wrote this down".
    """
    if not _table_exists(conn, "known_devices"):
        return 0

    existing = _columns(conn, "known_devices")
    added = 0
    for column in ("identified_by", "evidence"):
        if column not in existing:
            conn.execute(f"ALTER TABLE known_devices ADD COLUMN {column} TEXT")
            added += 1
    if "identified_at" not in existing:
        conn.execute("ALTER TABLE known_devices ADD COLUMN identified_at TIMESTAMP")
        added += 1
    return added


def _migrate_observation_supersede(conn) -> int:
    """
    Add superseded_by and superseded_reason to behavioral_session.

    The session log is append-only, which is right: it is the record of what
    the agent believed and when, and deleting from it destroys the evidence
    that a mistake happened. But append-only with no linkage means a wrong
    observation and its correction sit side by side as equal rows, and
    whether the correction is noticed depends on the model reading both and
    connecting them. That is not a correction, it is a hope.

    A link makes it real. The wrong row stays on disk and stays auditable;
    it simply stops being returned as current.
    """
    if not _table_exists(conn, "behavioral_session"):
        return 0

    existing = _columns(conn, "behavioral_session")
    added = 0
    if "superseded_by" not in existing:
        conn.execute("ALTER TABLE behavioral_session ADD COLUMN superseded_by INTEGER")
        added += 1
    if "superseded_reason" not in existing:
        conn.execute("ALTER TABLE behavioral_session ADD COLUMN superseded_reason TEXT")
        added += 1
    return added


def _migrate_service_note(conn) -> int:
    """
    Add service_note to port_scan_results and stop calling annotation a banner.

    The scanner never grabs banners; it connects and closes. The old column
    was filled with the profile-table note, and a column named 'banner' is a
    claim that a service identified itself. It had not.

    Old rows are copied across rather than rewritten, so the Ports tab keeps
    working and the history stays intact. Nothing is deleted.
    """
    if not _table_exists(conn, "port_scan_results"):
        return 0
    if "service_note" in _columns(conn, "port_scan_results"):
        return 0
    conn.execute("ALTER TABLE port_scan_results ADD COLUMN service_note TEXT")
    conn.execute("UPDATE port_scan_results SET service_note = banner "
                 "WHERE service_note IS NULL AND banner IS NOT NULL")
    return 1


def _migrate_packet_scope(conn) -> int:
    """
    Add packets.scope: the precise address classification.

    WHY A NEW COLUMN AND NOT A WIDER CHECK. The natural fix is to extend
    packets.direction's CHECK to cover the cases it is missing. SQLite cannot
    alter a CHECK in place, so that means creating a new table, copying every
    row, dropping the old one and renaming. On this database that is roughly
    900 MB of copying and about twice that in free space, against SC1, which
    says the disk is filling now. ALTER TABLE ADD COLUMN is a metadata write
    and costs the same at any table size.

    OLD ROWS ARE LEFT NULL DELIBERATELY, and this is the part not to change
    later without thinking it through. There is no backfill because no honest
    one exists: direction 'internal' meant either genuine local traffic OR a
    packet the classifier could not place, and nothing else in the row
    separates them after the fact. A backfill would have to guess, and it
    would be putting a confident value into exactly the rows whose confident
    value caused this.

    NULL here means "not recorded", which is true, and matches what the
    project does everywhere else it cannot know something. Any query over
    scope must treat NULL as unknown rather than as ordinary.
    """
    if not _table_exists(conn, "packets"):
        return 0
    if "scope" in _columns(conn, "packets"):
        return 0
    conn.execute("ALTER TABLE packets ADD COLUMN scope TEXT")
    return 1


# MIGRATION 10, sensor vantage points

# Tables that record an observation someone made, as opposed to tables that
# record a decision the model reached. Only these get a vantage point, because
# only these can be wrong about the world by virtue of where they were
# collected from. behavioral_baseline and behavioral_deviation are aggregates
# that may one day span several sensors, so stamping them with a single
# sensor_id would be a lie as soon as a second sensor exists.
_VANTAGE_TABLES = (
    "packets",
    "findings",
    "events",
    "port_scan_results",
    "known_devices",
    "pcap_results",
    "behavioral_session",
)


def _migrate_sensor_vantage(conn) -> dict:
    """
    Add the sensors table and stamp every observation with where it came from.

    THE PROBLEM THIS FIXES. Every collector in this project sees a subset of
    the network decided by where it sits. A capture on this host sees this
    host plus broadcast and multicast; unicast between two other devices is
    never forwarded to this port. That was documented in prose and repeated in
    tool descriptions, which meant the model had to take it on trust each time
    and had no field to reason from. It did not always take it on trust.

    With a sensor_id on the row, and a sensors table saying what that position
    structurally cannot see, an absence becomes interpretable rather than
    merely forbidden.

    BACKFILL. Every existing row was collected by this machine, running in the
    only mode this tool has ever had, so all of it is stamped with the local
    sensor. That is a true statement about the history, not a guess.
    """
    from core import sensors as sn

    added_columns = 0
    backfilled = 0

    if not _table_exists(conn, "sensors"):
        conn.execute("""
            CREATE TABLE sensors (
                sensor_id       TEXT PRIMARY KEY,
                label           TEXT,
                position        TEXT NOT NULL,
                summary         TEXT,
                can_see         TEXT NOT NULL,
                cannot_see      TEXT NOT NULL,
                first_seen      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes           TEXT
            )
        """)

    # The local sensor is written here rather than waiting for boot, so that
    # the backfill below points at a row that exists. Position is assumed to
    # be 'host' for history: it is what every past row was actually collected
    # from, regardless of what config.json says this instance is today.
    scope = sn.describe("host")
    conn.execute(
        "INSERT INTO sensors (sensor_id, label, position, summary, can_see, "
        "cannot_see, notes) VALUES (?,?,?,?,?,?,?) "
        "ON CONFLICT(sensor_id) DO NOTHING",
        (sn.LOCAL_SENSOR_ID, None, "host", scope["summary"],
         scope["can_see"], scope["cannot_see"],
         "Backfilled at schema v8. All observations recorded before this "
         "migration were collected by this process on this host.")
    )

    for table in _VANTAGE_TABLES:
        if not _table_exists(conn, table):
            continue
        if "sensor_id" in _columns(conn, table):
            continue
        conn.execute(f"ALTER TABLE {table} ADD COLUMN sensor_id TEXT")
        added_columns += 1
        cursor = conn.execute(
            f"UPDATE {table} SET sensor_id = ? WHERE sensor_id IS NULL",
            (sn.LOCAL_SENSOR_ID,)
        )
        backfilled += cursor.rowcount or 0

    conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_sensor "
                 "ON packets(sensor_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_sensor "
                 "ON findings(sensor_id)")

    return {"columns_added": added_columns, "rows_stamped": backfilled}


# MIGRATION 11, dns_queries

def _migrate_dns_queries(conn) -> int:
    """
    Add the DNS table. Nothing to backfill; there is no prior source for it.

    Kept separate from the vantage migration because a resolver is a
    different sensor at a different position, not another view from this one.
    Its rows are stamped with a sensor whose position is 'resolver', and the
    scope recorded there is what stops a quiet client in this table being read
    as a quiet device on the network.
    """
    if _table_exists(conn, "dns_queries"):
        return 0
    conn.execute("""
        CREATE TABLE dns_queries (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            queried_at      TIMESTAMP NOT NULL,
            client_ip       TEXT,
            domain          TEXT NOT NULL,
            query_type      TEXT,
            status          TEXT,
            blocked         INTEGER DEFAULT 0,
            upstream        TEXT,
            reply_type      TEXT,
            source          TEXT NOT NULL,
            source_row_id   TEXT NOT NULL,
            imported_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            sensor_id       TEXT REFERENCES sensors(sensor_id),
            UNIQUE(source, source_row_id)
        )
    """)
    for stmt in (
        "CREATE INDEX IF NOT EXISTS idx_dns_client     ON dns_queries(client_ip, queried_at)",
        "CREATE INDEX IF NOT EXISTS idx_dns_domain     ON dns_queries(domain)",
        "CREATE INDEX IF NOT EXISTS idx_dns_time       ON dns_queries(queried_at)",
        "CREATE INDEX IF NOT EXISTS idx_dns_client_dom ON dns_queries(client_ip, domain)",
    ):
        conn.execute(stmt)
    return 1


# MIGRATION 12 ,, the router's own tables
#
# Two tables, and they are separate on purpose because they answer different
# questions and go stale at different rates.
#
# router_clients is CURRENT STATE, not an append-only log. One row per
# (router, hardware address, address), upserted. A collection that finds
# nothing new writes no rows at all, only a last_seen touch, which is the
# whole point: this collector is meant to run on a timer and a timer that
# grows the database every tick is a timer that gets turned off. Change is
# carried by a finding at the moment it is detected, not by row count.
#
# router_config is the router's own settings as the router reports them, one
# row per setting, carrying the value it held before it changed. `present`
# exists so a setting DISAPPEARING is recorded rather than silently leaving
# the table; a listener that stops listening is drift in the same way a new
# one is.
#
# Nothing here is backfilled. There is no prior source for either, and a
# guessed history is the defect the identity columns at v8 were added to
# prevent.

def _migrate_router_tables(conn) -> int:
    created = 0

    if not _table_exists(conn, "router_clients"):
        conn.execute("""
            CREATE TABLE router_clients (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                router_host  TEXT NOT NULL,
                ip           TEXT NOT NULL,
                mac          TEXT,
                hostname     TEXT,
                vendor       TEXT,
                interface    TEXT,
                entry_type   TEXT,
                source       TEXT NOT NULL,
                first_seen   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                sensor_id    TEXT REFERENCES sensors(sensor_id)
            )
        """)
        # Expression index rather than a table constraint, because SQLite
        # treats two NULLs as distinct inside UNIQUE. A neighbour table row
        # essentially always carries a hardware address, but "essentially
        # always" is how a table quietly accumulates one duplicate per
        # collection on the one router that omits it.
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_router_clients_key "
                     "ON router_clients(router_host, ip, COALESCE(mac,''))")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_router_clients_ip "
                     "ON router_clients(ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_router_clients_mac "
                     "ON router_clients(mac)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_router_clients_seen "
                     "ON router_clients(last_seen)")
        created += 1

    if not _table_exists(conn, "router_config"):
        conn.execute("""
            CREATE TABLE router_config (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                router_host    TEXT NOT NULL,
                setting        TEXT NOT NULL,
                value          TEXT,
                detail         TEXT,
                previous_value TEXT,
                present        INTEGER DEFAULT 1,
                source         TEXT NOT NULL,
                first_seen     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                changed_at     TIMESTAMP,
                sensor_id      TEXT REFERENCES sensors(sensor_id),
                UNIQUE(router_host, setting)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_router_config_changed "
                     "ON router_config(changed_at)")
        created += 1

    return created


def _migrate_presence_tables(conn) -> int:
    """
    v12. Make absence countable.

    Before this, the only record that a device had been seen was
    known_devices.last_seen, a single value overwritten on every scan. So
    "when did I last see it" was answerable and "how many of the last forty
    sweeps did it answer" was not, because thirty-nine of those sweeps left
    nothing behind. A device that is supposed to be permanently present could
    stop answering and no query could show it.

    Two tables, positives only. Absence is derived by joining an address
    against the sweeps that ran, which bounds storage by the number of
    devices that actually answered rather than by the size of the address
    space, and makes it impossible to read a presence figure without also
    reading the denominator underneath it.

    Pure CREATE TABLE. No existing table is touched and no row is rewritten,
    so there is nothing here that can fail on a large database.
    """
    created = 0

    if not _table_exists(conn, "presence_sweep"):
        conn.execute("""
            CREATE TABLE presence_sweep (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id   TEXT NOT NULL,
                swept_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                subnet       TEXT,
                method       TEXT NOT NULL,
                outcome      TEXT NOT NULL CHECK(outcome IN ('ok','failed')),
                detail       TEXT,
                targets      INTEGER DEFAULT 0,
                responded    INTEGER DEFAULT 0,
                duration_ms  INTEGER,
                sensor_id    TEXT REFERENCES sensors(sensor_id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_presence_sweep_time "
                     "ON presence_sweep(swept_at)")
        # The denominator query filters on outcome and orders by time, and it
        # runs on every call. A failed sweep must never be counted, so the
        # filter is not optional and neither is the index.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_presence_sweep_outcome "
                     "ON presence_sweep(outcome, swept_at)")
        created += 1

    if not _table_exists(conn, "presence_observation"):
        conn.execute("""
            CREATE TABLE presence_observation (
                sweep_id  INTEGER NOT NULL REFERENCES presence_sweep(id) ON DELETE CASCADE,
                ip        TEXT NOT NULL,
                mac       TEXT,
                via       TEXT NOT NULL CHECK(via IN ('icmp','arp','both')),
                PRIMARY KEY (sweep_id, ip)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_presence_obs_ip "
                     "ON presence_observation(ip)")
        created += 1

    return created


def _migrate_device_permanence(conn) -> int:
    """
    v13. Give known_devices somewhere to record that a device is SUPPOSED to
    be here, and what it looked like when someone said so.

    Two separate gaps, both of which showed up as soon as absence became
    measurable in v12.

    is_permanent: absence only means something for a device that is meant to
    be present. Without this flag every low presence rate looks alike, and
    phones sleeping would drown the one signal worth having.

    enrollment_fingerprint: the table records what a device IS and has never
    recorded what it LOOKED LIKE. So a trusted device could change character
    completely and nothing could notice, because there was no recorded
    starting point to compare against. The instruction "known does not mean
    safe" was already there and already correct; the evidence it needs was
    not.

    All ADD COLUMN, which is O(1) in SQLite regardless of table size. No row
    is read or rewritten.
    """
    added = 0
    existing = _columns(conn, "known_devices")

    for column, ddl in (
        ("is_permanent",              "INTEGER DEFAULT 0"),
        ("permanence_set_by",         "TEXT"),
        ("permanence_set_at",         "TIMESTAMP"),
        ("enrollment_fingerprint",    "TEXT"),
        ("enrollment_fingerprint_at", "TIMESTAMP"),
    ):
        if column not in existing:
            conn.execute(f"ALTER TABLE known_devices ADD COLUMN {column} {ddl}")
            added += 1

    # Nothing is backfilled and that is the correct default. Marking a device
    # permanent is the user vouching for it, and no migration is in a
    # position to do that on their behalf. Every existing row starts at 0,
    # which reads as "nobody has said", not as "not permanent".
    if added:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_known_devices_permanent "
                     "ON known_devices(is_permanent)")

    return added


def _migrate_device_merge(conn) -> int:
    """
    v14. Let several IP rows be recorded as one physical device.

    v13 made the ghost rows correctly LABELLED. It did not make them stop
    accumulating: known_devices is keyed on IP, so a device that takes a new
    lease still gets a new row, and a randomizing phone takes new leases
    routinely. Labelled and merged are different states, and only the second
    one keeps the review queue finite.

    All ADD COLUMN, O(1) in SQLite. Nothing is merged by the migration: which
    rows are the same device is a judgement, and no migration is in a
    position to make it.
    """
    added = 0
    existing = _columns(conn, "known_devices")

    for column, ddl in (
        ("merged_into", "INTEGER REFERENCES known_devices(id)"),
        ("merged_at",   "TIMESTAMP"),
        ("merged_by",   "TEXT"),
    ):
        if column not in existing:
            conn.execute(f"ALTER TABLE known_devices ADD COLUMN {column} {ddl}")
            added += 1

    if added:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_known_devices_merged "
                     "ON known_devices(merged_into)")

    return added


def _migrate_probe(conn) -> int:
    """
    v15. The probe's own record, and somewhere to retire a device to.

    probe_run mirrors presence_sweep deliberately, including recording a pass
    that could not run. The two tables stay separate because the two cadences
    do different jobs, and collapsing them was the first design error this
    feature had caught in review.

    retired_at / retired_reason exist so that a permanent device which has
    genuinely gone stops reporting missing forever. Without that, absence
    alerts get ignored within a week and the whole signal is lost, not
    broken, ignored, which is worse because it still looks like it works.

    ADD COLUMN plus CREATE TABLE. Nothing existing is read or rewritten.
    """
    added = 0
    existing = _columns(conn, "known_devices")
    for column, ddl in (("retired_at", "TIMESTAMP"), ("retired_reason", "TEXT")):
        if column not in existing:
            conn.execute(f"ALTER TABLE known_devices ADD COLUMN {column} {ddl}")
            added += 1

    if not _table_exists(conn, "probe_run"):
        conn.execute("""
            CREATE TABLE probe_run (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id   TEXT NOT NULL,
                started_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                finished_at  TIMESTAMP,
                outcome      TEXT NOT NULL CHECK(outcome IN ('ok','failed','skipped')),
                detail       TEXT,
                eligible     INTEGER DEFAULT 0,
                probed       INTEGER DEFAULT 0,
                excluded     INTEGER DEFAULT 0,
                deferred     INTEGER DEFAULT 0,
                drift_found  INTEGER DEFAULT 0,
                retired      INTEGER DEFAULT 0,
                sensor_id    TEXT REFERENCES sensors(sensor_id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_probe_run_time "
                     "ON probe_run(started_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_probe_run_outcome "
                     "ON probe_run(outcome, started_at)")
        added += 1

    return added


def _migrate_integrity_journal(conn) -> int:
    """
    v16. An append-only journal of high-value writes, hash-chained.

    Item 3.2. Anything running with administrator rights on this machine can
    edit a finding, clear an event or rewrite a baseline, and until now
    nothing would ever know. That is not preventable on a box the attacker
    controls. It is DETECTABLE, and detectable is worth having: the whole
    value of this tool is that its record can be believed.

    Each entry carries the hash of the entry before it, so altering or
    removing anything in the middle breaks every hash after it.

    READ THE HONEST LIMITS IN core/integrity.py BEFORE TRUSTING THIS. In
    short: an attacker who reads this source can recompute the entire chain,
    so the chain alone catches careless tampering, not deliberate tampering.
    What makes it real is an ANCHOR, the head hash written somewhere the
    attacker does not control. That is why anchor() exists and why
    verify_chain() takes an expected head.

    CREATE TABLE only. Nothing existing is read or rewritten.
    """
    if _table_exists(conn, "integrity_journal"):
        return 0
    conn.execute("""
        CREATE TABLE integrity_journal (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            recorded_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            operation      TEXT NOT NULL,
            table_name     TEXT,
            row_ref        TEXT,
            payload_digest TEXT NOT NULL,
            prev_hash      TEXT NOT NULL,
            entry_hash     TEXT NOT NULL
        )
    """)
    # entry_hash is looked up on every append to find the head, and on every
    # verification pass. row_ref is how an investigator asks "what happened
    # to this finding".
    conn.execute("CREATE INDEX IF NOT EXISTS idx_journal_hash "
                 "ON integrity_journal(entry_hash)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_journal_ref "
                 "ON integrity_journal(table_name, row_ref)")
    return 1


def _migrate_observation_provenance(conn) -> int:
    """
    v17. What was the model READING when it wrote this observation?

    The slow-poisoning attack: feed crafted text to a sensor over weeks, the
    model reads it and writes observations establishing that something is
    normal, those observations become a baseline, and the baseline justifies
    suppression. Every step is individually reasonable. What is missing is
    that by the last step nothing records that the first step was
    attacker-controlled, the provenance is destroyed in the middle.

    Gating the write does not help: the tool is meant to be called constantly
    and a card on it gets click-throughed. Capping it does not help either:
    three observations a week for two months sits under any tolerable cap.
    The control has to be provenance, not volume.

    agent_loop already knows which tool results came back untrusted, it uses
    that to fence them and then discards the fact. These two columns keep it.

    ADD COLUMN only.
    """
    added = 0
    existing = _columns(conn, "behavioral_session")
    for column, ddl in (("evidence_untrusted", "INTEGER DEFAULT 0"),
                        ("evidence_sources", "TEXT")):
        if column not in existing:
            conn.execute(
                f"ALTER TABLE behavioral_session ADD COLUMN {column} {ddl}")
            added += 1
    return added


def _migrate_beacon_detail(conn) -> int:
    """
    v20. One column to hold measured contact regularity.

    value_mean / value_stddev already existed on behavioral_baseline and were
    empty on every beacon_destinations row. They can hold the numbers but not
    the thing the numbers are ABOUT, and an interval with no destination
    attached is not a fact anyone can act on.

    ADD COLUMN, O(1) in SQLite. Nothing is read or rewritten.
    """
    if "beacon_detail" in _columns(conn, "behavioral_baseline"):
        return 0
    conn.execute("ALTER TABLE behavioral_baseline ADD COLUMN beacon_detail TEXT")
    return 1


def _migrate_event_record_id(conn) -> int:
    """
    v21. One column and one unique index, so the same source record cannot be
    stored as two events.

    THE BUG THIS CLOSES IS A SIDE EFFECT OF A CORRECT DECISION, WHICH IS WHY
    IT SURVIVED REVIEW.

    EventMonitor reads the Windows Security log backwards and refuses to move
    its high-water mark when a burst ends the pass at a cap. That is right,
    and S22 argues it properly: a 4720 buried under a flood and skipped is
    gone for good, while one that gets read twice is merely untidy. The
    warning it logs even says so out loud.

    What nobody followed through on is where "merely untidy" lands. Every
    re-read record was inserted again, so a burst did not just repeat itself
    in the log, it repeated itself in the events table. Counts built from
    those rows come out high, and a baseline built on high counts is not
    noisy, it is wrong, and it is wrong in a way that looks like data.

    So the fix belongs at the write, not in the marker logic. Nothing about
    the reading changes.

    NULLS ARE DISTINCT IN A SQLITE UNIQUE INDEX, which is what makes this
    safe to add to a populated table. Every existing row has NULL here, and
    no two NULLs collide, so the index builds without touching a thing and
    without a chance of failing on old data. Sources with no id of their own
    keep inserting exactly as before.

    ADD COLUMN is O(1). The index build is one pass over events, which is a
    small table next to packets.
    """
    added = 0
    if "source_record_id" not in _columns(conn, "events"):
        conn.execute("ALTER TABLE events ADD COLUMN source_record_id INTEGER")
        added = 1
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_events_source_record "
        "ON events(source, source_record_id)")
    return added


def _migrate_promoted_findings(conn) -> int:
    """
    v28, 2026-09-09. Six columns on findings, so that a finding can be
    nominated by the model and promoted by the owner.

    WHY IT IS NOT A NEW TABLE, which was the first instinct and the wrong one.

    A separate "important findings" table holds COPIES. A copy cannot know
    that the rule which raised the original has since been fixed, so it sits
    there being wrong while everything around it gets corrected. That is not
    hypothetical: on 2026-09-08 the masquerading rule was fixed and seventeen
    false HIGH findings stayed exactly where they were, because nothing joins
    a row to the rule that produced it.

    Putting the flag ON the finding means there is only ever one row. Dismiss
    it, clear it, resolve it, and the promotion goes with it. There is no
    second place to remember to clean, which is the only reason the first
    place ever gets cleaned.

    TWO SETS OF COLUMNS, ON PURPOSE. nominated_* is the model raising its
    hand. promoted is the owner agreeing. The model has no path to the second
    set, in the engine or in the tool layer, because a list the model can
    write to is a list the model can fill.

    Everything defaults to nothing. No backfill, no guessing which existing
    findings "were probably important". Nobody has promoted anything yet
    because there was no way to, so the honest starting state is empty.
    """
    cols = _columns(conn, "findings")
    added = 0
    for col, ddl in (
        ("nominated_at",     "TIMESTAMP"),
        ("nominated_by",     "TEXT"),
        ("nominated_reason", "TEXT"),
        ("promoted",         "INTEGER DEFAULT 0"),
        ("promoted_at",      "TIMESTAMP"),
        ("promoted_reason",  "TEXT"),
    ):
        if col in cols:
            continue
        conn.execute(f"ALTER TABLE findings ADD COLUMN {col} {ddl}")
        added += 1

    if added:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_promoted "
                     "ON findings(promoted, dismissed)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_nominated "
                     "ON findings(nominated_at)")
    return added


def _migrate_baseline_retract(conn) -> int:
    """
    v29, 2026-09-13. Four columns so a baseline can be WITHDRAWN.

    THE GAP, from 45.5. supersede_observation withdraws a session observation,
    but run_rollup reads current observations only, so a withdrawal keeps the
    row out of FUTURE merges and does nothing about the baseline that already
    ate it. behavioral_baseline is cumulative and forward only. You could
    retract the sentence and not the belief it produced.

    WHAT WAS ALREADY FINE, and it is worth saying because 45.5 overstated
    this: revert_suppression exists, is ungated, is a live tool and backs the
    Review dashboard. The dangerous half, a baseline silencing alerts, was
    always undoable. What could not be undone is the LEARNED CONTENT:
    value_mean, typical_hours, typical_dest_ports, and the session count.

    NOTHING IS DELETED, same as every other withdrawal in this codebase. The
    row keeps its identity and gains a reason and a timestamp, so a later
    reader can see what was believed and why that changed.

    THE SESSION COUNT IS THE SUBTLE HALF. sample_count is derived from
    baseline_session_seen, so clearing the baseline row alone would leave the
    count intact and the very next observation would come back at the old
    confidence, as if nothing had been withdrawn. So the seen rows get stamped
    too, and the count only reads unstamped ones. The audit of which sessions
    saw what is kept, it just stops counting toward a belief that was pulled.
    """
    added = 0
    for table, col, ddl in (
        ("behavioral_baseline",  "retracted_at",     "TIMESTAMP"),
        ("behavioral_baseline",  "retracted_reason", "TEXT"),
        ("baseline_session_seen", "retracted_at",    "TIMESTAMP"),
    ):
        if col in _columns(conn, table):
            continue
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
        added += 1

    if added:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_baseline_retracted "
                     "ON behavioral_baseline(retracted_at)")
    return added


def _migrate_resolved_by(conn) -> int:
    """
    v30, 2026-09-14, TODO 98. One column, and it corrects a claim.

    behavioral_deviation has carried user_responded and user_response since
    the beginning, documented in the schema as "0 = silence, 1 = user replied"
    and "verbatim if they responded". resolve_deviation set both from whatever
    it was handed, and one of its three callers is the model's own tool, which
    is ungated and takes free text. The manifest asked for it by name.

    So a model resolve looked exactly like a human one, and it also lifted the
    row out of get_silent_deviations, which selects user_responded = 0 and
    exists precisely because silence is not approval.

    NOTHING IS BACKFILLED. Every existing row was written before this column
    existed and there is no way to tell now which of them a person answered.
    Guessing 'user' because user_responded is 1 would be manufacturing the
    exact provenance this column was added to stop manufacturing. NULL means
    not recorded, which is the truth about those rows.
    """
    if "resolved_by" in _columns(conn, "behavioral_deviation"):
        return 0
    # No CHECK constraint on the ALTER. SQLite cannot add one to an existing
    # table without rebuilding it, and rebuilding a table with hundreds of
    # thousands of rows to police three strings is the wrong trade. The values
    # are validated in memory_engine.resolve_deviation, which is the only
    # writer, and the CHECK is in Schema.SQL for databases created fresh.
    conn.execute("ALTER TABLE behavioral_deviation ADD COLUMN resolved_by TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_deviation_resolved_by "
                 "ON behavioral_deviation(resolved_by, user_responded)")
    return 1


def _migrate_detection_ids(conn) -> int:
    """
    v33, 2026-09-15, TODO 112. Two columns on findings plus one new table.

    NOTHING IS BACKFILLED, and this is the second time in three migrations the
    answer has been "leave it NULL". Same reasoning as _migrate_resolved_by:
    the old rows record which rule fired only as an English sentence, and
    deciding that "Threat detected: dangerous_port_inbound:445:SMB" was
    PKT-1013 is a guess dressed as a lookup. It would usually be right, which
    is what makes it dangerous, because the rows where it is wrong would be
    indistinguishable from the rows where it is right.

    NULL therefore means RAISED BEFORE THIS EXISTED. The Detections page says
    so in those words rather than showing the count as zero, because a rule
    that has fired fifty times since August and reads "0 findings" is a lie
    told by a column that was added last week.

    scripts/detection_report.py --backfill-preview shows what an exact
    title-prefix match WOULD claim, read only, writing nothing. If the owner wants
    those rows stamped it is the owner's call with the numbers in front of the owner.

    THE ALTER CARRIES NO CHECK and none is wanted. detection_id is validated
    against core/detections at the only place that writes it, which is
    memory_engine.save_finding, and a CHECK listing thirty ids in the schema
    would be a second copy of the register that goes stale the first time one
    is added.
    """
    added = 0
    cols = _columns(conn, "findings")
    if "detection_id" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN detection_id TEXT")
        added += 1
    if "detection_rev" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN detection_rev INTEGER")
        added += 1
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_detection "
                 "ON findings(detection_id)")

    if not _table_exists(conn, "detection_suppression"):
        # entity_type and entity_value default to '*', the literal wildcard.
        # NOT NULL, because NULL would defeat the UNIQUE index: SQLite treats
        # two NULLs as distinct, so the same "silence this everywhere" rule
        # could be inserted over and over with nothing objecting.
        conn.execute("""
            CREATE TABLE detection_suppression (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_id  TEXT NOT NULL,
                entity_type   TEXT NOT NULL DEFAULT '*',
                entity_value  TEXT NOT NULL DEFAULT '*',
                reason        TEXT NOT NULL,
                created_by    TEXT NOT NULL DEFAULT 'user'
                              CHECK(created_by IS NULL OR
                                    created_by IN ('user','model')),
                created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at    TIMESTAMP,
                UNIQUE(detection_id, entity_type, entity_value)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_suppression_detection "
                     "ON detection_suppression(detection_id)")
        added += 1
    return added


def _migrate_prediction_ledger(conn) -> int:
    """
    v31, 2026-09-14. One new table, and it is the first time anything in this
    project can tell the model it was wrong.

    WHY IT IS A NEW TABLE AND NOT A COLUMN ON behavioral_session. A baseline
    observation is a statement about what HAS happened, and it is allowed to
    feed suppression. A prediction is a statement about what WILL happen, it
    is wrong roughly as often as it is right, and it must never touch the
    tables that decide what gets alerted on. Two different lifetimes and two
    different blast radii, so two different tables.

    THE CHECK COLUMNS ARE FILLED BY PYTHON ONLY. core/predictions.py is the
    only writer of outcome, and the model has no tool that reaches it. This is
    the same rule as expected ports: the party being measured does not get to
    hold the ruler.

    NOTHING IS BACKFILLED because there is nothing to backfill. The table
    starts empty on every database, new or old, and a row only ever appears
    when the model files one.
    """
    if _table_exists(conn, "prediction"):
        return 0

    conn.execute("""
        CREATE TABLE prediction (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      TEXT NOT NULL,
            made_at         TIMESTAMP NOT NULL,
            horizon_ends_at TIMESTAMP NOT NULL,
            claim_kind      TEXT NOT NULL
                            CHECK(claim_kind IN ('no_traffic','traffic_above',
                                                 'traffic_below','no_finding',
                                                 'finding_expected',
                                                 'device_present','device_absent')),
            entity_type     TEXT NOT NULL
                            CHECK(entity_type IN ('ip','process','port','user')),
            entity_value    TEXT NOT NULL,
            threshold       REAL,
            detail          TEXT,
            statement       TEXT NOT NULL,
            reasoning       TEXT,
            outcome         TEXT CHECK(outcome IN ('hit','miss','unverifiable')),
            outcome_reason  TEXT,
            observed_value  REAL,
            coverage_note   TEXT,
            checked_at      TIMESTAMP
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_prediction_due "
                 "ON prediction(outcome, horizon_ends_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_prediction_entity "
                 "ON prediction(entity_type, entity_value)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_prediction_made "
                 "ON prediction(made_at)")
    return 1


def _migrate_question_queue(conn) -> int:
    """
    v32, 2026-09-14. The model gets to ask the owner something.

    TOPICS ARE A FIXED LIST and the unique index is on (topic, entity_type,
    entity_value), which is what makes "never ask the same thing twice" a
    property of the database rather than a rule the model is asked to follow.
    A free-text question could be rephrased around that without anyone
    meaning to.

    THE POPUP LOG IS A SEPARATE TABLE because a popup is not a question. One
    popup carries several, and the budget counts interruptions, not questions.
    A counter in memory would have reset on every boot, which is the same as
    no budget on a machine that gets restarted.
    """
    added = 0
    if not _table_exists(conn, "operator_question"):
        conn.execute("""
            CREATE TABLE operator_question (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id    TEXT NOT NULL,
                asked_at      TIMESTAMP NOT NULL,
                topic         TEXT NOT NULL
                              CHECK(topic IN ('identify_device',
                                              'identify_destination',
                                              'identify_process',
                                              'expected_behaviour',
                                              'confirm_change')),
                entity_type   TEXT NOT NULL
                              CHECK(entity_type IN ('ip','process','port','user')),
                entity_value  TEXT NOT NULL,
                question      TEXT NOT NULL,
                why_stuck     TEXT,
                tried_json    TEXT NOT NULL DEFAULT '[]',
                hints_json    TEXT NOT NULL DEFAULT '[]',
                first_shown_at TIMESTAMP,
                state         TEXT NOT NULL DEFAULT 'open'
                              CHECK(state IN ('open','answered','do_not_know',
                                              'expired')),
                answered_at   TIMESTAMP,
                answer_text   TEXT,
                answer_filed_as TEXT,
                UNIQUE(topic, entity_type, entity_value)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_question_state "
                     "ON operator_question(state, asked_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_question_shown "
                     "ON operator_question(first_shown_at)")
        added += 1

    if not _table_exists(conn, "operator_popup"):
        conn.execute("""
            CREATE TABLE operator_popup (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                shown_at     TIMESTAMP NOT NULL,
                question_ids TEXT NOT NULL DEFAULT '[]',
                carried      INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_popup_shown "
                     "ON operator_popup(shown_at)")
        added += 1

    return added


def _migrate_perf_hourly(conn) -> int:
    """
    v32, 2026-09-14. The performance axis, one row per device per hour.

    STORED RATHER THAN COMPUTED ON DEMAND, and it is the same argument
    core/intervals.py makes about beacon intervals: retention prunes packets,
    and when they go, so does the only place any of this was ever recorded.
    Measure while the packets are here, keep the summary, then prune.

    NOTHING IS BACKFILLED AT MIGRATION TIME even though the packets for the
    last few days are sitting right there. A backfill would be a long scan
    over the largest table in the database during boot, and the rollup will
    fill recent hours on its first pass anyway. The difference is only how
    quickly the page becomes useful, and a boot that hangs is a worse trade.
    """
    if _table_exists(conn, "perf_hourly"):
        return 0

    conn.execute("""
        CREATE TABLE perf_hourly (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_value     TEXT NOT NULL,
            hour_start       TIMESTAMP NOT NULL,
            bytes_in         INTEGER NOT NULL DEFAULT 0,
            bytes_out        INTEGER NOT NULL DEFAULT 0,
            packets_in       INTEGER NOT NULL DEFAULT 0,
            packets_out      INTEGER NOT NULL DEFAULT 0,
            distinct_peers   INTEGER NOT NULL DEFAULT 0,
            dns_queries      INTEGER,
            dns_failures     INTEGER,
            sweeps_total     INTEGER,
            sweeps_answered  INTEGER,
            coverage_seconds INTEGER NOT NULL DEFAULT 0,
            computed_at      TIMESTAMP NOT NULL,
            UNIQUE(entity_value, hour_start)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_perf_hour "
                 "ON perf_hourly(hour_start)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_perf_entity "
                 "ON perf_hourly(entity_value, hour_start)")
    return 1


def _migrate_incident_ledger(conn) -> int:
    """
    v35, 2026-09-17, T2. The incident table, and it is the layer between
    "a finding happened" and "somebody should look".

    WHY IT IS NOT A COLUMN ON findings. A finding is a single observation made
    by a single sensor at a single moment. An incident is a judgement that some
    number of those add up to one thing worth a person's attention, and that
    judgement has its own lifetime, its own state machine, and its own cost
    accounting once the duty loop exists. Folding it into findings would mean
    either one incident per finding (which is just the findings list again) or
    a findings row that several sensors share, which no sensor writes.

    THE COVERAGE COLUMNS ARE THE POINT OF THE TABLE, and they are the ones a
    reader is most likely to skip past. `coverage_json` records which sensors
    were BLIND at the moment the incident was assessed, and `coverage_note`
    is the same thing in a sentence. Without them the incident reads as an
    assessment of the network, when it is an assessment of what this app
    could see of the network. Those are different claims and only one of them
    is ever true. See core/sensor_health for the machinery that fills it.

    NOTHING IS BACKFILLED, for the third time in this project and always for
    the same reason: there are no incidents before this table exists, and
    manufacturing rows out of the findings already in the database would be
    inventing a triage history that nobody performed. The watcher starts
    where the database is, and the first incident it writes carries a
    first_seen_at it observed rather than one it inferred.

    THE STATE MACHINE IS IN A CHECK. new -> triaged -> action_pending ->
    resolved, plus dismissed from anywhere. `action_pending` exists in the
    schema NOW because T3's queue writes it; leaving it out would mean a
    schema change in the middle of the action-queue work, and a state that the
    ledger cannot name is a state the ledger will silently round to another
    one.

    DEDUP IS A KEY, NOT A RULE. incident_key is
    (detection_id, entity_type, entity_value) and it is UNIQUE. That makes
    "one incident per thing" a property of the database rather than something
    the watcher is asked to remember, which matters because the watcher's
    whole job is to read a stream of findings that repeat themselves and
    collapse them. A watcher that restarts and re-collapses everything is
    fine; one that cannot tell "already accounted for" from "new" is not.
    """
    added = 0
    if not _table_exists(conn, "incident"):
        conn.execute("""
            CREATE TABLE incident (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_key    TEXT NOT NULL UNIQUE,
                detection_id    TEXT NOT NULL,
                detection_rev   INTEGER,
                entity_type     TEXT NOT NULL,
                entity_value    TEXT NOT NULL,
                source          TEXT,
                severity        TEXT NOT NULL,
                severity_rank   INTEGER NOT NULL DEFAULT 0,
                cia_json        TEXT NOT NULL DEFAULT '[]',
                title           TEXT NOT NULL,
                first_seen_at   TIMESTAMP NOT NULL,
                last_seen_at    TIMESTAMP NOT NULL,
                finding_count   INTEGER NOT NULL DEFAULT 1,
                finding_ids_json TEXT NOT NULL DEFAULT '[]',
                status          TEXT NOT NULL DEFAULT 'new'
                                CHECK(status IN ('new','triaged','action_pending',
                                                 'resolved','dismissed')),
                status_at       TIMESTAMP NOT NULL,
                status_by       TEXT NOT NULL DEFAULT 'watcher'
                                CHECK(status_by IN ('watcher','model','user',
                                                    'silence_timer')),
                assessment      TEXT,
                assessed_at     TIMESTAMP,
                assessment_tokens INTEGER,
                actions_json    TEXT NOT NULL DEFAULT '[]',
                coverage_json   TEXT,
                coverage_note   TEXT,
                suppressed      INTEGER NOT NULL DEFAULT 0,
                suppressed_reason TEXT,
                created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_status "
                     "ON incident(status, last_seen_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_detection "
                     "ON incident(detection_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_entity "
                     "ON incident(entity_type, entity_value)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_seen "
                     "ON incident(last_seen_at)")
        added += 1

    # The watcher's own record of what it has done, and it is a TABLE rather
    # than a preference for the same reason the popup budget is: a counter in
    # memory resets on every boot, which on a machine that gets restarted is
    # the same as having no cap at all. One row per tick, so "was the watcher
    # actually running at 3am" is answerable after the fact.
    if not _table_exists(conn, "watcher_run"):
        conn.execute("""
            CREATE TABLE watcher_run (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id    TEXT NOT NULL,
                ran_at        TIMESTAMP NOT NULL,
                outcome       TEXT NOT NULL
                              CHECK(outcome IN ('ok','refused','error')),
                findings_read INTEGER NOT NULL DEFAULT 0,
                new_incidents INTEGER NOT NULL DEFAULT 0,
                coalesced     INTEGER NOT NULL DEFAULT 0,
                refused       INTEGER NOT NULL DEFAULT 0,
                capped        INTEGER NOT NULL DEFAULT 0,
                backlog       INTEGER NOT NULL DEFAULT 0,
                detail        TEXT,
                duration_ms   INTEGER,
                -- THE WATCHER'S CURSOR. The highest finding id this tick had
                -- accounted for. It lives here rather than in
                -- user_preferences because core/integrity snapshots that
                -- table as "the policy" and journals a config_observed entry
                -- whenever it moves, on the stated contract that such an
                -- entry ALWAYS means the rules changed and is never routine
                -- noise. A cursor written every 60 seconds would have turned
                -- the tamper journal into a log of the watcher's own
                -- bookkeeping, which is how the one warning that matters gets
                -- learned past. NULL means no row has ever carried a cursor,
                -- which is a first run; a run that read nothing carries the
                -- previous value forward instead.
                last_processed_finding_id INTEGER
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_watcher_run_at "
                     "ON watcher_run(ran_at)")
        added += 1
    else:
        # An existing watcher_run from the first cut of T2, before the cursor
        # moved here. ADD COLUMN is O(1) in SQLite and nothing needs
        # backfilling: NULL is the honest value for every row written before
        # the column existed, and the watcher re-reads from wherever the
        # newest non-NULL cursor is.
        cols = _columns(conn, "watcher_run")
        if "last_processed_finding_id" not in cols:
            conn.execute("ALTER TABLE watcher_run "
                         "ADD COLUMN last_processed_finding_id INTEGER")
            added += 1

    # The cursor's first home was user_preferences, in the first cut of T2. If
    # a database was booted against that version, the keys are still there and
    # they will make core/integrity journal a config_observed entry on the
    # next snapshot -- a false "the policy changed" warning caused by this
    # migration. Removing them is the only correct answer: they are this
    # codebase's own bookkeeping, they were never policy, and leaving them
    # would leave the tamper journal telling a story about a cursor.
    cur = conn.execute(
        "DELETE FROM user_preferences WHERE key IN "
        "('incident_watcher_watermark','incident_watcher_watermark_ts')")
    if cur.rowcount:
        logger.info(f"Removed {cur.rowcount} watcher-cursor preference "
                    f"key(s) left by the first cut of T2; the cursor lives on "
                    f"the watcher_run row now.")
        added += 1

    return added


def _migrate_action_queue(conn) -> int:
    """
    v36, 2026-09-18, T3. The action queue: a gated action filed as a request.

    WHY THIS IS A TABLE AND NOT A DICT IN agent_loop.

    The chat permission card is a data structure inside an SSE generator. The
    generator that yields the card is the same generator that runs the tool
    once the answer comes back, so the card and the tool call have exactly the
    lifetime of the HTTP connection that owns them. That is fine for a person
    sitting at the dashboard and it is the whole reason the 3am case was
    impossible: at 3am there is no connection, and at 7am the one that could
    have run the action is gone.

    agent_loop's own docstring named the missing piece before this table
    existed: "it needs something outside the turn to execute the action and a
    way to get the result back to the model". The table is the first half and
    core/actions.py's worker is the second.

    NOTHING IS BACKFILLED, for the fourth time in this project and for the
    same reason every time: there are no filed requests before this table
    exists, and manufacturing rows out of the permission prompts in old chat
    transcripts would invent a decision history nobody lived. The queue starts
    empty and that empty queue is the true state.

    THE STATE MACHINE IS IN A CHECK, with two deliberate shapes a reader might
    otherwise "tidy":

      * 'executed' and 'failed' are separate from 'approved', because approved
        is a DECISION and executed is an ACTION. Collapsing them would make a
        request that was approved and never ran indistinguishable from one
        that ran, which is the exact fact an operator would be misled by.
      * 'expired' is separate from 'denied', because nobody saying anything is
        not somebody saying no. core/actions.summary never sums them and this
        CHECK is what stops a writer blurring them.

    `decided_by` permits ONLY 'user'. That is a CHECK rather than a comment
    because it is the property the whole gate rests on: a row recording that
    the model approved its own request would be indistinguishable, later, from
    one a person approved. There is no code path that writes 'model' here and
    the constraint means there cannot be one added by accident.

    Kept in sync with Schema.SQL by hand; see the comment there.
    """
    added = 0
    if not _table_exists(conn, "action_request"):
        conn.execute("""
            CREATE TABLE action_request (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id      TEXT NOT NULL,
                created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

                verb            TEXT NOT NULL,
                target          TEXT NOT NULL,
                params_json     TEXT NOT NULL,
                reason          TEXT,

                evidence_json   TEXT,
                evidence_fingerprint TEXT,

                proposed_by     TEXT NOT NULL DEFAULT 'model'
                                CHECK(proposed_by IN ('model','watcher',
                                                      'user')),
                incident_id     INTEGER,

                state           TEXT NOT NULL DEFAULT 'pending'
                                CHECK(state IN ('pending','approved','denied',
                                                'executed','failed',
                                                'expired')),
                decided_at      TIMESTAMP,
                decided_by      TEXT
                                CHECK(decided_by IS NULL OR decided_by IN
                                      ('user')),
                decision_note   TEXT,

                claim_at        TIMESTAMP,
                claimed_by      TEXT,
                executed_at     TIMESTAMP,
                outcome         TEXT
                                CHECK(outcome IS NULL OR outcome IN
                                      ('success','refused','error',
                                       'not_attempted')),
                result_json     TEXT,
                error           TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_action_state "
                     "ON action_request(state, id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_action_target "
                     "ON action_request(verb, target, state)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_action_incident "
                     "ON action_request(incident_id)")
        added += 1

    return added


def _migrate_duty_loop(conn) -> int:
    """
    v37, 2026-09-18, T4. The duty loop's two tables.

    WHY A RUN TABLE RATHER THAN A LOG LINE. The whole subject of this task is
    a component that is allowed to do NOTHING, most of the time, on purpose.
    "The duty loop woke at 03:00 and found nothing above the bar" and "the
    duty loop was not running" are the same silence on the Agents page, and
    only one of them is a statement about the network. So every tick writes a
    row whether or not it investigated anything, exactly as watcher_run does
    for the deterministic half, and the row says which of the four ways the
    tick ended: examined an incident, ran the regular report, refused because
    a budget was spent, or refused because there was nothing eligible.

    `tokens_spent` ON THE RUN ROW IS THE LEDGER FOR THE CEILING. The cap is
    not a separate counter that has to be kept in step: it is
    SUM(tokens_spent) over the rolling window, computed from the same rows a
    reader would look at. A counter and a log disagree eventually, and the
    one that disagrees quietly is the one that lets a runaway spend happen.

    WHY duty_report IS ITS OWN TABLE. The owner asked for a page where the
    agent's work is READABLE, and the report is the artifact: a hypothesis, the
    evidence it gathered, a verdict, and -- when the verdict is "no action" --
    what it actually saw, in its own words. It is not a chat message, it is not
    a finding, and it is not an incident assessment. Storing it anywhere else
    would mean the thing the page shows is assembled at render time out of
    several rows, and a page that assembles its own evidence is a page that can
    show a sentence no component ever wrote.

    NOTHING IS BACKFILLED, for the fifth time in this project and always for
    the same reason: there are no duty runs and no reports before these tables
    exist. The loop starts with an empty history, and the first report on the
    page carries a timestamp it observed.

    THE BUDGET COLUMNS ARE ON THE RUN, NOT IN A PREFERENCE, and the incident
    table's own history is why. A cursor written into user_preferences would be
    hashed by core/integrity as "the policy" on every tick. The same argument
    applies here with one addition: a spend counter is a number a reader must
    be able to CHECK, and a number you can only read from a summary is a number
    you have to trust.

    Kept in sync with Schema.SQL by hand; see the comment there.
    """
    added = 0
    if not _table_exists(conn, "duty_run"):
        conn.execute("""
            CREATE TABLE duty_run (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id      TEXT NOT NULL,
                ran_at          TIMESTAMP NOT NULL,
                ended_at        TIMESTAMP,

                -- WHAT TRIGGERED IT. 'regular' is one of the four scheduled
                -- moments of the day; 'emergency' is the volume trigger; the
                -- two manual ones exist so the dashboard button and the
                -- verification script leave the same kind of record a
                -- scheduled wake-up does, rather than a second kind nobody
                -- reads.
                trigger         TEXT NOT NULL
                                CHECK(trigger IN ('regular','emergency',
                                                  'manual','verify')),

                -- HOW IT ENDED, and these are four different sentences:
                --   investigated  it looked at an incident and wrote a report
                --   reported      it gathered the regular report and wrote one
                --   budget        a cap refused it; nothing was examined
                --   idle          it woke, looked, and nothing was eligible
                --   error         something broke, and it says what
                -- 'idle' is the one a reader is most likely to misread, so
                -- the row always carries `detail` for it.
                outcome         TEXT NOT NULL
                                CHECK(outcome IN ('investigated','reported',
                                                  'budget','idle','error')),

                incident_id     INTEGER,
                report_id       INTEGER,

                -- SPEND, per run, in the units the provider reports. prompt +
                -- completion, because reasoning tokens are billed inside
                -- completion_tokens and a ceiling that counts only answers
                -- would be watching the smaller half. See duty.py's header.
                --
                -- tokens_estimated: 1 when the provider sent no usage block
                -- and the numbers above were derived from character counts by
                -- agent_loop._estimate_tokens. A ceiling that cannot tell a
                -- measured spend from a guessed one is a ceiling somebody will
                -- one day read as exact, so the flag is part of the row.
                tokens_prompt     INTEGER NOT NULL DEFAULT 0,
                tokens_completion INTEGER NOT NULL DEFAULT 0,
                tokens_spent      INTEGER NOT NULL DEFAULT 0,
                tokens_estimated  INTEGER NOT NULL DEFAULT 0,
                model_calls       INTEGER NOT NULL DEFAULT 0,

                -- THE COVERAGE THAT EXISTED WHEN THIS TICK RAN. Same column
                -- and same argument as the incident ledger's: an assessment of
                -- a network and an assessment of what this app could see are
                -- different claims and only one is ever true.
                coverage_json   TEXT,
                coverage_note   TEXT,

                detail          TEXT,
                duration_ms     INTEGER
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_duty_run_at "
                     "ON duty_run(ran_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_duty_run_outcome "
                     "ON duty_run(outcome, ran_at)")
        added += 1

    if not _table_exists(conn, "duty_report"):
        conn.execute("""
            CREATE TABLE duty_report (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id      TEXT NOT NULL,
                created_at      TIMESTAMP NOT NULL,

                kind            TEXT NOT NULL
                                CHECK(kind IN ('incident','regular')),
                trigger         TEXT NOT NULL,

                -- What this report is ABOUT. An incident report names one; a
                -- regular report names the two findings it chose, and the
                -- second one is here rather than in a join table because the
                -- number is fixed at two by the owner's instruction and a
                -- report about one thing must not look like a report about
                -- two.
                incident_id     INTEGER,
                finding_id      INTEGER,
                second_finding_id INTEGER,

                -- THE THREE PARTS THE OWNER ASKED TO BE ABLE TO READ.
                hypothesis      TEXT,
                evidence        TEXT,
                verdict         TEXT,

                -- WHAT IT SAW WHEN IT CONCLUDED NOTHING NEEDED DOING. This is
                -- the column that makes "no action" a claim rather than an
                -- absence, and it is required for a 'no_action' verdict in
                -- Python rather than in a CHECK, because the sentence it needs
                -- is longer than a constraint should carry.
                saw             TEXT,
                action_taken    TEXT
                                CHECK(action_taken IS NULL OR action_taken IN
                                      ('none','proposed','notified')),

                -- The prose the Agents page renders. Written in the app's own
                -- voice; see duty.REPORT_VOICE.
                body            TEXT NOT NULL,

                tokens_spent    INTEGER NOT NULL DEFAULT 0,
                model_calls     INTEGER NOT NULL DEFAULT 0,

                coverage_json   TEXT,
                coverage_note   TEXT,

                -- NULL means the report exists and nothing has read it, which
                -- is not the same as read-and-agreed. Nothing consumes these
                -- yet; they are here so a later reader has somewhere to say it
                -- looked without a schema change.
                read_at         TIMESTAMP,
                read_by         TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_duty_report_at "
                     "ON duty_report(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_duty_report_kind "
                     "ON duty_report(kind, created_at)")
        added += 1

    return added


def _migrate_agent_record_seal(conn) -> int:
    """
    v47, 2026-09-23. WHAT THE AGENT CALLED, on the run row.

    One column, and it closes a defect found while building the seal rather
    than a feature request. core/agent_loop.run_unattended already collects
    every tool name the unattended turn invoked and returns them; core/duty
    then read the dict through _usage_dict, which takes prompt tokens,
    completion tokens, answers and error -- and DROPS `tool_calls` and
    `refused_calls` on the floor. So the app paid for the collection, wrote
    the run row, and the only record of what the agent actually DID (as
    opposed to what it concluded) was nowhere on disk. The Agents page said
    "it worked an incident and left report #12"; it could not say the report
    was written after calling query_findings, query_packets and
    query_prediction_score, or that a gated call was refused on the way.

    THAT MATTERS MORE NOW, NOT LESS. This column lands in the same commit as
    core/integrity.seal_row, which digests duty_run rows. A seal over a run
    that says which tools ran is a record of the agent's behaviour; a seal
    over a run that only says how much it spent is a receipt. The owner's
    complaint was specifically "the tools it called" — this is the half of
    that which was collectable without a new table.

    NULL AND '[]' ARE DIFFERENT AND BOTH ARE KEPT. NULL means no unattended
    turn ran (a budget refusal, an idle tick, a run recorded by a script);
    '[]' means a turn ran and called nothing, which is the ordinary shape for
    a report that answered from the prompt alone. Collapsing them would make
    "it never got that far" and "it looked and needed no tools" the same
    value, which this project does not do anywhere else.

    NOTHING IS BACKFILLED, and it cannot be: those names were discarded at
    the time, so there is nothing on disk to reconstruct them from. Every
    existing row keeps NULL, which is exactly true — nobody recorded it.

    Additive ALTER, O(1) in SQLite. Schema.SQL carries the same column; the
    two are kept in step by hand, as the comment there says.
    """
    added = 0
    if not _table_exists(conn, "duty_run"):
        return 0
    if "tools_json" not in _columns(conn, "duty_run"):
        conn.execute("ALTER TABLE duty_run ADD COLUMN tools_json TEXT")
        added += 1
        logger.info(
            "v47: duty_run.tools_json added. The names of the tools the "
            "unattended turn called were being collected by agent_loop and "
            "then dropped by duty._usage_dict, so the app could report what "
            "the agent concluded and not what it ran. Existing rows keep "
            "NULL: nothing recorded it, and that is what NULL says.")
    return added


def _migrate_report_dismissal(conn) -> int:
    """
    v51, 2026-09-25. DISMISSING A REPORT WITHOUT DELETING IT.

    The owner's instruction: "we need a dismiss button plus check box for agent
    reports, also a dismiss all ... those however won't delete the agent
    entries from the database and baseline if it was initially writing in
    those."

    That last clause is the whole design and it is the correct instinct. An
    agent report is not a chat message: it is the agent's own hypothesis,
    evidence and verdict, and for a report written while something was blind it
    is also the coverage record of that moment. Deleting one would remove the
    only account of what the agent concluded and what it could see when it
    concluded it. So a dismissal is a FLAG, and this migration adds the three
    columns that hold it.

    WHY A FLAG AND NOT A ROW IN A DISMISSALS TABLE. The same argument
    _migrate_duty_loop makes about the spend counters: a fact a reader must be
    able to CHECK belongs on the row it is about. The Reports list is one SQL
    query with one WHERE clause; a second table would mean a join whose absence
    case is "not dismissed", which is a LEFT JOIN somebody eventually writes as
    an INNER one and silently hides every undismissed report.

    SEAL INTERACTION, and this is the reason the columns are separate rather
    than reusing read_at:
    
      * duty_report's seal excludes read_at/read_by, on the recorded argument
        that "a future 'mark this report read' would otherwise break the seal
        of every report anybody opened, and a tamper alarm that fires when a
        person reads a page teaches that person to ignore tamper alarms".
      * dismissed_at / dismissed_by / dismissal_note are the SAME argument with
        more force: a person clicking a button must not break a witness.
      * They are added to that exclusion list in core/integrity.SEALED_TABLES
        in this same change, and tests/test_integrity.py's own check
        ((sealed OR excluded) == every column) FAILS until they are, which is
        the mechanism working as designed.

    The dismissal is journalled separately as `report_dismissed`, an EVENT
    entry rather than a row witness (the same treatment incident_status_changed
    gets and for the same reason): the row legitimately changes after it is
    written, so a digest of it would cry wolf, while the TRANSITION -- who
    dismissed what, when, and why -- is exactly what a later reader needs.

    NOTHING IS BACKFILLED. Every existing report keeps NULL in all three,
    which reads as "nobody has dismissed this", which is true.

    Additive ALTERs, O(1) in SQLite. Schema.SQL carries the same three columns
    and the two are kept in step by hand.
    """
    added = 0
    if not _table_exists(conn, "duty_report"):
        return 0
    cols = _columns(conn, "duty_report")
    for name, ddl in (
        ("dismissed_at", "ALTER TABLE duty_report ADD COLUMN dismissed_at TIMESTAMP"),
        ("dismissed_by", "ALTER TABLE duty_report ADD COLUMN dismissed_by TEXT"),
        ("dismissal_note", "ALTER TABLE duty_report ADD COLUMN dismissal_note TEXT"),
    ):
        if name not in cols:
            conn.execute(ddl)
            added += 1
    if added:
        logger.info(
            "v51: duty_report gained dismissed_at, dismissed_by and "
            "dismissal_note. A dismissal is a FLAG ON THE ROW, never a "
            "DELETE: the report is the agent's own account of what it "
            "concluded and what it could see at the time, and that account is "
            "kept whether or not somebody has told the page to stop showing "
            "it. Existing rows keep NULL, which reads as 'nobody dismissed "
            "this'.")
    return added


def _migrate_port_owner(conn) -> int:
    """
    v51, 2026-09-25. WHICH PROCESS OWNS WHICH PORT ON THIS HOST.

    The owner's instruction: the agent has to be able to say which port relates
    to which process, Python has to sweep it on a set interval, and the agent
    has to be able to drive a pass itself when it wakes to write a report.

    THE THREE TABLES AND WHY THREE. The design is argued in full at the top of
    tools/port_owner.py; the schema half of the argument is here.

      port_owner_sweep   ONE ROW PER PASS. The heartbeat and the coverage
                         counts. This is what answers "is the sweep running",
                         which is a different question from "what is
                         listening" and must stay different: an empty listener
                         list with a healthy sweep is a machine with nothing
                         open, and an empty listener list with NO sweep rows is
                         a feature that never ran.
      port_owner_socket   ONE ROW PER LISTENER IDENTITY, carrying first_seen,
                         last_seen, seen_count and active. Bounded by
                         construction and it is the reason a five-minute sweep
                         does not write 8,640 rows a day: an ordinary desktop
                         has a few dozen listeners and a row is only INSERTED
                         when one appears.
      port_owner_change   ONE ROW PER TRANSITION -- appeared, disappeared,
                         owner_changed, bind_changed. A quiet machine writes
                         nothing here, and a report reads this table rather
                         than scanning the socket table for something to say.

    ONLY LISTENERS ARE TRACKED. Established sockets churn by the second (a
    browser opening one tab moves several) and tracking them would recreate the
    packets-table growth problem in a second table. The sweep row still counts
    them, because "400 connections and 29 listeners" is a different machine
    from "29 and 29".

    WHY ITS OWN TABLES AND NOT user_preferences, for the fourth time in this
    tree (see references/new-sensor-wiring.md, which has now paid for this
    lesson four times): anything a timer writes -- cursors, baselines, offsets,
    a per-pass result -- makes integrity.snapshot_config journal a false "the
    policy has CHANGED" warning on every legitimate sweep. A table that is not
    user_preferences cannot be confused for policy by anything.

    NOTHING IS BACKFILLED, and nothing here is possible to backfill: the
    kernel's socket table is a live thing, gone the moment a socket closes, so
    there is no honest reconstruction of who was listening before this shipped.

    Kept in sync with Schema.SQL by hand; see the comment there.
    """
    added = 0
    if not _table_exists(conn, "port_owner_sweep"):
        conn.execute("""
            CREATE TABLE port_owner_sweep (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id              TEXT NOT NULL,
                taken_at                TIMESTAMP NOT NULL,

                sockets                 INTEGER NOT NULL DEFAULT 0,
                listeners               INTEGER NOT NULL DEFAULT 0,
                established             INTEGER NOT NULL DEFAULT 0,

                -- THE FOUR NUMBERS THAT MAKE AN EMPTY LIST READABLE. See
                -- tools/port_owner.py's header: measured on this host, 9 of
                -- 29 listening sockets could be attributed unelevated. A
                -- reader who sees only `listeners` cannot tell a machine with
                -- nothing open from a run that could not read half the
                -- sockets, so the split travels on every sweep row.
                listeners_with_owner    INTEGER NOT NULL DEFAULT 0,
                listeners_unreadable    INTEGER NOT NULL DEFAULT 0,
                listeners_no_holder     INTEGER NOT NULL DEFAULT 0,
                all_interface_listeners INTEGER NOT NULL DEFAULT 0,

                processes_denied        INTEGER NOT NULL DEFAULT 0,
                duration_ms             INTEGER,

                -- The coverage sentence, rendered once by
                -- port_owner.coverage_sentence so that the boot log, the tool
                -- payload and the report block cannot describe one run three
                -- ways. Stored rather than recomputed because the counts it
                -- describes are THIS row's.
                note                    TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_port_owner_sweep_at "
                     "ON port_owner_sweep(taken_at)")
        added += 1

    if not _table_exists(conn, "port_owner_socket"):
        conn.execute("""
            CREATE TABLE port_owner_socket (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,

                -- The identity of a listener, which is deliberately NOT the
                -- socket inode: the inode changes every time the socket is
                -- recreated whereas pid+exe+bind is what a person means by
                -- "the same listener". The inode is carried anyway so a
                -- recreated socket under an unchanged process is visible.
                proto           TEXT NOT NULL,
                scope           TEXT NOT NULL
                                CHECK(scope IN ('listen','established')),
                local_address   TEXT NOT NULL,
                local_port      INTEGER NOT NULL,
                remote_address  TEXT,
                remote_port     INTEGER,

                pid             INTEGER,
                -- comm is 15 bytes the PROCESS chose for itself; exe is the
                -- kernel's answer. Both are stored, and the report says which
                -- is which, because this tree already has one register entry
                -- (LNX-3003's family) whose whole paragraph is about that
                -- difference.
                comm            TEXT,
                exe             TEXT,

                -- identified | unreadable_as_user | no_holder_found.
                -- THREE facts, never two: see the module header.
                owner_status    TEXT NOT NULL,
                inode           TEXT,

                first_seen_at   TIMESTAMP NOT NULL,
                last_seen_at    TIMESTAMP NOT NULL,
                seen_count      INTEGER NOT NULL DEFAULT 1,
                active          INTEGER NOT NULL DEFAULT 1
            )
        """)
        # A listener is identified by this tuple, and the sweep looks every
        # live socket up by it once per pass, so it is indexed exactly.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_port_owner_identity "
                     "ON port_owner_socket(proto, scope, local_address, "
                     "local_port, pid)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_port_owner_active "
                     "ON port_owner_socket(active, scope, local_port)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS "
                     "idx_port_owner_unique "
                     "ON port_owner_socket(proto, scope, local_address, "
                     "local_port, COALESCE(pid, -1), COALESCE(exe, ''), "
                     "COALESCE(remote_address, ''), "
                     "COALESCE(remote_port, 0))")
        added += 1

    if not _table_exists(conn, "port_owner_change"):
        conn.execute("""
            CREATE TABLE port_owner_change (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                sweep_id        INTEGER REFERENCES port_owner_sweep(id),
                detected_at     TIMESTAMP NOT NULL,

                -- appeared | disappeared | owner_changed | bind_changed.
                -- owner_changed and bind_changed are computed on the PORT
                -- rather than on the row identity, because identity IS pid+exe
                -- and a service restart would otherwise be reported as an
                -- arrival plus a departure every single time.
                kind            TEXT NOT NULL
                                CHECK(kind IN ('appeared','disappeared',
                                               'owner_changed','bind_changed')),

                proto           TEXT,
                scope           TEXT,
                local_address   TEXT,
                local_port      INTEGER,
                pid             INTEGER,
                comm            TEXT,
                exe             TEXT,

                -- The row as it stood BEFORE, for the two change kinds where
                -- "before" is the interesting half (owner_changed,
                -- bind_changed). NULL on an appearance, which is honest: there
                -- was nothing there.
                previous_json   TEXT,

                note            TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_port_owner_change_at "
                     "ON port_owner_change(detected_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_port_owner_change_kind "
                     "ON port_owner_change(kind, detected_at)")
        added += 1

    if added:
        logger.info(
            "v51: port_owner_sweep / port_owner_socket / port_owner_change "
            "created. This is the table set that answers 'which process owns "
            "which port' on this host, swept on a timer and on demand. Nothing "
            "is backfilled: the kernel's socket table is live-only, so there is "
            "no honest reconstruction of who was listening before this "
            "shipped.")
    return added


def _migrate_agent_runs(conn) -> int:
    """
    v37, 2026-09-17, TODO 116. The Windows agent driver's own record.

    PORTED TO LINUX 2026-09-21, AND THESE THREE ARE DORMANT HERE. The owner's
    instruction for this pass was to take everything in the Windows Schema.SQL
    that is possible to port, so they are created. Nothing in this tree writes
    to them: this tree's agentic record is T2/T3/T4, which is `incident`,
    `watcher_run`, `action_request`, `duty_run` and `duty_report`, and THAT is
    the design wired into main.py, the routes, the UI and the verification
    scripts. At the time of this port those tables held live data on this
    machine (575 watcher_run rows, 99 duty_run rows, 11 incidents, 7 duty
    reports) while these three are empty.

    So an empty agent_run here means "the Windows driver is not running",
    NOT "nothing has ever run". Anyone reading these tables has to know that,
    which is why it is written here and in the Schema.SQL block rather than
    left to be inferred from a row count.

    They are ported anyway, and the reason is that the fork is decision C2 and
    it is not a schema port's to close. If the owner ever chooses the Windows
    design, these tables exist and that port is a code job; if these did not
    exist, it would be a schema change under a live database first. Three
    empty tables cost a few kilobytes and close nothing.

    THE NAMING COLLISION WORTH KNOWING ABOUT. This tree's `action_request` (T3)
    and Windows's `agent_action_request` are NOT the same table under two
    names. They are two designs of one idea and neither is a subset of the
    other. This tree's carries evidence_fingerprint, evidence_json,
    incident_id, claim_at, claimed_by and outcome; the Windows one carries
    run_id, tool_name, reasoning, effect_note and decision_reason. Both are
    kept. Merging them would mean choosing whose columns survive, which is
    C2 again.

    Three tables, created together because they are one mechanism: a wake up,
    the steps inside it, and the actions that stopped to ask the owner first.

    NOTHING IS BACKFILLED and there is nothing that could be. Before this
    version the app never acted on its own, so there are no historical runs to
    reconstruct. An empty table here means exactly what it says.

    The CHECK constraints are written as full lists rather than left open. The
    v32 lesson applies: `x IN (a,b,NULL)` enforces nothing at all, because
    `x IN (NULL)` is NULL and a CHECK passes on NULL. Every nullable column
    here that carries a vocabulary spells it out as `IS NULL OR IN (...)`.
    """
    added = 0

    if not _table_exists(conn, "agent_run"):
        conn.execute("""
            CREATE TABLE agent_run (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id    TEXT NOT NULL,
                started_at    TIMESTAMP NOT NULL,
                finished_at   TIMESTAMP,
                trigger       TEXT NOT NULL
                              CHECK(trigger IN ('scheduled','critical_finding',
                                                'manual')),
                trigger_detail TEXT,
                job_id        TEXT,
                pillar        TEXT CHECK(pillar IS NULL OR
                                         pillar IN ('C','I','A')),
                entity_type   TEXT,
                entity_value  TEXT,
                pick_reason   TEXT,
                rounds_used   INTEGER NOT NULL DEFAULT 0,
                outcome       TEXT CHECK(outcome IS NULL OR outcome IN
                              ('concluded','asked_operator','parked_action',
                               'nothing_due','no_pick','rounds_exhausted',
                               'error')),
                summary       TEXT,
                error         TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_run_time "
                     "ON agent_run(started_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_run_trigger "
                     "ON agent_run(trigger, started_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_run_job "
                     "ON agent_run(job_id, started_at)")
        added += 1

    # The action table is created BEFORE the step table, because agent_step
    # carries a foreign key into it. SQLite does not enforce that ordering at
    # create time, but a reader of this function should not have to know that.
    if not _table_exists(conn, "agent_action_request"):
        conn.execute("""
            CREATE TABLE agent_action_request (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id        INTEGER REFERENCES agent_run(id),
                session_id    TEXT NOT NULL,
                requested_at  TIMESTAMP NOT NULL,
                tool_name     TEXT NOT NULL,
                params_json   TEXT NOT NULL,
                reasoning     TEXT NOT NULL,
                effect_note   TEXT,
                state         TEXT NOT NULL DEFAULT 'pending'
                              CHECK(state IN ('pending','approved','rejected',
                                              'executed','failed','expired')),
                decided_at    TIMESTAMP,
                decided_by    TEXT,
                decision_reason TEXT,
                executed_at   TIMESTAMP,
                result_json   TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_action_state "
                     "ON agent_action_request(state, requested_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_action_run "
                     "ON agent_action_request(run_id)")
        added += 1

    if not _table_exists(conn, "agent_step"):
        conn.execute("""
            CREATE TABLE agent_step (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id        INTEGER NOT NULL REFERENCES agent_run(id),
                step_no       INTEGER NOT NULL,
                happened_at   TIMESTAMP NOT NULL,
                kind          TEXT NOT NULL
                              CHECK(kind IN ('model','tool','gate','refusal')),
                tool_name     TEXT,
                params_json   TEXT,
                result_brief  TEXT,
                error         TEXT,
                action_request_id INTEGER REFERENCES agent_action_request(id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_step_run "
                     "ON agent_step(run_id, step_no)")
        added += 1

    if added:
        logger.info(
            "v41: agent_run / agent_action_request / agent_step created. They "
            "are DORMANT on this tree: Windows's agent driver is not ported and "
            "this tree's agentic record is T2/T3/T4. Nothing writes to them."
        )
    return added


def _migrate_local_integrity_store(conn) -> int:
    """
    v42. A TABLE OF ITS OWN FOR THE LOCAL INTEGRITY BASELINES, and the reason
    is a defect this project already paid for once.

    THE FIRST VERSION PUT THEM IN user_preferences, and it worked: the keys
    were written, the comparisons ran, the findings were raised. What it also
    did was make every one of those writes a POLICY CHANGE, because
    core/integrity.snapshot_config hashes that whole table and journals a
    config_observed entry on any difference, on the contract that such an
    entry ALWAYS MEANS THE RULES CHANGED.

    MEASURED IN THE BOOT LOG before this migration existed: the local
    integrity baselines landed in the shutdown snapshot and produced a
    "the policy in user_preferences has CHANGED" WARNING carrying six JSON
    blobs of sudoers, pam and systemd file hashes. The sensor writes those on
    every pass that finds a change, so the false warning would have appeared
    every time a file legitimately moved. That is exactly the T2 cursor bug
    reappearing with a different variable, and core/migrations already carries
    the cleanup for that one.

    WHY A TABLE RATHER THAN A PREFIX EXCLUDED FROM THE HASH. Excluding a key
    pattern from CONFIG_TABLE would make "the policy" mean "user_preferences
    except the ones starting with local_integrity", which is a rule living in
    a string comparison. The next person to add a prefix would have to know to
    extend it, and the integrity journal is the last place that should depend
    on somebody remembering. A table that is not user_preferences cannot be
    confused for policy by anything.

    The old keys are DELETED here rather than left, for the reason the
    watcher-cursor migration already gives: leaving them would leave the
    tamper journal telling a story about a sensor's bookkeeping.

    Nothing is backfilled. A baseline is a record of what a file looked like
    at a moment, and the row this table is missing is a moment that has passed.
    The sensor reseeds from the live filesystem on the next pass and raises
    nothing for it, which is the same first-look behaviour it has on a fresh
    install.
    """
    added = 0

    if not _table_exists(conn, "local_integrity_baseline"):
        conn.execute("""
            CREATE TABLE local_integrity_baseline (
                name        TEXT PRIMARY KEY,
                value_json  TEXT NOT NULL,
                recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        added += 1

    cur = conn.execute(
        "DELETE FROM user_preferences WHERE key LIKE 'local_integrity:%'")
    if cur.rowcount:
        logger.info(
            f"Removed {cur.rowcount} local_integrity preference key(s). They "
            f"were a sensor's baselines sitting in the table core/integrity "
            f"hashes as THE POLICY, so every rewrite of one journalled a "
            f"false 'the rules changed' warning. They live in "
            f"local_integrity_baseline now.")
        added += 1

    if added:
        logger.info(
            "v42: local_integrity_baseline created. This is the first step "
            "in the port that watches THIS host's own files; its baselines "
            "must not be mistaken for policy by the integrity journal.")
    return added


def _migrate_ebpf_camera_cursor(conn) -> int:
    """
    v44, 2026-09-22. THE KERNEL CAMERA'S CURSOR, in the app's own database.

    T6. ebpf/ebpf_monitor.py runs as root, attaches sched_process_exec and
    sys_enter_connect, and writes a SIDECAR file. tools/ebpf_events.py reads
    that file as the operator. This table is the reader's bookmark: it is how
    the app remembers which exec events it has already decided about, so a
    finding is raised once rather than every poll.

    WHY THE CURSOR LIVES HERE AND NOT IN THE CAMERA'S FILE. The camera's file
    belongs to a process running as root, and the reader must never write to
    it: that one-way street is the security property of the whole design (see
    ebpf/ebpf_monitor.py's header). A bookmark the reader writes into the
    writer's file would be exactly the coupling the sidecar exists to avoid.

    A TABLE OF ITS OWN, NOT user_preferences, for the reason the last two
    migrations both document at length: `user_preferences` IS the policy, and
    core/integrity.snapshot_config digests it and journals a `config_observed`
    entry on ANY difference, on the contract that such an entry always means
    the rules changed. A sensor that moves a bookmark on every poll would write
    a false "the policy has CHANGED" warning into the tamper journal every
    fifteen seconds -- in the one record whose whole value is that it never
    cries wolf. This table cannot be mistaken for policy by anything, which is
    the entire point of moving it out.

    `seeded_at` IS NULLABLE AND THE NULL MEANS SOMETHING. NULL is "this camera
    file has never been analysed", which is the state that must NOT raise
    findings from a file already holding a week of history. An empty cursor at
    zero is a different state from a cursor that has never been written, and
    conflating them makes the first real pass look like a change.

    NOTHING IS BACKFILLED, and unlike most migrations here nothing COULD be: a
    bookmark is a record of what has been read, and no earlier run read
    anything. The first pass seeds.

    `last_connect_id` IS ADDED BY _migrate_ebpf_cursor_connect_id (v49) and is
    NOT created here, so that a v43 database still lands on exactly the shape
    this migration always produced before walking forward through the chain.
    """
    if _table_exists(conn, "ebpf_camera_cursor"):
        return 0
    conn.execute("""
        CREATE TABLE ebpf_camera_cursor (
            name            TEXT PRIMARY KEY,
            last_event_id   INTEGER NOT NULL DEFAULT 0,
            last_event_at   TIMESTAMP,
            last_connect_ns INTEGER NOT NULL DEFAULT 0,
            seeded_at       TIMESTAMP,
            passes          INTEGER NOT NULL DEFAULT 0
        )
    """)
    return 1


def _migrate_ebpf_cursor_connect_id(conn) -> int:
    """
    v49, 2026-09-23. THE CONNECT WINDOW'S OWN MARK.

    E-4, bugfinder.md, measured on this host against the shipped code. The
    connect read was bounded by `ts_ns >= floor`, and ts_ns is the KERNEL's
    monotonic clock (bpf_ktime_get_ns, counting from boot) while the cursor is
    written from what this app has already CONSIDERED. A connect row with the
    next id and a timestamp one nanosecond below the stored watermark was
    therefore filtered out by the timestamp clause alone -- and skipped
    forever, silently, because it is not re-read on the next pass either.

    MEASURED: the row was present in the camera's file (id 4, daddr
    203.0.113.11, ts one ns below the watermark) and `analysed.connect` showed
    three rows read with no finding for it. That is a connection to a
    dangerous port that the sensor can never report.

    The id is the one mark in that table that is monotonic BY CONSTRUCTION --
    it is the camera's own AUTOINCREMENT -- so it is the one this app can keep
    across a reboot, a WAL checkpoint or a writer that is faster than the poll.
    The read is `ts_ns >= ? OR id > ?`: either bound is enough.

    DEFAULT 0 AND NOT NULL, so an existing cursor reads as "no connects seen
    by id yet" and the timestamp bound does all the work exactly as it did
    before this column existed. Nothing is backfilled, and nothing can be: the
    app has no record of which ids it read before there was a column for it,
    and inventing one would be inventing a claim about what was analysed.
    """
    if not _table_exists(conn, "ebpf_camera_cursor"):
        return 0
    have = {r[1] for r in conn.execute("PRAGMA table_info(ebpf_camera_cursor)")}
    if "last_connect_id" in have:
        return 0
    conn.execute("ALTER TABLE ebpf_camera_cursor ADD COLUMN "
                 "last_connect_id INTEGER NOT NULL DEFAULT 0")
    return 1


def _migrate_auditd_cursor(conn) -> int:
    """
    v45, 2026-09-22. THE AUDIT LOG'S CURSOR, in the app's own database.

    L4. tools/auditd_monitor.py reads the kernel's audit log and this table is
    its bookmark: a byte offset into the file, so a pass reads only what has
    arrived since the last one.

    A TABLE OF ITS OWN, NOT user_preferences, for the reason the previous
    three migrations all document at length and this one will not repeat beyond
    naming it: `user_preferences` IS the policy, core/integrity.snapshot_config
    digests it, and it journals a `config_observed` entry on ANY difference on
    the contract that such an entry always means the rules changed. A bookmark
    that moves every fifteen seconds would write a false "the policy has
    CHANGED" warning into the tamper journal forever.

    THIS TABLE IS CREATED EVEN ON A HOST WHERE AUDITD IS NOT INSTALLED, and
    that is deliberate rather than lazy. The module's cursor table is part of
    the schema so that a machine which installs auditd later -- by running the
    one command this app prints -- does not ALSO need a migration before the
    reader works. The alternative is a sensor that reports itself broken on the
    day its source appears, which is the worst possible day for it.

    `seeded_at` IS NULLABLE AND THE NULL MEANS SOMETHING: "the log has never
    been read". That is the state in which nothing may be raised from a file
    already holding a week of history. An offset of zero is a different state
    from a cursor that has never been written.
    """
    if _table_exists(conn, "auditd_cursor"):
        return 0
    conn.execute("""
        CREATE TABLE auditd_cursor (
            name            TEXT PRIMARY KEY,
            last_offset     INTEGER NOT NULL DEFAULT 0,
            last_record_at  TIMESTAMP,
            seeded_at       TIMESTAMP,
            passes          INTEGER NOT NULL DEFAULT 0,
            records_seen    INTEGER NOT NULL DEFAULT 0
        )
    """)
    return 1


def _migrate_feed_cursor(conn) -> int:
    """
    v46, 2026-09-23. THE FEED MATCHER'S BOOKMARK, moved out of the policy table.

    MISP AND OTX came with this move rather than after it, because building two
    new feeds on top of a known defect would have meant writing the false
    tamper-journal warning twice more per refresh.

    THE DEFECT, MEASURED BEFORE IT WAS FIXED. tools/feed_matcher kept four keys
    in `user_preferences`: three match cursors and the last-refresh time.
    core/integrity.snapshot_config digests that table as THE POLICY and
    journals a `config_observed` entry on any difference, on the contract that
    such an entry ALWAYS means the rules changed. Measured on a copy of the
    live database: writing one cursor moved the digest and produced a
    config_observed row whose payload carried
    `'feed_match_cursor_packets': '123456789'`. match_once advances three
    cursors every pass -- every five minutes by default -- so this was four
    false "the policy has CHANGED" warnings an hour, in the journal whose whole
    value is that it does not cry wolf.

    The live database held 9 config_observed rows when this was written and
    every one of them named a real event (boot, retention setup, rollup). The
    false entries would have been the only ones in there that meant nothing.

    THE OLD KEYS ARE DELETED rather than left, for the reason the v42 migration
    gives: leaving them leaves the tamper journal telling a story about a
    sensor's bookkeeping, and a database where the false warning persists until
    something else happens to touch the table.

    THE VALUES ARE NOT CARRIED ACROSS, and that is safe rather than lossy. A
    missing cursor is a state this module already handles deliberately: the
    next pass SEEDS from the current end of each table and says so, rather than
    scanning history. Carrying a cursor across would be the more fragile
    option, since the old value would have to be trusted to mean the same thing
    in a table with a different shape.
    """
    added = 0

    if not _table_exists(conn, "feed_cursor"):
        conn.execute("""
            CREATE TABLE feed_cursor (
                name        TEXT PRIMARY KEY,
                value       TEXT,
                updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        added += 1

    cur = conn.execute(
        "DELETE FROM user_preferences WHERE key LIKE 'feed_match_cursor%' "
        "OR key IN ('feed_last_refresh_at', 'feed_last_result')")
    if cur.rowcount:
        logger.info(
            f"Removed {cur.rowcount} feed matcher preference key(s). They were "
            f"a sensor's BOOKMARKS sitting in the table core/integrity hashes "
            f"as THE POLICY, so every pass (every five minutes) journalled a "
            f"false 'the rules changed' warning into the tamper journal. They "
            f"live in feed_cursor now.")
        added += 1

    if added:
        logger.info(
            "v46: feed_cursor created. MISP and OTX join the feed matcher in "
            "the same step, and their bookmarks land here rather than in the "
            "policy table.")
    return added


def _migrate_auditd_cursor_inode(conn) -> int:
    """
    v48, 2026-09-23. THE AUDIT CURSOR GAINS THE FILE'S IDENTITY (last_inode).

    A byte offset alone cannot tell "the same file, grown" from "a DIFFERENT
    file that is already past that byte" -- and auditd rotates by RENAMING
    audit.log to audit.log.1 and starting a fresh one, so the second case is
    the ordinary case rather than the exotic one.

    MEASURED, on the shipped reader before this column existed: a rotated log
    that had already grown past the stored offset produced 20 records,
    rotated=False, no note anywhere, with the first 940 bytes of the new file
    skipped and everything moved into audit.log.1 never read. The size test
    (offset > size) is true only until the new file outgrows the old offset,
    which on a busy host is seconds.

    THE COLUMN IS NULLABLE AND THE EXISTING ROW IS NOT BACKFILLED, because it
    cannot be: the cursor's own row does not know which file it was written
    against, and inventing the current log's inode would tell the next pass
    that a rotation had ALREADY been accounted for when it had not. NULL means
    "size test only", which is exactly the behaviour that shipped, so a live
    install keeps working and gains the second test on its next cursor write.
    """
    if not _table_exists(conn, "auditd_cursor"):
        # The v45 migration owns the table. Created fresh by v45 on this run.
        return 0
    if "last_inode" in _columns(conn, "auditd_cursor"):
        return 0
    conn.execute("ALTER TABLE auditd_cursor ADD COLUMN last_inode INTEGER")
    logger.info(
        "v48: auditd_cursor.last_inode added. A byte offset cannot tell a "
        "rotated log from a grown one, and rotation by rename is how auditd "
        "rotates; existing rows keep NULL, which means the size test alone "
        "until the next pass writes the inode.")
    return 1


def _migrate_case_memory(conn) -> int:
    """
    v43, 2026-09-22. CASE MEMORY: the patient file.

    The owner's words are the specification: "the agent writes an assessment
    for every incident and never reads the old ones. Every alert is
    investigated from a blank page. A doctor with no patient file." Verified in
    the source before this was built -- no embedding, no vector search and no
    precedent retrieval anywhere in the tree.

    TWO OBJECTS, AND THEY ARE ONE THING:

      case_index   the authority. One row per indexed incident, carrying the
                   content hash the index was built from, the disposition at
                   the time of indexing, and the mirror columns a ranked result
                   needs so it can be read without a join per field.
      case_fts     a STANDALONE FTS5 table, rowid = incident id, holding the
                   searchable text: subject, title, assessment, rule id and a
                   composed disposition line.

    WHY STANDALONE AND NOT content=/contentless WITH TRIGGERS, which is the
    obvious design and the one that was written first. MEASURED, and it is the
    reason for this shape: FTS5's own `integrity-check` command PASSES on a
    desynchronised external-content index. A row deleted from `incident`
    without the delete trigger firing leaves the index serving a phantom, and
    no check reports it -- the index looks verified and is wrong. In a tree
    whose whole discipline is "a check that cannot fail is worse than no
    check", shipping that would have been the defect rather than the feature.

    So the index is written by core/case_memory and BY NOTHING ELSE, and the
    distance between it and the ledger is COMPUTED AND REPORTED on every read
    (case_memory.index_lag). A number that can be wrong in a way a reader can
    see is worth more than a trigger that is right until it is not.

    NOTHING IS BACKFILLED HERE. The rows are written by index_pending on the
    watcher's tick. A migration that reached into the incident table would be a
    second writer with a different notion of what needs indexing, and the
    first pass of a new index over a year of incidents is exactly the pass
    whose cost should be measurable rather than part of a boot.

    A NOTE ON user_preferences, since the last two migrations both have one:
    nothing here touches it. The index tables are not policy and are not
    bookkeeping a reader would confuse for policy. `case_index.content_hash`
    changes every time an incident's assessment is rewritten, which is a fact
    about the index, and it lives where it can only be read as one.
    """
    added = 0

    if not _table_exists(conn, "case_index"):
        conn.execute("""
            CREATE TABLE case_index (
                incident_id   INTEGER PRIMARY KEY,
                indexed_at    TIMESTAMP NOT NULL,
                content_hash  TEXT NOT NULL,
                detection_id  TEXT NOT NULL DEFAULT '',
                entity_type   TEXT NOT NULL DEFAULT '',
                entity_value  TEXT NOT NULL DEFAULT '',
                severity      TEXT NOT NULL DEFAULT '',
                severity_rank INTEGER NOT NULL DEFAULT 0,
                cia_json      TEXT NOT NULL DEFAULT '[]',
                source        TEXT NOT NULL DEFAULT '',
                status        TEXT NOT NULL DEFAULT '',
                status_by     TEXT NOT NULL DEFAULT '',
                assessed      INTEGER NOT NULL DEFAULT 0,
                first_seen_at TIMESTAMP,
                last_seen_at  TIMESTAMP
            )
        """)
        added += 1

    # Whether FTS5 exists is a property of the SQLite this Python links
    # against, NOT of this database, and it cannot be known here. A build
    # without FTS5 must still migrate: the entity-history half of case memory
    # works on any SQLite, and refusing to migrate would take that down too.
    # The absence is reported by case_memory.fts_available() on every read.
    fts_error = None
    try:
        if not _table_exists(conn, "case_fts"):
            conn.execute("""
                CREATE VIRTUAL TABLE case_fts USING fts5(
                    subject, title, assessment, detection_id, verdict,
                    tokenize='porter unicode61'
                )
            """)
            added += 1
    except Exception as e:                              # noqa: BLE001
        fts_error = f"{type(e).__name__}: {e}"

    conn.execute("CREATE INDEX IF NOT EXISTS idx_case_index_rule "
                 "ON case_index(detection_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_case_index_entity "
                 "ON case_index(entity_type, entity_value)")

    if fts_error:
        logger.warning(
            f"v43: case_index created but case_fts COULD NOT BE, because this "
            f"install's SQLite has no usable FTS5 ({fts_error}). Entity "
            f"history still works; PRECEDENT SEARCH DOES NOT, and every answer "
            f"from it will say so rather than returning an empty list.")
    elif added:
        logger.info(
            "v43: case memory created (case_index + case_fts). Precedent "
            "search is available on this install; the index is built by the "
            "watcher's tick and its lag is reported on every read.")
    return added


def _migrate_operator_stated(conn) -> int:
    """
    v32. The fourth basis value. THERE IS NOTHING TO DO HERE, and that is the
    finding rather than the absence of one.

    v26 added `basis` with ALTER TABLE ADD COLUMN, and SQLite cannot attach a
    CHECK that way. So an existing database has NO constraint on that column
    at all, while a database created fresh from Schema.SQL has one listing
    three values. That divergence has been there since v26 and was harmless
    for as long as nobody added a value: the two shapes accepted the same
    three because nothing ever tried a fourth.

    Adding operator_stated is what would have made it bite. It would have
    been written happily on this machine and REJECTED on a fresh install, and
    the failure would have shown up on somebody else's first run rather than
    on ours, which is the worst place to find it.

    So the Schema.SQL CHECK now lists four, and the real gate for both shapes
    stays where it already was: memory_engine.VALID_OBSERVATION_BASIS, which
    every writer passes through. This function exists to make the reasoning
    findable, and to stop the next person rebuilding a table with hundreds of
    thousands of rows to police four strings. See _migrate_resolved_by, which
    made the same call for the same reason.
    """
    return 0


def _migrate_always_on(conn) -> int:
    """
    v22. One column, and it corrects a claim rather than adding a feature.

    is_permanent was carrying two declarations at once. The user set it to say
    "this device belongs on this network". The absence check read it as "this
    device should always be answering" and raised a medium finding every time
    a permanent device went quiet.

    Those are not the same statement, and the owner said so plainly: a TV, a
    console, a VM sit dark for days because nobody is using them. Under the old
    reading, vouching for a device silently also signed it up to stay awake.

    DEFAULTS TO 0, INCLUDING FOR DEVICES ALREADY MARKED PERMANENT. Backfilling
    it to 1 for existing permanent devices would preserve exactly the wrong
    behaviour and call it a migration. Nobody has declared availability yet
    because there was no way to, so the honest starting state is that nobody
    has.

    The consequence is stated out loud rather than discovered: until somebody
    declares a device always-on, the absence finding raises nothing. That is a
    real reduction in what the tool says, and network_scanner logs it on every
    pass so the silence can never be mistaken for "everything is present".

    Python does NOT guess here, not even for the gateway, which it could
    identify perfectly well. An expectation the user did not state is not an
    expectation, and inventing one is the failure this whole rule exists to
    prevent.
    """
    if "expected_always_on" in _columns(conn, "known_devices"):
        return 0
    conn.execute("ALTER TABLE known_devices "
                 "ADD COLUMN expected_always_on INTEGER DEFAULT 0")
    logger.warning(
        "v22: expected_always_on added, defaulting to 0 for every device. "
        "Absence findings now require that flag and will raise NOTHING until "
        "a device is declared always-on. Run scripts/set_always_on.py to "
        "declare one.")
    return 1


def _migrate_device_reacknowledge(conn) -> int:
    """
    v50, 2026-09-24. Two columns so a device that comes back can be un-retired.

    THE DEFECT. v15 added `retired_at` / `retired_reason` so a permanent device
    that has genuinely gone stops reporting missing forever. Nothing ever
    added the OTHER direction: `retire_device` was the only writer of that
    column in the whole tree, no function cleared it, and three readers filter
    it out —

        probe._retire_permanent    iterates permanent_devices(), retired_at IS NULL
        always_on_devices()        same filter, so no absence can be raised
        the scanner's is_new test  "no row for this IP", still False

    — so a device that left and came back was in the inventory, watched by
    nothing, on a row that says it is gone. Measured before the fix on a
    throwaway store: the device answers again, ZERO findings, `retired_at`
    unchanged.

    WHY COLUMNS AND NOT JUST A CLEAR. The obvious fix is to NULL the column,
    and that deletes the evidence that the device ever went away — which is
    exactly the record a reader needs after it comes back twice. So the
    retirement is LIFTED and the fact of it is MOVED here, and the row's own
    notes carry a sentence naming both times.

    Default 0 / NULL for existing rows, which is the honest state: nothing has
    been un-retired yet because there was no way to.
    """
    added = 0
    existing = _columns(conn, "known_devices")
    for column, ddl in (("unretired_at", "TIMESTAMP"),
                        ("unretired_reason", "TEXT")):
        if column not in existing:
            conn.execute(f"ALTER TABLE known_devices ADD COLUMN {column} {ddl}")
            added += 1
    if added:
        logger.info(
            "v50: unretired_at / unretired_reason added. A retired device that "
            "is seen again can now be acknowledged "
            "(memory_engine.reacknowledge_device) instead of staying invisible "
            "to every rule that watches a device.")
    return added


def _migrate_scan_run(conn) -> int:
    """
    v23. One new table so a packet can be told apart from an echo of our own.

    THE BUG THIS ANSWERS, 2026-09-02. The model port scanned a device, then
    read the packet table, saw source port 27017 and 32400 going to ephemeral
    ports on this host, and told the owner the device was "actively probing
    THIS host's ports". Those are the scanned device answering with RST
    because the port is closed. It reported the reply leg of its own scan as
    unsolicited hostile activity, and did it while arguing with the owner
    about whether the device was safe.

    WHY A NEW TABLE AND NOT A COLUMN ON packets. Same argument as
    _migrate_packet_scope, and by now it is the house rule: CREATE TABLE and
    ADD COLUMN are metadata writes and cost the same at any size, anything
    that rewrites two million rows does not belong at boot. This also means
    every packet ALREADY on disk gets the flag, because it is computed at read
    time from the join rather than stamped at capture.

    WHY NOT REUSE port_scan_results. It only holds ports that were found OPEN.
    A scan that found nothing leaves no row at all, and a scan that found
    nothing is precisely the one that generated a thousand refused
    connections. The run is a different fact from what the run found.

    NOTHING IS BACKFILLED. Scans that ran before today were not recorded and
    no honest reconstruction exists: guessing at a scan window from traffic
    shape would mean marking real packets as self-induced, which is the
    dangerous direction of this particular error. Old packets simply come
    back with self_induced false, which is what "not recorded" looks like
    everywhere else in this project.
    """
    if _table_exists(conn, "port_scan_run"):
        return 0

    conn.execute("""
        CREATE TABLE port_scan_run (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      TEXT NOT NULL,
            target_host     TEXT NOT NULL,
            started_at      TIMESTAMP NOT NULL,
            finished_at     TIMESTAMP,
            port_count      INTEGER,
            port_set        TEXT,
            scan_origin     TEXT DEFAULT 'remote'
                            CHECK(scan_origin IN ('self','remote')),
            sensor_id       TEXT REFERENCES sensors(sensor_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_run_target "
                 "ON port_scan_run(target_host, started_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_run_time "
                 "ON port_scan_run(started_at)")

    logger.info("v23: port_scan_run added. Packets from before now cannot be "
                "marked self-induced, there is no honest way to reconstruct "
                "which scans caused them.")
    return 1


def _migrate_expected_ports(conn) -> int:
    """
    v24. One column so the owner can say "that port is fine" and be believed.

    WHY, 2026-09-02, and it came out of the owner being annoyed, which is the
    right reason. The owner identified a device, told the tool it was the owner's, and the
    open-port finding stayed at high anyway. Naming a device says nothing
    about which of its ports are normal, so the tool asked the owner about the same
    port three times running. A tool that keeps asking a question you already
    answered is one you stop reading. That is the unread review queue in 4A
    arriving by a different road.

    WHY NOT dismiss_entity. It is keyed on (entity_type, entity_value), so
    dismissing port 8888 silences 8888 on every device on this network. The
    thing being said here is much narrower: one port, one device.

    JSON in a column rather than a table, following expected_always_on in v22.
    A handful of ports on a handful of devices is not a join.

    NOTHING IS ASSUMED. Every device starts with no expected ports, so this
    changes no existing behaviour on the day it lands. Every entry has to be
    declared by hand, with a reason and a timestamp.
    """
    if not _table_exists(conn, "known_devices"):
        return 0
    if "expected_ports" in _columns(conn, "known_devices"):
        return 0
    conn.execute("ALTER TABLE known_devices ADD COLUMN expected_ports TEXT")
    logger.info("v24: expected_ports added. Empty for every device until "
                "somebody runs scripts/expect_port.py.")
    return 1


def _migrate_enrichment(conn) -> int:
    """
    v25. Two tables for tier 1 of the research worker. TODO section 35.

    WHY SEPARATE TABLES AND NOT COLUMNS ON known_devices. Because these rows
    are a different KIND of claim. Everything in known_devices, packets and
    presence_observation was measured on this network by this tool. An
    enrichment row is what a registry in another country said when we asked.
    Both are useful and they are not interchangeable, and the moment they
    share a table the model loses the ability to tell them apart, which is
    exactly the failure in TODO 37, where invented evidence read like observed
    evidence because nothing in the shape of the data said otherwise.

    So `record_type` comes back as external_intel on every read, the source
    URLs live on the row, and the fields are stored as JSON rather than as
    columns because each kind of indicator answers with different fields.

    WHY status IS A CHECK CONSTRAINT. resolved, partial and unresolved are the
    contract with the model, from 35.3. A fourth value appearing later would
    be a silent change to what the model has been told these rows mean, so the
    database refuses it rather than storing it.

    NOTHING IS BACKFILLED and nothing needs to be. Every existing address in
    the database is still lookupable; the rows appear the first time somebody
    asks about one.
    """
    if _table_exists(conn, "enrichment"):
        return 0

    conn.execute("""
        CREATE TABLE enrichment (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator    TEXT NOT NULL,
            kind         TEXT NOT NULL
                         CHECK(kind IN ('ip','domain','cve','mac','hash','process')),
            status       TEXT NOT NULL
                         CHECK(status IN ('resolved','partial','unresolved')),
            confidence   TEXT,
            fields_json  TEXT NOT NULL DEFAULT '{}',
            sources_json TEXT NOT NULL DEFAULT '[]',
            tried_json   TEXT NOT NULL DEFAULT '[]',
            gap          TEXT,
            session_id   TEXT,
            fetched_at   TIMESTAMP NOT NULL,
            -- Past this, the row is stale and the next question re-runs it.
            -- An unresolved row gets a deliberately short life, which is how
            -- 35.3's "requeue it later" happens without a scheduler.
            expires_at   TIMESTAMP NOT NULL,
            UNIQUE(indicator, kind)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_enrichment_kind "
                 "ON enrichment(kind, status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_enrichment_expiry "
                 "ON enrichment(expires_at)")

    conn.execute("""
        CREATE TABLE enrichment_queue (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator    TEXT NOT NULL,
            kind         TEXT NOT NULL,
            requested_by TEXT,
            reason       TEXT,
            session_id   TEXT,
            requested_at TIMESTAMP NOT NULL,
            started_at   TIMESTAMP,
            finished_at  TIMESTAMP,
            state        TEXT NOT NULL DEFAULT 'queued'
                         CHECK(state IN ('queued','running','done','failed')),
            attempts     INTEGER NOT NULL DEFAULT 0,
            note         TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_enrichment_queue_state "
                 "ON enrichment_queue(state, id)")

    logger.info("v25: enrichment + enrichment_queue added. Tier 1 only, "
                "keyless sources. No page fetching until item 3.1 lands.")
    return 1


def _migrate_observation_basis(conn) -> int:
    """
    v26. What KIND of thing is this baseline row.

    THE ARGUMENT, and the owner won half of it, which is why the column exists
    in this shape rather than as a ban.

    My first position was that enrichment facts should not be written into the
    baseline at all, because they are second-hand. The owner pushed back and the owner was
    right: a model that re-looks-up the same address every session is exactly
    the waste the enrichment engine was built to stop, and not logging is
    worse than logging. The record has to be here or it does not get used.

    What survives from my side is narrower and is only about WHICH COLUMN. An
    enrichment fact written as a bare baseline line loses everything that made
    it checkable. The enrichment row carries a TTL, source URLs and a status
    BECAUSE registration goes stale and reputation moves weekly. The baseline
    carries none of that and nothing re-checks it, so six months on "that
    address is a VPN exit" is a permanent measured fact with no source and no
    date.

    So: keep the fact, keep the source with it, and let it go stale.

    THE THIRD VALUE is the one I would defend hardest and it did not come from
    that argument at all. On the same afternoon the model investigated a
    router advertisement, concluded the packet recorder had a byte-order bug,
    and wrote that here. It is wrong, `src` comes straight out of scapy.
    Unmarked, the next session reads it as something this tool MEASURED,
    believes the recorder is broken, and TODO 9 quietly closes on a wrong
    answer. A measurement has packets behind it and a lookup has a URL behind
    it; a conclusion has nothing behind it but itself.

    NOTHING IS BACKFILLED and nothing can be. Every row already here was
    written before the question was asked, so it gets NULL, which reads as
    "unrecorded" and is never counted as measured. Guessing a basis for two
    thousand old rows would be inventing exactly the kind of unearned
    certainty this column exists to prevent.
    """
    cols = _columns(conn, "behavioral_session")
    if not cols or "basis" in cols:
        return 0

    conn.execute("ALTER TABLE behavioral_session ADD COLUMN basis TEXT")
    conn.execute("ALTER TABLE behavioral_session ADD COLUMN basis_ref TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_session_basis "
                 "ON behavioral_session(basis)")

    logger.info("v26: basis + basis_ref added to behavioral_session. Existing "
                "rows stay NULL, which reads as 'unrecorded' and is never "
                "counted as measured.")
    return 1


def _migrate_packet_process(conn) -> int:
    """
    v27. Which local process owns the socket a packet belongs to.

    WHY THIS IS TWO PLAIN COLUMNS. The whole point of attribution is to answer
    "what on this machine is talking to that address" without the model
    guessing. A name and a pid are what answer it, so that is all that goes on
    the row. No path here, the packets table is most of the database and a
    full path on every row is width we do not need to read the answer. If a
    path is ever wanted it is process_monitor's job, keyed by the pid we do
    store.

    ADD COLUMN, same as scope and basis. Cheap at any table size, and the CHECK
    problem does not arise because neither column is constrained.

    OLD ROWS STAY NULL and there is no backfill, because none is possible. The
    OS connection table that gives the owning pid is a live thing, gone the
    moment the socket closes, so a packet captured before this shipped can
    never be attributed after the fact. NULL reads as NOT ATTRIBUTED, which is
    the truth, and every reader already treats NULL that way. It must never be
    read as "no process was responsible".
    """
    if not _table_exists(conn, "packets"):
        return 0
    cols = _columns(conn, "packets")
    if "process_name" in cols:
        return 0
    conn.execute("ALTER TABLE packets ADD COLUMN process_name TEXT")
    conn.execute("ALTER TABLE packets ADD COLUMN process_pid INTEGER")
    logger.info("v27: process_name + process_pid added to packets. Existing "
                "rows stay NULL, which reads as 'not attributed', never as "
                "'no process'. No backfill is possible, the connection table "
                "is gone once a socket closes.")
    return 1


def _migrate_stale_baseline_claims(conn) -> dict:
    """
    v19. Two corrections to rows that are already in the database.

    1. model_notes carried a sentence restating sample_count and confidence.
       The v11 recount changed the columns and never touched the prose, so
       rows exist saying "Sessions observed: 12 -> confidence high" while the
       columns say 3 and low. The model READS model_notes. It has been
       reading a number that was corrected a week ago.

       The sentence is removed rather than rewritten. rollup_engine no longer
       writes it, so rewriting it would just re-create a copy that goes stale
       again the next time anything recounts.

    2. confidence itself. update_behavioral_baseline now caps a claimed
       confidence at what the measured sessions support, but rows written
       before that cap existed are still sitting above their evidence.
       77.111.246.33 was at 'medium' with zero recorded sessions.

    Suppression is deliberately NOT touched here. Dropping a confidence tier
    does not un-suppress anything: suppression was an affirmative decision by
    a user or a gated tool call, and quietly reversing a human's decision
    because a number moved is its own kind of wrong. v11 already un-suppressed
    the baselines that were silenced by the counting bug; these were not.
    """
    import re as _re

    out = {"notes_cleaned": 0, "confidence_lowered": 0}
    if not _table_exists(conn, "behavioral_baseline"):
        return out

    # 1. the stale sentence
    pattern = _re.compile(
        r"\s*Sessions observed:\s*\d+\s*->\s*confidence\s*\w+\.?", _re.I)
    for row in conn.execute(
            "SELECT id, model_notes FROM behavioral_baseline "
            "WHERE model_notes LIKE '%Sessions observed:%'").fetchall():
        cleaned = pattern.sub("", row[1] or "").strip()
        conn.execute("UPDATE behavioral_baseline SET model_notes=? WHERE id=?",
                     (cleaned or None, row[0]))
        out["notes_cleaned"] += 1

    # 2. confidence above what the sessions support
    try:
        from core.memory_engine import confidence_thresholds
        t = confidence_thresholds()
    except Exception:
        t = {"low": 2, "medium": 4, "high": 6}

    rank = {"low": 0, "medium": 1, "high": 2}
    for row in conn.execute(
            "SELECT id, entity_type, entity_value, behavior_key, "
            "       confidence, sample_count "
            "FROM behavioral_baseline").fetchall():
        measured = conn.execute(
            "SELECT COUNT(*) FROM baseline_session_seen "
            "WHERE entity_type=? AND entity_value=? AND behavior_key=?",
            (row[1], row[2], row[3])).fetchone()[0]
        if measured >= t["high"]:
            ceiling = "high"
        elif measured >= t["medium"]:
            ceiling = "medium"
        else:
            ceiling = "low"
        current = (row[4] or "low").lower()
        if rank.get(current, 0) > rank[ceiling]:
            conn.execute(
                "UPDATE behavioral_baseline SET confidence=? WHERE id=?",
                (ceiling, row[0]))
            out["confidence_lowered"] += 1
            logger.info(
                f"Migration v19: {row[1]}:{row[2]} [{row[3]}] "
                f"confidence {current} -> {ceiling} "
                f"({measured} sessions recorded).")

    return out


def _schema_path() -> Path:
    """Schema.SQL sits in the project root, beside main.py."""
    return Path(__file__).resolve().parent.parent / "Schema.SQL"


def _database_looks_real(db_path: Path) -> bool:
    """
    Does this file hold the application's tables?

    The question this answers is deliberately narrow: is there a database
    here at all. It does NOT ask whether the schema is current, which is
    run_migrations' job, and it does not read any table's contents. A single
    known table that has been present since v1 is enough.

    Written as a function because "does the file exist" was tried first and
    was wrong. An empty SQLite database is a real 4096 byte file: it opens,
    it answers PRAGMA, and it has no tables. Anything reading size or
    existence concludes "the database is here" about a file that cannot
    store a single finding.
    """
    if not db_path.exists():
        return False
    try:
        import sqlite3
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            return _table_exists(conn, "user_preferences")
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"Could not read {db_path} to check whether it is a "
                       f"database ({e}). Treating it as not one.")
        return False


def create_fresh_database(db_path: Path) -> dict:
    """
    Build a brand new database from Schema.SQL, then bring it to current.

    WHY THIS EXISTS, 2026-09-17. It did not, and that was the single reason
    the Linux port never came up. run_migrations() answered "no_db" for a
    file that does not exist and returned without creating anything, so
    every boot on a machine that had never run the app before came up
    against an empty 4 KB file: no user_preferences, no packets, no events,
    no findings, no rollup_log. main.py read that as a failure, the sensor
    threads logged "no such table" into a log nobody was reading, and the
    dashboard came up as a shell with an empty module list and a chat box
    that could not answer.

    The Windows install never hit this because its database was created
    once, by hand, months ago and has been migrated in place ever since.
    A fresh clone of the Linux port has no such history, which is exactly
    the case nobody had exercised.

    WHAT IT DELIBERATELY DOES NOT DO: it does not run Schema.SQL and stop.
    Schema.SQL is the v1 shape, and _get_version() reports 1 for it, while
    SCHEMA_VERSION is 34. Stopping there would leave 33 migrations worth of
    columns missing, and the failure would arrive later and further away,
    as a random "no such column" inside a sensor thread. So this creates the
    table set and then runs the real migration chain over it, which is the
    same code path an old database takes and therefore the path that is
    already exercised.

    Idempotent in the sense that matters: if the file already exists this
    refuses rather than overwriting. Schema.SQL is all CREATE TABLE IF NOT
    EXISTS, so a re-run against a live database would be harmless rather
    than destructive, but a function called create_fresh_database has no
    business running against a file that has evidence in it.
    """
    import sqlite3

    # A FILE THAT EXISTS IS NOT NECESSARILY A DATABASE. This checked
    # size > 0 first and that was not enough: the broken Linux install had a
    # 4096 byte agental_sec.db, which is SQLite's empty-page size, so it
    # passed a size check while holding no tables at all. The real question
    # is whether the table set is there.
    if _database_looks_real(db_path):
        return {"status": "exists", "version": None}

    schema_file = _schema_path()
    if not schema_file.exists():
        raise FileNotFoundError(
            f"Schema.SQL is missing from {schema_file.parent}. It is the "
            f"only definition of the table set and a database cannot be "
            f"built without it."
        )

    logger.info(f"No usable database at {db_path}, building one from Schema.SQL.")

    db_path.parent.mkdir(parents=True, exist_ok=True)

    # A 4 KB empty file sitting there is the normal shape of a failed first
    # boot, not evidence worth keeping. Moved aside rather than deleted so
    # nobody has to take my word for what was in it.
    if db_path.exists():
        broken = db_path.with_suffix(db_path.suffix + ".empty_backup")
        try:
            if broken.exists():
                broken.unlink()
            db_path.rename(broken)
            logger.warning(f"{db_path.name} existed but held no tables. "
                           f"Moved to {broken.name}, which is safe to delete.")
        except OSError as e:
            logger.error(f"Could not move the unusable {db_path.name} aside "
                         f"({e}). It has to go before a new one can be built.")
            raise

    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(schema_file.read_text(encoding="utf-8"))
        conn.commit()
    finally:
        conn.close()

    # The real chain, over the fresh file. Returns the summary the caller
    # logs, so a fresh install reports "migrated v1 -> v34" exactly like an
    # upgraded one, and there is no second code path to keep honest.
    result = run_migrations(db_path)
    result["created"] = True
    return result


def _migrate_lan_baseline(conn) -> int:
    """
    v53, 2026-09-26 (register section 13, lan_watch). THE LAN BASELINES OUT OF
    THE POLICY TABLE, and the FIFTH time this tree has had to make this move.

    The gateway MAC and the DHCP server set were two user_preferences keys.
    core/integrity.snapshot_config hashes that whole table as THE POLICY and
    journals a config_observed entry on any difference, on the contract that
    such an entry ALWAYS MEANS THE RULES CHANGED.

    MEASURED on a scratch database, driving the shipped code: the FIRST
    gateway MAC a capture learns -- a packet off the wire, no person involved
    -- moved the policy digest and journalled a false "the policy in
    user_preferences has CHANGED" warning carrying the learned MAC; learning a
    DHCP server did the same; a person's accept moved it again. The shape is
    the T2 watcher cursor, the L3 baselines (v42), the threat feeds' refresh
    time (v46), and the port-owner tables (v51). A table that is not
    user_preferences cannot be mistaken for policy by anything.

    THE OLD KEYS ARE MOVED, then deleted. Moved first because the values are
    real learned state -- a gateway MAC that took a packet to learn -- and
    deleting without carrying them forward would relearn the attacker's
    address if a spoof were in progress at the upgrade. Deleted after because
    leaving them would leave the policy snapshot telling a story about a
    sensor's bookkeeping.

    A JSON array for the DHCP set rather than the old comma-joined string:
    the set is read and written as a unit, and JSON survives an address
    containing anything a comma would have split on.

    Nothing else is backfilled. A key that was never written stays unwritten,
    and the first value seen after the upgrade is LEARNED.
    """
    added = 0
    import json

    if not _table_exists(conn, "lan_baseline"):
        conn.execute("""
            CREATE TABLE lan_baseline (
                name        TEXT PRIMARY KEY,
                value_json  TEXT NOT NULL,
                recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        added += 1

    # Carry the two old keys over, then remove them.
    moved = 0
    for old_key, new_name, wrap in (
        ("lan_gateway_mac", "gateway_mac", None),
        ("lan_dhcp_servers", "dhcp_servers", "list"),
    ):
        row = conn.execute(
            "SELECT value FROM user_preferences WHERE key = ?",
            (old_key,)).fetchone()
        if row is None:
            continue
        raw = row[0]                        # a Row supports index access too
        if raw in (None, ""):
            value = [] if wrap else None
        elif wrap == "list":
            value = [s for s in str(raw).split(",") if s.strip()]
        else:
            value = str(raw)
        if value is None:
            continue
        conn.execute(
            "INSERT INTO lan_baseline(name, value_json) VALUES(?, ?) "
            "ON CONFLICT(name) DO UPDATE SET value_json=excluded.value_json",
            (new_name, json.dumps(value, separators=(",", ":"))))
        moved += 1

    cur = conn.execute(
        "DELETE FROM user_preferences WHERE key IN "
        "('lan_gateway_mac', 'lan_dhcp_servers')")
    if cur.rowcount:
        logger.info(
            f"Removed {cur.rowcount} LAN preference key(s) that were being "
            f"hashed as the policy. The baselines live in lan_baseline now; "
            f"{moved} of them were carried over.")

    return added + moved


def _migrate_dns_cursor(conn) -> int:
    """
    v54, 2026-09-26 (register section 15, dns). THE DNS CURSORS OUT OF THE
    POLICY TABLE, and the SIXTH move of this shape.

    tools/dns_monitor and tools/dns_inspector each kept a bookkeeping row in
    user_preferences -- 'dns_import_cursor_<source>' and 'dns_inspect_cursor'.
    core/integrity.snapshot_config hashes that whole table as THE POLICY and
    journals a config_observed entry on ANY difference, on the contract that
    such an entry ALWAYS means the rules changed.

    MEASURED on a scratch database, driving the shipped code rather than
    arguing: one call to dns_monitor._set_cursor("pihole", 1234) moved the
    digest and journalled an entry whose payload was
    {'dns_import_cursor_pihole': '1234'}, and dns_inspector's cursor did the
    same one line later. The importer advances its cursor on every pass (every
    fifteen minutes by default), so a working resolver sensor would have filled
    the tamper journal with warnings about row numbers.

    The old keys are MOVED, then deleted. Moved first because the values are
    real state: a cursor carried over means the first pass after the upgrade
    resumes where the last one stopped, and deleting without carrying would
    re-read the whole source log once. Deleted after because leaving them would
    leave the policy snapshot telling a story about a sensor's bookkeeping.

    Nothing else is backfilled. A key that was never written stays unwritten,
    and the first value seen after the upgrade is written by the importer.
    """
    added, moved = 0, 0

    if not _table_exists(conn, "dns_cursor"):
        conn.execute("""
            CREATE TABLE dns_cursor (
                name        TEXT PRIMARY KEY,
                value       TEXT,
                identity    TEXT,
                updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        added += 1

    old_keys = [r[0] for r in conn.execute(
        "SELECT key FROM user_preferences WHERE key = 'dns_inspect_cursor' "
        "OR key LIKE 'dns_import_cursor_%'").fetchall()]
    for key in old_keys:
        row = conn.execute("SELECT value FROM user_preferences WHERE key = ?",
                           (key,)).fetchone()
        value = row[0] if row else None
        if value not in (None, ""):
            conn.execute(
                "INSERT INTO dns_cursor(name, value) VALUES(?, ?) "
                "ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                (key, str(value)))
            moved += 1

    if old_keys:
        cur = conn.execute(
            "DELETE FROM user_preferences WHERE key = 'dns_inspect_cursor' "
            "OR key LIKE 'dns_import_cursor_%'")
        if cur.rowcount:
            logger.info(
                f"Removed {cur.rowcount} DNS cursor key(s) that were being "
                f"hashed as the policy. They live in dns_cursor now; {moved} "
                f"of them carried a value over.")

    if added:
        logger.info(
            "v54: dns_cursor created. The DNS importer's and inspector's "
            "bookmarks are no longer rows in the table core/integrity "
            "journals as THE POLICY; see the migration's own comment.")

    return added + moved


def _migrate_background_change(conn) -> int:
    """v55: the background app change journal. Written before any change runs."""
    if _table_exists(conn, "background_change"):
        return 0
    conn.execute("""CREATE TABLE IF NOT EXISTS background_change (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT NOT NULL,
    requested_by  TEXT NOT NULL,
    action        TEXT NOT NULL,
    owner_kind    TEXT NOT NULL,
    owner_name    TEXT NOT NULL,
    display_name  TEXT,
    tier          TEXT,
    reason        TEXT,
    steps_json    TEXT,
    state         TEXT NOT NULL,
    error         TEXT,
    finished_at   TEXT,
    undone_at     TEXT,
    undo_reason   TEXT,
    undo_error    TEXT
)""")
    return 1


DNS_ANSWER_DDL = """CREATE TABLE IF NOT EXISTS dns_answer (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    times_seen  INTEGER NOT NULL DEFAULT 1,
    name        TEXT NOT NULL,
    rrtype      TEXT NOT NULL,
    value       TEXT NOT NULL DEFAULT '',
    ttl         INTEGER,
    client_ip   TEXT NOT NULL DEFAULT '',
    resolver    TEXT NOT NULL DEFAULT '',
    protocol    TEXT NOT NULL DEFAULT 'dns',
    sensor_id   TEXT,
    UNIQUE(name, rrtype, value, client_ip, resolver)
)"""

DNS_ANSWER_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_dns_answer_value ON dns_answer(value)",
    "CREATE INDEX IF NOT EXISTS idx_dns_answer_name  ON dns_answer(name)",
    "CREATE INDEX IF NOT EXISTS idx_dns_answer_seen  ON dns_answer(last_seen)",
)


LAN_TRAFFIC_DDL = (
    """CREATE TABLE IF NOT EXISTS lan_traffic_minute (
    minute        TEXT NOT NULL,
    ip            TEXT NOT NULL,
    mac           TEXT,
    up_bytes      INTEGER NOT NULL DEFAULT 0,
    down_bytes    INTEGER NOT NULL DEFAULT 0,
    up_packets    INTEGER NOT NULL DEFAULT 0,
    down_packets  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (minute, ip)
)""",
    """CREATE TABLE IF NOT EXISTS lan_flow (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_ip     TEXT NOT NULL,
    device_mac    TEXT,
    proto         TEXT NOT NULL,
    dst           TEXT NOT NULL,
    dport         INTEGER,
    dst_name      TEXT,
    bytes_out     INTEGER NOT NULL DEFAULT 0,
    bytes_in      INTEGER NOT NULL DEFAULT 0,
    packets_out   INTEGER NOT NULL DEFAULT 0,
    packets_in    INTEGER NOT NULL DEFAULT 0,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    sensor_id     TEXT
)""",
    "CREATE INDEX IF NOT EXISTS idx_lan_flow_device ON lan_flow(device_ip, last_seen)",
    "CREATE INDEX IF NOT EXISTS idx_lan_flow_dst    ON lan_flow(dst)",
    "CREATE INDEX IF NOT EXISTS idx_lan_flow_seen   ON lan_flow(last_seen)",
    "CREATE INDEX IF NOT EXISTS idx_lan_minute_ip   ON lan_traffic_minute(ip, minute)",
)


def _migrate_lan_traffic(conn) -> int:
    """v57: the live LAN monitor's two tables. Idempotent."""
    added = sum(1 for t in ("lan_traffic_minute", "lan_flow")
                if not _table_exists(conn, t))
    for stmt in LAN_TRAFFIC_DDL:
        conn.execute(stmt)
    return added


def _migrate_quic_and_dns_answers(conn) -> int:
    """v56: tls_hello.transport, and the dns_answer table. Idempotent."""
    added = 0
    if _table_exists(conn, "tls_hello") and \
            "transport" not in _columns(conn, "tls_hello"):
        conn.execute("ALTER TABLE tls_hello ADD COLUMN transport TEXT "
                     "NOT NULL DEFAULT 'tcp'")
        added += 1
    if not _table_exists(conn, "dns_answer"):
        conn.execute(DNS_ANSWER_DDL)
        added += 1
    for stmt in DNS_ANSWER_INDEXES:
        conn.execute(stmt)
    return added


def _migrate_events_time_index(conn) -> int:
    """
    v52, 2026-09-25. THE ONE INDEX THE TIMELINE NEEDS, and why it is not just
    a line in Schema.SQL.

    TN-1's read asks for the newest events inside a time window and filters by
    nothing else, so it is a range scan on occurred_at. Every other index on
    the events table leads with a column a reader filters BY (session_id,
    event_type, username, the source record pair), and none of them can answer
    a question that names no column but the time.

    WHY THIS HAD TO BE A MIGRATION. Schema.SQL is what a FRESH database is
    built from. The owner's database has 725,000 event rows in it and was
    created long before this index existed, so a line added to Schema.SQL
    alone would leave the owner's store without it and the page slow for ever, while a
    new install was fast. That is exactly the "migrated and fresh differ"
    defect Schema.SQL's own comment records for idx_packets_sensor, in the
    other direction. Both places, deliberately.

    MEASURED on a WAL-correct copy of the live store (sqlite3's backup API,
    not a cp: a copied database with a live writer reads as "malformed"):

        the 200 newest events in a 2h window   1.765 s without, 0.002 s with
        COUNT over the same window             0.333 s without, 0.001 s with
        build cost on the 1.1 GB copy                      3.3 s, once

    Idempotent: it checks sqlite_master and returns 0 when the index is
    already there, so a boot after the first one does nothing.
    """
    existing = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' "
        "AND tbl_name='events'").fetchall()}
    if "idx_events_time" in existing:
        return 0
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_time "
                 "ON events(occurred_at)")
    logger.info(
        "v52: idx_events_time added. The Activity Timeline reads the newest "
        "rows in a time window and had no index it could use; see "
        "core/timeline.py TN-1.")
    return 1


AUTORUN_BASELINE_DDL = """CREATE TABLE IF NOT EXISTS autorun_baseline (
    entry_key    TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    name         TEXT,
    path         TEXT,
    fingerprint  TEXT NOT NULL,
    detail       TEXT,
    first_seen   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)"""


def _migrate_autorun_baseline(conn) -> int:
    """v58: the autorun monitor's last reading, so a new or removed entry is seen."""
    added = 0 if _table_exists(conn, "autorun_baseline") else 1
    conn.execute(AUTORUN_BASELINE_DDL)
    return added


PLACE_DDL = (
    """CREATE TABLE IF NOT EXISTS place_baseline (
    subject_type  TEXT NOT NULL,
    subject       TEXT NOT NULL,
    place_type    TEXT NOT NULL,
    place         TEXT NOT NULL,
    place_label   TEXT,
    example_ip    TEXT,
    hits          INTEGER NOT NULL DEFAULT 1,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    PRIMARY KEY (subject_type, subject, place_type, place)
)""",
    "CREATE INDEX IF NOT EXISTS idx_place_first ON place_baseline(first_seen)",
    "CREATE INDEX IF NOT EXISTS idx_place_where ON place_baseline(place_type, place)",
    """CREATE TABLE IF NOT EXISTS place_cursor (
    source   TEXT PRIMARY KEY,
    last_id  INTEGER NOT NULL DEFAULT 0
)""",
)


def _migrate_place_baseline(conn) -> int:
    """v60: place learning for the Threat Map. Idempotent."""
    added = 0 if _table_exists(conn, "place_baseline") else 1
    for ddl in PLACE_DDL:
        conn.execute(ddl)
    return added


PLACE_TRAFFIC_DDL = (
    """CREATE TABLE IF NOT EXISTS place_traffic (
    hour           TEXT NOT NULL,
    remote_ip      TEXT NOT NULL,
    local_ip       TEXT NOT NULL DEFAULT '',
    process        TEXT NOT NULL DEFAULT '',
    packets        INTEGER NOT NULL DEFAULT 0,
    bytes          INTEGER NOT NULL DEFAULT 0,
    ports          TEXT,
    protocols      TEXT,
    threat_labels  TEXT,
    PRIMARY KEY (hour, remote_ip, local_ip, process)
)""",
    "CREATE INDEX IF NOT EXISTS idx_place_traffic_ip ON place_traffic(remote_ip, hour)",
)


def _migrate_place_traffic(conn) -> int:
    """v61: the hourly destination tally behind the Threat Map. Idempotent."""
    added = 0 if _table_exists(conn, "place_traffic") else 1
    for ddl in PLACE_TRAFFIC_DDL:
        conn.execute(ddl)
    return added


SENSOR_GAPS_DDL = (
    """CREATE TABLE IF NOT EXISTS sensor_gaps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor      TEXT NOT NULL,
    reason      TEXT,
    started_at  TEXT NOT NULL,
    ended_at    TEXT,
    session_id  TEXT
)""",
    "CREATE INDEX IF NOT EXISTS idx_sensor_gaps_time "
    "ON sensor_gaps(started_at, ended_at)",
    # The watchdog's last check, one row. Kept out of user_preferences, which
    # the integrity journal reads as policy.
    """CREATE TABLE IF NOT EXISTS sensor_watch_beat (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    at        INTEGER NOT NULL,
    first_at  INTEGER NOT NULL
)""",
)


def _migrate_sensor_gaps(conn) -> int:
    """v62: when each sensor was not collecting. Idempotent."""
    added = 0 if _table_exists(conn, "sensor_gaps") else 1
    for ddl in SENSOR_GAPS_DDL:
        conn.execute(ddl)
    return added


def _migrate_merge_carried(conn) -> int:
    """v59: known_devices.merge_carried, the flags and labels a merge moved."""
    if "merge_carried" in _columns(conn, "known_devices"):
        return 0
    conn.execute("ALTER TABLE known_devices ADD COLUMN merge_carried TEXT")
    return 1


def run_migrations(db_path: Path = None) -> dict:
    """
    Apply all pending migrations. Idempotent, safe on every boot.
    Returns a summary dict for the boot log.

    A MISSING FILE IS NOW BUILT, NOT REFUSED. See create_fresh_database
    below for why that was the port's blocker. A fresh build reports status
    "migrated" with created=True rather than the old "no_db", which nothing
    could act on.
    """
    import sqlite3
    from core import memory_engine as me

    db_path = Path(db_path or me.DB_PATH)

    if not _database_looks_real(db_path):
        return create_fresh_database(db_path)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    try:
        current = _get_version(conn)
        if current >= SCHEMA_VERSION:
            logger.info(f"Schema up to date (v{current}).")
            return {"status": "current", "version": current}

        logger.info(f"Migrating schema v{current} -> v{SCHEMA_VERSION}...")

        needs_structural = (
            not _table_exists(conn, "baseline_session_seen")
            or "severity" not in _columns(conn, "behavioral_deviation")
        )
        if needs_structural:
            conn.close()
            _backup_once(db_path)
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row

        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("BEGIN")

        backfilled            = _migrate_baseline_sessions(conn)
        deviations            = _migrate_deviation_table(conn)
        recounted, unsuppressed = _migrate_sample_counts(conn)
        prefs                 = _migrate_preferences(conn)
        runbook_cols          = _migrate_runbook_qualifiers(conn)
        port_origin_col       = _migrate_port_scan_origin(conn)
        device_identity_cols  = _migrate_device_identity(conn)
        supersede_cols        = _migrate_observation_supersede(conn)
        service_note_col      = _migrate_service_note(conn)
        vantage               = _migrate_sensor_vantage(conn)
        dns_table             = _migrate_dns_queries(conn)
        packet_scope_col      = _migrate_packet_scope(conn)
        router_tables         = _migrate_router_tables(conn)
        presence_tables       = _migrate_presence_tables(conn)
        permanence_cols       = _migrate_device_permanence(conn)
        merge_cols            = _migrate_device_merge(conn)
        probe_added           = _migrate_probe(conn)
        journal_added         = _migrate_integrity_journal(conn)
        provenance_added      = _migrate_observation_provenance(conn)
        stale_claims          = _migrate_stale_baseline_claims(conn)
        beacon_detail_added   = _migrate_beacon_detail(conn)
        event_record_id_added = _migrate_event_record_id(conn)
        always_on_added       = _migrate_always_on(conn)
        scan_run_added        = _migrate_scan_run(conn)
        expected_ports_added  = _migrate_expected_ports(conn)
        enrichment_added      = _migrate_enrichment(conn)
        basis_added           = _migrate_observation_basis(conn)
        packet_process_added  = _migrate_packet_process(conn)
        promoted_added        = _migrate_promoted_findings(conn)
        baseline_retract_added = _migrate_baseline_retract(conn)
        resolved_by_added      = _migrate_resolved_by(conn)
        prediction_added       = _migrate_prediction_ledger(conn)
        question_tables_added  = _migrate_question_queue(conn)
        perf_added             = _migrate_perf_hourly(conn)
        _migrate_operator_stated(conn)
        detection_added        = _migrate_detection_ids(conn)
        port_protocol_added    = _migrate_port_protocol(conn)
        incident_added         = _migrate_incident_ledger(conn)
        action_queue_added     = _migrate_action_queue(conn)
        duty_loop_added        = _migrate_duty_loop(conn)
        kev_cvss_cols          = _migrate_kev_cvss(conn)
        kev_content            = _migrate_kev_row_content(conn)
        tls_table_added        = _migrate_tls_hello(conn)
        threat_feed_added      = _migrate_threat_feed(conn)
        payload_table_added    = _migrate_payload_capture(conn)
        agent_runs_added       = _migrate_agent_runs(conn)
        local_integrity_added  = _migrate_local_integrity_store(conn)
        case_memory_added      = _migrate_case_memory(conn)
        ebpf_cursor_added      = _migrate_ebpf_camera_cursor(conn)
        ebpf_connect_id_added  = _migrate_ebpf_cursor_connect_id(conn)
        auditd_cursor_added    = _migrate_auditd_cursor(conn)
        auditd_inode_added     = _migrate_auditd_cursor_inode(conn)
        feed_cursor_added      = _migrate_feed_cursor(conn)
        reacknowledge_cols     = _migrate_device_reacknowledge(conn)
        seal_tools_col_added   = _migrate_agent_record_seal(conn)
        report_dismissal_added = _migrate_report_dismissal(conn)
        port_owner_added       = _migrate_port_owner(conn)
        events_time_index      = _migrate_events_time_index(conn)
        lan_baseline_added     = _migrate_lan_baseline(conn)
        dns_cursor_added       = _migrate_dns_cursor(conn)
        background_change_added = _migrate_background_change(conn)
        quic_dns_added         = _migrate_quic_and_dns_answers(conn)
        lan_traffic_added      = _migrate_lan_traffic(conn)
        autorun_baseline_added = _migrate_autorun_baseline(conn)
        merge_carried_added    = _migrate_merge_carried(conn)
        place_baseline_added   = _migrate_place_baseline(conn)
        place_traffic_added    = _migrate_place_traffic(conn)
        sensor_gaps_added      = _migrate_sensor_gaps(conn)

        _set_version(conn, SCHEMA_VERSION)
        conn.commit()
        conn.execute("PRAGMA foreign_keys=ON")

        summary = {
            "status":              "migrated",
            "from_version":        current,
            "version":             SCHEMA_VERSION,
            "sessions_backfilled": backfilled,
            "background_change_added": background_change_added,
            "quic_dns_added":      quic_dns_added,
            "autorun_baseline_added": autorun_baseline_added,
            "merge_carried_added": merge_carried_added,
            "place_baseline_added": place_baseline_added,
            "place_traffic_added": place_traffic_added,
            "sensor_gaps_added":   sensor_gaps_added,
            "deviations_migrated": deviations,
            "baselines_unsuppressed": unsuppressed,
            "preferences_added":   prefs,
            "runbook_columns_added": runbook_cols,
            "port_scan_origin_added": port_origin_col,
            "device_identity_added": device_identity_cols,
            "observation_supersede_added": supersede_cols,
            "service_note_added": service_note_col,
            "vantage_columns_added": vantage["columns_added"],
            "vantage_rows_stamped": vantage["rows_stamped"],
            "dns_table_added": dns_table,
            "packet_scope_added": packet_scope_col,
            "router_tables_added": router_tables,
            "presence_tables_added": presence_tables,
            "permanence_columns_added": permanence_cols,
            "merge_columns_added": merge_cols,
            "integrity_journal_added": journal_added,
            "observation_provenance_added": provenance_added,
            "probe_schema_added": probe_added,
            "promoted_columns_added": promoted_added,
            "stale_notes_cleaned": stale_claims["notes_cleaned"],
            "confidence_lowered": stale_claims["confidence_lowered"],
            "beacon_detail_added": beacon_detail_added,
            "event_record_id_added": event_record_id_added,
            "always_on_added": always_on_added,
            "scan_run_added":  scan_run_added,
            "expected_ports_added": expected_ports_added,
            "enrichment_tables_added": enrichment_added,
            "observation_basis_added": basis_added,
            "baseline_retract_added": baseline_retract_added,
            "resolved_by_added": resolved_by_added,
            "prediction_ledger_added": prediction_added,
            "question_tables_added": question_tables_added,
            "perf_hourly_added": perf_added,
            "detection_ids_added": detection_added,
            "port_protocol_added": port_protocol_added,
            "incident_ledger_added": incident_added,
            "local_integrity_store_added": local_integrity_added,
            "case_memory_tables_added": case_memory_added,
            "ebpf_camera_cursor_added": ebpf_cursor_added,
            "ebpf_connect_id_column_added": ebpf_connect_id_added,
            "auditd_cursor_added": auditd_cursor_added,
            "auditd_inode_column_added": auditd_inode_added,
            "feed_cursor_added": feed_cursor_added,
            "device_reacknowledge_cols_added": reacknowledge_cols,
            "action_queue_added": action_queue_added,
            "duty_loop_added": duty_loop_added,
            "kev_cvss_columns_added": kev_cvss_cols,
            "kev_rows_repaired": kev_content["qualifiers_filled"],
            "kev_severities_cleared": kev_content["severity_cleared"],
            "tls_hello_table_added": tls_table_added,
            "threat_feed_table_added": threat_feed_added,
            "payload_capture_table_added": payload_table_added,
            "agent_runs_tables_added": agent_runs_added,
            "agent_record_seal_columns_added": seal_tools_col_added,
            "report_dismissal_columns_added": report_dismissal_added,
            "port_owner_tables_added": port_owner_added,
            "events_time_index_added": events_time_index,
            "lan_baseline_added":  lan_baseline_added,
            "dns_cursor_added":    dns_cursor_added,
            "lan_traffic_added":   lan_traffic_added,
        }
        logger.info(f"Migration complete: {summary}")
        return summary

    except Exception as e:
        conn.rollback()
        logger.error(f"Migration FAILED, rolled back: {e}", exc_info=True)
        raise
    finally:
        conn.close()
