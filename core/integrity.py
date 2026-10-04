# core/integrity.py
# AgentalSec V2, a hash-chained journal of high-value writes.
#
# Item 3.2. Anything running with administrator rights on this machine can
# edit a finding, clear an event, or rewrite a baseline, and nothing would
# know. On a box the attacker controls that is not preventable. It is
# detectable, and detection is the thing worth buying, because the entire
# value of this tool is that its record can be believed afterwards.
#
# WHAT THIS ACTUALLY DEFENDS AGAINST, STATED BEFORE THE MECHANISM
#
# The chain lives in the same database it protects. An attacker who reads
# this file can recompute every hash after the row they changed and hand back
# a chain that verifies perfectly. So, plainly:
#
#   CAUGHT      someone editing rows directly, sqlite3 on the file, a
#               script, a wiper, ransomware, a careless repair. None of these
#               know or care that a journal exists. This is the common case
#               and the chain catches it completely.
#
#   CAUGHT      partial or clumsy tampering: a deleted row, a changed
#               severity, a resolved_as flipped. The break names the entry.
#
#   NOT CAUGHT  an attacker who has read this module, has write access, and
#               takes the trouble to rebuild the chain. Nothing that lives
#               only on the attacked machine can catch that. Anyone who tells
#               you otherwise is selling a hash of a hash.
#
# The gap is closed by an ANCHOR: the head hash copied somewhere the attacker
# does not control. Then rebuilding the chain no longer helps, because the
# rebuilt chain will not contain the anchored hash. anchor() writes one out;
# verify_chain(expected_head=...) checks against it.
#
# "DOESN'T DOCUMENTING THIS HELP AN ATTACKER?"  Asked 2026-08-29. No, and the
# reasoning is worth keeping because it will be asked again.
#
# The table is called integrity_journal and its columns are prev_hash and
# entry_hash. Anyone who can write to this database can read the design in
# ten seconds. The documentation is not what tells them; the schema is.
# Security that depends on the attacker not knowing how it works always
# fails, and fails silently, because nobody learns the assumption broke.
#
# The real weakness is not that the design is written down. It is that the
# chain contains NO SECRET: there is nothing an attacker needs that they do
# not already have.
#
# The obvious repair, sign each entry with a key, does not work here. A
# key on this machine is readable by exactly the attacker this defends
# against, since they already hold administrator rights. It would look like
# protection while being none, which by this project's standards is worse
# than the honest gap.
#
# So the anchor is not a supplement to the chain. It is the only part of this
# that an attacker cannot defeat, because it is the only part they cannot
# reach. Note also that the anchor hash is not a secret and does not need to
# be: knowing it does not let anyone build a chain ending at it. What matters
# is that their copy cannot be EDITED. A note in a drawer satisfies that; a
# file beside the database does not.
#
# Hiding this limit would leave an operator believing in protection they do
# not have, which is the exact failure this whole codebase is organised
# against. The limit is documented on purpose.
#
# An anchor left on the same disk is a convenience, not a control, and
# anchor() says so in its own return value rather than letting the file's
# existence imply a guarantee it does not provide. Copy it off the machine,
# a phone photo of the hash is a better anchor than a file in the same
# folder, and that is not a joke.
#
#
# WHY A DIGEST AND NOT THE ROW
# The journal stores a digest of the payload, never the payload. A duplicate
# copy of every finding would double the storage this project is already
# fighting (section 4), and would hand an attacker a second copy of the same
# sensitive material to read. The digest answers "was this changed", which is
# the question. It cannot answer "what did it say before", and it does not
# pretend to.

import hashlib
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

GENESIS = "0" * 64

# Operations worth journaling. Deliberately short: these are the writes that
# change what the tool will TELL you later. Journaling every packet insert
# would bury the signal and cost more than it buys.
JOURNALLED = {
    # Background app block, disable and undo: a person or the agent switching
    # something off on this machine.
    "background_change_applied",
    "background_change_failed",
    "background_change_undone",
    "background_change_undo_failed",
    "finding_saved",
    "finding_dismissed",
    "finding_undismissed",
    "deviation_resolved",
    "baseline_suppressed",
    "device_vouched",
    "device_retired",
    "devices_merged",
    "enrollment_completed",
    "config_observed",
    # Added 2026-09-01, and it is a decision rather than accretion, which the
    # docstring on record() asks for. scripts/reclaim_packet_space.py clears
    # the payload off every unflagged packet row and drops a column, which on
    # the real database is 1.3 million rows losing data permanently. That is
    # not a packet insert, it is a person deleting evidence by hand from
    # outside the app, and it is precisely what somebody reading this journal
    # after an incident needs to see. Compare "the prune deleted seven hours
    # too much" in TODO 23: a destructive maintenance job that leaves no trace
    # is the thing being guarded against.
    "packet_space_reclaimed",
    # Added 2026-09-02 with schema v24. Declaring a port normal on a device
    # STOPS A FINDING FROM BEING RAISED, and anything that stops an alarm
    # belongs in the journal beside the dismissals. Withdrawing it is
    # journalled too, so the pair reads as a history rather than a state.
    "port_expectation_declared",
    "port_expectation_withdrawn",
    # Added 2026-09-03. Withdrawing an observation takes a row out of what the
    # tool tells you next time, which is the test this whole set is picked on,
    # so I think it just got missed rather than left out on purpose. It is the
    # same shape as port_expectation_withdrawn right above: something a person
    # did by hand that quietly changes the answer later.
    #
    # Nothing is deleted by a withdrawal, so this is not about catching a
    # wiper. It is so that "the baseline stopped saying X" has a line next to
    # it saying when and why, instead of being something you only find by
    # digging with include_superseded.
    #
    # The refile in scripts/refile_observation.py journals too, and it lands
    # as a withdrawal pointing at the row that replaced it, which is what you
    # want when reading it back.
    "observation_withdrawn",
    # Added 2026-09-04 with TODO 39.5. Declaring a port expected now RETIRES
    # the findings already raised for it, and that is a different act from
    # declaring. The declaration changes what happens next; this changes what
    # is on the screen right now.
    #
    # It belongs here for the same reason finding_dismissed does. Clearing an
    # alert somebody could otherwise have read is the whole class of thing
    # this journal exists for, and the clear being reasonable is not a reason
    # to leave it unrecorded. The entry carries the row ids and the reason, so
    # "why did the 8888 alert stop" has an answer that does not depend on
    # anybody remembering.
    "port_findings_cleared",
    # Added 2026-09-27 for EM2-4. The service-burst rule LNX-1014 counted one
    # service start three times (the pair of systemd lines, the same line out
    # of the second source, and a re-read by a lagging cursor) and wrote 84
    # false alerts into the owner's store before the counting was fixed. The owner's
    # instruction was to "get rid of all those 84 entries all together".
    #
    # DELETED, not dismissed, and the distinction is the reason this operation
    # exists rather than reusing finding_dismissed. A dismissal is a person
    # deciding an alert should stay quiet; these rows were never evidence of
    # anything, and leaving 84 dismissed rows would keep the false history on
    # the record. The rows themselves were read and listed before the delete
    # (see bugfinder.md's EM2-4 section); this entry carries the ids, the
    # detection ids and the reason, so the act is reversible by hand and
    # visible to anybody auditing the chain afterwards.
    "findings_removed",
    # Added 2026-09-15 with TODO 112. Suppressing one detection STOPS AN ALARM
    # FROM BEING RAISED, which is the exact test this set is picked on, and it
    # is a narrower and therefore more forgettable act than dismiss_entity.
    #
    # The pair is journalled, not just the suppression, so it reads as a
    # history rather than a state: "PKT-1002 went quiet for 192.0.2.50 on the
    # 15th and came back on the 20th" is a sentence somebody can check. A
    # state alone cannot say when it started.
    "detection_suppressed",
    "detection_unsuppressed",
    # Added 2026-09-21 with the action queue port. These three are the SHARPEST
    # entries on this list, because they are the only ones where the app ACTED
    # WITHOUT ANYBODY TYPING and then a person said yes or no.
    #
    # approved and rejected are journalled as a PAIR, for the same reason the
    # suppression pair is: a state alone cannot say when it changed or who
    # changed it, and "why was that process killed at 3am" needs an answer that
    # does not depend on anyone remembering.
    #
    # executed is separate from approved on purpose. Approving is a decision
    # and executing is an effect, and they can come apart: the kill can fail,
    # the port can already be blocked, the helper can be gone. Recording only
    # the approval would let a failed action read as done.
    "action_approved",
    "action_rejected",
    "action_executed",
    # THE AGENT'S OWN RECORD. Added 2026-09-23, and the argument is in the
    # block above SEALED_TABLES at the bottom of this file. Short version: the
    # journal sealed what the app knew about the NETWORK and nothing about
    # itself, so root could edit a duty report's verdict or delete a run row
    # and verify_chain() would still answer intact. MEASURED, not assumed —
    # see section 13 of tests/test_integrity.py.
    #
    # These four are ROW WITNESSES rather than event entries: the payload is
    # the row's own declared columns, so the digest can be re-derived later by
    # verify_sealed_rows(). Every operation above this line digests a payload
    # a call site built by hand, which records that a write happened and can
    # never say whether the row still matches.
    "agent_run_recorded",     # duty_run      — every wake, and what it called
    "agent_report_written",   # duty_report   — the agent's written decisions
    "agent_message_logged",   # session_log   — the prompts and the answers
    "action_request_filed",   # action_request — the proposal, before any
                              #                  person touches it
    "operator_question_filed",  # operator_question — what the app SAID to a
                                #                  person, and what it told
                                #                  the owner it had already tried
    # Event entry, not a row witness, because an incident row is legitimately
    # rewritten on every coalesce and a digest of it would cry wolf. What is
    # recorded is the TRANSITION: from, to, who, why. Dismissing an incident
    # stops it being shown, which is the sharpest form of the test this set is
    # picked on, and the model moves incidents to `triaged` on its own.
    "incident_status_changed",
    # v51, 2026-09-25. A DISMISSAL OF AN AGENT REPORT, and it is the same shape
    # as incident_status_changed one line up rather than a row witness. The
    # duty_report row legitimately changes after it is written (that is what a
    # dismissal IS), so a digest of the row would cry wolf on every click; what
    # a later reader needs is the TRANSITION -- which report, dismissed by
    # whom, when, and the reason if one was given.
    #
    # WHY THIS IS JOURNALLED AT ALL, given that a dismissal deletes nothing:
    # "why did nobody look at this" is answered by the fact that somebody DID
    # look and decided to stop showing it. An unjournalled dismissal would make
    # the Reports list quietly shorter with nothing anywhere saying who
    # shortened it, which is the blinding shape this file exists to make
    # visible.
    "report_dismissed",
}


def _digest(payload) -> str:
    """
    Stable digest of a payload.

    sort_keys because dict ordering is not part of the fact being recorded,
    and a digest that changes when nothing did produces false alarms, which
    on a tamper alarm is worse than useless, because it teaches the operator
    to dismiss it.
    """
    try:
        blob = json.dumps(payload, sort_keys=True, default=str)
    except (TypeError, ValueError):
        blob = str(payload)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _entry_hash(prev_hash, recorded_at, operation, table_name, row_ref,
                payload_digest) -> str:
    """
    The chain link.

    Every field that identifies the entry is inside the hash, not just the
    payload digest. If only the digest were chained, an attacker could move a
    legitimate entry to a different row_ref and the chain would still verify.
    """
    parts = [prev_hash, str(recorded_at), operation, str(table_name),
             str(row_ref), payload_digest]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def _head(conn) -> str:
    row = conn.execute(
        "SELECT entry_hash FROM integrity_journal ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row[0] if row else GENESIS


# How long a writer waits for another writer to finish an append. The chain is
# ONE row wide, so two appends cannot overlap; see record() for why that is
# enforced with a transaction rather than hoped for.
APPEND_LOCK_SECONDS = 10.0


def record(operation: str, table_name: str = None, row_ref=None,
           payload=None, conn=None) -> dict | None:
    """
    Append one entry to the chain.

    NEVER raises into the caller. A journal that can break the write it is
    journaling turns an integrity feature into an availability bug, and the
    first time it fires during an incident somebody will disable it. It logs
    and returns None instead.

    Unknown operations are refused rather than accepted, so the vocabulary
    stays a decision instead of accreting, the same argument as
    finding_policy's unregistered sensor, one layer down.

    THE HEAD IS READ AND THE ENTRY WRITTEN IN ONE TRANSACTION, FIXED
    2026-09-23. They used to be two statements on a fresh connection, and the
    chain is ONE ROW WIDE: two writers that both read head H both hash
    against H, the second one lands with a prev_hash pointing at an entry that
    is no longer its predecessor, and verify_chain() reports a break that no
    attacker caused. Every write path here is threaded (the duty daemon, the
    watcher, the executor, a Flask request thread), so this was reachable
    before this file gained its newest call sites and is much more reachable
    now. BEGIN IMMEDIATE takes the write lock BEFORE the head is read, so the
    second writer waits and then sees the first one's entry.
    """
    if operation not in JOURNALLED:
        logger.warning(f"integrity: refusing unknown operation {operation!r}")
        return None

    own_conn = conn is None
    try:
        if own_conn:
            from core import memory_engine as me
            conn = sqlite3.connect(me.DB_PATH, timeout=APPEND_LOCK_SECONDS)
        recorded_at = datetime.now(timezone.utc).isoformat()
        # A caller-supplied connection is usually already inside its own write
        # transaction, which holds the lock this needs; beginning another one
        # there would raise. So this only takes the lock it does not have.
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        prev = _head(conn)
        pd = _digest(payload)
        eh = _entry_hash(prev, recorded_at, operation, table_name, row_ref, pd)
        conn.execute(
            "INSERT INTO integrity_journal(recorded_at, operation, table_name,"
            " row_ref, payload_digest, prev_hash, entry_hash)"
            " VALUES (?,?,?,?,?,?,?)",
            (recorded_at, operation, table_name, str(row_ref), pd, prev, eh))
        if own_conn:
            conn.commit()
        return {"entry_hash": eh, "prev_hash": prev, "operation": operation}
    except Exception as e:
        logger.error(f"integrity: could not journal {operation}: {e}")
        return None
    finally:
        if own_conn and conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# THE POLICY ITSELF, 2026-08-29
#
# Every operation above journals a FACT: this finding was saved, this device
# was vouched for. None of them journalled the RULES those facts are judged
# by, and the rules are a plain table, user_preferences, holding the
# confidence thresholds, the silence cap, the severity floor, the alert
# timeout. One UPDATE against the database file changed all of it.
#
# That was strictly better than the attacks this module was built to catch.
# Editing a baseline breaks the chain at that row. Editing the row that
# decides what a baseline MEANS broke nothing: the chain stayed intact, the
# anchor still matched, and every entry written afterwards was a truthful
# record of a corrupted policy. The journal would have gone on faithfully
# attesting to garbage, which is worse than a visible break, because a break
# announces itself.
#
# So the config is journalled too, as a digest of the whole table, and ONLY
# when it differs from the last one recorded. That has a consequence worth
# stating: a config_observed entry in the journal always means the rules
# changed. It is never routine noise, so it never needs to be ignored.
#
# WHAT THIS CATCHES AND WHAT IT DOES NOT. The same honesty as the header.
# This is detection, not prevention, it tells you the rules moved, after
# they moved. It does not tell you WHO moved them, and it cannot tell you
# what they were before, because the journal stores digests and never
# payloads. The values as they now stand are written to the log at WARNING
# instead, so the log says what the policy IS and the chain says when it
# stopped being what it was. Refusing an insane value at the point of use is
# a separate control and lives in rollup_engine._confidence_thresholds.

CONFIG_TABLE = "user_preferences"


def _config_state(conn) -> dict:
    rows = conn.execute(
        f"SELECT key, value FROM {CONFIG_TABLE} ORDER BY key").fetchall()
    return {str(k): (None if v is None else str(v)) for k, v in rows}


def snapshot_config(reason: str = "periodic", conn=None) -> dict | None:
    """
    Journal the current preferences, but only if they changed.

    Returns the new state on a change, None when nothing moved or the
    snapshot could not be taken. Like record(), this never raises into the
    caller: it runs on the boot path and during rollup, and an integrity
    feature that can stop the monitor from starting will be switched off by
    the first person it inconveniences.
    """
    own_conn = conn is None
    try:
        if own_conn:
            from core import memory_engine as me
            conn = sqlite3.connect(me.DB_PATH)

        state  = _config_state(conn)
        digest = _digest(state)

        row = conn.execute(
            "SELECT payload_digest FROM integrity_journal"
            " WHERE operation='config_observed' ORDER BY id DESC LIMIT 1"
        ).fetchone()

        if row and row[0] == digest:
            return None

        record("config_observed", table_name=CONFIG_TABLE, row_ref=reason,
               payload=state, conn=conn)
        if own_conn:
            conn.commit()

        if row:
            # Not the first snapshot, so this is a real change. WARNING, not
            # INFO: nothing in the running system is supposed to rewrite
            # these rows, so a change here was made from outside the app.
            logger.warning(
                f"integrity: the policy in {CONFIG_TABLE} has CHANGED since "
                f"the last snapshot ({reason}). Current values: {state}")
        else:
            logger.info(
                f"integrity: first config snapshot recorded ({reason}).")
        return state

    except Exception as e:
        logger.error(f"integrity: could not snapshot config: {e}")
        return None
    finally:
        if own_conn and conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def verify_chain(expected_head: str = None, db_path=None) -> dict:
    """
    Walk the chain and report the FIRST break, with everything before it.

    Reports the first break rather than a count of breaks on purpose: after
    one alteration every subsequent link fails, so a count would say "1400
    entries corrupted" when one row was edited. The number that matters is
    where it starts.

    expected_head: a hash from a previous anchor. Supplying one is what turns
    this from a self-consistency check into a tamper check, see the header.
    Without it, this verifies only that the chain is internally coherent,
    which a rebuilt chain also is.
    """
    from core import memory_engine as me
    path = Path(db_path or me.DB_PATH)
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM integrity_journal ORDER BY id ASC").fetchall()
    except sqlite3.Error as e:
        conn.close()
        return {"status": "no_journal", "detail": str(e),
                "note": "The journal table is absent. That is not a clean "
                        "result, it means nothing is being recorded."}

    prev = GENESIS
    for r in rows:
        expect = _entry_hash(r["prev_hash"], r["recorded_at"], r["operation"],
                             r["table_name"], r["row_ref"], r["payload_digest"])
        if r["prev_hash"] != prev:
            conn.close()
            return {"status": "broken", "verified_entries": r["id"] - 1,
                    "first_break_id": r["id"],
                    "reason": "an entry does not follow the one before it",
                    "detail": ("Either a preceding entry was deleted, or this "
                               "one was inserted. Entries before this point "
                               "are still coherent."),
                    "recorded_at": r["recorded_at"],
                    "operation": r["operation"], "row_ref": r["row_ref"]}
        if expect != r["entry_hash"]:
            conn.close()
            return {"status": "broken", "verified_entries": r["id"] - 1,
                    "first_break_id": r["id"],
                    "reason": "an entry's own contents do not match its hash",
                    "detail": ("This row was edited after it was written. "
                               "What it referred to is named below."),
                    "recorded_at": r["recorded_at"],
                    "operation": r["operation"],
                    "table_name": r["table_name"], "row_ref": r["row_ref"]}
        prev = r["entry_hash"]
    conn.close()

    out = {"status": "intact", "verified_entries": len(rows), "head": prev}

    if expected_head:
        if expected_head == prev:
            out["anchor"] = "matches_head"
            out["note"] = ("Chain is intact AND ends at the anchored hash. "
                           "Nothing has been added or altered since the "
                           "anchor was taken.")
        else:
            # GENESIS is the head of an EMPTY journal. It is never an
            # entry_hash, only the prev_hash of the first entry, so a naive
            # membership test reports a false ANCHOR_MISSING for anyone who
            # anchored a fresh install and later added entries legitimately.
            #
            # Found 2026-08-29 by a sanity check, not by a test, the suite
            # anchored a populated journal and never exercised the empty case.
            # A tamper alarm that cries wolf is worse than no alarm, because
            # it teaches the operator to dismiss the real one. This file
            # already makes that argument about _digest's stability; the same
            # rule applies here.
            hit = (expected_head == GENESIS
                   or any(r["entry_hash"] == expected_head for r in rows))
            out["anchor"] = "contains_anchor" if hit else "ANCHOR_MISSING"
            out["note"] = (
                "Chain is intact and still contains the anchored hash; "
                "entries were appended after it, which is normal."
                if hit else
                "THE ANCHORED HASH IS NOT IN THIS CHAIN. An intact chain that "
                "does not contain a hash it previously ended at has been "
                "rebuilt. This is the case the chain alone cannot detect, and "
                "the only reason the anchor exists.")
            if not hit:
                out["status"] = "rebuilt"
    else:
        out["note"] = (
            "Internally coherent. This does NOT prove nothing was tampered "
            "with: a rebuilt chain is also coherent. Compare against an "
            "anchor taken earlier, and keep the anchor off this machine.")
    return out


def anchor(out_path=None, db_path=None) -> dict:
    """
    Take the current head hash so it can be compared later.

    Writes it to a file for convenience and RETURNS it so it can be put
    somewhere that matters. The return value says plainly that a file beside
    the database is not a control, because a path that exists tends to get
    read as a guarantee.
    """
    from core import memory_engine as me
    path = Path(db_path or me.DB_PATH)
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        head = _head(conn)
        count = conn.execute(
            "SELECT COUNT(*) FROM integrity_journal").fetchone()[0]
    except sqlite3.Error as e:
        return {"status": "no_journal", "detail": str(e)}
    finally:
        conn.close()

    taken = datetime.now(timezone.utc).isoformat()
    written = history = None
    record_line = {"head": head, "entries": count, "taken_at": taken}
    if out_path:
        try:
            Path(out_path).write_text(json.dumps(record_line, indent=2),
                                      encoding="utf-8")
            written = str(out_path)
        except OSError as e:
            logger.error(f"integrity: could not write anchor: {e}")

        # Anchors APPEND to a history as well as overwriting the latest file.
        # Added 2026-08-29 after advising an operator to keep both of their
        # anchors and then noticing that --anchor silently replaced the first
        # one. Two anchors taken at different times bracket any tampering to
        # the window between them; one anchor only tells you about now, and an
        # overwrite quietly destroys the older and more useful of the two.
        try:
            hist = Path(out_path).with_suffix("")
            hist = hist.with_name(hist.name + "_history.jsonl")
            with open(hist, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record_line) + "\n")
            history = str(hist)
        except OSError as e:
            logger.error(f"integrity: could not append anchor history: {e}")

    return {
        "head": head,
        "entries": count,
        "taken_at": taken,
        "written_to": written,
        "history": history,
        "note": ("Copy this hash somewhere this machine cannot reach: a "
                 "phone, a password manager, another host. An anchor stored "
                 "on the same disk as the database is a convenience for "
                 "spotting accidents, not a defence against anyone who can "
                 "write to that disk."),
    }


# THE AGENT'S OWN RECORD. Added 2026-09-23.
#
# WHAT WAS MISSING, AND HOW IT WAS FOUND. Every operation above journals what
# this app KNOWS ABOUT THE NETWORK: findings raised and dismissed, baselines
# suppressed, devices vouched for, ports declared, actions approved and
# executed. None of them journals what this app KNOWS ABOUT ITSELF — the
# prompts it was given, the tools it called, the verdicts it wrote, the
# mornings it did not wake. Root could rewrite a duty report's verdict, or
# delete the run row for the hour it was not running, and verify_chain() would
# still answer "intact" with every entry counting.
#
# That is the exact class of attack this file exists for, aimed at the one
# record an operator is most likely to trust without checking: the agent's
# account of its own work. The owner's words: "Someone with root could edit
# the agent's history and no seal would break."
#
# MEASURED BEFORE IT WAS FIXED, on a copy of the live database (627 MB, 229
# journal entries): rewrote `duty_report.verdict` from 'no_action' to 'benign',
# replaced its body with "Nothing to see here", and deleted the newest
# `duty_run` row. verify_chain() reported status=intact, verified_entries=231,
# before and after. Not a theory.
#
# WHY THESE ARE ROW WITNESSES AND NOT EVENT ENTRIES, which is the one design
# decision here worth arguing for. Every existing operation digests a payload
# a CALL SITE built by hand, so it can say "a finding was saved" and can never
# say "the finding still reads what it read". A row witness digests the ROW
# ITSELF — the sealed columns, read back out of the table after the write —
# so the digest can be RE-DERIVED later by verify_sealed_rows(). That single
# difference buys two detections the event shape cannot express:
#
#   EDITED   the row is there and its columns no longer hash to the entry.
#   DELETED  the row is GONE and the entry still names it. The chain is the
#            list of rows that must exist, which is what makes a deletion
#            detectable at all; a journal that only recorded events would have
#            nothing to compare against.
#
# WHAT THIS DOES NOT COVER, stated here rather than discovered later:
#
#   * Rows written BEFORE this landed have no witness entry. They are
#     reported as `unsealed`, which is its own word and is never summed with
#     `verified`. Nothing backfills them, and the reason is the same argument
#     routes.py makes about automatic anchors: sealing a row NOW attests to
#     what it says now, so a backfill run after a tamper would bless the
#     tampered text and report everything as fine. A row that was never
#     witnessed is honestly unknown, and verify_sealed_rows() counts it in its
#     own field rather than folding it into either column.
#
#   * The chat path's TOOL CALLS are still not recorded anywhere. The duty
#     loop's are, as of this change, in duty_run.tools_json — they were being
#     collected by run_unattended and then dropped on the floor by
#     core/duty._usage_dict, which is a defect this fix closes on the way past.
#     A chat turn's tool calls need a table of their own (agent_step is the
#     dormant Windows design for it, v41) and that is a decision, not a bug
#     fix, so it is named here and left alone.
#
#   * An attacker who rebuilds the whole chain still wins. Same limit as the
#     top of this file, same fix: the anchor. Nothing here changes that,
#     except that the rebuild now has more entries to redo.
#
# THE COLUMN SETS ARE A DECISION, AND THE TESTS ENFORCE IT. SEALED_TABLES
# declares, per table, exactly which columns are inside the digest and which
# are excluded. tests/test_integrity.py asserts that
# (sealed OR excluded) == every column the table actually has, so the day
# somebody ALTERs one of these tables the suite goes red and they have to
# decide: seal it, or exclude it with a reason. That is the same discipline as
# finding_policy's unregistered sensor and record()'s operation allow-list,
# pointed at a column list.
#
# Excluded columns are never accidents. duty_report.read_at/read_by are out
# because a future "mark this report read" would otherwise break the seal of
# every report anybody opened, and a tamper alarm that fires when a person
# reads a page teaches that person to ignore tamper alarms. action_request's
# state/decided_*/executed_*/outcome/result_json/error are out because they
# are SUPPOSED to change after filing; the transitions are already in this
# journal as action_approved / action_rejected / action_executed.

SEALED_TABLES = {
    # The wake record. Every tick, including the ones that spent nothing.
    "duty_run": {
        "operation": "agent_run_recorded",
        "key": "id",
        "columns": ("session_id", "ran_at", "ended_at", "trigger", "outcome",
                    "incident_id", "report_id", "tokens_prompt",
                    "tokens_completion", "tokens_spent", "tokens_estimated",
                    "model_calls", "coverage_json", "coverage_note", "detail",
                    "duration_ms", "tools_json"),
        "excluded": {},
        "note": ("The agent's account of its own wake: when, why, what it "
                 "worked on, what it spent, what it called, and what it could "
                 "not see. Nothing updates a duty_run row after it is "
                 "written, so all of it is sealed."),
    },
    # What the agent DECIDED, in its own words.
    "duty_report": {
        "operation": "agent_report_written",
        "key": "id",
        "columns": ("session_id", "created_at", "kind", "trigger",
                    "incident_id", "finding_id", "second_finding_id",
                    "hypothesis", "evidence", "verdict", "saw", "action_taken",
                    "body", "tokens_spent", "model_calls", "coverage_json",
                    "coverage_note"),
        "excluded": {
            "read_at": ("A future 'mark as read' would move this. A seal that "
                        "breaks when an operator opens a report would teach "
                        "them to ignore the alarm, which costs more than the "
                        "column is worth."),
            "read_by": "Same reason as read_at.",
            # v51, 2026-09-25. The DISMISSAL FLAG, same argument as read_at
            # with more force: the owner asked for a dismiss button on the
            # Reports list, and a person clicking a button must not break a row
            # witness. The transition is not lost -- it is journalled as
            # `report_dismissed`, an EVENT entry, which is the shape this file
            # reserves for things that legitimately change after they are
            # written (see incident_status_changed, and action_request's state
            # columns, both excluded for the same reason).
            #
            # WHAT THIS MEANS FOR THE SEAL, stated because it is a real
            # reduction: a dismissed report's verdict, evidence and body are
            # still witnessed, so editing them still breaks the chain. What is
            # NOT witnessed is who dismissed it and when -- that lives in the
            # journal as a chain entry, which is tamper-evident against
            # EDITS but, being an entry rather than a witness, cannot be
            # re-derived from a row. An attacker with root who deleted the
            # dismissal entry and cleared these three columns would leave a
            # report that reads as never dismissed. That is recorded here
            # rather than discovered later.
            "dismissed_at": ("The dismissal flag. Moved by a person clicking a "
                             "button on the Reports list, so it is excluded "
                             "for the same reason read_at is, and the "
                             "dismissal itself is journalled as "
                             "report_dismissed."),
            "dismissed_by": "Same reason as dismissed_at.",
            "dismissal_note": "Same reason as dismissed_at.",
        },
        "note": ("Hypothesis, evidence, verdict, and the body the Agents page "
                 "renders. Editing the verdict of a report is the attack this "
                 "table's witness exists for."),
    },
    # The prompts and the answers.
    "session_log": {
        "operation": "agent_message_logged",
        "key": "id",
        "columns": ("session_id", "logged_at", "role", "content",
                    "token_count"),
        "excluded": {},
        "note": ("What was said to the model and what it said back. Rows are "
                 "removed by the 500-per-session TRIGGER in Schema.SQL, the "
                 "app's own trim, not tampering, so verify_sealed_rows "
                 "checks a missing row against that rule and reports "
                 "'consistent with the trim' rather than crying wolf."),
    },
    # THE QUESTION THE MODEL PUT TO A PERSON, and the reason it needed a
    # witness of its own. Added 2026-09-26, after a round in which the ONE
    # question on this host's queue was read back and found to contain a false
    # statement about a file. Every other write in this journal is the app's
    # account of the NETWORK or of its own decisions; this one is the app's
    # account of what it SAID TO THE OWNER, and that is the text the owner reads when the owner
    # decides whether to spend the owner's attention. If root can rewrite the prose of
    # a question whose why_stuck was wrong, the record of the wrong advice
    # disappears with it.
    #
    # WHAT IS SEALED: the prose and the facts about WHEN it entered the owner's view.
    # asked_at is in, because the ordering of "the answer was filed" against
    # "the question was asked" is the whole of the unheard-answer finding.
    "operator_question": {
        "operation": "operator_question_filed",
        "key": "id",
        "columns": ("session_id", "asked_at", "topic", "entity_type",
                    "entity_value", "question", "why_stuck", "tried_json",
                    "hints_json", "first_shown_at"),
        "excluded": {
            "state": ("Moved by the owner answering, or by the expiry clock, a "
                      "legitimate transition, the same shape as "
                      "action_request.state. What is NOT witnessed by this "
                      "exclusion, stated rather than discovered later: an "
                      "attacker with root who rewrote a question's state to "
                      "'expired' would leave a row that reads as retired. The "
                      "prose, the why_stuck and the hints stay witnessed, so "
                      "the wrong ADVICE cannot be edited away."),
            "answered_at": "Set when the owner answers. Covered by the state change.",
            "answer_text": ("The owner's answer, and the same argument the answer "
                            "path already makes: the owner's sentence is filed as a "
                            "behavioral observation, which is witnessed, so "
                            "attesting to it here as well would put one fact "
                            "in two witnesses. This column is the copy the "
                            "card renders."),
            "answer_filed_as": "Set by the filing that follows the answer.",
        },
        "note": ("What the app SAID to the owner and what it told the owner it had "
                 "already tried. Rewriting the question or the why_stuck of a "
                 "question the owner was shown is the attack this witness exists "
                 "for, it is the app's advice, and the record of bad advice "
                 "should not be editable by whoever gave it."),
    },
    # The proposal, before any person touches it.
    "action_request": {
        "operation": "action_request_filed",
        "key": "id",
        "columns": ("session_id", "created_at", "verb", "target",
                    "params_json", "reason", "evidence_json",
                    "evidence_fingerprint", "proposed_by", "incident_id"),
        "excluded": {
            "state": "Changes on every legitimate decision. Covered by "
                     "action_approved / action_rejected.",
            "decided_at": "Set by a person's decision. Covered by the same.",
            "decided_by": "Same.",
            "decision_note": "Same.",
            "claim_at": "Set by the executor's claim. Covered by "
                        "action_executed.",
            "claimed_by": "Same.",
            "executed_at": "Set by execution. Covered by action_executed.",
            "outcome": "Same.",
            "result_json": "Same.",
            "error": "Same.",
        },
        "note": ("What was PROPOSED, and the evidence it was proposed "
                 "against. A root user rewriting the reason on a card, or "
                 "swapping the params after the fact, changes this digest."),
    },
}


def _sealed_columns(table: str) -> tuple:
    return tuple(SEALED_TABLES[table]["columns"])


def _sealed_row_payload(table: str, row) -> dict | None:
    """
    The digest payload for one sealed row: its declared columns, as stored.

    Returns None when a declared column is absent from the table, and that is
    a REFUSAL rather than a partial seal. A digest over the columns that
    happened to exist would read as a complete seal while silently covering
    less, which is the failure mode this whole module is written against.
    """
    columns = _sealed_columns(table)
    present = set(row.keys())
    missing = [c for c in columns if c not in present]
    if missing:
        logger.error(
            f"integrity: {table} is missing sealed column(s) {missing}. This "
            f"row is NOT sealed, so nothing attests to it. Run the migrations.")
        return None
    return {c: row[c] for c in columns}


def seal_row(table_name: str, row_id, conn=None) -> dict | None:
    """
    Append a witness for ONE row, digesting the row as it now stands.

    THE ROW IS READ BACK OUT OF THE TABLE rather than handed in by the caller.
    The caller has just written it and believes it knows what it wrote; the
    digest has to be of what is actually stored, or the witness witnesses the
    caller's intentions rather than the record.

    Called INSIDE the writing transaction where the caller already has one, so
    the row and its witness commit together and a crash cannot leave a sealed
    row unwitnessed or a witness pointing at a row that never landed. Like
    record(), this never raises: a write must not fail because its witness
    could not be taken.

    Returns record()'s dict, or None when anything went wrong.
    """
    spec = SEALED_TABLES.get(table_name)
    if spec is None:
        logger.warning(f"integrity: refusing to seal unknown table "
                       f"{table_name!r}")
        return None

    own_conn = conn is None
    try:
        if own_conn:
            from core import memory_engine as me
            conn = sqlite3.connect(me.DB_PATH, timeout=APPEND_LOCK_SECONDS)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            f"SELECT * FROM {table_name} WHERE {spec['key']} = ?",
            (row_id,)).fetchone()
        if row is None:
            logger.error(f"integrity: nothing to seal in {table_name} id "
                         f"{row_id!r}; the write did not land, so there is "
                         f"nothing to attest to.")
            return None
        payload = _sealed_row_payload(table_name, row)
        if payload is None:
            return None
        return record(spec["operation"], table_name=table_name, row_ref=row_id,
                      payload=payload, conn=conn)
    except Exception as e:
        logger.error(f"integrity: could not seal {table_name} id {row_id!r}: "
                     f"{e}")
        return None
    finally:
        if own_conn and conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _trim_consistent(conn, table: str, row_ref) -> bool:
    """
    Is this missing session_log row's absence explained by the app's own trim?

    Schema.SQL's trim_session_log trigger keeps the newest 500 rows PER
    SESSION and deletes older ones. A deletion-detector that does not know
    that reports the app's own housekeeping as tampering, which is the false
    alarm this module refuses to ship.

    The rule is checkable, so it is checked rather than excused. The missing
    row cannot be read (it is gone, so its session is unknown), so the
    condition is established from the other side: the absence is explained
    when some session ALREADY holds 500 or more surviving rows, all of them
    newer than the missing one. That is precisely the state the trigger fires
    from, so a trimmed row lands in it and a row deleted out of a young
    session does not.
    """
    try:
        row = conn.execute(
            f"SELECT COUNT(*) AS n, MIN(id) AS oldest FROM {table}"
            f" GROUP BY session_id HAVING COUNT(*) >= 500",).fetchall()
        for r in row:
            # CAST on both sides: ids are integers here and row_ref is TEXT in
            # the journal. Comparing them without the cast is the kind of
            # silent never-matches that would make this whole check read as
            # "not explained" and cry wolf on every trim.
            if r["oldest"] is not None and int(r["oldest"]) > int(row_ref):
                return True
        return False
    except Exception:
        return False


def verify_sealed_rows(db_path=None, max_entries: int = 10000) -> dict:
    """
    Re-derive every row witness and report what does not match.

    Read-only. Answers three questions the chain alone could not:
      EDITED    a sealed row's columns no longer hash to its entry
      DELETED   a row an entry names is not in the table any more
      UNSEALED  a row with no witness at all — honestly unknown, NOT clean

    `unsealed` is deliberately its own number and is never added to
    `verified`. A sealed row that matches is evidence; an unsealed row is a
    row nothing has an opinion about, and summing them would let a database
    with a hundred sealed rows and a hundred thousand unsealed ones report
    "100,100 rows verified".
    """
    from core import memory_engine as me
    path = Path(db_path or me.DB_PATH)
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error as e:
        return {"status": "unavailable", "detail": str(e)}
    conn.row_factory = sqlite3.Row

    by_table = {}
    verified = edited = deleted = deleted_explained = 0
    problems, unsealed_report, trimmed = [], {}, []
    truncated = False

    try:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        for table, spec in SEALED_TABLES.items():
            if table not in tables:
                continue                    # not this database's shape
            entries = conn.execute(
                "SELECT id, row_ref, payload_digest, recorded_at"
                "  FROM integrity_journal WHERE operation = ?"
                " ORDER BY id ASC LIMIT ?",
                (spec["operation"], max_entries + 1)).fetchall()
            if len(entries) > max_entries:
                entries = entries[:max_entries]
                truncated = True
            by_table[table] = {"entries": len(entries), "verified": 0,
                               "edited": 0, "deleted": 0,
                               "deleted_expected": 0, "unsealed": 0,
                               "note": spec["note"]}

            for e in entries:
                row = conn.execute(
                    f"SELECT * FROM {table} WHERE {spec['key']} = ?",
                    (e["row_ref"],)).fetchone()
                if row is None:
                    explained = (table == "session_log"
                                 and _trim_consistent(conn, table,
                                                      e["row_ref"]))
                    if explained:
                        # THE APP DID THIS. The 500-per-session trigger
                        # deleted the row, which is housekeeping and not
                        # tampering. It is still REPORTED -- in `trimmed`,
                        # where a reader can see it -- but it does NOT flip
                        # the status to broken and it is NOT a problem.
                        #
                        # Counted separately on purpose. Merging these into
                        # `deleted` would make an ordinary busy week of chat
                        # read as tampering, and this module's whole argument
                        # is that a false alarm teaches the operator to
                        # ignore the real one.
                        by_table[table]["deleted_expected"] += 1
                        deleted_explained += 1
                        trimmed.append({
                            "table": table, "row_ref": e["row_ref"],
                            "journal_id": e["id"], "sealed_at": e["recorded_at"],
                            "detail": (f"{table} row {e['row_ref']} was sealed "
                                       f"at {e['recorded_at']} and is gone. "
                                       f"Its absence is consistent with this "
                                       f"app's own 500-per-session trim."),
                        })
                        continue
                    by_table[table]["deleted"] += 1
                    deleted += 1
                    problems.append({
                        "kind": "deleted", "table": table,
                        "row_ref": e["row_ref"],
                        "journal_id": e["id"],
                        "sealed_at": e["recorded_at"],
                        "explained_by": ("the 500-per-session trim in "
                                         "Schema.SQL" if explained else None),
                        "detail": (
                            f"{table} row {e['row_ref']} was sealed at "
                            f"{e['recorded_at']} and is NOT in the table. Its "
                            f"absence is consistent with this app's own trim."
                            if explained else
                            f"{table} row {e['row_ref']} was sealed at "
                            f"{e['recorded_at']} and is NOT in the table. "
                            f"Nothing in this app deletes a row from "
                            f"{table}, so this is somebody else's delete."),
                    })
                    continue

                payload = _sealed_row_payload(table, row)
                if payload is None:
                    # A column the seal needs is gone (schema drift). This is
                    # NOT a match and NOT an edit: it could not be checked.
                    problems.append({
                        "kind": "cannot_check", "table": table,
                        "row_ref": e["row_ref"], "journal_id": e["id"],
                        "detail": (f"{table} row {e['row_ref']} cannot be "
                                   f"checked: a sealed column is missing from "
                                   f"the table. That is a schema problem, not "
                                   f"a tamper finding, and it is not a pass."),
                    })
                    continue

                if _digest(payload) == e["payload_digest"]:
                    by_table[table]["verified"] += 1
                    verified += 1
                else:
                    by_table[table]["edited"] += 1
                    edited += 1
                    problems.append({
                        "kind": "edited", "table": table,
                        "row_ref": e["row_ref"], "journal_id": e["id"],
                        "sealed_at": e["recorded_at"],
                        "detail": (f"{table} row {e['row_ref']} does not hash "
                                   f"to the entry sealed at "
                                   f"{e['recorded_at']}. The row was changed "
                                   f"after it was written."),
                    })

            # Rows with no witness. Counted, never guessed at, and capped so
            # a large unsealed table cannot turn this into a slow query.
            sealed_ids = {e["row_ref"] for e in entries}
            unsealed = conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE CAST({spec['key']} AS "
                f"TEXT) NOT IN (SELECT row_ref FROM integrity_journal WHERE "
                f"operation = ?)", (spec["operation"],)).fetchone()[0]
            by_table[table]["unsealed"] = int(unsealed or 0)
            if unsealed:
                unsealed_report[table] = {
                    "count": int(unsealed),
                    "note": ("Written before the agent's record was sealed, so "
                             "nothing attests to them. That is NOT the same as "
                             "clean, they are unknown, and this seal cannot "
                             "tell a row that was always right from one that "
                             "was edited before it was ever sealed."),
                }
            del sealed_ids
    except sqlite3.Error as e:
        conn.close()
        return {"status": "unavailable", "detail": str(e)}
    finally:
        try:
            conn.close()
        except Exception:
            pass

    if edited or deleted:
        status = "broken"
    elif truncated:
        status = "partial"
    else:
        status = "intact"

    out = {
        "status": status,
        "verified_rows": verified,
        "edited_rows": edited,
        "deleted_rows": deleted,
        "by_table": by_table,
        "problems": problems[:50],
        "problems_total": len(problems),
        "note": (
            "Row witnesses: the agent's own record (runs, reports, prompts, "
            "action proposals) digested row by row, so an edit AND a deletion "
            "both break a seal. An unsealed row is unknown, never clean. An "
            "attacker who rebuilds the chain defeats this exactly as it "
            "defeats the chain itself; the anchor is still the only thing that "
            "closes that, and still has to be kept off this machine."),
    }
    if deleted_explained:
        # REPORTED, NOT HIDDEN, AND NOT A PROBLEM. These are rows the app
        # itself deleted (the session_log trim). They are excluded from the
        # status because "the app trimmed its own chat log" is not a tamper
        # finding, and they are shown because a reader asked and deserves the
        # whole answer either way.
        out["deleted_expected"] = deleted_explained
        out["trimmed"] = trimmed[:20]
        out["trimmed_total"] = len(trimmed)
    if truncated:
        out["truncated"] = (
            f"Checked the oldest {max_entries} witnesses per table and "
            f"stopped. This is a PARTIAL result, not a clean one: rows beyond "
            f"that have not been re-derived.")
    if unsealed_report:
        out["unsealed"] = unsealed_report
    return out
