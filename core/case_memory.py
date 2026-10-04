# core/case_memory.py
# AgentalSec V2, the patient file.
#
# Case memory: what this app already knows about this subject, and what
# happened the last times something looked like this. The layer between "a new
# incident arrived" and "begin from a blank page".
#
# WHY THIS FILE EXISTS
#
# The owner's words, and they are the whole specification: "the agent writes an
# assessment for every incident and never reads the old ones. Every alert is
# investigated from a blank page. A doctor with no patient file."
#
# Verified in the source before this was built: there is no embedding, no vector
# search and no precedent retrieval anywhere in the tree. Incident assessments
# are written and never read back by similarity. The duty loop's own prompt
# (core/duty.INCIDENT_PROMPT) hands the model one incident row and tells it to
# form a hypothesis, and nothing in that prompt has ever mentioned that this
# exact address was looked at in March, or that this exact rule on this exact
# process name was investigated twice before and dismissed both times with the
# user saying it was their own tooling.
#
# So an assessment was a page written into a file nobody opened again. This
# module is the file.
#
# THE TWO QUESTIONS, AND THEY ARE NOT THE SAME QUESTION
#
#   entity_history(type, value)
#     WHAT HAS THIS SUBJECT EVER DONE HERE. Every incident, every finding,
#     every action proposed, on this one address / process / file / user.
#     Deterministic, exact, indexed, no text matching. "Have we EVER seen this
#     before?" is the single bit that resolves a large share of alerts, and it
#     is answered from the primary tables rather than from the index, so it is
#     answerable even when the index is behind.
#
#   similar_incidents(...)
#     WHAT HAPPENED THE LAST TIMES SOMETHING LOOKED LIKE THIS. Retrieval over
#     past incidents and their dispositions. "This looks like the June case,
#     here is how it ended."
#
# They are separate functions because they can disagree, and when they do the
# disagreement is the interesting part: an entity with no history at all but a
# dozen similar incidents from other addresses is a different situation from
# one that has done this exact thing every Tuesday for a month.
#
# THE RULE THIS FILE IS BUILT AROUND
#
# A PRECEDENT IS EVIDENCE, NOT A VERDICT. This is the honesty rule the whole
# module turns on, and it is worth stating twice because the failure is
# seductive: a retrieval layer that answers "you dismissed this last time, so
# it is benign" is a machine for teaching an analyst to wave things through.
# The past incident is a thing that HAPPENED. It carries what was decided, by
# whom, when, and why. It does not carry an opinion about today, and the
# scoring here never produces one.
#
# So every precedent travels with:
#   - what was decided (status), who decided it (status_by) and why (the note)
#   - when, and how long ago
#   - the coverage that existed when THAT assessment was made, because an
#     incident dismissed while capture was blind was dismissed on no evidence
#   - the exact fields that made it a match, named one by one
#
# And the second rule, which is this codebase's rule two:
#
#   "NO PRECEDENT FOUND" AND "THE INDEX COULD NOT ANSWER THAT" ARE DIFFERENT
#   SENTENCES. The index lags the incident table by design (it is written by a
#   tick, and an incident can be written between ticks), so an empty result
#   ALWAYS carries `index_lag`: how many incidents exist that this index has
#   not seen. An empty result with lag zero is a real negative. An empty
#   result with lag 11 is a statement about the index.
#
# WHY FTS5 AND NOT EMBEDDINGS
#
# Measured before choosing: SQLite 3.45.1 on this host has FTS5 with the porter
# and unicode61 tokenizers and the bm25 ranking function, all working (tested
# live, not assumed). Embeddings would need a model, a vector store and a
# network call on the critical path of a triage decision, for retrieval over a
# few thousand short rows that are mostly a rule id, a subject and two
# paragraphs. The keyword half of this problem is the half that exists, and it
# runs in the same database, in the same transaction, with no new dependency.
#
# A NOTE ON PARSING, because it is the reason the index is STANDALONE rather
# than a contentless table with triggers:
#
# MEASURED, and it changed the design. FTS5's own `integrity-check` command
# PASSES on a desynchronised external-content index -- a row deleted from the
# base table without the delete trigger firing leaves the index serving a
# phantom that no check reports. So a trigger-maintained index can be WRONG
# SILENTLY, which is this project's least acceptable failure shape, and the
# "integrity check passed" line would make it worse by looking like evidence.
#
# This index is therefore written by this module and BY NOTHING ELSE, it stores
# the incident id it was built from as its rowid, and the lag between it and
# the incident table is COMPUTED AND REPORTED on every read rather than trusted.
# A number that can be wrong in a way somebody can see is worth more here than
# a trigger that is right until it is not.
#
# WHAT THIS MODULE DELIBERATELY DOES NOT DO
#
# - It writes NOTHING except its own index tables. It never writes an incident,
#   never changes a status, never files an action. A memory that edits the
#   record it remembers is not a memory.
# - It does not score an entity's RISK and it does not produce a verdict. It
#   returns things that happened, with their sources.
# - It never deletes a row from the index for an incident that still exists;
#   only the "this incident is gone from the ledger" branch does that, and it
#   is counted and reported.
# - It is not on the policy path. Nothing here may be read by
#   requires_permission or by any gate. Brainstorming's own guardrail: never let
#   tool output steer the policy gate. A precedent is the most steerable
#   content in the app, since anybody who can cause findings can cause a
#   precedent to exist.

import hashlib
import json
import logging
import re
import sqlite3
import time
from datetime import datetime, timedelta, timezone

from core import memory_engine as me

logger = logging.getLogger(__name__)


class BadCaseMemoryInput(ValueError):
    """A caller asked the memory for something it will not do."""


# CAPS
#
# Each of these exists for a stated reason rather than as a default nobody
# chose. The retrieval result is read by a model inside a turn that already
# re-sends its system prompt every round (measured in T4: ~20,300 tokens of
# fixed overhead per round), so the memory's answer has to be small enough that
# it is worth its cost. A memory that returns eighty rows is a memory the model
# skims.

INDEX_BATCH_DEFAULT   = 200     # incidents indexed per tick. The ledger is 40/day capped, see core/incident.
INDEX_TEXT_CAP        = 4000    # per indexed field, before hashing. An assessment is a paragraph or three.
QUERY_TOKEN_CAP       = 24      # tokens taken from a seed's text to build the MATCH
QUERY_TOKEN_MIN_LEN   = 3       # 1 and 2 character tokens match almost everything
ENTITY_HISTORY_LIMIT  = 25      # incidents returned for one entity
SIMILAR_LIMIT_DEFAULT = 5       # precedents returned. Five is a file; twenty is a search result.
ENTITY_FINDINGS_LIMIT = 20

# Scoring weights. Named rather than inline because the reason each has the
# value it has IS the design, and a bare 0.45 in a sum is unreviewable.
W_SAME_RULE     = 0.45   # same detection id: the single strongest signal available
W_SAME_ENTITY   = 0.30   # same subject, exactly: "this address did this before"
W_TEXT          = 0.35   # bm25 text overlap, normalised. The weakest, so capped below the two above.
W_SAME_TYPE     = 0.08   # same KIND of subject
W_SAME_SOURCE   = 0.05   # same sensor raised it
W_SEVERITY      = 0.04   # severity within one rank
MIN_SCORE       = 0.12   # below this it is not a precedent, it is a coincidence

# An incident that has not been looked at yet is a poor precedent: it records
# that something happened, not what anybody concluded. It is still RETURNED
# (it is the honest list of what happened) and it is labelled `unassessed`.
UNASSESSED_STATUSES = ("new",)

_WORD_RE = re.compile(r"[A-Za-z0-9_]{2,}", re.UNICODE)

# The app's severity order, ascending, taken from core/detections._SEVERITY_ORDER
# reversed rather than restated. Restating it here would be a second answer to
# what "worse" means, and the two would eventually disagree; detections is the
# register and it owns the order.
SEVERITY_RANK = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


# SMALL HELPERS, matched to the rest of the tree

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sql_ts(dt: datetime) -> str:
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


def _age_days(stamp) -> float:
    when = _parse_ts(stamp)
    if not when:
        return 0.0
    return max(0.0, (_now() - when).total_seconds() / 86400.0)


def _clip(value, cap: int = INDEX_TEXT_CAP) -> str:
    text = "" if value is None else str(value)
    return text[:cap]


# IS FTS5 HERE AT ALL
#
# A HARD DEPENDENCY WOULD BE A LIE ON A MACHINE THAT LACKS IT. FTS5 is a
# compile-time option of the SQLite the Python build links against. On this host
# it is present and measured. On another it may not be, and the honest answer
# there is "the precedent half of case memory is not available on this install,
# and here is why" -- NOT an empty list, which would read as "nothing like this
# ever happened".
#
# entity_history does NOT depend on FTS5 and keeps working regardless. That
# split is deliberate: the half that answers "have we seen this before" is
# plain SQL over indexed columns and has no reason to be down.

_FTS_STATE = {"checked": False, "available": False, "reason": None}


def fts_available(force: bool = False) -> dict:
    """
    Whether this install's SQLite can serve the precedent index.

    Probes by BUILDING a throwaway table rather than by asking a version
    string, because the question is "can this build do it" and the only honest
    way to answer that is to do it.
    """
    if _FTS_STATE["checked"] and not force:
        return dict(_FTS_STATE)

    reason = None
    available = False
    try:
        conn = sqlite3.connect(":memory:")
        try:
            conn.execute(
                "CREATE VIRTUAL TABLE _probe USING fts5(x, tokenize='porter "
                "unicode61')")
            # bm25 is what makes the ranking usable. A build with the table but
            # not the ranker would match rows and order them uselessly.
            conn.execute("INSERT INTO _probe VALUES ('alpha beta')")
            conn.execute("SELECT bm25(_probe) FROM _probe WHERE _probe MATCH "
                         "'alpha'").fetchone()
            available = True
        finally:
            conn.close()
    except Exception as e:                    # noqa: BLE001, it is the point
        reason = (f"This install's SQLite cannot build an FTS5 index with the "
                  f"porter tokenizer and the bm25 ranker ({type(e).__name__}: "
                  f"{e}). The precedent half of case memory is unavailable; "
                  f"entity history still works.")

    _FTS_STATE.update({"checked": True, "available": available,
                       "reason": reason})
    return dict(_FTS_STATE)


def _table_ready(conn, name: str) -> bool:
    return me._table_exists_ro(conn, name)


def _index_ready(conn) -> bool:
    return (_table_ready(conn, "case_index") and _table_ready(conn, "case_fts"))


# THE INDEX
#
# One row per indexed incident in case_index, and one FTS row per indexed
# incident in case_fts, joined by rowid = incident id. case_index is the
# AUTHORITY on what is indexed: the lag, the content hash and the disposition
# all live there, so the FTS table never has to be the thing that is trusted.

_DDL_INDEX = """
CREATE TABLE IF NOT EXISTS case_index (
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
"""

_DDL_FTS = """
CREATE VIRTUAL TABLE IF NOT EXISTS case_fts USING fts5(
    subject, title, assessment, detection_id, verdict,
    tokenize='porter unicode61'
)
"""

_DDL_TRIGGER_NOTE = """
CREATE TRIGGER IF NOT EXISTS trim_case_fts_never_fires
AFTER INSERT ON case_index
BEGIN
    SELECT 1;
END
"""


def ensure_index_tables() -> dict:
    """
    Create the index tables if the migration has not run yet.

    THE MIGRATION IS THE PATH; THIS IS THE PARACHUTE. core/migrations v43
    creates exactly these three objects, and Schema.SQL carries them for a
    fresh install. This function exists so that a database sitting at v42 with
    the module loaded -- which is the state of the operator's own copy between
    the deploy and the owner's next boot -- answers honestly ("the index is not built
    yet") instead of raising a raw "no such table" out of a tick.

    It is idempotent and it is called from the writer, not from a reader: a read
    never creates anything.
    """
    out = {"created": [], "fts": fts_available()}
    if not out["fts"]["available"]:
        out["note"] = out["fts"]["reason"]
        return out

    with me._get_conn() as conn:
        if not _table_ready(conn, "case_index"):
            conn.execute(_DDL_INDEX)
            out["created"].append("case_index")
        if not _table_ready(conn, "case_fts"):
            conn.execute(_DDL_FTS)
            out["created"].append("case_fts")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_case_index_rule "
            "ON case_index(detection_id)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_case_index_entity "
            "ON case_index(entity_type, entity_value)")
    return out


def _disposition_text(row) -> str:
    """
    The one-line account of what was concluded, used as a searchable field.

    Built from the row rather than asked of the model: the point of indexing
    this is that a LATER investigation searches for how a thing ENDED, and the
    end of a thing is already in the ledger as status, status_by and the
    assessment. Composing a new sentence here would put words in the past
    assessor's mouth.
    """
    bits = []
    status = (row["status"] or "").strip()
    if status:
        by = (row["status_by"] or "").strip()
        bits.append(f"outcome {status}" + (f" by {by}" if by else ""))
    if row["suppressed"]:
        bits.append("suppressed at the time")
    return " ".join(bits)


def _index_one(conn, row) -> str:
    """
    Index or re-index one incident. Returns "indexed", "updated" or "unchanged".

    THE HASH IS OVER THE INDEXED TEXT, WHICH IS NOT THE WHOLE ROW. An incident
    is refreshed by the watcher on every tick that sees a matching finding, so
    finding_count and last_seen_at move constantly while the text stays put.
    Hashing the whole row would re-index everything every minute and make the
    "updated" count meaningless noise; hashing the text means an update is
    exactly the event that matters, which is the assessment landing or being
    rewritten.
    """
    subject = f"{row['entity_type'] or ''} {row['entity_value'] or ''}".strip()
    title = _clip(row["title"])
    assessment = _clip(row["assessment"])
    verdict = _disposition_text(row)

    payload = "\x00".join((subject, title, assessment, verdict,
                           row["detection_id"] or ""))
    digest = hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()

    existing = conn.execute(
        "SELECT content_hash FROM case_index WHERE incident_id = ?",
        (row["id"],)).fetchone()

    if existing and existing["content_hash"] == digest:
        # The text is unchanged. The DISPOSITION may still have moved (an
        # incident assessed after it was indexed), so the mirror columns are
        # refreshed even when the searchable text is not. This is the case the
        # first draft got wrong: it skipped the whole row on a matching hash,
        # so an incident indexed as `new` kept reporting itself as unassessed
        # forever, and the precedent list was quietly describing an older state
        # of the ledger than the ledger was in.
        conn.execute("""
            UPDATE case_index
               SET indexed_at = ?, detection_id = ?, entity_type = ?,
                   entity_value = ?, severity = ?, severity_rank = ?,
                   cia_json = ?, source = ?, status = ?, status_by = ?,
                   assessed = ?, first_seen_at = ?, last_seen_at = ?
             WHERE incident_id = ?
        """, (_sql_ts(_now()), row["detection_id"] or "",
              row["entity_type"] or "", row["entity_value"] or "",
              row["severity"] or "", int(row["severity_rank"] or 0),
              row["cia_json"] or "[]", row["source"] or "",
              row["status"] or "", row["status_by"] or "",
              1 if (row["assessment"] or "").strip() else 0,
              row["first_seen_at"], row["last_seen_at"], row["id"]))
        return "unchanged"

    if existing:
        # Standalone FTS5 has no triggers to keep it in step, so the old row is
        # deleted explicitly before the new one is written. A rowid deleted and
        # re-inserted in one transaction is the only way to replace an FTS row.
        conn.execute("DELETE FROM case_fts WHERE rowid = ?", (row["id"],))

    conn.execute("""
        INSERT INTO case_fts (rowid, subject, title, assessment,
                              detection_id, verdict)
        VALUES (?,?,?,?,?,?)
    """, (row["id"], subject, title, assessment,
          row["detection_id"] or "", verdict))

    conn.execute("""
        INSERT INTO case_index
            (incident_id, indexed_at, content_hash, detection_id, entity_type,
             entity_value, severity, severity_rank, cia_json, source, status,
             status_by, assessed, first_seen_at, last_seen_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(incident_id) DO UPDATE SET
            indexed_at = excluded.indexed_at,
            content_hash = excluded.content_hash,
            status = excluded.status,
            status_by = excluded.status_by,
            assessed = excluded.assessed,
            severity = excluded.severity,
            severity_rank = excluded.severity_rank,
            last_seen_at = excluded.last_seen_at
    """, (row["id"], _sql_ts(_now()), digest, row["detection_id"] or "",
          row["entity_type"] or "", row["entity_value"] or "",
          row["severity"] or "", int(row["severity_rank"] or 0),
          row["cia_json"] or "[]", row["source"] or "", row["status"] or "",
          row["status_by"] or "",
          1 if (row["assessment"] or "").strip() else 0,
          row["first_seen_at"], row["last_seen_at"]))

    return "updated" if existing else "indexed"


def index_pending(limit: int = INDEX_BATCH_DEFAULT) -> dict:
    """
    Bring the index up to the ledger. One bounded pass, no model, no tokens.

    Called from the watcher's tick, so the index follows the ledger on the same
    deterministic clock that writes it. It can also be called on demand, which
    is what makes the index self-healing after a restore or a schema change
    rather than permanently behind.

    ALSO REMOVES rows for incidents that no longer exist. Nothing in this app
    deletes an incident -- the retraction rule is "nothing is deleted, things
    are withdrawn" -- so a removal here means somebody restored a database or
    an incident really was deleted out from under the ledger. That is exactly
    the kind of thing that must be COUNTED rather than silently swept up, so
    it is reported as `removed` and the pass says so.
    """
    out = {"scanned": 0, "indexed": 0, "updated": 0, "unchanged": 0,
           "removed": 0, "lag_after": None, "fts": fts_available(),
           "note": None}

    if not out["fts"]["available"]:
        out["note"] = out["fts"]["reason"]
        return out

    ensure_index_tables()

    with me._get_conn() as conn:
        if not _table_ready(conn, "incident"):
            out["note"] = ("the incident table does not exist, so there is "
                           "nothing to remember yet. This is not an empty "
                           "ledger.")
            return out

        # WHICH ROWS TO LOOK AT, and the split is deliberate.
        #
        # The first SELECT is the LAG: incidents the index has never seen.
        # The second is the RECENT TAIL: incidents already indexed whose text
        # may have moved since (an assessment landing, a status changing).
        # _index_one compares the stored content hash and decides per row, so
        # this never re-indexes text that has not changed; what the two
        # SELECTs do is bound the WORK, not the decision.
        #
        # An earlier version tried to express "changed" in one SQL predicate
        # and referenced content_hash on the incident table, which does not
        # have that column. It failed loudly, which is the good outcome; the
        # shape below cannot, because it only asks about columns that exist.
        rows = conn.execute("""
            SELECT * FROM incident
             WHERE id NOT IN (SELECT incident_id FROM case_index)
             ORDER BY id DESC
             LIMIT ?
        """, (max(1, int(limit)),)).fetchall()

        if len(rows) < limit:
            seen = {r["id"] for r in rows}
            for row in conn.execute("""
                SELECT * FROM incident
                 WHERE id IN (SELECT incident_id FROM case_index)
                 ORDER BY last_seen_at DESC, id DESC
                 LIMIT ?
            """, (max(1, int(limit) - len(rows)),)).fetchall():
                if row["id"] not in seen:
                    rows.append(row)

        for row in rows:
            out["scanned"] += 1
            try:
                verdict = _index_one(conn, row)
            except Exception as e:                       # noqa: BLE001
                logger.error(f"case_memory: could not index incident "
                             f"{row['id']}: {e}")
                continue
            out[verdict] += 1

        # Rows in the mirror with no incident behind them.
        ghosts = conn.execute("""
            SELECT incident_id FROM case_index
             WHERE incident_id NOT IN (SELECT id FROM incident)
        """).fetchall()
        for ghost in ghosts:
            conn.execute("DELETE FROM case_fts WHERE rowid = ?",
                         (ghost["incident_id"],))
            conn.execute("DELETE FROM case_index WHERE incident_id = ?",
                         (ghost["incident_id"],))
            out["removed"] += 1

        out["lag_after"] = conn.execute("""
            SELECT COUNT(*) FROM incident
             WHERE id NOT IN (SELECT incident_id FROM case_index)
        """).fetchone()[0]

    return out


def reindex_all(limit: int = 100000) -> dict:
    """
    Rebuild the index from the ledger, in one pass.

    Used by tests and by a repair after the index is found lagging. It is
    deliberately the same code path as index_pending: a second implementation
    of "how an incident becomes a memory" is how two answers to one question
    start.
    """
    result = {"indexed": 0, "updated": 0, "unchanged": 0, "removed": 0,
              "scanned": 0}
    if not fts_available()["available"]:
        return {"error": fts_available()["reason"]}
    ensure_index_tables()
    with me._get_conn() as conn:
        rows = conn.execute("SELECT * FROM incident ORDER BY id").fetchall()
        for row in rows:
            result["scanned"] += 1
            verdict = _index_one(conn, row)
            result[verdict] += 1
    return result


def index_lag() -> dict:
    """
    How far behind the ledger the index is, as a number.

    THE POINT OF THE WHOLE MODULE'S HONESTY. Every read here reports this, so
    an empty precedent list can never be mistaken for "nothing like this ever
    happened" when the truth is "the index has not seen those incidents yet".
    """
    with me._get_readonly_conn() as conn:
        if not _table_ready(conn, "incident"):
            return {"available": False,
                    "note": ("there is no incident table, so there is nothing "
                             "to be behind. This is not an empty ledger.")}
        if not _index_ready(conn):
            return {"available": False, "indexed": 0,
                    "incidents": conn.execute(
                        "SELECT COUNT(*) FROM incident").fetchone()[0],
                    "lag": None,
                    "note": ("the case memory index has not been built on this "
                             "database yet, so NO incident is searchable as a "
                             "precedent. That is not the same as there being "
                             "none. The watcher builds it on its next tick.")}
        indexed = conn.execute(
            "SELECT COUNT(*) FROM case_index").fetchone()[0]
        total = conn.execute("SELECT COUNT(*) FROM incident").fetchone()[0]
        lag = conn.execute("""
            SELECT COUNT(*) FROM incident
             WHERE id NOT IN (SELECT incident_id FROM case_index)
        """).fetchone()[0]
    return {"available": True, "indexed": indexed, "incidents": total,
            "lag": lag}


# ENTITY HISTORY -- "has this subject ever done anything here"

def entity_history(entity_type: str, entity_value: str,
                   limit: int = ENTITY_HISTORY_LIMIT) -> dict:
    """
    Everything this app already knows about ONE subject, newest first.

    READ FROM THE PRIMARY TABLES, NOT FROM THE INDEX. This is the half that
    answers "have we EVER seen this before", and it is the half that must keep
    answering when the index is behind, when FTS5 is missing, or when the
    subject is a file path that no assessment has ever mentioned. An incident is
    a row; an entity is a question about rows, and it is a plain indexed SELECT.

    Returns incidents, findings and action requests about the subject, and the
    first/last seen stamps, because "how long has this been going on" is a
    different and often more decisive number than "how many times".
    """
    entity_type = (entity_type or "").strip().lower()
    entity_value = (entity_value or "").strip()
    if not entity_value:
        raise BadCaseMemoryInput(
            "entity_history needs an entity_value. Asking what has happened "
            "about 'something' is not a question with an answer.")
    if entity_type not in me.VALID_ENTITY_TYPES:
        raise BadCaseMemoryInput(
            f"entity_type must be one of {sorted(me.VALID_ENTITY_TYPES)}. Got "
            f"{entity_type!r}.")

    limit = max(1, min(int(limit or ENTITY_HISTORY_LIMIT), 200))
    out = {"entity_type": entity_type, "entity_value": entity_value,
           "incidents": [], "findings": [], "actions": [],
           "first_ever": None, "last_ever": None, "counting": None,
           "note": None}

    with me._get_readonly_conn() as conn:
        if _table_ready(conn, "incident"):
            out["incidents"] = [
                _decorate_incident(dict(r)) for r in conn.execute("""
                    SELECT id, detection_id, entity_type, entity_value,
                           severity, severity_rank, title, status, status_at,
                           status_by, assessment, assessed_at, finding_count,
                           first_seen_at, last_seen_at, coverage_note
                      FROM incident
                     WHERE entity_type = ? AND entity_value = ?
                     ORDER BY last_seen_at DESC
                     LIMIT ?
                """, (entity_type, entity_value, limit)).fetchall()]

            span = conn.execute("""
                SELECT MIN(first_seen_at) a, MAX(last_seen_at) b, COUNT(*) n
                  FROM incident WHERE entity_type = ? AND entity_value = ?
            """, (entity_type, entity_value)).fetchone()
            if span and span["n"]:
                out["first_ever"] = span["a"]
                out["last_ever"] = span["b"]
                out["counting"] = (
                    f"{span['n']} incident(s) on record about this subject, "
                    f"the earliest first seen {span['a']} and the latest last "
                    f"seen {span['b']}.")

        if _table_ready(conn, "findings"):
            out["findings"] = me._rows_to_dicts(conn.execute("""
                SELECT id, detection_id, source, severity, title, description,
                       found_at, dismissed, dismissed_reason
                  FROM findings
                 WHERE entity_type = ? AND entity_value = ?
                 ORDER BY found_at DESC
                 LIMIT ?
            """, (entity_type, entity_value, ENTITY_FINDINGS_LIMIT)).fetchall())
            # The count is a SEPARATE query over the SAME conditions, which is
            # the rule this project wrote down after a capped list was read as
            # the whole list: a count built from different conditions is right
            # until somebody uses a filter.
            out["findings_total"] = conn.execute("""
                SELECT COUNT(*) FROM findings
                 WHERE entity_type = ? AND entity_value = ?
            """, (entity_type, entity_value)).fetchone()[0]
            out["findings_capped"] = out["findings_total"] > len(out["findings"])

        if _table_ready(conn, "action_request"):
            out["actions"] = me._rows_to_dicts(conn.execute("""
                SELECT id, verb, target, state, outcome, created_at,
                       decided_at, decision_note
                  FROM action_request
                 WHERE target = ?
                 ORDER BY id DESC LIMIT 20
            """, (entity_value,)).fetchall())

    out["note"] = _history_note(out)
    return out


def _decorate_incident(row: dict) -> dict:
    """Add the derived fields a reader needs, without inventing any."""
    row["age_days"] = round(_age_days(row.get("last_seen_at")), 2)
    row["assessed"] = bool((row.get("assessment") or "").strip())
    row["assessment"] = _clip(row.get("assessment"), 1200)
    if not row["assessed"]:
        row["assessment_note"] = (
            "nobody has assessed this one, so it records that something "
            "happened and NOT what it meant")
    return row


def _history_note(out: dict) -> str:
    parts = []
    if not out["incidents"] and not out["findings"]:
        parts.append(
            "Nothing on record about this subject. That is a real negative: "
            "the incidents, findings and actions tables were all read and none "
            "of them mentions it.")
    if out.get("findings_capped"):
        parts.append(
            f"findings are capped at {len(out['findings'])} of "
            f"{out['findings_total']}; the list above is not all of them.")
    if out["incidents"]:
        unassessed = sum(1 for i in out["incidents"] if not i["assessed"])
        if unassessed:
            parts.append(
                f"{unassessed} of the incidents above carry no assessment, so "
                f"what they meant was never concluded.")
    return " ".join(parts) if parts else None


# PRECEDENT RETRIEVAL -- "what happened the last times something looked like
# this"

def _query_tokens(*texts, extra=()) -> list:
    """
    The words a MATCH is built from.

    EVERY TOKEN IS QUOTED IN THE MATCH STRING, and this is not decoration. FTS5
    query syntax has its own operators -- AND, OR, NOT, NEAR, and the column
    filter -- and the text being tokenised here is a finding title or an
    entity value, which is to say text somebody else chose. A process named
    `NEAR` or a path containing a quote would otherwise be a syntax error at
    best and a different query than the one intended at worst. Words are
    extracted with a regex, so what reaches FTS5 is only `[A-Za-z0-9_]+`.
    """
    seen, tokens = set(), []
    for text in list(texts) + list(extra):
        for match in _WORD_RE.findall(str(text or "")):
            word = match.lower()
            if len(word) < QUERY_TOKEN_MIN_LEN or word in seen:
                continue
            seen.add(word)
            tokens.append(word)
            if len(tokens) >= QUERY_TOKEN_CAP:
                return tokens
    return tokens


def _bm25_normalise(raw) -> float:
    """
    Kept for a single value's magnitude, and the docstring is now a warning.

    MEASURED, and it cost a defect: FTS5's bm25 returns a NEGATIVE number where
    MORE NEGATIVE IS A BETTER MATCH, and the magnitude is dominated by how rare
    the query tokens are, not by match quality. Two real rows from this host:

        the good match (its text literally contains the query words)
            bm25 = -2.8095418473796165
        a poor match (matched only on common words like 'the' and 'pass')
            bm25 = -1.0232558139534884e-06

    A mapping of the form 1/(1+|x|*k) turns those into 3.6e-06 and 0.907 --
    it RANKS THE WORST MATCH HIGHEST. That was the first implementation, and it
    was the whole text contribution of the score, so the ranking did the
    opposite of what it said. There is no fixed scale here to normalise to, so
    nothing is normalised: ORDER IS ALL THAT SURVIVES, and it is taken by
    ranking the candidates against each other. See _text_scores below.
    """
    try:
        return abs(float(raw))
    except (TypeError, ValueError):
        return 0.0


def _text_scores(rows: list) -> dict:
    """
    Turn the raw bm25 for a candidate set into a 0..1 score that PRESERVES the
    order bm25 produced.

    Rank-relative rather than absolute, because there is no absolute scale to
    use. The best text match in this result set scores 1.0 and the worst scores
    0.0, whatever the magnitudes are; every value between keeps bm25's own
    ordering exactly. A set with one row or with identical scores gives
    everyone 1.0 only if they actually matched -- a row present for a reason
    other than the text search (the rule+subject half of the query) has no bm25
    at all and is given 0.0 text contribution, which is the honest answer: the
    text search did not put it here.
    """
    scored = [(row.get("id"), row.get("_bm25")) for row in rows
              if row.get("_bm25") is not None]
    if not scored:
        return {}

    # More negative is better, so ascending order is best-first.
    ordered = sorted(scored, key=lambda pair: float(pair[1]))
    if len(ordered) == 1:
        return {ordered[0][0]: 1.0}

    best = float(ordered[0][1])
    worst = float(ordered[-1][1])
    span = worst - best

    out = {}
    for position, (row_id, value) in enumerate(ordered):
        if span == 0:
            # Every candidate matched equally well. Saying 1.0 for all of them
            # is a statement about the text, and it is true.
            out[row_id] = 1.0
        else:
            out[row_id] = round(1.0 - (position / (len(ordered) - 1)), 4)
    return out


def _rank_similar(seed: dict, candidates: list, limit: int) -> list:
    """
    Score candidates against the seed and explain each score.

    THE EXPLANATION IS THE PRODUCT. A model (or a person) reading
    "similarity 0.72" learns nothing it can act on and cannot audit; reading
    "same rule LNX-2002, same subject, text overlap" can be checked. So every
    hit carries `why`: the named fields that made it a match, in the order of
    how much they contributed.

    `text_scores` is passed in rather than computed per candidate, because the
    text half of the score is RANK-RELATIVE: it compares the candidates against
    each other, and a per-row function cannot see its own result set.
    """
    text_scores = _text_scores(candidates)

    scored = []
    for cand in candidates:
        why = []
        score = 0.0

        if seed.get("detection_id") and \
                cand.get("detection_id") == seed["detection_id"]:
            score += W_SAME_RULE
            why.append(f"same rule {cand['detection_id']}")

        same_entity = (
            seed.get("entity_type") and seed.get("entity_value") and
            cand.get("entity_type") == seed.get("entity_type") and
            cand.get("entity_value") == seed.get("entity_value"))
        if same_entity:
            score += W_SAME_ENTITY
            why.append(f"same subject ({cand.get('entity_type')} "
                       f"{cand.get('entity_value')})")
        elif seed.get("entity_type") and \
                cand.get("entity_type") == seed.get("entity_type"):
            score += W_SAME_TYPE
            why.append(f"same kind of subject ({cand.get('entity_type')})")

        if seed.get("source") and cand.get("source") == seed["source"]:
            score += W_SAME_SOURCE
            why.append(f"same sensor ({cand['source']})")

        rank_gap = abs(int(seed.get("severity_rank") or 0) -
                       int(cand.get("severity_rank") or 0))
        if rank_gap <= 1:
            score += W_SEVERITY
            if rank_gap == 0:
                why.append(f"same severity ({cand.get('severity')})")

        text_score = text_scores.get(cand.get("id"), 0.0)
        if text_score > 0:
            score += round(W_TEXT * text_score, 4)
            why.append("wording overlaps what you are looking at")

        if score < MIN_SCORE:
            continue

        cand["match_score"] = round(score, 4)
        cand["why"] = why
        scored.append(cand)

    scored.sort(key=lambda c: (-c["match_score"],
                               -(c.get("severity_rank") or 0),
                               str(c.get("last_seen_at") or "")))
    return scored[:limit]


def similar_incidents(detection_id: str = None, entity_type: str = None,
                      entity_value: str = None, title: str = None,
                      assessment: str = None, source: str = None,
                      severity: str = None, limit: int = SIMILAR_LIMIT_DEFAULT,
                      exclude_incident_id: int = None,
                      include_open: bool = True) -> dict:
    """
    Past incidents that resemble this one, with how each of them ended.

    TWO STAGES, AND THE SPLIT MATTERS. Stage one is the FTS index, which
    answers "which rows share words with this" and nothing else. Stage two is
    the ranking above, which is deterministic and readable. A single similarity
    number computed by a search engine would be unauditable; this way a reader
    can always ask which field caused a row to be here.

    A PRECEDENT IS EVIDENCE, NOT A VERDICT, and the shape of the return says
    so: every hit carries what was decided and by whom, and the block-level
    note says the thing that a hurried reader most needs -- that a dismissal in
    the past is a record of a decision about a different day.

    `include_open` is on by default because an incident that is still open is
    genuinely informative ("this is the third time this week and nobody has
    resolved any of them"). It is labelled rather than hidden.
    """
    limit = max(1, min(int(limit or SIMILAR_LIMIT_DEFAULT), 25))
    seed = {
        "detection_id": (detection_id or "").strip(),
        "entity_type":   (entity_type or "").strip().lower(),
        "entity_value":  (entity_value or "").strip(),
        "source":        (source or "").strip(),
        "severity":      (severity or "").strip(),
        "severity_rank": SEVERITY_RANK.get((severity or "").strip().lower(), 0),
    }

    out = {"seed": {k: v for k, v in seed.items() if v not in ("", None)},
           "precedents": [], "counts": {}, "index": index_lag(),
           "note": None, "how_to_read_this": PRECEDENT_NOTE}

    if not seed["detection_id"] and not seed["entity_value"] and \
            not (title or "").strip() and not (assessment or "").strip():
        out["note"] = ("Nothing was given to look for. Pass a detection id, a "
                       "subject, a title or an assessment. This is a refusal "
                       "and NOT a finding that no precedent exists.")
        out["counts"] = {"precedents": 0, "searched": False, "complete": False}
        return out

    fts = fts_available()
    if not fts["available"]:
        # The honest degradation. entity_history still answers; this half says
        # why it cannot.
        out["note"] = (fts["reason"] + " Use entity_history for 'has this "
                       "subject been seen before', which does not need the "
                       "index.")
        out["counts"] = {"precedents": 0, "searched": False, "complete": False}
        return out

    tokens = _query_tokens(seed["detection_id"], seed["entity_value"], title,
                           assessment)
    if not tokens:
        # A subject like an IP address or a file path with no words long enough
        # to search on is an ordinary case, not an error.
        out["note"] = ("There was no searchable wording in what was given (a "
                       "subject with no word-like parts), so the text half of "
                       "this search did not run. The results below are matches "
                       "on the rule id and the subject only.")
    match_expr = " OR ".join(f'"{t}"' for t in tokens) if tokens else None

    with me._get_readonly_conn() as conn:
        if not _index_ready(conn):
            out["note"] = (out["note"] or "") + (
                " The precedent index has not been built on this database "
                "yet, so NOTHING is searchable as a precedent. That is not "
                "the same as there being none: the watcher builds it on its "
                "next tick.")
            out["counts"] = {"precedents": 0, "searched": False,
                             "complete": False}
            return out

        sql = """
            SELECT i.id, i.detection_id, i.entity_type, i.entity_value,
                   i.severity, i.severity_rank, i.title, i.status, i.status_at,
                   i.status_by, i.assessment, i.assessed_at, i.finding_count,
                   i.first_seen_at, i.last_seen_at, i.coverage_note,
                   i.cia_json, i.source
              FROM case_index x
              JOIN incident i ON i.id = x.incident_id
        """
        params = []
        where = []

        if match_expr:
            sql = """
                SELECT i.id, i.detection_id, i.entity_type, i.entity_value,
                       i.severity, i.severity_rank, i.title, i.status,
                       i.status_at, i.status_by, i.assessment, i.assessed_at,
                       i.finding_count, i.first_seen_at, i.last_seen_at,
                       i.coverage_note, i.cia_json, i.source,
                       bm25(case_fts) AS _bm25
                  FROM case_fts
                  JOIN case_index x ON x.incident_id = case_fts.rowid
                  JOIN incident i ON i.id = case_fts.rowid
                 WHERE case_fts MATCH ?
            """
            params.append(match_expr)
        else:
            sql += " WHERE 1 = 1"

        if not include_open:
            where.append("i.status NOT IN ('new')")
        if exclude_incident_id is not None:
            where.append("i.id != ?")
            params.append(int(exclude_incident_id))

        if where:
            sql += (" AND " if "WHERE" in sql else " WHERE ") + \
                   " AND ".join(where)

        sql += " LIMIT 200"

        try:
            rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
        except sqlite3.OperationalError as e:
            logger.error(f"case_memory: precedent search failed: {e}")
            out["note"] = (f"The precedent index could not be searched "
                           f"({type(e).__name__}: {e}). This is a failure to "
                           f"look, NOT a finding that nothing like this ever "
                           f"happened.")
            out["counts"] = {"precedents": 0, "searched": False,
                             "complete": False}
            return out

        searched_text = bool(match_expr)
        out["counts"] = {"candidates": len(rows), "searched": True,
                         "text_searched": searched_text,
                         "tokens": tokens[:12],
                         # 'searched' and 'complete' are different claims, and
                         # the app has this vocabulary for exactly this reason.
                         # A search over an index that is BEHIND the ledger
                         # searched everything the index had and is not a
                         # complete answer about the ledger. Set properly at
                         # the end of this function, once the lag is known.
                         "complete": None}
        # The rule+subject half, which does not depend on the text search at
        # all. It runs SEPARATELY and its results are merged, because the case
        # that matters most -- "this exact rule on this exact subject, twice
        # last month" -- can have no word overlap with a title at all.
        keyed = []
        if seed["detection_id"] or seed["entity_value"]:
            key_sql = """
                SELECT id, detection_id, entity_type, entity_value, severity,
                       severity_rank, title, status, status_at, status_by,
                       assessment, assessed_at, finding_count, first_seen_at,
                       last_seen_at, coverage_note, cia_json, source
                  FROM incident
                 WHERE (detection_id = ? OR entity_value = ?)
            """
            key_params = [seed["detection_id"] or "\x00",
                          seed["entity_value"] or "\x00"]
            if exclude_incident_id is not None:
                key_sql += " AND id != ?"
                key_params.append(int(exclude_incident_id))
            key_sql += " ORDER BY last_seen_at DESC LIMIT 200"
            keyed = [dict(r) for r in conn.execute(
                key_sql, key_params).fetchall()]

        merged = {}
        for row in rows + keyed:
            merged.setdefault(row["id"], row)

    precedents = _rank_similar(seed, list(merged.values()), limit)
    for hit in precedents:
        try:
            hit["cia"] = json.loads(hit.pop("cia_json") or "[]")
        except (TypeError, ValueError):
            hit["cia"] = []
        hit["age_days"] = round(_age_days(hit.get("last_seen_at")), 2)
        hit["assessed"] = bool((hit.get("assessment") or "").strip())
        if not hit["assessed"]:
            hit["assessment"] = None
            hit["assessment_note"] = (
                "nobody has assessed this one; it records that something "
                "happened, not what it meant")
        else:
            hit["assessment"] = _clip(hit.get("assessment"), 900)
        if hit.get("coverage_note"):
            hit["coverage_note"] = _clip(hit["coverage_note"], 400)

    out["precedents"] = precedents
    out["counts"]["precedents"] = len(precedents)
    # COMPLETE IS DECIDED BY THE LAG, and this is the field a caller should
    # branch on rather than parsing the prose. `searched` says the search ran;
    # `complete` says whether its answer covers the whole ledger.
    lag = (out.get("index") or {}).get("lag")
    out["counts"]["complete"] = bool(
        (out.get("index") or {}).get("available") and not lag)
    out["note"] = _precedent_note(out)
    return out


PRECEDENT_NOTE = (
    "A PRECEDENT IS EVIDENCE, NOT A VERDICT. Each row here is a thing that "
    "happened and what somebody decided about it AT THE TIME, on a different "
    "day and usually a different subject. 'Dismissed' in this list means a "
    "person decided that incident was not worth acting on then; it says "
    "nothing about whether this one is. Read the coverage note on a row before "
    "leaning on its outcome: an incident dismissed while a sensor was blind "
    "was dismissed on no evidence."
)


def _precedent_note(out: dict) -> str:
    counts = out.get("counts") or {}
    lag = (out.get("index") or {}).get("lag")
    precedents = out.get("precedents") or []

    if not counts.get("searched"):
        return out.get("note")

    if not precedents:
        base = ("No incident on record resembles this one closely enough to "
                "show. ")
        if lag:
            return (base + f"BUT THE INDEX IS BEHIND BY {lag} INCIDENT(S), so "
                           f"this is not yet a claim about those. ")
        if (out.get("index") or {}).get("available"):
            return (base + "The index is current, so this IS a real negative: "
                           "nothing like this has been recorded here before. ")
        return base

    parts = [f"{len(precedents)} past incident(s) resemble this one."]
    if lag:
        parts.append(f"The index is behind by {lag} incident(s), so there may "
                     f"be more.")
    assessed = [p for p in precedents if p.get("assessed")]
    if assessed:
        parts.append(f"{len(assessed)} of them carry an assessment saying what "
                     f"was concluded.")
    if len(precedents) == len(assessed) and assessed:
        parts.append("Read what was concluded BEFORE deciding whether the "
                     "precedent applies: the reasons are on the rows.")
    return " ".join(parts)


# THE BRIEF -- what goes into an investigation's prompt
#
# THIS FUNCTION IS THE POINT OF THE WHOLE MODULE. Retrieval that the model has
# to remember to ask for is retrieval that gets used when somebody thinks of
# it, which is the same blank page with an extra step. The duty loop calls this
# BEFORE the model is asked anything, and the result is part of the prompt, so
# every unattended investigation STARTS with the patient file open.

def brief_for_incident(row: dict, *, limit: int = SIMILAR_LIMIT_DEFAULT,
                       history_limit: int = 6) -> dict:
    """
    The case file for one incident: this subject's history, and precedents.

    Never raises. A memory that cannot be read must say so in the brief rather
    than stopping the investigation -- an incident that goes unexamined because
    the MEMORY was down is a worse outcome than one examined without it, and
    the brief says which of the two happened so the assessment can be read
    accordingly.
    """
    brief = {"subject_history": None, "precedents": None,
             "memory_available": True, "note": None}

    try:
        history = entity_history(row.get("entity_type") or "",
                                 row.get("entity_value") or "",
                                 limit=history_limit)
        brief["subject_history"] = history
    except Exception as e:                              # noqa: BLE001
        brief["memory_available"] = False
        brief["note"] = (f"This subject's own history could not be read "
                         f"({type(e).__name__}: {e}). This investigation is "
                         f"running WITHOUT the patient file.")
        logger.error(f"case_memory: entity history failed for "
                     f"{row.get('entity_type')} {row.get('entity_value')}: {e}")

    try:
        brief["precedents"] = similar_incidents(
            detection_id=row.get("detection_id"),
            entity_type=row.get("entity_type"),
            entity_value=row.get("entity_value"),
            title=row.get("title"),
            source=row.get("source"),
            severity=row.get("severity"),
            limit=limit,
            exclude_incident_id=row.get("id"),
        )
    except Exception as e:                              # noqa: BLE001
        brief["memory_available"] = False
        brief["note"] = ((brief["note"] or "") +
                         f" Precedent retrieval failed "
                         f"({type(e).__name__}: {e}); this investigation has "
                         f"no past cases to compare against.").strip()
        logger.error(f"case_memory: precedent search failed: {e}")

    return brief


def render_brief(brief: dict) -> str:
    """
    The case file as the text that goes into a prompt.

    Kept here rather than in core/duty so the wording lives next to the data it
    describes, and so the duty loop's prompt cannot drift into describing a
    shape the memory does not return. The lines are plain and bounded: this is
    read by a model on a token budget and by a person on the Agents page.
    """
    if not brief:
        return ("CASE MEMORY: unavailable for this run. You are working this "
                "incident with no history. Say so in your report.")

    lines = []
    history = brief.get("subject_history")
    if history:
        counting = history.get("counting") or \
            "Nothing about this subject is on record."
        lines.append(f"SUBJECT HISTORY ({history['entity_type']} "
                     f"{history['entity_value']}): {counting}")
        for inc in (history.get("incidents") or [])[:5]:
            decided = (f"{inc['status']} by {inc['status_by']}"
                       if inc.get("status") else "no status")
            when = inc.get("last_seen_at") or "unknown"
            lines.append(
                f"  - incident {inc['id']} [{inc['detection_id']}] "
                f"{inc['severity']}, {decided}, last seen {when} "
                f"({inc['age_days']}d ago)"
                + (f": {inc['assessment']}" if inc.get("assessed")
                   else " (never assessed)"))
        if history.get("findings_capped"):
            lines.append(f"  ({len(history['findings'])} of "
                         f"{history['findings_total']} findings shown)")
        for act in (history.get("actions") or [])[:4]:
            lines.append(f"  - action {act['verb']} on {act['target']}: "
                         f"{act['state']}"
                         + (f" ({act['outcome']})" if act.get("outcome")
                            else ""))
    elif brief.get("memory_available") is False:
        lines.append("SUBJECT HISTORY: could not be read this run.")

    precedents = brief.get("precedents")
    if precedents:
        note = precedents.get("note") or ""
        lines.append(f"SIMILAR PAST INCIDENTS: {note}")
        for hit in (precedents.get("precedents") or []):
            decided = (f"{hit['status']} by {hit['status_by']}"
                       if hit.get("status") else "no status recorded")
            lines.append(
                f"  - incident {hit['id']} [{hit['detection_id']}] "
                f"{hit['severity']}, {decided}, {hit['age_days']}d ago "
                f"(matched: {'; '.join(hit.get('why') or []) or 'n/a'})")
            if hit.get("assessment"):
                lines.append(f"    what was concluded: {hit['assessment']}")
            elif hit.get("assessment_note"):
                lines.append(f"    {hit['assessment_note']}")
            if hit.get("coverage_note"):
                lines.append(f"    coverage then: {hit['coverage_note']}")

    if not lines:
        return ("CASE MEMORY: nothing on record for this subject and no "
                "similar past incident.")

    # THE WARNING IS UNCONDITIONAL WHENEVER THE FILE IS OPENED.
    #
    # It was attached only to the precedent list in the first draft, and a test
    # running against a subject with HISTORY BUT NO PRECEDENTS caught it: the
    # brief for a file that had been seen once, dismissed once, rendered the
    # disposition with no framing at all. That is the more dangerous case of
    # the two, not the lesser one -- a single line reading "dismissed by user"
    # with nothing around it is exactly the sentence that gets read as
    # permission, and it is the shape most briefs will actually have, because
    # most subjects have one incident rather than five.
    lines.append(_precedent_warning(precedents or {}))

    if brief.get("note"):
        lines.append(f"READ THIS: {brief['note']}")
    return "\n".join(lines)


def _precedent_warning(precedents: dict) -> str:
    return ("  HOW TO USE THIS: A PRECEDENT IS EVIDENCE, NOT A VERDICT. These "
            "are things that HAPPENED, not advice. A past dismissal is a "
            "decision somebody made about a different day and is not a reason "
            "to dismiss this one. If a precedent changes your view, say which "
            "one and why; if none of them applies, say that instead.")


# HEALTH, FOR sensor_health AND THE PAGE
#
# The key names here are the contract: blind, blind_reason, running, ready,
# reachable, last_error. Anything else is IGNORED by
# core/sensor_health._module_trouble, which is how a component ships
# blind-and-silent. See the wiring note in references/new-sensor-wiring.md.
#
# `blind` IS FOR FAILURES, NOT FOR PERMANENT LIMITS. A missing FTS5 build is a
# permanent property of this install and is reported in `note` and in every
# result, not as blindness -- reporting blind for it would attach a caveat to
# every answer for the life of the installation and teach its reader to skim.
#
# A LAGGING INDEX IS NOT BLINDNESS EITHER. It is a number. Blindness is
# reserved for: the ledger unreadable, the index unreadable, a write failing.

def status() -> dict:
    """
    What case memory can and cannot do right now.

    Never raises: it is called during a shutdown rollup and inside the health
    page, and a health reporter that throws takes the report down with it.

    THE THREE STATES HERE ARE KEPT APART, and the first draft got this wrong
    in a way the health page made visible: an index that has never been BUILT
    (a database one migration behind) was reported as `reachable: False`, which
    core/sensor_health._module_trouble turns into "case_memory is NOT
    ANSWERING: no reason recorded" -- a failure claim about a component that
    is working, on a subject it never asked about. Measured, not guessed.

      1. THE LEDGER IS UNREADABLE            -> blind, with a reason. A real
                                               failure.
      2. THE LEDGER IS READABLE, THE INDEX
         IS NOT BUILT OR IS BEHIND           -> reachable and NOT blind. Entity
                                               history works, which is half of
                                               what this module is for, and the
                                               lag is a NUMBER on the note.
      3. BOTH CURRENT                        -> ready.

    `ready` is the only key that tracks the index, because it is the one key
    _module_trouble consults LAST and only through the `running`/`ready`/
    `available` fallback.
    """
    out = {"running": True, "ready": False, "reachable": False,
           "role": "case_memory"}
    fts = fts_available()
    out["fts"] = fts

    try:
        lag = index_lag()
        out["index"] = lag
        # REACHABLE MEANS "CAN IT BE READ AT ALL", and the ledger being
        # readable is the whole of that question. See the three states above.
        out["reachable"] = bool(lag.get("incidents") is not None or
                                lag.get("available"))

        if not lag.get("available"):
            # The index table does not exist. entity_history still answers.
            out["ready"] = False
            out["note"] = lag.get("note")
            out["degraded"] = "precedent search unavailable: the index is not built"
        elif lag.get("lag"):
            out["ready"] = False
            out["note"] = (f"{lag['lag']} incident(s) are in the ledger and "
                           f"not yet in the memory index. Entity history is "
                           f"complete; a precedent search until the next tick "
                           f"may miss them.")
            out["degraded"] = f"index behind by {lag['lag']}"
        else:
            out["ready"] = True
            out["note"] = (f"{lag.get('indexed', 0)} incident(s) indexed and "
                           f"current.")
    except Exception as e:                              # noqa: BLE001
        out["blind"] = True
        out["blind_reason"] = (f"case memory could not read the ledger "
                               f"({type(e).__name__}: {e})")
        out["last_error"] = f"{type(e).__name__}: {e}"

    if not fts["available"]:
        out["precedent_search"] = False
        out["note"] = ((out.get("note") or "") +
                       " Precedent search is unavailable on this install: " +
                       (fts["reason"] or "")).strip()
    else:
        out["precedent_search"] = True

    return out


def summary() -> dict:
    """Counts for the dashboard and the model, never summed into one number."""
    try:
        with me._get_readonly_conn() as conn:
            if not _table_ready(conn, "incident"):
                return {"available": False,
                        "note": ("no incident table yet, so there is nothing "
                                 "to remember. This is not an empty memory.")}
            total = conn.execute("SELECT COUNT(*) FROM incident").fetchone()[0]
            if not _index_ready(conn):
                return {"available": True, "incidents": total, "indexed": 0,
                        "lag": None,
                        "note": (f"{total} incident(s) exist and NONE are "
                                 f"indexed, so no precedent can be found. "
                                 f"The watcher builds the index on its next "
                                 f"tick.")}
            indexed = conn.execute(
                "SELECT COUNT(*) FROM case_index").fetchone()[0]
            assessed = conn.execute(
                "SELECT COUNT(*) FROM case_index WHERE assessed = 1"
            ).fetchone()[0]
            decided = {}
            for row in conn.execute(
                    "SELECT status, COUNT(*) n FROM case_index "
                    "GROUP BY status"):
                decided[row["status"]] = row["n"]
    except Exception as e:                              # noqa: BLE001
        return {"available": False,
                "note": f"case memory could not be read: {e}"}

    return {
        "available": True,
        "incidents": total,
        "indexed": indexed,
        "lag": max(0, total - indexed),
        "assessed": assessed,
        "by_status": decided,
        "fts": fts_available()["available"],
        "how_to_read_this": (
            "assessed is how many incidents carry an assessment, which is the "
            "only kind worth reading as a precedent. lag is how many incidents "
            "the index has not seen; while it is above zero a precedent "
            "search is answering about an earlier state of the ledger."),
    }
