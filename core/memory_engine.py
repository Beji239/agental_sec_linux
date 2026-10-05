# core/memory_engine.py
# AgentalSec V2, Database connection and query layer
# All tools import from here. Returns dicts/lists only, no SQLite Row objects.
# Model has READ access to all tables via these functions.
# Model has WRITE access only to behavioral_session, behavioral_baseline, behavioral_deviation.

import sqlite3
import json
import logging
import os
import re
from pathlib import Path
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager

# core.voice imports nothing from this project (stdlib only), so this is the
# one project import here and it cannot make a cycle. It holds the rule about
# who a sentence in a tool result is addressed to. TODO 113.1, ported
# 2026-09-21 with query_tls, which is the caller that needs it.
from core import voice

logger = logging.getLogger(__name__)

# DB lives in project root, same folder as main.py
#
# TODO 108, 2026-09-14. AGENTALSEC_TEST_DB REPOINTS THIS, AND IT EXISTS FOR
# ONE REASON.
#
# Five test files reached the real database. They did not mean to and they do
# not mention it: they exercise code that writes through DB_PATH, and nothing
# repointed DB_PATH, so the writes landed in the project root beside main.py,
# which on a real install is the evidence store. Two of them were inserting
# rows on every suite run: nine bogus offline sensors from the pcap tests,
# each with a fresh random id so they accumulate rather than overwrite, and an
# enrichment_queue row for the test runner's own python process.
#
# The environment variable is named with TEST in it on purpose. A path to the
# database is the kind of setting that drifts into a .env because it looks
# like configuration, and this one is not: a value here silently moves the
# whole app onto a different database. The name is meant to make that obvious
# to whoever reads the .env, and scripts/run_tests.py is the only thing in
# this project that sets it.
_test_db = os.environ.get("AGENTALSEC_TEST_DB", "").strip()
DB_PATH = Path(_test_db) if _test_db else Path(__file__).parent.parent / "agental_sec.db"
if _test_db:
    logger.warning("AGENTALSEC_TEST_DB is set, using %s and NOT the real "
                   "database. If this is not a test run, unset it.", DB_PATH)

# Tables model is allowed to write to, enforced in write functions
MODEL_WRITABLE_TABLES = {
    "behavioral_session",
    "behavioral_baseline",
    "behavioral_deviation",
}

# BAD INPUT, AS ITS OWN THING
#
# 2026-09-03. api/routes.py had one handler turning EVERY ValueError raised
# during a request into a 400 "Bad request". The intent was right: this
# file's validation messages are written for a person to read and they were
# never reaching the caller. The net was far too wide though. A ValueError
# from anywhere else, a sensor, a parser, some arithmetic, came back as a 400
# carrying the internal message, which is the server telling the caller they
# were wrong when the server is the thing that broke. That is the exact
# inversion the handler's own comment said it was there to fix, and it hides
# real defects behind a status code nobody bothers to investigate.
#
# So bad input gets its own class. It still subclasses ValueError, so every
# existing `except ValueError` keeps working and nothing outside this file
# has to change. The route layer catches BadInput for its 400, and a plain
# ValueError is a 500 again, because that is what it is.
class BadInput(ValueError):
    """The caller passed something invalid. Not a defect in this tool."""


# Valid entity types, enforced on all behavioral writes
#
# 'file' ADDED 2026-09-22 WITH L3, and this is the one line that decides
# whether the local integrity findings are usable. dismiss_entity goes through
# _validate_entity, and the two behavioral writers below it do too. A finding
# whose entity_type is not in this set cannot be dismissed by a person, which
# is the wrong way round: the whole point of dismissal is that a noisy-but-real
# check can be quietened by somebody who looked.
#
# The two remediation rows that already wrote entity_type='file' (REM-1006
# quarantine, REM-1007 restore) were passing through save_finding, which does
# NOT validate, so they were written and could not then be dismissed. Adding
# the type fixes them too.
VALID_ENTITY_TYPES = {"ip", "process", "port", "user", "file"}

# WHAT KIND OF THING A BASELINE ROW IS. v26, 2026-09-02. See
# write_behavioral_observation for the two real rows that forced it.
#
#   measured          this tool watched it happen here
#   external_intel    somebody else's database said so. Dated, goes stale.
#   model_conclusion  the model reasoned to it. Nothing behind it but that.
#
# NULL means the row predates v26 and the question was never asked, which is
# NOT the same as measured and is never counted as it.
#   operator_stated   the owner told us, v32. See below.
#
# operator_stated is the FOURTH kind and none of the other three fit it. The
# owner answered a question the tool could not answer itself: "that address is
# my work laptop", "yes I changed that setting on Sunday". Nothing measured
# it, no registry stated it, the model did not reason to it. A person who was
# there said so.
#
# It is the strongest value here for one narrow class of question, is this
# yours, is this expected, did you do this, and that is the same authority the
# probe enrollment already rests on because there is no Intune on this
# network. It is NOT a measurement and must never be filed as one. People
# misremember, and an answer about last Tuesday is not a packet.
#
# THIS SET IS THE REAL GATE, not the CHECK in Schema.SQL. v26 added the basis
# column with ALTER TABLE ADD COLUMN and SQLite cannot attach a CHECK that
# way, so an existing database has no constraint on that column at all while a
# fresh one does. Both shapes come through here.
VALID_OBSERVATION_BASIS = {"measured", "external_intel", "model_conclusion",
                           "operator_stated"}

# Valid behavior keys per entity type
#
# operator_answer added v32, 2026-09-14, on all four. It holds what the owner
# said when the model asked the owner something it could not work out, and it is on
# every entity type because the question queue covers all four.
#
# WHY IT IS ITS OWN KEY AND NOT user_action_history. That key records things
# the owner DID through this app, dismissals and approvals, which the app
# watched happen. This records something the owner SAID about the world outside the
# app, which nothing here can check. Filing them under one name would make a
# statement and an action indistinguishable a month later, which is the same
# class of mistake the basis column exists to prevent.
VALID_BEHAVIOR_KEYS = {
    "ip": {
        "beacon_interval", "beacon_destinations", "connection_count",
        "avg_packet_size", "active_hours", "open_ports_inbound",
        "open_ports_outbound", "typical_dest_ports", "typical_dest_ips",
        "volume_per_session", "first_seen", "user_action_history",
        "operator_answer",
    },
    "process": {
        "typical_parent", "typical_network_ports", "typical_paths",
        "spawn_frequency", "user_action_history", "operator_answer",
    },
    "port": {
        "typical_process", "open_frequency", "typical_direction",
        "last_seen_open", "operator_answer",
    },
    "user": {
        "login_hours", "login_sources", "typical_processes",
        "failed_login_count", "user_action_history", "operator_answer",
    },
}

# WHAT A VALUE IS ALLOWED TO LOOK LIKE
#
# 2026-09-07. VALID_BEHAVIOR_KEYS checks the KEY. Nothing checked the VALUE,
# so when the model had two key choices rejected it reached for a key that was
# spellable and wrote a sentence into it. active_hours on the router now holds
# prose about why the router matters. The rollup reads that key expecting
# hours.
#
# A wrong key is loud, it gets refused with a list of the real ones. A wrong
# VALUE in a right key is silent, and it is read later as a measurement of the
# thing the key names.
#
# Only the two families whose shape is beyond argument are checked. Guessing
# at the shape of typical_paths or user_action_history would refuse honest
# writes, which is worse than the problem: a validator people work around is
# a validator that has stopped being one.
_HOUR_KEYS = {"active_hours", "login_hours"}
_PORT_KEYS = {"open_ports_inbound", "open_ports_outbound", "typical_dest_ports",
              "typical_network_ports"}

# Long enough for a real list of hours, ports or addresses. Anything past it
# is a paragraph, and a paragraph is not a value.
_MAX_VALUE_CHARS = 300


def _numbers_in(value: str) -> list[int] | None:
    """
    Every number in the value, or None if it holds anything that is not part
    of writing a list or a range of them.

    Kept deliberately permissive about FORM: "22", "9-17", "8, 9, 10" and
    "22:00 UTC" all pass. What it refuses is words.
    """
    import re
    text = str(value)
    # Words a real list of hours or ports is allowed to carry.
    text = re.sub(r"(?i)\b(utc|local|hours?|hrs?|am|pm)\b", "", text)
    # Punctuation a real list is allowed to carry. Brackets included: "[1,2]"
    # is how a list arrives when something json-dumped it, and refusing that
    # was a false positive the suite caught immediately.
    leftover = re.sub(r"[0-9,\-:.\s\[\]\(\)\{\}\"'h]", "", text)
    if leftover.strip():
        return None
    return [int(n) for n in re.findall(r"\d+", text)]


def _validate_behavior_value(behavior_key: str, value):
    """Raise BadInput when the value cannot be what the key says it is."""
    text = str(value)

    if len(text) > _MAX_VALUE_CHARS:
        raise BadInput(
            f"behavior_value is {len(text)} characters, which is a paragraph "
            f"rather than a value. A behaviour value is the measurement, not "
            f"the explanation of it. Put the reasoning in `context`, which "
            f"exists for exactly that, and leave this field as the value "
            f"itself."
        )

    if behavior_key in _HOUR_KEYS:
        nums = _numbers_in(text)
        if nums is None or not nums or any(n > 23 for n in nums):
            raise BadInput(
                f"{behavior_key!r} holds HOURS OF THE DAY, as numbers from 0 "
                f"to 23. Got {text!r}. Valid examples: '22', '9-17', "
                f"'8,9,10', '22:00 UTC'. If what you meant to record is not "
                f"an hour, this is the wrong key, and writing it here would "
                f"be read later as a measurement of when this entity is "
                f"active. Put prose in `context`."
            )

    if behavior_key in _PORT_KEYS:
        nums = _numbers_in(text)
        if nums is None or not nums or any(not 1 <= n <= 65535 for n in nums):
            raise BadInput(
                f"{behavior_key!r} holds PORT NUMBERS, 1 to 65535. Got "
                f"{text!r}. Valid examples: '445', '80,443', '8000-8100'. If "
                f"what you meant to record is not a port, this is the wrong "
                f"key. Put prose in `context`."
            )


# DIRECTIONAL BEHAVIOUR KEYS
#
# Added 2026-08-29. Some behaviour keys are not neutral labels: they assert a
# ROLE for the entity they are filed against. beacon_destinations means "the
# places this host reaches out to". Filing an address there says something
# here connected to it.
#
# VALID_BEHAVIOR_KEYS checks only that a key is spellable for the entity
# type. It cannot tell whether the observation means what the key says, and
# on 2026-08-28 that gap was used: two addresses that had only ever been
# SOURCES of inbound multicast were written to beacon_destinations, which
# recorded an outbound relationship that never happened. Beaconing is a C2
# signal, so a fabricated one is the worst kind to leave in memory.
#
# The check below does not decide whether a write is right, and does not
# refuse it. It reports what the packets table does and does not
# corroborate. See corroborate_direction for why it reports rather than
# rules.
DIRECTIONAL_KEYS = {
    "beacon_destinations": "destination",
    "typical_dest_ips":    "destination",
}

VALID_CONFIDENCE   = {"low", "medium", "high"}

def _journal(operation: str, table_name: str = None, row_ref=None,
             payload=None):
    """
    Append to the integrity journal, and NEVER let it affect the caller.

    Item 3.2. The guarantee this feature has to keep is that journaling can
    never break, delay or roll back the write it records. An integrity
    control that takes the app down during an incident gets switched off, and
    then it protects nothing at all.

    So the try/except lives HERE, at every call site, rather than only inside
    core.integrity. A test replaced the journal with something that raises and
    the write died, which showed the protection was one refactor away from
    being gone. Now the writer is safe even if the journal module is broken,
    missing, or swapped out entirely.

    The import is deferred because core.integrity reads DB_PATH from this
    module, so a module-level import would be circular. Same reason
    _suppression_flag defers tool_registry.
    """
    try:
        from core import integrity
        return integrity.record(operation, table_name, row_ref, payload)
    except Exception as e:
        logger.error(f"integrity journal unavailable ({operation}): {e}")
        return None


class _JournalShim:
    """Kept so `ig.record(...)` call sites read naturally. Delegates to
    _journal, which is where the guarantee is enforced."""

    record = staticmethod(_journal)


ig = _JournalShim()

VALID_ACTION_TAKEN = {"alerted", "logged", "blocked", "ignored", "quarantined"}
# 'unreviewed' added 2026-08: the silence timer now resolves to this instead
# of 'normal'. Silence is absence of evidence, not evidence of normality.
VALID_RESOLVED_AS  = {
    "normal", "threat", "investigating", "ignored", "false_positive", "unreviewed",
}
VALID_SEVERITY     = {"critical", "high", "medium", "low", "info"}
MAX_QUERY_LIMIT    = 500

# Severities the silence timer must never auto-resolve or baseline.
# A critical finding that nobody answered is an UNANSWERED critical finding.
SILENCE_PROTECTED_SEVERITIES = {"critical", "high"}

# Ceiling on confidence that silence alone can produce. Reaching 'high'
#, and therefore alert_suppressed, requires an affirmative signal.
MAX_SILENCE_CONFIDENCE = "medium"


# CONNECTION HELPERS

@contextmanager
def _get_conn():
    """Context manager, always returns dicts, always closes cleanly."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def _get_readonly_conn():
    """
    A handle that CANNOT write, enforced by SQLite rather than by policy.

    D1, 2026-08-28. THE POINT IS THAT THIS IS A PROPERTY OF THE CONNECTION,
    NOT A SENTENCE IN A TOOL DESCRIPTION.

    The inventory is meant to be something the model reads and never edits.
    That is true today because no tool writes it: there is no
    set_device_permanence in the manifest, no merge_devices, no probe. That is
    the primary boundary and it is a good one, but it is upheld by everyone
    who ever adds a tool remembering why, and it says nothing at all about a
    READ path that mutates by accident.

    `mode=ro` moves the guarantee down a layer. A write attempted through this
    handle fails inside SQLite with "attempt to write a readonly database",
    whatever the calling code meant to do. A description is a request; this is
    a fact.

    Used by the model-facing read functions. Writes keep the ordinary handle,
    because they are supposed to write and are gated separately.

    NOTE ON SCOPE. The original sketch was a separate inventory FILE opened
    read-only. The security property people wanted from that is the read-only
    HANDLE, which is what this is; the separate file would add isolation of
    the bytes, at the cost of migrating a populated table and losing joins
    across it. That trade was not worth taking blind, so the handle landed
    first and the file split is still available if isolation is ever wanted
    for its own sake.

    Falls back to the ordinary connection when the database does not exist:
    read-only mode cannot create a file, and a fresh install would otherwise
    fail at boot rather than at a write. That is the safe direction, there
    is nothing to protect in a database that does not exist, and it is
    logged so it can never be the silent explanation for a later surprise.
    """
    path = Path(DB_PATH)
    if not path.exists():
        logger.debug("Read-only handle requested before the database exists; "
                     "falling back to the ordinary connection.")
        with _get_conn() as conn:
            yield conn
        return

    conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# SQLite writes CURRENT_TIMESTAMP as "YYYY-MM-DD HH:MM:SS" in UTC, with no
# marker saying so. That naive string is the bug: JavaScript's Date() parses a
# space-separated timestamp with no zone as LOCAL time, so a UTC 22:34 rendered
# in the dashboard read as 10:34 PM local when the event actually happened at
# 3:34 PM. Every timestamp in the interface sat hours in the future.
#
# For a security tool that is not cosmetic. Timelines are the product. An
# analyst reading a scan as having run at 10 PM when it ran at 3 PM has the
# wrong story, and the tool sounded confident about it.
#
# Storage stays UTC, which is correct and portable. What changes is that the
# value leaving this module says so. One funnel, every table fixed at once.
_NAIVE_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?$")


def _to_iso_utc(value):
    """
    Tag a naive SQLite timestamp as UTC. Anything else passes through.

    Matched by SHAPE rather than by column name. A list of timestamp column
    names is a list that goes stale the first time someone adds a column, and
    the failure would be silent and identical to this one.
    """
    if not isinstance(value, str) or not _NAIVE_TIMESTAMP.match(value):
        return value
    return value.replace(" ", "T", 1) + "Z"


def _rows_to_dicts(rows) -> list[dict]:
    """Convert sqlite3.Row list to plain dicts, with timestamps marked UTC."""
    return [{k: _to_iso_utc(v) for k, v in dict(r).items()} for r in rows]


# FILTER VALUES AND THE COLUMN THEY ARE COMPARED AGAINST
#
# FOUND 2026-09-24 BY TRACING THE TIMELINE TAB, and it was not a defect in
# that page. Every `since` filter in this module compared the caller's string
# against a stored timestamp, and SQLite compares TEXT byte-wise.
#
# THE STORE WRITES TWO SHAPES AND ONLY TWO, measured across every *_at column
# in the live database:
#
#   'YYYY-MM-DD HH:MM:SS'          what CURRENT_TIMESTAMP writes. 17 of the 18
#                                  filtered columns, hundreds of thousands of
#                                  rows: packets, events, findings, presence,
#                                  port scans, deviations, router clients.
#   'YYYY-MM-DDTHH:MM:SS+00:00'    what dns_monitor._iso() and
#                                  save_tls_hellos() write. tls_hello.
#
# `T` is 0x54 and a space is 0x20, so 'T' sorts AFTER ' '. Compare an ISO-Z
# cutoff ('...T18:27:01.158Z') against a space-shaped column and EVERY row on
# the cutoff's own date compares less than the cutoff and fails `>=`, whatever
# its time. Measured on the live store before the fix:
#
#   cutoff 2h, ISO-Z   -> findings 0, events 0, packets 0
#   same window, space -> findings 7, events 500, packets 500
#   cutoff 24h, ISO-Z  -> 39 findings, where the store answers 43
#   cutoff 12h, ISO-Z  -> 0 events, where the store answers 500
#
# That is the whole content of the Timeline tab's default window, which is why
# it read "No activity in this window" on a machine capturing thousands of
# rows an hour. It was ALSO every model tool call whose description says "ISO
# timestamp", which is what those descriptions have said since they were
# written, so the model has been quietly losing the newest rows in every since
# query it has ever made.
#
# WHY THE FIX IS HERE AND NOT IN THE CALLERS. The UI would be fixed by sending
# the space shape and that would FIX NOTHING for the model, whose own schema
# advertises ISO and whose input nobody normalizes. The model cannot be made
# to send the right shape; the boundary it passes through can be made to stop
# caring. One funnel, every query fixed at once, exactly like _to_iso_utc one
# line up: that one tags what leaves, this one normalizes what arrives.
#
# THE VALUE IS REBUILT, NOT SLICED, and that is the lesson of a wrong first
# version. The first draft took min(isoform, spaceform) as "the floor", and it
# is not one:
#
#   asked  '2026-09-24T18:27:01Z'  ->  '2026-09-24 18:27:01'
#   a row  '2026-09-24T18:27:01Z'  compares GREATER than that cutoff, so a
#                                  row written AT the cutoff was dropped.
#
# It also mangled the compact form 'YYYYMMDDTHH:MM:SS' into 'YYYYMMDD HHMMSS'
# by replacing the separator at its own (earlier) index, which is not a
# timestamp in any calendar. Both were found by driving the helper rather than
# by reading it, and both are the same fault: a shape that is not understood
# being rewritten anyway. So now the value is PARSED and RE-EMITTED as the
# exact string the target column holds, which needs no hedge because it is
# exactly right, and a shape that cannot be parsed is REFUSED with the
# accepted forms named in the message.
#
# THE TWO TRAPS, both found by running it:
#
#   1. PYTHON 3.11+ PARSES `Z`. `datetime.fromisoformat('...Z')` returns an
#      aware datetime, and the first version refused every Z cutoff on the
#      grounds of "carries an offset" -- which is the exact string the UI
#      sends for EVERY window, so the refusal would have replaced an empty
#      timeline with a broken one. A Z names no zone the digits do not already
#      name, so it is normalized; only a NON-ZERO offset is refused, because
#      answering that needs the comparison done in SQLite, there is no index
#      on the expression, and the packets table alone holds 458,649 rows on
#      this host -- on every page load and every model query.
#   2. A CUTOFF WITH NO ZONE IS UTC. `CURRENT_TIMESTAMP` writes UTC, so
#      reading a naive cutoff as UTC is the honest reading of this store and
#      the one the page has always made (see parseUtc in ui/index.html, which
#      does exactly this). Both writers that emit the other shape are also
#      UTC, so one reading covers every column.
# The two shapes the store actually holds, named so a call site can say which
# one it is filtering. A default would be right for 17 columns and silently
# wrong for the eighteenth, which is the defect this whole block is about.
SHAPE_SPACE_UTC = "space_utc"        # 'YYYY-MM-DD HH:MM:SS'      CURRENT_TIMESTAMP
SHAPE_ISO_OFFSET = "iso_offset"      # 'YYYY-MM-DDTHH:MM:SS+00:00'  the dns/tls writers


def _sql_datetime(value: str, shape: str = SHAPE_SPACE_UTC) -> str:
    """
    A caller's cutoff, re-emitted in the shape of the column it filters.

    Accepts what the UI sends ('2026-09-24T18:27:01.158Z'), what the model is
    told to send ('ISO timestamp'), and what this module already sends
    internally (the space form). Raises BadInput for anything that cannot be
    placed on the store's timeline without guessing.

    THE ACCEPTED SET IS WIDER THAN THE MESSAGE USED TO SAY, and that is worth
    stating because a refusal naming two shapes while six are taken is the
    prose-drifted-from-code fault this project keeps recording. Measured, all
    six of these are accepted and all six resolve to the same instant as the
    space form: 'YYYY-MM-DD HH:MM:SS', 'YYYY-MM-DDTHH:MM:SS',
    'YYYY-MM-DDTHH:MM:SSZ', 'YYYY-MM-DDTHH:MM:SS.sssZ',
    'YYYY-MM-DDTHH:MM:SS+00:00', and a BARE DATE 'YYYY-MM-DD'.

    A bare date is KEPT rather than refused, and it is not a hedge: it is a
    real ISO 8601 form, it reads unambiguously as the start of that day in the
    store's own zone (UTC, like every other value here), and refusing it would
    break a caller for no gain. What was missing was not a refusal, it was the
    sentence that says so. The refusal messages name it now.

    A FALSY value never reaches here: every call site guards with `if since`,
    so None and '' mean "no filter" and are passed over. That is deliberate
    and it is the HTTP reading of an absent query parameter. Note the
    asymmetry and that it is intended: WHITESPACE is truthy, so it does reach
    this function and IS refused, because a caller who typed spaces meant to
    filter by something and there is nothing there to filter by.

    `shape` is required knowledge, not a preference: tls_hello and dns_queries
    are written by the two writers that emit an offset, every other filtered
    column is written by CURRENT_TIMESTAMP. See the block above. A default
    would be right for seventeen of them and silently wrong for the rest.
    """
    if not isinstance(value, str) or not value.strip():
        raise BadInput(
            f"A since/until filter was given as {value!r}. It must be a "
            f"timestamp string like '2026-09-24 18:27:01' or "
            f"'2026-09-24T18:27:01Z'.")

    text = value.strip()

    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        # INCLUDING 'session_start' AND 'now', which are the two sentinels the
        # packet queries accept. They are tested BY NAME at their own call
        # site before it ever builds a WHERE, because they are keywords rather
        # than cuts and a filter helper has no business guessing which one a
        # caller meant. Reaching here with one is a bug at that call site, and
        # this message says what a real value looks like.
        raise BadInput(
            f"A since/until filter was given as {value!r}, which is not a "
            f"timestamp this store can compare against. Use "
            f"'YYYY-MM-DD HH:MM:SS' (UTC), the ISO form "
            f"'YYYY-MM-DDTHH:MM:SSZ', or a bare date 'YYYY-MM-DD' for the "
            f"start of that day UTC.")

    if shape == SHAPE_ISO_OFFSET:
        # What dns_monitor._iso() and save_tls_hellos() both emit:
        # `datetime(...).isoformat()`, and the comparison is TEXT against it.
        #
        # THE FRACTION IS DROPPED HERE TOO, and that is the same fix as the
        # space path below rather than a second decision. The writers build
        # their value from a whole number of seconds -- `.isoformat()` on a
        # datetime whose microseconds are ZERO -- so the column holds
        # '...T20:03:01+00:00' and NOTHING with a fraction. A caller's
        # milliseconds therefore have to go, and this branch used to KEEP
        # them: measured on a throwaway store, a cutoff of
        # '...T20:03:01.413Z' became '...T20:03:01.413000+00:00', the row at
        # '...T20:03:01+00:00' compares LESS than that at the same second
        # ('.' 0x2E sorts after '+' 0x2B), and query_tls returned 0 rows for
        # a row that is inside the window. The same defect one second wide.
        #
        # It is not only the page that sends milliseconds: .isoformat() with
        # no timespec keeps them when the datetime carrying them is "now".
        # Every writer on these two columns truncates, so the cutoff does too.
        when = dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
        return when.astimezone(timezone.utc).replace(
            microsecond=0).isoformat()

    if dt.tzinfo is not None and dt.utcoffset() != timedelta(0):
        raise BadInput(
            f"A since/until filter was given as {value!r}, which carries a "
            f"UTC offset. This store's comparison is TEXT against a "
            f"space-separated UTC column, so an offset cannot be applied to "
            f"it in a way that can use the index. Convert it first, or pass "
            f"it without the offset: 'YYYY-MM-DD HH:MM:SS' is read as UTC.")

    # The exact string CURRENT_TIMESTAMP writes. It writes NO fraction, and
    # that is measured rather than assumed: zero rows across 1.2 million in
    # the ten filtered columns carry one, because CURRENT_TIMESTAMP is the
    # only writer any of them has. So dropping the fraction from a caller's
    # value truncates to the same instant the column stores, exactly.
    return (dt.astimezone(timezone.utc) if dt.tzinfo else dt).strftime(
        "%Y-%m-%d %H:%M:%S")


def _validate_limit(limit: int) -> int:
    if not isinstance(limit, int) or limit < 1:
        return 100
    return min(limit, MAX_QUERY_LIMIT)


def _all_rows(rows, kind):
    """
    The same three fields for a query that has no LIMIT at all. TODO 94.

    complete is True here because the SQL has no LIMIT clause, so every row
    that matched is in the list. That is a fact about the query, not an
    assumption about the data, and it is the only reason this is allowed to
    assert completeness without counting anything.

    It exists because "how many" is a question the answer should carry even
    when nothing was cut. A list that never states its own size cannot be
    told apart from an empty one by anything reading it later, and three of
    these functions were in exactly that position.
    """
    return {
        kind: rows,
        "returned": len(rows),
        "matching_total": len(rows),
        "complete": True,
        "note": ("This query has no row limit, so every row matching the "
                 "filter is here. An empty list means nothing matched, not "
                 "that something was cut off."),
    }


def _completeness(conn, table, where, filter_params, returned):
    """
    The same honesty as _with_total, for answers that already return a dict of
    their own. TODO 94.

    Returns keys to MERGE into that dict rather than a whole answer, so a tool
    that has spent effort on its own shape and its own note keeps both. The
    warning is PREPENDED to the existing note rather than living in a new key,
    because one place to look is the whole point: a second note beside the
    first is a second thing to miss.

    Same rule on failure as _with_total. A count that could not run gives
    complete=None and says so. It never reads as complete.
    """
    try:
        total = conn.execute(
            f"SELECT COUNT(*) FROM {table} {where}", filter_params).fetchone()[0]
    except sqlite3.Error as e:
        return {
            "returned": returned,
            "complete": None,
            "_note_prefix": (
                f"COULD NOT COUNT how many rows match this filter ({e}), so "
                f"there is no way to tell whether these {returned} are all of "
                f"them. Do not read this as a complete answer. "),
        }

    out = {"returned": returned, "matching_total": total,
           "complete": total <= returned}
    if not out["complete"]:
        out["_note_prefix"] = (
            f"THIS IS NOT EVERYTHING. {total} row(s) match and you are seeing "
            f"{returned}. Raise limit, up to {MAX_QUERY_LIMIT}, or narrow the "
            f"filter, before drawing any conclusion from this list. ")
    return out


def _merge_completeness(answer, extra):
    """Fold _completeness keys into a tool answer, note prefix included."""
    prefix = extra.pop("_note_prefix", "")
    answer.update(extra)
    if prefix:
        answer["note"] = prefix + answer.get("note", "")
    return answer


def _with_total(conn, rows, table, where, filter_params, limit, kind):
    """
    Rows, plus whether they are all the rows there were. TODO 94.

    WHY THIS EXISTS. Every query_ function here returned a bare list and
    stopped. A list of 50 findings out of 14,676 and a list of 50 findings out
    of 50 are the same shape, the same length, and the same silence, so
    nothing downstream could tell a complete answer from the top of a pile.
    Measured on a real database: 14,676 active findings behind a default of
    50, and not one word anywhere saying so.

    THE COUNT IS EXACT, NOT ESTIMATED, and that is the whole reason this takes
    a connection and a where clause instead of guessing from len(rows) == limit.
    It runs COUNT over the SAME where string and the SAME parameter list the
    rows came from, so the two cannot describe different questions. A count
    built from a second, similar-looking WHERE would be a number that is
    sometimes wrong, which is worse than no number.

    IF THE COUNT FAILS, the answer says it could not count. It does not fall
    back to "complete", because "I did not check" and "there is nothing else"
    are different sentences and only one of them is true.

    Callers pass with_total=True to get this shape. Default stays a bare list
    so the dashboard, which reads these functions directly, is untouched.
    """
    out = {kind: rows, "returned": len(rows)}
    try:
        total = conn.execute(
            f"SELECT COUNT(*) FROM {table} {where}", filter_params).fetchone()[0]
    except sqlite3.Error as e:
        out["complete"] = None
        out["note"] = (
            f"Could not count how many rows match this filter ({e}). You have "
            f"{len(rows)} row(s) and NO information about whether that is all "
            f"of them. Do not read this as a complete answer.")
        return out

    out["matching_total"] = total
    out["complete"] = total <= len(rows)
    if not out["complete"]:
        out["note"] = (
            f"{total} row(s) match this filter and you are seeing {len(rows)} "
            f"of them, the first {len(rows)} in this ordering. THIS IS NOT "
            f"EVERYTHING. Raise limit, up to {MAX_QUERY_LIMIT}, or narrow the "
            f"filter with a tighter since, or an entity, or a severity. Do "
            f"not describe the machine from this list alone.")
    return out


def _near(word: str, options) -> str:
    """
    " Did you mean 'x'?" or an empty string.

    A REFUSAL SHOULD NOT SEND ANYBODY GUESSING, 2026-09-06. Watching a real
    session, the model was refused here twice in one answer and corrected
    itself by trying different words rather than by reading the list, which
    is what a refusal that only says no produces. The list was already in the
    message; a printed python set with no ordering is not a thing anybody
    reads under pressure. So: sorted, quoted, and the closest match named.

    It still REFUSES. Nothing here accepts the wrong word or corrects it
    silently, because a key written by a guess is a row nobody can trust
    later.
    """
    import difflib
    hit = difflib.get_close_matches(str(word or "").lower(),
                                    [str(o) for o in options], n=1, cutoff=0.6)
    return f" Did you mean {hit[0]!r}?" if hit else ""


def _listed(options) -> str:
    """Sorted and quoted, so the reader can pick one without parsing a set."""
    return ", ".join(repr(o) for o in sorted(options))


def _validate_entity(entity_type: str, entity_value: str, behavior_key: str = None):
    """Raise BadInput if entity params are invalid."""
    if entity_type not in VALID_ENTITY_TYPES:
        raise BadInput(
            f"Invalid entity_type {entity_type!r}. The only ones that exist "
            f"are: {_listed(VALID_ENTITY_TYPES)}."
            f"{_near(entity_type, VALID_ENTITY_TYPES)}"
        )
    if not entity_value or not entity_value.strip():
        raise BadInput("entity_value cannot be empty")
    if behavior_key is not None:
        valid_keys = VALID_BEHAVIOR_KEYS.get(entity_type, set())
        if behavior_key not in valid_keys:
            # Which keys exist depends on the entity_type, and the pair being
            # wrong together is the normal way this fails: a key that is real
            # for 'ip' used on a 'process'. So the message names the type it
            # is judging against, and names the type the key WOULD have been
            # valid for when there is one.
            elsewhere = sorted(t for t, keys in VALID_BEHAVIOR_KEYS.items()
                               if behavior_key in keys)
            hint = ""
            if elsewhere:
                hint = (f" {behavior_key!r} is a real key, but for entity_type "
                        f"{_listed(elsewhere)}, not for {entity_type!r}.")
            raise BadInput(
                f"Invalid behavior_key {behavior_key!r} for entity_type "
                f"{entity_type!r}. The keys for {entity_type!r} are: "
                f"{_listed(valid_keys)}.{hint}"
                f"{_near(behavior_key, valid_keys)}"
            )


# PREFERENCES

def get_preference(key: str, default=None):
    """Get a single user preference by key."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT value FROM user_preferences WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else default


# get_all_preferences() was here. Deleted 2026-09-03: written, never called,
# by anything, ever. get_preference and set_preference are the pair in use.


def set_preference(key: str, value: str):
    """Set a user preference."""
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO user_preferences(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP",
            (key, value)
        )


# READ, PACKETS (model read-only)

# INVENTORY ENRICHMENT
#
# Attach what the inventory already knows to rows that carry an address.
#
# WHY THIS EXISTS. The inventory was built and then nothing consulted it.
# query_packets, query_findings, query_dns_clients and query_port_scan all
# returned bare addresses, so answering "which device is that" meant a second
# tool call and a manual join. The model did that join inconsistently between
# sessions when it remembered to do it at all, which is the same class of
# problem as a rule kept in someone's head: it works until the session it
# does not.
#
# TWO RULES, AND THEY ARE BOTH ABOUT RESTRAINT.
#
# 1. Nothing is attached when the inventory knows nothing. An unnamed address
#    gets no `device` key at all, rather than a key full of nulls. Five
#    hundred packet rows each carrying an empty object is a large amount of
#    context spent saying nothing, and it teaches the reader to skip the
#    field.
#
# 2. Only facts, never a verdict. is_permanent means the user said this device
#    BELONGS here. expected_always_on means they separately said it should be
#    answering; only that one makes absence worth reporting, and most devices
#    will never carry it.
#    retired means it stopped answering and was stood down. identity_class
#    says whether the address is even a usable identity. Nothing here says
#    trusted, safe, or expected, because the inventory does not know that and
#    neither does this function.
#
# The lookup is one query per call, not one per row.

_ENRICH_FIELDS = ("known_as", "device_type", "is_permanent",
                  "expected_always_on", "identity_class", "retired_at")


def _inventory_index() -> dict:
    """Address -> the compact facts worth attaching. One query."""
    with _get_readonly_conn() as conn:
        rows = conn.execute(
            "SELECT ip, mac, known_as, device_type, is_permanent, "
            "       expected_always_on, retired_at "
            "FROM known_devices"
        ).fetchall()

    index = {}
    for row in rows:
        label     = (row["known_as"] or "").strip()
        permanent = bool(row["is_permanent"])
        always_on = bool(row["expected_always_on"])
        retired   = row["retired_at"] is not None
        cls       = identity_class(row["mac"])

        # Rule 1: say nothing unless there is something to say. A stable
        # address with no label and no declaration is exactly what the reader
        # already assumed, so it earns no field.
        if not (label or permanent or always_on or retired):
            continue

        entry = {}
        if label:
            entry["known_as"] = label
            entry["device_type"] = row["device_type"]
        if permanent:
            entry["is_permanent"] = True
        # v22. Carried here so the model reads availability off the row it is
        # already looking at, instead of writing the rule into a behavioural
        # observation under whichever key happened to be valid. An inventory
        # fact belongs in the inventory.
        if always_on:
            entry["expected_always_on"] = True
        if retired:
            entry["retired"] = True
        entry["identity_class"] = cls
        index[row["ip"]] = entry
    return index


def _enrich(rows: list[dict], *fields: str) -> list[dict]:
    """
    Attach inventory context to the named address fields of each row.

    The key is named after the field it describes, src_ip gets src_device,
    dst_ip gets dst_device, so a row with two addresses does not collapse
    them into one ambiguous `device`.

    THE UNDERSCORE WAS MISSING UNTIL 2026-09-01. This built `srcdevice` and
    `dstdevice` while the docstring above, and TODO.md, both said src_device
    and dst_device. Nothing in the codebase reads the key by name, so nothing
    broke and nobody noticed; the only reader is the model, which takes
    whatever arrives. Found by a test that asserted the documented name.

    Worth the note, because a docstring describing a contract nobody checks is
    how the next person writes code against the name that was never real.
    """
    if not rows:
        return rows
    index = _inventory_index()
    if not index:
        return rows

    for row in rows:
        for field in fields:
            found = index.get(row.get(field))
            if found:
                key = (field[:-3] + "_device"
                       if field.endswith("_ip") else "device")
                row[key] = found
    return rows


# How long after a scan finishes its traffic can still be arriving. A closed
# port answers with RST immediately, but a filtered one times out and the
# teardown of an established connection lands after the scanner has already
# moved on. Ten seconds is generous for a LAN and still far short of anything
# a device would plausibly start on its own in the same window.
_SCAN_TAIL_SECONDS = 10

# When finished_at is NULL the scan either is still running or died. Neither
# is a zero length window, and treating it as one would mark nothing, which
# is the wrong direction to fail in for a flag whose whole job is to stop a
# false alarm. Cover a generous fixed window instead and say so.
_SCAN_UNFINISHED_SECONDS = 600


def _scan_windows(conn, since: str = None) -> list:
    """
    Every port scan this tool ran, as (target_host, start, end) strings.

    Read from port_scan_run, which records the RUN. port_scan_results cannot
    answer this: it only holds ports that were open, so a scan that found
    nothing leaves no row, and a scan that found nothing is exactly the one
    that produced a thousand refused connections. See TODO 37.2.
    """
    if not _table_exists_ro(conn, "port_scan_run"):
        return []

    params = []
    where = ""
    if since:
        where = "WHERE started_at >= ?"
        params.append(_sql_datetime(since))

    rows = conn.execute(f"""
        SELECT target_host, started_at,
               COALESCE(
                   datetime(finished_at, '+{_SCAN_TAIL_SECONDS} seconds'),
                   datetime(started_at, '+{_SCAN_UNFINISHED_SECONDS} seconds')
               ) AS ends_at
        FROM port_scan_run {where}
    """, params).fetchall()
    return [(r[0], r[1], r[2]) for r in rows]


def _table_exists_ro(conn, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _comparable_ts(value) -> str:
    """
    One shape for a timestamp, so two of them can be compared as strings.

    FOUND BY THE TEST, 2026-09-02, and it is worth the note because of which
    way it failed. The window bounds come straight out of SQLite as
    '2026-09-02 01:13:24'. The row's captured_at has already been through
    _rows_to_dicts, which returns '2026-09-02T01:13:54Z'. Compared as strings
    those never match, because 'T' sorts after a space.

    So every packet came back self_induced FALSE. Not an error, not a crash,
    just the flag quietly never firing, which is precisely the state the flag
    was written to end. A marker that fails closed is worse than no marker,
    because the description now promises the model something that is not true.
    """
    if not value:
        return ""
    text = str(value).strip().replace("T", " ")
    if text.endswith("Z"):
        text = text[:-1]
    # Drop any fractional seconds or offset tail. Second resolution is far
    # finer than a ten second grace window needs.
    return text[:19]


def _mark_self_induced(rows: list[dict], windows: list) -> list[dict]:
    """
    Stamp self_induced on packets this application caused.

    WHY THIS EXISTS, and it is the whole point of the flag. On 2026-09-02 the
    model port scanned a device, queried this table, saw rows with source port
    27017 and 32400 going to ephemeral ports on this host, and told the owner
    the device was "actively probing THIS host's ports". Those rows are the
    scanned device answering with RST because the port is closed. It read the
    reply leg of its own scan as unsolicited hostile activity, and escalated
    on it while the owner was telling it the device was the owner's.

    A packet counts as self-induced when the OTHER end of it was a scan target
    and it falls inside that scan's window. Both directions are marked: the
    probe going out and the answer coming back are equally caused by us.

    FALSE is not a claim of innocence, it means "no recorded scan explains
    this row". Scans from before 2026-09-02 were never recorded, so old
    packets all come back false. Deliberately not reconstructed: guessing a
    scan window from traffic shape would mark real packets as self-induced,
    and that is the dangerous direction for this particular flag.
    """
    if not rows:
        return rows

    normalised = [(t, _comparable_ts(s), _comparable_ts(e))
                  for t, s, e in windows]

    for row in rows:
        row["self_induced"] = False
        if not normalised:
            continue

        at = _comparable_ts(row.get("captured_at"))
        if not at:
            continue

        for target, start, end in normalised:
            if target not in (row.get("src_ip"), row.get("dst_ip")):
                continue
            if start <= at <= end:
                row["self_induced"] = True
                row["self_induced_note"] = (
                    f"caused by this tool's own port scan of {target}, which "
                    f"ran from {start} to {end}. This is NOT something the "
                    f"device did on its own and must not be reported as its "
                    f"behaviour."
                )
                break

    return rows


def _packet_conditions(since=None, until=None, src_ip=None, dst_ip=None,
                       port=None, direction=None, scope=None,
                       process_pid=None, process_name=None):
    """
    The WHERE for a packet search, WITHOUT the session clause, as a list of
    conditions and a list of parameters.

    WHY THIS IS A FUNCTION, 2026-09-14, TODO 98. query_packets built this
    inline and packet_search_scope built its own count from src_ip and dst_ip
    alone. So the moment anyone searched by port, by time, by direction or by
    process, the rows answered one question and the scope block answered a
    different one, and the scope block is the half the model reads for advice.

    That is the thing _with_total's own comment rules out: a count built from
    a second, similar looking WHERE is right until somebody uses a filter,
    which is exactly when they are investigating something. One builder means
    the two cannot drift, which is the only version of this that stays true.

    The session clause is NOT here on purpose. It is the one condition the
    scope block needs to apply twice, once with and once without, to tell
    "your limit cut this" apart from "there is more in earlier runs".
    """
    conditions, params = [], []

    if since and since != "session_start":
        conditions.append("captured_at >= ?")
        params.append(_sql_datetime(since))
    if until and until != "now":
        conditions.append("captured_at <= ?")
        params.append(_sql_datetime(until))
    if src_ip:
        conditions.append("src_ip = ?")
        params.append(src_ip)
    if dst_ip:
        conditions.append("dst_ip = ?")
        params.append(dst_ip)
    if port:
        conditions.append("(src_port = ? OR dst_port = ?)")
        params.extend([port, port])
    if direction:
        conditions.append("direction = ?")
        params.append(direction)
    if scope:
        conditions.append("scope = ?")
        params.append(scope)

    # Filter by the process that owned the socket. Added 2026-09-08, TODO 66.
    #
    # The columns went in with the attribution work two days earlier and
    # nothing could search on them, so the model tried process_pid as a
    # filter, got the whole capture back instead, and reasonably read that as
    # "no rows mention this pid". A filter that silently ignores what you
    # asked for is worse than no filter.
    #
    # NULL in these columns means NOT ATTRIBUTED, never "no process", so a
    # pid filter finding nothing does NOT mean that process sent nothing.
    if process_pid is not None:
        conditions.append("process_pid = ?")
        params.append(int(process_pid))
    if process_name:
        conditions.append("process_name LIKE ?")
        params.append(f"%{process_name}%")

    return conditions, params


def query_packets(
    since: str = "session_start",
    until: str = "now",
    src_ip: str = None,
    dst_ip: str = None,
    port: int = None,
    direction: str = None,
    scope: str = None,
    process_pid: int = None,
    process_name: str = None,
    session_id: str = None,
    all_sessions: bool = False,
    limit: int = 100,
    order: str = "desc",
) -> list[dict]:
    """
    Query captured packets. Model calls this to investigate live traffic.
    since/until: ISO timestamp string or 'session_start' / 'now'

    all_sessions=True searches the whole retained history instead of just the
    current run. Added 2026-08-29, see packet_search_scope below for why.

    scope is the precise address classification and is the one to filter on
    when the question is about what a packet IS. direction has three values
    and one of them, internal, covers several different situations. Rows
    written before 2026-08-24 have scope NULL, which means "not recorded",
    not "ordinary".
    """
    limit = _validate_limit(limit)
    order_clause = "DESC" if order.lower() != "asc" else "ASC"

    conditions, params = _packet_conditions(
        since=since, until=until, src_ip=src_ip, dst_ip=dst_ip, port=port,
        direction=direction, scope=scope, process_pid=process_pid,
        process_name=process_name)

    if session_id and not all_sessions:
        conditions.append("session_id = ?")
        params.append(session_id)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    # 2026-09-01. THIS WAS `SELECT *` AND IT WAS COSTING US IN A WAY NOBODY
    # WAS LOOKING AT.
    #
    # payload_snippet is up to 256 bytes of packet payload stored as HEX, so
    # up to 512 characters of text per row. SELECT * handed every one of them
    # to the model. Ask for 100 packets and that is roughly 50 KB of hex in
    # the context, and the model can do very little with raw hex anyway.
    #
    # It is mostly noise too. The signature checks already ran on the LIVE
    # bytes at capture time, so any payload that actually mattered is already
    # carrying a threat_label by the time the row is written.
    #
    # So the payload rides along ONLY on flagged rows, which is exactly when
    # somebody wants to look at one.
    #
    # 2026-09-01, LATER THE SAME DAY: the measurement happened and save_packet
    # now refuses to STORE a payload on an unflagged row either. The CASE
    # below is therefore belt and braces on new rows, and load-bearing on old
    # ones: every row written before today is still carrying its payload until
    # scripts/reclaim_packet_space.py has been run. Do not remove it on the
    # grounds that the writer already handles it.
    #
    # raw_summary stays out entirely: it is a scapy one-liner rebuilt from
    # fields this row already carries separately.
    sql = f"""
        SELECT id, session_id, captured_at, src_ip, dst_ip, src_port, dst_port,
               protocol, direction, scope, packet_size, flags, threat_label,
               vpn_state, sensor_id, process_name, process_pid,
               CASE WHEN threat_label IS NOT NULL THEN payload_snippet END
                    AS payload_snippet
        FROM packets {where} ORDER BY captured_at {order_clause} LIMIT ?
    """
    params.append(limit)

    with _get_conn() as conn:
        rows = _rows_to_dicts(conn.execute(sql, params).fetchall())
        # Marked BEFORE the inventory enrichment so that a row this tool
        # caused is already labelled by the time anything else decorates it.
        _mark_self_induced(rows, _scan_windows(conn))
        return _enrich(rows, "src_ip", "dst_ip")


def packet_search_scope(session_id=None, all_sessions=False, src_ip=None,
                        dst_ip=None, since=None, until=None, port=None,
                        direction=None, scope=None, process_pid=None,
                        process_name=None, returned=0) -> dict:
    """
    Say what a packet search actually looked at, and what it did not.

    WHY THIS EXISTS, 2026-08-29. Found by reading the model's own reasoning
    while it investigated one address. It called query_packets, got an empty
    list, guessed the window was wrong, tried another window, got empty again,
    and went round six times before giving up and saying so. Every one of
    those rounds cost tokens and none of them could have worked.

    The cause was not the model. query_packets is dispatched with
    session_id=<this run> always, and the model has no way to ask for
    anything wider. It was searching the last few minutes of a freshly booted
    process and being handed [] with no explanation. Empty looked like "this
    device sent nothing", when it meant "I only looked at the current run".

    An empty result that does not say what it searched is the same defect as
    every other one found today: a thing that knew something and did not say
    it. The fix is not a smarter model, it is an honest tool response. Silence
    is what made it guess.

    WHAT WAS WRONG WITH IT UNTIL 2026-09-14, TODO 98, and it is worth reading
    because this function was held up as the pattern that works.

    It took src_ip and dst_ip and nothing else. The dispatcher was passing
    since, until, port, direction, scope, process_pid and process_name to
    query_packets and none of them to here, so the count ran with almost no
    WHERE on it. Three things came out of that and all three were wrong the
    moment anyone filtered by anything but an address:

      * the total was described as "matching" and was really the whole table
      * complete said false on answers that were in fact whole
      * and worst, the hint said "N more matching packets exist in earlier
        runs, call again with all_sessions=true". The model did, got the
        newest rows of ANYTHING, and none of them matched. That is the six
        round loop in the paragraph above, rebuilt by the function written to
        stop it.

    TWO COUNTS NOW, both off the same builder the rows used:

      in_scope    the same filter, plus the session clause if the search was
                  scoped to this run. This is the one `complete` rests on.
      everywhere  the same filter with no session clause at all. The gap
                  between the two is what genuinely lives in earlier runs.

    Keeping them apart is the whole point. "Your limit cut this" and "there is
    more in earlier runs" are different facts with different fixes, and a
    reader handed one number cannot tell which they have.

    Cheap on purpose: two COUNT queries against indexed columns, and only the
    dispatcher calls it.
    """
    conditions, params = _packet_conditions(
        since=since, until=until, src_ip=src_ip, dst_ip=dst_ip, port=port,
        direction=direction, scope=scope, process_pid=process_pid,
        process_name=process_name)

    where_everywhere = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params_everywhere = list(params)

    scoped = bool(session_id and not all_sessions)
    if scoped:
        conditions = conditions + ["session_id = ?"]
        params = params + [session_id]
    where_in_scope = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    out = {
        "searched": "all retained sessions" if all_sessions
                    else "the current run only",
        "returned": returned,
    }
    try:
        with _get_conn() as conn:
            everywhere = conn.execute(
                f"SELECT COUNT(*) FROM packets {where_everywhere}",
                params_everywhere).fetchone()[0]
            in_scope = conn.execute(
                f"SELECT COUNT(*) FROM packets {where_in_scope}",
                params).fetchone()[0] if scoped else everywhere

            # Named for what they are. The old key was
            # matching_rows_in_whole_history and it was not matching anything.
            out["matching_in_this_search"] = in_scope
            out["matching_in_whole_history"] = everywhere
            out["complete"] = in_scope <= returned

            # YOUR LIMIT CUT THIS. True in both modes, which is why it is not
            # inside either branch below.
            if in_scope > returned:
                out["cut_by_limit"] = in_scope - returned
                out["hint"] = (
                    f"{in_scope} packet(s) match this exact filter in what "
                    f"you searched and you have {returned}. The LIMIT cut "
                    f"this, not the session scope. Raise limit or narrow the "
                    f"filter with since, a port, or an address. Do NOT read "
                    f"this as all the matching traffic.")

            # AND SEPARATELY, there is more of it in earlier runs. Only
            # reachable when the search was scoped, because otherwise there is
            # no elsewhere to be in.
            if scoped and everywhere > in_scope:
                out["elsewhere"] = everywhere - in_scope
                earlier = (
                    f"{everywhere - in_scope} more packet(s) matching this "
                    f"same filter exist in EARLIER RUNS. Call query_packets "
                    f"again with all_sessions=true to include them. Do NOT "
                    f"read this result as 'no such traffic'.")
                out["hint"] = (out["hint"] + " " + earlier) if out.get("hint") else earlier

            if everywhere == 0:
                out["hint"] = (
                    "No packet matching this filter exists anywhere in the "
                    "retained history, not just in this run. If a device is "
                    "expected to be talking, read query_sensors first: a "
                    "sensor at position 'host' never sees traffic between two "
                    "other devices, so zero rows is a statement about our "
                    "vantage point, not about the device.")

            if not all_sessions:
                row = conn.execute(
                    "SELECT MIN(captured_at), MAX(captured_at) FROM packets"
                ).fetchone()
                out["retained_history_spans"] = f"{row[0]} to {row[1]}"
    except sqlite3.Error as e:
        # RULE TWO. A count that did not run must not leave `complete` behind
        # to be read as an answer, and must not be silent about it either.
        out.pop("complete", None)
        out["scope_note_failed"] = str(e)
        out["hint"] = (
            f"COULD NOT COUNT how many packets match this filter ({e}), so "
            f"there is no way to tell whether these {returned} row(s) are all "
            f"of them or the top of a pile. Do not read this as a complete "
            f"answer and do not read an empty one as a quiet network.")
    return out



# READ, FINDINGS (model read-only)

def query_findings(
    since: str = None,
    severity: str = None,
    entity_type: str = None,
    entity_value: str = None,
    source: str = None,        # add this line
    dismissed: bool = False,
    session_id: str = None,
    limit: int = 50,
    order: str = "desc",
    with_total: bool = False,
    detection_id: str = None,
):
    """
    Query security findings. Pass dismissed=True to include dismissed findings.

    with_total=True returns a dict carrying the rows, the exact number that
    matched, and whether this is all of them. See _with_total. Default is the
    bare list, so the dashboard is unaffected. TODO 94.1.
    """
    limit = _validate_limit(limit)
    order_clause = "DESC" if order.lower() != "asc" else "ASC"

    conditions = ["dismissed = ?"]
    params = [1 if dismissed else 0]

    if since:
        conditions.append("found_at >= ?")
        params.append(_sql_datetime(since))
    if severity:
        if severity not in VALID_SEVERITY:
            raise BadInput(f"Invalid severity '{severity}'")
        conditions.append("severity = ?")
        params.append(severity)
        
    if source:
       conditions.append("source = ?")
       params.append(source)    
    # TODO 112. Every time ONE rule fired, across every entity and every
    # session. The question the old schema could not answer at all: `source`
    # is the whole sensor and `title` is prose, so "show me every beacon
    # finding" meant matching a sentence and hoping nobody had reworded it.
    if detection_id:
        conditions.append("detection_id = ?")
        params.append(detection_id)
    if entity_type:
        conditions.append("entity_type = ?")
        params.append(entity_type)
    if entity_value:
        conditions.append("entity_value = ?")
        params.append(entity_value)
    if session_id:
        conditions.append("session_id = ?")
        params.append(session_id)

    where = "WHERE " + " AND ".join(conditions)
    sql = f"SELECT * FROM findings {where} ORDER BY found_at {order_clause} LIMIT ?"
    # Kept before the limit is appended, so the count asks the same question
    # the rows answered. See _with_total.
    filter_params = list(params)
    params.append(limit)

    with _get_conn() as conn:
        rows = _enrich(_rows_to_dicts(conn.execute(sql, params).fetchall()),
                       "entity_value")
        if not with_total:
            return rows
        return _with_total(conn, rows, "findings", where, filter_params,
                           limit, "findings")


# Severity rank in SQL, in the one place it is written down. The Python side
# keeps its own RANK dicts for sorting rows it already has; this is for asking
# the database which row is worst without reading them all.
_SEVERITY_RANK_SQL = ("CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
                      "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END")


def worst_finding_by_entity(entity_type: str, session_id: str = None,
                            dismissed: bool = False) -> dict:
    """
    {entity_value: {"severity": ..., "title": ...}} for every entity with a
    finding against it. No limit, and there cannot be one.

    WHY THIS EXISTS, 2026-09-14, TODO 98. The threat map coloured its rows by
    calling query_findings(entity_type="ip", limit=500) and building this
    dictionary in Python. 500 is MAX_QUERY_LIMIT so it was the biggest ask
    available, and it was still a cap with nothing saying so. An address whose
    finding sat at row 501 came back with severity null, and the map's own
    docstring reads a null severity as ordinary traffic. On a database with
    14,676 findings that is reachable, and the answer it produces is the worst
    one this app can give: a flagged address described as ordinary.

    94 fixed the endpoint list in that same function, gave it
    endpoints_complete and unlocated_complete, and walked past this join.

    An aggregate has no such cap, which is why this is the fix rather than a
    bigger number. One row per entity comes back however many findings there
    are, so there is nothing to truncate and nothing to admit.

    ON THE BARE COLUMNS: SQLite documents that when MAX() is used with a
    GROUP BY, the other columns come from the row that produced the maximum.
    That is what picks the title belonging to the worst severity rather than
    an arbitrary one. Ties between two rows of the same severity are broken
    arbitrarily by the same rule, which is fine, they say the same thing.

    Raises sqlite3.Error rather than returning {}. An empty dictionary here
    would paint every address as having nothing against it, and "no finding"
    and "I could not read the findings" must not be the same answer. The
    callers catch it and say which one they got.
    """
    conditions = ["dismissed = ?", "entity_type = ?"]
    params = [1 if dismissed else 0, entity_type]
    if session_id:
        conditions.append("session_id = ?")
        params.append(session_id)
    where = "WHERE " + " AND ".join(conditions)

    sql = (f"SELECT entity_value, severity, title, "
           f"MAX({_SEVERITY_RANK_SQL}) AS worst_rank "
           f"FROM findings {where} GROUP BY entity_value")

    with _get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()

    out = {}
    for row in rows:
        value = row["entity_value"]
        if not value:
            continue
        out[value] = {"severity": row["severity"] or "low",
                      "title": row["title"] or ""}
    return out


def worst_finding_by_entity_with_rule(entity_type: str,
                                      session_id: str = None,
                                      dismissed: bool = False) -> dict:
    """
    worst_finding_by_entity, plus the rule that raised the worst row.

    SAME AGGREGATE, ONE EXTRA COLUMN, 2026-09-23. The threat map needs to know
    not only that an address is flagged but WHETHER THE RULE THAT FLAGGED IT
    SAYS THE ADDRESS IS A HOST AT ALL, and that fact lives on the detection.

    WHY IT IS A SECOND FUNCTION RATHER THAN A CHANGE TO THE FIRST. The first
    one is read by callers that only want a colour, and its return shape is
    asserted by tests on both trees. Adding a key to every row would be a
    change to a shared answer made for one reader's convenience. This is the
    same SQL with detection_id carried out, and its own docstring says which
    of the two a caller wants.

    detection_id can be NULL on old rows (the column arrived with v-112 and
    findings raised before it are unstamped). NULL means the rule is unknown,
    which is NOT the same as "a rule that says the entity is a host" -- so
    entity_is_not_a_host is False only when the register positively says so,
    and an unstamped row keeps exactly the old behaviour.

    Raises sqlite3.Error rather than returning {}, for the same reason the
    function above does: "nothing is flagged" and "I could not read the
    findings" must never be the same answer.
    """
    from core import detections as det

    conditions = ["dismissed = ?", "entity_type = ?"]
    params = [1 if dismissed else 0, entity_type]
    if session_id:
        conditions.append("session_id = ?")
        params.append(session_id)
    where = "WHERE " + " AND ".join(conditions)

    sql = (f"SELECT entity_value, severity, title, detection_id, "
           f"MAX({_SEVERITY_RANK_SQL}) AS worst_rank "
           f"FROM findings {where} GROUP BY entity_value")

    with _get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()

    out = {}
    for row in rows:
        value = row["entity_value"]
        if not value:
            continue
        did = row["detection_id"]
        # A rule that is no longer registered must not break the map. The
        # register is allowed to retire a number; the rows it already raised
        # stay in the table, and a reader that raised on them would turn a
        # retired rule into a broken threat map.
        not_a_host = False
        if did and det.exists(did):
            not_a_host = bool(getattr(det.get(did),
                                      "entity_is_not_a_host", False))
        out[value] = {
            "severity": row["severity"] or "low",
            "title": row["title"] or "",
            "detection_id": did,
            "entity_is_not_a_host": not_a_host,
        }
    return out


# READ, EVENTS (model read-only)

def query_events(
    since: str = None,
    event_type: str = None,
    username: str = None,
    src_ip: str = None,
    severity: str = None,
    session_id: str = None,
    limit: int = 50,
    order: str = "desc",
    with_total: bool = False,
):
    """
    Query Windows/Linux security events.

    with_total=True returns the rows plus the exact matching count and whether
    this is all of them. TODO 94.2.
    """
    limit = _validate_limit(limit)
    order_clause = "DESC" if order.lower() != "asc" else "ASC"

    conditions = []
    params = []

    if since:
        conditions.append("occurred_at >= ?")
        params.append(_sql_datetime(since))
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)
    if username:
        conditions.append("username = ?")
        params.append(username)
    if src_ip:
        conditions.append("src_ip = ?")
        params.append(src_ip)
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if session_id:
        conditions.append("session_id = ?")
        params.append(session_id)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"SELECT * FROM events {where} ORDER BY occurred_at {order_clause} LIMIT ?"
    filter_params = list(params)
    params.append(limit)

    with _get_conn() as conn:
        rows = _enrich(_rows_to_dicts(conn.execute(sql, params).fetchall()),
                       "entity_value")
        if not with_total:
            return rows
        return _with_total(conn, rows, "events", where, filter_params,
                           limit, "events")



    # READ, PORT SCAN RESULTS (model read-only)

def query_port_scan(
    target_host: str = None,
    risk_level: str = None,
    state: str = "open",
    session_id: str = None,
    all_sessions: bool = False,
    limit: int = 100,
    with_total: bool = False,
    protocol: str = None,
):
    """
    Query port scan results.

    with_total=True returns the rows plus the exact matching count and whether
    this is all of them. TODO 94.5.

    Every row carries `protocol` since v34. Filtering by it is optional and
    the default is no filter, because a reader asking "what is open on this
    host" wants everything that was found, not one protocol's worth of it.

    all_sessions ADDED 2026-09-25, REGISTER PS-12. The parameter mirrors
    query_packets' one of the same name. Without it, every reader of this
    table -- the Ports tab and the model's own query_port_scan -- was scoped
    to the CURRENT RUN's session id, and main.py mints a new id on every boot,
    so a restart emptied the Ports tab behind the words "No port scan results
    yet." while the store held 70 rows across 20 sessions. Every other reader
    of a growing record on that page (packets, events, findings, the Timeline)
    had already been fixed for exactly this; this table was the one that had
    not. A port scan is an operator action worth keeping: the record's value
    is cross-session ("when did I first see 22 open on this box"), which a
    current-session window throws away.
    """
    limit = _validate_limit(limit)
    conditions = []
    params = []

    if target_host:
        conditions.append("target_host = ?")
        params.append(target_host)
    if state:
        conditions.append("state = ?")
        params.append(state)
    if risk_level:
        conditions.append("risk_level = ?")
        params.append(risk_level)
    # A session_id WITH all_sessions MEANS "INCLUDE THIS RUN TOO", not "only
    # this run". Same reading as query_packets: all_sessions drops the scope
    # filter rather than narrowing it.
    if session_id and not all_sessions:
        conditions.append("session_id = ?")
        params.append(session_id)
    if protocol:
        if protocol not in VALID_PORT_PROTOCOL:
            raise BadInput(
                f"Invalid protocol '{protocol}'. "
                f"Valid: {sorted(VALID_PORT_PROTOCOL)}")
        conditions.append("protocol = ?")
        params.append(protocol)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"SELECT * FROM port_scan_results {where} ORDER BY risk_level, port LIMIT ?"
    filter_params = list(params)
    params.append(limit)

    with _get_conn() as conn:
        rows = _enrich(_rows_to_dicts(conn.execute(sql, params).fetchall()),
                       "target_host")
        if not with_total:
            return rows
        return _with_total(conn, rows, "port_scan_results", where,
                           filter_params, limit, "ports")


# PRESENCE SWEEPS (schema v12)
#
# Python writes these on a fixed tick. The model reads them and never writes
# them, which is the point: a presence series is only a measurement if the
# thing being measured did not choose when to look.

# Below this many usable sweeps, a presence rate is arithmetic on too little
# and the reader is told so rather than handed a percentage. Four is not a
# principled number; it is the smallest count where "absent twice running"
# is distinguishable from noise at all.
PRESENCE_THIN_DENOMINATOR = 4


def record_presence_sweep(session_id: str, method: str, outcome: str,
                          subnet: str = None, detail: str = None,
                          targets: int = 0, duration_ms: int = None,
                          responders: list[dict] = None,
                          sensor_id: str = None) -> int:
    """
    Write one sweep and the addresses that answered it. Returns the sweep id.

    responders is a list of {"ip", "mac", "via"}. Only positives are stored;
    absence is derived later by joining an address against the sweeps that
    ran. That keeps storage proportional to how many devices answered rather
    than to the size of the address space, and it means nothing can read a
    presence figure without also reading its denominator.

    A FAILED SWEEP IS STILL WRITTEN, with outcome='failed' and a reason.
    That is deliberate and it is most of the value of this table. If a sweep
    that could not run left no row, a stretch where the scanner was broken
    would be indistinguishable from a stretch where the network was quiet,
    and the second reading is the dangerous one. Failed rows are never
    counted as a denominator anywhere.
    """
    if outcome not in ("ok", "failed"):
        raise BadInput("outcome must be 'ok' or 'failed'")

    rows = responders or []
    if outcome == "failed" and rows:
        raise BadInput("a failed sweep cannot carry responders")

    with _get_conn() as conn:
        cur = conn.execute("""
            INSERT INTO presence_sweep
                (session_id, subnet, method, outcome, detail,
                 targets, responded, duration_ms, sensor_id)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (session_id, subnet, method, outcome, detail,
              int(targets or 0), len(rows), duration_ms,
              sensor_id or _local_sensor_id()))
        sweep_id = cur.lastrowid

        if rows:
            conn.executemany("""
                INSERT OR IGNORE INTO presence_observation(sweep_id, ip, mac, via)
                VALUES(?, ?, ?, ?)
            """, [(sweep_id, r["ip"], r.get("mac") or None,
                   r.get("via") or "icmp") for r in rows])

    return sweep_id


def sweeps_not_covering(ip: str, last_n: int) -> int:
    """How many of the last `last_n` usable sweeps ran on a subnet without `ip`.

    A sweep with no subnet recorded counts as not covering it.
    """
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return last_n
    with _get_readonly_conn() as conn:
        rows = conn.execute(
            "SELECT subnet FROM presence_sweep WHERE outcome = 'ok' "
            "ORDER BY swept_at DESC, id DESC LIMIT ?", (int(last_n),)).fetchall()
    outside = 0
    for (subnet,) in rows:
        try:
            if addr not in ipaddress.ip_network(subnet, strict=False):
                outside += 1
        except (TypeError, ValueError):
            outside += 1
    return outside


def query_presence(ip: str = None, since: str = None,
                   max_sweeps: int = 200, with_total: bool = False) -> dict:
    """
    How often an address answered, out of how many sweeps actually ran.

    The denominator is the product here, not a footnote. A device absent from
    the last forty sweeps and a device absent from the only sweep that has
    ever run produce the same word, 'absent', and mean completely different
    things. Every figure returned carries the count it was computed from.

    Sweeps with outcome='failed' are excluded from the denominator and
    reported separately, because a sweep that could not run is not a sweep in
    which everything was missing.

    absent_streak counts backwards from the most recent usable sweep, so it
    answers "has it stopped answering", which is the question, rather than
    "has it ever been missing", which on any real network is always yes.
    """
    max_sweeps = max(1, min(int(max_sweeps or 200), 2000))
    params: list = []
    where = ["outcome = 'ok'"]
    # THE CUTOFF IS NORMALIZED ONCE AND REUSED, because this answer carries
    # TWO counts built from it (usable sweeps here, failed sweeps below) and
    # they have to be counting the same window or the pair is not a pair.
    # Measured on a throwaway store: with the caller's ISO-Z cutoff, the
    # usable count normalizes and answers 1 while the failed count, which
    # passed the raw string into SQL, answered 0 for a sweep that exists.
    cutoff = _sql_datetime(since) if since else None

    if cutoff:
        where.append("swept_at >= ?")
        params.append(cutoff)

    with _get_readonly_conn() as conn:
        sweeps = conn.execute(f"""
            SELECT id, swept_at FROM presence_sweep
            WHERE {' AND '.join(where)}
            ORDER BY swept_at DESC, id DESC
            LIMIT ?
        """, (*params, max_sweeps)).fetchall()

        failed_row = conn.execute(f"""
            SELECT COUNT(*) AS n FROM presence_sweep
            WHERE outcome = 'failed'{' AND swept_at >= ?' if cutoff else ''}
        """, (cutoff,) if cutoff else ()).fetchone()
        failed = failed_row["n"] if failed_row else 0

        # TODO 94.12. How many usable sweeps EXIST, against how many this
        # window took. Every rate below is a fraction of the sweeps counted,
        # so a reader who cannot tell 200 of 200 from 200 of 9,000 cannot
        # tell a measurement of the last hour from one of the last month.
        usable_total = None
        if with_total:
            try:
                usable_total = conn.execute(
                    f"SELECT COUNT(*) FROM presence_sweep "
                    f"WHERE {' AND '.join(where)}", params).fetchone()[0]
            except sqlite3.Error:
                usable_total = None

        # Newest first above, because the LIMIT has to take the most recent
        # window. Flip to oldest first now: every figure below reads forward
        # in time and a reversed series makes a streak count backwards.
        sweeps = list(sweeps)[::-1]
        sweep_ids = [s["id"] for s in sweeps]
        total = len(sweep_ids)

        window = {
            "sweeps_counted":  total,
            "sweeps_failed_and_excluded": failed,
            **({"usable_sweeps_in_range": usable_total,
                "complete": usable_total <= total}
               if usable_total is not None else
               {"complete": None} if with_total else {}),
            "first_sweep_at":  _to_iso_utc(sweeps[0]["swept_at"]) if sweeps else None,
            "last_sweep_at":   _to_iso_utc(sweeps[-1]["swept_at"]) if sweeps else None,
            "since":           since,
        }

        if total == 0:
            return {
                "window":  window,
                "devices": [],
                "note": (
                    "NO USABLE SWEEPS in this window"
                    + (f", and {failed} sweep(s) failed and were excluded"
                       if failed else "")
                    + ". This is not evidence that any device is absent. It "
                      "means nothing looked. Do not report a device as missing "
                      "on the strength of this result."
                ),
            }

        # MERGED DEVICES ROLL UP TO THEIR CANONICAL ADDRESS.
        #
        # Logged as a known gap when merge landed, and it stops being cosmetic
        # the moment absence raises a finding: a device recorded as one thing
        # across several addresses is PRESENT if ANY of them answered, and
        # reporting the canonical address as missing while one of its own
        # appearances replied would be a false alarm generated by our own
        # bookkeeping.
        #
        # Built here rather than in SQL because the chain has to be resolved,
        # and _canonical_id already owns that logic including its cycle guard.
        merge_rows = conn.execute(
            "SELECT id, ip, merged_into FROM known_devices"
        ).fetchall()
        by_id  = {r["id"]: r for r in merge_rows}
        canon: dict[str, str] = {}
        for r in merge_rows:
            root, seen_ids = r["id"], set()
            while by_id.get(root) is not None and by_id[root]["merged_into"] is not None:
                if root in seen_ids:
                    break
                seen_ids.add(root)
                root = by_id[root]["merged_into"]
            if root in by_id and by_id[root]["ip"] != r["ip"]:
                canon[r["ip"]] = by_id[root]["ip"]

        placeholders = ",".join("?" * len(sweep_ids))
        obs_params: list = list(sweep_ids)
        ip_clause = ""
        if ip:
            # ASKING ABOUT A CANONICAL DEVICE MUST ALSO ASK ABOUT ITS
            # APPEARANCES.
            #
            # The filter runs in SQL, before the roll-up below, so filtering
            # on the canonical address alone would discard the very rows that
            # prove the device answered. Caught by a test where a merged
            # phone replied on its second address and the first read as
            # absent, which, now that absence raises a finding, would have
            # been a false alarm manufactured by our own bookkeeping.
            wanted = {ip} | {raw for raw, root in canon.items() if root == ip}
            ip_clause = " AND o.ip IN (" + ",".join("?" * len(wanted)) + ")"
            obs_params.extend(sorted(wanted))

        observations = conn.execute(f"""
            SELECT o.sweep_id, o.ip, o.mac, o.via
            FROM presence_observation o
            WHERE o.sweep_id IN ({placeholders}){ip_clause}
        """, obs_params).fetchall()

        labels = {
            r["ip"]: r["known_as"]
            for r in conn.execute(
                "SELECT ip, known_as FROM known_devices WHERE known_as IS NOT NULL"
            ).fetchall()
        }

    seen_at: dict[str, set] = {}
    macs: dict[str, str] = {}
    via_counts: dict[str, dict] = {}

    rolled_up: dict[str, set] = {}

    for o in observations:
        # An appearance answering counts for the device it is an appearance
        # OF. See the canon map above.
        raw  = o["ip"]
        addr = canon.get(raw, raw)
        if addr != raw:
            rolled_up.setdefault(addr, set()).add(raw)
        seen_at.setdefault(addr, set()).add(o["sweep_id"])
        if o["mac"]:
            macs.setdefault(addr, o["mac"])
        via_counts.setdefault(addr, {})
        via_counts[addr][o["via"]] = via_counts[addr].get(o["via"], 0) + 1

    # An explicitly requested address that answered nothing still gets a row.
    # Returning an empty list for "is the printer there" reads as no data
    # when the actual answer is zero out of forty, which is the finding.
    if ip and ip not in seen_at:
        seen_at[ip] = set()

    id_to_time = {s["id"]: s["swept_at"] for s in sweeps}

    # GAPS IN THE SERIES, AND WHY "CONSECUTIVE" HAS TO MEAN CONSECUTIVE IN TIME
    #
    # This tool is built for homelabs, and homelab machines get switched off.
    # The app runs for an hour, the machine sleeps for a fortnight, the app
    # runs again. Sweeps are only written while it is running, so two rows
    # that are adjacent in this table can be four weeks apart in wall clock.
    #
    # absent_streak counted rows, not time. So a device that missed the last
    # four sweeps before a shutdown and the first four after a restart scored
    # a streak of eight "consecutive" misses spanning a month, and at the
    # thresholds above that is an absence finding, and eventually a
    # retirement, for a device that may have been sitting there present the
    # entire time nobody was looking.
    #
    # That is the same error this project keeps a rule about, in a new place:
    # treating "we were not watching" as "nothing was there".
    #
    # So a streak BREAKS at a gap in the series. The nominal interval is not
    # known here, it is config the caller owns, so it is derived from the
    # data: the median spacing of the sweeps themselves. A gap far larger than
    # the machine's own rhythm is the app having been off, whatever the
    # interval is set to.
    def _seconds(value) -> float | None:
        try:
            text = str(value).replace(" ", "T")
            if not text.endswith("Z") and "+" not in text:
                text += "+00:00"
            return datetime.fromisoformat(
                text.replace("Z", "+00:00")).timestamp()
        except (ValueError, TypeError):
            return None

    times = [_seconds(s["swept_at"]) for s in sweeps]
    spacings = [b - a for a, b in zip(times, times[1:])
                if a is not None and b is not None and b >= a]

    gap_threshold = None
    if len(spacings) >= 3:
        ordered = sorted(spacings)
        median = ordered[len(ordered) // 2]
        # Six times the machine's own rhythm, floored at an hour so a very
        # fast sweep interval does not make ordinary jitter look like an
        # outage.
        gap_threshold = max(median * 6, 3600)

    broken_after: set = set()   # sweep ids immediately AFTER a gap
    gaps = 0
    largest_gap = 0.0
    if gap_threshold:
        for index in range(1, len(sweeps)):
            before, after = times[index - 1], times[index]
            if before is None or after is None:
                continue
            delta = after - before
            if delta > gap_threshold:
                broken_after.add(sweeps[index]["id"])
                gaps += 1
                largest_gap = max(largest_gap, delta)

    window["series_gaps"] = gaps
    window["largest_gap_hours"] = round(largest_gap / 3600, 1) if largest_gap else 0
    if gaps:
        window["gap_note"] = (
            f"The sweep series is NOT continuous: {gaps} gap(s), the largest "
            f"{round(largest_gap / 3600, 1)} hours. AgentalSec was not running "
            f"then. Absence streaks are counted only within an unbroken run, "
            f"because a device cannot be called missing for a period when "
            f"nothing was looking."
        )

    devices = []

    for addr, present_in in sorted(seen_at.items()):
        count = len(present_in)

        streak = 0
        for sid in reversed(sweep_ids):
            if sid in present_in:
                break
            streak += 1
            # Stop at the first gap. Everything older than the gap belongs to
            # a different run, and misses either side of a shutdown are not
            # consecutive in any sense the user means.
            if sid in broken_after:
                break

        last_present = None
        for sid in reversed(sweep_ids):
            if sid in present_in:
                last_present = _to_iso_utc(id_to_time[sid])
                break

        counts = via_counts.get(addr, {})
        arp_only = counts.get("arp", 0)

        # The vendor is stamped here too, not only on known_devices, and that
        # is the whole point. The device this was built for was NOT in the
        # inventory, so query_known_devices returned nothing for it and the
        # only place its hardware address existed was this list. See TODO 36.
        devices.append(_stamp_vendor({
            "ip":               addr,
            "mac":              macs.get(addr),
            "known_as":         labels.get(addr),
            "present_in":       count,
            "of_sweeps":        total,
            "presence_rate":    round(count / total, 3),
            "absent_streak":    streak,
            "last_present_at":  last_present,
            "answered_via":     counts,
            # Surfaced rather than left to be worked out of answered_via,
            # because it changes what the number means. An ARP cache entry is
            # the operating system's recollection and outlives the device; a
            # device seen only that way may already be gone.
            "arp_only_sweeps":  arp_only,
            # Which other addresses answered on this device's behalf, when it
            # has merged appearances. Empty for an ordinary device. Surfaced
            # rather than hidden, so a reader can see that the presence figure
            # is a roll-up and check the merge if it looks wrong.
            "answered_by_appearances": sorted(rolled_up.get(addr, [])),
        }))

    devices.sort(key=lambda d: (-d["absent_streak"], d["presence_rate"]))

    notes = []
    if total < PRESENCE_THIN_DENOMINATOR:
        notes.append(
            f"ONLY {total} usable sweep(s). That is too few to call anything "
            f"a pattern. Report the raw counts, not a rate."
        )
    if failed:
        notes.append(
            f"{failed} sweep(s) failed and are excluded from the denominator. "
            f"They are not absences."
        )
    notes.append(
        "Sweeps only run while AgentalSec is running. A gap in wall-clock "
        "time between sweeps is the tool being off, never a device being "
        "away. Read first_sweep_at and last_sweep_at before treating this as "
        "a continuous record."
    )
    notes.append(
        "A low presence_rate is not by itself a finding. Phones and laptops "
        "sleep and leave, and that is normal. It matters for a device that is "
        "supposed to be permanently present, and which devices those are is a "
        "question for the user, not an inference from this table."
    )
    if any(d["arp_only_sweeps"] for d in devices):
        notes.append(
            "Some presence here is ARP-only, meaning this machine's ARP cache "
            "still held an entry but the device did not reply to a ping. That "
            "is a weaker claim than an ICMP reply and can outlive the device."
        )

    # TODO 94.12. Said in the note as well as in the window, because every
    # rate in this answer is a fraction of sweeps_counted and a reader who
    # takes the window for the whole history will read a rate for the last
    # hour as a rate for the last month.
    if window.get("complete") is False:
        notes.insert(0, (
            f"THIS IS A WINDOW, NOT THE WHOLE HISTORY. "
            f"{window['usable_sweeps_in_range']} usable sweep(s) match and "
            f"this used the {window['sweeps_counted']} most recent. Every "
            f"rate below is a fraction of those. Raise max_sweeps, or set "
            f"since, to move the window deliberately."))
    elif window.get("complete") is None and "complete" in window:
        notes.insert(0, (
            "COULD NOT COUNT how many usable sweeps exist, so there is no "
            "way to tell whether this window is the whole range. Do not read "
            "it as complete."))
    return {"window": window, "devices": devices, "note": " ".join(notes)}


# DEVICE PERMANENCE AND DRIFT (schema v13)


def is_randomized_mac(mac: str) -> bool:
    """
    True if this is a randomized (locally administered) hardware address.

    Bit 1 of the first octet is the locally-administered bit. Set means the
    address was assigned by software rather than burned in at the factory,
    which on a home or office network overwhelmingly means MAC randomization
    on a phone or a laptop. This is a bit test, not a heuristic.

    It matters because randomizing devices present a NEW address per network
    and on a timer, so treating an address as a device identity would file
    the same phone as a new arrival over and over. That is not a cosmetic
    problem: a review queue that fills with the same device wearing new
    addresses stops being read, and an unread queue is worse than no queue
    because it still looks like coverage.

    The useful part is that the partition is almost free. Devices that
    randomize are the ones that come and go. Devices that are permanently
    present, routers, printers, televisions, speakers, cameras, use burned
    in addresses and do not randomize. So the set this excludes is very nearly
    exactly the set that should never have been marked permanent anyway.

    Unparseable or absent input returns False. Refusing to guess is right
    here: a missing address is a reason to ask, not a reason to classify.
    """
    if not mac:
        return False
    first = str(mac).strip().replace("-", ":").split(":")[0]
    try:
        return bool(int(first, 16) & 0b10)
    except ValueError:
        return False


_MAC_SHAPE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")


def identity_class(mac: str) -> str:
    """
    Whether an address is a usable identity for a device.

    'transient_client'  randomized address. This is one appearance of a
                        device that will look different next time, so the row
                        is an observation rather than a device.
    'stable_host'       burned-in address. The row can stand for a device.
    'no_hardware_address' nothing to judge on. Common and not suspicious:
                        ARP does not always have an entry, and a device one
                        hop away never appears in it at all.
    'unreadable_mac'    something is recorded but it is not a MAC (cut off,
                        junk, all zeros). Not guessed to be stable.

    Three values rather than two on purpose. Folding the third into
    'stable_host' would let a missing address quietly become a claim that the
    address is stable, which is the failure this codebase keeps writing rules
    about. Absence of evidence gets its own name.
    """
    if not mac or not str(mac).strip():
        return "no_hardware_address"
    norm = str(mac).strip().lower().replace("-", ":")
    if (not _MAC_SHAPE.fullmatch(norm)
            or norm in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")):
        # Truncated or junk: not guessed to be stable.
        return "unreadable_mac"
    return "transient_client" if is_randomized_mac(mac) else "stable_host"


def _with_identity_class(rows: list[dict]) -> list[dict]:
    """
    Stamp identity_class and the hardware vendor onto device rows on the way
    out.

    THE VENDOR IS DONE HERE AND NOT AS A TOOL, 2026-09-02. The obvious
    alternative was a `lookup_mac_vendor` tool the model calls when it wants
    one. The reason not to: on 2026-09-01 the model spent a long investigation
    identifying a device from its broadcast ports, got it wrong, and the
    address was sitting in the row the whole time. A tool it has to remember
    to call is a tool it will not call while it is busy being confident. A
    field that is simply there cannot be forgotten.

    It rides alongside identity_class rather than replacing it. They answer
    different questions: identity_class is whether the address is stable
    enough to BE an identity, vendor_status is who made the hardware. A
    randomized address is transient_client AND has no vendor, and the model
    needs both halves to read it correctly.

    Read `vendor_status` before `vendor`. See core/oui.py for why an absent
    vendor is four different claims.
    """
    for row in rows:
        row["identity_class"] = identity_class(row.get("mac"))
        _stamp_vendor(row)
    return rows


def _stamp_vendor(row: dict) -> dict:
    """
    Add vendor, vendor_status and vendor_note from the row's `mac`.

    Never overwrites an existing non-empty `vendor`. The scanner and the human
    both write that column, and a registry name is weaker evidence than either
    of them: the registry says who made the network chip, which on plenty of
    devices is not the company on the box. Where the two disagree, whoever
    looked at the actual device wins.
    """
    try:
        from core import oui
        found = oui.lookup(row.get("mac"))
    except Exception:
        # A vendor lookup must never be able to stop a device list rendering.
        return row

    if row.get("vendor"):
        row["vendor_status"] = "already_recorded"
        row["registry_vendor"] = found["vendor"]
        row["vendor_note"] = (
            "vendor came from a scan or a person. registry_vendor is what the "
            "IEEE registry says about the address, shown separately rather "
            "than merged so a disagreement stays visible."
        )
    else:
        row["vendor"] = found["vendor"]
        row["vendor_status"] = found["status"]
        row["vendor_note"] = found["note"]

    # Both paths, not just the registry one. Since 36.3 the vendor is also
    # written into the row at save time, so the already_recorded branch is
    # now the NORMAL one for a device the scanner has seen twice, and having
    # the suggestion only on the other branch meant it quietly stopped
    # appearing the moment the column was filled in.
    _stamp_suggested_name(row)
    return row


# Trailing words the IEEE registry carries because it holds LEGAL names.
# Nobody wants "Amazon Technologies Inc. device" in a device list, so they come
# off the end of a SUGGESTION only. The stored vendor keeps the full name,
# because that is the thing with a source behind it.
_VENDOR_TAIL = {
    "inc", "inc.", "llc", "l.l.c.", "ltd", "ltd.", "limited", "corp",
    "corp.", "corporation", "co", "co.", "company", "gmbh", "ag", "sa",
    "s.a.", "bv", "b.v.", "nv", "n.v.", "plc", "pty", "oy", "ab", "as",
    "technologies", "technology", "electronics", "electronic", "foundation",
    "international", "systems", "solutions", "communications", "networks",
}


def _short_vendor(vendor: str) -> str:
    """A registered name cut down to what a person would call the maker."""
    words = vendor.split(",")[0].split()
    while len(words) > 1 and words[-1].lower().strip(".,") in _VENDOR_TAIL:
        words.pop()
    return " ".join(words)


def _stamp_suggested_name(row: dict) -> dict:
    """
    A name to OFFER when somebody is about to name this device. TODO 36.3.

    It is a suggestion and it is labelled as one. 4A's rule stands: the human
    is the enrollment authority here because there is no MDM, so this makes
    the naming cheaper, it does not do the naming. Nothing reads
    suggested_name except a person deciding what to type.

    A hostname beats a vendor, because a hostname is what the device calls
    itself and a registry entry is only who made the network chip. Neither is
    offered for an address the device made up for itself, since a name
    attached to a randomized address is a name for one afternoon.
    """
    if (row.get("known_as") or "").strip():
        return row
    if row.get("identity_class") == "transient_client":
        return row

    hostname = (row.get("hostname") or "").strip()
    if hostname:
        row["suggested_name"] = hostname
        row["suggested_name_basis"] = "the hostname the device answers to"
        return row

    vendor = (row.get("vendor") or "").strip()
    if vendor and row.get("vendor_status") in ("resolved", "already_recorded"):
        row["suggested_name"] = f"{_short_vendor(vendor)} device"
        row["suggested_name_basis"] = ("who registered the hardware address. "
                                       "It is the maker of the network part, "
                                       "not the brand on the box, so change it "
                                       "if you know better.")
    return row


def build_device_fingerprint(ip: str) -> dict:
    """
    What this device looks like RIGHT NOW, from what the tool actually
    observes.

    Contents are deliberately limited to things this codebase produces. There
    is no OS field, because nothing here fingerprints a remote operating
    system and a column that is always null is a claim the tool cannot
    support. There is no banner either, for the reason written on
    port_scan_results.banner: nothing is ever read off the wire, so there is
    nothing to record.

    ports_observed carries its own provenance. `scanned` is False when no port
    scan has ever run against this address, and that is not the same as a
    device with nothing open. Collapsing the two would turn "never looked" into
    "nothing there", which is the failure this project keeps a rule about.
    """
    with _get_readonly_conn() as conn:
        device = conn.execute(
            "SELECT ip, mac, vendor, hostname FROM known_devices WHERE ip = ?",
            (ip,)
        ).fetchone()

        scans = conn.execute(
            "SELECT COUNT(*) AS n, MAX(scanned_at) AS last FROM port_scan_results "
            "WHERE target_host = ?", (ip,)
        ).fetchone()

        ports = [
            r["port"] for r in conn.execute(
                "SELECT DISTINCT port FROM port_scan_results "
                "WHERE target_host = ? AND state = 'open' ORDER BY port", (ip,)
            ).fetchall()
        ]

        # WHICH PROTOCOLS THIS LIST IS ABOUT. v34.
        #
        # open_ports stays a list of bare numbers on purpose: device drift
        # compares those two sets and changing their shape would make every
        # permanent device look like it had drifted. The qualification goes
        # beside it instead, so a reader can see that a list of numbers with
        # ['tcp'] next to it says nothing at all about UDP.
        protocols_checked = [
            r["protocol"] for r in conn.execute(
                "SELECT DISTINCT protocol FROM port_scan_results "
                "WHERE target_host = ? ORDER BY protocol", (ip,)
            ).fetchall()
        ]

    scanned = bool(scans and scans["n"])

    return {
        "ip":       ip,
        "mac":      (device["mac"] if device else None) or None,
        "vendor":   (device["vendor"] if device else None) or None,
        "hostname": (device["hostname"] if device else None) or None,
        "randomized_mac": is_randomized_mac(device["mac"] if device else None),
        "ports_observed": {
            # False means no port scan has ever run against this address.
            # An empty list under scanned=False is silence, not a clean host.
            "scanned":     scanned,
            "open_ports":  ports,
            # Empty when nothing has ever been scanned here. A reader must not
            # read an empty open_ports as "nothing listening" unless this says
            # which protocols were actually probed.
            "protocols_checked": protocols_checked,
            "last_scan_at": _to_iso_utc(scans["last"]) if scanned else None,
        },
    }


def set_device_permanence(ip: str, is_permanent: bool,
                          capture_fingerprint: bool = True) -> dict:
    """
    The USER declaring that a device is, or is no longer, supposed to be here.

    THERE IS NO TOOL THAT REACHES THIS. It is called from the dashboard route
    and from nowhere else, and permanence_set_by is written as 'user'
    unconditionally rather than taken from a parameter, so there is no
    argument any caller can pass that makes this look like a person.

    That is not decoration. Permanence is what makes absence a question, so a
    model that could set it could quieten the absence signal for exactly the
    device an attacker cares about, and could be argued into doing so by text
    arriving in a packet. The project already gates the destructive tools; a
    tool that turns off a signal deserves the same treatment, and the
    strongest version of the gate is not having the tool.

    A randomized hardware address is refused. See is_randomized_mac.

    Marking a device permanent captures its fingerprint at the same moment,
    because a starting point recorded later is a starting point that already
    includes whatever changed.
    """
    _validate_entity("ip", ip)

    with _get_conn() as conn:
        row = conn.execute(
            "SELECT ip, mac, known_as FROM known_devices WHERE ip = ?", (ip,)
        ).fetchone()

    if not row:
        return {"success": False,
                "error": f"{ip} is not in known_devices. It has to be seen "
                         f"before it can be vouched for."}

    if is_permanent and is_randomized_mac(row["mac"]):
        return {
            "success": False,
            "error": (
                f"{ip} has a randomized (locally administered) hardware "
                f"address, so the address is not a stable identity for it and "
                f"it cannot be marked permanent. This is normal for phones and "
                f"laptops, which rotate addresses per network and on a timer. "
                f"Permanence is for devices that are always here and keep one "
                f"address: routers, printers, televisions, speakers, cameras."
            ),
            "randomized_mac": True,
        }
    if is_permanent and identity_class(row["mac"]) == "unreadable_mac":
        return {"success": False,
                "error": (f"{ip} has a recorded hardware address that is not a "
                          f"readable MAC, so it cannot be marked permanent. A "
                          f"fresh scan usually fixes it.")}

    fingerprint = None
    if is_permanent and capture_fingerprint:
        fingerprint = json.dumps(build_device_fingerprint(ip))

    with _get_conn() as conn:
        if is_permanent:
            conn.execute("""
                UPDATE known_devices
                   SET is_permanent = 1,
                       permanence_set_by = 'user',
                       permanence_set_at = CURRENT_TIMESTAMP,
                       enrollment_fingerprint =
                           COALESCE(?, enrollment_fingerprint),
                       enrollment_fingerprint_at =
                           CASE WHEN ? IS NULL THEN enrollment_fingerprint_at
                                ELSE CURRENT_TIMESTAMP END
                 WHERE ip = ?
            """, (fingerprint, fingerprint, ip))
        else:
            # The fingerprint is kept on purpose. Un-vouching for a device is
            # not a reason to throw away what it looked like when someone did,
            # and a user who flips the flag twice should not silently reset
            # the baseline the drift check reads.
            conn.execute("""
                UPDATE known_devices
                   SET is_permanent = 0,
                       permanence_set_by = 'user',
                       permanence_set_at = CURRENT_TIMESTAMP
                 WHERE ip = ?
            """, (ip,))

        after = conn.execute(
            "SELECT ip, known_as, is_permanent, permanence_set_at, "
            "       enrollment_fingerprint_at "
            "FROM known_devices WHERE ip = ?", (ip,)
        ).fetchone()

    # Item 3.2, before the return so it is actually reached.
    _journal("device_vouched", "known_devices", ip, {"via": "set_device_permanence"})
    return {"success": True, "device": _rows_to_dicts([after])[0]}

def _canonical_id(conn, device_id: int, _depth: int = 0) -> int:
    """
    Follow merged_into to the root row for a physical device.

    merge_devices resolves through this before writing, so stored chains
    cannot be created by the normal path. The depth guard is here anyway,
    because a row edited by hand or restored from an older backup could
    produce a cycle, and a cycle in a helper this small would hang the
    dashboard rather than fail.
    """
    seen = set()
    current = device_id
    while True:
        if current in seen or len(seen) > 32:
            logger.warning(f"Merge cycle detected at known_devices id {current}")
            return current
        seen.add(current)
        row = conn.execute(
            "SELECT merged_into FROM known_devices WHERE id = ?", (current,)
        ).fetchone()
        if not row or row["merged_into"] is None:
            return current
        current = row["merged_into"]


def merge_devices(source_ip: str, target_ip: str) -> dict:
    """
    The USER recording that two address rows are one physical device.

    THERE IS NO TOOL THAT REACHES THIS, for the reason in the schema comment
    and one that is worth restating: merging removes a row from the review
    queue. A model that could merge could fold an unexplained device into the
    printer's identity and it would stop being asked about. That is the
    blinding attack carried out through filing rather than through
    suppression, and it would leave the suppression counters untouched.

    Nothing is deleted. The source row keeps its history and its own
    observations; it gains a pointer saying which device it is an appearance
    of. unmerge_device puts it back.

    Refusals, each for a specific reason:

    * A row cannot merge into itself, directly or after resolution.
    * A row that is marked permanent cannot be merged away. Saying "this
      device I vouched for is actually an appearance of that other one"
      should require un-vouching first, deliberately, rather than happening
      as a side effect of tidying.
    * The target is resolved to its own root first, so chains cannot form and
      every merged row points straight at a canonical row.
    """
    _validate_entity("ip", source_ip)
    _validate_entity("ip", target_ip)

    if source_ip == target_ip:
        return {"success": False, "error": "A device cannot be merged into itself."}

    with _get_conn() as conn:
        rows = {
            r["ip"]: r for r in conn.execute(
                "SELECT id, ip, known_as, is_permanent, merged_into "
                "FROM known_devices WHERE ip IN (?, ?)", (source_ip, target_ip)
            ).fetchall()
        }

        for addr in (source_ip, target_ip):
            if addr not in rows:
                return {"success": False,
                        "error": f"{addr} is not in known_devices."}

        source, target = rows[source_ip], rows[target_ip]

        if source["is_permanent"]:
            return {
                "success": False,
                "error": (
                    f"{source_ip} is marked as a permanently present device. "
                    f"Merging it away would remove a device you vouched for. "
                    f"Clear its permanence first if that is really what you "
                    f"mean."
                ),
            }

        target_root = _canonical_id(conn, target["id"])
        if target_root == source["id"]:
            return {
                "success": False,
                "error": (
                    f"{target_ip} already resolves to {source_ip}, so this "
                    f"merge would make a cycle."
                ),
            }

        # Rows already pointing at the source come along, so merging B into C
        # after A was merged into B leaves A pointing at C rather than at a
        # row that is itself an appearance.
        moved = conn.execute(
            "UPDATE known_devices SET merged_into = ? WHERE merged_into = ?",
            (target_root, source["id"])
        ).rowcount or 0

        conn.execute("""
            UPDATE known_devices
               SET merged_into = ?, merged_at = CURRENT_TIMESTAMP,
                   merged_by = 'user'
             WHERE id = ?
        """, (target_root, source["id"]))

        canonical = conn.execute(
            "SELECT ip, known_as FROM known_devices WHERE id = ?", (target_root,)
        ).fetchone()

    return {
        "success": True,
        "merged": source_ip,
        "into": canonical["ip"],
        "canonical_known_as": canonical["known_as"],
        "also_repointed": moved,
    }


def unmerge_device(ip: str) -> dict:
    """
    Undo one merge. A merge is a claim, and claims get revised.

    Only the row named is detached. Anything that was repointed onto the
    canonical row during the original merge stays there, because those were
    separate claims about separate rows and undoing one should not silently
    undo the others.
    """
    _validate_entity("ip", ip)

    with _get_conn() as conn:
        row = conn.execute(
            "SELECT id, merged_into FROM known_devices WHERE ip = ?", (ip,)
        ).fetchone()
        if not row:
            return {"success": False, "error": f"{ip} is not in known_devices."}
        if row["merged_into"] is None:
            return {"success": False,
                    "error": f"{ip} is not merged into anything."}

        conn.execute("""
            UPDATE known_devices
               SET merged_into = NULL, merged_at = NULL, merged_by = NULL
             WHERE id = ?
        """, (row["id"],))

    return {"success": True, "unmerged": ip}


def device_appearances(canonical_ip: str = None) -> dict:
    """
    Which address rows are recorded as appearances of which device.

    Read only and safe for anyone to call. This is the answer to "how many
    devices are actually on this network", which is a different number from
    how many rows known_devices holds and has been since the table was keyed
    on IP.
    """
    with _get_readonly_conn() as conn:
        rows = _rows_to_dicts(conn.execute(
            "SELECT id, ip, known_as, merged_into, mac FROM known_devices"
        ).fetchall())

    by_id = {r["id"]: r for r in rows}
    groups: dict = {}

    for row in rows:
        root_id = row["id"]
        seen = set()
        while by_id.get(root_id, {}).get("merged_into") is not None:
            if root_id in seen:
                break
            seen.add(root_id)
            root_id = by_id[root_id]["merged_into"]
        groups.setdefault(root_id, []).append(row)

    out = []
    for root_id, members in groups.items():
        root = by_id.get(root_id)
        if not root:
            continue
        if canonical_ip and root["ip"] != canonical_ip:
            continue
        appearances = [m["ip"] for m in members if m["id"] != root_id]
        out.append({
            "ip":          root["ip"],
            "known_as":    root["known_as"],
            "appearances": sorted(appearances),
            "appearance_count": len(appearances),
        })

    out.sort(key=lambda d: -d["appearance_count"])
    return {
        "devices":    out,
        "row_count":  len(rows),
        "device_count": len(out),
        "note": (
            f"{len(rows)} address row(s) resolve to {len(out)} device(s). "
            f"known_devices is keyed on IP, so a device that took several "
            f"leases has several rows; the device count is the one to quote."
        ),
    }


# WHEN PYTHON MAY RAISE A FINDING (decided 2026-08-28)
#
# THE RULE: Python raises a finding only when it can point to an expectation
# THE USER EXPLICITLY DECLARED. Everything else waits to be asked.
#
# This is the single answer to a question that was about to be answered three
# separate times, inconsistently:
#
#   Absence of a permanent device      RAISES. The user marked it permanent.
#                                      That declaration IS the expectation,
#                                      and reporting its violation is
#                                      arithmetic, not judgement.
#
#   Drift on an enrolled fingerprint   RAISES. Enrolling the device recorded
#                                      what it looked like. Same argument.
#
#   DNS novelty                        DOES NOT. No declaration exists, so any
#                                      threshold would be Python inventing an
#                                      opinion. A laptop resolves hundreds of
#                                      new names an hour and a camera none for
#                                      months, so a fixed number is wrong for
#                                      one of them by construction. That is
#                                      STATIC-001 again: the class of mistake
#                                      that once reported a 2017 CVE on a
#                                      machine where it could not exist.
#
# The rule also explains WHY the third differs rather than merely excluding
# it, which is what makes it usable on the next feature instead of being
# re-litigated.
#
# Rule 2 is intact. Python still does not decide what is suspicious. The user
# decided; Python is reporting that what they declared is no longer true, and
# the model still weighs what that means.

# Consecutive missed sweeps before a permanent device is retired. Deliberately
# larger than the absence-finding threshold: report first, retire later. A
# device that vanishes should generate a question before it generates a
# shrug.
RETIRE_AFTER_MISSES  = 96     # ~24h at the 15 minute sweep interval
ABSENCE_FINDING_AFTER = 8     # ~2h, long enough to survive a reboot


def record_probe_run(session_id: str, outcome: str, detail: str = None,
                     eligible: int = 0, probed: int = 0, excluded: int = 0,
                     deferred: int = 0, drift_found: int = 0,
                     retired: int = 0, sensor_id: str = None) -> int:
    """
    Write one probe pass. A pass that could not run is recorded as failed.

    Same reasoning as record_presence_sweep: if a broken probe left no row, a
    stretch where it was broken would be indistinguishable from a stretch
    where nothing changed, and the second reading is the dangerous one.

    'skipped' is neither. It is the ordinary case where the cadence has not
    elapsed, recorded so that "the probe has not actually run in five weeks"
    is answerable rather than assumed.
    """
    if outcome not in ("ok", "failed", "skipped"):
        raise BadInput("outcome must be 'ok', 'failed' or 'skipped'")

    with _get_conn() as conn:
        cur = conn.execute("""
            INSERT INTO probe_run
                (session_id, outcome, detail, eligible, probed, excluded,
                 deferred, drift_found, retired, finished_at, sensor_id)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
        """, (session_id, outcome, detail, int(eligible), int(probed),
              int(excluded), int(deferred), int(drift_found), int(retired),
              sensor_id or _local_sensor_id()))
        return cur.lastrowid


def last_probe_run(outcome: str = "ok") -> dict | None:
    """The most recent probe pass with this outcome, or None."""
    with _get_readonly_conn() as conn:
        row = conn.execute(
            "SELECT * FROM probe_run WHERE outcome = ? "
            "ORDER BY started_at DESC, id DESC LIMIT 1", (outcome,)
        ).fetchone()
    return _rows_to_dicts([row])[0] if row else None


def permanent_devices() -> list[dict]:
    """
    Devices the user declared MEMBERS of this network, not yet retired.

    Membership only. This says nothing about whether any of them is powered
    on, and nothing that reads this list may treat absence from it as an
    event. See always_on_devices for the availability question, which is a
    separate declaration on purpose.
    """
    with _get_readonly_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM known_devices "
            "WHERE is_permanent = 1 AND retired_at IS NULL ORDER BY ip"
        ).fetchall()
    return _with_identity_class(_rows_to_dicts(rows))


def always_on_devices() -> list[dict]:
    """
    Devices the user declared should ALWAYS BE ANSWERING, not yet retired.

    v22. This is the only list whose absence is a finding, and the licence
    comes from the same place it always did: the user said so. What changed is
    that they now have to say THIS, rather than having it inferred from having
    said something else.

    Expected to be short. On a home network it is usually the gateway and
    nothing else, and a long list here is worth a second look, because a user
    who marks everything always-on has re-created the noise this split was
    made to remove.
    """
    with _get_readonly_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM known_devices "
            "WHERE expected_always_on = 1 AND retired_at IS NULL ORDER BY ip"
        ).fetchall()
    return _with_identity_class(_rows_to_dicts(rows))


def set_device_always_on(ip: str, always_on: bool) -> dict:
    """
    Declare, or withdraw, that a device should always be answering.

    Called from scripts/set_always_on.py and from nowhere the model can reach,
    for the same reason set_device_permanence is not in the manifest: this is
    the statement that makes absence loud, so it has to come from a person.
    """
    with _get_conn() as conn:
        # A database that has not run the v22 migration has no column to set,
        # and letting sqlite raise "no such column" at a person who typed a
        # correct command is a bad way to tell them to start the app once.
        cols = {r[1] for r in conn.execute("PRAGMA table_info(known_devices)")}
        if "expected_always_on" not in cols:
            return {"ok": False, "reason": (
                "This database has not run the v22 migration yet, so there is "
                "no availability column to set. Start main.py once to "
                "migrate, then run this again.")}

        row = conn.execute(
            "SELECT ip, known_as, is_permanent FROM known_devices "
            "WHERE ip = ?", (ip,)).fetchone()
        if not row:
            return {"ok": False, "reason": f"{ip} is not in the inventory."}
        conn.execute(
            "UPDATE known_devices SET expected_always_on = ? WHERE ip = ?",
            (1 if always_on else 0, ip))
        out = {"ok": True, "ip": ip, "known_as": row["known_as"],
               "expected_always_on": bool(always_on),
               "is_permanent": bool(row["is_permanent"])}
    _journal("device_vouched", "known_devices", ip,
             {"via": "set_device_always_on", "always_on": bool(always_on)})
    return out


def retire_device(ip: str, reason: str) -> dict:
    """
    Stop expecting a device that has gone.

    Clears is_permanent and stamps retired_at, so absence stops being
    reported. Without this one discarded printer reports missing on every
    sweep forever, the user stops reading absence alerts within days, and the
    signal is lost, not broken, ignored, which is worse because the
    mechanism still looks like it is working.

    permanence_set_by is deliberately left alone: it records who last vouched
    for the device, which stays true and is worth keeping. retired_at is what
    distinguishes an automatic retirement from the user un-vouching by hand.

    The row and the enrollment fingerprint both survive. If the device comes
    back, everything needed to recognise it is still here.
    """
    _validate_entity("ip", ip)
    with _get_conn() as conn:
        conn.execute("""
            UPDATE known_devices
               SET is_permanent = 0,
                   retired_at = CURRENT_TIMESTAMP,
                   retired_reason = ?
             WHERE ip = ? AND retired_at IS NULL
        """, (reason, ip))
        row = conn.execute(
            "SELECT ip, known_as, retired_at, retired_reason "
            "FROM known_devices WHERE ip = ?", (ip,)
        ).fetchone()
    # Item 3.2, before the return so it is actually reached.
    _journal("device_retired", "known_devices", ip, {"via": "retire_device"})
    return {"success": True, "device": _rows_to_dicts([row])[0] if row else None}

def query_device_drift(ip: str = None) -> dict:
    """
    How each enrolled device compares with what it looked like at enrollment.

    This is the answer to "known does not mean safe" having been an
    instruction with no evidence behind it. A device whose open port set has
    grown, or whose hardware address has changed under the same address, has
    changed character, and a device changing character is the signal the
    inventory exists to make visible.

    Reports the comparison and NEVER a verdict. Whether a newly open port is
    a firmware update or an intrusion is not a question arithmetic can answer,
    and Python guessing at it here would be exactly the hardcoded judgement
    this codebase already got burned by once.

    A device with no enrollment fingerprint is reported as such rather than
    skipped. Silence would read as "no drift", which is the wrong answer to
    "nothing to compare against".
    """
    with _get_readonly_conn() as conn:
        sql = ("SELECT ip, mac, vendor, hostname, known_as, is_permanent, "
               "       enrollment_fingerprint, enrollment_fingerprint_at "
               "FROM known_devices WHERE is_permanent = 1")
        params: list = []
        if ip:
            sql += " AND ip = ?"
            params.append(ip)
        rows = conn.execute(sql + " ORDER BY ip", params).fetchall()

    devices, unbaselined = [], []

    for row in rows:
        addr = row["ip"]

        if not row["enrollment_fingerprint"]:
            unbaselined.append(addr)
            devices.append({
                "ip": addr, "known_as": row["known_as"],
                "comparable": False,
                "reason": ("Marked permanent but has no enrollment "
                           "fingerprint, so there is nothing to compare "
                           "against. This is not the same as no drift."),
            })
            continue

        try:
            before = json.loads(row["enrollment_fingerprint"])
        except (ValueError, TypeError):
            devices.append({
                "ip": addr, "known_as": row["known_as"],
                "comparable": False,
                "reason": "Stored enrollment fingerprint could not be read.",
            })
            continue

        now = build_device_fingerprint(addr)

        before_ports = before.get("ports_observed", {}) or {}
        now_ports    = now.get("ports_observed", {}) or {}
        old_set = set(before_ports.get("open_ports") or [])
        new_set = set(now_ports.get("open_ports") or [])

        # If either side never had a scan, a port difference is a difference
        # in what was looked at, not in the device. Saying so beats reporting
        # every unscanned device as having lost all its ports.
        ports_comparable = bool(before_ports.get("scanned")) and bool(now_ports.get("scanned"))

        changes = []
        if ports_comparable:
            if new_set - old_set:
                changes.append(f"ports opened since enrollment: "
                               f"{sorted(new_set - old_set)}")
            if old_set - new_set:
                changes.append(f"ports no longer open: {sorted(old_set - new_set)}")

        for field in ("mac", "vendor", "hostname"):
            was, is_now = before.get(field), now.get(field)
            if was and is_now and was != is_now:
                changes.append(f"{field} changed from {was} to {is_now}")

        devices.append({
            "ip":            addr,
            "known_as":      row["known_as"],
            "comparable":    True,
            "enrolled_at":   _to_iso_utc(row["enrollment_fingerprint_at"]),
            "changes":       changes,
            "ports_comparable": ports_comparable,
            "ports_note": None if ports_comparable else (
                "Ports not compared: no port scan on one side of the "
                "comparison. Run one against this host before reading "
                "anything into its port set."
            ),
            "enrollment_fingerprint": before,
            "current_fingerprint":    now,
        })

    changed = [d for d in devices if d.get("changes")]

    notes = [
        "Differences only. Nothing here is a verdict. A newly open port can "
        "be a firmware update or an intrusion, and deciding which is your "
        "job, not this table's.",
    ]
    if unbaselined:
        notes.append(
            f"{len(unbaselined)} permanent device(s) have no enrollment "
            f"fingerprint and were NOT compared. Absence of drift for them is "
            f"absence of a baseline."
        )
    if not rows:
        notes.append(
            "No device is marked permanent, so there is nothing to compare. "
            "That is a gap in what the user has told the tool, not a finding "
            "about the network."
        )

    return {
        "devices_compared": len(devices),
        "devices_changed":  len(changed),
        "devices":          devices,
        "note":             " ".join(notes),
    }


# READ, KNOWN DEVICES (model read-only)

def query_known_devices(ip: str = None, with_total: bool = False):
    """Get all known network devices, or a specific IP."""
    with _get_readonly_conn() as conn:
        if ip:
            rows = conn.execute(
                "SELECT * FROM known_devices WHERE ip = ?", (ip,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM known_devices ORDER BY last_seen DESC"
            ).fetchall()
        out = _with_identity_class(_rows_to_dicts(rows))
        # TODO 94.18. No LIMIT above, so this is everything that matched.
        return _all_rows(out, "devices") if with_total else out


def save_known_device(ip: str, mac: str = None, vendor: str = None,
                      hostname: str = None, known_as: str = None,
                      device_type: str = None, notes: str = None):
    """
    Upsert the OBSERVED facts about a device. The network scanner calls this.

    Deliberately does not touch identified_by, evidence or identified_at.
    Who decided what a device is, and what a ping sweep found, are different
    kinds of claim, and a scan re-running must never look like a fresh
    identification.

    A RETIRED DEVICE THAT IS SEEN AGAIN GETS ITS RETIREMENT LIFTED HERE,
    2026-09-24. `retire_device` stamps retired_at and nothing in the tree
    cleared it, so a device that came back was invisible to every rule that
    watches a device (permanent_devices and always_on_devices both filter
    retired_at IS NULL) while its row said it was gone. This function runs on
    every observation, so it is the one place that cannot miss the return.
    The lift itself lives in reacknowledge_device, which also MOVES the
    retirement facts rather than deleting them. is_permanent is NOT restored —
    that is the operator's statement, and a device answering a probe is not
    one. expected_always_on is not written either way; it was never cleared by
    the retirement, so a device declared always-on becomes loud again the
    moment this runs. See reacknowledge_device's docstring for why that
    asymmetry is deliberate.
    """
    with _get_conn() as conn:
        # Seen again, therefore not gone. Checked BEFORE the upsert so the row
        # below is written against a live device rather than a retired one.
        try:
            was_retired = conn.execute(
                "SELECT retired_at FROM known_devices WHERE ip = ? AND "
                "retired_at IS NOT NULL", (ip,)).fetchone()
        except sqlite3.Error:
            was_retired = None

        conn.execute("""
            INSERT INTO known_devices(ip, mac, vendor, hostname, known_as, device_type, notes)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                mac        = COALESCE(excluded.mac, mac),
                vendor     = COALESCE(excluded.vendor, vendor),
                hostname   = COALESCE(excluded.hostname, hostname),
                known_as   = COALESCE(excluded.known_as, known_as),
                device_type= COALESCE(excluded.device_type, device_type),
                notes      = COALESCE(excluded.notes, notes),
                last_seen  = CURRENT_TIMESTAMP
        """, (ip, mac, vendor, hostname, known_as, device_type, notes))

        # THE REGISTRY NAME, WRITTEN DOWN. TODO 36.3.
        #
        # Read time already covers every screen, so this is not about the
        # answer being available, it is about the row being complete: an
        # export, a query somebody writes by hand, or a future table that
        # forgets to stamp on the way out all see the column now.
        #
        # It only fills an EMPTY vendor, never replaces one. A scan or a
        # person looked at the actual device; the registry only knows who
        # made the network chip, and where they disagree the registry loses.
        if not vendor and mac:
            try:
                from core import oui
                found = oui.lookup(mac)
                if found.get("status") == "resolved" and found.get("vendor"):
                    conn.execute(
                        "UPDATE known_devices SET vendor = ? "
                        "WHERE ip = ? AND (vendor IS NULL OR vendor = '')",
                        (found["vendor"], ip))
            except Exception as e:
                # Same rule as everywhere else this lookup appears: it must
                # never be able to stop a device being recorded.
                logger.debug(f"oui: could not stamp a vendor for {ip}: {e}")

    # OUTSIDE the connection above, so the lift runs on the committed row and
    # so a failure in it cannot roll back an observation. It cannot raise —
    # see reacknowledge_device — but the guard is stated rather than assumed,
    # because this call sits on the scan's hot path.
    changed = None
    if was_retired:
        try:
            lift = reacknowledge_device(
                ip, reason="seen answering again by the network scanner")
            changed = lift.get("changed")
            if changed:
                logger.info(
                    f"Device {ip} answered again after being retired "
                    f"{was_retired['retired_at']}; the retirement was lifted. "
                    f"It is NOT permanent and NOT declared always-on.")
        except Exception as e:                              # noqa: BLE001
            logger.warning(f"could not lift the retirement on {ip}: {e}")
    return {"ip": ip, "retirement_lifted": bool(changed)}


def identify_device(ip: str, known_as: str, device_type: str = None,
                    notes: str = None, evidence: str = None,
                    identified_by: str = "model") -> dict:
    """
    Record what a device IS, together with the basis for saying so.

    Identifying is not dismissing. The row stays fully monitored. All this
    does is give every later report a name to use instead of an address, plus
    a stated reason that a future session is free to disagree with.

    evidence is required and is not decorative. The failure it is built
    against went: the user mentioned owning a games console, the agent then
    reported a device as that console, and cited a service record that in
    fact belongs to a different vendor entirely. Both the suggestion and the
    misread record would have been visible in this field, and either one is
    enough for the next reader to throw the label out.

    Returns the row as it now stands, so the caller reports what was actually
    stored rather than what it meant to store.
    """
    _validate_entity("ip", ip)

    label = (known_as or "").strip()
    if not label:
        return {"success": False, "error": "known_as is required."}

    basis = (evidence or "").strip()
    if not basis:
        return {
            "success": False,
            "error": ("evidence is required. State what the identification "
                      "rests on: an OUI vendor match, a hostname, an observed "
                      "service, or that the user said so. If the only basis is "
                      "that it seemed likely, do not identify it."),
        }

    if identified_by not in ("user", "model"):
        identified_by = "model"

    with _get_conn() as conn:
        existing = conn.execute(
            "SELECT id FROM known_devices WHERE ip = ?", (ip,)
        ).fetchone()

        if existing is None:
            # A device nothing has ever seen. Allowed, because the user can
            # describe something before a scan reaches it, but it arrives
            # with no observed facts attached and reads that way.
            conn.execute("""
                INSERT INTO known_devices(ip, known_as, device_type, notes,
                                          identified_by, evidence, identified_at)
                VALUES(?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (ip, label, device_type, notes, identified_by, basis))
        else:
            conn.execute("""
                UPDATE known_devices SET
                    known_as      = ?,
                    device_type   = COALESCE(?, device_type),
                    notes         = COALESCE(?, notes),
                    identified_by = ?,
                    evidence      = ?,
                    identified_at = CURRENT_TIMESTAMP
                WHERE ip = ?
            """, (label, device_type, notes, identified_by, basis, ip))

        row = conn.execute(
            "SELECT * FROM known_devices WHERE ip = ?", (ip,)
        ).fetchone()

    return {"success": True, "device": dict(row) if row else None}


PREF_ENROLLMENT_DONE = "enrollment_completed_at"


def enrollment_state() -> dict:
    """
    Everything a first-run walkthrough needs, and nothing it should infer.

    THE SUBSTITUTE FOR AN MDM. There is no Intune here, so the human is the
    enrollment authority: the tool enumerates, the person says what each thing
    is and which ones are supposed to be here permanently. This is the backend
    for that conversation; the interface is the dashboard's.

    Deliberately reports THREE populations rather than one number, because
    "12 devices need reviewing" is misleading on any real network:

      needs_review        stable hardware address, no label. Genuinely
                          unknown, and the only count worth showing
                          prominently.
      transient_clients   randomized address. Appearances of phones and
                          laptops, several of which are probably the same
                          handset. Reviewing them individually is wasted
                          effort and counting them is misleading.
      no_hardware_address nothing to judge on. Missing evidence, not a
                          device.

    completed_at records that the user has been through the walkthrough once.
    It does NOT mean there is nothing left to review, and it is named for what
    it is so nobody reads it as an all-clear: new devices appear on a live
    network forever and the queue is never permanently empty.
    """
    queue = unidentified_devices()

    def of(cls):
        return [d for d in queue if d.get("identity_class") == cls]

    needs_review = of("stable_host")
    permanent    = permanent_devices()
    completed    = get_preference(PREF_ENROLLMENT_DONE)

    # DEVICES THAT COULD BE MARKED PERMANENT BUT ARE NOT YET.
    #
    # Separate from needs_review, and the distinction is the one this whole
    # feature rests on: NAMING AND VOUCHING ARE DIFFERENT ACTS.
    #
    # The first version of the walkthrough listed only unnamed devices, which
    # meant a user who had already named everything, the normal state after
    # using the tool for a while, saw an empty table and had no way to mark
    # anything permanent at all. The queue was answering "what have you not
    # labelled" when the walkthrough also needs to ask "what should always be
    # here". A dead end, and it was found by someone opening the page.
    #
    # Randomized addresses are excluded because they cannot be permanent
    # anyway, so offering the button would only produce a refusal.
    permanent_ips = {d["ip"] for d in permanent}
    candidates = [
        d for d in query_known_devices()
        if d.get("identity_class") == "stable_host"
        and d["ip"] not in permanent_ips
        and not d.get("retired_at")
    ]

    return {
        "completed_at": completed,
        "has_been_run": bool(completed),
        "counts": {
            "needs_review":        len(needs_review),
            "transient_clients":   len(of("transient_client")),
            "no_hardware_address": len(of("no_hardware_address")),
            "unreadable_mac":      len(of("unreadable_mac")),
            "retired":             len([d for d in query_known_devices()
                                        if d.get("retired_at")]),
            "identified":          len([d for d in query_known_devices()
                                        if (d.get("known_as") or "").strip()]),
            "marked_permanent":    len(permanent),
            "not_yet_permanent":   len(candidates),
        },
        # Already ordered by the queue's own sort, stable hosts first.
        "needs_review": needs_review,
        # Named or not: anything with a stable address that has not been
        # vouched for. This is what the walkthrough table shows.
        "not_yet_permanent": candidates,
        "note": (
            "needs_review is the number that means something: devices with a "
            "stable hardware address and no label. The transient count is "
            "appearances of phones and laptops rotating addresses, several of "
            "which are probably one device, so do not present it as a device "
            "count. "
            + ("No device has been marked permanently present yet, so absence "
               "cannot be a signal for anything."
               if not permanent else
               f"{len(permanent)} device(s) are marked permanently present, "
               f"so their absence is measurable.")
        ),
    }


def complete_enrollment() -> dict:
    """
    Record that the user has been through the walkthrough.

    Sets a timestamp and nothing else. It marks nothing reviewed, implies
    nothing about the queue being empty, and grants no device anything. It
    exists only so the dashboard can stop showing a first-run flow to someone
    who has already done it.
    """
    from datetime import datetime, timezone
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    set_preference(PREF_ENROLLMENT_DONE, when)
    # Item 3.2, before the return so it is actually reached.
    _journal("enrollment_completed", "known_devices", "-", {"via": "complete_enrollment"})
    return {"success": True, "completed_at": when}

def reacknowledge_device(ip: str, reason: str = None) -> dict:
    """
    A device that was retired has been seen again, and it is not retried.

    THE DEFECT THIS ANSWERS, MEASURED 2026-09-24. `retire_device` is the
    automatic end of the absence question: after RETIRE_AFTER_MISSES misses a
    device stops being expected, its row keeps `retired_at`, and nothing in
    the tree ever cleared that column — there was no un-retire path at all.
    So a device that came back was worse off than one that never left:

      * `probe._retire_permanent` iterates `permanent_devices()`, which
        filters `retired_at IS NULL`, so the returned device is never asked
        about again whatever happens to it;
      * `always_on_devices()` filters the same way, so it can never raise an
        absence finding either;
      * and the scanner's own `is_new` test is `no row for this IP`, which is
        still False for a retired row, so no arrival is reported.

    The device was in the inventory, invisible to every rule that watches a
    device, with a row that says it is gone. Measured before the fix on a
    throwaway store: retired row, the device answers again, ZERO findings and
    `retired_at` unchanged.

    WHAT IT DELIBERATELY DOES NOT DO:
      * it does not restore `is_permanent` — permanence is what makes absence
        loud, and the whole design keeps that a human statement. Retirement
        CLEARED it, and returning to the network is evidence the device exists,
        not evidence the operator wants to be woken at 3am if it leaves again.
      * it does not touch `expected_always_on`, and that is not an omission: it
        is an asymmetry that has to be reported rather than glossed. Checked in
        the live row before writing this: `retire_device` clears `is_permanent`
        and leaves `expected_always_on` ALONE, so a device retired while
        declared always-on still carries the declaration, and lifting the
        retirement puts that declaration back in force — NET-1002 can fire for
        this device again. That is the right way round, because the operator
        never withdrew it: the owner said this device should always answer, the
        machine stopped expecting it because it went quiet for a day, and it
        answers again. Clearing the flag here would silently overrule the owner. The
        asymmetry is PUBLISHED in the return so nobody has to read the code to
        find out which of the two declarations came back;
      * it does not erase the retirement. `retired_at` and `retired_reason`
        move to `unretired_at` / `unretired_reason`, and a NOTE records both,
        so the row remembers that this device once went away and came back.
        A control that deletes its own history is not a control.
    """
    _validate_entity("ip", ip)
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT ip, mac, known_as, retired_at, retired_reason FROM known_devices "
            "WHERE ip = ?", (ip,)).fetchone()
        if row is None:
            return {"success": False, "ip": ip,
                    "reason": ("there is no device row for this address, so "
                               "there is nothing to acknowledge")}
        if row["retired_at"] is None:
            return {"success": True, "ip": ip, "changed": False,
                    "reason": "this device is not retired; nothing to do",
                    "device": _rows_to_dicts([row])[0]}

        columns = {r[1] for r in conn.execute("PRAGMA table_info(known_devices)")}
        note = (f"Returned to the network after being retired "
                f"{row['retired_at']} ({row['retired_reason'] or 'no reason recorded'})."
                + (f" {reason}" if reason else ""))
        sets, params = ["retired_at = NULL", "retired_reason = NULL"], []
        if "unretired_at" in columns:
            sets.append("unretired_at = CURRENT_TIMESTAMP")
            sets.append("unretired_reason = ?")
            params.append(reason or "seen again")
        if "notes" in columns:
            sets.append("notes = CASE WHEN notes IS NULL OR notes = '' THEN ? "
                        "ELSE notes || '; ' || ? END")
            params.extend([note, note])

        conn.execute(f"UPDATE known_devices SET {', '.join(sets)} "
                     f"WHERE ip = ?", (*params, ip))
        after = conn.execute(
            "SELECT ip, mac, known_as, is_permanent, expected_always_on, "
            "       notes FROM known_devices WHERE ip = ?", (ip,)).fetchone()

    _journal("device_reacknowledged", "known_devices", ip,
             {"via": "reacknowledge_device", "was_retired_at": row["retired_at"]})
    _after = _rows_to_dicts([after])[0] if after else {}
    return {"success": True, "changed": True, "ip": ip,
            "was_retired_at": row["retired_at"],
            # REPORTED, NOT DECIDED. Both are read off the row as it stands and
            # neither is written by this function; the point is that a caller
            # (and the readiness row) can see that a device restored to
            # watching may still be declared always-on, which is what makes
            # NET-1002 able to fire for it again. See the docstring.
            "is_permanent": bool(_after.get("is_permanent")),
            "expected_always_on": bool(_after.get("expected_always_on")),
            "reason": ("the retirement is lifted and the device is watched "
                       "again. is_permanent is NOT restored, the operator "
                       "says that, and a device answering a probe is not a "
                       "statement. expected_always_on is left exactly as the "
                       "operator set it, so a device declared always-on and "
                       "then retired becomes loud again the moment it is "
                       "lifted."),
            "device": _after or None}


def inventory_gaps() -> dict:
    """
    Addresses this machine has seen answering that have no device row.

    THE HOLE THIS FILLS, MEASURED 2026-09-24. `known_devices` is written by
    `scan()` and by nothing else, and `scan()` is the tool the MODEL fires by
    hand — it is on no clock. The presence sweeper, which runs every fifteen
    minutes whether or not anyone is looking, deliberately writes no rows
    (that is its design: a tick that filed findings would be switched off in a
    day). So on a machine where nobody has asked for a scan, the presence
    record can hold an address for a week that the inventory has never heard
    of, and nothing anywhere says so.

    Measured on the owner's own store: 142 sweeps, 13 distinct addresses
    answering, 9 with a device row — and the four without one had replied to
    93, 140, 142 and 21 sweeps respectively. Two of them were seen ONLY
    through the neighbour cache, which is exactly the case `scan()`'s
    ICMP-only answer cannot see at all.

    This does not write anything. Naming a device is a person's act and the
    scan is where an arrival is reported; this is the question a reader should
    have been able to ask — "is the store missing anything the sweeps have
    been seeing" — answered from the two tables that already hold it.
    """
    with _get_readonly_conn() as conn:
        rows = conn.execute("""
            SELECT o.ip, MAX(o.mac) AS mac, COUNT(*) AS seen_in,
                   MAX(o.via)  AS last_via, MAX(s.swept_at) AS last_seen_at
              FROM presence_observation o
              JOIN presence_sweep s ON s.id = o.sweep_id
             WHERE s.outcome = 'ok'
               AND o.ip NOT IN (SELECT ip FROM known_devices)
             GROUP BY o.ip
             ORDER BY seen_in DESC
        """).fetchall()
        total_sweeps = conn.execute(
            "SELECT COUNT(*) FROM presence_sweep WHERE outcome = 'ok'"
        ).fetchone()[0]

    devices = []
    for row in rows:
        d = dict(row)
        d["identity_class"] = identity_class(d.get("mac"))
        devices.append(d)

    arp_only = [d["ip"] for d in devices if d.get("last_via") == "arp"]
    return {
        "count": len(devices),
        "sweeps_considered": total_sweeps,
        "devices": devices,
        "seen_only_in_the_neighbour_cache": arp_only,
        "note": (
            "These addresses have answered this machine's presence sweeps and "
            "have NO row in the device inventory, because only a scan writes "
            "one and a scan is fired by hand. Seen is not the same as known: "
            "an address here is something to identify, not something that has "
            "been identified. Run scan_network, or name one with "
            "identify_device, and the next reading of this list is short by "
            "that one. An address that is in the neighbour cache only (via "
            "'arp') is weaker evidence than one that replied."),
    }


def unidentified_devices() -> list[dict]:
    """
    Devices that have been seen but never named. This is the review queue.

    Separated out because "there are 30 device rows" and "we know what 4 of
    them are" are different states, and only the second one means this table
    is doing its job.

    Every row carries identity_class, and that is what keeps this queue
    readable. `known_devices` is keyed on IP, so one physical device picks up
    a fresh row every time it takes a new lease, and a phone that
    randomizes its hardware address looks like a new client to the DHCP
    server, so it takes a new lease routinely. Left unmarked, the queue fills
    with the same three phones wearing different addresses, the user stops
    opening it, and an unread queue is worse than no queue because it still
    looks like coverage.

    Sorted so stable hosts come first. A genuinely unknown device with a
    burned-in address is the row worth a person's attention; a transient
    client is usually a phone.
    """
    with _get_readonly_conn() as conn:
        # merged_into IS NULL is what actually bounds this queue. A row the
        # user has already recorded as an appearance of a known device has
        # been answered, and re-asking about it every time the phone takes a
        # new lease is how the queue became unreadable in the first place.
        # The row is not gone; device_appearances still lists it.
        rows = conn.execute("""
            SELECT * FROM known_devices
            WHERE (known_as IS NULL OR TRIM(known_as) = '')
              AND merged_into IS NULL
            ORDER BY last_seen DESC
        """).fetchall()

    devices = _with_identity_class(_rows_to_dicts(rows))
    order = {"stable_host": 0, "no_hardware_address": 1, "transient_client": 2}
    devices.sort(key=lambda d: order.get(d["identity_class"], 3))
    return devices


# READ, RUNBOOK / CISA KEV (model read-only)

# A CVE reference with no year in it. "CVE-59822" instead of
# "CVE-2026-59822", which is what a person types when they are reading the
# number off a table or half-remembering it.
_CVE_NO_YEAR_RE = re.compile(r"^\s*CVE[-_ ]?(\d{4,})\s*$", re.I)


RUNBOOK_SEVERITIES = ("critical", "high", "medium", "low", "unrated")


def query_runbook(search_term: str = None, limit: int = 20,
                  with_total: bool = False, severity: str = None):
    """
    Search runbook and CISA KEV entries.
    search_term can be a CVE ID, port number, or keyword.

    2026-09-03: A YEARLESS CVE NOW ALSO MATCHES ON ITS NUMBER.

    Someone asked about "CVE-59822". The runbook holds CVE-2026-59822, a KEV
    entry with a due date twelve days out, and the search returned nothing,
    because "CVE-59822" is not a substring of "CVE-2026-59822". The tool did
    exactly what it was written to do and the answer was still wrong, so the
    model reported "not in the runbook" about a row that was sitting there.

    That is the failure worth fixing rather than the typo. "Not in the
    runbook" is a NEGATIVE, the model states it with confidence, and nobody
    goes and checks a confident negative. A missing year in a question should
    not manufacture one.

    Only the yearless CVE shape is special-cased. A bare number is left
    alone: "443" should keep matching ports and text the way it always has,
    and widening this into fuzzy matching would trade a rare miss for a
    steady stream of wrong hits, which is the worse deal.
    """
    limit = _validate_limit(limit)
    # TODO 94.9. The where is built once and reused by the count, because a
    # runbook search is exactly where a quiet cut off is worst: the answer
    # "not in the runbook" is a confident negative and nobody re-checks one.
    # See the yearless CVE story above for what that costs.
    if search_term:
        like = f"%{search_term}%"
        m = _CVE_NO_YEAR_RE.match(str(search_term))
        # The number on its own, so CVE-59822 reaches CVE-2026-59822.
        # Anchored on the trailing digits rather than loose, so 59822
        # cannot also drag in CVE-2019-598220 style neighbours.
        alt = f"%-{m.group(1)}" if m else like
        where = ("WHERE cve_id LIKE ? OR cve_id LIKE ? OR vulnerability LIKE ? "
                 "OR description LIKE ? OR known_ports LIKE ? OR product LIKE ?")
        filter_params = [like, alt, like, like, like, like]
        # 2026-09-16, PORTED 2026-09-21. This was ORDER BY severity, which
        # sorts the WORD. That put low ahead of medium, alphabetically, and it
        # only ever looked right because every imported KEV row said 'high' so
        # there was nothing to sort. KEV rows now say 'unknown' unless the
        # feed gave a real signal, so the ordering has to mean something.
        #
        # Unrated sorts last, on purpose. It is not a claim that those rows
        # matter less, it is that they carry no rating and a rated row is the
        # better thing to show first when the limit cuts the list.
        #
        # 2026-09-17. The rank now reads the FETCHED rating first and falls
        # back to the feed's. A KEV row scored 9.8 by NVD still says 'unknown'
        # in `severity`, because that column means what the feed states and
        # the feed states nothing, so sorting on `severity` alone put every
        # scored row at the bottom with the unrated ones. COALESCE, not a
        # rewrite of severity: two sources, two columns, and the sort is
        # allowed to prefer the one that actually looked.
        order = ("ORDER BY CASE LOWER(COALESCE(NULLIF(cvss_severity, ''), "
                 "severity, '')) "
                 "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                 "WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END, "
                 "date_added DESC")
    else:
        where = ""
        filter_params = []
        order = ("ORDER BY CASE LOWER(COALESCE(NULLIF(cvss_severity, ''), "
                 "severity, '')) "
                 "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                 "WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END, "
                 "date_added DESC")

    # Severity filter: the fetched CVSS rating first, else the feed's word.
    # 'unrated' is every row with neither.
    sev = (severity or "").strip().lower()
    if sev in RUNBOOK_SEVERITIES:
        rated = "LOWER(COALESCE(NULLIF(cvss_severity, ''), severity, ''))"
        clause = (f"{rated} IN ('', 'unknown', 'info')" if sev == "unrated"
                  else f"{rated} = ?")
        where = (f"WHERE ({where[6:]}) AND {clause}" if where
                 else f"WHERE {clause}")
        if sev != "unrated":
            filter_params = filter_params + [sev]

    with _get_conn() as conn:
        rows = conn.execute(f"SELECT * FROM runbook {where} {order} LIMIT ?",
                            filter_params + [limit]).fetchall()
        out = _rows_to_dicts(rows)
        if not with_total:
            return out
        return _with_total(conn, out, "runbook", where, filter_params,
                           limit, "entries")


# READ, DISMISSED FINDINGS (model read-only)

def query_dismissed(entity_type: str = None, entity_value: str = None,
                    with_total: bool = False):
    """Get dismissed entities, model checks this before alerting."""
    with _get_conn() as conn:
        if entity_type and entity_value:
            rows = conn.execute(
                "SELECT * FROM dismissed_findings WHERE entity_type=? AND entity_value=?",
                (entity_type, entity_value)
            ).fetchall()
        elif entity_type:
            rows = conn.execute(
                "SELECT * FROM dismissed_findings WHERE entity_type=?", (entity_type,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM dismissed_findings").fetchall()
        out = _rows_to_dicts(rows)
        # TODO 94.19. No LIMIT above. A dismissal list that looks short when
        # it is not would understate what has been silenced.
        return _all_rows(out, "dismissed") if with_total else out


def is_dismissed(entity_type: str, entity_value: str) -> bool:
    """Quick check, is this entity dismissed? Model calls this before alerting."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT id FROM dismissed_findings WHERE entity_type=? AND entity_value=?",
            (entity_type, entity_value)
        ).fetchone()
        return row is not None


def dismissal_covers(entity_type: str, entity_value: str,
                     evidence: str = None) -> dict:
    """
    PM-7, 2026-09-23. Does the dismissal of this entity still cover THIS
    finding? A second question, because the first one was not enough.

    THE DEFECT, MEASURED. The adapter keys dismissal on the process NAME for
    every rule about it, so the four dismissals already in the live database
    (systemd, systemd-journald, systemd-logind, bash) were made to quiet 84
    false LNX-1102 HIGH findings and 37 false LNX-1103 rows. The masquerading
    rule carries that SAME name, so:

        cp /bin/sleep /tmp/systemd ; run it
        _analyze_process -> [location low, masquerading_system_binary HIGH]
        is_dismissed('process','systemd') -> True
        -> the one rule that could see a fake systemd is silenced

    A name is not evidence. This asks the rows the dismissal actually closed
    what they were about — the executable paths are in their raw_data — and a
    finding at a DIFFERENT executable is not covered by it.

    THE ANSWER IS A DICT, not a bool, because "not dismissed", "dismissed for
    this same file" and "dismissed, and the comparison could not be made" are
    three different sentences and collapsing them is the fault this whole file
    keeps digging out of itself.

        covered     True/False — may this finding be skipped?
        compared    True when there was evidence on both sides to compare
        reason      the sentence to put in the log or on the row
    """
    if not is_dismissed(entity_type, entity_value):
        return {"covered": False, "compared": False,
                "reason": "no dismissal is recorded for this entity"}

    closed = []
    try:
        with _get_readonly_conn() as conn:
            rows = conn.execute(
                "SELECT raw_data FROM findings "
                " WHERE entity_type=? AND entity_value=? AND dismissed=1 "
                "   AND dismissed_reason LIKE ?",
                (entity_type, entity_value, ENTITY_DISMISSAL_MARK + "%")
            ).fetchall()
        for row in rows:
            raw = row["raw_data"] if isinstance(row, sqlite3.Row) else row[0]
            try:
                blob = json.loads(raw or "{}")
            except (TypeError, ValueError):
                continue
            exe = (blob or {}).get("exe")
            if exe:
                closed.append(exe)
    except Exception as e:                              # noqa: BLE001
        logger.debug(f"could not read what dismissal {entity_type}:"
                     f"{entity_value} closed: {e}")
        return {"covered": True, "compared": False,
                "reason": (f"the name is dismissed and the evidence behind "
                           f"that dismissal could not be read ({e}), so it is "
                           f"still honoured. This is not a claim that the "
                           f"finding above is the same thing.")}

    closed_set = {c.lower() for c in closed}

    if evidence is None:
        return {"covered": True, "compared": False,
                "reason": ("the name is dismissed. This finding carries no "
                           "executable path, so there is nothing to compare "
                           "against what was dismissed, a finding that NAMES "
                           "a file is the one this check can tell apart.")}

    if not closed_set:
        return {"covered": True, "compared": False,
                "reason": ("the name is dismissed, and the rows that dismissal "
                           "closed recorded no executable path, so there is "
                           "nothing to compare this one against.")}

    if evidence.lower() in closed_set:
        return {"covered": True, "compared": True,
                "reason": (f"the name is dismissed, and this is the same file "
                           f"that dismissal was made about ({evidence}).")}

    return {"covered": False, "compared": True,
            "reason": (f"THE NAME IS DISMISSED BUT THIS IS A DIFFERENT FILE. "
                       f"The dismissal of {entity_value!r} was made about "
                       f"{sorted(closed_set)}, and this finding is about "
                       f"{evidence!r}. A name is not evidence: quieting what a "
                       f"file in the system's own directory was doing does not "
                       f"quiet something wearing that name from somewhere "
                       f"else, which is the masquerade the rule exists for.")}


# READ, PCAP RESULTS (model read-only for raw results,
#          model writes model_assessment field)

def query_pcap_results(session_id: str = None, limit: int = 10,
                       with_total: bool = False):
    """
    Get PCAP analysis results, each carrying the scope of the capture it came
    from.

    The join is the point. Without it the model reads a list of findings from
    a file and has nothing telling it that the file's reach is unknown, so it
    reasons about an imported capture exactly as it would about this host's
    own traffic. The scope has to arrive WITH the rows, not be available
    somewhere else on request, because a lookup nobody makes is a lookup that
    does not happen.

    A result with no sensor still comes back. Those are the rows written
    before sensor_id was filled in, and they are labelled as unknown rather
    than quietly given the local sensor's scope.
    """
    limit = _validate_limit(limit)
    sql = """
        SELECT p.*, s.position, s.summary, s.can_see, s.cannot_see,
               s.notes AS sensor_notes
        FROM pcap_results p
        LEFT JOIN sensors s ON s.sensor_id = p.sensor_id
        {where}
        ORDER BY p.analyzed_at DESC LIMIT ?
    """
    # TODO 94.10. One where, used by both the rows and the count. The count
    # runs against pcap_results alone: the join only decorates each row with
    # its sensor and is a LEFT JOIN, so it cannot change how many rows match.
    where = "WHERE p.session_id=?" if session_id else ""
    filter_params = [session_id] if session_id else []

    with _get_conn() as conn:
        rows = conn.execute(sql.format(where=where),
                            filter_params + [limit]).fetchall()
        out = _rows_to_dicts(rows)
        counted = None
        if with_total:
            counted = _with_total(conn, out, "pcap_results p", where,
                                  filter_params, limit, "results")
    for row in out:
        if not row.get("sensor_id"):
            row["position"] = "unrecorded"
            row["cannot_see"] = (
                "Unknown. This capture was imported before its vantage point "
                "was recorded, so nothing absent from it supports any "
                "conclusion.")
    # The sensor labelling above edits the rows in place, and `counted` holds
    # the same list object, so this returns the labelled rows either way.
    return counted if counted is not None else out


# READ, BEHAVIORAL TABLES (model reads its own tables)

def query_behavioral_baseline(
    entity_type: str = None,
    entity_value: str = None,
    behavior_key: str = None,
    flagged_as_normal: bool = None,
    confidence: str = None,
    with_total: bool = False,
):
    """
    Read behavioral baselines. Model calls this before deciding whether to alert.
    If flagged_as_normal=True returned, do not alert, log quietly only.

    RETRACTED ROWS ARE STILL RETURNED, and that is a decision rather than an
    oversight. retract_baseline empties the numbers, drops confidence to low
    and clears suppression, so the row can no longer silence anything or claim
    anything. What is left is retracted_at and retracted_reason, which are
    worth reading: "this was withdrawn, and here is why" is information, and
    hiding it would mean a reader could not tell a retraction from a device
    nobody has ever measured. Those two states are very different.
    """
    conditions = []
    params = []

    if entity_type:
        if entity_type not in VALID_ENTITY_TYPES:
            raise BadInput(f"Invalid entity_type '{entity_type}'")
        conditions.append("entity_type = ?")
        params.append(entity_type)
    if entity_value:
        conditions.append("entity_value = ?")
        params.append(entity_value)
    if behavior_key:
        conditions.append("behavior_key = ?")
        params.append(behavior_key)
    if flagged_as_normal is not None:
        # Plain coercion, deliberately NOT _suppression_flag. This is a read
        # filter, so there is nothing to gate and nothing to deny by default;
        # borrowing the security helper here would only make a WHERE clause
        # behave surprisingly.
        conditions.append("flagged_as_normal = ?")
        params.append(1 if flagged_as_normal else 0)
    if confidence:
        if confidence not in VALID_CONFIDENCE:
            raise BadInput(f"Invalid confidence '{confidence}'")
        conditions.append("confidence = ?")
        params.append(confidence)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"SELECT * FROM behavioral_baseline {where} ORDER BY entity_type, entity_value"

    with _get_conn() as conn:
        rows = _rows_to_dicts(conn.execute(sql, params).fetchall())

    # The claim must not be readable without what does or does not back it.
    # A note filed under a destination key is read as an outbound
    # relationship; when nothing retained supports that, the reader learns it
    # here instead of inheriting it as a fact.
    out = []
    for r in rows:
        r = _annotate_hours(r)
        check = corroborate_direction(r.get("entity_type"),
                                      r.get("entity_value"),
                                      r.get("behavior_key"))
        if check:
            r["direction_check"] = check
        # TODO 21. Travels with the row for the same reason direction_check
        # does: a claim must not be readable without what it rests on.
        r["provenance"] = observation_provenance(
            r.get("entity_type"), r.get("entity_value"), r.get("behavior_key"))
        # The measured session count, beside the stored one. They should agree
        # now that writes are clamped; a disagreement on an old row means the
        # stored number predates TODO 22 and was asserted rather than counted.
        r["distinct_sessions_measured"] = count_baseline_sessions(
            r.get("entity_type"), r.get("entity_value"), r.get("behavior_key"))
        out.append(r)
    # TODO 94.20. No LIMIT on the select above, so every matching baseline is
    # here. Worth stating rather than leaving implied: this list is what the
    # app has decided is normal, and a reader who cannot tell a short list
    # from a truncated one cannot tell how much is being treated as normal.
    return _all_rows(out, "baselines") if with_total else out


def _local_utc_offset_hours() -> int:
    """Whole hours this machine is offset from UTC right now."""
    offset = datetime.now().astimezone().utcoffset()
    return int(offset.total_seconds() // 3600) if offset else 0


def _annotate_hours(row: dict) -> dict:
    """
    Add the local-time reading of typical_hours.

    typical_hours is derived from observed_at, which is UTC, so the stored
    numbers are UTC hours. Nothing said so, and the agent reported them to
    the user as if they were wall-clock hours on this network. A device whose
    baseline read "active at hours 4 and 21" was described as waking at 4 in
    the morning. Seven hours west of UTC that is 9 in the evening, which is
    an entirely ordinary time for somebody to be watching television.

    Hour of day is one of the few signals where the human reading IS the
    point. "Why is this thing awake at 4am" is a real question and "it is
    not, it is 9pm" is a real answer, and the tool was manufacturing the
    question.

    The stored value is left in UTC on purpose. It is portable, it needs no
    migration, and every existing row was written the same way, so nothing
    silently mixes. The translation happens here, where the offset is known.
    """
    hours = row.get("typical_hours")
    if not hours:
        return row

    try:
        parsed = json.loads(hours) if isinstance(hours, str) else hours
        if not isinstance(parsed, list):
            return row
        offset = _local_utc_offset_hours()
        row["typical_hours_utc"] = parsed
        row["typical_hours_local"] = sorted({(int(h) + offset) % 24 for h in parsed})
        row["typical_hours_note"] = (
            f"typical_hours is stored in UTC. typical_hours_local is the same "
            f"set on this machine's clock, currently UTC{offset:+d}. Quote the "
            f"LOCAL hours to the user; a person asking why something is awake "
            f"at 4am means their own 4am."
        )
    except (ValueError, TypeError):
        pass

    return row


def all_session_observations(session_id: str,
                             include_superseded: bool = False) -> list[dict]:
    """
    EVERY observation for one session. No cap, and not for the model.

    WHY THIS EXISTS, 2026-09-13, and it is the most important comment in this
    file. The hourly rollup merges session observations into
    behavioral_baseline. That baseline is what this app calls normal, and what
    suppression is decided from.

    It was reading them through query_behavioral_session with limit=500, and
    _validate_limit clamps every limit to MAX_QUERY_LIMIT, which is 500. So on
    any session that produced more than 500 observations the rollup built the
    baseline from the newest 500 and the rest were never merged. Not delayed,
    not queued. Dropped, silently, on the busiest sessions, which are the ones
    where the baseline matters most.

    Nothing said so. The rollup logged how many it processed and that number
    looked like the whole thing.

    THE MODEL FACING PATH STAYS CAPPED, on purpose, because that one has a
    context window on the other end of it. This path does not: it is Python
    reading its own table to compute an aggregate, and there is no reason on
    earth for that to be limited. Those two facts are different and were being
    served by one function.

    Pages by rowid so a large session does not build one enormous list in a
    single statement. Ordered oldest first, because the baseline reads forward
    in time and the old path handed it the newest 500 in reverse.
    """
    where = ["session_id = ?"]
    params: list = [session_id]
    if not include_superseded:
        try:
            with _get_conn() as conn:
                conn.execute("SELECT superseded_by FROM behavioral_session LIMIT 1")
            where.append("superseded_by IS NULL")
        except sqlite3.OperationalError:
            pass   # pre-migration database, nothing to exclude

    out: list[dict] = []
    last_id = 0
    PAGE = 1000
    with _get_conn() as conn:
        while True:
            rows = conn.execute(
                f"SELECT * FROM behavioral_session "
                f"WHERE {' AND '.join(where)} AND id > ? "
                f"ORDER BY id ASC LIMIT ?",
                (*params, last_id, PAGE)).fetchall()
            if not rows:
                break
            out.extend(_rows_to_dicts(rows))
            last_id = rows[-1]["id"]
            if len(rows) < PAGE:
                break
    return out


def query_behavioral_session(
    session_id: str = "current",
    entity_type: str = None,
    entity_value: str = None,
    behavior_key: str = None,
    limit: int = 200,
    include_superseded: bool = False,
    with_total: bool = False,
) -> dict:
    """
    Read session behavioral observations.

    Superseded observations are excluded by default but their COUNT is always
    reported. That combination is the whole design. Hiding a withdrawn claim
    is what makes the correction real; hiding the fact that anything was
    withdrawn would make this a quiet way to erase the record, which is the
    attack this system worries about most.
    """
    limit = _validate_limit(limit)
    conditions = []
    params = []

    # SESSION FILTERING. This parameter existed, was documented, was passed by
    # every caller, and was never applied to the query. Every call returned the
    # 500 most recent observations from EVERY session that had ever run.
    #
    # The damage was in rollup_engine, which pulls this and then credits each
    # group to the CURRENT session via record_baseline_session. An entity
    # observed once weeks ago therefore earned a fresh session credit on every
    # rollup, climbing to 'high' confidence with no new evidence behind it,
    # and high confidence is what drives suppression. Baselines were being
    # promoted, and entities silenced, by the passage of time rather than by
    # observation.
    #
    # 'current' is the historical default and has always meant no filter here,
    # so it keeps meaning that; scripts/withdraw_observation.py relies on it to
    # list everything. 'all' is accepted as the honest spelling of the same
    # thing. Any other value now filters, which is what every caller that
    # passes a real session id already believed was happening.
    if session_id and session_id not in ("current", "all"):
        conditions.append("session_id = ?")
        params.append(session_id)

    if entity_type:
        conditions.append("entity_type = ?")
        params.append(entity_type)
    if entity_value:
        conditions.append("entity_value = ?")
        params.append(entity_value)
    if behavior_key:
        conditions.append("behavior_key = ?")
        params.append(behavior_key)

    base_where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    with _get_conn() as conn:
        hidden = 0
        if not include_superseded:
            count_sql = (f"SELECT COUNT(*) AS n FROM behavioral_session {base_where}"
                         + (" AND " if conditions else " WHERE ")
                         + "superseded_by IS NOT NULL")
            try:
                hidden = conn.execute(count_sql, params).fetchone()["n"]
            except sqlite3.OperationalError:
                hidden = 0   # pre-migration database

        where = base_where
        if not include_superseded:
            try:
                conn.execute("SELECT superseded_by FROM behavioral_session LIMIT 1")
                where = (base_where + (" AND " if conditions else " WHERE ")
                         + "superseded_by IS NULL")
            except sqlite3.OperationalError:
                pass

        sql = f"SELECT * FROM behavioral_session {where} ORDER BY observed_at DESC LIMIT ?"
        rows = _rows_to_dicts(conn.execute(sql, params + [limit]).fetchall())
        # TODO 94.13. Counted against `where`, which is the one the rows used,
        # superseded filter included. Counting against base_where instead
        # would quietly include the withdrawn observations that the rows
        # deliberately leave out, and superseded_hidden already reports those
        # separately.
        counted = (_completeness(conn, "behavioral_session", where, params,
                                 len(rows)) if with_total else None)

    result = {"observations": rows, "count": len(rows), "superseded_hidden": hidden}
    if hidden:
        result["note"] = (
            f"{hidden} observation(s) matching this query were withdrawn as "
            f"wrong and are not shown. They are still on disk. Pass "
            f"include_superseded=true to read them, which is worth doing when "
            f"you want to know what was previously believed and why it changed."
        )
    return _merge_completeness(result, counted) if counted else result


def supersede_observation(observation_id: int, reason: str,
                          superseded_by: int = None) -> dict:
    """
    Withdraw an observation that turned out to be wrong.

    Nothing is deleted. The row keeps its text, its timestamp and its author,
    and gains a reason it was withdrawn plus an optional pointer at the
    observation that replaced it. It stops being returned as current.

    A reason is required. "Superseded" with no explanation is indistinguishable
    from a quiet retraction, and the point of keeping the row at all is that a
    later reader can see what was believed, and why that changed.
    """
    basis = (reason or "").strip()
    if not basis:
        return {"success": False,
                "error": "reason is required. State what was wrong and how it is known."}

    with _get_conn() as conn:
        try:
            row = conn.execute(
                "SELECT id, behavior_value, superseded_by FROM behavioral_session WHERE id = ?",
                (observation_id,)
            ).fetchone()
        except sqlite3.OperationalError as e:
            # The column arrives with schema v6, which is applied at boot. A
            # caller reaching this module directly can be ahead of the last
            # migration, and a raw SQL error is a poor way to say so.
            if "superseded_by" in str(e):
                return {
                    "success": False,
                    "error": ("This database has not been migrated to schema v6 yet, "
                              "so observations cannot be withdrawn. Start AgentalSec "
                              "once (python main.py) to apply it, or run "
                              "core.migrations.run_migrations directly."),
                }
            raise

        if row is None:
            return {"success": False, "error": f"No observation with id {observation_id}."}
        if row["superseded_by"] is not None:
            return {"success": False,
                    "error": f"Observation {observation_id} was already withdrawn."}

        conn.execute(
            "UPDATE behavioral_session SET superseded_by = ?, superseded_reason = ? "
            "WHERE id = ?",
            (superseded_by if superseded_by is not None else -1, basis, observation_id)
        )

    # Journalled from 2026-09-03. A withdrawal changes what the tool will tell
    # you next time, and that is the rule core/integrity.py picks its
    # operations on, so I think this one was just missed. Same shape as
    # port_expectation_withdrawn: a person changing the answer by hand.
    #
    # After the UPDATE and outside the connection block on purpose. _journal
    # never raises, but the write is the thing that matters and it should not
    # be sharing a transaction with the record of it.
    _journal("observation_withdrawn", "behavioral_session", observation_id,
             {"reason": basis[:200],
              "replaced_by": superseded_by,
              "via": "supersede_observation"})

    logger.info(f"Observation {observation_id} withdrawn: {basis[:80]}")
    return {
        "success": True,
        "observation_id": observation_id,
        "withdrawn_text": row["behavior_value"],
        "reason": basis,
        "note": ("The observation is retained on disk and readable with "
                 "include_superseded. It no longer counts as current."),
    }


def query_behavioral_deviation(
    since: str = None,
    entity_value: str = None,
    resolved_as: str = None,
    unresolved_only: bool = False,
    session_id: str = None,
    limit: int = 50,
    with_total: bool = False,
):
    """
    Query deviation log. Pass unresolved_only=True to find open deviations.

    with_total=True adds the exact matching count and whether this is all of
    them. TODO 94.7.
    """
    limit = _validate_limit(limit)
    conditions = []
    params = []

    if since:
        conditions.append("detected_at >= ?")
        params.append(_sql_datetime(since))
    if entity_value:
        conditions.append("entity_value = ?")
        params.append(entity_value)
    if resolved_as:
        conditions.append("resolved_as = ?")
        params.append(resolved_as)
    if unresolved_only:
        conditions.append("resolved_as IS NULL")
    if session_id:
        conditions.append("session_id = ?")
        params.append(session_id)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"SELECT * FROM behavioral_deviation {where} ORDER BY detected_at DESC LIMIT ?"
    filter_params = list(params)
    params.append(limit)

    with _get_conn() as conn:
        rows = _rows_to_dicts(conn.execute(sql, params).fetchall())
        if not with_total:
            return rows
        return _with_total(conn, rows, "behavioral_deviation", where,
                           filter_params, limit, "deviations")


# WRITE, BEHAVIORAL TABLES (model-owned, guarded)

def _enrichment_is_stale(basis_ref: str) -> bool | None:
    """
    Has the lookup behind this observation expired? None when unknowable.

    The owner's call, 2026-09-02, and I think it is the right one: STALE the
    fact rather than just date-stamp it. An unflagged stale fact costs nothing
    right up until it is wrong, and then it is silently wrong. A flagged one
    costs a single query_enrichment call, which is free when the row is still
    fresh because the cache answers it.

    The trade the owner named out loud: it will occasionally push a session into
    re-looking-up something that had not really changed. That is a few hundred
    tokens. The other way round is a baseline quietly asserting an allocation
    that was reassigned months ago.
    """
    if not basis_ref or not basis_ref.startswith("enrichment:"):
        return None
    indicator = basis_ref.split(":", 1)[1].strip()
    if not indicator:
        return None
    try:
        from core import enrichment
        row = enrichment.read(indicator)
    except Exception:
        return None
    if not row:
        # The observation cites a lookup that is no longer in the cache. That
        # is not "fine", it is the least verifiable state of all: the claim is
        # here and the thing it rested on is gone.
        return True
    return bool(row.get("stale"))


def _basis_breakdown(rows) -> dict:
    """
    How many of these observations are measurements, lookups, or reasoning.

    NEVER SUMMED. Same discipline as the untrusted/clean/unknown split above
    and for the same reason: three populations that mean different things
    become meaningless the moment they are added together.
    """
    counts = {"measured": 0, "external_intel": 0, "model_conclusion": 0,
              "operator_stated": 0, "unrecorded": 0}
    stale_refs, live_refs = set(), set()

    for r in rows:
        try:
            value = r["basis"]
            ref = r["basis_ref"]
        except (IndexError, KeyError):
            value, ref = None, None
        if value in counts:
            counts[value] += 1
        else:
            counts["unrecorded"] += 1
        if value == "external_intel" and ref:
            stale = _enrichment_is_stale(ref)
            (stale_refs if stale else live_refs).add(ref)

    total = sum(counts.values())
    if not total:
        note = "No observations recorded."
    elif counts["model_conclusion"] and counts["model_conclusion"] >= max(1, total // 2):
        note = (f"{counts['model_conclusion']} of {total} of these are the "
                f"MODEL'S OWN CONCLUSIONS rather than measurements or lookups. "
                f"Nothing outside this tool backs them. Treat them as a prior "
                f"worth re-examining, not as established facts about this "
                f"network.")
    elif stale_refs:
        note = (f"{len(stale_refs)} external fact(s) here rest on lookups that "
                f"have EXPIRED ({', '.join(sorted(stale_refs))}). Re-run "
                f"enqueue_enrichment on those indicators before relying on "
                f"them. Registration and reputation both change.")
    elif counts["unrecorded"] and not (counts["measured"] or counts["external_intel"]):
        note = (f"All {total} predate v26, so nothing is recorded about what "
                f"backed them. Unrecorded is not the same as measured.")
    else:
        parts = [f"{v} {k}" for k, v in counts.items() if v]
        note = "Mix: " + ", ".join(parts) + "."

    return {
        "counts": counts,
        "stale_external_refs": sorted(stale_refs),
        "current_external_refs": sorted(live_refs),
        "note": note,
        "how_to_read_this": (
            "measured means this tool watched it happen here. external_intel "
            "means somebody else's database said so, and it expires. "
            "model_conclusion means a model reasoned to it and nothing else "
            "backs it. operator_stated means the owner answered a question "
            "this tool could not answer itself, which is the strongest thing "
            "there is for 'is this yours' and is still not a measurement. "
            "unrecorded means the row predates v26 and the question "
            "was never asked, which is NOT the same as measured."),
    }


def observation_provenance(entity_type: str, entity_value: str,
                           behavior_key: str = None) -> dict:
    """
    What is this baseline actually resting on?

    TODO 21. Answers the question a human is implicitly asked whenever they
    approve a suppression: "normal for eight weeks, forty observations" sounds
    like forty independent confirmations. It is not, if thirty-eight of them
    were written in turns where the model had just read attacker-controllable
    sensor text.

    Computed live from behavioral_session rather than stored on the baseline,
    for the same reason corroborate_direction is: no staleness, no migration,
    and the answer moves honestly as rows age out.

    THREE POPULATIONS, REPORTED APART, never summed into one number:
      untrusted_derived  written in a turn that had read fenced sensor text
      clean              written with no fenced text in that turn
      unknown            written before v17, so the question was not asked.
                         NOT the same as clean, and never counted as clean.
    """
    clauses = ["entity_type = ?", "entity_value = ?"]
    params = [entity_type, entity_value]
    if behavior_key:
        clauses.append("behavior_key = ?")
        params.append(behavior_key)
    where = " AND ".join(clauses)

    with _get_readonly_conn() as conn:
        rows = conn.execute(
            f"""SELECT evidence_untrusted, evidence_sources, written_by,
                       observed_at, basis, basis_ref
                  FROM behavioral_session WHERE {where}""", params).fetchall()

    untrusted = clean = unknown = 0
    sources: set[str] = set()
    for r in rows:
        flag = r["evidence_untrusted"]
        if flag is None:
            unknown += 1
        elif flag:
            untrusted += 1
            try:
                sources.update(json.loads(r["evidence_sources"] or "[]"))
            except (ValueError, TypeError):
                pass
        else:
            clean += 1

    total = len(rows)
    if not total:
        note = ("No recorded observations for this entity. An empty record is "
                "not a clean one.")
    elif untrusted and untrusted >= max(1, total // 2):
        note = (f"{untrusted} of {total} observations were written in turns "
                f"where the model had just read attacker-controllable sensor "
                f"text ({', '.join(sorted(sources))}). That does not make them "
                f"wrong. It means this baseline is not {total} independent "
                f"confirmations, and it is the shape a slow poisoning attack "
                f"produces.")
    elif untrusted:
        note = (f"{untrusted} of {total} observations were written after "
                f"reading fenced sensor text; the rest were not.")
    elif unknown:
        note = (f"{unknown} of {total} observations predate provenance "
                f"recording, so nothing is known about what backed them. "
                f"Unknown is not clean.")
    else:
        note = f"All {total} observations were written without fenced text in context."

    return {
        "total": total,
        "basis": _basis_breakdown(rows),
        "untrusted_derived": untrusted,
        "clean": clean,
        "unknown": unknown,
        "untrusted_sources": sorted(sources),
        "note": note,
    }


def corroborate_direction(entity_type: str, entity_value: str,
                          behavior_key: str) -> dict | None:
    """
    Does the packet record support the ROLE this behaviour key asserts?

    Returns None when the question does not apply, a key that asserts no
    direction, or an entity that is not an address. Otherwise a dict whose
    status is one of THREE values, never two:

      corroborated          seen in the asserted role in the retained window.
      contradicted          seen in the retained window, but only in the
                            opposite role. NOT "never", "not in what we
                            kept". The counts and the window come back with
                            it so the difference stays visible.
      no_evidence_retained  the window holds nothing about this address
                            either way. Says so, so silence is not read as
                            innocence.

    WHY THIS REPORTS INSTEAD OF REFUSING
    A refusal would cost a true fact to prevent a false one. The sniffer is
    not always running, a host may have talked before it existed, and this
    tool is built for homelabs where the app goes off for weeks. Blocking
    the write would make the memory quieter and less true.

    WHY IT RUNS AT READ TIME AND STORES NOTHING
    idx_packets_src and idx_packets_dst both exist, so each count is an
    index seek rather than a scan. Computing live means the answer cannot go
    stale, and no column or migration is needed. It also means the answer
    moves as retention prunes, which is honest, because the window is
    reported alongside it.

    WHY THE WINDOW IS REPORTED
    An earlier sketch tried to answer "was this ever a destination", which
    pruning makes unanswerable, and which would have been forced into a
    wrong verdict once raw packets aged out. A count paired with the window
    it covers stays true whatever was pruned. The verdict was the problem,
    not the pruning.
    """
    role = DIRECTIONAL_KEYS.get(behavior_key)
    if role is None or entity_type != "ip":
        return None

    with _get_readonly_conn() as conn:
        as_dst = conn.execute(
            "SELECT COUNT(*) FROM packets WHERE dst_ip = ?", (entity_value,)
        ).fetchone()[0]
        as_src = conn.execute(
            "SELECT COUNT(*) FROM packets WHERE src_ip = ?", (entity_value,)
        ).fetchone()[0]
        oldest = conn.execute(
            "SELECT MIN(captured_at) FROM packets"
        ).fetchone()[0]

    wanted, opposite = ((as_dst, as_src) if role == "destination"
                        else (as_src, as_dst))
    other = "source" if role == "destination" else "destination"

    if wanted:
        status = "corroborated"
        note = f"seen as a {role} on {wanted} retained packet(s)"
    elif opposite:
        status = "contradicted"
        note = (f"in the retained window this address appears {opposite} "
                f"time(s) as a {other} and 0 times as a {role}. That is not "
                f"proof it was never a {role}, only that nothing kept says "
                f"it was.")
    else:
        status = "no_evidence_retained"
        note = ("the retained packets say nothing about this address in "
                "either role. Absence here is a gap in the record, not "
                "evidence that the observation is wrong OR right.")

    return {
        "status":         status,
        "asserted_role":  role,
        "behavior_key":   behavior_key,
        "as_destination": as_dst,
        "as_source":      as_src,
        "retained_since": oldest,
        "note":           note,
    }


def write_behavioral_observation(
    entity_type: str,
    entity_value: str,
    behavior_key: str,
    behavior_value: str,
    session_id: str,
    context: str = None,
    basis: str = None,
    basis_ref: str = None,
) -> dict:
    """
    Write a behavioral observation to behavioral_session.
    Model calls this constantly to build its conscience about this network.

    BASIS. v26, 2026-09-02, and it is the column that says WHAT KIND OF THING
    this row is. Three very different things used to land here looking
    identical:

        measured          a packet, a sensor, a port scan. Something this tool
                          watched happen on this network.
        external_intel    a registry said so. Second-hand, dated, and it goes
                          stale. Carries basis_ref, normally
                          "enrichment:<indicator>".
        model_conclusion  nobody measured it and no registry said it. The
                          model reasoned to it.
        operator_stated   the owner answered a question this tool could not
                          answer itself. v32. Best authority there is for
                          "is this yours", and still not a measurement.

    WHY THIS EXISTS, and it is two real rows from one afternoon.

    The owner's point, and the owner is right: enrichment facts SHOULD be recorded
    here. A model that re-looks-up the same address every session is the waste
    the whole enrichment engine was built to stop. Not logging is worse than
    logging.

    But an enrichment fact written as a bare baseline line loses everything
    that made it checkable. The enrichment row has a TTL, source URLs and a
    status BECAUSE registry data goes stale and reputation changes weekly. The
    baseline has none of that and nothing re-checks it. Six months on, "that
    address is an Opera VPN exit" is a permanent measured fact with no source
    and no date, and if the block is reallocated nothing catches it.

    The third value came from the same afternoon and is the one I would defend
    hardest. The model investigated a router advertisement, concluded "the
    address parser has a byte-order bug", and wrote it here. It is wrong: src
    comes straight out of scapy. Unmarked, the next session reads it as
    something this tool measured, believes the recorder is broken, and TODO 9
    quietly closes on a wrong answer. Type 1 has packets behind it, type 2 has
    a URL behind it, type 3 has nothing behind it at all, which is why it is
    the one that most needs saying out loud.

    DEFAULTS TO model_conclusion when the caller does not say. That is the
    safe direction to be wrong in: over-marking makes a row look weaker than
    it is, under-marking makes a guess look like a measurement, and this
    project has already been bitten by the second one twice (TODO 37, 38).
    """
    _validate_entity(entity_type, entity_value, behavior_key)
    _validate_behavior_value(behavior_key, behavior_value)

    basis = (basis or "").strip().lower() or "model_conclusion"
    if basis not in VALID_OBSERVATION_BASIS:
        return {"success": False,
                "error": (f"basis must be one of {_listed(VALID_OBSERVATION_BASIS)}. "
                          f"Got {basis!r}."
                          f"{_near(basis, VALID_OBSERVATION_BASIS)}")}
    if basis == "external_intel" and not basis_ref:
        return {"success": False,
                "error": ("external_intel needs a basis_ref saying WHERE it came "
                          "from, normally 'enrichment:<indicator>'. An external "
                          "fact with no source is the thing this column exists "
                          "to prevent.")}

    # TODO 21. What was the model reading when it wrote this? An observation
    # derived from fenced sensor text is a different kind of evidence from one
    # derived from a Python measurement, and after it rolls into a baseline
    # nothing else can tell them apart. Recorded here, at the only moment the
    # answer is still knowable.
    sources = []
    try:
        from core import agent_loop
        sources = agent_loop.untrusted_sources_this_turn()
    except Exception as e:          # never block a write on provenance
        logger.debug(f"provenance unavailable: {e}")

    with _get_conn() as conn:
        cursor = conn.execute("""
            INSERT INTO behavioral_session
                (session_id, entity_type, entity_value, behavior_key,
                 behavior_value, context, written_by,
                 evidence_untrusted, evidence_sources, basis, basis_ref)
            VALUES (?, ?, ?, ?, ?, ?, 'model', ?, ?, ?, ?)
        """, (session_id, entity_type, entity_value, behavior_key,
              str(behavior_value), context,
              1 if sources else 0,
              json.dumps(sources) if sources else None,
              basis, basis_ref))
        result = {"success": True, "id": cursor.lastrowid}

    # Reported in the response, never raised. The model that just filed this
    # sees whether the packet record backs the role its key asserts, while it
    # still has the context to correct itself.
    check = corroborate_direction(entity_type, entity_value, behavior_key)
    if check:
        result["direction_check"] = check

    # Same idea, one field over. Told to the model AT THE MOMENT IT FILES,
    # while it still has the context to correct itself, rather than left for
    # a later session to discover.
    result["basis"] = basis
    if basis == "model_conclusion":
        result["basis_note"] = (
            "Filed as model_conclusion, which is the DEFAULT. Nothing measured "
            "this and no source was cited, so every later session reads it as "
            "your reasoning rather than as a fact about this network. If a "
            "packet or a sensor actually showed it, re-file with "
            "basis='measured'. If a lookup did, use basis='external_intel' "
            "with basis_ref='enrichment:<indicator>'.")
    elif basis == "external_intel":
        result["basis_note"] = (
            f"Filed as external_intel from {basis_ref}. It is reported STALE "
            f"once that enrichment row expires, and a later session is told to "
            f"re-check rather than trust it indefinitely.")
    elif basis == "operator_stated":
        result["basis_note"] = (
            "Filed as operator_stated. The owner said this, and for 'is it "
            "yours' or 'is this expected' that is the best authority on this "
            "network, because there is no directory here to ask. It is still "
            "NOT a measurement: the owner can misremember, and an answer about last "
            "Tuesday is not a packet. Do not later re-describe it as "
            "something this tool observed.")
    return result


# THE QUIET DOOR. TODO 8.1F, closed 2026-09-04.
#
# 8.1F said the largest known gap here is that write_behavioral_observation is
# ungated and uncapped, and that the fix is NOT a cap: it is making the
# baseline weigh untrusted evidence differently. A cap only slows an honest
# sensor down. The attack it worried about is patient poisoning: feed the
# model attacker-chosen text often enough that an entity accumulates sessions,
# reaches high confidence, and stops being alerted on.
#
# Recording that was already built. evidence_untrusted is written on every
# observation with the tools that were read, and observation_provenance
# reports the three populations apart. What ignored it was the promotion.
#
# MEASURED FIRST, on the real database, 2026-09-04, because the obvious fix
# could have been a disaster. sanitize.UNTRUSTED_TOOLS is 38 tools, nearly the
# whole read surface, so a large share of a healthy baseline carries the flag
# by construction. If that share had been most of it, a rule blocking
# untrusted evidence from high confidence would not have hardened anything, it
# would have switched suppression off and buried the operator in alerts.
#
# It was not most of it: 68.2% clean, 31.8% untrusted, and not one baseline
# row at high or medium confidence rested on untrusted evidence alone. So the
# strong rule is affordable, and this is it, in two parts of different
# strengths:
#
#   THE FLOOR      never stop alerting on something whose evidence is
#                  ENTIRELY untrusted. Not a judgement about how much
#                  evidence, just a refusal to go blind on a set of text an
#                  attacker could have chosen all of.
#   THE CAP        high confidence needs the CLEAN sessions alone to reach the
#                  medium threshold. Untrusted evidence can carry a row from
#                  medium to high; it cannot get there by itself.
#
# Sessions, not observations, because that is what confidence has meant since
# TODO 22. Counting observations is how one chatty poll loop used to
# manufacture a high-confidence baseline in an afternoon.

VALID_EVIDENCE_RULE = {"off", "floor", "full"}
EVIDENCE_RULE_PREF  = "untrusted_evidence_rule"


def evidence_rule() -> str:
    """
    Which of the two parts is switched on. Defaults to 'full'.

    A preference rather than a constant because the measurement it was chosen
    from is one network on one day. Somebody whose baseline is nearly all
    untrusted, which is a real possibility on a busier network, needs to be
    able to fall back to 'floor' without editing this file. Same reasoning as
    the confidence thresholds above, including falling back rather than
    raising: a monitor that refuses to start over a bad preference is a
    monitor that is not watching.
    """
    raw = (get_preference(EVIDENCE_RULE_PREF, "full") or "full").strip().lower()
    if raw not in VALID_EVIDENCE_RULE:
        logger.warning(
            f"{EVIDENCE_RULE_PREF} is {raw!r}, which is not one of "
            f"{sorted(VALID_EVIDENCE_RULE)}. Using 'full'.")
        return "full"
    return raw


def clean_session_count(entity_type: str, entity_value: str,
                        behavior_key: str = None) -> int:
    """
    Distinct sessions that contributed at least one CLEAN observation.

    A session counts as clean if anything written in it was written without
    fenced text having been read that turn. Deliberately generous: the claim
    being made is "this is not built entirely out of somebody else's text",
    not "no untrusted text was involved anywhere". The strict version would
    fail nearly every real session, because the model reads packets before it
    writes almost anything.
    """
    clauses = ["entity_type = ?", "entity_value = ?",
               "(evidence_untrusted = 0)"]
    params  = [entity_type, entity_value]
    if behavior_key:
        clauses.append("behavior_key = ?")
        params.append(behavior_key)
    try:
        with _get_readonly_conn() as conn:
            row = conn.execute(
                f"SELECT COUNT(DISTINCT session_id) FROM behavioral_session "
                f" WHERE {' AND '.join(clauses)}", params).fetchone()
        return int(row[0] or 0)
    except Exception as e:
        # Fail OPEN on a read error. Failing closed here would silently stop
        # every promotion and every suppression on a database hiccup, which
        # looks like the tool having an opinion rather than a fault.
        logger.warning(f"Could not count clean sessions: {e}")
        return -1


def evidence_gate(entity_type: str, entity_value: str,
                  behavior_key: str = None) -> dict:
    """
    Can this entity be promoted to high, and can it be suppressed?

    {clean_sessions, required, rule, may_reach_high, may_suppress, reason}

    clean_sessions of -1 means the count could not be read, and both answers
    are True in that case. See clean_session_count for why it fails open.
    """
    rule  = evidence_rule()
    clean = clean_session_count(entity_type, entity_value, behavior_key)
    need  = confidence_thresholds()["medium"]

    if rule == "off" or clean < 0:
        return {"clean_sessions": clean, "required": need, "rule": rule,
                "may_reach_high": True, "may_suppress": True, "reason": None}

    may_suppress = clean > 0
    may_high     = True if rule == "floor" else clean >= need

    # BOTH REASONS WHEN BOTH APPLY. An entity with no clean evidence at all
    # trips the floor AND the cap, and reporting only the first leaves the
    # model told it cannot suppress while silently wondering why its
    # confidence moved. Two sentences is cheaper than that confusion.
    parts = []
    if not may_suppress:
        parts.append(
            f"Every observation behind {entity_type}:{entity_value} was "
            f"written in a turn where the model had just read attacker-"
            f"controllable text, and none in a turn where it had not. That "
            f"does not make them wrong. It means this is not a set of "
            f"independent confirmations, and it is the exact shape a slow "
            f"poisoning attack produces, so this tool will not stop alerting "
            f"on it. Observe it in a turn that does not rest on fenced "
            f"sensor text and it becomes suppressible.")
    if not may_high:
        parts.append(
            f"{clean} clean session(s) here, and {need} are needed for high "
            f"confidence. Untrusted evidence can carry a baseline from medium "
            f"to high; it cannot get there on its own.")
    reason = " ".join(parts) or None
    return {"clean_sessions": clean, "required": need, "rule": rule,
            "may_reach_high": may_high, "may_suppress": may_suppress,
            "reason": reason}


def _suppression_flag(value) -> int:
    """
    Coerce a suppression parameter to the integer this table stores.

    S8, 2026-08-28. Delegates to tool_registry.suppression_is_requested so
    that the WRITE and the PERMISSION GATE can never disagree about what
    counts as suppression. They did disagree: the gate matched an exact
    allowlist while this used bare Python truthiness, so the string "false"
    passed the gate ungated and then wrote a 1.

    Imported lazily. tool_registry imports this module at load time, so a
    module-level import here would be circular.
    """
    from core.tool_registry import suppression_is_requested
    return 1 if suppression_is_requested(value) else 0


# CONFIDENCE THRESHOLDS
#
# 2026-08-29. These numbers decide how much evidence is required before the
# tool calls a behaviour normal. They live in user_preferences, which is a
# plain database row: anything that can write to the file can change them,
# and until now nothing validated what came back.
#
# {"low":1,"medium":1,"high":1} made a single session enough for HIGH.
# {"high":99999} meant nothing ever reached high, so nothing was ever
# suppressed and the operator drowned in alerts. Both were accepted silently.
#
# The values were also parsed in two separate places with two copies of the
# defaults, which is how the schema comments came to say 5 while the code
# used 6. One function now, one set of defaults, both callers use it.
#
# Rejected values fall back to the defaults and log a WARNING rather than
# raising: a monitor that refuses to start because a preference is wrong is
# a monitor that is not watching, which is the worse failure.

DEFAULT_THRESHOLDS = {"low": 2, "medium": 4, "high": 6}

# An upper bound, not a preference. A threshold larger than this is not a
# strict operator, it is an off switch wearing a number.
MAX_SESSION_THRESHOLD = 100


def confidence_thresholds() -> dict:
    """
    Read confidence_session_thresholds, validate it, or fall back.

    Valid means: three whole numbers, each at least 1, strictly increasing,
    none above MAX_SESSION_THRESHOLD. Anything else is refused WHOLE, a
    partly-sane dict is not repaired field by field, because guessing which
    half the operator meant is how you end up enforcing something nobody
    chose.
    """
    raw = get_preference("confidence_session_thresholds")
    if raw is None:
        return dict(DEFAULT_THRESHOLDS)

    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        logger.warning(
            f"confidence_session_thresholds is not valid JSON ({raw!r}). "
            f"Using defaults {DEFAULT_THRESHOLDS}.")
        return dict(DEFAULT_THRESHOLDS)

    if not isinstance(parsed, dict):
        logger.warning(
            f"confidence_session_thresholds is not an object ({raw!r}). "
            f"Using defaults {DEFAULT_THRESHOLDS}.")
        return dict(DEFAULT_THRESHOLDS)

    out = {}
    for tier in ("low", "medium", "high"):
        v = parsed.get(tier)
        # bool is a subclass of int in Python; True would silently become 1.
        if isinstance(v, bool) or not isinstance(v, int):
            logger.warning(
                f"confidence_session_thresholds['{tier}'] is not a whole "
                f"number ({v!r}). Using defaults {DEFAULT_THRESHOLDS}.")
            return dict(DEFAULT_THRESHOLDS)
        if v < 1 or v > MAX_SESSION_THRESHOLD:
            logger.warning(
                f"confidence_session_thresholds['{tier}'] = {v} is outside "
                f"1..{MAX_SESSION_THRESHOLD}. Using defaults "
                f"{DEFAULT_THRESHOLDS}.")
            return dict(DEFAULT_THRESHOLDS)
        out[tier] = v

    if not (out["low"] < out["medium"] < out["high"]):
        logger.warning(
            f"confidence_session_thresholds must increase "
            f"(low < medium < high), got {out}. "
            f"Using defaults {DEFAULT_THRESHOLDS}.")
        return dict(DEFAULT_THRESHOLDS)

    return out


def update_behavioral_baseline(
    entity_type: str,
    entity_value: str,
    behavior_key: str,
    session_id: str,
    sample_count: int = None,
    value_mean: float = None,
    value_stddev: float = None,
    value_min: float = None,
    value_max: float = None,
    typical_hours: list = None,
    typical_dest_ports: list = None,
    typical_dest_ips: list = None,
    confidence: str = None,
    model_notes: str = None,
    beacon_detail: str = None,
    flagged_as_normal: bool = None,
    alert_suppressed: bool = None,
    first_seen: str = None,
) -> dict:
    """
    Upsert a behavioral baseline entry. Model calls this during rollup
    or when it explicitly decides to classify something as normal.
    """
    _validate_entity(entity_type, entity_value, behavior_key)
    if confidence and confidence not in VALID_CONFIDENCE:
        raise BadInput(f"Invalid confidence '{confidence}'")

    # SAMPLE COUNT IS MEASURED, NOT CLAIMED. TODO 22, 2026-08-29.
    #
    # The schema says sample_count is distinct SESSIONS, and the comment above
    # record_baseline_session says plainly "sample_count is derived from it".
    # rollup_engine does exactly that: it calls record_baseline_session and
    # passes back the count it returns, so the legitimate path was always
    # correct.
    #
    # But this function also accepts sample_count as a parameter, and the
    # model can call it directly. Nothing reconciled the two. So the number a
    # human reads as "forty sessions of consistent behaviour", the number
    # that drives confidence, and confidence drives suppression, could be
    # asserted rather than counted. An attacker patient enough to poison a
    # baseline over weeks did not need the weeks; one call claiming forty
    # would do.
    #
    # Clamped rather than reported, unlike the other controls added tonight,
    # and the distinction is deliberate: provenance and direction are CLAIMS a
    # reader should weigh, while an inflated session count is simply false. It
    # is not a competing view of the evidence, it is a wrong number about how
    # much evidence exists. Making the code match its own documented intent is
    # a bug fix, not a new policy.
    #
    # rollup_engine is unaffected: it passes the measured value, which equals
    # the measurement. Only a claim ABOVE what was recorded is reduced, and
    # the original claim comes back in the result so nothing is hidden.
    measured = count_baseline_sessions(entity_type, entity_value, behavior_key)
    claimed = sample_count
    clamped = False
    if sample_count is not None and sample_count > measured:
        sample_count = measured
        clamped = True

    # CONFIDENCE IS MEASURED TOO. 2026-08-29.
    #
    # The clamp above fixed sample_count and stopped there, which left the
    # door it was built to close still open. sample_count only matters
    # because confidence is derived from it, and confidence is what drives
    # suppression, so a caller who could not inflate the count could still
    # just pass confidence='high' and skip the count entirely.
    #
    # Found by reading real rows: 77.111.246.33 was sitting at confidence
    # 'medium' with sample_count 0. Zero sessions of evidence, a tier that
    # claims several. Nothing was lying; nothing was checking either.
    #
    # So a claimed confidence is now capped at what the measured session
    # count supports. Lower is always allowed: a caller saying "I have less
    # faith in this than the arithmetic does" is information, and refusing it
    # would be the tool overruling a human who looked at the thing.
    #
    # The original claim comes back in the result, same as sample_count. A
    # control that silently overrides a caller teaches nobody anything.
    conf_claimed = confidence
    conf_clamped = False
    if confidence is not None:
        t = confidence_thresholds()
        if measured >= t["high"]:
            ceiling = "high"
        elif measured >= t["medium"]:
            ceiling = "medium"
        else:
            ceiling = "low"
        rank = {"low": 0, "medium": 1, "high": 2}
        if rank[confidence] > rank[ceiling]:
            confidence = ceiling
            conf_clamped = True

    # THE QUIET DOOR. TODO 8.1F, 2026-09-04. See evidence_gate above.
    #
    # The two clamps above ask HOW MUCH evidence there is. This asks WHOSE it
    # is. An entity can have twenty honest-looking sessions and still be
    # nothing but text an attacker chose, and that is the case the counting
    # clamps cannot see.
    #
    # SUPPRESSION IS REFUSED, CONFIDENCE IS CLAMPED, and the difference is
    # deliberate. Clamping a confidence is a smaller claim than the caller
    # made and the caller learns what happened from the result. Suppression
    # is not a claim, it is an act with no smaller version: half-suppressed
    # does not exist, so the only honest answers are yes and no.
    gate = None
    if alert_suppressed is not None or confidence == "high":
        gate = evidence_gate(entity_type, entity_value, behavior_key)

        if _suppression_flag(alert_suppressed) and not gate["may_suppress"]:
            raise BadInput(gate["reason"])

        if confidence == "high" and not gate["may_reach_high"]:
            confidence = "medium"
            conf_clamped = True

    with _get_conn() as conn:
        # Check if row exists
        existing = conn.execute("""
            SELECT id, sample_count FROM behavioral_baseline
            WHERE entity_type=? AND entity_value=? AND behavior_key=?
        """, (entity_type, entity_value, behavior_key)).fetchone()

        if existing:
            # Build update dynamically, only update fields that are provided
            #
            # A REAL NEW OBSERVATION LIFTS A RETRACTION. v29, TODO 93. The
            # retraction says "what you learned was wrong", not "never learn
            # about this again". Leaving the stamp on would make the row read
            # as withdrawn while carrying fresh numbers, which is worse than
            # either state on its own.
            #
            # Guarded, because this is the hot write path. A pre-v29 database
            # has nothing to un-stamp, and naming a column that is not there
            # would break every baseline write rather than just the retract.
            updates = ["last_updated = CURRENT_TIMESTAMP"]
            if _retract_ready(conn):
                updates += ["retracted_at = NULL", "retracted_reason = NULL"]
            params = []

            if sample_count is not None:
                updates.append("sample_count = ?"); params.append(sample_count)
            if value_mean is not None:
                updates.append("value_mean = ?"); params.append(value_mean)
            if value_stddev is not None:
                updates.append("value_stddev = ?"); params.append(value_stddev)
            if value_min is not None:
                updates.append("value_min = ?"); params.append(value_min)
            if value_max is not None:
                updates.append("value_max = ?"); params.append(value_max)
            if typical_hours is not None:
                updates.append("typical_hours = ?")
                params.append(json.dumps(typical_hours))
            if typical_dest_ports is not None:
                updates.append("typical_dest_ports = ?")
                params.append(json.dumps(typical_dest_ports))
            if typical_dest_ips is not None:
                updates.append("typical_dest_ips = ?")
                params.append(json.dumps(typical_dest_ips))
            if confidence is not None:
                updates.append("confidence = ?"); params.append(confidence)
            if model_notes is not None:
                updates.append("model_notes = ?"); params.append(model_notes)
            if beacon_detail is not None:
                updates.append("beacon_detail = ?")
                params.append(beacon_detail)
            if flagged_as_normal is not None:
                updates.append("flagged_as_normal = ?")
                params.append(_suppression_flag(flagged_as_normal))
            if alert_suppressed is not None:
                updates.append("alert_suppressed = ?")
                params.append(_suppression_flag(alert_suppressed))

            params.extend([entity_type, entity_value, behavior_key])
            conn.execute(
                f"UPDATE behavioral_baseline SET {', '.join(updates)} "
                f"WHERE entity_type=? AND entity_value=? AND behavior_key=?",
                params
            )
            row_id = existing["id"]
        else:
            cursor = conn.execute("""
                INSERT INTO behavioral_baseline
                    (entity_type, entity_value, behavior_key, sample_count,
                     value_mean, value_stddev, value_min, value_max,
                     typical_hours, typical_dest_ports, typical_dest_ips,
                     confidence, model_notes, beacon_detail,
                     flagged_as_normal, alert_suppressed, first_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                entity_type, entity_value, behavior_key,
                sample_count or 0,
                value_mean, value_stddev, value_min, value_max,
                json.dumps(typical_hours) if typical_hours else None,
                json.dumps(typical_dest_ports) if typical_dest_ports else None,
                json.dumps(typical_dest_ips) if typical_dest_ips else None,
                confidence or "low",
                model_notes,
                beacon_detail,
                1 if flagged_as_normal else 0,
                1 if alert_suppressed else 0,
                first_seen or datetime.now(timezone.utc).isoformat(),
            ))
            row_id = cursor.lastrowid

    result = {"success": True, "id": row_id,
              "sample_count_recorded": measured}
    if conf_clamped:
        result["confidence_claimed"] = conf_claimed
        result["confidence_note"] = (
            f"confidence '{conf_claimed}' was reduced to '{confidence}'. "
            f"Confidence is derived from distinct sessions observed, and "
            f"{measured} have been recorded for this entity. Observing it in "
            f"more sessions raises the ceiling; asserting a tier does not."
        )
    if clamped:
        result["sample_count_claimed"] = claimed
        result["sample_count_note"] = (
            f"sample_count is counted in distinct sessions and {measured} "
            f"have been recorded for this entity, not {claimed}. The stored "
            f"value is the measured one. If more sessions genuinely observed "
            f"this, they were never registered via record_baseline_session, "
            f"which is where the count comes from."
        )
    # TODO 8.1F. Told at the moment of the write, while the model still has
    # the context to go and get a clean observation, rather than left for
    # somebody to discover in the row later. Same pattern as basis_note.
    if gate and gate["reason"]:
        result["evidence_note"] = gate["reason"]
        result["clean_sessions"] = gate["clean_sessions"]

    check = corroborate_direction(entity_type, entity_value, behavior_key)
    if check:
        result["direction_check"] = check
    return result


def _derive_severity(deviation_score: float) -> str:
    """
    Fallback severity when the model does not supply one.

    Schema documents >2.0 stddevs as notable and >3.0 as alert-worthy, so
    those are the cut points.
    """
    try:
        score = abs(float(deviation_score))
    except (TypeError, ValueError):
        return "low"
    if score >= 4.0:
        return "critical"
    if score >= 3.0:
        return "high"
    if score >= 2.0:
        return "medium"
    return "low"


def write_deviation(
    entity_type: str,
    entity_value: str,
    behavior_key: str,
    session_id: str,
    expected_value: str,
    observed_value: str,
    deviation_score: float,
    model_assessment: str,
    action_taken: str,
    severity: str = None,
) -> dict:
    """
    Write a behavioral deviation. Model calls this when something falls
    outside the established baseline. Starts the silence timer clock.

    severity drives the silence-timer floor: 'critical' and 'high' are never
    auto-resolved by silence. If omitted it is derived from deviation_score.
    """
    _validate_entity(entity_type, entity_value)
    if action_taken not in VALID_ACTION_TAKEN:
        raise BadInput(f"Invalid action_taken '{action_taken}'")

    if severity is None:
        severity = _derive_severity(deviation_score)
    if severity not in VALID_SEVERITY:
        raise BadInput(f"Invalid severity '{severity}'")

    silence_timeout = int(get_preference("silence_timeout_seconds", 150))

    with _get_conn() as conn:
        cursor = conn.execute("""
            INSERT INTO behavioral_deviation
                (session_id, entity_type, entity_value, behavior_key,
                 expected_value, observed_value, deviation_score,
                 model_assessment, action_taken, alerted_at,
                 silence_timeout_seconds, severity)
            VALUES (?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,?,?)
        """, (
            session_id, entity_type, entity_value, behavior_key,
            str(expected_value), str(observed_value), deviation_score,
            model_assessment, action_taken, silence_timeout, severity
        ))
        result = {
            "success": True,
            "id": cursor.lastrowid,
            "deviation_id": cursor.lastrowid,
            "severity": severity,
        }

    # This is the path that produced the 2026-08-28 pair: two inbound
    # multicast SOURCES filed under beacon_destinations, which reads as an
    # outbound relationship. The write still succeeds, see
    # corroborate_direction on why refusing would cost more than it saves,
    # but it no longer succeeds silently.
    check = corroborate_direction(entity_type, entity_value, behavior_key)
    if check:
        result["direction_check"] = check
    return result


VALID_RESOLVED_BY = ("user", "model", "silence_timer")

_RESOLVED_BY_COLUMN = None       # None = not looked yet


def _resolved_by_ready(conn) -> bool:
    """
    Does this database have the v30 resolved_by column yet?

    Same guard as _retract_ready and it is here for the same reason, which is
    93.5: a new column used in a shared write path needs its guard in the same
    commit as the migration, because the migration and the code do not land at
    the same moment on a running machine. The app migrates at boot, a script
    against an un-migrated file does not.
    """
    global _RESOLVED_BY_COLUMN
    if _RESOLVED_BY_COLUMN is None:
        try:
            cols = {r[1] for r in
                    conn.execute("PRAGMA table_info(behavioral_deviation)")}
            _RESOLVED_BY_COLUMN = "resolved_by" in cols
        except sqlite3.OperationalError:
            _RESOLVED_BY_COLUMN = False
    return _RESOLVED_BY_COLUMN


def resolve_deviation(
    deviation_id: int,
    resolved_as: str,
    user_response: str = None,
    resolved_by: str = "user",
) -> dict:
    """
    Resolve a deviation, and say WHO resolved it.
    resolved_as: 'normal','threat','investigating','ignored','false_positive'

    WHAT WAS WRONG WITH THIS UNTIL 2026-09-14, TODO 98.

    The schema says `user_responded, 0 = silence, 1 = user replied` and
    `user_response, verbatim if they responded`. This function set both from
    whatever it was handed, and one of the three callers is a MODEL TOOL. It
    is ungated and takes free text, and the manifest invited it: "Verbatim
    user response if they replied".

    So the model could write a sentence into the column that means a human
    said it, flip the flag that means a human answered, and nothing anywhere
    recorded that the model was the one holding the pen. dismiss_entity has
    passed dismissed_by="model" since the day it was written. This table had
    no such column at all.

    It also took the row out of get_silent_deviations, which selects
    user_responded = 0, and that path exists because silence is not approval.

    THE RULE NOW: user_responded and user_response belong to the USER path and
    to nothing else. A model resolve is recorded as a model resolve. It is
    still allowed, because the model reading a deviation and saying what it
    thinks is the job, but it is a RECOMMENDATION and query_review_queue keeps
    showing it until a person answers. Same shape as nominate_finding, where
    the model raises its hand and the owner decides. See TODO 84.
    """
    if resolved_as not in VALID_RESOLVED_AS:
        raise BadInput(f"Invalid resolved_as '{resolved_as}'")
    if resolved_by not in VALID_RESOLVED_BY:
        raise BadInput(
            f"Invalid resolved_by '{resolved_by}'. One of "
            f"{list(VALID_RESOLVED_BY)}. This says who is answering, and it "
            f"is not optional, because the row cannot be read later without "
            f"it.")

    # REFUSED, NOT IGNORED, and the message names the column to use instead.
    # Silently dropping it would leave the model thinking it had been recorded.
    if resolved_by != "user" and user_response:
        raise BadInput(
            "user_response is the operator's own words and only the operator "
            "writes it. Put your own reading in model_assessment through "
            "write_deviation, or say it in your answer. Recording it here "
            "would make the row say a person replied when none did.")

    human_answered = 1 if (resolved_by == "user" and user_response) else 0

    with _get_conn() as conn:
        sets = ["resolved_as = ?", "resolved_at = CURRENT_TIMESTAMP",
                "user_responded = ?", "user_response = ?"]
        params = [resolved_as, human_answered, user_response]
        ready = _resolved_by_ready(conn)
        if ready:
            sets.append("resolved_by = ?")
            params.append(resolved_by)
        params.append(deviation_id)
        conn.execute(f"UPDATE behavioral_deviation SET {', '.join(sets)} "
                     f"WHERE id = ?", params)
        result = {"success": True, "deviation_id": deviation_id,
                  "resolved_as": resolved_as, "resolved_by": resolved_by}
        if not ready:
            # RULE TWO. The write happened, part of it did not, and the
            # caller is told which part rather than being handed a plain
            # success that reads as all of it.
            result["resolved_by_recorded"] = False
            result["note"] = (
                "This database has not taken the v30 migration, so there is "
                "no resolved_by column and WHO resolved this was not stored. "
                "The resolution itself was. Start the app once to migrate.")
            logger.warning(
                f"resolve_deviation({deviation_id}) could not record "
                f"resolved_by={resolved_by}: pre-v30 database.")
    _journal("deviation_resolved", "behavioral_deviation", deviation_id,
             {"resolved_as": resolved_as, "user_response": user_response,
              "resolved_by": resolved_by})
    return result


# WRITE, PYTHON-OWNED TABLES
# (Python monitors call these, model never calls these directly)

# SENSORS, vantage points
#
# Where an observation was made from. See core/sensors.py for why this
# exists and what each position can and cannot see. Collectors do not pass a
# sensor_id; it defaults to whichever sensor this process is, which keeps
# every existing call site working unchanged and means a collector cannot
# accidentally claim to have been somewhere else.

def _local_sensor_id() -> str:
    """Imported lazily so that core.sensors can import this module."""
    from core import sensors as sn
    return sn.LOCAL_SENSOR_ID


def upsert_sensor(sensor_id: str, position: str, can_see: str,
                  cannot_see: str, summary: str = None, label: str = None,
                  notes: str = None):
    """
    Register or refresh a sensor. Called at boot by core.sensors.register_local
    and, later, by any remote sensor reporting in.

    can_see and cannot_see are written by Python because they are facts about
    topology rather than judgements about this network. They are stored per
    row rather than looked up at read time so that a sensor whose position
    changes does not silently rewrite the scope of observations it already
    made.
    """
    with _get_conn() as conn:
        conn.execute("""
            INSERT INTO sensors
                (sensor_id, label, position, summary, can_see, cannot_see, notes)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(sensor_id) DO UPDATE SET
                label      = COALESCE(excluded.label, sensors.label),
                position   = excluded.position,
                summary    = excluded.summary,
                can_see    = excluded.can_see,
                cannot_see = excluded.cannot_see,
                notes      = COALESCE(excluded.notes, sensors.notes),
                last_seen  = CURRENT_TIMESTAMP
        """, (sensor_id, label, position, summary, can_see, cannot_see, notes))


def query_sensors(sensor_id: str = None) -> list[dict]:
    """
    Every sensor that has ever reported, with what its position can and
    cannot observe, and how many observations it has contributed.

    The counts matter as much as the scope text. A network with one host
    sensor and ten thousand rows is not well covered; it is one vantage point
    seen ten thousand times.
    """
    conditions, params = [], []
    if sensor_id:
        conditions.append("s.sensor_id = ?")
        params.append(sensor_id)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    sql = f"""
        SELECT s.*,
               (SELECT COUNT(*) FROM packets p
                 WHERE p.sensor_id = s.sensor_id) AS packet_rows,
               (SELECT COUNT(*) FROM findings f
                 WHERE f.sensor_id = s.sensor_id) AS finding_rows
        FROM sensors s
        {where}
        ORDER BY s.last_seen DESC
    """
    with _get_conn() as conn:
        return _rows_to_dicts(conn.execute(sql, params).fetchall())


# DNS, imported from the network's resolver
#
# Written by tools/dns_monitor.py only. Read by the model through query_dns
# and query_dns_clients, both fenced as untrusted, because every domain here
# was chosen by whoever controls the device that asked for it.

def save_dns_queries(rows: list[dict], sensor_id: str) -> dict:
    """
    Bulk insert imported resolver rows. Returns counts.

    INSERT OR IGNORE against UNIQUE(source, source_row_id) makes a re-import
    a no-op instead of a duplicate, which matters because the importer is
    restartable and a resolver log is usually read from the start after any
    doubt about the cursor. Preferring idempotency to a perfect cursor is the
    right trade here: a missed row is invisible, a duplicated row inflates
    every count the model reasons from.
    """
    if not rows:
        return {"inserted": 0, "seen": 0}

    payload = [
        (
            r["queried_at"], r.get("client_ip"), r["domain"],
            r.get("query_type"), r.get("status"),
            1 if r.get("blocked") else 0,
            r.get("upstream"), r.get("reply_type"),
            r["source"], str(r["source_row_id"]), sensor_id,
        )
        for r in rows
    ]
    with _get_conn() as conn:
        before = conn.execute("SELECT COUNT(*) FROM dns_queries").fetchone()[0]
        conn.executemany("""
            INSERT OR IGNORE INTO dns_queries
                (queried_at, client_ip, domain, query_type, status, blocked,
                 upstream, reply_type, source, source_row_id, sensor_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, payload)
        after = conn.execute("SELECT COUNT(*) FROM dns_queries").fetchone()[0]
    return {"inserted": after - before, "seen": len(rows)}


def query_dns(client_ip: str = None, domain: str = None, since: str = None,
              blocked: bool = None, limit: int = 100,
              order: str = "desc", with_total: bool = False):
    """
    Raw resolver rows. Prefer query_dns_clients for behaviour questions.

    with_total=True adds the exact matching count and whether this is all of
    them. TODO 94.4.
    """
    limit = _validate_limit(limit)
    conditions, params = [], []
    if client_ip:
        conditions.append("client_ip = ?")
        params.append(client_ip)
    if domain:
        conditions.append("domain LIKE ?")
        params.append(f"%{domain}%")
    if since:
        conditions.append("queried_at >= ?")
        params.append(_sql_datetime(since, SHAPE_ISO_OFFSET))
    if blocked is not None:
        conditions.append("blocked = ?")
        params.append(1 if blocked else 0)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    direction = "ASC" if str(order).lower() == "asc" else "DESC"
    sql = (f"SELECT * FROM dns_queries {where} "
           f"ORDER BY queried_at {direction} LIMIT ?")
    filter_params = list(params)
    params.append(limit)
    with _get_conn() as conn:
        rows = _rows_to_dicts(conn.execute(sql, params).fetchall())
        if not with_total:
            return rows
        return _with_total(conn, rows, "dns_queries", where, filter_params,
                           limit, "queries")


def save_dns_answers(rows: list[dict], sensor_id: str = None) -> dict:
    """
    Fold captured DNS answers into dns_answer, one row per distinct answer.

    Upsert on (name, rrtype, value, client_ip, resolver): a repeat moves
    last_seen and the TTL and counts in times_seen. Returns counts.
    """
    if not rows:
        return {"seen": 0, "new": 0, "repeats": 0}
    new = repeats = 0
    with _get_conn() as conn:
        for r in rows:
            name = (r.get("name") or "")[:253]
            rrtype = (r.get("rrtype") or "")[:16]
            if not name or not rrtype:
                continue
            conn.execute("""
                INSERT INTO dns_answer
                    (first_seen, last_seen, name, rrtype, value, ttl,
                     client_ip, resolver, protocol, sensor_id)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(name, rrtype, value, client_ip, resolver)
                DO UPDATE SET last_seen  = excluded.last_seen,
                              ttl        = excluded.ttl,
                              times_seen = times_seen + 1
            """, (r.get("seen") or datetime.now(timezone.utc).isoformat(),
                  r.get("seen") or datetime.now(timezone.utc).isoformat(),
                  name, rrtype, (r.get("value") or "")[:253], r.get("ttl"),
                  r.get("client_ip") or "", r.get("resolver") or "",
                  (r.get("protocol") or "dns")[:16], sensor_id))
            row = conn.execute(
                "SELECT times_seen FROM dns_answer WHERE name = ? AND "
                "rrtype = ? AND value = ? AND client_ip = ? AND resolver = ?",
                (name, rrtype, (r.get("value") or "")[:253],
                 r.get("client_ip") or "", r.get("resolver") or "")).fetchone()
            if row and row[0] == 1:
                new += 1
            else:
                repeats += 1
    return {"seen": len(rows), "new": new, "repeats": repeats}


def query_dns_answers(address: str = None, name: str = None,
                      rrtype: str = None, since: str = None,
                      limit: int = 100) -> dict:
    """
    What captured DNS replies said: the names behind an address, or the
    addresses behind a name.

    Always carries `coverage`: only replies that crossed the capture in the
    clear are here, so an address with no row may still have a name (DoH,
    DoT, a cached lookup, or a lookup made before capture started).
    """
    limit = _validate_limit(limit)
    conditions, params = [], []
    if address:
        conditions.append("value = ?")
        params.append(address.strip().lower())
    if name:
        conditions.append("name LIKE ?")
        params.append(f"%{name.strip().lower()}%")
    if rrtype:
        conditions.append("rrtype = ?")
        params.append(rrtype.strip().upper())
    if since:
        conditions.append("last_seen >= ?")
        params.append(_sql_datetime(since, SHAPE_ISO_OFFSET))
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    with _get_conn() as conn:
        rows = _rows_to_dicts(conn.execute(
            f"SELECT * FROM dns_answer {where} ORDER BY last_seen DESC "
            f"LIMIT ?", params + [limit]).fetchall())
        total = conn.execute(f"SELECT COUNT(*) FROM dns_answer {where}",
                             params).fetchone()[0]
    return {
        "rows": rows,
        "total": total,
        "complete": total <= len(rows),
        "coverage": ("Built from DNS replies the packet capture saw in the "
                     "clear. Lookups over DoH, DoT or DoQ, answers served "
                     "from a cache, and anything before capture started are "
                     "not here, so no row is not proof of no name."),
    }


def save_tls_hellos(rows: list[dict], session_id: str = None,
                    sensor_id: str = None) -> dict:
    """
    Fold a batch of parsed ClientHellos into tls_hello. TODO 113.2.

    PORTED TO LINUX 2026-09-21. No part of this is platform specific: it is an
    upsert into a table the schema port added.

    UPSERT, not insert. The key is the combination that a question is asked
    about (this client, this destination, this port, this name, this
    fingerprint, this process), and times_seen counts the repeats. A browser
    reopening the same connection two hundred times an hour adds 1 row and
    199 to a counter.

    WHAT COMES BACK is counts, and 'unreadable' is one of them, separately.
    The caller logs it and query_tls reports it, because the number of hellos
    we could NOT read is the only thing that makes the list of names we could
    read an honest answer rather than a confident subset.
    """
    if not rows:
        return {"seen": 0, "new": 0, "repeats": 0, "unreadable": 0}

    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    new = repeats = unreadable = 0

    with _get_conn() as conn:
        for r in rows:
            state = r.get("sni_state") or "unreadable"
            if state == "unreadable":
                unreadable += 1
            payload = (
                now, now,
                r.get("src_ip") or "", r.get("dst_ip") or "",
                int(r.get("dst_port") or 0),
                (r.get("sni") or "")[:253],
                state,
                (r.get("ja3") or "")[:600],
                r.get("ja3_md5") or "",
                ",".join(r.get("alpn") or [])[:120],
                r.get("legacy_version") or "",
                r.get("cipher_count"), r.get("ext_count"),
                (r.get("process_name") or "")[:120],
                r.get("process_pid"),
                # Only unreadable rows carry a reason, so a readable row
                # cannot be split into two key rows by a reason string that
                # changes wording between versions.
                (r.get("parse_reason") or "")[:200] if state == "unreadable" else "",
                session_id, sensor_id,
                # 'quic' for a hello read out of a QUIC Initial packet.
                "quic" if r.get("transport") == "quic" else "tcp",
            )
            cur = conn.execute("""
                INSERT INTO tls_hello
                    (first_seen, last_seen, src_ip, dst_ip, dst_port, sni,
                     sni_state, ja3, ja3_md5, alpn, legacy_version,
                     cipher_count, ext_count, process_name, process_pid,
                     parse_reason, session_id, sensor_id, transport)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(src_ip, dst_ip, dst_port, sni, ja3_md5,
                            process_name, parse_reason)
                DO UPDATE SET last_seen  = excluded.last_seen,
                              times_seen = times_seen + 1
            """, payload)
            # rowcount is 1 either way on an upsert, so the two cases are
            # told apart by whether the insert produced a new id rather than
            # by guessing from the statement.
            if cur.lastrowid and conn.execute(
                    "SELECT times_seen FROM tls_hello WHERE id = ?",
                    (cur.lastrowid,)).fetchone()[0] == 1:
                new += 1
            else:
                repeats += 1

    return {"seen": len(rows), "new": new, "repeats": repeats,
            "unreadable": unreadable}


def query_tls(sni: str = None, ja3_md5: str = None, dst_ip: str = None,
              src_ip: str = None, process_name: str = None,
              since: str = None, limit: int = 100) -> dict:
    """
    What TLS clients on this network asked for, by name. TODO 113.2.

    PORTED TO LINUX 2026-09-21, so the model can see a domain behind an
    encrypted connection on this host rather than only on the Windows one.

    Returns a dict, not a list, because the rows alone would be a lie by
    omission. Every answer carries `coverage`, which says how many hellos
    could not be read at all. A list of eleven domains with four hundred
    unreadable hellos behind it is not a list of the domains this machine
    talked to, and nothing downstream can tell unless the number travels with
    the rows.
    """
    limit = _validate_limit(limit)
    conditions, params = ["sni_state != 'unreadable'"], []
    if sni:
        conditions.append("sni LIKE ?")
        params.append(f"%{sni.lower()}%")
    if ja3_md5:
        conditions.append("ja3_md5 = ?")
        params.append(ja3_md5.lower())
    if dst_ip:
        conditions.append("dst_ip = ?")
        params.append(dst_ip)
    if src_ip:
        conditions.append("src_ip = ?")
        params.append(src_ip)
    if process_name:
        conditions.append("process_name LIKE ?")
        params.append(f"%{process_name}%")
    if since:
        conditions.append("last_seen >= ?")
        params.append(_sql_datetime(since, SHAPE_ISO_OFFSET))

    where = "WHERE " + " AND ".join(conditions)

    with _get_conn() as conn:
        rows = _rows_to_dicts(conn.execute(
            f"SELECT * FROM tls_hello {where} "
            f"ORDER BY last_seen DESC LIMIT ?", params + [limit]).fetchall())

        total = conn.execute(
            f"SELECT COUNT(*) FROM tls_hello {where}", params).fetchone()[0]

        # The coverage numbers are deliberately NOT filtered by sni or ja3:
        # "how much of the traffic could we read" is a question about the
        # sensor, not about the search. Filtering them would make a narrow
        # search look better covered than a wide one, which is backwards.
        unreadable = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(times_seen), 0) FROM tls_hello "
            "WHERE sni_state = 'unreadable'").fetchone()
        readable = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(times_seen), 0) FROM tls_hello "
            "WHERE sni_state != 'unreadable'").fetchone()
        why = _rows_to_dicts(conn.execute(
            "SELECT parse_reason AS reason, COUNT(*) AS rows_ "
            "FROM tls_hello WHERE sni_state = 'unreadable' "
            "GROUP BY parse_reason ORDER BY rows_ DESC LIMIT 5").fetchall())

    seen_ok, seen_bad = readable[1], unreadable[1]
    both = seen_ok + seen_bad

    return {
        "rows": rows,
        "returned": len(rows),
        "matching": total,
        "complete": len(rows) >= total,
        "coverage": {
            "hellos_read": seen_ok,
            "hellos_unreadable": seen_bad,
            "read_share": round(seen_ok / both, 3) if both else None,
            "why_unreadable": why,
            "note": voice.for_you(
                "hellos_unreadable counts TLS handshakes this sensor saw and "
                "could not parse, usually because the ClientHello spanned two "
                "TCP segments. Those connections are NOT in the rows above "
                "and their destination names are not known. Do not answer "
                "'this machine contacted no other domains' off this list "
                "while that number is above zero."
            ),
        },
    }


def query_dns_clients(client_ip: str = None, since: str = None,
                      new_since: str = None, top: int = 15,
                      with_total: bool = False):
    """
    Per-device resolver behaviour, and which names are NEW.

    This is the shape that answers the question the address layer cannot.
    A camera or a television resolves a handful of names and keeps resolving
    the same handful for months, so the strong signal is not what a name is,
    which is usually unknowable, but that a name appeared which never
    appeared before. Novelty and volume survive the fact that a destination
    address resolves to shared infrastructure; identity does not.

    new_since defaults to the last 24 hours. A domain counts as new when it
    was FIRST seen for that client after that point, not merely seen since.
    """
    new_since = _sql_datetime(new_since, SHAPE_ISO_OFFSET) if new_since else (
        (datetime.now(timezone.utc).replace(microsecond=0)
         - timedelta(hours=24)).isoformat())

    conditions, params = [], []
    if client_ip:
        conditions.append("client_ip = ?")
        params.append(client_ip)
    if since:
        conditions.append("queried_at >= ?")
        params.append(_sql_datetime(since, SHAPE_ISO_OFFSET))
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    summary_sql = f"""
        SELECT client_ip,
               COUNT(*)               AS total_queries,
               COUNT(DISTINCT domain) AS distinct_domains,
               MIN(queried_at)        AS first_seen,
               MAX(queried_at)        AS last_seen,
               SUM(blocked)           AS blocked_queries
        FROM dns_queries
        {where}
        GROUP BY client_ip
        ORDER BY total_queries DESC
    """

    top = max(1, min(int(top), 100))
    with _get_conn() as conn:
        clients = _rows_to_dicts(conn.execute(summary_sql, params).fetchall())

        for row in clients:
            ip = row["client_ip"]
            row["top_domains"] = _rows_to_dicts(conn.execute("""
                SELECT domain, COUNT(*) AS queries,
                       MIN(queried_at) AS first_seen,
                       MAX(queried_at) AS last_seen
                FROM dns_queries WHERE client_ip IS ?
                GROUP BY domain ORDER BY queries DESC LIMIT ?
            """, (ip, top)).fetchall())

            # First seen AFTER the cutoff, so a long-standing name that was
            # merely queried again today does not read as new.
            row["new_domains"] = _rows_to_dicts(conn.execute("""
                SELECT domain, MIN(queried_at) AS first_seen, COUNT(*) AS queries
                FROM dns_queries WHERE client_ip IS ?
                GROUP BY domain
                HAVING MIN(queried_at) >= ?
                ORDER BY first_seen DESC LIMIT ?
            """, (ip, new_since, top)).fetchall())
            # A REAL BUG, found doing TODO 94.17 and worth its own note.
            #
            # This line used to read len(row["new_domains"]), and that list is
            # cut at `top`. So a client with 200 newly seen domains, which is
            # the shape of a DGA or a device that has just started beaconing,
            # reported new_domain_count 15. The most interesting number in
            # this whole answer was silently clamped to the display limit, and
            # it read as a measurement.
            #
            # Counted properly now, with the same HAVING the list uses.
            row["new_domain_count"] = conn.execute("""
                SELECT COUNT(*) FROM (
                    SELECT domain FROM dns_queries WHERE client_ip IS ?
                    GROUP BY domain HAVING MIN(queried_at) >= ?
                )
            """, (ip, new_since)).fetchone()[0]
            row["new_since"] = new_since

            # Both lists above are capped at `top` PER CLIENT, so each one
            # says whether it is the whole picture for that client.
            # distinct_domains is already counted by the summary query, so
            # the domain side costs nothing extra.
            row["top_domains_complete"] = (
                len(row["top_domains"]) >= (row.get("distinct_domains") or 0))
            row["new_domains_complete"] = (
                len(row["new_domains"]) >= row["new_domain_count"])
            if not (row["top_domains_complete"] and row["new_domains_complete"]):
                row["note"] = (
                    f"Lists for this client are cut at top={top}. It has "
                    f"{row.get('distinct_domains')} distinct domain(s) and "
                    f"{row['new_domain_count']} first seen since "
                    f"{new_since}. Raise top to see more. The COUNTS are "
                    f"exact; the lists are not the whole set.")

    # The resolver sees devices this host cannot reach at all, so a label
    # here is often the only name that will ever be attached to that address.
    out = _enrich(clients, "client_ip")
    if not with_total:
        return out
    # The CLIENT list itself has no limit, only the per client domain lists
    # do, so the set of clients is complete and each row says whether its own
    # lists are. TODO 94.17.
    answer = _all_rows(out, "clients")
    partial = [r["client_ip"] for r in out
               if not (r.get("top_domains_complete", True)
                       and r.get("new_domains_complete", True))]
    if partial:
        answer["clients_with_cut_lists"] = partial
        answer["note"] = (
            f"Every client is here, but the domain lists inside "
            f"{len(partial)} of them are cut at top={top}. Their own counts "
            f"are exact. " + answer["note"])
    return answer


def _shift_iso_hours(iso: str, hours: int) -> str:
    """Shift an ISO timestamp. Local helper so query_dns_clients has a default
    window without importing timedelta at module scope for one use."""
    from datetime import timedelta
    try:
        base = datetime.fromisoformat(iso)
    except ValueError:
        return iso
    return (base + timedelta(hours=hours)).isoformat()


# ROUTER, read from the gateway's own management interface
#
# Written by tools/router_monitor.py only. Read by the model through
# query_router_clients and query_router_config, both fenced as untrusted,
# because a name in this table was chosen by whoever controls the device that
# presented it and a firmware description was chosen by the vendor.
#
# NOTHING HERE IS MERGED INTO known_devices, and that is a decision rather
# than an omission. known_devices is what a sensor on this host observed;
# these rows are what the router says. Folding one into the other would make
# the device inventory contain devices no host sensor ever saw while still
# reading as though it had seen them, and would destroy the only thing that
# makes a disagreement between the two visible. Reconciling them is the
# model's job, which is what query_router_clients returns the overlap for.

def router_has_history(router_host: str, table: str = "any") -> bool:
    """
    Has anything ever been recorded for this router?

    The first pass has nothing to compare against, so every device is new and
    every setting is new. Reporting that as change would be a wall of findings
    that says only that the collector started, which is the same mistake the
    dashboard's NEW badge avoids on a first scan.

    `table` selects WHICH leg of the collection is asking, RVP-8, 2026-09-27:
    "clients", "config", or "any" for the old both-tables answer. A router
    that answered its neighbour table and refused everything else leaves
    history in ONE table, and a caller baselining the OTHER leg against that
    answer reports a whole first configuration as a set of changes — which is
    precisely the wall of findings this function exists to prevent.
    """
    if table not in ("any", "clients", "config"):
        raise BadInput(f"table must be 'any', 'clients' or 'config', "
                       f"got {table!r}")

    wanted = ["router_clients", "router_config"] if table == "any" else [
        "router_clients" if table == "clients" else "router_config"]

    with _get_conn() as conn:
        for name in wanted:
            row = conn.execute(
                f"SELECT 1 FROM {name} WHERE router_host = ? LIMIT 1",
                (router_host,)
            ).fetchone()
            if row:
                return True
    return False


def save_router_clients(rows: list[dict], router_host: str,
                        sensor_id: str) -> dict:
    """
    Upsert the router's neighbour table. Returns what was actually new.

    A repeat collection that finds the same devices writes no rows, only a
    last_seen touch, which is what makes this safe to run on a short timer.

    Two lookups are done for every new entry, and neither is a judgement:
    whether that hardware address was previously recorded at a DIFFERENT
    address, and whether that address was previously held by a DIFFERENT
    hardware address. The second one is the shape of a device impersonating
    another, and it is also the shape of an ordinary lease expiring and being
    handed on. Which of those it is cannot be decided here; both facts are
    attached to the row so that whoever reads the finding has them.
    """
    if not rows:
        return {"seen": 0, "new": [], "updated": 0}

    new, updated = [], 0

    with _get_conn() as conn:
        for row in rows:
            ip  = (row.get("ip") or "").strip()
            mac = (row.get("mac") or "").strip() or None
            if not ip:
                continue

            existing = conn.execute(
                "SELECT id, hostname FROM router_clients "
                "WHERE router_host = ? AND ip = ? AND COALESCE(mac,'') = ?",
                (router_host, ip, mac or "")
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE router_clients SET last_seen = CURRENT_TIMESTAMP, "
                    "hostname = COALESCE(?, hostname), "
                    "vendor = COALESCE(?, vendor), "
                    "interface = COALESCE(?, interface), "
                    "entry_type = COALESCE(?, entry_type) "
                    "WHERE id = ?",
                    (row.get("hostname"), row.get("vendor"),
                     row.get("interface"), row.get("entry_type"),
                     existing["id"])
                )
                updated += 1
                continue

            other_ips = []
            if mac:
                other_ips = [r["ip"] for r in conn.execute(
                    "SELECT DISTINCT ip FROM router_clients "
                    "WHERE router_host = ? AND mac = ? AND ip != ?",
                    (router_host, mac, ip)
                ).fetchall()]

            other_macs = [r["mac"] for r in conn.execute(
                "SELECT DISTINCT mac FROM router_clients "
                "WHERE router_host = ? AND ip = ? AND COALESCE(mac,'') != ? "
                "AND mac IS NOT NULL",
                (router_host, ip, mac or "")
            ).fetchall()]

            conn.execute("""
                INSERT INTO router_clients
                    (router_host, ip, mac, hostname, vendor, interface,
                     entry_type, source, sensor_id)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (router_host, ip, mac, row.get("hostname"), row.get("vendor"),
                  row.get("interface"), row.get("entry_type"),
                  row.get("source") or "router", sensor_id))

            entry = dict(row)
            entry["mac"] = mac
            entry["also_seen_at"] = other_ips
            entry["address_previously_held_by"] = other_macs
            new.append(entry)

    return {"seen": len(rows), "new": new, "updated": updated}


def save_router_config(rows: list[dict], router_host: str, source: str,
                       sensor_id: str) -> dict:
    """
    Upsert the router's own settings and report which ones CHANGED.

    A change is a value differing from the one previously stored, a setting
    appearing for the first time, or a setting the router has stopped
    reporting. No severity is assigned and no setting is treated as more
    important than another; that ranking is the model's to make against what
    the router is actually for.

    AN EMPTY BATCH IS A FAILED READ, NOT AN EMPTY ROUTER. If the collector
    could not read the settings at all, every stored row would otherwise be
    marked absent and the next pass would report the whole configuration as
    having changed twice. So an empty batch returns immediately and touches
    nothing. This is the same distinction web_search draws between
    searched=false and found nothing.
    """
    if not rows:
        return {"seen": 0, "changed": [], "skipped": "nothing was read"}

    changed = []
    seen_settings = set()

    with _get_conn() as conn:
        for row in rows:
            setting = (row.get("setting") or "").strip()
            if not setting:
                continue
            seen_settings.add(setting)

            value  = row.get("value")
            detail = json.dumps(row["detail"]) if row.get("detail") else None

            existing = conn.execute(
                "SELECT id, value, present FROM router_config "
                "WHERE router_host = ? AND setting = ?",
                (router_host, setting)
            ).fetchone()

            if existing is None:
                conn.execute("""
                    INSERT INTO router_config
                        (router_host, setting, value, detail, source, sensor_id)
                    VALUES (?,?,?,?,?,?)
                """, (router_host, setting, value, detail, source, sensor_id))
                changed.append({"setting": setting, "value": value,
                                "previous_value": None, "added": True,
                                "removed": False, "detail": row.get("detail")})
                continue

            came_back = not existing["present"]
            differs   = (existing["value"] or "") != (value or "")

            if differs or came_back:
                conn.execute("""
                    UPDATE router_config
                       SET previous_value = ?, value = ?, detail = ?,
                           present = 1, source = ?, sensor_id = ?,
                           last_seen = CURRENT_TIMESTAMP,
                           changed_at = CURRENT_TIMESTAMP
                     WHERE id = ?
                """, (existing["value"], value, detail, source, sensor_id,
                      existing["id"]))
                changed.append({
                    "setting": setting, "value": value,
                    "previous_value": existing["value"],
                    "added": False, "removed": False,
                    "returned": came_back, "detail": row.get("detail"),
                })
            else:
                conn.execute(
                    "UPDATE router_config SET last_seen = CURRENT_TIMESTAMP, "
                    "detail = ?, present = 1 WHERE id = ?",
                    (detail, existing["id"])
                )

        # Settings the router used to report and no longer does.
        for gone in conn.execute(
            "SELECT id, setting, value FROM router_config "
            "WHERE router_host = ? AND present = 1", (router_host,)
        ).fetchall():
            if gone["setting"] in seen_settings:
                continue
            conn.execute(
                "UPDATE router_config SET present = 0, previous_value = value, "
                "changed_at = CURRENT_TIMESTAMP WHERE id = ?", (gone["id"],)
            )
            changed.append({"setting": gone["setting"], "value": None,
                            "previous_value": gone["value"],
                            "added": False, "removed": True, "detail": None})

    return {"seen": len(rows), "changed": changed}


def query_router_clients(ip: str = None, mac: str = None,
                         since: str = None, limit: int = 200,
                         with_total: bool = False) -> dict:
    """
    What the router says is on the network, joined against what this host has
    actually observed.

    The join is the point. A device in this table with no known_devices row is
    a device the router exchanges traffic with and no sensor on this machine
    has ever seen, which is a real gap rather than a bookkeeping difference,
    and it is invisible if the two inventories are read separately.
    """
    limit = _validate_limit(limit)
    conditions, params = [], []
    if ip:
        conditions.append("rc.ip = ?")
        params.append(ip)
    if mac:
        conditions.append("rc.mac = ?")
        params.append(mac.lower())
    if since:
        conditions.append("rc.last_seen >= ?")
        params.append(_sql_datetime(since))
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    sql = f"""
        SELECT rc.ip, rc.mac, rc.hostname, rc.vendor, rc.interface,
               rc.entry_type, rc.source, rc.first_seen, rc.last_seen,
               rc.sensor_id,
               kd.known_as     AS known_as,
               kd.device_type  AS device_type,
               kd.evidence     AS identification_evidence
          FROM router_clients rc
          LEFT JOIN known_devices kd ON kd.ip = rc.ip
        {where}
      ORDER BY rc.last_seen DESC
         LIMIT ?
    """
    filter_params = list(params)
    params.append(limit)

    with _get_conn() as conn:
        rows = _rows_to_dicts(conn.execute(sql, params).fetchall())
        host_seen = {r["ip"] for r in conn.execute(
            "SELECT ip FROM known_devices").fetchall()}
        # TODO 94.14. Counted against router_clients alone: the LEFT JOIN on
        # known_devices decorates each row and cannot change how many match.
        counted = (_completeness(conn, "router_clients rc", where,
                                 filter_params, len(rows))
                   if with_total else None)

    for row in rows:
        row["seen_by_a_host_sensor"] = row["ip"] in host_seen
        row["identified"] = bool((row.get("known_as") or "").strip())

    unseen_here = [r["ip"] for r in rows if not r["seen_by_a_host_sensor"]]
    unnamed     = sum(1 for r in rows if not r["identified"])

    answer = {
        "clients": rows,
        "count": len(rows),
        "not_seen_by_any_host_sensor": unseen_here,
        "unidentified": unnamed,
        "note": (
            "PRESENCE HERE MEANS RECENT CONTACT WITH THE ROUTER, NOT PRESENCE "
            "NOW, and absence means nothing at all: this is a neighbour table, "
            "entries age out, and a device that is powered off drops out of "
            "it. It is not a lease table, so a device with a static address "
            "that is talking appears and a device holding a lease that is not "
            "talking does not. Call query_sensors and quote the gateway_api "
            "sensor's cannot_see before drawing any conclusion from something "
            "being missing here."
            + (
                f" {len(unseen_here)} of these have never been seen by a "
                f"sensor on this host. That is a coverage gap, not a finding "
                f"about those devices."
                if unseen_here else ""
            )
        ),
    }
    return _merge_completeness(answer, counted) if counted else answer


def query_router_config(router_host: str = None, changed_only: bool = False,
                        limit: int = 200, with_total: bool = False) -> dict:
    """The router's own settings, and which of them have ever changed."""
    limit = _validate_limit(limit)
    conditions, params = [], []
    if router_host:
        conditions.append("router_host = ?")
        params.append(router_host)
    if changed_only:
        conditions.append("changed_at IS NOT NULL")
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    sql = (f"SELECT setting, value, previous_value, detail, present, "
           f"first_seen, last_seen, changed_at, source, sensor_id "
           f"FROM router_config {where} "
           f"ORDER BY (changed_at IS NULL), changed_at DESC, setting ASC "
           f"LIMIT ?")
    filter_params = list(params)
    params.append(limit)

    with _get_conn() as conn:
        rows = _rows_to_dicts(conn.execute(sql, params).fetchall())
        # TODO 94.15
        counted = (_completeness(conn, "router_config", where, filter_params,
                                 len(rows)) if with_total else None)

    for row in rows:
        if row.get("detail"):
            try:
                row["detail"] = json.loads(row["detail"])
            except (TypeError, ValueError):
                pass
        row["present"] = bool(row.get("present"))

    answer = {
        "settings": rows,
        "count": len(rows),
        "changed": sum(1 for r in rows if r.get("changed_at")),
        "note": (
            "NO SEVERITY IS ATTACHED TO ANY OF THESE, deliberately. A value "
            "differing from the one recorded earlier is a measurement; what "
            "the value MEANS is yours to judge against what this router is "
            "for. A listener on 'all_interfaces' is reachable on every "
            "interface the router has, but whether it is reachable from "
            "outside depends on filtering this tool cannot observe, so do not "
            "report it as an exposed service without saying that. A firmware "
            "string is a PRIOR to look up with web_search and query_runbook, "
            "never a vulnerability on its own."
        ),
    }
    return _merge_completeness(answer, counted) if counted else answer


def router_client_hostname(ip: str) -> dict:
    """
    The name a device presented to the router, if it presented one.

    Separate from identify_device on purpose. This returns a SELF-REPORT and
    labels it as one; turning a self-report into the inventory's answer for
    what a device is goes through adopt_router_hostname, which is gated,
    because a name a device chose for itself is exactly as trustworthy as the
    device.
    """
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT ip, mac, hostname, vendor, first_seen, last_seen "
            "FROM router_clients WHERE ip = ? AND hostname IS NOT NULL "
            "AND TRIM(hostname) != '' ORDER BY last_seen DESC LIMIT 1",
            (ip,)
        ).fetchone()
    return dict(row) if row else None


def adopt_router_hostname(ip: str) -> dict:
    """
    Promote a device's self-reported name into the device inventory.

    TAKES NO NAME. The only parameter is an address, and the label is read
    back out of router_clients. That is the containment property and it is
    worth stating plainly: if this accepted a string, it would be a way for
    attacker-influenced text to arrive in the inventory wearing the authority
    of a gated call the user approved. It cannot, because there is no string
    parameter to put text in.

    The evidence recorded carries the whole story rather than the flattering
    half. identified_by is 'user' because a person approved it at the gate,
    but the name did not come from that person; it came from the device, and
    a later session reading this row is entitled to weigh that correctly and
    throw the label out.
    """
    record = router_client_hostname(ip)
    if not record:
        return {
            "success": False,
            "error": ("No self-reported name is recorded for that address. "
                      "The router's neighbour table carries addresses and "
                      "hardware addresses; standard SNMP does not carry "
                      "device names, so this will usually be the case on that "
                      "backend. There is nothing to adopt, and inventing a "
                      "label would be the exact failure this call exists to "
                      "avoid."),
        }

    name = (record.get("hostname") or "").strip()[:64]
    if not name:
        return {"success": False,
                "error": "The recorded name is empty after trimming."}

    return identify_device(
        ip=ip,
        known_as=name,
        evidence=(
            f"Self-reported: the device presented the name {name!r} to the "
            f"router, and a user approved adopting it at the permission gate. "
            f"This is the device's own claim about itself, not an "
            f"observation of what it does. A device can present any name it "
            f"likes, so treat this as weaker than an identification made from "
            f"observed behaviour, and revise it if what you see disagrees."
        ),
        identified_by="user",
    )


def save_packet(session_id: str, src_ip: str, dst_ip: str,
                src_port: int = None, dst_port: int = None,
                protocol: str = None, direction: str = None,
                packet_size: int = None, flags: dict = None,
                payload_snippet: str = None, threat_label: str = None,
                vpn_state: str = "unknown",
                sensor_id: str = None, scope: str = None,
                process_name: str = None, process_pid: int = None):
    """
    Called by packet_sniffer.py only.

    TWO COLUMNS THIS NO LONGER WRITES, both retired 2026-09-01 on the
    measurement in TODO 34. Neither is a judgement call, both came off
    scripts/db_breakdown.py run against the real 1.6 GB database.

    raw_summary is GONE. The parameter is gone with it, so a caller still
    passing one now fails loudly instead of writing 124 MB nobody reads. It
    was scapy's summary() line, rebuilt from src_ip, dst_ip, protocol and
    flags, every one of which is a column right here.

    payload_snippet is written ONLY on a flagged row. It was 566.7 MB across
    1,304,740 rows, of which 242 were flagged. The sniffer already drops it
    before calling, and the guard below is the second half of that: this
    function is where the invariant belongs, because this is the only door
    into the table.

    A pre-existing database still HAS a raw_summary column, holding whatever
    was written before today. The INSERT names its columns, so it simply goes
    on being NULL for new rows. Reclaiming the space it already took needs
    scripts/reclaim_packet_space.py, which is a manual job and deliberately
    not part of boot.

    `scope` is the precise address classification; `direction` is the coarse
    one. They are separate columns because direction carries a CHECK
    constraint allowing only three values, and widening it would mean
    rebuilding a table that is most of a 907 MB database.

    See the comment above classify_scope in tools/packet_sniffer.py for why
    the distinction exists: direction's third value used to double as the
    bucket for packets nothing could classify, and a fallthrough wearing the
    name of a real category is how a foreign multicast packet was read as
    ordinary local chatter.
    """
    # The invariant, enforced at the only door into the table rather than
    # trusted to every caller. An unflagged row does not carry a payload.
    if not threat_label:
        payload_snippet = None

    with _get_conn() as conn:
        conn.execute("""
            INSERT INTO packets
                (session_id, src_ip, dst_ip, src_port, dst_port, protocol,
                 direction, scope, packet_size, flags, payload_snippet,
                 threat_label, vpn_state, sensor_id, process_name, process_pid)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            session_id, src_ip, dst_ip, src_port, dst_port, protocol,
            direction, scope, packet_size,
            json.dumps(flags) if flags else None,
            payload_snippet, threat_label, vpn_state,
            sensor_id or _local_sensor_id(),
            process_name, process_pid
        ))


def finding_already_open(source: str, entity_type: str, entity_value: str,
                         title: str) -> bool:
    """
    Is there already an undismissed finding saying exactly this?

    TODO 90, 2026-09-13. THE MEASUREMENT THAT FORCED IT: 220 Defender findings
    across 11 sessions, exactly 20 every boot, 20 distinct ThreatIDs. Same
    detections, re-raised from scratch every start, because the only thing
    stopping a repeat lived in memory and memory does not survive a restart.

    A cooldown cannot fix that shape. packet_sniffer's 30 minute cooldown is
    right for a live condition that comes and goes, but Defender's detection
    history is PERMANENT: it hands back the same rows forever, so anything
    keyed on time will re-raise them on every boot until the end of the world.
    The only thing that knows what was already raised is the database.

    DISMISSED ROWS DO NOT COUNT AS OPEN, deliberately. Dismissing says "stop
    telling me", and dismissed_findings already handles that separately by
    entity. If a dismissed row blocked a re-raise here too, an entity that was
    dismissed and then genuinely came back would be silenced by the wrong
    mechanism, and silence is the expensive kind of wrong.

    Matched on the four fields that make up what the row SAYS. Not on the
    description, which carries counts and timestamps and would differ on every
    poll, which would make this function always return False and look like it
    was working.
    """
    with _get_conn() as conn:
        row = conn.execute("""
            SELECT id FROM findings
            WHERE dismissed = 0 AND source = ? AND entity_type = ?
              AND entity_value = ? AND title = ?
            LIMIT 1
        """, (source, entity_type, entity_value, title)).fetchone()
        return row is not None


def dismissal_silences(detection_id: str, entity_type: str,
                       entity_value: str, raw_data: dict = None):
    """
    The reason a dismissal stops this finding, or None.

    A dismissal covers the SAME RULE about the same thing, never a different
    rule: dismissing a noisy DNS alert about a device must not hide a tunnel
    or a spoof about it. A process dismissal must also be about the same
    executable (PM-7). Fails open: a store that cannot be read raises.
    """
    try:
        if not is_dismissed(entity_type, entity_value):
            return None
        with _get_readonly_conn() as conn:
            same_rule = conn.execute(
                "SELECT 1 FROM findings WHERE entity_type=? AND entity_value=? "
                "AND detection_id=? AND dismissed=1 AND dismissed_reason LIKE ? "
                "LIMIT 1",
                (entity_type, entity_value, detection_id,
                 ENTITY_DISMISSAL_MARK + "%")).fetchone()
    except Exception as e:                              # noqa: BLE001
        logger.warning(f"Could not read the dismissal of {entity_type}:"
                       f"{entity_value} ({e}). Raising anyway.")
        return None
    if same_rule is None:
        return None
    if entity_type == "process":
        exe = (raw_data or {}).get("exe") if isinstance(raw_data, dict) else None
        covered = dismissal_covers("process", entity_value, exe)
        return covered["reason"] if covered["covered"] else None
    return (f"{entity_type} {entity_value} was dismissed for {detection_id}, "
            f"and this is the same rule")


def save_finding(session_id: str, source: str, severity: str,
                 entity_type: str, entity_value: str, title: str,
                 description: str = None, raw_data: dict = None,
                 vpn_state: str = "unknown", sensor_id: str = None,
                 detection_id: str = None) -> dict:
    """
    Called by monitors only. Model reads findings, never writes them.

    TODO 112, 2026-09-15. detection_id is REQUIRED and is checked against
    core/detections before anything is written. It is keyword-with-a-default
    rather than positional so that a caller who forgets gets the sentence
    explaining what to do instead of a bare TypeError about argument counts.

    RETURNS A DICT NOW, WHERE IT USED TO RETURN None, and that is rule two
    applied to a writer. This function can decline to write, because of a
    suppression rule, and a caller that gets None back cannot tell "saved" from
    "deliberately not saved" from "could not check". Nothing read the old
    return value, so nothing breaks; everything that calls it can now tell.

        {"saved": True,  "detection_id": ..., "rev": n}
        {"saved": False, "detection_id": ..., "reason": "...",
         "suppression_id": n}

    THE SEVERITY IS CHECKED AGAINST THE REGISTER, not just against
    VALID_SEVERITY. A detection that starts raising critical where it used to
    raise low has changed meaning, and that belongs in the register as a
    decision rather than arriving as a surprise on the dashboard.
    """
    from core import detections as det

    if not detection_id:
        raise det.MissingDetectionId(
            f"save_finding was called for '{title}' with no detection_id. "
            f"Every finding names the rule that raised it. Pick the id from "
            f"core/detections._REGISTER, or add an entry there first if this "
            f"is a new detection."
        )
    rule = det.get(detection_id)            # raises UnknownDetection
    if severity not in VALID_SEVERITY:
        raise BadInput(f"Invalid severity '{severity}'")
    det.check_severity(detection_id, severity)

    # Checked HERE rather than at each call site so it cannot be forgotten by
    # the next sensor somebody writes. The two mechanisms stay distinct, so
    # that "why was I not told" always has one answer rather than a shrug.
    silenced = detection_suppressed(detection_id, entity_type, entity_value)
    if silenced.get("suppressed"):
        logger.info(
            f"{detection_id} not raised for {entity_value}: "
            f"{silenced.get('reason')}")
        return {"saved": False, "detection_id": detection_id,
                "reason": silenced.get("reason"),
                "suppression_id": silenced.get("suppression_id")}

    # A dismissal is honoured here too, because several sensors never asked.
    dismissed = dismissal_silences(detection_id, entity_type, entity_value,
                                   raw_data)
    if dismissed:
        logger.info(f"{detection_id} not raised for {entity_value}: "
                    f"{dismissed}")
        return {"saved": False, "detection_id": detection_id,
                "reason": dismissed, "suppression_id": None}

    with _get_conn() as conn:
        conn.execute("""
            INSERT INTO findings
                (session_id, source, severity, entity_type, entity_value,
                 title, description, raw_data, vpn_state, sensor_id,
                 detection_id, detection_rev)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            session_id, source, severity, entity_type, entity_value,
            title, description,
            json.dumps(raw_data) if raw_data else None,
            vpn_state, sensor_id or _local_sensor_id(),
            detection_id, rule.rev
        ))
    # Item 3.2. A finding raised and then quietly deleted is the most
    # valuable thing for an attacker to erase, so it is journaled first.
    # Outside the connection block: a journal failure must never roll back
    # or block the write it is recording.
    _journal("finding_saved", "findings", entity_value,
              {"source": source, "severity": severity, "title": title,
               "entity_type": entity_type, "detection_id": detection_id,
               "detection_rev": rule.rev})
    return {"saved": True, "detection_id": detection_id, "rev": rule.rev}


# PER-DETECTION SUPPRESSION, TODO 112
#
# The scalpel that dismiss_entity could never be. dismiss_entity is keyed on
# the entity, so silencing one chatty rule about a printer silences every rule
# about that printer, including the ones nobody has thought about yet.
#
# BOTH MECHANISMS STAY AND ARE CHECKED SEPARATELY. When something was not
# raised, the operator should be able to find out WHICH decision did it, and
# folding two different decisions into one flag destroys that answer.
#
# THE MODEL CANNOT CREATE ONE. Same call as expected ports in item 39: a tool
# that lets the model silence a detection is a tool for blinding this app, and
# the model already has documented trouble with evidence it invented. It can
# READ every suppression through query_detections, and it can argue for one in
# chat. A human clicks the button.

def detection_suppressed(detection_id: str, entity_type: str,
                         entity_value: str) -> dict:
    """
    Is this detection silenced for this entity right now?

    {"suppressed": bool, "reason": str|None, "suppression_id": int|None,
     "checked": bool}

    `checked` IS THE POINT OF THE DICT. If the table cannot be read, this
    returns suppressed False with checked False, which says "nothing is
    stopping this, and also I could not look". The caller still writes the
    finding, because failing open on a silencing check is the safe direction:
    the cost is a finding the operator has already asked not to see, and the
    alternative cost is silence nobody chose.
    """
    try:
        with _get_conn() as conn:
            row = conn.execute("""
                SELECT id, reason, entity_value FROM detection_suppression
                 WHERE detection_id = ?
                   AND (entity_type  = '*' OR entity_type  = ?)
                   AND (entity_value = '*' OR entity_value = ?)
                   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
                 ORDER BY CASE WHEN entity_value = '*' THEN 1 ELSE 0 END
                 LIMIT 1
            """, (detection_id, entity_type or "", entity_value or "")
            ).fetchone()
    except Exception as e:
        logger.warning(
            f"Could not read detection_suppression for {detection_id}: {e}. "
            f"Treating as not suppressed, which means this may be raised "
            f"despite a rule saying otherwise.")
        return {"suppressed": False, "reason": None, "suppression_id": None,
                "checked": False}

    if row is None:
        return {"suppressed": False, "reason": None, "suppression_id": None,
                "checked": True}

    scope = ("every entity" if row["entity_value"] == "*"
             else f"{entity_value}")
    return {
        "suppressed": True,
        "suppression_id": row["id"],
        "reason": f"suppressed for {scope}: {row['reason']}",
        "checked": True,
    }


def suppress_detection(detection_id: str, reason: str,
                       entity_type: str = "*", entity_value: str = "*",
                       created_by: str = "user",
                       expires_at: str = None) -> dict:
    """
    Stop one detection raising, optionally only for one entity.

    Never raises on a duplicate: re-suppressing an already suppressed pair
    updates the reason instead, because the operator's intent is the same
    either way and an error here would just make the button feel broken.

    created_by defaults to 'user' and 'model' is accepted by the column, not
    because the model may call this (no tool exposes it, deliberately) but so
    that if that decision is ever reversed the row can say who did it. A
    column that cannot record the answer forces the next person to add one.
    """
    from core import detections as det
    det.get(detection_id)                    # refuse ids that do not exist
    if not reason or not str(reason).strip():
        raise BadInput("A suppression needs a reason. This is the record of "
                       "why something stopped being reported.")
    if created_by not in ("user", "model"):
        raise BadInput(f"created_by must be 'user' or 'model', got "
                       f"{created_by!r}")

    et = entity_type or "*"
    ev = entity_value or "*"
    try:
        with _get_conn() as conn:
            cur = conn.execute("""
                INSERT INTO detection_suppression
                    (detection_id, entity_type, entity_value, reason,
                     created_by, expires_at)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(detection_id, entity_type, entity_value)
                DO UPDATE SET reason     = excluded.reason,
                              created_by = excluded.created_by,
                              created_at = CURRENT_TIMESTAMP,
                              expires_at = excluded.expires_at
            """, (detection_id, et, ev, reason, created_by, expires_at))
            sid = cur.lastrowid
            # The open alerts this covers are closed with it, or the page
            # shows them again on its next poll.
            where, args = _suppression_scope(detection_id, et, ev)
            closed = conn.execute(f"""
                UPDATE findings SET dismissed = 1,
                       dismissed_at = CURRENT_TIMESTAMP, dismissed_reason = ?
                 WHERE dismissed = 0 AND {where}
            """, [RULE_SILENCED_MARK + " " + reason] + args).rowcount or 0
    except Exception as e:
        logger.error(f"Could not suppress {detection_id}: {e}")
        return {"ok": False, "error": str(e)}

    _journal("detection_suppressed", "detection_suppression",
             f"{detection_id}:{et}:{ev}",
             {"reason": reason, "created_by": created_by,
              "expires_at": expires_at, "closed": closed})
    return {"ok": True, "id": sid, "detection_id": detection_id,
            "entity_type": et, "entity_value": ev, "closed": closed}


RULE_SILENCED_MARK = "rule silenced:"


def _suppression_scope(detection_id: str, et: str, ev: str):
    where, args = ["detection_id = ?"], [detection_id]
    if et != "*":
        where.append("entity_type = ?"); args.append(et)
    if ev != "*":
        where.append("entity_value = ?"); args.append(ev)
    return " AND ".join(where), args


def unsuppress_detection(detection_id: str, entity_type: str = "*",
                         entity_value: str = "*") -> dict:
    """
    Let a detection speak again. {"ok": bool, "removed": n}

    removed 0 is NOT an error and says so: it means no such rule was in place,
    which is a different sentence from "the rule was removed".
    """
    et = entity_type or "*"
    ev = entity_value or "*"
    try:
        with _get_conn() as conn:
            cur = conn.execute("""
                DELETE FROM detection_suppression
                 WHERE detection_id = ? AND entity_type = ?
                   AND entity_value = ?
            """, (detection_id, et, ev))
            removed = cur.rowcount or 0
            reopened = 0
            if removed:
                # Only the alerts the silencing closed come back.
                where, args = _suppression_scope(detection_id, et, ev)
                reopened = conn.execute(f"""
                    UPDATE findings SET dismissed = 0, dismissed_at = NULL,
                           dismissed_reason = NULL
                     WHERE dismissed = 1 AND dismissed_reason LIKE ?
                       AND {where}
                """, [RULE_SILENCED_MARK + "%"] + args).rowcount or 0
    except Exception as e:
        logger.error(f"Could not unsuppress {detection_id}: {e}")
        return {"ok": False, "removed": 0, "error": str(e)}

    if removed:
        _journal("detection_unsuppressed", "detection_suppression",
                 f"{detection_id}:{et}:{ev}", {"removed": removed})
    return {"ok": True, "removed": removed, "reopened": reopened,
            "note": (None if removed else
                     "No suppression was in place for that combination. "
                     "Nothing was removed and nothing was wrong.")}


def list_suppressions(include_expired: bool = False) -> list[dict]:
    """Every standing suppression, newest first."""
    where = ("" if include_expired else
             "WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP")
    try:
        with _get_conn() as conn:
            return _rows_to_dicts(conn.execute(f"""
                SELECT id, detection_id, entity_type, entity_value, reason,
                       created_by, created_at, expires_at
                  FROM detection_suppression
                  {where}
                 ORDER BY created_at DESC
            """).fetchall())
    except Exception as e:
        logger.warning(f"Could not list suppressions: {e}")
        return []


def detection_counts(since: str = None) -> dict:
    """
    How many findings each detection has raised, plus the unstamped rows.

    {"counts": {did: {...}}, "unstamped": n, "counted": bool}

    `unstamped` IS REPORTED SEPARATELY AND NEVER FOLDED INTO A TOTAL. Those
    are rows raised before detection ids existed. Showing a rule as "0
    findings" when it has been firing since August would be a lie told by a
    column that was added last week, so the page says how many rows predate
    the column instead of pretending they belong to nobody.

    `counted` false means the query failed, so the zeroes in here are "I could
    not look", not "nothing fired". Same distinction as everywhere else.
    """
    out = {"counts": {}, "unstamped": 0, "counted": False}
    clause, params = "", []
    if since:
        clause = "WHERE found_at >= ?"
        params = [_sql_datetime(since)]
    try:
        with _get_conn() as conn:
            rows = conn.execute(f"""
                SELECT detection_id,
                       COUNT(*)                                   AS total,
                       SUM(CASE WHEN dismissed = 0 THEN 1 ELSE 0 END) AS open,
                       MAX(found_at)                              AS last_seen,
                       MAX(detection_rev)                         AS last_rev
                  FROM findings
                  {clause}
                 GROUP BY detection_id
            """, params).fetchall()
    except Exception as e:
        logger.warning(f"Could not count findings by detection: {e}")
        return out

    for r in rows:
        if r["detection_id"] is None:
            out["unstamped"] = r["total"]
            continue
        out["counts"][r["detection_id"]] = {
            "total": r["total"],
            "open": r["open"],
            "last_seen": r["last_seen"],
            "last_rev": r["last_rev"],
        }
    out["counted"] = True
    return out


def detection_overview(since: str = None) -> dict:
    """
    The register joined to what it has actually done. For the page and the
    model's read-only tool, so both read one shape and cannot disagree.
    """
    from core import detections as det

    counts = detection_counts(since=since)
    supp: dict[str, list] = {}
    for s in list_suppressions():
        supp.setdefault(s["detection_id"], []).append(s)

    rows = []
    for d in det.summary():
        did = d["detection_id"]
        c = counts["counts"].get(did)
        rows.append({
            **d,
            "findings_total": (c or {}).get("total", 0),
            "findings_open": (c or {}).get("open", 0),
            "last_seen": (c or {}).get("last_seen"),
            "suppressions": supp.get(did, []),
            # Never let a failed count read as a real zero.
            "counted": counts["counted"],
        })
    return {
        "detections": rows,
        "unstamped_findings": counts["unstamped"],
        "unstamped_note": (
            "Findings raised before detections had ids. They are not missing "
            "and they are not unknown: nothing stamped them because nothing "
            "could. They are not counted against any rule."
        ),
        "counted": counts["counted"],
        "count_note": (None if counts["counted"] else
                       "The findings table could not be read, so every count "
                       "here is 'I could not look', not zero."),
    }

def query_endpoint_pairs(session_id: str = None, since: str = None) -> list[dict]:
    """
    Distinct (src_ip, dst_ip) pairs for a session with traffic totals.

    Exists because the threat map needs every endpoint of a session, and
    query_packets is capped at MAX_QUERY_LIMIT (500) rows, which on a live
    sniffer is a few seconds of traffic, not a session. Aggregating in SQL
    returns one row per conversation instead of one per packet, so the whole
    session fits comfortably and the map stops depending on how chatty the
    last half-minute happened to be.

    No LIMIT here on purpose: the result is bounded by the number of
    distinct peers, which on a home network is dozens, not thousands.
    """
    conditions, params = [], []
    if session_id:
        conditions.append("session_id = ?")
        params.append(session_id)
    if since:
        conditions.append("captured_at >= ?")
        params.append(_sql_datetime(since))

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"""
        SELECT
            src_ip,
            dst_ip,
            COUNT(*)                            AS packets,
            COALESCE(SUM(packet_size), 0)       AS bytes,
            MIN(captured_at)                    AS first_seen,
            MAX(captured_at)                    AS last_seen,
            GROUP_CONCAT(DISTINCT dst_port)     AS ports,
            GROUP_CONCAT(DISTINCT protocol)     AS protocols,
            GROUP_CONCAT(DISTINCT threat_label) AS threat_labels
        FROM packets
        {where}
        GROUP BY src_ip, dst_ip
        ORDER BY packets DESC
    """
    with _get_conn() as conn:
        return _rows_to_dicts(conn.execute(sql, params).fetchall())


VALID_PORT_STATE = {"open", "closed", "filtered"}

# Deliberately NOT VALID_SEVERITY. That set includes 'info', which the
# port_scan_results CHECK constraint rejects, and it lacks 'none', which the
# constraint allows. Mirroring the schema exactly keeps the failure at the
# call site instead of surfacing as an IntegrityError later.
VALID_PORT_RISK = {"critical", "high", "medium", "low", "none"}


VALID_SCAN_ORIGIN = {"self", "remote"}

# v34, 2026-09-15. A port row has to say which protocol it is about.
#
# Only 'tcp' is ever written today because the connect scanner is the only
# prober in the codebase. 'udp' is allowed here so that the day a UDP prober
# lands it does not need a schema change, and so that nothing can quietly
# write a third value that readers would have to interpret.
VALID_PORT_PROTOCOL = {"tcp", "udp"}


def start_port_scan_run(session_id: str, target_host: str,
                        port_count: int = None, port_set: str = None,
                        scan_origin: str = "remote",
                        sensor_id: str = None,
                        protocols: str = "tcp") -> int | None:
    """
    Record that a scan STARTED. Returns the run id, or None if it could not.

    Called by the port scanner before it sends anything. The run is written up
    front rather than at the end so that a scan which crashes, hangs or is
    killed still leaves the window that explains its traffic. A scan recorded
    only on success would leave exactly the crashed runs unexplained, and a
    crashed scan still put packets on the wire.

    Never raises. A scan must not fail because its bookkeeping did, but it is
    logged rather than swallowed: without this row the packets it causes come
    back self_induced false, which reads as "the device did this".

    `protocols` says what this run actually probed, comma separated. It is
    recorded so that a run can never be quoted as evidence about a protocol it
    never sent a packet on.
    """
    try:
        with _get_conn() as conn:
            cur = conn.execute("""
                INSERT INTO port_scan_run
                    (session_id, target_host, started_at, port_count,
                     port_set, protocols, scan_origin, sensor_id)
                VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?)
            """, (session_id, target_host, port_count, port_set,
                  protocols or "tcp", scan_origin,
                  sensor_id or _local_sensor_id()))
            return cur.lastrowid
    except Exception as e:
        logger.error(
            f"Could not record the start of the port scan of {target_host}: "
            f"{e}. Packets it causes will not be marked self_induced.")
        return None


def finish_port_scan_run(run_id: int | None, port_count: int = None):
    """
    Close the window. A NULL finished_at is handled by the reader.

    port_count corrects the probe count when the run sent more than it
    planned, as a SYN pass that fell back to connect does (PS-27).
    """
    if not run_id:
        return
    try:
        with _get_conn() as conn:
            if port_count is None:
                conn.execute(
                    "UPDATE port_scan_run SET finished_at = CURRENT_TIMESTAMP "
                    "WHERE id = ?", (run_id,))
            else:
                conn.execute(
                    "UPDATE port_scan_run SET finished_at = CURRENT_TIMESTAMP, "
                    "port_count = ? WHERE id = ?", (int(port_count), run_id))
    except Exception as e:
        logger.error(f"Could not close port scan run {run_id}: {e}")


def save_port_scan_result(session_id: str, target_host: str, port: int,
                          state: str = "open", service_guess: str = None,
                          banner: str = None, risk_level: str = "low",
                          service_note: str = None,
                          scan_origin: str = "remote",
                          sensor_id: str = None,
                          protocol: str = "tcp"):
    """
    Persist one port scan result. Called by tools/port_scanner.py.

    This function was referenced by port_scanner but never existed. The call
    site imported it inside a `try: ... except Exception: pass`, so the
    resulting ImportError was swallowed on every scan and NOTHING was ever
    written to port_scan_results, the table the Ports tab reads. Findings
    were still saved, so scans looked like they half-worked: alerts appeared,
    the Ports tab stayed permanently empty.

    Both CHECK constraints are validated here rather than left to SQLite, so
    a bad value fails at the call site with a readable message instead of as
    an IntegrityError from three frames down.

    protocol defaults to 'tcp' because the connect scanner is the only caller
    and TCP is all it speaks. The default is here rather than implied so that
    a UDP prober has to pass 'udp' deliberately and cannot inherit the wrong
    label by forgetting an argument.
    """
    if state not in VALID_PORT_STATE:
        raise BadInput(f"Invalid port state '{state}'")
    if risk_level not in VALID_PORT_RISK:
        raise BadInput(f"Invalid risk_level '{risk_level}'")
    if scan_origin not in VALID_SCAN_ORIGIN:
        raise BadInput(f"Invalid scan_origin '{scan_origin}'")
    if protocol not in VALID_PORT_PROTOCOL:
        raise BadInput(
            f"Invalid protocol '{protocol}'. A port row must say which "
            f"protocol it is about: {sorted(VALID_PORT_PROTOCOL)}")

    with _get_conn() as conn:
        conn.execute("""
            INSERT INTO port_scan_results
                (session_id, target_host, port, state, service_guess,
                 banner, service_note, risk_level, scan_origin, sensor_id,
                 protocol)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            session_id, target_host, int(port), state,
            service_guess, banner, service_note, risk_level, scan_origin,
            sensor_id or _local_sensor_id(), protocol
        ))


def save_event(session_id: str, source: str, event_id: str,
               event_type: str, severity: str = "info",
               username: str = None, src_ip: str = None,
               process_name: str = None, description: str = None,
               raw_data: dict = None, vpn_state: str = "unknown",
               sensor_id: str = None, source_record_id: int = None):
    """
    Called by event_monitor.py only.

    source_record_id is the id the SOURCE gave the record, and passing it
    makes this write idempotent. v21, 2026-08-31.

    WHY, because the reason is not obvious from here. EventMonitor refuses to
    advance its high-water mark when a burst caps a pass, so that nothing
    unread is ever claimed as read. That is the right call: a skipped 4720 is
    gone forever and a re-read one is not. The price is that the newest
    records are read again on the following poll, and they were being STORED
    again as well. Nobody notices duplicate rows directly; they notice a
    baseline built on counts that are too high.

    ON CONFLICT names the two columns rather than using INSERT OR IGNORE,
    which would also swallow a bad severity or a missing session_id. A write
    that silently drops rows for reasons nobody chose is worse than the
    duplicate it was meant to fix.

    A caller that passes nothing keeps the old behaviour exactly: NULLs are
    distinct in a SQLite unique index, so every row still lands.
    """
    with _get_conn() as conn:
        conn.execute("""
            INSERT INTO events
                (session_id, source, event_id, event_type, severity,
                 username, src_ip, process_name, description, raw_data,
                 vpn_state, sensor_id, source_record_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(source, source_record_id) DO NOTHING
        """, (
            session_id, source, event_id, event_type, severity,
            username, src_ip, process_name, description,
            json.dumps(raw_data) if raw_data else None,
            vpn_state, sensor_id or _local_sensor_id(), source_record_id
        ))


def save_pcap_result(session_id: str, file_path: str, packet_count: int,
                     duration_seconds: float, result_json: dict,
                     sensor_id: str = None):
    """
    Called by pcap tool after analysis. Model writes model_assessment
    separately.

    sensor_id, 2026-08-31. The column has been on this table since the vantage
    work and nothing ever filled it, so every imported capture sat in the
    database with NO position at all. That is the worst of the three possible
    states: a row with a bad position is arguable, a row with a position is
    readable, and a row with none reads exactly like a row nobody needs to
    think about.

    Deliberately NOT defaulting to the local sensor the way save_event and
    save_packet do. This host did not observe an imported file, and stamping
    it with the host sensor would tell the model the capture has this
    machine's reach, which is the specific mistake that makes an absence in
    somebody else's capture look like a fact about this network.
    """
    with _get_conn() as conn:
        cursor = conn.execute("""
            INSERT INTO pcap_results
                (session_id, file_path, packet_count, duration_seconds,
                 result_json, sensor_id)
            VALUES (?,?,?,?,?,?)
        """, (session_id, file_path, packet_count, duration_seconds,
              json.dumps(result_json), sensor_id))
        return cursor.lastrowid


def save_pcap_assessment(pcap_result_id: int, model_assessment: str) -> dict:
    """
    The model writes its reading of a PCAP result here.

    WIRED UP 2026-09-03, and it is worth recording why it needed to be. This
    was written when the pcap table was, and then nothing ever called it. No
    tool, no route, no UI. So the column existed, was documented, and was
    never once written to, and every capture analysis was thrown away the
    moment the conversation moved on. The next session started again from the
    same raw numbers with no idea anyone had already looked.

    It returns a result now instead of None. A write that reports nothing
    cannot tell you it matched no row, and "saved" about a row that does not
    exist is exactly the sort of quiet lie the rest of this file is built to
    avoid.
    """
    text = (model_assessment or "").strip()
    if not text:
        raise BadInput("model_assessment cannot be empty")

    with _get_conn() as conn:
        cur = conn.execute(
            "UPDATE pcap_results SET model_assessment=? WHERE id=?",
            (text, pcap_result_id)
        )
        if cur.rowcount == 0:
            return {
                "success": False,
                "pcap_result_id": pcap_result_id,
                "error": (f"No pcap_results row has id {pcap_result_id}. That "
                          f"id comes back as 'pcap_result_id' from "
                          f"run_pcap_analysis. Nothing was written."),
            }

    return {
        "success": True,
        "pcap_result_id": pcap_result_id,
        "chars": len(text),
        "note": ("Stored. query_pcap_results returns it alongside the row, so "
                 "a later session reads your conclusion instead of deriving "
                 "it again from the same numbers."),
    }


# SILENCE TIMER, called by background thread every 2 minutes

def get_silent_deviations() -> list[dict]:
    """
    Return deviations that were alerted but never responded to,
    and whose silence_timeout has elapsed. Rollup engine resolves these.

    Note: this returns critical/high rows too. The rollup engine needs to
    see them in order to mark them 'unreviewed' and surface them in the
    review queue, it just must not baseline them. Filtering here would
    leave them stuck in the alerted state forever.
    """
    with _get_conn() as conn:
        rows = conn.execute("""
            SELECT * FROM behavioral_deviation
            WHERE user_responded = 0
              AND resolved_as IS NULL
              AND alerted_at IS NOT NULL
              AND datetime(alerted_at, '+' || silence_timeout_seconds || ' seconds')
                  <= datetime('now')
            ORDER BY alerted_at ASC
        """).fetchall()
        return _rows_to_dicts(rows)


# BASELINE SESSION ACCOUNTING
#
# Schema documents confidence in SESSIONS (the tier boundaries live in the
# confidence_session_thresholds preference; high defaults to 6) but the
# old rollup incremented sample_count by observation count. With a 120s
# poll loop one entity could clear the 'high' threshold, and therefore
# alert_suppressed, inside a single session.
#
# baseline_session_seen records the distinct sessions in which an entity /
# behavior_key was actually observed. sample_count is derived from it.

def record_baseline_session(entity_type: str, entity_value: str,
                            behavior_key: str, session_id: str) -> int:
    """
    Mark this (entity, behavior_key) as seen in this session and return the
    resulting distinct session count. Idempotent within a session.
    """
    with _get_conn() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO baseline_session_seen
                (entity_type, entity_value, behavior_key, session_id)
            VALUES (?,?,?,?)
        """, (entity_type, entity_value, behavior_key, session_id))

        # SEEING IT AGAIN UN-RETRACTS THIS SESSION'S ROW. v29, TODO 93.
        #
        # INSERT OR IGNORE does nothing when the row already exists, and after
        # a retraction the existing row is stamped. So without this, a session
        # that was open across the retraction would stay stamped forever and
        # its later observations would never count toward the rebuild. The
        # retraction is meant to reset the count, not to blacklist a session.
        ready = _retract_ready(conn)
        if ready:
            conn.execute("""
                UPDATE baseline_session_seen SET retracted_at = NULL
                WHERE entity_type=? AND entity_value=? AND behavior_key=?
                  AND session_id=? AND retracted_at IS NOT NULL
            """, (entity_type, entity_value, behavior_key, session_id))

        extra = " AND retracted_at IS NULL" if ready else ""
        row = conn.execute(f"""
            SELECT COUNT(*) AS n FROM baseline_session_seen
            WHERE entity_type=? AND entity_value=? AND behavior_key=?{extra}
        """, (entity_type, entity_value, behavior_key)).fetchone()
        return int(row["n"]) if row else 1


_RETRACT_COLUMNS = None          # None = not looked yet


def _retract_ready(conn) -> bool:
    """
    Does this database have the v29 retract columns yet?

    MY BUG, 2026-09-13, and it was worse than the crash it caused. I added
    "AND retracted_at IS NULL" to the session count, and
    query_behavioral_baseline calls that count on EVERY row. So on a database
    that had not taken the v29 migration, every baseline read raised
    OperationalError: no such column. The owner hit it on the first thing the owner ran.

    The app migrates at boot so the app itself was fine, but any script
    against a not-yet-migrated file blew up, and "run the app first" is not an
    answer a tool should make somebody guess. Checked once and remembered,
    because this is a schema fact and it cannot change while the process runs
    except by a migration that restarts nothing.
    """
    global _RETRACT_COLUMNS
    if _RETRACT_COLUMNS is None:
        try:
            cols = {r[1] for r in
                    conn.execute("PRAGMA table_info(baseline_session_seen)")}
            _RETRACT_COLUMNS = "retracted_at" in cols
        except sqlite3.OperationalError:
            _RETRACT_COLUMNS = False
    return _RETRACT_COLUMNS


def count_baseline_sessions(entity_type: str, entity_value: str,
                            behavior_key: str) -> int:
    """
    Distinct sessions in which this behavior has been observed.

    Retracted rows are not counted, see retract_baseline. They are still
    there, they just stop feeding a belief that was withdrawn.

    On a pre-v29 database nothing can have been retracted, so counting
    everything IS the right answer there rather than a fallback that quietly
    means something else.
    """
    with _get_conn() as conn:
        extra = " AND retracted_at IS NULL" if _retract_ready(conn) else ""
        row = conn.execute(f"""
            SELECT COUNT(*) AS n FROM baseline_session_seen
            WHERE entity_type=? AND entity_value=? AND behavior_key=?{extra}
        """, (entity_type, entity_value, behavior_key)).fetchone()
        return int(row["n"]) if row else 0


def retract_baseline(entity_type: str, entity_value: str,
                     behavior_key: str, reason: str) -> dict:
    """
    Withdraw what a baseline LEARNED. TODO 93, 2026-09-13.

    THE GAP THIS CLOSES, from 45.5. supersede_observation withdraws a session
    observation, but run_rollup reads current observations only, so the
    withdrawal keeps that row out of FUTURE merges and does nothing about the
    baseline that already ate it. behavioral_baseline is cumulative and
    forward only. Until now you could retract the sentence and not the belief
    it produced.

    WHAT WAS ALREADY FINE. revert_suppression exists, is ungated, and backs
    the Review dashboard, so the dangerous half, a baseline SILENCING alerts,
    was always undoable. This is the other half: the numbers.

    WHAT THIS DOES

      * clears the learned content, mean, stddev, min, max, typical hours,
        ports and ips, and the model's notes
      * clears suppression and flagged_as_normal, and drops confidence to low,
        because a withdrawn baseline must not keep silencing anything
      * stamps the row with when and why, keeping it, because a deleted row
        cannot tell a later reader what was believed
      * stamps the session-seen rows so the count restarts honestly

    THE SESSION COUNT IS THE SUBTLE HALF and getting it wrong would have made
    this look like it worked. sample_count is DERIVED from
    baseline_session_seen. Clear the baseline row alone and the count survives
    untouched, so the very next observation comes straight back at the old
    confidence as if nothing had been withdrawn. The seen rows are stamped,
    not deleted: the audit of which session saw what is kept, it simply stops
    counting toward a belief that was pulled.

    A reason is required, same rule as supersede_observation. A retraction
    with no explanation is indistinguishable from tampering, and the whole
    point of keeping the row is that somebody can read why.

    behavior_key=None retracts every key for the entity, which is what a
    person means by "forget what you learned about this device".
    """
    _validate_entity(entity_type, entity_value)
    basis = (reason or "").strip()
    if not basis:
        return {"success": False,
                "error": ("reason is required. State what was wrong and how "
                          "it is known.")}

    conditions = ["entity_type = ?", "entity_value = ?"]
    params = [entity_type, entity_value]
    if behavior_key:
        conditions.append("behavior_key = ?")
        params.append(behavior_key)
    where = " AND ".join(conditions)

    with _get_conn() as conn:
        # A RETRACT ON A PRE-v29 DATABASE MUST REFUSE, not half-apply. The
        # UPDATE below would throw partway and leave the numbers cleared with
        # no record of why, which is the worst of both. Says what to run.
        if not _retract_ready(conn):
            return {"success": False,
                    "error": ("This database has not been migrated to schema "
                              "v29 yet, so a baseline cannot be withdrawn. "
                              "Start AgentalSec once (python main.py) to apply "
                              "it, or run core.migrations.run_migrations "
                              "directly.")}

        cur = conn.execute(f"""
            UPDATE behavioral_baseline SET
                value_mean = NULL, value_stddev = NULL,
                value_min = NULL, value_max = NULL,
                typical_hours = NULL, typical_dest_ports = NULL,
                typical_dest_ips = NULL, beacon_detail = NULL,
                model_notes = NULL,
                sample_count = 0,
                confidence = 'low',
                flagged_as_normal = 0,
                alert_suppressed = 0,
                retracted_at = CURRENT_TIMESTAMP,
                retracted_reason = ?,
                last_updated = CURRENT_TIMESTAMP
            WHERE {where}
        """, [basis] + params)
        retracted = cur.rowcount

        seen = conn.execute(f"""
            UPDATE baseline_session_seen
            SET retracted_at = CURRENT_TIMESTAMP
            WHERE {where} AND retracted_at IS NULL
        """, params)
        sessions_cleared = seen.rowcount

    # Journalled outside the connection block, same as supersede_observation.
    # A journal failure must never roll back the write it is recording.
    _journal("baseline_retracted", "behavioral_baseline", entity_value,
             {"reason": basis[:200], "behavior_key": behavior_key,
              "entity_type": entity_type, "rows": retracted,
              "sessions_cleared": sessions_cleared,
              "via": "retract_baseline"})

    logger.info(f"Baseline retracted for {entity_type} {entity_value} "
                f"{behavior_key or '(all keys)'}: {basis[:80]}")
    return {
        "success": True,
        "entity_type": entity_type,
        "entity_value": entity_value,
        "behavior_key": behavior_key,
        "retracted": retracted,
        "sessions_cleared": sessions_cleared,
        "reason": basis,
        "note": ("The learned numbers are gone and the session count restarts "
                 "from zero. The row is kept, carrying the reason. Anything "
                 "observed from here on rebuilds it from scratch."),
    }


# SUPPRESSION AUDIT + UNDO
#
# alert_suppressed = 1 means the agent has stopped reporting an entity
# entirely. That is the single most consequential state in the database and
# it used to be invisible. These functions back the Review dashboard.

def query_suppressed_baselines(limit: int = 200, with_total: bool = False):
    """
    Every baseline currently suppressing alerts, newest first.

    with_total=True adds the exact matching count and whether this is all of
    them. TODO 94.8. This one is worth having: a suppression list that is
    quietly cut off understates how much of the machine is being silenced.
    """
    limit = _validate_limit(limit)
    with _get_conn() as conn:
        rows = conn.execute("""
            SELECT b.*,
                   (SELECT COUNT(*) FROM baseline_session_seen s
                     WHERE s.entity_type  = b.entity_type
                       AND s.entity_value = b.entity_value
                       AND s.behavior_key = b.behavior_key) AS distinct_sessions
            FROM behavioral_baseline b
            WHERE b.alert_suppressed = 1
            ORDER BY b.last_updated DESC
            LIMIT ?
        """, (limit,)).fetchall()
        out = _rows_to_dicts(rows)
        if not with_total:
            return out
        return _with_total(conn, out, "behavioral_baseline b",
                           "WHERE b.alert_suppressed = 1", [], limit,
                           "suppressing_baselines")


def revert_suppression(entity_type: str, entity_value: str,
                       behavior_key: str = None,
                       reset_confidence: bool = True) -> dict:
    """
    Undo a suppression. Alerts resume immediately.

    behavior_key=None reverts every suppressed key for the entity, which is
    what the dashboard's per-row button uses when the row is an entity roll-up.
    """
    _validate_entity(entity_type, entity_value)

    sets = ["alert_suppressed = 0", "flagged_as_normal = 0",
            "last_updated = CURRENT_TIMESTAMP"]
    if reset_confidence:
        sets.append("confidence = 'low'")

    conditions = ["entity_type = ?", "entity_value = ?"]
    params = [entity_type, entity_value]
    if behavior_key:
        conditions.append("behavior_key = ?")
        params.append(behavior_key)

    with _get_conn() as conn:
        cur = conn.execute(
            f"UPDATE behavioral_baseline SET {', '.join(sets)} "
            f"WHERE {' AND '.join(conditions)}",
            params
        )
        return {
            "success": True,
            "reverted": cur.rowcount,
            "entity_type": entity_type,
            "entity_value": entity_value,
            "behavior_key": behavior_key,
        }


def query_review_queue(limit: int = 100, include_all: bool = False,
                       with_total: bool = False):
    """
    Deviations the silence timer closed as 'unreviewed', nobody looked at
    these. By default only severities the silence floor protects
    (critical/high) are returned, since those are the ones that matter.
    """
    limit = _validate_limit(limit)
    # Built as one where string so the count below asks the same question.
    # TODO 94.6.
    #
    # A MODEL RESOLUTION IS A RECOMMENDATION, NOT A CLOSURE. TODO 98,
    # 2026-09-14. The model can resolve a deviation, and before today that
    # took the row off this queue and out of get_silent_deviations at the same
    # time, with nothing recording that a model rather than a person had
    # decided. Now it stays here until a human answers it.
    #
    # Guarded because the column arrives with v30 and this read runs against
    # databases that have not migrated yet. Pre-v30 nothing can be marked
    # model-resolved, so the old where IS the right answer there.
    with _get_conn() as _probe:
        _has_resolved_by = _resolved_by_ready(_probe)
    if _has_resolved_by:
        where = ("WHERE (resolved_as = 'unreviewed' "
                 "OR (resolved_by = 'model' AND user_responded = 0))")
    else:
        where = "WHERE resolved_as = 'unreviewed'"
    if not include_all:
        where += " AND severity IN ('critical','high')"
    sql = (f"SELECT * FROM behavioral_deviation {where} "
           f"ORDER BY detected_at DESC LIMIT ?")

    with _get_conn() as conn:
        rows = _rows_to_dicts(conn.execute(sql, (limit,)).fetchall())
        if not with_total:
            return rows
        return _with_total(conn, rows, "behavioral_deviation", where, [],
                           limit, "awaiting_review")


# ROLLUP LOG

def log_rollup(session_id: str, trigger_reason: str,
               entities_processed: int, baselines_updated: int,
               baselines_created: int, duration_ms: int, notes: str = None):
    """Log a completed rollup operation."""
    with _get_conn() as conn:
        conn.execute("""
            INSERT INTO rollup_log
                (session_id, trigger_reason, entities_processed,
                 baselines_updated, baselines_created, duration_ms, notes)
            VALUES (?,?,?,?,?,?,?)
        """, (session_id, trigger_reason, entities_processed,
              baselines_updated, baselines_created, duration_ms, notes))


def get_last_rollup(session_id: str = None) -> dict | None:
    """Get the most recent rollup record."""
    with _get_conn() as conn:
        if session_id:
            row = conn.execute(
                "SELECT * FROM rollup_log WHERE session_id=? ORDER BY rolled_at DESC LIMIT 1",
                (session_id,)
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM rollup_log ORDER BY rolled_at DESC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None


# SESSION LOG

def log_message(session_id: str, role: str, content: str, token_count: int = None):
    """
    Log a chat message. Trigger in DB caps at 500 per session.

    SEALED AS OF 2026-09-23. This is the record of what was SAID TO THE MODEL
    and what it said back — the prompts and the answers, in the owner's own
    list of what "the agent's own record" means. Nothing sealed it, so a root
    user could rewrite an assistant turn or delete a prompt and the chain
    would still verify.

    The row is sealed in the same transaction as the insert, so the message
    and its witness land together. Returns the row id now (it returned None
    before), because a caller may want it and a function that has the value
    should not throw it away.

    THE 500-ROW TRIM IS NOT TAMPERING, and core/integrity knows: it carries
    the rule and reports an old row's disappearance as "consistent with the
    trim" rather than as a deletion. That is the whole reason the check
    exists rather than an excuse to skip sealing this table.
    """
    try:
        from core import integrity
    except Exception as e:                          # noqa: BLE001
        integrity = None
        logger.error(f"integrity module unavailable, chat messages will not "
                     f"be sealed: {e}")

    with _get_conn() as conn:
        cur = conn.execute("""
            INSERT INTO session_log (session_id, role, content, token_count)
            VALUES (?,?,?,?)
        """, (session_id, role, content, token_count))
        row_id = cur.lastrowid
        if integrity is not None and row_id:
            integrity.seal_row("session_log", row_id, conn=conn)
    return row_id


# DISMISSED FINDINGS, write (Python and model can call this)

# BLINDING CEILING
#
# Item 2.1, built 2026-08-29. The threat model names blinding as the valuable
# attack: an injection that persuades the model to stop looking at something.
# The permission gate and the untrusted fence both already exist and are good,
# but they are per-call. Nothing limited how MANY entities could be blinded,
# so a single successful persuasion could sweep the network in one sitting.
#
# The ceiling does not try to tell a good dismissal from a bad one, it
# cannot, and pretending otherwise is how a control becomes theatre. It makes
# volume expensive. One dismissal is routine. Twenty in an afternoon is a
# different event, and it now has to be noticed and re-authorised rather than
# happening quietly.
#
# The window is rolling, not calendar-daily: a midnight boundary is a free
# reset for anyone who waits for it.
BLINDING_WINDOW_HOURS = 24
BLINDING_CEILING      = 10   # model-initiated blinding acts per rolling window


class BlindingCeilingReached(Exception):
    """Refusal: too many entities blinded inside the rolling window."""


def blinding_budget() -> dict:
    """
    How much of the blinding ceiling has been spent, and by whom.

    Counted from the rows themselves rather than from a separate counter,
    so the number cannot drift from what actually happened, and so it
    survives a restart without any bookkeeping.

    USER actions are counted and reported but never refused. A person
    silencing their own monitor is making a choice about their own network;
    the ceiling exists to stop the MODEL being talked into it at scale. That
    asymmetry is the same one the rest of this file keeps: reversal is free,
    suppression is expensive, and a human may always overrule.
    """
    since = f"-{BLINDING_WINDOW_HOURS} hours"
    with _get_readonly_conn() as conn:
        by_model = conn.execute(
            "SELECT COUNT(*) FROM dismissed_findings "
            "WHERE dismissed_by = 'model' AND dismissed_at >= datetime('now', ?)",
            (since,)).fetchone()[0]
        by_user = conn.execute(
            "SELECT COUNT(*) FROM dismissed_findings "
            "WHERE dismissed_by != 'model' AND dismissed_at >= datetime('now', ?)",
            (since,)).fetchone()[0]
        suppressed = conn.execute(
            "SELECT COUNT(*) FROM behavioral_baseline "
            "WHERE alert_suppressed = 1 AND last_updated >= datetime('now', ?)",
            (since,)).fetchone()[0]

    # Only MODEL dismissals count against the ceiling. Suppressions are
    # reported beside it, not folded into it: suppression already requires
    # explicit user approval, enforced by tool_registry.
    # suppression_is_requested and the permission card, and letting a
    # user-approved act consume the model's budget would mean a person tidying
    # their own baseline could lock the model out of a legitimate dismissal.
    # Visible, not chargeable.
    #
    # This comment cited a 'suppression_requires_user' preference until
    # 2026-08-29. The conclusion was right and the citation was not: that row
    # was read by no code path and was deleted in schema v18. Naming the wrong
    # mechanism is how a real guarantee gets attributed to a dead one, and
    # then removed by someone tidying up.
    spent = by_model
    return {
        "window_hours":      BLINDING_WINDOW_HOURS,
        "ceiling":           BLINDING_CEILING,
        "spent_by_model":    spent,
        "dismissals_model":  by_model,
        "suppressions":      suppressed,
        "dismissals_user":   by_user,
        "remaining":         max(0, BLINDING_CEILING - spent),
        "at_ceiling":        spent >= BLINDING_CEILING,
        "note": (f"{spent} of {BLINDING_CEILING} model dismissals used in the "
                 f"last {BLINDING_WINDOW_HOURS}h. Shown alongside, and NOT "
                 f"charged against the ceiling: {by_user} user dismissal(s) "
                 f"and {suppressed} baseline suppression(s), which already "
                 f"require explicit approval of their own."),
    }


def _spend_blinding_budget(actor: str):
    """
    Refuse a model-initiated blinding act once the window is full.

    Raises rather than returning a flag, so a caller cannot proceed by
    ignoring a return value, the same reasoning as item 1.8, one call
    above in this evening's list.
    """
    if actor == "user":
        return
    budget = blinding_budget()
    if budget["at_ceiling"]:
        raise BlindingCeilingReached(
            f"{budget['spent_by_model']} blinding actions already in the last "
            f"{BLINDING_WINDOW_HOURS}h, ceiling is {BLINDING_CEILING}. This is "
            f"a volume limit, not a judgement about this particular entity. A "
            f"user can still dismiss it, and the ceiling frees up as the "
            f"window rolls."
        )


def expected_ports(ip: str) -> dict:
    """
    Ports the owner has declared normal for this device. {} if none.

    Keyed by port as a string, each value carrying when it was declared, by
    whom and why. Read by the port scanner before it raises a finding, and by
    the model as an ordinary column on the device row.
    """
    try:
        with _get_readonly_conn() as conn:
            row = conn.execute(
                "SELECT expected_ports FROM known_devices WHERE ip = ?",
                (ip,)).fetchone()
        if not row or not row[0]:
            return {}
        found = json.loads(row[0])
        return found if isinstance(found, dict) else {}
    except Exception as e:
        # An unreadable declaration must not silence anything. Failing to
        # suppress produces a noisy finding; failing the other way hides one.
        logger.warning(f"Could not read expected_ports for {ip}: {e}")
        return {}


def is_port_expected(ip: str, port: int) -> dict | None:
    """The declaration for this port on this device, or None."""
    return expected_ports(ip).get(str(port))


def declare_expected_port(ip: str, port: int, reason: str,
                          declared_by: str = "user",
                          clear_existing: bool = True) -> dict:
    """
    Record that a port is normal on a device. NOT A MODEL TOOL, on purpose.

    There is no entry for this in the tool manifest and there should not be
    one. A model that can mark its own findings expected has a path to
    silencing itself, which is 8.1F one layer up. The owner declares this,
    through scripts/expect_port.py.

    A reason is required rather than optional. The whole value of this column
    is that six months from now somebody can read why a port stopped raising,
    and "no reason given" is how a safety mechanism becomes a mystery.

    It silences the FINDING, not the observation. The port still lands in
    port_scan_results, still shows on the device row, and any OTHER port on
    the same device still raises normally. That is the rule the owner set for
    the safe list on 2026-08-31.
    """
    if not reason or not str(reason).strip():
        raise BadInput(
            "A reason is required. A port that stopped raising findings with "
            "no recorded why is worse than one that never raised.")

    with _get_conn() as conn:
        row = conn.execute(
            "SELECT expected_ports FROM known_devices WHERE ip = ?",
            (ip,)).fetchone()
        if row is None:
            raise BadInput(
                f"{ip} is not in the inventory. Identify the device first: "
                f"saying which of its ports are normal only means something "
                f"once somebody has said what it is.")

        current = {}
        if row[0]:
            try:
                current = json.loads(row[0]) or {}
            except Exception:
                current = {}

        current[str(port)] = {
            "declared_at": datetime.now(timezone.utc).isoformat(),
            "declared_by": declared_by,
            "reason": str(reason).strip(),
        }
        conn.execute(
            "UPDATE known_devices SET expected_ports = ? WHERE ip = ?",
            (json.dumps(current), ip))

    _journal("port_expectation_declared", "known_devices", f"{ip}:{port}",
             {"reason": reason, "by": declared_by})

    entry = dict(current[str(port)])

    # TODO 39.5, 2026-09-04. Declaring used to stop FUTURE scans raising and
    # leave the ones already raised sitting in the review queue, so the owner
    # answered the question and the question stayed on screen. That is the
    # unread queue arriving by a different road, which is the exact failure
    # 39 was built to stop, so the declaration now clears its own backlog.
    if clear_existing:
        entry["cleared"] = clear_port_findings(
            ip, port, reason=f"Declared expected: {str(reason).strip()}",
            cleared_by=declared_by)
    return entry


def clear_port_findings(ip: str, port: int, reason: str,
                        cleared_by: str = "user") -> dict:
    """
    Retire the port findings already raised for ONE port on ONE device.

    {"count": n, "ids": [...]}. Never raises; a clear that fails must not take
    the declaration down with it.

    THIS IS NARROWER THAN dismiss_entity AND THAT IS THE WHOLE POINT.
    dismiss_entity is keyed on the entity, and a port finding's entity is the
    PORT NUMBER, so dismissing it would silence 8888 on every device on the
    network, forever, including one that has no business running anything
    there. This marks specific rows that have already been raised, for one
    address, and changes nothing about what raises next.

    WHY IT DOES NOT SPEND THE BLINDING BUDGET. The budget exists to make the
    MODEL work repeatedly and visibly to blind this tool, and _spend_blinding_
    budget returns immediately for a user actor anyway. This path is not
    reachable by the model at all: there is no tool for declaring an expected
    port, on purpose, per 39. It is still a silencing act, so it is journaled
    with the reason and the rows keep their dismissed_reason, which is what
    makes it reconstructable later.

    MATCHING, and the fallback is the interesting half. New findings carry the
    host in raw_data. Every finding written before 2026-09-04 does not, so the
    only record of which device it was about is the title, which reads
    "... listening on <host>:<port>" with the operator's own address in it.
    Matching that string is ugly and it is honest: the alternative is telling
    the owner their old findings cannot be cleared because of a column we
    forgot to write.
    """
    needle = f"{ip}:{port}"
    cleared = []
    try:
        with _get_conn() as conn:
            rows = conn.execute(
                """SELECT id, raw_data, title FROM findings
                    WHERE entity_type = 'port' AND entity_value = ?
                      AND dismissed = 0""",
                (str(port),)).fetchall()

            for row in rows:
                host = None
                try:
                    host = (json.loads(row["raw_data"] or "{}") or {}).get("host")
                except (ValueError, TypeError):
                    host = None
                # Structured first, prose only as the fallback for old rows.
                if host is not None:
                    if host != ip:
                        continue
                elif needle not in (row["title"] or ""):
                    continue
                cleared.append(row["id"])

            if cleared:
                marks = ",".join("?" * len(cleared))
                conn.execute(
                    f"""UPDATE findings
                           SET dismissed = 1,
                               dismissed_at = CURRENT_TIMESTAMP,
                               dismissed_reason = ?
                         WHERE id IN ({marks})""",
                    [reason] + cleared)
    except Exception as e:
        logger.warning(f"Could not clear port findings for {needle}: {e}")
        return {"count": 0, "ids": [], "error": str(e)}

    if cleared:
        _journal("port_findings_cleared", "findings", needle,
                 {"count": len(cleared), "ids": cleared,
                  "reason": reason, "by": cleared_by})
        logger.info(f"Cleared {len(cleared)} open port finding(s) for {needle}: "
                    f"{reason}")
    return {"count": len(cleared), "ids": cleared}


def undeclare_expected_port(ip: str, port: int) -> bool:
    """Take it back. Returns True if there was something to remove."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT expected_ports FROM known_devices WHERE ip = ?",
            (ip,)).fetchone()
        if not row or not row[0]:
            return False
        try:
            current = json.loads(row[0]) or {}
        except Exception:
            return False
        if str(port) not in current:
            return False
        current.pop(str(port))
        conn.execute(
            "UPDATE known_devices SET expected_ports = ? WHERE ip = ?",
            (json.dumps(current) if current else None, ip))

    _journal("port_expectation_withdrawn", "known_devices", f"{ip}:{port}", {})
    return True


# FINDINGS THAT MATTER. TODO 81/84, 2026-09-09.
#
# The owner's idea, and the owner named the failure mode in the same breath as the
# idea: a table of important findings would be useful, and it would be
# extremely annoying the moment it filled with things that are not important.
# The seventeen false masquerading findings of 2026-09-08 are the proof. A
# model asked to promote what matters will promote all seventeen, confidently.
#
# So the value of this list is not its contents. It is its BELIEVABILITY. One
# row in it the owner knows is wrong and it becomes a second alert list that
# gets ignored, which is worse than not having it.
#
# THREE RULES, AND THE CODE BELOW IS JUST THEM WRITTEN OUT:
#
#   1. The model NOMINATES. It never promotes. There is no engine function
#      that lets it, and no tool that reaches one.
#   2. The owner confirms. That is the only path to promoted = 1.
#   3. It lives on the finding, not in a table of its own, so a finding that
#      is dismissed or cleared takes its promotion with it. No copy, nothing
#      to go stale, nothing to remember to clean twice.
#
# ON NOMINATION AND ATTACKER-CONTROLLABLE TEXT. Process names and log lines
# reach the model as tool output and an attacker can influence them, which is
# why dismiss_entity is gated. Nomination is the one model write where that
# risk points the safe way: the worst a planted nomination achieves is the
# owner looking at something harmless. It still gets a cap, because burying
# the real nomination under forty invented ones is a real attack even when
# each one is individually harmless.
MAX_OPEN_NOMINATIONS = 25


def nominate_finding(finding_id: int, reason: str,
                     nominated_by: str = "model") -> dict:
    """
    Raise a hand about one finding. Writes nothing the owner has to trust.

    Returns {"nominated": bool, "finding_id": int, ...}. Never promotes,
    never changes what the finding says, never touches severity. Nominating
    an already nominated finding replaces the reason rather than adding a
    second row, so a model that keeps arguing for the same thing does not
    get louder by repeating itself.
    """
    if not reason or not str(reason).strip():
        raise BadInput("A nomination needs a reason. Saying why is the point.")
    reason = str(reason).strip()[:1000]

    with _get_conn() as conn:
        row = conn.execute(
            "SELECT id, dismissed, promoted, nominated_at, title "
            "FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if row is None:
            return {"nominated": False, "finding_id": finding_id,
                    "reason_refused": "no finding has that id"}
        if row["dismissed"]:
            return {"nominated": False, "finding_id": finding_id,
                    "reason_refused": "that finding is dismissed. Un-dismiss "
                                      "it first if it matters after all."}
        if row["promoted"]:
            return {"nominated": False, "finding_id": finding_id,
                    "reason_refused": "already promoted by the user. Nothing "
                                      "to nominate."}

        # The cap counts OPEN nominations only, so confirming or rejecting
        # makes room. A full list is not an error the model can fix by
        # trying again, so it is told what to do instead.
        if row["nominated_at"] is None:
            open_now = conn.execute(
                "SELECT COUNT(*) AS n FROM findings "
                "WHERE nominated_at IS NOT NULL AND promoted = 0 "
                "AND dismissed = 0").fetchone()["n"]
            if open_now >= MAX_OPEN_NOMINATIONS:
                return {"nominated": False, "finding_id": finding_id,
                        "reason_refused": (
                            f"{open_now} nominations are already waiting for "
                            f"the user, which is the cap. Say what you think "
                            f"in your answer instead of adding to a queue "
                            f"nobody has read yet.")}

        conn.execute(
            "UPDATE findings SET nominated_at = CURRENT_TIMESTAMP, "
            "nominated_by = ?, nominated_reason = ? WHERE id = ?",
            (nominated_by, reason, finding_id))

    _journal("finding_nominated", "findings", str(finding_id),
             {"by": nominated_by, "reason": reason})
    return {"nominated": True, "finding_id": finding_id,
            "title": row["title"],
            "note": ("Nominated. It is NOT on the important list yet and will "
                     "not be until the user confirms it. Do not report it as "
                     "though it were.")}


def promote_finding(finding_id: int, reason: str = None) -> dict:
    """
    The user agreeing. This is the ONLY path to promoted = 1.

    Deliberately has no by= parameter. Every other write in this file that a
    model can reach carries one so the actor is recorded; this one has no
    model path at all, and adding the parameter would be the first step to
    somebody wiring one up.
    """
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT id, dismissed, nominated_reason FROM findings WHERE id = ?",
            (finding_id,)).fetchone()
        if row is None:
            return {"promoted": False,
                    "reason_refused": "no finding has that id"}
        if row["dismissed"]:
            return {"promoted": False,
                    "reason_refused": "that finding is dismissed"}
        # The reason the user gives wins. Falling back to the model's
        # nomination text is fine and is labelled as such by the UI, because
        # a promoted row with no stated reason is the thing that becomes
        # unauditable six weeks later.
        why = (reason or "").strip() or (row["nominated_reason"] or "")
        conn.execute(
            "UPDATE findings SET promoted = 1, promoted_at = CURRENT_TIMESTAMP, "
            "promoted_reason = ? WHERE id = ?", (why[:1000], finding_id))

    _journal("finding_promoted", "findings", str(finding_id), {"reason": why})
    return {"promoted": True, "finding_id": finding_id}


def reject_nomination(finding_id: int, reason: str = None) -> dict:
    """
    Turn down a nomination. Clears the nomination, keeps the finding.

    The finding itself is untouched: turning down "this matters" is not the
    same statement as "this is not real", and conflating them is how a list
    like this starts eating evidence.
    """
    with _get_conn() as conn:
        conn.execute(
            "UPDATE findings SET nominated_at = NULL, nominated_by = NULL, "
            "nominated_reason = NULL WHERE id = ? AND promoted = 0",
            (finding_id,))
    _journal("nomination_rejected", "findings", str(finding_id),
             {"reason": reason})
    return {"rejected": True, "finding_id": finding_id}


def demote_finding(finding_id: int, reason: str = None) -> dict:
    """Take a row back off the important list. The finding stays."""
    with _get_conn() as conn:
        conn.execute(
            "UPDATE findings SET promoted = 0, promoted_at = NULL, "
            "promoted_reason = NULL, nominated_at = NULL, "
            "nominated_by = NULL, nominated_reason = NULL WHERE id = ?",
            (finding_id,))
    _journal("finding_demoted", "findings", str(finding_id),
             {"reason": reason})
    return {"demoted": True, "finding_id": finding_id}


def query_important(include_nominations: bool = True,
                    limit: int = 50, with_total: bool = False) -> dict:
    """
    The important list, plus what is waiting on the user.

    Both halves filter dismissed = 0, which is the point of the design. When
    a rule turns out to be wrong and its findings are cleared, they leave
    this list on their own. Nobody has to remember there was a second place.
    """
    limit = _validate_limit(limit)
    with _get_conn() as conn:
        promoted = _rows_to_dicts(conn.execute(
            "SELECT * FROM findings WHERE promoted = 1 AND dismissed = 0 "
            "ORDER BY promoted_at DESC LIMIT ?", (limit,)).fetchall())
        waiting = []
        if include_nominations:
            waiting = _rows_to_dicts(conn.execute(
                "SELECT * FROM findings WHERE nominated_at IS NOT NULL "
                "AND promoted = 0 AND dismissed = 0 "
                "ORDER BY nominated_at DESC LIMIT ?", (limit,)).fetchall())

        # TODO 94.11. TWO lists, so two counts. One combined number would be
        # a number that answers neither question: a full promoted list beside
        # a truncated nomination list would read as partly complete, and
        # there is no such thing.
        totals = {}
        if with_total:
            p_total = _completeness(
                conn, "findings", "WHERE promoted = 1 AND dismissed = 0", [],
                len(promoted))
            n_total = _completeness(
                conn, "findings",
                "WHERE nominated_at IS NOT NULL AND promoted = 0 "
                "AND dismissed = 0", [], len(waiting)) if include_nominations \
                else {"returned": 0, "matching_total": 0, "complete": True}
            prefix = (p_total.pop("_note_prefix", "")
                      + n_total.pop("_note_prefix", ""))
            totals = {
                "promoted_total":   p_total.get("matching_total"),
                "promoted_complete": p_total.get("complete"),
                "nominated_total":  n_total.get("matching_total"),
                "nominated_complete": n_total.get("complete"),
                "_note_prefix": prefix,
            }

    answer = {
        "promoted":       _enrich(promoted, "entity_value"),
        "nominated":      _enrich(waiting, "entity_value"),
        "promoted_count": len(promoted),
        "waiting_count":  len(waiting),
        "cap":            MAX_OPEN_NOMINATIONS,
        "note": ("Promotion lives on the finding itself, so anything "
                 "dismissed or cleared leaves this list on its own. A "
                 "nomination is the model's opinion and nothing more until "
                 "the user confirms it."),
    }
    return _merge_completeness(answer, totals) if totals else answer


# The stamp that says WHY a findings row is dismissed, so undismissing can
# reverse exactly the rows an entity dismissal closed and leave alone the ones
# somebody closed one at a time for their own reasons. The two acts are
# different and the row has no other column that tells them apart.
#
# PORTED 2026-09-21. The Linux port was missing this whole mechanism, and the
# missing half was the visible one: dismiss wrote the dismissed_findings row,
# which stops NEW findings being raised, and left every finding already on
# screen with dismissed = 0. query_findings filters on exactly that column, so
# the Alerts list went on showing every one of them. The dashboard removed the
# row, the next poll brought it back, and the correct reading of that is "the
# dismiss button does not work".
ENTITY_DISMISSAL_MARK = "entity dismissed:"

# At most this many dismissals stand. The oldest beyond it expire, which puts
# that entity back under watch; findings it already closed stay closed.
DISMISSAL_CAP = 100


def dismiss_entity(entity_type: str, entity_value: str,
                   reason: str = None, dismissed_by: str = "user") -> dict:
    """
    Dismiss an entity permanently. Model calls this with dismissed_by='model'.

    IT CLOSES THE FINDINGS THAT ARE ALREADY ON SCREEN. Until 2026-09-21 this
    wrote one row into dismissed_findings and nothing else, which is half the
    job and the half nobody can see. The sensors read that row and stop
    raising NEW findings; the findings already in the table kept
    `dismissed = 0`, and query_findings filters on exactly that column.

    Two writes, one transaction, and it RETURNS WHAT IT DID so the caller can
    say "12 closed" instead of "done". The count is also how the page tells a
    dismissal that closed something from one that closed nothing.
    """
    _validate_entity(entity_type, entity_value)
    _spend_blinding_budget(dismissed_by)
    stamp = f"{ENTITY_DISMISSAL_MARK} {reason or 'no reason given'}"
    with _get_conn() as conn:
        conn.execute("""
            INSERT INTO dismissed_findings (entity_type, entity_value, reason, dismissed_by)
            VALUES (?,?,?,?)
            ON CONFLICT(entity_type, entity_value) DO UPDATE SET
                reason = excluded.reason,
                dismissed_at = CURRENT_TIMESTAMP
        """, (entity_type, entity_value, reason, dismissed_by))
        cur = conn.execute("""
            UPDATE findings
               SET dismissed = 1,
                   dismissed_at = CURRENT_TIMESTAMP,
                   dismissed_reason = ?
             WHERE entity_type = ? AND entity_value = ? AND dismissed = 0
        """, (stamp, entity_type, entity_value))
        closed = cur.rowcount or 0
        expired = conn.execute("""
            SELECT entity_type, entity_value, dismissed_by FROM dismissed_findings
             ORDER BY dismissed_at DESC, id DESC LIMIT -1 OFFSET ?
        """, (DISMISSAL_CAP,)).fetchall()
        for et, ev, _by in expired:
            conn.execute("DELETE FROM dismissed_findings WHERE entity_type=? AND entity_value=?",
                         (et, ev))
    for et, ev, by in expired:
        _journal("dismissal_expired", "dismissed_findings", f"{et}:{ev}",
                 {"cap": DISMISSAL_CAP, "by": by})
    # Item 3.2. Journaled AFTER the write, outside the connection block, so a
    # journal failure can never roll back or block the write it records.
    _journal("finding_dismissed", "dismissed_findings",
              f"{entity_type}:{entity_value}",
              {"reason": reason, "by": dismissed_by, "findings_closed": closed})
    logger.info("Dismissed %s:%s, %d open finding(s) closed with it.",
                entity_type, entity_value, closed)
    return {"dismissed": True, "findings_closed": closed,
            "entity_type": entity_type, "entity_value": entity_value,
            "expired": [f"{et}:{ev}" for et, ev, _by in expired]}


def undismiss_entity(entity_type: str, entity_value: str) -> dict:
    """
    Remove a dismissal, model or user can re-activate monitoring.

    REVERSES THE FINDINGS THE DISMISSAL CLOSED, and only those. A row closed
    by an entity dismissal carries the stamp above; a row somebody closed on
    its own says something else and stays closed, because undoing "stop
    watching this address" is not the same as reopening every alert anybody
    ever cleared about it.

    Rows dismissed before the stamp existed carry no mark, so they cannot be
    told apart and are left as they are. Said here rather than quietly: the
    undo is complete for anything dismissed from today on.
    """
    with _get_conn() as conn:
        conn.execute(
            "DELETE FROM dismissed_findings WHERE entity_type=? AND entity_value=?",
            (entity_type, entity_value)
        )
        cur = conn.execute("""
            UPDATE findings
               SET dismissed = 0, dismissed_at = NULL, dismissed_reason = NULL
             WHERE entity_type = ? AND entity_value = ? AND dismissed = 1
               AND dismissed_reason LIKE ?
        """, (entity_type, entity_value, ENTITY_DISMISSAL_MARK + "%"))
        reopened = cur.rowcount or 0
    _journal("finding_undismissed", "dismissed_findings",
              f"{entity_type}:{entity_value}", {"findings_reopened": reopened})
    logger.info("Undismissed %s:%s, %d finding(s) reopened.",
                entity_type, entity_value, reopened)
    return {"undismissed": True, "findings_reopened": reopened}