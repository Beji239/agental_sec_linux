# tools/dns_monitor.py
# AgentalSec V2, Import DNS queries from the network's resolver.
#
# WHY THIS IS THE HIGHEST VALUE SENSOR AVAILABLE WITHOUT HARDWARE
#
# Every other collector in this project observes from this host, and a switch
# forwards a unicast frame only to the port that owns the destination MAC, so
# no other device's traffic reaches this card. That is not a coding problem
# and no capture fixes it.
#
# The resolver sits somewhere else. A device that cannot resolve cannot
# connect, so a resolver log covers every device on the network, including
# ones nothing can be installed on and ones this host will never see a packet
# from. It requires no hardware, no topology change and no agent.
#
# It also answers the objection that destination addresses are useless. They
# largely are: shared hosting and content delivery networks put thousands of
# unrelated services behind one address deliberately, which is why RFC 6066
# introduced Server Name Indication, and why command and control is routinely
# run over Drive, Telegram and GitHub. The address is shared on purpose; the
# name is the identity.
#
# WHAT IT DOES NOT COVER, recorded on the sensor row rather than here so the
# model reads it as data: devices using DNS over HTTPS or TLS, devices with a
# hardcoded public resolver that ignore DHCP, answers served from the client's
# own cache so no query is emitted, and connections to a literal address. A
# missing name is not a missing connection.
#
# READ ONLY. The source database or log is opened read-only and never
# written, moved or truncated. If it cannot be opened, this module reports
# itself unavailable rather than failing the boot.
#
# THIS MODULE MAKES NO JUDGEMENTS. It normalises rows and stores them. Whether
# a name is interesting is the model's job, and PORT_PROFILES is the standing
# reminder of what happens when a hand-written table decides that in Python.

# THIS MODULE RAISES NO FINDINGS, AND THAT IS A DECISION.
#
# TODO 8.4, 2026-08-29. It used to be an oversight. dns_monitor called
# save_finding nowhere, while absence and drift each raised on thresholds of
# their own invention. From outside, a sensor that raises nothing looks
# exactly like a sensor nobody finished, and that ambiguity is the thing 8.4
# exists to remove.
#
# The decision now lives in core/finding_policy under `dns_novelty`. The
# reasoning: a name never resolved before is the commonest event on any
# network with a browser on it. Raising on it would produce findings faster
# than anyone can read them, which this codebase already documents as the
# road to an operator who ignores their own sensors.
#
# So DNS novelty does not raise ALONE. It is evidence that strengthens other
# findings and it stays fully queryable. fp.explain_silence() reports this to
# anyone looking at an empty findings list and wondering which kind of quiet
# they are looking at.
#
# If this is revisited, the version worth building is novelty COMBINED with
# something else, a new name on a metronome cadence, or a new name from a
# device whose baseline is otherwise narrow. Register that as its own rule
# rather than loosening this one.

import hashlib
import json
import logging
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

SOURCE_PIHOLE = "pihole"
SOURCE_ADGUARD = "adguard"
# dnsmasq on the router, read through the gateway agent's dnslog verb.
SOURCE_ROUTER = "router"
VALID_SOURCES = {SOURCE_PIHOLE, SOURCE_ADGUARD, SOURCE_ROUTER}

# The agent returns at most this many log lines per call.
ROUTER_LOG_LINES = 2000

# Rows per import pass. A busy network produces tens of thousands of queries a
# day, and the point of the cursor is that the next pass picks up where this
# one stopped, so a bounded batch costs nothing and keeps memory flat.
BATCH_LIMIT = 20000


# PI-HOLE DECODING
#
# Pi-hole stores integers. These maps are transcription, not interpretation:
# each one is documented by Pi-hole itself, and none of them decides whether
# anything is suspicious. An unknown code is passed through as its number
# rather than guessed at, because a wrong label here would be exactly the
# lookup-table failure this project keeps having.

_PIHOLE_TYPES = {
    1: "A", 2: "AAAA", 3: "ANY", 4: "SRV", 5: "SOA", 6: "PTR", 7: "TXT",
    8: "NAPTR", 9: "MX", 10: "DS", 11: "RRSIG", 12: "DNSKEY", 13: "NS",
    14: "OTHER", 15: "SVCB", 16: "HTTPS",
}

# TRANSCRIBED FROM FTL's OWN src/enums.h AND src/datastructure.c, 2026-09-26,
# because two entries had been added to the resolver since this map was
# written and a third was never in it. Read off the vendor's files rather than
# remembered: get_query_status_str maps QUERY_DBBUSY -> "DBBUSY",
# QUERY_SPECIAL_DOMAIN -> "SPECIAL_DOMAIN", QUERY_CACHE_STALE -> "CACHE_STALE"
# and QUERY_EXTERNAL_BLOCKED_EDE15 -> "EXTERNAL_BLOCKED_EDE15".
#
# WHAT THE OLD MAP DID WITH THEM, measured through the shipped reader: 18
# decoded to the string "code_18", an unrecognised code passed through as the
# number it was. That is the right fallback for a code nobody has documented;
# it is the wrong answer for a code Pi-hole's own source documents, because a
# reader of the row cannot tell "this resolver is newer than the tool" from
# "this is an unclassified query".
_PIHOLE_STATUS = {
    0: "unknown", 1: "blocked_gravity", 2: "forwarded", 3: "cached",
    4: "blocked_regex", 5: "blocked_exact", 6: "blocked_upstream_ip",
    7: "blocked_upstream_null", 8: "blocked_upstream_nxdomain",
    9: "blocked_gravity_cname", 10: "blocked_regex_cname",
    11: "blocked_exact_cname", 12: "retried", 13: "retried_dnssec",
    14: "already_forwarded", 15: "blocked_database_busy",
    16: "blocked_special_domain", 17: "cached_stale",
    18: "blocked_upstream_ede15",
}

# Codes that mean the resolver refused to answer normally. Kept as an explicit
# set rather than a substring test on the label, because 'blocked_database_busy'
# would otherwise be counted as a policy block when it is an internal failure.
#
# 18 ADDED 2026-09-26 and it was in FTL's own blocked list all along: in
# src/database/query-table.c the switch sets `query->flags.blocked = true` for
# QUERY_EXTERNAL_BLOCKED_EDE15 together with the other external-blocked
# codes. A resolver blocking a name upstream (an EDE 15 answer, "blocked by
# upstream") is blocked, and this tree counted it as an ordinary answer -- a
# blocked query published as a question that was answered.
_PIHOLE_BLOCKED = {1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18}

_PIHOLE_REPLY = {
    0: "N/A", 1: "NODATA", 2: "NXDOMAIN", 3: "CNAME", 4: "IP", 5: "DOMAIN",
    6: "RRNAME", 7: "SERVFAIL", 8: "REFUSED", 9: "NOTIMP", 10: "OTHER",
    11: "DNSSEC", 12: "NONE", 13: "BLOB",
}

# ADGUARD'S OWN REASON TABLE, transcribed 2026-09-26 from the vendor's
# internal/filtering/reason.go (`reasonNames`), which is what its writer puts
# in the `Result.Reason` field of every line of querylog.json. The names are
# the VENDOR'S OWN, including the two it kept as legacy spellings
# ("NotFilteredWhiteList", "FilteredBlackList") because its HTTP API still
# publishes those.
#
# THE COLUMN THIS LANDS IN holds words for the tree's other resolver reader
# ("forwarded", "blocked_gravity"), and it used to hold the raw integer here:
# measured through the shipped reader, a blocked query was stored with
# status=4. A number in a text column reads as a code the reader is expected
# to know, and no surface in this tree does.
_ADGUARD_REASON = {
    0: "not_filtered_not_found",
    1: "not_filtered_allow_list",
    2: "not_filtered_error",
    3: "filtered_block_list",
    4: "filtered_safe_browsing",
    5: "filtered_parental",
    6: "filtered_invalid",
    7: "filtered_safe_search",
    8: "filtered_blocked_service",
    9: "rewritten",
    10: "rewritten_auto_hosts",
    11: "rewritten_rule",
}


def _adguard_reason(value):
    """The vendor's name for one reason code, or the code as a string.

    None and "" become "answered", which is what the field meant before this
    existed: AdGuard omits Reason on a line it did not filter, so the absence
    of a reason IS the ordinary answer. Anything unrecognised is passed
    through as its own number, the same rule the Pi-hole maps follow.
    """
    if value in (None, ""):
        return "answered"
    try:
        code = int(value)
    except (TypeError, ValueError):
        return str(value)
    return _ADGUARD_REASON.get(code, f"reason_{code}")


def _decode(mapping: dict, value) -> str:
    """Look up a code, or return it verbatim. An unrecognised code stays a
    number so it reads as unknown rather than as a confident wrong name."""
    if value is None:
        return None
    try:
        return mapping.get(int(value), f"code_{int(value)}")
    except (TypeError, ValueError):
        return str(value)


def _iso(unix_seconds) -> str:
    """A Pi-hole REAL timestamp in the EXACT shape the store's column holds.

    THE FRACTION IS DROPPED, and that is a fix rather than tidiness. MEASURED:
    Pi-hole stores its timestamp as a REAL number of seconds, so a query at
    half a second past the mark arrives as 1758915061.5 and this function used
    to emit '2025-09-26T19:31:01.500000+00:00'. Every `since` filter in this
    tree re-emits its cutoff WITHOUT a fraction -- that is the section-9 fix in
    core/memory_engine._sql_datetime, made because '.' sorts AFTER '+' at the
    same second -- so a row carrying a fraction compares LESS than a cutoff at
    that very second and is dropped from a window it is inside.

    One column, one shape: this function is the only writer of it and it now
    emits what _sql_datetime(SHAPE_ISO_OFFSET) emits, for every input.
    """
    try:
        dt = datetime.fromtimestamp(float(unix_seconds), tz=timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError):
        return None
    return dt.replace(microsecond=0).isoformat()


def _iso_from_text(text) -> str:
    """An AdGuard RFC 3339 stamp, normalised into the store's own shape.

    MEASURED, and this one is larger than it looks. AdGuard writes the
    timestamp in the SERVER's own local time with its UTC offset
    ('2026-09-26T19:31:01.376690873+03:00' in the vendor's own test fixture;
    the operator's own zone produces '-07:00'). The store compares its
    timestamp column BYTE-WISE and every windowed check builds its cutoff in
    UTC, so on any host west of Greenwich a local-evening row sorts BEHIND a
    UTC cutoff carrying the next day's date and is invisible to every window
    it is inside. MEASURED through the shipped check: a row 20 minutes old was
    selected by 0 of 1 four-hour windows.

    The nanoseconds are dropped for the same reason the fraction is dropped
    from the Pi-hole reader: the column's readers all emit a whole second, and
    a fraction makes a row compare less than a cutoff at its own second.
    The RAW string still goes into the row identity (see read_adguard), so two
    queries in the same second stay two rows and a re-import stays a no-op.
    """
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def file_identity(path: Path):
    """The source file's inode, as text, or None when it cannot be read.

    A cursor of (offset, inode) can tell a file that GREW from a DIFFERENT
    file. An offset alone cannot, and the difference is measured: AdGuard
    rotates by renaming querylog.json away and starting a new one, and a new
    file that is already past the stored offset makes the next pass skip its
    first rows in silence. The auditd round carries its source's inode for
    exactly this reason.
    """
    try:
        return str(path.stat().st_ino)
    except OSError:
        return None


# READERS

def _open_readonly(path: Path):
    """
    Open the resolver's SQLite file without writing to it.

    Pi-hole runs in WAL mode and holds the file open, so a plain read-only URI
    can fail or block. A snapshot copy is taken when that happens: it costs
    disk and is a moment out of date, both of which are acceptable, and it
    guarantees the resolver's own database is never touched by this tool.
    """
    uri = f"file:{path.as_posix()}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=5)
        conn.execute("SELECT 1")
        return conn, None
    except sqlite3.Error as e:
        logger.info(f"Read-only open failed ({e}); using a snapshot copy.")

    tmp_dir = tempfile.mkdtemp(prefix="agentalsec_dns_")
    snapshot = Path(tmp_dir) / path.name
    try:
        shutil.copy2(path, snapshot)
        for suffix in ("-wal", "-shm"):
            side = Path(str(path) + suffix)
            if side.exists():
                shutil.copy2(side, Path(str(snapshot) + suffix))
        return sqlite3.connect(snapshot.as_posix(), timeout=5), tmp_dir
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(f"Could not read {path.name}: {e}") from e


def read_pihole(path: Path, after_row_id: int = 0,
                limit: int = BATCH_LIMIT) -> tuple[list[dict], int, dict]:
    """
    Read new rows from pihole-FTL.db.

    Columns are discovered rather than assumed, because Pi-hole has changed
    this table between major versions and a hardcoded column list would fail
    on some installs and silently return nothing on others.

    RETURNS (rows, highest_row_id, notes). `notes` carries rows_read,
    rows_dropped and hit_limit: the caller needs the SOURCE's own count, not
    the count of what survived this loop, to answer "is there more waiting".
    MEASURED before it existed: a source holding 20,010 rows with a quarter of
    them missing a domain returned 15,000 rows -- under BATCH_LIMIT -- so
    `more_available` read False and the caller declared itself caught up with
    10 rows still behind the cursor.
    """
    conn, tmp_dir = _open_readonly(path)
    try:
        conn.row_factory = sqlite3.Row
        available = {r[1] for r in conn.execute("PRAGMA table_info(queries)")}
        if not available:
            raise RuntimeError("no 'queries' table; is this a Pi-hole database?")

        wanted = [c for c in ("id", "timestamp", "type", "status", "domain",
                              "client", "forward", "reply_type")
                  if c in available]
        if "domain" not in wanted or "timestamp" not in wanted:
            raise RuntimeError("'queries' lacks domain or timestamp")

        key = "id" if "id" in wanted else "rowid"
        sql = (f"SELECT {', '.join(wanted)}, {key} AS _rid FROM queries "
               f"WHERE {key} > ? ORDER BY {key} ASC LIMIT ?")

        # MATERIALISED, so the reader can say how many rows the SOURCE handed
        # back and how many of them it could not use. Both numbers are needed
        # downstream: see the caller's `more_available`, which used to be
        # computed from the ROWS RETURNED and therefore read "caught up" when
        # the batch had been full of rows this loop discarded.
        fetched = conn.execute(sql, (after_row_id, limit)).fetchall()
        rows, highest = [], after_row_id
        dropped = 0
        for r in fetched:
            queried_at = _iso(r["timestamp"])
            if not queried_at or not r["domain"]:
                # No domain to store, or no usable timestamp. Counted rather
                # than passed over in silence: a resolver whose rows routinely
                # arrive in this shape would otherwise show a clean, quiet log
                # with an import that is quietly discarding all of it.
                dropped += 1
                # THE CURSOR STILL MOVES PAST IT, deliberately. It cannot be
                # stored, and leaving the cursor behind it would re-read the
                # same row on every pass forever.
                highest = max(highest, int(r["_rid"]))
                continue
            status_code = r["status"] if "status" in r.keys() else None
            rows.append({
                "queried_at":    queried_at,
                "client_ip":     r["client"] if "client" in r.keys() else None,
                "domain":        r["domain"],
                "query_type":    _decode(_PIHOLE_TYPES, r["type"]) if "type" in r.keys() else None,
                "status":        _decode(_PIHOLE_STATUS, status_code),
                "blocked":       _is_pihole_blocked(status_code),
                "upstream":      r["forward"] if "forward" in r.keys() else None,
                "reply_type":    _decode(_PIHOLE_REPLY, r["reply_type"]) if "reply_type" in r.keys() else None,
                "source":        SOURCE_PIHOLE,
                "source_row_id": r["_rid"],
            })
            highest = max(highest, int(r["_rid"]))
        notes = {
            "rows_read": len(fetched),
            "rows_dropped": dropped,
            # True when the SOURCE had at least a full batch to give, which is
            # the honest answer to "is there more waiting" whether or not the
            # rows in it were usable.
            "hit_limit": len(fetched) >= limit,
        }
        return rows, highest, notes
    finally:
        conn.close()
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def _is_pihole_blocked(status_code) -> bool:
    try:
        return int(status_code) in _PIHOLE_BLOCKED
    except (TypeError, ValueError):
        return False


def read_adguard(path: Path, after_offset: int = 0,
                 limit: int = BATCH_LIMIT) -> tuple[list[dict], int, dict]:
    """
    Read new lines from an AdGuard Home querylog.json.

    RETURNS (rows, end_offset, notes) since 2026-09-26. The third value is new
    and it is the point: two of this reader's most expensive failure modes are
    SILENT, and a caller that only receives rows cannot tell either of them
    from a quiet resolver. `notes` carries:

        "rotation_reset"   the file's identity changed (or it is shorter than
                           the stored offset), so reading restarted at the
                           start. Rows re-read are absorbed by the UNIQUE
                           constraint; without this note the operator is never
                           told a rotation happened at all.
        "line_skipped"     a line that is NOT the last one failed to parse, so
                           it is not a writer mid-line and it will never be
                           read again. THIS ONE EXISTED FOR REAL: MEASURED, a
                           line caught half-written at the end of one pass had
                           its remainder appended before the next pass, the
                           completed line sat BEHIND the cursor, and no pass
                           ever read it. The reader's own comment called that
                           "normal on a live log" and moved the cursor past it
                           anyway. Now the last line is the ONLY one that may
                           be skipped, and a skipped line says so.

    ROTATION IS DETECTED BY THE CALLER, and this docstring said otherwise for
    one sitting: it listed a "rotation_reset" note among the things this
    function returns, and the function never emits one. The cursor here is a
    bare byte offset, so this reader CANNOT tell a grown file from a different
    one; the identity check lives in import_once, which compares the recorded
    inode (see file_identity) against the file's and resets the offset before
    calling. MEASURED for the reason it has to: a log rotated by rename whose
    replacement had already outgrown the stored offset skipped 3 of 12 rows in
    silence. What this function does about it is nothing, on purpose -- it
    takes the offset it is given -- and the note is written where the decision
    is made, in the importer's own log line naming both inodes.

    The file is newline-delimited JSON and AdGuard rotates it, so the cursor
    is a byte offset with a guard: if the file is now shorter than the stored
    offset it was rotated, and reading resumes from the start. Duplicate rows
    that produces are absorbed by the UNIQUE constraint on insert rather than
    by trying to be clever here.

    THE GUARD WAS NOT ENOUGH ON ITS OWN. A rotated file that is ALREADY BIGGER
    than the stored offset passes it -- and that is the ordinary case on a busy
    resolver, because the new file grows fast. MEASURED: 3 of 12 rows in the
    new file were skipped with no note anywhere. The caller now also passes the
    inode it recorded (see file_identity) and a different inode is treated as a
    rotation whatever the sizes say.
    """
    size = path.stat().st_size
    notes = {}
    start = after_offset if 0 <= after_offset <= size else 0
    if start > size:
        start = 0

    # S19, 2026-08-28. THIS KILLED THE SENSOR PERMANENTLY, AND ANY DEVICE ON
    # THE NETWORK COULD TRIGGER IT.
    #
    # It iterated a TEXT file with `for line in fh`, broke out at the batch
    # limit, then called fh.tell(). Python refuses that: breaking out of
    # iteration over a text file leaves a read-ahead buffer, and tell() raises
    # `OSError: telling position disabled by next() call`. Reproduced exactly
    # against this module.
    #
    # It only ever exhausted the loop when the backlog was UNDER the limit, so
    # the failure appeared precisely when there was a lot to import. After
    # that: import_once catches it and returns ran=False, and the cursor is
    # never advanced because _set_cursor sits on the success path. Every later
    # pass re-reads the same oversized backlog and fails the same way. The
    # thread stays alive, status() still reports available, the dashboard
    # still shows the sensor configured, and not one DNS row is ever written
    # again.
    #
    # Anything on the LAN can push the log past the limit in seconds with a
    # resolver loop over a wordlist. A remotely triggerable, permanent, silent
    # kill of the one sensor that sees devices this host cannot: exactly the
    # "a dead sensor looks like a quiet network" failure this project keeps a
    # rule about, self-inflicted.
    #
    # Count the offset here instead of asking the file. Bytes rather than text
    # so len(raw) is the true offset delta, which text mode does not guarantee
    # under newline translation.
    rows = []
    end_offset = start
    with open(path, "rb") as fh:
        fh.seek(start)
        for raw in fh:
            if len(rows) >= limit:
                break
            # A line that does NOT end in a newline is the writer's current
            # line: whatever is there now may be a prefix of what will be
            # there. Leave the cursor BEFORE it and come back next pass.
            if not raw.endswith(b"\n"):
                break
            # Advanced only for lines actually consumed, so the next pass
            # resumes exactly where this one stopped.
            end_offset += len(raw)
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                # It is newline-terminated, so the writer finished writing it
                # and it is not valid JSON: a corrupt line, not a live one.
                # It will never be read again, so it is COUNTED rather than
                # passed over in silence.
                notes["line_skipped"] = notes.get("line_skipped", 0) + 1
                continue
            domain = entry.get("QH")
            when = entry.get("T")
            if not domain or not when:
                continue
            result = entry.get("Result") or {}
            # AdGuard has no row id, so identity is derived from the fields
            # that make a query unique in practice. A collision would drop a
            # genuine duplicate query, which costs a count; the alternative is
            # re-importing the whole log on every rotation.
            #
            # THE RAW TIMESTAMP IS IN THE IDENTITY, not the normalised one:
            # two queries in the same second carry different raw stamps and
            # must stay two rows, and the identity must not change when the
            # stored SHAPE changes or every existing row would re-import once.
            digest = hashlib.sha256(
                f"{when}|{entry.get('IP')}|{domain}|{entry.get('QT')}".encode()
            ).hexdigest()[:32]
            rows.append({
                # NORMALISED TO UTC, whole second: see _iso_from_text.
                "queried_at":    _iso_from_text(when),
                "client_ip":     entry.get("IP"),
                "domain":        domain,
                "query_type":    entry.get("QT"),
                # THE RESOLVER'S OWN WORD FOR WHY, not a bare integer. The
                # column's other writer puts words here ("forwarded",
                # "blocked_gravity") and the value used to be the raw code:
                # measured, a blocked query landed as the integer 4, which no
                # reader can act on and which reads as a code only because
                # somebody happened to know AdGuard's table. Decoded from the
                # vendor's own internal/filtering/reason.go, with the raw code
                # kept beside it so nothing is lost.
                "status":        _adguard_reason(result.get("Reason")),
                "blocked":       bool(result.get("IsFiltered")),
                "upstream":      entry.get("Upstream"),
                "reply_type":    None,
                "source":        SOURCE_ADGUARD,
                "source_row_id": digest,
            })

    return rows, end_offset, notes


# ROUTER DNSMASQ DECODING

import re

# logread stamp, then dnsmasq[pid], then the log-queries=extra prefix of
# serial and client/port, which older dnsmasq builds leave out.
_DNSMASQ_LINE = re.compile(
    r"^(?P<stamp>\w{3} \w{3} +\d+ \d\d:\d\d:\d\d \d{4}) \S+ "
    r"dnsmasq\[(?P<pid>\d+)\]: "
    r"(?:(?P<serial>\d+) (?P<peer>\S+/\d+) )?"
    r"(?P<body>.*)$")
_DNSMASQ_QUERY = re.compile(r"^query\[(?P<qtype>[^\]]+)\] (?P<domain>\S+) from (?P<client>\S+)$")
_DNSMASQ_ANSWER = re.compile(r"^(?P<kind>reply|cached|config|forwarded) (?P<domain>\S+) (?:is|to) (?P<value>.+)$")


def _router_stamp(text) -> str:
    """logread writes local time with no zone. Read it in this host's zone."""
    try:
        dt = datetime.strptime(" ".join(text.split()), "%a %b %d %H:%M:%S %Y")
    except (TypeError, ValueError):
        return None
    return dt.astimezone().astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _router_reply_type(value: str) -> str:
    v = value.strip()
    if v.startswith("NXDOMAIN"):
        return "NXDOMAIN"
    if v.startswith("NODATA"):
        return "NODATA"
    if v == "<CNAME>":
        return "CNAME"
    if v.startswith("<"):
        return v.strip("<>")
    return "IP"


def parse_router_dnslog(lines) -> tuple[list[dict], dict]:
    """Turn dnsmasq query lines into rows, one per query.

    The forwarded, reply, cached and config lines that share a query's
    serial fill in its upstream, status and reply type.
    """
    rows, by_key, answers = [], {}, []
    skipped = 0
    for line in lines:
        m = _DNSMASQ_LINE.match(line.strip())
        if not m:
            skipped += 1
            continue
        body = m["body"]
        key = (m["pid"], m["serial"], m["peer"]) if m["serial"] else None
        q = _DNSMASQ_QUERY.match(body)
        if q:
            queried_at = _router_stamp(m["stamp"])
            if not queried_at:
                skipped += 1
                continue
            identity = "|".join(str(x) for x in (
                m["stamp"], m["pid"], m["serial"], m["peer"],
                q["qtype"], q["domain"], q["client"]))
            row = {
                "queried_at":    queried_at,
                "client_ip":     q["client"],
                "domain":        q["domain"].rstrip(".").lower(),
                "query_type":    q["qtype"],
                "status":        None,
                "blocked":       False,
                "upstream":      None,
                "reply_type":    None,
                "source":        SOURCE_ROUTER,
                "source_row_id": hashlib.sha256(identity.encode()).hexdigest()[:32],
            }
            rows.append(row)
            if key:
                by_key[key] = row
            continue
        a = _DNSMASQ_ANSWER.match(body)
        row = by_key.get(key) if (a and key) else None
        if row is None:
            continue
        kind, value = a["kind"], a["value"]
        if kind == "forwarded":
            row["upstream"] = value.strip()
            row["status"] = row["status"] or "forwarded"
            continue
        if row["status"] != "forwarded":
            row["status"] = "reply" if kind == "reply" else kind
        if row["reply_type"] in (None, "CNAME"):
            row["reply_type"] = _router_reply_type(value)
        # The address goes under the name the device ASKED for, not the end
        # of a CNAME chain, because that is the name it will be known by.
        if kind in ("reply", "cached") and _router_reply_type(value) == "IP":
            answers.append({
                "name": row["domain"], "value": value.strip(),
                "rrtype": "AAAA" if ":" in value else "A",
                "client_ip": row["client_ip"], "resolver": "router",
                "protocol": "dns", "seen": row["queried_at"]})
        # A local rule answering nothing is a sinkhole. NODATA-IPv6 is the
        # router's own AAAA filter, not a block.
        if kind == "config" and value.strip() in ("NXDOMAIN", "0.0.0.0", "::"):
            row["blocked"] = True
    return rows, {"rows_read": len(rows), "line_skipped": skipped,
                  "lines": len(lines), "answers": answers,
                  "hit_limit": len(lines) >= ROUTER_LOG_LINES}


def read_router(config: dict) -> tuple[list[dict], dict]:
    from tools import gateway as gw
    lines = gw.Gateway(config).dnslog(ROUTER_LOG_LINES)
    return parse_router_dnslog(lines)


# IMPORT

# THE CURSORS LEFT user_preferences, 2026-09-26 (schema v54).
#
# THE SIXTH TIME THIS TREE HAS PAID FOR THIS SHAPE, and the evidence is the
# measurement rather than the argument. core/integrity.snapshot_config DIGESTS
# user_preferences as THE POLICY and journals a `config_observed` entry on ANY
# difference, on the contract that such an entry ALWAYS means the rules
# changed. The importer advances this cursor on every pass -- every 15 minutes
# by default -- so a working resolver sensor wrote a false "the policy has
# CHANGED" warning into the tamper journal, carrying nothing but a row number.
#
# MEASURED on a scratch database, driving the shipped code: one call to
# _set_cursor("pihole", 1234) moved the digest and produced a config_observed
# row whose payload was {'dns_import_cursor_pihole': '1234'}. Same for the
# inspector's cursor. The shapes this repeat: the T2 watcher cursor, the L3
# baselines (v42), the feeds' refresh time (v46), the port-owner tables (v51)
# and the lan_watch baselines (v53).
#
# A table rather than a prefix excluded from the digest, for the reason
# local_integrity's migration gives at length: excluding a key PATTERN would
# make "the policy" mean "user_preferences except the ones starting with dns_",
# a rule living in a string comparison that the next person has to know about.
# A table that is not user_preferences cannot be confused for policy by
# anything.
#
# `identity` CARRIES THE SOURCE FILE'S INODE for the two file cursors, and
# that is not decoration. A byte offset cannot tell a grown file from a
# DIFFERENT one: measured on this host, a resolver log rotated by rename and
# regrown past the stored offset made the next pass skip 3 of 12 rows and say
# nothing. The auditd round carried its source's inode for exactly this reason.
_CURSOR_TABLE = "dns_cursor"

_CURSOR_KEY = "dns_import_cursor_{source}"
_INSPECT_CURSOR_KEY = "dns_inspect_cursor"


def _cursor_row(name: str):
    """(value, identity) for one cursor, or (None, None) when never written."""
    from core import memory_engine as me
    try:
        with me._get_conn() as conn:
            row = conn.execute(
                f"SELECT value, identity FROM {_CURSOR_TABLE} WHERE name = ?",
                (name,)).fetchone()
    except Exception as e:
        logger.debug(f"Could not read the DNS cursor {name} ({e}).")
        return None, None
    if row is None:
        return None, None
    return (row[0], row[1])


def _cursor_write(name: str, value, identity=None):
    """Write one cursor row. Never raises into the caller."""
    from core import memory_engine as me

    def _do(conn):
        conn.execute(
            f"INSERT INTO {_CURSOR_TABLE} (name, value, identity) "
            f"VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET "
            f"value = excluded.value, identity = excluded.identity, "
            f"updated_at = CURRENT_TIMESTAMP",
            (name, None if value is None else str(value),
             None if identity is None else str(identity)))

    try:
        with me._get_conn() as conn:
            _do(conn)
        return True
    except Exception as e:
        logger.warning(
            f"Could not persist the DNS cursor {name} ({e}). The next pass "
            f"will re-read; duplicates are dropped by the UNIQUE constraint, "
            f"so this costs time, not correctness.")
        return False


def _get_cursor(source: str) -> int:
    value, _identity = _cursor_row(_CURSOR_KEY.format(source=source))
    try:
        return int(value) if value not in (None, "") else 0
    except (TypeError, ValueError):
        return 0


def _set_cursor(source: str, value: int, identity=None):
    _cursor_write(_CURSOR_KEY.format(source=source), int(value), identity)


def resolver_sensor_id() -> str:
    """The sensor row the resolver vantage is filed under, named in one place.

    The importer registers it and the INSPECTOR files its findings under it, so
    both call this rather than each building the string. A finding filed under
    the host sensor reads, to the model, as evidence about traffic on THIS
    machine -- which is the wrong scope sentence for something the resolver
    saw about another device.
    """
    from core import sensors as sn
    return f"{sn.LOCAL_SENSOR_ID}-resolver"


def register_resolver_sensor(config: dict) -> str:
    """Register or refresh the resolver vantage row. Idempotent."""
    from core import memory_engine as me
    from core import sensors as sn

    scope = sn.describe("resolver")
    sensor_id = resolver_sensor_id()
    me.upsert_sensor(
        sensor_id=sensor_id,
        label=(config.get("dns_monitor", {}) or {}).get("label"),
        position="resolver",
        summary=scope["summary"],
        can_see=scope["can_see"],
        cannot_see=scope["cannot_see"],
        notes="Imported from a resolver log by tools/dns_monitor.py.",
    )
    return sensor_id


def status(config: dict) -> dict:
    """Is DNS ingestion configured and usable? Reported at boot and in the UI."""
    block = (config or {}).get("dns_monitor", {}) or {}
    if not block.get("enabled"):
        return {"available": False, "reason": "disabled in config.json"}

    source = block.get("source")
    if source not in VALID_SOURCES:
        return {"available": False,
                "reason": f"source must be one of {sorted(VALID_SOURCES)}, "
                          f"got {source!r}"}

    if source == SOURCE_ROUTER:
        gw_block = (config or {}).get("gateway", {}) or {}
        if not (gw_block.get("enabled") and gw_block.get("host")):
            return {"available": False,
                    "reason": "source is router but gateway is not enabled "
                              "with a host in config.json"}
        return {"available": True, "source": source, "path": None,
                "reason": None}

    raw_path = block.get("path")
    if not raw_path:
        return {"available": False, "reason": "no path set in config.json"}

    path = Path(os.path.expandvars(str(raw_path))).expanduser()
    if not path.exists():
        # The path is not echoed back. It is a map of the operator's setup and
        # scripts/check_no_local_details exists to keep that out of anything
        # the model or a log reader sees.
        return {"available": False,
                "reason": "the configured resolver file does not exist"}

    return {"available": True, "source": source, "path": path,
            "reason": None}


def import_once(config: dict) -> dict:
    """
    One import pass. Safe to call repeatedly; re-importing is a no-op.

    Registers its own sensor at position 'resolver' rather than reusing the
    host sensor, because it is a different vantage point with a different
    blind spot. That distinction is the entire reason schema v8 exists: a
    device silent in this table and a device silent in packets are silent for
    completely different reasons, and only the sensor row says which.
    """
    from core import memory_engine as me

    state = status(config)
    if not state["available"]:
        return {"ran": False, "reason": state["reason"], "inserted": 0}

    source, path = state["source"], state["path"]
    sensor_id = register_resolver_sensor(config)

    if source == SOURCE_ROUTER:
        return _import_router(config, sensor_id)

    cursor = _get_cursor(source)
    stored_identity = _cursor_row(_CURSOR_KEY.format(source=source))[1]
    current_identity = file_identity(path)

    # A DIFFERENT FILE WITH THE SAME NAME IS A ROTATION, whatever the sizes
    # say. The offset guards alone cannot see it; see read_adguard and
    # file_identity. The row id cursor of a Pi-hole database is a different
    # instrument (FTL's rowids keep climbing across a database rewrite), so
    # this is only applied where the cursor IS a file offset.
    rotated = (source == SOURCE_ADGUARD
               and stored_identity is not None
               and current_identity != stored_identity)
    if rotated:
        logger.info(
            f"DNS import: the {source} log is a different file from the one "
            f"the cursor was recorded against (inode {stored_identity} -> "
            f"{current_identity}); reading it from the start. Rows already "
            f"imported are dropped by the UNIQUE constraint.")
        cursor = 0

    try:
        if source == SOURCE_PIHOLE:
            rows, new_cursor, notes = read_pihole(path, after_row_id=cursor)
        else:
            rows, new_cursor, notes = read_adguard(path, after_offset=cursor)
    except Exception as e:
        logger.error(f"DNS import from {source} failed: {e}")
        return {"ran": False, "reason": str(e), "inserted": 0}

    result = me.save_dns_queries(rows, sensor_id=sensor_id)
    _set_cursor(source, new_cursor, current_identity)

    # EVERY PASS SAYS WHAT IT READ, not only the ones that read something.
    # MEASURED before this: a pass that ran and found 0 rows logged NOTHING at
    # all, so "the sensor is working and the resolver is quiet" and "the
    # thread died" produced identical logs. The line now carries the reader's
    # own count of the rows it was handed, including the ones it could not use.
    dropped = notes.get("rows_dropped", 0)
    logger.info(
        f"DNS import: {result['inserted']} new of {result['seen']} stored "
        f"from {source}; {notes.get('rows_read', result['seen'])} row(s) read "
        f"at the source"
        + (f", {dropped} dropped by the reader (no domain or no usable "
           f"timestamp)" if dropped else "")
        + ("; the source had a full batch waiting" if notes.get("hit_limit")
           else "; the source is caught up")
        + (". A rotation was seen and the file was read from the start."
           if rotated else "."))
    if notes.get("line_skipped"):
        logger.warning(
            f"DNS import: {notes['line_skipped']} malformed line(s) in the "
            f"{source} log were skipped and will NOT be read again. They are "
            f"counted here because nothing else records them.")

    return {
        "ran": True,
        "source": source,
        "sensor_id": sensor_id,
        "read": result["seen"],
        "inserted": result["inserted"],
        "cursor": new_cursor,
        "rows_read_at_source": notes.get("rows_read", result["seen"]),
        "rows_dropped": dropped,
        "rotated": rotated,
        "lines_skipped": notes.get("line_skipped", 0),
        # A FULL BATCH AT THE SOURCE means there is more waiting, and it is
        # the SOURCE's own count that says so. It used to be the count of rows
        # that survived the reader's filters, so a batch full of unusable rows
        # read as "caught up" with the source still holding a backlog --
        # measured: 15,000 of 20,010 rows returned, 10 rows still behind the
        # cursor, more_available False.
        "more_available": bool(notes.get("hit_limit")),
        "reason": None,
    }


def _import_router(config: dict, sensor_id: str) -> dict:
    """One pass over the router's recent log. The UNIQUE key drops overlap,
    so no cursor is kept. A full read with nothing already stored means the
    log rolled past rows between passes, and that is said out loud."""
    from core import memory_engine as me
    try:
        rows, notes = read_router(config)
    except Exception as e:
        logger.error(f"DNS import from router failed: {e}")
        return {"ran": False, "reason": str(e), "inserted": 0}

    with me._get_conn() as conn:
        seen_before = conn.execute(
            "SELECT 1 FROM dns_queries WHERE source = ? LIMIT 1",
            (SOURCE_ROUTER,)).fetchone() is not None
    result = me.save_dns_queries(rows, sensor_id=sensor_id)
    try:
        me.save_dns_answers(notes["answers"], sensor_id=sensor_id)
    except Exception as e:
        logger.error(f"DNS import: router answers were not stored: {e}")
    gap = bool(seen_before and notes["hit_limit"] and rows
               and result["inserted"] == result["seen"])
    logger.info(
        f"DNS import: {result['inserted']} new of {result['seen']} queries "
        f"from the router; {notes['lines']} log line(s) read.")
    if gap:
        logger.warning(
            "DNS import: every query in a full read from the router was new, "
            "so queries older than this read may have rolled out of its log "
            "unread. Shorten dns_monitor.interval_minutes or raise the "
            "router's log_size.")
    if notes["line_skipped"]:
        logger.warning(f"DNS import: {notes['line_skipped']} router log "
                       f"line(s) did not parse and were skipped.")
    return {
        "ran": True, "source": SOURCE_ROUTER, "sensor_id": sensor_id,
        "read": result["seen"], "inserted": result["inserted"],
        "cursor": None, "rows_read_at_source": notes["rows_read"],
        "rows_dropped": 0, "rotated": False,
        "lines_skipped": notes["line_skipped"], "possible_gap": gap,
        # A re-read returns the same window, so there is never a backlog to chase.
        "more_available": False, "reason": None,
    }
