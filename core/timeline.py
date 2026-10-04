# core/timeline.py
# AgentalSec V2, the Activity Timeline read. TN-1..TN-5, 2026-09-25.
#
# WHY THIS IS ITS OWN MODULE RATHER THAN A FUNCTION IN memory_engine.py.
#
# memory_engine is the data access layer: one function per table, each one a
# faithful read of what is stored. This is not that. This is a JOIN ACROSS
# THREE TABLES, a fair mixing rule, and five paragraphs of prose per row whose
# whole job is explaining the row to a person. It is a presentation read, it is
# read by exactly one caller (the page), and it belongs beside the other
# cross-cutting readers rather than in the middle of the table accessors.
#
# IT STILL OWNS NO CONNECTION OF ITS OWN. Every read goes through
# memory_engine's own connection helpers, so the read-only handle and the
# row-to-dict timestamp tagging are the same ones the rest of the app uses and
# there is no second way to reach this database.
#
# THE FIVE DEFECTS THIS ROUND FOUND, each measured on the live store
#
# THE PAGE'S OWN CLAIM, from its card: "One list, in time order, of everything
# this app recorded", answering "what else was happening at the same time".
# Every word of that was false on this host.
#
# TN-1. THE LIST WAS NOT "EVERYTHING", IT WAS ALL PACKETS. The route read
# findings, events and packets with the SAME limit and merged them by
# timestamp, and the three write rates differ by four orders of magnitude.
# Measured on the live store, window 2h:
#
#     packets in window   136,442   (20 to 50 rows a SECOND)
#     events in window        607
#     findings in window       13
#
# so the newest 200 rows of the merge were 200 packets, ZERO events and ZERO
# findings. The two record types an operator opens this tab to correlate were
# off the end of every window, at every window size, on any machine with a
# capture running. Confirmed against direct SQL: the 13 findings sat at
# positions 400 to 412 of the merged order.
#
# THE FIX IS NOT A BIGGER LIMIT. 200 rows cannot represent 136,442 packets at
# any limit a screen can read, and raising the limit only moves the boundary.
# What the page needs is COVERAGE OF THE WINDOW: a finding at 02:02 is
# explained by what was happening AT 02:02, and the newest 200 packets are two
# seconds wide. So the window is cut into equal TIME SLICES, each slice gets a
# reserved budget, and the budget is spent round robin across the three record
# types. A slice with no findings spends its whole budget on events and
# packets, so a quiet record type leaves no hole; a slice with findings spends
# first on them. Nothing is starved by volume and every slice of the window is
# represented.
#
# TN-2. A PACKET ROW RENDERED AS AN EMPTY LINE. The page printed
# `title or description or event_type or threat_label`, and a packet row has
# none of the four: the first three are columns on the other two tables, and
# threat_label is NULL on every unflagged row (measured: 0 of the 1,260,634
# rows in the live store carry one). So all 200 rows of the default window
# rendered as a time, the word "packet", and NOTHING. The store knew the
# protocol, both addresses, both ports, the size and, on 439,175 of those
# rows, WHICH LOCAL PROCESS owned the socket. The page printed none of it.
#
# TN-3. THE TIMELINE WAS SCOPED TO THE CURRENT RUN. main.py mints a session id
# on every boot and the route passed it to all three reads, so a restart
# emptied the tab behind "No activity in this window." Measured in the same 2h
# window: 13 findings across all sessions, 1 in the current one. This is
# REGISTER PS-12 (the Ports tab, fixed 2026-09-25) in the one growing-record
# reader that had not been fixed for it, and the argument is identical: "what
# else was happening at the same time" is a question about the clock, not
# about this process.
#
# TN-4. NO ROW SAID WHERE IT CAME FROM OR WHY IT WAS THERE, and a finding
# carried no way to reach the rule that raised it either, though the register
# has had stable ids since TODO 112 and the Detections page has been able to
# answer "what fires this" since then. Every row now carries four lines, WHAT,
# WHO, WHERE FROM and WHY, plus the id of the rule it connects to.
#
# TN-5. A ROW WHOSE DETECTION HAS NO RULE IN THIS BUILD. The lookup is
# detections.exists() and never detections.get(): get() raises on an
# unregistered id, which is right for a writer (the register's own header
# argues it) and wrong for a page, because a page that raises renders as an
# empty tab and an empty tab is the failure this whole read exists to end. An
# unregistered id reads as an unregistered id, in words.
#
# WHAT THIS DOES NOT DO, so the next reader does not assume it:
#   * It does not read payload_snippet. A flagged packet's bytes are not in
#     this answer; the label and the rule link are, and the bytes belong to a
#     row somebody asks for by hand.
#   * It does not reconstruct process attribution that was never recorded. A
#     NULL process_name is reported as NOT ATTRIBUTED, with the schema's own
#     reasons, and never as "no process".
#   * It does not hide a dismissed finding. A dismissed row is shown WITH the
#     dismissal, because the dismissal is itself an explanation of what
#     happened at that moment (bugfinder RT-2's rule).
#
# HOUSE STYLE: the comma-run separator, no vertical bars in prose, no em
# dashes, no double hyphens. scripts/check_no_local_details.py enforces it.

import logging
import sqlite3
from datetime import datetime, timedelta, timezone

from core import memory_engine as me

logger = logging.getLogger(__name__)


# Equal time slices across the window, and the reason for the number.
#
# 24 was chosen against the page's own smallest filter. A 2h window becomes
# five minutes a slice, which is fine enough that a finding and the traffic
# around it land in the same slice, and coarse enough that a slice's budget is
# worth spending. A larger count shrinks per-slice coverage on the wide
# windows (7d would put a finding in a slice with 5 minutes of traffic and 6
# hours of nothing); a smaller one lets one busy slice eat the page. See TN-1.
SLICE_COUNT = 24

# Used only when a caller passes no since at all. The page always sends one;
# this exists so a bare call cannot silently mean "the whole table".
DEFAULT_HOURS = 24

# The order a slice spends its budget in. Findings first: they are the rarest,
# the most expensive to produce, and the reason most readers opened the page.
# Then events, then packets. A slice where a record type has nothing simply
# passes to the next, so an empty stretch of findings does not reserve budget
# it cannot use.
ORDER = ("finding", "event", "packet")

_TABLE_AND_TIME = {
    "finding": ("findings", "found_at"),
    "event":   ("events",   "occurred_at"),
    "packet":  ("packets",  "captured_at"),
}

# Per record type, the column names a page or a test may read without having
# to guess. Kept here rather than inline so the SELECT and the shape of a row
# cannot drift apart.
#
# payload_snippet is DELIBERATELY ABSENT from the packet read. It is up to 512
# characters of hex per row and it is only ever set on a flagged row; the
# bytes belong to a row somebody asks for by name, not to a list of 200.
_PACKET_COLUMNS = (
    "id, session_id, captured_at, src_ip, dst_ip, src_port, dst_port, "
    "protocol, direction, scope, packet_size, flags, threat_label, vpn_state, "
    "sensor_id, process_name, process_pid"
)


# WHAT A ROW CONNECTS TO
#
# Two links, and each one is offered only when the page it points at can
# actually answer for this row. A link that lands on a page with nothing to
# say is worse than no link: it teaches the reader that the links here do not
# mean anything.

def rule_note(detection_id: str) -> dict:
    """
    What is known about the rule a row names, WITHOUT EVER RAISING.

    Returns {"known": False, "reason": ...} for an id this build does not
    carry. See TN-5: this is the one place in the tree that reads the register
    with exists() where the rest of the app uses get(), and the reason is that
    the caller is a page.
    """
    if not detection_id:
        return {"known": False, "reason": "no detection id on this row"}

    from core import detections as det
    if not det.exists(detection_id):
        return {
            "known": False,
            "reason": (f"the rule {detection_id} is not in this build's "
                       f"register, so what fires it cannot be read here"),
        }

    d = det.get(detection_id)
    return {
        "known":          True,
        "detection_id":   d.did,
        "name":           d.name,
        "rev":            d.rev,
        "summary":        d.summary,
        "kind":           d.kind,
        "retired":        d.retired,
        "retired_reason": d.retired_reason,
        "entity_is_not_a_host": d.entity_is_not_a_host,
    }


def _map_link(row: dict, kind: str) -> tuple:
    """
    (address, note) for the Threat Map link. Exactly one of the two is set.

    THE MAP DRAWS PUBLIC ENDPOINTS ONLY, so a link is offered only when the
    map could have something to draw. Two cases get a NOTE instead, and both
    were measured:

      * An address a registered rule says is NOT A HOST. That is PKT-1017 on
        this host: 1.0.0.10 and 11.22.37.169 are routable strings the
        sender's own stack wrote wrong, and api/routes.threatmap holds them
        out of the globe deliberately. A link would promise a picture the map
        has decided not to draw.
      * A row whose addresses are all private, loopback or multicast. The map
        geolocates public endpoints; there is nothing on it for a private address of this host.
    """
    from core import geoip

    if kind == "finding":
        rule = rule_note(row.get("detection_id"))
        if rule.get("entity_is_not_a_host"):
            return None, ("no map link: the rule that raised this says the "
                          "address is not a host at all")
        if (row.get("entity_type") or "") != "ip":
            return None, None
        addr = row.get("entity_value")
    elif kind == "packet":
        # Whichever side of the packet is publicly routable is the endpoint
        # the map draws.
        addr = next((a for a in (row.get("src_ip"), row.get("dst_ip"))
                     if a and geoip.is_routable(a)), None)
        if not addr:
            return None, None
    else:
        addr = row.get("src_ip")
        if not addr or not geoip.is_routable(addr):
            return None, None

    if not addr:
        return None, None
    if not geoip.is_routable(addr):
        return None, (f"no map link: {addr} is not a public address, and the "
                      f"map draws public endpoints only")
    return addr, None


# WHAT A ROW IS, WHO IT BELONGS TO, WHERE IT CAME FROM, WHY IT IS THERE

def _process_note(row: dict) -> str:
    """
    The process or app a row is related to, or why that cannot be said.

    THE NULL RULE COMES FROM Schema.SQL AND NOT FROM HERE: a NULL
    process_name means NOT ATTRIBUTED, never "no process". The schema's own
    comment names the three cases, so the sentence does not invent a fourth.
    """
    name = (row.get("process_name") or "").strip()
    pid = row.get("process_pid")
    if name and pid:
        return f"process {name}, pid {pid}"
    if name:
        return f"process {name}, pid not recorded"
    return ("no process was recorded for this row, which is NOT the same as "
            "saying no process was involved. The capture records the owner of "
            "the socket when it can, and it could not here: either the packet "
            "had no local endpoint, or the owning socket opened and closed "
            "between two polls")


def _explain_finding(row: dict) -> dict:
    """WHAT, WHO, WHERE FROM and WHY for one finding row."""
    rule = rule_note(row.get("detection_id"))
    entity_type = row.get("entity_type") or "?"
    entity_value = row.get("entity_value") or ""

    who = f"filed against the {entity_type} {entity_value}".strip()
    if rule.get("entity_is_not_a_host"):
        who += ("; the rule that raised this says that address is the "
                "sender's own malformed header and not a host")

    where_from = (f"raised by {row.get('source') or 'an unnamed sensor'}"
                  f" in session {row.get('session_id') or '?'}")
    if row.get("sensor_id"):
        where_from += f", sensor {row['sensor_id']}"

    if rule.get("known"):
        why = (f"why it is here: {rule['detection_id']} rev {rule['rev']} "
               f"({rule['name']}) fired. {rule['summary']}")
        if rule.get("retired"):
            why += (f" This rule is RETIRED: "
                    f"{rule.get('retired_reason') or 'no reason recorded'}.")
    else:
        why = f"why it is here: {rule.get('reason')}"

    if row.get("dismissed"):
        why += (" It is DISMISSED and kept on the record: "
                f"{row.get('dismissed_reason') or 'no reason recorded'}. "
                "Dismissed rows are shown rather than hidden, because the "
                "dismissal is itself an explanation of what happened here.")

    return {
        "what":       row.get("title") or "a finding with no title",
        "who":        who,
        "where_from": where_from,
        "why":        why,
        "detection_id": row.get("detection_id"),
    }


def _explain_event(row: dict) -> dict:
    """WHAT, WHO, WHERE FROM and WHY for one event row."""
    from core import detections as det

    etype = row.get("event_type") or "log_entry"
    subject = (row.get("username") or row.get("src_ip")
               or row.get("process_name") or "")

    what = etype.replace("_", " ")
    if subject:
        what += f": {subject}"

    bits = []
    if row.get("username"):
        bits.append(f"account {row['username']}")
    if row.get("process_name"):
        bits.append(f"service or process {row['process_name']}")
    if row.get("src_ip"):
        bits.append(f"from {row['src_ip']}")
    who = ", ".join(bits) if bits else (
        "no account, process or address is recorded on this row; the source "
        "line did not carry one that could be trusted")

    where_from = (f"read from {row.get('source') or 'an unnamed log'} by the "
                  f"local event monitor (event_monitor) in session "
                  f"{row.get('session_id') or '?'}")
    if row.get("sensor_id"):
        where_from += f", sensor {row['sensor_id']}"

    # WHY IT IS ON THE LIST, and what would turn it into a finding instead.
    # The mapping lives in core/detections so the page and the model read one
    # truth; a rule named there that is not in the register is reported as
    # such rather than dropped.
    did = det.EVENT_TYPE_RULES.get(etype)
    severity = row.get("severity") or "info"
    why = (f"why it is here: the event monitor records every log line it "
           f"matches as an event, at {severity} severity. This is a record of "
           f"something that happened, not an alert about it.")
    if did:
        rule = rule_note(did)
        if rule.get("known"):
            why += (f" A burst of this shape raises {did} "
                    f"({rule['name']}): {rule['summary']}")
        else:
            why += f" {rule.get('reason')}"

    return {
        "what":       what,
        "who":        who,
        "where_from": where_from,
        "why":        why,
        "detection_id": did,
    }


def _explain_packet(row: dict) -> dict:
    """WHAT, WHO, WHERE FROM and WHY for one packet row."""
    proto = (row.get("protocol") or "?").upper()
    size = row.get("packet_size")
    direction = (row.get("direction") or "?").lower()
    src = (f"{row.get('src_ip')}:{row.get('src_port')}"
           if row.get("src_port") is not None else str(row.get("src_ip")))
    dst = (f"{row.get('dst_ip')}:{row.get('dst_port')}"
           if row.get("dst_port") is not None else str(row.get("dst_ip")))

    what = (f"{proto} {size if size is not None else '?'} bytes, {direction}, "
            f"{src} to {dst}")
    label = row.get("threat_label")
    if label:
        what += f". FLAGGED by the sniffer: {label}"

    where_from = (f"captured by the packet sniffer (packet_sniffer) in session "
                  f"{row.get('session_id') or '?'}")
    if row.get("scope"):
        where_from += f", scope {row['scope']}"
    if row.get("sensor_id"):
        where_from += f", sensor {row['sensor_id']}"

    if label:
        from core import detections as det
        did = det.detection_for_threat(label)
        rule = rule_note(did) if did else {"known": False}
        if rule.get("known"):
            why = (f"why it is here: the packet carries the threat label "
                   f"{label}, which maps to {did} ({rule['name']}): "
                   f"{rule['summary']}")
        else:
            why = (f"why it is here: the packet carries the threat label "
                   f"{label}, which no rule in this build is registered for, "
                   f"so what it means cannot be read from here.")
    else:
        why = ("why it is here: the sniffer stores a row for ordinary traffic "
               "it sees. Nothing is flagged on this row, which means no "
               "signature matched it, NOT that it was checked and cleared.")

    return {
        "what":       what,
        "who":        _process_note(row),
        "where_from": where_from,
        "why":        why,
    }


_EXPLAIN = {
    "finding": _explain_finding,
    "event":   _explain_event,
    "packet":  _explain_packet,
}


# THE READ

def timeline_rows(since: str = None, until: str = None, limit: int = 200,
                  session_id: str = None, all_sessions: bool = True) -> dict:
    """
    The Activity Timeline: findings, events and packets, fairly mixed across
    the window, each row carrying what it is, who it belongs to, where it was
    recorded from, why it is there, and what it connects to.

    See the module header for TN-1..TN-5 and the measurements behind them.

    RETURNS A DICT, where the route used to build a bare list. A list could
    not carry the three things the page has to say: how many rows the window
    holds against how many are shown (rule 3, a capped list must say it is
    capped), which record types could not be read (rule 2, "no match" and "I
    could not search" are different sentences), and whether the answer
    describes the clock or only this run (TN-3).

    all_sessions defaults TRUE, which is the opposite of query_packets, and
    deliberately: this read exists to answer "what else was happening at the
    same time", and a restart must not empty that answer. Pass all_sessions=
    False for the current run only.
    """
    limit = me._validate_limit(limit)
    if limit < len(ORDER):
        limit = len(ORDER)

    # THE WINDOW
    #
    # A cutoff that cannot be placed on the store's timeline is REFUSED rather
    # than defaulted, which is _sql_datetime's own rule since TL-1: an
    # unplaceable cutoff answered with a default window is a wrong answer
    # wearing the clothes of a right one. "now" is resolved ONCE so the three
    # reads and the three counts all describe the same instant.
    now = datetime.now(timezone.utc)
    defaulted = False
    if since:
        since_sql = me._sql_datetime(since)
    else:
        since_sql = (now - timedelta(hours=DEFAULT_HOURS)) \
            .strftime("%Y-%m-%d %H:%M:%S")
        defaulted = True
    until_sql = (me._sql_datetime(until) if until
                 else now.strftime("%Y-%m-%d %H:%M:%S"))

    start = datetime.strptime(me._comparable_ts(since_sql), "%Y-%m-%d %H:%M:%S")
    end = datetime.strptime(me._comparable_ts(until_sql), "%Y-%m-%d %H:%M:%S")
    if end <= start:
        raise me.BadInput(
            f"the Timeline window ends before it starts: since={since_sql} "
            f"until={until_sql}. Nothing can be placed on that window.")

    width = max(1.0, (end - start).total_seconds() / SLICE_COUNT)
    # Ceil, so the slices together can always hold the whole limit. With 200
    # rows over 24 slices this is 9 a slice, and 24 times 9 is more than 200,
    # so the last slice does not run out of budget on someone else's account.
    per_slice = max(1, -(-limit // SLICE_COUNT))

    session_clause = ""
    params_tail: list = []
    if session_id and not all_sessions:
        session_clause = " AND session_id = ?"
        params_tail = [session_id]
    elif not all_sessions:
        # ASKING FOR ONE RUN WITHOUT NAMING ONE IS REFUSED, and this was found
        # by the negative control for TN-3: the first version skipped the
        # session clause entirely when session_id was None, so the answer
        # returned EVERY session's rows under the sentence "session None
        # only". A caller that asked to be narrowed got everything and was
        # told it had been narrowed, which is the same defect this round is
        # about, one layer in. Refusing is the only honest answer available.
        raise me.BadInput(
            "all_sessions=False asks for ONE RUN, and no session_id was "
            "given, so there is no run to scope to. Pass a session_id, or "
            "leave all_sessions at its default.")

    # THE READ IS ASKED FOR SLICE BY SLICE, AND THE FIRST DRAFT WAS NOT.
    #
    # Found by running this function against the live store before writing its
    # test, and the number is the whole argument:
    #
    #     newest `limit` rows of the WINDOW, then sliced   -> 4 packets shown,
    #     and 23 of the 24 slices held NOTHING, because a capture writing 20
    #     to 50 rows a second spends its entire 200-row allowance inside the
    #     window's last two slices.
    #
    # A per-slice budget over rows selected newest-first only helps when more
    # than one slice has rows to spend it on. So each slice is asked for its
    # OWN rows, with a bound it computes from its own bounds: a time range
    # small enough to be cheap (measured, 0.004 s with idx_events_time), and
    # the row count the slice could contribute at most, which is 3 times its
    # round-robin budget because every record type passes through it.
    #
    # The cost is bounded and it is the same order as one full-window read:
    # 3 records times 24 slices, each capped at 3 times a 9-row budget.
    selects = {
        # HALF-OPEN SLICES, [start, end), AND THIS MATTERS. The first draft
        # asked every slice for `>= start AND <= end`, so the instant where
        # two slices meet belonged to BOTH of them: measured on the fixture,
        # every finding and every event rendered TWICE. The last slice closes
        # at the window's own end, so nothing inside the window is excluded by
        # the half-open rule.
        "finding": ("SELECT * FROM findings WHERE found_at >= ? "
                    "AND found_at < ?" + session_clause +
                    " ORDER BY found_at DESC LIMIT ?"),
        "event":   ("SELECT * FROM events WHERE occurred_at >= ? "
                    "AND occurred_at < ?" + session_clause +
                    " ORDER BY occurred_at DESC LIMIT ?"),
        "packet":  (f"SELECT {_PACKET_COLUMNS} FROM packets "
                    f"WHERE captured_at >= ? AND captured_at < ?"
                    + session_clause + " ORDER BY captured_at DESC LIMIT ?"),
    }
    # The last slice's upper bound is INCLUSIVE, so a row stamped exactly at
    # the window's end is in the answer. Written as its own operator rather
    # than by widening the range, because a widened range would collide with
    # the next window the operator asks for.
    last_selects = {
        kind: selects[kind].replace(" < ?", " <= ?")
        for kind in selects
    }

    slice_rows: list = []          # one dict per slice: {kind: [rows]}
    totals: dict = {}
    read_ok: dict = {}
    read_errors: dict = {}
    unplaceable = 0
    slice_cap = per_slice * len(ORDER)

    with me._get_conn() as conn:
        for kind in ORDER:
            table, when = _TABLE_AND_TIME[kind]
            where = (f"WHERE {when} >= ? AND {when} <= ?"
                     + (" AND session_id = ?" if session_clause else ""))
            try:
                totals[kind] = conn.execute(
                    f"SELECT COUNT(*) FROM {table} {where}",
                    [since_sql, until_sql] + params_tail).fetchone()[0]
            except sqlite3.Error as e:
                # RULE TWO, AT THE TOP OF THE FUNCTION RATHER THAN IN A NOTE
                # SOMEBODY HAS TO REMEMBER TO READ. A table that cannot be
                # read is a HOLE in this list and the caller is told which one
                # it is; it is never allowed to render as an empty stretch.
                totals[kind] = None
                read_ok[kind] = False
                read_errors[kind] = str(e)
                logger.warning(f"Timeline could not read {table}: {e}")

        for index in range(SLICE_COUNT):
            slice_start = start + timedelta(seconds=index * width)
            slice_end = start + timedelta(seconds=(index + 1) * width)
            # THE LAST SLICE INCLUDES ITS UPPER BOUND and every other slice
            # excludes it. Together that is a half-open partition of the window
            # with both ends closed, so no row is in two slices and no row
            # inside the window is left out.
            is_last = (index == SLICE_COUNT - 1)
            end_sql = (until_sql if is_last else
                       slice_end.strftime("%Y-%m-%d %H:%M:%S"))
            start_sql = slice_start.strftime("%Y-%m-%d %H:%M:%S")

            here: dict = {}
            for kind in ORDER:
                here[kind] = []
                if not read_ok.get(kind, kind not in read_errors):
                    continue
                # PER KIND, AND THIS LINE IS LOAD BEARING. The first draft of
                # this loop read `when` from the enclosing scope, where it had
                # been left set to "captured_at" by the counts loop above, so
                # every finding and every event was timestamped off a column
                # its row does not have, read as empty, and discarded as
                # unplaceable: MEASURED, 200 rows of output and every one of
                # them a packet, while 621 events sat in the same window. The
                # test for it is the one that asserts every record type is
                # represented when the window holds all three.
                _table, when = _TABLE_AND_TIME[kind]
                try:
                    raw = conn.execute(
                        (last_selects if is_last else selects)[kind],
                        [start_sql, end_sql] + params_tail
                        + [slice_cap]).fetchall()
                    if kind not in read_ok:
                        read_ok[kind] = True
                except sqlite3.Error as e:
                    read_ok[kind] = False
                    read_errors.setdefault(kind, str(e))
                    logger.warning(f"Timeline could not read {table}: {e}")
                    continue
                for row in me._rows_to_dicts(raw):
                    at = me._comparable_ts(row.get(when))
                    if not at:
                        # A ROW WITH NO TIMESTAMP AT ALL. It cannot be placed
                        # on the window and it must not land in a slice
                        # carrying an empty `at`, which renders as a blank
                        # time beside a real row. Counted, and said out loud
                        # in the note; see `unplaceable` below.
                        unplaceable += 1
                        continue
                    row["_at"] = at
                    here[kind].append(row)
            slice_rows.append(here)

        # Read here, inside the same connection, and used below to mark the
        # rows this app's own port scan caused. See _mark_self_induced.
        scan_windows = me._scan_windows(conn)

    # SPEND EACH SLICE'S BUDGET, NEWEST SLICE FIRST
    #
    # Newest first, because the page's question is almost always about
    # something that just happened. The slices are what keep the answer from
    # being nothing but the last two seconds of it.
    out_rows: list = []
    shown = {k: 0 for k in ORDER}

    for index in range(SLICE_COUNT - 1, -1, -1):
        if len(out_rows) >= limit:
            break
        bucket = slice_rows[index]
        cursor = {k: 0 for k in ORDER}
        picked: list = []
        budget = min(per_slice, limit - len(out_rows))

        while budget > 0:
            took = False
            for kind in ORDER:
                if budget <= 0:
                    break
                if cursor[kind] < len(bucket[kind]):
                    picked.append((kind, bucket[kind][cursor[kind]]))
                    cursor[kind] += 1
                    budget -= 1
                    took = True
            if not took:
                break

        picked.sort(key=lambda pair: pair[1]["_at"], reverse=True)
        for kind, row in picked:
            out_rows.append((kind, row))
            shown[kind] += 1

    # SAY WHAT EACH ROW IS, AND WHAT IT CONNECTS TO
    me._mark_self_induced([r for _, r in out_rows if isinstance(r, dict)
                           and r.get("captured_at") is not None],
                          scan_windows)

    rows = []
    for kind, row in out_rows:
        say = _EXPLAIN[kind](row)
        target, no_link = _map_link(row, kind)

        did = say.get("detection_id") or row.get("detection_id")
        note = rule_note(did)
        known_id = did if (did and note.get("known")) else None

        rows.append({
            "kind":       kind,
            "id":         row.get("id"),
            "at":         row.get("_at"),
            "session_id": row.get("session_id"),
            "sensor_id":  row.get("sensor_id"),
            "severity":   row.get("severity"),
            # THE TWO LINKS IN FRONT OF A ROW, and each is a pair of "where to
            # go" and "why there is nowhere to go". A reader must never be
            # left wondering whether a missing link is a bug.
            "detection_id": known_id,
            "rule_note":  (None if known_id else note.get("reason")),
            "map_target": target,
            "map_note":   no_link,
            "what":       say["what"],
            "who":        say["who"],
            "where_from": say["where_from"],
            "why":        say["why"],
            "self_induced": bool(row.get("self_induced")),
            "self_induced_note": row.get("self_induced_note"),
            # The raw fields, thin on purpose: the explanation is the product
            # here and a second copy of the row is not.
            "detail": {
                "source":       row.get("source"),
                "event_type":   row.get("event_type"),
                "username":     row.get("username"),
                "src_ip":       row.get("src_ip"),
                "dst_ip":       row.get("dst_ip"),
                "dst_port":     row.get("dst_port"),
                "protocol":     row.get("protocol"),
                "scope":        row.get("scope"),
                "direction":    row.get("direction"),
                "packet_size":  row.get("packet_size"),
                "process_name": row.get("process_name"),
                "process_pid":  row.get("process_pid"),
                "threat_label": row.get("threat_label"),
                "entity_type":  row.get("entity_type"),
                "entity_value": row.get("entity_value"),
                "dismissed":    bool(row.get("dismissed")),
            },
        })

    # WHAT THIS ANSWER IS NOT (rule 3 and rule 2, in one place)
    notes = []

    unreadable = [k for k in ORDER if not read_ok.get(k)]
    if unreadable:
        notes.append(
            "COULD NOT READ: " + ", ".join(
                f"{k} ({read_errors.get(k)})" for k in unreadable)
            + ". Those records are MISSING from this list, so a gap here is a "
              "failed read and not a quiet machine.")

    cut = [k for k in ORDER if (totals.get(k) or 0) > shown[k]]
    if cut:
        notes.append(
            "THIS IS A SAMPLE, NOT EVERYTHING: "
            + ", ".join(f"{totals[k]} {k}s in the window and {shown[k]} shown"
                        for k in cut)
            + f". The list holds {limit} rows at most, spread across the "
              f"window in {SLICE_COUNT} equal time slices so that every part "
              f"of the window is represented and a finding keeps the traffic "
              f"from its own moment beside it. Narrow the window to see more "
              f"of any one stretch.")

    # A TIMESTAMP THAT COULD NOT BE PLACED IS COUNTED, NOT SWALLOWED. Rows only
    # reach a slice by asking for a time range, so this can only be a malformed
    # stamp inside an otherwise valid row, and it is the one case where a row
    # the window counted does not appear in the list and is NOT explained by
    # the cap above.
    if unplaceable:
        notes.append(
            f"{unplaceable} row(s) in this window carry a timestamp that could "
            f"not be read, so they are NOT in this list. The count above "
            f"includes them.")

    return {
        "rows":    rows,
        "window": {
            "since":     since_sql,
            "until":     until_sql,
            "defaulted": defaulted,
            "slices":    SLICE_COUNT,
            "per_slice": per_slice,
        },
        "totals":  totals,
        "shown":   shown,
        "read_ok": read_ok,
        "searched": ("all sessions" if all_sessions
                     else f"session {session_id} only"),
        # True only when every record type was read, every one of them fits in
        # what is shown, and nothing was dropped for an unreadable timestamp.
        "complete": (all(read_ok.get(k) for k in ORDER)
                     and all((totals.get(k) or 0) <= shown[k] for k in ORDER)
                     and not unplaceable),
        "note": " ".join(notes) if notes else None,
    }
