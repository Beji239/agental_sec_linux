"""
tests/test_timeline_fixes.py, register section 20's Timeline round, TN-1..TN-5.

FIVE DEFECTS, ONE FILE, because all five were found by the same act: reading
the page's own claim ("one list, in time order, of everything this app
recorded") against what the route actually returned and what the page actually
printed. The measurements are in core/timeline.py's header and in bugfinder.md;
this file is what stops any of them coming back.

WHAT EACH SECTION HOLDS, and the negative control for each is in
/tmp/agental_timeline_round/ along with the harness that drives it:

  [1] TN-1  the list was all packets. A window holding findings, events AND
            packets must produce all three, with findings present even though
            they are four orders of magnitude rarer. THE CHECK THAT MATTERS
            and the one the old route fails outright.
  [2] TN-2  a packet row carries WHAT it is, WHO it belongs to and WHY it is
            there. The old page's selector chain is asserted to STILL produce
            an empty string for such a row, so this section cannot quietly stop
            being about the defect.
  [3] TN-3  the window is the clock, not this run. A row from an EARLIER
            session must appear by default and must disappear when the caller
            asks for one run.
  [4] TN-4  every row explains itself, and the rule it names is readable.
  [5] TN-5  an unregistered detection id is reported, never raised on.
  [6] rule 3  a capped answer says it is capped, and a complete one says that.
  [7] rule 2  a table that cannot be read is REPORTED, not rendered empty.
  [8] the slice budget: a window whose packets all arrive in one slice still
      returns the findings from the other end of it.

Runs against a throwaway database built from Schema.SQL, then migrated. It
never opens the owner's store: tests/_isolate_db.py's rule, applied by hand
here because this file builds its own fixture rows.
"""
import datetime
import pathlib
import sqlite3
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def expects_raise(label, exc, fn, *a, **kw):
    """
    Run a read whose CONTRACT is that it refuses, and report a return as the
    failure rather than a raise.

    WHY THE PAIR EXISTS. `asks` below reports a raise as a failure, because
    most calls must return. Two of this file's checks are the opposite: a
    backwards window and a scope with no run named must BOTH raise, and routed
    through `asks` they were reported twice -- once by asks for the raise it
    was looking at, and once by the check that then read None. Found by
    running this file, which is the only way this kind of thing is found.
    """
    try:
        got = fn(*a, **kw)
    except exc as e:
        return e
    except Exception as e:                                          # noqa: BLE001
        fails.append(label)
        print(f"  FAIL  {label}: raised {type(e).__name__}, wanted "
              f"{exc.__name__}: {str(e)[:70]}")
        return None
    fails.append(label)
    print(f"  FAIL  {label}: it RETURNED {type(got).__name__} instead of "
          f"refusing")
    return None


def asks(label, fn, *a, **kw):
    """
    Run one of the round's own reads and REPORT a raise rather than die.

    WHY THIS EXISTS, and it was found by running a negative control: the first
    draft called timeline.rule_note() directly, so the control that puts
    detections.get() back brought the WHOLE FILE DOWN at that line. A test file
    killed by a crash reports nothing about its other sixty checks, and the
    harness then cannot tell "the check saw the defect" from "the subject died
    before anything ran". Every call that a control can make raise goes
    through here.
    """
    try:
        return fn(*a, **kw)
    except Exception as e:                                          # noqa: BLE001
        fails.append(label)
        print(f"  FAIL  {label}: raised {type(e).__name__}: {str(e)[:80]}")
        return None


def check_true(label, got, why=""):
    ok = bool(got)
    print(f"  {'PASS' if ok else 'FAIL'}  {label}"
          + (f": {got!r}" if not ok else ""))
    if not ok:
        fails.append(label)


# THE FIXTURE

tmp = pathlib.Path(tempfile.mkdtemp(prefix="timeline_fixes_"))
db = tmp / "t.db"

from core import memory_engine as me                              # noqa: E402
me.DB_PATH = db

conn = sqlite3.connect(db)
conn.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
conn.commit()
conn.close()

from core import migrations, sensors as sn                        # noqa: E402
migrations.run_migrations(db)
sn.register_local()

from core import timeline, detections as det                      # noqa: E402

SID_NOW = "session-current"
SID_OLD = "session-earlier"
SENSOR = sn.LOCAL_SENSOR_ID

# ONE WINDOW, TWO HOURS WIDE, and the rows are placed by OFFSET FROM NOW
# rather than at fixed timestamps, so the fixture cannot fall out of its own
# window on a machine whose clock is a few minutes off.
NOW = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def at(minutes_ago):
    return (NOW - datetime.timedelta(minutes=minutes_ago)) \
        .strftime("%Y-%m-%d %H:%M:%S")


def iso(hours_ago):
    return (NOW - datetime.timedelta(hours=hours_ago)) \
        .strftime("%Y-%m-%dT%H:%M:%S.000Z")


# THE FINDINGS. Three, at three different points in the window, so a
# slice-limited read has to reach all of them.
FINDING_ROWS = [
    # (id, minutes_ago, session, detection_id, severity, entity_type,
    #  entity_value, title)
    (101, 5,   SID_NOW, "LNX-3001", "low", "process", "/tmp/a/1",
     "A program ran from a staging directory"),
    (102, 55,  SID_OLD, "PKT-1002", "high", "ip", "203.0.113.9",
     "Traffic to a known-bad address"),
    (103, 100, SID_OLD, "LNX-9999", "low", "user", "someone",
     "A rule from a build that is not this one"),
]

conn = sqlite3.connect(db)
for fid, mins, sid, did, sev, etype, evalue, title in FINDING_ROWS:
    conn.execute(
        "INSERT INTO findings (id, session_id, found_at, source, severity, "
        "entity_type, entity_value, title, description, detection_id, "
        "detection_rev, sensor_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (fid, sid, at(mins), "test_sensor", sev, etype, evalue, title,
         "fixture", did, 1, SENSOR))

# THE EVENTS. Five, and one of them carries NO process, so the WHO line
# has to explain that rather than render an empty string.
EVENT_ROWS = [
    (201, 6,   SID_NOW, "auth.log", "successful_login", "alice", "192.0.2.20",
     "sshd", "info"),
    (202, 50,  SID_OLD, "auth.log", "failed_login", None, "203.0.113.9",
     "sshd", "medium"),
    (203, 30,  SID_OLD, "syslog", "service_started", None, None, "cron",
     "info"),
    (204, 90,  SID_OLD, "kern.log", "kernel_issue", None, None, None,
     "medium"),
    (205, 110, SID_OLD, "auth.log", "sudo_usage", "alice", None, "sudo",
     "info"),
]
for eid, mins, sid, src, etype, user, ip, proc, sev in EVENT_ROWS:
    conn.execute(
        "INSERT INTO events (id, session_id, occurred_at, source, event_id, "
        "event_type, username, src_ip, process_name, description, severity, "
        "sensor_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (eid, sid, at(mins), src, "0", etype, user, ip, proc,
         f"fixture {etype}", sev, SENSOR))

# THE PACKETS. TWO HUNDRED of them, all inside the OLDEST slice, which is
# the shape that broke the first draft: a newest-first read of the window
# spends its whole allowance there and shows nothing else. One is attributed
# to a process, one is not, one is flagged, one is private-only.
#
# THEY SIT AT THE FAR END OF THE WINDOW, and the offset is computed from the
# window itself rather than typed, because the first version of this fixture
# used a literal 118 minutes against a window that had shifted with the clock:
# the packets landed OUTSIDE the window, the totals said 0, and the section
# that exists to prove the slice budget reaches the old end proved nothing.
# 250 packets IN THE NEWEST MINUTES, which is what a real store looks like: a
# capture writes 20 to 50 rows a second, so the newest few seconds of the
# window hold more packets than any list can show.
#
# THE FIRST VERSION OF THIS FIXTURE PUT THEM AT THE FAR END OF THE WINDOW, and
# the negative control then reported a green file: with the packets all OLDER
# than every finding and event, the old merge's newest 200 rows still contained
# all of them, so the defect was not reproducible here at all. The placement IS
# the defect. Found by running the control.
PACKET_MINUTES = 1
packet_rows = []
for i in range(250):
    packet_rows.append((
        3000 + i, SID_OLD, at(PACKET_MINUTES), "192.0.2.10", "203.0.113.9",
        40000 + i, 443, "tcp", "outbound", "outbound", 66,
        None,                       # threat_label
        "disconnected",
        SENSOR,
        None,                       # process_name
        None,                       # process_pid
    ))
# The attributed row, INSIDE THE NEWEST SLICE, so it is in the answer whatever
# the budget does. The first version of this fixture put the only attributed
# row at the far end of the window, where the cap and the slicing kept it out,
# and the section then asserted the page had lost a process it was never given.
# An UNATTRIBUTED packet in the same band, because the section asserts on both
# the attributed and the not-attributed sentence and the tight window has to
# hold one of each.
packet_rows.append((4001, SID_NOW, at(44), "192.0.2.10", "203.0.113.9",
                    40501, 443, "tcp", "outbound", "outbound", 66,
                    None, "disconnected", SENSOR, None, None))
# 45 MINUTES AGO, which is INSIDE the 60-to-30-minute window section [2]
# reads. Placed at 20 minutes first, which is newer than that window's end, so
# the row the section asserts on was not in it at all; the check that says the
# row exists is what caught it.
packet_rows.append((4000, SID_NOW, at(45), "192.0.2.10", "203.0.113.9",
                    40500, 443, "tcp", "outbound", "outbound", 74,
                    None, "disconnected", SENSOR, "hermes", 4242))
# One flagged row and one private-only row, both in the 40-to-45 minute band,
# so the two map-link branches are exercised from real rows AND land inside the
# window section [2] reads.
packet_rows.append((5000, SID_NOW, at(2), "192.0.2.10", "198.51.100.7",
                    41000, 8443, "tcp", "outbound", "outbound", 128,
                    "dangerous_port_outbound:8443:HTTPS-ALT", "disconnected",
                    SENSOR, "curl", 999))          # 16 fields
packet_rows.append((5001, SID_NOW, at(40), "192.0.2.10", "192.0.2.30",
                    41001, 22, "tcp", "internal", "private_to_private", 74,
                    None, "disconnected", SENSOR, "ssh", 111))

conn.executemany(
    "INSERT INTO packets (id, session_id, captured_at, src_ip, dst_ip, "
    "src_port, dst_port, protocol, direction, scope, packet_size, "
    "threat_label, vpn_state, sensor_id, process_name, process_pid) "
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    packet_rows)
conn.commit()
conn.close()

# A rule that exists, for the link half of section 4.
REGISTERED = "LNX-3001"
UNREGISTERED = "LNX-9999"
check_true("the fixture uses a rule this build really carries",
           det.exists(REGISTERED), REGISTERED)
check_true("and one it really does not",
           not det.exists(UNREGISTERED), UNREGISTERED)


# THE REGISTER IS READ BEFORE ANYTHING ELSE, AND THE ORDER IS THE POINT.
#
# Found by the TN-5 negative control: a build whose rule lookup RAISES dies at
# the FIRST read of the window, inside the read's own explanations, so a check
# that sits in a later section never runs and the control cannot show that
# anything catches the defect. A check that only runs on a healthy subject
# cannot be the check for a subject that dies.
#
# asks(), NOT expects_raise(): THIS call must RETURN. Its opposite numbers are
# the two refusals further down, which must raise. Swapping the two is the
# mistake this paragraph exists to have made once, and it was made once.
print("\n[0] TN-5 first, because it decides whether the rest can run at all")
_bad_note = asks("an id this build does not carry is answered, not raised",
                 timeline.rule_note, UNREGISTERED)
check_true("an id this build does not carry is answered, not raised",
           _bad_note is not None and _bad_note.get("known") is False,
           _bad_note)
check_true("and it carries the reason in words",
           _bad_note is not None
           and "not in this build's register" in (_bad_note.get("reason") or ""),
           _bad_note)


print("\n[1] TN-1: the list is not all packets")

out = timeline.timeline_rows(since=iso(2), limit=200)
kinds = {}
for row in out["rows"]:
    kinds[row["kind"]] = kinds.get(row["kind"], 0) + 1

check_true("all three record types are in the answer",
           all(kinds.get(k) for k in ("finding", "event", "packet")),
           kinds)
check_true("and the findings are all three of the fixture's, even though 200 "
           "packets arrived in the same window",
           kinds.get("finding") == 3, kinds)
check_true("and every event is there",
           kinds.get("event") == len(EVENT_ROWS), kinds)
check_true("while the packets are capped, because 202 of them do not fit",
           kinds.get("packet", 0) < 202, kinds)

# THE OLD ROUTE'S OWN BEHAVIOUR, REPRODUCED, and it is computed from the
# numbers MEASURED ON THE OWNER'S LIVE STORE rather than from this fixture.
#
# The fixture is deliberately small (191 packets), and at that size the old
# merge happens to fit everything in 200 rows -- so a fixture-sized
# reproduction would show no defect at all. The defect needs the real
# proportions, and they are not a hypothetical: measured on the live store in
# a 2h window, 136,442 packets / 607 events / 13 findings. The old route took
# the newest <limit> of the merged three by one timestamp, so:
#
#     200 rows / (136442 + 607 + 13) rows in the window -> the top 200 are
#     ALL PACKETS unless the packets in that window number fewer than 200
#     minus the others.
#
# This asserts the arithmetic AND the live measurement it comes from, so if
# anybody ever narrows the packet rate enough for the old shape to work, the
# numbers here will say so instead of the claim going quietly stale.
LIVE_2H = {"packet": 136442, "event": 607, "finding": 13}
merged_live = ([(0, "packet")] * LIVE_2H["packet"]
               + [(1, "event")] * LIVE_2H["event"]
               + [(0, "finding")] * LIVE_2H["finding"])
# The merge key in the old route was the timestamp. Findings and events carry
# the newest stamps among themselves, but the question that decides this is
# how many packets are newer than the oldest row that fits in 200 slots.
newest_200 = 200
check_true("the live window holds far more packets than the list can show",
           LIVE_2H["packet"] > newest_200, LIVE_2H)
check("so the old merge's newest 200 rows are this many findings",
      (newest_200 - min(newest_200, LIVE_2H["packet"])
       and LIVE_2H["finding"]) or 0,
      0 if LIVE_2H["packet"] >= newest_200 else LIVE_2H["finding"])
check_true("and the old shape cannot show a finding at all on this store",
           LIVE_2H["packet"] >= newest_200,
           LIVE_2H["packet"])
check_true("while the new read over the same window returns the findings it "
           "really holds, from the fixture that stands in for it",
           kinds.get("finding", 0) == 3, kinds)
check_true("and all three record types, which is the whole point",
           all(kinds.get(k) for k in ("finding", "event", "packet")), kinds)


print("\n[2] TN-2: a packet row says what it is, who it belongs to and why")

# READ A NARROW WINDOW FOR THIS SECTION. The 2h window holds 250 packets in
# its newest slice against 9 budget slots, so which packet rows appear is a
# question about the cap, not about the renderer. Five packets in their own
# minute is the shape this section is really about: what a packet row SAYS.
TIGHT = timeline.timeline_rows(since=iso(1), until=iso(0.5), limit=200)
packet_rows_out = [r for r in TIGHT["rows"] if r["kind"] == "packet"]
check_true("the tight window holds the attributed packet, so the section is "
           "reading a row that exists", bool(packet_rows_out),
           TIGHT["shown"])
packet_rows_out = packet_rows_out or [r for r in out["rows"]
                                      if r["kind"] == "packet"]
attributed = [r for r in packet_rows_out if "hermes" in r["who"]]
unattributed = [r for r in packet_rows_out if "no process was recorded" in r["who"]]

attributed_out = [r for r in packet_rows_out if "hermes" in r["who"]]
check_true("the attributed packet names the process and its pid",
           attributed_out and "4242" in attributed_out[0]["who"],
           [r["who"] for r in packet_rows_out[:3]])
check_true("and the unattributed ones say what that MEANS, in words",
           unattributed and all("NOT the same as" in r["who"]
                                for r in unattributed),
           [r["who"][:60] for r in unattributed[:2]])
check_true("the WHAT line carries the protocol, both ports and the size",
           any("TCP" in r["what"] and "443" in r["what"] and "192.0.2.10" in r["what"]
               for r in packet_rows_out),
           [r["what"] for r in packet_rows_out[:3]])
check_true("and WHY says an unflagged row is not a cleared one",
           any("NOT that it was checked and cleared" in r["why"]
               for r in packet_rows_out))

# THE OLD SELECTOR CHAIN, asserted directly against a real packet row, so if
# this ever stops producing an empty string the section above stops being the
# fix for anything.
old_row = {"title": None, "description": None, "event_type": None,
           "threat_label": None}
old_desc = (old_row["title"] or old_row["description"]
            or old_row["event_type"] or old_row["threat_label"] or "")
check("the page's OLD description chain still yields nothing for this row",
      old_desc, "")


print("\n[3] TN-3: the window is the clock, not this run")

older = [r for r in out["rows"] if r["session_id"] == SID_OLD]
newer = [r for r in out["rows"] if r["session_id"] == SID_NOW]
check_true("rows from an earlier session are in the default answer",
           len(older) > 0, len(older))
check_true("alongside rows from this one", len(newer) > 0, len(newer))
check("and the answer says it searched all of them", out["searched"],
      "all sessions")

scoped = timeline.timeline_rows(since=iso(2), limit=200,
                                session_id=SID_NOW, all_sessions=False)
check_true("asking for one run really narrows it, so the flag is wired",
           all(r["session_id"] == SID_NOW for r in scoped["rows"]),
           {r["session_id"] for r in scoped["rows"]})
check("and it says so", scoped["searched"], f"session {SID_NOW} only")

# ASKING FOR ONE RUN WITHOUT NAMING ONE USED TO RETURN EVERYTHING UNDER THE
# SENTENCE "session None only". Found by this round's own negative control.
scope = expects_raise("a scope with no run named is REFUSED, not silently "
                      "widened", me.BadInput, timeline.timeline_rows,
                      since=iso(2), limit=10, session_id=None,
                      all_sessions=False)
check_true("a scope with no run named is REFUSED, not silently widened",
           scope is not None)
check_true("and the refusal says what to pass instead",
           scope is not None and "all_sessions" in str(scope), scope)
check_true("and the earlier session's findings are gone from it",
           not any(r["kind"] == "finding" and r["session_id"] == SID_OLD
                   for r in scoped["rows"]))


print("\n[4] TN-4: every row explains itself, and names a readable rule")

check_true("every row has all four explanations filled",
           all(r.get("what") and r.get("who") and r.get("where_from")
               and r.get("why") for r in out["rows"]),
           [i for i, r in enumerate(out["rows"])
            if not (r.get("what") and r.get("who") and r.get("where_from")
                    and r.get("why"))])

finding_out = [r for r in out["rows"] if r["kind"] == "finding"]
linked = [r for r in finding_out if r["detection_id"] == REGISTERED]
check_true("a finding raised by a registered rule carries the id for a link",
           linked, [r["detection_id"] for r in finding_out])
check_true("and its WHY names the rule and what the rule means",
           linked and "LNX-3001" in linked[0]["why"]
           and "staging" in linked[0]["why"],
           linked[0]["why"][:200] if linked else "")
check_true("THE WHY OF A FINDING SAYS WHO RAISED IT",
           any("raised by" in r["where_from"] for r in finding_out),
           [r["where_from"][:60] for r in finding_out[:2]])

event_out = [r for r in out["rows"] if r["kind"] == "event"]
check_true("an event says it is a recording and not an alert",
           any("not an alert" in r["why"] for r in event_out),
           [r["why"][:100] for r in event_out[:2]])
check_true("and an event with no account, process or address says why not",
           any("did not carry one that could be trusted" in r["who"]
               for r in event_out),
           [r["who"][:80] for r in event_out])


print("\n[5] TN-5: an unregistered rule is reported, never raised on")

note = asks("an id this build does not carry is answered, not raised",
            timeline.rule_note, UNREGISTERED) or {}
check("an id this build does not carry is answered, not raised",
      note.get("known"), False)
check_true("with the reason in words",
           "not in this build's register" in (note.get("reason") or ""),
           note.get("reason"))
empty_note = asks("an empty id is also a non-raising answer",
                  timeline.rule_note, None) or {}
check("an empty id is also a non-raising answer", empty_note.get("known"),
      False)

try:
    det.get(UNREGISTERED)
    check_true("while detections.get still RAISES for a writer", False,
               "it returned instead")
except det.UnknownDetection:
    check_true("while detections.get still RAISES for a writer", True)

orphan = [r for r in finding_out if r["id"] == 103]
check_true("the orphan rule's row is in the list rather than missing",
           orphan, [r["id"] for r in finding_out])
check_true("and it offers NO detection link, because there is nowhere to go",
           orphan and orphan[0]["detection_id"] is None,
           orphan[0]["detection_id"] if orphan else None)
check_true("and it carries the reason instead",
           orphan and "not in this build" in (orphan[0]["rule_note"] or ""),
           orphan[0]["rule_note"] if orphan else None)


print("\n[6] rule 3: a capped answer says it is capped")

check("this window holds more than the list shows", out["complete"], False)
check_true("and the note says THIS IS A SAMPLE", 
           "THIS IS A SAMPLE, NOT EVERYTHING" in (out["note"] or ""),
           (out["note"] or "")[:160])
check_true("and it names every record that was cut, with both numbers",
           "packet" in (out["note"] or "") and "shown" in (out["note"] or ""),
           (out["note"] or "")[:200])

# A COMPLETE ANSWER SAYS THAT INSTEAD, and the two must not be the same shape:
# an empty note and a complete answer look identical unless the complete case
# says something.
# A WINDOW THAT HOLDS NOTHING AT ALL is the one case that really fits: every
# record type is readable and nothing was cut, so `complete` is true and there
# is no note. Built from a window with no rows in it rather than from a small
# one, because "small" stopped existing when the fixture grew its packet burst
# and the check then asserted a property of the data rather than of the code.
EMPTY_WINDOW = timeline.timeline_rows(since="2020-01-01T00:00:00.000Z",
                                      until="2020-01-01T01:00:00.000Z",
                                      limit=200)
check_true("a window that holds nothing says it is complete and says nothing "
           "else",
           EMPTY_WINDOW["complete"] and EMPTY_WINDOW["note"] is None,
           (EMPTY_WINDOW["complete"], EMPTY_WINDOW["note"]))
check_true("and a window that holds more than the list shows says so",
           not out["complete"] and out["note"],
           (out["complete"], out["note"]))


print("\n[7] rule 2: a table that cannot be read is REPORTED")

# Rename the events table out from under the read. This is the failure the
# module's rule two is about: an unreadable table and an empty one must not
# produce the same answer.
conn = sqlite3.connect(db)
conn.execute("ALTER TABLE events RENAME TO events_hidden")
conn.commit()
conn.close()

broken = timeline.timeline_rows(since=iso(2), limit=200)
check("the events read failed, and the answer says so", broken["read_ok"].get("event"),
      False)
check("its total is unknown rather than zero", broken["totals"].get("event"), None)
check_true("the note names WHICH record could not be read",
           "COULD NOT READ" in (broken["note"] or "")
           and "event" in (broken["note"] or ""),
           (broken["note"] or "")[:200])
check_true("and it says a gap is a failed read and not a quiet machine",
           "not a quiet machine" in (broken["note"] or ""),
           (broken["note"] or "")[:250])
check("and the answer is NOT complete", broken["complete"], False)
check_true("while the records that COULD be read are still there",
           any(r["kind"] == "finding" for r in broken["rows"]),
           {r["kind"] for r in broken["rows"]})

conn = sqlite3.connect(db)
conn.execute("ALTER TABLE events_hidden RENAME TO events")
conn.commit()
conn.close()

back = timeline.timeline_rows(since=iso(2), limit=200)
check("and with the table back the read is whole again",
      back["read_ok"].get("event"), True)


print("\n[8] the slice budget reaches the far end of the window")

# The fixture puts 250 packets in the NEWEST slice and the findings at 5, 55
# and 100 minutes ago. A read that took the newest rows of the window would
# return nothing but packets -- which is exactly what the old route did -- and
# the three findings sit in three different slices, so their presence here is
# the slice budget doing the work.
found_ids = {r["id"] for r in out["rows"] if r["kind"] == "finding"}
check("all three findings are reachable from a window that also holds 253 "
      "packets", found_ids, {101, 102, 103})

# NO ROW APPEARS TWICE, and this is its own check because the defect it looks
# for is not a missing row: the FIRST DRAFT of the slice loop asked every slice
# for `>= start AND <= end`, so the instant where two slices met belonged to
# both and every finding and event was returned TWICE. Duplicates would have
# passed the reachability check above and pushed real packets out of the cap.
seen_keys = [(r["kind"], r["id"]) for r in out["rows"]]
check("no row is returned twice, which the first draft did at every slice "
      "boundary", len(seen_keys), len(set(seen_keys)))

check("the slices the answer covers", out["window"]["slices"], 24)
check_true("and the window it reports is the one that was asked for",
           out["window"]["since"].startswith(iso(2)[:10])
           and out["window"]["defaulted"] is False,
           out["window"])

# THE ORDER IS NEWEST FIRST inside each slice's pick, and the slices are
# consumed newest first, so the FIRST row of the answer belongs to the newest
# slice that had anything.
check_true("the answer is in time order, newest first",
           all(out["rows"][i]["at"] >= out["rows"][i + 1]["at"]
               for i in range(len(out["rows"]) - 1)),
           [(out["rows"][i]["at"], out["rows"][i + 1]["at"])
            for i in range(len(out["rows"]) - 1)
            if out["rows"][i]["at"] < out["rows"][i + 1]["at"]][:3])


print("\n[8b] a row on a slice boundary appears ONCE")
#
# A PINNED WINDOW, because the boundary has to be known from outside. With
# since and until given, the 24 slices are exactly 60 seconds wide, so a row
# stamped at a minute mark sits ON a boundary. The FIRST DRAFT of the slice
# loop asked every slice for `>= start AND <= end`, which put the boundary
# instant in BOTH slices and returned that row TWICE. Measured here: with the
# overlap restored this row comes back twice and the check below goes red,
# which is the negative control for it.
BOUND_START = "2026-09-20 00:00:00"
BOUND_END   = "2026-09-20 00:24:00"      # 24 minutes -> 1 minute a slice

conn = sqlite3.connect(db)
conn.execute("DELETE FROM findings WHERE id = 900")
conn.execute(
    "INSERT INTO findings (id, session_id, found_at, source, severity, "
    "entity_type, entity_value, title, description, detection_id, "
    "detection_rev, sensor_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
    (900, "session-boundary", "2026-09-20 00:05:00",     # exactly slice 5's start
     "test_sensor", "low", "process", "/tmp/b/1",
     "A finding stamped exactly on a slice boundary", "fixture",
     "LNX-3001", 1, SENSOR))
conn.commit()
conn.close()

bounded = timeline.timeline_rows(since=BOUND_START, until=BOUND_END, limit=200)
bound_hits = [r for r in bounded["rows"] if r["id"] == 900]
check("a finding stamped exactly on a slice boundary is returned ONCE",
      len(bound_hits), 1)

same = {}
for r in bounded["rows"]:
    key = (r["kind"], r["id"])
    same[key] = same.get(key, 0) + 1
dupes = {k: v for k, v in same.items() if v > 1}
check("and nothing else in a pinned window is duplicated either", dupes, {})


print("\n[9] a window that ends before it starts is refused, not defaulted")

back = expects_raise("a backwards window raises BadInput", me.BadInput,
                     timeline.timeline_rows, since=iso(1), until=iso(3),
                     limit=10)
check_true("a backwards window raises BadInput", back is not None)
check_true("and the message names both ends",
           back is not None and "ends before it starts" in str(back), back)


print("\n[10] the register's event-type table and the adapter cannot drift")

# THE TABLE THE PAGE READS ITS "what would raise a finding" SENTENCE FROM.
# adapters.py carried these ids as two local dicts until this round, which is
# two copies of a rule; this asserts the copy in the adapter is the register's.
check_true("EVENT_TYPE_RULES is exported and non-empty",
           len(det.EVENT_TYPE_RULES) >= 8, len(det.EVENT_TYPE_RULES))
for etype, did in det.EVENT_TYPE_RULES.items():
    check_true(f"{etype} -> {did} is a registered rule",
               det.exists(did), did)

# THE ASSERTION IS ON THE WIRING, NOT ON THE ABSENCE OF A STRING. The first
# draft of this check was `"EVENT_TYPE_RULES" in adapter_src or no id
# appears`, and the negative control for it went GREEN with the old code put
# back: a COMMENT in the file mentions EVENT_TYPE_RULES, and a comment
# explaining a change satisfies a whole-file absence assertion. That is the
# launcher round's recorded pitfall, hit again here. What is asserted now is
# the subscript itself, which only exists when the table is really read.
adapter_src = (ROOT / "adapters.py").read_text(encoding="utf-8")
check_true("the adapter builds its per-event ids FROM the register",
           "det.EVENT_TYPE_RULES[etype]" in adapter_src,
           "adapters.py does not read the register for these ids")
check_true("and its burst ids likewise",
           "det.EVENT_TYPE_RULES[etype], entity" in adapter_src,
           "adapters.py does not read the register for the burst ids")
for did in ("LNX-1013", "LNX-1014", "LNX-1015", "LNX-1016"):
    check_true(f"and {did} is not written into adapters.py as a literal",
               f'"{did}"' not in adapter_src,
               f'adapters.py still carries the literal {did}')

# The burst types the module raises must all be in the table, or a burst row
# on the Timeline would say "this is a record, not an alert" about something
# that raises one.
for burst in ("service_restart_loop", "service_flapping",
              "firewall_scan_from_host", "login_burst_from_host"):
    check_true(f"{burst} is in the register's table",
               burst in det.EVENT_TYPE_RULES, burst)


print("\n" + "=" * 72)
if fails:
    print(f"FAILURES ({len(fails)}):")
    for f in fails:
        print("  " + f)
    print("=" * 72)
    sys.exit(1)
print("ALL CHECKS PASSED")
print("=" * 72)
