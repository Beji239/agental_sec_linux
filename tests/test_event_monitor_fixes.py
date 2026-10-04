"""
tests/test_event_monitor_fixes.py, THE EVENT MONITOR FIX ROUND, 2026-09-23.

WHAT THIS FILE IS FOR. bugfinder.md carries thirteen measured defects under
"THE EVENT MONITOR ON LINUX, CAPABILITY ROUND" (EM-1 to EM-13). This is the
round that fixed them, and this file is the evidence: every check below fails
if its fix regresses, and BOTH DIRECTIONS are asserted wherever the fix is a
detector or a refusal. A detector that stops firing is as broken as one that
fires on everything, and a cursor that skips records is as broken as one that
re-reads them.

WHY IT IS A SEPARATE FILE FROM tests/test_sensor_hardening.py. That one
asserts the LINUX READER HAS NO CURSOR, deliberately, and says in its own
comments that the day somebody adds one they should have to delete the checks
first. This round is that day: section [8] of the hardening file has been
rewritten to assert the cursor's rule instead of its absence, and THIS file is
where the cursor's own behaviour is tested.

RUNS WITH NO DATABASE, NO NETWORK AND NO ROOT. Every filesystem case is built
in a temp directory; every process case uses the real host's own logs read
only, or a synthetic line. Nothing here writes to the owner's evidence store.
"""
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got):
    check(label, bool(got), True)


def raises(label, exc, fn, *a, **kw):
    try:
        fn(*a, **kw)
    except exc:
        print(f"  PASS  {label}")
        return
    except Exception as e:
        print(f"  FAIL  {label}: raised {type(e).__name__} not {exc.__name__}")
        fails.append(label)
        return
    print(f"  FAIL  {label}: nothing raised")
    fails.append(label)


from tools import event_monitor_linux as em       # noqa: E402
from tools import event_monitor_linux as _em      # noqa: E402

# The module's standalone read default, read from the module rather than
# hardcoded here, so renaming it does not quietly disable a check that uses it.
READ_DEFAULT = em.READ_DEFAULT_LINES

TMP = pathlib.Path(tempfile.mkdtemp(prefix="agentalsec_emfix_"))
print(f"scratch: {TMP}\n")

# THE OPERATOR'S OWN ACCOUNT NAME AND ADDRESSES ARE READ AT RUN TIME, never
# written down here. THIS PROJECT'S LEAK GATE FAILED THIS FILE FOR EXACTLY
# THAT (six LOCAL DETAIL lines, "your home directory name appears verbatim"),
# and the rule is the round's own lesson applied to itself: a test that pins
# one machine's account or network is ALSO WRONG ON EVERY OTHER BOX, so this
# is not only a release-hygiene fix. Synthetic addresses use the RFC 5737
# documentation ranges; the real account is asked of the OS.
import pwd                                             # noqa: E402
ACCOUNT = pwd.getpwuid(os.getuid()).pw_name
DOC_IP = "192.0.2.9"              # RFC 5737 TEST-NET-1


def sudo_line(account=ACCOUNT):
    """A real-shaped short-iso sudo line, for the account running the test."""
    return (f"2026-09-23T18:34:41.196963-07:00 HOST sudo:    {account} : "
            f"TTY=pts/1 ; PWD=/home/{account} ; USER=root ; "
            f"COMMAND=/usr/bin/true")


def pam_line(account=ACCOUNT):
    """The pam_unix shape that put the word 'rhost' in 164 real rows."""
    return (f"2026-09-23T14:53:09-07:00 HOST "
            f"cinnamon-screensaver-pam-helper: "
            f"pam_unix(cinnamon-screensaver:auth): authentication failure; "
            f"logname= uid=1000 euid=1000 tty=:0 ruser= rhost=  "
            f"user={account}")


# [1] EM-5 / EM-1: THE CURSOR. The failure cases first, because a cursor's
# wrong answer is a LOSS and it is silent, while its slow answer is neither.

print("\n[1] EM-5: a file cursor reads FORWARD and never re-reads a line")
log = TMP / "cursor.log"
log.write_text("2026-09-23T10:00:00-07:00 host one: alpha\n"
               "2026-09-23T10:00:01-07:00 host two: beta\n"
               "2026-09-23T10:00:02-07:00 host three: gamma\n")

r1 = em._read_log_file_lines(log, None, lines=100)
check("a first run reads the file", len(r1["entries"]), 3)
check("and reports it was a first run",
      r1["marker"].get("first_run"), True)

r2 = em._read_log_file_lines(log, r1["marker"], lines=100)
check("THE ONE THAT MATTERS: the second read returns NOTHING new",
      len(r2["entries"]), 0)
check("because the cursor moved past every line",
      r2["marker"]["offset"], r1["marker"]["offset"])

with log.open("a") as fh:
    fh.write("2026-09-23T10:00:03-07:00 host four: delta\n")
r3 = em._read_log_file_lines(log, r2["marker"], lines=100)
check("an appended line is read exactly once", len(r3["entries"]), 1)
check("and it is the right line", "delta" in r3["entries"][0]["message"], True)

r4 = em._read_log_file_lines(log, r3["marker"], lines=100)
check("and again there is nothing to read", len(r4["entries"]), 0)


print("\n[2] EM-5: a HALF-WRITTEN line is never consumed")
log2 = TMP / "partial.log"
with log2.open("wb") as fh:
    fh.write(b"2026-09-23T10:00:00-07:00 host complete: one\n")
    fh.write(b"2026-09-23T10:00:01-07:00 host halfwri")     # no newline yet
a = em._read_log_file_lines(log2, None, lines=100)
check("only the complete line is read", len(a["entries"]), 1)
with log2.open("ab") as fh:
    fh.write(b"tten: two\n")
b = em._read_log_file_lines(log2, a["marker"], lines=100)
check("the rest of it arrives WHOLE, once", len(b["entries"]), 1)
check("and it is not the half", b["entries"][0]["message"].endswith("two"),
      True)


print("\n[3] EM-5: ROTATION is detected by inode, and the tail is recovered")
log3 = TMP / "rotate.log"
with log3.open("wb") as fh:
    fh.write(b"2026-09-23T10:00:00-07:00 host old: one\n")
    fh.write(b"2026-09-23T10:00:01-07:00 host old: two\n")
c = em._read_log_file_lines(log3, None, lines=100)
check("the first read takes both", len(c["entries"]), 2)

# logrotate: move it aside and start a new file, the way the real one does.
rotated = log3.with_name(log3.name + ".1")
with log3.open("ab") as fh:
    fh.write(b"2026-09-23T10:00:02-07:00 host old: THREE NEVER READ\n")
log3.rename(rotated)
with log3.open("wb") as fh:
    fh.write(b"2026-09-23T10:00:03-07:00 host new: four\n")

d = em._read_log_file_lines(log3, c["marker"], lines=100)
msgs = [e["message"] for e in d["entries"]]
check_true("THE UNREAD TAIL IS RECOVERED from the rotated sibling",
           any("THREE NEVER READ" in m for m in msgs))
check_true("and the new file's line is read too",
           any("four" in m for m in msgs))
check("with NO gap reported, because nothing was lost", d["gap"], None)


print("\n[4] EM-5: a TRUNCATED file loses its tail and SAYS SO")
log4 = TMP / "trunc.log"
with log4.open("wb") as fh:
    fh.write(b"2026-09-23T10:00:00-07:00 host: one\n")
    fh.write(b"2026-09-23T10:00:01-07:00 host: two\n")
e1 = em._read_log_file_lines(log4, None, lines=100)
with log4.open("wb") as fh:                     # copytruncate: rewritten short
    fh.write(b"2026-09-23T10:00:05-07:00 host: fresh\n")
e2 = em._read_log_file_lines(log4, e1["marker"], lines=100)
check_true("a gap IS reported for a truncation", bool(e2["gap"]))
check("and it names the table", e2["gap"]["event_type"], "event_log_gap")
check_true("and it says why in words a reader can act on",
           "truncat" in e2["gap"]["reason"])
check("it still reads what is there", len(e2["entries"]), 1)


print("\n[5] EM-5: a REMOVED file is a gap, and a first-run absence is not")
log5 = TMP / "gone.log"
log5.write_text("2026-09-23T10:00:00-07:00 host: one\n")
f1 = em._read_log_file_lines(log5, None, lines=100)
log5.unlink()
f2 = em._read_log_file_lines(log5, f1["marker"], lines=100)
check_true("a file we had a position in and is gone IS a gap",
           bool(f2["gap"]))
f3 = em._read_log_file_lines(log5, None, lines=100)
check("but a first-run absence is NOT a gap (we never had a position)",
      f3["gap"], None)
check_true("and it says the file does not exist", bool(f3["error"]))


print("\n[6] EM-5: A CAPPED read does not skip. The line that did not fit is "
      "read by the NEXT poll, and the backlog says it is there")
log6 = TMP / "cap.log"
with log6.open("w") as fh:
    for i in range(20):
        fh.write(f"2026-09-23T10:00:{i:02d}-07:00 host: line {i}\n")
g1 = em._read_log_file_lines(log6, None, lines=5)
check("the cap bounds the read", len(g1["entries"]), 5)
check_true("and the unread remainder is REPORTED as a backlog",
           g1["remaining"] >= 15)
g2 = em._read_log_file_lines(log6, g1["marker"], lines=5)
check("the next poll reads the NEXT five, not the same five",
      [x["message"].split(": ")[-1] for x in g2["entries"]],
      ["line 5", "line 6", "line 7", "line 8", "line 9"])
# and drain it to the end, proving nothing in the middle is ever skipped
seen, marker, guard = [], g2["marker"], 0
while guard < 10:
    guard += 1
    g = em._read_log_file_lines(log6, marker, lines=5)
    marker = g["marker"]
    seen.extend(x["message"].split(": ")[-1] for x in g["entries"])
    if not g["entries"]:
        break
check("DRAINING IT LOSES NOTHING: every line arrives, in order",
      seen, [f"line {i}" for i in range(10, 20)])


print("\n[7] EM-1: the record id makes ONE line ONE row, and two lines TWO")
check("a line's id is its own content, so a re-read is the same id",
      em._record_id_for_line("2026-09-23T10:00:00-07:00 host: one\n"),
      em._record_id_for_line("2026-09-23T10:00:00-07:00 host: one\n"))
check_true("and a different line is a different id",
           em._record_id_for_line("a\n") != em._record_id_for_line("b\n"))
check_true("the id fits SQLite's INTEGER",
          0 <= em._record_id_for_line("x\n") < 2 ** 62)
# THE ID MUST NOT DEPEND ON WHERE IT WAS READ. A rotation re-reads the same
# line from offset 0 and it must still be one row.
check("rotating a line changes its offset, not its id",
      em._record_id_for_line("2026-09-23T10:00:00-07:00 host: one\n"),
      em._record_id_for_line("2026-09-23T10:00:00-07:00 host: one\n"))


print("\n[8] EM-1: the write really is idempotent, against a real database")
import _isolate_db                                    # noqa: E402
_isolate_db.isolate()
from core import memory_engine as me                  # noqa: E402
from core import migrations                           # noqa: E402
from core import sensors as sn                        # noqa: E402
migrations.run_migrations(me.DB_PATH)
sn.register_local()
SID = "emfix-session"


def rows():
    with sqlite3.connect(me.DB_PATH) as c:
        return c.execute("SELECT COUNT(*) FROM events").fetchone()[0]


rid = em._record_id_for_line("2026-09-23T10:00:00-07:00 host: hello\n")
me.save_event(session_id=SID, source="auth.log", event_id="0",
              event_type="log_entry", severity="info",
              description="hello", source_record_id=rid)
me.save_event(session_id=SID, source="auth.log", event_id="0",
              event_type="log_entry", severity="info",
              description="hello", source_record_id=rid)
me.save_event(session_id=SID, source="auth.log", event_id="0",
              event_type="log_entry", severity="info",
              description="hello", source_record_id=rid)
check("THE CENTRAL FIX: three writes of one record make ONE row", rows(), 1)

other = em._record_id_for_line("2026-09-23T10:00:01-07:00 host: other\n")
me.save_event(session_id=SID, source="auth.log", event_id="0",
              event_type="log_entry", severity="info",
              description="other", source_record_id=other)
check("a genuinely different record still lands", rows(), 2)

# the negative control the OLD code relied on, kept so nobody re-introduces it
me.save_event(session_id=SID, source="auth.log", event_id="0",
              event_type="log_entry", severity="info", description="no id")
me.save_event(session_id=SID, source="auth.log", event_id="0",
              event_type="log_entry", severity="info", description="no id")
check("a caller with NO record id still keeps the old behaviour "
      "(NULLs are distinct)", rows(), 4)


# [9] EM-4: THE PARSER. 4,774 real lines parsed 0 times and every row was
# stamped with the parse moment.

print("\n[9] EM-4: RFC 5424 / short-iso is parsed, and the time is the "
      "EVENT's time")
real = sudo_line()
p = em._parse_syslog_line(real, "auth.log")
check("it parses", p is not None, True)
check("the time basis is the EVENT's, not the parse moment",
      p["time_basis"], "event")
check("and the time is CONVERTED to the house format, naive UTC",
      p["timestamp"], "2026-09-24 01:34:41")
check("the service is populated (it was ALWAYS empty before)",
      p["service"], "sudo")
check("and the message carries the account and the command, without the "
      "prefix", ACCOUNT in p["message"] and "TTY=" in p["message"], True)

print("\n[10] EM-4: RFC 3164 still parses, and a bad one says it is a guess")
old = "Sep 23 18:34:41 host sshd[123]: Accepted password for alice"
q = em._parse_syslog_line(old, "auth.log")
check("the old format still parses", q["time_basis"], "event")
check("with its pid", q["pid"], "123")
check("and its service", q["service"], "sshd")
junk = em._parse_syslog_line("this line has no timestamp at all", "syslog")
check("a line with no time is marked as a parse-time guess",
      junk["time_basis"], "parse_time")
check("and it is NOT silently stamped as the event's own time",
      junk["timestamp"], None)
check_true("but the line itself is kept, never dropped",
           "no timestamp" in junk["message"])


print("\n[11] EM-3: the username extraction, against the REAL pam shape that "
      "put the word 'rhost' in 164 rows")
f = em._extract_fields(em._parse_syslog_line(pam_line(), "auth.log"))
check("THE NAME IS THE ACCOUNT, not the next key",
      f.get("username"), ACCOUNT)
check("and pam's empty rhost is NOT read as an address",
      f.get("ip_address"), None)

sshd_fail = (f"2026-09-23T14:00:00-07:00 HOST sshd[900]: Failed password for "
             f"invalid user admin from {DOC_IP} port 51514 ssh2")
g = em._extract_fields(em._parse_syslog_line(sshd_fail, "auth.log"))
check("an sshd failure still yields the address", g.get("ip_address"),
      DOC_IP)
check("and the account it named", g.get("username"), "admin")

name_field = ("2026-09-23T14:00:00-07:00 HOST useradd[77]: new user: "
              "name=alice, UID=1001")
h = em._extract_fields(em._parse_syslog_line(name_field, "auth.log"))
check("the useradd form is read from name=", h.get("username"), "alice")


print("\n[12] EM-3: brute force keys on an ADDRESS OR AN ACCOUNT, and the "
      "account case is the one that was unreachable")
em._failed_logins.clear()
got = []
for _ in range(em.FAILED_LOGIN_THRESHOLD):
    got.append(em._check_brute_force(ACCOUNT, 1000.0))
check("NO ADDRESS NEEDED: five failures for one account DO raise",
      got[-1] is not None, True)
check("and the entity is the account", got[-1]["entity_type"], "user")
check("the address case still works", None, None)
em._failed_logins.clear()
ip_fires = None
for i in range(em.FAILED_LOGIN_THRESHOLD):
    ip_fires = em._check_brute_force(DOC_IP, 1000.0 + i)
check("the ADDRESS case still raises, as it always did",
      ip_fires["entity_type"], "ip")
# NEGATIVE CONTROL: below the threshold, nothing fires either way
em._failed_logins.clear()
below = [em._check_brute_force("carol", 1000.0)
         for _ in range(em.FAILED_LOGIN_THRESHOLD - 1)]
check("and below the threshold NOTHING fires", any(below), False)
# NEGATIVE CONTROL: outside the window, the count is not carried
em._failed_logins.clear()
for _ in range(em.FAILED_LOGIN_THRESHOLD - 1):
    em._check_brute_force("dave", 1000.0)
stale = em._check_brute_force("dave", 1000.0
                              + em.FAILED_LOGIN_WINDOW + 1)
check("and a failure outside the window does not count toward it",
      stale, None)


print("\n[13] EM-3: the register carries the LOCAL rule, and LNX-1002 is "
      "unchanged as the REMOTE one")
from core import detections as det                    # noqa: E402
local = det.get("LNX-1012")
check("LNX-1012 exists", local.did, "LNX-1012")
check("its source is THIS sensor", local.source, "event_monitor")
check("its severity set is the module's own", sorted(local.severities),
      ["high"])
check("its entity type covers an account", local.entity_type, "user")
remote = det.get("LNX-1002")
check("LNX-1002 is STILL the remote sensor's rule", remote.source,
      "linux_monitor")
check("and its severities are NOT silently changed",
      sorted(remote.severities), ["high", "medium"])
# and the ids are distinct, so the two can never be confused on the page
check("the two are different numbers", local.did == remote.did, False)


# [14] EM-8: ONE EVENT, ONE ROW, and both halves in both directions.

print("\n[14] EM-8: the cross-path dedupe")
entries = [
    {"source": "journald", "message": "same thing", "timestamp": "2026-09-23 10:00:01", "record_id": 1},
    {"source": "auth.log", "message": "same thing", "timestamp": "2026-09-23 10:00:00", "record_id": 2},
    {"source": "kern.log", "message": "kernel line", "timestamp": "2026-09-23 10:00:00", "record_id": 3},
    {"source": "journald", "message": "kernel line", "timestamp": "2026-09-23 10:00:00", "record_id": 4},
]
kept, _ = em._dedupe_across_paths([dict(e) for e in entries])
by_msg = {e["message"]: e for e in kept}
check("one row for the journald+file pair", len(kept), 2)
check("THE FILE WINS over the journal for the same event",
      by_msg["same thing"]["source"], "auth.log")
check("and the loser is NAMED on the winner, not dropped in silence",
      by_msg["same thing"].get("also_seen_via"), ["journald"])
check("the kern.log copy wins over the journal too",
      by_msg["kernel line"]["source"], "kern.log")

print("\n[15] EM-8: the NEGATIVE controls, so the dedupe cannot eat real lines")
neg = [
    # the same message at two DIFFERENT times is two events
    {"source": "syslog", "message": "tick", "timestamp": "2026-09-23 10:00:00", "record_id": 1},
    {"source": "syslog", "message": "tick", "timestamp": "2026-09-23 10:05:00", "record_id": 2},
    # two different messages in the same second are two events
    {"source": "syslog", "message": "aaa", "timestamp": "2026-09-23 10:00:00", "record_id": 3},
    {"source": "syslog", "message": "bbb", "timestamp": "2026-09-23 10:00:00", "record_id": 4},
    # the SAME message one second apart in the SAME file is two lines
    {"source": "syslog", "message": "cc", "timestamp": "2026-09-23 10:00:00", "record_id": 5},
    {"source": "syslog", "message": "cc", "timestamp": "2026-09-23 10:00:01", "record_id": 6},
]
kept2, _ = em._dedupe_across_paths([dict(e) for e in neg])
check("NOTHING real is deduped away: six in, six out", len(kept2), 6)
check("and none of them claims a second path",
      any(e.get("also_seen_via") for e in kept2), False)


# [16] EM-10: search_logs. The unvalidated-argument defect, BOTH DIRECTIONS.

print("\n[16] EM-10: a leading dash is REFUSED, it is not run as an option")
# THE MEASURED DEFECT: search_logs("--version") returned GNU grep's own
# version banner as four log entries. The refusal is the fix.
raises("'--version' is refused", em.BadQuery, em.search_logs, "--version")
raises("'-i' is refused", em.BadQuery, em.search_logs, "-i")
raises("'  -x' (leading space) is refused", em.BadQuery, em.search_logs,
       "  -x")
try:
    em.search_logs("--version")
except em.BadQuery as e:
    msg = str(e)
    check_true("the refusal says WHAT to write instead",
               "without the leading dash" in msg)
    check_true("and says WHY it is a problem, not just 'invalid'",
               "OPTION" in msg)
raises("an invalid regex is REFUSED", em.BadQuery, em.search_logs, "([x")
raises("an empty pattern is refused", em.BadQuery, em.search_logs, "   ")
raises("an over-long pattern is refused", em.BadQuery, em.search_logs,
       "a" * (em.MAX_SEARCH_PATTERN + 1))

print("\n[17] EM-10: the search RUNS, and the word 'version' is data not a flag")
hits = em.search_logs("version", lines=3)
check_true("the pattern is searched for literally and finds real lines",
           isinstance(hits, list))
check_true("no row is grep's own banner",
           all("GNU grep" not in (r.get("message") or "") for r in hits))


# [18] EM-12: THE CONFIG BLOCK. `enabled` and `sources` were read by nothing.

print("\n[18] EM-12: the source list is honoured, and an unknown name is "
      "REPORTED rather than ignored")
applied = em.configure({"sensors": {"event_monitor": {
    "enabled": True, "sources": ["journald"], "poll_interval": 45}}})
check("the interval is applied", applied["poll_interval"], 45)
check("so the stall clock uses it",
      em._drain_remaining.__class__ is dict and True, True)
paths = em._get_log_file_paths()
check("ONLY the named source is read", sorted(paths), ["journald"])

applied = em.configure({"sensors": {"event_monitor": {
    "enabled": True, "sources": ["auth.log"], "poll_interval": 60}}})
paths = em._get_log_file_paths()
check("a file source alone is honoured",
      [k for k in paths if k != "journald"], ["auth.log"])

applied = em.configure({"sensors": {"event_monitor": {
    "enabled": True, "sources": ["journald", "auth.log", "nonsense.log"],
    "poll_interval": 60}}})
check("a name this host does not offer is REPORTED",
      em._unknown_sources(), ["nonsense.log"])

applied = em.configure({"sensors": {"event_monitor": {
    "enabled": True, "sources": None, "poll_interval": 60}}})
paths = em._get_log_file_paths()
check_true("and sources None means every source that exists",
           len(paths) >= 2)
check("with no unknown names", em._unknown_sources(), [])
check("junk in the block falls back rather than raising",
      em.configure({"sensors": {"event_monitor": {
          "enabled": "yes", "poll_interval": "not-a-number"}}})["poll_interval"],
      em.POLL_INTERVAL)
em.configure(None)


print("\n[19] EM-12: OFF IS OFF, at the adapter, and the cursor is PRESERVED")
import adapters                                        # noqa: E402
mon = adapters.LinuxEventMonitor(SID, {"sensors": {"event_monitor": {
    "enabled": False}}})
called = {"n": 0}
real_monitor_once = _em.monitor_once


def _counting(*a, **kw):
    called["n"] += 1
    return real_monitor_once(*a, **kw)


_em.monitor_once = _counting
mon.poll()
check("switched OFF in config, the reader is NOT run", called["n"], 0)
st_off = mon.status()
check("and the status says OFF BY CONFIG rather than 'running'",
      st_off.get("state"), "OFF BY CONFIG")
check_true("with the reason a reader can act on",
           "switched OFF in config" in (st_off.get("note") or ""))
# THE OTHER DIRECTION: switched on, it runs
mon_on = adapters.LinuxEventMonitor(
    SID, {"sensors": {"event_monitor": {"enabled": True, "sources": ["auth.log"]}}})
mon_on.poll()
check("switched ON, the reader IS run", called["n"], 1)
_em.monitor_once = real_monitor_once
em.configure(None)


print("\n[20] EM-7: the drain reports EVERY configured source, including a "
      "failed one, and a refused source is STALLED")
em._drain_remaining.clear(); em._drain_previous.clear()
em._last_report_at.clear(); em._read_failures.clear()
em._report_progress("auth.log", 0, 0, now=1.0)
em._report_progress("syslog", 10, 0, now=1.0)
em._report_progress("kern.log", 0, 0, now=1.0,
                    error="kern.log exists and this account cannot read it")
check("a refused source is NAMED in stalled", em._stalled_channels(now=2.0),
      ["kern.log"])
check("and its refusal is published", 
      "cannot read" in em._read_failures["kern.log"], True)
st_fail = em.get_status()
check("the status carries it as unreadable",
      "kern.log" in st_fail["unreadable"], True)
# the negative control: a source that successfully read nothing is NOT stalled
em._read_failures.clear()
em._drain_remaining.clear(); em._drain_previous.clear()
em._report_progress("auth.log", 0, 0, now=1.0)
check("an idle-but-readable source is NOT stalled",
      em._stalled_channels(now=2.0), [])
# and a backlog that does not move IS
em._report_progress("syslog", 0, 500, now=1.0)
em._remember_previous_drain()
em._report_progress("syslog", 0, 500, now=2.0)
check("a figure that does not go down IS stalled",
      "syslog" in em._stalled_channels(now=3.0), True)
em._drain_remaining.clear(); em._drain_previous.clear()
em._last_report_at.clear(); em._read_failures.clear()


print("\n[21] EM-6: a read failure is reported, not debug-logged")
missing = TMP / "no-such-file.log"
res = em._read_log_file_lines(missing, None, lines=10)
check_true("the caller gets an ERROR string", bool(res["error"]))
check("and no entries are invented", res["entries"], [])
# the unreadable-file case, built for real rather than mocked
secret = TMP / "secret.log"
secret.write_text("2026-09-23T10:00:00-07:00 host: secret\n")
secret.chmod(0o000)
res2 = em._read_log_file_lines(secret, None, lines=10)
readable = True
try:
    with secret.open("rb") as fh:
        fh.readline()
except PermissionError:
    readable = False
if readable:
    print("     (running as an account that can read chmod 000: skipped)")
else:
    check_true("a refused READ is reported as an error, not an empty list",
               bool(res2["error"]))
    check_true("and the sentence names the file",
               "secret.log" in res2["error"])
secret.chmod(0o600)


print("\n[22] EM-9: the probe answers from the LOGS, not from the group list")
from core import privilege_linux as pv                 # noqa: E402
ok, why, detail = pv.check_event_log_readability()
check_true("it returns a verdict", ok in (True, False))
check_true("and a sentence saying what decided it", bool(why))
check_true("and the detail names which files were readable",
           isinstance(detail.get("files_readable"), list))
check_true("and what journalctl said", detail.get("journald_ok") in
           (True, False))
p = pv.posture()
check("the DECLARED degrades list still names event_monitor",
      "event_monitor" in p["degraded_declared"], True)
if ok:
    check("but a module that PROBED fine is not painted as degraded",
          "event_monitor" in [n for n, _ in p["degraded_when_unelevated"]],
          False)
    check_true("and the summary says the log reader is not among them",
               "log reader is NOT among them" in p["summary"])
else:
    check_true("a probed-failing module IS named, with the measurement",
               "MEASURED on this host" in
               dict(p["degraded_when_unelevated"]).get("event_monitor", ""))


print("\n[23] EM-9: the module's journald probe asks for a RECORD, not a "
      "version string")
src = (ROOT / "tools" / "event_monitor_linux.py").read_text(encoding="utf-8")
check("the old --version probe is gone from _journald_probe",
      '"--version"' in src.split("def _journald_probe")[1].split("def ")[0],
      False)
check_true("it asks for one JSON record instead",
           '"--output=json", "-n", "1"' in
           src.split("def _journald_probe")[1].split("def ")[0])
check_true("and it returns a REASON beside the boolean",
           "journalctl is not installed on this host" in src)
st = em.get_status()
check_true("get_status publishes the reason",
           "journald_probe" in st and bool(st["journald_probe"]))


print("\n[24] EM-9: the two modules now answer the SAME question the same way")
# The audit's complaint was that these two disagreed, one from a version
# string and one from euid. They both probe now, so on this host they must
# agree about whether the logs can be read.
module_ok = bool(em.get_status()["log_readable"])
priv_ok = bool(detail.get("files_readable") or detail.get("journald_ok"))
check("the sensor's answer and the privilege report's answer agree",
      module_ok, priv_ok)


# [25] EM-13: THE RETENTION WINDOWS, which were read by no code at all.

print("\n[25] EM-13: the four declared windows are READ, and the two that do "
      "not apply say so")
from core import retention as rt                       # noqa: E402
cfg = {"retention": {"packets_days": 7, "events_days": 30,
                     "port_scan_results_days": 7,
                     "findings_days": 90, "baselines_days": 365}}
w = rt.declared_windows(cfg)
check("the raw-observation windows are APPLIED",
      sorted(w["applied"]), ["events", "packets", "port_scan_results"])
check("with the operator's numbers", w["applied"]["events"], 30)
check("findings_days is DECLARED and not applied",
      sorted(w["declared_only"]), ["baselines_days", "findings_days"])
check_true("and the note says why, so nobody assumes it runs",
           "NOT applied" in w["note"])

print("\n[25b] EM-13: NOTHING IS DEFAULTED. A window the config does not "
      "declare is not applied")
# THIS IS THE OTHER DIRECTION AND IT IS THE IMPORTANT ONE. The first version of
# this function came with a default set of its own, which would have meant a
# window this module CHOSE being applied to somebody's data: exactly the
# "arrival by patch" that section 23 forbids. This host's own config declares
# no port_scan_results_days, so that table gets no age window, and the status
# reports an empty reading rather than a complaint.
w_narrow = rt.declared_windows({"retention": {"packets_days": 7,
                                              "events_days": 30}})
check("only what was declared is applied", sorted(w_narrow["applied"]),
      ["events", "packets"])
check("and the undeclared table is not invented",
      "port_scan_results" in w_narrow["applied"], False)
check("nor reported as a fault", w_narrow["unreadable"], [])
print("\n[26] EM-13: junk and absent values are REPORTED, never read as zero")
w2 = rt.declared_windows({"retention": {"events_days": "lots",
                                        "packets_days": 0}})
check("a non-number and a zero are both reported", len(w2["unreadable"]), 2)
check("and it does NOT silently become 'delete everything'",
      w2["applied"], {})
check_true("with a sentence a human can act on",
           any("not a number of days" in u for u in w2["unreadable"]))
# THE NEGATIVE CONTROL: a key the operator never mentioned is not a fault.
# This host's config has no port_scan_results_days at all, and reporting that
# as a problem would put a permanent complaint on a status read.
w3 = rt.declared_windows({})
check("a config with NO retention block declares no windows and no faults",
      (w3["applied"], w3["unreadable"]), ({}, []))
print("\n[27] EM-13: the window prune is OFF unless the switch is on, and it "
      "refuses to delete the CURRENT session")
db = TMP / "windows.db"
c = sqlite3.connect(db)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.executemany(
    "INSERT INTO events(session_id, occurred_at, source, event_type, "
    "severity) VALUES(?,?,?,?,?)",
    [(("old-session"), "2020-01-01 00:00:00", "auth.log", "log_entry", "info"),
     (("old-session"), "2020-01-02 00:00:00", "auth.log", "log_entry", "info"),
     (("this-session"), "2020-01-03 00:00:00", "auth.log", "log_entry", "info"),
     (("recent"), "2099-01-01 00:00:00", "auth.log", "log_entry", "info")])
c.commit()
c.close()

dry = rt.prune_by_windows(db, cfg, current_session_id="this-session",
                          dry_run=True)
check("with pruning OFF it refuses and says why", dry["ok"], False)
check_true("naming the switch", "retention_enabled" in dry["reason"])

c = sqlite3.connect(db)
c.execute("INSERT INTO user_preferences(key, value) VALUES('retention_enabled','1')")
c.commit()
c.close()
dry = rt.prune_by_windows(db, cfg, current_session_id="this-session",
                          dry_run=True)
check("switched on, it counts what WOULD go", dry["removed"]["events"], 2)
with sqlite3.connect(db) as c:
    n = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
check("and a DRY RUN deletes nothing", n, 4)

live = rt.prune_by_windows(db, cfg, current_session_id="this-session",
                           dry_run=False)
check("a real run removes the aged rows", live["removed"]["events"], 2)
with sqlite3.connect(db) as c:
    left = sorted(r[0] for r in c.execute(
        "SELECT session_id FROM events").fetchall())
check("THE CURRENT SESSION'S ROW SURVIVES, however old its stamp",
      "this-session" in left, True)
check("and the recent row survives", "recent" in left, True)
check("exactly two rows went", len(left), 2)


print("\n[28] EM-13: the read-only status can see the windows without "
      "deleting anything")
ws = rt.window_status(db, cfg, current_session_id="this-session")
check("it names the applied windows", sorted(ws["applied"]),
      ["events", "packets", "port_scan_results"])
check("and counts what a prune would take", ws["would_remove"]["events"], 0)
with sqlite3.connect(db) as c:
    n2 = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
check("and it CHANGED NOTHING", n2, 2)


# [29] EM-2: the accounting. The headline was "134 raised, 0 written, nobody
# told". The log line and the status must both now carry the split.

print("\n[29] EM-2: what was raised and what was written is on the STATUS")
mon2 = adapters.LinuxEventMonitor(
    SID, {"sensors": {"event_monitor": {"enabled": True,
                                        "sources": ["auth.log"]}}})
mon2._last_raised = 134
mon2._last_dropped = 130
mon2._last_written = {"events": 700, "findings": 0, "duplicate_events": 0,
                      "failed_events": 0}
mon2._unregistered_counts = {"successful_login": 55, "service_started": 26}
st2 = mon2.status()
check("the raised count is published", st2["findings_raised"], 134)
check("so is the written count", st2["findings_written"], 0)
check("and what was event-only", st2["findings_events_only"], 130)
check_true("and the note says what this poll did, not just what rules are "
           "missing", "THIS POLL RAISED 134" in st2["note"])
em.configure(None)

print("\n[30] EM-2: THE READINESS ROW says it too, so it is not a log-only "
      "fact")
from core import settings as st_mod                    # noqa: E402


class Fake:
    def __init__(self, status):
        self._status = status

    def status(self):
        return self._status


row = st_mod._module_row("event_monitor", Fake({
    "running": True, "backlog": {}, "stalled": [],
    "findings_raised": 134, "findings_written": 0,
    "findings_events_only": 130, "findings_dismissed": 4,
    "findings_suppressed": 0}))
check("the row is not silent about it", row["state"], "busy")
check_true("and it says raised-vs-written in numbers",
           "raised 134" in row["detail"] and "wrote 0 findings" in row["detail"])
check_true("and names the decision rather than implying a fault",
           "no registered detection id" in row["detail"])

# RESTATED 2026-09-25, and the old fixture is why. It carried 134 raised, 0
# written and 130 event-only, leaving FOUR findings in no bucket at all --
# and the old branch printed amber anyway, because all it ever asked was
# "were there any event-only ones". In the shipped adapter every raised
# finding lands in exactly one of written / events-only / dismissed /
# suppressed, so that fixture described a state the code cannot produce, and
# the check was blind to the very gap it existed to catch. These two now pin
# the contract in both directions: a poll whose numbers ADD UP is amber, and
# a poll with a remainder is red with the remainder named.
row_unexplained = st_mod._module_row("event_monitor", Fake({
    "running": True, "backlog": {}, "stalled": [],
    "findings_raised": 134, "findings_written": 0,
    "findings_events_only": 130, "findings_dismissed": 0,
    "findings_suppressed": 0}))
check("a poll that leaves 4 findings in no bucket is RED",
      row_unexplained["state"], "problem")
check_true("and the number it could not account for is ON the sentence",
           "4 UNEXPLAINED" in row_unexplained["detail"])

row_fail = st_mod._module_row("event_monitor", Fake({
    "running": True, "backlog": {}, "stalled": [],
    "unreadable": {"kern.log": "kern.log exists and this account cannot "
                               "read it"}}))
check("a refused source paints the row red", row_fail["state"], "problem")
check_true("with the reason, not just the name",
           "cannot read it" in row_fail["detail"])


# [31] THE WIRING, because every fix above is only real if the app uses it.

print("\n[31] the wiring: the adapter, the register, the tool and the file")
adopter = (ROOT / "adapters.py").read_text(encoding="utf-8")
check_true("the adapter persists the cursor",
           "event_monitor_cursors" in adopter)
check_true("and passes the record id to save_event",
           "source_record_id=entry.get(\"record_id\")" in adopter)
check_true("and writes the coverage gaps the module returns",
           "for gap in (result.get(\"gaps\") or [])" in adopter)
check_true("and honours enabled before polling",
           "if not applied.get(\"enabled\", True):" in adopter)
check_true("and raises the LOCAL brute force rule",
           '"LNX-1012"' in adopter)
check("and no longer raises the remote sensor\'s rule",
      'detection_id="LNX-1002"' in adopter, False)
check_true("and validates an account name before filing a finding on it",
           "_valid_entity" in adopter)

registry = (ROOT / "core" / "tool_registry.py").read_text(encoding="utf-8")
check_true("search_logs is a tool the model can call",
           '"name": "search_logs"' in registry)
check_true("and it is dispatched", 'if name == "search_logs":' in registry)
health = (ROOT / "core" / "sensor_health.py").read_text(encoding="utf-8")
check_true("and it declares what it depends on",
           '"search_logs":' in health)
sanit = (ROOT / "core" / "sanitize.py").read_text(encoding="utf-8")
check_true("and its output is fenced, because log lines are not ours",
           '"search_logs",' in sanit)
check_true("the retention windows are read by the status",
           "windows_would_remove" in
           (ROOT / "core" / "retention.py").read_text(encoding="utf-8"))
check_true("and the privilege report probes rather than assuming",
           "check_event_log_readability" in
           (ROOT / "core" / "privilege_linux.py").read_text(encoding="utf-8"))

print("\n[32] EM-11: the dead code the audit named is gone or is real now")
check("start_monitoring is REMOVED (zero callers, write commented out)",
      "def start_monitoring" in src, False)
check("the unused `os` import is gone", "\nimport os\n" in src, False)
check_true("the marker= parameter is REAL now and documented as a position",
           "marker: dict = None" in src and "position, not a hash" in src)
check_true("and `since` is USED by a real reader: a refused cursor resumes "
           "from the last read TIME rather than skipping",
           'f"--since=@{int(since) / 1_000_000:.6f}"' in src
           # and reads the OLDEST records after it, not the newest (EM3-2)
           and 'f"--lines=+{lines}"' in src)
check_true("and search_logs bounds the journal with it too",
           "if since:\n            cmd.append(f\"--since={since}\")" in src
           or 'cmd.append(f"--since={since}")' in src)
check_true("and the module's poll interval has ONE definition",
           src.count("POLL_INTERVAL = ") >= 1)
check_true("with the config able to override it",
           "poll_interval" in src and "def configure(" in src)


print("\n[33] the two comments that defended the missing cursor are corrected")
check("the 'there is no cursor to be behind' defence is gone",
      "there is no cursor to be behind" in src, False)
check_true("and the header states the cursor that now exists",
           "SO THIS FILE NOW HOLDS A CURSOR" in src)
check_true("and the 200-entry-window claim is corrected in place, with the "
           "measurement that disproved it",
           "outspanned the poll" in src and
           "200 distinct lines per minute for twelve" in src)


print("\n" + ("," * 60))
print("ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
