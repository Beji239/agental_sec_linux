"""
tests/test_auditd_monitor.py, L4. The kernel audit feed's reader.

FAILURE CASES FIRST, and this file's reason is the sharpest version of that
rule in the tree: ON THIS MACHINE THE HAPPY PATH IS AN EMPTY LIST. auditd is
not installed here, so the module's normal, correct, everyday answer is "the
kernel audit feed is absent, nothing is being recorded, here is the one
command". A test suite that only proved records parse would pass against a
module that reported that absence as a quiet machine -- which is the exact
defect this whole tier exists to prevent, because an empty findings list is
read as a clean bill of health by everything downstream.

So the order is:

  [1]  NOTHING IS INSTALLED AND THAT IS SAID, NOT IMPLIED. Four states that
       produce the same empty record list must never collapse: not installed,
       switched off by config, installed with no log yet, and the log existing
       while this account cannot read it. The last one is the DEFAULT on every
       real install and is the only genuine `blind`.

  [2]  BOTH RECORD FORMATS ARE PARSED. audit 3.x writes a raw half and an
       enriched half into the same file. A parser that knows only one gets a
       PLAUSIBLE SMALLER NUMBER from the other with no error anywhere. There
       is a test for each format, and a test that the enriched value WINS
       where both halves carry the same field.

  [3]  THE FIRST PASS SEEDS. A log already holding a week of somebody else's
       history must raise NOTHING, or the first useful run is a page of
       history and its reader learns to skim it.

  [4]  A CHANGE RAISES ONCE, and the cursor moves with it.

  [5]  THE CURSOR DETECTS A ROTATION instead of seeking past the end of a
       shorter file and reporting zero records -- which would read as a quiet
       machine for as long as the offset stayed ahead of the file.

  [6]  The two rules, their severities and their entity types, against the
       register AND against the incident writer's own vocabulary. The second
       one RAISES and its caller SWALLOWS the raise, so a wrong entity type
       reaches the findings table and opens no incident, silently.

  [7]  The model-facing tool. Its DEPENDS entry, its fence, its dispatch, and
       -- the one that matters -- that its payload carries the absence in
       words on a host where auditd is not installed.

WHAT THIS FILE CANNOT TEST HERE, said out loud rather than skipped quietly:
a REAL auditd writing a real log. That needs `sudo apt install auditd` on the
owner's machine, which is the owner's command and not this test's. Everything below
runs against fixture logs built in both of audit's own formats, and the
live half belongs to scripts/verify_auditd.sh, whose skips name themselves.

Run it directly: python tests/test_auditd_monitor.py
"""
import io
import json
import os
import pathlib
import sqlite3
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import detections as det                    # noqa: E402
from core import memory_engine as me                  # noqa: E402
from core import sanitize                             # noqa: E402
from core import sensor_health as sh                  # noqa: E402
from core import sensors as sn                        # noqa: E402
from core import tool_registry as tr                  # noqa: E402
from tools import auditd_monitor as am                # noqa: E402

sn.register_local()
TEST_SESSION = "test_auditd_monitor"

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def ok(label, condition):
    check(label, bool(condition), True)


SCRATCH = pathlib.Path(_isolate_db.isolate()).parent
LOG = str(SCRATCH / "audit.log")

# FIXTURE LOGS, IN AUDIT'S OWN TWO SHAPES
#
# EVERY TIMESTAMP IS BUILT RELATIVE TO NOW, AND THAT IS NOT TIDINESS. The
# module ages a log by the record's OWN audit() stamp -- not by the file's
# mtime -- because on a real host the two agree and the stamp is the one the
# kernel wrote. A fixture with a hardcoded epoch is therefore a log that
# stopped recording a year ago, and the first version of this file was built
# that way: every "a fresh log is recording" assertion failed against a
# module that was behaving exactly correctly. A test pinned to the wall clock
# is a test that goes red on a machine whose clock moved.
#
# THE UNIT SEPARATOR IS WRITTEN AS AN ESCAPE AND NEVER AS THE BYTE. A literal
# \x1d in a source file makes grep, diff and every editor misbehave -- the
# module's own header says so -- and a fixture that corrupted this file would
# take the test suite down with it.
GS = "\x1d"

# THE CLOCK THE FIXTURES ARE BUILT ON. One read, so every record in one run
# sits on the same second and two calls in the same test cannot straddle it.
NOW = time.time()


def audit_stamp(offset_seconds: float = 0.0, msg_id: int = 456) -> str:
    """An audit() stamp `offset_seconds` in the past, with a given event id."""
    return f"{NOW - offset_seconds:.3f}:{msg_id}"


def raw_syscall(offset=0.0, msg_id=456) -> str:
    return (
        f'type=SYSCALL msg=audit({audit_stamp(offset, msg_id)}): '
        'arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffd '
        'a2=0 a3=0 items=1 ppid=1 pid=4242 auid=1000 uid=0 gid=0 euid=0 '
        'comm="vim" exe="/usr/bin/vim" key="identity"'
    )


def raw_path(name="/etc/passwd", offset=0.0, msg_id=456, item=0) -> str:
    return (
        f'type=PATH msg=audit({audit_stamp(offset, msg_id)}): item={item} '
        f'name="{name}" inode=1234 dev=08:01 mode=0100644 ouid=0 ogid=0 '
        f'rdev=00:00 nametype=NORMAL'
    )


def raw_proctitle(offset=0.0, msg_id=456) -> str:
    return (f'type=PROCTITLE msg=audit({audit_stamp(offset, msg_id)}): '
            f'proctitle=76696D002F6574632F706173737764')


def raw_config(op="add_rule", offset=0.0, msg_id=457) -> str:
    return (
        f'type=CONFIG_CHANGE msg=audit({audit_stamp(offset, msg_id)}): '
        f'auid=1000 ses=3 op={op} key="identity" list=4 res=1'
    )


def enriched_config(op="remove_rule", offset=0.0, msg_id=458) -> str:
    """ENRICHED FORM: the readable half, then \x1d-separated key=value pairs."""
    return (
        f'type=CONFIG_CHANGE msg=audit({audit_stamp(offset, msg_id)}): '
        f'op={op}' + GS + 'key="identity"' + GS + 'list="4"' + GS
        + 'res="yes"' + GS
    )


def enriched_path(name="/etc/sudoers", offset=0.0, msg_id=459) -> str:
    return (
        f'type=PATH msg=audit({audit_stamp(offset, msg_id)}): item=0'
        + GS + 'item="0"' + GS + f'name="{name}"' + GS
        + 'nametype="NORMAL"' + GS + 'key="identity"' + GS
    )


def user_auth(offset=0.0, msg_id=461) -> str:
    return (
        f'type=USER_AUTH msg=audit({audit_stamp(offset, msg_id)}): pid=5000 '
        f'uid=0 auid=1000 ses=3 msg=\'op=PAM:authentication acct="user1" '
        f'exe="/usr/sbin/sshd" hostname=192.0.2.5 addr=192.0.2.5 '
        f'terminal=ssh res=success\''
    )


# A PATH RECORD WITH A NAME THAT DISAGREES BETWEEN THE TWO HALVES, which is
# the shape the enriched value has to win on.
ENRICHED_PATH_CONFLICT = (
    'type=PATH msg=audit(1758500071.000:460): item=1 name="/wrong/raw/name"'
    + GS + 'name="/etc/shadow"' + GS
)


def write_log(lines, path=LOG):
    """A fixture log, exactly the bytes auditd would have written."""
    if os.path.exists(path):
        os.unlink(path)
    io.open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    return path


def cfg_for(path=LOG, **kw):
    block = {"enabled": True, "log_path": str(path)}
    block.update(kw)
    return {"sensors": {"auditd": block}}


print("\n[1] THE ABSENCE IS SAID, NOT IMPLIED")

# The FIRST assertion is about this host, because this host is the one the
# module was written for. If auditd were ever installed here the test below
# would still be correct -- it asserts the SHAPE, not the absence.
st = am.status({})
ok("this host's auditd state was read ("
   f"{st['state']}, tools={st['tools_present']})",
   st["state"] in ("NOT INSTALLED", "NO LOG YET", "CANNOT READ LOG",
                   "READABLE"))

check("the module never reports `blind` for a machine with no auditd",
      am.status({}).get("blind"),
      # CANNOT READ LOG is the one genuine blind case and can only happen on a
      # host that HAS an audit log, so it is excluded from this assertion by
      # being a different state rather than by being tolerated here.
      am.status({}).get("state") == "CANNOT READ LOG")

# THE ONE COMMAND IS PRINTED, NOT DESCRIBED. This is the owner's Q7 wording
# for the whole tier and it is asserted as a literal because it is the string
# a person is meant to copy.
check("the install command is the one the operator would run",
      am.INSTALL_COMMAND, "sudo apt install auditd")
ok("and it is carried in the status",
   am.status({}).get("install_command") == am.INSTALL_COMMAND)

# NOT INSTALLED, WITH NOTHING CONFIGURED.
# Forced by pointing the reader at a path that does not exist AND telling it
# not to use the override -- the state a fresh host is in.
_real_which = am._which
try:
    am._which = lambda name: None                 # pretend nothing is installed
    st = am.status({})
    check("with no binaries and no conf, the state is NOT INSTALLED",
          st["state"], "NOT INSTALLED")
    check("  and `installed` is false", st["installed"], False)
    ok("  and the note says NOTHING is being recorded rather than nothing happened",
       "NOTHING of that kind is being recorded" in (st["note"] or "")
       or "NOTHING" in (st["note"] or ""))
    ok("  and the note prints the install command",
       am.INSTALL_COMMAND in (st["note"] or ""))
    check("  and it is NOT blind, because the machine's choice is not our fault",
          st["blind"], False)
    check("  and running is false", st["running"], False)
    check("  and it is ready for nothing", st["ready"], False)
    ok("  and the coverage block carries the same sentence a model would read",
       any("NOTHING" in lim for lim in st["coverage_limits"]))

    # OFF BY CONFIG IS A DIFFERENT SENTENCE FROM NOT INSTALLED.
    st_off = am.status({"sensors": {"auditd": {"enabled": False}}})
    check("switched off in config, the state says so and not NOT INSTALLED",
          st_off["state"], "OFF BY CONFIG")
    check("  and the machine's own state is still reported beside it",
          st_off["installed"], False)
    ok("  and the note blames the configuration, not the machine",
       "SWITCHED OFF" in (st_off["note"] or ""))
    ok("  and it still says what the machine looks like",
       "NOT installed here" in (st_off["note"] or ""))
finally:
    am._which = _real_which

# INSTALLED, NO LOG YET.
try:
    am._which = lambda name: f"/usr/sbin/{name}"
    st_nolog = am.status({"sensors": {"auditd": {"log_path": "/nonexistent/x.log"}}})
    check("tools present and no log gives NO LOG YET", st_nolog["state"],
          "NO LOG YET")
    ok("  and the note says the configured path is not there",
       "CONFIGURED AUDIT LOG IS NOT THERE" in (st_nolog["note"] or ""))
finally:
    am._which = _real_which

# THE ONE GENUINE BLIND CASE.
# A log that EXISTS and that this account cannot open. Built for real with
# mode 000, because os.access is what decides it and a mocked access check
# would be testing the mock.
write_log([raw_syscall()])
os.chmod(LOG, 0o000)
try:
    st_blind = am.status(cfg_for(LOG))
    if os.geteuid() == 0:                          # root reads anything
        print("  SKIP  running as root: a mode-000 file is still readable, "
              "so the blind case cannot be built here. THIS IS A SKIP AND "
              "NOT A PASS.")
    else:
        check("a log this account cannot read IS blind", st_blind["blind"], True)
        check("  and the state says which failure it is",
              st_blind["state"], "CANNOT READ LOG")
        ok("  and the reason says NOTHING was examined rather than nothing found",
           "NOTHING" in (st_blind["blind_reason"] or ""))
        ok("  and it says what to do about it",
           "elevated" in (st_blind["blind_reason"] or ""))
        ok("  and it reports the mode and owner so a reader can act",
           "mode" in (st_blind["blind_reason"] or ""))
finally:
    os.chmod(LOG, 0o644)

# A READABLE LOG IS READABLE, AND SAYS SO.
write_log([raw_syscall(offset=5), raw_path(offset=5)])
st_ok = am.status(cfg_for(LOG))
check("a fresh readable log is READABLE", st_ok["state"], "READABLE")
check("  and is running", st_ok["running"], True)
check("  and is not blind", st_ok["blind"], False)
ok("  and the note names the path and the age rather than a bare boolean",
   "recording" in (st_ok["note"] or "") and LOG in (st_ok["note"] or ""))

# STALE IS NOT BLIND.
# A file with real records and nothing recent: the recording stopped, which is
# a statement about the daemon and not about this app's ability to read. The
# records are aged past the threshold BY THEIR OWN STAMPS, which is what the
# module measures.
write_log([raw_syscall(offset=am.STALE_AFTER_SECONDS + 600)])
st_stale = am.status(cfg_for(LOG))
check("a stale log is still READABLE", st_stale["state"], "READABLE")
check("  and is not running", st_stale["running"], False)
check("  and is NOT blind", st_stale["blind"], False)
ok("  and the note says the recording may have stopped",
   "MAY HAVE STOPPED" in (st_stale["note"] or "").upper())

# AND A CONFIGURED LOG ON A HOST WITH NO AUDITD IS EXPLAINED.
# READABLE beside installed:false is exactly the pair somebody reports as a
# bug. It is the state a verification run is in, and it has to carry its own
# warning or the age is read as being about this machine.
write_log([raw_syscall(offset=5)])
try:
    am._which = lambda name: None
    st_mixed = am.status(cfg_for(LOG))
    check("a configured log on a host with no auditd still reads", 
          st_mixed["state"], "READABLE")
    check("  and installed is honestly false", st_mixed["installed"], False)
    ok("  and a warning says this file is NOT written by a running auditd",
       "NOT being written by a running auditd" in
       (st_mixed.get("log_path_warning") or ""))
    ok("  and the warning survives the state branches that set `note`",
       any("NOT being written" in lim for lim in st_mixed["coverage_limits"]))
finally:
    am._which = _real_which


print("\n[2] BOTH RECORD FORMATS ARE PARSED")

# RAW.
rec = am.parse_record(raw_path())
check("a RAW path record parses", rec["type"], "PATH")
check("  and the msg_id groups it with its syscall", rec["msg_id"], 456)
ok("  and the name is lifted", rec["fields"].get("name") == "/etc/passwd")
ok("  and the timestamp is a real one", rec["at"] > 1_700_000_000)

# ENRICHED. THE DEFECT THIS GUARDS IS A WRONG COUNT, NOT AN EXCEPTION: a
# parser that never looks past the unit separator finds the fields that happen
# to be in the raw half and silently misses the rest.
erec = am.parse_record(enriched_config())
check("an ENRICHED config record parses", erec["type"], "CONFIG_CHANGE")
check("  and its msg_id is read", erec["msg_id"], 458)
check("  and the enriched `op` is lifted", erec["fields"].get("op"),
      "remove_rule")
check("  and the enriched `key` is lifted too, which the raw half lacks",
      erec["fields"].get("key"), "identity")

# THE ENRICHED VALUE WINS WHERE BOTH HALVES CARRY THE SAME FIELD.
crec = am.parse_record(ENRICHED_PATH_CONFLICT)
check("where both halves name a path, the ENRICHED one wins",
      crec["fields"].get("name"), "/etc/shadow")
ok("  and the stale raw value is gone rather than sitting beside it",
   "/wrong/raw/name" not in json.dumps(crec["fields"]))

# THE PATH WITH A SPACE, which is why the enriched half is read at all: the
# raw form writes name="/tmp/a b" and a naive split breaks it in two.
write_log([raw_path(name="/tmp/a b/c")], path=LOG)
spaced = am.recent_records(cfg_for(LOG), record_type="PATH")
check("a raw path with a space survives whole",
      spaced["records"][0]["fields"].get("name"), "/tmp/a b/c")

# NOT A RECORD.
check("a human message is not forced into the record shape",
      am.parse_record("----"), None)
check("an empty line is not a record", am.parse_record(""), None)
check("a DAEMON_START style line without type= is skipped",
      am.parse_record("auditd start"), None)

# THE READER'S OWN COUNT, OVER BOTH FORMATS.
write_log([raw_syscall(), raw_path(), raw_proctitle(), raw_config(),
           enriched_config(), enriched_path(), user_auth()])
r = am.recent_records(cfg_for(LOG))
check("every record in the log was parsed", len(r["records"]), 7)
check("  and the per-type counts are complete, not just the raised types",
      r["counts_by_type"].get("CONFIG_CHANGE"), 2)
check("  and the enriched record is among them, so no format was skipped",
      r["counts_by_type"].get("PATH"), 2)

# THE CUT IS ANNOUNCED.
r_cut = am.recent_records(cfg_for(LOG), limit=3)
check("a limit is honoured", len(r_cut["records"]), 3)
ok("  and the cut is announced rather than silent",
   "SHOWING THE 3 NEWEST" in (r_cut["note"] or ""))

# FILTERS.
r_type = am.recent_records(cfg_for(LOG), record_type="PATH")
check("filtering by record type works", {x["type"] for x in r_type["records"]},
      {"PATH"})
r_search = am.recent_records(cfg_for(LOG), search="passwd")
check("a search finds the record mentioning it",
      [x["type"] for x in r_search["records"]], ["PATH"])
r_none = am.recent_records(cfg_for(LOG), search="nothing-matches-this")
check("a search that matches nothing returns nothing", r_none["records"], [])
ok("  and says so against what WAS there, so it cannot be read as an empty log",
   "MATCHING" in (r_none["note"] or "").upper())

# THE TAIL READ DROPS ITS FRAGMENT RATHER THAN PARSING IT. A log larger than
# the window starts mid-record, and a torn record parses into a record with
# fields missing -- the wrong shape of wrong.
#
# THE FIXTURE HAS TO BE BIGGER THAN THE WINDOW, which is the whole point and
# was got wrong first time: 9,000 records is 1.8 MB against a 4 MB window, so
# this exercised the read-everything path and asserted nothing about tails.
# Built from the window itself rather than from a number, so a window that
# moves takes the fixture with it instead of quietly going back to testing
# nothing.
one = raw_syscall() + "\n"
big = [raw_syscall(offset=i * 0.0001) for i in
       range(int(am.RECENT_TAIL_BYTES / len(one)) + 500)]
write_log(big)
r_big = am.recent_records(cfg_for(LOG), limit=5)
ok("  the read window really was a cut of a bigger file",
   r_big["coverage"]["tail_bytes_read"] < r_big["coverage"]["log_size_bytes"])
ok("  and the cut is STATED rather than left for a reader to infer",
   "ONLY THE LAST" in (r_big["coverage"].get("window") or ""))
ok("  and no record came back torn, which is what parsing the fragment "
   "would look like",
   all(x["msg_id"] == 456 and x["at"] for x in r_big["records"]))


print("\n[3] THE FIRST PASS SEEDS AND RAISES NOTHING")

HIST = str(SCRATCH / "audit_history.log")
write_log([raw_config(), raw_path(), enriched_config()], path=HIST)

report = am.analyze(cfg_for(HIST))
check("the first pass SEEDS", report["seeded"], True)
check("  and raises NOTHING for the history already in the file",
      len(report["findings"]), 0)
ok("  and the coverage says the cursor was set to the END of the file",
   "cursor was set to the end of the file" in
   (report["coverage"].get("first_pass") or ""))
ok("  and it says how much history was skipped rather than passing over it",
   "byte(s) of records" in (report["coverage"].get("first_pass") or ""))
cur = am.read_cursor()
check("  and the cursor is now marked as seeded", cur["seeded"], True)
ok("  and it sits at the end of the file, not at zero",
   cur["last_offset"] == os.path.getsize(HIST))

# A SECOND PASS over an unchanged file: nothing new, and a DIFFERENT reason.
report2 = am.analyze(cfg_for(HIST))
check("a second pass over an unchanged log raises nothing",
      len(report2["findings"]), 0)
check("  and it is no longer a seeding pass", report2["seeded"], False)
ok("  and it really did read the file (offset reached the same end)",
   report2["cursor"]["moved_to"] == os.path.getsize(HIST))


print("\n[4] A CHANGE RAISES ONCE, AND THE CURSOR MOVES WITH IT")

NEW = str(SCRATCH / "audit_new.log")
write_log([raw_syscall(), raw_path()], path=NEW)
am.analyze(cfg_for(NEW))                                    # seed

# A genuinely new CONFIG_CHANGE, appended the way auditd appends.
with io.open(NEW, "a", encoding="utf-8") as fh:
    fh.write(raw_config(offset=-10, msg_id=470) + "\n")

report = am.analyze(cfg_for(NEW))
ids = [f["detection_id"] for f in report["findings"]]
check("a new audit-rule change is raised", ids, ["AUD-1001"])
check("  and it is severity medium, which the register declares",
      report["findings"][0]["severity"], "medium")

# THE SAME RECORD AGAIN. The cursor moved, so this pass has nothing to look at.
report = am.analyze(cfg_for(NEW))
check("THE SAME RECORD DOES NOT RAISE TWICE", len(report["findings"]), 0)
check("  because the cursor moved past it", report["analysed"].get("records"), 0)

# ONE SYSCALL TOUCHING SEVERAL WATCHED FILES.
#
# THE CLAIM THE MODULE MAKES IS DEDUP ON (msg_id, path), NOT ONE FINDING PER
# SYSCALL, and the first version of this test asserted the wrong one. A syscall
# that touches four DIFFERENT watched files touched four different files, and
# each is its own fact with its own entity value -- collapsing them would throw
# three of the paths away. What must NOT repeat is the SAME path within the
# same event, which auditd can write twice (once per nametype) and which would
# otherwise be the same sentence on the board twice. Both halves are asserted.
FOUR = str(SCRATCH / "audit_four.log")
write_log([raw_syscall(), raw_path()], path=FOUR)
am.analyze(cfg_for(FOUR))
with io.open(FOUR, "a", encoding="utf-8") as fh:
    for i in range(4):
        fh.write(raw_path(name=f"/etc/watched{i}", offset=-1, msg_id=500,
                          item=i) + "\n")
    # THE SAME PATH AGAIN, in the same event. This is the one that must not
    # produce a second finding.
    fh.write(raw_path(name="/etc/watched0", offset=-1, msg_id=500,
                      item=0) + "\n")
    # AND ONE FROM A DIFFERENT EVENT, which is its own finding.
    fh.write(raw_path(name="/etc/other", offset=-2, msg_id=501) + "\n")

report = am.analyze(cfg_for(FOUR))
paths = sorted(f["entity_value"] for f in report["findings"])
check("four distinct watched paths in one syscall are four findings, not one",
      len(paths), 5)
ok("  and every distinct path is kept rather than collapsed to the first",
   all(f"/etc/watched{i}" in paths for i in range(4)))
ok("  and a later event's path is its own finding", "/etc/other" in paths)
check("  and the same path twice in one event is counted, not raised twice",
      report["counted"].get("path_repeat"), 1)

# A PATH RECORD WITH NO NAME IS NOT A PATH.
# It happens on a delete, and reporting an empty string as a watched file
# touched would be a finding with nothing in it.
NONAME = str(SCRATCH / "audit_noname.log")
write_log([raw_syscall()], path=NONAME)
am.analyze(cfg_for(NONAME))
with io.open(NONAME, "a", encoding="utf-8") as fh:
    fh.write(f'type=PATH msg=audit({audit_stamp(-1, 600)}): item=0 inode=0 '
             f'nametype=DELETE\n')
report = am.analyze(cfg_for(NONAME))
check("a PATH record with no name raises nothing", report["findings"], [])
check("  and is counted as nameless rather than ignored",
      report["counted"].get("path_no_name"), 1)

# THE CAP ANNOUNCES ITSELF.
# "11 watched paths were touched" and "11 of 300" are different sentences and
# only one of them is honest.
CAP = str(SCRATCH / "audit_cap.log")
write_log([raw_syscall()], path=CAP)
am.analyze(cfg_for(CAP))
with io.open(CAP, "a", encoding="utf-8") as fh:
    for i in range(am.CAP_PER_ID_PER_PASS + 7):
        fh.write(raw_path(name=f"/etc/capped{i}", offset=-1, msg_id=700 + i)
                 + "\n")
report = am.analyze(cfg_for(CAP))
capped = [f for f in report["findings"]
          if f["entity_value"] == "capped:AUD-1002"]
check("the cap produces a summary row of its own", len(capped), 1)
ok("  and the summary says how many were NOT written",
   "further watched-path record(s)" in capped[0]["description"])
ok("  and it says the records themselves are NOT lost",
   "NOT LOST" in capped[0]["description"])


print("\n[5] A ROTATED LOG IS DETECTED, NOT READ FROM THE WRONG PLACE")

ROT = str(SCRATCH / "audit_rot.log")
# A long log, seeded, so the cursor sits far down the file.
write_log([raw_syscall(offset=i) for i in range(40)], path=ROT)
am.analyze(cfg_for(ROT))
before = am.read_cursor()["last_offset"]
ok("the cursor sits well into the file before the rotation", before > 1000)

# NOW THE ROTATION: the file is replaced by a SHORTER one, which is what
# logrotate does. A reader that seeked past the end would report zero records
# and a healthy sensor, for as long as the offset stayed ahead of the file --
# which is the silent version of this defect and the one that matters.
write_log([raw_syscall(offset=-1), raw_config(offset=-1, msg_id=470)], path=ROT)
report = am.analyze(cfg_for(ROT))
check("a shorter file is reported as ROTATED", report["coverage"].get("rotated")
      is not None, True)
ok("  and the sentence says the log is shorter than where the reader had got to",
   "shorter" in (report["coverage"].get("rotated") or ""))
ok("  and it says the old file could not be found, so records were not read",
   "NOT read" in (report["coverage"].get("rotated") or ""))
check("  and the new file WAS read from the beginning rather than skipped",
      report["analysed"].get("records"), 2)
check("  and the rotated log's CONFIG_CHANGE was raised",
      [f["detection_id"] for f in report["findings"]], ["AUD-1001"])


print("\n[6] THE REGISTER, THE SEVERITIES AND THE ENTITY VOCABULARY")

for did in ("AUD-1001", "AUD-1002"):
    entry = det.get(did)
    check(f"{did} is registered", entry.did, did)

check("AUD-1001 declares medium",
      det.get("AUD-1001").severities, {"medium"})
check("AUD-1002 declares low", det.get("AUD-1002").severities, {"low"})
check("AUD-1001 is an auditd detection",
      det.get("AUD-1001").source, "auditd")
check("AUD-1002 is an auditd detection",
      det.get("AUD-1002").source, "auditd")

# BOTH VOCABULARIES. memory_engine RAISES on an unknown entity type; so does
# incident.write_incident, and ITS CALLER SWALLOWS THE RAISE -- so a wrong
# type reaches the findings table and opens no incident, silently. That is the
# defect this pair of assertions exists for.
for did in ("AUD-1001", "AUD-1002"):
    check(f"{did}'s entity type is in memory_engine's vocabulary",
          det.get(did).entity_type in me.VALID_ENTITY_TYPES, True)
    check(f"{did}'s entity type is in the incident writer's vocabulary",
          det.get(did).entity_type in ("ip", "process", "port", "user",
                                       "file"), True)

# ONE ID PER CLAIM: the config change and the watch hit are different facts
# with different remedies and must not share an id.
ok("the two ids are different claims",
   det.get("AUD-1001").name != det.get("AUD-1002").name)

# THE FINDINGS THE MODULE RAISES ALL CARRY A REGISTERED ID, proved by writing
# them through the real adapter into the real findings table.
from adapters import LinuxAuditd                          # noqa: E402

ADP = str(SCRATCH / "audit_adapter.log")
write_log([raw_syscall()], path=ADP)
am.analyze(cfg_for(ADP))
with io.open(ADP, "a", encoding="utf-8") as fh:
    fh.write(raw_config(offset=-1, msg_id=470) + "\n")
    fh.write(raw_path(name="/etc/passwd", offset=-1, msg_id=471) + "\n")

report = am.analyze(cfg_for(ADP))
adapter = LinuxAuditd(TEST_SESSION, cfg_for(ADP))
written = adapter._emit_all(report["findings"])
check("the real adapter wrote both findings", written, 2)
check("  and refused NO id as unregistered", adapter._unregistered, {})

rows = [r for r in me.query_findings(limit=50)]
mine = [r for r in rows if r.get("source") == "auditd"]
check("both rows are in the findings table under this sensor", len(mine), 2)
ok("  and one of them is the watch hit on the real path",
   any(r.get("detection_id") == "AUD-1002"
       and r.get("entity_value") == "/etc/passwd" for r in mine))
ok("  and the config change is filed against auditd.conf, which is what changed",
   any(r.get("detection_id") == "AUD-1001"
       and r.get("entity_value") == am.DEFAULT_AUDITD_CONF for r in mine))

# RAISED ONCE, end to end. The same window again must not re-open the board.
report = am.analyze(cfg_for(ADP))
written = adapter._emit_all(report["findings"])
check("the adapter does not write the same finding twice", written, 0)

# THE ADAPTER'S OWN HEADLINE AGREES WITH THE MODULE.
st_ad = adapter.status()
check("the adapter carries the module's state string",
      (st_ad.get("auditd") or {}).get("state"),
      am.status(cfg_for(ADP))["state"])
ok("  and its headline repeats that state rather than recomputing it",
   f"state: {am.status(cfg_for(ADP))['state']}" in (st_ad.get("note") or ""))

# OFF VERSUS BROKEN, through the adapter: a reader switched off must not be
# reported as a machine with no auditd.
off_adapter = LinuxAuditd(TEST_SESSION,
                          {"sensors": {"auditd": {"enabled": False}}})
st_off_ad = off_adapter.status()
ok("a switched-off reader's headline blames the configuration, not the machine",
   "SWITCHED OFF" in (st_off_ad.get("note") or ""))
check("  and it is not reported blind", st_off_ad.get("blind"), None)


print("\n[7] THE MODEL-FACING TOOL, THROUGH execute_tool")

names = {t["name"] for t in tr.TOOL_MANIFEST}
ok("query_audit_events is in the model-facing manifest",
   "query_audit_events" in names)

try:
    deps = sh.depends_on("query_audit_events")
    check("it declares its dependencies", list(deps), ["auditd"])
except Exception as e:                              # noqa: BLE001
    check("it declares its dependencies", f"{type(e).__name__}: {e}", "ok")

ok("query_audit_events is classified as a READ",
   tr.tool_writes("query_audit_events") is False)
ok("it is FENCED, because its rows carry attacker-chosen text",
   sanitize.is_untrusted("query_audit_events"))
ok("and it needs no approval, because it stops nothing",
   tr.requires_permission("query_audit_events", {}) is False)

# THE DISPATCH, CALLED. This is the check that catches the three-way
# registration being incomplete: a tool in the manifest with no dispatch
# branch is a 500 on every call, and a DEPENDS entry naming nothing raises
# UnregisteredTool inside execute_tool. Both are runtime failures no unit test
# of the module itself can see.
tr.init_registry("auditd-wiring-test", {})
out = tr.execute_tool("query_audit_events", {"limit": 5})
check("query_audit_events dispatches with no module loaded", out["error"], None)
inner = out["result"] or {}

# THE PAYLOAD CARRIES THE ABSENCE IN WORDS.
# On this host auditd is not installed, and this is the assertion that makes
# the whole tier's promise checkable: the model must be able to tell "nothing
# was watching" from "nothing happened" by reading the answer, WITHOUT having
# to know anything about auditd first.
_real_which_2 = am._which
try:
    am._which = lambda name: None
    tr.init_registry("auditd-wiring-test", {})
    out = tr.execute_tool("query_audit_events", {})
    inner = out["result"] or {}
    check("on a host with no auditd the tool still answers", out["error"], None)
    check("  and it says the feed is NOT INSTALLED",
          inner.get("auditd_state"), "NOT INSTALLED")
    check("  and installed is false", inner.get("installed"), False)
    check("  and the record list is empty", inner.get("records"), [])
    ok("  and the note says NOTHING was being recorded",
       "NOTHING" in (inner.get("note") or ""))
    ok("  and it prints the one command",
       inner.get("install_command") == am.INSTALL_COMMAND)
    ok("  and the coverage block carries the sentence a model would quote",
       any("NOTHING" in lim for lim in (inner.get("coverage_limits") or [])))
finally:
    am._which = _real_which_2

# AND WITH A READABLE FIXTURE LOG, the tool serves records through dispatch.
tr.init_registry("auditd-wiring-test", {"auditd": LinuxAuditd(
    "auditd-wiring-test", cfg_for(LOG))})
write_log([raw_path(name="/etc/passwd"), raw_path(name="/etc/sudoers")])
out = tr.execute_tool("query_audit_events", {"record_type": "PATH", "limit": 3})
inner = out["result"] or {}
check("a readable log is dispatched and read", out["error"], None)
check("  and the state says so", inner.get("auditd_state"), "READABLE")
ok("  and records came back", len(inner.get("records") or []) > 0)
ok("  and each record carries its identity fields",
   all("identity" in r for r in (inner.get("records") or [])))

# THE TOOL'S OWN DESCRIPTION TELLS THE MODEL THE FOUR STATES. A description
# that omitted them would leave the model to infer what an empty list means,
# which is the inference this whole file exists to prevent.
desc = [t for t in tr.TOOL_MANIFEST
        if t["name"] == "query_audit_events"][0]["description"]
for token in ("NOT INSTALLED", "NO LOG YET", "CANNOT READ LOG", "READABLE"):
    ok(f"the tool's description names the {token} state", token in desc)
ok("  and it names the two rules built on the feed",
   "AUD-1001" in desc and "AUD-1002" in desc)
ok("  and it says the fields are chosen by whoever ran the process",
   "CHOSEN BY WHOEVER RAN THE PROCESS" in desc)
ok("  and it warns that comm is fifteen bytes the program picks itself",
   "fifteen-byte name a program sets for itself" in desc)
ok("  and it says the output is fenced for that reason",
   "fenced" in desc)
ok("  and it names the rotated files it does NOT read",
   "rotated files" in desc)

# EVERY OTHER TOOL THAT READS THIS FEED IS WHOLE, TOO.
# depends_on raises for a tool that never declared. This walks the manifest so
# a tool added next month without a DEPENDS entry fails HERE rather than in
# production, where the failure is a 500 on every call.
undeclared = []
for t in tr.TOOL_MANIFEST:
    try:
        sh.depends_on(t["name"])
    except sh.UnregisteredTool:
        undeclared.append(t["name"])
check("every tool in the manifest declares what its answer rests on",
      undeclared, [])


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
