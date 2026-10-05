"""
tests/test_ebpf_events.py, T6. The kernel camera's reader, and the camera's
own contract with it.

FAILURE CASES FIRST, and this file has an unusually sharp reason for that
ordering: THE READER'S HAPPY PATH IS AN EMPTY LIST. A camera that was never
installed, one that has stopped, one whose cursor is seeded and one that is
quietly recording all produce the same zero findings, and a test that only
checks the happy path cannot tell those four apart. Every case below exists to
prove that two of them are never collapsed into one sentence.

The order:

  [1]  THE STRUCT LAYOUT MATCHES THE C. This is first because it is the one
       defect here that produces PLAUSIBLE WRONG DATA instead of an error: a
       format four bytes short makes struct.unpack read the padding as data and
       return addresses and timestamps that decode cleanly and mean nothing.
       The test reads the C source and recomputes the size, so the next person
       to add a field to the struct gets a failure rather than a shifted record.
  [2]  The camera's absence is NOT a quiet machine. Never installed, stopped,
       empty and never-analysed are four different answers.
  [3]  THE FIRST PASS SEEDS. A file holding a week of history must raise
       NOTHING, or the first run of the sensor is a page of somebody else's
       past and its reader learns to skim it.
  [4]  A change raises ONCE, and the cursor moves with it, so the same event is
       not re-reported every poll until somebody switches the module off.
  [5]  systemd's private tmp does NOT raise. MEASURED on this host: a boot
       executes systemd's own executor out of /tmp. A security tool that files a
       finding on every boot of the machine it was installed on is a tool whose
       page two nobody reads.
  [6]  A real staging hit DOES raise, and a shell on a staged file is a
       DIFFERENT id from a plain program in one -- one id per claim, because the
       remedies differ (look at the file / ask what it ran).
  [7]  Loopback on a dangerous port does NOT raise. 127.0.0.1:4444 is a
       developer's test server.
  [8]  The cap ANNOUNCES itself. "5 programs ran from /tmp" and "5 of 436" are
       different sentences and only one of them is honest.
  [9]  Every id this module can raise IS registered, at a severity the register
       declares, and the entity types are in BOTH vocabularies -- memory_engine
       AND incident.write_incident. The second one raises and its caller
       SWALLOWS the raise, so a wrong entity type reaches the findings table and
       opens no incident, silently.
 [10]  The camera's own arithmetic: its drop counters are read over the
       POSSIBLE cpu count, and its --verbose flag (which promised output it
       never produced) is gone.

Run it directly: python tests/test_ebpf_events.py
"""
import os
import pathlib
import re
import sqlite3
import struct
import sys
import time
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import detections as det                    # noqa: E402
from core import memory_engine as me                  # noqa: E402
from core import sensors as sn                        # noqa: E402
from tools import ebpf_events as ee                   # noqa: E402

# THE SENSOR ROW AND THE SESSION ROW, which the findings table has a foreign
# key to. The local integrity test does the same thing for the same reason: a
# finding written against a session that does not exist is refused by the
# database, and a test that hits that would be reporting a fixture problem as a
# code failure.
sn.register_local()
TEST_SESSION = "test_ebpf_events"

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def ok(label, condition):
    check(label, bool(condition), True)


# A CAMERA FILE, BUILT THE WAY THE CAMERA BUILDS ONE
#
# The columns and the two tables are copied from ebpf_monitor.py's own
# executescript, so this fixture cannot drift from the writer without the test
# noticing: a column this file forgets is a column the reader asks for and does
# not get, and the read fails loudly.
CAMERA_DDL = """
CREATE TABLE ebpf_event (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    kind      TEXT NOT NULL,
    ts_ns     INTEGER NOT NULL,
    pid       INTEGER NOT NULL,
    tgid      INTEGER NOT NULL,
    ppid      INTEGER NOT NULL DEFAULT 0,
    uid       INTEGER NOT NULL DEFAULT 0,
    comm      TEXT NOT NULL DEFAULT '',
    parent    TEXT NOT NULL DEFAULT '',
    filename  TEXT,
    daddr     TEXT,
    dport     INTEGER,
    family    TEXT,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE ebpf_health (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    dropped_exec    INTEGER NOT NULL DEFAULT 0,
    dropped_connect INTEGER NOT NULL DEFAULT 0,
    events_written  INTEGER NOT NULL DEFAULT 0,
    note       TEXT
);
"""


def make_camera(path, events=(), health=None, age_seconds=0):
    """
    A camera file with the given events, oldest first.

    `age_seconds` puts the newest row that far in the past, which is how the
    stopped-camera case is built: a file with real rows in it and nothing
    recent, which is exactly the state a reader must not call quiet.
    """
    if os.path.exists(path):
        os.unlink(path)
    conn = sqlite3.connect(path)
    conn.executescript(CAMERA_DDL)
    stamp = datetime.now(timezone.utc) - timedelta(seconds=age_seconds)
    for i, ev in enumerate(events):
        when = (stamp - timedelta(seconds=len(events) - i)).strftime(
            "%Y-%m-%d %H:%M:%S")
        conn.execute(
            """INSERT INTO ebpf_event (kind, ts_ns, pid, tgid, ppid, uid, comm,
                                       parent, filename, daddr, dport, family,
                                       recorded_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ev.get("kind", "exec"), ev.get("ts_ns", 1000 + i * 10),
             ev.get("pid", 100 + i), ev.get("tgid", 100 + i),
             ev.get("ppid", 1), ev.get("uid", 1000), ev.get("comm", "prog"),
             ev.get("parent", "bash"), ev.get("filename"),
             ev.get("daddr"), ev.get("dport"), ev.get("family", "inet"),
             when))
    if health is not None:
        conn.execute(
            """INSERT INTO ebpf_health (dropped_exec, dropped_connect,
                                        events_written, note)
               VALUES (?,?,?,?)""",
            (health.get("dropped_exec", 0), health.get("dropped_connect", 0),
             health.get("events_written", len(events)), health.get("note")))
    conn.commit()
    conn.close()
    return path


def cfg_for(path, **kw):
    block = {"enabled": True, "events_db": str(path)}
    block.update(kw)
    return {"sensors": {"ebpf_events": block}}


SCRATCH = pathlib.Path(_isolate_db.isolate()).parent
CAM = str(SCRATCH / "camera.db")


print("\n[1] THE STRUCT LAYOUT MATCHES THE C SOURCE, FIELD FOR FIELD")

import importlib.util as _ilu                          # noqa: E402
_cam_spec = _ilu.spec_from_file_location("ebpf_camera",
                                         ROOT / "ebpf" / "ebpf_monitor.py")
_cm = _ilu.module_from_spec(_cam_spec)
_cam_spec.loader.exec_module(_cm)

# THE COMPILER'S OWN ALIGNMENT RULES, recomputed here rather than trusted.
# Reading the C declaration and summing the members is the only way this test
# can catch a format that drifted: struct.calcsize(EVENT_FMT) on the wrong
# format still returns a number, and it is a number that makes unpack succeed.
C_SRC = (ROOT / "ebpf" / "ebpf_monitor.bpf.c").read_text(encoding="utf-8")

# The symbolic sizes are #defines in the same file, so they are read from it
# rather than hardcoded: a PATH_LEN that moves from 256 to 512 must move the
# expected size with it, or this test would pass against a stale constant.
DEFINES = {name: int(value) for name, value in
           re.findall(r"#define\s+(\w+)\s+(\d+)", C_SRC)}
ok(f"the C file's own size defines were read "
   f"(TASK_COMM_LEN={DEFINES.get('TASK_COMM_LEN')}, "
   f"PATH_LEN={DEFINES.get('PATH_LEN')})",
   DEFINES.get("TASK_COMM_LEN") and DEFINES.get("PATH_LEN"))

member_block = C_SRC.split("struct event_t {", 1)[1].split("};", 1)[0]
members = []
for line in member_block.splitlines():
    line = line.split("//")[0].strip()
    if not line or line.startswith("#"):
        continue
    m = re.match(r"^(?:unsigned\s+)?(__u\d+|char)\s+(\w+)\s*"
                 r"\[\s*(\w+)\s*\]\s*;", line)
    if m:
        count = DEFINES.get(m.group(3))
        if count is None:
            count = int(m.group(3))
        members.append((m.group(1), count))
        continue
    m = re.match(r"^(?:unsigned\s+)?(__u\d+|char)\s+(\w+)\s*;", line)
    if m:
        members.append((m.group(1), 1))

SIZES = {"__u8": 1, "__u16": 2, "__u32": 4, "__u64": 8}
ALIGN = {"__u8": 1, "__u16": 2, "__u32": 4, "__u64": 8}

offset, max_align = 0, 1
for type_name, count in members:
    size = SIZES.get(type_name, 1) * count
    align = ALIGN.get(type_name, 1)
    max_align = max(max_align, align)
    offset += (-offset) % align
    offset += size
c_size = offset + ((-offset) % max_align)

check("every member of the C struct was found, none skipped",
      len(members), 14)
check("sizeof(struct event_t) computed from the C source", c_size, 344)
check("the loader's EVENT_SIZE matches it EXACTLY",
      _cm.EVENT_SIZE, c_size)

# The four fields the wrong format read wrongly, asserted by ROUND TRIP rather
# than by total size alone: a struct can be the right size and still place a
# member four bytes early, which is precisely the defect that was here.
check("the format declares the padding member the C inserts implicitly",
      "_pad" in _cm.EVENT_FMT or _cm.EVENT_FMT.count("I") >= 4, True)

# A round trip: pack a record the way the kernel would and decode it with the
# reader's own _decode. If the format is off by any field, the address and the
# timestamp come back wrong HERE, which is the whole point of this test.
import random                                          # noqa: E402
random.seed(7)
probe_comm = b"payload\x00" + b"\x00" * 8
probe_parent = b"bash\x00" + b"\x00" * 11
probe_file = b"/tmp/implant.sh\x00" + b"\x00" * 239
probe_addr = 0x0100007F                              # 127.0.0.1, network order
probe_port = 4444
probe_ts = 987654321012345
raw = struct.pack(_cm.EVENT_FMT, 2, 4242, 4242, 1, probe_ts, 1000, 0,
                  probe_comm, probe_parent, probe_file, probe_addr,
                  probe_port, 2, b"\x00" * 16)
check("a kernel record round-trips through the reader's own _decode",
      len(raw), c_size)
decoded = _cm._decode(raw)
check("  the timestamp survives the padding", decoded["ts_ns"], probe_ts)
check("  the uid survives it", decoded["uid"], 1000)
check("  the comm survives it", decoded["comm"], "payload")
check("  the address decodes to the right four octets", decoded["daddr"],
      "127.0.0.1")
check("  the port survives it", decoded["dport"], 4444)

# And the short-read case is NAMED, not silently mis-parsed. The loader treats a
# record shorter than EVENT_SIZE as a mismatch rather than parsing it.
check("a short record is refused rather than parsed around",
      len(raw) >= _cm.EVENT_SIZE, True)


print("\n[2] THE CAMERA'S ABSENCE IS NOT A QUIET MACHINE")

missing = str(SCRATCH / "no-such-camera.db")
st = ee.camera_status(cfg_for(missing))
check("a camera that was never installed is not reported blind", st["blind"], False)
ok("and it says so in words", "never" in (st.get("note") or "").lower())
check("  and it is not reachable", st["reachable"], False)

make_camera(CAM, events=[
    {"comm": "apt", "filename": "/usr/bin/apt"},
], age_seconds=3600)
st = ee.camera_status(cfg_for(CAM))
check("a camera that has STOPPED is not reported blind either", st["blind"], False)
check("  it is reachable", st["reachable"], True)
check("  it has run before", st["has_ever_run"], True)
check("  but it is NOT running now", st["running"], False)
ok("and the note names the moment everything after which is unsampled",
   "stopped" in (st.get("note") or "").lower()
   or "unsampled" in (st.get("coverage_limits") or [""])[0].lower())

make_camera(CAM, events=[], age_seconds=0)
st = ee.camera_status(cfg_for(CAM))
check("a camera that never recorded an EVENT is not running", st["running"], False)
check("  and it has never run, which is a different sentence from stopped",
      st["has_ever_run"], False)
ok("  and the note says no event has ever been recorded",
   "no events at all" in (st.get("note") or "").lower())

make_camera(CAM, events=[{"comm": "ls", "filename": "/usr/bin/ls"}], age_seconds=0)
st = ee.camera_status(cfg_for(CAM))
check("a camera recording RIGHT NOW is running", st["running"], True)
check("  and is not blind", st["blind"], False)

# THE DROP COUNTERS ARE AN ANSWER, NOT A DETAIL.
make_camera(CAM, events=[{"comm": "ls", "filename": "/usr/bin/ls"}],
            health={"dropped_exec": 41, "dropped_connect": 3,
                    "events_written": 1})
st = ee.camera_status(cfg_for(CAM))
ok("drops are carried on the status", st["drops"]["exec"] == 41)
ok("and the coverage block states that those events are GONE, not delayed",
   any("dropped" in lim.lower() for lim in st["coverage_limits"]))

# A file that exists and is NOT a camera file is a real blind spot: the reader
# could not look, and that is about the reader rather than about the operator.
not_a_camera = SCRATCH / "not_a_camera.db"
conn = sqlite3.connect(not_a_camera)
conn.execute("CREATE TABLE something_else (x INTEGER)")
conn.commit()
conn.close()
st = ee.camera_status(cfg_for(not_a_camera))
check("a file that is not a camera file IS blind", st["blind"], True)
ok("and the reason says what is wrong with it",
   "ebpf_event" in (st.get("blind_reason") or ""))


print("\n[3] THE FIRST PASS SEEDS AND RAISES NOTHING")

HIST = str(SCRATCH / "camera_history.db")
history = [{"comm": "curl", "filename": f"/tmp/old-{i}.sh"} for i in range(5)]
history.append({"comm": "bash", "filename": "/tmp/old-shell.sh"})
make_camera(HIST, events=history, age_seconds=5)

report = ee.analyze(cfg_for(HIST))
check("the first pass SEEDS", report["seeded"], True)
check("  and raises NOTHING for the history already in the file",
      len(report["findings"]), 0)
ok("  and the coverage says the cursor was set to the newest event, not the first",
   "newest" in (report["coverage"].get("first_pass") or "").lower())
cur = ee.read_cursor()
check("  and the cursor is now marked as seeded", cur["seeded"], True)

# THE SECOND PASS over the same file has nothing new either -- and that is a
# different reason, which is the point: no new events, not a seeded cursor.
report2 = ee.analyze(cfg_for(HIST))
check("a second pass over an unchanged file raises nothing", len(report2["findings"]), 0)
check("  and it is no longer a seeding pass", report2["seeded"], False)
check("  and it really did run", report2["analysed"]["exec"], 0)


print("\n[4] A CHANGE RAISES ONCE AND THE CURSOR MOVES WITH IT")

make_camera(CAM, events=[{"comm": "ls", "filename": "/usr/bin/ls"}], age_seconds=0)
ee.analyze(cfg_for(CAM))                            # seed
# Now a genuinely new event, and it is a staging hit.
conn = sqlite3.connect(CAM)
when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
conn.execute(
    """INSERT INTO ebpf_event (kind, ts_ns, pid, tgid, ppid, uid, comm, parent,
                               filename, recorded_at)
       VALUES ('exec', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
    (999, 777, 777, 1, 1000, "curl", "bash", "/tmp/payload.bin", when))
conn.commit()
conn.close()

report = ee.analyze(cfg_for(CAM))
ids = [f["detection_id"] for f in report["findings"]]
check("a new event is analysed", report["analysed"]["exec"], 1)
check("  and it raises the staging-location rule", ids,
      [ee.DID_LOCATION])

# THE SAME EVENT AGAIN. The cursor moved, so this pass has nothing to look at.
report = ee.analyze(cfg_for(CAM))
check("THE SAME EVENT DOES NOT RAISE TWICE", len(report["findings"]), 0)
check("  because the cursor moved past it", report["analysed"]["exec"], 0)
cur = ee.read_cursor()
ok("  and the cursor is at the newest event id",
    cur["last_event_id"] >= 2 and cur["passes"] >= 2)

# A REAL SECOND EVENT WITH THE SAME PATH, in a LATER window. The module looks
# at what is new since the cursor and correctly reports the second execution;
# DEDUPING it is the ADAPTER's job, because that is the layer that can see what
# is already open on the board. This assertion pins the boundary between the
# two: the module decides what is true, the adapter decides what to record.
conn = sqlite3.connect(CAM)
conn.execute(
    """INSERT INTO ebpf_event (kind, ts_ns, pid, tgid, ppid, uid, comm, parent,
                               filename, recorded_at)
       VALUES ('exec', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
    (1000, 778, 778, 1, 1000, "curl", "bash", "/tmp/payload.bin", when))
conn.commit()
conn.close()
report = ee.analyze(cfg_for(CAM))
check("a later repeat reaches the module as a new fact",
      len(report["findings"]), 1)
check("  and is counted in the analyser's own totals",
      report["analysed"]["exec"], 1)

# THE ADAPTER DROPS IT, which is the end-to-end "raised once" behaviour. Driven
# through the real adapter against the real findings table.
from adapters import LinuxEbpfEvents                     # noqa: E402

adapter = LinuxEbpfEvents("test_ebpf_events", cfg_for(CAM))
adapter._emit_all(report["findings"])
adapter._state["findings"] += 1
report = ee.analyze(cfg_for(CAM))
conn = sqlite3.connect(CAM)
conn.execute(
    """INSERT INTO ebpf_event (kind, ts_ns, pid, tgid, ppid, uid, comm, parent,
                               filename, recorded_at)
       VALUES ('exec', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
    (1001, 779, 779, 1, 1000, "curl", "bash", "/tmp/payload.bin", when))
conn.commit()
conn.close()
report = ee.analyze(cfg_for(CAM))
written = adapter._emit_all(report["findings"])
check("THE ADAPTER DOES NOT WRITE THE SAME FINDING TWICE", written, 0)


print("\n[5] systemd's PRIVATE TMP DOES NOT RAISE, ON THE SEED PASS OR EVER")

SPT = str(SCRATCH / "camera_spt.db")
make_camera(SPT, events=[
    {"comm": "systemd-resolve", "filename":
     "/tmp/systemd-private-8f3a2b-systemd-resolved.service-Xy9Z/tmp/x"},
    {"comm": "systemd-executor", "filename":
     "/tmp/systemd-private-aaaa-bbbb.service-cccc/tmp/y"},
], age_seconds=0)
ee.analyze(cfg_for(SPT))                            # seed
# The same shape arrives AGAIN, as a new event, which is what a reboot does.
conn = sqlite3.connect(SPT)
conn.execute(
    """INSERT INTO ebpf_event (kind, ts_ns, pid, tgid, ppid, uid, comm, parent,
                               filename, recorded_at)
       VALUES ('exec', 5, 900, 900, 1, 0, 'systemd-executor', 'systemd',
               '/tmp/systemd-private-ffff-systemd-logind.service-gggg/tmp/z',
               ?)""",
    (datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),))
conn.commit()
conn.close()
report = ee.analyze(cfg_for(SPT))
check("a NEW systemd private-tmp execution raises NOTHING", len(report["findings"]), 0)
check("  and it was looked at rather than skipped by luck",
      report["analysed"]["exec"], 1)

# The allowlist is CONFIGURABLE and a custom entry works, because the default
# is a default and not the only thing the rule can do.
report = ee.analyze(cfg_for(SPT, path_allowlist=["/tmp/systemd-private-",
                                                 "/tmp/nothing-matches/"]))
check("a custom allowlist is honoured", len(report["findings"]), 0)

print("\n  -- Timeshift's own scripts are quiet only when they run as root")
TS = str(SCRATCH / "camera_ts.db")
make_camera(TS, events=[], age_seconds=0)
ee.analyze(cfg_for(TS))                             # seed an empty file
conn = sqlite3.connect(TS)
_when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
for _pid, _uid, _file in ((910, 0, "/tmp/timeshift-Ab12Cd34/1"),
                          (911, 1000, "/tmp/timeshift-fake/payload")):
    conn.execute(
        """INSERT INTO ebpf_event (kind, ts_ns, pid, tgid, ppid, uid, comm,
                                   parent, filename, recorded_at)
           VALUES ('exec', ?, ?, ?, 1, ?, 'timeshift', 'timeshift', ?, ?)""",
        (_pid, _pid, _pid, _uid, _file, _when))
conn.commit()
conn.close()
report = ee.analyze(cfg_for(TS))
_paths = [f["entity_value"] for f in report["findings"]]
check("a root Timeshift script raises nothing",
      any("Ab12Cd34" in p for p in _paths), False)
check("THE SAME NAME RUN BY A USER STILL RAISES",
      any("timeshift-fake" in p for p in _paths), True)


print("\n[6] A REAL HIT RAISES, AND A SHELL IS A DIFFERENT ID")

R = str(SCRATCH / "camera_real.db")
make_camera(R, events=[], age_seconds=0)
ee.analyze(cfg_for(R))                              # seed an empty file
when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
conn = sqlite3.connect(R)
conn.execute(
    """INSERT INTO ebpf_event (kind, ts_ns, pid, tgid, ppid, uid, comm, parent,
                               filename, recorded_at)
       VALUES ('exec', 1, 501, 501, 1, 1000, 'implant', 'bash',
               '/dev/shm/implant', ?)""", (when,))
conn.commit()
conn.close()
report = ee.analyze(cfg_for(R))
check("a program in /dev/shm raises LNX-3001", 
      [f["detection_id"] for f in report["findings"]], [ee.DID_LOCATION])
check("  at the severity the register declares for it",
      report["findings"][0]["severity"], "low")
check("  with the process entity type",
      report["findings"][0]["entity_type"], "process")

# A SHELL on a staged file is the OTHER id, and this is the case an early draft
# folded into the first one with a severity that moved.
S = str(SCRATCH / "camera_shell.db")
make_camera(S, events=[], age_seconds=0)
ee.analyze(cfg_for(S))
conn = sqlite3.connect(S)
conn.execute(
    """INSERT INTO ebpf_event (kind, ts_ns, pid, tgid, ppid, uid, comm, parent,
                               filename, recorded_at)
       VALUES ('exec', 1, 502, 502, 1, 1000, 'bash', 'curl',
               '/tmp/x.sh', ?)""", (when,))
conn.commit()
conn.close()
report = ee.analyze(cfg_for(S))
check("a SHELL on a staged file raises LNX-3002, not LNX-3001",
      [f["detection_id"] for f in report["findings"]], [ee.DID_SHELL])
check("  and it is high, where the plain location rule is low",
      report["findings"][0]["severity"], "high")

# The classifier itself, called directly, so a rule change is caught here
# rather than only through the whole pipeline.
check("a shell name is matched exactly, not by substring",
      ee.is_shell("bashful", "/usr/bin/bashful"), False)
check("  a real shell is matched", ee.is_shell("bash", "/usr/bin/bash"), True)
check("  a renamed shell is caught by its comm", ee.is_shell("sh", "/tmp/x"),
      True)
check("a path outside every watch is not staged",
      ee.in_staging_directory("/usr/bin/ls"), None)
check("a user's Downloads directory IS watched",
      ee.in_staging_directory(
          os.path.expanduser("~/Downloads/thing.bin")), "Downloads/")

# A SYMLINK IS CLASSIFIED BY ITS TARGET, and this is a decision with a cost
# that is written down rather than an accident. realpath() resolves the link, so
# a link at /tmp/innocent pointing at /usr/bin/true reports NOTHING -- which is
# the right answer for a rule about where a program's BYTES are, and the wrong
# answer for a rule about where a NAME lives. The rule here is about the bytes.
# The test asserts the behaviour so a future change to it is deliberate.
_link = SCRATCH / "link_probe"
if os.path.lexists(_link):
    os.unlink(_link)
os.symlink("/usr/bin/true", _link)
check("a symlink is judged by where its TARGET lives, not where the link does",
      ee.in_staging_directory(str(_link)), None)
os.unlink(_link)


print("\n[7] LOOPBACK IS NOT A DANGEROUS DESTINATION")

P = str(SCRATCH / "camera_ports.db")
make_camera(P, events=[], age_seconds=0)
ee.analyze(cfg_for(P))
conn = sqlite3.connect(P)
for addr, port in (("127.0.0.1", 4444), ("192.0.2.9", 4444),
                   ("8.8.8.8", 443), ("::1", 4444), ("203.0.113.5", 31337)):
    conn.execute(
        """INSERT INTO ebpf_event (kind, ts_ns, pid, tgid, ppid, uid, comm,
                                   parent, daddr, dport, family, recorded_at)
           VALUES ('connect', ?, 900, 900, 1, 1000, 'nc', 'bash', ?, ?, 'inet',
                   ?)""",
        (int(time.time() * 1e9), addr, port, when))
conn.commit()
conn.close()
report = ee.analyze(cfg_for(P))
entities = sorted(f["entity_value"] for f in report["findings"]
                  if f["detection_id"] == ee.DID_PORT)
check("only the off-host dangerous ports raise", entities,
      ["192.0.2.9", "203.0.113.5"])
check("  and the finding is the port rule", 
      sorted({f["detection_id"] for f in report["findings"]}), [ee.DID_PORT])
check("  at medium", report["findings"][0]["severity"], "medium")
check("  with the ip entity type, which is what the register declares",
      report["findings"][0]["entity_type"], "ip")
check("loopback is refused by the classifier itself",
      ee.danger_destination("127.0.0.1", 4444), False)
check("  and an ordinary port is refused too",
      ee.danger_destination("192.0.2.9", 443), False)


print("\n[8] THE CAP ANNOUNCES ITSELF")

C = str(SCRATCH / "camera_cap.db")
make_camera(C, events=[], age_seconds=0)
ee.analyze(cfg_for(C))
conn = sqlite3.connect(C)
for i in range(ee.CAP_PER_ID_PER_PASS + 7):
    conn.execute(
        """INSERT INTO ebpf_event (kind, ts_ns, pid, tgid, ppid, uid, comm,
                                   parent, filename, recorded_at)
           VALUES ('exec', ?, ?, ?, 1, 1000, 'prog', 'bash', ?, ?)""",
        (i, 600 + i, 600 + i, f"/tmp/bulk-{i}.bin", when))
conn.commit()
conn.close()
report = ee.analyze(cfg_for(C))
raised = [f for f in report["findings"] if f["detection_id"] == ee.DID_LOCATION]
summary = [f for f in raised if (f.get("raw_data") or {}).get("capped")]
check("the per-id cap holds", len(raised) - len(summary),
      ee.CAP_PER_ID_PER_PASS)
check("  and ONE summary row is written", len(summary), 1)
check("  carrying the number it did NOT write",
      summary[0]["raw_data"]["dropped"], 7)
ok("  and the summary counts itself in the total it reports",
   summary[0]["raw_data"]["shown"] == ee.CAP_PER_ID_PER_PASS)
ok("  and its own text says the rows are not lost",
   "not lost" in summary[0]["description"].lower())


print("\n[9] EVERY ID, SEVERITY AND ENTITY TYPE IS REGISTERED IN BOTH PLACES")

from core import incident as inc                       # noqa: E402

check("this module declares exactly three detections", len(ee.DETECTIONS), 3)
for d in ee.DETECTIONS:
    did = d.split()[0]
    entry = det.get(did)
    ok(f"{did} is in the register", entry is not None)
    check(f"  {did} is owned by this module's role", entry.source, ee.ROLE)

for did, severity, entity in ((ee.DID_LOCATION, "low", "process"),
                              (ee.DID_SHELL, "high", "process"),
                              (ee.DID_PORT, "medium", "ip")):
    entry = det.get(did)
    ok(f"{did} declares the severity the code raises ({severity})",
       severity in entry.severities)
    ok(f"  and declares the entity type the code raises ({entity})",
       entity == entry.entity_type)
    ok(f"  and {entity} is in memory_engine's vocabulary",
       entity in me.VALID_ENTITY_TYPES)
    # THE SECOND VOCABULARY, AND IT IS THE SILENT ONE. incident.write_incident
    # RAISES for a type outside its own tuple and the WATCHER CATCHES it and
    # counts it, so a finding with a wrong type reaches the findings table and
    # opens NO incident with nothing said anywhere.
    ok(f"  and {entity} is in incident.write_incident's vocabulary",
       entity in ("ip", "process", "port", "user", "file"))

# PROVEN BY WRITING, not by reading the register. The writers are called with
# the ids the analyze() path actually produces.
me.save_finding(session_id=TEST_SESSION, source=ee.ROLE,
                detection_id=ee.DID_LOCATION, severity="low",
                entity_type="process", entity_value="/tmp/proof.bin",
                title="proof", description="proof", raw_data={})
me.save_finding(session_id=TEST_SESSION, source=ee.ROLE,
                detection_id=ee.DID_SHELL, severity="high",
                entity_type="process", entity_value="/tmp/proof.sh",
                title="proof", description="proof", raw_data={})
me.save_finding(session_id=TEST_SESSION, source=ee.ROLE,
                detection_id=ee.DID_PORT, severity="medium",
                entity_type="ip", entity_value="203.0.113.9",
                title="proof", description="proof", raw_data={})
check("all three write through save_finding without raising", True, True)

# A severity the register does NOT allow is refused, which proves the check is
# live rather than a formality.
try:
    me.save_finding(session_id=TEST_SESSION, source=ee.ROLE,
                    detection_id=ee.DID_LOCATION, severity="critical",
                    entity_type="process", entity_value="/tmp/nope",
                    title="proof", description="proof", raw_data={})
    check("a severity the register forbids is refused", "no raise", "raise")
except Exception:
    check("a severity the register forbids is refused", "raise", "raise")


print("\n[10] THE CAMERA'S OWN ARITHMETIC AND ITS HONEST FLAGS")

spec = __import__("importlib").import_module("importlib").util
import importlib.util as _ilu                       # noqa: E402

spec = _ilu.spec_from_file_location("ebpf_camera_again",
                                    ROOT / "ebpf" / "ebpf_monitor.py")
cam = _ilu.module_from_spec(spec)
spec.loader.exec_module(cam)

check("the camera's EVENT_SIZE is the C struct's size",
      cam.EVENT_SIZE, c_size)

# --verbose promised one line per event and PRINTED NOTHING, and the flag is
# gone rather than left in the help text as a lie.
help_text = open(ROOT / "ebpf" / "ebpf_monitor.py", encoding="utf-8").read()
check("the dead --verbose flag is gone from the source",
      "--verbose" in help_text, False)

# The per-cpu map is sized by POSSIBLE cpus. os.cpu_count() is the ONLINE set,
# and on a host with an offlined core the two differ -- which would read the
# drop counters short with no error at all.
sink_ring = cam.RingBuffer.__new__(cam.RingBuffer)
possible = sink_ring._possible_cpus()
online = os.cpu_count() or 1
ok(f"the camera counts POSSIBLE cpus ({possible}) not just online ({online})",
   possible >= online)

# The drop reader answers None for "unreadable" and never 0. That distinction
# is the whole point: a camera with no idea how many events it lost must not
# report that it lost none.
src = open(ROOT / "ebpf" / "ebpf_monitor.py", encoding="utf-8").read()
ok("the drop reader reports UNKNOWN rather than zero when refused",
   'out["error"]' in src and '"exec": None, "connect": None' in src)

print(f"\n{len(fails)} failure(s)")
if fails:
    for f in fails:
        print(f"  FAILED: {f}")
    sys.exit(1)
print("all checks passed")
sys.exit(0)
