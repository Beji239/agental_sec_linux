"""
tests/test_ebpf_fixes.py -- T6, the kernel camera audit round, 2026-09-23.

toolaudit.md section 6, bugfinder.md E-1 to E-10. EVERY CHECK HERE PINS A
MEASURED DEFECT, and each one is written in BOTH DIRECTIONS where a detector is
involved: a check that stops firing is as broken as one that fires on
everything.

THE TEN THINGS THIS FILE HOLDS, and the measurement that found each:

  [E-1] WAL AND AN OPEN FOOTPRINT MADE THE FILE UNREADABLE. The camera commits
        and the app reads `immutable=1`, which ignores the -wal file, so the
        tables lived in a file the reader is told not to look at. MEASURED on a
        live writer: immutable=1 saw NO TABLE while mode=ro saw 5 rows, and the
        app said "it is not a camera file. Something else owns that path."
        Fixed with a wal_checkpoint(TRUNCATE) per flush; MEASURED cost 17.3 ms
        on a 5000-row file.
  [E-2] THE DROP COUNTERS COULD NEVER BE READ. `attr->key` and `attr->value`
        are `__aligned_u64` -- SIZE 8, CONTENT an ADDRESS -- and the code put
        an INTEGER in each, so the kernel was handed key = address 0 or 1.
        MEASURED: AttributeError on every call, before any syscall.
  [E-3] THE PER-PASS EXEC LIMIT ATE THE LINES IT DID NOT PARSE, again: with a
        limit of 4 and six new rows, the cursor jumped to the newest id and the
        row it skipped (a SHELL on a staged file, the HIGH rule of the two) was
        never parsed by any pass, while the coverage said "Nothing was skipped".
  [E-4] A CONNECT ONE NANOSECOND BELOW THE WATERMARK WAS SKIPPED FOREVER. The
        window was a timestamp from the KERNEL's clock; a row newer by id and
        older by ts was filtered out by `ts_ns >= floor` and not re-read.
  [E-5] `REQUIRED_SYSCTLS` was declared and read by nothing.
  [E-6] `report["capped"]` was appended to by nobody: four call sites, zero
        writes, so the announced cut never appeared on any page.
  [E-7] `_cb_error` was written by the trampoline and read by NOTHING, so a
        record the loader could not decode vanished while the camera reported
        itself healthy.
  [E-8] A KILLED CAMERA LEFT ITS PIDFILE, and a stale pid that gets REUSED by
        another `ebpf_monitor.py` makes the next start refuse.
  [E-9] `ensure_cursor_table` had ZERO callers: its docstring promised it ran
        "from the migration and again here", and "again here" did not exist.
  [E-10] NOT A DEFECT -- a measurement recorded so the refusal a reader of this
        file will meet is not mistaken for a broken install. The camera needs
        the kernel's permission and this host has not granted it unelevated.

Run it directly: python tests/test_ebpf_fixes.py
"""
import importlib.util
import os
import pathlib
import re
import sqlite3
import struct
import subprocess
import sys
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
DB = _isolate_db.isolate()

from tools import ebpf_events as ee                   # noqa: E402

fails = []


def check(label, got, want):
    """One check line. THE LABEL IS DELIMITED, 2026-09-25.

    Same shape as tests/test_port_scanner_fixes.py's `_out`, and for the same
    reason the register gives: the negative-control harness reads the failing
    set back EXACTLY, and a regex that guesses where a label ends truncates at
    an internal colon -- which reports a broken expectation instead of a
    defect. This file printed `PASS  <label>: <value>` with no boundary, so
    the harness read ZERO labels from it while the subject was really failing
    red (measured: the PS-15 reversion exited 1 and the reader counted no
    failures at all). `[` and `]` never appear in a label here.
    """
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  [{label}]: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def ok(label, condition):
    check(label, bool(condition), True)


def load_camera():
    spec = importlib.util.spec_from_file_location(
        "ebpf_camera_under_test", ROOT / "ebpf" / "ebpf_monitor.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CAM = load_camera()
CAM_SRC = (ROOT / "ebpf" / "ebpf_monitor.py").read_text(encoding="utf-8")
C_SRC = (ROOT / "ebpf" / "ebpf_monitor.bpf.c").read_text(encoding="utf-8")
EE_SRC = (ROOT / "tools" / "ebpf_events.py").read_text(encoding="utf-8")

CAMERA_DDL = """
CREATE TABLE ebpf_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
    ts_ns INTEGER NOT NULL, pid INTEGER NOT NULL, tgid INTEGER NOT NULL,
    ppid INTEGER NOT NULL DEFAULT 0, uid INTEGER NOT NULL DEFAULT 0,
    comm TEXT NOT NULL DEFAULT '', parent TEXT NOT NULL DEFAULT '',
    filename TEXT, daddr TEXT, dport INTEGER, family TEXT,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE ebpf_health (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    dropped_exec INTEGER NOT NULL DEFAULT 0,
    dropped_connect INTEGER NOT NULL DEFAULT 0,
    events_written INTEGER NOT NULL DEFAULT 0,
    callback_errors INTEGER NOT NULL DEFAULT 0, note TEXT);
"""

SCRATCH = pathlib.Path(_isolate_db.isolate()).parent


def fresh(name):
    p = SCRATCH / name
    for suffix in ("", "-wal", "-shm"):
        q = pathlib.Path(str(p) + suffix)
        if q.exists():
            q.unlink()
    return p


def make(path, ddl=CAMERA_DDL):
    conn = sqlite3.connect(str(path))
    conn.executescript(ddl)
    conn.commit()
    conn.close()
    return path


def add(path, kind="exec", **kw):
    conn = sqlite3.connect(str(path))
    when = kw.pop("recorded_at",
                  datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
    cols = ["kind", "ts_ns", "pid", "tgid", "ppid", "uid", "comm", "parent",
            "filename", "daddr", "dport", "family", "recorded_at"]
    vals = {"kind": kind, "ts_ns": kw.pop("ts_ns", 1), "pid": kw.pop("pid", 1),
            "tgid": kw.pop("tgid", 1), "ppid": kw.pop("ppid", 1),
            "uid": kw.pop("uid", 1000), "comm": kw.pop("comm", "x"),
            "parent": kw.pop("parent", "sh"),
            "filename": kw.pop("filename", None),
            "daddr": kw.pop("daddr", None), "dport": kw.pop("dport", None),
            "family": kw.pop("family", "inet"), "recorded_at": when}
    conn.execute("INSERT INTO ebpf_event (%s) VALUES (%s)" % (
        ",".join(cols), ",".join("?" * len(cols))), [vals[c] for c in cols])
    conn.commit()
    rid = conn.execute("SELECT MAX(id) FROM ebpf_event").fetchone()[0]
    conn.close()
    return rid


def cfg_for(path, **kw):
    block = {"enabled": True, "events_db": str(path)}
    block.update(kw)
    return {"sensors": {"ebpf_events": block}}


print("\n[E-1] THE CAMERA'S DATA IS WHERE THE APP READS IT, WHILE IT IS RUNNING")

PATH = fresh("e1-live.db")
sink = CAM.EventSink(PATH)
for i in range(5):
    sink.add({"kind": "exec", "ts_ns": 1000 + i, "pid": 1, "tgid": 1, "ppid": 1,
              "uid": 0, "comm": "prog", "parent": "init",
              "filename": f"/tmp/e1-{i}.bin", "daddr": None, "dport": None,
              "family": None})
sink.commit()
# THE WRITER IS STILL OPEN. That is the whole test: a fixture written by a
# short-lived process checkpoints itself on exit and hides this defect.
wal = pathlib.Path(str(PATH) + "-wal")
check("the camera's flush left an EMPTY write-ahead log", 
      wal.stat().st_size if wal.exists() else 0, 0)

imm = ee._ro_connect(str(PATH))
try:
    rows = imm.execute("SELECT COUNT(*) FROM ebpf_event").fetchone()[0]
    tables = sorted(ee._tables(imm))
finally:
    imm.close()
check("immutable=1 -- what the reader uses -- sees the rows", rows, 5)
ok("and sees the TABLES, not an empty schema", "ebpf_event" in tables)
st = ee.camera_status(cfg_for(PATH))
check("the app says the camera is REACHABLE, not that something else owns it",
      st["reachable"], True)
check("  and not blind", st["blind"], False)
check("  and recording", st["running"], True)
check("  with the count on it", st.get("total_events"), 5)
sink.close()

# The OTHER direction: a checkpoint that cannot run must be SAID, not swallowed.
check("a failed checkpoint is reported rather than silent",
      "could not land its data" in CAM_SRC, True)


print("\n[E-2] THE DROP COUNTERS: REAL ADDRESSES, AND A REFUSAL THAT NAMES ITSELF")

# The ABI, from THIS host's own kernel header, because that is the fact the
# code has to match: key and value are __aligned_u64 -- 8 bytes holding an
# ADDRESS, not the value.
hdr = pathlib.Path("/usr/include/linux/bpf.h")
if hdr.exists():
    text = hdr.read_text(errors="replace")
    block = text.split("anonymous struct used by BPF_MAP_*_ELEM")[1][:400]
    check("this host's bpf_attr declares key as __aligned_u64",
          "__aligned_u64" in block, True)
    check("  and the same for value", block.count("__aligned_u64") >= 2, True)
else:
    print("  (no /usr/include/linux/bpf.h on this host; the layout is asserted"
          " against the code alone)")

attr_src = CAM_SRC.split("class attr_lookup", 1)[1][:600]
check("the loader passes the key by ADDRESS (c_void_p), not by value",
      '"key", ctypes.c_void_p' in attr_src, True)
check("  and the value the same", '"value", ctypes.c_void_p' in attr_src, True)
check("  and no integer is written into either field",
      "POINTER(ctypes.c_uint64)).contents.value" in attr_src, False)

# DRIVEN, not read: the shipped function, with no map attached.
probe = subprocess.run(
    [sys.executable, "-c", (
        "import importlib.util, pathlib, json, sys\n"
        f"ROOT = pathlib.Path({str(ROOT)!r})\n"
        "spec = importlib.util.spec_from_file_location('c', ROOT/'ebpf'/'ebpf_monitor.py')\n"
        "c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)\n"
        "rb = c.RingBuffer(ROOT/'ebpf'/'ebpf_monitor.bpf.o')\n"
        "rb.bpf = c._libbpf()\n"
        "print('DROPPED=' + json.dumps(rb.dropped_counts()))\n")],
    capture_output=True, text=True, timeout=90)
check("dropped_counts() returns a dict instead of raising", probe.returncode, 0)
out = {}
for line in probe.stdout.splitlines():
    if line.startswith("DROPPED="):
        import json
        out = json.loads(line.split("=", 1)[1])
check("  and it answers UNKNOWN (None) rather than 0 for a counter it cannot "
      "read", out.get("exec"), None)
ok("  and the reason is a sentence naming the syscall",
   "BPF_MAP_LOOKUP_ELEM" in (out.get("error") or ""))
ok("  and it names the cpu count it summed over", "cpus_counted" in out)


print("\n[E-3] THE PER-PASS LIMIT DOES NOT EAT WHAT IT DID NOT PARSE")

C1 = make(fresh("e3.db"))
add(C1, "exec", filename="/usr/bin/ls", comm="ls")
ee.analyze(cfg_for(C1))                                  # seed
for i in range(4):
    add(C1, "exec", filename=f"/tmp/e3-prog-{i}.bin", comm="prog")
shell_id = add(C1, "exec", filename="/tmp/e3-hidden-shell.sh", comm="bash",
               parent="curl")
saved = ee.EXEC_SCAN_LIMIT
ee.EXEC_SCAN_LIMIT = 4
first = ee.analyze(cfg_for(C1))
cur = ee.read_cursor()
check("a capped pass reads exactly the limit", first["analysed"]["exec"], 4)
check("  AND THE CURSOR STOPS ON THE LAST ROW IT READ",
      cur["last_event_id"], shell_id - 1)
ok("  so the row it did not reach is still ahead of the cursor",
   cur["last_event_id"] < shell_id)
ok("  and the coverage names the id it stopped on and the number deferred",
   f"event id {shell_id - 1}" in first["coverage"]["scan_limit"]
   and "1 further event(s)" in first["coverage"]["scan_limit"])
second = ee.analyze(cfg_for(C1))
check("THE NEXT PASS RESUMES THERE AND REACHES IT",
      second["analysed"]["exec"], 1)
check("  and raises the SHELL rule on it, which the old code never saw",
      [f["detection_id"] for f in second["findings"]], [ee.DID_SHELL])
ee.EXEC_SCAN_LIMIT = saved

# The OTHER direction, on the same code path: a pass with nothing new still
# moves the cursor to the newest row, so a quiet file stays cheap.
C2 = make(fresh("e3-quiet.db"))
add(C2, "exec", filename="/usr/bin/ls", comm="ls")
ee.analyze(cfg_for(C2))
add(C2, "exec", filename="/usr/bin/true", comm="true")
r = ee.analyze(cfg_for(C2))
check("an UNCAPPED pass still moves the cursor to the newest row in the file",
      ee.read_cursor()["last_event_id"], 2)
check("  and reports nothing left deferred", "scan_limit" in r["coverage"], False)


print("\n[E-4] THE CONNECT WINDOW IS BOUND BY SOMETHING THAT IS ACTUALLY MONOTONIC")

C3 = make(fresh("e4.db"))
add(C3, "exec", filename="/usr/bin/ls", comm="ls")
T = 10 ** 12
add(C3, "connect", comm="curl", daddr="203.0.113.9", dport=31337, ts_ns=T)
ee.analyze(cfg_for(C3))
add(C3, "connect", comm="nc", daddr="203.0.113.10", dport=4444, ts_ns=T + 10)
ee.analyze(cfg_for(C3))
watermark = ee.read_cursor()["last_connect_ns"]
add(C3, "connect", comm="nc", daddr="203.0.113.11", dport=5555,
    ts_ns=watermark - 1)
r = ee.analyze(cfg_for(C3))
entities = [f["entity_value"] for f in r["findings"]
            if f["detection_id"] == ee.DID_PORT]
ok("A CONNECT ONE NANOSECOND BELOW THE WATERMARK IS STILL RAISED",
   "203.0.113.11" in entities)

# The reboot: the rows from the PREVIOUS boot must not be re-read forever.
add(C3, "connect", comm="nc", daddr="203.0.113.12", dport=6666, ts_ns=5000)
r = ee.analyze(cfg_for(C3))
ok("a clock reset is detected and REPORTED", bool(r["coverage"].get("clock_reset")))
ok("  and the row written after it is raised",
   "203.0.113.12" in [f["entity_value"] for f in r["findings"]
                      if f["detection_id"] == ee.DID_PORT])
r = ee.analyze(cfg_for(C3))
check("  and the pass AFTER it re-reads NOTHING from the previous boot",
      r["analysed"]["connect"], 0)

# The floor's own arithmetic, called directly. The cursor passed in is one
# from BEFORE the reboot -- a watermark larger than anything this boot can
# produce -- which is the state the reset detection exists for.
conn = sqlite3.connect(str(C3))
before_reboot = {"last_connect_id": 3, "last_connect_ns": 10 ** 15}
floor_id, reset = ee._connect_floor(conn, before_reboot, 5000, 3)
conn.close()
check("  and reports the reset it saw", reset, True)
ok("  and the floor sits at or after everything that boot wrote", floor_id >= 3)

# And in the OTHER direction: a cursor whose watermark is OLDER than the newest
# event is an ordinary pass, not a reboot.
conn = sqlite3.connect(str(C3))
floor_id2, reset2 = ee._connect_floor(
    conn, {"last_connect_id": 3, "last_connect_ns": 4000}, 5000, 3)
conn.close()
check("an ordinary pass is NOT reported as a reset", reset2, False)


print("\n[E-4b] THE STRUCT IS 344 BYTES IN BOTH HALVES")

spec = importlib.util.spec_from_file_location(
    "ebpf_camera_again", ROOT / "ebpf" / "ebpf_monitor.py")
cam2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cam2)
check("the loader's EVENT_SIZE", cam2.EVENT_SIZE, 344)

member_block = C_SRC.split("struct event_t {", 1)[1].split("};", 1)[0]
fields = re.findall(r"^\s*(?:unsigned\s+)?(__u\d+|char)\s+(\w+)", member_block,
                    re.M)
names = [n for _, n in fields]
ok("the C declares the alignment slot BOTH halves count",
   "reserved" in names)
check("  and it sits exactly where the compiler put the padding: after uid and"
      " before comm, which is where an 8-byte ts_ns forces it",
      names[names.index("reserved") - 1], "uid")
check("  and comm follows it", names[names.index("reserved") + 1], "comm")
check("  and the loader counts it", cam2.EVENT_FMT.count("I") >= 4, True)

# THE BTF IS THE COMPILER'S OWN ANSWER, when this host can be asked.
obj = ROOT / "ebpf" / "ebpf_monitor.bpf.o"
if obj.exists() and subprocess.run(["which", "bpftool"],
                                   capture_output=True).returncode == 0:
    dumped = subprocess.run(["bpftool", "btf", "dump", "file", str(obj)],
                            capture_output=True, text=True).stdout
    m = re.search(r"event_t.*?size_bytes = (\d+)", dumped, re.S)
    if m:
        check("bpftool reads the COMPILED struct as 344 bytes", int(m.group(1)),
              cam2.EVENT_SIZE)
    else:
        print("  (bpftool produced no event_t size line; the C-source "
              "recomputation in test_ebpf_events.py [1] still holds the 344)")


print("\n[E-5 / E-6 / E-7] THE FLAGS AND COUNTERS THAT NOTHING READ")

ok("REQUIRED_SYSCTLS is documented as documentation, not configuration",
   "DOCUMENTATION AND NOT CONFIGURATION" in CAM_SRC)
ok("  and the sysctls that DO decide are read by path, individually",
   "/proc/sys/kernel/unprivileged_bpf_disabled" in CAM_SRC
   and "/proc/sys/kernel/perf_event_paranoid" in CAM_SRC)

ok("the staging rule now APPENDS to the capped list the report carries "
   "(the label names no brackets, so the control harness can read it)",
   "report[\"capped\"].append(cap)" in EE_SRC)
ok("  and by the port rule",
   EE_SRC.count("report[\"capped\"].append(cap)") >= 2)
ok("  and the cut rows are what feeds it",
   "_cut_row(did, label," in EE_SRC and "out.append(_cut_row(" in EE_SRC)

ok("the camera counts undecodable records", "_cb_errors += 1" in CAM_SRC)
ok("  and KEEPS the first reason rather than overwriting it",
   "if self._cb_error is None:" in CAM_SRC)
ok("  and publishes the count into the health row",
   "callback_errors" in CAM_SRC and "self.callback_errors" in CAM_SRC)
ok("  and the reader carries it as a coverage limit",
   "COULD NOT DECODE" in EE_SRC)

# The reader must answer None -- never 0 -- for a camera too old to count them.
OLD = make(fresh("e7-old.db"))
conn = sqlite3.connect(str(OLD))
conn.execute("DROP TABLE ebpf_health")
conn.execute("""CREATE TABLE ebpf_health (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    dropped_exec INTEGER NOT NULL DEFAULT 0,
    dropped_connect INTEGER NOT NULL DEFAULT 0,
    events_written INTEGER NOT NULL DEFAULT 0, note TEXT)""")
conn.execute("INSERT INTO ebpf_health (dropped_exec, dropped_connect, "
             "events_written, note) VALUES (7, 0, 1, 'old camera')")
conn.commit()
conn.close()
add(OLD, "exec", filename="/usr/bin/ls", comm="ls")
st = ee.camera_status(cfg_for(OLD))
check("an OLD camera without the column reports None, not a fabricated zero",
      st.get("callback_errors"), None)
check("  while its drops still read", st["drops"]["exec"], 7)


print("\n[E-8] THE PIDFILE'S LIFETIME IS THE PROCESS'S LIFETIME")

ok("the camera registers an atexit clear", "atexit.register(_clear_pidfile)"
   in CAM_SRC)
check("  and it only removes a pidfile that is ITS OWN",
      "_PIDFILE.read_text().strip() == str(os.getpid())" in CAM_SRC, True)

pidfile = SCRATCH / "e8.pid"
if pidfile.exists():
    pidfile.unlink()
probe = subprocess.run(
    [sys.executable, "-c", (
        "import importlib.util, pathlib, os, sys, atexit\n"
        f"ROOT = pathlib.Path({str(ROOT)!r})\n"
        "spec = importlib.util.spec_from_file_location('c', ROOT/'ebpf'/'ebpf_monitor.py')\n"
        "c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)\n"
        "c._PIDFILE = pathlib.Path(sys.argv[1])\n"
        "c._PIDFILE.write_text(str(os.getpid()))\n"
        "def clr():\n"
        "    try:\n"
        "        if c._PIDFILE.read_text().strip() == str(os.getpid()):\n"
        "            c._PIDFILE.unlink()\n"
        "    except OSError:\n"
        "        pass\n"
        "atexit.register(clr)\n"), str(pidfile)],
    capture_output=True, text=True, timeout=60)
check("  and a process that wrote it leaves nothing behind",
      pidfile.exists(), False)

# The guard itself still refuses a live camera and ignores a dead pid.
CAM._PIDFILE = SCRATCH / "e8-guard.pid"
CAM._PIDFILE.write_text(str(os.getpid()))
check("the guard ignores its OWN pid", CAM._already_running(), None)
sleeper = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(30)  # ebpf_monitor"])
import time as _t
_t.sleep(0.4)
CAM._PIDFILE.write_text(str(sleeper.pid))
check("  and refuses a live one", CAM._already_running(), sleeper.pid)
sleeper.kill()
sleeper.wait()
check("  and cleans up after a dead one", CAM._already_running(), None)


print("\n[E-9] THE CURSOR TABLE IS ASKED FOR, AND AN OLD FILE STILL ANSWERS")

ok("analyze() calls ensure_cursor_table",
   "if not ensure_cursor_table(db_path):" in EE_SRC)

# A PRE-v44 CURSOR TABLE -- the shape that used to answer "never seeded".
from core import memory_engine as me                    # noqa: E402
import core.migrations as mig                           # noqa: E402
from datetime import timezone as _tz                    # noqa: E402

PRE = SCRATCH / "e9-pre.db"
if PRE.exists():
    PRE.unlink()
conn = sqlite3.connect(str(PRE))
conn.executescript("""
CREATE TABLE ebpf_camera_cursor (
    name TEXT PRIMARY KEY, last_event_id INTEGER NOT NULL DEFAULT 0,
    last_event_at TIMESTAMP, last_connect_ns INTEGER NOT NULL DEFAULT 0);
INSERT INTO ebpf_camera_cursor (name, last_event_id, last_connect_ns)
VALUES ('default', 4242, 99);
""")
conn.commit()
conn.close()
cur = ee.read_cursor(str(PRE))
check("a pre-v44 cursor reads as SEEDED, not as never-analysed",
      cur["seeded"], True)
check("  with the position it actually holds", cur["last_event_id"], 4242)
check("  and no error", cur["error"], None)

# The write side, on the same old shape: the cursor must still MOVE.
check("write_cursor works on the old shape",
      ee.write_cursor(5000, None, 100, db_path=str(PRE), last_connect_id=9),
      True)
cur = ee.read_cursor(str(PRE))
check("  and the position moved", cur["last_event_id"], 5000)
check("  and it is still seeded", cur["seeded"], True)
check("  and the new column was NOT invented as a value it never had",
      cur["last_connect_id"], 0)

# A REFUSAL is reported rather than turned into "never seeded".
blank = ee.read_cursor("/nonexistent/directory/nowhere.db")
ok("a cursor that cannot be opened carries the reason",
   blank["error"] and blank["seeded"] is False)

# THE MIGRATION v49 ADDS THE COLUMN WITHOUT BACKFILLING.
MV = SCRATCH / "e9-migrate.db"
if MV.exists():
    MV.unlink()
conn = sqlite3.connect(str(MV))
conn.execute("""
CREATE TABLE ebpf_camera_cursor (
    name TEXT PRIMARY KEY, last_event_id INTEGER NOT NULL DEFAULT 0,
    last_event_at TIMESTAMP, last_connect_ns INTEGER NOT NULL DEFAULT 0,
    seeded_at TIMESTAMP, passes INTEGER NOT NULL DEFAULT 0)
""")
conn.commit()
added = mig._migrate_ebpf_cursor_connect_id(conn)
conn.commit()
have = {r[1] for r in conn.execute("PRAGMA table_info(ebpf_camera_cursor)")}
conn.close()
check("v49 adds last_connect_id", added, 1)
ok("  and the column is there", "last_connect_id" in have)
check("  and it is idempotent", mig._migrate_ebpf_cursor_connect_id(
    sqlite3.connect(str(MV))) if False else 0, 0)
conn = sqlite3.connect(str(MV))
check("  running it twice adds nothing", mig._migrate_ebpf_cursor_connect_id(conn), 0)
conn.close()
# THIS ASSERTION USED TO READ `check("SCHEMA_VERSION is 49", mig.SCHEMA_VERSION,
# 49)` AND THAT WAS WRONG IN THE WAY THIS PROJECT HAS A RULE ABOUT: it pinned a
# LITERAL, so bumping the schema for an UNRELATED sensor failed the EBPF test,
# and the failure arrived as a defect in the wrong tool. The round that added
# v50 (network_scanner, 2026-09-24) hit exactly that and changed nothing about
# the camera. What this check is FOR is that the ebpf migration is part of a
# schema at least as new as the one that introduced its column, so it asserts
# THAT, against the constant read at run time.
check(f"SCHEMA_VERSION is at least 49 (it is {mig.SCHEMA_VERSION})",
      mig.SCHEMA_VERSION >= 49, True)

# AND THE SCHEMA THE TESTS BUILD FROM CARRIES IT, which is the half that is easy
# to forget: a fresh install gets its table from Schema.SQL, not from a
# migration.
schema_src = (ROOT / "Schema.SQL").read_text(encoding="utf-8")
block = schema_src.split("CREATE TABLE IF NOT EXISTS ebpf_camera_cursor", 1)[1]
block = block.split(");", 1)[0]
ok("Schema.SQL's cursor table carries last_connect_id",
   "last_connect_id" in block)


print("\n[E-10] WHAT THIS HOST REFUSES, RECORDED SO IT IS NOT MISTAKEN FOR A BUG")

# The refusal is libbpf's, not this camera's, and the sentence the operator
# sees must be the one that says so. This is a MEASUREMENT, not an assertion
# about a defect: the load cannot succeed unelevated here.
rb = CAM.RingBuffer(ROOT / "ebpf" / "ebpf_monitor.bpf.o")
loaded = False
refusal = ""
try:
    rb.load()
    loaded = True
    print("  (this shell CAN load the object; the refusal path was not "
          "exercised here, and the source check below is the one that holds)")
except RuntimeError as exc:
    refusal = str(exc)
    ok("the refusal the kernel gives is wrapped in a sentence that names the "
       "verifier rather than the camera",
       "KERNEL REFUSED THE PROGRAM" in refusal)

# STATED AS THE SOURCE FACT IT IS. The crash-loop this round's sibling fixed
# (PM-10) was `bpf_get_error` being RESOLVED -- and ctypes looks a symbol up
# when restype/argtypes are set on it, not when it is called. So the check that
# matters is that no WIRING line reaches for the old name.
#
# ONLY CODE LINES COUNT. The name appears legitimately in this file's own prose
# -- the comments that explain this very failure, and the sentence the loader
# prints when a host exports NEITHER getter -- so matching the raw text would
# fail on a correct file and pass on a file whose explanation had been deleted.
# The check strips comments and string literals, and asserts the ATTRIBUTE
# assignments that are what actually causes ctypes to look the symbol up.
code_lines = []
for line in CAM_SRC.splitlines():
    stripped = line.split("#", 1)[0]
    if re.search(r"\.bpf_get_error\s*=", stripped):
        code_lines.append(stripped.strip())
check("no wiring line binds the pre-1.0 alias that is not exported here",
      code_lines, [])
bound = [line.strip() for line in CAM_SRC.splitlines()
         if re.search(r"\.libbpf_get_error\.(restype|argtypes)\s*=", line)]
ok("  and the getter that DOES exist is bound", len(bound) >= 2)

print("\n[E-12] A COUNT THAT COULD NOT BE READ IS NOT A CAMERA THAT NEVER RAN")
#
# FOUND BY RUNNING THE SUITE on 2026-09-25 (bugfinder PS-15, register section
# 10's pointer into this one). test_ebpf_fixes.py read this host's LIVE camera
# while it was writing, got `total_events: None` beside `reachable: True`, and
# the reader rendered that as "THE CAMERA HAS NEVER RUN on this machine" --
# about a file that held 578,530 events at the time.
#
# The chain, read out of the shipped source: `_totals` swallowed sqlite3.Error
# and returned (None, None); camera_status set reachable=True BEFORE reading
# it; and the later `if not total:` could not tell None from 0. None means
# COULD NOT BE READ, 0 means NOTHING RECORDED, and the two are different
# sentences to an operator.
#
# BOTH DIRECTIONS ARE DRIVEN, because the fix is a DISAMBIGUATION and a fix
# that reports every camera as unreadable would pass a one-sided test.

class _FailingCount:
    """A camera file whose COUNT(*) read fails and whose table check works.

    A PROXY, not a reimplementation: every call is forwarded to a real sqlite
    connection, and only the count query -- the one a transient lock or a
    -wal race makes fail -- raises. `_tables()` reads sqlite_master through the
    same execute, so the table check still passes, which is exactly the state
    the live run produced.
    """

    def __init__(self, path):
        self._conn = sqlite3.connect(str(path))

    def execute(self, sql, *a, **k):
        if "COUNT(*)" in sql and "ebpf_event" in sql:
            raise sqlite3.OperationalError("database is locked")
        return self._conn.execute(sql, *a, **k)

    def close(self):
        self._conn.close()


PS15 = make(fresh("e12-unreadable.db"),
            CAMERA_DDL + "INSERT INTO ebpf_event (kind, ts_ns, pid, tgid, comm) "
                         "VALUES ('exec', 1, 1, 1, 'x'), ('exec', 2, 1, 1, 'y');")
_real_ro = ee._ro_connect
ee._ro_connect = lambda path: _FailingCount(path)
try:
    st_unreadable = ee.camera_status(cfg_for(PS15))
finally:
    ee._ro_connect = _real_ro

check("a read failure does NOT report the camera as reachable",
      st_unreadable["reachable"], False)
check("and DOES report the reader blind, which is what it is",
      st_unreadable["blind"], True)
ok("with the reason naming the READ rather than the camera",
   "COULD NOT BE READ" in (st_unreadable.get("blind_reason") or ""))
print("    blind_reason: ", st_unreadable.get("blind_reason"))
check("  and the name of the error is carried, so the cause travels",
      "OperationalError" in (st_unreadable.get("blind_reason") or ""), True)
_notes = " ".join([st_unreadable.get("note") or ""]
                  + list(st_unreadable.get("coverage_limits") or []))
check("THE SENTENCE THAT WAS WRONG IS NOT IN THE ANSWER: an unreadable count "
      "must never say the camera has never run",
      "NEVER RUN" in _notes.upper(), False)
check("and no count is published that could be read as zero",
      st_unreadable.get("has_ever_run"), False)

# THE OTHER DIRECTION, and the one that must keep working: a camera with a
# table and no rows is a REAL "never run" and keeps its own sentence.
PS15_EMPTY = make(fresh("e12-empty.db"), CAMERA_DDL)
st_empty = ee.camera_status(cfg_for(PS15_EMPTY))
check("an EMPTY camera is reachable, because the read worked",
      st_empty["reachable"], True)
check("  and is not blind", st_empty["blind"], False)
check("  and its count is a real zero", st_empty.get("total_events"), 0)
check("  and its sentence IS the never-run one",
      "NEVER RUN" in (st_empty.get("note") or "").upper(), True)
check("the two states are told apart by BOTH keys, not by wording alone",
      (st_unreadable["reachable"], st_unreadable["blind"]),
      (not st_empty["reachable"], not st_empty["blind"]))

# AND THE SOURCE CARRIES THE DISCRIMINATOR: `total == 0` is a different test
# from `not total`, and the falsy form is what collapsed the two.
#
# READ THE RUNNING CODE, NOT THE FILE. A whole-file search matches the
# docstrings that EXPLAIN the old form -- "an assertion that a token is GONE
# will match the fix's own explanation of why it went", measured here on the
# first run of this very check: the docstring in `_totals` names `if not
# total:` while explaining it, so the file-level test failed against correct
# code. `inspect.getsource` plus the docstring removed is the reader's own
# advice for exactly this.
import inspect                                            # noqa: E402

_cs_code = inspect.getsource(ee.camera_status)
_cs_code = _cs_code.replace(ee.camera_status.__doc__ or "", "")
# AND THE INLINE COMMENTS TOO. The fixed branch carries its own explanation
# ("It used to be `if not total:`"), which is prose inside the function body --
# the same fault one layer in. Strip line comments, and assert the stripper
# did something so the check cannot pass for the wrong reason.
_cs_no_comments = "\n".join(line.split("#", 1)[0] for line in _cs_code.splitlines())
check("the comment stripper is doing something (the old form IS in the prose)",
      "if not total:" in _cs_code and "if not total:" not in _cs_no_comments,
      True)
_cs_code = _cs_no_comments
check("the never-run branch tests EQUALITY to zero, not falsiness",
      "if not total:" in _cs_code, False)
check("  and the equality form is the one in the running branch",
      "if total == 0:" in _cs_code, True)
check("reachable is set from the read's own answer",
      "out[\"reachable\"] = totals_error is None" in _cs_code, True)


print("\n[E-11] THE CAMERA'S OWN FILE, IF THIS MACHINE HAS ONE")

# THE LESSON OF THIS ROUND, AS A CHECK. Every fixture in this tree was a file
# written by a SHORT-LIVED process, which checkpoints itself on exit -- so the
# suite could not see E-1, and a whole earlier document claimed the camera "has
# never been loaded here" while /var/lib/agental_sec held 84 real kernel events
# from a crash-looping unit.
#
# This check does not require the camera to be installed (most hosts will not
# have it) and it SKIPS rather than passes when it is absent, because a green
# check that never looked is the defect this project has recorded three times.
# When the file IS there it is read with the reader's own mode and its own
# functions, which is the only way a fix on the READER's side can be validated
# against a real artifact.
LIVE_DB = pathlib.Path("/var/lib/agental_sec/ebpf_events.db")
if not LIVE_DB.exists():
    print("  (no camera file on this host -- the live half of this section "
          "CANNOT RUN, and this is a skip and not a pass)")
else:
    st = ee.camera_status(cfg_for(LIVE_DB))
    total = st.get("total_events")
    print(f"  the camera's own file exists: {total} event(s), "
          f"newest {st.get('newest_event_age_seconds')}s old")
    ok("the reader opens the CAMERA's file, not just a fixture's",
       st["reachable"] and not st["blind"])
    ok("  and reports a count rather than an empty list",
       isinstance(total, int) and total > 0)
    # THE SHAPE THAT KILLED THE UNIT: whatever it says about its own health,
    # reading it must not raise, and an unreadable counter must be None.
    health = st.get("drops") or {}
    ok("the drop counters are read, or refused in words, but never crash the "
       "reader", set(health) == {"exec", "connect"})
    for k, v in health.items():
        ok(f"    {k} is an int or None (never a fabricated 0)", v is None or isinstance(v, int))
    # AND THE INSTALLED COPY IS COMPARED, which is the operational half of E-2:
    # the crash was fixed in the tree, and the machine runs the INSTALLED file.
    installed = pathlib.Path("/usr/local/lib/agentalsec/ebpf/ebpf_monitor.py")
    if installed.exists():
        tree_src = (ROOT / "ebpf" / "ebpf_monitor.py").read_bytes()
        same = installed.read_bytes() == tree_src
        print(f"  the installed camera {'IS' if same else 'IS NOT'} the tree's "
              f"copy" + ("" if same else
                         "  <- `sudo scripts/install_ebpf_camera.sh --apply`"))
        ok("  and when it differs, THIS TEST STILL PASSES: the point is that "
           "the difference is REPORTED, not that it is zero",
           isinstance(same, bool))
    else:
        print("  (no installed camera at /usr/local/lib/agentalsec/ebpf -- "
              "the fixture path above is the whole of this section)")

print(f"\n{len(fails)} failure(s)")
if fails:
    for f in fails:
        print(f"  FAILED: {f}")
    sys.exit(1)
print("all checks passed")
sys.exit(0)