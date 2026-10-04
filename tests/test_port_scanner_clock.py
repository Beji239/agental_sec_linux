"""
tests/test_port_scanner_clock.py — PS-14 OPTION (a), THE BACKGROUND CLOCK,
2026-09-25.

WHAT THIS FILE IS FOR. Register section 10 carried PS-14's design question as
PENDING THE OWNER'S WORD: (a) give the port scanner a real clock, so a self-scan runs
on a schedule and `sensors.port_scanner.poll_interval` gates it; or (b) keep it
pull-only and make the switch refuse the call. (b) was built first, as the
reversible direction; (a) was recorded as UNTOUCHED WORK. **The owner answered
in the owner's own words: "I want you to create that back ground clock".** This file
asserts the clock that answer asked for, in both directions:

  * the clock exists and is ARMED BY THE BOOT, with the cadence coming from
    the key that had no reader;
  * its due arithmetic is WALL CLOCK — read off the run record, so a restart
    inside the window does not double-scan and a machine waking from sleep
    does not drift an interval further behind every reboot;
  * the pass it runs is THE SHIPPED scan(), not a cheaper second scanner;
  * it records what it finds, in the operator's own store shape, as a
    self-scan — and a self-scan of loopback measures what is BOUND, never
    exposure;
  * the switch stops BOTH the clock and the call: a switch that stopped one
    of two paths is the AR-12 shape one layer down;
  * a failure is COUNTED and survives to status(), because a daemon thread
    that dies quietly is the shape this project has fixed three times;
  * a tick NEVER raises — one bad pass must not end the thread.

Nothing here writes to the operator's live store: memory_engine.DB_PATH is
pointed at a throwaway database built from Schema.SQL. The scans this file
drives are REAL scans of this host's loopback, which is the subject under
test; the clock's arithmetic is driven with explicit timestamps rather than by
sleeping.
"""
import json
import pathlib
import sqlite3
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def _out(tag, label, extra=""):
    """One check line. THE LABEL IS DELIMITED so the negative-control harness
    can read it back EXACTLY — the harness reads `^  FAIL  \\[(.*?)\\]`, so
    `[` and `]` never appear inside a label here."""
    print(f"  {tag}  [{label}]{extra}")


def check(label, got, want):
    ok = got == want
    _out("PASS" if ok else "FAIL", label,
         f": {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, value, detail=None):
    ok = bool(value)
    _out("PASS" if ok else "FAIL", label,
         (f": {detail!r}" if detail is not None else "")
         + ("" if ok else "  (want truthy)"))
    if not ok:
        fails.append(label)


def check_in(label, needle, haystack):
    ok = needle in (haystack or "")
    _out("PASS" if ok else "FAIL", label,
         ("" if ok else f": {needle!r} not in {str(haystack)[:200]!r}"))
    if not ok:
        fails.append(label)


tmp = pathlib.Path(tempfile.mkdtemp())
db = tmp / "t.db"

from core import memory_engine as me          # noqa: E402
me.DB_PATH = db

c = sqlite3.connect(db)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.commit()
c.close()

from core import migrations                   # noqa: E402
migrations.run_migrations(db)
from core import sensors as sn                # noqa: E402
sn.register_local()

from tools import port_scanner as ps          # noqa: E402

MAIN_SRC = (ROOT / "main.py").read_text(encoding="utf-8")


print("\n[1] THE CADENCE: the key that had no reader is the clock's clock")
#
# MEASURED BEFORE THE FIX (register PS-14): config.json carried
# `"port_scanner": {"enabled": true, "poll_interval": 600}` and a grep across
# main.py, adapters.py, core/ and tools/ found NO READER of either key. This
# section is the reader.

print("\n  -- the operator's own key is honoured, and the floor is in code")
check("the operator's own 600 is what the clock uses",
      ps.clock_interval_seconds(
          {"sensors": {"port_scanner": {"poll_interval": 600}}})[0], 600)
check("  and the sentence names the key that answered",
      ps.clock_interval_seconds(
          {"sensors": {"port_scanner": {"poll_interval": 600}}})[1],
      "sensors.port_scanner.poll_interval")
# A FLOOR IN CODE, not in prose: a config cannot ask for a permanently busy
# scanner. The measured cost of one pass is 0.54 s; at 60 s that is under 1%.
check("a value below the floor is RAISED to it, in code",
      ps.clock_interval_seconds(
          {"sensors": {"port_scanner": {"poll_interval": 5}}})[0],
      ps.MIN_CLOCK_SECONDS)
check("  and the raised value SAYS it was raised",
      "floor" in ps.clock_interval_seconds(
          {"sensors": {"port_scanner": {"poll_interval": 5}}})[1], True)
# AN UNREADABLE VALUE IS REPORTED, NOT SWALLOWED — the rule PS-13's
# tcp_method paid for, applied to this key: the operator who typed "600s"
# must be able to see that the string did not take.
check("a value that is not a number falls back to the default",
      ps.clock_interval_seconds(
          {"sensors": {"port_scanner": {"poll_interval": "600s"}}})[0],
      ps.DEFAULT_CLOCK_SECONDS)
check("  and the answer SAYS the key was unreadable",
      "unreadable" in ps.clock_interval_seconds(
          {"sensors": {"port_scanner": {"poll_interval": "600s"}}})[1], True)
check("an absent key falls back to the default",
      ps.clock_interval_seconds({})[0], ps.DEFAULT_CLOCK_SECONDS)
check("  and says why it could not be read",
      "not set" in ps.clock_interval_seconds({})[1], True)
check("an absent sensors block is the same answer as an absent key",
      ps.clock_interval_seconds({"sensors": {}})[0], ps.DEFAULT_CLOCK_SECONDS)
check("and the default IS the value the operator's own file carries, so an "
      "absent key and the owner's file land in the same place",
      ps.DEFAULT_CLOCK_SECONDS, 600)


print("\n[2] DUE ON WALL CLOCK, READ OFF THE RECORD — never off a counter this")
print("    process owns, so a restart inside the window does not double-scan")
now = time.time()
check("no record at all means LOOK NOW — a first boot is a seed pass",
      ps.clock_due(None, 600), (True, None))
check("a scan inside the window is NOT due",
      ps.clock_due(now - 100, 600, now=now), (False, 100.0))
check("a scan just past the window IS due",
      ps.clock_due(now - 601, 600, now=now)[0], True)
check("  and the wait it reports is the real one",
      round(ps.clock_due(now - 700, 600, now=now)[1]), 700)
# THE FLOOR APPLIES TO THE DUE TEST TOO, or a caller holding a raw number
# bypasses the floor the reader enforces.
check("the due test floors the interval as well as the reader",
      ps.clock_due(now - 59, 5, now=now)[0], False)


print("\n[3] THE RECORD IS THE AUTHORITY — a pass somebody else took counts")
#
# MEASURED after a real pass: last_self_scan_at reads MAX(strftime('%s',
# started_at)) out of port_scan_run WHERE scan_origin='self'. The clock has
# no counter of its own to disagree with this, which is the property that
# makes a restart inside the window free.

check("before any scan, the record says LOOK NOW",
      ps.last_self_scan_at(ps.SELF_SCAN_TARGET), None)

_sc = ps.PortScanner("clock-record")
_sc._check_udp_port = lambda h, p: {"state": "no_answer", "probe": "stub",
                                    "banner": None}
_res = _sc.scan("127.0.0.1", port_set="common")
check("a real self-scan is recorded", _res.get("scan_origin"), "self")

stamp = ps.last_self_scan_at(ps.SELF_SCAN_TARGET)
check_true("and the record answers with a real epoch timestamp",
           isinstance(stamp, float) and abs(time.time() - stamp) < 120,
           stamp)
check("a pass taken a moment ago is NOT due",
      ps.clock_due(stamp, 600)[0], False)
# THE CONVERSION IS SQLITE'S OWN, so the store's UTC shape is read the way it
# was written. Asserted against a direct read of the same row rather than
# against a second Python parser.
_raw = sqlite3.connect(db).execute(
    "SELECT strftime('%s', started_at) FROM port_scan_run "
    "WHERE scan_origin='self' ORDER BY id DESC LIMIT 1").fetchone()[0]
# GUARDED ON PURPOSE: under the negative control this reader returns None,
# and a check that INDEXES it dies of TypeError instead of printing FAIL —
# which measures nothing and sends the round after the wrong thing.
check_true("and the timestamp agrees with the store's own reading of its "
           "column", stamp is not None and int(stamp) == int(_raw),
           (stamp, _raw))
# A REMOTE scan is a different measurement and must not postpone the clock's
# own question. The row is planted rather than driven: a real remote scan
# would send packets at another machine.
me.start_port_scan_run(session_id="clock-record", target_host="192.0.2.9",
                       port_count=1, port_set="common",
                       scan_origin="remote", protocols="tcp")
_after_remote = ps.last_self_scan_at(ps.SELF_SCAN_TARGET)
check_true("a REMOTE scan does not count as this host measuring itself",
           _after_remote is not None and int(_after_remote) == int(_raw),
           (_after_remote, _raw))


print("\n[4] THE TICK RUNS THE SHIPPED SCAN AND RECORDS IT — and never raises")
_sc2 = ps.PortScanner("clock-tick")
_sc2._check_udp_port = lambda h, p: {"state": "no_answer", "probe": "stub",
                                     "banner": None}
_runs_before = sqlite3.connect(db).execute(
    "SELECT COUNT(*) FROM port_scan_run").fetchone()[0]
_rows_before = sqlite3.connect(db).execute(
    "SELECT COUNT(*) FROM port_scan_results").fetchone()[0]

tick = _sc2.clock_tick("clock-tick", reason="test pass")
check("the tick reports that it ran", tick.get("ran"), True)
check("  and which reason it ran for", tick.get("reason"), "test pass")
check("IT RECORDS: a run row was written for the pass",
      sqlite3.connect(db).execute(
          "SELECT COUNT(*) FROM port_scan_run").fetchone()[0] - _runs_before,
      1)
_rows_after = sqlite3.connect(db).execute(
    "SELECT COUNT(*) FROM port_scan_results").fetchone()[0]
check_true("  and the open ports it found are IN the store, not only in the "
           "return value",
           _rows_after >= _rows_before + 1, (_rows_before, _rows_after))
check("the row it wrote is a SELF-scan, so nothing it records can be read as "
      "exposure from elsewhere",
      sqlite3.connect(db).execute(
          "SELECT scan_origin FROM port_scan_run ORDER BY id DESC "
          "LIMIT 1").fetchone()[0], "self")
check("the tick's target is loopback, which is the address this clock may "
      "honestly measure",
      tick.get("target_host"), ps.SELF_SCAN_TARGET)
check_true("the tick names the TCP method that actually ran, like every other "
           "payload", tick.get("tcp_method") in
           (ps.SYN_METHOD, ps.CONNECT_METHOD, None))
check("and it carries the duration it took", isinstance(
    tick.get("duration_ms"), int), True)

# A FAILURE IS CAUGHT AND COUNTED. A clock thread that dies quietly on one
# bad pass is the shape this project has fixed three times.
#
# THE CALLS GO THROUGH A HELPER THAT CATCHES, and that is not tidiness: this
# round's own negative control (control 5, /tmp/agental_ps14_clock) removes
# the tick's own error handling, and a check that calls clock_tick DIRECTLY
# dies of the planted exception -- the file stops there and the harness reads
# a crash instead of a FAIL, which measures nothing. A helper turns "it
# raised" into a printed FAIL like any other.
def _tick_caught(scanner, sid):
    try:
        return scanner.clock_tick(sid)
    except Exception as e:                                   # noqa: BLE001
        return {"raised": f"{type(e).__name__}: {e}"}


_failing = ps.PortScanner("clock-failing")
_failing.scan = lambda *a, **k: (_ for _ in ()).throw(
    RuntimeError("planted store failure"))
_bad = _tick_caught(_failing, "clock-failing")
check_true("a failing pass does NOT raise out of the tick — the thread survives",
           "raised" not in _bad, _bad.get("raised"))
check("  and it reports that it did not run", _bad.get("ran"), False)
check_in("and the reason travels with the refusal", "planted store failure",
         _bad.get("reason"))
check("  and the failure is COUNTED, not swallowed",
      _bad.get("consecutive_failures"), 1)
check("the count is visible in the module state every surface reads",
      ps.clock_state().get("consecutive_failures"), 1)
_bad2 = _tick_caught(_failing, "clock-failing")
check("a second failure in a row is counted as two",
      _bad2.get("consecutive_failures"), 2)

# AND A GOOD PASS CLEARS IT — or the count can only ever grow.
_ok = ps.PortScanner("clock-recover")
_ok._check_udp_port = lambda h, p: {"state": "no_answer", "probe": "stub",
                                    "banner": None}
_tick_caught(_ok, "clock-recover")
check("a good pass clears the failure count, so it cannot only grow",
      ps.clock_state().get("consecutive_failures"), 0)
check("and clears the recorded error with it",
      ps.clock_state().get("last_error"), None)


print("\n[5] THE SWITCH STOPS BOTH PATHS — the clock AND the call")
#
# A switch that stopped only one of two paths is the AR-12 shape one layer
# down: the operator flips it, the call refuses, and a thread carries on
# scanning behind the owner.
_off = ps.PortScanner("clock-off",
                      config={"sensors": {"port_scanner":
                                          {"enabled": False}}})
_rows_before_off = sqlite3.connect(db).execute(
    "SELECT COUNT(*) FROM port_scan_results").fetchone()[0]
_runs_before_off = sqlite3.connect(db).execute(
    "SELECT COUNT(*) FROM port_scan_run").fetchone()[0]
_off_tick = _off.clock_tick("clock-off")
check("with the switch off, the tick does NOT scan",
      _off_tick.get("ran"), False)
check("  and says it was the switch", _off_tick.get("skipped"), True)
check("  and names the key that switched it off",
      "sensors.port_scanner.enabled" in (_off_tick.get("reason") or ""), True)
check("NOTHING was written while switched off: no port row",
      sqlite3.connect(db).execute(
          "SELECT COUNT(*) FROM port_scan_results").fetchone()[0]
      - _rows_before_off, 0)
check("  and no run row", sqlite3.connect(db).execute(
    "SELECT COUNT(*) FROM port_scan_run").fetchone()[0] - _runs_before_off, 0)
check("the call refuses in the same state, which is the other half",
      _off.scan("127.0.0.1").get("off_by_config"), True)
check("and the status dict says the clock is NOT running",
      _off.status().get("clock_running"), False)


print("\n[6] STATUS TELLS THE OPERATOR WHAT THE CLOCK IS DOING")
_cfg = {"sensors": {"port_scanner": {"enabled": True, "poll_interval": 600}}}
_on = ps.PortScanner("clock-status", config=_cfg)
_was = ps.clock_state()
ps.set_clock_running(True, interval=600,
                     interval_key="sensors.port_scanner.poll_interval")
try:
    st = _on.status()
    check("status says the clock is running", st.get("clock_running"), True)
    check("and publishes the cadence actually in force",
          st.get("clock_interval_seconds"), 600)
    check("and names the key that decided it",
          st.get("clock_interval_key"), "sensors.port_scanner.poll_interval")
    check("and the address it measures", st.get("clock_target"),
          ps.SELF_SCAN_TARGET)
    check_in("and a sentence saying what it does, with the number in it",
             "600 second(s)", st.get("clock_note"))
    check_in("  which says a pass taken by anything else postpones the next",
             "postpones", st.get("clock_note"))
    # THE READY ROW MUST NOT READ GREEN OFF A THREAD NOBODY ARMED. A bare
    # object in a test or a tool call has clock_running False beside ready
    # True, which is exactly the pair this project's Settings card exists to
    # tell apart.
    ps.set_clock_running(False)
    bare = ps.PortScanner("clock-bare", config=_cfg).status()
    check("an unarmed clock says so, rather than reading green beside ready",
          bare.get("clock_running"), False)
    check("  while the module itself is still ready, which is a different "
          "fact", bare.get("ready"), True)
finally:
    ps.set_clock_running(bool(_was["running"]), interval=_was["interval"],
                         interval_key=_was["interval_key"])


print("\n[7] THE BOOT ARMS IT — a clock nobody starts is the defect this closes")
check("main.py has the clock's starter",
      "_start_port_scanner_clock" in MAIN_SRC, True)
check("and CALLS it at boot",
      "_start_port_scanner_clock(config, modules, session_id)" in MAIN_SRC,
      True)
check("the thread is a daemon, so it cannot hold the app open",
      'name="port-scanner-clock"' in MAIN_SRC
      and "daemon=True" in MAIN_SRC, True)
check("the cadence comes from the module rather than a second config reader",
      "ps.clock_interval_seconds(config)" in MAIN_SRC, True)
check("the switch comes from the module too",
      "ps.scan_enabled(config)" in MAIN_SRC, True)
check("and the due check reads the record rather than a private counter",
      "ps.last_self_scan_at(ps.SELF_SCAN_TARGET)" in MAIN_SRC, True)
check("the SKIP path for a switched-off sensor is its own sentence in the log",
      "[SKIP] port scanner clock" in MAIN_SRC, True)
# THE FIRST PASS IS NOT DELAYED. A fresh install would otherwise sit on "No
# port scan results yet." for a whole interval.
check("the first pass is attempted before any sleep",
      MAIN_SRC.index("due, waited = ps.clock_due(last, interval)")
      < MAIN_SRC.index('name="port-scanner-clock"'), True)
check("and the loop's wake is the due check's resolution, never longer than "
      "the cadence itself",
      "wake = min(interval, ps.CLOCK_WAKE_SECONDS)" in MAIN_SRC, True)


print("\n[8] THE OPERATOR'S OWN INSTALL: what changes for the owner, measured")
_live = ROOT / "config.json"
if _live.exists():
    _lc = json.loads(_live.read_text(encoding="utf-8"))
    _interval, _key = ps.clock_interval_seconds(_lc)
    _on_now = ps.scan_enabled(_lc)[0]
    print(f"  INFO  the owner's config.json: switch {'ON' if _on_now else 'OFF'}, "
          f"clock every {_interval}s ({_key})")
    check("the owner's own config is ON, so the clock will run for the owner",
          _on_now, True)
    check("and the owner's own poll_interval is what the clock will use",
          _interval, 600)
else:
    print("  SKIP  no config.json in this tree, so the operator's setting "
          "cannot be read here")


print("\n" + "=" * 62)
if fails:
    print(f"{len(fails)} FAILED: " + ", ".join(fails))
    sys.exit(1)
print("All port scanner clock checks passed.")
