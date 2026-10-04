"""
tests/test_event_monitor_flapping_fixes.py — EM2-4, 2026-09-27.

WHAT THIS FILE IS FOR. The owner reported the dashboard flooding the owner with
LNX-1014 "service flapping" findings after one boot — 69 rows against 60
distinct units, for services that had each started ONCE. This file holds the
fixed counting so it cannot quietly rot, and it is written in BOTH
DIRECTIONS everywhere: a rule that stops counting real recurrences is as
broken as one that counts one start three times.

MEASURED, from the owner's store and this host's journal (all figures in
bugfinder.md, section "THE SERVICE-BURST COUNTING ROUND"):
  * one 21:11:19 start of xdg-desktop-portal-xapp was counted at the 21:17
    read AND again at the 21:20 read, and journald + syslog carried it twice;
  * one start writes a PAIR of lines ("Starting x.service" / "Started
    x.service") and both were counted;
  * the window ran on the READ clock, so a whole boot's backlog landed inside
    one 300-second window it never occupied;
  * "dbus.service" started three times in three seconds because THREE
    different systemd managers run one — the system bus and two user sessions
    — and the name alone added them into a fake burst;
  * one failed episode writes "Failed to start x.service" once AND
    "x.service: Failed with result" per cycle, and both were counted.

RUNS WITH NO DATABASE AND NO NETWORK: every case is synthetic and driven
through the SHIPPED parser, categoriser and shape rules. The live-log section
reads /etc logs and never writes. Addresses use the RFC 5737 documentation
ranges; no machine is named.

Run: python3 tests/test_event_monitor_flapping_fixes.py
"""
import pathlib
import sys

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


from tools import event_monitor_linux as em       # noqa: E402

TS = "2026-09-26T21:%02d:%02d.000000-07:00 host "
PAIR_START = "systemd[1371]: Starting x.service - X..."
PAIR_DONE = "systemd[1371]: Started x.service - X."


def clear():
    em._service_failures.clear()
    em._service_starts.clear()
    em._firewall_blocks.clear()
    em._login_successes.clear()
    em._service_failure_seen.clear()
    em._service_start_seen.clear()
    em._firewall_seen.clear()
    em._login_seen.clear()


def drive(lines, source="syslog"):
    out = []
    for i, line in enumerate(lines):
        e = em._parse_syslog_line(line, source)
        cats = em._categorize_entry(e)
        f = em._extract_fields(e)
        out.extend(em._shape_findings(e, cats, f, now=10_000.0 + i))
    return out


def clock(n):
    """A stamp a fixture can place anywhere without hand-writing it."""
    return TS % (n // 60, n % 60)


print("[1] THE PAIR: one start, written as two lines, counts ONCE")
# MEASURED shape of the defect: both halves of systemd's pair were counted,
# so three starts inside the window read as six and the rule fired on a
# machine doing nothing wrong.
clear()
got = drive([clock(0) + PAIR_START, clock(0) + PAIR_DONE,
             clock(20) + PAIR_START, clock(20) + PAIR_DONE])
check("two starts (their four lines) do NOT fire", got, [])
clear()
got = drive([clock(0) + PAIR_START, clock(0) + PAIR_DONE,
             clock(20) + PAIR_START, clock(20) + PAIR_DONE,
             clock(40) + PAIR_START, clock(40) + PAIR_DONE,
             clock(60) + PAIR_START, clock(60) + PAIR_DONE])
check("and three starts (six lines) fire exactly ONCE with count 3",
      [(f["type"], f["burst_count"]) for f in got],
      [("service_flapping", 3)])

print("\n  AND A REAL RESTART LOOP STILL FIRES, which is why the rule counts "
      "the 'Started' form and not the other:")
# MEASURED on this host: a unit in a genuine restart loop (the app's own eBPF
# camera, boot -4) logged SIXTEEN "Started" lines and ZERO "Starting" ones --
# systemd's restart job logs the start, not the attempt. Counting "Starting"
# would have made the crash loop invisible.
clear()
got = drive([clock(i * 5) + "systemd[1]: Started loop.service - L."
             for i in range(5)])
check("a unit started five times inside the window fires ONCE",
      [(f["type"], f["entity_value"], f["burst_count"]) for f in got],
      [("service_flapping", "loop.service", 3)])
check("and the count is what was counted, not the window's length",
      got[0]["burst_count"] if got else None, 3)
# AND A LOOP THAT KEEPS GOING KEEPS FIRING: the burst clears when it fires,
# so the next three starts are their own finding -- a sustained loop is not
# silenced by the first alarm it raised.
clear()
got = drive([clock(i * 5) + "systemd[1]: Started loop.service - L."
             for i in range(6)])
check("six starts are TWO findings of three, not one silent run",
      [(f["burst_count"]) for f in got], [3, 3])

print("\n[2] THE MANAGERS: one unit name, three systemd instances")
# MEASURED on this host's 21:10 boot: "dbus.service" started under pid 1 (the
# system manager), 1371 (the login session) and 1485 (the greeter) inside
# three seconds. Keyed on the name alone that is a burst of three; they are
# three DIFFERENT buses, each started once.
clear()
got = drive([clock(0) + "systemd[1]: Starting dbus.service - System Bus...",
             clock(0) + "systemd[1]: Started dbus.service - System Bus.",
             clock(2) + "systemd[1371]: Starting dbus.service - User Bus...",
             clock(2) + "systemd[1371]: Started dbus.service - User Bus.",
             clock(4) + "systemd[1485]: Starting dbus.service - Greeter...",
             clock(4) + "systemd[1485]: Started dbus.service - Greeter."])
check("three managers starting one unit each do NOT fire", got, [])
clear()
got = drive([clock(0) + "systemd[1371]: Starting dbus.service - User Bus...",
             clock(0) + "systemd[1371]: Started dbus.service - User Bus.",
             clock(20) + "systemd[1371]: Starting dbus.service - User Bus...",
             clock(20) + "systemd[1371]: Started dbus.service - User Bus.",
             clock(40) + "systemd[1371]: Starting dbus.service - User Bus...",
             clock(40) + "systemd[1371]: Started dbus.service - User Bus."])
check("but ONE manager starting the same unit three times DOES fire",
      [(f["entity_value"], f["burst_count"]) for f in got],
      [("dbus.service", 3)])

print("\n[3] THE CLOCK: the window runs on the EVENT's own time")
# The measured defect: a boot's backlog is read in one poll and every line's
# own stamp says 21:11, but the burst ran on the READ clock so the whole boot
# landed inside one window. Here three genuinely distant starts are read in
# the same pass: they must not be inside one window together.
#
# CORRECTED 2026-09-27: the first draft of this fixture built its "old" line
# by string-slicing a stamp, which dropped the zone and the microseconds and
# produced a line the parser did not read as a start at all -- so the old code
# never counted it either and the control for this case stayed GREEN. A
# fixture that the defect cannot act on cannot catch the defect. Every line
# below is built by the same helper, in the full format this host writes.
def stamp_line(hh, mm, ss, text):
    return (f"2026-09-26T{hh:02d}:{mm:02d}:{ss:02d}.000000-07:00 host {text}")


clear()
got = drive([stamp_line(19, 0, 0, "systemd[1]: Started old.service - O."),
             stamp_line(21, 0, 0, "systemd[1]: Starting old.service - O..."),
             stamp_line(21, 0, 0, "systemd[1]: Started old.service - O."),
             stamp_line(21, 2, 0, "systemd[1]: Starting old.service - O..."),
             stamp_line(21, 2, 0, "systemd[1]: Started old.service - O.")])
check("a start two hours before the window is not in it", got, [])
clear()
got = drive([stamp_line(21, 0, 0, "systemd[1]: Started old.service - O."),
             stamp_line(21, 0, 0, "systemd[1]: Starting old.service - O..."),
             stamp_line(21, 0, 0, "systemd[1]: Started old.service - O."),
             stamp_line(21, 2, 0, "systemd[1]: Starting old.service - O..."),
             stamp_line(21, 2, 0, "systemd[1]: Started old.service - O."),
             stamp_line(21, 4, 0, "systemd[1]: Starting old.service - O..."),
             stamp_line(21, 4, 0, "systemd[1]: Started old.service - O.")])
check("while three starts INSIDE the window still fire",
      [(f["type"], f["burst_count"]) for f in got],
      [("service_flapping", 3)])

print("\n[4] THE SAME LINE TWICE: a re-read or the second source counts once")
clear()
lines = [clock(0) + PAIR_START, clock(0) + PAIR_DONE,
         clock(20) + PAIR_START, clock(20) + PAIR_DONE,
         clock(40) + PAIR_START, clock(40) + PAIR_DONE]
first = drive(lines)
again = drive(lines)
check("the three starts fire once", len(first), 1)
check("and reading the identical lines again fires NOTHING", again, [])
clear()
sources = drive(lines, "syslog") + drive(lines, "journald")
check("nor does the SAME line from the second source double it",
      [(f["type"], f["burst_count"]) for f in sources],
      [("service_flapping", 3)])

print("\n[5] THE FAILURE RULE: the per-cycle line, not the final stop")
# MEASURED: one crashed episode writes "x.service: Failed with result" on
# EVERY cycle (18 in the camera loop's boot) and "Failed to start x.service"
# ONCE, at the end. Counting both made one episode read as two failures.
clear()
FAIL = "systemd[1]: x.service: Failed with result 'exit-code'."
got = drive([clock(i * 10) + FAIL for i in range(3)])
check("three failed cycles fire service_restart_loop once",
      [(f["type"], f["burst_count"]) for f in got],
      [("service_restart_loop", 3)])
clear()
got = drive([clock(i * 10) + "systemd[1]: Failed to start x.service - X"
             for i in range(3)])
check("three 'Failed to start' lines alone do NOT fire", got, [])

print("\n[6] MEASURED ON THIS HOST'S REAL BOOT -- the flood, re-driven")
# The exact window that produced the owner's 69 false findings: everything
# this host wrote from 21:10:40 to 21:13:30 on 2026-09-26, read out of the
# journal, driven through the shipped rules. The old code wrote 69 rows here;
# the fixed code must write none -- and if this machine is not the one the
# round was measured on, the section says so instead of passing silently.
import subprocess
try:
    raw = subprocess.run(["journalctl", "-b", "0", "--no-pager",
                          "-o", "short-iso", "--since", "2026-09-26 21:10:40",
                          "--until", "2026-09-26 21:13:30"],
                         capture_output=True, text=True, timeout=120).stdout
except Exception as e:                                        # noqa: BLE001
    raw = ""
    print(f"  (journalctl could not be read: {type(e).__name__}; "
          f"this section is NOT evaluated)")
lines = [l for l in raw.splitlines() if ".service" in l]
if lines:
    clear()
    got = drive(lines)
    check(f"the real boot window ({len(lines)} lines) raises NOTHING false",
          [(f["type"], f["entity_value"]) for f in got], [])
    check_true("and the material was really there to be counted",
               len(lines) > 50)
else:
    print("  (this boot's journal window is not present on this machine; "
          "the synthetic sections above stand and this one is SKIPPED, "
          "not passed)")

print("\n[7] THE ORDINARY LINES ARE STILL ORDINARY")
clear()
check("ONE failure is not a loop",
      drive([clock(0) + FAIL]), [])
clear()
check("TWO starts are not flapping",
      drive([clock(0) + PAIR_START, clock(0) + PAIR_DONE,
             clock(20) + PAIR_START, clock(20) + PAIR_DONE]), [])

print("\n" + ("," * 60))
print("ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
