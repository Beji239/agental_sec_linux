"""
tests/test_rowtruth_fixes.py, the four defects closed on 2026-09-25.

WHAT THIS FILE IS FOR, in one line: what a PAGE and what the MODEL are told
about a component that is fine, refused, absent, or failing, when the answer
used to be wrong in a way nobody could see.

Register: toolaudit.md sections 18 and 20 (addendum 3 in this same round).
Bugfinder: RT-1..RT-4 with the measurements. Every check below drives a
SHIPPED function; none of them reimplements the logic it is checking.

   RT-1  a capability this PLATFORM does not have was painted RED, forever,
         beside genuine faults, with a fix line that could not fix it, and
         the model was told "the machine refuses 'security_log'" on every
         query_events and search_logs result. THE WINDOWS CAPABILITIES
         THEMSELVES HAVE SINCE LEFT THE TREE (2026-09-25), so the card can no
         longer print the row at all; the checks in [1] to [3] now assert the
         stronger property: no such row exists, and the model path cannot
         name one either.
   RT-2  a DISMISSED finding painted that same row red with a sentence saying
         the gap was unexplained -- on a poll whose whole reason was the
         dismissal.
   RT-3  a write DECLINED by a suppression rule was counted as written.
   RT-4  a sensor failing EVERY poll read green, to the card and to the model.

THE FIRST THREE LIVE IN ONE FILE. core/settings.py is imported at module
scope by the tree's own tests, so the two halves are exercised in one process,
which is also how the app runs them.

Runs with no network and no database of its own: memory_engine's writers are
stubbed (RT-2/RT-3) exactly the way tests/test_event_monitor_fixes.py drives
its own paths, and the isolation module points the DB at a throwaway file for
every other import.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                        # noqa: E402
_isolate_db.isolate()

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got):
    check(label, bool(got), True)


from core import capabilities as C          # noqa: E402
from core import privilege_linux as privilege  # noqa: E402
from core import sensor_health as sh        # noqa: E402
from core import settings as st             # noqa: E402


class Fake:
    def __init__(self, status):
        self._status = status

    def status(self):
        return self._status


# RT-1a. The PRODUCER states WHY each capability row is in its state.

print("\n[1] RT-1a: availability() says WHICH KIND of unavailable each row is")
_avail = C.get().availability()
check("every row carries a kind", sorted({r["kind"] for r in _avail.values()}),
      sorted({r["kind"] for r in _avail.values()}))
# THERE ARE THREE KINDS NOW, NOT FOUR. "not_on_this_platform" existed for the
# two Windows capabilities and left with them: a kind whose only members are
# absences this platform can never fill is not a distinction, it is a label for
# permanent red.
check_true("and it is one of the three this platform can act on",
           all(r["kind"] in ("available", "limited", "unavailable")
               for r in _avail.values()))
check("no row is a platform absence any more",
      [n for n, r in _avail.items()
       if r["kind"] == "not_on_this_platform"], [])
check("the Windows pair is not published at all",
      [n for n in ("defender", "security_log") if n in _avail], [])
check("and capture, which is THIS run's, is merely unavailable",
      _avail["capture"]["kind"] in ("unavailable", "available", "limited"),
      True)


# RT-1b. The MODEL path: the sentence that was false.

print("\n[2] RT-1b: the model is no longer told a sensor was refused when it "
      "was not")
# THE DEFECT'S PREMISE IS GONE, so the check is stronger instead of weaker.
# It used to be: "security_log really is unavailable here, and the consumer
# must not say so". Both halves matter no longer -- the capability does not
# exist, so the producer cannot publish it and the consumer cannot name it.
# A dependency entry that named it again would raise UnregisteredTool at the
# first call rather than quietly degrading, which is asserted in [2b].
check("the capability the defect was about is gone from the producer",
      "security_log" in _avail, False)

MODS = {"event_monitor": Fake({"running": True, "blind": False,
                               "backlog": {}, "stalled": []})}
w = sh.warnings_for("query_events", MODS)
check("query_events carries NO bogus refusal", w, [])
w = sh.warnings_for("search_logs", MODS)
check("search_logs carries NO bogus refusal", w, [])
check("and the sensor's own health still travels when it IS unwell",
      sh.warnings_for("query_events",
                      {"event_monitor": Fake({"running": True,
                                              "blind": True,
                                              "blind_reason": "probe"})}),
      ["event_monitor is BLIND: probe"])
# THE OTHER DIRECTION, so the fix is not a blanket silence: a capability that
# IS unavailable for a fixable reason still reaches the model.
#
# SAVED AND RESTORED PROPERLY, and that is not style. The first draft of this
# file left the patch in place in its finally clause, so the NEXT section
# compared rows measured ELEVATED against a capability table measured
# UNELEVATED and failed on correct code. A fixture that changes a global and
# does not put it back makes the assertions after it measure a world
# production never runs in.
_real_elev = privilege.is_elevated
try:
    privilege.is_elevated = lambda: False
    w = sh.warnings_for("block_port", {"remediation": Fake({"running": True})})
finally:
    privilege.is_elevated = _real_elev
check_true("a rights-refused capability is STILL flagged",
           any("firewall_write" in line for line in w))

# and the dependency map itself cannot name a Windows capability.
print("\n[2b] no tool declares a dependency on a capability this platform "
      "does not have")
_bad = sorted({d for deps in sh.DEPENDS.values() for d in deps
               if d.startswith(sh.CAP)
               and d[len(sh.CAP):] not in C.get().availability()})
check("every declared capability exists", _bad, [])
check("and query_events rests on the SENSOR, not on a channel",
      sh.depends_on("query_events"), ("event_monitor",))
check("so does search_logs", sh.depends_on("search_logs"), ("event_monitor",))


# RT-1c. The CARD: colour and fix line.

print("\n[3] RT-1c: the card paints no Windows capability, at any elevation, "
      "and keeps a real fix for a real problem")
# WHAT THIS SECTION USED TO ASSERT, and why it changed hands. The previous
# round's fix was to keep the two rows and paint them AMBER with no fix line,
# so "a platform absence stays reported rather than hidden". That argument was
# overruled by measurement and by the owner: the rows named a WORKING sensor
# (event_monitor) in their own explanation, they were on the card in 40 of 40
# samples, and they were Windows capabilities in a Linux build. So the fix is
# no longer a colour, it is the absence of the row -- and this section asserts
# THAT, in both elevation states, because "gone" is the property now.
for _elev in (True, False):
    _real_e = privilege.is_elevated
    try:
        privilege.is_elevated = lambda v=_elev: v
        _rows = st._privilege_rows()
    finally:
        privilege.is_elevated = _real_e
    by_title = {r["title"]: r for r in _rows}
    for title in ("Defender detections", "Windows Security channel"):
        check(f"{title} is not on the card, elevated={_elev}",
              title in by_title, False)
    check_true(f"nothing on the card names Windows, elevated={_elev}",
               not any("Windows" in (r["detail"] + r["title"] + r["fix"])
                       for r in _rows))

# THE OTHER DIRECTION: what IS this run's problem stays red with its fix.
if "Packet capture" in by_title:
    cap = by_title["Packet capture"]
    check("capture, which this RUN cannot do, is still a problem",
          cap["state"], "problem")
    check_true("and it keeps the fix that really applies",
               "cap_net_raw" in cap["fix"] or "wireshark" in cap["fix"]
               or "run_elevated" in cap["fix"])
# AND THE ARITHMETIC: "The rest" must not count absent capabilities as fine,
# and must still be right about the ones that ARE fine. The expectation is
# derived from the SAME table the row was built from -- read here, in the same
# elevation the row was -- rather than from the snapshot in section [1], which
# was taken before another section patched a global. An expectation captured
# under different conditions is a fixture defect, not a code defect.
_avail_now = C.get().availability()
_expected_ok = sum(1 for r in _avail_now.values()
                   if r["available"] and not r["limited"])
if _expected_ok:
    check_true("a 'The rest' row exists when some are fine",
               "The rest" in by_title)
    if "The rest" in by_title:
        check("and it counts only what is actually fully available",
              int(by_title["The rest"]["detail"].split(" ")[0]), _expected_ok)
else:
    check("with nothing fully available, no 'The rest' claim is made",
          "The rest" in by_title, False)


# RT-2/RT-3. The finding accounting, driven through the SHIPPED adapter.

print("\n[4] RT-2/RT-3: a finding that was not written says WHICH decision "
      "stopped it")
import adapters as A                          # noqa: E402
from core import memory_engine as me          # noqa: E402
from tools import event_monitor_linux as em   # noqa: E402

SID = "rowtruth-round"
CFG = {"sensors": {"event_monitor": {"enabled": True, "sources": ["auth.log"]}}}

_real = (me.is_dismissed, me.save_finding, me.save_event, me.get_preference,
         me.set_preference, em.monitor_once)

WRITES = []


def _brute():
    return {"type": "brute_force_detected", "entity_type": "user",
            "entity_value": "probe-user", "severity": "high",
            "description": "probe finding", "username": "probe-user"}


def drive(dismissed, saved):
    """One poll of the shipped adapter, with the writers stubbed."""
    me.is_dismissed = lambda et, ev: dismissed
    WRITES.clear()

    def fake_save(**kw):
        WRITES.append(kw["detection_id"])
        return ({"saved": True} if saved else
                {"saved": False, "reason": "suppressed for probe",
                 "suppression_id": 7})

    me.save_finding = fake_save
    me.save_event = lambda **kw: {"saved": True}
    me.get_preference = lambda k, d=None: d
    me.set_preference = lambda k, v: None
    em.monitor_once = lambda markers=None: {
        "findings": [_brute()], "events": [], "markers": {}}
    mon = A.LinuxEventMonitor(SID, CFG)
    mon._event_rows = lambda m: 0
    mon.poll()
    return mon.status(), st._module_row("event_monitor", mon)


try:
    stt, row = drive(dismissed=True, saved=True)
    check("a dismissed finding is counted as dismissed",
          stt.get("findings_dismissed"), 1)
    check("and NOT counted as written", stt.get("findings_written"), 0)
    check("so the poll never asked the writer", WRITES, [])
    check("the row is AMBER, not red: nothing is wrong",
          row["state"], "busy")
    check_true("and it names the dismissal as the reason",
               "dismissed" in row["detail"])
    check("with no 'unexplained' anywhere on it",
          "unexplained" in row["detail"], False)

    stt, row = drive(dismissed=False, saved=False)
    check("a suppressed write is counted as suppressed",
          stt.get("findings_suppressed"), 1)
    check("and NOT counted as written", stt.get("findings_written"), 0)
    check("though the writer WAS asked", WRITES, ["LNX-1012"])
    check("that row is amber too", row["state"], "busy")
    check_true("and it names the suppression",
               "suppression rule" in row["detail"])

    # CONTROL, both directions: nothing in the way, the finding is written and
    # the row says nothing about any of this.
    stt, row = drive(dismissed=False, saved=True)
    check("the control writes the finding", stt.get("findings_written"), 1)
    check("with neither reason counted", (stt.get("findings_dismissed"),
                                          stt.get("findings_suppressed")),
          (0, 0))
    check("and the row is not red", row["state"] == "problem", False)
finally:
    (me.is_dismissed, me.save_finding, me.save_event, me.get_preference,
     me.set_preference, em.monitor_once) = _real

print("\n[5] RT-2: a gap that really IS unexplained still reads red")
# The whole point of the fix is that the sentence is still available for the
# case it was written for. A poll that raises findings and accounts for none
# of them must not have been made quiet by the dismissal branch.
r = st._module_row("event_monitor", Fake({
    "running": True, "backlog": {}, "stalled": [],
    "findings_raised": 4, "findings_written": 0,
    "findings_events_only": 1, "findings_dismissed": 0,
    "findings_suppressed": 0}))
check("3 of 4 unaccounted for is still a problem", r["state"], "problem")
check_true("and the count it could not explain is ON the sentence",
           "3 UNEXPLAINED" in r["detail"])
# And a fully accounted poll is not.
r = st._module_row("event_monitor", Fake({
    "running": True, "backlog": {}, "stalled": [],
    "findings_raised": 4, "findings_written": 0,
    "findings_events_only": 1, "findings_dismissed": 2,
    "findings_suppressed": 1}))
check("everything accounted for is amber, not red", r["state"], "busy")


# RT-4. A sensor failing every poll.

print("\n[6] RT-4: a module failing every poll is not 'running.'")
FAILING = Fake({"running": True, "consecutive_failures": 7,
                "last_error": "RuntimeError: probe failure"})
r = st._module_row("local integrity", FAILING)
check("the card paints it red", r["state"], "problem")
check_true("and says how many polls in a row failed",
           "last 7 poll(s) in a row FAILED" in r["detail"])
check_true("and carries the module's own error",
           "probe failure" in r["detail"])
check_true("with something to wait for", "cached read" in r["fix"])
t = sh._module_trouble("local_integrity", FAILING)
check_true("and the MODEL is told too", t and "FAILING POLLS" in t)
check_true("in the same words", "last 7 in a row failed" in (t or ""))

# THE FLOOR, both directions. One failed poll is a blip and must stay quiet;
# the number is read from the ONE constant both surfaces import.
check("one failure is not worth a colour",
      st._module_row("x", Fake({"running": True, "consecutive_failures": 1,
                                "last_error": "blip"}))["state"], "ok")
check("nor is two", st._module_row(
    "x", Fake({"running": True, "consecutive_failures": 2}))["state"], "ok")
check("three is, at the floor", st._module_row(
    "x", Fake({"running": True, "consecutive_failures": 3}))["state"],
    "problem")
check("the floor is the figure this tree already uses for the same question",
      sh.CONSECUTIVE_FAILURE_FLOOR, 3)
check("and the card reads THAT constant rather than a copy of it",
      st._FAILING_POLLS_FLOOR, sh.CONSECUTIVE_FAILURE_FLOOR)

# THE PRECEDENCE THAT MATTERS: the failure count is live and the figures
# below it are from the last SUCCESSFUL poll, so a stale healthy-looking
# backlog must not get to speak first.
r = st._module_row("event monitor", Fake({
    "running": True, "consecutive_failures": 4, "last_error": "probe",
    "backlog": {}, "stalled": []}))
check("a failing module with an EMPTY backlog is still red, not 'running.'",
      r["state"], "problem")
r = st._module_row("event monitor", Fake({
    "running": True, "consecutive_failures": 4, "last_error": "probe",
    "backlog": {"auth.log": 900}, "stalled": []}))
check("and a STALE backlog does not paint it amber-catch-up either",
      r["state"], "problem")

# NOT the wrong direction: a stopped module keeps its own, more precise
# sentence rather than being blamed for its counter.
r = st._module_row("x", Fake({"running": False, "consecutive_failures": 9,
                              "last_error": "probe"}))
check("a stopped module is still simply 'not running'", r["state"], "off")
check_true("with its own reason",
           "not running" in r["detail"])


print("\n[7] the wiring: the two surfaces read the same shape, and the page "
      "reads it at all")
src = lambda p: (ROOT / p).read_text(encoding="utf-8")      # noqa: E731
ui = src("ui/index.html")
check_true("the tile draws a failing poll",
           "polls in a row FAILED" in ui)
check_true("and the tile's DOT agrees with that line",
           "const failing = state" in ui)
check_true("the card publishes the two other reasons",
           '"findings_dismissed"' in src("adapters.py")
           and '"findings_suppressed"' in src("adapters.py"))
check_true("the log line names them too",
           "declined by a suppression rule" in src("adapters.py"))
# THE TOOL DESCRIPTION NO LONGER EXPLAINS A PLATFORM ABSENCE, because there is
# no longer one to explain. What it must still do is tell the model that every
# capability row is a capability this machine HAS, so an empty sensor answer is
# not read as a machine that cannot do the thing.
check_true("the tool description still tells the model how to read a row",
           "kind: available, limited, or unavailable" in src("core/tool_registry.py"))
check("and does not offer a platform-absence kind",
      "not_on_this_platform" in src("core/tool_registry.py"), False)
check("the card's Windows rows are gone from the module too",
      '"Windows Security channel"' in src("core/settings.py"), False)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
