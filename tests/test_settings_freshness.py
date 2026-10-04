"""
tests/test_settings_freshness.py, the Settings page has to say how old it is
and must not call a normal catch up a broken sensor.

WHERE THIS CAME FROM. 2026-09-21. Settings showed the event monitor red with
"read but not yet stored: Security 15098". The log had said "Security backlog
cleared" at 13:27. The screenshot was at 13:44. Two faults:

  1. The page read /api/settings once at boot and then only on a tab click,
     and never said how old the read was. So a 19 minute old snapshot looked
     live.

  2. Any backlog above zero was 'problem'. Every boot starts with one, so a
     drain that was working fine was painted as a dead sensor.

FAILURE CASES FIRST. The stuck drain, the dead drain thread and the module
that cannot say whether it is stuck all come before the happy path.

Runs with no database, no network and no Windows.
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


from core import settings as st          # noqa: E402
from tools import event_monitor_linux as em    # noqa: E402


class Fake:
    def __init__(self, status):
        self._status = status

    def status(self):
        return self._status


def row(status):
    return st._module_row("event_monitor", Fake(status))


# WHERE THIS TEST WAS RETARGETED, 2026-09-21, AND WHY IT HAD TO BE
#
# It was written against the WINDOWS EventMonitor class, whose _report_progress
# and _stalled_channels track a per-channel drain over a reader that pages
# through a Windows event log. That class is in agental_sec_win32_reference/
# and nothing on this host loads it.
#
# The Linux sensor this tree runs is tools/event_monitor_linux.py, a module of
# functions that reads a window off the end of each log file. It had no drain at
# all, so the first sections had nothing to drive. THE FIX WAS TO BUILD THE
# MISSING HALF rather than delete the checks: the sensor now measures what it
# read and did not hand back, reports it per source, and publishes both
# 'backlog' and 'stalled'. Section [7b] drives that, and the reader's own
# reason for a drain differs from the Windows one and is written above the code.
#
# The module is imported under `em` below and used THROUGH ITS OWN FUNCTIONS:
# _report_progress, _stalled_channels and _last_report_at are module-level here
# where the Windows class held them as instance state.


# THE FAILURE PATHS

print("\n[1] FAILURE: a drain that is stuck, same number two polls running")
em._drain_remaining.clear(); em._drain_previous.clear()
em._last_report_at.clear()
em._report_progress("Security", 0, 5000, now=100.0)
em._remember_previous_drain()
em._report_progress("Security", 0, 5000, now=101.0)
check("the monitor calls it stalled", em._stalled_channels(now=102.0),
      ["Security"])
r = row({"running": True, "backlog": {"Security": 5000}, "stalled": ["Security"]})
check("the row is red", r["state"], "problem")
check("and says it is not going down", "NOT going down" in r["detail"], True)

print("\n[2] FAILURE: a drain thread that died after its last good poll")
em._drain_remaining.clear(); em._drain_previous.clear()
em._last_report_at.clear()
em._report_progress("Security", 100, 5000, now=100.0)
check("fresh report, not stalled yet",
      em._stalled_channels(now=101.0), [])
later = em._last_report_at["Security"] + 3 * em.POLL_INTERVAL + 1
check("no report for three poll intervals is stalled",
      em._stalled_channels(now=later), ["Security"])

print("\n[3] FAILURE: a backlog with no stall info at all")
# A module that cannot say whether it is moving has not been checked, so it
# must not get the calmer colour.
r = row({"running": True, "backlog": {"Security": 31000}})
check("unknown stays red", r["state"], "problem")
r = row({"running": True, "backlog": {"Security": 31000}, "stalled": None})
check("stalled None is unknown too", r["state"], "problem")
check("an int backlog with no stall info stays red",
      row({"running": True, "backlog": 12})["state"], "problem")

print("\n[4] FAILURE: blind still beats a moving backlog")
check("blind wins", row({"running": True, "blind": True, "blind_reason": "x",
                         "backlog": {"Security": 5}, "stalled": []})["state"],
      "problem")

print("\n[5] FAILURE: the badge must not count catching up")
rows = [st._row("C", "a", "busy", ""), st._row("C", "b", "problem", "")]
s = st.summary(rows)
check("one problem", s["problem"], 1)
check("one busy, counted apart", s["busy"], 1)

# THE HAPPY PATHS

print("\n[6] a boot backlog that is going down is amber, not red")
em._drain_remaining.clear(); em._drain_previous.clear()
em._last_report_at.clear()
em._report_progress("Security", 4271, 15098, now=1.0)
em._remember_previous_drain()
em._report_progress("Security", 4487, 10743, now=2.0)
check("moving is not stalled", em._stalled_channels(now=3.0), [])
r = row({"running": True, "backlog": {"Security": 10743}, "stalled": []})
check("the row is busy", r["state"], "busy")
check("and says catching up", r["detail"].startswith("catching up"), True)
check("with the number", "Security 10743" in r["detail"], True)

print("\n[7] cleared means green, whatever the stall flag last said")
em._drain_remaining.clear(); em._drain_previous.clear()
em._last_report_at.clear()
em._report_progress("Security", 0, 5000, now=1.0)
em._remember_previous_drain()
em._report_progress("Security", 0, 5000, now=2.0)
em._report_progress("Security", 5000, 0, now=3.0)
check("nothing behind is never stalled",
      em._stalled_channels(now=4.0), [])
check("row is green",
      row({"running": True, "backlog": {"Security": 0}, "stalled": []})["state"],
      "ok")

print("\n[7b] THE DRAIN IS REAL NOW: the sensor the page reads publishes both keys")
# This section used to assert the OPPOSITE, and the reason it changed is worth
# keeping. When this file was first converted, core/settings._module_row read
# 'stalled' and nothing on this side published it, so the stall branch was
# unreachable and the check said so out loud. The owner's instruction was to
# build the missing half rather than document the hole, so tools/
# event_monitor_linux.py now measures a drain and publishes both keys, and this
# check guards THAT instead.
em._drain_remaining.clear(); em._drain_previous.clear()
em._last_report_at.clear()
st = em.get_status()
check("the sensor publishes a backlog", "backlog" in st, True)
check("and a stalled list", isinstance(st.get("stalled"), list), True)
em._report_progress("syslog", 10, 0, now=100.0)
check("caught up is not stalled", em._stalled_channels(now=101.0), [])
em._report_progress("syslog", 0, 500, now=101.0)
em._remember_previous_drain()
em._report_progress("syslog", 0, 500, now=102.0)
check("a figure that does not move IS stalled",
      em._stalled_channels(now=103.0), ["syslog"])
em._report_progress("syslog", 500, 0, now=104.0)
check("and clearing it is never stalled",
      em._stalled_channels(now=105.0), [])
em._drain_remaining.clear(); em._drain_previous.clear()
em._last_report_at.clear()

# THE WIRING

print("\n[8] the pieces are really connected")
src = lambda p: (ROOT / p).read_text(encoding="utf-8")   # noqa: E731
# THE PATH IS THE LINUX SENSOR, not tools/event_monitor.py: that module was
# moved to agental_sec_win32_reference/ with the L5 pass and this check was
# reading a file the tree no longer has.
ev = src("tools/event_monitor_linux.py")
ui = src("ui/index.html")
# The module publishes `stalled` from get_status(), spelled `"stalled":` there
# rather than as the Windows class's method call: the state is module-level on
# this side. The MEANING is unchanged, which is what the check is about.
check("the sensor publishes stalled",
      '"stalled":' in ev, True)
check("the page refreshes on its own", "startSettingsRefresh();" in ui, True)
check("it skips hidden windows", "if (document.hidden) return;" in ui, True)
check("the background refresh leaves typed fields alone",
      "renderConfigFields" in ui.split("async function refreshReadiness")[1]
      .split("function fmtSettingsAge")[0], False)
check("the age is shown", 'id="settings-age"' in ui, True)
check("a failed refresh says so", "refresh failed, these rows are from" in ui,
      True)
check("busy has a colour", "busy: 'var(--amber)'" in ui, True)
check("the dashboard tile can say stuck", "stuck, ${esc(behind.join" in ui, True)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
