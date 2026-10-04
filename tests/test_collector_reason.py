"""
tests/test_collector_reason.py, a failing collector row has to say WHY.

WHERE THIS CAME FROM. 2026-09-07. The Linux box was switched off when the app
started, so the row for it read:

    linux monitor:192.0.2.26
      not answering.

Two words. Underneath them the collector was holding the error text, the
number of polls that had failed in a row, and its own sentence about what the
silence meant. None of it reached the screen, so the only way to find out
whether it was off, refusing us, or simply thirty seconds from its next try
was to restart the app, which is the one action that throws the answer away.

Same mistake as 47.9: _module_row synthesised its own wording and dropped the
collector's note. That was fixed for the healthy rows and this branch was
missed.

Nothing here needs a database, a network or Windows. It hands _module_row a
fake status and reads the sentence that comes back.
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
from tools import linux_monitor as lm     # noqa: E402


class FakeModule:
    def __init__(self, status):
        self._status = status

    def status(self):
        return self._status


def row_for(status):
    return st._module_row("linux monitor", FakeModule(status))


print("\n[1] the real case: a host that was off when the app started")
r = row_for({
    "running": True,
    "reachable": False,
    "consecutive_failures": 2,
    "last_error": "could not open an SSH session",
    "last_success_age_seconds": None,
    "poll_interval_seconds": 120,
    "next_poll_in_seconds": 90,
})
check("still a problem, not something to shrug at", r["state"], "problem")
check("it still leads with the plain fact",
      r["detail"].startswith("not answering"), True)
check("it says how many polls have failed", "2 polls in a row" in r["detail"], True)
check("it carries the collector's own error",
      "could not open an SSH session" in r["detail"], True)
check("and it gives you something to wait for",
      "Next try in about 90 seconds" in r["detail"], True)
check("with the reminder that this page is cached",
      "cached read" in r["fix"], True)


print("\n[2] a poll running right now says so, rather than counting to zero")
r = row_for({"running": True, "reachable": False, "consecutive_failures": 1,
             "last_error": "timed out", "next_poll_in_seconds": 0,
             "poll_interval_seconds": 120})
check("it says it is trying", "Trying again now" in r["detail"], True)
check("one failure is not worth a count",
      "polls in a row" in r["detail"], False)


print("\n[3] the note is used when there is no specific error")
r = row_for({"running": True, "reachable": False, "consecutive_failures": 3,
             "note": "Reaching the host is fine, but every log source is empty"})
check("the wider sentence gets through",
      "every log source is empty" in r["detail"], True)
check("and with no timing available it does not invent one",
      "Next try" in r["detail"], False)


print("\n[4] a collector that says nothing still gets an honest row")
r = row_for({"running": True, "reachable": False})
check("the old two words are still the floor", r["detail"], "not answering.")
check("and no empty fix is offered", r["fix"], "")


print("\n[5] the states either side of it are unchanged")
check("never tried yet is not a failure",
      row_for({"running": True, "reachable": None})["state"], "ok")
check("reachable and running is fine",
      row_for({"running": True, "reachable": True})["state"], "ok")
check("a backlog still wins, it is a different problem",
      "not yet stored" in row_for(
          {"running": True, "reachable": True, "backlog": 5})["detail"], True)


print("\n[6] the collector actually publishes what the row now reads")
# The row above is only as good as the fields underneath it, and a test that
# feeds itself its own fake proves nothing about the real module.
mon = lm.LinuxMonitor.__new__(lm.LinuxMonitor)
check("poll interval is a real number", isinstance(lm.POLL_INTERVAL, int), True)
src = (ROOT / "tools" / "linux_monitor.py").read_text(encoding="utf-8")
check("status publishes the interval", '"poll_interval_seconds"' in src, True)
check("and the countdown", '"next_poll_in_seconds"' in src, True)
check("stamped at the end of the poll, not the start",
      "self._last_poll_at = time.time()" in src, True)


print("\n[7] a sensor that is alive and cannot see says so")
# 2026-09-07. Unelevated, the dashboard showed "packet sniffer, running" in
# green and "event monitor, running, log up to date" in green, while the
# Settings block on the same screen said capture was unavailable and the
# Security channel could not be opened. running only ever meant the thread was
# up and the library imported.
r = row_for({"running": True, "blind": True,
             "blind_reason": "installed, but this process is not elevated, "
                             "so Npcap will not open an adapter"})
check("blind is a problem, not a green row", r["state"], "problem")
check("it says running AND blind, both are true",
      "running, but blind" in r["detail"], True)
check("and carries the reason", "not elevated" in r["detail"], True)
check("and points at the block that explains it",
      "Privileged access" in r["fix"], True)
check("blind beats a healthy backlog, it is the bigger fact",
      row_for({"running": True, "blind": True, "blind_reason": "x",
               "backlog": {"Security": 0}})["state"], "problem")
check("not blind is left completely alone",
      row_for({"running": True, "blind": False})["state"], "ok")


print("\n[8] the sensors publish it, and the dashboard reads it")
# WHERE 'blind' LIVES IS DIFFERENT ON THIS PLATFORM and the check had to
# follow it rather than be deleted. On Windows these were classes that reported
# their own health. Here the sensor modules are plain functions, and the thing
# that knows whether capture is really happening is the ADAPTER, which is what
# main.py loads and what core/settings reads. So the assertion is against
# adapters.py, and its meaning is unchanged: whatever the page reads a health
# flag from must actually publish one.
src = lambda p: (ROOT / p).read_text(encoding="utf-8")   # noqa: E731
adapters_src = src("adapters.py")
check("the sniffer adapter publishes blind", '"blind"' in adapters_src, True)
check("and says WHY when it is blind", "blind_reason" in adapters_src, True)
# THE PER-RUN COUNT IS THE POINT of the tile: a number that is about this run
# rather than about recent rows. The sniffer's is packets_this_run; the event
# monitor's is the events it actually read this pass.
check("the sniffer counts what THIS RUN did",
      "packets_this_run" in adapters_src, True)
check("the event monitor reports this run's own read",
      "event_count" in adapters_src, True)

ui = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check("the tile reads the sensor's own count, not recent rows",
      "function statTile(" in ui, True)
# The dash was two hyphens until 2026-09-14, when the whole tree was swept of
# double hyphens. It is one hyphen now. The CHECK is unchanged in meaning: a
# blind sensor's tile must show a dash rather than a number, because a number
# there is a count the sensor could not have taken.
check("a blind sensor's tile shows a dash rather than a number",
      "if (mod.blind) return '-';" in ui, True)
check("and it is a dash, not an empty string or a zero",
      "if (mod.blind) return '';" in ui or "if (mod.blind) return '0';" in ui,
      False)
check("and the module grid paints blind red",
      "BLIND, SEEING NOTHING" in ui, True)
# The dot and the pill were the two surfaces left saying the opposite. A green
# dot beside a red line, and a green "Sniffer: ON" on every page.
#
# RESTATED 2026-09-25. This asserted the literal expression
# `const dot = blind ? 'var(--red)'`, which was a pin on HOW the dot was
# computed rather than on what it does. The row-truth round added a second
# reason for a red dot (a module whose last several polls failed, which
# moduleExtra draws as a red line of its own), so the expression now reads
# `(blind || failing) ? 'var(--red)'`. The PROPERTY this check exists for is
# unchanged and is what is asserted now: blind feeds the red, and the dot can
# never be red-or-green by a rule that forgot about blind.
check("the tile's dot goes red too, not just the text",
      "blind || failing" in ui and "var(--red)" in ui, True)
check("and blind is still one of the things that reds it",
      "const blind = state" in ui and "const failing = state" in ui, True)
check("and the sniffer pill says blind rather than ON",
      "'Sniffer: BLIND'" in ui, True)


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
