"""
tests/test_readiness_honesty.py, a green row on the settings page has to
have been earned.

WHERE THIS CAME FROM. 2026-09-18, reading the settings page top to bottom
after the kev cvss question. Nothing on it was red and nothing was wrong,
and that turned out to be most of the problem: the rows that said 'running.'
were saying it without having checked anything.

Four separate ways the page could print a green row it had not earned:

  1. event_monitor publishes backlog as a DICT of channel to remaining.
     _module_row tested isinstance(backlog, int). The one module in the tree
     that has a backlog was the one module the backlog check could not see,
     so a stuck Security drain read 'running.' here while the dashboard tile
     beside it read 31,000 behind. Section 30, on the other page.

  2. rollup_engine had no status() at all, so the row fell through to the
     no-status branch and printed 'loaded.' Both of its threads are daemons.
     Either one dying stops the baseline merging and changes nothing here.

  3. web_search reports ready=True for as long as the object exists, and
     puts "the last five searches did not resolve" in its note. The note was
     dropped on the floor: _row had no note field at all, while the page has
     been rendering r.note the whole time.

  4. A module that is alive and has measured nothing, a probe with no pass,
     a runbook with an empty mirror, a linux monitor that has not reached the
     host, all said the bare word running.

FAILURE CASES COME FIRST IN THIS FILE, deliberately. Every one of the four
above is a function that worked perfectly on the happy path and lied on the
other one, which is what happens when the happy path is the test that gets
written first.

Runs with no database, no network and no Windows. It hands _module_row and
status() fakes and reads the sentences that come back.
"""
import pathlib
import sys
import threading
import time

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
from core import rollup_engine as re_    # noqa: E402


class Fake:
    def __init__(self, status):
        self._status = status

    def status(self):
        return self._status


class Exploding:
    def status(self):
        raise RuntimeError("no")


def row(status, name="event monitor"):
    return st._module_row(name, Fake(status))


# THE FAILURE PATHS

print("\n[1] FAILURE: a stuck drain, published the way event_monitor "
      "publishes it")
r = row({"running": True, "backlog": {"Security": 31000, "System": 0}})
check("a dict backlog is a problem, not a green row", r["state"], "problem")
check("it names the channel", "Security 31000" in r["detail"], True)
check("and leaves out the channel that is up to date",
      "System" in r["detail"], False)

print("\n[2] FAILURE: the same thing as an int, which is what used to work")
check("an int backlog still fires",
      row({"running": True, "backlog": 12})["state"], "problem")
check("True is not a backlog of one",
      row({"running": True, "backlog": True})["state"], "ok")

print("\n[3] FAILURE: a worker that knows it is broken")
r = row({"running": True, "fault": "the rollup thread is no longer alive.",
         "fix": "Restart the app."})
check("fault beats a True next to running", r["state"], "problem")
check("it uses the module's own sentence",
      r["detail"], "the rollup thread is no longer alive.")
check("and carries its fix", r["fix"], "Restart the app.")

print("\n[4] FAILURE: search that is loaded, callable and getting nowhere")
r = row({"ready": True, "consecutive_unresolved": 5,
         "last_failure_kind": "challenged",
         "note": "The last 5 searches did not resolve."}, name="web search")
check("three in a row is a problem", r["state"], "problem")
check("it says how many", "last 5" in r["detail"], True)
check("and what kind", "challenged" in r["detail"], True)
check("one unresolved search is still not worth a colour",
      row({"ready": True, "consecutive_unresolved": 1},
          name="web search")["state"], "ok")

print("\n[5] FAILURE: the collector wrote a sentence and the row dropped it")
r = row({"ready": True, "note": "The CISA KEV mirror has NOT synced."},
        name="runbook")
check("the note reaches the row", r["note"],
      "The CISA KEV mirror has NOT synced.")
check("even on a green row", r["state"], "ok")
check("a row with nothing to add gets an empty note, not a missing key",
      row({"running": True})["note"], "")

print("\n[6] FAILURE: rollup threads that are not running")
re_._threads_started = False
s = re_.status()
check("never started is not running", s["running"], False)
check("and says what is not happening",
      "merging the session into the baseline" in s["reason"], True)

re_._threads_started    = True
re_._threads_started_at = time.time() - 60
re_._last_rollup_at     = None
re_._last_rollup_error  = None
re_._rollup_thread      = None
re_._silence_thread     = None
s = re_.status()
check("a dead thread is a fault, not an off switch", "fault" in s, True)
check("it names which thread", "rollup" in s["fault"], True)
check("and the row for it is red",
      st._module_row("rollup engine", Fake(s))["state"], "problem")

print("\n[7] FAILURE: alive and merging nothing, which is not the same as "
      "healthy")
alive = threading.Thread(target=lambda: time.sleep(30), daemon=True)
alive.start()
re_._rollup_thread  = alive
re_._silence_thread = alive
re_._rollup_interval_minutes = 60
re_._threads_started_at = time.time() - (60 * 60 * 3)
re_._last_rollup_at     = time.time() - (60 * 60 * 3)
s = re_.status()
check("three hours with no merge on an hourly timer is a fault",
      "fault" in s, True)
check("it says alive is not working",
      "Alive is not the same as working" in s["fault"], True)
check("and it is still honestly reporting the thread as alive",
      s["running"], True)

# THE HAPPY PATHS, which must not have been broken on the way past

print("\n[8] a healthy rollup is green and says when it last merged")
re_._last_rollup_at     = time.time() - 120
re_._threads_started_at = time.time() - 600
s = re_.status()
check("no fault", "fault" in s, False)
check("running", s["running"], True)
check("the note says how often it merges", "every 60 minutes" in s["note"],
      True)
check("and the row is green",
      st._module_row("rollup engine", Fake(s))["state"], "ok")

print("\n[9] the window before the first merge is not a fault")
re_._last_rollup_at     = None
re_._threads_started_at = time.time() - 300
s = re_.status()
check("a fresh start is not broken", "fault" in s, False)
check("and it says nothing has merged yet",
      "no merge yet this run" in s["note"], True)

print("\n[10] the rows either side of the new checks are unchanged")
check("an empty dict backlog is fine",
      row({"running": True, "backlog": {}})["state"], "ok")
check("all channels drained is fine",
      row({"running": True, "backlog": {"Security": 0}})["state"], "ok")
check("blind still beats everything",
      row({"running": True, "blind": True, "blind_reason": "no rights",
           "backlog": {"Security": 5}})["state"], "problem")
check("unreachable is still a problem",
      row({"running": True, "reachable": False},
          name="linux monitor")["state"], "problem")
check("never tried yet is still not a failure",
      row({"running": True, "reachable": None},
          name="linux monitor")["state"], "ok")
check("but it no longer claims the host answered",
      "has not reached the host yet" in row(
          {"running": True, "reachable": None},
          name="linux monitor")["detail"], True)
check("a module that never loaded is still off",
      st._module_row("probe", None)["state"], "off")
check("a status() that throws is still a finding",
      st._module_row("boom", Exploding())["state"], "problem")

print("\n[11] a module with no status() no longer implies it was checked")
r = st._module_row("rollup engine", object())
check("still green, nothing is wrong", r["state"], "ok")
check("but it says nothing was checked",
      "nothing here has been checked" in r["detail"], True)

# THE WIRING, because a row is only as good as what is underneath it

print("\n[12] the modules really publish what these rows now read")
src = lambda p: (ROOT / p).read_text(encoding="utf-8")   # noqa: E731
check("event_monitor really publishes a dict backlog",
      '"backlog":' in
      src("tools/event_monitor_linux.py"), True)
check("rollup_engine really has a status now",
      "def status() -> dict:" in src("core/rollup_engine.py"), True)
check("runbook says whether the mirror synced",
      '"note": note' in src("tools/runbook.py"), True)
check("kev_cvss says how many rows are still unrated",
      "_state_note" in src("tools/kev_cvss.py"), True)
check("probe says whether a pass has ever completed",
      "_state_note" in src("tools/probe.py"), True)
check("_row carries a note field at all",
      '"note": note' in src("core/settings.py"), True)
check("and the page renders it",
      "r.note ?" in src("ui/index.html"), True)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
