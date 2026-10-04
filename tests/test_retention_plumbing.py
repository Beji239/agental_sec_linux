"""
tests/test_retention_plumbing.py, section 23 is actually WIRED IN.

WHY THIS IS A SEPARATE FILE FROM test_retention.py, and it is the point.

The engine passed every one of its own tests on 2026-08-31 and the app still
never pruned anything, because nothing called it. test_retention.py checks that
retention DOES THE RIGHT THING WHEN RUN. This file checks that it RUNS. Those
are different failures and the second one is invisible to a test suite that
only ever calls the function directly.

The checks:
  the switch has three states, and unset is not on
  an existing install upgrades into "ask", never into "start deleting"
  status() is read-only and says the honest thing in each situation
  the setup presets validate against the module's own limit rules
  the boot hook never deletes, whatever the size
  the shutdown hook prunes only when a person switched it on AND it is over
  the model's tool exists, is read-only, and has no write twin
  main.py calls both hooks, and asks once without a timer
"""
import pathlib
import re
import sqlite3
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


from core import retention as rt        # noqa: E402
from core import migrations             # noqa: E402

SCHEMA = (ROOT / "Schema.SQL").read_text(encoding="utf-8")


def make_db(sessions, row_bytes=400):
    """A database holding {session_id: (rows, day)}, same shape as 23's suite."""
    tmp = pathlib.Path(tempfile.mkdtemp())
    db = tmp / "t.db"
    c = sqlite3.connect(db)
    c.executescript(SCHEMA)
    c.commit()
    c.close()
    migrations.run_migrations(db)

    c = sqlite3.connect(db)
    blob = "x" * row_bytes
    for sid, (n, day) in sessions.items():
        # 2026-09-05: was raw_summary, which TODO 34 retired from the schema on
        # 2026-09-01. Red ever since. payload_snippet is the column that
        # carries bulk now, and bulk is the only thing the blob is for here.
        c.executemany(
            "INSERT INTO packets(session_id, captured_at, src_ip, dst_ip, "
            "protocol, direction, packet_size, payload_snippet) "
            "VALUES(?,?,?,?,?,?,?,?)",
            [(sid, f"2026-08-{day:02d} {i % 24:02d}:00:00", "192.0.2.10",
              "192.0.2.20", "TCP", "outbound", 100, blob) for i in range(n)])
    c.commit()
    c.close()
    return db


def set_limits(db, trigger, floor):
    c = sqlite3.connect(db)
    for k, v in ((rt.PREF_TRIGGER, trigger), (rt.PREF_FLOOR, floor)):
        rt._write_pref(c, k, v)
    c.close()


def rows(db, table="packets"):
    with sqlite3.connect(db) as c:
        return c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


class FakeLog:
    def __init__(self):
        self.lines = []

    def _add(self, level):
        return lambda msg, *a: self.lines.append((level, str(msg)))

    def __getattr__(self, name):
        return self._add(name)


print("\n[1] THE SWITCH HAS THREE STATES, AND UNSET IS NOT ON")
# The whole safety property. An install that upgrades into this code has no
# answer on file, and "no answer" must mean ask, never mean start deleting.
db = make_db({"a": (200, 10)})
c = sqlite3.connect(db)
check("a fresh database is not configured", rt.configured(c), False)
check("and not enabled", rt.enabled(c), False)
c.close()

rt.decline(db)
c = sqlite3.connect(db)
check("declining counts as configured", rt.configured(c), True)
check("but still not enabled", rt.enabled(c), False)
c.close()

rt.apply_choice(db, "homelab", turn_on=True)
c = sqlite3.connect(db)
check("a preset turns it on", rt.enabled(c), True)
c.close()


print("\n[2] the presets are real numbers that pass the module's own rules")
# A preset that fails limits() would be a setup flow that hands somebody a
# configuration the prune then refuses to use.
for p in rt.PRESETS:
    d = make_db({"a": (10, 10)})
    r = rt.apply_choice(d, p["key"], turn_on=True)
    check(f"{p['key']} validates", r["ok"], True)
    check(f"{p['key']} floor is below trigger", p["floor"] < p["trigger"], True)
    gap_ok = (p["trigger"] - p["floor"]) >= p["trigger"] * rt.MIN_GAP_FRACTION
    check(f"{p['key']} gap is wide enough", gap_ok, True)

check("index and key pick the same preset",
      rt.apply_choice(make_db({"a": (10, 10)}), 2)["preset"], "homelab")
check("a nonsense choice is refused, not guessed",
      rt.apply_choice(make_db({"a": (10, 10)}), "enormous")["ok"], False)


print("\n[3] the trade is stated in the prompt, per 23.5")
text = "\n".join(rt.choice_lines())
check("it says a smaller database is a shorter memory",
      "shorter memory" in text, True)
# 23.6 is the honest half and it is the half people get wrong.
check("and that keeping more days is not the fix",
      "slower than ONE capture run" in text, True)
check("all three presets are offered", len(re.findall(r"^  \d\. ", text,
                                                      re.M)), 4)


print("\n[4] status() is read-only and says the honest thing")
db = make_db({"old": (400, 10), "new": (400, 20)})
set_limits(db, 1_000, 500)          # tiny, so it is over
before = rows(db)
st = rt.status(db)
check("nothing was deleted by reading", rows(db), before)
check("it knows it is over", st["over_trigger"], True)
check("pruning is off because nobody said yes", st["auto_prune"], False)
# The sentence that matters: over the line AND switched off means the file is
# just growing, and saying only "over the trigger" would imply something is
# about to happen.
check("and the note says nothing will be deleted",
      "nothing will be deleted" in st["note"].lower(), True)
check("it declares the model cannot delete", st["model_cannot_delete"], True)
check("it carries the 23.6 caveat",
      "slower than a single capture run" in st["measurement_limit"], True)
check("it counts the capture runs", st["capture_runs"], 2)


print("\n[5] THE BOOT HOOK NEVER DELETES, WHATEVER THE SIZE")
# Boot is the wrong moment: sensors are about to write and a VACUUM would hold
# the boot for minutes. If this ever starts deleting, this check fails.
db = make_db({"old": (400, 10), "new": (400, 20)})
set_limits(db, 1_000, 500)
rt.apply_choice(db, "occasional", turn_on=True)
set_limits(db, 1_000, 500)          # put the tiny limits back
before = rows(db)
log = FakeLog()
rt.boot_report(db, log=log)
check("boot deleted nothing", rows(db), before)
check("but it did say the size out loud",
      any("Database:" in m for _, m in log.lines), True)


print("\n[6] the shutdown hook prunes only when told to, and only when over")
db = make_db({"old": (400, 10), "mid": (400, 15), "new": (400, 20)})
set_limits(db, 1_000, 500)
before = rows(db)

log = FakeLog()
out = rt.run_if_due(db, log=log)
check("off means it does not run", out["ran"], False)
check("and nothing was deleted", rows(db), before)
check("it says why", out["reason"], "automatic pruning is off")

# Switched on, but under the trigger.
rt.apply_choice(db, "business", turn_on=True)      # 20 GB budget
log = FakeLog()
out = rt.run_if_due(db, log=log)
check("under the trigger means it does not run", out["ran"], False)
check("still nothing deleted", rows(db), before)

# Switched on AND over.
set_limits(db, 1_000, 500)
log = FakeLog()
out = rt.run_if_due(db, log=log)
check("on and over means it runs", out["ran"], True)
check("something was actually deleted", rows(db) < before, True)
# The newest run and the current run are never touched. That is the engine's
# rule; this checks the hook did not somehow bypass it.
with sqlite3.connect(db) as conn:
    left = {r[0] for r in conn.execute(
        "SELECT DISTINCT session_id FROM packets")}
check("the newest run survived", "new" in left, True)
check("it warned before starting, not after",
      any("Pruning the oldest whole capture runs now" in m
          for lvl, m in log.lines if lvl == "warning"), True)


print("\n[7] a broken limit pair refuses rather than inventing its own")
db = make_db({"a": (400, 10)})
rt.apply_choice(db, "homelab", turn_on=True)
set_limits(db, 1_000, 1_000)        # floor not below trigger
before = rows(db)
log = FakeLog()
out = rt.run_if_due(db, log=log)
check("it did not run", out["ran"], False)
check("and deleted nothing", rows(db), before)


print("\n[8] the model gets a read-only tool and no write twin")
from core import tool_registry as tr    # noqa: E402
names = {t["name"] for t in tr.TOOL_MANIFEST}
check("the tool exists", "query_database_size" in names, True)

# THE ONE THAT MATTERS. 23.4: deletion is the only irreversible act here and
# it never belongs to the model. A tool named for pruning must not exist.
banned = [n for n in names
          if any(w in n for w in ("prune", "delete_database", "vacuum",
                                  "purge", "wipe"))]
check("no tool lets the model delete or prune", banned, [])

desc = [t for t in tr.TOOL_MANIFEST
        if t["name"] == "query_database_size"][0]["description"]
check("the description says so plainly",
      "cannot delete anything here" in desc, True)
check("it points at the script instead", "prune_db.py" in desc, True)
check("and it warns against implying otherwise",
      "Do not imply you did anything" in desc, True)
check("it takes no parameters",
      [t for t in tr.TOOL_MANIFEST
       if t["name"] == "query_database_size"][0]["input_schema"]
      ["properties"], {})


print("\n[9] MAIN.PY ACTUALLY CALLS BOTH HOOKS")
# The bug this whole file exists for. Everything above can pass while the app
# still never prunes, if main.py does not call it. Asserted against the source
# because there is no way to boot main.py in a test.
main_src = (ROOT / "main.py").read_text(encoding="utf-8")
check("boot report is wired in", "retention.boot_report" in main_src, True)
check("the shutdown prune is wired in", "retention.run_if_due" in main_src,
      True)

# And in the right place: the prune must sit inside the clean shutdown, after
# the rollup. A prune before the final rollup would measure from a record that
# is not finished.
#
# RENAMED 2026-09-08. This used to look for "def handle_shutdown", which was
# right until the dashboard Stop button work split that function into
# _clean_shutdown(reason) plus two doors into it, Ctrl+C and the button. The
# assertion was stale, not the code. Anchoring on _clean_shutdown now, which
# is the function that actually does the work, so BOTH doors are covered by
# one check rather than only the keyboard one.
after_handler = main_src.split("def _clean_shutdown", 1)[-1]
check("the prune is inside the clean shutdown",
      "retention.run_if_due" in after_handler, True)
check("and after the final rollup",
      after_handler.index("shutdown_rollup")
      < after_handler.index("retention.run_if_due"), True)
check("boot never calls the pruner",
      "retention.run_if_due" in main_src.split("def _clean_shutdown", 1)[0],
      False)

# Both doors have to reach it, or the button is a shutdown that skips
# retention and nothing on screen would say so.
check("Ctrl+C goes through it", "_clean_shutdown(" in main_src.split(
      "def handle_shutdown", 1)[-1], True)
# PROC-14. A second signal must not exit through the first one's cleanup.
handler = main_src.split("def handle_shutdown", 1)[-1].split("\n    def ", 1)[0]
check("only the call that ran the shutdown exits",
      'if _clean_shutdown("Shutdown signal received"):' in handler, True)
check("and the second ask returns False",
      "return False" in main_src.split("def _clean_shutdown", 1)[-1].split(
          "Running final rollup", 1)[0], True)
check("and so does the dashboard Stop button",
      "_clean_shutdown(" in main_src.split(
          "def _shutdown_from_dashboard", 1)[-1], True)

# The live monitor and sensors still writing during the prune got
# "database is locked" and lost what they held.
shutdown = main_src.split("def _clean_shutdown", 1)[-1]
check("every writer is stopped before the prune",
      shutdown.index("_quiet_writers()") < shutdown.index("retention.run_if_due"),
      True)
for stop in ("_inc.stop()", "_acts.stop()", "_duty.stop()"):
    check(f"{stop} comes before the prune",
          shutdown.index(stop) < shutdown.index("retention.run_if_due"), True)
check("the live LAN monitor is one of them",
      "lan_live" in main_src.split("def _quiet_writers", 1)[-1].split(
          "def _clean_shutdown", 1)[0], True)

check("the setup script exists",
      (ROOT / "scripts" / "setup_retention.py").exists(), True)



print("\n[10] BOOT ASKS, AND IT WAITS. NO TIMER ANYWHERE.")
# This went wrong twice in one day and both are asserted here so neither can
# come back quietly.
#
# v1 put a 90 second timeout on the question. A question that expires is worse
# than no question: it gives up on you and teaches you to ignore it.
# v2 removed the question from boot entirely, which was an overcorrection and
# meant a fresh install would never get set up at all. 23.5 says first run
# should ASK.
# v3, what is asserted below: ask on a terminal, wait as long as it takes, and
# skip silently when there is no terminal so a service start cannot hang.
main_src_2 = (ROOT / "main.py").read_text(encoding="utf-8")
check("main.py asks at boot", "retention.first_run_prompt" in main_src_2, True)

rt_src = (ROOT / "core" / "retention.py").read_text(encoding="utf-8")
check("there is no timeout constant", "PROMPT_TIMEOUT" in rt_src, False)
check("and no timed-read helper", "_ask_with_timeout" in rt_src, False)
# The v1 timeout worked by handing input() to a thread and joining with a
# deadline. If a thread ever shows up in this module again, that is how it
# will come back.
check("the prompt does not run input on a thread",
      "threading" in rt_src, False)

# It waits: the only read is a bare input() with no deadline around it.
db = make_db({"a": (10, 10)})
seen = []
r = rt.first_run_prompt(db, input_fn=lambda p: (seen.append(p), "2")[1])
check("it asked", r["asked"], True)
check("and it saved what was typed", r.get("auto_prune"), True)
c = sqlite3.connect(db)
check("homelab is what landed", rt._pref_int(c, rt.PREF_TRIGGER, 0),
      5_000_000_000)
c.close()
check("asking twice is a no-op", rt.first_run_prompt(
    db, input_fn=lambda p: "1")["asked"], False)

# Enter is not an answer. Nothing is recorded, and it asks again next start.
db2 = make_db({"a": (10, 10)})
r2 = rt.first_run_prompt(db2, input_fn=lambda p: "")
check("empty answer configures nothing", r2["answered"], False)
c = sqlite3.connect(db2)
check("and it will be asked again", rt.configured(c), False)
check("and nothing is enabled meanwhile", rt.enabled(c), False)
c.close()

# Choice 4 IS an answer. It stops the asking and leaves pruning off.
db3 = make_db({"a": (10, 10)})
rt.first_run_prompt(db3, input_fn=lambda p: "4")
c = sqlite3.connect(db3)
check("declining is recorded", rt.configured(c), True)
check("and pruning stays off", rt.enabled(c), False)
c.close()

# A nonsense answer does not silently pick something.
db4 = make_db({"a": (10, 10)})
r4 = rt.first_run_prompt(db4, input_fn=lambda p: "banana")
check("a bad answer saves nothing", r4["answered"], False)
c = sqlite3.connect(db4)
check("and leaves it unconfigured", rt.configured(c), False)
c.close()


print("\n[10b] boot_report itself still only reports")
db = make_db({"a": (400, 10)})
set_limits(db, 1_000, 500)          # tiny, so it is already over
before = rows(db)
log = FakeLog()
st = rt.boot_report(db, log=log)
check("boot changed nothing", rows(db), before)
check("and did not configure anything", st["configured"], False)
# Over the budget with pruning off: the useful pointer is the pruner, because
# the file is already too big and setting a limit alone will not shrink it.
check("over the budget, it names the pruner",
      any("prune_db.py" in m for _, m in log.lines), True)

# Under the budget and not set up: the useful pointer is the setup script,
# for the headless case where the question was never asked.
db = make_db({"a": (10, 10)})
log = FakeLog()
rt.boot_report(db, log=log)
check("under the budget, it names the setup script",
      any("setup_retention.py" in m for _, m in log.lines), True)
check("and it is INFO, not a warning, because nothing is wrong",
      any(lvl == "warning" for lvl, _ in log.lines), False)


print("\n[11] the smallest budget is not one you fall over on day one")
# 1 GB was the smallest option. The real database is already about 1.6 GB, so
# picking it would have put the file over the line immediately and the first
# thing that choice ever did would be to delete. Owner's call to raise it.
smallest = min(p["trigger"] for p in rt.PRESETS)
check("smallest preset is 2 GB", smallest, 2_000_000_000)
check("and it matches the unconfigured default",
      smallest, rt.DEFAULT_TRIGGER_BYTES)
check("its floor matches the default floor too",
      [p for p in rt.PRESETS if p["trigger"] == smallest][0]["floor"],
      rt.DEFAULT_FLOOR_BYTES)
check("no preset is below the database as it stands today",
      all(p["trigger"] >= 2_000_000_000 for p in rt.PRESETS), True)

# apply_choice is still the only way a limit gets set, and it still validates.
db = make_db({"a": (10, 10)})
r = rt.apply_choice(db, 1, turn_on=True)
check("choice 1 saves 2 GB", r["trigger"], 2_000_000_000)
check("and it validates", r["ok"], True)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
