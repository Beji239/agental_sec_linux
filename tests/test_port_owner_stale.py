"""
tests/test_port_owner_stale.py, a stopped port sweep is noticed.

The sweeper now says it is running and at what interval, so status() can
call a sweep that is three intervals late stale (and blind, so every page
and the sensor check show it). The Ports tab shows the listener list the
agent reads. Scratch database, no app.
"""
import pathlib
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                      # noqa: E402
DB = _isolate_db.isolate()

from core import memory_engine as me                    # noqa: E402
from core import migrations                             # noqa: E402
migrations.run_migrations(me.DB_PATH)
from tools import port_owner as po                      # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def sweep_at(minutes_ago: int):
    at = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)) \
        .strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(me.DB_PATH) as c:
        c.execute("INSERT INTO port_owner_sweep (session_id, taken_at, sockets, "
                  "listeners, established, listeners_with_owner, "
                  "listeners_unreadable, note) VALUES ('s', ?, 3, 2, 1, 2, 0, "
                  "'2 of 2 listening socket(s) were matched to a process.')",
                  (at,))


print("\n[1] a sweeper that never said it runs is never called stale")
sweep_at(120)
st = po.status()
check("not stale while not marked running", st.get("stale"), None)
check("but the age is published", st["last_sweep_age_seconds"] >= 7190, True)

print("\n[2] marked running: late is stale, recent is not")
po.mark_running(300)
st = po.status()
check("two hours late is stale", st.get("stale"), True)
check("and blind, so every page shows it", st.get("blind"), True)
check("the reason says it is out of date", "out of date" in st["blind_reason"],
      True)
sweep_at(2)
st = po.status()
check("a sweep two minutes ago is fresh", st.get("stale"), None)
check("and not blind", bool(st.get("blind")), False)
sweep_at(-0)
po.mark_running(30)
sweep_at(10)
check("the 15 minute floor holds for short intervals",
      po.status().get("stale"), None)

print("\n[3] the age reader")
check("a T and Z stamp reads", po._age_seconds("2000-01-01T00:00:00Z") > 0, True)
check("junk is None", po._age_seconds("not a time"), None)

print("\n[4] the sweeper and the page are wired")
main = (ROOT / "main.py").read_text(encoding="utf-8")
check("the sweeper marks itself running",
      "port_owner.mark_running(interval)" in main, True)
check("the sensor check covers it", '"port_owner": _port_owner_tracker' in main,
      True)
page = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check("the Ports tab loads the listener list",
      "loadPorts(); loadPortSets(); loadListeners();" in page, True)
check("from the owners route", "'/api/ports/owners'" in page, True)
check("and shows a stale or blind sweep", "mod.blind_reason" in page, True)

print()
if fails:
    print(f"FAILED: {len(fails)}")
    sys.exit(1)
print("ALL PASSED")
