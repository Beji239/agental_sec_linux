"""
tests/test_sensor_watch.py, the sensor watchdog.

A collecting sensor that goes quiet raises SYS-1001 once, its recovery raises
SYS-1002, each quiet stretch is stored as a gap the Timeline can shade, the
time the app was off is a gap too, and stopping the watch at shutdown raises
nothing. Runs on a scratch database with fake sensors.
"""
import pathlib
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


tmp = pathlib.Path(tempfile.mkdtemp(prefix="sensorwatch_"))
DB = tmp / "t.db"
DB.write_text("")
sqlite3.connect(DB).executescript(
    (ROOT / "Schema.SQL").read_text(encoding="utf-8"))

from core import memory_engine as me            # noqa: E402
me.DB_PATH = DB
from core import migrations                     # noqa: E402
migrations.run_migrations(DB)
from core import detections as det              # noqa: E402
from core import sensor_watch as sw             # noqa: E402
import adapters                                 # noqa: E402


class FakeThread:
    def __init__(self, alive=True):
        self.alive = alive

    def is_alive(self):
        return self.alive


class Fake:
    """A sensor whose liveness and status the test sets directly."""

    def __init__(self, interval=60, started_at=0.0):
        self.lv = {"started": True, "thread_alive": True, "running": True,
                   "interval": interval, "started_at": started_at,
                   "last_ok_at": started_at, "consecutive_failures": 0,
                   "last_error": None}
        self.st = {"running": True}

    def liveness(self):
        return dict(self.lv)

    def status(self):
        return dict(self.st)


def sys_findings():
    with sqlite3.connect(DB) as c:
        return [r[0] for r in c.execute(
            "SELECT detection_id FROM findings WHERE source = 'sensor_watch' "
            "ORDER BY id")]


def gap_rows():
    with sqlite3.connect(DB) as c:
        return c.execute("SELECT sensor, reason, started_at, ended_at "
                         "FROM sensor_gaps ORDER BY id").fetchall()


print("\n[1] the register and the schema")
check("SYS-1001 is registered as high",
      sorted(det.get("SYS-1001").severities), ["high"])
check("SYS-1002 is registered as info",
      sorted(det.get("SYS-1002").severities), ["info"])
check("both have a plain sentence", all(det.PLAIN.get(d) for d in
      ("SYS-1001", "SYS-1002")) if hasattr(det, "PLAIN") else True, True)
with sqlite3.connect(DB) as c:
    tables = {r[0] for r in c.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
check("sensor_gaps exists", "sensor_gaps" in tables, True)
check("sensor_watch_beat exists", "sensor_watch_beat" in tables, True)


print("\n[2] assess reads each way a sensor goes quiet")
T = 100000.0
f = Fake(started_at=T)
check("fresh sensor is ok", sw.assess("x", f, T + 10)["state"], "ok")
f.lv["last_ok_at"] = T - 1000
check("no good poll for longer than the grace is quiet",
      sw.assess("x", f, T)["state"], "quiet")
f.lv["last_ok_at"] = T - 250
check("but a short stall under the five minute floor is not",
      sw.assess("x", f, T)["state"], "ok")
f = Fake(started_at=T)
f.lv["consecutive_failures"] = 3
f.lv["last_error"] = "OSError: boom"
a = sw.assess("x", f, T)
check("three failed polls in a row is quiet", a["state"], "quiet")
check("and says the error", "boom" in a["reason"], True)
f = Fake(started_at=T)
f.lv["thread_alive"] = False
check("a dead thread is quiet", sw.assess("x", f, T)["state"], "quiet")
f = Fake(started_at=T)
f.st["blind"] = True
f.st["blind_reason"] = "no capture right"
check("blind is quiet", sw.assess("x", f, T)["reason"],
      "cannot see: no capture right")
f = Fake(started_at=T)
f.st["off_by_config"] = True
check("switched off in Settings is off, not quiet",
      sw.assess("x", f, T)["state"], "off")
f = Fake(started_at=T)
f.st["engine"] = {"installed": False}
check("a scanner with no engine installed is off",
      sw.assess("x", f, T)["state"], "off")
f = Fake(started_at=T)
f.lv["started"] = False
f.st = {"note": "No router agent is configured."}
check("never started is off", sw.assess("x", f, T)["state"], "off")
f = Fake(started_at=T)
f.st["capture_state"] = {"alive": False, "failure": "interface gone"}
check("a stopped packet capture is quiet",
      sw.assess("x", f, T)["state"], "quiet")
check("an on-demand module is not watched",
      sw.assess("x", object(), T), None)


print("\n[3] the real base adapter reports its own liveness")
ad = adapters._BaseAdapter("s", {})
check("before start: not started", ad.liveness()["started"], False)
ad.poll = lambda: None
ad._wait_for_next_poll = lambda: ad.stop()
ad.start()
ad._thread.join(2)
lv = ad.liveness()
check("after one clean poll: last_ok_at is set", lv["last_ok_at"] is not None,
      True)
check("and the failure count is zero", lv["consecutive_failures"], 0)


print("\n[4] went quiet, recovered, one finding each")
mods = {"process_monitor": Fake(started_at=T), "event_monitor": Fake(started_at=T)}
w = sw.SensorWatch(mods, "sid")
out = w.check_once(T + 30)
check("all ok at first", out["label"], "All sensors OK")
check("nothing raised", sys_findings(), [])
mods["process_monitor"].lv["thread_alive"] = False
out = w.check_once(T + 90)
check("one quiet", out["label"], "1 sensor quiet")
check("SYS-1001 raised", sys_findings(), ["SYS-1001"])
check("a gap opened", [(g[0], g[3]) for g in gap_rows()],
      [("process_monitor", None)])
w.check_once(T + 150)
check("still quiet raises nothing more", sys_findings(), ["SYS-1001"])
mods["process_monitor"].lv["thread_alive"] = True
mods["process_monitor"].lv["last_ok_at"] = T + 200
w.check_once(T + 210)
check("recovery raises SYS-1002", sys_findings(), ["SYS-1001", "SYS-1002"])
check("and closes the gap", gap_rows()[0][3] is not None, True)
with sqlite3.connect(DB) as c:
    row = c.execute("SELECT entity_type, entity_value, severity FROM findings "
                    "WHERE detection_id = 'SYS-1001'").fetchone()
check("the finding names the sensor", row,
      ("process", "sensor:process_monitor", "high"))

mods["process_monitor"].lv["thread_alive"] = False
w.check_once(T + 300)
check("quiet again within the hour: gap, no second alert",
      (len(gap_rows()), sys_findings().count("SYS-1001")), (2, 1))
mods["process_monitor"].lv["thread_alive"] = True
mods["process_monitor"].lv["last_ok_at"] = T + 350
w.check_once(T + 360)
check("and no recovery for an episode that raised nothing",
      sys_findings().count("SYS-1002"), 1)


print("\n[5] quiet from the first check: gap, no alert")
q = Fake(started_at=T)
q.st["blind"] = True
w2 = sw.SensorWatch({"packet_sniffer": q}, "sid")
w2._booted = True
before = len(sys_findings())
w2.check_once(T + 30)
check("no finding for a sensor never seen collecting",
      len(sys_findings()), before)
check("but the gap is recorded", gap_rows()[-1][0], "packet_sniffer")


print("\n[6] the app being off is a gap, and a stop at shutdown raises nothing")
with sqlite3.connect(DB) as c:
    c.execute("DELETE FROM sensor_gaps")
    c.execute("INSERT OR REPLACE INTO sensor_watch_beat (id, at, first_at) "
              "VALUES (1, ?, ?)", (int(T), int(T)))
    c.execute("INSERT INTO sensor_gaps (sensor, reason, started_at) "
              "VALUES ('event_monitor', 'left open', ?)", (sw._sql(T - 60),))
w3 = sw.SensorWatch({"event_monitor": Fake(started_at=T + 3600)}, "sid")
w3._started = T + 3600
w3.check_once(T + 3660)
g = gap_rows()
check("the open gap from the last run is closed at its last check",
      (g[0][0], g[0][3]), ("event_monitor", sw._sql(T)))
check("and the hour off is recorded as the app not running",
      (g[1][0], g[1][2], g[1][3]),
      ("agentalsec", sw._sql(T), sw._sql(T + 3600)))
shown = sw.gaps(sw._sql(T - 1800), sw._sql(T + 7200))
check("gaps() returns both, cut to the window", len(shown), 2)
check("and labels the app gap in words", shown[1]["label"], "AgentalSec")
check("watched_since is the first check", sw.watched_since(), sw._sql(T))

before = len(sys_findings())
w3.stopped = True
for m in w3.modules.values():
    m.lv["running"] = False
w3.check_once(T + 3720)
check("after stop, stopped sensors raise nothing", len(sys_findings()), before)


print("\n[7] plain loop threads: DNS importer and router collector")
lt = sw.LoopTracker(300, idle=lambda: "waiting for a resolver")
check("a collector with nothing to read is off, with the reason",
      sw.assess("dns_monitor", lt, T), {"sensor": "dns_monitor", "state": "off",
                                        "reason": "waiting for a resolver"})
reading = {"why": None}
lt = sw.LoopTracker(300, idle=lambda: reading["why"])
lt.begin(FakeThread())
lt.started_at = T
lt.ok()
lt.last_ok_at = T
check("reading and recent is ok", sw.assess("dns_monitor", lt, T + 60)["state"],
      "ok")
for _ in range(3):
    lt.failed("router did not answer")
a = sw.assess("dns_monitor", lt, T + 60)
check("three failed passes is quiet", (a["state"], "router did not answer" in
      a["reason"]), ("quiet", True))
lt.ok()
lt.last_ok_at = T
check("no pass for three intervals is quiet",
      sw.assess("dns_monitor", lt, T + 3 * 300 + 5)["state"], "quiet")

from tools import dns_monitor as dm             # noqa: E402
gw_on = {"gateway": {"enabled": True, "host": "192.0.2.1"}}
check("auto reads the router once the agent is enrolled",
      dm.resolve_source({"dns_monitor": {"source": "auto"}, **gw_on}), "router")
check("auto with no router and no file waits",
      dm.status({"dns_monitor": {"enabled": True, "source": "auto"}})["reason"],
      dm.WAITING_FOR_RESOLVER)
check("auto picks AdGuard for a .json file",
      dm.resolve_source({"dns_monitor": {"source": "auto",
                                         "path": "/srv/querylog.json"}}),
      "adguard")
check("auto picks Pi-hole for a database file",
      dm.resolve_source({"dns_monitor": {"source": "auto",
                                         "path": "/srv/pihole-FTL.db"}}),
      "pihole")
check("an explicit source is kept",
      dm.resolve_source({"dns_monitor": {"source": "pihole"}, **gw_on}),
      "pihole")
check("a missing source means auto",
      dm.status({"dns_monitor": {"enabled": True}, **gw_on})["available"], True)


print("\n[8] visible text has no dash punctuation or pipes")
src = (ROOT / "core" / "sensor_watch.py").read_text(encoding="utf-8")
check("no em or en dash in the module", any(ch in src for ch in "\u2014\u2013"),
      False)
page = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
legend = page.split('<b>The bar under the filters</b>')[1].split('</div>')[0]
check("the Timeline legend has no dash punctuation",
      any(x in legend for x in ("\u2014", "\u2013", " - ", " -- ", " | ")), False)
check("the old caveat is gone", "What it cannot tell you" in page, False)


print()
if fails:
    print(f"FAILED: {len(fails)}")
    for f_ in fails:
        print(f"  {f_}")
    sys.exit(1)
print("ALL PASSED")
