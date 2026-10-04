"""
tests/test_config_write_and_status.py, BP-1 and WS-1.

BP-1: every config.json writer reads the file fresh under one lock and
replaces it atomically, so two saves in the same second both land.
WS-1: retention.status() answers from indexes, with the same counts the
full scan gives.
"""
import json
import pathlib
import sqlite3
import sys
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


from core import settings as st           # noqa: E402
from core import retention as rt          # noqa: E402
from core import migrations               # noqa: E402

print("[1] concurrent writes to config.json all land")
tmp = pathlib.Path(tempfile.mkdtemp())
st.CONFIG_PATH = tmp / "config.json"
st.CONFIG_PATH.write_text(json.dumps({"router_monitor": {}, "probe": {}}))
threads = [threading.Thread(target=st.persist_config_value,
                            args=("probe", f"k{i}", i)) for i in range(40)]
threads.append(threading.Thread(target=st.persist_config_value,
                                args=("router_monitor", "enabled", True)))
for t in threads:
    t.start()
for t in threads:
    t.join()
raw = json.loads(st.CONFIG_PATH.read_text())
check("all 40 keys survived", len(raw["probe"]), 40)
check("and the router switch too", raw["router_monitor"]["enabled"], True)
check("no temp file left", sorted(p.name for p in tmp.iterdir()), ["config.json"])

print("[2] a Settings save is not undone by the router switch")
st.CONFIG_PATH.write_text(json.dumps({"router_monitor": {"enabled": False},
                                      "probe": {"interval_days": 21}}))
check("settings save", st.set_config("probe.interval_days", 30)["ok"], True)
check("router toggle", st.persist_config_value("router_monitor", "enabled", True), None)
raw = json.loads(st.CONFIG_PATH.read_text())
check("the Settings value is still 30", raw["probe"]["interval_days"], 30)

print("[3] no writer is left on plain write_text")
routes = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")
main = (ROOT / "main.py").read_text(encoding="utf-8")
check("router toggle uses the shared writer",
      'persist_config_value("router_monitor", "enabled"' in routes, True)
check("routes write config.json nowhere else",
      "config_path.write_text" in routes, False)
check("main.py writes config.json atomically",
      "CONFIG_PATH.write_text" in main, False)

print("[4] status() counts runs from indexes, and agrees with the full scan")
db = tmp / "t.db"
c = sqlite3.connect(db)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.commit()
c.close()
migrations.run_migrations(db)
c = sqlite3.connect(db)
for sid, day in (("a", 1), ("b", 3), ("c", 2)):
    c.executemany(
        "INSERT INTO packets(session_id, captured_at, src_ip, dst_ip, protocol,"
        " direction, packet_size) VALUES(?,?,?,?,?,?,?)",
        [(sid, f"2026-08-{day:02d} {h:02d}:00:00", "192.0.2.1", "192.0.2.2",
          "TCP", "outbound", 60) for h in range(5)])
c.execute("INSERT INTO events(session_id, occurred_at, event_type, source) "
          "VALUES('d','2026-08-04 00:00:00','test','test')")
c.commit()
inv = rt.session_inventory(c)
summ = rt.run_summary(c)
c.close()
check("run count matches", summ["runs"], len(inv))
check("oldest matches", summ["oldest_at"], inv[0]["first_at"])
check("newest matches", summ["newest_at"], max(s["last_at"] for s in inv))
s = rt.status(str(db))
check("status reports it", (s["capture_runs"], s["oldest_run_at"]),
      (4, "2026-08-01 00:00:00"))
check("the cheap inventory skips the byte sum",
      rt.session_inventory(sqlite3.connect(db), with_bytes=False)[0]["bytes_estimate"],
      None)

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
