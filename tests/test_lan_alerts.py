# tests/test_lan_alerts.py
# The live LAN alerts: a new hardware address, an upload far above a device's
# own history, a connection to a listed address or name, and a blocked device
# back under a new address. Each is raised once, and a dismissed address
# raises nothing.

import pathlib
import sys
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import memory_engine as me                  # noqa: E402
from core import migrations                           # noqa: E402
migrations.run_migrations(me.DB_PATH)

from tools import lan_alerts as la                    # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


MB = la.MB
KNOWN = "00:00:5e:00:53:01"
NEW = "00:00:5e:00:53:02"
me.save_known_device("192.0.2.10", mac=KNOWN, hostname="laptop")


def ids(raised):
    return sorted(r["detection_id"] for r in raised)


def rows(det):
    with me._get_conn() as conn:
        return conn.execute("SELECT severity, entity_value FROM findings "
                            "WHERE detection_id = ?", (det,)).fetchall()


print("[1] a hardware address the inventory has never held")
a = la.LanAlerts("t", upload_floor_mb=50)
inv = {"192.0.2.10": {"mac": KNOWN}, "192.0.2.20": {"mac": NEW, "hostname": "unknown-box"}}
out = a.check(1000.0, inv, set(), {}, [], {})
check("the new one is raised, the known one is not", ids(out), ["LAN-1008"])
check("at high, so it wakes the agent", [tuple(r) for r in rows("LAN-1008")],
      [("high", "192.0.2.20")])
check("and only once", ids(a.check(1030.0, inv, set(), {}, [], {})), [])
b = la.LanAlerts("t")
b._known_macs = None
b._refresh_known = lambda now: None
check("an unreadable inventory raises nothing rather than everything",
      ids(b.check(1000.0, {"192.0.2.30": {"mac": "00:00:5e:00:53:03"}}, set(), {}, [], {})), [])
me.dismiss_entity("ip", "192.0.2.40", "known guest")
c = la.LanAlerts("t")
check("a dismissed address raises nothing",
      ids(c.check(1000.0, {"192.0.2.40": {"mac": "00:00:5e:00:53:04"}}, set(), {}, [], {})), [])


print("[2] a blocked device back under a new address")
a = la.LanAlerts("t")
a.check(2000.0, {"192.0.2.10": {"mac": KNOWN}}, {"192.0.2.10"}, {}, [], {})
out = a.check(2030.0, {"192.0.2.11": {"mac": KNOWN}}, {"192.0.2.10"}, {}, [], {})
check("blocked by address only, back elsewhere: high", ids(out), ["LAN-1011"])
check("it says it is online again",
      [r for r in rows("LAN-1011") if r[1] == "192.0.2.11"][0][0], "high")
check("raised once", ids(a.check(2060.0, {"192.0.2.11": {"mac": KNOWN}}, {"192.0.2.10"}, {}, [], {})), [])
m = "00:00:5e:00:53:05"
me.save_known_device("192.0.2.50", mac=m)
a2 = la.LanAlerts("t")
a2.check(3000.0, {"192.0.2.50": {"mac": m}}, {m}, {}, [], {})
out = a2.check(3030.0, {"192.0.2.51": {"mac": m}}, {m}, {}, [], {})
check("blocked by hardware address, new address: medium",
      [r[0] for r in rows("LAN-1011") if r[1] == "192.0.2.51"], ["medium"])


print("[3] an upload far above the device's own history")
a = la.LanAlerts("t", upload_floor_mb=50)
t0 = 10000.0
out = []
for i in range(0, 11):
    out += a.check(t0 + i * 60, {}, set(), {"192.0.2.60": {"up_total": i * 1 * MB}}, [], {})
check("10 MB in ten minutes is under the floor", ids(out), [])
a = la.LanAlerts("t", upload_floor_mb=50)
out = []
for i in range(0, 11):
    out += a.check(t0 + i * 60, {}, set(), {"192.0.2.61": {"up_total": i * 20 * MB}}, [], {})
check("200 MB in ten minutes with no history passes twice the floor", ids(out), ["LAN-1009"])
check("not again within the cooldown",
      ids(a.check(t0 + 700, {}, set(), {"192.0.2.61": {"up_total": 400 * MB}}, [], {})), [])
# A device that sends 30 MB a minute every day has a baseline that covers it.
now = datetime.now(timezone.utc)
with me._get_conn() as conn:
    conn.executemany(
        "INSERT INTO lan_traffic_minute(minute, ip, up_bytes, down_bytes) VALUES(?,?,?,0)",
        [((now - timedelta(minutes=k)).strftime("%Y-%m-%dT%H:%M:00+00:00"),
          "192.0.2.62", 30 * MB) for k in range(1, 1500)])
a = la.LanAlerts("t", upload_floor_mb=50)
out = []
for i in range(0, 11):
    out += a.check(t0 + i * 60, {}, set(), {"192.0.2.62": {"up_total": i * 30 * MB}}, [], {})
check("its usual 300 MB in ten minutes is not raised", ids(out), [])
a = la.LanAlerts("t", upload_floor_mb=50)
out = []
for i in range(0, 11):
    out += a.check(t0 + i * 60, {}, set(), {"192.0.2.62": {"up_total": i * 200 * MB}}, [], {})
check("but 2 GB is", ids(out), ["LAN-1009"])


print("[4] a connection to a listed address or name")
with me._get_conn() as conn:
    conn.execute("INSERT INTO threat_feed(indicator, indicator_type, feed, malware_family, "
                 "first_added, last_refreshed) VALUES('203.0.113.66','ip','testfeed','Botnet',"
                 "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)")
    conn.execute("INSERT INTO threat_feed(indicator, indicator_type, feed, malware_family, "
                 "first_added, last_refreshed) VALUES('bad.example','domain','testfeed','',"
                 "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)")
a = la.LanAlerts("t")
flows = [{"device": "192.0.2.70", "remote": "203.0.113.66", "port": 443, "proto": "tcp"},
         {"device": "192.0.2.71", "remote": "198.51.100.9", "port": 443, "proto": "tcp"},
         {"device": "192.0.2.72", "remote": "198.51.100.10", "port": 443, "proto": "tcp"}]
names = {("192.0.2.72", "198.51.100.10"): "cdn.bad.example"}
out = a.check(20000.0, {}, set(), {}, flows, names)
check("the listed address and the listed name are raised, the clean one is not",
      sorted(r["ip"] for r in out), ["192.0.2.70", "192.0.2.72"])
check("on the device's address", sorted(r[1] for r in rows("LAN-1010")),
      ["192.0.2.70", "192.0.2.72"])
check("not again on the next poll", ids(a.check(20030.0, {}, set(), {}, flows, names)), [])

print()
print("ALL CHECKS PASSED" if not fails else f"FAILED: {fails}")
sys.exit(1 if fails else 0)
