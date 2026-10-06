# tests/test_lan_live.py
# The live LAN monitor against a scripted router: rates from counter deltas,
# destinations from the connection table with names from DNS answers, the
# upstream side kept out, finished connections and minute totals stored, and
# the dashboard's cut and restore routes reaching the router by hardware
# address.

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import memory_engine as me                  # noqa: E402
from core import migrations                           # noqa: E402
migrations.run_migrations(me.DB_PATH)

from tools import lan_live                            # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def flow(src, sport, dst, dport, out_b, in_b, proto="tcp"):
    return {"proto": proto, "state": "ESTABLISHED", "src": src, "dst": dst,
            "sport": sport, "dport": dport, "bytes_out": out_b,
            "packets_out": 1, "bytes_in": in_b, "packets_in": 1,
            "nat_src": "198.51.100.2", "unreplied": False}


class FakeRouter:
    def __init__(self):
        self.caps = {"counters", "dnslog", "leases", "neighbors", "block",
                     "blockmac", "conntrack", "persist"}
        self.ctr = {}
        self.fl = []
        self.blocked = set()
        self.calls = []

    def probe(self):
        return {"capabilities": sorted(self.caps)}

    def has(self, c):
        return c in self.caps

    def counters(self):
        return {"restored": False, "devices": {k: dict(v) for k, v in self.ctr.items()}}

    def flows(self, ip=None):
        return list(self.fl)

    def leases(self):
        return [{"ip": "172.21.0.10", "mac": "aa:bb:cc:00:00:10", "hostname": "console"},
                {"ip": "172.21.0.11", "mac": "02:00:5e:00:53:01", "hostname": None}]

    def neighbors(self):
        return [{"ip": "172.21.0.10", "mac": "aa:bb:cc:00:00:10", "interface": "br-lan"},
                {"ip": "172.20.0.1", "mac": "00:00:5e:00:53:22", "interface": "eth1"}]

    def blocks(self):
        return sorted(self.blocked)

    def dnslog(self, n):
        return [
            "Wed Sep 30 23:09:34 2026 daemon.info dnsmasq[1]: 5 172.21.0.10/5000 query[A] game.example from 172.21.0.10",
            "Wed Sep 30 23:09:34 2026 daemon.info dnsmasq[1]: 5 172.21.0.10/5000 reply game.example is 203.0.113.7",
        ]

    def block_mac(self, mac):
        self.calls.append(("block_mac", mac))
        self.blocked.add(mac)
        return {"mac": mac, "already": "no", "verified": "read_back"}

    def unblock_mac(self, mac):
        self.calls.append(("unblock_mac", mac))
        was = mac in self.blocked
        self.blocked.discard(mac)
        return {"mac": mac, "was_blocked": "yes" if was else "no"}


def c(up, down):
    return {"up_packets": 1, "up_bytes": up, "down_packets": 1, "down_bytes": down}


r = FakeRouter()
cfg = {"gateway": {"enabled": True, "host": "172.21.0.1"},
       "lan_live": {"poll_seconds": 2}}
m = lan_live.LanLive(cfg, gateway=r, store=True)

print("rates")
r.ctr = {"172.21.0.10": c(1000, 5000), "172.21.0.11": c(0, 0)}
r.fl = [flow("172.21.0.10", 40000, "203.0.113.7", 443, 100, 1000),
        flow("172.21.0.10", 40001, "172.21.0.1", 53, 10, 10, "udp")]
m.tick(1000.0)
r.ctr = {"172.21.0.10": c(3000, 25000), "172.21.0.11": c(0, 0)}
r.fl = [flow("172.21.0.10", 40000, "203.0.113.7", 443, 300, 9000)]
m.tick(1002.0)
snap = m.snapshot(now=1002.0)
dev = {d["ip"]: d for d in snap["devices"]}
check("upstream neighbour is not a device", sorted(dev), ["172.21.0.10", "172.21.0.11"])
check("upload rate from the counters", dev["172.21.0.10"]["up_bps"], 1000)
check("download rate from the counters", dev["172.21.0.10"]["down_bps"], 10000)
check("totals since start", (dev["172.21.0.10"]["up_total"], dev["172.21.0.10"]["down_total"]), (2000, 20000))
check("busiest device first", snap["devices"][0]["ip"], "172.21.0.10")
d = m.device("172.21.0.10", now=1002.0)
check("one destination, the router itself left out", len(d["destinations"]), 1)
x = d["destinations"][0]
check("destination named from the DNS answer", x["name"], "game.example")
check("destination rate from the connection delta", (x["out_bps"], x["in_bps"]), (100, 4000))
check("the device's lookups", [q["domain"] for q in d["lookups"]], ["game.example"])

print("counter reset")
r.ctr = {"172.21.0.10": c(10, 10), "172.21.0.11": c(0, 0)}
m.tick(1004.0)
check("a reset counter is not a negative rate",
      m.snapshot(now=1004.0)["devices"][0]["up_bps"] >= 0, True)

print("stored")
r.fl = []
m.tick(1062.0)
with me._get_conn() as conn:
    flows = conn.execute("SELECT device_ip, dst, dst_name, bytes_in FROM lan_flow").fetchall()
    minutes = conn.execute("SELECT ip, up_bytes, down_bytes FROM lan_traffic_minute").fetchall()
check("a finished connection is kept with its name",
      [tuple(f) for f in flows], [("172.21.0.10", "203.0.113.7", "game.example", 9000)])
check("the minute total is kept", [tuple(x) for x in minutes], [("172.21.0.10", 2000, 20000)])

print("a locked database loses nothing")
import sqlite3                                         # noqa: E402
from contextlib import contextmanager                  # noqa: E402

real_conn = me._get_conn


@contextmanager
def locked_conn():
    raise sqlite3.OperationalError("database is locked")
    yield


r2 = FakeRouter()
m2 = lan_live.LanLive(cfg, gateway=r2, store=True)
r2.ctr = {"172.21.0.20": c(0, 0)}
r2.fl = [flow("172.21.0.20", 41000, "203.0.113.9", 443, 100, 100)]
m2.tick(1200.0)
me._get_conn = locked_conn
try:
    r2.ctr = {"172.21.0.20": c(1000, 2000)}
    m2.tick(1210.0)
    r2.ctr = {"172.21.0.20": c(3000, 6000)}
    r2.fl = []
    m2.tick(1265.0)
    r2.ctr = {"172.21.0.20": c(4000, 8000)}
    m2.tick(1330.0)
    check("two failed minutes are both kept", len(m2._pending_minutes), 2)
    check("the finished connection is kept", len(m2.finished), 1)
finally:
    me._get_conn = real_conn
r2.ctr = {"172.21.0.20": c(4500, 9000)}
m2.tick(1340.0)


def minutes_for(ip):
    with me._get_conn() as conn:
        return [tuple(x) for x in conn.execute(
            "SELECT minute, up_bytes, down_bytes FROM lan_traffic_minute "
            "WHERE ip=? ORDER BY minute", (ip,))]


check("both minutes written once the lock clears",
      [x[1:] for x in minutes_for("172.21.0.20")], [(3000, 6000), (1000, 2000)])
with me._get_conn() as conn:
    n = conn.execute("SELECT COUNT(*) FROM lan_flow WHERE device_ip='172.21.0.20'").fetchone()[0]
check("and the connection", n, 1)
m2.stop()
check("stop writes the minute under way",
      [x[1:] for x in minutes_for("172.21.0.20")][-1], (500, 1000))
r2.ctr = {"172.21.0.20": c(4600, 9100)}
m2.tick(1345.0)
m2._flush(force=True)
check("a later poll in that minute adds to it, not doubles it",
      [x[1:] for x in minutes_for("172.21.0.20")][-1], (600, 1100))

print("cut and restore from the dashboard")
from flask import Flask                                # noqa: E402
from api import routes                                 # noqa: E402
import adapters                                        # noqa: E402


class FakeGatewayModule(adapters.LinuxGateway):
    def __init__(self):
        self.session_id = "t"
        self.cfg = {"enabled": True, "host": "172.21.0.1"}
        self._gw = r

    def _gateway(self):
        return r


lan_live._monitor = m
app = Flask(__name__)
app.config.update(AGENTAL_CONFIG=cfg, AGENTAL_MODULES={"gateway": FakeGatewayModule()},
                  AGENTAL_SESSION_ID="t", AGENTAL_API_KEY="k",
                  AGENTAL_ALLOWED_HOSTS={"localhost"})
routes.register_routes(app)
client = app.test_client()
h = {"X-API-Key": "k", "Host": "localhost"}
res = client.post("/api/lan/block", json={"mac": "AA:BB:CC:00:00:10", "ip": "172.21.0.10"}, headers=h)
check("cut reaches the router by hardware address", (res.status_code, r.calls[-1]),
      (200, ("block_mac", "aa:bb:cc:00:00:10")))
check("the record says it survives a reboot", res.get_json().get("lasts"),
      "until it is lifted, across router reboots")
snap = client.get("/api/lan/live", headers=h).get_json()
row = next(x for x in snap["devices"] if x["ip"] == "172.21.0.10")
check("the device shows as cut off, by mac", (row["blocked"], row["blocked_by"]), (True, "mac"))
res = client.post("/api/lan/unblock", json={"mac": "aa:bb:cc:00:00:10"}, headers=h)
check("restore lifts it", (res.status_code, r.calls[-1]), (200, ("unblock_mac", "aa:bb:cc:00:00:10")))
res = client.post("/api/lan/unblock", json={"mac": "aa:bb:cc:00:00:10"}, headers=h)
check("restoring what is not blocked says so", res.status_code, 409)
res = client.post("/api/lan/block", json={}, headers=h)
check("nothing named is refused", res.status_code, 400)
with me._get_conn() as conn:
    recs = [x[0] for x in conn.execute(
        "SELECT detection_id FROM findings WHERE source = 'remediation' ORDER BY id")]
check("each change is an action record", recs, ["REM-1013", "REM-1014"])

print("a device that has left the router keeps its inventory name")
me.save_known_device("192.0.2.40", mac="00:00:5e:00:53:40", hostname="ps5")
with me._get_conn() as conn:
    conn.execute("UPDATE known_devices SET known_as = 'PlayStation', "
                 "device_type = 'console' WHERE ip = '192.0.2.40'")
with m._lock:
    m.devices["192.0.2.40"] = dict(next(iter(m.devices.values())))
    m.inventory.pop("192.0.2.40", None)
snap = client.get("/api/lan/live", headers=h).get_json()
row = next(x for x in snap["devices"] if x["ip"] == "192.0.2.40")
check("named from the inventory row for its IP",
      (row["present"], row["known_as"], row["device_type"], row["mac"], row["hostname"]),
      (False, "PlayStation", "console", "00:00:5e:00:53:40", "ps5"))
res = client.get("/api/lan/device?ip=192.0.2.40", headers=h).get_json()
check("and in the detail panel", (res.get("known_as"), res.get("mac")),
      ("PlayStation", "00:00:5e:00:53:40"))
me.retire_device("192.0.2.40", "gone")
snap = client.get("/api/lan/live", headers=h).get_json()
row = next(x for x in snap["devices"] if x["ip"] == "192.0.2.40")
check("a retired row lends no name", (row.get("known_as"), row["mac"]), (None, None))

print()
if fails:
    print(f"{len(fails)} FAILED: {fails}")
    sys.exit(1)
print("all passed")
