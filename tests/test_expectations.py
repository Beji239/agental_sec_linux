"""
tests/test_expectations.py, the expectations engine and the network mood.

A fake router reader and seeded router records on a scratch database: each
check holds on quiet data, breaks or turns new on the matching evidence, and
says "could not check" when the router cannot back it.
"""
import json
import pathlib
import sys
import threading
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
db = _isolate_db.isolate()

from core import expectations as ex  # noqa: E402
from core import memory_engine as me  # noqa: E402
from core import migrations  # noqa: E402

migrations.run_migrations(db)

failures = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        failures.append(label)
        print(f"        {detail}")


class FakeGateway:
    def __init__(self, version=9, caps=("block", "conntrack", "counters"),
                 hits=None, counted=True):
        self.probe_result = {"capabilities": list(caps),
                             "agent_version": str(version), "firewall": "nft"}
        self.hits, self.counted = hits or {}, counted

    def block_hits(self):
        return {"counted": self.counted, "reason": None, "hits": self.hits}


class FakeLive:
    def __init__(self, ok=True, blocked=(), devices=3, **gw):
        self._lock = threading.Lock()
        self.g = FakeGateway(**gw)
        self.blocked = set(blocked)
        self.inventory = {f"172.21.0.{10 + i}": {} for i in range(devices)}
        self.app_blocks = {}
        self._ok = ok

    def _read_status(self):
        return {"ok": self._ok, "error": None if self._ok
                else "Could not read the router: no answer for 90 s."}


NOW = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)


def by_kind(ov):
    return {(e["kind"], e["subject"]): e for e in ov["expectations"]}


def sql(*stmts):
    with me._get_conn() as conn:
        for s, args in stmts:
            conn.execute(s, args)
        conn.commit()


# A router that answers, a quiet network

print("A quiet network")
sql(("INSERT INTO lan_baseline (name, value_json) VALUES ('gateway_mac', ?)",
     (json.dumps("aa:bb:cc:dd:ee:ff"),)))
ov = ex.check_once({}, live=FakeLive(blocked=["198.51.100.7"]), now=NOW)
k = by_kind(ov)
check("one expectation per network kind, plus one per block",
      set(k) == {(n, "") for n in ex.NETWORK_KINDS}
      | {("block_holds", "198.51.100.7")}, sorted(k))
check("the block holds with no traffic", k[("block_holds", "198.51.100.7")]
      ["state"] == "holding", k[("block_holds", "198.51.100.7")])
check("all blocks hold", k[("blocks_hold", "")]["state"] == "holding")
check("the gateway did not change", k[("same_gateway", "")]["state"]
      == "holding", k[("same_gateway", "")])
check("quiet nights say they are still learning",
      k[("quiet_nights", "")]["state"] == "unknown")
check("the mood is calm", ov["mood"] == "calm", ov["sentence"])
check("the sentence carries the numbers", "expectations held" in
      ov["sentence"] and "Router watched" in ov["sentence"], ov["sentence"])

# A block that leaks

print("\nA leaking block")
since = ex._parse(k[("block_holds", "198.51.100.7")]["since"])
sql(("INSERT INTO lan_flow (device_ip, proto, dst, dport, bytes_out, "
     "bytes_in, packets_out, packets_in, first_seen, last_seen) "
     "VALUES ('172.21.0.10', 'tcp', '198.51.100.7', 443, 500, 900, 4, 3, ?, ?)",
     (ex._iso(since + timedelta(minutes=5)),
      ex._iso(since + timedelta(minutes=6)))))
ov = ex.check_once({}, live=FakeLive(blocked=["198.51.100.7"]),
                   now=NOW + timedelta(minutes=10))
k = by_kind(ov)
b = k[("block_holds", "198.51.100.7")]
check("an answered connection after the block breaks it",
      b["state"] == "broken" and "leaked" in b["detail"], b)
check("all blocks hold is broken too", k[("blocks_hold", "")]["state"]
      == "broken")
check("the mood is alarmed", ov["mood"] == "alarmed", ov["sentence"])
check("acknowledging the break",
      ex.acknowledge(b["id"], now=NOW + timedelta(minutes=10))["success"])
sql(("DELETE FROM lan_flow", ()))
ov = ex.check_once({}, live=FakeLive(blocked=["198.51.100.7"]),
                   now=NOW + timedelta(minutes=20))
check("after it is seen and the leak stopped, the mood calms",
      ov["mood"] == "calm", ov["sentence"])

# A router that cannot back the block

print("\nA router that cannot confirm")
ov = ex.check_once({}, live=FakeLive(blocked=["198.51.100.7"], version=7),
                   now=NOW + timedelta(minutes=30))
b = by_kind(ov)[("block_holds", "198.51.100.7")]
check("an old agent: the block is not called held",
      b["state"] == "unknown" and "can't confirm" in b["detail"], b)
check("the mood is uneasy, not calm", ov["mood"] == "uneasy", ov["sentence"])
ov = ex.check_once({}, live=FakeLive(ok=False),
                   now=NOW + timedelta(minutes=40))
check("an unreachable router keeps the block, not ended",
      ("block_holds", "198.51.100.7") in by_kind(ov))
check("and the mood says why", ov["mood"] == "uneasy" and "no answer"
      in ov["sentence"], ov["sentence"])
ov = ex.check_once({}, live=FakeLive(blocked=[]),
                   now=NOW + timedelta(minutes=50))
b = by_kind(ov).get(("block_holds", "198.51.100.7"))
check("a block gone from the router that the app did not lift is broken",
      b and b["state"] == "broken" and "no longer on the router" in b["detail"],
      b)
check("and the mood says so", ov["mood"] == "alarmed", ov["sentence"])
sql(("INSERT INTO findings (session_id, found_at, source, severity, "
     "entity_type, entity_value, title, detection_id, raw_data) VALUES "
     "('t', ?, 'remediation', 'info', 'ip', '198.51.100.7', 'Unblocked', "
     "'REM-1010', ?)", (ex._sql(NOW + timedelta(minutes=55)),
                        json.dumps({"argument": "198.51.100.7"}))))
ov = ex.check_once({}, live=FakeLive(blocked=[]),
                   now=NOW + timedelta(minutes=58))
check("an unblock the app made ends the expectation",
      ("block_holds", "198.51.100.7") not in by_kind(ov))
ov = ex.check_once({}, live=FakeLive(blocked=["aa:aa:aa:aa:aa:77"]),
                   now=NOW + timedelta(minutes=59))
ov = ex.check_once({}, live=FakeLive(blocked=[]),
                   now=NOW + timedelta(minutes=59, seconds=30))
gone = by_kind(ov)[("block_holds", "aa:aa:aa:aa:aa:77")]
ex.acknowledge(gone["id"], now=NOW + timedelta(minutes=59, seconds=35))
ov = ex.check_once({}, live=FakeLive(blocked=[]),
                   now=NOW + timedelta(minutes=59, seconds=40))
check("a missing block the owner has seen ends",
      ("block_holds", "aa:aa:aa:aa:aa:77") not in by_kind(ov))

# The block wall

print("\nThe block wall")
W = NOW + timedelta(minutes=59, seconds=50)
WALL = dict(version=10, caps=("block", "conntrack", "counters", "blockhits"))
ov = ex.check_once({}, live=FakeLive(blocked=["198.51.100.8"]), now=W)
check("agent 9: no wall, and it says why",
      ov["walls"] == [] and "version 10" in ov["router"]["wall_reason"],
      ov["router"])
check("an old agent does not turn the mood uncertain", ov["mood"] != "uneasy",
      ov["sentence"])
w0 = W + timedelta(minutes=5)
for i, n in enumerate((0, 4, 4, 30)):
    ov = ex.check_once({}, live=FakeLive(blocked=["198.51.100.8"], hits={
        "198.51.100.8": {"packets": n, "bytes": n * 60}}, **WALL),
        now=w0 + timedelta(minutes=20 * i))
walls = ov["walls"]
check("one wall per block", [x["subject"] for x in walls] == ["198.51.100.8"],
      walls)
check("the caught packets are counted from the readings",
      walls[0]["caught_24h"] == 30, walls[0])
check("by hour, 24 of them", len(walls[0]["hours"]) == 24
      and sum(walls[0]["hours"]) == 30, walls[0]["hours"])
check("a public address is the far side", walls[0]["side"] == "address")
b = by_kind(ov)[("block_holds", "198.51.100.8")]
check("the ticket says what the router caught",
      "caught 30 packets" in b["detail"], b["detail"])
ov = ex.check_once({}, live=FakeLive(blocked=["198.51.100.8"], hits={
    "198.51.100.8": {"packets": 5, "bytes": 300}}, **WALL),
    now=w0 + timedelta(minutes=80))
check("a router restart counts on from zero",
      ov["walls"][0]["caught_24h"] == 35, ov["walls"][0])
ov = ex.check_once({}, live=FakeLive(blocked=["198.51.100.8"], counted=False,
                                     **WALL), now=w0 + timedelta(minutes=85))
check("a router that cannot count draws no wall and says so",
      ov["walls"] == [] and "no count per block" in ov["router"]["wall_reason"],
      ov["router"])
check("and the overview remembers it", ex.overview(
    now=w0 + timedelta(minutes=86))["router"]["wall_reason"]
    is not None)
cam = "192.0.2.41"
live = FakeLive(blocked=["198.51.100.8", cam],
                hits={cam: {"packets": 2, "bytes": 80}}, **WALL)
live.inventory[cam] = {}
ov = ex.check_once({}, live=live, now=w0 + timedelta(minutes=90))
dev = [x for x in ov["walls"] if x["subject"] == cam]
check("a blocked device is the near side, its first reading counts",
      dev and dev[0]["side"] == "device" and dev[0]["caught_24h"] == 2, dev)
sql(("DELETE FROM block_hit", ()))

# New device, DNS around the router, gateway change

print("\nNew things and breaks")
t = ex._sql(NOW + timedelta(hours=1))
sql(("INSERT INTO findings (session_id, found_at, source, severity, "
     "entity_type, entity_value, title, detection_id) VALUES "
     "('t', ?, 'lan_live', 'high', 'ip', '172.21.0.99', 'New device', "
     "'LAN-1008')", (t,)))
sql(("INSERT INTO lan_flow (device_ip, device_mac, proto, dst, dport, "
     "first_seen, last_seen) VALUES ('172.21.0.11', 'aa:aa:aa:aa:aa:01', "
     "'udp', '8.8.8.8', 53, ?, ?)",
     (ex._iso(NOW + timedelta(hours=1)), ex._iso(NOW + timedelta(hours=1)))),
    ("INSERT INTO lan_flow (device_ip, proto, dst, dport, first_seen, "
     "last_seen) VALUES ('172.21.0.12', 'udp', '172.21.0.1', 53, ?, ?)",
     (ex._iso(NOW + timedelta(hours=1)), ex._iso(NOW + timedelta(hours=1)))))
ov = ex.check_once({}, live=FakeLive(), now=NOW + timedelta(hours=1, minutes=5))
k = by_kind(ov)
check("a new device turns head count new, not broken",
      k[("head_count", "")]["state"] == "new", k[("head_count", "")])
check("a device asking 8.8.8.8 itself breaks DNS through the router",
      k[("dns_via_router", "")]["state"] == "broken"
      and "8.8.8.8" in k[("dns_via_router", "")]["detail"],
      k[("dns_via_router", "")])
check("DNS to the router itself is not counted", "172.21.0.12" not in
      json.dumps(k[("dns_via_router", "")]["evidence"]))
sql(("INSERT INTO findings (session_id, found_at, source, severity, "
     "entity_type, entity_value, title, detection_id) VALUES "
     "('t', ?, 'lan_watch', 'high', 'ip', '172.21.0.1', "
     "'Gateway hardware address changed', 'LAN-1002')", (t,)))
ov = ex.check_once({}, live=FakeLive(), now=NOW + timedelta(hours=1, minutes=10))
check("a gateway change breaks same gateway",
      by_kind(ov)[("same_gateway", "")]["state"] == "broken")
check("marking the gateway break seen by kind",
      ex.acknowledge_kind("same_gateway",
                          now=NOW + timedelta(hours=1, minutes=11))["success"])
check("an unknown kind is not acknowledged",
      not ex.acknowledge_kind("no_such_kind")["success"])

# Quiet nights

print("\nQuiet nights")
local_tz = NOW.astimezone().tzinfo


def night(days_ago, mb):
    end = (NOW + timedelta(days=1)).astimezone(local_tz).replace(
        hour=6, minute=0, second=0, microsecond=0) - timedelta(days=days_ago)
    start = end.replace(hour=1)
    with me._get_conn() as conn:
        m = start
        per = int(mb * 1e6 / 300)
        while m < end:
            conn.execute("INSERT OR REPLACE INTO lan_traffic_minute (minute, ip, "
                         "up_bytes, down_bytes) VALUES (?, '172.21.0.10', ?, 0)",
                         (ex._iso(m), per))
            m += timedelta(minutes=1)
        conn.commit()


for d in range(1, 6):
    night(d, 20)
night(0, 25)
later = (NOW + timedelta(days=1)).astimezone(local_tz).replace(
    hour=9, minute=0, second=0, microsecond=0)
ov = ex.check_once({}, live=FakeLive(), now=later)
q = by_kind(ov)[("quiet_nights", "")]
check("a usual night holds", q["state"] == "holding", q)
night(0, 900)
ov = ex.check_once({}, live=FakeLive(), now=later + timedelta(minutes=5))
q = by_kind(ov)[("quiet_nights", "")]
check("900 MB against a usual 20 MB breaks it",
      q["state"] == "broken" and "900 MB" in q["detail"], q)

# Router coverage

print("\nWhen the router was not watched")
fresh = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
sql(("INSERT INTO sensor_gaps (sensor, reason, started_at, ended_at) "
     "VALUES ('lan_live', 'test', ?, NULL)",
     (ex._sql(fresh - timedelta(hours=20)),)))
ov = ex.check_once({}, live=FakeLive(), now=fresh)
check("most of the day unwatched reads uneasy",
      ov["mood"] in ("uneasy", "alarmed") and ov["coverage"] < 0.5,
      (ov["mood"], ov["coverage"]))
check("a check with no evidence and no watching is not called held",
      by_kind(ov)[("head_count", "")]["state"] == "unknown",
      by_kind(ov)[("head_count", "")])

# One device's contacts

print("\nOne device")
T = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)
sql(("INSERT INTO lan_flow (device_ip, device_mac, proto, dst, dport, "
     "dst_name, bytes_out, bytes_in, first_seen, last_seen) VALUES "
     "('172.21.0.30', 'aa:aa:aa:aa:aa:30', 'tcp', '198.51.100.20', 443, "
     "'updates.example', 1000, 5000, ?, ?)",
     (ex._iso(T - timedelta(days=3)), ex._iso(T - timedelta(hours=2)))),
    ("INSERT INTO lan_flow (device_ip, device_mac, proto, dst, dport, "
     "dst_name, bytes_out, bytes_in, first_seen, last_seen) VALUES "
     "('172.21.0.30', 'aa:aa:aa:aa:aa:30', 'tcp', '203.0.113.50', 443, "
     "'<b>odd.example</b>', 10, 10, ?, ?)",
     (ex._iso(T - timedelta(hours=1)), ex._iso(T - timedelta(minutes=50)))))
live = FakeLive(blocked=["aa:aa:aa:aa:aa:30"])
live.inventory["172.21.0.30"] = {"mac": "AA:AA:AA:AA:AA:30", "hostname": "tv"}
d = ex.device_detail("172.21.0.30", now=T, live=live)
check("the usual contact is on the inner list",
      [c["contact"] for c in d["usual"]] == ["updates.example"], d["usual"])
check("a contact first seen today is new",
      [c["contact"] for c in d["new"]] == ["<b>odd.example</b>"], d["new"])
check("a block by hardware address is shown", d["blocked"] is True)
check("the name comes from the router's list", d["name"] == "tv")
tv = d["ip"]
sql(("INSERT INTO known_devices (ip, mac, known_as, last_seen) VALUES "
     "(?, 'aa:aa:aa:aa:aa:30', 'Living room TV', ?)", (tv, ex._iso(T))),
    ("INSERT INTO known_devices (ip, mac, known_as, last_seen) VALUES "
     "('192.0.2.31', NULL, 'Office speaker', ?)", (ex._iso(T),)),
    ("INSERT INTO known_devices (ip, mac, known_as, last_seen, retired_at) "
     "VALUES ('192.0.2.99', '00:00:5e:00:53:32', 'Old name', ?, ?)",
     (ex._iso(T), ex._iso(T))))
live.inventory["192.0.2.31"] = {"mac": "00:00:5e:00:53:31"}
live.inventory["192.0.2.32"] = {"mac": "00:00:5e:00:53:32"}
d = ex.device_detail(tv, now=T, live=live)
check("the name given in the Network tab wins over the router's",
      d["name"] == "Living room TV", d["name"])
ring = {x["ip"]: x["name"] for x in ex._devices(live, [])}
check("the ring uses the given name too",
      ring.get(tv) == "Living room TV", ring)
check("a device the router has no hostname for is named by its address",
      ring.get("192.0.2.31") == "Office speaker", ring)
check("a retired name on a reused hardware address is not used",
      ring.get("192.0.2.32") == "192.0.2.32", ring)
d = ex.device_detail("172.21.0.30", now=T - timedelta(days=2, hours=23),
                     live=live)
check("under a day of watching, nothing is called new",
      d["learning"] and not d["new"], d)
check("a value that is not an address is refused",
      "error" in ex.device_detail("1.2.3.4' OR 1=1", live=live))

# Smart devices keep to their usual contacts

print("\nUsual contacts")
U = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
sql(("UPDATE sensor_gaps SET ended_at = ? WHERE ended_at IS NULL",
     (ex._sql(fresh),)))
sql(("INSERT INTO known_devices (ip, mac, known_as, device_type, last_seen) "
     "VALUES ('192.0.2.60', '00:00:5e:00:53:60', 'Doorbell', 'iot', ?)",
     (ex._iso(U),)),
    ("INSERT INTO known_devices (ip, device_type, last_seen) VALUES "
     "('192.0.2.61', 'printer', ?)", (ex._iso(U),)),
    ("INSERT INTO known_devices (ip, device_type, last_seen) VALUES "
     "('192.0.2.62', 'tv', ?)", (ex._iso(U),)))
for ip, name, first in (
        ("192.0.2.60", "api.doorbell.example", U - timedelta(days=5)),
        ("192.0.2.60", "eu.api.doorbell.example", U - timedelta(hours=2)),
        ("192.0.2.61", "ink.example", U - timedelta(hours=30)),
        ("192.0.2.62", "stream.example", U - timedelta(hours=1))):
    sql(("INSERT INTO lan_flow (device_ip, proto, dst, dport, dst_name, "
         "first_seen, last_seen) VALUES (?, 'tcp', '198.51.100.30', 443, ?, ?, ?)",
         (ip, name, ex._iso(first), ex._iso(first + timedelta(minutes=5)))),)
live = FakeLive()
live.inventory["192.0.2.60"] = {}
ov = ex.check_once({}, live=live, now=U)
u = by_kind(ov)[("usual_contacts", "")]
check("a new name under a known service is not new", u["state"] == "holding"
      and "1 device(s) kept" in u["detail"] and "1 still learning" in u["detail"],
      u)
check("a TV is left out by default", "192.0.2.62" not in json.dumps(u))
sql(("INSERT INTO lan_flow (device_ip, proto, dst, dport, dst_name, "
     "first_seen, last_seen) VALUES ('192.0.2.60', 'tcp', '203.0.113.80', 443, "
     "'odd-relay.example.net', ?, ?)",
     (ex._iso(U + timedelta(minutes=2)), ex._iso(U + timedelta(minutes=3)))))
ov = ex.check_once({}, live=live, now=U + timedelta(minutes=5))
u = by_kind(ov)[("usual_contacts", "")]
check("a service the doorbell never used is new, not broken",
      u["state"] == "new" and "Doorbell to example.net" in u["detail"], u)
check("the doorbell turns amber on the ring",
      {d["ip"]: d["state"] for d in ov["devices"]}.get("192.0.2.60") == "new",
      ov["devices"])
ov = ex.check_once({"expectations": {"simple_types": ["tv"]}}, live=live,
                   now=U + timedelta(minutes=10))
u = by_kind(ov)[("usual_contacts", "")]
check("TVs can be added in config", "1 still learning" in u["detail"]
      or "192.0.2.62" in json.dumps(u), u)

# False alarms per day

print("\nFalse alarms per day")
from core import incident  # noqa: E402
F = datetime.now(timezone.utc).replace(microsecond=0)


def add_incident(rule, entity, status="new", by="watcher"):
    with me._get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO incident (incident_key, detection_id, entity_type, "
            "entity_value, severity, title, first_seen_at, last_seen_at, "
            "status, status_at, status_by) VALUES (?, ?, 'ip', ?, 'medium', "
            "?, ?, ?, ?, ?, ?)",
            (f"{rule}:{entity}", rule, entity, f"{rule} on {entity}",
             ex._sql(F), ex._sql(F), status, ex._sql(F), by))
        conn.commit()
        return cur.lastrowid


def fire(rule, entity, when, n=1):
    with me._get_conn() as conn:
        for k in range(n):
            conn.execute(
                "INSERT INTO findings (session_id, found_at, source, severity, "
                "entity_type, entity_value, title, detection_id) VALUES "
                "('t', ?, 'test', 'medium', 'ip', ?, 'x', ?)",
                (ex._sql(when + timedelta(minutes=k)), entity, rule))
        conn.commit()


fed = add_incident("FED-1002", "203.0.113.70")
lan = add_incident("LNX-2007", "172.21.0.40")
fire("FED-1002", "203.0.113.70", F - timedelta(days=1), n=300)
fire("FED-1002", "203.0.113.70", F - timedelta(minutes=30))
fire("LNX-2007", "172.21.0.40", F - timedelta(minutes=20))
check("an unknown verdict is refused",
      not incident.set_verdict(fed, "benign")["success"])
check("the model needs the owner's words",
      not incident.set_verdict(fed, "false_alarm", by="model")["success"])
check("the owner's verdict is stored",
      incident.set_verdict(fed, "false_alarm", by="owner")["success"])
fa = ex.false_alarms(days=3, now=F)
today = fa["days"][-1]
check("one dot per incident per day, not per alert",
      len(fa["days"][-2]["dots"]) == 1 and len(today["dots"]) == 2,
      [len(d["dots"]) for d in fa["days"]])
check("the false alarm is counted on each day it fired",
      fa["days"][-2]["false_alarms"] == 1 and today["false_alarms"] == 1)
fed_row = next(r for r in fa["rules"] if r["rule"] == "FED-1002")
check("the rule totals count days, so FED leads",
      fa["rules"][0]["rule"] == "FED-1002" and fed_row["false_alarm"] == 2,
      fa["rules"])
check("the incident without a verdict is listed to label",
      [u["id"] for u in fa["unlabelled"]] == [lan], fa["unlabelled"])
check("the model records a verdict on the owner's word",
      incident.set_verdict(lan, "real", by="model",
                           note="that was my backup job")["success"])
fa = ex.false_alarms(days=3, now=F)
check("then nothing is left to label", fa["unlabelled_total"] == 0)
check("and who set it is kept", any(
    d["verdict_by"] == "model" for d in fa["days"][-1]["dots"]))

import sqlite3 as _sq  # noqa: E402
import tempfile  # noqa: E402
old_db = me.DB_PATH
me.DB_PATH = pathlib.Path(tempfile.mkdtemp()) / "old.db"
c = _sq.connect(me.DB_PATH)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.execute("INSERT INTO incident (incident_key, detection_id, entity_type, "
          "entity_value, severity, title, first_seen_at, last_seen_at, "
          "status, status_at, status_by, assessment) VALUES ('k1', 'FED-1003', "
          "'ip', '203.0.113.9', 'low', 't', '2026-10-01 00:00:00', "
          "'2026-10-01 00:00:00', 'dismissed', '2026-10-02 00:00:00', 'user', "
          "'a CDN, fine')")
c.execute("INSERT INTO incident (incident_key, detection_id, entity_type, "
          "entity_value, severity, title, first_seen_at, last_seen_at, "
          "status, status_at, status_by) VALUES ('k2', 'FED-1003', 'ip', "
          "'203.0.113.10', 'low', 't', '2026-10-01 00:00:00', "
          "'2026-10-01 00:00:00', 'dismissed', '2026-10-02 00:00:00', 'model')")
c.commit()
c.row_factory = _sq.Row
ex.ensure_tables(c)
c.commit()
got = {r["incident_key"]: (r["verdict"], r["verdict_by"]) for r in c.execute(
    "SELECT incident_key, verdict, verdict_by FROM incident")}
c.close()
me.DB_PATH = old_db
check("an owner's past dismissal carries over, marked as a dismissal",
      got["k1"] == ("false_alarm", "dismissal"), got)
check("a dismissal by the model does not become a verdict",
      got["k2"] == (None, None), got)

# History rows stay few

with me._get_conn() as conn:
    per = conn.execute("SELECT MAX(n) FROM (SELECT COUNT(*) AS n FROM "
                       "expectation_check GROUP BY expectation_id)"
                       ).fetchone()[0]
check("a check row is written on a change or once an hour, not every pass",
      per <= 12, per)

print(f"\n{'FAILED' if failures else 'ALL PASSED'}"
      f"{f': {len(failures)} check(s)' if failures else ''}")
sys.exit(1 if failures else 0)
