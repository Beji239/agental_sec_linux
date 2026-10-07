"""
tests/test_place_map.py, the Threat Map upgrade.

Covers the shared place picture (this machine plus router flows, and this
machine alone when there is no router), the place learner and its learning
period, the wake summary, separate chat threads, and the page wiring.
"""
import asyncio
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

from core import geoip, place_map                     # noqa: E402
from tools import place_watch                         # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, cond):
    check(label, bool(cond), True)


# Public resolver addresses stand in for destinations; LAN values are made up.
GEO = {
    "8.8.8.8": {"lat": 37.4, "lon": -122.1, "city": "Mountain View",
                "region": "California", "country": "United States",
                "country_code": "US"},
    "1.1.1.1": {"lat": -33.9, "lon": 151.2, "city": "Sydney",
                "region": "New South Wales", "country": "Australia",
                "country_code": "AU"},
    "9.9.9.9": {"lat": 47.4, "lon": 8.5, "city": "Zurich", "region": "Zurich",
                "country": "Switzerland", "country_code": "CH"},
}
ASN = {"8.8.8.8": {"asn": "AS64500", "org": "Example One"},
       "1.1.1.1": {"asn": "AS64501", "org": "Example Two"},
       "9.9.9.9": {"asn": "AS64502", "org": "Example Three"}}
geoip.lookup = lambda ip: GEO.get(ip)
geoip.asn_lookup = lambda ip: ASN.get(ip)
geoip.asn_status = lambda: {"ready": True, "status": "ready"}
place_map.own_addresses = lambda: {"192.0.2.5"}
place_map.CACHE_SECONDS = 0      # data is added between calls here

SID = "test-session"
DEV_IP, DEV_MAC = "192.0.2.20", "00:00:5e:00:53:20"


def add_packet(src, dst, proc=None, size=100, when=None):
    with me._get_conn() as c:
        c.execute("INSERT INTO packets (session_id, captured_at, src_ip, dst_ip, "
                  "src_port, dst_port, protocol, packet_size, process_name) "
                  "VALUES (?,?,?,?,?,?,?,?,?)",
                  (SID, when or datetime.now(timezone.utc).strftime(
                      "%Y-%m-%d %H:%M:%S"), src, dst, 50000, 443, "tcp", size,
                   proc))


def add_flow(device_ip, mac, dst, out_b=1000, in_b=5000, name=None):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    with me._get_conn() as c:
        c.execute("INSERT INTO lan_flow (device_ip, device_mac, proto, dst, "
                  "dport, dst_name, bytes_out, bytes_in, packets_out, "
                  "packets_in, first_seen, last_seen) "
                  "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                  (device_ip, mac, "tcp", dst, 443, name, out_b, in_b, 3, 7,
                   now, now))


print("\n[1] This machine only, no router data")
add_packet("192.0.2.5", "8.8.8.8", proc="browser")
add_packet("8.8.8.8", "192.0.2.5", proc="browser")
g = place_map.gather(session_id=SID)
check("one endpoint", sorted(g["endpoints"]), ["8.8.8.8"])
check("router reported unavailable", g["router"]["available"], False)
check_true("with a reason", "router" in (g["router"]["reason"] or "").lower())
w = place_map.who(g["endpoints"]["8.8.8.8"])
check("the program is named", [p["name"] for p in w["processes"]], ["browser"])
check("seen from this machine", w["sources"], ["this_machine"])

print("\n[2] Router flows join the map, named by device")
with me._get_conn() as c:
    c.execute("INSERT INTO known_devices (ip, mac, known_as, first_seen, "
              "last_seen) VALUES (?,?,?,datetime('now'),datetime('now'))",
              (DEV_IP, DEV_MAC, "Test console"))
add_flow(DEV_IP, DEV_MAC, "1.1.1.1", name="cdn.example.")
add_flow("192.0.2.5", "00:00:5e:00:53:05", "9.9.9.9")
g = place_map.gather(session_id=SID)
check("router endpoint added", "1.1.1.1" in g["endpoints"], True)
check("this machine's own router rows are not double counted",
      "9.9.9.9" in g["endpoints"], False)
w = place_map.who(g["endpoints"]["1.1.1.1"])
check("device named", [d["name"] for d in w["devices"]], ["Test console"])
check("name from the router log", w["names"], ["cdn.example"])
check("router available", g["router"]["available"], True)

print("\n[3] One point for the side panel")
p = place_map.point("1.1.1.1", session_id=SID)
check("place", p["place"], "Sydney, New South Wales, Australia")
check("device listed", [d["mac"] for d in p["devices"]], [DEV_MAC])
check("findings read", p["findings_read"], True)
ctx = place_map.context_for_chat("1.1.1.1", session_id=SID)
check_true("chat context names the device", "Test console" in ctx)
check_true("and says no alerts", "No alerts" in ctx)

print("\n[4] The place learner and its learning period")
pw = place_watch.PlaceWatch({"place_watch": {"learn_hours": 72}}, SID)
r1 = pw.learn_once()
check("first pass learns", r1["ran"], True)
with me._get_readonly_conn() as c:
    subjects = {(x[0], x[1]) for x in c.execute(
        "SELECT subject_type, subject FROM place_baseline")}
check_true("program learned", ("program", "browser") in subjects)
check_true("device learned by hardware address", ("device", DEV_MAC) in subjects)
check("no alerts during learning", r1["alerts"], 0)

# Move every subject's first sighting back past the learning period.
old = (datetime.now(timezone.utc) - timedelta(hours=100)).strftime(
    "%Y-%m-%dT%H:%M:%S+00:00")
with me._get_conn() as c:
    c.execute("UPDATE place_baseline SET first_seen = ?", (old,))
add_packet("192.0.2.5", "9.9.9.9", proc="browser")
r2 = pw.learn_once()
check("a new country after learning raises", r2["alerts"], 2)
rows = me.query_findings(entity_type="ip", entity_value="9.9.9.9", limit=10)
dids = sorted(f["detection_id"] for f in rows)
check("country and network rules", dids, ["GEO-1001", "GEO-1002"])
sev = {f["detection_id"]: f["severity"] for f in rows}
check("medium when nothing in the home reached that country",
      sev["GEO-1001"], "medium")
r3 = pw.learn_once()
check("a known place does not raise again", r3["alerts"], 0)

new_sub = place_watch.PlaceWatch({}, SID)
add_packet("192.0.2.5", "1.1.1.1", proc="newtool")
r4 = new_sub.learn_once()
check("a brand new program only learns", r4["alerts"], 0)
check_true("places_for lists them",
           place_watch.places_for("browser")["places"])

print("\n[4b] The hourly tally keeps this machine on the map across a restart")
with me._get_readonly_conn() as c:
    tallied = {r[0] for r in c.execute("SELECT remote_ip FROM place_traffic")}
check_true("the learner tallied this machine's destinations",
           {"8.8.8.8", "9.9.9.9"} <= tallied)
g = place_map.gather(session_id="a-new-run-with-no-packets")
check_true("a new run still shows this machine's destinations",
           "8.8.8.8" in g["endpoints"])
check("and says what it covers", g["this_machine_covers"], "the last 24 hours")
check("the program is still named",
      [p["name"] for p in place_map.who(g["endpoints"]["8.8.8.8"])["processes"]],
      ["browser"])
def _tallied(ip):
    with me._get_readonly_conn() as c:
        return c.execute("SELECT COALESCE(SUM(packets), 0) FROM place_traffic "
                         "WHERE remote_ip = ?", (ip,)).fetchone()[0]


before = _tallied("8.8.8.8")
pw.learn_once()
after = _tallied("8.8.8.8")
check("a pass with nothing new does not count packets twice", after, before)
p8 = place_map.point("8.8.8.8", session_id="a-new-run-with-no-packets")
check("the panel names the program from the tally",
      [x["name"] for x in p8["processes"]], ["browser"])

print("\n[5] The wake summary")
d = place_map.digest(since=old, session_id=SID)
check_true("names new places", "New places since the last wake" in d)
check_true("lists endpoints with an alert", "Endpoints with an alert" in d)
check_true("lists the biggest", "Biggest by data" in d)
from core import duty                                 # noqa: E402
check_true("duty builds a map block", "THREAT MAP SUMMARY"
           in duty.build_map_block(SID))
check_true("the duty loop may read the summary",
           "query_map_summary" in duty.DUTY_TOOL_ALLOWLIST)

print("\n[6] Side chat threads keep their own history")
from core import agent_loop                           # noqa: E402


async def _fake_turn(msg):
    agent_loop._history.append({"role": "user", "content": msg})
    agent_loop._history.append({"role": "assistant", "content": "ok"})
    yield "ok"

agent_loop._run_turn = _fake_turn
agent_loop._history[:] = [{"role": "user", "content": "main"}]


async def _drain(gen):
    return [t async for t in gen]

asyncio.run(_drain(agent_loop.run("about the map", thread="map:1.1.1.1")))
check("main history untouched", [m["content"] for m in agent_loop._history],
      ["main"])
check("thread kept", agent_loop.thread_exists("map:1.1.1.1"), True)
asyncio.run(_drain(agent_loop.run("second", thread="map:1.1.1.1")))
check("thread grows", len(agent_loop._threads["map:1.1.1.1"]), 4)

print("\n[7] Wiring")
ROUTES = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")
UI = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
for route in ("/api/map/point", "/api/map/block", "/api/map/unblock",
              "/api/map/sinkhole", "/api/map/unsinkhole"):
    check_true(f"route {route}", f'"{route}"' in ROUTES)
check_true("chat accepts a map address", 'data.get("map_ip")' in ROUTES)
check_true("map context is fenced", "sanitize.fence(" in ROUTES)
for fn in ("openMapPanel", "openMapChat", "mapChatSend", "mapBlock",
           "mapSinkhole", "mapCutDevice", "_mapChatDragSetup"):
    check_true(f"page has {fn}", f"function {fn}(" in UI)
check_true("chat window is resizable", "resize: both" in UI)
check_true("the map picture is cached", "CACHE_SECONDS" in
           (ROOT / "core" / "place_map.py").read_text(encoding="utf-8"))
check_true("approval cards render in the side chat",
           "renderPermissionCard(body, JSON.parse(raw[1]))" in UI)

print("\n" + ("ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}"))
sys.exit(1 if fails else 0)
