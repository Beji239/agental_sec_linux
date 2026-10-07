# tests/test_baseline_text.py
# The Behavioural tab in plain words, and baselines that learn by themselves.
#   1. every key the store accepts has a sentence template
#   2. the sentences read values the way they are stored, JSON included
#   3. a device whose hardware answers at a newer address is marked old
#   4. the app's own measurements become observations, and confidence grows
#      session by session through the real rollup

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

from core import auto_observe as ao                   # noqa: E402
from core import baseline_text as bt                  # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


print("[1] a template for every key")
missing = sorted(k for keys in me.VALID_BEHAVIOR_KEYS.values() for k in keys
                 if k not in bt.TEMPLATES)
check("no key without a sentence", missing, [])

print("[2] the sentences")
T = bt.TEMPLATES
check("hours become ranges", T["active_hours"]({}, ["8,9,10", "21"]),
      "is usually active at 8:00 to 10:59, 21:00")
check("a JSON list reads as a list", T["open_ports_inbound"]({}, ["[8008, 8009]"]),
      "usually accepts connections on port 8008, 8009")
check("a JSON object with a list reads as that list",
      T["typical_dest_ips"]({}, ['{"destinations": ["a.example", "b.example"]}']),
      "usually talks to a.example, b.example")
check("bytes are sized", T["volume_per_hour"]({}, ["3145728"]), "moves about 3.0 MB an hour")
check("long lists are cut with a count", T["typical_dest_ports"]({}, ["1,2,3,4,5,6,7"]),
      "usually talks to port 1, 2, 3, 4, 5 and 2 more")
check("an answer is quoted", T["operator_answer"]({}, ["it is my printer"]),
      "you told the app: it is my printer")

print("[3] names and old addresses")
mac = "00:00:5e:00:53:21"
me.save_known_device("192.0.2.30", mac=mac, hostname="printer-old")
me.save_known_device("192.0.2.31", mac=mac, hostname="printer")
with me._get_conn() as conn:
    conn.execute("UPDATE known_devices SET last_seen = '2026-01-01 00:00:00' WHERE ip = '192.0.2.30'")
    conn.execute("UPDATE known_devices SET last_seen = '2026-10-01 00:00:00' WHERE ip = '192.0.2.31'")
rows = bt.describe_all([
    {"entity_type": "ip", "entity_value": "192.0.2.30", "behavior_key": "first_seen",
     "sample_count": 1, "confidence": "low", "model_notes": "Rollup [x] noise"},
    {"entity_type": "ip", "entity_value": "192.0.2.31", "behavior_key": "first_seen",
     "sample_count": 3, "confidence": "low", "model_notes": "A printer, says the owner."}])
check("the older address is marked old", (rows[0]["stale"], rows[0]["display_name"]),
      (True, "printer-old (192.0.2.30) (old address)"))
check("the current one is not", (rows[1]["stale"], rows[1]["display_name"]),
      (False, "printer (192.0.2.31)"))
check("progress is sessions seen of those needed", rows[1]["progress"]["seen"], 3)
check("rollup bookkeeping is not shown as a note", rows[0]["agent_note"], None)
check("a real note is", rows[1]["agent_note"], "A printer, says the owner.")
check("an unknown key has no made-up sentence",
      bt.describe_all([{"entity_type": "ip", "entity_value": "192.0.2.9",
                        "behavior_key": "not_a_key"}])[0]["summary"], None)

print("[4] the app's measurements teach the baseline")
from core import rollup_engine as re_                 # noqa: E402
import ipaddress                                      # noqa: E402
# The test devices use a documentation range; count it as the home network.
ao._LAN.append(ipaddress.ip_network("192.0.2.0/24"))
now = datetime.now(timezone.utc)
dev = "192.0.2.40"
with me._get_conn() as conn:
    for k in range(1, 40):
        m = (now - timedelta(minutes=k)).strftime("%Y-%m-%dT%H:%M:00+00:00")
        conn.execute("INSERT INTO lan_traffic_minute(minute, ip, up_bytes, down_bytes) "
                     "VALUES(?,?,?,?)", (m, dev, 1000, 5000))
    conn.execute("INSERT INTO lan_flow(device_ip, device_mac, proto, dst, dport, dst_name, "
                 "bytes_out, bytes_in, first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?,?,?)",
                 (dev, None, "tcp", "198.51.100.5", 443, "updates.example", 900, 9000,
                  now.isoformat(), now.isoformat()))
out = ao.observe("sess-1")
check("observations were written", out["written"] > 0, True)
with me._get_conn() as conn:
    got = {r[0]: (r[1], r[2], r[3]) for r in conn.execute(
        "SELECT behavior_key, behavior_value, written_by, basis FROM behavioral_session "
        "WHERE entity_value = ? AND session_id = 'sess-1'", (dev,))}
check("the device's keys", sorted(got),
      ["active_hours", "connection_count", "typical_dest_ips", "typical_dest_ports", "volume_per_hour"])
check("marked as the app's own measurement", got["typical_dest_ports"][1:], ("system", "measured"))
check("the destination by name", got["typical_dest_ips"][0], "updates.example")
with me._get_conn() as conn:
    n_proc = conn.execute("SELECT COUNT(*) FROM behavioral_session WHERE entity_type = 'process' "
                          "AND written_by = 'system'").fetchone()[0]
check("this host's programs are observed too", n_proc > 0, True)
again = ao.observe("sess-1")
with me._get_conn() as conn:
    n_dev = conn.execute("SELECT COUNT(*) FROM behavioral_session WHERE entity_value = ? "
                         "AND session_id = 'sess-1' AND behavior_key = 'typical_dest_ports'",
                         (dev,)).fetchone()[0]
check("an unchanged value is not written twice in a session", n_dev, 1)

levels = []
for i in range(1, 6):
    sid = f"sess-{i}"
    ao.observe(sid)
    re_.run_rollup(sid, trigger_reason="manual")
    row = me.query_behavioral_baseline(entity_type="ip", entity_value=dev,
                                       behavior_key="typical_dest_ports")
    levels.append((row[0]["sample_count"], row[0]["confidence"]) if row else None)
check("confidence grows with each session", [l[1] for l in levels],
      ["low", "low", "low", "medium", "medium"])
check("sessions are counted", levels[-1][0], 5)
s = bt.describe_all(me.query_behavioral_baseline(entity_type="ip", entity_value=dev,
                                                 behavior_key="typical_dest_ports"))[0]
check("and the tab says it in words", s["summary"], "usually talks to port 443")

print()
print("ALL CHECKS PASSED" if not fails else f"FAILED: {fails}")
sys.exit(1 if fails else 0)
