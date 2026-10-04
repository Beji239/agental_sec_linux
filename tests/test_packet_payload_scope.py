"""
tests/test_packet_payload_scope.py, payloads only ride along when flagged.

WHAT THIS IS ABOUT

query_packets was SELECT *, so every row handed the model up to 512
characters of hex payload. Ask for 100 packets and that is roughly 50 KB of
hex in the context, on every call, and hex is close to useless to the model
anyway. It is a token bill nobody was looking at.

It is also mostly pointless. The signature checks run on the LIVE bytes at
capture time, so a payload that mattered already carries a threat_label by
the time the row exists.

2026-09-01, LATER THE SAME DAY. The measurement happened, so this file now
covers the STORAGE side too. scripts/db_breakdown.py on the real 1.6 GB
database: payload_snippet was 566.7 MB on 1,304,740 rows, 242 of them
flagged. raw_summary was another 124.0 MB with no reader at all. save_packet
stopped writing both.

The checks:
  a flagged row still carries its payload, because that is when you want one
  an unflagged row does not, on disk OR on the way out
  a row written BEFORE today still has its payload, and the read still hides
    it, which is the only reason the CASE in query_packets still exists
  save_packet will not accept raw_summary at all any more
  every field anyone actually reasons from is still returned
  the model is TOLD that a null payload means unflagged, not unavailable
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


tmp = pathlib.Path(tempfile.mkdtemp())
db = tmp / "t.db"

from core import memory_engine as me       # noqa: E402
me.DB_PATH = db

c = sqlite3.connect(db)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.commit()
c.close()

from core import migrations                # noqa: E402
migrations.run_migrations(db)
from core import sensors as sn             # noqa: E402
sn.register_local()

SID = "payload-session"
HEX = "de" * 256          # 512 characters, the real worst case


def save(dst, threat=None):
    me.save_packet(session_id=SID, src_ip="192.0.2.5", dst_ip=dst,
                   src_port=51000, dst_port=443, protocol="TCP",
                   direction="outbound", scope="outbound", packet_size=1200,
                   flags={"S": True}, payload_snippet=HEX,
                   threat_label=threat)


save("192.0.2.10")                       # ordinary
save("192.0.2.11", threat="sqli")        # flagged


print("\n[1] the payload is not even STORED on an unflagged row")
# This is the half that changed on 2026-09-01. save_packet was handed a
# payload for BOTH rows above, exactly as the sniffer used to, and it is
# supposed to drop the one that carries no threat_label.
with sqlite3.connect(db) as conn:
    stored = conn.execute(
        "SELECT COUNT(*) FROM packets WHERE payload_snippet IS NOT NULL"
    ).fetchone()[0]
check("only the flagged row has a payload on disk", stored, 1)


print("\n[1b] save_packet will not take a raw_summary at all")
# The parameter is gone, not ignored. A caller still passing one is a caller
# that has not been updated, and it should fail where it is rather than
# quietly write 124 MB nobody reads.
try:
    me.save_packet(session_id=SID, src_ip="192.0.2.5", dst_ip="192.0.2.99",
                   raw_summary="IP / TCP 192.0.2.5 > x")
    check("it rejects raw_summary", "accepted it", "TypeError")
except TypeError:
    check("it rejects raw_summary", "TypeError", "TypeError")


rows = {r["dst_ip"]: r for r in me.query_packets(session_id=SID, limit=10)}
check("both rows come back", len(rows), 2)


print("\n[2] THE POINT: the flagged row keeps its payload, the other does not")
check("flagged row carries the payload",
      rows["192.0.2.11"].get("payload_snippet"), HEX)
check("unflagged row does not", rows["192.0.2.10"].get("payload_snippet"), None)
# The key must still be PRESENT and null, not absent. A missing key reads as
# "this tool does not have payloads", which is a different claim.
check("the key is present, just null",
      "payload_snippet" in rows["192.0.2.10"], True)


print("\n[2b] a row written BEFORE today still has a payload, and the read"
      " still hides it")
# Every one of the 1.3 million rows already on disk was written by the old
# save_packet and still carries its payload until
# scripts/reclaim_packet_space.py has been run. That is the ONLY reason the
# CASE in query_packets still exists now that the writer drops them too.
# Written straight through sqlite3 on purpose, because save_packet is exactly
# the thing that will no longer let this happen.
with sqlite3.connect(db) as conn:
    conn.execute(
        "INSERT INTO packets (session_id, src_ip, dst_ip, protocol, "
        "direction, scope, payload_snippet, threat_label) "
        "VALUES (?,?,?,?,?,?,?,NULL)",
        (SID, "192.0.2.5", "192.0.2.12", "TCP", "outbound", "outbound", HEX))
    conn.commit()
    legacy_on_disk = conn.execute(
        "SELECT payload_snippet FROM packets WHERE dst_ip='192.0.2.12'"
    ).fetchone()[0]
check("the legacy row really does have one on disk", legacy_on_disk, HEX)

legacy = {r["dst_ip"]: r
          for r in me.query_packets(session_id=SID, limit=10)}["192.0.2.12"]
check("but the model never sees it", legacy.get("payload_snippet"), None)


print("\n[3] nothing anyone reasons from was dropped along with it")
# The risk of moving off SELECT * is quietly losing a column something
# depends on. Named one by one rather than trusting the change.
must_have = ["id", "session_id", "captured_at", "src_ip", "dst_ip",
             "src_port", "dst_port", "protocol", "direction", "scope",
             "packet_size", "flags", "threat_label", "vpn_state", "sensor_id"]
missing = [k for k in must_have if k not in rows["192.0.2.10"]]
check("every meaningful column is still returned", missing, [])
check("sensor_id survives, so vantage point still works",
      bool(rows["192.0.2.10"].get("sensor_id")), True)


print("\n[4] raw_summary is gone entirely")
# It is a scapy one-liner rebuilt from fields the row already carries
# separately, so it was pure duplication in the context window.
check("raw_summary not returned",
      "raw_summary" in rows["192.0.2.11"], False)


print("\n[5] the filters still work, this was a column change not a query one")
only = me.query_packets(session_id=SID, dst_ip="192.0.2.11", limit=10)
check("dst_ip filter still narrows", len(only), 1)
check("and it is the right row", only[0]["dst_ip"], "192.0.2.11")
check("port filter still works",
      len(me.query_packets(session_id=SID, port=443, limit=10)), 2)
check("a port nothing used returns nothing",
      len(me.query_packets(session_id=SID, port=9999, limit=10)), 0)


print("\n[6] the model is TOLD what a null payload means")
# 27.3's lesson. A rule the code follows and the description does not mention
# is a rule the model will break, and here it would break it by treating a
# missing payload as evidence.
from core import tool_registry as tr        # noqa: E402
desc = {t["name"]: t for t in tr.TOOL_MANIFEST}["query_packets"]["description"]
check("it says payloads come back only on flagged rows",
      "ONLY ON FLAGGED ROWS" in desc, True)
check("and that null means unflagged, not unavailable",
      "NOTHING WAS FLAGGED ON THAT ROW" in desc, True)
check("and tells it not to re-query hoping for one",
      "the answer will be the same" in desc, True)


print("\n[7] no SELECT * left on the packets table")
src = (ROOT / "core" / "memory_engine.py").read_text(encoding="utf-8")
check("the query names its columns",
      "SELECT * FROM packets" in src, False)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
