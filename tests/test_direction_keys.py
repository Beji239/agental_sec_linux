"""
tests/test_direction_keys.py, do the packets back the role the key asserts?

Written 2026-08-29, the same night as test_icmp_routing.py and for the
second half of the same failure.

The sensor's part was fixed there. This is the model's part: it filed two
addresses under `beacon_destinations`, a key meaning "the places this host
reaches out to". Both addresses were SOURCES of inbound multicast. Nothing
here had ever connected to either. VALID_BEHAVIOR_KEYS accepted it because
the key is spellable for an ip, which is the only question it asks.

What is tested here is that the packet record now gets consulted, that its
answer has THREE outcomes rather than two, and, the part that matters
most, that a write is never refused on the strength of it.
"""
import sys, sqlite3, tempfile, pathlib, json

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []
def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)

tmp = pathlib.Path(tempfile.mkdtemp())
db  = tmp / "t.db"

from core import memory_engine as me
me.DB_PATH = db
c = sqlite3.connect(db)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.commit(); c.close()
from core import migrations; migrations.run_migrations(db)
from core import sensors as sn; sn.register_local()

SID = "test-session"

# A host that only ever SENDS to us (the shape of the real packets: inbound
# multicast advertisements), and a host we genuinely reach out to.
with sqlite3.connect(db) as c:
    for _ in range(18):
        c.execute("""INSERT INTO packets(session_id,src_ip,dst_ip,protocol,direction,scope)
                     VALUES(?,'100.64.100.100','224.0.0.1','ICMP','inbound',
                            'foreign_multicast')""", (SID,))
    for _ in range(5):
        c.execute("""INSERT INTO packets(session_id,src_ip,dst_ip,protocol,direction,scope)
                     VALUES(?,'192.0.2.50','100.64.9.9','TCP','outbound','outbound')""",
                  (SID,))


print("\n[1] a key that asserts nothing is not second-guessed")
check("neutral key", me.corroborate_direction("ip", "192.0.2.50",
                                              "active_hours"), None)
check("non-ip entity", me.corroborate_direction("process", "svchost.exe",
                                                "typical_parent"), None)
check("beacon_destinations IS directional",
      me.DIRECTIONAL_KEYS.get("beacon_destinations"), "destination")


print("\n[2] a real destination is corroborated")
r = me.corroborate_direction("ip", "100.64.9.9", "beacon_destinations")
check("status", r["status"], "corroborated")
check("counted as destination", r["as_destination"], 5)
check("and never as a source here", r["as_source"], 0)


print("\n[3] the exact 2026-08-28 shape: a SOURCE filed as a destination")
r = me.corroborate_direction("ip", "100.64.100.100", "beacon_destinations")
check("status", r["status"], "contradicted")
check("18 packets, all inbound", r["as_source"], 18)
check("zero as a destination", r["as_destination"], 0)
assert "not proof it was never" in r["note"], r["note"]
print("       and the note refuses to say 'never', only 'nothing kept says so'")
check("the window it covers is reported",
      isinstance(r["retained_since"], str), True)


print("\n[4] no evidence is its own answer, not a quiet pass")
r = me.corroborate_direction("ip", "100.64.7.7", "beacon_destinations")
check("status", r["status"], "no_evidence_retained")
check("not corroborated", r["status"] == "corroborated", False)
check("not contradicted either", r["status"] == "contradicted", False)
assert "not\n" not in r["note"]
assert "wrong OR right" in r["note"], r["note"]
print("       absence is named as a gap in the record, in both directions")


print("\n[5] THE WRITE IS NEVER REFUSED, only reported on")
# The whole design turns on this. A refusal would cost a true fact whenever
# the sniffer was off, which on a homelab is most of the time.
res = me.write_behavioral_observation(
    entity_type="ip", entity_value="100.64.100.100",
    behavior_key="beacon_destinations", behavior_value='["224.0.0.1"]',
    session_id=SID, context="the exact bad write from that night")
check("the write succeeded", res["success"], True)
check("and it carries the contradiction back",
      res["direction_check"]["status"], "contradicted")
check("the row really is in the table",
      len(me.query_behavioral_session(entity_value="100.64.100.100")) > 0, True)

res2 = me.write_deviation(
    entity_type="ip", entity_value="100.64.100.100",
    behavior_key="beacon_destinations", session_id=SID,
    expected_value="none", observed_value="multicast advertisements",
    deviation_score=0.6, model_assessment="test", action_taken="logged")
check("write_deviation succeeds too", res2["success"], True)
check("and reports the same contradiction",
      res2["direction_check"]["status"], "contradicted")

res3 = me.update_behavioral_baseline(
    entity_type="ip", entity_value="100.64.100.100",
    behavior_key="beacon_destinations", session_id=SID,
    sample_count=18, confidence="low")
check("baseline write succeeds", res3["success"], True)
check("and reports it", res3["direction_check"]["status"], "contradicted")

# A neutral key gets no annotation at all, no noise where there is no claim.
res4 = me.write_behavioral_observation(
    entity_type="ip", entity_value="100.64.100.100",
    behavior_key="active_hours", behavior_value="[1,2]", session_id=SID)
check("neutral write is not annotated", "direction_check" in res4, False)


print("\n[6] the annotation travels to whoever READS the baseline")
# A write-time warning nobody sees again is worthless: the next session
# inherits the row, not the response.
rows = me.query_behavioral_baseline(entity_type="ip",
                                    entity_value="100.64.100.100")
check("the baseline row is there", len(rows), 1)
check("and carries its corroboration",
      rows[0]["direction_check"]["status"], "contradicted")
check("with the counts attached, not just a word",
      (rows[0]["direction_check"]["as_source"],
       rows[0]["direction_check"]["as_destination"]), (18, 0))

me.update_behavioral_baseline(entity_type="ip", entity_value="100.64.9.9",
                              behavior_key="beacon_destinations",
                              session_id=SID, sample_count=5)
good = [r for r in me.query_behavioral_baseline(entity_value="100.64.9.9")]
check("a legitimate destination reads as corroborated",
      good[0]["direction_check"]["status"], "corroborated")

me.update_behavioral_baseline(entity_type="ip", entity_value="192.0.2.50",
                              behavior_key="active_hours", session_id=SID)
neutral = me.query_behavioral_baseline(entity_value="192.0.2.50")
check("and a neutral key stays unannotated on read",
      "direction_check" in neutral[0], False)


print("\n[7] it reads through the READ-ONLY handle, like every other read")
src = (ROOT / "core" / "memory_engine.py").read_text(encoding="utf-8")
start = src.index("def corroborate_direction(")
body  = src[start:src.find("\ndef ", start + 1)]
check("uses _get_readonly_conn", "_get_readonly_conn()" in body, True)
check("and does not open a writable one", "_get_conn()" in body, False)


print("\n[8] the answer moves with retention, and says what window it saw")
# The design point that unblocked this: the check reports counts and a
# window rather than the verdict 'never a destination', which pruning makes
# unanswerable. Prune the evidence and the status degrades honestly to
# no_evidence_retained instead of silently becoming a wrong 'contradicted'.
before = me.corroborate_direction("ip", "100.64.100.100", "beacon_destinations")
with sqlite3.connect(db) as c:
    c.execute("DELETE FROM packets WHERE src_ip = '100.64.100.100'")
after = me.corroborate_direction("ip", "100.64.100.100", "beacon_destinations")
check("was contradicted while the packets existed", before["status"], "contradicted")
check("degrades to no_evidence_retained once pruned",
      after["status"], "no_evidence_retained")
check("it does NOT keep asserting a contradiction it can no longer support",
      after["status"] == "contradicted", False)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
