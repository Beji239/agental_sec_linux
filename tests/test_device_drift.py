"""
tests/test_device_drift.py, device permanence and enrollment drift.

Weighted towards what this must REFUSE to claim. A drift check that reports
every device as unchanged passes any positive test ever written; the value is
in the cases where it declines to answer.
"""
import sys, json, tempfile, sqlite3, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

tmp = tempfile.mkdtemp()
db  = pathlib.Path(tmp) / "t.db"

from core import memory_engine as me
me.DB_PATH = db

schema = (ROOT / 'Schema.SQL').read_text(encoding='utf-8')
c = sqlite3.connect(db); c.executescript(schema); c.commit(); c.close()

from core import migrations
r1 = migrations.run_migrations(db)
r2 = migrations.run_migrations(db)
print(f"migration pass 1: {r1.get('status')}  pass 2: {r2.get('status')}")

from core import sensors as sn
sn.register_local()

fails = []
def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)

SID = "test-session"

print("\n[1] the locally-administered bit, by construction not by guess")
# Bit 1 of the first octet. 0x02, 0x06, 0x0a, 0x0e ... are locally assigned.
check("burned-in b8:27:eb (Raspberry Pi)", me.is_randomized_mac("b8:27:eb:11:22:33"), False)
check("burned-in 44:27:45 (LG)",           me.is_randomized_mac("44:27:45:11:22:33"), False)
check("randomized 02:...",                 me.is_randomized_mac("02:1a:2b:3c:4d:5e"), True)
check("randomized 8e:... (0x8e & 2)",      me.is_randomized_mac("8e:1a:2b:3c:4d:5e"), True)
check("dash-separated randomized",         me.is_randomized_mac("06-1a-2b-3c-4d-5e"), True)
check("absent address does not guess",     me.is_randomized_mac(""), False)
check("unparseable does not guess",        me.is_randomized_mac("not-a-mac"), False)

print("\n[2] a device must be seen before it can be vouched for")
r = me.set_device_permanence("198.51.100.99", True)
check("refused", r["success"], False)

print("\n[3] a randomized address cannot be marked permanent")
me.save_known_device(ip="198.51.100.50", mac="02:1a:2b:3c:4d:5e", hostname="phone")
r = me.set_device_permanence("198.51.100.50", True)
check("refused", r["success"], False)
check("reason given", r.get("randomized_mac"), True)
rows = me.query_known_devices(ip="198.51.100.50")
check("flag not set anyway", rows[0]["is_permanent"], 0)

print("\n[4] permanent, but never port scanned: silence is not a clean host")
me.save_known_device(ip="198.51.100.10", mac="b8:27:eb:11:22:33",
                     vendor="Raspberry Pi", hostname="printer")
r = me.set_device_permanence("198.51.100.10", True)
check("accepted", r["success"], True)
fp = json.loads(me.query_known_devices(ip="198.51.100.10")[0]["enrollment_fingerprint"])
check("scanned recorded as False", fp["ports_observed"]["scanned"], False)

d = me.query_device_drift(ip="198.51.100.10")["devices"][0]
check("compared", d["comparable"], True)
check("ports NOT compared", d["ports_comparable"], False)
check("no change asserted", d["changes"], [])
assert d["ports_note"] and "no port scan" in d["ports_note"], d["ports_note"]
print("       ports_note explains why, rather than reporting zero open ports")

print("\n[5] permanent with a real baseline, then a port opens")
me.save_known_device(ip="198.51.100.20", mac="44:27:45:11:22:33",
                     vendor="LG Electronics", hostname="tv")
for p in (80, 443):
    me.save_port_scan_result(session_id=SID, target_host="198.51.100.20",
                             port=p, state="open", risk_level="low")
r = me.set_device_permanence("198.51.100.20", True)
check("accepted", r["success"], True)

d = me.query_device_drift(ip="198.51.100.20")["devices"][0]
check("baseline compares clean", d["changes"], [])
check("ports comparable now", d["ports_comparable"], True)

# 23/telnet appears after enrollment.
me.save_port_scan_result(session_id=SID, target_host="198.51.100.20",
                         port=23, state="open", risk_level="high")
d = me.query_device_drift(ip="198.51.100.20")["devices"][0]
check("drift detected", any("ports opened" in c and "23" in c for c in d["changes"]), True)
print(f"       {d['changes']}")

print("\n[6] the same address wearing a different hardware address")
me.save_known_device(ip="198.51.100.20", mac="fc:65:de:99:88:77")
d = me.query_device_drift(ip="198.51.100.20")["devices"][0]
check("mac change reported", any("mac changed" in c for c in d["changes"]), True)

print("\n[7] permanent with no baseline reads as 'not compared', never 'no drift'")
with me._get_conn() as conn:
    conn.execute("UPDATE known_devices SET is_permanent = 1, "
                 "enrollment_fingerprint = NULL WHERE ip = ?", ("198.51.100.10",))
res = me.query_device_drift(ip="198.51.100.10")
check("comparable false", res["devices"][0]["comparable"], False)
check("counted as changed? no", res["devices_changed"], 0)
assert "absence of a baseline" in res["note"], res["note"]
print("       note distinguishes no baseline from no drift")

print("\n[8] un-vouching keeps the baseline")
before = me.query_known_devices(ip="198.51.100.20")[0]["enrollment_fingerprint"]
me.set_device_permanence("198.51.100.20", False)
row = me.query_known_devices(ip="198.51.100.20")[0]
check("flag cleared", row["is_permanent"], 0)
check("fingerprint retained", row["enrollment_fingerprint"], before)

print("\n[9] nothing in the model's manifest can set permanence")
from core import tool_registry as tr
names = [t["name"] for t in tr.TOOL_MANIFEST]
check("no permanence tool in manifest",
      [n for n in names if "permanen" in n.lower() or "vouch" in n.lower()], [])
out = tr.execute_tool("set_device_permanence", {"ip": "198.51.100.10", "is_permanent": True})
# UPDATED 2026-08-29, item 1.8 fixed. This used to assert the old shape: the
# refusal lived inside result while the envelope's own error stayed None, so
# a caller testing out["error"] read an unknown tool as a success. The note
# here logged it as a known defect rather than fixing it.
#
# The envelope is now the authority, so that is what is asserted. Worth
# noticing that this assertion FAILED the moment the contract changed, which
# is the only reason the change was safe to make, TODO 1.8 warned against
# changing it blind, and this test is what made it not blind.
check("the envelope carries the refusal",
      (out["error"] or "").startswith("Unknown tool"), True)
check("and result is empty rather than error-shaped", out["result"], None)
check("and it stayed unset", me.query_known_devices(ip="198.51.100.10")[0]["is_permanent"], 1)
print("       (that row was set to 1 directly in step 7, not by a tool)")

print("\n[10] identify_device does not grant permanence")
me.save_known_device(ip="198.51.100.30", mac="70:85:c2:11:22:33")
me.identify_device(ip="198.51.100.30", known_as="speaker",
                   evidence="test fixture", identified_by="model")
check("named", me.query_known_devices(ip="198.51.100.30")[0]["known_as"], "speaker")
check("still not permanent", me.query_known_devices(ip="198.51.100.30")[0]["is_permanent"], 0)

print("\n[11] drift reads through execute_tool")
out = tr.execute_tool("query_device_drift", {})
check("no error", out["error"], None)
check("returns the note", isinstance(out["result"].get("note"), str), True)

print("\n[12] identity_class has three values, and the third is not 'stable'")
check("randomized",        me.identity_class("02:1a:2b:3c:4d:5e"), "transient_client")
check("burned-in",         me.identity_class("b8:27:eb:11:22:33"), "stable_host")
check("absent, not stable", me.identity_class(""),                 "no_hardware_address")
check("None, not stable",   me.identity_class(None),               "no_hardware_address")

print("\n[13] the review queue separates appearances from devices")
# One genuinely unknown host, three appearances of randomizing clients, one
# with no hardware address at all. This is the shape that makes a queue
# unreadable if every row is counted the same.
me.save_known_device(ip="198.51.100.60", mac="dc:a6:32:11:22:33")          # stable, unknown
me.save_known_device(ip="198.51.100.61", mac="02:aa:bb:cc:dd:01")          # randomized
me.save_known_device(ip="198.51.100.62", mac="06:aa:bb:cc:dd:02")          # randomized
me.save_known_device(ip="198.51.100.63", mac="8e:aa:bb:cc:dd:03")          # randomized
me.save_known_device(ip="198.51.100.64")                                   # no mac

queue = me.unidentified_devices()
classes = [d["identity_class"] for d in queue]
check("stable hosts sort to the front", classes[0], "stable_host")
check("transient clients sort to the back", classes[-1], "transient_client")
check("every row classified", all(c in
      {"stable_host","transient_client","no_hardware_address"} for c in classes), True)

out = tr.execute_tool("query_known_devices", {"unidentified_only": True})["result"]
print(f"       unidentified={out['unidentified']} "
      f"stable={out['unidentified_stable_hosts']} "
      f"transient={out['unidentified_transient_clients']} "
      f"no_mac={out['unidentified_without_hardware_address']}")
# Four, not three: the phone from step 3 is also an unnamed randomized row.
# Counting the fixtures by hand here would just re-encode the same mistake, so
# the expectation is derived from the queue itself.
expected_transient = sum(1 for d in me.unidentified_devices()
                         if d["identity_class"] == "transient_client")
check("transient counted apart", out["unidentified_transient_clients"], expected_transient)
check("and that is more than one", expected_transient >= 3, True)
check("the no-mac row is not called stable", out["unidentified_without_hardware_address"], 1)
check("counts reconcile",
      out["unidentified_stable_hosts"] + out["unidentified_transient_clients"]
      + out["unidentified_without_hardware_address"], out["unidentified"])
assert "RANDOMIZED" in out["note"], out["note"]
assert "NOT count them as separate devices" in out["note"], out["note"]
print("       note tells the model not to count appearances as devices")

print("\n[14] classification rides along on the ordinary device read")
rows = me.query_known_devices(ip="198.51.100.61")
check("present on query_known_devices", rows[0]["identity_class"], "transient_client")

print("\n[15] merge: several address rows become one device")
me.save_known_device(ip="198.51.100.70", mac="02:11:11:11:11:01")   # phone, lease 1
me.save_known_device(ip="198.51.100.71", mac="02:22:22:22:22:02")   # phone, lease 2
me.save_known_device(ip="198.51.100.72", mac="02:33:33:33:33:03")   # phone, lease 3
me.identify_device(ip="198.51.100.70", known_as="my phone",
                   evidence="test fixture", identified_by="user")

before_queue = len(me.unidentified_devices())
r = me.merge_devices("198.51.100.71", "198.51.100.70")
check("merge accepted", r["success"], True)
r = me.merge_devices("198.51.100.72", "198.51.100.70")
check("second merge accepted", r["success"], True)
after_queue = len(me.unidentified_devices())
check("queue shrank by exactly the merged rows", before_queue - after_queue, 2)

app = me.device_appearances(canonical_ip="198.51.100.70")["devices"][0]
check("appearances recorded", app["appearance_count"], 2)
check("canonical keeps the label", app["known_as"], "my phone")

print("\n[16] merge refuses the cases that would corrupt the record")
check("into itself", me.merge_devices("198.51.100.70","198.51.100.70")["success"], False)
check("unknown source", me.merge_devices("198.51.100.98","198.51.100.70")["success"], False)
check("cycle", me.merge_devices("198.51.100.70","198.51.100.71")["success"], False)

# A vouched-for device can merge only where the flag can go: the target here
# has a randomized MAC, so moving permanence onto it is refused.
me.save_known_device(ip="198.51.100.80", mac="dc:a6:32:aa:bb:cc")
me.set_device_permanence("198.51.100.80", True)
r = me.merge_devices("198.51.100.80", "198.51.100.70")
check("permanence onto a randomized address refused", r["success"], False)
me.set_device_permanence("198.51.100.80", False)
check("and allowed once un-vouched",
      me.merge_devices("198.51.100.80","198.51.100.70")["success"], True)

print("\n[17] chains cannot form: merging a canonical row carries its members")
me.save_known_device(ip="198.51.100.90", mac="b8:27:eb:aa:bb:cc")
r = me.merge_devices("198.51.100.70", "198.51.100.90")   # canonical into a new root
check("accepted", r["success"], True)
check("its appearances came along", r["also_repointed"] >= 2, True)
with me._get_conn() as conn:
    depths = conn.execute(
        "SELECT k.ip FROM known_devices k JOIN known_devices p "
        "ON k.merged_into = p.id WHERE p.merged_into IS NOT NULL").fetchall()
check("no row points at a merged row", len(depths), 0)

print("\n[18] unmerge puts one row back, and only that one")
n_before = len(me.unidentified_devices())
check("unmerge works", me.unmerge_device("198.51.100.72")["success"], True)
check("exactly one row returned to the queue",
      len(me.unidentified_devices()) - n_before, 1)
check("unmerging twice is refused", me.unmerge_device("198.51.100.72")["success"], False)

print("\n[19] nothing in the manifest can merge")
names = [t["name"] for t in tr.TOOL_MANIFEST]
check("no merge tool", [n for n in names if "merge" in n.lower()], [])
out = tr.execute_tool("merge_devices", {"source_ip":"198.51.100.71","target_ip":"198.51.100.90"})
check("dispatch refuses",
      (out["error"] or "").startswith("Unknown tool"), True)

print("\n[20] the two new tools are behind the untrusted-data fence")
from core import sanitize as sz
check("query_device_drift fenced", sz.is_untrusted("query_device_drift"), True)
check("query_presence fenced",     sz.is_untrusted("query_presence"), True)
check("consistent with query_known_devices",
      sz.is_untrusted("query_known_devices"), True)

print("\n[21] S8: the suppression gate and the writer agree on every value")
from core.tool_registry import requires_permission, suppression_is_requested
mismatches = []
for v in [True, 1, "1", "true", "True", "yes", "TRUE", "on", 2, [1], {"a":1},
          "false", "FALSE", "0", 0, False, None, "", "  ", "no", "off"]:
    gated  = requires_permission("update_behavioral_baseline", {"alert_suppressed": v})
    writes = suppression_is_requested(v)
    if gated != writes:
        mismatches.append((v, gated, writes))
check("no value where the write happens ungated", mismatches, [])
check("the 'false' string no longer suppresses", suppression_is_requested("false"), False)
check("an unrecognised value is gated, not silently allowed",
      suppression_is_requested({"a": 1}), True)

print("\n[22] S9: an all-ports sweep is gated even on an internal target")
# DERIVED, not hardcoded. This branch needs an address the gate classifies
# as internal, so an RFC 5737 documentation address will not exercise it,
# but writing a literal RFC1918 address here is precisely what design rule 1
# forbids, and check_no_local_details flags it. Ask the gate's own source of
# truth what counts as internal.
internal_net  = next(iter(tr._internal_networks()))
internal_host = str(next(internal_net.hosts()))

check("port_set=all gated", requires_permission(
      "run_port_scan", {"target_host": internal_host, "port_set": "all"}), True)
check("port_set=common still ungated internally", requires_permission(
      "run_port_scan", {"target_host": internal_host, "port_set": "common"}), False)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
