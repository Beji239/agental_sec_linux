"""
tests/test_device_router_change.py, devices that moved address.

After a router change each device gets a new row at its new address while
the old row keeps the user's labels and flags. Covered here: presence by MAC,
merges that carry the user's facts and move permanence, unmerge giving them
back, merged rows hidden from the lists, and the same-MAC helper.
"""
import sys, json, tempfile, sqlite3, pathlib

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
schema = (ROOT / "Schema.SQL").read_text(encoding="utf-8")
c = sqlite3.connect(db); c.executescript(schema); c.commit(); c.close()

from core import migrations
r1 = migrations.run_migrations(db)
r2 = migrations.run_migrations(db)
print(f"migration pass 1: {r1.get('status')}  pass 2: {r2.get('status')}")
check("merge_carried column exists",
      "merge_carried" in migrations._columns(sqlite3.connect(db), "known_devices"), True)

from core import sensors as sn
sn.register_local()

OLD_NET, NEW_NET = "198.51.100.0/24", "203.0.113.0/24"
TV_MAC, SPK_MAC, CAM_MAC = "00:00:5e:00:53:01", "00:00:5e:00:53:02", "00:00:5e:00:53:03"


def sweep(responders, subnet=NEW_NET):
    return me.record_presence_sweep(
        "t", "icmp", "ok", subnet=subnet, targets=254,
        responders=[{"ip": ip, "mac": mac, "via": "both"} for ip, mac in responders])


# The old network: named and vouched for.
me.save_known_device(ip="198.51.100.10", mac=TV_MAC)
me.identify_device(ip="198.51.100.10", known_as="living room TV", device_type="tv",
                   evidence="test fixture", identified_by="user")
me.set_device_permanence("198.51.100.10", True)
me.set_device_always_on("198.51.100.10", True)

me.save_known_device(ip="198.51.100.20", mac=SPK_MAC)
me.identify_device(ip="198.51.100.20", known_as="kitchen speaker", device_type="iot",
                   evidence="test fixture", identified_by="user")
me.set_device_permanence("198.51.100.20", True)

# The new router: same hardware, new addresses, no labels yet.
me.save_known_device(ip="203.0.113.10", mac=TV_MAC.upper())
me.save_known_device(ip="203.0.113.20", mac=SPK_MAC)
me.identify_device(ip="203.0.113.20", known_as="speaker (new name)",
                   evidence="test fixture", identified_by="user")

for _ in range(6):
    sweep([("203.0.113.10", TV_MAC), ("203.0.113.20", SPK_MAC)])


print("\n[1] presence by MAC: the old row answers through the new address")
res = me.query_presence()
by_ip = {d["ip"]: d for d in res["devices"]}
check("old TV row present", by_ip["198.51.100.10"]["present_in"], 6)
check("old TV row not missing", by_ip["198.51.100.10"]["absent_streak"], 0)
check("says which address answered",
      by_ip["198.51.100.10"]["answered_by_appearances"], ["203.0.113.10"])
check("new row still counts for itself", by_ip["203.0.113.10"]["present_in"], 6)

one = me.query_presence(ip="198.51.100.10")["devices"]
check("asking for the old row finds it by MAC", [d["present_in"] for d in one], [6])
check("and returns only the row asked for", [d["ip"] for d in one], ["198.51.100.10"])


print("\n[2] the same-MAC helper finds the pairs, newest row kept")
groups = me.same_mac_groups()
pairs = sorted((g["keep"]["ip"], [m["ip"] for m in g["merge"]]) for g in groups["groups"])
check("two pairs, case of the MAC ignored", pairs,
      [("203.0.113.10", ["198.51.100.10"]), ("203.0.113.20", ["198.51.100.20"])])


print("\n[3] merging a permanent row moves its flags and fills the gaps")
tv_old = me.query_known_devices(ip="198.51.100.10")[0]
r = me.merge_devices("198.51.100.10", "203.0.113.10")
check("accepted", r["success"], True)
check("flags moved", sorted(r["moved_flags"]), ["expected_always_on", "is_permanent"])
new = me.query_known_devices(ip="203.0.113.10")[0]
old = me.query_known_devices(ip="198.51.100.10")[0]
check("target now permanent", new["is_permanent"], 1)
check("target now always on", new["expected_always_on"], 1)
check("target took the name it lacked", new["known_as"], "living room TV")
check("and the type", new["device_type"], "tv")
check("and the enrollment fingerprint",
      new["enrollment_fingerprint"], tv_old["enrollment_fingerprint"])
check("old row no longer permanent", old["is_permanent"], 0)
check("old row no longer always on", old["expected_always_on"], 0)
check("old row kept, pointing at the new one", old["merged_into"], new["id"])

perm = [d["ip"] for d in me.permanent_devices()]
check("permanent list shows the device once, at its new address",
      ("203.0.113.10" in perm, "198.51.100.10" in perm), (True, False))
check("always on list too", [d["ip"] for d in me.always_on_devices()], ["203.0.113.10"])
drift_ips = [d["ip"] for d in me.query_device_drift()["devices"]]
check("drift table does not list the old row", "198.51.100.10" in drift_ips, False)


print("\n[4] a target with its own name keeps it")
r = me.merge_devices("198.51.100.20", "203.0.113.20")
check("accepted", r["success"], True)
spk = me.query_known_devices(ip="203.0.113.20")[0]
check("user's newer name kept", spk["known_as"], "speaker (new name)")
check("empty type filled", spk["device_type"], "iot")
check("permanent moved", spk["is_permanent"], 1)


print("\n[5] unmerge gives the flags back and takes back what it gave")
r = me.unmerge_device("198.51.100.10")
check("accepted", r["success"], True)
old = me.query_known_devices(ip="198.51.100.10")[0]
new = me.query_known_devices(ip="203.0.113.10")[0]
check("old row permanent again", old["is_permanent"], 1)
check("old row always on again", old["expected_always_on"], 1)
check("old row not merged", (old["merged_into"], old["merge_carried"]), (None, None))
check("target loses the flag it was given", new["is_permanent"], 0)
check("target loses the always on flag", new["expected_always_on"], 0)
check("target loses the copied name", new["known_as"], None)
check("target loses the copied type", new["device_type"], None)

# A field the user changed after the merge is theirs and stays.
me.merge_devices("198.51.100.10", "203.0.113.10")
me.identify_device(ip="203.0.113.10", known_as="TV, renamed later",
                   evidence="test fixture", identified_by="user")
me.unmerge_device("198.51.100.10")
check("a name set after the merge survives unmerge",
      me.query_known_devices(ip="203.0.113.10")[0]["known_as"], "TV, renamed later")


print("\n[6] permanence cannot move onto an address that cannot hold it")
me.save_known_device(ip="198.51.100.30", mac=CAM_MAC)
me.set_device_permanence("198.51.100.30", True)
me.save_known_device(ip="203.0.113.30", mac="02:00:5e:00:53:30")   # randomized
r = me.merge_devices("198.51.100.30", "203.0.113.30")
check("refused", r["success"], False)
check("old row untouched",
      me.query_known_devices(ip="198.51.100.30")[0]["is_permanent"], 1)
check("but the other way round is fine",
      me.merge_devices("203.0.113.30", "198.51.100.30")["success"], True)

me.save_known_device(ip="203.0.113.31", mac=CAM_MAC)
me.retire_device("203.0.113.31", "test")
r = me.merge_devices("198.51.100.30", "203.0.113.31")
check("refused onto a retired row", r["success"], False)


print("\n[7] merge all, one step, through the helper")
before = me.same_mac_groups()["rows_to_merge"]
check("there is something to merge", before >= 1, True)
out = me.merge_same_mac(macs=[])
check("an empty list merges nothing", out["merged"] + out["refused"], 0)
out = me.merge_same_mac(macs=[TV_MAC.upper()])
check("one MAC given, one merged", out["merged"], 1)
check("the TV pair is gone from the helper",
      TV_MAC in [g["mac"] for g in me.same_mac_groups()["groups"]], False)
check("its flags moved", me.query_known_devices(ip="203.0.113.10")[0]["is_permanent"], 1)


print("\n[8] the always-on absence check reads the moved device as present")
res = me.query_presence()
row = {d["ip"]: d for d in res["devices"]}["203.0.113.10"]
check("no absence streak on the device that moved", row["absent_streak"], 0)


print("\n[9] still user only")
from core import tool_registry as tr
names = [t["name"] for t in tr.TOOL_MANIFEST]
check("no merge tool in the manifest", [n for n in names if "merge" in n.lower()], [])
routes = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")
check("helper routes exist",
      ('"/api/devices/same-mac"' in routes, '"/api/devices/merge-same-mac"' in routes),
      (True, True))
ui = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check("the page calls them",
      ("/api/devices/same-mac" in ui, "/api/devices/merge-same-mac" in ui), (True, True))
check("the Network list hides merged rows", "!d.merged_into" in ui, True)


print()
if fails:
    print(f"{len(fails)} FAILED: {fails}")
    sys.exit(1)
print("all passed")
