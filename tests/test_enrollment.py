"""
tests/test_enrollment.py, session B of the probe.

Two things, and the second is the one that carries a security property.

Enrollment: the tool has no MDM behind it, so the human is the enrollment
authority. What is tested here is mostly that the backend refuses to
oversimplify: three populations reported separately rather than one
misleading count, and "the walkthrough has been run" never presented as
"there is nothing left to review".

The read-only handle: that the model's read path CANNOT write, enforced by
SQLite rather than by anybody remembering the rule.
"""
import sys, sqlite3, tempfile, pathlib

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
from core import migrations; migrations.run_migrations(db)
from core import sensors as sn; sn.register_local()

SID = "test-session"


print("\n[1] a fresh install says plainly that nothing is anchored yet")
state = me.enrollment_state()
check("never run", state["has_been_run"], False)
check("nothing permanent", state["counts"]["marked_permanent"], 0)
assert "absence cannot be a signal" in state["note"], state["note"]
print("       and says absence cannot be a signal until something is marked")


print("\n[2] the three populations are reported apart, never as one number")
me.save_known_device(ip="198.51.100.10", mac="b8:27:eb:11:22:33")   # stable
me.save_known_device(ip="198.51.100.11", mac="dc:a6:32:11:22:33")   # stable
me.save_known_device(ip="198.51.100.20", mac="02:aa:bb:cc:dd:01")   # randomized
me.save_known_device(ip="198.51.100.21", mac="06:aa:bb:cc:dd:02")   # randomized
me.save_known_device(ip="198.51.100.22", mac="8e:aa:bb:cc:dd:03")   # randomized
me.save_known_device(ip="198.51.100.30")                            # no mac

state  = me.enrollment_state()
counts = state["counts"]
check("only stable hosts count as needing review", counts["needs_review"], 2)
check("transient appearances counted apart", counts["transient_clients"], 3)
check("and no-address rows counted apart", counts["no_hardware_address"], 1)
check("the three do not get added together anywhere in the payload",
      counts["needs_review"] != len(me.unidentified_devices()), True)
assert "do not present it as a device count" in state["note"]
print("       note warns against presenting the transient count as devices")

check("needs_review list is stable hosts only",
      {d["identity_class"] for d in state["needs_review"]}, {"stable_host"})


print("\n[3] naming a device removes it from the queue, and only that device")
me.identify_device(ip="198.51.100.10", known_as="printer",
                   evidence="test fixture", identified_by="user")
counts = me.enrollment_state()["counts"]
check("one fewer needing review", counts["needs_review"], 1)
check("identified count moved", counts["identified"], 1)
check("naming grants no permanence", counts["marked_permanent"], 0)


print("\n[4] completing the walkthrough is not an all-clear")
res = me.complete_enrollment()
check("recorded", res["success"], True)
state = me.enrollment_state()
check("has_been_run flips", state["has_been_run"], True)
check("but the queue is untouched", state["counts"]["needs_review"], 1)
check("completed_at is a timestamp, not a boolean 'clean'",
      isinstance(state["completed_at"], str), True)
print("       a live network produces new devices forever; this only stops")
print("       the interface re-running a first-run flow")


print("\n[5] marking a device permanent is what makes absence measurable")
me.set_device_permanence("198.51.100.11", True)
state = me.enrollment_state()
check("permanent count", state["counts"]["marked_permanent"], 1)
assert "absence is measurable" in state["note"], state["note"]


print("\n[6] D1: the model's read handle CANNOT write, enforced by SQLite")
# Not a policy assertion. An actual write, through the actual handle.
wrote = None
try:
    with me._get_readonly_conn() as conn:
        conn.execute("UPDATE known_devices SET known_as = 'hijacked' "
                     "WHERE ip = '198.51.100.11'")
        conn.commit()
    wrote = True
except sqlite3.OperationalError as e:
    wrote = False
    print(f"       SQLite refused it: {e}")
check("the write was refused", wrote, False)
check("and the row is untouched",
      me.query_known_devices(ip="198.51.100.11")[0]["known_as"], None)

# Deletes and inserts too, not just updates.
for statement in ("DELETE FROM known_devices",
                  "INSERT INTO known_devices(ip) VALUES('198.51.100.99')",
                  "DROP TABLE presence_sweep"):
    refused = False
    try:
        with me._get_readonly_conn() as conn:
            conn.execute(statement)
            conn.commit()
    except sqlite3.OperationalError:
        refused = True
    check(f"refused: {statement.split()[0]}", refused, True)

check("reads still work through it", len(me.query_known_devices()) > 0, True)
check("and the ordinary handle can still write",
      me.identify_device(ip="198.51.100.20", known_as="phone",
                         evidence="fixture",
                         identified_by="user").get("success"), True)


print("\n[7] the read functions actually use it")
src = (ROOT / "core" / "memory_engine.py").read_text(encoding="utf-8")
for fn in ("def query_presence(", "def query_known_devices(",
           "def query_device_drift(", "def permanent_devices("):
    start = src.index(fn)
    nxt   = src.find("\ndef ", start + 1)
    body  = src[start:nxt if nxt != -1 else len(src)]
    check(f"{fn.split('(')[0].replace('def ', '')} reads read-only",
          "_get_readonly_conn()" in body, True)

# And the writers deliberately do NOT.
for fn in ("def set_device_permanence(", "def merge_devices(",
           "def retire_device("):
    start = src.index(fn)
    nxt   = src.find("\ndef ", start + 1)
    body  = src[start:nxt if nxt != -1 else len(src)]
    check(f"{fn.split('(')[0].replace('def ', '')} keeps the writable handle",
          "_get_readonly_conn()" in body, False)


print("\n[8] the enrollment endpoints exist and are behind the API key")
from api.server import create_app, allowed_hosts
API_KEY = "0" * 64
app = create_app({"flask": {"host": "127.0.0.1", "port": 5000}}, {}, SID,
                 api_key=API_KEY)
app.config["AGENTAL_ALLOWED_HOSTS"] = allowed_hosts({"flask": {"host": "127.0.0.1"}})
client = app.test_client()

for route in ("/api/enrollment", "/api/probe/status"):
    check(f"{route} needs the key", client.get(route).status_code, 401)
    check(f"{route} answers with it",
          client.get(route, headers={"X-API-Key": API_KEY}).status_code, 200)

r = client.post("/api/enrollment/complete", headers={"X-API-Key": API_KEY})
check("complete is a POST, not a GET", r.status_code, 200)
check("and GET is refused",
      client.get("/api/enrollment/complete",
                 headers={"X-API-Key": API_KEY}).status_code, 405)

r = client.get("/api/probe/status", headers={"X-API-Key": API_KEY})
check("probe status is honest when the module is absent",
      r.get_json().get("running"), False)
assert "not being re-verified" in r.get_json().get("detail", "")
print("       and says the inventory is not being re-verified at all")


print("\n[9] the walkthrough table lists what is UNVOUCHED, not what is unnamed")
# Found by opening the page: with every device already named, the table was
# empty and there was no way to mark anything permanent from the tab at all.
# Naming and vouching are different acts and the queue was only asking about
# the first one.
st = me.enrollment_state()
named_ips = {d["ip"] for d in me.query_known_devices()
             if (d.get("known_as") or "").strip()}
candidates = {d["ip"] for d in st["not_yet_permanent"]}
check("a NAMED but unvouched device is still listed",
      bool(named_ips & candidates), True)
check("count matches the list",
      st["counts"]["not_yet_permanent"], len(st["not_yet_permanent"]))
check("randomized addresses are not offered, since they would be refused",
      [d for d in st["not_yet_permanent"]
       if d["identity_class"] != "stable_host"], [])

before = len(st["not_yet_permanent"])
target = st["not_yet_permanent"][0]["ip"]
me.set_device_permanence(target, True)
after = me.enrollment_state()
check("vouching removes it from the list",
      len(after["not_yet_permanent"]), before - 1)
check("and it appears as permanent",
      after["counts"]["marked_permanent"] > st["counts"]["marked_permanent"], True)

check("needs_review still means UNNAMED, and is left alone",
      st["counts"]["needs_review"],
      len([d for d in me.unidentified_devices()
           if d["identity_class"] == "stable_host"]))

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
