"""
tests/test_always_on.py, v22, membership and availability are two statements.

is_permanent meant "this device belongs on my network". The absence check read
it as "this device should always be answering", so vouching for a TV silently
signed it up to stay awake and every quiet evening produced a finding. The
owner put it plainly: those devices are off because nobody is using them.

Checked here, worst outcome first:

  a permanent device that is NOT always-on never appears in the absence list
  the two flags are independent in both directions
  the migration does NOT backfill always-on from permanence
  the flag reaches the model through inventory enrichment, so nothing has to
    write the rule into a behavioural observation to remember it
  clearing always-on leaves membership alone
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

GATEWAY = "192.0.2.1"
TV = "192.0.2.50"
LAPTOP = "192.0.2.60"

with sqlite3.connect(db) as c:
    c.executemany(
        "INSERT INTO known_devices(ip, mac, known_as, device_type, "
        "is_permanent) VALUES(?,?,?,?,?)",
        [(GATEWAY, "00:00:5e:00:53:01", "gateway", "router", 1),
         (TV,      "00:00:5e:00:53:02", "living room TV", "tv", 1),
         (LAPTOP,  "00:00:5e:00:53:03", "a laptop", "laptop", 0)])


print("\n[1] the migration does NOT backfill always-on from permanence")
# Backfilling would preserve exactly the behaviour being corrected and call it
# a migration. Nobody has declared availability yet because there was no way
# to, so the honest starting state is that nobody has.
check("no device starts always-on", me.always_on_devices(), [])
check("but both permanent devices are still members",
      sorted(d["ip"] for d in me.permanent_devices()), [GATEWAY, TV])


print("\n[2] THE CENTRAL ONE: a member is not automatically expected awake")
me.set_device_always_on(GATEWAY, True)
always = [d["ip"] for d in me.always_on_devices()]
check("only the gateway is always-on", always, [GATEWAY])
check("the TV is a member but NOT in the absence list", TV in always, False)


print("\n[3] the two flags are independent in both directions")
# A device can be expected awake without being vouched for as a member. Odd,
# but they are separate statements and the code must not tie them together.
me.set_device_always_on(LAPTOP, True)
with sqlite3.connect(db) as c:
    c.row_factory = sqlite3.Row
    row = c.execute("SELECT is_permanent, expected_always_on FROM "
                    "known_devices WHERE ip=?", (LAPTOP,)).fetchone()
check("always-on without membership is allowed",
      (row["is_permanent"], row["expected_always_on"]), (0, 1))
me.set_device_always_on(LAPTOP, False)


print("\n[4] clearing always-on leaves membership alone")
me.set_device_always_on(TV, True)
me.set_device_always_on(TV, False)
with sqlite3.connect(db) as c:
    c.row_factory = sqlite3.Row
    row = c.execute("SELECT is_permanent, expected_always_on FROM "
                    "known_devices WHERE ip=?", (TV,)).fetchone()
check("still a member", bool(row["is_permanent"]), True)
check("no longer expected awake", bool(row["expected_always_on"]), False)


print("\n[5] the flag reaches the model on the row it is already reading")
# This is the other half of the fix. With the fact on the inventory, nothing
# has to write the availability rule into a behavioural observation under
# whichever key happened to be valid, which is what actually happened.
rows = me._enrich([{"src_ip": GATEWAY}, {"src_ip": TV}], "src_ip")
gw, tv = rows[0]["src_device"], rows[1]["src_device"]
check("gateway carries the flag", gw.get("expected_always_on"), True)
check("TV does not", tv.get("expected_always_on"), None)
check("TV still shows as a member", tv.get("is_permanent"), True)


print("\n[6] a setter refuses an address it does not know")
result = me.set_device_always_on("192.0.2.222", True)
check("refused", result["ok"], False)
check("and says why", "not in the inventory" in result["reason"], True)


print("\n[7] the declaration is journalled")
# A flood of always-on marks would manufacture findings, so the change leaves
# a trace the same way a vouch does.
with sqlite3.connect(db) as c:
    n = c.execute("SELECT COUNT(*) FROM integrity_journal WHERE "
                  "operation='device_vouched'").fetchone()[0]
check("journal entries exist", n > 0, True)


print("\n[8] a retired device is never expected awake")
me.set_device_always_on(GATEWAY, True)
me.retire_device(GATEWAY, "test")
check("retired device drops out of the always-on list",
      [d["ip"] for d in me.always_on_devices()], [])


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
