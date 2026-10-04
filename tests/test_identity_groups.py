"""
tests/test_identity_groups.py: the four MAC identity groups and the tabs.

The Inventory tab lists only stable MACs and explains the other groups; the
Network tab shows every group in an Identity column, with retired devices
behind a checkbox. An unreadable MAC is its own group and is never counted
as stable or marked permanent.
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
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


tmp = pathlib.Path(tempfile.mkdtemp())
db = tmp / "t.db"
from core import memory_engine as me  # noqa: E402
me.DB_PATH = db
c = sqlite3.connect(db)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.commit()
c.close()
from core import migrations  # noqa: E402
migrations.run_migrations(db)


print("\n[1] identity_class has four groups")
check("burned-in", me.identity_class("b8:81:98:40:d0:01"), "stable_host")
check("dash form, upper case", me.identity_class("B8-81-98-40-D7-33"), "stable_host")
check("randomized", me.identity_class("02:1a:2b:3c:4d:5e"), "transient_client")
check("absent", me.identity_class(""), "no_hardware_address")
check("junk", me.identity_class("not-a-mac"), "unreadable_mac")
check("cut off", me.identity_class("b8:81:98:40"), "unreadable_mac")
check("all zeros", me.identity_class("00:00:00:00:00:00"), "unreadable_mac")


print("\n[2] the enrollment counts and list")
me.save_known_device("192.0.2.1", mac="b8:81:98:40:d0:01")
me.save_known_device("192.0.2.2", mac="02:1a:2b:3c:4d:5e")
me.save_known_device("192.0.2.3", mac="")
me.save_known_device("192.0.2.4", mac="b8:81:98")
me.save_known_device("192.0.2.5", mac="44:27:45:11:22:33")
with sqlite3.connect(db) as conn:
    conn.execute("UPDATE known_devices SET retired_at = CURRENT_TIMESTAMP "
                 "WHERE ip = '192.0.2.5'")
st = me.enrollment_state()
cn = st["counts"]
check("unreadable counted on its own", cn.get("unreadable_mac"), 1)
check("retired counted", cn.get("retired"), 1)
check("only the stable, live device is listed",
      [d["ip"] for d in st["not_yet_permanent"]], ["192.0.2.1"])


print("\n[3] an unreadable MAC cannot be marked permanent")
r = me.set_device_permanence("192.0.2.4", True)
check("refused", r.get("success"), False)
check("stable one still can be",
      me.set_device_permanence("192.0.2.1", True).get("success"), True)


print("\n[4] the page carries the explanation, column and checkbox")
html = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check("Inventory explains the stable-MAC rule",
      "Only devices with a stable MAC address get listed here." in html, True)
for group in ("Randomized MAC:", "No MAC:", "Unreadable MAC:", "Retired:"):
    check(f"  and names {group}", group in html, True)
check("Network table has an Identity column", "<th>Identity</th>" in html, True)
check("and a show-retired checkbox", 'id="devices-show-retired"' in html, True)

print()
if fails:
    print(f"{len(fails)} FAILED: {fails}")
    sys.exit(1)
print("all passed")
