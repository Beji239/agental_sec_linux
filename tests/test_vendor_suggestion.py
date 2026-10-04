"""
tests/test_vendor_suggestion.py, TODO 36.3, the three small things the
hardware vendor lookup opened up.

WHAT IS BEING PROVED, and it is deliberately narrow. Section 36 already made
the lookup itself work and test_oui.py covers that. This is only about the
three places the answer was not being used:

  a name OFFERED when somebody is about to name a device
  the vendor written into the row, not only stamped on the way out
  and the registry never overwriting a vendor a person or a scan supplied

The rule the suggestion has to keep is 4A's: the human is the enrollment
authority, because there is no MDM here. A suggestion makes that cheaper. A
suggestion that fills itself in would be the tool naming devices, which is
the thing 4A refused.
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


from core import oui                            # noqa: E402
from core import memory_engine as me            # noqa: E402

# A tiny registry of our own rather than the real 53,791 line one. The real
# file is a download that may not be there, and a test that needs it is a
# test that skips on a fresh clone.
data = pathlib.Path(tempfile.mkdtemp())
(data / "manuf").write_text(
    "# a cut down copy of the wireshark format\n"
    "5C:41:5A\tAmazon\tAmazon Technologies Inc.\n"
    "B8:27:EB\tRaspberry\tRaspberry Pi Foundation\n",
    encoding="utf-8")
oui.DATA_DIR = data
oui.reload()

tmp = pathlib.Path(tempfile.mkdtemp())
db  = tmp / "t.db"
me.DB_PATH = db
sqlite3.connect(db).executescript(
    (ROOT / "Schema.SQL").read_text(encoding="utf-8"))
from core import migrations                     # noqa: E402
migrations.run_migrations(db)


print("\n[1] a device with no label gets a name offered, with its basis")
me.save_known_device(ip="198.51.100.40", mac="5c:41:5a:11:22:33")
row = [d for d in me.query_known_devices() if d["ip"] == "198.51.100.40"][0]
check("the maker was resolved", row["vendor"], "Amazon Technologies Inc.")
check("a name is offered", row.get("suggested_name"), "Amazon device")
# The basis is not decoration. It is the difference between a suggestion
# somebody can judge and a label that appeared from nowhere.
check("and it says where the name came from",
      "hardware address" in (row.get("suggested_name_basis") or ""), True)


print("\n[2] a hostname beats the registry, because the device said it")
me.save_known_device(ip="198.51.100.41", mac="b8:27:eb:44:55:66",
                     hostname="kitchen-pi")
row = [d for d in me.query_known_devices() if d["ip"] == "198.51.100.41"][0]
check("the hostname is what gets offered",
      row.get("suggested_name"), "kitchen-pi")
check("and the basis says so",
      "hostname" in (row.get("suggested_name_basis") or ""), True)


print("\n[3] nothing is offered where a name would be meaningless")
# Already named. The queue is about devices nobody has named, and offering a
# second name for one that has one is noise on every screen it appears on.
me.save_known_device(ip="198.51.100.42", mac="5c:41:5a:77:88:99")
me.identify_device("198.51.100.42", known_as="Echo in the kitchen",
                   evidence="the user said so", identified_by="user")
row = [d for d in me.query_known_devices() if d["ip"] == "198.51.100.42"][0]
check("a named device gets no suggestion",
      "suggested_name" in row, False)

# A randomized address is one afternoon's address. A name attached to it is
# wrong by tomorrow, and 4A already counts these separately for that reason.
me.save_known_device(ip="198.51.100.43", mac="02:aa:bb:cc:dd:01")
row = [d for d in me.query_known_devices() if d["ip"] == "198.51.100.43"][0]
check("a randomized address gets no suggestion",
      "suggested_name" in row, False)
check("and is still reported as transient",
      row["identity_class"], "transient_client")


print("\n[4] the vendor is written into the row, not only stamped on read")
with sqlite3.connect(db) as conn:
    stored = conn.execute(
        "SELECT vendor FROM known_devices WHERE ip = ?",
        ("198.51.100.40",)).fetchone()[0]
check("the column itself carries it", stored, "Amazon Technologies Inc.")


print("\n[5] the registry never overwrites what a person or a scan said")
# The registry knows who made the network chip. Somebody who looked at the
# actual device knows what the device is, and those disagree often enough
# that this has to be a rule rather than a habit.
me.save_known_device(ip="198.51.100.44", mac="5c:41:5a:aa:bb:cc",
                     vendor="Ring, from the label on the back")
me.save_known_device(ip="198.51.100.44", mac="5c:41:5a:aa:bb:cc")
with sqlite3.connect(db) as conn:
    stored = conn.execute(
        "SELECT vendor FROM known_devices WHERE ip = ?",
        ("198.51.100.44",)).fetchone()[0]
check("the human's answer survives a later scan",
      stored, "Ring, from the label on the back")
row = [d for d in me.query_known_devices() if d["ip"] == "198.51.100.44"][0]
check("and the disagreement stays visible rather than being merged",
      row.get("registry_vendor"), "Amazon Technologies Inc.")


print("\n[6] with no registry file, nothing is offered and nothing is claimed")
oui.DATA_DIR = pathlib.Path(tempfile.mkdtemp())
oui.reload()
me.save_known_device(ip="198.51.100.45", mac="5c:41:5a:de:ad:00")
row = [d for d in me.query_known_devices() if d["ip"] == "198.51.100.45"][0]
check("no vendor is invented", row.get("vendor"), None)
check("status says nobody looked", row.get("vendor_status"), "no_data")
check("and no name is offered", "suggested_name" in row, False)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
