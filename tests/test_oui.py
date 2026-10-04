"""
tests/test_oui.py, the vendor lookup, and the four ways of not having one.

WHY THIS EXISTS. On 2026-09-01 the model identified an always-on unknown
device as a LIFX bulb from its broadcast ports. The first three bytes of its
address are registered to somebody else entirely, and the address was sitting
in the presence row the whole time. See TODO 36.

So the checks here are mostly about REFUSING TO GUESS. The easy part is
returning a name when the registry has one. The part worth testing is that
the four failure modes stay four different answers:

    randomized       no vendor EXISTS, this is a fact about the device
    unknown_prefix   the registry is loaded and really does not have it
    no_data          there is no registry, so we know nothing either way
    unparseable      that was not a hardware address

Collapsing any of those into "unknown" is the bug. no_data means ask,
unknown_prefix means the registry has no entry, and randomized is a finding.
"""
import pathlib
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


from core import oui                          # noqa: E402

tmp = pathlib.Path(tempfile.mkdtemp())
oui.DATA_DIR = tmp
oui.reload()


print("\n[1] with NO registry file, it says no_data and not 'unknown'")
# The distinction that matters most. A tool with no data saying "unknown
# vendor" reads as "the registry has no entry", which is a different and much
# stronger claim than the truth, which is that nobody looked.
r = oui.lookup("5c:41:5a:80:80:01")
check("status is no_data", r["status"], "no_data")
check("no vendor is claimed", r["vendor"], None)
check("and it says what to run", "update_oui" in r["note"], True)


print("\n[2] a randomized address needs no registry at all")
# Locally administered bit set. There is no vendor to find, so this answer is
# correct even with no file on disk, and it must not depend on one.
r = oui.lookup("02:11:22:33:44:55")
check("status is randomized", r["status"], "randomized")
check("no vendor", r["vendor"], None)
check("the note says no vendor CAN exist", "none can be" in r["note"], True)
check("the bit test agrees", oui.is_locally_administered("02:11:22:33:44:55"),
      True)
check("and a burned in address is not locally administered",
      oui.is_locally_administered("5c:41:5a:80:80:01"), False)


print("\n[3] rubbish in does not become a vendor")
for bad in (None, "", "not-a-mac", "5C:41:5A", "zz:zz:zz:zz:zz:zz"):
    r = oui.lookup(bad)
    check(f"{bad!r} is unparseable", r["status"], "unparseable")


# A tiny registry, shaped exactly like IEEE's real CSV.
(tmp / "oui.csv").write_text(
    "Registry,Assignment,Organization Name,Organization Address\n"
    "MA-L,5C415A,Example Devices Inc,Somewhere\n"
    "MA-L,ACDE48,Another Vendor Ltd,Elsewhere\n",
    encoding="utf-8")
# And a longer prefix carved out of the SAME block, which is the case that
# breaks a naive lookup: 5C415A is claimed by two companies at two lengths.
(tmp / "mam.csv").write_text(
    "Registry,Assignment,Organization Name,Organization Address\n"
    "MA-M,5C415A9,Small Vendor Co,Elsewhere\n",
    encoding="utf-8")
oui.reload()


print("\n[4] a registered prefix resolves")
r = oui.lookup("5c:41:5a:80:80:01")
check("vendor found", r["vendor"], "Example Devices Inc")
check("status is resolved", r["status"], "resolved")
check("case and separators do not matter",
      oui.lookup("5C-41-5A-80-86-A5")["vendor"], "Example Devices Inc")
check("so does no separator at all",
      oui.lookup("5c415a8086a5")["vendor"], "Example Devices Inc")


print("\n[5] THE POINT: the longer prefix wins")
# MA-M and MA-S are blocks carved out of an MA-L. Matching the short one first
# would attribute a small vendor's device to whoever owns the parent block,
# which is a confident wrong answer rather than a gap.
check("the 28 bit registration beats the 24 bit one",
      oui.lookup("5c:41:5a:98:80:01")["vendor"], "Small Vendor Co")
check("and an address outside it still gets the parent",
      oui.lookup("5c:41:5a:80:80:01")["vendor"], "Example Devices Inc")


print("\n[6] a prefix genuinely absent from a LOADED registry")
r = oui.lookup("00:11:22:33:44:55")
check("status is unknown_prefix", r["status"], "unknown_prefix")
check("which is NOT the same string as no_data",
      r["status"] == "no_data", False)
check("no vendor invented", r["vendor"], None)


print("\n[7] a broken registry file does not raise, it degrades")
# A holding page written over the CSV, which is exactly what a captive portal
# or a failed download produces. It must behave like no_data, not crash a
# device listing.
(tmp / "oui.csv").write_text("<html>we are down</html>", encoding="utf-8")
(tmp / "mam.csv").unlink()
oui.reload()
r = oui.lookup("5c:41:5a:80:80:01")
check("falls back to no_data", r["status"], "no_data")
check("status() reports not ready", oui.status()["ready"], False)


print("\n[8] the device rows carry it, so nothing has to remember to ask")
# The reason this is not a model tool. The address was in the row all along
# on 2026-09-01 and the identification still went wrong.
(tmp / "oui.csv").write_text(
    "Registry,Assignment,Organization Name,Organization Address\n"
    "MA-L,5C415A,Example Devices Inc,Somewhere\n",
    encoding="utf-8")
oui.reload()

from core import memory_engine as me           # noqa: E402
rows = me._with_identity_class([
    {"ip": "192.0.2.5", "mac": "5c:41:5a:80:80:01"},
    {"ip": "192.0.2.6", "mac": "02:11:22:33:44:55"},
    {"ip": "192.0.2.7", "mac": None},
])
check("a burned in address gets its vendor",
      rows[0]["vendor"], "Example Devices Inc")
check("and still gets its identity class",
      rows[0]["identity_class"], "stable_host")
check("a randomized one gets no vendor but says why",
      rows[1]["vendor_status"], "randomized")
check("and is still transient_client",
      rows[1]["identity_class"], "transient_client")
check("no address at all is unparseable, not unknown",
      rows[2]["vendor_status"], "unparseable")


print("\n[9a] the Wireshark manuf file works as a fallback source")
# Added 2026-09-02 after IEEE answered the update script with HTTP 418 on all
# three files. One source and one format was a single point of failure for
# something whose whole point is working offline forever.
for f in ("oui.csv", "mam.csv"):
    if (tmp / f).exists():
        (tmp / f).unlink()
(tmp / "manuf").write_text(
    "# a comment\n"
    "\n"
    "5C:41:5A\tAmazon\tAmazon Technologies Inc.\n"
    "00:55:DA:80:00:00/28\tSmallCo\tSmall Company Ltd\n"
    "AC:DE:48\tPrivate\n",
    encoding="utf-8")
oui.reload()
r = oui.lookup("5c:41:5a:80:80:01")
check("the 24 bit prefix resolves", r["vendor"], "Amazon Technologies Inc.")
# The whole section this test belongs to is about claims having a source
# behind them. It would be a poor joke for the lookup itself not to say
# where its answer came from.
check("and it says which file said so", r["source"], "manuf")
check("the /28 form lands in the 28 bit bucket",
      oui.lookup("00:55:DA:81:00:00")["vendor"], "Small Company Ltd")
check("an address outside that block is not given its name",
      oui.lookup("00:55:DA:91:00:00")["status"], "unknown_prefix")
check("a two field line still works",
      oui.lookup("AC:DE:48:11:22:33")["vendor"], "Private")

# Put the CSV back for the last group.
(tmp / "oui.csv").write_text(
    "Registry,Assignment,Organization Name,Organization Address\n"
    "MA-L,5C415A,Example Devices Inc,Somewhere\n",
    encoding="utf-8")
oui.reload()
check("IEEE wins over manuf where both have the prefix",
      oui.lookup("5c:41:5a:80:80:01")["vendor"], "Example Devices Inc")
check("and the source says so", oui.lookup("5c:41:5a:80:80:01")["source"],
      "oui.csv")


print("\n[9] an existing vendor is never overwritten")
# A scan or a person looked at the device. The registry only knows who made
# the network chip, which on plenty of hardware is not the brand on the box.
# The two are shown side by side so a disagreement is visible.
row = me._stamp_vendor({"ip": "192.0.2.5", "mac": "5c:41:5a:80:80:01",
                        "vendor": "Brand On The Box"})
check("the recorded vendor survives", row["vendor"], "Brand On The Box")
check("the registry answer is kept separately",
      row["registry_vendor"], "Example Devices Inc")
check("and it is labelled as already recorded",
      row["vendor_status"], "already_recorded")


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
