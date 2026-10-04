"""
tests/test_expected_ports.py, the owner can say "that port is fine" and be
believed, without silencing anything else.

WHY THIS EXISTS, 2026-09-02.

The owner identified a device, said it was the owner's, and the open-port finding on
it stayed at high anyway. Naming a device says nothing about which of its
ports are normal, so the tool asked the owner about the same port three sessions
running, and by the third the owner was, fairly, annoyed.

The risk in fixing that is obvious: a mechanism for silencing alarms is a
mechanism for silencing alarms. So most of this file is about how NARROW it
is. Declaring 8888 normal on one device must not touch 8888 anywhere else,
must not touch any other port on that device, and must not stop the port
being recorded at all.
"""
import json
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

ECHO = "192.0.2.23"
TV = "192.0.2.24"
me.save_known_device(ip=ECHO, mac="5c:41:5a:80:80:01", known_as="Amazon device")
me.save_known_device(ip=TV, mac="00:11:22:33:44:55", known_as="LG TV")


print("\n[1] nothing is expected until somebody says so")
# The column lands empty on every device, so the day this shipped it changed
# no behaviour anywhere.
check("no declarations to start", me.expected_ports(ECHO), {})
check("and nothing is expected", me.is_port_expected(ECHO, 8888), None)


print("\n[2] a declaration needs a reason")
# Not decoration. Six months from now this is the only thing that says whether
# a port stopped raising because somebody decided it or because somebody was
# tired.
for bad in (None, "", "   "):
    try:
        me.declare_expected_port(ECHO, 8888, bad)
        check(f"reason {bad!r} was rejected", "accepted", "ValueError")
    except ValueError:
        check(f"reason {bad!r} was rejected", "ValueError", "ValueError")


print("\n[3] and the device has to be in the inventory first")
# Saying which of a device's ports are normal only means something once
# somebody has said what the device IS.
try:
    me.declare_expected_port("192.0.2.22", 8888, "no idea what this is")
    check("an unknown device is refused", "accepted", "ValueError")
except ValueError:
    check("an unknown device is refused", "ValueError", "ValueError")


print("\n[4] declaring it records who, when and why")
entry = me.declare_expected_port(ECHO, 8888,
                                 "Echo devices listen here, owner confirmed")
check("the reason is kept", entry["reason"],
      "Echo devices listen here, owner confirmed")
check("and who said it", entry["declared_by"], "user")
check("there is a timestamp", bool(entry["declared_at"]), True)
check("and it reads back", me.is_port_expected(ECHO, 8888)["reason"],
      "Echo devices listen here, owner confirmed")


print("\n[5] THE POINT: it is as narrow as it looks")
# Every one of these is a way a silencing mechanism goes wrong by being wider
# than the sentence the person said.
check("another port on the SAME device still raises",
      me.is_port_expected(ECHO, 22), None)
check("the SAME port on another device still raises",
      me.is_port_expected(TV, 8888), None)
me.declare_expected_port(TV, 443, "smart TV web UI")
check("a second device's declaration is its own",
      me.is_port_expected(TV, 443)["reason"], "smart TV web UI")
check("and it did not leak onto the first",
      me.is_port_expected(ECHO, 443), None)


print("\n[6] it silences the FINDING, not the observation")
# The rule the owner set for the safe list on 2026-08-31: it silences one
# specific alert and everything else about the device still applies. The port
# must remain visible, with the reason attached.
row = me.query_known_devices(ip=ECHO)[0]
stored = json.loads(row["expected_ports"])
check("the declaration is on the device row", "8888" in stored, True)
check("so a reader can see it without asking",
      stored["8888"]["reason"], "Echo devices listen here, owner confirmed")


print("\n[7] the scanner checks it before raising, not before recording")
src = (ROOT / "tools" / "port_scanner.py").read_text(encoding="utf-8")
check("the scanner asks", "is_port_expected" in src, True)
check("and the finding is what it skips",
      "if not expected and SEVERITY_ORDER.index(risk) >= floor" in src, True)
check("the port is still written to port_scan_results",
      "save_port_scan_result" in src, True)
check("with the declaration attached to it",
      "DECLARED EXPECTED on this device by" in src, True)


print("\n[8] the model cannot declare one")
# The important one. A model that can mark its own findings expected has a
# path to silencing itself, which is 8.1F one layer up. There is no tool for
# this and there must not be.
from core import tool_registry as tr        # noqa: E402
names = {t["name"] for t in tr.TOOL_MANIFEST}
check("no declare tool in the manifest",
      any("expect" in n for n in names), False)


print("\n[9] it is journalled, both directions")
# Anything that stops an alarm belongs beside the dismissals. Withdrawing it
# too, so the pair reads as a history rather than a state.
with sqlite3.connect(db) as conn:
    ops = [r[0] for r in conn.execute(
        "SELECT operation FROM integrity_journal").fetchall()]
check("declaring is journalled", "port_expectation_declared" in ops, True)

check("withdrawing works", me.undeclare_expected_port(ECHO, 8888), True)
check("and the port raises again", me.is_port_expected(ECHO, 8888), None)
check("withdrawing a second time says nothing to do",
      me.undeclare_expected_port(ECHO, 8888), False)
with sqlite3.connect(db) as conn:
    ops = [r[0] for r in conn.execute(
        "SELECT operation FROM integrity_journal").fetchall()]
check("withdrawing is journalled too",
      "port_expectation_withdrawn" in ops, True)
check("the other device's declaration survived the withdrawal",
      me.is_port_expected(TV, 443)["reason"], "smart TV web UI")


print("\n[10] a corrupt declaration does not silence anything")
# Failing to suppress produces a noisy finding. Failing the other way hides
# one. Only one of those is acceptable, so a value that cannot be read must
# mean "nothing is expected".
with sqlite3.connect(db) as conn:
    conn.execute("UPDATE known_devices SET expected_ports = ? WHERE ip = ?",
                 ("{not json at all", TV))
    conn.commit()
check("unreadable JSON expects nothing", me.expected_ports(TV), {})
check("so the port raises again", me.is_port_expected(TV, 443), None)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
