"""
tests/test_self_induced.py, the tool must not read its own footprints as
the network's behaviour.

WHAT HAPPENED, 2026-09-02.

The model port scanned a device on the LAN, then queried the packet table,
saw rows with source port 27017 and 32400 going to ephemeral ports on this
host, and told the owner the device was "actively probing THIS host's ports
27017 and 32400". It called it a scanner pattern.

Those rows are the scanned device answering with RST because the port was
closed. It read the reply leg of its own scan as unsolicited hostile
activity, and did it while the owner was telling it the device was the owner's.

That is worse than the wrong device label the same session produced. A wrong
label is a wrong answer. This is a FALSE ALARM ABOUT AN ATTACK, aimed at the
owner, manufactured by the tool's own actions. A security tool that alarms on
its own footprints teaches its operator to stop reading alarms.

So: port_scan_run records the window, query_packets stamps self_induced, and
the tool description says what it means. All three have to hold or the flag
is decoration.
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

SID = "scan-session"
TARGET = "192.0.2.23"
HOST = "192.0.2.29"
OTHER = "192.0.2.24"


def packet(src, dst, at, src_port=None, dst_port=None, flags=None):
    with sqlite3.connect(db) as conn:
        conn.execute(
            "INSERT INTO packets (session_id, captured_at, src_ip, dst_ip, "
            "src_port, dst_port, protocol, direction, scope, flags) "
            "VALUES (?,?,?,?,?,?,'TCP','inbound','private_to_private',?)",
            (SID, at, src, dst, src_port, dst_port, flags))
        conn.commit()


print("\n[1] a scan run is recorded before anything goes out")
run_id = me.start_port_scan_run(session_id=SID, target_host=TARGET,
                                port_count=1062, port_set="extended")
check("it returns a run id", isinstance(run_id, int), True)
with sqlite3.connect(db) as conn:
    row = conn.execute(
        "SELECT target_host, port_count, finished_at FROM port_scan_run "
        "WHERE id = ?", (run_id,)).fetchone()
check("the target is recorded", row[0], TARGET)
check("so is how many ports", row[1], 1062)
# The row exists while the scan is still running. A scan that crashes still
# put packets on the wire and still needs a window that explains them.
check("and finished_at is open until it closes", row[2], None)

with sqlite3.connect(db) as conn:
    started = conn.execute(
        "SELECT started_at FROM port_scan_run WHERE id = ?",
        (run_id,)).fetchone()[0]
    conn.execute("UPDATE port_scan_run SET finished_at = "
                 "datetime(started_at, '+30 seconds') WHERE id = ?", (run_id,))
    conn.commit()
    ends = conn.execute("SELECT finished_at FROM port_scan_run WHERE id = ?",
                        (run_id,)).fetchone()[0]

inside = ends            # right at the end of the scan, still ours
before = started         # the moment it began
after_tail = None
with sqlite3.connect(db) as conn:
    after_tail = conn.execute(
        "SELECT datetime(?, '+60 seconds')", (ends,)).fetchone()[0]


print("\n[2] THE CASE FROM THE TRANSCRIPT: a RST reply is not the device"
      " probing us")
# Source port 27017 to an ephemeral port. This is exactly the row the model
# read as "the device is probing this host's MongoDB port".
packet(TARGET, HOST, inside, src_port=27017, dst_port=64251, flags='{"RA":1}')
packet(TARGET, HOST, inside, src_port=32400, dst_port=64253, flags='{"RA":1}')
# And the outgoing half of the same scan.
packet(HOST, TARGET, inside, src_port=64251, dst_port=27017, flags='{"S":1}')

rows = me.query_packets(session_id=SID, all_sessions=True, limit=50)
marked = [r for r in rows if r.get("self_induced")]
check("all three legs are marked", len(marked), 3)
check("including the reply from the device", all(
    r["self_induced"] for r in rows
    if r.get("src_ip") == TARGET and r.get("src_port") in (27017, 32400)), True)
check("and the note says not to report it as the device's behaviour",
      "must not be reported as its behaviour" in marked[0]["self_induced_note"],
      True)


print("\n[3] traffic outside the window is NOT ours")
# The same device, the same shape of packet, well after the scan finished.
# This is the case the flag must not swallow: if everything near a scan target
# got marked, a real connection from that device would be hidden, which is the
# dangerous direction for this particular flag.
packet(TARGET, HOST, after_tail, src_port=27017, dst_port=64299,
       flags='{"RA":1}')
rows = me.query_packets(session_id=SID, all_sessions=True, limit=50)
late = [r for r in rows if r.get("dst_port") == 64299]
check("the late packet is not marked", late[0]["self_induced"], False)


print("\n[4] a different device inside the same window is NOT ours")
# We scanned .124. Nothing about that makes the TV's traffic ours.
packet(OTHER, HOST, inside, src_port=443, dst_port=51000, flags='{"A":1}')
rows = me.query_packets(session_id=SID, all_sessions=True, limit=50)
tv = [r for r in rows if r.get("src_ip") == OTHER]
check("the other device is untouched", tv[0]["self_induced"], False)


print("\n[5] every row carries the key, present and false")
# A missing key reads as "this tool does not know about self-induced traffic",
# which is a different claim from "no scan explains this row". Same rule as
# the null payload key in test_packet_payload_scope.
check("the key is on every row",
      all("self_induced" in r for r in rows), True)


print("\n[6] an unfinished run still covers its traffic")
# A scan that hung or was killed leaves finished_at NULL. Treating that as a
# zero length window would mark nothing, and failing to mark is the direction
# that produces the false alarm.
open_run = me.start_port_scan_run(session_id=SID, target_host=OTHER,
                                  port_count=10, port_set="common")
with sqlite3.connect(db) as conn:
    at = conn.execute("SELECT datetime(started_at, '+120 seconds') "
                      "FROM port_scan_run WHERE id = ?",
                      (open_run,)).fetchone()[0]
packet(OTHER, HOST, at, src_port=6379, dst_port=64400, flags='{"RA":1}')
rows = me.query_packets(session_id=SID, all_sessions=True, limit=50)
hung = [r for r in rows if r.get("dst_port") == 64400]
check("traffic during an unfinished scan is still ours",
      hung[0]["self_induced"], True)


print("\n[7] the model is TOLD what the flag means")
# 27.3's rule. A rule the code follows and the description does not mention is
# a rule the model will break, and here it would break it by reporting our own
# scan as an attack, which is exactly what it did.
from core import tool_registry as tr        # noqa: E402
desc = {t["name"]: t for t in tr.TOOL_MANIFEST}["query_packets"]["description"]
check("it says some rows are our own footprints",
      "self_induced" in desc, True)
check("it covers the reply leg, not just the probe",
      "the target's answer coming back" in desc, True)
check("it forbids reporting one as the device's behaviour",
      "never cite it as evidence about the device's behaviour" in desc, True)
check("and it says false is not a guarantee",
      "NO RECORDED SCAN EXPLAINS THIS ROW" in desc, True)


print("\n[8] a scan does not raise a finding at all any more")
# THIS SECTION USED TO CHECK THE WORDING OF THAT FINDING. Changed 2026-09-06,
# TODO 38.5: the wording was the half fix and the owner closed the question the
# other way. A finding here is the tool reporting a condition it went looking
# for, landing in the review queue beside things that came from watching, and
# no title solves that. The observation stays, the alarm goes.
src  = (ROOT / "tools" / "port_scanner.py").read_text(encoding="utf-8")
body = src.split("def scan(", 1)[1]
check("nothing in the scan saves a finding", "save_finding" in body, False)
check("the open port is still recorded",
      "save_port_scan_result" in body, True)
check("and the answer says why there is no finding",
      "raises no findings" in body, True)
# What raises instead is a device nobody can account for, which is the queue
# this belongs in. network_scanner owns that one.
netsrc = (ROOT / "tools" / "network_scanner.py").read_text(encoding="utf-8")
check("an unidentified device still raises",
      "This device has no recorded identification" in netsrc, True)
check("and it names the ask-then-ban path", "block_device" in netsrc, True)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
