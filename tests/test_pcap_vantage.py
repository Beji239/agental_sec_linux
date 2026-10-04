"""
tests/test_pcap_vantage.py, 24.2, imports carry a vantage point.

pcap_results.sensor_id existed since the vantage work and nothing ever filled
it, so every imported capture sat in the database with no position at all. The
model then read findings from somebody else's file exactly as it reads this
host's own traffic.

What is checked, in order of what goes wrong if it breaks:

  an import registers a sensor and the row is stamped with it
  the position is ALWAYS offline, whatever the operator claims
  the operator's claim is kept, as a claim, in notes
  the scope travels back with the findings, not on request
  an old row with no sensor is labelled unknown, never given the host's scope
  re-importing the same file reuses one sensor rather than growing rows
  nothing local ends up in the sensor id
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

SID = "test-session"
KEY = "capture.pcap:4096:1788000000"
SPAN = "SPAN port on the office switch"


print("\n[1] an import registers a sensor, and the row is stamped with it")
sid1 = sn.register_offline(KEY, origin=SPAN)
me.save_pcap_result(session_id=SID, file_path="capture.pcap",
                    packet_count=10, duration_seconds=1.0,
                    result_json={"x": 1}, sensor_id=sid1)
rows = me.query_pcap_results()
check("one result", len(rows), 1)
check("it has a sensor", rows[0]["sensor_id"], sid1)


print("\n[2] THE CENTRAL ONE: the position is offline whatever was claimed")
# A capture the operator says came from a SPAN port must NOT register as
# 'mirror'. That position promises same-segment unicast was visible, and
# believing it about a file nobody here produced turns "not in the capture"
# into "did not happen", on the strength of a sentence in a text box.
check("position is offline", rows[0]["position"], "offline")
check("scope still admits it does not know",
      "unknown" in (rows[0]["cannot_see"] or "").lower(), True)


print("\n[3] the claim is kept, as a claim")
check("origin is in the notes", SPAN in (rows[0]["sensor_notes"] or ""), True)
check("and it is marked as the operator saying so",
      "Operator says" in (rows[0]["sensor_notes"] or ""), True)


print("\n[4] an import with no origin invents nothing, and erases nothing")
# The position's own scope already says the reach of an imported file is
# unknown, so there is no need to write a sentence saying it twice.
sid2 = sn.register_offline("other.pcap:99:1", origin=None)
with sqlite3.connect(db) as c:
    note = c.execute("SELECT notes FROM sensors WHERE sensor_id=?",
                     (sid2,)).fetchone()[0]
check("no origin means no note", note, None)

# THE ONE THAT BIT. Re-importing the same capture from a script that passes no
# origin must not wipe an origin a person recorded earlier. Found by running
# the import twice, not by reading the code.
sn.register_offline(KEY, origin=None)
with sqlite3.connect(db) as c:
    kept = c.execute("SELECT notes FROM sensors WHERE sensor_id=?",
                     (sid1,)).fetchone()[0]
check("the earlier claim survives a re-import", SPAN in (kept or ""), True)

sid_blank = sn.register_offline("blank.pcap:1:1", origin="   ")
with sqlite3.connect(db) as c:
    note_blank = c.execute("SELECT notes FROM sensors WHERE sensor_id=?",
                           (sid_blank,)).fetchone()[0]
check("whitespace counts as no origin", note_blank, None)


print("\n[5] a row written before any of this is labelled unknown")
# Not given the local sensor's scope. A pcap row with the host's scope would
# claim this machine observed the file, which is the mistake the whole change
# exists to stop.
me.save_pcap_result(session_id=SID, file_path="old.pcap", packet_count=5,
                    duration_seconds=1.0, result_json={}, sensor_id=None)
old = [r for r in me.query_pcap_results(limit=50)
       if r["file_path"] == "old.pcap"][0]
check("position reads unrecorded", old["position"], "unrecorded")
check("not stamped with the local sensor", old["sensor_id"], None)
check("and it says absence proves nothing",
      "supports any conclusion" in (old["cannot_see"] or "").lower(), True)


print("\n[6] re-importing the same file reuses one sensor")
again = sn.register_offline(KEY, origin=SPAN)
with sqlite3.connect(db) as c:
    n = c.execute("SELECT COUNT(*) FROM sensors WHERE sensor_id=?",
                  (again,)).fetchone()[0]
check("same id", again, sid1)
check("one row, not two", n, 1)


print("\n[7] the sensor id leaks nothing about the machine")
# The same argument as LOCAL_SENSOR_ID. A file path names somebody's folder,
# and check_no_local_details would be right to fail a build over one sitting
# in a database row.
leaky = sn.offline_sensor_id("C:/Users/someone/Desktop/secret_folder/x.pcap")
check("id is a hash", leaky.startswith("offline-"), True)
check("no path in it", "Users" in leaky or "secret" in leaky, False)
check("fixed length", len(leaky), len("offline-") + 12)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
