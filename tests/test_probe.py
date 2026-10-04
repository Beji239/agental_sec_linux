"""
tests/test_probe.py, the device inventory probe, schema v15.

The probe originates traffic aimed at somebody else's hardware, so most of
what matters here is what it DECLINES to do: not probing outside its cadence,
not probing an excluded address, not probing more hosts in one pass than the
rate limit allows, and not retiring a device on a handful of samples.

It also pins the finding rule decided 2026-08-28: Python raises a finding only
where the USER declared an expectation. Absence and drift qualify. DNS novelty
does not, and that is asserted here so it cannot drift back in later.
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

from core import sensors as sn
sn.register_local()
from tools.probe import DeviceProbe

SID = "test-session"


def sweep(responders):
    me.record_presence_sweep(session_id=SID, method="icmp+arp", outcome="ok",
                             subnet="198.51.100.0/24", targets=254,
                             responders=[{"ip": ip, "via": "icmp"} for ip in responders])


print("\n[1] schema v15 is present and the migration is idempotent")
conn = sqlite3.connect(db)
have = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
cols = {r[1] for r in conn.execute("PRAGMA table_info(known_devices)")}
conn.close()
check("probe_run table", "probe_run" in have, True)
check("retired_at column", "retired_at" in cols, True)
check("second migration is a no-op", r2.get("status"), "current")


print("\n[2] the cadence is honoured, and a skip is recorded as a skip")
probe = DeviceProbe(SID, {"probe": {"interval_days": 21, "pacing_seconds": 0}})
check("due on a database that has never probed", probe.due(), True)

probe.run_once()                      # first real pass
check("no longer due immediately after", probe.due(), False)
res = probe.run_once()                # second call, inside the cadence
check("second call skips", res["outcome"], "skipped")

runs = me.query_findings  # noqa: F841  (placeholder to keep imports honest)
conn = sqlite3.connect(db); conn.row_factory = sqlite3.Row
outcomes = [r["outcome"] for r in conn.execute(
    "SELECT outcome FROM probe_run ORDER BY id")]
conn.close()
check("a skipped pass leaves a row, not silence", "skipped" in outcomes, True)
check("and 'the probe has not run in weeks' is answerable",
      me.last_probe_run("ok") is not None, True)


print("\n[3] the exclusion list is honoured even for a permanent device")
me.save_known_device(ip="198.51.100.10", mac="b8:27:eb:11:22:33", hostname="printer")
me.save_known_device(ip="198.51.100.11", mac="dc:a6:32:11:22:33", hostname="camera")
me.set_device_permanence("198.51.100.10", True)
me.set_device_permanence("198.51.100.11", True)
check("both are permanent", len(me.permanent_devices()), 2)

excluded_probe = DeviceProbe(SID, {"probe": {
    "pacing_seconds": 0, "exclusion_list": ["198.51.100.11"]}})
res = excluded_probe.run_once(force=True)
check("the excluded device is counted apart", res["excluded"], 1)
check("and only the other one was probed", res["probed"], 1)


print("\n[4] the rate limit defers rather than dropping")
for n in range(20, 26):
    me.save_known_device(ip=f"198.51.100.{n}", mac=f"b8:27:eb:11:22:{n}")
    me.set_device_permanence(f"198.51.100.{n}", True)
limited = DeviceProbe(SID, {"probe": {"pacing_seconds": 0, "max_hosts_per_pass": 3}})
res = limited.run_once(force=True)
check("probed the cap, not more", res["probed"], 3)
check("the rest are deferred, not lost",
      res["deferred"], res["eligible"] - 3)
check("eligible + excluded reconcile", res["eligible"], len(me.permanent_devices()))


print("\n[5] drift on an ENROLLED device raises a finding (declared expectation)")
me.save_known_device(ip="198.51.100.30", mac="44:27:45:11:22:33", hostname="tv")
for p in (80, 443):
    me.save_port_scan_result(session_id=SID, target_host="198.51.100.30",
                             port=p, state="open", risk_level="low")
me.set_device_permanence("198.51.100.30", True)

before = len(me.query_findings(source="probe", limit=500))
me.save_port_scan_result(session_id=SID, target_host="198.51.100.30",
                         port=23, state="open", risk_level="high")
drift_probe = DeviceProbe(SID, {"probe": {"pacing_seconds": 0}})
res = drift_probe.run_once(force=True)
after = me.query_findings(source="probe", limit=500)
check("drift counted", res["drift_found"] >= 1, True)
check("a finding was raised", len(after) > before, True)
titles = [f["title"] for f in after]
check("and it names the device, not a verdict",
      any("Enrolled device changed" in t for t in titles), True)
body = next(f["description"] for f in after if "Enrolled device changed" in f["title"])
check("the description refuses to conclude", "not a verdict" in body, True)


print("\n[6] a device with NO enrollment fingerprint raises nothing")
me.save_known_device(ip="198.51.100.40", mac="70:85:c2:11:22:33")
me.set_device_permanence("198.51.100.40", True)
with me._get_conn() as conn:
    conn.execute("UPDATE known_devices SET enrollment_fingerprint = NULL "
                 "WHERE ip = ?", ("198.51.100.40",))
DeviceProbe(SID, {"probe": {"pacing_seconds": 0}}).run_once(force=True)
# Counted for THIS address specifically. The first version of this assertion
# compared total finding counts across a pass that also probes every other
# permanent device, so it failed on a finding correctly raised about a
# different, genuinely drifted host. The code was right and the test was
# imprecise, which is its own lesson: a count is not an assertion about a
# subject.
about_40 = [f for f in me.query_findings(source="probe", limit=500)
            if f["entity_value"] == "198.51.100.40"]
check("no baseline means no claim about THAT device", about_40, [])


print("\n[7] retirement needs enough samples, then fires exactly once")
probe = DeviceProbe(SID, {"probe": {"pacing_seconds": 0}})
check("nothing retired on a thin series", probe.retire_absent(), 0)

# Every permanent device answers, except the printer.
present = [f"198.51.100.{n}" for n in (11, 20, 21, 22, 23, 24, 25, 30, 40)]
for _ in range(me.RETIRE_AFTER_MISSES - 1):
    sweep(present)
check("still not retired one sweep short",
      probe.retire_absent(), 0)
check("and it is still marked permanent",
      me.query_known_devices(ip="198.51.100.10")[0]["is_permanent"], 1)

sweep(present)
check("retired on the threshold", probe.retire_absent(), 1)
row = me.query_known_devices(ip="198.51.100.10")[0]
check("permanence cleared", row["is_permanent"], 0)
check("retired_at stamped, distinguishing it from a manual un-vouch",
      row["retired_at"] is not None, True)
check("the fingerprint is KEPT so it can be recognised if it returns",
      row["enrollment_fingerprint"] is not None, True)
check("retiring again does nothing", probe.retire_absent(), 0)


print("\n[8] a merged appearance answering counts for its canonical device")
me.save_known_device(ip="198.51.100.60", mac="fc:65:de:11:22:33", hostname="phone")
me.save_known_device(ip="198.51.100.61", mac="02:11:11:11:11:01")
me.identify_device(ip="198.51.100.60", known_as="my phone",
                   evidence="test fixture", identified_by="user")
me.merge_devices("198.51.100.61", "198.51.100.60")

# Only the APPEARANCE answers. The canonical address never does.
sweep(["198.51.100.61"])
res = me.query_presence(ip="198.51.100.60")
row = res["devices"][0]
check("canonical device reads present", row["present_in"] >= 1, True)
check("and says which appearance answered for it",
      row["answered_by_appearances"], ["198.51.100.61"])


print("\n[9] the finding rule holds: DNS novelty raises nothing")
# Asserted at the source rather than by behaviour, because the correct
# behaviour here is the ABSENCE of a mechanism, and absence is what quietly
# grows a mechanism back later.
#
# UPDATED 2026-08-29. This used to grep the file for the string
# "save_finding" and expect no hits. TODO 8.4 then added a comment to
# dns_monitor explaining WHY it raises nothing, and the comment contains
# the word, so the test failed against the documentation of the thing it was
# checking. That was the fourth time in one day a check here read prose
# instead of code. It now parses the module and looks at the calls.
import ast as _ast
_dns = (ROOT / "tools" / "dns_monitor.py").read_text(encoding="utf-8")
_called = {
    n.func.attr for n in _ast.walk(_ast.parse(_dns))
    if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute)
}
check("dns_monitor raises no findings at all",
      "save_finding" in _called, False)
check("and the decision is now registered, not merely absent",
      "dns_novelty" in _dns, True)

probe_src = (ROOT / "tools" / "probe.py").read_text(encoding="utf-8")
check("the rule is written down where the next person will read it",
      "declared" in probe_src.lower(), True)
check("and the probe is not a model tool", "tool_registry" in probe_src, True)

from core import tool_registry as tr
names = [t["name"] for t in tr.TOOL_MANIFEST]
check("nothing in the manifest probes",
      [n for n in names if "probe" in n.lower()], [])


print("\n[10] a pass that blows up is recorded as failed, not as no change")
broken = DeviceProbe(SID, {"probe": {"pacing_seconds": 0}})
me.record_probe_run(SID, "failed", detail="synthetic")
conn = sqlite3.connect(db); conn.row_factory = sqlite3.Row
last = conn.execute("SELECT outcome, detail FROM probe_run "
                    "ORDER BY id DESC LIMIT 1").fetchone()
conn.close()
check("failure is on the record", last["outcome"], "failed")
check("a failed pass is not counted as a successful one",
      me.last_probe_run("ok")["outcome"], "ok")
try:
    me.record_probe_run(SID, "nonsense")
    check("bad outcome refused", False, True)
except ValueError:
    print("  PASS  bad outcome refused")


print("\n[11] THE HOMELAB CASE: the app is off for weeks and then comes back")
# This machine profile is the expected one, not the exception. The app runs
# for an hour, the machine is off for a month, the app runs again.
lab = tmp / "lab.db"
me.DB_PATH = lab
c = sqlite3.connect(lab); c.executescript(schema); c.commit(); c.close()
migrations.run_migrations(lab)
sn.register_local()

import datetime as _dt

def sweep_at(when, responders):
    """Write a sweep with an explicit timestamp, to fake a wall-clock gap."""
    sid_row = me.record_presence_sweep(
        session_id=SID, method="icmp+arp", outcome="ok",
        subnet="198.51.100.0/24", targets=254,
        responders=[{"ip": ip, "via": "icmp"} for ip in responders])
    with me._get_conn() as conn:
        conn.execute("UPDATE presence_sweep SET swept_at = ? WHERE id = ?",
                     (when.strftime("%Y-%m-%d %H:%M:%S"), sid_row))
    return sid_row

me.save_known_device(ip="198.51.100.70", mac="b8:27:eb:aa:bb:cc", hostname="nas")
me.set_device_permanence("198.51.100.70", True)

base = _dt.datetime(2026, 7, 1, 9, 0, 0)

# Run one: an hour of sweeps, and the NAS is quiet for the last few.
for i in range(12):
    sweep_at(base + _dt.timedelta(minutes=15 * i),
             ["198.51.100.70"] if i < 6 else [])

# The machine is then off for four weeks.
later = base + _dt.timedelta(days=28)

# Run two: another hour, still quiet.
for i in range(6):
    sweep_at(later + _dt.timedelta(minutes=15 * i), [])

res  = me.query_presence(ip="198.51.100.70")
win  = res["window"]
row  = res["devices"][0]

check("the gap is detected", win["series_gaps"], 1)
check("and its size is reported", win["largest_gap_hours"] > 600, True)
# Case-insensitive: the note says "NOT continuous" for emphasis, and an
# assertion that breaks on capitalisation tests the wrong thing.
check("the window says the series is not continuous",
      "not continuous" in (win.get("gap_note") or "").lower(), True)

# 6 misses before the shutdown + 6 after = 12 rows, but they are not
# consecutive in any sense a person means. The streak must stop at the gap.
check("the streak stops at the gap, it does not span four weeks",
      row["absent_streak"], 6)

print("\n[12] and the probe fires on the next boot after coming due")
probe = DeviceProbe(SID, {"probe": {"interval_days": 21, "pacing_seconds": 0}})
check("first ever run is due", probe.due(), True)
probe.run_once()
check("not due again immediately", probe.due(), False)

# Backdate the successful run by four weeks: the machine was off.
with me._get_conn() as conn:
    conn.execute("UPDATE probe_run SET started_at = ? WHERE outcome = 'ok'",
                 ((_dt.datetime.utcnow() - _dt.timedelta(days=28))
                  .strftime("%Y-%m-%d %H:%M:%S"),))
check("four weeks later it is overdue again", probe.due(), True)
check("and age is wall clock, not uptime", round(probe.age_days()) >= 27, True)
check("status surfaces how stale the inventory is",
      probe.status()["overdue"], True)

me.DB_PATH = db

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
