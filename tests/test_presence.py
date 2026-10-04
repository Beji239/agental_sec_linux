"""
tests/test_presence.py, presence sweep checks, against a synthetic database.

Deliberately checks the negative cases harder than the positive ones. A
presence table that reports everything as present passes any positive test
ever written; the value is entirely in what it refuses to claim.
"""
import sys, tempfile, sqlite3, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

tmp = tempfile.mkdtemp()
db = pathlib.Path(tmp) / "t.db"

from core import memory_engine as me
me.DB_PATH = db

# Build the schema the way a fresh install does, then run the migration over
# it to prove the migration is idempotent against an already-current file.
schema = (ROOT / 'Schema.SQL').read_text(encoding='utf-8')
c = sqlite3.connect(db); c.executescript(schema); c.commit(); c.close()

from core import migrations
r1 = migrations.run_migrations(db)
r2 = migrations.run_migrations(db)
print(f"migration pass 1: {r1.get('status')}  pass 2: {r2.get('status')}")

conn = sqlite3.connect(db)
have = {r[0] for r in conn.execute(
    "SELECT name FROM sqlite_master WHERE type='table'")}
assert "presence_sweep" in have and "presence_observation" in have, have
conn.close()

fails = []
def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)

SID = "test-session"

print("\n[1] no sweeps at all must not read as absence")
res = me.query_presence()
check("devices returned", res["devices"], [])
check("sweeps counted", res["window"]["sweeps_counted"], 0)
assert "nothing looked" in res["note"], res["note"]
print("       note says nothing looked, not that devices are missing")

print("\n[2] a failed sweep is recorded and never counted")
me.record_presence_sweep(session_id=SID, method="icmp+arp", outcome="failed",
                         detail="no subnet", targets=0)
res = me.query_presence()
check("usable sweeps", res["window"]["sweeps_counted"], 0)
check("failed excluded", res["window"]["sweeps_failed_and_excluded"], 1)

print("\n[3] 40 sweeps: A always, B stops after 30, C arp-only, D never")
for i in range(40):
    responders = [{"ip": "198.51.100.10", "mac": "aa:bb:cc:00:00:01", "via": "both"}]
    if i < 30:
        responders.append({"ip": "198.51.100.20", "mac": "aa:bb:cc:00:00:02", "via": "icmp"})
    responders.append({"ip": "198.51.100.30", "mac": "aa:bb:cc:00:00:03", "via": "arp"})
    me.record_presence_sweep(session_id=SID, method="icmp+arp", outcome="ok",
                             subnet="198.51.100.0/24", targets=254,
                             responders=responders)

res = me.query_presence()
by_ip = {d["ip"]: d for d in res["devices"]}
check("sweeps counted", res["window"]["sweeps_counted"], 40)
check("A present_in", by_ip["198.51.100.10"]["present_in"], 40)
check("A absent_streak", by_ip["198.51.100.10"]["absent_streak"], 0)
check("B present_in", by_ip["198.51.100.20"]["present_in"], 30)
check("B absent_streak (the finding)", by_ip["198.51.100.20"]["absent_streak"], 10)
check("B rate still high", by_ip["198.51.100.20"]["presence_rate"], 0.75)
check("C arp_only_sweeps", by_ip["198.51.100.30"]["arp_only_sweeps"], 40)
check("D absent entirely, not listed", "198.51.100.40" in by_ip, False)

print("       ordering puts the longest absence first:",
      [d['ip'] for d in res['devices']][:2])
check("B ranked above A", res["devices"][0]["ip"], "198.51.100.20")

print("\n[4] an explicitly asked-for absent address returns 0-of-N, not nothing")
res = me.query_presence(ip="198.51.100.40")
check("row returned", len(res["devices"]), 1)
check("present_in", res["devices"][0]["present_in"], 0)
check("of_sweeps carried", res["devices"][0]["of_sweeps"], 40)
check("absent_streak", res["devices"][0]["absent_streak"], 40)

print("\n[5] a thin denominator says so instead of quoting a rate")
db2 = pathlib.Path(tmp) / "t2.db"
me.DB_PATH = db2
c = sqlite3.connect(db2); c.executescript(schema); c.commit(); c.close()
# sensor_id carries a foreign key, as every observation table here does, so a
# sweep can only be written once this instance has registered its vantage
# point. main.py does that before any collector starts. Worth knowing how it
# fails if that were ever not true: the write raises, nothing is recorded, and
# query_presence reports that nothing looked. It does not report absence.
from core import sensors as sn
sn.register_local()
me.record_presence_sweep(session_id=SID, method="icmp+arp", outcome="ok",
                         subnet="198.51.100.0/24", targets=254,
                         responders=[{"ip": "198.51.100.10", "via": "icmp"}])
res = me.query_presence()
check("one sweep counted", res["window"]["sweeps_counted"], 1)
check("rate is 1.0 but denominator is 1", res["devices"][0]["of_sweeps"], 1)
assert "too few" in res["note"], res["note"]
print("       note warns the denominator is too thin to call a pattern")

print("\n[6] a failed sweep may not smuggle in responders")
try:
    me.record_presence_sweep(session_id=SID, method="icmp+arp", outcome="failed",
                             responders=[{"ip": "198.51.100.99", "via": "icmp"}])
    check("rejected", False, True)
except ValueError:
    print("  PASS  rejected, as it must be")

print("\n[7] dispatch reaches it through execute_tool")
me.DB_PATH = db
from core import tool_registry as tr
out = tr.execute_tool("query_presence", {"ip": "198.51.100.20"})
check("no error", out["error"], None)
check("through dispatch, absent_streak", out["result"]["devices"][0]["absent_streak"], 10)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
