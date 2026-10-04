"""
tests/test_baseline_retract.py, withdrawing what a baseline LEARNED.

TODO 93, 2026-09-13. Closes the gap 45.5 named.

supersede_observation could withdraw a session observation, but run_rollup
reads current observations only, so the withdrawal kept that row out of FUTURE
merges and did nothing about the baseline that had already eaten it.
behavioral_baseline is cumulative and forward only. You could retract the
sentence and not the belief it produced.

45.5 OVERSTATED IT, and the correction is worth carrying. revert_suppression
already existed, ungated, live, backing the Review dashboard, so the dangerous
half, a baseline SILENCING alerts, was always undoable. What could not be
undone is the learned content: mean, typical hours, typical ports, and the
session count behind confidence.

THE SUBTLE HALF, and getting it wrong would have made this look like it
worked: sample_count is DERIVED from baseline_session_seen. Clear the baseline
row alone and the count survives, so the very next observation comes straight
back at the old confidence as if nothing had been withdrawn. Section [3] is
that check and it is the reason this file exists.

Builds a temp database from the REAL Schema.SQL, so a schema that does not
carry the v29 columns fails here rather than at runtime on the owner's machine.
Runs anywhere.
"""
import os
import pathlib
import re
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


DB = os.path.join(tempfile.mkdtemp(), "retract.db")
_conn = sqlite3.connect(DB)
_conn.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
_conn.commit()
_conn.close()

from core import memory_engine as me              # noqa: E402


class _Conn:
    def __enter__(self):
        self.c = sqlite3.connect(DB)
        self.c.row_factory = sqlite3.Row
        return self.c

    def __exit__(self, *a):
        self.c.commit()
        self.c.close()


me._get_conn = lambda *a, **k: _Conn()

# TODO 108, 2026-09-14. PATCHING _get_conn WAS NOT ISOLATION, it only looked
# like it. There are two ways into the database and this file closed one.
# observation_provenance goes through _get_readonly_conn, which opens DB_PATH
# directly, so this test was reading the REAL database on every run and
# passing because the real one happened to have the tables in it. It fails
# with "no such table: behavioral_session" on any machine where that file is
# absent or empty, and that failure is how the whole thing came to light.
# Pointing DB_PATH at the same temp file closes the other door, and any third
# one somebody adds later.
me.DB_PATH = DB

IP = "192.0.2.29"
KEY = "active_hours"


def row(key=KEY):
    got = me.query_behavioral_baseline(entity_type="ip", entity_value=IP,
                                       behavior_key=key)
    return got[0] if got else None


print("\n[1] the schema carries the v29 columns")
# If this fails, the migration and Schema.SQL have drifted apart and the owner's
# machine would take the ALTER while a fresh install would not have it.
with _Conn() as c:
    base_cols = {r[1] for r in c.execute("PRAGMA table_info(behavioral_baseline)")}
    seen_cols = {r[1] for r in c.execute("PRAGMA table_info(baseline_session_seen)")}
check("behavioral_baseline can be retracted",
      {"retracted_at", "retracted_reason"} <= base_cols, True)
check("and the session-seen rows can be stamped",
      "retracted_at" in seen_cols, True)

mig = (ROOT / "core" / "migrations.py").read_text(encoding="utf-8")
check("the migration exists too", "_migrate_baseline_retract" in mig, True)
check("and it is wired into the runner",
      "baseline_retract_added = _migrate_baseline_retract(conn)" in mig, True)
# PARSED, NOT PINNED. 2026-09-14. This asserted the literal "SCHEMA_VERSION
# = 29" and went red the moment TODO 98 bumped it to 30 for a column that has
# nothing to do with baselines. test_important_findings had the identical
# stale assertion and was fixed the same way on 2026-09-13. A test that
# breaks when an unrelated feature migrates is a test nobody trusts.
_ver = re.search(r"SCHEMA_VERSION\s*=\s*(\d+)", mig)
check("schema version is at least the one this feature needs",
      int(_ver.group(1)) >= 29 if _ver else None, True)


print("\n[2] a baseline is built the ordinary way first")
for sid in ("s1", "s2", "s3", "s4"):
    n = me.record_baseline_session("ip", IP, KEY, sid)
me.update_behavioral_baseline(
    entity_type="ip", entity_value=IP, behavior_key=KEY, session_id="s4",
    sample_count=n, value_mean=12.5, typical_hours=[8, 9, 10],
    model_notes="quiet in the evenings", confidence="medium")
check("four distinct sessions counted", n, 4)
r = row()
check("the numbers are on file", r["value_mean"], 12.5)
check("and the hours", r["typical_hours"], "[8, 9, 10]")
check("nothing is retracted yet", r["retracted_at"], None)


print("\n[3] retracting clears the LEARNED CONTENT, and the count with it")
# THE CHECK THIS FILE EXISTS FOR. sample_count is derived from
# baseline_session_seen, so a retraction that only touched the baseline row
# would leave the count at 4 and the next observation would come back at the
# old confidence, as if nothing had been withdrawn.
out = me.retract_baseline("ip", IP, KEY, "measured on a run where the sniffer was blind")
check("it reports success", out["success"], True)
check("one row retracted", out["retracted"], 1)
check("and four counted sessions cleared", out["sessions_cleared"], 4)

r = row()
check("the mean is gone", r["value_mean"], None)
check("the hours are gone", r["typical_hours"], None)
check("the model's notes are gone", r["model_notes"], None)
check("sample_count is zero", r["sample_count"], 0)
check("confidence is back to low", r["confidence"], "low")
check("THE SESSION COUNT RESTARTS", me.count_baseline_sessions("ip", IP, KEY), 0)


print("\n[4] nothing is deleted, and the reason is kept")
check("the row is still there", r is not None, True)
check("stamped with when", bool(r["retracted_at"]), True)
check("and with why", "sniffer was blind" in (r["retracted_reason"] or ""), True)
with _Conn() as c:
    n_seen = c.execute("SELECT COUNT(*) FROM baseline_session_seen "
                       "WHERE entity_value=?", (IP,)).fetchone()[0]
check("the session rows are stamped, not deleted", n_seen, 4)

# A reason is required, same rule as supersede_observation. A retraction with
# no explanation is indistinguishable from tampering.
check("a retraction with no reason is refused",
      me.retract_baseline("ip", IP, KEY, "   ")["success"], False)


print("\n[5] a retracted baseline cannot still be silencing alerts")
# The safety half. revert_suppression already covered this on its own, but a
# retract that left suppression on would be the worst of both.
me.update_behavioral_baseline(
    entity_type="ip", entity_value="192.0.2.7", behavior_key="connection_count",
    session_id="s1", flagged_as_normal=True)
with _Conn() as c:
    c.execute("UPDATE behavioral_baseline SET alert_suppressed = 1 "
              "WHERE entity_value = '192.0.2.7'")
before = me.query_suppressed_baselines()
check("it is suppressing before", len(before) >= 1, True)

me.retract_baseline("ip", "192.0.2.7", "connection_count", "false normal")
after = [b for b in me.query_suppressed_baselines()
         if b["entity_value"] == "192.0.2.7"]
check("and suppresses nothing after", after, [])


print("\n[6] observing it again rebuilds from scratch, it is not a blacklist")
# The retraction says "what you learned was wrong", not "never learn about
# this again". A session that was already counted before the retraction must
# be able to count again, or INSERT OR IGNORE would silently blacklist it.
again = me.record_baseline_session("ip", IP, KEY, "s1")
check("the same session can count again", again, 1)
check("a new one adds to it", me.record_baseline_session("ip", IP, KEY, "s9"), 2)
check("and not back to the old four",
      me.count_baseline_sessions("ip", IP, KEY), 2)

me.update_behavioral_baseline(
    entity_type="ip", entity_value=IP, behavior_key=KEY, session_id="s9",
    value_mean=3.0)
r = row()
check("a real new observation lifts the retraction", r["retracted_at"], None)
check("and the reason goes with it", r["retracted_reason"], None)
check("the fresh number is on file", r["value_mean"], 3.0)


print("\n[7] retracting every key at once")
# What a person means by "forget what you learned about this device".
for k in ("connection_count", "typical_dest_ports"):
    me.record_baseline_session("ip", "192.0.2.10", k, "s1")
    me.update_behavioral_baseline(entity_type="ip", entity_value="192.0.2.10",
                                  behavior_key=k, session_id="s1",
                                  value_mean=9.0)
out = me.retract_baseline("ip", "192.0.2.10", None, "wiping this device")
check("both keys went", out["retracted"], 2)
check("and both session counts",
      me.count_baseline_sessions("ip", "192.0.2.10", "connection_count"), 0)


print("\n[8] a retracted row is still READABLE, and that is deliberate")
# Hiding it would mean a reader cannot tell a withdrawn baseline from a device
# nobody ever measured. Those are very different states. The row is already
# harmless by then: no numbers, low confidence, no suppression.
me.retract_baseline("ip", IP, KEY, "second thoughts")
visible = me.query_behavioral_baseline(entity_type="ip", entity_value=IP,
                                       behavior_key=KEY)
check("it still comes back on a read", len(visible), 1)
check("carrying its reason", visible[0]["retracted_reason"], "second thoughts")
check("but claiming nothing", visible[0]["value_mean"], None)
check("and suppressing nothing", visible[0]["alert_suppressed"], 0)


print("\n[9] it is reachable, and it is NOT a model tool")
# A model that can erase what it learned can also erase what it learned about
# an intruder. This is an owner action, so it gets a script and stays out of
# the tool manifest.
script = ROOT / "scripts" / "retract_baseline.py"
check("the owner has a way to run it", script.exists(), True)
check("and it refuses without a reason",
      "--reason is required" in script.read_text(encoding="utf-8"), True)

registry = (ROOT / "core" / "tool_registry.py").read_text(encoding="utf-8")
check("the model has no path to it", "retract_baseline" in registry, False)


print("\n[10] a database that has not migrated yet does NOT crash")
# MY BUG, and the owner hit it on the first thing the owner ran. I put
# "AND retracted_at IS NULL" in the session count, and
# query_behavioral_baseline calls that count on EVERY row, so on a pre-v29
# database every baseline read raised:
#
#     sqlite3.OperationalError: no such column: retracted_at
#
# The app migrates at boot so the app was fine, but any script against a
# not-yet-migrated file blew up, and "boot the app first" is not something a
# tool should make somebody work out from a traceback.
# The v28 database is the REAL schema with the three v29 lines taken back out,
# not a hand written stub. A stub only ever tests the tables somebody
# remembered to put in it, and the first version of this missed
# behavioral_session and failed for a reason that had nothing to do with the
# bug.
OLD_DB = os.path.join(tempfile.mkdtemp(), "v28.db")
_schema = (ROOT / "Schema.SQL").read_text(encoding="utf-8")
_v28 = "\n".join(
    line for line in _schema.splitlines()
    if not line.strip().startswith(("retracted_at", "retracted_reason")))
assert "retracted_at" not in _v28, "the v29 columns did not come out"
_old = sqlite3.connect(OLD_DB)
_old.executescript(_v28)
_old.execute("INSERT INTO baseline_session_seen "
             "(entity_type, entity_value, behavior_key, session_id) "
             "VALUES ('ip','192.0.2.5','active_hours','s1')")
_old.commit(); _old.close()


class _OldConn:
    def __enter__(self):
        self.c = sqlite3.connect(OLD_DB)
        self.c.row_factory = sqlite3.Row
        return self.c

    def __exit__(self, *a):
        self.c.commit(); self.c.close()


me._get_conn = lambda *a, **k: _OldConn()
me._RETRACT_COLUMNS = None          # forget what the v29 database taught it
try:
    check("the count still answers on a v28 database",
          me.count_baseline_sessions("ip", "192.0.2.5", "active_hours"), 1)
    # Nothing can have been retracted there, so counting everything IS the
    # right answer rather than a fallback that quietly means something else.
    check("recording a session still works",
          me.record_baseline_session("ip", "192.0.2.5", "active_hours", "s2"), 2)
    me.update_behavioral_baseline(entity_type="ip", entity_value="192.0.2.5",
                                  behavior_key="active_hours", session_id="s2",
                                  value_mean=1.0)
    check("and writing a baseline still works",
          me.query_behavioral_baseline(entity_type="ip",
                                       entity_value="192.0.2.5")[0]["value_mean"],
          1.0)

    # A retract there must REFUSE, not half-apply. The UPDATE would throw
    # partway and leave the numbers cleared with no record of why.
    out = me.retract_baseline("ip", "192.0.2.5", "active_hours", "nope")
    check("but a retract refuses", out["success"], False)
    check("and says what to run", "migrations" in out["error"], True)
    check("the numbers were NOT touched",
          me.query_behavioral_baseline(entity_type="ip",
                                       entity_value="192.0.2.5")[0]["value_mean"],
          1.0)
finally:
    me._get_conn = lambda *a, **k: _Conn()
    me._RETRACT_COLUMNS = None


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
