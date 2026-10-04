"""
tests/test_sample_count.py, TODO 22. The evidence count is measured.

sample_count is documented as distinct SESSIONS, and the comment above
record_baseline_session says "sample_count is derived from it".
rollup_engine does exactly that. But update_behavioral_baseline also takes
sample_count as a parameter, the model can call it directly, and nothing
reconciled the two.

So the number a human reads as "forty sessions of consistent behaviour",
the number that drives confidence, and confidence drives suppression, could
be asserted rather than counted. An attacker patient enough to poison a
baseline over weeks did not need the weeks. One call claiming forty would do,
which is cheaper than the slow attack the provenance work was defending
against.

This is clamped rather than annotated, unlike provenance and direction. Those
are claims a reader should weigh. An inflated session count is not a competing
view of the evidence, it is a wrong number about how much evidence exists.
"""
import sys, sqlite3, tempfile, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []
def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)

tmp = pathlib.Path(tempfile.mkdtemp()); db = tmp / "t.db"
from core import memory_engine as me
me.DB_PATH = db
c = sqlite3.connect(db); c.executescript((ROOT/"Schema.SQL").read_text(encoding="utf-8"))
c.commit(); c.close()
from core import migrations; migrations.run_migrations(db)
from core import sensors as sn; sn.register_local()

E = ("ip", "192.0.2.50", "beacon_interval")


print("\n[1] with no recorded sessions, a claim of forty stores zero")
r = me.update_behavioral_baseline(entity_type=E[0], entity_value=E[1],
                                  behavior_key=E[2], session_id="s1",
                                  sample_count=40, confidence="high")
check("stored value is the measured one", r["sample_count_recorded"], 0)
check("the claim is reported back, not hidden", r["sample_count_claimed"], 40)
row = me.query_behavioral_baseline(entity_value=E[1])[0]
check("and the row holds the measured value", row["sample_count"], 0)
assert "not 40" in r["sample_count_note"], r["sample_count_note"]
print("       note explains where the count comes from")


print("\n[2] real sessions raise it, one per session, idempotently")
for sid in ("s1", "s1", "s1", "s2", "s3"):
    me.record_baseline_session(E[0], E[1], E[2], sid)
check("three distinct sessions", me.count_baseline_sessions(*E), 3)
r = me.update_behavioral_baseline(entity_type=E[0], entity_value=E[1],
                                  behavior_key=E[2], session_id="s3",
                                  sample_count=40)
check("a claim of 40 still clamps to 3", r["sample_count_recorded"], 3)
check("repeats within one session do not inflate it",
      me.query_behavioral_baseline(entity_value=E[1])[0]["sample_count"], 3)


print("\n[3] the ROLLUP path is untouched, it passes the measured value")
# rollup_engine calls record_baseline_session and hands back what it returns,
# so its value equals the measurement and is never reduced. Only a claim
# ABOVE the measurement is clamped.
n = me.record_baseline_session(E[0], E[1], E[2], "s4")
r = me.update_behavioral_baseline(entity_type=E[0], entity_value=E[1],
                                  behavior_key=E[2], session_id="s4",
                                  sample_count=n)
check("passed exactly what was measured", r["sample_count_recorded"], n)
check("nothing was clamped", "sample_count_claimed" in r, False)
check("no spurious note", "sample_count_note" in r, False)


print("\n[4] a claim BELOW the measurement is honoured, not raised")
# Clamping is one-directional on purpose. Reducing a count is not the attack,
# and silently inflating a caller's number would be this control committing
# the very error it exists to prevent.
r = me.update_behavioral_baseline(entity_type=E[0], entity_value=E[1],
                                  behavior_key=E[2], session_id="s4",
                                  sample_count=1)
check("stored as given", me.query_behavioral_baseline(
      entity_value=E[1])[0]["sample_count"], 1)
check("not clamped upward", "sample_count_claimed" in r, False)


print("\n[5] the measured count travels on every read")
row = me.query_behavioral_baseline(entity_value=E[1])[0]
check("annotated", "distinct_sessions_measured" in row, True)
check("and it is the truth even when the stored value disagrees",
      row["distinct_sessions_measured"], 4)
check("stored value here was deliberately set lower in [4]",
      row["sample_count"], 1)
print("       a disagreement on an old row means it predates this fix")


print("\n[6] omitting sample_count entirely does not zero an existing one")
before = me.query_behavioral_baseline(entity_value=E[1])[0]["sample_count"]
me.update_behavioral_baseline(entity_type=E[0], entity_value=E[1],
                              behavior_key=E[2], session_id="s4",
                              confidence="medium")
check("left alone", me.query_behavioral_baseline(
      entity_value=E[1])[0]["sample_count"], before)


print("\n[7] the documented intent and the code now agree")
src = (ROOT / "core" / "memory_engine.py").read_text(encoding="utf-8")
check("the derivation comment is still there",
      "sample_count is derived from it" in src, True)
import ast
tree = ast.parse(src)
fn = next(n for n in ast.walk(tree)
          if isinstance(n, ast.FunctionDef) and n.name == "update_behavioral_baseline")
calls = {n.func.id for n in ast.walk(fn)
         if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
check("and update_behavioral_baseline actually measures",
      "count_baseline_sessions" in calls, True)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
