"""
tests/test_deviation_provenance.py, who answered the alert. TODO 98, v30.
2026-09-14.

WHAT THIS IS ABOUT. behavioral_deviation carries user_responded and
user_response, documented in the schema as "0 = silence, 1 = user replied" and
"verbatim if they responded". resolve_deviation wrote both from whatever it
was handed, and one of its three callers is the model's own tool, ungated,
taking free text. The manifest asked the model for it by name.

So the model could put a sentence in the column that means a person said it,
set the flag that means a person answered, and nothing recorded that a model
had done either. It also lifted the row out of get_silent_deviations, which
selects user_responded = 0 and exists because silence is not approval.

dismiss_entity has recorded dismissed_by="model" since it was written. This
table had no such column at all.

THE RULE BEING TESTED: a model resolution is a recommendation. It is stored as
the model's, it never touches the user columns, and the review queue keeps
showing it until a person answers. Same shape as nominate_finding in TODO 84.

Failure cases first. Runs anywhere, builds its own database from the real
Schema.SQL, and section [6] builds a pre-v30 one to prove the guard.
"""
import io
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


from core import memory_engine as me            # noqa: E402

SCHEMA = io.open(ROOT / "Schema.SQL", encoding="utf-8").read()
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
me.DB_PATH = _tmp.name
_c = sqlite3.connect(me.DB_PATH)
_c.executescript(SCHEMA)
_c.commit()
_c.close()


def add_deviation(severity="high", alerted="2026-09-14T09:00:00"):
    with me._get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO behavioral_deviation (session_id, entity_type, "
            "entity_value, behavior_key, severity, alerted_at, "
            "silence_timeout_seconds) VALUES ('s1','ip','192.0.2.8', "
            "'bytes_per_hour',?,?,1)", (severity, alerted))
        return cur.lastrowid


def row(dev_id):
    with me._get_conn() as conn:
        r = conn.execute("SELECT * FROM behavioral_deviation WHERE id=?",
                         (dev_id,)).fetchone()
    return dict(r)


print("\n[1] FAILURE CASE. The model must not be able to write the words")
print("    that mean a person spoke. This is the whole point of the file.")

d1 = add_deviation()
refused = None
try:
    me.resolve_deviation(d1, "normal", user_response="The owner said it is fine",
                         resolved_by="model")
except me.BadInput as e:
    refused = str(e)

check("it is refused", refused is not None, True)
check("and the refusal names the column that is not the model's",
      "user_response" in (refused or ""), True)
check("and says where the model's own reading goes",
      "model_assessment" in (refused or ""), True)
check("and nothing was written", row(d1)["resolved_as"], None)
check("and the user flag was not set", row(d1)["user_responded"], 0)


print("\n[2] FAILURE CASE. A model resolve must not look like a human one.")

d2 = add_deviation()
out = me.resolve_deviation(d2, "normal", resolved_by="model")
r2 = row(d2)
check("the resolution is recorded", r2["resolved_as"], "normal")
check("resolved_by says model", r2["resolved_by"], "model")
check("user_responded stays 0", r2["user_responded"], 0)
check("user_response stays empty", r2["user_response"], None)
check("and the caller is told who it recorded", out["resolved_by"], "model")


print("\n[3] FAILURE CASE. A model resolve must NOT take the row off the")
print("    queue a person reads. Before today it did, silently.")

queue = me.query_review_queue(include_all=True)
ids = [q["id"] for q in queue]
check("the model-resolved row is still in the review queue", d2 in ids, True)

# And it leaves once a person answers it, or the queue is just a list that
# grows forever.
me.resolve_deviation(d2, "normal", user_response="checked, it is my backup",
                     resolved_by="user")
ids_after = [q["id"] for q in me.query_review_queue(include_all=True)]
check("and it leaves when a person answers", d2 in ids_after, False)
check("the person's words are stored now",
      row(d2)["user_response"], "checked, it is my backup")
check("and the flag that means a person answered is set",
      row(d2)["user_responded"], 1)
check("and resolved_by moved to user", row(d2)["resolved_by"], "user")


print("\n[4] FAILURE CASE. An unknown resolved_by must be refused, not")
print("    stored. A column nobody validates is a column nobody can read.")

d4 = add_deviation()
bad = None
try:
    me.resolve_deviation(d4, "normal", resolved_by="the operator")
except me.BadInput as e:
    bad = str(e)
check("refused", bad is not None, True)
check("and the message lists what is allowed", "silence_timer" in (bad or ""), True)
check("and nothing was written", row(d4)["resolved_as"], None)


print("\n[5] The silence timer. Nobody answered, and the row says so in its")
print("    own column now rather than only by an absence.")

d5 = add_deviation()
me.resolve_deviation(d5, "unreviewed", user_response=None,
                     resolved_by="silence_timer")
r5 = row(d5)
check("resolved_by says silence_timer", r5["resolved_by"], "silence_timer")
check("user_responded is 0", r5["user_responded"], 0)
check("and it is in the review queue", d5 in
      [q["id"] for q in me.query_review_queue(include_all=True)], True)

# A user resolve with NO words is still not a user reply. The flag tracks
# whether somebody said something, and the column tracks who acted.
d5b = add_deviation()
me.resolve_deviation(d5b, "normal", resolved_by="user")
check("a user resolve with no words leaves the reply flag at 0",
      row(d5b)["user_responded"], 0)
check("but still records who acted", row(d5b)["resolved_by"], "user")


print("\n[6] FAILURE CASE. A pre-v30 database must not crash and must not")
print("    claim it stored something it could not. This is 93.5's lesson.")

# The REAL schema with the v30 line stripped, not a hand written stub. A stub
# forgets a table and then fails for a reason that has nothing to do with the
# thing under test, which is exactly what happened last time.
# STRIP BY THE COLUMN NAME, NOT BY THE SHAPE OF ITS DECLARATION.
#
# This was `re.sub(r"^\s*resolved_by\s+TEXT CHECK.*$", ...)` with re.M, which
# matched exactly one line. On 2026-09-14 TODO 110 rewrote the constraint as
# `IS NULL OR ... IN (...)` and it wrapped onto a second line. The regex then
# removed the first half and left the orphan half behind, so the check above
# went red and executescript died with "near IN: syntax error". Broken since,
# and only noticed when the suite was next run in full.
#
# Same lesson as test_sensor_hardening pinning "if reached_old or first_run:"
# and test_ui_wiring looking for a string that wrapped across two f-string
# pieces. A test that asserts on the exact shape of somebody else's source
# text breaks when that text is reformatted, and the breakage says nothing
# about the thing under test. Dropping every line that mentions the column
# works whether the declaration is one line or five.
old_schema = "\n".join(
    line for line in SCHEMA.splitlines() if "resolved_by" not in line)
check("the v30 column really was stripped from the test schema",
      "resolved_by" in old_schema, False)

_old = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_old.close()
_c2 = sqlite3.connect(_old.name)
_c2.executescript(old_schema)
_c2.commit()
_c2.close()

_new_db = me.DB_PATH
me.DB_PATH = _old.name
me._RESOLVED_BY_COLUMN = None          # forget what the other database said
try:
    d6 = add_deviation()
    res = me.resolve_deviation(d6, "normal", resolved_by="model")
    check("the resolution still applies", row(d6)["resolved_as"], "normal")
    check("the answer says who was NOT recorded",
          res.get("resolved_by_recorded"), False)
    check("and names the reason", "v30" in res.get("note", ""), True)
    check("and the review queue still works on the old shape",
          isinstance(me.query_review_queue(include_all=True), list), True)
finally:
    me.DB_PATH = _new_db
    me._RESOLVED_BY_COLUMN = None


print("\n[7] The model's TOOL cannot get near the user columns, whatever it")
print("    sends. The engine refuses and the dispatch never asks.")

src = (ROOT / "core" / "tool_registry.py").read_text(encoding="utf-8")
block = src.split('if name == "resolve_deviation":')[1][:900]
check("the dispatch hardcodes resolved_by", 'resolved_by="model"' in block, True)
check("and does not pass user_response at all",
      "user_response" in block.split("return me.resolve_deviation")[1], False)

manifest_block = src.split('"name": "resolve_deviation"')[1][:2200]
check("the manifest no longer offers user_response as a parameter",
      '"user_response": {"type"' in manifest_block, False)
check("and tells the model its resolve is a recommendation",
      "RECOMMENDATION, NOT A CLOSURE" in manifest_block, True)


print("\n[8] The other two callers say who they are.")

routes = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")
rb = routes.split("me.resolve_deviation(")[1][:400]
check("the review queue route resolves as the user", 'resolved_by="user"' in rb, True)

rollup = (ROOT / "core" / "rollup_engine.py").read_text(encoding="utf-8")
rl = rollup.split("me.resolve_deviation(")[1][:400]
check("the silence timer resolves as the silence timer",
      'resolved_by="silence_timer"' in rl, True)
check("and still sends no words", "user_response=None" in rl, True)


print("\n[9] The migration and the schema agree, and nothing is backfilled.")

mig = (ROOT / "core" / "migrations.py").read_text(encoding="utf-8")
# NOT `"SCHEMA_VERSION = 30" in mig`. That pinned the version number that
# happened to be current the day this was written, so every later migration
# broke it, and the breakage said nothing about resolved_by. It has been red
# since v31. What this section actually cares about is that the v30 migration
# is still in the chain and still refuses to backfill, which the three checks
# below test directly.
from core import migrations as _mig                   # noqa: E402
check("the schema is at least v30", _mig.SCHEMA_VERSION >= 30, True)
check("the migration runs in the chain", "_migrate_resolved_by(conn)" in mig, True)
check("it is reported in the summary", '"resolved_by_added"' in mig, True)
check("and it says why nothing is backfilled",
      "NOTHING IS BACKFILLED" in mig, True)

schema_txt = SCHEMA
check("the fresh schema has the column", "resolved_by" in schema_txt, True)
check("and constrains it to the three values",
      "'user','model','silence_timer'" in schema_txt, True)


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
