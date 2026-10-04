"""
tests/test_important_findings.py, the list is only worth having if it is
believable.

WHERE THIS CAME FROM, 2026-09-09. The owner wanted a table of findings that
matter, and named the failure mode in the same breath as the idea: a model
asked to promote what matters would have promoted all seventeen of the false
masquerading findings from the day before, confidently, and one wrong row
turns the list into a second alert list nobody reads.

So the rules were agreed before any code:

    1. The model NOMINATES. It never promotes.
    2. The user confirms.
    3. Every row records WHY, and the evidence behind it.
    4. A row is re-checked when the rule that raised it changes.

Rule 4 is the one that decided the design. A separate table would hold
COPIES, and a copy cannot know that the rule which raised the original has
been fixed. So promotion is a column ON the finding: dismiss or clear the
finding and the promotion goes with it, with no second place to remember.

Section [5] is the whole point of the file. It stages the actual 2026-09-08
situation, promotes some of the bad findings, fixes the rule, and checks the
list empties itself.
"""
import io
import os
import re
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


from core import memory_engine as me            # noqa: E402

# A temp database built from the WHOLE of Schema.SQL rather than a retyped
# copy of one table. Two reasons: the engine enriches its answers from other
# tables, so a lone findings table is not enough to call anything; and running
# the real schema means a broken Schema.SQL fails here rather than on somebody
# else's first boot.
SCHEMA = io.open(ROOT / "Schema.SQL", encoding="utf-8").read()

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
me.DB_PATH = _tmp.name
_c = sqlite3.connect(me.DB_PATH)
_c.executescript(SCHEMA)
_c.commit()
_c.close()


def add(title, severity="high", dismissed=0):
    with me._get_conn() as conn:
        return conn.execute(
            "INSERT INTO findings (session_id, severity, entity_type, "
            "entity_value, title, dismissed) VALUES ('s',?,'process',?,?,?)",
            (severity, title, title, dismissed)).lastrowid


def titles(key):
    d = me.query_important()
    return [r["title"] for r in d[key]]


print("\n[1] a nomination is not a promotion")
real = add("something worth a look")
out = me.nominate_finding(real, "it talks to a host nothing else talks to")
check("the nomination is accepted", out["nominated"], True)
check("it does NOT land on the list", titles("promoted"), [])
check("it is waiting on the user", titles("nominated"), ["something worth a look"])
# The model reads this text back. If it ever stops saying so, the model starts
# reporting nominations as though the user had agreed to them.
check("and the model is told so in the result",
      "not until the user confirms" in out["note"].lower()
      or "NOT on the important list" in out["note"], True)


print("\n[2] a nomination needs a reason, and the reason is kept")
try:
    me.nominate_finding(real, "   ")
    check("an empty reason is refused", False, True)
except Exception:
    check("an empty reason is refused", True, True)
row = me.query_important()["nominated"][0]
check("the model's words are stored verbatim",
      row["nominated_reason"], "it talks to a host nothing else talks to")
check("and it is recorded as the model's opinion, not the user's",
      row["nominated_by"], "model")


print("\n[3] the user is the only path onto the list")
# There is deliberately no by= on promote_finding. If somebody adds one, this
# is the test that should make them explain why.
import inspect                                   # noqa: E402
sig = inspect.signature(me.promote_finding)
check("promote_finding takes no actor parameter",
      [p for p in sig.parameters if p in ("by", "promoted_by", "actor")], [])
check("and the tool layer has no promote path",
      "promote_finding" in io.open(ROOT / "core" / "tool_registry.py",
                                   encoding="utf-8").read(), False)

me.promote_finding(real, "I want this in front of me")
check("now it is on the list", titles("promoted"), ["something worth a look"])
check("and it is no longer waiting", titles("nominated"), [])
check("with the USER's reason, not the model's",
      me.query_important()["promoted"][0]["promoted_reason"],
      "I want this in front of me")


print("\n[4] turning one down is not the same as saying it is not real")
noise = add("probably nothing")
me.nominate_finding(noise, "worth asking about")
me.reject_nomination(noise, "I know what that is")
check("it leaves the waiting list", "probably nothing" in titles("nominated"), False)
check("it never reached the list", "probably nothing" in titles("promoted"), False)
with me._get_conn() as conn:
    still = conn.execute("SELECT dismissed FROM findings WHERE id=?",
                         (noise,)).fetchone()["dismissed"]
# Rejecting a nomination must not silence the finding. Conflating "not
# important" with "not real" is how a list like this starts eating evidence.
check("but the finding itself is untouched", still, 0)


print("\n[5] THE 2026-09-08 CASE. The list cleans itself when the rule is fixed.")
# Seventeen false masquerading findings, all HIGH, all convincing. Exactly the
# rows a model would have promoted.
seventeen = [add(f"masquerading_system_binary {i}") for i in range(17)]
for fid in seventeen[:3]:
    me.nominate_finding(fid, "a system binary at a path that is not System32")
    me.promote_finding(fid)
check("three of the false ones make it onto the list",
      len(me.query_important()["promoted"]), 4)

# The rule gets fixed, and the findings it wrongly raised are cleared. This is
# the ONLY step. Nobody touches the important list.
with me._get_conn() as conn:
    conn.execute(
        f"UPDATE findings SET dismissed = 1 WHERE id IN "
        f"({','.join('?' * len(seventeen))})", seventeen)

check("they leave the list on their own", titles("promoted"),
      ["something worth a look"])
check("and nothing was left waiting either",
      me.query_important()["waiting_count"], 0)


print("\n[6] the cap, because burying the real one is also an attack")
check("there is a cap at all", isinstance(me.MAX_OPEN_NOMINATIONS, int), True)
spam = [add(f"spam {i}") for i in range(me.MAX_OPEN_NOMINATIONS + 5)]
results = [me.nominate_finding(f, "trust me") for f in spam]
accepted = [r for r in results if r["nominated"]]
check("nominations stop at the cap",
      len(accepted) <= me.MAX_OPEN_NOMINATIONS, True)
refused = [r for r in results if not r["nominated"]]
check("and the refusal says what to do instead of retrying",
      any("instead" in (r.get("reason_refused") or "") for r in refused), True)
# Confirming or rejecting must make room again, otherwise the cap becomes a
# permanent lockout rather than a queue depth.
before = len([r for r in results if r["nominated"]])
me.reject_nomination(spam[0])
after = me.nominate_finding(spam[-1], "now there is room")
check("clearing one makes room for another",
      after["nominated"] or before == 0, True)


print("\n[7] a dismissed finding cannot be nominated at all")
dead = add("old news", dismissed=1)
out = me.nominate_finding(dead, "surely")
check("refused", out["nominated"], False)
check("with a reason that says what to do",
      "un-dismiss" in (out["reason_refused"] or "").lower(), True)


print("\n[8] removing a row from the list keeps the finding")
keep = add("still a real finding")
me.nominate_finding(keep, "x")
me.promote_finding(keep)
me.demote_finding(keep, "changed my mind")
check("off the list", "still a real finding" in titles("promoted"), False)
with me._get_conn() as conn:
    r = conn.execute("SELECT dismissed, promoted FROM findings WHERE id=?",
                     (keep,)).fetchone()
check("finding not dismissed", r["dismissed"], 0)
check("promotion cleared", r["promoted"], 0)


print("\n[9] the schema and the migration agree")
MIG = io.open(ROOT / "core" / "migrations.py", encoding="utf-8").read()
for col in ("nominated_at", "nominated_by", "nominated_reason",
            "promoted", "promoted_at", "promoted_reason"):
    check(f"{col} is in Schema.SQL", col in SCHEMA, True)
    check(f"{col} is in the migration", col in MIG, True)
# 2026-09-13: this pinned the exact string "SCHEMA_VERSION = 28" and went red
# the moment v29 landed for the baseline retract, which has nothing to do with
# this feature. A test that fails for the correct reason over and over is a
# test people learn to ignore, same lesson as the event marker assertion in
# test_sensor_hardening.
#
# What this section actually means is that these columns arrived with a
# version bump, so the number is read and compared instead of spelled.
_v = re.search(r"^SCHEMA_VERSION\s*=\s*(\d+)", MIG, re.MULTILINE)
check("the schema version is declared where it can be read", bool(_v), True)
check("and it is at or past the version these columns landed in",
      int(_v.group(1)) >= 28 if _v else None, True)
# Nothing gets backfilled. Guessing which old findings "were probably
# important" would fill the list on day one with rows nobody agreed to.
check("the migration backfills nothing",
      "UPDATE findings SET promoted = 1" in MIG, False)


try:
    os.unlink(_tmp.name)
except OSError:
    pass

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
