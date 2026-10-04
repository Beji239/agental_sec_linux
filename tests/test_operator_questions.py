"""
tests/test_operator_questions.py, the model asks the owner something.

FAILURE CASES FIRST, per rule one. For this feature the failure is not a
crash, it is BEING ANNOYING, because a mechanism the owner learns to close without
reading is worth nothing however well the rest of it works. So the first four
sections are all about refusing to bother the owner.

  1. A question the lookups already answered is REFUSED.
  2. The same question cannot be asked twice, in any wording.
  3. The popup respects the budget and the gap, and asking whether one is due
     never spends one.
  4. No popup while the owner is in the chat tab.
  5. The expiry clock runs from when the owner was SHOWN it, never from when it was
     filed.
  6. Only then, the happy path, including "I do not know" as a real answer.
  7. The owner's answer lands as operator_stated, not as a measurement.
  8. The hints say where to look and never what the owner will find.
  9. The page and the routes exist.

Run it directly: python tests/test_operator_questions.py
"""
import json
import pathlib
import sys
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import memory_engine as me                  # noqa: E402
from core import questions as q                       # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got):
    check(label, bool(got), True)


SID = "test-session"


def ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def seed_enrichment(indicator, status, kind="ip", gap=None, tried=None):
    with me._get_conn() as c:
        c.execute("""
            INSERT OR REPLACE INTO enrichment
                (indicator, kind, status, fields_json, sources_json,
                 tried_json, gap, fetched_at, expires_at)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (indicator, kind, status, json.dumps({"organisation": "Example"}),
              json.dumps(["https://rdap.example/x"]),
              json.dumps(tried or ["rdap", "ip_api"]), gap,
              "2026-09-14T00:00:00+00:00", "2099-01-01T00:00:00+00:00"))


print("\n[1] FAILURE FIRST: do not ask the owner what the lookups already answered")
# The fastest way to kill this feature is to spend the owner's attention on something
# the app could have worked out. Once the owner stops reading these, every other rule
# in the file is worthless.
seed_enrichment("203.0.113.9", "resolved")
r = q.file_question(SID, "identify_destination", "ip", "203.0.113.9",
                    "what is this address")
check("refused", r["success"], False)
check_true("and it says to read the lookup instead",
           "query_enrichment" in r["error"])
check_true("and hands back what is already known", r.get("already_known"))

# Ownership is the exception and it is not a loophole. No registry anywhere
# knows whether a device is THE OWNER'S, so a resolved row says nothing about it.
r = q.file_question(SID, "identify_device", "ip", "203.0.113.9",
                    "is this one of yours")
check("but ownership is never blocked by a lookup", r["success"], True)


print("\n[2] the same question cannot be asked twice, in any wording")
seed_enrichment("203.0.113.10", "unresolved", gap="nothing knew anything")
first = q.file_question(SID, "identify_destination", "ip", "203.0.113.10",
                        "do you recognise this?")
check("the first ask lands", first["success"], True)

again = q.file_question(SID, "identify_destination", "ip", "203.0.113.10",
                        "completely different wording, same question")
check("the second is refused", again["success"], False)
check_true("and it says so plainly", again.get("already_asked"))
check("and names the open one", again["question_id"], first["question_id"])

r = q.file_question(SID, "not_a_topic", "ip", "203.0.113.10", "x")
check("an invented topic is refused", r["success"], False)
check_true("naming the real ones", "identify_device" in r["error"])


print("\n[3] the interruption budget, and asking never spends one")
# THE SPLIT THAT MATTERS. The dashboard polls popup_due every eight seconds.
# If asking spent budget, a page left open would burn the whole day without
# ever showing the owner anything.
me.set_preference("question_popup_daily_cap", "2")
me.set_preference("question_popup_min_gap_min", "0")

for _ in range(6):
    d = q.popup_due()
check_true("a popup is due", d["due"])
with me._get_conn() as c:
    spent = c.execute("SELECT COUNT(*) FROM operator_popup").fetchone()[0]
check("six asks spent nothing", spent, 0)

shown = q.claim_popup()
check_true("claiming shows it", shown["shown"])
check_true("and it carries more than one question", shown["carried"] >= 2)

# One popup carried everything waiting, so nothing is left to show.
check("nothing is waiting now", q.popup_due()["due"], False)

# Fill the budget and confirm the cap holds.
seed_enrichment("203.0.113.11", "unresolved")
q.file_question(SID, "identify_destination", "ip", "203.0.113.11", "and this?")
check_true("a new question is due again", q.popup_due()["due"])
q.claim_popup()
seed_enrichment("203.0.113.12", "unresolved")
q.file_question(SID, "identify_destination", "ip", "203.0.113.12", "this too?")
d = q.popup_due()
check("the cap refuses the third", d["due"], False)
check_true("and says it is the budget", "budget is spent" in d["reason"])

# The gap is a separate limit from the cap and is tested separately.
me.set_preference("question_popup_daily_cap", "99")
me.set_preference("question_popup_min_gap_min", "120")
d = q.popup_due()
check("the minimum gap refuses it", d["due"], False)
check_true("and says how long ago the owner was interrupted",
           "minimum gap" in d["reason"])


print("\n[4] no popup while the owner is standing in the doorway")
me.set_preference("question_popup_min_gap_min", "0")
d = q.popup_due(in_chat=True)
check("no popup when the owner is in the chat", d["due"], False)
check_true("it says to ask the owner there instead", d.get("ask_in_chat"))
check_true("and hands over the questions to say", d.get("questions"))


print("\n[5] the expiry clock runs from when the owner was SHOWN it")
# A question sitting behind the budget for nine days must not expire the day
# after the owner first sees it. Not being asked and choosing not to answer are
# different things.
me.set_preference("question_expiry_days", "10")
seed_enrichment("203.0.113.20", "unresolved")
never_shown = q.file_question(SID, "identify_destination", "ip",
                              "203.0.113.20", "old and never shown")
with me._get_conn() as c:
    c.execute("UPDATE operator_question SET asked_at=? WHERE id=?",
              (ts(datetime(2026, 1, 1)), never_shown["question_id"]))

out = q.expire_stale()
check("an ancient question that was never shown does NOT expire",
      out["expired"], 0)
with me._get_conn() as c:
    state = c.execute("SELECT state FROM operator_question WHERE id=?",
                      (never_shown["question_id"],)).fetchone()["state"]
check("it is still open", state, "open")

# Now show it, and backdate the showing instead.
with me._get_conn() as c:
    c.execute("UPDATE operator_question SET first_shown_at=? WHERE id=?",
              (ts(datetime(2026, 8, 1)), never_shown["question_id"]))
out = q.expire_stale()
check("once shown and ignored past the window, it retires", out["expired"], 1)
check("after the number of days the owner chose", out["after_days"], 10)

with me._get_conn() as c:
    row = c.execute("SELECT state, question FROM operator_question WHERE id=?",
                    (never_shown["question_id"],)).fetchone()
check("the state is expired", row["state"], "expired")
check_true("and nothing was deleted", row["question"])


print("\n[6] only now, the happy path, and 'I do not know' is an answer")
seed_enrichment("203.0.113.30", "unresolved", gap="no registry placed it")
ask = q.file_question(SID, "identify_device", "ip", "203.0.113.30",
                      "Is this yours? I cannot place it.",
                      why_stuck="every lookup came back empty")
check("filed", ask["success"], True)
check_true("it carries what was already tried", ask["tried"])
check_true("and where the owner could look", ask["hints"])

r = q.answer(ask["question_id"], answer_text="")
check("an empty answer is refused", r["success"], False)
check_true("and it says why that is different from not knowing",
           "different" in r["error"])

r = q.answer(ask["question_id"], answer_text="That is my work laptop")
check("a real answer lands", r["success"], True)
check("state is answered", r["state"], "answered")
# THE FAILURE PATH OF THE FILING, and it caught a real bug on the first run.
# The first version returned success with a note saying "Recorded as
# operator_stated" whether or not the observation write worked, and it did not
# work: operator_answer was missing from VALID_BEHAVIOR_KEYS, the write was
# refused, the error went to the log, and the caller was told it was recorded.
check("the filing actually happened", r["filing_failed"], None)
check_true("and the note is the one that says so",
           "Recorded as operator_stated" in r["note"])

r = q.answer(ask["question_id"], answer_text="changed my mind")
check("an answered question cannot be answered twice", r["success"], False)

seed_enrichment("203.0.113.31", "unresolved")
ask2 = q.file_question(SID, "identify_destination", "ip", "203.0.113.31",
                       "do you know this one?")
r = q.answer(ask2["question_id"], do_not_know=True)
check("'I do not know' is accepted", r["success"], True)
check("as its own state, not as a failure", r["state"], "do_not_know")
check_true("and it says nobody knows", "Nobody knows" in r["note"])

s = q.summary()
check("the four states are counted apart",
      sorted(k for k in ("open", "answered", "do_not_know", "expired")
             if k in s),
      ["answered", "do_not_know", "expired", "open"])
check_true("and the reading says they are never added together",
           "never added together" in s["how_to_read_this"])


print("\n[7] the owner's answer is operator_stated, and is NOT a measurement")
session = me.query_behavioral_session(
    session_id=f"operator-answer-{ask['question_id']}",
    entity_value="203.0.113.30")
rows = session["observations"] if isinstance(session, dict) else session
filed = [r for r in rows if r["behavior_key"] == "operator_answer"]
check("the answer was filed as an observation", len(filed), 1)
check_true("and the owner's whole sentence survived in the context, not just 280 chars",
           "That is my work laptop" in (filed[0]["context"] or ""))
check("with the fourth basis", filed[0]["basis"], "operator_stated")
check_true("and it is in the valid set",
           "operator_stated" in me.VALID_OBSERVATION_BASIS)

prov = me.observation_provenance("ip", "203.0.113.30")["basis"]
check("counted in its own column", prov["counts"]["operator_stated"], 1)
check("and never as measured", prov["counts"]["measured"], 0)
check_true("the reading says it is still not a measurement",
           "still not a measurement" in prov["how_to_read_this"])

# The write path has to accept it directly too, not only through answer().
direct = me.write_behavioral_observation(
    entity_type="ip", entity_value="203.0.113.32",
    behavior_key="typical_dest_ips", behavior_value="x",
    session_id=SID, basis="operator_stated")
check("the write path accepts it", direct["success"], True)
check_true("and warns against re-filing it as measured",
           "not later re-describe it" in direct["basis_note"]
           or "NOT a measurement" in direct["basis_note"])


print("\n[8] hints say WHERE to look, never what the owner will find")
# A hint carrying the model's guess is that guess smuggled in wearing a
# helpful hat. The owner would go looking for confirmation of something nobody
# established, and come back believing it.
hints = q._research_hints("8.8.8.8", kind="ip")
check_true("there are hints", hints)
check_true("they are real places",
           any("shodan.io" in (h.get("url") or "") for h in hints))
for h in hints:
    text = f"{h.get('label','')} {h.get('why','')}".lower()
    leaky = any(w in text for w in ("probably", "likely", "appears to be",
                                    "malicious", "this is a"))
    check(f"no verdict in the hint {h.get('label','')!r}", leaky, False)

# And the model does not get to write them. The tool takes no hints field.
from core import tool_registry as tr                  # noqa: E402
schema = next(t for t in tr.TOOL_MANIFEST if t["name"] == "ask_operator")
props = set(schema["input_schema"]["properties"])
check("the model cannot supply hints", "hints" in props, False)
check("nor what was tried", "tried" in props, False)
check_true("and the description tells it not to guess in the question",
           "guess" in schema["description"].lower())


print("\n[9] the owner can see and answer it")
UI = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check_true("there is a tab", 'data-page="questions"' in UI)
check_true("and a page", 'id="page-questions"' in UI)
check_true("there is a doorbell", 'id="question-popup"' in UI)
check_true("it does not carry the question itself",
           "qp-body" in UI and "Have a look" in UI)
check_true("'I do not know either' is a button, not buried",
           "I do not know either" in UI)
check_true("the four states are four tiles",
           "Nobody knows" in UI and "Retired unanswered" in UI)

ROUTES = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")
for route in ("/api/questions", "/api/questions/popup",
              "/api/questions/popup/claim", "/api/questions/answer"):
    check_true(f"{route} is served", f'"{route}"' in ROUTES)

# Asking and spending are separate routes, which is the thing section [3]
# proves at the module level. If they are ever merged this goes red.
check_true("asking and claiming are separate routes",
           '"/api/questions/popup"' in ROUTES
           and '"/api/questions/popup/claim"' in ROUTES)



print("\n[10] the CHECK constraints actually check something")
# FOUND 2026-09-14 while adding the fourth basis value, and it is the reason
# this section exists.
#
# Three CHECK constraints in Schema.SQL were written as
# `x IN ('a','b','c',NULL)`. That enforces NOTHING. In SQL, `x IN (a, NULL)`
# evaluates to NULL rather than false for a value not in the list, and a CHECK
# passes when its expression is NULL: only an explicit false rejects. So a
# fresh database accepted any string at all in those columns while the
# comments above them described a constraint.
#
# resolved_by is the one that stings: TODO 98 added it specifically so a model
# resolution could not look like a human one, and the migration note says "the
# CHECK is in Schema.SQL for databases created fresh". It was not enforcing.
#
# Nothing bad ever reached those columns, because the Python writers validate.
# The second line of defence was the decoration.
import sqlite3                                        # noqa: E402

fresh = pathlib.Path(__file__).parent / "_check_probe.db"
fresh.unlink(missing_ok=True)
probe = sqlite3.connect(fresh)
probe.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
probe.commit()


def refuses(sql, params):
    try:
        probe.execute(sql, params)
        return False
    except sqlite3.IntegrityError:
        return True


check("a junk basis is refused on a fresh database",
      refuses("""INSERT INTO behavioral_session
                 (session_id, entity_type, entity_value, behavior_key,
                  behavior_value, basis)
                 VALUES ('s','ip','1.1.1.1','first_seen','x',?)""",
              ("not_a_real_basis",)), True)
check("the fourth value is accepted",
      refuses("""INSERT INTO behavioral_session
                 (session_id, entity_type, entity_value, behavior_key,
                  behavior_value, basis)
                 VALUES ('s','ip','1.1.1.2','first_seen','x',?)""",
              ("operator_stated",)), False)
check("NULL is still allowed, pre-v26 rows carry it",
      refuses("""INSERT INTO behavioral_session
                 (session_id, entity_type, entity_value, behavior_key,
                  behavior_value, basis)
                 VALUES ('s','ip','1.1.1.3','first_seen','x',NULL)""",
              ()), False)

check("a junk resolved_by is refused",
      refuses("""INSERT INTO behavioral_deviation
                 (session_id, entity_type, entity_value, behavior_key,
                  resolved_by)
                 VALUES ('s','ip','1.1.1.4','first_seen',?)""",
              ("whatever_i_like",)), True)
check("a real one is accepted",
      refuses("""INSERT INTO behavioral_deviation
                 (session_id, entity_type, entity_value, behavior_key,
                  resolved_by)
                 VALUES ('s','ip','1.1.1.5','first_seen',?)""",
              ("model",)), False)

probe.close()
fresh.unlink(missing_ok=True)


print("\n" + ("ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}"))
sys.exit(1 if fails else 0)
