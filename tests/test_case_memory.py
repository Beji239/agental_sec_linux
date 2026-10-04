"""
tests/test_case_memory.py, the patient file's rules.

FAILURE CASES FIRST. Case memory's happy path is a search that returns rows.
What is worth testing is every way it can be WRONG while looking like it
worked, and this module has an unusually dangerous version of that failure,
because its output is read by a model that is deciding whether to act:

  A LIST OF PAST DISMISSALS, RETURNED WITH NOTHING SAID, IS AN INSTRUCTION TO
  DISMISS. So the order below starts there.

  [1]  NO PRECEDENT and THE INDEX COULD NOT ANSWER are different sentences.
       This is the module's whole honesty claim and it is asserted in all
       three states: index current, index behind, index missing entirely.
  [2]  A precedent carries WHAT WAS DECIDED, BY WHOM, and WHEN. Not a score
       and not an opinion.
  [3]  A PRECEDENT MAY NOT BE MISTAKEN FOR PERMISSION. The rendered brief
       carries the warning, and the warning is asserted rather than assumed,
       because the text is the only thing between the model and a list of
       things nobody bothered to act on.
  [4]  An unassessed incident is labelled, not silently presented as a
       conclusion. A row that says "nobody looked at this" must never read
       like a row that says "this was cleared".
  [5]  entity_history IS A REAL NEGATIVE when it is one, and it is a SEPARATE
       question from precedent search: a subject with no history but plenty of
       similar incidents is a different situation, and the two are never
       collapsed into each other.
  [6]  The index follows the ledger and reports its LAG as a number.
  [7]  A missing FTS5 build degrades precedent search and says so, WITHOUT
       taking entity history down with it.
  [8]  The brief never fails an investigation. A memory that cannot be read
       produces text saying so and still returns.
  [9]  The status contract: blind only for a real failure, NEVER for a
       permanent limit or an index that is merely behind.
 [10]  Text that reaches FTS5 is QUOTED and word-filtered, so a process named
       after an FTS operator is searched for rather than executed.
 [11]  Indexing is idempotent and a re-index does not duplicate rows.

Run it directly: python tests/test_case_memory.py
"""
import os
import pathlib
import sqlite3
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import case_memory as cm                    # noqa: E402
from core import memory_engine as me                  # noqa: E402

fails = []
checks = [0]


def check(label, got, want):
    checks[0] += 1
    ok = (got == want)
    if not ok:
        fails.append(f"{label}\n      got  {got!r}\n      want {want!r}")
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")


def ok(label, cond, detail=""):
    checks[0] += 1
    if not cond:
        fails.append(f"{label} {detail}")
    print(f"  {'PASS' if cond else 'FAIL'}  {label}"
          + ("" if cond else f"  <- {detail}"))


def section(title):
    print(f"\n[{title}]")


# The isolated database is built from Schema.SQL, so it already carries
# case_index, case_fts and the indexes. To exercise the "no index built"
# states below, the tables are dropped in a COPY.

def _seed_incidents():
    """
    Real-shaped incidents, written through the real writer.

    Written through core.incident.write_incident rather than by INSERT, because
    the module under test reads rows that writer produces and a hand-made row
    would let the test agree with itself about a shape production never emits.
    """
    from core import incident
    made = []

    made.append(incident.write_incident(
        "LNX-2002", "file", "/home/operator/.ssh/authorized_keys", "high",
        "SSH key added to a key file", source="local_integrity"))

    made.append(incident.write_incident(
        "LNX-1102", "process", "systemd-journald", "high",
        "Process masquerading as a system binary",
        source="process_monitor"))

    made.append(incident.write_incident(
        "LNX-1102", "process", "systemd-logind", "high",
        "Process masquerading as a system binary",
        source="process_monitor"))

    made.append(incident.write_incident(
        "NET-1001", "ip", "192.0.2.47", "medium",
        "New device appeared on the LAN", source="network_scanner"))

    # Give two of them a disposition and an assessment, through the real path.
    # THE ASSESSMENT COLUMN IS WRITTEN BY set_status's note (see
    # core/incident.set_status: `assessment = COALESCE(?, assessment)`), so the
    # test writes it the way the duty loop does rather than by a private
    # helper. A fixture that writes a column directly can agree with a reader
    # about a shape production never produces.
    incident.set_status(made[0]["id"], "dismissed", by="user",
                        note="it was the operator's own new laptop")
    incident.set_status(
        made[0]["id"], "dismissed", by="user",
        note="The key was the operator's own new laptop, confirmed by the owner "
             "directly.")
    incident.set_status(made[3]["id"], "dismissed", by="user",
                        note="Known printer on the LAN, benign.")
    return made


incidents = _seed_incidents()


section("[1] an index that is BEHIND is not an index that found nothing")
#
# THE CENTRAL DEFECT THIS MODULE EXISTS TO PREVENT, and it bit the first draft:
# an empty result that says nothing about the index, so "nothing similar has
# ever happened" and "the index has not looked at those rows" arrive as the
# same sentence. MEASURED against real data -- 14 incidents existed, 0 were
# indexed.
#
# THREE STATES ARE ASSERTED HERE, and they are the three that exist:
#   a. the index table is ABSENT      -> searched False, says so
#   b. the index is BEHIND            -> searched True, complete False, number
#   c. the index is CURRENT           -> searched True, complete True, a real
#                                        negative is a real negative
#
# (a) and (b) are different code paths on purpose. (a) is "never built", which
# is a database one migration behind; (b) is "built and lagging", which is the
# ordinary state between two watcher ticks.

# state (b) first, because the isolated database starts with an empty
# index: 4 incidents exist, none are indexed. That is "behind", not "absent".
empty = cm.similar_incidents(detection_id="ZZZ-9999", title="qqqq zzzz wwww",
                             entity_type="ip", entity_value="198.51.100.250")

check("with an index that is BEHIND, the search did run",
      empty["counts"].get("searched"), True)
check("but the answer is flagged INCOMPLETE, not empty",
      empty["counts"].get("complete"), False)
ok("and the note carries the lag as a NUMBER",
   "behind by" in (empty["note"] or "").lower(),
   detail=f"note was: {empty['note']!r}")
ok("the note does NOT claim nothing similar ever happened",
   "real negative" not in (empty["note"] or ""),
   detail=f"note was: {empty['note']!r}")

built = cm.index_pending()
check("index_pending indexed every incident", built["lag_after"], 0)

lag_now = cm.index_lag()
check("lag is zero once built", lag_now["lag"], 0)

# state (c): current, so an empty result IS a real negative.
real_negative = cm.similar_incidents(detection_id="ZZZ-9999",
                                     title="qqqq zzzz wwww",
                                     entity_type="ip",
                                     entity_value="198.51.100.250")
ok("a REAL negative says so, and says the index is current",
   "real negative" in (real_negative["note"] or ""),
   detail=f"note was: {real_negative['note']!r}")
check("a real negative was searched", real_negative["counts"]["searched"], True)
check("a real negative is COMPLETE", real_negative["counts"]["complete"], True)

# state (a): the ledger readable, the index gone. Written by dropping the
# tables in a copy of the isolated database rather than by monkeypatching a
# function, so what is tested is what a database one migration behind looks
# like.
copy_db = pathlib.Path(str(me.DB_PATH) + ".noindex")
copy_db.write_bytes(pathlib.Path(me.DB_PATH).read_bytes())
raw = sqlite3.connect(copy_db)
raw.execute("DROP TABLE case_fts")
raw.execute("DROP TABLE case_index")
raw.commit()
raw.close()

real_path = me.DB_PATH
me.DB_PATH = copy_db
try:
    cm._FTS_STATE["checked"] = False
    no_index = cm.similar_incidents(detection_id="LNX-1102",
                                    title="masquerading")
    ok("with the index table ABSENT the note says so plainly",
       "index has not been built" in (no_index["note"] or ""),
       detail=f"note was: {no_index['note']!r}")
    check("and it does not claim to have searched",
          no_index["counts"]["searched"], False)
    check("and it is not complete",
          no_index["counts"]["complete"], False)

    # [7]'s first half: entity history is a SEPARATE question and must survive.
    hist_still = cm.entity_history("process", "systemd-journald")
    ok("entity_history STILL ANSWERS with no index table at all",
       "incident" in (hist_still["counting"] or ""),
       detail=str(hist_still["counting"]))
finally:
    me.DB_PATH = real_path
cm._FTS_STATE["checked"] = False


section("[2] a precedent carries what was DECIDED, by WHOM, and WHEN")
#
# A retrieval layer that returns "similarity 0.7" and nothing else is one a
# model can only act on blindly. Every hit must carry the disposition.

found = cm.similar_incidents(detection_id="LNX-1102", entity_type="process",
                             entity_value="systemd-logind",
                             title="Process masquerading as a system binary")
ok("a seed with a real twin finds it", len(found["precedents"]) >= 1,
   detail=str(found["counts"]))

top = found["precedents"][0]
for field in ("id", "detection_id", "severity", "status", "status_by",
              "why", "match_score", "age_days", "assessed"):
    ok(f"the hit carries {field}", field in top,
       detail=f"keys: {sorted(top)}")

ok("the hit carries WHY it matched, naming the fields",
   any("same rule" in w for w in top.get("why") or [])
   or any("same subject" in w for w in top.get("why") or []),
   detail=str(top.get("why")))
ok("the hit's why names the rule by id when the rule matched",
   "LNX-1102" in " ".join(top.get("why") or []),
   detail=str(top.get("why")))

# The dismissed one, deliberately, so [3] has something real to warn about.
dismissed = cm.similar_incidents(detection_id="LNX-2002",
                                 entity_type="file",
                                 entity_value="/home/operator/.ssh/authorized_keys",
                                 title="SSH key added")
ok("the dismissed incident IS returned (it happened, and that is the record)",
   any(p["id"] == incidents[0]["id"] for p in dismissed["precedents"]),
   detail=str([p["id"] for p in dismissed["precedents"]]))
# The reason a thing was dismissed is the part a later reader needs, and it
# travels in the row's assessment (see core/incident.set_status). Asserted by
# reading the returned row rather than by grepping a dump of the whole list.
dismissed_row = next((p for p in dismissed["precedents"]
                      if p["id"] == incidents[0]["id"]), {})
ok("and it carries the reason it was dismissed",
   "laptop" in ((dismissed_row.get("assessment") or "").lower()),
   detail=str(dismissed_row.get("assessment")))
check("and says who decided", dismissed_row.get("status_by"), "user")
check("and what they decided", dismissed_row.get("status"), "dismissed")


section("[3] a precedent may NOT be mistaken for permission")
#
# THE MOST IMPORTANT ASSERTION IN THIS FILE. The danger of case memory is not
# that it breaks; it is that it works, and teaches its reader to clear today's
# alert because last month's looked similar. The warning text is the only thing
# standing between this feature and that outcome.

brief = cm.brief_for_incident({
    "id": incidents[0]["id"], "detection_id": "LNX-2002",
    "entity_type": "file", "entity_value": "/home/operator/.ssh/authorized_keys",
    "title": "SSH key added to a key file", "severity": "high",
    "source": "local_integrity", "first_seen_at": None,
})
text = cm.render_brief(brief)

ok("the rendered brief carries the evidence-not-verdict warning",
   "EVIDENCE, NOT A VERDICT" in text, detail=text[:300])
ok("the warning says a past dismissal is not a reason to dismiss this one",
   "not a reason to dismiss this one" in text, detail=text[-400:])
ok("the brief instructs the model to say WHICH precedent changed its view",
   "say which one and why" in text or "which one" in text, detail=text[-300:])
ok("the brief names the subject it is about",
   "/home/operator/.ssh/authorized_keys" in text, detail=text[:400])


section("[4] an unassessed row is LABELLED, never presented as a conclusion")
#
# "new" means the watcher raised it and nobody has looked. A precedent list
# that shows such a row with an empty assessment field reads as "nothing was
# found wrong", which is the opposite of "nobody examined this".

unassessed = cm.similar_incidents(detection_id="LNX-1102",
                                  title="masquerading system binary")
rows = unassessed["precedents"]
unassessed_rows = [r for r in rows if not r["assessed"]]
ok("there is at least one unassessed row in this fixture to check",
   len(unassessed_rows) >= 1, detail=str([r["id"] for r in rows]))

if unassessed_rows:
    row = unassessed_rows[0]
    ok("an unassessed precedent says nobody assessed it",
       "nobody has assessed" in (row.get("assessment_note") or ""),
       detail=str(row.get("assessment_note")))
    check("and it carries no assessment text at all",
          row.get("assessment"), None)

unassessed_brief = cm.render_brief(cm.brief_for_incident({
    "id": incidents[2]["id"], "detection_id": "LNX-1102",
    "entity_type": "process", "entity_value": "systemd-logind",
    "title": "Process masquerading as a system binary", "severity": "high",
    "source": "process_monitor"}))
ok("the rendered brief marks an unassessed row as never assessed",
   "never assessed" in unassessed_brief
   or "nobody has assessed" in unassessed_brief,
   detail=unassessed_brief[:600])
ok("and it does not print an empty 'what was concluded:' line",
   "what was concluded: \n" not in unassessed_brief
   and "what was concluded: None" not in unassessed_brief,
   detail=unassessed_brief[:600])


section("[5] entity_history and similar_incidents are DIFFERENT questions")
#
# They can disagree, and when they do the disagreement is the finding: an
# address with no history of its own but a dozen similar incidents elsewhere is
# a different situation from one that has done this every Tuesday for a month.
# A module that answered both with one function would lose that.

hist = cm.entity_history("ip", "192.0.2.47")
ok("entity_history finds the subject's own incident",
   any(i["id"] == incidents[3]["id"] for i in hist["incidents"]),
   detail=str(hist["counting"]))
ok("and states the span, not just the count",
   "earliest first seen" in (hist["counting"] or ""),
   detail=str(hist["counting"]))

nobody = cm.entity_history("ip", "203.0.113.99")
check("a subject with nothing is None, not a zero-length list dressed up",
      nobody["counting"], None)
ok("and it says the empty answer is a REAL negative",
   "real negative" in (nobody["note"] or ""), detail=str(nobody["note"]))
check("and lists nothing rather than something",
      (nobody["incidents"], nobody["findings"]), ([], []))

# The disagreement case, asserted as a property rather than a fixture: a
# subject can have NO history and STILL have precedents.
lonely = cm.similar_incidents(detection_id="LNX-1102",
                              entity_value="a-process-nobody-has-seen")
lonely_hist = cm.entity_history("process", "a-process-nobody-has-seen")
check("no history at all for that subject", lonely_hist["incidents"], [])
ok("but precedents for the RULE still come back",
   len(lonely["precedents"]) >= 1,
   detail=str(lonely["counts"]))
ok("the two answers are reported in different fields",
   "precedents" in lonely and "incidents" in lonely_hist,
   detail="collapsing them would lose the difference")

# A bad entity type is REFUSED rather than answered emptily.
try:
    cm.entity_history("nonsense", "x")
    ok("an unknown entity_type is refused", False, "it was accepted")
except cm.BadCaseMemoryInput as e:
    ok("an unknown entity_type is refused with a reason",
       "entity_type must be one of" in str(e), detail=str(e))

try:
    cm.entity_history("ip", "")
    ok("an empty entity_value is refused", False, "it was accepted")
except cm.BadCaseMemoryInput:
    ok("an empty entity_value is refused", True)


section("[6] the index follows the ledger and reports its lag as a NUMBER")
#
# The lag has to be able to be NON-ZERO, or the honesty claim in [1] is
# decoration. Forced here by REMOVING an index row, which is the shape a
# database restored from an older backup really has.

from core import incident as _inc                      # noqa: E402

before = cm.index_lag()
check("lag is 0 before the experiment", before["lag"], 0)

with me._get_conn() as conn:
    conn.execute("DELETE FROM case_fts WHERE rowid = ?", (incidents[3]["id"],))
    conn.execute("DELETE FROM case_index WHERE incident_id = ?",
                 (incidents[3]["id"],))

lagging = cm.index_lag()
check("removing one index row moves the lag by exactly one",
      lagging["lag"], 1)

behind = cm.similar_incidents(detection_id="NET-1001", title="New device")
ok("a lagging index does not claim a clean history",
   "behind by" in (behind["note"] or ""),
   detail=str(behind["note"]))

# And the SAME call after the watcher's pass is a real negative again, which is
# the other half of the claim: the number is not permanently alarming.
cm.index_pending()
now_current = cm.similar_incidents(detection_id="NET-1001", title="New device")
check("after a pass the lag is back to 0", cm.index_lag()["lag"], 0)
ok("and the same search now names the index as current",
   "behind by" not in (now_current["note"] or ""),
   detail=str(now_current["note"]))


section("[7] a missing FTS5 build degrades ONE half and says which")
#
# FTS5 is a compile-time option. On a build without it, the honest answer is a
# sentence naming the limit, NOT an empty list that reads as "nothing like this
# ever happened".

real_state = dict(cm._FTS_STATE)
cm._FTS_STATE.update({"checked": True, "available": False,
                      "reason": "TEST: this build has no FTS5"})
try:
    degraded = cm.similar_incidents(detection_id="LNX-1102", title="x")
    ok("precedent search reports the missing capability by name",
       "TEST: this build has no FTS5" in (degraded["note"] or ""),
       detail=str(degraded["note"]))
    check("and does not claim to have searched",
          degraded["counts"]["searched"], False)

    still = cm.entity_history("process", "systemd-logind")
    ok("entity history is UNAFFECTED by a missing FTS5",
       "incident" in (still["counting"] or ""), detail=str(still["counting"]))

    st = cm.status()
    check("status reports precedent_search off", st["precedent_search"], False)
    ok("and the note carries the reason rather than just a false",
       "FTS5" in (st["note"] or ""), detail=str(st["note"]))
finally:
    cm._FTS_STATE.update(real_state)


section("[8] the brief NEVER fails an investigation")
#
# An incident that goes unexamined because the MEMORY was broken is a worse
# outcome than one examined without it. The brief must always render, always
# say what happened, and never raise.

broken = cm.render_brief({"subject_history": None, "precedents": None,
                          "memory_available": False,
                          "note": "TEST: the memory could not be read"})
ok("a failed brief still renders text", isinstance(broken, str) and broken,
   detail=repr(broken))
ok("and it says the run has no history",
   "no history" in broken or "could not be read" in broken, detail=broken)

check("render_brief survives an empty dict", bool(cm.render_brief({})), True)
check("render_brief survives None", bool(cm.render_brief(None)), True)

# The real one: point the memory at something that cannot be read and confirm
# brief_for_incident still returns a usable brief rather than raising.
saved_path = me.DB_PATH
me.DB_PATH = "/nonexistent/definitely/not/a/database.db"
try:
    survived = cm.brief_for_incident({"id": 1, "detection_id": "LNX-1102",
                                      "entity_type": "process",
                                      "entity_value": "whatever",
                                      "title": "t", "severity": "high",
                                      "source": "process_monitor"})
    check("brief_for_incident does not raise on an unreadable database",
          isinstance(survived, dict), True)
    check("and flags itself unavailable", survived["memory_available"], False)
    rendered = cm.render_brief(survived)
    ok("and the rendered text tells the model it is working blind",
       "no history" in rendered or "without" in rendered
       or "could not be read" in rendered,
       detail=rendered[:300])
    st_blind = cm.status()
    check("status is BLIND when the ledger cannot be read at all",
          st_blind.get("blind"), True)
    ok("and the blind reason names the failure",
       bool(st_blind.get("blind_reason")), detail=str(st_blind))
finally:
    me.DB_PATH = saved_path


section("[9] the status contract: blind is for FAILURES only")
#
# A permanent limit reported as blind attaches a caveat to every answer for the
# life of the installation, and that is how a warning list becomes something a
# reader skips. An index that is merely BEHIND is not a failure either: it is a
# number, and it is on the note.

good = cm.status()
ok("a healthy memory is not blind", not good.get("blind"), detail=str(good))
check("it is reachable", good["reachable"], True)
check("it is ready", good["ready"], True)
ok("it carries the keys sensor_health actually reads",
   all(k in good for k in ("running", "ready", "reachable")),
   detail=str(sorted(good)))

from core import sensor_health as sh                  # noqa: E402
check("_module_trouble finds nothing wrong with a healthy memory",
      sh._module_trouble("case_memory", cm), None)

# The regression this file exists to hold: a database whose index is missing
# must NOT be reported as a component that is not answering. MEASURED before
# the fix -- it read "case_memory is NOT ANSWERING: no reason recorded".
me.DB_PATH = copy_db
cm._FTS_STATE["checked"] = False
try:
    degraded_status = cm.status()
    ok("an index that is NOT BUILT is not reported as blind",
       not degraded_status.get("blind"), detail=str(degraded_status))
    check("nor as unreachable", degraded_status["reachable"], True)
    check("but it is not ready either", degraded_status["ready"], False)
    trouble = sh._module_trouble("case_memory", cm)
    ok("and the health page finds nothing to shout about",
       trouble is None, detail=str(trouble))
    ok("while the note still names what is missing",
       "not been built" in (degraded_status.get("note") or ""),
       detail=str(degraded_status.get("note")))
finally:
    me.DB_PATH = saved_path
    cm._FTS_STATE["checked"] = False


section("[10] what reaches FTS5 is QUOTED and word-filtered")
#
# FTS5's MATCH string has its own syntax: AND, OR, NOT, NEAR, column filters
# and double quotes. A process name or a path is text somebody else chose, so a
# process named `NEAR` or a title containing a quote must be SEARCHED FOR, not
# executed as query syntax.

tokens = cm._query_tokens('NEAR("evil"', "OR", "AND", "x")
ok("operator words are extracted as plain words, not passed through",
   all(t.isalnum() for t in tokens) if tokens else True,
   detail=str(tokens))

hostile = cm.similar_incidents(title='x" OR "a" OR "b NEAR( AND ) --',
                               detection_id="LNX-1102")
ok("a hostile title does not raise out of the search",
   isinstance(hostile.get("precedents"), list), detail=str(hostile.get("note")))
check("and the search still ran", hostile["counts"]["searched"], True)

# A subject with no searchable words at all (an IP address) is an ordinary case
# and must not be treated as an error.
numeric = cm.similar_incidents(entity_type="ip", entity_value="192.0.2.47",
                               detection_id="NET-1001")
check("an address-only seed still searches on the rule and subject",
      numeric["counts"]["searched"], True)
ok("and it found the device incident",
   any(p["id"] == incidents[3]["id"] for p in numeric["precedents"]),
   detail=str([p["id"] for p in numeric["precedents"]]))

# The refusal: nothing to look for at all.
nothing = cm.similar_incidents()
check("a call with nothing to search on refuses", nothing["counts"].get("searched"), False)
ok("and says it is a refusal, not a negative",
   "refusal" in (nothing["note"] or "").lower(), detail=str(nothing["note"]))


section("[11] indexing is idempotent and does not duplicate")

cm.index_pending()
first = cm.index_lag()
second = cm.index_pending()
third = cm.index_lag()
check("a second pass adds no rows", (second["indexed"], second["updated"]),
      (0, 0))
check("and the lag is unchanged", (first["lag"], third["lag"]), (0, 0))

with me._get_readonly_conn() as conn:
    fts_rows = conn.execute("SELECT COUNT(*) FROM case_fts").fetchone()[0]
    idx_rows = conn.execute("SELECT COUNT(*) FROM case_index").fetchone()[0]
    incidents_now = conn.execute("SELECT COUNT(*) FROM incident").fetchone()[0]
check("the FTS table has exactly one row per incident", fts_rows, incidents_now)
check("the index table has exactly one row per incident", idx_rows,
      incidents_now)

# Re-indexing after an assessment lands must UPDATE, not duplicate: this is the
# path that carries a new assessment into the memory, and it is the one a model
# depends on when it asks what was concluded last time.
with me._get_conn() as conn:
    conn.execute("UPDATE incident SET assessment = ? WHERE id = ?",
                 ("TEST: a conclusion written after the first index pass",
                  incidents[1]["id"]))
updated_pass = cm.index_pending()
ok("a new assessment is picked up as an update",
   updated_pass["updated"] >= 1, detail=str(updated_pass))


with me._get_readonly_conn() as conn:
    still = conn.execute("SELECT COUNT(*) FROM case_fts").fetchone()[0]
check("the FTS row count is still one per incident after the update",
      still, incidents_now)

# The re-index must have made the NEW text findable, which is the whole point.
by_new_text = cm.similar_incidents(title="conclusion written after the first index pass")
new_text_hits = [p for p in by_new_text["precedents"]
                 if p["id"] == incidents[1]["id"]]
ok("the updated assessment is findable by its new wording",
   len(new_text_hits) >= 1,
   detail=f"counts={by_new_text['counts']} ids={[p['id'] for p in by_new_text['precedents']]}")


print()
print(f"{checks[0] - len(fails)}/{checks[0]} checks passed")
if fails:
    print(f"\n{len(fails)} FAILED:")
    for f in fails:
        print(f"  - {f}")
    sys.exit(1)
print("ALL PASS")
