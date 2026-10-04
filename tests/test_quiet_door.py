"""
tests/test_quiet_door.py, TODO 8.1F. Untrusted evidence cannot suppress,
and cannot reach high confidence on its own.

WHY THIS FILE EXISTS. 8.1F is the largest security gap this project had
written down, and the thing that makes it dangerous is that being wrong here
is INVISIBLE. Nothing errors when a poisoned baseline reaches high confidence
and stops being alerted on. It just goes quiet, which is what everybody wants
it to look like anyway.

THE RULE, in two parts of different strengths:

  the floor   never stop alerting on an entity whose evidence is ENTIRELY
              untrusted. Not a judgement about volume, a refusal to go blind
              on a set of text an attacker could have chosen all of.
  the cap     high confidence needs the CLEAN sessions alone to reach the
              medium threshold. Untrusted evidence can carry a row from
              medium to high; it cannot get there by itself.

Suppression is REFUSED and confidence is CLAMPED, and the asymmetry is tested
because it is a decision rather than an accident. A smaller confidence is
still a claim the caller can learn from. Half-suppressed does not exist.

Both parts count SESSIONS, not observations, because that is what confidence
has meant since TODO 22 and counting observations is how one chatty poll loop
used to manufacture a high-confidence baseline in an afternoon.
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


tmp = pathlib.Path(tempfile.mkdtemp(prefix="agental_quiet_"))
DB = tmp / "test.db"

from core import memory_engine as me            # noqa: E402
me.DB_PATH = str(DB)

conn = sqlite3.connect(DB)
conn.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
conn.commit()
conn.close()

from core import migrations                     # noqa: E402
migrations.run_migrations(DB)

ENTITY = ("ip", "203.0.113.9", "beacon_destinations")


def observe(session, untrusted, entity=ENTITY):
    """One observation, in a named session, flagged or not."""
    with sqlite3.connect(DB) as c:
        c.execute(
            """INSERT INTO behavioral_session
                 (session_id, entity_type, entity_value, behavior_key,
                  behavior_value, written_by, evidence_untrusted)
               VALUES (?,?,?,?,'x','model',?)""",
            (session, entity[0], entity[1], entity[2], 1 if untrusted else 0))
        c.execute(
            """INSERT OR IGNORE INTO baseline_session_seen
                 (entity_type, entity_value, behavior_key, session_id)
               VALUES (?,?,?,?)""",
            (entity[0], entity[1], entity[2], session))


def sessions_seen(entity=ENTITY):
    return me.count_baseline_sessions(*entity)


print("\n[1] a baseline built ENTIRELY from untrusted turns")
# Eight sessions, past the high threshold of six, every one of them written
# while the model was reading text somebody else chose. This is the patient
# poisoning shape, and by session count alone it looks like a solid baseline.
for i in range(8):
    observe(f"poisoned-{i}", untrusted=True)
check("it has enough sessions for high on the count alone",
      sessions_seen() >= me.confidence_thresholds()["high"], True)

gate = me.evidence_gate(*ENTITY)
check("no clean session under it", gate["clean_sessions"], 0)
check("it may not be suppressed", gate["may_suppress"], False)
check("and it may not reach high", gate["may_reach_high"], False)
check("the refusal explains itself rather than just saying no",
      "poisoning" in (gate["reason"] or ""), True)


print("\n[2] suppression is REFUSED, not quietly downgraded")
# The whole attack is getting the tool to stop reporting. This is the line
# that has to hold, so it raises rather than returning a flag somebody can
# forget to read. Same argument as item 1.8.
try:
    me.update_behavioral_baseline(*ENTITY, session_id="poisoned-8",
                                  alert_suppressed=True)
    check("suppression on all-untrusted evidence refused", False, True)
except me.BadInput as e:
    check("suppression on all-untrusted evidence refused", True, True)
    check("and the refusal says what would fix it",
          "does not rest on fenced" in str(e), True)

with sqlite3.connect(DB) as c:
    row = c.execute("SELECT alert_suppressed FROM behavioral_baseline "
                    "WHERE entity_value = ?", (ENTITY[1],)).fetchone()
check("nothing was suppressed", (row[0] if row else 0), 0)


print("\n[3] high confidence is CLAMPED, and the caller is told")
# Asymmetric on purpose: a smaller confidence is still a claim, and a caller
# that learns why can go and fix it. Suppression has no smaller version.
res = me.update_behavioral_baseline(*ENTITY, session_id="poisoned-8",
                                    confidence="high")
check("the write succeeded", res["success"], True)
with sqlite3.connect(DB) as c:
    conf = c.execute("SELECT confidence FROM behavioral_baseline "
                     "WHERE entity_value = ?", (ENTITY[1],)).fetchone()[0]
check("stored at medium, not high", conf, "medium")
check("and the result says why",
      "poisoning attack produces" in res.get("evidence_note", ""), True)
# Both halves are reported when both apply, so the model is not told it
# cannot suppress while silently wondering why its confidence moved.
check("and it also names the confidence bar",
      "needed for high confidence" in res.get("evidence_note", ""), True)


print("\n[4] clean evidence unblocks it, which is the point")
# The rule has to be passable by an honest sensor or it is an off switch.
for i in range(me.confidence_thresholds()["medium"]):
    observe(f"clean-{i}", untrusted=False)
gate = me.evidence_gate(*ENTITY)
check("clean sessions counted", gate["clean_sessions"],
      me.confidence_thresholds()["medium"])
check("it may reach high now", gate["may_reach_high"], True)
check("and it may be suppressed", gate["may_suppress"], True)

res = me.update_behavioral_baseline(*ENTITY, session_id="clean-9",
                                    confidence="high")
with sqlite3.connect(DB) as c:
    conf = c.execute("SELECT confidence FROM behavioral_baseline "
                     "WHERE entity_value = ?", (ENTITY[1],)).fetchone()[0]
check("high is allowed once clean evidence carries it", conf, "high")
check("no evidence note when nothing was held back",
      "evidence_note" in res, False)


print("\n[5] ONE clean session is enough for the floor, not for the cap")
# The two parts are different strengths and must not collapse into each
# other. One clean session says this is not built entirely out of somebody
# else's text; it does not say there is much evidence.
OTHER = ("ip", "203.0.113.44", "beacon_destinations")
for i in range(8):
    observe(f"o-poison-{i}", untrusted=True, entity=OTHER)
observe("o-clean-0", untrusted=False, entity=OTHER)

gate = me.evidence_gate(*OTHER)
check("one clean session lifts the suppression floor", gate["may_suppress"], True)
check("but not the high-confidence cap", gate["may_reach_high"], False)
check("and it says how many more are needed",
      f"{me.confidence_thresholds()['medium']} are needed for high"
      in (gate["reason"] or ""), True)


print("\n[6] the rule can be turned down, and turning it off is total")
# The measurement it was chosen from is one network on one day. A busier
# network could be nearly all untrusted, and somebody has to be able to fall
# back without editing the module.
me.set_preference(me.EVIDENCE_RULE_PREF, "floor")
gate = me.evidence_gate(*OTHER)
check("'floor' keeps the suppression refusal", gate["may_suppress"], True)
check("'floor' drops the confidence cap", gate["may_reach_high"], True)

me.set_preference(me.EVIDENCE_RULE_PREF, "off")
gate = me.evidence_gate(*ENTITY)
check("'off' allows everything", (gate["may_suppress"], gate["may_reach_high"]),
      (True, True))

# A bad preference falls back rather than raising. A monitor that refuses to
# start over a typo is a monitor that is not watching.
me.set_preference(me.EVIDENCE_RULE_PREF, "nonsense")
check("an invalid rule falls back to full", me.evidence_rule(), "full")
me.set_preference(me.EVIDENCE_RULE_PREF, "full")


print("\n[7] an entity with no observations at all is not suppressible")
# An empty record is not a clean one. This is the same rule
# observation_provenance already states in words.
EMPTY = ("ip", "203.0.113.77", "beacon_destinations")
gate = me.evidence_gate(*EMPTY)
check("nothing observed means nothing to suppress", gate["may_suppress"], False)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
