"""
tests/test_provenance.py, TODO 21, what a baseline actually rests on.

THE ATTACK THIS ANSWERS
Feed crafted text to a sensor over weeks. The model reads it, writes
observations establishing that something is normal, those roll into a
baseline, and the baseline justifies suppression. Every step is individually
reasonable. What is missing is that by the last step nothing records that the
first step was attacker-controlled.

WHY NOT A GATE OR A CAP
write_behavioral_observation is meant to be called constantly, so a permission
card on it gets click-throughed within a day and then trains the operator to
approve writes unread. And the attack is patient, three observations a week
for two months sits under any tolerable cap. Volume controls do not fit this
tool; that is why the dismissal ceiling was the right shape for dismissals and
is the wrong shape here.

So the control is provenance. agent_loop already knew which tool results came
back untrusted and threw the fact away; now it reaches the row.
"""
import sys, sqlite3, tempfile, pathlib, json

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
from core import agent_loop, tool_registry as tr

SID = "test-session"


print("\n[1] the migration landed")
# 2026-09-02: this was an exact `== 17` and had been red since v18, which is
# five schema bumps ago. Same defect as the raise-count in
# test_tool_envelope.py: an exact assertion on a number that is SUPPOSED to
# grow fails for the correct reason every time, and a test that cries wolf is
# a test people stop reading.
#
# What this section actually asserts is that provenance landed, so the floor
# is the version that landed it.
check("schema is at or past the provenance version",
      migrations.SCHEMA_VERSION >= 17, True)
with sqlite3.connect(db) as c:
    cols = {r[1] for r in c.execute("PRAGMA table_info(behavioral_session)")}
check("evidence_untrusted", "evidence_untrusted" in cols, True)
check("evidence_sources", "evidence_sources" in cols, True)


print("\n[2] an observation written with NO fenced text in context is clean")
agent_loop._untrusted_seen.clear()
me.write_behavioral_observation(
    entity_type="ip", entity_value="192.0.2.10", behavior_key="active_hours",
    behavior_value="[9,17]", session_id=SID)
p = me.observation_provenance("ip", "192.0.2.10")
check("counted", p["total"], 1)
check("clean", p["clean"], 1)
check("not untrusted", p["untrusted_derived"], 0)


print("\n[3] an observation written AFTER reading fenced text is marked")
agent_loop._untrusted_seen.clear()
agent_loop._untrusted_seen.update({"query_packets", "query_dns"})
for _ in range(4):
    me.write_behavioral_observation(
        entity_type="ip", entity_value="192.0.2.20",
        behavior_key="beacon_interval", behavior_value="300",
        session_id=SID, context="derived from traffic")
p = me.observation_provenance("ip", "192.0.2.20")
check("all four marked", p["untrusted_derived"], 4)
check("none counted clean", p["clean"], 0)
check("and the sources are named", p["untrusted_sources"],
      ["query_dns", "query_packets"])
assert "slow poisoning" in p["note"], p["note"]
print("       note names the attack shape rather than just a ratio")


print("\n[4] the three populations are never summed into one number")
# 'unknown' is rows written before v17. Silence about provenance is not the
# same as clean provenance, and the payload must not let a reader treat it so.
with sqlite3.connect(db) as c:
    c.execute("""INSERT INTO behavioral_session
                 (session_id, entity_type, entity_value, behavior_key,
                  behavior_value, written_by, evidence_untrusted)
                 VALUES (?,?,?,?,?,?,NULL)""",
              (SID, "ip", "192.0.2.30", "active_hours", "[1]", "model"))
p = me.observation_provenance("ip", "192.0.2.30")
check("counted as unknown", p["unknown"], 1)
check("not as clean", p["clean"], 0)
check("not as untrusted either", p["untrusted_derived"], 0)
assert "Unknown is not clean" in p["note"], p["note"]


print("\n[5] an empty record is reported as empty, not as clean")
p = me.observation_provenance("ip", "192.0.2.99")
check("total zero", p["total"], 0)
assert "not a clean one" in p["note"], p["note"]


print("\n[6] provenance travels with the baseline on READ")
me.update_behavioral_baseline(entity_type="ip", entity_value="192.0.2.20",
                              behavior_key="beacon_interval",
                              session_id=SID, sample_count=4)
rows = me.query_behavioral_baseline(entity_value="192.0.2.20")
check("annotated", "provenance" in rows[0], True)
check("with the untrusted count attached",
      rows[0]["provenance"]["untrusted_derived"], 4)


print("\n[7] THE POINT: the suppression card says what the evidence rests on")
# Suppression already requires a human. So the attack targets the person, not
# the code, and this is the one moment where provenance changes the outcome.
card = tr.permission_summary("update_behavioral_baseline",
                             {"entity_type": "ip", "entity_value": "192.0.2.20",
                              "alert_suppressed": True})
check("card still says what the action does", "suppress future alerts" in card, True)
check("and now says what backs it", "What this rests on" in card, True)
check("naming the untrusted share", "4 of 4" in card, True)
print("       " + card.split("What this rests on: ")[1][:100] + "...")

clean_card = tr.permission_summary("update_behavioral_baseline",
                                   {"entity_type": "ip",
                                    "entity_value": "192.0.2.10"})
check("a clean baseline says so plainly",
      "without fenced text" in clean_card, True)


print("\n[8] the write is NEVER blocked by provenance")
# Same rule as the integrity journal: a control that can break the write it
# annotates gets switched off, and then it protects nothing.
import core.agent_loop as _al
_orig = _al.untrusted_sources_this_turn
_al.untrusted_sources_this_turn = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
try:
    r = me.write_behavioral_observation(
        entity_type="ip", entity_value="192.0.2.40",
        behavior_key="active_hours", behavior_value="[2]", session_id=SID)
    ok = r.get("success")
except Exception as e:
    ok = f"raised: {e}"
finally:
    _al.untrusted_sources_this_turn = _orig
check("the observation still lands", ok, True)


print("\n[9] taint is per TURN, not per session")
# "the model read fenced text at some point this session" is too coarse to
# mean anything. "the model had just read fenced text when it wrote this" is
# the actual claim being recorded.
src = (ROOT / "core" / "agent_loop.py").read_text(encoding="utf-8")
check("cleared at the top of each run", "_untrusted_seen.clear()" in src, True)
check("and the reasoning is written down", "per-turn rather than" in src, True)

print("\n[10] re-filing a row that predates the basis column")
# TODO 45. Rows written before v26 carry NULL, which reads as unrecorded. The
# fix is a copy with the basis filled in plus a withdrawal pointing at it, not
# an UPDATE on the old row. Two reasons, and I think the second is the bigger
# one: an in-place stamp pretends somebody answered the question at the time,
# and it leaves nothing behind for anyone reading later.
sys.path.insert(0, str(ROOT / "scripts"))
import refile_observation as rf                       # noqa: E402
rf.me.DB_PATH = db

with me._get_conn() as conn:
    old_id = conn.execute(
        "INSERT INTO behavioral_session (session_id, entity_type, entity_value,"
        " behavior_key, behavior_value, context, written_by,"
        " evidence_untrusted, evidence_sources)"
        " VALUES (?,?,?,?,?,?,'model',1,?)",
        (SID, "ip", "192.0.2.90", "typical_dest_ports", "[443]",
         "written before the column existed", '["query_packets"]')).lastrowid

check("the old row has no basis",
      rf.fetch(old_id)["basis"], None)

check("a bad basis is refused",
      rf.refile(old_id, "guessed", "no"), 1)
check("external_intel with no ref is refused",
      rf.refile(old_id, "external_intel", "no"), 1)
check("a dry run writes nothing",
      rf.refile(old_id, "measured", "the sniffer saw it", dry_run=True), 0)
check("and really wrote nothing", rf.fetch(old_id)["superseded_by"], None)

check("the re-file runs", rf.refile(old_id, "measured", "the sniffer saw it"), 0)

old = rf.fetch(old_id)
check("the old row is withdrawn", old["superseded_by"] is not None, True)
check("the old row still has its text", old["behavior_value"], "[443]")
check("and its basis was NOT stamped in place", old["basis"], None)

new = rf.fetch(old["superseded_by"])
check("the new row carries the basis", new["basis"], "measured")
check("the same claim came across", new["behavior_value"], "[443]")
check("the provenance came across rather than being recomputed",
      new["evidence_untrusted"], 1)
check("and it is not passed off as the model's",
      new["written_by"], "system")
check_contains = "re-filed from observation"
check("the new row says where it came from",
      check_contains in (new["context"] or ""), True)

check("a second re-file of the same row is refused",
      rf.refile(old_id, "measured", "again"), 1)

# The thing the script must never quietly skip. behavioral_baseline is
# cumulative and forward only, so a withdrawal does not rewind what the old
# row already fed into it. Saying so on screen is the whole mitigation we
# have today.
me.record_baseline_session(entity_type="ip", entity_value="192.0.2.91",
                           behavior_key="active_hours", session_id=SID)
with me._get_conn() as conn:
    rolled = conn.execute(
        "INSERT INTO behavioral_session (session_id, entity_type, entity_value,"
        " behavior_key, behavior_value, written_by)"
        " VALUES (?,?,?,?,?,'model')",
        (SID, "ip", "192.0.2.91", "active_hours", "[3]")).lastrowid
note = rf.baseline_note(rf.fetch(rolled))
check("a rolled up row says the baseline keeps what it got",
      "does not rewind" in note, True)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
