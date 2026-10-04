"""
tests/test_integrity.py, item 3.2, the hash-chained journal.

The point of this feature is narrow and the tests are mostly about keeping
the claim narrow. A chain living in the database it protects catches careless
tampering completely and a determined attacker not at all, because anyone who
reads core/integrity can rebuild it. What closes that gap is an ANCHOR held
off the machine.

So the suite checks three things in order of importance:
  the chain detects an edit and names where it starts
  an intact-but-REBUILT chain is reported as rebuilt when an anchor exists
  the journal can never break the write it is journaling
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
from core import integrity as ig

SID = "test-session"


print("\n[1] the migration created the journal")
with sqlite3.connect(db) as c:
    tables = {r[0] for r in c.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
check("integrity_journal exists", "integrity_journal" in tables, True)
# Asserted as a FLOOR, not an equality. The first version pinned 16 and broke
# the next time a migration landed (v17, observation provenance), a test
# about the journal failing because of an unrelated schema change is noise
# that teaches people to edit tests without reading them.
JOURNAL_INTRODUCED_IN = 16
check("schema is at least the version that added the journal",
      migrations.SCHEMA_VERSION >= JOURNAL_INTRODUCED_IN, True)


print("\n[2] high-value writes are journaled as they happen")
me.save_finding(session_id=SID, source="test", severity="high",
                entity_type="ip", entity_value="192.0.2.10",
                title="something", description="d",
                # TODO 112: every finding names the rule that raised it. Any
                # registered id declaring this severity does for a journal
                # test, which is about the chain and not the rule.
                detection_id="LNX-1004")
me.dismiss_entity("ip", "192.0.2.20", reason="test", dismissed_by="user")
# b8:27:eb is a real OUI with the locally-administered bit CLEAR.
# The first version of this fixture used aa:bb:cc, whose second
# nibble sets that bit, so set_device_permanence correctly refused
# it as a randomized address and nothing was journaled. The test
# was wrong, not the code.
me.save_known_device(ip="192.0.2.30", mac="b8:27:eb:11:22:33")
me.set_device_permanence("192.0.2.30", True)

with sqlite3.connect(db) as c:
    ops = [r[0] for r in c.execute(
        "SELECT operation FROM integrity_journal ORDER BY id")]
check("a finding was journaled", "finding_saved" in ops, True)
check("a dismissal was journaled", "finding_dismissed" in ops, True)
check("vouching was journaled", "device_vouched" in ops, True)
check("entries so far", len(ops) >= 3, True)


print("\n[3] an unrecognised operation is refused, not accepted")
# Same argument as finding_policy's unregistered sensor: the vocabulary stays
# a decision instead of accreting whatever a caller passes.
check("refused", ig.record("something_invented", "t", "1", {}), None)


print("\n[4] an untouched chain verifies, and says what that does NOT prove")
v = ig.verify_chain()
check("intact", v["status"], "intact")
check("counts what it checked", v["verified_entries"] >= 3, True)
check("and warns that coherence is not proof of no tampering",
      "rebuilt chain is also coherent" in v["note"], True)


print("\n[5] EDITING A ROW BREAKS THE CHAIN AND NAMES WHERE")
anchor_before = ig.anchor()
with sqlite3.connect(db) as c:
    target = c.execute("SELECT id FROM integrity_journal ORDER BY id LIMIT 1"
                       ).fetchone()[0]
    c.execute("UPDATE integrity_journal SET payload_digest='tampered' WHERE id=?",
              (target,))
v = ig.verify_chain()
check("detected", v["status"], "broken")
check("names the first break, not every downstream link",
      v["first_break_id"], target)
check("and says what kind of break it is",
      "do not match its hash" in v["reason"], True)
print(f"       {v['detail'][:70]}...")


print("\n[6] DELETING a row is caught too, as a different kind of break")
with sqlite3.connect(db) as c:
    c.execute("UPDATE integrity_journal SET payload_digest=("
              "SELECT payload_digest FROM integrity_journal WHERE id=?) "
              "WHERE id=?", (target, target))   # leave it tampered
    # now delete a middle entry outright
    mid = c.execute("SELECT id FROM integrity_journal ORDER BY id LIMIT 1 OFFSET 1"
                    ).fetchone()[0]
    c.execute("DELETE FROM integrity_journal WHERE id=?", (mid,))
v = ig.verify_chain()
check("still broken", v["status"], "broken")


print("\n[7] THE CASE THE CHAIN ALONE CANNOT CATCH, AND WHY THE ANCHOR EXISTS")
# Rebuild a perfectly valid chain from scratch, as an attacker who has read
# core/integrity would. Internal verification passes completely.
fresh = tmp / "rebuilt.db"
import shutil; shutil.copy(db, fresh)
with sqlite3.connect(fresh) as c:
    c.execute("DELETE FROM integrity_journal")
    prev = ig.GENESIS
    for i in range(3):
        ts, op, tbl, ref, pd = f"2026-01-0{i+1}", "finding_saved", "findings", f"r{i}", "d"
        eh = ig._entry_hash(prev, ts, op, tbl, ref, pd)
        c.execute("INSERT INTO integrity_journal(recorded_at,operation,"
                  "table_name,row_ref,payload_digest,prev_hash,entry_hash)"
                  " VALUES (?,?,?,?,?,?,?)", (ts, op, tbl, ref, pd, prev, eh))
        prev = eh

v = ig.verify_chain(db_path=fresh)
check("a rebuilt chain verifies as intact, this is the honest limit",
      v["status"], "intact")

v = ig.verify_chain(expected_head=anchor_before["head"], db_path=fresh)
check("but against an ANCHOR it is reported as rebuilt", v["status"], "rebuilt")
check("and the anchor is named as missing", v["anchor"], "ANCHOR_MISSING")
check("with an explanation, not just a status",
      "has been rebuilt" in v["note"], True)
print("       this is the whole reason anchor() returns the hash instead of")
print("       only writing a file next to the database")


print("\n[8] an anchor refuses to imply a guarantee it does not give")
a = ig.anchor(out_path=str(tmp / "anchor.json"))
check("returns the head", len(a["head"]), 64)
check("wrote the file", pathlib.Path(a["written_to"]).exists(), True)
check("and says a same-disk anchor is not a defence",
      "not a defence" in a["note"], True)


print("\n[9] the journal can NEVER break the write it is journaling")
# An integrity feature that takes down the app during an incident gets
# switched off, and then it protects nothing.
broke = False
try:
    ig.record("finding_saved", "findings", "x",
              {"unserialisable": object()})       # digest falls back to str()
except Exception:
    broke = True
check("a difficult payload does not raise", broke, False)

import core.integrity as _ig
_orig = _ig.sqlite3.connect
_ig.sqlite3.connect = lambda *a, **k: (_ for _ in ()).throw(OSError("disk gone"))
try:
    r = ig.record("finding_saved", "findings", "y", {})
    check("a dead database returns None instead of raising", r, None)
finally:
    _ig.sqlite3.connect = _orig

# And the real writer keeps working when journaling is impossible.
# Break the journal MODULE, which is the realistic failure: a bug in
# integrity.py, a missing table, a corrupt file. The writer must survive it.
#
# The first version of this check replaced me.ig.record instead, and the
# write died, which was fair, because the try/except lived only inside the
# shim. The guarantee now sits in _journal at every call site, so it holds
# however the journal fails.
import core.integrity as _igmod
_orig_record = _igmod.record
_igmod.record = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("journal down"))
try:
    me.save_finding(session_id=SID, source="test", severity="low",
                    entity_type="ip", entity_value="192.0.2.99",
                    title="written anyway", description="d",
                    detection_id="PKT-1001")
    wrote = len(me.query_findings(entity_value="192.0.2.99")) > 0
except Exception as e:
    wrote = f"raised: {e}"
finally:
    _igmod.record = _orig_record
check("the finding is still saved when the journal throws", wrote, True)

# And a dismissal too, the guarantee has to hold at every hooked site, not
# just the one that happened to be tested.
_igmod.record = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down"))
try:
    me.dismiss_entity("ip", "192.0.2.98", reason="x", dismissed_by="user")
    dismissed = me.is_dismissed("ip", "192.0.2.98")
except Exception as e:
    dismissed = f"raised: {e}"
finally:
    _igmod.record = _orig_record
check("and a dismissal still lands", dismissed, True)


print("\n[10] an anchor taken on an EMPTY journal is not a false alarm")
# GENESIS is the head when nothing has been recorded yet. It is never an
# entry_hash, only the first prev_hash, so a membership test alone reported
# ANCHOR_MISSING for anyone who anchored a fresh install and then used the
# tool normally. A tamper alarm that cries wolf teaches the operator to
# dismiss the real one.
empty = tmp / "empty.db"
c2 = sqlite3.connect(empty)
c2.executescript((ROOT/"Schema.SQL").read_text(encoding="utf-8")); c2.commit(); c2.close()
migrations.run_migrations(empty)
first = ig.anchor(db_path=empty)
check("an empty journal anchors at genesis", first["head"], ig.GENESIS)
check("and reports zero entries", first["entries"], 0)

_saved = me.DB_PATH
me.DB_PATH = empty
try:
    me.save_finding(session_id=SID, source="t", severity="low",
                    entity_type="ip", entity_value="192.0.2.77",
                    title="a legitimate later write", description="d",
                    detection_id="PKT-1001")
finally:
    me.DB_PATH = _saved

v = ig.verify_chain(expected_head=first["head"], db_path=empty)
check("the older anchor is still honoured", v["anchor"], "contains_anchor")
check("and the chain is not called rebuilt", v["status"], "intact")


print("\n[11] anchors append to a history instead of overwriting")
# Two anchors from different times bracket tampering to the window between
# them. One anchor only says something about now, and an overwrite destroys
# the older and more useful of the two.
h = tmp / "a.json"
a1 = ig.anchor(out_path=str(h), db_path=empty)
me_db = me.DB_PATH; me.DB_PATH = empty
try:
    me.save_finding(session_id=SID, source="t", severity="low",
                    entity_type="ip", entity_value="192.0.2.78",
                    title="another", description="d",
                    detection_id="PKT-1001")
finally:
    me.DB_PATH = me_db
a2 = ig.anchor(out_path=str(h), db_path=empty)
check("head moved", a1["head"] != a2["head"], True)
lines = pathlib.Path(a2["history"]).read_text().strip().split("\n")
check("both anchors kept in the history", len(lines), 2)
check("the latest file still holds the newest",
      json.loads(pathlib.Path(a2["written_to"]).read_text())["head"], a2["head"])
check("and the EARLIER anchor still verifies against the current chain",
      ig.verify_chain(expected_head=a1["head"], db_path=empty)["anchor"],
      "contains_anchor")

print("\n[12] withdrawing an observation is journalled")
# Added 2026-09-03, TODO 45. A withdrawal takes a row out of what the tool
# tells you next time, which is the rule this journal picks its operations on.
# It was missing, and I think it was just an oversight rather than a decision,
# since port_expectation_withdrawn right next to it is the same shape.
check("the vocabulary knows the operation",
      "observation_withdrawn" in ig.JOURNALLED, True)

wrote = me.write_behavioral_observation(
    entity_type="ip", entity_value="192.0.2.55",
    behavior_key="beacon_destinations", behavior_value="[443]",
    session_id=SID, context="test row", basis="measured")
check("a test observation went in", wrote.get("success"), True)

with sqlite3.connect(db) as c:
    before = c.execute("SELECT COUNT(*) FROM integrity_journal "
                       "WHERE operation='observation_withdrawn'").fetchone()[0]

res = me.supersede_observation(wrote["id"], "wrong on purpose, this is a test")
check("the withdrawal succeeded", res.get("success"), True)

with sqlite3.connect(db) as c:
    rows = c.execute(
        "SELECT row_ref FROM integrity_journal "
        "WHERE operation='observation_withdrawn'").fetchall()
check("one journal entry appeared", len(rows) - before, 1)
check("and it names the observation", rows[-1][0], str(wrote["id"]))

# The guarantee that matters more than the entry: the journal must never be
# able to break the write it is journaling. Same check [9] makes for findings,
# pointed at this path, because a broken journal taking down a withdrawal
# would get the journal switched off the first time it happened.
saved = ig.record
ig.record = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("journal down"))
try:
    w2 = me.write_behavioral_observation(
        entity_type="ip", entity_value="192.0.2.56",
        behavior_key="beacon_destinations", behavior_value="[80]",
        session_id=SID, basis="measured")
    out = me.supersede_observation(w2["id"], "still has to work")
    check("a withdrawal survives a broken journal", out.get("success"), True)
finally:
    ig.record = saved

with sqlite3.connect(db) as c:
    still = c.execute("SELECT superseded_by FROM behavioral_session "
                      "WHERE id=?", (w2["id"],)).fetchone()[0]
check("and the row really is withdrawn", still, -1)

print("\n[13] THE AGENT'S OWN RECORD IS SEALED, AND THAT WAS THE GAP")
# Added 2026-09-23. THE DEFECT THIS SECTION EXISTS FOR, measured before it was
# fixed on a copy of the live database: the journal sealed what the app knew
# about the NETWORK (findings, baselines, devices, suppressions) and nothing
# about ITSELF. Rewriting a duty report's verdict from 'no_action' to 'benign'
# and deleting the newest duty_run row left verify_chain() reporting intact
# with every entry counting. Root could edit the agent's history silently.
check("the vocabulary knows the new operations",
      all(op in ig.JOURNALLED for op in (
          "agent_run_recorded", "agent_report_written", "agent_message_logged",
          "action_request_filed", "incident_status_changed")), True)


def _fresh_sealed_db(name):
    """
    A brand-new migrated database for one group of checks.

    EVERY GROUP BELOW GETS ITS OWN, and the first draft of this section did
    not: it ran the tampering, the trim, the incident move and the action
    lifecycle against one file, so "filing does not break an untouched seal"
    failed on a database that an EARLIER check had already edited. The check
    was right and the apparatus was wrong. Same trap the skill records as
    stale state from a reused scratch dir.
    """
    path = tmp / name
    conn = sqlite3.connect(path)
    conn.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
    conn.commit()
    conn.close()
    migrations.run_migrations(path)
    return path


print("       A RUN ROW IS SEALED AND CARRIES WHAT THE AGENT CALLED")
db1 = _fresh_sealed_db("seal_run.db")
_saved_db = me.DB_PATH
me.DB_PATH = db1
try:
    from core import duty as _duty
    from core import actions as _actions
    from core import incident as _incident

    run_id = _duty._record_run("seal-test", "manual", "idle",
                               detail="a wake that did nothing",
                               tool_names=["query_findings", "query_packets"])
    check("a run row was written", run_id > 0, True)

    with sqlite3.connect(db1) as c:
        tools = c.execute("SELECT tools_json FROM duty_run WHERE id=?",
                          (run_id,)).fetchone()[0]
        n_entries = c.execute(
            "SELECT COUNT(*) FROM integrity_journal WHERE "
            "operation='agent_run_recorded'").fetchone()[0]
    # THE COLUMN THAT CLOSED THE DROPPED-NAMES DEFECT: run_unattended has
    # always returned these and duty._usage_dict threw them away.
    check("what the agent CALLED is on the row", json.loads(tools),
          ["query_findings", "query_packets"])
    check("and the row was sealed as it was written", n_entries, 1)

    v = ig.verify_sealed_rows(db_path=db1)
    check("an untouched sealed row verifies", v["status"], "intact")
    check("and it is counted as VERIFIED, not assumed",
          v["verified_rows"], 1)

    print("       EDITING THE AGENT'S OWN RUN RECORD BREAKS THE SEAL")
    with sqlite3.connect(db1) as c:
        c.execute("UPDATE duty_run SET detail='Nothing happened. All quiet.'"
                  " WHERE id=?", (run_id,))
    v = ig.verify_sealed_rows(db_path=db1)
    check("status is broken", v["status"], "broken")
    check("counted as an edit", v["edited_rows"], 1)
    check("and the entry NAMES the row, not just a count",
          v["problems"][0]["table"], "duty_run")
    check("and it names the row's id", v["problems"][0]["row_ref"],
          str(run_id))
finally:
    me.DB_PATH = _saved_db


print("       A REPORT'S VERDICT IS THE SHARPEST CASE, EDIT AND DELETE")
db2 = _fresh_sealed_db("seal_report.db")
me.DB_PATH = db2
try:
    report = _duty.write_report("seal-test", "incident", "manual",
                                body="I looked at this and read six things.",
                                hypothesis="a service restarted",
                                verdict="real",
                                coverage={"complete": True})
    rid = report["report_id"]
    check("an untouched report verifies",
          ig.verify_sealed_rows(db_path=db2)["status"], "intact")

    with sqlite3.connect(db2) as c:
        c.execute("UPDATE duty_report SET verdict='benign',"
                  " body='Nothing to see here.' WHERE id=?", (rid,))
    v = ig.verify_sealed_rows(db_path=db2)
    check("rewriting a verdict is caught", v["status"], "broken")
    check("and the report is the named table",
          any(p["table"] == "duty_report" for p in v["problems"]), True)

    with sqlite3.connect(db2) as c:
        c.execute("DELETE FROM duty_report WHERE id=?", (rid,))
    v = ig.verify_sealed_rows(db_path=db2)
    check("a deleted sealed row is reported as deleted", v["deleted_rows"], 1)
    # The filter matters: the earlier EDIT is still a problem on this
    # database, so index 0 is not necessarily the delete.
    del_problem = [p for p in v["problems"] if p["kind"] == "deleted"][0]
    check("and the sentence says the app never deletes from that table",
          "somebody else's delete" in del_problem["detail"], True)
finally:
    me.DB_PATH = _saved_db


print("       AN UNSEALED ROW IS 'UNKNOWN', NEVER CLEAN")
db3 = _fresh_sealed_db("seal_unsealed.db")
me.DB_PATH = db3
try:
    # A row written WITHOUT a seal, which is what every row that predates this
    # change looks like. Inserted directly because that is the only way to
    # produce one now.
    with sqlite3.connect(db3) as c:
        c.execute("INSERT INTO duty_run (session_id, ran_at, trigger, outcome,"
                  " detail) VALUES ('old','2026-09-01 00:00:00','manual',"
                  "'idle','a row from before the seal existed')")
    v = ig.verify_sealed_rows(db_path=db3)
    check("an unsealed row is counted in its OWN field",
          v["unsealed"]["duty_run"]["count"], 1)
    check("and it is NOT claimed as verified", v["verified_rows"], 0)
    check("and the note refuses to call it clean",
          "unknown" in v["unsealed"]["duty_run"]["note"], True)
    check("the status with nothing sealed is still intact, because nothing "
          "is broken", v["status"], "intact")
finally:
    me.DB_PATH = _saved_db


print("       THE CHAT LOG: the trim is housekeeping, a young delete is not")
db4 = _fresh_sealed_db("seal_trim.db")
me.DB_PATH = db4
try:
    for i in range(510):
        me.log_message("trim-sess", "user", f"message {i}")
    v = ig.verify_sealed_rows(db_path=db4)
    check("the app's own 500-row trim is counted separately",
          v.get("deleted_expected", 0) > 0, True)
    # THE NEGATIVE CONTROL THAT MATTERS: rows the app itself deleted must not
    # reach `deleted_rows`, or a busy week of chat would read as tampering.
    check("and trimmed rows do NOT count as tampering",
          v["deleted_rows"], 0)
    check("so a healthy database stays intact",
          v["status"], "intact")

    mid = me.log_message("young-sess", "user", "a real prompt")
    with sqlite3.connect(db4) as c:
        c.execute("DELETE FROM session_log WHERE id=?", (mid,))
    v = ig.verify_sealed_rows(db_path=db4)
    check("POSITIVE CONTROL: a row deleted out of a young session IS flagged",
          v["deleted_rows"], 1)
    check("and the flagged row is that one",
          [p for p in v["problems"] if p["row_ref"] == str(mid)][0]["table"],
          "session_log")
finally:
    me.DB_PATH = _saved_db


print("       AN INCIDENT MOVES AND THE MOVE IS WRITTEN DOWN")
db5 = _fresh_sealed_db("seal_incident.db")
me.DB_PATH = db5
try:
    made = _incident.write_incident("NET-1001", "ip", "198.51.100.99", "medium",
                                    "a test subject")
    with sqlite3.connect(db5) as c:
        before = c.execute(
            "SELECT COUNT(*) FROM integrity_journal WHERE "
            "operation='incident_status_changed'").fetchone()[0]
    _incident.set_status(made["id"], "triaged", by="model", note="assessed")
    with sqlite3.connect(db5) as c:
        rows = c.execute(
            "SELECT row_ref FROM integrity_journal WHERE "
            "operation='incident_status_changed'").fetchall()
    check("the transition left an entry", len(rows) - before, 1)
    check("and it names the incident", rows[-1][0], str(made["id"]))
finally:
    me.DB_PATH = _saved_db


print("       AN ORDINARY DECISION MUST NOT BREAK ANYTHING")
db6 = _fresh_sealed_db("seal_action.db")
me.DB_PATH = db6
try:
    # The negative control that matters most in practice: if approving a card
    # tripped the seal, every operator would learn to ignore the alarm.
    filed = _actions.write_request(
        "block_port", {"port": 4444, "direction": "inbound", "reason": "x"},
        reason="a test proposal")
    v = ig.verify_sealed_rows(db_path=db6)
    check("filing then verifying is quiet", (v["status"], v["edited_rows"]),
          ("intact", 0))
    check("and the proposal is sealed", v["verified_rows"], 1)

    _actions.decide(filed["request_id"], approved=True, decided_by="user",
                    note="ok")
    v = ig.verify_sealed_rows(db_path=db6)
    check("APPROVING it leaves the seal ALONE (decided_* is excluded)",
          (v["status"], v["edited_rows"]), ("intact", 0))
    _actions.expire_stale()
    v = ig.verify_sealed_rows(db_path=db6)
    check("and expiring leaves it alone too", (v["status"], v["edited_rows"]),
          ("intact", 0))

    # POSITIVE CONTROL for the same table: the FILED half is what is sealed.
    with sqlite3.connect(db6) as c:
        c.execute("UPDATE action_request SET reason='the operator asked me to'"
                  " WHERE id=?", (filed["request_id"],))
    v = ig.verify_sealed_rows(db_path=db6)
    check("but rewriting the REASON on the card is caught",
          (v["status"], v["edited_rows"]), ("broken", 1))
finally:
    me.DB_PATH = _saved_db


print("       THE COLUMN LISTS ARE ENFORCED, NOT TRUSTED")
# Every column of every sealed table must be either sealed or excluded WITH A
# REASON. An ALTER that adds one silently is the day the seal quietly covers
# less, so this is the check that goes red instead.
with sqlite3.connect(db1) as c:
    for table, spec in ig.SEALED_TABLES.items():
        actual = {r[1] for r in
                  c.execute(f"PRAGMA table_info({table})").fetchall()}
        declared = set(spec["columns"]) | set(spec["excluded"]) | {spec["key"]}
        check(f"{table}: every column is sealed or excluded",
              sorted(actual - declared), [])
        check(f"{table}: no declared column is a ghost",
              sorted(declared - actual), [])
        check(f"{table}: every excluded column carries a reason",
              [k for k, why in spec["excluded"].items() if not (why or "").strip()],
              [])

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
