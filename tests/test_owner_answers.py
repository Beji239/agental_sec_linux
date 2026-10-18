"""
tests/test_owner_answers.py, what the owner's answers and verdicts do.

On a scratch database: a yes to "is this device yours" names the device from
the owner's words and closes its new device incidents, a no leaves both
alone; while a device waits on the owner its low and medium alerts are kept
under its new device incident, with one notice, and a high one still gets
its own; calling an incident real undoes rules the model made that would
hide it, stops new ones, and sends alarms like it past the model's review.
"""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
db = _isolate_db.isolate()

from core import actions  # noqa: E402
from core import alert_review as ar  # noqa: E402
from core import duty  # noqa: E402
from core import incident  # noqa: E402
from core import learned_rules as lr  # noqa: E402
from core import memory_engine as me  # noqa: E402
from core import migrations  # noqa: E402
from core import questions  # noqa: E402

migrations.run_migrations(db)
duty.budget_state = lambda urgent=False: {"may_spend": True, "reasons": []}

failures = []
notices = []
actions.notify = lambda title, body, urgency="normal": notices.append(
    (title, body)) or {"sent": True}


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        failures.append(label)
        print(f"        {detail}")


def new_device(ip):
    return me.save_finding(
        session_id="t", source="router_monitor", detection_id="RTR-1001",
        severity="medium", entity_type="ip", entity_value=ip,
        title=f"Router reports a device not seen before: {ip}",
        description="test", raw_data={"ip": ip, "mac": "00:00:5e:00:53:44"})


def dns_alert(ip, severity="medium", did="DNS-1003", domain="sync.example"):
    return me.save_finding(
        session_id="t", source="dns_inspector", detection_id=did,
        severity=severity, entity_type="ip", entity_value=ip,
        title=f"Possible DNS tunnel under {domain}", description="test",
        raw_data={"registered_domain": domain, "client_ip": ip})


def incidents(ip):
    with me._get_readonly_conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM incident WHERE entity_value = ? ORDER BY id", (ip,))]


def ask(ip):
    with me._get_conn() as c:
        return c.execute(
            "INSERT INTO operator_question (session_id, asked_at, topic, "
            "entity_type, entity_value, question, state) VALUES ('t', "
            "datetime('now'), 'identify_device', 'ip', ?, 'Whose is it?', "
            "'open')", (ip,)).lastrowid


incident.watch_once("t")                      # sets the watermark

print("\n[1] One notice per new device, its lesser alerts kept under it")
NEW = "192.0.2.60"
new_device(NEW)
incident.watch_once("t")
check("one notice that a device needs attention",
      len(notices) == 1 and NEW in notices[0][1], notices)
dns_alert(NEW)
dns_alert(NEW, did="DNS-1006", domain="txt.example")
tick = incident.watch_once("t")
rows = incidents(NEW)
check("its medium alerts open no incident of their own",
      len(rows) == 1 and rows[0]["detection_id"] == "RTR-1001", rows)
check("they are counted under its new device incident",
      rows[0]["finding_count"] == 3 and tick.get("folded_into_device") == 2,
      (rows[0]["finding_count"], tick))
check("and no further notice", len(notices) == 1, notices)
with me._get_readonly_conn() as c:
    kept = c.execute("SELECT COUNT(*) FROM findings WHERE entity_value = ? "
                     "AND dismissed = 0", (NEW,)).fetchone()[0]
check("every alert is still in the findings", kept == 3, kept)
dns_alert(NEW, severity="high")
incident.watch_once("t")
check("a high alert still gets its own incident",
      [r for r in incidents(NEW) if r["detection_id"] == "DNS-1003"
       and r["severity"] == "high"], incidents(NEW))

print("\n[2] A yes names the device and closes its new device incidents")
qid = ask(NEW)
out = questions.answer(qid, "yes, the front desk laptop")
dev = out.get("device", {})
check("named from the owner's words", dev.get("named") ==
      "the front desk laptop", out)
with me._get_readonly_conn() as c:
    row = c.execute("SELECT known_as, identified_by, evidence FROM "
                    "known_devices WHERE ip = ?", (NEW,)).fetchone()
check("as the owner's own naming", row and row["identified_by"] == "user"
      and "question" in row["evidence"], dict(row) if row else None)
closed = [r for r in incidents(NEW) if r["detection_id"] == "RTR-1001"][0]
check("its new device incident is closed as a false alarm, on the owner's "
      "word", closed["status"] == "dismissed" and closed["verdict"] ==
      "false_alarm" and closed["verdict_by"] == "owner", closed)
check("the high incident is left for the owner",
      [r for r in incidents(NEW) if r["detection_id"] == "DNS-1003"][0]
      ["status"] in ("new", "triaged"))
with me._get_readonly_conn() as c:
    still = lr.waiting_device(c, {"entity_value": NEW, "raw_data": "{}"})
check("nothing is waiting on the owner any more", still is None, still)

print("\n[3] A no leaves both alone")
NOPE = "192.0.2.61"
new_device(NOPE)
incident.watch_once("t")
out = questions.answer(ask(NOPE), "no, I have never seen it")
with me._get_readonly_conn() as c:
    nope_named = c.execute("SELECT 1 FROM known_devices WHERE ip = ? AND "
                           "identified_by = 'user'", (NOPE,)).fetchone()
check("not named", "device" not in out and not nope_named, out)
check("its incident stays open", incidents(NOPE)[0]["status"] in
      ("new", "triaged"), incidents(NOPE))
check("a plain yes still names it, from what is known",
      questions.answer(ask("192.0.2.62"), "yes").get("device", {})
      .get("named") == "Known device")

print("\n[4] Real: nothing may hide an alarm the owner worried about")
OWNED = "192.0.2.70"
with me._get_conn() as c:
    c.execute("INSERT INTO known_devices (ip, known_as, identified_by) "
              "VALUES (?, 'Office PC', 'user')", (OWNED,))
    c.execute("INSERT INTO dns_answer (first_seen, last_seen, times_seen, "
              "name, rrtype, value) VALUES (datetime('now'), datetime('now'), "
              "1, 'beacon.example', 'A', '198.51.100.70')")
first = me.save_finding(
    session_id="t", source="dns_inspector", detection_id="DNS-1002",
    severity="medium", entity_type="ip", entity_value=OWNED,
    title="DNS beacon: polls beacon.example on schedule", description="t",
    raw_data={"domain": "beacon.example", "registered_domain":
              "beacon.example", "client_ip": OWNED})
with me._get_readonly_conn() as c:
    fid = c.execute("SELECT id FROM findings WHERE detection_id = 'DNS-1002' "
                    "AND entity_value = ?", (OWNED,)).fetchone()[0]
PATTERN = {"raw": {"registered_domain": "beacon.example"}}
made = lr.learn("DNS-1002", fid, PATTERN, "an update check",
                reason_kind="named_lookup")
check("the model made a rule", made.get("success"), made)
owner = lr.learn("DNS-1002", fid, {"raw": {"domain": "beacon.example"}},
                 "the owner's own", owner_words="that is my backup job")
inc = incident.write_incident("DNS-1002", "ip", OWNED, "medium", "beacon")
v = incident.set_verdict(inc["id"], "real", by="owner")
check("calling it real undoes the model's rule", v.get("rules_undone") ==
      [made["rule_id"]], v)
check("a rule on the owner's own words stays",
      [r for r in lr.listing()["rules"] if r["id"] == owner.get("rule_id")])
again = lr.learn("DNS-1002", fid, PATTERN, "an update check",
                 reason_kind="named_lookup")
check("and the model cannot learn it again", not again.get("success")
      and "real" in again.get("error", ""), again)
lr.undo(owner["rule_id"], reason="test")
ar._state["running"] = True
held = me.save_finding(
    session_id="t", source="dns_inspector", detection_id="DNS-1002",
    severity="medium", entity_type="ip", entity_value=OWNED,
    title="DNS beacon: polls beacon.example on schedule", description="t",
    raw_data={"domain": "beacon.example", "registered_domain":
              "beacon.example", "client_ip": OWNED})
asked = []
ar.review_once(run=lambda p: asked.append(p) or {"answers": [], "usage": {}})
item = [i for i in ar.listing()["items"] if i["id"] == held.get("review_id")]
check("alarms like it skip the model's review and come to the owner",
      item and item[0]["status"] == "shown" and not asked, item)

print("\nALL PASSED" if not failures else f"\nFAILED: {failures}")
sys.exit(1 if failures else 0)
