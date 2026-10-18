"""
tests/test_learned_rules.py, quiet rules learned from false alarms.

On a scratch database: a rule learned from one false alarm holds back the
same pattern from another address and counts it, clears the matching open
findings, leaves other devices alone, refuses rules that fit nothing, that
turn a detection off or that cover critical findings, and stops holding once
undone. The model's tools reach the same code.
"""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
db = _isolate_db.isolate()

from core import learned_rules as lr  # noqa: E402
from core import memory_engine as me  # noqa: E402
from core import migrations  # noqa: E402
from core import tool_registry as tr  # noqa: E402

migrations.run_migrations(db)

failures = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        failures.append(label)
        print(f"        {detail}")


TV, PHONE = "00:00:5e:00:53:31", "00:00:5e:00:53:32"


def raise_geo(ip, mac, label, asn="AS64500"):
    return me.save_finding(
        session_id="t", source="place_watch", severity="low",
        entity_type="ip", entity_value=ip, detection_id="GEO-1002",
        title=f"Device {label} reached a new network: {asn} Example",
        description="test",
        raw_data={"subject_type": "device", "subject": mac, "label": label,
                  "place_type": "network", "place": asn, "ip": ip})


def open_ids():
    with me._get_readonly_conn() as c:
        return [r[0] for r in c.execute(
            "SELECT id FROM findings WHERE detection_id = 'GEO-1002' "
            "AND dismissed = 0 ORDER BY id")]


def named(ip, name="cdn.example"):
    """The router's resolver answered this address for a name."""
    with me._get_conn() as c:
        c.execute("INSERT INTO dns_answer (first_seen, last_seen, times_seen, "
                  "name, rrtype, value) VALUES (datetime('now'), "
                  "datetime('now'), 1, ?, 'A', ?)", (name, ip))


TV_RULE = {"raw": {"subject": TV, "place_type": "network"}}

print("\n[1] Learn from one false alarm, with a fact Python checks")
for ip in ("203.0.113.10", "203.0.113.11", "198.51.100.20"):
    named(ip)
raise_geo("203.0.113.10", TV, "Test TV")
raise_geo("203.0.113.11", TV, "Test TV")
raise_geo("203.0.113.12", PHONE, "Test phone")
first = open_ids()[0]
out = lr.learn("GEO-1002", first, TV_RULE,
               "the TV reaches its streaming CDNs", by="model",
               reason_kind="named_lookup")
check("the rule is made", out.get("success"), out)
check("the replay counts both TV findings",
      out.get("replay", {}).get("would_hold") == 2, out.get("replay"))
check("the open TV findings are cleared", out.get("cleared_open_findings") == 2,
      out)
check("the phone's finding stays open", len(open_ids()) == 1, open_ids())
check("an attended rule is not on trial", out.get("trial_until") is None)
rid = out.get("rule_id")

print("\n[2] The same pattern is held back only when the fact checks out")
r = raise_geo("198.51.100.20", TV, "Test TV", asn="AS64511")
check("a named destination is held", r.get("learned_rule_id") == rid, r)
r = raise_geo("198.51.100.23", TV, "Test TV", asn="AS64511")
check("an unnamed one from the same TV is raised", r.get("saved") is True, r)
check("another device still raises",
      raise_geo("198.51.100.21", PHONE, "Test phone").get("saved") is True)
rules = lr.listing()["rules"]
check("the hold is counted", rules and rules[0]["held_count"] == 1, rules)
check("and shown for the last week", rules[0]["held_last_7_days"] == 1, rules)

print("\n[3] Refusals")
check("a rule must fit its example", not lr.learn(
    "GEO-1002", first, {"raw": {"subject": "00:00:5e:00:53:99",
                                "place_type": "network"}}, "x",
    reason_kind="named_lookup").get("success"))
check("a pattern of wildcards is refused", not lr.learn(
    "GEO-1002", first, {"raw": {"domain": "*"}}, "x",
    reason_kind="named_lookup").get("success"))
check("an empty pattern is refused", not lr.learn(
    "GEO-1002", first, {}, "x", reason_kind="named_lookup").get("success"))
check("a reason is needed", not lr.learn(
    "GEO-1002", first, TV_RULE, "", reason_kind="named_lookup").get("success"))
check("the same rule twice is refused", not lr.learn(
    "GEO-1002", first, TV_RULE, "again",
    reason_kind="named_lookup").get("success"))
title = lr.learn("GEO-1002", first, {"title": "*Test TV*"}, "x",
                 reason_kind="named_lookup")
check("a title pattern is refused", not title.get("success")
      and "title" in title.get("error", ""), title)
check("a MAC alone is refused", not lr.learn(
    "GEO-1002", first, {"raw": {"subject": TV}}, "x",
    reason_kind="named_lookup").get("success"))
check("no reason_kind and no owner words is refused", not lr.learn(
    "GEO-1002", first, {"entity": "203.0.113.10"}, "x").get("success"))
unchecked = lr.learn("GEO-1002", open_ids()[0], {"entity": "203.0.113.12"},
                     "x", reason_kind="named_lookup")
check("a fact that does not check out is refused",
      not unchecked.get("success")
      and "could not confirm" in unchecked.get("error", ""), unchecked)
for i in range(6):
    raise_geo(f"192.0.2.{40 + i}", f"00:00:5e:00:53:{40 + i}", f"Box {i}")
wide = lr.learn("GEO-1002", open_ids()[-1],
                {"raw": {"place_type": "network"}},
                "everything is fine", owner_words="all fine")
check("a rule that holds every finding turns the detection off, refused",
      not wide.get("success") and "turns" in wide.get("error", ""), wide)
check("a finding from another detection is refused", not lr.learn(
    "GEO-1001", first, TV_RULE, "x", reason_kind="named_lookup").get("success"))
check("critical findings are never held",
      lr.holds("GEO-1002", "x", "t", {"subject": TV}, "critical") is None)

print("\n[3b] The owner's word, threat lists and trials")
fed = me.save_finding(
    session_id="t", source="feed_matcher", severity="high",
    entity_type="ip", entity_value="192.0.2.90", detection_id="FED-1002",
    title="Resolved a listed malicious domain: files.example",
    raw_data={"domain": "files.example", "matched": "files.example"})
with me._get_readonly_conn() as c:
    fid = c.execute("SELECT MAX(id) FROM findings WHERE detection_id = "
                    "'FED-1002'").fetchone()[0]
check("a threat list hit is refused without the owner", not lr.learn(
    "FED-1002", fid, {"raw": {"matched": "files.example"}}, "x",
    reason_kind="named_lookup").get("success"))
own = lr.learn("FED-1002", fid, {"raw": {"matched": "files.example"}},
               "the owner's own downloads", owner_words="that was me")
check("but made on the owner's word", own.get("success"), own)
named("192.0.2.95")
raise_geo("192.0.2.95", "00:00:5e:00:53:60", "Speaker")
sid = open_ids()[-1]
trial = lr.learn("GEO-1002", sid, {"entity": "192.0.2.95"},
                 "a speaker's named CDN", reason_kind="named_lookup",
                 unattended=True)
check("a rule made with nobody watching is on trial",
      bool(trial.get("trial_until")), trial)
check("no owner words when nobody is watching", not lr.learn(
    "GEO-1002", sid, {"entity": "192.0.2.95"}, "x", owner_words="me",
    unattended=True).get("success"))
with me._get_conn() as c:
    c.execute("UPDATE learned_rule SET trial_until = '2000-01-01T00:00:00"
              "+00:00' WHERE id = ?", (trial["rule_id"],))
lr._forget()
check("a lapsed trial holds nothing", raise_geo(
    "192.0.2.95", "00:00:5e:00:53:60", "Speaker").get("saved") is True)
check("keep turns it back on", lr.keep(trial["rule_id"])["success"])
check("and it holds again", raise_geo(
    "192.0.2.95", "00:00:5e:00:53:60", "Speaker").get("learned_rule_id")
    == trial["rule_id"])
for k in range(lr.UNATTENDED_PER_DAY):
    named(f"192.0.2.{100 + k}")
    raise_geo(f"192.0.2.{100 + k}", "00:00:5e:00:53:61", "Lamp")
    lr.learn("GEO-1002", open_ids()[-1], {"entity": f"192.0.2.{100 + k}"},
             "lamp", reason_kind="named_lookup", unattended=True)
capped = lr.learn("GEO-1002", open_ids()[-1], {"entity": "192.0.2.104"},
                  "lamp again", reason_kind="named_lookup", unattended=True)
check("a daily limit on rules made with nobody watching",
      not capped.get("success") and "limit" in capped.get("error", ""),
      capped)

print("\n[4] The model's tools")
check("learn_quiet_rule is a tool", tr.tool_exists("learn_quiet_rule"))
check("and counts as a write", tr.tool_writes("learn_quiet_rule"))
listed = tr._dispatch("query_learned_rules", {})
check("query_learned_rules lists the rule",
      rid in [x["id"] for x in listed["rules"]], listed)

print("\n[5] Undo")
u = tr._dispatch("undo_learned_rule", {"rule_id": rid, "reason": "test"})
check("undone", u.get("success"), u)
named("198.51.100.22")
check("the TV raises again",
      raise_geo("198.51.100.22", TV, "Test TV", asn="AS64512").get("saved"))
check("an undone rule is listed only on request",
      rid not in [x["id"] for x in lr.listing()["rules"]]
      and [x for x in lr.listing(include_undone=True)["rules"]
           if x["id"] == rid][0]["undone_by"] == "model")
with me._get_readonly_conn() as c:
    ops = {r[0] for r in c.execute("SELECT operation FROM integrity_journal")}
check("making and undoing are journalled",
      {"learned_rule_made", "learned_rule_undone"} <= ops, ops)

print("\n[6] Closing incidents")
from core import incident  # noqa: E402
raise_geo("192.0.2.80", PHONE, "Test phone")
a = incident.write_incident("GEO-1002", "ip", "192.0.2.80", "low", "t")
b = incident.write_incident("LNX-2012", "file", "/etc/example", "high", "t")
ids = [a.get("incident_id") or a.get("id"), b.get("incident_id") or b.get("id")]
out = tr._dispatch("close_incidents", {"incident_ids": ids,
                                       "reason": "the owner's own work",
                                       "owner_words": "that was me"})
check("both closed", sorted(out["closed"]) == sorted(ids), out)
check("their open findings are cleared", out["findings_cleared"] >= 1, out)
with me._get_readonly_conn() as c:
    v = [r[0] for r in c.execute("SELECT verdict FROM incident WHERE id IN "
                                 "(?, ?)", ids)]
check("a false alarm verdict on the owner's word", v == ["false_alarm"] * 2, v)
check("a reason is needed", not incident.close_many(ids, "")["success"])

print("\n[7] Nothing is learned from a device still waiting on the owner")
NEWCOMER = "192.0.2.239"
with me._get_conn() as c:
    c.execute("INSERT INTO incident (incident_key, detection_id, entity_type, "
              "entity_value, severity, title, first_seen_at, last_seen_at, "
              "status, status_at) VALUES ('t-new-device', 'RTR-1001', 'ip', ?, "
              "'medium', 'Router reports a device not seen before', "
              "datetime('now'), datetime('now'), 'triaged', datetime('now'))",
              (NEWCOMER,))
zoom = {"review_id": 1, "detection_id": "DNS-1003", "severity": "medium",
        "entity_value": NEWCOMER, "title": "Possible DNS tunnel under zoom.us",
        "raw_data": json.dumps({"registered_domain": "zoom.us",
                                "client_ip": NEWCOMER})}
waiting = lr.learn("DNS-1003", None, {"raw": {"registered_domain": "zoom.us"}},
                   "a big cloud service", example=zoom,
                   reason_kind="cloud_network", unattended=True)
check("a rule from the new device's traffic is refused",
      not waiting.get("success") and "waiting on the owner" in
      (waiting.get("error") or ""), waiting)
check("the owner's own words still make one", lr.learn(
    "DNS-1003", None, {"raw": {"registered_domain": "zoom.us"}},
    "a big cloud service", example=zoom,
    owner_words="that is my laptop on zoom").get("success"))
lr.undo(max(r["id"] for r in lr.listing()["rules"]), reason="test")
with me._get_conn() as c:
    c.execute("INSERT INTO known_devices (ip, known_as, identified_by) "
              "VALUES (?, 'Laptop', 'user')", (NEWCOMER,))
named_now = lr.learn("DNS-1003", None, {"raw": {"registered_domain": "zoom.us"}},
                     "a big cloud service", example=zoom,
                     reason_kind="cloud_network", unattended=True)
check("once the owner names it, that refusal is gone",
      "waiting on the owner" not in (named_now.get("error") or ""), named_now)

print("\n[9] A rule the model makes covers its own device until it is earned")
named("198.51.100.7", "updates.example.net")
BEACON = {"raw": {"registered_domain": "example.net"}}


def beacon(ip, n):
    return {"review_id": 100 + n, "detection_id": "DNS-1002",
            "severity": "medium", "entity_value": ip,
            "title": "DNS beacon: polls updates.example.net on schedule",
            "raw_data": json.dumps({"domain": "updates.example.net",
                                    "registered_domain": "example.net",
                                    "client_ip": ip})}


def learn_from(ip, n):
    return lr.learn("DNS-1002", None, BEACON, "a vendor's update check",
                    example=beacon(ip, n), reason_kind="named_lookup")


def name_device(ip):
    with me._get_conn() as c:
        c.execute("INSERT INTO known_devices (ip, known_as, identified_by) "
                  "VALUES (?, 'device', 'user')", (ip,))


first = learn_from("192.0.2.21", 1)
check("it is made for that device only",
      first.get("success") and first["match"].get("entity") == "192.0.2.21"
      and first.get("scope") == "only 192.0.2.21", first)
check("another device doing the same is not covered",
      not lr.matches(first["match"], "192.0.2.22", "x",
                     json.dumps({"registered_domain": "example.net"})))
for ip in ("192.0.2.21", "192.0.2.22", "192.0.2.23", "192.0.2.24"):
    name_device(ip)
learn_from("192.0.2.22", 2)
learn_from("192.0.2.23", 3)
fresh = learn_from("192.0.2.24", 4)
check("named devices with rules days younger than the limit do not earn it",
      fresh["match"].get("entity") == "192.0.2.24", fresh)
with me._get_conn() as c:
    c.execute("UPDATE learned_rule SET created_at = '2026-01-01T00:00:00+00:00' "
              "WHERE detection_id = 'DNS-1002' AND match_json LIKE "
              "'%example.net%'")
name_device("192.0.2.25")
wide = learn_from("192.0.2.25", 5)
check("held on enough named devices for days, it covers every device",
      wide.get("success") and "entity" not in wide["match"]
      and wide.get("scope", "").startswith("every device"), wide)
own = lr.learn("DNS-1002", None, {"raw": {"registered_domain": "example.org"}},
               "my own words", example=dict(beacon("192.0.2.30", 6), raw_data=
               json.dumps({"domain": "a.example.org",
                           "registered_domain": "example.org",
                           "client_ip": "192.0.2.30"})),
               owner_words="every device may do this")
check("the owner's words keep the pattern as written",
      own.get("success") and "entity" not in own["match"], own)

print("\n[10] While the owner's answer is due, a rule is provisional")
from core import questions  # noqa: E402
named("198.51.100.9", "sync.example.com")
SYNC = {"raw": {"registered_domain": "example.com"}}


def sync(ip, n=0):
    return {"review_id": 200 + n, "detection_id": "DNS-1002",
            "severity": "medium", "entity_value": ip,
            "title": "DNS beacon: polls sync.example.com on schedule",
            "raw_data": json.dumps({"domain": "sync.example.com",
                                    "registered_domain": "example.com",
                                    "client_ip": ip})}


def ask(ip):
    with me._get_conn() as c:
        return c.execute(
            "INSERT INTO operator_question (session_id, asked_at, topic, "
            "entity_type, entity_value, question, state) VALUES ('t', "
            "datetime('now'), 'identify_device', 'ip', ?, ?, 'open')",
            (ip, f"Do you know {ip}?")).lastrowid


def raise_sync(ip):
    return me.save_finding(
        session_id="t", source="dns_inspector", severity="medium",
        entity_type="ip", entity_value=ip, detection_id="DNS-1002",
        title="DNS beacon: polls sync.example.com on schedule",
        description="test", raw_data=json.loads(sync(ip)["raw_data"]))


def finding_state(ip):
    with me._get_readonly_conn() as c:
        return [tuple(r) for r in c.execute(
            "SELECT dismissed, dismissed_reason FROM findings WHERE "
            "detection_id = 'DNS-1002' AND entity_value = ? ORDER BY id",
            (ip,))]


ASKED, OTHER = "192.0.2.77", "192.0.2.78"
qid = ask(ASKED)
prov = lr.learn("DNS-1002", None, SYNC, "a sync service polling",
                example=sync(ASKED), reason_kind="named_lookup")
check("a rule is made, provisional", prov.get("success")
      and prov.get("provisional"), prov)
check("it covers that device only", prov.get("match", {}).get("entity")
      == ASKED and "provisional until the owner answers" in
      prov.get("scope", ""), prov)
held = raise_sync(ASKED)
check("a repeat is recorded, not raised", held.get("held_provisionally")
      == prov.get("rule_id") and finding_state(ASKED)[-1][0] == 1, held)
check("another device is not covered",
      raise_sync(OTHER).get("held_provisionally") is None
      and finding_state(OTHER)[-1][0] == 0)
with me._get_conn() as c:
    c.execute("UPDATE learned_rule SET created_at = '2026-01-01T00:00:00+00:00' "
              "WHERE question_state = 'open'")
    for ip in ("192.0.2.71", "192.0.2.72", ASKED):
        c.execute("INSERT INTO known_devices (ip, known_as, identified_by) "
                  "VALUES (?, 'device', 'user')", (ip,))
    extra = c.execute(
        "INSERT INTO learned_rule (detection_id, match_json, reason, "
        "created_by, created_at, question_id, question_state) VALUES "
        "('DNS-1002', ?, 't', 'model', '2026-01-01T00:00:00+00:00', 0, "
        "'open')", (json.dumps(dict(SYNC, entity="192.0.2.72"),
                               sort_keys=True),)).lastrowid
    earned = lr._earned_wide(c, "DNS-1002", SYNC, ("entity", "192.0.2.71"))
    still = [r[0] for r in c.execute("SELECT id FROM learned_rule WHERE "
                                     "question_state = 'open'")]
    c.execute("UPDATE learned_rule SET question_state = 'yes' WHERE "
              "question_state = 'open'")
    counted = lr._earned_wide(c, "DNS-1002", SYNC, ("entity", "192.0.2.71"))
    c.executemany("UPDATE learned_rule SET question_state = 'open' WHERE "
                  "id = ?", [(i,) for i in still])
    c.execute("DELETE FROM learned_rule WHERE id = ?", (extra,))
check("a provisional rule never helps earn a wide one", not earned)
check("once the owner said yes, it counts", counted)
out = questions.answer(qid, "no idea, not mine")
check("a no ends the rule", out.get("provisional_rules", {}).get("verdict")
      == "no" and [r for r in lr.listing(include_undone=True)["rules"]
                   if r["id"] == prov["rule_id"]][0]["status"] == "undone",
      out)
check("and shows what it held", finding_state(ASKED)[-1] == (0, None)
      and out["provisional_rules"]["shown_again"] >= 1, finding_state(ASKED))
check("the device raises again", raise_sync(ASKED).get("held_provisionally")
      is None and finding_state(ASKED)[-1][0] == 0)

YES = "192.0.2.79"
qid2 = ask(YES)
prov2 = lr.learn("DNS-1002", None, SYNC, "a sync service polling",
                 example=sync(YES, 1), reason_kind="named_lookup")
raise_sync(YES)
out2 = questions.answer(qid2, "yes, that is the kitchen tablet")
rule2 = [r for r in lr.listing()["rules"] if r["id"] == prov2.get("rule_id")]
check("a yes makes it permanent", rule2 and rule2[0]["status"] == "on"
      and rule2[0]["question_state"] == "yes" and rule2[0]["kept_at"], rule2)
check("what it held stays quiet", finding_state(YES)[-1][0] == 1)
check("and it holds outright from now on",
      raise_sync(YES).get("saved") is False)

LATE = "192.0.2.81"
qid3 = ask(LATE)
prov3 = lr.learn("DNS-1002", None, SYNC, "a sync service polling",
                 example=sync(LATE, 2), reason_kind="named_lookup")
with me._get_conn() as c:
    c.execute("UPDATE operator_question SET first_shown_at = "
              "'2020-01-01 00:00:00' WHERE id = ?", (qid3,))
questions.expire_stale()
with me._get_readonly_conn() as c:
    ops = {r[0] for r in c.execute("SELECT operation FROM integrity_journal")}
check("the answer's effect on a rule is journalled",
      "learned_rule_settled" in ops, ops)
check("an unanswered question that expires counts as no",
      [r for r in lr.listing(include_undone=True)["rules"]
       if r["id"] == prov3.get("rule_id")][0]["status"] == "undone")
check("an answer that is unclear counts as no",
      [lr.verdict_of(w) for w in ("No.", "nope", "don't know it",
                                  "I don't recognise it", "", "normal, my TV",
                                  "Yes, the office laptop", "nothing to worry")]
      == ["no", "no", "no", "no", "no", "yes", "yes", "yes"])

print("\nALL PASSED" if not failures else f"\nFAILED: {failures}")
sys.exit(1 if failures else 0)
