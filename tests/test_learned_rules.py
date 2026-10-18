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

print("\nALL PASSED" if not failures else f"\nFAILED: {failures}")
sys.exit(1 if failures else 0)
