"""
tests/test_learned_rules.py, quiet rules learned from false alarms.

On a scratch database: a rule learned from one false alarm holds back the
same pattern from another address and counts it, clears the matching open
findings, leaves other devices alone, refuses rules that fit nothing, that
turn a detection off or that cover critical findings, and stops holding once
undone. The model's tools reach the same code.
"""
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


print("\n[1] Learn from one false alarm")
raise_geo("203.0.113.10", TV, "Test TV")
raise_geo("203.0.113.11", TV, "Test TV")
raise_geo("203.0.113.12", PHONE, "Test phone")
first = open_ids()[0]
out = lr.learn("GEO-1002", first, {"raw": {"subject": TV}},
               "the TV reaches its streaming CDNs", by="model")
check("the rule is made", out.get("success"), out)
check("the replay counts both TV findings",
      out.get("replay", {}).get("would_hold") == 2, out.get("replay"))
check("the open TV findings are cleared", out.get("cleared_open_findings") == 2,
      out)
check("the phone's finding stays open", len(open_ids()) == 1, open_ids())
rid = out.get("rule_id")

print("\n[2] The same pattern from a new address is held back")
r = raise_geo("198.51.100.20", TV, "Test TV", asn="AS64511")
check("not saved", r.get("saved") is False, r)
check("names the rule", r.get("learned_rule_id") == rid, r)
check("another device still raises",
      raise_geo("198.51.100.21", PHONE, "Test phone").get("saved") is True)
rules = lr.listing()["rules"]
check("the hold is counted", rules and rules[0]["held_count"] == 1, rules)
check("and shown for the last week", rules[0]["held_last_7_days"] == 1, rules)

print("\n[3] Refusals")
check("a rule must fit its example", not lr.learn(
    "GEO-1002", first, {"raw": {"subject": "00:00:5e:00:53:99"}}, "x").get(
    "success"))
check("a pattern of wildcards is refused", not lr.learn(
    "GEO-1002", first, {"title": "*"}, "x").get("success"))
check("an empty pattern is refused", not lr.learn(
    "GEO-1002", first, {}, "x").get("success"))
check("a reason is needed", not lr.learn(
    "GEO-1002", first, {"raw": {"subject": TV}}, "").get("success"))
check("the same rule twice is refused", not lr.learn(
    "GEO-1002", first, {"raw": {"subject": TV}}, "again").get("success"))
for i in range(6):
    raise_geo(f"192.0.2.{40 + i}", f"00:00:5e:00:53:{40 + i}", f"Box {i}")
wide = lr.learn("GEO-1002", open_ids()[-1], {"title": "*reached a new*"},
                "everything is fine")
check("a rule that holds every finding turns the detection off, refused",
      not wide.get("success") and "turns" in wide.get("error", ""), wide)
check("a finding from another detection is refused", not lr.learn(
    "GEO-1001", first, {"raw": {"subject": TV}}, "x").get("success"))
check("critical findings are never held",
      lr.holds("GEO-1002", "x", "t", {"subject": TV}, "critical") is None)

print("\n[4] The model's tools")
check("learn_quiet_rule is a tool", tr.tool_exists("learn_quiet_rule"))
check("and counts as a write", tr.tool_writes("learn_quiet_rule"))
listed = tr._dispatch("query_learned_rules", {})
check("query_learned_rules lists the rule",
      [x["id"] for x in listed["rules"]] == [rid], listed)

print("\n[5] Undo")
u = tr._dispatch("undo_learned_rule", {"rule_id": rid, "reason": "test"})
check("undone", u.get("success"), u)
check("the TV raises again",
      raise_geo("198.51.100.22", TV, "Test TV", asn="AS64512").get("saved"))
check("an undone rule is listed only on request",
      lr.listing()["rules"] == []
      and lr.listing(include_undone=True)["rules"][0]["undone_by"] == "model")
with me._get_readonly_conn() as c:
    ops = {r[0] for r in c.execute("SELECT operation FROM integrity_journal")}
check("making and undoing are journalled",
      {"learned_rule_made", "learned_rule_undone"} <= ops, ops)

print("\nALL PASSED" if not failures else f"\nFAILED: {failures}")
sys.exit(1 if failures else 0)
