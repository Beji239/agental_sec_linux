"""
tests/test_dns_spread.py, one destination reaching several devices.

On a scratch database: two devices polling a new, rare name on a timer raise
DNS-1007 for each, high, never held or sorted; a name many devices use, a name
the house has known for weeks, and a name only one device polls stay quiet;
too little history is said, not guessed. A destination a learned rule holds
back raises DNS-1008 once when a device that never asked for it starts to.
"""
import json
import pathlib
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
db = _isolate_db.isolate()

from core import alert_review as ar  # noqa: E402
from core import learned_rules as lr  # noqa: E402
from core import memory_engine as me  # noqa: E402
from core import migrations  # noqa: E402
from tools import dns_inspector as di  # noqa: E402

migrations.run_migrations(db)
from tools import dns_monitor  # noqa: E402
dns_monitor.register_resolver_sensor({})

failures = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        failures.append(label)
        print(f"        {detail}")


NOW = datetime.now(timezone.utc)
_row = [0]


def ask(client, domain, at):
    _row[0] += 1
    with me._get_conn() as c:
        c.execute("INSERT INTO dns_queries (queried_at, client_ip, domain, "
                  "source, source_row_id) VALUES (?, ?, ?, 'router', ?)",
                  (at.strftime("%Y-%m-%dT%H:%M:%S+00:00"), client, domain,
                   f"t{_row[0]}"))


def poll(client, domain, every=300, times=12, offset=0):
    for i in range(times):
        ask(client, domain, NOW - timedelta(seconds=offset + every * i))


def found(did, ip=None):
    with me._get_readonly_conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM findings WHERE detection_id = ? AND "
            "(? IS NULL OR entity_value = ?) ORDER BY id", (did, ip, ip))]


def run():
    with me._get_conn() as c:
        pairs = di._beacon_pairs(c)
        return di._check_spread(c, "t", pairs), di._check_held_spread(c, "t")


A, B, C = "192.0.2.10", "192.0.2.11", "192.0.2.12"

print("\n[1] Too little history is said, not guessed")
poll(A, "c2.example.org")
poll(B, "c2.example.org", offset=40)
spread, _ = run()
check("nothing is raised", spread["raised"] == 0 and not found("DNS-1007"),
      spread)
check("and the reason is given", "cannot be judged yet" in
      (spread.get("unjudged") or ""), spread)

print("\n[2] Two devices polling a new, rare name")
ask("192.0.2.50", "weather.example.net", NOW - timedelta(days=30))
with me._get_conn() as c:
    c.execute("INSERT INTO known_devices (ip, known_as, identified_by) "
              "VALUES (?, 'Kitchen tablet', 'user')", (B,))
spread, _ = run()
a, b = found("DNS-1007", A), found("DNS-1007", B)
check("each device gets a high finding", spread["raised"] == 2 and len(a) == 1
      and len(b) == 1 and a[0]["severity"] == "high", spread)
check("each names the other, by name when it has one",
      "Kitchen tablet (192.0.2.11)" in a[0]["description"]
      and A in b[0]["description"], a[0]["description"])
check("the raw fields carry the destination and the devices",
      json.loads(a[0]["raw_data"])["registered_domain"] == "example.org"
      and json.loads(a[0]["raw_data"])["devices"] == [A, B])
check("a second pass adds nothing", run()[0]["raised"] == 0)

print("\n[3] Never held, never sorted")
check("the model's review never takes it", not ar.reviewable("DNS-1007",
                                                             "high"))
held = lr.learn("DNS-1007", a[0]["id"], {"raw": {"registered_domain":
                                                 "example.org"}},
                "a sync service", reason_kind="named_lookup")
check("no rule can be learned from it without the owner",
      not held.get("success"), held)

print("\n[4] What stays quiet")
for n in range(6):
    ask(f"192.0.2.{60 + n}", "cdn.example.com", NOW - timedelta(hours=2))
poll(A, "cdn.example.com")
poll(C, "cdn.example.com", offset=20)
ask(A, "old.example.net", NOW - timedelta(days=20))
poll(A, "old.example.net")
poll(C, "old.example.net", offset=30)
poll(C, "solo.example.info")
run()
check("the checks below can see a title",
      [f for f in found("DNS-1007") if "call example.org " in f["title"]])
check("a name many devices use", not [f for f in found("DNS-1007")
                                      if "call example.com " in f["title"]])
check("a name the house has known for weeks",
      not [f for f in found("DNS-1007") if "call example.net " in f["title"]])
check("a name only one device polls",
      not [f for f in found("DNS-1007") if "call example.info " in f["title"]])

print("\n[5] A held destination reached by more devices")
OWN, NEWER, EARLIER = "192.0.2.20", "192.0.2.21", "192.0.2.22"
ask(EARLIER, "meet.example.biz", NOW - timedelta(hours=5))
ask(OWN, "meet.example.biz", NOW - timedelta(hours=4))
with me._get_conn() as c:
    lr.ensure_tables(c)
    rid = c.execute(
        "INSERT INTO learned_rule (detection_id, match_json, reason, "
        "created_by, created_at, owner_words) VALUES ('DNS-1003', ?, "
        "'my laptop on calls', 'model', ?, 'that is my laptop')",
        (json.dumps({"entity": OWN, "raw": {"registered_domain":
                                            "example.biz"}}),
         (NOW - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%S+00:00"))
    ).lastrowid
lr._forget()
_, quiet = run()
check("nothing while only the rule's own device asks", quiet == 0)
ask(NEWER, "video.meet.example.biz", NOW - timedelta(hours=1))
_, raised = run()
f = found("DNS-1008")
check("a device new to it raises it", raised == 1 and len(f) == 1
      and f[0]["entity_value"] == NEWER, f)
check("it names the new device, not the one from before the rule",
      NEWER in f[0]["description"] and EARLIER not in f[0]["description"],
      f[0]["description"] if f else None)
ask("192.0.2.23", "meet.example.biz", NOW - timedelta(minutes=5))
check("once per rule", run()[1] == 0 and len(found("DNS-1008")) == 1)
check("never sorted by the model", not ar.reviewable("DNS-1008", "medium"))

print("\nALL PASSED" if not failures else f"\nFAILED: {failures}")
sys.exit(1 if failures else 0)
