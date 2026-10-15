"""
tests/test_duty_close.py, the duty loop closes a benign incident only when
Python confirms the fact it names.

On a scratch database: a benign verdict with a fact that checks out closes
the incident; one without a fact, or with one Python cannot confirm, stays
triaged with the reason; a threat list incident never closes; and a rule the
loop makes during its turn is on trial.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
db = _isolate_db.isolate()

from core import duty  # noqa: E402
from core import incident  # noqa: E402
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


with me._get_conn() as c:
    c.execute("INSERT INTO dns_answer (first_seen, last_seen, times_seen, "
              "name, rrtype, value) VALUES (datetime('now'), datetime('now'), "
              "1, 'cdn.example', 'A', '198.51.100.30')")


def case(ip, did="GEO-1002", severity="low", raw=None):
    me.save_finding(session_id="t", source="place_watch", severity=severity,
                    entity_type="ip", entity_value=ip, detection_id=did,
                    title=f"t {ip}", description="t",
                    raw_data=raw or {"ip": ip, "place_type": "network"})
    with me._get_readonly_conn() as c:
        fid = c.execute("SELECT MAX(id) FROM findings").fetchone()[0]
    r = incident.write_incident(did, "ip", ip, severity, "t",
                                finding_ids=[fid])
    return r.get("incident_id") or r.get("id"), fid


def status(iid):
    with me._get_readonly_conn() as c:
        return c.execute("SELECT status, assessment FROM incident WHERE id = ?",
                         (iid,)).fetchone()


print("\n[1] Benign closes only with a confirmed fact")
a, fa = case("198.51.100.30")
duty._finish_incident(a, "benign", "looks fine", reason_kind="named_lookup")
check("confirmed, closed", status(a)[0] == "dismissed", status(a))
check("and the check is on the record", "Checked:" in (status(a)[1] or ""))
b, _ = case("198.51.100.31")
duty._finish_incident(b, "benign", "looks fine", reason_kind="named_lookup")
check("not confirmed, left for the owner", status(b)[0] == "triaged"
      and "could not confirm" in (status(b)[1] or ""), status(b))
c_, _ = case("198.51.100.32")
duty._finish_incident(c_, "benign", "looks fine")
check("no fact named, left for the owner", status(c_)[0] == "triaged")
d, _ = case("198.51.100.30", did="FED-1001", severity="high",
            raw={"ip": "198.51.100.30"})
duty._finish_incident(d, "benign", "looks fine", reason_kind="named_lookup")
check("a threat list incident never closes", status(d)[0] == "triaged",
      status(d))
e, _ = case("198.51.100.33")
duty._finish_incident(e, "real", "bad")
check("a real verdict is triaged", status(e)[0] == "triaged")

print("\n[2] A rule made in the loop's turn is on trial")
with lr.unattended_turn():
    out = tr._dispatch("learn_quiet_rule", {
        "detection_id": "GEO-1002", "finding_id": fa,
        "match": {"entity": "198.51.100.30"}, "reason": "named CDN",
        "reason_kind": "named_lookup"})
check("made", out.get("success"), out)
check("on trial", bool(out.get("trial_until")), out)
check("outside the turn it is not unattended", not lr.unattended_now())
check("the loop may call the rule tools", {
    "learn_quiet_rule", "query_learned_rules", "undo_learned_rule"}
    <= set(duty._tool_allowlist()))

print("\nALL PASSED" if not failures else f"\nFAILED: {failures}")
sys.exit(1 if failures else 0)
