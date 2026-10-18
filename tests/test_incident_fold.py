# tests/test_incident_fold.py
# One new device is one incident, whichever sensor saw it first: the router's
# report joins the live sensor's open incident, a high one is never folded
# down into a medium one, and a device seen again after its incident was
# closed starts a new one.

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import incident                             # noqa: E402
from core import memory_engine as me                  # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def rows(ip):
    with me._get_readonly_conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM incident WHERE entity_value = ? ORDER BY id", (ip,))]


print("live sensor first, then the router")
a = incident.write_incident("LAN-1008", "ip", "192.0.2.10", "high",
                            "New device on the network: 192.0.2.10",
                            finding_ids=[1])
b = incident.write_incident("RTR-1001", "ip", "192.0.2.10", "medium",
                            "Router reports a device not seen before: 192.0.2.10",
                            finding_ids=[2])
check("one incident", len(rows("192.0.2.10")), 1)
check("the router's report joined it", b["id"], a["id"])
check("it stays high", rows("192.0.2.10")[0]["severity"], "high")
check("and keeps its title", rows("192.0.2.10")[0]["title"],
      "New device on the network: 192.0.2.10")
check("both findings are on it", rows("192.0.2.10")[0]["finding_ids_json"],
      "[1, 2]")

print("router first, then the live sensor")
incident.write_incident("RTR-1001", "ip", "192.0.2.11", "medium",
                        "Router reports a device not seen before: 192.0.2.11")
incident.write_incident("LAN-1008", "ip", "192.0.2.11", "high",
                        "New device on the network: 192.0.2.11")
sev = sorted(r["severity"] for r in rows("192.0.2.11"))
check("a high alert is not folded down into a medium incident", sev,
      ["high", "medium"])

print("other devices and closed incidents")
incident.write_incident("RTR-1001", "ip", "192.0.2.12", "medium", "other device")
check("another address gets its own", len(rows("192.0.2.12")), 1)
with me._get_conn() as c:
    c.execute("UPDATE incident SET status = 'dismissed' WHERE entity_value = ?",
              ("192.0.2.12",))
incident.write_incident("NET-1001", "ip", "192.0.2.12", "medium", "seen again")
check("after its incident was closed, a new one starts",
      len(rows("192.0.2.12")), 2)
incident.write_incident("PRC-1001", "process", "192.0.2.10", "medium", "x")
check("other detections never fold into a device incident",
      len(rows("192.0.2.10")), 2)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
