# tests/test_incident_reopen.py
# A closed incident is not a mute. A new open finding about the same thing
# brings it back, unless the owner's suppression covers it. A finding that is
# already closed reopens nothing.

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import incident                             # noqa: E402
from core import memory_engine as me                  # noqa: E402
from core import sensors                              # noqa: E402
sensors.register_local()

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def status(iid):
    with me._get_readonly_conn() as c:
        return c.execute("SELECT status FROM incident WHERE id = ?",
                         (iid,)).fetchone()[0]


def closed(name, how="dismissed"):
    out = incident.write_incident("PRC-1001", "process", name, "medium",
                                  f"Suspicious process: {name}")
    if how == "resolved":
        incident.set_status(out["id"], "triaged", by="user")
    incident.set_status(out["id"], how, by="user", note="was the test suite")
    return out["id"]


print("\n[1] Written directly")
iid = closed("example-nc")
out = incident.write_incident("PRC-1001", "process", "example-nc", "medium",
                              "Suspicious process: example-nc", reopen=True)
check("a dismissed incident comes back", (out["action"], status(iid)),
      ("reopened", "new"))
check("the old reason is kept in the note",
      "was the test suite" in (out.get("assessment") or ""), True)

iid = closed("example-ncat", "resolved")
incident.write_incident("PRC-1001", "process", "example-ncat", "medium", "t",
                        reopen=True)
check("a resolved one comes back too", status(iid), "new")

iid = closed("example-socat")
incident.write_incident("PRC-1001", "process", "example-socat", "medium", "t")
check("callers that do not ask keep the old behaviour", status(iid),
      "dismissed")

iid = closed("example-quiet")
me.suppress_detection("PRC-1001", "owner asked for quiet",
                      entity_type="process", entity_value="example-quiet")
incident.write_incident("PRC-1001", "process", "example-quiet", "medium", "t",
                        reopen=True)
check("the owner's suppression still holds it", status(iid), "dismissed")

print("\n[2] Through the watcher")
incident.watch_once("test-session")
iid = closed("example-tool")
me.save_finding(session_id="test-session", source="process_monitor",
                severity="medium", entity_type="process",
                entity_value="example-tool", title="Suspicious process",
                detection_id="PRC-1001")
counts = incident.watch_once("test-session")
check("an open finding reopens it", status(iid), "new")
check("and the tick counts it", (counts.get("counts") or counts).get("reopened"),
      1)

iid = closed("example-closed")
f = me.save_finding(session_id="test-session", source="process_monitor",
                    severity="medium", entity_type="process",
                    entity_value="example-closed", title="Suspicious process",
                    detection_id="PRC-1001")
with me._get_conn() as c:
    c.execute("UPDATE findings SET dismissed = 1, dismissed_reason = 'closed' "
              "WHERE entity_value = 'example-closed'")
incident.watch_once("test-session")
check("a finding that is already closed reopens nothing", status(iid),
      "dismissed")

print("\nALL PASS" if not fails else f"\n{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
