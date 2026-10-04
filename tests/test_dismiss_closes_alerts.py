"""
tests/test_dismiss_closes_alerts.py, does the dismiss button do the thing the
person pressing it is asking for.

THE OWNER'S REPORT, 2026-09-17: the dismiss button in the alert adds that finding to
the review but immediately after the same finding appears in Alerts. And:
pressing Dismiss All once is asking for pressing it again and after the second
press it only shows the Dismiss All button again.

WHAT WAS ACTUALLY WRONG, and it was two separate faults that looked like one:

  1. dismiss_entity wrote one row into dismissed_findings and nothing else.
     The sensors read that row and stop raising NEW findings, which is the
     half nobody can see. Every finding already in the table kept
     dismissed = 0, and query_findings filters on exactly that column, so
     Alerts went on listing them. The page deleted the row from the screen and
     the next poll brought it back.
  2. Dismiss All read data-type and data-value off each dismiss button, and
     nothing ever put those attributes there. Every call posted two empty
     strings, the route refused them all with a 400, and the page reported
     nothing because it never looked at the response.

THE FAILURE CASES COME FIRST. Section [1] is the exact thing the owner saw.

What is tested, in order:

  1. After a dismissal the finding is GONE from the alert list. This is the
     check that was missing.
  2. The dismissal says how many it closed, so a page can report what
     happened instead of asserting that something did.
  3. Undismissing reopens exactly the rows the dismissal closed.
  4. A finding somebody closed for their own reason is NOT reopened by it.
  5. Dismissing an entity with no open findings closes zero, and zero is a
     real answer rather than a failure.
  6. Another entity's findings are untouched.
  7. The route hands the count back, and refuses a call with no entity.
  8. The page reads the attributes it writes, and counts what happened.

Run it directly: python tests/test_dismiss_closes_alerts.py
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                      # noqa: E402
_isolate_db.isolate()

from core import memory_engine as me                    # noqa: E402
from core import sensors as sn                          # noqa: E402

sn.register_local()

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_in(label, needle, haystack):
    ok = needle in (haystack or "")
    print(f"  {'PASS' if ok else 'FAIL'}  {label}"
          + ("" if ok else f": {needle!r} not in {str(haystack)[:160]!r}"))
    if not ok:
        fails.append(label)


SID = "test-dismiss"


def raise_finding(entity_value, title, detection_id="PKT-1002",
                  severity="medium", entity_type="ip"):
    return me.save_finding(
        session_id=SID, source="packet_sniffer", severity=severity,
        entity_type=entity_type, entity_value=entity_value, title=title,
        description="raised by a test", detection_id=detection_id)


def open_values():
    return [f["entity_value"] for f in me.query_findings(limit=500)]


print("\n[1] After a dismissal the finding is GONE from the alert list.")

raise_finding("192.0.2.12", "beacon to 3.1.2.3")
raise_finding("192.0.2.12", "second beacon")
raise_finding("192.0.2.15", "unrelated")
check("three findings are listed", len(open_values()), 3)

me.dismiss_entity("ip", "192.0.2.12", reason="my own box", dismissed_by="user")

listed = open_values()
check("the dismissed entity is no longer listed",
      "192.0.2.12" in listed, False)
check("BOTH of its findings went, not just the one on screen",
      listed.count("192.0.2.12"), 0)
check("and it is on the dismissed list", me.is_dismissed("ip", "192.0.2.12"),
      True)
check("the rows still exist, they are closed rather than deleted",
      len(me.query_findings(dismissed=True, entity_value="192.0.2.12",
                            limit=50)), 2)


print("\n[2] It says how many it closed.")

raise_finding("192.0.2.17", "one")
raise_finding("192.0.2.17", "two")
raise_finding("192.0.2.17", "three")
out = me.dismiss_entity("ip", "192.0.2.17", reason="printer",
                        dismissed_by="user")
check("the count comes back", out["findings_closed"], 3)
check("and it says which entity", out["entity_value"], "192.0.2.17")


print("\n[3] Undismissing reopens exactly what the dismissal closed.")

undo = me.undismiss_entity("ip", "192.0.2.12")
check("it says how many came back", undo["findings_reopened"], 2)
check("and they are listed again", open_values().count("192.0.2.12"), 2)
check("the entity is no longer dismissed",
      me.is_dismissed("ip", "192.0.2.12"), False)


print("\n[4] A finding closed for its own reason is NOT reopened.")
#
# "Stop watching this address" and "I have dealt with this alert" are two
# different acts, and undoing the first must not undo the second. The stamp on
# dismissed_reason is the only thing in the row that tells them apart.

fid = raise_finding("192.0.2.19", "handled by hand")["finding_id"] \
    if "finding_id" in raise_finding("192.0.2.19", "probe") else None
with me._get_conn() as conn:
    conn.execute(
        "UPDATE findings SET dismissed = 1, dismissed_reason = ? "
        "WHERE entity_value = '192.0.2.19'",
        ("I looked at this myself and it is fine",))

me.dismiss_entity("ip", "192.0.2.19", reason="and now stop watching it",
                  dismissed_by="user")
undo2 = me.undismiss_entity("ip", "192.0.2.19")
check("nothing was reopened", undo2["findings_reopened"], 0)
check("the hand-closed rows stayed closed",
      open_values().count("192.0.2.19"), 0)
with me._get_readonly_conn() as conn:
    reasons = {r[0] for r in conn.execute(
        "SELECT dismissed_reason FROM findings "
        "WHERE entity_value='192.0.2.19'").fetchall()}
check("and their own reason was not overwritten",
      reasons, {"I looked at this myself and it is fine"})


print("\n[5] Closing nothing is a real answer, not a failure.")

out = me.dismiss_entity("ip", "192.0.2.28", reason="pre-emptive",
                        dismissed_by="user")
check("zero closed", out["findings_closed"], 0)
check("the dismissal still happened",
      me.is_dismissed("ip", "192.0.2.28"), True)


print("\n[6] Another entity's findings are untouched.")

check("192.0.2.15 is still listed", open_values().count("192.0.2.15"), 1)
# A process and an address can share a value in principle; the entity TYPE is
# part of the key and must be honoured.
raise_finding("192.0.2.15", "same value, different type",
              detection_id="PRC-1001", entity_type="process")
me.dismiss_entity("process", "192.0.2.15", reason="type specific",
                  dismissed_by="user")
still = me.query_findings(entity_type="ip", entity_value="192.0.2.15", limit=10)
check("dismissing the process left the ip finding alone", len(still), 1)


print("\n[7] The route hands the count back, and refuses an empty call.")

try:
    from api.server import create_app
    app = create_app({"dashboard": {}}, {}, SID, api_key="k")
    cl = app.test_client()
    H = {"X-API-Key": "k"}

    raise_finding("192.0.2.21", "via the route")
    r = cl.post("/api/findings/dismiss", headers=H,
                json={"entity_type": "ip", "entity_value": "192.0.2.21",
                      "reason": "User dismissed"})
    check("the route answers 200", r.status_code, 200)
    check("and carries the count", r.get_json().get("findings_closed"), 1)

    r = cl.post("/api/findings/dismiss", headers=H,
                json={"entity_type": "", "entity_value": ""})
    check("an empty call is refused", r.status_code, 400)
    # THE EXACT SHAPE OF THE OLD BUG: Dismiss All sent empty strings for every
    # row. It has to be a refusal, and the page has to notice it.
    check("and nothing was dismissed by it",
          me.is_dismissed("ip", ""), False)
except ImportError as e:
    print(f"  SKIP  flask not available here ({e})")


print("\n[8] The page reads the attributes it writes.")
#
# Read as text, the same approach as test_ui_wiring, because the bug was
# exactly a mismatch between two places in one file: one wrote the entity into
# an onclick handler and the other read it from attributes that did not exist.

UI = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")

check("loadFindings writes data-type",
      "data-type=" in UI and "data-value=" in UI, True)
check("dismissAll reads the same attributes",
      "getAttribute('data-type')" in UI, True)
# The two have to be in the same feature, not just both somewhere in a
# 6000 line file.
dismiss_all = UI.split("async function dismissAll()")[1].split(
    "\nasync function")[0] if "async function dismissAll()" in UI else ""
check("dismissAll skips a row with no entity rather than posting blanks",
      "if (!t || !v) return;" in dismiss_all, True)
check("it counts what happened instead of counting rows",
      "let ok = 0, failed = 0;" in dismiss_all, True)
check("and it says so when nothing was dismissed",
      "Nothing was dismissed" in dismiss_all, True)

find_fn = UI.split("async function dismissFinding(")[1].split(
    "\n// ")[0] if "async function dismissFinding(" in UI else ""
check("dismissFinding checks the response before removing the row",
      "if (!r.ok)" in find_fn, True)
check("and reports a failure on the button",
      "'failed'" in find_fn, True)

# 9. At most DISMISSAL_CAP dismissals stand; the oldest expire first.
print("\n[9] the dismissal list is capped")
raise_finding("198.51.100.1", "oldest")
me.dismiss_entity("ip", "198.51.100.1", reason="oldest")
with me._get_conn() as c:
    c.execute("UPDATE dismissed_findings SET dismissed_at='2000-01-01' "
              "WHERE entity_value='198.51.100.1'")
    have = c.execute("SELECT COUNT(*) FROM dismissed_findings").fetchone()[0]
last = None
for i in range(me.DISMISSAL_CAP - have + 1):
    last = me.dismiss_entity("port", str(20000 + i), dismissed_by="user")
check("the list stops at the cap", len(me.query_dismissed()), me.DISMISSAL_CAP)
check("the oldest one expired", me.is_dismissed("ip", "198.51.100.1"), False)
check("and the call says which", "ip:198.51.100.1" in last["expired"], True)
check("the newest one stands", me.is_dismissed("port", str(20000 + i)), True)
check("the finding it closed stays closed",
      "198.51.100.1" in open_values(), False)

print("\n" + "=" * 62)
if fails:
    print(f"{len(fails)} FAILED: " + ", ".join(fails))
    sys.exit(1)
print("All dismiss checks passed.")
