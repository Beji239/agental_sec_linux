"""
tests/test_dismissal_same_rule.py, a dismissal is honoured where findings are
saved, and it covers the same rule about the same thing and nothing more.

Several sensors never asked whether a device was dismissed, so a dismissed
DNS alert came back five minutes later. save_finding now asks for all of
them. The limit is the point of the second half: dismissing a noisy rule
about a device must not hide a different rule about it.

Run it directly: python tests/test_dismissal_same_rule.py
"""
import pathlib
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


DEVICE = "192.0.2.77"


def dga(domain):
    return me.save_finding(
        session_id="t", source="dns_inspector", severity="medium",
        entity_type="ip", entity_value=DEVICE,
        title=f"DGA-profile domain queried by {DEVICE}: {domain}",
        detection_id="DNS-1001")


print("\n[1] a dismissed rule stays quiet for that device")
check("before any dismissal it is saved", dga("a1.example")["saved"], True)
me.dismiss_entity("ip", DEVICE, "noisy")
r = dga("b2.example")
check("the same rule after the dismissal is not saved", r["saved"], False)
check("and it says a dismissal did it", "dismissed" in (r.get("reason") or ""),
      True)

print("\n[2] a different rule about the same device still speaks")
r = me.save_finding(
    session_id="t", source="dns_inspector", severity="medium",
    entity_type="ip", entity_value=DEVICE,
    title=f"Possible DNS tunnel under evil.example from {DEVICE}",
    detection_id="DNS-1003")
check("a tunnel alert is saved despite the dismissed DGA alert",
      r["saved"], True)

print("\n[3] another device is untouched")
r = me.save_finding(
    session_id="t", source="dns_inspector", severity="medium",
    entity_type="ip", entity_value="192.0.2.78",
    title="DGA-profile domain queried by 192.0.2.78: c3.example",
    detection_id="DNS-1001")
check("the same rule on a different device is saved", r["saved"], True)

print("\n[4] a process dismissal covers the same file only (PM-7)")
name = "svc-under-test"


def proc(exe):
    return me.save_finding(
        session_id="t", source="process_monitor", severity="medium",
        entity_type="process", entity_value=name,
        title=f"Suspicious process name: {name}",
        raw_data={"exe": exe}, detection_id="PRC-1001")


check("first sighting is saved", proc("/usr/sbin/svc")["saved"], True)
me.dismiss_entity("process", name, "it is ours")
check("the same file after the dismissal is quiet",
      proc("/usr/sbin/svc")["saved"], False)
check("A DIFFERENT FILE WEARING THE NAME STILL RAISES",
      proc("/tmp/svc")["saved"], True)

print("\n[5] silencing a rule from an alert closes it and stays closed")
OTHER = "192.0.2.79"
for title in ("Possible DNS tunnel under a.example from " + OTHER,
              "Possible DNS tunnel under b.example from " + OTHER):
    me.save_finding(session_id="t", source="dns_inspector", severity="medium",
                    entity_type="ip", entity_value=OTHER, title=title,
                    detection_id="DNS-1003")
me.save_finding(session_id="t", source="dns_inspector", severity="medium",
                entity_type="ip", entity_value=OTHER,
                title=f"DGA-profile domain queried by {OTHER}: d4.example",
                detection_id="DNS-1001")


def open_rows(did):
    return [f for f in me.query_findings(limit=500)
            if f["entity_value"] == OTHER and f["detection_id"] == did]


r = me.suppress_detection("DNS-1003", "streaming service", "ip", OTHER)
check("the silence reports what it closed", r.get("closed"), 2)
check("those alerts are gone from the list", len(open_rows("DNS-1003")), 0)
check("the other rule's alert is still there", len(open_rows("DNS-1001")), 1)
r = me.save_finding(session_id="t", source="dns_inspector", severity="medium",
                    entity_type="ip", entity_value=OTHER,
                    title="Possible DNS tunnel under c.example from " + OTHER,
                    detection_id="DNS-1003")
check("a new one is not raised", r["saved"], False)
r = me.unsuppress_detection("DNS-1003", "ip", OTHER)
check("letting it speak reopens what the silence closed", r.get("reopened"), 2)
check("and they are back in the list", len(open_rows("DNS-1003")), 2)

print("\n[6] the alert list offers it")
page = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
alert_list = page.split("async function loadFindings()")[1].split(
    "\n}\n")[0]
check("each alert has a silence button", "silenceFinding(" in alert_list, True)
check("and it posts to the suppression route",
      "/api/detections/suppress" in page.split(
          "async function silenceFinding(")[1].split("\n}\n")[0], True)

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
