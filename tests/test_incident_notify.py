# tests/test_incident_notify.py
# A desktop notice goes out once when an incident first reaches the urgent
# floor, never again for the same incident, and stops at the daily cap.

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import actions                              # noqa: E402
from core import incident                             # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


sent = []
actions.notify = lambda title, body, urgency="normal": (
    sent.append((title, body, urgency)) or {"sent": True})
incident._urgent_floor_rank = lambda: incident._severity_rank("high")
incident._config_cache = {"incident_watcher": {"notify": True,
                                               "notify_daily_cap": 3}}


def write(did, value, severity):
    out = incident.write_incident(did, "process", value, severity, f"{did} on {value}")
    return incident.notify_urgent(out)


print("crossings")
check("medium stays quiet", write("PRC-1001", "a", "medium")["sent"], False)
check("raised to high rings", write("PRC-1001", "a", "high")["sent"], True)
check("title says raised", "raised to HIGH" in sent[-1][0], True)
check("urgency is critical", sent[-1][2], "critical")
check("again at high is quiet", write("PRC-1001", "a", "high")["sent"], False)
check("a lower finding is quiet", write("PRC-1001", "a", "medium")["sent"], False)
check("new at high rings", write("LNX-1011", "b", "high")["sent"], True)
check("body names the subject", "process: b" in sent[-1][1], True)

print("switches")
incident._config_cache["incident_watcher"]["notify"] = False
check("off means quiet", write("LNX-1011", "c", "high")["sent"], False)
incident._config_cache["incident_watcher"]["notify"] = True
out = incident.write_incident("LNX-1011", "process", "d", "high", "t")
check("suppressed is quiet", incident.notify_urgent(dict(out, suppressed=1))["sent"], False)

print("cap")
before = len(sent)
check("third notice of the day rings", write("LNX-1011", "e", "high")["sent"], True)
r = write("LNX-1011", "f", "high")
check("past the cap, one summary notice", (r["sent"], "more urgent" in sent[-1][0]), (True, True))
check("then silence", write("LNX-1011", "g", "high")["sent"], False)
check("notices sent in this block", len(sent) - before, 2)

print("through the watcher")
from core import memory_engine as me  # noqa: E402
from core import sensors as sn  # noqa: E402
me.upsert_sensor(sensor_id=sn.LOCAL_SENSOR_ID, label=None, position="host",
                 summary="test", can_see="test", cannot_see="test")
incident._notify_day.update(date=None)
incident.watch_once("notify-test")
before = len(sent)
me.save_finding("notify-test", "test", "high", "process", "w1", "watched",
                detection_id="LNX-1011")
r = incident.watch_once("notify-test")
check("watcher counts the notice", (r["new"], r["notified"]), (1, 1))
check("watcher rang once", len(sent) - before, 1)
me.save_finding("notify-test", "test", "high", "process", "w1", "watched",
                detection_id="LNX-1011")
r = incident.watch_once("notify-test")
check("a repeat finding coalesces quietly", (r["coalesced"], r["notified"]), (1, 0))

print()
if fails:
    print(f"{len(fails)} FAILED: {fails}")
    sys.exit(1)
print("all passed")
