"""
tests/test_xss_daily_report.py, outside text cannot become markup in the
daily security report.

Hostile text is planted where outside data really enters (a login name and
log line, finding and incident titles, a device name, a process name, an
action reason, the model's own assessment), the real collect and render run,
and no tag or attribute from it may survive. A second pass adds hostile
text to every string the report is built from.
"""
import json
import pathlib
import sqlite3
import sys
import tempfile
from datetime import date, datetime, timedelta

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)
        print(f"        {str(detail)[:400]}")


tmp = pathlib.Path(tempfile.mkdtemp(prefix="xss_report_"))
DB = tmp / "t.db"
DB.write_text("")
sqlite3.connect(DB).executescript(
    (ROOT / "Schema.SQL").read_text(encoding="utf-8"))

from core import memory_engine as me            # noqa: E402
me.DB_PATH = DB
from core import migrations                     # noqa: E402
migrations.run_migrations(DB)
from core import daily_report as dr             # noqa: E402

dr._state["started"] = 0

# Each one tries a different way out: a tag, an attribute, a closing tag.
HOSTILE = ['<img src=x onerror=alert(1)>', '"><svg onload=alert(2)>',
           "'><script>alert(3)</script>", '</td></tr><iframe src=//x>']
H = "".join(HOSTILE)
# Each payload carries its own tag, so an attribute it closed shows up as
# that tag. Escaped text may still read "onload=alert", which is harmless.
RAW = ("<img src=x", "<svg onload", "<script>alert", "<iframe src=//x")

DAY = date.today() - timedelta(days=2)
START, END = dr.day_bounds(DAY)


def at(h, m=0):
    return dr._sql(datetime(DAY.year, DAY.month, DAY.day, h, m).astimezone())


with sqlite3.connect(DB) as c:
    c.execute("INSERT INTO sensor_watch_beat (id, at, first_at) VALUES (1, 0, ?)",
              (int((START - timedelta(days=5)).timestamp()),))
    for h in range(24):
        c.execute("INSERT INTO watcher_run (session_id, ran_at, outcome) "
                  "VALUES ('s', ?, 'ok')", (at(h, 5),))
    c.execute("INSERT INTO sensor_gaps (sensor, reason, started_at, ended_at) "
              "VALUES ('packet_sniffer', ?, ?, ?)", (H, at(13, 5), at(13, 20)))
    ev = ("INSERT INTO events (session_id, occurred_at, source, event_type, "
          "username, src_ip, description) VALUES ('s', ?, 'auth.log', ?, ?, ?, ?)")
    for i in range(3):
        c.execute(ev, (at(3, 12 + i), "failed_login", H, "203.0.113.45",
                       "sshd[1]: Failed password for " + H))
    c.execute(ev, (at(10), "successful_login", H, "198.51.100.7",
                   "sshd[2]: Accepted publickey for " + H))
    fi = ("INSERT INTO findings (session_id, found_at, source, severity, "
          "entity_type, entity_value, title, detection_id, dismissed, "
          "description) VALUES ('s', ?, ?, ?, 'ip', ?, ?, ?, 0, ?)")
    c.execute(fi, (at(11), "process_monitor", "medium", "/tmp/" + H,
                   "Running from suspicious location: " + H, "LNX-1101", H))
    c.execute(fi, (at(20, 35), "lan_live", "high", "192.0.2.125",
                   "New device on the network: " + H, "LAN-1008", H))
    inc = ("INSERT INTO incident (incident_key, detection_id, entity_type, "
           "entity_value, source, severity, severity_rank, title, "
           "first_seen_at, last_seen_at, finding_count, status, status_at, "
           "assessment) VALUES (?, ?, 'ip', ?, 'x', ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    c.execute(inc, ("k1", "LNX-1002", "203.0.113.45", "high", 3, H,
                    at(3, 12), at(3, 19), 3, "triaged", at(3, 20), H))
    c.execute(inc, ("k2", "LAN-1008", "192.0.2.125", "high", 3,
                    "New device " + H, at(20, 35), at(20, 35), 1, "new",
                    at(20, 35), H))
    c.execute("INSERT INTO duty_report (session_id, created_at, kind, trigger, "
              "incident_id, verdict, saw, body) VALUES ('s', ?, 'incident', "
              "'regular', 1, 'real', ?, ?)", (at(3, 21), H, H))
    c.execute("INSERT INTO action_request (session_id, created_at, verb, "
              "target, params_json, evidence_json, reason, evidence_fingerprint, "
              "proposed_by, incident_id, state) VALUES ('s', ?, 'block_device', "
              "'192.0.2.125', '{}', '{}', ?, 'f', 'model', 2, 'pending')",
              (at(20, 40), H))
    c.execute("INSERT INTO port_owner_change (sweep_id, detected_at, kind, "
              "proto, scope, local_address, local_port, comm) VALUES "
              "(1, ?, 'appeared', 'tcp', 'listen', '0.0.0.0', 8080, ?)",
              (at(12), H))
    c.execute("INSERT INTO known_devices (ip, mac, known_as, hostname, "
              "last_seen) VALUES ('192.0.2.125', '00:00:5e:00:53:25', ?, ?, ?)",
              (H, H, at(20)))
    c.execute("INSERT INTO lan_traffic_minute (minute, ip, mac, up_bytes, "
              "down_bytes, up_packets, down_packets) VALUES (?, '192.0.2.125', "
              "'', 1200000000, 0, 1, 1)",
              (dr._iso(datetime(DAY.year, DAY.month, DAY.day, 15).astimezone()),))


def survivors(page):
    return [r for r in RAW if r in page]


print("Hostile text from the sensors and the model")
f = dr.collect(DAY, END - timedelta(hours=3))
assessment = {"text": "Fine. " + H, "recommendations": [H, "Patch " + H],
              "usage": {"total_tokens": 10}}
page = dr.render(f, assessment)
check("the report was written", "The day in brief" in page, page[:200])
check("the hostile text is in it, as text", "&lt;img src=x" in page
      or "&lt;img" in page, "")
check("no tag or attribute from outside survives", not survivors(page),
      survivors(page))
check("a model error message is text too", not survivors(
    dr.render(f, {"text": "", "error": H})))


def poison(v, depth=0):
    """Every string gains the hostile text; keys and numbers stay."""
    if depth > 12:
        return v
    if isinstance(v, str):
        return v + H
    if isinstance(v, dict):
        return {k: poison(x, depth + 1) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return type(v)(poison(x, depth + 1) for x in v)
    return v


print("\nHostile text in every value the report is built from")
try:
    page2 = dr.render(poison(f), poison(assessment))
    check("no tag or attribute survives anywhere", not survivors(page2),
          [(r, page2[max(0, page2.find(r) - 120):page2.find(r) + 40])
           for r in survivors(page2)][:3])
except Exception as e:                                      # noqa: BLE001
    check("the report renders with every value poisoned", False, repr(e))

print(f"\n{'ALL PASSED' if not fails else str(len(fails)) + ' FAILED'}")
sys.exit(1 if fails else 0)
