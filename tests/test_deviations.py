"""
tests/test_deviations.py, Python's own check of a session against the past.

A program started by a new parent, a port taken by a new program and a
device far above its usual traffic are written as deviations, with enough
history only. A device busy at most hours or on many ports has no routine to
break. A device's past follows it to a new address, two named devices that
share a hardware address stay apart, the story reads as a sentence, the
owner's "This is fine" is recorded as the owner's, and the rollup's usual
comes from every session. Runs on a scratch database with made-up data.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import baseline_text as bt                  # noqa: E402
from core import deviations as dv                     # noqa: E402
from core import memory_engine as me                  # noqa: E402
from core import migrations                           # noqa: E402
from core import rollup_engine as ru                  # noqa: E402

migrations.run_migrations(me.DB_PATH)
fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def obs(sid, etype, value, key, val):
    with me._get_conn() as conn:
        conn.execute(
            "INSERT INTO behavioral_session (session_id, observed_at, "
            "entity_type, entity_value, behavior_key, behavior_value, "
            "written_by, basis) VALUES (?, '2026-03-04 10:00:00', ?, ?, ?, ?, "
            "'system', 'measured')", (sid, etype, value, key, str(val)))
        conn.commit()


def stories():
    return [r["story"] for r in dv.for_page(days=100000)]


PAST = [f"s{i}" for i in range(7)]
for i, sid in enumerate(PAST):
    obs(sid, "process", "demo-daemon", "typical_parent", "systemd")
    obs(sid, "process", "demo-daemon", "typical_paths", "/usr/bin/demo-daemon")
    obs(sid, "port", "8080", "typical_process", "demo-daemon")
    obs(sid, "ip", "192.0.2.10", "volume_per_hour", 2_000_000 + i * 100_000)
    obs(sid, "ip", "192.0.2.10", "typical_dest_ports", "443,80")
    obs(sid, "ip", "192.0.2.11", "active_hours", ",".join(str(h) for h in range(20)))
    obs(sid, "ip", "192.0.2.12", "active_hours", "18,19")

print("a quiet session")
NOW = "now1"
obs(NOW, "process", "demo-daemon", "typical_parent", "systemd")
obs(NOW, "ip", "192.0.2.10", "volume_per_hour", 2_300_000)
check("nothing unlike the past, nothing written", dv.check(NOW)["written"], 0)

print("a session unlike the past")
NOW = "now2"
obs(NOW, "process", "demo-daemon", "typical_parent", "bash")
obs(NOW, "port", "8080", "typical_process", "nc")
obs(NOW, "ip", "192.0.2.10", "volume_per_hour", 40_000_000)
obs(NOW, "ip", "192.0.2.10", "typical_dest_ports", "443,80,6667,51000")
obs(NOW, "ip", "192.0.2.11", "active_hours", "22")
obs(NOW, "ip", "192.0.2.12", "active_hours", "3")
obs(NOW, "process", "brand-new", "typical_parent", "bash")
r = dv.check(NOW)
got = stories()
check("five written", r["written"], 5)
check("a new parent is told as a story",
      "demo-daemon was started by bash. Before, it was started by systemd "
      "(in 8 earlier sessions)." in got, True)
check("a port taken by another program",
      "Port 8080 was opened by nc. Before, it was opened by demo-daemon "
      "(in 7 earlier sessions)." in got, True)
check("traffic far above its usual",
      any(s.startswith("192.0.2.10 moved 40.0 MB an hour. Usually about 2.3 MB")
          for s in got), True)
check("a new service port, but not a short-lived client port",
      [s for s in got if "used port" in s and "6667" in s] != []
      and not [s for s in got if "51000" in s], True)
check("a new hour for a device with a routine",
      any(s.startswith("192.0.2.12 was active at 3:00") for s in got), True)
check("but not for one busy at most hours",
      any("192.0.2.11" in s for s in got), False)
check("nothing without enough history", any("brand-new" in s for s in got), False)
levels = {r["story"][:20]: r["level"] for r in dv.for_page(days=100000)}
check("a well known program's change is far from usual",
      levels.get("demo-daemon was star"), "far from usual")
check("a device's new hour is only worth a look",
      levels.get("192.0.2.12 was activ"), "worth a look")
check("the same thing is not written twice in a week",
      dv.check(NOW)["written"], 0)

print("the owner's answer")
row = next(r for r in dv.for_page(days=100000) if r["behavior_key"] == "typical_parent")
check("This is fine is recorded", dv.mark_fine(row["id"])["success"], True)
with me._get_conn() as conn:
    saved = conn.execute("SELECT resolved_as, resolved_by, user_responded "
                         "FROM behavioral_deviation WHERE id = ?",
                         (row["id"],)).fetchone()
check("as the owner's", tuple(saved), ("normal", "user", 1))
check("and it leaves the list",
      any(r["id"] == row["id"] for r in dv.for_page(days=100000)), False)
check("an unknown id is refused", dv.mark_fine(999999)["success"], False)

print("a device keeps its past at a new address")
mac = "00:00:5e:00:53:31"
me.save_known_device("192.0.2.40", mac=mac, hostname="speaker")
for sid in PAST:
    obs(sid, "ip", "192.0.2.40", "active_hours", "18,19")
me.save_known_device("192.0.2.41", mac=mac, hostname="speaker")
with me._get_conn() as conn:
    conn.execute("UPDATE known_devices SET last_seen = '2026-01-01 00:00:00' "
                 "WHERE ip = '192.0.2.40'")
    conn.execute("UPDATE known_devices SET last_seen = '2026-03-01 00:00:00' "
                 "WHERE ip = '192.0.2.41'")
    conn.commit()
m = bt.device_map()
check("both addresses are one device", m["192.0.2.40"]["key"], m["192.0.2.41"]["key"])
check("the newer one is current", (m["192.0.2.41"]["old"], m["192.0.2.40"]["old"]),
      (False, True))
obs("now3", "ip", "192.0.2.41", "active_hours", "4")
dv.check("now3")
check("so the new address is judged on the old one's history",
      any(s.startswith("speaker (192.0.2.41) was active at 4:00")
          for s in stories()), True)

print("two named devices that share a hardware address")
shared = "00:00:5e:00:53:32"
me.save_known_device("192.0.2.50", mac=shared, hostname="pc")
me.save_known_device("192.0.2.51", mac=shared, hostname="vm")
with me._get_conn() as conn:
    conn.execute("UPDATE known_devices SET known_as = 'Desk PC' WHERE ip = '192.0.2.50'")
    conn.execute("UPDATE known_devices SET known_as = 'Test VM' WHERE ip = '192.0.2.51'")
    conn.commit()
m = bt.device_map()
check("stay apart", m["192.0.2.50"]["key"] != m["192.0.2.51"]["key"], True)

print("the rollup's usual is every session's")
check("history numbers come from all sessions",
      len(ru._history_numbers("ip", "192.0.2.10", "volume_per_hour")), 9)

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
