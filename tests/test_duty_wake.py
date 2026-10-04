"""
tests/test_duty_wake.py: when the duty loop wakes, and what it spends.

  1. A client session this host opened is not an emergency, however busy.
     The live storm of 2026-09-22 to 09-28 was downloads and the model
     provider's own replies.
  2. Unsolicited traffic at a listener, or a UDP spray at ports nobody here
     opened, still trips it and names the peer.
  3. One peer is one emergency an hour, unless its count triples.
  4. A new high incident wakes the loop on the next poll, not at the next
     regular hour, and a run for it holds it off for the retry window.
  5. Ordinary work stops short of the ceiling so the reserve is there for an
     emergency; an emergency still stops at the ceiling.
  6. End to end through _tick_once with the model stubbed: the flood is what
     the model is shown, the run row is tagged, and a second poll inside the
     cooldown spends nothing and writes nothing.
"""
import json
import pathlib
import sqlite3
import sys
import tempfile
from datetime import timedelta

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


db = pathlib.Path(tempfile.mkdtemp()) / "t.db"
from core import memory_engine as me  # noqa: E402
me.DB_PATH = db
c = sqlite3.connect(db)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.commit()
c.close()
from core import migrations  # noqa: E402
migrations.run_migrations(db)
from core import duty, sensor_health  # noqa: E402

sensor_health.warnings_for = lambda tool, modules: []
duty.build_host_survey_block = lambda *a, **k: ""

model = {"n": 0, "prompt": None}


def fake_model(prompt, session_id, allowlist=None, extra_system=""):
    model["n"] += 1
    model["prompt"] = prompt
    return {"answers": [json.dumps({"hypothesis": "h", "evidence": "e",
                                    "verdict": "needs_human", "saw": "",
                                    "report": "r"})],
            "tool_calls": [], "refused_calls": [],
            "usage": {"calls": 1, "prompt_tokens": 100,
                      "completion_tokens": 10, "total_tokens": 110,
                      "estimated": False},
            "error": None}


duty._run_unattended = fake_model

HOST = "192.0.2.207"
now = duty._now()
ts = duty._sql_ts(now)


def packets(rows):
    with me._get_conn() as conn:
        conn.executemany(
            "INSERT INTO packets (session_id, captured_at, src_ip, dst_ip, "
            "src_port, dst_port, protocol, direction, packet_size) "
            "VALUES ('t', ?, ?, ?, ?, ?, ?, ?, 60)", rows)


def clear():
    with me._get_conn() as conn:
        for t in ("packets", "duty_run", "duty_report", "incident"):
            conn.execute(f"DELETE FROM {t}")


def measure():
    return duty.emergency_check({}, now)


print("\n[1] a busy client session this host opened is not an emergency")
clear()
packets([(ts, HOST, "11.22.35.15", 50000, 443, "tcp", "outbound")] * 400
        + [(ts, "11.22.35.15", HOST, 443, 50000, "tcp", "inbound")] * 2000)
out = measure()
check("no emergency", out.get("emergency"), False)
check("the set-aside traffic is named, so the negative is a measurement",
      (out["evidence"]["busiest_solicited_peer"] or {}).get("peer"),
      "11.22.35.15")


print("\n[2] unsolicited traffic still trips it")
clear()
flood = []
for i in range(600):
    flood.append((ts, "198.51.100.9", HOST, 40000 + i, 22, "tcp", "inbound"))
    flood.append((ts, HOST, "198.51.100.9", 22, 40000 + i, "tcp", "outbound"))
packets(flood)
out = measure()
check("a flood at a listener fires, even with this host answering it",
      out.get("emergency"), True)
check("and names the peer", out.get("peer"), "198.51.100.9")
clear()
packets([(ts, "203.0.113.66", HOST, 5353, 40000 + i, "udp", "inbound")
         for i in range(400)])
out = measure()
check("a UDP spray at ephemeral ports nobody opened fires",
      out.get("emergency"), True)
check("as the UDP shape", "UDP" in (out.get("reason") or ""), True)


print("\n[3] one peer, one emergency an hour")
clear()
duty._record_run("t", "emergency", "investigated", at=now,
                 detail=duty._flood_tag("198.51.100.9", 600) + "benign")
check("the same peer at the same size is cooled down",
      duty.emergency_cooled_down("198.51.100.9", 700, now)["cooled"], True)
check("a different peer is not",
      duty.emergency_cooled_down("198.51.100.10", 700, now)["cooled"], False)
check("the same peer three times bigger comes back",
      duty.emergency_cooled_down("198.51.100.9", 1800, now)["cooled"], False)
check("and the cooldown ends after the hour",
      duty.emergency_cooled_down("198.51.100.9", 700,
                                 now + timedelta(minutes=61))["cooled"], False)


print("\n[4] a new high incident is urgent")
clear()


def incident(key, severity, rank):
    with me._get_conn() as conn:
        return conn.execute(
            "INSERT INTO incident (incident_key, detection_id, entity_type, "
            "entity_value, severity, severity_rank, title, first_seen_at, "
            "last_seen_at, status_at) VALUES (?, 'LNX-2002', 'file', "
            "'/home/u/.ssh/authorized_keys', ?, ?, 'a key was added', ?, ?, ?)",
            (key, severity, rank, ts, ts, ts)).lastrowid


incident("m", "medium", 2)
check("a medium incident waits for the schedule", duty.urgent_incident(now), None)
hid = incident("h", "high", 3)
check("a high one is picked", (duty.urgent_incident(now) or {}).get("id"), hid)
duty._record_run("t", "emergency", "budget", at=now, incident_id=hid,
                 detail="refused")
check("a run for it inside the retry window holds it off",
      duty.urgent_incident(now), None)
check("and it comes back after the window",
      (duty.urgent_incident(now + timedelta(minutes=31)) or {}).get("id"), hid)


print("\n[5] the emergency reserve")
clear()
me.set_preference("duty_daily_token_ceiling", "2000000")
with me._get_conn() as conn:
    conn.execute("INSERT INTO duty_run (session_id, ran_at, ended_at, trigger, "
                 "outcome, tokens_spent, model_calls) VALUES ('t', ?, ?, "
                 "'regular', 'reported', 1500000, 0)", (ts, ts))
check("ordinary work stops at 70% of the ceiling",
      duty.budget_state()["may_spend"], False)
check("an emergency may still spend", duty.budget_state(urgent=True)["may_spend"], True)
with me._get_conn() as conn:
    conn.execute("UPDATE duty_run SET tokens_spent = 2100000")
check("and an emergency stops at the ceiling",
      duty.budget_state(urgent=True)["may_spend"], False)


print("\n[6] end to end through the poll")
clear()
packets([(ts, "203.0.113.66", HOST, 5353, 40000 + i, "udp", "inbound")
         for i in range(400)])
result = duty._tick_once("t", modules={}, now=now)
check("the poll ran an emergency", result.get("outcome"), "investigated")
check("the model was shown the flood, not a ledger row",
      "THE MEASUREMENT THAT WOKE YOU" in (model["prompt"] or "")
      and "203.0.113.66" in model["prompt"], True)
with me._get_readonly_conn() as conn:
    rows = conn.execute("SELECT trigger, detail FROM duty_run").fetchall()
check("one run row", len(rows), 1)
check("tagged with the peer and count",
      (rows[0]["detail"] or "").startswith("[flood 203.0.113.66 400]"), True)
calls = model["n"]
again = duty._tick_once("t", modules={}, now=now + timedelta(minutes=1))
check("a poll a minute later is not a wake", again.get("outcome"), "not_due")
check("and spent nothing", model["n"], calls)
with me._get_readonly_conn() as conn:
    check("and wrote nothing",
          conn.execute("SELECT COUNT(*) FROM duty_run").fetchone()[0], 1)

clear()
hid = incident("h2", "high", 3)
result = duty._tick_once("t", modules={}, now=now)
check("an urgent incident is worked on the poll", result.get("outcome"),
      "investigated")
check("the model was shown that incident",
      "a key was added" in (model["prompt"] or ""), True)
with me._get_readonly_conn() as conn:
    row = conn.execute("SELECT detail, incident_id FROM duty_run").fetchone()
    status = conn.execute("SELECT status FROM incident WHERE id = ?",
                          (hid,)).fetchone()[0]
check("the run row is tagged urgent",
      (row["detail"] or "").startswith(f"[urgent incident {hid}]"), True)
check("and the incident left `new`", status != "new", True)


print()
if fails:
    print(f"{len(fails)} FAILED: {fails}")
    sys.exit(1)
print("all passed")
