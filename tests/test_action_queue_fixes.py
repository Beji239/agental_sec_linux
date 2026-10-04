"""
tests/test_action_queue_fixes.py: three fixes to the action queue.

  1. Two claims in the same second ran one request twice and parked the other.
  2. A queued kill carried no process name, so a pid reused between filing
     and approval would be killed. The name is now read at filing, shown on
     the card, and pinned for the kill.
  3. Two decisions racing both reported success.
"""
import json
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

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
from core import actions, tool_registry as tr  # noqa: E402

calls = []
tr.execute_tool = lambda verb, params: (calls.append(params.get("port")),
                                        {"error": None, "result": {"success": True}})[1]
real_now = actions._now
actions._now = lambda: datetime(2026, 9, 27, 12, 0, 0, tzinfo=timezone.utc)


print("\n[1] two approvals claimed in one second each run once")
with me._get_conn() as conn:
    for port, decided in ((1111, "2026-09-27 10:01:00"), (2222, "2026-09-27 10:00:00")):
        conn.execute(
            "INSERT INTO action_request (session_id, created_at, verb, target, "
            "params_json, reason, proposed_by, state, decided_at, decided_by) "
            "VALUES ('s','2026-09-27 09:00:00','block_port',?,?,'r','model',"
            "'approved',?,'user')",
            (f"{port}/inbound",
             json.dumps({"port": port, "direction": "inbound", "reason": "r"}),
             decided))
out = actions.execute_pending(limit=5)
check("each ran exactly once, oldest decision first", calls, [2222, 1111])
check("both recorded as executed", sorted(o["state"] for o in out), ["executed", "executed"])
actions._now = real_now


print("\n[2] a queued kill names the process and pins it")
p = subprocess.Popen(["sleep", "30"])
try:
    r = actions.write_request("kill_process", {"pid": p.pid, "expected_name": "sshd"}, "test")
    check("the name is read from the process, not the caller",
          r["params"].get("expected_name"), "sleep")
    card = actions.query_requests(request_id=r["request_id"])[0]["card"]
    check("the card names it", card["action"].startswith(f"Kill process sleep (PID {p.pid})"), True)
finally:
    p.kill()
try:
    actions.write_request("kill_process", {"pid": 999999}, "gone")
    check("a pid that is not running is refused at filing", False, True)
except actions.BadActionRequest:
    check("a pid that is not running is refused at filing", True, True)


print("\n[3] a second decision on the same request changes nothing")
first = actions.decide(r["request_id"], True)
second = actions.decide(r["request_id"], False)
check("the first decision stands", first["success"], True)
check("the second is refused", second["success"], False)

print()
if fails:
    print(f"{len(fails)} FAILED: {fails}")
    sys.exit(1)
print("all passed")
