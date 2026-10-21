"""
tests/test_questions_actions_map.py, the 2026-10-11 round on the Questions,
Actions and Threat Map tabs.

The duty loop can ask the owner and is told when to, the question badge
counts every open question, a question filed while you are in the chat is said
there, an incident leaves action_pending once its request is settled, a
second request for one incident is added rather than replacing the first,
and the map tool can look at one address. Runs on a scratch database with
made-up addresses.
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
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


tmp = pathlib.Path(tempfile.mkdtemp(prefix="qam_"))
DB = tmp / "t.db"
DB.write_text("")
sqlite3.connect(DB).executescript(
    (ROOT / "Schema.SQL").read_text(encoding="utf-8"))

from core import memory_engine as me            # noqa: E402
me.DB_PATH = DB
from core import migrations                     # noqa: E402
migrations.run_migrations(DB)
from core import actions, agent_loop, duty, questions, tool_registry  # noqa: E402

print("the duty loop may ask")
allow = duty._tool_allowlist()
check("ask_operator is allowed", "ask_operator" in allow, True)
check("and so is reading the answers", "query_operator_answers" in allow, True)
check("no allowed tool needs approval",
      [n for n in allow if agent_loop.requires_permission(n, {})], [])
blocks = dict(incident_block="i", coverage_block="c", case_block="k",
              host_block="h", findings_block="f", emergency_block="e",
              voice="v", ask=duty.ASK_STEP)
for name in ("INCIDENT_PROMPT", "REGULAR_PROMPT", "EMERGENCY_PROMPT"):
    text = getattr(duty, name).format(**blocks)
    check(f"{name} tells it to ask", "ask_operator" in text, True)
desc = next(t["description"] for t in tool_registry.TOOL_MANIFEST
            if t["name"] == "ask_operator")
check("the tool no longer says to use it sparingly",
      "SPARINGLY" in desc, False)

print("\nthe question badge")
r = questions.file_question("s", "identify_device", "ip", "192.0.2.40",
                            "Is 192.0.2.40 yours?")
check("filed", r.get("success"), True)
due = questions.popup_due()
check("one open, one not shown", (due["open"], due["waiting"]), (1, 1))
questions.claim_popup()
due = questions.popup_due()
check("after the popup it is still open", due.get("open"), 1)
check("and nothing is left to show", due.get("waiting"), 0)
questions.file_question("s", "identify_destination", "ip", "198.51.100.9",
                        "Do you recognise 198.51.100.9?")
chat = questions.popup_due(in_chat=True)
check("in the chat the new one is handed over to say there",
      ([q["entity_value"] for q in chat.get("questions") or []],
       chat.get("ask_in_chat")), (["198.51.100.9"], True))

print("\nan incident leaves action_pending")


def incident(key):
    with me._get_conn() as c:
        cur = c.execute(
            "INSERT INTO incident (incident_key, detection_id, entity_type, "
            "entity_value, source, severity, severity_rank, title, "
            "first_seen_at, last_seen_at, status, status_at) VALUES "
            "(?, 'LAN-1008', 'ip', ?, 'x', 'high', 3, 't', "
            "'2026-10-11 10:00:00', '2026-10-11 10:00:00', 'triaged', "
            "'2026-10-11 10:00:00')", (key, key))
        return cur.lastrowid


def status_of(iid):
    with me._get_conn() as c:
        row = c.execute("SELECT status, status_by, actions_json FROM incident "
                        "WHERE id = ?", (iid,)).fetchone()
    return row["status"], row["status_by"], json.loads(row["actions_json"] or "[]")


i1 = incident("192.0.2.61")
a = actions.write_request("block_device", {"ip": "192.0.2.61"}, "test one",
                          incident_id=i1)
check("filing moves it to action_pending", status_of(i1)[0], "action_pending")
actions.decide(a["request_id"], approved=False)
st = status_of(i1)
check("a denial moves it back to triaged", st[:2], ("triaged", "user"))
check("and the list says denied", [x["state"] for x in st[2]], ["denied"])

i2 = incident("192.0.2.62")
b1 = actions.write_request("block_device", {"ip": "192.0.2.62"}, "first",
                           incident_id=i2)
b2 = actions.write_request("kill_process", {"pid": __import__("os").getpid()},
                           "second", incident_id=i2)
check("a second request is added, not swapped in",
      [x["request_id"] for x in status_of(i2)[2]],
      [b1["request_id"], b2["request_id"]])
actions.decide(b1["request_id"], approved=False)
check("still waiting while the other card is open",
      status_of(i2)[0], "action_pending")

real_exec = tool_registry.execute_tool
tool_registry.execute_tool = lambda verb, params: {
    "result": {"success": True}, "error": None}
actions.decide(b2["request_id"], approved=True)
actions.execute_pending()
tool_registry.execute_tool = real_exec
check("an action that ran resolves it", status_of(i2)[0], "resolved")

i3 = incident("192.0.2.63")
c1 = actions.write_request("block_device", {"ip": "192.0.2.63"}, "old",
                           incident_id=i3)
with me._get_conn() as c:
    c.execute("UPDATE action_request SET created_at = ? WHERE id = ?",
              (actions._sql_ts(actions._now() - timedelta(days=40)),
               c1["request_id"]))
actions.expire_stale()
check("an unanswered card that expired hands it back",
      status_of(i3)[:2], ("triaged", "silence_timer"))

print("\nthe map tool, one address")
one = tool_registry._query_threat_map({"ip": "203.0.113.7"})
check("one address gives the panel view",
      (one.get("ip"), "devices" in one, "findings" in one),
      ("203.0.113.7", True, True))
check("a non-address is refused",
      "error" in tool_registry._query_threat_map({"ip": "nope"}), True)

print("\nthe pages")
ui = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check("no spaced comma separators left", " , " in ui, False)
check("the chat path says the question and starts its clock",
      "/api/questions/shown-in-chat" in ui and "d.ask_in_chat" in ui, True)
check("the badge counts open questions", "setQuestionBadge(d.open)" in ui, True)
check("a map error is not reported as a missing database",
      "An error reply is not a missing location database" in ui, True)
check("a filter cannot hide waiting cards",
      "the filter above hides them" in ui, True)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
