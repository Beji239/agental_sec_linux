"""
tests/test_agent_cost.py, the unattended agent does not pay for the same
tool result over and over, and a spent budget does not wake it every minute.

LOOP-15: every model call resends the whole conversation, so a result read
in round one was paid for on every later round. Measured on a live install:
624,169 prompt tokens for one investigation of 8 calls. Results are capped,
and results more than two rounds old are cut to an excerpt.

LOOP-14: once the daily budget was spent, each poll picked the next untried
urgent incident and wrote a refused run, 110 of them in one day.

Run it directly: python tests/test_agent_cost.py
"""
import json
import pathlib
import sys
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                      # noqa: E402
_isolate_db.isolate()

from core import agent_loop as al                       # noqa: E402
from core import duty                                   # noqa: E402
from core import sanitize                               # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


print("\n[1] an unattended run caps results and shortens old ones")
seen_per_call = []
first_text = []
ROUNDS = 5


async def fake_stream(messages, allowlist, round_usage):
    tool_sizes = [len(m["content"] or "") for m in messages
                  if m["role"] == "tool"]
    seen_per_call.append(tool_sizes)
    tools = [m for m in messages if m["role"] == "tool"]
    first_text[:] = [tools[0]["content"]] if tools else []
    round_usage.update(calls=1, prompt_tokens=1, completion_tokens=1,
                       estimated=False)
    n = len(seen_per_call)
    if n <= ROUNDS:
        yield {"type": "tool_calls",
               "calls": [{"id": f"c{n}", "name": "query_big",
                          "params": {}}]}
    else:
        yield {"type": "text", "token": "done"}


def fake_execute(name, params):
    return {"result": "x" * 100_000,
            "untrusted": len(seen_per_call) == 1}


al._api_key, al._model = "test-key", "test-model"
al._stream_model = fake_stream
al.execute_tool = fake_execute
al.tool_exists = lambda name: True
al.requires_permission = lambda name, params: False

out = al.run_unattended("investigate", "s", allowlist=["query_big"])
check("the run finished", out["error"], None)
first_seen = seen_per_call[1][0]
check("a new result is capped near the unattended limit",
      al.UNATTENDED_RESULT_CHARS < first_seen < al.UNATTENDED_RESULT_CHARS + 2000,
      True)
last = seen_per_call[-1]
check("the latest two rounds are sent in full",
      [s > al.UNATTENDED_RESULT_CHARS for s in last[-2:]], [True, True])
check("older rounds are cut to an excerpt",
      all(s < al.UNATTENDED_OLD_RESULT_CHARS + 400 for s in last[:-2]), True)
check("the untrusted result became a note, with no fence left open",
      (first_text[0].startswith("[EARLIER RESULT"),
       sanitize.FENCE_OPEN in first_text[0]), (True, False))
total_now = sum(sum(x) for x in seen_per_call)
total_before = sum(len(x) * 100_000 for x in seen_per_call)
check("what the run resends is under a third of before",
      total_now * 3 < total_before, True)

print("\n[2] a spent budget holds urgent work after one refusal")
calls = []
duty._enabled = lambda: True
duty._next_regular_moment = lambda now=None: {"due_now": False}
duty.emergency_check = lambda modules, now: {"emergency": False}
duty.urgent_incident = lambda now=None: {"id": len(calls) + 100,
                                         "title": "t", "severity": "high"}
duty.run_once = lambda *a, **k: calls.append(k.get("incident_id")) or {
    "outcome": "budget"}
shut = {"may_spend": False, "reasons": ["10 of a 5 token daily ceiling is spent"]}
duty.budget_state = lambda urgent=False: shut
now = datetime(2026, 10, 5, 16, 0, tzinfo=timezone.utc)
duty._duty_state["budget_refused_at"] = None
r1 = duty._tick_once("s", now=now)
r2 = duty._tick_once("s", now=now)
r3 = duty._tick_once("s", now=now)
check("the first refusal still runs, so the limit is on record", len(calls), 1)
check("later polls wait instead of writing a row each",
      (r2.get("held_by_budget"), r3.get("held_by_budget")), (True, True))
duty._tick_once_state(r3)
check("and the loop says why it is waiting",
      "budget spent" in duty._duty_state["last_skip"]["reason"], True)
duty.budget_state = lambda urgent=False: {"may_spend": True, "reasons": []}
duty._tick_once("s", now=now)
check("when the budget reopens the next urgent incident runs", len(calls), 2)

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
