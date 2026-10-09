"""
tests/test_agent_report_text.py, how agent runs are written up.

An investigation that uses every round of lookups is asked to answer from what
it read, so it ends in a report rather than in nothing; one that still gives
no answer says so without a made-up token count; and a run's line on the
Agents page is a sentence, not a bare verdict code.

Run it directly: python tests/test_agent_report_text.py
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                      # noqa: E402
_isolate_db.isolate()

from core import agent_loop as al                       # noqa: E402
from core import duty                                   # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


calls = []
answer_on_last = {"text": '{"verdict": "benign", "hypothesis": "A laptop."}'}


async def fake_stream(messages, allowlist, round_usage):
    calls.append(messages[-1])
    round_usage.update(calls=1, prompt_tokens=10, completion_tokens=5,
                       estimated=False)
    last = messages[-1]
    if last["role"] == "user" and "rounds of lookups" in (last["content"] or ""):
        if answer_on_last["text"]:
            yield {"type": "text", "token": answer_on_last["text"]}
        # A model that ignores the note and asks for more.
        yield {"type": "tool_calls",
               "calls": [{"id": "late", "name": "query_findings", "params": {}}]}
        return
    yield {"type": "tool_calls",
           "calls": [{"id": f"c{len(calls)}", "name": "query_findings",
                      "params": {}}]}


ran = []
al._api_key, al._model = "test-key", "test-model"
al._stream_model = fake_stream
al.execute_tool = lambda name, params: ran.append(name) or {"result": "ok"}
al.tool_exists = lambda name: True
al.requires_permission = lambda name, params: False

print("\n[1] at the lookup limit it is asked to answer, and does")
out = al.run_unattended("investigate", "s", allowlist=["query_findings"])
check("no error", out["error"], None)
check("the answer is kept", out["answers"][-1], answer_on_last["text"])
check("it is marked as answered at the limit", out["hit_ceiling"], True)
check("13 model calls, the same as before", len(calls),
      al.UNATTENDED_MAX_ROUNDS + 1)
check("tool calls on the last round are not run", len(ran),
      al.UNATTENDED_MAX_ROUNDS)
check("the answer appears once, not twice", len(out["answers"]), 1)

print("\n[2] still no answer: the error says so, with no token count")
calls.clear(); ran.clear()
answer_on_last["text"] = ""
out = al.run_unattended("investigate", "s", allowlist=["query_findings"])
check("an error is returned", bool(out["error"]), True)
check("it names the limit", "12 rounds of lookups" in out["error"], True)
check("and quotes no token figure", "tokens" in out["error"], False)
check("the usage is still counted", out["usage"]["total_tokens"],
      15 * (al.UNATTENDED_MAX_ROUNDS + 1))

print("\n[3] a short run is untouched")
calls.clear(); ran.clear()


async def quick(messages, allowlist, round_usage):
    calls.append(messages[-1])
    round_usage.update(calls=1, prompt_tokens=1, completion_tokens=1,
                       estimated=False)
    yield {"type": "text", "token": '{"verdict": "no_action"}'}


al._stream_model = quick
out = al.run_unattended("investigate", "s", allowlist=["query_findings"])
check("one call", len(calls), 1)
check("not marked as at the limit", out["hit_ceiling"], False)
check("no final note was sent", any("rounds of lookups" in (m.get("content") or "")
                                    for m in calls), False)

print("\n[4] the run line is a sentence")
line = duty._run_summary({"verdict": "needs_human",
                          "hypothesis": "A new device joined. It is a VM."})
check("verdict in words, then the first sentence", line,
      "Verdict: needs your decision. A new device joined.")
check("benign reads as harmless",
      duty._run_summary({"verdict": "benign"}), "Verdict: harmless.")
check("the limit is mentioned when it was hit",
      "lookup limit" in duty._run_summary({"verdict": "benign"}, True), True)
check("a long first sentence is cut",
      len(duty._run_summary({"verdict": "real", "hypothesis": "x" * 500}))
      < 300, True)
check("usage carries the limit flag",
      duty._usage_dict({"usage": {}, "hit_ceiling": True})["hit_ceiling"], True)

print("\n[5] the page reads old rows too")
page = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check("bare verdict codes are translated", "RUN_VERDICT_WORDS" in page, True)
check("the cooldown tags are hidden", "runDetailText(r.detail)" in page, True)
check("lookups are grouped with counts", "toolSummary(r.tools)" in page, True)

print()
if fails:
    print(f"FAILED: {len(fails)}")
    sys.exit(1)
print("ALL PASSED")
