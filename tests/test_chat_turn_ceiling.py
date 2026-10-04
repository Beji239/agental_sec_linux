"""
tests/test_chat_turn_ceiling.py: the per-turn ceilings on a chat turn.

Drives the real run() with the model stubbed. Each ceiling must stop the turn
before the next model call and say which one it was; a normal turn and time
spent at an approval card must not trip it.
"""
import asyncio
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import agent_loop  # noqa: E402

fails = []


def check(label, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f": {detail}" if detail else ""))
    if not ok:
        fails.append(label)


ORIG = {k: getattr(agent_loop, k) for k in
        ("CHAT_TURN_MAX_SECONDS", "MAX_TOOL_ROUNDS", "_api_context",
         "_stream_model", "execute_tool", "requires_permission",
         "_wait_for_permission", "get_session_id")}


def restore():
    for k, v in ORIG.items():
        setattr(agent_loop, k, v)


def drive(result_chars=10, answer_after=None, permission=False):
    """
    One real turn. The model asks for a tool every round, or answers "done."
    on round `answer_after`. Returns (text on screen, model calls made).
    """
    state = {"calls": 0}

    async def fake_stream(messages, allowlist=None, usage_out=None):
        state["calls"] += 1
        if answer_after is not None and state["calls"] > answer_after:
            yield {"type": "text", "token": "done."}
            return
        yield {"type": "tool_calls",
               "calls": [{"id": f"c{state['calls']}", "name": "query_host_info",
                          "params": {}, "parse_error": ""}]}

    def fake_execute(name, params):
        return {"result": {"blob": "x" * result_chars}, "error": None,
                "untrusted": False}

    agent_loop._stream_model = fake_stream
    agent_loop.execute_tool = fake_execute
    agent_loop.requires_permission = lambda *a, **k: permission
    agent_loop.get_session_id = lambda: None
    agent_loop._history.clear()

    out = []

    async def run():
        async for tok in agent_loop.run("investigate"):
            if tok != agent_loop.CARD_WAITING_MARKER:
                out.append(tok)

    asyncio.run(run())
    return "".join(out), state["calls"]


print("\n[1] THE WALL CLOCK. A ceiling of 0 s stops the turn after round one,")
print("    before a second model call is made.")
agent_loop.CHAT_TURN_MAX_SECONDS = 0
text, calls = drive()
check("one model call, not twenty-six", calls == 1, f"calls={calls}")
check("the screen names the time ceiling", "0-second ceiling" in text, text[-160:])
check("and does not claim an unknown reason",
      "not one this app recognises" not in text)
check("history holds no dangling user message", agent_loop._history == [],
      repr(agent_loop._history))
restore()


print("\n[2] THE CONTEXT CEILING INSIDE A TURN. Each result is ~30,000 tokens;")
print("    the room is set so the first call fits and the next one would not.")
agent_loop._api_context = 1       # _build_messages below needs a value first
base = (agent_loop._estimate_tokens(agent_loop._build_messages())
        + len(__import__("json").dumps(agent_loop._tools_payload())) // 4)
agent_loop._api_context = base + agent_loop._response_reserve() + 10_000
text, calls = drive(result_chars=200_000)
check("stopped after one call", calls == 1, f"calls={calls}")
check("the screen names the context ceiling", "context ceiling" in text,
      text[-200:])
restore()


print("\n[3] THE ROUND CAP now ends honestly rather than promising a summary")
print("    and falling through to 'the reason is not one this app recognises'.")
agent_loop.MAX_TOOL_ROUNDS = 3
text, calls = drive()
check("four calls (rounds 0..3)", calls == 4, f"calls={calls}")
check("names the round ceiling", "3-round ceiling" in text, text[-160:])
check("no false summary promise", "Summarizing what I found" not in text)
check("no unknown-reason sentence", "not one this app recognises" not in text)
restore()


print("\n[4] A NORMAL TURN IS UNTOUCHED: one tool, then the answer.")
text, calls = drive(answer_after=1)
check("answered", text.strip().endswith("done."), text[-80:])
check("no ceiling sentence", "Stopped by" not in text)
restore()


print("\n[5] TIME AT AN APPROVAL CARD IS NOT COUNTED. A 1 s ceiling and a card")
print("    that takes 1.5 s to answer must still end in the model's answer.")


async def slow_card(call_id, decision, card=None):
    await asyncio.sleep(1.5)
    decision["value"] = True
    return
    yield  # an async generator, like the real one


agent_loop.CHAT_TURN_MAX_SECONDS = 1
agent_loop._wait_for_permission = slow_card
text, calls = drive(answer_after=1, permission=True)
check("the approved turn reached its answer", text.strip().endswith("done."),
      text[-200:])
check("no ceiling sentence", "Stopped by" not in text)
restore()


print()
if fails:
    print(f"{len(fails)} FAILED: {fails}")
    sys.exit(1)
print("all passed")
