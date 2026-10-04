"""
tests/test_stream_nulls.py, the OpenAI-shaped stream survives null fields, and
a budget too small for the fixed part of a request is named before any call.

SGLang and vLLM send "tool_calls": null where other providers leave the key out, and
.get(key, default) gives None for a key that is present. Every turn against
such a server ended in "'NoneType' object is not iterable".

[1] null tool_calls, null function, null arguments, empty choices
[2] a tool call split across chunks with nulls in between still assembles
[3] a budget below the fixed overhead is refused before the first call
"""
import asyncio
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


from core import agent_loop as al            # noqa: E402


class _Resp:
    status_code = 200

    def __init__(self, lines):
        self._l = lines

    async def aiter_lines(self):
        for x in self._l:
            yield x


class _Ctx:
    def __init__(self, r):
        self.r = r

    async def __aenter__(self):
        return self.r

    async def __aexit__(self, *a):
        return False


def _client_for(events):
    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def stream(self, method, url, json=None, headers=None):
            lines = ["data: " + __import__("json").dumps(e) for e in events]
            return _Ctx(_Resp(lines + ["data: [DONE]"]))
    return _Client


def run_stream(events):
    real = al.httpx
    al.httpx = type("H", (), {"AsyncClient": _client_for(events)})

    async def go():
        return [c async for c in al._stream_model(
            [{"role": "user", "content": "q"}], None, {})]
    try:
        return asyncio.run(go())
    finally:
        al.httpx = real


al.init_agent({"provider": {"model": "local-test",
                            "api_url": "http://localhost:9/v1/chat/completions"}},
              api_key="none")


def delta(**d):
    base = {"role": None, "content": None, "reasoning_content": None,
            "tool_calls": None}
    base.update(d)
    return {"choices": [{"index": 0, "delta": base, "finish_reason": None}]}


print("\n[1] a text answer with every unused field null, then a usage chunk")
print("    with an empty choices list")
events = [delta(role="assistant", content=""),
          delta(content="\n\nDONE"),
          {"choices": [{"index": 0, "delta": None, "finish_reason": "stop"}]},
          {"choices": [], "usage": {"prompt_tokens": 5, "completion_tokens": 2,
                                    "total_tokens": 7}}]
chunks = run_stream(events)
check("no error chunk", [c for c in chunks if c["type"] == "error"], [])
check("text arrives", "".join(c["token"] for c in chunks if c["type"] == "text"),
      "\n\nDONE")

print("\n[2] a tool call in pieces, nulls in every field it leaves out")
events = [
    delta(tool_calls=[{"index": 0, "id": "c1", "type": "function",
                       "function": {"name": "query_host_info", "arguments": None}}]),
    delta(tool_calls=[{"index": None, "id": None, "function": None}]),
    delta(tool_calls=[{"index": 0, "id": None,
                       "function": {"name": None, "arguments": "{\"a\": "}}]),
    delta(tool_calls=[{"index": 0, "function": {"arguments": "1}"}}]),
    {"choices": [{"index": 0, "delta": {"tool_calls": None},
                  "finish_reason": "tool_calls"}]},
]
chunks = run_stream(events)
check("no error chunk", [c for c in chunks if c["type"] == "error"], [])
calls = [c for c in chunks if c["type"] == "tool_calls"]
check("one tool_calls chunk", len(calls), 1)
if calls:
    call = calls[0]["calls"][0]
    check("name kept", call["name"], "query_host_info")
    check("id kept", call["id"], "c1")
    check("arguments assembled", call["params"], {"a": 1})

print("\n[3] a context_budget below the fixed overhead is refused up front")
calls_made = {"n": 0}


async def fake_stream(messages, allowlist=None, usage_out=None):
    calls_made["n"] += 1
    yield {"type": "text", "token": "answer"}

real_stream, real_ctx, real_explicit = al._stream_model, al._api_context, al._context_explicit
al._stream_model = fake_stream
al._api_context = al._fixed_overhead_tokens() + al._response_reserve() - 1
al._context_explicit = True
al._history.clear()


async def turn():
    return "".join([t async for t in al.run("anything")])
try:
    text = asyncio.run(turn())
finally:
    al._stream_model, al._api_context, al._context_explicit = (
        real_stream, real_ctx, real_explicit)
check("no model call made", calls_made["n"], 0)
check("says it was not sent", text.startswith("[Not sent to the model."), True)
check("names the setting", "context_budget in config.json" in text, True)
check("gives a floor", f"at least {al._budget_floor():,}" in text, True)
check("history holds no dangling user message", al._history, [])

print()
print("ALL CHECKS PASSED" if not fails else f"FAILED: {fails}")
sys.exit(1 if fails else 0)
