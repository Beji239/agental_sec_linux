"""
tests/test_anthropic_provider.py, the app runs on a native Anthropic endpoint
as well as on OpenAI-shaped ones, and describes whichever one is configured.

Failure cases first. [1] style detection, [2] the request translation,
[3] the stream translation, [4] config and key names, old and new.
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
from core import provider_api as pa          # noqa: E402
from core import secret_store as ss          # noqa: E402

print("\n[1] which wire format an endpoint speaks")
D = pa.detect_style
check("anthropic messages url", D("https://api.anthropic.com/v1/messages"), "anthropic")
check("anthropic bare host", D("https://api.anthropic.com"), "anthropic")
check("anthropic compat layer stays openai",
      D("https://api.anthropic.com/v1/chat/completions"), "openai")
check("deepseek", D("https://api.example.com/v1/chat/completions"), "openai")
check("openrouter", D("https://gateway.example.com/api/v1/chat/completions"), "openai")
check("explicit setting wins", D("https://x.test/v1/chat/completions", "anthropic"), "anthropic")
check("garbage setting is auto", D("https://x.test/v1/messages", "nonsense"), "anthropic")
check("bare base gets the endpoint",
      pa.normalise_url("https://api.anthropic.com", "anthropic"),
      "https://api.anthropic.com/v1/messages")
check("models url from messages url",
      pa.models_url("https://api.anthropic.com/v1/messages"),
      "https://api.anthropic.com/v1/models")
check("anthropic auth header", pa.auth_headers("anthropic", "k")["x-api-key"], "k")
check("openai auth header", pa.auth_headers("openai", "k")["Authorization"], "Bearer k")

print("\n[2] request translation")
msgs = [
    {"role": "system", "content": "SYS"},
    {"role": "user", "content": "hi"},
    {"role": "assistant", "content": None, "tool_calls": [
        {"id": "t1", "type": "function",
         "function": {"name": "a", "arguments": "{\"x\": 1}"}},
        {"id": "t2", "type": "function",
         "function": {"name": "b", "arguments": "not json"}}]},
    {"role": "tool", "tool_call_id": "t1", "content": "r1"},
    {"role": "tool", "tool_call_id": "t2", "content": "r2"},
    {"role": "assistant", "content": ""},
    {"role": "user", "content": "again"},
]
tools = [{"type": "function", "function": {"name": "a", "description": "d",
          "parameters": {"type": "object", "properties": {}}}}]
req = pa.to_anthropic_request(msgs, tools, "m", 100)
check("system is top level", req["system"], "SYS")
check("roles alternate", [m["role"] for m in req["messages"]],
      ["user", "assistant", "user"])
check("tool_use input parsed", req["messages"][1]["content"][0]["input"], {"x": 1})
check("bad arguments become empty input", req["messages"][1]["content"][1]["input"], {})
check("both results in one user turn",
      [b["type"] for b in req["messages"][2]["content"]],
      ["tool_result", "tool_result", "text"])
check("tools translated", req["tools"][0]["input_schema"],
      {"type": "object", "properties": {}})
check("max_tokens present", req["max_tokens"], 100)

print("\n[3] stream translation")
st = pa.AnthropicStream()
evs = [
    {"type": "message_start", "message": {"usage": {"input_tokens": 12}}},
    {"type": "content_block_start", "index": 0, "content_block": {"type": "text"}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hel"}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "lo"}},
    {"type": "content_block_start", "index": 1,
     "content_block": {"type": "tool_use", "id": "tu1", "name": "a"}},
    {"type": "content_block_delta", "index": 1,
     "delta": {"type": "input_json_delta", "partial_json": "{\"x\":"}},
    {"type": "content_block_delta", "index": 1,
     "delta": {"type": "input_json_delta", "partial_json": " 2}"}},
    {"type": "message_delta", "delta": {"stop_reason": "tool_use"},
     "usage": {"output_tokens": 7}},
    {"type": "message_stop"},
]
got = []
for e in evs:
    got += st.feed(e)
check("text tokens", "".join(v for k, v in got if k == "text"), "Hello")
check("tool call assembled", st.tool_calls, {1: {"id": "tu1", "name": "a", "args": "{\"x\": 2}"}})
check("usage", st.usage(), {"prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19})
check("stop reason", st.stop_reason, "tool_use")
check("error event surfaces",
      pa.AnthropicStream().feed({"type": "error", "error": {"type": "overloaded_error",
                                                            "message": "busy"}}),
      [("error", "overloaded_error: busy")])


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


class _Client:
    seen = {}

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def stream(self, method, url, json=None, headers=None):
        _Client.seen = {"url": url, "payload": json, "headers": headers}
        lines = ["event: x"] + ["data: " + __import__("json").dumps(e) for e in evs]
        return _Ctx(_Resp(lines))


print("\n[4] end to end through _stream_model, with the fake provider")
al.init_agent({"provider": {"model": "model-test",
                            "api_url": "https://api.anthropic.com/v1/messages"}},
              api_key="sk-ant-test")
check("style detected", al.api_style(), "anthropic")
real = al.httpx
al.httpx = type("H", (), {"AsyncClient": _Client})
usage = {}


async def go():
    out = []
    async for c in al._stream_model([{"role": "user", "content": "q"}], None, usage):
        out.append(c)
    return out


try:
    chunks = asyncio.run(go())
finally:
    al.httpx = real
check("url used", _Client.seen["url"], "https://api.anthropic.com/v1/messages")
check("model sent", _Client.seen["payload"]["model"], "model-test")
check("x-api-key sent", _Client.seen["headers"]["x-api-key"], "sk-ant-test")
check("no bearer header", "Authorization" in _Client.seen["headers"], False)
check("text chunks", "".join(c["token"] for c in chunks if c["type"] == "text"), "Hello")
calls = [c for c in chunks if c["type"] == "tool_calls"]
check("one tool_calls chunk", len(calls), 1)
check("call params", calls[0]["calls"][0]["params"], {"x": 2})
check("usage is the provider's", usage["estimated"], False)
check("usage prompt tokens", usage["prompt_tokens"], 12)
st_ = al.model_status()
check("status says which API", st_["api_style"], "anthropic")
check("status model", st_["model"], "model-test")

print("\n[5] only the provider section and AGENTAL_API_KEY are read")
check("the provider section is read",
      al.provider_section({"provider": {"model": "a", "api_url": "u"}})["model"], "a")
check("a blank value is left out",
      "model" in al.provider_section({"provider": {"model": ""}}), False)
check("the old deepseek section is not read",
      al.provider_section({"deepseek": {"model": "a"}}), {})
import os                                    # noqa: E402
import pathlib                               # noqa: E402
import tempfile                              # noqa: E402
os.environ.pop("AGENTAL_API_KEY", None)
os.environ["AGENTAL_DEEPSEEK_API_KEY"] = "old"
with tempfile.TemporaryDirectory() as _d:
    _got = ss.resolve({}, pathlib.Path(_d))["api_key"]
os.environ.pop("AGENTAL_DEEPSEEK_API_KEY", None)
check("the old env var is not read", _got, "")

print()
print("ALL CHECKS PASSED" if not fails else f"FAILED: {fails}")
sys.exit(1 if fails else 0)
