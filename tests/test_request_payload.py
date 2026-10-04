"""
tests/test_request_payload.py, the request we actually send. TODO 106,
2026-09-14.

WHY THIS EXISTS, and it is a bug I shipped yesterday.

Removing local mode changed _tools_payload from taking a mode to taking
nothing. I updated the two call sites that passed the variable, _tools_payload
(_mode), and never saw the third, which passed the literal string:

    "tools": _tools_payload("api"),

It sat inside _stream_deepseek, which is the function that builds the request
body for every chat turn. Seventy two tests passed. The suite was green on two
machines. Then the first real question after the boot raised

    TypeError: _tools_payload() takes 0 positional arguments but 1 was given

and the dashboard showed a 500 with no explanation.

THE REAL GAP IS NOT THE TYPO. Nothing in the suite ever built the request. The
tests covered the manifest, the budget numbers, the trimmer, the parser and
the empty answer handling, and every one of them stopped short of the one dict
that gets posted. A function nobody calls in tests is a function that only
production calls first.

So this file runs _stream_deepseek FOR REAL, with httpx replaced by a fake
that captures what was about to go on the wire and answers with a canned
stream. No network, no key, no provider.

Failure cases first, as always.
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


from core import agent_loop as al               # noqa: E402


# A stand-in for httpx. It records the payload, then answers with the smallest
# stream the parser accepts so the generator finishes normally.
class _FakeResponse:
    def __init__(self, status=200, lines=None):
        self.status_code = status
        self._lines = lines if lines is not None else ["data: [DONE]"]

    async def aiter_lines(self):
        for line in self._lines:
            yield line

    async def aread(self):
        return b'{"error": {"message": "fake"}}'


class _FakeStream:
    def __init__(self, resp):
        self._resp = resp

    async def __aenter__(self):
        return self._resp

    async def __aexit__(self, *a):
        return False


class _FakeClient:
    captured = {}
    status = 200
    lines = None

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def stream(self, method, url, json=None, headers=None):
        _FakeClient.captured = {"method": method, "url": url,
                                "payload": json, "headers": headers}
        return _FakeStream(_FakeResponse(_FakeClient.status, _FakeClient.lines))


def run_turn(messages=None):
    """Drive _stream_deepseek to completion and return the chunks it yielded."""
    _FakeClient.captured = {}

    async def go():
        out = []
        async for chunk in al._stream_deepseek(
                messages if messages is not None else
                [{"role": "user", "content": "hello"}]):
            out.append(chunk)
        return out

    return asyncio.run(go())


al.init_agent({"deepseek": {"model": "test-model",
                            "api_url": "https://example.invalid/v1/chat"}},
              "test-key")
_real_httpx = al.httpx
al.httpx = type("_FakeHttpx", (), {"AsyncClient": _FakeClient})


try:
    print("\n[1] THE FAILURE THAT SHIPPED. Building the request must not raise.")
    # This is the whole point of the file. The old code raised TypeError here,
    # inside the dict literal, before a single byte went anywhere.
    raised = None
    try:
        chunks = run_turn()
    except Exception as e:
        raised = f"{type(e).__name__}: {e}"
    check("the request builds without raising", raised, None)
    check("and something actually got sent",
          bool(_FakeClient.captured.get("payload")), True)
    check("no chunk came back as an error",
          [c for c in chunks if c.get("type") == "error"], [])

    payload = _FakeClient.captured["payload"]

    print("\n[2] the tools really go in, and it is the WHOLE manifest")
    # A payload with no tools is the other way this breaks: the model answers
    # from memory and calls nothing, which reads as the model being stupid
    # rather than as the app forgetting to offer it anything.
    from core import tool_registry as tr        # noqa: E402
    check("tools are present", "tools" in payload, True)
    check("and it is every tool in the manifest",
          len(payload["tools"]), len(tr.TOOL_MANIFEST))
    check("in the shape the provider expects",
          all(t.get("type") == "function" and "name" in t.get("function", {})
              for t in payload["tools"]), True)
    check("tool_choice lets the model decide", payload.get("tool_choice"), "auto")

    print("\n[3] the numbers in the body are the configured ones")
    check("the model name is the configured one", payload.get("model"), "test-model")
    check("max_tokens is the answer budget", payload.get("max_tokens"),
          al._max_output_tokens)
    check("and that budget is the same one the trimmer reserves",
          al._response_reserve(), payload.get("max_tokens"))
    check("streaming is on", payload.get("stream"), True)
    check("the messages went through untouched",
          payload.get("messages"), [{"role": "user", "content": "hello"}])

    print("\n[4] it posts to the configured endpoint with the key")
    check("method", _FakeClient.captured["method"], "POST")
    check("url is the configured one", _FakeClient.captured["url"],
          "https://example.invalid/v1/chat")
    check("the key is sent as a bearer token",
          _FakeClient.captured["headers"]["Authorization"], "Bearer test-key")

    print("\n[5] FAILURE CASE. A provider error is reported, not swallowed.")
    _FakeClient.status = 400
    try:
        chunks = run_turn()
    finally:
        _FakeClient.status = 200
    errors = [c for c in chunks if c.get("type") == "error"]
    check("an error chunk comes back", len(errors), 1)
    check("and it carries the status", "400" in errors[0]["message"], True)
    check("and what the provider said", "fake" in errors[0]["message"], True)

    print("\n[6] FAILURE CASE. No key means no request at all.")
    _saved_key = al._api_key
    al._api_key = ""
    try:
        chunks = run_turn()
    finally:
        al._api_key = _saved_key
    errors = [c for c in chunks if c.get("type") == "error"]
    check("it refuses", len(errors), 1)
    check("and says why", "key" in errors[0]["message"].lower(), True)
    check("and nothing was sent", _FakeClient.captured, {})

    print("\n[7] only the unattended turn passes an allowlist")
    # CONVERTED 2026-09-21, and the difference is a FORK rather than drift.
    # The Windows tree removed the argument entirely; THIS tree keeps it,
    # because run_unattended is given the read tools plus the two writes that
    # touch this app's own records, and the chat path still gets everything.
    # The RULE the check was written for is unchanged and still the point: a
    # call site must not pass a stray argument by accident, and the argument
    # that does exist must be passed by exactly one caller.
    import re                                    # noqa: E402
    src = (ROOT / "core" / "agent_loop.py").read_text(encoding="utf-8")
    code = "\n".join(l.split("#")[0] for l in src.splitlines())
    check("(the comment stripper works)",
          "\n".join(l.split("#")[0] for l in
                    ['x = 1  # _tools_payload("api")']).strip(), "x = 1")
    calls = re.findall(r"(?<!def )_tools_payload\(([^)]*)\)", code)
    passed = [c.strip() for c in calls if c.strip()]
    check("only the allowlist form is ever passed",
          sorted(set(passed)), ["allowlist"])
    check("and the chat path still passes nothing",
          "" in [c.strip() for c in calls], True)
    check("and there are calls to check at all", len(calls) > 1, True)

finally:
    al.httpx = _real_httpx


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
