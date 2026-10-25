# tests/test_complete_once_closes.py
# complete_once, the daily report's one model call, closes its stream and the
# stream's inner generators before its loop goes, so no "Task was destroyed
# but it is pending" follows the report.

import gc
import logging
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import agent_loop as al                     # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


seen = []


class Catch(logging.Handler):
    def emit(self, record):
        seen.append(record.getMessage())


logging.getLogger("asyncio").addHandler(Catch())


async def body_lines():
    for i in range(10):
        yield i


async def stream_ok(messages, allowlist=None, usage_out=None):
    # Like a streamed HTTP body: an inner generator left open part way.
    lines = body_lines()
    async for _ in lines:
        yield {"type": "text", "token": "ok "}
        break
    yield {"type": "text", "token": "done"}


async def stream_error(messages, allowlist=None, usage_out=None):
    lines = body_lines()
    async for _ in lines:
        yield {"type": "error", "message": "boom"}
    yield {"type": "text", "token": "never"}


al._api_key, al._model = "x", "m"

print("an answer that ends normally")
al._stream_model = stream_ok
out = al.complete_once("system", "prompt")
gc.collect()
check("the text comes back", out["text"], "ok done")
check("nothing is left pending", sum("destroyed" in m for m in seen), 0)

print("an answer that ends in an error")
al._stream_model = stream_error
out = al.complete_once("system", "prompt")
gc.collect()
check("the error comes back", (out["text"], out["error"]), ("", "boom"))
check("nothing is left pending", sum("destroyed" in m for m in seen), 0)

print()
if fails:
    print(f"FAILED: {len(fails)}")
    for f in fails:
        print(f"  {f}")
    sys.exit(1)
print("ALL PASSED")
