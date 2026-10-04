"""
tests/test_loop_fixes_2.py, bugfinder LOOP-7, LOOP-9, LOOP-10, LOOP-12.

Failure cases first, then the happy path, then a control.

LOOP-7   the kill card line imported core.actions inside the function with
         nothing around it, so a broken import blew up the whole chat turn.
LOOP-9   two tool calls with the same id got two cards and one decision slot.
LOOP-10  nothing stopped two chat turns running at once over one history.
LOOP-12  duty.run_once had no guard, so run-now could race the daemon.
"""
import asyncio
import pathlib
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import agent_loop as al  # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


al.get_session_id = lambda: None


# LOOP-7
print("\n[1] LOOP-7, FAILURE PATH FIRST: core.actions cannot be imported")
saved = sys.modules.get("core.actions")
sys.modules["core.actions"] = None          # makes the import raise
try:
    try:
        line = al._kill_card_line({"pid": 4412, "_process": {"name": "sshd"}})
        raised = None
    except Exception as e:
        line, raised = None, type(e).__name__
    check("building the card line does not raise", raised, None)
    check("the card still names the process", bool(line) and "Kill sshd, PID 4412" in line, True)
    check("and says the restart check could not be done, not that it is fine",
          bool(line) and "could not check" in line.lower(), True)

    al._pin_process_name = lambda params: None
    try:
        card = al._build_permission_card(
            "kill_process", {"pid": 4412, "_process": {"name": "sshd"}}, "c1")
        raised = None
    except Exception as e:
        card, raised = None, type(e).__name__
    check("the whole card still builds", raised, None)
finally:
    if saved is not None:
        sys.modules["core.actions"] = saved
    else:
        sys.modules.pop("core.actions", None)

print("\n[2] LOOP-7 control: with the module there, the real warning still shows")
line = al._kill_card_line({"pid": 1365, "_process": {"name": "sshd"},
                           "_unit": {"verdict": "supervised", "unit": "ssh.service"}})
check("the restart warning is on the card", "RESTART IT" in line, True)
check("and no 'could not check' next to it", "could not check" in line.lower(), False)


# LOOP-9
print("\n[3] LOOP-9, FAILURE PATH FIRST: the model sends one id twice")
calls = al._build_calls({
    0: {"id": "dup", "name": "kill_process", "args": '{"pid": 4412}'},
    1: {"id": "dup", "name": "kill_process", "args": '{"pid": 5510}'},
})
ids = [c["id"] for c in calls]
check("two calls get two different ids", len(set(ids)), 2)
check("the first keeps the model's own id", ids[0], "dup")

print("\n[4] LOOP-9 control: normal ids are left exactly as the model sent them")
calls = al._build_calls({
    0: {"id": "a1", "name": "query_host_info", "args": "{}"},
    1: {"id": "",   "name": "query_host_info", "args": "{}"},
})
# MS-2: a missing id is filled with a random one, never a guessable call_<n>.
got = [c["id"] for c in calls]
check("ids unchanged, missing one filled in",
      (got[0], got[1].startswith("call_") and got[1] != "call_1"), ("a1", True))


# LOOP-10
print("\n[5] LOOP-10, FAILURE PATH FIRST: a second chat turn while one is running")
inside = threading.Event()
release = threading.Event()


async def slow_stream(messages, allowlist=None, usage_out=None):
    inside.set()
    while not release.is_set():
        await asyncio.sleep(0.01)
    yield {"type": "text", "token": "first answer."}


async def fast_stream(messages, allowlist=None, usage_out=None):
    yield {"type": "text", "token": "second answer."}


def drive(msg):
    out = []

    async def go():
        async for tok in al.run(msg):
            out.append(tok)
    asyncio.run(go())
    return "".join(out)


al._history.clear()
al._stream_model = slow_stream
result_a = {}
t = threading.Thread(target=lambda: result_a.setdefault("text", drive("turn A")))
t.start()
check("turn A is inside the model call", inside.wait(5), True)

al._stream_model = fast_stream      # what turn B would get if it ran
shown_b = drive("turn B")
check("turn B is refused, in words", "already running" in shown_b.lower(), True)
check("and turn B did not touch the history",
      [m["content"] for m in al._history], ["turn A"])

release.set()
t.join(5)
check("turn A finishes normally", result_a.get("text"), "first answer.")
check("history is turn A and its answer only",
      [m["role"] for m in al._history], ["user", "assistant"])

print("\n[6] LOOP-10 happy path: once A is done, the next turn runs")
shown = drive("turn C")
check("turn C answered", shown, "second answer.")

print("\n[7] LOOP-10: the lock comes back on every way out")
al._stream_model = lambda *a, **k: _err()


async def _err():
    yield {"type": "error", "message": "timeout"}

drive("error turn")
check("after a provider error", al._chat_lock.locked(), False)


async def abandon():
    al._stream_model = slow_stream
    release.clear()
    gen = al.run("closed tab")
    task = asyncio.ensure_future(gen.__anext__())
    await asyncio.sleep(0.05)
    locked_mid = al._chat_lock.locked()
    release.set()
    await task
    await gen.aclose()
    return locked_mid

check("held while the turn runs", asyncio.run(abandon()), True)
check("and released when the tab closes mid answer", al._chat_lock.locked(), False)


# LOOP-12
print("\n[8] LOOP-12, FAILURE PATH FIRST: run-now while a tick is running")
from core import duty  # noqa: E402

tick_inside = threading.Event()
tick_release = threading.Event()
ran = []


def slow_tick(session_id, trigger="manual", **kw):
    ran.append(trigger)
    tick_inside.set()
    tick_release.wait(5)
    return {"outcome": "ran", "trigger": trigger}

duty._run_once_unguarded = slow_tick
res_a = {}
t = threading.Thread(target=lambda: res_a.update(duty.run_once("s", "regular")))
t.start()
check("the daemon tick is running", tick_inside.wait(5), True)
res_b = duty.run_once("s", "manual")
check("run-now is refused, not run on top", res_b.get("outcome"), "busy")
check("and it says so", "already running" in (res_b.get("detail") or "").lower(), True)
check("only one tick actually ran", ran, ["regular"])
tick_release.set()
t.join(5)
check("the first tick finished with its own result", res_a.get("outcome"), "ran")

print("\n[9] LOOP-12 happy path and control")
check("the next call runs", duty.run_once("s", "manual").get("outcome"), "ran")


def boom(*a, **k):
    raise RuntimeError("tick blew up")

duty._run_once_unguarded = boom
try:
    duty.run_once("s", "manual")
except RuntimeError:
    pass
check("a tick that raises still gives the lock back", duty._tick_lock.locked(), False)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
