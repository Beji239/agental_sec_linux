"""
tests/test_loop_fixes.py, bugfinder LOOP-4 and LOOP-8 (plus LOOP-5, LOOP-6).

Failure cases first, then the happy path, then a control, same order as the
house rule.

LOOP-4. A provider error (timeout, network, non 200, no key) made run() yield
"[Error: ...]" and return BEFORE the unwind at the bottom, so the user message
it had just appended stayed in _history with no assistant after it. Three
errors in a row gave [user, user, user], the malformed history run() already
documents as a one way door. This file drives the REAL run() with only the
stream stubbed and reads _history afterwards.

LOOP-8. _unbacked_kill_claims flagged every integer >= 4 in a sentence that
said killed/terminated/dead, so an honest count ("Killed 12 duplicate
workers") got an UNCONFIRMED banner. Now only a pid shaped number counts: one
after "pid"/"process", one inside a list of numbers, or one sitting right next
to the kill word. The five answers measured in bugfinder are replayed here, plus
the cases test_process_lookup.py already pins, so the fix cannot trade one
lie for the other.
"""
import asyncio
import pathlib
import re
import sys

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


# The DB log at the bottom of run() is not what is measured here, keep it off.
al.get_session_id = lambda: None


def stream_script(*rounds):
    """
    A fake _stream_model that plays one list of chunks per call, in order.
    Only the model is stubbed. run(), its bookkeeping and the history
    handling are the shipped code.
    """
    state = {"i": 0}

    async def fake(messages, allowlist=None, usage_out=None):
        chunks = rounds[min(state["i"], len(rounds) - 1)]
        state["i"] += 1
        for c in chunks:
            yield c
    return fake


def drive(msg):
    out = []

    async def go():
        async for tok in al.run(msg):
            out.append(tok)
    asyncio.run(go())
    return "".join(out)


def roles():
    return [m["role"] for m in al._history]


ERR = [{"type": "error", "message": "DeepSeek API timeout"}]
OK = [{"type": "text", "token": "all quiet."}]


print("\n[1] LOOP-4, FAILURE PATH FIRST: three provider errors in a row")
al._history.clear()
al._stream_model = stream_script(ERR)
for q in ("first", "second", "third"):
    shown = drive(q)
check("the error is still shown to the user", "[Error: DeepSeek API timeout]" in shown, True)
check("and no user message is left dangling", roles(), [])

print("\n[2] an error does not eat the conversation that came before it")
al._history.clear()
al._stream_model = stream_script(OK)
drive("hello")
check("a good turn is kept", roles(), ["user", "assistant"])
al._stream_model = stream_script(ERR)
drive("and now?")
check("the failed turn is unwound, the good one stays", roles(), ["user", "assistant"])
check("and it is the right user message that stayed",
      al._history[0]["content"], "hello")

print("\n[3] an error AFTER a tool round unwinds too")
al._history.clear()
al.execute_tool = lambda name, params: {"result": {"rows": []}, "error": None,
                                         "untrusted": False}
al.requires_permission = lambda *a, **k: False
al._stream_model = stream_script(
    [{"type": "tool_calls", "calls": [{"id": "c1", "name": "query_host_info",
                                        "params": {}, "parse_error": ""}]}],
    ERR)
drive("look around")
check("tool round then provider error leaves nothing dangling", roles(), [])

print("\n[4] HAPPY PATH: the next turn after an error is well formed")
al._stream_model = stream_script(OK)
drive("try again")
check("one user, one assistant", roles(), ["user", "assistant"])

print("\n[5] CONTROL: the unwind only removes THIS turn's message")
# If the history ends with a user message that is not ours (should not
# happen, but if it did), the error path must not pop the wrong thing.
al._history[:] = [{"role": "user", "content": "someone else's"}]
al._stream_model = stream_script(ERR)
drive("mine")
check("the other message is left alone", [m["content"] for m in al._history],
      ["someone else's"])


print("\n[6] LOOP-8, FAILURE PATH FIRST: honest answers that used to be accused")
al._killed_pids.clear()
check("a count of workers is not a pid",
      al._unbacked_kill_claims("Killed 12 duplicate workers the scan left"), [])
check("a count of sessions is not a pid",
      al._unbacked_kill_claims("Terminated the 40 leftover sessions"), [])
check("a count of devices is not a pid",
      al._unbacked_kill_claims("6 devices answered and none are dead"), [])
check("a small count stays quiet too",
      al._unbacked_kill_claims("Killed 3 stale workers"), [])
check("a count of processes is not a pid",
      al._unbacked_kill_claims("I killed 2 of the 5 processes it listed"), [])

print("\n[7] the real claims are still caught")
check("PID next to the number",
      al._unbacked_kill_claims("PID 31612 (LM Studio.exe crashpad-handler) killed"),
      [31612])
check("a list after the kill word",
      al._unbacked_kill_claims("All four killed: 24112, 6104, 16100, 12760"),
      [24112, 6104, 16100, 12760])
check("a bare number right before the kill word",
      al._unbacked_kill_claims("22140 killed, and 420 killed"), [22140, 420])
check("a bare number right after the kill word",
      al._unbacked_kill_claims("Killed 31612."), [31612])
check("two pids joined by and",
      al._unbacked_kill_claims("Killed 31612 and 4410."), [31612, 4410])
check("process keyword plus a list",
      al._unbacked_kill_claims("Processes 5120, 5124 and 5130 are dead"),
      [5120, 5124, 5130])
check("pid in brackets after a name",
      al._unbacked_kill_claims("Terminated chrome (7788) as asked"), [7788])
check("was killed",
      al._unbacked_kill_claims("9912 was killed a minute ago"), [9912])

print("\n[8] the pinned non claims still say nothing")
check("a plan", al._unbacked_kill_claims("Killing 12760 will close the whole app"), [])
check("a card", al._unbacked_kill_claims("Sending the kill card for 31612 now"), [])
check("a lookup", al._unbacked_kill_claims("I checked 1610 and it is not running"), [])
check("a negation", al._unbacked_kill_claims("PID 4410 was not killed"), [])

print("\n[9] CONTROL: a real kill is remembered, so its recap is quiet")
al._remember_kill("kill_process", {"result": {"success": True, "pid": 22140}})
check("recap of a real kill",
      al._unbacked_kill_claims("22140 renderer, killed earlier"), [])
check("while a false one beside it still trips",
      al._unbacked_kill_claims("22140 killed, and 420 killed"), [420])
al._killed_pids.clear()


print("\n[10] LOOP-5 and LOOP-6, the dead names are gone")
src = (ROOT / "core" / "agent_loop.py").read_text(encoding="utf-8")
check("MAX_ARG_RETRIES is not declared",
      bool(re.search(r"^MAX_ARG_RETRIES\s*=", src, re.M)), False)
check("_pending_permission is not declared",
      "_pending_permission:" in src or "_pending_permission =" in src, False)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
