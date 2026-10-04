"""
tests/test_answer_budget.py, the model gets enough room to speak, and the app
says what happened when it does not.

WHERE THIS CAME FROM, 2026-09-09. Two "[No response was produced. Please try
again.]" turns in one afternoon, on a model that had clearly just done real
work. The instrumentation from 76 caught it on its first real failure and both
reports were identical:

    2050 chunk(s), ended by [DONE], finish_reason 'length',
    0 content chunk(s), 2048 reasoning, tool calls [], HTTP 200

max_tokens was 2048. Reasoning and answer share ONE budget on these models,
DeepSeek counts reasoning_tokens inside completion_tokens, so the model spent
all 2048 thinking and had nothing left to say a word with.

THREE THINGS THIS FILE GUARDS, and the third is the one that will rot first.

ONE, the size. If max_tokens ever goes back down near 2048 this returns.

TWO, the pair. max_tokens and the trimmer's reserve were two separate 2048
literals in two different parts of one file. Raise one and the trimmer starts
handing the model less room than it just promised itself, silently.

THREE, the message. "Please try again" named a cause that was not the cause,
and the advice that followed from it sent the owner round in a circle: the
same question produces the same result, because nothing about it changed.
That is the same failure as 47.9, 59, 60.5 and 77, and it is the one somebody
will tidy away without realising what it was for.
"""
import io
import pathlib
import re
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


from core import agent_loop as al                 # noqa: E402

SRC = io.open(ROOT / "core" / "agent_loop.py", encoding="utf-8").read()
# The comments explain the old numbers, so phrase matching has to look at what
# the code DOES, not at the file. Same lesson as the two checks that failed on
# their own documentation earlier today.
CODE = "\n".join(ln for ln in SRC.splitlines()
                 if not ln.lstrip().startswith("#"))


def boot(**deepseek):
    """init_agent with a minimal config. No network."""
    al.init_agent({"provider": {"model": "test-model", **deepseek}}, "test-key")


print("\n[1] the answer budget is big enough to think AND speak")
boot()
check("the model name took", al._model, "test-model")
# 2048 is the number that caused this. Anything near it is the bug returning.
check("the default is far above the 2048 that broke it",
      al._max_output_tokens >= 8192, True)
check("and it is a real ceiling, not unlimited",
      al._max_output_tokens <= 64000, True)


print("\n[2] ONE number, not two literals in two places")
# The whole bug class here is a reserve that stops matching the ceiling.
check("the reserve IS the ceiling",
      al._response_reserve(), al._max_output_tokens)
check("the payload does not hardcode a number",
      '"max_tokens":  2048' in CODE, False)
check("it sends the configured one",
      '"max_tokens":  _max_output_tokens' in CODE, True)
check("and the trimmer asks the function, not a constant",
      "_context_limit() - _fixed_overhead_tokens() - _response_reserve()"
      in CODE, True)


print("\n[3] there is ONE backend and ONE set of numbers")
# Local mode had its own context and its own reserve, and a second branch in
# every one of these functions. Removed 2026-09-14, TODO 105. What is checked
# here is that no branch survived it, because a leftover branch on a mode
# that no longer exists is dead code that still decides things.
for gone in ("_mode", "_local_cfg", "_local_ready", "RESPONSE_RESERVE",
             "MIN_LOCAL_NUM_CTX", "LOCAL_MODE_ADDENDUM"):
    check(f"{gone} is gone from agent_loop", hasattr(al, gone), False)
check("and nothing still branches on a mode", '_mode ==' in CODE, False)


print("\n[4] config can move it, within bounds that cannot reintroduce the bug")
boot(max_output_tokens=2048)
check("a config asking for 2048 is clamped UP", al._max_output_tokens >= 4096, True)
boot(max_output_tokens=999_999)
check("and an absurd one is clamped down", al._max_output_tokens <= 64000, True)
boot(max_output_tokens=20000)
check("a sensible value is honoured", al._max_output_tokens, 20000)


print("\n[5] the context number is no longer a wrong hardcoded 64,000")
# The V4 models take 1,000,000. The old hardcoded 64,000 made one failing
# request read as "63,550 against a context of 64,000", which nearly sent us
# chasing a context bug that did not exist, for the SECOND time on this same
# symptom.
boot()
check("api context is configurable", "_api_context" in CODE, True)
check("64000 is no longer returned as a literal",
      "return 64000" in CODE, False)
check("the default leaves real room after overhead and the answer",
      al._context_limit() - al._response_reserve() > 80_000, True)
boot(context_budget=250_000)
check("config can raise it", al._context_limit(), 250_000)
boot(context_budget=10)
check("but not below something workable", al._context_limit() >= 32_000, True)


print("\n[6] the history budget now holds the turn that failed")
# The failing turn sent 41,753 tokens of messages. Under the old numbers that
# was above the budget and being trimmed; it has to fit comfortably now.
boot()
check("41,753 tokens of conversation fits", al._history_budget() > 41_753, True)
check("with real headroom, not by a hair",
      al._history_budget() > 60_000, True)


print("\n[7] THE MESSAGE. It says what happened, not 'try again'.")
check("the circular advice is gone",
      "No response was produced. Please try again." in SRC, False)
check("the length case is detected at all",
      'report.get("finish_reason") == "length"' in CODE, True)
check("and only when nothing was actually said",
      'not report.get("content_chunks")' in CODE, True)
# Adjacent string literals again. A sentence the owner reads as one line is
# several literals in the file, so "share ONE budget" is not one contiguous
# run of characters. Join the literals first, then flatten whitespace. Three
# checks below failed on this before the join was added, which is the third
# time today a check tripped over source formatting rather than behaviour.
JOINED = re.sub(r'"\s*\n\s*f?"', "", SRC)
FLAT = " ".join(JOINED.split())
check("it says the budget was spent thinking",
      "answer budget thinking" in FLAT, True)
check("it explains that reasoning and answer share one budget",
      "share ONE budget" in FLAT, True)
check("it says retrying the same question will not help",
      "same question again will most likely do the same thing" in FLAT, True)
check("and it names the config key that changes it",
      "provider.max_output_tokens in config.json" in FLAT, True)
# A cause we do not recognise must not borrow the explanation of one we do.
check("an unrecognised empty answer says so instead of guessing",
      "not one this app recognises" in FLAT, True)
check("and points at the stream report rather than a theory",
      "before theorising" in FLAT, True)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
