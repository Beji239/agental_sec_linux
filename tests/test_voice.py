"""
tests/test_voice.py, TODO 113.1. The app stops lecturing the operator about
itself, and stops denying things it can actually do.

2026-09-17, the owner, about the chat: it is very discouraging that the model
starts explaining its deficiencies in the MIDDLE of the conversation, what it
cannot do and what it does not have. "Kinda gives this feeling that why are we
using this tool to begin with."

2026-09-18, after being told the fix was about relocating rule two, the owner pushed
back harder and the owner was right: the explanation itself is VOID. The app has a
UDP scanner now, it hashes and checks signatures, it looks up reputation, and
the router work is coming. A paragraph about its own blindness is not honesty
any more, it is out of date.

TWO FAULTS, AND THIS FILE GUARDS BOTH.

  FAULT ONE, the recital. Guidance written for the model arrived in results as
  plain prose, so the model passed it to the operator. Fixed by marking it:
  core.voice.for_you puts "FOR YOU, NOT FOR THE OPERATOR" on the front, and
  the prompt says that text is to be obeyed, not read out.

  FAULT TWO, the stale denial, and it is the worse one. SYSTEM_PROMPT told the
  model there was no hashing and no reputation lookup while inspect_process
  was returning a sha256, a signature and the reputation for that hash. Nobody
  catches a modest lie. core.voice.stale_denials catches it now.

FAILURE CASES FIRST, sections [1] to [3], per the rule from 2026-09-13. Each
one is driven with input that PRODUCED the bug, so a regression is caught by
something going red rather than by somebody reading the file.

What this file does NOT test: whether the model actually shuts up. That is a
model behaviour and no test here can prove it. What is provable is that the
instructions no longer ask it to talk that way, and that nothing in a result
arrives looking like a paragraph for the user. That is the claim, and it is
narrower than the complaint.
"""
import sys, pathlib, ast

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []
def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)

from core import voice


print("\n[1] FAILURE CASE: a prompt that denies a capability the app HAS")
# The exact sentence that shipped in SYSTEM_PROMPT for weeks, against a tool
# list that contains the tool disproving it.
stale = ("You are a security analyst.\n"
         "Specifically, you do NOT have these: no file integrity or file "
         "access monitoring, no antivirus, hashing, reputation lookup or "
         "YARA, and no memory analysis.")
live_tools = ["query_findings", "inspect_process", "lookup_ip", "restore_file"]
problems = voice.stale_denials(stale, live_tools)
check("the old sentence is caught", len(problems) > 0, True)
check("and it names the tool that disproves it",
      any("inspect_process" in p for p in problems), True)
for p in problems:
    print(f"       caught: {p}")

# The same sentence against an app that really does lack those tools is NOT a
# problem. A denial is only stale when something contradicts it.
check("the same words are fine when the tools are absent",
      voice.stale_denials(stale, ["query_findings", "query_events"]), [])

# And the guard never claims more than it looked for.
check("an honest prompt produces nothing",
      voice.stale_denials("Answer from the tools in front of you.", live_tools), [])


print("\n[2] FAILURE CASE: guidance that arrives unmarked")
# An unmarked note is a note the model reads as prose for the user. This is
# the check, driven first against text that has NOT been through for_you.
raw = "Something this answer rests on is degraded right now."
check("raw guidance is not marked", voice.is_marked(raw), False)
check("for_you marks it", voice.is_marked(voice.for_you(raw)), True)
check("the marker comes FIRST, where it gets read",
      voice.for_you(raw).startswith(voice.NOT_FOR_RECITAL), True)
check("the original text survives intact",
      raw in voice.for_you(raw), True)


print("\n[3] FAILURE CASE: the edges of for_you")
check("empty stays empty, marking nothing is noise", voice.for_you(""), "")
check("None-ish stays falsy", voice.for_you(None), None)
once = voice.for_you(raw)
check("marking twice does not stack the marker", voice.for_you(once), once)
check("a doubled marker would have been visible",
      once.count(voice.NOT_FOR_RECITAL), 1)


print("\n[4] the REAL prompt carries no stale denial")
from core import agent_loop
from core import tool_registry as tr
names = [t["name"] for t in tr.TOOL_MANIFEST]
real = voice.stale_denials(agent_loop.SYSTEM_PROMPT, names)
for p in real:
    print(f"       STALE: {p}")
check("SYSTEM_PROMPT does not deny what the tool list provides", real, [])


print("\n[5] the real guidance constants say who they are for")
from core import sensor_health
from tools.vpn_state import VPNState
check("sensor_health.READING_NOTE is marked",
      voice.is_marked(sensor_health.READING_NOTE), True)
check("vpn_state.BLIND_TO is marked",
      voice.is_marked(VPNState.BLIND_TO), True)
# The one sentence that IS for the operator must NOT be marked, or nobody
# would ever say it and 'disconnected' goes back to meaning 'no VPN'.
check("the operator-facing scope line is NOT marked",
      voice.is_marked(VPNState.SCOPE_LINE), False)
check("and it is short enough to say out loud", len(VPNState.SCOPE_LINE) < 140, True)


print("\n[6] every how_to_read_this in the manifest is marked, by AST not by regex")
# Read as a syntax tree on purpose. FOUR times this project has been bitten by
# a test pinning the exact SHAPE of source text: test_sensor_hardening on an
# if line, test_ui_wiring on a wrapped f-string, test_deviation_provenance on
# a CHECK constraint, test_heartbeat_shutdown on a split anchor. A tree does
# not care how the string was wrapped.
def unmarked_guidance(path):
    tree = ast.parse(pathlib.Path(path).read_text(encoding="utf-8"))
    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for k, v in zip(node.keys, node.values):
            if not (isinstance(k, ast.Constant) and k.value == "how_to_read_this"):
                continue
            # A call is assumed to be for_you or something that delegates to
            # it, and a name is checked where it is defined. A bare literal is
            # the thing that gets recited.
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                if not v.value.startswith(voice.NOT_FOR_RECITAL):
                    bad.append((v.lineno, v.value[:60]))
            elif isinstance(v, ast.JoinedStr):
                bad.append((v.lineno, "f-string, not marked"))
    return bad

for f in ("core/tool_registry.py", "core/predictions.py", "core/sensor_health.py"):
    bad = unmarked_guidance(ROOT / f)
    for line, snippet in bad:
        print(f"       {f}:{line} unmarked: {snippet}...")
    check(f"{f} has no unmarked how_to_read_this", bad, [])

# PROVE THE SCAN CATCHES IT, rather than trusting a clean result. A clean
# answer from a check that cannot see is the exact fault this project keeps
# repeating.
probe = ROOT / "tests" / "_voice_probe_tmp.py"
probe.write_text('X = {"how_to_read_this": "this one is bare prose"}\n', encoding="utf-8")
try:
    caught = unmarked_guidance(probe)
    check("the scan goes red on a deliberately bare literal", len(caught), 1)
finally:
    probe.unlink(missing_ok=True)


print("\n[7] the prompt asks for the new voice and no longer asks for the old one")
p = agent_loop.SYSTEM_PROMPT
check("it says a no-tool answer is one line",
      "I do not have a tool for that" in p, True)
check("it forbids opening with a limitation",
      "Never open an answer with what you cannot do" in p, True)
check("it says tool text is to obey, not to read out",
      "not paragraphs to read out" in p, True)
check("it no longer promises to keep every caveat at any length",
      "never\nthe limits of your evidence" in p or
      "Cut the explanation of your process, never" in p, False)
check("rule two is still there for the CODE",
      "sensor could not look" in p.lower(), True)
check("and measured is still refused on a blind window",
      "basis='measured'" in p, True)


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
