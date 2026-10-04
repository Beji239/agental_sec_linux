"""
tests/test_process_lookup.py, what is PID 26920.

TODO 66. Where this came from, 2026-09-08.

The owner asked the model to stop a process by pid. It could not find out what
that pid was, because nothing in this tool could: process identity only ever
arrived attached to a packet or an event, so a pid with no traffic was a
number with nothing behind it. It said so honestly, four times, and the
conversation went round in circles until the owner shouted at it. Then it killed one
anyway and learned the name from the OS at the moment of termination, which
is the worst possible moment to find out.

Four faults came out of that one transcript and this file covers all four:

  1. no way to turn a pid into a process
  2. the approval card said "Kill process PID 26920" and nothing else, so a
     person was approving a number, and nothing carried the name across the
     gap between the decision and the kill
  3. the model wrote "raising the approval card now" five times without ever
     calling the tool, and nothing on screen contradicted it
  4. query_packets had process columns and no way to filter on them, so a pid
     search returned the whole capture and read as "nothing mentions this pid"

Runs anywhere. No database, no network, no Windows.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ISOLATED, ADDED 2026-09-22, AND THIS FILE MADE THE CASE FOR IT.
#
# Section [3] below kills a process FOR REAL and the kill writes a finding.
# scripts/run_tests.py points every child it starts at a throwaway database, so
# under the runner this file is harmless. Run BY HAND -- which is how a test is
# run most often, while working on it -- it went straight through
# memory_engine.DB_PATH to the project's own evidence store, and the row it
# left was a real one:
#
#     id 151  session_id 'test'  source remediation  REM-1001
#     title 'Process killed: python3 (pid 107931)'
#     description 'testing the guard'
#
# That is TODO 108 again, found the same way the first round was: by reading
# the database rather than by reading the test. `tests/_isolate_db.py` exists
# for exactly this and its own docstring says so -- "the runner covers the
# suite, this module covers the other way tests get run". This file was written
# before that helper and never picked it up.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db                              # noqa: E402
_isolate_db.isolate()

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


from core import agent_loop as al               # noqa: E402
from core import sensor_health as sh            # noqa: E402
from core import tool_registry as tr            # noqa: E402
from tools import process_monitor as pm         # noqa: E402


print("\n[1] the tool exists, is reachable, and is not gated")
names = [t["name"] for t in tr.TOOL_MANIFEST]
check("query_processes is in the manifest", "query_processes" in names, True)
check("it needs no approval, because it is what makes a kill safe",
      tr.requires_permission("query_processes", {}), False)
check("it declares what it rests on, or execute_tool would refuse it",
      sh.depends_on("query_processes"), ("cap:process_details",))
check("it is read only", tr.tool_writes("query_processes"), False)


print("\n[2] it actually answers, on this machine, right now")
me_pid = __import__("os").getpid()
one = pm.list_processes(pid=me_pid)
check("a pid comes back as one process", one["count"], 1)
row = one["processes"][0]
check("with a name", bool(row["name"]), True)
check("and a parent", isinstance(row["parent_pid"], int), True)
check("and an owner", bool(row["username"]), True)
check("and the command line that says which one it is",
      bool(row["cmdline"]), True)

gone = pm.list_processes(pid=999999)
check("a pid that is not running comes back empty", gone["count"], 0)
# AN EMPTY ANSWER IS NOT "IT IS FINE". Same rule as every other sensor here.
check("and says what empty means",
      "No process with PID" in gone["note"] and "Do not treat this" in gone["note"],
      True)

many = pm.list_processes(limit=3)
check("a listing is capped", len(many["processes"]) <= 3, True)
# 2026-09-13: this used to check for "do not read the list as complete", and
# the note said "Capped at 3" with no second number. A cap you cannot see the
# size of is not much better than no answer, so it names both now.
check("and says it is not everything",
      "NOT everything that is running" in many["note"], True)
check("and says how many there really are",
      f"3 of {many['running_total']}" in many["note"], True)
check("and running_total is the real count, not the capped one",
      many["running_total"] > 3, True)


print("\n[3] the card says WHAT is being killed, not just a number")
# This is the half of the fix a person actually sees.
params = {"pid": me_pid, "reason": "the operator asked"}
card = al._build_permission_card("kill_process", params, "call_1")
check("the card names the process",
      pm.describe_process(me_pid)["name"] in card["action"], True)
check("and still shows the pid", str(me_pid) in card["action"], True)
check("the name is pinned onto the call for the kill to check later",
      params.get("expected_name"), pm.describe_process(me_pid)["name"])

# A pid that does not exist must not produce a confident looking card.
ghost = {"pid": 999999, "reason": "x"}
card = al._build_permission_card("kill_process", ghost, "call_2")
check("an unidentifiable pid says so on the card",
      "could not read what that process is" in card["action"], True)
check("and pins no name, so the kill is not checked against a guess",
      "expected_name" in ghost, False)

# THE KILL ITSELF, RUN FOR REAL, against a process we started on purpose.
#
# Not a source check. The last four red tests in this suite were all
# assertions on exact lines of source, see TODO 50, and this is the one
# behaviour where being wrong means ending somebody else's process.
import subprocess                               # noqa: E402
import time                                     # noqa: E402
# CONVERTED 2026-09-21. This used to import `tools.remediation` -- the Windows
# class, which moved OUT of this tree with the L5 pass -- and construct it with
# `Remediation(session_id=...)`. On this platform the kill guard lives in
# `adapters.LinuxRemediation`, which is the object `main.py` puts in the module
# table under the "remediation" role and what `tool_registry.execute_tool`
# dispatches to. THE ASSERTIONS ARE UNCHANGED: the same refusal, the same
# reason sentence, and the same real kill of a process this file starts.
from adapters import LinuxRemediation, _name_matches_pin as remediation_pin

victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
time.sleep(0.4)
try:
    rem = LinuxRemediation(session_id="test")
    out = rem.kill_process(victim.pid, reason="testing the guard",
                           expected_name="definitely-not-this.exe")
    check("a pid that is not what the card said is refused",
          out.get("refused"), True)
    check("and nothing was killed", victim.poll(), None)
    check("the refusal explains the recycled pid, not just 'no'",
          "reused between the approval" in out.get("error", ""), True)

    # And the ordinary path still works: the right name kills it.
    live = pm.describe_process(victim.pid)["name"]
    out = rem.kill_process(victim.pid, reason="testing the guard",
                           expected_name=live)
    time.sleep(0.4)
    check("the right name still kills", out.get("success"), True)
    check("and the process really went", victim.poll() is not None, True)
    # Found writing this test: the kill used to be reported as a FAILURE when
    # the finding could not be written, on a machine with no database. The
    # process was already dead by then, and "it did not work" is the answer
    # most likely to make somebody try again on a recycled pid.
    #
    # REPOINTED 2026-09-23, and the assertion it carried had gone stale rather
    # than been broken by anything here. It read:
    #
    #     "NOT written" in note or note is None
    #
    # which was true when `note` could only ever be the writing-failure
    # sentence. The L2 work gave a SUCCESSFUL kill a note of its own -- what
    # unit the process was part of and whether a signal holds -- so a note is
    # now the NORMAL case and that check fails on a working kill. The
    # invariant underneath it is what gets asserted instead, and it is the one
    # that was ever meant: a real kill is never reported as a failure, and any
    # note that comes back is a STATEMENT rather than an error. The refusal
    # fields are asserted absent as well, because that is what "not a failure"
    # cashes out to for a caller.
    note = out.get("note") or ""
    check("bookkeeping cannot turn a real kill into a failure",
          bool(out.get("success")) and not out.get("refused")
          and out.get("error") is None, True)
    check("and a note on a successful kill is an explanation, not an error",
          "NOT written" not in note or "could not record it" in note, True)
    check("and the L2 unit facts travelled with the success",
          (out.get("systemd") or {}).get("verdict") in
          ("not_in_a_unit", "supervised_no_restart", "unknown"), True)
finally:
    if victim.poll() is None:
        victim.kill()

reg_src = (ROOT / "core" / "tool_registry.py").read_text(encoding="utf-8")
check("and the dispatch passes it through",
      'expected_name=params.get("expected_name")' in reg_src, True)


print("\n[4] a described card is not a card")
check("an announcement is caught",
      al._claims_a_card("Raising the approval card now."), True)
check("so is the one it used when it gave up pretending",
      al._claims_a_card("The approval card is up now, approve or deny."), True)
check("an honest conditional is NOT caught",
      al._claims_a_card("I will raise a card once you tell me the name."), False)
check("and neither is ordinary talk about cards",
      al._claims_a_card("The card is the operator's gate, not mine."), False)

loop_src = (ROOT / "core" / "agent_loop.py").read_text(encoding="utf-8")
check("the app says so on screen rather than trusting the claim",
      "NO CARD WAS RAISED" in loop_src, True)
check("counted from the cards actually yielded",
      "cards_raised += 1" in loop_src, True)
check("the prompt says announcing is not sending",
      "SAYING YOU ARE SENDING A CARD IS NOT SENDING ONE" in loop_src, True)
check("and tells it a conversation means no card is pending",
      "no card of yours is open" in loop_src, True)
check("the prompt points at the new lookup",
      "query_processes reads the live process table" in loop_src, True)
check("and says the operator naming a process is evidence",
      "a vantage point you do not have" in loop_src, True)

kill_desc = [t for t in tr.TOOL_MANIFEST if t["name"] == "kill_process"][0]["description"]
check("the tool text no longer demands a threat before acting",
      "THE OPERATOR ASKING IS A GOOD ENOUGH REASON" in kill_desc, True)
check("and it sends people to the lookup first",
      "CALL query_processes FIRST" in kill_desc, True)


print("\n[5] a claimed kill that never happened")
# TODO 67, the same evening. The model wrote "PID 31612 killed" for a process
# that was still running, twice, and the owner caught it rather than the app. A
# card that never appears is obvious, you wait for a button. A kill that never
# happened looks finished.
al._killed_pids.clear()
check("a kill claimed for a pid this app never killed is caught",
      al._unbacked_kill_claims("PID 31612 (LM Studio.exe crashpad-handler) killed"),
      [31612])
check("several at once",
      al._unbacked_kill_claims("All four killed: 24112, 6104, 16100, 12760"),
      [24112, 6104, 16100, 12760])

# The recap case, which is why this looks at the SESSION and not the turn.
al._remember_kill("kill_process", {"result": {"success": True, "pid": 22140}})
check("a real kill is remembered", 22140 in al._killed_pids, True)
check("so an honest recap of it does not trip",
      al._unbacked_kill_claims("22140 renderer, killed earlier"), [])
check("while a false one beside it still does",
      al._unbacked_kill_claims("22140 killed, and 420 killed"), [420])

# Sentences about what a kill WOULD do are not claims that it happened.
check("a plan is not a claim",
      al._unbacked_kill_claims("Killing 12760 will close the whole app"), [])
check("neither is raising a card",
      al._unbacked_kill_claims("Sending the kill card for 31612 now"), [])
check("nor a lookup that found nothing",
      al._unbacked_kill_claims("I checked 1610 and it is not running"), [])

# A kill that returned failure must not count as a kill.
al._killed_pids.clear()
al._remember_kill("kill_process", {"result": {"success": False, "pid": 999}})
check("a failed kill is not remembered as one", 999 in al._killed_pids, False)

check("and the app says so on screen",
      "UNCONFIRMED" in loop_src and "no record of killing" in loop_src, True)


print("\n[6] the packet filter that was missing")
from core import memory_engine as me            # noqa: E402
import inspect                                  # noqa: E402
sig = inspect.signature(me.query_packets).parameters
check("query_packets can filter by pid", "process_pid" in sig, True)
check("and by process name", "process_name" in sig, True)
props = [t for t in tr.TOOL_MANIFEST
         if t["name"] == "query_packets"][0]["input_schema"]["properties"]
check("the model is told it can", "process_pid" in props, True)
check("the wrapper passes it through rather than dropping it",
      '"process_pid", "process_name",' in reg_src, True)
check("and the null warning is still the loudest thing about it",
      "NOT ATTRIBUTED" in props["process_pid"]["description"].upper()
      or "does NOT mean" in props["process_pid"]["description"], True)


print("\n[7] the pinned name survives query_processes becoming a fenced tool")
# 2026-09-13. query_processes was added to sanitize.UNTRUSTED_TOOLS, so the
# name the model reads has been scrubbed. The model pins that scrubbed name
# onto kill_process, and the pin compare leaves a model-supplied name alone.
#
# THE FAILURE CASE FIRST, because it is the whole reason this exists. A
# process whose real name carries an invisible character is the Trojan Source
# disguise, so it is the process most worth ending. Under a plain string
# compare the pin would not match, the kill would be refused, and the refusal
# would say the pid had been reused, which nothing here knows.
# CONVERTED 2026-09-21: the compare lives in adapters._name_matches_pin on
# this platform, and `remediation_pin` is that function. THE COST OF THIS
# DEFECT WAS MEASURED, not read: this tree's compare was a plain lowered
# string equality, the file could not run because it imported the moved
# Windows module, and so every check below sat dormant while the live branch
# refused to kill exactly the process it was written to protect.
disguised = "svc​host.exe"          # a zero-width space in the middle
from core import sanitize as _sz                # noqa: E402
pinned = _sz.scrub_string(disguised)            # what the model actually sees

check("the fence really does change this name", pinned != disguised, True)
check("a plain compare would have refused the kill",
      disguised.lower() == pinned.lower(), False)
check("the pin accepts it, because the pid did not change",
      remediation_pin(disguised, pinned), True)

# A right-to-left override, the other shape of the same trick.
rtl = "cod‮exe.doc"
check("and the same for a bidi override",
      remediation_pin(rtl, _sz.scrub_string(rtl)), True)

# NOW THE THING THE PIN IS FOR. A genuinely different process must still be
# refused, or this change would have traded a rare false refusal for a kill
# landing on the wrong process, which is far worse.
check("a recycled pid is still refused",
      remediation_pin("notepad.exe", "LM Studio.exe"), False)
check("a near miss is still a miss",
      remediation_pin("svchost.exe", "svchosts.exe"), False)
check("an empty live name never passes",
      remediation_pin("", "svchost.exe"), False)
check("a missing live name never passes",
      remediation_pin(None, "svchost.exe"), False)
check("a missing pin never passes here",
      remediation_pin("svchost.exe", None), False)

# The ordinary cases, unchanged by any of this.
check("the same name matches", remediation_pin(
    "LM Studio.exe", "LM Studio.exe"), True)
check("case does not matter on this platform either",
      remediation_pin("LM STUDIO.EXE", "lm studio.exe"), True)

# And the call site uses the helper rather than its own compare, so the two
# cannot drift apart later. CONVERTED 2026-09-21: the call site is in
# adapters.py here (the Windows module held it in tools/remediation.py), and
# the assertion is on the same two facts: the helper is asked, and the old
# inline compare is gone.
#
# UPDATED 2026-09-24 (REM-6b). The call site now asks _identity_matches_pin,
# which ASKS THIS HELPER FIRST and then the identity's other names. The
# assertion is restated rather than deleted, because the rule it is checking
# is unchanged — the helper is the one doing the comparing, and the old inline
# compare is still gone. What was added is that a failure of the single name
# is no longer the end of the question: psutil's name comes from basename
#(argv[0]) once /proc/comm is at the kernel's 15-character cap (measured), so
# a comparison that stops there is a comparison against text the process
# chooses.
rem_src = (ROOT / "adapters.py").read_text(encoding="utf-8")
check("kill_process asks the helper",
      "_name_matches_pin(ident.get(\"reported_name\"), pinned)" in rem_src, True)
check("and through the identity, not the single name",
      "_identity_matches_pin(ident, expected_name)" in rem_src, True)
check("and the old inline compare is gone",
      "name.lower() != str(expected_name).lower()" in rem_src, False)


print("\n[8] the process list never loses a process quietly")
# 2026-09-13. MEASURED on a real machine before any of this was written: a
# 200 row answer weighed 112,520 characters against a 60,000 result budget,
# so 124 processes were cut off the end on every single call and the list
# still read as complete. The tool that answers "what is running" could see
# about a quarter of it.
#
# THE FAILURE CASES COME FIRST HERE, because every one of them is a way for a
# process to disappear without anybody being told.
import json as _json                              # noqa: E402


def _row(pid, name, cmd_len):
    return {"pid": pid, "name": name, "exe": r"C:\Windows\System32\%s" % name,
            "parent_pid": 4, "username": "user",
            "cmdline": "c:\\x.exe " + ("a" * max(0, cmd_len - 9)),
            "started": "2026-09-13T10:00:00"}


# A machine shaped like the owner's: mostly tiny, a tail of browser renderers.
real_shape = ([_row(i, f"p{i}.exe", 80) for i in range(249)] +
              [_row(900 + i, "opera.exe", 2700) for i in range(37)] +
              [_row(990, "claude.exe", 6351), _row(991, "claude.exe", 5257)])

BUDGET = pm._list_budget()

# FAILURE ONE: the old behaviour. Everything at full length does not fit.
check("the real shape genuinely does not fit at full length",
      pm._weigh(real_shape) > BUDGET, True)

fitted, note = pm._fit_process_rows(real_shape, BUDGET)
check("but every single process survives", len(fitted), len(real_shape))
check("and it fits now", pm._weigh(fitted) <= BUDGET, True)
check("and it says what it did", bool(note), True)
check("and the note says nothing was left out",
      "Nothing was left out" in (note or ""), True)

# FAILURE TWO: a shortened command line that reads like a whole one. The
# longest row on the owner's machine was a claude.exe renderer at 6,351 characters.
original = [r for r in real_shape if r["pid"] == 990][0]["cmdline"]
short = [r for r in fitted if r["pid"] == 990][0]["cmdline"]
check("the long one really was shortened", len(short) < len(original), True)
check("and it says so on the row itself", "ask by pid]" in short, True)

# The number has to be RIGHT, not merely present. What is kept plus what it
# claims is missing must add back up to the original, or the marker is just
# a reassuring noise.
kept_text, _, claim = short.partition(" ...[+")
check("and the count it gives is exact",
      len(kept_text) + int(claim.split(" ")[0]), len(original))

check("a command line that was already short is untouched",
      [r for r in fitted if r["pid"] == 0][0]["cmdline"],
      real_shape[0]["cmdline"])

# FAILURE THREE: rows that truly cannot fit must be COUNTED, not dropped off
# the end by the serialiser.
huge = [_row(i, f"big{i}.exe", 4000) for i in range(400)]
kept, hnote = pm._fit_process_rows(huge, BUDGET)
check("when rows really must go, some are kept", len(kept) > 0, True)
check("and fewer than we started with", len(kept) < len(huge), True)
check("and what is kept fits", pm._weigh(kept) <= BUDGET, True)
check("the note says the list is incomplete",
      "THIS LIST IS INCOMPLETE" in (hnote or ""), True)
check("and gives both numbers",
      f"{len(kept)} of {len(huge)}" in (hnote or ""), True)
check("and says which ones are missing",
      "end of the list in name order" in (hnote or ""), True)
check("and says how to reach them", "name=" in (hnote or ""), True)

# THE QUIET CASES. An answer that already fits must not be touched at all,
# or every small lookup grows a note nobody needs and stops being readable.
small = [_row(i, f"s{i}.exe", 60) for i in range(5)]
kept2, note2 = pm._fit_process_rows(small, BUDGET)
check("a small answer is unchanged", kept2, small)
check("and carries no note", note2, None)
check("an empty answer is not an error", pm._fit_process_rows([], BUDGET),
      ([], None))

# The budget is read from sanitize, not copied, so one number governs.
from core.sanitize import MAX_RESULT_LEN                      # noqa: E402
check("the budget comes from MAX_RESULT_LEN", BUDGET < MAX_RESULT_LEN, True)
check("with headroom for the envelope and the fence",
      MAX_RESULT_LEN - BUDGET, pm.RESULT_HEADROOM)

# And the live call on this machine, which is the only part that proves the
# wiring rather than the arithmetic.
live = pm.list_processes(limit=200)
if live.get("available"):
    payload = _json.dumps({"result": live, "error": None, "untrusted": True})
    check("a real call now fits inside the result budget",
          len(payload) <= MAX_RESULT_LEN, True)
    check("and it reports how many are really running",
          isinstance(live.get("running_total"), int), True)
    check("and running_total is at least what it returned",
          live["running_total"] >= live["count"], True)
    if live["running_total"] > live["count"]:
        check("and when it held some back it says both numbers",
              f"{live['count']} of {live['running_total']}" in live.get("note", ""),
              True)
else:
    print("  SKIP  psutil is not available here, so the live call says "
          "nothing either way. That is not a pass.")


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
