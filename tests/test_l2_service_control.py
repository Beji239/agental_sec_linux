"""
tests/test_l2_service_control.py, L2. The wiring, not the module.

test_systemd_units.py proves what a unit question answers. This file proves the
CALL PATH around it, because a sensor or verb that is right in its own file and
not reachable from the app is the failure this project has already paid for
twice (the three prediction tools with no DEPENDS entry, and the 113 detectors
whose findings were refused by an unregistered id).

FAILURE CASES FIRST, and each one is a way the kill theatre could reappear
through the wiring rather than through the logic:

  [1]  The three-way registration. A tool in the manifest with no dispatch is a
       500 on every call; a verb with no DEPENDS entry raises UnregisteredTool
       inside execute_tool; a tool nobody classified as read-only is counted as
       a write. Checked by CALLING execute_tool, not by reading the source.
  [2]  THE GATE. stop_service must require approval, and query_services must
       not: one stops a service, the other lists what is there.
  [3]  An ordinary kill still works, and now says what the process was part of.
  [4]  REM-1008 is registered and is an action record, so the Detections page
       does not claim this app can "detect" a service stop.
  [5]  The card says what a stop means, and a kill on a SUPERVISED process
       carries the warning BEFORE the person presses approve.
  [6]  The queue accepts stop_service and refuses it without a reason, like
       every other filable verb.
  [7]  THE L2 RESIDUALS, 2026-09-23. The card the ACTION QUEUE renders through
       carries the supervised-process warning too (it did not: ac.describe said
       "Kill process PID N" with no warning while the chat card carried one),
       and query_services is reachable from the duty loop (it was not, so the
       loop could file stop_service but not look up what units exist).

NOTHING OF THE OWNER'S IS STOPPED BY THIS FILE. The only real stop is of a
transient unit this file creates and removes, in the user manager. Every system
unit named is read, never touched.

Run it directly: python tests/test_l2_service_control.py
"""
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import actions as ac                        # noqa: E402
from core import agent_loop as al                     # noqa: E402
from core import detections as det                    # noqa: E402
from core import duty as du                           # noqa: E402
from core import memory_engine as me                  # noqa: E402
from core import sensor_health as sh                  # noqa: E402
from core import tool_registry as tr                  # noqa: E402
from core import sensors as sn                        # noqa: E402
from tools import systemd_units as sd                 # noqa: E402

sn.register_local()
fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def ok(label, condition):
    check(label, bool(condition), True)


def has_user_manager() -> bool:
    rc, out, err = sd._run(["systemctl", "--user", "is-system-running"])
    return (out + err).strip() in ("running", "degraded", "maintenance") or rc == 0


print("\n[1] THE THREE-WAY REGISTRATION, PROVED BY CALLING IT")

names = {t["name"] for t in tr.TOOL_MANIFEST}
for tool in ("stop_service", "query_services"):
    ok(f"{tool} is in the model-facing manifest", tool in names)

for tool in ("stop_service", "query_services"):
    try:
        deps = sh.depends_on(tool)
        ok(f"{tool} declares its dependencies ({deps})", True)
    except Exception as e:
        check(f"{tool} declares its dependencies", f"{type(e).__name__}: {e}",
              "ok")

ok("query_services is classified as a READ",
   tr.tool_writes("query_services") is False)
ok("stop_service is classified as a WRITE (unclassified means yes)",
   tr.tool_writes("stop_service") is True)

# THE READ PATH, CALLED. It needs no module loaded, and that is deliberate:
# reading the unit list is not a privileged act and answering "unavailable"
# because remediation did not load would be the OFF-versus-BROKEN mistake.
tr.init_registry("l2-wiring-test", {})
out = tr.execute_tool("query_services", {"limit": 5})
check("query_services dispatches with no module loaded", out["error"], None)
ok("  and returns units", "units" in (out["result"] or {}))
ok("  and says what the whole list holds",
   (out["result"] or {}).get("total", 0) > 0)

# THE WRITE PATH with no module: a refusal with a sentence, not a 500.
out = tr.execute_tool("stop_service", {"unit": "ssh.service", "reason": "x"})
ok("stop_service without the remediation module refuses in words",
   out["error"] and "unavailable" in out["error"].lower())


print("\n[2] THE GATE: ONE STOPS A SERVICE, THE OTHER ONLY LOOKS")

ok("stop_service requires approval",
   tr.requires_permission("stop_service", {"unit": "ssh.service"}))
ok("query_services needs NO approval",
   tr.requires_permission("query_services", {}) is False)
ok("stop_service is in the static gated set",
   "stop_service" in tr.PERMISSION_GATED)


print("\n[3] THE ACTION RECORD IS AN ACTION RECORD")

entry = det.get("REM-1008")
check("REM-1008 is registered", entry.did, "REM-1008")
check("  and it is an action record, not a detection", entry.kind,
      "action_record")
check("  and its source is the remediation app", entry.source, "remediation")
ok("  and a real detection list does not include it",
   "REM-1008" not in {d["detection_id"] for d in det.real_detections()})


print("\n[4] AN ORDINARY KILL STILL WORKS AND NOW SAYS WHAT IT WAS PART OF")

import adapters                                        # noqa: E402

rem = adapters.LinuxRemediation("l2-wiring-test")
tr.init_registry("l2-wiring-test", {"remediation": rem})

victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
time.sleep(0.5)
try:
    r = rem.kill_process(victim.pid, reason="testing the ordinary path")
    check("an ordinary process still dies", r.get("success"), True)
    facts = r.get("systemd") or {}
    ok("  and the answer carries what unit it was part of",
       facts.get("verdict") in ("not_in_a_unit", "supervised_no_restart",
                                "supervised", "unknown"))
    ok("  and a verdict is named rather than an empty dict", bool(facts))
finally:
    if victim.poll() is None:
        victim.kill()


print("\n[5] KILL THEATRE IS REFUSED THROUGH THE ADAPTER")

if not has_user_manager():
    print("  SKIP  no user manager here, so no supervised unit can be made. "
          "THIS IS A SKIP AND NOT A PASS.")
else:
    name = f"agental_l2_wiring_{__import__('os').getpid()}"
    subprocess.run(["systemctl", "--user", "reset-failed", f"{name}.service"],
                   capture_output=True)
    subprocess.run(["systemd-run", "--user", "--unit", name, "--collect",
                    "--property=Restart=always", "sleep", "120"],
                   capture_output=True)
    time.sleep(1.3)
    pid = int(subprocess.run(
        ["systemctl", "--user", "show", f"{name}.service", "-p", "MainPID",
         "--value"], capture_output=True, text=True).stdout.strip())

    r = rem.kill_process(pid, reason="checking the theatre guard")
    check("THE KILL IS REFUSED", r.get("refused"), True)
    check("  and it says so with the flag a caller can branch on",
          r.get("supervised"), True)
    check("  and it names the unit", r.get("unit"), f"{name}.service")
    ok("  and the sentence names the tool that would work",
       "stop_service" in (r.get("error") or ""))
    ok("  AND NOTHING WAS KILLED",
       subprocess.run(["ps", "-p", str(pid), "-o", "pid="],
                      capture_output=True, text=True).stdout.strip() != "")

    # THE REAL STOP, through the adapter, of a unit this file made.
    s = rem.stop_service(f"{name}.service", reason="L2 wiring test")
    check("stop_service stops it", s.get("success"), True)
    check("  and reports that it verified rather than trusting the exit code",
          s.get("verified"), True)

    rows = [f for f in me.query_findings(limit=50)
            if f.get("detection_id") == "REM-1008"]
    ok("  and the action is recorded under REM-1008", len(rows) >= 1)
    ok("  with the unit as the entity",
       any(f.get("entity_value") == f"{name}.service" for f in rows))

    # THE SELF-PROTECTION, which is the abuse case for a denial verb.
    for protected in ("agentalsec-anything.service",
                      "systemd-journald.service"):
        rr = rem.stop_service(protected, reason="probe")
        check(f"stopping {protected} is refused", rr.get("refused"), True)
        ok("    and nothing was run", rr.get("ran") in (False, None))

    # A name that is not a unit at all.
    rr = rem.stop_service("definitely-not-a-unit-xyz.service", reason="probe")
    check("a name in neither manager is refused", rr.get("refused"), True)
    ok("  and it says to look the name up", "query_services" in
       (rr.get("error") or ""))


print("\n[6] THE CARD AND THE QUEUE")

line = tr.permission_summary("stop_service",
                             {"unit": "ssh.service", "reason": "test"})
ok("the card names the unit", "ssh.service" in line)
ok("  and says a stop does not restart", "does not restart" in line)
ok("  and says nothing here starts it again",
   "starts it again" in line or "starting it back up" in line)

ok("stop_service is filable for the duty loop",
   "stop_service" in ac.queueable_verbs())

# A REASON IS REQUIRED, like every filable verb.
try:
    ac.write_request("stop_service", {"unit": "x.service"}, "",
                     session_id="l2-wiring-test")
    check("a filable request with no reason is refused", "accepted", "refused")
except ac.BadActionRequest:
    check("a filable request with no reason is refused", "refused", "refused")

# And with one, it files and does NOT run.
filed = ac.write_request("stop_service", {"unit": "some.service"},
                         "the duty loop wants this stopped",
                         session_id="l2-wiring-test")
check("it files", filed.get("filed"), True)
check("  and nothing ran", filed.get("state"), "pending")
ok("  and the receipt says so in words",
   "NOTHING HAS RUN" in (filed.get("note") or ""))

# The card for a queued request renders the unit, not a bare verb.
card = ac.card_for({"id": 1, "verb": "stop_service",
                    "params": {"unit": "some.service"},
                    "reason": "why", "state": "pending",
                    "created_at": "2026-09-22 00:00:00",
                    "proposed_by": "model"})
ok("the queued card names the unit", "some.service" in card["action"])

# A kill card on a SUPERVISED process warns BEFORE the approval.
sup_params = {"pid": 1234, "_process": {"name": "sshd", "username": "root"},
              "_unit": {"verdict": "supervised", "unit": "ssh.service"}}
kill_line = al._kill_card_line(sup_params)
ok("the kill card on a supervised process carries the warning",
   "WILL NOT" in kill_line.upper() or "RESTART" in kill_line.upper())
ok("  and names the unit that owns it", "ssh.service" in kill_line)
ok("  and names the tool that would work",
   "stop_service" in kill_line)

ordinary = {"pid": 1234, "_process": {"name": "myprog"},
            "_unit": {"verdict": "not_in_a_unit", "unit": None}}
plain = al._kill_card_line(ordinary)
ok("an ordinary kill card stays a plain sentence",
   "WARNING" not in plain and "RESTART" not in plain)


print("\n[7] THE PROMPT TELLS THE MODEL THE RULE")

kill_desc = [t for t in tr.TOOL_MANIFEST
             if t["name"] == "kill_process"][0]["description"]
ok("the kill tool says it can be refused for a supervised process",
   "REFUSED IF THE PROCESS BELONGS TO A SYSTEMD UNIT" in kill_desc)
ok("  and it points at stop_service", "stop_service" in kill_desc)

stop_desc = [t for t in tr.TOOL_MANIFEST
             if t["name"] == "stop_service"][0]["description"]
ok("stop_service says to use it rather than killing the process",
   "RATHER THAN KILLING ITS PROCESS" in stop_desc)
ok("  and it refuses a bare unit name on purpose",
   "A bare 'ssh' is refused" in stop_desc)


print("\n[8] THE L2 RESIDUALS, 2026-09-23: THE QUEUE CARD AND THE DUTY LOOP")
#
# BOTH WERE MEASURED BROKEN BEFORE THEY WERE FIXED.
#
# (a) THE QUEUED KILL CARD LOST THE UNIT FACT. ac.describe() is what the Action
#     Queue renders through -- the card somebody reads at breakfast about a
#     decision proposed at 3am -- and it said "Kill process PID 1365" with no
#     warning at all, while agent_loop's chat card carried one. Two causes,
#     both real: _validated_params NARROWS the params to what the verb declares
#     so agent_loop's `_unit` pin is gone by then (correctly -- a fact captured
#     at 3am describes a pid that may have changed hands), and nothing in the
#     queue path asked the question.
#
# (b) query_services WAS UNREACHABLE FROM THE DUTY LOOP. The loop may file
#     stop_service, but it could not look up what units exist, so it could only
#     propose a stop against a name it had to invent.

# (a) the queued card, on a REAL supervised unit this file creates.
if not has_user_manager():
    print("  SKIP  no user manager here, so no supervised card can be made. "
          "THIS IS A SKIP AND NOT A PASS.")
else:
    name = f"agental_l2_queue_{__import__('os').getpid()}"
    subprocess.run(["systemctl", "--user", "reset-failed", f"{name}.service"],
                   capture_output=True)
    subprocess.run(["systemd-run", "--user", "--unit", name, "--collect",
                    "--property=Restart=always", "sleep", "120"],
                   capture_output=True)
    time.sleep(1.3)
    sup_pid = int(subprocess.run(
        ["systemctl", "--user", "show", f"{name}.service", "-p", "MainPID",
         "--value"], capture_output=True, text=True).stdout.strip())

    line = ac.describe("kill_process", {"pid": sup_pid})
    ok("the QUEUE card for a supervised pid carries the warning",
       "RESTART" in line.upper())
    ok("  and names the unit", f"{name}.service" in line)
    ok("  and names stop_service as the tool that works",
       "stop_service" in line)

    # THE NEGATIVE CONTROL: an ordinary process's card must not carry the
    # ALARM. It may still say the truth about what it is part of -- a process
    # started from this terminal genuinely lives in a vte-spawn scope, and the
    # fact that a signal ends it is worth stating -- so what is asserted is the
    # absence of the WARNING, not the absence of the word "restart". The first
    # version of this check tested the word and failed on the correct sentence
    # "which does not restart it, so this kill holds", which is the same class
    # of mistake as a check reading the artifact with the wrong reader.
    victim = subprocess.Popen([sys.executable, "-c",
                               "import time; time.sleep(30)"])
    time.sleep(0.4)
    try:
        plain = ac.describe("kill_process", {"pid": victim.pid})
        ok("an ordinary pid's card carries NO alarm", "WARNING" not in plain.upper())
        ok("  and it does not claim the kill will be undone",
           "WILL NOT STOP" not in plain.upper())
    finally:
        if victim.poll() is None:
            victim.kill()

    # A pid that is not running: the card must still render, saying nothing
    # about a unit it could not read.
    gone = ac.describe("kill_process", {"pid": 2 ** 31 - 1})
    ok("a pid that is not running still renders a card", bool(gone))
    ok("  and it invents nothing about a unit", "WARNING" not in gone.upper())

    subprocess.run(["systemctl", "--user", "stop", f"{name}.service"],
                   capture_output=True)
    subprocess.run(["systemctl", "--user", "reset-failed", f"{name}.service"],
                   capture_output=True)

# The missing pid is still a missing SUBJECT, not a quiet '?'.
bad = ac.describe("kill_process", {})
ok("a kill card with no pid says so in words",
   "CANNOT TELL YOU" in bad)
ok("  and it does not mention a unit it never looked up",
   "WARNING" not in bad.upper())

# THE TWO CARD BUILDERS RENDER THE SAME SENTENCES. One implementation, two
# sources of facts: the chat card renders a pinned reading, the queue card asks
# live. If they ever disagree, the operator is told two things about one pid.
sup = {"verdict": "supervised", "unit": "ssh.service"}
ok("the shared sentence exists", bool(ac.unit_warning_line(sup)))
ok("  and the chat card renders it",
   ac.unit_warning_line(sup) in al._kill_card_line(
       {"pid": 1, "_process": {"name": "sshd"}, "_unit": sup}))
ok("an empty verdict renders nothing rather than a stray full stop",
   ac.unit_warning_line({}) == "")
ok("and a non-dict does not raise", ac.unit_warning_line(None) == "")

# (b) the duty loop's allowlist.
allow = set(du._tool_allowlist())
ok("the duty loop can read the service list", "query_services" in allow)
ok("  and it still CANNOT stop one directly (it files instead)",
   "stop_service" not in allow)
# THIS CHECK USED TO ASK `PERMISSION_GATED` AND THAT WAS THE WRONG QUESTION
# AFTER 2026-09-24: scan_network moved into requires_permission()'s conditional
# branch, so it is a member of neither set — gated on a foreign range, ungated
# on this host's own network — while the set still contains it. What the check
# is FOR is that no tool the LOOP can reach would pause for approval mid-run, so
# it asks the function agent_loop actually calls, with the loop's own arguments.
gated_in_allow = [n for n in ("kill_process", "stop_service", "block_port",
                              "block_device", "quarantine_file",
                              "unblock_device", "restore_file",
                              "dismiss_entity", "run_port_scan",
                              "scan_network")
                  if n in allow and tr.requires_permission(n)]
ok("no tool that would pause for approval is in the unattended allowlist",
   not gated_in_allow)
ok("  (and run_port_scan still IS gated when aimed off this LAN, so the "
   "check above is not vacuous)",
   tr.requires_permission("run_port_scan", {"target_host": "203.0.113.7"}))


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
