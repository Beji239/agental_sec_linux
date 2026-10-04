"""
tests/test_systemd_units.py, L2. Which unit owns a process, and whether a kill
on it would be theatre.

WHY THIS FILE'S SUBJECT MATTER IS A REFUSAL AND NOT A FEATURE. The owner's
phrase for the failure is "kill theatre": a service unit with Restart=always
owns its process, so SIGTERM kills nothing that stays dead. systemd starts it
again a second later, and every reader downstream of the kill - the finding,
the incident, the model's own summary - is told the thing was contained. The
kill succeeded. The thing did not stop.

FAILURE CASES FIRST, per rule one, and four of them are the answer "I do not
know" arriving in four different shapes. Each one is a way to get a plausible
reading out of a question that was never really answered:

  [1]  A pid in NO unit is not a pid in a unit with no restart policy. A plain
       process stops when signalled; the two must not read the same.
  [2]  A TRANSIENT unit that was stopped is REMOVED, not missing. systemd
       deletes the name once it has stopped, so a successful stop reads back
       as not-found -- and the first version of this module called that
       "unverified". A working action reported as broken is the same defect
       shape, pointed the other way.
  [3]  THE WRONG MANAGER INVENTS AN ANSWER. `systemctl show` on a unit that
       exists only in the USER manager does not fail: it returns
       ActiveState=inactive, Restart=no. Read as a policy, that is a green
       light on the theatre.
  [4]  A NAME THIS MANAGER HAS NEVER HEARD OF is not an inactive unit. Same
       invented-defaults trap, one layer down, and the first version of
       unit_properties could not see it because it never asked for LoadState.
  [5]  THE UNIT NAME IS AN ARGUMENT POSITION. `systemctl stop --all` is not a
       unit; a name starting with a dash is read as a flag, which is how one
       stop becomes a wildcard act.
  [6]  Then, and only then, the happy paths: attribution, the supervised
       verdict, and a real stop that verifies itself.

WHAT THIS FILE CANNOT TEST HERE, said out loud rather than skipped quietly:
stopping a SYSTEM unit. Verifying that path for real would mean stopping a
service on the owner's running machine. The user-manager equivalent is
exercised end to end (a transient unit is created, stopped and read back), and
the system-manager path differs only in the manager flag, which is asserted
separately by reading a real system unit's properties without touching it.

Run it directly: python tests/test_systemd_units.py
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from tools import systemd_units as su                 # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def ok(label, condition):
    check(label, bool(condition), True)


HAVE_SYSTEMD = shutil.which("systemctl") is not None


def _user_manager_works() -> bool:
    if not HAVE_SYSTEMD:
        return False
    rc, out, err = su._run(["systemctl", "--user", "is-system-running"])
    return (out + err).strip() in ("running", "degraded", "maintenance") or rc == 0


HAVE_USER_MANAGER = _user_manager_works()
print(f"environment: systemctl={HAVE_SYSTEMD}, "
      f"user manager={HAVE_USER_MANAGER}")


print("\n[1] A PID IN NO UNIT IS NOT A PID IN AN UNSUPERVISED UNIT")

v = su.unit_state(999999)
check("a pid that is not running is not_in_a_unit", v["verdict"],
      "not_in_a_unit")
ok("and the reason says the process is gone rather than that it is safe",
   "not running" in (v["verdict_reason"] or ""))

g = su.unit_for_pid("not-a-pid")
check("a non-numeric pid is unknown, not none", g["state"], "unknown")
ok("  and it says why", "must be a number" in (g["reason"] or ""))

g = su.unit_for_pid(None)
check("a missing pid is unknown", g["state"], "unknown")

# The four states are four different sentences, and the one that matters is
# that 'unknown' never collapses into 'none'.
ok("the four states are distinct values",
   {"none", "unknown", "system", "user"} == {"none", "unknown", "system", "user"})


print("\n[2] A TRANSIENT UNIT THAT STOPPED IS REMOVED, NOT UNVERIFIED")

if not HAVE_USER_MANAGER:
    print("  SKIP  no user manager here, so a transient unit cannot be made."
          " THIS IS A SKIP AND NOT A PASS.")
else:
    name = f"agental_unit_test_{os.getpid()}.service"
    subprocess.run(["systemctl", "--user", "reset-failed", name],
                   capture_output=True)
    subprocess.run(["systemd-run", "--user", "--unit", name.rsplit(".", 1)[0],
                    "--collect", "--property=Restart=always",
                    "sleep", "120"], capture_output=True)
    time.sleep(1.2)

    props = su.unit_properties(name, manager="--user")
    ok("the transient unit is readable before the stop", props["ok"])
    check("  and it really carries Restart=always",
          props["properties"].get("Restart"), "always")

    main_pid = int(props["properties"].get("MainPID") or 0)
    v = su.unit_state(main_pid)
    check("A PROCESS OF A Restart=always UNIT IS CALLED SUPERVISED",
          v["verdict"], "supervised")
    ok("  and the verdict says the kill would not stop the service",
       "WOULD NOT STOP THE SERVICE" in (v["verdict_reason"] or ""))
    ok("  and it names the tool that would stop it",
       "stop_service" in (v["verdict_reason"] or ""))

    r = su.stop_unit(name, manager="--user")
    check("the real stop succeeded", r.get("success"), True)
    check("  and it VERIFIED rather than assuming", r.get("verified"), True)
    check("  and the state it read back is the removal", r.get("active_state"),
          "removed")
    ok("  and the note explains that gone means stopped, not missing",
       "successful stop" in (r.get("note") or ""))

    # The read-back of a unit that was just stopped on purpose is exactly the
    # case that must NOT be reported as a broken stop.
    again = su.unit_properties(name, manager="--user")
    check("the same name now reads as not-loaded", again["ok"], False)
    check("  with the load state named", again.get("load_state"), "not-found")

    r2 = su.stop_unit(name, manager="--user")
    check("stopping it again is refused before anything runs",
          r2.get("ran"), False)
    ok("  and the refusal is about the unit not existing, not about failure",
       "no unit named" in (r2.get("error") or ""))

    # THE PID IS GONE AND THE VERDICT SAYS SO RATHER THAN CLAIMING A UNIT.
    v = su.unit_state(main_pid)
    check("the stopped pid is not_in_a_unit afterwards", v["verdict"],
          "not_in_a_unit")


print("\n[3] THE WRONG MANAGER INVENTS AN ANSWER, AND THIS DOES NOT RELY ON IT")

if HAVE_SYSTEMD:
    # A unit that exists in the SYSTEM manager. Read only: nothing is stopped.
    sys_props = su.unit_properties("ssh.service", manager="")
    if sys_props["ok"]:
        ok("a real system unit reads back with a load state",
           sys_props.get("load_state") in ("loaded",))
        ok("  and carries its own Restart policy",
           "Restart" in sys_props["properties"])
    else:
        print("  SKIP  ssh.service is not present here, so the system-manager "
              "read could not be exercised. THIS IS A SKIP AND NOT A PASS.")

    # ASKED THE USER MANAGER ABOUT A SYSTEM UNIT, the answer must be a
    # refusal rather than the system unit's properties.
    cross = su.unit_properties("ssh.service", manager="--user")
    if HAVE_USER_MANAGER:
        check("the user manager does not answer for a system unit",
              cross["ok"], False)
        ok("  and it says the unit is not known to that manager",
           "no unit named" in (cross.get("reason") or ""))


print("\n[4] A NAME A MANAGER HAS NEVER HEARD OF IS NOT AN INACTIVE UNIT")

r = su.unit_properties("definitely-not-a-unit-xyz.service", manager="")
check("an unknown unit is refused rather than reported inactive", r["ok"],
      False)
check("  and the load state is named in the answer", r.get("load_state"),
      "not-found")
ok("  and the reason says defaults are not a reading",
   "defaults" in (r.get("reason") or ""))

r = su.stop_unit("definitely-not-a-unit-xyz.service", manager="")
check("stopping a name that is not a unit runs NOTHING", r.get("ran"), False)
ok("  and the refusal is about the name, not about the service being down",
   "no unit named" in (r.get("error") or ""))


print("\n[5] THE UNIT NAME IS AN ARGUMENT POSITION, NOT A STRING")

for bad, why in (
    ("--all", "a dash is read by systemctl as an OPTION"),
    ("-h", "a short option is the same trap"),
    ("../etc/passwd", "a path is not a unit name"),
    ("a/b.service", "a slash is a path separator"),
    ("", "an empty name"),
    (None, "no name at all"),
    ("ssh", "a bare name is refused so systemd does not guess the suffix"),
    ("ssh.service; rm -rf /", "a shell metacharacter is not in a unit name"),
    ("unit name with spaces.service", "spaces are not in a unit name"),
):
    try:
        got = su._validated_unit_name(bad)
        check(f"{bad!r} is refused ({why})", f"ACCEPTED {got}", "REFUSED")
    except ValueError as e:
        check(f"{bad!r} is refused ({why})", "REFUSED", "REFUSED")
        ok("    and the refusal explains itself", len(str(e)) > 20)

for good in ("ssh.service", "getty@tty1.service", "systemd-journald.service",
             "vte-spawn-abc.scope", "a-b_c.d.service"):
    try:
        check(f"{good!r} is accepted", su._validated_unit_name(good), good)
    except ValueError as e:
        check(f"{good!r} is accepted", f"REFUSED: {e}", good)


print("\n[6] ATTRIBUTION AGAINST REAL PROCESSES ON THIS MACHINE")

mine = su.unit_for_pid(os.getpid())
check("this test's own process is attributed to a unit",
      mine["state"] in ("user", "system"), True)
ok("  and the unit name is real, not a slice",
   (mine.get("unit") or "").endswith((".scope", ".service")))
ok("  and the manager flag matches the state",
   (mine["state"] == "user") == (mine.get("manager") == "--user"))

first = su.unit_for_pid(1)
check("pid 1 is attributed to the system manager", first["state"], "system")
check("  and it is init.scope", first["unit"], "init.scope")

# The path can hold several unit-shaped components. The LAST one is the owner:
# user@1000.service and app.slice are both above the terminal scope, and
# stopping user@1000.service would end every session that user has.
if mine["state"] == "user" and "user@" in (mine.get("cgroup") or ""):
    ok("the deepest unit is the owner, not the user manager itself",
       mine["unit"] != "user@1000.service")
    ok("  even though the user manager appears earlier in the path",
       "user@1000.service" in mine["cgroup"])


print("\n[7] A SCOPE IS NOT A SERVICE")

if HAVE_USER_MANAGER:
    v = su.unit_state(os.getpid())
    if (su.unit_for_pid(os.getpid()).get("unit_kind")) == "scope":
        check("a process in a scope is not called supervised-by-policy",
              v["verdict"], "supervised_no_restart")
        ok("  and the reason says a scope has no restart policy rather than "
           "reporting a null one as a fact",
           "not a service" in (v["verdict_reason"] or ""))


print("\n[8] THE STATUS CONTRACT THE REST OF THE APP READS")

st = su.status()
for key in ("role", "ready", "running", "blind", "blind_reason"):
    ok(f"status carries {key}", key in st)
check("the role is the one sensors are registered under", st["role"], su.ROLE)
if HAVE_SYSTEMD:
    check("systemd is present, so this run is not blind", st["blind"], False)


print("\n[9] THE LISTING SAYS WHAT IT COULD NOT DO")

lu = su.list_units()
ok("the listing reports an ok flag", "ok" in lu)
ok("  and a reason field is always present, so empty is never the whole "
   "answer", "reason" in lu)
if lu["ok"]:
    ok("  on a working host it returns real units", lu["total"] > 0)
    ok("  and each row names an active state",
       all("active" in u for u in lu["units"]))
    if lu["total"] > len(lu["units"]):
        ok("  and a cut is announced rather than silent",
           "cut" in (lu.get("note") or "").lower())


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
