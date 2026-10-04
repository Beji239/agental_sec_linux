# tools/systemd_units.py
# AgentalSec Linux, L2. WHICH SYSTEMD UNIT OWNS A PROCESS, AND WHETHER KILLING
# IT WOULD BE THEATRE.
#
# WHY THIS MODULE EXISTS
#
# The owner's word for it is "kill theatre", and it is exact. On a systemd host
# a service unit with Restart=always owns its process: SIGTERM it, the unit
# goes active (auto-restart), systemd starts it again a second later, and
# anything this app reported as "contained" is still running. The kill
# succeeded. The thing did not stop. Every reader downstream of that - the
# finding, the incident, the model's own summary - says the opposite of what
# happened.
#
# That is the same shape as every other defect this project keeps a rule
# about: a tool that reports an effect it did not have. The fix is not a
# better kill. It is knowing WHAT the process belongs to before deciding
# whether a signal is the right instrument at all.
#
# THE TWO MEASUREMENTS THIS IS BUILT ON, MADE ON THIS HOST 2026-09-22
#
# 1. `systemctl show <pid>` DOES NOT RESOLVE A PID. It was the obvious first
#    idea and it does not work here:
#
#        systemctl show 94763
#        Failed to get properties: Unknown object
#        '/org/freedesktop/systemd1/job/94763'
#
#    The pid is read as a JOB id. So attribution comes from
#    /proc/<pid>/cgroup, which is where the kernel actually records it:
#
#        0::/user.slice/user-1000.slice/user@1000.service/app.slice/
#            vte-spawn-9f758cb4.scope
#        0::/system.slice/ssh.service
#        0::/system.slice/system-getty.slice/getty@tty1.service
#
# 2. THE USER MANAGER ANSWERS DIFFERENTLY FROM THE SYSTEM ONE, AND THE WRONG
#    ANSWER IS SILENT. A unit started with `systemd-run --user` lives in the
#    user's own manager. Asked the SYSTEM manager about it, systemctl does not
#    error, it INVENTS a default:
#
#        systemctl --user show agental_l2_probe.service -p Restart
#        Restart=always                      <-- the truth
#        systemctl show agental_l2_probe.service -p Restart      (no --user)
#        Restart=no                          <-- a default, not a reading
#
#    So a system-manager-only check would look at a running service with
#    Restart=always, read Restart=no, and conclude the kill was the right
#    instrument. That is the theatre with a green light on it. The manager
#    flag is therefore chosen from the cgroup, never guessed, and a user unit
#    that cannot be asked is reported as UNKNOWN rather than as "no restart
#    policy".
#
# WHAT THIS MODULE DOES NOT DO
#
#   * It does not stop anything. Reading and acting are separate, and the
#     acting half lives behind the permission gate in tool_registry.
#   * It does not run systemctl without a reason. Every call here is one
#     subprocess for one question, with a timeout, because this runs on a
#     poll path in the kill decision and must not be able to hang it.
#   * IT NEVER READS A RESTART POLICY OUT OF A FAILED CALL. Three outcomes
#     are kept apart everywhere in this file: a unit with a policy, a unit
#     with none, and a question that could not be answered. Collapsing the
#     third into the second is the defect this whole module is about.

import logging
import os
import re
import subprocess

logger = logging.getLogger(__name__)

ROLE = "systemd_units"

# How long any systemctl call may take. These are local queries against a
# manager that answers in milliseconds; a call that needs longer is a manager
# that is not answering, and the honest answer then is UNKNOWN rather than a
# paused kill decision.
SYSTEMCTL_TIMEOUT_SECONDS = 5

# Restart policies that make a plain signal ineffective. systemd's own names,
# not a paraphrase: 'always' restarts on any exit, 'on-failure' and
# 'on-abnormal' restart on a signal-kill (which is what SIGTERM/SIGKILL are),
# and 'on-abort' covers an uncaught signal.
#
# 'no' and 'on-success' are NOT in this set and the difference matters: a
# process that exits on SIGTERM and is not restarted genuinely stops.
RESTART_POLICIES_THAT_RESURRECT = frozenset({
    "always", "on-failure", "on-abnormal", "on-abort",
})

# The slice paths that mean "a system unit" versus "a user manager unit".
_SYSTEM_PREFIX = "/system.slice/"
_USER_MARKERS = ("/user@", ".service/", ".slice/", "/user.slice/")

# A unit name as systemd spells it, with the suffix that says what kind it is.
# getty@tty1.service, ssh.service, vte-spawn-<uuid>.scope, system-getty.slice.
_UNIT_RE = re.compile(r"([A-Za-z0-9@:_.\\-]+\.(?:service|scope|socket|timer|"
                      r"target|slice|mount|path))")


def _run(cmd: list, timeout: int = SYSTEMCTL_TIMEOUT_SECONDS):
    """
    Run a command, return (rc, stdout, stderr). Never raises.

    A missing systemctl is a fact about the machine, not an exception in a
    kill path: this answers rc=127 with the reason, and the caller reports
    UNKNOWN.
    """
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        return 127, "", "the command was not found on this host"
    except subprocess.TimeoutExpired:
        return 124, "", f"the command did not answer within {timeout}s"
    except Exception as e:                                  # noqa: BLE001
        return 1, "", f"{type(e).__name__}: {e}"


# WHICH UNIT OWNS A PID

def unit_for_pid(pid) -> dict:
    """
    The systemd unit a pid belongs to, and which manager owns it.

    Returns a dict, never raises, and the `state` key is the one to branch on:

        {"state": "system", "unit": "ssh.service", ...}
        {"state": "user",   "unit": "app-org.gnome.Terminal.slice/...scope"}
        {"state": "none"}    the process is not in a unit systemd manages
        {"state": "unknown"} the cgroup could not be read, and says why

    'none' and 'unknown' are DIFFERENT ANSWERS and the whole file is written
    around keeping them apart: a process genuinely outside any unit is not
    restarted by anything, and a cgroup this account cannot read might belong
    to a unit with Restart=always. Treating the second as the first is how a
    kill theatre gets built out of an unreadable file.
    """
    out = {"pid": None, "state": "unknown", "unit": None, "manager": None,
           "cgroup": None, "reason": None, "unit_kind": None}

    try:
        pid = int(str(pid).strip())
    except (TypeError, ValueError):
        out["reason"] = f"pid must be a number, got {pid!r}"
        return out
    out["pid"] = pid

    path = f"/proc/{pid}/cgroup"
    # os.path, not pathlib: /proc/<pid> for another account's process is not
    # traversable, and Path.exists() RAISES there while os.path answers False.
    # Same defect this project has already paid for twice.
    if not os.path.exists(path):
        out["state"] = "none"
        out["reason"] = (f"there is no /proc/{pid}, so that process is not "
                         f"running. That is not a unit question.")
        return out

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read().strip()
    except PermissionError:
        out["reason"] = (f"the cgroup of pid {pid} could not be read (not "
                         f"permitted), so whether a UNIT owns it is UNKNOWN. "
                         f"That is not the same as it having none.")
        return out
    except OSError as e:
        out["reason"] = f"/proc/{pid}/cgroup could not be read: {e}"
        return out

    if not text:
        out["state"] = "none"
        out["reason"] = (f"pid {pid} has an empty cgroup, so nothing systemd "
                         f"manages owns it.")
        return out

    # THE UNIFIED LINE IS THE ONE TO TRUST, when it is there: "0::/path".
    # The older v1 format prefixes a hierarchy id and a controller list, and
    # 'name=systemd:' is the one that carries the unit path. Both are read
    # because both shapes are live on real machines.
    cgroup_path = None
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        controllers, path = parts[1], parts[2]
        if controllers == "" and path:
            cgroup_path = path                     # v2 unified
            break
        if "name=systemd" in controllers and path:
            cgroup_path = path                     # v1 with the systemd name
    if not cgroup_path:
        out["reason"] = (f"the cgroup file for pid {pid} has no line that "
                         f"names a systemd hierarchy, so nothing here says "
                         f"which unit owns it.")
        return out

    out["cgroup"] = cgroup_path

    # THE DEEPEST UNIT PATH COMPONENT IS THE OWNER, and this is the part that
    # is easy to get wrong in a way that looks right. A cgroup path can hold
    # several unit-shaped components:
    #
    #   /user.slice/user-1000.slice/user@1000.service/app.slice/
    #       app-org.gnome.Terminal.slice/vte-spawn-9f758cb4.scope
    #
    # user@1000.service, app.slice and the terminal slice are all real units,
    # and the one whose process this is is the LAST of them. Taking the first
    # would report "the user manager is running this process", which is true
    # and useless: stopping user@1000.service would end every session that
    # user has. The last unit in the path is the one holding the pid.
    found = _UNIT_RE.findall(cgroup_path)
    if not found:
        out["state"] = "none"
        out["reason"] = (f"the cgroup path {cgroup_path!r} names no unit, so "
                         f"pid {pid} is in a slice systemd does not manage as "
                         f"a unit.")
        return out

    unit = found[-1]
    out["unit"] = unit
    out["unit_kind"] = unit.rsplit(".", 1)[-1]

    # WHICH MANAGER. A unit under a user@<uid>.service path belongs to that
    # user's own manager, and asking the system manager about it is the
    # silent-wrong-answer case in the header. Anything under /system.slice is
    # the system manager's.
    if _SYSTEM_PREFIX in cgroup_path:
        out["state"] = "system"
        out["manager"] = ""                      # systemctl with no flag
    elif "/user@" in cgroup_path or cgroup_path.startswith("/user.slice/"):
        out["state"] = "user"
        out["manager"] = "--user"
        uid_match = re.search(r"user@(\d+)\.service", cgroup_path)
        out["uid"] = int(uid_match.group(1)) if uid_match else None
    elif cgroup_path in ("/init.scope", "/init.scope/") or \
            cgroup_path.startswith("/system.slice"):
        # PID 1 AND THE MANAGER'S OWN SCOPE. `/init.scope` is where init lives
        # under the SYSTEM manager, and it is the one path that is a unit
        # without being in a slice: pid 1's cgroup on this host reads exactly
        # `/init.scope`. Found by running this against pid 1 rather than by
        # reading systemd's documentation, and it matters because a kill of
        # pid 1 is the most destructive thing this app could be asked to do,
        # so "which manager" must not be the unknown answer there.
        out["state"] = "system"
        out["manager"] = ""
        out["note"] = ("pid 1 is the system manager itself. Nothing in this "
                       "app may stop it: see the refusal list in the kill "
                       "path.")
    else:
        # A unit-shaped name on a path that is neither. Said out loud rather
        # than guessed at, because the manager flag is what decides whether
        # the restart reading is real.
        out["state"] = "unknown"
        out["manager"] = None
        out["reason"] = (f"pid {pid} is in {unit} on the path {cgroup_path!r}, "
                         f"which is neither a system slice nor a user manager "
                         f"path. Which manager to ask is UNKNOWN.")
    return out


# WHAT THAT UNIT WOULD DO IF THE PROCESS WERE SIGNALLED

def _manager_env(manager: str, uid=None) -> dict:
    """
    The environment a systemctl call needs, built rather than inherited.

    MEASURED: `systemctl --user` without XDG_RUNTIME_DIR fails with
    "Failed to connect to bus: No medium found". An app started from a
    launcher or from a boot script does not necessarily have it, and the
    failure is a connect error rather than a wrong answer, so it is reported
    as UNKNOWN. Supplying the value this host already has is what makes the
    question answerable; supplying it for a uid other than our own would be
    reaching into another session's manager, so it is only done for ours.
    """
    env = dict(os.environ)
    if manager != "--user":
        return env
    if env.get("XDG_RUNTIME_DIR") and env.get("DBUS_SESSION_BUS_ADDRESS"):
        return env
    if uid is not None and uid != os.getuid():
        return env                       # not ours to reach; stay unknown
    runtime = env.get("XDG_RUNTIME_DIR") or f"/run/user/{uid or os.getuid()}"
    env.setdefault("XDG_RUNTIME_DIR", runtime)
    bus = os.path.join(runtime, "bus")
    if os.path.exists(bus):
        env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={bus}")
    return env


def unit_properties(unit: str, manager: str = "", uid=None) -> dict:
    """
    Ask the right manager about one unit. Never raises.

    Returns:
        {"ok": True,  "properties": {...}, "load_state": "loaded"}
        {"ok": False, "reason": "..."}          the question could not be asked

    THE FIVE PROPERTIES ARE THE DECISION, nothing more. `LoadState` is in the
    list and that is not decoration: without it, a name this manager has never
    heard of comes back with a set of DEFAULT properties (ActiveState=inactive,
    Restart=no) that look exactly like a real reading. That defect shipped in
    the first version of this function -- it asked for Id,ActiveState,SubState,
    Restart and MainPID, so the
    `if props.get("LoadState") == "not-found"` guard below it could never fire,
    and stopping a unit that does not exist reported "it is already inactive,
    nothing to stop" instead of "there is no such unit". Running it found that,
    not reading it.
    """
    if not unit:
        return {"ok": False, "reason": "no unit name was given"}

    cmd = ["systemctl"]
    if manager == "--user":
        cmd.append("--user")
    cmd += ["show", unit,
            "-p", "Id,LoadState,ActiveState,SubState,Restart,MainPID,ActiveEnterTimestamp"]

    env = _manager_env(manager, uid=uid)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=SYSTEMCTL_TIMEOUT_SECONDS, env=env)
    except FileNotFoundError:
        return {"ok": False, "reason": "systemctl is not installed on this "
                                       "host, so what a unit would do cannot "
                                       "be read"}
    except subprocess.TimeoutExpired:
        return {"ok": False,
                "reason": (f"systemctl did not answer within "
                           f"{SYSTEMCTL_TIMEOUT_SECONDS}s")}
    except Exception as e:                                  # noqa: BLE001
        return {"ok": False, "reason": f"{type(e).__name__}: {e}"}

    text = (proc.stdout or "").strip()
    if not text:
        return {"ok": False,
                "reason": (proc.stderr or "").strip()[:200]
                          or f"systemctl exited {proc.returncode} with no "
                             f"output"}

    props = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        props[key.strip()] = value.strip()

    # THE GUARD AGAINST THE INVENTED ANSWER. A unit this manager has never
    # heard of is NOT an answer about a unit: systemctl fills in defaults for
    # a name that does not exist, and those defaults are indistinguishable
    # from a reading unless LoadState is asked for.
    load_state = props.get("LoadState")
    if load_state in (None, "", "not-found"):
        return {"ok": False,
                "load_state": load_state or "not reported",
                "reason": (f"this manager has no unit named {unit!r} "
                           f"(LoadState={load_state or 'not reported'}), so "
                           f"nothing was read about it. Anything that reported "
                           f"a state for that name would be reporting "
                           f"systemctl's defaults, not a unit.")}
    if not props:
        return {"ok": False, "reason": f"systemctl returned no properties for {unit!r}"}

    return {"ok": True, "properties": props, "load_state": load_state}


def unit_state(pid) -> dict:
    """
    THE ONE FUNCTION THE KILL PATH NEEDS: what a signal to this pid would do.

    Returns a dict whose `verdict` key is the decision:

        "not_in_a_unit"        nothing systemd manages owns this pid, so a
                               signal is the end of it
        "supervised"           a unit owns it and would bring it back. A kill
                               is theatre; the unit has to be stopped
        "supervised_no_restart" a unit owns it and would NOT bring it back
        "unknown"              the question could not be answered, and
                               `reason` says which part failed

    THE UNKNOWN CASE IS NOT FAIL-OPEN AND IS NOT FAIL-CLOSED, it is a fact
    reported to the caller. The kill path decides what to do about it; this
    module's job is to make sure the decision is made on a reading rather than
    on a default.
    """
    where = unit_for_pid(pid)
    out = {"pid": where.get("pid"), "unit": where.get("unit"),
           "manager": where.get("manager"), "verdict": "unknown",
           "restart": None, "verdict_reason": None,
           "cgroup": where.get("cgroup")}

    if where["state"] == "none":
        out["verdict"] = "not_in_a_unit"
        if where.get("reason", "").startswith("there is no /proc"):
            out["verdict_reason"] = f"pid {pid} is not running."
        else:
            out["verdict_reason"] = (
                f"nothing systemd manages owns pid {pid}, so a signal to it "
                f"is the end of the process.")
        return out

    if where["state"] == "unknown":
        out["verdict"] = "unknown"
        out["verdict_reason"] = where.get("reason")
        return out

    props = unit_properties(where["unit"], manager=where.get("manager") or "",
                            uid=where.get("uid"))
    if not props["ok"]:
        out["verdict"] = "unknown"
        out["verdict_reason"] = (
            f"pid {pid} belongs to {where['unit']}, but what that unit would "
            f"do if the process died COULD NOT BE READ: {props['reason']}. "
            f"Until that is readable, a signal to this pid may or may not be "
            f"undone a second later, and this app cannot say which.")
        return out

    p = props["properties"]
    out["restart"] = p.get("Restart")
    out["active_state"] = p.get("ActiveState")
    out["main_pid"] = p.get("MainPID")

    # A SCOPE IS NOT A SERVICE. A .scope unit is a container systemd makes to
    # track a process somebody else started, and it has no restart policy
    # because it is not something systemd can start. Reporting a scope's
    # Restart=None as "this service does not restart" reads as a fact about a
    # policy the unit was never given. Found by running this against the
    # terminal's own scope, which is where the app's shell lives.
    if where.get("unit_kind") == "scope":
        out["verdict"] = "supervised_no_restart"
        out["verdict_reason"] = (
            f"pid {pid} is tracked by the scope {where['unit']}, which systemd "
            f"created to hold a process that was already started. A scope is "
            f"not a service and has no restart policy to read, so nothing here "
            f"would bring the process back: a signal to it stops it. Stopping "
            f"the scope is the tidier act because the manager then records "
            f"that it ended.")
        return out

    if p.get("Restart") in RESTART_POLICIES_THAT_RESURRECT:
        out["verdict"] = "supervised"
        out["verdict_reason"] = (
            f"pid {pid} belongs to {where['unit']} (Restart={p.get('Restart')}, "
            f"ActiveState={p.get('ActiveState')}). KILLING THE PROCESS WOULD "
            f"NOT STOP THE SERVICE: systemd would start it again within "
            f"seconds, while this app reported the thing as stopped. The unit "
            f"is what has to be stopped, with stop_service.")
    else:
        out["verdict"] = "supervised_no_restart"
        out["verdict_reason"] = (
            f"pid {pid} belongs to {where['unit']} (Restart={p.get('Restart')}"
            f"). That policy does not restart it after a signal, so a signal "
            f"to the process stops it. Stopping the UNIT is still the cleaner "
            f"act, because the manager then knows and records the state.")
    return out


# STOPPING A UNIT

def stop_unit(unit: str, manager: str = "", uid=None,
              dry_run: bool = False) -> dict:
    """
    Stop one unit, and VERIFY it stopped. Never raises.

    WHY THIS VERIFIES RATHER THAN RELYING ON THE RETURN CODE. `systemctl stop`
    returns 0 when the request was accepted, which is not the same as the unit
    being inactive: a unit with a long TimeoutStopSec, or one that ignores
    SIGTERM and waits for SIGKILL, is still "stopping" at exit. The Windows
    firewall lesson in this project is the same lesson: both return codes were
    unchecked, and the function returned success for a rule that was never
    traversed. So the state is READ BACK and the two facts are reported
    separately.

    THE UNIT NAME IS VALIDATED BEFORE IT IS PASSED. It comes from a model or
    a person, and `systemctl stop` with a name that begins with a dash would
    be read as a FLAG, which is how a stop request becomes a wildcard act.
    See _validated_unit_name.
    """
    try:
        unit = _validated_unit_name(unit)
    except ValueError as e:
        return {"success": False, "error": str(e), "ran": False}

    if dry_run:
        return {"success": True, "ran": False, "dry_run": True, "unit": unit,
                "would_run": f"systemctl {'--user ' if manager == '--user' else ''}"
                             f"stop {unit}"}

    before = unit_properties(unit, manager=manager, uid=uid)
    if not before["ok"]:
        return {"success": False, "ran": False, "unit": unit,
                "error": (f"{unit} could not be read before stopping it: "
                          f"{before['reason']}. Nothing was run, because "
                          f"stopping a name whose state cannot be read is "
                          f"acting blind on a system-wide object.")}

    if before["properties"].get("ActiveState") in ("inactive", "failed"):
        return {"success": False, "ran": False, "unit": unit,
                "outcome": "not_running",
                "error": (f"{unit} is already "
                          f"{before['properties'].get('ActiveState')}. Nothing "
                          f"was stopped, and this is not a failure of the "
                          f"stop: there was nothing running to stop.")}

    cmd = ["systemctl"]
    if manager == "--user":
        cmd.append("--user")
    cmd += ["stop", unit]

    # THE ONLY CALL IN THIS FILE THAT NEEDS AN ENVIRONMENT, which is why it
    # does its own subprocess.run rather than going through _run. `systemctl
    # --user` without XDG_RUNTIME_DIR fails with "Failed to connect to bus",
    # measured on this host, and that failure looks like a stop that did not
    # happen rather than a question that was never asked.
    env = _manager_env(manager, uid=uid)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=60, env=env)
        rc, out, err = proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return {"success": False, "ran": True, "unit": unit,
                "error": (f"the stop of {unit} did not return within 60s. The "
                          f"request was SENT, so the unit may be stopping or "
                          f"may be refusing to stop. Read it again before "
                          f"reporting anything.")}
    except Exception as e:                                  # noqa: BLE001
        return {"success": False, "ran": True, "unit": unit,
                "error": f"the stop request could not be run: {e}"}

    if rc != 0:
        return {"success": False, "ran": True, "unit": unit,
                "returncode": rc,
                "error": (f"systemctl stop {unit} exited {rc}: "
                          f"{(err or out).strip()[:300]}")}

    after = unit_properties(unit, manager=manager, uid=uid)
    if not after["ok"]:
        # THE STOPPED-AND-REMOVED CASE.
        #
        # A TRANSIENT UNIT THAT WAS STOPPED IS GONE, and that is not the same
        # as the unit never having existed. MEASURED on this host: after
        # `systemctl --user stop` of a transient unit, the read-back returns
        # `LoadState=not-found` with `ActiveState=inactive` -- systemd removed
        # the name it had created. The first version of this function treated
        # any unreadable read-back as "unverified", so a stop that WORKED
        # reported itself as "the request ran; whether the service is down is
        # UNKNOWN". That is the defect shape this project writes rules about:
        # a working action reported as broken sends the operator hunting for a
        # fault that is not there, and the next time it happens they do not
        # read the sentence.
        #
        # The distinction is available and is used deliberately: this branch is
        # only reachable when the BEFORE read succeeded and showed the unit
        # active or failed, so the unit provably existed a moment ago. It is
        # not reachable for a name that was never a unit, which is refused
        # earlier.
        if after.get("load_state") == "not-found":
            logger.info(f"systemd_units: {unit} stopped; the manager has "
                        f"removed the unit name (it was transient).")
            return {"success": True, "ran": True, "unit": unit,
                    "verified": True, "active_state": "removed",
                    "note": (f"THE UNIT IS GONE, and that is a successful "
                             f"stop: {unit} was a transient unit, so systemd "
                             f"removed the name once it stopped. It was "
                             f"{before['properties'].get('ActiveState')} "
                             f"immediately before the stop and does not exist "
                             f"afterwards.")}
        return {"success": False, "ran": True, "unit": unit,
                "verified": False,
                "error": (f"the stop was accepted and the unit could not be "
                          f"read back to confirm it: {after['reason']}. The "
                          f"request ran; whether the service is down is "
                          f"UNKNOWN.")}

    state = after["properties"].get("ActiveState")
    if state == "inactive":
        logger.info(f"systemd_units: {unit} stopped and verified inactive.")
        return {"success": True, "ran": True, "unit": unit, "verified": True,
                "active_state": state,
                "note": (f"{unit} is inactive, read back from the manager "
                         f"rather than assumed from the return code.")}

    return {"success": False, "ran": True, "unit": unit, "verified": True,
            "active_state": state,
            "error": (f"systemctl accepted the stop but {unit} is {state} "
                      f"afterwards, not inactive. It may still be stopping, or "
                      f"something may be holding it. Do not report this "
                      f"service as stopped.")}


# A unit name as systemd itself spells it. Deliberately a strict allowlist of
# the characters systemd permits rather than a check for the dangerous ones:
# the same argument the rest of this tree makes about validation.
_UNIT_NAME_RE = re.compile(r"^[A-Za-z0-9@:_.\\-]{1,255}\."
                           r"(?:service|scope|socket|timer|target|slice|"
                           r"mount|path|swap|device)$")


def _validated_unit_name(unit) -> str:
    """
    Refuse anything that is not a plain unit name, with the reason.

    THE DASH IS THE SHARP EDGE and it is why this exists. `systemctl stop`'s
    first argument is parsed as an option if it starts with a dash, so a unit
    named "--all" or "-.mount" would turn one stop into a wildcard act
    affecting units nobody approved. There is no quoting fix for that; the fix
    is refusing the shape.

    A bare name like "ssh" is also refused, and that is deliberate rather than
    pedantic: systemctl would accept it and guess the suffix, which means the
    thing that is stopped is decided by systemd's guessing rules rather than
    by what a person approved. Everything in this app that names a target
    names it exactly.
    """
    if unit is None:
        raise ValueError("no unit name was given")
    name = str(unit).strip()
    if not name:
        raise ValueError("the unit name is empty")
    if name.startswith("-"):
        raise ValueError(
            f"{name!r} starts with a dash, which systemctl would read as an "
            f"OPTION rather than a unit name. Refusing: that is how a stop "
            f"request becomes a wildcard act.")
    if "/" in name or "\\" in name:
        raise ValueError(
            f"{name!r} contains a path separator. A unit is named, not "
            f"pathed, and a name with a slash in it is a name chosen to look "
            f"like something else.")
    if not _UNIT_NAME_RE.match(name):
        raise ValueError(
            f"{name!r} is not a unit name. Expected something like "
            f"'ssh.service' or 'getty@tty1.service': letters, digits and "
            f"@ : . _ - only, ending in a real unit suffix. A bare name is "
            f"refused too, because systemd would then guess the suffix and "
            f"the thing stopped would be decided by that guess.")
    return name


# WHAT IS RUNNING, FOR THE MODEL

def list_units(manager: str = "", limit: int = 200) -> dict:
    """
    The units this manager knows about, with their restart policy.

    READ THIS BEFORE CALLING stop_service ON SOMETHING. A stop on a unit this
    app has never seen is the kind of act that should be preceded by a look.

    The answer distinguishes what could be read from what could not: on a host
    with no systemd, or in a container with no user manager, `ok` is False and
    the reason says so, rather than an empty list that reads as "nothing is
    running".
    """
    cmd = ["systemctl"]
    if manager == "--user":
        cmd.append("--user")
    cmd += ["list-units", "--type=service", "--all", "--no-pager",
            "--plain", "--no-legend"]

    env = _manager_env(manager)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=SYSTEMCTL_TIMEOUT_SECONDS, env=env)
    except FileNotFoundError:
        return {"ok": False, "units": [],
                "reason": "systemctl is not installed on this host"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "units": [],
                "reason": (f"systemctl did not answer within "
                           f"{SYSTEMCTL_TIMEOUT_SECONDS}s")}
    except Exception as e:                                  # noqa: BLE001
        return {"ok": False, "units": [], "reason": f"{type(e).__name__}: {e}"}

    if proc.returncode != 0 and not (proc.stdout or "").strip():
        return {"ok": False, "units": [],
                "reason": ((proc.stderr or "").strip()[:200]
                           or f"systemctl exited {proc.returncode}")}

    units = []
    for line in (proc.stdout or "").splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        name, load, active, sub = parts[0], parts[1], parts[2], parts[3]
        if not name.endswith(".service"):
            continue
        units.append({"unit": name, "load": load, "active": active,
                      "sub": sub,
                      "description": parts[4] if len(parts) > 4 else ""})

    units.sort(key=lambda u: (u["active"] != "active", u["unit"]))
    total = len(units)
    shown = units[:max(1, int(limit or 200))]

    out = {"ok": True, "manager": manager or "system", "units": shown,
           "total": total, "reason": None}
    if total > len(shown):
        out["note"] = (f"SHOWING {len(shown)} OF {total} SERVICE UNIT(S). This "
                       f"is a cut, not the whole list: ask again with a "
                       f"higher limit if what you need is not here.")
    return out


def status(config: dict = None) -> dict:
    """
    Is systemd usable from this run, in the vocabulary the rest of the app
    uses (running / ready / blind / blind_reason).

    IT IS NOT BLIND WHEN THERE IS NO SYSTEMD. `blind` is for "I could not
    look", and a host without systemd is a stated limit of the machine, not a
    fault in this app; the same argument the kernel camera's reader makes. It
    IS blind when systemctl exists and cannot answer, because then a unit
    question was asked and no answer came back.
    """
    out = {"role": ROLE, "ready": False, "running": False, "blind": False,
           "blind_reason": None, "systemctl": None, "user_manager": None}

    path = None
    for candidate in ("/usr/bin/systemctl", "/bin/systemctl"):
        if os.path.exists(candidate):
            path = candidate
            break
    out["systemctl"] = path
    if not path:
        out["note"] = ("there is no systemctl on this host, so this app cannot "
                       "say which unit owns a process or stop a service. That "
                       "is a limit of the machine, not a fault in this app, "
                       "and a kill here is a kill.")
        return out

    rc, out_text, err = _run(["systemctl", "is-system-running"])
    state = (out_text or err or "").strip()
    out["manager_state"] = state

    if rc == 0 or state in ("running", "degraded", "maintenance",
                            "starting", "stopping"):
        out["ready"] = True
        out["running"] = True
    else:
        out["blind"] = True
        out["blind_reason"] = (
            f"systemctl is present but the system manager did not answer "
            f"({state or f'rc {rc}'}). Whether a process belongs to a "
            f"supervised unit CANNOT be determined this run, so a kill may be "
            f"undone by a manager this app cannot see.")
    return out
