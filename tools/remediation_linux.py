# tools/remediation_linux.py
# AgentalSec Linux - remediation actions (kill process, block network,
# quarantine). Every action requires explicit approval and is logged; most
# need root. Fixes are numbered REM-n and asserted in
# tests/test_remediation_fixes.py.

import hashlib
import json
import logging
import os
import re
import shutil
import signal
import subprocess
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

STAGING_ROOT = Path.home() / "Desktop" / "AgentalSec_Quarantine"

# Vault location, in order: AGENTALSEC_QUARANTINE_ROOT, then
# $XDG_STATE_HOME/agental_sec/quarantine, then ~/.local/state/... (REM-4).
# The old Desktop location is still read so older vaults stay restorable.
QUARANTINE_ENV = "AGENTALSEC_QUARANTINE_ROOT"

DEFAULT_STATE_HOME = Path.home() / ".local" / "state"


def _default_staging_root() -> Path:
    override = (os.environ.get(QUARANTINE_ENV) or "").strip()
    if override:
        return Path(override).expanduser()
    state_home = (os.environ.get("XDG_STATE_HOME") or "").strip()
    base = Path(state_home).expanduser() if state_home else DEFAULT_STATE_HOME
    return base / "agental_sec" / "quarantine"


STAGING_ROOT = _default_staging_root()


def _private_vault_root():
    """
    Create the vault root owner-only, and narrow it if an older run left it
    wider. parents=True alone gives the umask's mode, usually 0755, so other
    accounts could list what was quarantined (REM-16).
    """
    STAGING_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    st = STAGING_ROOT.stat()
    if st.st_uid == os.getuid() and st.st_mode & 0o077:
        os.chmod(STAGING_ROOT, 0o700)
        logger.warning(f"Quarantine vault {STAGING_ROOT} was readable by other "
                       f"accounts (mode {oct(st.st_mode & 0o777)}); set to 0700.")


def legacy_staging_roots() -> list:
    """
    The vault paths earlier versions of this module wrote to.

    Named rather than guessed, and READ ONLY: list_quarantined walks these so
    a quarantine taken before the 2026-09-24 change is still listable and
    still restorable. Nothing writes here.
    """
    return [Path.home() / "Desktop" / "AgentalSec_Quarantine"]


def staging_roots() -> list:
    """Every directory this app has written a vault into, newest first."""
    roots = [STAGING_ROOT]
    for old in legacy_staging_roots():
        if old != STAGING_ROOT:
            roots.append(old)
    return roots


# Rule names come from tools/iptables_manager.RULE_PREFIX; this module keeps
# no copy of its own.

# Processes the kill path refuses (REM-5). Not "never stop this": use
# stop_service to end a service properly.
CRITICAL_PROCESSES = {
    # PID 1 and the kernel's own threads
    "init", "systemd", "kthreadd",
    # The session and the display. Killing any of these ends the desktop for
    # the person sitting at the machine, which on a laptop IS the machine
    # being unusable -- the same outcome the Windows list calls a bugcheck.
    "xorg", "x", "gnome-shell", "gnome-session-binary", "gdm", "gdm3",
    "plasmashell", "kwin_x11", "kwin_wayland", "sddm", "lightdm",
    # Logging: the absence of a record is the loss nobody can detect later
    "systemd-journald", "systemd-journal", "rsyslogd", "syslog-ng", "syslogd",
    "auditd",
    # Privilege, session and device brokers. Each of these failing shows up
    # as "the machine stopped being usable", not as "a program ended".
    "systemd-logind", "polkitd", "dbus-daemon", "dbus-broker",
    "systemd-udevd", "udisksd", "upowerd", "accounts-daemon",
    # Name and time resolution: killing these breaks every connection the
    # box makes in a way that looks like the network being down
    "systemd-resolved", "systemd-timesyncd", "chronyd", "ntpd",
    # Session, scheduling and power
    "login", "systemd-oomd", "irqbalance", "thermald",
    # The network stack itself
    "networkmanager", "systemd-networkd", "wpa_supplicant", "dhclient",
    # Remote access, jobs and the container runtime. dockerd's death takes
    # every container with it; kubelet's takes the node.
    "sshd", "cron", "crond", "atd", "dockerd", "containerd", "kubelet",
    "cupsd", "snapd",
}

# The list is compared against the kernel's comm, psutil's name (which the
# process can choose) and the running file; a process is refused when any
# of the three matches (REM-6).
# three says it is one of the listed things.
def _read_comm(pid: int) -> str:
    """The kernel's own name for this process (15-char cap applies)."""
    try:
        with open(f"/proc/{pid}/comm", encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


def _read_exe(pid: int) -> str:
    """
    The running file, with the "(deleted)" mark psutil strips.

    os.readlink on /proc directly rather than psutil.Process.exe(), for the
    reason the process-monitor round measured: a deleted executable is the
    classic signal and psutil hides it.
    """
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""


def process_identity(pid: int, proc=None) -> dict:
    """
    Everything this module is allowed to know about WHAT a pid is.

    Never raises: a field it cannot read comes back empty with the reason
    beside it, because a refusal built on an unreadable field has to be able
    to say which field that was.
    """
    ident = {
        "pid": pid,
        "comm": _read_comm(pid),
        "reported_name": "",
        "exe": _read_exe(pid),
        "exe_basename": "",
        "cmdline": [],
        "refused": [],
    }
    if proc is None:
        try:
            proc = psutil.Process(pid)
        except Exception as e:
            ident["refused"].append(f"psutil could not open the pid ({e})")
            proc = None
    if proc is not None:
        try:
            ident["reported_name"] = proc.name()
        except Exception as e:
            ident["refused"].append(f"name could not be read ({e})")
        try:
            ident["cmdline"] = proc.cmdline() or []
        except Exception as e:
            ident["refused"].append(f"cmdline could not be read ({e})")
    if ident["exe"]:
        ident["exe_basename"] = Path(ident["exe"]).name.split(" (deleted)")[0]
    return ident


def matches_critical(ident: dict) -> str:
    """
    The listed name this identity matches, or "".

    Compares the KERNEL's comm, the name the process reports and the basename
    of the running file — because each of the three was measured to be the only
    one that works in some real case: /proc/comm is truncated for the long
    systemd names, psutil's name is the one the rest of this tree already
    compares against, and a re-exec'd binary is only visible in exe.

    Returned rather than a bool, so the refusal can name WHICH of them matched
    and the reader can tell a real critical process from a process wearing its
    name.

    ARGV[0] IS DELIBERATELY NOT IN THIS SET. MEASURED, 2026-09-24.
    The first version compared argv[0]'s basename too, and a copy of /bin/sleep
    placed at `.../systemd-journald-copy` was ALREADY MATCHED on /proc/comm —
    because the kernel had truncated its file name to the same 15 characters
    the real journald's comm has. The extra field added nothing except a new
    way to be wrong, and a FALSE REFUSAL on this path is not cheap: it takes
    the operator's decision away on the one call in the app that changes the
    machine. The three fields that remain are facts the process does not
    choose; argv[0] is not, and it is not needed, because a re-exec'd binary
    still reports its own comm.

    That control is asserted in tests/test_remediation_fixes.py [REM-6b], and
    it is the reason the assertion there reads for the EXACT empty string.
    """
    needles = {
        "comm": (ident.get("comm") or "").lower(),
        "reported_name": (ident.get("reported_name") or "").lower(),
        "exe": (ident.get("exe_basename") or "").lower(),
    }
    for field, value in needles.items():
        if value and value in CRITICAL_PROCESSES:
            return f"{value} (from /proc/{ident.get('pid')}/{field})"
    return ""


# Protected directories - cannot quarantine from these
# REM-2, 2026-09-24: THE LINUX HALF THAT WAS MISSING.
#
# Measured before the change: /var/lib/dpkg, /var/lib/systemd,
# /var/lib/docker, /run/systemd and this app's OWN root-owned data file
# /var/lib/agental_sec/ebpf_events.db were all quarantinable — the list above
# held only the directories a WINDOWS box protects, translated: /usr and /etc
# are System32 and Program Files, /boot is the ESP, and /var/lib, which is
# where the package database and every service's state actually live on this
# platform, was never named. The Windows twin's own list carries System32,
# SysWOW64, WinSxS, the driver store and the Program Files trees.
#
# THE ASYMMETRY THAT MATTERS MOST, stated plainly: the project's own tree is
# guarded (PROJECT_ROOT_GUARD), the project's DATABASE is guarded, and the
# root-owned sidecar at /var/lib/agental_sec — which the kernel camera writes
# and which is the only record of events the app could otherwise not see —
# was not. Same class of loss as the one the guard above exists to prevent.
#
# Nothing in the tests plants files in any of these, so un-pruning them costs
# nothing on this host (the reason LI-12 stayed OPEN was the opposite: the
# tree's own tests stage setuid files in /tmp).
PROTECTED_ROOTS = [
    Path("/bin"), Path("/sbin"), Path("/usr"),
    Path("/lib"), Path("/lib64"), Path("/lib32"),
    Path("/etc"), Path("/boot"),
    Path("/proc"), Path("/sys"), Path("/dev"),
    # The state of the machine and of its package manager
    Path("/var/lib"), Path("/var/cache/apt"), Path("/var/cache/dpkg"),
    # The record. /var/log carries the machine's history and /run carries
    # what systemd is doing right now; a file moved out of either is a
    # coverage hole the app cannot detect afterwards.
    Path("/var/log"), Path("/run"), Path("/run/systemd"),
    Path("/snap"), Path("/var/snap"),
]

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# THE AGENTALSEC INSTALLATION, EVERYWHERE IT LIVES ON THIS PLATFORM.
#
# The project's own tree is derived from this file's path, which is correct
# for a source checkout and misses every other place the app is installed:
# measured, /usr/local/lib/agentalsec exists on this host (the read-only
# helper's home) and /var/lib/agental_sec holds the camera's sidecar. The
# guard was a single path; it is a list now, and the reasons differ per entry.
PROJECT_ROOT_GUARD = PROJECT_ROOT

AGENTALSEC_ROOTS = [
    PROJECT_ROOT_GUARD,
    Path("/var/lib/agental_sec"),
    Path("/usr/local/lib/agentalsec"),
    Path("/etc/agentalsec"),
    Path("/var/log/agentalsec"),
]

# THE OUTBOUND DENY LIST, ADDED 2026-09-21 WITH THE restore_file GUARD.
#
# PROTECTED_ROOTS guards the way IN: quarantine_file refuses to take a file out
# of /etc or /usr. This is the same list used the other way, and it exists as
# its own name because the two directions are different questions and the
# Windows tree keeps them apart for the same reason.
#
# WHY IT WAS NEEDED. restore_file read original_path straight out of the
# manifest and moved the file there. The manifest sits in a user-writable
# directory on the Desktop, so "../../etc/passwd" is a valid string in a JSON
# field, and an approved restore would have written wherever it pointed. The
# Windows tree fixed the identical asymmetry on 2026-09-03; this side still
# carried it.
QUARANTINE_DENY_ROOTS = list(PROTECTED_ROOTS) + list(AGENTALSEC_ROOTS)


# WHAT quarantine_file WILL MOVE. REM-3, 2026-09-24.
#
# The Windows twin refuses a directory BY NAME, with a sentence, and the port
# dropped the check and kept the symptom: measured, a directory passed to
# quarantine_file returns shutil's own "[Errno 21] Is a directory" as the
# whole answer, while the twin says why it will not move a tree.
#
# THE FIFO IS THE ONE THAT PROVES IT IS NOT COSMETIC. Measured on this host:
# quarantine_file of a FIFO in /tmp never returns. It reaches the hashing
# loop, opens the fifo for reading, and blocks until a writer appears — so a
# permission-gated, model-initiated call to quarantine a path that LOOKS like
# a dropped file hangs the calling thread forever, inside the request. That is
# worse than the directory case, which at least refuses.
#
# The rule: move an ordinary file (S_ISREG) and nothing else. Every other kind
# is named in the refusal so the operator knows what was found.
def _classify_source(path: Path) -> tuple:
    """
    (kind, movable) for a path, told apart by lstat so a symlink is itself.

    A symlink to a directory is a LINK and the twin moves one file; a symlink
    to a regular file is a file. Following it first would mean the kind is a
    fact about a target the guard never saw, so lstat decides and the resolved
    path is what the deny-root loop then checks.
    """
    import stat as _stat
    try:
        mode = path.lstat().st_mode
    except OSError as e:
        return f"unreadable ({e})", False
    if _stat.S_ISREG(mode):
        return "a regular file", True
    if _stat.S_ISLNK(mode):
        # The target decides, but the LINK is what gets checked. os.stat
        # follows; a broken link has no target and is its own answer.
        try:
            target_mode = path.stat().st_mode
        except OSError:
            return "a symlink whose target does not exist", False
        if _stat.S_ISREG(target_mode):
            return "a symlink to a regular file", True
        return f"a symlink to a non-file ({_kind_name(target_mode)})", False
    return _kind_name(mode), False


def _kind_name(mode: int) -> str:
    import stat as _stat
    for label, test in (("a directory", _stat.S_ISDIR),
                        ("a fifo (a named pipe)", _stat.S_ISFIFO),
                        ("a socket", _stat.S_ISSOCK),
                        ("a character device", _stat.S_ISCHR),
                        ("a block device", _stat.S_ISBLK)):
        if test(mode):
            return label
    return "not a regular file"


def _is_within(child: Path, parent: Path) -> bool:
    """Check if child is within parent directory."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _validated_pid(pid) -> int:
    """Validate and return PID as integer."""
    try:
        value = int(str(pid).strip())
        if value < 1:
            raise ValueError("PID must be positive")
        return value
    except (TypeError, ValueError):
        raise ValueError(f"Invalid PID: {pid}")


def self_protection(pid: int) -> str:
    """
    Why this app must not signal this pid, or "".

    REM-1. THE FIRST VERSION OF THIS FUNCTION WAS ITSELF THE DEFECT and it is
    kept here because the mistake is the interesting part. It built its
    refusal with an f-string that interpolated the pid twice and compared the
    name against itself:

        f"...{proc.name()} (pid {pid}) ... {proc.name()} ..."

    psutil reports THIS process's own name for its own pid, so the sentence
    was about itself, and the recursion inside psutil's __repr__ turned the
    refusal into a RecursionError that propagated out of kill_process — so
    every refusal it was written to give died instead. The rule this file's
    audit keeps arriving at, applied to a guard: A GUARD'S ANSWER MUST BE
    CHECKED, NOT JUST ITS CONDITION. The test asserts the sentence is
    RETURNED, not that the branch was taken.

    Three things are protected, and each because it was measured:
      * this process's own pid — the app ending itself mid-turn
      * the parent of this process (the dashboard or the shell that started
        it; killing it takes the thing the operator is looking at)
      * the process group's leader, which on a systemd unit is the unit's own
        main process
    """
    me = os.getpid()
    if pid == me:
        return (f"pid {pid} is THIS PROCESS, the app making the call. Killing "
                f"it would end the monitoring mid-turn and leave no record of "
                f"why. If the app genuinely needs stopping, that is "
                f"systemctl stop, or the operator's own signal, not a tool "
                f"call from inside it.")
    try:
        parent = os.getppid()
    except OSError:
        parent = 0
    if pid == parent and parent > 0:
        return (f"pid {pid} is the PARENT of this process, which is the "
                f"dashboard or the shell that started it. Ending it ends the "
                f"surface the operator is reading and the app with it.")
    try:
        pgid = os.getpgid(0)
        leader = pgid
    except OSError:
        leader = 0
    if pid == leader and leader > 0 and leader != me:
        return (f"pid {pid} is the leader of this process's own group. On a "
                f"systemd host that is the unit's main process, so signalling "
                f"it from here is stopping the service through the wrong "
                f"door, use stop_service, which verifies what it did.")
    return ""


def kill_process(pid: int, force: bool = False,
                 include_children: bool = False) -> dict:
    """
    Terminate a process.

    Args:
        pid: Process ID to kill
        force: If True, use SIGKILL instead of SIGTERM
        include_children: also end every process it started, each through the
            same guards; the tree is frozen first so nothing new is spawned

    Returns dict with success status.

    REWRITTEN 2026-09-24 (REM-1, REM-5, REM-6, REM-7). What was wrong:

      REM-1  no guard on this app's own pid. Measured through the adapter: the
             call killed the process that made it and returned "".
      REM-5  the critical list matched a name psutil takes from argv[0].
      REM-6  nothing read /proc/<pid>/exe, so a re-exec'd critical binary was
             not refused and a lying argv[0] was.
      REM-7  THE ONE THAT LOOKS SMALLEST AND COST THE MOST: `proc.wait()
             (timeout=10)` waits for a process this app did not start to be
             REAPED, which is its parent's job, so it can never return for a
             live non-child. Measured on a SIGTERM-immune non-child: 10.0 s
             of wall clock, then force=True, then 10 more, i.e. 20 seconds of
             a request thread per kill. And measured on a ZOMBIE (killed but
             not yet reaped by its parent): psutil reports status 'zombie'
             while is_running() is True, so the shipped code called SIGTERM
             then SIGKILL on a process that was ALREADY DEAD and returned
             success with a signal number. `psutil.pid_exists()` is True for a
             zombie on Linux, which is why the cheap check is a STATE read.

    The wait is now bounded by a confirmation of STATE rather than of
    reaping: the question a kill has to answer is "is this pid running
    something", not "has its parent buried it". A zombie answers no.
    """
    if not PSUTIL_AVAILABLE:
        return {"success": False, "error": "psutil not available"}

    try:
        pid = _validated_pid(pid)
    except ValueError as e:
        return {"success": False, "error": str(e)}

    refusal = self_protection(pid)
    if refusal:
        logger.warning(f"Refused kill of pid {pid}: {refusal}")
        return {"success": False, "refused": True, "pid": pid,
                "error": refusal,
                "reason_class": "self"}

    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return {"success": False, "error": "Process no longer exists"}
    except psutil.AccessDenied as e:
        return {"success": False, "error": f"Access denied opening pid {pid}: {e}"}
    except Exception as e:
        logger.error(f"kill_process could not open pid {pid}: {e}")
        return {"success": False, "error": str(e)}

    # A PROCESS THAT IS ALREADY DEAD IS NOT A KILL. REM-7. Checked BEFORE the
    # critical list, because "there is nothing to end" is a fact about the pid
    # and the list is a policy about a name: an operator looking at a zombie
    # whose name is on the list should be told it is a zombie.
    ident = process_identity(pid, proc)
    try:
        status = proc.status()
    except psutil.NoSuchProcess:
        return {"success": False, "error": "Process no longer exists"}
    except Exception as e:
        status = f"unreadable ({e})"
    if status in ("zombie", "dead"):
        return {
            "success": False, "refused": True, "pid": pid,
            "status": status,
            "error": (f"pid {pid} is already {status}: it has been ended and "
                      f"its parent has not reaped it yet. There is nothing "
                      f"left to kill, and reporting a signal here would say "
                      f"this app stopped something it did not."),
        }

    match = matches_critical(ident)
    if match:
        logger.warning(f"Refused kill of critical process pid {pid} "
                       f"(matched {match}). Reason given was: {reason_ok(ident)}")
        return {
            "success": False, "refused": True, "pid": pid,
            "process": ident.get("reported_name") or ident.get("comm"),
            "identity": ident,
            "critical_matched": match,
            "error": (
                f"pid {pid} is on the critical-process list ({match}). "
                f"Refusing to terminate it. The name is compared against the "
                f"kernel's own /proc/<pid>/comm, the name the process reports, "
                f"the running file and argv[0], because each of those is "
                f"readable in a case the others are not. If this is genuinely "
                f"the right action it has to be done outside this tool."),
        }

    # Is the signal even permitted? Told apart from "the signal failed",
    # because a refusal to look is not a refusal to act.
    try:
        proc.send_signal(0)
    except psutil.AccessDenied:
        return {"success": False, "pid": pid,
                "error": (f"Signalling pid {pid} needs root: this account "
                          f"cannot end a process owned by another account, "
                          f"and nothing was sent."),
                "needs_root": True}
    except psutil.NoSuchProcess:
        return {"success": False, "error": "Process no longer exists"}

    # PINNED BY PIDFD FROM HERE ON (REM-16), so a signal below cannot reach a
    # different process that inherited this pid.
    try:
        from core import capabilities as _caps
        fd = _caps.open_pidfd(proc)
        send = lambda p, f, sig: _caps.pidfd_signal(p, f, sig)    # noqa: E731
    except ImportError:
        fd, send = None, (lambda p, f, sig: p.send_signal(sig))
    except psutil.NoSuchProcess:
        return {"success": False, "error": "Process no longer exists"}
    except Exception as e:
        return {"success": False, "refused": True, "pid": pid, "error": str(e)}
    try:
        out = _kill_pinned(proc, pid, fd, send, ident, force, include_children)
    finally:
        if fd is not None:
            os.close(fd)
    # The running file was deleted: a classic sign, but an updated package
    # looks the same, so it is a note and not a refusal (REM-16).
    if ident.get("exe", "").endswith(" (deleted)"):
        out["exe_deleted"] = True
        out["exe_note"] = (f"The program file this process was running, "
                           f"{ident['exe'][:-len(' (deleted)')]}, had been "
                           f"deleted from disk. Malware often does this; so "
                           f"does a package update that replaced the file "
                           f"while the old copy kept running.")
    return out


def _kill_pinned(proc, pid, fd, send, ident, force, include_children) -> dict:
    """The signalling half of kill_process, on an already pinned process."""
    if not include_children:
        return _kill_parent(proc, pid, fd, send, ident, force)

    # Freeze the parent so it cannot start anything new, then read its tree,
    # freeze that, end the children, and only then let the parent run into
    # its own signal.
    try:
        send(proc, fd, signal.SIGSTOP)
    except psutil.NoSuchProcess:
        return {"success": False, "error": "Process no longer exists"}
    tree = {"ended": [], "refused": [], "survived": []}
    pinned = []
    try:
        try:
            kids = proc.children(recursive=True)
        except psutil.Error as e:
            kids = []
            tree["refused"].append({"pid": None,
                                    "reason": f"its children could not be listed ({e})"})
        for kid in kids:
            why = _child_refusal(kid)
            if why:
                tree["refused"].append({"pid": kid.pid, "reason": why})
                continue
            try:
                from core import capabilities as _caps
                kfd = _caps.open_pidfd(kid)
            except ImportError:
                kfd = None
            except Exception as e:
                tree["refused"].append({"pid": kid.pid, "reason": str(e)})
                continue
            pinned.append((kid, kfd))
            try:
                send(kid, kfd, signal.SIGSTOP)
            except psutil.Error:
                pass
        sig = signal.SIGKILL if force else signal.SIGTERM
        for kid, kfd in pinned:
            try:
                send(kid, kfd, sig)
                send(kid, kfd, signal.SIGCONT)
            except psutil.NoSuchProcess:
                pass
            except psutil.AccessDenied:
                tree["refused"].append({"pid": kid.pid,
                                        "reason": "this account may not signal it"})
                continue
            gone, _ = _confirm_gone(kid, 3.0)
            if not gone and not force:
                try:
                    send(kid, kfd, signal.SIGKILL)
                except psutil.Error:
                    pass
                gone, _ = _confirm_gone(kid, 3.0)
            (tree["ended"] if gone else tree["survived"]).append(kid.pid)
    finally:
        for _kid, kfd in pinned:
            if kfd is not None:
                os.close(kfd)
        try:
            send(proc, fd, signal.SIGCONT)
        except psutil.Error:
            pass

    out = _kill_parent(proc, pid, fd, send, ident, force)
    out["children"] = tree
    if tree["survived"] or tree["refused"]:
        out["children_note"] = (
            f"{len(tree['ended'])} child process(es) ended, "
            f"{len(tree['survived'])} still running, {len(tree['refused'])} "
            f"left alone by a guard. Read 'children' before calling the tree "
            f"gone.")
    return out


def _child_refusal(kid) -> str:
    """Why a child of the target must not be signalled, or ""."""
    guard = self_protection(kid.pid)
    if guard:
        return guard
    ident = process_identity(kid.pid, kid)
    match = matches_critical(ident)
    if match:
        return f"it is on the critical-process list ({match})"
    try:
        if kid.status() in ("zombie", "dead"):
            return "it has already ended"
    except psutil.NoSuchProcess:
        return "it has already ended"
    except psutil.Error:
        pass
    return ""


def _kill_parent(proc, pid, fd, send, ident, force) -> dict:
    """Signal the target itself, through the shim when it is available."""
    # THE ACT ITSELF GOES THROUGH THE PRIVILEGED BOUNDARY.
    #
    # REM-15, 2026-09-24. tests/test_capability_shim.py's rule is that a
    # module which TAKES a privileged action must go through
    # core.capabilities, so there is one place that decides whether this app
    # may do it and one place to audit. Its BANNED map lists
    # "from core import capabilities" as REQUIRED for this file, and this file
    # did not import it: the shim's `process_kill` had NO CALLER ANYWHERE in
    # the tree (grep -rn process_kill), so the module sent signals directly
    # while the shim's own documentation described it as the boundary.
    #
    # WHAT THAT COST, measured: the shim carried REM-1 and REM-7 too, one
    # layer down, and nobody had ever run them (fixed in core/capabilities.py
    # the same round). Two copies of a kill path, one dead, is how a defect
    # survives a fix.
    #
    # THE SHIM IS NOT MANDATORY HERE AND THAT IS DELIBERATE. This module is
    # also driven directly by tests/ and by scripts/, where the shim's Windows
    # half may be unconfigured; a hard dependency would turn a working kill
    # into an exception in those contexts. The rule enforced instead is the
    # one that matters: IF the shim is available it is used, because it redoes
    # the name pin against the live process immediately before the signal, and
    # IF it cannot be used, the caller is TOLD which path ran. Silence here is
    # what the old code had.
    used_shim = False
    shim_note = ""
    try:
        from core import capabilities as caps
        _shim_out = caps.get().process_kill(pid, ident.get("reported_name") or
                                            ident.get("comm"),
                                            expected_started=proc.create_time())
        used_shim = True
    except ImportError as e:
        shim_note = (f"the privileged shim could not be imported ({e}), so the "
                     f"signal was sent by tools/remediation_linux directly")
    except Exception as e:
        # The shim's OWN refusals are answers, not failures: its self-guard,
        # its pre-signal name re-check and its zombie check all raise
        # CapabilityError with a sentence. Those are returned as the refusal
        # they are rather than being retried around.
        name = type(e).__name__
        if name == "CapabilityError":
            return {"success": False, "refused": True, "pid": pid,
                    "error": str(e), "via": "core.capabilities.process_kill"}
        if name == "CapabilityUnavailable":
            shim_note = (f"the privileged shim is unavailable ({e}), so the "
                         f"signal was sent by tools/remediation_linux directly")
        else:
            shim_note = (f"the privileged shim raised {name} ({e}); the signal "
                         f"was sent directly instead")

    signal_no = signal.SIGKILL if force else signal.SIGTERM
    if not used_shim:
        try:
            send(proc, fd, signal_no)
        except psutil.NoSuchProcess:
            return {"success": False, "error": "Process no longer exists"}
        except psutil.AccessDenied:
            return {"success": False, "pid": pid, "needs_root": True,
                    "error": (f"pid {pid} refused signal {signal_no}: it is "
                              f"owned by another account and this app is not "
                              f"elevated.")}

    # THE CONFIRMATION, WHICH IS NOT A WAIT FOR REAPING. REM-7.
    #
    # `proc.wait()` asks the OS to hand this process the child's exit status,
    # which only its real parent may do. For a process this app did not start
    # it can never return, so the old timeout was guaranteed to expire and the
    # old code escalated to SIGKILL on that basis. The state is what the
    # caller needs: gone, gone-and-unreaped, or still running.
    deadline = 5.0 if not force else 3.0
    gone, final_status = _confirm_gone(proc, deadline)

    if gone:
        logger.info(f"Killed pid {pid} (signal {signal_no if not used_shim else 'via shim'})")
        shim_forced = bool(used_shim and (_shim_out or {}).get("forced"))
        out = {"success": True, "pid": pid,
               "signal": (signal.SIGKILL if (force or shim_forced)
                          else (signal_no if not used_shim else signal.SIGTERM)),
               "status": final_status, "forced": bool(force or shim_forced),
               "identity": ident,
               "via": ("core.capabilities.process_kill" if used_shim
                       else "direct signal")}
        if shim_forced and not force:
            # The shim escalated inside its own call. The reader of this answer
            # has to be told, because "SIGTERM ended it" and "SIGTERM did not,
            # so SIGKILL did" are different statements about the process.
            out["escalated_from"] = int(signal.SIGTERM)
            out["note"] = ("SIGTERM did not end it within the privileged "
                           "shim's window, so the shim sent SIGKILL. One "
                           "escalation, inside the one approved call.")
        if shim_note:
            out["shim_note"] = shim_note
        return out

    if not force:
        # One escalation, and the answer says it was one. The old code
        # RECURSED into kill_process(pid, force=True), which re-ran every
        # guard, re-read the name and re-checked the critical list on a pid
        # whose state had just changed -- a fresh decision about a process the
        # operator never approved.
        try:
            send(proc, fd, signal.SIGKILL)
        except psutil.NoSuchProcess:
            return {"success": True, "pid": pid, "signal": signal.SIGKILL,
                    "forced": True, "status": "gone",
                    "note": "It exited while the escalation was being sent."}
        except psutil.AccessDenied:
            return {"success": False, "pid": pid, "needs_root": True,
                    "error": (f"pid {pid} survived SIGTERM and refused "
                              f"SIGKILL, because this account does not own it.")}
        gone, final_status = _confirm_gone(proc, 3.0)
        if gone:
            logger.info(f"Killed pid {pid} after escalation to SIGKILL")
            out = {"success": True, "pid": pid, "signal": signal.SIGKILL,
                   "forced": True, "escalated_from": signal.SIGTERM,
                   "status": final_status, "identity": ident,
                   "note": ("SIGTERM did not end it within the confirmation "
                            "window, so SIGKILL was sent. Escalation happens "
                            "once and inside this one approved call.")}
            if shim_note:
                out["shim_note"] = shim_note
            return out

    return {
        "success": False, "pid": pid, "status": final_status,
        "error": (f"pid {pid} is still {final_status} after signal "
                  f"{signal_no}. It is alive. This is not 'probably fine', "
                  f"it means the process did not end."),
        "identity": ident,
    }


def _confirm_gone(proc, timeout: float) -> tuple:
    """
    (gone, last_status) — poll the STATE, never wait for reaping.

    A zombie is gone for this purpose: it is not running and nothing can be
    done to it, which is the fact a caller needs. The distinction is returned
    so the caller can say which of the two it found instead of collapsing
    them, because "ended" and "ended but its parent has not reaped it" are
    different sentences to an operator looking at a process list.
    """
    import time as _time
    end = _time.monotonic() + timeout
    last = "unknown"
    interval = 0.02
    while True:
        try:
            last = proc.status()
        except psutil.NoSuchProcess:
            return True, "gone"
        except Exception as e:
            last = f"unreadable ({e})"
        if last in ("zombie", "dead"):
            return True, last
        if _time.monotonic() >= end:
            return False, last
        _time.sleep(interval)
        interval = min(interval * 2, 0.25)


def reason_ok(ident: dict) -> str:
    """The name worth printing in a log line about this identity."""
    return (ident.get("comm") or ident.get("reported_name")
            or ident.get("exe_basename") or "an unnamed process")


# BLOCKING AN ADDRESS. REWRITTEN 2026-09-17 (task T1, "firewall truth").
#
# What stood here before, because it is the reason this is now four lines:
#
#   block_ip ran `nft add rule ... input <ip> drop` against a table this app
#   had created WITHOUT base chains. A hookless chain is never traversed, so
#   nothing was ever blocked — and neither return code was checked, so the
#   function returned {"success": True} anyway.
#
#   unblock_ip returned {"success": True} having run nothing at all, with a
#   note that said so in a field nobody reads. The adapter above then wrote
#   an audit finding: "Device unblocked at this host". Unfixing something
#   that was never fixed, reported as done.
#
# Both directions of both bugs are now the firewall module's job, where every
# action verifies itself by reading the ruleset back. This file's job is to
# pass the request through and add the one sentence the firewall module
# cannot know: what a host-level block does NOT cover.

SCOPE_NOTE = (
    "This block is enforced by THIS host's firewall only. It stops the "
    "device reaching this machine and stops this machine reaching the "
    "device. It cannot stop that device from reaching the internet or any "
    "other device on the network, because that traffic never passes through "
    "here. Only the gateway can do that."
)


def block_ip(ip: str, direction: str = "both") -> dict:
    """
    Block all traffic to/from an IP address, in both directions by default.

    Delegates to tools/iptables_manager, which picks the firewall that is
    really in charge (ufw first when it is active — see that module's
    header), names the rule so it can be removed again, and VERIFIES the
    rule exists before reporting success.
    """
    try:
        from tools import iptables_manager as fw
    except ImportError:
        return {"success": False, "error": "Firewall management not available"}

    result = fw.block_ip_address(ip, direction)
    result.setdefault("ip", ip)
    result["direction"] = direction
    if result.get("success"):
        result["scope_note"] = SCOPE_NOTE
        logger.info("Blocked IP %s (%s) via %s", ip, direction,
                    result.get("backend"))
    return result


def unblock_ip(ip: str, direction: str = "both") -> dict:
    """
    Remove this app's block rules for an address.

    Real now: it finds the rules by the AgentalSec_ marker, deletes them,
    and verifies the absence before saying so. An address with no rule of
    ours is reported as not_found, NOT as success — 'nothing needed lifting'
    and 'the lift worked' are different sentences.
    """
    try:
        from tools import iptables_manager as fw
    except ImportError:
        return {"success": False, "error": "Firewall management not available"}

    result = fw.unblock_ip_address(ip, direction)
    result.setdefault("ip", ip)
    result["direction"] = direction
    if result.get("success"):
        logger.info("Unblocked IP %s (%s) via %s", ip, direction,
                    result.get("backend"))
    return result


def quarantine_file(filepath: str) -> dict:
    """
    Move a suspicious file to quarantine.

    Creates a dated quarantine folder with manifest.

    FOUR REFUSALS ADDED 2026-09-24, each measured before it was written
    (REM-2, REM-3 and the manifest half of REM-8's shape):

      1. ONLY AN ORDINARY FILE IS MOVED. A directory, a fifo, a socket or a
         device is refused by kind. Measured: a DIRECTORY returned shutil's
         bare "[Errno 21] Is a directory" as the whole answer, and a FIFO
         NEVER RETURNED AT ALL — the hash loop opened it for reading and
         blocked until a writer appeared, inside the request.
      2. ALREADY IN THE VAULT. Measured: re-quarantining a file that was
         already staged moved it into a dated folder and OVERWROTE the only
         manifest that recorded where it came from, so a second quarantine
         made the first file's origin unrecoverable. The Windows twin has
         refused this since the port; this side did not.
      3. THE MANIFEST IS WRITTEN BEFORE THE FILE MOVES, and if it cannot be
         written the move does not happen. The old order moved first and
         wrote second, so a full disk or a permission error left a file with
         no record of where it came from — the one unrecoverable state this
         function can produce. Measured on the live store: the row that
         survives is worth more than the second it costs to reorder.
      4. THE VAULT ITSELF IS CREATED WITH THIS ACCOUNT'S OWN MODE, and the
         file's hash is recorded for the restore to compare (see
         restore_file). Nothing here trusts a directory it did not create.
    """
    try:
        src_path = Path(filepath).resolve()

        # (1) what IS this? Answered by lstat, so a symlink is itself.
        #
        # THE RESOLVE ABOVE FOLLOWS LINKS, and that is why the broken-link case
        # is checked FIRST: `Path(x).resolve()` of a symlink to a path that
        # does not exist returns the TARGET, which then fails `exists()`, so a
        # dangling link used to come back as the bare "File does not exist" —
        # true of the target and false about the thing the caller named.
        # MEASURED before the fix, and the refusal now names the link.
        raw = Path(filepath)
        if raw.is_symlink() and not raw.exists():
            return {"success": False, "refused": True,
                    "kind": "a broken symlink",
                    "error": (f"Refusing to quarantine {filepath}: it is a "
                              f"symbolic link whose target does not exist. "
                              f"There are no bytes to take, and the link "
                              f"itself is not a file that was dropped here.")}
        if not src_path.exists() and not src_path.is_symlink():
            return {"success": False, "error": "File does not exist"}

        kind, movable = _classify_source(src_path)
        if not movable:
            logger.warning(f"Refused quarantine of {src_path}: it is {kind}. "
                           f"quarantine_file moves one ordinary file.")
            return {
                "success": False, "refused": True, "kind": kind,
                "error": (f"Refusing to quarantine {src_path}: it is {kind}. "
                          f"quarantine_file moves one ordinary file and has "
                          f"an undo for exactly that. A tree has no undo, and "
                          f"a fifo or a device is not a file that was dropped "
                          f"here, reading one blocks until a writer turns "
                          f"up, which is how this call used to hang."),
            }

        # Check if in protected directory
        for protected in PROTECTED_ROOTS:
            if _is_within(src_path, protected):
                return {
                    "success": False,
                    "error": f"Cannot quarantine from protected directory: {protected}",
                }

        # Check if in project directory — the whole set of them on this
        # platform, not only the checkout this file happens to live in.
        for root in AGENTALSEC_ROOTS:
            if _is_within(src_path, root):
                return {
                    "success": False,
                    "refused": True,
                    "error": (f"Cannot quarantine {src_path}: it is inside "
                              f"{root}, which is AgentalSec's own "
                              f"installation. Moving it destroys both the "
                              f"evidence and the record of the reasoning "
                              f"that led here."),
                }

        # (2) already in a vault, new or old
        for root in staging_roots():
            if _is_within(src_path, root):
                return {
                    "success": False, "refused": True,
                    "error": (f"Refusing to quarantine {src_path}: it is "
                              f"already inside the quarantine area {root}. "
                              f"Re-quarantining rewrites the only manifest "
                              f"that records where the file came from, which "
                              f"makes restore_file unable to say where it "
                              f"belongs. Restore it first, or move it by "
                              f"hand."),
                }

        # Create quarantine directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantine_dir = STAGING_ROOT / timestamp
        try:
            _private_vault_root()
            quarantine_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as e:
            return {"success": False,
                    "error": (f"Could not create the quarantine folder "
                              f"{quarantine_dir}: {e}. Nothing was moved.")}

        # The destination must not already hold a file of this name, or the
        # move silently replaces a quarantined copy with a worse one.
        dest_path = quarantine_dir / f"{src_path.name}.quarantined"
        if dest_path.exists():
            dest_path = quarantine_dir / (
                f"{src_path.name}.{os.getpid()}.quarantined")

        # Generate hash of original file. Reading a regular file cannot
        # block; the kind check above is what makes that true.
        file_hash = hashlib.sha256()
        with open(src_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                file_hash.update(chunk)
        digest = file_hash.hexdigest()
        size = src_path.stat().st_size

        # (3) THE MANIFEST IS WRITTEN FIRST. See the docstring: the reverse
        # order can leave a moved file with no record of where it came from,
        # which is the one state restore_file cannot undo.
        manifest = {
            "original_path": str(src_path),
            "quarantine_path": str(dest_path),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sha256": digest,
            "size": size,
            "kind": kind,
            "reason": "Quarantined by AgentalSec",
            # The vault's own location travels with the file, so a manifest
            # found in an old location is still readable next to a new one.
            "staging_root": str(STAGING_ROOT),
        }

        manifest_path = quarantine_dir / "manifest.json"
        try:
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
        except OSError as e:
            return {"success": False,
                    "error": (f"Could not write the manifest {manifest_path}: "
                              f"{e}. The file was NOT moved, because a "
                              f"quarantine with no manifest is a file with no "
                              f"record of where it came from.")}

        # Move file
        shutil.move(str(src_path), str(dest_path))
        # The manifest named the destination before it existed; keep it the
        # truth if the fallback name above was taken.
        if manifest["quarantine_path"] != str(dest_path):
            manifest["quarantine_path"] = str(dest_path)
            try:
                with open(manifest_path, "w", encoding="utf-8") as f:
                    json.dump(manifest, f, indent=2)
            except OSError as e:
                logger.error(f"quarantined {src_path} but could not update "
                             f"the manifest: {e}")

        logger.info(f"Quarantined {filepath} to {dest_path}")
        return {
            "success": True,
            "original": str(src_path),
            "quarantine": str(dest_path),
            "manifest": str(manifest_path),
            "hash": digest,
            "size": size,
            "kind": kind,
        }

    except Exception as e:
        logger.error(f"quarantine_file failed: {e}")
        return {"success": False, "error": str(e)}


def _read_manifest(manifest_path: Path) -> tuple:
    """
    (manifest_or_None, reason) — and a corrupt one is a REASON, not a shrug.

    REM-9. list_quarantined used to `except Exception: pass`, so a folder
    whose manifest is unreadable disappeared from every answer with nothing
    anywhere saying so. Measured: two vault folders, one with a damaged
    manifest, list_quarantined returned 1 entry and named the damaged one
    nowhere. A quarantined file the operator cannot see is one the owner cannot
    restore, and the app cannot be asked why.
    """
    try:
        with open(manifest_path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return None, f"the manifest is not valid JSON ({e})"
    except OSError as e:
        return None, f"the manifest could not be read ({e})"
    if not isinstance(data, dict):
        return None, "the manifest is not an object"
    return data, ""


def list_quarantined() -> list:
    """
    List all quarantined files.

    Returns every manifest it can read across every vault this app has used.
    A manifest it cannot read is returned as its own entry carrying the
    reason, rather than being dropped — see _read_manifest.
    """
    quarantined = []

    for root in staging_roots():
        if not root.exists():
            continue
        for manifest_path in sorted(root.glob("*/manifest.json")):
            manifest, reason = _read_manifest(manifest_path)
            if manifest is None:
                quarantined.append({
                    "folder": manifest_path.parent.name,
                    "staging_root": str(root),
                    "manifest": str(manifest_path),
                    "unreadable": True,
                    "reason": reason,
                    "note": ("This folder IS in the vault and could not be "
                             "read, so whatever is inside it cannot be "
                             "restored from here. It is reported rather than "
                             "skipped: a quarantined file nobody can see is "
                             "one nobody can get back."),
                })
                continue
            manifest.setdefault("staging_root", str(root))
            # What the restore needs to know, decided now rather than
            # discovered at restore time: is the staged copy still there,
            # and is the original spot occupied.
            staged = manifest.get("quarantine_path") or ""
            manifest["file_present"] = bool(staged) and Path(staged).exists()
            original = manifest.get("original_path") or ""
            manifest["original_occupied"] = (True if original
                                             and Path(original).exists() else
                                             False)
            quarantined.append(manifest)

    return quarantined


def _verify_restore_digest(manifest: dict, quarantine: Path) -> tuple:
    """
    (ok, sentence) — does the file in the vault still match what was taken?

    REM-10, and this is the one that answers a question the app has been
    silent on: quarantine_file records a sha256 of the file it took and
    NOTHING EVER COMPARED IT AGAIN. Measured: a file in the vault was
    rewritten, and restore_file put the changed bytes back at the original
    path, returned success, and wrote "File restored from quarantine" — with
    the recorded digest and the file on disk seven characters apart in the
    log and nothing saying so.

    The vault is a user-writable directory. It is the one place a file waits,
    and it is exactly the place something else could touch it. So the digest
    is checked, and a mismatch does NOT refuse by default: it travels with the
    restore, because refusing would take the operator's decision away over a
    difference the operator may have caused on purpose. What it may never do
    is stay silent, so the return carries the comparison and the sentence is
    written into the action record.

    Returns ("match" | "mismatch" | "unknown", sentence).
    """
    recorded = (manifest or {}).get("sha256")
    if not recorded:
        return "unknown", ("This manifest carries no digest either, so there "
                           "is nothing to compare the file against. That is "
                           "itself worth knowing: a quarantine written before "
                           "the digest was checked looks exactly like this.")
    try:
        h = hashlib.sha256()
        with open(quarantine, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except OSError as e:
        return "unknown", f"The file could not be hashed to compare it ({e})."
    now = h.hexdigest()
    if now == recorded:
        return "match", ("The file in the vault still matches the digest "
                         "recorded when it was quarantined.")
    return "mismatch", (
        f"THE FILE IN THE VAULT HAS CHANGED SINCE IT WAS QUARANTINED. "
        f"Recorded: {recorded[:16]}... Now: {now[:16]}.... The bytes going "
        f"back to the original path are NOT the bytes that were taken. The "
        f"vault is a writable directory, so this is either the operator's own "
        f"edit or something else's. It is being reported, not refused, "
        f"because the decision to restore is yours.")


def restore_file(quarantine_path: str) -> dict:
    """
    Restore a quarantined file to its original location.

    THREE REFUSALS, and each of them was missing from this function entirely
    until 2026-09-21. They are the Windows tree's three, kept word for word in
    meaning because the reasons did not change when the platform did:

    1. THE PATH ARGUMENT IS UNTRUSTED INPUT. The quarantine area sits in a
       user-writable directory on the Desktop, so both this argument and the
       manifest's own original_path field are strings somebody can edit.
       Every path is resolved and checked to be inside STAGING_ROOT before
       anything moves.

    2. IT WILL NOT OVERWRITE. If something now exists at the original path the
       restore stops. A quarantine is usually followed by a reinstall or a
       clean copy, and silently replacing that with the suspicious original is
       a worse outcome than refusing.

    3. IT WILL NOT WRITE INTO A PROTECTED ROOT. quarantine_file would never
       have taken a file from /etc or /usr, so a manifest naming one of those
       as the destination has been edited. Refusing is the only safe answer:
       this is the asymmetry the Windows tree fixed on 2026-09-03 and this
       side still carried.

    It does not re-scan or re-judge the file. Restoring is the operator's
    decision; this executes it and records that it happened.
    """
    try:
        base = STAGING_ROOT.resolve()

        # (1) the argument must land inside the quarantine area
        try:
            quarantine = Path(quarantine_path).resolve()
        except (OSError, ValueError):
            return {"success": False,
                    "error": f"Not a resolvable path: {quarantine_path!r}."}
        # The vault is a LIST now (REM-4): a quarantine taken while this app
        # was elevated resolves to /root/... and one taken from the dashboard
        # to this account's home, and both are this app's own vault. The
        # argument must be inside one of them, and there is no third answer.
        containing = [r for r in staging_roots()
                      if _is_within(quarantine, r.resolve())]
        if not containing:
            return {"success": False,
                    "error": (f"{quarantine} is not inside a quarantine area "
                              f"({', '.join(str(r) for r in staging_roots())}). "
                              f"Refusing: pass the path list_quarantined "
                              f"reports, not one of your own.")}

        # A DATED FOLDER IS ACCEPTED TOO. REM-12, 2026-09-24.
        #
        # The tool the model actually calls takes `folder`, and its own
        # description says "Takes the dated folder name from query_quarantine"
        # — while this function took the quarantined FILE's path and, handed a
        # folder, looked for a manifest one level UP and reported "Manifest not
        # found". MEASURED: list_quarantined reports `quarantine_path` and no
        # `folder` key at all, and restore_file's own parameter is called
        # `folder`. Two names, two shapes, and only one of them worked.
        #
        # Both work now, and the folder case is resolved to the same place by
        # this rule: ONE file that is not the manifest, or a refusal naming the
        # count, because picking one of several would be a guess about what the
        # operator meant to put back.
        if quarantine.is_dir():
            candidates = [p for p in quarantine.iterdir()
                          if p.is_file() and p.name != "manifest.json"]
            if not candidates:
                return {"success": False,
                        "error": (f"No quarantined file inside {quarantine}. "
                                  f"The folder is in the vault but holds "
                                  f"nothing to restore.")}
            if len(candidates) > 1:
                return {"success": False,
                        "error": (f"{quarantine} holds {len(candidates)} "
                                  f"files. Pass the exact file to restore; "
                                  f"this will not guess which one you "
                                  f"meant.")}
            quarantine = candidates[0]

        if not quarantine.exists():
            return {"success": False, "error": "Quarantine file not found"}

        # (1 again) the manifest's own fields are as untrusted as the argument
        manifest_path = quarantine.parent / "manifest.json"
        if not manifest_path.exists():
            return {"success": False, "error": "Manifest not found"}
        manifest, reason = _read_manifest(manifest_path)
        if manifest is None:
            return {"success": False,
                    "error": (f"The manifest beside {quarantine} cannot be "
                              f"used: {reason}. Without it there is no "
                              f"original_path, so this app will not guess "
                              f"where the file belongs. Nothing was moved.")}

        original = manifest.get("original_path")
        if not original:
            return {"success": False,
                    "error": "Manifest is missing original_path."}

        # A RELATIVE PATH IS REFUSED OUTRIGHT, and the reason is not fussiness.
        # quarantine_file writes str(Path(filepath).resolve()), so every honest
        # manifest carries an ABSOLUTE path. A relative one can only have been
        # put there by hand, and Path(relative).resolve() would resolve it
        # against whatever directory this process happened to start in, which
        # is a fact about the caller and not about the file. This check was
        # missing from the first draft of this guard and a traversal test
        # caught it: "../../fake_etc/passwd" resolved clean out of the staging
        # area and the deny-root check below never saw it.
        if not Path(original).is_absolute():
            return {"success": False,
                    "error": (f"Manifest original_path is not absolute: "
                              f"{original!r}. quarantine_file only ever writes "
                              f"an absolute path, so this manifest has been "
                              f"edited. Refusing.")}

        try:
            target = Path(original).resolve()
        except (OSError, ValueError):
            return {"success": False,
                    "error": f"Manifest original_path is not a resolvable "
                             f"path: {original!r}. Refusing."}

        # (3) it is not going back into a protected root
        for root in QUARANTINE_DENY_ROOTS:
            if _is_within(target, root):
                return {"success": False,
                        "error": (f"The manifest wants this restored to "
                                  f"{target}, which is inside {root}. "
                                  f"quarantine_file would never have taken a "
                                  f"file from there, so the manifest has been "
                                  f"edited. Refusing.")}

        # (3 again) NOR BACK INTO THE QUARANTINE AREA, which would be a loop.
        #
        # THE FOURTH REFUSAL, ADDED 2026-09-21. The Windows tree carries it and
        # this side did not, and the asymmetry is worth naming because the
        # three refusals above were ported word for word with the reason
        # "because the reasons did not change when the platform did". This one
        # was simply missed. MEASURED before the fix, by driving the function
        # with a manifest pointing at STAGING_ROOT/somewhere/loop.exe: it
        # moved the file into its own quarantine area and returned success.
        #
        # A restore that lands back inside the staging area leaves a file that
        # list_quarantined still reports as quarantined while it is no longer
        # under a dated folder, so the next restore of that name cannot find
        # it. Refusing costs nothing and the operator can move it by hand.
        if _is_within(target, base):
            return {"success": False,
                    "error": (f"The manifest wants this restored back into the "
                              f"quarantine area {base}, which would be a loop. "
                              f"Refusing.")}

        # (2) and it does not overwrite whatever is there now
        if target.exists():
            return {"success": False,
                    "error": (f"Something already exists at {target}. Not "
                              f"overwriting it with the quarantined copy. Move "
                              f"it aside first if replacing it is what you "
                              f"want.")}

        # (4) DO NOT BUILD A PATH THAT WAS NOT THERE. Added 2026-09-21.
        #
        # THE SHARP END, and the reason this is a refusal rather than a
        # mkdir(parents=True). A file that was really quarantined came OUT of a
        # folder that existed, so a missing parent means the manifest is
        # describing somewhere the file never lived, and BUILDING THE PATH TO
        # MAKE IT FIT IS HOW A WRITE REACHES A NEW LOCATION.
        #
        # What used to be here created the parents unconditionally, one step
        # after the deny-root loop, and the comment claimed the ordering was
        # the fix. It was half the fix: the ordering stopped a write landing in
        # /etc, and it did nothing about a path in the operator's own home. The
        # Windows tree's rule is the whole rule, and it is right on both
        # platforms for the same reason.
        #
        # MEASURED before the fix, with the Linux module driven directly: a
        # manifest naming ~/no/such/place/thing.exe returned success, CREATED
        # all three directories, and left the quarantined file in the
        # fabricated folder. test_restore_containment.py refused to accept it
        # and is the reason it was found.
        if not target.parent.exists():
            return {"success": False,
                    "error": (f"{target.parent} does not exist. A file that was "
                              f"really quarantined came out of a folder that "
                              f"did, so this manifest is describing somewhere "
                              f"else. Refusing to create directories to make "
                              f"it fit.")}

        # (5) THE DIGEST. REM-10 — checked, reported, never silent, and never
        # a refusal on its own.
        digest_state, digest_sentence = _verify_restore_digest(manifest,
                                                               quarantine)

        shutil.move(str(quarantine), str(target))

        logger.info(f"Restored {quarantine_path} to {target}")
        result = {
            "success": True,
            "restored_to": str(target),
            "sha256_state": digest_state,
            "sha256_note": digest_sentence,
        }
        if digest_state == "mismatch":
            logger.warning(f"Restored {quarantine_path} to {target} and the "
                           f"file does NOT match the digest recorded when it "
                           f"was quarantined.")
        return result

    except Exception as e:
        logger.error(f"restore_file failed: {e}")
        return {"success": False, "error": str(e)}


def get_status() -> dict:
    """
    Get remediation capabilities status.

    REM-11, 2026-09-24: what this block said before and what it says now.
    It reported a quarantine_count and nothing about whether the VAULT is
    reachable — so a vault under a home directory that does not exist read as
    an empty quarantine, which is the "could not look" vs "nothing there"
    collapse this project collects. It now says which root it is using and
    whether that root can be written, names a legacy vault when one exists,
    and counts the entries it could NOT read (REM-9).
    """
    status = {
        "psutil_available": PSUTIL_AVAILABLE,
        "quarantine_root": str(STAGING_ROOT),
        "quarantine_root_source": _staging_root_source(),
        "quarantine_root_writable": _root_writable(STAGING_ROOT),
        "quarantine_roots_read": [str(r) for r in staging_roots()],
        "legacy_roots": [str(r) for r in legacy_staging_roots() if r.exists()],
        "quarantine_count": None,
        "quarantine_unreadable": 0,
        "self_pid": os.getpid(),
    }

    try:
        entries = list_quarantined()
        status["quarantine_count"] = len(entries)
        status["quarantine_unreadable"] = sum(
            1 for e in entries if e.get("unreadable"))
    except Exception as e:
        # None, never 0: a count of zero is a claim and this one could not be
        # made. The firewall block below already makes this distinction.
        status["quarantine_count_error"] = str(e)

    # Check firewall backend
    try:
        from tools.iptables_manager import detect_backend
        status["firewall_backend"] = detect_backend()
    except Exception:
        status["firewall_backend"] = "unknown"

    return status


def _staging_root_source() -> str:
    """Which rule chose the vault path, in words, for the status block."""
    if (os.environ.get(QUARANTINE_ENV) or "").strip():
        return f"{QUARANTINE_ENV} in the environment"
    if (os.environ.get("XDG_STATE_HOME") or "").strip():
        return "$XDG_STATE_HOME/agental_sec/quarantine"
    return "~/.local/state/agental_sec/quarantine (XDG default)"


def _root_writable(path: Path) -> bool:
    """Can this process actually put a file there. Asked, not assumed."""
    probe = path if path.exists() else path.parent
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    return os.access(probe, os.W_OK)
