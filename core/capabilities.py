# core/capabilities.py
# AgentalSec Linux, the privileged capability surface.
#
# TODO 3.1, step 2 of the Windows tree's PRIVILEGE_SPLIT_PLAN.md, and every
# operation in this app that genuinely needs rights goes through this file and
# nowhere else.
#
# THIS FILE IS THE LINUX SURFACE. THE WINDOWS ONE IS OUT OF IT. 2026-09-25.
#
# Owner's instruction, quoted: "those areas of the app that have code
# specifically for windows are unnecessary in Linux version ... Please locate
# those windows related parts of the code that are showing in the setting app
# and uninstall them."
#
# WHAT WAS REMOVED HERE, and why each one was not a feature this platform was
# missing:
#
#   win32evtlog, WIN32_AVAILABLE   pywin32 does not install here. The import
#                                  guard that made a WINDOWS CHANNEL look like
#                                  a library THIS RUN was missing is what put
#                                  "Windows Security channel" on the card.
#   security_log                   a capability row for that channel. It could
#                                  never be anything but unavailable here, at
#                                  any elevation, and the row said so in a
#                                  sentence that named event_monitor, a sensor
#                                  that was working fine at the time.
#   defender, defender_detections  Windows Defender, read by shelling out to
#                                  PowerShell. Same absence, same cost.
#   event_log_open/bounds/read/close   the four primitives behind the channel.
#                                  Nothing on Linux called any of them.
#   firewall_add/delete/list       netsh advfirewall. tools/iptables_manager is
#                                  what writes and reads rules HERE, and it is
#                                  driven by remediation_linux rather than by
#                                  this file. A netsh verb on this platform is
#                                  a privileged surface nobody can use.
#   npcap_admin_only, NPCAP_KEY    a Windows capture driver's registry setting,
#                                  read through winreg.
#   the Windows elevation tables   CANNOT_WITHOUT_ELEVATION and
#                                  LIMITED_WITHOUT_ELEVATION named netsh,
#                                  Npcap and Defender. The Linux tables below
#                                  are the ones this platform has always used.
#   MODE_INPROCESS, set_instance   the privileged-helper split: an unelevated
#                                  parent, a helper process holding the rights,
#                                  and an opaque session handle across the
#                                  boundary. That is a Windows design and its
#                                  files live in agental_sec_win32_reference/.
#                                  On Linux the rights question is answered by
#                                  capabilities on the binary, which is a
#                                  launcher property, and there is no second
#                                  process for a mode to describe.
#
# The two removed ROWS are the visible half and the reason for this round: the
# Settings card painted them, permanently, beside genuine faults, and one of
# their sentences named the event monitor -- which is what made a working
# sensor read as the broken thing on the page.
#
# THE RULE THIS FILE EXISTS TO PROTECT
#
# The privileged side never parses. It captures, reads, executes, and hands
# back raw bytes or a status. Every bit of interpretation happens on the
# unprivileged side, where a parser bug costs a user level process.
#
# So no verb below returns a decoded packet, a tidied rule list or a
# judgement. They return frames, records, text and integers, and the callers
# do what they have always done with them.
#
# WHAT THIS INTERFACE MUST REFUSE TO BE
#
# No run_command. No read_file(path). No shell string from the caller. No
# firewall rule name from the caller that we did not build ourselves.
#
# The moment this surface accepts a general instruction it stops being a
# small privileged helper and becomes a privilege escalation service with
# extra steps, which is worse than what we had before this file existed,
# because at least then nobody thought there was a boundary.
#
# SIX CAPABILITIES, SIX PRIMITIVES. THIS PLATFORM'S OWN MECHANISMS.
#
#   capture          capture_open      AF_PACKET via scapy. Needs root or
#                                      CAP_NET_RAW, and this file ASKS rather
#                                      than assumes (see the capture row).
#   firewall write   firewall_add,     tools/iptables_manager, which picks ufw,
#                    firewall_delete   nft or iptables by what is installed
#                                      and in charge. Driven by remediation,
#                                      not by this file. See the note on the
#                                      availability rows below.
#   firewall read    firewall_list
#   process kill     process_kill      signals, with a state poll rather than a
#                                      wait-for-reap (REM-7/REM-14).
#   process details  process_details   /proc fields for pids the caller could
#                                      not read.
#   connection table conn_table         psutil's socket table with the process
#                                      name resolved on the readable side.
#
# security_log's four primitives are gone with it. The platform's equivalent
# is a SENSOR rather than a capability -- tools/event_monitor_linux.py reads
# journald and the log files -- and its health is declared where every other
# sensor's is, in core/sensor_health.DEPENDS, which is the thing the model
# actually reads. A capability row here would have been a second, weaker
# declaration of the same fact.

import logging
import os
import socket as _socket

logger = logging.getLogger(__name__)

# Imported at module level, optionally, the same way the sensors do it. Two
# reasons rather than one: a missing library is answered once at import
# instead of on every call, and a test can stand a fake in the way, which is
# how the existing suite drives these code paths.
try:
    from scapy.all import sniff as _scapy_sniff
    SCAPY_AVAILABLE = True
except ImportError:
    _scapy_sniff = None
    SCAPY_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE = False

# Frames get truncated to this before crossing a boundary, once there is one.
DEFAULT_SNAPLEN = 512

# WHICH CAPABILITIES THE MACHINE REFUSES WITHOUT RIGHTS, IN LINUX WORDS.
#
# Two lists, because there are two different answers and one row cannot say
# both. A capability in the first list does not work at all unelevated. A
# capability in the second works, on a smaller set of things, and saying it is
# unavailable would be as wrong as saying it is fine.
#
# The Windows tree's version of these two tables named netsh, Npcap and
# Defender's cmdlets. They were removed with those capabilities; these are the
# rows that were already being used on this platform, unchanged apart from a
# corrected comment about what the read row needs.
CANNOT_WITHOUT_ELEVATION = {
    "firewall_write": "ufw, nft and iptables all refuse to change the ruleset",
    "capture": "AF_PACKET cannot be opened without root or CAP_NET_RAW, so "
               "there will be no packet rows",
}

# Reading is NOT always free on Linux the way it was under netsh: `ufw status`
# requires root, and `nft list ruleset` and `iptables -S` also require root to
# read the live ruleset. So the read row is unavailable-or-limited unelevated
# and the firewall module already reports the same thing in its own words. Two
# surfaces, one answer.
LIMITED_WITHOUT_ELEVATION = {
    "process_kill": "only processes this user owns. Ending a system service "
                    "or another user's process needs root",
    "process_details": "command lines and executable paths for other users' "
                       "processes stay empty, because /proc only exposes "
                       "those to their owner or root",
    "conn_table": "only this user's sockets are listed. Other users' and "
                  "root's connections need root to see",
}

# A ceiling on process_details, so one bad caller cannot turn one call into
# thousands of privileged reads. Higher than any real machine's process count.
MAX_DETAIL_PIDS = 2048


class CapabilityError(Exception):
    """The request was refused. Bad arguments, or a rule we do not own."""


class CapabilityUnavailable(Exception):
    """
    The capability cannot run here at all: a missing library or no rights.

    Kept apart from CapabilityError on purpose. "I refused this" and "I could
    not do this" are different sentences to put in front of somebody, and
    collapsing them is how a machine with no scapy ends up looking like a
    quiet network.
    """


def open_pidfd(proc):
    """
    A pidfd for exactly this psutil.Process, or None where the kernel or
    Python has none. A signal through it cannot reach a recycled pid (REM-16).

    The start time is compared AFTER the fd is open: if the pid was reused in
    between, the fd names the new process and the open is refused.
    """
    if not hasattr(os, "pidfd_open"):
        return None
    try:
        fd = os.pidfd_open(proc.pid)
    except ProcessLookupError:
        raise psutil.NoSuchProcess(proc.pid)
    except OSError:
        return None
    try:
        same = psutil.Process(proc.pid).create_time() == proc.create_time()
    except psutil.NoSuchProcess:
        os.close(fd)
        raise
    if not same:
        os.close(fd)
        raise CapabilityError(
            f"PID {proc.pid} was reused by another process before it could be "
            f"pinned. Refusing: this is not the process that was chosen.")
    return fd


def pidfd_signal(proc, fd, sig):
    """Send through the pidfd when there is one, else through psutil."""
    import signal as _signal
    if fd is None:
        proc.send_signal(sig)
        return
    try:
        _signal.pidfd_send_signal(fd, sig)
    except ProcessLookupError:
        raise psutil.NoSuchProcess(proc.pid)
    except PermissionError:
        raise psutil.AccessDenied(proc.pid)


def _int_arg(name, value, low, high):
    try:
        out = int(value)
    except (TypeError, ValueError):
        raise CapabilityError(f"{name} must be an integer, got {value!r}")
    if not low <= out <= high:
        raise CapabilityError(f"{name} must be between {low} and {high}, got {out}")
    return out


class Capabilities:
    """
    The whole privileged surface. One instance, from get().

    Every method is small on purpose. If one of them starts growing options,
    that is the signal it is turning into a general instruction, which is the
    thing at the top of this file we said we would not build.
    """

    # WHAT IS ACTUALLY AVAILABLE

    def availability(self) -> dict:
        """
        Per capability: can this run here, and if not, what is missing.

        Written for the readiness card. A capability that is unavailable has
        to be able to SAY so, in words, or the app degrades quietly, which is
        the one failure mode this codebase cannot have.

        EVERY ROW HERE IS A CAPABILITY THIS PLATFORM HAS. There is no
        "not on this platform" kind any more and no row carrying one: the two
        that used to (the Windows Security channel, Defender) were removed
        from this file on 2026-09-25 with their verbs. A row that can only
        ever say "this does not exist here" is not information about this
        machine, and on the card it was a permanent amber line beside the
        faults that matter.
        """
        out = {}
        out["capture"] = (SCAPY_AVAILABLE, None if SCAPY_AVAILABLE
                          else "scapy is not installed, so no adapter can be "
                               "opened and there will be no packet rows")
        for name in ("process_kill", "process_details", "conn_table"):
            out[name] = (PSUTIL_AVAILABLE, None if PSUTIL_AVAILABLE
                         else "psutil is not installed")

        # THE FIREWALL ROWS ARE DERIVED, NOT ASSUMED. 2026-09-17, T1.
        #
        # The firewall module can say, right now, which backend exists and
        # whether the ruleset can be read -- so this asks it rather than
        # guessing. Two hardcoded True rows here would have contradicted the
        # tool's own answer on the same screen.
        out["firewall_write"] = (True, None)
        out["firewall_read"] = (True, None)

        try:
            from tools import iptables_manager as _fw
            _detail = _fw.detect_backend_detail()
            _listing = _fw.list_agental_rules_status()
            # A BACKEND EXISTING IS NOT PERMISSION TO USE IT.
            #
            # Found 2026-09-21 by running test_capability_shim, which asks
            # every unavailable capability to say what is missing. This row
            # was derived as `_detail["backend"] != "none"` and that is a
            # statement about what is INSTALLED: ufw, nft and iptables were
            # all present on this host, so the row read available with
            # why_not=None, on a process running unelevated where all three
            # refuse to change the ruleset. The operator's own firewall tool
            # said "not elevated" two rows away (firewall_read, which reads
            # the same ruleset and correctly reported it could not).
            #
            # That is the direction this file's own comment calls the worse of
            # the two: a false "you can do this" costs a failed action. So the
            # row is derived from whether a rule can actually be WRITTEN, which
            # is what the capability promises, and the sentence names the
            # missing right.
            _can_write = bool(_detail.get("backend")
                              and _detail["backend"] != "none")
            # BOTH HALVES ARE ASKED, ALWAYS, and this is the fix for the
            # second thing that test found. The first version branched: no
            # backend gave one sentence, a backend with no rights gave
            # another. Inside the suite the backend probe can come back "none"
            # on a host where ufw IS installed (the tool decides from what it
            # can read at that moment), so the row reported only "no backend"
            # while the process was ALSO unelevated and the rights question
            # was the one that mattered to a reader looking at why their block
            # failed.
            #
            # So the rights answer is attached whenever it is missing,
            # independently of the backend sentence. A capability blocked for
            # two reasons says both, in the order the operator would hit them.
            from core import privilege_linux as _priv
            _elevated = True
            try:
                _elevated = bool(_priv.is_elevated())
            except Exception:
                _elevated = True        # cannot tell: do not claim a fault
            _why_write = None
            if not _can_write:
                _why_write = (
                    "no firewall backend this app can drive (ufw, nft and "
                    "iptables were all unavailable)")
            if not _elevated:
                _rights = ("not elevated: ufw, nft and iptables all refuse "
                           "to change the ruleset")
                _why_write = (f"{_why_write}. {_rights}"
                              if _why_write else _rights)
                _can_write = False
            out["firewall_write"] = (_can_write, _why_write)
            out["firewall_read"] = (
                _listing["readable"],
                None if _listing["readable"] else
                f"the ruleset could not be read ({_listing['reason']}). "
                f"Reading the rule list needs root here, so an empty list "
                f"from this app is no information about what is blocked")
        except Exception as e:              # pragma: no cover
            # THE ROWS STAY, SAYING THEY COULD NOT BE DERIVED. The version
            # before this left the optimistic `True` rows standing when the
            # derivation failed, which is the worse of the two directions: a
            # firewall that cannot be read would have reported itself
            # available on the strength of a hardcoded default nobody
            # rechecked. A false "you can do this" costs the operator a failed
            # action; a false "I could not tell" costs them a look.
            logger.warning(f"Could not derive the firewall rows: {e}")
            out["firewall_write"] = (
                False, f"the firewall module could not be asked ({e}), so "
                       f"whether a rule can be written is UNKNOWN rather "
                       f"than yes")
            out["firewall_read"] = (
                False, f"the firewall module could not be asked ({e}), so "
                       f"the rule list could not be read. An empty list "
                       f"here is no information about what is blocked")

        rows = {k: {"available": v[0], "why_not": v[1], "limited": None}
                for k, v in out.items()}

        # IS THE LIBRARY THERE is only half the question. The other half is
        # whether this machine will let us, and the first version of this
        # method only asked the first half. It reported all eight available on
        # an unelevated run, directly under a row saying three modules were
        # unavailable for want of rights. Two rows, one card, contradicting
        # each other, which is worse than no card.
        elevated = None
        try:
            from core import privilege_linux
            elevated = privilege_linux.is_elevated()
        except Exception as e:                      # pragma: no cover
            logger.debug(f"Could not read elevation: {e}")

        # WHICH SENTENCE NAMES THIS PLATFORM. There is one map per direction
        # now rather than one per platform: the Windows tables left with the
        # Windows capabilities, so there is nothing here that can print a
        # netsh sentence on a Linux host.
        for name, row in rows.items():
            if not row["available"]:
                continue                            # a missing library wins

            if elevated is False and name in CANNOT_WITHOUT_ELEVATION:
                row["available"] = False
                row["why_not"] = (
                    f"not elevated: {CANNOT_WITHOUT_ELEVATION[name]}")
            elif elevated is False and name in LIMITED_WITHOUT_ELEVATION:
                row["limited"] = ("not elevated, so "
                                  + LIMITED_WITHOUT_ELEVATION[name])
            elif elevated is None:
                row["limited"] = ("elevation could not be determined on this "
                                  "platform, so this may be narrower than it "
                                  "looks")

        # WHY EACH ROW IS IN THE STATE IT IS IN, AS A FIELD.
        #
        # Added 2026-09-25 with the row-truth round, and KEPT after the
        # Windows rows were removed from this file, because it is the thing
        # that stopped three consumers from each guessing: no consumer decides
        # a row's state from the wording of a why_not sentence. The set is
        # three values here rather than four; see the note on availability().
        for name, row in rows.items():
            if not row["available"]:
                row["kind"] = "unavailable"
            elif row["limited"]:
                row["kind"] = "limited"
            else:
                row["kind"] = "available"
        return rows

    # 1. CAPTURE

    def capture_open(self, on_frame, bpf="ip", timeout=30, iface=None,
                     snaplen=DEFAULT_SNAPLEN):
        """
        Capture for `timeout` seconds, calling on_frame for each frame.

        Returns nothing. Blocks for the timeout, same as the sniff call it
        replaces, so the caller keeps its own loop and its own thread.

        snaplen is accepted and IGNORED today, deliberately. There is no
        process boundary yet, so truncating a frame after scapy already built
        it in our own memory buys nothing, and scapy's sniff has no snaplen
        argument to pass it down to. It is in the signature so the call sites
        do not have to change again later.
        """
        if _scapy_sniff is None:
            raise CapabilityUnavailable(
                "scapy is not installed, so no adapter can be opened")

        kwargs = {"prn": on_frame, "store": False, "timeout": timeout,
                  "filter": bpf}
        if iface:
            kwargs["iface"] = iface
        _scapy_sniff(**kwargs)

    # 2. KILL A PROCESS

    def process_kill(self, pid, expected_name, wait=5, expected_started=None):
        """
        Terminate a process, but only if it is still the one the caller meant.

        The name is re-checked HERE, against the live process, immediately
        before the kill. The caller already checks it too, and that check is
        not redundant: the gap between the operator reading the approval card
        and this line running is however long they took to think, and pids are
        recycled. The caller's check protects the decision, this one protects
        the action.

        The critical-process denylist stays in the caller. It is policy, and
        policy belongs on the unprivileged side where it can be read and
        argued with.

        CORRECTED 2026-09-24, REM-14.

        THIS PRIMITIVE CARRIED REM-7 AND REM-1 ONE LAYER DOWN, and it is the
        layer the register's own rule points at: a PRIVILEGED operation must go
        through this shim. It had the same two defects the module had, and it
        is the version an audit will find first, so both are fixed here too and
        asserted in tests/test_remediation_fixes.py [REM-14].

          REM-1  no self-guard. `process_kill(os.getpid(), ...)` ended the
                 calling process. The module now refuses before this is
                 reached, but "the caller checks" is the exact argument this
                 project has recorded as not holding: this primitive is the
                 boundary and a boundary that trusts its caller is not one.
          REM-7  `proc.wait(timeout=wait)` waits to REAP a process this shim
                 did not start, which only its real parent may do. On Linux
                 that can never return for a live non-child, so 5 s of the
                 caller's thread was spent producing a `forced: True` verdict
                 that was not about the process at all. Measured against the
                 module's own former behaviour: 20 s per kill.

        The confirmation is a STATE poll now, for the same reason it is in the
        module: the question is "is this pid running something", not "has its
        parent buried it". A zombie answers no.
        """
        if psutil is None:
            raise CapabilityUnavailable("psutil is not installed")

        pid = _int_arg("pid", pid, 1, 2 ** 31)

        # REM-1, one layer down. os.getpid() is the fact; nothing here builds
        # a sentence out of the process's own name, which is what made the
        # module's first version of this guard die of a RecursionError.
        if pid == os.getpid():
            raise CapabilityError(
                f"pid {pid} is the process making this call. Refusing: the "
                f"privileged boundary does not end its own caller.")
        try:
            if pid == os.getppid():
                raise CapabilityError(
                    f"pid {pid} is the parent of this process. Refusing: that "
                    f"is the surface the operator is reading, and ending it "
                    f"ends the app with it.")
        except AttributeError:                      # not POSIX; the caller's
            pass                                    # own guards still apply

        proc = psutil.Process(pid)
        live_name = proc.name()
        if expected_name and live_name.lower() != str(expected_name).lower():
            raise CapabilityError(
                f"PID {pid} is now {live_name!r}, not {expected_name!r}. "
                f"Refusing: the PID was recycled between the decision and "
                f"the kill, so this is a different process.")
        # The start time is the exact identity; a name can repeat (REM-16).
        if expected_started is not None and \
                abs(proc.create_time() - float(expected_started)) > 0.01:
            raise CapabilityError(
                f"PID {pid} started at a different time than the process the "
                f"caller chose. Refusing: the PID was recycled.")

        # A process that is already dead is not a kill. See the module's
        # _confirm_gone for why a zombie counts as gone.
        try:
            status = proc.status()
        except psutil.NoSuchProcess:
            raise CapabilityError(f"PID {pid} no longer exists.")
        if status in ("zombie", "dead"):
            raise CapabilityError(
                f"PID {pid} is already {status}: it has been ended and its "
                f"parent has not reaped it. There is nothing left to kill.")

        import signal as _signal
        fd = open_pidfd(proc)
        forced = False
        try:
            pidfd_signal(proc, fd, _signal.SIGTERM)
            gone, last = self._confirm_gone(proc, wait)
            if not gone:
                forced = True
                pidfd_signal(proc, fd, _signal.SIGKILL)
                gone, last = self._confirm_gone(proc, wait)
        finally:
            if fd is not None:
                os.close(fd)
        if not gone:
            raise CapabilityError(
                f"PID {pid} is still {last} after SIGTERM and SIGKILL. "
                f"It is alive; this is not 'probably fine'.")
        if forced:
            return {"killed": True, "name": live_name, "forced": True,
                    "status": last}
        return {"killed": True, "name": live_name, "forced": False,
                "status": last}

    @staticmethod
    def _confirm_gone(proc, timeout):
        """
        (gone, last_status) — poll the STATE, never wait for reaping.

        REM-7/REM-14. `psutil.Process.wait()` asks the OS for a child's exit
        status, which only the process's real parent may collect: for a pid
        this app did not start it cannot return, so a timeout there was
        measuring the wrong thing. A zombie is gone for the purpose of "did
        this process end", which is the question a kill has to answer.
        """
        import time as _time
        end = _time.monotonic() + max(0.2, float(timeout))
        interval = 0.02
        last = "unknown"
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

    # 3. PROCESS DETAILS

    def process_details(self, pids):
        """
        exe, command line and owner for processes the caller could not read.

        Reading these for a process owned by another account needs rights.
        Your own processes are readable by you, so the caller enumerates first
        and asks here only about the ones that came back empty, which on a
        normal machine is a short list and often none at all.

        A read, not an action. It takes pids and returns strings, it cannot
        change anything, and it is the smallest thing that keeps a process
        finding useful on a shared machine. A finding that says the daemon's
        name and nothing else is not worth raising.

        Missing processes are simply absent from the answer. A process that
        exited between the caller's list and this call is ordinary, not an
        error.
        """
        if psutil is None:
            raise CapabilityUnavailable("psutil is not installed")
        if not isinstance(pids, (list, tuple, set)):
            raise CapabilityError(f"pids must be a list, got {type(pids).__name__}")
        if len(pids) > MAX_DETAIL_PIDS:
            raise CapabilityError(
                f"at most {MAX_DETAIL_PIDS} pids per call, got {len(pids)}. "
                f"That is more processes than a machine has, so this is a "
                f"caller with a bug rather than a caller with a big list.")

        out = {}
        for raw in pids:
            pid = _int_arg("pid", raw, 1, 2 ** 31)
            try:
                p = psutil.Process(pid)
                out[pid] = {"exe": p.exe(),
                            "cmdline": p.cmdline(),
                            "username": p.username()}
            except Exception:
                # NoSuchProcess, AccessDenied even here, or a protected
                # system process. Absent means not readable, and the caller
                # already treats an empty field as unknown.
                continue
        return out

    # 4. THE CONNECTION TABLE

    def conn_table(self):
        """
        Raw socket rows: protocol number, local port, pid, and the process
        name for that pid where it can be read.

        No arguments, so there is nothing to abuse.

        The name is resolved here rather than in the caller for one reason:
        /proc exposes another user's socket owners to root, so a caller that
        cannot read them would attach a pid with no name beside it. Doing it on
        this side keeps attribution working, and a name is not a parse.
        """
        if psutil is None:
            raise CapabilityUnavailable("psutil is not installed")

        rows = []
        names = {}
        for c in psutil.net_connections(kind="inet"):
            laddr = getattr(c, "laddr", None)
            port = getattr(laddr, "port", None) if laddr else None
            # PID 0 IS NOT A PROCESS, it is the kernel saying it will not tell
            # you. Found on the first real run of the Windows helper,
            # 2026-09-08: 109 sockets came back and some carried pid 0.
            #
            # This matters beyond a tidy list. These rows feed the packet to
            # process attribution, and a socket mapped to pid 0 would attach
            # a process id that does not exist to real packets, with no name
            # beside it. NULL there already means NOT ATTRIBUTED and is
            # honest. A zero is not.
            if not port or not c.pid:
                continue
            if c.type == _socket.SOCK_STREAM:
                proto = "TCP"
            elif c.type == _socket.SOCK_DGRAM:
                proto = "UDP"
            else:
                continue
            if c.pid not in names:
                try:
                    names[c.pid] = psutil.Process(c.pid).name()
                except Exception:
                    names[c.pid] = None
            rows.append({"proto": proto, "port": port, "pid": c.pid,
                         "name": names[c.pid]})
        return rows


_INSTANCE = None


def get():
    """
    The one instance.

    A plain Capabilities, and there is no second kind on this platform. The
    Windows tree swapped in a helper-backed surface here; that design, its
    protocol and its client all live in agental_sec_win32_reference/ now. On
    Linux the rights a sensor needs are granted to the BINARY (a capability,
    a group, or a launcher that asks for a password), so there is nothing for
    this process to swap and nothing that can go stale behind it.
    """
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = Capabilities()
    return _INSTANCE
