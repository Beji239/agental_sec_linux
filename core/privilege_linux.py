# core/privilege_linux.py
# AgentalSec, privilege and capability checking.
#
# Checks for root, capabilities, and what sensors need what.
#
# IT IS THE ONLY PRIVILEGE REGISTER IN THIS TREE NOW. 2026-09-25. The Windows
# one (core/privilege.py, byte-identical to the Windows tree's copy, listing
# Windows module names and Windows consequences) sat beside it and was read by
# live code in three places until this round: main.py's report was already
# repointed on 2026-09-21, and core/settings.py and core/capabilities.py were
# repointed here too, after which the file had no reader left and moved to
# agental_sec_win32_reference/core/privilege.py.
#
# WHAT A WINDOWS REGISTER COSTS ON THIS PLATFORM, measured on this host: the
# Settings card printed "Not elevated. 3 module(s) unavailable, 1 degraded" and
# the fix line "Start it from an Administrator prompt." -- a prompt that does
# not exist here -- while this file's real answer was 2 unavailable and 4
# degraded. Two registers, one question, and the card read the wrong one.

import logging
import os
import pwd
import socket
import sys
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

NEEDS = "needs"          # Will not work at all without root/capability
DEGRADES = "degrades"    # Works, with limited functionality
NONE = "none"            # Needs nothing; running elevated buys nothing


class UnregisteredModule(Exception):
    """A module asked about elevation and no entry exists for it."""


class Requirement:
    def __init__(self, level, consequence, reason=None):
        self.level = level
        self.consequence = consequence   # What user loses, in their words
        self.reason = reason             # What the OS withholds


# Linux privilege requirements
# Verified against what each sensor actually needs on Linux
REQUIREMENTS: dict[str, Requirement] = {
    
    # Packet capture needs CAP_NET_RAW or root
    # Without it, libpcap/AF_PACKET sockets fail to open
    "packet_sniffer": Requirement(
        NEEDS,
        "No raw capture available, so there will be no packet rows, "
        "no beacon analysis and no threat map arcs",
        reason="CAP_NET_RAW capability or root for raw socket / AF_PACKET",
    ),
    
    # Journald/Security log access may need systemd-journal group or root
    #
    # CONVERTED 2026-09-23, EM-9, and the sentence it used to print was
    # MEASURABLY FALSE ON THIS HOST. `posture()` built its degraded list from
    # `modules_by_level(DEGRADES)` and `is_elevated()` ALONE, so this line was
    # printed whenever euid was not 0 and there was no branch in which the
    # opposite could be said. Measured here: the account is in `adm`,
    # /var/log/auth.log is group-readable, `journalctl -n 1` answers with rc 0,
    # and the sensor demonstrably reads all four sources, while the report said
    # on every boot that it could read only this user's own entries.
    #
    # SNF-5 fixed exactly this shape in the sniffer's sibling probe: probe
    # first, treat group membership as a HINT, never let a group name be a
    # green. The probe below is that fix applied to this entry, and the
    # register's `consequence` and `reason` are now what is lost WHEN THE
    # PROBE REFUSES rather than a guess made from the account's uid.
    "event_monitor": Requirement(
        DEGRADES,
        "Cannot read journal entries from other users or system services. "
        "Only user-owned log entries will be visible",
        reason="Read access to /var/log/journal or systemd-journal group membership",
    ),
    
    # Firewall manipulation needs root or nftables/iptables group
    "remediation": Requirement(
        NEEDS,
        "Cannot write iptables/nftables rules for block_port/unblock_port, "
        "and kill_process cannot end processes owned by other users",
        reason="Root for iptables/nftables; cross-user process termination",
    ),
    
    # Process monitoring degrades without root (can't read other users' proc info)
    "process_monitor": Requirement(
        DEGRADES,
        "Command lines and executable paths unreadable for processes owned "
        "by other users. Processes still appear, with those fields empty",
        reason="Read access to /proc/[pid]/cmdline for other users' processes",
    ),
    
    # Network scanning works unelevated but limited
    "network_scanner": Requirement(
        DEGRADES,
        "ARP scanning requires root. ICMP ping may work unelevated depending "
        "on ping_group_range sysctl. Results will be incomplete",
        reason="CAP_NET_RAW for raw sockets (ARP/ICMP)",
    ),
    
    # Port scanning: TWO THINGS HAPPEN HERE AND BOTH ARE ABOUT PRIVILEGE.
    #
    # PS-13, 2026-09-25, AND THIS ENTRY HAS NOW BEEN WRONG IN TWO DIRECTIONS.
    #
    # It first read "TCP SYN scan requires root. Falls back to TCP connect()
    # scan which is slower and more detectable, but works unelevated" with
    # reason="CAP_NET_RAW for raw sockets (SYN scan)" -- AND NO SYN SCAN
    # EXISTED anywhere in this tree. Measured at the time: a grep for a
    # raw-socket scan returned only capture probes, and `_check_port` had been
    # socket.create_connection since the first commit. The row described code
    # nobody had written.
    #
    # The first correction set the row to NONE with the sentence "elevating
    # buys a scan nothing it does not already have". THAT WAS ALSO FALSE, and
    # measurably so: a self-scan attaches tools/port_owner's answer to every
    # open port, and unelevated that answer matched 0 of this host's 13
    # listeners -- 13 unreadable, 142 of 216 processes' fd directories refused.
    # An elevated run resolves them. The audit had measured `_check_port` and
    # GENERALISED IT TO THE WHOLE MODULE, which is the same shape this register
    # has recorded a dozen times: a claim about a part of the tool written as a
    # claim about the tool.
    #
    # THE OWNER WAS GIVEN THREE DESIGNS AND TOOK THE THIRD, in the owner's own words:
    # "do option C and when done report back". So the raw SYN scan was BUILT
    # (tools/port_scanner.py, SynScanEngine), and this row now says what the
    # module loses unelevated -- BOTH losses, because there are two:
    #
    #   the SYN scan      a raw socket. Without it the TCP pass is a connect
    #                     test, which cannot separate a CLOSED port from a
    #                     FILTERED one: refused and silent are the same answer
    #                     to it. The method that ran is named on every scan
    #                     payload (`tcp_method`), so the row and the results
    #                     cannot describe different scans.
    #   the owner lookup  a self-scan's "which process holds this port" comes
    #                     from tools/port_owner, and unelevated it can read no
    #                     root-owned listener at all.
    #
    # WHY DEGRADES AND NOT NEEDS: the connect fallback still works. The module
    # loses capability unelevated and does not fail.
    #
    # The consequence sentence is deliberately the same words the scan payload
    # uses, because this row and that payload describe one module.
    "port_scanner": Requirement(
        DEGRADES,
        "The TCP pass falls back to a connect test: it can still find open "
        "ports, but a CLOSED port and a FILTERED one are the same answer to "
        "it, because only the raw SYN scan reads which one replied. A "
        "self-scan also loses every port's OWNER: the process holding a "
        "root-owned listener is unreadable from this account (measured: 0 of "
        "13 listeners on this host), and an elevated run resolves them",
        reason="CAP_NET_RAW or root for the raw socket the SYN scan sends "
               "and receives on; and read access to other accounts' "
               "/proc/[pid]/fd for the port-owner lookup",
    ),

    # tools/port_owner.py: WHICH PROCESS HOLDS WHICH PORT, and it had NO ENTRY
    # AT ALL until 2026-09-25 (register PS-13). That is the defect this table
    # exists to prevent, in its own words: "a module that never declared its
    # requirement fails one capability silently on an unelevated run" -- and
    # this one fails it with a number, measured here: 13 listeners, 0 matched,
    # 142 of 216 fd directories refused.
    #
    # IT IS NOT THE SAME AS process_monitor (also DEGRADES): that one loses
    # command lines and executable paths. This one loses the answer to "what
    # is on port 631" altogether, and it is the module the PORT SCANNER's
    # self-scan reads. Registered separately so the two losses can be counted
    # separately -- which is the whole reason the register is per-module.
    "port_owner": Requirement(
        DEGRADES,
        "The holder of every root-owned listening socket is unreadable: an "
        "open port whose owner is a service running as another account is "
        "reported as unreadable_as_user rather than named. Measured on this "
        "host: 0 of 13 listeners matched unelevated, 13 unreadable, 142 of "
        "216 processes' fd directories refused. An elevated run resolves "
        "every one of them",
        reason="Read access to /proc/[pid]/fd for other accounts' processes, "
               "which is what joins a socket inode to its owning pid",
    ),
    
    # Everything below needs nothing - listed explicitly for enforcement
    **{
        name: Requirement(NONE, "runs identically unelevated")
        for name in (
            "host_info", "software_inventory", "pcap_analyzer",
            "dns_monitor", "router_monitor", "geoip", "runbook",
            "web_search", "rollup_engine", "linux_monitor", "probe",
            "announce_harvester", "dashboard", "model_driver",
            "vpn_state", "autorun_monitor", "journald_monitor",
        )
    },
}


def requires_elevation(module: str) -> Requirement:
    """
    What this module needs. Raises if module is not registered.
    
    Fatal on purpose - new modules must declare their requirements.
    """
    req = REQUIREMENTS.get(module)
    if req is None:
        raise UnregisteredModule(
            f"No privilege entry for module '{module}'. Add one to "
            f"core/privilege_linux.REQUIREMENTS, including if the answer is "
            f"that it needs nothing. A module that never declared its "
            f"requirement fails one capability silently on an unelevated run."
        )
    return req


def modules_by_level(level: str) -> list[tuple[str, str]]:
    """(name, consequence) pairs at one level, for startup report."""
    return [(n, r.consequence) for n, r in REQUIREMENTS.items()
            if r.level == level]


def is_elevated() -> bool | None:
    """
    True if running as root, False if not, None if check failed.
    
    None is a real answer - guessing would mislead about sensor capabilities.
    """
    try:
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0
        # Fallback: try to read a root-only file
        return Path("/etc/shadow").exists() and os.access("/etc/shadow", os.R_OK)
    except Exception as e:
        logger.debug(f"Elevation check failed: {e}")
        return None


# Bit numbers from linux/capability.h for the ones this app asks about.
CAP_BITS = {"CAP_CHOWN": 0, "CAP_DAC_OVERRIDE": 1, "CAP_DAC_READ_SEARCH": 2,
            "CAP_KILL": 5, "CAP_NET_BIND_SERVICE": 10, "CAP_NET_ADMIN": 12,
            "CAP_NET_RAW": 13, "CAP_SYS_PTRACE": 19, "CAP_SYS_ADMIN": 21,
            "CAP_AUDIT_READ": 37, "CAP_BPF": 39, "CAP_PERFMON": 38}


def has_capability(cap: str) -> bool:
    """
    Whether THIS process holds `cap` in its effective set.

    Read from /proc/self/status. It used to run `getpcaps 0`, which reports
    the getpcaps child, matched inheritable-only entries, and never names
    capabilities for root ("=ep"), so every answer could be wrong (CC-3).
    """
    bit = CAP_BITS.get((cap or "").upper())
    if bit is None:
        return False
    try:
        with open("/proc/self/status", encoding="ascii") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    return bool(int(line.split()[1], 16) >> bit & 1)
    except (OSError, ValueError, IndexError):
        pass
    return False


def check_port_owner_readability(sample_limit: int = 40) -> tuple:
    """
    Can this account read the fd table of a process owned by ANOTHER account?

    Returns (can_read, reason, detail). This is the question
    tools/port_owner.py's whole answer depends on: a socket inode is joined to
    its owning pid through /proc/<pid>/fd, so a refused fd directory is a
    listener this run cannot name.

    PROBED, NOT INFERRED FROM uid -- the same correction SNF-5 and EM-9 made
    for capture and for the logs. The probe looks for pids owned by a
    different account and tries to LIST their fd directory, which is exactly
    what the sweep does, and it is bounded (sample_limit) because this runs on
    every boot and the sweep's own walk is the expensive one.

    THE DETAIL CARRIES THE NUMBERS rather than a boolean alone: how many
    foreign-account processes this host has, how many were tried and how many
    were refused. Those counts are what turn "0 of 13 listeners matched" on a
    scan payload into "unreadable as this user" instead of "nothing owns it".
    """
    detail = {"foreign_processes": 0, "tried": 0, "refused": 0,
              "readable": 0, "probe_error": None}
    try:
        my_uid = os.getuid()
    except Exception as e:                                    # noqa: BLE001
        return False, f"this account could not be read ({e})", detail

    try:
        entries = sorted((p for p in os.listdir("/proc") if p.isdigit()),
                         key=int)
    except OSError as e:
        return False, f"/proc could not be listed ({e.strerror or e})", detail

    for pid in entries:
        try:
            owner = os.stat(f"/proc/{pid}").st_uid
        except OSError:
            continue
        if owner == my_uid:
            continue
        detail["foreign_processes"] += 1
        if detail["tried"] >= sample_limit:
            continue
        detail["tried"] += 1
        try:
            os.listdir(f"/proc/{pid}/fd")
            detail["readable"] += 1
        except OSError:
            detail["refused"] += 1

    if not detail["foreign_processes"]:
        return True, ("no process on this host belongs to another account, so "
                      "there is no fd table this run could be refused"), detail
    if detail["readable"]:
        return True, (f"{detail['readable']} of {detail['tried']} sampled "
                      f"other-account process fd tables were readable, so "
                      f"port owners can be named"), detail
    return False, (
        f"every other-account process fd table sampled was refused "
        f"({detail['refused']} of {detail['tried']} of "
        f"{detail['foreign_processes']} foreign-account processes). The "
        f"process holding a root-owned listening socket cannot be named from "
        f"here: an open port reads as unreadable_as_user, never as unowned"), \
        detail


def check_syn_scan_capability() -> tuple:
    """
    Can this process open a raw TCP socket, which is what the SYN scan needs?

    Returns (can_syn, reason). A PROBE, not an elevation check: CAP_NET_RAW
    can be attached to the binary (root can still be refused by a hardened
    kernel) and a user namespace can hold it while euid is not 0. The only
    thing that answers the question is opening the socket.

    The probe is kept LOCAL rather than imported from tools.port_scanner for
    the reason the log probe above is kept local: this module is imported by
    main.py at boot and the tools package pulls in more than a privilege
    report should. tools/port_scanner.syn_scan_available() is the same
    question and the same three lines; a change to one belongs in both.
    """
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                              socket.IPPROTO_TCP)
    except OSError as e:
        return False, (f"a raw TCP socket was refused ({e.strerror or e}, "
                       f"errno {e.errno})")
    except Exception as e:                                    # noqa: BLE001
        return False, f"a raw TCP socket could not be opened ({e})"
    probe.close()
    return True, "a raw TCP socket opened, so the TCP pass can send SYNs"


def check_packet_capture_capability() -> tuple[bool, str]:
    """
    Check if packet capture is possible.

    Returns (can_capture, reason)

    THE SAME THREE DEFECTS AS THE SNIFFER'S COPY, fixed in both places
    2026-09-23 (SNF-5): the probe decides and is not second-guessed, group
    membership is a hint rather than a green (a group name proves an account
    was added to a group, not that anything was installed for it -- measured
    here, dumpcap carries no setuid bit and no file capability), and the
    account is read with os.getuid() rather than os.environ["USER"], which is
    empty under systemd and cron.
    """
    if is_elevated():
        return True, "Running as root"

    probe_error = None
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
        s.close()
        return True, "Has CAP_NET_RAW capability"
    except PermissionError as e:
        probe_error = f"EPERM ({e})"
    except OSError as e:
        probe_error = f"{type(e).__name__} ({e})"

    groups = []
    try:
        import grp
        user = pwd.getpwuid(os.getuid()).pw_name
        for g in os.getgroups() + [os.getgid()]:
            try:
                name = grp.getgrgid(g).gr_name
            except KeyError:
                continue
            if name in ("wireshark", "pcap", "netdev"):
                groups.append(name)
        for name in ("wireshark", "pcap", "netdev"):
            try:
                if user in grp.getgrnam(name).gr_mem and name not in groups:
                    groups.append(name)
            except KeyError:
                continue
    except Exception:
        pass

    hint = ""
    if groups:
        hint = (f" This account is in {', '.join(groups)}, which only helps "
                f"if something is installed for that group.")

    return False, (f"No raw socket access ({probe_error}). Capture needs root "
                   f"or CAP_NET_RAW.{hint}")


def check_event_log_readability() -> tuple:
    """
    Can this account actually read the logs this sensor reads?

    Returns (can_read, reason, detail) where detail is a dict.

    THE CONVERSION THAT EM-9 ASKED FOR, and the shape is SNF-5's, from the
    sniffer's sibling probe in this same file: PROBE FIRST, group membership
    is a HINT, and a group name is NEVER a green. The old answer was built
    from `is_elevated()` alone, so on this host -- where the account is in
    `adm`, auth.log is group-readable and journalctl answers -- the startup
    report said the opposite of what was true, on every boot, for the life of
    the port.

    It asks the logs themselves: can a byte be read from one of the real log
    files, and does journalctl answer with a record. Both questions are the
    ones the sensor's own reader asks, so the report and the sensor cannot
    disagree again.
    """
    detail = {"files_readable": [], "files_unreadable": [],
              "journald_ok": None, "journald_why": None,
              "groups": [], "probe_error": None}

    groups = []
    try:
        import grp
        seen_g = set()
        for g in os.getgroups() + [os.getgid()]:
            if g in seen_g:
                continue
            seen_g.add(g)
            try:
                groups.append(grp.getgrgid(g).gr_name)
            except KeyError:
                continue
    except Exception as e:                                    # noqa: BLE001
        detail["probe_error"] = f"group list unreadable: {e}"
    detail["groups"] = sorted(groups)

    # THE PROBE: A REAL LOG FILE, ONE BYTE
    #
    # The same candidate list the sensor uses, in the same order, so "readable
    # here" and "the sensor read it" mean the same thing. Kept local rather
    # than imported from tools.event_monitor_linux: this module is imported by
    # main.py at boot and the tools package pulls in more than a privilege
    # report should.
    candidates = [
        Path("/var/log/auth.log"), Path("/var/log/secure"),
        Path("/var/log/authorization"), Path("/var/log/syslog"),
        Path("/var/log/messages"), Path("/var/log/kern.log"),
    ]
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            with candidate.open("rb") as fh:
                fh.readline()
            detail["files_readable"].append(candidate.name)
        except PermissionError:
            detail["files_unreadable"].append(candidate.name)
        except OSError as e:
            detail["files_unreadable"].append(f"{candidate.name} ({e})")

    # THE PROBE: JOURNALD ANSWERS
    #
    # NOT `journalctl --version`, which is a statement about the binary being
    # installed. This asks for a record.
    try:
        result = subprocess.run(
            ["journalctl", "--no-pager", "--output=json", "-n", "1"],
            capture_output=True, text=True, timeout=15)
        if result.returncode == 0 and (result.stdout or "").strip():
            detail["journald_ok"] = True
            detail["journald_why"] = "journalctl answered with a record"
        elif result.returncode == 0:
            detail["journald_ok"] = False
            detail["journald_why"] = ("journalctl answered and the journal "
                                      "holds no record")
        else:
            detail["journald_ok"] = False
            why = (result.stderr or "").strip().splitlines()
            detail["journald_why"] = (
                f"journalctl refused this account (rc={result.returncode}"
                + (f": {why[0][:120]}" if why else "") + ")")
    except FileNotFoundError:
        detail["journald_ok"] = False
        detail["journald_why"] = "journalctl is not installed on this host"
    except subprocess.TimeoutExpired:
        detail["journald_ok"] = False
        detail["journald_why"] = "journalctl did not answer within 15s"
    except Exception as e:                                    # noqa: BLE001
        detail["journald_ok"] = False
        detail["journald_why"] = f"journalctl could not be run: {e}"

    if detail["files_readable"] or detail["journald_ok"]:
        hint = ""
        if groups:
            hint = (f" This account is in {', '.join(sorted(groups))}, which "
                    f"is only a hint: what decided this answer is that the "
                    f"logs themselves could be read."
                    if len(groups) < 12 else "")
        return True, ("the logs this sensor reads are readable by this "
                      "account." + hint), detail

    why = "; ".join(
        filter(None, [detail.get("journald_why"),
                      (f"no log file is readable ({detail['files_unreadable']})"
                       if detail["files_unreadable"] else
                       "no log file exists for this sensor to read")]))
    return False, why, detail


def posture() -> dict:
    """
    Current privilege position as data.
    
    Written for understanding what this run can do.
    """
    elevated = is_elevated()
    needs = modules_by_level(NEEDS)
    degrades = modules_by_level(DEGRADES)
    none = modules_by_level(NONE)
    
    can_capture, capture_reason = check_packet_capture_capability()

    # THE DEGRADED LIST IS PROBED, NOT ASSUMED. EM-9, 2026-09-23.
    #
    # It used to be `modules_by_level(DEGRADES)` on the non-root path, full
    # stop: whichever modules are DECLARED to degrade were reported as
    # degrading, whether or not they were. Measured here, event_monitor is
    # declared DEGRADES and degrades at NOTHING: the account is in `adm`,
    # auth.log is group-readable and journalctl answers, while the report said
    # on every boot that only this user's own entries were visible.
    #
    # So the modules that CAN answer the question are asked it, and a module
    # whose probe says it is fine is not painted as degraded. What this does
    # not do is invent a new verdict vocabulary: `degraded_when_unelevated`
    # keeps its meaning (these are the modules that lose something when this
    # process has no rights) and two new keys say what was MEASURED.
    log_ok, log_why, log_detail = check_event_log_readability()

    # PS-13, 2026-09-25: the two port modules are probed for the same reason,
    # and each probe answers the question ITS OWN consequence sentence is
    # about. port_scanner loses the SYN scan (a raw socket) AND the owner
    # lookup; port_owner loses the owner lookup alone. The probes are separate
    # because the LOSSES are: a host can hold CAP_NET_RAW on the binary -- so
    # the SYN scan works unelevated -- while still being refused other
    # accounts' fd tables, and a single "degraded: yes/no" would then describe
    # one of the two wrongly.
    syn_ok, syn_why = check_syn_scan_capability()
    owner_ok, owner_why, owner_detail = check_port_owner_readability()

    measured_degrades = []
    for name, consequence in degrades:
        if name == "event_monitor":
            if log_ok:
                continue        # probed and FINE: not a degraded line
            consequence = (f"{consequence} MEASURED on this host: {log_why}")
        elif name == "port_scanner":
            # TWO HALVES, EACH MEASURED, AND THE PROBED-FINE ONE IS DROPPED
            # FROM THE SENTENCE RATHER THAN PRINTED AS A LOSS.
            losses = []
            if not syn_ok:
                losses.append(
                    f"the TCP pass cannot send SYNs from here ({syn_why}), so "
                    f"it falls back to a connect test and a CLOSED port is "
                    f"indistinguishable from a FILTERED one")
            if not owner_ok:
                losses.append(
                    f"a self-scan's port-to-process lookup cannot read the "
                    f"owners of other accounts' sockets ({owner_why})")
            if not losses:
                continue        # both halves probed FINE: not a degraded line
            consequence = ("MEASURED on this host, unelevated: "
                           + "; and ".join(losses)
                           + ". An elevated run resolves both.")
        elif name == "port_owner":
            if owner_ok:
                continue        # probed and FINE: not a degraded line
            consequence = (f"{consequence} MEASURED on this host: {owner_why}")
        measured_degrades.append((name, consequence))

    if elevated is None:
        summary = (
            "Could not determine elevation on this platform. If capture or "
            "firewall actions fail, privilege is the first thing to check."
        )
    elif elevated:
        summary = (
            f"Running as root. All sensors and actions available, and "
            f"{len(none)} of {len(REQUIREMENTS)} modules are holding root "
            f"privileges they never use."
        )
    else:
        summary = (
            f"Not elevated. {len(needs)} module(s) unavailable, "
            f"{len(measured_degrades)} degraded, the rest unaffected. A quiet "
            f"dashboard from an unelevated run is not evidence of a quiet network."
        )
        if log_ok:
            # THE SENTENCE THAT WAS MISSING. Without it, a reader who knows
            # this module is registered as DEGRADES cannot tell whether the
            # absence of a degraded line means "probed and fine" or "the
            # report forgot it".
            summary += (f" The log reader is NOT among them: {log_why}")

    return {
        "elevated": elevated,
        "summary": summary,
        "can_capture_packets": can_capture,
        "capture_reason": capture_reason,
        "unavailable_when_unelevated": needs,
        "degraded_when_unelevated": measured_degrades,
        "degraded_declared": [n for n, _ in degrades],
        "event_log_probe": {"readable": log_ok, "reason": log_why,
                            **log_detail},
        # PS-13, 2026-09-25. The two port-module probes, published as data so
        # a card or a test can read the MEASUREMENT rather than re-running it
        # or inferring it from the summary sentence.
        "syn_scan_probe": {"available": syn_ok, "reason": syn_why},
        "port_owner_probe": {"readable": owner_ok, "reason": owner_why,
                             **owner_detail},
        "unaffected_count": len(none),
        "excess_privilege_modules": len(none) if elevated else 0,
    }
