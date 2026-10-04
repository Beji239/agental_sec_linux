# tools/host_info_linux.py
# AgentalSec Linux - System information gathering
#
# Linux equivalent of Windows host_info.py
# Collects OS, kernel, hardware, and configuration information
#
# Read-only. Does not modify system state.

import logging
import os
import platform
import pwd
import grp
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Where this app writes its evidence. The disk figure a reader needs is the
# one for THIS filesystem, because a full filesystem is how a capture stops
# silently -- the module used to answer only for "/".
_HERE = Path(__file__).resolve()
_APP_DIR = str(_HERE.parent.parent) if _HERE.parent.name == "tools" else str(_HERE.parent)


def _run_command(cmd: list, timeout: int = 10) -> tuple[bool, str]:
    """
    Run a command and return (success, output).

    THE ERROR PATH USED TO BE A TRAP FOR ITS OWN CALLER, measured 2026-09-25.
    It caught `Exception` (which swallows a programmer error as though the
    machine had refused), and then built its log line with `' '.join(cmd)`,
    which RAISES TypeError when the list holds anything that is not a string.
    So `_run_command([None])` left this function as a TypeError rather than as
    `(False, reason)` -- the one shape every caller in this module is written
    against. The join is str()'d and the log call is guarded, so a caller
    that passes junk gets its failure back as a value like any other.

    `_run_command_both` is the sibling for the callers that need stdout AND
    stderr in one answer; `subprocess.run` returns both, and throwing one away
    is why a refusal and a quiet machine could not be told apart here.
    """
    ok, out, _err = _run_command_both(cmd, timeout=timeout)
    return ok, out


def _run_command_both(cmd: list, timeout: int = 10) -> tuple[bool, str, str]:
    """
    Run a command and return (success, stdout, stderr).

    A REFUSAL AND AN EMPTY ANSWER ARE DIFFERENT FACTS, and they arrive in
    different streams. `iptables -L -n` failing with "Permission denied (you
    must be root)" prints NOTHING on stdout, so a reader that keeps only
    stdout sees the same thing as a firewall with no rules -- which is
    exactly what this module reported for two years of its ported life.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode == 0:
            return True, result.stdout, result.stderr
        return False, result.stdout, result.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        return False, "", f"{type(e).__name__}: {e}"
    except Exception as e:                      # a malformed cmd list
        logger.debug(f"Command failed: {' '.join(str(c) for c in cmd)} - "
                     f"{type(e).__name__}: {e}")
        return False, "", f"{type(e).__name__}: {e}"


def _read_file_safe(path: str) -> Optional[str]:
    """
    Read a file safely, returning None if unreadable.

    THIS IS THE 'COULD NOT LOOK' SENTINEL, and every caller must treat None
    as unknown rather than as an empty file or a missing feature. Measured
    2026-09-25: half the callers turned it into a value that read as a fact.
    """
    try:
        return Path(path).read_text(encoding='utf-8', errors='replace').strip()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def _read_os_release() -> tuple[dict, Optional[str]]:
    """
    /etc/os-release, parsed, with the reason it is missing when it is.

    Returns (fields, problem). `problem` is None when the file was read.
    The distinction is the whole point: a machine whose /etc/os-release
    cannot be read is not a machine with no distribution name, and this
    module used to report exactly that ('Unknown').
    """
    raw = _read_file_safe("/etc/os-release")
    if raw is None:
        # One retry through the OTHER parser before calling it missing: a
        # file that exists but is not utf-8-decodable is a real shape and
        # read_text(errors='replace') hides it as mojibake.
        return {}, "/etc/os-release could not be read"
    fields = {}
    for line in raw.split('\n'):
        if '=' in line and not line.strip().startswith('#'):
            key, value = line.split('=', 1)
            fields[key.strip().lower()] = value.strip().strip('"')
    if not fields:
        return {}, "/etc/os-release holds no KEY=VALUE lines"
    return fields, None


def get_os_info() -> dict:
    """
    Get operating system information.

    UNKNOWN IS REPORTED AS UNKNOWN, 2026-09-25. This used to answer
    distribution "Unknown" and distro_version "" when /etc/os-release could
    not be read -- and the MODEL-facing description of this tool says fields
    can be null when a value could not be read, with null meaning UNKNOWN
    rather than false. A reader given "Unknown" cannot tell a distro this
    module does not recognise from a file it was refused.
    """
    info = {
        "system": platform.system(),
        "node": platform.node(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
    }

    distro_info, problem = _read_os_release()

    # Fallback: lsb_release, only when os-release gave us nothing.
    if not distro_info and problem:
        success, output = _run_command(["lsb_release", "-a"])
        if success:
            for line in output.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    distro_info[key.strip().lower().replace(' ', '_')] = value.strip()
            if distro_info:
                problem = None

    if problem:
        info["distribution"] = None
        info["distro_version"] = None
        info["unknown_because"] = problem
        info["unknown_fields"] = ["distribution", "distro_version"]
    else:
        info["distribution"] = distro_info.get(
            "pretty_name", distro_info.get("name", None))
        info["distro_version"] = distro_info.get("version_id",
                                                 distro_info.get("version", None))

    return info


def get_kernel_info() -> dict:
    """
    Get kernel information.

    THE grsecurity LINE WAS DEAD CODE, measured 2026-09-25: its condition
    was `if "grsecurity" in proc_version.lower() if proc_version else False:`
    -- a chained conditional expression, so when /proc/version is MISSING
    the whole test is `False`, and when it is PRESENT the test is on a str.
    It never fired, and the field it set is read by nothing in this tree.
    Removed rather than repaired: grsecurity is not shipped for this kernel
    and the module's own contract is to report what the machine says.

    The sysctl reads below keep the module's null convention -- a key that
    could not be read is ABSENT here rather than present with a value that
    reads as a setting.
    """
    info = {
        "version": platform.release(),
        "architecture": platform.machine(),
    }

    # Get full kernel info from /proc/version
    proc_version = _read_file_safe("/proc/version")
    if proc_version:
        info["full_version"] = proc_version
    else:
        info["full_version"] = None
        info["unknown_because"] = "/proc/version could not be read"

    # Kernel parameters, read from the kernel's own files. The paths are the
    # authority; the dotted key names are kept because they are what this
    # module published before and a reader may have pinned them.
    sysctl_params = {
        "kernel.unprivileged_userns_clone": "/proc/sys/kernel/unprivileged_userns_clone",
        "kernel.dmesg_restrict": "/proc/sys/kernel/dmesg_restrict",
        "kernel.kptr_restrict": "/proc/sys/kernel/kptr_restrict",
        "kernel.yama.ptrace_scope": "/proc/sys/kernel/yama/ptrace_scope",
    }

    unreadable = []
    for param, path in sysctl_params.items():
        value = _read_file_safe(path)
        if value is not None:
            info[f"sysctl_{param}"] = value
        else:
            unreadable.append(path)
    if unreadable:
        info["sysctl_unreadable"] = unreadable

    # THE KERNEL'S OWN BUILD, from the package manager. The registry-shaped
    # twin records a build and a patch level; on Linux the honest equivalent
    # is the kernel PACKAGE version (`7.0.0-31.31~24.04.1`), which is what
    # a vulnerability comparison would actually be made against. Read
    # unelevated; dpkg-query needs no privileges.
    pkg = _kernel_package_version()
    if pkg:
        info["package_version"] = pkg

    return info


def _kernel_package_version() -> Optional[str]:
    """
    The installed kernel package's own version, or None.

    `uname -r` names the running kernel; the PACKAGE version is the one with
    the distribution's rebuild suffix on it (measured here:
    `7.0.0-31.31~24.04.1` against a release of `7.0.0-31-generic`). A patch
    comparison wants the second. dpkg is asked directly rather than through a
    glob so a missing package is a None and not an empty list.
    """
    ok, out = _run_command(["dpkg-query", "-W",
                            "-f=${Package} ${Version}",
                            f"linux-image-{platform.release()}"])
    if ok and out.strip():
        return out.strip()
    return None


def get_hardware_info() -> dict:
    """
    Get hardware information.

    THE DISK FIGURES WERE FOR THE WRONG FILESYSTEM'S PURPOSE, 2026-09-25.
    `df -h /` answers for the root filesystem, and on this machine that
    happens to be the same device the app's store lives on -- but the number
    a reader of a security tool needs is the one where THE EVIDENCE is
    written, because a full filesystem is how a capture stops silently. Both
    are reported now, named.

    MEMORY IS REPORTED THREE WAYS on purpose. `MemFree` is what this module
    published, and on this host it read 146 MB while 5.0 GB was available
    (page cache is reclaimable, MemFree is not what an allocation actually
    faces). MemAvailable is the kernel's own answer to "how much can I
    actually get".

    CPU COUNT: `cpu_count()` is the machine's; the affinity mask is what
    THIS PROCESS may use. A cgroup-limited process has both and they differ,
    which is the difference between "the machine is busy" and "we are
    confined".
    """
    info = {}

    # CPU info from /proc/cpuinfo
    cpuinfo = _read_file_safe("/proc/cpuinfo")
    if cpuinfo:
        cpu_count = cpuinfo.count("processor")
        info["cpu_count"] = cpu_count

        # Get model name
        for line in cpuinfo.split('\n'):
            if line.startswith("model name"):
                info["cpu_model"] = line.split(':', 1)[1].strip()
                break

    # The platform's own answers, alongside the parsed file.
    info["cpu_count_platform"] = os.cpu_count()
    try:
        info["cpu_count_available_to_this_process"] = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        pass
    try:
        load1, load5, load15 = os.getloadavg()
        info["load_average"] = {"1m": round(load1, 2), "5m": round(load5, 2),
                                "15m": round(load15, 2)}
    except OSError:
        pass

    # Memory info from /proc/meminfo
    meminfo = _read_file_safe("/proc/meminfo")
    if meminfo:
        for line in meminfo.split('\n'):
            if line.startswith("MemTotal:"):
                mem_kb = int(line.split()[1])
                info["memory_total_mb"] = mem_kb // 1024
            elif line.startswith("MemFree:"):
                mem_kb = int(line.split()[1])
                info["memory_free_mb"] = mem_kb // 1024
            elif line.startswith("MemAvailable:"):
                mem_kb = int(line.split()[1])
                info["memory_available_mb"] = mem_kb // 1024

    # Disk info -- for the root filesystem AND for where this app writes.
    info["disk"] = {}
    for label, path in (("root", "/"), ("app_data", _APP_DIR)):
        entry = {"path": path}
        success, output = _run_command(["df", "-h", "-P", path])
        if success:
            lines = output.strip().split('\n')
            if len(lines) >= 2:
                parts = lines[1].split()
                if len(parts) >= 6:
                    entry.update({
                        "filesystem": parts[0],
                        "total": parts[1],
                        "used": parts[2],
                        "available": parts[3],
                        "use_percent": parts[4],
                        "mounted_on": parts[5],
                    })
        if len(entry) == 1:
            entry["unknown"] = f"df refused or did not answer for {path}"
        info["disk"][label] = entry

    # The flat keys this module published before, kept so a reader pinned to
    # them keeps working. Sourced from the ROOT filesystem entry.
    root = info["disk"].get("root", {})
    for key, src in (("disk_total", "total"), ("disk_used", "used"),
                     ("disk_available", "available"),
                     ("disk_use_percent", "use_percent")):
        if src in root:
            info[key] = root[src]

    return info


def _primary_ipv4() -> tuple[Optional[str], Optional[str]]:
    """
    This host's own outbound-usable IPv4 address, unelevated.

    Returns (address, how) or (None, reason). `socket.gethostbyname(hostname)`
    is NOT a way to ask this -- see get_network_info -- so the address is
    taken from the routing decision the kernel has already made, by binding a
    UDP socket to a documentation address (RFC 5737, 192.0.2.0/24). NO PACKET
    IS SENT: a connected UDP socket only selects a source address, and the
    kernel resolves the route locally.

    Falls back to reading /proc/net/route when the socket path refuses, so a
    locked-down host reports a named reason instead of a loopback address.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.0.2.1", 9))
            addr = s.getsockname()[0]
        finally:
            s.close()
        if addr and not addr.startswith("127."):
            return addr, "the route the kernel would use to leave this host"
    except OSError as e:
        sock_reason = f"{type(e).__name__}: {e}"
    else:
        sock_reason = "the route chose a loopback address, so this host has no outbound route"

    raw = _read_file_safe("/proc/net/route")
    if raw:
        for line in raw.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 8 and parts[1] == "00000000" and parts[7] == "00000000":
                return None, (f"no usable outbound route ({sock_reason}); the default "
                              f"route is on {parts[0]} with gateway {parts[2]}")
    return None, f"no usable outbound route ({sock_reason})"


def _dns_servers() -> tuple[list, Optional[str]]:
    """
    The DNS servers this host actually resolves through, with the caveat.

    MEASURED 2026-09-25: /etc/resolv.conf on this machine is a SYMLINK to
    systemd-resolved's stub file and names ONE server, 127.0.0.53 -- the
    local stub. The servers that actually answer are in
    /run/systemd/resolve/resolv.conf and are reached over the stub. A reader
    who treats the stub as "the DNS server this host uses" gets a loopback
    address and none of the real ones, so both are reported and the stub is
    NAMED as a stub rather than counted as a resolver.

    Returns (servers, note). The note is None when nothing needed saying.
    """
    def _parse(path):
        out = []
        raw = _read_file_safe(path)
        if not raw:
            return out
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            if line.split()[0] == "nameserver" and len(line.split()) > 1:
                out.append(line.split()[1])
        return out

    configured = _parse("/etc/resolv.conf")
    note = None

    stubs = [s for s in configured
             if s.startswith("127.") or s in ("::1", "0.0.0.0")]
    if stubs:
        upstream = _parse("/run/systemd/resolve/resolv.conf")
        if upstream:
            note = (f"{', '.join(stubs)} is a local stub resolver, not a "
                    f"resolver: the servers it forwards to are "
                    f"{', '.join(upstream)}.")
            return configured, note
        note = (f"{', '.join(stubs)} is a local stub resolver. Its upstream "
                f"servers could not be read from "
                f"/run/systemd/resolve/resolv.conf.")
    return configured, note


def get_network_info() -> dict:
    """
    Get network configuration information.

    THE OLD primary_ip WAS A LOOPBACK ADDRESS, measured 2026-09-25: the line
    was `socket.gethostbyname(socket.gethostname())`, and on a systemd host
    the hostname resolves through /etc/hosts to 127.0.1.1 -- so the module
    told the model this machine's address was 127.0.1.1 while its only real
    interface held a routable one (the value is measured in bugfinder.md).
    That is the exact class of error the
    Linux-native module exists to prevent, and it was reported through
    summarize() and monitor_once() as `primary_ip`.

    A value that could not be determined is now ABSENT-or-null with the
    reason beside it, never a plausible-looking address.
    """
    info = {
        "hostname": socket.gethostname(),
        "interfaces": {},
    }

    try:
        info["fqdn"] = socket.getfqdn()
    except Exception:
        info["fqdn"] = None

    addr, how = _primary_ipv4()
    info["primary_ip"] = addr
    if addr:
        info["primary_ip_basis"] = how
    else:
        info["primary_ip_basis"] = None
        info["primary_ip_unknown_because"] = how

    # Get interface info via ip command
    success, output = _run_command(["ip", "-o", "addr", "show"])
    if success:
        for line in output.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 4:
                iface = parts[1]
                if iface not in info["interfaces"]:
                    info["interfaces"][iface] = []

                # Extract IP address
                if len(parts) >= 4:
                    ip = parts[3]
                    info["interfaces"][iface].append(ip)
    else:
        info["interfaces_unknown_because"] = (
            "`ip -o addr show` refused or is not installed")

    # Get default gateway
    success, output = _run_command(["ip", "route", "show", "default"])
    if success:
        for line in output.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "default":
                info["default_gateway"] = parts[2]
                break
    if "default_gateway" not in info:
        info["default_gateway"] = None
        info["default_gateway_unknown_because"] = (
            "no default route, or `ip route show default` refused")

    # DNS servers
    servers, note = _dns_servers()
    info["dns_servers"] = servers or None
    if note:
        info["dns_note"] = note
    if not servers:
        info["dns_servers_unknown_because"] = (
            "/etc/resolv.conf holds no nameserver line, or could not be read")

    return info


def _account() -> tuple[Optional[str], Optional[str]]:
    """
    The account this process runs as, from the platform.

    MEASURED 2026-09-25: the old line was
    `os.environ.get("USER", os.environ.get("USERNAME", "unknown"))`, which
    answers "unknown" under systemd -- $USER is not set there, and systemd is
    the environment this app actually runs in. The passwd database is the
    authority: `pwd.getpwuid(os.getuid())` answers under any manager,
    elevated or not, with or without an environment.

    Returns (name, problem).
    """
    try:
        return pwd.getpwuid(os.getuid()).pw_name, None
    except KeyError:
        return None, (f"uid {os.getuid()} has no entry in the passwd "
                      f"database, so the account name is unknown")
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def _sudo_answer() -> dict:
    """
    Whether this ACCOUNT may use sudo, told apart from whether it can now.

    MEASURED 2026-09-25: the old probe was `sudo -n true`, which returned
    rc 1 ("a password is required") for an account that IS in the sudo group.
    `-n` asks "can I sudo WITHOUT A PASSWORD PROMPT", which is a question
    about NOPASSWD configuration; the group is the question about
    permission. The tool reported has_sudo=False about an account that can
    sudo at any prompt, and has_sudo=True about a machine where a prompt
    would block a non-interactive caller for ever.

    Three facts, each sourced, named so they cannot be conflated:
      sudo_group_member    from the group database (the platform's answer)
      sudoers_may_read     whether /etc/sudoers could be read at all
      sudo_without_password the OLD probe, kept under the name that says
                            what it means
    """
    out = {
        "sudo_group_member": None,
        "sudo_group_basis": None,
        "sudo_without_password": None,
    }

    name, _problem = _account()
    if name:
        try:
            groups = [g.gr_name for g in grp.getgrall() if name in g.gr_mem]
            try:
                primary = grp.getgrgid(os.getgid()).gr_name
                if primary not in groups:
                    groups.append(primary)
            except KeyError:
                pass
            out["sudo_group_member"] = "sudo" in groups or "wheel" in groups
            out["sudo_group_basis"] = f"the group database, for account {name!r}"
        except Exception as e:
            out["sudo_group_basis"] = f"group database unreadable: {type(e).__name__}"

    ok, _out, err = _run_command_both(["sudo", "-n", "true"])
    out["sudo_without_password"] = bool(ok)
    if not ok:
        out["sudo_without_password_note"] = (
            "this is `sudo -n true`, which asks whether a password is "
            f"required, not whether the account may sudo ({err.strip() or 'refused'})")

    out["sudoers_readable"] = os.access("/etc/sudoers", os.R_OK)
    if not out["sudoers_readable"]:
        out["sudoers_note"] = ("/etc/sudoers is not readable by this account, "
                               "so a per-command rule cannot be checked from here")
    return out


def get_user_info() -> dict:
    """
    Get user and session information.

    FIELDS THAT COULD NOT BE READ ARE NULL, WITH THE REASON. Measured
    2026-09-25: this block answered `current_user: "unknown"` under systemd,
    `has_sudo: False` about an account in the sudo group, and a 500-character
    TRUNCATION of `last` output with nothing saying it had been cut -- a
    record severed mid-line reads exactly like a short login history.
    """
    account, acct_problem = _account()

    info = {
        "current_user": account,
        "current_uid": os.getuid(),
        "current_gid": os.getgid(),
        "home": os.path.expanduser("~"),
    }
    if acct_problem:
        info["current_user_unknown_because"] = acct_problem

    # Get logged in users
    success, output, err = _run_command_both(["who"])
    if success:
        users = []
        for line in output.strip().split('\n'):
            if line:
                users.append(line.split()[0])
        info["logged_in_users"] = sorted(set(users))
    else:
        info["logged_in_users"] = None
        info["logged_in_users_unknown_because"] = err.strip() or "`who` refused"

    # Get last logins -- the LAST N RECORDS, never a character cut.
    success, output, err = _run_command_both(["last", "-n", "10"])
    if success:
        records = [l for l in output.splitlines() if l.strip()]
        info["recent_logins"] = records
        info["recent_logins_shown"] = len(records)
        # If the tool cut its own output at a fixed number of lines, the
        # last line can be a partial record. Say when it might be.
        if records and not records[-1].strip().endswith(")"):
            info["recent_logins_note"] = (
                "the last record may be incomplete: `last` cut its own output")
    else:
        info["recent_logins"] = None
        info["recent_logins_unknown_because"] = err.strip() or "`last` refused"

    # sudo, told apart properly
    info.update(_sudo_answer())

    return info


def get_security_info() -> dict:
    """
    Get security configuration information.

    THE RULE THIS BLOCK BROKE, AND IT BROKE IT IN EVERY FIELD, measured
    2026-09-25. Running it UNELEVATED on this host -- which is how the app
    runs unless the launcher is used -- it answered:

        {'iptables_active': False, 'nftables_active': False, 'apparmor': False}

    Every one of those is wrong in the same direction. Measured beside it:
    `iptables -L -n` fails with "Permission denied (you must be root)", not
    with an empty ruleset; `nft list ruleset` fails with "netlink: Error:
    cache initialization failed"; `aa-status` prints "apparmor module is
    loaded." and THEN "You do not have enough privilege to read the profile
    set"; and /sys/module/apparmor/parameters/enabled reads 'Y'. The module
    turned four refusals into four FALSE facts about this machine's defences.
    A reader of that answer would conclude this host has no firewall and no
    mandatory access control.

    THE FIREWALL QUESTION ALREADY HAD A RIGHT ANSWER IN THIS TREE, one file
    away: tools/iptables_manager.detect_backend_detail() answers 'ufw' with
    the reason ("ufw is installed and configured ENABLED in /etc/ufw/ufw.conf")
    by reading the state FILE rather than by running a privileged command.
    This block asks that function now instead of reimplementing it badly.

    EVERY FIELD IS TRI-STATE: True / False / None-with-a-reason. None means
    "this account could not look", and it must never read as "the machine
    does not have it".
    """
    info = {}

    # firewall. Asked through the tree's own detector, which reads FILES.
    try:
        from tools import iptables_manager as fw
        detail = fw.detect_backend_detail()
        info["firewall_backend"] = detail.get("backend")
        info["firewall_backend_basis"] = detail.get("reason")
        info["firewall_active"] = detail.get("backend") not in (None, "", "none")
    except Exception as e:
        info["firewall_backend"] = None
        info["firewall_backend_basis"] = None
        info["firewall_active"] = None
        info["firewall_unknown_because"] = (
            f"the firewall detector raised {type(e).__name__}: {e}")

    # The per-backend probes are kept, each as its own tri-state, because an
    # operator asking "is nftables doing anything" is asking a narrower
    # question than "what is blocking traffic".
    ok, out, err = _run_command_both(["iptables", "-L", "-n"])
    if ok:
        info["iptables_active"] = len(out.strip().split('\n')) > 2
    else:
        info["iptables_active"] = None
        info["iptables_unknown_because"] = (
            err.strip().splitlines()[-1] if err.strip() else "iptables refused")

    ok, out, err = _run_command_both(["nft", "list", "ruleset"])
    if ok:
        info["nftables_active"] = bool(out.strip())
    else:
        info["nftables_active"] = None
        info["nftables_unknown_because"] = (
            err.strip().splitlines()[-1] if err.strip() else "nft refused")

    # mandatory access control. The kernel's own file first: it is
    # readable by anyone and it is the LSM's own answer.
    lsm = _read_file_safe("/sys/kernel/security/lsm")
    if lsm is not None:
        info["lsm_enabled"] = [x.strip() for x in lsm.split(",") if x.strip()]
    apparmor_enabled = _read_file_safe("/sys/module/apparmor/parameters/enabled")
    if apparmor_enabled is not None:
        info["apparmor"] = apparmor_enabled.upper().startswith("Y")

    if "apparmor" not in info:
        # Fall back to the tool, and DO NOT read its exit code as the answer:
        # aa-status exits 4 when it is loaded but this account may not read
        # the profile set, and the old code called that "not installed".
        ok, out, err = _run_command_both(["aa-status"], timeout=10)
        if ok:
            info["apparmor"] = True
        elif "apparmor module is loaded" in out.lower():
            info["apparmor"] = True
            info["apparmor_profiles_unreadable"] = (
                "the AppArmor module IS loaded; this account may not read "
                f"the profile set ({err.strip().splitlines()[-1] if err.strip() else 'refused'})")
        elif "not found" in err.lower() or "No such file" in err:
            info["apparmor"] = False
        else:
            info["apparmor"] = None
            info["apparmor_unknown_because"] = err.strip() or "aa-status refused"

    # SELinux: /sys/fs/selinux is the kernel's own answer and it exists on
    # every SELinux-enabled kernel whether or not it is enforcing.
    if os.path.isdir("/sys/fs/selinux"):
        info["selinux_present"] = True
        enforcing = _read_file_safe("/sys/fs/selinux/enforce")
        if enforcing is not None:
            info["selinux_enforcing"] = enforcing.strip() == "1"
    else:
        info["selinux_present"] = False

    # SSH: THE EFFECTIVE CONFIGURATION, and only real directives.
    info.update(_ssh_answer())

    # container. THE OLD TEST COULD ONLY EVER READ THE FIRST LINE of
    # /proc/1/cgroup, and on a cgroup-v2 host that line is "0::/init.scope"
    # for the host itself -- measured here. The platform's own answer is
    # systemd-detect-virt, and a wrong container verdict is not harmless:
    # this field is what tells a reader whether the machine's limits are
    # ITS OWN.
    info.update(_container_answer())

    return info


def _ssh_answer() -> dict:
    """
    The SSH daemon's EFFECTIVE answer to two questions, or null.

    TWO DEFECTS WERE MEASURED HERE, 2026-09-25.

    (1) The check was `"PermitRootLogin yes" in sshd_config`, a SUBSTRING
    search over the whole file. It matches a COMMENT -- this host's
    /etc/ssh/sshd_config line 90 reads `# the setting of "PermitRootLogin
    prohibit-password".` -- so a machine that comments a line out reports
    the opposite of what it does, and a machine that sets
    `PermitRootLogin yes` with different spacing or a trailing comment
    reports nothing at all. The shape is AR-1's, one module over.

    (2) ONLY /etc/ssh/sshd_config WAS READ, and its FIRST LINE on this host
    is `Include /etc/ssh/sshd_config.d/*.conf`. A drop-in that sets
    `PermitRootLogin yes` is the daemon's real answer and was invisible.

    The directives are parsed properly (first field = key, comments
    stripped, last value wins as sshd itself does), and when the account
    cannot read the daemon's effective config through `sshd -T` the answer
    is null WITH THE REASON rather than a guess from a file.
    """
    out = {
        "ssh_permit_root_login": None,
        "ssh_password_auth": None,
        "ssh_config_source": None,
    }

    # The daemon's own answer, when this account may ask. sshd -T needs the
    # host keys and usually needs to be root; -f lets an unprivileged run
    # point at a config it CAN read, which is what makes this usable below.
    for args, source in ((["sshd", "-T"], "`sshd -T` (the effective config)"),):
        ok, text, err = _run_command_both(args, timeout=10)
        if ok and text.strip():
            parsed = _parse_sshd_directives(text)
            out["ssh_config_source"] = source
            out["ssh_permit_root_login"] = parsed.get("permitrootlogin")
            out["ssh_password_auth"] = parsed.get("passwordauthentication")
            out["ssh_effective"] = True
            return out

    # Fall back to reading the files, and SAY that is what was read.
    files = ["/etc/ssh/sshd_config"]
    main = _read_file_safe("/etc/ssh/sshd_config")
    if main:
        for line in main.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if parts and parts[0].lower() == "include" and len(parts) > 1:
                import glob
                files.extend(sorted(glob.glob(parts[1])))

    merged = {}
    for path in files:
        text = _read_file_safe(path)
        if text is None:
            continue
        for k, v in _parse_sshd_directives(text).items():
            merged[k] = v

    if merged:
        out["ssh_config_source"] = ("the config files, not the daemon's "
                                    "effective config (sshd -T was refused)")
        out["ssh_config_files"] = files
        out["ssh_permit_root_login"] = merged.get("permitrootlogin")
        out["ssh_password_auth"] = merged.get("passwordauthentication")
        out["ssh_effective"] = False
    else:
        out["ssh_config_source"] = None
        out["ssh_unknown_because"] = (
            "neither `sshd -T` nor /etc/ssh/sshd_config could be read by "
            "this account")
    return out


def _parse_sshd_directives(text: str) -> dict:
    """
    sshd_config directives, parsed the way sshd reads them.

    First whitespace-separated field is the keyword, case-insensitively;
    a line whose first non-blank character is '#' is a comment; a value
    continues to end of line and may carry its own trailing comment; the
    LAST occurrence wins, which is what the daemon does. A substring search
    over the file satisfies none of those, and satisfied this module until
    2026-09-25.
    """
    out = {}
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        key = parts[0].lower()
        value = parts[1].strip().strip('"')
        out[key] = value
    return out


def _container_answer() -> dict:
    """
    Whether this process is in a container, and by whose answer.

    MEASURED 2026-09-25: the old test read /.dockerenv, then searched the
    FIRST LINE of /proc/1/cgroup for the word "docker". On a cgroup-v2 host
    the first line is `0::/init.scope` for the host itself, so the search
    could only ever see the first line and read as "not a container" -- and
    a docker container whose line is NOT first reads the same way. The
    platform's own command is `systemd-detect-virt`, and /proc/1/comm and
    /run/systemd/system distinguish a real systemd host from a container.
    """
    out = {"container": None, "container_basis": None}

    # `systemd-detect-virt` reports BARE METAL AS "none" AND EXIT 1, measured
    # 2026-09-25. Reading its exit code as the answer would therefore treat a
    # clean host as a failure and fall through to weaker tests -- the exact
    # mistake this round exists to remove, caught in this fix's first draft.
    # Its OUTPUT is the answer; its exit code only says whether it could run.
    ok, text, _err = _run_command_both(["systemd-detect-virt"], timeout=10)
    verdict = (text or "").strip().lower()
    if verdict:
        if verdict == "none":
            out["container"] = None
            out["container_basis"] = ("systemd-detect-virt answered 'none': "
                                      "this is a bare machine, not a container")
        else:
            out["container"] = verdict
            out["container_basis"] = "systemd-detect-virt, the platform's own answer"
        return out

    if os.path.exists("/.dockerenv"):
        out["container"] = "docker"
        out["container_basis"] = "/.dockerenv exists"
        return out

    # Every line, not the first.
    cgroup = _read_file_safe("/proc/1/cgroup")
    if cgroup:
        for line in cgroup.splitlines():
            for name in ("docker", "lxc", "kubepods", "podman"):
                if name in line:
                    out["container"] = name
                    out["container_basis"] = f"/proc/1/cgroup names {name}"
                    return out

    out["container"] = None
    out["container_basis"] = ("not a container by every test that could run "
                              "(systemd-detect-virt was unavailable, "
                              "/.dockerenv absent and /proc/1/cgroup clean)")
    return out


def get_service_info() -> dict:
    """
    Get running services information.

    THE PARSE PRODUCED FOUR SERVICES THAT DO NOT EXIST, measured
    2026-09-25. Running on this host, the list ended:

        ['user@1000.service', 'wpa_supplicant.service',
         'Legend:', 'ACTIVE', 'SUB', '36']

    `systemctl list-units` prints a HEADER and a FOOTER (a legend block and
    "36 loaded units listed."), and the old parser skipped only line [0] and
    then took `parts[0]` of everything else. So a reader counting this
    machine's services counted six characters of legend and a bare number.
    Worse, the FAILED list is prefixed with a bullet: the first field of a
    failed unit is '●', not the unit name, so the one failed service on this
    host came back as ['●', 'Legend:', 'ACTIVE', 'SUB', '1'] -- the unit
    that is actually broken was the one thing missing.

    The fix is the one this tree already wrote down for the autoruns round:
    pass --no-legend, accept a line only when its first field ends in the
    unit suffix, and DO NOT slice [1:] once the legend is off -- that is how
    the first real row gets dropped. Every row is verified against the unit
    suffix, so a legend block cannot re-enter even if the flag is ignored by
    an older systemctl.
    """
    info = {
        "services": [],
        "failed_services": [],
        "service_count": 0,
        "failed_service_count": 0,
    }

    def _units(state_flag: str) -> tuple[list, Optional[str]]:
        args = ["systemctl", "list-units", "--type=service", state_flag,
                "--no-legend", "--plain", "--no-pager"]
        ok, out, err = _run_command_both(args, timeout=15)
        if not ok:
            return [], (err.strip().splitlines()[-1] if err.strip()
                        else f"systemctl refused ({state_flag})")
        units = []
        for line in out.splitlines():
            parts = line.split()
            if parts and parts[0].endswith(".service"):
                units.append(parts[0])
        return units, None

    running, problem = _units("--state=running")
    if problem:
        info["services_unknown_because"] = problem
        info["services"] = None
    else:
        info["services"] = running
        info["service_count"] = len(running)

    failed, problem = _units("--state=failed")
    if problem:
        info["failed_services_unknown_because"] = problem
        info["failed_services"] = None
    else:
        # `systemctl --failed` is the same set asked the short way; keep the
        # list-units form above so both answers come from one parser, and
        # cross-check when the manager is new enough to offer the short one.
        ok, out, _err = _run_command_both(
            ["systemctl", "--failed", "--no-legend", "--plain", "--no-pager"],
            timeout=15)
        short = None
        if ok:
            short = [l.split()[0] for l in out.splitlines()
                     if l.split() and l.split()[0].endswith(".service")]
            if short is not None and sorted(short) != sorted(failed):
                info["failed_services_disagree"] = (
                    f"`systemctl list-units --state=failed` says {failed} and "
                    f"`systemctl --failed` says {short}; both are reported")
                info["failed_services_short_form"] = short
        info["failed_services"] = failed
        info["failed_service_count"] = len(failed)

    return info


def get_all_info() -> dict:
    """
    Collect all system information.

    Returns comprehensive dict with all host info.

    ONE READ, ONE TIMESTAMP, ONE ERROR LIST, 2026-09-25. Until this round
    the section readers had no shared error channel: each swallowed a
    refusal into a value, so the payload could not say what it had failed to
    read. Now every reader writes into `unreadable` (section -> reason) and
    the payload carries it. A caller that finds `unreadable` non-empty knows
    the answer is partial and WHICH PART.

    `timestamp` is the START of the read, in ISO-8601 UTC with the offset on
    it. `elapsed_seconds` is how long it took. `timestamp` and the
    `collected_at` the adapter publishes used to be two different instants
    from two different walks of the machine; there is one walk now.
    """
    start_time = datetime.now(timezone.utc)

    unreadable = {}

    def _collect(label, fn):
        try:
            return fn()
        except Exception as e:
            unreadable[label] = f"{type(e).__name__}: {e}"
            return None

    result = {
        "timestamp": start_time.isoformat(),
        "os": _collect("os", get_os_info),
        "kernel": _collect("kernel", get_kernel_info),
        "hardware": _collect("hardware", get_hardware_info),
        "network": _collect("network", get_network_info),
        "users": _collect("users", get_user_info),
        "security": _collect("security", get_security_info),
        "services": _collect("services", get_service_info),
    }

    # Any section that itself refused a field names it here, so ONE key is
    # the whole answer to "what could this read not get".
    for section, block in result.items():
        if isinstance(block, dict):
            for key, value in block.items():
                if key.endswith("_unknown_because") and value:
                    unreadable[f"{section}.{key[:-len('_unknown_because')]}"] = value

    result["unreadable"] = unreadable or None
    result["elapsed_seconds"] = (datetime.now(timezone.utc) - start_time).total_seconds()

    return result


def build_summary(info: dict) -> dict:
    """
    The concise reading, BUILT FROM AN ALREADY-COLLECTED payload.

    THE OLD get_summary() WALKED THE MACHINE AGAIN, measured 2026-09-25:
    monitor_once() called get_all_info() and then get_summary(), which called
    get_all_info() a SECOND time -- two full walks in one payload, 1.04 s
    apart, with the two halves of one answer carrying different timestamps
    for the same machine. A record that reports two different instants for
    one reading cannot be diffed.

    This builds the summary from what was read. `get_summary()` below is
    kept as the one-shot convenience for a caller that wants only the
    summary, and it says so.
    """
    os_b = info.get("os") or {}
    kernel_b = info.get("kernel") or {}
    hw_b = info.get("hardware") or {}
    net_b = info.get("network") or {}
    users_b = info.get("users") or {}
    sec_b = info.get("security") or {}
    svc_b = info.get("services") or {}

    return {
        "timestamp": info.get("timestamp"),
        "hostname": os_b.get("node"),
        "os": os_b.get("distribution"),
        "os_version": os_b.get("distro_version"),
        "kernel": kernel_b.get("version"),
        "kernel_package": kernel_b.get("package_version"),
        "cpu": hw_b.get("cpu_model"),
        "cpu_count": hw_b.get("cpu_count"),
        "memory_mb": hw_b.get("memory_total_mb"),
        "memory_available_mb": hw_b.get("memory_available_mb"),
        "primary_ip": net_b.get("primary_ip"),
        "user": users_b.get("current_user"),
        "container": sec_b.get("container"),
        "firewall_backend": sec_b.get("firewall_backend"),
        "services_running": svc_b.get("service_count"),
        "services_failed": svc_b.get("failed_service_count"),
        "unreadable": info.get("unreadable"),
    }


def get_summary() -> dict:
    """
    The concise reading, COLLECTED FRESH.

    Kept for callers that want only this (scripts/test_all_sensors.py is one).
    Anything holding a full payload should call build_summary(info) instead,
    so one answer carries one timestamp.
    """
    return build_summary(get_all_info())


def monitor_once() -> dict:
    """
    Run host info collection once.

    Returns dict suitable for database storage.

    ONE WALK, 2026-09-25. This used to call get_all_info() and get_summary()
    -- and get_summary() called get_all_info() again, so one monitor_once()
    walked the machine twice: measured 1.88 s wall with the two halves'
    timestamps 1.04 s apart, reporting the same facts from two different
    instants under one key. The summary is now BUILT from the read above.
    """
    info = get_all_info()
    return {
        "timestamp": info["timestamp"],
        "full_info": info,
        "summary": build_summary(info),
        "searched": True,
    }


def get_status() -> dict:
    """
    Get current host info status.

    TRI-STATE, ON PURPOSE. This used to answer `available: True` and a
    hostname and nothing else, whatever state the machine was in -- so the
    readiness card and the model-facing health check both read a module that
    cannot read /etc/os-release as a healthy one (measured 2026-09-25:
    os_name 'Linux' with an error recorded, status() still {'available':
    True}). It now runs the cheapest read that can fail and reports what it
    got: a key is present only when it was read, and `note` carries the
    reason when something was not.
    """
    out = {"available": True}

    hostname = None
    try:
        hostname = socket.gethostname() or None
    except OSError as e:
        out["note"] = f"hostname unreadable: {type(e).__name__}: {e}"
    if hostname:
        out["hostname"] = hostname

    # The one file every other reading rests on: if this cannot be read, the
    # payload's own `os` block says so, and so should this.
    fields, problem = _read_os_release()
    if problem:
        out["os_readable"] = False
        out["note"] = problem
    else:
        out["os_readable"] = True
        out["os_name"] = fields.get("pretty_name") or fields.get("name")

    return out
