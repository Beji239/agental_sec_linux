#!/usr/bin/python3 -I
# tools/action_helper.py
# The root half of an approved action. The app runs unelevated and asks this
# helper, through pkexec, to carry out an action a person already approved.
#
# It imports nothing from the project tree and runs Python with -I, so no
# file the operator's account can write is ever executed as root.
#
# Two ways to run it:
#   serve [--max-age-hours N]   the session broker. pkexec asks for the
#                               password once, then this reads one JSON
#                               request per line on stdin until the app closes
#                               the pipe or the age cap is reached.
#   <verb> <args...>            one call, for the installer's --verify.
#
# Verbs, and nothing else:
#   block_ip <ip>                         drop one address, both directions
#   unblock_ip <ip>                       lift a block this helper made
#   list_blocks                           what this helper has blocked
#   kill <pid> <comm> <start_ticks>       end one process, pinned by identity
#   stop_unit <unit>                      systemctl stop, read back
#   disable_unit <unit>                   stop, disable and mask, read back
#   quarantine <path> <sha256>            move one file, pinned by its hash
#   restore <quarantine_id>               put a quarantined file back
#   list_quarantine                       what is held
#   kill_tree <pid> <comm> <start_ticks>  end one process and all it started
#   enable_unit <unit>                    unmask and enable, the undo of disable
#   remove_ssh_key <user> <fingerprint>   take one key out of authorized_keys
#   restore_ssh_key <undo_id>             put it back
#   lock_account <user>                   lock the password and expire it
#   unlock_account <undo_id>              put the account back as it was
#   remove_group_member <user> <group>    take a user out of a privileged group
#   restore_group_member <undo_id>        put the membership back
#   disable_cron_line <path> <line>       comment out one cron line
#   restore_cron_line <undo_id>           uncomment it
#   restore_blocks                        reapply saved blocks, run at boot
#
# The guards are here and not only in the app, because anything running as
# the operator's account can start this helper too. The password prompt is
# what stops that; these refusals are what stand behind it.
#
# Output is JSON with an "ok" key. Every call, refusals included, is appended
# to a root-owned log.

import base64
import fnmatch
import hashlib
import ipaddress
import json
import os
import pwd
import re
import select
import signal
import stat
import subprocess
import sys
import time

SCHEMA = 1

LOG_DIR = "/var/log/agentalsec"
LOG_PATH = LOG_DIR + "/action_helper.log"
QUARANTINE_DIR = "/var/lib/agental_sec/quarantine"
UNDO_DIR = "/var/lib/agental_sec/undo"
BLOCKS_STATE = "/var/lib/agental_sec/helper_blocks.json"
BOOT_UNIT = "agentalsec-blocks.service"
SHADOW_PATH = "/etc/shadow"
GROUP_PATH = "/etc/group"
NFT_TABLE = "agentalsec_helper"
MAX_BLOCKS = 512
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_REQUEST_BYTES = 64 * 1024
DEFAULT_MAX_AGE_HOURS = 12.0

VERBS = {
    "block_ip": ["ip"],
    "unblock_ip": ["ip"],
    "list_blocks": [],
    "kill": ["pid", "comm", "start_ticks"],
    "stop_unit": ["unit"],
    "disable_unit": ["unit"],
    "quarantine": ["path", "sha256"],
    "restore": ["quarantine_id"],
    "list_quarantine": [],
    "kill_tree": ["pid", "comm", "start_ticks"],
    "enable_unit": ["unit"],
    "remove_ssh_key": ["user", "fingerprint"],
    "restore_ssh_key": ["undo_id"],
    "lock_account": ["user"],
    "unlock_account": ["undo_id"],
    "remove_group_member": ["user", "group"],
    "restore_group_member": ["undo_id"],
    "disable_cron_line": ["path", "line"],
    "restore_cron_line": ["undo_id"],
    "restore_blocks": [],
}

# Groups that can become root or read what root reads. Membership of any
# other group is not this helper's business.
PRIVILEGED_GROUPS = ("sudo", "wheel", "adm", "docker", "lxd", "libvirt",
                     "disk", "shadow")

# Where cron reads jobs from. Scripts in cron.daily and friends are files,
# and quarantine is the verb for those.
CRON_FILES = ("/etc/crontab",)
CRON_DIRS = ("/etc/cron.d", "/var/spool/cron/crontabs")
USER_SPOOL = "/var/spool/cron/crontabs"

USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
UNDO_RE = re.compile(r"^\d{8}T\d{6}Z-[a-z_]{1,20}-[0-9a-f]{8}$")
KEY_TYPES = {
    "ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
}
MAX_SMALL_FILE = 1024 * 1024
MAX_TREE = 1024

# Processes this helper will not signal. Ending any of them takes the desktop,
# the logs, the network or a security control with it.
CRITICAL_PROCESSES = {
    "init", "systemd", "kthreadd",
    "xorg", "x", "gnome-shell", "gnome-session-binary", "gdm", "gdm3",
    "plasmashell", "kwin_x11", "kwin_wayland", "sddm", "lightdm",
    "cinnamon", "cinnamon-session", "cinnamon-session-binary", "muffin",
    "systemd-journald", "systemd-journal", "rsyslogd", "syslog-ng", "syslogd",
    "auditd", "systemd-logind", "polkitd", "dbus-daemon", "dbus-broker",
    "systemd-udevd", "udisksd", "upowerd", "accounts-daemon",
    "systemd-resolved", "systemd-timesyncd", "chronyd", "ntpd",
    "login", "systemd-oomd", "irqbalance", "thermald",
    "networkmanager", "systemd-networkd", "wpa_supplicant", "dhclient",
    "cron", "crond", "atd", "dockerd", "containerd", "kubelet",
    "cupsd", "snapd", "fail2ban-server", "pkexec", "sudo",
}

# Anything whose running file or arguments live here is part of AgentalSec,
# including the kernel camera, and is not signalled.
AGENTALSEC_PATHS = ("/usr/local/lib/agentalsec", "/var/lib/agental_sec")

UNIT_RE = re.compile(r"^[A-Za-z0-9:_.@\\-]{1,200}\.(service|socket|timer|path)$")

# Units this helper will not stop. Security controls, logging, the session
# and the machinery everything else depends on.
PROTECTED_UNITS = (
    "agentalsec*", "systemd-*", "dbus*", "polkit*", "auditd*", "apparmor*",
    "ufw*", "nftables*", "firewalld*", "fail2ban*", "rsyslog*", "syslog*",
    "networkmanager*", "network-manager*", "wpa_supplicant*", "lightdm*",
    "gdm*", "sddm*", "display-manager*", "getty@*", "user@*",
    "user-runtime-dir@*", "cron*", "accounts-daemon*", "udisks2*", "upower*",
    "init*", "emergency*", "rescue*",
)

# Paths quarantine will not take. The rest of the filesystem is allowed,
# because a file root planted in /etc/cron.d or /usr/local/bin is exactly
# what this verb is for. Package-owned files are refused separately.
DENY_PREFIXES = (
    "/proc", "/sys", "/dev", "/run", "/boot", "/var/lib/dpkg", "/var/lib/apt",
    "/var/log", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/usr/bin",
    "/usr/sbin", "/usr/lib", "/usr/lib32", "/usr/lib64", "/usr/libexec",
    "/snap", "/var/snap",
) + AGENTALSEC_PATHS
DENY_FILES = {
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/sudoers", "/etc/fstab", "/etc/hosts", "/etc/resolv.conf",
    "/etc/hostname", "/etc/ld.so.cache", "/etc/ld.so.conf",
    "/etc/nsswitch.conf", "/etc/ssh/sshd_config", "/etc/crypttab",
    "/etc/login.defs", "/etc/environment",
}
DENY_GLOBS = ("/etc/pam.d/*", "/etc/security/*", "/etc/sudoers.d/README",
              "/etc/polkit-1/*", "/usr/share/polkit-1/*")

QID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{12}$")


class Refusal(Exception):
    """A verb that will not run. Always carries a sentence for the operator."""


# THE SELF-CHECKS, the same two the read helper makes.

def self_problems() -> list:
    path = os.path.realpath(__file__)
    problems = []
    while True:
        try:
            st = os.stat(path)
        except OSError as e:
            problems.append(f"{path}: cannot be stat'ed ({e})")
            break
        if st.st_uid != 0:
            problems.append(f"{path} is owned by uid {st.st_uid}, not root")
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            problems.append(f"{path} is group- or world-writable")
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    return problems


def preflight():
    problems = self_problems()
    if problems:
        raise Refusal(
            "This helper refused to run because the path it is installed at "
            "could be replaced by a non-root account: " + "; ".join(problems)
            + ". Install it with scripts/install_action_helper.sh. Nothing ran.")
    if os.geteuid() != 0:
        raise Refusal(
            f"This helper is running as uid {os.geteuid()}, not root, so it "
            f"cannot do anything the app could not. pkexec did not elevate.")


# THE RECORD

def log(entry: dict):
    """Append one line to the root-owned log. A failure to log is reported,
    never fatal: the action's own result still reaches the caller."""
    try:
        os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
        fd = os.open(LOG_PATH, os.O_WRONLY | os.O_APPEND | os.O_CREAT
                     | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
        return None
    except OSError as e:
        return f"{type(e).__name__}: {e}"


def _run(argv, timeout=30):
    """(returncode, stdout, stderr). Never a shell, never a caller string
    that is not already validated."""
    try:
        res = subprocess.run(argv, capture_output=True, text=True,
                             timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                                                   "LC_ALL": "C"})
    except subprocess.TimeoutExpired:
        return 124, "", f"{argv[0]} did not finish within {timeout}s"
    except OSError as e:
        return 127, "", f"{type(e).__name__}: {e}"
    return res.returncode, res.stdout, res.stderr.strip()


# ADDRESSES

def _host_addresses() -> set:
    """This host's addresses, its default gateways and its resolvers."""
    found = set()
    rc, out, _ = _run(["ip", "-j", "addr"])
    if rc == 0:
        try:
            for iface in json.loads(out):
                for a in iface.get("addr_info", []):
                    if a.get("local"):
                        found.add(a["local"].split("%")[0])
        except ValueError:
            pass
    for fam in ("-4", "-6"):
        rc, out, _ = _run(["ip", "-j", fam, "route", "show", "default"])
        if rc == 0:
            try:
                for r in json.loads(out):
                    if r.get("gateway"):
                        found.add(r["gateway"].split("%")[0])
            except ValueError:
                pass
    for conf in ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"):
        try:
            with open(conf, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        found.add(parts[1].split("%")[0])
        except OSError:
            pass
    return found


def _validated_ip(value: str):
    if not isinstance(value, str) or "/" in value or len(value) > 64:
        raise Refusal(f"{value!r} is not one address. This helper blocks a "
                      f"single host, never a range.")
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        raise Refusal(f"{value!r} is not an IP address.")
    if (ip.is_loopback or ip.is_unspecified or ip.is_multicast
            or ip.is_link_local or ip.is_reserved
            or str(ip) == "255.255.255.255"):
        raise Refusal(f"{ip} is a loopback, unspecified, multicast, link-local "
                      f"or reserved address. Blocking it would break this "
                      f"host's own networking rather than stop a peer.")
    return ip


def _set_name(ip) -> str:
    return "blocked4" if ip.version == 4 else "blocked6"


NFT_SKELETON = f"""
table inet {NFT_TABLE} {{
    set blocked4 {{ type ipv4_addr; }}
    set blocked6 {{ type ipv6_addr; }}
    chain input {{
        type filter hook input priority -5; policy accept;
        ip saddr @blocked4 drop
        ip6 saddr @blocked6 drop
    }}
    chain output {{
        type filter hook output priority -5; policy accept;
        ip daddr @blocked4 drop
        ip6 daddr @blocked6 drop
    }}
    chain forward {{
        type filter hook forward priority -5; policy accept;
        ip saddr @blocked4 drop
        ip daddr @blocked4 drop
        ip6 saddr @blocked6 drop
        ip6 daddr @blocked6 drop
    }}
}}
"""


def _nft_ensure():
    rc, _, _ = _run(["nft", "list", "table", "inet", NFT_TABLE])
    if rc == 0:
        return
    try:
        res = subprocess.run(["nft", "-f", "-"], input=NFT_SKELETON, text=True,
                             capture_output=True, timeout=30,
                             env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"})
    except (OSError, subprocess.SubprocessError) as e:
        raise Refusal(f"nft could not be run: {type(e).__name__}: {e}")
    if res.returncode != 0:
        raise Refusal(f"nft refused to create the {NFT_TABLE} table: "
                      f"{res.stderr.strip()[:300]}")


def _nft_elements(set_name: str) -> list:
    rc, out, err = _run(["nft", "-j", "list", "set", "inet", NFT_TABLE,
                         set_name])
    if rc != 0:
        raise Refusal(f"nft could not read the {set_name} set: {err[:300]}")
    found = []
    try:
        for item in json.loads(out).get("nftables", []):
            for elem in (item.get("set") or {}).get("elem", []) or []:
                found.append(elem if isinstance(elem, str) else str(elem))
    except (ValueError, AttributeError):
        raise Refusal("nft returned a listing this helper could not parse.")
    return found


def verb_block_ip(ip_text):
    ip = _validated_ip(ip_text)
    if str(ip) in _host_addresses():
        raise Refusal(f"{ip} is this host, its default gateway or its DNS "
                      f"resolver. Blocking it would cut this machine off "
                      f"rather than stop a peer. Nothing was changed.")
    _nft_ensure()
    name = _set_name(ip)
    before = _nft_elements(name)
    if str(ip) in before:
        return {"blocked": str(ip), "already": True, "set": name,
                "persists": _save_blocks()}
    if len(_nft_elements("blocked4")) + len(_nft_elements("blocked6")) >= MAX_BLOCKS:
        raise Refusal(f"This helper already holds {MAX_BLOCKS} blocks, its "
                      f"cap. Lift some before adding more.")
    rc, _, err = _run(["nft", "add", "element", "inet", NFT_TABLE, name,
                       "{", str(ip), "}"])
    if rc != 0:
        raise Refusal(f"nft refused to add {ip}: {err[:300]}")
    if str(ip) not in _nft_elements(name):
        raise Refusal(f"nft reported success but {ip} is not in the set when "
                      f"read back. Treat it as NOT blocked.")
    return {"blocked": str(ip), "already": False, "set": name,
            "verified_by": "read back from the nft set",
            "persists": _save_blocks()}


def verb_unblock_ip(ip_text):
    ip = _validated_ip(ip_text)
    name = _set_name(ip)
    rc, _, _ = _run(["nft", "list", "table", "inet", NFT_TABLE])
    if rc != 0 or str(ip) not in _nft_elements(name):
        return {"unblocked": str(ip), "was_blocked": False,
                "note": "this helper held no block on that address"}
    rc, _, err = _run(["nft", "delete", "element", "inet", NFT_TABLE, name,
                       "{", str(ip), "}"])
    if rc != 0:
        raise Refusal(f"nft refused to remove {ip}: {err[:300]}")
    if str(ip) in _nft_elements(name):
        raise Refusal(f"{ip} is still in the set after the delete. It is "
                      f"STILL BLOCKED.")
    _save_blocks()
    return {"unblocked": str(ip), "was_blocked": True,
            "verified_by": "read back from the nft set"}


def _write_root_file(path: str, data: str):
    """Write a root-only file atomically, never through a link."""
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = f"{path}.tmp-{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _boot_restore_installed() -> bool:
    rc, _, _ = _run(["systemctl", "is-enabled", "--quiet", BOOT_UNIT])
    return rc == 0


def _save_blocks() -> str:
    """Record what is blocked so the boot unit can put it back. Says how
    long the block lasts, which depends on whether that unit is installed."""
    try:
        held = _nft_elements("blocked4") + _nft_elements("blocked6")
        _write_root_file(BLOCKS_STATE, json.dumps(
            {"schema": SCHEMA, "blocked": sorted(set(held))}, indent=2))
    except (OSError, Refusal) as e:
        return f"until reboot (the saved list could not be written: {e})"
    if _boot_restore_installed():
        return "across reboots"
    return (f"until reboot, because {BOOT_UNIT} is not installed. The block "
            f"is saved and comes back once it is.")


def _read_root_file(path: str) -> bytes:
    """Read a file only root could have written."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if st.st_uid != os.geteuid() or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise Refusal(f"{path} is not owned by this account alone, so it "
                          f"is not trusted.")
        return fh.read(MAX_SMALL_FILE)


def verb_restore_blocks():
    try:
        saved = json.loads(_read_root_file(BLOCKS_STATE))
    except FileNotFoundError:
        return {"restored": [], "note": "no saved blocks"}
    except ValueError as e:
        raise Refusal(f"{BLOCKS_STATE} could not be parsed: {e}")
    _nft_ensure()
    restored, skipped = [], []
    for text in saved.get("blocked", [])[:MAX_BLOCKS]:
        try:
            ip = _validated_ip(str(text))
        except Refusal as e:
            skipped.append({"ip": text, "why": str(e)})
            continue
        name = _set_name(ip)
        if str(ip) in _nft_elements(name):
            restored.append(str(ip))
            continue
        rc, _, err = _run(["nft", "add", "element", "inet", NFT_TABLE, name,
                           "{", str(ip), "}"])
        if rc != 0:
            skipped.append({"ip": str(ip), "why": err[:200]})
        else:
            restored.append(str(ip))
    held = set(_nft_elements("blocked4") + _nft_elements("blocked6"))
    missing = [ip for ip in restored if ip not in held]
    return {"restored": [ip for ip in restored if ip in held],
            "skipped": skipped, "missing_after": missing,
            "verified_by": "read back from the nft set"}


def verb_list_blocks():
    rc, _, _ = _run(["nft", "list", "table", "inet", NFT_TABLE])
    if rc != 0:
        return {"table": False, "blocked": []}
    return {"table": True,
            "blocked": _nft_elements("blocked4") + _nft_elements("blocked6")}


# PROCESSES

def _stat_fields(pid: int):
    """(comm, flags, start_ticks) from /proc/<pid>/stat, or None."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            data = fh.read(4096).decode("utf-8", errors="replace")
    except OSError:
        return None
    head, _, rest = data.rpartition(")")
    comm = head.split("(", 1)[-1]
    fields = rest.split()
    try:
        return comm, int(fields[6]), int(fields[19])
    except (IndexError, ValueError):
        return None


def _cmdline(pid: int) -> list:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            return [a.decode("utf-8", errors="replace")
                    for a in fh.read(65536).split(b"\0") if a]
    except OSError:
        return []


PF_KTHREAD = 0x00200000


def _protected_reason(pid: int, comm: str, flags: int) -> str:
    """Why this process is never signalled, or empty."""
    if pid <= 1:
        return f"pid {pid} is init or not a process"
    if pid in (os.getpid(), os.getppid()):
        return f"pid {pid} is this helper or the app that started it"
    if flags & PF_KTHREAD:
        return f"pid {pid} ({comm}) is a kernel thread"
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = ""
    exe_base = os.path.basename(exe.split(" (deleted)")[0]).lower()
    for label, value in (("comm", comm.lower()), ("exe", exe_base)):
        if value in CRITICAL_PROCESSES:
            return (f"pid {pid} is {value} (from its {label}), which this "
                    f"helper never signals: it would take the desktop, the "
                    f"logs, the network or a security control with it. If it "
                    f"is a service, stop_unit is the door")
    args = [exe] + _cmdline(pid)
    if any(a.startswith(p) for a in args for p in AGENTALSEC_PATHS):
        return (f"pid {pid} is part of AgentalSec ({exe or comm}). This "
                f"helper does not end its own camera or sensors")
    return ""


def _pinned(pid_text, comm_expected, ticks_text):
    """(pid, ticks, comm) for the process the approval named, or a Refusal.
    None for pid when it has already exited."""
    try:
        pid = int(pid_text)
        ticks = int(ticks_text)
    except (TypeError, ValueError):
        raise Refusal("pid and start_ticks must be integers.")
    if pid <= 1:
        raise Refusal(f"pid {pid} is init or not a process. Never signalled.")
    if pid in (os.getpid(), os.getppid()):
        raise Refusal(f"pid {pid} is this helper or the app that started it.")
    fields = _stat_fields(pid)
    if fields is None:
        return None, ticks, comm_expected
    comm, flags, start = fields
    if start != ticks or comm != comm_expected:
        raise Refusal(
            f"pid {pid} is now {comm!r} started at tick {start}, and the "
            f"approval named {comm_expected!r} at tick {ticks}. The pid was "
            f"reused or the wrong process was named. Nothing was signalled.")
    why = _protected_reason(pid, comm, flags)
    if why:
        raise Refusal(why + ". Nothing was signalled.")
    return pid, ticks, comm


def verb_kill(pid_text, comm_expected, ticks_text):
    pid, ticks, comm = _pinned(pid_text, comm_expected, ticks_text)
    if pid is None:
        return {"pid": int(pid_text), "gone": True, "note": "the process had "
                "already exited, so nothing was signalled"}
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = ""

    try:
        pidfd = os.pidfd_open(pid)
    except ProcessLookupError:
        return {"pid": pid, "gone": True,
                "note": "exited before it could be signalled"}
    try:
        # Checked again through the pidfd, so the signal cannot reach a
        # process that took this pid after the checks above.
        again = _stat_fields(pid)
        if again is None or again[2] != ticks:
            raise Refusal(f"pid {pid} changed while it was being checked. "
                          f"Nothing was signalled.")
        signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        poller = select.poll()
        poller.register(pidfd, select.POLLIN)
        sent = ["SIGTERM"]
        if not poller.poll(5000):
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            sent.append("SIGKILL")
            poller.poll(3000)
        gone = bool(poller.poll(0))
    finally:
        os.close(pidfd)
    return {"pid": pid, "comm": comm, "exe": exe, "signals": sent,
            "gone": gone,
            "note": ("confirmed exited through its pidfd" if gone else
                     "STILL RUNNING after SIGKILL: likely stuck in the kernel "
                     "or already a zombie waiting on its parent")}


def _children_map() -> dict:
    """ppid -> [(pid, start_ticks, comm, flags)] from one pass over /proc."""
    kids = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        try:
            with open(f"/proc/{pid}/stat", "rb") as fh:
                data = fh.read(4096).decode("utf-8", errors="replace")
        except OSError:
            continue
        head, _, rest = data.rpartition(")")
        fields = rest.split()
        try:
            ppid, flags, start = int(fields[1]), int(fields[6]), int(fields[19])
        except (IndexError, ValueError):
            continue
        kids.setdefault(ppid, []).append(
            (pid, start, head.split("(", 1)[-1], flags))
    return kids


def verb_kill_tree(pid_text, comm_expected, ticks_text):
    root, ticks, comm = _pinned(pid_text, comm_expected, ticks_text)
    if root is None:
        return {"pid": int(pid_text), "gone": True, "note": "the process had "
                "already exited, so nothing was signalled"}
    held = {}          # pid -> (pidfd, comm)
    skipped = []
    try:
        fd = os.pidfd_open(root)
    except ProcessLookupError:
        return {"pid": root, "gone": True,
                "note": "exited before it could be signalled"}
    again = _stat_fields(root)
    if again is None or again[2] != ticks:
        os.close(fd)
        raise Refusal(f"pid {root} changed while it was being checked. "
                      f"Nothing was signalled.")
    # Stopped first, parent before children, so nothing in the tree can fork
    # a new child or be reparented while it is being collected.
    signal.pidfd_send_signal(fd, signal.SIGSTOP)
    held[root] = (fd, comm)
    try:
        for _ in range(8):
            kids = _children_map()
            found = False
            for parent in list(held):
                for pid, start, kcomm, flags in kids.get(parent, []):
                    if pid in held or any(s["pid"] == pid for s in skipped):
                        continue
                    why = _protected_reason(pid, kcomm, flags)
                    if why:
                        skipped.append({"pid": pid, "comm": kcomm, "why": why})
                        continue
                    if len(held) >= MAX_TREE:
                        raise Refusal(f"the tree under pid {root} has more "
                                      f"than {MAX_TREE} processes. It was "
                                      f"stopped, not killed; check it by hand.")
                    try:
                        kfd = os.pidfd_open(pid)
                    except ProcessLookupError:
                        continue
                    now = _stat_fields(pid)
                    if now is None or now[2] != start:
                        os.close(kfd)
                        continue
                    signal.pidfd_send_signal(kfd, signal.SIGSTOP)
                    held[pid] = (kfd, kcomm)
                    found = True
            if not found:
                break
        for pid, (kfd, _) in held.items():
            try:
                signal.pidfd_send_signal(kfd, signal.SIGKILL)
            except ProcessLookupError:
                pass
        results = []
        deadline = time.monotonic() + 5
        for pid, (kfd, kcomm) in held.items():
            poller = select.poll()
            poller.register(kfd, select.POLLIN)
            left = max(0, int((deadline - time.monotonic()) * 1000))
            results.append({"pid": pid, "comm": kcomm,
                            "gone": bool(poller.poll(left))})
    except Exception:
        # Anything that stops the kill part way must not leave the tree frozen.
        for kfd, _ in held.values():
            try:
                signal.pidfd_send_signal(kfd, signal.SIGCONT)
            except ProcessLookupError:
                pass
        raise
    finally:
        for kfd, _ in held.values():
            os.close(kfd)
    still = [r for r in results if not r["gone"]]
    return {"pid": root, "comm": comm, "signals": ["SIGSTOP", "SIGKILL"],
            "killed": results, "skipped": skipped,
            "gone": not still,
            "note": ("every process in the tree confirmed exited through its "
                     "pidfd" if not still else
                     f"{len(still)} process(es) STILL RUNNING after SIGKILL")
                    + (f". {len(skipped)} protected child process(es) were "
                       f"left alone, see skipped" if skipped else "")}


# UNITS

def _validated_unit(unit: str) -> str:
    if not isinstance(unit, str) or not UNIT_RE.match(unit) \
            or unit.startswith("-"):
        raise Refusal(f"{unit!r} is not a system unit name this helper "
                      f"accepts (name.service, .socket, .timer or .path).")
    lowered = unit.lower()
    for pattern in PROTECTED_UNITS:
        if fnmatch.fnmatch(lowered, pattern):
            raise Refusal(
                f"{unit} matches {pattern!r}, a unit this helper never stops: "
                f"a security control, the logs, the session or something "
                f"everything else depends on.")
    return unit


def _unit_state(unit: str) -> dict:
    rc, out, err = _run(["systemctl", "show", "--no-pager", "-p",
                         "LoadState,ActiveState,SubState,UnitFileState,"
                         "FragmentPath", "--", unit])
    if rc != 0:
        raise Refusal(f"systemctl could not describe {unit}: {err[:300]}")
    state = {}
    for line in out.splitlines():
        key, _, value = line.partition("=")
        state[key] = value
    return state


def verb_stop_unit(unit):
    unit = _validated_unit(unit)
    before = _unit_state(unit)
    if before.get("LoadState") != "loaded":
        raise Refusal(f"{unit} is not a loaded system unit "
                      f"(LoadState={before.get('LoadState')}). Nothing ran.")
    rc, _, err = _run(["systemctl", "stop", "--", unit], timeout=120)
    after = _unit_state(unit)
    stopped = after.get("ActiveState") in ("inactive", "failed")
    if rc != 0 and not stopped:
        raise Refusal(f"systemctl stop {unit} failed: {err[:300]}")
    return {"unit": unit, "before": before, "after": after,
            "stopped": stopped,
            "note": ("read back as not running" if stopped else
                     "STILL ACTIVE after the stop, so something restarted it")}


def verb_disable_unit(unit):
    unit = _validated_unit(unit)
    before = _unit_state(unit)
    if before.get("LoadState") not in ("loaded", "masked"):
        raise Refusal(f"{unit} is not a loaded system unit "
                      f"(LoadState={before.get('LoadState')}). Nothing ran.")
    steps = []
    for argv in (["systemctl", "disable", "--now", "--", unit],
                 ["systemctl", "mask", "--", unit]):
        rc, _, err = _run(argv, timeout=120)
        steps.append({"ran": " ".join(argv[1:]), "exit": rc,
                      "stderr": err[:300]})
    after = _unit_state(unit)
    done = (after.get("ActiveState") in ("inactive", "failed")
            and after.get("UnitFileState") == "masked")
    return {"unit": unit, "before": before, "after": after, "steps": steps,
            "disabled_and_masked": done,
            "note": ("read back as stopped and masked" if done else
                     "NOT fully disabled, see steps and after"),
            "undo": f"systemctl unmask {unit} && systemctl enable {unit}"}


def verb_enable_unit(unit):
    unit = _validated_unit(unit)
    before = _unit_state(unit)
    steps = []
    for argv in (["systemctl", "unmask", "--", unit],
                 ["systemctl", "enable", "--", unit]):
        rc, _, err = _run(argv, timeout=120)
        steps.append({"ran": " ".join(argv[1:]), "exit": rc,
                      "stderr": err[:300]})
    after = _unit_state(unit)
    done = after.get("UnitFileState") not in ("masked", "masked-runtime")
    return {"unit": unit, "before": before, "after": after, "steps": steps,
            "unmasked": done,
            "note": ("read back as unmasked; it is enabled but was not started"
                     if done else "STILL MASKED, see steps and after")}


# FILES

def _path_refusal(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/") or "\0" in path \
            or len(path) > 4096:
        return "the path must be absolute"
    if os.path.normpath(path) != path:
        return "the path must be written without '..', '.' or doubled slashes"
    if any(c in path for c in "*?[]"):
        return "the path contains a glob character"
    for prefix in DENY_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return (f"it is under {prefix}, which holds the system's own "
                    f"programs, logs or state, or AgentalSec itself")
    if path in DENY_FILES:
        return "it is a file the machine cannot run or log in without"
    for pattern in DENY_GLOBS:
        if fnmatch.fnmatch(path, pattern):
            return f"it matches {pattern}, which decides who may log in or act"
    parent = os.path.dirname(path)
    if os.path.realpath(parent) != parent:
        return ("a directory on its way is a symlink, so the file that would "
                "move is not the one named")
    return ""


def _package_owner(path: str) -> str:
    rc, out, _ = _run(["dpkg-query", "-S", path], timeout=60)
    if rc == 0 and out.strip():
        return out.strip().split(":", 1)[0]
    return ""


def verb_quarantine(path, sha_expected):
    why = _path_refusal(path)
    if why:
        raise Refusal(f"{path} was not quarantined: {why}.")
    # "-" when the app could not read the file to pin it; the hash taken here
    # is then the record.
    if sha_expected != "-" and not re.fullmatch(r"[0-9a-f]{64}",
                                                 sha_expected or ""):
        raise Refusal("the pin must be the file's full sha256, or '-'.")
    owner = _package_owner(path)
    if owner:
        raise Refusal(f"{path} belongs to the package {owner}. Moving it "
                      f"would break that package; if it was tampered with, "
                      f"reinstall the package instead.")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        raise Refusal(f"{path} could not be opened without following a link: "
                      f"{e}")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refusal(f"{path} is not a regular file.")
        if st.st_size > MAX_FILE_BYTES:
            raise Refusal(f"{path} is larger than {MAX_FILE_BYTES} bytes.")
        digest = hashlib.sha256()
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            digest.update(chunk)
            chunks.append(chunk)
        sha = digest.hexdigest()
        if sha_expected != "-" and sha != sha_expected:
            raise Refusal(f"{path} now hashes to {sha[:16]}..., not the "
                          f"{sha_expected[:16]}... that was approved. It "
                          f"changed since the approval. Nothing was moved.")
        qid = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + sha[:12]
        os.makedirs(QUARANTINE_DIR, mode=0o700, exist_ok=True)
        os.chmod(QUARANTINE_DIR, 0o700)
        home = os.path.join(QUARANTINE_DIR, qid)
        os.mkdir(home, 0o700)
        out = os.open(os.path.join(home, "payload"),
                      os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                      0o400)
        with os.fdopen(out, "wb") as fh:
            for chunk in chunks:
                fh.write(chunk)
            fh.flush()
            os.fsync(fh.fileno())
        manifest = {"schema": SCHEMA, "id": qid, "original_path": path,
                    "sha256": sha, "size": st.st_size,
                    "mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid,
                    "gid": st.st_gid, "mtime_ns": st.st_mtime_ns,
                    "quarantined_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                    time.gmtime()),
                    "by_uid": os.environ.get("PKEXEC_UID")}
        mfd = os.open(os.path.join(home, "manifest.json"),
                      os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                      0o600)
        with os.fdopen(mfd, "w") as fh:
            json.dump(manifest, fh, indent=2)
        # The original goes only if it is still the file that was hashed.
        now = os.lstat(path)
        if (now.st_ino, now.st_dev) != (st.st_ino, st.st_dev):
            raise Refusal(f"{path} was replaced while it was being copied. "
                          f"A copy is held as {qid}; the original was left.")
        os.unlink(path)
    finally:
        os.close(fd)
    return {"quarantined": path, "id": qid, "sha256": sha,
            "held_at": home, "undo": f"restore {qid}"}


def verb_restore(qid):
    if not QID_RE.match(qid or ""):
        raise Refusal(f"{qid!r} is not a quarantine id.")
    home = os.path.join(QUARANTINE_DIR, qid)
    try:
        with open(os.path.join(home, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as e:
        raise Refusal(f"quarantine {qid} has no readable manifest: {e}")
    path = manifest.get("original_path", "")
    why = _path_refusal(path)
    if why:
        raise Refusal(f"the manifest names {path}, which is refused: {why}.")
    if os.path.lexists(path):
        raise Refusal(f"{path} exists again, so restoring would overwrite it. "
                      f"Nothing was changed.")
    with open(os.path.join(home, "payload"), "rb") as fh:
        data = fh.read(MAX_FILE_BYTES + 1)
    if hashlib.sha256(data).hexdigest() != manifest.get("sha256"):
        raise Refusal(f"the held copy of {qid} no longer matches its recorded "
                      f"hash. Not restored.")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.chown(path, int(manifest.get("uid", 0)), int(manifest.get("gid", 0)))
    os.chmod(path, int(manifest.get("mode", 0o600)))
    for name in ("payload", "manifest.json"):
        os.unlink(os.path.join(home, name))
    os.rmdir(home)
    return {"restored": path, "id": qid, "sha256": manifest.get("sha256")}


def verb_list_quarantine():
    held = []
    try:
        names = sorted(os.listdir(QUARANTINE_DIR))
    except FileNotFoundError:
        return {"held": []}
    for name in names:
        try:
            with open(os.path.join(QUARANTINE_DIR, name, "manifest.json"),
                      encoding="utf-8") as fh:
                m = json.load(fh)
            held.append({k: m.get(k) for k in ("id", "original_path",
                                               "sha256", "size",
                                               "quarantined_at")})
        except (OSError, ValueError) as e:
            held.append({"id": name, "unreadable": str(e)})
    return {"held": held}


# UNDO RECORDS. What a containment verb changed, kept root-only, so the
# matching restore verb puts back exactly that and nothing a caller supplies.

def _save_undo(kind: str, record: dict) -> str:
    uid = (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{kind}-"
           + os.urandom(4).hex())
    record = dict(record, kind=kind, id=uid, schema=SCHEMA,
                  by_uid=os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID"))
    _write_root_file(os.path.join(UNDO_DIR, uid + ".json"),
                     json.dumps(record, indent=2))
    return uid


def _load_undo(uid: str, kind: str) -> dict:
    if not isinstance(uid, str) or not UNDO_RE.match(uid):
        raise Refusal(f"{uid!r} is not an undo id.")
    if f"-{kind}-" not in uid:
        raise Refusal(f"{uid} is not a {kind} undo record.")
    try:
        return json.loads(_read_root_file(os.path.join(UNDO_DIR, uid + ".json")))
    except FileNotFoundError:
        raise Refusal(f"there is no undo record {uid}; it was used already or "
                      f"never existed.")
    except ValueError as e:
        raise Refusal(f"undo record {uid} could not be parsed: {e}")


def _spend_undo(uid: str):
    try:
        os.unlink(os.path.join(UNDO_DIR, uid + ".json"))
    except OSError:
        pass


# ACCOUNTS

def _validated_user(name) -> "pwd.struct_passwd":
    if not isinstance(name, str) or not USER_RE.match(name):
        raise Refusal(f"{name!r} is not an account name this helper accepts.")
    try:
        return pwd.getpwnam(name)
    except KeyError:
        raise Refusal(f"There is no account named {name}.")


def _caller_name():
    raw = os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID") or ""
    try:
        return pwd.getpwuid(int(raw)).pw_name
    except (ValueError, KeyError):
        return None


def _refuse_core_account(pw, what: str):
    if pw.pw_name == "root":
        raise Refusal(f"{what} root is refused: it is how this machine is "
                      f"administered and recovered.")
    if pw.pw_name == _caller_name():
        raise Refusal(f"{what} {pw.pw_name} is refused: it is the account "
                      f"that approved this, and doing it could lock the "
                      f"operator out of their own machine.")


def _shadow_fields(user: str):
    with open(SHADOW_PATH, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            f = line.rstrip("\n").split(":")
            if f and f[0] == user and len(f) >= 8:
                return {"locked": f[1].startswith("!"), "expire": f[7]}
    return None


def verb_lock_account(user):
    pw = _validated_user(user)
    _refuse_core_account(pw, "Locking")
    before = _shadow_fields(user)
    if before is None:
        raise Refusal(f"{user} has no line in {SHADOW_PATH}, so it cannot be "
                      f"locked here.")
    # -L locks the password, an expiry date in the past stops key logins too.
    rc, _, err = _run(["usermod", "-L", "-e", "1", user])
    after = _shadow_fields(user)
    done = bool(after and after["locked"] and after["expire"] == "1")
    if not done:
        raise Refusal(f"usermod did not leave {user} locked and expired "
                      f"(exit {rc}: {err[:200]}). Treat it as NOT locked.")
    uid = _save_undo("account", {"user": user, "before": before})
    return {"user": user, "locked": True, "before": before, "after": after,
            "verified_by": f"read back from {SHADOW_PATH}",
            "undo": f"unlock_account {uid}", "undo_id": uid,
            "note": ("New logins are refused, by password and by key. "
                     "Sessions and processes already running as this account "
                     "keep running.")}


def verb_unlock_account(uid):
    rec = _load_undo(uid, "account")
    pw = _validated_user(rec.get("user", ""))
    before = rec.get("before") or {}
    steps = []
    if not before.get("locked"):
        rc, _, err = _run(["usermod", "-U", pw.pw_name])
        steps.append({"ran": "usermod -U", "exit": rc, "stderr": err[:200]})
    expire = str(before.get("expire") or "")
    if not re.fullmatch(r"\d{0,6}", expire):
        expire = ""
    rc, _, err = _run(["usermod", "-e", expire or "", pw.pw_name])
    steps.append({"ran": f"usermod -e {expire!r}", "exit": rc,
                  "stderr": err[:200]})
    after = _shadow_fields(pw.pw_name)
    done = bool(after and after["locked"] == bool(before.get("locked"))
                and after["expire"] == expire)
    if done:
        _spend_undo(uid)
    return {"user": pw.pw_name, "restored": done, "after": after,
            "steps": steps,
            "note": ("read back as it was before the lock" if done else
                     "NOT back to how it was, see steps and after")}


# GROUPS

def _group_members(group: str):
    with open(GROUP_PATH, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            f = line.rstrip("\n").split(":")
            if len(f) >= 4 and f[0] == group:
                return int(f[2]), [m for m in f[3].split(",") if m]
    return None


def verb_remove_group_member(user, group):
    pw = _validated_user(user)
    if group not in PRIVILEGED_GROUPS:
        raise Refusal(f"{group!r} is not one of the groups this helper "
                      f"manages: {', '.join(PRIVILEGED_GROUPS)}.")
    _refuse_core_account(pw, f"Taking out of {group}")
    found = _group_members(group)
    if found is None:
        raise Refusal(f"There is no group named {group} on this machine.")
    gid, members = found
    primary = gid == pw.pw_gid
    if user not in members:
        return {"user": user, "group": group, "removed": False,
                "note": (f"{user} is not a listed member of {group}"
                         + (f". It is {user}'s PRIMARY group, which gpasswd "
                            f"cannot remove; that needs usermod -g by hand"
                            if primary else ", so nothing was changed"))}
    rc, _, err = _run(["gpasswd", "-d", user, group])
    after = _group_members(group)
    if after is None or user in after[1]:
        raise Refusal(f"{user} is still in {group} after gpasswd (exit {rc}: "
                      f"{err[:200]}). Treat it as NOT removed.")
    uid = _save_undo("group", {"user": user, "group": group})
    return {"user": user, "group": group, "removed": True,
            "verified_by": f"read back from {GROUP_PATH}",
            "undo": f"restore_group_member {uid}", "undo_id": uid,
            "note": ("Sessions already logged in keep the group until they "
                     "log out; a running process keeps it until it exits."
                     + (f" {group} is also {user}'s primary group, which "
                        f"still applies." if primary else ""))}


def verb_restore_group_member(uid):
    rec = _load_undo(uid, "group")
    pw = _validated_user(rec.get("user", ""))
    group = rec.get("group")
    if group not in PRIVILEGED_GROUPS:
        raise Refusal(f"the undo record names {group!r}, which is refused.")
    rc, _, err = _run(["gpasswd", "-a", pw.pw_name, group])
    after = _group_members(group)
    done = bool(after and pw.pw_name in after[1])
    if done:
        _spend_undo(uid)
    return {"user": pw.pw_name, "group": group, "restored": done,
            "note": ("read back as a member again" if done else
                     f"NOT a member after gpasswd -a (exit {rc}: {err[:200]})")}


# TEXT FILES SHARED BY THE SSH KEY AND CRON VERBS

def _open_text(path: str):
    """(text, stat) of a small regular file, opened without following a link."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise Refusal(f"{path} is not a regular file.")
        if st.st_size > MAX_SMALL_FILE:
            raise Refusal(f"{path} is larger than {MAX_SMALL_FILE} bytes.")
        return fh.read().decode("utf-8", errors="surrogateescape"), st


def _rewrite(path: str, text: str, st):
    """Replace a file atomically, keeping its owner and mode."""
    tmp = f"{path}.agentalsec-{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 stat.S_IMODE(st.st_mode))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(text.encode("utf-8", errors="surrogateescape"))
            fh.flush()
            os.fchown(fh.fileno(), st.st_uid, st.st_gid)
            os.fchmod(fh.fileno(), stat.S_IMODE(st.st_mode))
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# SSH KEYS

def _key_fingerprint(line: str):
    """OpenSSH's SHA256 fingerprint of the key on one authorized_keys line."""
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    parts = text.split()
    for i, token in enumerate(parts[:-1]):
        if token not in KEY_TYPES:
            continue
        try:
            blob = base64.b64decode(parts[i + 1], validate=True)
        except (ValueError, TypeError):
            return None
        n = int.from_bytes(blob[:4], "big") if len(blob) >= 4 else 0
        if blob[4:4 + n].decode("ascii", errors="replace") != token:
            return None
        return "SHA256:" + base64.b64encode(
            hashlib.sha256(blob).digest()).decode().rstrip("=")
    return None


def _key_files(pw) -> list:
    ssh_dir = os.path.join(pw.pw_dir, ".ssh")
    try:
        if stat.S_ISLNK(os.lstat(ssh_dir).st_mode):
            raise Refusal(f"{ssh_dir} is a symlink, so the file that would "
                          f"change is not the one named.")
    except FileNotFoundError:
        return []
    return [os.path.join(ssh_dir, n) for n in ("authorized_keys",
                                               "authorized_keys2")]


def verb_remove_ssh_key(user, fingerprint):
    pw = _validated_user(user)
    if not isinstance(fingerprint, str) or not FINGERPRINT_RE.match(fingerprint):
        raise Refusal("The key must be named by its SHA256 fingerprint, as "
                      "ssh-keygen -lf prints it (SHA256: and 43 characters).")
    changed, record = [], []
    for path in _key_files(pw):
        try:
            text, st = _open_text(path)
        except FileNotFoundError:
            continue
        except OSError as e:
            raise Refusal(f"{path} could not be opened without following a "
                          f"link: {e}")
        lines = text.splitlines(keepends=True)
        gone = [ln for ln in lines if _key_fingerprint(ln) == fingerprint]
        if not gone:
            continue
        _rewrite(path, "".join(ln for ln in lines
                                if _key_fingerprint(ln) != fingerprint), st)
        after, _ = _open_text(path)
        if any(_key_fingerprint(ln) == fingerprint for ln in after.splitlines()):
            raise Refusal(f"the key is still in {path} after the rewrite. "
                          f"Treat it as NOT removed.")
        changed.append({"file": path, "lines_removed": len(gone)})
        record.append({"file": path, "lines": gone})
    if not changed:
        return {"user": user, "fingerprint": fingerprint, "removed": False,
                "note": "no authorized_keys line for this account carries "
                        "that key, so nothing was changed"}
    uid = _save_undo("ssh_key", {"user": user, "fingerprint": fingerprint,
                                 "files": record})
    return {"user": user, "fingerprint": fingerprint, "removed": True,
            "files": changed, "verified_by": "read back from each file",
            "undo": f"restore_ssh_key {uid}", "undo_id": uid,
            "note": ("New logins with this key are refused. A session "
                     "already open with it stays open. Only authorized_keys "
                     "and authorized_keys2 were checked; an AuthorizedKeysFile "
                     "set elsewhere in sshd_config was not.")}


def verb_restore_ssh_key(uid):
    rec = _load_undo(uid, "ssh_key")
    pw = _validated_user(rec.get("user", ""))
    allowed = set(_key_files(pw))
    fingerprint = rec.get("fingerprint")
    restored = []
    for item in rec.get("files", []):
        path = item.get("file")
        if path not in allowed:
            raise Refusal(f"the undo record names {path!r}, which is not "
                          f"{pw.pw_name}'s authorized_keys.")
        try:
            text, st = _open_text(path)
        except FileNotFoundError:
            raise Refusal(f"{path} no longer exists, so the key was not put "
                          f"back. The record is kept.")
        if any(_key_fingerprint(ln) == fingerprint for ln in text.splitlines()):
            restored.append({"file": path, "already_there": True})
            continue
        if text and not text.endswith("\n"):
            text += "\n"
        _rewrite(path, text + "".join(ln if ln.endswith("\n") else ln + "\n"
                                      for ln in item.get("lines", [])), st)
        restored.append({"file": path, "already_there": False})
    _spend_undo(uid)
    return {"user": pw.pw_name, "fingerprint": fingerprint,
            "restored": restored}


# CRON

def _cron_path_refusal(path) -> str:
    if not isinstance(path, str) or os.path.normpath(path) != path:
        return "the path must be absolute and written plainly"
    if path in CRON_FILES:
        return ""
    base = os.path.basename(path)
    if os.path.dirname(path) in CRON_DIRS and base and not base.startswith("."):
        return ""
    return (f"it is not a file cron reads jobs from ({', '.join(CRON_FILES)} "
            f"or a file in {', '.join(CRON_DIRS)})")


def _touch_spool(path: str):
    # cron rereads a user's crontab when the spool directory changes.
    if os.path.dirname(path) == USER_SPOOL:
        try:
            os.utime(USER_SPOOL)
        except OSError:
            pass


def verb_disable_cron_line(path, line):
    why = _cron_path_refusal(path)
    if why:
        raise Refusal(f"{path} was not changed: {why}.")
    if not isinstance(line, str) or not line.strip() or "\n" in line \
            or len(line) > 4096:
        raise Refusal("The line must be one non-empty line, exactly as it "
                      "appears in the file.")
    if line.lstrip().startswith("#"):
        raise Refusal("That line is already a comment, so cron does not run it.")
    try:
        text, st = _open_text(path)
    except FileNotFoundError:
        raise Refusal(f"{path} does not exist.")
    except OSError as e:
        raise Refusal(f"{path} could not be opened without following a link: "
                      f"{e}")
    lines = text.splitlines(keepends=True)
    hits = [i for i, ln in enumerate(lines) if ln.rstrip("\r\n") == line]
    if not hits:
        return {"path": path, "disabled": False,
                "note": "the line is not in the file exactly as given, so "
                        "nothing was changed"}
    prefix = f"# disabled by AgentalSec {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}: "
    for i in hits:
        lines[i] = prefix + lines[i]
    _rewrite(path, "".join(lines), st)
    _touch_spool(path)
    after, _ = _open_text(path)
    if any(ln.rstrip("\r\n") == line for ln in after.splitlines()):
        raise Refusal(f"the line is still active in {path} after the rewrite. "
                      f"Treat it as NOT disabled.")
    uid = _save_undo("cron", {"path": path, "line": line, "prefix": prefix})
    return {"path": path, "disabled": True, "lines": len(hits),
            "kept_as": prefix + line,
            "verified_by": "read back from the file",
            "undo": f"restore_cron_line {uid}", "undo_id": uid,
            "note": "The line is kept as a comment. A job already running "
                    "from it is not stopped."}


def verb_restore_cron_line(uid):
    rec = _load_undo(uid, "cron")
    path, line, prefix = rec.get("path"), rec.get("line"), rec.get("prefix")
    why = _cron_path_refusal(path)
    if why or not line or not prefix:
        raise Refusal(f"the undo record is not usable: {why or 'it is incomplete'}.")
    try:
        text, st = _open_text(path)
    except FileNotFoundError:
        raise Refusal(f"{path} no longer exists. The record is kept.")
    lines = text.splitlines(keepends=True)
    hits = [i for i, ln in enumerate(lines)
            if ln.rstrip("\r\n") == prefix + line]
    if not hits:
        return {"path": path, "restored": False,
                "note": "the commented line is no longer in the file, so "
                        "nothing was changed. The record is kept."}
    for i in hits:
        lines[i] = lines[i][len(prefix):]
    _rewrite(path, "".join(lines), st)
    _touch_spool(path)
    _spend_undo(uid)
    return {"path": path, "restored": True, "lines": len(hits)}


HANDLERS = {
    "block_ip": verb_block_ip,
    "unblock_ip": verb_unblock_ip,
    "list_blocks": verb_list_blocks,
    "kill": verb_kill,
    "stop_unit": verb_stop_unit,
    "disable_unit": verb_disable_unit,
    "quarantine": verb_quarantine,
    "restore": verb_restore,
    "list_quarantine": verb_list_quarantine,
    "kill_tree": verb_kill_tree,
    "enable_unit": verb_enable_unit,
    "remove_ssh_key": verb_remove_ssh_key,
    "restore_ssh_key": verb_restore_ssh_key,
    "lock_account": verb_lock_account,
    "unlock_account": verb_unlock_account,
    "remove_group_member": verb_remove_group_member,
    "restore_group_member": verb_restore_group_member,
    "disable_cron_line": verb_disable_cron_line,
    "restore_cron_line": verb_restore_cron_line,
    "restore_blocks": verb_restore_blocks,
}


def handle(verb, args) -> dict:
    """One request, refused or done, always answered and always logged."""
    started = time.time()
    entry = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "verb": verb, "args": args,
             "caller_uid": os.environ.get("PKEXEC_UID"),
             "caller_pid": os.getppid()}
    if verb not in VERBS:
        reply = {"ok": False, "refused": f"No verb named {verb!r}. The table "
                 f"is fixed: {sorted(VERBS)}."}
    elif not isinstance(args, list) or len(args) != len(VERBS[verb]) \
            or not all(isinstance(a, str) for a in args):
        reply = {"ok": False, "refused": f"{verb} takes exactly "
                 f"{len(VERBS[verb])} text argument(s): {VERBS[verb]}."}
    else:
        try:
            reply = {"ok": True, "result": HANDLERS[verb](*args)}
        except Refusal as e:
            reply = {"ok": False, "refused": str(e)}
        except Exception as e:                          # noqa: BLE001
            reply = {"ok": False, "refused": f"{verb} failed: "
                     f"{type(e).__name__}: {e}. Treat it as not done."}
    reply.update({"schema": SCHEMA, "verb": verb,
                  "seconds": round(time.time() - started, 2)})
    entry.update({"ok": reply["ok"], "refused": reply.get("refused"),
                  "result": reply.get("result")})
    problem = log(entry)
    if problem:
        reply["log_problem"] = problem
    return reply


def serve(max_age_hours: float):
    """The session broker. One JSON request per line, one reply per line."""
    deadline = (time.monotonic() + max_age_hours * 3600
                if max_age_hours > 0 else None)
    log({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
         "verb": "session_start", "caller_uid": os.environ.get("PKEXEC_UID"),
         "caller_pid": os.getppid(), "max_age_hours": max_age_hours})
    print(json.dumps({"ready": True, "schema": SCHEMA, "verbs": sorted(VERBS),
                      "max_age_hours": max_age_hours}), flush=True)
    stdin = sys.stdin.buffer
    while True:
        line = stdin.readline(MAX_REQUEST_BYTES + 1)
        if not line:
            break
        if deadline is not None and time.monotonic() > deadline:
            print(json.dumps({"ok": False, "expired": True, "refused":
                              f"This root session reached its "
                              f"{max_age_hours:g} hour cap and closed. The "
                              f"next action asks for the password again. "
                              f"Nothing ran."}), flush=True)
            break
        if len(line) > MAX_REQUEST_BYTES:
            print(json.dumps({"ok": False, "refused": "request too large"}),
                  flush=True)
            break
        try:
            req = json.loads(line)
            reply = handle(req.get("verb"), req.get("args"))
            reply["id"] = req.get("id")
        except (ValueError, AttributeError):
            reply = {"ok": False, "refused": "the request was not a JSON "
                     "object with verb and args"}
        print(json.dumps(reply, default=str), flush=True)
    log({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
         "verb": "session_end", "caller_pid": os.getppid()})


def main(argv):
    args = argv[1:]
    if not args or args[0] in ("-h", "--help"):
        sys.stderr.write("AgentalSec action helper. Verbs:\n"
                         + "".join(f"    {v} {' '.join('<'+a+'>' for a in VERBS[v])}\n"
                                   for v in sorted(VERBS))
                         + "\n    serve [--max-age-hours N]\n")
        return 2
    if args[0] == "--verbs":
        print(json.dumps({"ok": True, "schema": SCHEMA, "verbs": VERBS}))
        return 0
    try:
        preflight()
    except Refusal as e:
        print(json.dumps({"ok": False, "schema": SCHEMA, "refused": str(e)}))
        return 1
    if args[0] == "serve":
        hours = DEFAULT_MAX_AGE_HOURS
        if len(args) == 3 and args[1] == "--max-age-hours":
            try:
                hours = max(0.0, float(args[2]))
            except ValueError:
                pass
        elif len(args) != 1:
            print(json.dumps({"ok": False, "refused": "serve takes only "
                              "--max-age-hours N"}))
            return 1
        serve(hours)
        return 0
    reply = handle(args[0], args[1:])
    print(json.dumps(reply, indent=2, default=str))
    return 0 if reply["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
