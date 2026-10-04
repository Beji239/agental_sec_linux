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
#
# The guards are here and not only in the app, because anything running as
# the operator's account can start this helper too. The password prompt is
# what stops that; these refusals are what stand behind it.
#
# Output is JSON with an "ok" key. Every call, refusals included, is appended
# to a root-owned log.

import fnmatch
import hashlib
import ipaddress
import json
import os
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
}

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
                "persists": "until reboot"}
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
            "persists": "until reboot"}


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
    return {"unblocked": str(ip), "was_blocked": True,
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


def verb_kill(pid_text, comm_expected, ticks_text):
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
        return {"pid": pid, "gone": True, "note": "the process had already "
                "exited, so nothing was signalled"}
    comm, flags, start = fields
    if start != ticks or comm != comm_expected:
        raise Refusal(
            f"pid {pid} is now {comm!r} started at tick {start}, and the "
            f"approval named {comm_expected!r} at tick {ticks}. The pid was "
            f"reused or the wrong process was named. Nothing was signalled.")
    if flags & PF_KTHREAD:
        raise Refusal(f"pid {pid} ({comm}) is a kernel thread.")
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = ""
    exe_base = os.path.basename(exe.split(" (deleted)")[0]).lower()
    for label, value in (("comm", comm.lower()), ("exe", exe_base)):
        if value in CRITICAL_PROCESSES:
            raise Refusal(
                f"pid {pid} is {value} (from its {label}), which this helper "
                f"never signals: it would take the desktop, the logs, the "
                f"network or a security control with it. If it is a service, "
                f"stop_unit is the door.")
    args = [exe] + _cmdline(pid)
    if any(a.startswith(p) for a in args for p in AGENTALSEC_PATHS):
        raise Refusal(f"pid {pid} is part of AgentalSec ({exe or comm}). "
                      f"This helper does not end its own camera or sensors.")

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
