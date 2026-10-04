# tools/process_monitor_linux.py
# AgentalSec Linux - process monitoring via psutil.
#
# Checks running processes against suspicious patterns and writes findings
# to the database. Fixes from the PM round (PM-n) are asserted in
# tests/test_process_monitor_linux.py.

import hashlib
import logging
import os
import threading
import time
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not available, process monitoring disabled")

from core import enrichment

# No capability shim here: on Linux it has no implementation, so asking it
# was a silent no-op. Refused fields are reported per field instead (PM-4).

POLL_INTERVAL = 60

# Cache bounds
MAX_SEEN_PROCS = 20000
MAX_HASH_CACHE = 5000

# Defined here; it used to live only in tools/process_monitor.py, so every
# hash raised NameError and came back None (PM-11).
MAX_HASH_BYTES = 256 * 1024 * 1024   # past this the read costs more than the answer

# Whether the sensor ran elevated, recorded once so a row with no exe path
# can say why (PM-3).
ELEVATED = None      # True / False / None = could not tell


def _read_elevated() -> bool | None:
    """
    True if this process can read another account's /proc entries.

    Asked as a FACT rather than a claim: /etc/shadow is mode 640 root:shadow,
    so "can I open it" is exactly the question "am I root". The same test
    core/privilege_linux.is_elevated() makes; kept here as its own small
    function so this module does not import a package for one boolean.
    """
    try:
        return Path("/etc/shadow").exists() and os.access("/etc/shadow", os.R_OK)
    except Exception:                                   # noqa: BLE001
        return None


ELEVATED = _read_elevated()

# Process identity cache: (pid, create_time) -> info
_seen_procs = OrderedDict()

# Hash cache: (path, size, mtime) -> sha256
_hash_cache = OrderedDict()

# PM-13. The window between the two CPU readings, taken ONCE for the whole
# list. See _get_all_processes.
CPU_SAMPLE_INTERVAL = 0.1

# What the last pass got from the read helper (PROC-6), for status reporting.
LAST_HELPER_FILL = {"asked": False, "filled": 0, "reason": None}

# Known offensive tooling (Linux-focused)
SUSPICIOUS_NAMES = {
    "mimikatz", "pwdump", "procdump", "wce",
    "fgdump", "gsecdump", "cachedump",
    "meterpreter", "nc", "ncat", "netcat",
    "psexec", "wmiexec", "smbexec",
    "lazagne", "rubeus", "seatbelt", "sharphound",
    "bloodhound", "certify",
    # Linux-specific
    "linpeas", "linenum", "linux-exploit-suggester",
    "chisel", "chokudai", "ligolo",
    "fping", "masscan", "zmap",
    "john", "hashcat", "hydra", "medusa",
    "sqlmap", "nikto", "nmap",
}

# Patterns are whole tokens or literal substrings that cannot occur in
# ordinary text, resolved by _match_pattern (PM-5). Substring matching
# used to fire on "sync", "launcher" and "grep -i".
LOLBIN_ARG_PATTERNS = {
    "bash": [
        # "own" means bash's own arguments, not the script it was handed: a -i
        # belonging to sed or grep is not evidence about bash.
        {"token": "-i", "where": "own"},
        {"path": "/dev/tcp/"},           # bash's own network redirection
        {"path": "/dev/udp/"},
        {"token": "0<&196-"},
        {"path": "exec 196<"},
        {"token": "curl"},               # a downloader being driven BY bash
        {"token": "wget"},
        {"token": "nc"},
        {"token": "netcat"},
        {"token": "ncat"},
        {"token": "base64 -d"},
        {"token": "openssl enc"},
    ],
    "python": [
        {"token": "-c"},
        {"path": "import base64"}, {"path": "import socket"},
        {"path": "socket.connect"}, {"path": "subprocess.call"},
        {"path": "eval("}, {"path": "exec("},
        {"path": "urllib.request"}, {"path": "http.client"},
        {"path": "pty.spawn"}, {"path": "pexpect"},
    ],
    "python3": [
        {"token": "-c"},
        {"path": "import base64"}, {"path": "import socket"},
        {"path": "socket.connect"}, {"path": "subprocess.call"},
        {"path": "eval("}, {"path": "exec("},
        {"path": "urllib.request"}, {"path": "http.client"},
        {"path": "pty.spawn"}, {"path": "pexpect"},
    ],
    "perl": [
        {"token": "-e"},
        {"path": "Socket"}, {"path": "socket"},
        {"path": "connect"},
        {"path": "open("}, {"path": "PIPE"},
        {"path": "exec("},
    ],
    "curl": [{"path": "-o /tmp/"}, {"path": "-o /var/tmp/"},
             {"path": "| bash"}, {"path": "| sh"}, {"path": "bash <"}],
    "wget": [{"path": "-O /tmp/"}, {"path": "-O /var/tmp/"},
             {"path": "-O - | bash"}, {"path": "-O - | sh"}],
    "ssh": [{"token": "-R"}, {"token": "-D"}, {"token": "-L"},
            {"path": "DynamicForward"}, {"path": "RemoteForward"}],
    "scp": [{"path": "/tmp/"}, {"path": "/var/tmp/"}, {"path": ".cache/"}],
    "rsync": [{"path": "-e ssh"}, {"path": "--rsh=ssh"}],
    "find": [{"token": "-exec"}, {"path": "| bash"}, {"path": "| sh"}],
    "nmap": [{"token": "--script"}, {"token": "-sV"}, {"token": "-sC"},
             {"token": "-O"}, {"token": "-A"}],
}

# Suspicious paths. Entries with * are real globs, tried longest-first so
# the label names the folder the file is actually in (PM-8).
SUSPICIOUS_PATHS = [
    "/home/*/Downloads/", "/home/*/downloads/",
    "/home/*/.cache/", "/root/.cache/",
    "/var/tmp/", "/tmp/", "/dev/shm/",
    "/opt/.",  # Hidden dirs in /opt
]

# Trusted paths for the suspicious-path check. /usr/local/bin is left out
# on purpose. The masquerade check asks the package manager instead (PM-1).
WHITELISTED_PATHS = [
    "/bin/", "/usr/bin/",
    "/sbin/", "/usr/sbin/",
    "/snap/", "/flatpak/",
]

# Where a system binary may run from; used only by the masquerade fast path.
SYSTEM_BINARY_ROOTS = [
    "/bin/", "/usr/bin/", "/usr/sbin/", "/sbin/",
    "/usr/lib/", "/usr/libexec/", "/usr/lib/systemd/",
    "/lib/", "/lib64/", "/usr/lib64/",
    "/snap/", "/flatpak/",
]

# Trusted system binaries
WHITELISTED_NAMES = {
    "init", "systemd", "systemd-journald", "systemd-logind",
    "sshd", "cron", "crond", "anacron",
    "rsyslogd", "syslog-ng",
    "dbus-daemon", "avahi-daemon", "networkmanager",
    "dockerd", "containerd", "kubelet",
    "nginx", "apache2", "httpd",
    "mysql", "mysqld", "postgres", "postgresql",
    "mongod", "redis-server",
    "python3", "python2", "perl", "ruby",
    "bash", "sh", "zsh", "fish",
    "sudo", "su",
}


def _hash_file(filepath: str) -> str | None:
    """
    Compute SHA-256 hash of a file.

    Returns None if file cannot be read or is too large.
    """
    try:
        path = Path(filepath)
        if not path.exists() or not path.is_file():
            return None

        file_size = path.stat().st_size
        if file_size > MAX_HASH_BYTES:
            return None

        # Check cache
        mtime = path.stat().st_mtime
        cache_key = (filepath, file_size, mtime)
        if cache_key in _hash_cache:
            return _hash_cache[cache_key]

        # Compute hash
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)

        file_hash = sha256.hexdigest()

        # Cache result
        _hash_cache[cache_key] = file_hash
        if len(_hash_cache) > MAX_HASH_CACHE:
            _hash_cache.popitem(last=False)

        return file_hash
    except (PermissionError, OSError, Exception) as e:
        logger.debug(f"Cannot hash {filepath}: {e}")
        return None


def _is_suspicious_path(filepath: str) -> tuple[bool, str | None]:
    """
    Check if a file path is suspicious.

    Returns (is_suspicious, reason)

    PM-8: the glob entries are expanded against the real path with fnmatch, and
    the list is ordered longest-first so the label names the folder the file is
    ACTUALLY in. Both halves were broken: four patterns could never match, and
    a /var/tmp hit was reported as /tmp/.
    """
    if not filepath:
        return False, None

    filepath_lower = filepath.lower()

    # Check trusted paths first
    for trusted in WHITELISTED_PATHS:
        if filepath_lower.startswith(trusted.lower()):
            return False, None

    # Check suspicious paths. Longest-first, and globs are REAL globs.
    for suspicious in sorted(SUSPICIOUS_PATHS, key=len, reverse=True):
        pattern = suspicious.lower()
        if "*" in pattern or "?" in pattern or "[" in pattern:
            # Directory globs are matched against every parent of the path.
            if _glob_hits(pattern, filepath_lower):
                return True, f"Running from suspicious location: {suspicious}"
        elif pattern in filepath_lower:
            return True, f"Running from suspicious location: {suspicious}"

    return False, None


def _glob_hits(pattern: str, path_lower: str) -> bool:
    """
    True if a globbed directory pattern names a directory this file sits in.

    A pattern ending in "/" is a DIRECTORY pattern and is matched against every
    parent of the path, not the path itself: "/home/*/Downloads/" must hit
    "/home/ada/Downloads/payload.sh" and must not hit
    "/home/ada/Downloads-archive/x". fnmatch on the whole path cannot express
    that boundary, so this walks the parents instead — and the boundary is the
    whole reason the old substring version fired wrongly in the other
    direction.
    """
    import fnmatch

    if not pattern.endswith("/"):
        return fnmatch.fnmatch(path_lower, pattern + "*") \
            or fnmatch.fnmatch(path_lower, pattern)

    # Every ancestor directory of the path, as a directory string.
    parts = [p for p in path_lower.split("/") if p]
    for i in range(len(parts)):
        ancestor = "/" + "/".join(parts[:i + 1]) + "/"
        if fnmatch.fnmatch(ancestor, pattern):
            return True
    return False


def _package_owns(path: str) -> str | None:
    """
    The package a file belongs to, or None.

    The same batched dpkg basis the Processes page uses (tools/process_monitor.
    _package_owner_map), asked here with a single path. Returns None whenever
    dpkg cannot place the file — no package, no dpkg, no answer — and None
    means UNKNOWN, never "suspicious".
    """
    if not path:
        return None
    try:
        from tools import process_monitor as reg
        owners = reg._package_owner_map([path])
    except Exception as e:                              # noqa: BLE001
        logger.debug(f"package ownership could not be asked for {path}: {e}")
        return None
    return owners.get(os.path.realpath(path)) or owners.get(path)


def _masquerade_verdict(proc_name: str, filepath: str,
                        sig: dict | None = None) -> tuple[bool, str | None]:
    """
    PM-1: does a system-named process run the system's copy of the file?

    1. digest matches the package  -> not a masquerade
    2. digest does not match       -> a real masquerade, wherever it sits
    3. nothing to compare          -> fall back to "is it under a system root"

    `sig` is the signature record monitor_once already batched for this path;
    leave it None to have it asked here.
    """
    if not proc_name or not filepath:
        return False, None

    name_lower = proc_name.lower()

    # Check the file's basename as well as the process name, which the process
    # can choose (PM-2).
    names = {name_lower, os.path.basename(filepath).lower()}
    if not (names & WHITELISTED_NAMES):
        return False, None

    # 1. Is this the file the package shipped? Then it is not masquerading.
    if sig is None:
        try:
            from tools import process_monitor as reg
            sig = reg.signatures_for([filepath]).get(filepath, {})
        except Exception as e:                          # noqa: BLE001
            logger.debug(f"the package basis could not be asked about "
                         f"{filepath}: {e}")
            sig = {}
    status = ((sig or {}).get("status") or "unknown").lower()
    if status == "valid":
        return False, None
    if status == "hashmismatch":
        return True, (f"System binary '{proc_name}' running from {filepath}, "
                      f"and that file is NOT what its package shipped: its "
                      f"digest does not match the {sig.get('package')} "
                      f"package's own record")

    # 2. No positive answer. Fall back to the roots question, which is all the
    # old check ever had.
    probe = filepath.lower()
    for root in SYSTEM_BINARY_ROOTS:
        if probe.startswith(root):
            return False, None

    return True, f"System binary '{proc_name}' running from untrusted path: {filepath}"


def _masquerade_paths(processes: list[dict]) -> list[str]:
    """
    The paths the masquerade question actually applies to, once for the pass.

    Only a process wearing a SYSTEM NAME can be masquerading, so only those
    paths are worth a package-manager lookup — a few dozen on a desktop, not
    the whole table. Batched through signatures_for this is one dpkg call for
    all of them (2.0 s measured on the page for 257 paths, warm-cached after).
    """
    out = []
    for row in processes:
        exe = row.get("exe")
        if not exe:
            continue
        names = {(row.get("name") or "").lower(),
                 os.path.basename(exe).lower()}
        if names & WHITELISTED_NAMES:
            out.append(exe)
    return out


def _check_masquerading(proc_name: str, filepath: str) -> tuple[bool, str | None]:
    """Backwards-compatible name for the masquerade check. See _masquerade_verdict."""
    return _masquerade_verdict(proc_name, filepath)


def _match_pattern(pattern: dict, tokens: list[str], cmdline_lower: str,
                   own_tokens: list[str] | None = None) -> bool:
    """
    PM-5: one matcher for both pattern spellings.

    A "token" pattern is a WHOLE ARGUMENT. Two spellings are honoured, and both
    came from measured false negatives rather than guessing:

        "-sV"       the token itself, or as the head of a clustered flag
                    ("-sV" inside "-sVn") — nmap's real spellings
        "-o /tmp/"  a token plus its argument, which is how curl and wget are
                    actually INVOKED. The old table had "-o /tmp/" as a
                    substring and it is a two-token shape; splitting on spaces
                    would have lost the one pattern that describes a download
                    to a staging directory.

    A "path" pattern is a literal substring, and is only allowed where it cannot
    occur in ordinary English ("/dev/tcp/", "import socket").

    {"where": "own"} narrows a token to the SHELL'S OWN ARGUMENTS (see
    _own_tokens): `bash -i` is an interactive shell, while a `-i` handed to sed
    inside the script is sed's flag. Without this the fix would have traded one
    false positive for another.
    """
    if "token" in pattern:
        want = pattern["token"].lower()
        haystack = own_tokens if pattern.get("where") == "own" else tokens
        haystack = haystack or []
        for i, tok in enumerate(haystack):
            if tok == want:
                return True
            if want.startswith("-") and len(want) > 1 and tok.startswith(want):
                # "-sV" matching "-sVn": a clustered short flag whose cluster
                # BEGINS with the pattern. "-c" still does not match "-exec",
                # which is the whole point of the boundary.
                return True
            if i + 1 < len(haystack) and f"{tok} {haystack[i + 1]}" == want:
                return True
        return False
    if "path" in pattern:
        return pattern["path"].lower() in cmdline_lower
    # A bare string: treated as a literal, because the table above is
    # explicit and a bare entry was a mistake waiting to be loud about it.
    raise ValueError(f"pattern {pattern!r} is neither a token nor a path")


def _own_tokens(tokens: list[str]) -> list[str]:
    """
    The flags of the shell invocation itself, up to the script it was handed.

    `bash -i >& /dev/tcp/1.2.3.4/4444 0>&1` -> ["-i"]  (an interactive shell)
    `bash -c 'sed -i s/a/b/ f'`             -> ["-c"]  (sed's -i, not bash's)

    Splitting the line on spaces cannot tell those apart; stopping at the first
    non-flag token can, and that boundary is the whole difference between the
    real signal and the false positive that fired 37 times in the live store.
    """
    out = []
    for tok in tokens[1:]:
        if not tok.startswith("-"):
            break
        out.append(tok)
    return out


def _check_lolbin(proc_name: str, cmdline: str) -> tuple[bool, str | None]:
    """
    Check for living-off-the-land binary abuse.

    Returns (is_suspicious, reason)

    PM-5/PM-9: matches on ARGUMENT BOUNDARIES, and reports the ARGUMENT that
    matched rather than the pattern that happened to be first in the list. The
    old version returned "Suspicious bash usage: -i" for every bash process
    whose command line contained the letter sequence "-i" anywhere, which is
    why all 37 live LNX-1103 rows read the same uninformative sentence and 29
    of them were this app's own launcher.
    """
    if not proc_name or not cmdline:
        return False, None

    name_lower = proc_name.lower()
    cmdline_lower = cmdline.lower()
    tokens = cmdline_lower.split()
    own_tokens = _own_tokens(tokens)

    for binary, patterns in LOLBIN_ARG_PATTERNS.items():
        # Match binary name (with wildcard support)
        if binary.endswith("*"):
            if not name_lower.startswith(binary[:-1]):
                continue
        else:
            if name_lower != binary:
                continue

        for pattern in patterns:
            if _match_pattern(pattern, tokens, cmdline_lower, own_tokens):
                shown = pattern.get("token") or pattern.get("path")
                return True, f"Suspicious {proc_name} usage: {shown}"

    return False, None


def _read_proc_status(pid: int) -> dict:
    """
    PM-3/PM-4. /proc/<pid>/status, which is readable UNELEVATED and which
    nothing in this tree had ever read.

    Three fields a process cannot hide, and each one is a fact rather than an
    opinion:

        CapEff      the capability set the process is actually holding. A
                    process running with CAP_SYS_ADMIN that has no business
                    doing so is a real finding; a blank here is a refusal, not
                    a zero.
        Seccomp     whether the process has a seccomp filter installed.
        NoNewPrivs  whether it can gain privileges through setuid binaries.

    Also reports the two facts that make a row readable rather than mysterious:
    the process's own cgroup line (PM-10's unit attribution) and whether
    /proc/<pid>/exe says "(deleted)" — the mark of a binary that was removed
    while still running, which is a real implant signal and which psutil STRIPS.

    Returns {} when the file cannot be read, and {} means UNKNOWN.
    """
    out = {}
    try:
        with open(f"/proc/{int(pid)}/status", "r") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    out["cap_eff"] = line.split(":", 1)[1].strip()
                elif line.startswith("Seccomp:"):
                    out["seccomp"] = int(line.split(":", 1)[1].strip() or 0)
                elif line.startswith("NoNewPrivs:"):
                    out["no_new_privs"] = int(line.split(":", 1)[1].strip() or 0)
    except (OSError, ValueError) as e:
        logger.debug(f"/proc/{pid}/status could not be read: {e}")
        return {}
    return out


def _proc_exe_path(pid: int) -> tuple[str | None, str | None]:
    """
    PM-2. The path of the file a PID is ACTUALLY running, and whether the
    kernel says it has been deleted underneath it.

    Returns (path_or_None, note_or_None).

    THIS IS THE FIELD THE NAME CHECKS WANT. A process can call
    prctl(PR_SET_NAME) and choose its comm, and psutil's name() extends a
    15-character comm out of the process's OWN argv[0], so `_analyze_process`
    was matching a list of offensive-tool names against a value the flagged
    process itself had chosen. Measured before the fix: a 23-character
    offensive-tool binary running from /tmp walked through untouched when its
    argv[0] lied.

    /proc/<pid>/exe is the kernel's own answer and is not process-settable. It
    is refused for another account's process (PermissionError), and that
    refusal is reported as a refusal rather than as "no file".
    """
    try:
        raw = os.readlink(f"/proc/{int(pid)}/exe")
    except PermissionError:
        return None, ("this account was REFUSED /proc/<pid>/exe "
                      "(PermissionError): the process belongs to another "
                      "account and only its owner or root may read it")
    except FileNotFoundError:
        return None, "the process exited while it was being read"
    except OSError as e:                                # noqa: BLE001
        return None, f"/proc/<pid>/exe could not be read ({type(e).__name__})"

    deleted = raw.endswith(" (deleted)")
    if deleted:
        raw = raw[:-len(" (deleted)")]
    return raw, ("the kernel marks this executable as DELETED: the file was "
                 "removed while the process kept running" if deleted else None)


def _read_cgroup_unit(pid: int) -> str | None:
    """
    The systemd unit a process belongs to, from /proc/<pid>/cgroup (PM-10).
    """
    try:
        with open(f"/proc/{int(pid)}/cgroup", "r") as fh:
            for line in fh:
                parts = line.rstrip("\n").split(":", 2)
                if len(parts) != 3:
                    continue
                path = parts[2]
                if not path or path == "/":
                    continue
                leaf = path.rstrip("/").rsplit("/", 1)[-1]
                if leaf.endswith((".service", ".scope", ".slice")):
                    return leaf
    except (OSError, ValueError) as e:
        logger.debug(f"/proc/{pid}/cgroup could not be read: {e}")
    return None


def _read_one_field(proc, label, fn, default=None) -> tuple:
    """
    One /proc read in its own try, returning (value, reason_or_None) so a
    refused field never costs the rest of the row (PM-4).
    """
    try:
        return fn(), None
    except psutil.NoSuchProcess:
        return default, "the process exited while it was being read"
    except psutil.ZombieProcess:
        return default, "the process is a zombie: its parent has not reaped it"
    except psutil.AccessDenied as e:
        return default, (f"this account was REFUSED {label} "
                         f"({type(e).__name__}): {e}")
    except Exception as e:                              # noqa: BLE001
        return default, f"{label} could not be read ({type(e).__name__}: {e})"


def _get_process_info(proc: psutil.Process) -> dict | None:
    """
    One process's row. Each field is read in its own try and refusals travel
    with the row (PM-4). Returns None only when not even the name is readable.
    """
    pid = getattr(proc, "pid", None)
    if pid is None:
        return None

    name, _name_gap = _read_one_field(proc, "name", proc.name)
    if name is None:
        # No name, nothing to report.
        logger.debug(f"Cannot read the name of process {pid}, skipping it")
        return None

    # The file, read from /proc; psutil strips "(deleted)" (PM-2).
    exe, exe_note = _proc_exe_path(pid)
    if exe is None:
        # psutil can still answer for our own processes.
        exe, err = _read_one_field(proc, "exe", proc.exe)
        if err and exe_note is None:
            exe_note = err

    cmdline_list, cmdline_note = _read_one_field(proc, "cmdline", proc.cmdline)
    cmdline = " ".join(cmdline_list) if cmdline_list else None

    username, username_note = _read_one_field(proc, "username", proc.username)
    create_time, create_time_note = _read_one_field(
        proc, "create_time", proc.create_time)
    mem_info, mem_note = _read_one_field(proc, "memory_info", proc.memory_info)

    rss = getattr(mem_info, "rss", None)
    vms = getattr(mem_info, "vms", None)

    # PM-1/PM-2. WHAT IS ACTUALLY RUNNING, in the kernel's own words.
    status = _read_proc_status(pid)

    row = {
        "pid": pid,
        "name": name,
        "cmdline": cmdline,
        "exe": exe,
        "username": username,
        "create_time": (datetime.fromtimestamp(create_time, tz=timezone.utc)
                        .isoformat() if create_time else None),
        "create_time_ts": create_time,
        "memory_rss": rss,
        "memory_vms": vms,
        # Filled in once by the caller for the whole list (PM-12).
        "cpu_percent": None,
        # Refusals travel with the row (PM-3).
        "unreadable": {},
    }
    for label, gap in (("exe", exe_note), ("cmdline", cmdline_note),
                       ("username", username_note),
                       ("create_time", create_time_note),
                       ("memory_info", mem_note)):
        if gap:
            row["unreadable"][label] = gap

    # The facts a process cannot hide, read straight from /proc (PM-3).
    row.update({k: v for k, v in status.items()})
    row["unit"] = _read_cgroup_unit(pid)

    return row


def _own_start_ticks(pid: int):
    """Field 22 of /proc/<pid>/stat, readable for every process unelevated."""
    try:
        with open(f"/proc/{int(pid)}/stat", "r") as fh:
            rest = fh.read().rsplit(")", 1)[-1].split()
        return int(rest[19])
    except (OSError, IndexError, ValueError):
        return None


def _fill_exe_from_helper(rows: list[dict]) -> dict:
    """
    PROC-6. Rows whose exe this account was refused get it from the read
    helper's proc_exe verb: one call per pass, and only when a row needs it.
    A path is taken only when pid AND start time match, so a reused pid never
    inherits another process's file. Returns a small report for the pass.
    """
    report = {"asked": False, "filled": 0, "reason": None}
    missing = [r for r in rows if not r.get("exe")
               and (r.get("unreadable") or {}).get("exe")]
    if not missing or ELEVATED:
        return report
    try:
        from tools import local_integrity as li
        status = li.helper_status()
    except Exception as e:                              # noqa: BLE001
        report["reason"] = f"the helper could not be asked: {e}"
        return report
    if not status.get("available"):
        report["reason"] = status.get("reason")
        return report
    if "proc_exe" not in (status.get("verbs") or []):
        report["reason"] = ("the installed helper predates proc_exe; rerun "
                            "scripts/install_read_helper.sh --apply")
        return report

    report["asked"] = True
    res = li.helper_call("proc_exe", timeout=30)
    if not res.get("ok"):
        report["reason"] = res.get("reason")
        return report
    table = (res.get("data") or {}).get("processes") or {}
    for row in missing:
        got = table.get(str(row["pid"])) or {}
        exe = got.get("exe")
        if not exe or got.get("start_ticks") is None:
            continue
        if got["start_ticks"] != _own_start_ticks(row["pid"]):
            continue
        row["exe"] = exe
        row["exe_via"] = "read_helper"
        row["unreadable"].pop("exe", None)
        report["filled"] += 1
    return report


def _get_all_processes(collect_extras: bool = False) -> list[dict]:
    """
    Every process's row, with one CPU sampling interval for the whole pass
    rather than one per process (PM-13).
    """
    processes = []

    if not PSUTIL_AVAILABLE:
        return processes

    if collect_extras:
        logger.debug("collect_extras is accepted and unused: nothing reads cwd "
                     "or open_files (PM-4 measured both at 0 consumers).")

    # FIRST CPU READING for every process, before any of the slow reads.
    primed = []
    try:
        for proc in psutil.process_iter(['pid']):
            try:
                proc.cpu_percent(interval=None)     # non-blocking: arms it
                primed.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:                              # noqa: BLE001
        logger.error(f"Failed to enumerate processes: {e}")
        return processes

    # Every other field, with ONE wait in the middle instead of one per process.
    started = time.time()
    rows = []
    for proc in primed:
        row = _get_process_info(proc)
        if row:
            rows.append((proc, row))

    global LAST_HELPER_FILL
    LAST_HELPER_FILL = _fill_exe_from_helper([row for _, row in rows])

    gap = CPU_SAMPLE_INTERVAL - (time.time() - started)
    if gap > 0:
        time.sleep(gap)                                 # the single sleep

    # Second CPU reading, paired with its own process.
    out = []
    for proc, row in rows:
        try:
            row["cpu_percent"] = proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):  # noqa: BLE001
            row["cpu_percent"] = None
        out.append(row)

    processes.extend(out)
    return processes


def _true_name(proc_data: dict) -> str:
    """
    The name the name checks match: the running file's basename first, then
    the process's own name, which the process can set (PM-2).
    """
    exe = proc_data.get("exe")
    if exe:
        base = os.path.basename(exe.rstrip("/"))
        if base:
            return base
    return proc_data.get("name") or ""


def _analyze_process(proc_data: dict, sigmap: dict | None = None) -> list[dict]:
    """
    Analyze a process for suspicious characteristics.

    `sigmap` is the pass's batched signature answers, keyed by path. See
    _masquerade_verdict for why the batch exists.

    Returns list of findings.
    """
    findings = []
    name = proc_data["name"]
    exe = proc_data["exe"]
    cmdline = proc_data["cmdline"]
    pid = proc_data["pid"]

    # PM-2: what the rules match. See _true_name.
    match_name = _true_name(proc_data)

    # Keyed on the process instance, not just the pid, so a reused pid is
    # analyzed again (PM-12).
    proc_key = (pid, proc_data.get("create_time_ts"))
    if proc_key in _seen_procs:
        return []  # Already analyzed this process instance

    # Add to seen cache
    _seen_procs[proc_key] = proc_data
    if len(_seen_procs) > MAX_SEEN_PROCS:
        _seen_procs.popitem(last=False)

    # Check 1: suspicious name, matched on the executable's name; the finding
    # carries the path, arguments and package ownership (PM-2, PM-6).
    match_lower = match_name.lower()
    for suspicious in SUSPICIOUS_NAMES:
        if match_lower == suspicious:
            pkg = _package_owns(exe) if exe else None
            where = (f"the file is {exe}" if exe else
                     "the executable path could not be read")
            if pkg:
                provenance = (f"that file belongs to the INSTALLED {pkg} "
                              f"package, which is ordinary software somebody "
                              f"installed on this machine, not evidence of "
                              f"anything on its own")
            else:
                provenance = ("no installed package owns that file, which is "
                              "the fact worth acting on: an offensive tool "
                              "outside the package manager is not part of "
                              "this machine's software")
            findings.append({
                "type": "suspicious_process_name",
                "pid": pid,
                "name": name,
                "exe": exe,
                "cmdline": cmdline,
                "package": pkg,
                "severity": "medium",
                "description": (f"Known offensive tooling: {suspicious}. It is "
                                f"running as {match_name}, {where}; "
                                f"{provenance}"),
            })
            break

    # Check 2: Suspicious path
    is_suspicious, reason = _is_suspicious_path(exe)
    if is_suspicious:
        findings.append({
            "type": "suspicious_process_location",
            "pid": pid,
            "name": name,
            "exe": exe,
            "severity": "low",
            "description": reason,
        })

    # Check 3: Masquerading (PM-1: asks the package basis, see the function)
    is_masq, reason = _masquerade_verdict(
        match_name, exe, (sigmap or {}).get(exe) if sigmap else None)
    if is_masq:
        findings.append({
            "type": "masquerading_system_binary",
            "pid": pid,
            "name": name,
            "exe": exe,
            "severity": "high",
            "description": reason,
        })

    # Check 4: LOLBIN abuse (PM-5: whole tokens)
    is_lolbin, reason = _check_lolbin(match_name, cmdline)
    if is_lolbin:
        findings.append({
            "type": "lolbin_abuse",
            "pid": pid,
            "name": name,
            "exe": exe,
            "cmdline": cmdline,
            "severity": "medium",
            "description": reason,
        })

    # Check 5: hash and queue for enrichment, behind ENABLE_PROCESS_HASHES.
    if exe and ENABLE_PROCESS_HASHES and findings:
        try:
            file_hash = _hash_file(exe)
            if file_hash:
                enrichment.enqueue(file_hash, kind="hash",
                                   requested_by="process_monitor_linux",
                                   reason=(f"{findings[0]['type']} on "
                                           f"{match_name} (pid {pid})"))
        except Exception as e:                          # noqa: BLE001
            logger.debug(f"could not queue a hash for {exe}: {e}")

    return findings


# Hash a flagged binary and queue the digest for enrichment (PM-11).
ENABLE_PROCESS_HASHES = True


def monitor_once() -> dict:
    """
    Run process monitoring once. process_count is the rows this sensor could
    build, not the number of processes on the machine (PM-12).
    """
    if not PSUTIL_AVAILABLE:
        return {"error": "psutil not available", "searched": False}

    start_time = time.time()
    processes = _get_all_processes()
    all_findings = []

    # One package-manager call for the whole pass (PM-1).
    sigmap = {}
    try:
        from tools import process_monitor as reg
        paths = _masquerade_paths(processes)
        if paths:
            sigmap = reg.signatures_for(paths)
    except Exception as e:                              # noqa: BLE001
        logger.debug(f"the package basis could not be batched this pass: {e}")

    for proc_data in processes:
        findings = _analyze_process(proc_data, sigmap)
        all_findings.extend(findings)

    # Summarize
    users = defaultdict(int)
    names = defaultdict(int)

    for proc in processes:
        users[proc["username"] or "unreadable"] += 1
        names[proc["name"]] += 1

    elapsed = time.time() - start_time

    # Refusals counted by field (PM-3).
    unreadable = defaultdict(int)
    for proc in processes:
        for field in (proc.get("unreadable") or {}):
            unreadable[field] += 1

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "process_count": len(processes),
        "process_count_means": (
            "the processes this sensor could build a row for. It is NOT the "
            "number of processes on the machine; get_status() reports that."),
        "users": dict(users),
        "top_processes": dict(sorted(names.items(), key=lambda x: -x[1])[:20]),
        "findings": all_findings,
        "finding_count": len(all_findings),
        "elapsed_seconds": elapsed,
        # The rights this pass ran with (PM-3).
        "elevated": ELEVATED,
        "unreadable_by_field": dict(unreadable),
        # PROC-6: exe paths recovered through the read helper this pass.
        "exe_from_helper": dict(LAST_HELPER_FILL),
        "searched": True,
    }

    if all_findings:
        logger.info(f"Process monitor: {len(processes)} processes, {len(all_findings)} findings")

    return result


def start_monitoring(interval: int = None):
    """
    Standalone monitoring loop. The adapter is the real caller and writer;
    this loop only reports what it saw (PM-11).
    """
    if not PSUTIL_AVAILABLE:
        logger.warning("Cannot start monitoring: psutil not available")
        return False

    if interval is None:
        interval = POLL_INTERVAL

    def monitor_thread():
        logger.info(f"Process monitor started (interval={interval}s)")
        while True:
            try:
                out = monitor_once()
                # The adapter writes findings; this loop only reports.
                if out.get("finding_count"):
                    logger.info(
                        "Process monitor: %d finding(s) this pass, not written "
                        "by this loop, the adapter writes findings.",
                        out["finding_count"])
            except Exception as e:                      # noqa: BLE001
                logger.error(f"Process monitoring error: {e}")

            time.sleep(interval)

    thread = threading.Thread(target=monitor_thread, daemon=True)
    thread.start()
    return True


def get_process_details(pid: int) -> dict | None:
    """
    Get detailed information about a specific process.

    PM-11: kept, and given back its missing half. It read _get_process_info
    with a psutil.Process in hand, which is the OLD signature; it now goes
    through the same per-field reader everything else uses, so a refused exe
    no longer costs the caller the command line.
    """
    if not PSUTIL_AVAILABLE:
        return None

    try:
        proc = psutil.Process(pid)
        return _get_process_info(proc)
    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:  # noqa: BLE001
        logger.debug(f"Cannot get process {pid}: {e}")
        return None


def kill_process(pid: int, signal: int = None) -> dict:
    """
    Terminate a process.

    PM-11, 2026-09-23. THIS IS NOT A KILL PATH AND MUST NEVER BECOME ONE.
    Measured: it had no caller anywhere in the tree, which is the only reason
    it was not a hole rather than a defect — it is a bare send_signal with no
    name pin and no unit check, the exact shape of the duplicate
    remediation_linux.kill_process the FOUND-CLEAN list already records.

    It is kept, and it now REFUSES by default, because the honest thing to do
    with a second kill path nobody uses is to make sure nobody can quietly
    start using it. The app's kill goes through adapters.LinuxRemediation,
    which pins the name, checks the unit, and writes a finding.
    """
    # A single module-level flag so a test or a script can reach it, and a
    # refusal that names the right tool rather than a traceback.
    if not ALLOW_LEGACY_KILL:
        return {
            "success": False,
            "refused": True,
            "error": (
                "this function is a bare SIGTERM with no name pin and no unit "
                "check, and it is NOT this application's kill path. The kill "
                "goes through adapters.LinuxRemediation.kill_process, which "
                "verifies the pid is still the process the card named, checks "
                "whether the process is supervised, and records what it did. "
                "If you are reading this from a caller, use that."
            ),
        }

    if not PSUTIL_AVAILABLE:
        return {"success": False, "error": "psutil not available"}

    try:
        proc = psutil.Process(pid)

        # Check if we can signal this process
        try:
            proc.send_signal(0)  # Test signal
        except psutil.AccessDenied:
            return {"success": False, "error": "Access denied"}

        # Send signal (default: SIGTERM)
        if signal is None:
            signal = 15  # SIGTERM

        proc.send_signal(signal)

        # Wait for termination
        try:
            proc.wait(timeout=10)
            return {"success": True, "pid": pid, "signal": signal}
        except psutil.TimeoutExpired:
            # Force kill
            proc.kill()
            proc.wait(timeout=5)
            return {"success": True, "pid": pid, "signal": 9, "forced": True}

    except psutil.NoSuchProcess:
        return {"success": False, "error": "Process no longer exists"}
    except Exception as e:                              # noqa: BLE001
        return {"success": False, "error": str(e)}


# PM-11. False by default: see kill_process's docstring.
ALLOW_LEGACY_KILL = False


def get_status() -> dict:
    """
    Get current process monitor status.

    PM-12. THIS IS THE OTHER COUNT, and it now says so. It walks EVERY process
    on the machine (224 live) while monitor_once() returns the ones it could
    build a row for (81 live before the PM-4 fix). Both are correct answers to
    different questions; the defect was that nothing said which was which.

    PM-3: it also reports the privilege level and the fields that were refused,
    so a reader can tell an unelevated load from an elevated one.
    """
    if not PSUTIL_AVAILABLE:
        return {"available": False, "reason": "psutil not installed"}

    # Count processes by user
    users = defaultdict(int)
    try:
        for proc in psutil.process_iter(['username']):
            try:
                users[proc.username()] += 1
            except (psutil.AccessDenied, Exception):    # noqa: BLE001
                users["unknown"] += 1
    except Exception:                                   # noqa: BLE001
        pass

    return {
        "available": True,
        "process_count": sum(users.values()),
        "process_count_means": (
            "EVERY process on the machine, readable or not. This is not the "
            "count monitor_once() reports: that one is the processes whose "
            "fields could actually be read."),
        "user_counts": dict(users),
        "elevated": ELEVATED,
        "cache_size": len(_seen_procs),
    }
