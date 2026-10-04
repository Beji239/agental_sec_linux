# tools/autorun_monitor.py
# AgentalSec Linux - Monitor system autoruns: systemd, cron, init scripts
#
# Watches for persistence mechanisms on Linux:
# - systemd service units (system and user)
# - cron jobs (system and user)
# - init.d scripts
# - shell startup files (.bashrc, .profile, etc.)
#
# Read-only. Does not modify any files.
#
# WHAT THIS MODULE IS FOR, AND WHAT IT DELIBERATELY IS NOT
#
# It is an INVENTORY, and the twin's own header says it best: persistence
# entries on a machine are stable for months, which makes them ideal baseline
# material, and "the interesting signal is not 'this entry looks bad', it is
# 'this entry was not here last session'". A hardcoded list of suspicious names
# is defeated by a rename and is wrong on somebody else's machine.
#
# This module was ported without that half. It has a pattern list, and the
# pattern list was doing the judging -- badly. See AR-1 in bugfinder.md:
# measured on this host, 151 of 151 systemd findings were false, and 150 of
# them matched the two-letter pattern "nc" inside ordinary words
# (DefaultDependencies=no, Description=Run anacron jobs, synchronized,
# ConditionCapability=CAP_SYS_ADMIN). That is the SNF-1 and PM-1 shape for the
# third time in this tree: a detector that fires on everything is a detector
# nobody can use, and it teaches its reader to skim the one page that exists to
# say something is wrong.
#
# SO THE PATTERN LIST IS NOW A NARROW, HONEST THING:
#
#   * it is matched TOKEN-WISE, not as a substring, so "nc" means the command
#     `nc` and not the middle of "anacron";
#   * a unit is judged on its EXECUTIVE lines (ExecStart and friends), because
#     `Description=Run anacron jobs` and `DefaultDependencies=no` are not
#     things that run;
#   * a shell startup file is judged line by line, where a `# comment` is
#     reported as a comment and weighted lower than live code;
#   * every finding carries the line that matched it, so a reader can check the
#     claim instead of trusting the word "suspicious".
#
# AND WHAT IT DOES NOT DO, said plainly rather than left to be discovered:
# this module does not persist a baseline and it does not write findings into
# the evidence store. Both are recorded as OPEN in bugfinder.md with their
# measurements and a design, because the first one starts writing rows into the
# owner's store and that is the owner's call rather than a port's.

import hashlib
import json
import logging
import os
import pwd
import re
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

from core import memory_engine as me

# Standard locations for autoruns on Linux
AUTORUN_PATHS = {
    "systemd_system": [
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    ],
    "systemd_user": [
        "~/.config/systemd/user",
        "/etc/systemd/user",
    ],
    "cron_system": [
        "/etc/crontab",
        "/etc/cron.d",
    ],
    # RUN-PARTS DIRECTORIES ARE NOT CRONTABS. Debian ships /etc/crontab with a
    # line that calls `run-parts --report /etc/cron.daily`, and the scripts in
    # those directories are SHELL PROGRAMS that happen to be invoked on a
    # schedule. Reading them as crontabs (which the first version did) produced
    # 130 "cron jobs" that were really `if test -f ...` and `fi`: measured
    # 2026-09-24, 130 of 143 reported cron entries were lines of a script body.
    # They are listed as executables now, which is what they are.
    "cron_runparts": [
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ],
    "cron_user": [
        "/var/spool/cron/crontabs",  # Debian/Ubuntu
        "/var/spool/cron",            # RHEL/CentOS
    ],
    "init_d": [
        "/etc/init.d",
    ],
    "shell_startup": [
        "~/.bashrc",
        "~/.bash_profile",
        "~/.profile",
        "~/.zshrc",
        "~/.zprofile",
    ],
}

# SUSPICIOUS PATTERNS, AND THE RULE THEY ARE MATCHED UNDER
#
# TWO-WAY MATCHING, decided per pattern, because one rule cannot be right for
# both kinds:
#
#   TOKEN   the pattern must stand alone: not preceded or followed by a word
#           character. "nc" must not match "anacron"; "curl" must not match
#           "a curl of the data". This is the default and it is what makes the
#           short names usable at all.
#   PHRASE  the pattern is a distinctive byte sequence that reads as itself
#           wherever it appears: "/dev/tcp/", "bash -i", "chmod +x".
#
# A pattern that needs to fire on a bare filename (`nc`, `ncat`, `wget`,
# `curl`) is ONLY safe token-wise. A pattern that is already unambiguous is
# safer phrase-wise, because a shell can write it without a space after the
# last character (`...bash -i>/dev/tcp/...`). The list below says which is
# which instead of leaving it to whoever adds the next entry.
#
# EVERY ENTRY IS (pattern, mode, what-it-means). The third field is what the
# finding says, because "matched the pattern nc" is not a sentence anybody can
# act on and "a command that reads a remote script and pipes it to a shell" is.
SUSPICIOUS_PATTERNS: list[tuple[str, str, str]] = [
    # remote fetch / staging: the classic first stage
    ("curl",           "token",  "fetches a remote resource"),
    ("wget",           "token",  "fetches a remote resource"),
    ("nc",             "token",  "netcat: a raw network connection or a shell"),
    ("ncat",           "token",  "netcat: a raw network connection or a shell"),
    ("socat",          "token",  "relays a connection between two endpoints"),
    ("tftp",           "token",  "fetches over an unauthenticated protocol"),
    ("/dev/tcp/",      "phrase", "a bash TCP socket, which needs no tool at all"),

    # a shell on the other end
    ("bash -i",        "phrase", "an interactive shell"),
    ("sh -i",          "phrase", "an interactive shell"),
    ("/bin/sh -i",     "phrase", "an interactive shell"),
    ("-e /bin/sh",     "phrase", "a remote shell"),
    ("-e /bin/bash",   "phrase", "a remote shell"),

    # inline interpreters, which is how a one-liner hides
    ("python -c",      "phrase", "an inline script, invisible to a file listing"),
    ("python3 -c",     "phrase", "an inline script, invisible to a file listing"),
    ("perl -e",        "phrase", "an inline script, invisible to a file listing"),
    ("ruby -e",        "phrase", "an inline script, invisible to a file listing"),

    # payload assembly
    ("base64 -d",      "phrase", "decodes a payload it did not have to explain"),
    ("base64 --decode", "phrase", "decodes a payload it did not have to explain"),
    ("openssl enc",    "phrase", "decrypts a staged payload"),
    ("xxd -r",         "phrase", "reassembles binary from text"),

    # permission and detach tricks
    ("chmod +x",       "phrase", "makes a staged file executable"),
    ("chmod 777",      "phrase", "makes a staged file world-writable"),
    ("nohup",          "token",  "runs detached from the terminal that started it"),
    ("setsid",         "token",  "starts a new session, away from the caller's"),
    ("disown",         "token",  "detaches a job from the shell's job control"),

    # disarming the machine's own defences
    ("systemctl disable", "phrase", "turns a service off so it stops starting"),
    ("systemctl stop",    "phrase", "stops a service that was running"),
    ("systemctl mask",    "phrase", "makes a service impossible to start"),
    ("ufw disable",    "phrase", "turns the firewall off"),
    ("iptables -F",    "phrase", "flushes the firewall rules"),
    ("nft flush",      "phrase", "flushes the nftables rules"),
    ("apparmor=0",     "phrase", "boots with the MAC framework disabled"),
    ("selinux=0",      "phrase", "boots with the MAC framework disabled"),
    ("setenforce 0",   "phrase", "turns SELinux off at runtime"),

    # staging directories, as a weak positive
    ("/tmp/",          "phrase", "runs from a world-writable directory"),
    ("/var/tmp/",      "phrase", "runs from a world-writable directory"),
    ("/dev/shm/",      "phrase", "runs from memory, which survives no forensics"),
]

# CRITICAL_SERVICES WAS DELETED HERE, 2026-09-24. It was a ten-name list with
# ZERO consumers anywhere in the tree (measured: grep across every .py file).
# A list nothing reads is not a check, it is a decoration that reads as one --
# AD7's and EM-11's shape, and the register's rule 4 puts it last for that
# reason.

# WHERE AN ENTRY'S COMMAND LIVES, per systemd. A unit's executive lines are the
# ones that run something; Description=, Documentation= and DefaultDependencies=
# are not programs, and matching the whole file against a pattern list is what
# produced the 151 false findings.
UNIT_EXEC_DIRECTIVES = (
    "ExecStart", "ExecStartPre", "ExecStartPost",
    "ExecReload", "ExecStop", "ExecStopPost",
    "ExecCondition",
)

# The twin caps every command at 1000 characters (`str(value)[:1000]`) and the
# port dropped it. A unit file or a crontab line is attacker-writable text and
# reaches the model as tool output; core/sanitize fences it and caps the whole
# payload, and this cap is the module's own so that one enormous field cannot
# crowd out the rest of the inventory. Same number as the twin, deliberately.
MAX_FIELD = 1000

# A unit file read in full. Measured on this host: the largest of 260 system
# unit files is 2,474 bytes and the median is 664, so this ceiling is roughly
# ten times the biggest real file and exists only so that a pathological one
# cannot be read into memory without a limit.
MAX_UNIT_BYTES = 262144

# `systemctl show` ABORTS THE WHOLE BATCH AT THE FIRST NAME IT CANNOT TAKE.
# Measured 2026-09-24: twelve names with one template (`autovt@.service`) in
# the middle returned ten blocks, rc 1, and silently dropped everything after
# the bad name. That is AD1's shape -- a reader that loses rows and says
# nothing -- so every batched call here VERIFIES the ids it got back against
# the ids it asked for, and names what was missing.
SHOW_CHUNK = 200

_TEMPLATE_RE = re.compile(r"@\.(service|socket|target|timer|mount)$")


def _expand_path(path: str) -> Path:
    """Expand ~ and environment variables in a path."""
    return Path(os.path.expanduser(os.path.expandvars(path)))


def _cap(value, limit: int = MAX_FIELD) -> Optional[str]:
    """
    One field, as text, capped and marked when it was cut.

    Returns None for a value that is not there, so a caller can tell "empty"
    from "absent" instead of printing an empty string that reads as a real
    answer. The twin caps silently (`str(value)[:1000]`); this one says it cut,
    because a command trimmed to fit is a command a reader must not read as
    complete.
    """
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    if len(text) > limit:
        return text[:limit] + f" [...cut at {limit} characters]"
    return text


def _hash_content(content: str) -> str:
    """SHA-256 hash of content for change detection."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _read_file_safe(path: Path, limit: int = MAX_UNIT_BYTES):
    """
    Read a file, returning (text, refusal).

    THE REFUSAL IS RETURNED, NOT SWALLOWED. The first version logged a debug
    line and returned None, so a permission refusal and an empty file arrived at
    the caller as the same thing: nothing. Measured on this host, the per-user
    crontab spool (/var/spool/cron/crontabs, mode 1730 root:crontab) is refused
    to this account, and the module reported it as zero user cron jobs with
    nothing anywhere saying it had not been allowed to look.
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read(limit + 1)
    except (PermissionError, FileNotFoundError, IsADirectoryError, OSError) as e:
        return None, f"{type(e).__name__}: {e}"
    if len(raw) > limit:
        return None, (f"file is larger than the {limit}-byte read limit this "
                      f"module sets for a unit file; not read")
    return raw.decode("utf-8", errors="replace"), None


def _list_dir_safe(path: Path):
    """List a directory's files, returning (paths, refusal)."""
    try:
        entries = sorted(p for p in path.iterdir() if p.is_file())
    except (PermissionError, FileNotFoundError, NotADirectoryError, OSError) as e:
        return [], f"{type(e).__name__}: {e}"
    return entries, None


def _file_owner(path: Path) -> Optional[str]:
    """
    The ACCOUNT THAT OWNS THE FILE, read from the file itself.

    WHAT THIS REPLACES, and it is SNF-5's rule for the third time in this tree:
    the module used `os.environ.get("USER", "unknown")`, which answers with the
    account running the APP and not the account that owns the file -- and which
    is EMPTY under systemd, so the honest-looking default `"unknown"` was the
    normal answer in the one environment this app is meant to run in. Measured
    with `env -u USER`: both shell startup files reported owner "unknown" on a
    machine where the owner is readable from a stat() call.
    """
    try:
        st = os.stat(path)
    except OSError:
        return None
    try:
        return pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        return f"uid:{st.st_uid}"


def _file_mode(path: Path) -> Optional[str]:
    """The file's permission bits, octal, or None. Read, never changed."""
    try:
        return oct(stat.S_IMODE(os.stat(path).st_mode))
    except OSError:
        return None


def _pattern_hits(text: str, patterns=None) -> list[dict]:
    """
    Every suspicious pattern in one piece of text, with the line that carried it.

    TOKEN-WISE OR PHRASE-WISE PER PATTERN, see SUSPICIOUS_PATTERNS for why the
    distinction exists. The old test was `pattern.lower() in text.lower()`, which
    is how "nc" matched `DefaultDependencies=no` on 111 of this host's 261
    units.
    """
    out = []
    for pattern, mode, meaning in (patterns or SUSPICIOUS_PATTERNS):
        if mode == "token":
            rx = re.compile(r"(?<![\w.-])" + re.escape(pattern) + r"(?![\w.-])",
                            re.IGNORECASE)
        else:
            rx = re.compile(re.escape(pattern), re.IGNORECASE)
        for line_num, line in enumerate(text.split("\n"), 1):
            if not rx.search(line):
                continue
            stripped = line.strip()
            out.append({
                "pattern":   pattern,
                "meaning":   meaning,
                "line":      line_num,
                "content":   _cap(stripped, 500),
                # A COMMENT CANNOT RUN. It is still worth reporting -- somebody
                # wrote it down, and a commented-out `curl | sh` is a fact about
                # the file -- but it is not the same claim as live code, and the
                # finding says which one it is instead of leaving the reader to
                # guess from the text.
                "commented": stripped.startswith("#"),
            })
            break
    return out


def _is_template(name: str) -> bool:
    """
    A unit NAME with no instance: `getty@.service`, `autovt@.service`.

    systemd refuses to answer for these by name -- measured: `systemctl show
    autovt@.service` returns rc 1 with "Unit name autovt@.service is neither a
    valid invocation ID nor unit name" -- so they are named in the coverage
    rather than asked for and silently dropped.
    """
    return bool(_TEMPLATE_RE.search(name))


def _resolve_unit_paths(names: list[str]) -> tuple[dict, dict, dict]:
    """
    Where each unit's file lives, in ONE systemctl call, with its answers checked.

    Returns (paths, state, coverage). `paths` maps unit name to its absolute
    fragment path; `state` maps unit name to systemd's own UnitFileState.

    WHY THIS REPLACES THE DIRECTORY GUESS. The first version looked for each unit
    in the three system directories, in order, and gave up at the first miss.
    Measured on this host: THREE of 261 units had no resolvable path
    (netplan-ovs-cleanup.service and speech-dispatcher.service are both real,
    both enabled, and both live under /run/systemd/system and
    /run/systemd/generator.late -- directories the module never looked in). A
    unit whose file cannot be found is a unit whose CONTENT cannot be read, so
    the guess was also the reason three units contributed nothing.

    AND THE ANSWER IS CHECKED -- BY NAME, NOT BY ID. `systemctl show` aborts a
    whole batch at the first name it cannot take, and it answers an ALIAS under
    the canonical unit's id: measured, `show sshd.service` returns
    `Id=ssh.service, Names=ssh.service sshd.service`. Asking for `Id` alone
    therefore read 20 working aliases as "no answer", which is the same
    false-alarm shape as the findings this round removed. `Names=` is asked for
    and every alias is resolved to the file it points at.
    """
    paths, states, missing = {}, {}, []
    askable = [n for n in names if not _is_template(n)]

    for start in range(0, len(askable), SHOW_CHUNK):
        chunk = askable[start:start + SHOW_CHUNK]
        try:
            r = subprocess.run(
                ["systemctl", "show", "--no-pager",
                 "-p", "Id", "-p", "Names", "-p", "FragmentPath",
                 "-p", "UnitFileState"]
                + chunk,
                capture_output=True, text=True, timeout=60)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            logger.warning(f"autorun_monitor: systemctl show failed for a "
                           f"chunk of {len(chunk)} units: {e}")
            missing.extend(chunk)
            continue

        answered = set()
        current = {}
        for line in list(r.stdout.split("\n")) + [""]:
            if not line.strip():
                if current.get("Id"):
                    for alias in (current.get("Names") or
                                  current["Id"]).split():
                        answered.add(alias)
                        paths[alias] = current.get("FragmentPath") or None
                        states[alias] = current.get("UnitFileState") or None
                current = {}
                continue
            key, _, value = line.partition("=")
            current[key] = value
        if current.get("Id"):
            for alias in (current.get("Names") or current["Id"]).split():
                answered.add(alias)
                paths[alias] = current.get("FragmentPath") or None
                states[alias] = current.get("UnitFileState") or None

        gone = [n for n in chunk if n not in answered]
        if gone:
            missing.extend(gone)
            logger.debug(f"autorun_monitor: systemctl show answered for "
                         f"{len(answered)} of {len(chunk)} units; "
                         f"{len(gone)} had no block")

    coverage = {
        "units_asked": len(askable),
        "units_answered": len([n for n in askable if n in paths]),
        "template_names_skipped": len(names) - len(askable),
        "units_without_a_fragment_path": sorted(
            n for n in askable if n in paths and not paths[n]),
        "units_the_manager_did_not_answer_for": sorted(missing)[:20],
        "units_the_manager_did_not_answer_for_count": len(missing),
    }
    return paths, states, coverage


def _resolve_exec_starts(names: list[str]) -> tuple[dict, dict]:
    """
    What each unit actually RUNS, in ONE systemctl call, ids checked.

    THE TWIN HAS THIS AND THE PORT DROPPED IT. `tools/registry_monitor.py`
    records a `command` for every autorun entry; this module recorded a unit
    file PATH and no command at all, and the adapter passed that path through
    under the name `command` -- so the model was told the command that starts an
    autorun was `/lib/systemd/system/anacron.service`, a filename. Measured
    2026-09-24: the module's entry keys were exactly
    {description, name, path, state, type}. The question an autorun inventory
    exists to answer -- what does this thing run? -- was unanswerable.

    Measured cost of asking properly: 0.27 s for all 261 units in one call,
    against 2.68 s for the per-file content reads the module already did.
    """
    execs, coverage = {}, {"asked": 0, "answered": 0, "empty": []}
    askable = [n for n in names if not _is_template(n)]
    coverage["asked"] = len(askable)

    for start in range(0, len(askable), SHOW_CHUNK):
        chunk = askable[start:start + SHOW_CHUNK]
        try:
            r = subprocess.run(
                ["systemctl", "show", "--no-pager",
                 "-p", "Id", "-p", "Names", "-p", "ExecStart"]
                + chunk,
                capture_output=True, text=True, timeout=60)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            logger.warning(f"autorun_monitor: ExecStart read failed for a chunk "
                           f"of {len(chunk)} units: {e}")
            continue

        current_id, names_val, current_exec = None, None, None
        for line in list(r.stdout.split("\n")) + [""]:
            if not line.strip():
                if current_id:
                    coverage["answered"] += 1
                    command = _cap(_parse_exec_start(current_exec))
                    for alias in (names_val or current_id).split():
                        execs[alias] = command
                    if not current_exec:
                        coverage["empty"].append(current_id)
                current_id, names_val, current_exec = None, None, None
                continue
            key, _, value = line.partition("=")
            if key == "Id":
                current_id = value
            elif key == "Names":
                names_val = value
            elif key == "ExecStart":
                current_exec = value

    coverage["empty"] = sorted(set(coverage["empty"]))[:20]
    return execs, coverage


def _parse_exec_start(raw: Optional[str]) -> Optional[str]:
    """
    systemd's ExecStart struct, as the command a reader would type.

    The field arrives in systemd's own notation rather than as a command line:
    measured on this host,

        ExecStart={ path=/usr/sbin/anacron ; argv[]=/usr/sbin/anacron -d -q
        $ANACRON_ARGS ; ignore_errors=no ; start_time=[n/a] ; ... }

    The `argv[]` half is the one a human wrote, so it wins. When there is no
    argv (a unit that only names a path) the `path=` half is used, and when
    neither is there the empty string is returned rather than an invented one.
    A unit with several ExecStart lines arrives as one value per line and they
    are joined with " ; " -- measured: lm-sensors.service has two.
    """
    if not raw or not raw.strip():
        return None
    argv = re.search(r"argv\[\]=(.*?)\s*;", raw)
    if argv and argv.group(1).strip():
        return argv.group(1).strip()
    path = re.search(r"path=([^;]+);", raw)
    if path and path.group(1).strip():
        return path.group(1).strip()
    return raw.strip()


def get_systemd_services() -> list[dict]:
    """
    Enumerate systemd service units.

    Returns list of dicts with:
    - name: service name
    - path: full path to unit file, or None when systemd did not name one
    - state: systemd's own UnitFileState
    - description: service description
    - command: what the unit RUNS (ExecStart), or None
    - exec_lines: the unit's executive lines, for the pattern matcher
    - hash: content hash for change detection
    """
    services = []
    names = []

    try:
        result = subprocess.run(
            ["systemctl", "list-unit-files", "--type=service", "--all",
             "--no-pager", "--no-legend"],
            capture_output=True,
            text=True,
            timeout=30
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        # RAISED, NOT SWALLOWED. A machine with no systemctl is not a machine
        # with no autoruns, and the first version logged this at debug and
        # returned [] -- measured: with systemctl unreachable the module
        # reported 0 systemd services, searched=True and no note anywhere.
        raise UnitEnumerationRefused(
            f"systemctl could not be run, so NO systemd unit was enumerated "
            f"at all. This is a refusal to look and not an empty machine: {e}")

    if result.returncode != 0:
        raise UnitEnumerationRefused(
            f"`systemctl list-unit-files` answered rc={result.returncode}: "
            f"{_cap(result.stderr.strip(), 300)}")

    for line in result.stdout.split("\n"):
        parts = line.split()
        # THE PARSER, CORRECTED.
        #
        # The first version sliced `raw.strip().split('\n')[2:]`, assuming one
        # header line. `--no-legend` removes the header AND the "N unit files
        # listed." footer, which is why it is passed now. MEASURED on this host
        # with the old slice: the module DROPPED accounts-daemon.service (a real
        # enabled unit, the first data line) and INVENTED a unit called "261"
        # from the footer line "261 unit files listed.", giving it state "unit"
        # and no path. One real entry lost, one fiction added, nothing said.
        if len(parts) < 2 or not parts[0].endswith(".service"):
            continue
        names.append(parts[0])

    paths, states, path_coverage = _resolve_unit_paths(names)
    execs, exec_coverage = _resolve_exec_starts(names)

    for name in names:
        unit_path = paths.get(name)
        description = ""
        content = None
        read_refusal = None

        if unit_path and os.path.isfile(unit_path):
            content, read_refusal = _read_file_safe(Path(unit_path))
            if content:
                for line in content.split("\n"):
                    if line.startswith("Description="):
                        description = _cap(line[12:].strip(), 300) or ""
                        break

        services.append({
            "name":        name,
            "path":        unit_path,
            "state":       states.get(name),
            "description": description,
            "command":     execs.get(name),
            "exec_lines":  _unit_exec_text(content),
            "read_refusal": read_refusal,
            "type":        "systemd_service",
        })

    # The coverage travels WITH the list. A caller that has to ask separately
    # is a caller that will not.
    get_systemd_services.coverage = {
        **path_coverage,
        "exec_starts_asked": exec_coverage["asked"],
        "exec_starts_answered": exec_coverage["answered"],
        "units_with_no_exec_start": exec_coverage["empty"],
        "units_whose_file_could_not_be_read": sorted(
            s["name"] for s in services if s["read_refusal"]),
    }
    return services


def _unit_exec_text(content: Optional[str]) -> Optional[str]:
    """
    Just the lines that RUN something, for the matcher.

    `Description=Run anacron jobs` is not a program, and neither is
    `DefaultDependencies=no`. Matching a whole unit file is what made the first
    version report 151 findings about words like "performance" and "since".
    """
    if not content:
        return None
    keep = []
    for line in content.split("\n"):
        stripped = line.strip()
        if stripped.startswith("#"):
            keep.append(line)
            continue
        directive = stripped.split("=", 1)[0]
        if directive in UNIT_EXEC_DIRECTIVES:
            keep.append(line)
    return "\n".join(keep)


class UnitEnumerationRefused(RuntimeError):
    """systemctl could not be asked, so nothing was enumerated."""


def get_cron_jobs() -> list[dict]:
    """
    Enumerate cron jobs.

    Returns list of dicts with:
    - name: job identifier
    - path: full path to cron file
    - schedule: the five time fields, or the reason they could not be read
    - command: command to execute
    - user: user who owns the job (if known)
    - hash: content hash
    """
    jobs = []

    # SYSTEM CRONTAB FILES: /etc/crontab and /etc/cron.d/*
    #
    # A crontab FILE has real schedule lines, and they are parsed as such. The
    # first version wrote the literal string "system" into every row's schedule
    # field instead, so the adapter's `schedule` column was a constant and the
    # tool description's promise of a schedule was unbacked.
    for cron_path in AUTORUN_PATHS["cron_system"]:
        path = _expand_path(cron_path)
        if path.is_file():
            targets = [(path, None)]
        elif path.is_dir():
            targets, refusal = _list_dir_safe(path)
            if refusal:
                logger.warning(f"autorun_monitor: {path} could not be listed "
                               f"({refusal}); its cron entries are NOT in this "
                               f"result.")
            targets = [(f, None) for f in targets]
        else:
            continue

        for file_path, _ in targets:
            content, refusal = _read_file_safe(file_path)
            if refusal:
                logger.warning(f"autorun_monitor: {file_path} could not be read "
                               f"({refusal}); its cron entries are NOT in this "
                               f"result.")
                continue
            if not content:
                continue
            owner = _file_owner(file_path)
            for line_num, line in enumerate(content.split("\n"), 1):
                parsed = _parse_crontab_line(line)
                if parsed is None:
                    continue
                jobs.append({
                    "name":     f"{file_path.name}:{line_num}",
                    "path":     str(file_path),
                    "schedule": parsed["schedule"],
                    "command":  _cap(parsed["command"]),
                    "user":     parsed["user"] or owner,
                    "type":     "system_cron",
                    "line":     line_num,
                })

    # RUN-PARTS DIRECTORIES: the SCRIPTS are the entries, not their lines
    #
    # /etc/crontab calls `run-parts --report /etc/cron.daily`, so what runs is
    # each EXECUTABLE FILE in the directory. The first version read those files
    # and emitted every non-comment line as its own "cron job" -- measured: 130
    # of 143 reported entries were lines of a script body (`bak=/var/backups`,
    # `if test -f ...`, `fi`).
    for dir_path in AUTORUN_PATHS["cron_runparts"]:
        path = _expand_path(dir_path)
        if not path.is_dir():
            continue
        entries, refusal = _list_dir_safe(path)
        if refusal:
            logger.warning(f"autorun_monitor: {path} could not be listed "
                           f"({refusal}); its scheduled scripts are NOT in this "
                           f"result.")
            continue
        for script in entries:
            if script.name.startswith("."):
                continue
            runnable = os.access(script, os.X_OK)
            owner = _file_owner(script)
            jobs.append({
                "name":     script.name,
                "path":     str(script),
                "schedule": f"run-parts {path.name}",
                "command":  _cap(_first_code_line(script)),
                "user":     owner,
                "type":     "run_parts",
                "line":     None,
                "runnable": runnable,
            })

    # USER CRONTABS: readable only as a member of `crontab` or as root
    #
    # MEASURED on this host: /var/spool/cron/crontabs is mode 1730 root:crontab
    # and this account cannot list it. The first version returned [] for that
    # and nothing anywhere said it had not been allowed to look -- the
    # "honest nothing" and "cannot look" confusion this project writes checks
    # for. The refusal is recorded now.
    cron_spool = None
    for spool_path in AUTORUN_PATHS["cron_user"]:
        candidate = _expand_path(spool_path)
        if candidate.exists():
            cron_spool = candidate
            break

    get_cron_jobs.user_spool = {
        "path": str(cron_spool) if cron_spool else None,
        "readable": bool(cron_spool and os.access(cron_spool, os.R_OK | os.X_OK)),
        "entries": 0,
        "refusal": None,
    }
    if cron_spool and cron_spool.is_dir():
        user_crons, refusal = _list_dir_safe(cron_spool)
        get_cron_jobs.user_spool["refusal"] = refusal
        if refusal:
            logger.warning(
                f"autorun_monitor: per-user cron tabs live in {cron_spool} and "
                f"this account cannot list it ({refusal}), so NO per-user cron "
                f"job is in this result. That is a refusal to look, not a "
                f"machine with no user cron: the directory is mode "
                f"{_file_mode(cron_spool)} and belongs to "
                f"{_file_owner(cron_spool)}.")
        for user_cron in user_crons:
            content, refusal = _read_file_safe(user_cron)
            if refusal:
                continue
            if not content:
                continue
            for line_num, line in enumerate(content.split("\n"), 1):
                parsed = _parse_crontab_line(line)
                if parsed is None:
                    continue
                jobs.append({
                    "name":     f"{user_cron.name}:{line_num}",
                    "path":     str(user_cron),
                    "schedule": parsed["schedule"],
                    "command":  _cap(parsed["command"]),
                    "user":     user_cron.name,
                    "type":     "user_cron",
                    "line":     line_num,
                })
        get_cron_jobs.user_spool["entries"] = sum(
            1 for j in jobs if j.get("type") == "user_cron")

    return jobs


def _first_code_line(path: Path) -> Optional[str]:
    """The first line of a script that would actually run, for a summary."""
    content, refusal = _read_file_safe(path, limit=65536)
    if not content:
        return None
    for line in content.split("\n"):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped
    return None


def _parse_crontab_line(line: str) -> Optional[dict]:
    """
    One line of a crontab file, or None when the line is not a job.

    WHAT IS REJECTED, and why each one had to be named rather than left to a
    strip(): an environment assignment (`SHELL=/bin/sh`, `PATH=...`, `MAILTO=""`)
    is not a job -- measured, 20 of this host's 143 "cron jobs" were these. A
    comment is not a job. A bare run-parts line is a job.

    Returns {"schedule": "m h dom mon dow", "user": str|None, "command": str}.
    The schedule is the FIVE TIME FIELDS as written, because that is what the
    reader needs to see and what the adapter was calling "system" for every row.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    # An assignment: NAME=value with no whitespace around a legal variable name
    # and nothing before it. `MAILTO=""` and `bak=/var/backups` both match;
    # `0 * * * * root timeshift --check` does not.
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", stripped):
        return None

    # The five time fields, either the five-field form or a @keyword form.
    parts = stripped.split()
    keyword = re.match(r"^(@(reboot|yearly|annually|monthly|weekly|daily|"
                       r"midnight|hourly))(\s+)(.*)$", stripped)
    if keyword:
        return {
            "schedule": keyword.group(1),
            "user":     None,
            "command":  keyword.group(3),
        }

    # A five-field schedule plus a command. The command may itself start with a
    # user field (system crontab), which is why the caller decides that part.
    if len(parts) < 6:
        return None
    if not all(_looks_like_time_field(f) for f in parts[:5]):
        return None

    return {
        "schedule": " ".join(parts[:5]),
        "user":     None,
        "command":  " ".join(parts[5:]),
    }


def _looks_like_time_field(field: str) -> bool:
    """A cron time field: digits, `*`, ranges, lists, steps, and month names."""
    if field == "*":
        return True
    if any(ch.isalpha() for ch in field) and not re.match(
            r"^[A-Za-z]{3}(-[A-Za-z]{3})?(/\d+)?$", field):
        return False
    return bool(re.match(
        r"^(\*|\d+)(-\d+)?(/\d+)?(,(\*|\d+)(-\d+)?(/\d+)?)*$", field))


def get_init_scripts() -> list[dict]:
    """
    Enumerate SysV init scripts.

    Returns list of dicts with:
    - name: script name
    - path: full path
    - description: script description
    - owner, mode: read from the file
    - runlevels: the rc*.d links that actually call it, or [] when nothing does
    - hash: content hash
    """
    scripts = []

    for init_path in AUTORUN_PATHS["init_d"]:
        path = _expand_path(init_path)
        if not path.is_dir():
            continue
        entries, refusal = _list_dir_safe(path)
        if refusal:
            logger.warning(f"autorun_monitor: {path} could not be listed "
                           f"({refusal}); no init.d script is in this result.")
            continue
        for script_path in entries:
            content, refusal = _read_file_safe(script_path)
            if refusal:
                continue
            # THE DOCSTRING PROMISED `runlevels` AND THE CODE NEVER SET
            # IT. Four of this module's five docstrings promised a `hash` key
            # that no branch produced; this one promised runlevels too. Both are
            # real fields now, because a promise in a docstring that the code
            # does not keep is a claim a reader can check and find false.
            description = ""
            if content:
                for line in content.split("\n"):
                    if line.startswith("# Short-Description:"):
                        description = _cap(line.split(":", 1)[1].strip(), 300) or ""
                        break

            scripts.append({
                "name":        script_path.name,
                "path":        str(script_path),
                "description": description,
                "owner":       _file_owner(script_path),
                "mode":        _file_mode(script_path),
                "runlevels":   _rc_links_for(script_path.name),
                "hash":        _hash_content(content) if content else None,
                "type":        "init_script",
            })

    return scripts


def _rc_links_for(name: str) -> list[str]:
    """
    The rc*.d symlinks that call this init script, if any.

    WHY IT MATTERS: an init script that NO runlevel links is not something that
    starts at boot -- it is a leftover. Reporting the two the same is how an
    inventory turns into a list of everything that has ever been installed.
    Measured on this host: all 33 are linked, so this is a no-op here and the
    field still has to be right on a machine where it is not.
    """
    links = []
    for rc_dir in sorted(Path("/etc").glob("rc*.d")):
        try:
            entries = list(rc_dir.iterdir())
        except OSError:
            continue
        for entry in entries:
            if len(entry.name) > 3 and entry.name[0] in "SK" \
                    and entry.name[3:] == name:
                links.append(entry.name)
                break
    return links


def get_shell_startup() -> list[dict]:
    """
    Enumerate shell startup files.

    Returns list of dicts with:
    - name: file name
    - path: full path
    - user: the account that OWNS the file, read from a stat
    - mode: the file's permission bits
    - hash: content hash
    - suspicious_lines: lines matching suspicious patterns
    """
    startup_files = []

    for startup_path in AUTORUN_PATHS["shell_startup"]:
        path = _expand_path(startup_path)
        if not (path.exists() and path.is_file()):
            continue
        content, refusal = _read_file_safe(path)
        if refusal:
            logger.warning(f"autorun_monitor: {path} could not be read "
                           f"({refusal}); it is NOT in this result.")
            continue
        if content:
            startup_files.append({
                "name":            path.name,
                "path":            str(path),
                # THE FILE'S OWNER, never $USER. See _file_owner.
                "user":            _file_owner(path),
                "mode":            _file_mode(path),
                "hash":            _hash_content(content),
                "suspicious_lines": _pattern_hits(content),
                "type":            "shell_startup",
            })

    return startup_files


def get_user_units() -> list[dict]:
    """
    User-manager unit FILES, read from disk.

    ,,,, DECLARED IN AUTORUN_PATHS SINCE THE PORT AND READ BY NOTHING. ,,,,
    Measured 2026-09-24: the string `AUTORUN_PATHS["systemd_user"]` occurred ZERO
    times in this file while the key sat at the top of it declaring two
    directories. On this host that hid `~/.config/systemd/user/
    hermes-gateway.service` -- a unit that starts a program at every login --
    and the user manager's own list is 109 unit files.

    WHY THE FILES AND NOT `systemctl --user`: this sensor runs as a service, and
    a service's `systemctl --user` talks to the USER MANAGER OF WHICHEVER
    ACCOUNT THE CALLER IS, which is not the account whose autostart files matter.
    A unit file on disk is true whether or not its manager is running, and the
    twin reads a registry key for the same reason: it is the stored arrangement,
    not the running state.

    These are NOT merged into get_systemd_services() on purpose. A user unit and
    a system unit are different claims about who starts what, and a merged list
    would lose which is which.
    """
    out = []
    for base in AUTORUN_PATHS["systemd_user"]:
        root = _expand_path(base)
        if not root.is_dir():
            continue
        try:
            files = [p for p in sorted(root.iterdir())
                     if p.is_file() and p.suffix in (".service", ".socket",
                                                     ".timer", ".target",
                                                     ".path")]
        except OSError as e:
            logger.warning(f"autorun_monitor: {root} could not be listed ({e}); "
                           f"no user unit is in this result.")
            continue
        for unit in files:
            content, refusal = _read_file_safe(unit)
            if refusal:
                continue
            description = ""
            if content:
                for line in content.split("\n"):
                    if line.startswith("Description="):
                        description = _cap(line[12:].strip(), 300) or ""
                        break
            out.append({
                "name":        unit.name,
                "path":        str(unit),
                "state":       None,
                "description": description,
                "command":     _cap(_exec_start_from_file(content)),
                "exec_lines":  _unit_exec_text(content),
                # A FILE IN A DIRECTORY IS NOT ENABLED. Enabling writes a
                # want-link in <target>.wants and it is that link, not the file,
                # that starts it -- so this says whether one exists instead of
                # calling every file "enabled".
                "wanted_by":   _want_links_for(unit, root),
                "owner":       _file_owner(unit),
                "type":        "systemd_service",
                "scope":       "user",
            })
    return out


def _exec_start_from_file(content: Optional[str]) -> Optional[str]:
    """
    The ExecStart line of a unit FILE, for the user units that have no manager
    to ask. systemd's own `show` gives a parsed struct; a file gives the
    directive line, which is what was written and is enough to match on.
    """
    if not content:
        return None
    for line in content.split("\n"):
        stripped = line.strip()
        if stripped.startswith("ExecStart="):
            return stripped[len("ExecStart="):].strip() or None
    return None


def _want_links_for(unit: Path, root: Path) -> list[str]:
    """The `<something>.wants/` links pointing at this unit, if any."""
    wanted = []
    for wants_dir in root.glob("*.wants"):
        try:
            for link in wants_dir.iterdir():
                if link.name == unit.name:
                    wanted.append(wants_dir.name)
                    break
        except OSError:
            continue
    return wanted


BASELINE_TABLE = "autorun_baseline"


def _fp(*parts) -> str:
    return hashlib.sha256("\x00".join(str(p or "") for p in parts)
                          .encode("utf-8", "replace")).hexdigest()


def snapshot(services=None, user_units=None, crons=None, inits=None,
             startup=None) -> dict:
    """
    Every autorun entry as {entry_key: {kind, name, path, fingerprint, detail}}.

    The key says which entry it is, the fingerprint what it runs. A cron line
    is keyed by its content, since its line number moves when another line is
    added above it.
    """
    services = get_systemd_services() if services is None else services
    user_units = get_user_units() if user_units is None else user_units
    crons = get_cron_jobs() if crons is None else crons
    inits = get_init_scripts() if inits is None else inits
    startup = get_shell_startup() if startup is None else startup

    out = {}
    for u in list(services) + list(user_units):
        kind = "user_unit" if u.get("scope") == "user" else "systemd_service"
        key = f"{kind}:{u.get('path') or u.get('name')}"
        out[key] = {"kind": kind, "name": u.get("name"), "path": u.get("path"),
                    "fingerprint": _fp(u.get("command"), u.get("exec_lines"),
                                       u.get("state"), u.get("wanted_by")),
                    "detail": _cap(u.get("command"), 300)}
    for c in crons:
        body = _fp(c.get("schedule"), c.get("user"), c.get("command"))
        key = f"cron:{c.get('path')}:{body[:16]}"
        out[key] = {"kind": "cron", "name": c.get("name"), "path": c.get("path"),
                    "fingerprint": body,
                    "detail": _cap(f"{c.get('schedule') or ''} "
                                   f"{c.get('command') or ''}".strip(), 300)}
    for kind, rows in (("init_script", inits), ("shell_startup", startup)):
        for r in rows:
            key = f"{kind}:{r.get('path')}"
            out[key] = {"kind": kind, "name": r.get("name"), "path": r.get("path"),
                        "fingerprint": r.get("hash") or _fp(r.get("path")),
                        "detail": None}
    return out


def load_baseline() -> Optional[dict]:
    """The stored reading, or None when there has never been one."""
    try:
        with me._get_conn() as conn:
            rows = conn.execute(
                f"SELECT entry_key, kind, name, path, fingerprint, detail, "
                f"first_seen FROM {BASELINE_TABLE}").fetchall()
    except Exception as e:
        logger.error(f"autorun_monitor: could not read the baseline ({e}).")
        return None
    if not rows:
        return None
    return {r[0]: {"kind": r[1], "name": r[2], "path": r[3],
                   "fingerprint": r[4], "detail": r[5], "first_seen": r[6]}
            for r in rows}


def _still_unseen(entry: dict) -> bool:
    """
    True when an entry missing from this reading may simply not have been
    readable now (another account's crontab, a refused directory), so it is
    kept rather than reported removed.
    """
    path = entry.get("path")
    if not path or not os.path.lexists(path):
        return False
    return not os.access(path, os.R_OK)


def check_for_changes(current: Optional[dict] = None, update: bool = True) -> dict:
    """
    Compare this reading with the stored one. {first_run, added, removed,
    changed, kept_unreadable, baseline_entries, note}.

    The first run records a baseline and claims nothing. After that each
    change is reported once and the baseline moves to the new reading.
    """
    current = snapshot() if current is None else current
    stored = load_baseline()
    if stored is None:
        saved = save_baseline(current) if update else False
        return {"first_run": True, "added": [], "removed": [], "changed": [],
                "kept_unreadable": 0, "baseline_entries": len(current),
                "note": (f"No earlier reading, so this one is the baseline "
                         f"({len(current)} entries"
                         f"{'' if saved else ', NOT saved'}). Changes are "
                         f"reported from the next check on.")}

    added = [{"entry_key": k, **v} for k, v in current.items() if k not in stored]
    changed = [{"entry_key": k, **v, "was": stored[k].get("detail")}
               for k, v in current.items()
               if k in stored and stored[k]["fingerprint"] != v["fingerprint"]]
    removed, unreadable = [], {}
    for k, v in stored.items():
        if k in current:
            continue
        if _still_unseen(v):
            unreadable[k] = v
        else:
            removed.append({"entry_key": k, **v})

    if update:
        save_baseline({**unreadable, **current})
    return {"first_run": False, "added": added, "removed": removed,
            "changed": changed, "kept_unreadable": len(unreadable),
            "baseline_entries": len(stored),
            "note": (f"{len(added)} added, {len(removed)} removed, "
                     f"{len(changed)} changed since the last reading.")}


def analyze_suspicious() -> list[dict]:
    """
    Analyze autoruns for suspicious entries.

    WHAT CHANGED, AND IT IS THE WHOLE POINT OF THIS ROUND. The first version
    matched every pattern as a SUBSTRING of the WHOLE unit file and produced 151
    findings on this host, 150 of which were the two-letter pattern "nc" sitting
    inside an ordinary word. Each entry below is now matched TOKEN-WISE against
    the lines that RUN something, carries the line that matched it, and says
    whether that line is live code or a comment.

    Every finding still reports what matched and where rather than a score: a
    reader can check the claim, which is the only thing that makes a
    "suspicious" finding worth reading.
    """
    findings = []

    # systemd services: the executive lines
    for service in get_systemd_services():
        text = service.get("exec_lines")
        if not text:
            continue
        for hit in _pattern_hits(text):
            findings.append({
                "type":        "suspicious_systemd_service",
                "name":        service["name"],
                "path":        service["path"],
                "pattern":     hit["pattern"],
                "line":        hit["line"],
                "content":     hit["content"],
                "commented":   hit["commented"],
                "severity":    "medium",
                "description": (
                    f"Unit {service['name']} line {hit['line']} "
                    f"{'mentions' if hit['commented'] else 'runs'} "
                    f"{hit['meaning']}: {hit['pattern']!r}."),
            })

    # user units: the same rule, one scope over
    for unit in get_user_units():
        text = unit.get("exec_lines")
        if not text:
            continue
        for hit in _pattern_hits(text):
            findings.append({
                "type":        "suspicious_systemd_service",
                "name":        unit["name"],
                "path":        unit["path"],
                "pattern":     hit["pattern"],
                "line":        hit["line"],
                "content":     hit["content"],
                "commented":   hit["commented"],
                "scope":       "user",
                "severity":    "medium",
                "description": (
                    f"USER unit {unit['name']} line {hit['line']} "
                    f"{'mentions' if hit['commented'] else 'runs'} "
                    f"{hit['meaning']}: {hit['pattern']!r}. This starts for "
                    f"one account at its login, not for the machine."),
            })

    # cron jobs
    for job in get_cron_jobs():
        for hit in _pattern_hits(job.get("command") or ""):
            findings.append({
                "type":        "suspicious_cron_job",
                "name":        job["name"],
                "path":        job.get("path"),
                "command":     job["command"],
                "pattern":     hit["pattern"],
                "severity":    "medium",
                "description": (
                    f"Cron entry {job['name']} ({job.get('schedule')}) runs "
                    f"{hit['meaning']}: {hit['pattern']!r}."),
            })

    # shell startup files
    for startup in get_shell_startup():
        for suspicious in startup.get("suspicious_lines", []):
            findings.append({
                "type":        "suspicious_shell_startup",
                "name":        startup["name"],
                "path":        startup["path"],
                "line":        suspicious["line"],
                "content":     suspicious["content"],
                "pattern":     suspicious["pattern"],
                "commented":   suspicious["commented"],
                # A COMMENTED LINE IN .bashrc IS NOT A BACKDOOR. It is worth
                # reporting and it is not worth the same reading, so it is
                # ranked lower here instead of being left to the reader.
                "severity":    "low" if suspicious["commented"] else "medium",
                "description": (
                    f"Shell startup {startup['name']} line "
                    f"{suspicious['line']} "
                    f"{'mentions' if suspicious['commented'] else 'runs'} "
                    f"{suspicious['meaning']}: {suspicious['pattern']!r}. "
                    f"This runs on every interactive shell for "
                    f"{startup.get('user') or 'the file owner'}."),
            })

    return findings


def save_baseline(entries: Optional[dict] = None) -> bool:
    """Store this reading as the baseline, replacing the last one."""
    entries = snapshot() if entries is None else entries
    try:
        with me._get_conn() as conn:
            conn.execute(f"DELETE FROM {BASELINE_TABLE} WHERE entry_key NOT IN "
                         f"(SELECT value FROM json_each(?))",
                         (json.dumps(list(entries)),))
            conn.executemany(
                f"INSERT INTO {BASELINE_TABLE}(entry_key, kind, name, path, "
                f"fingerprint, detail) VALUES(?,?,?,?,?,?) "
                f"ON CONFLICT(entry_key) DO UPDATE SET "
                f"fingerprint=excluded.fingerprint, detail=excluded.detail, "
                f"name=excluded.name, last_seen=CURRENT_TIMESTAMP",
                [(k, v["kind"], v.get("name"), v.get("path"), v["fingerprint"],
                  v.get("detail")) for k, v in entries.items()])
        return True
    except Exception as e:
        logger.error(f"autorun_monitor: could not save the baseline ({e}). "
                     f"The next check compares against the old one.")
        return False


def change_findings(changes: dict) -> list[dict]:
    """The changes as findings, in analyze_suspicious()'s shape."""
    out = []
    for kind, verb, sev in (("added", "appeared", "medium"),
                            ("changed", "changed", "medium"),
                            ("removed", "disappeared", "low")):
        for e in changes.get(kind) or []:
            what = e.get("detail") or e.get("path") or e.get("name")
            out.append({
                "type": f"autorun_entry_{kind}",
                "name": e.get("name"), "path": e.get("path"),
                "command": e.get("detail"), "severity": sev,
                "description": (
                    f"{e['kind'].replace('_', ' ')} {e.get('name')} {verb} "
                    f"since the last reading: {what}"
                    + (f" (was: {e['was']})" if kind == "changed" and e.get("was")
                       else "") + "."),
            })
    return out


def monitor_once() -> dict:
    """
    Run autorun monitoring once and return results.

    Returns dict with counts and any findings.

    `searched` IS FOUR ANSWERS NOW, NOT ONE BOOLEAN. It used to be the literal
    True, returned whether or not anything had been read -- measured on
    2026-09-24: with systemctl unreachable the payload still said
    searched=True beside a count of zero. A caller cannot tell "the machine has
    no autoruns here" from "this process was not allowed to look", and those are
    different sentences to a reader.
    """
    services = get_systemd_services()
    crons = get_cron_jobs()
    inits = get_init_scripts()
    startup = get_shell_startup()
    user_units = get_user_units()
    findings = analyze_suspicious()
    changes = check_for_changes(snapshot(services, user_units, crons, inits,
                                         startup))
    findings += change_findings(changes)

    spool = getattr(get_cron_jobs, "user_spool", {}) or {}
    coverage = {
        "systemd":     getattr(get_systemd_services, "coverage", {}) or {},
        "user_units":  {"read": len(user_units)},
        "user_cron":   spool,
    }

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "counts": {
            "systemd_services": len(services),
            "systemd_user_units": len(user_units),
            "cron_jobs": len(crons),
            "init_scripts": len(inits),
            "shell_startup": len(startup),
        },
        "findings": findings,
        "changes": {k: changes[k] for k in ("first_run", "kept_unreadable",
                                            "baseline_entries", "note")}
                   | {k: len(changes[k]) for k in ("added", "removed", "changed")},
        "coverage": coverage,
        "searched": True,
    }

    # The one refusal this module raises rather than records: systemctl is the
    # spine of the systemd half and the module already raised above. Anything
    # that got here looked at least at some of the four sources, so `searched`
    # is True AND the coverage says exactly which parts answered.
    logger.info(
        f"Autorun monitor: {len(services)} systemd services "
        f"({len(user_units)} user units), {len(crons)} cron jobs, "
        f"{len(inits)} init scripts, {len(startup)} shell startup files, "
        f"{len(findings)} findings")

    return result
