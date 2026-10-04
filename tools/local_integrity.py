# tools/local_integrity.py
# AgentalSec Linux, L3. The integrity of THIS host, read directly.
#
# WHY THIS IS NOT A LOCALHOST SSH CLIENT
#
# tools/linux_monitor.py already does three of these checks. It does them over
# SSH, for another machine, and every one of its paths needs a session, a host
# key and a remote user. Pointing it at 127.0.0.1 would build a paramiko
# dependency on the machine we are already sitting on, to read a file this
# process can open. So this is a sibling module, not a mode of that one.
#
# The duplication of the IDEA is deliberate and temporary: both trees watch
# passwd, sudoers, cron and setuid. De-duplicating two implementations of a
# check is a smaller job later than untangling SSH from checks that never
# needed it, and linux_monitor is left exactly as it was. Its own tests still
# cover it.
#
# WHAT IS READ, AND WHAT CANNOT BE
#
# MEASURED ON THIS HOST, 2026-09-22, unelevated, BEFORE ANY OF THIS WAS
# WRITTEN. The numbers are why the module has the shape it has:
#
#   /etc/passwd, /etc/group, /etc/hosts, /etc/nsswitch.conf, /etc/crontab,
#   /etc/ssh/sshd_config, /etc/pam.d/*, /etc/cron.d/*        READABLE
#   /etc/sudoers, /etc/sudoers.d/*                 root-only, 440, NOT READABLE
#   /etc/shadow, /etc/gshadow            metadata readable, content NOT
#   /root/.ssh/*                                            NOT READABLE
#   the 39 directories named in UNREADABLE_DIRS_TYPICAL      NOT READABLE
#
# So the sudoers check is a SET, and it reads HALF of it, and it says so. The
# directory lists and the files stat; the contents do not come back. What is
# watched unelevated is therefore name, mode, owner, size and mtime, and a
# content edit that leaves all four identical is NOT DETECTED. That sentence
# belongs in the finding and in the coverage block, because the alternative is
# a check that reads as "sudoers is fine" while having never read it.
#
# THE SAME CODE PATH READS CONTENT WHEN IT CAN. There is no privilege switch
# here: every reader tries the read, hashes it if it worked, records the
# metadata if it did not, and carries `readable` with the record. Run this
# under an allowlisted read-only helper and the sudoers hashes appear by
# themselves. See T5_LOCAL_INTEGRITY.md for the elevation decision.
#
# THE TWO TIERS, AND WHY THEY ARE NOT ON THE SAME CLOCK
#
# TIER A, every poll (60s default). Files and directory sets, all opens on
# paths that are known in advance. Measured: the whole of tier A is about one
# second on this host, which is cheap enough to run on the sensor's own loop.
#
# TIER B, hourly. The setuid, setgid and file-capability sweep has to walk the
# filesystem. MEASURED, and this is the number that sets the cadence:
#
#     python os.walk over / with the prune list      30 to 40 seconds
#     the same walk plus getxattr per file           about 40 seconds
#     getcap -r / (the tool, spawning per file)      150 seconds
#     936,143 files seen, 19 setuid, 9 setgid, 3 with capabilities
#
# A 40 second walk does not belong on a 60 second loop. It runs on its own
# thread with its own interval and its own status, so a sweep in progress
# cannot delay a tier A pass and a slow sweep is visible as a slow sweep.
#
# ONE WALK, NOT THREE. getcap is 150s because it spawns a process per file;
# reading the security.capability xattr inside the walk that is already there
# costs nothing measurable and returns the same three answers. The walk also
# reports how many entries it could not stat and which directories it could
# not enter, which getcap cannot do at all: its silence on an unreadable
# directory is indistinguishable from that directory having no capabilities.
#
# WHAT THIS RAISES, AND WHAT IT REFUSES TO
#
# One id per CLAIM, because "the package manager disagrees about shipped
# files" and "this specific file was modified" are different sentences and
# deserve different numbers. The whole LNX-20xx block is in core/detections.
#
# A FIRST PASS SEEDS AND RAISES NOTHING, apart from one exception that is not
# really an exception: /etc/ld.so.preload EXISTING on the first pass is a
# finding immediately, because its expected state on a normal machine is
# absent and that expectation was declared by the owner, not invented here.
#
# PERMISSIONS ARE RECORDED, NOT JUDGED, ON THE SEED PASS. This host's own
# ~/.ssh/authorized_keys is 664 (measured), so a detector that shouts about a
# mode wider than 600 on sight would fire on the operator's own key file on
# day one and teach the owner to skim this module. A mode that becomes wider LATER
# is a finding with both modes in it, which is the change that means something.
# The one mode that does raise on sight is world-writable, because there is no
# reading of a world-writable key file that is safe.
#
# EVERY FINDING CARRIES WHAT IT RESTED ON: the old value, the new value, and
# whether the content was actually read or only its metadata was. A reader who
# cannot tell those apart cannot weigh the finding.
#
# ONE THING THIS MODULE CANNOT DO, SAID PLAINLY: THE SWEEP IS ANONYMOUS.
#
# Every other reader in here records WHICH file moved. The setuid walk cannot:
# the baseline is a {path: hash} map and nothing in that map knows what
# PACKAGE a path came from, so the finding's description says "Ordinary
# causes: a package was installed" rather than naming it. The sweep runs
# hourly over 940,000 files and cannot afford a package lookup per entry. That
# is a real limit and it is recorded rather than papered over; dpkg -V (tier C)
# is the check that knows what package owns what.
#
# Read-only. Nothing in this file writes to any watched path, ever.

import errno
import hashlib
import json
import logging
import os
import stat
import subprocess
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# cadence

# The poll loop's own interval, the same contract every adapter's poll uses.
POLL_INTERVAL = 60

# The sweep. The floor is here rather than in config because the walk costs
# 30 to 40 seconds of real CPU on this host: a config that asked for it every
# 10 seconds would ask for a permanently busy disk.
SWEEP_INTERVAL = 3600
SWEEP_MIN_INTERVAL = 30

# How long after start the FIRST sweep runs. Long enough that a boot is not
# competing with a filesystem walk for the disk while eight sensors are
# starting, short enough that a fresh install has a baseline the same hour.
FIRST_SWEEP_DELAY = 60

# tier A: the watch set

# Files whose CONTENT is read and hashed.
WATCHED_FILES = (
    "/etc/passwd",
    "/etc/group",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/at.deny",
    "/etc/at.allow",
    "/etc/rc.local",
    "/etc/ld.so.preload",
)

# Files whose METADATA is read and whose content is deliberately not. The two
# that matter here:
#
#   /etc/sudoers      root-only on this host, and it says so in the coverage
#   /etc/shadow       NEVER READ, and that rule is linux_monitor's, carried
#                     over word for word: it holds password hashes and has no
#                     business sitting in our database. Its mtime, size and
#                     mode are still worth watching, because adding an account
#                     moves all three.
METADATA_ONLY_FILES = (
    "/etc/sudoers",
    "/etc/shadow",
    "/etc/gshadow",
)

# Directory sets, one entry per file inside, hashed where readable. These are
# the operator-writable persistence surfaces plus the two auth config sets.
DIR_WATCH_HASHED = (
    "/etc/sudoers.d",
    "/etc/pam.d",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/etc/systemd/system",
    "/etc/systemd/user",
    "/etc/init.d",
)

# PRESENCE ONLY, no content hash, and this is a decision with a reason rather
# than a shortcut. /usr/lib/systemd/system is 467 files owned by root and
# shipped by packages. A CHANGE to one of those files is a package-owned-file
# change, which is dpkg -V's job (tier C, not built yet, see the T-file). A
# NEW FILE in that directory is nobody's job today: dpkg does not report files
# it has never heard of. So presence and disappearance are watched here, and
# the storage stays small because 467 hashes is 30 KB of JSON we would have to
# carry in the preferences table on every write.
DIR_WATCH_PRESENCE = (
    "/usr/lib/systemd/system",
)

# Per-user directories, expanded for each real home. A unit file appearing in
# here is the cheapest persistence there is.
USER_DIR_WATCH = (
    "~/.config/systemd/user",
    "~/.config/autostart",
)

# The SSH artifacts, in every real home, with their permissions recorded.
SSH_ARTIFACTS = ("authorized_keys", "known_hosts", "config")

# Caps. A list that is capped has to SAY it is capped, so the cap travels with
# the baseline and with the status.
MAX_DIR_ENTRIES = 4000
MAX_SSH_LINES = 200
MAX_FINDINGS_PER_ID_PER_PASS = 20

# Trees the sweep does not walk: backup snapshots, container images, removable
# media and kernel filesystems, where a setuid copy is not a live binary.
# /tmp and /var/tmp ARE walked: they are not nosuid here, a setuid file planted
# there really runs, and staging one there is a classic attack (LI-12).
SUID_PRUNE = (
    "/timeshift",           # timeshift snapshots, the one that bit us
    "/.snapshots",          # snapper, btrfs
    "/var/lib/snapper",
    "/snapshots",
    "/var/lib/docker",      # container images, their own filesystems
    "/var/lib/containers",
    "/mnt",                 # anything mounted by hand
    "/media",               # removable media
    "/proc",
    "/sys",
    "/run",
    "/dev",
)

# Directories every Linux host has but this user cannot enter. Listed so the
# sweep can say WHICH of its blind spots are the ordinary ones rather than
# leaving the reader to work it out from a count. Not used to suppress
# anything: an unreadable directory is reported either way.
UNREADABLE_DIRS_TYPICAL = (
    "/root",
    "/lost+found",
    "/etc/credstore",
    "/etc/credstore.encrypted",
    "/etc/polkit-1/rules.d",
    "/etc/ssl/private",
    "/boot/efi",
)

SSH_SECRET_MODE_LIMIT = 0o600


# TIER D: THE READ-ONLY HELPER, AND WHY THE SENSOR TREATS IT AS A MAYBE
#
# tools/read_helper.py is a fixed verb table of root-only read verbs, invoked
# with `sudo -n`. There is no privilege SWITCH in this module and there must
# not be one: every reader here still tries the read first, and the helper is
# only consulted when the direct read was refused. That shape matters because
# it makes the module work identically in all three states --
#
#   no helper installed        the files stay metadata-only, and the coverage
#                              block says so in the same words it always has
#   helper installed, works    the hashes appear by themselves
#   helper installed, broken   the refusal is REPORTED, per file, and never
#                              silently collapses into "unchanged"
#
# THE THIRD STATE IS THE ONE THAT BITES. A helper that is installed but
# failing (a sudoers drop-in that needs a password, a python path that does
# not exist for root) would otherwise look exactly like a machine where
# nothing changed. So the outcome of every helper call is carried on the
# record as `elevated_read`, with its own reason when it did not work.
HELPER_PATH = "/usr/local/lib/agentalsec/read_helper.py"

# The helper is tried at most once per path per pass, and this is the cache.
# Per-pass rather than per-process, because a helper that was fixed while the
# app was running should be picked up by the next pass, not by the next
# restart.
_HELPER = {"checked": False, "available": False, "reason": None,
           "verbs": {}, "cached_at": 0.0}

HELPER_CACHE_SECONDS = 60


def helper_status(force: bool = False) -> dict:
    """
    Can the read-only helper be used, and if not, exactly why.

    ONE CHEAP CALL decides it: `sudo -n <helper> --verbs`. That verb lists the
    table and reads nothing, so probing costs nothing and cannot itself leak
    anything. `-n` is the point: a helper that PROMPTS is not usable by a
    sensor -- there is nobody at the keyboard -- and a prompt that hung the
    poll loop would be a stalled sensor caused by a privilege check.

    Returns {"available": bool, "reason": str|None, "verbs": [...],
             "euid": int, "helper": path}.
    """
    now = time.monotonic()
    if (not force and _HELPER["checked"]
            and (now - _HELPER["cached_at"]) < HELPER_CACHE_SECONDS):
        return {"available": _HELPER["available"], "reason": _HELPER["reason"],
                "verbs": sorted(_HELPER["verbs"]), "euid": os.geteuid(),
                "helper": HELPER_PATH, "cached": True}

    out = {"available": False, "reason": None, "verbs": [],
           "euid": os.geteuid(), "helper": HELPER_PATH, "cached": False}

    if os.geteuid() == 0:
        # ALREADY ROOT. The helper adds nothing and calling it would be a
        # confusing extra hop; the direct reads work for everything.
        out["reason"] = ("this process is already root, so every file this "
                         "helper would read is readable directly and the "
                         "helper is not used")
        _remember_helper(out)
        return out

    if not os.path.exists(HELPER_PATH):
        out["reason"] = (
            f"{HELPER_PATH} is not installed, so /etc/sudoers, the contents "
            f"of /etc/sudoers.d and root's authorized_keys remain watched for "
            f"name, mode, owner, size and mtime only. Install it with "
            f"scripts/install_read_helper.sh; see T5_LOCAL_INTEGRITY.md for "
            f"the decision behind it.")
        _remember_helper(out)
        return out

    try:
        res = subprocess.run(["sudo", "-n", HELPER_PATH, "--verbs"],
                             capture_output=True, text=True, timeout=20)
    except FileNotFoundError:
        out["reason"] = "sudo is not installed, so the read-only helper cannot be invoked"
        _remember_helper(out)
        return out
    except subprocess.TimeoutExpired:
        out["reason"] = ("sudo -n did not return within 20s. That is the shape "
                         "of a sudoers rule that wants a password, which no "
                         "sensor can supply, and it is REPORTED rather than "
                         "retried.")
        _remember_helper(out)
        return out
    except (OSError, subprocess.SubprocessError) as e:
        out["reason"] = f"sudo could not be run: {type(e).__name__}: {e}"
        _remember_helper(out)
        return out

    if res.returncode != 0:
        detail = (res.stderr or res.stdout or "").strip().splitlines()
        # Name the file sets rather than count them (test_read_helper.py [10]).
        out["reason"] = (
            "`sudo -n " + HELPER_PATH + " --verbs` exited "
            f"{res.returncode}: {detail[-1] if detail else 'no message'}. "
            "Until this works /etc/sudoers, the contents of /etc/sudoers.d and "
            "root's authorized_keys stay metadata-only: watched for name, "
            "mode, owner, size and mtime, and NOT for content.")
        _remember_helper(out)
        return out

    try:
        parsed = json.loads(res.stdout)
    except (ValueError, TypeError) as e:
        out["reason"] = (f"the helper answered with something that is not "
                         f"JSON ({e}), so nothing it says can be trusted")
        _remember_helper(out)
        return out

    if parsed.get("ok") is not True:
        out["reason"] = (f"the helper refused: "
                         f"{parsed.get('refused') or 'no reason given'}")
        _remember_helper(out)
        return out

    out["available"] = True
    out["verbs"] = sorted((parsed.get("verbs") or {}).keys())
    _remember_helper(out)
    return out


def _remember_helper(state: dict):
    _HELPER["checked"] = True
    _HELPER["available"] = bool(state.get("available"))
    _HELPER["reason"] = state.get("reason")
    _HELPER["verbs"] = {v: True for v in (state.get("verbs") or [])}
    _HELPER["cached_at"] = time.monotonic()


def helper_forget():
    """Drop the cached verdict, so the next call probes again."""
    _HELPER["checked"] = False
    _HELPER["cached_at"] = 0.0
    _HELPER["verbs"] = {}


def helper_call(verb: str, timeout: int = 1800) -> dict:
    """
    Run one verb and return {"ok", "data", "reason"}. NEVER raises.

    A verb that fails returns ok=False with a sentence, and the callers here
    treat that as "this file was not read" rather than as "this file did not
    change". The distinction is rule two and it is the whole reason this
    function returns a dict instead of raising.
    """
    if verb not in ("sudoers", "sudoers_d", "root_ssh", "dpkg_verify",
                    "proc_exe"):
        return {"ok": False, "data": None,
                "reason": (f"{verb!r} is not one of the helper's verbs. The "
                           f"table is fixed and nothing here may ask for a "
                           f"path: a helper that takes a path is sudo cat.")}
    try:
        res = subprocess.run(["sudo", "-n", HELPER_PATH, verb],
                             capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "data": None,
                "reason": (f"the helper did not answer within {timeout}s for "
                           f"verb {verb!r}")}
    except FileNotFoundError:
        return {"ok": False, "data": None,
                "reason": "sudo is not installed"}
    except (OSError, subprocess.SubprocessError) as e:
        return {"ok": False, "data": None,
                "reason": f"{type(e).__name__}: {e}"}

    try:
        parsed = json.loads(res.stdout or "")
    except (ValueError, TypeError):
        return {"ok": False, "data": None,
                "reason": (f"the helper answered with non-JSON output (exit "
                           f"{res.returncode}): "
                           f"{(res.stderr or res.stdout or '').strip()[:200]}")}
    if parsed.get("ok") is not True:
        return {"ok": False, "data": None,
                "reason": (parsed.get("refused")
                           or f"the helper exited {res.returncode} with no reason")}
    return {"ok": True, "data": parsed, "reason": None}


def elevated_file_record(path: str, timeout: int = 60) -> dict:
    """
    One root-only file's record, read through the helper.

    RETURNS THE SAME SHAPE file_record() DOES, so the comparison code cannot
    tell the two apart and does not need to. The extra keys say where the
    record came from, which is a fact the finding carries.
    """
    if path == "/etc/sudoers":
        result = helper_call("sudoers", timeout=timeout)
        if not result["ok"]:
            return {"elevated_read": False, "elevated_reason": result["reason"]}
        entry = ((result["data"].get("entries") or {}).get(path) or {})
        rec = dict(entry.get("meta") or {})
        rec["path"] = path
        rec["readable"] = bool(entry.get("readable"))
        rec["hash"] = entry.get("sha256")
        rec["elevated_read"] = True
        rec["read_by"] = "read_helper.py via sudo -n"
        if not rec["readable"]:
            rec["unreadable_reason"] = entry.get("unreadable_reason")
        return rec
    return {"elevated_read": False,
            "elevated_reason": (f"there is no helper verb for {path!r}")}


def elevated_dir_records() -> dict:
    """
    /etc/sudoers.d through the helper: one entry per file, content hashed.

    SAME ENTRY FORMAT as dir_record(), mode:uid:gid:size:hash, so a set read
    through the helper compares against one read directly without either side
    knowing which it was.
    """
    result = helper_call("sudoers_d", timeout=120)
    out = {"elevated_read": False, "elevated_reason": result["reason"],
           "entries": {}, "blocked": False, "exists": None, "capped": False,
           "total": 0, "unreadable": [], "path": "/etc/sudoers.d"}
    if not result["ok"]:
        return out

    data = result["data"]
    meta = data.get("mode") or {}
    out["exists"] = meta.get("exists")
    out["elevated_read"] = True
    out["elevated_reason"] = None
    out["total"] = int(data.get("total") or 0)
    for name, entry in (data.get("entries") or {}).items():
        m = entry.get("meta") or {}
        if m.get("exists") is not True:
            out["unreadable"].append(f"/etc/sudoers.d/{name}: {m.get('reason')}")
            continue
        value = (f"{m.get('mode')}:{m.get('uid')}:{m.get('gid')}:"
                 f"{m.get('size')}:{entry.get('sha256') or '-'}")
        out["entries"][name] = value
        if not entry.get("readable"):
            out["unreadable"].append(
                f"/etc/sudoers.d/{name}: {entry.get('unreadable_reason')}")
    if out["total"] > MAX_DIR_ENTRIES:
        out["capped"] = True
    return out


def elevated_root_ssh() -> dict:
    """
    root's authorized_keys through the helper, with its modes and key lines.

    THE HIGHEST-VALUE FILE ON THIS MACHINE, and the one the sensor has been
    unable to see at all: /root is mode 700, so before this the module could
    not even list the directory, let alone read the key list.
    """
    result = helper_call("root_ssh", timeout=60)
    out = {"elevated_read": False, "elevated_reason": result["reason"],
           "entries": {}, "unreadable": []}
    if not result["ok"]:
        return out
    data = result["data"]
    path = data.get("path") or "/root/.ssh/authorized_keys"
    rec = dict(data.get("meta") or {})
    rec["path"] = path
    rec["readable"] = bool(data.get("readable"))
    rec["hash"] = data.get("sha256")
    rec["elevated_read"] = True
    rec["read_by"] = "read_helper.py via sudo -n"
    if not rec["readable"]:
        rec["unreadable_reason"] = data.get("unreadable_reason")
        out["unreadable"].append(f"{path}: {data.get('unreadable_reason')}")
    else:
        # The per-line map in the SAME shape collect_ssh builds, so an added
        # key to root is comparable with an added key anywhere else.
        lines = {}
        for fingerprint, info in (data.get("keys") or {}).items():
            lines[fingerprint] = (
                f"{info.get('type') or ''} {info.get('comment') or ''}".strip()
                or "unrecognised line")
        rec["lines"] = lines
        if data.get("keys_capped"):
            rec["lines_capped"] = True
    out["entries"][path] = rec
    out["elevated_read"] = True
    out["elevated_reason"] = None
    return out


# the three shims collect_watched() calls.
#
# THEY ARE THIN ON PURPOSE, and they are SHIMS rather than direct calls so the
# decision "should the helper be used at all" lives in one place. Each returns
# the "not used" shape with a reason rather than raising, because every caller
# treats a refusal as "this file was not read" -- which is the same discipline
# as the rest of this module and the reason none of them can turn into
# "unchanged" by accident.

def _helper_available() -> bool:
    """One cached probe, so a pass does not call sudo three times a minute."""
    return bool(helper_status().get("available"))


def _helper_read_file(path: str) -> dict:
    """A root-only file through the helper, or {elevated_read: False}."""
    if not _helper_available():
        return {"elevated_read": False,
                "elevated_reason": helper_status().get("reason")}
    if path == "/etc/sudoers":
        return elevated_file_record(path)
    return {"elevated_read": False,
            "elevated_reason": (f"the helper table has no verb for {path!r}. "
                                f"It reads sudoers, sudoers.d and root's "
                                f"authorized_keys, and shadow is refused by "
                                f"design.")}


def _helper_read_dir(path: str) -> dict:
    """/etc/sudoers.d through the helper, or {elevated_read: False}."""
    if not _helper_available():
        return {"elevated_read": False,
                "elevated_reason": helper_status().get("reason")}
    if path == "/etc/sudoers.d":
        return elevated_dir_records()
    return {"elevated_read": False,
            "elevated_reason": f"the helper table has no verb for {path!r}"}


def _helper_root_ssh_for_home() -> dict:
    """root's .ssh through the helper, or {elevated_read: False} with a reason."""
    if not _helper_available():
        return {"elevated_read": False,
                "elevated_reason": helper_status().get("reason")}
    return elevated_root_ssh()


def _merge_dir_records(direct: dict, elevated: dict) -> dict:
    """
    Fold a helper-read directory into the directly-read one.

    THE MERGE IS ADDITIVE AND SAYS WHICH SIDE EACH ENTRY CAME FROM. The direct
    read still runs and still contributes what it could see (the names, the
    modes, the directory's own state), and the helper contributes the content
    hashes it could reach. Overwriting wholesale would throw away the direct
    read's evidence that the directory exists and is listable, which is a fact
    a finding about it may need.
    """
    out = dict(direct)
    out["elevated_read"] = True
    out["elevated_reason"] = None
    out["entries"] = dict(direct.get("entries") or {})
    added = 0
    for name, value in (elevated.get("entries") or {}).items():
        # The elevated value carries a real hash where the direct one carried
        # "-" for a file it could list but not read. A direct entry with a real
        # hash is left alone: both are the same file, and the direct read is
        # the one that did not need privilege to get it.
        if name not in out["entries"] or out["entries"][name].endswith(":-"):
            if out["entries"].get(name) != value:
                out["entries"][name] = value
                added += 1
    out["elevated_entries_added"] = added
    # The directly-recorded unreadable list is now partly WRONG: those files
    # were read, just not by this process. What stays is what neither side
    # could read.
    still_unreadable = []
    for item in (direct.get("unreadable") or []):
        name = item.split(":", 1)[0].strip().replace("/etc/sudoers.d/", "")
        entry = out["entries"].get(name)
        if entry and not entry.endswith(":-"):
            continue
        still_unreadable.append(item)
    still_unreadable.extend(elevated.get("unreadable") or [])
    out["unreadable"] = still_unreadable
    return out


def helper_coverage_note() -> dict:
    """
    The tier D coverage sentence, for the status block.

    IT NAMES ALL THREE STATES, because the middle one is the one an operator
    will actually be in and the third is the one that silently degrades.
    """
    state = helper_status()
    covered, uncovered = [], []
    if state.get("available"):
        verbs = state.get("verbs") or []
        if "sudoers" in verbs:
            covered.append("/etc/sudoers CONTENTS")
        if "sudoers_d" in verbs:
            covered.append("/etc/sudoers.d CONTENTS")
        if "root_ssh" in verbs:
            covered.append("root's authorized_keys")
    # Always uncovered, in every state, and it is a DECISION rather than a gap.
    uncovered.append("/etc/shadow and /etc/gshadow CONTENTS, refused by design "
                     "(they hold password hashes)")
    if not state.get("available"):
        uncovered.extend(["/etc/sudoers CONTENTS", "/etc/sudoers.d CONTENTS",
                          "root's authorized_keys"])
    return {
        "available": bool(state.get("available")),
        "helper": state.get("helper"),
        "verbs": state.get("verbs") or [],
        "euid": state.get("euid"),
        "reason": state.get("reason"),
        "covered": covered,
        "uncovered": sorted(set(uncovered)),
        "note": (
            "The read-only helper is AVAILABLE, so these are read with its "
            "verbs: " + ", ".join(covered) + ". "
            if state.get("available") else
            "The read-only helper is NOT in use: " + (state.get("reason") or "")
            + " "
        ) + (
            "STILL NOT READ IN ANY STATE: " + "; ".join(sorted(set(uncovered)))
            + ". A file nobody read is not a file that did not change."
        ),
    }


# TIER C: dpkg -V
#
# MEASURED ON THIS HOST, 2026-09-22, unelevated, BEFORE ANY OF THIS WAS
# WRITTEN, and CORRECTED 2026-09-26 where a number was read off the wrong
# thing. Every number here decided something, so they are reproduced rather
# than summarised.
#
#   bare `dpkg -V`                                  ABORTS, exit 2
#   the run the owner measured (2m23s, a page)      was therefore NOT complete
#   full run, offenders named and excluded          209.1s, 55 lines
#   installed packages                              2756, one of them unusable
#   control files dpkg will refuse                  1  (one package whose
#                                                   md5sums separates with ONE
#                                                   space where dpkg wants two
#                                                   or more: 'missing value
#                                                   separator')
#
# THE CORRECTION, 2026-09-26: the line that used to stand here called that
# file "malformed ... no separator", and two other sites claimed a bare run
# "reports two files and stops" and that reinstalling repairs it. All three
# were wrong about the file. Measured: the installed control file is COMPLETE
# (846 lines, newline-terminated, every line a valid digest) and
# BYTE-IDENTICAL to the copy inside the owner's own downloaded .deb. The
# defect is the separator character, it arrived that way from the build, and
# a reinstall cannot remove it. dpkg's rule, measured variant by variant
# against a rebuilt control archive: TWO OR MORE SPACES accepted, ONE space
# refused, TAB refused. See _md5sums_ok and _dpkg_refused_text.
#
# THE ABORT IS THE FINDING THAT SHAPED THIS TIER. dpkg -V loads control files
# lazily and DIES on the first one it cannot parse, killing the verification of
# every package after it in the alphabet. So:
#
#   $ dpkg -V
#   dpkg: error: control file 'md5sums' for package 'example-app' is missing
#   value separator
#   ... exit 2. THE LINE THAT USED TO FOLLOW SAID "and two files reported",
#   which was MEASURED WRONG on 2026-09-26: a bare run today prints 42 lines
#   before dpkg reaches the bad control file and stops. The number is not the
#   point -- the point is that the lines it DOES print cover only the packages
#   sorting before the bad one, so the output looks like a complete sweep of
#   55 rows and is really a sweep of a fraction of them.
#
# A sensor that ran that and reported what it saw would say "dpkg verified
# your system and found 42 problems", which is FALSE about the ~2700 packages
# dpkg never reached. That is rule two with a package manager.
#
# SO THE SENSOR NAMES THE GOOD PACKAGES AND EXCLUDES THE BAD ONES, and the
# exclusions become a finding in their own right rather than being silently
# dropped. The cost is not hidden: it is one dpkg-query and one file read per
# control file, and it does NOT re-verify anything. What it buys is a run that
# actually completes.
#
# THREE OUTPUT CLASSES, and the third is the one that must never be read as
# clean:
#
#   ??5??????          content differs from what dpkg recorded
#   ?????????          dpkg could not read the file or the directory it is in
#   missing <path> (Permission denied)   NOT "the file is gone"
#
# THE THIRD LINE IS A LIE ABOUT THE FILE AND THE TRUTH ABOUT US, and this host
# produces it in bulk: /boot/vmlinuz-* is mode 600 root, so every kernel image
# comes back as `missing ... (Permission denied)` on an unelevated run. Reading
# that as "your kernel images have been deleted" is the worst sentence this
# sensor could produce, so `missing` splits into two claims by whether the
# reason is present: GONE is a missing file, UNREADABLE is a file we could not
# open, and only the first is an integrity finding.
#
# ONE FINDING PER PACKAGE, NOT PER FILE LINE. Measured above: 18 `?????????`
# on /boot, 22 `??5??????` across icons and .desktop files, 15 `missing` lines
# -- 55 rows about seven packages. The owner's rule is one finding per claim,
# and the claim is the package: "the package manager disagrees about files
# this package shipped". The individual paths travel in raw_data, capped, so
# the row stays readable and the evidence stays attached.
DPKG_TIMEOUT = 1200          # 20 minutes. The measured full run is 3.5.

# How long after start the first run waits. Longer than the sweep's delay on
# purpose: this one runs dpkg, which takes the dpkg lock in shared mode and
# reads 151 MB of control files, and the boot is already starting eight
# sensors. A first run an hour in is fine; a first run competing with boot is
# visible to the operator as a slow start.
FIRST_DPKG_DELAY = 300

DPKG_MIN_INTERVAL = 300      # a floor, not a default. Below this you are
                             # re-asking dpkg the same question about a machine
                             # that has not had time to change.

# /boot IS EXCLUDED BY DEFAULT. THIS IS THE OWNER'S CALL AND HERE IS WHY IT IS
# THE RIGHT ONE: kernel images and System.map files legitimately churn, they
# are unreadable anyway on an ordinary run, and they produced 18 of the 55
# measured lines. A knob rather than a hard exclusion, because on a host where
# /boot is readable and stable the check is worth having.
DPKG_EXCLUDE_BOOT = True

# The cap. The owner's requirement is that a real corruption sweep must not
# bury the dashboard: if 200 packages go bad, the dashboard gets the twenty
# that say the most and one row that says how many were not listed.
DPKG_MAX_FINDINGS_PER_RUN = 40

# A package whose control file dpkg cannot parse is not a package with bad
# files. It is a package dpkg cannot check, and the difference decides whether
# the number in the finding means anything.
DPKG_OFFENDER_FINDING_LIMIT = 20

# How many individual paths ride along inside one package's raw_data. Not a
# silence: the count of everything dpkg said is in the same dict, so a reader
# can always tell "three files" from "three of ninety".
DPKG_MAX_PATHS_PER_PACKAGE = 25

_MD5SUMS_LINE = None         # compiled on first use, see _md5sums_ok()

# TWO compiled patterns rather than one, because the two failure modes dpkg's
# loader can hit have different fixes and the reason string has to say which.
# MEASURED on this host 2026-09-26 by rebuilding a control archive under a
# scratch --admindir and running the real dpkg -V against it, one variant per
# run:
#
#   digest + 1 space          -> dpkg: error ... missing value separator, rc 2
#   digest + 2 spaces         -> accepted, rc 0
#   digest + 3 spaces         -> accepted, rc 0
#   digest + TAB              -> REFUSED, rc 2 (tab is not a space to dpkg)
#   digest + TAB + space      -> REFUSED, rc 2
#   digest + space + TAB      -> REFUSED, rc 2
#
# So dpkg's rule is SPACES, TWO OR MORE, and nothing else. The check here used
# to be 'exactly two', which is not dpkg's rule -- it is a paraphrase that
# happens to agree with every well-formed file in the archive and disagrees
# with dpkg on a file that is one space out. Paraphrasing a refusal is the
# same class of defect as paraphrasing a detection: it reads as the original
# and drifts.
_MD5SUMS_LINE_OK = None      # '^<32 hex><two or more spaces><path>'
_MD5SUMS_DIGEST = None       # '^<32 hex>' -- for naming WHAT is wrong


def _md5sums_line_problem(line: str) -> str:
    """
    What is wrong with this control-file line, in dpkg's own vocabulary.

    Returns "" when the line is well formed. The wording matters more than it
    looks: this string travels into a finding, the finding's reason travels
    into `why_stuck`, and from there into the sentence the owner reads on the
    question card. MEASURED, 2026-09-26: the previous reason cut the line at
    60 characters with NO marker, so `'87ccd9ca... usr/share/example-app/.eclip'`
    read as a file that STOPS MID-PATH -- truncated, damaged in packaging --
    and that reading was written into the question the owner was asked and
    into an operator_stated observation. The file was never truncated: it has
    846 complete lines and its last line ends in a newline. A sliced string
    with no ellipsis is a claim about the file that the file's own bytes
    contradict.
    """
    global _MD5SUMS_LINE_OK, _MD5SUMS_DIGEST
    if not line.strip():
        return ""
    if _MD5SUMS_DIGEST is None:
        import re
        _MD5SUMS_DIGEST = re.compile(r"^[0-9a-fA-F]{32}")
        _MD5SUMS_LINE_OK = re.compile(r"^[0-9a-fA-F]{32}  +\S.*$")

    if not _MD5SUMS_DIGEST.match(line):
        head = line.split(" ", 1)[0]
        return (f"the line does not start with a 32-character md5 digest "
                f"(it starts with {head[:40]!r})")
    if _MD5SUMS_LINE_OK.match(line):
        return ""
    # Digest is fine, so the separator is what dpkg will refuse. Name the
    # exact shape rather than assuming which of the two it is.
    rest = line[32:]
    if rest.startswith("\t"):
        return ("a TAB separates the digest from the path, and dpkg's "
                "separator is spaces only")
    if rest.startswith(" "):
        return ("ONE space separates the digest from the path where dpkg "
                "requires two or more")
    return (f"the digest is followed by {rest[:1]!r} instead of a space, "
            f"which dpkg does not accept as a separator")


def _md5sums_ok(path) -> tuple:
    """
    (bool, reason) -- will dpkg refuse to load this md5sums control file.

    MEASURED, and this is the whole reason the function exists. dpkg's own
    error for the one bad file on this host is:

        dpkg: error: control file 'md5sums' for package 'example-app' is
        missing value separator

    and it exits 2, having verified only the packages alphabetically before
    it. The check here is dpkg's own rule rather than a paraphrase of it --
    see the measured table above _MD5SUMS_LINE_OK for the variants and what
    dpkg did with each.

    WHAT THIS FUNCTION DOES NOT CLAIM, corrected 2026-09-26. Earlier prose
    here and in the findings said the file was 'malformed' in a way that read
    as damage, and the reason string sliced the line at 60 characters with no
    marker, which read as a truncated file. The measured truth about the one
    package in this state on this host: its md5sums file is COMPLETE (846
    lines, newline-terminated, every line a valid digest) and BYTE-IDENTICAL
    to the copy inside the vendor's own .deb, checked with cmp and md5sum.
    The defect is the SEPARATOR -- one space where dpkg wants two -- and it
    is a packaging defect in the upstream build, not damage on this machine.
    That distinction decides the fix: a reinstall cannot repair a file the
    installer wrote correctly from a correctly-built package. See
    _dpkg_refused_text.
    """
    global _MD5SUMS_LINE
    data, reason = _read_bytes(path, limit=64 * 1024 * 1024)
    if data is None:
        # AN UNREADABLE CONTROL FILE IS ALSO AN ABORT FOR DPKG, and it is a
        # DIFFERENT fact from a malformed one: the fix is permissions, not a
        # reinstall.
        return False, f"unreadable ({reason})"
    lines = data.decode("utf-8", errors="replace").splitlines()
    non_empty = [ln for ln in lines if ln.strip()]
    for n, line in enumerate(lines, 1):
        problem = _md5sums_line_problem(line)
        if not problem:
            continue
        # THE EVIDENCE IS MARKED WHEN IT IS CUT. A bare slice is how a
        # complete file came to read as a truncated one; the marker is the
        # difference between a display limit and a claim.
        shown = line if len(line) <= 60 else line[:60] + f"...[{len(line)} chars]"
        return False, (f"line {n} of {len(non_empty)}: {problem}. "
                       f"That line reads: {shown!r}")
    return True, ""


# THE LOCK FILES dpkg AND apt USE, AND WHY THERE ARE TWO. dpkg -V takes the
# package DATABASE lock (/var/lib/dpkg/lock) for the length of its read, and a
# frontend (apt, aptitude, unattended-upgrades) holds the FRONTEND lock
# (/var/lib/dpkg/lock-frontend) for the length of a whole transaction. They
# are different files with different lifetimes, and an apt transaction in
# flight holds both. MEASURED on this host 2026-09-23: both are mode 640
# root:root, so an unelevated run cannot even open them for reading, which is
# why the probe below has a THIRD answer beyond held and free.
DPKG_LOCK_PATHS = ("/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock")


def dpkg_package_for_path(path: str) -> str:
    """
    Which installed package owns this path, from dpkg's own file list.

    dpkg -V DOES NOT PRINT THE PACKAGE NAME. Its output is '<status> <path>'
    and nothing else, so a finding attributed to a package needs this lookup,
    and the lookup has to be right rather than plausible: a finding that names
    the wrong package sends the operator to the wrong upgrade.

    WALKS UP THE PATH rather than scanning the map. The map holds every path
    every package owns (about half a million entries over 2755 control files),
    so a scan per reported file would be quadratic. Walking the path's own
    parents is the depth of the path instead, and it lands on the LONGEST
    matching prefix by construction -- which is the right answer, because a
    package owns a directory and every file under it, and when two packages
    own nested directories the deeper one is the owner.
    """
    owning = _dpkg_owning_map()
    if not owning:
        return ""
    probe = path.rstrip("/")
    while True:
        hit = owning.get(probe)
        if hit:
            return hit
        if probe == "/" or not probe:
            return ""
        nxt = probe.rsplit("/", 1)[0] or "/"
        if nxt == probe:
            return ""
        probe = nxt


_DPKG_OWNERS = {"built_at": 0.0, "by_root": {}}


def _dpkg_owning_map() -> dict:
    """
    path-prefix -> package name, cached.

    Cached because a pass asks this question once per reported file and the
    map is a second of I/O. The cache is per-process and never invalidated on
    purpose: within one pass the package database does not change underneath
    us, and a pass that runs across an apt transaction would be reporting on
    two different dpkg states anyway, which is exactly what
    dpkg_verification_pass refuses to do (see its lock check).
    """
    if _DPKG_OWNERS["by_root"] and (time.monotonic() - _DPKG_OWNERS["built_at"]) < 300:
        return _DPKG_OWNERS["by_root"]

    info = Path("/var/lib/dpkg/info")
    out = {}
    try:
        listing = sorted(info.glob("*.list"))
    except OSError:
        return _DPKG_OWNERS["by_root"]
    for entry in listing:
        pkg = entry.name[:-len(".list")]
        # A multiarch package's control files are named 'name:arch.list' and
        # 'name:arch.md5sums' while dpkg's own output uses the bare name. The
        # name is kept as dpkg reports it rather than stripped, because a
        # finding that names a package must name it the way the operator's
        # 'apt install' would.
        data, reason = _read_bytes(entry, limit=8 * 1024 * 1024)
        if data is None:
            continue
        for line in data.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line == "/.":
                continue
            if line not in out:
                out[line] = pkg
    _DPKG_OWNERS["by_root"] = out
    _DPKG_OWNERS["built_at"] = time.monotonic()
    return out


def dpkg_verifiable_packages() -> dict:
    """
    Every installed package, split into what dpkg -V can and cannot verify.

    Returns {"ok": [name], "refused": {name: reason}, "installed": int,
             "seconds": float, "error": None|str}.

    THE SPLIT IS THE POINT. Naming the good packages on the command line is
    what turns an aborting 2m23s run into a completing 3.5 minute one, and the
    refused set becomes a finding of its own rather than a silent omission.
    """
    started = time.monotonic()
    out = {"ok": [], "refused": {}, "installed": 0, "error": None}
    try:
        res = subprocess.run(
            ["dpkg-query", "-W", "-f=${binary:Package}\t${db:Status-Abbrev}\n"],
            capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        out["error"] = "dpkg-query is not installed on this host"
        return out
    except (OSError, subprocess.SubprocessError) as e:
        out["error"] = f"{type(e).__name__}: {e}"
        return out

    if res.returncode != 0:
        out["error"] = (f"dpkg-query exited {res.returncode}: "
                        f"{(res.stderr or '').strip()[:200]}")
        return out

    names = []
    for line in res.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        name, status = parts[0].strip(), parts[1].strip()
        # ii = desired install, current install. Anything else (rc, iU, iF) is
        # a package dpkg considers unfinished, and verifying an unfinished
        # package reports its half-unpacked state as corruption.
        if status.startswith("ii"):
            names.append(name)
    out["installed"] = len(names)

    info = Path("/var/lib/dpkg/info")
    for name in names:
        md5sums = info / f"{name}.md5sums"
        # A package with NO md5sums file is not a broken package: dpkg only
        # checks files whose digest it recorded, and many packages ship none.
        # It is skipped from the run rather than refused, because naming it
        # would make dpkg verify nothing and the count would lie.
        if not md5sums.exists():
            continue
        ok, reason = _md5sums_ok(md5sums)
        if ok:
            out["ok"].append(name)
        else:
            out["refused"][name] = reason

    out["seconds"] = round(time.monotonic() - started, 1)
    return out


def parse_dpkg_verify(output: str, exclude_boot: bool = DPKG_EXCLUDE_BOOT) -> dict:
    """
    dpkg -V output into per-package claims. Pure function, no disk.

    Returns a dict keyed by PATH:

        {path: {"verdict": "changed"|"unreadable"|"gone", "raw": str,
                "flags": str, "conffile": bool}}

    THREE VERDICTS, AND THE THIRD SPLIT IS THE ONE THAT MATTERS.
    `missing <path> (Permission denied)` is a file dpkg could not READ, which
    is a statement about this process's privilege and not about the file. On
    this host that is every kernel image. It becomes "unreadable", never
    "gone", unless there is genuinely no reason on the line -- in which case
    the file is not there and that IS the finding.

    A LINE THAT DOES NOT PARSE IS DROPPED FROM THE DIFF AND COUNTED, in
    "unparsed", rather than being guessed at. dpkg's output format is declared
    selectable with --verify-format and the man page warns that the default
    may change; guessing at a shape we do not recognise would put a confident
    wrong sentence on a dashboard, which is the one thing this project does
    not do.
    """
    out = {"paths": {}, "unparsed": [], "lines": 0}
    if not output:
        return out

    for line in output.splitlines():
        line = line.rstrip("\n")
        if not line.strip():
            continue
        out["lines"] += 1

        # 'missing     /path (Permission denied)' -- the reason in parentheses
        # is dpkg's, and it is the difference between gone and unreadable.
        #
        # THE 'c' MARKER APPEARS ON THESE LINES TOO, and that is a defect this
        # parser had for the length of one measurement: dpkg printed
        #
        #   missing   c /etc/polkit-1/rules.d/mintcommon-unattended-meta-update.rules (Permission denied)
        #
        # on the reference host, and the first version of this branch took
        # everything after the word 'missing' as the path -- so the path came
        # out as "c /etc/polkit-1/...", which no package owns and no reader can
        # act on. ONE LINE SHAPE HANDLED IN ONE BRANCH AND NOT THE OTHER is the
        # exact class of bug this project keeps recording, so the handling is
        # now identical in both branches rather than similar.
        if line.startswith("missing"):
            rest = line[len("missing"):].strip()
            path, reason = rest, ""
            if rest.endswith(")") and "(" in rest:
                cut = rest.rfind("(")
                path, reason = rest[:cut].strip(), rest[cut + 1:-1].strip()
            conffile = False
            if path.startswith("c "):
                conffile, path = True, path[2:].strip()
            if exclude_boot and (path == "/boot" or path.startswith("/boot/")):
                continue
            verdict = "unreadable" if reason else "gone"
            out["paths"][path] = {"verdict": verdict, "raw": line,
                                  "flags": "missing", "conffile": conffile,
                                  "reason": reason or None}
            continue

        parts = line.split()
        if len(parts) < 2:
            out["unparsed"].append(line)
            continue

        flags = parts[0]
        # RPM's nine-column format: mode, digest, owner, group, size, mtime,
        # symlink, device, ... and dpkg prints 'c' between the flags and the
        # path for a CONFFILE, which is the one character that changes what
        # the row means.
        conffile = False
        path = parts[1]
        if len(parts) >= 3 and parts[1] == "c":
            conffile = True
            path = " ".join(parts[2:])
        elif len(parts) >= 3 and parts[0][0] in "?.":
            # Anything else with extra columns is not a shape we recognise.
            path = " ".join(parts[1:])

        if exclude_boot and (path == "/boot" or path.startswith("/boot/")):
            continue

        if flags == "?????????":
            # Every character unknown: dpkg could not read the file at all.
            verdict = "unreadable"
        elif flags.startswith("?"):
            # A mixture, e.g. '??5??????' -- the digest column is '5', which
            # is rpm's 'MD5 differs'. This is a real content difference and it
            # is the only class that is an integrity claim about the file.
            verdict = "changed"
        else:
            out["unparsed"].append(line)
            continue

        out["paths"][path] = {"verdict": verdict, "raw": line, "flags": flags,
                              "conffile": conffile, "reason": None}
    return out


def group_dpkg_by_package(paths: dict) -> dict:
    """
    Path-keyed verdicts into package-keyed claims, one entry per package.

    ONE FINDING PER PACKAGE, which is the owner's rule and the reason 55 lines
    become a handful of rows. A package's entry keeps its own counts and a
    capped list of paths, so "one finding" does not mean "one path's worth of
    evidence".
    """
    out = {}
    for path, info in sorted(paths.items()):
        pkg = dpkg_package_for_path(path) or "unattributed"
        entry = out.setdefault(pkg, {
            "changed": [], "unreadable": [], "gone": [], "conffiles": [],
            "counts": {"changed": 0, "unreadable": 0, "gone": 0},
        })
        verdict = info.get("verdict") or "changed"
        entry["counts"][verdict] = entry["counts"].get(verdict, 0) + 1
        if info.get("conffile"):
            entry["conffiles"].append(path)
        bucket = entry.get(verdict)
        if isinstance(bucket, list) and len(bucket) < DPKG_MAX_PATHS_PER_PACKAGE:
            bucket.append(path)
    return out


def dpkg_verification_pass(exclude_boot: bool = DPKG_EXCLUDE_BOOT,
                           packages: list = None) -> dict:
    """
    One dpkg -V run, parsed and grouped. The tier C collector.

    Returns {"ran", "reason", "seconds", "lines", "packages_claimed",
             "packages_verified", "refused", "unparsed", "aborted",
             "stderr", "by_package", "excluded_boot", "in_progress"}.

    RAN IS NOT THE SAME AS COMPLETED. A run that aborted, or that was missing
    the packages it was supposed to check, returns ran=True with an `aborted`
    or a `refused` block, because a caller that reads only `ran` would treat
    an empty result as a clean machine. Same discipline as every other reader
    here: the empty answer carries the reason it is empty.

    THE DPKG LOCK IS CHECKED FIRST. dpkg -V shares the dpkg database with any
    apt transaction in flight, and a verification that runs across an upgrade
    compares the OLD md5sums with NEW files, which reports the upgrade as
    corruption. Rather than guess, this refuses and says so; the next run
    picks it up.
    """
    started = time.monotonic()
    out = {"ran": True, "reason": None, "seconds": None, "lines": 0,
           "packages_claimed": None, "packages_verified": 0,
           "refused": {}, "unparsed": [], "aborted": False, "stderr": "",
           "by_package": {}, "excluded_boot": bool(exclude_boot),
           "in_progress": False, "paths": {}}

    lock_state, lock_why = dpkg_lock_state()
    out["lock_state"] = lock_state
    if lock_state == "held":
        out["ran"] = False
        out["reason"] = lock_why
        return out
    if lock_state == "unknown":
        # A lock question that could not be answered is RECORDED rather than
        # assumed in either direction. Proceeding is the safe direction --
        # dpkg itself refuses -- but a reader has to be able to see that this
        # particular run did not know.
        out.setdefault("notes", []).append(lock_why)

    if packages is None:
        avail = dpkg_verifiable_packages()
        if avail.get("error"):
            out["ran"] = False
            out["reason"] = f"could not enumerate packages: {avail['error']}"
            return out
        packages = avail["ok"]
        out["refused"] = avail["refused"]
        out["packages_claimed"] = avail["installed"]
        out["enumerate_seconds"] = avail.get("seconds")

    out["packages_verified"] = len(packages)
    if not packages:
        out["ran"] = False
        out["reason"] = (
            "No installed package has a control file dpkg can load, so there "
            "is nothing this check could verify. That is a statement about "
            "the package database, not about the files on this machine.")
        return out

    # THE LOCK IS CHECKED AGAIN, HERE.
    #
    # The check at the top of this function runs BEFORE the package
    # enumeration, and dpkg_verifiable_packages() reads several thousand
    # control files with the package database open -- seconds of real time on
    # this host. An apt transaction that starts inside that window is not seen
    # by the first check at all, and the verification would then compare OLD
    # md5sums against files being replaced. So the question is asked at the
    # last moment before dpkg is invoked, which is the moment that matters.
    # Both answers are reported: `lock_state` carries whichever probe answered,
    # and a run that proceeded on an UNKNOWN lock says so in `notes`.
    state, why = dpkg_lock_state()
    out["lock_state"] = state
    if state == "held":
        out["ran"] = False
        out["reason"] = why
        return out

    argv = ["dpkg", "-V"] + list(packages)
    try:
        res = subprocess.run(argv, capture_output=True, text=True,
                             timeout=DPKG_TIMEOUT)
    except subprocess.TimeoutExpired:
        out["ran"] = False
        out["aborted"] = True
        out["reason"] = (
            f"dpkg -V did not finish within {DPKG_TIMEOUT}s, so NOTHING here "
            f"says whether this machine's package files are intact. The "
            f"measured cost on this host is about 3.5 minutes for a full run; "
            f"a run this long means something else is holding the disk.")
        return out
    except FileNotFoundError:
        out["ran"] = False
        out["reason"] = "dpkg is not installed on this host"
        return out
    except (OSError, subprocess.SubprocessError) as e:
        out["ran"] = False
        out["reason"] = f"{type(e).__name__}: {e}"
        return out

    out["seconds"] = round(time.monotonic() - started, 1)
    out["stderr"] = (res.stderr or "").strip()[:500]

    if res.returncode == 2:
        # AN ABORTED RUN IS NOT A VERIFICATION. dpkg stopped partway, so the
        # packages it never reached are UNKNOWN and not clean, and the message
        # it printed names the package it choked on.
        #
        # `ran` STAYS TRUE HERE, AND THAT IS DELIBERATE. The distinction the
        # caller needs is "a run happened, so the partial output is real and
        # the baseline may move" versus "no run happened, so nothing was seen
        # and the baseline must not move". dpkg DID verify every package
        # alphabetically before the one it choked on, and throwing that away
        # would be the other half of the same defect. What marks it as
        # incomplete is `aborted`, and dpkg_coverage_findings turns that into a
        # finding that names the consequence: the rest are UNKNOWN, not clean.
        out["aborted"] = True
        out["reason"] = (
            f"dpkg -V exited 2, which is dpkg refusing to continue rather "
            f"than a report about your files: {out['stderr'][:200] or 'no message'}")
        parsed = parse_dpkg_verify(res.stdout, exclude_boot=exclude_boot)
        out.update(parsed)
        out["by_package"] = group_dpkg_by_package(parsed["paths"])
        out["packages_unknown"] = True
        return out

    parsed = parse_dpkg_verify(res.stdout, exclude_boot=exclude_boot)
    out.update(parsed)
    out["by_package"] = group_dpkg_by_package(parsed["paths"])
    out["packages_unknown"] = False
    return out


def _lock_is_held(path) -> bool:
    """
    Is this lock file held by a live process. THE LEGACY PROBE, kept because
    tests and readers use it; dpkg_lock_state() is what the pass calls.

    flock is advisory and the holder is not recorded in the file, so the test
    is the same one the kernel makes: try to take a shared lock. A file that
    cannot be locked is in use. Returns False on any refusal, because a check
    that cannot answer must not invent a reason to skip the run.

    A NOTE ON WHAT THIS CANNOT DO, MEASURED 2026-09-23 rather than reasoned
    about. It opens the file "r+b", and dpkg's own lock files are mode 640
    root:root on this host, so an unelevated caller gets PermissionError and
    this returns False for a file it never opened. It also tests FLOCK, and
    dpkg and apt take a POSIX record lock (fcntl F_SETLK, which is what
    libc's fcntl call in dpkg's own object table is for): flock and POSIX
    locks do not see each other on Linux, so a second process holding
    F_WRLCK on the same file was measured NOT to make this return True. Use
    dpkg_lock_state() when the answer has to be right.
    """
    try:
        import fcntl
        with open(path, "r+b") as fh:
            try:
                fcntl.flock(fh, fcntl.LOCK_SH | fcntl.LOCK_NB)
                fcntl.flock(fh, fcntl.LOCK_UN)
                return False
            except OSError:
                return True
    except (OSError, ImportError):
        return False


def dpkg_lock_state() -> tuple:
    """
    (state, sentence) -- is a dpkg or apt transaction in flight, and if not,
    do we actually KNOW that.

    THREE ANSWERS, NOT TWO, AND THE THIRD IS THE ONE THE FIRST VERSION OF THIS
    MODULE DID NOT HAVE. MEASURED on this host 2026-09-23:

      * /var/lib/dpkg/lock-frontend and /var/lib/dpkg/lock are mode 640
        root:root, so an unelevated caller cannot open either one -- not even
        for reading. The old probe opened "r+b", took the OSError, and
        returned "free", which is a claim it was in no position to make.
      * dpkg and apt take a POSIX record lock on those files. The old probe
        tested flock, and on Linux a flock and a POSIX lock are independent:
        a second process holding F_WRLCK on the same file was measured NOT to
        register as held.
      * /proc/locks IS READABLE by this account and records every POSIX lock
        with the device and inode of the file it is on, so the question CAN
        be answered without privilege.

    Returns "held", "free" or "unknown":
      held     a POSIX write lock on one of dpkg's lock files exists
      free     every lock file was checked and nothing holds one
      unknown  the lock files could not be stat'ed or /proc/locks could not
               be read, so nothing here says whether a transaction is running
    """
    targets = {}
    for path in DPKG_LOCK_PATHS:
        try:
            st = os.stat(path)
        except OSError as e:
            continue
        targets[(os.major(st.st_dev), os.minor(st.st_dev), st.st_ino)] = path

    if not targets:
        return "unknown", (
            "None of dpkg's lock files could be stat'ed ("
            + ", ".join(DPKG_LOCK_PATHS) + "), so this run cannot say whether "
            "an apt transaction is in flight. It proceeds, and dpkg itself "
            "refuses if one is.")

    try:
        with open("/proc/locks", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError as e:
        return "unknown", (
            f"/proc/locks could not be read ({type(e).__name__}: {e}), so "
            f"this run cannot say whether an apt transaction is in flight. "
            f"dpkg itself refuses if one is.")

    for line in lines:
        parts = line.split()
        # '1: POSIX  ADVISORY  WRITE 60022 08:02:12726139 0 EOF'
        #     [0]  [1]     [2]      [3]   [4]  [5]           [6][7]
        if len(parts) < 8 or parts[1] not in ("POSIX", "FLOCK"):
            continue
        if parts[3] not in ("WRITE", "RW"):
            continue
        # FIELD 5 IS 'major:minor:inode' WITH THE DEVICE IN HEX AND THE INODE
        # IN DECIMAL, and that asymmetry was read off a real line rather than
        # assumed: a lock this process took on a file with inode 12726483
        # printed '08:02:12726483'. Parsed field by field, and a line whose
        # numbers will not parse is SKIPPED rather than guessed at.
        dev, ino_text = parts[5].rsplit(":", 1)
        if ":" not in dev:
            continue
        major_text, minor_text = dev.split(":", 1)
        try:
            lock_dev = (int(major_text, 16), int(minor_text, 16))
            lock_ino = int(ino_text)
        except ValueError:
            continue
        for (major, minor, stat_ino), path in targets.items():
            if (lock_dev == (major, minor) and lock_ino == stat_ino):
                return "held", (
                    f"{path} is held (a {parts[1]} {parts[3]} lock by pid "
                    f"{parts[4]}). An apt or dpkg transaction is in flight, so "
                    f"a verification run now would compare this package "
                    f"database against files another process is in the middle "
                    f"of replacing and report the upgrade as corruption. "
                    f"Nothing was checked.")

    return "free", ("No lock on " + " or ".join(DPKG_LOCK_PATHS)
                    + " is held, so no apt or dpkg transaction is in flight.")


def diff_dpkg(old: dict, new: dict) -> list:
    """
    The package-manager diff, one finding per package, seeded like everything
    else.

    THIS IS WHERE THE OWNER'S "KNOWN-NORMAL ON DAY ONE" REQUIREMENT IS MET.
    The first run stores what dpkg says and raises nothing, so firefox's
    distribution.ini, the six HighContrast start-here icons and the kernel
    images are the recorded state of the machine rather than eleven findings
    the operator has to dismiss. A change LATER is a finding, which is the
    claim that is worth waking up for.

    ONE FINDING PER PACKAGE, and the severity split is by claim rather than by
    size:

      LNX-2006 high    dpkg disagrees with a file the package shipped and the
                       file could be read -- a real content difference.
                       LNX-2006 medium  the same, for a CONFFILE, because a
                       conffile is a file the package manager EXPECTS the
                       administrator to edit. /etc/cryptsetup-initramfs/
                       conf-hook measured '??5?????? c' on this host exactly
                       as shipped, and a rule that called that high would
                       teach its reader to skim.
      LNX-2005 medium  dpkg could not read the file, or the package's own
                       control file is one dpkg refuses, or files came back
                       as gone. Availability, not integrity -- and on an
                       unelevated run this is the ordinary case for /boot.
    """
    out = []
    was_pkgs = (old or {}).get("by_package") or {}
    now_pkgs = (new or {}).get("by_package") or {}

    for pkg, now in sorted(now_pkgs.items()):
        was = was_pkgs.get(pkg)
        if was is None:
            continue                    # seeding handles it, see tier_c_pass()
        now_counts = now.get("counts") or {}
        was_counts = was.get("counts") or {}

        # the readable content difference: an integrity claim
        changed_now = now_counts.get("changed", 0)
        changed_was = was_counts.get("changed", 0)
        if changed_now != changed_was or now.get("changed") != was.get("changed"):
            paths_now = now.get("changed") or []
            paths_was = set(was.get("changed") or [])
            fresh = [p for p in paths_now if p not in paths_was]
            # THE SEVERITY IS DECIDED PER PATH, NOT PER PACKAGE.
            #
            # THE DEFECT THIS FIXES, MEASURED 2026-09-23. The first version
            # asked `bool(now.get("conffiles"))` -- "does this package have ANY
            # conffile in the changed bucket" -- and used the answer for the
            # WHOLE package. `dpkg -V sudo` on this host reports ONE line, and
            # it is `/etc/sudoers`, a conffile, so the package row is medium
            # and that is right. But a package with one changed conffile and
            # one changed BINARY produced ONE row at medium carrying both, and
            # the register's own words for this id are "High when the file is
            # not a conffile -- the shape of a binary or library replaced in
            # place". So the loudest claim the rule can make was being issued
            # at the quieter severity whenever a package happened to ship a
            # conffile too. Same class as every other one of these: a fact
            # about one thing used as a fact about another.
            #
            # A path is a conffile when dpkg -V's own line carried the `c`
            # marker, which parse_dpkg_verify records per path. A path dpkg
            # reported WITHOUT that marker is a package-owned file nobody
            # should be editing, and it is high.
            conffile_paths = set(now.get("conffiles") or [])
            nonconffile_fresh = [p for p in (fresh or paths_now)
                                 if p not in conffile_paths]
            conffile = bool(now.get("conffiles")) and not nonconffile_fresh
            # A package whose paths moved out of agreement with what dpkg
            # recorded. Raised with the count of EVERYTHING dpkg said, not
            # just the paths that fit in the list.
            out.append(_finding(
                "LNX-2006", "medium" if conffile else "high", "file", pkg,
                (f"Package manager disagrees with installed files: {pkg}"
                 if not conffile else
                 f"Configuration file changed since install: {pkg}"),
                _dpkg_changed_text(pkg, changed_now, changed_was, fresh,
                                   now.get("changed") or [], conffile,
                                   nonconffile_fresh),
                {"package": pkg, "claim": "content_differs",
                 "files_changed_now": changed_now,
                 "files_changed_before": changed_was,
                 "paths": (now.get("changed") or [])[:DPKG_MAX_PATHS_PER_PACKAGE],
                 "paths_capped": max(0, changed_now - DPKG_MAX_PATHS_PER_PACKAGE),
                 "conffiles_involved": (now.get("conffiles") or [])[:10],
                 "nonconffiles_involved": nonconffile_fresh[:DPKG_MAX_PATHS_PER_PACKAGE],
                 "is_conffile": conffile,
                 "verifier": "dpkg -V (dpkg's own md5sums database)",
                 "read_by": "tools/local_integrity.py"}))

        # the unreadable and the gone: an availability claim
        unread_now = now_counts.get("unreadable", 0)
        unread_was = was_counts.get("unreadable", 0)
        gone_now = now_counts.get("gone", 0)
        gone_was = was_counts.get("gone", 0)
        if (unread_now != unread_was or gone_now != gone_was
                or now.get("unreadable") != was.get("unreadable")
                or now.get("gone") != was.get("gone")):
            out.append(_finding(
                "LNX-2005", "medium", "file", pkg,
                f"Package files dpkg could not verify: {pkg}",
                _dpkg_unreadable_text(pkg, unread_now, gone_now, now),
                {"package": pkg, "claim": "not_verifiable",
                 "files_unreadable_now": unread_now,
                 "files_unreadable_before": unread_was,
                 "files_gone_now": gone_now,
                 "files_gone_before": gone_was,
                 "paths_unreadable":
                     (now.get("unreadable") or [])[:DPKG_MAX_PATHS_PER_PACKAGE],
                 "paths_gone": (now.get("gone") or [])[:DPKG_MAX_PATHS_PER_PACKAGE],
                 "verifier": "dpkg -V (dpkg's own md5sums database)",
                 "read_by": "tools/local_integrity.py"}))

    # the packages dpkg refuses to check at all
    #
    # NOT a diff: this is a fact about the machine that was true before this
    # run and will be true until somebody fixes it, so it is raised ONCE on
    # the seed pass and not repeated. The baseline records which packages were
    # refused so a NEWLY refused package is a change worth reporting.
    refused = (new or {}).get("refused") or {}
    refused_was = (old or {}).get("refused") or {}
    for pkg in sorted(set(refused) - set(refused_was)):
        out.append(_finding(
            "LNX-2005", "medium", "file", pkg,
            f"dpkg cannot check this package at all: {pkg}",
            _dpkg_refused_text(pkg, refused[pkg], len(refused)),
            {"package": pkg, "claim": "package_unverifiable",
             "reason": refused[pkg],
             "packages_refused_total": len(refused),
             "consequence": (
                 "The files this package shipped are NOT covered by any "
                 "verification on this machine until its control file is "
                 "fixed. CORRECTED 2026-09-26: this field used to say 'a "
                 "reinstall of this package repairs it', and that is false "
                 "for the separator defect, the installed file is "
                 "byte-identical to the copy in the vendor's package, so a "
                 "reinstall writes the same bytes back. The repair is the "
                 "separator itself (one space where dpkg wants two or more), "
                 "in a root-owned file, and whether to make that edit is the "
                 "operator's call."),
             "read_by": "tools/local_integrity.py"}))
    return out


def _dpkg_changed_text(pkg, now_n, was_n, fresh, all_paths, conffile,
                       nonconffile_fresh=None) -> str:
    parts = [
        f"dpkg's own recorded digest for {now_n} file(s) shipped by {pkg} no "
        f"longer matches what is on disk"
        + (f", where the last run recorded {was_n}." if was_n != now_n else "."),
        "The digest is the one dpkg stored at unpack time, so this is the "
        "package manager disagreeing with the filesystem rather than this "
        "sensor's opinion of them.",
    ]
    if conffile:
        parts.append(
            "AT LEAST ONE OF THESE IS A CONFIGURATION FILE, which is the one "
            "class of dpkg-managed file an administrator is EXPECTED to edit. "
            "On this host /etc/cryptsetup-initramfs/conf-hook and "
            "/etc/fwupd/fwupd.conf differ from their shipped versions on a "
            "stock install. Read the file before treating this as damage.")
    else:
        parts.append(
            "A file this package shipped has been changed since it was "
            "installed. Ordinary causes: a manual edit, a file restored from "
            "a backup, or a post-install script the package itself ships. The "
            "guilty case is a system binary or library replaced in place, "
            "which is what a rootkit does and why this is high.")
    if nonconffile_fresh:
        parts.append(
            f"AT LEAST ONE OF THESE IS NOT A CONFIGURATION FILE and this row "
            f"is therefore HIGH: "
            + "; ".join(nonconffile_fresh[:DPKG_MAX_PATHS_PER_PACKAGE])
            + ". dpkg did not mark it `c`, so the package manager does not "
              "expect a person to have edited it.")
    parts.append(f"First {len(all_paths[:DPKG_MAX_PATHS_PER_PACKAGE])} path(s): "
                 + "; ".join(all_paths[:DPKG_MAX_PATHS_PER_PACKAGE])
                 + (f" (and {len(all_paths) - DPKG_MAX_PATHS_PER_PACKAGE} more)"
                    if len(all_paths) > DPKG_MAX_PATHS_PER_PACKAGE else ""))
    if fresh:
        parts.append(f"{len(fresh)} of them were not reported by the last run.")
    return " ".join(parts)


def _dpkg_unreadable_text(pkg, unread_n, gone_n, now) -> str:
    parts = [
        f"For {pkg}, dpkg could not check {unread_n} file(s)"
        + (f" and reported {gone_n} as missing" if gone_n else "")
        + ".",
        "WHY THIS IS NOT AN ALL-CLEAR FOR THOSE FILES: a file dpkg could not "
        "read is a file nobody has checked, which is a different sentence "
        "from a file that is intact.",
    ]
    if gone_n:
        parts.append(
            f"{gone_n} file(s) are actually absent. Files a package shipped "
            f"that are no longer on disk.")
    examples = (now.get("unreadable") or [])[:6]
    if examples:
        parts.append("Unreadable: " + "; ".join(examples) + ".")
        parts.append(
            "On an unelevated run the ordinary cause is ownership: on this "
            "host /boot/vmlinuz-* and /boot/System.map-* are mode 600 root, "
            "so every kernel image lands in this class. Raising the sensor's "
            "privilege (see tools/read_helper.py) moves them out of it.")
    return " ".join(parts)


def _dpkg_refused_text(pkg, reason, total) -> str:
    """
    The sentence for a package dpkg will not load, and every claim in it is
    MEASURED -- corrected 2026-09-26, because two of the claims it used to
    carry were false.

    WHAT IT SAID AND WHAT WAS TRUE. It said the file was malformed in a way
    that read as damage, and it ended with "Reinstalling the package rewrites
    its control file and restores coverage." Measured on this host against the
    vendor's own artifact: the installed control file is BYTE-IDENTICAL to the
    copy inside the owner's downloaded example-app .deb (cmp and md5sum, same
    digest), 846 complete lines, newline-terminated. Nothing was damaged on
    this machine and nothing was truncated. The build ships a separator dpkg
    does not accept, so a reinstall writes the SAME file back and the state is
    unchanged. Advice that cannot work is worse than no advice: it sends the
    owner to re-download 125 MB, and when the finding is still there
    afterwards it teaches the owner the findings are noise.

    WHAT THE FIX ACTUALLY IS, measured the same day by rebuilding a control
    archive under a scratch --admindir: dpkg's separator is TWO OR MORE
    SPACES (1 space refused, 2 accepted, 3 accepted, TAB refused). Inserting
    the missing space in the INSTALLED copy made a real `dpkg -V` run the
    package and exit 0. So the repair exists and it is local -- a one-character
    edit to the control file, or a build that fixes it upstream -- and what
    the finding can honestly do is name both and name WHICH ONE the state
    permits.

    IT DOES NOT DO THE EDIT ITSELF. The file is root-owned and lives in
    dpkg's own database directory, so changing it is the owner's call under
    this register's rule 6 (a root-owned file). The finding reports the
    measurement; the owner decides.
    """
    return (
        f"dpkg will not load this package's control file, so `dpkg -V` cannot "
        f"verify a single file it shipped. dpkg's own words for this class "
        f"are 'missing value separator' in the md5sums file; this run's "
        f"reading of it is: {reason}. "
        f"THIS MATTERS PAST THE ONE PACKAGE: dpkg -V aborts on the first "
        f"control file it cannot parse and exits 2, having verified only the "
        f"packages that sort before it. That is why the sensor names the good "
        f"packages on the command line instead of running dpkg blind, a "
        f"bare `dpkg -V` on this host stops at this package and never reaches "
        f"the ones after it. "
        f"{total} package(s) are in this state. "
        f"WHAT ACTUALLY REPAIRS IT, measured rather than assumed: the "
        f"separator dpkg wants is two or more spaces, and one space in the "
        f"installed copy is the whole defect (inserting it made a real run "
        f"verify this package and exit 0). This file is root-owned, in dpkg's "
        f"own database, so the edit is the operator's to make, a reinstall "
        f"is NOT the fix here, and it is not advice this finding gives: the "
        f"installed file is byte-identical to the copy inside the vendor's "
        f"own package, so downloading it again writes the same bytes back.")


def dpkg_coverage_findings(result: dict) -> list:
    """
    What the run could not see, as a finding rather than a footnote.

    THE WHOLE POINT: an unelevated run reports every kernel image unreadable
    and a bare run ABORTS. Both produce a short, tidy output that reads
    exactly like a machine with nothing wrong, and the only thing that
    separates them is a sentence saying so.
    """
    out = []
    if result.get("aborted"):
        out.append(_finding(
            "LNX-2005", "medium", "file", "dpkg-verification",
            "The package verification did not complete",
            (f"dpkg -V refused to continue: {result.get('stderr') or 'no message'}. "
             f"A run that stops partway has verified the packages it reached "
             f"and NOTHING can be said about the rest, they are unknown, not "
             f"clean. {result.get('packages_verified')} package(s) were named "
             f"on the command line; the output below may cover fewer. This run "
             f"still names the good packages and excludes the ones dpkg "
             f"refuses, so reaching this message means dpkg failed for a "
             f"reason the exclusion list did not predict."),
            {"stderr": result.get("stderr"), "seconds": result.get("seconds"),
             "packages_named": result.get("packages_verified"),
             "packages_claimed": result.get("packages_claimed"),
             "read_by": "tools/local_integrity.py"}))

    unparsed = result.get("unparsed") or []
    if unparsed:
        out.append(_finding(
            "LNX-2005", "medium", "file", "dpkg-output",
            "Some dpkg output lines were not understood",
            (f"{len(unparsed)} line(s) of dpkg -V output did not match any "
             f"shape this parser knows, so they were NOT counted either way. "
             f"They are not clean results and they are not findings: they are "
             f"lines nobody has read. dpkg's output format is selectable "
             f"(--verify-format) and its man page says the default may change. "
             f"Shapes seen: " + "; ".join(unparsed[:5])),
            {"lines": unparsed[:10], "line_count": len(unparsed),
             "total_lines": result.get("lines"),
             "read_by": "tools/local_integrity.py"}))
    return out


def cap_dpkg_findings(findings: list, cap: int = DPKG_MAX_FINDINGS_PER_RUN) -> list:
    """
    Cap a run, and SAY what was cut. The owner's requirement, kept.

    A corruption sweep that goes wrong produces one row per package, and two
    hundred rows is how the one that mattered goes under the fold. The order
    is preserved -- the caller sorts integrity before availability -- so what
    survives the cap is the loudest half, and the summary row carries the
    count that did not fit.
    """
    if len(findings) <= cap:
        return findings
    kept = list(findings[:cap])
    cut = len(findings) - cap
    counts = {}
    for f in findings:
        counts[f["detection_id"]] = counts.get(f["detection_id"], 0) + 1
    kept.append(_finding(
        "LNX-2006", "medium", "file", "dpkg-pass-cap",
        f"dpkg verification: {cut} further finding(s) in this run not listed",
        (f"This run produced {len(findings)} findings and only the first "
         f"{cap} are listed. The rest are real and were not written: this cap "
         f"exists so a verification run that goes wrong cannot bury the "
         f"dashboard, and it is stated here rather than being silently "
         f"applied. Per detection id: "
         + ", ".join(f"{k} x{v}" for k, v in sorted(counts.items()))),
        {"produced": len(findings), "listed": cap, "cut": cut,
         "by_detection_id": counts,
         "read_by": "tools/local_integrity.py"}))
    return kept


def compact_dpkg(result: dict) -> dict:
    """
    The storable form of one dpkg run.

    COMPACTED BECAUSE THE STORED BASELINE IS COMPARED, NOT JUST COUNTED. The
    paths per package are what make a later run able to say WHICH file moved,
    and they are capped so a package with four thousand reported files cannot
    grow the table without limit. The counts stay whole, so the cap never
    makes the number wrong.
    """
    by_package = {}
    for pkg, entry in (result.get("by_package") or {}).items():
        by_package[pkg] = {
            "counts": entry.get("counts") or {},
            "changed": (entry.get("changed") or [])[:DPKG_MAX_PATHS_PER_PACKAGE],
            "unreadable": (entry.get("unreadable") or [])[:DPKG_MAX_PATHS_PER_PACKAGE],
            "gone": (entry.get("gone") or [])[:DPKG_MAX_PATHS_PER_PACKAGE],
            "conffiles": (entry.get("conffiles") or [])[:DPKG_MAX_PATHS_PER_PACKAGE],
        }
    return {
        "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "by_package": by_package,
        "refused": dict(result.get("refused") or {}),
        "packages_verified": result.get("packages_verified"),
        "packages_claimed": result.get("packages_claimed"),
        "excluded_boot": bool(result.get("excluded_boot")),
        "seconds": result.get("seconds"),
    }


def tier_c_pass(exclude_boot: bool = DPKG_EXCLUDE_BOOT) -> dict:
    """
    One dpkg verification, compared against the stored set and reseeded.

    THE FIRST RUN SEEDS. This is the owner's requirement in the owner's own words: the
    baseline is seeded from the first run so the firefox icons and the kernel
    images are known-normal rather than a page of findings on day one. It is
    the same rule tier A and tier B already follow, and it is the reason this
    module can be switched on for an existing machine at all.

    Returns {"ran", "reason", "seeded", "reseeded", "findings", "coverage",
             "counts", "seconds", "refused_count", "packages_verified"}.
    """
    result = dpkg_verification_pass(exclude_boot=exclude_boot)
    out = {"ran": bool(result.get("ran")), "reason": result.get("reason"),
           "seeded": False, "reseeded": False, "findings": [],
           "seconds": result.get("seconds"),
           "counts": {"packages": result.get("by_package") and
                      len(result.get("by_package")) or 0,
                      "packages_verified": result.get("packages_verified"),
                      "refused": len(result.get("refused") or {}),
                      "lines": result.get("lines")},
           "refused_count": len(result.get("refused") or {}),
           "packages_verified": result.get("packages_verified"),
           "coverage": dpkg_coverage_block(result),
           "aborted": bool(result.get("aborted")),
           "excluded_boot": bool(result.get("excluded_boot"))}

    if not out["ran"]:
        # NOT SEEDED, NOT RESEEDED, AND NOTHING RAISED. A run that did not
        # happen must not move the baseline: reseeding on a failed run would
        # silently adopt whatever changed while the sensor was not looking.
        return out

    current = compact_dpkg(result)
    stored = load_baseline("dpkg")

    if stored is None:
        save_baseline("dpkg", current)
        out["seeded"] = True
        # THE ONE THING THAT RAISES ON A SEED PASS, and it is not really an
        # exception: a package dpkg CANNOT CHECK is a hole in coverage that
        # exists right now, and seeding it would mean the operator is never
        # told that 2755 of the owner's 2756 packages are covered. It is raised once
        # and the baseline records it, so it does not repeat.
        out["findings"].extend(dpkg_refused_seed_findings(result))
        out["findings"].extend(dpkg_coverage_findings(result))
        out["findings"] = cap_dpkg_findings(out["findings"])
        return out

    changes = diff_dpkg(stored, current)
    if changes or (result.get("refused") or {}) != (stored.get("refused") or {}):
        save_baseline("dpkg", current)
        out["reseeded"] = True
        out["findings"].extend(changes)

    # Coverage last, and always. What this run could not see is a fact about
    # EVERY run, not about the runs that happened to find something.
    out["findings"].extend(dpkg_coverage_findings(result))

    # Integrity claims first, so a cap keeps the loudest half.
    out["findings"].sort(key=lambda f: (0 if f["detection_id"] == "LNX-2006" else 1,
                                        f.get("entity_value") or ""))
    out["findings"] = cap_dpkg_findings(out["findings"])
    return out


def dpkg_refused_seed_findings(result: dict) -> list:
    """
    Packages dpkg refuses, raised on the SEED pass because they are a hole in
    coverage rather than a change.

    THE ARGUMENT FOR RAISING ON A FIRST PASS, since every other rule here
    seeds silently: seeding says "this is the state of the machine, remember
    it". For a package dpkg cannot load, remembering it quietly means the
    dashboard shows a green package verification over a machine where one
    package was never checked and a BARE dpkg run would have aborted at it.
    The operator cannot dismiss what the owner is never told. Capped, and the count
    travels, so 200 of them is one page rather than 200.
    """
    refused = (result.get("refused") or {})
    out = []
    for pkg, reason in sorted(refused.items())[:DPKG_OFFENDER_FINDING_LIMIT]:
        out.append(_finding(
            "LNX-2005", "medium", "file", pkg,
            f"dpkg cannot verify this package: {pkg}",
            _dpkg_refused_text(pkg, reason, len(refused)),
            {"package": pkg, "claim": "package_unverifiable",
             "reason": reason, "packages_refused_total": len(refused),
             "on_seed_pass": True,
             "read_by": "tools/local_integrity.py"}))
    if len(refused) > DPKG_OFFENDER_FINDING_LIMIT:
        out.append(_finding(
            "LNX-2005", "medium", "file", "dpkg-refused-packages",
            f"{len(refused) - DPKG_OFFENDER_FINDING_LIMIT} more packages dpkg cannot verify",
            (f"{len(refused)} installed package(s) have a control file dpkg "
             f"will not load. The first {DPKG_OFFENDER_FINDING_LIMIT} are "
             f"listed separately; the rest are counted here rather than "
             f"written out, so a package database in a bad state produces one "
             f"page rather than a wall. Every one of them means the files that "
             f"package shipped are outside all verification on this machine."),
            {"refused_total": len(refused),
             "listed": DPKG_OFFENDER_FINDING_LIMIT,
             "packages": sorted(refused)[:100],
             "read_by": "tools/local_integrity.py"}))
    return out


def dpkg_coverage_block(result: dict) -> dict:
    """
    What this run could and could not examine, for the status block.

    Same discipline as coverage_block() for tier A: the numbers a reader needs
    to tell "nothing changed" from "nothing was looked at".
    """
    counts = {"changed": 0, "unreadable": 0, "gone": 0}
    for entry in (result.get("by_package") or {}).values():
        for k, v in (entry.get("counts") or {}).items():
            counts[k] = counts.get(k, 0) + v
    return {
        "packages_verified": result.get("packages_verified"),
        "packages_claimed": result.get("packages_claimed"),
        "packages_refused": len(result.get("refused") or {}),
        "files_changed": counts.get("changed", 0),
        "files_unreadable": counts.get("unreadable", 0),
        "files_gone": counts.get("gone", 0),
        "lines": result.get("lines"),
        "unparsed_lines": len(result.get("unparsed") or []),
        "excluded_boot": bool(result.get("excluded_boot")),
        "aborted": bool(result.get("aborted")),
        "note": (
            "packages_verified is how many packages were named on the dpkg "
            "command line this run: a package dpkg refuses to load is NOT in "
            "it, and neither is a package that ships no md5sums. "
            "files_unreadable counts files dpkg could not open, on an "
            "unelevated run that is every /boot kernel image, and it is a "
            "statement about this process's privilege, NOT about the files. "
            "A file in that count has NOT been checked."
            + (" /boot is currently EXCLUDED by config, so the count above "
               "has no /boot rows in it at all."
               if result.get("excluded_boot") else "")
        ),
    }


def dpkg_status_block() -> dict:
    """What the dpkg tier can say about itself, without running dpkg."""
    out = {"command": "dpkg -V <the packages it can load>",
           "cost_note": (
               "MEASURED on this host 2026-09-22: a bare `dpkg -V` ABORTS "
               "with exit 2 on one control file whose separator dpkg will not "
               "accept, having verified only the packages sorting before it "
               "(CORRECTED 2026-09-26: this used to read 'one MALFORMED "
               "control file' and the file is not malformed, it is complete "
               "and byte-identical to the vendor's own copy; the defect is "
               "the separator character). A full run with the "
               "unloadable packages excluded took 209s over 2755 packages and "
               "printed 55 lines.")}
    from core import memory_engine as me
    try:
        with me._get_conn() as conn:
            row = conn.execute(
                f"SELECT value_json, recorded_at FROM {BASELINE_TABLE} "
                f"WHERE name = 'dpkg'").fetchone()
    except Exception as e:
        out["error"] = f"the dpkg baseline could not be read: {e}"
        return out
    if row is None:
        out["seeded"] = False
        out["note"] = ("This tier has never completed a run, so it has no "
                       "baseline and NO diff is being computed. It also means "
                       "nothing here says whether your package files are "
                       "intact.")
        return out
    try:
        stored = json.loads(row["value_json"])
    except (ValueError, TypeError) as e:
        out["error"] = f"the dpkg baseline could not be parsed: {e}"
        return out
    out["seeded"] = True
    out["baseline_at"] = stored.get("at")
    out["recorded_at"] = row["recorded_at"]
    out["packages_verified"] = stored.get("packages_verified")
    out["packages_claimed"] = stored.get("packages_claimed")
    out["packages_refused"] = len(stored.get("refused") or {})
    out["packages_with_findings"] = len(stored.get("by_package") or {})
    out["excluded_boot"] = stored.get("excluded_boot")
    out["baseline_seconds"] = stored.get("seconds")
    return out


# SMALL SHARED HELPERS

def _hash16(data: bytes) -> str:
    """
    16 hex characters of sha256, for a stored comparison value.

    Truncated on purpose and the reason is worth one line: this hash is only
    ever compared against the value WE recorded for the same path, so its job
    is to notice that a file moved, not to be a cryptographic commitment to
    its contents. tools/linux_monitor._sha truncates at the same width for the
    same class of comparison.
    """
    return hashlib.sha256(data).hexdigest()[:16]


def _octal(mode: int) -> str:
    """Permission bits as three octal digits, which is how people read them."""
    return format(stat.S_IMODE(mode), "03o")


def _read_bytes(path, limit: int = 4 * 1024 * 1024):
    """
    (bytes, None) or (None, reason). NEVER raises, and never returns empty on
    a failure, because an empty read would hash the same as an empty file.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit + 1)
    except FileNotFoundError:
        return None, "gone"
    except PermissionError:
        return None, "permission denied"
    except OSError as e:
        return None, f"{type(e).__name__}: {e}"
    if len(data) > limit:
        return None, f"larger than {limit} bytes, not read"
    return data, None


def stat_record(path) -> dict:
    """
    What a stat says about one path, or why there is nothing to say.

    Returns a dict with exists, reason, mode, uid, gid, size, mtime_ns
    and type.

    A path that does not exist is NOT an error: on this watch set "absent" is
    a real state, and for /etc/ld.so.preload it is the expected one.
    """
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return {"exists": False, "reason": None}
    except PermissionError:
        return {"exists": None, "reason": "permission denied"}
    except OSError as e:
        return {"exists": None, "reason": f"{type(e).__name__}: {e}"}
    return {
        "exists": True,
        "reason": None,
        "mode": _octal(st.st_mode),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        # ctime: THE ONE FIELD utime() CANNOT PUT BACK, and the reason it is
        # here at all. MEASURED ON THIS HOST, 2026-09-22:
        #
        #   an edit that keeps the file's LENGTH and then calls utime() with
        #   the old mtime restores size, mtime, mode and owner EXACTLY. Every
        #   field the metadata watch had would agree, and a line added to
        #   /etc/sudoers by an unprivileged process would have been invisible.
        #   ctime moved, because the kernel stamps it on every inode change
        #   and only root can hand it back (CAP_SYS_ADMIN or a clock reset).
        #
        # AND IT CANNOT BE A FINDING ON ITS OWN. Also measured: a plain
        # chmod, a plain utime() with unchanged values, and an ordinary package
        # upgrade ALL move ctime. On this host that is sudoers moving ctime on
        # every apt run, which is a finding per upgrade and how a module
        # teaches its reader to skim it.
        #
        # So it is recorded RAW and the COMPARISON decides, in _ctime_only_move:
        # ctime moved while size, mtime, mode and owner all agree is the
        # stealth case, and that is the only time it is reported.
        "ctime_ns": st.st_ctime_ns,
        # The inode. A file REPLACED rather than edited (dpkg does this with a
        # rename) gets a new one, and a new inode with an old mtime is not a
        # write, it is a substitution.
        "ino": st.st_ino,
        "type": ("dir" if stat.S_ISDIR(st.st_mode) else
                 "link" if stat.S_ISLNK(st.st_mode) else
                 "file" if stat.S_ISREG(st.st_mode) else "other"),
    }


def file_record(path, read_content: bool = True) -> dict:
    """
    One file's record for the baseline, content included when it can be read.

    THE SHAPE IS THE HONESTY. `readable` says whether the content was actually
    read this pass. `hash` is None when it was not, and a comparison against a
    None hash is reported as a coverage question rather than as "unchanged".
    """
    rec = stat_record(path)
    rec["path"] = str(path)
    rec["readable"] = False
    rec["hash"] = None

    if rec.get("exists") is not True:
        return rec
    if rec.get("type") != "file":
        # A directory or a symlink where a file was expected is itself worth
        # knowing, and it is reported by the comparison rather than here.
        return rec

    if read_content:
        data, reason = _read_bytes(path)
        if data is None:
            rec["unreadable_reason"] = reason
            return rec
        rec["hash"] = _hash16(data)
        rec["readable"] = True
    else:
        # Metadata-only by design. Named so a reader cannot mistake the
        # absence of a hash for a failed read.
        rec["unreadable_reason"] = "not read by design (metadata only)"
    return rec


def dir_record(path, hashed: bool = True) -> dict:
    """
    Every file inside one directory, one entry each, hashed where readable.

    PER FILE, NOT ONE HASH OF THE DIRECTORY. A digest over the directory tells
    you that something moved and never which thing, and the whole point of
    watching /etc/sudoers.d or /etc/pam.d is to be able to say WHICH file.

    AN UNREADABLE DIRECTORY IS NOT THE SAME AS A DIRECTORY THAT IS NOT THERE,
    and the difference is the whole reason `blocked` exists. /etc/sudoers.d
    IS there on this host and every file in it is root-only: reporting that as
    exists=false would collapse "you cannot read this" into "this is not a
    thing", and the coverage block would then have nothing to name.
    """
    out = {
        "path": str(path),
        "exists": _is_dir(path),
        "blocked": False,
        "entries": {},
        "unreadable": [],
        "capped": False,
        "total": 0,
    }
    if not out["exists"]:
        return out

    base = Path(path)
    # A DIRECTORY WHOSE CONTENTS CANNOT BE LISTED IS 'blocked', NOT ABSENT.
    # os.access is the cheap test for "could I read this directory", and it
    # answers the question this needs answered: is the empty entry list below
    # a statement about the directory or about our privilege.
    try:
        out["blocked"] = not os.access(path, os.R_OK | os.X_OK)
    except OSError:
        out["blocked"] = True

    try:
        listing = sorted(p for p in base.rglob("*") if p.is_file())
    except (PermissionError, OSError) as e:
        out["blocked"] = True
        out["unreadable"].append(f"{path}: {type(e).__name__}: {e}")
        return out

    out["total"] = len(listing)
    for entry in listing[:MAX_DIR_ENTRIES]:
        rel = str(entry.relative_to(base))
        st = stat_record(entry)
        if st.get("exists") is not True:
            out["unreadable"].append(f"{entry}: {st.get('reason')}")
            continue
        value = f"{st['mode']}:{st['uid']}:{st['gid']}:{st['size']}"
        if hashed:
            data, reason = _read_bytes(entry)
            if data is None:
                out["unreadable"].append(f"{entry}: {reason}")
                value += ":-"
            else:
                value += ":" + _hash16(data)
        else:
            value += ":-"
        out["entries"][rel] = value

    if out["total"] > MAX_DIR_ENTRIES:
        out["capped"] = True
    return out


def _is_dir(path) -> bool:
    """
    True/false/False-on-refusal directory test.

    WHY NOT Path.is_dir(). FOUND BY THIS MODULE'S OWN TRIP TEST, 2026-09-22,
    on the first run: `Path('/root/.ssh').is_dir()` RAISES PermissionError
    when the parent directory cannot be traversed, and /root is mode 700, so
    the very first pass died on it. os.path.isdir swallows the OSError and
    answers False, which is the right answer here: "I cannot see it" and "it
    is not there" both mean there are no key files to read, and the reason is
    recorded elsewhere by the home's own stat. A module that crashes on the
    operator's own filesystem because a root-only directory exists is a module
    that never runs at all.
    """
    try:
        return os.path.isdir(path)
    except OSError:
        return False


def _homes() -> list:
    """
    Every real home directory on this host, from /etc/passwd.

    /root IS INCLUDED AND WILL USUALLY BE UNREADABLE, which is the honest
    answer rather than an omission: root's authorized_keys is one of the
    highest-value files on the machine and reporting that we cannot see it is
    the entire point. Homes that do not exist are dropped; homes that exist and
    cannot be entered are kept and reported.
    """
    import pwd
    homes = []
    try:
        entries = sorted(pwd.getpwall(), key=lambda p: p.pw_uid)
    except Exception as e:                      # pragma: no cover
        logger.warning(f"local_integrity: could not read /etc/passwd: {e}")
        return homes
    for entry in entries:
        home = (entry.pw_dir or "").strip()
        if not home or home == "/":
            continue
        if not (home.startswith("/home/") or home == "/root"):
            continue
        if not os.path.isdir(home):
            continue
        if home in [h["home"] for h in homes]:
            continue
        homes.append({"user": entry.pw_name, "home": home})
    return homes


def collect_ssh() -> dict:
    """
    authorized_keys, known_hosts and config in every real home.

    PERMISSIONS AND OWNERSHIP ARE PART OF THE RECORD, not decoration. A key
    file that is world-writable is a key file anybody can add a key to, and a
    hash of its contents would not say so.
    """
    out = {"homes": [], "entries": {}, "unreadable": []}
    for home in _homes():
        sshdir = Path(home["home"]) / ".ssh"
        out["homes"].append({"user": home["user"], "home": home["home"],
                             "ssh_dir_exists": _is_dir(sshdir)})
        # TIER D: /root's .ssh CANNOT BE LISTED AT ALL UNELEVATED.
        #
        # `_is_dir('/root/.ssh')` answers False for the same reason it answers
        # False for a directory that is not there: /root is mode 700 and this
        # process cannot traverse it. Before tier D the loop below therefore
        # `continue`d and root's key file was not in the baseline in any form
        # -- not unreadable, absent. Reporting a file as absent when it is
        # merely unseeable is the defect this project has a name for.
        #
        # So when the helper can read it, the record is built from the helper
        # and the loop below is skipped for this home. When the helper cannot,
        # the home is recorded as not enterable, in words, rather than being
        # dropped silently.
        if home["home"] == "/root" and not _is_dir(sshdir):
            elevated = _helper_root_ssh_for_home()
            if elevated.get("elevated_read"):
                out["entries"].update(elevated["entries"])
                out["unreadable"].extend(elevated["unreadable"])
                out["homes"][-1]["ssh_dir_exists"] = True
                out["homes"][-1]["read_by"] = "read_helper.py via sudo -n"
            else:
                out["homes"][-1]["cannot_enter"] = (
                    "permission denied: /root is mode 700 and the read-only "
                    "helper is not in use, so root's authorized_keys is NOT "
                    "watched at all, not even its metadata."
                    + (f" ({elevated.get('elevated_reason')})"
                       if elevated.get("elevated_reason") else ""))
            continue
        if not _is_dir(sshdir):
            continue

        dir_stat = stat_record(sshdir)
        out["entries"][str(sshdir)] = (
            f"{dir_stat.get('mode')}:{dir_stat.get('uid')}:{dir_stat.get('gid')}"
            if dir_stat.get("exists") is True else "unstatable")

        for name in SSH_ARTIFACTS:
            path = sshdir / name
            rec = file_record(path)
            out["entries"][str(path)] = rec
            if not rec.get("readable"):
                continue
            # Per-line fingerprints, so an added key can be named rather than
            # only counted. authorized_keys also gets its type and comment,
            # because "which key" is the question a person actually has.
            #
            # EVERY FILE GETS A LABEL, AND THAT IS A FIX. MEASURED 2026-09-23:
            # the label was built only for authorized_keys, so every
            # known_hosts line was stored as the literal string "unrecognised
            # line" -- the live baseline on this host holds two of them. A
            # finding about known_hosts then said "A line that was not there
            # at the last pass: unrecognised line", which names nothing and
            # cannot be acted on. The label is now built from the file's own
            # first fields, which for known_hosts is the key type and the
            # host, and for config is the directive.
            lines = {}
            raw, reason = _read_bytes(path)
            if raw is None:
                out["unreadable"].append(f"{path}: {reason}")
                continue
            for line in raw.decode("utf-8", errors="replace").splitlines():
                text = line.strip()
                if not text or text.startswith("#"):
                    continue
                if len(lines) >= MAX_SSH_LINES:
                    break
                parts = text.split()
                if name == "authorized_keys":
                    label = " ".join(parts[:2])
                    comment = " ".join(parts[2:])[:80]
                elif name == "known_hosts":
                    # 'type host' -- the key type and the host it is for. The
                    # host may be hashed (|1|...|...), which is still the
                    # thing that tells two lines apart.
                    label = " ".join(parts[:2])
                    comment = ""
                else:                       # config
                    label = " ".join(parts[:2])[:80]
                    comment = ""
                lines[_hash16(text.encode())] = (f"{label} {comment}".strip()
                                                 or "unrecognised line")
            rec["lines"] = lines
    return out


def collect_mac_posture() -> dict:
    """
    Is a mandatory access control system actually enforcing.

    "WE ARE PROTECTED" IS A CLAIM, so it gets checked rather than assumed. On
    this host AppArmor is compiled in and loaded; the profile set needs root to
    read, and that is reported as a limit rather than as an absence.

    SELinux is checked for the same reason: on a host that uses it, a change
    from Enforcing to Permissive is a finding, and reading the mode needs no
    privilege at all.
    """
    out = {"apparmor": {}, "selinux": {}}

    try:
        with open("/sys/module/apparmor/parameters/enabled", encoding="utf-8") as fh:
            enabled = fh.read().strip()
        out["apparmor"] = {"present": True, "kernel_enabled": enabled}
    except OSError as e:
        out["apparmor"] = {"present": False, "reason": f"{type(e).__name__}: {e}"}

    # The profile set needs root. Distinguish "the tool is missing" from "the
    # tool is there and refused us", because they are different fixes.
    import shutil
    import subprocess
    tool = shutil.which("aa-status")
    if tool:
        try:
            res = subprocess.run([tool, "--enabled"], capture_output=True,
                                 text=True, timeout=10)
            out["apparmor"]["profiles"] = res.stdout.strip()[:200]
            out["apparmor"]["profiles_readable"] = (res.returncode == 0)
            if res.returncode != 0:
                out["apparmor"]["profiles_reason"] = (
                    (res.stderr or res.stdout or "").strip()[:200]
                    or f"exit {res.returncode}")
        except (OSError, subprocess.SubprocessError) as e:
            out["apparmor"]["profiles_readable"] = False
            out["apparmor"]["profiles_reason"] = f"{type(e).__name__}: {e}"
    else:
        out["apparmor"]["profiles_readable"] = False
        out["apparmor"]["profiles_reason"] = "aa-status is not installed"

    try:
        with open("/sys/fs/selinux/enforce", encoding="utf-8") as fh:
            mode = fh.read().strip()
        out["selinux"] = {"present": True,
                          "mode": "enforcing" if mode == "1" else "permissive"}
    except OSError as e:
        out["selinux"] = {"present": False, "reason": f"{type(e).__name__}: {e}"}

    return out


def collect_watched(state_dir_records: bool = True) -> dict:
    """
    One tier A picture: every watched file, every directory set, every home.

    Nothing here raises. Every failure is recorded against the path it
    happened to, because a reader has to be able to tell "no change" from "no
    look" for each individual file.
    """
    out = {"files": {}, "dirs": {}, "user_dirs": {}, "ssh": {},
           "unreadable": [], "at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}

    for path in WATCHED_FILES:
        out["files"][path] = file_record(path, read_content=True)
        if out["files"][path].get("exists") is None:
            out["unreadable"].append(f"{path}: {out['files'][path]['reason']}")

    for path in METADATA_ONLY_FILES:
        rec = file_record(path, read_content=False)
        # TIER D: THE ROOT-ONLY SET, WHEN THE HELPER CAN REACH IT.
        #
        # THE DIRECT READ COMES FIRST AND DECIDES. Only when it did not work
        # is the helper consulted, so an unelevated run with no helper
        # installed behaves EXACTLY as it did before this code existed -- same
        # record, same coverage block, same findings. That is deliberate: a
        # privilege feature that changes the unelevated path is a feature that
        # changes every existing finding.
        #
        # /etc/shadow IS IN METADATA_ONLY_FILES AND IS NEVER SENT TO THE
        # HELPER. It has no verb, on purpose. Its size, mode and mtime are
        # what catches an account being added, and its contents have no
        # business in this database.
        if not rec.get("readable") and path != "/etc/shadow" and path != "/etc/gshadow":
            elevated = _helper_read_file(path)
            if elevated.get("readable") is True:
                rec = dict(rec)
                rec.update({k: v for k, v in elevated.items()
                            if k in ("hash", "size", "mtime_ns", "ctime_ns",
                                     "ino", "mode", "uid", "gid", "readable")})
                rec["readable"] = True
                rec["elevated_read"] = True
                rec["read_by"] = "read_helper.py via sudo -n"
                # The reason it was metadata-only before is now WRONG and is
                # removed rather than left sitting on a record that has a hash.
                rec.pop("unreadable_reason", None)
            elif elevated.get("elevated_reason"):
                rec = dict(rec)
                rec["elevated_read"] = False
                rec["elevated_reason"] = elevated["elevated_reason"]
        out["files"][path] = rec
        if out["files"][path].get("exists") is None:
            out["unreadable"].append(f"{path}: {out['files'][path]['reason']}")

    for path in DIR_WATCH_HASHED:
        rec = dir_record(path, hashed=True)
        # The sudoers drop-in directory is the one directory set whose
        # CONTENTS are root-only. Same rule as above: the direct read decides,
        # and the helper only fills in what the direct read could not.
        if path == "/etc/sudoers.d" and rec.get("unreadable"):
            elevated = _helper_read_dir(path)
            if elevated.get("elevated_read"):
                rec = _merge_dir_records(rec, elevated)
        out["dirs"][path] = rec
        out["unreadable"].extend(rec["unreadable"])

    for path in DIR_WATCH_PRESENCE:
        rec = dir_record(path, hashed=False)
        out["dirs"][path] = rec
        out["unreadable"].extend(rec["unreadable"])

    for home in _homes():
        for template in USER_DIR_WATCH:
            path = Path(home["home"]) / template.replace("~/", "")
            rec = dir_record(path, hashed=True)
            out["user_dirs"][str(path)] = rec
            out["unreadable"].extend(rec["unreadable"])

    if state_dir_records:
        out["ssh"] = collect_ssh()
        out["unreadable"].extend(out["ssh"]["unreadable"])

    return out


# TIER B: THE SWEEP

def sweep_filesystem() -> dict:
    """
    Walk the filesystem once and return setuid, setgid and capabilities.

    Returns {"suid": {path: hash16}, "sgid": {path: hash16},
             "caps": {path: "capabilities"}, "files_seen": int,
             "unreadable_dirs": [str], "unhashable": int,
             "xattr_unreadable": int, "seconds": float}

    HASHES ARE TAKEN NOW, WHICH THE REMOTE MODULE DOES NOT DO, and it is the
    difference between "a new setuid binary appeared" and "the binary at this
    path is not the one that was there". Those are different findings: the
    first is a new capability on the box, the second is the shape of a rootkit
    replacing sudo. Only the hash can tell them apart.

    XATTR_UNREADABLE COUNTS REFUSALS, NOT ABSENCES. A file with no capability
    answers the kernel with ENODATA, which is an answer; only a real refusal
    (a filesystem that stores no xattrs, a file this process may not read)
    increments the counter. The first version counted both and reported a
    nineteen-thousand-file coverage hole on a machine that had none --
    MEASURED 2026-09-23, see the comment at the getxattr call.
    """
    started = time.monotonic()
    prune = set(SUID_PRUNE)
    result = {"suid": {}, "sgid": {}, "caps": {}, "files_seen": 0,
              "unreadable_dirs": [], "unhashable": 0, "xattr_unreadable": 0}

    def on_error(err):
        result["unreadable_dirs"].append(
            f"{getattr(err, 'filename', '?')} ({getattr(err, 'strerror', err)})")

    for root, dirs, names in os.walk("/", topdown=True, onerror=on_error):
        # Pruned in the walk, not filtered afterwards. Same reasoning as the
        # remote module's SUID_PRUNE comment: a snapshot directory is a second
        # copy of the whole filesystem and walking it in full for every sweep
        # costs minutes to produce findings about backups.
        dirs[:] = [d for d in dirs if os.path.join(root, d) not in prune]

        for name in names:
            path = os.path.join(root, name)
            result["files_seen"] += 1
            try:
                st = os.lstat(path)
            except OSError:
                result["unhashable"] += 1
                continue
            if not stat.S_ISREG(st.st_mode):
                continue

            wanted = (st.st_mode & stat.S_ISUID) or (st.st_mode & stat.S_ISGID)
            try:
                cap = os.getxattr(path, b"security.capability")
            except OSError as e:
                cap = None
                # 'NO CAPABILITY' IS NOT 'COULD NOT READ'.
                #
                # THE DEFECT THIS FIXES, MEASURED 2026-09-23: any getxattr
                # failure was counted as xattr_unreadable for every executable
                # file, and the ordinary failure on this host is ENODATA --
                # 'this file has no such attribute', which is the kernel
                # ANSWERING rather than refusing. The count came out 19,382
                # while a straight walk of /usr/bin found ENODATA for 1,765 of
                # 1,767 files and real refusals for NONE. That number rides in
                # LNX-2010 and in the status block as a blind spot, so the
                # sensor was reporting a nineteen-thousand-file coverage hole
                # that did not exist. Same family as everything else in this
                # file: a fact about the answer used as a fact about us.
                if e.errno != errno.ENODATA and (st.st_mode & stat.S_IXUSR):
                    result["xattr_unreadable"] += 1
            except AttributeError:
                # os.getxattr does not exist on this build. A GENUINE limit,
                # and it counts for every executable examined because it is a
                # property of the platform rather than of one file.
                cap = None
                if st.st_mode & stat.S_IXUSR:
                    result["xattr_unreadable"] += 1

            if not wanted and not cap:
                continue

            if cap:
                result["caps"][path] = cap.hex()[:32]

            if wanted:
                data, reason = _read_bytes(path)
                if data is None:
                    result["unhashable"] += 1
                    digest = f"unreadable:{reason}"
                else:
                    digest = _hash16(data)
                if st.st_mode & stat.S_ISUID:
                    result["suid"][path] = digest
                if st.st_mode & stat.S_ISGID:
                    result["sgid"][path] = digest

    result["seconds"] = round(time.monotonic() - started, 1)
    result["unreadable_dirs"] = sorted(set(result["unreadable_dirs"]))
    return result


# THE COMPARISONS. PURE FUNCTIONS, so the test can drive them without a disk.

def _finding(detection_id, severity, entity_type, entity_value, title,
             description, raw_data) -> dict:
    """One finding in the shape the adapter writes. Nothing is defaulted."""
    return {
        "detection_id": detection_id,
        "severity": severity,
        "entity_type": entity_type,
        "entity_value": entity_value,
        "title": title,
        "description": description,
        "raw_data": raw_data,
    }


def _mode_int(text) -> int:
    try:
        return int(str(text), 8)
    except (TypeError, ValueError):
        return 0


def diff_watched_files(old: dict, new: dict) -> list:
    """
    Compare two tier A file pictures. Returns findings, oldest claim first.

    ABSENT IS A STATE, NOT A FAILURE. On this watch set every path is one the
    OS ships, so "it is gone" is as much a fact as "it changed", and it is
    reported with the same weight. The one path where the two are not
    symmetric is /etc/ld.so.preload, below, and that is because its expected
    state is absent rather than because absent is bad in general.
    """
    out = []
    old_files = (old or {}).get("files") or {}
    new_files = (new or {}).get("files") or {}

    for path, now in sorted(new_files.items()):
        was = old_files.get(path)
        if was is None:
            continue                      # seeding handles this, see seed()

        # NO EARLY "BOTH UNREADABLE, SKIP" GUARD HERE, AND ITS ABSENCE IS THE
        # FIX FOR A REAL DEFECT THIS FILE'S OWN TEST FOUND ON 2026-09-22.
        #
        # The first version had one, on the reasoning that two unreadable
        # records tell you nothing about each other. That reasoning is right
        # about the CONTENT and wrong about the FILE, and it made the entire
        # metadata-only watch DEAD CODE: /etc/sudoers, /etc/shadow and
        # /etc/gshadow are unreadable on every unelevated pass, so both sides
        # took the same branch, every comparison was skipped, and an account
        # added to this machine moved /etc/shadow's size and mtime for
        # nothing. The check existed, ran, and could not fire.
        #
        # What replaces it is the comparison itself. _file_value carries the
        # metadata always and the hash only when it was read, so two
        # unreadable records with identical metadata compare EQUAL and raise
        # nothing, and one whose mode, owner, size or mtime moved raises with
        # the content question answered explicitly in the wording.

        value_now = _file_value(now)
        value_was = _file_value(was)

        if value_now != value_was:
            if path == "/etc/ld.so.preload":
                appeared = now.get("exists") and not was.get("exists")
                out.append(_finding(
                    "LNX-2004", "critical" if appeared else "medium", "file", path,
                    ("ld.so.preload appeared on this host"
                     if appeared else "ld.so.preload changed on this host"),
                    _ld_preload_text(now, was, appeared),
                    {"path": path, "before": value_was, "after": value_now,
                     "read_by": "tools/local_integrity.py"}))
                continue

            # A mode or owner change is the loudest thing the metadata watch
            # can see, and a widening is louder than any other direction.
            severity = "high" if _widened(was, now) else "medium"
            out.append(_finding(
                "LNX-2001", severity, "file", path,
                f"Local security file changed: {path}",
                _file_change_text(path, now, was),
                {"path": path, "before": value_was, "after": value_now,
                 "content_read": now.get("readable") is True,
                 "read_by": "tools/local_integrity.py"}))
            continue

        # THE STEALTH CASE, AND THE ONLY FIELD LEFT THAT CAN SEE IT.
        #
        # Everything above compares the fields an ordinary edit moves. This is
        # the one that an edit can HIDE: same length, mtime forced back with
        # utime(), and size, mtime, mode and owner all agree with the baseline
        # exactly. Measured on this host and it works, which means a line
        # appended to /etc/sudoers by an unprivileged process was invisible to
        # the first version of this module.
        #
        # ctime is the field utime() cannot set, so it is the only remaining
        # witness. It is checked LAST and only here, after everything else has
        # been found to agree, because that conjunction is what separates this
        # from the ctime noise of ordinary maintenance.
        if _ctime_only_move(was, now):
            out.append(_finding(
                "LNX-2012", "high", "file", path,
                f"File rewritten with its timestamps put back: {path}",
                _stealth_text(path, now, was),
                {"path": path,
                 "ctime_before": was.get("ctime_ns"),
                 "ctime_after": now.get("ctime_ns"),
                 "size": now.get("size"), "mtime_ns": now.get("mtime_ns"),
                 "mode": now.get("mode"), "uid": now.get("uid"),
                 "gid": now.get("gid"),
                 "content_read": now.get("readable") is True,
                 "read_by": "tools/local_integrity.py"}))
    return out


def _stealth_text(path, now, was) -> str:
    """
    The sentence for a same-length edit whose mtime was put back.

    IT HAS TO EXPLAIN WHY IT CAN SEE THIS when the ordinary comparison could
    not, or the reader has no way to judge it and will assume the module is
    confused. It also has to name the innocent case, because there is one.
    """
    readable = now.get("readable") is True
    parts = [
        f"{path} was modified after this sensor recorded it, and its mtime was "
        f"put back to the recorded value.",
        f"Size ({now.get('size')}), mtime, mode ({now.get('mode')}) and owner "
        f"(uid {now.get('uid')}, gid {now.get('gid')}) ALL MATCH the baseline. "
        f"What does not match is the inode change time, which the kernel "
        f"stamps on every change and which no unprivileged program can set "
        f"back: recorded {was.get('ctime_ns')}, now {now.get('ctime_ns')}.",
    ]
    if readable:
        parts.append("Content IS readable on this pass, so the hash above is a "
                     "real reading of the file as it stands now.")
    else:
        parts.append(
            "THE CONTENT COULD NOT BE READ, so this finding says the file "
            "CHANGED and does NOT say what it now contains. On an unelevated "
            "run that is the ordinary case for /etc/sudoers and the shadow "
            "files. Read the file yourself, or read it from a run that can.")
    parts.append(
        "Ordinary maintenance that only rewrote the file would have moved "
        "mtime as well and been caught by the normal comparison, so reaching "
        "this rule means the timestamps were deliberately preserved. A "
        "restored backup, a package with a post-install script that touches "
        "timestamps, and a file copied with rsync's timestamp preservation all "
        "do this innocently. A privileged change made to look old does it too, "
        "and that is the one worth waking up for.")
    return " ".join(parts)


def _file_value(rec: dict) -> str:
    """
    The one string a file record is compared on.

    `content_read` is part of it, and that is deliberate: a file that stops
    being readable is a change in what this sensor can see, and folding it
    into "same hash absent" would make a permission change invisible.

    CTIME IS DELIBERATELY NOT IN HERE, and it is the exception that proves the
    rule for the rest of the function. This string decides whether a pass
    produces a finding at all, and ctime moves on the ordinary maintenance
    this host does to its own files. Putting it here would make every apt run
    a finding. Instead the comparison calls _ctime_only_move, which reports it
    in exactly one case: ctime moved while everything else AGREED.
    """
    if rec.get("exists") is not True:
        return "absent" if rec.get("exists") is False else \
               f"unstatable:{rec.get('reason')}"
    return (f"{rec.get('mode')}:{rec.get('uid')}:{rec.get('gid')}:"
            f"{rec.get('size')}:{rec.get('mtime_ns')}:{rec.get('hash')}:"
            f"{rec.get('readable')}")


def _ctime_only_move(was: dict, now: dict) -> bool:
    """
    Did the inode change while every ordinary field stayed the same.

    THIS IS THE STEALTH CASE, and it is the answer to a real hole that the
    first version of this module had. MEASURED ON THIS HOST, 2026-09-22, on a
    file shaped exactly like /etc/sudoers (mode 440, owned by the account
    running the sensor):

        write the same NUMBER of bytes with different content, then call
        utime() with the recorded mtime

    restores size, mtime, mode and owner EXACTLY. Every field the metadata-only
    watch had would agree with its baseline, and a line added to sudoers by an
    unprivileged process would have been invisible. The kernel's inode change
    time moved, because it stamps ctime on every inode change and there is no
    unprivileged way to set it back.

    WHY IT IS NOT A FINDING ON ITS OWN, also measured: a plain chmod, a plain
    utime() with unchanged values, and an ordinary package upgrade all move
    ctime. A raw ctime watch fires on every apt run on this host.

    So the test is CONJUNCTIVE and deliberately narrow: ctime moved AND size,
    mtime, mode and owner ALL agree. Ordinary maintenance moves mtime as well
    and is caught by the normal comparison, which is why it never reaches this
    function. The conjunction is what makes this the only reachable case where
    nothing else moved.

    A CTIME CHECK IS ONLY AS GOOD AS ITS RECORDING DISCIPLINE.

    FOUND THE HARD WAY, 2026-09-22, by this rule's own noise test: the FIRST
    version of that test called os.chmod() inside its record() helper, to
    normalise the mode before each reading. A chmod STAMPS CTIME. So the test
    itself moved ctime between two recordings and this rule fired on a file
    nobody had touched, twice, on cases that were supposed to be silent.

    The rule was right and the test was manufacturing the condition, which is
    the exact shape this project keeps writing down: the measurement apparatus
    changed the thing being measured. ANYTHING THAT SO MUCH AS chmods A WATCHED
    FILE BETWEEN TWO RECORDINGS WILL PRODUCE A HIT HERE. This module only ever
    opens watched paths read-only (verified in the source), and nothing that
    touches one should be added to the recording path.

    The innocent-population question is answered honestly in the finding's own
    description rather than here: a restored backup, a post-install script
    that touches timestamps, and rsync with -t all reach this rule without
    anybody doing anything wrong.
    """
    if was.get("exists") is not True or now.get("exists") is not True:
        return False
    if was.get("ctime_ns") is None or now.get("ctime_ns") is None:
        return False
    if was.get("ctime_ns") == now.get("ctime_ns"):
        return False
    for field in ("size", "mtime_ns", "mode", "uid", "gid"):
        if was.get(field) != now.get(field):
            return False
    return True


def _widened(was: dict, now: dict) -> bool:
    """
    Did the permissions get LOOSER, rather than merely different.

    Used only to pick between two declared severities. A file whose mode went
    from 644 to 600 is a change; one that went from 600 to 666 is a change
    and a warning, and the register lets this id carry both.
    """
    before, after = _mode_int(was.get("mode")), _mode_int(now.get("mode"))
    if not before or not after:
        return False
    return bool(after & ~before)


def _file_change_text(path, now, was) -> str:
    """
    The sentence, with the content question answered explicitly.

    FOUR CASES, NOT THREE, and the fourth is the one that catches people out.
    A file can be readable on both passes (a real content difference), become
    readable (we gained access), stop being readable (we lost it), or be
    unreadable on both and change anyway because its METADATA moved.

    The first version of this function only handled three, and the fourth fell
    through to "content was readable before and is not now", which is FALSE
    and which the module's own test caught. It is the ordinary case on this
    host: /etc/sudoers is root-only on every unelevated pass, so the fourth
    branch is the one an operator will actually read.
    """
    read_before = was.get("readable") is True
    read_now = now.get("readable") is True

    parts = [f"{path} no longer matches the recorded baseline."]
    parts.append(f"was {_file_value(was)}")
    parts.append(f"now {_file_value(now)}")

    if read_before and read_now:
        parts.append("Content was read on both passes, so this is a real "
                     "difference in the file.")
    elif not read_before and not read_now:
        parts.append(
            "THE CONTENT WAS NOT READ BY EITHER PASS, so what moved is the "
            "file's name, mode, owner, size or mtime"
            + (f" ({now.get('unreadable_reason')})"
               if now.get("unreadable_reason") else "")
            + ". On an unelevated run this is the ordinary case for "
              "/etc/sudoers and the shadow files, and it is the only way a "
              "change to them can be seen at all. A content edit that left "
              "all four of those identical would not be detected here.")
    elif read_before and not read_now:
        parts.append("Content was readable at the last pass and is NOT any "
                     "more, which is itself the change: whatever this process "
                     "could see before, it cannot see now.")
    else:                                  # not read before, readable now
        parts.append("Content could NOT be read at the last pass and can be "
                     "read now, so the readable value below is the first real "
                     "look at this file rather than a change in it.")
    return " ".join(parts)


def _ld_preload_text(now, was, appeared) -> str:
    if appeared:
        return (
            "This file did not exist and now does. Every dynamically linked "
            "program on this machine loads whatever it names BEFORE anything "
            "else, which is how a userland rootkit is installed without "
            "touching a single system binary. It is absent on a normal install "
            "and its expected state is absence, which was declared by the "
            "owner rather than assumed here. Read what it names before "
            "removing it.")
    return (
        "This file exists and no longer matches its baseline. Its contents "
        "name libraries that every program on this machine loads first. "
        f"was {_file_value(was)}, now {_file_value(now)}.")


def _entry_parts(value) -> dict:
    """
    One stored directory entry, split into its metadata and its hash.

    THE STORED FORM IS mode:uid:gid:size:hash, and the hash field is '-' when
    the file could not be read. THE SPLIT EXISTS BECAUSE '-' IS NOT A HASH: an
    entry whose hash is '-' was NOT READ, and comparing that against a real
    hash as two values of one field is how "this run could not read it"
    becomes the false sentence "this file changed". MEASURED 2026-09-23: the
    live baseline holds `/etc/sudoers.d/0pwfeedback` as
    `440:0:0:20:41526a8294489c39` because it was recorded by a run that could
    read it; every unelevated pass records `440:0:0:20:-`, and the difference
    is this process's privilege rather than the file.
    """
    text = str(value if value is not None else "")
    parts = text.split(":")
    if len(parts) < 5:
        # Not a file record at all (or a truncated one). Compared as an
        # opaque string, and said so rather than guessed at.
        return {"meta": text, "hash": None, "unreadable": False,
                "well_formed": False}
    digest = parts[4]
    return {"meta": ":".join(parts[:4]),
            "hash": None if digest == "-" else digest,
            "unreadable": digest == "-",
            "well_formed": True}


def _entry_mode_int(meta: str) -> int:
    """The mode out of a 'mode:uid:gid:size' string, or 0 if it will not parse."""
    try:
        return int(str(meta).split(":", 1)[0], 8)
    except (TypeError, ValueError):
        return 0


def _dir_entry_finding(path: str, rel: str, was_value, now_value) -> dict:
    """
    The ONE finding for a changed file inside a hashed directory set.

    THREE DIFFERENT CLAIMS, AND THE FIRST VERSION OF THIS COMPARISON MADE ONLY
    ONE OF THEM. Measured 2026-09-23, against this host's own history: the
    entry value carries a hash when the file was READ and a '-' when it was
    not, so a pass that loses or gains the ability to read a file produces a
    different value string for a file nobody has touched. Raising that as
    "Watched file changed" at high would be a false accusation per file, on
    every elevated/unelevated transition. So:

      both hashes real, and different   the file's CONTENTS moved. High: this
                                        is the shape of a file replaced
                                        underneath its name.
      metadata moved (mode/uid/gid/size)  a real change to the entry. High
                                        when the permissions WIDENED and
                                        medium otherwise, which is what the
                                        register for LNX-2001 declares --
                                        the first version raised high for
                                        every one of these.
      one side unreadable, metadata same  NOT a content claim: this pass could
                                        not read what an earlier pass could
                                        (or the reverse). Medium, and the
                                        wording says which side was read,
                                        because "unreadable" is not
                                        "unchanged" and it is not "changed"
                                        either.
    """
    was = _entry_parts(was_value)
    now = _entry_parts(now_value)
    target = f"{path}/{rel}"
    raw = {"dir": path, "entry": rel, "before": was_value, "after": now_value,
           "entry_format": "mode:uid:gid:size:hash", "hash_before": was["hash"],
           "hash_after": now["hash"],
           "read_by": "tools/local_integrity.py"}

    if not (was["well_formed"] and now["well_formed"]):
        return _finding(
            "LNX-2001", "medium", "file", target,
            f"Watched directory entry changed shape: {target}",
            (f"was {was_value}, now {now_value}. One of these does not parse "
             f"as mode:uid:gid:size:hash, so this comparison cannot say WHICH "
             f"field moved and does not guess."),
            raw)

    if was["meta"] != now["meta"]:
        widened = bool(_entry_mode_int(now["meta"]) & ~_entry_mode_int(was["meta"]))
        return _finding(
            "LNX-2001", "high" if widened else "medium", "file", target,
            (f"Watched file permissions widened: {target}" if widened else
             f"Watched file metadata changed: {target}"),
            (f"was {was_value}, now {now_value}. The entry format is "
             f"mode:uid:gid:size:hash"
             + (". The permissions are LOOSER than they were, which is a "
                "change in who can use this file rather than only in how it "
                "is stored." if widened else
                ". An owner, group or size move on a file in a watched "
                "directory is how a unit, a cron entry or a sudoers drop-in "
                "is replaced.")
             + (" The content was read on both passes." if
                (was["hash"] and now["hash"]) else
                " The CONTENT hash could not be compared on both passes; see "
                "the hash fields in this finding's data.")),
            raw)

    if was["hash"] and now["hash"]:
        return _finding(
            "LNX-2001", "high", "file", target,
            f"Watched file changed: {target}",
            (f"was {was_value}, now {now_value}. Its mode, owner and size all "
             f"agree and its CONTENTS do not, which is the shape of a file "
             f"replaced underneath its name. The entry format is "
             f"mode:uid:gid:size:hash."),
            raw)

    # One side has a real hash and the other does not. NOT a content claim.
    return _finding(
        "LNX-2001", "medium", "file", target,
        f"Watched file could not be read on this pass: {target}",
        (f"was {was_value}, now {now_value}. Mode, owner and size agree; what "
         f"differs is whether the CONTENT could be read, "
         + ("it could be read at the recorded pass and could not be read on "
            "this one, so a content edit made since then would NOT be "
            "detected by this pass."
            if was["hash"] and not now["hash"] else
            "it could not be read at the recorded pass and can be read now, "
            "so the hash above is the first real look at this file rather "
            "than a change in it.")
         + " A file nobody read is not a file that did not change, and it is "
           "not a file that changed either."),
        raw)


def diff_dir_sets(old: dict, new: dict, hashed: bool,
                  presence_only=()) -> list:
    """
    Additions and removals in a directory set, and (where hashed) edits.

    ONE FINDING PER FILE, never per line: a rule that raises per line writes
    thousands of rows and buries the one that mattered. The caller caps how
    many individual rows a single pass may raise and summarises the rest.

    THE `hashed` DECISION IS PER PATH, NOT PER SET, AND THAT IS A FIX RATHER
    THAN A REFINEMENT. MEASURED 2026-09-23, on the shipped code: tier_a_pass
    asked `not any(p in DIR_WATCH_PRESENCE for p in dirs)` -- "is the
    presence-only directory in this set at all" -- and used the answer for
    EVERY directory in it. /usr/lib/systemd/system IS in that set, so the
    answer was always "do not compare hashes", and the file-change branch
    below was therefore DEAD for all ten hashed directories: an edit to
    /etc/pam.d/common-auth, /etc/cron.d/*, /etc/systemd/system/* or a sudoers
    drop-in raising content changes produced NO finding. Against the live
    baseline a corrected comparison produces 6 findings the shipped code
    cannot see, 2 of them real content moves. The check existed, ran, and
    could not fire, which is the one defect shape this project keeps paying
    for.
    """
    out = []
    old_dirs = (old or {}).get("dirs") or {}
    new_dirs = (new or {}).get("dirs") or {}
    presence_only = set(presence_only or ())

    for path, now in sorted(new_dirs.items()):
        was = old_dirs.get(path)
        if was is None:
            continue
        was_entries = was.get("entries") or {}
        now_entries = now.get("entries") or {}

        for rel in sorted(set(now_entries) - set(was_entries)):
            out.append(_finding(
                "LNX-2001", "high", "file", f"{path}/{rel}",
                f"New file in a watched directory: {path}/{rel}",
                (f"{path} gained an entry it did not have at the last pass. "
                 f"Recorded as {now_entries[rel]}. A file appearing in this "
                 f"directory is how a schedule or a boot-time action is "
                 f"installed."),
                {"dir": path, "entry": rel, "after": now_entries[rel],
                 "read_by": "tools/local_integrity.py"}))

        for rel in sorted(set(was_entries) - set(now_entries)):
            out.append(_finding(
                "LNX-2001", "medium", "file", f"{path}/{rel}",
                f"File removed from a watched directory: {path}/{rel}",
                (f"{path} had this entry at the last pass and does not now. "
                 f"It was recorded as {was_entries[rel]}. Removing one of "
                 f"these is also how an act is covered up, so a removal is a "
                 f"change and not a housekeeping note."),
                {"dir": path, "entry": rel, "before": was_entries[rel],
                 "read_by": "tools/local_integrity.py"}))

        # The presence-only set (/usr/lib/systemd/system, 467 package-owned
        # files): additions and removals above, and nothing else. A CHANGE to
        # one of those files is dpkg -V's job; this set is watched so that a
        # file nobody shipped and nobody knows about shows up as an addition.
        if not hashed or path in presence_only:
            continue
        for rel in sorted(set(was_entries) & set(now_entries)):
            if was_entries[rel] == now_entries[rel]:
                continue
            out.append(_dir_entry_finding(path, rel, was_entries[rel],
                                          now_entries[rel]))
    return out


def _ssh_line_text(path, kind) -> str:
    """
    The sentence for a changed line, WHICH DEPENDS ON WHAT FILE IT IS IN.

    THE DEFECT THIS FIXES, MEASURED 2026-09-23 by driving diff_ssh: every SSH
    artifact was described with the authorized_keys sentence. A line added to
    `~/.ssh/config` produced "SSH key added to /home/x/.ssh/config ... A key
    in this file grants standing access that survives a password change, and
    it works from anywhere", and a line added to `known_hosts` produced the
    same. Both sentences are FALSE about those files: `config` is a client
    configuration file and `known_hosts` is a list of hosts the client has
    already talked to, and neither grants anybody access to this machine.
    Only authorized_keys does. The claim being made is the loudest one this
    sensor can make -- "somebody can log in as you" -- so attaching it to a
    harmless file is the worst kind of wrong row: it teaches the reader that
    this id cries wolf.
    """
    if str(path).endswith("authorized_keys"):
        return ("A key in this file grants standing access that survives a "
                "password change, and it works from anywhere unless the "
                "account or the key is removed.")
    if str(path).endswith("known_hosts"):
        return ("This file is the client's record of hosts it has already "
                "connected to. A new line here means this account SSH'd to a "
                "host it had not spoken to before, or accepted a changed host "
                "key, the second is worth a look, because accepting a new "
                "key for a known host is what a person does when a "
                "machine-in-the-middle has told them to. It grants nobody "
                "access TO this machine.")
    if str(path).endswith("config"):
        return ("This is the SSH CLIENT's configuration: which keys to use "
                "for which host, which ports, and which commands may run "
                "without a terminal. A change here alters how this account "
                "reaches other machines. It grants nobody access TO this "
                "machine.")
    return ("This file is in a home's .ssh directory. What it controls "
            "depends on which file it is; the path is in the finding.")


def diff_ssh(old: dict, new: dict) -> list:
    """
    Every SSH artifact in every home: key lists, and the modes that carry them.

    TWO DIFFERENT CLAIMS, TWO IDS. A key that was added is LNX-2002, because
    the set of people who can log in changed. A mode that got wider is
    LNX-2003, because the set of people who can ALTER that list changed. They
    are reported separately even when they happen together, which is exactly
    what a key being planted looks like.

    THE DIRECTORY ITSELF IS COMPARED TOO, and it was silently skipped before.
    MEASURED 2026-09-23: `.ssh` is recorded as a `mode:uid:gid` STRING while
    every file inside it is a dict, and the first version of this function
    began `if was is None or not isinstance(now, dict) ... continue`, so the
    directory fell through every branch. A home whose `.ssh` went from 700 to
    777 -- which lets any account on the machine add a key to it, the exact
    fact LNX-2003 exists for -- raised NOTHING. A world-writable `.ssh`
    directory is not a quieter version of a world-writable key file; it is
    the same capability with one more step.
    """
    out = []
    old_ssh = (old or {}).get("ssh") or {}
    new_ssh = (new or {}).get("ssh") or {}
    old_entries = old_ssh.get("entries") or {}
    new_entries = new_ssh.get("entries") or {}

    for path, now in sorted(new_entries.items()):
        was = old_entries.get(path)
        if was is None or not isinstance(now, dict) or not isinstance(was, dict):
            continue

        read_before = was.get("readable") is True
        read_now = now.get("readable") is True

        if read_before and read_now:
            old_lines = was.get("lines") or {}
            new_lines = now.get("lines") or {}
            for fp in sorted(set(new_lines) - set(old_lines)):
                out.append(_finding(
                    "LNX-2002", "high", "file", path,
                    (f"SSH key added to {path}"
                     if str(path).endswith("authorized_keys")
                     else f"New entry in {path}"),
                    (f"A line that was not there at the last pass: "
                     f"{new_lines[fp]}. Fingerprint {fp}. "
                     + _ssh_line_text(path, "added")),
                    {"path": path, "change": "added",
                     "key": new_lines[fp], "fingerprint": fp,
                     "keys_before": len(old_lines), "keys_after": len(new_lines),
                     "read_by": "tools/local_integrity.py"}))
            for fp in sorted(set(old_lines) - set(new_lines)):
                out.append(_finding(
                    "LNX-2002", "high", "file", path,
                    (f"SSH key removed from {path}"
                     if str(path).endswith("authorized_keys")
                     else f"Entry removed from {path}"),
                    (f"A line that was there at the last pass is gone: "
                     f"{old_lines[fp]}. Fingerprint {fp}. "
                     + ("Removing the wrong key locks somebody out and "
                        "removing the right one is tidy-up; both are worth "
                        "seeing." if str(path).endswith("authorized_keys")
                        else _ssh_line_text(path, "removed"))),
                    {"path": path, "change": "removed",
                     "key": old_lines[fp], "fingerprint": fp,
                     "keys_before": len(old_lines), "keys_after": len(new_lines),
                     "read_by": "tools/local_integrity.py"}))

        mode_before, mode_now = was.get("mode"), now.get("mode")
        if mode_before is None or mode_now is None:
            continue
        if mode_before == mode_now and was.get("uid") == now.get("uid") \
                and was.get("gid") == now.get("gid"):
            continue

        bits = _mode_int(mode_now)
        world_writable = bool(bits & 0o002)
        out.append(_finding(
            "LNX-2003", "high" if world_writable else "medium", "file", path,
            f"SSH key file permissions changed: {path}",
            (f"was {mode_before}:{was.get('uid')}:{was.get('gid')}, now "
             f"{mode_now}:{now.get('uid')}:{now.get('gid')}. "
             + ("IT IS NOW WORLD-WRITABLE, which means any account on this "
                "machine can add a key to it. "
                if world_writable else "")
             + "A file that becomes readable or writable by others is a change "
               "in who can use it, not just in how it is stored."),
            {"path": path, "before_mode": mode_before, "after_mode": mode_now,
             "before_uid": was.get("uid"), "after_uid": now.get("uid"),
             "before_gid": was.get("gid"), "after_gid": now.get("gid"),
             "world_writable": world_writable,
             "read_by": "tools/local_integrity.py"}))

    # THE DIRECTORIES.
    #
    # The `.ssh` directory itself is stored as "mode:uid:gid" rather than as a
    # dict, which is why it used to fall out of this function entirely.
    # Checked here on its own terms: a `.ssh` that anything on this machine
    # can write to is a key file anybody can add a key to, one directory up.
    for path, now in sorted(new_entries.items()):
        was = old_entries.get(path)
        if not isinstance(now, str) or not isinstance(was, str):
            continue
        if now == was:
            continue
        mode_before = was.split(":", 1)[0]
        mode_now = now.split(":", 1)[0]
        bits = _mode_int(mode_now)
        world_writable = bool(bits & 0o002)
        out.append(_finding(
            "LNX-2003", "high" if world_writable else "medium", "file", path,
            f"SSH directory permissions changed: {path}",
            (f"was {was}, now {now}. This is the .ssh DIRECTORY, not a file "
             f"in it. "
             + ("IT IS NOW WORLD-WRITABLE, so any account on this machine "
                "can add a key file to it or replace one, which puts a key "
                "in the account's authorized_keys without ever touching that "
                "file. "
                if world_writable else
                "A directory whose mode moves decides who may CREATE entries "
                "in it, which is a different capability from who may read "
                "them.")),
            {"path": path, "before": was, "after": now,
             "world_writable": world_writable, "kind": "directory",
             "read_by": "tools/local_integrity.py"}))
    return out


def seed_ssh_permission_findings(new: dict) -> list:
    """
    The ONE permission state that raises on a first pass.

    Everything else about a mode is recorded and compared, because this host's
    own authorized_keys is 664 and a detector that shouts about that on day
    one is a detector its reader learns to skim. World-writable is different
    in kind: there is no reading of a world-writable key file that is safe, and
    no umask produces one by accident.
    """
    out = []
    for path, rec in sorted(((new or {}).get("ssh") or {}).get("entries", {}).items()):
        if not isinstance(rec, dict) or rec.get("exists") is not True:
            continue
        if rec.get("mode") is None:
            continue
        if _mode_int(rec["mode"]) & 0o002:
            out.append(_finding(
                "LNX-2003", "high", "file", path,
                f"SSH key file is world-writable: {path}",
                (f"Its mode is {rec['mode']}, owned by uid {rec.get('uid')} "
                 f"gid {rec.get('gid')}. Any account on this machine can add "
                 f"a key to it, so the list of who can log in is not this "
                 f"account's to control. This fires on the first pass rather "
                 f"than being seeded, because a world-writable key file is "
                 f"never a state to remember quietly."),
                {"path": path, "mode": rec["mode"], "uid": rec.get("uid"),
                 "gid": rec.get("gid"), "on_seed_pass": True,
                 "read_by": "tools/local_integrity.py"}))
    return out


def diff_sweep(old: dict, new: dict, unreadable_dirs=None,
               files_seen=None, seconds=None) -> list:
    """
    The setuid, setgid and capability diff.

    ADDED, REPLACED AND REMOVED ARE THREE ANSWERS, not one. The remote module
    can only say "a setuid binary exists that was not in the baseline", which
    merges the first two: a binary planted at a new path and the system's own
    sudo being overwritten are the same row to it. Keeping the hash turns that
    into two sentences, and the second one is the one that matters.
    """
    out = []
    # SEVERITY IS PER CHANGE, NOT PER ID, and the three rows below each carry
    # the severity the REGISTER declares for that specific sentence.
    #
    # THE DEFECT THIS FIXES, MEASURED 2026-09-23 by driving this function:
    # the first version took ONE severity per id and used it for all three
    # changes, so a setuid bit being CLEARED was raised at high where
    # LNX-2007's own text says "a setuid bit that was cleared (medium)", and a
    # setgid file whose CONTENTS changed was raised at medium where LNX-2008's
    # text says "a known setgid file whose contents changed (high)". The
    # detections page and the code therefore disagreed about what the same id
    # means, and the disagreement ran in BOTH directions: one claim was louder
    # than declared and the other was quieter. A rule that is quieter than its
    # own declaration is the dangerous direction, because the register is what
    # a reader consults to decide how hard to look.
    pairs = (
        ("suid", "LNX-2007", "setuid",
         {"added": "high", "replaced": "high", "removed": "medium"}),
        ("sgid", "LNX-2008", "setgid",
         {"added": "medium", "replaced": "high", "removed": "low"}),
    )
    for key, did, label, severity_by_change in pairs:
        was_all = (old or {}).get(key) or {}
        now_all = (new or {}).get(key) or {}
        for path in sorted(set(now_all) - set(was_all)):
            out.append(_finding(
                did, severity_by_change["added"], "file", path,
                f"New {label} file: {path}",
                (f"This file is {label} and was not in the recorded baseline. "
                 f"A {label} file runs with {'root' if label == 'setuid' else 'its group'}'s "
                 f"authority regardless of who starts it, so a new one is a new "
                 f"capability on this machine. Ordinary causes: a package was "
                 f"installed. The hash is {now_all[path]}."),
                {"path": path, "change": "added", "hash": now_all[path],
                 "read_by": "tools/local_integrity.py"}))
        for path in sorted(set(now_all) & set(was_all)):
            if now_all[path] == was_all[path]:
                continue
            out.append(_finding(
                did, severity_by_change["replaced"], "file", path,
                f"{label.capitalize()} file REPLACED: {path}",
                (f"The path is the same and the contents are not. was "
                 f"{was_all[path]}, now {now_all[path]}. That is the shape of "
                 f"a binary being swapped underneath its name, which is why "
                 f"this is reported apart from a new file appearing. Ordinary "
                 f"causes: a package upgrade."),
                {"path": path, "change": "replaced",
                 "hash_before": was_all[path], "hash_after": now_all[path],
                 "read_by": "tools/local_integrity.py"}))
        for path in sorted(set(was_all) - set(now_all)):
            out.append(_finding(
                did, severity_by_change["removed"], "file", path,
                f"{label.capitalize()} bit removed: {path}",
                (f"This file was {label} in the recorded baseline and is not "
                 f"now. Clearing the bit is also what somebody does after "
                 f"using one, so a removal is a change rather than an all "
                 f"clear. It was recorded as {was_all[path]}."),
                {"path": path, "change": "removed",
                 "hash_before": was_all[path],
                 "read_by": "tools/local_integrity.py"}))

    was_caps = (old or {}).get("caps") or {}
    now_caps = (new or {}).get("caps") or {}
    for path in sorted(set(now_caps) - set(was_caps)):
        out.append(_finding(
            "LNX-2009", "high", "file", path,
            f"New file capability: {path}",
            (f"This executable carries a capability that was not in the "
             f"recorded baseline ({now_caps[path]}). Capabilities are quieter "
             f"than setuid and they are how the modern packages do this, so "
             f"they are watched in the same pass that watches setuid rather "
             f"than in a second tool nobody remembers to run. "
             f"getcap -r / would be the second tool."),
            {"path": path, "change": "added", "xattr": now_caps[path],
             "read_by": "tools/local_integrity.py"}))
    for path in sorted(set(was_caps) & set(now_caps)):
        if was_caps[path] == now_caps[path]:
            continue
        out.append(_finding(
            "LNX-2009", "high", "file", path,
            f"File capability changed: {path}",
            (f"was {was_caps[path]}, now {now_caps[path]}. The capability set "
             f"on this executable is different from the one recorded."),
            {"path": path, "change": "changed",
             "before": was_caps[path], "after": now_caps[path],
             "read_by": "tools/local_integrity.py"}))
    for path in sorted(set(was_caps) - set(now_caps)):
        out.append(_finding(
            "LNX-2009", "medium", "file", path,
            f"File capability removed: {path}",
            (f"was {was_caps[path]} and the executable carries no capability "
             f"now. A package upgrade moving its work into a helper it spawns "
             f"would do this."),
            {"path": path, "change": "removed", "before": was_caps[path],
             "read_by": "tools/local_integrity.py"}))

    return out


def sweep_coverage_findings(sweep: dict, typical=None) -> list:
    """
    What the sweep could not see, as a finding rather than as a footnote.

    THE WHOLE REASON THIS EXISTS: a sweep that could not enter thirty-nine
    directories returns the same empty answer as a sweep of a machine with
    nothing setuid on it. The count of entries examined is the fact that makes
    the difference readable, and it travels here.
    """
    out = []
    dirs = sweep.get("unreadable_dirs") or []
    if dirs:
        ordinary = [d for d in dirs
                    if any(d.startswith(p) for p in (typical or ()))]
        out.append(_finding(
            "LNX-2010", "medium", "file", "filesystem-sweep",
            "Filesystem sweep could not enter some directories",
            (f"{len(dirs)} director{'y' if len(dirs) == 1 else 'ies'} could "
             f"not be read, so the setuid, setgid and capability lists are "
             f"complete for the readable tree and UNKNOWN for these. "
             f"{sweep.get('files_seen')} entries were examined in "
             f"{sweep.get('seconds')}s. "
             + (f"{len(ordinary)} of them are the ordinary root-only "
                f"directories every host has. " if ordinary else "")
             + "Unreadable: " + "; ".join(dirs[:12])
             + (" (and more)" if len(dirs) > 12 else "")),
            {"unreadable_dirs": dirs, "files_seen": sweep.get("files_seen"),
             "unhashable": sweep.get("unhashable"),
             "xattr_unreadable": sweep.get("xattr_unreadable"),
             "seconds": sweep.get("seconds"),
             "read_by": "tools/local_integrity.py"}))
    if sweep.get("unhashable"):
        out.append(_finding(
            "LNX-2010", "medium", "file", "filesystem-sweep-hashes",
            "Some setuid or setgid files could not be hashed",
            (f"{sweep['unhashable']} file(s) carry setuid or setgid and could "
             f"not be read, so they are recorded as unreadable rather than as "
             f"a hash. A file recorded that way cannot be told apart from "
             f"itself by content; only its path and mode are watched until "
             f"this process can read it."),
            {"unhashable": sweep["unhashable"],
             "read_by": "tools/local_integrity.py"}))
    # THE XATTR COUNTER MEANS 'REFUSED', NOT 'ABSENT'.
    #
    # MEASURED 2026-09-23, and it is why this finding is raised only on a REAL
    # refusal now. The counter used to increment on any getxattr failure, and
    # the ordinary failure on this host is ENODATA -- the kernel saying "this
    # file has no capability", which is an ANSWER. The count came out 19,382
    # against 1,765 files in /usr/bin that all answered ENODATA and NONE that
    # refused, so this finding was describing a nineteen-thousand-file
    # coverage hole that did not exist. A finding that is wrong about the
    # size of the blind spot is worse than no finding, because it is the one
    # a reader uses to decide how much to trust everything else here.
    if sweep.get("xattr_unreadable"):
        out.append(_finding(
            "LNX-2010", "medium", "file", "filesystem-sweep-xattrs",
            "Some executables could not have their file capabilities read",
            (f"{sweep['xattr_unreadable']} executable(s) could not have "
             f"their security.capability attribute read at all, so for those "
             f"files this sweep cannot say whether a capability is present. "
             f"This is a REFUSAL count: a file with no capability answers "
             f"ENODATA, and that is an answer rather than a failure, so it is "
             f"not counted here."),
            {"xattr_unreadable": sweep["xattr_unreadable"],
             "files_seen": sweep.get("files_seen"),
             "read_by": "tools/local_integrity.py"}))
    return out


def mac_posture_findings(old: dict, new: dict) -> list:
    """
    A MAC system that stopped enforcing is a finding, and one that is merely
    unreadable is not.

    "WE ARE PROTECTED" has to be checked or it becomes the assumption an
    operator never revisits. On this host AppArmor is loaded and the profile
    set needs root: the honest output is "loaded, and I cannot tell you what it
    is enforcing", not "protected".
    """
    out = []
    was = ((old or {}).get("selinux") or {})
    now = ((new or {}).get("selinux") or {})
    if was.get("present") and now.get("present") \
            and was.get("mode") == "enforcing" and now.get("mode") != "enforcing":
        out.append(_finding(
            "LNX-2011", "high", "file", "selinux",
            "SELinux stopped enforcing",
            (f"was {was.get('mode')}, now {now.get('mode')}. A permissive MAC "
             f"system logs and does not stop, so this is the difference "
             f"between a control and a note in the log. It is also what "
             f"setenforce 0 does, and one of the strings autorun_monitor "
             f"already watches for."),
            {"before": was.get("mode"), "after": now.get("mode"),
             "read_by": "tools/local_integrity.py"}))

    was_aa = ((old or {}).get("apparmor") or {})
    now_aa = ((new or {}).get("apparmor") or {})
    if was_aa.get("kernel_enabled") and now_aa.get("kernel_enabled") \
            and was_aa["kernel_enabled"] != now_aa["kernel_enabled"]:
        out.append(_finding(
            "LNX-2011", "high", "file", "apparmor",
            "AppArmor is no longer enabled in the kernel",
            (f"was {was_aa['kernel_enabled']}, now {now_aa['kernel_enabled']}. "
             f"Profiles do nothing when the module is off, and apparmor=0 on "
             f"a kernel command line is one of the strings autorun_monitor "
             f"watches for."),
            {"before": was_aa.get("kernel_enabled"),
             "after": now_aa.get("kernel_enabled"),
             "read_by": "tools/local_integrity.py"}))
    return out


def cap_findings(findings: list, per_id_cap: int = MAX_FINDINGS_PER_ID_PER_PASS) -> list:
    """
    Cap how many rows one id may raise in one pass, and SAY what was cut.

    A CAP MUST ANNOUNCE ITSELF. Fifty setuid files appearing at once is either
    an upgrade or a very loud intrusion, and in both cases the reader needs the
    count rather than the first twenty rows. The summary row is a finding in
    its own right and names the number that did not fit.
    """
    counts, kept, cut = {}, [], {}
    for f in findings:
        did = f["detection_id"]
        counts[did] = counts.get(did, 0) + 1
        if counts[did] <= per_id_cap:
            kept.append(f)
        else:
            cut[did] = cut.get(did, 0) + 1

    for did, extra in sorted(cut.items()):
        first = next((f for f in findings if f["detection_id"] == did), {})
        kept.append(_finding(
            did, first.get("severity", "medium"), "file", "pass-cap",
            f"{did}: {extra} further finding(s) in this pass not listed",
            (f"{counts[did]} findings for {did} were produced in one pass and "
             f"only the first {per_id_cap} are listed. The rest are real and "
             f"were not written: this cap exists so that a sweep that goes "
             f"wrong cannot bury the dashboard, and it is stated here rather "
             f"than being silently applied. The pass's own count is in "
             f"query_local_integrity."),
            {"detection_id": did, "produced": counts[did], "listed": per_id_cap,
             "cut": extra, "read_by": "tools/local_integrity.py"}))
    return kept


# BASELINES. A TABLE OF THEIR OWN, v42, and that is a bug fix.
#
# THE FIRST VERSION PUT THESE IN user_preferences UNDER A local_integrity:
# PREFIX. It worked, and it was wrong, and the boot log said so: core/integrity
# hashes that whole table as "the policy" and journals a config_observed entry
# on ANY difference, on the contract that such an entry always means the rules
# changed. MEASURED before the fix: a shutdown snapshot produced
#
#     integrity: the policy in user_preferences has CHANGED (rollup:shutdown)
#
# carrying six JSON blobs of sudoers, pam and systemd file hashes. This sensor
# rewrites a baseline every pass that finds a change, so the false warning
# would have fired on every legitimate file move -- and a tamper journal that
# cries wolf is worse than no journal, because somebody is trusting it.
#
# It is the SAME defect as the T2 watcher cursor, which core/migrations still
# carries a cleanup for. That is the argument for a table rather than for
# excluding a key prefix from the hash: a table that is not user_preferences
# cannot be mistaken for policy by anything, and nothing has to remember.
#
# NOTHING HERE READS THE OLD KEYS. They are deleted by the v42 migration.

BASELINE_TABLE = "local_integrity_baseline"

# The sets that persist between runs. Named here so the status block and the
# seeder cannot disagree about how many there are.
#
# "dpkg" IS THE FOURTH CLOCK and it was added last, deliberately. It is not
# part of "sweep": the sweep is this app's own reading of the filesystem and
# dpkg is the PACKAGE MANAGER's recorded opinion about files it shipped. They
# disagree with each other legitimately (dpkg cannot see a file it never
# shipped, and the sweep does not know what a file was supposed to contain),
# so folding them into one stored set would make one of them overwrite the
# other's baseline on every pass.
BASELINE_NAMES = ("files", "dirs", "user_dirs", "ssh", "sweep", "mac", "dpkg")


def load_baseline(name: str):
    """
    The stored baseline for one set, or None when there has never been one.

    None and {} ARE DIFFERENT ANSWERS and the callers depend on it: None means
    "this has never run", which seeds and raises nothing; {} would mean "it ran
    and there was nothing", which is a claim about the machine.
    """
    from core import memory_engine as me
    try:
        with me._get_conn() as conn:
            row = conn.execute(
                f"SELECT value_json FROM {BASELINE_TABLE} WHERE name = ?",
                (name,)).fetchone()
    except Exception as e:
        # A table that is not there yet means the migration has not run. Said
        # plainly, because the alternative is a sensor that silently reseeds
        # on every pass and reports no changes forever.
        logger.error(
            f"local_integrity: could not read the {name} baseline ({e}). If "
            f"this is a missing table, run the migrations. Until it can be "
            f"read, this set reseeds every pass and reports NO CHANGES for it.")
        return None
    if row is None:
        return None
    try:
        return json.loads(row["value_json"])
    except (ValueError, TypeError) as e:
        logger.warning(f"local_integrity: the {name} baseline could not be "
                       f"parsed ({e}). Treating it as absent, which reseeds "
                       f"it and raises nothing this pass.")
        return None


def save_baseline(name: str, value) -> bool:
    """Persist one set. Returns whether it was written."""
    from core import memory_engine as me
    try:
        with me._get_conn() as conn:
            conn.execute(
                f"INSERT INTO {BASELINE_TABLE}(name, value_json) "
                f"VALUES(?, ?) "
                f"ON CONFLICT(name) DO UPDATE SET "
                f"value_json=excluded.value_json, "
                f"recorded_at=CURRENT_TIMESTAMP",
                (name, json.dumps(value, separators=(",", ":"))))
        return True
    except Exception as e:
        # A baseline that cannot be saved means the NEXT run reseeds and stays
        # quiet about everything in this set, which is a coverage fact the
        # status block has to carry. Said out loud here, reported there.
        logger.error(f"local_integrity: could not save the {name} baseline "
                     f"({e}). This set will reseed on the next run and will "
                     f"report no changes for it until then.")
        return False


def compact(picture: dict, name: str) -> dict:
    """
    The storable form of one tier A picture.

    THE SWEEP'S LARGE SET IS WHY THIS EXISTS. A raw tier A picture is about
    8 KB of JSON because the vendor unit directory carries 467 file names, and
    the preferences table is hashed as "the policy" by core/integrity on every
    change. Smaller is not cosmetics here: it is the difference between a
    policy digest that moves because the operator changed a rule and one that
    moves because a package was upgraded.
    """
    if name == "files":
        return {"at": picture.get("at"), "files": picture.get("files") or {}}
    if name == "dirs":
        return {"at": picture.get("at"), "dirs": picture.get("dirs") or {}}
    if name == "user_dirs":
        return {"at": picture.get("at"),
                "dirs": picture.get("user_dirs") or {}}
    if name == "ssh":
        ssh = dict(picture.get("ssh") or {})
        # The per-line maps are the useful half and they are small per file,
        # but they are dropped for known_hosts, which is usually hashed
        # already and where a comment carries no meaning.
        return {"at": picture.get("at"), "ssh": ssh}
    return {"at": picture.get("at")}


def capped_sets(picture: dict) -> list:
    """Which directory sets had to be capped, so the status can say so."""
    out = []
    for path, rec in ((picture.get("dirs") or {}).items()):
        if rec.get("capped"):
            out.append(path)
    for path, rec in ((picture.get("user_dirs") or {}).items()):
        if rec.get("capped"):
            out.append(path)
    return out


# THE PASSES

def tier_a_pass() -> dict:
    """
    One tier A pass: read, compare against the stored baseline, reseed.

    Returns a dict with ran, reason, findings, seeded, reseeded, coverage
    and capped.

    THE BASELINE MOVES IN THE SAME PASS THE FINDING IS RAISED, which is what
    makes this fire once per change rather than once per poll forever. That is
    the same shape linux_monitor's passwd check uses, and for the same reason:
    a monitor that repeats the same alert every minute is a monitor nobody
    reads by the end of the hour.
    """
    started = time.monotonic()
    picture = collect_watched()
    out = {"ran": True, "reason": None, "findings": [], "seeded": [],
           "reseeded": [], "capped": capped_sets(picture),
           "coverage": coverage_block(picture),
           "seconds": round(time.monotonic() - started, 2)}

    for name in ("files", "dirs", "user_dirs", "ssh"):
        current = compact(picture, name)
        stored = load_baseline(name)

        # FIRST RUN: seed and raise nothing. There is no earlier state to
        # differ against, and inventing findings out of a first look is how a
        # security tool teaches its operator to skim it.
        if stored is None:
            save_baseline(name, current)
            out["seeded"].append(name)
            continue

        if name == "files":
            changes = diff_watched_files(stored, current)
        elif name in ("dirs", "user_dirs"):
            # THE HASHED DECISION IS MADE PER PATH INSIDE THE COMPARISON NOW.
            # What this call site used to do was ask "is the presence-only
            # directory in this set", and the answer was yes for `dirs` on
            # every pass, so the file-change branch was dead for all ten
            # hashed directories. The set that is presence-only is named here
            # and the comparison applies it per path.
            changes = diff_dir_sets(stored, current, hashed=(name == "dirs"),
                                    presence_only=DIR_WATCH_PRESENCE)
        else:
            changes = diff_ssh(stored, current)

        if changes:
            # Reseed only the sets that moved. A set with no change keeps the
            # baseline it already had, so a later comparison is still against
            # the oldest known state rather than against yesterday.
            save_baseline(name, current)
            out["reseeded"].append(name)
            out["findings"].extend(changes)

    # The first pass, and only the first pass, gets the world-writable rule.
    if "ssh" in out["seeded"]:
        out["findings"].extend(
            seed_ssh_permission_findings(compact(picture, "ssh")))

    out["findings"] = cap_findings(out["findings"])
    return out


def tier_b_pass() -> dict:
    """
    One sweep, compared against the stored setuid, setgid and capability sets.

    The FIRST sweep seeds for the same reason tier A does, and it is the reason
    the owner's dpkg note gives for tier C: a machine that has never been looked
    at produces a page of pre-existing noise on day one, and that page is how
    the module gets switched off.
    """
    sweep = sweep_filesystem()
    stored = load_baseline("sweep")
    out = {"ran": True, "findings": [], "seeded": False,
           "counts": {"suid": len(sweep["suid"]), "sgid": len(sweep["sgid"]),
                      "caps": len(sweep["caps"])},
           "files_seen": sweep["files_seen"],
           "unreadable_dirs": sweep["unreadable_dirs"],
           "seconds": sweep["seconds"]}

    if stored is None:
        save_baseline("sweep", {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                "suid": sweep["suid"], "sgid": sweep["sgid"],
                                "caps": sweep["caps"]})
        out["seeded"] = True
        return out

    changes = diff_sweep(stored, sweep)
    if changes:
        save_baseline("sweep", {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                "suid": sweep["suid"], "sgid": sweep["sgid"],
                                "caps": sweep["caps"]})
        out["findings"].extend(changes)

    # The coverage findings are raised whether or not the sets moved: the
    # sweep's blind spots are a fact about EVERY pass, not about the passes
    # that happened to find something.
    out["findings"].extend(
        sweep_coverage_findings(sweep, UNREADABLE_DIRS_TYPICAL))
    out["findings"] = cap_findings(out["findings"])
    return out


def mac_pass() -> dict:
    """
    The MAC posture, once per sweep. Cheap, and it is a checked claim rather
    than an assumed one. Seeded on the first pass like everything else.
    """
    posture = collect_mac_posture()
    stored = load_baseline("mac")
    out = {"ran": True, "findings": [], "seeded": False, "posture": posture}
    if stored is None:
        save_baseline("mac", {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                              **posture})
        out["seeded"] = True
        return out
    findings = mac_posture_findings(stored, posture)
    if findings:
        save_baseline("mac", {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                              **posture})
        out["findings"] = findings
    return out


def coverage_block(picture: dict) -> dict:
    """
    What this pass could and could not examine, for the status block.

    Same discipline as every other module here: the numbers a reader needs to
    tell "nothing changed" from "nothing was looked at" travel with the answer.
    """
    files = (picture.get("files") or {})
    readable = [p for p, r in files.items() if r.get("readable")]
    metadata_only = [p for p, r in files.items()
                     if r.get("exists") and not r.get("readable")]
    # TIER D CHANGES THIS LIST, AND THAT IS THE WHOLE POINT OF THE FEATURE.
    # A file read through the helper HAS a hash and is NOT metadata-only any
    # more, so the sentence that used to name it -- "a content edit leaving
    # those fields identical is NOT detected" -- would be FALSE about it.
    # Rather than a second list that could drift from the first, the split is
    # made here from the record itself, which is the same record the
    # comparison reads.
    elevated = sorted(p for p, r in files.items() if r.get("elevated_read"))
    elevated_refused = {p: r.get("elevated_reason")
                        for p, r in files.items()
                        if r.get("elevated_read") is False
                        and r.get("elevated_reason")}
    dirs = (picture.get("dirs") or {})
    dir_unreadable = {p: len(r.get("unreadable") or []) for p, r in dirs.items()
                      if r.get("unreadable")}
    dirs_elevated = sorted(p for p, r in dirs.items() if r.get("elevated_read"))
    ssh = (picture.get("ssh") or {})
    homes_unreadable = [h for h in (ssh.get("homes") or [])
                        if h.get("ssh_dir_exists")]
    homes_unreachable = [h for h in (ssh.get("homes") or [])
                         if h.get("cannot_enter")]
    return {
        "files_read": len(readable),
        "files_metadata_only": sorted(metadata_only),
        "files_read_elevated": elevated,
        "files_elevated_refused": elevated_refused,
        "dirs_read_elevated": dirs_elevated,
        "dirs_unreadable": dir_unreadable,
        "dirs_blocked": sorted(p for p, r in dirs.items() if r.get("blocked")),
        "unreadable": (picture.get("unreadable") or [])[:40],
        "unreadable_count": len(picture.get("unreadable") or []),
        "homes": homes_unreadable,
        "homes_not_enterable": homes_unreachable,
        "note": (
            "files_read counts the watched files whose CONTENT was hashed, "
            "INCLUDING any read through the read-only helper "
            "(files_read_elevated names those). files_metadata_only lists the "
            "ones only their name, mode, owner, size and mtime are watched "
            "for: without the helper that is /etc/sudoers and the shadow "
            "files, and a content edit that leaves all four identical is NOT "
            "detected for those. /etc/shadow and /etc/gshadow are in that "
            "list in EVERY state, because reading them is refused by design."
        ),
    }


def status_block() -> dict:
    """What the module can say about itself, without doing any work."""
    from core import memory_engine as me
    out = {"baselines_present": {}, "baseline_bytes": {}}
    try:
        with me._get_conn() as conn:
            rows = conn.execute(
                f"SELECT name, LENGTH(value_json) AS n "
                f"FROM {BASELINE_TABLE}").fetchall()
        present = {r["name"]: r["n"] for r in rows}
    except Exception as e:
        # A table that cannot be read is not "no baselines": it is a table
        # that cannot be read, and the difference decides whether the sensor
        # is about to reseed and go quiet.
        return {"error": f"the {BASELINE_TABLE} table is unreadable: {e}",
                "baselines_present": None, "baseline_bytes": None,
                "note": ("The baseline table could not be read, so nothing "
                         "here says whether this sensor has ever run. If the "
                         "table is missing, the migrations have not run.")}
    for name in BASELINE_NAMES:
        out["baselines_present"][name] = name in present
        out["baseline_bytes"][name] = present.get(name, 0)
    return out
