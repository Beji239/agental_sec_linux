# tools/process_monitor.py
# AgentalSec, the SHARED process reads.
#
# WHAT THIS FILE IS NOW. 2026-09-25, THE WINDOWS-LEFTOVERS ROUND.
#
# This was the Windows tree's process MONITOR, carried into the Linux port as
# a module that nothing loaded. main.py has pointed the process_monitor ROLE
# at tools/process_monitor_linux.py since the port began, and it refuses to
# boot on anything else, so the class in this file had no caller: no thread,
# no findings, no rows. What kept it alive was the OTHER thing this file
# holds, which the whole Linux process page genuinely rests on:
#
#     list_processes, process_table, describe_process, inspect_process,
#     trust_of, signatures_for, _sha256_of, _package_owner_map,
#     odd_path_reason and the /proc readers behind them.
#
# Those are not Windows code. They were written against /proc, dpkg and rpm
# during the PM and PROC rounds, and both the Linux monitor and the Processes
# page import them from here.
#
# WHAT WAS REMOVED, and why each one was not a feature this platform lost:
#
#   class ProcessMonitor            the Windows poll loop: a name/path
#                                   whitelist of c:\ folders, a LOLBin
#                                   argument table of powershell.exe and
#                                   certutil.exe, and a Defender poll.
#   _check_defender                 Get-MpThreatDetection, through the
#                                   capability shim. Windows Defender does not
#                                   exist here and could never report.
#   the Defender readers            THREAT_STATUS, EXECUTION_STATUS,
#                                   DETECTION_SOURCE, THREAT_SEVERITY,
#                                   _parse_defender_payload, _group_detections,
#                                   _defender_severity/_title/_description.
#   Authenticode                    _PS_SIGNATURE, _check_chunk, _as_text,
#                                   _short_signer and the PowerShell half of
#                                   signatures_for. The Linux half that
#                                   REPLACED it (the package manager's own
#                                   recorded digests) is what this file calls
#                                   on every path now.
#   the Windows path lists          WHITELISTED_PATHS, SYSTEM_BINARY_ROOTS,
#                                   SYSTEM_ROOT_EXCEPTIONS, SUSPICIOUS_PATHS,
#                                   ODD_PATH_MARKERS, LOW_SIGNAL_PATHS and the
#                                   drive-letter rewrite in _resolve_path.
#
# THE ONE THAT MATTERED ON SCREEN. Nothing here raised a finding, but the
# SETTINGS CARD painted two permanent red rows for the Windows capabilities
# these imports implied -- see core/capabilities.py, where the removal and the
# measurement are written down. The card rows are gone with the code that
# justified them.
#
# WHAT REMAINS, IN THIS FILE'S OWN WORDS
#
# NOTE ON THE APPROACH. Matching on filename is the weakest signal in
# detection engineering, renaming the binary defeats it completely. The
# monitor that uses these reads catches careless behaviour and commodity
# tooling, not a competent attacker. Treat findings from it as leads, not
# verdicts.
#
# THE HASH. core/enrichment.py has had a "hash" lane since 2026-09-02, wired
# to MalwareBazaar. When a finding is raised about a process, the binary
# behind it gets a SHA-256 and the digest is queued for enrichment. Nothing
# else is hashed: hashing every process on a desktop every 60 seconds would be
# a lot of disk for a lookup that will almost always say "never seen it".
#
# AND WHAT IT DOES NOT ANSWER. This is a hash of the file ON DISK, right now.
# A process that was injected into hashes its innocent original, and one whose
# image was swapped after it started hashes the swap. It corroborates the
# disk, not the running image. There is no memory analysis in this tool.
#
# Unelevated, exe is empty for another account's processes, which
# core/privilege_linux registers as the monitor DEGRADING. That shows up here
# as a reason string rather than a silent absence.

import hashlib
import json
import logging
import os
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not available, process monitoring disabled")

from core import enrichment
from core import capabilities as caps
from core import memory_engine as me

POLL_INTERVAL = 60

# Bound on the process-identity cache. ~20k covers any desktop; beyond that
# we evict oldest-first rather than growing forever. The Linux monitor keeps
# its own copy of this bound; both are the same number for the same reason.
MAX_SEEN_PROCS = 20000

# THE HASH
#
# core/enrichment.py has had a "hash" lane since 2026-09-02, wired to
# MalwareBazaar, and nothing in this project ever produced a hash to put in
# it. The lookup could only answer if a person typed a hash into the chat. So
# the intake existed and the feeder did not, which is a fair description of
# nothing at all.
#
# WHAT THIS DOES. When a finding is raised about a process, the binary behind
# it gets a SHA-256 and the digest is queued for enrichment. Nothing else is
# hashed. Hashing every process on a desktop every 60 seconds would be a lot
# of disk for a lookup that will almost always say "never seen it".
#
# WHAT A HIT AND A MISS EACH MEAN, because they are not symmetric and the
# miss is the one people misread:
#
#   a hit    the file is a known malware sample. That is a real finding.
#   a miss   MalwareBazaar has not been sent this file. Almost nothing is in
#            it. A miss is not a clean bill and must never be written up as
#            one, which is why "sha256_unavailable" says why a hash is
#            missing rather than leaving a null that reads as fine.
#
# AND WHAT IT DOES NOT ANSWER. This is a hash of the file ON DISK, right now.
# A process that was injected into hashes its innocent original, and one
# whose image was swapped after it started hashes the swap. It corroborates
# the disk, not the running image. There is no memory analysis in this tool
# and a hash does not add any.
#
# Unelevated, exe is empty for another account's processes, which
# core/privilege_linux registers as the monitor DEGRADING. That shows up here
# as a reason string rather than a silent absence.
MAX_HASH_BYTES = 256 * 1024 * 1024   # past this the read costs more than the answer
MAX_HASH_CACHE = 5000
_HASH_CACHE = OrderedDict()          # (path, size, mtime) -> sha256


# THE PATH
#
# WHAT THIS USED TO BE AND WHY IT IS NOT ANY MORE. 2026-09-25.
#
# This section was a Windows path RESOLVER: it rewrote a drive-relative
# "\\Windows\\System32\\x.exe" into "c:\\windows\\system32\\x.exe", translated
# the \\SystemRoot form, unwrapped \\?\ and \\?\UNC\ prefixes, and returned a
# note about the privilege split for anything without a drive letter. Every
# one of those is a fact about Windows, and the lists it fed were hand-written
# c:\ paths.
#
# PM-9, 2026-09-23, caught it running on Linux: /usr/bin/ls came back as the
# comparable path "c:\usr\bin\ls" carrying a reassurance about a privilege
# split this platform does not have, printed on every row of the page. The
# fix then was to branch on the platform. This round removes the Windows half
# outright, because nothing here can reach it.
#
# WHAT REMAINS IS THE ONLY QUESTION THIS PLATFORM ASKS: which folder is this
# executable in, in plain words. The list of folders worth a second look is
# ODD_PATH_MARKERS_LINUX, further down, and it is matched on path COMPONENTS
# rather than by substring.
#
# A LINUX PATH ARRIVES IN ITS OWN SHAPE AND NEEDS NO TRANSLATION. What is
# left of this function is the shape check that keeps an unplaceable path
# unplaceable, which is the oldest rule on this page: unknown is not bad, and
# a path we could not read must never be the thing that turns a row amber.


def _resolve_path(path: str) -> tuple[str, str | None]:
    """
    Give back a comparable lowercase path, plus a note when one was assumed.

    Returns (comparable_path_or_empty, note_or_None). An EMPTY first value
    means we could not place this file at all, and every caller treats that as
    unknown rather than as bad. A path we cannot read must never be the thing
    that raises a HIGH alert.
    """
    p = (path or "").strip()
    if not p:
        return "", "no executable path was readable"
    if p.startswith("/"):
        return p.lower(), None
    return "", f"the path form was not recognised: {p[:80]}"


def _basename(path: str) -> str:
    if not path:
        return ""
    return os.path.basename(path).lower()


def _sha256_of(path: str) -> tuple[str | None, str | None]:
    """
    (digest, why_there_isn_t_one). Never raises, and never returns None with
    no reason. A missing hash with no explanation reads as "fine", and this
    file has been bitten by that shape of silence before.

    Cached on (path, size, mtime) so a binary that has not changed is read
    once. Bounded like _seen_procs.
    """
    if not path:
        return None, ("no executable path. Unelevated runs cannot read this "
                      "for another account's process, or it had already exited")
    try:
        st = os.stat(path)
    except OSError as e:
        return None, f"could not stat the file ({type(e).__name__})"

    if st.st_size > MAX_HASH_BYTES:
        return None, (f"file is {st.st_size} bytes, over the "
                      f"{MAX_HASH_BYTES} byte hashing cap")

    key = (path.lower(), st.st_size, int(st.st_mtime))
    cached = _HASH_CACHE.get(key)
    if cached:
        _HASH_CACHE.move_to_end(key)
        return cached, None

    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError as e:
        return None, f"could not read the file ({type(e).__name__})"

    digest = h.hexdigest()
    _HASH_CACHE[key] = digest
    while len(_HASH_CACHE) > MAX_HASH_CACHE:
        _HASH_CACHE.popitem(last=False)
    return digest, None


# FITTING THE ANSWER, 2026-09-13. Measured, not guessed.
#
# A tool answer is serialised and then cut at sanitize.MAX_RESULT_LEN, and
# the cut lands wherever it lands, mid row, mid string, with no count of what
# went missing. On a real machine a 200 row answer weighed 112,520 characters
# against a 60,000 budget, so 124 processes were vanishing on EVERY call and
# the list still read as complete. The tool whose whole job is answering
# "what is running" could see about a quarter of it and said nothing.
#
# What made it heavy was not the processes, it was the command lines: 39 of
# 288 were over 2,000 characters, almost all of them browser renderers
# carrying thousands of characters of Chromium flags.
#
# So the COMMAND LINE is what shrinks and the ROW is the last thing to go. A
# shortened command line still tells you a process exists and says how much
# is missing. A dropped row is a process nobody hears about at all.
#
# The steps are tried in order until the answer fits. None means do not
# shorten. The numbers are not load bearing: if a machine needs smaller it
# takes the next step down on its own, and if even the smallest does not fit
# it drops rows and says exactly how many.
LIST_CMDLINE_STEPS = (None, 1000, 600, 300, 150)

# Room left for the envelope execute_tool wraps around this, the fence
# markers, and the fact that scrubbing and JSON escaping both change lengths
# a little. Better to come in under the budget than to discover the cut.
RESULT_HEADROOM = 4000


def _list_budget() -> int:
    """Characters this answer may weigh. Read from sanitize so one number
    governs, rather than a copy here that drifts when that one moves."""
    try:
        from core.sanitize import MAX_RESULT_LEN
    except Exception:
        return 56000
    return max(4000, MAX_RESULT_LEN - RESULT_HEADROOM)


def _weigh(obj) -> int:
    return len(json.dumps(obj, default=str))


def _shorten_cmdlines(rows, cap):
    """
    Copy of rows with every command line over cap cut, each one saying how
    much is missing and where the rest lives.

    The marker is not decoration. A cut command line that reads like a whole
    one is how somebody concludes a process is not doing the thing that was
    in the part they never saw.
    """
    out = []
    for row in rows:
        cmd = row.get("cmdline")
        if cmd and len(cmd) > cap:
            row = dict(row)
            # Terse on purpose. The full explanation goes in the answer's
            # note, once, and repeating it on 39 rows was costing 4,000
            # characters of the very budget this is trying to save.
            row["cmdline"] = (cmd[:cap] +
                              f" ...[+{len(cmd) - cap} chars, ask by pid]")
        out.append(row)
    return out


def _fit_process_rows(rows, budget):
    """
    Make the answer fit, and say what was done to it.

    Returns (rows, note). note is None only when nothing was changed. The
    input list is never modified.

    Rows are dropped ONLY when even the shortest command line does not fit,
    and then the note says how many and how to reach them. There is no path
    through this function that loses a process quietly.
    """
    if not rows:
        return rows, None

    for cap in LIST_CMDLINE_STEPS:
        candidate = rows if cap is None else _shorten_cmdlines(rows, cap)
        if _weigh(candidate) <= budget:
            if cap is None:
                return candidate, None
            shortened = sum(1 for r in candidate
                            if (r.get("cmdline") or "").endswith("ask by pid]"))
            return candidate, (
                f"Every running process is in this list. {shortened} command "
                f"line(s) were shortened to {cap} characters to fit, and each "
                f"one says how much is missing. Nothing was left out. Ask by "
                f"pid for a whole command line.")

    # Even the smallest step does not fit, so rows have to go. Say so with
    # numbers rather than letting the serialiser cut the tail off in silence.
    candidate = _shorten_cmdlines(rows, LIST_CMDLINE_STEPS[-1])
    # The two brackets, then each row plus its separator. json.dumps writes
    # ", " between items, two characters, not one. Counting one was an
    # undercount that grew with the row count and put the answer back over
    # the budget, which is the failure this whole function exists to stop.
    # Caught by the test, not by reading it.
    kept, used = [], 2
    for row in candidate:
        size = _weigh(row) + 2
        if used + size > budget:
            break
        kept.append(row)
        used += size
    missing = len(candidate) - len(kept)
    return kept, (
        f"THIS LIST IS INCOMPLETE. {len(kept)} of {len(candidate)} processes "
        f"are here and {missing} did not fit, even with every command line "
        f"cut to {LIST_CMDLINE_STEPS[-1]} characters. The ones missing are "
        f"the end of the list in name order. Do NOT read this as everything "
        f"that is running. Ask again with name= or pid= to reach the rest.")


def list_processes(pid=None, name=None, limit=500):
    """
    What is running, or what one PID is.

    pid    exactly one process, or an empty list if it is gone
    name   substring match on the process name, case insensitive
    limit  a ceiling, because a machine has hundreds and the model does not
           need all of them to answer a question about one

    Enumerating processes needs no rights, so it happens here. Only the
    fields this process is refused go through the privileged shim, one call
    for all of them, exactly as the monitor already does.
    """
    if not PSUTIL_AVAILABLE:
        return {"available": False,
                "reason": "psutil is not installed, so nothing here can see "
                          "the process table. This is not an empty machine.",
                "processes": []}

    try:
        limit = max(1, min(int(limit or 500), 2000))
    except (TypeError, ValueError):
        limit = 500

    if pid is not None:
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return {"available": True, "processes": [],
                    "note": f"pid must be a number, got {pid!r}"}

    wanted = (name or "").strip().lower()
    rows = []
    matched = 0
    for p in psutil.process_iter(["pid", "name", "exe", "ppid", "username",
                                  "cmdline", "create_time"]):
        info = p.info
        if pid is not None and info.get("pid") != pid:
            continue
        if wanted and wanted not in (info.get("name") or "").lower():
            continue
        matched += 1
        # KEEP COUNTING PAST THE LIMIT. 2026-09-13. It used to break here, so
        # "capped at 200" was all it could say and 200 was the only number it
        # knew. Counting to the end costs one more loop over an in-memory
        # list and lets the answer say 200 OF 295, which is the difference
        # between a cap and a mystery.
        if pid is None and len(rows) >= limit:
            continue
        rows.append(info)

    _fill_details(rows)

    # PM-3, 2026-09-23. THE ROW CARRIES WHICH RIGHTS PRODUCED IT.
    #
    # Measured on this host, unelevated: 146 of 234 processes have no readable
    # exe, and the page said, about nine of them, "this process has no
    # executable path on disk, so there was no file to compare against any
    # package record" — while every one of those files is on disk and readable
    # by root. The note told the owner a fact about the MACHINE (nothing there)
    # when the fact is about RIGHTS (not readable by me), and it contradicted
    # the page's own legend two inches above it.
    #
    # The same daemon is not grey on a different load: the LNX-1102 rows in the
    # live store carry a real path for systemd-journald, written by an
    # ELEVATED run. So the row has to say which load produced it, or the two
    # surfaces contradict each other on the same screen with nothing to
    # explain the difference. That is the TM-4 shape ("null meant both clean
    # and could not look"), one tool over.
    from core import privilege_linux as _priv
    elevated = _priv.is_elevated()

    out = []
    for info in rows:
        started = info.get("create_time")
        exe = info.get("exe") or None
        cmdline = " ".join(info.get("cmdline") or []) or None
        refusal = None
        if not exe:
            # WHY there is no path, in the kernel's own words wherever we have
            # them. A refused read and a process that genuinely has no file are
            # different sentences and they used to be the same one.
            refusal = _exe_refusal_note(info.get("pid"), elevated)
        out.append({
            "pid": info.get("pid"),
            "name": info.get("name"),
            "exe": exe,
            "parent_pid": info.get("ppid"),
            "username": info.get("username") or None,
            "cmdline": cmdline,
            # PM-12. UTC WITH AN OFFSET, the same base the app's tables use and
            # the same base the Linux sensor uses. This read `fromtimestamp(t)`
            # with no timezone, so the field the MODEL reads was local time with
            # no offset and could not be compared with any other timestamp in
            # the app. Measured: the same process came back seven hours apart
            # from the two modules, and neither said which clock it was on.
            "started": (datetime.fromtimestamp(
                started, tz=timezone.utc).isoformat(timespec="seconds")
                if started else None),
            # The refusal travels with the row, and it is None when there was
            # nothing to refuse. A caller reading this field gets a fact rather
            # than having to infer one from a null.
            "exe_refusal": refusal,
        })
    out.sort(key=lambda r: (r["name"] or "").lower())

    # Fit the answer to what will actually reach the model, and carry back
    # whatever had to be done to it. See _fit_process_rows.
    out, fit_note = _fit_process_rows(out, _list_budget())

    answer = {"available": True, "count": len(out), "processes": out}
    if pid is None:
        answer["running_total"] = matched
    notes = []
    if fit_note:
        notes.append(fit_note)
    if pid is not None and not out:
        # AN EMPTY ANSWER HERE HAS A MEANING AND IT IS NOT "NOTHING TO SEE".
        # Either the process ended, or the PID never existed. Both are worth
        # saying out loud, because the caller is usually about to act on it.
        notes.append(f"No process with PID {pid} is running right now. "
                     f"Either it has exited or that PID was never live. "
                     f"Do not treat this as a process that is fine.")
    if pid is None and matched > len(out):
        # The limit, said with both numbers. "Capped at 200" never told
        # anyone whether 200 was all of them or a third of them.
        notes.append(f"{len(out)} of {matched} processes are in this answer, "
                     f"because limit is {limit}. This is NOT everything that "
                     f"is running. Raise limit, or ask with name= or pid=.")
    if notes:
        answer["note"] = " ".join(notes)
    return answer


def describe_process(pid):
    """
    One process, or None. Used by the approval card so a person is shown a
    NAME rather than a bare number before they press approve.
    """
    got = list_processes(pid=pid)
    rows = got.get("processes") or []
    return rows[0] if rows else None


def _exe_refusal_note(pid, elevated) -> str:
    """
    PM-3. WHY there is no executable path for this row, in words that name the
    kernel's own refusal.

    The old note was one canned sentence, "this process has no executable path
    on disk, so there was no file to compare against any package record", which
    is a claim about the MACHINE. Measured on this host, all nine rows carrying
    it had a file on disk and readable by root: the fact was about RIGHTS.

    This asks the kernel directly, so the sentence is a measurement rather than
    a guess, and it names which rights the load ran with. A refused read and a
    process that genuinely has no file are different sentences, and the
    difference is the whole reason this exists.
    """
    if pid is None:
        return "this row has no pid, so nothing could be asked about its file"

    try:
        target = os.readlink(f"/proc/{int(pid)}/exe")
    except PermissionError:
        return ("the executable path was REFUSED by the kernel: this account "
                "may not read /proc/<pid>/exe for a process it does not own "
                "(PermissionError). The file exists; the read is what failed. "
                + ("This load runs ELEVATED, so the refusal is from a kernel "
                   "protection rather than from a missing right."
                   if elevated else
                   "Run the app elevated to read it, or read the process's own "
                   "command line below, which needs no rights."))
    except FileNotFoundError:
        return ("the process ended between the listing and this read, so there "
                "is nothing on disk TO read any more. That is not a refusal.")
    except OSError as e:
        return (f"the executable path could not be read ({type(e).__name__}: "
                f"{e}), and this is a read failure rather than a missing file")

    # It read fine — so the exe field is missing for some OTHER reason and the
    # note says which, rather than reusing the sentence that was wrong.
    return (f"the kernel reports this process is running {target}, but psutil "
            f"did not hand back a path for it. That is a gap in the reading, "
            f"not a fact about the file.")


def _fill_details(rows):
    """
    Same trick as _fill_privileged_fields on the monitor: ask the shim only
    about the ones we were refused. Never fatal, an empty field already
    reads as unknown.
    """
    missing = [r.get("pid") for r in rows
               if r.get("pid") and not r.get("cmdline") and not r.get("exe")]
    if not missing:
        return
    try:
        extra = caps.get().process_details(missing)
    except Exception as e:
        logger.debug(f"process_details unavailable, fields stay empty: {e}")
        return
    for info in rows:
        got = extra.get(info.get("pid"))
        if not got:
            continue
        info["exe"] = info.get("exe") or got.get("exe")
        info["cmdline"] = info.get("cmdline") or got.get("cmdline")
        info["username"] = info.get("username") or got.get("username")


# LOOKING AT A PROCESS PROPERLY
#
# Added 2026-09-08, TODO 68, the owner's call.
#
# list_processes reads the LABEL on a process: name, path, owner, parent,
# command line. That is the Task Manager view and it is genuinely useful, but
# it is not examining anything. Two cheap things turn "this exe is in a temp
# folder, that is odd" into something a person can act on:
#
#   1. THE HASH, and whether anyone has ever seen this exact binary before.
#      The monitor already hashes and enrichment already asks MalwareBazaar
#      about hashes. Neither was reachable per process, on demand.
#   2. THE SIGNATURE. Signed by Microsoft, versus unsigned and sitting in
#      AppData, is one of the strongest cheap signals there is, and it needs
#      no administrator rights.
#
# DELIBERATELY NOT HERE:
#   * Asking Defender to scan the file. It scanned it when it landed and when
#      it ran, and we already read Defender's own detections. Slower, same
#      answer.
#   * Reading process memory. Different class of tool, and it means parsing
#     hostile bytes inside our own process, which is the exact thing the
#     privilege split is trying to shrink. The owner's call too, and the owner is right.
#
# ON DEMAND, PER PROCESS. Hashing three hundred executables is minutes of
# disk, and it would go in front of an answer nobody asked for. The listing
# stays cheap, this is the follow up on the two or three that look odd.

import subprocess as _sp
# tempfile was imported here for the PowerShell signature sweep, which is gone.
# Nothing in this file writes a temporary file any more.

# WHERE A RUNNING BINARY IS WORTH A SECOND LOOK, ON THIS PLATFORM
#
# The amber half of the Processes page's colour rests on this list. It used to
# be a Windows list (\\appdata\\local\\temp\\, \\windows\\tasks\\, \\$recycle.bin\\
# and friends) which on this platform could not name /dev/shm or a user cache
# -- two of the three places a Linux dropper actually lives -- while the
# SENSOR knew about both. Two lists, one idea, and only one of them was written
# for the platform it ran on.
#
# Measured before that fix landed, on this host:
#     /tmp/dropper                 -> "a temp folder"      (right, by accident)
#     /var/tmp/y                   -> "a temp folder"      (wrong folder)
#     /dev/shm/x                   -> None                 SHOULD BE AMBER
#     /home/<user>/.cache/implant  -> None                 SHOULD BE AMBER
#
# The entries are matched against path COMPONENTS, not by substring, so
# "/home/x/shipped/" cannot match "~/shipped" the way "/tmp/" matched
# "/var/tmp/". Nothing goes in here that the row cannot say out loud.
ODD_PATH_MARKERS_LINUX = (
    ("/.cache/",        "a user cache directory (a favourite place for dropped "
                        "files: a program has no business running from one)"),
    ("/.local/share/",  "a user data directory (installed software does not "
                        "live here)"),
    ("/dev/shm/",       "shared memory (it lives in RAM and does not survive a "
                        "reboot, which is why dropped files are put there)"),
    ("/var/tmp/",       "the /var/tmp folder (a temp folder whose contents "
                        "survive a reboot)"),
    ("/tmp/",           "a temp folder"),
    ("/run/user/",      "a per-user runtime directory (a program has no "
                        "business running from one)"),
    ("/downloads/",     "a Downloads folder"),
) 


def odd_path_reason(path):
    """
    Plain words for the folder this executable sits in, when it is one worth
    a second look. None when it is not, and None when the path could not be
    placed at all.

    Unplaceable returns None on purpose, the same rule
    _is_plausible_system_location follows. A path we could not read must never
    be the thing that turns a row amber. Unknown is not bad.

    The path is resolved first so this asks its question against the same
    shape every other path check in this file does: a lowercased absolute
    path, matched on path COMPONENTS (see _linux_odd_reason). The question
    "is this file inside a directory called tmp" is not the question "does the
    string /tmp/ occur in this path", and conflating the two is how /var/tmp/y
    was reported as /tmp/ and how the glob entries in the sensor could never
    fire at all.
    """
    p, _note = _resolve_path(path)
    if not p:
        return None
    return _linux_odd_reason(p)


def _linux_odd_reason(path_lower: str):
    """
    The Linux half of odd_path_reason: matched on COMPONENTS, longest first.

    A component match rather than a substring one is the whole difference
    between "/var/tmp/y is in /var/tmp" and "/var/tmp/y is in /tmp". Both facts
    matter: the label has to be right, and a directory named "tmp" at the root
    is not the same thing as a file whose name happens to contain the letters.
    """
    parts = [c for c in path_lower.split("/") if c]
    for marker, words in ODD_PATH_MARKERS_LINUX:
        seg = [c for c in marker.split("/") if c]
        if not seg:
            continue
        # Every ancestor of the file is a directory prefix of its components;
        # the marker must match one of those prefixes, whole.
        for i in range(len(parts) - 1):
            if parts[i:i + len(seg)] == seg:
                return words
    return None


# HOW A FILE IS CHECKED HERE: WHAT THE PACKAGE MANAGER RECORDED
#
# 2026-09-23. THE DEFECT THIS SECTION EXISTS FOR. Every row on the Processes
# page was grey, which this app uses for "could not be read". Measured on the
# owner's machine: 214 of 214 rows, and the page's own summary line said, in
# words, that signature checking only works on Windows.
#
# Linux has no Authenticode, and the honest thing is not to keep asking for
# one. What this platform HAS is a stronger answer for the question the page
# is really asking -- "is this still the file that came with this machine":
# the package manager knows which package owns a file and keeps a digest of
# every file that package installed, so the comparison is about CONTENT rather
# than about a vendor name.
#
# A file no package owns is ordinary on a machine where people build software,
# and it is a reason to look, exactly as an unsigned binary is on Windows.
# That is the existing amber branch of trust_of, reused rather than reinvented.
#
# THE ANSWERS, KEPT APART ON PURPOSE, the rule everywhere else in this file:
#
#   Valid         the file on disk matches the digest dpkg recorded
#   HashMismatch  it does not — the case this page exists for
#   NotSigned     no installed package claims it, so there is no record
#   unknown       there was nothing to compare, and the note says why, never
#                 a shrug
#
# AND A FOURTH THING THAT IS NOT A FAILURE: a kernel thread has no executable
# file at all and no command line. Saying that is a fact about it, not a
# failure to read it. See _is_kernel_thread.
#
# COST, MEASURED ON THE OWNER'S MACHINE 2026-09-23 before any of this was
# written: 90 running executables, 201 MB between them, md5 over all of them
# 0.98 s, and 54 package records read in 1.97 s. The listing stays cheap, like
# every other listing here, and the expensive half is cached on
# (path, size, mtime).
#
# THE CAP IS 256 MB AND THAT NUMBER IS MEASURED TOO. The first version used
# 32 MB and it left two rows grey for a reason that was about this file rather
# than about the machine: /usr/bin/dockerd is 111 MB and /usr/bin/containerd is
# 43 MB, and on a box that runs containers those are two of the binaries most
# worth knowing about. Read whole, the whole set costs 0.60 s. A cap that
# produces "could not be read" for the two biggest things on the machine is a
# cap that has become the grey it was written to avoid.
_SIG_CACHE = OrderedDict()           # (path, size, mtime) -> {"status":..., "signer":...}
MAX_SIG_CACHE = 2000

MAX_VERIFY_BYTES = 256 * 1024 * 1024    # the hashing cap, reused
_PKG_CHECK_DEADLINE = 8.0               # seconds for the whole verify pass
_HASH_WORKERS = min(8, (os.cpu_count() or 2) * 2)   # disk reads overlap (PM-C1)

_PKG_TOOL = {"looked": False, "name": None, "path": None}
_MD5SUMS = OrderedDict()                # package -> {registered path: md5}
MAX_MD5SUMS_PACKAGES = 600


def _package_tool():
    """
    ("dpkg"|"rpm", path) for the package manager that can answer here, or
    None. Looked up once.

    Kept as a function rather than a module constant because the answer is a
    fact about the host, not about this file, and a host can be rebuilt under
    a running install.
    """
    if not _PKG_TOOL["looked"]:
        _PKG_TOOL["looked"] = True
        for name in ("dpkg-query", "rpm"):
            for directory in ("/usr/bin", "/bin", "/usr/local/bin"):
                candidate = os.path.join(directory, name)
                if os.path.exists(candidate):
                    _PKG_TOOL["name"], _PKG_TOOL["path"] = name, candidate
                    break
            if _PKG_TOOL["path"]:
                break
    return ((_PKG_TOOL["name"], _PKG_TOOL["path"])
            if _PKG_TOOL["path"] else None)


def _dpkg_query_path():
    """The dpkg-query binary, or None. None means this is not a dpkg host."""
    tool = _package_tool()
    return tool[1] if tool and tool[0] == "dpkg-query" else None


def _package_owner_map(paths):
    """
    {registered path: package} for the paths an installed package owns.

    ONE dpkg CALL FOR THE WHOLE LIST, and the measurement is why: a dpkg-query
    -S call costs about two seconds whatever is in it, because the cost is
    dpkg's own scan of its file database rather than the number of patterns.
    Asked one path at a time, a 260-process table took long enough that the
    first version of this timed out at three minutes. Asked all at once it is
    the same two seconds. Same lesson as the Windows signature sweep, arrived
    at from the other direction.

    THE REAL PATH IS WHAT GETS ASKED, and that is not a detail: PID 1 runs
    /sbin/init, which is a symlink to /usr/lib/systemd/systemd, and dpkg has
    never heard of /sbin/init. Asked with the raw path the two most important
    processes on the machine (systemd and every getty) come back "no package
    claims this", which is false. The same class of bug as the Windows tree's
    drive-letter work: two places doing their own string handling on a path.

    Never raises. An empty map means the question could not be asked, and
    every caller here treats that as unknown rather than as unowned.
    """
    tool = _package_tool()
    if not tool or not paths:
        return {}
    name, binary = tool
    owner = {}

    wanted = []
    for path in paths:
        if not path:
            continue
        real = os.path.realpath(path)
        if real not in wanted:
            wanted.append(real)
        if path not in wanted:
            wanted.append(path)

    # Chunked by COUNT, not by time. A path can be 200 characters and the
    # caller's limit goes to 2000, so this stays well inside any ARG_MAX
    # without having to know what ARG_MAX is on this host.
    for i in range(0, len(wanted), 500):
        chunk = wanted[i:i + 500]
        try:
            if name == "dpkg-query":
                run = _sp.run([binary, "-S", "--"] + chunk,
                              capture_output=True, text=True, timeout=60)
                text = run.stdout or ""
            else:
                run = _sp.run([binary, "-qf", "--qf", "%{NAME} %{FILENAMES}\n"]
                              + chunk, capture_output=True, text=True, timeout=60)
                text = run.stdout or ""
                for line in text.splitlines():
                    pkg, _, owned = line.partition(" ")
                    if pkg and owned:
                        owner[owned.strip()] = pkg
                continue
        except Exception as e:
            logger.debug(f"package lookup failed for a batch: {e}")
            continue
        for line in text.splitlines():
            line = line.strip()
            # A diversion is not an owner, and dpkg says so in its own shape:
            # "diversion by <pkg> from: /path".
            if not line or "diversion" in line:
                continue
            pkg, _, owned = line.partition(": ")
            if pkg and owned:
                # "libc6:amd64" and "libc6" name one package; the record files
                # and the display name use the plain one.
                owner[owned.strip()] = pkg.split(":")[0]
    return owner


def _md5sums_for(package):
    """
    {registered path: md5} from the package's own record, cached.

    These are the files dpkg wrote when it installed the package. Readable
    unelevated, and their absence is itself an answer: a package can keep no
    record, and then nothing can be compared rather than everything being
    "fine".
    """
    cached = _MD5SUMS.get(package)
    if cached is not None:
        _MD5SUMS.move_to_end(package)
        return cached

    out = {}
    for candidate in (package, package.split(":")[0]):
        record = f"/var/lib/dpkg/info/{candidate}.md5sums"
        try:
            with open(record, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    digest, _, rel = line.rstrip("\n").partition("  ")
                    rel = rel.strip()
                    if digest and rel:
                        out["/" + rel.lstrip("/")] = digest.strip().lower()
        except OSError:
            continue
        if out:
            break

    _MD5SUMS[package] = out
    while len(_MD5SUMS) > MAX_MD5SUMS_PACKAGES:
        _MD5SUMS.popitem(last=False)
    return out


def _md5_of(path):
    """(digest, why_there_is_not_one). Never raises, never silent."""
    try:
        st = os.stat(path)
    except OSError as e:
        return None, f"the file could not be read ({type(e).__name__})"
    if st.st_size > MAX_VERIFY_BYTES:
        return None, (f"the file is {st.st_size} bytes, over the "
                      f"{MAX_VERIFY_BYTES} byte verification cap")
    try:
        h = hashlib.md5()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError as e:
        return None, f"the file could not be read ({type(e).__name__})"
    except Exception as e:
        # FIPS mode refuses md5, and a refusal to hash is not a clean file.
        return None, f"the digest could not be taken ({type(e).__name__})"
    return h.hexdigest(), None


def _hash_in_parallel(fresh, owners):
    """
    {real path: (digest, why)} for every packaged file in the batch.

    Each distinct file is hashed once, on several threads, within
    _PKG_CHECK_DEADLINE. A file not done in time is left out, and its row
    says "not checked yet" (PM-C1).
    """
    todo = []
    for path, _key in fresh:
        real = os.path.realpath(path)
        if real not in todo and (owners.get(real) or owners.get(path)):
            todo.append(real)
    if not todo:
        return {}
    pool = ThreadPoolExecutor(max_workers=_HASH_WORKERS,
                              thread_name_prefix="pkg-hash")
    futures = {pool.submit(_md5_of, real): real for real in todo}
    done, _pending = wait(futures, timeout=_PKG_CHECK_DEADLINE)
    pool.shutdown(wait=False, cancel_futures=True)
    return {futures[f]: f.result() for f in done}


def _linux_signatures(out, fresh, stats):
    """
    The Linux half of signatures_for: what the package manager can say about
    each file, in the same answer shape the Windows sweep uses.

    Statuses reuse the Windows vocabulary because trust_of reads it and
    everything downstream is written against it: Valid and HashMismatch mean
    what they say, NotSigned is "no installed package owns this file". The
    words beside them are Linux words, and `label` carries the sentence the
    page prints.
    """
    tool = _package_tool()
    if not tool:
        for path, _key in fresh:
            out[path] = {
                "status": "unknown", "signer": None, "kind": "none",
                "package": None, "label": None,
                "note": ("no package manager on this host can say where a "
                         "file came from, so nothing was compared")}
            stats["failed"] += 1
        return out

    owners = _package_owner_map([p for p, _k in fresh])
    digests = _hash_in_parallel(fresh, owners)

    for path, key in fresh:
        real = os.path.realpath(path)
        package = owners.get(real) or owners.get(path)

        if not package:
            answer = {
                "status": "NotSigned", "signer": None, "kind": "package",
                "package": None, "label":
                    ("no installed package claims this file, so there is no "
                     "record of what it should be. Ordinary for software "
                     "installed by hand, worth a look from a temporary "
                     "folder")}
        else:
            if real not in digests:
                out[path] = {
                    "status": "unknown", "signer": None, "kind": "package",
                    "package": package, "label": None,
                    "note": ("not checked yet, the sweep ran out of time. "
                             "Refresh and it will carry on from here")}
                stats["not_reached"] += 1
                continue
            record = (_md5sums_for(package).get(real)
                      or _md5sums_for(package).get(path))
            if not record:
                answer = {
                    "status": "unknown", "signer": None, "kind": "package",
                    "package": package, "label": None,
                    "note": (f"the {package} package is installed but keeps "
                             f"no digest record for this file, so there was "
                             f"nothing to compare")}
            else:
                digest, why = digests[real]
                if digest is None:
                    answer = {
                        "status": "unknown", "signer": None, "kind": "package",
                        "package": package, "label": None,
                        "note": f"{why}, so nothing was compared"}
                elif digest.lower() == record:
                    answer = {
                        "status": "Valid", "signer": package, "kind": "package",
                        "package": package, "label":
                            (f"matches the {package} package installed on "
                             f"this machine: this is the file that package "
                             f"shipped")}
                else:
                    answer = {
                        "status": "HashMismatch", "signer": package,
                        "kind": "package", "package": package, "label":
                            (f"NOT what the {package} package shipped: the "
                             f"file on disk does NOT match the digest the "
                             f"package recorded for it. Either something "
                             f"changed it or the package was unpacked over "
                             f"it")}
        if answer["status"] == "unknown":
            stats["failed"] += 1
        else:
            stats["checked"] += 1
        _SIG_CACHE[key] = answer
        while len(_SIG_CACHE) > MAX_SIG_CACHE:
            _SIG_CACHE.popitem(last=False)
        out[path] = answer
    return out


def _is_kernel_thread(row):
    """
    True for a kernel thread, and only for one.

    A kernel thread is exactly this: no executable file of its own, no
    command line, and it is either kthreadd itself or a child of kthreadd.
    Measured on this machine, all 106 of them satisfy the rule and nothing
    else does.

    EVERY OTHER PART OF THE RULE IS LOAD BEARING. A process with a command
    line but no readable path is a process we were REFUSED, which is not the
    same thing at all — every other account's daemon looks like that.
    (sd-pam) on this machine is the owner's own process with a command line
    and a denied exe, and calling it a kernel thread would be a lie told to
    make a page look tidier. See the control checks in
    tests/test_process_color_linux.py.
    """
    if row.get("exe") or row.get("cmdline"):
        return False
    pid = row.get("pid")
    parent = row.get("parent_pid", row.get("ppid"))
    return pid == 2 or parent == 2


def signatures_for(paths, stats=None):
    """
    What this machine's package manager recorded about a batch of executables,
    cached.

    THE SHAPE OF THE ANSWER IS THE OLD ONE ON PURPOSE. Every caller downstream
    -- trust_of, the Processes page, the model's own tool description -- reads
    {"status", "signer", "note"}, so the vocabulary is kept and the SENTENCE
    inside it is this platform's: Valid means the file matches the digest its
    package recorded, HashMismatch means it does not, NotSigned means no
    installed package claims it. See the section above for why the package
    manager is the better basis for the question this page asks.

    ONE BATCHED PASS, not one call per file: dpkg-query -S costs the same
    whether it is handed one path or a thousand, because the cost is dpkg
    scanning its own file database, and the records are cached on
    (path, size, mtime) so a second look is a dictionary read.

    Returns {path: {"status": ..., "signer": ..., "note": ...}}. A path we
    could not check comes back with a note saying why, never missing.
    """
    out = {}
    fresh = []
    stats = stats if stats is not None else {}
    stats.setdefault("cached", 0)
    stats.setdefault("checked", 0)
    stats.setdefault("failed", 0)
    stats.setdefault("not_reached", 0)
    for path in paths:
        if not path:
            continue
        key = _sig_key(path)
        if key is None:
            # AND IT IS COUNTED. FOUND 2026-09-25, IN THIS ROUND'S OWN
            # RE-WRITTEN TEST.
            #
            # A path that cannot be stat'd was returned as a row with a reason
            # and incremented NOTHING: not checked, not cached, not failed, not
            # unreached. Measured on a two-path batch where one file did not
            # exist: two rows came back, the stats said checked=1 failed=0, and
            # the sentence the operator reads on the page said "1 file(s)
            # compared with the digest their package recorded" -- with no
            # mention that a row on that same page is grey BECAUSE the file
            # could not be read.
            #
            # It is the same fault this project keeps finding: a count that is
            # right about the case it was written for and silent about the
            # other one. `failed` already means "could not be checked, and the
            # row says why", which is exactly this case.
            out[path] = {"status": "unknown", "signer": None, "kind": None,
                         "package": None, "label": None,
                         "note": "the file could not be read, so it could not "
                                 "be checked"}
            stats["failed"] += 1
            continue
        cached = _SIG_CACHE.get(key)
        if cached:
            _SIG_CACHE.move_to_end(key)
            out[path] = cached
            stats["cached"] += 1
        else:
            fresh.append((path, key))

    if not fresh:
        return out

    return _linux_signatures(out, fresh, stats)


def _sig_key(path):
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (path.lower(), st.st_size, int(st.st_mtime))


def inspect_process(pid, session_id=None):
    """
    One process, looked at rather than listed.

    Gives back the label (from list_processes), the sha256, what the
    signature says, and whatever reputation is already known for that hash.

    The reputation lookup is the same non-blocking pattern the rest of the
    app uses: a cached answer comes back now, an unknown hash gets queued and
    the caller is told to look again. Nothing here waits on the network.
    """
    got = list_processes(pid=pid)
    if not got.get("processes"):
        return {"found": False, "pid": pid,
                "note": got.get("note") or f"No process with PID {pid} is running."}

    row = dict(got["processes"][0])
    exe = row.get("exe")

    sha256, hash_note = _sha256_of(exe) if exe else (None, "no executable path")
    row["sha256"] = sha256
    row["sha256_unavailable"] = hash_note

    sig = signatures_for([exe]).get(exe, {}) if exe else {
        "status": "unknown", "signer": None,
        "note": "no executable path to check"}
    row["signature"] = sig

    # Reputation, only if we have something to ask about.
    reputation = None
    if sha256:
        try:
            from core import enrichment
            reputation = enrichment.read(sha256, "hash")
            if not reputation or reputation.get("stale"):
                queued = enrichment.enqueue(sha256, kind="hash",
                                            requested_by="inspect_process",
                                            reason=f"process {row.get('name')}",
                                            session_id=session_id)
                reputation = reputation or {
                    "note": ("Not looked up yet. It has been queued, ask again "
                             "in a few seconds. NOT KNOWN is not the same as "
                             "clean: most files are in no malware database at "
                             "all."),
                    "queued": bool(queued.get("queued"))}
        except Exception as e:
            logger.debug(f"Reputation lookup failed for {sha256}: {e}")
            reputation = {"note": f"the reputation lookup did not run ({type(e).__name__})"}
    row["reputation"] = reputation

    level, why = trust_of(row)
    row["trust"] = level
    row["trust_reason"] = why

    # THE HONEST CEILING ON THIS WHOLE ANSWER, said in the answer rather than
    # left for somebody to remember. Everything above is the file on disk and
    # what is known about it. None of it says what the process is DOING right
    # now, and a file that matches its package can be doing something awful.
    #
    # IT NAMES WHAT WAS ACTUALLY COMPARED. The comparison is against the
    # digest the package recorded, which is a claim about CONTENT -- different
    # from, and in some ways stronger than, "a publisher signed this". Saying
    # "signed by its publisher" here would be a sentence about a check that
    # did not happen.
    row["how_to_read_this"] = (
        "This describes the executable on disk and what is known about "
        "it. The file is compared with the digest the package that owns it "
        "recorded when it was installed, so it says whether this is still "
        "the file this machine shipped, NOT that its behaviour is fine. A "
        "file no package owns is ordinary and is not a finding. An unknown "
        "hash means nobody has published anything about it, which is true "
        "of most software, so it is a reason to look rather than a finding.")
    return {"found": True, "process": row}


# HOW A COLOUR IS DECIDED. One function, so the page, the tool and the model
# cannot disagree about what red means.
#
# FIVE levels now, and the fifth is not a shade of the fourth. "could not be
# read" and "there is nothing to read" are different sentences, and this file
# has been bitten by collapsing them before. A kernel thread has no file at
# all; a process owned by another account has a file we were refused. Same
# grey, wildly different facts, so they are two levels.
TRUST_LEVELS = ("bad", "watch", "ok", "kernel", "unknown")


def trust_of(row, findings=None):
    """
    (level, reason). findings is an optional list of finding rows already
    read for this process name, so the page can colour without re-querying
    per row.
    """
    rep = row.get("reputation") or {}
    if rep.get("flagged"):
        by = ", ".join(rep.get("flagged_by") or []) or "a malware source"
        return "bad", f"this exact binary is flagged by {by}"

    worst = None
    for f in (findings or []):
        sev = (f.get("severity") or "").lower()
        if sev in ("critical", "high"):
            worst = sev
            break
        if sev == "medium" and worst is None:
            worst = sev
    if worst in ("critical", "high"):
        return "bad", f"there is a {worst} finding against this process"

    sig = row.get("signature") or {}
    status = (sig.get("status") or "unknown").lower()
    # The FOLDER, in words, or None. Never a canned sentence covering a list
    # of places that have nothing in common. See ODD_PATH_MARKERS_LINUX.
    odd = odd_path_reason(row.get("exe") or "")

    if status in ("hashmismatch", "notsigned", "notrusted", "unknownerror",
                  "notsupportedfiletype") or status.startswith("not"):
        # A PACKAGE FILE THAT CHANGED IS NOT THE SAME AS AN UNSIGNED ONE, and
        # both are amber because both are a reason to look rather than a
        # finding: a package is a thing somebody can install by hand, and a
        # digest mismatch can also be an unpack over a file. The row says
        # which one it is, in the Linux words the checker put on it.
        if sig.get("kind") == "package":
            label = sig.get("label") or ""
            if status == "hashmismatch":
                return "watch", (label or "it does not match the package that "
                                         "installed it")
            if odd:
                return "watch", (
                    (label or f"the signature says {sig.get('status')}")
                    + f", and it is running from {odd}, which is worth a "
                      f"second look")
            return "watch", (label or f"the signature says {sig.get('status')}")
        why = f"the checker says {sig.get('status')}"
        if odd:
            why += f", and it is running from {odd}, which is worth a second look"
        return "watch", why
    if worst == "medium":
        return "watch", "there is a medium finding against this process"
    if odd:
        return "watch", f"it is running from {odd}, which is worth a look"
    if status == "valid":
        signer = sig.get("signer")
        if sig.get("kind") == "package":
            # The green, and it is a claim about CONTENT and says so: the
            # file on disk is the one the package installed, on this machine,
            # which is not the same claim as "somebody out there signed this".
            return "ok", (f"matches the {signer} package installed on this "
                          f"machine" if signer
                          else (sig.get("label") or "it matches what its "
                                                    "package shipped"))
        return "ok", (sig.get("label") or "it matches what its package shipped")

    # NOTHING TO READ IS NOT THE SAME AS NOTHING THERE. A kernel thread is a
    # part of the kernel with no file behind it; the colour still says we
    # learned nothing about a file, because we did not, but the reason says
    # which of the two it is.
    if row.get("kind") == "kernel_thread" or _is_kernel_thread(row):
        return "kernel", (
            "a kernel thread: it has no executable file of its own and no "
            "command line, so there is nothing to check and that is normal, "
            "not a failure to read it")

    # THE CAVEAT IS ALWAYS ON THE END, not only when there is nothing else to
    # say. The first version returned the note on its own when there was one,
    # so the most informative case was the one that dropped the sentence
    # explaining what grey means.
    why = sig.get("note") or "nothing could be read about this one"
    return "unknown", f"{why}, which is not the same as it being fine"


def process_table(limit=400, session_id=None):
    """
    The whole process list with a colour on every row, for the Processes page.

    The signature check is batched into ONE pass and cached, so the first load
    pays a couple of seconds and every later one is free. Hashes are NOT taken
    here, deliberately: three hundred files is minutes of disk, and nobody
    asked for it just by opening a tab. That is what inspect_process is for,
    one row at a time.

    So the colours on this page rest on the signature check, the path, and
    findings already raised. A row can turn red later, when somebody looks
    properly. Say that on the page rather than letting green read as "checked".
    """
    got = list_processes(limit=limit)
    rows = got.get("processes") or []
    if not got.get("available"):
        return {"available": False, "reason": got.get("reason"),
                "processes": [], "counts": {}}

    sig_stats = {}
    sigs = signatures_for([r["exe"] for r in rows if r.get("exe")], sig_stats)

    # Findings for processes, once, keyed by the name they were raised
    # against, rather than a query per row.
    #
    # TWO THINGS WERE WRONG HERE UNTIL 2026-09-14, TODO 98, and they were the
    # same fault pointing two ways.
    #
    # It read query_findings(limit=200) and said nothing about the cap, so
    # past two hundred process findings in one session the rest simply were
    # not in the colouring. And the read was wrapped in except Exception with
    # a logger.debug, so when it failed EVERY row went through trust_of with
    # no findings at all and came back "ok, signed by X". A process with a
    # critical finding against it drew green, and the page had no field that
    # could say the findings had not been read.
    #
    # "No finding against this process" and "I could not read the findings"
    # are different sentences. They were the same colour.
    #
    # worst_finding_by_entity is an aggregate with no limit, so the cap is
    # gone rather than reported. trust_of still takes a list of rows, which is
    # why the single worst row is wrapped in one, and that keeps its signature
    # and its tests untouched.
    by_name = {}
    findings_read = True
    findings_error = None
    try:
        from core import memory_engine as me
        worst = me.worst_finding_by_entity("process", session_id=session_id)
        for value, hit in worst.items():
            by_name[value.lower()] = [hit]
    except Exception as e:
        findings_read = False
        findings_error = str(e)
        logger.warning(
            f"Could not read process findings for the table: {e}. Every row "
            f"on this load is coloured WITHOUT findings, which is not the "
            f"same as having none.")

    counts = {level: 0 for level in TRUST_LEVELS}
    threads = 0
    # PM-3. The load's rights are printed with the counts, so "23 grey" is
    # readable as "23 rows this account was refused" rather than as a fact
    # about the machine.
    try:
        from core import privilege_linux as _priv
        elevated = _priv.is_elevated()
    except Exception:                                   # noqa: BLE001
        elevated = None

    for row in rows:
        row["signature"] = sigs.get(row.get("exe")) or {
            "status": "unknown", "signer": None,
            # PM-3, 2026-09-23. THE NOTE USED TO BE A LIE ABOUT THE MACHINE.
            # It read "this process has no executable path on disk, so there was
            # no file to compare against any package record" for nine processes
            # whose files are all on disk and readable by root — and it sat
            # directly under a legend that says grey means "nothing could be
            # read about it". The row now carries the kernel's own answer from
            # list_processes (see _exe_refusal_note), so the grey says WHAT was
            # refused and by whom.
            "note": (row.get("exe_refusal") or
                     "this process has no executable path on disk, so there "
                     "was no file to compare against any package record"),
        }
        # A KERNEL THREAD IS MARKED BEFORE THE COLOUR IS DECIDED, because the
        # colour and the tool that reports the page both need to say what it
        # is. Saying it here means there is one rule, not two.
        if _is_kernel_thread(row):
            row["kind"] = "kernel_thread"
            threads += 1
        level, why = trust_of(row, by_name.get((row.get("name") or "").lower()))
        row["trust"] = level
        row["trust_reason"] = why
        counts[level] += 1

    return {"available": True,
            "counts": counts,
            "total": len(rows),
            "kernel_threads": threads,
            "capped": got.get("note"),
            # PM-3. Which rights produced these colours. An unelevated load
            # cannot read another account's exe, so it greys more rows than an
            # elevated one — and the same daemon has appeared on this page with
            # a real path (elevated) and with none (unelevated) with nothing
            # saying why. Every row carries its own refusal too.
            "elevated": elevated,
            "exe_refusals": sum(1 for r in rows if r.get("exe_refusal")),
            # TODO 98. The colours rest on two reads, the signatures and the
            # findings, and either can fail on its own. The signature side has
            # said so since the first real run; this is the other half.
            "findings_read": findings_read,
            "findings_note": (
                None if findings_read else
                f"The findings could not be read ({findings_error}), so these "
                f"colours are the signature and the path ONLY. A process with "
                f"a finding against it is showing here as if it had none. "
                f"Refresh, and read the Alerts tab before trusting a green "
                f"row on this load."),
            # WHY THE GREYS ARE GREY, as a number rather than a shrug. The
            # first real run put 283 of 288 in grey and the page could not
            # say whether that was a slow machine, a broken call or a
            # genuinely unreadable set of binaries.
            "signature_check": _sig_summary(sig_stats),
            "processes": rows}


def _sig_summary(stats):
    checked = stats.get("checked", 0) + stats.get("cached", 0)
    failed = stats.get("failed", 0)
    later = stats.get("not_reached", 0)
    # This sentence used to read "Signature checking only works on Windows, so
    # every row is grey here", and on this host it was the only explanation for
    # a page of 214 grey rows. It says what was actually compared now, because
    # the colours are no longer all the same one.
    tool = _package_tool()
    if not tool:
        return ("No package manager on this host can say where a file came "
                "from, so no file was compared to anything on this load.")
    parts = [f"{checked} file(s) compared with the digest their package "
             f"recorded"]
    if failed:
        parts.append(f"{failed} could not be, and each row says why")
    if later:
        parts.append(f"{later} not reached yet, refresh to carry on")
    return ", ".join(parts) + "."
