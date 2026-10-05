# tools/ebpf_events.py
# AgentalSec V2, T6. THE KERNEL CAMERA'S READ SIDE.
#
# WHAT THIS IS, IN ONE LINE
#
# The app reads the event file that ebpf/ebpf_monitor.py writes, decides which
# of those events are worth a finding, and says what it could not read.
#
# THE GAP THIS CLOSES, IN THE OWNER'S WORDS
#
#   "Today a program that lives five seconds inside a sixty-second poll gap
#    is invisible."
#
# Every other sensor in this tree learns what is happening by ASKING: the
# process monitor walks /proc once a poll, the event monitor reads journald in
# batches, the local integrity sensor stats files. A program that starts, acts
# and exits between two asks leaves NO ROW ANYWHERE, so the app cannot even
# report that it might have missed it. That is what the camera fixes, and why
# this module exists: without a reader the camera is a file nobody opens.
#
# THE ONE-WAY STREET, RESTATED HERE BECAUSE THIS IS THE OTHER END OF IT
#
# ebpf/ebpf_monitor.py runs as root and writes a SIDECAR database. This module
# runs as the operator and READS it. There is no path in either direction
# except the file:
#
#   * nothing that runs as root ever opens this app's database, so a malformed
#     row cannot become a malformed query in a privileged process;
#   * this module opens the sidecar READ-ONLY (immutable only when the camera
#     is stopped), so a reader cannot disturb a writer that is running as root.
#
# THE CONTENT OF THAT FILE IS ATTACKER-INFLUENCED, and this is the part worth
# being careful about: `filename` is a path somebody chose, `comm` is a name
# somebody chose (a process can call prctl(PR_SET_NAME) and pick any fifteen
# bytes it likes), and both arrive here as text. So nothing in this file
# executes, evaluates or interpolates any of it. Every value is compared,
# realpath'd as a FILENAME and stored. The tool that serves it to the model is
# fenced (core/sanitize.UNTRUSTED_TOOLS) for the same reason.
#
# RULE TWO APPLIES TO EVERY ANSWER THIS MODULE GIVES
#
# "I could not look" and "nothing happened" are different sentences, and this
# module has MORE ways of being unable to look than any other sensor here:
#
#   the camera is not installed       no sidecar file at all
#   the camera is installed, not running   file present, nothing arriving
#   the camera is running, stale      last event is hours old
#   the camera is dropping events     the ring buffer overflowed
#   the camera is behind              there are events we have not analysed
#   the camera is new                 we have never analysed anything
#
# Every one of those is a NAMED state in `coverage`, and the tool's own
# `how_to_read_this` says which of them the answer is resting on. A quiet
# camera result is NEVER allowed to read as a quiet machine.
#
# WHAT IT DELIBERATELY DOES NOT DO
#
#   * it does not hash binaries. That is the local integrity sensor's job and
#     doing it here would mean reading attacker-named paths on the poll loop.
#   * it does not classify by name. `nc` in a comm field is not evidence of
#     anything on a machine where netcat is a tool somebody installed.
#   * it does not keep a process table. A camera event is a FACT about a
#     moment; the process monitor is the thing that owns "what is running".
#   * IT NEVER RAISES ON THE SEED PASS. The first analysis of a camera file
#     that already holds a week of history would otherwise be a page of
#     pre-existing state, and a monitor that shouts on its first useful look
#     is one its reader learns to skim. Seed, then diff.

import logging
import os
import sqlite3
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

ROLE = "ebpf_events"

# THE DETECTIONS THIS MODULE CAN RAISE, AND THE ONE ID PER CLAIM RULE
#
# LNX-3001 and LNX-3002 are both "something ran from a staging directory" and
# they are deliberately two ids, because they are two facts with two remedies:
#
#   LNX-3001  a program's CONTENT is in /tmp, /dev/shm or a user's cache. The
#             remedy is to look at that file, and the file is still there.
#   LNX-3002  a SHELL was started on such a file. A shell is a program that
#             runs other programs, so the remedy is to ask what it ran, and
#             that is a different piece of work.
#
# An early draft had one id with a severity that moved between low and high.
# That is the exact shape core/detections.py documents as forbidden: two
# different things sharing a history on the Detections page.
DID_LOCATION = "LNX-3001"
DID_SHELL    = "LNX-3002"
DID_PORT     = "LNX-3003"

DETECTIONS = [f"{DID_LOCATION} execution_from_staging_directory",
              f"{DID_SHELL} shell_on_staged_file",
              f"{DID_PORT} process_connect_dangerous_port"]

# The default sidecar location. The camera's own --out must match it; see
# ebpf/install_ebpf_camera.sh, which is what keeps the two in step.
DEFAULT_EVENTS_DB = "/var/lib/agental_sec/ebpf_events.db"

# HOW OLD AN EVENT HAS TO BE BEFORE THE CAMERA IS CALLED STALE. This is not a
# poll interval: the camera writes continuously and this app reads on its own
# clock, so the question "is it still running" is answered by "did anything
# arrive recently". Fifteen minutes is deliberately generous, because a quiet
# desktop legitimately executes nothing for minutes at a time and a tight
# window would report a working camera as dead.
STALE_AFTER_SECONDS = 900

# A camera that has never been started cannot be stale. It is NAMED as never
# run, which is a different sentence, and it is the one most installs will see
# until the operator runs the installer.
NEVER_RUN_NOTE = (
    "THE CAMERA HAS NEVER RUN on this machine, or its file is somewhere else. "
    "No kernel event has ever been recorded, so this answer says nothing about "
    "what has executed here, only that nothing was watching. Install and "
    "start it with: sudo scripts/install_ebpf_camera.sh --apply")

# WHAT IS WORTH A FINDING, AND WHY THESE THREE THINGS AND NOTHING ELSE
#
# The camera records two kinds of event: every execve and every connect(2).
# On a working desktop that is tens of thousands of rows an hour, none of them
# interesting. So the value of the camera is not the rows -- it is that a SMALL
# number of questions can finally be asked of them, and the questions here are
# chosen to be ones the polling sensors structurally cannot answer.
#
# STAGING DIRECTORIES ARE THE SAME LIST THE PROCESS MONITOR ALREADY USES
# (tools/process_monitor_linux.SUSPICIOUS_PATHS) and are copied on purpose
# rather than reused. Those are a list of SUBSTRING matches for the /proc walk;
# these are path PREFIXES matched against a realpath. Sharing one list between
# two different matching rules is how a tuning change to one silently retunes
# the other, and the two would then be described by one comment.
STAGING_PREFIXES = (
    "/tmp/", "/var/tmp/", "/dev/shm/",
    "/run/user/",                # the per-user runtime dir, wiped every boot
    "/var/tmp/.", "/tmp/.",
)

# A user's own cache and Downloads directories are here for a different reason
# from the staging directories: a program running from one of them is usually
# something the owner downloaded and chose to run, which is why LNX-3001 is LOW for
# these and why the finding's description says so rather than implying malice.
HOME_SUBPATHS = (".cache/", "Downloads/", "downloads/", "AppData/")

# The shells. This is the "a shell was started on that file" test and it is
# kept NARROW on purpose: a data-processing tool living in /tmp is an
# inconvenience, and a shell living in /tmp is normally how a payload is
# started. Names are compared exactly, against comm as the kernel reports it,
# and against the basename of the executable path -- never by substring, so
# `bashful_helper` is not a shell here.
SHELL_COMMS = frozenset({
    "sh", "bash", "dash", "ash", "zsh", "ksh", "mksh", "ksh93", "busybox",
    "csh", "tcsh", "fish", "yash", "posh", "sh.distrib",
})

# THE TWO ALLOWLISTS, AND WHY EVERY INSTALL WILL NEED THEM
#
# MEASURED ON THIS HOST: a boot executes systemd's own executor OUT OF /tmp.
#
#     /tmp/systemd-private-<random>-systemd-resolved.service-<random>/...
#
# That is not an attack, it is how systemd runs a service with PrivateTmp.
# Anything matching that shape must be silent by DEFAULT and not by the
# operator's configuration, because the alternative is a security tool that
# produces a finding on every boot of the machine it is installed on -- and a
# monitor whose first page is noise is one whose reader never gets to page two.
#
# These are matched against the REALPATH, which for a private tmp is still
# under /tmp (the private namespace is per-process, so the path this app sees
# is the host's).
DEFAULT_PATH_ALLOWLIST = (
    "/tmp/systemd-private-",
    "/var/tmp/systemd-private-",
)

# Allowed only when the program runs as root. Timeshift runs its own scripts
# from /tmp/timeshift-<random>/ as root on every backup. Anyone can create a
# directory with that name, but a non-root run of it is still reported.
ROOT_PATH_ALLOWLIST = (
    "/tmp/timeshift-",
)

# Ports where a connection is worth looking at. This is the same set the packet
# sensor's Windows-era detector used (tools/packet_sniffer_linux.DANGEROUS_PORTS)
# and it is NOT a threat feed: these are ports that appear in the default
# configurations of remote-control and post-exploitation tooling, which is a
# weaker and more honest claim than "known bad".
DANGEROUS_PORTS = frozenset({4444, 5555, 6666, 31337, 12345, 54321})

# A loopback or link-local destination is never worth a finding: 4444 on
# 127.0.0.1 is a developer's test server and raising it teaches the reader to
# ignore the rule for the case that matters.
_IGNORED_DESTINATIONS = ("127.", "0.0.0.0", "::1", "fe80:", "224.0.0.", "255.255.255.255")

# THE BUDGETS, EACH ONE MEASURED RATHER THAN CHOSEN
#
# CAP_PER_ID_PER_PASS. A build on this host executes ten thousand programs in
# a minute; a build inside /tmp would produce ten thousand findings about it.
# The cap keeps the dashboard readable and the SUMMARY ROW ANNOUNCES THE CUT,
# which is the part that matters: "5 shown, 431 further not listed" is an
# answer, and a silently truncated list of 5 is a lie.
CAP_PER_ID_PER_PASS = 5

# EXEC_SCAN_LIMIT. How many camera rows one analysis pass will look at. The
# camera writes continuously and this app reads on a 60-second poll; the limit
# only binds if the app has been switched off for a long time, and when it does
# bind the coverage block SAYS SO rather than pretending it caught up.
EXEC_SCAN_LIMIT = 20000

# CONNECT_WINDOW. Connections are matched against the window since the last
# pass, clamped to this, so a first pass over a week-old file does not evaluate
# a week of connect() calls against a five-minute idea of relevance.
CONNECT_WINDOW_SECONDS = 900

# The camera writes its own health rows (drops, totals). If the newest one is
# old, the camera stopped and the events after it are missing.
HEALTH_STALE_SECONDS = 900


# CONFIGURATION

def config_for(config: dict = None) -> dict:
    """
    Where the camera's file is, and how it is judged. Never raises.

    A MISSING CONFIG BLOCK IS NOT AN ERROR AND IS NOT A SILENT DEFAULT: the
    defaults are named here and the caller can always see which of them are in
    force, because every one of them appears in the status the adapter
    publishes.
    """
    block = {}
    try:
        block = ((config or {}).get("sensors", {}) or {}).get(ROLE, {}) or {}
    except Exception as e:                              # noqa: BLE001
        logger.debug(f"ebpf_events: config block unreadable: {e}")
        block = {}

    path = block.get("events_db") or DEFAULT_EVENTS_DB
    allow = block.get("path_allowlist")
    if not isinstance(allow, list) or not allow:
        allow = list(DEFAULT_PATH_ALLOWLIST)

    try:
        stale = int(block.get("stale_after_seconds", STALE_AFTER_SECONDS))
    except (TypeError, ValueError):
        stale = STALE_AFTER_SECONDS

    return {
        "events_db": str(path),
        "path_allowlist": tuple(str(a) for a in allow),
        "stale_after_seconds": max(60, stale),
        "enabled": bool(block.get("enabled", True)),
        "watch_staging": bool(block.get("watch_staging_directories", True)),
        "watch_ports": bool(block.get("watch_dangerous_ports", True)),
    }


# READING THE SIDECAR

def _ro_connect(path: str):
    """
    A connection to the camera's file that cannot disturb it.

    IMMUTABLE AND READ-ONLY, and both words matter here in a way they do not
    for this app's own database. The writer is a process running AS ROOT, so a
    reader that tried to create a WAL sidecar, take a lock or replay a journal
    would be a process running as the operator reaching into a root-owned
    writer's files. `immutable=1` tells SQLite not to touch anything at all.

    Plain read-only first, because immutable reads race the camera's live
    checkpoint and fail as "malformed" now and then, and they skip the WAL.
    Read-only needs the camera's -shm file, which only exists while it runs,
    so a stopped camera falls back to immutable, which is safe when nothing
    writes.
    """
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone()
        return conn
    except sqlite3.Error:
        pass
    return sqlite3.connect(f"file:{path}?immutable=1", uri=True, timeout=5)


def _tables(conn) -> set:
    try:
        return {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    except sqlite3.Error:
        return set()


def _newest_health(conn):
    """
    The camera's own last words about itself, or None.

    THE COLUMNS ARE CHECKED, NOT ASSUMED (AD10). A camera file written before
    this round has no `callback_errors` column; naming it in the SELECT raises,
    and the raise used to read as "the camera has never written a health row",
    which is a different and much more alarming fact than "it wrote one
    without that counter".
    """
    try:
        have = {r[1] for r in conn.execute("PRAGMA table_info(ebpf_health)")}
    except sqlite3.Error:
        return None
    if not have:
        return None
    wanted = [c for c in ("at", "dropped_exec", "dropped_connect",
                          "events_written", "callback_errors", "note")
              if c in have]
    try:
        row = conn.execute(
            f"SELECT {', '.join(wanted)} FROM ebpf_health "
            f"ORDER BY id DESC LIMIT 1").fetchone()
    except sqlite3.Error:
        return None
    if not row:
        return None
    got = dict(zip(wanted, row))
    return {"at": got.get("at"),
            "dropped_exec": got.get("dropped_exec"),
            "dropped_connect": got.get("dropped_connect"),
            "events_written": got.get("events_written"),
            # None, NOT 0, WHEN THE CAMERA IS TOO OLD TO HAVE THE COLUMN. A
            # zero here would be this app inventing the statement "the camera
            # decoded every record it read", which is the one thing this whole
            # file exists not to do.
            "callback_errors": (got.get("callback_errors")
                                if "callback_errors" in have else None),
            "note": got.get("note")}


def _totals(conn):
    """
    (count, newest_recorded, error) for the camera's own record.

    THE THIRD ELEMENT IS THE FIX, 2026-09-25, REGISTER PS-15. This returned
    (None, None) on any sqlite3.Error, and the caller set `reachable = True`
    before reading it and then tested `if not total:` -- where None and 0 are
    the same answer. So a TRANSIENT READ FAILURE on a camera holding 578,530
    events took the branch written for a camera with NOTHING ON FILE, and the
    page said "THE CAMERA HAS NEVER RUN on this machine" while the unit was
    running. None means COULD NOT BE READ and 0 means NOTHING RECORDED; two
    different sentences, and collapsing them is the shape this register keeps
    recording. The error travels so the sentence can name it.
    """
    try:
        row = conn.execute(
            "SELECT COUNT(*), MAX(recorded_at) FROM ebpf_event").fetchone()
    except sqlite3.Error as e:
        return (None, None, f"{type(e).__name__}: {e}")
    return (row[0] if row else None, row[1] if row else None, None)


def camera_status(config: dict = None) -> dict:
    """
    What the camera is, in the same vocabulary every other sensor uses.

    READ THIS BEFORE READING ANY CAMERA FINDING. A quiet list of findings is
    three completely different answers depending on what this returns, and the
    whole point of the block below is that they never collapse into one.

    Never raises: a camera that cannot be read is a camera whose state is
    reported, not an exception in a poll loop.
    """
    cfg = config_for(config)
    out = {
        "events_db": cfg["events_db"],
        "enabled": cfg["enabled"],
        "reachable": False,
        "running": False,
        "ready": False,
        "has_ever_run": False,
        "blind": False,
        "blind_reason": None,
        "note": None,
        "coverage_limits": [],
    }

    path = cfg["events_db"]

    # os.path, NOT pathlib. The camera's file lives under /var/lib with a
    # root-owned parent on this host, and Path(...).exists() RAISES
    # PermissionError when it cannot traverse -- which is the same defect this
    # project already paid for twice, once in the local integrity sweep and
    # once in ebpf_monitor.py's own --check. os.path answers False, which is
    # the right answer: "no camera file for me to read".
    if not os.path.exists(path):
        parent = os.path.dirname(path) or "/"
        if not os.path.isdir(parent):
            out["note"] = (
                f"there is no camera file at {path}, and {parent} does not "
                f"exist either. " + NEVER_RUN_NOTE)
        elif not os.access(parent, os.R_OK | os.X_OK):
            out["note"] = (
                f"{path} cannot be checked because {parent} is not readable "
                f"by this account (mode "
                f"{oct(os.stat(parent).st_mode & 0o777) if os.path.isdir(parent) else '?'}"
                f"). THE CAMERA MAY BE RUNNING FINE. This is a limit of this "
                f"run, not a statement that nothing is recording.")
        else:
            out["note"] = f"there is no camera file at {path}. " + NEVER_RUN_NOTE
        out["coverage_limits"].append(out["note"])
        return out

    try:
        conn = _ro_connect(path)
    except sqlite3.Error as e:
        out["blind"] = True
        out["blind_reason"] = (
            f"the camera file at {path} exists but could not be opened "
            f"({type(e).__name__}: {e}). Nothing about what has executed on "
            f"this machine can be said from this run.")
        out["coverage_limits"].append(out["blind_reason"])
        return out

    try:
        tables = _tables(conn)
        if "ebpf_event" not in tables:
            out["blind"] = True
            out["blind_reason"] = (
                f"{path} exists and opens, but it has no ebpf_event table, so "
                f"it is not a camera file. Something else owns that path.")
            out["coverage_limits"].append(out["blind_reason"])
            return out

        total, newest_recorded, totals_error = _totals(conn)
        health = _newest_health(conn)
        # REACHABLE IS EARNED BY A READ THAT SUCCEEDED, not by the file having
        # opened (PS-15, 2026-09-25). It used to be set before this line, so a
        # failing COUNT(*) still produced reachable=True with total None --
        # a combination the test that found this was right to fail on.
        out["reachable"] = totals_error is None
        out["total_events"] = total
        out["newest_event_at"] = newest_recorded
        if totals_error:
            # COULD NOT BE READ IS NOT NOTHING RECORDED. Its own sentence, its
            # own field, and it is the state a transient error produces on a
            # camera that is running: the count is unknown, which says nothing
            # about the camera and everything about this read.
            out["blind"] = True
            out["blind_reason"] = (
                f"the camera file at {path} is open and its table is there, "
                f"but the count of what it holds COULD NOT BE READ "
                f"({totals_error}). That is a statement about this read, not "
                f"about the camera: whatever is recording may be recording "
                f"fine, and this answer has no figure for how much.")
            out["coverage_limits"].append(out["blind_reason"])
            return out
        out["has_ever_run"] = bool(total)

        # THE HOST'S OWN CLOCK. The camera stamps every row with both the
        # kernel's monotonic nanosecond counter and the database's
        # CURRENT_TIMESTAMP, and only the second one can be compared against
        # time.time() here. Using ts_ns would compare two clocks that started
        # at different moments and produce an age that is nonsense.
        age = _age_seconds(newest_recorded)
        if age is not None:
            out["newest_event_age_seconds"] = round(age, 1)

        out["drops"] = {"exec": None, "connect": None}
        if health:
            out["last_health_at"] = health["at"]
            out["drops"] = {"exec": health["dropped_exec"],
                            "connect": health["dropped_connect"]}
            out["last_health_note"] = health["note"]
            out["callback_errors"] = health.get("callback_errors")
            if health.get("callback_errors"):
                # E-7. A DECODE FAILURE USED TO BE INVISIBLE FROM HERE, and it
                # is loss in the same sense a drop is: the record reached the
                # loader and did not become a row. None means the camera is
                # older than the column and never counted them, which is said
                # as such rather than as a zero.
                out["coverage_limits"].append(
                    f"THE CAMERA COULD NOT DECODE {health['callback_errors']} "
                    f"RING-BUFFER RECORD(S). Those records were NOT written to "
                    f"the file and are NOT in this answer. The camera's own "
                    f"note: {health.get('note') or 'none recorded'}. A decode "
                    f"failure is a struct mismatch between the object and the "
                    f"loader, not a busy moment: rebuild with ebpf/build.sh.")
            if health["dropped_exec"] > 0 or health["dropped_connect"] > 0:
                out["coverage_limits"].append(
                    f"THE CAMERA DROPPED EVENT(S): exec={health['dropped_exec']}, "
                    f"connect={health['dropped_connect']}. The ring buffer filled "
                    f"and the kernel had nowhere to put the event, so those "
                    f"executions and connections are NOT in this file and NOT in "
                    f"this answer. A drop means a busy moment, not a failure, but "
                    f"it does mean this window is incomplete.")
            if _age_seconds(health["at"]) is not None and \
                    _age_seconds(health["at"]) > HEALTH_STALE_SECONDS:
                out["coverage_limits"].append(
                    f"the camera's last health row is "
                    f"{round(_age_seconds(health['at']))}s old, so the events "
                    f"after that moment were never counted. The drop numbers "
                    f"above are the numbers as of then, not as of now.")

        # THE NEVER-RUN SENTENCE IS RESERVED FOR A COUNT OF EXACTLY 0, 2026-09-25
        # (PS-15). It used to be `if not total:`, where None and 0 are the same
        # answer -- which is how a transient read error became "THE CAMERA HAS
        # NEVER RUN". The unreadable case returns above, so this branch is now
        # reached only by a read that WORKED and found the table empty, and the
        # test is written as equality rather than falsiness so that stays true.
        if total == 0:
            out["note"] = (
                f"the camera file at {path} exists and is readable, but it "
                f"holds NO EVENTS AT ALL. Either it was started and nothing "
                f"has executed since, or it was started and failed before it "
                f"attached. " + NEVER_RUN_NOTE)
            out["coverage_limits"].append(out["note"])
            return out

        if age is not None and age > cfg["stale_after_seconds"]:
            # NOT blind, and the distinction is the whole of rule two here:
            # the file is readable and holds real events. What has stopped is
            # the camera. Reporting blind would attach "I could not look" to
            # an answer that is really "nobody is looking any more".
            out["note"] = (
                f"the newest camera event is {round(age)}s old, which is past "
                f"the {cfg['stale_after_seconds']}s staleness window. THE "
                f"CAMERA HAS STOPPED, or the machine has been idle since it "
                f"stopped. Everything after {newest_recorded} is UNSAMPLED, "
                f"so a quiet result here covers the period before that moment "
                f"only.")
            out["coverage_limits"].append(out["note"])
        else:
            out["running"] = True
            out["note"] = (
                f"the camera is recording: {total} event(s) on file, the "
                f"newest {round(age)}s old (window {cfg['stale_after_seconds']}s).")

        out["ready"] = bool(out["running"])
        return out
    finally:
        try:
            conn.close()
        except sqlite3.Error:
            pass


def _age_seconds(stamp):
    """
    Seconds between a stored timestamp and now, or None.

    THE TWO FORMATS ARE BOTH REAL HERE. The camera's own tables default their
    timestamps to CURRENT_TIMESTAMP, which SQLite renders as
    'YYYY-MM-DD HH:MM:SS' in UTC; a row somebody wrote with a Python datetime
    carries microseconds. An unparseable stamp answers None rather than an
    invented age, because an invented age is a claim about the camera.
    """
    if not stamp:
        return None
    text = str(stamp).strip().replace("T", " ")
    if text.endswith("Z"):
        text = text[:-1]
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            when = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            return max(0.0, time.time() - when.timestamp())
        except ValueError:
            continue
    return None


# THE CURSOR
#
# WHAT THIS APP HAS ALREADY ANALYSED. It is a row in THIS app's database, not
# in the camera's file: the camera's file belongs to a root process and this
# module must not write to it.
#
# The three values are deliberately separate rather than one timestamp. An
# event id and a recorded_at are both needed because the camera's table is
# written by another process and an id is the only monotonic thing in it,
# while a timestamp is the only thing that survives the file being replaced.
CURSOR_TABLE = "ebpf_camera_cursor"
CURSOR_NAME = "default"

CURSOR_DDL = f"""
CREATE TABLE IF NOT EXISTS {CURSOR_TABLE} (
    name            TEXT PRIMARY KEY,
    last_event_id   INTEGER NOT NULL DEFAULT 0,
    last_event_at   TIMESTAMP,
    last_connect_ns INTEGER NOT NULL DEFAULT 0,
    last_connect_id INTEGER NOT NULL DEFAULT 0,
    seeded_at       TIMESTAMP,
    passes          INTEGER NOT NULL DEFAULT 0
)
"""

# THE CURSOR'S COLUMNS ARE READ FROM THE TABLE, NOT ASSUMED. AD10's rule.
#
# THE SAME DEFECT THE AUDIT FOUND IN tools/auditd_monitor.py IS LIVE HERE, and
# this round measured it rather than reasoning about it. A SELECT that NAMES a
# column the table does not have raises OperationalError; the error was caught
# by the `except sqlite3.Error` below and collapsed into the BLANK cursor; and
# a blank cursor answers `seeded: False`, which is "never seeded" -- which
# makes the next pass SEED: cursor to the end of the file, and NOTHING raised
# for everything written since. Silent loss dressed as a fresh start.
#
# MEASURED, on a table in the pre-v44 shape (name, last_event_id,
# last_event_at, last_connect_ns only -- the shape any file from before
# seeded_at has):
#
#     read_cursor() -> seeded=False  last_event_id=0
#     analyze()     -> seeded=True, 0 findings, cursor moved to the NEWEST event
#
# and the events in between were never looked at by any pass. Building the
# SELECT from PRAGMA table_info is what makes an old table answer honestly:
# the fields it does not have read as their defaults and `seeded` is decided
# by a column the table ACTUALLY HAS.
def _cursor_columns(conn) -> set:
    try:
        return {r[1] for r in conn.execute(f"PRAGMA table_info({CURSOR_TABLE})")}
    except sqlite3.Error:
        return set()


def ensure_cursor_table(db_path: str = None) -> bool:
    """
    Create the cursor table if it is not there. Returns whether it is now.

    CALLED FROM THE MIGRATION AND AGAIN HERE, which is not belt-and-braces for
    its own sake: this module is read by tests against databases built from
    Schema.SQL, by the migration path, and by the operator's own file after an
    upgrade. A cursor that does not exist must not stop the sensor from
    REPORTING -- it stops it from ANALYSING, and says so.
    """
    from core import memory_engine as me

    path = db_path or str(me.DB_PATH)
    try:
        conn = sqlite3.connect(path, timeout=10)
        try:
            conn.executescript(CURSOR_DDL)
            conn.commit()
        finally:
            conn.close()
        return True
    except sqlite3.Error as e:
        logger.warning(f"ebpf_events: could not create the cursor table in "
                       f"{path}: {type(e).__name__}: {e}")
        return False


def read_cursor(db_path: str = None) -> dict:
    """
    What has been analysed so far. `seeded: False` means NEVER, which is a
    different answer from a cursor at zero rows.

    THE COLUMNS ARE READ OFF THE TABLE rather than named in the SELECT. A
    cursor table from before a column existed answers HONESTLY here instead of
    raising, because raising collapses into the blank cursor and the blank
    cursor makes the next pass SEED -- skip to the end and raise nothing. See
    _cursor_columns above for the measurement.
    """
    from core import memory_engine as me

    path = db_path or str(me.DB_PATH)
    blank = {"name": CURSOR_NAME, "last_event_id": 0, "last_event_at": None,
             "last_connect_ns": 0, "seeded_at": None, "passes": 0,
             "seeded": False, "error": None}
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error as e:
        blank["error"] = f"cursor unreadable: {type(e).__name__}: {e}"
        return blank
    try:
        have = _cursor_columns(conn)
        if not have:
            # No table yet is not an error: it is the first run.
            return blank
        wanted = [c for c in ("last_event_id", "last_event_at",
                              "last_connect_ns", "last_connect_id",
                              "seeded_at", "passes")
                  if c in have]
        select = ", ".join(wanted) if wanted else "1"
        row = conn.execute(
            f"SELECT {select} FROM {CURSOR_TABLE} WHERE name = ?",
            (CURSOR_NAME,)).fetchone()
    except sqlite3.Error as e:
        # A REFUSAL HERE IS REPORTED, not turned into "never seeded". A read
        # that failed and a cursor that is empty are different facts, and only
        # one of them is safe to seed from.
        blank["error"] = (f"the cursor could not be read "
                          f"({type(e).__name__}: {e}). The next pass will "
                          f"treat this as a FIRST RUN, which seeds to the "
                          f"newest event and raises nothing for the history "
                          f"in between.")
        return blank
    finally:
        try:
            conn.close()
        except sqlite3.Error:
            pass
    if not row:
        return blank
    got = dict(zip(wanted, row)) if wanted else {}
    # `seeded` IS DECIDED BY EVIDENCE THE TABLE ACTUALLY HOLDS, and BOTH KINDS
    # COUNT. `seeded_at IS NOT NULL` is the explicit mark this app writes when
    # it seeds. A NON-ZERO `last_event_id` is the other half, and it is not a
    # nicety: on a cursor table created before `seeded_at` existed -- the shape
    # any file reaches through the migration path or an upgrade -- that column
    # is added NULL, and reading NULL alone as "never analysed" makes the next
    # pass SEED: skip to the end and raise nothing for everything in between.
    # A cursor that holds a position IS a cursor that has analysed something,
    # and inventing a timestamp for when it did would be a false claim about
    # this app's own history. Reporting the position as the evidence is true.
    if "seeded_at" in have:
        seeded = (got.get("seeded_at") is not None
                  or bool(got.get("last_event_id") or 0))
    else:
        seeded = bool(got.get("last_event_id") or 0)
    return {"name": CURSOR_NAME,
            "last_event_id": got.get("last_event_id") or 0,
            "last_event_at": got.get("last_event_at"),
            "last_connect_ns": got.get("last_connect_ns") or 0,
            "last_connect_id": got.get("last_connect_id") or 0,
            "seeded_at": got.get("seeded_at"),
            "passes": got.get("passes") or 0,
            "seeded": seeded, "error": None}


def write_cursor(last_event_id: int, last_event_at, last_connect_ns: int,
                 seeded: bool = False, db_path: str = None,
                 last_connect_id: int = None) -> bool:
    """
    Move the cursor. Returns whether it moved.

    A FAILED WRITE IS REPORTED, never swallowed: the consequence is that the
    next pass re-analyses the same window, which produces duplicate findings
    the dedup will suppress -- and, worse, a reader who sees the same finding
    twice learns to ignore it.

    THE COLUMNS ARE WRITTEN ONLY IF THE TABLE HAS THEM, which is the write
    side of AD10's rule and the same reasoning read_cursor uses: this module
    runs against databases built from Schema.SQL, from the migration path, and
    from whatever shape an operator's file happens to be in. An INSERT that
    names a column an old table lacks raises, and a cursor that never moves
    re-reads the same window forever.
    """
    from core import memory_engine as me

    path = db_path or str(me.DB_PATH)
    try:
        conn = sqlite3.connect(path, timeout=10)
        try:
            have = _cursor_columns(conn)
            if not have:
                conn.executescript(CURSOR_DDL)
                have = _cursor_columns(conn)

            # An old table missing seeded_at gets the column first, because
            # "never analysed" and "analysed and found nothing" must not be the
            # same fact on the next read.
            if "seeded_at" not in have:
                try:
                    conn.execute(f"ALTER TABLE {CURSOR_TABLE} ADD COLUMN "
                                 f"seeded_at TIMESTAMP")
                except sqlite3.Error:
                    pass
                have = _cursor_columns(conn)

            values = {"name": CURSOR_NAME}
            if "last_event_id" in have:
                values["last_event_id"] = int(last_event_id)
            if "last_event_at" in have:
                values["last_event_at"] = last_event_at
            if "last_connect_ns" in have:
                values["last_connect_ns"] = int(last_connect_ns)
            if "last_connect_id" in have and last_connect_id is not None:
                values["last_connect_id"] = int(last_connect_id)
            if "seeded_at" in have:
                values["seeded_at"] = _now() if seeded else None
            if "passes" in have:
                values["passes"] = 1

            cols = list(values)
            # seeded_at is only ever FILLED IN, never cleared, and passes
            # counts up: both are what the previous version of this statement
            # did and they are load-bearing. Everything else is replaced.
            assignments = []
            for col in cols:
                if col == "name":
                    continue
                if col == "seeded_at":
                    # The LEFT side must be a bare column; the qualified name
                    # belongs on the right. SQLite refuses `table.col = ...` in
                    # an UPSERT's SET clause and the whole statement dies with
                    # "near '.': syntax error" -- which is how this was caught,
                    # by running it rather than by reading it.
                    assignments.append(
                        f"seeded_at = COALESCE({CURSOR_TABLE}.seeded_at, "
                        f"excluded.seeded_at)")
                elif col == "passes":
                    assignments.append(f"passes = {CURSOR_TABLE}.passes + 1")
                else:
                    assignments.append(f"{col} = excluded.{col}")

            conn.execute(
                f"INSERT INTO {CURSOR_TABLE} ({', '.join(cols)}) "
                f"VALUES ({', '.join('?' * len(cols))}) "
                f"ON CONFLICT(name) DO UPDATE SET {', '.join(assignments)}",
                tuple(values[c] for c in cols))
            conn.commit()
        finally:
            conn.close()
        return True
    except sqlite3.Error as e:
        logger.error(f"ebpf_events: THE CURSOR DID NOT MOVE ({type(e).__name__}: "
                     f"{e}). The next pass will re-analyse this same window, so "
                     f"expect the same findings twice.")
        return False


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# THE CLASSIFIER

def in_staging_directory(path: str) -> str | None:
    """
    The prefix this path is staged in, or None.

    THE REALPATH IS WHAT GETS COMPARED, and that is a decision with a cost
    worth naming: realpath() resolves symlinks, so a link at /tmp/evil ->
    /usr/bin/true is classified by its TARGET and reports nothing. That is the
    correct answer for this rule -- nothing suspicious executed -- and it is
    the wrong answer for a rule about where a NAME lives. The rule here is
    about where the program's bytes are.
    """
    if not path or not path.startswith("/"):
        return None
    try:
        real = os.path.realpath(path)
    except OSError:
        real = path
    for prefix in STAGING_PREFIXES:
        if real.startswith(prefix):
            return prefix
    for sub in HOME_SUBPATHS:
        if f"/{sub}" in real and real.count("/") > 2:
            home = real.split(f"/{sub}", 1)[0] + "/"
            if home.startswith("/home/") or home.startswith("/root/"):
                return sub
    return None


def is_allowlisted(path: str, allowlist) -> str | None:
    """The allowlist entry that covers this path, or None."""
    if not path:
        return None
    try:
        real = os.path.realpath(path)
    except OSError:
        real = path
    for entry in allowlist or ():
        if entry and real.startswith(entry):
            return entry
    return None


def basename(path: str) -> str:
    """The last component, without pathlib. See the note on os.path above."""
    return path.rsplit("/", 1)[-1] if path else ""


def is_shell(comm: str, filename: str) -> bool:
    """
    Is this execution a shell?

    COMM IS WHAT THE KERNEL REPORTED, and it is the value to trust here: it is
    set from the executable at execve time. The basename of the path is checked
    as well because the two disagree exactly when somebody has renamed a shell,
    which is itself interesting. Neither is checked by substring.
    """
    if (comm or "").strip().lower() in SHELL_COMMS:
        return True
    return basename(filename or "").lower() in SHELL_COMMS


def danger_destination(daddr: str, dport) -> bool:
    """
    A connection worth reporting: a dangerous port, off this machine.

    LOOPBACK IS EXCLUDED ON PURPOSE. Port 4444 on 127.0.0.1 is a developer's
    local server, and a rule that fires on it is a rule its reader learns to
    ignore before the one that matters arrives.
    """
    if not dport or int(dport) not in DANGEROUS_PORTS:
        return False
    if not daddr:
        return False
    return not str(daddr).startswith(_IGNORED_DESTINATIONS)


# ONE ANALYSIS PASS

def analyze(config: dict = None, db_path: str = None) -> dict:
    """
    Read the camera since the cursor, and say what is in it.

    RETURNS A REPORT, NOT A LIST OF FINDINGS, and the report always carries the
    coverage that makes the findings readable. The keys:

        findings       the rows the adapter writes
        coverage       what could and could not be read, in words
        analysed       counts of what was actually examined
        cursor         where this pass got to
        seeded         True when this was the first pass over this file
        capped         [{detection_id, shown, dropped}] -- the announced cuts
        notes          anything else that changes how the answer reads

    THIS FUNCTION DOES NOT WRITE FINDINGS. That is the adapter's job, for the
    same reason it is in the local integrity sensor: the module decides what is
    true, the adapter decides how this app records it. Keeping the two apart is
    what makes it possible to test the decision without a database.
    """
    cfg = config_for(config)
    report = {
        "findings": [], "coverage": {}, "analysed": {}, "capped": [],
        "notes": [], "seeded": False, "error": None,
        "cursor": read_cursor(db_path),
    }

    if not cfg["enabled"]:
        report["coverage"]["camera"] = (
            "the camera's reader is switched OFF in config "
            "(sensors.ebpf_events.enabled = false), so NO kernel event is "
            "being analysed at all. That is a configuration choice and not a "
            "failure, and an empty findings list here means nothing was looked "
            "at.")
        return report

    # THE CURSOR TABLE IS THIS MODULE'S OWN, AND THIS IS WHERE IT IS ASKED
    # FOR. E-9: `ensure_cursor_table` had ZERO callers in this file -- its own
    # docstring promised it ran "from the migration and again here", and the
    # "again here" had never been written. A module that only works against a
    # migrated database is a module that raises, or silently stops moving, on
    # the first database that has not been through the migration path -- and
    # the tests and Schema.SQL builds are exactly that case. A failure to
    # create it is REPORTED rather than left to surface as a cursor that never
    # moves.
    if not report["cursor"]["seeded"]:
        if not ensure_cursor_table(db_path):
            report["notes"].append(
                "THE CURSOR TABLE COULD NOT BE CREATED in this app's database, "
                "so nothing this sensor analyses can be remembered and every "
                "pass will re-read the whole window. The database may be "
                "read-only or the schema may be older than this module.")
            report["coverage"]["cursor_table"] = report["notes"][-1]

    status = camera_status(config)
    report["coverage"]["camera"] = status.get("note") or status.get("blind_reason")
    report["camera"] = status

    if not status["reachable"]:
        report["coverage"]["camera_state"] = (
            "UNREADABLE" if status["blind"] else "NOT INSTALLED")
        return report

    path = cfg["events_db"]
    try:
        conn = _ro_connect(path)
    except sqlite3.Error as e:
        report["error"] = f"could not open the camera file: {e}"
        report["coverage"]["camera_state"] = "UNREADABLE"
        return report

    try:
        cursor = report["cursor"]
        if not cursor["seeded"]:
            # THE SEED PASS.
            #
            # There is no earlier state to compare against, so every finding
            # this pass could produce is pre-existing state that nobody has
            # ever looked at. Raising it would be a page of history on the
            # first useful look, which is the dpkg lesson and the setuid
            # lesson, both paid for already.
            #
            # WHAT IS STILL REPORTED is the camera's own health, because that
            # is not a finding about the machine: it is this sensor saying what
            # it can see.
            newest_id, newest_at, newest_ns, conn_id = _newest_position(conn)
            moved = write_cursor(newest_id, newest_at, newest_ns, seeded=True,
                                 last_connect_id=conn_id, db_path=db_path)
            report["seeded"] = True
            report["analysed"] = {"exec": 0, "connect": 0, "seeded": True}
            report["coverage"]["first_pass"] = (
                f"THIS IS THE FIRST ANALYSIS of the camera's file, which already "
                f"holds {status.get('total_events')} event(s) going back to "
                f"before this app ever read it. The cursor was set to the "
                f"newest of them and NOTHING was raised for any of it: a first "
                f"look over somebody else's history is not a change, and a "
                f"monitor that shouts on its first look is one its reader "
                f"skims. Analysis starts from the next event.")
            if not moved:
                report["notes"].append(
                    "THE CURSOR COULD NOT BE SAVED, so this seeding will happen "
                    "again next pass and nothing will ever be analysed. The "
                    "cursor table is in this app's database; the boot log names "
                    "the error.")
            return report

        since_id = int(cursor["last_event_id"] or 0)
        rows = _exec_rows(conn, since_id)
        # THE CURSOR MOVES PAST WHAT WAS PARSED, NOT PAST EVERYTHING.
        #
        # E-3, 2026-09-23. This was AD1's exact shape and the audit measured it
        # against a file that GROWS:
        #
        #     a per-pass limit of 4, six new rows in the file ->
        #       pass 1 parsed ids 2..5 and the cursor jumped to id 6
        #       pass 2 reported analysed.exec=0 and NO note
        #       the row at id 6 (a SHELL on /tmp/e1-shell.sh) was never parsed
        #       by any pass, and the coverage sentence said "Nothing was
        #       skipped"
        #
        # The cursor advanced to the newest event in the file while only the
        # OLDEST rows had been examined, so every row in between was consumed
        # unread -- and the one row the limit ate here was the SHELL, which is
        # the HIGH-severity rule of the two.
        #
        # The floor is the last id actually looked at. A pass with nothing new
        # moves to the newest id, which is what keeps a quiet file cheap; a
        # capped pass stops on the last row it read and the next pass resumes
        # there. This is tools/auditd_monitor.py's fix, applied to the reader
        # whose window is a row count rather than a byte count.
        newest_id, newest_at, newest_ns, newest_connect_id = _newest_position(conn)
        truncated = len(rows) >= EXEC_SCAN_LIMIT
        if truncated:
            exec_floor_id = rows[-1][0]
        else:
            # NOT TRUNCATED MEANS THE WHOLE WINDOW WAS READ, so the cursor goes
            # to the newest row in the file -- which is what it always did, and
            # which is right: there is nothing left unread behind it.
            exec_floor_id = int(newest_id or 0)

        if cfg["watch_staging"]:
            findings, dropped = _staging_findings(rows, cfg)
            report["findings"].extend(findings)
            for cap in dropped:
                report["capped"].append(cap)

        if cfg["watch_ports"]:
            floor_id, reset = _connect_floor(conn, cursor, newest_ns,
                                             newest_connect_id)
            if reset:
                # THE CLOCK WENT BACKWARDS, AND THAT IS A REBOOT.
                #
                # The camera's timestamp is bpf_ktime_get_ns, which counts from
                # BOOT and therefore restarts near zero on every reboot. The
                # watermark the cursor stores is therefore meaningless across
                # one, and a reader that trusted it would filter out EVERY
                # connect for the life of the new boot -- silently, while
                # reporting that it was reading the file fine. That is the
                # exact hole this project treats as fatal, so the reset is
                # detected, acted on, and SAID OUT LOUD rather than inferred.
                report["coverage"]["clock_reset"] = (
                    f"THE CAMERA'S CLOCK IS YOUNGER THAN THIS CURSOR: the newest "
                    f"event's timestamp ({newest_ns}) is lower than the "
                    f"watermark this app recorded from a previous run "
                    f"({cursor.get('last_connect_ns')}). The kernel's monotonic "
                    f"clock restarts at boot, so this is what a reboot looks "
                    f"like. The connect watermark was RESET for this pass "
                    f"instead of filtered against, because filtering would have "
                    f"discarded every connection of the new boot silently.")
                report["notes"].append(report["coverage"]["clock_reset"])
            # THE WINDOW IS AN ID FLOOR, NOT A TIMESTAMP.
            #
            # E-4, 2026-09-23. The connect read was bounded by `ts_ns >=
            # floor`, and ts_ns is the KERNEL'S clock while the cursor is
            # written from what this app has already CONSIDERED. MEASURED, on
            # a camera file driven through the shipped code:
            #
            #     a connect row with the NEXT id and a ts one nanosecond below
            #     the stored watermark ->
            #       the ROW ITSELF was filtered out by the ts >= floor clause
            #       and skipped forever: it is not re-read on the next pass
            #       either. A connection to a dangerous port the sensor can
            #       never report.
            #
            # The id is the camera table's own AUTOINCREMENT -- monotonic by
            # construction -- so the bound is the id, and the window is
            # expressed as where that floor starts. See _connect_floor.
            connect_rows = _connect_rows(conn, floor_id)
            connects = len(connect_rows)
            findings, dropped = _port_findings(connect_rows)
            report["findings"].extend(findings)
            for cap in dropped:
                report["capped"].append(cap)

        report["analysed"] = {"exec": len(rows), "connect": connects,
                              "from_event_id": since_id,
                              "exec_cursor_to": exec_floor_id}
        if truncated:
            deferred = max(0, int(newest_id or 0) - int(exec_floor_id))
            report["coverage"]["scan_limit"] = (
                f"ONLY THE OLDEST {EXEC_SCAN_LIMIT} UNANALYSED EVENT(S) WERE "
                f"LOOKED AT THIS PASS, because that is the per-pass limit. "
                f"{deferred} further event(s) are already in the camera's file "
                f"and have NOT been looked at yet: THE CURSOR WAS LEFT ON THE "
                f"LAST ROW ACTUALLY READ (event id {exec_floor_id}) and the "
                f"next pass resumes there. Nothing was skipped, and this answer "
                f"does not yet cover everything the camera recorded.")
            report["notes"].append(report["coverage"]["scan_limit"])

        report["cursor"] = dict(cursor)
        report["cursor"]["moved_to"] = {"event_id": exec_floor_id,
                                        "event_at": newest_at,
                                        "connect_ns": newest_ns,
                                        "connect_id": int(newest_connect_id or 0),
                                        "newest_in_file": int(newest_id or 0)}
        if not write_cursor(exec_floor_id, newest_at, newest_ns,
                            last_connect_id=int(newest_connect_id or 0),
                            db_path=db_path):
            report["notes"].append(
                "THE CURSOR DID NOT MOVE, so the next pass will re-read this "
                "same window and produce the same findings again.")
        return report
    except sqlite3.Error as e:
        report["error"] = f"{type(e).__name__}: {e}"
        report["coverage"]["camera_state"] = "READ FAILED"
        return report
    finally:
        try:
            conn.close()
        except sqlite3.Error:
            pass


def _newest_position(conn):
    """
    The newest event's id, recorded_at and ts_ns.

    A COLUMN THE TABLE DOES NOT HAVE IS NOT AN ERROR HERE, for AD10's reason:
    this runs against whatever shape a camera file happens to be in, and a
    reader that raises on a missing column reports "no events" for a file full
    of them. The shape is checked once and the SELECT is built from what is
    there.

    THE NEWEST CONNECT'S ID IS RETURNED SEPARATELY from the newest row's,
    because the two can differ: a connect written a moment ago and an exec
    written after it mean the newest ROW is not necessarily the newest
    connect, and the connect window needs its own mark (E-4).
    """
    try:
        have = {r[1] for r in conn.execute("PRAGMA table_info(ebpf_event)")}
    except sqlite3.Error:
        return (0, None, 0, 0)
    if "id" not in have:
        return (0, None, 0, 0)
    cols = ["id"] + [c for c in ("recorded_at", "ts_ns") if c in have]
    try:
        row = conn.execute(
            f"SELECT {', '.join(cols)} FROM ebpf_event "
            f"ORDER BY id DESC LIMIT 1").fetchone()
        got = dict(zip(cols, row)) if row else {}
        newest_id = got.get("id") or 0
        newest_at = got.get("recorded_at")
        newest_ns = got.get("ts_ns") or 0
    except sqlite3.Error:
        return (0, None, 0, 0)
    connect_id = 0
    try:
        r = conn.execute("SELECT MAX(id) FROM ebpf_event WHERE kind = 'connect'"
                         ).fetchone()
        connect_id = (r[0] if r and r[0] else 0)
    except sqlite3.Error:
        connect_id = 0
    return (newest_id, newest_at, newest_ns, connect_id)


def _exec_rows(conn, since_id: int) -> list:
    """
    Unanalysed exec events, oldest first.

    ts_ns is deliberately NOT used for ordering here. It is the kernel's
    monotonic clock, which is not comparable to anything outside the kernel,
    and the camera's own `id` is the only strictly increasing column in the
    table. Ordering by anything else would put rows back in front of the
    cursor and re-raise them.
    """
    try:
        return conn.execute(
            """
            SELECT id, pid, tgid, ppid, uid, comm, parent, filename, ts_ns
            FROM ebpf_event
            WHERE kind = 'exec' AND id > ?
            ORDER BY id ASC
            LIMIT ?
            """, (int(since_id), EXEC_SCAN_LIMIT)).fetchall()
    except sqlite3.Error as e:
        logger.debug(f"ebpf_events: exec read failed: {e}")
        return []


def _connect_floor(conn, cursor: dict, newest_ns: int,
                   newest_connect_id: int = 0) -> tuple:
    """
    Where the connect read starts, and whether the kernel's clock reset.

    ROWS ARE SELECTED BY ID AND NOT BY TIMESTAMP, and that is the whole of
    E-4's fix stated positively. The id is the camera table's own AUTOINCREMENT:
    it is monotonic BY CONSTRUCTION, it survives a reboot, a WAL checkpoint and
    a writer that is faster than this app's poll. `ts_ns` is the KERNEL's
    monotonic clock (bpf_ktime_get_ns, counting from boot) and it is none of
    those things.

    MEASURED, on the shipped code, before this: a connect row with the next id
    and a timestamp ONE NANOSECOND below the stored watermark was filtered out
    by `ts_ns >= floor` alone and never read by any later pass either. The row
    was in the file (id 4, daddr 203.0.113.11) and the sensor could not report
    it. A watermark over a clock this app does not own is not a watermark.

    THE WINDOW IS STILL HONOURED, and it is expressed as where the id floor
    STARTS rather than as a second predicate, for two reasons that were both
    measured on the way to this version:

      * a second predicate of `ts_ns >= floor` lets a PREVIOUS BOOT's rows stay
        "in the future" forever. MEASURED on the intermediate version: after a
        clock reset the next pass re-read three rows from the boot before it,
        and it would have done so on every pass for the life of the file.
      * the window's purpose is "do not judge a week of connections against a
        fifteen-minute idea of relevance". An id floor taken at the cutoff
        achieves exactly that, and the rows before it are left alone by
        construction rather than by a comparison that a reboot defeats.

    THE BOUNDARY OF A REBOOT IS COMPUTED RATHER THAN ASSUMED. Every row written
    before the current boot has a timestamp HIGHER than the newest one now, so
    the last such id is the exact line between the two boots: everything after
    it belongs to this boot and is read, and everything before it belongs to a
    boot whose clock means nothing here.

    Returns (floor_id, did_reset).
    """
    stored_id = int(cursor.get("last_connect_id") or 0)
    stored_ns = int(cursor.get("last_connect_ns") or 0)
    newest = int(newest_ns or 0)
    did_reset = bool(stored_ns and newest and newest < stored_ns)

    floors = [stored_id]
    try:
        # Rows from BEFORE this boot: their monotonic timestamps are larger
        # than anything this boot has produced.
        r = conn.execute("SELECT MAX(id) FROM ebpf_event "
                         "WHERE kind = 'connect' AND ts_ns > ?",
                         (newest,)).fetchone()
        if r and r[0]:
            floors.append(int(r[0]))
    except sqlite3.Error:
        pass
    try:
        # The window's own floor: the newest row at or before the cutoff. This
        # only ever moves the floor FORWARD, which is what the window is for.
        cutoff = max(0, newest - CONNECT_WINDOW_SECONDS * 1_000_000_000)
        r = conn.execute("SELECT MAX(id) FROM ebpf_event "
                         "WHERE kind = 'connect' AND ts_ns <= ?",
                         (cutoff,)).fetchone()
        if r and r[0]:
            floors.append(int(r[0]))
    except sqlite3.Error:
        pass
    return max(floors), did_reset


def _connect_rows(conn, floor_id: int) -> list:
    """
    Connect events newer than the floor, oldest first.

    ONE BOUND, AND IT IS THE SOUND ONE. See _connect_floor: the id is the
    camera's own monotonic key, and every window question is answered by where
    the floor starts rather than by a timestamp comparison that a reboot, a
    checkpoint or a fast writer can defeat.
    """
    try:
        return conn.execute(
            """
            SELECT id, pid, tgid, ppid, uid, comm, parent, daddr, dport,
                   family, ts_ns
            FROM ebpf_event
            WHERE kind = 'connect' AND id > ?
            ORDER BY id ASC
            """, (int(floor_id),)).fetchall()
    except sqlite3.Error as e:
        logger.debug(f"ebpf_events: connect read failed: {e}")
        return []


def _staging_findings(rows: list, cfg: dict):
    """
    The two staging rules, capped and announced.

    ONE PASS OVER THE ROWS FOR BOTH RULES, because they share the expensive
    part (realpath) and because a single pass is the only way to guarantee the
    two rules agree about what they saw.
    """
    out, seen, counts = [], set(), {}
    for row in rows:
        (eid, pid, tgid, ppid, uid, comm, parent, filename, ts_ns) = row
        staged = in_staging_directory(filename)
        if not staged:
            continue
        if (is_allowlisted(filename, cfg["path_allowlist"])
                or (uid == 0
                    and is_allowlisted(filename, ROOT_PATH_ALLOWLIST))):
            counts["allowlisted"] = counts.get("allowlisted", 0) + 1
            continue

        shell = is_shell(comm, filename)
        did = DID_SHELL if shell else DID_LOCATION
        real = os.path.realpath(filename) if filename else ""
        entity = real or (filename or comm or "")

        # A change must be raised ONCE. Dedup on what this app already knows
        # is (source, entity_type, entity_value, title) and the adapter checks
        # it; this set is the cheaper in-pass guard against the same file
        # executing five times in one window.
        key = f"{did}:{entity}"
        if key in seen:
            counts[f"repeat:{did}"] = counts.get(f"repeat:{did}", 0) + 1
            continue
        seen.add(key)

        if counts.get(f"shown:{did}", 0) >= CAP_PER_ID_PER_PASS:
            counts[f"cut:{did}"] = counts.get(f"cut:{did}", 0) + 1
            continue
        counts[f"shown:{did}"] = counts.get(f"shown:{did}", 0) + 1

        out.append({
            "detection_id": did,
            "entity_type": "process",
            "entity_value": entity[:400],
            "severity": "high" if shell else "low",
            "title": ("A shell was started on a file in a staging directory"
                      if shell else
                      "A program ran from a staging directory"),
            "description": _describe_staging(shell, filename, comm, parent,
                                             pid, uid, staged),
            "raw_data": {
                "camera_event_id": eid, "pid": pid, "tgid": tgid,
                "ppid": ppid, "uid": uid, "comm": comm, "parent_comm": parent,
                "path": filename, "realpath": real, "matched": staged,
                "detection_id": did,
            },
        })

    for did, label in ((DID_LOCATION, "execution_from_staging_directory"),
                       (DID_SHELL, "shell_on_staged_file")):
        cut = counts.get(f"cut:{did}", 0)
        if cut:
            out.append(_cut_row(did, label, counts.get(f"shown:{did}", 0), cut,
                                "program(s) executed from a staging directory"))
    return out, []


def _cut_row(did, label, shown, cut, what):
    """
    THE ANNOUNCED CUT, which is part of the check rather than an extra.

    A capped list that does not say it was capped is a lie of omission: "5
    programs ran from /tmp" and "5 of 436 programs that ran from /tmp are
    listed here" are different sentences, and only the second one lets a reader
    decide whether to care. This row carries the count and is itself capped at
    one per id per pass.
    """
    return {
        "detection_id": did,
        "entity_type": "process",
        "entity_value": f"capped:{did}",
        "severity": "low",
        "title": f"More than {shown} {what} in this window",
        "description": (
            f"{cut} further event(s) for rule {label} were NOT written as "
            f"findings during this pass, because a single pass is capped at "
            f"{CAP_PER_ID_PER_PASS} per rule so that a build or a batch job in "
            f"a staging directory cannot bury the dashboard. THE EVENTS "
            f"THEMSELVES ARE NOT LOST and the cap is not applied to the "
            f"camera's file: query_ebpf_events reads the raw records. This row "
            f"will not repeat while it is open."),
        "raw_data": {"capped": True, "shown": shown, "dropped": cut,
                     "detection_id": did},
    }


def _describe_staging(shell, filename, comm, parent, pid, uid, staged):
    """
    The finding's own sentence, and it has to carry the innocent reading.

    A staging directory is where installers, browser downloads, build tools and
    every `mktemp` script on the machine legitimately put things. A finding
    that does not say so is a finding that trains its reader to assume malice,
    which is the failure this project's whole voice is written against.
    """
    innocent = (
        "This is where installers, package builds, downloaded files and every "
        "script that uses mktemp legitimately run, so the location alone is not "
        "evidence of anything.")
    if shell:
        lead = (
            f"A shell ({comm!r}) executed {filename} from {staged}, started by "
            f"{parent!r} (pid {pid}, uid {uid}). A shell is a program whose "
            f"whole purpose is running other programs, so the file at that path "
            f"is a script that something chose to start.")
    else:
        lead = (
            f"{comm!r} (pid {pid}, uid {uid}, started by {parent!r}) executed "
            f"{filename} from {staged}.")
    return (lead + " The kernel recorded this execution directly, so it does "
            f"not depend on the process still being alive: it was seen even if "
            f"it lasted a fraction of a second. {innocent}")


def _port_findings(rows: list):
    """Connections to dangerous ports, capped and announced."""
    out, seen, counts = [], set(), {}
    for row in rows:
        (eid, pid, tgid, ppid, uid, comm, parent, daddr, dport, family,
         ts_ns) = row
        if not danger_destination(daddr, dport):
            continue
        entity = str(daddr)
        if entity in seen:
            counts["repeat"] = counts.get("repeat", 0) + 1
            continue
        seen.add(entity)
        if counts.get("shown", 0) >= CAP_PER_ID_PER_PASS:
            counts["cut"] = counts.get("cut", 0) + 1
            continue
        counts["shown"] = counts.get("shown", 0) + 1
        out.append({
            "detection_id": DID_PORT,
            "entity_type": "ip",
            "entity_value": entity,
            "severity": "medium",
            "title": "A local process connected to a port used by remote-control tooling",
            "description": (
                f"{comm!r} (pid {pid}, uid {uid}, started by {parent!r}) opened "
                f"a connection to {daddr}:{dport} ({family}). {dport} is one of "
                f"the ports that appear in the default configurations of "
                f"remote-control and post-exploitation tools "
                f"({', '.join(str(p) for p in sorted(DANGEROUS_PORTS))}). That "
                f"is a weaker claim than \"known bad\": it is a port nobody "
                f"usually listens on by accident, and the honest test is what "
                f"is at the other end. The capture, if it is running, has the "
                f"same connection from the wire side."),
            "raw_data": {"camera_event_id": eid, "pid": pid, "tgid": tgid,
                         "ppid": ppid, "uid": uid, "comm": comm,
                         "parent_comm": parent, "daddr": daddr,
                         "dport": dport, "family": family,
                         "detection_id": DID_PORT},
        })
    if counts.get("cut"):
        out.append(_cut_row(DID_PORT, "process_connect_dangerous_port",
                            counts.get("shown", 0), counts["cut"],
                            "connection(s) to a dangerous port"))
    return out, []


# THE TOOL'S OWN REPORT

def recent_events(config: dict = None, db_path: str = None, kind: str = None,
                  limit: int = 50, search: str = None) -> dict:
    """
    RAW CAMERA ROWS, for looking at what the camera actually saw.

    THIS IS THE OTHER HALF OF THE ANSWERS. A findings list is a judgement; this
    is the evidence, and both are needed the first time somebody asks "why do
    you think that". It is capped and it says it is capped, because the camera
    can hold millions of rows and nothing here should ever try to serve them
    all into a model's context.
    """
    cfg = config_for(config)
    out = {"events_db": cfg["events_db"], "kind": kind or "any",
           "limit": limit, "events": [], "note": None, "coverage": {}}
    status = camera_status(config)
    out["coverage"]["camera"] = status.get("note") or status.get("blind_reason")
    out["camera_state"] = ("running" if status["running"]
                           else "not_running" if status["has_ever_run"]
                           else "never_run" if status["reachable"]
                           else "unreadable")

    if not status["reachable"]:
        out["note"] = (status.get("blind_reason") or status.get("note")
                       or "the camera's file could not be read")
        return out

    limit = max(1, min(int(limit or 50), 200))
    try:
        conn = _ro_connect(cfg["events_db"])
    except sqlite3.Error as e:
        out["note"] = f"the camera file could not be opened: {e}"
        return out
    try:
        where, params = [], []
        if kind in ("exec", "connect"):
            where.append("kind = ?")
            params.append(kind)
        if search:
            # A CONTAINS MATCH ON THE THREE TEXT COLUMNS, with the pattern
            # bound as a parameter rather than interpolated. `search` comes
            # from a model or an operator and the values it is matched against
            # came from a process table, so both ends of this are untrusted
            # text going into SQL.
            where.append("(comm LIKE ? OR filename LIKE ? OR daddr LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like])
        sql = ("SELECT id, kind, recorded_at, pid, tgid, ppid, uid, comm, "
               "parent, filename, daddr, dport, family, ts_ns FROM ebpf_event")
        if where:
            sql += " WHERE " + " AND ".join(where)
        # NEWEST FIRST HERE, unlike the analysis pass. A person asking "what
        # has the camera seen" wants the latest rows; a cursor wants the oldest
        # unprocessed ones. The same query with the opposite sort serves two
        # different questions honestly.
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        out["events"] = [
            {"event_id": r[0], "kind": r[1], "at": r[2], "pid": r[3],
             "tgid": r[4], "ppid": r[5], "uid": r[6], "comm": r[7],
             "parent_comm": r[8],
             "path": r[9], "daddr": r[10], "dport": r[11], "family": r[12],
             "ts_ns": r[13]}
            for r in rows]
        total = conn.execute("SELECT COUNT(*) FROM ebpf_event").fetchone()[0]
        out["total_events"] = total
        if len(out["events"]) >= limit:
            out["note"] = (
                f"SHOWING THE {len(out['events'])} NEWEST EVENT(S) OF {total} "
                f"IN THE FILE. This is a cut, not the whole record: pass a "
                f"smaller limit, a kind, or a search term to narrow it.")
        else:
            out["note"] = f"ALL {len(out['events'])} MATCHING EVENT(S), of {total} on file."
        return out
    except sqlite3.Error as e:
        out["note"] = f"the camera file could not be read: {type(e).__name__}: {e}"
        return out
    finally:
        try:
            conn.close()
        except sqlite3.Error:
            pass
