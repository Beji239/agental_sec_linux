# tools/auditd_monitor.py
# AgentalSec Linux, L4. THE AUDIT SUBSYSTEM: read it if it is there, and SAY SO
# if it is not.
#
# WHAT THIS IS, IN ONE LINE
#
# The Linux kernel's own audit subsystem records syscalls, file watches and
# account changes at the kernel level, with the identity of whoever did it. On
# a host where it is running, its log is the deepest always-listening feed
# available. This module reads that log and raises findings from two things
# nothing else in this tree can see.
#
# THE PART THAT MATTERS MOST ON THIS MACHINE: IT IS NOT INSTALLED.
#
# MEASURED on the owner's box, 2026-09-22, and the finding is the whole reason
# this module has a shape rather than a feature:
#
#   auditctl, auditd, ausearch, aureport, augenrules   NONE PRESENT
#   /etc/audit, /etc/audit/auditd.conf, /etc/audit/rules.d   DO NOT EXIST
#   /var/log/audit, /var/log/audit/audit.log                 DO NOT EXIST
#   libaudit.so.1                        PRESENT (pulled in by something else)
#   systemctl is-active auditd           inactive
#   systemctl is-enabled auditd          not-found
#
# So the honest answer from this machine is NOT "no audit events", which is
# what a quiet module would say and what a reader would take as a clean
# bill of health. It is: THE KERNEL FEED IS ABSENT, NOTHING IS BEING
# RECORDED, and here is the one command that changes that.
#
# The owner's approved wording for this task, Q7 on 2026-09-17: "The module
# must report 'not installed, blind, here is the one command' rather than
# pretending." That is what status() and the coverage block do, and it is why
# this file spends more lines on the absence than on the parsing.
#
# THE ONE COMMAND, and it is printed rather than described:
#
#     sudo apt install auditd
#
# WHY IT IS NOT BLIND WHEN AUDITD IS SIMPLY NOT INSTALLED
#
# The same argument LinuxEbpfEvents makes about its camera, and it is the same
# situation: the absence is a DELIBERATE state of the machine (it needs root
# and a package install that only the operator can do), not a fault in this
# app. Reporting `blind` for it would attach a permanent caveat to every
# query_findings answer for the life of the installation, which is how a
# warning list becomes something a reader skips.
#
# So the absence travels as a NAMED STATE: `installed: False`, a `note` in
# words, and a `coverage_limits` entry. It IS blind for the two real failures:
# the log exists and cannot be opened, or the log exists and is not an audit
# log. Those are "I could not look" and they are about this app rather than
# about the operator's choices.
#
# THE TWO RECORD FORMATS, AND WHY BOTH ARE READ
#
# audit 3.x writes TWO shapes into the same file, and a parser that knows only
# one of them gets a plausible result from the other: it finds the records
# whose fields are in the raw form, silently misses the enriched ones, and
# reports a smaller number than the truth with no error anywhere.
#
#   RAW       type=SYSCALL msg=audit(1695000000.123:456): arch=c000003e ...
#             type=PATH msg=audit(1695000000.123:456): item=0 name="/etc/passwd" ...
#   ENRICHED  type=PROCTITLE msg=audit(1695000000.123:456): proctitle=...
#             ... AUDIT_FIELD\x1dkey="value"\x1dkey="value"\x1d
#
# The second form appends unit-separator-delimited key=value pairs after the
# human-readable half. Both are handled here, and there is a test for each,
# because this is the class of defect that produces a WRONG COUNT rather than
# an exception.
#
# WHAT IT DELIBERATELY DOES NOT DO
#
#   * It does not install anything, start anything, or write a single audit
#     rule. Installing the kernel feed is the operator's act, and a security
#     tool that silently enables kernel-level logging of everything on the
#     machine is the worst thing this project could ship. The command is
#     PRINTED. The operator runs it.
#   * It does not run ausearch or aureport. Those are a subprocess per pass
#     against a root-owned file, and reading the log directly is both cheaper
#     and testable against a fixture.
#   * It does not raise on the SEED pass. A log file that already holds weeks
#     of records is somebody else's history, and a first look that shouts is a
#     first look a reader learns to skim. Seed, then diff -- the same rule the
#     kernel camera's reader and the local integrity sensor both follow.
#   * It does not decode every record type. Two are raised on, and everything
#     else is COUNTED by type so that "nothing found" can be read against what
#     was actually there. A module that silently ignores 90% of its input and
#     reports zero findings is the shape this whole project is written against.

import logging
import os
import re
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

ROLE = "auditd"

# THE ONE COMMAND, AND THE PATHS IT WOULD CREATE

INSTALL_COMMAND = "sudo apt install auditd"

# Where the log lives on every mainstream distribution. Debian and Ubuntu use
# /var/log/audit/audit.log; the config file can move it, so the config is read
# when it exists and this is the fallback.
DEFAULT_LOG_PATH = "/var/log/audit/audit.log"
DEFAULT_AUDITD_CONF = "/etc/audit/auditd.conf"

# The binaries whose absence means "the tools are not installed". auditd itself
# is the daemon; the others are what a person would use to read the log, and
# their absence is what makes the one command a package install rather than a
# service start.
_REQUIRED_BINARIES = ("auditd", "auditctl")

# How far back a log may be before it is called STALE rather than quiet. An
# idle machine legitimately records nothing for minutes; systemd, cron and
# logins put something in the log on any working host within the hour.
STALE_AFTER_SECONDS = 3600

# A single pass reads at most this much NEW data from the log. An audit log
# under load can grow faster than this app reads, and the honest response is a
# bounded read plus a coverage sentence, never an unbounded slurp of a file
# that may be gigabytes.
MAX_READ_BYTES = 8 * 1024 * 1024
MAX_LINES_PER_PASS = 20000

# One finding per id per pass for the aggregate rows, plus the announced cut.
CAP_PER_ID_PER_PASS = 10

# THE RECORD TYPES THE KERNEL'S OWN WORD ARRIVES IN
#
# auditd writes its own state into the log as records, and two of them are the
# difference between "the rules changed" and "THE RECORDING STOPPED":
#
#   KERNEL      every KERNEL record is a snapshot of the kernel audit
#               configuration: audit_enabled, audit_lost,
#               audit_backlog_limit, audit_rate_limit. `auditctl -e 0` sets
#               audit_enabled=0 and the kernel then records NOTHING until
#               somebody turns it back on -- which is a fact about every
#               quiet answer that follows it.
#   DAEMON_END  the auditd process exited, by shutdown or by signal.
#
# BOTH ARE READ AND BOTH ARE RAISED ON (AUD-1003 and AUD-1004 in the
# register). They are NOT "a record type we do not decode": each one is a
# fact that makes a later empty findings list wrong to read as a quiet
# machine, which is the single class of thing this module exists to refuse.
# The first version of this file counted them as `unhandled:` and reported
# zero findings, which is exactly the shape its own header warns about.
_KERNEL_STATE_TYPE = "KERNEL"
_DAEMON_END_TYPE = "DAEMON_END"

# The kernel writes this in a KERNEL record when records have been dropped
# because the backlog overflowed -- the OTHER way a kernel feed can be
# quietly incomplete.
_KERNEL_MISSED_FIELDS = ("audit_lost", "lost")

# The shapes a record can take. Both are anchored on the audit() timestamp,
# which every record carries and which is the only reliable ordering key.
_AUDIT_RE = re.compile(r"audit\((\d+(?:\.\d+)?):(\d+)\)")
_TYPE_RE = re.compile(r"^type=([A-Z0-9_]+)")
_KEYVAL_RE = re.compile(r'([A-Za-z0-9_]+)=("[^"]*"|\S+)')

# The enrichment separator in audit 3.x. Written as an escape so the byte
# never appears in this file's own text, which matters: a literal unit
# separator in a source file makes grep, diff and every editor misbehave.
_GS = "\x1d"

# The id field is the ONLY thing that groups records of one syscall together,
# and auditd writes the same msg=audit(...:ID) on every record of an event.
_MSGID_RE = re.compile(r"audit\(\d+(?:\.\d+)?:(\d+)\)")


# IS IT THERE, AND CAN THIS RUN SEE IT

def _which(name: str) -> str | None:
    """Where a binary lives, without importing shutil into a poll path."""
    for directory in ("/usr/sbin", "/sbin", "/usr/bin", "/bin",
                      "/usr/local/sbin", "/usr/local/bin"):
        candidate = os.path.join(directory, name)
        if os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _configured_log_path() -> str:
    """
    The log path auditd itself would use, if it says so.

    READ FROM THE CONFIG RATHER THAN ASSUMED, because auditd.conf carries a
    `log_file` line and a host that moved it would otherwise be reported as
    having no log at all -- the "wrong file, correct-looking answer" failure.
    An unparseable or missing config falls back to the distribution default,
    and the fallback is named in the answer rather than passed off as read.
    """
    try:
        with open(DEFAULT_AUDITD_CONF, "r", encoding="utf-8",
                  errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                if key.strip() == "log_file":
                    path = value.strip().strip('"').strip("'")
                    if path:
                        return path
    except OSError:
        pass
    return DEFAULT_LOG_PATH


def config_for(config: dict = None) -> dict:
    """
    The `sensors.auditd` block, read once, with its defaults named.

    TWO KEYS, AND EACH ONE EARNS ITS PLACE. A missing block is not an error and
    is not a silent default -- the defaults are named here and the caller can
    always see which are in force, because `enabled` appears in the status the
    adapter publishes.

      enabled     whether this app reads the log at all. OFF and BROKEN stay
                  different sentences: the module still loads and still reports
                  the machine's state, and the pass says it was switched off.
      log_path    WHERE TO READ INSTEAD OF THE CONFIGURED PATH. This exists
                  because auditd.conf IS the authority for where auditd writes,
                  and on a host with no auditd there is no conf to read -- so a
                  verification run has to be able to point the reader at a
                  fixture file without becoming root and editing /etc. Absent
                  means "read what auditd.conf says", which is the honest
                  default.
    """
    block = {}
    try:
        block = ((config or {}).get("sensors", {}) or {}).get(ROLE, {}) or {}
    except Exception as e:                              # noqa: BLE001
        logger.debug(f"auditd: config block unreadable: {e}")
        block = {}

    override = block.get("log_path")
    return {
        "enabled": bool(block.get("enabled", True)),
        "log_path": str(override) if override else None,
    }


def status(config: dict = None) -> dict:
    """
    What the audit subsystem is, in words, without pretending.

    The keys every sensor in this tree publishes (running / ready / reachable /
    blind / blind_reason) plus the ones that make the ABSENCE readable:
    `installed`, `tools_present`, `paths_present`, `install_command`.

    NEVER RAISES. This is read at boot and on the readiness page, and a
    module that can break the readiness page by finding a missing directory is
    a module that gets switched off.

    THIS IS A STATEMENT ABOUT THE MACHINE, NOT ABOUT THIS APP'S CHOICES, and
    that is why `enabled` is reported beside the facts rather than collapsed
    into them: auditd either is or is not installed on this host whether or not
    somebody switched the reader off, and the two facts have different remedies.
    """
    cfg = config_for(config)
    out = {
        "role": ROLE,
        "enabled": cfg["enabled"],
        # THE STATE STRING IS DECIDED HERE AND NOWHERE ELSE. Four callers need
        # to know which of these situations the machine is in -- the boot's log
        # line, the adapter's headline, the model-facing tool, and the analysis
        # pass -- and four copies of the same if-cascade is exactly how four
        # surfaces end up disagreeing about the same machine. It is a value in
        # this dict so that a caller reads it rather than recomputing it.
        #
        #   OFF BY CONFIG   sensors.auditd.enabled is false. Our choice.
        #   NOT INSTALLED   no audit userspace on this machine. Stated limit.
        #   HALF INSTALLED  the configuration is there and the tools are not,
        #                   or the reverse. Records nothing, and it is NOT
        #                   "no log yet": there is no daemon to write one, so
        #                   "restart it" is not the remedy and reading it as
        #                   NOT INSTALLED sends the operator hunting for a
        #                   package that is already half there.
        #   NO LOG YET      installed, nothing written. Restart auditd.
        #   CANNOT READ LOG the log is there and this account cannot open it.
        #   READABLE        records were read.
        "state": None,
        "installed": False,
        "installed_reason": None,
        "tools_present": {},
        "paths_present": {},
        "install_command": INSTALL_COMMAND,
        "log_path": None,
        "log_path_source": None,
        "log_path_warning": None,
        "log_readable": False,
        "reachable": False,
        "running": False,
        "ready": False,
        "blind": False,
        "blind_reason": None,
        "note": None,
        "coverage_limits": [],
    }

    for binary in _REQUIRED_BINARIES:
        out["tools_present"][binary] = _which(binary)

    for path in ("/etc/audit", DEFAULT_AUDITD_CONF, "/etc/audit/rules.d",
                 "/var/log/audit"):
        out["paths_present"][path] = os.path.exists(path)

    if cfg["log_path"]:
        log_path = cfg["log_path"]
        out["log_path_source"] = ("config: sensors.auditd.log_path overrides "
                                  "whatever auditd.conf says")
    else:
        log_path = _configured_log_path()
        out["log_path_source"] = (
            f"read from {DEFAULT_AUDITD_CONF}"
            if os.path.exists(DEFAULT_AUDITD_CONF)
            else f"{DEFAULT_AUDITD_CONF} does not exist, so this is the "
                 f"distribution default")
    out["log_path"] = log_path
    out["paths_present"][log_path] = os.path.exists(log_path)

    tools_ok = all(out["tools_present"].get(b) for b in _REQUIRED_BINARIES)
    config_ok = out["paths_present"].get(DEFAULT_AUDITD_CONF, False)
    out["installed"] = bool(tools_ok or config_ok)

    # SWITCHED OFF IS NOT BROKEN.
    #
    # Checked BEFORE the machine's state, because a reader that is off is not
    # reading anything whatever the machine looks like, and the two facts have
    # different remedies. `installed` above is still filled in and still
    # travels with the answer, so the page can say both sentences.
    if not cfg["enabled"]:
        out["state"] = "OFF BY CONFIG"
        out["note"] = (
            "THE AUDIT READER IS SWITCHED OFF in config "
            "(sensors.auditd.enabled = false), so NOTHING is reading the "
            "kernel audit log. That is a configuration choice and not a "
            "failure, and an empty findings list here means nothing was looked "
            "at. The machine's own state is reported beside this: "
            + ("the audit userspace IS installed here."
               if out["installed"] else
               "the audit userspace is NOT installed here either."))
        out["coverage_limits"].append(out["note"])
        return out

    # THE ABSENCE, NAMED.
    #
    # This is the branch this host takes, so it is the branch that has to be
    # most carefully worded. It does not say "no events". It says nothing is
    # being recorded, lists what is missing, and prints the command.
    #
    # SKIPPED WHEN A LOG PATH IS CONFIGURED, and that exception is deliberate
    # rather than a hole: an operator or a verification script that has set
    # sensors.auditd.log_path has NAMED the file to read, and refusing to read
    # it because /etc/audit does not exist would make this module untestable
    # against a fixture on the one host it has to be tested on -- which is
    # exactly the host where auditd is not installed. The override is named in
    # log_path_source either way, and the machine's own state is still reported
    # in `installed` and `installed_reason`.
    if not cfg["log_path"]:
        if not tools_ok and not config_ok:
            missing_binaries = [b for b in _REQUIRED_BINARIES
                                if not out["tools_present"].get(b)]
            out["installed_reason"] = (
                f"the audit userspace is not installed on this machine "
                f"(missing: {', '.join(missing_binaries)}; "
                f"{DEFAULT_AUDITD_CONF} does not exist). "
                f"libaudit.so may still be present, pulled in by another "
                f"package, and that is NOT the audit subsystem.")
            out["note"] = (
                "THE KERNEL AUDIT FEED IS ABSENT on this machine. Auditd "
                "records syscalls, file watches and account changes at the "
                "kernel level with the identity of whoever did it, and on this "
                "host NOTHING of that kind is being recorded. So an empty list "
                "of audit findings here says nothing about this machine: "
                "nothing was watching. "
                f"To change that, one command: {INSTALL_COMMAND}")
            out["state"] = "NOT INSTALLED"
            out["coverage_limits"].append(out["note"])
            return out

        if not tools_ok:
            # Half-installed: the config is there and the tools are not, or
            # the reverse. Named as such rather than collapsed into either
            # answer.
            missing_binaries = [b for b in _REQUIRED_BINARIES
                                if not out["tools_present"].get(b)]
            out["installed_reason"] = (
                f"{DEFAULT_AUDITD_CONF} exists but the tools do not "
                f"(missing: {', '.join(missing_binaries)}). A half-installed "
                f"audit subsystem records nothing.")
            out["note"] = (
                "THE AUDIT CONFIGURATION IS PRESENT AND THE AUDIT TOOLS ARE "
                "NOT, so nothing is being recorded despite the machine looking "
                f"configured. One command: {INSTALL_COMMAND}")
            # NOT "NOT INSTALLED": half of it is installed, and a reader who
            # goes looking for a missing package will find one already there.
            #
            # AND NOT "NO LOG YET" EITHER, which is what the first version of
            # this branch said and what both consumers of the state string
            # rendered as "the audit tools are installed and there is no
            # readable log yet. Start it with: sudo systemctl start auditd".
            # The tools are NOT installed, so that start command fails, and
            # the sentence sent the operator to restart a daemon that is not
            # there. MEASURED on a fixture with /etc/audit/auditd.conf present
            # and no binaries: state NO LOG YET, installed True, tools
            # {'auditd': None, 'auditctl': None}. Its own state now.
            out["state"] = "HALF INSTALLED"
            out["coverage_limits"].append(out["note"])
            return out

    if not os.path.exists(log_path):
        if cfg["log_path"]:
            out["installed_reason"] = (
                f"sensors.auditd.log_path sends this reader to {log_path}, "
                f"and that file does not exist.")
            out["note"] = (
                f"THE CONFIGURED AUDIT LOG IS NOT THERE. sensors.auditd."
                f"log_path names {log_path} and nothing is at that path, so "
                f"NOTHING was examined, which is a different sentence from "
                f"finding nothing. Clear that setting to read what auditd "
                f"itself is configured to write.")
        else:
            out["installed_reason"] = (
                f"the audit tools are installed and {log_path} does not exist "
                f"yet. That is what an installed-but-never-used audit "
                f"subsystem looks like.")
            out["note"] = (
                f"THE AUDIT TOOLS ARE INSTALLED but there is no log at "
                f"{log_path}, so nothing has been recorded. Either the daemon "
                f"has never run, or it was stopped before it wrote anything. "
                f"Restart it and ask whether it is recording: "
                f"sudo systemctl restart auditd, then "
                f"sudo systemctl status auditd")
        out["state"] = "NO LOG YET"
        out["coverage_limits"].append(out["note"])
        return out

    out["reachable"] = True

    # A CONFIGURED LOG ON A HOST WITH NO AUDITD.
    #
    # Reachable here and `installed: false`, and the two are NOT in conflict --
    # this is the state a verification run against a fixture log is in, and it
    # is a state a reader must be able to read correctly rather than be
    # surprised by. Said in words here because the payload carries both fields
    # and "READABLE" beside "installed: false" is exactly the kind of pair
    # somebody reports as a bug. It is not: the reader was told WHERE to read
    # and read it. What the machine is NOT doing is writing one.
    #
    # CARRIED IN ITS OWN FIELD AND NOT IN `note`, deliberately: `note` below is
    # overwritten by every state branch that follows (recording / stale / age
    # unreadable), so a warning parked there would be silently replaced by
    # whichever sentence came last -- the "a caveat that stops being said"
    # defect, in the one place a reader is told not to trust the ages.
    if not out["installed"]:
        out["log_path_warning"] = (
            f"WARNING, AND READ THIS BEFORE TRUSTING A NUMBER FROM HERE. "
            f"sensors.auditd.log_path sent this reader to {log_path}, and it "
            f"was read. But the audit userspace IS NOT INSTALLED on this "
            f"machine, so this file is NOT being written by a running auditd: "
            f"either it is a fixture, or it is a log left behind by an "
            f"installation that has since been removed. Its age says nothing "
            f"about this machine right now.")
        out["coverage_limits"].append(out["log_path_warning"])

    # CAN THIS ACCOUNT READ IT. The log is 0600 root:root on every default
    # install, so an unelevated run cannot. That is a statement about this
    # app's reach, not about the machine, and it is the ONE case here that is
    # genuinely `blind` -- because the sensor's entire input is unreadable and
    # there is no partial half to fall back on.
    if not os.access(log_path, os.R_OK):
        out["blind"] = True
        out["state"] = "CANNOT READ LOG"
        try:
            st = os.stat(log_path)
            mode = oct(st.st_mode & 0o777)
            owner = st.st_uid
            detail = f"mode {mode}, uid {owner}"
        except OSError:
            detail = "permissions could not be read"
        out["blind_reason"] = (
            f"the audit log exists at {log_path} ({detail}) and this account "
            f"cannot read it. Auditd writes it root-only by default. NOTHING "
            f"has been examined, which is a different sentence from finding "
            f"nothing: run this app elevated (scripts/run_elevated.sh) to read "
            f"the kernel feed.")
        out["coverage_limits"].append(out["blind_reason"])
        return out

    out["log_readable"] = True
    out["state"] = "READABLE"

    # THE KERNEL'S OWN SWITCH, READ FROM THE LOG.
    #
    # auditctl -e 0 / -e 2 changes what the KERNEL records, not what auditd
    # writes, and it is the difference between a quiet machine and a switched
    # -off recorder. It is answered from the newest KERNEL record in the tail
    # of the log, and only when the tail holds one -- a log that has never
    # carried a KERNEL record says None rather than inventing 1.
    kernel_enabled = _newest_kernel_enabled(log_path)
    if kernel_enabled is not None:
        out["kernel_enabled"] = kernel_enabled

    age = _newest_record_age(log_path)
    if age is not None:
        out["newest_record_age_seconds"] = round(age, 1)
        if age > STALE_AFTER_SECONDS:
            # NOT blind, for the camera's reason: the file is readable and
            # holds real records. What has stopped is the recording.
            out["note"] = (
                f"the audit log is readable and its newest record is "
                f"{round(age)}s old, past the {STALE_AFTER_SECONDS}s window. "
                f"THE RECORDING MAY HAVE STOPPED, or the machine may simply "
                f"have been idle. Everything after that moment is unrecorded, "
                f"so a quiet result covers the period before it only."
                + (f" AND THE KERNEL'S AUDIT SWITCH ITSELF READS "
                   f"audit_enabled={kernel_enabled}, so this feed is not "
                   f"merely idle: the kernel is not recording."
                   if kernel_enabled == 0 else ""))
            out["coverage_limits"].append(out["note"])
        else:
            out["running"] = True
            out["ready"] = True
            out["note"] = (
                f"the audit subsystem is recording: the log at {log_path} has "
                f"a record {round(age)}s old (window {STALE_AFTER_SECONDS}s)."
                + (f" BUT THE KERNEL'S AUDIT SWITCH READS audit_enabled=0, so "
                   f"the RECORDING has been turned OFF under a log that is "
                   f"still fresh, see the kernel_enabled coverage sentence."
                   if kernel_enabled == 0 else ""))
            if kernel_enabled == 0:
                out["coverage_limits"].append(_kernel_enabled_text(0))
    else:
        out["running"] = True
        out["ready"] = True
        out["note"] = (f"the audit log at {log_path} is readable. Age could "
                       f"not be read from its last line, so whether it is "
                       f"still being written is UNKNOWN.")

    return out


def _newest_kernel_enabled(path: str):
    """
    audit_enabled from the newest KERNEL record in the tail, or None.

    THE SAME TAIL READ _newest_record_age MAKES, for the same reason: an audit
    log is hundreds of megabytes and this runs on a 60-second poll. Only
    complete lines are trusted, and a tail with no KERNEL record answers None
    rather than guessing 1.
    """
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            tail = min(size, 65536)
            fh.seek(size - tail)
            raw = fh.read(tail)
    except OSError:
        return None
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if tail < size and lines:
        lines = lines[1:]                 # the first line is a fragment
    for line in reversed(lines):
        record = parse_record(line)
        if record and record.get("type") == _KERNEL_STATE_TYPE:
            return _kernel_enabled_from([record])
    return None


# READING THE LOG

def _newest_record_age(path: str):
    """
    Seconds since the newest record in the log, or None.

    READS THE TAIL, NOT THE FILE. An audit log on a busy host is hundreds of
    megabytes and this runs on a 60-second poll; seeking to the end and reading
    the last few kilobytes is the only shape that is affordable. A file small
    enough to read whole is read whole, which keeps the fixture tests exact.
    """
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            tail = min(size, 65536)
            fh.seek(size - tail)
            raw = fh.read(tail)
    except OSError:
        return None

    text = raw.decode("utf-8", errors="replace")
    # The newest record is the LAST parseable audit() stamp in the tail. A
    # partially written final line is normal on a live log, so the search goes
    # backwards through whole lines rather than trusting the last one.
    for line in reversed(text.splitlines()):
        stamp = _record_time(line)
        if stamp is not None:
            return max(0.0, time.time() - stamp)
    return None


def _record_time(line: str):
    """The unix time of a record's audit() stamp, or None."""
    m = _AUDIT_RE.search(line or "")
    if not m:
        return None
    try:
        return float(m.group(1))
    except (TypeError, ValueError):
        return None


def _iso(seconds) -> str:
    try:
        return datetime.fromtimestamp(float(seconds), tz=timezone.utc) \
                       .isoformat()
    except (TypeError, ValueError, OSError):
        return None


def parse_record(line: str) -> dict | None:
    """
    One log line as a dict, or None when it is not a record.

    RETURNS EVERY FIELD IT CAN FIND, from BOTH formats, and never raises. The
    keys every caller can rely on:

        type      the record type, e.g. "PATH" or "CONFIG_CHANGE"
        msg_id    the event id that groups records of one syscall
        at        unix seconds, from the audit() stamp
        fields    every key=value pair, raw and enriched alike
    """
    if not line:
        return None
    line = line.strip()
    if not line:
        return None

    type_match = _TYPE_RE.match(line)
    if not type_match:
        # Not a record. auditd also writes multi-line human messages (the
        # DAEMON_* family) and a "----" separator; those are not key=value
        # records and are skipped rather than being forced into the shape.
        return None

    record = {
        "type": type_match.group(1),
        "msg_id": None,
        "at": None,
        "fields": {},
        "raw": line,
    }

    msg = _MSGID_RE.search(line)
    if msg:
        record["msg_id"] = int(msg.group(1))
    stamp = _record_time(line)
    if stamp is not None:
        record["at"] = stamp
        record["at_iso"] = _iso(stamp)

    # THE ENRICHED HALF.
    #
    # audit 3.x appends \x1d-separated key=value pairs after the readable
    # half. They are the SAME values, quoted, and they are the half that
    # survives a path with a space in it: the raw form writes `name="/tmp/a b"`
    # unquoted in some versions, where a naive split breaks the field in two
    # and reports a path that does not exist. Where both halves carry a field,
    # THE ENRICHED VALUE WINS, because it is the one that was written
    # explicitly rather than the one a human is reading.
    enriched = {}
    readable = line
    if _GS in line:
        readable, _, tail = line.partition(_GS)
        for chunk in tail.split(_GS):
            chunk = chunk.strip()
            if not chunk or "=" not in chunk:
                continue
            key, _, value = chunk.partition("=")
            value = value.strip().strip('"')
            if key.strip():
                enriched[key.strip()] = value

    # THE ENRICHED HALF IS PARSED ONLY WHERE IT ACTUALLY IS.
    #
    # The key=value scan runs over `readable` (the line UP TO the separator),
    # not over the whole line. Running it over the whole line meant every
    # enriched pair was found twice -- once raw, then overwritten by the
    # enriched value from the same scan -- so the "ENRICHED VALUE WINS"
    # comment above described an overwrite order inside ONE dict rather than
    # a rule about two sources. It happened to land on the enriched value;
    # a reader could not tell that from the code, and the enriched half is
    # now merged once, from the half that holds it.
    fields = {}
    for match in _KEYVAL_RE.finditer(readable):
        key, value = match.group(1), match.group(2)
        if key == "msg" or key == "type":
            continue
        if value.startswith('"') and value.endswith('"') and len(value) > 1:
            value = value[1:-1]
        fields[key] = value
    fields.update(enriched)

    record["fields"] = fields
    return record


def read_new(log_path: str, after_offset: int = 0,
             limit: int = MAX_LINES_PER_PASS,
             after_inode=None) -> dict:
    """
    Records after a byte offset, with the coverage that makes them readable.

    Returns:
        {"records": [...], "offset": n, "read": n, "more_available": bool,
         "truncated": bool, "reason": None | "..."}

    A BYTE OFFSET IS THE CURSOR and it is the right instrument for this log for
    a reason worth stating: auditd only ever APPENDS, and it only rotates under
    its own logrotate rules. Rotation makes the new file shorter than the
    stored offset, and that case is DETECTED here rather than producing a read
    from the wrong place -- see the rotation branch below. The kernel camera's
    reader had to learn the equivalent lesson about bpf_ktime across a reboot.

    ROTATION IS DETECTED TWO WAYS, AND THE SECOND ONE IS THE ONE THAT BITES.
    The first is the size test below: the file is shorter than where this app
    had read to. The second is the INODE, because logrotate moves audit.log to
    audit.log.1 and auditd starts a fresh file immediately -- and an audit log
    on a real host can grow past the stored offset BETWEEN TWO POLLS, after
    which the size test is false forever and every later pass reads the new
    file from the middle. MEASURED: 940 bytes of a rotated file were skipped
    with no note at all, and the tail of audit.log.1 was never read. The inode
    is carried across passes in the cursor (see CURSOR_DDL) and a change in it
    is a rotation regardless of size.
    """
    out = {"records": [], "offset": after_offset, "read": 0,
           "more_available": False, "truncated": False, "deferred": 0,
           "rotated": False, "inode": None, "leftover_bytes": 0,
           "reason": None}

    try:
        size = os.path.getsize(log_path)
        inode = os.stat(log_path).st_ino
        out["inode"] = inode
    except OSError as e:
        out["reason"] = f"the audit log could not be measured: {e}"
        return out

    start = after_offset
    rotated = rotated_to(after_offset, size, inode, after_inode)
    # AD11. The file the cursor points at was renamed, not lost: find it by
    # its inode among the rotated siblings and finish it before the new one.
    sibling = _rotated_sibling(log_path, after_inode) if rotated else None
    if sibling:
        try:
            sib_size = os.path.getsize(sibling)
        except OSError:
            sib_size = 0
        if after_offset < sib_size:
            out = read_new(sibling, after_offset, limit, after_inode)
            out["rotated"] = True
            out["reading_rotated"] = sibling
            out["more_available"] = True
            out["reason"] = (f"the audit log was rotated; finishing the rest "
                             f"of the old file, now {sibling}, from where this "
                             f"app had read to. The new file is read next.")
            return out
    if rotated:
        # ROTATION.
        #
        # The file is not the one this app was reading: either it is SHORTER
        # than where this app stopped reading, or it is a DIFFERENT FILE
        # (inode changed) that has already grown past that offset. Auditd
        # rotated and a fresh log is being written. The honest response is to
        # read from the beginning of the new file and SAY SO, not to seek past
        # its end and report zero records -- which would read as a quiet
        # machine for as long as the offset stayed ahead of the file,
        # silently, with the sensor reporting itself healthy.
        out["rotated"] = True
        start = 0
        if sibling:
            out["reason"] = (
                f"the audit log was rotated and the old file, now {sibling}, "
                f"had already been read to its end. Reading the new file from "
                f"the beginning; nothing was skipped.")
        elif after_offset and after_offset > size:
            out["reason"] = (
                f"the audit log is shorter ({size} bytes) than where this app "
                f"had read to ({after_offset} bytes), so it has been ROTATED. "
                f"Reading the new file from the beginning. The old file could "
                f"not be found among the rotated files (compressed, removed, "
                f"or no inode on the cursor), so records between the last "
                f"read and the rotation were NOT read.")
        else:
            out["reason"] = (
                f"the file at the audit log's path is NOT THE ONE THIS APP HAD "
                f"READ TO: it has a different inode ({inode} now, "
                f"{after_inode} when the cursor was written) and is already "
                f"{size} bytes long, past the {after_offset} bytes this app had "
                f"read. It has been ROTATED, auditd renames audit.log and "
                f"starts a fresh one, and this pass caught the new file after "
                f"it had grown past the old offset. Reading it from the "
                f"beginning. The old file could not be found among the "
                f"rotated files, so the rest of it was NOT read.")
        out["rotation_basis"] = ("size" if after_offset and after_offset > size
                                 else "inode")

    try:
        with open(log_path, "rb") as fh:
            fh.seek(start)
            raw = fh.read(MAX_READ_BYTES)
    except OSError as e:
        out["reason"] = f"the audit log could not be read: {e}"
        return out

    text = raw.decode("utf-8", errors="replace")

    # A PARTIAL FINAL LINE IS NORMAL ON A LIVE LOG, and it must not be
    # consumed: the offset stops at the last complete newline so the next pass
    # re-reads the fragment once auditd has finished writing it. Without this,
    # a torn line is parsed as a record with missing fields, or worse, a
    # truncated path is reported as a path.
    lines = text.split("\n")
    leftover = lines.pop() if lines else ""
    consumed = len(raw) - len(leftover.encode("utf-8", errors="replace"))

    # THE PER-PASS LINE LIMIT IS A LINE COUNT, NOT A BYTE COUNT.
    #
    # When MAX_LINES_PER_PASS binds first, the offset must stop where the
    # PARSED lines stop. It did not: it was set to `start + consumed`, the end
    # of the whole 8 MB read, and the next pass began from there -- so every
    # line past the limit was consumed without ever being parsed, by any pass,
    # and the report said "Nothing was skipped". MEASURED: a 12-record fixture
    # read with limit=5 returned 5 records and an offset of 1130, which is the
    # whole file; records 6..12 were never seen, and the next pass reported 0
    # records and no note. That is this file's own EM-1 class one layer up: a
    # quiet number produced by a reader that ate the evidence.
    #
    # The offset now stops at the last line that WAS parsed, and the rest is
    # left in the file for the next pass, counted here and named in the
    # coverage. The byte size of the deferred tail is what gets re-read, so
    # the cost of a busy log is bounded by the same constant as before.
    consumed = _bytes_of_lines(lines[:limit], consumed, raw)
    if len(lines) > limit:
        deferred = lines[limit:]
        out["deferred"] = len(deferred)
        out["deferred_bytes"] = len(
            "\n".join(deferred).encode("utf-8", errors="replace")) + 1
    end_offset = start + consumed

    out["truncated"] = len(lines) > limit
    for line in lines[:limit]:
        record = parse_record(line)
        if record:
            out["records"].append(record)

    out["read"] = len(lines[:limit])
    out["offset"] = end_offset
    out["leftover_bytes"] = len(leftover.encode("utf-8", errors="replace"))
    out["more_available"] = (len(lines) > limit
                             or len(raw) >= MAX_READ_BYTES)
    return out


def _bytes_of_lines(lines: list, consumed_all: int, raw: bytes) -> int:
    """
    The byte count of the lines that were actually parsed, plus their newline.

    Computed from the decoded lines rather than from a re-encode of the whole
    read, so a multi-byte character that straddles the limit cannot move the
    cursor into the middle of a record. A non-UTF-8 byte in the log decodes to
    U+FFFD and re-encodes as three bytes, which would put the cursor PAST the
    line it claims to have stopped at -- so the caller's ceiling is applied as
    a floor: the answer never exceeds the bytes actually consumed.
    """
    if not lines:
        return 0
    total = 0
    for line in lines:
        total += len(line.encode("utf-8", errors="replace")) + 1
    return min(total, consumed_all)


def _rotated_sibling(log_path: str, after_inode):
    """The rotated file (audit.log.1, .2, ...) still holding this inode, or None.

    Compressed siblings are skipped: their inode is a new file anyway.
    """
    if after_inode is None:
        return None
    folder, name = os.path.split(log_path)
    try:
        entries = os.listdir(folder or ".")
    except OSError:
        return None
    for entry in sorted(entries):
        if not entry.startswith(name + ".") or \
                entry.endswith((".gz", ".xz", ".bz2", ".zst")):
            continue
        path = os.path.join(folder, entry)
        try:
            if os.stat(path).st_ino == int(after_inode):
                return path
        except (OSError, ValueError):
            continue
    return None


def rotated_to(after_offset: int, size: int, inode, after_inode) -> bool:
    """
    Whether the file at the log path is a different file than the cursor means.

    TWO TESTS, and they are not redundant. The SIZE test catches a rotation
    that has not yet been outgrown; the INODE test catches the one that has.
    A cursor written before the inode was recorded (`after_inode` is None) can
    only be answered by size -- a missing inode must never be read as a
    rotation, or every pass would re-read the whole log from the start.
    """
    if after_offset and after_offset > size:
        return True
    if (after_inode is not None and inode is not None
            and int(after_inode) != int(inode)):
        return True
    return False


# THE CURSOR
#
# ITS OWN TABLE, NOT user_preferences, for the reason this tree has now
# written down three times: that table IS the policy, core/integrity digests it
# and journals a `config_observed` entry on ANY difference on the contract that
# such an entry always means the rules changed. A bookmark that moves every
# fifteen seconds would write a false "the policy has CHANGED" warning into the
# tamper journal forever, in the one record whose whole value is that it never
# cries wolf.
CURSOR_TABLE = "auditd_cursor"
CURSOR_NAME = "default"

CURSOR_DDL = f"""
CREATE TABLE IF NOT EXISTS {CURSOR_TABLE} (
    name            TEXT PRIMARY KEY,
    last_offset     INTEGER NOT NULL DEFAULT 0,
    last_inode      INTEGER,
    last_record_at  TIMESTAMP,
    seeded_at       TIMESTAMP,
    passes          INTEGER NOT NULL DEFAULT 0,
    records_seen    INTEGER NOT NULL DEFAULT 0
)
"""

# v48, 2026-09-23. THE CURSOR GAINS THE FILE'S IDENTITY.
#
# A byte offset alone cannot tell "the same file, grown" from "a different file
# that is already past that byte" -- and auditd rotates by RENAMING audit.log
# to audit.log.1 and starting a new one, so the second case is the ordinary
# case. MEASURED before this column existed: a rotated log that had grown past
# the stored offset produced 20 records, rotated=False, and no note, with the
# first 940 bytes of the new file skipped and everything in audit.log.1 never
# read. An existing install has no inode in its cursor row, so the column is
# added by a migration and read as None (size test only) until the next write.
CURSOR_ADD_COLUMN_DDL = f"ALTER TABLE {CURSOR_TABLE} ADD COLUMN last_inode INTEGER"


def ensure_cursor_table(db_path: str = None) -> bool:
    """Create the cursor table if it is not there. Returns whether it is now."""
    import sqlite3
    from core import memory_engine as me

    path = db_path or str(me.DB_PATH)
    try:
        conn = sqlite3.connect(path, timeout=10)
        try:
            conn.executescript(CURSOR_DDL)
            # A TABLE CREATED BEFORE v48 HAS NO last_inode. CREATE TABLE IF NOT
            # EXISTS does not add it, so the migration below is mirrored here:
            # a database whose version is already current but whose table came
            # from an older shape would otherwise raise on every pass.
            if "last_inode" not in {row[1] for row in
                                    conn.execute(f"PRAGMA table_info({CURSOR_TABLE})")}:
                conn.execute(CURSOR_ADD_COLUMN_DDL)
            conn.commit()
        finally:
            conn.close()
        return True
    except sqlite3.Error as e:
        logger.warning(f"auditd_monitor: could not create the cursor table in "
                       f"{path}: {type(e).__name__}: {e}")
        return False


def read_cursor(db_path: str = None) -> dict:
    """
    What has been read so far. `seeded: False` means never.

    A TABLE FROM BEFORE v48 HAS NO last_inode COLUMN, and this reader is also
    used by scripts that run against a database no migration has touched. So
    the SELECT is built from the columns the table ACTUALLY has rather than
    from the shape this version writes, and a table missing the column answers
    last_inode None instead of raising. The alternative -- a bare SELECT
    against a fixed column list -- raised sqlite3.Error, which the caller
    below turns into the blank cursor, and a blank cursor means NOT SEEDED: the
    next pass would then SEED, setting the cursor to the end of the log and
    raising nothing for every record written since. Silent loss dressed as a
    fresh start, which is the class of defect this whole file is written
    against.
    """
    import sqlite3
    from core import memory_engine as me

    path = db_path or str(me.DB_PATH)
    blank = {"name": CURSOR_NAME, "last_offset": 0, "last_inode": None,
             "last_record_at": None, "seeded_at": None, "passes": 0,
             "records_seen": 0, "seeded": False, "error": None}
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error as e:
        blank["error"] = f"cursor unreadable: {type(e).__name__}: {e}"
        return blank
    try:
        columns = {row[1] for row in
                   conn.execute(f"PRAGMA table_info({CURSOR_TABLE})")}
        inode_col = ("last_inode" if "last_inode" in columns else "NULL AS last_inode")
        row = conn.execute(
            f"SELECT last_offset, {inode_col}, last_record_at, seeded_at, "
            f"passes, records_seen FROM {CURSOR_TABLE} WHERE name = ?",
            (CURSOR_NAME,)).fetchone()
    except sqlite3.Error:
        return blank
    finally:
        try:
            conn.close()
        except sqlite3.Error:
            pass
    if not row:
        return blank
    return {"name": CURSOR_NAME, "last_offset": row[0], "last_inode": row[1],
            "last_record_at": row[2], "seeded_at": row[3], "passes": row[4],
            "records_seen": row[5], "seeded": True, "error": None}


def write_cursor(last_offset: int, last_record_at=None, seeded: bool = False,
                 records_seen: int = 0, db_path: str = None,
                 last_inode=None) -> bool:
    """
    Move the cursor. Returns whether it moved.

    A FAILED WRITE IS REPORTED, never swallowed: the next pass re-reads the
    same window and the same findings come back, and a reader who sees a
    monitor repeat itself stops trusting what it says.
    """
    import sqlite3
    from core import memory_engine as me

    path = db_path or str(me.DB_PATH)
    try:
        conn = sqlite3.connect(path, timeout=10)
        try:
            conn.executescript(CURSOR_DDL)
            if "last_inode" not in {row[1] for row in
                                    conn.execute(f"PRAGMA table_info({CURSOR_TABLE})")}:
                conn.execute(CURSOR_ADD_COLUMN_DDL)
            conn.execute(
                f"""
                INSERT INTO {CURSOR_TABLE}
                    (name, last_offset, last_inode, last_record_at, seeded_at,
                     passes, records_seen)
                VALUES (?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(name) DO UPDATE SET
                    last_offset    = excluded.last_offset,
                    last_inode     = excluded.last_inode,
                    last_record_at = excluded.last_record_at,
                    seeded_at      = COALESCE({CURSOR_TABLE}.seeded_at,
                                              excluded.seeded_at),
                    passes         = {CURSOR_TABLE}.passes + 1,
                    records_seen   = {CURSOR_TABLE}.records_seen
                                     + excluded.records_seen
                """,
                (CURSOR_NAME, int(last_offset),
                 int(last_inode) if last_inode is not None else None,
                 last_record_at, _now() if seeded else None,
                 int(records_seen)))
            conn.commit()
        finally:
            conn.close()
        return True
    except sqlite3.Error as e:
        logger.error(f"auditd_monitor: THE CURSOR DID NOT MOVE "
                     f"({type(e).__name__}: {e}). The next pass will re-read "
                     f"this same window, so expect the same findings twice.")
        return False


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# THE CLASSIFIERS

def is_config_change(record: dict) -> bool:
    """
    A CONFIG_CHANGE record, which means the audit rules were edited.

    THE `op` FIELD SAYS WHAT KIND, and it is passed through rather than
    interpreted: "add_rule", "remove_rule", "updated_rules" and the reset
    operations are all audit's own names for what happened, and a paraphrase
    here would be this app's guess about somebody else's vocabulary.

    TYPE OR FIELD, and that is the only reading of this predicate that is true
    for every caller. The shipped shape tests the type -- CONFIG_CHANGE is the
    type audit writes for a rule change, so that is right almost always -- but
    the docstring above says "a CONFIG_CHANGE record", and a record written
    with the op in a different record type would have been answered wrongly by
    a function whose whole job is to answer that question. It had zero callers
    when this was measured, which is exactly why it was worth making correct
    before anybody leans on it.
    """
    if record.get("type") == "CONFIG_CHANGE":
        return True
    return "CONFIG_CHANGE" in str((record.get("fields") or {}).get("op") or "")


def watched_path(record: dict) -> str | None:
    """
    The path a PATH record names, if it names one.

    A PATH record with NO name is real and means a watched file was touched but
    the kernel entry is empty (it happens on a delete). It is not a path and it
    is not this rule's business.

    A WATCHED FILE CAN BE NAMED BY A RECORD THAT IS NOT A PATH, and the
    absolute-path requirement is what makes that safe to accept: auditd
    attaches name="..." to the sibling record of a rename or a link with
    nametype=DELETE or a parent-directory entry, and the kernel's own PATH set
    is where a path always lives. Refusing anything that is not type=PATH
    threw those away silently -- see the finding path in _findings_from, which
    accepts a name on any record type and counts what it raises.
    """
    name = (record.get("fields") or {}).get("name")
    if name is None:
        return None
    name = str(name)
    if "(" in name:
        # audit writes name="(null)" and the 3.x hex form name=2F657463... for
        # a path it could not decode. Neither is a path, and the hex form
        # starts with a hex digit rather than a slash, so the test below
        # already refuses it; the parenthesised form is refused here because
        # "(null)" is a string like any other until somebody checks.
        return None
    if not name.startswith("/"):
        return None
    return name


def process_identity(record: dict) -> dict:
    """
    Who did it, as far as the record says.

    EVERY FIELD IS OPTIONAL AND ABSENT MEANS UNKNOWN, never zero. A uid of 0
    is root and a MISSING uid is not root; collapsing them would put "root did
    this" on a finding raised from a record that never said so.
    """
    f = record.get("fields") or {}
    out = {}
    for key, label in (("pid", "pid"), ("ppid", "ppid"), ("uid", "uid"),
                       ("auid", "auid"), ("gid", "gid"), ("ses", "session"),
                       ("comm", "comm"), ("exe", "exe"), ("key", "rule_key")):
        if key in f:
            out[label] = f[key]
    return out


# ONE ANALYSIS PASS

def analyze(config: dict = None, db_path: str = None) -> dict:
    """
    Read the audit log since the cursor and say what is in it.

    RETURNS A REPORT, NOT A LIST OF FINDINGS, and the report always carries the
    coverage that makes the findings readable. Keys:

        findings    the rows the adapter writes
        coverage    what could and could not be read, in words
        analysed    counts of what was actually examined
        cursor      where this pass got to
        seeded      True when this was the first pass over this file
        notes       anything else that changes how the answer reads

    THIS FUNCTION DOES NOT WRITE FINDINGS. That is the adapter's job, for the
    same reason it is in the kernel camera's reader and the local integrity
    sensor: the module decides what is true, the adapter decides how this app
    records it, and keeping them apart is what makes the decision testable
    without a database.
    """
    report = {"findings": [], "coverage": {}, "analysed": {}, "capped": [],
              "notes": [], "seeded": False, "error": None,
              "by_type": {}, "unhandled": {},
              "cursor": read_cursor(db_path)}

    state = status(config)
    report["auditd"] = state
    report["coverage"]["auditd"] = state.get("note") or state.get("blind_reason")

    # THE ABSENCE.
    #
    # Everything below this point assumes a readable log, and on a host where
    # the subsystem is not installed there is not one. The report says why, in
    # the coverage block, and returns the same empty findings list an
    # uneventful pass would -- which is exactly why the coverage block has to
    # carry the sentence. See this module's header for why this is the state
    # the owner's machine is actually in.
    #
    # THE DECISION IS status()'s, NOT THIS FUNCTION'S. `state` is a value in
    # the dict above rather than a cascade repeated here, because the boot log,
    # the adapter's headline and the model-facing tool all need the same
    # answer and three copies of the same if-chain is how three surfaces end up
    # describing one machine differently.
    report["coverage"]["auditd_state"] = state.get("state")
    if state.get("state") != "READABLE":
        return report
    log_path = state["log_path"]

    cursor = report["cursor"]
    if cursor.get("error"):
        report["notes"].append(
            f"THE CURSOR COULD NOT BE READ ({cursor['error']}), so this pass "
            f"does not know what has already been looked at.")

    if not cursor["seeded"]:
        # THE SEED PASS.
        #
        # Same rule as the kernel camera and the local integrity sensor: a log
        # that already holds somebody else's history is not a change, and a
        # monitor that shouts on its first useful look is one its reader
        # skims. The cursor is set to the END of the file and nothing is
        # raised for what is already in it.
        try:
            size = os.path.getsize(log_path)
            inode = os.stat(log_path).st_ino
        except OSError as e:
            report["error"] = f"the audit log could not be measured: {e}"
            return report

        newest = _newest_record_age(log_path)
        moved = write_cursor(size, last_record_at=_now() if newest else None,
                             seeded=True, db_path=db_path, last_inode=inode)
        report["seeded"] = True
        report["analysed"] = {"records": 0, "seeded": True}
        report["coverage"]["first_pass"] = (
            f"THIS IS THE FIRST PASS over {log_path}, which already holds "
            f"{size} byte(s) of records going back to before this app ever "
            f"read it. The cursor was set to the end of the file and NOTHING "
            f"was raised for any of it. Analysis starts from the next record.")
        if not moved:
            report["notes"].append(
                "THE CURSOR COULD NOT BE SAVED, so this seeding will happen "
                "again next pass and nothing will ever be analysed.")
        return report

    read = read_new(log_path, after_offset=int(cursor["last_offset"] or 0),
                    after_inode=cursor.get("last_inode"))
    if read.get("reason") and not read["records"]:
        report["error"] = read["reason"]
        report["coverage"]["read"] = read["reason"]
        # A ROTATION WITH NOTHING READ IS STILL COVERAGE, not an error: the
        # next pass reads the new file from the start.
        if read.get("rotated"):
            report["notes"].append(read["reason"])
            return report
        return report

    if read.get("rotated"):
        report["notes"].append(read["reason"])
        report["coverage"]["rotated"] = read["reason"]
    if read.get("more_available"):
        # AND THE SENTENCE THAT USED TO BE FALSE.
        #
        # This said "Nothing was skipped -- the cursor moved to the last line
        # examined". The cursor moved to the end of the whole READ, which is
        # every deferred line as well, so the lines past the limit were
        # consumed unparsed and this sentence told the reader they had not
        # been. MEASURED: 7 of a 12-line fixture were eaten by one pass and
        # the next pass reported a quiet file. The count is now real and the
        # deferred lines are named in `analysed`, so the number under the
        # sentence can be checked against the cursor's movement.
        deferred = int(read.get("deferred") or 0)
        report["coverage"]["scan_limit"] = (
            f"{read['read']} LINE(S) OF NEW RECORDS WERE LOOKED AT THIS PASS, "
            f"which is the per-pass limit. "
            + (f"{deferred} further line(s) were NOT read this pass, they "
               f"have been LEFT IN THE FILE and the cursor stopped before "
               f"them, so the next pass reads them from the start. Nothing is "
               f"lost; this answer simply does not cover them yet."
               if deferred else
               f"The rest of the file was left for the next pass by the byte "
               f"cap on one read; the cursor stopped at the last complete "
               f"line, so nothing is lost and this answer does not cover it "
               f"yet."))
        report["notes"].append(report["coverage"]["scan_limit"])

    # Count every record by type BEFORE deciding what to raise, so that
    # "nothing found" can be read against what was actually there. A module
    # that silently drops 90% of its input is indistinguishable from a quiet
    # machine otherwise.
    by_type = {}
    for record in read["records"]:
        by_type[record["type"]] = by_type.get(record["type"], 0) + 1
    report["by_type"] = dict(sorted(by_type.items(),
                                    key=lambda kv: -kv[1]))

    findings, counted = _findings_from(read["records"])
    report["findings"] = findings
    report["analysed"] = {
        "records": len(read["records"]),
        "lines": read["read"],
        "deferred_lines": int(read.get("deferred") or 0),
        "from_offset": cursor["last_offset"],
        "raised": len(findings),
    }
    report["counted"] = counted

    # AND THE ONE FACT THAT CHANGES HOW EVERY FOLLOWING PASS READS.
    #
    # `auditctl -e 0` sets the kernel's audit_enabled to 0 and the kernel then
    # records NOTHING until somebody turns it back on. A KERNEL record carries
    # that flag, and a pass that read one must publish it: from that moment,
    # "no records since" is a statement about the switch rather than about the
    # machine, and a reader who does not know the switch is off will read every
    # later quiet answer as a quiet host. Same shape as the disabled-auditd
    # case, one layer lower, and it is carried on `state` as `kernel_enabled`.
    kernel_enabled = _kernel_enabled_from(read["records"])
    if kernel_enabled is not None:
        report["kernel_enabled"] = kernel_enabled
        report["coverage"]["kernel_enabled"] = _kernel_enabled_text(
            kernel_enabled)
        if kernel_enabled == 0:
            report["notes"].append(report["coverage"]["kernel_enabled"])

    newest_at = None
    for record in reversed(read["records"]):
        if record.get("at_iso"):
            newest_at = record["at_iso"]
            break

    if not write_cursor(read["offset"], last_record_at=newest_at,
                        records_seen=len(read["records"]), db_path=db_path,
                        last_inode=read.get("inode")):
        report["notes"].append(
            "THE CURSOR DID NOT MOVE, so the next pass will re-read this same "
            "window and produce the same findings again.")

    report["cursor"] = dict(cursor)
    report["cursor"]["moved_to"] = read["offset"]
    return report


def _kernel_enabled_from(records: list):
    """
    The kernel's own enabled flag from the newest KERNEL record, or None.

    THE NEWEST ONE WINS, and the flag is 0, 1 or 2: 0 means the kernel is
    recording NOTHING, 1 means recording normally, 2 means the configuration is
    IMMUTABLE (nothing may change it until the machine reboots). All three are
    published because they are three different sentences.
    """
    value = None
    for record in records:
        if record.get("type") != _KERNEL_STATE_TYPE:
            continue
        f = record.get("fields") or {}
        for key in ("audit_enabled", "enabled"):
            if key in f:
                try:
                    value = int(str(f[key]).strip())
                except (TypeError, ValueError):
                    continue
                break
    return value


def _kernel_enabled_text(enabled: int) -> str:
    """What a reader needs to know about the kernel's own switch."""
    if enabled == 0:
        return (
            "THE KERNEL'S AUDIT SWITCH IS OFF ON THIS MACHINE (the newest "
            "KERNEL record in the log says audit_enabled=0). Somebody ran "
            "`auditctl -e 0`, or the setting was disabled at boot, and the "
            "kernel is now recording NOTHING at all: no syscalls, no file "
            "watches, no rule changes. Every quiet answer from this feed "
            "until somebody turns it back on is a statement about the switch "
            "rather than about this machine. The command that turns it back "
            "on is: sudo auditctl -e 1")
    if enabled == 2:
        return (
            "THE KERNEL'S AUDIT CONFIGURATION IS IMMUTABLE (the newest KERNEL "
            "record says audit_enabled=2). Nothing, not root, not this app "
            "-- can change the audit rules until this machine reboots. That is "
            "a deliberate hardening state, and it also means the rules in "
            "force now are the rules this app will be reading under.")
    return (f"the kernel's audit switch is ON (audit_enabled={enabled}): the "
            f"kernel is recording according to the rules in force.")


def _findings_from(records: list):
    """
    The four rules, capped and counted.

    ONE PASS OVER THE RECORDS FOR ALL OF THEM, and one id per claim:

      AUD-1001  the audit configuration changed. Availability and integrity:
                the monitoring this app reads was RECONFIGURED, and on a host
                where the rules are what make the log worth reading, a rule
                removed is a watch removed. Nothing else in this tree can see
                this at all.
      AUD-1002  a path under an audit WATCH was touched, with the identity
                auditd recorded. The local integrity sensor can only stat
                root-only files unelevated; this is the same class of fact at
                content level, with the process attached.
      AUD-1003  THE KERNEL'S AUDIT SWITCH IS OFF (a KERNEL record saying
                audit_enabled=0), or the kernel has DROPPED records
                (audit_lost > 0). Nothing is being recorded from that moment
                on, so every later quiet answer is about the switch rather
                than about the machine -- the one reading this app must never
                allow. AUD-1001 is a rule being edited; this is the recording
                being turned OFF, and they have different remedies.
      AUD-1004  AUDITD STOPPED: a DAEMON_END record, by shutdown or by signal.
                Userspace is gone, so nothing is being written to the log
                however healthy the kernel looks.

    Records of the same event arrive several at a time, so two dedups run and
    they are different claims:

      (msg_id, path)   the SAME path inside the SAME event. auditd writes one
                       record per nametype, and audit 3.x can emit the same
                       path twice in one syscall. Raising twice would put the
                       same sentence on the board twice for one event.
      NOT the path     a syscall that touched four DIFFERENT watched files
                       touched four different files. Each is its own fact with
                       its own entity value, and collapsing them into one
                       finding would throw three of the paths away -- which is
                       a silent loss of evidence, not a reduction in noise.
                       The count of what each syscall touched is `items` on the
                       SYSCALL record, which is counted rather than raised.

    A NAMED PATH IS ACCEPTED ON ANY RECORD TYPE, which is a correction: the
    first version raised only on type=PATH, and auditd writes the path of a
    rename's removed half on the SIBLING record with nametype=DELETE. The
    absolute-path requirement in watched_path() is what keeps this narrow --
    a record with no `name`, or a name that is not a path, still raises
    nothing and is counted instead.
    """
    out, counts = [], {}
    seen_paths = set()

    for record in records:
        rtype = record.get("type")

        if rtype == "CONFIG_CHANGE":
            op = (record.get("fields") or {}).get("op") or "changed"
            # THE AGGREGATE ROW IS THE FINDING. A rule reload writes one
            # CONFIG_CHANGE, and a `auditctl -R` writes many; capping here
            # keeps a reload from burying the dashboard.
            counts["config"] = counts.get("config", 0) + 1
            if counts["config"] > CAP_PER_ID_PER_PASS:
                continue
            who = process_identity(record)
            out.append({
                "detection_id": "AUD-1001",
                "entity_type": "file",
                "entity_value": DEFAULT_AUDITD_CONF,
                "severity": "medium",
                "title": f"The audit configuration was changed ({op})",
                "description": _config_change_text(record, op, who),
                "raw_data": {"record_type": rtype, "op": op,
                             "msg_id": record.get("msg_id"),
                             "at": record.get("at_iso"),
                             "identity": who,
                             "fields": _safe_fields(record)},
            })
            continue

        if rtype == _KERNEL_STATE_TYPE:
            # THE SWITCH, AND THE LOST RECORDS.
            #
            # ONE FINDING PER PASS, not one per KERNEL record: the kernel
            # re-asserts its configuration on every rule change, and ten
            # copies of "the switch is off" is nine rows a reader has to
            # scroll past to reach the tenth. What is counted instead is how
            # many KERNEL records said it.
            f = record.get("fields") or {}
            enabled = _kernel_enabled_from([record])
            lost = _kernel_lost(f)
            counts["kernel"] = counts.get("kernel", 0) + 1
            if enabled == 0:
                counts["kernel_disabled"] = counts.get("kernel_disabled", 0) + 1
            if lost:
                counts["kernel_lost"] = counts.get("kernel_lost", 0) + lost
            if (enabled == 0 or lost) and not counts.get("kernel_raised"):
                counts["kernel_raised"] = 1
                who = process_identity(record)
                out.append({
                    "detection_id": "AUD-1003",
                    "entity_type": "file",
                    "entity_value": DEFAULT_AUDITD_CONF,
                    "severity": "high",
                    "title": ("The kernel's audit switch is OFF"
                              if enabled == 0 else
                              f"The kernel DROPPED {lost} audit record(s)"),
                    "description": _kernel_state_text(record, enabled, lost,
                                                      who),
                    "raw_data": {"record_type": rtype,
                                 "audit_enabled": enabled,
                                 "audit_lost": lost,
                                 "msg_id": record.get("msg_id"),
                                 "at": record.get("at_iso"),
                                 "identity": who,
                                 "fields": _safe_fields(record)},
                })
            continue

        if rtype == _DAEMON_END_TYPE:
            counts["daemon_end"] = counts.get("daemon_end", 0) + 1
            if counts.get("daemon_end_raised"):
                continue
            counts["daemon_end_raised"] = 1
            who = process_identity(record)
            out.append({
                "detection_id": "AUD-1004",
                "entity_type": "file",
                "entity_value": DEFAULT_AUDITD_CONF,
                "severity": "medium",
                "title": "The audit daemon STOPPED (auditd wrote DAEMON_END)",
                "description": _daemon_end_text(record, who),
                "raw_data": {"record_type": rtype,
                             "msg_id": record.get("msg_id"),
                             "at": record.get("at_iso"),
                             "identity": who,
                             "fields": _safe_fields(record)},
            })
            continue

        path = watched_path(record)
        if not path:
            if rtype == "PATH":
                counts["path_no_name"] = counts.get("path_no_name", 0) + 1
            else:
                counts[f"unhandled:{rtype}"] = counts.get(
                    f"unhandled:{rtype}", 0) + 1
            continue
        key = (record.get("msg_id"), path)
        if key in seen_paths:
            counts["path_repeat"] = counts.get("path_repeat", 0) + 1
            continue
        seen_paths.add(key)
        counts["path"] = counts.get("path", 0) + 1
        if counts["path"] > CAP_PER_ID_PER_PASS:
            counts["path_cut"] = counts.get("path_cut", 0) + 1
            continue
        who = process_identity(record)
        out.append({
            "detection_id": "AUD-1002",
            "entity_type": "file",
            "entity_value": path,
            "severity": "low",
            "title": f"Audit watch touched: {path}",
            "description": _watch_text(record, path, who),
            "raw_data": {"record_type": rtype,
                         "msg_id": record.get("msg_id"),
                         "at": record.get("at_iso"),
                         "identity": who,
                         "fields": _safe_fields(record)},
        })

    if counts.get("path_cut"):
        out.append({
            "detection_id": "AUD-1002",
            "entity_type": "file",
            "entity_value": "capped:AUD-1002",
            "severity": "low",
            "title": (f"More than {CAP_PER_ID_PER_PASS} audit watch hits in "
                      f"this window"),
            "description": (
                f"{counts['path_cut']} further watched-path record(s) were NOT "
                f"written as findings this pass, because a single pass is "
                f"capped at {CAP_PER_ID_PER_PASS} so that one busy watched "
                f"directory cannot bury the dashboard. THE RECORDS THEMSELVES "
                f"ARE NOT LOST: the audit log holds every one of them, and the "
                f"cursor moved past them all. This row will not repeat while "
                f"it is open."),
            "raw_data": {"capped": True,
                         "shown": CAP_PER_ID_PER_PASS,
                         "dropped": counts["path_cut"],
                         "detection_id": "AUD-1002"},
        })

    return out, counts


def _kernel_lost(fields: dict) -> int:
    """How many records the kernel says it DROPPED, or 0."""
    for key in _KERNEL_MISSED_FIELDS:
        if key in fields:
            try:
                return max(0, int(str(fields[key]).strip()))
            except (TypeError, ValueError):
                return 0
    return 0


def _kernel_state_text(record: dict, enabled, lost: int, who: dict) -> str:
    parts = [f"KERNEL record: audit_enabled={enabled}, "
             f"audit_lost={lost}.",
             f"Identity recorded on the record: {who or 'NOT RECORDED'}"]
    if enabled == 0:
        parts.append(
            "\nWHAT THIS MEANS. Somebody turned the kernel's audit switch OFF "
            "(`auditctl -e 0`, or a boot-time setting). The kernel is now "
            "recording NOTHING: no syscall records, no file watches, no rule "
            "changes reach the log at all. THE EVIDENCE OF EVERYTHING THAT "
            "HAPPENS FROM NOW ON IS SIMPLY NOT WRITTEN, which is why this is "
            "raised at high rather than as a configuration note. Until "
            "somebody turns it back on, an empty findings list from this feed "
            "is a statement about the switch and NOT about this machine.\n\n"
            "THE COMMAND: sudo auditctl -e 1\n\n"
            "Ordinary causes: an operator hardening a machine for a "
            "maintenance window and forgetting to re-enable it, a "
            "configuration management tool with the wrong template, or "
            "somebody with root turning the recorder off before doing "
            "something they did not want recorded.")
    if lost:
        parts.append(
            f"\nWHAT THIS MEANS. The kernel's audit backlog overflowed and it "
            f"DROPPED {lost} record(s) before userspace could read them: the "
            f"rate of events exceeded what auditd could write, or the "
            f"backlog limit is set too low for this machine. The records are "
            f"gone, they were never written, so a quiet stretch in the "
            f"log that covers the drop is NOT a quiet machine.\n\n"
            f"WHAT TO LOOK AT: audit_backlog_limit and audit_rate_limit in the "
            f"log around this record, and the `-b` setting auditd is running "
            f"with (`sudo auditctl -s`). The kernel's own counter for this is "
            f"what produced the number above.")
    return "\n".join(parts)


def _daemon_end_text(record: dict, who: dict) -> str:
    res = (record.get("fields") or {}).get("res")
    return (
        f"auditd wrote DAEMON_END: the daemon STOPPED"
        + (f" (res={res})" if res else "") + ".\n"
        f"Identity recorded on the record: {who or 'NOT RECORDED'}\n\n"
        f"WHAT THIS MEANS. The process that writes the kernel's audit records "
        f"to the log has exited. The kernel may still be collecting events "
        f"into its own buffers, but NOTHING is being written down, so from "
        f"this moment the log is silent for a reason that has nothing to do "
        f"with this machine being quiet.\n\n"
        f"Ordinary causes: a deliberate `sudo systemctl stop auditd`, a "
        f"package upgrade restarting it, or a crash, DAEMON_ERR records "
        f"nearby say which. A DAEMON_START record after this one means it "
        f"came back; if there is no DAEMON_START, nothing has been recorded "
        f"since.\n\n"
        f"THE COMMAND: sudo systemctl status auditd, then "
        f"sudo systemctl restart auditd")


def _safe_fields(record: dict) -> dict:
    """
    The record's fields, with the long ones cut.

    AN AUDIT RECORD CAN CARRY A PROCTITLE FIELD OF SEVERAL KILOBYTES, and every
    field written here lands in a findings row and from there in a model's
    context. The cap is what keeps one exec of a long command line from being
    the whole answer.
    """
    out = {}
    for key, value in (record.get("fields") or {}).items():
        text = str(value)
        out[key] = text if len(text) <= 300 else text[:300] + "...[cut]"
    return out


def _config_change_text(record: dict, op: str, who: dict) -> str:
    return (
        f"audit reported a configuration change: op={op}.\n"
        f"Identity recorded on the record: {who or 'NOT RECORDED'}\n\n"
        f"WHAT THIS MEANS AND WHY IT IS A FINDING AT ALL. The audit rules are "
        f"what decide which syscalls and which file watches get recorded. A "
        f"rule ADDED means somebody is watching more; a rule REMOVED means "
        f"less of what happens on this machine is written down at all, and the "
        f"absence of a record afterwards is the one loss nobody can detect by "
        f"reading the log, because the evidence of it is what was deleted.\n\n"
        f"Ordinary causes: an operator editing a rule set, a configuration "
        f"management tool, or a package installing its own rules under "
        f"/etc/audit/rules.d. Confirm the change is one the operator made: "
        f"`sudo auditctl -l` prints the rules that are in force, and the files "
        f"under /etc/audit/rules.d hold the ones that were loaded."
    )


def _watch_text(record: dict, path: str, who: dict) -> str:
    fields = record.get("fields") or {}
    rule_key = fields.get("key")
    return (
        f"Path: {path}\n"
        f"Identity recorded: {who or 'NOT RECORDED'}\n"
        + (f"Audit rule key: {rule_key}\n" if rule_key
           else "Audit rule key: not set on this watch\n")
        + "\n"
        + "WHAT THIS IS. An audit rule is watching this path, and something "
          "touched it. The record was written by the KERNEL, so unlike a "
          "polling check it does not depend on the process still being alive: "
          "even if it lasted milliseconds, it is here.\n\n"
          "WHY IT IS LOW. A watch that produced one record is exactly what a "
          "watch is FOR: an operator set it on a file they want to know "
          "about, and the first thing it tells them is that the file is being "
          "touched, which is often the answer they wanted and not a surprise. "
          "The record's identity fields are what make it worth reading.\n\n"
          "AND WHAT IT IS NOT. This tool has the path and the identity, and "
          "NOT the content of what changed. It does not read the file, and it "
          "does not compare it against anything: that is the local integrity "
          "sensor's job, which hashes what it ships and reports what moved."
    )


# THE RAW RECORD, FOR THE MODEL-FACING TOOL
#
# analyze() ABOVE ANSWERS "WHAT IS NEW SINCE THE CURSOR", and this answers
# "WHAT IS IN THE LOG". They are different questions and the app needs both:
# a findings list is a judgement and this is the evidence underneath it, which
# is what somebody asks for the first time they want to know why the app
# thinks what it thinks. Same pairing as ebpf_events.recent_events beside its
# own analyze().
#
# IT READS THE TAIL, NOT THE FILE, and the reason is the one _newest_record_age
# gives: an audit log on a busy host is hundreds of megabytes and this runs
# inside a chat turn. What it can therefore promise is "the newest records in
# the file", and the promise is bounded and stated rather than implied.

RECENT_TAIL_BYTES = 4 * 1024 * 1024
RECENT_MAX_LIMIT = 200


def recent_records(config: dict = None, record_type: str = None,
                   search: str = None, limit: int = 50,
                   db_path: str = None) -> dict:
    """
    The newest records in the audit log, as raw evidence.

    NEVER RAISES. The three states a reader most needs to tell apart -- the
    feed is not installed, the log exists and cannot be read by this account,
    and the log is readable -- are carried as `installed`, `readable` and
    `auditd_state` in words, with the one command that changes the first of
    them printed rather than described.

    WHAT IT DOES NOT DO: it does not consult the cursor and it does not raise
    findings. A record here is not a finding and an absence of records here is
    not the same as an absence of findings -- the cursor decides what has been
    ANALYSED, and a reader who wants that should read the findings table.
    """
    state = status(config)
    out = {
        "installed": bool(state.get("installed")),
        "installed_reason": state.get("installed_reason"),
        "auditd_state": state.get("state"),
        "enabled": state.get("enabled"),
        "log_path": state.get("log_path"),
        "log_path_source": state.get("log_path_source"),
        "log_path_warning": state.get("log_path_warning"),
        "log_readable": bool(state.get("log_readable")),
        "install_command": state.get("install_command"),
        "kernel_enabled": state.get("kernel_enabled"),
        "record_type": record_type or "any",
        "search": search,
        "limit": limit,
        "records": [],
        "counts_by_type": {},
        "records_matching": None,
        "note": None,
        "coverage": {},
        "coverage_limits": list(state.get("coverage_limits") or []),
    }

    # THE ABSENCE, BEFORE ANYTHING IS READ.
    #
    # This is the branch the owner's machine takes, so it is the branch that
    # has to be most carefully worded. It says the feed is absent and prints
    # the command. It does NOT return an empty record list and stop there,
    # which is the shape a reader takes as "nothing happened".
    #
    # AND IT IS status()'s DECISION, not a second copy of it: `auditd_state`
    # above is the module's one answer to what this machine is, and every
    # caller reads that value rather than rebuilding it.
    if state.get("state") != "READABLE":
        out["note"] = (state.get("note") or state.get("blind_reason")
                       or state.get("installed_reason"))
        return out

    log_path = state["log_path"]

    try:
        limit = max(1, min(int(limit or 50), RECENT_MAX_LIMIT))
    except (TypeError, ValueError):
        limit = 50
    out["limit"] = limit

    try:
        size = os.path.getsize(log_path)
        with open(log_path, "rb") as fh:
            tail = min(size, RECENT_TAIL_BYTES)
            fh.seek(size - tail)
            raw = fh.read(tail)
    except OSError as e:
        out["auditd_state"] = "UNREADABLE"
        out["note"] = (f"the audit log at {log_path} could not be read: {e}. "
                       f"NOTHING was examined, which is a different sentence "
                       f"from finding nothing.")
        return out

    text = raw.decode("utf-8", errors="replace")
    lines = text.split("\n")
    # THE FIRST LINE IS A FRAGMENT ONLY WHEN THE READ STARTED MID-FILE. A tail
    # read begins at a byte offset rather than a line boundary, so on a log
    # LARGER than the window the first line is the tail of a record and must be
    # dropped -- it would otherwise parse into a record with fields missing,
    # which is the wrong shape of wrong.
    #
    # WHEN THE WHOLE FILE WAS READ THERE IS NO FRAGMENT, and dropping one
    # anyway LOSES A REAL RECORD SILENTLY. That was this reader's first defect,
    # found by running it: a seven-line fixture returned six records and the
    # missing one was simply the oldest, with no error and no note. The
    # condition below is therefore the read's own extent, not a habit.
    if tail < size and len(lines) > 1:
        lines = lines[1:]
    # A partially written FINAL line is normal on a live log. Kept out of the
    # parse and NAMED, so the count is honest rather than short by one.
    partial = lines.pop() if lines and not text.endswith("\n") else ""

    out["coverage"]["tail_bytes_read"] = tail
    out["coverage"]["log_size_bytes"] = size
    if tail < size:
        out["coverage"]["window"] = (
            f"ONLY THE LAST {tail} BYTE(S) OF A {size}-BYTE LOG WERE READ, "
            f"because that is the read window. Older records are in the file "
            f"and are not in this answer. Nothing was skipped silently: this "
            f"is the newest end of the log.")

    parsed, by_type, matched = [], {}, 0
    for line in lines:
        record = parse_record(line)
        if not record:
            continue
        rtype = record["type"]
        by_type[rtype] = by_type.get(rtype, 0) + 1
        if record_type and rtype != str(record_type).upper():
            continue
        if search and not _record_matches(record, search):
            continue
        matched += 1
        parsed.append(record)

    out["counts_by_type"] = dict(sorted(by_type.items(),
                                        key=lambda kv: -kv[1]))
    total = len(parsed)
    kept = parsed[-limit:]
    kept.reverse()          # newest first, which is what a person asking asks
    out["records"] = [{
        "type": r["type"],
        "msg_id": r.get("msg_id"),
        "at": r.get("at_iso"),
        "identity": process_identity(r),
        "fields": _safe_fields(r),
    } for r in kept]

    out["records_in_window"] = matched
    out["records_matching"] = total
    if total > limit:
        out["note"] = (
            f"SHOWING THE {limit} NEWEST OF {total} MATCHING RECORD(S) IN THE "
            f"READ WINDOW. This is a cut, not the whole record: pass a smaller "
            f"limit, a record type, or a search term to narrow it.")
    else:
        out["note"] = (f"ALL {total} MATCHING RECORD(S) IN THE READ WINDOW, "
                       f"OF {sum(by_type.values())} RECORD(S) PARSED.")
    # AN EMPTY LIST UNDER A SWITCHED-OFF KERNEL IS NOT A QUIET MACHINE.
    #
    # The state string stays READABLE -- the FILE is readable, which is what
    # that word is about -- and the sentence that changes the meaning of an
    # empty record list rides on top of it. Without this a reader is handed
    # "ALL 0 MATCHING RECORD(S)" over a kernel that has been told to record
    # nothing, which is the reading this whole module exists to prevent.
    if out.get("kernel_enabled") == 0:
        out["note"] = (
            "THE KERNEL'S AUDIT SWITCH IS OFF (audit_enabled=0 in the newest "
            "KERNEL record), so the kernel is recording NOTHING: an empty or "
            "short list here is a statement about the switch and NOT about "
            "this machine. " + (out["note"] or ""))
        if _kernel_enabled_text(0) not in out["coverage_limits"]:
            out["coverage_limits"].append(_kernel_enabled_text(0))
    if partial:
        out["coverage"]["partial_final_line"] = (
            "the last line of the log was mid-write and was NOT parsed, so it "
            "is not counted anywhere above. It will be complete on the next "
            "read.")
    return out


def _record_matches(record: dict, needle: str) -> bool:
    """
    Whether a record mentions a string, across the fields a person searches.

    THE SEARCH IS CASE-INSENSITIVE AND IT IS A CONTAINS MATCH, stated here
    because the alternative -- a "helpful" guess at what the reader meant --
    is how a search returns something that is not there. The raw line is
    searched last and it is searched at all on purpose: a field this parser
    does not lift (an a0 argument, a syscall number) is still in the record,
    and searching only the parsed fields would report "nothing matched" for a
    string that is visibly on the line.
    """
    if not needle:
        return True
    low = str(needle).lower()
    if low in (record.get("type") or "").lower():
        return True
    for key, value in (record.get("fields") or {}).items():
        if low in str(key).lower() or low in str(value).lower():
            return True
    return low in (record.get("raw") or "").lower()
