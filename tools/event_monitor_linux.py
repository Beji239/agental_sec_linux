# tools/event_monitor_linux.py
# AgentalSec Linux - System log monitoring (journald, syslog, auth.log)
#
# Linux equivalent of Windows event_monitor.py
# Monitors:
# - journald (systemd journal)
# - /var/log/syslog or /var/log/messages
# - /var/log/auth.log or /var/log/secure
# - Kernel log
#
# Writes to events and findings tables, THROUGH THE ADAPTER. This module never
# opens the database: it reads logs and returns what it read, and
# adapters.LinuxEventMonitor is the only writer. That separation is older than
# this comment and it is kept (see the FOUND CLEAN list in bugfinder.md, the
# event monitor round: "no SQL in the module").
#
# THE FIX ROUND, 2026-09-23. WHAT CHANGED AND WHY, IN ONE PLACE.
#
# The audit (bugfinder.md, "THE EVENT MONITOR ON LINUX, CAPABILITY ROUND",
# EM-1 to EM-13) measured two things this file could not say for itself:
#
#   1. 97.4% of the owner's events table was re-stored copies of log lines
#      that had not changed. The reader took a fixed 200-entry window off the
#      END of every file every poll, so a line that stayed inside the window
#      was read again and written again, 971 times for one immutable kern.log
#      line. The idempotent write in memory_engine.save_event exists for
#      exactly this, and could never engage, because this side passed no
#      source_record_id.
#
#   2. A line was only ever seen if it happened to sit in that window when a
#      poll ran. auth.log produced exactly 200 distinct lines per minute for
#      twelve consecutive minutes, 200 being the window size: there is no
#      margin in a window, and anything that overflowed it was never read by
#      any later poll, because there was nothing to catch up FROM. The
#      Windows twin persists a per-channel high-water mark, drains forward
#      from it, reports a gap when records are lost, and writes an
#      `event_log_gap` row. NONE of that survived the port.
#
# SO THIS FILE NOW HOLDS A CURSOR, and the shape is the Windows twin's:
#
#   * PER SOURCE, a persisted position. journald's is the journal's own
#     __CURSOR plus its sequence number; a file's is (device, inode, byte
#     offset), which is why the module returns them and the adapter stores
#     them. The module still owns no database handle.
#   * A FORWARD DRAIN from that position, capped per poll. Records that do
#     not fit stay IN THE LOG and are read next poll, which is the difference
#     that matters: the old window could only ever re-read or lose them.
#   * A FIRST RUN still adopts the NEWEST window rather than ingesting
#     history, and it says so rather than pretending the window was complete.
#   * A GAP IS REPORTED, never rounded up. If the journal refuses our cursor
#     (rotated or vacuumed), or a file was rotated or truncated before its
#     unread tail was read, the module returns a gap record naming what was
#     lost and why, and the adapter writes it as an `event_log_gap` event.
#     The Windows comment for that is the rule and it carries over word for
#     word: silently jumping to the newest record is the S22 failure, and a
#     coverage hole the model cannot see is a coverage hole it will reason
#     straight past.
#
# THE CURSOR ALSO MAKES THE FINDING PATH HONEST (EM-2, EM-3). With no cursor
# the same line was re-raised as a finding on every poll, so the only way to
# keep the volume sane was to count and drop most of it (eight of the eleven
# categories were counted and dropped). With the cursor a line is seen ONCE,
# so a finding is raised once, and the accounting below reports what was read
# and what was actually stored on every poll.

import logging
import re
import socket
import struct
import subprocess
import time
import hashlib
import ipaddress
import json
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# The module's OWN interval, used by _stalled_channels to decide "this source
# has gone quiet" and by the standalone monitor_once() when no config has been
# handed in. When the adapter has a config it wins: see configure(). There is
# one number here, not two, because the audit (EM-12) found the dead second
# definition of it sitting in this file for nothing.
POLL_INTERVAL = 60
FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW = 300  # 5 minutes

# HOW MUCH OF ONE SOURCE ONE POLL WILL READ WHEN IT IS ASKED DIRECTLY. Since
# the per-poll budget above is divided across the sources, this is only the
# DEFAULT for a standalone call to _read_log_file_lines or _read_journald_lines
# with no explicit cap: a cursor means a cap is no longer a loss, because
# whatever does not fit stays in the log and is read by the next poll, in
# order, from the position we stopped at. Measured on this host, auth.log
# reached 200 distinct lines per minute and the four sources together about
# 800, so this is about six minutes of a busy log for a single source.
READ_DEFAULT_LINES = 5000

# A first run adopts the newest window and marks the position. It does not
# ingest history: reading a four-day auth.log on first boot is not wanted, and
# there is no earlier position to resume from. The Windows twin does the same
# thing with single_page=True and calls it "taking the newest page".
FIRST_RUN_LINES = 200

# Watched event patterns
WATCHED_PATTERNS = {
    # Authentication events
    "failed_login": {
        "patterns": [
            r"Failed password for",
            r"authentication failure",
            r"FAILED LOGIN",
            r"pam_unix.*authentication failure",
            r"Invalid user",
            # Every sshd method, not only passwords (EM3-5).
            r"Failed (?:publickey|keyboard-interactive(?:/pam)?|none|hostbased|gssapi-with-mic) for",
            r"FAILED SU",
        ],
        "severity": "medium",
        "sources": ["auth.log", "secure", "journald"],
        "auth": True,
    },
    "successful_login": {
        "patterns": [
            r"Accepted \S+ for",
            r"session opened for user",
            r"Successful login",
        ],
        "severity": "info",
        "sources": ["auth.log", "secure", "journald"],
        "auth": True,
    },
    "sudo_usage": {
        "patterns": [
            r"sudo:.*COMMAND=",
            r"sudo:.*user NOT in sudoers",
            r"sudo:.*authentication failure",
        ],
        "severity": "info",
        "sources": ["auth.log", "secure", "journald"],
        # THE PATTERNS NAME THE SERVICE, so the haystack has to carry it. The
        # parser takes "sudo" out of the message and returns it as `service`
        # (which is EM-4 working as designed); before this key existed, all
        # three patterns above were unreachable. MEASURED: 66 live lines match
        # the whole line and 0 matched the message. See _categorize_entry.
        "haystack": "line_prefix",
    },
    "account_created": {
        "patterns": [
            r"useradd\[.*\]: new user:",
            r"adduser.*created",
            r"new user: name=",
        ],
        "severity": "high",
        "sources": ["auth.log", "secure", "journald"],
    },
    "account_deleted": {
        "patterns": [
            r"userdel\[.*\]: delete user:",
            r"deluser.*removed",
        ],
        "severity": "high",
        "sources": ["auth.log", "secure", "journald"],
    },
    "service_started": {
        "patterns": [
            r"Started .*\.service",
            r"Starting .*\.service",
            r"systemd.*Started",
        ],
        "severity": "info",
        "sources": ["journald", "syslog", "messages"],
    },
    "service_failed": {
        "patterns": [
            r"Failed to start .*\.service",
            r"\.service: Failed with result",
            r"systemd.*failed",
        ],
        "severity": "medium",
        "sources": ["journald", "syslog", "messages"],
    },
    "kernel_issue": {
        "patterns": [
            r"kernel:.*error",
            r"kernel:.*segfault",
            r"kernel:.*OOM",
            r"Out of memory",
        ],
        "severity": "medium",
        "sources": ["kern.log", "syslog", "messages", "journald"],
        # "kernel:" is the SERVICE the parser strips, so the three prefixed
        # patterns were unreachable without it. MEASURED: 42 live lines match
        # the whole line, 0 matched the message. The bare "Out of memory"
        # pattern needs no prefix and keeps matching either way.
        "haystack": "line_prefix",
    },
    "firewall_block": {
        "patterns": [
            r"iptables.*DROP",
            r"nftables.*drop",
            r"UFW BLOCK",
            r"firewalld.*DROP",
            # Any netfilter log line, whatever prefix the rule set; a line a
            # rule logged on its way to ACCEPT is excluded below (EM3-5).
            r"\bIN=\S*\s+OUT=\S*\s.*\bSRC=\S+",
        ],
        "exclude": [r"\bALLOW\b", r"\bACCEPT\b", r"\bAUDIT\b"],
        "severity": "low",
        "sources": ["kern.log", "syslog", "messages", "journald"],
    },
    "ssh_key_added": {
        "patterns": [
            r"Authorized key added to .*\.ssh/authorized_keys",
            r"sshd.*authorized_keys",
        ],
        "severity": "high",
        "sources": ["auth.log", "secure", "journald"],
    },
    "cron_execution": {
        "patterns": [
            r"CRON\[[0-9]+\]:",
            r"cron\[[0-9]+\]:",
        ],
        "severity": "info",
        "sources": ["syslog", "messages", "journald"],
        # THE MEASURED CASE, 150 live lines. The parser returns "CRON" as the
        # service and "129327" as the pid -- exactly the two fields these two
        # patterns are written against -- so without line_prefix BOTH were
        # dead, and cron_execution has been silent since 2026-09-23 23:19.
        "haystack": "line_prefix",
    },
    # EM3-5: what the monitor did not read before. Events unless a rule
    # below (_shape_findings) makes a finding of them.
    "ssh_preauth_disconnect": {
        "patterns": [
            r"Connection closed by (?:authenticating|invalid) user",
            r"Disconnected from (?:authenticating|invalid) user",
            r"Received disconnect from .*\[preauth\]",
            r"Connection (?:closed|reset) by \S+ port \d+ \[preauth\]",
        ],
        "severity": "info",
        "sources": ["auth.log", "secure", "journald"],
    },
    "ssh_max_auth_attempts": {
        "patterns": [
            r"maximum authentication attempts exceeded",
            r"Too many authentication failures",
        ],
        "severity": "medium",
        "sources": ["auth.log", "secure", "journald"],
    },
    "ssh_scanner_probe": {
        "patterns": [
            r"kex_exchange_identification",
            r"banner exchange: Connection from .* invalid format",
            r"Did not receive identification string",
            r"Bad protocol version identification",
            r"Unable to negotiate with \S+ port \d+",
            r"Protocol major versions differ",
        ],
        "severity": "low",
        "sources": ["auth.log", "secure", "journald"],
    },
    "group_membership_changed": {
        "patterns": [
            r"add '[^']+' to (?:shadow )?group '[^']+'",
            r"user \S+ added by \S+ to group \S+",
            r"members of group \S+ set by \S+ to",
            r"groupadd\[\d+\]: (?:new group|group added)",
            r"groupmod\[\d+\]:",
            r"delete '[^']+' from (?:shadow )?group '[^']+'",
            r"user \S+ removed by \S+ from group \S+",
        ],
        "severity": "medium",
        "sources": ["auth.log", "secure", "journald"],
        "haystack": "line_prefix",
    },
    "password_changed": {
        "patterns": [
            r"password changed for",
            r"password for '[^']+' changed by",
            r"chpasswd\[\d+\]:.*changed",
        ],
        "severity": "medium",
        "sources": ["auth.log", "secure", "journald"],
        "haystack": "line_prefix",
    },
    "account_locked": {
        "patterns": [
            r"pam_faillock.*(?:Consecutive login failures|temporarily locked)",
            r"pam_tally2?.*(?:tally|deny)",
            r"account locked due to",
        ],
        "severity": "medium",
        "sources": ["auth.log", "secure", "journald"],
    },
    "polkit_auth_failed": {
        "patterns": [
            r"FAILED to authenticate to gain authorization",
        ],
        "severity": "medium",
        "sources": ["auth.log", "secure", "syslog", "messages", "journald"],
    },
    "mac_denial": {
        "patterns": [
            r'apparmor="DENIED"',
            r"avc:\s+denied",
        ],
        "severity": "low",
        "sources": ["kern.log", "syslog", "messages", "journald", "auth.log"],
    },
    "kernel_taint": {
        "patterns": [
            r"taints kernel",
            r"module verification failed",
            r"Tainted: [A-Z]",
        ],
        "severity": "medium",
        "sources": ["kern.log", "syslog", "messages", "journald"],
    },
    "process_crashed": {
        "patterns": [
            r"Process \d+ \(.*\) of user \d+ dumped core",
            r"dumped core",
        ],
        "severity": "low",
        "sources": ["syslog", "messages", "journald"],
    },
    # ADDED 2026-09-23 WITH THE CURSOR, and it is the register's own note
    # being acted on. `journald rate limiting` was listed DECLINED in the
    # register with the reason "reporting it is a new rule, not a fix, and it
    # belongs in whichever round adopts the cursor". This is that round.
    #
    # IT IS AN EVENT, NOT A FINDING, and that is deliberate. Both daemons
    # write a record when they DROP records: systemd-journald writes
    # "Suppressed N messages from <unit>", and rsyslog's imuxsock writes
    # "imuxsock begins to drop messages". It is a statement about this
    # machine's own logging, and it is exactly what an operator needs beside
    # a quiet log. It is not registered as a detection because there is no
    # address, no account and no process to file it against, and inventing an
    # entity for a host-level fact would put a finding on the wrong subject.
    "log_throttled": {
        "patterns": [
            r"Suppressed \d+ messages from",
            r"imuxsock begins to drop messages",
            r"ratelimit: \d+ message\(s\) suppressed",
        ],
        "severity": "medium",
        "sources": ["journald", "syslog", "messages"],
    },
}

# systemd's catalog message IDs. The ID and the UNIT field name the event and
# its unit exactly, where the text has to be parsed (EM3-6).
MSGID_JOB_DONE = "39f53479d3a045ac8e11786248231fbf"      # a job finished
MSGID_JOB_FAILED = "be02cf6855d2428ba40df7e9d022f03d"    # a start job failed
MSGID_UNIT_FAILED = "d9b373ed55a64feb8242e02dbe79a49c"   # "Failed with result"
MSGID_COREDUMP = "fc2e22bc6ee647b6b90729ab34a250b1"      # systemd-coredump

# Syslog facilities an authentication line comes from: auth and authpriv.
# A journald line from any other facility that merely contains the words is
# not a login (EM3-6).
AUTH_FACILITIES = {"4", "10"}

# Groups whose members can become root or read what root reads.
PRIVILEGED_GROUPS = {"sudo", "wheel", "admin", "root", "adm", "docker",
                     "lxd", "libvirt", "disk", "shadow"}


def _msgid_categories(entry: dict) -> list:
    """Categories that come from a journald record's MESSAGE_ID."""
    mid = entry.get("message_id") or ""
    if mid == MSGID_JOB_DONE and entry.get("job_type") == "start" \
            and entry.get("job_result") == "done":
        return [("service_started", WATCHED_PATTERNS["service_started"]["severity"])]
    if mid in (MSGID_JOB_FAILED, MSGID_UNIT_FAILED):
        return [("service_failed", WATCHED_PATTERNS["service_failed"]["severity"])]
    if mid == MSGID_COREDUMP:
        return [("process_crashed", WATCHED_PATTERNS["process_crashed"]["severity"])]
    return []


# Brute force detection
_failed_logins = defaultdict(deque)  # source key -> deque of timestamps
_seen_events = deque(maxlen=10000)   # in-memory second net, see _is_duplicate
_failed_login_seen = {}              # (key, message, stamp) already counted

# THE FOUR CATEGORIES THAT WERE READ AND RAISED NOTHING (2026-09-25)
# The owner's report: "296 events collected with no detection rule to evaluate
# them... a firewall deny, a service crash, a service start, or a login
# happening right now would show up in query_events but would not raise an
# alert." Confirmed against the store: 55,294 service_started, 72,758
# successful_login, 18,740 firewall_block, 989 service_failed rows, and ZERO
# event_monitor findings ever, because no rule covered any of them.
#
# WHY THEY ARE NOT RAISED ONE-FINDING-PER-EVENT, and this is the decision T1's
# Q2 already made on a measurement rather than on taste: 2,782 successful
# logins and 232 sudo rows in one evening is how an operator is trained to
# ignore the owner's own tool. That decision STANDS for the per-event case. What was
# missing is the other half of it -- the SHAPE rules. A single service failure
# is noise; the same unit failing seven times in five minutes is a restart
# loop. One blocked packet is the firewall doing its job; twenty from one
# address is a scan. So each of the four gets a rule that fires on the shape
# and CANNOT fire on the ordinary case, and the threshold of every one of them
# is set from this host's own measured ordinary traffic:
#
#   service_failed     largest ordinary burst, one unit, 5 min: 7
#                      (agentalsec-ebpf-camera, crash-looping -- a real fault)
#                      histogram: 10 windows with 1, 6 with 2, 2 with 6, 1 with 7
#                      -> BURST_SERVICE_FAILURES = 3 catches the loops and
#                         nothing else
#   service_started    447 windows with 1, 208 with 2, then 7 with 3
#                      -> BURST_SERVICE_STARTS = 3
#   firewall_block     EXCLUDING the multicast housekeeping below, the largest
#                      ordinary burst from one address in 5 min is 2
#                      -> BURST_FIREWALL_BLOCKS = 5
#   successful_login   largest ordinary burst from one address in 5 min: 3
#                      -> BURST_LOGINS = 5
#
# AND THE FIREWALL RULE NEEDS THE MULTICAST EXCLUSION OR IT IS THE AR-1 TRAP
# AGAIN. MEASURED on this host: 76 categorised firewall_block lines, of which
# 40 are DST=224.0.0.1 ICMP type 9 (router-advertisement housekeeping that
# Linux drops by design), 24 are ff02::/mDNS and 12 are 239.255.255.250 SSDP.
# The largest "burst" in that set is 10 from one address and it is a machine
# minding its own business. A block is only interesting when something was
# trying to REACH this host, so the subject of this rule is a source whose
# traffic had a UNICAST destination.
BURST_WINDOW = 300            # seconds, the same window brute force uses
BURST_SERVICE_FAILURES = 3
BURST_SERVICE_STARTS = 3
BURST_FIREWALL_BLOCKS = 5
BURST_LOGINS = 5

_service_failures = defaultdict(deque)   # unit -> timestamps
_service_starts = defaultdict(deque)     # unit -> timestamps
_firewall_blocks = defaultdict(deque)    # src address -> timestamps
_login_successes = defaultdict(deque)    # src address -> timestamps

# THE SAME EVENT, COUNTED ONCE. Added 2026-09-26, EM2-4.
#
# MEASURED, from the owner's report: the dashboard raised 69 LNX-1014
# "service flapping" findings in the ten minutes after one boot, against 60
# DISTINCT units, for services that had each started ONCE (systemd reported
# NRestarts=0 for every one of them, and the binary is the package's own).
# One real start was being counted as many as three times:
#
#   1. THE COPIES. The same line reaches this sensor from journald AND from
#      the syslog file, and a cursor that lags re-reads what it already
#      read. MEASURED in the store: the one 21:11:19 start of
#      xdg-desktop-portal-xapp was counted at the 21:17 read AND again at the
#      21:20 read, and the two sources carried it as two rows.
#   2. THE PAIR. systemd writes "Starting x.service" and then "Started
#      x.service" for one start, and both lines were counted. A boot writes
#      55 such pairs on this host; 34 share a second and 21 straddle one, so
#      no timestamp trick separates them -- the rule counts the "Started"
#      line ONLY, which is one line per start in both directions.
#   3. THE CLOCK. The burst window ran on time.time() -- the READ time, not
#      the line's own time -- so a whole boot's backlog landed inside one
#      300-second window it never occupied in reality.
#
# `marks` closes (1): a (subject, message, stamp) already counted is not
# counted again. The call sites close (2) and (3).
#
# AND (2) IS WHAT THE "Started" LINE GETS RIGHT IN BOTH DIRECTIONS, which is
# why it is that line and not the other. MEASURED on boot -4: a unit
# genuinely crash-looping logged SIXTEEN "Started" lines and ZERO "Starting"
# ones (systemd's restart job logs the start, not the attempt), while an
# ordinary boot logs one of each. Counting "Started" alone therefore gives
# exactly one count per start for an ordinary service AND for a loop -- where
# counting "Starting" alone would have made the crash loop invisible, which
# is the one thing this rule exists to see.
_BURST_MARKS_MAX = 8192          # prune threshold; a boot adds ~200 marks

_service_failure_seen = {}       # (unit, message, stamp) -> True
_service_start_seen = {}         # (unit, message, stamp) -> True
_firewall_seen = {}              # (address, message, stamp) -> True
_login_seen = {}                 # (address, message, stamp) -> True


def _event_seconds(entry: dict):
    """
    The entry's OWN clock in epoch seconds, or None when the line carried no
    timestamp this tree understands.

    None means "use the caller's", and it is a named answer rather than a
    silent fallback: time_basis is set to "parse_time" by both parsers for
    exactly this case, and this reads it (see _parse_syslog_line and
    _journald_entry for where the basis is decided).
    """
    if entry.get("time_basis") != "event":
        return None
    try:
        dt = datetime.strptime(entry.get("timestamp") or "",
                               "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None
    return dt.replace(tzinfo=timezone.utc).timestamp()


def _burst(key: str, store, seen, now: float, threshold: int,
           window: int = BURST_WINDOW, mark=None) -> int:
    """
    One more event for `key`, and the count if it cleared the threshold.

    Returns 0 while the count is ordinary and the size of the burst when it
    fires, CLEARING the store so the next burst is its own finding rather than
    a counter that only ever grows -- the same call _check_brute_force makes,
    and for the same reason.

    A shared helper on purpose: four copies of this loop is how four rules
    come to disagree about what a window means.

    `seen` AND `mark` ARE EM2-4's FIX. `mark` identifies the EVENT, not the
    subject: (subject, message, its own stamp). The same line arriving from
    the second source, or being re-read by a lagging cursor, carries the same
    mark and is not counted again -- while two real recurrences of one unit
    carry different stamps and both count. `now` must be the EVENT's clock
    where the line has one (see _event_seconds); the read clock is only the
    fallback for lines that carry none, where a re-read cannot be told from a
    recurrence and counting twice is the safer error.
    """
    if mark is not None:
        if mark in seen:
            return 0
        seen[mark] = True
        if len(seen) > _BURST_MARKS_MAX:
            for k in list(seen)[:len(seen) - _BURST_MARKS_MAX]:
                del seen[k]

    dq = store[key]
    dq.append(float(now))
    cutoff = float(now) - window
    while dq and dq[0] < cutoff:
        dq.popleft()
    if len(dq) >= threshold:
        count = len(dq)
        dq.clear()
        return count
    return 0


# THE ONE LINE PER EVENT (EM2-4), and why each form is the right one
#
# THE START RULE COUNTS "Started" AND NOT "Starting". MEASURED on this host:
# an ordinary boot logs the pair "Starting x.service" / "Started x.service"
# ONCE per unit, and a unit in a real restart loop (agentalsec-ebpf-camera,
# boot -4) logged SIXTEEN "Started" lines and ZERO "Starting" ones -- systemd
# logs the restart's start, not the attempt. So "Started" alone gives exactly
# one count per start in BOTH directions, where "Starting" alone would have
# made the crash loop invisible, which is the one thing this rule exists to
# see. The price, stated rather than discovered: a ONESHOT unit logs
# "Starting ... Finished" and never "Started", so LNX-1014 does not count
# oneshot units at all. Their failures are still seen -- oneshot failure
# writes "Failed with result", which is LNX-1013's line -- measured on
# casper-md5check.service, a real oneshot failure on this host.
#
# THE FAILURE RULE COUNTS "Failed with result" AND NOT "Failed to start". A
# failing systemd unit writes "x.service: Failed with result 'exit-code'."
# on EVERY failed cycle (18 of them in the camera loop's boot, against 3
# "Failed to start" lines), so it is the per-cycle marker. "Failed to start"
# is the final rate-limited stop, and counting both forms made ONE episode
# read as two failures. The price, stated: a start job that fails without
# the unit entering the failed state -- a dependency or "unit not found"
# refusal -- is no longer counted. Each was measured present-or-absent on
# this host before the choice was made.
_UNIT_FAILED_LINE = re.compile(
    r"^([\w@.\-]+\.(?:service|socket|mount|timer|target)): Failed with result")
# "Started x.service - description" AND the name-only form "Started
# x.service." both exist on this host (MEASURED: 92 real "Started *.service"
# lines in one boot, 91 with a description and 1 -- mintsystem.service --
# without), so the lookahead accepts a trailing period as well as the
# separator characters.
_UNIT_STARTED_LINE = re.compile(
    r"^Started\s+([\w@.\-]+\.(?:service|socket|mount|timer|target))"
    r"(?=[\s:,\"']|\.?$|$)")


def _event_mark(subject: str, message: str, stamp):
    """
    The identity of one event for the duplicate mark: subject, the line's own
    text, and its own stamp. None when the line carried no stamp it can be
    identified BY -- a line with no clock cannot be told from its own re-read,
    and counting it twice is the safer error (see _burst).
    """
    return (subject, message, stamp) if stamp else None


def _manager_of(entry: dict) -> str:
    """
    WHICH systemd INSTANCE wrote the line, or "" when it was not systemd.

    MEASURED, and this is EM2-4's second half: the same unit NAME exists once
    per systemd manager. On this host's 21:10 boot, `dbus.service` started
    once under the system manager (pid 1), once under the login session's user
    manager (1371) and once under the greeter's (1485) -- three real starts of
    THREE different buses. Keyed on the name alone they add up to a burst of
    three, and the rule reports flapping for a machine that did exactly what
    it is supposed to do at a login. The manager's own pid is on every line
    ("systemd[1371]: ..." in a file, `_PID` in a journald record), so the
    subject of this rule is an INSTANCE of a unit under one manager; the
    finding still NAMES the plain unit, because that is what a person acts on.
    """
    if (entry.get("service") or "") != "systemd":
        return ""
    return str(entry.get("pid") or "")


def _unit_of(message: str) -> str:
    """The unit name a systemd line is about, or "" when it carries none."""
    m = re.search(r'([\w@.\-]+\.(?:service|socket|mount|timer|target))'
                  r'(?=[\s:,\'"]|$)', message or "")
    return m.group(1) if m else ""


def _firewall_subject(message: str) -> str:
    """
    The address that tried to REACH this host, or "" if the line is
    housekeeping.

    Returns "" for a multicast or broadcast destination, which is the measured
    exclusion this rule cannot work without (see the block comment above):
    40 of the 76 live firewall_block lines are ICMP type 9 to 224.0.0.1 and
    counting those would put a finding on a machine minding its own business.
    A line with no SRC= at all returns "" too: a block with no subject is not
    evidence of anything about a source.
    """
    msg = message or ""
    src = re.search(r'\bSRC=(\S+)', msg)
    if not src:
        return ""
    src = src.group(1).strip("[]")
    dst = re.search(r'\bDST=(\S+)', msg)
    if dst:
        d = dst.group(1).strip("[]")
        head = d.split(".")[0]
        if head.isdigit() and 224 <= int(head) <= 239:
            return ""
        if d in ("255.255.255.255", "ff02::1", "ff02::2"):
            return ""
        if d.startswith("ff0") or d.startswith("ff1") or d.startswith("ff2"):
            return ""
    return src


def _login_source(message: str) -> str:
    """
    The address a successful login came FROM, or "".

    Only a real address counts. A session opened by root on the console, or by
    a service, has no source address and is not something a burst rule can
    say anything about.
    """
    m = _IP_FROM.search(message or "")
    return _valid_address(m.group(1)) if m else ""

# HOW MUCH ONE POLL HANDS BACK, AND THEREFORE HOW MUCH IT READS.
#
# ONE NUMBER, NOT TWO, and that is the fix for a loss this file introduced
# while fixing a different one. The first version of the cursor kept a
# per-source read cap (5000) and a separate return cap (2000 across all
# sources), so a first run read 5,389 records, handed back 2,000, and the
# cursor had already advanced past the other 3,389: read, categorised, DROPPED
# and never re-readable. The Windows twin has exactly one number for this
# (MAX_EVENTS_PER_POLL, used as both the read cap and the store cap) and that
# is not a coincidence: a cursor may only advance past records the caller
# actually received.
#
# So EVENT_RETURN_CAP is the per-poll BUDGET and it is divided across the
# sources in the poll, each source capped at its share. Whatever does not fit
# STAYS IN THE LOG and is read next poll, in order, from the position we
# stopped at, and get_status()['backlog'] says how much is behind.
EVENT_RETURN_CAP = 2000


def per_source_cap(n_sources: int) -> int:
    """
    This poll's read cap for one source: the budget divided by the sources.

    A plain division with a floor of one, and the division is the safety
    property rather than a tuning choice: the sum of every source's cap is the
    budget, so the records this poll read are records this poll can hand back,
    which is what makes it honest for the cursor to advance past them. There
    is deliberately NO per-source minimum here: a host with twenty sources
    gets a hundred records each per poll and drains over successive polls with
    the backlog saying so, which is the correct behaviour and not a fault.
    """
    return max(1, EVENT_RETURN_CAP // max(1, int(n_sources or 1)))


# CONFIGURATION. EM-12: the documented block was read by nothing.
#
# config.json has carried this since the port:
#
#     "event_monitor": {"enabled": true,
#                       "sources": ["journald", "syslog", "auth.log"],
#                       "poll_interval": 60}
#
# and an operator who removed "syslog" from that list, or set enabled false,
# changed nothing at all: the reader was driven by a hard-coded path list and
# main.py loaded the sensor unconditionally. auditd beside it has a real
# OFF-BY-CONFIG state and this is that shape, copied rather than invented.
#
# THE DEFAULTS ARE NAMED HERE AND THE CALLER CAN SEE WHICH ARE IN FORCE: the
# block this returns is published in get_status()['config'].
DEFAULT_CONFIG = {
    "enabled": True,
    "sources": None,      # None means "every source that exists on this host"
    "poll_interval": POLL_INTERVAL,
    "login_records": True,  # read /var/log/wtmp and btmp (EM3-7)
    "stream": True,         # follow journald and poll as soon as it writes
}

# What configure() last set, for the module-level helpers that have no config
# argument (_stalled_channels, monitor_once's standalone path).
_config = dict(DEFAULT_CONFIG)


def configure(config: dict = None) -> dict:
    """
    The `sensors.event_monitor` block, read once, applied, and returned.

    APPLIED, not just returned: the poll interval below decides how long a
    silence counts as a dead source, and reading it in two places is how the
    two drift. Returns the block so a caller can publish exactly what is in
    force, defaults included.
    """
    block = {}
    try:
        block = ((config or {}).get("sensors", {}) or {}).get("event_monitor", {}) or {}
    except Exception as e:                                   # noqa: BLE001
        logger.debug(f"event_monitor: config block unreadable: {e}")
        block = {}

    sources = block.get("sources")
    if sources is not None:
        try:
            sources = [str(s).strip() for s in sources if str(s).strip()]
        except TypeError:
            logger.warning("event_monitor: sensors.event_monitor.sources is "
                           "not a list, so every available source is read.")
            sources = None

    try:
        interval = int(block.get("poll_interval", POLL_INTERVAL))
    except (TypeError, ValueError):
        interval = POLL_INTERVAL
    if interval < 1:
        interval = POLL_INTERVAL

    applied = {
        "enabled": bool(block.get("enabled", True)),
        "sources": sources,
        "poll_interval": interval,
        "login_records": bool(block.get("login_records", True)),
        "stream": bool(block.get("stream", True)),
    }
    _config.update(applied)
    return dict(applied)


def config_in_force() -> dict:
    """The block currently applied, defaults included."""
    return dict(_config)


def _poll_interval() -> int:
    return int(_config.get("poll_interval") or POLL_INTERVAL)


# THE DRAIN, PORTED TO THE LINUX READER AND THEN REBUILT, 2026-09-21 / 2026-09-23
#
# The 2026-09-21 version of this block measured the wrong quantity and its own
# comment defended a design that was not there. It said "there is no cursor to
# be behind", which was true only while a 200-entry window outspanned the poll
# interval. MEASURED on this host, it does not: auth.log's window covered
# SECONDS and it produced exactly 200 distinct lines per minute for twelve
# minutes running, so the window was the thing deciding coverage and the
# backlog figure it published could only ever be zero.
#
# NOW THERE IS A CURSOR (see the header), so "behind" is a real quantity on
# this side: how much of each source has NOT been read yet. That is what
# `remaining` is, and it is measured, not estimated, for both source kinds:
#
#   file      the unread bytes between the read position and EOF, counted as
#             lines (bounded scan; see _file_remaining)
#   journald  the newest record's sequence number minus ours, which journald
#             answers in one cheap command (_journald_remaining)
#
# A SOURCE THAT WAS CONFIGURED BUT REPORTED NOTHING IS A DEAD ONE, and this is
# the case the 2026-09-21 block claimed to catch and could not: it iterated
# the sources that HAD been read, so a source that read zero entries had no
# key and was never compared. A failed read is reported now, by name, in
# `unreadable` and in `stalled`, and monitor_once reports every configured
# source on every poll, including the ones that returned nothing.
#
# The rule is the Windows rule, kept because it was right there: a remaining
# figure that DOES NOT GO DOWN between two polls is a stuck drain, and a
# source that has not reported for three poll intervals is a dead one. Both
# are lists of source names, never a boolean, so the page can name which one.
_drain_remaining: dict = {}
_drain_previous: dict = {}
_drain_drained: dict = {}
_last_report_at: dict = {}
_read_failures: dict = {}     # source -> the sentence explaining its last failure
_drain_floor: dict = {}       # source -> its backlog figure is a floor, not a count
_gaps_this_run: list = []     # gap records the caller must write, see monitor_once


def _report_progress(source: str, drained: int, remaining: int,
                     now: float | None = None, error: str = None,
                     floor: bool = False) -> None:
    """
    Record what one source's drain did this poll. Called once per source, for
    every configured source, whether or not it returned anything.
    """
    at = time.monotonic() if now is None else now
    _drain_remaining[source] = int(remaining)
    _drain_drained[source] = int(drained)
    _last_report_at[source] = at
    if floor:
        _drain_floor[source] = True
    else:
        _drain_floor.pop(source, None)
    if error:
        _read_failures[source] = str(error)
    else:
        _read_failures.pop(source, None)


def _stalled_channels(now: float | None = None) -> list:
    """
    Sources that are not moving, by name.

    THREE FAULTS, ONE ANSWER, because all three mean the same thing to a
    reader: nothing is coming out of this source.

      * a remaining figure that is non-zero and identical to the previous
        poll's is stuck
      * a source whose last read FAILED is stuck, because a refused read is
        not a quiet log (rule 2 of the honesty rules)
      * a source that has not reported in three poll intervals is gone

    A source with nothing remaining is NEVER stalled, which is the negative
    control that matters: an idle machine is not a broken one.
    """
    at = time.monotonic() if now is None else now
    stuck = []
    for source, remaining in _drain_remaining.items():
        if source in _read_failures:
            stuck.append(source)
            continue
        if remaining > 0 and remaining == _drain_previous.get(source):
            stuck.append(source)
            continue
        if remaining > 0:
            last = _last_report_at.get(source)
            if last is not None and at - last > 3 * _poll_interval():
                stuck.append(source)
    return sorted(stuck)


def _remember_previous_drain() -> None:
    """Called at the end of a poll so the NEXT one can compare against it."""
    _drain_previous.clear()
    _drain_previous.update(_drain_remaining)


# WHERE THE LOGS ARE, AND WHICH OF THEM THE OPERATOR WANTS READ
#
# The canonical name of a source is the FILE'S OWN NAME on this host
# ("auth.log", "syslog", "kern.log", "secure", "messages") or "journald".
# That is not cosmetic: EM-8 measured the store carrying the same file's rows
# under "auth.log" from the file reader and "auth" from search_logs, and the
# regex path used to prefix "linux_" on top of that. One vocabulary, decided
# here, used by every reader in this file.

LOG_CANDIDATES = {
    "auth":    [Path("/var/log/auth.log"),        # Debian/Ubuntu
                Path("/var/log/secure"),          # RHEL/CentOS
                Path("/var/log/authorization")],  # some systems
    "syslog":  [Path("/var/log/syslog"),          # Debian/Ubuntu
                Path("/var/log/messages")],       # RHEL/CentOS
    "kern":    [Path("/var/log/kern.log"),        # Debian/Ubuntu
                Path("/var/log/messages")],       # RHEL/CentOS (mixed)
}

SOURCE_ORDER = ["auth.log", "secure", "authorization", "kern.log", "syslog",
                "messages", "journald", "wtmp", "btmp"]


def _source_family(name: str) -> str:
    """This file's family key, or the name itself when it is not a file."""
    for family, candidates in LOG_CANDIDATES.items():
        if name in (p.name for p in candidates):
            return family
    return name


def _get_log_file_paths() -> dict:
    """
    Paths to log files based on distribution, filtered by the configured
    source list. Returns {canonical name: Path}, plus "journald": None.

    THE FILTER IS THE FIX FOR EM-12's FIRST HALF. An operator who removes
    "syslog" from sensors.event_monitor.sources gets a sensor that does not
    read syslog, and a name that is not a source at all is REPORTED by
    monitor_once rather than ignored, the same call threat_feeds makes for an
    unknown feed name.
    """
    wanted = _config.get("sources")

    def _wanted(name: str) -> bool:
        if wanted is None:
            return True
        if name in wanted:
            return True
        # "auth.log" in the config on a host whose file is "secure", and the
        # other way round: the family key is accepted so one config travels.
        return _source_family(name) in wanted

    paths = {}
    for family in ("auth", "syslog", "kern"):
        for candidate in LOG_CANDIDATES[family]:
            if candidate.exists():
                if _wanted(candidate.name):
                    paths[candidate.name] = candidate
                break

    if wanted is None or "journald" in wanted:
        paths["journald"] = None  # special handling, no file
    return paths


def _unknown_sources() -> list:
    """Configured source names that match nothing this host offers."""
    wanted = _config.get("sources")
    if not wanted:
        return []
    known = {p.name for cands in LOG_CANDIDATES.values() for p in cands}
    known |= set(LOG_CANDIDATES.keys()) | {"journald"}
    return sorted(s for s in wanted if s not in known)


def _log_read_probe() -> tuple:
    """
    (can this account read ANY of the logs, why not).

    ASKED OF THE LOGS, NOT OF THE GROUP LIST. A group name proves an account
    was added to a group, not that anything was installed for it; this reads
    a byte from a real log and journalctl's answer, which is the same call
    SNF-5 made in the sniffer's sibling probe (core/privilege_linux). Both
    readers of that question now answer it the same way.
    """
    for candidate in [p for cands in LOG_CANDIDATES.values() for p in cands]:
        if not candidate.exists():
            continue
        try:
            with candidate.open("rb") as fh:
                fh.readline()
            return True, f"{candidate.name} is readable by this account"
        except PermissionError:
            return False, (f"{candidate.name} exists and this account cannot "
                           f"read it")
        except OSError as e:
            return False, f"{candidate.name}: {type(e).__name__} ({e})"

    ok, why = _journald_probe()
    if ok:
        return True, "journalctl answers, so the journal is readable"
    return False, (why or "no log file exists and journalctl does not answer")


# JOURNALD

def _journald_probe() -> tuple:
    """
    (can this account read the journal, why not).

    THE OLD PROBE RAN `journalctl --version` AND RETURNED TRUE FROM A RETURN
    CODE, which is a statement about the BINARY being installed and not about
    this account's access. It is published as journald_available and the
    adapter turned it into blind: False, so a refused journal read as a green
    line. This reads one record. Three answers are kept apart: the binary is
    missing, the binary is there and refused us, and the journal answered.
    """
    try:
        result = subprocess.run(
            ["journalctl", "--no-pager", "--output=json", "-n", "1"],
            capture_output=True, text=True, timeout=15,
        )
    except FileNotFoundError:
        return False, "journalctl is not installed on this host"
    except subprocess.TimeoutExpired:
        return False, "journalctl did not answer within 15s"
    except Exception as e:                                    # noqa: BLE001
        return False, f"journalctl could not be run: {type(e).__name__} ({e})"

    if result.returncode != 0:
        why = (result.stderr or "").strip().splitlines()
        return False, (f"journalctl refused this account (rc={result.returncode}"
                       + (f": {why[0][:160]}" if why else "") + ")")
    if not (result.stdout or "").strip():
        return False, ("journalctl answered and the journal holds no record, "
                       "so nothing could be read")
    return True, "journalctl answered with a record"


def _journald_entry(record: dict) -> dict:
    """
    One journald JSON record, in the shape the rest of this file speaks.

    THE TIMESTAMP IS THE RECORD'S OWN CLOCK, formatted the way every other
    writer in this app writes a time (naive UTC, "%Y-%m-%d %H:%M:%S"), and
    timestamp_us keeps the raw microsecond value for anyone who needs the
    precision. PRIORITY is no longer parsed and thrown away: it rides the
    entry and into raw_data, because it is the field that says how the
    journal itself rated the record.
    """
    us = record.get("__REALTIME_TIMESTAMP")
    stamp, basis = None, "parse_time"
    if us:
        try:
            stamp = datetime.fromtimestamp(
                int(us) / 1_000_000, tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S")
            basis = "event"
        except (TypeError, ValueError, OverflowError, OSError):
            stamp = None
    seqnum = record.get("__SEQNUM")
    seqnum_id = record.get("__SEQNUM_ID") or ""
    record_id = None
    if seqnum is not None:
        # THE JOURNAL GIVES EVERY RECORD AN ID, and this is it. Sequence
        # numbers are unique within one journal file, which __SEQNUM_ID
        # names; together they are stable across restarts and across a
        # vacuum, so the same record keeps one row on a re-read. See
        # _record_id_for for why a file line needs a different answer.
        record_id = _hash_to_int(f"{seqnum_id}:{seqnum}")
    text = _journald_text
    return {
        "source": "journald",
        "timestamp": stamp,
        "timestamp_us": str(us) if us else None,
        "time_basis": basis,
        "record_id": record_id,
        "seqnum": int(seqnum) if seqnum is not None else None,
        "seqnum_id": seqnum_id,
        "cursor": record.get("__CURSOR"),
        "priority": text(record.get("PRIORITY")),
        "hostname": text(record.get("_HOSTNAME")),
        "service": text(record.get("SYSLOG_IDENTIFIER")),
        "unit": text(record.get("_SYSTEMD_UNIT")),
        "message": text(record.get("MESSAGE")),
        "pid": text(record.get("_PID")),
        "uid": text(record.get("_UID")),
        # Structured fields (EM3-6): what the record is, and about which unit.
        "message_id": text(record.get("MESSAGE_ID")),
        "subject_unit": text(record.get("UNIT") or record.get("USER_UNIT")),
        "job_type": text(record.get("JOB_TYPE")),
        "job_result": text(record.get("JOB_RESULT")),
        "facility": text(record.get("SYSLOG_FACILITY")),
        "coredump_exe": text(record.get("COREDUMP_EXE")),
        "coredump_signal": text(record.get("COREDUMP_SIGNAL_NAME")),
    }


def _journald_text(value) -> str:
    """
    A journald JSON field as text. journalctl writes a non-UTF-8 value as a
    list of byte values, a repeated field as a list of strings, and an
    oversized one as null; any local user can send the first (EM3-1).
    """
    if value is None:
        return ""
    if isinstance(value, list):
        if all(isinstance(v, int) and 0 <= v < 256 for v in value):
            return bytes(value).decode("utf-8", errors="replace")
        return " ".join(_journald_text(v) for v in value)
    return value if isinstance(value, str) else str(value)


def _journald_newest_seqnum() -> tuple:
    """
    (seqnum id, seqnum) of the newest record, or (None, None).

    ONE CHEAP COMMAND, and it is how the backlog is measured: journald's
    sequence numbers are contiguous per journal file, so newest minus ours is
    the exact number of records waiting. The Windows twin works the same way
    out of `newest - scanned_to`.
    """
    try:
        result = subprocess.run(
            ["journalctl", "--no-pager", "--output=json", "-n", "1"],
            capture_output=True, text=True, timeout=15,
        )
    except Exception as e:                                    # noqa: BLE001
        logger.debug(f"journald: could not read the newest record: {e}")
        return None, None
    if result.returncode != 0 or not (result.stdout or "").strip():
        return None, None
    try:
        rec = json.loads(result.stdout.strip().split("\n")[-1])
    except (json.JSONDecodeError, IndexError):
        return None, None
    return rec.get("__SEQNUM_ID"), rec.get("__SEQNUM")


def _journald_lost(marker: dict, first: dict) -> tuple:
    """
    (count, reason) records that were lost between our cursor and `first`.

    MEASURED, NOT GUESSED, and this is the Linux form of the Windows twin's
    "the marker fell off the bottom of the log" report. Journald's sequence
    numbers are contiguous WITHIN ONE JOURNAL FILE, which __SEQNUM_ID names:

        same seqnum id, first.seqnum > ours + 1   -> that many records were
                                                     removed from under us
        a different seqnum id                     -> the journal was
                                                     recreated (a vacuum that
                                                     took everything, or a
                                                     fresh /var/log/journal),
                                                     and the number cannot be
                                                     counted from here
        otherwise                                 -> nothing was lost

    Returns (None, reason) when the count cannot be established, which is a
    different sentence from zero and must not be rounded to it.
    """
    if not marker.get("cursor"):
        return None, None
    ours_i, ours_s = marker.get("seqnum"), marker.get("seqnum_id")
    first_i, first_s = first.get("seqnum"), first.get("seqnum_id")
    if ours_i is None or first_i is None:
        return None, None
    if ours_s and first_s and ours_s != first_s:
        return None, ("the journal was recreated since the last read (its "
                      "sequence id changed), so how many records went with "
                      "the old one cannot be counted from here")
    if first_i > ours_i + 1:
        return first_i - ours_i - 1, "they were removed from the journal"
    return None, None


def _read_journald_lines(marker: dict = None,
                         lines: int = EVENT_RETURN_CAP) -> dict:
    """
    Read journald FORWARD from a persisted marker.

    Returns a dict rather than a bare list because four things have to travel
    back together, and the 2026-09-21 version of this function returned one of
    them (entries) and dropped the rest on the floor:

        entries / marker / error / gap / cursor_refused / remaining

    MARKER IS {'cursor', 'seqnum', 'seqnum_id', 'realtime'}, and each field
    has a job. The cursor is exact. The sequence number is what makes a LOSS
    countable (see _journald_lost). The realtime is the FALL BACK when the
    journal refuses the cursor, which happens when the journal was rotated or
    vacuumed: journalctl answers a stale cursor with "Failed to seek to
    cursor: Invalid argument" and rc 1, measured on this host 2026-09-23. A
    refused cursor is NOT a loss by itself: resuming from the timestamp reads
    everything that is still there, and the sequence number says what is not.
    """
    marker = marker or {}
    cursor = marker.get("cursor")
    capped = False
    refused = False
    fallback_reason = None

    def _run(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=60)
        except FileNotFoundError:
            return None
        except subprocess.TimeoutExpired:
            raise
        except Exception as e:                                # noqa: BLE001
            logger.debug(f"journald read failed: {e}")
            return None

    cmd = ["journalctl", "--no-pager", "--output=json", f"--lines={lines}"]
    if cursor:
        cmd.append(f"--after-cursor={cursor}")

    try:
        result = _run(cmd)
    except subprocess.TimeoutExpired:
        return {"entries": [], "marker": marker, "remaining": 0,
                "error": "journalctl did not answer within 60s",
                "gap": None, "cursor_refused": False}

    if result is None:
        return {"entries": [], "marker": marker, "remaining": 0,
                "error": "journalctl could not be run",
                "gap": None, "cursor_refused": False}

    if cursor and result.returncode != 0:
        # THE CURSOR WENT STALE. Say it, then resume by TIME rather than
        # jumping to the newest record, because a jump is the S22 failure.
        refused = True
        fallback_reason = ((result.stderr or "").strip().splitlines() or
                           [f"rc={result.returncode}"])[0][:200]
        logger.warning(
            f"Event monitor: journald refused the stored cursor ({fallback_reason}). "
            f"Resuming from the last read time instead, so nothing that is "
            f"still in the journal is skipped.")
        since = marker.get("realtime")
        # With --since, "--lines=N" returns the NEWEST N and skips the rest;
        # "+N" returns the oldest N, so the backlog drains in order (EM3-2).
        cmd = ["journalctl", "--no-pager", "--output=json"]
        if since:
            cmd += [f"--lines=+{lines}",
                    f"--since=@{int(since) / 1_000_000:.6f}"]
        else:
            cmd.append(f"--lines={lines}")
        result = _run(cmd)
        if result is None or result.returncode != 0:
            why = (result.stderr or "").strip()[:200] if result else "no answer"
            return {"entries": [], "marker": marker, "remaining": 0,
                    "error": f"the journal refused both the cursor and the "
                             f"time resume ({why})",
                    "gap": None, "cursor_refused": True}

    if result.returncode != 0:
        why = (result.stderr or "").strip().splitlines()
        return {"entries": [], "marker": marker, "remaining": 0,
                "error": (f"journalctl failed (rc={result.returncode}"
                          + (f": {why[0][:160]}" if why else "") + ")"),
                "gap": None, "cursor_refused": refused}

    raw_lines = [l for l in (result.stdout or "").strip().split("\n") if l]
    entries = []
    for line in raw_lines:
        try:
            entries.append(_journald_entry(json.loads(line)))
        except json.JSONDecodeError:
            # A malformed record costs one entry, not the poll. That was
            # found clean in the audit and it is kept.
            continue

    # Order by sequence number: --after-cursor already returns oldest-first,
    # but the first-run path reads a window and a re-read can interleave, and
    # the brute force window must see events in real order.
    entries.sort(key=lambda e: (e.get("seqnum") is None, e.get("seqnum") or 0))

    if len(entries) >= lines:
        capped = True

    new_marker = dict(marker)
    if entries:
        last = entries[-1]
        new_marker = {
            "cursor": last.get("cursor"),
            "seqnum": last.get("seqnum"),
            "seqnum_id": last.get("seqnum_id"),
            "realtime": last.get("timestamp_us"),
        }

    gap = None
    if refused:
        first = entries[0] if entries else None
        if first:
            lost, reason = _journald_lost(marker, first)
        else:
            lost, reason = None, ("the journal refused the stored cursor and "
                                  "returned nothing, so records written since "
                                  "the last read are not recoverable")
        if reason:
            gap = {
                "source": "journald",
                "event_type": "event_log_gap",
                "count": lost,
                "reason": (f"the journal refused the stored cursor "
                           f"({fallback_reason}); {reason}"),
                "from_seqnum": marker.get("seqnum"),
                "to_seqnum": (first or {}).get("seqnum"),
                "cursor_refused": True,
            }

    remaining = 0
    if capped:
        sid, newest = _journald_newest_seqnum()
        ours = new_marker.get("seqnum")
        if sid and new_marker.get("seqnum_id") and sid == new_marker.get("seqnum_id") \
                and newest is not None and ours is not None:
            remaining = max(0, int(newest) - int(ours))
        else:
            # Cannot be counted (the journal moved under us). One is the
            # honest floor: a capped read with an uncountable drain is NOT
            # "nothing behind", and reporting zero here would make a stuck
            # source look caught up.
            remaining = 1

    return {"entries": entries, "marker": new_marker, "remaining": remaining,
            "error": None, "gap": gap, "cursor_refused": refused}


# LOG FILES, AND THE CURSOR THAT REPLACES THE 200-ENTRY WINDOW
#
# A file's position is (device, inode, byte offset) plus the size it had when
# we read, and the three of them answer three different questions:
#
#   device+inode  IS THIS STILL THE SAME FILE? logrotate writes a new file and
#                 moves the old one aside, so a changed inode is a rotation.
#   offset        WHERE WE STOPPED, and it only ever advances past COMPLETE
#                 lines, so a line being written as we read it is not consumed
#                 twice.
#   size          WHAT THE FILE WAS, so a truncation can be measured rather
#                 than guessed at.
#
# THIS REPLACES `tail -n 200` AND THE SHELLING OUT IS GONE WITH IT. Reading in
# Python is what makes a per-source failure sayable: tail's refusal, a missing
# file and a file with nothing new all collapsed into the same empty list
# before (EM-6), and this returns an error string beside the entries instead.
# It also removes a subprocess whose output had to be re-parsed to get back
# the line the kernel already wrote.

# How far into an unread tail the backlog counter will count lines. Bounded
# because the alternative is reading a gigabyte to produce one number, and the
# number is a progress indicator, not an accounting figure. When the scan
# stops early the figure is a FLOOR and the status says so.
MAX_BACKLOG_SCAN_BYTES = 8 * 1024 * 1024


# READ ONE FILE FROM A POSITION

def _read_file_from(path: Path, offset: int, lines: int,
                    skip_partial: bool = False) -> dict:
    """
    Read up to `lines` complete lines from `offset`. Returns
    {bytes, text, error, capped}.

    BINARY, DELIBERATELY. A log is bytes and this host's rsyslog writes UTF-8;
    decoding with errors="replace" per line costs nothing and a decode failure
    can never take a poll down.

    `skip_partial` IS FOR THE MID-FILE SEEK. A position that the app CHOSE
    (the first-run window, which seeks backwards from EOF) can land in the
    middle of a line, and storing the tail of somebody else's record would be
    a row that says something the log never said. A position the app STORED
    always sits on a line boundary, so this is off for the normal path.
    """
    try:
        with path.open("rb") as fh:
            fh.seek(offset)
            chunk = fh.read()
    except PermissionError:
        return {"bytes": b"", "error": f"{path.name} exists and this account "
                                       f"cannot read it"}
    except FileNotFoundError:
        return {"bytes": b"", "error": f"{path.name} disappeared between the "
                                       f"stat and the read"}
    except OSError as e:
        return {"bytes": b"", "error": f"{path.name}: {type(e).__name__} ({e})"}

    if skip_partial and offset > 0:
        # ONLY WHEN THE OFFSET IS GENUINELY MID-FILE. Byte 0 is the start of a
        # line by definition, and skipping to the first newline there discards
        # a complete record: caught by this round's own test on the first run
        # of a small file, which read 2 of its 3 lines.
        cut = chunk.find(b"\n")
        if cut < 0:
            return {"bytes": b"", "text": "", "error": None, "capped": False}
        chunk = chunk[cut + 1:]

    # ONLY COMPLETE LINES ARE CONSUMED. The last record in a file being
    # appended to is usually half-written at the moment of the read; taking it
    # would store a truncated line and then skip the rest of it.
    cut = chunk.rfind(b"\n")
    if cut < 0:
        return {"bytes": b"", "text": "", "error": None, "capped": False}
    complete = chunk[:cut + 1]

    capped = False
    if lines and complete.count(b"\n") > lines:
        # Stop at the Nth newline: the rest stays in the file, and the offset
        # advances only to the last line actually taken, so a capped poll
        # loses NOTHING. This is the difference the cursor makes: the old
        # window handed back its 200 entries and the rest were never read.
        idx = -1
        for _ in range(lines):
            idx = complete.find(b"\n", idx + 1)
        complete = complete[:idx + 1]
        capped = True

    return {"bytes": complete,
            "text": complete.decode("utf-8", errors="replace"),
            "error": None, "capped": capped}


def _file_remaining(path: Path, offset: int) -> tuple:
    """
    (lines not yet read, is it a floor) for the backlog figure.

    Counted from the read position to EOF, bounded by MAX_BACKLOG_SCAN_BYTES.
    Called ONLY when a read was capped, which is the one case where the figure
    is not zero: a caught-up source costs nothing to report.
    """
    try:
        with path.open("rb") as fh:
            fh.seek(offset)
            chunk = fh.read(MAX_BACKLOG_SCAN_BYTES + 1)
    except OSError as e:
        logger.debug(f"could not count the unread tail of {path.name}: {e}")
        return 1, True
    floor = len(chunk) > MAX_BACKLOG_SCAN_BYTES
    n = chunk.count(b"\n")
    return max(1, n), floor


def _read_log_file_lines(log_path: Path, marker: dict = None,
                         lines: int = EVENT_RETURN_CAP) -> dict:
    """
    Read a log file FORWARD from its cursor.

    Returns {entries, marker, error, gap, remaining, floor}.

    THE `marker=` PARAMETER IS THE ONE THE AUDIT FOUND DUSTY, and it is real
    now. EM-11: it was accepted, defaulted, documented as "Last seen line hash
    (for dedup)" and never passed by any caller, so a reader who found it
    concluded dedup was done. What is passed now is a position, not a hash,
    and the position is what makes a re-read impossible rather than merely
    unlikely.

    FOUR THINGS CAN HAPPEN TO A CURSOR, and they are four sentences, not one:

        the same file grew          read from the offset, no gap
        the same file SHRANK        truncated (logrotate with copytruncate, or
                                    a manual >): the unread tail is gone, gap
        a DIFFERENT file            rotated: try the rotated sibling for the
                                    unread tail; whatever is not recovered is
                                    a gap
        the file is gone            gap if we had a position in it

    A GAP IS RETURNED, NOT WRITTEN. This module holds no database handle; the
    adapter writes it as an event_log_gap event, the same row the Windows twin
    writes when its marker falls off the bottom of a log.
    """
    entries, gap = [], None
    marker = marker or {}
    result = {"entries": entries, "marker": marker, "error": None, "gap": None,
              "remaining": 0, "floor": False}

    if not log_path or not log_path.exists():
        # A source we had a position in and is now gone: whatever was appended
        # after our last read is unread, and no amount of later reading brings
        # it back.
        if marker and marker.get("ino"):
            result["gap"] = {
                "source": log_path.name if log_path else "unknown",
                "event_type": "event_log_gap",
                "count": None,
                "lost_bytes": max(0, int(marker.get("size") or 0)
                                  - int(marker.get("offset") or 0)),
                "reason": ("the file is gone: it existed at the last read and "
                           "has been removed since, so anything appended after "
                           "the last read was never seen"),
            }
        if log_path:
            result["error"] = f"{log_path} does not exist"
        return result

    try:
        st = log_path.stat()
    except OSError as e:
        result["error"] = f"{log_path.name}: {type(e).__name__} ({e})"
        return result

    offset = int(marker.get("offset") or 0)
    known = bool(marker.get("ino"))
    rotated = known and (int(marker.get("ino")) != st.st_ino
                         or int(marker.get("dev") or 0) != st.st_dev)
    truncated = known and not rotated and st.st_size < offset

    if rotated:
        # THE ROTATED SIBLING IS THE HONEST ATTEMPT AT THE TAIL. logrotate
        # moves the old file to .1, so the lines between our offset and ITS
        # OWN END are usually still on disk and readable.
        #
        # "ITS OWN END", NOT THE SIZE WE RECORDED, and this round's own test
        # caught the difference. The size in the marker was read at the moment
        # of the last poll, and anything appended after that moment is not in
        # it: the first version compared the recovered bytes against a STALE
        # size and concluded that a tail it had just read had not been read.
        # So the sibling is read from our offset to EOF, and the gap question
        # is asked afterwards, of what could NOT be read.
        recovered, recovered_bytes, why = _recover_rotated(log_path, marker)
        if why:
            gap = {
                "source": log_path.name,
                "event_type": "event_log_gap",
                "count": None,
                # A FLOOR, and the reason says so: the file may have grown
                # after the last read, so the true number is at least this.
                "lost_bytes": max(0, int(marker.get("size") or 0) - offset),
                "reason": ("the file was rotated before its unread tail was "
                           f"read, and {why}. The number of lost bytes is a "
                           f"FLOOR: the file may have grown after the last "
                           f"read and this side cannot see how much"),
            }
        elif recovered:
            # RECOVERED LINES ARE STORED, not merely counted. They are lines
            # this host's log carried and no other pass will ever see them, so
            # dropping them after reading them would be the worst of both.
            entries.extend(_recovered_lines(log_path, offset))
            logger.info(
                f"Event monitor: {log_path.name} was rotated and {recovered} "
                f"unread line(s) were recovered from the rotated sibling.")
        offset = 0

    if truncated:
        unread_bytes = max(0, int(marker.get("size") or 0) - offset)
        gap = {
            "source": log_path.name,
            "event_type": "event_log_gap",
            "count": None,
            "lost_bytes": unread_bytes,
            "reason": ("the file was truncated (it shrank below the position "
                       "we had read to), so the unread tail was discarded"),
        }
        offset = 0

    if not known:
        # FIRST RUN: adopt the newest window and mark the position. Reading a
        # four-day back-catalogue on first boot is not wanted, and pretending
        # the window was complete would be worse than saying it is a start
        # point. The Windows twin does exactly this with single_page=True and
        # calls it "taking the newest page".
        #
        # THE SEEK LANDS MID-LINE BY CONSTRUCTION, so the reader skips to the
        # first newline before storing anything: half of somebody else's
        # record is a row that says something the log never said.
        offset = _window_start(log_path, FIRST_RUN_LINES)
        marker = dict(marker)
        marker["first_run"] = True

    read = _read_file_from(log_path, offset, lines,
                           skip_partial=not known)
    if read["error"]:
        result["error"] = read["error"]
        return result

    new_offset = offset + len(read["bytes"])
    text = read.get("text") or ""
    for line in text.split("\n"):
        if not line.strip():
            continue
        parsed = _parse_syslog_line(line, log_path.name)
        if parsed:
            entries.append(parsed)

    new_marker = {
        "dev": st.st_dev,
        "ino": st.st_ino,
        "offset": new_offset,
        "size": max(st.st_size, new_offset),
    }
    if not known:
        new_marker["first_run"] = True

    if read.get("capped"):
        result["remaining"], result["floor"] = _file_remaining(log_path,
                                                               new_offset)

    result.update(entries=entries, marker=new_marker, gap=gap)
    return result


def _window_start(path: Path, lines: int) -> int:
    """
    A byte offset that puts roughly the last `lines` lines ahead of it.

    The first run needs a position near the end rather than at the start, and
    a line count is not a byte count. This walks BACKWARDS from EOF in bounded
    chunks until it has seen enough newlines, so the guess is made from the
    file's own contents rather than from an average line length. The reader
    skips to the next newline afterwards, so landing mid-line is expected and
    handled.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return 0
    chunk = 64 * 1024
    seen = 0
    pos = size
    try:
        with path.open("rb") as fh:
            while pos > 0 and seen < lines:
                start = max(0, pos - chunk)
                fh.seek(start)
                seen += fh.read(pos - start).count(b"\n")
                pos = start
                if chunk < 4 * 1024 * 1024:
                    chunk *= 4
    except OSError:
        return 0
    return pos


def _recover_rotated(path: Path, marker: dict) -> tuple:
    """
    (lines recovered, bytes recovered, why not) from `path`.1.

    Best effort by design and it says which it was. Checks the inode: a `.1`
    that is NOT the file we were reading is somebody else's rotation, and
    reading it would put an unrelated host's lines in this one's rows.

    READS UNCAPPED BUT BOUNDED, because the caller compares the bytes it got
    against the bytes that were unread: a capped recovery would look like a
    loss that did not happen. MAX_BACKLOG_SCAN_BYTES is the bound, and hitting
    it is reported as a floor rather than as recovery.
    """
    sibling = path.with_name(path.name + ".1")
    if not sibling.exists():
        return 0, 0, "there is no rotated sibling to read it from"
    try:
        sib = sibling.stat()
    except OSError as e:
        return 0, 0, f"the rotated sibling could not be stat'ed ({e})"
    if int(marker.get("ino") or 0) != sib.st_ino:
        return 0, 0, ("the rotated sibling is not the file this position was "
                      "taken in")
    offset = int(marker.get("offset") or 0)
    # READ FROM OUR OFFSET TO THE SIBLING'S OWN END, bounded. Not to the size
    # in the marker: that number was read at the last poll and the file kept
    # growing after it.
    try:
        with sibling.open("rb") as fh:
            fh.seek(offset)
            data = fh.read(MAX_BACKLOG_SCAN_BYTES + 1)
    except PermissionError:
        return 0, 0, ("the rotated sibling exists and this account cannot "
                      "read it")
    except OSError as e:
        return 0, 0, f"the rotated sibling could not be read ({e})"
    if len(data) > MAX_BACKLOG_SCAN_BYTES:
        return (data[:MAX_BACKLOG_SCAN_BYTES].count(b"\n"),
                MAX_BACKLOG_SCAN_BYTES,
                f"its unread tail is larger than {MAX_BACKLOG_SCAN_BYTES} "
                f"bytes and was not read past that bound")
    return data.count(b"\n"), len(data), None


def _recovered_lines(path: Path, offset: int) -> list:
    """
    The unread tail of a rotated sibling, PARSED, or [] when it cannot be had.

    The caller above only needs the count; this is what a reader needs, and it
    is separate so a test can look at what was actually recovered rather than
    at a number.
    """
    sibling = path.with_name(path.name + ".1")
    if not sibling.exists():
        return []
    read = _read_file_from(sibling, offset, 0)
    if read.get("error"):
        return []
    out = []
    for line in (read.get("text") or "").split("\n"):
        if not line.strip():
            continue
        parsed = _parse_syslog_line(line, path.name)
        if parsed:
            parsed["recovered_from"] = "rotated"
            out.append(parsed)
    return out


# BINARY LOGIN RECORDS (EM3-7). wtmp holds every login, logout, boot and
# shutdown; btmp every failed login, including ones a text log never kept or
# lost to rotation. Fixed 384-byte glibc utmp records on Linux.
LOGIN_RECORD_FILES = {"wtmp": Path("/var/log/wtmp"), "btmp": Path("/var/log/btmp")}
UTMP_FORMAT = "<h2xi32s4s32s256s2hi2i16s20x"
UTMP_SIZE = struct.calcsize(UTMP_FORMAT)
FIRST_RUN_RECORDS = 50
_UT_RUN_LVL, _UT_BOOT, _UT_LOGIN, _UT_USER, _UT_DEAD = 1, 2, 6, 7, 8
_login_record_warned = {}
_login_record_state = {}         # name -> "read" or why it was not


def _utmp_text(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", errors="replace").strip()


def _utmp_address(raw: bytes, host: str) -> str:
    """The remote address in ut_addr_v6, else the host field if it is one."""
    if raw.strip(b"\0"):
        try:
            if not raw[4:].strip(b"\0"):
                return socket.inet_ntop(socket.AF_INET, raw[:4])
            return str(ipaddress.ip_address(socket.inet_ntop(socket.AF_INET6, raw)))
        except (OSError, ValueError):
            pass
    return _valid_address(host)


def _login_record_entry(rec: bytes, kind: str) -> dict | None:
    """One utmp record as an event entry, or None for records that say nothing."""
    try:
        (ut_type, pid, line, _id, user, host, _e1, _e2, _sess, sec, _usec,
         addr) = struct.unpack(UTMP_FORMAT, rec)
    except struct.error:
        return None
    line, user, host = _utmp_text(line), _utmp_text(user), _utmp_text(host)
    ip = _utmp_address(addr, host)
    where = f" from {ip or host}" if (ip or host) else ""
    if kind == "btmp":
        cats = [("failed_login", WATCHED_PATTERNS["failed_login"]["severity"])]
        message = f"failed login for {user or 'an unknown account'}{where} on {line or 'unknown line'}"
    elif ut_type == _UT_USER:
        cats = [("login_session", "info")]
        message = f"login by {user}{where} on {line}"
    elif ut_type == _UT_DEAD:
        cats = [("logout_session", "info")]
        message = f"session on {line} ended"
    elif ut_type == _UT_BOOT:
        cats = [("system_boot", "info")]
        message = f"system boot ({host})"
    elif ut_type == _UT_RUN_LVL and user == "shutdown":
        cats = [("system_shutdown", "info")]
        message = f"system shutdown ({host})"
    else:
        return None
    try:
        stamp = datetime.fromtimestamp(sec, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S") if sec > 0 else None
    except (OverflowError, OSError, ValueError):
        stamp = None
    entry = {
        "source": kind, "timestamp": stamp,
        "time_basis": "event" if stamp else "parse_time",
        "record_id": _hash_to_int(kind + rec.hex()),
        "service": kind, "pid": str(pid) if pid else "",
        "message": message, "raw": message,
        "preset_categories": cats,
    }
    if user and (kind == "btmp" or ut_type == _UT_USER):
        entry["username"] = user
    if ip:
        entry["ip_address"] = ip
    return entry


def _read_login_records(path: Path, kind: str, marker: dict = None,
                        limit: int = EVENT_RETURN_CAP) -> dict:
    """
    Read utmp records forward from a byte offset, with the same rotation and
    truncation handling as the text logs. Returns the same shape as
    _read_log_file_lines.
    """
    marker = marker or {}
    result = {"entries": [], "marker": marker, "error": None, "gap": None,
              "remaining": 0, "floor": False}
    if not path.exists():
        result["error"] = f"{path} does not exist"
        return result
    try:
        st = path.stat()
    except OSError as e:
        result["error"] = f"{path.name}: {e.strerror or e}"
        return result
    offset = int(marker.get("offset") or 0)
    known = bool(marker.get("ino"))
    rotated = known and int(marker.get("ino")) != st.st_ino
    if rotated or (known and st.st_size < offset):
        result["gap"] = {
            "source": kind, "event_type": "event_log_gap", "count": None,
            "lost_bytes": max(0, int(marker.get("size") or 0) - offset),
            "reason": (f"{path.name} was {'rotated' if rotated else 'truncated'} "
                       f"before its unread records were read")}
        offset = 0
    if not known:
        offset = max(0, st.st_size - FIRST_RUN_RECORDS * UTMP_SIZE)
    offset -= offset % UTMP_SIZE
    try:
        with path.open("rb") as fh:
            fh.seek(offset)
            data = fh.read((limit or EVENT_RETURN_CAP) * UTMP_SIZE)
    except PermissionError:
        result["error"] = (f"{path.name} exists and this account cannot read it "
                           f"(it is root:utmp); the records only it holds are "
                           f"not seen unelevated")
        return result
    except OSError as e:
        result["error"] = f"{path.name}: {e.strerror or e}"
        return result
    whole = len(data) - len(data) % UTMP_SIZE
    for i in range(0, whole, UTMP_SIZE):
        entry = _login_record_entry(data[i:i + UTMP_SIZE], kind)
        if entry:
            result["entries"].append(entry)
    new_offset = offset + whole
    result["marker"] = {"dev": st.st_dev, "ino": st.st_ino,
                        "offset": new_offset, "size": st.st_size}
    if not known:
        result["marker"]["first_run"] = True
    if st.st_size > new_offset + UTMP_SIZE - 1:
        result["remaining"] = (st.st_size - new_offset) // UTMP_SIZE
    return result


# PARSING
#
# EM-4: the parser expected RFC 3164 and this host's rsyslog writes ISO
# timestamps with an offset. MEASURED over every line of the three live files:
# 4774 lines read, 0 parsed by the regex, 4774 fell to a fallback that
# returned FOUR keys (no hostname, no service, no pid) stamped with the PARSE
# time. One row in the owner's store is 92 minutes off the event it describes,
# and every file-source row had an empty process_name.

# RFC 5424 / systemd short-iso, which is what this host actually writes:
#   2026-09-23T18:34:41.196963-07:00 HOST sudo:    USER : TTY=pts/1 ; ...
_SHORT_ISO = re.compile(
    r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
    r'\s+(\S+)\s+([^:\[]+?)(?:\[(\d+)\])?:\s?(.*)$'
)

# RFC 3164, kept because a RHEL host still writes it:
#   Sep 23 18:34:41 host sudo: message
_RFC3164 = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$'
)


def _to_utc_string(dt: datetime) -> str:
    """The house format for a stored time: naive UTC, seconds."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _parse_syslog_line(line: str, source: str) -> dict:
    """
    Parse a syslog line, ISO first and RFC 3164 second.

    Returns a dict with the EVENT'S OWN TIME when the line carries one, and
    says which basis the time is on when it does not:

        time_basis "event"       the timestamp is the line's own
        time_basis "parse_time"  the line carried no timestamp this parser
                                 understands, so the caller must not pass it
                                 to the database as the event's time

    THE FALLBACK IS STILL A FALLBACK AND IT NO LONGER LIES. It used to return
    timestamp=now() and no marker at all, so a row that happened 92 minutes
    ago was stored as though it happened when the app looked. The row is still
    stored (losing the line would be worse) and the app now knows, and says,
    that the time on it is the read time.
    """
    match = _SHORT_ISO.match(line)
    stamp, basis = None, "parse_time"
    hostname = service = pid = None
    message = line

    if match:
        ts, hostname, service, pid, message = match.groups()
        try:
            # fromisoformat handles Z, +HH:MM and +HHMM on 3.11+; this app
            # requires 3.10, so the Z form is normalised rather than trusted.
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00")
                                        if ts.endswith("Z") else ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            stamp = _to_utc_string(dt)
            basis = "event"
        except ValueError:
            stamp, basis = None, "parse_time"
    else:
        match = _RFC3164.match(line)
        if match:
            ts, hostname, service, pid, message = match.groups()
            try:
                # RFC 3164 carries NO ZONE and means LOCAL time. The old code
                # stamped UTC on it, which is a second time error waiting on a
                # host that writes this format.
                dt = datetime.strptime(
                    f"{datetime.now().year} {ts}", "%Y %b %d %H:%M:%S"
                ).astimezone()
                stamp = _to_utc_string(dt)
                basis = "event"
            except ValueError:
                stamp, basis = None, "parse_time"

    return {
        "source": source,
        "timestamp": stamp,
        "time_basis": basis,
        "record_id": _record_id_for_line(line),
        "hostname": hostname,
        "service": (service or "").strip() or None,
        "pid": pid,
        "message": message,
        "raw": line,
    }


def _hash_to_int(text: str) -> int:
    """
    A stable 60-bit integer for a record. Fits SQLite's INTEGER with room to
    spare, and is short enough that a row is readable in a query.
    """
    return int(hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:15], 16)


def _record_id_for_line(line: str) -> int:
    """
    The identity of a FILE log line, for the idempotent write.

    A LINE HAS NO ID OF ITS OWN, and that is the whole reason EM-1 happened:
    save_event's ON CONFLICT(source, source_record_id) is the mechanism that
    stops a re-read becoming a second row, and this side never passed one, so
    97.4% of the store became copies. rsyslog gives the line no record number,
    so its identity IS its content: the same bytes are the same event, and the
    offset it was read at deliberately does NOT take part, because a rotation
    re-reads the same line from a different offset and must still be one row.

    THE COST, STATED RATHER THAN DISCOVERED: two byte-identical lines written
    in the same SECOND are one row. rsyslog has nothing in a line that tells
    them apart, so any answer here is a choice; this one keeps the re-read
    out of the store, which is the failure that was measured, and the
    in-memory net below catches the same case within a poll either way.
    """
    return _hash_to_int(line)


def _hash_event(entry: dict) -> str:
    """Create a hash for event deduplication."""
    content = f"{entry.get('source', '')}{entry.get('record_id', '')}" \
              f"{entry.get('timestamp', '')}{entry.get('message', '')}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _is_duplicate(entry: dict) -> bool:
    """
    The IN-MEMORY second net, bounded at _seen_events.

    It is no longer the thing that keeps the store clean (the persisted cursor
    and the record id are), and it is kept because it costs one hash: it
    catches a re-read inside a single process between two polls, before the
    database has to.
    """
    event_hash = _hash_event(entry)
    if event_hash in _seen_events:
        return True
    _seen_events.append(event_hash)
    return False


# FIELD EXTRACTION

# pam_unix writes key=value pairs and EMPTY VALUES ARE NORMAL: a console login
# has "ruser= rhost= user=<account>". EM-3 measured the consequence of the old
# regex against this shape: `user[=:\s]+(\w+)` matched "user= rhost" and put
# THE WORD "rhost" in the username column of 164 real rows, while the account
# the line is about sat one field to the right.
_USER_KEYVALUE = re.compile(r'(?:^|\s)r?user=(\S+)')
# THE CAPTURE IS BOUNDED BY EVIDENCE, NOT BY PROSE. Two alternatives, and each
# carries its own proof that an account follows:
#
#   A  "for user X" / "for invalid user X"   X may end the message, because the
#      word `user` already said what X is. pam_unix writes exactly this on
#      every session line: "session closed for user root".
#   B  "for X" where X is followed by a STRONG MARKER -- "(uid=", " from ",
#      " port " or " by ". sshd writes this shape on every accepted key:
#      "Accepted publickey for <account> from 203.0.113.9 port 61113".
#      THE ACCOUNT AND THE ADDRESS ARE PLACEHOLDERS, deliberately: this file
#      ships, and the real values came out of this machine's own auth.log.
#      The pattern below is the claim; it reads the real values at run time
#      and nothing in this comment is read by any code.
#   C  "for [X]", pam's bracketed form on the screensaver path, same mask:
#      "auth could not identify password for [<account>]".
#
# WHAT IT REPLACED, MEASURED. The old pattern was 'for (?:invalid user )?(\S+)'
# -- no word boundary, no marker, no evidence -- and the store shows what it
# took: 19,350 rows whose username is 'processes' (from "Waiting for processes
# to exit"), 12,312 at 'appstream2' (a flatpak pull line), 1,516 at 'UDMA'
# ("configured for UDMA/133"), and 21,576 rows in total whose username is a
# bare word. Against the same live logs, the evidence-bounded form refuses
# every one of those and still reads all 991 real auth.log captures, the 474
# lines in the "for <account> from <address>" shape among them. (The real
# account and address were measured on this machine; the placeholder is
# deliberate, because this file ships. The register of measurements is
# bugfinder.md, which does not.)
_USER_FOR = re.compile(
    r'for (?:invalid user |user )([^\s(]+)(?=\s*(?:\(uid=|from\s|port\s|by\s|$))'
    r'|for ([^\s(]+)(?=\s*(?:\(uid=|from\s|port\s|by\s))'
    r'|for \[([^\]]+)\]')
_USER_NAME_FIELD = re.compile(r'(?:new user|useradd)[^;]*?\bname=([^,\s]+)')
# An IPv4 dotted quad or an IPv6 literal. The v6 half is loose on purpose and
# every capture is checked by _valid_address before it is used (EM3-4).
_ADDR = r'((?:\d{1,3}\.){3}\d{1,3}(?!\d)|[0-9A-Fa-f]{0,4}:[0-9A-Fa-f:.]*(?:%[\w.-]+)?)'
_IP_FROM = re.compile(r'from\s+' + _ADDR)
_IP_RHOST = re.compile(r'rhost=' + _ADDR)
# THE LAST RESORT, AND IT IS BOUNDED NOW. It was '((?:\d{1,3}\.){3}\d{1,3})'
# -- any dotted quad ANYWHERE on the line -- and two values in the src_ip
# column of rows this sensor wrote prove what that costs:
#
#     1,967 rows at 1.0.0.10     from "intel/ibt-hw-37.8.10-fw-1.10.3.11.e.bseq"
#                                (a Bluetooth FIRMWARE FILENAME)
#     4 rows at 170.0.0.192      from the in-addr.arpa list systemd-resolved
#                                prints ("...-addr.arpa 170.0.0.192.in-addr.arpa")
#
# Both are MEASURED: the bounded form below returns None for the producing
# lines and still reads every real one, including the SRC= values. A value in
# an IP column that is not an address is the same defect class as the "rhost"
# usernames: the model reasons confidently over a wrong fact.
#
# NOT INCLUDED IN THAT CLAIM, because they were checked and are genuine:
# 11.22.37.169, 11.22.33.44 and one more are the SRC= of real ICMP type 9
# records this host's own logs carry. The third value is written out in full
# in the register of measurements rather than here, because it lies inside a
# private range and this file ships. All three look wrong and they are not.
_IP_ANY = re.compile(r'(?<![\w./:-])((?:\d{1,3}\.){3}\d{1,3})(?![\w./:-])')


def _looks_like_account(value: str) -> bool:
    r"""
    Could this captured token plausibly be a login name?

    NARROW AND DELIBERATELY PERMISSIVE, the same shape as adapters'
    _valid_entity and for the same measured reason. The three username
    patterns are prose matchers -- they read English sentences -- so their
    captures run from the account itself to whole paths and identifier
    strings. MEASURED on this host's live logs, before the patterns were
    fixed: 1,453 captures were implausible, including 'user' (762 times, from
    "session opened for user root(uid=0)"), 'processes' (from "Waiting for
    processes to exit"), '/run/user/1000/gvfsd/socket-B2anI405' and
    '/home/.../whoami2.py'.

    It refuses only what it can SEE is not a name: a path (a slash or a
    leading dot), whitespace, a trailing fragment of a sentence, an
    over-long token, and the handful of field names and English words these
    patterns are known to land on. Everything else is accepted, because a
    rule that is too strict would silence a real account on a host this app
    has never seen -- and 'user' IS a legal account name somewhere.
    """
    value = (value or "").strip().strip("'\"").rstrip(",;:").strip("()")
    if not value or len(value) > 64:
        return False
    if any(c.isspace() for c in value):
        return False
    if "/" in value or value.startswith("."):
        return False
    if value.endswith("=") or value.startswith("=") or "=" in value:
        return False
    if value.lower() in _NOT_AN_ACCOUNT:
        return False
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\-]*", value))


# The tokens these prose patterns are MEASURED to land on that are not
# accounts. Kept as a named set so a test can assert every member is still
# refused, and so adding one is a visible edit rather than a silent widening.
_NOT_AN_ACCOUNT = {
    "user", "invalid", "unknown", "processes", "process", "session",
    "uid", "gid", "root(", "by", "for", "from", "and", "the", "of", "to",
    "in", "on", "with", "at", "is", "a", "an", "no", "not", "root)",
}


def _captured_account(match, pattern_group: int) -> str:
    """
    The account a username pattern captured, from whichever alternative hit.

    _USER_FOR has three alternatives and only one of them is ever a match, so
        the value is the first group that is not None. Kept here rather than
        inline at the call site so a fourth alternative cannot be added and
        silently ignored -- which is exactly how the "for ..." pattern came to
        capture the word "user" in the first place.
    """
    groups = match.groups()
    for g in groups[pattern_group:]:
        if g:
            return g.strip().strip("'\"").strip("[]").rstrip(",;:")
    return ""


def _extract_fields(entry: dict) -> dict:
    r"""
    Pull username and address out of a log line.

    Ordered, and the order is the point: pam's key=value pairs first because
    they are the machine-readable form, then the sshd/dbus "for <user>" form,
    then a name= field. The old list had `user[=:\s]+(\w+)` FIRST and it
    matched the wrong token on every pam line this host writes.

    EM2-2, MEASURED 2026-09-25: THE PROSE PATTERNS STILL MIS-FIRE
    EM-3 fixed the "rhost" rows in the key=value pattern. The other two were
    never measured against the store, and the store says what they do:

        username column, this sensor's own sources, top values
            19,350  'processes'   "Session 134 logged out. Waiting for
                                   processes to exit."
            12,312  'appstream2'  a flatpak pull line
             1,516  'UDMA'        "configured for UDMA/133"
               919  'user'        "session opened for user root(uid=0)"
               164  'rhost'       the rows EM-3 fixed
        and 21,576 rows in total whose username is a bare word, against
        134,000 that were right.

    Three causes, each fixed at the source rather than filtered afterwards:

      1. "for ..." took the next word whatever it was, so "configured for
         IRQ 11" filed a kernel line under an account called IRQ. It now
         requires EVIDENCE that an account follows (see _USER_FOR).
      2. The name= pattern fired on ANY line containing name=, and this host
         writes 56 AppArmor records a day carrying name="Discord",
         name="brave", name="net_admin". A profile name in the username
         column is a wrong fact about an account. It now only reads a line
         that is ABOUT user management ("new user: name=...").
      3. Both were unchecked prose captures. _looks_like_account is the net
         under all three patterns, applied where the value is produced
         rather than at each of the call sites.

    MEASURED AFTER: 1,344 captures on the same logs, 1,260 of them from a
    service that authenticates; every false value above reads 0, while the
    real ones are unchanged. Those real ones (the operator's own account,
    `root`, and the address 238 captures came from) are named in
    bugfinder.md with their counts; this file ships, so they are not
    written here.
    """
    message = entry.get("message", "") or ""
    extracted = {}

    for pattern in (_USER_KEYVALUE, _USER_FOR, _USER_NAME_FIELD):
        match = pattern.search(message)
        if not match:
            continue
        value = _captured_account(match, 0)
        if value and _looks_like_account(value):
            extracted["username"] = value
            break

    for pattern in (_IP_FROM, _IP_RHOST, _IP_ANY):
        match = pattern.search(message)
        addr = _valid_address(match.group(1)) if match else ""
        if addr:
            extracted["ip_address"] = addr
            break

    if entry.get("service"):
        extracted["service"] = entry["service"]

    return extracted


def _valid_address(value: str) -> str:
    """The canonical form of an IPv4 or IPv6 literal, or "" if it is not one."""
    try:
        return str(ipaddress.ip_address((value or "").split("%")[0]))
    except ValueError:
        return ""


def _looks_like_ip(value: str) -> bool:
    """The Windows twin's own test, ported: an address, or something v6-ish."""
    parts = (value or "").split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return True
    return ":" in (value or "")


def _shape_findings(entry: dict, categories: list, fields: dict,
                    now: float) -> list:
    """
    The SHAPE rules for the four categories that raised nothing (2026-09-25).

    Each of these categories is events-only, by the owner's T1 decision, and
    that decision was made on a measurement: raising one finding per login
    trains an operator to ignore the owner's own tool. This is the other half of the
    same decision. One service failure is noise; the same unit failing three
    times in five minutes is a restart loop. One blocked packet is the
    firewall working; five from one address is somebody probing.

    RETURNS ONLY THE BURST FINDINGS. The per-event finding for each category
    is still the caller's business and is still not raised, exactly as before.

    EVERY RULE HERE NEEDS A SUBJECT, and a line with no subject produces no
    finding rather than one filed against "unknown": a burst rule that cannot
    name what burst has nothing to tell anybody. That is the same call the
    brute force check makes.
    """
    types = {c[0] for c in categories}
    message = entry.get("message") or ""
    out = []

    # WHEN IT HAPPENED vs WHEN IT WAS READ (EM2-4)
    #
    # The window runs on the EVENT's own clock. Measured in the owner's store:
    # a line stamped 21:11:19 was counted at the 21:17 read and again at the
    # 21:20 read, and a whole boot's backlog landed inside one window it never
    # occupied. `now` is only the fallback for a line that carries no stamp
    # (its time_basis is "parse_time" and that is its own visible answer).
    # `stamp` keys the duplicate mark so the SAME event from the other source,
    # or from a re-read, is counted once.
    event_now = _event_seconds(entry) or now
    stamp = entry.get("timestamp") if entry.get("time_basis") == "event" else None
    # WHICH systemd INSTANCE (EM2-4's second half): the same unit name exists
    # once per manager, and the system bus plus two user sessions started
    # "dbus.service" three times in three seconds on this host's last boot.
    # The count is keyed on the INSTANCE; the finding names the plain unit.
    manager = _manager_of(entry)

    if "service_failed" in types:
        # THE "Failed with result" FORM ONLY (EM2-4, measured): it is the line
        # a unit writes on EVERY failed cycle, where "Failed to start" is the
        # final rate-limited stop and appears once per episode -- counting
        # both made one episode read as two failures.
        m = _UNIT_FAILED_LINE.search(message)
        unit = m.group(1) if m else ""
        # journald names the unit in a field (EM3-6).
        if not unit and entry.get("message_id") == MSGID_UNIT_FAILED:
            unit = entry.get("subject_unit") or ""
        if unit:
            n = _burst((manager, unit), _service_failures, _service_failure_seen,
                       event_now, BURST_SERVICE_FAILURES,
                       mark=_event_mark((manager, unit), message, stamp))
            if n:
                out.append({
                    "type": "service_restart_loop",
                    "entity_type": "process",
                    "entity_value": unit,
                    "burst_count": n,
                    "window_seconds": BURST_WINDOW,
                    "severity": "medium",
                    "source": entry.get("source"),
                    "timestamp": entry.get("timestamp"),
                    "message": message,
                    "description": (
                        f"{unit} failed {n} times inside {BURST_WINDOW}s. A "
                        f"single failure is ordinary; this many in one window "
                        f"is a unit that cannot stay up, and systemd will keep "
                        f"restarting it. Read the unit's own log for why."),
                })

    if "service_started" in types:
        # THE "Started" FORM ONLY (EM2-4, measured -- see the block above
        # _event_mark for both directions of that measurement). One line per
        # start for an ordinary unit AND for a crash-looping one, so the
        # "Starting"/"Started" pair counts once instead of twice and a restart
        # loop stays visible.
        m = _UNIT_STARTED_LINE.search(message)
        unit = m.group(1) if m else ""
        # A "Started" job done record names its unit in a field (EM3-6).
        # "Finished" records of oneshot units stay uncounted, as before.
        if not unit and entry.get("message_id") == MSGID_JOB_DONE \
                and message.startswith("Started"):
            unit = entry.get("subject_unit") or ""
        if unit:
            n = _burst((manager, unit), _service_starts, _service_start_seen,
                       event_now, BURST_SERVICE_STARTS,
                       mark=_event_mark((manager, unit), message, stamp))
            if n:
                out.append({
                    "type": "service_flapping",
                    "entity_type": "process",
                    "entity_value": unit,
                    "burst_count": n,
                    "window_seconds": BURST_WINDOW,
                    "severity": "low",
                    "source": entry.get("source"),
                    "timestamp": entry.get("timestamp"),
                    "message": message,
                    "description": (
                        f"{unit} started {n} times inside {BURST_WINDOW}s. A "
                        f"unit that keeps starting is a unit that keeps "
                        f"stopping: either it is failing and being restarted, "
                        f"or something is cycling it on purpose."),
                })

    if "firewall_block" in types:
        subject = _firewall_subject(message)
        if subject:
            n = _burst(subject, _firewall_blocks, _firewall_seen,
                       event_now, BURST_FIREWALL_BLOCKS,
                       mark=_event_mark(subject, message, stamp))
            if n:
                out.append({
                    "type": "firewall_scan_from_host",
                    "entity_type": "ip",
                    "entity_value": subject,
                    "ip_address": subject,
                    "burst_count": n,
                    "window_seconds": BURST_WINDOW,
                    "severity": "medium",
                    "source": entry.get("source"),
                    "timestamp": entry.get("timestamp"),
                    "message": message,
                    "description": (
                        f"{subject} had {n} packets blocked inside "
                        f"{BURST_WINDOW}s that were addressed to this host. "
                        f"One block is the firewall doing its job; a run of "
                        f"them from one address is that address probing. "
                        f"The multicast housekeeping Linux drops by design is "
                        f"excluded from this rule."),
                })

    if "successful_login" in types:
        subject = _login_source(message)
        if subject:
            n = _burst(subject, _login_successes, _login_seen,
                       event_now, BURST_LOGINS,
                       mark=_event_mark(subject, message, stamp))
            if n:
                out.append({
                    "type": "login_burst_from_host",
                    "entity_type": "ip",
                    "entity_value": subject,
                    "ip_address": subject,
                    "burst_count": n,
                    "window_seconds": BURST_WINDOW,
                    "severity": "low",
                    "source": entry.get("source"),
                    "timestamp": entry.get("timestamp"),
                    "message": message,
                    "description": (
                        f"{n} successful logins from {subject} inside "
                        f"{BURST_WINDOW}s. Logins are ordinary and this is "
                        f"not an accusation; it is the shape that is worth "
                        f"knowing, because an automated login loop, a "
                        f"misconfigured client and a stolen key being used "
                        f"all look like this."),
                })

    if "group_membership_changed" in types:
        for account, group in _group_additions(message):
            if group.lower() not in PRIVILEGED_GROUPS:
                continue
            mark = _event_mark((account, group), "group", stamp)
            if mark is not None:
                if mark in _group_seen:
                    continue
                _group_seen[mark] = True
            out.append({
                "type": "privileged_group_added",
                "entity_type": "user",
                "entity_value": account,
                "username": account,
                "group": group,
                "severity": "high",
                "source": entry.get("source"),
                "timestamp": entry.get("timestamp"),
                "message": message,
                "description": (
                    f"The account {account} was added to the {group} group. "
                    f"Members of {group} can become root or read what root "
                    f"reads, so this is a change in who controls the machine. "
                    f"Expected when an administrator did it on purpose; if "
                    f"nobody did, it is how an intruder keeps access."),
            })

    if "kernel_taint" in types:
        module = _tainting_module(message)
        mark = _event_mark(module or "kernel", message, stamp)
        if mark is None or mark not in _taint_seen:
            if mark is not None:
                _taint_seen[mark] = True
            out.append({
                "type": "kernel_tainted",
                "entity_type": "file",
                "entity_value": f"module:{module}" if module else "kernel",
                "severity": "medium",
                "source": entry.get("source"),
                "timestamp": entry.get("timestamp"),
                "message": message,
                "description": (
                    (f"The kernel module {module} tainted the kernel: "
                     if module else "The kernel reports it is tainted: ")
                    + f"{message[:200]}\n\nAn out-of-tree or unsigned module "
                    f"runs with full kernel rights and is how rootkits load. "
                    f"Driver packages built locally (NVIDIA, VirtualBox and "
                    f"other DKMS modules) do this legitimately on every boot; "
                    f"dismiss this module if that is what it is."),
            })

    return out


_GROUP_ADD = (
    re.compile(r"add '([^']+)' to (?:shadow )?group '([^']+)'"),
    re.compile(r"user (\S+) added by \S+ to group (\S+)"),
)
_GROUP_SET = re.compile(r"members of group (\S+) set by \S+ to (\S*)")
_TAINT_MODULE = re.compile(
    r"^(?:[\w-]+:\s+)?([\w-]+): (?:loading out-of-tree module|module "
    r"verification failed|module license '[^']*' taints|module is from the "
    r"staging directory)")

_group_seen = {}                 # ((account, group), "group", stamp) -> True
_taint_seen = {}                 # (module, message, stamp) -> True


def _group_additions(message: str) -> list:
    """(account, group) pairs a group-change line adds, or []."""
    pairs = []
    for rx in _GROUP_ADD:
        for m in rx.finditer(message or ""):
            pairs.append((m.group(1), m.group(2)))
    m = _GROUP_SET.search(message or "")
    if m:
        for account in filter(None, m.group(2).split(",")):
            pairs.append((account, m.group(1)))
    return [(a, g) for a, g in pairs if _looks_like_account(a)]


def _tainting_module(message: str) -> str:
    """The module a taint line names, or ''."""
    m = _TAINT_MODULE.search(message or "")
    return m.group(1) if m else ""


# One failed attempt writes several lines: sshd's "Invalid user", pam_unix's
# "authentication failure" and sshd's "Failed password". Counting all three
# fired brute force after two real attempts (EM3-3), so one line per attempt
# counts: sshd's "Failed <method> for", login's "FAILED LOGIN", and for every
# other service the pam failure line.
_SSHD_ATTEMPT = re.compile(r"^Failed \S+ for ")


def _counts_as_login_attempt(entry: dict) -> bool:
    """Is this failed_login line the one line that counts for its attempt?"""
    if entry.get("source") == "btmp":
        # The same attempts are already counted from the text logs; btmp
        # counts only when no text auth log could be read this poll.
        return bool(entry.get("count_attempt"))
    service = (entry.get("service") or "").lower()
    message = entry.get("message") or ""
    if service.startswith("sshd"):
        return bool(_SSHD_ATTEMPT.search(message))
    if service == "login":
        return "FAILED LOGIN" in message
    return "authentication failure" in message.lower()


def _check_brute_force(source_key: str, timestamp: float,
                       mark=None) -> dict | None:
    """
    One failed login, against a threshold and a window.

    Returns a finding if the threshold is cleared, else None. `source_key` is
    an address when the log carried one and an account when it did not, which
    is EM-3's fix: the audit measured 662 failed logins in the owner's store
    and NOT ONE carried an address, so a check keyed on ip_address alone could
    never fire on this host. The Windows twin already keys on
    `src_ip or username or "unknown"` and this is that.

    `mark` names the line (key, message, stamp) so a re-read or a copy from
    the other source is not counted again; the window is sorted by the
    event's own time, since sources arrive interleaved.
    """
    if mark is not None:
        if mark in _failed_login_seen:
            return None
        _failed_login_seen[mark] = True
        if len(_failed_login_seen) > _BURST_MARKS_MAX:
            for k in list(_failed_login_seen)[:len(_failed_login_seen)
                                              - _BURST_MARKS_MAX]:
                del _failed_login_seen[k]

    dq = _failed_logins[source_key]
    dq.append(float(timestamp))
    newest = max(dq)
    kept = sorted(t for t in dq if t >= newest - FAILED_LOGIN_WINDOW)
    dq.clear()
    dq.extend(kept)

    if len(_failed_logins[source_key]) >= FAILED_LOGIN_THRESHOLD:
        count = len(_failed_logins[source_key])
        entity_type = "ip" if _looks_like_ip(source_key) else "user"
        finding = {
            "type": "brute_force_detected",
            "entity_type": entity_type,
            "entity_value": source_key,
            "attempt_count": count,
            "window_seconds": FAILED_LOGIN_WINDOW,
            "severity": "high",
            "description": (f"{count} failed logins for {source_key} inside "
                            f"{FAILED_LOGIN_WINDOW}s"),
        }
        if entity_type == "ip":
            finding["ip_address"] = source_key
        else:
            finding["username"] = source_key
        # Cleared so the NEXT burst is its own finding rather than a count
        # that only ever grows. The Windows twin does the same.
        _failed_logins[source_key].clear()
        return finding

    return None


# CATEGORISING

def _categorize_entry(entry: dict) -> list:
    """
    Categorize a log entry by type. Returns [(event_type, severity), ...].

    THE SOURCE TEST IS AN EXACT ONE NOW. It was `any(s in source ...)`, a
    substring test against a source string that itself differed by entry
    point ("auth.log" from the file reader, "auth" from search_logs), so it
    matched by luck and would have matched "auth" inside anything. Canonical
    names (see LOG_CANDIDATES) make membership the right test.

    EM2-1, MEASURED 2026-09-25: THE PREFIX CLIFF, AND IT KILLED THREE RULES
    The patterns are matched against entry["message"]. SEVERAL OF THEM ARE
    WRITTEN AS "<service>: ..." AND _parse_syslog_line RETURNS THE SERVICE
    SEPARATELY FROM THE MESSAGE -- so the day the parser landed (2026-09-23,
    EM-4: "the parser reads what this host writes"), those patterns stopped
    being able to match ANY line, silently. A detector that cannot fire reads
    exactly like a detector with nothing to say, which is this project's
    most-repeated lesson.

    MEASURED on this host, whole live logs, matched against `message` (the
    shipped haystack) versus the WHOLE LINE (the haystack before the parser
    fix):

        sudo_usage      message    0   whole line   66
        kernel_issue    message    0   whole line   42
        cron_execution  message    0   whole line  150
        service_started message  528   whole line  838
        service_failed  message   29   whole line   45

    A live example of each dead pattern, from auth.log/syslog (account and
    host placeholders; the real lines are on the machine this was measured
    on):

        2026-09-23T01:15:26... host sudo:    <account> : PWD=... COMMAND=/usr/bin/mint-refresh-cache
        2026-09-23T12:50:11... host kernel: ACPI BIOS Error (bug): Could not resolve symbol ...
        2026-09-23T00:17:01... host CRON[122339]: (root) CMD (cd / && run-parts --report ...)

    THE REASON IT IS INVISIBLE IN THE STORE: the parser landed at 23:19 on
    2026-09-23, and the last row of each of those three categories is
    23:19:47 / 23:18:31 / 23:19:52 -- the minutes BEFORE it. The three
    categories have not been able to fire since, while auditd, cron and sudo
    kept writing to the logs the whole time.

    THE FIX. The haystack is built ONCE, per entry, by a helper that states
    its own rule: the message is the subject, and where a pattern names a
    service that the parser has already taken OUT of the message, the parsed
    service field is put back in front of it. That is deliberately NOT "match
    the whole raw line", which is what AR-1 was about: a whole-line match puts
    the timestamp, the hostname and every other field into the haystack, so
    `kernel:.*error` starts matching a line that merely CONTAINS those words.

    The three rules whose patterns name a service are marked with
    `"haystack": "line_prefix"` in WATCHED_PATTERNS, which is a DECLARATION of
    what the pattern needs rather than a second matching implementation, and
    _pattern_haystack is the one place that reads it.
    """
    if (entry or {}).get("preset_categories"):
        # A binary login record says what it is; there is no text to match.
        return list(entry["preset_categories"])
    entry = dict(entry or {})
    message = (entry.get("message") or "").lower()
    raw = entry.get("raw") or ""
    source = entry.get("source", "")
    service = (entry.get("service") or "")
    pid = entry.get("pid")
    categories = []

    # THE HAYSTACKS
    #
    # "message" is what this file has always searched and it is still the
    # default. "line_prefix" is message with the parsed service (and its pid,
    # when the line carried one) restored in front of it, in the same shape
    # the raw line had: "CRON[122339]: (root) CMD (...)". The trailing
    # newline-free form matters, because the patterns are anchored with \\[.
    prefix = ""
    if service:
        prefix = f"{service}[{pid}]: " if pid else f"{service}: "
    entry["_haystack"] = {
        "message": message,
        "line_prefix": (prefix + message).lower(),
        # Kept for a pattern that genuinely needs the whole line, and NOT
        # used by any pattern today. A whole-line haystack is the AR-1 trap:
        # 151 of 151 findings were false because a two-letter pattern was
        # searched against everything on the line.
        "raw": raw.lower(),
    }

    facility = str(entry.get("facility") or "")
    for event_type, config in WATCHED_PATTERNS.items():
        if source not in config["sources"]:
            continue
        # A journald line from outside auth/authpriv is not a login, however
        # it is worded.
        if config.get("auth") and source == "journald" and facility \
                and facility not in AUTH_FACILITIES:
            continue
        haystack = entry["_haystack"].get(config.get("haystack", "message"),
                                          message)
        for pattern in config["patterns"]:
            if re.search(pattern, haystack, re.IGNORECASE):
                if any(re.search(x, haystack, re.IGNORECASE)
                       for x in config.get("exclude", ())):
                    break
                categories.append((event_type, config["severity"]))
                break

    for cat in _msgid_categories(entry):
        if cat[0] not in {c[0] for c in categories}:
            categories.append(cat)
    return categories


# ONE POLL

def _dedupe_across_paths(entries: list) -> tuple:
    """
    (kept, also_seen) for entries that are one real event seen by two paths.

    EM-8: the same line reaches this sensor through journald AND through the
    file, and kern.log and syslog both carry the kernel's own messages. The
    store held 17,182 (minute, message) groups where ONE message sat under two
    source values, and each copy was then re-stored on every poll.

    THE WINNER IS THE FILE WHEN A FILE SAW IT, and that is a decision rather
    than taste: the file line is what the operator's existing rows are, and
    the store's own history (auth.log 213,384 rows, journald 25,808) is mostly
    file-derived. Journald wins only when it is the only path that has it.

    THE KEY IS (message, second) WITH A ONE-SECOND TOLERANCE, because the
    journal's clock and rsyslog's clock are two clocks: measured on this host,
    53 of one poll's rows sat in both sources at the same (message, second),
    and the journal's own copy of an event can land a second either side of
    the file's. The tolerance is only applied ACROSS sources: two lines one
    second apart in the SAME file are two lines, not one.

    THE LOSERS ARE NAMED ON THE WINNER, in `also_seen_via`, rather than
    dropped without a trace. That is the difference between "this event was
    seen once" and "this event was seen once and the journal agrees", and it
    is the second one that is true.
    """
    def _rank(entry):
        src = entry.get("source") or ""
        try:
            return SOURCE_ORDER.index(src)
        except ValueError:
            return len(SOURCE_ORDER)

    owner = {}                          # (message, second) -> index of the row
    drops = set()
    also_seen = defaultdict(set)

    for idx, entry in enumerate(entries):
        msg = entry.get("message") or ""
        sec = entry.get("timestamp") or ""
        source = entry.get("source") or ""

        candidate = owner.get((msg, sec))
        if candidate is not None and entries[candidate].get("source") == source:
            # Same path, same message, same second: rsyslog wrote the same
            # line twice and they are two lines.
            candidate = None
        if candidate is None:
            for alt in _adjacent_seconds(sec):
                cand = owner.get((msg, alt))
                if cand is not None and entries[cand].get("source") != source:
                    candidate = cand
                    break

        if candidate is None:
            owner[(msg, sec)] = idx
            continue

        keep, drop = ((candidate, idx)
                      if _rank(entries[candidate]) <= _rank(entry)
                      else (idx, candidate))
        owner[(msg, sec)] = keep
        if drop == candidate:
            # The earlier row loses: every key it owned now belongs to the
            # winner, and so does everything the winner had already absorbed.
            for k, v in list(owner.items()):
                if v == drop:
                    owner[k] = keep
            also_seen[keep] |= also_seen.pop(drop, set())
        drops.add(drop)
        also_seen[keep].add(entries[drop].get("source"))

    kept = []
    for idx, entry in enumerate(entries):
        if idx in drops:
            continue
        extra = sorted(s for s in also_seen.get(idx, set()) if s)
        if extra:
            entry["also_seen_via"] = extra
        kept.append(entry)
    return kept, also_seen


def _adjacent_seconds(stamp: str) -> list:
    """The second before and after a "%Y-%m-%d %H:%M:%S" stamp, as strings."""
    try:
        dt = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return []
    from datetime import timedelta
    return [(dt + timedelta(seconds=d)).strftime("%Y-%m-%d %H:%M:%S")
            for d in (-1, 1)]


def monitor_once(markers: dict = None, sources: list = None,
                 budget: int = None) -> dict:
    """
    Run event monitoring once and return results.

    `markers` IS THE CURSOR and it is passed IN, not stored here: the module
    holds no database handle, so the adapter loads it and persists what comes
    back in result['markers']. A caller that passes nothing gets a first run
    for every source, which is what the standalone entry points want
    (scripts/test_all_sensors.py drives this function with no arguments).

    `budget` is how many records this poll may hand back, DIVIDED ACROSS the
    sources. The cursor only ever advances past records the caller received:
    a source that hit its share stops where it stopped and the rest are read
    next poll. See EVENT_RETURN_CAP for why the two numbers are one number.

    Returns the same keys it always did, plus:
        markers        what to persist, per source
        gaps           coverage holes the ADAPTER must write as event_log_gap
        read_failures  source -> why its last read failed
        config         the block actually in force
        unregistered_sources  configured names this host does not offer
        sources_read   every source this poll reported on, including the
                       ones that read nothing
        first_run_sources  sources that adopted the newest window this poll
    """
    if sources is not None:
        _config["sources"] = [str(s).strip() for s in sources if str(s).strip()]
    markers = dict(markers or {})

    start_time = time.time()
    events = []
    gaps = []
    failures = {}

    log_paths = _get_log_file_paths()
    login_files = LOGIN_RECORD_FILES if _config.get("login_records", True) else {}
    read_sources = sorted(list(log_paths.keys()) + list(login_files))
    cap = per_source_cap(len(read_sources)) if budget is None else \
        max(1, int(budget) // max(1, len(read_sources)))

    # journald
    if "journald" in log_paths:
        jd = _read_journald_lines(markers.get("journald"), lines=cap)
        if jd.get("error"):
            failures["journald"] = jd["error"]
            logger.warning(f"Event monitor: journald read failed: {jd['error']}")
        if jd.get("gap"):
            gaps.append(jd["gap"])
        events.extend(jd["entries"])
        markers["journald"] = jd["marker"]
        _report_progress("journald", len(jd["entries"]), jd.get("remaining", 0),
                         error=jd.get("error"))

    # the files
    for name, path in log_paths.items():
        if path is None:
            continue
        r = _read_log_file_lines(path, markers.get(name), lines=cap)
        if r.get("error"):
            failures[name] = r["error"]
            logger.warning(f"Event monitor: {name} read failed: {r['error']}")
        if r.get("gap"):
            gaps.append(r["gap"])
        events.extend(r["entries"])
        markers[name] = r["marker"]
        _report_progress(name, len(r["entries"]), r.get("remaining", 0),
                         error=r.get("error"), floor=r.get("floor", False))

    # binary login records (EM3-7)
    auth_text_read = any(n in log_paths and n not in failures
                         for n in ("auth.log", "secure", "authorization", "journald"))
    for name, path in login_files.items():
        r = _read_login_records(path, name, markers.get(name), cap)
        # A permission refusal is a stated limit (btmp is root:utmp), not a
        # stalled source; any other error is reported like a text log's.
        refused = bool(r.get("error")) and "cannot read" in r["error"]
        _login_record_state[name] = r.get("error") or "read"
        if r.get("error"):
            failures[name] = r["error"]
            if _login_record_warned.get(name) != r["error"]:
                logger.warning(f"Event monitor: {name}: {r['error']}")
                _login_record_warned[name] = r["error"]
        elif r.get("gap"):
            gaps.append(r["gap"])
        if name == "btmp" and not auth_text_read:
            for e in r["entries"]:
                e["count_attempt"] = True
        events.extend(r["entries"])
        if not r.get("error"):
            markers[name] = r["marker"]
        _report_progress(name, len(r["entries"]), r.get("remaining", 0),
                         error=None if refused else r.get("error"))

    # one event, one row (EM-8)
    events, _also = _dedupe_across_paths(events)

    # categorise, and build the finding list
    stored = []
    findings = []
    skipped = 0

    for entry in events:
        try:
            _process_entry(entry, stored, findings)
        except Exception as e:                                # noqa: BLE001
            # One unreadable line costs itself, never the poll: a poll that
            # raises never saves its cursor and re-reads the same line forever.
            logger.warning(f"Event monitor: skipped one {entry.get('source')} "
                           f"entry that could not be processed: "
                           f"{type(e).__name__}: {e}")
            skipped += 1

    elapsed = time.time() - start_time
    result = _finish_poll(events, stored, findings, gaps, failures, markers,
                          read_sources, sources, elapsed)
    result["entries_skipped"] = skipped
    return result


def _process_entry(entry: dict, stored: list, findings: list) -> None:
    """Categorise one entry, store it, and add whatever findings it raises."""
    if _is_duplicate(entry):
        return

    categories = _categorize_entry(entry)
    fields = _extract_fields(entry)

    # The entry carries its own category, so a stored event says what it was.
    entry["type"] = categories[0][0] if categories else "log_entry"
    entry["severity"] = categories[0][1] if categories else "info"
    entry["matched_categories"] = [c[0] for c in categories]
    entry.update({k: v for k, v in fields.items() if k not in entry})
    stored.append(entry)

    for event_type, severity in categories:
        finding = {
            "type": event_type,
            "severity": severity,
            "timestamp": entry.get("timestamp"),
            "source": entry.get("source"),
            "message": entry.get("message"),
            **fields,
        }

        # Keyed on an address, or an account when the line has none (EM-3).
        # Only one line per real attempt counts, on the event's own clock,
        # and a re-read line is not counted twice (EM3-3).
        if event_type == "failed_login" and _counts_as_login_attempt(entry):
            key = fields.get("ip_address") or fields.get("username")
            if key:
                stamp = (entry.get("timestamp")
                         if entry.get("time_basis") == "event" else None)
                brute_force = _check_brute_force(
                    key, _event_seconds(entry) or time.time(),
                    mark=_event_mark(key, entry.get("message"), stamp))
                if brute_force:
                    findings.append(brute_force)

        findings.append(finding)

    # Once per entry, outside the category loop, so a line matching two
    # categories cannot count twice toward a burst.
    findings.extend(_shape_findings(entry, categories, fields, time.time()))


def _finish_poll(events, stored, findings, gaps, failures, markers,
                 read_sources, sources, elapsed) -> dict:
    """The drain accounting and the result dict for one poll."""
    # THE DRAIN ACCOUNTING
    #
    # Sources that were configured but did NOT report are a fault, and the
    # only way to see one is to compare the configured list against the
    # reported one. The 2026-09-21 version could not: it iterated what it had
    # read. It is checked here, and it is checked on the CONFIGURED list, so a
    # source that failed to appear at all still gets a line.
    for name in (sources or _config.get("sources") or []):
        if name not in _drain_remaining and name not in ("journald",):
            _report_progress(name, 0, 0,
                             error="this source was configured and did not "
                                   "report at all")

    # A GAP IS SAID OUT LOUD IN THE LOG TOO
    #
    # The row the adapter writes is what the model reads; this line is what the
    # operator reads, and a coverage hole that only exists in a table nobody
    # has queried yet is the failure the Windows twin's _report_gap comment
    # names. `_gaps_this_run` is published in get_status() so the readiness
    # page can see the same fact.
    for gap in gaps:
        _gaps_this_run.append(gap)
        logger.warning(
            f"Event monitor: {gap['source']} COVERAGE GAP - {gap['reason']}"
            + (f" ({gap['count']} record(s))" if gap.get("count") else ""))

    truncated_total = max(0, len(stored) - EVENT_RETURN_CAP)
    _remember_previous_drain()

    by_source = defaultdict(int)
    for entry in events:
        by_source[entry.get("source", "unknown")] += 1

    by_type = defaultdict(int)
    for finding in findings:
        by_type[finding["type"]] += 1

    result = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "event_count": len(events),
        "finding_count": len(findings),
        "by_source": dict(by_source),
        "findings_by_type": dict(by_type),
        "findings": findings,
        # THE EVENTS THEMSELVES. This returned counts and findings and threw
        # the entries away, so nothing could store them and the events table
        # stayed empty no matter how much was read.
        "events": stored[:EVENT_RETURN_CAP],
        "events_truncated": truncated_total,
        "elapsed_seconds": elapsed,
        "searched": True,
        # THE CURSOR, THE GAPS AND THE FAILURES
        "markers": markers,
        "gaps": gaps,
        "read_failures": dict(failures),
        "sources_read": read_sources,
        "unregistered_sources": _unknown_sources(),
        "config": config_in_force(),
        # A first run covers no history, and saying so is the difference
        # between "the log is quiet" and "we started watching here".
        "first_run_sources": sorted(
            name for name, m in markers.items()
            if isinstance(m, dict) and m.get("first_run")),
    }

    if findings or failures:
        logger.info(
            f"Event monitor: {len(events)} events read, {len(findings)} "
            f"finding(s) raised"
            + (f", {len(failures)} source(s) unreadable" if failures else ""))

    return result


def get_status() -> dict:
    """Get current event monitor status."""
    log_paths = _get_log_file_paths()
    journald_ok, journald_why = _journald_probe()

    available_sources = []
    unavailable_sources = []

    for log_type, log_path in log_paths.items():
        if log_type == "journald":
            if journald_ok:
                available_sources.append("journald")
            else:
                unavailable_sources.append("journald")
        elif log_path and log_path.exists():
            available_sources.append(f"{log_type} ({log_path})")
        else:
            unavailable_sources.append(log_type)

    can_read, read_why = _log_read_probe()

    return {
        "journald_available": journald_ok,
        # WHY, in the journal's own words. The old key was a boolean built
        # from `journalctl --version`, which is a statement about the binary
        # and not about this account's access (EM-9).
        "journald_probe": journald_why,
        "log_readable": can_read,
        "log_readable_reason": read_why,
        "log_files_available": available_sources,
        "log_files_unavailable": unavailable_sources,
        "cache_size": len(_seen_events),
        "tracked_ips": len(_failed_logins),
        # THE DRAIN, PUBLISHED AND NOW REAL. These two keys are the ones
        # core/settings._module_row has been reading since the tools/ pass and
        # NOTHING ON THIS SIDE PUBLISHED until 2026-09-21; they were published
        # and could only ever be empty until the cursor landed 2026-09-23.
        #
        # backlog is source -> records NOT YET READ. It is an EMPTY DICT when
        # nothing is behind, which is a reading, and the page treats it as
        # one: no backlog means caught up, not unknown. A figure that is a
        # floor (a very large unread tail) is named in backlog_is_a_floor.
        #
        # stalled NAMES THE SOURCES that are not moving: a figure that is not
        # going down, a source that has gone quiet for three intervals, or a
        # source whose last read FAILED. Never a boolean, so the page can say
        # which one.
        "backlog": {k: v for k, v in _drain_remaining.items() if v > 0},
        "backlog_is_a_floor": sorted(
            s for s in _drain_remaining
            if _drain_remaining.get(s, 0) > 0 and _drain_floor.get(s)),
        "stalled": _stalled_channels(),
        # A SOURCE THAT REFUSED A READ IS NOT A QUIET ONE. Named, with the
        # sentence its own read produced.
        "unreadable": dict(_read_failures),
        "gaps_this_run": len(_gaps_this_run),
        "config": config_in_force(),
        "unregistered_sources": _unknown_sources(),
        "login_records": dict(_login_record_state),
    }


# Which sources reported a backlog figure that is a floor rather than a count.
_drain_floor: dict = {}


def _note_backlog_floor(source: str, floor: bool) -> None:
    if floor:
        _drain_floor[source] = True
    else:
        _drain_floor.pop(source, None)


# SEARCHING THE LOGS, BY HAND AND BY THE MODEL (EM-10)
#
# This function had zero callers and the audit proved why that was lucky:
# search_logs("--version") ran GNU grep's own banner and returned it as four
# matching log entries, because the query went into `["grep", "-i", query,
# path]` unvalidated and grep ate the leading dash as an OPTION.
#
# There are two honest ways out of dead code with a live argument bug: delete
# it, or make it safe and give it a caller. It is wired to the model as
# `search_logs` because the capability is genuinely missing (the register's
# ABSENT list has no way to ask "what does this host's log say about X"), and
# the three faults are fixed rather than documented:
#
#   1. THE QUERY CANNOOT BE AN OPTION. It goes through `-e`, which is the
#      POSIX way to end option parsing, so a leading dash is data.
#   2. AN INVALID REGEX IS REFUSED, not silently empty. grep exits 2 on a bad
#      pattern and the old code read a non-zero return as "no matches", which
#      is the shape this project treats as the worst kind of quiet.
#   3. THE SOURCE NAMES ARE THE CANONICAL ONES, so a row found by searching
#      and a row found by reading carry the same source (EM-8).

class BadQuery(ValueError):
    """A search that cannot be run, with the reason a person can act on."""


MAX_SEARCH_PATTERN = 200

# HOW FAR BACK A JOURNALD SEARCH LOOKS, AND IT IS A REAL BOUND RATHER THAN
# TIDINESS. `journalctl --grep` walks the journal from the end looking for a
# match, and MEASURED on this host a pattern that matches nothing took the
# whole 30 second timeout and then gave up: the search had to scan everything
# before it could answer "no". A bounded window answers the same question in a
# second and says in the result which window it answered over, so "no matches"
# is a statement about a period rather than about all time.
SEARCH_WINDOW_DEFAULT = "-24h"


def _validate_query(query: str) -> str:
    """
    The pattern, or BadQuery. Never returns something grep could read as a flag.
    """
    if not isinstance(query, str) or not query.strip():
        raise BadQuery("the search needs a pattern; it was empty")
    if len(query) > MAX_SEARCH_PATTERN:
        raise BadQuery(f"the pattern is longer than {MAX_SEARCH_PATTERN} "
                       f"characters, which is longer than any real log "
                       f"pattern and usually a sign it should be narrower")
    if query.lstrip().startswith("-"):
        raise BadQuery(
            f"{query!r} starts with a dash. A dash means an OPTION to the "
            f"search tool, so a pattern like '--version' would ask for the "
            f"search program's own version banner instead of reading this "
            f"host's logs. Write the pattern without the leading dash "
            f"(for example 'version') and it is searched for literally.")
    try:
        re.compile(query)
    except re.error as e:
        raise BadQuery(
            f"{query!r} is not a valid regular expression: {e}. As a plain "
            f"string it would match nothing, so it is refused rather than "
            f"answered with an empty list that reads as 'no matches'.")
    return query


def search_logs(query: str, lines: int = 100, sources: list = None,
                since: str = SEARCH_WINDOW_DEFAULT) -> list:
    """
    Search this host's logs for a pattern. Returns matching entries.

    Bounded, read-only, and it only ever reads the sources this sensor is
    configured for. `sources` narrows it further for one call. `since` is how
    far back the journald half looks (journalctl's own time syntax); the file
    half reads the file, which is already bounded by logrotate.
    """
    query = _validate_query(query)
    try:
        lines = max(1, min(int(lines), 500))
    except (TypeError, ValueError):
        lines = 100

    results = []
    wanted = set(sources) if sources else None
    log_paths = _get_log_file_paths()

    if "journald" in log_paths and (wanted is None or "journald" in wanted):
        cmd = ["journalctl", "--no-pager", "--output=json",
               f"--lines={lines}", "--grep", query]
        if since:
            cmd.append(f"--since={since}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=30)
            if result.returncode not in (0, 1):
                logger.warning(
                    f"Event monitor: journalctl search failed "
                    f"(rc={result.returncode}): "
                    f"{(result.stderr or '').strip()[:160]}")
            elif result.returncode == 0:
                for line in (result.stdout or "").strip().split("\n"):
                    if not line:
                        continue
                    try:
                        entry = _journald_entry(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                    entry["matched"] = True
                    results.append(entry)
        except subprocess.TimeoutExpired:
            # SAID, NOT SWALLOWED. A search that timed out has not answered
            # anything, and returning the file half's rows without saying so
            # would report a partial answer as a complete one.
            logger.warning(
                f"Event monitor: the journald search for {query!r} did not "
                f"finish within 30s, so ONLY the log files were searched "
                f"for this call. Narrow it with a shorter 'since' window.")
        except Exception as e:                                # noqa: BLE001
            logger.warning(f"Event monitor: journald search failed: {e}")

    for name, path in log_paths.items():
        if path is None:
            continue
        if wanted is not None and name not in wanted:
            continue
        try:
            # -e ends option parsing: THE FIX. The old call site passed the
            # pattern straight in, so "--version" was read as a flag.
            result = subprocess.run(
                # -m stops grep at the limit instead of returning a whole
                # log to be cut here (MS-3).
                ["grep", "-i", "-m", str(lines), "-e", query, str(path)],
                capture_output=True, text=True, timeout=30,
            )
        except Exception as e:                                # noqa: BLE001
            logger.warning(f"Event monitor: search of {name} failed: {e}")
            continue
        if result.returncode not in (0, 1):
            logger.warning(
                f"Event monitor: search of {name} failed "
                f"(rc={result.returncode}): "
                f"{(result.stderr or '').strip()[:160]}")
            continue
        for line in (result.stdout or "").split("\n")[:lines]:
            if not line.strip():
                continue
            parsed = _parse_syslog_line(line, name)
            if parsed:
                parsed["matched"] = True
                results.append(parsed)

    return results[:lines]
