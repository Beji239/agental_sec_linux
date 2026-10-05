# tools/linux_monitor.py
# AgentalSec V2, Linux remote monitor via SSH (Paramiko)
# Disabled by default in config. Enable with linux_monitor.enabled=true.
#
# CHANGES FROM PREVIOUS VERSION
#
# 1. Process matching is now exact-basename, not substring.
#    Old code did `if any(s in cmd for s in SUSPICIOUS_PROCESSES)` with "nc"
#    in the set, so every *-launcher process matched ("lau-NC-her"), along
#    with sync/async/vnc. That was the source of the bogus "high" findings.
#
# 2. Findings are aggregated, not emitted per log line.
#    Failed logins now increment a windowed counter and raise ONE finding at
#    threshold, the same way event_monitor handles Windows 4625.
#
# 3. Deduplication across polls.
#    Old code re-read `tail -n 200` every 120s and re-saved every matching
#    line every time. Line hashes are now tracked and persisted, so a given
#    log line is recorded once.
#
# 4. Dismissals are honoured.
#    Every check now guards with me.is_dismissed(). Previously nothing in
#    this module checked, so dismissed findings came back every poll forever.
#
# 5. Baselines persist across restarts.
#    passwd/sudoers hashes and the SUID list were in a plain dict, so every
#    restart re-seeded from current state, meaning a compromise that landed
#    while the monitor was down silently became the baseline. Now stored via
#    memory_engine preferences.
#
# 6. Expensive checks moved to a slow interval.
#    `find / -perm -4000` walked the entire remote filesystem every 2 minutes.
#    Now hourly, configurable via SLOW_CHECK_INTERVAL.
#
# 7. Crontab is diffed, not snapshotted.
#    Old code wrote a full snapshot event every poll (~720/day). Now only
#    writes when the hash changes.
#
# 8. Host key policy is configurable.
#    AutoAddPolicy accepts any key, so the monitoring channel itself was
#    MITM-able. Set strict_host_key=True (or linux_monitor.strict_host_key
#    in config.json) once you have connected at least once.

import hashlib
import json
import logging
import os
import re
import threading
import time
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    logger.warning("paramiko not available, Linux monitor disabled")

from core import memory_engine as me

# Fast checks: auth log, active sessions, process list
POLL_INTERVAL = 120

# Slow checks: crontab diff, passwd/sudoers diff, SUID scan.
# The SUID scan walks the whole remote filesystem, do not run it every poll.
SLOW_CHECK_INTERVAL = 3600

# Failed logins are aggregated rather than emitted one finding per line.
#
# These are DEFAULTS. main.py can override them per host from config.json, so
# different environments tune without touching code.
#
# Two tiers, so a serious burst reads louder than a mild one:
#   FINDING -> a finding worth showing (medium)
#   HIGH    -> the same, at high severity
# And a success from an IP that just failed this many times escalates on its
# own (see _track_success), because fails-then-in is the shape of a real break-in.
#
# THE NUMBERS CHANGED 2026-09-06, AND HERE IS WHY. They used to be 10 fails
# in 60 seconds for a medium and 20 for a high, which was a guess made before
# anything had been measured on a real host.
#
# Then the re-test would not run. Kali could not even reach sshd, because
# fail2ban on that box had banned it during the LAST test and the ban
# outlived the session. Once it was stopped for the run, our detector fired
# correctly at 10 in 60 seconds.
#
# So the measurement is: that host bans a source at 5 failures inside 10
# minutes, which is fail2ban's own default and therefore what most defended
# Linux boxes do. Our old numbers sat ABOVE that in count and BELOW it in
# time, so on any host running fail2ban the attacker was gone before we had
# seen enough, and a slow attacker, five tries spread over ten minutes, fell
# out of our 60 second window entirely. We would only ever have caught
# attacks on machines that do not defend themselves.
#
# Now: the same shape as fail2ban's default, 5 in 600 seconds, with a second
# tier at 10. A burst of ten in four seconds still trips both, because a
# short window is contained in a long one. A slow drip is caught too, which
# it was not before.
#
# THE COST, said plainly: five failures in ten minutes is also what a person
# with the wrong key looks like. That is a medium, which is a row in a queue,
# not an alarm, and the finding says what it rests on. Worth it, because the
# alternative is silence on exactly the hosts that are being attacked.
FAILED_LOGIN_WINDOW     = 600    # seconds, fail2ban's default findtime
FAILED_LOGIN_FINDING    = 5      # fails in the window -> finding (medium)
FAILED_LOGIN_HIGH       = 10     # fails in the window -> high
FAILED_THEN_SUCCESS_MIN = 5      # fails then a success from the same IP -> high

# fail2ban writes here. Same multi-source approach as the auth log, and for
# the same reason: the file exists on Debian and friends, the journal is the
# fallback, and a box may have either.
F2B_SOURCES = (
    "tail -n 200 /var/log/fail2ban.log 2>/dev/null",
    "journalctl -u fail2ban -n 200 --no-pager 2>/dev/null",
)

# NOTICE [sshd] Ban 192.0.2.69      /      NOTICE [sshd] Unban 192.0.2.69
_F2B_RE = re.compile(
    r"\[(?P<jail>[^\]]{1,40})\]\s+(?P<action>Ban|Unban)\s+"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})")

# The two shapes the line can start with:
#   2026-09-06 13:38:18,900 fail2ban.actions ...     the log file
#   Sep 06 13:38:18 box fail2ban.actions[1]: ...     the journal
_F2B_TS_FILE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
_F2B_TS_JOURNAL = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})")


def _f2b_time(line: str):
    """
    When a fail2ban line happened, as a local timestamp, or None.

    None is a real answer and the caller treats it as such. A format we
    cannot read must not silently become "now", because that turns a log
    full of old bans into a screen full of fresh findings, which is the
    thing this was written to stop.
    """
    m = _F2B_TS_FILE.match(line)
    if m:
        try:
            return time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            return None

    m = _F2B_TS_JOURNAL.match(line)
    if m:
        # The journal's own format carries no year. Assume the current one,
        # and if that lands in the future assume last year, which is the only
        # sane reading of a December line seen in January.
        try:
            now = time.localtime()
            parsed = time.strptime(f"{now.tm_year} {m.group(1)}",
                                   "%Y %b %d %H:%M:%S")
            stamp = time.mktime(parsed)
            if stamp > time.time() + 86400:
                parsed = time.strptime(f"{now.tm_year - 1} {m.group(1)}",
                                       "%Y %b %d %H:%M:%S")
                stamp = time.mktime(parsed)
            return stamp
        except ValueError:
            return None

    return None

# How many recent log-line hashes to remember (persisted across restarts).
SEEN_LINE_CAP = 500

# Exact executable basenames. Matched with == against os.path.basename(),
# never as a substring, that is what produced the *-launcher false positives.
SUSPICIOUS_PROCESS_NAMES = {
    "nc", "ncat", "netcat", "nc.traditional", "nc.openbsd",
    "meterpreter", "mimikatz",
    "cryptominer", "xmrig", "minerd", "cpuminer",
    "socat",
}

# A process merely *named* nc is a weak signal, plenty of legitimate scripts
# shell out to it. These argument patterns are what make it interesting.
SUSPICIOUS_ARG_PATTERNS = [
    re.compile(r"\s-[a-z]*e\b"),          # -e /bin/sh  (exec on connect)
    re.compile(r"\s-[a-z]*l[a-z]*p\b"),   # -lp / -lvp  (listener on a port)
    re.compile(r"/bin/(ba)?sh\b"),        # shell as payload
    re.compile(r"\bexec\s*[0-9]*<>/dev/tcp/"),  # bash reverse shell idiom
    re.compile(r"\bstratum\+tcp://"),     # mining pool
    re.compile(r"--donate-level\b"),      # xmrig
]

# Source IP out of an auth.log line
_IP_RE = re.compile(r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b")

# A successful login. We only act on it when the same IP was just hammering us,
# so this is how a brute force that finally got in gets caught. Our own poller
# logs in constantly too, but it never fails first, so it never trips this.
_ACCEPT_RE = re.compile(r"\bAccepted\b.+?\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b")


def _sha(text: str) -> str:
    """Short stable hash used for line-level dedup."""
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _sha_full(text: str) -> str:
    """Full sha256, the one the passwd and sudoers baselines use."""
    return hashlib.sha256(text.encode()).hexdigest()


# WHAT ACTUALLY CHANGED. Added 2026-09-21 after a real run.
#
# The owner changed /etc/passwd and the crontab on the Linux box themselves, and the
# Windows side caught both. Good. But the alert only said "the hash moved",
# so nobody, the owner or the model, could tell the owner's change from an attacker adding
# a user in the same minute. The two look identical when all you keep is
# a hash.
#
# So now we keep the last copy too and put the actual lines in the finding.
# Only for passwd, sudoers and crontab. Never /etc/shadow, that one holds
# password hashes and has no business sitting in our database.
#
# The failure path matters more than the happy one here. If there is no
# earlier copy (first change after this shipped), or the copy we have does
# not match the hash we alerted on, we SAY that. An empty diff must never
# read as "nothing changed".
DIFF_LINE_CAP = 20


def _what_changed(old_copy, baseline_hash, current: str, hash_fn) -> dict:
    """
    Compare the stored copy with what is on disk now.

    Returns a dict with diff_status, one of:
      shown               the lines are real, trust them
      no_earlier_copy     we never kept one, so we cannot say what changed
      earlier_copy_stale  the copy we kept is not the one the baseline hash
                          was taken from, so a diff against it would lie
    """
    if not isinstance(old_copy, str):
        return {
            "diff_status": "no_earlier_copy",
            "added": [], "removed": [],
            "note": ("No earlier copy was kept, so I cannot show what changed. "
                     "Only the hash moved. Check the file on the host."),
        }
    if hash_fn(old_copy) != baseline_hash:
        return {
            "diff_status": "earlier_copy_stale",
            "added": [], "removed": [],
            "note": ("The earlier copy I kept does not match the baseline hash, "
                     "so a diff against it would be wrong. Check the file on "
                     "the host."),
        }

    old_lines = old_copy.splitlines()
    new_lines = current.splitlines()
    old_set, new_set = set(old_lines), set(new_lines)
    added   = [l for l in new_lines if l not in old_set]
    removed = [l for l in old_lines if l not in new_set]

    cut = len(added) > DIFF_LINE_CAP or len(removed) > DIFF_LINE_CAP
    note = f"{len(added)} line(s) added, {len(removed)} removed."
    if not added and not removed:
        # Same lines, different order or whitespace. Still a real change.
        note = "No line was added or removed, the order or spacing changed."
    if cut:
        note += f" Only the first {DIFF_LINE_CAP} of each are shown."
    return {
        "diff_status": "shown",
        "added": added[:DIFF_LINE_CAP],
        "removed": removed[:DIFF_LINE_CAP],
        "note": note,
    }


def _diff_text(diff: dict) -> str:
    """One readable block for the finding description."""
    if diff["diff_status"] != "shown":
        return diff["note"]
    parts = [diff["note"]]
    parts += [f"+ {l}" for l in diff["added"]]
    parts += [f"- {l}" for l in diff["removed"]]
    return "\n".join(parts)


class LinuxMonitor:

    def __init__(
        self,
        session_id: str,
        host: str,
        user: str,
        key_path: str,
        port: int = 22,
        strict_host_key: bool = False,
        failed_login_window: int = FAILED_LOGIN_WINDOW,
        failed_login_finding: int = FAILED_LOGIN_FINDING,
        failed_login_high: int = FAILED_LOGIN_HIGH,
        failed_then_success_min: int = FAILED_THEN_SUCCESS_MIN,
    ):
        self.session_id      = session_id
        self.host            = host
        self.user            = user
        self.key_path        = key_path
        self.port            = port
        self.strict_host_key = strict_host_key

        # Brute-force thresholds, overridable per host from config.
        self.win       = int(failed_login_window)
        self.t_finding = int(failed_login_finding)
        self.t_high    = int(failed_login_high)
        self.t_fts     = int(failed_then_success_min)

        self._running = False
        self._thread  = None

        # Per-source brute-force state: {ip: {"hits":[ts], "finding":bool, "high":bool}}
        # We keep the failure timestamps in the window plus which tiers we have
        # already reported, so a running attack raises each tier once, not one
        # finding every poll. When the window goes quiet the tiers re-arm.
        self._bf = defaultdict(lambda: {"hits": [], "finding": False, "high": False})

        # LOG INTAKE HEALTH, added 2026-09-04.
        # A host can log SSH auth to /var/log/auth.log, /var/log/secure, or the
        # journal under "sshd" or (OpenSSH 9.8+) "sshd-session", depending on the
        # distro and how sshd was started. The old code only tried auth.log then
        # `journalctl -u ssh`, and when both missed it read nothing and SAID
        # nothing, so a host with dead log intake looked exactly like a quiet,
        # safe host. Now we remember the source that last worked and shout when
        # every source is empty on a host we can otherwise reach.
        self._log_source     = None
        self._log_blind      = False
        self._log_blind_since = None

        # DOES THIS HOST DEFEND ITSELF, added 2026-09-06. None means we have
        # not looked yet, which is not the same as no.
        #
        # This matters for reading our own silence. On a host running
        # fail2ban, an attacker is banned after a handful of tries, so the
        # failed-login count we see is the count BEFORE the ban, not the
        # count the attacker intended. Without knowing that, "only five
        # failures" reads as a half-hearted attempt when it may be a
        # determined one that got shut down.
        self._f2b_present  = None
        self._f2b_source   = None
        self._f2b_bans     = 0

        # WHEN THIS MONITOR STARTED, and the first-read flag.
        #
        # THE BUG THIS FIXES, found on the first real run 2026-09-06. The
        # fail2ban reader tails the last 200 lines of a log that goes back
        # days, so its very first read raised THREE fresh medium findings for
        # bans from two days ago, two of which had already been lifted. That
        # is history reported as news, which is the same mistake as a scan
        # reporting a port it just went and looked at.
        #
        # Same shape as the SUID and crontab checks: the first read SEEDS.
        # Everything already in the log is recorded as an event, so it is on
        # the record and readable, and only bans that happen while we are
        # watching become findings.
        self._started_at   = time.time()
        self._f2b_seeded   = False

        # Recently-seen log line hashes, newest last. Persisted on update.
        self._seen_lines = deque(self._load_seen_lines(), maxlen=SEEN_LINE_CAP)
        self._seen_set   = set(self._seen_lines)

        # Timestamp of the last slow-check pass
        self._last_slow_check = 0.0

        # REACHABILITY, added 2026-09-03. See status() for why.
        self._last_ok             = None    # epoch of the last successful connect
        self._consecutive_fails   = 0
        self._last_error          = None
        # Epoch of the end of the last poll, so status can say when the next
        # one is due. A host you have just switched on is the case that needs
        # it: without a number there, waiting and being broken look the same.
        self._last_poll_at        = None

        # Remote package inventory. TODO 8.6.
        self._software            = None
        self._software_at         = 0.0

        # Application manifests, the things the package manager cannot see.
        # TODO 79, 2026-09-09.
        self._apps                = None
        self._apps_at             = 0.0

    # LIFECYCLE

    def start(self):
        if not PARAMIKO_AVAILABLE:
            return
        if not self.host:
            logger.info("LinuxMonitor: no host configured, skipping.")
            return
        self._running = True
        self._thread  = threading.Thread(
            target=self._poll_loop,
            name="LinuxMonitor",
            daemon=True,
        )
        self._thread.start()
        logger.info(f"LinuxMonitor started: {self.host}")

    def stop(self):
        self._running = False

    def status(self) -> dict:
        """
        Running is not the same as working, and this used to conflate them.

        FOUND 2026-09-03, from a log. The Linux box was switched off for
        about an hour. Every two minutes this module logged "SSH connect
        failed: timed out", and all that time status() reported
        running: True, because _running only ever meant "the thread is
        alive". So the one host with real endpoint visibility was completely
        unwatched and the dashboard said the sensor was fine.

        That is section 31 happening again in a new module. The event monitor
        tile got a backlog figure for exactly this shape of failure: a status
        that says running while nothing is getting through. A sensor that
        cannot see must say so, or its silence gets read as a quiet network.

        So: running still means the thread is alive, because that is a real
        thing worth knowing. reachable means we actually got a session. They
        are separate fields on purpose, and the UI reads the second one.
        """
        age = None if self._last_ok is None else int(time.time() - self._last_ok)

        if not (self._running and PARAMIKO_AVAILABLE):
            note = "Not running."
        elif self._last_ok is None:
            note = (f"Never connected to {self.host} since start. "
                    f"{self._consecutive_fails} attempt(s) failed. Nothing "
                    f"observed on this host at all, which is NOT the same as "
                    f"nothing happening on it.")
        elif self._consecutive_fails:
            note = (f"Last reached {self.host} {age}s ago, and the "
                    f"{self._consecutive_fails} attempt(s) since have failed. "
                    f"Anything on that host during this gap was not seen.")
        else:
            note = f"Reached {self.host} {age}s ago."

        # How to read our own numbers on this host. A defended box cuts an
        # attack off before our counters fill, so the count is a floor, not
        # a measurement of what was attempted.
        if self._f2b_present:
            note += (f" fail2ban is running there and has banned "
                     f"{self._f2b_bans} source(s) since this session started, "
                     f"so failure counts here are what happened before a ban, "
                     f"not the whole attempt.")
        elif self._f2b_present is False:
            note += (" No fail2ban on that host, so a failed login count is "
                     "the whole attempt rather than the part before a ban.")

        # Reachable but blind is its own alarm: the SSH channel is fine, the
        # logs are not. Say it loudly, ahead of the reachability note.
        if self._log_blind:
            note = (f"Reaching {self.host} is fine, but every SSH log source is "
                    f"empty, so login detection on it is BLIND. ") + note

        return {
            "running":         self._running and PARAMIKO_AVAILABLE,
            # Reachable is deliberately not a bool-with-no-third-state. None
            # means we have not tried yet, which is not the same as failing.
            "reachable":       None if self._last_ok is None and not self._consecutive_fails
                               else (self._consecutive_fails == 0),
            "host":            self.host,
            "paramiko":        PARAMIKO_AVAILABLE,
            "strict_host_key": self.strict_host_key,
            "last_success_age_seconds": age,
            "consecutive_failures":     self._consecutive_fails,
            # How long until it tries again. The dashboard shows this on a
            # failing row so that a box you have just turned back on gives
            # you something to wait for rather than a guess.
            "poll_interval_seconds":    POLL_INTERVAL,
            "next_poll_in_seconds":
                None if self._last_poll_at is None
                else max(0, int(POLL_INTERVAL - (time.time() - self._last_poll_at))),
            "last_error":               self._last_error,
            "log_source":      self._log_source,
            "log_blind":       self._log_blind,
            # None means we have not looked yet. False means we looked and
            # this host has no fail2ban, which changes how to read a quiet
            # log rather than being a problem in itself.
            "fail2ban":        self._f2b_present,
            "fail2ban_source": self._f2b_source,
            "bans_seen":       self._f2b_bans,
            "packages":       None if self._software is None else self._software["count"],
            "applications":   None if self._apps is None else len(self._apps),
            "note":            note,
        }

    # POLL LOOP

    def _poll_loop(self):
        while self._running:
            try:
                client = self._connect()
                if client is None:
                    # Recorded, not just logged. A failure that only reaches
                    # the log file is a failure the dashboard cannot show.
                    self._consecutive_fails += 1
                    self._last_error = "could not open an SSH session"
                else:
                    self._last_ok = time.time()
                    self._consecutive_fails = 0
                    self._last_error = None
                if client:
                    # S24, 2026-08-28. try/finally around the checks.
                    #
                    # client.close() sat only on the clean path. _run swallows
                    # its own exceptions, but me.save_event, me.save_finding
                    # and me.is_dismissed can all raise: SQLite lock
                    # contention against the packet flush, or save_finding's
                    # own severity ValueError. Any of those leaked a paramiko
                    # Transport thread and a socket, one per poll, 720 a day.
                    #
                    # The end state is the quiet kind. The monitoring host
                    # runs out of file descriptors, or the remote sshd hits
                    # MaxSessions and starts refusing, after which _connect
                    # returns None and this module logs a warning every two
                    # minutes and reports nothing at all about a host it is
                    # supposed to be watching.
                    try:
                        # Fast checks, every poll
                        self._check_auth_log(client)
                        self._check_fail2ban(client)
                        self._check_sessions(client)
                        self._check_processes(client)

                        # Slow checks, hourly. These are expensive on the
                        # remote host and their signals change infrequently.
                        now = time.time()
                        if now - self._last_slow_check >= SLOW_CHECK_INTERVAL:
                            self._check_crontab(client)
                            self._check_passwd_sudoers(client)
                            self._check_suid(client)
                            self._collect_software(client)
                            self._collect_manifests(client)
                            self._last_slow_check = now
                    finally:
                        try:
                            client.close()
                        except Exception:
                            pass
            except Exception as e:
                logger.error(f"LinuxMonitor poll error: {e}")
            # Stamped at the END of the poll, not the start, because that is
            # what the next sleep is measured from. During a slow poll the
            # countdown reads zero, which is true: it is trying right now.
            self._last_poll_at = time.time()
            time.sleep(POLL_INTERVAL)

    def _connect(self):
        try:
            client = paramiko.SSHClient()

            # Load known_hosts so previously-verified keys are trusted.
            try:
                client.load_system_host_keys()
            except Exception:
                pass

            if self.strict_host_key:
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
            else:
                # Trust-on-first-use. Flip strict_host_key to True in
                # config.json once the host key is in known_hosts.
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            client.connect(
                self.host,
                port=self.port,
                username=self.user,
                key_filename=self.key_path if self.key_path else None,
                timeout=10,
            )
            return client
        except paramiko.SSHException as e:
            logger.warning(f"LinuxMonitor SSH error ({self.host}): {e}")
            return None
        except Exception as e:
            logger.warning(f"LinuxMonitor SSH connect failed: {e}")
            return None

    # S23, 2026-08-28. A CEILING ON OUTPUT FROM THE MONITORED HOST.
    #
    # stdout.read() read to EOF with no size limit, and timeout=30 is the
    # channel's INACTIVITY timeout, so a host streaming continuously never
    # trips it.
    #
    # This module exists on the premise that the box at the other end might be
    # the compromised one. That box controls exactly what these commands
    # print. Replace `find`, or just make /var/log/auth.log enormous, and
    # `stdout.read()` accumulates gigabytes in the MONITORING host's memory,
    # after which _check_suid builds sorted(set(...)) on top of it. The
    # monitor dies, taking every other sensor thread with it, at the choosing
    # of the machine it was watching.
    #
    # 4 MB is far more than any of these commands legitimately produce: `find
    # / -perm -4000` on a real system is a few hundred lines.
    #
    # Truncation is logged rather than silent. Output that was cut is a fact
    # about the remote host, and on this module's own premise an unexplained
    # flood of output is itself the signal.
    MAX_CMD_OUTPUT = 4 * 1024 * 1024

    def _run(self, client, cmd: str) -> str:
        try:
            _, stdout, _ = client.exec_command(cmd, timeout=30)
            data = stdout.read(self.MAX_CMD_OUTPUT + 1)
            if len(data) > self.MAX_CMD_OUTPUT:
                logger.warning(
                    f"LinuxMonitor: {cmd.split()[0]!r} on {self.host} returned "
                    f"more than {self.MAX_CMD_OUTPUT} bytes and was truncated. "
                    f"That is far beyond what this command should produce and "
                    f"is worth investigating on the host itself."
                )
                data = data[:self.MAX_CMD_OUTPUT]
                try:
                    stdout.channel.close()
                except Exception:
                    pass
            return data.decode(errors="ignore").strip()
        except Exception:
            return ""

    # PACKAGE INVENTORY. TODO 8.6, built 2026-09-03.
    #
    # HOW THIS GOT NOTICED. Somebody asked about a CISA KEV entry for
    # LiteLLM, which is a Python service that lives on a Linux host. The
    # right next question is "do we run it anywhere", and the honest answer
    # was that this tool could not find out. tools/software_inventory.py has
    # dpkg, rpm and apk support and only ever inventories THE MACHINE IT RUNS
    # ON, which here is Windows. So there was Linux support in the codebase
    # and none of it pointed at the Linux box we actually monitor.
    #
    # A runbook is a list of priors. The only thing that turns a prior into
    # something useful is checking it against what is installed. Without this,
    # every KEV entry can only ever produce "worth a look", forever.
    #
    # WHAT IT DOES NOT SEE, and this matters more than what it does:
    #
    #   containers   dpkg on the host knows nothing about what is inside a
    #                docker image. A service running in a container is
    #                invisible here.
    #   venvs        a pip install into a virtualenv is not a system package.
    #                LiteLLM, the thing that prompted this, would live in
    #                exactly such a venv and would NOT show up below.
    #   pipx, npm,   same story, different package manager.
    #   snap, flatpak
    #
    # So a miss here is close to meaningless and the result says so in its
    # own note rather than leaving the model to remember. Getting that
    # backwards would be worse than not having the feature: "not in the
    # inventory" would start reading as "not installed".
    #
    # Runs on the SLOW timer, hourly, with the other expensive checks. A
    # package list does not change between two-minute polls.
    SOFTWARE_MAX_PACKAGES = 5000

    _SOFTWARE_SOURCES = (
        # THE STATUS FIELD IS ASKED FOR AND FILTERED, added 2026-09-26
        # (register section 12, SI-4's remote half). `dpkg-query -W` lists
        # every entry in the package database including `rc` ones -- removed
        # packages whose config files are still on disk -- so the remote
        # inventory published software the monitored host does not have.
        # Measured on the local copy of the same command: 2792 entries, 36
        # of them rc. The same fix landed in tools/software_inventory.py's
        # dpkg branch; a monitored host must not answer differently from
        # this one.
        ("dpkg", "dpkg-query -W -f='${binary:Package}\\t${Version}"
                 "\\t${Maintainer}\\t${db:Status-Abbrev}\\n' 2>/dev/null"),
        ("rpm",  "rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}"
                 "\\t%{VENDOR}\\n' 2>/dev/null"),
        ("apk",  "apk info -v 2>/dev/null"),
    )

    def _collect_software(self, client) -> None:
        """
        Fill self._software from whichever package manager answers.

        DEDUPED AND CUT-HONEST, 2026-09-26 (register section 12). Measured
        on a fixture: two identical lines produced two rows, and once the
        5000-row cap was reached the payload reported count AND total as
        5000 -- a cut list that reads as a complete machine. The local class
        path dedupes on (name, version); this now does the same, and a cut
        list keeps counting what it did not keep so the number it publishes
        is the host's, not the cap's.
        """
        for name, cmd in self._SOFTWARE_SOURCES:
            raw = self._run(client, cmd)
            if not raw:
                continue

            packages, seen, truncated = [], 0, False

            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                if name == "apk":
                    # apk prints name-version-release with no separator, so
                    # the version is whatever follows the last two dashes.
                    # Split from the right and do not pretend to more.
                    bits = line.rsplit("-", 2)
                    row = {
                        "name":      bits[0],
                        "version":   "-".join(bits[1:]) if len(bits) > 1 else "",
                        "publisher": "",
                    }
                else:
                    bits = line.split("\t")
                    if name == "dpkg":
                        if len(bits) < 4 or not bits[3].strip().startswith("ii"):
                            continue          # rc/iU/iF: not installed software
                    row = {
                        "name":      bits[0].strip(),
                        "version":   bits[1].strip() if len(bits) > 1 else "",
                        "publisher": bits[2].strip() if len(bits) > 2 else "",
                    }
                if any(p["name"].lower() == row["name"].lower()
                       and p["version"] == row["version"] for p in packages):
                    continue
                seen += 1
                if len(packages) >= self.SOFTWARE_MAX_PACKAGES:
                    truncated = True
                    continue
                packages.append(row)

            self._software = {
                "software":  packages,
                "count":     len(packages),
                "seen":      seen,
                "source":    f"{name}@{self.host}",
                "truncated": truncated,
                "errors":    [],
                "collected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._software_at = time.time()
            logger.info(f"LinuxMonitor inventory: {len(packages)} packages "
                        f"via {name} on {self.host}"
                        + (f" (of {seen}: the cap is "
                           f"{self.SOFTWARE_MAX_PACKAGES}, the rest were not "
                           f"kept)" if truncated else ""))
            return

        # Nothing answered. Say so rather than leaving a stale list in place.
        self._software = {
            "software": [], "count": 0, "source": f"none@{self.host}",
            "truncated": False,
            "errors": ["no dpkg, rpm or apk answered on this host"],
            "collected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._software_at = time.time()

    # APPLICATION MANIFESTS. TODO 79, built 2026-09-09.
    #
    # WHY. On a Magento KEV row the model reported that dpkg shows no Magento,
    # and then flagged its own answer as weak, because Composer deploys into a
    # web root and dpkg cannot see anything that arrives that way. It was
    # right, and the honest answer "dpkg cannot see there" is not the same
    # answer as "no".
    #
    # The gap was never PHP. It is that software inventory only ever asked the
    # package manager. A PHP investigator would answer PHP questions. Reading
    # the manifests those apps leave behind answers four ecosystems at once
    # and costs one hourly command.
    #
    # THE DISTINCTION THAT KEEPS THIS HONEST, and it is the whole design:
    #
    #   INSTALLED   a lock file, a pinned requirement, WordPress's own version
    #               file. This is what is actually on disk right now.
    #   DECLARED    composer.json "^2.4", package.json "~1.9". This is what
    #               somebody ASKED for. The resolved version can be anything
    #               inside that range, and on a box nobody has deployed to in
    #               a year it can be far from it.
    #
    # These are two different facts and they are kept in two different fields.
    # Collapsing them into one version number is how this feature would turn
    # into a confident liar, which is worse than the shrug it replaces.
    #
    # WHAT IT STILL DOES NOT SEE, said here so the note below can say it too:
    # anything inside a container, anything a deploy pipeline builds without
    # committing a lock file, and anything outside the roots searched. A hit
    # is evidence. A miss is still not.
    APP_MAX_FILES  = 40
    APP_MAX_BYTES  = 200_000
    APP_ROOTS      = "/var/www /srv /opt /usr/share/nginx /home"
    APP_MAX_DEPTH  = 6

    APP_MANIFESTS = (
        "composer.lock", "composer.json",
        "package-lock.json", "package.json",
        "requirements.txt", "wp-config.php",
    )

    # Pruned rather than searched. vendor and node_modules hold the installed
    # dependencies themselves, thousands of nested manifests belonging to
    # libraries and not to the application. An app that genuinely lives in a
    # folder called vendor will be missed, which is a trade made knowingly.
    APP_PRUNE = ("node_modules", "vendor", ".git", ".cache", "test", "tests")

    # Paths come back from a remote host and then go into a shell command, so
    # they are filtered to a conservative charset first. This is a security
    # tool; building a command out of unvalidated remote strings inside one
    # would be a poor advert for it.
    _APP_SAFE_PATH = re.compile(r"^[A-Za-z0-9/._@+-]{1,400}$")

    def _collect_manifests(self, client) -> None:
        """Fill self._apps from application manifests under the web roots."""
        prune = " -o ".join(f"-name {n}" for n in self.APP_PRUNE)
        names = " -o ".join(f"-name {n}" for n in self.APP_MANIFESTS)
        find_cmd = (
            f"find {self.APP_ROOTS} -maxdepth {self.APP_MAX_DEPTH} "
            f"\\( {prune} \\) -prune -o "
            f"-type f \\( {names} \\) -print 2>/dev/null | "
            f"head -n {self.APP_MAX_FILES}"
        )
        listing = self._run(client, find_cmd)
        paths = [p for p in (listing.splitlines() if listing else [])
                 if self._APP_SAFE_PATH.match(p.strip())]
        paths = [p.strip() for p in paths]

        if not paths:
            self._apps = []
            self._apps_at = time.time()
            return

        # One command for all of them rather than one SSH channel each. The
        # delimiter is printed by the remote shell, so a file whose own
        # content contains it would confuse the split. It is deliberately
        # long and unlikely, and a confused split costs a garbled entry, not
        # a wrong version number attached to a real app.
        cat_cmd = "; ".join(
            f"echo '===AGSEC-MANIFEST==={p}'; head -c {self.APP_MAX_BYTES} '{p}'; echo"
            for p in paths
        )
        blob = self._run(client, cat_cmd)

        apps = []
        for chunk in (blob.split("===AGSEC-MANIFEST===") if blob else []):
            if not chunk.strip():
                continue
            head, _, body = chunk.partition("\n")
            path = head.strip()
            if not path:
                continue
            try:
                apps.extend(self._parse_manifest(path, body))
            except Exception as e:
                logger.debug(f"LinuxMonitor: could not parse {path}: {e}")

        self._apps = apps
        self._apps_at = time.time()
        logger.info(f"LinuxMonitor manifests: {len(apps)} application(s) from "
                    f"{len(paths)} manifest file(s) on {self.host}")

    def _parse_manifest(self, path: str, body: str) -> list:
        """
        One manifest file to a list of application entries.

        Every entry says where it came from and whether the version is
        installed or merely declared. Nothing here guesses a version it was
        not given, and nothing here decides anything is vulnerable.
        """
        name = path.rsplit("/", 1)[-1]
        out  = []

        def add(pkg, version, kind, ecosystem):
            if not pkg:
                return
            out.append({
                "name":      str(pkg)[:200],
                "version":   str(version)[:100] if version else "",
                "evidence":  kind,          # installed or declared
                "ecosystem": ecosystem,
                "source":    path,
            })

        if name == "composer.lock":
            data = json.loads(body)
            for pkg in (data.get("packages") or []) + (data.get("packages-dev") or []):
                add(pkg.get("name"), pkg.get("version"), "installed", "php")

        elif name == "composer.json":
            data = json.loads(body)
            add(data.get("name"), data.get("version"), "declared", "php")
            for pkg, ver in (data.get("require") or {}).items():
                if pkg.lower() in ("php",) or pkg.startswith("ext-"):
                    continue
                add(pkg, ver, "declared", "php")

        elif name == "package-lock.json":
            data = json.loads(body)
            # npm lockfile v2 and v3 key by install path, v1 by name.
            for key, meta in (data.get("packages") or {}).items():
                if not key or not isinstance(meta, dict):
                    continue
                add(key.rsplit("node_modules/", 1)[-1],
                    meta.get("version"), "installed", "node")
            for pkg, meta in (data.get("dependencies") or {}).items():
                if isinstance(meta, dict):
                    add(pkg, meta.get("version"), "installed", "node")

        elif name == "package.json":
            data = json.loads(body)
            add(data.get("name"), data.get("version"), "declared", "node")
            for pkg, ver in (data.get("dependencies") or {}).items():
                add(pkg, ver, "declared", "node")

        elif name == "requirements.txt":
            for line in body.splitlines():
                line = line.split("#", 1)[0].strip()
                if not line or line.startswith("-"):
                    continue
                if "==" in line:
                    # Pinned. This is what will actually be installed.
                    pkg, _, ver = line.partition("==")
                    add(pkg.strip(), ver.strip(), "installed", "python")
                else:
                    for op in (">=", "<=", "~=", ">", "<"):
                        if op in line:
                            pkg, _, ver = line.partition(op)
                            add(pkg.strip(), op + ver.strip(), "declared", "python")
                            break
                    else:
                        add(line, "", "declared", "python")

        elif name == "wp-config.php":
            # The config file names no version. Its presence is the fact, and
            # the version lives in a sibling file that may or may not be
            # readable. Reporting WordPress with an empty version is honest;
            # inventing one from the config would not be.
            add("wordpress", "", "installed", "wordpress")

        return out

    def collect_applications(self, search: str = None) -> dict:
        """Applications found in manifests, kept separate from packages."""
        if self._apps is None:
            return {
                "applications": [], "count": 0, "total": 0, "host": self.host,
                "collected_at": None,
                "note": (f"No manifest scan has run against {self.host} yet. "
                         f"It runs on the hourly timer and needs one "
                         f"successful SSH session first."),
            }
        items = self._apps
        if search:
            needle = search.lower()
            items = [a for a in items if needle in a["name"].lower()]
        return {
            "applications": items[:500],
            "count":        len(items),
            "total":        len(self._apps),
            "host":         self.host,
            "collected_at": time.strftime("%Y-%m-%d %H:%M:%S",
                                          time.localtime(self._apps_at)),
            "note": (f"Applications on {self.host} read from their own "
                     f"manifest files, not from the package manager. Check "
                     f"the evidence field on every row before using it: "
                     f"'installed' comes from a lock file, a pinned "
                     f"requirement or the app's own version file and is a "
                     f"real version; 'declared' is a version RANGE somebody "
                     f"asked for in a config, and the version actually on "
                     f"disk can be anywhere inside it. Still blind to "
                     f"anything inside a container and anything outside the "
                     f"searched web roots. A hit is evidence. A miss is not."),
        }

    def collect_software(self, search: str = None) -> dict:
        """
        The same shape software_inventory.collect() returns, for this host.

        Read only, from the cache the poll loop fills. It does NOT reach out
        on demand: this is called from a model turn, and a turn should not
        block on an SSH round trip to a host that may be switched off.
        """
        if self._software is None:
            return {
                "software": [], "count": 0, "total": 0,
                "source": f"unknown@{self.host}",
                "truncated": False, "collected_at": None,
                "errors": ["no inventory collected yet"],
                "host": self.host,
                "note": (f"No package list has been collected from {self.host} "
                         f"yet. It runs on the hourly timer and needs one "
                         f"successful SSH session first. Check the module "
                         f"status: if the host is unreachable this is silence "
                         f"from a sensor, not an empty machine."),
            }
        data  = self._software
        items = data["software"]
        if search:
            needle = search.lower()
            items = [pkg for pkg in items
                     if needle in (pkg.get("name") or "").lower()
                     or needle in (pkg.get("publisher") or "").lower()]

        return {
            "software":     items,
            "count":        len(items),
            # `total` is what the HOST holds, not what was kept: a cut list
            # must not publish the cap as the machine's inventory (SI-5).
            "total":        data.get("seen", data["count"]),
            "source":       data["source"],
            "truncated":    data["truncated"],
            "collected_at": data["collected_at"],
            "errors":       data["errors"],
            "host":         self.host,
            "note": (f"System packages on {self.host}, from "
                     f"{data['source'].split('@')[0]}. Inventory only, no "
                     f"vulnerability matching happens here. IMPORTANT: this "
                     f"is the SYSTEM package manager. It does not see inside "
                     f"containers, virtualenvs, pipx, npm, snap or flatpak, "
                     f"so a service installed by pip into a venv is not "
                     f"listed and its absence here says nothing. A hit is "
                     f"evidence. A miss is not."
                     + (f" Application manifests were also read on this host "
                        f"and are in the 'applications' field below, which is "
                        f"where a Composer, npm, pip or WordPress install "
                        f"would show up. Read that before concluding an "
                        f"application is absent."
                        if self._apps else
                        f" No application manifests have been read on this "
                        f"host, so a Composer, npm, pip or WordPress install "
                        f"would be invisible to everything in this answer.")),
            # TODO 79. Carried here rather than behind a separate tool call,
            # because the question that needs it ("do we run X") is already
            # being asked of this answer, and a fact the model has to know to
            # go looking for is a fact it will not find.
            "applications": (self._apps or [])[:500],
            "applications_note": (
                "Read from manifest files, not from the package manager. "
                "evidence 'installed' is a real version from a lock file or "
                "pinned requirement. evidence 'declared' is a range somebody "
                "asked for, not what is on disk."),
        }

    # DEDUP + BASELINE PERSISTENCE

    def _pref_key(self, name: str) -> str:
        return f"linux_monitor:{self.host}:{name}"

    def _load_seen_lines(self) -> list:
        try:
            raw = me.get_preference(self._pref_key("seen_lines"), "[]")
            return json.loads(raw)
        except Exception:
            return []

    def _persist_seen_lines(self):
        try:
            me.set_preference(
                self._pref_key("seen_lines"),
                json.dumps(list(self._seen_lines)),
            )
        except Exception as e:
            logger.debug(f"Could not persist seen lines: {e}")

    def _is_new_line(self, line: str) -> bool:
        """True the first time a given log line is seen, False after."""
        h = _sha(line)
        if h in self._seen_set:
            return False
        if len(self._seen_lines) == self._seen_lines.maxlen:
            self._seen_set.discard(self._seen_lines[0])
        self._seen_lines.append(h)
        self._seen_set.add(h)
        return True

    def _get_baseline(self, name: str):
        raw = me.get_preference(self._pref_key(name), None)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    def _set_baseline(self, name: str, value):
        try:
            me.set_preference(self._pref_key(name), json.dumps(value))
        except Exception as e:
            logger.debug(f"Could not persist baseline {name}: {e}")

    def _host_dismissed(self) -> bool:
        try:
            return me.is_dismissed("ip", self.host)
        except Exception:
            return False

    # CHECKS

    # WHERE SSH AUTH ACTUALLY LANDS.
    #
    # There is no single answer across distros. Debian and Kali write
    # /var/log/auth.log, RHEL and its family write /var/log/secure, and a box
    # with no rsyslog logs only to the journal, where sshd shows up under the
    # identifier "sshd" or, on OpenSSH 9.8+, "sshd-session". So we try each in
    # turn and take the first that returns lines. journald is filtered by
    # identifier (-t), not unit (-u ssh), because the unit name is not reliable:
    # a custom-port sshd may not sit under a unit called ssh at all. That exact
    # gap is what left this monitor blind on a real box.
    _LOG_SOURCES = (
        "tail -n 500 /var/log/auth.log 2>/dev/null",
        "tail -n 500 /var/log/secure 2>/dev/null",
        "journalctl -t sshd -t sshd-session -n 500 --no-pager 2>/dev/null",
    )

    def _read_auth_lines(self, client):
        """
        Return (lines, source) from the first log source that yields anything.

        'anything' means any lines at all, not just failures. A source that
        returns lines but no failures is a working sensor on a quiet host. A
        source that returns nothing across every option is a BLIND sensor, and
        that is a different thing entirely, which _check_auth_log acts on.
        """
        for cmd in self._LOG_SOURCES:
            out = self._run(client, cmd)
            if out:
                return out.splitlines(), cmd
        return [], None

    def _check_auth_log(self, client):
        """
        Read new login lines once each, raise tiered brute-force findings, flag
        a success that follows a burst, and raise a health finding when no log
        source can be read at all.
        """
        if self._host_dismissed():
            return

        lines, source = self._read_auth_lines(client)

        if not lines:
            # Reached the host, saw no log lines from any source. Not 'quiet',
            # blind. Say so instead of silently reporting nothing.
            self._flag_log_blind()
            return
        self._clear_log_blind(source)

        new_lines = 0

        for line in lines:
            # A success only matters when this IP is mid-attack, so it is
            # checked before the failure filter would skip the line. An IP that
            # is not already failing, including our own poller logging in over
            # and over, is ignored here and never touches dedup or findings.
            acc = _ACCEPT_RE.search(line)
            if acc:
                ip = acc.group(1)
                if self._bf.get(ip, {}).get("hits") and self._is_new_line(line):
                    new_lines += 1
                    self._track_success(ip)
                continue

            if "Failed password" not in line and "Invalid user" not in line:
                continue
            if not self._is_new_line(line):
                continue

            new_lines += 1
            match  = _IP_RE.search(line)
            src_ip = match.group(1) if match else None

            # Individual lines are informational. The signal is the rate,
            # not any single failure.
            me.save_event(
                session_id=self.session_id,
                source="linux_monitor",
                event_id="SSH_FAIL",
                event_type="failed_login",
                severity="info",
                src_ip=src_ip,
                description=line[:300],
                raw_data={"host": self.host, "log_line": line},
            )

            if src_ip:
                self._track_failed_login(src_ip)

        self._prune_bf()

        if new_lines:
            self._persist_seen_lines()

    def _check_fail2ban(self, client):
        """
        Read fail2ban's own bans off the host, TODO 53.15, 2026-09-06.

        WHY THIS IS A SENSOR AND NOT A NICETY. A ban is a fact the host has
        already established, with its own evidence, and until now we were
        blind to it. Two things fall out of that:

        1. It is the strongest single signal on a defended box. "This host
           banned an address" is not our inference from a rate, it is the
           host saying it decided something.
        2. Without it, a host that banned an attacker at five tries and a
           host nobody touched produce the SAME quiet. That is the shape of
           mistake this project keeps finding: absence of a signal read as
           absence of an event.

        Read-only, and deliberately from the log rather than by running
        fail2ban-client, which needs root. We poll as an unprivileged user
        and that is worth keeping.
        """
        if self._host_dismissed():
            return

        lines, source = None, None
        for cmd in F2B_SOURCES:
            out = self._run(client, cmd)
            if out:
                lines, source = out.splitlines(), cmd
                break

        if not lines:
            # Not an alarm. Plenty of hosts do not run it, and saying so is
            # the point: it tells the reader how to weigh a quiet log.
            if self._f2b_present is None:
                self._f2b_present = False
                logger.info(f"LinuxMonitor: no fail2ban log on {self.host}. "
                            f"Nothing is banning sources there, so a failed "
                            f"login count is the whole attempt.")
            return

        self._f2b_present = True
        self._f2b_source  = source

        # An address unbanned AFTER a ban is not still banned. The catch is
        # the word AFTER. fail2ban's normal life on a host under repeated
        # attack is ban, unban when the time expires, ban the same source
        # again, over and over, so the last 200 lines are full of OLD unbans
        # of an address that is banned right now. The first version of this
        # kept a flat set of every unbanned address and skipped any ban whose
        # address was in it, with no regard for order, so those old unbans
        # suppressed the real standing ban. Live on 2026-09-06 the box was
        # actively banning the Kali box and we filed it as already lifted.
        #
        # So keep the NEWEST unban time per address, and later only skip a ban
        # that has an unban after it. A ban with no readable time still falls
        # back to the safe reading, any unban of it counts as lifting, because
        # we cannot order the two.
        last_unban = {}
        for line in lines:
            m = _F2B_RE.search(line)
            if m and m.group("action") == "Unban":
                w = _f2b_time(line)
                if w is None:
                    continue
                key = (m.group("jail"), m.group("ip"))
                if key not in last_unban or w > last_unban[key]:
                    last_unban[key] = w

        new_lines = 0
        seeding = not self._f2b_seeded
        for line in lines:
            m = _F2B_RE.search(line)
            if not m:
                continue
            if not self._is_new_line("f2b:" + line):
                continue

            new_lines += 1
            jail   = m.group("jail")
            action = m.group("action")
            ip     = m.group("ip")
            when   = _f2b_time(line)

            me.save_event(
                session_id=self.session_id,
                source="linux_monitor",
                event_id="F2B_" + action.upper(),
                event_type="host_ban" if action == "Ban" else "host_unban",
                severity="info",
                src_ip=ip,
                description=line[:300],
                raw_data={"host": self.host, "jail": jail, "action": action,
                          "banned_ip": ip, "log_line": line},
            )

            if action != "Ban" or me.is_dismissed("ip", ip):
                continue

            # HISTORY IS NOT NEWS. A ban from before this monitor started is
            # on the record as an event above, and that is where it belongs.
            # An unparseable timestamp counts as old only on the seeding
            # read, so a format we do not recognise costs one missed finding
            # rather than a permanently silent sensor.
            if when is not None:
                if when < self._started_at - 60:
                    continue
            elif seeding:
                continue

            # Lifted only if this address was unbanned AFTER this ban. An
            # older unban belongs to a previous ban of the same source and
            # says nothing about the one in front of us. If either side has no
            # readable time we cannot order them, so treat any unban as
            # lifting, which is the safe reading and matches the old behaviour.
            lu = last_unban.get((jail, ip))
            if lu is not None and (when is None or lu >= when):
                continue

            self._f2b_bans += 1
            me.save_finding(
                session_id=self.session_id,
                source="linux_monitor",
                detection_id="LNX-1001",
                severity="medium",
                entity_type="ip",
                entity_value=ip,
                title=f"{self.host} banned {ip} by itself",
                description=(
                    f"fail2ban on {self.host} banned {ip} in the {jail!r} "
                    f"jail. This is the HOST'S OWN decision, read out of its "
                    f"log, not our inference from a rate.\n\n"
                    f"Read it alongside any brute force finding for the same "
                    f"address: the ban stops the attempts, so our own failure "
                    f"count is what happened BEFORE the ban, not what the "
                    f"source intended. A low count next to a ban is not a "
                    f"half-hearted attempt.\n\n"
                    f"If this address is yours and the ban is a nuisance, it "
                    f"is lifted on the host itself, not from here. Nothing in "
                    f"AgentalSec can change fail2ban."
                ),
                raw_data={"host": self.host, "jail": jail, "banned_ip": ip,
                          "decided_by": "fail2ban on the monitored host",
                          "log_line": line},
            )

        self._f2b_seeded = True
        if new_lines:
            self._persist_seen_lines()

    def _track_failed_login(self, src_ip: str):
        """
        Windowed per-source counter with two tiers. Each tier fires once per
        burst, not once per poll. When the window goes quiet the tiers re-arm,
        so the next burst is reported fresh.
        """
        if me.is_dismissed("ip", src_ip):
            return

        now    = time.time()
        cutoff = now - self.win

        st = self._bf[src_ip]
        st["hits"] = [t for t in st["hits"] if t >= cutoff]
        if not st["hits"]:
            # The window emptied out. This is a fresh burst, re-arm the tiers.
            st["finding"] = False
            st["high"]    = False
        st["hits"].append(now)
        count = len(st["hits"])

        if count >= self.t_high and not st["high"]:
            st["high"] = True
            self._bf_finding(src_ip, count, "high")
        elif count >= self.t_finding and not st["finding"]:
            st["finding"] = True
            self._bf_finding(src_ip, count, "medium")

    def _bf_finding(self, src_ip: str, count: int, severity: str):
        me.save_finding(
            session_id=self.session_id,
            source="linux_monitor",
            detection_id="LNX-1002",
            severity=severity,
            entity_type="ip",
            entity_value=src_ip,
            title=f"SSH brute force against {self.host} from {src_ip}",
            description=(
                f"{count} failed SSH logins from {src_ip} in {self.win}s."
            ),
            raw_data={
                "host":       self.host,
                "source_ip":  src_ip,
                "fail_count": count,
                "window_s":   self.win,
                "tier":       severity,
            },
        )

    def _track_success(self, src_ip: str):
        """
        A login from an IP that was just failing succeeded. That is the shape
        of a brute force that finally landed, so it is high no matter how the
        fail count sits against the tiers. Reported once, then the state is
        cleared.
        """
        if me.is_dismissed("ip", src_ip):
            return

        st = self._bf.get(src_ip)
        if not st:
            return

        cutoff = time.time() - self.win
        fails  = [t for t in st["hits"] if t >= cutoff]
        if len(fails) < self.t_fts:
            return

        me.save_finding(
            session_id=self.session_id,
            source="linux_monitor",
            detection_id="LNX-1003",
            severity="high",
            entity_type="ip",
            entity_value=src_ip,
            title=f"Possible SSH break-in on {self.host} from {src_ip}",
            description=(
                f"A login from {src_ip} succeeded right after {len(fails)} "
                f"failed attempts in {self.win}s. That is the pattern of a "
                f"brute force that got in. Check this host now."
            ),
            raw_data={
                "host":       self.host,
                "source_ip":  src_ip,
                "fail_count": len(fails),
                "window_s":   self.win,
                "kind":       "failed_then_success",
            },
        )
        # One report per break-in, not one per poll.
        self._bf.pop(src_ip, None)

    def _prune_bf(self):
        """Drop IPs whose window has emptied and that owe no open tier."""
        cutoff = time.time() - self.win
        for ip in list(self._bf):
            st = self._bf[ip]
            if not [t for t in st["hits"] if t >= cutoff] \
                    and not st["finding"] and not st["high"]:
                self._bf.pop(ip, None)

    def _flag_log_blind(self):
        """
        Every log source came back empty on a host we reached. Raised once,
        cleared when a source recovers. An empty log is not a safe host.
        """
        if self._log_blind:
            return
        self._log_blind = True
        self._log_blind_since = time.time()
        me.save_finding(
            session_id=self.session_id,
            source="linux_monitor",
            detection_id="LNX-1004",
            severity="high",
            entity_type="ip",
            entity_value=self.host,
            title=f"SSH log intake unavailable on {self.host}",
            description=(
                "The monitor reached this host but every SSH log source came "
                "back empty: no /var/log/auth.log, no /var/log/secure, and "
                "nothing under the sshd or sshd-session journal identifiers. "
                "Login and brute-force detection on this host is BLIND until "
                "logging is restored. An empty log is not a quiet host."
            ),
            raw_data={"host": self.host, "sources_tried": list(self._LOG_SOURCES)},
        )

    def _clear_log_blind(self, source: str):
        self._log_source = source
        if self._log_blind:
            self._log_blind = False
            self._log_blind_since = None
            logger.info(
                f"LinuxMonitor: log intake recovered on {self.host} via {source!r}"
            )

    def _check_sessions(self, client):
        """Record newly-observed active sessions only."""
        if self._host_dismissed():
            return

        output = self._run(client, "last -n 20 2>/dev/null")
        if not output:
            return

        new_lines = 0
        for line in output.splitlines():
            if "still logged in" not in line:
                continue
            if not self._is_new_line(line):
                continue

            new_lines += 1
            me.save_event(
                session_id=self.session_id,
                source="linux_monitor",
                event_id="ACTIVE_SESSION",
                event_type="active_session",
                severity="info",
                description=line[:200],
                raw_data={"host": self.host},
            )

        if new_lines:
            self._persist_seen_lines()

    def _check_processes(self, client):
        """
        Exact basename match against SUSPICIOUS_PROCESS_NAMES.

        The previous implementation used substring matching, so "nc" matched
        "at-spi-bus-launcher", "cinnamon-launcher", "sync" and anything else
        containing those two letters. Every desktop Linux box produced a wall
        of high-severity false positives.
        """
        if self._host_dismissed():
            return

        output = self._run(client, "ps aux --no-headers 2>/dev/null")
        if not output:
            return

        saw_new_process = False

        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 11:
                continue

            # parts[10:] is the full command with arguments. The old code used
            # parts[10] alone, discarding the args, which is exactly where a
            # reverse shell or miner announces itself.
            argv     = parts[10:]
            cmdline  = " ".join(argv)
            basename = os.path.basename(argv[0]).lower()

            if basename not in SUSPICIOUS_PROCESS_NAMES:
                continue

            if me.is_dismissed("process", basename):
                continue

            # S25, 2026-08-28. THIS CHECK WAS THE ONLY ONE WITH NO DEDUP.
            #
            # Every other check in this module gates on _is_new_line, and the
            # module header claims deduplication across polls as a feature.
            # This one did not, and me.save_finding is a bare INSERT with no
            # dedup of its own. So one long-running `socat` produced a finding
            # every POLL_INTERVAL for as long as it ran: 720 rows a day,
            # forever, for one process.
            #
            # Worse than noise, it is a burial tool. A few hundred short-lived
            # `nc` processes write tens of thousands of findings an hour into
            # the table the model reads, and query_findings defaults to 100
            # rows. Every real finding goes under the fold. Note that fencing
            # does not help here at all: the fence bounds what attacker text
            # can DO, not how much of it there can be.
            #
            # Keyed on process identity rather than the raw ps line, because
            # the line carries a CPU and time column that changes every poll
            # and would defeat the dedup completely.
            identity = f"proc:{self.host}:{parts[1]}:{basename}:{cmdline[:200]}"
            if not self._is_new_line(identity):
                continue
            saw_new_process = True

            # Name alone is weak. Name + telltale arguments is strong.
            armed = any(p.search(cmdline) for p in SUSPICIOUS_ARG_PATTERNS)

            me.save_finding(
                session_id=self.session_id,
                source="linux_monitor",
                detection_id="LNX-1005",
                severity="high" if armed else "medium",
                entity_type="process",
                entity_value=basename,
                title=(
                    f"Suspicious Linux process: {basename} on {self.host}"
                    + (" (armed)" if armed else "")
                ),
                description=cmdline[:300],
                raw_data={
                    "host":     self.host,
                    "ps_line":  line[:500],
                    "cmdline":  cmdline[:500],
                    "basename": basename,
                    "armed":    armed,
                    "pid":      parts[1],
                    "user":     parts[0],
                },
            )

        # Persisted once per poll rather than per finding, matching the other
        # checks in this module.
        if saw_new_process:
            self._persist_seen_lines()

    def _check_crontab(self, client):
        """Diff against the stored baseline. Only report on change."""
        if self._host_dismissed():
            return

        output = self._run(
            client,
            "crontab -l 2>/dev/null; ls -la /etc/cron* 2>/dev/null",
        )
        if not output:
            return

        current  = _sha(output)
        baseline = self._get_baseline("crontab")

        if baseline is None:
            # First run seeds silently, nothing to compare against yet.
            self._set_baseline("crontab", current)
            self._set_baseline("copy:crontab", output)
            logger.info(f"LinuxMonitor: crontab baseline seeded for {self.host}")
            return

        if baseline != current:
            diff = _what_changed(self._get_baseline("copy:crontab"),
                                 baseline, output, _sha)
            me.save_finding(
                session_id=self.session_id,
                source="linux_monitor",
                detection_id="LNX-1006",
                severity="high",
                entity_type="ip",
                entity_value=self.host,
                title=f"Crontab changed on {self.host}",
                description=(
                    "Scheduled task configuration differs from baseline, "
                    "common persistence mechanism.\n" + _diff_text(diff)
                ),
                raw_data={"host": self.host, "crontab": output[:2000],
                          **diff},
            )
            self._set_baseline("crontab", current)
            self._set_baseline("copy:crontab", output)
        elif not isinstance(self._get_baseline("copy:crontab"), str):
            # Baseline from before copies were kept. Take one now, while it
            # still matches, so the NEXT change can be shown.
            self._set_baseline("copy:crontab", output)

    def _check_passwd_sudoers(self, client):
        """
        Hash-diff /etc/passwd and /etc/sudoers against a PERSISTED baseline.

        Previously the baseline lived in an instance dict, so every restart
        re-seeded from whatever was on disk at that moment. A change made
        while the monitor was down became the new normal, silently.
        """
        if self._host_dismissed():
            return

        for fname in ["/etc/passwd", "/etc/sudoers"]:
            content = self._run(client, f"cat {fname} 2>/dev/null")
            if not content:
                continue

            current  = _sha_full(content)
            key      = f"hash:{fname}"
            copy_key = f"copy:{fname}"
            baseline = self._get_baseline(key)

            if baseline is None:
                self._set_baseline(key, current)
                self._set_baseline(copy_key, content)
                logger.info(f"LinuxMonitor: {fname} baseline seeded for {self.host}")
                continue

            if baseline == current:
                if not isinstance(self._get_baseline(copy_key), str):
                    # Hash from before copies were kept. Take one now.
                    self._set_baseline(copy_key, content)
                continue

            diff = _what_changed(self._get_baseline(copy_key),
                                 baseline, content, _sha_full)
            me.save_finding(
                session_id=self.session_id,
                source="linux_monitor",
                detection_id="LNX-1007",
                severity="critical",
                entity_type="ip",
                entity_value=self.host,
                title=f"File changed on {self.host}: {fname}",
                description=(
                    f"{fname} no longer matches the stored baseline hash. "
                    "Possible account or privilege modification.\n"
                    + _diff_text(diff)
                ),
                raw_data={
                    "host":          self.host,
                    "file":          fname,
                    "baseline_hash": baseline,
                    "current_hash":  current,
                    **diff,
                },
            )
            self._set_baseline(key, current)
            self._set_baseline(copy_key, content)

    # TREES THE SUID SCAN DOES NOT WALK. Added 2026-09-06 from a real run.
    #
    # The first real SUID scan on the test box raised EIGHT high findings, all
    # of them inside /timeshift/snapshots/<a date>/localhost/usr/..., and
    # every one of them was a copy of a binary that is already in the
    # baseline at its normal path. A system snapshot is a photograph of the
    # filesystem, so of course it contains sudo and pppd and Xorg.wrap. None
    # of that is privilege escalation, and eight highs about a backup is
    # exactly the noise that gets a real high scrolled past.
    #
    # Pruned at the FIND, not filtered afterwards, so the walk is cheaper too:
    # a snapshot directory is a second copy of the whole filesystem and it was
    # being walked in full every slow check.
    #
    # These are backup and snapshot roots, plus mount points where the thing
    # being scanned is not this host's own system. Nothing here hides a path a
    # real attacker would use on the live filesystem: a SUID binary planted
    # inside a read-only snapshot does not run as root on this box, and if it
    # is planted at the real path it still shows up.
    SUID_PRUNE = (
        "/timeshift",           # timeshift snapshots, the one that bit us
        "/.snapshots",          # snapper, btrfs
        "/var/lib/snapper",
        "/snapshots",
        "/var/lib/docker",      # container images, their own filesystems
        "/var/lib/containerd",  # the same, for Docker on the containerd store
        "/var/lib/containers",
        "/mnt",                 # anything mounted by hand
        "/media",               # removable media
        "/proc",
        "/sys",
        "/run",
    )

    def _suid_command(self) -> str:
        """
        The find, with the backup trees pruned. Built here so the test can
        read it without an SSH connection.
        """
        prunes = " -o ".join(f"-path {p} -prune" for p in self.SUID_PRUNE)
        return (f"find / \\( {prunes} \\) -o "
                f"\\( -perm -4000 -type f -print \\) 2>/dev/null")

    def _check_suid(self, client):
        """
        SUID binary diff against a PERSISTED baseline.

        Runs on SLOW_CHECK_INTERVAL, `find /` walks the entire remote
        filesystem and has no business running every two minutes.
        """
        if self._host_dismissed():
            return

        output = self._run(client, self._suid_command())
        if not output:
            return

        binaries = sorted(set(output.splitlines()))
        baseline = self._get_baseline("suid")

        # A baseline seeded BEFORE the prune list carries the snapshot copies
        # in it forever. Nothing re-raises off them, so it is only tidiness,
        # but a baseline that lists files this scan will never look at again
        # is a baseline that lies about what it covers.
        if baseline:
            pruned = [b for b in baseline
                      if any(b.startswith(p + "/") or b == p
                             for p in self.SUID_PRUNE)]
            if pruned:
                baseline = [b for b in baseline if b not in pruned]
                self._set_baseline("suid", baseline)
                logger.info(
                    f"LinuxMonitor: dropped {len(pruned)} SUID baseline "
                    f"entries under pruned paths for {self.host}. They are "
                    f"backup copies, see SUID_PRUNE.")

        if baseline is None:
            self._set_baseline("suid", binaries)
            logger.info(
                f"LinuxMonitor: SUID baseline seeded for {self.host} "
                f"({len(binaries)} binaries)"
            )
            return

        new = sorted(set(binaries) - set(baseline))
        for b in new:
            if me.is_dismissed("process", b):
                continue
            me.save_finding(
                session_id=self.session_id,
                source="linux_monitor",
                detection_id="LNX-1008",
                severity="high",
                entity_type="ip",
                entity_value=self.host,
                title=f"New SUID binary on {self.host}: {b}",
                description="SUID binary not in baseline, possible privilege escalation.",
                raw_data={"host": self.host, "binary": b},
            )

        if new:
            self._set_baseline("suid", binaries)