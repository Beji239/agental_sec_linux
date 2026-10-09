# adapters.py
# AgentalSec Linux: makes the Linux-native sensor modules fit the interface
# the rest of the application already speaks.
#
# WHY THIS FILE EXISTS AT ALL
#
# The Linux port grew a second set of sensors (process_monitor_linux.py,
# packet_sniffer_linux.py, event_monitor_linux.py, host_info_linux.py,
# software_inventory_linux.py, remediation_linux.py). They were written as
# MODULE-LEVEL FUNCTIONS, and every one of them ends in something like:
#
#     def monitor_once() -> dict:
#         ...
#         # me.save_finding(finding)      <- commented out
#
# The Windows sensors are CLASSES, and they are the ones the rest of the app
# knows how to talk to:
#
#   * core/tool_registry.execute_tool dispatches to _modules["remediation"]
#     .kill_process(pid=..., reason=..., session_id=...), and remediation_linux
#     has a bare kill_process(pid, force=False).
#   * core/sensor_health reads mod.status() and looks for blind / running /
#     reachable. The Linux modules have get_status() with different keys.
#   * the findings they raise have no detection_id, which memory_engine
#     .save_finding has REQUIRED since TODO 112, so every write would raise
#     MissingDetectionId even if the calls were uncommented.
#
# Two ways out. Rewrite the Linux sensors into classes, or wrap them. Wrapping
# wins here for one reason: the Linux sensors' detection logic is worth
# keeping and rewriting it is how the logic quietly changes. A wrapper that
# calls the tested function and adapts its OUTPUT cannot alter what the
# function noticed, and that is the property that matters in a security tool.
#
# WHAT EACH WRAPPER IS ALLOWED TO DO, AND WHAT IT IS NOT
#
# ALLOWED: rename keywords, convert a return dict into another shape, call
# status() instead of get_status(), supply a detection id that a finding was
# missing, and refuse to write a finding whose detection genuinely does not
# exist yet.
#
# NOT ALLOWED: decide a process is suspicious when the underlying function did
# not, invent a severity, or write a finding for an event that was not raised.
# Every finding written below comes from a list the sensor produced. Where a
# sensor's output cannot be mapped to a registered detection, the finding is
# logged and NOT written, because a finding with a made-up id is worse than a
# finding that is missing: it puts a rule number on the dashboard that catches
# nothing.

import collections
import json
import logging
import re
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _human_duration(seconds) -> str:
    """
    A duration a person reads, e.g. "11h 37m". None means unknown.

    Module level because two readers need it: this file's host-info wrapper
    and any adapter reporting an uptime pair. It is the SAME sentence shape
    tools/host_info.py uses, so a reader of either backend sees one
    vocabulary -- which is the correction the host_info round made to the
    wrapper that used to publish the uptime fields not at all.
    """
    if seconds is None:
        return "unknown"
    seconds = int(seconds)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"

# The two cadences this file's own adapters need at MODULE level rather than
# inside the class body, because the class reads them in two places.
#
# THE SWEEP IS HOURLY AND THE NUMBER IS NOT A PREFERENCE. Measured on this
# host 2026-09-22: the setuid/setgid/capability walk is 30 to 40 seconds over
# 936,143 files. A floor is enforced in the adapter as well as a default here,
# because a config asking for it every 10 seconds is asking for a permanently
# busy disk rather than for a faster sensor.
SWEEP_INTERVAL = 3600
SWEEP_MIN_INTERVAL = 30

# TIER C, ADDED 2026-09-22. Three hours, and the number is measured rather
# than picked: a full dpkg -V run on this host took 209s over 2755 packages,
# and the thing it detects -- a file a package shipped being replaced -- is
# not a race with a three-hour window. The owner's instruction was "expensive,
# hourly at most"; this is slower than hourly on purpose, and the config knob
# can bring it in for a host where package integrity is the thing being
# watched. The floor is 300s because below that the run costs more than the
# machine changes.
DPKG_INTERVAL = 10800
DPKG_MIN_INTERVAL = 300

# How long after start the first dpkg run waits, mirrored from
# tools/local_integrity.FIRST_DPKG_DELAY. Longer than the sweep's delay on
# purpose -- see that constant's own comment -- and named here as well because
# the status block has to be able to say when the first run is due without
# importing the tools module.
FIRST_DPKG_DELAY = 300

# THE FLOOR UNDER THAT DELAY, and it is not zero. The delay exists so a full
# dpkg run -- 209s measured -- does not compete with eight sensors starting at
# once. A config that asked for the first run in the same second as the boot
# would reinstate exactly that competition, so the floor here is 30s: past the
# boot, short enough that a verification script can actually wait for it.
DPKG_MIN_FIRST_DELAY = 30

# The /boot default, mirrored here so the adapter can fall back to it without
# importing the tools module at class-definition time.
DPKG_EXCLUDE_BOOT = True

# FINDING SEVERITY MAPPING
#
# The Linux sensors emit severities as plain words ("medium", "high"). The
# register declares which severities each detection may be raised at, and
# check_severity REFUSES a mismatch rather than clamping it. So a sensor that
# says "high" about a rule registered for {"low","medium"} would raise
# BadSeverity and the finding would be lost.
#
# These maps put each sensor's own word onto a severity the register actually
# accepts for that specific detection. Where they disagree, the REGISTER wins
# and the disagreement is logged, because the register is the place that
# answer is supposed to live.


def _unreadable(reason: str) -> dict:
    """
    A ClientHello we could not read, in the shape tools/tls_hello returns.

    NOT A NEGATIVE RESULT, and that is the whole reason it exists as a named
    helper rather than three dict literals. sni_state 'unreadable' says we
    could not finish parsing, which is a different fact from 'absent', which
    says the hello parsed cleanly and carried no server name. Anything
    downstream that reports "no SNI seen" has to check this field, and the
    two must never collapse into one another.

    `reason` is named to match the parser's own key, so _record_tls maps both
    the parser's output and these through one line rather than two.
    """
    return {
        "ok": False, "sni": None, "sni_state": "unreadable",
        "ja3": None, "ja3_md5": None, "alpn": None,
        "legacy_version": None, "cipher_count": 0, "ext_count": 0,
        "truncated_by": None, "truncated": False, "reason": reason,
    }


def _valid_entity(entity_type: str, value: str) -> bool:
    """
    Does this value look like the kind of thing its column claims it is?

    NARROW ON PURPOSE, and it exists because of a measured bug rather than a
    principle. The audit of the event monitor (EM-3, and the "rhost" rows
    under it) found 164 rows in the owner's store whose username column held
    the literal string "rhost", because a regex designed for `user=alice`
    matched `user= rhost=` on a pam_unix line and took the next word. The
    entity a finding is filed against decides what can be dismissed and what
    the finding is ABOUT, so a value that is plainly not an account name must
    not be filed as one.

    It is not a validator: it refuses what it can see is wrong and accepts
    everything else, because an account naming rule that is too strict would
    silence a real account on a host this app has never seen.
    """
    value = (value or "").strip()
    if not value or len(value) > 64:
        return False
    if entity_type == "user":
        # A login name: no spaces, and it is not a bare key=value fragment.
        if any(c.isspace() for c in value):
            return False
        if value.endswith("=") or value.startswith("="):
            return False
        if re.search(r'\b(rhost|ruser|user|tty|comm|exe|uid|gid|ses|acct)=?\b',
                     value, re.IGNORECASE) and "=" not in value:
            # The measured case: "rhost" itself. A real account may be named
            # "user" on some hosts, which is why this only refuses when the
            # string is EXACTLY one of pam's own field names.
            return value.lower() not in {
                "rhost", "ruser", "tty", "comm", "exe", "acct", "uid", "gid",
                "ses", "user=", "invalid", "unknown"}
        return True
    if entity_type == "ip":
        parts = value.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return True
        return ":" in value or value == "unknown"
    return True


def _fit_severity(detection_id: str, wanted: str, default: str) -> str:
    """
    The severity this detection actually declares, nearest to what was asked.

    Returns the requested value when the register allows it, otherwise the
    closest declared one, and logs the substitution so it is not silent.
    """
    from core import detections as det

    try:
        allowed = det.get(detection_id).severities
    except Exception as e:
        logger.warning(f"cannot read severities for {detection_id} ({e}), "
                       f"using {default!r}")
        return default

    if wanted in allowed:
        return wanted

    order = ["info", "low", "medium", "high", "critical"]
    if wanted in order:
        idx = order.index(wanted)
        ranked = sorted(allowed, key=lambda s: abs(order.index(s) - idx)
                        if s in order else 99)
        chosen = ranked[0]
    else:
        chosen = default if default in allowed else sorted(allowed)[0]

    logger.info(f"{detection_id} does not declare severity {wanted!r}; "
                f"raising at {chosen!r} instead. Declared: {sorted(allowed)}.")
    return chosen


def _finding_landed(res) -> bool:
    """
    Did save_finding actually write the row?

    save_finding RETURNS A DICT SINCE TODO 112, {"saved": True/False}, and
    until 2026-09-25 this adapter threw that answer away: the call site
    incremented its written count straight after the call, so a write DECLINED
    by a suppression rule was counted as written, and the status said a
    finding had reached the store when the store had deliberately refused it.
    MEASURED by driving the shipped adapter with save_finding stubbed to the
    suppression path: status reported written=1 and the log line claimed a
    finding that does not exist.

    None counts as written, which is what the call meant before the return
    value existed, and is what every stub in the test tree returns.
    """
    return not (isinstance(res, dict) and res.get("saved") is False)


class _BaseAdapter:
    """
    Shared plumbing: a session id, an enabled flag, and a status().

    status() is the interface core/sensor_health._module_trouble reads, and it
    looks for exactly these keys: blind, blind_reason, running, ready,
    reachable, last_error. Anything else is ignored, so a wrapper that reports
    the wrong key names reads as healthy no matter what it says.
    """

    role = "sensor"

    def __init__(self, session_id: str, config: dict = None):
        self.session_id = session_id
        self.config     = config or {}
        self._running   = False
        self._thread    = None
        # The last error this sensor hit, kept so status() can report a
        # failure instead of a clean-looking zero. A monitor whose last poll
        # threw and which reports "running: true" is the silent failure this
        # whole project is built to avoid.
        self._last_error = None
        self._consecutive_failures = 0
        # For the sensor watchdog: when the loop started and last polled clean.
        self._started_at = None
        self._last_ok_at = None

    def start(self):
        """Start the poll loop on a daemon thread."""
        if self._running:
            return
        self._running = True
        self._started_at = time.time()
        self._thread = threading.Thread(target=self._loop, name=type(self).__name__,
                                        daemon=True)
        self._thread.start()
        logger.info(f"{type(self).__name__} started.")

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            try:
                self.poll()
                self._last_error = None
                self._consecutive_failures = 0
                self._last_ok_at = time.time()
            except Exception as e:
                self._consecutive_failures += 1
                self._last_error = f"{type(e).__name__}: {e}"
                logger.error(f"{type(self).__name__} poll failed: {e}")
            self._wait_for_next_poll()

    def _wait_for_next_poll(self):
        """Sleep until the next poll. A sensor that can be woken overrides it."""
        time.sleep(self.poll_interval)

    @property
    def poll_interval(self) -> int:
        return int((self.config.get("sensors", {}) or {})
                   .get(self.role, {}).get("poll_interval", 60))

    def poll(self):
        """One pass. Overridden. Must write whatever findings it raises."""

    def liveness(self) -> dict:
        """Is the poll loop alive and recent. Read by core/sensor_watch."""
        t = self._thread
        try:
            interval = int(self.poll_interval)
        except Exception:
            interval = 60
        return {"started": t is not None,
                "thread_alive": bool(t is not None and t.is_alive()),
                "running": bool(self._running),
                "interval": interval,
                "started_at": self._started_at,
                "last_ok_at": self._last_ok_at,
                "consecutive_failures": self._consecutive_failures,
                "last_error": self._last_error}

    def status(self) -> dict:
        out = {
            "running": self._running,
            "role":    self.role,
            "consecutive_failures": self._consecutive_failures,
        }
        if self._last_error:
            out["last_error"] = self._last_error
        return out


# PROCESS MONITOR
#
# tools/process_monitor_linux.py raises five kinds of finding:
#
#   suspicious_process_name      -> PRC-1001 (registered, process_monitor source)
#   suspicious_process_location  -> LNX-1101 (registered in T2)
#   masquerading_system_binary   -> LNX-1102 (registered in T2)
#   lolbin_abuse                 -> LNX-1103 (registered in T2)
#   (brute force is the event monitor's, below)
#
# THE THREE THAT HAD NO ENTRY ARE NOW REGISTERED, on the owner's answer to Q1
# on 2026-09-17. Before that they were logged with their own detail and
# counted in status(), and the boot log said how many were waiting for ids,
# because writing them under PRC-1001 would have made the Detections page
# report that one rule catches four different things.
class LinuxProcessMonitor(_BaseAdapter):
    """
    Wraps tools/process_monitor_linux.py's monitor_once().

    The dedup lives in the underlying module (it caches process identity as
    (pid, create_time)), so polling it every 60s does not re-raise the same
    process forever. findings already counted here are the ones that were
    genuinely new to the sensor.
    """

    role = "process_monitor"

    def __init__(self, session_id, config=None):
        super().__init__(session_id, config)
        self._last_result = {}
        self._unregistered_counts = {}

    def poll(self):
        from tools import process_monitor_linux as pm
        from core import memory_engine as me

        result = pm.monitor_once()
        if result.get("error"):
            raise RuntimeError(result["error"])

        self._last_result = result
        findings = result.get("findings") or []

        for f in findings:
            ftype = f.get("type") or "unknown"
            pid   = f.get("pid")
            name  = f.get("name") or f"pid {pid}"

            if ftype == "suspicious_process_name":
                severity = _fit_severity("PRC-1001", f.get("severity", "medium"),
                                         "medium")
                # PM-7, 2026-09-23. THE DISMISSAL IS ASKED WHAT IT CLOSED, not
                # just what it is called. `is_dismissed` alone is the check
                # that let a name-keyed dismissal silence a real masquerade;
                # `dismissal_covers` compares the executable this finding is
                # about against the executables the dismissal actually closed,
                # and a mismatch re-raises with the comparison on the row.
                covered = me.dismissal_covers("process", name, f.get("exe"))
                if covered["covered"]:
                    logger.debug("PRC-1001 for %s (pid %s) skipped: %s",
                                 name, pid, covered["reason"])
                else:
                    me.save_finding(
                        session_id=self.session_id,
                        source="process_monitor",
                        detection_id="PRC-1001",
                        severity=severity,
                        entity_type="process",
                        entity_value=name,
                        title=f"Suspicious process: {name} (PID {pid})",
                        description=f.get("description"),
                        raw_data={
                            "pid":      pid,
                            "name":     name,
                            "exe":      f.get("exe"),
                            "cmdline":  f.get("cmdline"),
                            "package":  f.get("package"),
                            "detector": "tools/process_monitor_linux.py",
                            "dismissal": covered["reason"] if covered["compared"]
                                         else None,
                        },
                    )
                continue

            # THE THREE THAT NOW HAVE IDS. T2, 2026-09-17, owner's answer Q1.
            #
            # These were counted and logged for one day, from the moment this
            # adapter was written until T2, because writing them under PRC-1001
            # would have made one rule claim four different things and the
            # operator could not tell which had fired. They have their own
            # numbers now and are written like any other finding.
            #
            # THE SEVERITY IS THE MODULE'S OWN, passed through _fit_severity
            # rather than restated here: process_monitor_linux declares low for
            # location, high for masquerading and medium for lolbin, and if
            # that changes the register refuses the new value and this logs the
            # substitution rather than silently agreeing.
            _PROCESS_FINDING_IDS = {
                "suspicious_process_location": "LNX-1101",
                "masquerading_system_binary":  "LNX-1102",
                "lolbin_abuse":                "LNX-1103",
            }
            if ftype in _PROCESS_FINDING_IDS:
                did = _PROCESS_FINDING_IDS[ftype]
                severity = _fit_severity(did, f.get("severity", "medium"),
                                         "medium")
                # The entity is the process NAME, same as PRC-1001 uses, so a
                # dismissal of the name covers every rule about it and the
                # incident key is stable across a restart of the process. The
                # pid goes in raw_data where it belongs: a pid is reuse-prone
                # and is evidence about THIS occurrence, not an identity.
                #
                # PM-7, 2026-09-23. AND THE NAME IS NO LONGER THE WHOLE TEST.
                # Four dismissals already sit in the live database (systemd,
                # systemd-journald, systemd-logind, bash), every one of them
                # made to quiet the 84 false LNX-1102 rows and the 37 false
                # LNX-1103 rows. Measured: a real `cp /bin/sleep /tmp/systemd`
                # still trips this sensor at HIGH — and the dismissal of the
                # NAME skipped the write, so the one rule on this machine that
                # can see a fake systemd was silenced by the dismissals made to
                # quiet the false ones.
                #
                # dismissal_covers compares the file this finding is about with
                # the files that dismissal actually closed. Same file: quiet,
                # as the operator asked. Different file: it writes, and the row
                # says why it was not covered.
                covered = me.dismissal_covers("process", name, f.get("exe"))
                if covered["covered"]:
                    logger.debug("%s for %s (pid %s) skipped: %s",
                                 did, name, pid, covered["reason"])
                else:
                    me.save_finding(
                        session_id=self.session_id,
                        source="process_monitor",
                        detection_id=did,
                        severity=severity,
                        entity_type="process",
                        entity_value=name,
                        title=f.get("description") or f"{ftype}: {name}",
                        description=f.get("description"),
                        raw_data={
                            "pid":      pid,
                            "name":     name,
                            "exe":      f.get("exe"),
                            "cmdline":  f.get("cmdline"),
                            "package":  f.get("package"),
                            "detector": "tools/process_monitor_linux.py",
                            # PM-7: when a live dismissal existed and did NOT
                            # cover this one, the reason travels with the row.
                            # A reader can then tell a first occurrence from the
                            # third one the same dismissal failed to quiet.
                            "dismissal": covered["reason"] if covered["compared"]
                                         else None,
                        },
                    )
                continue

            # Anything this sensor grows NEXT. Counted and logged, never
            # written under somebody else's detection id.
            self._unregistered_counts[ftype] = \
                self._unregistered_counts.get(ftype, 0) + 1
            logger.warning(
                f"process_monitor_linux raised {ftype!r} for {name} "
                f"(PID {pid}) and there is NO registered detection id for it, "
                f"so it was NOT written to the findings table: "
                f"{f.get('description')}. Add it to core/detections.py and "
                f"map it here to stop losing these."
            )

    def status(self) -> dict:
        out = super().status()
        out["process_count"] = self._last_result.get("process_count")
        out["findings_this_pass"] = self._last_result.get("finding_count")
        if self._unregistered_counts:
            # Surfaced, not buried. These are real observations being dropped
            # for want of a rule number and the count has to be visible or the
            # dashboard reads as "nothing found".
            out["unregistered_finding_types"] = dict(self._unregistered_counts)
            out["note"] = (
                f"{sum(self._unregistered_counts.values())} finding(s) could "
                f"not be written because this sensor raises types that have no "
                f"detection id: {sorted(self._unregistered_counts)}. The log "
                f"carries each one. This is a gap in this app, not a quiet "
                f"machine."
            )
        return out


# EVENT MONITOR
#
# tools/event_monitor_linux.py reads journald and the log files, categorises
# each entry against WATCHED_PATTERNS, and raises a finding per match.
#
# AN EVENT IS "this happened", A FINDING IS "this is wrong". A successful
# sudo is an event; five failed logins in a window is a finding.
#
# THE BRUTE FORCE RULE HERE IS LNX-1002, the registered Linux ssh_brute_force,
# and it has been since the EM round. The Windows tree raised this under
# EVT-1001 windows_brute_force, whose summary named event 4625 -- an event
# number from a channel nothing on this platform can read, on a row that came
# out of auth.log. That id is retired in core/detections.py (2026-09-25) and is
# never handed out again.
class LinuxEventMonitor(_BaseAdapter):
    """Wraps tools/event_monitor_linux.py's monitor_once()."""

    role = "event_monitor"

    # WHERE THE CURSOR LIVES BETWEEN POLLS. user_preferences, one row per
    # source, JSON. The Windows twin keeps its per-channel high-water mark in
    # exactly this table and for exactly this reason ("an in-memory-only
    # marker meant every restart either re-ingested old events or skipped new
    # ones"), and the Linux port kept nothing at all: EM-5 measured the
    # consequence in the owner's store, where auth.log produced exactly 200
    # distinct lines per minute for twelve minutes and no cursor existed to
    # catch up from.
    PREF_MARKERS = "event_monitor_cursors"

    # NO SEVERITY TABLE HERE, and that is deliberate. The source module's
    # WATCHED_PATTERNS already declares a severity for every category it can
    # raise, and a second copy in this file would be a drift waiting to
    # happen: change one and the other silently disagrees.
    #
    # The severities those categories would carry are visible in
    # tools/event_monitor_linux.py's WATCHED_PATTERNS, which is the thing the
    # owner needs to read when deciding whether each deserves a detection id.

    def __init__(self, session_id, config=None):
        super().__init__(session_id, config)
        self._last_result = {}
        # The sensor hands back a PERSISTED ID per record now (a journald
        # sequence number, or the hash of a file line), and that id is what
        # makes save_event's idempotent write engage. Until 2026-09-23 this
        # adapter passed nothing, so ON CONFLICT(source, source_record_id) had
        # no key to fire on and 97.4% of the events table was re-stored copies
        # of 18,255 distinct lines (EM-1).
        self._unregistered_counts = {}
        # WHAT WAS RAISED AND WHAT WAS WRITTEN, per poll. EM-2: eight of the
        # eleven categories the sensor raises had no registered detection id,
        # so 134 findings in one live poll became zero rows and the only trace
        # was a debug line the operator never sees. The audit's headline was
        # "0 finding(s)" 119 times over; this counter is what makes the page
        # able to say so.
        self._last_raised = 0
        self._last_dropped = 0
        # What the last poll actually stored, and what it refused to store.
        self._last_written = {"events": 0, "findings": 0, "duplicate_events": 0,
                              "failed_events": 0}
        self._gaps_total = 0
        # The journald follower (EM3-8): it only wakes the poll loop, so the
        # cursor stays the one record of what has been read.
        self._wake = threading.Event()
        self._follower = None
        self._stream = {"running": False, "lines_seen": 0, "wakeups": 0,
                        "note": "not started"}

    # Least time between two polls a burst of journal lines can cause.
    STREAM_MIN_GAP = 10.0
    STREAM_RESTART_SECONDS = 30

    def start(self):
        super().start()
        from tools import event_monitor_linux as em
        cfg = em.configure(self.config)
        wanted = cfg.get("sources")
        if not cfg.get("stream", True):
            self._stream["note"] = "switched off in config (stream: false)"
        elif wanted is not None and "journald" not in wanted:
            self._stream["note"] = "journald is not a configured source"
        else:
            threading.Thread(target=self._follow_journal, daemon=True,
                             name="event-monitor-follow").start()

    def stop(self):
        super().stop()
        self._wake.set()
        proc = self._follower
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass

    def _follow_journal(self):
        """Run journalctl -f and wake the poll loop on every new record."""
        import subprocess
        while self._running:
            try:
                proc = subprocess.Popen(
                    ["journalctl", "--no-pager", "-f", "-n", "0", "-q",
                     "-o", "cat"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, errors="replace")
            except (OSError, ValueError) as e:
                self._stream.update(running=False,
                                    note=f"journalctl -f could not start: {e}")
                return
            self._follower = proc
            self._stream.update(running=True, note="following journald")
            for _line in proc.stdout:
                if not self._running:
                    break
                self._stream["lines_seen"] += 1
                self._wake.set()
            err = (proc.stderr.read() or "").strip() if proc.stderr else ""
            proc.wait()
            self._stream["running"] = False
            if not self._running:
                self._stream["note"] = "stopped with the sensor"
                return
            self._stream["note"] = (
                f"journalctl -f exited (rc={proc.returncode}"
                + (f": {err.splitlines()[-1][:160]}" if err else "")
                + f"); polling every {self.poll_interval}s until it restarts")
            logger.warning(f"Event monitor: {self._stream['note']}")
            time.sleep(self.STREAM_RESTART_SECONDS)

    def _wait_for_next_poll(self):
        """Wait out the poll interval, or less when journald has written."""
        if self._wake.wait(self.poll_interval) and self._running:
            self._stream["wakeups"] += 1
            # Gather a burst of lines into one poll.
            time.sleep(self.STREAM_MIN_GAP)
        self._wake.clear()

    # THE CURSOR

    def _load_markers(self) -> dict:
        """
        The persisted positions, or {} on a first run.

        A junk value is not fatal and is not silently treated as a first run
        either: it is REPORTED through last_marker_error, because a cursor
        that cannot be read means the next poll will re-read from wherever it
        lands, and that is worth knowing rather than discovering in the row
        count.
        """
        from core import memory_engine as me
        self._marker_error = None
        try:
            raw = me.get_preference(self.PREF_MARKERS, "") or ""
        except Exception as e:
            self._marker_error = f"the stored cursors could not be read: {e}"
            logger.warning(f"Event monitor: {self._marker_error}")
            return {}
        if not raw:
            return {}
        try:
            data = json.loads(raw)
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, TypeError) as e:
            self._marker_error = (f"the stored cursors are not readable JSON "
                                  f"({e}), so this poll starts from a first "
                                  f"run for every source")
            logger.warning(f"Event monitor: {self._marker_error}")
            return {}

    def _save_markers(self, markers: dict) -> None:
        """
        Persist the positions. A failure here is reported, never swallowed:
        losing the cursor is what turns a forward drain back into a re-read.
        """
        from core import memory_engine as me
        try:
            me.set_preference(self.PREF_MARKERS, json.dumps(markers))
        except Exception as e:
            self._marker_error = f"the cursors could not be saved: {e}"
            logger.warning(
                f"Event monitor: {self._marker_error}. The next poll will "
                f"start from the last cursor that DID save, so records are "
                f"re-read rather than skipped.")

    def poll(self):
        from tools import event_monitor_linux as em
        from core import memory_engine as me

        # THE CONFIG BLOCK IS APPLIED BEFORE THE POLL, so this sensor honours
        # enabled / sources / poll_interval like every other sensor in the
        # tree (EM-12). See status() for the OFF BY CONFIG case.
        applied = em.configure(self.config)

        # OFF MEANS OFF
        #
        # `sensors.event_monitor.enabled = false` used to change nothing: the
        # reader ran, the store grew, and no line anywhere said the switch had
        # been ignored (EM-12). An operator's switch that does not switch is
        # worse than no switch, because it is a control the operator believes
        # they have. The cursor is deliberately NOT touched while it is off:
        # the position stays where it was, so switching the sensor back on
        # reads everything that accumulated instead of skipping it, and the
        # backlog that finds is REPORTED.
        if not applied.get("enabled", True):
            if not getattr(self, "_off_logged", False):
                logger.info(
                    "Event monitor: the log reader is switched OFF in config "
                    "(sensors.event_monitor.enabled = false), so NOTHING is "
                    "reading journald or the log files. The stored cursors "
                    "are left where they are: switching this back on reads "
                    "everything written since, in order, rather than skipping "
                    "it.")
                self._off_logged = True
            self._last_result = {}
            return
        self._off_logged = False

        markers = self._load_markers()
        result = em.monitor_once(markers=markers)
        self._last_result = result

        self._save_markers(result.get("markers") or {})

        for name in (result.get("unregistered_sources") or []):
            logger.warning(
                f"Event monitor: {name!r} is listed in "
                f"sensors.event_monitor.sources and is not a source this host "
                f"offers. It is NOT being read. Known sources: journald and "
                f"the log files that exist here.")

        # THE COVERAGE GAPS
        #
        # Records that will never be read. Written as EVENTS, not findings,
        # and that is the Windows twin's own call carried over with its
        # reasoning: "an event row rather than a finding, per the
        # declared-expectation rule... nobody declared an expectation about
        # log rotation. It is something the model should be able to weigh, not
        # an alert on its own."
        for gap in (result.get("gaps") or []):
            self._write_gap(me, gap)

        # Events first: what happened, whether or not anything is wrong.
        #
        # STORED vs ALREADY STORED IS COUNTED, NOT ASSUMED. save_event's
        # ON CONFLICT DO NOTHING is deliberately silent (memory_engine's own
        # comment on that clause says so), so the difference between "wrote
        # this" and "already had it" has to be measured or the log line would
        # claim writes that did not happen. ONE count before the loop and one
        # after: a per-row count would be O(rows x table) on a seven-hundred
        # thousand row table, which is the kind of fix that makes the sensor
        # slower than the bug it replaced.
        #
        # THE COST OF THIS LOOP, MEASURED 2026-09-23 on the owner's 706 MB
        # store, because it is a real number and somebody will meet it: about
        # 15 ms PER ROW, which is one connection, one WAL commit and one fsync
        # per event, and save_event opens its own connection. A first run
        # that read 1,211 events therefore took 19.8 s of wall clock, and a
        # steady-state poll reads a handful. THE OLD CODE PAID THE SAME COST
        # AND WORSE: it re-wrote the same lines every 60 seconds, forever, so
        # this is strictly less writing than before, not more. It is recorded
        # here rather than fixed because batching memory_engine's writes is a
        # change to a shared writer, with its own round.
        rows_before = self._event_rows(me)
        attempted = 0
        failed = 0
        for entry in (result.get("events") or []):
            try:
                me.save_event(
                    session_id=self.session_id,
                    source=entry.get("source") or "linux_logs",
                    event_id=str(entry.get("event_id") or "0"),
                    event_type=entry.get("type") or "log_entry",
                    severity=entry.get("severity") or "info",
                    username=entry.get("username"),
                    src_ip=entry.get("ip_address"),
                    process_name=entry.get("process") or entry.get("service"),
                    description=(entry.get("message") or "")[:500],
                    raw_data=self._raw_for(entry),
                    # THE ID THE SOURCE GAVE THE RECORD. This is the whole
                    # fix for EM-1: save_event dedupes on
                    # (source, source_record_id), and the sensor now derives
                    # one per record (journald's sequence number, a file
                    # line's own hash).
                    source_record_id=entry.get("record_id"),
                )
                attempted += 1
            except Exception as e:
                failed += 1
                logger.debug(f"could not store an event row: {e}")
        rows_after = self._event_rows(me)
        stored_events = attempted
        duplicates = 0
        if rows_before >= 0 and rows_after >= 0:
            stored_events = max(0, rows_after - rows_before)
            duplicates = max(0, attempted - stored_events)

        findings_written = 0
        dropped = 0
        # WHY A RAISED FINDING DID NOT BECOME A ROW, COUNTED WHERE IT HAPPENS.
        # 2026-09-25. Until this line the loop knew only "written" and "raised
        # with no registered id", so a finding its own entity dismissal
        # silenced -- or one save_finding declined under a suppression rule --
        # landed in neither count, and the readiness row read the remainder as
        # an UNEXPLAINED gap: MEASURED, "last poll raised 1 finding(s) and only
        # 0 were written, while 0 are event types with no rule. The gap is
        # unexplained", on a poll whose entire reason was the dismissal. Same
        # class as EM-2 one layer in: the number was right and the explanation
        # was missing, and the sentence blamed the sensor for the operator's
        # own decision.
        dismissed = 0
        suppressed = 0
        for f in (result.get("findings") or []):
            ftype = f.get("type") or "unknown"

            # BRUTE FORCE. The one category that is a finding rather than an
            # event, and the one the Windows twin raises too.
            #
            # THE RULE ID CHANGED 2026-09-23, EM-3. It used to be raised under
            # LNX-1002, whose registered source is "linux_monitor" (the REMOTE
            # sensor that reads another box over SSH), for a finding this
            # LOCAL sensor raised with source="event_monitor". The register's
            # own invariant, written at core/detections.py:235-245, is "for
            # the same rule those two are the same string", and LNX-1002 broke
            # it. LNX-1012 is the LOCAL brute force rule, registered with
            # source="event_monitor", the module's own severities and its own
            # CIA axis. LNX-1002 is unchanged and is still the remote rule.
            if ftype == "brute_force_detected":
                entity_type = f.get("entity_type") or (
                    "ip" if f.get("ip_address") else "user")
                entity_value = f.get("entity_value") or f.get("ip_address") \
                    or f.get("username") or "unknown"
                severity = _fit_severity("LNX-1012",
                                         f.get("severity", "high"), "high")
                if me.is_dismissed(entity_type, entity_value):
                    # The operator already closed this entity. A DECISION, and
                    # the row must be able to say which one it was.
                    dismissed += 1
                    continue
                res = me.save_finding(
                    session_id=self.session_id,
                    source="event_monitor",
                    detection_id="LNX-1012",
                    severity=severity,
                    entity_type=entity_type,
                    entity_value=entity_value,
                    title=f"Brute force login attempt: {entity_value}",
                    description=f.get("description"),
                    raw_data={
                        "attempt_count":  f.get("attempt_count"),
                        "window_seconds": f.get("window_seconds"),
                        "source":         f.get("source"),
                        "read_by":        "tools/event_monitor_linux.py",
                    },
                )
                # save_finding answers {"saved": False} when a suppression
                # rule refuses the write, and the count has to follow the
                # WRITER'S ANSWER rather than the call having been made.
                if _finding_landed(res):
                    findings_written += 1
                else:
                    suppressed += 1
                continue

            # THE THREE PER-EVENT CATEGORIES THAT ARE FINDINGS. T2,
            # 2026-09-17, owner's answer Q2.
            #
            # account_created, account_deleted and ssh_key_added are §53.3
            # "violated declaration" cases: threshold 1, not statistical.
            #
            # THE OTHER CATEGORIES STAY EVENTS ONLY, BY DECISION, and the
            # reasoning is a volume measurement rather than taste: the boot
            # data from this machine showed 2,782 successful logins and 232
            # sudo rows in a single evening. Raising findings on those is how
            # an operator is trained to ignore their own tool.
            #
            # WHAT CHANGED 2026-09-23 IS NOT THAT DECISION, IT IS THE SILENCE
            # AROUND IT. The eight remaining categories were counted, logged
            # at DEBUG and dropped, so nothing on any page said "134 things
            # were raised this poll and none of them were stored" for as long
            # as the sensor has existed. They are still not findings, and now
            # every poll says how many were raised and how many were written,
            # in the log AND on the status the readiness page reads.
            #
            # AND WHAT CHANGED 2026-09-25 IS THE OTHER HALF OF THAT
            # DECISION: the four get SHAPE rules.
            #
            # The owner's report named four categories that "would not raise
            # an alert": firewall_block, service_failed, service_started and
            # successful_login. The decision above is not reversed -- one
            # finding per login is still what trains an operator to ignore the owner's
            # own tool -- but a BURST is a different fact from an event, and
            # the module now raises one finding per burst. Those four types
            # are wired here, each with its own registered id, its own entity
            # type and its own severities.
            #
            # THE TABLE IS THE WHOLE CONTRACT, and nothing outside it is
            # written: a type the module grows NEXT is still counted and
            # logged, which is what makes the next gap visible instead of
            # silent. That is EM-2's fix and it is why this is a dict rather
            # than four more branches.
            # AND SINCE 2026-09-25 THE IDS COME FROM THE REGISTER.
            #
            # The two dicts below used to hold the id strings themselves, and
            # the Timeline round found that this made a SECOND copy of a rule:
            # a page that has to say "a burst of this shape raises LNX-1013"
            # had nowhere to read that from except its own hardcoded table, and
            # the copy that goes stale is always the one nobody edits.
            #
            # core/detections.EVENT_TYPE_RULES is now the one place, checked at
            # import against the register itself, and this reads it. What stays
            # HERE is the half the register has no business knowing: which
            # entity type each finding is filed against, because that is a
            # property of the sensor's data rather than of the rule.
            from core import detections as det
            _EVENT_CATEGORY_ENTITY = {
                "account_created": "auto",
                "account_deleted": "auto",
                "ssh_key_added":   "auto",
            }
            _BURST_FINDING_ENTITY = {
                "service_restart_loop":    "process",
                "service_flapping":        "process",
                "firewall_scan_from_host": "ip",
                "login_burst_from_host":   "ip",
                # Per-event, but the module names the subject (EM3-5).
                "privileged_group_added":  "user",
                "kernel_tainted":          "file",
            }
            # A TYPE THE REGISTER HAS NO RULE FOR IS NOT SILENTLY DROPPED: it
            # falls through to the accounting below, which counts it and logs
            # it, exactly as it did before this table existed.
            _EVENT_CATEGORY_IDS = {
                etype: det.EVENT_TYPE_RULES[etype]
                for etype in _EVENT_CATEGORY_ENTITY
                if etype in det.EVENT_TYPE_RULES
            }
            _BURST_FINDING_IDS = {
                etype: (det.EVENT_TYPE_RULES[etype], entity)
                for etype, entity in _BURST_FINDING_ENTITY.items()
                if etype in det.EVENT_TYPE_RULES
            }
            if ftype in _EVENT_CATEGORY_IDS:
                did = _EVENT_CATEGORY_IDS[ftype]
                username = (f.get("username") or "").strip()
                entity_type = "user" if username else "ip"
                entity_value = username or (f.get("ip_address") or "unknown")
                if username and not _valid_entity(entity_type, entity_value):
                    # A GUESSED ACCOUNT NAME IS WORSE THAN NO NAME, and this
                    # is not hypothetical: the audit measured 164 real rows
                    # where the old username regex had written the literal
                    # word "rhost" into the username column. Where the name
                    # cannot be trusted the finding is filed against the
                    # HOST, which is a fact about the entry ("an account
                    # changed and the log does not say which"), rather than
                    # against a name that was never an account. The raw line
                    # still rides in raw_data either way.
                    entity_type = "ip"
                    entity_value = f.get("ip_address") or "unknown"
                    logger.warning(
                        f"Event monitor: {ftype} carries {username!r}, which "
                        f"does not look like an account name, so the finding "
                        f"is filed against the host rather than that string. "
                        f"The raw line is on the row.")
                severity = _fit_severity(did, f.get("severity", "high"),
                                         "high")
                if me.is_dismissed(entity_type, entity_value):
                    dismissed += 1
                    continue
                res = me.save_finding(
                    session_id=self.session_id,
                    source="event_monitor",
                    detection_id=did,
                    severity=severity,
                    entity_type=entity_type,
                    entity_value=entity_value,
                    title=(f"{did} {ftype.replace('_', ' ')}: "
                           f"{entity_value}"),
                    description=f.get("description") or f.get("message"),
                    raw_data={
                        "username":  username or None,
                        "source":    f.get("source"),
                        "timestamp": f.get("timestamp"),
                        "time_basis": f.get("time_basis"),
                        "message":   (f.get("message") or "")[:500],
                        "read_by":   "tools/event_monitor_linux.py",
                    },
                )
                if _finding_landed(res):
                    findings_written += 1
                else:
                    suppressed += 1
                continue

            # THE BURST FINDINGS, WIRED 2026-09-25
            #
            # The module raises one finding per BURST for the four categories
            # that used to raise nothing. The subject is either a unit name or
            # an address, and the module named it -- so the entity type is
            # declared here rather than sniffed from the string, because a
            # unit called "1.2.3.4.service" would otherwise be filed as an
            # address.
            if ftype in _BURST_FINDING_IDS:
                did, entity_type = _BURST_FINDING_IDS[ftype]
                entity_value = (f.get("entity_value") or "").strip()
                if not entity_value:
                    # NO SUBJECT MEANS NO FINDING, and the module is supposed
                    # to have refused it already. Counted as dropped rather
                    # than written, so the poll line cannot claim a row that
                    # says nothing about anything.
                    dropped += 1
                    self._unregistered_counts[ftype + " (no subject)"] = \
                        self._unregistered_counts.get(ftype + " (no subject)", 0) + 1
                    continue
                severity = _fit_severity(did, f.get("severity", "medium"),
                                         "medium")
                if me.is_dismissed(entity_type, entity_value):
                    dismissed += 1
                    continue
                res = me.save_finding(
                    session_id=self.session_id,
                    source="event_monitor",
                    detection_id=did,
                    severity=severity,
                    entity_type=entity_type,
                    entity_value=entity_value,
                    title=(f"{did} {ftype.replace('_', ' ')}: {entity_value} "
                           f"({f.get('burst_count')} in "
                           f"{f.get('window_seconds')}s)"),
                    description=f.get("description") or f.get("message"),
                    raw_data={
                        "burst_count":    f.get("burst_count"),
                        "window_seconds": f.get("window_seconds"),
                        "source":         f.get("source"),
                        "timestamp":      f.get("timestamp"),
                        "message":        (f.get("message") or "")[:500],
                        "read_by":        "tools/event_monitor_linux.py",
                    },
                )
                if _finding_landed(res):
                    findings_written += 1
                else:
                    suppressed += 1
                continue

            # Anything this sensor grows NEXT. Counted and logged.
            self._unregistered_counts[ftype] = \
                self._unregistered_counts.get(ftype, 0) + 1
            dropped += 1

        self._last_raised = len(result.get("findings") or [])
        self._last_dropped = dropped
        self._last_written = {
            "events": stored_events,
            "findings": findings_written,
            "duplicate_events": duplicates,
            "failed_events": failed,
            # THE TWO OTHER REASONS A RAISED FINDING WROTE NOTHING. Both are
            # decisions the operator made, so both are named rather than
            # bundled into an unexplained remainder.
            "dismissed": dismissed,
            "suppressed": suppressed,
        }

        # THE SENTENCE THE APP'S OWN LOG HAS BEEN CARRYING SINCE THE PORT IS
        # NOW THE WHOLE TRUTH INSTEAD OF HALF OF IT. It said "stored N
        # event(s), 0 finding(s)" 119 times and never said that 134 findings
        # had been raised and dropped. It says both, and it says why.
        #
        # 2026-09-25: it also says WHY each unwritten finding was not written,
        # including a dismissal and a suppression. Both used to vanish: the
        # poll log line said "0 finding(s)" and the readiness row read the
        # remainder as an unexplained gap. The whole point of a raised-vs-
        # written line is that every raised one is accounted for, so a silent
        # reason here would put the lie back one layer down.
        if (findings_written or attempted or dropped
                or dismissed or suppressed):
            logger.info(
                f"Event monitor stored {stored_events} event(s) "
                f"({duplicates} already stored, by record id), "
                f"{findings_written} finding(s)"
                + (f", {dropped} raised with no registered detection id "
                   f"(events only, by decision)"
                   if dropped else "")
                + (f", {dismissed} not written because their entity is "
                   f"dismissed" if dismissed else "")
                + (f", {suppressed} declined by a suppression rule "
                   f"(save_finding said so)" if suppressed else "")
                + (f", {failed} event(s) could not be written"
                   if failed else "") + ".")

    def _raw_for(self, entry: dict) -> dict:
        """
        The row's raw_data: everything the parser produced for this entry.

        The message is the only thing left out, because it has its own column
        and the description is already its first 500 characters; everything
        else (the record id, the time basis, the service, the matched
        categories, and the raw line itself) rides here where a reader can get
        at it without a second query.
        """
        return {k: v for k, v in entry.items() if k != "message"}

    def _event_rows(self, me) -> int:
        """
        How many event rows exist. Used ONLY to tell "stored" from "already
        had it": save_event's ON CONFLICT DO NOTHING is silent by design
        (memory_engine's own comment says so), so the difference has to be
        counted rather than assumed, or the log line would claim writes that
        did not happen.
        """
        try:
            with me._get_readonly_conn() as conn:
                return conn.execute("SELECT COUNT(*) c FROM events"
                                    ).fetchone()["c"]
        except Exception as e:                                # noqa: BLE001
            logger.debug(f"event row count unreadable: {e}")
            return -1

    def _write_gap(self, me, gap: dict) -> None:
        """
        One coverage hole, as an EVENT row, and in the log.

        An event rather than a finding, per the Windows twin's own reasoning,
        carried over with it. The row is what the model can weigh; the log
        line is what an operator sees without querying anything.
        """
        source = gap.get("source") or "linux_logs"
        count = gap.get("count")
        lost_bytes = gap.get("lost_bytes")
        amount = (f"{count} record(s)" if count
                  else (f"up to {lost_bytes} byte(s)" if lost_bytes
                        else "an unknown number of records"))
        description = (f"{amount} in {source} were never read: "
                       f"{gap.get('reason')}")
        try:
            me.save_event(
                session_id=self.session_id,
                source=source,
                event_id="0",
                event_type="event_log_gap",
                severity="medium",
                description=description[:500],
                raw_data=gap,
                source_record_id=None,
            )
            self._gaps_total += 1
        except Exception as e:
            logger.debug(f"could not record the {source} log gap: {e}")
        logger.warning(f"Event monitor: {source} COVERAGE GAP - {description}")

    def status(self) -> dict:
        from tools import event_monitor_linux as em

        out = super().status()
        try:
            raw = em.get_status()
        except Exception as e:
            out["last_error"] = f"get_status failed: {e}"
            out["stream"] = dict(self._stream)
            return out

        applied = raw.get("config") or em.config_in_force()

        # OFF BY CONFIG, WHICH DID NOT EXIST BEFORE 2026-09-23
        #
        # EM-12: `sensors.event_monitor.enabled = false` did not stop the
        # reader and produced no log line saying so, while auditd beside it
        # has had a real OFF-BY-CONFIG state since main.py:700. OFF and BROKEN
        # stay different sentences, and this is the OFF half: a choice, not a
        # fault, and an empty findings list from this run means nothing was
        # looked at.
        if not applied.get("enabled", True):
            out["off_by_config"] = True
            out["state"] = "OFF BY CONFIG"
            out["note"] = (
                "the log reader is switched OFF in config "
                "(sensors.event_monitor.enabled = false), so NOTHING is "
                "reading journald or the log files. That is an operator's "
                "choice and not a fault, and an empty events list from this "
                "run is a statement about configuration rather than about "
                "this machine.")

        out["event_count"] = self._last_result.get("event_count")
        out["journald_available"] = raw.get("journald_available")
        # WHY, in the journal's own words. The old key was a boolean built
        # from `journalctl --version`, which is a statement about the binary
        # being installed and not about this account's access (EM-9).
        out["journald_probe"] = raw.get("journald_probe")
        out["log_readable"] = raw.get("log_readable")
        out["log_readable_reason"] = raw.get("log_readable_reason")
        out["sources_available"] = raw.get("log_files_available")
        out["sources_unavailable"] = raw.get("log_files_unavailable")
        out["config"] = applied
        if raw.get("unregistered_sources"):
            out["unregistered_sources"] = list(raw["unregistered_sources"])

        # THE DRAIN TRAVELS WITH THE STATUS. The sensor measures what has not
        # been read yet, and core/settings reads 'backlog' and 'stalled' off
        # THIS dict. Dropping them here is how the stall branch stayed
        # unreachable: the module published nothing for it to read. A missing
        # key reads as "nobody checked", so they are passed through
        # explicitly, including the empty reading.
        out["backlog"] = raw.get("backlog", {})
        out["stalled"] = raw.get("stalled", [])
        if raw.get("backlog_is_a_floor"):
            # A figure that is a floor rather than a count says so, because
            # "we stopped counting" and "there are exactly this many" are
            # different statements and the page prints one number.
            out["backlog_is_a_floor"] = list(raw["backlog_is_a_floor"])

        # A SOURCE WHOSE LAST READ FAILED IS NOT A QUIET ONE (EM-6). The
        # module's failure paths were all logger.debug and a caller could not
        # tell "nothing new" from "tail refused"; the sentence each read
        # produced travels here, and it also puts the source in `stalled`.
        if raw.get("unreadable"):
            out["unreadable"] = dict(raw["unreadable"])
        # wtmp and btmp: "read", or why not (btmp is root-only).
        if raw.get("login_records"):
            out["login_records"] = dict(raw["login_records"])

        # WHAT WAS RAISED AND WHAT WAS WRITTEN. EM-2's fix, on the page: the
        # sensor raised 134 findings in one live poll, converted four
        # event_types, and stored none, while the readiness row said nothing
        # about it at all.
        out["findings_raised"] = self._last_raised
        out["findings_written"] = self._last_written.get("findings")
        out["events_written"] = self._last_written.get("events")
        out["events_already_stored"] = self._last_written.get("duplicate_events")
        if self._last_dropped:
            out["findings_events_only"] = self._last_dropped
        # THE OTHER TWO REASONS A RAISED FINDING WROTE NOTHING, 2026-09-25.
        # Both are decisions the operator made rather than faults, and before
        # these lines neither reached any surface: a poll whose finding was
        # dismissed showed up on the card as an UNEXPLAINED gap, red, with the
        # sentence "the log names the reason" about a reason the log did not
        # carry. Published always, including zero, because a zero here is a
        # fact this card reads rather than an absent key it has to guess at.
        out["findings_dismissed"] = self._last_written.get("dismissed", 0)
        out["findings_suppressed"] = self._last_written.get("suppressed", 0)

        # BLIND IS THE KEY sensor_health reads, and this is the case it exists
        # for: no journald AND no readable log file means this sensor saw
        # nothing, which is not the same as nothing having happened.
        #
        # ASKED OF THE LOGS, NOT OF THE GROUP LIST, since 2026-09-23. The two
        # halves of this question used to disagree: the module said journald
        # was available because the binary answered --version, and the
        # privilege report said the opposite because euid was not 0. Both now
        # read the account's real access.
        if not raw.get("log_readable") and not raw.get("sources_available"):
            out["blind"] = True
            out["blind_reason"] = (
                f"Neither journald nor any log file could be read "
                f"({raw.get('log_readable_reason') or 'no reason recorded'}), "
                f"so no event was seen at all. An empty events list from this "
                f"run is a statement about access, not about this machine.")
        else:
            out["blind"] = False

        if self._unregistered_counts:
            out["unregistered_finding_types"] = dict(self._unregistered_counts)
            note = (
                f"{sum(self._unregistered_counts.values())} security-relevant "
                f"event(s) had no registered detection id and were not written "
                f"as findings: {sorted(self._unregistered_counts)}. The log "
                f"carries each one."
            )
            # THE NOTE IS THE WHOLE FIX FOR EM-2. Until this round the note
            # only ever counted CATEGORIES, on a status dict, and the poll
            # line in the log said "0 finding(s)" as though that were the
            # whole answer. Now it says what was raised and what was dropped,
            # so "nothing on the page" is a reading rather than a silence.
            if self._last_dropped:
                note += (f" THIS POLL RAISED {self._last_raised} finding(s) "
                         f"and wrote {self._last_written.get('findings')}: the "
                         f"rest are events by decision and are in the events "
                         f"table.")
            out["note"] = note
        out["stream"] = dict(self._stream)
        return out


# PACKET SNIFFER
#
# tools/packet_sniffer_linux.py analyses each packet and raises three kinds:
#
#   beaconing_detected        -> PKT-1002 beacon_interval
#   dangerous_port_connection -> PKT-1013 / PKT-1014 by direction
#   suspicious_payload        -> PKT-1010 or nothing
#
# The dangerous-port split is real and the register has both: PKT-1013 is
# inbound (something reaching us), PKT-1014 is outbound (us reaching out,
# which is the more interesting direction). The sensor reports one type for
# both, so the direction is read from the packet's own scope.
#
# THE PAYLOAD CASE IS THE HONEST PROBLEM. The sensor's signatures are bare
# magic bytes: 4d5a (MZ, a Windows executable), 7f454c46 (ELF), 504b0304
# (ZIP). A ZIP file is not evidence of anything. The register's PKT-1010 is
# metasploit_signature and requires an actual Metasploit byte sequence, which
# this sensor does not look for. Raising a ZIP header under it would put a
# critical rule on the dashboard for a download. So payload hits are counted
# and logged and NOT written, and the status says how many.
class LinuxPacketSniffer(_BaseAdapter):
    """Wraps tools/packet_sniffer_linux.py's packet callback."""

    role = "packet_sniffer"

    # TODO 113.2. Reassembly limits for a ClientHello that spans TCP segments.
    # PORTED HERE 2026-09-21, and the numbers are the Windows tree's, measured
    # rather than chosen: ten minutes after the first boot with TLS capture on,
    # 124 hellos produced ONE parse and 123 truncations. Post-quantum key
    # exchange is why, a browser offering X25519MLKEM768 sends a key share over
    # a kilobyte long, so the hello runs past a 1460 byte segment and arrives
    # in two packets. Reading one packet at a time reads the updater traffic
    # and misses every browser on the machine.
    #
    # The limits are small on purpose: this is a buffer keyed by whatever a
    # device chooses to send, so it is a thing an attacker could try to grow.
    MAX_PENDING_HELLOS = 400       # distinct flows held at once
    MAX_PENDING_BYTES  = 16384     # per flow, a hello above this is not a hello
    PENDING_TTL_SEC    = 10        # a continuation that never came

    def __init__(self, session_id, config=None):
        super().__init__(session_id, config)
        self._capturing = False
        self._packets_seen = 0
        self._unregistered_counts = {}
        self._started_reason = "not started"
        self._cooldowns = {}
        self._lock = threading.Lock()
        # TODO 113.2. Half-read hellos keyed on (src, sport, dst, dport), the
        # count thrown out to make room, and how many were thrown away in
        # total. The two counters are the honest half: making room for a newer
        # hello is a reason to lose a name, not a reason to pretend we never
        # had one.
        self._tls_pending = {}
        self._init_capture_extras()
        self._tls_abandoned = 0
        self._tls_reassembled_this_run = 0
        # Finished hellos waiting to be saved in one call (TP-17).
        self._tls_batch = []
        self._tls_batch_at = time.monotonic()
        # DNS questions read off the capture, saved in batches (SNF-11).
        self._dns_batch = []
        self._dns_batch_at = time.time()
        self._dns_saved_this_run = 0

        # The stamped VPN state, held for VPN_STAMP_TTL seconds. See
        # _vpn_state_now — this is read once per captured FRAME otherwise.
        self._vpn_cache = (0.0, "unknown")

    # How long a stamped VPN state is reused. See _vpn_state_now.
    VPN_STAMP_TTL = 2.0

    def _vpn_state_now(self) -> str:
        """
        The VPN state to stamp on this packet row, at most once every TTL.

        Read from the module table rather than imported directly, because
        vpn_state is optional at boot and a machine without psutil still has a
        packet sniffer. Anything that goes wrong here is 'unknown' and never
        'disconnected': an unreadable state is not a no.
        """
        now = time.monotonic()
        stamp, value = self._vpn_cache
        if now - stamp < self.VPN_STAMP_TTL:
            return value
        state = "unknown"
        try:
            from core import tool_registry as _tr
            _vpn = getattr(_tr, "_modules", {}).get("vpn_state")
            if _vpn is not None and hasattr(_vpn, "status"):
                state = _vpn.status().get("state", "unknown") or "unknown"
        except Exception:
            state = "unknown"
        self._vpn_cache = (now, state)
        return state

    # ONE FINDING PER SUBJECT PER COOLDOWN. The Windows sniffer has the same
    # mechanism for the same reason: a beaconing destination that beacons
    # every 30 seconds would otherwise write 2,880 rows a day saying the same
    # thing.
    COOLDOWN_SECONDS = 1800

    def _should_emit(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            last = self._cooldowns.get(key, 0)
            if now - last < self.COOLDOWN_SECONDS:
                return False
            self._cooldowns[key] = now
        return True

    def start(self):
        """
        Start capture, or say clearly why not.

        Capture needs CAP_NET_RAW or root. Unelevated it CANNOT work, and the
        important thing is that this reports that rather than starting a
        thread that silently captures zero packets.
        """
        from tools import packet_sniffer_linux as sn

        can_capture, reason = sn.check_capture_capability()
        self._started_reason = reason

        if not can_capture:
            logger.warning(
                f"Packet capture NOT started: {reason}. This sensor will "
                f"contribute no packets and no findings this run. That is a "
                f"limitation of how it was launched, not a quiet network. Run "
                f"with sudo, or grant CAP_NET_RAW: "
                f"sudo setcap cap_net_raw+ep $(readlink -f $(which python3))")
            return

        # The module's callback writes nothing; this replaces it with one that
        # does, by handing the module our own function. See _on_packet.
        #
        # TODO 113.2 / 113.5 / 113.6, PORTED 2026-09-21. The three detectors
        # that live on the Windows sniffer's own class are built here on the
        # ADAPTER instead, because this tree's capture is a module of functions
        # with an adapter in front of it rather than a class. The wiring is the
        # same job in a different place, and the reasoning from the Windows
        # side carries over unchanged:
        #
        #   tls_hello   parses the ClientHello out of a captured frame. It
        #               opens nothing and captures nothing itself; it is a
        #               parser, so it costs the capture thread a few hundred
        #               microseconds on a SYN+data packet and nothing on the
        #               rest.
        #   lan_watch   ARP and DHCP abuse. Same shape: it holds the state and
        #               the judgement, this callback holds the capture and the
        #               write.
        #   payload_ring  the always-on in-memory ring, tiny and constantly
        #               overwritten, so that when a detector fires the bytes
        #               that CAUSED the alert are still around to be kept.
        #
        # ALL THREE ARE REGISTERED GLOBALLY so detectors running on other
        # threads can reach them. feed_matcher and dns_inspector raise findings
        # about flows this sniffer captured, and until now had no handle on the
        # ring, so the two detections with the strongest evidence in the whole
        # app were the two keeping no bytes.
        try:
            from tools import lan_watch
            from tools import payload_ring
            self._lan = lan_watch.LanWatch(gateway_ip=self._default_gateway())
            lan_watch.set_active(self._lan)
            # AND IT IS HANDED THE CONFIG, 2026-09-26.
            #
            # This call used to be `PayloadRing(self.session_id)` and the
            # comment beside it said the ring "reads the defaults and the
            # arming list out of user_preferences". That was half true and the
            # useful half was missing: PayloadRing.__init__ reads its whole
            # block from `(config or {}).get("payload_capture")`, its FIRST
            # argument, so with no config passed, five keys -- enabled,
            # ring_bytes_per_flow, armed_bytes_per_flow, max_total_bytes,
            # max_flows -- were structurally unreachable. MEASURED 2026-09-26:
            # every one of them took its module default on every boot, and no
            # file in the tree could change that; `payload_capture` appears in
            # NO config.json, example or otherwise. Same shape as SNF-7's
            # `capture_method` and LI-10's `enabled`: a control that reads as
            # present and cannot be set.
            #
            # The arming list still comes from user_preferences, which is
            # where a runtime decision belongs; this is the POLICY half.
            self._payload = payload_ring.PayloadRing(
                self.session_id,
                (self.config or {}).get("payload_capture"))
            payload_ring.set_active(self._payload)
        except Exception as e:
            logger.warning(f"LAN/payload detectors not wired: {e}")
            self._lan = None
            self._payload = None

        # Short flows the socket snapshot misses are named from the eBPF
        # camera's connect() records when the camera is on (SNF-24).
        try:
            from tools import ebpf_events
            cam = ebpf_events.config_for(self.config)
            sn.set_ebpf_events_db(cam["events_db"] if cam["enabled"] else None)
        except Exception as e:
            logger.debug(f"eBPF attribution not wired: {e}")
        sn._packet_callback = self._on_packet
        # the interface is CONFIGURED HERE, not guessed below. 2026-09-22
        #
        # This called sn.start_sniffer() with no arguments for the whole life
        # of the port, so the module fell back to its own auto-detect and that
        # auto-detect picked lo on this workstation (see the note above
        # select_capture_interface). sensors.packet_sniffer.interface was
        # never read by anything, which is why the config looked fine.
        #
        # AND THREE MORE KEYS BESIDE IT, 2026-09-23.
        #
        # The block already carried `capture_method` and nothing read it
        # (SNF-7). It now carries a decision for each of the three things the
        # module used to inherit from scapy's defaults or drop on the floor:
        #
        #   promiscuous  default FALSE in the module. scapy's conf.sniff_promisc
        #                is True, so every run so far has silently put this
        #                NIC into promiscuous mode -- a change to the interface
        #                of the machine being monitored, made without asking.
        #   filter       a BPF string, passed to the KERNEL, so frames it
        #                excludes are never copied to userspace. Default null
        #                (no filter) because a narrow filter starves the ARP,
        #                DHCP, TLS and ICMP parsers, all of which need frames a
        #                "not port 22" style filter would keep but a
        #                destination-based one would not.
        #   rcvbuf       the AF_PACKET receive queue. scapy asks for 0, which
        #                this kernel resolves to 2304 bytes (measured) against
        #                a default of 212,992 -- the queue for the entire
        #                capture path.
        sniff_cfg = (self.config.get("sensors", {}) or {}).get(
            "packet_sniffer", {}) or {}
        self._promisc = bool(sniff_cfg.get("promiscuous", False))
        self._filter = sniff_cfg.get("filter") or None
        self._rcvbuf = sniff_cfg.get("rcvbuf")
        started = sn.start_sniffer(
            interface=sniff_cfg.get("interface") or None,
            filter_str=self._filter,
            promisc=self._promisc,
            rcvbuf=self._rcvbuf)
        if started:
            self._capturing = True
            super().start()
            logger.info(f"Packet capture started: {reason}")
            if self._promisc:
                logger.warning(
                    "packet capture is running with promiscuous=true: this "
                    "NIC now receives frames addressed to other stations that "
                    "the switch floods to it. That is a deliberate setting "
                    "from config.json, and it is a visible change to the "
                    "interface of the host being monitored.")

    def _default_gateway(self) -> str:
        """
        The default gateway's address, or '' if we cannot work it out.

        '' IS A REAL ANSWER AND IT IS HANDLED. lan_watch reports that the
        gateway MAC check is not running rather than running it against
        nothing, because the check that never fires is worse than the check
        that is honestly switched off. Nothing else needs the gateway, so a
        failure here costs exactly one detection and is reported as costing it.

        Read from /proc/net/route, which is the kernel's own table and needs no
        subprocess and no privileges. The flags field has 0x0002 (RTF_GATEWAY)
        set on the row that is the default route, and the address is stored as
        little-endian hex, which is the part that catches people out: the byte
        pairs have to be reversed or the gateway comes out backwards.
        """
        try:
            with open("/proc/net/route", encoding="utf-8") as f:
                next(f, None)                      # header
                for line in f:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    dest, gw, flags = parts[1], parts[2], parts[3]
                    if dest != "00000000":
                        continue
                    if not (int(flags, 16) & 0x0002):
                        continue
                    octets = [str(int(gw[i:i + 2], 16))
                              for i in (6, 4, 2, 0)]
                    return ".".join(octets)
        except (OSError, ValueError) as e:
            logger.warning(f"Could not read the default gateway ({e}). "
                           f"LAN-1002, the gateway MAC check, will not run.")
        return ""

    def stop(self):
        """Stop capture and drop the global handles.

        The handles are cleared rather than left behind: a stale one would let
        another thread ask a ring nothing is filling any more, and get
        "nothing held" as an answer about a sensor that had stopped.

        AND THE HALF-READ HELLOS ARE REAPED FIRST, 2026-09-26 (register
        section 14). This dropped the pending dict with NO row, which was the
        one give-up path in this sensor that left no trace: the TTL reaper
        writes an unreadable row per abandoned flow, the make-room branch
        writes one since this round, and this one wrote nothing -- so a hello
        whose second segment was in flight at shutdown simply vanished from
        the coverage count the model is told to trust. force=True because the
        TTL is meaningless here: nothing more is going to arrive.
        """
        try:
            self._reap_pending_tls(
                force=True,
                reason=("the sensor stopped before the rest of this hello "
                        "arrived, so this handshake was never read"))
        except Exception as e:
            logger.debug(f"pending hellos not reaped at stop: {e}")
        try:
            self._flush_tls()
        except Exception as e:
            logger.debug(f"waiting hellos not saved at stop: {e}")
        try:
            self._flush_dns()
        except Exception as e:
            logger.debug(f"waiting DNS rows not saved at stop: {e}")
        try:
            self._flush_dns_answers()
        except Exception as e:
            logger.debug(f"waiting DNS answers not saved at stop: {e}")
        from tools import lan_watch
        from tools import payload_ring
        from tools import packet_sniffer_linux as sn
        try:
            sn.stop_sniffer()
        except Exception as e:
            logger.debug(f"sniffer stop: {e}")
        self._capturing = False
        try:
            payload_ring.set_active(None)
            lan_watch.set_active(None)
        except Exception:
            pass
        super().stop()

    def poll(self):
        """
        The capture thread is scapy's; there is nothing to poll.

        Kept so the base loop has something to call and so a capture thread
        that died shows up as a failure rather than a running-but-quiet
        sniffer.

        THE REAPER RIDES THIS LOOP, 2026-09-21. A half-read ClientHello whose
        continuation never arrived would otherwise sit in the pending dict
        until the process ended, holding bytes and, worse, never being
        recorded: the coverage count would show a hello that simply vanished.
        This is the only periodic clock this adapter has, so the TTL is
        enforced here. The Windows sniffer does the same thing from its own
        flush loop.
        """
        from tools import packet_sniffer_linux as sn
        from core import memory_engine as me
        if not self._capturing:
            return
        if not sn.SCAPY_AVAILABLE:
            raise RuntimeError("scapy went away mid-run")

        # SNF-6 / SNF-15. A DEAD CAPTURE IS A FAILURE, NOT A QUIET
        # NETWORK. 2026-09-23.
        #
        # The module now keeps its own liveness (its capture thread clears it
        # in a finally), because before this a thread that died left every
        # field reading healthy: capture_interface() still named the device
        # and can_capture was still True. This loop is the only periodic clock
        # the adapter has, so it is where that is noticed. Raising is correct
        # here -- the base loop records it and the readiness page shows the
        # sensor as failed, which is what it is.
        state = sn.capture_state()
        if not state.get("alive"):
            raise RuntimeError(
                f"the capture thread is no longer running: "
                f"{state.get('reason')}")

        # SNF-4. WHAT THE KERNEL SAW AND WE DID NOT KEEP.
        #
        # PKT-1003 has been in the register since the packet rules were
        # written, with text that reads "The capture buffer hit its ceiling and
        # packets were counted but not stored, so this window is incomplete and
        # cannot be called quiet" -- and nothing raised it, because nothing
        # compared our count against the interface's own. /proc/net/dev has
        # counted both from boot, at no privilege.
        #
        # THE COMPARISON IS DELIBERATELY LOOSE and the finding says so: rx
        # packets include frames the BPF filter would keep and frames from
        # protocols this module ignores (no IP layer), so a gap between the two
        # numbers is NORMAL and is not by itself evidence. What is not normal
        # is a run that claims to be reading and did not keep a single frame,
        # or a kernel drop/error counter that moved. Those are the two
        # sentences raised here, and both name their own basis.
        try:
            counters = sn.capture_counters()
        except Exception as e:
            counters = {"readable": False, "note": f"counter read failed: {e}"}
        if counters.get("readable"):
            delta = counters.get("delta") or {}
            nic_dropped = (delta.get("rx_dropped", 0) + delta.get("tx_dropped", 0))
            errored = (delta.get("rx_errors", 0) + delta.get("tx_errors", 0))
            carried = delta.get("rx_packets", 0) + delta.get("tx_packets", 0)
            # Frames this sensor's own socket queue dropped (SNF-20); the
            # interface counters never include them.
            sock = counters.get("socket") or {}
            sock_dropped = sock.get("drops", 0) if sock.get("readable") else 0
            dropped = nic_dropped + sock_dropped
            if (dropped or errored) and self._should_emit("overflow"):
                if not me.is_dismissed("ip", sn.capture_interface() or "local"):
                    me.save_finding(
                        session_id=self.session_id,
                        source="packet_sniffer",
                        detection_id="PKT-1003",
                        severity=_fit_severity("PKT-1003", "medium", "medium"),
                        entity_type="ip",
                        entity_value=sn.capture_interface() or "local",
                        title=(f"The kernel dropped {dropped} frame(s) while "
                               f"capture was running"),
                        description=(
                            f"The capture socket dropped {sock_dropped} "
                            f"frame(s) because this sensor fell behind. "
                            f"/proc/net/dev reports {nic_dropped} dropped and "
                            f"{errored} errored frame(s) on "
                            f"{sn.capture_interface()} since capture started, "
                            f"against {carried} the interface carried. The "
                            f"kernel counts every frame, including ones this "
                            f"sensor does not keep, so a gap in the counts is "
                            f"normal; a DROP counter that moves is not, because "
                            f"those frames reached this host and were thrown "
                            f"away before any sensor saw them. This window "
                            f"cannot be called quiet."),
                        raw_data={
                            "iface":      sn.capture_interface(),
                            "delta":      delta,
                            "socket":     sock,
                            "kept_this_run": self._packets_seen,
                            "read_by": "tools/packet_sniffer_linux.py",
                        },
                    )

        expired = self._reap_pending_tls()
        self._flush_tls()
        self._flush_dns_answers()
        if expired:
            logger.info(f"{expired} half-read ClientHello(s) gave up on after "
                        f"{self.PENDING_TTL_SEC}s and were recorded as "
                        f"unreadable. Their destination names are not known, "
                        f"and the count says so rather than the list reading "
                        f"as complete.")

    def _on_packet(self, pkt):
        """
        Called by scapy for every captured frame.

        This replaces packet_sniffer_linux._packet_callback, whose database
        writes were commented out. The analysis is entirely the module's: this
        calls _analyze_packet and the module's three detectors and writes
        whatever they return. It does not add a detector and does not change a
        verdict.
        """
        from tools import packet_sniffer_linux as sn
        from core import memory_engine as me

        try:
            # ARP / BOOTP / DHCP / Ether, looked up in the SNIFFER MODULE's
            # namespace rather than imported here. tools/tls_hello.py imports
            # no scapy at all -- it parses bytes and nothing else, which is
            # deliberate and is why it can be unit tested without a capture.
            # The module that already holds the scapy import is the sniffer,
            # and each layer is optional in its own right: a scapy build
            # without the DHCP layer should cost LAN-1003 and nothing else,
            # which is what None in this dict means.
            lan_layers = {
                "ARP":   getattr(sn, "ARP",   None),
                "BOOTP": getattr(sn, "BOOTP", None),
                "DHCP":  getattr(sn, "DHCP",  None),
                "Ether": getattr(sn, "Ether", None),
            }

            # LAN WATCH RUNS BEFORE THE IP CHECK, AND THAT ORDER IS THE FIX.
            #
            # MEASURED, 2026-09-21, on the first end-to-end run of this
            # wiring: an ARP frame produced arp_frames_seen 0. The cause is
            # that an ARP frame is NOT an IP frame. sn._analyze_packet returns
            # None for anything without an IP layer, and this callback
            # returned on None, so not one ARP packet ever reached lan_watch
            # and LAN-1001 to LAN-1004 could never fire on any network. The
            # sensor reported "no ARP frames have reached this sensor", which
            # was true and had nothing to do with the network.
            #
            # ARP STILL RETURNS HERE, and it is the only frame type that
            # does: it has no IP layer, so there is no packet row to write.
            # Wrapped on its own so a LAN parse cannot cost the packet row.
            #
            # CORRECTED 2026-09-26 (register section 13), because this
            # comment used to say "ARP and DHCP are NOT IP frames" and the
            # DHCP half of that is false. DHCP rides on UDP/IP, so the early
            # return took every DHCP frame out of the packets record -- the
            # twin STORES them ("this is an extra read of it, not a
            # diversion", agental_sec/tools/packet_sniffer.py:914) and this
            # tree was measured writing 0 rows for a DHCP OFFER against
            # _packets_seen 1. The DHCP read now falls through to the IP
            # path like the twin's does, and the name-service read below was
            # ADDED in the same pass: before it, lan_watch.parse_llmnr_query
            # _name and parse_nbtns_query_name had NO production caller on
            # this platform, so LAN-1004 could not fire at all (measured:
            # four distinct LLMNR responses through this callback left
            # name_frames_seen at 0), though the twin wires them at
            # agental_sec/tools/packet_sniffer.py:1154-1167.
            if self._lan is not None \
                    and lan_layers["ARP"] is not None \
                    and pkt.haslayer(lan_layers["ARP"]):
                self._packets_seen += 1
                try:
                    arp = pkt[lan_layers["ARP"]]
                    for hit in self._lan.observe_arp(
                            op=int(arp.op),
                            sender_ip=arp.psrc, sender_mac=arp.hwsrc,
                            now=time.monotonic()):
                        self._emit_lan_hit(hit)
                except Exception as e:
                    logger.debug(f"LAN watch skipped on an ARP frame: {e}")
                return

            if self._lan is not None \
                    and lan_layers["BOOTP"] is not None \
                    and pkt.haslayer(lan_layers["BOOTP"]) \
                    and pkt.haslayer(lan_layers["DHCP"]):
                try:
                    bootp = pkt[lan_layers["BOOTP"]]
                    dhcp  = pkt[lan_layers["DHCP"]]
                    # Only a server's own OFFER or ACK says who hands out
                    # leases. A client DISCOVER or REQUEST says nothing about
                    # that, which is why the message type is checked and not
                    # just the port.
                    #
                    # BOTH FORMS OF THE VALUE, and this is a real trap rather
                    # than defensive padding. MEASURED 2026-09-21: scapy keeps
                    # a message-type as the SYMBOLIC string ("offer") on a
                    # packet assembled in memory, and as the NUMBER (2) on one
                    # parsed off the wire, and this tree's DHCP detection was
                    # written against the number alone. The result was a
                    # detector that could not see any packet a test built
                    # while working correctly on live capture, which is the
                    # worst way round for something nobody can run in CI.
                    mtype = None
                    for opt in (dhcp.options or []):
                        if opt[0] == "message-type":
                            mtype = opt[1]
                            break
                    if isinstance(mtype, str):
                        mtype = {"discover": 1, "offer": 2, "request": 3,
                                 "decline": 4, "ack": 5, "nak": 6,
                                 "release": 7, "inform": 8}.get(mtype.lower())
                    # WHOSE OFFER IS IT: OPTION 54, NOT siaddr.
                    # CORRECTED 2026-09-26 (register section 13).
                    #
                    # This used to read `server = str(bootp.siaddr or "")`.
                    # siaddr is the BOOTP "next server" field -- the TFTP
                    # server for a PXE boot -- and on an ordinary router OFFER
                    # it is 0.0.0.0. MEASURED on this host through the shipped
                    # callback: an OFFER carrying the DHCP SERVER IDENTIFIER
                    # option (54) set to the router, with siaddr empty, never
                    # reached the module at all (0 calls to observe_dhcp
                    # _server), so LAN-1003 was blind to ordinary DHCP; and an
                    # OFFER whose siaddr named a DIFFERENT host had that host
                    # recorded as the DHCP server. The protocol's own answer
                    # is option 54, required by RFC 2131 section 4.3.1 in
                    # every OFFER and ACK. The twin reads the IP source
                    # (agental_sec/tools/packet_sniffer.py:1146); this reads
                    # option 54 first, falls back to the IP source, and keeps
                    # siaddr only as a LAST resort with the field it came from
                    # recorded beside the value, so the finding never claims
                    # more than it knows.
                    server, server_from = self._dhcp_server_identity(
                        pkt, bootp, dhcp)
                    if mtype in (2, 5) and server and server != "0.0.0.0":
                        for hit in self._lan.observe_dhcp_server(
                                server_ip=server,
                                msg_type={2: "offer", 5: "ack"}[mtype],
                                now=time.monotonic()):
                            raw = dict(hit.get("raw_data") or {})
                            raw["server_id_source"] = server_from
                            hit["raw_data"] = raw
                            self._emit_lan_hit(hit)
                except Exception as e:
                    logger.debug(f"LAN watch skipped on a DHCP frame: {e}")

            # LLMNR AND NBT-NS, WIRED 2026-09-26 (register section
            # 13).
            #
            # WHY THIS BRANCH EXISTS AT ALL: it did not, and on this platform
            # LAN-1004 was a detector that could not fire. tools/lan_watch
            # holds both wire parsers and the distinct-name counter, and the
            # ONLY callers of parse_llmnr_query_name / parse_nbtns_query_name
            # / observe_name_response were its own tests -- while the twin
            # wires them into its capture callback (agental_sec/tools/
            # packet_sniffer.py:1154-1167). MEASURED through this callback
            # before the branch existed: four distinct LLMNR responses left
            # name_frames_seen at 0 and wrote nothing.
            #
            # ONLY RESPONSES COUNT, and that is the module's own rule: a
            # query says what somebody was looking for, a response says who
            # claimed to be it, and only the claim can be a lie. The parsers
            # enforce it (they return '' for a query), so a malformed or
            # query-shaped frame costs nothing.
            #
            # NO EARLY RETURN, like the twin: this is an extra read of a
            # frame that was already being stored as a packet row, not a
            # diversion. Wrapped on its own for the same reason as the other
            # two -- a name parse must not cost the packet row.
            if self._lan is not None and sn.UDP is not None \
                    and pkt.haslayer(sn.UDP):
                try:
                    from tools import lan_watch
                    sport = int(pkt[sn.UDP].sport)
                    if sport in (lan_watch.LLMNR_PORT, lan_watch.NBTNS_PORT):
                        payload = (bytes(pkt[sn.Raw].load)
                                   if sn.Raw is not None
                                   and pkt.haslayer(sn.Raw) else b"")
                        if sport == lan_watch.LLMNR_PORT:
                            name = lan_watch.parse_llmnr_query_name(payload)
                            proto = "LLMNR"
                        else:
                            name = lan_watch.parse_nbtns_query_name(payload)
                            proto = "NBT-NS"
                        src_ip = (str(pkt[sn.IP].src)
                                  if pkt.haslayer(sn.IP) else
                                  str(pkt[sn.IPv6].src)
                                  if sn.IPv6 is not None
                                  and pkt.haslayer(sn.IPv6) else "")
                        if name:
                            for hit in self._lan.observe_name_response(
                                    proto, src_ip, name,
                                    now=time.monotonic()):
                                self._emit_lan_hit(hit)
                except Exception as e:
                    logger.debug(
                        f"LAN watch skipped on a name-service frame: {e}")

            # IPv6 neighbour discovery and DHCPv6 (LAN-1005 to LAN-1007).
            # Wrapped on its own so a parse failure costs only these checks.
            if self._lan is not None:
                try:
                    for hit in self._observe_ipv6_lan(pkt, sn):
                        self._emit_lan_hit(hit)
                except Exception as e:
                    logger.debug(f"IPv6 LAN watch skipped on a frame: {e}")

            data = sn._analyze_packet(pkt)
            if not data:
                return
            self._packets_seen += 1

            # SNF-9. THE HOST'S OWN TRAFFIC IS STILL STORED, BUT THE
            # DETECTIONS ARE TOLD WHAT THEY ARE LOOKING AT. 2026-09-23.
            #
            # A packet aimed at this host, at loopback, or at a broadcast
            # group is recorded as a row like any other -- the record is what
            # the row is for -- but no detector below may raise anything about
            # a destination that is not somebody else's host. The three live
            # PKT-1002 classes were this host's own address, 127.0.0.1 and the
            # /24 broadcast; all 35 rows were false.
            #
            # direction_hint tells the attribution lookup which end is local
            # (SNF-13), and the same answer feeds the detectors' own gating.
            dst_is_host, dst_not_host_reason = sn.peer_is_a_host(data["dst_ip"])
            if not dst_is_host:
                sn._note_skip(f"detections: {dst_not_host_reason}")

            # The raw payload of this frame, once, for the two detectors below
            # that read headers _analyze_packet does not carry. Guarded because
            # a scapy layer that throws here would cost every detection on the
            # packet rather than the one that needs it.
            try:
                raw_bytes = (bytes(pkt[sn.Raw].load)
                             if sn.Raw is not None and pkt.haslayer(sn.Raw)
                             else b"")
            except Exception:
                raw_bytes = b""
            # The TCP sequence number lets the TLS reassembly tell a
            # retransmit from a continuation (TP-19).
            try:
                if raw_bytes and pkt.haslayer(sn.TCP):
                    data["tcp_seq"] = int(pkt[sn.TCP].seq)
            except Exception:
                pass

            from tools import tls_hello

            # THE VPN STATE IS STAMPED ON EVERY PACKET ROW, WIRED 2026-09-21.
            #
            # tools/vpn_state.py's own header says "packet_sniffer._flush stamps
            # every packet batch with vpn_state, and that is worth keeping. A
            # packet captured while a tunnel was up is a different fact from one
            # captured while it was down." On this tree NOTHING READ IT: the
            # column exists and is CHECK-constrained to three values, and every
            # row written here took the schema default of 'unknown'. So the
            # model could never tell those two facts apart, which is the exact
            # thing the module exists for.
            #
            # 'unknown' STAYS A REAL ANSWER and is never collapsed into
            # 'disconnected': if the module cannot be reached or refuses to
            # answer, that is "we could not look", not "there is no tunnel".
            # The same rule the Windows call site writes beside its own version
            # of these lines.
            #
            # CACHED FOR TWO SECONDS, RVP-13, 2026-09-27. This call sits in
            # _on_packet, which scapy invokes FOR EVERY CAPTURED FRAME, and the
            # module's own status() reads the whole interface table through
            # psutil — measured on this host at 0.19 ms a call with three
            # interfaces, on a capture path that was measured in this same
            # column at 0.79 ms a packet after the sniffer round. So the stamp
            # cost a quarter of the per-packet budget to answer a value that
            # changes when somebody runs WireGuard, not between two frames.
            # Two seconds is chosen to be far shorter than any tunnel coming up
            # or going down by hand, and far longer than the gap between two
            # frames: measured against the live store, the busiest hour on this
            # host was 26.4 packets/second.
            vpn_state = self._vpn_state_now()

            me.save_packet(
                session_id=self.session_id,
                src_ip=data["src_ip"],
                dst_ip=data["dst_ip"],
                src_port=data.get("src_port"),
                dst_port=data.get("dst_port"),
                protocol=data.get("protocol"),
                direction=data.get("direction"),
                packet_size=data.get("length"),
                # The payload is NOT stored. It was 566 MB of a 1.6 GB
                # database on the Windows side for 242 flagged rows, and this
                # module keeps the bytes for its own signature check and
                # throws them away after. See memory_engine.save_packet.
                payload_snippet=None,
                threat_label=None,
                scope=data.get("scope"),
                process_name=data.get("process_name"),
                process_pid=data.get("pid"),
                vpn_state=vpn_state,
            )

            # SNF-11. This host's own DNS questions, from the capture, so the
            # feed matcher and the DNS reader see them without a resolver log.
            try:
                q = sn.dns_query_of(pkt)
                # mDNS is constant background chatter from every device, so
                # only this host's own mDNS questions are kept.
                if q and (q["protocol"] != "mdns"
                          or sn.is_self_address(data["src_ip"])):
                    self._queue_dns(q, data)
                answers = sn.dns_answers_of(pkt)
                if answers:
                    self._queue_dns_answers(answers, data)
                kind = sn.encrypted_dns_of(data)
                if kind:
                    self._note_encrypted_dns(kind, data["dst_ip"])
            except Exception as e:
                logger.debug(f"DNS read skipped on a frame: {e}")

            beacon = sn._detect_beaconing(data)
            if beacon:
                dst = beacon["dst_ip"]
                if self._should_emit(f"beacon:{dst}") and not me.is_dismissed("ip", dst):
                    me.save_finding(
                        session_id=self.session_id,
                        source="packet_sniffer",
                        detection_id="PKT-1002",
                        severity=_fit_severity("PKT-1002", "medium", "medium"),
                        entity_type="ip",
                        entity_value=dst,
                        title=f"Regular beaconing to {dst}",
                        description=beacon.get("description"),
                        raw_data={
                            "destination":              dst,
                            "connections":              beacon.get("connection_count"),
                            "mean_interval_seconds":    beacon.get("avg_interval"),
                            "coefficient_of_variation": beacon.get("coefficient_of_variation"),
                            "window_seconds":           beacon.get("window_seconds"),
                            "method": "coefficient of variation of inter-arrival times over CONNECTION ATTEMPTS (SYN without ACK, plus UDP off 53/123), inside a sliding window",
                            "read_by": "tools/packet_sniffer_linux.py",
                        },
                    )

            # PKT-1001 volume_sustained. NEW RAISER 2026-09-23.
            #
            # The register has carried this rule since the packet rules were
            # written and NOTHING raised it: grep found the id in
            # core/detections.py only, and VOLUME_THRESHOLD sat in the sniffer
            # with no reader. Same shape as the ICMP rules before they were
            # ported: the Detections page showed it because the register is
            # the only thing that page reads.
            volume = sn._detect_volume(data)
            if volume:
                src = volume["src_ip"]
                if self._should_emit(f"volume:{src}") \
                        and not me.is_dismissed("ip", src):
                    me.save_finding(
                        session_id=self.session_id,
                        source="packet_sniffer",
                        detection_id="PKT-1001",
                        severity=_fit_severity("PKT-1001", "low", "low"),
                        entity_type="ip",
                        entity_value=src,
                        title=f"Sustained packet volume from {src}",
                        description=volume.get("description"),
                        raw_data={
                            "source":         src,
                            "packet_count":   volume.get("packet_count"),
                            "window_seconds": volume.get("window_seconds"),
                            "read_by": "tools/packet_sniffer_linux.py",
                        },
                    )

            port_hit = sn._detect_dangerous_ports(data)
            if port_hit:
                dst   = port_hit["dst_ip"]
                dport = port_hit["dst_port"]
                # Direction decides the rule. The register carries both.
                inbound = data.get("direction") == "inbound"
                did = "PKT-1013" if inbound else "PKT-1014"
                if self._should_emit(f"port:{did}:{dst}:{dport}") \
                        and not me.is_dismissed("ip", dst):
                    me.save_finding(
                        session_id=self.session_id,
                        source="packet_sniffer",
                        detection_id=did,
                        severity=_fit_severity(did, "low" if inbound else "high",
                                               "low" if inbound else "high"),
                        entity_type="ip",
                        entity_value=dst,
                        title=(f"Connection to dangerous port {dport} "
                               f"({'inbound' if inbound else 'outbound'})"),
                        description=port_hit.get("description"),
                        raw_data={
                            "destination": dst,
                            "port":        dport,
                            "direction":   "inbound" if inbound else "outbound",
                            "read_by":     "tools/packet_sniffer_linux.py",
                        },
                    )

            payload_hit = sn._detect_payload_signatures(data)
            if payload_hit:
                # See the class docstring. A ZIP header under a Metasploit
                # rule is not a finding, it is a false alarm with a critical
                # rule number on it.
                sig = payload_hit.get("signature")
                self._unregistered_counts[f"payload:{sig}"] = \
                    self._unregistered_counts.get(f"payload:{sig}", 0) + 1
                logger.info(
                    f"payload signature {sig!r} "
                    f"({payload_hit.get('description')}) seen going to "
                    f"{payload_hit.get('dst_ip')}. NOT written as a finding: "
                    f"these are bare magic bytes and the register's payload "
                    f"rule (PKT-1010) means a real Metasploit sequence, which "
                    f"this sensor does not look for. Counting it instead.")

            # ICMP ROUTING, TODO 91, PORTED OUT OF THE WINDOWS SNIFFER 2026-09-21.
            #
            # WHY THIS IS HERE AT ALL. The register in core/detections.py has
            # carried PKT-1016 (icmp_routing_from_offlink) and PKT-1017
            # (icmp_routing_source_mismatch) since the packet rules were
            # written, and until now NOTHING IN THIS TREE COULD RAISE THEM:
            # the only raiser was tools/packet_sniffer.py, the stale Windows
            # copy that main.py does not load. So the app advertised two
            # routing rules on its own detections page and could not fire
            # either, which is the same shape as a disabled sensor reading as
            # a quiet network.
            #
            # This is the owner's rule applied rather than quoted: the FILE is
            # Windows-only and is out of the tree, and the PARTS of it that
            # this host needs are ported. See the ledger, THE OWNER'S RULE.
            #
            # WHAT IT READS, and why the source address alone is not the test.
            # A router advertisement is defined by what it CLAIMS, not by
            # where it appears to come from. An RFC 1256 body lists the router
            # addresses it is advertising, so this parses those and compares:
            #
            #   the source is the octet-reverse of an advertised address
            #       -> a byte-order bug in the sender's own stack. The header
            #          is malformed, NOT foreign, and the app used to say the
            #          scariest thing on the page about it. PKT-1017.
            #   the body names a LOCAL router while the source is not local
            #       -> the two fields contradict each other. PKT-1017.
            #   source off this network, nothing reconciling the two
            #       -> PKT-1016, a host outside advertising routes to it.
            #
            # A PALINDROME IS ITS OWN REVERSE, so reversing is only evidence
            # when reversing CHANGES the address. 192.0.2.10 compares equal to
            # itself and there is no discrepancy to report; that case keeps
            # the off-link wording, which is what it is.
            #
            # Wrapped on its own so an ICMP body that will not parse costs
            # this detection and nothing else on the packet.
            #
            # TYPES 5 AND 9, not 9 alone. 5 is a redirect and 9 is a router
            # advertisement; the register's own summary for both rules says
            # "an ICMP message that CHANGES ROUTING", and the Windows tree
            # gates them together in ICMP_ROUTING_TYPES = {5, 9}. Only type 9
            # carries the RFC 1256 address list, so a redirect is evaluated on
            # its source alone, which is what the original does too.
            try:
                if sn.ICMP is not None and pkt.haslayer(sn.ICMP) \
                        and int(pkt[sn.ICMP].type) in (5, 9) \
                        and pkt.haslayer(sn.IP):
                    src = pkt[sn.IP].src
                    icmp_type = int(pkt[sn.ICMP].type)
                    advertised = (_ra_addresses(bytes(pkt[sn.ICMP]))
                                  if icmp_type == 9 else [])
                    did = description = None
                    if advertised:
                        reversed_src = ".".join(reversed(src.split(".")))
                        if reversed_src != src \
                                and reversed_src in advertised:
                            did = "PKT-1017"
                            description = (
                                f"{src} advertises {reversed_src}, which is "
                                f"its own address with the octets reversed. "
                                f"THAT IS A MALFORMED HEADER, not a foreign "
                                f"host: do not read the source as a real "
                                f"address and do not chase where it "
                                f"geolocates to. The sender's stack wrote it "
                                f"wrong.")
                        else:
                            local = [a for a in advertised
                                     if _is_local_address(a)]
                            if local and not _is_local_address(src):
                                did = "PKT-1017"
                                description = (
                                    f"{src} names the local router "
                                    f"{', '.join(local)} while its own "
                                    f"source is not on this network. The two "
                                    f"fields contradict each other; do not "
                                    f"read the source as a real host.")
                    if did is None and not _is_local_address(src):
                        did = "PKT-1016"
                        description = (
                            f"An ICMP router advertisement arrived from "
                            f"{src}, which is not on this network"
                            + (f", and it advertises "
                               f"{', '.join(advertised)}" if advertised else
                               " and its body did not parse")
                            + ". A host outside a network advertising routes "
                              "to it is never ordinary.")
                    if did and self._should_emit(f"icmp:{did}:{src}") \
                            and not me.is_dismissed("ip", src):
                        me.save_finding(
                            session_id=self.session_id,
                            source="packet_sniffer",
                            detection_id=did,
                            severity=_fit_severity(did, "low", "low"),
                            entity_type="ip",
                            entity_value=src,
                            title=("Routing ICMP whose source contradicts "
                                   "its own body"
                                   if did == "PKT-1017" else
                                   "Routing ICMP from an off-network source"),
                            description=description,
                            raw_data={
                                "source":     src,
                                "advertises": advertised,
                                "read_by":    "adapters.py, ported from the "
                                              "Windows sniffer's "
                                              "_check_icmp_routing",
                            },
                        )
            except Exception as e:
                logger.debug(f"ICMP routing check skipped on a frame: {e}")

            # The IPv6 half of the same two rules (SNF-10): router
            # advertisements and redirects, judged by RFC 4861's own rules.
            try:
                icmp6 = sn.icmpv6_layer(pkt)
                if icmp6 is not None and int(icmp6.type) in sn.ICMPV6_ROUTING_TYPES:
                    src = str(pkt[sn.IPv6].src)
                    description = sn.icmpv6_routing_verdict(
                        src, int(pkt[sn.IPv6].hlim), int(icmp6.type))
                    if description and self._should_emit(f"icmp:PKT-1016:{src}") \
                            and not me.is_dismissed("ip", src):
                        me.save_finding(
                            session_id=self.session_id,
                            source="packet_sniffer",
                            detection_id="PKT-1016",
                            severity=_fit_severity("PKT-1016", "low", "low"),
                            entity_type="ip",
                            entity_value=src,
                            title="Routing ICMPv6 from an off-network source",
                            description=description,
                            raw_data={
                                "source":    src,
                                "icmp_type": int(icmp6.type),
                                "hop_limit": int(pkt[sn.IPv6].hlim),
                                "read_by":   "adapters.py, RFC 4861 check",
                            },
                        )
            except Exception as e:
                logger.debug(f"ICMPv6 routing check skipped on a frame: {e}")

            # TODO 113.2 / 113.5 / 113.6, PORTED 2026-09-21.
            #
            # THREE DETECTORS THAT NEED THE RAW FRAME, which is why they are
            # here rather than beside the three above: _analyze_packet returns
            # a summary and throws the layer objects away, and each of these
            # reads a header that the summary does not carry.
            #
            # ALL THREE ARE WRAPPED INDIVIDUALLY. A parser that throws inside
            # the capture callback must cost its own detection and nothing
            # else: the packet row and the three detections above have already
            # been written by this point, and losing a TLS parse must not roll
            # any of it back.

            # TODO 113.2. TLS ClientHello -> the domain behind the encryption.
            try:
                if raw_bytes:
                    self._handle_tls(raw_bytes, data)
            except Exception as e:
                logger.debug(f"TLS parse skipped on a frame: {e}")

            # QUIC: the same ClientHello, inside an encrypted Initial packet.
            try:
                if raw_bytes and data.get("protocol") == "udp" \
                        and data.get("dst_port") in self.QUIC_PORTS:
                    self._handle_quic(raw_bytes, data)
            except Exception as e:
                logger.debug(f"QUIC parse skipped on a frame: {e}")

            # TODO 113.6. The always-on payload ring. Memory only, tiny, and
            # overwritten constantly, so a later flush has the bytes that
            # caused a finding rather than the bytes that came after somebody
            # decided to look.
            if self._payload is not None and raw_bytes:
                try:
                    self._payload.append(
                        src_ip=data["src_ip"], dst_ip=data["dst_ip"],
                        dst_port=data.get("dst_port") or 0,
                        protocol=(data.get("protocol") or "").upper(),
                        direction=data.get("direction") or "",
                        src_port=data.get("src_port"),
                        data=raw_bytes)
                except Exception as e:
                    logger.debug(f"payload ring append skipped: {e}")

        except Exception as e:
            # Never let a packet kill the capture thread.
            logger.debug(f"packet handling error: {e}")

    def _observe_ipv6_lan(self, pkt, sn) -> list:
        """Hand IPv6 neighbour, router and DHCPv6 frames to lan_watch."""
        if sn.IPv6 is None or not pkt.haslayer(sn.IPv6):
            return []
        now = time.monotonic()
        src_ip = str(pkt[sn.IPv6].src)
        ether_mac = (str(pkt[sn.Ether].src)
                     if sn.Ether is not None and pkt.haslayer(sn.Ether) else "")
        hits = []
        if sn.ICMPv6ND_NA is not None and pkt.haslayer(sn.ICMPv6ND_NA):
            na = pkt[sn.ICMPv6ND_NA]
            mac = (str(pkt[sn.ICMPv6NDOptDstLLAddr].lladdr)
                   if sn.ICMPv6NDOptDstLLAddr is not None
                   and pkt.haslayer(sn.ICMPv6NDOptDstLLAddr) else ether_mac)
            hits += self._lan.observe_neighbor_advert(str(na.tgt), mac, now)
        if sn.ICMPv6ND_RA is not None and pkt.haslayer(sn.ICMPv6ND_RA):
            ra = pkt[sn.ICMPv6ND_RA]
            mac = (str(pkt[sn.ICMPv6NDOptSrcLLAddr].lladdr)
                   if sn.ICMPv6NDOptSrcLLAddr is not None
                   and pkt.haslayer(sn.ICMPv6NDOptSrcLLAddr) else ether_mac)
            prefixes = []
            layer = pkt[sn.ICMPv6ND_RA].payload
            while layer and sn.ICMPv6NDOptPrefixInfo is not None:
                if isinstance(layer, sn.ICMPv6NDOptPrefixInfo):
                    prefixes.append(f"{layer.prefix}/{layer.prefixlen}")
                layer = layer.payload if layer.payload else None
            hits += self._lan.observe_router_advert(
                src_ip, mac, int(ra.routerlifetime), prefixes, now)
        for kind, layer in (("advertise", sn.DHCP6_Advertise),
                            ("reply", sn.DHCP6_Reply)):
            if layer is not None and pkt.haslayer(layer):
                duid = ""
                if sn.DHCP6OptServerId is not None \
                        and pkt.haslayer(sn.DHCP6OptServerId):
                    # The option's value after its 4-byte code and length,
                    # cut at its own length: bytes() includes later options.
                    opt = pkt[sn.DHCP6OptServerId]
                    n = int(getattr(opt, "optlen", 0) or 0)
                    duid = bytes(opt)[4:4 + n].hex()
                hits += self._lan.observe_dhcpv6_server(
                    src_ip, ether_mac, duid, kind, now)
                break
        return hits

    @staticmethod
    def _dhcp_server_identity(pkt, bootp, dhcp):
        """
        (address, where_it_came_from) for the server behind an OFFER or ACK.

        WHY THIS EXISTS, MEASURED 2026-09-26 (register section 13): this
        callback used to read `bootp.siaddr`, which is the BOOTP "next
        server" field -- the TFTP server for a PXE boot. On an ordinary
        router OFFER it is 0.0.0.0, so the module never saw the frame at
        all; when it was set, it named a DIFFERENT host and that host was
        recorded as the DHCP server. Either way a value was published as a
        fact about who hands out leases and the field it came from was not.

        THE ORDER IS THE PROTOCOL'S: RFC 2131 section 4.3.1 requires every
        server OFFER and ACK to carry the DHCP SERVER IDENTIFIER option
        (54), so that option is the answer. The packet's own IP source is
        the next best: it is who physically sent the frame. siaddr is kept
        only as a LAST resort, and whichever field was read travels beside
        the value in `server_id_source`, so a finding built on it can say
        where the address came from instead of implying it was the option.

        Returns ("", "none") when none of the three holds a usable address;
        the caller treats that as "this frame was not a server's".
        """
        # Option 54. scapy gives options as (name, value) pairs; the value
        # is a dotted-quad string on both an in-memory and a wire packet.
        for opt in (dhcp.options or []):
            try:
                if opt[0] == "server_id" and len(opt) > 1:
                    candidate = str(opt[1] or "").strip()
                    if candidate and candidate != "0.0.0.0":
                        return candidate, "option-54"
            except (TypeError, IndexError):
                continue
        # The frame's own source address.
        try:
            from tools import packet_sniffer_linux as sn
            if sn.IP is not None and pkt.haslayer(sn.IP):
                src = str(pkt[sn.IP].src or "").strip()
                if src and src != "0.0.0.0":
                    return src, "ip-source"
        except Exception:
            pass
        # Last resort: siaddr, named as what it is.
        candidate = str(getattr(bootp, "siaddr", "") or "").strip()
        if candidate and candidate != "0.0.0.0":
            return candidate, "siaddr"
        return "", "none"

    def _emit_lan_hit(self, hit: dict):
        """
        Write one LAN-100x finding, with the cooldown this tree uses.

        Kept a separate method rather than inlined three times so the cooldown
        key and the dismissal check cannot drift between the ARP path, the
        DHCP path and the name path. The detection id comes from lan_watch
        itself, which is the module that decided the rule.
        """
        from core import memory_engine as me
        did  = hit.get("detection_id")
        ent  = str(hit.get("entity_value") or "")
        if not did or not ent:
            return
        key = f"lan:{did}:{ent}"
        if not self._should_emit(key) or me.is_dismissed(
                hit.get("entity_type", "ip"), ent):
            return
        me.save_finding(
            session_id=self.session_id,
            source="packet_sniffer",
            detection_id=did,
            severity=_fit_severity(did, hit.get("severity", "medium"),
                                   hit.get("severity", "medium")),
            entity_type=hit.get("entity_type", "ip"),
            entity_value=ent,
            title=hit.get("title"),
            description=hit.get("description"),
            raw_data=dict(hit.get("raw_data") or {},
                          read_by="tools/lan_watch.py"),
        )

    # TLS CLIENT HELLO, TODO 113.2, AND THE REASSEMBLY IT NEEDS
    #
    # PORTED 2026-09-21, from the Windows sniffer's _handle_tls. The Windows
    # tree grew this on 2026-09-19 off a measurement: 124 hellos in ten
    # minutes, ONE parsed, 123 truncated, because a post-quantum key share
    # does not fit in a 1460 byte segment. This tree's capture ran the parser
    # per frame and had nowhere to hold the first half, so it wrote an
    # unreadable row for every browser on the machine and read the software
    # nobody cares about. Measured on this host before the port: a
    # browser-shaped hello split at 1460 bytes gives sni_state 'unreadable'
    # per frame and sni 'example.com' reassembled.
    #
    # The bytes held here are a buffer keyed on what a device chose to send,
    # so all three limits are small and all three are enforced: how many
    # flows, how many bytes each, and how long. A flow that goes over any of
    # them is recorded as unreadable WITH THE REASON, never dropped silently,
    # because an unrecorded hello is a destination name this app will not
    # have and nothing would say so.

    def _handle_tls(self, payload: bytes, data: dict):
        """Continue a ClientHello across TCP segments, then record it."""
        from tools import tls_hello

        src, dst = data["src_ip"], data["dst_ip"]
        sport, dport = data.get("src_port"), data.get("dst_port") or 443
        proc_name = data.get("process_name") or ""
        proc_pid  = data.get("pid")

        starts_hello = tls_hello.looks_like_client_hello(payload)
        key = (src, sport, dst, dport)
        seq = data.get("tcp_seq")
        seg_end = ((seq + len(payload)) & 0xFFFFFFFF) if seq is not None else None

        with self._lock:
            held = self._tls_pending.pop(key, None)

        if held is not None:
            # A retransmit must not be appended as if it were new bytes
            # (TP-19). With a sequence number, keep only the bytes past what
            # is held; without one, drop a segment that repeats the held start.
            next_seq = held.get("next_seq")
            if seq is not None and next_seq is not None:
                behind = (next_seq - seq) & 0xFFFFFFFF
                if behind == 0:
                    pass
                elif behind < len(payload):
                    payload = payload[behind:]
                elif behind < 0x80000000:
                    payload = b""
                else:
                    # A gap: a segment in between was never captured.
                    self._record_tls(src, dst, dport, held["proc"][0],
                                     held["proc"][1],
                                     _unreadable("a segment of the hello was "
                                                 "missing from the capture"))
                    return
            elif held["buf"].startswith(payload):
                payload = b""
            if not payload:
                with self._lock:
                    self._tls_pending[key] = held
                return
            # The continuation of a hello this flow already started. The
            # cheap gate is NOT applied to it: the first segment is a
            # handshake record and the rest is raw continuation bytes, so
            # looks_like_client_hello is false on those by construction.
            buf = held["buf"] + payload
            # Attribution comes from the FIRST segment. By the time the
            # second arrives the socket may be gone from the connection
            # table, and an unattributed row would lose the process for
            # exactly the long hellos worth having.
            proc_name = held["proc"][0] or proc_name
            proc_pid  = held["proc"][1] or proc_pid
        elif starts_hello:
            buf = payload
        else:
            # Not the start of a hello and not the continuation of one.
            # Nothing to do, and this is the common case by design.
            return

        if len(buf) > self.MAX_PENDING_BYTES:
            self._record_tls(src, dst, dport, proc_name, proc_pid,
                             _unreadable(f"hello larger than "
                                         f"{self.MAX_PENDING_BYTES} bytes, "
                                         f"not read"))
            return

        info = tls_hello.parse_client_hello(buf)

        if info["truncated"]:
            # Valid so far, the rest is in another packet. Hold it.
            with self._lock:
                if len(self._tls_pending) >= self.MAX_PENDING_HELLOS:
                    # The oldest goes, and it is written as an unreadable
                    # row rather than silently forgotten (TP-6). The row is
                    # written outside the lock, below.
                    oldest = min(self._tls_pending,
                                 key=lambda k: self._tls_pending[k]["at"])
                    evicted = self._tls_pending.pop(oldest, None)
                    self._tls_abandoned += 1
                else:
                    evicted = None
                self._tls_pending[key] = {
                    "buf": buf, "at": time.monotonic(),
                    "proc": (proc_name, proc_pid), "next_seq": seg_end}
            if evicted is not None:
                (e_src, _e_sport, e_dst, e_dport) = oldest
                self._record_tls(
                    e_src, e_dst, e_dport,
                    evicted["proc"][0], evicted["proc"][1],
                    _unreadable(
                        f"evicted from the pending table to make room: more "
                        f"than {self.MAX_PENDING_HELLOS} half-read "
                        f"ClientHellos were being held at once"))
            return

        if held is not None:
            self._tls_reassembled_this_run += 1
        self._record_tls(src, dst, dport, proc_name, proc_pid, info)

    QUIC_PORTS = (443, 8443)
    QUIC_DONE_MAX = 4096

    def _init_capture_extras(self):
        """
        State for QUIC, DNS answers and encrypted DNS. Also run lazily by the
        handlers, so an instance built without __init__ still works.
        """
        # QUIC hellos being reassembled, keyed on the flow and the client's
        # connection ID, and the IDs already read so a retransmit is skipped.
        self._quic_pending = {}
        self._quic_done = collections.OrderedDict()
        self._quic_read_this_run = 0
        self._quic_undecryptable = 0
        self._dns_answer_batch = []
        self._dns_answer_batch_at = time.time()
        self._dns_answers_saved_this_run = 0
        self._encrypted_dns = {"dot_flows": 0, "doq_flows": 0,
                               "doh_hellos": 0, "destinations": {}}

    def _extras(self):
        if "_quic_pending" not in self.__dict__:
            self._init_capture_extras()

    def _handle_quic(self, datagram: bytes, data: dict):
        """Decrypt a client Initial, collect its CRYPTO data, record the hello."""
        from tools import quic_initial, tls_hello

        if not quic_initial.looks_like_initial(datagram):
            return
        self._extras()
        res = quic_initial.decrypt_client_initial(datagram)
        if not res["ok"]:
            # A server's Initial to our port 443 fails the same way; only a
            # flow that never decrypts is counted, by the reaper.
            self._quic_undecryptable += 1
            return
        src, dst = data["src_ip"], data["dst_ip"]
        sport, dport = data.get("src_port"), data.get("dst_port")
        key = (src, sport, dst, dport, res["dcid"])
        with self._lock:
            if key in self._quic_done:
                return
            held = self._quic_pending.get(key)
            if held is None:
                if len(self._quic_pending) >= self.MAX_PENDING_HELLOS:
                    oldest = min(self._quic_pending,
                                 key=lambda k: self._quic_pending[k]["at"])
                    self._quic_pending.pop(oldest, None)
                    self._tls_abandoned += 1
                held = {"asm": quic_initial.CryptoAssembler(),
                        "at": time.monotonic(),
                        "proc": (data.get("process_name") or "",
                                 data.get("pid"))}
                self._quic_pending[key] = held
        try:
            held["asm"].add(res["crypto"])
        except ValueError as e:
            with self._lock:
                self._quic_pending.pop(key, None)
            self._record_tls(src, dst, dport, held["proc"][0], held["proc"][1],
                             _unreadable(f"QUIC hello not read: {e}"),
                             transport="quic")
            return
        record = held["asm"].hello_record()
        if record is None:
            return
        with self._lock:
            self._quic_pending.pop(key, None)
            self._quic_done[key] = True
            while len(self._quic_done) > self.QUIC_DONE_MAX:
                self._quic_done.popitem(last=False)
        self._quic_read_this_run += 1
        self._record_tls(src, dst, dport, held["proc"][0] or
                         (data.get("process_name") or ""),
                         held["proc"][1] or data.get("pid"),
                         tls_hello.parse_client_hello(record), transport="quic")

    def _record_tls(self, src, dst, dport, proc_name, proc_pid, info,
                    transport: str = "tcp"):
        """
        Write one finished hello, readable or not.

        THE KEY NAMES ARE THE PARSE RESULT'S, AND THE WRITER'S ARE DIFFERENT.
        PORTED AND MAPPED 2026-09-21. tools/tls_hello.py returns its failure
        wording under `reason`; memory_engine.save_tls_hellos reads
        `parse_reason`. Nothing connected the two and nothing errors when a
        .get() misses, so every unreadable row went in with parse_reason = ''.
        Two consumers went blind on it, both silent:

          memory_engine.query_tls   the coverage note the TLS card prints had
                                    no wording to print, so it could not say
                                    WHY a hello was unreadable.
          clean_tls_unreadable.py   matches truncation rows by PREFIX on this
                                    column, so it matched nothing and would
                                    have reported "Nothing to remove" on a
                                    database full of them.

        Measured before the fix: written parse_reason '' against a parser
        reason of 'truncated TLS record, the hello spans segments'. The
        Windows tree does not have this because its _record_tls builds the
        row explicitly and names parse_reason itself; this maps it at the
        boundary, which is where the two contracts meet.

        The row is queued and saved in a batch by _flush_tls (TP-17).
        """
        try:
            from tools import packet_sniffer_linux as sn
            if sn.encrypted_dns_of({}, info.get("sni")) == "doh":
                self._note_encrypted_dns("doh", dst)
        except Exception as e:                                # noqa: BLE001
            logger.debug(f"DoH check skipped: {e}")
        parsed = dict(info)
        # `reason` is what the parser and _unreadable() both set. The second
        # half is not decoration: a caller that hands this method a dict which
        # already carries the WRITER's key must not have it wiped, or a
        # mapping added upstream would be silently undone here.
        parsed["parse_reason"] = (
            info.get("reason") or info.get("parse_reason") or "")
        parsed.update({
            "src_ip":       src,
            "dst_ip":       dst,
            "dst_port":     dport or 443,
            "process_name": proc_name or "",
            "process_pid":  proc_pid,
            "transport":    transport,
        })
        with self._lock:
            self._tls_batch.append(parsed)
            due = (len(self._tls_batch) >= self.TLS_BATCH_ROWS
                   or time.monotonic() - self._tls_batch_at
                   >= self.TLS_BATCH_SECS)
        if due:
            self._flush_tls()

    DNS_BATCH_ROWS = 50
    DNS_BATCH_SECS = 5.0

    def _queue_dns(self, q: dict, data: dict):
        """One DNS question as a dns_queries row, saved with its batch."""
        import hashlib
        from tools import dns_monitor
        now = time.time()
        row_id = hashlib.sha1(
            f"{now:.6f}|{data['src_ip']}|{data.get('src_port')}|{q['txid']}|"
            f"{q['domain']}|{q['query_type']}".encode()).hexdigest()[:24]
        with self._lock:
            self._dns_batch.append({
                "queried_at": dns_monitor._iso(now),
                "client_ip": data["src_ip"],
                "domain": q["domain"],
                "query_type": q["query_type"],
                "upstream": data["dst_ip"],
                "source": "capture",
                "source_row_id": row_id,
            })
            due = (len(self._dns_batch) >= self.DNS_BATCH_ROWS
                   or now - self._dns_batch_at >= self.DNS_BATCH_SECS)
        if due:
            self._flush_dns()

    def _flush_dns(self) -> int:
        from core import memory_engine as me
        from core import sensors as snr
        with self._lock:
            rows, self._dns_batch = self._dns_batch, []
            self._dns_batch_at = time.time()
        if not rows:
            return 0
        try:
            out = me.save_dns_queries(rows, sensor_id=snr.LOCAL_SENSOR_ID)
        except Exception as e:
            logger.debug(f"{len(rows)} DNS row(s) not saved: {e}")
            return 0
        self._dns_saved_this_run += int(out.get("inserted") or 0)
        return int(out.get("inserted") or 0)

    # Batched because one save per hello blocked the capture thread about
    # 100 times longer than one save for the batch (TP-17).
    ENCRYPTED_DNS_MAX_DESTS = 64

    def _queue_dns_answers(self, answers: dict, data: dict):
        """One DNS reply's answers as dns_answer rows, saved with their batch."""
        from tools import dns_monitor
        from tools import packet_sniffer_linux as sn
        self._extras()
        now = time.time()
        seen = dns_monitor._iso(now)
        # A multicast reply is for everyone on the link, not one client.
        multicast = sn.is_group_address(data["dst_ip"])
        rows = [{
            "seen": seen, "name": name, "rrtype": rrtype, "value": value,
            "ttl": ttl,
            "client_ip": "" if multicast else data["dst_ip"],
            "resolver": data["src_ip"],
            "protocol": answers["protocol"],
        } for name, rrtype, value, ttl in answers["answers"]]
        with self._lock:
            self._dns_answer_batch.extend(rows)
            due = (len(self._dns_answer_batch) >= self.DNS_BATCH_ROWS
                   or now - self._dns_answer_batch_at >= self.DNS_BATCH_SECS)
        if due:
            self._flush_dns_answers()

    def _flush_dns_answers(self) -> int:
        from core import memory_engine as me
        from core import sensors as snr
        self._extras()
        with self._lock:
            rows, self._dns_answer_batch = self._dns_answer_batch, []
            self._dns_answer_batch_at = time.time()
        if not rows:
            return 0
        try:
            out = me.save_dns_answers(rows, sensor_id=snr.LOCAL_SENSOR_ID)
        except Exception as e:
            logger.debug(f"{len(rows)} DNS answer row(s) not saved: {e}")
            return 0
        self._dns_answers_saved_this_run += int(out.get("new") or 0)
        return int(out.get("new") or 0)

    def _note_encrypted_dns(self, kind: str, dst: str):
        """Count a DNS flow this sensor cannot read, and where it went."""
        self._extras()
        with self._lock:
            enc = self._encrypted_dns
            enc["doh_hellos" if kind == "doh" else f"{kind}_flows"] += 1
            dests = enc["destinations"]
            if dst in dests or len(dests) < self.ENCRYPTED_DNS_MAX_DESTS:
                dests[dst] = kind

    def encrypted_dns_state(self) -> dict:
        """What name resolution this sensor could not read, for status()."""
        self._extras()
        enc = self._encrypted_dns
        total = enc["dot_flows"] + enc["doq_flows"] + enc["doh_hellos"]
        return {
            "dot_flows": enc["dot_flows"],
            "doq_flows": enc["doq_flows"],
            "doh_hellos": enc["doh_hellos"],
            "destinations": dict(enc["destinations"]),
            "note": ("No encrypted DNS seen, so this host's name lookups "
                     "reached the capture in the clear." if not total else
                     "Some name lookups went over encrypted DNS (DoT, DoQ or "
                     "DoH). Those names are NOT in dns_queries or dns_answer; "
                     "a missing name is not proof it was never looked up."),
        }

    TLS_BATCH_ROWS = 50
    TLS_BATCH_SECS = 5.0

    def _flush_tls(self) -> int:
        """Save the waiting hellos in one call. Returns how many were saved."""
        from core import memory_engine as me

        with self._lock:
            rows, self._tls_batch = self._tls_batch, []
            self._tls_batch_at = time.monotonic()
        if not rows:
            return 0
        try:
            result = me.save_tls_hellos(rows, session_id=self.session_id)
        except Exception as e:
            # A TLS failure must not cost the packet row or the sibling
            # detections on the same frame.
            logger.debug(f"{len(rows)} TLS row(s) not saved: {e}")
            return 0
        self._tls_saved_this_run = getattr(
            self, "_tls_saved_this_run", 0) + int(result.get("new") or 0)
        self._tls_unreadable_this_run = getattr(
            self, "_tls_unreadable_this_run", 0) + sum(
                1 for r in rows if r.get("sni_state") == "unreadable")
        return len(rows)

    def _reap_pending_tls(self, now: float = None, force: bool = False,
                          reason: str = None) -> int:
        """
        Give up on half-read hellos whose rest never arrived, and SAY SO.

        A continuation can be lost to a reordered capture, a connection that
        died mid-handshake, or a frame this sensor dropped. Whatever the
        cause, the honest record is one unreadable row per abandoned flow, so
        the coverage count stays true rather than showing a hello that simply
        vanished. Returns how many it reaped.

        THE TTL IS A LOWER BOUND, NOT A CLOCK, and that is worth stating
        because the row's own wording could be misread as one. This runs from
        poll(), which the base adapter drives every `poll_interval` seconds
        (60 by default), so a half hello is given up on at the first poll
        AFTER PENDING_TTL_SEC has passed, which can be up to a minute later.
        The sentence written is "the rest of the hello never arrived within
        10s" and that remains exactly true either way. What it costs in the
        meantime is memory, and that is bounded: MAX_PENDING_HELLOS flows of
        at most MAX_PENDING_BYTES each, so a few megabytes at the ceiling and
        nothing on an ordinary network.

        force=True REAPS EVERYTHING REGARDLESS OF AGE, and it exists for the
        one moment where waiting for the TTL is meaningless: the sensor is
        being STOPPED. MEASURED 2026-09-26 (register section 14): stop()
        dropped the pending dict with no row at all, so a hello whose second
        segment was still in flight when the app shut down vanished from the
        coverage count -- the same silence the TTL reaper exists to remove,
        on the one path that has no later poll to catch it. The caller passes
        its own `reason` so the row says WHY it was given up on.
        """
        now = now if now is not None else time.monotonic()
        with self._lock:
            if force:
                expired = list(self._tls_pending.items())
                self._tls_pending.clear()
            else:
                expired = [(k, h) for k, h in self._tls_pending.items()
                           if now - h["at"] >= self.PENDING_TTL_SEC]
                for key, _held in expired:
                    self._tls_pending.pop(key, None)
            self._extras()
            if force:
                quic_expired = list(self._quic_pending.items())
                self._quic_pending.clear()
            else:
                quic_expired = [(k, h) for k, h in self._quic_pending.items()
                                if now - h["at"] >= self.PENDING_TTL_SEC]
                for key, _held in quic_expired:
                    self._quic_pending.pop(key, None)
        why = reason or (f"the rest of the hello never arrived within "
                         f"{self.PENDING_TTL_SEC}s")
        for (src, _sport, dst, dport), held in expired:
            self._record_tls(src, dst, dport, held["proc"][0], held["proc"][1],
                             _unreadable(why))
        for (src, _sport, dst, dport, _dcid), held in quic_expired:
            self._record_tls(src, dst, dport, held["proc"][0], held["proc"][1],
                             _unreadable(f"QUIC: {why}"), transport="quic")
        return len(expired) + len(quic_expired)

    def tls_run_counts(self) -> dict:
        """The five TLS counters, cheap enough for a page to ask (TP-7)."""
        return {
            "read":        getattr(self, "_tls_saved_this_run", 0),
            "unreadable":  getattr(self, "_tls_unreadable_this_run", 0),
            "reassembled": getattr(self, "_tls_reassembled_this_run", 0),
            "pending":     len(self._tls_pending),
            "waiting_to_save": len(self._tls_batch),
            "dns_from_capture_saved": getattr(self, "_dns_saved_this_run", 0),
            "dns_answers_saved": getattr(self, "_dns_answers_saved_this_run", 0),
            "abandoned":   self._tls_abandoned,
            "quic_read":   getattr(self, "_quic_read_this_run", 0),
            "quic_pending": len(getattr(self, "_quic_pending", {})),
            "quic_undecryptable": getattr(self, "_quic_undecryptable", 0),
        }

    def status(self) -> dict:
        from tools import packet_sniffer_linux as sn

        out = super().status()
        try:
            available, reason = sn.check_capture_capability()
        except Exception as e:
            available, reason = False, f"capability check failed: {e}"

        out["scapy"] = sn.SCAPY_AVAILABLE
        out["packets_this_run"] = self._packets_seen
        out["capture_reason"] = reason

        # WHICH INTERFACE, AND WHY THAT ONE. 2026-09-22.
        #
        # Added with the loopback fix. The module picked lo for the whole life
        # of the port and nothing outside a log line said so, so every tool
        # that depended on capture reported healthy. These two keys are the
        # fact that was missing; `capture_blind_reason` is deliberately NOT
        # set here, because capture on a real interface with no traffic is a
        # different sentence from capture that could not start.
        out["capture_interface"] = sn.capture_interface()
        out["capture_interface_reason"] = sn.capture_interface_reason()

        # SNF-3 / SNF-4 / SNF-6 / SNF-7 / SNF-13 / SNF-15. THE PARTS A
        # READER COULD NOT GET. 2026-09-23.
        #
        # Each of these is a question the app could not answer before, and
        # each is reported as its own block rather than flattened, because the
        # note inside each one is the part that stops a number being read as a
        # clean answer:
        #
        #   capture_state  is the THREAD alive (a dead capture read as healthy)
        #   capture_settings what it was started with (promisc, filter, buffer)
        #   counters       what the kernel carried and dropped (SNF-4)
        #   attribution    the socket snapshot's size and age (SNF-3/SNF-13)
        #   detections     the three tables' sizes and the SKIP REASONS
        out["capture_state"] = sn.capture_state()
        out["capture_settings"] = {
            "promiscuous": getattr(self, "_promisc", None),
            "filter": getattr(self, "_filter", None),
            "rcvbuf": getattr(self, "_rcvbuf", None),
        }
        out["counters"] = sn.capture_counters()
        out["attribution"] = sn.attribution_state()
        out["detections"] = sn.detection_state()

        # TODO 113.2 / 113.5 / 113.6, PORTED 2026-09-21.
        #
        # THE THREE NUMBERS STAY APART. "hellos read" on its own would let a
        # run that could not parse a single handshake look the same as a run on
        # a machine that speaks no TLS, so the readable count, the unreadable
        # count and the dropped count are published separately and never
        # summed. Same rule as every other sensor in this tree.
        #
        # lan and payload are carried WHOLE rather than flattened, because the
        # notes list is the part that stops a quiet LAN result being read as a
        # clean one. A caller that takes the counts and drops the notes has
        # taken the half that can lie.
        out["tls_hellos_this_run"]     = getattr(self, "_tls_saved_this_run", 0)
        out["tls_unreadable_this_run"] = getattr(self, "_tls_unreadable_this_run", 0)
        # TODO 113.2. The two numbers that separate "every browser on this
        # machine was read" from "the small updater hellos were read", which
        # is exactly the difference the reassembly exists to make. Measured
        # here before the port: 0 of 1 readable, because a single frame is
        # never enough for a modern hello.
        out["tls_reassembled_this_run"] = getattr(
            self, "_tls_reassembled_this_run", 0)
        out["tls_pending"]             = len(self._tls_pending)
        out["tls_abandoned_this_run"]  = self._tls_abandoned
        out["quic_hellos_this_run"]    = getattr(self, "_quic_read_this_run", 0)
        out["quic_undecryptable_this_run"] = getattr(self, "_quic_undecryptable", 0)
        out["dns_answers_this_run"]    = getattr(self, "_dns_answers_saved_this_run", 0)
        try:
            out["encrypted_dns"] = self.encrypted_dns_state()
            out["attribution_ebpf"] = sn.ebpf_attribution_state()
        except Exception as e:
            out["encrypted_dns"] = {"note": f"not readable: {e}"}
        out["ipv6_lan_decode_available"] = (
            getattr(sn, "ICMPv6ND_NA", None) is not None
            and getattr(sn, "DHCP6_Advertise", None) is not None)
        out["arp_capture_available"]   = getattr(sn, "ARP", None) is not None
        out["dhcp_decode_available"]   = (getattr(sn, "BOOTP", None) is not None
                                          and getattr(sn, "DHCP", None) is not None)
        try:
            out["lan"] = self._lan.status() if self._lan is not None else {
                "running": False,
                "notes": ["The LAN checks are not running, so nothing was "
                          "examined. That is not the same as a quiet LAN."]}
        except Exception as e:
            out["lan"] = {"running": False, "notes": [f"LAN status failed: {e}"]}
        try:
            out["payload"] = (self._payload.status() if self._payload is not None
                              else {"ring_enabled": False,
                                    "note": ("No payload ring is active, so no "
                                             "bytes were held. That is a fact "
                                             "about the ring, not about the "
                                             "traffic.")})
        except Exception as e:
            out["payload"] = {"ring_enabled": False,
                              "note": f"payload ring status failed: {e}"}

        # THIS IS THE ONE THE REST OF THE APP READS. Unelevated, capture
        # cannot work, and reporting running:true with zero packets would make
        # every "no traffic to that address" answer wrong in the same
        # direction. sensor_health turns blind into a caveat on every tool
        # result that depends on capture.
        if not available:
            out["blind"] = True
            out["blind_reason"] = (
                f"{reason}. No packet was captured, so an empty result is a "
                f"statement about privileges on this host and not about the "
                f"network. Run elevated, or grant CAP_NET_RAW.")
        else:
            out["blind"] = not self._capturing
            if out["blind"]:
                out["blind_reason"] = (
                    "Capture is possible on this host but this sensor is not "
                    "running, so nothing was captured this session.")
            out["running"] = self._capturing

        if self._unregistered_counts:
            out["unregistered_finding_types"] = dict(self._unregistered_counts)
        return out


# LOCAL INTEGRITY. L3, 2026-09-22.
#
# THE FIRST SENSOR THAT WATCHES THIS MACHINE'S OWN FILES. Everything else in
# this file watches traffic, processes, logs or a remote host. The remote twin
# is tools/linux_monitor.py, and this is deliberately NOT that module pointed
# at localhost: doing that would build a paramiko session and a host-key
# requirement onto the machine we are already sitting on, to read files this
# process can open directly. linux_monitor is left exactly as it was and keeps
# reading other hosts.
#
# TWO TIERS ON TWO CLOCKS, and the second clock is the point.
#
# Tier A is files and directory sets, on the poll interval. Measured at about
# a second for the whole set on this host.
#
# Tier B is the setuid, setgid and file-capability sweep, which has to walk the
# filesystem. MEASURED ON THIS HOST, 2026-09-22, before any of this was wired:
#
#     python os.walk over / with the prune list     30 to 40 seconds
#     the same walk plus getxattr per file          about 40 seconds
#     getcap -r /  (the tool, a process per file)   150 seconds
#     936,143 files seen; 19 setuid, 9 setgid, 3 with capabilities
#
# A 40 second walk on a 60 second loop is not a slow sensor, it is a stalled
# one: tier A would be delayed by every sweep and the poll interval would
# silently stretch, which is exactly the failure this project writes whole
# modules about. So the sweep gets its own daemon thread and its own interval,
# and its lateness is REPORTED rather than absorbed.
#
# ONE WALK, NOT THREE. getcap is 150s because it spawns a process per file.
# Reading the security.capability xattr inside the walk that already exists
# costs nothing measurable and returns the same three answers. The walk also
# reports which directories it could not enter, which getcap cannot do at all:
# its silence on an unreadable directory is indistinguishable from that
# directory holding nothing.
class LinuxLocalIntegrity(_BaseAdapter):
    """Wraps tools/local_integrity.py, which reads THIS host directly."""

    role = "local_integrity"

    def __init__(self, session_id, config=None):
        super().__init__(session_id, config)
        self._tier_a = {"passes": 0, "findings": 0, "last": None,
                        "last_seconds": None, "coverage": {}, "seeded": [],
                        "capped": [], "off": False}
        self._sweep = {"sweeps": 0, "findings": 0, "last": None,
                       "last_seconds": None, "counts": None,
                       "files_seen": None, "unreadable_dirs": [],
                       "in_progress": False, "seeded": False,
                       "last_error": None, "mac": {}}
        # TIER C'S OWN STATE, on its own clock for the same reason tier B has
        # one: MEASURED at 209s for a full run on this host, which is three and
        # a half minutes of dpkg, 151 MB of control files and a lock shared
        # with apt. Nothing about that belongs on a 60 second poll.
        self._dpkg = {"runs": 0, "findings": 0, "last": None,
                      "last_seconds": None, "counts": None,
                      "coverage": {}, "seeded": False, "reseeded": 0,
                      "in_progress": False, "last_error": None,
                      "last_reason": None, "aborted": False,
                      "packages_verified": None, "refused_count": None,
                      "excluded_boot": None, "attempts": 0}
        self._sweep_stop = None
        self._sweep_thread = None
        self._dpkg_stop = None
        self._dpkg_thread = None
        # Set when a baseline could not be persisted. That is a real blind
        # spot: the next run reseeds that set and reports no changes for it.
        self._baseline_error = None
        self._unregistered = {}
        # The `enabled` gate's own latch, so the OFF notice is logged once
        # rather than every poll. See poll() for why the key is honoured.
        self._off_logged = False

    # tier A, on the poll loop

    def poll(self):
        """One tier A pass. Tier B rides its own thread, see start()."""
        from tools import local_integrity as li

        # OFF MEANS OFF (EM-12's SHAPE, CAUGHT HERE BY GREP).
        #
        # `sensors.local_integrity.enabled = false` was read by NOTHING: this
        # adapter had no gate at all, while its neighbours (event_monitor,
        # dns_monitor, router_monitor, auditd_monitor) all honour their own
        # `enabled` key. The example config documents the block; an operator
        # who sets `enabled` and watches findings keep arriving has been told
        # a control exists that does not. MEASURED 2026-09-23 by grepping
        # every reader of that key in the tree: zero of them were this one.
        #
        # THE BASELINES ARE DELIBERATELY NOT TOUCHED WHILE IT IS OFF, exactly
        # as the event monitor leaves its cursor: switching the sensor back on
        # compares the CURRENT state against the last recorded one, so a
        # change made while it was off is found rather than adopted.
        cfg = ((self.config.get("sensors", {}) or {})
               .get("local_integrity", {}) or {})
        if cfg.get("enabled") is False:
            if not getattr(self, "_off_logged", False):
                logger.info(
                    "local_integrity: switched OFF in config "
                    "(sensors.local_integrity.enabled = false), so NOTHING is "
                    "watching this machine's own files. The stored baselines "
                    "are left where they are: switching this back on compares "
                    "the current state against them rather than adopting "
                    "whatever changed in between.")
                self._off_logged = True
            self._tier_a["off"] = True
            return
        self._off_logged = False
        self._tier_a["off"] = False

        result = li.tier_a_pass()
        self._tier_a["passes"] += 1
        self._tier_a["last"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        self._tier_a["last_seconds"] = result.get("seconds")
        self._tier_a["coverage"] = result.get("coverage") or {}
        self._tier_a["capped"] = result.get("capped") or []

        if result.get("seeded"):
            self._tier_a["seeded"] = sorted(set(self._tier_a["seeded"])
                                            | set(result["seeded"]))
            logger.info(
                f"local_integrity: seeded the baseline for "
                f"{', '.join(result['seeded'])} and raised NOTHING for it. A "
                f"first look is not a change. This host's own authorized_keys "
                f"is mode 664, so a module that shouted about permissions on "
                f"its first pass would be one its reader learns to skim.")

        self._tier_a["findings"] += self._emit_all(result.get("findings") or [])

    # tier B, on its own thread

    def _sweep_loop(self):
        """
        The sweep, on its own clock.

        DELAYED rather than immediate: a boot is eight sensors starting at once,
        and a filesystem walk competing with that for the disk makes the whole
        start look slow for a reason nobody would guess from the log.
        """
        from tools import local_integrity as li

        if self._sweep_stop.wait(li.FIRST_SWEEP_DELAY):
            return
        while self._running and not self._sweep_stop.is_set():
            try:
                self._sweep_once()
            except Exception as e:
                self._sweep["last_error"] = f"{type(e).__name__}: {e}"
                logger.error(f"local_integrity sweep failed: {e}")
            if self._sweep_stop.wait(self._sweep_interval()):
                return

    def _sweep_interval(self) -> int:
        cfg = ((self.config.get("sensors", {}) or {})
               .get("local_integrity", {}) or {})
        try:
            wanted = int(cfg.get("sweep_interval_seconds", SWEEP_INTERVAL))
        except (TypeError, ValueError):
            wanted = SWEEP_INTERVAL
        return max(SWEEP_MIN_INTERVAL, wanted)

    def _sweep_once(self):
        from tools import local_integrity as li

        self._sweep["in_progress"] = True
        try:
            result = li.tier_b_pass()
            self._sweep["sweeps"] += 1
            self._sweep["findings"] += self._emit_all(result.get("findings") or [])
            self._sweep["last"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            self._sweep["last_seconds"] = result.get("seconds")
            self._sweep["counts"] = result.get("counts")
            self._sweep["files_seen"] = result.get("files_seen")
            self._sweep["unreadable_dirs"] = result.get("unreadable_dirs") or []
            if result.get("seeded"):
                self._sweep["seeded"] = True
                logger.info(
                    f"local_integrity: the setuid, setgid and capability "
                    f"baseline is seeded from {result.get('counts')} over "
                    f"{result.get('files_seen')} entries in "
                    f"{result.get('seconds')}s. Nothing is raised for it: the "
                    f"dpkg lesson, applied before dpkg is built.")
            self._sweep["last_error"] = None
        finally:
            self._sweep["in_progress"] = False

        try:
            self._sweep["mac"] = li.mac_pass()
        except Exception as e:
            self._sweep["mac"] = {"error": f"{type(e).__name__}: {e}"}

    # tier C, on its own thread, slower than tier B

    def _dpkg_loop(self):
        """
        dpkg -V, on the slowest clock in this sensor.

        DELAYED FIVE MINUTES, longer than the sweep's one, and the reason is
        measured rather than cautious: a full run is 209s of dpkg reading 151
        MB of control files with the package database open, and this sensor
        already walks 936,143 files on its own thread. Starting both at boot
        would put two heavy readers on one disk while eight sensors start, and
        the operator would see a slow boot for a reason nothing in the log
        explains.
        """
        from tools import local_integrity as li

        if self._dpkg_stop.wait(self._dpkg_first_delay()):
            return
        while self._running and not self._dpkg_stop.is_set():
            try:
                self._dpkg_once()
            except Exception as e:
                self._dpkg["last_error"] = f"{type(e).__name__}: {e}"
                logger.error(f"local_integrity dpkg verification failed: {e}")
            if self._dpkg_stop.wait(self._dpkg_interval()):
                return

    def _dpkg_interval(self) -> int:
        cfg = ((self.config.get("sensors", {}) or {})
               .get("local_integrity", {}) or {})
        try:
            wanted = int(cfg.get("dpkg_interval_seconds", DPKG_INTERVAL))
        except (TypeError, ValueError):
            wanted = DPKG_INTERVAL
        return max(DPKG_MIN_INTERVAL, wanted)

    def _dpkg_exclude_boot(self) -> bool:
        """
        The /boot knob, read with `is True`/`is False` rather than truthiness.

        A config value of the string "false" is TRUTHY, and this project has
        already been walked past a security gate by exactly that (§1.9/S7). An
        unrecognised value keeps the default rather than being guessed at, and
        the default is exclude.
        """
        cfg = ((self.config.get("sensors", {}) or {})
               .get("local_integrity", {}) or {})
        value = cfg.get("dpkg_exclude_boot", None)
        if value is True or value is False:
            return value
        if isinstance(value, str):
            low = value.strip().lower()
            if low in ("true", "yes", "1", "on"):
                return True
            if low in ("false", "no", "0", "off"):
                return False
        return DPKG_EXCLUDE_BOOT

    def _dpkg_first_delay(self) -> int:
        """
        How long after start the first run waits. Configurable, WITH A FLOOR.

        WHY THIS IS A KNOB AT ALL, when the sweep's equivalent is a constant:
        the production delay is five minutes (a full dpkg run is 209s and the
        boot is already starting eight sensors), and a verification script
        cannot wait five minutes plus three and a half more for every run.
        WITHOUT A KNOB FOR IT, THE ONLY WAY TO VERIFY THIS TIER IS TO WAIT
        NINE MINUTES, and a check nobody runs is a check that rots.

        THE FLOOR IS NOT ZERO. A first run in the same second as the boot is
        the thing the delay exists to prevent, so the minimum here is 30s --
        long enough that the boot has finished, short enough to verify.
        """
        cfg = ((self.config.get("sensors", {}) or {})
               .get("local_integrity", {}) or {})
        try:
            wanted = int(cfg.get("dpkg_first_delay_seconds", FIRST_DPKG_DELAY))
        except (TypeError, ValueError):
            wanted = FIRST_DPKG_DELAY
        return max(DPKG_MIN_FIRST_DELAY, wanted)

    def _dpkg_once(self):
        from tools import local_integrity as li

        self._dpkg["in_progress"] = True
        self._dpkg["attempts"] += 1
        try:
            exclude_boot = self._dpkg_exclude_boot()
            result = li.tier_c_pass(exclude_boot=exclude_boot)
            self._dpkg["last_reason"] = result.get("reason")
            self._dpkg["last_seconds"] = result.get("seconds")
            self._dpkg["counts"] = result.get("counts")
            self._dpkg["coverage"] = result.get("coverage") or {}
            self._dpkg["aborted"] = bool(result.get("aborted"))
            self._dpkg["packages_verified"] = result.get("packages_verified")
            self._dpkg["refused_count"] = result.get("refused_count")
            self._dpkg["excluded_boot"] = result.get("excluded_boot")

            if not result.get("ran"):
                # A RUN THAT DID NOT HAPPEN IS NOT A RUN. The counters that
                # say "this sensor has verified your packages" do NOT move,
                # because moving them would make the status block claim
                # coverage the machine does not have. The reason is kept so
                # the dashboard can print why.
                logger.warning(
                    f"local_integrity: dpkg verification did NOT run: "
                    f"{result.get('reason')}")
                return

            self._dpkg["runs"] += 1
            self._dpkg["last"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            self._dpkg["findings"] += self._emit_all(result.get("findings") or [])
            if result.get("seeded"):
                self._dpkg["seeded"] = True
                logger.info(
                    f"local_integrity: the dpkg baseline is SEEDED from "
                    f"{result.get('packages_verified')} package(s) in "
                    f"{result.get('seconds')}s. Nothing is raised for the "
                    f"package files themselves: this is the owner's rule, so "
                    f"that firefox's icons and the kernel images are known-"
                    f"normal on day one rather than a page of findings. What "
                    f"IS raised is the {result.get('refused_count')} package(s) "
                    f"dpkg cannot check at all, because that is a hole in "
                    f"coverage rather than a change.")
            if result.get("reseeded"):
                self._dpkg["reseeded"] += 1
            if result.get("aborted"):
                logger.warning(
                    f"local_integrity: dpkg -V aborted before finishing: "
                    f"{result.get('reason')}")
            self._dpkg["last_error"] = None
        finally:
            self._dpkg["in_progress"] = False

    # writing

    def _emit_all(self, findings: list) -> int:
        """
        Write each finding, or count it and say why not.

        THE UNREGISTERED CASE IS COUNTED, NOT SWALLOWED. Every id this module
        raises IS registered in core/detections, so this should never fire; if
        somebody adds a check here and forgets the register, the count and the
        log line are what make it visible rather than a rule that quietly
        writes nothing at all.
        """
        from core import detections as det
        from core import memory_engine as me

        written = 0
        for f in findings:
            did = f.get("detection_id")
            try:
                det.get(did)
            except Exception as e:
                self._unregistered[did] = self._unregistered.get(did, 0) + 1
                logger.warning(
                    f"local_integrity produced {did!r} for "
                    f"{f.get('entity_value')} and there is NO registered "
                    f"detection id for it, so it was NOT written: {e}")
                continue

            entity_type = f.get("entity_type") or "file"
            entity_value = f.get("entity_value") or ""
            if not entity_value:
                continue
            if me.is_dismissed(entity_type, entity_value):
                continue
            if me.finding_already_open(self.role, entity_type, entity_value,
                                       f.get("title") or ""):
                # Already open and undismissed. The baseline has moved past
                # this change; the row that reports it is already on the board.
                # Raised once per change, not once per pass.
                continue

            severity = _fit_severity(did, f.get("severity", "medium"), "medium")
            me.save_finding(
                session_id=self.session_id,
                source=self.role,
                detection_id=did,
                severity=severity,
                entity_type=entity_type,
                entity_value=entity_value,
                title=f.get("title") or f"{did} fired",
                description=f.get("description"),
                raw_data=f.get("raw_data") or {},
            )
            written += 1
        return written

    # lifecycle

    def start(self):
        from tools import local_integrity as li

        cfg = ((self.config.get("sensors", {}) or {})
               .get("local_integrity", {}) or {})
        if cfg.get("enabled") is False:
            # The two heavy threads are NOT started either. Honouring the key
            # on the poll loop alone would leave a 940,000-file walk and a
            # dpkg run going while the operator believes the sensor is off.
            logger.info(
                "local_integrity: switched OFF in config, so the tier A poll "
                "loop, the setuid sweep thread and the dpkg verification "
                "thread are all NOT started. Nothing is watching this "
                "machine's own files.")
            super().start()
            return

        self._sweep_stop = threading.Event()
        self._sweep_thread = threading.Thread(target=self._sweep_loop,
                                              name="local_integrity-sweep",
                                              daemon=True)
        self._sweep_thread.start()
        logger.info(
            f"local_integrity: watching THIS host. Tier A every "
            f"{self.poll_interval}s over {len(li.WATCHED_FILES)} files, "
            f"{len(li.DIR_WATCH_HASHED)} hashed directory sets, "
            f"{len(li.DIR_WATCH_PRESENCE)} presence-only directory and every "
            f"real home's SSH artifacts. Tier B, the setuid/setgid/capability "
            f"sweep, every {self._sweep_interval()}s starting "
            f"{li.FIRST_SWEEP_DELAY}s from now, on its own thread because it "
            f"walks about 940,000 files and takes 30 to 40 seconds here.")
        self._dpkg_stop = threading.Event()
        self._dpkg_thread = threading.Thread(target=self._dpkg_loop,
                                             name="local_integrity-dpkg",
                                             daemon=True)
        self._dpkg_thread.start()
        logger.info(
            f"local_integrity: tier C, the package verification, runs "
            f"`dpkg -V` over the packages dpkg can load, every "
            f"{self._dpkg_interval()}s starting {self._dpkg_first_delay()}s "
            f"from now, on its own thread. MEASURED on this host: a bare "
            f"`dpkg -V` ABORTS with exit 2 on one malformed control file, so "
            f"this names the packages it can verify instead, 2755 of 2756, "
            f"and that run takes 209s. /boot is "
            f"{'EXCLUDED' if self._dpkg_exclude_boot() else 'INCLUDED'} by "
            f"config.")
        super().start()

    def stop(self):
        if self._sweep_stop is not None:
            self._sweep_stop.set()
        if self._dpkg_stop is not None:
            self._dpkg_stop.set()
        super().stop()

    # status

    def status(self) -> dict:
        """
        What this sensor can see. Read by /api/status and by sensor_health.

        BLIND IS RESERVED FOR THE CASES WHERE IT COULD NOT DO ITS JOB. An
        unelevated run cannot read /etc/sudoers, and that is a permanent,
        documented limit of the run rather than a fault: reporting blind for it
        would attach a caveat to every query_findings answer for the life of
        the installation, which is how a warning list becomes something a
        reader skips past. The limit travels in `coverage_limits` and in the
        coverage block instead.

        Blind is for three real cases, and they are the three below: the last
        pass threw, the account database itself could not be read (which takes
        every home and every key file with it), or a baseline could not be
        saved, which means the next run reseeds that set and reports no changes
        for it.
        """
        out = super().status()
        coverage = self._tier_a.get("coverage") or {}
        out["tier_a"] = dict(self._tier_a)
        out["tier_b"] = {k: v for k, v in self._sweep.items()
                         if k != "unreadable_dirs"}
        out["tier_b"]["unreadable_dir_count"] = len(
            self._sweep.get("unreadable_dirs") or [])
        out["tier_c"] = dict(self._dpkg)
        out["baselines"] = self._baselines()
        out["scope_note"] = (
            "The machine AgentalSec is running on, read directly. This is NOT "
            "tools/linux_monitor.py, which reads remote hosts over SSH.")

        # TIER C'S OWN LIMIT, STATED IN WORDS.
        #
        # The unelevated fact applies here more sharply than anywhere else in
        # this sensor: dpkg reports an unreadable file as `missing ... (Permission
        # denied)`, which reads like a deletion. It is stated rather than
        # reported as blind, for the same reason the sudoers limit is: this is
        # a permanent property of an unelevated run, and a caveat attached to
        # every answer forever is a caveat a reader skips.
        if self._tier_a.get("off"):
            # OFF BY CONFIG IS ITS OWN STATE, exactly as auditd's OFF BY
            # CONFIG is. A sensor switched off and a sensor that found nothing
            # produce the same empty findings list, and only a sentence
            # separates them.
            out["off_by_config"] = True
            out["note"] = (
                "THIS SENSOR IS SWITCHED OFF IN CONFIG "
                "(sensors.local_integrity.enabled = false). Nothing is "
                "watching this machine's own files: no /etc/passwd or sudoers "
                "watch, no authorized_keys check, no setuid or capability "
                "sweep, no package verification. A quiet answer here is not a "
                "clean machine.")
        elif not self._dpkg.get("runs"):
            out["tier_c_state"] = (
                "NO PACKAGE VERIFICATION HAS COMPLETED on this sensor since it "
                "started"
                + (f", and the last attempt did not run: {self._dpkg['last_reason']}"
                   if self._dpkg.get("last_reason") else "")
                + ". Nothing here says whether the files your packages shipped "
                  "are intact. The first run seeds, takes about 3.5 minutes "
                  "(measured on this host), and starts "
                  f"{self._dpkg_first_delay()}s after the sensor does.")
        else:
            cov = self._dpkg.get("coverage") or {}
            parts = [
                f"dpkg verified {self._dpkg.get('packages_verified')} package(s) "
                f"in {self._dpkg.get('last_seconds')}s on {self._dpkg.get('last')}",
                f"{self._dpkg.get('refused_count')} package(s) are ones dpkg "
                f"REFUSES to load and are therefore NOT covered by this check "
                f"at all",
            ]
            if cov.get("files_unreadable"):
                parts.append(
                    f"{cov['files_unreadable']} file(s) came back as ones dpkg "
                    f"could not read. On an unelevated run that is every /boot "
                    f"kernel image: it is a statement about this process's "
                    f"privilege, NOT about those files, and they have NOT been "
                    f"checked")
            if cov.get("files_gone"):
                parts.append(f"{cov['files_gone']} file(s) a package shipped "
                             f"are genuinely absent")
            if cov.get("excluded_boot"):
                parts.append("/boot is excluded by config")
            out["tier_c_coverage_limits"] = ". ".join(parts) + "."

        meta = coverage.get("files_metadata_only") or []
        if meta:
            out["files_metadata_only"] = meta
            out["coverage_limits"] = (
                f"{len(meta)} watched file(s) are METADATA ONLY on this run: "
                + ", ".join(meta)
                + ". Name, mode, owner, size and mtime are watched; the "
                  "CONTENTS are not readable, so a content edit that leaves "
                  "all of those identical is NOT detected for those files.")
        if self._tier_a.get("capped"):
            out["capped_sets"] = self._tier_a["capped"]

        unreadable = coverage.get("unreadable") or []
        blocking = [u for u in unreadable
                    if u.startswith("/etc/passwd") or u.startswith("/etc/group")]

        if self._last_error:
            out["blind"] = True
            out["blind_reason"] = (
                f"The last pass failed ({self._last_error}), so nothing was "
                f"compared this run. That is a statement about this sensor and "
                f"not about this machine.")
        elif blocking:
            out["blind"] = True
            out["blind_reason"] = (
                f"The account database could not be read ({blocking[0]}), so "
                f"accounts and every home's key files were not examined at "
                f"all. An empty result here is not a clean host.")
        elif self._baseline_error:
            out["blind"] = True
            out["blind_reason"] = self._baseline_error
        else:
            out["blind"] = False

        if self._unregistered:
            out["unregistered_finding_types"] = dict(self._unregistered)
            out["note"] = (
                f"{sum(self._unregistered.values())} finding(s) could not be "
                f"written because this module produced a detection id that is "
                f"not registered: {sorted(self._unregistered)}. That is a gap "
                f"in this app, not a quiet machine.")
        elif not out.get("blind") and not out.get("off_by_config"):
            out["note"] = (
                "Files, directory sets, every real home's SSH artifacts with "
                "their modes, and the setuid/setgid/capability sweep, on this "
                "host. A change is raised once and the baseline moves with it, "
                "so the same change does not repeat on every pass.")
        return out

    def _baselines(self) -> dict:
        """
        Which baselines exist and how big, for the status block.

        READ FROM THE TABLE, v42. This used to read user_preferences under a
        prefix, which is where the baselines lived before they were moved out
        of the table core/integrity hashes as policy. Reading the old keys here
        would have reported every baseline as absent on a database that had
        just been migrated, and that reads exactly like a sensor that has never
        run.
        """
        from tools import local_integrity as li
        from core import memory_engine as me
        out = {}
        try:
            with me._get_conn() as conn:
                rows = conn.execute(
                    f"SELECT name, LENGTH(value_json) AS n "
                    f"FROM {li.BASELINE_TABLE}").fetchall()
            present = {r["name"]: r["n"] for r in rows}
        except Exception as e:
            for name in li.BASELINE_NAMES:
                out[name] = {"present": None, "error": str(e)}
            return out
        for name in li.BASELINE_NAMES:
            out[name] = {"present": name in present,
                         "bytes": present.get(name, 0)}
        return out


# REMEDIATION
#
# THIS ONE IS DIFFERENT IN KIND. The others adapt sensors, which only read.
# This adapts the module that CHANGES the machine, so every check the Windows
# version performs before acting has to survive here, and the Linux module
# does not perform all of them.
#
# What the Windows class checks and the Linux functions do not:
#
#   1. pid is coerced to int at the boundary, with a sentence on failure
#   2. pid must be above a floor (Windows: 100, kernel/session-0)
#   3. the process must NOT be a critical one, checked by NAME at kill time
#   4. the name shown on the approval card must match the name now, which is
#      the only defence against PID reuse during the pause while a person
#      reads the card
#   5. a port must be one integer in 1..65535. iptables accepts ranges and the
#      word "any", so an unchecked value turns a one-port rule into a
#      host-wide block
#   6. an address must be a single IP, not a range or a subnet
#   7. every action writes an action_record finding so it appears in the same
#      timeline as the thing that prompted it
#
# The Linux module has a CRITICAL_PROCESSES set and a PROTECTED_ROOTS list,
# so 3 and the quarantine guard are already there. 1, 2, 4, 5, 6 and 7 are
# this wrapper's job. None of them is optional: the model supplies every one
# of these values.


def _is_local_address(ip: str) -> bool:
    """
    Is this address on our own network, for the routing-ICMP comparison.

    Reads the live Linux sniffer's own test rather than restating it: that
    module already decides what "ours" means for a packet's scope, and a
    second copy of the rule here would drift from it silently. Falls back to
    a conservative reading only if the module cannot be imported, so a
    detection never quietly stops working because an import moved.
    """
    try:
        from tools import packet_sniffer_linux as sn
        return bool(sn._is_private(ip))
    except Exception as e:
        logger.debug(f"local-address test unavailable ({e}); using ipaddress")
        import ipaddress
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return bool(a.is_private or a.is_loopback or a.is_link_local)


def _ra_addresses(icmp_bytes: bytes) -> list:
    """
    The router addresses an RFC 1256 advertisement actually advertises.

    PORTED 2026-09-21 out of the Windows sniffer, where it sat behind the two
    registered routing-ICMP rules that this tree could not raise. RFC 1256,
    after the four-byte ICMP header:

        byte 4     number of addresses
        byte 5     entry size in 32-bit words (2 for IPv4)
        bytes 6-7  lifetime
        byte 8+    entries; the first word of each is the router address

    Returns [] for anything that does not parse as an advertisement. An
    unreadable body is NOT an empty list of claims: the caller distinguishes
    them and says "(body did not parse)" rather than "advertises nothing",
    because those two mean opposite things.
    """
    import ipaddress
    if len(icmp_bytes) < 12 or icmp_bytes[0] != 9:
        return []
    num, size = icmp_bytes[4], icmp_bytes[5]
    if size < 2 or num == 0 or num > 32:
        return []
    out, off, stride = [], 8, size * 4
    for _ in range(num):
        if off + 4 > len(icmp_bytes):
            break
        try:
            out.append(str(ipaddress.IPv4Address(icmp_bytes[off:off + 4])))
        except (ipaddress.AddressValueError, ValueError):
            break
        off += stride
    return out


def _validated_port(port) -> int:
    """One TCP port, or ValueError. Copied in spirit from the Windows class."""
    try:
        value = int(str(port).strip())
    except (TypeError, ValueError):
        raise ValueError(
            f"port must be a single integer between 1 and 65535, got {port!r}. "
            f"Ranges and the word 'any' are refused on purpose: they turn a "
            f"one-port rule into a host-wide block."
        )
    if not 1 <= value <= 65535:
        raise ValueError(f"port must be between 1 and 65535, got {value}.")
    return value


def _validated_ip(value) -> str:
    """A single address, or ValueError. ipaddress does the parsing."""
    import ipaddress
    text = str(value or "").strip()
    if not text:
        raise ValueError("ip is required.")
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        raise ValueError(
            f"{text!r} is not a single IP address. Ranges, subnets and 'any' "
            f"are refused here on purpose: this call blocks one device."
        )
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        raise ValueError(
            f"{text} is a loopback, unspecified or multicast address. There "
            f"is no device there to ban.")
    return str(addr)


def _own_addresses() -> set:
    """Every address this machine answers on. Banning one bans ourselves."""
    import psutil
    found = set()
    try:
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if getattr(a, "address", None):
                    found.add(str(a.address).split("%")[0])
    except Exception as e:
        logger.debug(f"could not read local addresses: {e}")
    return found


# READING ONE SETTING OUT OF config.json
#
# WHY THIS IS A FUNCTION RATHER THAN ONE LINE INSIDE THE GUARD.
#
# The guard below and the test that holds it both have to read the same
# setting, and if each one opens the file its own way then the file can be
# fixed once while the readers disagree about where it is. A guard whose reader
# cannot find the file returns "" and refuses NOTHING, with every test green:
# the inert-control shape REM-13 was ported to avoid, arrived at twice.
#
# So there is ONE reader, the test calls THIS rather than searching for a name
# in the source, and what the guard refuses with is what the test measured.


def read_operator_config() -> dict:
    """
    The operator's real config.json, from the ONE path that names it.

    core/settings.CONFIG_PATH is that path. It is the file main.py loads at
    boot, the file the settings panel writes, and the file the dashboard's
    router toggle writes, so reading the same file those three use is the whole
    point. A second rule for finding the file can be wrong without anything
    failing, which is exactly what happened here (see _configured_router).

    Returns {} when the file is absent or unreadable. Every caller reads this
    only to REFUSE something, so an empty dict narrows nothing and silences
    nothing.
    """
    try:
        from core import settings
        path = settings.CONFIG_PATH
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.debug(f"could not read the operator's config.json: {e}")
        return {}


def _configured_router_from(config: dict) -> str:
    """The router address in one already-read config, or "". Never raises."""
    return str(((config or {}).get("router_monitor") or {})
               .get("host") or "").strip()


def _configured_router() -> str:
    """
    The router address from config.json, if one is set.

    REM-13, 2026-09-24. Copied in meaning from the Windows twin, which has
    carried this guard since the tool was written and explains it in one
    sentence: blocking the gateway from this host takes this host off the
    network, which looks exactly like the tool breaking, and the gateway is
    the one address most likely to be sitting in a finding.

    Only used to REFUSE. Never to allow, never to narrow a block.

    REM-13b, 2026-09-24, MEASURED BEFORE IT WAS CHANGED. This function was
    ported with the twin's PATH as well as its rule, and on this tree the path
    is wrong. `Path(__file__)` HERE is adapters.py at the project root, so
    `parent.parent` is the folder ABOVE the project; the twin resolves
    correctly only because its own source sits one level deeper, in tools/.
    Measured: the two-parent path is <parent of project>/config.json and does
    not exist, while the file main.py loads is the one in the project root.

    So the guard answered "" for every value the operator could set, and
    filling router_monitor.host in by hand would STILL have refused nothing.
    That is worse than a guard waiting for a setting: it is a guard that reads
    as armed and is not, which is the inert-control shape named in the
    docstring that used to sit here.

    Now it reads the file the app actually loads, through read_operator_config
    above. And tests/test_remediation_fixes.py [REM-13] drives the REAL guard
    with the operator's own configuration instead of searching adapters.py for
    the string _configured_router: that search passed for the broken port,
    because a name in a file and a working guard are two different claims.
    """
    return _configured_router_from(read_operator_config())


def _configured_gateway() -> str:
    """The router agent's address from config.json, or "". Refuses only."""
    return str(((read_operator_config() or {}).get("gateway") or {})
               .get("host") or "").strip()


def _identity_matches_pin(ident: dict, pinned) -> bool:
    """
    Is the process holding this pid now the one that was approved.

    REM-6b, 2026-09-24. `_name_matches_pin` below compares ONE name, and the
    name it compares is psutil's — which substitutes basename(argv[0]) once
    /proc/comm is at the kernel's 15-character cap. Measured on this host: a
    copy of /bin/sleep at 'systemd-journald-copy' reports psutil name
    'systemd-journald-copy' while the kernel's comm is 'systemd-journal'. The
    pin therefore compares a value a process can choose, in the one function
    whose entire job is to notice that the thing behind the pid changed.

    It is still a fair question, so it is still the FIRST one asked: the card
    is built from query_processes, which reports psutil's name, and a pin that
    does not match what the card said must refuse. What changes is that a
    failure of the name comparison is no longer the end of the question — the
    identity's OTHER names are asked before anything is refused, because
    /proc/comm and /proc/<pid>/exe are facts the process does not choose.

    MEASURED, both directions, [REM-6] in tests/test_remediation_fixes.py:
      a process whose comm is at the cap matches on comm
      the same process under a different binary does NOT match
      and the disguise case (sanitize.scrub_string) still goes through
    """
    if not pinned:
        return True                      # nothing pinned = nothing to check
    if _name_matches_pin(ident.get("reported_name"), pinned):
        return True
    for field in ("comm", "exe_basename"):
        value = ident.get(field)
        if value and _name_matches_pin(value, pinned):
            return True
    # argv[0]'s basename counts only when the two agree by that route AND the
    # reported name already failed, which is the shape a re-exec leaves.
    cmdline = ident.get("cmdline") or []
    if cmdline:
        import os.path as _osp
        if _name_matches_pin(_osp.basename(cmdline[0]), pinned):
            return True
    return False


def _name_matches_pin(live_name: str, pinned: str) -> bool:
    """
    Is the process holding this pid now the one that was approved.

    The pin exists to catch ONE thing: the pid being reused between the
    operator reading the card and this line running. Nothing else. Case
    differences are not evidence of reuse on any platform.

    THE SECOND COMPARISON, AND WHY IT IS HERE. This function was a plain
    lowered compare, and on this platform that made the disguise case
    UNKILLABLE. `query_processes` is a fenced tool in core/sanitize.py --
    it was added to UNTRUSTED_TOOLS on 2026-09-13 on both trees -- so the
    name the model reads has been through `sanitize.scrub_string`, which
    strips invisible characters. A process name carrying a zero-width or
    bidi character is the Trojan Source disguise, which makes it the process
    most worth ending; the model's pinned copy and the live name then differ
    by exactly those characters while the pid never changed at all.

    MEASURED on this host before the fix:

        real name  'svc\\u200bhost.exe'
        model sees 'svchost.exe'
        _name_matches_pin(real, model_pinned) -> False

    False here is the worst available answer twice over. The kill is refused,
    so the one disguised process is the one that cannot be killed, and the
    refusal says "the pid was reused", which is a statement this function has
    no evidence for. The Windows tree carries the scrub comparison and wrote
    that reasoning beside it on 2026-09-13; this side lost it in the port and
    `tests/test_process_lookup.py` asserts it.

    What this gives up, said plainly: two names that differ ONLY by characters
    the scrubber removes now compare equal, so a pid reused by a process whose
    name is the approved one plus an invisible character would not be caught
    here. That is a much narrower hole than the one it closes, and the
    critical-process list and the operator's own card still apply.
    """
    if live_name is None or pinned is None:
        return False
    live, pin = str(live_name), str(pinned)
    if live.lower() == pin.lower():
        return True
    from core import sanitize
    return (sanitize.scrub_string(live).lower()
            == sanitize.scrub_string(pin).lower())


def _unelevated() -> bool:
    import os
    return os.geteuid() != 0


def _movable_by_me(path: str) -> bool:
    """Whether this account owns the file and can write its directory."""
    import os
    try:
        st = os.lstat(path)
    except OSError:
        return True             # let the module give its own sentence
    return st.st_uid == os.getuid() and os.access(os.path.dirname(
        os.path.abspath(path)), os.W_OK)


def _via_helper(verb: str, *args) -> dict:
    """
    One approved action carried out by the root action helper, in the shape
    the rest of this class returns. Used only when the app is unelevated; the
    first call of a run asks for the operator's password (tools/action_broker).
    """
    from tools import action_broker as ab
    reply = ab.call(verb, *args)
    out = {"success": bool(reply.get("ok")),
           "via": "root action helper (pkexec session)"}
    if reply.get("ok"):
        out.update(reply.get("result") or {})
    else:
        out["error"] = reply.get("refused") or "the helper gave no reason"
        out["refused"] = True
        if reply.get("not_installed"):
            out["not_installed"] = True
            out["needs_root"] = True
        if reply.get("unknown"):
            out["outcome_unknown"] = True
    return out


class LinuxRemediation:
    """
    Wraps tools/remediation_linux.py for the interface tool_registry expects.

    UNELEVATED, the actions that need root go through the root action helper
    (tools/action_helper.py, installed by scripts/install_action_helper.sh),
    which asks for the password once per run of the app. Elevated, the modules
    act directly as before.

    The registry dispatches these methods with keyword arguments that the
    Linux module's bare functions do not accept:
        kill_process(pid=, reason=, expected_name=, session_id=)
        block_port(port=, direction=, reason=, session_id=)
        unblock_port(port=, direction=, reason=, session_id=)
        quarantine_file(file_path=, reason=, session_id=)
        restore_file(folder=, reason=, session_id=)
    """

    def __init__(self, session_id: str, config: dict = None):
        self.session_id = session_id
        self.config     = config or {}

    def start(self):
        from tools import iptables_manager as fw
        detail = fw.detect_backend_detail()
        if detail["backend"] == "none":
            logger.info(
                "Remediation loaded, but no firewall backend exists on this "
                "host. Firewall actions will refuse with that reason rather "
                "than appear to succeed.")
        else:
            logger.info(f"Remediation loaded. Firewall backend: "
                        f"{detail['backend']}. {detail['reason']}")

    def status(self) -> dict:
        from tools import iptables_manager as fw
        import os
        try:
            detail = fw.detect_backend_detail()
        except Exception as e:
            detail = {"backend": f"unreadable: {e}", "reason": str(e)}
        elevated = os.geteuid() == 0
        return {
            "ready":     True,
            "elevated":  elevated,
            "firewall_backend": detail["backend"],
            "firewall_reason": detail["reason"],
            "note": (
                "Killing another user's process and every firewall change "
                "need root. Unelevated, those refuse with a reason rather "
                "than reporting success. Rules this app writes are named "
                "AgentalSec_-something so they can be listed and removed."),
        }

    # process

    def kill_process(self, pid, reason: str, expected_name: str = None,
                     session_id: str = None, include_children: bool = False) -> dict:
        import psutil
        from tools import remediation_linux as rl
        from core import memory_engine as me

        sid = session_id or self.session_id

        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return {"success": False,
                    "error": f"pid must be an integer, got {pid!r}"}

        # ON LINUX THE FLOOR IS 1, NOT 100. The Windows floor exists because
        # pids below 100 there are kernel and session-0 infrastructure. Linux
        # allocates from a shared pool with no such reservation: systemd is
        # pid 1 and a normal process can legitimately hold pid 27. The real
        # protection on both platforms is the by-name critical list, which the
        # Linux module enforces below.
        if pid < 1:
            return {"success": False,
                    "error": f"Refusing to terminate pid {pid}: that is not a "
                             f"process."}

        # REM-1, 2026-09-24. THE APP COULD KILL ITSELF.
        #
        # MEASURED through this class, before the fix: kill_process(os.getpid())
        # returned an EMPTY STRING and the process died with rc -15. Every
        # guard below was skipped, because none of them is about THIS process:
        # 1 is not < 1, psutil reports its own name, there is no expected_name
        # to compare, and the app's own name is not on the critical list. So a
        # model call, or a typo in a pid, ended the monitoring mid-turn and
        # left no record of why — which is the one loss this project's own
        # rules say nobody can detect afterwards.
        #
        # The check lives in the module too (rl.self_protection), because the
        # module is what a test or the app loads directly. Checked FIRST here
        # so the refusal is given before anything else is read: a refusal that
        # depends on a later read is a refusal that can be skipped by whatever
        # makes that read fail.
        refusal = rl.self_protection(pid)
        if refusal:
            logger.warning(f"Refused kill of pid {pid}: {refusal}")
            return {"success": False, "refused": True, "pid": pid,
                    "reason_class": "self", "error": refusal}

        try:
            proc = psutil.Process(pid)
            name = proc.name()
        except psutil.NoSuchProcess:
            return {"success": False, "error": "Process no longer exists"}
        except Exception as e:
            return {"success": False, "error": str(e)}

        # REM-6. THE NAME THIS PATH COMPARES IS PARTLY CHOSEN.
        #
        # psutil's name() is /proc/comm UNLESS comm is at the kernel's
        # 15-character cap, in which case psutil substitutes basename(argv[0])
        # — text the process chooses. Measured: the real systemd-journald
        # reports comm 'systemd-journal' (15 chars) and psutil name
        # 'systemd-journald'; a copy of /bin/sleep placed at
        # 'systemd-journald-copy' reports psutil name 'systemd-journald-copy'.
        # The list's own 16-character entry can never equal the kernel's
        # spelling, so a check against comm alone would MISS the real journald,
        # and a check against psutil alone can be dodged by an argv[0].
        #
        # The identity is read once, here, and both the list check and the pin
        # below are answered from it, so the two cannot disagree.
        ident = rl.process_identity(pid, proc)

        # IS THIS STILL THE PROCESS THEY SAID YES TO. The only defence against
        # pid reuse across the pause while a person reads the approval card.
        #
        # REM-6b: the comparison is now made against ALL of the identity's
        # names rather than psutil's alone. The pin on the card comes from
        # query_processes, which reports psutil's name, so a process whose
        # argv[0] lied after the card was built would be caught by the exe
        # comparison and one that lied before it is caught here.
        if expected_name and not _identity_matches_pin(ident, expected_name):
            logger.warning(f"Refused kill of pid {pid}: it is "
                           f"{rl.reason_ok(ident)} now, and the card said "
                           f"{expected_name}.")
            return {"success": False,
                    "error": (f"pid {pid} is {rl.reason_ok(ident)} now, not "
                              f"{expected_name}. Refusing: the pid was reused "
                              f"between the approval and this line, so killing "
                              f"it would end a different process from the one "
                              f"that was approved. Look it up again with "
                              f"query_processes and ask again if you still "
                              f"want it."),
                    "refused": True, "process": name,
                    "identity": ident}

        match = rl.matches_critical(ident)
        if match:
            logger.warning(f"Refused kill of critical process {name} "
                           f"(pid {pid}, name matched {match}). Reason given "
                           f"was: {reason}")
            return {"success": False, "refused": True, "process": name,
                    "pid": pid, "identity": ident,
                    "critical_matched": match,
                    "error": (f"{name} is on the critical-process list "
                              f"({match}). Refusing to terminate it at pid "
                              f"{pid}. The comparison uses the kernel's own "
                              f"/proc/<pid>/comm, the name the process "
                              f"reports, the running file and argv[0], "
                              f"because each of those is the only readable "
                              f"one in some real case. If this is genuinely "
                              f"the right action, it has to be done outside "
                              f"this tool.")}

        # KILL THEATRE. L2, 2026-09-22.
        #
        # WHAT THIS PREVENTS, in the owner's own word for it. On a systemd host
        # a service unit with Restart=always owns its process: SIGTERM it, the
        # unit goes active (auto-restart), systemd starts it again within
        # seconds, and every reader downstream of this call is told the thing
        # was stopped. The kill succeeded and the thing is still running, and
        # the only record of it is a finding that says "Process killed".
        #
        # SO THE UNIT IS READ FIRST, and what happens depends on the answer:
        #
        #   not_in_a_unit          nothing systemd manages owns it. A signal
        #                          is the end of the process. Kill as before.
        #   supervised_no_restart  a unit owns it and would not bring it back.
        #                          The kill works; the answer carries a note
        #                          saying the tidier act is a unit stop.
        #   supervised             a kill would be undone. REFUSED, with the
        #                          tool that does work named in the sentence.
        #   unknown                the question could not be answered. The kill
        #                          goes ahead with the uncertainty ON THE
        #                          ANSWER, because refusing on an unreadable
        #                          cgroup would take the operator's decision
        #                          away over a permissions problem -- and the
        #                          same mistake in the other direction is what
        #                          this block exists to prevent, so it is named
        #                          rather than hidden.
        #
        # THE REFUSAL IS ONLY FOR THE CASE THE MODULE IS SURE ABOUT. That is
        # the whole design: a supervisor that will definitely resurrect the
        # process is not a judgement call, it is a fact that makes the
        # requested action meaningless.
        unit_facts = None
        try:
            from tools import systemd_units as sd
            unit_facts = sd.unit_state(pid)
        except Exception as e:                              # noqa: BLE001
            logger.warning(f"Could not ask systemd about pid {pid}: {e}")
            unit_facts = {"verdict": "unknown",
                          "verdict_reason": (f"the systemd question could not "
                                             f"be asked at all ({e})")}

        verdict = unit_facts.get("verdict")
        if verdict == "supervised":
            logger.warning(
                f"Refused kill of pid {pid} ({name}): it belongs to "
                f"{unit_facts.get('unit')} which would restart it "
                f"({unit_facts.get('verdict_reason')})")
            return {"success": False, "refused": True, "process": name,
                    "pid": pid, "unit": unit_facts.get("unit"),
                    "supervised": True,
                    "error": (
                        f"pid {pid} ({name}) belongs to the systemd unit "
                        f"{unit_facts.get('unit')}, and that unit is set to "
                        f"restart it. KILLING IT WOULD NOT STOP THE SERVICE: "
                        f"systemd would start it again within seconds while "
                        f"this app reported it as stopped. Use stop_service on "
                        f"{unit_facts.get('unit')} instead, which stops the "
                        f"unit and is verified. If the unit is what you meant "
                        f"to keep running and you want one process gone, that "
                        f"has to be decided outside this tool.")}

        result = rl.kill_process(pid, include_children=bool(include_children))
        if not result.get("success") and result.get("needs_root") \
                and _unelevated():
            # Another account's process. The helper re-checks the same pin
            # (name and start time) as root before it signals anything.
            from tools import action_helper as ah
            fields = ah._stat_fields(pid)
            if fields is None:
                return {"success": False, "error": "Process no longer exists"}
            result = _via_helper("kill_tree" if include_children else "kill",
                                 str(pid), fields[0], str(fields[2]))
        if not result.get("success"):
            return result

        # THE UNIT FACTS TRAVEL WITH THE SUCCESS, so the model can say what the
        # process was part of rather than reporting a bare kill. This is also
        # where the 'unknown' case reaches the reader instead of dying here.
        if unit_facts:
            result["systemd"] = {
                "verdict": verdict,
                "unit": unit_facts.get("unit"),
                "manager": unit_facts.get("manager"),
                "restart": unit_facts.get("restart"),
                "note": unit_facts.get("verdict_reason"),
            }
            if verdict == "supervised_no_restart":
                result["note"] = (
                    f"{name} (pid {pid}) was part of "
                    f"{unit_facts.get('unit')}. That unit does not restart it "
                    f"after a signal, so this kill holds. Stopping the unit is "
                    f"still the cleaner act when the whole service is what you "
                    f"meant, because the manager then records that it ended.")
            elif verdict == "unknown":
                result["note"] = (
                    f"WHETHER THIS STAYS KILLED IS UNKNOWN. {name} (pid {pid}) "
                    f"belongs to a unit this app could not read: "
                    f"{unit_facts.get('verdict_reason')} If that unit restarts "
                    f"its process, the service comes back and this finding "
                    f"will be the only record that anything was stopped.")

        # 7. THE ACTION RECORD. Written so the kill appears in the same
        # timeline as the finding that prompted it. A failure to record does
        # not undo the kill, so it is reported rather than raised.
        try:
            me.save_finding(
                session_id=sid,
                source="remediation",
                detection_id="REM-1001",
                severity="info",
                entity_type="process",
                entity_value=name,
                title=f"Process killed: {name} (pid {pid})",
                description=reason,
                raw_data={"pid": pid, "name": name, "reason": reason,
                          "platform": "linux"},
            )
        except Exception as e:
            logger.error(f"Killed {name} (pid {pid}) but could not record it: "
                         f"{e}")
            result["record_error"] = (
                f"The process was killed. The record of it was NOT written: "
                f"{e}. So this happened, and the findings table does not "
                f"know.")
        return result

    # firewall

    def block_port(self, port, direction: str, reason: str,
                   session_id: str = None) -> dict:
        from tools import iptables_manager as fw
        from core import memory_engine as me

        sid = session_id or self.session_id

        if direction not in ("inbound", "outbound"):
            return {"success": False,
                    "error": f"direction must be 'inbound' or 'outbound', "
                             f"got {direction!r}"}
        try:
            port = _validated_port(port)
        except ValueError as e:
            return {"success": False, "error": str(e)}

        # The firewall module picks the backend that is really in charge
        # (ufw first when it is active — see its header) and refuses with a
        # reason when there is none, so there is nothing to pre-check here.
        result = fw.block_port(port, direction)
        if not result.get("success"):
            return result
        if result.get("ordering_note"):
            logger.info("block_port %s (%s): %s", port, direction,
                        result["ordering_note"])

        try:
            me.save_finding(
                session_id=sid,
                source="remediation",
                detection_id="REM-1002",
                severity="info",
                entity_type="port",
                entity_value=str(port),
                title=f"Port blocked: {port} ({direction})",
                description=reason,
                raw_data={"port": port, "direction": direction,
                          "reason": reason, "platform": "linux"},
            )
        except Exception as e:
            result["record_error"] = (f"The port was blocked. The record of "
                                      f"it was NOT written: {e}")
        return result

    def unblock_port(self, port, direction: str, reason: str,
                     session_id: str = None) -> dict:
        from tools import iptables_manager as fw
        from core import memory_engine as me

        sid = session_id or self.session_id

        if direction not in ("inbound", "outbound"):
            return {"success": False,
                    "error": f"direction must be 'inbound' or 'outbound', "
                             f"got {direction!r}"}
        try:
            port = _validated_port(port)
        except ValueError as e:
            return {"success": False, "error": str(e)}

        # No pre-check here either: unblock refuses with its own reason when
        # there is no backend, and reports not_found (a failure) when there
        # is nothing of ours to remove.
        result = fw.unblock_port(port, direction)
        if not result.get("success"):
            return result

        try:
            me.save_finding(
                session_id=sid,
                source="remediation",
                detection_id="REM-1003",
                severity="info",
                entity_type="port",
                entity_value=str(port),
                title=f"Port unblocked: {port} ({direction})",
                description=reason,
                raw_data={"port": port, "direction": direction,
                          "reason": reason, "platform": "linux"},
            )
        except Exception as e:
            result["record_error"] = (f"The block was lifted. The record of "
                                      f"it was NOT written: {e}")
        return result

    def list_blocked_ports(self) -> dict:
        from tools import iptables_manager as fw
        status = fw.list_agental_rules_status()
        backend = status.get("backend")

        # READABLE AND EMPTY IS NOT "NOTHING IS BLOCKED". The rules this app
        # writes are named AgentalSec_port_..., so anything else in the
        # ruleset is the user's own and is deliberately not listed here.
        rules = [r for r in status["rules"]
                 if f"{fw.RULE_PREFIX}port_" in str(r.get("rule", ""))]

        out = {
            "rules":   rules,
            "count":   len(rules) if status["readable"] else None,
            "backend": backend,
            "readable": status["readable"],
            "backend_reason": fw.detect_backend_detail()["reason"],
        }
        if not status["readable"]:
            out["note"] = (
                f"The rule set could NOT be read: {status['reason']}. So "
                f"this is not an empty list of rules, it is no information "
                f"about the rules. Nothing here says whether anything is "
                f"blocked.")
        else:
            out["note"] = (
                "Only rules this app wrote are listed (marker "
                f"{fw.RULE_PREFIX}port_...). The rest of the firewall is "
                f"the user's own and is not shown by this tool.")
        return out

    def block_device(self, ip: str, reason: str,
                     session_id: str = None) -> dict:
        from tools import remediation_linux as rl
        from core import memory_engine as me

        sid = session_id or self.session_id

        try:
            ip = _validated_ip(ip)
        except ValueError as e:
            return {"success": False, "error": str(e)}

        # A REASON IS REQUIRED. Added 2026-09-21, and it was missing entirely
        # from this method while the Windows tree has carried it since the
        # tool was written. Same rule as identify_device's evidence field: a
        # ban with no stated reason is one nobody can review in six weeks, and
        # the reviewer is usually the person who made it. The tool's own
        # description already told the model "reason is required and is not
        # decorative" -- so the model was being TOLD a rule that nothing
        # enforced, and a blank reason would have gone to the firewall and
        # been recorded as an empty audit row with no way to explain it later.
        #
        # Found by tests/test_device_ban.py, which asserts this refusal. The
        # file could not run here because it imported the moved Windows
        # module, so the assertion had been dormant since the port.
        if not (reason or "").strip():
            return {"success": False,
                    "error": "reason is required. Say what this device did, "
                             "or that the user did not recognise it."}

        if ip in _own_addresses():
            return {"success": False, "refused": True,
                    "error": f"{ip} is an address this machine holds. "
                             f"Blocking it would cut this host off from its "
                             f"own network."}

        # REM-13, 2026-09-24. THE GATEWAY GUARD THE TWIN HAS.
        #
        # `tools/remediation.py` refuses "the router, when config.json names
        # one" and says why: blocking the gateway from this host takes this
        # host off the network, which is exactly what a device ban does NOT
        # mean, and the router is the single address most likely to be sitting
        # in a finding because everything this host talks to goes through it.
        # MEASURED: the Linux side carried no equivalent — the string
        # _configured_router occurred in the twin and in neither this adapter
        # nor tools/remediation_linux.py.
        #
        # The own-address check covers it only when config's router IS one of
        # this host's own addresses, which it is not on a normal LAN (the host
        # holds its own private address while the gateway holds another, e.g.
        # 192.0.2.5 and 192.0.2.1).
        #
        # REM-13b, same day, and it is the reason this comment is longer than
        # the guard. The port arrived with the twin's PATH as well as its rule,
        # and on this tree the path named a file that does not exist, so
        # _configured_router answered "" for every value an operator could set:
        # filling router_monitor.host in by hand would have refused nothing,
        # while the guard, the register and the test all read as armed.
        # `read_operator_config` above now reads the file main.py loads, and
        # [REM-13] in tests/test_remediation_fixes.py drives this real path
        # with the operator's own configuration rather than grepping the file
        # for the function's name. A control is armed when something has
        # measured it refuse, not when its name is present.
        router = _configured_router()
        if not (router and ip == router) and ip == _configured_gateway():
            router = ip
        if router and ip == router:
            return {"success": False, "refused": True,
                    "error": (f"{ip} is the router named in config.json "
                              f"(router_monitor.host). Blocking the gateway "
                              f"from this host takes this host off the "
                              f"network, which is not what a device ban means "
                              f"and looks exactly like the app breaking. If "
                              f"the router is really the problem, that is a "
                              f"conversation, not a firewall rule.")}

        # No pre-check: block_ip refuses with its own reason when there is no
        # backend, and reports a verification failure when the rule did not
        # land. Both travel back to the model unchanged. Unelevated, the root
        # helper blocks it in its own nft table and reads it back.
        if _unelevated():
            result = _via_helper("block_ip", ip)
            if result.get("success"):
                result.update({"backend": "nft table inet agentalsec_helper",
                               "verified": True})
        else:
            result = rl.block_ip(ip, direction="both")
        if not result.get("success"):
            return result

        try:
            me.save_finding(
                session_id=sid,
                source="remediation",
                detection_id="REM-1004",
                severity="info",
                entity_type="ip",
                entity_value=ip,
                title=f"Device blocked at this host: {ip}",
                description=(reason + " " + rl.SCOPE_NOTE),
                raw_data={"ip": ip, "reason": reason, "platform": "linux",
                          "backend": result.get("backend"),
                          "verified": bool(result.get("verified")),
                          "scope": "this host only, not the gateway"},
            )
        except Exception as e:
            result["record_error"] = (f"The address was blocked. The record "
                                      f"of it was NOT written: {e}")
        return result

    def unblock_device(self, ip: str, reason: str,
                       session_id: str = None) -> dict:
        from tools import remediation_linux as rl
        from core import memory_engine as me

        sid = session_id or self.session_id
        try:
            ip = _validated_ip(ip)
        except ValueError as e:
            return {"success": False, "error": str(e)}

        if _unelevated():
            result = _via_helper("unblock_ip", ip)
            if result.get("success") and not result.get("was_blocked"):
                # Lifting nothing is not a success. A ufw rule left by an
                # elevated run is not the helper's to remove.
                return {"success": False, "refused": True, "ip": ip,
                        "error": (f"The root helper holds no block on {ip}, so "
                                  f"nothing was lifted. If a rule from an "
                                  f"elevated run blocks it, that one has to be "
                                  f"removed from an elevated run.")}
        else:
            result = rl.unblock_ip(ip, direction="both")
        if not result.get("success"):
            return result

        try:
            me.save_finding(
                session_id=sid,
                source="remediation",
                detection_id="REM-1005",
                severity="info",
                entity_type="ip",
                entity_value=ip,
                title=f"Device unblocked at this host: {ip}",
                description=reason,
                raw_data={"ip": ip, "reason": reason, "platform": "linux"},
            )
        except Exception as e:
            result["record_error"] = (f"The block was lifted. The record of "
                                      f"it was NOT written: {e}")
        return result

    # CONTAINMENT. Each one is a single verb of the root helper, which holds
    # the guards, reads the change back and keeps an undo record. Unelevated
    # it goes through the pkexec session; run as root the same code runs here.

    def _contain(self, verb: str, args: list, *, done: str, rem_id: str,
                 entity_type: str, entity_key: str, title: str, reason: str,
                 session_id: str = None, runner=None) -> dict:
        from core import memory_engine as me
        if not (reason or "").strip():
            return {"success": False,
                    "error": "reason is required. Say what was found and why "
                             "this is the response."}
        args = [str(a) for a in args]
        if runner is not None:
            result = runner(*args)
        elif _unelevated():
            result = _via_helper(verb, *args)
        else:
            from tools import action_helper as ah
            reply = ah.handle(verb, args)
            result = {"success": bool(reply.get("ok")),
                      "via": "in process, the app runs as root"}
            if reply.get("ok"):
                result.update(reply.get("result") or {})
            else:
                result.update(error=reply.get("refused") or "no reason given",
                              refused=True)
        if not result.get("success") or not result.get(done):
            return result
        entity = str(result.get(entity_key) or "")
        try:
            me.save_finding(
                session_id=session_id or self.session_id,
                source="remediation",
                detection_id=rem_id,
                severity="info",
                entity_type=entity_type,
                entity_value=entity,
                title=title.format(**{k: result.get(k) for k in
                                      ("user", "group", "path", "unit",
                                       "fingerprint")}),
                description=reason,
                raw_data={k: v for k, v in result.items()
                          if k not in ("before", "after", "steps")},
            )
        except Exception as e:
            logger.error(f"{verb} was done but could not be recorded: {e}")
            result["record_error"] = (
                f"The change was made. The record of it was NOT written: {e}.")
        return result

    def remove_ssh_key(self, user: str, fingerprint: str, reason: str,
                       session_id: str = None) -> dict:
        return self._contain(
            "remove_ssh_key", [user, fingerprint], done="removed",
            rem_id="REM-1017", entity_type="user", entity_key="user",
            title="SSH key removed from {user}: {fingerprint}",
            reason=reason, session_id=session_id)

    def restore_ssh_key(self, undo_id: str, reason: str,
                        session_id: str = None) -> dict:
        return self._contain(
            "restore_ssh_key", [undo_id], done="restored",
            rem_id="REM-1018", entity_type="user", entity_key="user",
            title="SSH key put back for {user}: {fingerprint}",
            reason=reason, session_id=session_id)

    def lock_account(self, user: str, reason: str,
                     session_id: str = None) -> dict:
        return self._contain(
            "lock_account", [user], done="locked",
            rem_id="REM-1019", entity_type="user", entity_key="user",
            title="Account locked: {user}", reason=reason,
            session_id=session_id)

    def unlock_account(self, undo_id: str, reason: str,
                       session_id: str = None) -> dict:
        return self._contain(
            "unlock_account", [undo_id], done="restored",
            rem_id="REM-1020", entity_type="user", entity_key="user",
            title="Account unlocked: {user}", reason=reason,
            session_id=session_id)

    def remove_group_member(self, user: str, group: str, reason: str,
                            session_id: str = None) -> dict:
        return self._contain(
            "remove_group_member", [user, group], done="removed",
            rem_id="REM-1021", entity_type="user", entity_key="user",
            title="{user} taken out of the {group} group", reason=reason,
            session_id=session_id)

    def restore_group_member(self, undo_id: str, reason: str,
                             session_id: str = None) -> dict:
        return self._contain(
            "restore_group_member", [undo_id], done="restored",
            rem_id="REM-1022", entity_type="user", entity_key="user",
            title="{user} put back in the {group} group", reason=reason,
            session_id=session_id)

    def disable_cron_line(self, path: str, line: str, reason: str,
                          session_id: str = None) -> dict:
        return self._contain(
            "disable_cron_line", [path, line], done="disabled",
            rem_id="REM-1023", entity_type="file", entity_key="path",
            title="Cron line disabled in {path}", reason=reason,
            session_id=session_id)

    def restore_cron_line(self, undo_id: str, reason: str,
                          session_id: str = None) -> dict:
        return self._contain(
            "restore_cron_line", [undo_id], done="restored",
            rem_id="REM-1024", entity_type="file", entity_key="path",
            title="Cron line enabled again in {path}", reason=reason,
            session_id=session_id)

    # A unit in the user's own manager (systemctl --user) is handled there,
    # as that user; anything else is a system unit for the root helper.

    def disable_service(self, unit: str, reason: str,
                        session_id: str = None) -> dict:
        from tools import systemd_units as sd
        return self._contain(
            "disable_unit", [unit], done="disabled_and_masked",
            rem_id="REM-1025", entity_type="process", entity_key="unit",
            title="Service stopped, disabled and masked: {unit}",
            reason=reason, session_id=session_id,
            runner=sd.disable_user_unit if sd.user_unit_known(unit) else None)

    def enable_service(self, unit: str, reason: str,
                       session_id: str = None) -> dict:
        from tools import systemd_units as sd
        return self._contain(
            "enable_unit", [unit], done="unmasked",
            rem_id="REM-1026", entity_type="process", entity_key="unit",
            title="Service unmasked and enabled: {unit}", reason=reason,
            session_id=session_id,
            runner=sd.enable_user_unit if sd.user_unit_known(unit) else None)

    # systemd units. L2, 2026-09-22.

    def stop_service(self, unit: str, reason: str,
                     session_id: str = None) -> dict:
        """
        Stop a systemd unit, and record it. The Linux answer to kill theatre.

        WHAT THIS IS FOR, in one sentence: on a systemd host, ending a SERVICE
        means stopping the unit, because killing its process only makes the
        manager start it again. kill_process refuses that case and names this
        tool; this is the tool.

        THE RECORD IS WRITTEN HERE RATHER THAN IN THE MODULE, the same split
        every other remediation in this app uses: tools/systemd_units.py decides
        what is true about a unit, and this decides how the app writes it down.
        The REM id is an action_record, not a detection, because this row is a
        statement about something THIS APP DID.
        """
        from tools import systemd_units as sd
        from core import memory_engine as me

        sid = session_id or self.session_id

        # THE MANAGER IS CHOSEN FROM THE UNIT, not from a parameter. A unit
        # whose owning manager is unknown is asked of BOTH, in the order that
        # can do least harm: the user manager first, because a system unit is
        # not stopped by accident that way. A name that is in neither is
        # refused with both answers in the sentence.
        tried = []
        chosen = None
        for manager in ("--user", ""):
            props = sd.unit_properties(unit, manager=manager)
            tried.append((manager or "system", props.get("reason")))
            if props["ok"]:
                chosen = (manager, props)
                break

        if not chosen:
            return {
                "success": False, "refused": True, "unit": unit,
                "error": (
                    f"{unit!r} is not a unit either manager knows. The user "
                    f"manager said: {tried[0][1]}. The system manager said: "
                    f"{tried[-1][1]}. Nothing was stopped. Check the name with "
                    f"query_services, which lists what is actually there."),
            }

        manager, props = chosen
        state = props["properties"].get("ActiveState")

        # WHAT THIS APP WILL NOT STOP: ITSELF, AND THE RECORD.
        #
        # The same three guards the rest of this tree applies to its own
        # existence: it never kills its own pid, never touches its own
        # directory, and never blocks its own host's addresses. Stopping a
        # service is a DENIAL, and the two units whose loss is worst are this
        # app's own and the thing that keeps the record of what happened.
        #
        # NAMED BY PREFIX RATHER THAN BY EXACT MATCH, because a unit can be
        # installed under more than one name (agentalsec-ebpf-camera.service,
        # any future agentalsec-*.service) and an exact list would silently
        # cover only the ones written down on the day. The list is deliberately
        # short and the reason is on each entry.
        self_protected = (
            (f"it is this app's OWN unit ({unit}); stopping it would end the "
             f"monitoring as well as the thing being stopped"),
            (f"it is the system journal ({unit}); stopping it would stop the "
             f"recording of what happens next, and the absence of a record is "
             f"the one loss nobody can detect afterwards"),
        )
        for prefix, why in (("agentalsec-", self_protected[0][0]),
                            ("systemd-journald", self_protected[1][0])):
            if unit == prefix or unit.startswith(prefix):
                return {"success": False, "refused": True, "unit": unit,
                        "error": (f"Refusing to stop {unit}: {why}. If this is "
                                  f"genuinely what you want, it has to be done "
                                  f"outside this tool, where nothing is left "
                                  f"to report it.")}

        if state in ("inactive", "failed"):
            return {
                "success": False, "refused": True, "unit": unit,
                "active_state": state,
                "error": (
                    f"{unit} is already {state} in the "
                    f"{'user' if manager == '--user' else 'system'} manager. "
                    f"Nothing was stopped and nothing is running under that "
                    f"name. This is not a failure of the stop: there was "
                    f"nothing to stop."),
            }

        if manager == "" and _unelevated():
            # A system unit. The helper stops it as root, refuses its own
            # protected list, and reads the state back.
            result = _via_helper("stop_unit", unit)
            if result.get("success"):
                result["verified"] = bool(result.get("stopped"))
                if not result["verified"]:
                    result["success"] = False
                    result["error"] = (f"{unit} was asked to stop and is still "
                                       f"active when read back, so something "
                                       f"restarted it.")
        else:
            result = sd.stop_unit(unit, manager=manager)
        if not result.get("success"):
            # The module's sentence is already exact about which half worked
            # (the request, the verification, or neither), so it travels back
            # unchanged rather than being re-worded here.
            return result

        try:
            me.save_finding(
                session_id=sid,
                source="remediation",
                detection_id="REM-1008",
                severity="info",
                entity_type="process",
                entity_value=unit,
                title=f"Service stopped: {unit}",
                description=reason,
                raw_data={"unit": unit, "reason": reason,
                          "manager": manager or "system",
                          "restart": props["properties"].get("Restart"),
                          "active_state_before": state,
                          "verified": result.get("verified"),
                          "platform": "linux"},
            )
        except Exception as e:
            result["record_error"] = (
                f"The unit was stopped. The record of it was NOT written: {e}")
        return result

    def list_device_blocks(self) -> dict:
        from tools import iptables_manager as fw
        status = fw.list_agental_rules_status()
        rules = [r for r in status["rules"]
                 if f"{fw.RULE_PREFIX}device_" in str(r.get("rule", ""))]
        out = {
            "blocks": rules,
            "count":  len(rules) if status["readable"] else None,
            "backend": status.get("backend"),
            "readable": status["readable"],
            "scope_note": (
                "A block here stops that device talking to THIS machine only. "
                "It cannot stop the device reaching the internet or any other "
                "device on the network, because that traffic never passes "
                "through here. Only the gateway can do that."),
        }
        if not status["readable"]:
            out["note"] = (
                f"The rule set could NOT be read: {status['reason']}. So this "
                f"is not 'no devices are blocked', it is no information about "
                f"which devices are blocked.")
        # THE ROOT HELPER'S BLOCKS live in their own nft table. They are read
        # through the session when one is open this run; otherwise reading
        # them would ask for the password, so the answer says it is unknown.
        from tools import action_broker as ab
        if ab.status()["session_open"]:
            reply = ab.call("list_blocks")
            out["helper_blocks"] = ((reply.get("result") or {}).get("blocked")
                                    if reply.get("ok") else None)
        else:
            out["helper_blocks"] = None
            out["helper_blocks_note"] = (
                "Blocks made by the root helper are not readable until the root "
                "session opens this run, so they are UNKNOWN here, not absent. "
                "They last until reboot.")
        return out

    # quarantine

    def quarantine_file(self, file_path: str, reason: str,
                        session_id: str = None) -> dict:
        from tools import remediation_linux as rl
        from core import memory_engine as me

        sid = session_id or self.session_id

        # The Linux module has its own path guards (protected roots, the
        # project directory) and they run inside rl.quarantine_file. Nothing
        # is duplicated here. A file this account cannot move (another
        # account's, or in a directory it cannot write) goes to the root
        # helper, pinned by the hash taken here when the file is readable.
        if _unelevated() and not _movable_by_me(file_path):
            import hashlib
            try:
                with open(file_path, "rb") as fh:
                    pin = hashlib.file_digest(fh, "sha256").hexdigest()
            except OSError:
                pin = "-"
            result = _via_helper("quarantine", file_path, pin)
            if result.get("success"):
                result.update({"original": result.get("quarantined"),
                               "quarantine": result.get("held_at"),
                               "hash": result.get("sha256")})
        else:
            result = rl.quarantine_file(file_path)
        if not result.get("success"):
            return result

        try:
            me.save_finding(
                session_id=sid,
                source="remediation",
                detection_id="REM-1006",
                severity="info",
                entity_type="file",
                entity_value=result.get("original") or file_path,
                title=f"File quarantined: {result.get('original') or file_path}",
                description=reason,
                raw_data={"original":   result.get("original"),
                          "quarantine": result.get("quarantine"),
                          "sha256":     result.get("hash"),
                          "reason":     reason,
                          "platform":   "linux"},
            )
        except Exception as e:
            result["record_error"] = (f"The file was moved. The record of it "
                                      f"was NOT written: {e}")
        return result

    def list_quarantined(self) -> dict:
        from tools import remediation_linux as rl
        entries = rl.list_quarantined()
        unreadable = [e for e in entries if e.get("unreadable")]
        out = {"quarantined": entries, "count": len(entries),
               "root": str(rl.STAGING_ROOT),
               "roots_read": [str(r) for r in rl.staging_roots()],
               "unreadable_count": len(unreadable)}
        if unreadable:
            # A vault folder whose manifest cannot be read is REPORTED, not
            # skipped: REM-9. A quarantined file the operator cannot see is one
            # the owner cannot get back, and the count alone would hide that.
            out["note"] = (
                f"{len(unreadable)} folder(s) in the vault could not be read "
                f"and are listed with their reason rather than dropped. "
                f"Whatever is inside them cannot be restored from here.")
        return out

    def restore_file(self, folder: str, reason: str,
                     session_id: str = None) -> dict:
        from tools import remediation_linux as rl
        from core import memory_engine as me

        sid = session_id or self.session_id

        # The registry passes `folder`; the Linux function accepts EITHER the
        # dated folder or the quarantined file, and resolves a folder by its
        # own rule (exactly one non-manifest file inside, or a refusal naming
        # the count). REM-12: the resolution used to live HERE, which meant the
        # module — the thing tests and scripts load directly — could not do it,
        # and a caller that reached the module was told "Manifest not found"
        # for a path list_quarantined had just reported.
        import os
        from tools import action_helper as ah
        qid = os.path.basename(str(folder).rstrip("/"))
        if ah.QID_RE.match(qid) and (str(folder) == qid or str(folder).startswith(
                ah.QUARANTINE_DIR + "/")):
            # Held by the root helper, so only the root helper can return it.
            result = _via_helper("restore", qid)
            if result.get("success"):
                result.update({"restored_to": result.get("restored"),
                               "sha256_state": "match"})
        else:
            result = rl.restore_file(str(folder))
        if not result.get("success"):
            return result

        digest_state = result.get("sha256_state")
        try:
            me.save_finding(
                session_id=sid,
                source="remediation",
                detection_id="REM-1007",
                severity="info",
                entity_type="file",
                entity_value=result.get("restored_to") or str(folder),
                title=f"File restored from quarantine: {folder}",
                description=(reason if digest_state != "mismatch"
                             else f"{reason} || {result.get('sha256_note')}"),
                raw_data={"restored": result.get("restored_to"),
                          "reason": reason,
                          "sha256_state": digest_state,
                          "sha256_note": result.get("sha256_note"),
                          "platform": "linux"},
            )
        except Exception as e:
            result["record_error"] = (f"The file was restored. The record of "
                                      f"it was NOT written: {e}")
        return result


# THE AUDIT SUBSYSTEM'S READER. L4, 2026-09-22.
#
# WHY IT IS IN THIS TABLE AT ALL, given that on this host the thing it reads
# is not installed. The role has to be DECLARED so that it is loaded, so that
# it reports the absence at boot, and so that query_audit_events has something
# to answer from. A role that is only registered when its source happens to
# exist is a role that silently disappears on the machine where it matters
# most -- and the machine where it matters most is exactly this one, where the
# answer a reader needs is "the kernel feed is absent, and here is the command
# that changes that".
#
# It is NOT blind when auditd is simply not installed, for the reason its own
# module header gives at length: that is a deliberate state of the machine and
# not a fault in this app, and a permanent blind flag on every findings answer
# is how a warning list becomes something a reader skips. The absence travels
# in the coverage block and in the tool's own payload, in words.
#
# IT IS BLIND FOR THE ONE REAL FAILURE: the log exists and this account cannot
# read it, which is the default on every install (root-only, 0600), and means
# every answer would otherwise be an empty list that reads as a quiet machine.
class LinuxAVScanner(_BaseAdapter):
    """Wraps tools/av_scanner.py: ClamAV over running programs and the
    folders a payload is dropped in. AV-1001 on a signature match."""

    role = "av_scanner"

    def __init__(self, session_id, config=None):
        super().__init__(session_id, config)
        from tools import av_scanner as av
        self._scanner = av.Scanner(config)

    @property
    def poll_interval(self) -> int:
        return int(((self.config or {}).get("sensors") or {})
                   .get(self.role, {}).get("poll_interval", 900))

    def poll(self):
        from core import memory_engine as me
        for f in self._scanner.run_pass():
            if me.is_dismissed("file", f["entity_value"]):
                continue
            if me.finding_already_open(self.role, "file", f["entity_value"], f["title"]):
                continue
            me.save_finding(session_id=self.session_id, source=self.role,
                            detection_id=f["detection_id"], severity=f["severity"],
                            entity_type="file", entity_value=f["entity_value"],
                            title=f["title"], description=f["description"],
                            raw_data=f["raw_data"])
            logger.warning(f"av_scanner: {f['title']}")

    def _wait_for_next_poll(self):
        from tools import av_scanner as av
        av.wake.wait(self.poll_interval)
        av.wake.clear()

    def stop(self):
        from tools import av_scanner as av
        super().stop()
        av.wake.set()

    def scan(self, paths: list) -> dict:
        """An on-demand scan of named files, for the agent."""
        import os
        from tools import av_scanner as av
        asked = [str(p) for p in (paths or [])][:20]
        # Files only: a folder, even "/", would have ClamAV walk all of it.
        files = [p for p in asked if os.path.isfile(p) and not os.path.islink(p)]
        out = av.scan_paths(files, timeout=int(self._scanner.cfg["scan_timeout_seconds"]))
        skipped = [p for p in asked if p not in files]
        if skipped:
            out["not_scanned"] = {"paths": skipped,
                                  "why": "not a regular file (a folder, a link or missing)"}
        return out

    def status(self) -> dict:
        st = self._scanner.status()
        st["running"] = self._running
        st["role"] = self.role
        st["state"] = ("NOT INSTALLED" if not st["engine"]["installed"]
                       else "READABLE")
        return st


class LinuxAuditd(_BaseAdapter):
    """Wraps tools/auditd_monitor.py, which reads the kernel audit log."""

    role = "auditd"

    def __init__(self, session_id, config=None):
        super().__init__(session_id, config)
        self._state = {
            "passes": 0, "findings": 0, "last": None, "seeded": False,
            "last_error": None, "analysed": {}, "notes": [], "cursor": None,
            "auditd": {}, "coverage": {}, "by_type": {},
        }
        self._unregistered = {}

    # one pass

    def poll(self):
        """One analysis pass over the audit log, since the cursor."""
        from tools import auditd_monitor as am

        report = am.analyze(self.config)
        self._state["passes"] += 1
        self._state["last"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        self._state["analysed"] = report.get("analysed") or {}
        self._state["notes"] = report.get("notes") or []
        self._state["auditd"] = report.get("auditd") or {}
        self._state["coverage"] = report.get("coverage") or {}
        self._state["cursor"] = report.get("cursor")
        self._state["by_type"] = report.get("by_type") or {}

        if report.get("error"):
            logger.error(f"auditd: the pass could not read the log: "
                         f"{report['error']}")

        if report.get("seeded"):
            self._state["seeded"] = True
            logger.info(
                f"auditd: the log is being read for the first time. The cursor "
                f"was set to the end of the file and NOTHING was raised for "
                f"the history already in it. "
                f"{report['coverage'].get('auditd') or ''}")

        written = self._emit_all(report.get("findings") or [])
        self._state["findings"] += written
        if written:
            logger.info(f"auditd: {written} finding(s) from "
                        f"{self._state['analysed']}")

        for note in self._state["notes"]:
            logger.warning(f"auditd: {note}")

    def _emit_all(self, findings: list) -> int:
        """
        Write each finding, or count it and say why not.

        THE FLOOR IS low, which is where the register puts AUD-1002, and it is
        stated here rather than left to the default: a watch firing is
        information its owner asked for, and raising it above its declared
        severity would put a low thing beside a high one on the dashboard.
        """
        from core import detections as det
        from core import memory_engine as me

        written = 0
        for f in findings:
            did = f.get("detection_id")
            try:
                det.get(did)
            except Exception as e:                      # noqa: BLE001
                self._unregistered[did] = self._unregistered.get(did, 0) + 1
                logger.warning(
                    f"auditd produced {did!r} for {f.get('entity_value')} and "
                    f"there is NO registered detection id for it, so it was "
                    f"NOT written: {e}")
                continue

            entity_type = f.get("entity_type") or "file"
            entity_value = f.get("entity_value") or ""
            if not entity_value:
                continue
            if me.is_dismissed(entity_type, entity_value):
                continue
            if me.finding_already_open(self.role, entity_type, entity_value,
                                       f.get("title") or ""):
                continue

            severity = _fit_severity(did, f.get("severity", "low"), "low")
            me.save_finding(
                session_id=self.session_id,
                source=self.role,
                detection_id=did,
                severity=severity,
                entity_type=entity_type,
                entity_value=entity_value,
                title=f.get("title") or f"{did} fired",
                description=f.get("description"),
                raw_data=f.get("raw_data") or {},
            )
            written += 1
        return written

    # status

    def status(self) -> dict:
        """
        What the audit feed can see. Read by /api/status and by sensor_health.

        THE COVERAGE IS THE ANSWER, and on this host the answer is that the
        feed is absent. Three situations produce the same empty findings list
        and only the coverage block tells them apart: not installed, installed
        and unreadable by this account, and recording normally.
        """
        from tools import auditd_monitor as am

        out = super().status()
        st = am.status(self.config)

        out["auditd"] = {
            "state": st.get("state"),
            "enabled": st.get("enabled"),
            "installed": st.get("installed"),
            "installed_reason": st.get("installed_reason"),
            "log_path": st.get("log_path"),
            "log_path_source": st.get("log_path_source"),
            "log_readable": st.get("log_readable"),
            "reachable": st.get("reachable"),
            "running": st.get("running"),
            "newest_record_age_seconds": st.get("newest_record_age_seconds"),
            "kernel_enabled": st.get("kernel_enabled"),
            "install_command": st.get("install_command"),
            "tools_present": st.get("tools_present"),
            "note": st.get("note"),
        }
        out["reader"] = {k: v for k, v in self._state.items()
                         if k not in ("auditd", "coverage", "notes", "by_type")}
        if self._state["by_type"]:
            out["records_by_type"] = dict(self._state["by_type"])
        out["coverage_limits"] = st.get("coverage_limits") or []
        if self._state["notes"]:
            out["notes"] = list(self._state["notes"])
        if self._unregistered:
            out["unregistered_detection_ids"] = dict(self._unregistered)

        if st.get("blind"):
            out["blind"] = True
            out["blind_reason"] = st.get("blind_reason")

        # THE HONEST HEADLINE.
        #
        # IT LEADS WITH THE STATE STRING THE MODULE DECIDED, and that is a
        # correction rather than a restyle. The cascade that used to live here
        # tested running / log_readable / installed in that order, which put
        # "auditd is installed but there is no readable log yet" on a reader
        # that had been switched off in config -- a sentence blaming the
        # machine for this app's choice. Reading one value the module owns
        # makes that class of disagreement impossible rather than unlikely.
        parts = []
        state = st.get("state")
        _installed = bool(st.get("installed"))
        if state == "OFF BY CONFIG":
            parts.append("THE AUDIT READER IS SWITCHED OFF in config, so "
                         "nothing is reading the kernel audit log")
        elif st.get("running") and not _installed:
            # READABLE, RECENT, AND AUDITD IS NOT INSTALLED.
            #
            # THIS IS THE CASE A FIXTURE RUN IS IN, and the sentence the
            # first version of this adapter printed there was FALSE:
            # "the audit subsystem is recording". Nothing is recording.
            # sensors.auditd.log_path pointed the reader at a file, the file
            # was readable and its newest record was recent, and the
            # CONCLUSION that follows is about the FILE. The audit userspace
            # is not on this machine, so there is no subsystem to be doing
            # any recording -- and this project's whole discipline is that a
            # status line must not claim more than the measurement behind it.
            parts.append(
                f"a log at {st.get('log_path')} is READABLE and its newest "
                f"record is recent, BUT THE AUDIT USERSPACE IS NOT INSTALLED "
                f"on this machine, so nothing is writing it: this is a file "
                f"someone configured, not a running auditd")
        elif st.get("running") and st.get("kernel_enabled") == 0:
            # RECORDING, AND SWITCHED OFF AT THE KERNEL.
            #
            # `running` comes from the log being fresh, and the kernel's own
            # audit_enabled says the RECORDER was turned off underneath it.
            # The first version of this cascade would have printed "the audit
            # subsystem is recording" over a kernel told to record nothing,
            # which is the reassuring reading of the one state that most needs
            # the opposite.
            parts.append(
                "the audit log is FRESH but THE KERNEL'S AUDIT SWITCH IS OFF "
                "(audit_enabled=0), so nothing is being recorded despite a "
                "log that looks current: sudo auditctl -e 1 turns it back on")
        elif st.get("running"):
            parts.append("the audit subsystem is recording")
        elif state == "READABLE":
            parts.append("the audit log is readable but its newest record is "
                         "old, so the recording may have stopped")
        elif state == "CANNOT READ LOG":
            parts.append("the audit log exists and this account cannot read "
                         "it, so NOTHING was examined")
        elif state == "HALF INSTALLED":
            parts.append("the audit CONFIGURATION is on this machine and the "
                         "audit TOOLS ARE NOT, so nothing is being recorded "
                         "and starting a daemon will not help")
        elif state == "NO LOG YET":
            parts.append("the audit tools are installed and there is no "
                         "readable log yet")
        else:
            parts.append("AUDITD IS NOT INSTALLED on this machine, so NOTHING "
                         "at kernel level is being recorded")
        parts.append(f"state: {state}")
        parts.append(f"install command: {st.get('install_command')}")

        if self._state["passes"] == 0:
            parts.append("and this app has not read the log yet this session")
        elif self._state["seeded"] and self._state["passes"] == 1:
            parts.append("and this app has SEEDED it, raising nothing for the "
                         "history already in the file")
        else:
            parts.append(f"and this app has read it {self._state['passes']} "
                         f"time(s), {self._state['findings']} finding(s)")
        out["note"] = ", ".join(parts) + "."
        return out


# HOST INFO
#
# Only used when config.sensor_backends sends this role to the Linux module.
# The default is tools/host_info.py, whose collect() already has a _linux()
# branch. This wrapper exists so the choice is real rather than theoretical.
class LinuxHostInfo:
    """
    Wraps tools/host_info_linux.py's get_all_info().

    THE ADAPTER DROPPED THE HALF OF THE ANSWER THE TASK TURNS ON, measured
    2026-09-25. The tree's default host_info module answers 21 keys; this
    wrapper published 10 of them, and among the 11 it dropped were
    `boot_time_utc`, `uptime_seconds`, `uptime_human`, `agentalsec_started_utc`,
    `agentalsec_uptime_human`, `observed_fraction`, `observation_note`,
    `errors` and `scope` -- every field the model-facing description of
    query_host_info tells the analyst to QUOTE, and every field the tool is
    documented as existing for. Choosing this backend by config (or by
    typo, see main.py's door) silently removed them.

    It also published `collected_at` from the read's own `timestamp`, which
    is the honest source and is kept; and `os_patch_level` carried the
    kernel release, a value about the kernel, under a name the Windows twin
    uses for the OS patch level. The kernel facts now travel under kernel
    names and the distribution's own answer is named as such.
    """

    role = "host_info"

    def __init__(self, session_id: str = None, config: dict = None):
        self.session_id = session_id
        self._cache = None
        self._cached_at = 0.0
        self.CACHE_TTL = 300

    def start(self):
        logger.info("HostInfo (linux module) ready.")

    def status(self) -> dict:
        """
        The Linux module's own status(), passed through.

        IT WAS A FABRICATED `ready` BEFORE, measured 2026-09-25: this method
        returned `{"ready": True, "hostname": ...}` without calling the
        module at all, so the readiness card and core/sensor_health both read
        a module that cannot read /etc/os-release as healthy. The module now
        answers a tri-state status; this returns it rather than inventing one.
        """
        from tools import host_info_linux as hi
        try:
            return hi.get_status()
        except Exception as e:
            return {"available": False,
                    "reason": f"the host info module's status() raised "
                              f"{type(e).__name__}: {e}"}

    def collect(self, refresh: bool = False) -> dict:
        import time as _t
        from tools import host_info_linux as hi

        if (not refresh and self._cache
                and _t.time() - self._cached_at < self.CACHE_TTL):
            return self._cache

        info = hi.get_all_info()
        os_info = info.get("os") or {}
        kernel  = info.get("kernel") or {}
        hw      = info.get("hardware") or {}
        out = {
            "hostname":       os_info.get("node"),
            "platform":       "linux",
            "os_family":      "Linux",
            "os_name":        os_info.get("distribution"),
            "os_version":     os_info.get("distro_version"),
            # THE LINUX MODULE'S OWN VOCABULARY. `os_build` and
            # `os_patch_level` are Windows-shaped names; on this platform the
            # values that answer them come from the KERNEL and the package
            # manager, so they are published under names that say so. The
            # Windows-named keys are kept (a caller may read them) but they
            # now carry the kernel release deliberately rather than by
            # accident, and the package version is beside them.
            "os_build":       kernel.get("version"),
            "os_patch_level": kernel.get("package_version") or kernel.get("version"),
            "kernel_release": kernel.get("version"),
            "kernel_package": kernel.get("package_version"),
            "arch":           hw.get("architecture") or os_info.get("machine"),
            # What the default module answers and this one used to drop.
            "scope":          "local",
            "detail":         info,
            "collected_at":   info.get("timestamp"),
            "unreadable":     info.get("unreadable"),
        }

        # The uptime pair, the same shape and the same question the default
        # module answers: how much of this machine's life has this run
        # watched. Built here from the module's own numbers so a reader of
        # EITHER backend gets one vocabulary.
        try:
            import psutil
            now = _t.time()
            boot = psutil.boot_time()
            started = psutil.Process().create_time()
            out["boot_time_utc"] = datetime.fromtimestamp(
                boot, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            out["uptime_seconds"] = int(now - boot)
            out["uptime_human"] = _human_duration(now - boot)
            out["agentalsec_started_utc"] = datetime.fromtimestamp(
                started, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            out["agentalsec_uptime_seconds"] = int(now - started)
            out["agentalsec_uptime_human"] = _human_duration(now - started)
            if out["uptime_seconds"] > 0:
                out["observed_fraction"] = round(
                    min(out["agentalsec_uptime_seconds"] / out["uptime_seconds"], 1.0), 4)
                out["observation_note"] = (
                    f"This machine has been up {out['uptime_human']}. "
                    f"This run of AgentalSec has been watching for "
                    f"{out['agentalsec_uptime_human']}, which is "
                    f"{out['observed_fraction'] * 100:.0f}% of it. Anything "
                    f"that happened while it was not running was not observed "
                    f"by this sensor.")
        except Exception as e:
            out["uptime_unknown_because"] = (
                f"boot time unreadable: {type(e).__name__}: {e}")

        self._cache, self._cached_at = out, _t.time()
        return out


# NETWORK SCANNER
#
# A THIN WRAPPER, AND THE REASON IT EXISTS IS THE ONE THING THIS MODULE COULD
# NOT DO FOR ITSELF. tools/network_scanner.NetworkScanner is a real class with
# a real status() and needs no adapter to be the sensor — main.py builds it
# directly and the presence sweeper drives it. What it cannot do is hand its
# own status() to core/settings._module_row, which resolves a verdict from
# `running`, then `ready`, then `available`: the module's class publishes
# `ready`, and it has to, because that is the key main.py's readiness table
# and the module's own contract already use.
#
# So the switch and the interval are reported by the module itself (see
# sweep_enabled / sweep_interval_seconds, one reader each) and status() here
# re-shapes that answer into the row the page reads, dropping the key that
# would paint a switched-off scanner green. Same correction the autoruns round
# made on its own adapter, for the same reason: a control's own row must not
# contradict the control.
class LinuxNetworkScanner:
    """Re-shapes tools.network_scanner's status for the readiness page."""

    role = "network_scanner"

    def __init__(self, session_id: str = None, config: dict = None,
                 scanner=None):
        self.session_id = session_id
        self.config     = config or {}
        if scanner is None:
            from tools.network_scanner import NetworkScanner
            scanner = NetworkScanner(session_id, self.config)
        self.scanner    = scanner

    def start(self):
        self.scanner.start()

    def scan(self, session_id: str = None, **kw):
        return self.scanner.scan(session_id, **kw)

    def sweep_presence(self, session_id: str = None, **kw):
        return self.scanner.sweep_presence(session_id, **kw)

    def get_last_result(self) -> list:
        return self.scanner.get_last_result()

    def status(self) -> dict:
        """
        The module's answer, with the verdict key fixed for this page.

        A SWITCHED-OFF SCANNER MUST NOT RENDER GREEN. _module_row reads
        `running`, then `ready`, then `available`; a dict carrying
        `ready: True` beside a note saying the sweep is switched off paints
        the row green and prints "running." directly beside its own
        contradiction. So when the module says off_by_config, this drops the
        truthy keys it was carrying and keeps the falsy one plus `reason`,
        which is the key the row prints. Measured before the correction on the
        autoruns round's own adapter, which shipped exactly that defect.
        """
        st = dict(self.scanner.status() or {})
        if st.get("off_by_config"):
            st.pop("ready", None)
            st.pop("running", None)
            st["available"] = False
            st.setdefault("reason", st.get("note") or
                          "SWITCHED OFF IN CONFIG.")
        return st


# SOFTWARE INVENTORY
class LinuxSoftwareInventory:
    """
    Wraps tools/software_inventory_linux.py's get_all_software().

    SI-6/SI-7, 2026-09-26 (register section 12): the search here matched
    name and VERSION, while the model-facing description of
    query_installed_software promises "filter by product or PUBLISHER" --
    measured: search="Ubuntu Developers" returned 0 rows here and 1782 on
    the live class path, so the same question answered differently depending
    on which backend was configured. Publisher is now searched, version is
    kept (the field is genuinely in the rows), and `count`/`total` are named
    the same way the class path names them (count = rows returned, total =
    rows in the inventory) so the two payloads cannot disagree about which
    number is which.
    """

    def __init__(self, session_id: str = None, config: dict = None):
        self.session_id = session_id
        self._cache = None
        self._cached_at = 0.0
        self.CACHE_TTL = 900

    def start(self):
        from tools import software_inventory_linux as si
        managers = si.detect_package_managers()
        logger.info(f"SoftwareInventory (linux module) ready. Package "
                    f"managers: {', '.join(managers) or 'none detected'}.")

    def status(self) -> dict:
        """
        The Linux module's own status(), passed through, so a host with NO
        package manager reports unavailable rather than a fabricated ready
        (SI-16, the HI-8 shape). get_status() answers a tri-state since
        2026-09-26; a raise is reported rather than swallowed.
        """
        from tools import software_inventory_linux as si
        try:
            return si.get_status()
        except Exception as e:
            return {"available": False,
                    "reason": f"the inventory module's status() raised "
                              f"{type(e).__name__}: {e}"}

    def collect(self, search: str = None, refresh: bool = False) -> dict:
        import time as _t
        from tools import software_inventory_linux as si

        if (not refresh and self._cache
                and _t.time() - self._cached_at < self.CACHE_TTL):
            packages = self._cache
            cached = True
        else:
            packages = si.get_all_software().get("packages") or []
            self._cache, self._cached_at = packages, _t.time()
            cached = False

        rows = packages
        if search:
            needle = search.lower()

            def _plain(s):
                return (s or "").split(":")[0].lower()
            rows = [p for p in packages
                    if needle in _plain(p.get("name"))
                    or needle in (p.get("name") or "").lower()
                    or needle in (p.get("publisher") or "").lower()
                    or needle in (p.get("description") or "").lower()
                    or needle in (p.get("version") or "").lower()]

        return {
            "software": rows,
            "count":    len(rows),
            "total":    len(packages),
            "source":   "linux-module",
            "cached":   cached,
            "note": (
                "Package inventory for THIS host, read from its package "
                "managers. A package absent here is absent from this machine, "
                "which says nothing about any other machine. This is the "
                "SYSTEM package manager only: nothing inside containers, "
                "virtualenvs, pipx, npm, snap or flatpak is here unless a "
                "manager above listed it, so a miss is close to meaningless "
                "and a hit is evidence."),
        }


# AUTORUNS
#
# Key stays "registry_monitor" because sensor_health.DEPENDS names it, but on
# Linux the right answer is systemd/cron/init.d, not the registry. The
# Windows class already answers supported=false with words on Linux, which is
# honest but useless, and tools/autorun_monitor.py has the Linux answer.
#
# THIS IS A PULL-ONLY SENSOR AND THAT IS THE FACT EVERYTHING ELSE HERE FOLLOWS
# FROM. It has no poll(), so nothing happens until the model calls
# query_autoruns. Two consequences, both measured 2026-09-24 and both stated on
# the page rather than left for a reader to work out:
#
#   * the config block's `enabled` is a control nothing reads (AR-12). Every
#     other Linux adapter honours its own key -- event_monitor, local_integrity,
#     dns_monitor, router_monitor, auditd_monitor -- and an operator who sets
#     `sensors.autorun_monitor.enabled = false` here has been told a control
#     exists that does not. Honouring it from a pull-only sensor is a DECISION
#     rather than a patch, so it is recorded in bugfinder.md with its
#     measurement and its design, not invented here.
#   * `poll_interval` in the same block is read by nothing for the same reason.
#     The cache below is the only clock this sensor has.
class LinuxAutorunMonitor(_BaseAdapter):
    """Wraps tools/autorun_monitor.py's monitor_once()."""

    # THIS CLASS HAD NO BASE, NO ROLE AND NO START-OF-LOG.
    #
    # Measured 2026-09-24: of the seven Linux adapters, six inherit
    # _BaseAdapter and this one did not. It carried its own `session_id`,
    # `config`, `_cache` and `_cached_at` by hand, and it had NO `role`, which
    # `save_finding` needs for the `source` column -- so when this round added
    # the write path, there was nothing to write under. The class comment on
    # _BaseAdapter says the base exists for exactly the plumbing this class was
    # re-implementing, and the `source` string is load-bearing: sensor_health's
    # DEPENDS and the readiness page both key on "registry_monitor", and a second
    # hand-rolled copy of it is a second place for it to drift.
    role = "registry_monitor"

    def __init__(self, session_id: str = None, config: dict = None):
        super().__init__(session_id, config)
        self._last_tally = None
        # The cached payload and its clock. These are this adapter's own,
        # because the base class's poll loop is not how this sensor is driven --
        # see poll() below and the class comment above.
        self._cache = None
        self._cached_at = 0.0
        # The OFF notice is logged once rather than on every call, the same
        # latch local_integrity and event_monitor use for their own.
        self._off_logged = False
        # THE CACHE IS NOW READ FROM CONFIG, AND ITS KEY IS `poll_interval`.
        #
        # CACHE_TTL was a bare 3600 beside a config block that documented a
        # `poll_interval` of 3600: two numbers that were meant to be one and
        # could drift apart with nothing saying so. The documented key is the
        # source now. And on this pull-only sensor the cache lifetime is the
        # ONLY thing `poll_interval` can honestly mean -- there is no loop for
        # it to time -- which is why the tool description says an answer may be
        # up to `poll_interval` old and carries its age.
        try:
            self.CACHE_TTL = int(((self.config.get("sensors", {}) or {})
                                  .get("autorun_monitor", {}) or {})
                                 .get("poll_interval", 3600))
        except (TypeError, ValueError):
            self.CACHE_TTL = 3600
        self.CACHE_TTL = max(60, self.CACHE_TTL)

    def start(self):
        logger.info("AutorunMonitor (linux module) ready.")

    # THE WRITE PATH, WHICH DID NOT EXIST.
    #
    # MEASURED BEFORE THIS ROUND: this module raises three finding types and the
    # adapter did nothing with them. `collect()` returned them under `findings`,
    # the tool result carried them, and no code anywhere turned one into a row:
    # there was no `_emit_all`, no `save_finding`, and no registered detection id
    # for any of the three types. So a model reading the answer saw a list of
    # suspicious entries and the evidence store held nothing -- and since
    # query_findings is what the app's own pages and the duty loop read, the
    # findings were invisible to everything except the one caller that happened
    # to ask. EM-2's shape: "134 findings raised, 0 registered types."
    #
    # THE ID PER TYPE IS DECLARED HERE because the module's types are the
    # module's vocabulary and this is where it becomes the register's:
    # LNX-4001 a unit, LNX-4002 a cron entry, LNX-4003 a shell startup file.
    #
    # AND EVERY SKIP IS COUNTED. An id that is not registered, an entity with no
    # value, an entity already dismissed, a row already open -- each one is
    # counted under its own reason and reported in status() and on the payload.
    # A count of findings raised that does not say what became of each one is
    # how a sensor writes nothing for a week and reports itself healthy.
    FINDING_IDS = {
        "suspicious_systemd_service": "LNX-4001",
        "suspicious_cron_job":        "LNX-4002",
        "suspicious_shell_startup":   "LNX-4003",
        "autorun_entry_added":        "LNX-4004",
        "autorun_entry_changed":      "LNX-4005",
        "autorun_entry_removed":      "LNX-4006",
    }

    def _emit_all(self, findings: list) -> dict:
        """Write each finding, or count it and say why not. Returns the tally."""
        from core import detections as det
        from core import memory_engine as me

        tally = {"written": 0, "unregistered": {}, "no_entity": 0,
                 "dismissed": 0, "already_open": 0, "failed": {}}

        for f in findings:
            did = self.FINDING_IDS.get(f.get("type"))
            if not did:
                why = f.get("type") or "(no type)"
                tally["unregistered"][why] = tally["unregistered"].get(why, 0) + 1
                logger.warning(
                    f"autorun_monitor produced a finding of type {why!r} and "
                    f"there is NO entry in this adapter's FINDING_IDS for it, so "
                    f"it was NOT written. Add the id to core/detections and to "
                    f"FINDING_IDS.")
                continue
            try:
                det.get(did)
            except Exception as e:                      # noqa: BLE001
                tally["unregistered"][did] = tally["unregistered"].get(did, 0) + 1
                logger.warning(
                    f"autorun_monitor produced {did!r} and the register has no "
                    f"such detection: {e}")
                continue

            # THE ENTITY IS THE FILE. Every one of these three is a fact about a
            # file on this machine -- the unit, the crontab, the startup file --
            # and `file` is in both VALID_ENTITY_TYPES and core/incident's
            # vocabulary. Using the command string as the entity would make a
            # dismissal key on text an attacker can edit.
            entity_value = f.get("path") or f.get("name") or ""
            if not entity_value:
                tally["no_entity"] += 1
                continue
            if me.is_dismissed("file", entity_value):
                tally["dismissed"] += 1
                continue

            # THE TITLE IS BUILT ONCE AND USED TWICE, which is the whole point:
            # `finding_already_open` matches on the TITLE, and the first version
            # of this method passed the DESCRIPTION to it instead -- so the guard
            # compared a sentence that is never stored as a title, returned False
            # every time, and wrote a duplicate row on every pass. That is the
            # failure its own docstring warns about, in one line: "Not on the
            # description, which carries counts and timestamps and would differ
            # on every poll, which would make this function always return False
            # and look like it was working." MEASURED with the wrong argument:
            # two passes wrote 4 rows for 2 findings.
            title = f"{f.get('type')} in {f.get('name')}"
            if me.finding_already_open(self.role, "file", entity_value, title):
                tally["already_open"] += 1
                continue

            severity = _fit_severity(did, f.get("severity", "medium"), "medium")
            try:
                me.save_finding(
                    session_id=self.session_id,
                    source=self.role,
                    detection_id=did,
                    severity=severity,
                    entity_type="file",
                    entity_value=entity_value,
                    title=title,
                    description=f.get("description"),
                    raw_data={
                        "pattern":  f.get("pattern"),
                        "line":     f.get("line"),
                        "content":  f.get("content"),
                        "commented": f.get("commented"),
                        "command":  f.get("command"),
                        "scope":    f.get("scope"),
                    },
                )
                tally["written"] += 1
            except Exception as e:                      # noqa: BLE001
                key = f"{type(e).__name__}"
                tally["failed"][key] = tally["failed"].get(key, 0) + 1
                logger.error(f"autorun_monitor: could not write {did} for "
                             f"{entity_value}: {e}")

        if tally["written"]:
            logger.info(f"autorun_monitor: {tally['written']} finding(s) written "
                        f"to the evidence store")
        return tally

    def poll(self):
        """
        One pass, for the base class's loop -- AND THE BASE CLASS'S LOOP IS NOT
        WHAT RUNS THIS SENSOR TODAY. main.py starts every module that has
        start(), and this adapter's start() deliberately does not spawn a thread:
        the L5-line answer is PULL, and turning it into a poll would change what
        the page says about how fresh an answer is.

        It is here so that a caller who DOES run it on a clock -- or a future
        round that decides to, which is AR-12's open question -- gets the
        findings written rather than only raised. Without this method,
        BaseAdapter._loop would call the inherited no-op poll() forever and this
        sensor would report itself running and healthy while doing nothing at
        all, which is the defect the whole register is written against.

        AND IT HONOURS THE SAME OFF SWITCH collect() DOES. A poll loop that ran
        while the operator had switched the sensor off would be the defect
        again, one layer down.
        """
        if self._switched_off():
            return {"written": 0, "off_by_config": True}
        from tools import autorun_monitor as am
        result = am.monitor_once()
        tally = self._emit_all(result.get("findings") or [])
        self._last_tally = tally
        self._cache = None          # the next collect() re-reads
        return tally

    # THE OFF SWITCH, AR-12, 2026-09-24.
    #
    # `sensors.autorun_monitor.enabled` was documented in config.json and read
    # by NOTHING, for the reason its entry in bugfinder.md gives: this sensor
    # has no poll loop, so there was nothing for the key to gate. The owner's
    # answer, 2026-09-24, was the second of the two designs offered: keep it
    # pull-only and make the switch REFUSE THE CALL, rather than give it a
    # background clock that would start writing rows into the owner's evidence store on
    # a schedule the owner did not ask for.
    #
    # WHAT IT DOES, EXACTLY: with `enabled: false`, query_autoruns does not
    # read systemd, cron, init.d or a single shell file. It returns the refusal
    # below, by name, with the sentence that says an empty answer here is not a
    # clean machine. /api/status carries off_by_config, so the readiness page
    # shows the sensor as switched off rather than as healthy or broken.
    #
    # WHAT IT DOES NOT DO: it does not keep a "last reading" to serve while off.
    # A stale inventory handed out under an off switch is the shape this whole
    # register is written against -- an answer that looks like a measurement and
    # is not one. The refusal names how to turn it back on instead.
    def _switched_off(self) -> bool:
        """Is this sensor switched off in config? Absent key means ON."""
        cfg = ((self.config.get("sensors", {}) or {})
               .get("autorun_monitor", {}) or {})
        return cfg.get("enabled") is False

    def _off_refusal(self) -> dict:
        """
        The answer query_autoruns gives when the operator switched it off.

        Shaped like a real payload on purpose -- same keys, `count: 0`,
        `entries: []` -- so a caller written against the working answer does not
        crash on it, AND carrying `off_by_config: true` plus a sentence no
        reader can mistake for "no autoruns on this machine".
        """
        if not getattr(self, "_off_logged", False):
            logger.info(
                "AutorunMonitor: switched OFF in config "
                "(sensors.autorun_monitor.enabled = false), so NOTHING is "
                "reading this machine's systemd units, cron, init.d scripts or "
                "shell startup files. query_autoruns refuses by name rather "
                "than returning an empty list, because an empty list here "
                "reads as a clean machine.")
            self._off_logged = True
        return {
            "entries": [],
            "count": 0,
            "supported": True,
            "off_by_config": True,
            "counts": {},
            "findings": [],
            "changes": {},
            "coverage": {},
            "cached": False,
            "note": (
                "THIS SENSOR IS SWITCHED OFF IN CONFIG "
                "(sensors.autorun_monitor.enabled = false). Nothing was read: "
                "no systemd unit, no user unit, no cron entry, no init.d script "
                "and no shell startup file. AN EMPTY LIST HERE IS NOT A CLEAN "
                "MACHINE. Set sensors.autorun_monitor.enabled = true in "
                "config.json and ask again."),
            "collected_at": None,
        }

    def status(self) -> dict:
        cached = self._cache or {}
        counts = cached.get("counts", {})
        # AN EMPTY counts DICT IS NOT "NO AUTORUNS", IT IS "NOT LOOKED YET".
        #
        # Found 2026-09-21 by reading the live /api/status back after the
        # backend was flipped to this adapter: the row read counts {} on a
        # host with 438 autorun entries, because nothing calls collect() until
        # the model asks for it. That is the same shape as every other defect
        # this project is written against: a zero that can mean two things,
        # rendered as the reassuring one. The count is now omitted until there
        # is a count, and the note says which state it is in.
        out = {
            "ready": True,
            # NOT `running`. This sensor has no loop, so a readiness page that
            # printed "running" would be answering a question it never asked --
            # the same sentence the L5 line is about.
            "runs_on": "demand (query_autoruns), no poll loop",
            "enabled": not self._switched_off(),
            "note": ("systemd units (system and user), cron jobs, init.d "
                     "scripts and shell startup files. This is the Linux "
                     "answer to registry persistence."),
        }
        # OFF BY CONFIG IS ITS OWN STATE, AND THE PAGE HAS TO SEE IT.
        # A sensor switched off and a sensor that found nothing produce the same
        # empty list, and only a sentence separates them -- the same argument
        # LI-10 and auditd's OFF BY CONFIG make.
        #
        # `ready` IS REMOVED AND `running` IS SET FALSE HERE, which is what
        # local_integrity's switched-off status does, and it is not cosmetic:
        # core/settings._module_row picks its verdict with
        # `st.get("running", st.get("ready", st.get("available")))`, so a dict
        # that keeps `ready: True` paints this row GREEN AND SAYS "running."
        # directly beside the note that says the sensor is switched off.
        # MEASURED before this was corrected: the row read
        # `state: "ok", detail: "running."` with the switched-off sentence
        # underneath it. A control whose own page contradicts it is the defect
        # this round exists to remove.
        if self._switched_off():
            out.pop("ready", None)
            out["running"] = False
            out["off_by_config"] = True
            out["reason"] = (
                "switched OFF in config "
                "(sensors.autorun_monitor.enabled = false)")
            out["note"] = (
                "THIS SENSOR IS SWITCHED OFF IN CONFIG "
                "(sensors.autorun_monitor.enabled = false). Nothing is reading "
                "this machine's systemd units, cron, init.d scripts or shell "
                "startup files. A quiet answer here is not a clean machine: "
                "set sensors.autorun_monitor.enabled = true in config.json to "
                "turn it back on.")
            return out
        if counts:
            out["counts"] = counts
            out["note"] = (f"{sum(counts.values())} autorun entries read: "
                           + ", ".join(f"{v} {k}" for k, v in counts.items())
                           + ". " + out["note"])
        else:
            out["note"] = ("Nothing has been enumerated yet this session. "
                           "That is a statement about when this was asked, "
                           "not about the machine: ask for query_autoruns and "
                           "it reads them. " + out["note"])
        return out

    def collect(self, refresh: bool = False) -> dict:
        import time as _t
        from tools import autorun_monitor as am

        # OFF MEANS OFF, AND IT REFUSES BY NAME (AR-12).
        # Checked BEFORE the cache, deliberately: a cached payload served while
        # the operator has the sensor switched off is a measurement from before
        # the switch, handed out as if it were current.
        if self._switched_off():
            return self._off_refusal()
        self._off_logged = False

        if (not refresh and self._cache
                and _t.time() - self._cached_at < self.CACHE_TTL):
            # A CACHED ANSWER SAYS THAT IT IS CACHED. The first version returned
            # the stored dict and nothing in it moved, so a reader had no way to
            # tell this session's reading from one taken up to an hour ago --
            # and the timestamp it did carry was the module's `timestamp`, which
            # is the time of THAT reading, not of the answer. `cached_at` and
            # `age_seconds` are on the payload now.
            out = dict(self._cache)
            out["cached"] = True
            out["cached_age_seconds"] = round(_t.time() - self._cached_at, 1)
            return out

        result = am.monitor_once()
        counts = result.get("counts", {}) or {}
        entries = []

        # THE COMMAND COLUMN, REPAIRED.
        #
        # Every unit row used to carry `svc.get("path")` under the name
        # `command`, so the model was told that the command starting an autorun
        # was `/lib/systemd/system/anacron.service` -- a filename. The module
        # records the real thing now (`command`, from ExecStart) and the path
        # keeps its own name. The old comment beside that line said a missing key
        # "would have produced a column of NULL commands and looked like a clean
        # inventory", which was true and was also a description of what the line
        # below it was doing.
        for svc in am.get_systemd_services():
            entries.append({
                "location": "systemd" + (" (user)" if svc.get("scope") == "user"
                                         else ""),
                "kind":     "service",
                "name":     svc.get("name"),
                "command":  svc.get("command"),
                "unit_file": svc.get("path"),
                "state":    svc.get("state"),
                "runnable": svc.get("runnable"),
                "why_it_matters": (
                    "A systemd unit starts without anyone asking it to."),
            })
        # USER UNITS, READ AT LAST.
        #
        # AUTORUN_PATHS["systemd_user"] was declared in the module since the port
        # and read by nothing, so ~/.config/systemd/user was invisible: measured
        # on this host it holds hermes-gateway.service, a unit that starts a
        # program at every login. They are a separate block from the system units
        # because who they start for is a different claim.
        for unit in am.get_user_units():
            entries.append({
                "location": "systemd (user)",
                "kind":     "service",
                "name":     unit.get("name"),
                "command":  unit.get("command"),
                "unit_file": unit.get("path"),
                "state":    ("enabled" if unit.get("wanted_by") else "not linked"),
                "wanted_by": unit.get("wanted_by") or [],
                "owner":    unit.get("owner"),
                "why_it_matters": (
                    "A USER unit starts for one account at its login, not for "
                    "the machine."),
            })
        for job in am.get_cron_jobs():
            entries.append({
                "location": job.get("path") or "cron",
                "kind":     job.get("type") or "cron",
                "name":     job.get("name"),
                "command":  job.get("command"),
                "schedule": job.get("schedule"),
                "user":     job.get("user"),
                "runnable": job.get("runnable"),
                "why_it_matters": (
                    "Runs on a schedule, unattended."
                    if job.get("type") == "system_cron" else
                    "An executable in a run-parts directory: cron runs it on "
                    "the schedule of the directory it sits in."),
            })
        for script in am.get_init_scripts():
            entries.append({
                "location": "init.d",
                "kind":     "init_script",
                "name":     script.get("name"),
                # A PATH, NAMED AS ONE. This row is honest about having no
                # command to offer: an init script is the program.
                "command":  script.get("path"),
                "state":    ("linked" if script.get("runlevels") else "not linked"),
                "runlevels": script.get("runlevels") or [],
                "user":     script.get("owner"),
                "why_it_matters": (
                    "A legacy boot script. `not linked` means no runlevel "
                    "calls it, so it is a leftover rather than something that "
                    "starts."),
            })
        for startup in am.get_shell_startup():
            entries.append({
                "location": startup.get("path") or "shell startup",
                "kind":     "shell_startup",
                "name":     startup.get("path"),
                "command":  "; ".join(
                    f"line {s.get('line')}: {(s.get('content') or '').strip()}"
                    for s in (startup.get("suspicious_lines") or [])
                    if isinstance(s, dict)),
                "matched_patterns": sorted({
                    s.get("pattern") for s in
                    (startup.get("suspicious_lines") or [])
                    if isinstance(s, dict) and s.get("pattern")}),
                "user":     startup.get("user"),
                "mode":     startup.get("mode"),
                "why_it_matters": (
                    "Runs on every interactive shell. A line here is how a "
                    "session gets a backdoor."),
            })

        # A change is reported once, so it is filed now, whichever path
        # asked; the next reading compares against this one.
        changes = [f for f in (result.get("findings") or [])
                   if str(f.get("type", "")).startswith("autorun_entry_")]
        if changes:
            self._emit_all(changes)

        coverage = result.get("coverage") or {}
        out = {
            "entries": entries,
            "count":   len(entries),
            "supported": True,
            "counts":  counts,
            "findings": result.get("findings") or [],
            "changes": result.get("changes") or {},
            # THE REFUSALS TRAVEL WITH THE ROWS. A per-user cron spool this
            # account cannot list is a hole in the answer, and it is reported
            # as one rather than as zero user cron jobs.
            "coverage": coverage,
            "cached": False,
            "note": (
                "systemd units (system and user), cron jobs, init.d scripts "
                "and shell startup files on THIS host. Judge these against the "
                "baseline rather than expectations: most are legitimate and "
                "specific to the machine. What is NOT covered is in the "
                "coverage block; an empty list there and an empty list of "
                "entries are different answers."),
            "collected_at": result.get("timestamp"),
        }
        self._cache, self._cached_at = out, _t.time()
        return out


# THE KERNEL CAMERA. T6, 2026-09-22.
#
# The adapter for ebpf/ebpf_monitor.py, which runs as ROOT and writes a sidecar
# file. This class runs as the operator and READS that file. It is the app-side
# end of the one-way street described at length in the camera's own header.
#
# WHY THE SENSOR IS AN ADAPTER AROUND A FILE AND NOT AROUND A PROCESS. The
# camera is not this app's child. It has to be started by root and it has to
# keep running when the app does not, because the whole point of it is to
# record what happens in the gaps. So there is nothing here to start, nothing
# to stop and nothing to restart: there is a file that either has recent events
# in it or does not, and this class's job is to say which, honestly, and to
# turn the small number of interesting events into findings.
#
# WHY IT IS NOT BLIND WHEN THE CAMERA IS SIMPLY NOT INSTALLED. `blind` is for
# "I could not look", and on most hosts the camera is a deliberate absence: it
# needs root and an explicit installer run. Reporting blind for it would attach
# a permanent caveat to every query_findings answer forever, which is how a
# warning list becomes something a reader skips -- the exact argument
# LinuxLocalIntegrity's status() makes about /etc/sudoers. The absence travels
# in the coverage block, in words, and in the tool's own how_to_read_this.
#
# IT IS BLIND FOR THE TWO REAL FAILURES: the file exists but cannot be opened,
# or it opens and is not a camera file. Those are both "I could not look" and
# they are both about the camera rather than about the operator's choices.
class LinuxEbpfEvents(_BaseAdapter):
    """Wraps tools/ebpf_events.py, which reads the kernel camera's sidecar."""

    role = "ebpf_events"

    def __init__(self, session_id, config=None):
        super().__init__(session_id, config)
        self._state = {
            "passes": 0, "findings": 0, "last": None, "seeded": False,
            "last_error": None, "analysed": {}, "capped": [], "notes": [],
            "cursor": None, "camera": {}, "coverage": {},
        }
        self._unregistered = {}
        # A FAILED CURSOR WRITE IS A REAL BLIND SPOT and it is kept here rather
        # than in the notes list, because it means the next pass re-reads the
        # same window: the same finding appears twice, and a reader who sees a
        # monitor repeat itself stops trusting what it says.
        self._cursor_error = None

    # one pass

    def poll(self):
        """One analysis pass over the camera's file, since the cursor."""
        from tools import ebpf_events as ee

        report = ee.analyze(self.config)
        self._state["passes"] += 1
        self._state["last"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        self._state["analysed"] = report.get("analysed") or {}
        self._state["capped"] = report.get("capped") or []
        self._state["notes"] = report.get("notes") or []
        self._state["camera"] = report.get("camera") or {}
        self._state["coverage"] = report.get("coverage") or {}
        self._state["cursor"] = report.get("cursor")

        if report.get("error"):
            # The module caught a read failure inside its own pass. Counted,
            # and the coverage block already says what was not read.
            logger.error(f"ebpf_events: the pass could not read the camera: "
                         f"{report['error']}")

        if report.get("seeded"):
            self._state["seeded"] = True
            logger.info(
                f"ebpf_events: the camera's file is being analysed for the "
                f"first time. The cursor was set to the newest event already "
                f"in it and NOTHING was raised for any of that history: a "
                f"first look over somebody else's record is not a change. "
                f"Analysis starts from the next event. "
                f"{report['coverage'].get('camera') or ''}")

        written = self._emit_all(report.get("findings") or [])
        self._state["findings"] += written
        if written:
            logger.info(f"ebpf_events: {written} finding(s) from "
                        f"{self._state['analysed']}")

        for note in self._state["notes"]:
            logger.warning(f"ebpf_events: {note}")

    def _emit_all(self, findings: list) -> int:
        """
        Write each finding, or count it and say why not.

        THE UNREGISTERED CASE IS COUNTED, NOT SWALLOWED, the same discipline
        the local integrity sensor uses: every id this module raises IS in
        core/detections, so this should never fire, and if somebody adds a
        check and forgets the register, the count and the log line are what
        make it visible rather than a rule that quietly writes nothing.

        THE ENTITY TYPE IS 'process' FOR THE TWO STAGING RULES, which is what
        the register declares, and core/incident.write_incident RAISES on a
        type outside its own vocabulary -- and the watcher CATCHES that and
        counts it, so a wrong type here would reach the findings table and
        open NO incident, silently. 'process' is in both vocabularies.
        """
        from core import detections as det
        from core import memory_engine as me

        written = 0
        for f in findings:
            did = f.get("detection_id")
            try:
                det.get(did)
            except Exception as e:                      # noqa: BLE001
                self._unregistered[did] = self._unregistered.get(did, 0) + 1
                logger.warning(
                    f"ebpf_events produced {did!r} for "
                    f"{f.get('entity_value')} and there is NO registered "
                    f"detection id for it, so it was NOT written: {e}")
                continue

            entity_type = f.get("entity_type") or "process"
            entity_value = f.get("entity_value") or ""
            if not entity_value:
                continue
            if me.is_dismissed(entity_type, entity_value):
                continue
            if me.finding_already_open(self.role, entity_type, entity_value,
                                       f.get("title") or ""):
                # Already open and undismissed. Raised once, not once a poll.
                continue

            severity = _fit_severity(did, f.get("severity", "medium"), "low")
            me.save_finding(
                session_id=self.session_id,
                source=self.role,
                detection_id=did,
                severity=severity,
                entity_type=entity_type,
                entity_value=entity_value,
                title=f.get("title") or f"{did} fired",
                description=f.get("description"),
                raw_data=f.get("raw_data") or {},
            )
            written += 1
        return written

    # status

    def status(self) -> dict:
        """
        What the camera can see. Read by /api/status and by sensor_health.

        THE COVERAGE IS THE ANSWER. A camera that is not installed, one that
        has stopped and one that is quietly recording are three different
        situations with the same empty findings list, and this is the only
        place the difference is written down where a person reads it.
        """
        from tools import ebpf_events as ee

        out = super().status()
        st = ee.camera_status(self.config)

        out["camera"] = {
            "events_db": st.get("events_db"),
            "reachable": st.get("reachable"),
            "running": st.get("running"),
            "has_ever_run": st.get("has_ever_run"),
            "total_events": st.get("total_events"),
            "newest_event_at": st.get("newest_event_at"),
            "newest_event_age_seconds": st.get("newest_event_age_seconds"),
            "drops": st.get("drops"),
            "note": st.get("note"),
        }
        out["reader"] = {k: v for k, v in self._state.items()
                         if k not in ("camera", "coverage", "notes")}
        out["coverage_limits"] = st.get("coverage_limits") or []
        if self._state["notes"]:
            out["notes"] = list(self._state["notes"])
        if self._state["capped"]:
            out["capped"] = self._state["capped"]
        if self._unregistered:
            out["unregistered_detection_ids"] = dict(self._unregistered)

        # THE THREE BLIND CASES, and only these three. A camera that is absent,
        # stopped or dropping is NOT blind: in all three of those the reader
        # could look at everything the camera had, and the answer to "what did
        # it see" is about the camera's uptime rather than about this app's
        # ability to read. See the class header.
        if st.get("blind"):
            out["blind"] = True
            out["blind_reason"] = st.get("blind_reason")
        elif not st.get("enabled", True):
            # Switched off by config: OFF, not broken, and the two must stay
            # different sentences or the readiness page reports a choice as a
            # fault.
            out["note"] = ("the camera's reader is OFF by config, so no kernel "
                           "event is being analysed. That is a configuration "
                           "choice, not a failure, and an empty findings list "
                           "means nothing was looked at.")

        # THE HONEST HEADLINE.
        #
        # The reader's own counters say how much IT has done; the camera's say
        # how much there was to read. Both are needed and neither alone answers
        # "am I being watched", which is the question somebody actually has.
        parts = []
        if st.get("running"):
            parts.append(
                f"the camera is recording ({st.get('total_events')} event(s), "
                f"newest {st.get('newest_event_age_seconds')}s old)")
        elif st.get("has_ever_run"):
            parts.append("the camera is NOT currently recording")
        elif st.get("reachable"):
            parts.append("the camera has never recorded anything")
        else:
            parts.append("there is no readable camera file on this host")

        if self._state["passes"] == 0:
            parts.append("and this app has not analysed it yet this session")
        elif self._state["seeded"] and self._state["passes"] == 1:
            parts.append("and this app has SEEDED it, raising nothing for the "
                         "history already in the file")
        else:
            parts.append(f"and this app has read it {self._state['passes']} "
                         f"time(s), {self._state['findings']} finding(s)")
        out["note"] = ", ".join(parts) + "."

        if not out.get("blind") and not st.get("running"):
            # NOT blind, and deliberately. Stated as a note so it travels with
            # the answer instead of sitting in a coverage dict nobody reads.
            out["coverage_note"] = (
                "NO KERNEL EVENT IS BEING COLLECTED RIGHT NOW. Anything that "
                "ran or connected since the camera stopped is INVISIBLE to "
                "this app, and unlike the polling sensors there is no later "
                "pass that will pick it up: a camera that was off simply did "
                "not see it. This is not the same as a machine where nothing "
                "ran.")
        return out


# THE GATEWAY. T9, 2026-09-29.
#
# Any router that runs tools/gateway_agent.sh is the same thing here. What
# this adapter offers comes from the capabilities the agent reported, never
# from the router's make. See tools/gateway.py.
#
# The clients it reads (DHCP leases and the neighbour table) go through the
# same store and the same RTR-1001 raiser as the SNMP router monitor, so a
# device the router knows about and this store does not is raised once, and
# dismissals apply to it the same way.
#
# NOT CONFIGURED IS NOT BLIND, the same argument as auditd: no router agent is
# an ordinary state of an install, and it travels in status() in words.
class LinuxGateway(_BaseAdapter):
    """The router, asked through its agent."""

    role = "gateway"

    def __init__(self, session_id, config=None, transport=None):
        super().__init__(session_id, config)
        from tools import gateway as gw
        self.cfg = gw.settings(config)
        self._transport = transport
        self._gw = None
        self._state = {"probe": None, "polls": 0, "last": None,
                       "clients_seen": 0, "clients_new": 0, "raised": 0}

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.get("enabled") and self.cfg.get("host"))

    @property
    def poll_interval(self) -> int:
        return max(60, int(float(self.cfg.get("interval_minutes") or 5) * 60))

    def _gateway(self):
        from tools import gateway as gw
        if not self.enabled:
            raise gw.GatewayError(
                "No router agent is configured. Enroll one with "
                "scripts/install_gateway_agent.sh, then set gateway.enabled "
                "and gateway.host in config.json.")
        if self._gw is None:
            self._gw = gw.Gateway(self.config, transport=self._transport)
        return self._gw

    def _sensor_id(self) -> str:
        import hashlib
        return "gw-" + hashlib.sha256(self.cfg["host"].encode()).hexdigest()[:12]

    def start(self):
        if not self.enabled:
            logger.info("Gateway agent not configured; router reads and "
                        "router actions are not offered.")
            return
        super().start()

    def poll(self):
        from tools import gateway as gw
        from tools import router_monitor as rm
        from core import memory_engine as me
        from core import sensors as sn

        g = self._gateway()
        probe = g.probe()
        self._state["probe"] = probe
        caps = probe["capabilities"]

        scope = sn.describe("gateway_api")
        described = gw.describe_capabilities(caps)
        me.upsert_sensor(
            sensor_id=self._sensor_id(), position="gateway_api",
            label=self.cfg.get("label"), summary=scope["summary"],
            can_see=("Through the router agent: "
                     + ("; ".join(described["can_see"]) or "nothing yet")
                     + "."),
            cannot_see=scope["cannot_see"],
            notes=(f"Router agent over SSH, capabilities reported: "
                   f"{', '.join(caps) or 'none'}. Router OS as it reports "
                   f"itself: {probe.get('os_release') or probe.get('os')}."))

        rows = {}
        if "neighbors" in caps:
            for r in g.neighbors():
                rows[(r["ip"], r["mac"])] = r
        if "leases" in caps:
            for r in g.leases():
                rows[(r["ip"], r["mac"])] = r
        saved = me.save_router_clients(list(rows.values()), self.cfg["host"],
                                       self._sensor_id())
        raised = rm._raise_client_findings(saved["new"], self.cfg["host"],
                                           self.session_id, self._sensor_id())
        self._state.update({"polls": self._state["polls"] + 1,
                            "last": time.strftime("%Y-%m-%dT%H:%M:%S"),
                            "clients_seen": saved["seen"],
                            "clients_new": len(saved["new"]),
                            "raised": self._state["raised"] + raised})

    def status(self) -> dict:
        out = super().status()
        out["enabled"] = self.enabled
        if not self.enabled:
            out.update({"ready": True, "blind": False,
                        "note": ("No router agent is configured. The app sees "
                                 "this host's traffic only, and cannot block "
                                 "at the router.")})
            return out
        out.update(self._state)
        if self._last_error:
            out["blind"] = True
            out["blind_reason"] = (f"Could not read the router through its agent: "
                                   f"{self._last_error}. Router clients and "
                                   f"router actions are unavailable, which is "
                                   f"not the same as the network being quiet.")
        else:
            out["blind"] = False
        return out

    # reads, for query_gateway

    def query(self, what: str = "capabilities", ip: str = None,
              lines: int = 200) -> dict:
        from tools import gateway as gw
        try:
            g = self._gateway()
            if what == "capabilities":
                probe = g.probe()
                return {"router": probe,
                        **gw.describe_capabilities(probe["capabilities"])}
            if what == "leases":
                return {"leases": g.leases()}
            if what == "neighbors":
                return {"neighbors": g.neighbors()}
            if what == "connections":
                if ip:
                    ip = _validated_ip(ip)
                return {"connections": g.conntrack(ip)}
            if what == "log":
                return {"lines": g.log(lines)}
            if what == "dns_log":
                return {"lines": g.dnslog(lines)}
            if what == "blocks":
                return {"blocked": g.blocks(),
                        "note": "blocks at the router last until it reboots"}
            if what == "sinkholes":
                return {"sinkholed": g.sinkholes()}
            if what in ("live", "live_device"):
                from tools import lan_live
                mon = lan_live.get()
                if mon is None:
                    return {"error": "the live LAN monitor is not running"}
                if what == "live":
                    snap = mon.snapshot()
                    for d in snap["devices"]:
                        d.pop("spark", None)
                    return snap
                out = mon.device(_validated_ip(ip))
                out.pop("history", None)
                out["destinations"] = out.get("destinations", [])[:50]
                out["lookups"] = out.get("lookups", [])[:50]
                return out
            return {"error": f"what must be one of capabilities, leases, "
                             f"neighbors, connections, log, dns_log, blocks, "
                             f"sinkholes, live, live_device; got {what!r}"}
        except (gw.GatewayError, ValueError) as e:
            return {"error": str(e)}

    # actions, each recorded as an action record

    def _act(self, method: str, arg: str, reason: str, session_id: str,
             did: str, title: str, entity: str) -> dict:
        from tools import gateway as gw
        from core import memory_engine as me
        if not (reason or "").strip():
            return {"success": False,
                    "error": "reason is required. Say what this is for."}
        args = arg if isinstance(arg, tuple) else (arg,)
        try:
            g = self._gateway()
            fields = getattr(g, method)(*args)
        except gw.GatewayError as e:
            return {"success": False, "refused": True, "error": str(e)}
        kept = method in ("block", "block_mac", "block_app") and g.has("persist")
        result = {"success": True, "enforcement_point": "gateway",
                  "router": self.cfg["host"], **fields,
                  "lasts": ("until it is lifted, across router reboots"
                            if kept else "until the router reboots")}
        changed = fields.get("already") != "yes" and \
            fields.get("was_blocked") != "no" and \
            fields.get("was_sinkholed") != "no"
        if not changed:
            result["note"] = "nothing changed: it was already in that state"
            return result
        try:
            me.save_finding(
                session_id=session_id or self.session_id,
                source="remediation", detection_id=did, severity="info",
                entity_type="ip", entity_value=entity, title=title,
                description=reason,
                raw_data={"router": self.cfg["host"], "argument": arg,
                          "reason": reason, "agent_reply": fields})
        except Exception as e:
            result["record_error"] = (f"The router changed. The record of it "
                                      f"was NOT written: {e}")
        return result

    def block_device(self, ip: str, reason: str, session_id: str = None):
        try:
            ip = _validated_ip(ip)
        except ValueError as e:
            return {"success": False, "error": str(e)}
        return self._act("block", ip, reason, session_id, "REM-1009",
                         f"Device blocked at the router: {ip}", ip)

    def unblock_device(self, ip: str, reason: str, session_id: str = None):
        try:
            ip = _validated_ip(ip)
        except ValueError as e:
            return {"success": False, "error": str(e)}
        out = self._act("unblock", ip, reason, session_id, "REM-1010",
                        f"Device unblocked at the router: {ip}", ip)
        if out.get("was_blocked") == "no":
            return {"success": False, "refused": True, "ip": ip,
                    "error": f"The router held no block on {ip} from this "
                             f"app, so nothing was lifted."}
        return out

    def block_address(self, ip: str, reason: str, session_id: str = None):
        """Block a remote address for the whole home, both directions."""
        try:
            ip = _validated_ip(ip)
        except ValueError as e:
            return {"success": False, "error": str(e)}
        return self._act("block", ip, reason, session_id, "REM-1009",
                         f"Address blocked at the router for every device: "
                         f"{ip}", ip)

    def unblock_address(self, ip: str, reason: str, session_id: str = None):
        try:
            ip = _validated_ip(ip)
        except ValueError as e:
            return {"success": False, "error": str(e)}
        out = self._act("unblock", ip, reason, session_id, "REM-1010",
                        f"Address unblocked at the router: {ip}", ip)
        if out.get("was_blocked") == "no":
            return {"success": False, "refused": True, "ip": ip,
                    "error": f"The router held no block on {ip} from this "
                             f"app, so nothing was lifted."}
        return out

    def block_mac(self, mac: str, reason: str, session_id: str = None,
                  ip: str = None):
        """Cut a device off by hardware address. ip, when known, is what the
        record is filed under."""
        mac = str(mac or "").strip().lower()
        return self._act("block_mac", mac, reason, session_id, "REM-1013",
                         f"Device blocked at the router by hardware address "
                         f"{mac}", ip or mac)

    def unblock_mac(self, mac: str, reason: str, session_id: str = None,
                    ip: str = None):
        mac = str(mac or "").strip().lower()
        out = self._act("unblock_mac", mac, reason, session_id, "REM-1014",
                        f"Device unblocked at the router: {mac}", ip or mac)
        if out.get("was_blocked") == "no":
            return {"success": False, "refused": True, "mac": mac,
                    "error": f"The router held no block on {mac} from this "
                             f"app, so nothing was lifted."}
        return out

    def block_app(self, mac: str, app: str, reason: str,
                  session_id: str = None, ip: str = None):
        """Block one app on one device by its hardware address."""
        mac = str(mac or "").strip().lower()
        app = str(app or "").strip().lower()
        return self._act("block_app", (mac, app), reason, session_id,
                         "REM-1015", f"App {app} blocked at the router for "
                         f"{mac}", ip or mac)

    def unblock_app(self, mac: str, app: str, reason: str,
                    session_id: str = None, ip: str = None):
        mac = str(mac or "").strip().lower()
        app = str(app or "").strip().lower()
        out = self._act("unblock_app", (mac, app), reason, session_id,
                        "REM-1016", f"App {app} allowed again at the router "
                        f"for {mac}", ip or mac)
        if out.get("was_blocked") == "no":
            return {"success": False, "refused": True, "mac": mac, "app": app,
                    "error": f"The router held no block on {app} for {mac} "
                             f"from this app, so nothing was lifted."}
        return out

    def sinkhole_domain(self, domain: str, reason: str,
                        session_id: str = None):
        return self._act("sinkhole", str(domain or "").strip().lower(),
                         reason, session_id, "REM-1011",
                         f"Domain sinkholed at the router: {domain}",
                         self.cfg.get("host") or "?")

    def unsinkhole_domain(self, domain: str, reason: str,
                          session_id: str = None):
        out = self._act("unsinkhole", str(domain or "").strip().lower(),
                        reason, session_id, "REM-1012",
                        f"Domain sinkhole lifted at the router: {domain}",
                        self.cfg.get("host") or "?")
        if out.get("was_sinkholed") == "no":
            return {"success": False, "refused": True,
                    "error": f"The router held no sinkhole for {domain} from "
                             f"this app, so nothing was lifted."}
        return out
