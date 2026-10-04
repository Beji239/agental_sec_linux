# tools/probe.py
# AgentalSec V2, the device inventory probe.
#
# WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT.
#
# This is the expensive half of a two-cadence design. The other half is the
# presence sweep in network_scanner, which runs every fifteen minutes, sends a
# ping and reads the ARP cache, and answers ONE question: is it there.
#
# This one runs every three weeks and answers a different question: is it
# still the same thing. It re-derives the fingerprint of every device the user
# marked permanent and compares it with what was recorded when they vouched
# for it.
#
# THE TWO CADENCES MUST NOT BE COLLAPSED, and that is not a style preference.
# Microsoft's three week figure for Defender is a FINGERPRINTING cadence;
# Defender is passively discovering continuously in between. A single three
# week cadence doing both jobs leaves a 21 day window in which a device can
# join, act and leave without being enumerated once, and it destroys the
# absence signal outright, because "always present" cannot be asserted from
# samples taken every 21 days. That conflation was the first design error
# review caught in this feature.
#
# NOT A MODEL TOOL. Nothing in core/tool_registry dispatches to it, at any
# privilege. The reasoning is the same as for set_device_permanence and
# merge_devices, and one step further: probing ORIGINATES TRAFFIC. Every
# comparable product bounds it as scheduled infrastructure with an exclusion
# list, a rate limit and a stated blast radius, and never as a capability an
# analyst fires at will. In the one product where the analyst is a model, it
# is not in the manifest at all.

import logging
import threading
import time

logger = logging.getLogger(__name__)

from core import memory_engine as me
from core import finding_policy as fp

# Microsoft's published Defender figure: a device is re-scanned no more than
# once every three weeks, and only when its characteristics change. Taken as
# the yardstick because it is the most conservative published cadence for the
# same job, not because 21 is special.
DEFAULT_INTERVAL_DAYS = 21

# Hosts fingerprinted in a single pass. The rate limit is not about CPU on
# this machine; it is about how much traffic arrives at somebody else's
# device in one burst. Defender's stated budget is under 50 KB per attempt.
DEFAULT_MAX_HOSTS_PER_PASS = 25

# Seconds between hosts within a pass. Spreads the traffic rather than
# arriving as a wave, which is what makes a fragile device fall over.
DEFAULT_PACING_SECONDS = 2.0

SECONDS_PER_DAY = 86400


class DeviceProbe:
    """
    Scheduled re-fingerprinting of devices the user declared permanent.

    Owns its own schedule. That is the property that makes its output a
    measurement: the model cannot choose when it runs, so it cannot choose
    what the record shows.
    """

    def __init__(self, session_id: str, config: dict = None):
        block = (config or {}).get("probe", {}) or {}

        self.session_id     = session_id
        self.enabled        = bool(block.get("enabled", True))
        self.interval_days  = max(1, int(block.get("interval_days",
                                                   DEFAULT_INTERVAL_DAYS)))
        self.max_per_pass   = max(1, int(block.get("max_hosts_per_pass",
                                                   DEFAULT_MAX_HOSTS_PER_PASS)))
        self.pacing_seconds = max(0.0, float(block.get("pacing_seconds",
                                                       DEFAULT_PACING_SECONDS)))

        # THE EXCLUSION LIST FAILS OPEN, WHICH IS THE OPPOSITE OF THE
        # PERMANENT LIST, AND THE ASYMMETRY IS DELIBERATE.
        #
        # Permanence is an allowlist: a device nobody vouched for is simply
        # not probed, so a new device defaults to being left alone. Exclusion
        # is a denylist on top: an address here is never probed even if it is
        # marked permanent.
        #
        # Both directions therefore default to NOT touching the device, which
        # is the safe default for something that originates traffic. The
        # documented reason other products carry an exclusion list is
        # honeypots belonging to other security tools, and that reason applies
        # here unchanged.
        self.exclusions = {
            str(a).strip() for a in (block.get("exclusion_list") or []) if str(a).strip()
        }

        self._running = False
        self._thread  = None

    # LIFECYCLE

    def start(self):
        if not self.enabled:
            logger.info("Device probe disabled in config.")
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, name="device-probe", daemon=True)
        self._thread.start()
        logger.info(
            f"Device probe started, every {self.interval_days} day(s), "
            f"up to {self.max_per_pass} host(s) per pass, "
            f"{len(self.exclusions)} address(es) excluded."
        )

    def stop(self):
        self._running = False

    def status(self) -> dict:
        """
        One read of the run record, used for every figure below.

        IT USED TO CALL me.last_probe_run THREE TIMES per read (measured by
        counting the calls: last_probe_run, age_days and due each fetched it),
        and the three answers could straddle a pass that finished between
        them — a status line assembled from two different runs. RVP-11.
        """
        last = me.last_probe_run("ok")
        age = self._age_days_from(last)
        overdue = True if age is None else age >= self.interval_days
        return {
            "running":        self._running,
            "interval_days":  self.interval_days,
            "max_per_pass":   self.max_per_pass,
            "exclusions":     len(self.exclusions),
            "last_run_at":    (last or {}).get("started_at"),
            "days_since_last": (round(age, 1) if age is not None else None),
            "overdue":        overdue,
            # No last run is NOT the same as nothing to report, and the
            # difference matters on a fresh install where a user might read a
            # quiet probe as a clean one.
            "has_ever_run":   last is not None,
            # Both of the fields above were already here and nothing read
            # them, so the readiness row said 'running.' on a probe that had
            # never completed a pass. The thread being alive is not the
            # claim anybody wants from this module.
            "note":           self._state_note(last, age, overdue),
        }

    def _state_note(self, last, age, overdue) -> str:
        """
        What this module can honestly say about itself, in words.

        RVP-12, 2026-09-27. The overdue sentence used to promise "the next
        hourly check will run one", and the HOURLY CHECK IS NOT WHAT RUNS A
        PASS: _loop wakes hourly but run_once() returns "skipped" until the
        wall-clock interval has elapsed, which is the whole point of the
        cadence design. The sentence also said "Past the N day interval"
        about a value the reader could not check.

        AND THE RETIREMENT HALF WAS MISSING ENTIRELY. retire_absent() runs at
        the END of a due pass, so a device 106 consecutive sweeps absent is
        not retired at all until the 21-day cadence comes round again —
        measured: with 106 misses on record and a successful pass inside the
        interval, run_once() returned "skipped" and the device stayed
        permanent. That is a real answer to "why is this still being reported
        absent", and it belongs in the note rather than in the reader's head.
        """
        if last is None:
            return ("No probe pass has completed yet, so nothing has been "
                    "measured about the devices on this network. That is not "
                    "the same as nothing being found.")
        when = "unknown" if age is None else f"{age:.1f} days"
        if overdue:
            return (f"Last pass {when} ago, past the {self.interval_days} day "
                    f"interval. The next check that comes due will run a pass, "
                    f"a fingerprint comparison and the retirement sweep; a "
                    f"check that is not due does none of them.")
        return (f"Last pass {when} ago. Runs every {self.interval_days} days, "
                f"and the retirement sweep runs with the same pass.")

    def _loop(self):
        # Checked hourly rather than slept for three weeks, so that a machine
        # which is off most of the time still probes when it is on. A three
        # week sleep on a laptop that runs four hours a day would fire roughly
        # never.
        while self._running:
            try:
                self.run_once()
            except Exception as e:
                logger.error(f"Device probe error: {e}")
                try:
                    me.record_probe_run(self.session_id, "failed",
                                        detail=f"Unhandled error: {e}")
                except Exception:
                    pass
            time.sleep(3600)

    # THE PASS

    def age_days(self) -> float | None:
        """
        Days since the last successful pass, or None if there has never been
        one. Wall clock, not uptime.

        THE DISTINCTION MATTERS HERE MORE THAN ALMOST ANYWHERE.
        This tool is for homelabs, and homelab machines are switched off. A
        cadence measured in the app's own running time would drift further
        behind reality the less the machine is used, which is exactly
        backwards, because a machine that has been off for a month is the one
        whose inventory is most stale. Measuring against the calendar means
        the probe fires on the next boot after it comes due, whether the gap
        was three weeks of uptime or three weeks of the lid being shut.
        """
        return self._age_days_from(me.last_probe_run("ok"))

    @staticmethod
    def _age_days_from(last: dict | None) -> float | None:
        """The arithmetic above, against a run row the caller already read."""
        if not last or not last.get("started_at"):
            return None
        from datetime import datetime, timezone
        try:
            when = datetime.fromisoformat(
                str(last["started_at"]).replace(" ", "T").replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - when).total_seconds() / SECONDS_PER_DAY

    def due(self) -> bool:
        """
        Has the cadence elapsed since the last successful pass?

        An unreadable or missing timestamp returns True. Failing towards
        probing is right: the cost is one extra pass, and the cost of the
        other direction is an inventory that silently never refreshes.
        """
        age = self.age_days()
        if age is None:
            return True
        return age >= self.interval_days

    def run_once(self, force: bool = False) -> dict:
        """
        One pass. Returns a summary and always records what happened.

        force exists for tests and for the dashboard, never for the model.
        """
        age = self.age_days()

        if not force and not self.due():
            me.record_probe_run(
                self.session_id, "skipped",
                detail=(f"Cadence has not elapsed: {age:.1f} of "
                        f"{self.interval_days} day(s)." if age is not None
                        else "Cadence has not elapsed."))
            return {"outcome": "skipped"}

        # Say how stale the inventory had become, because on a machine that is
        # off most of the time this is frequently much larger than the
        # configured interval, and that is worth knowing rather than hiding.
        # It is not a fault: it is the honest coverage of a tool that only
        # runs when the machine does.
        if age is None:
            logger.info("Device probe: first pass, no previous run on record.")
        elif age > self.interval_days * 1.5:
            logger.warning(
                f"Device probe: last successful pass was {age:.1f} days ago, "
                f"well past the {self.interval_days} day cadence. The machine "
                f"was probably off. Running now, and the inventory has been "
                f"unverified for that whole period."
            )
        else:
            logger.info(f"Device probe: due after {age:.1f} day(s).")

        eligible = me.permanent_devices()
        excluded = [d for d in eligible if d["ip"] in self.exclusions]
        targets  = [d for d in eligible if d["ip"] not in self.exclusions]

        # Oldest fingerprint first, so a rate-limited pass makes progress
        # through the whole set over successive passes instead of
        # re-fingerprinting the same alphabetical prefix forever.
        targets.sort(key=lambda d: (d.get("enrollment_fingerprint_at") or "",
                                    d["ip"]))
        deferred = max(0, len(targets) - self.max_per_pass)
        targets  = targets[:self.max_per_pass]

        drift_found = 0
        probed      = 0

        for device in targets:
            if not self._running and not force:
                break
            try:
                if self._probe_one(device):
                    drift_found += 1
                probed += 1
            except Exception as e:
                logger.warning(f"Probe of {device['ip']} failed: {e}")
            if self.pacing_seconds:
                time.sleep(self.pacing_seconds)

        retired = self.retire_absent()

        me.record_probe_run(
            self.session_id, "ok",
            eligible=len(eligible), probed=probed, excluded=len(excluded),
            deferred=deferred, drift_found=drift_found, retired=retired,
        )
        logger.info(
            f"Device probe pass: {probed} probed, {drift_found} with drift, "
            f"{len(excluded)} excluded, {deferred} deferred, {retired} retired."
        )
        return {
            "outcome": "ok", "eligible": len(eligible), "probed": probed,
            "excluded": len(excluded), "deferred": deferred,
            "drift_found": drift_found, "retired": retired,
        }

    def _probe_one(self, device: dict) -> bool:
        """
        Compare one device against its enrollment fingerprint.

        Returns True if anything changed. Raises a finding when it did, under
        the declared-expectation rule in memory_engine: enrolling the device
        recorded what it looked like, so reporting that it no longer looks
        that way is arithmetic against the user's own declaration, not an
        opinion about whether the change is bad.
        """
        ip     = device["ip"]
        result = me.query_device_drift(ip=ip)
        rows   = result.get("devices") or []
        if not rows:
            return False

        row = rows[0]
        if not row.get("comparable"):
            return False

        changes = row.get("changes") or []
        # TODO 8.4. Threshold unchanged (one changed field), but it now comes
        # from the register rather than from `if not changes`, so drift and
        # absence can no longer drift apart without the diff showing it.
        if fp.should_raise("device_drift", len(changes))["decision"] != fp.RAISE:
            return False

        # THE TWO RULES EVERY OTHER RAISER IN THIS TREE OBEYS. PRB-3,
        # 2026-09-27. Measured before this fix, driving the shipped pass:
        #
        #   * A DRIFT THAT IS STILL TRUE IS NOT NEWS. Three consecutive
        #     passes over one unchanged, still-drifted device wrote THREE
        #     PRB-1001 rows, because nothing here asked whether the condition
        #     was already open — the guard memory_engine provides and that
        #     tools/dns_inspector and tools/feed_matcher both call. The
        #     cadence does not save it: a device drifts once and every pass
        #     from then on re-files it, which is the burial-tool failure
        #     this codebase has already paid for once (PM-1's family).
        #   * A DISMISSED ADDRESS IS NOT RAISED ABOUT. The operator's
        #     dismissal is consulted by ten call sites in adapters.py and by
        #     network_scanner and linux_monitor; this module never asked.
        #     The retirement path below had the worse version of the same
        #     gap: PRB-1002 CHANGES THE MACHINE (it clears the permanence
        #     flag) and then filed a finding about a device the operator had
        #     explicitly dismissed. Measured: with 'ip' dismissed,
        #     retire_absent() returned 1 and wrote the row.
        title = (f"Enrolled device changed: "
                 f"{device.get('known_as') or ip}")
        if me.is_dismissed("ip", ip):
            logger.debug(f"PRB-1001 not raised for {ip}: dismissed")
            return False
        if me.finding_already_open("probe", "ip", ip, title):
            logger.debug(f"PRB-1001 not raised for {ip}: already open")
            return False

        res = me.save_finding(
            session_id=self.session_id,
            source="probe",
            detection_id="PRB-1001",
            severity="medium",
            entity_type="ip",
            entity_value=ip,
            title=title,
            description=(
                f"You marked this device as permanently present and its "
                f"fingerprint was recorded then. It no longer matches:\n\n"
                + "\n".join(f"  - {c}" for c in changes)
                + "\n\nThis is a DIFFERENCE, not a verdict. A newly open port "
                  "can be a firmware update or an intrusion, and a changed "
                  "hardware address under the same IP can be a replaced "
                  "device or a lease reassignment. What would separate the "
                  "innocent explanation from the other one is whether you "
                  "changed anything about this device recently."
                + ("" if row.get("ports_comparable") else
                   "\n\nNote: ports were NOT compared, because no port scan "
                   "exists on one side. Run one before reading anything into "
                   "the port set.")
            ),
            raw_data={"changes": changes,
                      "enrolled_at": row.get("enrolled_at")},
        )
        # THE COUNT FOLLOWS THE WRITER'S ANSWER, not the call having been
        # made. save_finding returns {"saved": False, ...} when a suppression
        # rule declines the write, and drift_found is published on every pass
        # and stored on the probe_run row — so counting the call instead of
        # the answer reports a drift this tool deliberately did not file.
        # Same shape as adapters.py's _finding_landed, one module over.
        return not (isinstance(res, dict) and res.get("saved") is False)

    def retire_absent(self) -> int:
        """
        Stop expecting devices that have stopped answering, and say so once.

        Two thresholds, and the order is the point. A device raises an ABSENCE
        FINDING first, well before it is retired, so a vanished device
        produces a question rather than a silent shrug. Only after it has been
        gone long enough that the question has clearly been answered by
        events does it stop being expected.
        """
        retired = 0
        presence = me.query_presence(max_sweeps=max(me.RETIRE_AFTER_MISSES, 200))
        window   = presence.get("window") or {}

        # Not enough sweeps to justify retiring anything. Absence measured
        # against three samples is not absence, it is a small number.
        if (window.get("sweeps_counted") or 0) < me.RETIRE_AFTER_MISSES:
            return 0

        by_ip = {d["ip"]: d for d in presence.get("devices", [])}

        for device in me.permanent_devices():
            row = by_ip.get(device["ip"])
            streak = (row or {}).get("absent_streak")
            if streak is None:
                # Never seen in the window at all. Treated as absent for the
                # whole window rather than as unknown, because a permanent
                # device that never answered once across the window is the
                # case being looked for.
                streak = window.get("sweeps_counted") or 0
            if streak < me.RETIRE_AFTER_MISSES:
                continue
            # A sweep of another network says nothing about this device: a
            # laptop away from home would otherwise retire everything there
            # (PRB-4). Every sweep in the streak must have covered its subnet.
            outside = me.sweeps_not_covering(device["ip"], streak)
            if outside:
                logger.info(
                    f"{device['ip']} not retired: {outside} of its last "
                    f"{streak} sweep(s) ran on a network that does not "
                    f"contain it, so its silence there is not absence.")
                continue

            me.retire_device(
                device["ip"],
                reason=(f"No reply across {streak} consecutive presence "
                        f"sweeps. Retired automatically."),
            )
            # THE RETIREMENT HAPPENS; THE FINDING OBEYS THE DISMISSAL. PRB-3,
            # 2026-09-27. These are two different things and they were one
            # statement: an operator who dismissed an address said "stop
            # telling me about this device", not "keep expecting it forever".
            # So the retirement still runs — otherwise a dismissed dead device
            # stays in the absence check and the dismissal becomes the reason
            # the noise never ends — while the row about it is suppressed,
            # which is what the dismissal asked for.
            if me.is_dismissed("ip", device["ip"]):
                logger.info(
                    f"{device['ip']} retired after {streak} consecutive "
                    f"misses; its finding was not filed, because the operator "
                    f"has dismissed this address.")
                retired += 1
                continue
            title = (f"Permanent device retired: "
                     f"{device.get('known_as') or device['ip']}")
            if me.finding_already_open("probe", "ip", device["ip"], title):
                continue
            me.save_finding(
                session_id=self.session_id,
                source="probe",
                detection_id="PRB-1002",
                severity="medium",
                entity_type="ip",
                entity_value=device["ip"],
                title=title,
                description=(
                    f"This device was marked as permanently present and has "
                    f"not answered {streak} consecutive presence sweeps. It "
                    f"is no longer being treated as expected, so it will stop "
                    f"reporting as missing.\n\n"
                    f"Nothing has been deleted. Its record and its enrollment "
                    f"fingerprint are kept, so if it returns it can be "
                    f"recognised and marked permanent again.\n\n"
                    f"If this device should still be here, that is the "
                    f"finding, not this message."
                ),
                raw_data={"absent_streak": streak},
            )
            retired += 1

        return retired
