# core/rollup_engine.py
# AgentalSec V2, Behavioral baseline rollup engine
# Runs hourly in background + on clean shutdown.
# Merges behavioral_session into behavioral_baseline.
# Also processes silence timer, unresponded deviations -> flagged as normal.

import json
import logging
import math
import threading
import time
from datetime import datetime, timezone

from core import memory_engine as me

logger = logging.getLogger(__name__)

# Set by main.py
_session_id: str = None
_rollup_interval_minutes: int = 60
_stop_event = threading.Event()
_rollup_thread: threading.Thread = None

# Silence check runs every 2 minutes independently
_silence_thread: threading.Thread = None

# WHAT status() READS.
#
# Both threads above are daemons. If either dies the process keeps serving
# pages perfectly happily, the baseline quietly stops being merged, and the
# settings panel went on printing 'loaded.', because this module had no
# status() at all and the panel fell through to its no-status branch. That
# word only ever meant the import worked.
#
# _last_rollup_at is stamped by run_rollup itself rather than by the loop, so
# a manual or shutdown merge counts too. The question this answers is when
# the baseline last merged, not which caller asked for it.
_threads_started: bool = False
_threads_started_at: float = None
_last_rollup_at: float = None
_last_rollup_error: str = None


# CONFIDENCE THRESHOLDS
#
# Moved into memory_engine on 2026-08-29. It lived here, but memory_engine
# needs it too (it clamps a claimed confidence against measured sessions) and
# rollup_engine already imports memory_engine, so importing the other way
# would be a cycle. One copy, in the module that owns the preference.
_confidence_thresholds = me.confidence_thresholds

# (session, entity type, value, key) -> the newest observation id rolled up.
_rolled = {}


# INIT

def init_rollup(session_id: str, interval_minutes: int = None):
    """Called by main.py after DB is ready."""
    global _session_id, _rollup_interval_minutes
    _session_id = session_id

    pref = me.get_preference("rollup_interval_minutes", "60")
    _rollup_interval_minutes = interval_minutes or int(pref)

    logger.info(
        f"Rollup engine initialized. "
        f"Session: {session_id}; Interval: {_rollup_interval_minutes} min"
    )


def start_background_threads():
    """Start hourly rollup + silence timer threads. Called by main.py."""
    global _rollup_thread, _silence_thread
    global _threads_started, _threads_started_at

    _stop_event.clear()
    _threads_started = True
    _threads_started_at = time.time()

    _rollup_thread = threading.Thread(
        target=_rollup_loop,
        name="RollupEngine",
        daemon=True,
    )
    _rollup_thread.start()
    logger.info("Rollup background thread started.")

    _silence_thread = threading.Thread(
        target=_silence_loop,
        name="SilenceTimer",
        daemon=True,
    )
    _silence_thread.start()
    logger.info("Silence timer thread started.")


def stop_background_threads():
    """Signal threads to stop. Called on clean shutdown."""
    global _threads_started
    _stop_event.set()
    # A stop asked for is not a thread that died, and status() must not
    # report the two the same way.
    _threads_started = False


def _stamp_rollup():
    """
    Record that a merge finished. Called by run_rollup on both of its exits.

    Stamped there rather than in the loop so a manual or shutdown merge
    counts too: status() answers when the baseline last merged, not when the
    timer last fired.
    """
    global _last_rollup_at, _last_rollup_error
    _last_rollup_at = time.time()
    _last_rollup_error = None


def _age_words(seconds) -> str:
    """Seconds to something a person reads. Only used by status()."""
    if seconds is None:
        return "never"
    seconds = int(seconds)
    if seconds < 90:
        return f"{seconds} seconds"
    if seconds < 5400:
        return f"{seconds // 60} minutes"
    return f"{seconds // 3600} hours"


def status() -> dict:
    """
    Is the merge actually happening, rather than merely imported.

    Three things can be true here and they do not look alike:
      the threads were never started        off, and nothing is merging
      a thread has died                     a fault, the baseline is frozen
      a thread is alive and merging nothing  also a fault. Alive was never
                                             the same as working, and this
                                             loop can sit inside a run_rollup
                                             that never returns without ever
                                             dying.

    The window before the first merge is NOT a fault. On a fresh start there
    is legitimately nothing yet, and saying so beats both a green tick and a
    red one.

    WHY THIS EXISTS AT ALL. The dashboard's readiness page normalises every
    module through settings._module_row, which reads status() and paints a
    row. A module with no status() got the bare word 'loaded.', which means
    the import worked and nothing was checked. Both threads here are daemons:
    if either dies, the app keeps serving pages and the baseline silently
    stops merging, which is exactly the shape a 'loaded.' row cannot show.
    """
    now = time.time()

    if not _threads_started:
        return {
            "running": False,
            "reason": ("the background threads are not running, so nothing "
                       "is merging the session into the baseline."),
        }

    interval_s = max(60, int(_rollup_interval_minutes) * 60)
    uptime = now - (_threads_started_at or now)
    last_age = (now - _last_rollup_at) if _last_rollup_at else None

    dead = [n for n, t in (("rollup", _rollup_thread),
                           ("silence timer", _silence_thread))
            if not (t and t.is_alive())]

    parts = [f"merging every {_rollup_interval_minutes} minutes"]
    if _last_rollup_at:
        parts.append(f"last merge {_age_words(last_age)} ago")
    else:
        parts.append(f"no merge yet this run, the first is due "
                     f"{_rollup_interval_minutes} minutes after start")
    if _last_rollup_error:
        parts.append(f"the last failure said: {_last_rollup_error}")
    note = "Baseline rollup: " + ", ".join(parts) + "."

    base = {
        "rollup_thread_alive":    bool(_rollup_thread and _rollup_thread.is_alive()),
        "silence_thread_alive":   bool(_silence_thread and _silence_thread.is_alive()),
        "interval_minutes":       _rollup_interval_minutes,
        "last_rollup_age_seconds": int(last_age) if last_age is not None else None,
        "last_error":             _last_rollup_error,
        "note":                   note,
    }

    if dead:
        return dict(base,
                    running=False,
                    fault=(f"started at boot, but the {' and the '.join(dead)} "
                           f"thread is no longer alive. Nothing is merging the "
                           f"session into the baseline."),
                    fix="Restart the app. The log holds what killed it.")

    # Two intervals, not one. A merge that starts late is normal, a merge
    # that has not happened in twice its own period is not.
    stalled_for = last_age if last_age is not None else uptime
    if stalled_for > interval_s * 2:
        return dict(base,
                    running=True,
                    fault=(f"the thread is alive and nothing has merged in "
                           f"{_age_words(stalled_for)}, which is more than "
                           f"two intervals. Alive is not the same as working."),
                    fix="The log is the place to look, a merge may be stuck.")

    return dict(base, running=True)


# BACKGROUND LOOPS

def _rollup_loop():
    """Runs every _rollup_interval_minutes. Triggers partial rollup each time."""
    interval_seconds = _rollup_interval_minutes * 60

    # BEFORE THE FIRST SLEEP, 2026-09-15.
    #
    # This loop sleeps an hour before it does anything, and _build_perf only
    # ever reaches six hours back. Between the two, a run that was killed
    # rather than closed cleanly left every hour it observed without buckets,
    # and once six hours had passed nothing would ever go back for them. The
    # packets were still on disk the whole time. That is why the Performance
    # page had six blocks after two days and never coloured any of them.
    #
    # It runs here rather than in main.py so boot is not held up by it, and it
    # is cheap on the second run because hours that already have rows are
    # skipped.
    _backfill_perf()

    while not _stop_event.is_set():
        # Sleep in small increments so shutdown is responsive
        for _ in range(interval_seconds * 2):
            if _stop_event.is_set():
                return
            time.sleep(0.5)

        logger.info("Hourly rollup triggered.")
        try:
            result = run_rollup(
                session_id=_session_id,
                trigger_reason="hourly",
                scope="partial",
            )
            logger.info(f"Hourly rollup complete: {result}")
        except Exception as e:
            # Kept for status(), because a loop that is alive and failing
            # every hour looks exactly like a healthy one from outside.
            global _last_rollup_error
            _last_rollup_error = f"{type(e).__name__}: {e}"
            logger.error(f"Rollup error: {e}", exc_info=True)

        _check_predictions("hourly")
        _build_perf("hourly")
        _expire_questions()
        _expire_actions()


def _check_predictions(trigger: str):
    """Score any prediction whose deadline has passed.

    IN ITS OWN try, deliberately not inside the rollup's. A prediction is a
    scorecard and the rollup is the baseline merge. A failure in the scorecard
    must not cost a baseline merge, and a failure in the merge must not leave
    predictions permanently unscored. They ride the same thread only because
    they want the same cadence, and that is the only thing they share.

    The import is local so a broken predictions module cannot stop the rollup
    engine from loading at boot.
    """
    try:
        from core import predictions
        result = predictions.check_due()
        if result["checked"]:
            logger.info(
                "Predictions checked (%s): %d hit, %d miss, %d could not be "
                "checked.", trigger, result["hit"], result["miss"],
                result["unverifiable"])
    except Exception as e:
        logger.error(f"Prediction check error: {e}", exc_info=True)


def _build_perf(trigger: str):
    """Fill the performance buckets for the hours that have finished.

    Six hours back rather than one, so a session that was closed for an
    afternoon fills in what it missed rather than leaving a hole. Rebuilding
    an hour that already exists replaces the row, it does not duplicate it, so
    the overlap costs nothing.
    """
    try:
        from core import perf
        result = perf.build_recent(hours=6)
        if result.get("rows"):
            logger.info("Performance buckets built (%s): %d rows over %d hours.",
                        trigger, result["rows"], result["built"])
    except Exception as e:
        logger.error(f"Performance rollup error: {e}", exc_info=True)


def _backfill_perf():
    """Fill any completed hour in the last two days that has no buckets.

    Separate from _build_perf because they answer different questions.
    _build_perf keeps up with the clock. This one goes back for what previous
    runs never got around to, which is only ever needed at startup.

    In its own try for the usual reason: a failure here must not stop the
    rollup loop from starting.
    """
    try:
        from core import perf
        result = perf.backfill(hours=48)
        if result.get("built"):
            logger.info(
                "Performance backfill: %d hour(s) built, %d rows, %d already "
                "had buckets, %ss.", result["built"], result["rows"],
                result.get("skipped", 0), result.get("seconds", "?"))
    except Exception as e:
        logger.error(f"Performance backfill error: {e}", exc_info=True)


def _expire_questions():
    """Retire questions the owner was shown and did not answer.

    The clock runs from when the owner was SHOWN it, never from when it was filed.
    See core/questions.expire_stale.
    """
    try:
        from core import questions
        result = questions.expire_stale()
        if result.get("expired"):
            logger.info("%d question(s) retired unanswered after %d days.",
                        result["expired"], result["after_days"])
    except Exception as e:
        logger.error(f"Question expiry error: {e}", exc_info=True)


def _expire_actions():
    """Retire action requests nobody answered.

    THE CLOCK, WIRED, 2026-09-18. core/actions.expire_stale() existed, was
    tested, and was reachable only by a manual POST to /api/actions/expire —
    so the promise config.json makes ("a request nobody answers retires, as
    NOT APPROVED AND NOT DENIED") was never kept on its own. A pending row
    would have sat there forever while the dashboard showed it as still
    waiting on the operator. Found by reading what CALLS the function rather
    than what the function does.

    It only ever moves a request towards DID NOT RUN. There is deliberately no
    counterpart that moves silence towards approval: an approval carries a
    person's timestamp or it is not an approval.
    """
    try:
        from core import actions
        result = actions.expire_stale()
        if result.get("expired"):
            logger.info(
                "%d action request(s) retired unanswered after %d days. None "
                "of them ran and none of them were denied.",
                result["expired"], result["after_days"])
    except Exception as e:
        logger.error(f"Action request expiry error: {e}", exc_info=True)


def _silence_loop():
    """
    Runs every 2 minutes.
    Finds deviations with elapsed silence timeout and resolves them as 'normal'.
    This is how user silence becomes implicit approval.
    """
    check_interval = 120  # 2 minutes

    while not _stop_event.is_set():
        for _ in range(check_interval * 2):
            if _stop_event.is_set():
                return
            time.sleep(0.5)

        try:
            _process_silent_deviations()
        except Exception as e:
            logger.error(f"Silence timer error: {e}", exc_info=True)


def _severity_rank(severity: str) -> int:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get((severity or "low").lower(), 1)


def _process_silent_deviations():
    """
    Resolve deviations that timed out with no user response.

    DESIGN CHANGE (2026-08). Previously: silence resolved a deviation as
    'normal', flagged the baseline normal, and at 6 counts set
    alert_suppressed permanently. For an unattended monitor, which is the
    entire point of this tool, every detection converged toward suppressed,
    and the noisier a detector was, the faster it silenced itself.

    Now:
      * Silence resolves to 'unreviewed', never 'normal'. Nobody looked at
        it; that is not the same as approving it.
      * Severities at or above the silence floor (default 'high') are never
        baselined at all. They land in the review queue and keep alerting.
      * Confidence from silence alone is capped (default 'medium').
      * Silence NEVER sets alert_suppressed. Suppression now requires an
        affirmative signal, an explicit user decision, or a model call
        that passes the permission gate.
    """
    silent = me.get_silent_deviations()
    if not silent:
        return

    floor_pref  = (me.get_preference("silence_severity_floor", "high") or "high").lower()
    floor_rank  = _severity_rank(floor_pref)
    cap_pref    = (me.get_preference("silence_confidence_cap", "medium") or "medium").lower()
    if cap_pref not in me.VALID_CONFIDENCE:
        cap_pref = "medium"

    thresholds  = _confidence_thresholds()
    med_thresh  = thresholds["medium"]
    high_thresh = thresholds["high"]

    protected = 0
    baselined = 0

    logger.info(f"Silence timer: processing {len(silent)} unresponded deviations.")

    for dev in silent:
        severity = dev.get("severity") or "low"

        # Every silent deviation is closed as 'unreviewed' so it stops
        # re-firing, but the label records the truth: nobody answered.
        me.resolve_deviation(
            deviation_id=dev["id"],
            resolved_as="unreviewed",
            user_response=None,
            # Nobody answered, and the row now says so in its own column
            # rather than only by the absence of a response. TODO 98.
            resolved_by="silence_timer",
        )

        # SEVERITY FLOOR
        # A critical finding nobody answered is an unanswered critical
        # finding. Do not touch the baseline; leave it in the review queue.
        if _severity_rank(severity) >= floor_rank:
            protected += 1
            logger.warning(
                f"Silence timer: {severity.upper()} deviation on "
                f"{dev['entity_type']}:{dev['entity_value']} "
                f"({dev['behavior_key']}) went unanswered. "
                f"NOT baselined, queued for review."
            )
            continue

        existing = me.query_behavioral_baseline(
            entity_type=dev["entity_type"],
            entity_value=dev["entity_value"],
            behavior_key=dev["behavior_key"],
        )
        if not existing:
            continue

        # SESSION-BASED COUNTING
        # Count distinct sessions, not observations. One noisy poll loop can
        # no longer manufacture confidence inside a single session.
        session_count = me.record_baseline_session(
            entity_type=dev["entity_type"],
            entity_value=dev["entity_value"],
            behavior_key=dev["behavior_key"],
            session_id=_session_id,
        )

        if session_count >= high_thresh:
            new_confidence = "high"
        elif session_count >= med_thresh:
            new_confidence = "medium"
        else:
            new_confidence = "low"

        # CONFIDENCE CAP
        # Silence can carry a baseline to 'medium' at most. 'high', the
        # level that used to trigger suppression, needs a real signal.
        if _confidence_rank(new_confidence) > _confidence_rank(cap_pref):
            new_confidence = cap_pref

        me.update_behavioral_baseline(
            entity_type=dev["entity_type"],
            entity_value=dev["entity_value"],
            behavior_key=dev["behavior_key"],
            session_id=_session_id,
            sample_count=session_count,
            confidence=new_confidence,
            # Not flagged normal: unreviewed is not approved.
            flagged_as_normal=False,
            # Never suppressed by silence. This is the core of the fix.
            alert_suppressed=False,
            model_notes=(
                f"Unreviewed after silence x{session_count} session(s). "
                f"Last silence: {datetime.now(timezone.utc).isoformat()}. "
                f"Confidence: {new_confidence} (silence-capped at {cap_pref}). "
                f"Severity was {severity}. Not approved, nobody responded."
            ),
        )
        baselined += 1

    logger.info(
        f"Silence timer done. {baselined} baselines nudged, "
        f"{protected} high-severity deviations protected and queued for review."
    )


def _confidence_rank(confidence: str) -> int:
    return {"low": 0, "medium": 1, "high": 2}.get((confidence or "low").lower(), 0)


# MAIN ROLLUP FUNCTION
# Called by background thread (hourly), shutdown handler, and model via trigger_rollup tool

def run_rollup(session_id: str, trigger_reason: str = "manual", scope: str = "full") -> dict:
    """See _run_rollup. The thresholds read once for the pass are always
    released afterwards, error or not."""
    try:
        return _run_rollup(session_id, trigger_reason, scope)
    finally:
        me._thresholds_scope = None


def _run_rollup(session_id: str, trigger_reason: str = "manual", scope: str = "full") -> dict:
    """
    Merge behavioral_session into behavioral_baseline.
    scope='full'    , all entities in session
    scope='partial', same, but logs as partial for audit trail
    Returns summary dict.
    """
    start_time = time.time()

    # The rules get recorded before they are applied. This is the only place
    # that runs regularly while the app is up, so it is where an edit made to
    # user_preferences DURING a session becomes visible. No-ops when nothing
    # changed, so it costs one SELECT per rollup.
    try:
        from core import integrity
        integrity.snapshot_config(reason=f"rollup:{trigger_reason}")
    except Exception as e:
        logger.error(f"Could not snapshot config at rollup: {e}")

    # Pull all session observations for this session.
    #
    # query_behavioral_session returns a WRAPPER DICT, not a list:
    #   {"observations": [...], "count": n, "superseded_hidden": n}
    #
    # It changed shape on 2026-08-19 when supersede support landed, so that a
    # withdrawn observation could be hidden while the FACT of a withdrawal
    # stayed visible. scripts/withdraw_observation.py was written against the
    # new shape. This function was not, and nothing caught it, because the two
    # failure modes were both silent:
    #
    #   `if not observations` never fired, since a dict with a count of zero is
    #   still truthy, so the honest "nothing to process" path was dead.
    #
    #   `for obs in observations` then iterated the dict's KEYS, making obs the
    #   string "observations", and obs["entity_type"] raised
    #   TypeError: string indices must be integers.
    #
    # Both background callers wrap run_rollup in try/except and only log, so
    # EVERY hourly rollup and every shutdown rollup failed to a log line
    # nobody read. Session observations were still written; they were simply
    # never merged into behavioral_baseline. The conscience stopped
    # accumulating and the tool went on looking like it worked.
    #
    # Unwrapped defensively rather than by assuming the current shape, because
    # this is the second time the caller and the callee have disagreed about
    # it and a rollup that quietly does nothing is worse than one that errors.
    # 2026-09-13. THIS USED TO READ A CAPPED LIST AND IT WAS A REAL BUG.
    #
    # It called query_behavioral_session(limit=500), and _validate_limit
    # clamps every limit to MAX_QUERY_LIMIT, which is 500. So on any session
    # that produced more than 500 observations, the baseline, the thing this
    # app calls normal and decides suppression from, was built from the newest
    # 500 and the rest were never merged at all. On the busiest sessions, the
    # ones where a baseline matters most, most of the evidence was dropped
    # before anything looked at it. The log then printed how many it had
    # processed, and that number read like the whole thing.
    #
    # all_session_observations pages and has no cap. It is deliberately NOT
    # the model facing function: that one is capped because there is a context
    # window on the other end of it. This is Python reading its own table to
    # compute an aggregate, and there is no reason for that to be limited.
    # The app's own measurements for this window, so baselines grow every
    # session and not only when the model writes something down.
    try:
        from core import auto_observe
        written = auto_observe.observe(session_id)
        logger.info(f"Rollup [{trigger_reason}]: {written['written']} measured "
                    f"observation(s) from the sensors.")
    except Exception as e:                              # noqa: BLE001
        logger.warning(f"Rollup [{trigger_reason}]: auto observation failed: {e}")

    observations = me.all_session_observations(session_id)

    # Said out loud, because the old number was the thing that hid this.
    logger.info(
        f"Rollup [{trigger_reason}]: read {len(observations)} session "
        f"observation(s), all of them, no cap.")

    if not observations:
        logger.info(f"Rollup [{trigger_reason}]: no session observations to process.")
        duration_ms = int((time.time() - start_time) * 1000)
        # A merge that ran and found nothing still ran, and status() must
        # not report it as a merge that never happened.
        _stamp_rollup()
        me.log_rollup(
            session_id=session_id,
            trigger_reason=trigger_reason,
            entities_processed=0,
            baselines_updated=0,
            baselines_created=0,
            duration_ms=duration_ms,
            notes="No observations to process.",
        )
        return {
            "trigger_reason": trigger_reason,
            "entities_processed": 0,
            "baselines_updated": 0,
            "baselines_created": 0,
            "duration_ms": duration_ms,
        }

    # Group observations by (entity_type, entity_value, behavior_key)
    # One reading of the thresholds for the whole pass.
    me._thresholds_scope = _confidence_thresholds()

    groups: dict[tuple, list] = {}
    for obs in observations:
        key = (obs["entity_type"], obs["entity_value"], obs["behavior_key"])
        groups.setdefault(key, []).append(obs)

    baselines_updated = 0
    baselines_created = 0

    for (entity_type, entity_value, behavior_key), obs_list in groups.items():
        # The same observations as at the last rollup of this session give the
        # same baseline, so a group with nothing new is not written again.
        newest = max((o.get("id") or 0) for o in obs_list)
        mark = (session_id, entity_type, entity_value, behavior_key)
        if _rolled.get(mark) == newest:
            continue
        _rolled[mark] = newest

        # Attempt to parse numeric values for statistical summary
        numeric_values = []
        for obs in obs_list:
            try:
                numeric_values.append(float(obs["behavior_value"]))
            except (ValueError, TypeError):
                pass

        # Compute stats if we have numeric data
        stats = {}
        if numeric_values:
            n = len(numeric_values)
            mean = sum(numeric_values) / n
            variance = sum((x - mean) ** 2 for x in numeric_values) / n if n > 1 else 0
            stddev = math.sqrt(variance)
            stats = {
                "sample_count": n,
                "value_mean":   round(mean, 4),
                "value_stddev": round(stddev, 4),
                "value_min":    round(min(numeric_values), 4),
                "value_max":    round(max(numeric_values), 4),
            }

        # Pull hours active from observations (for temporal baseline)
        hours_seen = []
        for obs in obs_list:
            if obs.get("observed_at"):
                try:
                    dt = datetime.fromisoformat(obs["observed_at"])
                    hours_seen.append(dt.hour)
                except (ValueError, TypeError):
                    pass
        typical_hours = sorted(set(hours_seen)) if hours_seen else None

        # Check if baseline already exists
        existing = me.query_behavioral_baseline(
            entity_type=entity_type,
            entity_value=entity_value,
            behavior_key=behavior_key,
        )

        is_new = len(existing) == 0

        # Build model notes summarizing what was observed this session
        model_notes = (
            f"Rollup [{trigger_reason}] {datetime.now(timezone.utc).date()}. "
            f"{len(obs_list)} observations this session."
        )
        if numeric_values:
            model_notes += f" Mean={stats['value_mean']}, StdDev={stats['value_stddev']}."
        if typical_hours:
            model_notes += f" Active hours: {typical_hours}."

        # CONFIDENCE FROM DISTINCT SESSIONS
        # Was: current_count + len(obs_list), i.e. counting observations.
        # Schema documents confidence in SESSIONS (boundaries come from the
        # confidence_session_thresholds preference; high defaults to 6), and
        # with a 120s poll loop one entity easily produced 6+ observations in
        # a single session, reaching 'high', and suppression, immediately.
        #
        # record_baseline_session is idempotent per session, so N observations
        # in one session now count once, which is what the schema always meant.
        new_count = me.record_baseline_session(
            entity_type=entity_type,
            entity_value=entity_value,
            behavior_key=behavior_key,
            session_id=session_id,
        )

        thresholds  = _confidence_thresholds()
        high_thresh = thresholds["high"]
        med_thresh  = thresholds["medium"]

        if new_count >= high_thresh:
            confidence = "high"
        elif new_count >= med_thresh:
            confidence = "medium"
        else:
            confidence = "low"

        # WHOSE EVIDENCE, NOT JUST HOW MUCH. TODO 8.1F, 2026-09-04.
        #
        # The count above asks how many distinct sessions saw this. It cannot
        # tell twenty honest sessions from twenty sessions of text an attacker
        # chose, and the second one is the patient poisoning path 8.1F names.
        #
        # High confidence now needs the CLEAN sessions alone to reach the
        # medium threshold. Untrusted evidence still counts and can carry a
        # baseline from medium to high; it cannot get there by itself.
        #
        # Enforced in update_behavioral_baseline as well, which is the path
        # the model reaches directly. It is here too because a control that
        # lives only on the caller's side is a control that lapses the day
        # somebody adds a second caller.
        # Only asked when the answer can change something. The gate is two
        # queries and a preference read, and a rollup walks every entity, so
        # running it on the eighty-odd rows that are nowhere near high is
        # cost for no decision.
        if confidence == "high":
            gate = me.evidence_gate(entity_type, entity_value, behavior_key)
            if not gate["may_reach_high"]:
                logger.info(
                    f"{entity_type}:{entity_value} [{behavior_key}] held at "
                    f"medium: {gate['clean_sessions']} clean session(s), "
                    f"{gate['required']} needed for high.")
                confidence = "medium"

        # stats["sample_count"] is the per-session observation count from the
        # numeric summary above. Drop it so it cannot overwrite the
        # session-based sample_count we just computed.
        stats.pop("sample_count", None)

        # THE NOTE NO LONGER RESTATES THE NUMBERS. 2026-08-29.
        #
        # This used to append " Sessions observed: N -> confidence X." and
        # that sentence went stale the moment anything recomputed the row.
        # The v11 recount did exactly that: 192.0.2.171 ended up storing
        # sample_count 3 / confidence low while its own note still read
        # "Sessions observed: 12 -> confidence high". Both were written by
        # this project, months apart, and the wrong one is the one the model
        # reads as prose.
        #
        # sample_count and confidence are columns on this very row. Copying
        # them into free text created a second source of truth that nothing
        # kept in step, the same defect as the stale schema comments and the
        # dead suppression_requires_user knob, in a third place.
        #
        # The note now says what only a note can say: what happened in THIS
        # session. The numbers stay in the columns, where they get corrected.

        # MEASURE THE SPACING WHILE THE PACKETS ARE STILL HERE. 2026-08-29.
        #
        # `packets` is 98.7% of the database and has to be pruned. The gaps
        # between contacts exist nowhere else, so if this is not written now
        # it is not written at all, and every beacon_destinations row was
        # sitting with value_mean and value_stddev empty, which is to say the
        # columns for exactly this had been there, unused, the whole time.
        #
        # Only for beacon_destinations. Measuring intervals for
        # open_ports_inbound would be arithmetic on something nobody asked
        # about, and it costs a query per entity per rollup.
        beacon_detail = None
        if behavior_key == "beacon_destinations" and entity_type == "ip":
            try:
                from core import intervals
                with me._get_conn() as _c:
                    measured = intervals.contact_intervals(_c, entity_value)
                if measured["most_regular"]:
                    mr = measured["most_regular"]
                    stats["value_mean"]   = mr["mean_seconds"]
                    stats["value_stddev"] = mr["stddev_seconds"]
                    stats["value_min"]    = mr["min_seconds"]
                    stats["value_max"]    = mr["max_seconds"]
                    beacon_detail = json.dumps({
                        "measured_at": datetime.now(timezone.utc).isoformat(),
                        "unit": "seconds_between_contacts",
                        "most_regular": mr,
                        "destinations": measured["destinations"][:8],
                        "note": intervals.describe(mr),
                    })
            except Exception as e:
                # Never let a measurement stop a rollup.
                logger.warning(
                    f"Could not measure intervals for {entity_value}: {e}")

        me.update_behavioral_baseline(
            entity_type=entity_type,
            entity_value=entity_value,
            behavior_key=behavior_key,
            session_id=session_id,
            sample_count=new_count,
            beacon_detail=beacon_detail,
            typical_hours=typical_hours,
            confidence=confidence,
            model_notes=model_notes,
            **stats,
        )

        if is_new:
            baselines_created += 1
        else:
            baselines_updated += 1

    duration_ms = int((time.time() - start_time) * 1000)
    entities_processed = len(groups)

    _stamp_rollup()

    me.log_rollup(
        session_id=session_id,
        trigger_reason=trigger_reason,
        entities_processed=entities_processed,
        baselines_updated=baselines_updated,
        baselines_created=baselines_created,
        duration_ms=duration_ms,
    )

    logger.info(
        f"Rollup [{trigger_reason}] complete. "
        f"Entities: {entities_processed}, "
        f"Updated: {baselines_updated}, "
        f"Created: {baselines_created}, "
        f"Duration: {duration_ms}ms"
    )

    return {
        "trigger_reason":     trigger_reason,
        "entities_processed": entities_processed,
        "baselines_updated":  baselines_updated,
        "baselines_created":  baselines_created,
        "duration_ms":        duration_ms,
    }


# SHUTDOWN ROLLUP
# Called by main.py signal handler on clean exit

def shutdown_rollup():
    """
    Full rollup on clean shutdown.
    Stops background threads first, then runs final merge.
    """
    logger.info("Shutdown rollup triggered.")
    stop_background_threads()

    try:
        result = run_rollup(
            session_id=_session_id,
            trigger_reason="shutdown",
            scope="full",
        )
        logger.info(f"Shutdown rollup complete: {result}")
    except Exception as e:
        logger.error(f"Shutdown rollup failed: {e}", exc_info=True)

    # Last chance to score anything due. A short session that files a 15
    # minute prediction and is closed 20 minutes later would otherwise leave
    # it pending until the next boot, which reads as "never checked".
    _check_predictions("shutdown")
    _build_perf("shutdown")