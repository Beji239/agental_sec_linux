# core/predictions.py
# AgentalSec V2, the prediction ledger.
#
# PREREQUISITES: nothing beyond the standard library and core.memory_engine.
# Run the checker by hand with: python scripts/check_predictions.py
#
#
# WHAT THIS IS FOR
#
# Until now nothing in this project ever told the model it was wrong. It
# writes observations, it writes baselines, it writes deviations, and every
# one of those is a statement about the past that nothing ever comes back and
# grades. So the model has no way of finding out which of its instincts about
# THIS network are any good.
#
# A prediction is different. It is a claim with a deadline, and after the
# deadline the answer is sitting in tables we already have. So the model says
# what it expects, the app waits, and then the app checks.
#
#
# THE MODEL DOES NOT GRADE ITSELF
#
# Python writes the outcome. There is no tool that lets the model set one, and
# there should never be. This is the same argument as expected ports: the
# party being measured does not get to hold the ruler. The model's job is to
# make a falsifiable claim; the checker's job is to count.
#
#
# THREE OUTCOMES, AND THE THIRD ONE IS THE POINT
#
#   hit           the claim held, and we could see well enough to say so
#   miss          the claim did not hold
#   unverifiable  we could not look
#
# "No traffic from the TV between 2am and 6am" is trivially true if the
# sniffer was off at 3am. Scoring that as a hit would build a hit rate out of
# our own blind spots, and a hit rate that flatters the model is worse than
# having none, because someone would believe it.
#
# So every check asks COULD I HAVE SEEN IT before it asks WAS IT TRUE. Two
# ways the answer is no:
#
#   1. The capture was not running for enough of the window. Measured from
#      the packets actually stored, not from an uptime log, because the
#      packets are the thing the claim rests on.
#
#   2. This sensor has never once seen that device. A host-position sensor
#      cannot observe two other devices talking to each other, so silence
#      from a games console is a fact about our vantage point and not about
#      the console. SENSOR_PLACEMENT.md has the long version.
#
# Unverifiable is never counted as either of the other two, and the hit rate
# is computed over checked predictions only, with the unverifiable count
# printed right beside it so nobody reads one without the other.
#
#
# THE WALL
#
# Nothing in this file writes to behavioral_session, behavioral_baseline,
# behavioral_deviation or findings. A prediction is a guess that is allowed to
# be wrong at no cost, and that is only safe while being wrong cannot reach
# the tables that decide what gets alerted on. If a future version wants a
# good prediction record to earn the model more confidence somewhere, that is
# a separate decision and it needs its own argument.
#
#
# HONEST LIMITS, written down before anyone has to discover them
#
#   * Retention prunes packets. A prediction whose window has been pruned
#     before the check runs reads as zero traffic. That comes back as
#     unverifiable rather than a hit, because zero stored packets across the
#     whole window is exactly what an off sniffer looks like, and the two are
#     indistinguishable from here. Keep horizons well inside the retention
#     window.
#
#   * Coverage is measured from first to last packet in each capture session
#     inside the window. A session that ran the whole time but genuinely saw
#     nothing for an hour in the middle counts as covered for that hour. That
#     is the right call for this purpose, a quiet network is not a blind one,
#     but it does mean coverage is an upper bound.
#
#   * There is no port_open or port_closed claim kind, deliberately. A port
#     claim can only be checked if a scan happens to run inside the window,
#     and scans are user-triggered, so nearly every one of those would come
#     back unverifiable. A claim kind that almost never scores is not a claim
#     kind, it is a way of looking busy.

import logging
from datetime import datetime, timedelta, timezone

from core import memory_engine as me
from core.voice import for_you

logger = logging.getLogger(__name__)


# HOW MUCH OF THE WINDOW WE HAVE TO HAVE SEEN.
#
# Half. Below that, a quiet answer says more about the app than the network.
# It is a judgement call rather than a discovered constant, which is why it is
# a preference and can be argued with.
DEFAULT_MIN_COVERAGE = 0.5

# A horizon shorter than this cannot be judged, the checker itself runs on the
# rollup cycle. Longer than the cap and the window outlives the packets.
MIN_HORIZON_MINUTES = 15
MAX_HORIZON_HOURS = 24 * 14

# How many predictions the model may file in one day. Per DAY on purpose and
# not per hour: this app runs when somebody starts it, so an hourly quota
# would hand a short session a quota of one and an overnight run a quota of
# twelve, which rewards leaving the laptop on rather than thinking well.
DEFAULT_DAILY_CAP = 12

CLAIM_KINDS = (
    "no_traffic",
    "traffic_above",
    "traffic_below",
    "no_finding",
    "finding_expected",
    "device_present",
    "device_absent",
)

# Which claim kinds need a number, and which need a severity.
NEEDS_THRESHOLD = ("traffic_above", "traffic_below")
NEEDS_IP = ("no_traffic", "traffic_above", "traffic_below",
            "device_present", "device_absent")

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _pref_float(key: str, default: float) -> float:
    try:
        return float(me.get_preference(key, str(default)))
    except (TypeError, ValueError):
        return default


def _pref_int(key: str, default: int) -> int:
    try:
        return int(float(me.get_preference(key, str(default))))
    except (TypeError, ValueError):
        return default


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _sql_ts(dt: datetime) -> str:
    """The shape SQLite's CURRENT_TIMESTAMP writes, so string comparison works.

    Every timestamp column in this database is naive UTC in this exact format.
    Storing an ISO string with a 'T' and a 'Z' here would sort wrongly against
    packets.captured_at, which is the bug _comparable_ts in memory_engine
    exists to document.
    """
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _parse_ts(value) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("T", " ")
    if text.endswith("Z"):
        text = text[:-1]
    text = text[:19]
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc)
    except ValueError:
        return None


# COVERAGE

def capture_coverage(conn, start: str, end: str) -> tuple[float, str]:
    """
    How much of this window did the packet capture actually cover?

    Measured from the stored packets themselves, grouped by capture session,
    because those rows ARE the evidence any traffic claim rests on. An uptime
    log would answer a different question: it would say the app was running,
    which is not the same as the sniffer having stored anything.

    Returns (fraction 0.0 to 1.0, a sentence for a person).
    """
    start_dt, end_dt = _parse_ts(start), _parse_ts(end)
    if not start_dt or not end_dt or end_dt <= start_dt:
        return 0.0, "the window is not a valid time range"

    window_seconds = (end_dt - start_dt).total_seconds()

    rows = conn.execute("""
        SELECT session_id, MIN(captured_at) AS first_seen,
                           MAX(captured_at) AS last_seen
        FROM packets
        WHERE captured_at >= ? AND captured_at <= ?
        GROUP BY session_id
    """, (start, end)).fetchall()

    if not rows:
        return 0.0, ("no packets are stored anywhere in that window, so the "
                     "capture was either off or the rows have since been "
                     "pruned by retention")

    covered = 0.0
    for row in rows:
        first, last = _parse_ts(row["first_seen"]), _parse_ts(row["last_seen"])
        if not first or not last:
            continue
        # Clip to the window. A session that started before it or ran past it
        # only counts for the part that overlaps.
        first = max(first, start_dt)
        last = min(last, end_dt)
        if last > first:
            covered += (last - first).total_seconds()

    fraction = min(covered / window_seconds, 1.0) if window_seconds else 0.0
    pct = round(fraction * 100)
    note = (f"the capture covered about {pct}% of that window, "
            f"across {len(rows)} capture session"
            f"{'s' if len(rows) != 1 else ''}")
    return fraction, note


def _ever_seen(conn, ip: str) -> bool:
    """Has this address EVER produced a packet this sensor could store?

    If it never has, silence from it is a statement about our vantage point.
    Nothing about the device can be concluded from it in either direction.
    """
    row = conn.execute(
        "SELECT 1 FROM packets WHERE src_ip = ? OR dst_ip = ? LIMIT 1",
        (ip, ip)).fetchone()
    return row is not None


# WRITING A PREDICTION

def write_prediction(session_id: str, claim_kind: str, entity_type: str,
                     entity_value: str, statement: str,
                     horizon_hours: float = None,
                     horizon_minutes: float = None,
                     threshold: float = None, detail: str = None,
                     reasoning: str = None) -> dict:
    """
    File a claim about what is going to happen, with a deadline on it.

    Refuses anything it could not later check. That refusal is the feature: a
    prediction nothing can grade is not a prediction, and the quiet failure
    mode here would be a ledger full of untestable sentences that never get an
    outcome and make the pending count look like work in progress.
    """
    claim_kind = (claim_kind or "").strip().lower()
    if claim_kind not in CLAIM_KINDS:
        return {"success": False,
                "error": (f"claim_kind must be one of {', '.join(CLAIM_KINDS)}. "
                          f"Got {claim_kind!r}. These are the only claims this "
                          f"app can check for you afterwards.")}

    entity_type = (entity_type or "").strip().lower()
    entity_value = (entity_value or "").strip()
    if not entity_value:
        return {"success": False, "error": "entity_value is required."}

    if claim_kind in NEEDS_IP and entity_type != "ip":
        return {"success": False,
                "error": (f"{claim_kind} is checked against packets and "
                          f"presence sweeps, both of which are keyed by "
                          f"address, so entity_type must be 'ip'. "
                          f"Got {entity_type!r}.")}
    if entity_type not in ("ip", "process", "port", "user"):
        return {"success": False,
                "error": "entity_type must be one of ip, process, port, user."}

    statement = (statement or "").strip()
    if not statement:
        return {"success": False,
                "error": ("statement is required. Say the claim in one plain "
                          "sentence, the way you would say it to the operator. "
                          "The structured fields are what gets checked; this "
                          "is what makes the row worth reading afterwards.")}

    if claim_kind in NEEDS_THRESHOLD:
        if threshold is None:
            return {"success": False,
                    "error": (f"{claim_kind} needs a threshold, the packet "
                              f"count you are predicting against.")}
        try:
            threshold = float(threshold)
        except (TypeError, ValueError):
            return {"success": False, "error": "threshold must be a number."}
        if threshold < 0:
            return {"success": False, "error": "threshold cannot be negative."}
    else:
        threshold = None

    if claim_kind in ("no_finding", "finding_expected"):
        detail = (detail or "low").strip().lower()
        if detail not in SEVERITY_RANK:
            return {"success": False,
                    "error": (f"detail must be a severity for {claim_kind}: "
                              f"{', '.join(SEVERITY_RANK)}. It is the floor, "
                              f"so 'medium' means medium and above.")}

    # HORIZON
    if horizon_minutes is None and horizon_hours is None:
        return {"success": False,
                "error": ("say how far ahead this claim reaches, with "
                          "horizon_hours or horizon_minutes. A claim with no "
                          "deadline can never be checked.")}
    minutes = float(horizon_minutes) if horizon_minutes is not None \
        else float(horizon_hours) * 60.0
    if minutes < MIN_HORIZON_MINUTES:
        return {"success": False,
                "error": (f"the shortest horizon is {MIN_HORIZON_MINUTES} "
                          f"minutes. The checker runs on the rollup cycle, so "
                          f"anything shorter would be judged before the window "
                          f"it describes has finished.")}
    if minutes > MAX_HORIZON_HOURS * 60:
        return {"success": False,
                "error": (f"the longest horizon is {MAX_HORIZON_HOURS} hours. "
                          f"Past that, retention will have pruned the packets "
                          f"the claim rests on and the answer comes back "
                          f"unverifiable no matter what the network did.")}

    now = _now_utc()
    made_at = _sql_ts(now)
    ends_at = _sql_ts(now + timedelta(minutes=minutes))

    cap = _pref_int("prediction_daily_cap", DEFAULT_DAILY_CAP)
    day_start = _sql_ts(now - timedelta(hours=24))

    with me._get_conn() as conn:
        used = conn.execute(
            "SELECT COUNT(*) FROM prediction WHERE made_at >= ?",
            (day_start,)).fetchone()[0]
        if used >= cap:
            return {"success": False,
                    "error": (f"you have filed {used} predictions in the last "
                              f"24 hours and the cap is {cap}. The cap is "
                              f"there so you have to choose which claims are "
                              f"worth making. Wait, or make the next one "
                              f"count."),
                    "daily_cap": cap, "used_today": used}

        # The same open claim filed twice would be graded twice.
        dup = conn.execute("""
            SELECT id FROM prediction
            WHERE outcome IS NULL AND claim_kind = ? AND entity_type = ?
              AND entity_value = ? AND COALESCE(detail, '') = ?
              AND COALESCE(threshold, -1) = ?
            LIMIT 1
        """, (claim_kind, entity_type, entity_value, detail or "",
              threshold if threshold is not None else -1)).fetchone()
        if dup:
            return {"success": False,
                    "error": (f"prediction {dup[0]} already makes this exact "
                              f"claim and is still open. It will be checked "
                              f"when its deadline passes; filing it again "
                              f"would only count the same guess twice."),
                    "existing_prediction_id": dup[0]}

        cursor = conn.execute("""
            INSERT INTO prediction
                (session_id, made_at, horizon_ends_at, claim_kind,
                 entity_type, entity_value, threshold, detail,
                 statement, reasoning)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (session_id, made_at, ends_at, claim_kind, entity_type,
              entity_value, threshold, detail, statement, reasoning))
        new_id = cursor.lastrowid

    # NOT JOURNALLED, AND THAT IS A DECISION. 2026-09-14.
    #
    # The first version of this file called me._journal here and in the
    # checker. core/integrity.py refused both operations, which is the
    # allow-list doing exactly its job, and the right answer was to stop
    # asking rather than to widen the list.
    #
    # The journal's own test is writes that CHANGE WHAT THIS TOOL WILL TELL
    # YOU LATER: findings saved and dismissed, baselines suppressed, devices
    # vouched for. Filing a prediction changes nothing about what the app says
    # about this network, and neither does scoring one. Adding the operations
    # would be the accretion record()'s docstring warns about, and a journal
    # warning that fires on every ordinary prediction teaches people to ignore
    # journal warnings.
    #
    # If the ledger ever becomes load-bearing, if a good record earns the
    # model confidence somewhere that affects alerting, that is the moment
    # this decision gets revisited, and it would need its own argument.
    return {
        "success": True,
        "prediction_id": new_id,
        "claim_kind": claim_kind,
        "horizon_ends_at": ends_at,
        "used_today": used + 1,
        "daily_cap": cap,
        "note": ("Filed. Nothing checks this until the horizon passes, and "
                 "you do not get to grade it. The outcome will be hit, miss, "
                 "or unverifiable if the capture could not see enough of the "
                 "window to say."),
    }


# CHECKING

def _check_traffic(conn, row, start, end, coverage, coverage_note):
    ip = row["entity_value"]

    if not _ever_seen(conn, ip):
        return ("unverifiable",
                (f"{ip} has never produced a single packet this sensor could "
                 f"store, at any time. Silence from it is a fact about where "
                 f"this sensor sits, not about the device. See "
                 f"SENSOR_PLACEMENT.md."),
                None)

    count = conn.execute("""
        SELECT COUNT(*) FROM packets
        WHERE captured_at >= ? AND captured_at <= ?
          AND (src_ip = ? OR dst_ip = ?)
    """, (start, end, ip, ip)).fetchone()[0]

    kind = row["claim_kind"]
    if kind == "no_traffic":
        held = count == 0
        reason = (f"{count} packets involving {ip} in that window, "
                  f"{coverage_note}")
    elif kind == "traffic_above":
        held = count > (row["threshold"] or 0)
        reason = (f"{count} packets, predicted more than "
                  f"{row['threshold']:.0f}, {coverage_note}")
    else:  # traffic_below
        held = count < (row["threshold"] or 0)
        reason = (f"{count} packets, predicted fewer than "
                  f"{row['threshold']:.0f}, {coverage_note}")

    return ("hit" if held else "miss", reason, float(count))


def _check_findings(conn, row, start, end, coverage_note):
    floor = SEVERITY_RANK.get((row["detail"] or "low").lower(), 1)
    at_or_above = [s for s, rank in SEVERITY_RANK.items() if rank >= floor]
    placeholders = ",".join("?" for _ in at_or_above)

    # DISMISSED FINDINGS STILL COUNT. The claim is about whether this app
    # RAISED something, and it did. Dismissing it afterwards is a judgement
    # about the finding, made later, by somebody else. Filtering them out
    # here would let a prediction be scored right by an action taken after
    # the prediction was made.
    count = conn.execute(f"""
        SELECT COUNT(*) FROM findings
        WHERE found_at >= ? AND found_at <= ?
          AND entity_type = ? AND entity_value = ?
          AND severity IN ({placeholders})
    """, (start, end, row["entity_type"], row["entity_value"],
          *at_or_above)).fetchone()[0]

    kind = row["claim_kind"]
    held = (count == 0) if kind == "no_finding" else (count > 0)
    reason = (f"{count} findings at {row['detail'] or 'low'} or above for "
              f"{row['entity_value']} in that window, {coverage_note}")
    return ("hit" if held else "miss", reason, float(count))


def _decided_by_evidence(kind: str, count: float, threshold) -> bool:
    """True when what WAS seen settles the claim, however little was watched.

    Gaps can only hide events, never invent them. So a finding or packet that
    did show up is final, and only a quiet answer needs the coverage floor.
    """
    if kind in ("no_finding", "finding_expected", "no_traffic"):
        return count > 0
    if kind == "traffic_above":
        return count > (threshold or 0)
    if kind == "traffic_below":
        return count >= (threshold or 0)
    return False


def _check_with_gaps(conn, row, start, end, coverage, coverage_note,
                     min_coverage):
    """Score a low-coverage window if the evidence decides it, else unverifiable."""
    kind = row["claim_kind"]
    if kind in ("no_finding", "finding_expected"):
        outcome, reason, observed = _check_findings(
            conn, row, start, end, coverage_note)
    elif kind in ("no_traffic", "traffic_above", "traffic_below"):
        outcome, reason, observed = _check_traffic(
            conn, row, start, end, coverage, coverage_note)
    else:
        outcome, observed = "unverifiable", None

    if outcome != "unverifiable" and observed is not None \
            and _decided_by_evidence(kind, observed, row["threshold"]):
        return (outcome,
                reason + ". Decided by what was seen, so the time the app "
                         "was not running does not change it",
                observed)
    return ("unverifiable",
            (f"{coverage_note}, which is below the {min_coverage:.0%} floor. "
             f"Nothing turned up in the part that was watched, and a quiet "
             f"answer from a mostly unwatched window would be about this "
             f"tool, not about the network."),
            observed)


def recheck_unverifiable() -> dict:
    """
    Re-score rows marked unverifiable only because coverage was low.

    One-off repair for rows scored before _check_with_gaps existed. Still the
    checker writing, never the model, and rows whose reason was not coverage
    (no sweep, device never seen) are left alone.
    """
    min_coverage = _pref_float("prediction_min_coverage", DEFAULT_MIN_COVERAGE)
    changed = []
    with me._get_conn() as conn:
        rows = conn.execute("""
            SELECT * FROM prediction
            WHERE outcome = 'unverifiable'
              AND outcome_reason LIKE '%below the%floor%'
        """).fetchall()
        for row in rows:
            start, end = row["made_at"], row["horizon_ends_at"]
            coverage, coverage_note = capture_coverage(conn, start, end)
            if coverage >= min_coverage:
                continue
            outcome, reason, observed = _check_with_gaps(
                conn, row, start, end, coverage, coverage_note, min_coverage)
            if outcome == "unverifiable":
                continue
            conn.execute("""
                UPDATE prediction
                   SET outcome = ?, outcome_reason = ?, observed_value = ?,
                       coverage_note = ?, checked_at = ?
                 WHERE id = ?
            """, (outcome, reason, observed, coverage_note,
                  _sql_ts(_now_utc()), row["id"]))
            changed.append({"id": row["id"], "outcome": outcome})
    return {"rescored": len(changed), "rows": changed}


def _check_presence(conn, row, start, end):
    """Did the device answer a sweep in the window?

    A sweep that FAILED is never a denominator. presence_sweep carries that
    distinction already and this reads it rather than counting rows.
    """
    sweeps = conn.execute("""
        SELECT id FROM presence_sweep
        WHERE swept_at >= ? AND swept_at <= ? AND outcome = 'ok'
    """, (start, end)).fetchall()

    if not sweeps:
        return ("unverifiable",
                ("no presence sweep completed successfully in that window, so "
                 "nothing asked the device whether it was there. This is not "
                 "the device being quiet, it is nobody having knocked."),
                None)

    ids = [s["id"] for s in sweeps]
    placeholders = ",".join("?" for _ in ids)
    answered = conn.execute(f"""
        SELECT COUNT(*) FROM presence_observation
        WHERE ip = ? AND sweep_id IN ({placeholders})
    """, (row["entity_value"], *ids)).fetchone()[0]

    present = answered > 0
    held = present if row["claim_kind"] == "device_present" else not present
    reason = (f"{row['entity_value']} answered {answered} of {len(ids)} "
              f"successful sweeps in that window")
    return ("hit" if held else "miss", reason, float(answered))


def check_due(now: datetime = None, limit: int = 200) -> dict:
    """
    Score every prediction whose horizon has passed and that has no outcome.

    Called on the rollup cycle and on clean shutdown. Safe to call as often as
    you like: a prediction with an outcome is never looked at again, and the
    query only selects rows where outcome IS NULL.
    """
    now = now or _now_utc()
    now_sql = _sql_ts(now)
    min_coverage = _pref_float("prediction_min_coverage", DEFAULT_MIN_COVERAGE)

    scored = {"hit": 0, "miss": 0, "unverifiable": 0}
    results = []

    with me._get_conn() as conn:
        due = conn.execute("""
            SELECT * FROM prediction
            WHERE outcome IS NULL AND horizon_ends_at <= ?
            ORDER BY horizon_ends_at ASC
            LIMIT ?
        """, (now_sql, limit)).fetchall()

        for row in due:
            start, end = row["made_at"], row["horizon_ends_at"]
            coverage, coverage_note = capture_coverage(conn, start, end)
            observed = None

            if row["claim_kind"] in ("device_present", "device_absent"):
                # Presence has its own coverage question and it is a better
                # one: a sweep either ran or it did not. The packet capture
                # being down does not stop a sweep from having happened.
                outcome, reason, observed = _check_presence(conn, row, start, end)
            elif coverage < min_coverage:
                outcome, reason, observed = _check_with_gaps(
                    conn, row, start, end, coverage, coverage_note,
                    min_coverage)
            elif row["claim_kind"] in ("no_traffic", "traffic_above",
                                       "traffic_below"):
                outcome, reason, observed = _check_traffic(
                    conn, row, start, end, coverage, coverage_note)
            elif row["claim_kind"] in ("no_finding", "finding_expected"):
                outcome, reason, observed = _check_findings(
                    conn, row, start, end, coverage_note)
            else:
                # Unreachable while CLAIM_KINDS and the branches above agree.
                # Said out loud rather than defaulting to a score, because a
                # claim kind nobody wrote a checker for must not quietly
                # become a hit.
                outcome = "unverifiable"
                reason = (f"no checker exists for claim_kind "
                          f"{row['claim_kind']!r}. This is a defect in "
                          f"core/predictions.py, not a result about the "
                          f"network.")

            conn.execute("""
                UPDATE prediction
                   SET outcome = ?, outcome_reason = ?, observed_value = ?,
                       coverage_note = ?, checked_at = ?
                 WHERE id = ?
            """, (outcome, reason, observed, coverage_note, now_sql, row["id"]))

            scored[outcome] += 1
            results.append({"id": row["id"], "statement": row["statement"],
                            "outcome": outcome, "reason": reason})

    # Logged, not journalled. See the note in write_prediction for why the
    # integrity journal is the wrong home for this.
    for r in results:
        logger.info("Prediction %s scored %s: %s",
                    r["id"], r["outcome"], r["statement"])

    return {"checked": len(results), **scored, "results": results}


# READING THE SCORE

def score(recent: int = 10) -> dict:
    """
    The model's own record, which it reads before it thinks.

    THE HIT RATE IS OVER CHECKED PREDICTIONS ONLY and the unverifiable count
    sits right beside it, because those two numbers together are the honest
    statement and either one alone is misleading. A high hit rate next to a
    large unverifiable pile means most claims were about things this tool
    cannot see, which is a finding in itself and a reason to predict about
    something else.
    """
    with me._get_readonly_conn() as conn:
        if not me._table_exists_ro(conn, "prediction"):
            return {"available": False,
                    "note": ("the prediction table does not exist yet, so "
                             "nothing has been filed or checked. This is not "
                             "a score of zero, it is no data.")}

        counts = {"hit": 0, "miss": 0, "unverifiable": 0, "pending": 0}
        for row in conn.execute("""
            SELECT COALESCE(outcome, 'pending') AS state, COUNT(*) AS n
            FROM prediction GROUP BY state
        """).fetchall():
            counts[row["state"]] = row["n"]

        checked = counts["hit"] + counts["miss"]
        hit_rate = round(counts["hit"] / checked, 3) if checked else None

        by_kind = [dict(r) for r in conn.execute("""
            SELECT claim_kind,
                   SUM(outcome = 'hit')  AS hits,
                   SUM(outcome = 'miss') AS misses,
                   SUM(outcome = 'unverifiable') AS unverifiable
            FROM prediction
            WHERE outcome IS NOT NULL
            GROUP BY claim_kind
        """).fetchall()]

        why_blind = [dict(r) for r in conn.execute("""
            SELECT outcome_reason AS reason, COUNT(*) AS n
            FROM prediction
            WHERE outcome = 'unverifiable'
            GROUP BY outcome_reason
            ORDER BY n DESC
            LIMIT 5
        """).fetchall()]

        rows = me._rows_to_dicts(conn.execute("""
            SELECT id, made_at, horizon_ends_at, claim_kind, entity_value,
                   statement, reasoning, outcome, outcome_reason,
                   observed_value, checked_at
            FROM prediction
            ORDER BY id DESC LIMIT ?
        """, (max(1, min(int(recent or 10), 100)),)).fetchall())

    if checked == 0:
        reading = for_you(
            "Nothing has been checked yet, so there is no hit rate. "
            "That is no data, not a score of zero.")
    else:
        reading = for_you(
            f"{counts['hit']} right and {counts['miss']} wrong out of "
            f"{checked} that could be checked. {counts['unverifiable']} more "
            f"could not be checked at all and are counted separately, never "
            f"folded into the rate. If that number is large, most of what you "
            f"predicted was about something this tool cannot see, and the fix "
            f"is to predict about something it can."
        )

    return {
        "available": True,
        "hit": counts["hit"],
        "miss": counts["miss"],
        "unverifiable": counts["unverifiable"],
        "pending": counts["pending"],
        "checked": checked,
        "hit_rate": hit_rate,
        "by_claim_kind": by_kind,
        "why_unverifiable": why_blind,
        "recent": rows,
        "how_to_read_this": reading,
    }


def query_predictions(outcome: str = None, entity_value: str = None,
                      limit: int = 100) -> list[dict]:
    """The ledger itself, for the dashboard and for the model."""
    where, params = [], []
    if outcome:
        if outcome == "pending":
            where.append("outcome IS NULL")
        else:
            where.append("outcome = ?")
            params.append(outcome)
    if entity_value:
        where.append("entity_value = ?")
        params.append(entity_value)

    sql = "SELECT * FROM prediction"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(int(limit or 100), 500)))

    with me._get_readonly_conn() as conn:
        if not me._table_exists_ro(conn, "prediction"):
            return []
        return me._rows_to_dicts(conn.execute(sql, params).fetchall())
