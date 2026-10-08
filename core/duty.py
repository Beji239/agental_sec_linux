# core/duty.py
# AgentalSec V2, the duty loop: the agentic half.
#
# T4 of the agentic programme, 2026-09-18. See AGENTIC_PROGRAMME.md piece C and
# wiki/concepts/duty-watch-programme.
#
# WHY THIS FILE EXISTS
#
# The owner, 2026-09-17: "it seems to me that it is entirely up to the human to
# launch pretty much anything... the Agentic soul of the code has been
# missing." The verified diagnosis named four pieces. T2 built the ledger
# (what is worth looking at). T3 built the executor (so a decision outlives
# the turn that asked for it). This is the piece in between, and it is the one
# that actually spends tokens: SOMETHING HAS TO DO THE LOOKING.
#
# Before this file the model had exactly one door. agent_loop.run() is called
# from /api/chat and from nowhere else. No thread, timer or sensor ever called
# the model. If nobody typed, the analyst did not exist that hour.
#
# THE TWO TRIGGERS, ON THE OWNER'S INSTRUCTION (AGENTIC_PROGRAMME §T4)
#
# 1. EMERGENCY. An incident of a kind that cannot wait for a scheduled moment:
#    a UDP port under attack, a high volume of packets inbound AND outbound.
#    It runs as soon as the conditions are seen.
#
# 2. REGULAR MOMENTS, FOUR TIMES A DAY. Around the day's ordinary points the
#    agent wakes, picks up to TWO findings from DIFFERENT tools (all of them
#    are candidates, and it may prefer the ones that look high priority),
#    writes about them, and goes back to sleep.
#
#    THE DAEMON ENFORCES THIS, and until 2026-09-18 it did not. This paragraph
#    described what _next_regular_moment() WOULD answer and nothing asked it:
#    the loop called run_once every sixty seconds and every minute was a
#    regular moment. Measured on the live database that evening — 62 run rows
#    between 19:08 and 22:05, eight runs that called the model (2,216,938
#    tokens between them), and once the daily ceiling was crossed at 22:04 a
#    `budget` row EVERY SIXTY SECONDS, still being written when this was read.
#    See _tick_once, which is the function that now asks.
#
# THE RULES THIS FILE IS BUILT AROUND
#
# 1. DOING NOTHING IS AN OUTCOME, AND IT IS RECORDED LIKE ANY OTHER. Every
#    WAKE writes a duty_run row whatever it decided — including one a budget
#    refused and one that found nothing eligible. "It woke and found nothing
#    eligible" and "it was not running" are the same silence on the page and
#    only one of them is a statement about the network. This is T2's rule
#    pointed at the piece that spends money.
#
#    A POLL THAT IS NOT A WAKE-UP WRITES NOTHING, and the difference is
#    carried by the loop's own state (`polls`, `last_poll`, `last_skip` in
#    status()) rather than by the run table. The run table is the record of
#    every time the agent WOKE; a row per minute of looking at the clock
#    would bury a day's few wakes under 1,440 lines of nothing-due and make
#    the page unreadable. See _tick_once.
#
# 2. THE BUDGETS ARE HARD STOPS, NOT ADVICE. Three investigations an hour and a
#    daily token ceiling, both counted from rows that were actually written, and
#    when a cap is reached the tick records `budget` and examines NOTHING. It
#    does not examine a cheap one, it does not start and give up: a ceiling that
#    can be walked past is decoration.
#
# 3. THE LOOP CANNOT ACT ON ITS OWN. Every write goes through the same
#    tool_registry.execute_tool the chat path uses, and every gated tool the
#    loop calls resolves to an ActionRequest row through T3's queue. There is
#    no second path to remediation here, and there must never be one.
#
# 4. THE MODEL IS TOLD WHAT IT COULD NOT SEE, BEFORE IT CONCLUDES ANYTHING.
#    The coverage snapshot is taken when the tick starts and is carried in the
#    prompt, in the report row, and on the page. An assessment of a network and
#    an assessment of what this app could see are different claims and only one
#    of them is ever true.
#
# 5. "NO ACTION" MUST SAY WHAT IT SAW. The verdict and the `saw` column are
#    separate fields because "nothing needed doing" with nothing behind it is an
#    absence, while "I read these four things and here is why none of them
#    needed doing" is a claim a person can disagree with. The model is required
#    to fill both, in the app's own voice.
#
# WHAT THIS FILE DELIBERATELY DOES NOT DO
#
#  * It does not read the packet table itself. The emergency check is one
#    bounded SQL aggregate over `packets` with a rolling window, because the
#    first version of this test walked the whole table pairwise and took over
#    three minutes on 12k rows. That is not a detector, that is a stall inside
#    a 60-second loop.
#  * It does not write findings, and it does not write suppressions. Ever.
#    Findings come from sensors, suppressions need a person looking at evidence
#    (see core/actions.QUEUEABLE's argument), and the loop is neither.
#  * It does not touch the model's conversation history. A duty run is not a
#    chat turn and must not appear in one; the operator's chat is the
#    operator's.
#  * It does not close incidents by itself. It moves one to `triaged` when it
#    has assessed it, and it may FILE an action request, which is a proposal
#    and nothing else. Resolving is a judgement and the model does not get to
#    make it silently.

import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from core import memory_engine as me

logger = logging.getLogger(__name__)

# ONE WARNING PER DISTINCT CONFIG/LIVE DRIFT. See the note in _knob: the
# schedule gate reads its knobs on every poll, and an undamped warning here
# would write an identical line into the durable log 1,440 times a day.
_CONFIG_DRIFT_WARNED = {}


class BadDutyInput(ValueError):
    """A caller asked the duty loop for something it will not do."""


# CAPS AND THRESHOLDS
#
# Every one of these is a preference rather than a constant, so changing one is
# a recorded decision with a date on it rather than a diff in a file nobody
# re-reads. The defaults are the owner's Q6 answers (AGENTIC_PROGRAMME, owner
# decisions 2026-09-17): "3 investigations/hour, token ceiling with hard stop".

DEFAULT_TICK_SECONDS       = 60
DEFAULT_MAX_PER_HOUR       = 3
DEFAULT_WAKE_HOURS         = (9, 13, 17, 21)
DEFAULT_DAILY_TOKEN_CEILING = 2_000_000

# THE SHARE OF THE CEILING ONLY AN EMERGENCY OR AN URGENT INCIDENT MAY SPEND.
# 30% of 2M is 600,000, about three worst-case investigations. See
# budget_state.
DEFAULT_EMERGENCY_RESERVE = 0.3
URGENT_EXTRA_PER_HOUR = 2

# THE TOKEN CEILING'S UNIT, said plainly because the number is meaningless
# without it. It counts prompt_tokens + completion_tokens as the provider
# reports them, summed over the rolling 24 hours of duty_run rows. Reasoning
# tokens are billed INSIDE completion_tokens on this provider (measured, see
# agent_loop's TODO 88 note and the T4 handoff), so a ceiling that counted only
# answers would be watching the smaller half of the spend.
#
# 2,000,000 IS MEASURED, NOT A TASTE, AND THE FIRST NUMBER WAS WRONG.
#
# The first draft of this file said 250,000, chosen against a guess at what a
# run costs. The first live unattended turn against the real provider spent
# 166,797 tokens on ONE incident: seven model rounds, ~23,600 prompt tokens
# each, of which ~20,300 is the fixed overhead (the system prompt plus the
# duty turn's 36-tool manifest) that every round re-sends. At that size a
# 250,000 ceiling would have refused the SECOND investigation of the day and
# reported `budget` for the rest of the week, which would have looked exactly
# like a quiet network on the Agents page.
#
# So the ceiling is set from the measured shape:
#
#     four regular wake-ups at ~150,000-165,000  = ~660,000
#     headroom for an emergency or a manual run  = ~340,000
#     and a runaway is still stopped: one investigation cannot exceed
#     ~12 rounds x ~24,000 = ~290,000, so 2M is about seven worst-case runs
#     in a rolling day, and a loop stuck in a retry hits it in hours.
#
# The floor is a runaway stop, not a ration. If a future measurement shows a
# normal day touching this number, the number is wrong and this comment is
# where that argument goes.

# HOW MUCH OF A WINDOW THE CAPTURE HAS TO HAVE COVERED for a "nothing seen"
# answer to be allowed. The same number and the same argument as
# predictions.DEFAULT_MIN_COVERAGE: below this, a quiet answer says more about
# the app than about the network, and the tick says so instead of concluding.
DEFAULT_MIN_COVERAGE = 0.5


def _pref_int(key: str, default: int) -> int:
    try:
        return int(float(me.get_preference(key, str(default))))
    except (TypeError, ValueError):
        return default


def _pref_str(key: str, default: str) -> str:
    try:
        value = me.get_preference(key, default)
    except Exception:
        return default
    return str(value) if value else default


def _knob(name: str, default):
    """
    One setting, read from the LIVE value (the preference table) and seeded
    from config.json, with any disagreement between the two said out loud.

    THE SHAPE THIS AVOIDS, and T4's own verification caught the first version of
    it. The incident watcher documents `severity_floor` and `daily_cap` in
    config.json and reads them from user_preferences, and nothing syncs the
    two — so the config block documents two knobs that control nothing and an
    operator lowering the floor there changes nothing and never finds out.

    The first version of THIS function had the same defect pointing the other
    way: config.json won unconditionally, so the preference table could never
    change anything and a runtime change would silently do nothing. Both
    directions are the same bug.

    So: the preference table holds the live value (it is where every other cap
    in this app leaves one — prediction_daily_cap, question_popup_daily_cap),
    config.json SEEDS it when there is no row yet, and if the two ever
    disagree the reader logs a warning naming both values and which one is in
    force. A drift that nobody can see is the problem; a drift that announces
    itself is just a fact.
    """
    block = _block()
    configured = block.get(name)
    key = f"duty_{name}"

    live = None
    try:
        live = me.get_preference(key, None)
    except Exception:
        live = None

    # NOTHING IS WRITTEN HERE, AND THAT IS THE POINT. The tempting move is to
    # seed the preference row from config.json so the two doors "agree" — and
    # it is wrong for the exact reason T2's cursor bug was wrong: core/integrity
    # hashes user_preferences as "the policy" and journals a config_observed
    # entry on any change, on the contract that such an entry ALWAYS means the
    # rules changed. A background loop writing its own knob on first read would
    # put a false "the rules changed" line in the tamper journal. The loop
    # reads; it does not write policy.
    if live in (None, ""):
        return default if configured is None else configured

    if configured is not None:
        try:
            same = (str(live) == str(configured)
                    or (isinstance(configured, (list, dict))
                        and json.loads(live) == configured))
        except (TypeError, ValueError):
            same = str(live) == str(configured)
        if not same:
            # ONCE PER DISTINCT DRIFT, not once per read. The schedule gate now
            # reads these knobs on EVERY POLL — 1,440 times a day — and this
            # warning was written when they were read a few times a session.
            # Undamped it would write 1,440 identical lines a day into the
            # durable log, which is how a real warning becomes invisible; and
            # the drift this is watching for is exactly a knob somebody set on
            # the dashboard, which they will do at most a handful of times.
            # So the pair of values is remembered and the same pair warns once.
            seen = _CONFIG_DRIFT_WARNED.get(name)
            if seen != (str(configured), str(live)):
                _CONFIG_DRIFT_WARNED[name] = (str(configured), str(live))
                logger.warning(
                    "duty_loop.%s in config.json says %r but the live value is "
                    "%r. THE LIVE VALUE WINS, and config.json is not in control "
                    "of this knob any more. Change it on the dashboard, or delete "
                    "the duty_%s row to let config.json take over again. "
                    "(This warning is repeated only when one of the two values "
                    "changes; it is read on every poll and would otherwise fill "
                    "the log on its own.)",
                    name, configured, live, name)

    return live


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sql_ts(dt: datetime) -> str:
    """The shape SQLite's CURRENT_TIMESTAMP writes, so string compares work."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _parse_ts(value):
    if not value:
        return None
    text = str(value).strip().replace("T", " ").rstrip("Z")[:19]
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc)
    except ValueError:
        return None


def _table_ready(conn, name: str) -> bool:
    return me._table_exists_ro(conn, name)


def _config() -> dict:
    try:
        from core import incident
        return incident._config()
    except Exception:
        return {}


def _block() -> dict:
    return (_config().get("duty_loop") or {})


def _enabled() -> bool:
    return bool(_block().get("enabled", True))


def _tick_seconds() -> int:
    return max(10, int(_block().get("tick_seconds", DEFAULT_TICK_SECONDS)))


def _max_per_hour() -> int:
    try:
        return max(1, int(_knob("max_investigations_per_hour",
                                DEFAULT_MAX_PER_HOUR)))
    except (TypeError, ValueError):
        return DEFAULT_MAX_PER_HOUR


def _wake_hours() -> tuple:
    """
    The local hours at which the four regular wake-ups happen.

    LOCAL, not UTC, and the difference is the point: "around the day's ordinary
    points" is a statement about the owner's day. The machine is at UTC-7, so a
    list held in UTC would drift an hour twice a year and mean nothing the owner could
    check against the owner's own clock.

    config.json holds a real JSON list here. The preference table can only hold
    a string, so it is parsed as JSON too rather than as a comma list: one
    format, one parser, and a malformed value falls back to the default with a
    warning instead of producing a schedule nobody can see.
    """
    raw = _knob("wake_hours", None)
    if raw is None:
        return DEFAULT_WAKE_HOURS
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (TypeError, ValueError):
            logger.warning("duty wake_hours is not a JSON list (%r); using "
                           "the default four hours.", raw)
            return DEFAULT_WAKE_HOURS
    try:
        hours = tuple(sorted({int(h) for h in raw}))
    except (TypeError, ValueError):
        logger.warning("duty wake_hours is not a list of hours (%r); using "
                       "the default four.", raw)
        return DEFAULT_WAKE_HOURS
    if not hours or not all(0 <= h <= 23 for h in hours):
        logger.warning("duty wake_hours has an hour outside 0-23 (%r); using "
                       "the default four.", raw)
        return DEFAULT_WAKE_HOURS
    return hours


def _daily_token_ceiling() -> int:
    try:
        return max(1000, int(_knob("daily_token_ceiling",
                                   DEFAULT_DAILY_TOKEN_CEILING)))
    except (TypeError, ValueError):
        return DEFAULT_DAILY_TOKEN_CEILING


# THE EMERGENCY CHECK — deterministic, bounded, and it names its own limits
#
# WHAT THE OWNER ASKED FOR, in the owner's words: "an incident of emergency — for
# example a UDP port under attack, a high volume of packets inbound and
# outbound — the agent has to become active, without waiting for a scheduled
# moment."
#
# WHAT THIS ACTUALLY MEASURES, and the shape of it matters more than the
# thresholds. Three conditions, all computed as ONE bounded SQL aggregate over
# a rolling window:
#
#   flood_udp        one remote source sent this many UDP packets at us in the
#                    window
#   flood_inbound    one remote source sent this many packets at us at all
#   two_way          one remote peer is BOTH sending us a lot AND receiving a
#                    lot from us, which is the "inbound AND outbound" shape the owner
#                    named and is the one that separates an attack from a
#                    backup or a download
#
# THE THRESHOLDS ARE MEASURED ON THIS MACHINE, not guessed. The busiest five
# minutes this host has ever recorded: 2,647 packets on loopback (a browser
# talking to a local service), 485 from the LAN laptop, 144 UDP between the
# host and systemd-resolved. Ordinary. So:
#
#   500 packets from ONE EXTERNAL peer in 5 minutes is above anything this
#   machine does by accident, and would be a small flood;
#   300 UDP from one external peer is the "UDP port under attack" case;
#   200 in each direction is sustained two-way bulk with a peer.
#
# THEY ARE DELIBERATELY NOT TIGHT. A trigger that fires on a busy evening
# spends the token budget on nothing, and that is not a hypothetical: it is how
# an alert channel is trained to be ignored. The cost of a missed emergency is
# paid on the next regular wake-up, which is at most six hours away.
#
# AND IT CANNOT SEE WHAT IT CANNOT SEE. With capture blind (the ordinary
# unelevated case on this host) this check returns `blind` with the reason, and
# the loop runs its regular work rather than claiming the machine is calm.
# That distinction is the whole reason the function returns a reason and not a
# boolean.

EMERGENCY_WINDOW_MINUTES = 5
EMERGENCY_INBOUND_PACKETS = 500
EMERGENCY_UDP_PACKETS     = 300
EMERGENCY_TWO_WAY_PACKETS = 200

# ONLY UNSOLICITED TRAFFIC COUNTS, as of 2026-09-29. Measured on the live
# database over 2026-09-22 to 09-28: 1,990 emergency wakes, 55 investigated,
# 54 of them benign or no_action, and every sampled trigger was a client HTTPS
# session THIS HOST opened (Cloudflare, a Google Cloud download, and
# the model provider's address, so the agent's own calls woke the agent).
# A download is two-way bulk with one peer by nature. The storm then spent the
# daily token ceiling by evening, so a real flood after that would have been
# refused as `budget`.
#
# A reply is an inbound packet to a local EPHEMERAL port from a peer and port
# this host sent to on that same port pair inside the window. Everything else
# is unsolicited: a flood at a listener, a UDP spray at random ports, a peer
# answering something we never asked. The capture records no TCP flags on this
# host (all NULL), so SYN counting is not available and the port pair is the
# discriminator. The trade: exfiltration over a connection this host opened no
# longer wakes the loop as an emergency. It is still what the beacon and
# volume detections exist for, and those reach the loop as incidents.
EPHEMERAL_PORT_FLOOR_DEFAULT = 32768

# ONE PEER, ONE EMERGENCY AN HOUR. A flood that lasts twenty minutes is one
# event, and before this every poll inside it was a fresh emergency. A peer
# comes back sooner only when its count has grown this many times over.
EMERGENCY_PEER_COOLDOWN_MINUTES = 60
EMERGENCY_REFIRE_GROWTH = 3

# THE TAG AN EMERGENCY RUN'S DETAIL STARTS WITH, so the cooldown is read from
# the run rows like every other limit in this file. A column would mean a new
# field in a sealed table; the detail is already sealed and already free text.
FLOOD_TAG = "[flood "
URGENT_TAG = "[urgent incident "


def _ephemeral_port_floor() -> int:
    """The bottom of this kernel's local port range, where client sockets live."""
    try:
        with open("/proc/sys/net/ipv4/ip_local_port_range") as f:
            return int(f.read().split()[0])
    except (OSError, ValueError, IndexError):
        return EPHEMERAL_PORT_FLOOR_DEFAULT


def _own_addresses() -> set:
    """Every address this machine holds, so 'remote peer' can be filtered."""
    import socket
    found = set()
    try:
        import psutil
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family in (socket.AF_INET, socket.AF_INET6) \
                        and getattr(a, "address", None):
                    found.add(str(a.address).split("%")[0])
    except Exception as e:
        logger.debug(f"could not read local addresses for the duty check: {e}")
    return found


def _remote_peer_clause(column: str, own: set) -> tuple:
    """
    SQL saying 'this address is not us, not loopback, not multicast'.

    Returns (clause, params). The address family is checked by EXCLUSION
    rather than parsed: SQLite has no ipaddress module and a LIKE list is exact
    for the ranges that matter here. Loopback and link-local are the two that
    would otherwise drown the count, because on this host loopback is the
    busiest interface by an order of magnitude.
    """
    params = []
    clause = (f"({column} NOT LIKE '127.%' AND {column} NOT LIKE '169.254.%' "
              f"AND {column} NOT LIKE '224.%' AND {column} NOT LIKE '239.%' "
              f"AND {column} NOT LIKE 'fe80%' AND {column} <> '::1' "
              f"AND {column} <> '255.255.255.255' AND {column} IS NOT NULL")
    if own:
        marks = ",".join("?" for _ in own)
        clause += f" AND {column} NOT IN ({marks})"
        params.extend(sorted(own))
    return clause + ")", params


def _emergency_measure(own: set, since: str, until: str = None) -> dict:
    """
    The MEASUREMENT half of the emergency check, over UNSOLICITED traffic only.

    Split out from emergency_check so it can be tested on its own, and that is
    not for convenience. The check has two halves that fail in different ways —
    "could I look at all" and "what did I see" — and a test that can only drive
    the pair cannot tell which half produced a wrong answer. verify_duty.py
    section 7 drives this one directly: a healthy measurement must return a
    NEGATIVE THAT CARRIES EVIDENCE, because a negative with nothing in it is
    indistinguishable from never having looked.

    Two bounded queries: inbound grouped per flow with a flag saying whether
    it answers a flow this host opened, and outbound counted per peer. The
    grouping is per flow, so a five-minute window is a few thousand rows at
    most and the per-peer sums are done here. `busiest_solicited_peer` is
    carried as evidence, so a negative says what traffic was set aside and
    why, instead of just being smaller. See the note above the thresholds.

    `until` bounds the window from above, so a past window can be measured.

    Raises on a bad database; the caller decides what that means.
    """
    until = until or "9999-12-31 23:59:59"
    floor = _ephemeral_port_floor()
    with me._get_readonly_conn() as conn:
        if not _table_ready(conn, "packets"):
            raise RuntimeError("the packets table does not exist")

        src_clause, src_params = _remote_peer_clause("i.src_ip", own)
        dst_clause, dst_params = _remote_peer_clause("dst_ip", own)

        # THE FLOWS THIS HOST OPENED, read once into a set. A correlated
        # lookup per inbound flow was measured at over two minutes on a busy
        # 48-hour window, and a real flood makes a five-minute window busy.
        opened = {(r[0], r[1], r[2]) for r in conn.execute("""
            SELECT DISTINCT dst_ip, dst_port, src_port FROM packets
             WHERE captured_at >= ? AND captured_at <= ?
               AND direction = 'outbound' AND dst_port IS NOT NULL
        """, (since, until))}

        flows = conn.execute(f"""
            SELECT i.src_ip AS peer, i.src_port AS rport, i.dst_port AS lport,
                   i.protocol AS protocol, COUNT(*) AS n
              FROM packets i
             WHERE i.captured_at >= ? AND i.captured_at <= ?
               AND i.direction = 'inbound' AND {src_clause}
             GROUP BY i.src_ip, i.src_port, i.dst_port, i.protocol
        """, [since, until] + src_params).fetchall()

        outbound = {r["peer"]: r["n"] for r in conn.execute(f"""
            SELECT dst_ip AS peer, COUNT(*) AS n FROM packets
             WHERE captured_at >= ? AND captured_at <= ?
               AND direction = 'outbound' AND {dst_clause}
             GROUP BY dst_ip
        """, [since, until] + dst_params).fetchall()}

    unsolicited, unsolicited_udp, solicited = {}, {}, {}
    for f in flows:
        is_reply = (f["lport"] is not None and f["lport"] >= floor
                    and (f["peer"], f["rport"], f["lport"]) in opened)
        bucket = solicited if is_reply else unsolicited
        bucket[f["peer"]] = bucket.get(f["peer"], 0) + f["n"]
        if not is_reply and f["protocol"] == "udp":
            unsolicited_udp[f["peer"]] = unsolicited_udp.get(f["peer"], 0) + f["n"]

    def _top(counts: dict):
        if not counts:
            return None
        peer = max(counts, key=counts.get)
        return {"peer": peer, "n": counts[peer]}

    two_way = None
    for peer, n_in in unsolicited.items():
        n_out = outbound.get(peer, 0)
        if two_way is None or min(n_in, n_out) > min(two_way["in_n"],
                                                     two_way["out_n"]):
            two_way = {"peer": peer, "in_n": n_in, "out_n": n_out}

    return {
        "window_minutes": EMERGENCY_WINDOW_MINUTES,
        "since": since,
        "busiest_inbound_peer": _top(unsolicited),
        "busiest_udp_peer": _top(unsolicited_udp),
        "busiest_two_way_peer": two_way,
        "busiest_solicited_peer": _top(solicited),
        "ephemeral_port_floor": floor,
        "counted": ("unsolicited inbound only: replies to a flow this host "
                    "opened are set aside and the busiest of them is named "
                    "in busiest_solicited_peer"),
        "thresholds": {
            "inbound_packets": EMERGENCY_INBOUND_PACKETS,
            "udp_packets": EMERGENCY_UDP_PACKETS,
            "two_way_packets": EMERGENCY_TWO_WAY_PACKETS,
        },
    }


def emergency_check(modules: dict = None, now: datetime = None) -> dict:
    """
    Is something happening that cannot wait for the next scheduled wake-up?

    Returns a dict that ALWAYS says which of the three answers it is:

        {"emergency": True,  "reason": "...", "evidence": {...}}
        {"emergency": False, "reason": "...", "evidence": {...}}   # looked
        {"emergency": False, "blind": True, "blind_reason": "..."} # could not look

    Never raises: this runs inside a tick and a failed check must not kill the
    loop. A check that could not run says so, and says it in the same field a
    person reads for a negative answer, because "nothing is happening" and "I
    could not tell" are different sentences everywhere else in this codebase
    and they stay different here.

    A NOTE ON THIS HOST, because it is the ordinary case rather than a corner:
    unelevated, the packet capture cannot be opened at all (AF_PACKET needs
    root or CAP_NET_RAW), so this check returns BLIND every tick. That is the
    truth — no volume can be measured from a capture that never started — and
    it is why the duty loop runs its regular report anyway instead of treating
    the silence as calm.
    """
    now = now or _now()
    since = _sql_ts(now - timedelta(minutes=EMERGENCY_WINDOW_MINUTES))

    # THE CAPTURE IS THE ONLY SENSOR THIS READS, so its health is the health of
    # the whole answer. Checked before the query rather than after, because a
    # blind capture returns an empty table and an empty table reads as calm.
    capture_trouble = None
    try:
        from core import sensor_health
        for problem in sensor_health.warnings_for("query_packets", modules or {}):
            if "packet_sniffer" in problem or "capture" in problem.lower():
                capture_trouble = problem
                break
    except Exception as e:
        capture_trouble = (f"the packet sensor's health could not be read "
                           f"({type(e).__name__}: {e}), so whether anything "
                           f"could be seen is unknown rather than fine.")

    if capture_trouble:
        return {
            "emergency": False, "blind": True,
            "blind_reason": (
                f"{capture_trouble} So no volume can be measured here, and "
                f"'nothing is happening' is NOT what this check found."),
            "window_minutes": EMERGENCY_WINDOW_MINUTES,
        }

    own = _own_addresses()
    try:
        evidence = _emergency_measure(own, since)
    except Exception as e:
        logger.error(f"Emergency check could not read packets: {e}")
        return {"emergency": False, "blind": True,
                "blind_reason": (f"the packet table could not be read "
                                 f"({type(e).__name__}: {e}), so this check "
                                 f"saw nothing. That is a statement about "
                                 f"this app, not about the network."),
                "window_minutes": EMERGENCY_WINDOW_MINUTES}

    inbound = evidence["busiest_inbound_peer"]
    udp = evidence["busiest_udp_peer"]
    two_way = evidence["busiest_two_way_peer"]

    if inbound and inbound["n"] >= EMERGENCY_INBOUND_PACKETS:
        return {"emergency": True, "evidence": evidence,
                "peer": inbound["peer"], "n": inbound["n"],
                "reason": (f"{inbound['peer']} sent {inbound['n']} unsolicited "
                           f"packets at this host in {EMERGENCY_WINDOW_MINUTES} minutes, "
                           f"against a threshold of "
                           f"{EMERGENCY_INBOUND_PACKETS}. That is a flood "
                           f"shape, not ordinary use.")}
    if udp and udp["n"] >= EMERGENCY_UDP_PACKETS:
        return {"emergency": True, "evidence": evidence,
                "peer": udp["peer"], "n": udp["n"],
                "reason": (f"{udp['peer']} sent {udp['n']} unsolicited UDP "
                           f"packets at this host in {EMERGENCY_WINDOW_MINUTES} minutes, "
                           f"against a threshold of {EMERGENCY_UDP_PACKETS}. "
                           f"That is the UDP-flood shape.")}
    if two_way and min(two_way["in_n"], two_way["out_n"]) >= \
            EMERGENCY_TWO_WAY_PACKETS:
        return {"emergency": True, "evidence": evidence,
                "peer": two_way["peer"],
                "n": min(two_way["in_n"], two_way["out_n"]),
                "reason": (f"{two_way['peer']} sent {two_way['in_n']} "
                           f"unsolicited packets while receiving {two_way['out_n']} in the same "
                           f"{EMERGENCY_WINDOW_MINUTES} minutes, both above "
                           f"{EMERGENCY_TWO_WAY_PACKETS}. Sustained two-way "
                           f"bulk with one peer is the shape worth waking "
                           f"for.")}

    return {"emergency": False, "evidence": evidence,
            "reason": (f"No peer is above any of the three thresholds in the "
                       f"last {EMERGENCY_WINDOW_MINUTES} minutes. The evidence "
                       f"block names the busiest peer of each kind, so this "
                       f"negative answer is a measurement rather than an "
                       f"absence.")}


def _flood_tag(peer: str, n: int) -> str:
    return f"{FLOOD_TAG}{peer} {int(n)}] "


def emergency_cooled_down(peer: str, n: int, now: datetime = None) -> dict:
    """
    Whether this peer's emergency was already handled inside the cooldown.

    Read from the run rows, whatever they concluded: an investigated run, a
    budget refusal and an error all count as the hour's attempt, which is the
    same rule _next_regular_moment applies to the schedule. The peer comes
    back early only when its count grew EMERGENCY_REFIRE_GROWTH times over,
    because a flood that triples is a new fact.
    """
    now = now or _now()
    cutoff = _sql_ts(now - timedelta(minutes=EMERGENCY_PEER_COOLDOWN_MINUTES))
    prefix = f"{FLOOD_TAG}{peer} "
    try:
        with me._get_readonly_conn() as conn:
            if not _table_ready(conn, "duty_run"):
                return {"cooled": False}
            row = conn.execute("""
                SELECT ran_at, detail FROM duty_run
                 WHERE ran_at >= ? AND trigger = 'emergency'
                   AND substr(detail, 1, ?) = ?
                 ORDER BY id DESC LIMIT 1
            """, (cutoff, len(prefix), prefix)).fetchone()
    except Exception as e:
        logger.warning(f"could not read the emergency cooldown: {e}")
        return {"cooled": False}
    if not row:
        return {"cooled": False}
    try:
        last_n = int(row["detail"][len(prefix):].split("]", 1)[0])
    except (ValueError, IndexError):
        last_n = 0
    if last_n and n >= last_n * EMERGENCY_REFIRE_GROWTH:
        return {"cooled": False, "grew_from": last_n}
    return {"cooled": True, "last_at": row["ran_at"], "last_n": last_n}


# THE URGENT INCIDENT, the second thing that cannot wait for a schedule
#
# Added 2026-09-29. Until then a high incident waited for the next regular
# hour, and the last one of the day is 21:00, so an SSH key added at 21:30
# was first read at 09:00. The only reason high incidents were being read
# promptly at all was the emergency storm above picking them up by accident.
#
# The watcher already coalesces findings into incidents and `triaged` marks
# one as read, so the loop-breaker is the ledger itself. The cooldown covers
# the run that failed or was refused: the incident stays `new`, and without it
# every poll would retry.

DEFAULT_URGENT_SEVERITY = "high"
URGENT_RETRY_MINUTES = 30
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _urgent_floor_rank() -> int:
    floor = str(_knob("urgent_severity_floor", DEFAULT_URGENT_SEVERITY)).lower()
    return _SEVERITY_RANK.get(floor, _SEVERITY_RANK[DEFAULT_URGENT_SEVERITY])


def urgent_incident(now: datetime = None) -> dict | None:
    """
    The worst new incident at or above the urgent floor that has not had a
    run in the retry window, or None.
    """
    now = now or _now()
    cutoff = _sql_ts(now - timedelta(minutes=URGENT_RETRY_MINUTES))
    with me._get_readonly_conn() as conn:
        if not _table_ready(conn, "incident") or \
                not _table_ready(conn, "duty_run"):
            return None
        row = conn.execute("""
            SELECT i.* FROM incident i
             WHERE i.status = 'new' AND i.severity_rank >= ?
               AND NOT EXISTS (SELECT 1 FROM duty_run r
                                WHERE r.incident_id = i.id AND r.ran_at >= ?)
             ORDER BY i.severity_rank DESC, i.last_seen_at DESC
             LIMIT 1
        """, (_urgent_floor_rank(), cutoff)).fetchone()
    return dict(row) if row else None


# THE BUDGETS
#
# COUNTED FROM THE ROWS THAT WERE ACTUALLY WRITTEN, never from a counter kept
# in memory. A counter and a log eventually disagree, and the direction they
# disagree in is always the one that lets one more run happen than should. The
# loop restarts with the app, so an in-memory count would also reset the
# ceiling every time somebody restarted it, which is the definition of a limit
# that is not one.

def spend_in_window(hours: int = 24) -> dict:
    """What the loop has spent in the last N hours, from the run rows."""
    cutoff = _sql_ts(_now() - timedelta(hours=hours))
    with me._get_readonly_conn() as conn:
        if not _table_ready(conn, "duty_run"):
            return {"available": False, "spent": 0, "runs": 0,
                    "note": ("the duty_run table does not exist yet, so "
                             "nothing has been recorded and this is not a "
                             "spend of zero.")}
        row = conn.execute("""
            SELECT COALESCE(SUM(tokens_spent), 0) AS spent,
                   COUNT(*) AS runs,
                   COALESCE(SUM(model_calls), 0) AS calls,
                   COALESCE(SUM(tokens_estimated), 0) AS estimated,
                   COALESCE(SUM(CASE WHEN outcome IN
                       ('investigated','reported') THEN 1 ELSE 0 END), 0)
                       AS worked
              FROM duty_run WHERE ran_at >= ?
        """, (cutoff,)).fetchone()
    return {"available": True, "spent": row["spent"], "runs": row["runs"],
            "model_calls": row["calls"], "ran_work": row["worked"],
            "estimated_rows": row["estimated"], "window_hours": hours}


def investigations_this_hour() -> dict:
    """How many runs that reached the model the last hour actually produced.

    AN ERROR STILL SPENT, AND THIS QUERY USED TO MISS IT. Until 2026-09-18
    this counted only `investigated` and `reported`, so a run that failed —
    hit the 12-round ceiling, for instance — counted as zero. Measured on the
    live database, two errored runs spent 357,000 and 414,000 tokens between
    them while this function read "0 of 3", so a loop that failed repeatedly
    could make unlimited model calls per hour. That is the exact shape the
    hourly cap exists to stop. A row with model_calls > 0 is a row that
    called the model, whatever it concluded, and those are what the cap
    counts.
    """
    cutoff = _sql_ts(_now() - timedelta(hours=1))
    with me._get_readonly_conn() as conn:
        if not _table_ready(conn, "duty_run"):
            return {"available": False, "count": 0}
        count = conn.execute("""
            SELECT COUNT(*) FROM duty_run
             WHERE ran_at >= ?
               AND (outcome IN ('investigated','reported')
                    OR COALESCE(model_calls, 0) > 0)
        """, (cutoff,)).fetchone()[0]
    return {"available": True, "count": count}


def _emergency_reserve_fraction() -> float:
    try:
        value = float(_knob("emergency_reserve_fraction",
                            DEFAULT_EMERGENCY_RESERVE))
    except (TypeError, ValueError):
        return DEFAULT_EMERGENCY_RESERVE
    return min(0.9, max(0.0, value))


def budget_state(urgent: bool = False) -> dict:
    """
    Whether the loop may spend anything right now, and exactly why not.

    ONE FUNCTION, SO THE ANSWER CANNOT DIFFER BETWEEN THE TICK THAT ACTS ON IT
    AND THE PAGE THAT SHOWS IT. A dashboard that computes its own version of
    this is how a limit shown as "2 left" and a loop that refuses look like two
    different systems.

    TWO CLASSES OF WORK, as of 2026-09-29. Regular and manual work stops at
    the ceiling minus the emergency reserve; an emergency or an urgent
    incident may spend into the reserve up to the full ceiling, and gets
    URGENT_EXTRA_PER_HOUR runs above the hourly cap. Before this, ordinary
    work and the emergency storm drew on one pool, and the ceiling was spent
    by evening on every day from 09-22 to 09-28, so the one thing that must
    not wait was the thing most likely to be refused.
    """
    hourly = investigations_this_hour()
    spend = spend_in_window(24)
    ceiling = _daily_token_ceiling()
    reserve = _emergency_reserve_fraction()
    limit = ceiling if urgent else int(ceiling * (1 - reserve))
    per_hour = _max_per_hour() + (URGENT_EXTRA_PER_HOUR if urgent else 0)

    reasons = []
    if hourly.get("available") and hourly["count"] >= per_hour:
        reasons.append(
            f"{hourly['count']} of {per_hour} runs that call the model "
            f"already ran this hour")
    if spend.get("available") and spend["spent"] >= limit:
        if urgent or limit == ceiling:
            reasons.append(
                f"{spend['spent']:,} of a {ceiling:,} token daily ceiling is "
                f"spent")
        else:
            reasons.append(
                f"{spend['spent']:,} tokens spent, and ordinary work stops at "
                f"{limit:,} so the last {reserve:.0%} of the {ceiling:,} "
                f"ceiling stays free for an emergency")

    return {
        "may_spend": not reasons,
        "reasons": reasons,
        "urgent": urgent,
        "investigations_last_hour": hourly.get("count"),
        "max_per_hour": per_hour,
        "tokens_last_24h": spend.get("spent"),
        "daily_token_ceiling": ceiling,
        "ordinary_token_limit": int(ceiling * (1 - reserve)),
        "emergency_reserve_fraction": reserve,
        "runs_last_24h": spend.get("runs"),
        "ran_work_last_24h": spend.get("ran_work"),
        "spend_is_estimated": bool(spend.get("estimated_rows")),
        "note": (
            "A budget refusal means NOTHING WAS EXAMINED. It is not a quiet "
            "network and it is not an all-clear; it is a limit, and the run "
            "row says `budget` so the two never look alike."
            if reasons else
            "Within budget. The counts above are read from the run rows "
            "themselves, so this number and the loop act on the same one."),
    }


# WHAT THE LOOP MAY LOOK AT
#
# READ TOOLS ONLY, and this list is not a suggestion to the model: it is the
# manifest the unattended turn is given. See agent_loop.run_unattended.
#
# WHY A NARROWER SET THAN CHAT HAS. Two reasons, both measured.
#
# 1. COST. The whole manifest is ~28,500 tokens of tool descriptions, and every
#    round of an unattended turn resends it. The 47 read tools plus the two
#    writes the loop is allowed are ~20,000, and the loop typically needs a
#    handful. An unattended loop that fires several times a day at three times
#    the overhead is a budget that means something different from what the
#    operator read.
#
# 2. THE GATE'S HONESTY. file_action_request is the ONLY way this loop can
#    reach remediation, and it files a row. Giving it kill_process directly
#    would be giving it a tool whose semantics in a context with no person are
#    "assert you have permission" -- which is precisely the thing T3's gate
#    exists to make impossible. Read tools cannot change the machine; the two
#    writes here change only the app's own records (an action request, a
#    prediction).
#
# write_prediction is included deliberately: it is the one thing in this app
# that can tell the model it was wrong, and a loop that investigates without
# ever predicting learns nothing it can be graded on. It is also on the wall --
# predictions feed nothing that decides alerting.

DUTY_TOOL_ALLOWLIST = (
    # the ledger and its neighbours
    "query_incidents", "query_incident_summary", "query_findings",
    "query_important", "query_action_requests", "query_detections",
    # case memory, added 2026-09-22 with the tool. It is here so the loop can
    # FOLLOW UP on what its prompt already put in front of it -- the brief is
    # bounded on purpose, and "there were 3 similar incidents, show me the
    # fourth" is an ordinary next question. The prompt half is what makes this
    # retrieval that HAPPENS; this entry is what makes it retrieval that can be
    # dug into.
    "query_case_memory",
    # what the sensors saw
    "query_packets", "query_events", "query_processes", "query_known_devices",
    "query_presence", "query_device_drift", "query_port_scan", "query_sensors",
    "query_sensor_health", "query_autoruns",
    # Added 2026-09-24. THE LOOP IS THE ONE READER THAT WAS ASKING THE QUESTION
    # THIS TOOL ANSWERS, EVERY DAY, AND GETTING NOTHING. Its brief carries the
    # device inventory and the presence record; the loop could see an address
    # answering fourteen sweeps running and had no tool that says whether the
    # store knows what it is. It is read-only (tool_registry._READ_ONLY_EXTRA)
    # so it costs nothing to allow, and it is exactly the retrieval that makes
    # "there are devices nobody has named" a fact the unattended turn can act
    # on rather than a number it repeats.
    "query_inventory_gaps",
    # T9, 2026-09-25. WHAT IS LISTENING ON THIS HOST AND WHAT HOLDS IT. It is
    # in the unattended allowlist because the owner asked for it there: the
    # report should come back naming the process behind a port, and this is the
    # tool that answers that. It is read-only, it originates no traffic (unlike
    # run_port_scan, kept out above and for the same reason scan_network is
    # kept out of the prompt path), and it cannot change anything about the
    # machine. What it CAN do is record a sweep of its own tables, which is the
    # same write the interval thread makes every five minutes.
    "query_port_owner",
    # Added 2026-09-24 with the conditional scan_network gate above. It is in
    # this list rather than PERMISSION_GATED because requires_permission()
    # decides per-call: a sweep of THIS host's own network is ungated, and one
    # aimed anywhere else still asks. This set is what
    # scripts/verify_duty.py's section 8 reads to prove no gated tool reaches
    # the unattended allowlist, so a name here would keep the loop from ever
    # being able to sweep at all — which is the state the audit found and the
    # reason the duty round had to exclude it by hand.
    "scan_network",

    # THE L2 QUESTION, ADDED 2026-09-23.
    #
    # query_services lists the systemd units on this machine and what each
    # would do if its process died. READING IT CHANGES NOTHING: it runs
    # `systemctl list-units` with no verb, and tools/systemd_units.list_units
    # is named in tool_registry._READ_ONLY_EXTRA so the classification is
    # stated rather than inferred from a name.
    #
    # WHY THE LOOP NEEDS IT, and this is not a convenience. The L2 work made
    # kill_process REFUSE the kill-theatre case and named stop_service as the
    # tool that works. file_action_request is the loop's only route to
    # remediation, and stop_service is filable -- so the loop can propose
    # stopping a unit. What it could NOT do was look up what the units ARE on
    # this machine: query_services was absent from this list, so an unattended
    # turn could only propose a stop against a name it had to invent, and the
    # filable-params validation would then refuse it or the executor would.
    # That is the same defect shape as the three prediction tools with no
    # DEPENDS entry, one level up: a capability the model is TOLD about in a
    # tool description it can never call.
    #
    # MEASURED BEFORE THIS FIX: 24 read-only tools were unreachable from the
    # loop, and this is the one the L2 work created a need for.
    "query_services",
    # scan_network is deliberately NOT here. It is a gated tool (it originates
    # traffic at other people's hardware on a target the model chose), and it
    # was in this list until verify_duty.py section 8 asserted "NO gated tool
    # is in the unattended allowlist" and FAILED. The assertion was right and
    # the list was wrong: an unattended turn that can port-sweep the network
    # at 3am against a target nothing is watching is the liability
    # core/actions.QUEUEABLE already refuses to queue for the same reason.
    # the router, when an agent is enrolled (T9). Read-only.
    "query_gateway",
    # this host
    "query_host_info", "query_installed_software", "query_vpn_state",
    # behaviour and its record
    "query_behavioral_baseline", "query_behavioral_session",
    "query_behavioral_deviation", "query_dismissed", "query_review_queue",
    "query_suppressed_baselines", "query_prediction_score", "query_predictions",
    # outside knowledge
    "lookup_ip", "query_enrichment", "geolocate_ip", "query_threat_map",
    "query_map_summary",
    "query_runbook", "query_performance",
    # the two writes the loop is allowed, both of which only touch our records
    "file_action_request", "write_prediction",
)


def _tool_allowlist() -> tuple:
    """
    The allowlist, resolved against the real manifest.

    A NAME THAT DOES NOT EXIST IS DROPPED AND REPORTED, never silently
    filtered, and this is not tidiness. The first version of this list carried
    two typo'd names and a filter would have turned that into a duty loop that
    quietly cannot call a tool it believes it has — indistinguishable, from
    inside the loop, from that tool having nothing to say. This project has
    already shipped one fence that covered nothing for its whole life because a
    name did not match (core/sanitize's list_quarantined entry), and the lesson
    there was that the check has to be beside the list.

    The import is lazy because core/duty is imported by main.py before the
    registry is populated in some orders, and a module-scope import of
    tool_registry from here would be the third import cycle this project has
    had to unpick.
    """
    from core import tool_registry as tr
    real = {t["name"] for t in tr.TOOL_MANIFEST}

    missing = [n for n in DUTY_TOOL_ALLOWLIST if n not in real]
    if missing:
        logger.warning(
            "The duty loop's tool allowlist names %s, which no tool in the "
            "manifest answers to. They were DROPPED, so the unattended turn "
            "will not have them and its reports may be thinner than they look. "
            "Fix DUTY_TOOL_ALLOWLIST in core/duty.py.", missing)

    if "file_action_request" not in real:
        logger.error(
            "file_action_request is not in the manifest, so the duty loop has "
            "NO WAY to propose an action. It will still investigate and "
            "report; it cannot ask for anything to be done.")

    return tuple(n for n in DUTY_TOOL_ALLOWLIST if n in real)


# PICKING WHAT TO LOOK AT

def _incident_candidates(limit: int = 3) -> list:
    """
    Incidents the loop has not assessed yet, worst first.

    `triaged` IS THE MARKER THAT IT HAS BEEN LOOKED AT, and this is where T2's
    status vocabulary earns its keep: without it the loop would re-investigate
    the same row every hour forever and the token ceiling would be spent on one
    incident. `action_pending` is excluded too, deliberately: that incident is
    already waiting on a person and re-assessing it would be the loop talking
    to itself.
    """
    with me._get_readonly_conn() as conn:
        if not _table_ready(conn, "incident"):
            return []
        rows = me._rows_to_dicts(conn.execute("""
            SELECT id, incident_key, detection_id, entity_type, entity_value,
                   severity, severity_rank, title, finding_count,
                   first_seen_at, last_seen_at, coverage_note, suppressed,
                   suppressed_reason
              FROM incident
             WHERE status = 'new'
             ORDER BY severity_rank DESC, last_seen_at DESC
             LIMIT ?
        """, (max(1, limit),)).fetchall())
    return rows


def pick_findings(n: int = 2) -> list:
    """
    Up to N findings from DIFFERENT tools, newest and worst first.

    THE OWNER'S INSTRUCTION: "Each report is about 2 findings — whether the
    findings came from the alerts or from processes... It picks 2 reports from
    different tools — all of them are candidates. It can look for the ones that
    seem to have high priority."

    "FROM DIFFERENT TOOLS" IS ENFORCED HERE, not requested of the model. A
    report about two rows from the same sensor is one fact repeated, and the
    whole point of picking two is to put two vantage points in front of a
    reader. One finding per `source`, in priority order, so a machine whose
    loudest sensor is the process monitor does not produce two process rows
    while a packet finding goes unread.

    Priority is the register's severity first and recency second. `dismissed`
    rows are excluded: a reader who dismissed something has already said they
    do not want to hear about it, and re-raising it in a report would be the
    nag §53.3 exists to prevent.
    """
    n = max(1, min(int(n or 2), 2))       # the owner fixed this at two
    with me._get_readonly_conn() as conn:
        if not _table_ready(conn, "findings"):
            return []
        rows = me._rows_to_dicts(conn.execute("""
            SELECT id, found_at, source, severity, entity_type, entity_value,
                   title, description, detection_id, sensor_id
              FROM findings
             WHERE COALESCE(dismissed, 0) = 0
               AND detection_id IS NOT NULL
               AND found_at >= datetime('now', '-24 hours')
             ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                                    WHEN 'medium' THEN 2 WHEN 'low' THEN 1
                                    ELSE 0 END DESC,
                      found_at DESC
             LIMIT 60
        """).fetchall())

    picked, used_sources = [], set()
    for row in rows:
        source = row.get("source") or "unknown"
        if source in used_sources:
            continue
        picked.append(row)
        used_sources.add(source)
        if len(picked) >= n:
            break
    return picked


# COVERAGE

def _coverage(modules: dict) -> dict:
    """The snapshot incident.py already owns. Never a second implementation."""
    try:
        from core import incident
        return incident.coverage_snapshot(modules)
    except Exception as e:
        return {"taken_at": _sql_ts(_now()), "complete": None,
                "note": (f"The coverage snapshot could not be taken "
                         f"({type(e).__name__}: {e}). So what this app could "
                         f"see when this ran is UNKNOWN, which is not the "
                         f"same as everything having been visible.")}


# WRITING THE RECORDS

def _record_run(session_id: str, trigger: str, outcome: str, *,
                incident_id: int = None, report_id: int = None,
                usage: dict = None, coverage: dict = None, detail: str = None,
                started: float = None, at: datetime = None,
                tool_names: list = None) -> int:
    """
    One row per WAKE, whatever the wake decided. Returns the row id, or 0.

    THE ROW'S CLOCK IS THE TICK'S CLOCK (`at`), not whatever time it is when
    the row is written. For the running loop the two are the same instant, but
    a tick asked to act at a given moment must leave a row that agrees with
    the decision it recorded — otherwise the schedule that reads `ran_at` is
    answering a different question from the one the tick answered.

    A WAKE THAT COULD NOT BE RECORDED SAYS SO IN THE LOG, because the whole
    point of the table is that "nothing happened" has a record. If this fails
    the loop keeps running -- a bookkeeping failure must not stop the work --
    but the failure is loud.

    `tool_names` IS THE AGENT'S OWN BEHAVIOUR, and until 2026-09-23 it was
    collected and thrown away. run_unattended returns the names of every tool
    the unattended turn called; _usage_dict pulled out tokens and answers and
    dropped them, so a run row said what the agent CONCLUDED and never what it
    RAN. NULL and [] are kept apart deliberately: NULL is a tick that never
    reached a model (budget, idle, a script), [] is a turn that ran and called
    nothing.

    THE SEAL IS TAKEN IN THE SAME TRANSACTION AS THE INSERT, so a crash
    cannot leave a run row that nothing attests to. See core/integrity's
    SEALED_TABLES block: this row is the agent's account of its own wake, and
    it is one of the four things the owner meant by "the agent's history".
    """
    usage = usage or {}
    coverage = coverage or {}
    stamp = _sql_ts(at) if at else _sql_ts(_now())
    try:
        from core import integrity
    except Exception as e:                          # noqa: BLE001
        integrity = None
        logger.error(f"integrity module unavailable, run rows will not be "
                     f"sealed: {e}")
    try:
        with me._get_conn() as conn:
            if not _table_ready(conn, "duty_run"):
                logger.error("duty_run does not exist, so this tick left NO "
                             "record. Run the migrations.")
                return 0
            prompt = int(usage.get("prompt_tokens") or 0)
            completion = int(usage.get("completion_tokens") or 0)
            cur = conn.execute("""
                INSERT INTO duty_run
                    (session_id, ran_at, ended_at, trigger, outcome,
                     incident_id, report_id, tokens_prompt,
                     tokens_completion, tokens_spent, tokens_estimated,
                     model_calls, coverage_json, coverage_note, detail,
                     duration_ms, tools_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                session_id, stamp, stamp, trigger,
                outcome, incident_id, report_id, prompt, completion,
                int(usage.get("total_tokens") or (prompt + completion)),
                1 if usage.get("estimated") else 0,
                int(usage.get("calls") or 0),
                json.dumps(coverage) if coverage else None,
                coverage.get("note"), detail,
                int((time.time() - started) * 1000) if started else None,
                json.dumps(tool_names) if tool_names is not None else None,
            ))
            row_id = cur.lastrowid
            # Inside the transaction, on the same connection: the row and its
            # witness land together or not at all.
            if integrity is not None and row_id:
                integrity.seal_row("duty_run", row_id, conn=conn)
    except Exception as e:
        logger.error(f"Could not record this duty run: {e}")
        return 0
    logger.info("Duty run #%s (%s/%s): %s", row_id, trigger, outcome,
                detail or "")
    return row_id


def write_report(session_id: str, kind: str, trigger: str, body: str, *,
                 incident_id: int = None, finding_id: int = None,
                 second_finding_id: int = None, hypothesis: str = None,
                 evidence: str = None, verdict: str = None, saw: str = None,
                 action_taken: str = None, usage: dict = None,
                 coverage: dict = None) -> dict:
    """
    Leave one report where a person can read it.

    RAISES BadDutyInput for the two things this will not accept, and both of
    them exist to stop a report that reads like work while saying nothing:

      * a `no_action` verdict with no `saw` -- "nothing needed doing" with
        nothing behind it is an absence, and the whole point of the column is
        to turn it into a claim a person can check;
      * an empty body -- the page renders this text and a blank report is
        worse than no report, because it occupies the place a real one goes.

    The coverage block is REQUIRED and not defaulted: a report written while
    the capture was blind must carry that fact, or it reads as a statement
    about the network.
    """
    verdict = (verdict or "").strip()
    saw = (saw or "").strip()

    if not (body or "").strip():
        raise BadDutyInput(
            "A report needs a body. The Agents page renders this text, so an "
            "empty report would occupy the place a real one goes.")

    if verdict.lower() in ("no_action", "no action", "none") and not saw:
        raise BadDutyInput(
            "A 'no action' verdict must say WHAT IT SAW. 'Nothing needed "
            "doing' with nothing behind it is an absence; 'I read these four "
            "things and here is why none of them needed doing' is a claim "
            "somebody can disagree with, which is what makes it worth "
            "recording.")

    if kind not in ("incident", "regular"):
        raise BadDutyInput(f"kind must be 'incident' or 'regular', got "
                           f"{kind!r}.")
    if action_taken is not None and action_taken not in ("none", "proposed",
                                                         "notified"):
        raise BadDutyInput(
            f"action_taken must be none, proposed or notified (or omitted), "
            f"got {action_taken!r}. 'proposed' means an action request was "
            f"FILED; nothing else in this app is an action.")

    usage = usage or {}
    coverage = coverage or {}
    prompt = int(usage.get("prompt_tokens") or 0)
    completion = int(usage.get("completion_tokens") or 0)

    try:
        from core import integrity
    except Exception as e:                          # noqa: BLE001
        integrity = None
        logger.error(f"integrity module unavailable, reports will not be "
                     f"sealed: {e}")

    with me._get_conn() as conn:
        if not _table_ready(conn, "duty_report"):
            raise BadDutyInput("the duty_report table does not exist.")
        cur = conn.execute("""
            INSERT INTO duty_report
                (session_id, created_at, kind, trigger, incident_id, finding_id,
                 second_finding_id, hypothesis, evidence, verdict, saw,
                 action_taken, body, tokens_spent, model_calls, coverage_json,
                 coverage_note)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            session_id, _sql_ts(_now()), kind, trigger, incident_id, finding_id,
            second_finding_id, hypothesis, evidence, verdict, saw,
            action_taken, body.strip(),
            int(usage.get("total_tokens") or (prompt + completion)),
            int(usage.get("calls") or 0),
            json.dumps(coverage) if coverage else None, coverage.get("note"),
        ))
        report_id = cur.lastrowid
        # The seal, in the same transaction as the row. This is the agent's
        # VERDICT, in its own words, which is the single most valuable thing
        # in this database for somebody who wants a quiet-looking week: edit
        # one `verdict` and the Agents page tells a different story. See
        # core/integrity's SEALED_TABLES block.
        if integrity is not None and report_id:
            integrity.seal_row("duty_report", report_id, conn=conn)

    logger.info("Duty report #%s (%s): %s", report_id, kind,
                (verdict or body[:60]))
    try:
        expire_old_reports()
    except Exception as e:                          # noqa: BLE001
        logger.warning(f"Could not expire old duty reports: {e}")
    return {"report_id": report_id, "kind": kind, "verdict": verdict}


# Reports are kept for one week and then deleted. The owner's rule: anything
# longer is too much for a home network.
REPORT_KEEP_DAYS = 7


def _report_cutoff(days: int = REPORT_KEEP_DAYS) -> str:
    return _sql_ts(_now() - timedelta(days=days))


def expire_old_reports(days: int = REPORT_KEEP_DAYS) -> int:
    """
    Delete reports older than the keep window and return how many went.

    Each delete is journalled as agent_report_expired in the same transaction,
    so the integrity check reads the missing row as housekeeping, not tampering.
    """
    from core import integrity

    cutoff = _report_cutoff(days)
    with me._get_conn() as conn:
        if not _table_ready(conn, "duty_report"):
            return 0
        ids = [r[0] for r in conn.execute(
            "SELECT id FROM duty_report WHERE created_at < ? ORDER BY id",
            (cutoff,)).fetchall()]
        for rid in ids:
            if integrity.record(
                    "agent_report_expired", table_name="duty_report",
                    row_ref=rid, payload={"cutoff": cutoff, "keep_days": days},
                    conn=conn) is None:
                # No journal entry means the delete would read as tampering.
                raise RuntimeError(f"could not journal the expiry of report "
                                   f"#{rid}, nothing was deleted")
            conn.execute("DELETE FROM duty_report WHERE id = ?", (rid,))
    if ids:
        logger.info("Deleted %d duty report(s) older than %d days.",
                    len(ids), days)
    return len(ids)



# THE PROMPTS
#
# WRITTEN IN THIS APP'S OWN VOICE, on the owner's instruction, and the
# instruction has a reason behind it worth writing down: a page of model prose
# in a different register from the rest of the dashboard reads as a different
# product. The same voice also carries the same rules — say what you saw, say
# what you could not see, do not narrate a card you did not send.

REPORT_VOICE = (
    "Write the way the rest of this application writes. Plain sentences, "
    "direct, no preamble, no closing summary of what you just said. Say what "
    "you looked at and what came back. If a sensor could not see, say that "
    "rather than drawing a conclusion from its silence. Do not dramatise and "
    "do not hedge: 'the process monitor raised 24 masquerading findings about "
    "systemd binaries in one evening, which is more likely a rule that is too "
    "broad than 24 attacks' is the voice. Never write that you have sent, "
    "raised or are sending a card unless a tool call in THIS turn filed one."
)

# WHAT THE UNATTENDED TURN IS TOLD ABOUT ITSELF. Deliberately short: the chat
# system prompt is 4,471 tokens and most of it is about conversations with a
# person, which this is not. What it DOES keep are the rules that apply harder
# with nobody watching — the fence, the coverage discipline, and the fact that
# it cannot decide its own requests.
UNATTENDED_ADDENDUM = (
    "\n\nTHIS TURN IS UNATTENDED.\n"
    "Nobody is at the keyboard. You were woken by a timer or by a condition, "
    "you are spending the operator's money without being asked to, and you go "
    "back to sleep when this turn ends. That changes three things and nothing "
    "else:\n"
    "- There is no one to ask a question mid-turn. ask_operator files a "
    "question for the owner to read later; it does not reach the owner now, so do not use "
    "it to resolve something you need in this turn.\n"
    "- Any action that changes the machine must go through "
    "file_action_request. It files a request, returns immediately, and a "
    "worker outside this turn runs it if and only if a person approves it. "
    "Nothing you do here runs anything.\n"
    "- Your output is a REPORT, not a chat message. It is stored, shown on the "
    "Agents page, and read later by somebody who was not here. Write what you "
    "saw, what you concluded, and what you could not see, in that order.\n"
)

INCIDENT_PROMPT = """You have been woken to look at one incident from the ledger. Nobody asked you to; a watcher decided this was worth a look and this is your turn to work it.

THE INCIDENT
{incident_block}

WHAT THIS APP COULD SEE WHEN THIS RUN STARTED
{coverage_block}

THE CASE FILE, what this app already knows about this subject, and what happened the last times something looked like this
{case_block}

THIS MACHINE'S PORTS AND THE PROCESSES HOLDING THEM, swept moments ago
{host_block}

WHAT TO DO, in order:
1. READ THE CASE FILE FIRST. It is not background: it is what this app already recorded about this subject and about incidents like this one. If the subject has been seen before, say what happened then and whether this is the same thing. If a past incident was dismissed, say WHO dismissed it and WHY before deciding anything about today; a dismissal is a decision somebody made about a different day and is not a reason to dismiss this one.
2. Form a hypothesis about what this is. Anything is allowed; nothing is recorded yet.
3. Gather evidence with your READ tools. Look at the entity, at what the sensors recorded around it, at the baseline for it, and at what your own past predictions said about it. The hypothesis is only worth recording if evidence follows it. If this incident is about a port, an address or a process ON THIS MACHINE, the host block above is the freshest evidence there is and it names the process holding each listening socket, use it, and use query_port_owner if you need a port it did not list.
4. Reach a verdict. One of: `real`, `benign`, `needs_human`, or `no_action`.
5. If the verdict is `needs_human` and there is an action that would stop it, FILE it with file_action_request. That is a proposal and nothing runs from it. State your objection in the reason if you have one.
6. If the verdict is `no_action`, you must say WHAT YOU SAW. Not "all clear", the specific things you read and why none of them needed doing.

IF THE CASE FILE SAYS IT COULD NOT BE READ, that is a real limitation of this run and you must say so in your report. An assessment made with no history is a different thing from one made with it, and a reader has to be able to tell which they are reading.

{voice}

ANSWER WITH A JSON OBJECT AND NOTHING ELSE, in exactly this shape:
{{
  "hypothesis": "what you think this is, one or two sentences",
  "evidence": "what you read, naming the tools, and what came back",
  "verdict": "real; benign; needs_human; no_action",
  "saw": "required when the verdict is no_action: the specific things you examined and why none needed doing",
  "report": "the report body for the Agents page, in this app's voice, a short paragraph or three"
}}
"""

REGULAR_PROMPT = """You have been woken at one of the day's regular moments. Nobody asked you to. Your job is one short report about TWO findings from DIFFERENT tools, and then you go back to sleep.

THE TWO FINDINGS, already picked from different tools on purpose:
{findings_block}

WHAT THIS APP COULD SEE WHEN THIS RUN STARTED
{coverage_block}

THIS MACHINE'S PORTS AND THE PROCESSES HOLDING THEM, swept moments ago
{host_block}

WHAT TO DO:
1. Read enough about each finding to say something true about it. Use your read tools, the entity, its baseline, the packets or events around it, the register entry for the detection that raised it. The host block above is the freshest look at this machine's own listening ports and their owning processes; if either finding touches a port, an address or a process here, that is evidence and query_port_owner answers for any port it did not list.
2. You MAY look at other findings or incidents if these two turn out to be uninteresting, but the report stays about these two: the page picks them so the report has a subject.
3. If either finding genuinely warrants an action, file it with file_action_request and say so in the report. Otherwise say plainly that neither did, and what you looked at to decide that.

{voice}

ANSWER WITH A JSON OBJECT AND NOTHING ELSE, in exactly this shape:
{{
  "hypothesis": "what you expect these two to be, before you looked",
  "evidence": "what you read, naming the tools, and what came back",
  "verdict": "real; benign; needs_human; no_action",
  "saw": "required when the verdict is no_action: what you examined and why neither finding needed acting on",
  "report": "the report body for the Agents page, about these two findings, in this app's voice"
}}
"""

# THE FLOOD ITSELF IS THE SUBJECT, as of 2026-09-29. Before this an emergency
# relabelled the run and then handed the model the next incident in the
# ledger, so 55 emergency investigations were about something other than the
# traffic that woke them.
EMERGENCY_PROMPT = """You have been woken by an EMERGENCY, not by a timer. The packet capture measured unsolicited traffic from one peer above a threshold in the last few minutes. Replies to connections this host opened were already set aside; what is below is traffic nobody here asked for.

THE MEASUREMENT THAT WOKE YOU
{emergency_block}

WHAT THIS APP COULD SEE WHEN THIS RUN STARTED
{coverage_block}

THIS MACHINE'S PORTS AND THE PROCESSES HOLDING THEM, swept moments ago
{host_block}

WHAT TO DO, in order:
1. Look at the peer with query_packets: which local ports it is hitting, which protocol, whether it is still going. Look it up with lookup_ip and query_enrichment. Check query_known_devices in case it is a device on this network.
2. Decide what it is. A flood at a listener, a scan, a misbehaving device on the LAN, or something ordinary this check did not recognise.
3. Reach a verdict. One of: `real`, `benign`, `needs_human`, or `no_action`.
4. If it is real or needs a human and blocking the peer would stop it, FILE block_device for that address with file_action_request. That is a proposal and nothing runs from it. Say in the reason that a block here is at this host only.
5. If the verdict is `no_action`, you must say WHAT YOU SAW.

{voice}

ANSWER WITH A JSON OBJECT AND NOTHING ELSE, in exactly this shape:
{{
  "hypothesis": "what you think this traffic is, one or two sentences",
  "evidence": "what you read, naming the tools, and what came back",
  "verdict": "real; benign; needs_human; no_action",
  "saw": "required when the verdict is no_action: the specific things you examined and why none needed doing",
  "report": "the report body for the Agents page, in this app's voice, a short paragraph or three"
}}
"""


def _emergency_block(emergency: dict) -> str:
    ev = emergency.get("evidence") or {}
    lines = [f"Reason: {emergency.get('reason') or ''}",
             f"Peer: {emergency.get('peer')}",
             f"Window: {ev.get('window_minutes')} minutes since {ev.get('since')}"]
    for key in ("busiest_inbound_peer", "busiest_udp_peer",
                "busiest_two_way_peer", "busiest_solicited_peer"):
        lines.append(f"{key}: {json.dumps(ev.get(key))}")
    lines.append(f"thresholds: {json.dumps(ev.get('thresholds'))}")
    return "\n".join(lines)


def _fenced(block: str) -> str:
    """
    A prompt block built from sensor rows, scrubbed and fenced like a tool
    result. Titles, entity values and descriptions carry text an attacker
    chose (a domain, a process name, a command line), and this prompt goes
    to a turn nobody is watching (CC-2).
    """
    from core import sanitize
    return sanitize.fence(sanitize.scrub_string(block, max_len=sanitize.MAX_RESULT_LEN))


def _incident_block(row: dict) -> str:
    cov = row.get("coverage_note") or "no coverage note was recorded"
    return (
        f"id: {row.get('id')}\n"
        f"rule: {row.get('detection_id')} ({row.get('title')})\n"
        f"subject: {row.get('entity_type')} {row.get('entity_value')}\n"
        f"severity: {row.get('severity')}   findings collapsed into it: "
        f"{row.get('finding_count')}\n"
        f"first seen: {row.get('first_seen_at')}   last seen: "
        f"{row.get('last_seen_at')}\n"
        f"suppressed at the time: "
        f"{'yes: ' + (row.get('suppressed_reason') or 'no reason recorded') if row.get('suppressed') else 'no'}\n"
        f"coverage when it was raised: {cov}"
    )


def _findings_block(rows: list) -> str:
    if not rows:
        return "No finding was available to report on. Say so in the report."
    lines = []
    for row in rows:
        lines.append(
            f"- finding {row.get('id')} from the {row.get('source')} sensor, "
            f"{row.get('severity')}, about {row.get('entity_type')} "
            f"{row.get('entity_value')}\n"
            f"  rule: {row.get('detection_id')}\n"
            f"  {row.get('title')}\n"
            f"  {row.get('description') or '(no description recorded)'}"
        )
    return "\n".join(lines)


# THE HOST SURVEY -- THE SECOND HALF OF THE OWNER'S INSTRUCTION
#
# "agent also should start reporting those in its report page ... whenever the
# agent wakes up to a full check and report back in the report page, it should
# be able to deploy python". 2026-09-25.
#
# So this runs on EVERY wake-up, before the prompt is built, whatever the tick
# turned out to be about, and its output goes into the prompt as a block the
# report is expected to read. Three decisions in it are worth their reasons:
#
#   * IT SWEEPS FIRST. An incident report is often written minutes or hours
#     after the thing it is about, and "which process holds that port NOW" is
#     the question a report about a listener cannot answer from a five-minute
#     old picture. port_owner.sweep_now is the same pass the timer runs.
#
#   * IT IS BOUNDED. Only the interesting listeners (all-interface, newly
#     appeared, moved, or the ones tied to the incident's own subject) plus
#     every change since the previous wake-up, capped. A prompt is not a
#     database dump and this project has a rule about handing a model a list
#     without saying whether it is whole -- so the cut is announced in words.
#
#   * A FAILURE IS IN THE BLOCK, NOT AN EXCEPTION. If the sweep cannot run,
#     the report still gets written and says the host picture is missing. A
#     monitoring tool that stops reporting because a convenience failed is
#     worse than one that reports without the convenience.

# How many listeners and how many changes go into a prompt. Chosen against
# this host's own measurement (16 listeners, of which 2 attributable
# unelevated): 40 is every listener on an ordinary desktop with room to spare,
# and the cap is announced when it bites.
SURVEY_LISTENER_CAP = 40
SURVEY_CHANGE_CAP = 25


def _interesting_listeners(rows: list, subject_values: set) -> tuple:
    """
    The listeners a report should read, worst-first, plus what was left out.

    ORDER IS THE DECISION, and it is not by port number. A report reader cares
    about, in this order: an address the incident itself names; a listener on
    ALL interfaces (that is the LAN question); one that appeared recently (new
    news); one whose holder changed or which moved; and then everything else,
    because a machine's ordinary listener set is still the context the
    interesting rows are read against.

    Returns (rows, omitted_count). The omitted count is never dropped: the
    caller announces it in the block.
    """
    def _rank(row):
        binds_subject = (row.get("local_address") in subject_values
                         or str(row.get("local_port")) in subject_values)
        wildcard = row.get("local_address") in ("0.0.0.0", "::")
        recent = False
        try:
            first = _parse_ts(row.get("first_seen_at"))
            recent = bool(first and (time.time() - first) < 3600)
        except Exception:                                # noqa: BLE001
            recent = False
        return (0 if binds_subject else 1,
                0 if wildcard else 1,
                0 if recent else 1,
                0 if (row.get("seen_count") or 0) <= 2 else 1,
                row.get("local_port") or 0)

    ordered = sorted(rows, key=_rank)
    return ordered[:SURVEY_LISTENER_CAP], max(0, len(ordered) - SURVEY_LISTENER_CAP)


def _render_listener(row: dict) -> str:
    where = f"{row.get('proto')} {row.get('local_address')}:{row.get('local_port')}"
    status = row.get("owner_status")
    if status == "identified":
        who = row.get("comm") or "?"
        exe = row.get("exe") or "path unreadable"
        extra = ""
        if row.get("seen_count") is not None:
            extra = (f"   first seen {row.get('first_seen_at')}, "
                     f"seen {row.get('seen_count')}x")
        return (f"- {where}  HELD BY pid {row.get('pid')} ({who})\n"
                f"    exe: {exe}{extra}")
    if status == "unreadable_as_user":
        return (f"- {where}  OWNER NOT READABLE from this account (root-owned "
                f"service, or another user's process). This is a privilege "
                f"limit, NOT a port with no owner.")
    return (f"- {where}  no process held this socket at the moment of the "
            f"pass; it closed between the two reads.")


def build_host_survey_block(session_id: str, modules: dict = None,
                            subject_values: set = None,
                            sweep: bool = True) -> str:
    """
    What is listening on this host, who holds it, and what changed since the
    last wake-up. NEVER RAISES; a failure is a sentence in the block.

    Runs a fresh sweep first so the report describes the machine as it is at
    the moment the agent looked, which is the owner's third instruction in the owner's
    own words. The sweep is the same one the interval thread runs, so there is
    one implementation of the correlation and one place its coverage sentence
    is written.
    """
    subject_values = {str(v) for v in (subject_values or set()) if v}
    lines = []
    try:
        from tools import port_owner
    except Exception as e:                                   # noqa: BLE001
        return (f"HOST PORTS AND PROCESSES: this app's port correlation "
                f"module could not be imported ({type(e).__name__}: {e}), so "
                f"NOTHING here says which process owns which port.")

    sweep_result = {}
    if sweep:
        try:
            sweep_result = port_owner.sweep_now(session_id,
                                                reason="duty report")
        except Exception as e:                               # noqa: BLE001
            sweep_result = {"ran": False, "reason": f"{type(e).__name__}: {e}"}

    if not sweep_result.get("ran"):
        reason = sweep_result.get("reason") or "no reason recorded"
        lines.append(
            f"THE SWEEP DID NOT RUN FOR THIS REPORT: {reason}. Anything below "
            f"is from the previous pass, and this report was written without a "
            f"look taken at the time it was written.")

    try:
        data = port_owner.query_listeners(limit=200)
    except Exception as e:                                   # noqa: BLE001
        return ("\n".join(lines + [
            f"HOST PORTS AND PROCESSES: the listener list could not be read "
            f"({type(e).__name__}: {e}). This report has NO host picture and "
            f"you must say so rather than describing the machine as quiet."]))

    if not data.get("available"):
        return ("\n".join(lines + [
            data.get("note") or "the port record is not available."]))

    last = data.get("last_sweep") or {}
    listeners = data.get("listeners") or []
    interesting, omitted = _interesting_listeners(listeners, subject_values)

    head = (f"HOST PORTS AND PROCESSES (this machine), swept "
            f"{last.get('taken_at') or 'at an unknown time'}.")
    lines.append(head)
    lines.append(
        f"  {last.get('listeners', 0)} listening socket(s), "
        f"{last.get('established', 0)} established connection(s). "
        + port_owner.coverage_sentence_for_row(last))

    if interesting:
        lines.append("  Listeners, the ones worth a reader's eye first:")
        lines.extend("  " + _render_listener(r) for r in interesting)
    else:
        lines.append("  No listening socket was recorded on this host.")
    if omitted:
        lines.append(f"  ...and {omitted} further listener(s) not listed here "
                     f"(cap {SURVEY_LISTENER_CAP}). This list is CUT, not "
                     f"complete.")

    try:
        changes = port_owner.query_changes(limit=SURVEY_CHANGE_CAP + 1)
    except Exception:                                        # noqa: BLE001
        changes = []
    if changes:
        cut = len(changes) > SURVEY_CHANGE_CAP
        changes = changes[:SURVEY_CHANGE_CAP]
        lines.append("  What changed since an earlier pass (this is the part "
                     "that is news):")
        for c in changes:
            lines.append(f"  - [{c.get('kind')}] {c.get('note')}")
        if cut:
            lines.append(f"  ...and more changes than {SURVEY_CHANGE_CAP}; "
                         f"this list is CUT.")
    else:
        lines.append("  Nothing about this host's listeners has changed since "
                     "the previous pass. That is a statement about the record, "
                     "not an all-clear about the machine.")

    lines.append(
        "  HOW TO USE THIS. A listener this app could not attribute is a "
        "PRIVILEGE LIMIT and must be described that way: never as an "
        "unowned or mysterious port. A port being open raises no finding in "
        "this app by design, so say what you see and what it is, not that "
        "something is wrong. If a change here bears on the subject of this "
        "report, say so in the evidence; if none does, do not pad the report "
        "with the list.")
    return "\n".join(lines)


def _last_wake() -> str | None:
    """When the loop last called the model, as stored, or None."""
    try:
        with me._get_readonly_conn() as conn:
            if not _table_ready(conn, "duty_run"):
                return None
            row = conn.execute("SELECT MAX(ran_at) FROM duty_run "
                               "WHERE model_calls > 0").fetchone()
        return row[0] if row else None
    except Exception:                                        # noqa: BLE001
        return None


def build_map_block(session_id: str) -> str:
    """The Threat Map in a few lines. NEVER RAISES."""
    try:
        from core import place_map
        last = _last_wake()
        since = None
        if last:
            dt = _parse_ts(last)
            since = (dt.strftime("%Y-%m-%dT%H:%M:%S+00:00") if dt else None)
        return place_map.digest(since=since, session_id=session_id)
    except Exception as e:                                   # noqa: BLE001
        return (f"THREAT MAP SUMMARY: could not be built ({type(e).__name__}: "
                f"{e}). Say so rather than describing the traffic as quiet.")


def _coverage_block(coverage: dict) -> str:
    note = (coverage or {}).get("note") or "unknown"
    if (coverage or {}).get("complete") is True:
        return (f"{note}\nEvery sensor that reports its own health said it "
                f"could see, so an empty answer here really does mean nothing "
                f"was there.")
    return (f"{note}\nREAD THIS BEFORE CONCLUDING ANYTHING: something above is "
            f"degraded, so a small or empty answer may mean A SENSOR COULD "
            f"NOT LOOK rather than nothing happened. Say which, in the report.")


# ONE TICK

def _next_regular_moment(now: datetime = None) -> dict:
    """
    When the next regular wake-up is, and whether this minute is one.

    THE SCHEDULE IS THE OWNER'S HOURS IN LOCAL TIME, and "is it due" is
    answered by the last run rather than by a timer that fires once: the loop
    ticks every minute, so a moment is due when the local hour matches and no
    regular run has happened in this hour yet. That makes a wake-up survive a
    restart mid-hour instead of being skipped, which a one-shot timer would
    not.

    THE BOUNDARY IS BUILT FROM THE CLOCK AND THE WINDOW IS COMPARED, not
    approximated by subtracting the elapsed minute. The first version computed
    its cutoff as `now - <minutes into this hour>`, which lands a few seconds
    AFTER the top of the hour (the seconds of `now` ride along), so a run
    written at the exact top of the hour fell outside its own hour's window
    and the hour looked un-served. Subtracting the hour's start as a datetime
    makes the comparison exact for every second of the hour.

    ONE ATTEMPT PER WAKE-HOUR, WHATEVER THE ATTEMPT DECIDED. Any duty_run row
    written in this hour serves it: investigated, reported, idle, budget or
    error. The earlier version counted only `investigated` and `reported` as
    serving the hour, and the live database shows what that costs — once the
    daily ceiling was reached, the loop wrote a `budget` row EVERY SIXTY
    SECONDS for the remaining hour, because each refusal left the hour looking
    un-served and the next poll woke it again. Same defect for an `idle` wake
    on a quiet machine. A moment is a moment: it is due once, it is attempted
    once, and the row it leaves is the record of that attempt. An emergency
    still promotes on every poll and is not gated by this.
    """
    now = now or _now()
    local = now.astimezone()
    hours = _wake_hours()

    due = local.hour in hours
    # THE WINDOW IS THE CLOCK HOUR, built from the LOCAL value so the boundary
    # is the top of the owner's hour whatever the machine's offset. Replacing
    # the minutes on the UTC-converted value is identical on a whole-hour
    # offset like this box's UTC-7 and WRONG on a 30- or 45-minute offset,
    # where it would move the boundary half an hour and let a wake-up repeat
    # in one hour or vanish from the next.
    hour_start = _sql_ts(local.replace(minute=0, second=0, microsecond=0))
    if due:
        try:
            with me._get_readonly_conn() as conn:
                if _table_ready(conn, "duty_run"):
                    already = conn.execute(
                        "SELECT COUNT(*) FROM duty_run WHERE ran_at >= ?",
                        (hour_start,)).fetchone()[0]
                    if already:
                        due = False
        except Exception as e:
            logger.warning(f"could not read the duty history for the schedule: "
                           f"{e}")
            due = False

    later = [h for h in hours if h > local.hour]
    next_hour = later[0] if later else hours[0]
    return {"due_now": due, "local_hour": local.hour, "hours": list(hours),
            "next_hour": next_hour,
            "next_is_tomorrow": not later,
            "note": (f"Regular wake-ups at local hours "
                     f"{', '.join(str(h) for h in hours)}. This machine is "
                     f"at {local.strftime('%Z') or local.tzname()}.")}


def _held_by_budget(now: datetime):
    """
    Hold urgent work while the budget is shut, after its one refusal row.

    LOOP-14, 2026-10-05. Once the ceiling was spent, every poll picked the
    next untried urgent incident and wrote a `budget` row for it: 110 on
    2026-10-05, one a minute. The first refusal still runs and writes its
    row, so the limit is on record; later ones wait for the window to reopen,
    which the poll sees through budget_state, a few indexed counts.
    """
    try:
        state = budget_state(urgent=True)
    except Exception as e:                              # noqa: BLE001
        logger.error(f"budget check failed on a poll, not holding: {e}")
        return None
    if state.get("may_spend"):
        _duty_state["budget_refused_at"] = None
        return None
    if _duty_state.get("budget_refused_at") is None:
        _duty_state["budget_refused_at"] = _sql_ts(now)
        return None
    return {"outcome": "not_due", "held_by_budget": True,
            "budget_refused_at": _duty_state["budget_refused_at"],
            "reasons": state.get("reasons")}


def _tick_once(session_id: str, modules: dict = None,
               now: datetime = None) -> dict:
    """
    ONE POLL OF THE LOOP, and the gate the daemon was missing.

    THE DEFECT THIS FUNCTION EXISTS TO FIX, measured rather than reasoned
    about. `_next_regular_moment()` answered "is a wake-up due" correctly and
    NOTHING CALLED IT. The daemon called run_once every sixty seconds with
    `trigger="regular"`, and run_once treats any call as a wake-up, so every
    minute of every day was a regular moment. The live database from
    2026-09-18: 62 duty_run rows between 19:08 and 22:05 — eight runs that
    called the model (2,216,938 tokens between them), and once the daily
    ceiling was crossed at 22:04, a `budget` row EVERY SIXTY SECONDS, still
    being written when this was read. The owner's requirement was four
    moments a day.

    So the poll decides between three things, and they are different facts:

      * an EMERGENCY, which outranks the schedule and runs NOW;
      * a REGULAR MOMENT, when the owner's local hour matches and no run that
        reached the model has happened in this hour;
      * NOTHING DUE, which writes NO row and is recorded only in the loop's
        own state (`polls`, `last_poll`, `last_skip`). The run table is the
        record of every time the agent woke; a row per minute of looking at
        the clock would bury the day's few wakes under 1,440 lines and make
        the page unreadable.

    THE EMERGENCY CHECK RUNS ON EVERY POLL and costs one bounded SQL aggregate
    — three indexed count queries, no model call. That is deliberate: a
    condition that cannot wait for a schedule must be noticed on the minute it
    happens, not at the next scheduled hour. It only ever SAVES money (it
    promotes a tick that would otherwise be a no-op) or spends it on the one
    thing the owner said must not wait.

    A tick a budget refused still writes its row, because "a cap stopped it"
    is an outcome a person needs to see. It just does not consume the hour's
    moment: see _next_regular_moment.

    Returns the run result dict when a tick ran, or
    {"outcome": "not_due", ...} when nothing was due.
    """
    now = now or _now()

    def _run(trigger: str, **kw) -> dict:
        # MARKED BEFORE THE WORK so an in-flight tick is visible for its whole
        # duration (an investigation runs 1-3 minutes), then cleared however
        # the call ends. See the note on tick_started_at.
        _duty_state["tick_started_at"] = _sql_ts(_now())
        try:
            return run_once(session_id, trigger, modules=modules, now=now,
                            **kw)
        finally:
            _duty_state["tick_started_at"] = None

    if not _enabled():
        # SWITCHED OFF STILL RESPECTS THE CLOCK. run_once records it and says
        # so, and status() calls the loop blind for it — but one row per
        # WAKE-HOUR, not one per minute. The first version of this gate let
        # the disabled branch straight through, which would have written an
        # `idle, switched off` row every sixty seconds: the same flood this
        # function exists to stop, one layer down.
        schedule = _next_regular_moment(now)
        if not schedule.get("due_now"):
            return {"outcome": "not_due", "schedule": schedule}
        return _run("regular")

    schedule = _next_regular_moment(now)
    emergency = None
    try:
        emergency = emergency_check(modules, now)
    except Exception as e:
        logger.error(f"emergency check failed on a poll: {e}")
        emergency = {"emergency": False, "blind": True,
                     "blind_reason": f"the check itself failed: {e}"}

    if emergency.get("emergency"):
        cooled = emergency_cooled_down(emergency.get("peer"),
                                       emergency.get("n") or 0, now)
        if not cooled.get("cooled"):
            held = _held_by_budget(now)
            if held:
                return dict(held, schedule=schedule, emergency=emergency)
            logger.warning("DUTY EMERGENCY: %s", emergency.get("reason"))
            return _run("emergency", emergency=emergency)
        # THE SAME FLOOD, ALREADY HANDLED THIS HOUR. No row: the run that
        # handled it is the record, and a row a minute was the storm.
        emergency = dict(emergency, cooled_down=cooled)

    # AN URGENT INCIDENT outranks the schedule too. The DB trigger stays
    # 'emergency' (duty_run's CHECK), and the detail tag says which kind.
    try:
        urgent = urgent_incident(now)
    except Exception as e:
        logger.error(f"urgent incident check failed on a poll: {e}")
        urgent = None
    if urgent:
        held = _held_by_budget(now)
        if held:
            return dict(held, schedule=schedule, emergency=emergency)
        logger.warning("DUTY URGENT INCIDENT #%s: %s (%s)", urgent.get("id"),
                       urgent.get("title"), urgent.get("severity"))
        return _run("emergency", incident_id=urgent["id"], urgent=True)

    if not schedule.get("due_now"):
        return {"outcome": "not_due", "schedule": schedule,
                "emergency": emergency}

    return _run("regular", emergency=emergency)


def _usage_dict(result: dict) -> dict:
    """
    The usage block the unattended turn reports, in this file's shape.

    `tool_names` AND `refused_calls` ARE CARRIED THROUGH AS OF 2026-09-23, and
    their absence was a real defect rather than a tidy-up. run_unattended has
    always returned both; this function read the dict for tokens, answers and
    error and dropped them, so every name the agent invoked was collected,
    paid for, and then thrown away in the one place that writes the record.
    The run row could say the agent spent 166,797 tokens and reached a
    verdict; it could not say what it ran to get there, which is most of what
    "the tools it called" means. Now they land in duty_run.tools_json.
    """
    usage = (result or {}).get("usage") or {}
    calls = (result or {}).get("tool_calls")
    refused = (result or {}).get("refused_calls")
    return {
        "prompt_tokens": usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
        "total_tokens": usage.get("total_tokens"),
        "calls": usage.get("calls"),
        "estimated": usage.get("estimated"),
        "answers": (result or {}).get("answers") or [],
        "error": (result or {}).get("error"),
        # None, not []: a caller that never reached this returns no list at
        # all, and the two must stay distinguishable in the column.
        "tool_names": list(calls) if calls is not None else None,
        "refused_calls": list(refused) if refused is not None else None,
    }


def _parse_report(replies: list) -> dict:
    """
    Pull the JSON object out of whatever the model answered with.

    IT TOLERATES A FENCED BLOCK AND NOTHING ELSE. A model that wraps its answer
    in ```json is common enough to handle, and a model that writes prose
    instead is a real failure that must be recorded rather than papered over:
    the fallback keeps the whole text as the report body and leaves verdict and
    `saw` empty, which make_report will then REFUSE if the verdict needs a
    `saw`. That is the right shape — a malformed answer becomes a recorded
    problem, not a silent empty report.
    """
    text = ""
    for reply in reversed(replies or []):
        if reply and reply.strip():
            text = reply
            break
    if not text:
        return {"error": "the model produced no answer at all"}

    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```")[1] if "```" in cleaned[3:] else cleaned[3:]
        if cleaned.lstrip().lower().startswith("json"):
            cleaned = cleaned.lstrip()[4:]
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start < 0 or end <= start:
        return {"error": (f"the model's answer was not a JSON object: "
                          f"{text[:200]}"), "body_fallback": text.strip()}
    try:
        parsed = json.loads(cleaned[start:end + 1])
    except (TypeError, ValueError) as e:
        return {"error": (f"the model's answer looked like JSON but did not "
                          f"parse ({e}): {text[:200]}"),
                "body_fallback": text.strip()}
    if not isinstance(parsed, dict):
        return {"error": "the model's answer was JSON but not an object"}
    return parsed


def _finish_incident(incident_id: int, verdict: str, note: str) -> dict:
    """
    Move an assessed incident to `triaged`, with the assessment on the row.

    IT DOES NOT RESOLVE AND IT DOES NOT DISMISS. Both of those are judgements
    about whether something is over, and the loop's own output is a hypothesis
    plus a look — resolving on that would be the app closing its own tickets.
    The owner asked for a page where the agent's work is READABLE; making the
    work also self-certifying is a different, worse thing.
    """
    try:
        from core import incident
        return incident.set_status(incident_id, "triaged", by="model", note=note)
    except Exception as e:
        logger.error(f"Could not move incident {incident_id} to triaged: {e}")
        return {"success": False, "error": str(e)}


def _run_unattended(prompt: str, session_id: str) -> dict:
    """Call agent_loop's unattended turn. Imported lazily; see _tool_allowlist."""
    from core import agent_loop
    return agent_loop.run_unattended(prompt, session_id, _tool_allowlist(),
                                     extra_system=UNATTENDED_ADDENDUM)


# LOOP-12, 2026-09-27. ONE TICK AT A TIME.
#
# /api/agents/run-now calls run_once in the request thread while the daemon
# may be mid investigation, and nothing stopped the two racing the same
# incident. A second caller now gets {"outcome": "busy"} straight away and
# nothing is examined or spent. No duty_run row is written for it: it was not
# a wake, and the tick already running writes its own row.
_tick_lock = threading.Lock()


def run_once(session_id: str, trigger: str = "manual", *,
             modules: dict = None, incident_id: int = None,
             now: datetime = None, emergency: dict = None,
             urgent: bool = False) -> dict:
    """ONE TICK, never two at once. The work is _run_once_unguarded."""
    if not _tick_lock.acquire(blocking=False):
        return {"outcome": "busy",
                "detail": ("A duty tick is already running, so this one did "
                           "not start. Nothing was examined and nothing was "
                           "spent. Its result will be in the report when it "
                           "finishes.")}
    try:
        return _run_once_unguarded(session_id, trigger, modules=modules,
                                   incident_id=incident_id, now=now,
                                   emergency=emergency, urgent=urgent)
    finally:
        _tick_lock.release()


def _run_once_unguarded(session_id: str, trigger: str = "manual", *,
                        modules: dict = None, incident_id: int = None,
                        now: datetime = None, emergency: dict = None,
                        urgent: bool = False) -> dict:
    """
    ONE TICK. This is the function the daemon calls and the one a script calls.

    `emergency` is the poll's own check, passed in so the tick acts on the
    measurement that woke it rather than taking a second one. `urgent` marks a
    run the poll started for an incident above the urgent floor. Both runs
    may spend into the emergency reserve, and both tag their run row's detail
    (FLOOD_TAG, URGENT_TAG) so the cooldowns can be read back from the rows.

    THE ORDER OF THE DECISIONS MATTERS AND IT IS DELIBERATE:

      1. switched off?  say so, record `idle`, stop. Nothing is examined.
      2. emergency?     if a condition is above threshold, that decides the
                        trigger whatever this call was asked for. An emergency
                        does not queue behind a schedule.
      3. budgets?       THE HARD STOP, BEFORE anything is picked and before a
                        token is spent. A tick that picked work first and then
                        discovered it could not afford it would have spent the
                        model call it was trying to avoid.
      4. what work?     an incident (worst first) or a regular report (two
                        findings from different tools).
      5. nothing?       `idle`, with a detail sentence naming what was looked
                        for. NOT an error and not a quiet network.
      6. run it, record it, return.

    Every exit path writes a duty_run row. That is the rule this file is built
    around and it has no exceptions.
    """
    started = time.time()
    now = now or _now()
    coverage = _coverage(modules)

    if not _enabled():
        _record_run(session_id, trigger, "idle", coverage=coverage,
                    started=started, at=now,
                    detail=("the duty loop is switched off in config.json "
                            "(duty_loop.enabled). NOTHING IS BEING INVESTIGATED "
                            "and that is a configuration choice, not a quiet "
                            "network."))
        return {"outcome": "idle", "reason": "switched off in config.json"}

    # 2. the emergency check runs on EVERY tick, whatever was asked for, and
    # its answer can promote an ordinary tick into an emergency one. A tick
    # the poll started carries the poll's check, and a cooled-down flood is
    # not promoted again: the poll already decided it was handled.
    if emergency is None:
        emergency = {"emergency": False}
        if not incident_id:
            try:
                emergency = emergency_check(modules, now)
            except Exception as e:
                logger.error(f"emergency check failed: {e}")
                emergency = {"emergency": False, "blind": True,
                             "blind_reason": f"the check itself failed: {e}"}
    flood = (emergency if emergency.get("emergency") and not incident_id
             and not emergency.get("cooled_down") else None)
    if flood:
        trigger = "emergency"
        logger.warning("DUTY EMERGENCY: %s", flood.get("reason"))

    if flood:
        tag = _flood_tag(flood.get("peer"), flood.get("n") or 0)
    elif urgent and incident_id:
        tag = f"{URGENT_TAG}{incident_id}] "
    else:
        tag = ""

    def _record_run_tagged(*args, **kwargs):
        if tag:
            kwargs["detail"] = tag + (kwargs.get("detail") or "")
        return _record_run(*args, **kwargs)

    # 3. the budgets. An emergency or an urgent incident may spend the reserve.
    budget = budget_state(urgent=bool(flood or urgent))
    if not budget["may_spend"]:
        # incident_id IS RECORDED so urgent_incident's retry window sees
        # this refusal; without it an urgent incident refused by a budget
        # would be retried on every poll.
        _record_run_tagged(session_id, trigger, "budget", coverage=coverage,
                    started=started, at=now, incident_id=incident_id,
                    detail=("Refused by a budget: "
                            + "; ".join(budget["reasons"])
                            + ". NOTHING WAS EXAMINED. This is a limit being "
                              "hit, which is not a quiet network."))
        return {"outcome": "budget", "budget": budget}

    # 4. what work is there. A flood is its own subject.
    if flood:
        rows = [{"entity_value": flood.get("peer")}]
        kind = "emergency"
    elif incident_id:
        rows = [r for r in _incident_candidates(limit=200)
                if r["id"] == incident_id]
        if not rows:
            with me._get_readonly_conn() as conn:
                row = None
                if _table_ready(conn, "incident"):
                    row = conn.execute("SELECT * FROM incident WHERE id = ?",
                                       (incident_id,)).fetchone()
            rows = [dict(row)] if row else []
        kind = "incident"
    else:
        rows = _incident_candidates(limit=3)
        kind = "incident" if rows else "regular"

    if not rows:
        if kind == "regular":
            rows = pick_findings(2)
        if not rows:
            _record_run_tagged(session_id, trigger, "idle", coverage=coverage,
                        started=started, at=now,
                        detail=("Woke and found nothing eligible: no incident "
                                "in `new`, and no undismissed finding with a "
                                "detection id in the last 24 hours. That is "
                                "what was looked for, and an empty ledger is a "
                                "statement about the ledger."))
            return {"outcome": "idle",
                    "reason": ("nothing eligible: no new incidents and no "
                               "recent findings")}

    # duty_report's CHECK knows incident and regular; a flood is reported as
    # an incident with no ledger row, and its trigger says emergency.
    report_kind = "incident" if kind == "emergency" else kind
    subject = {}
    # report_subject is the ONLY shape write_report accepts, kept next to
    # `subject` (which is what the caller and the run row read) so the two can
    # never be confused again. The first live run of this loop died on
    # `write_report() got an unexpected keyword argument 'detection_id'`
    # because the incident's whole row was being splatted into a call whose
    # signature has no idea what an incident looks like.
    report_subject = {}

    # THE HOST SURVEY, AND IT RUNS BEFORE THE PROMPT IS BUILT.
    #
    # The owner's instruction, 2026-09-25: the agent "should start reporting
    # those in its report page" and "whenever the agent wakes up to a full
    # check and report back in the report page, it should be able to deploy
    # python". This runs a FRESH port-ownership sweep and renders the result
    # into the prompt, so a report always describes the machine as it was when
    # the agent looked rather than as it was up to a sweep-interval ago.
    #
    # IT IS NOT A TOOL CALL AND THAT IS DELIBERATE. The duty loop already has
    # the same problem case_memory was built for: retrieval the model has to
    # think to ask for is retrieval that happens exactly when an investigation
    # already feels uncertain. The survey is the machine's standing state, it
    # costs 65 ms, and a report about a host that does not carry it is a report
    # written from a blank page about the one thing the owner asked to see.
    #
    # subject_values ties the survey to THIS tick's work: an incident about
    # port 8888 or about an address gets those rows ranked first. It is passed
    # rather than filtered so the block can say what it left out.
    _survey_subject = set()
    if kind == "incident" and rows:
        _survey_subject = {rows[0].get("entity_value")}
    else:
        _survey_subject = {r.get("entity_value") for r in rows}
    host_block = build_host_survey_block(session_id, modules,
                                         subject_values=_survey_subject)
    # The map summary rides with the host survey, so every wake prompt has it.
    map_block = build_map_block(session_id)
    host_block = "\n\n".join(b for b in (host_block, map_block) if b)

    # 5. build the prompt and call the model.
    if kind == "emergency":
        prompt = EMERGENCY_PROMPT.format(
            emergency_block=_fenced(_emergency_block(flood)),
            coverage_block=_coverage_block(coverage),
            host_block=_fenced(host_block) if host_block else host_block,
            voice=REPORT_VOICE)
        subject = {"emergency_peer": flood.get("peer"),
                   "packets": flood.get("n")}
    elif kind == "incident":
        row = rows[0]
        # THE PATIENT FILE IS OPENED BEFORE THE MODEL IS ASKED ANYTHING.
        #
        # Case memory, 2026-09-22. This is a call in the PROMPT-BUILDING PATH
        # rather than a tool the model may choose to use, and that is the whole
        # difference between retrieval that happens and retrieval that is
        # available. The owner's complaint was that every alert was
        # investigated from a blank page; a memory the model has to think to
        # ask for would be the same blank page with an extra step, and would be
        # asked for exactly when an investigation already felt uncertain.
        #
        # It CANNOT fail the investigation. brief_for_incident never raises and
        # reports its own failure in the text, and the failure is written into
        # the report so an assessment made without the history can be told
        # apart from one made with it.
        case_block = ""
        try:
            from core import case_memory
            brief = case_memory.brief_for_incident(row)
            case_block = case_memory.render_brief(brief)
        except Exception as e:                          # noqa: BLE001
            # brief_for_incident is written not to raise. This arm exists
            # because "written not to" and "cannot" are different claims, and
            # the difference is an investigation that never happens.
            logger.error(f"case memory unavailable for incident "
                         f"{row.get('id')}: {e}")
            case_block = (
                "CASE MEMORY: could not be read for this run "
                f"({type(e).__name__}: {e}). You are working this incident "
                "with no history, and you must say so in your report.")

        prompt = INCIDENT_PROMPT.format(
            incident_block=_fenced(_incident_block(row)),
            coverage_block=_coverage_block(coverage),
            case_block=_fenced(case_block) if case_block else case_block,
            host_block=_fenced(host_block) if host_block else host_block,
            voice=REPORT_VOICE)
        subject = {"incident_id": row.get("id"),
                   "detection_id": row.get("detection_id"),
                   "entity_value": row.get("entity_value")}
        report_subject = {"incident_id": row.get("id")}
    else:
        prompt = REGULAR_PROMPT.format(
            findings_block=_fenced(_findings_block(rows)),
            coverage_block=_coverage_block(coverage),
            host_block=_fenced(host_block) if host_block else host_block,
            voice=REPORT_VOICE)
        subject = {"finding_id": rows[0].get("id") if rows else None,
                   "second_finding_id": rows[1].get("id") if len(rows) > 1
                   else None,
                   "sources": [r.get("source") for r in rows]}
        report_subject = {"finding_id": subject["finding_id"],
                          "second_finding_id": subject["second_finding_id"]}

    result = _run_unattended(prompt, session_id)
    usage = _usage_dict(result)
    # THE NAMES THE TURN CALLED, carried to every run row below. Collected
    # since T4, returned by run_unattended since T4, and dropped by
    # _usage_dict until 2026-09-23; see its docstring.
    tool_names = usage.get("tool_names")
    if usage.get("error") or not usage.get("answers"):
        detail = (f"the model call did not produce an answer: "
                  f"{usage.get('error') or 'no answer text'}")
        _record_run_tagged(session_id, trigger, "error", coverage=coverage,
                    usage=usage, started=started, at=now, detail=detail,
                    incident_id=subject.get("incident_id"),
                    tool_names=tool_names)
        return {"outcome": "error", "reason": detail, "usage": usage}

    parsed = _parse_report(usage.get("answers"))

    # A MALFORMED ANSWER IS RECORDED AS A REPORT WITH ITS PROBLEM ON IT,
    # never dropped. A duty run that spent tokens and left nothing behind is
    # the exact failure this component exists to make impossible, so the
    # fallback keeps the model's own text as the body and says what went
    # wrong.
    if parsed.get("error"):
        body = parsed.get("body_fallback") or "The model's answer could not " \
                                              "be read as a report."
        report = write_report(
            session_id, report_kind, trigger,
            body=(f"{body}\n\n[THIS REPORT IS MALFORMED. "
                  f"{parsed['error']}]"),
            hypothesis=None, evidence=None,
            verdict="unparsed", saw=None, action_taken=None,
            usage=usage, coverage=coverage, **report_subject)
        _record_run_tagged(session_id, trigger, "error", coverage=coverage,
                    usage=usage, started=started, at=now,
                    report_id=report["report_id"],
                    incident_id=subject.get("incident_id"),
                    detail=parsed["error"], tool_names=tool_names)
        return {"outcome": "error", "reason": parsed["error"], "usage": usage,
                "report_id": report["report_id"]}

    try:
        report = write_report(
            session_id, report_kind, trigger,
            body=parsed.get("report") or "",
            hypothesis=parsed.get("hypothesis"),
            evidence=parsed.get("evidence"),
            verdict=parsed.get("verdict"),
            saw=parsed.get("saw"),
            action_taken=parsed.get("action_taken"),
            usage=usage, coverage=coverage, **report_subject)
    except BadDutyInput as e:
        # write_report's own refusal, and it is the interesting case: the
        # model concluded "no action" and did not say what it saw. Recorded
        # with the model's text and the refusal in it, because the sentence
        # explaining what is missing is worth more than a second model call.
        report = write_report(
            session_id, report_kind, trigger,
            body=(f"{(parsed.get('report') or '').strip()}\n\n"
                  f"[THIS REPORT WAS REFUSED. {e}]"),
            hypothesis=parsed.get("hypothesis"), evidence=parsed.get("evidence"),
            verdict="refused", saw=None, action_taken=None,
            usage=usage, coverage=coverage, **report_subject)
        _record_run_tagged(session_id, trigger, "error", coverage=coverage,
                    usage=usage, started=started, at=now,
                    report_id=report["report_id"],
                    incident_id=subject.get("incident_id"), detail=str(e),
                    tool_names=tool_names)
        return {"outcome": "error", "reason": str(e),
                "report_id": report["report_id"], "usage": usage}

    if kind == "incident" and subject.get("incident_id"):
        _finish_incident(
            subject["incident_id"], parsed.get("verdict") or "",
            note=(f"Assessed by the duty loop: "
                  f"{parsed.get('verdict') or 'no verdict recorded'}. "
                  f"{(parsed.get('hypothesis') or '')[:300]}"))

    _record_run_tagged(session_id, trigger,
                "reported" if kind == "regular" else "investigated",
                coverage=coverage, usage=usage, started=started, at=now,
                report_id=report["report_id"],
                incident_id=subject.get("incident_id"),
                detail=(parsed.get("verdict") or "")[:200],
                tool_names=tool_names)

    return {"outcome": "reported" if kind == "regular" else "investigated",
            "report_id": report["report_id"], "kind": kind,
            "verdict": parsed.get("verdict"), "usage": usage,
            "subject": subject}


# THE DAEMON

_duty_thread = None
_duty_stop = threading.Event()
_duty_state = {
    "running": False,
    # When the budget last refused an urgent run. While it stays shut, later
    # urgent incidents wait without a run row each (LOOP-14).
    "budget_refused_at": None,
    "session_id": None,
    "modules": None,
    "last_error": None,
    "consecutive_failures": 0,
    "last_tick": None,
    # SET WHILE A TICK IS IN FLIGHT, AND IT WAS ADDED BECAUSE WATCHING THE LIVE
    # APP SHOWED WHAT ITS ABSENCE COSTS. A tick that investigates takes one to
    # three minutes (seven model rounds, measured at 113-190s). With the run
    # row written only at the END, the Agents page showed `ticks: 0` and no
    # runs at all for the whole of that window — which is exactly the same
    # picture as a loop that is not ticking. That is the failure this whole
    # programme is about, in the component written to fix it.
    #
    # last_tick_started_at is set BEFORE the work and moved to last_tick when
    # it lands, so a reader can tell "in the middle of something" from both
    # "idle and healthy" and "not running".
    "tick_started_at": None,
    "last_result": None,
    "ticks": 0,
    # THE POLLS THAT WERE NOT WAKE-UPS. The schedule gate means most polls do
    # nothing, and "nothing was due" must be readable somewhere or the new
    # quiet looks exactly like the old silence. It is NOT written to the run
    # table (see _tick_once for why); it lives here and travels in status().
    "polls": 0,
    "last_poll": None,
    "last_skip": None,
    "last_skip_at": None,
}


def _tick_once_state(result: dict) -> None:
    """Fold one poll's result into the loop state. Never raises."""
    _duty_state["polls"] += 1
    _duty_state["last_poll"] = _sql_ts(_now())
    if result.get("outcome") == "not_due":
        sched = result.get("schedule") or {}
        _duty_state["last_skip"] = {
            "reason": ("budget spent, urgent work waits for it to reopen: "
                       + "; ".join(result.get("reasons") or [])
                       if result.get("held_by_budget") else "not due"),
            "local_hour": sched.get("local_hour"),
            "next_hour": sched.get("next_hour"),
            "next_is_tomorrow": sched.get("next_is_tomorrow"),
            "hours": sched.get("hours"),
        }
        _duty_state["last_skip_at"] = _duty_state["last_poll"]
    else:
        # A WAKE CLEARS THE STALE SKIP. Left standing, the page would keep
        # showing "nothing was due at <an hour ago>" beside recent wake-ups,
        # which is a true sentence about a time that no longer means anything.
        _duty_state["last_skip"] = None
        _duty_state["last_skip_at"] = None


def start(session_id: str, modules: dict = None) -> bool:
    """
    Start the duty loop. Returns whether it started.

    REFUSES RATHER THAN STARTING A THREAD THAT CANNOT WORK, the same contract
    the watcher and the executor have: a loop reporting running:true against a
    database with no duty tables has nothing to write its runs into, and every
    record this component makes would be lost while the page showed it as
    awake.
    """
    global _duty_thread

    if _duty_state["running"]:
        return False

    if not _enabled():
        logger.info("Duty loop is switched off in config.json.")
        return False

    try:
        with me._get_readonly_conn() as conn:
            if not _table_ready(conn, "duty_run") or \
                    not _table_ready(conn, "duty_report"):
                logger.warning(
                    "Duty loop NOT started: the duty tables do not exist. "
                    "Run the migrations. NOTHING IS INVESTIGATING ANYTHING "
                    "until this is fixed, and that is a statement about this "
                    "app rather than about the network.")
                return False
    except Exception as e:
        logger.warning(f"Duty loop NOT started, database unreadable: {e}")
        return False

    _duty_state.update({"running": True, "session_id": session_id,
                        "modules": modules, "last_error": None,
                        "consecutive_failures": 0})
    _duty_stop.clear()

    def loop():
        interval = _tick_seconds()
        logger.info("Duty loop started, checking the schedule every %ss. "
                    "Regular wake-ups at local hours %s; emergencies run as "
                    "soon as they are seen.", interval,
                    ", ".join(str(h) for h in _wake_hours()))
        while not _duty_stop.is_set():
            try:
                # THE POLL, NOT A WAKE-UP. _tick_once decides whether this
                # minute is a wake-up at all; for most polls it is not, and no
                # row is written. See _tick_once for the measurement that made
                # this necessary.
                result = _tick_once(session_id, modules=modules)
                _tick_once_state(result)
                if result.get("outcome") in ("not_due", "busy"):
                    # "busy" (LOOP-12) means run-now already holds the tick,
                    # so this poll did nothing and is not counted either.
                    # NOT A TICK AND NOT A FAILURE. Ticks counts wake-ups;
                    # polls counts polls. A page that showed a wake-up a
                    # minute would be the old defect drawn on the screen.
                    _duty_stop.wait(interval)
                    continue
                _duty_state["last_tick"] = _sql_ts(_now())
                _duty_state["last_result"] = result
                _duty_state["ticks"] += 1
                _duty_state["last_error"] = None
                _duty_state["consecutive_failures"] = 0
                if result.get("outcome") in ("reported", "investigated"):
                    logger.info("Duty loop: %s a %s report (report #%s).",
                                result["outcome"],
                                result.get("kind") or "?", result.get("report_id"))
                elif result.get("outcome") == "budget":
                    logger.info("Duty loop: refused by a budget at wake-up "
                                "time; it examined nothing.")
            except Exception as e:
                _duty_state["tick_started_at"] = None
                _duty_state["consecutive_failures"] += 1
                _duty_state["last_error"] = f"{type(e).__name__}: {e}"
                logger.error(f"Duty tick failed: {e}", exc_info=True)
            _duty_stop.wait(interval)
        _duty_state["running"] = False
        logger.info("Duty loop stopped.")

    _duty_thread = threading.Thread(target=loop, name="duty-loop", daemon=True)
    _duty_thread.start()
    return True


def stop():
    _duty_stop.set()


def status() -> dict:
    """
    The contract core/sensor_health reads: blind, blind_reason, running,
    last_error.

    WHAT `blind` MEANS HERE, and it is a narrower claim than the watcher's. The
    duty loop is blind when its SPEND CANNOT BE MEASURED, because then the
    ceiling that is supposed to stop a runaway is not stopping anything. It is
    NOT blind merely for being switched off (that is in blind_reason too, with
    the distinction said out loud) — being off is a configuration choice, and
    the loop is the one component in this app whose absence is visible on a
    page rather than in an absence of findings.
    """
    last = _duty_state.get("last_result") or {}
    out = {
        "running": _duty_state["running"],
        "role": "duty_loop",
        "ticks": _duty_state["ticks"],
        "last_tick": _duty_state["last_tick"],
        "blind": False,
    }

    # THE POLLS THAT WERE NOT WAKE-UPS. With the schedule gate in place most
    # minutes are a poll and nothing more, and a reader must be able to tell
    # "the schedule is being watched" from "the loop is dead" — otherwise the
    # fix for a loop that ran too often reads as a loop that stopped. polls
    # counts every look; ticks counts only the ones that woke.
    out["polls"] = _duty_state.get("polls", 0)
    out["last_poll"] = _duty_state.get("last_poll")
    if _duty_state.get("last_skip"):
        out["last_skip"] = _duty_state["last_skip"]
        out["last_skip_at"] = _duty_state.get("last_skip_at")

    # AN IN-FLIGHT TICK IS A THIRD STATE, and the page has to be able to say
    # it. Without this, a two-minute investigation was indistinguishable from a
    # stopped loop on the Agents tab — the exact confusion this whole programme
    # exists to remove. `busy_since` is the honest name: it says when the
    # current tick began and nothing about how long it will take.
    if _duty_state.get("tick_started_at"):
        out["busy_since"] = _duty_state["tick_started_at"]
        out["busy"] = True

    if _duty_state["consecutive_failures"]:
        out["consecutive_failures"] = _duty_state["consecutive_failures"]
    if _duty_state["last_error"]:
        out["last_error"] = _duty_state["last_error"]

    budget = budget_state()
    out["budget"] = budget
    out["spend_measured"] = bool(budget.get("tokens_last_24h") is not None)

    if not _enabled():
        out["blind"] = True
        out["blind_reason"] = (
            "The duty loop is switched off in config.json. NOTHING IS "
            "INVESTIGATING ANYTHING, and the Agents page will stay as empty "
            "as it is. That is a configuration choice rather than a network "
            "with nothing in it.")
    elif not _duty_state["running"]:
        out["blind"] = True
        out["blind_reason"] = (
            "The duty loop is not running, so no incident is being worked and "
            "no regular report is being written. The watcher is still "
            "aggregating findings; nothing is investigating them.")
    elif not budget.get("available", True):
        out["blind"] = True
        out["blind_reason"] = (
            f"The spend ledger cannot be read, so the daily ceiling is not "
            f"bounded by anything this loop can see: "
            f"{budget.get('note') or 'the duty_run table is missing'}")
    elif last.get("outcome") == "error":
        out["blind"] = False
        out["last_error"] = (f"The last tick failed: "
                             f"{last.get('reason') or 'no reason recorded'}")
    elif last:
        out["last_result"] = {
            "outcome": last.get("outcome"),
            "report_id": last.get("report_id"),
            "kind": last.get("kind"),
            "verdict": last.get("verdict"),
        }

    out["schedule"] = _next_regular_moment()
    return out


# READING THE RECORD

def query_reports(kind: str = None, limit: int = 50,
                  report_id: int = None, include_dismissed: bool = False,
                  only_dismissed: bool = False,
                  session_id: str = None) -> list:
    """
    The reports, newest first, for the Agents page and for the model.

    `tokens_spent` and `model_calls` travel with every row: a reader looking at
    a page of the agent's work should be able to see what it cost without
    asking a second question, and the number is on the row it belongs to
    rather than summed into a headline.

    DISMISSED REPORTS ARE HIDDEN BY DEFAULT AND THE FILTER IS AN EXPLICIT
    ARGUMENT, added 2026-09-25 with the feature. Three readings of the same
    list, each its own parameter, because they are three different questions:
    the page shows undismissed ones (`include_dismissed=False`), the "show
    dismissed" toggle passes `only_dismissed=True` so a person can find and
    restore one, and a caller asking for ONE report by id gets it regardless --
    a dismissal hides a row from a list, and it must never make a report that
    exists unreadable, or the model could be asked about report 12 and answer
    that it does not exist.

    The rows carry dismissed_at/dismissed_by/dismissal_note either way, so the
    page can render the fact without a second query.

    `session_id` limits a list to one run. A list never shows a report past
    the one-week keep window, even before expire_old_reports has run.
    """
    where, params = [], []
    if report_id is not None:
        where.append("id = ?")
        params.append(int(report_id))
    else:
        if kind:
            where.append("kind = ?")
            params.append(kind)
        if session_id:
            where.append("session_id = ?")
            params.append(session_id)
        where.append("created_at >= ?")
        params.append(_report_cutoff())
        if only_dismissed:
            where.append("dismissed_at IS NOT NULL")
        elif not include_dismissed:
            where.append("dismissed_at IS NULL")

    sql = "SELECT * FROM duty_report"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(int(limit or 50), 200)))

    with me._get_readonly_conn() as conn:
        if not _table_ready(conn, "duty_report"):
            return []
        # A database from before this feature has no dismissal columns. The
        # filter is dropped rather than faked: every row in such a database
        # genuinely has never been dismissed, so the unfiltered list IS the
        # undismissed list, and `only_dismissed` correctly returns nothing. The
        # alternative -- letting the WHERE reach SQLite -- is an
        # OperationalError on every page load for an operator who has not
        # restarted since the upgrade.
        cols = {r[1] for r in conn.execute(
            "PRAGMA table_info(duty_report)").fetchall()}
        if "dismissed_at" not in cols:
            if only_dismissed:
                return []
            where = [w for w in where if "dismissed_at" not in w]
            sql = "SELECT * FROM duty_report"
            if where:
                sql += " WHERE " + " AND ".join(where)
            sql += " ORDER BY id DESC LIMIT ?"
        rows = me._rows_to_dicts(conn.execute(sql, params).fetchall())

    for row in rows:
        try:
            row["coverage"] = json.loads(row.pop("coverage_json") or "null")
        except (TypeError, ValueError):
            row["coverage"] = None
    return rows


def query_runs(limit: int = 50, outcome: str = None) -> list:
    """The tick record, newest first. Every tick, including the ones that
    did nothing: that is the point of the table."""
    where, params = [], []
    if outcome:
        where.append("outcome = ?")
        params.append(outcome)
    sql = "SELECT * FROM duty_run"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(int(limit or 50), 200)))

    with me._get_readonly_conn() as conn:
        if not _table_ready(conn, "duty_run"):
            return []
        rows = me._rows_to_dicts(conn.execute(sql, params).fetchall())

    for row in rows:
        try:
            row["coverage"] = json.loads(row.pop("coverage_json") or "null")
        except (TypeError, ValueError):
            row["coverage"] = None
        # THE TOOLS THE TURN CALLED, decoded for the page. None stays None:
        # "this tick never reached a model" and "the turn called nothing" are
        # different facts about a wake and the reader is entitled to both.
        raw_tools = row.pop("tools_json", None)
        try:
            row["tools"] = json.loads(raw_tools) if raw_tools else None
        except (TypeError, ValueError):
            row["tools"] = None
    return rows


def dismiss_reports(report_ids: list, dismissed_by: str = "user",
                    note: str = None, all_open: bool = False) -> dict:
    """
    STOP SHOWING THESE REPORTS. Delete nothing, change no verdict, touch no
    baseline.

    The owner's instruction, 2026-09-25: "we need a dismiss button plus check
    box for agent reports, also a dismiss all ... those however won't delete
    the agent entries from the database and baseline if it was initially
    writing in those."

    EVERY CLAUSE OF THAT IS HONOURED LITERALLY AND THIS IS HOW:

      * nothing is DELETEd -- `dismissed_at` is set and the row stays;
      * the report's own words (verdict, evidence, saw, body, coverage) are
        never touched, so a dismissal cannot be mistaken for a disagreement
        with what the report said;
      * no baseline is touched. The duty loop writes predictions and files
        action requests, and NEITHER is a baseline; a report is not an input to
        behavioral_baseline in any direction. There is no code path from here
        to memory_engine.update_behavioral_baseline and the test asserts it.

    WHAT A DISMISSAL IS FOR, and the honest version is not flattering to the
    reader: a report list grows one row per wake-up forever, and after a month
    the four-a-day regular reports are mostly "nothing needed doing today". The
    dismiss button is how a person says they have read that and do not need to
    see it again. It is a FILING decision about the page.

    WHAT IT IS NOT: it is not a suppression, it does not stop the agent
    investigating the same subject again, and it does not change what the
    sensors record. A future incident about the same entity raises a new
    finding and a new report, which is why this does not need to ask the
    suppression gate's permission -- it silences nothing about the machine, it
    hides one row a person has already read.

    IT IS JOURNALLED. Each dismissal writes an integrity entry naming the
    report, who dismissed it and why, so "who shortened my Reports list" has an
    answer that does not depend on the flag columns surviving. That is the one
    property that makes hiding rows safe: the hiding is itself recorded.

    `all_open=True` dismisses every report that is not already dismissed, and
    it RETURNS THE COUNT rather than a bare success. "Dismiss all" on a list
    somebody has filtered can hide more than they saw, and the number is how
    they find out.
    """
    from core import integrity

    out = {"dismissed": 0, "skipped": [], "report_ids": [], "note": note}
    now = _sql_ts(_now())

    with me._get_conn() as conn:
        if not _table_ready(conn, "duty_report"):
            raise BadDutyInput("the duty_report table does not exist.")

        cols = {r[1] for r in conn.execute(
            "PRAGMA table_info(duty_report)").fetchall()}
        if "dismissed_at" not in cols:
            raise BadDutyInput(
                "the duty_report table has no dismissed_at column, so this "
                "database predates the dismissal feature. Run the migrations "
                "(they are the same boot path the app uses) and try again.")

        if all_open:
            rows = conn.execute(
                "SELECT id FROM duty_report WHERE dismissed_at IS NULL"
            ).fetchall()
            ids = [r[0] for r in rows]
        else:
            ids = [int(i) for i in (report_ids or [])]

        if not ids:
            out["reason"] = ("nothing to dismiss: no report was named and no "
                             "report is currently undismissed.")
            return out

        for rid in ids:
            row = conn.execute(
                "SELECT id, dismissed_at FROM duty_report WHERE id = ?",
                (rid,)).fetchone()
            if row is None:
                out["skipped"].append({"report_id": rid,
                                       "reason": "no report with that id"})
                continue
            if row["dismissed_at"]:
                # ALREADY DISMISSED IS NOT RE-DISMISSED. Overwriting would move
                # the original timestamp and destroy the only record of when
                # the person actually decided, which is the fact worth keeping.
                out["skipped"].append({"report_id": rid,
                                       "reason": "already dismissed"})
                continue
            conn.execute(
                "UPDATE duty_report SET dismissed_at = ?, dismissed_by = ?, "
                "dismissal_note = ? WHERE id = ? AND dismissed_at IS NULL",
                (now, dismissed_by, note, rid))
            # The transition, journalled inside the same transaction as the
            # flag. A flag with no journal entry is a row that changed with
            # nothing attesting to who changed it.
            integrity.record(
                "report_dismissed", table_name="duty_report", row_ref=rid,
                payload={"dismissed_at": now, "dismissed_by": dismissed_by,
                         "note": note, "all_open": bool(all_open)},
                conn=conn)
            out["dismissed"] += 1
            out["report_ids"].append(rid)

    logger.info("Duty reports dismissed: %s (by=%s, all_open=%s, skipped=%s)",
                out["dismissed"], dismissed_by, all_open, len(out["skipped"]))
    return out


def restore_report(report_id: int, by: str = "user",
                   note: str = None) -> dict:
    """
    UN-DISMISS: put one report back on the list.

    THE UNDO IS FREE and deliberately ungated, the same rule the rest of this
    app follows (revert_suppression, undismiss_entity): the direction that
    shows a person MORE information never asks permission. Without it, a
    mis-click on "dismiss all" would be permanent, which is how a page's
    convenience turns into a small act of destruction.

    The flag is cleared, so the row reads as never dismissed rather than as
    dismissed-then-restored. That is deliberate and it is the ONE case where
    this differs from the withdrawal pattern the rest of the tree uses for
    baselines: what is being undone is a DISPLAY decision about a row, not a
    belief about the machine, and a restored report should read like any other
    report. The restoration still leaves a journal entry, so "it was dismissed
    for an hour on Tuesday" is answerable.
    """
    from core import integrity

    with me._get_conn() as conn:
        if not _table_ready(conn, "duty_report"):
            raise BadDutyInput("the duty_report table does not exist.")
        row = conn.execute(
            "SELECT id, dismissed_at FROM duty_report WHERE id = ?",
            (int(report_id),)).fetchone()
        if row is None:
            return {"restored": False, "reason": f"no report with id "
                                                 f"{report_id}"}
        if not row["dismissed_at"]:
            return {"restored": False, "reason": "that report was not "
                                                 "dismissed"}
        previous = row["dismissed_at"]
        conn.execute(
            "UPDATE duty_report SET dismissed_at = NULL, dismissed_by = NULL, "
            "dismissal_note = NULL WHERE id = ?", (int(report_id),))
        integrity.record(
            "report_dismissed", table_name="duty_report", row_ref=int(report_id),
            payload={"restored": True, "was_dismissed_at": previous,
                     "by": by, "note": note},
            conn=conn)
    logger.info("Duty report #%s restored (by=%s).", report_id, by)
    return {"restored": True, "report_id": int(report_id),
            "was_dismissed_at": previous}


def summary() -> dict:
    """
    Counts for the Agents page. Kept apart, never summed.

    investigated / reported / budget / idle / error are five different facts
    about five different things, and "3 runs" that adds a refusal to quiet and
    a real investigation is the reading this whole programme is organised
    against.
    """
    with me._get_readonly_conn() as conn:
        if not _table_ready(conn, "duty_report") or \
                not _table_ready(conn, "duty_run"):
            return {"available": False,
                    "note": ("the duty tables do not exist yet, so nothing "
                             "has been investigated and nothing has been "
                             "recorded. This is not zero activity.")}
        reports = conn.execute("SELECT COUNT(*) FROM duty_report").fetchone()[0]
        by_kind = {r["kind"]: r["n"] for r in conn.execute(
            "SELECT kind, COUNT(*) n FROM duty_report GROUP BY kind")}
        # HOW MANY ARE HIDDEN, 2026-09-25. Reported rather than implied: a
        # Reports list that is shorter than the reports that exist is exactly
        # the shape this project has a rule against, and the count is the one
        # number that makes the page's own filter visible. Zero on a database
        # from before the feature, which is true -- none of those rows has ever
        # been dismissed.
        cols = {r[1] for r in conn.execute(
            "PRAGMA table_info(duty_report)").fetchall()}
        dismissed = (conn.execute(
            "SELECT COUNT(*) FROM duty_report WHERE dismissed_at IS NOT NULL"
        ).fetchone()[0] if "dismissed_at" in cols else 0)
        runs = conn.execute("SELECT COUNT(*) FROM duty_run").fetchone()[0]
        by_outcome = {r["outcome"]: r["n"] for r in conn.execute(
            "SELECT outcome, COUNT(*) n FROM duty_run GROUP BY outcome")}
        last_report = conn.execute(
            "SELECT * FROM duty_report ORDER BY id DESC LIMIT 1").fetchone()
        last_run = conn.execute(
            "SELECT * FROM duty_run ORDER BY id DESC LIMIT 1").fetchone()

    spend = spend_in_window(24)
    return {
        "available": True,
        "reports": reports,
        "dismissed_reports": dismissed,
        "reports_incident": by_kind.get("incident", 0),
        "reports_regular": by_kind.get("regular", 0),
        "runs": runs,
        "runs_investigated": by_outcome.get("investigated", 0),
        "runs_reported": by_outcome.get("reported", 0),
        "runs_budget": by_outcome.get("budget", 0),
        "runs_idle": by_outcome.get("idle", 0),
        "runs_error": by_outcome.get("error", 0),
        "tokens_last_24h": spend.get("spent"),
        "ran_work_last_24h": spend.get("ran_work"),
        "spend_is_estimated": bool(spend.get("estimated_rows")),
        "last_report": dict(last_report) if last_report else None,
        "last_run": (json.loads(json.dumps(dict(last_run), default=str))
                     if last_run else None),
        "budget": budget_state(),
        "how_to_read_this": (
            "A report is what the agent left behind after looking. A run is "
            "one time it woke, and MOST RUNS DO NOTHING ON PURPOSE: `idle` "
            "means it looked for work and found none, `budget` means a limit "
            "stopped it before it examined anything. Those four are never "
            "added together. An empty page with a running loop is a quiet "
            "machine; an empty page with no runs is a loop that is not "
            "running, and the status line above says which."),
    }
