"""
core/intervals.py
AgentalSec V2, how regularly does one thing contact another?

WHY THIS EXISTS, 2026-08-29
Retention forced the question. `packets` is 98.7% of the database and grows
about 100 MB a day, so it has to be pruned. But the moment raw packets go, so
does the only place the SPACING between contacts was ever recorded.

Reading the real baselines showed the gap plainly: the model happily writes a
`beacon_destinations` key naming WHO a device talks to, and every one of those
rows had value_mean, value_stddev, value_min and value_max sitting empty. The
columns to hold "every 6 hours, for weeks" already existed. Nothing filled
them.

So: measure it while the packets are still here, store the summary on the
baseline, and only then prune. Never the other way round.

WHAT A "CONTACT" IS, AND WHY IT IS NOT A PACKET
This is the part that makes the number mean anything.

One TLS session is hundreds of packets a few milliseconds apart. Measuring
gaps between raw packets would report an average interval of about 4
milliseconds for everything on the network, which is true and completely
useless.

So packets are collapsed into CONTACTS first: a run of packets with no quiet
period longer than BURST_GAP_SECONDS counts as one contact. The intervals we
measure are between contacts, which is the thing a human means by "it phones
home every six hours".

BURST_GAP_SECONDS is 60. A gap under a minute is almost certainly the same
conversation continuing; a gap over a minute is a new one. It is a judgement
call, not a discovered constant, and it is a preference so it can be argued
with later.

WHAT REGULARITY MEANS HERE
The useful signal is not the interval, it is how CONSISTENT the interval is.
A laptop browsing contacts a CDN at wildly uneven gaps. Malware on a timer
does not.

So we report the coefficient of variation: stddev divided by mean.

    cv near 0.0    metronomic. Same gap every time. This is what a beacon
                   looks like, and it is also what NTP, a software updater
                   and a keepalive look like. REGULAR IS NOT MALICIOUS.
    cv above ~0.5  human-driven or event-driven traffic.

This module does not decide anything. It measures, and the model reads the
measurement alongside everything else it knows. Handing a number a verdict it
did not earn is how a tool starts lying confidently.

HONEST LIMITS
  * Needs MIN_CONTACTS samples before it will report at all. Three contacts
    can look perfectly regular by luck.
  * Only sees what this sensor saw. A host-position sensor cannot observe two
    other devices talking to each other, so absence here is not absence on
    the network. See SENSOR_PLACEMENT.
  * Once packets are pruned, this can only be recomputed for the window that
    still exists. That is the whole reason it is written to the baseline.
  * A beacon slower than the retention window cannot be measured at all, and
    will not appear here as anything, not even as a low-confidence guess.
  * NOR CAN ANYTHING SLOWER THAN ONE CAPTURE SESSION. This tool runs when
    somebody starts it, so the record is a set of windows with darkness in
    between, and gaps spanning that darkness are discarded rather than
    guessed at. See _gaps_within_sessions, it is the most important
    function here and it exists because the first version of this file
    measured the operator's uptime and reported it as network behaviour.
"""

import logging
import math
import sqlite3
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# A quiet gap longer than this starts a new contact. See the header.
BURST_GAP_SECONDS = 60

# Below this many contacts we report nothing rather than a shaky number.
MIN_CONTACTS = 6

# Destinations noisier than this are not worth storing a "regularity" for.
# Local discovery chatter (mDNS, SSDP) is regular and means nothing.
IGNORED_PREFIXES = ("224.", "239.", "255.255.255.255", "ff02:")


def _parse(ts):
    """
    SQLite timestamps arrive as strings in more than one shape.

    A NAIVE STRING FROM THIS DATABASE IS UTC, NOT LOCAL. 2026-08-30.
    packets.captured_at is never written explicitly, save_packet omits the
    column and the schema default CURRENT_TIMESTAMP fills it, and SQLite's
    CURRENT_TIMESTAMP is UTC, formatted with no zone marker at all.

    This used to end in datetime.strptime(s, fmt).timestamp(). strptime
    returns a naive datetime and naive .timestamp() applies the MACHINE's
    local zone, so every packet time came out 7 hours off here.

    It did not change any published number, and that is worth saying plainly
    rather than pretending the fix mattered more than it did: a constant
    offset cancels when you subtract two timestamps, and gaps are all this
    module computes. Every interval and every cv was correct.

    It is fixed anyway, for three reasons that are not cosmetic:

      1. DST. The offset is not actually constant, it is whatever was in
         force on that date. A gap spanning the November change would gain or
         lose an hour.
      2. `since` is compared as a STRING against these rows elsewhere. A
         caller passing a local-time cutoff would silently select the wrong
         7 hours of history.
      3. RETENTION. The prune being written next compares captured_at against
         a cutoff. If that cutoff is built from datetime.now() rather than
         UTC, it deletes seven hours too much, permanently, and the mistake
         looks like nothing at all. Getting the meaning of these strings
         settled BEFORE that code exists is the whole point of fixing it now.

    Found by the model reading its own source, which reported it as low
    severity and was right about the impact and short by two of the reasons.
    """
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    s = str(ts).strip().replace("T", " ")
    if s.endswith("Z"):
        s = s[:-1]
    if "+" in s[10:]:
        s = s[:10] + s[10:].split("+")[0]
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            # tzinfo=utc, because that is what the writer meant.
            return datetime.strptime(s, fmt).replace(
                tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def _collapse(rows):
    """
    (timestamp, session_id) pairs -> the start of each distinct contact,
    tagged with the capture session it happened in.
    """
    contacts = []
    last = None
    last_sid = None
    for t, sid in rows:
        if last is None or sid != last_sid or (t - last) > BURST_GAP_SECONDS:
            contacts.append((t, sid))
        last, last_sid = t, sid
    return contacts


def _gaps_within_sessions(contacts):
    """
    Gaps between consecutive contacts, but ONLY inside one capture session.

    THIS IS THE CORRECTION OF 2026-08-29, AND IT MATTERS MORE THAN THE REST
    OF THE FILE. The first version measured every gap between consecutive
    contacts. On synthetic data it worked perfectly. On the real database
    every single entity came back with a coefficient of variation between
    1.1 and 5.8, when a beacon should be near 0 and even human browsing sat
    at 0.6 in the test.

    Nothing on the network was that erratic. The tool was.

    AgentalSec is not a service; it runs when somebody starts it and stops
    when they stop it. So the packet record is a handful of capture windows
    separated by hours of nothing. Measuring straight through those windows
    reported gaps of a few minutes, a few minutes, a few minutes, then ten
    hours, and the ten hours was the laptop being closed, not the device
    going quiet. The dominant signal in the numbers was OUR OWN uptime.

    A measurement that mostly reflects the observer is worse than no
    measurement, because it looks like data. So gaps that cross a capture
    session are dropped rather than corrected: there is no honest way to
    know what happened while nothing was watching, and inventing a value for
    it would be the exact failure this codebase keeps writing comments about.

    THE LIMIT THIS LEAVES, STATED PLAINLY: nothing slower than a single
    capture session can be measured at all. Run the app for two hours and no
    six-hour beacon will ever show up here, not as a weak signal, not as a
    guess, not at all.

    SO THE THING TO TELL THE USER, AND IT IS THE ONLY FIX THERE IS:
    if you want an accurate reading of your network, please leave the app
    running. Longer runs are what let it see traffic that is slow in transit
    or on a schedule. No amount of arithmetic substitutes for having watched,
    and nothing in this file will pretend otherwise.
    """
    gaps = []
    for (t1, s1), (t2, s2) in zip(contacts, contacts[1:]):
        if s1 == s2:
            gaps.append(t2 - t1)
    return gaps


def _stats(gaps):
    n = len(gaps)
    mean = sum(gaps) / n
    if n > 1:
        var = sum((g - mean) ** 2 for g in gaps) / (n - 1)
        sd = math.sqrt(var)
    else:
        sd = 0.0
    return {
        "mean_seconds":   round(mean, 1),
        "stddev_seconds": round(sd, 1),
        "min_seconds":    round(min(gaps), 1),
        "max_seconds":    round(max(gaps), 1),
        "cv":             round(sd / mean, 3) if mean else None,
        "intervals":      n,
    }


def contact_intervals(conn, entity_value, since=None, limit_dests=12):
    """
    For one IP, how regularly does it contact each destination?

    Returns {"destinations": [...], "most_regular": {...} or None}, sorted so
    the steadiest destination comes first. Never raises: it runs inside the
    rollup, and a measurement that can stop a rollup is a measurement that
    gets deleted the first time it misbehaves.
    """
    out = {"destinations": [], "most_regular": None}
    try:
        where = "src_ip = ?"
        params = [entity_value]
        if since:
            where += " AND captured_at >= ?"
            params.append(since)

        pairs = conn.execute(
            f"SELECT dst_ip, COUNT(*) n FROM packets WHERE {where} "
            f"AND dst_ip IS NOT NULL GROUP BY dst_ip "
            f"ORDER BY n DESC LIMIT ?", params + [limit_dests]).fetchall()

        for dst, _n in pairs:
            if not dst or str(dst).startswith(IGNORED_PREFIXES):
                continue
            rows = conn.execute(
                f"SELECT captured_at, session_id FROM packets "
                f"WHERE {where} AND dst_ip = ? "
                f"ORDER BY session_id, captured_at", params + [dst]).fetchall()

            parsed = [(_parse(r[0]), r[1]) for r in rows]
            parsed = [(t, s) for t, s in parsed if t is not None]
            if len(parsed) < 2:
                continue
            contacts = _collapse(parsed)
            if len(contacts) < MIN_CONTACTS:
                continue

            gaps = _gaps_within_sessions(contacts)
            if len(gaps) < MIN_CONTACTS - 1:
                # Plenty of contacts, but spread thinly across many short
                # capture windows. Not enough of them sit inside one window
                # to say anything about spacing.
                continue

            d = _stats(gaps)
            d["destination"] = str(dst)
            d["contacts"] = len(contacts)
            d["packets"] = len(parsed)
            d["sessions"] = len({s for _, s in contacts})
            d["gaps_used"] = len(gaps)
            out["destinations"].append(d)

        # Steadiest first. cv is the signal; ties break on more evidence.
        out["destinations"].sort(
            key=lambda d: (d["cv"] if d["cv"] is not None else 9e9,
                           -d["contacts"]))
        if out["destinations"]:
            out["most_regular"] = out["destinations"][0]
    except sqlite3.Error as e:
        logger.warning(f"intervals: could not measure {entity_value}: {e}")
    return out


def describe(most_regular) -> str:
    """One human-readable line. Deliberately states no verdict."""
    if not most_regular:
        return "no destination contacted often enough to measure"
    m = most_regular["mean_seconds"]
    unit, val = ("hours", m / 3600) if m >= 3600 else \
                ("minutes", m / 60) if m >= 60 else ("seconds", m)
    return (f"{most_regular['destination']}: {most_regular['contacts']} "
            f"contacts, every {val:.1f} {unit} on average "
            f"(cv {most_regular['cv']}). Regular timing is common in updaters, "
            f"NTP and keepalives as well as beacons; this is a measurement, "
            f"not a finding.")
