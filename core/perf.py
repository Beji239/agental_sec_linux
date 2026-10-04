# core/perf.py
# AgentalSec V2, the performance axis. How much each device talks, and how
# that compares to how much it usually talks.
#
# PREREQUISITES: standard library plus core.memory_engine.
# Look at it from the command line with:
#   python scripts/show_perf.py
#
#
# WHY THIS EXISTS
#
# Everything else in this app is security shaped. It asks whether something is
# dangerous. Nothing has ever asked whether something is BUSY, and the two
# questions cross in useful places: a device whose traffic tripled the week
# after a firmware update is not a finding, it is not an alert, and it is the
# kind of thing a person wants to know. The model has had no way to say it.
#
#
# WHAT IT ACTUALLY MEASURES, AND WHAT IT DELIBERATELY DOES NOT
#
# Measured, from data already stored:
#   bytes in and out, per device, per hour
#   packets in and out
#   how many distinct peers it talked to
#   DNS queries and DNS failures, when a resolver is importing
#   whether it answered presence sweeps in that hour
#
# NOT measured, and named as gaps rather than shown as zeroes:
#   TCP retransmissions. Detecting one needs sequence numbers, and the sniffer
#     does not store them. It stores flags. Adding them is a change to
#     packet_sniffer and a wider packets table, which is already 98% of the
#     database.
#   Gateway round trip time. Nothing in this app measures latency to anything.
#     It needs an active probe on a timer, which is a new collector.
#
# A zero in either of those would read as a perfect network. This is the same
# rule the rest of the project keeps relearning: no match and could not look
# are different sentences.
#
#
# WHAT COVERAGE DOES AND DOES NOT PROVE, found while testing this file
#
# coverage_seconds is a property of the HOUR, not of the device. It is
# measured once per hour across every packet stored, from any source, so one
# chatty device marks that hour as covered for every device in it.
#
# That is the right answer to the question it actually asks, which is "was the
# sniffer running". It is NOT an answer to "could this sensor see that
# device", and the two are easy to confuse while reading the page. A
# host-position sensor cannot observe two other devices talking to each other
# however long it runs, so a device on a switched network can sit at zero
# bytes through a fully covered hour and be perfectly busy. Green here means
# the capture was up and this device was quiet FROM WHERE WE STAND.
#
# Answering it per device would mean asking whether this sensor's vantage can
# reach each address, which is the blind spot register's job and not this
# one's. SENSOR_PLACEMENT.md has the long version. Written down here because
# a wall of green reads as a completeness claim and it is not one.
#
#
# COVERAGE IS THE COLUMN THAT MAKES THE REST MEAN ANYTHING
#
# An hour with zero bytes and an hour with four million look like a quiet
# device and a busy one, right up until you notice the quiet hour had forty
# seconds of capture in it. So every bucket records how long the capture was
# actually running inside that hour, and a bucket under the floor is painted
# GREY rather than counted. Grey is a third colour, and it means the same
# thing it means everywhere else in this app: we could not look.
#
#
# WHY IT IS STORED RATHER THAN COMPUTED WHEN THE PAGE LOADS
#
# The same argument core/intervals.py makes. Retention prunes packets, and
# when they go so does the only place any of this was ever recorded. Measure
# it while the packets are here, keep the summary, then prune. A page that
# recomputed from packets would also be scanning the largest table in the
# database on every load, and would show a device's history shrinking every
# time retention ran, which looks like the device going quiet.
#
#
# WHAT "UNUSUAL" MEANS HERE
#
# Compared against THAT DEVICE'S OWN history, never against other devices. A
# TV and a workstation have nothing to say about each other. Under
# perf_min_history_hours of its own history, the answer is "not enough history
# to know", which is its own state and is not the same as normal.

import bisect
import ipaddress
import logging
from datetime import datetime, timedelta, timezone

from core import memory_engine as me

logger = logging.getLogger(__name__)

DEFAULT_MIN_COVERAGE_SECONDS = 600     # 10 minutes of a 60 minute bucket
DEFAULT_MIN_HISTORY_HOURS = 12

# How far from its own median counts as unusual. A device that normally moves
# 1 MB an hour and moves 3 MB is interesting; one that moves 1.1 MB is not.
HIGH_MULTIPLIER = 3.0
LOW_DIVISOR = 3.0

# A device that said nothing for this long keeps its row off the page. Ported
# from the Windows tree 2026-09-21 with the grid: it exists so addresses from
# months ago do not pile up as empty rows once the grid stops dropping hours.
SILENT_DEVICE_DAYS = 7

# What this cannot measure, said once, in one place, so the page and the model
# read the same sentence and it cannot drift into two different claims.
NOT_MEASURED = [
    {
        "name": "TCP retransmissions",
        "why": ("detecting a retransmit needs sequence numbers and the "
                "sniffer stores flags, not sequence numbers"),
        "what_it_would_take": ("a change to tools/packet_sniffer.py and two "
                               "more columns on packets, which is already "
                               "most of the database"),
    },
    {
        "name": "Gateway round trip time",
        "why": "nothing in this app measures latency to anything",
        "what_it_would_take": ("a small active probe on a timer, which is a "
                               "new collector with its own sensor row"),
    },
]


# WHAT COUNTS AS A DEVICE ON THIS PAGE. 2026-09-15.
#
# THE BUG THIS FIXES. build_hour groups packets by src_ip and again by dst_ip
# with no filter, so every address that ever appeared on either side of a
# packet got a row and a baseline. The page listed the owner's TV and the owner's Linux
# box next to 77.111.246.43, 11.22.36.63, 11.22.33.53, 224.0.0.251 and
# 239.255.255.250. Those are destinations and multicast groups, not devices.
#
# Worse than untidy. "Usual for this device" is a median of that entity's own
# history, and a remote destination's history is a measurement of what THIS
# network chose to send it. Calling that the destination's normal is measuring
# ourselves and putting somebody else's name on it.
#
# CLASSIFYING AT READ TIME, NOT AT WRITE TIME, ON PURPOSE. Nothing is deleted
# and nothing already recorded changes meaning. The rows stay, the page shows
# devices, and the counts of what was set aside are reported rather than
# silently dropped. Reversible, no migration, and it cannot corrupt a bucket
# that was already correct.
#
# The rule is the address itself, not the scope column, so it works the same on
# rows written before scope existed.
#
# WHAT WAS STILL WRONG, ported 2026-09-21 from the Windows tree's 2026-09-18
# fix. The rule above was "is_private, so it is a device", and measured on
# this host it put the SUBNET BROADCAST and an address in 0.0.0.0/8 in the
# list with names, byte totals and baselines of their own, because
# addr.is_private answers yes to 0.0.0.0/8, 100.64/10, 192.0.0.0/24,
# 192.0.2.0/24 and the rest of the reserved blocks:
#
#   the subnet broadcast of a /24 home network. Every device on the network
#               sends to it, so its byte total is everybody's traffic wearing
#               one name, and calling that ITS normal is the same mistake the
#               multicast rule above already fixed, one case short.
#   0.0.0.0/8   "this network", RFC 1122. Not a host anyone owns.
#
# So the rule is now the other way round: a device is an address in one of the
# three RFC1918 blocks, or IPv6 unique local, and nothing else. Everything the
# old rule waved through lands in `reserved` with a reason beside it.
_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_ULA = ipaddress.ip_network("fc00::/7")

# Blocks that are neither a host on this network nor somewhere we talked to.
# Listed out rather than left to addr.is_private, because that property has
# changed between Python versions: 100.64.0.0/10 answers differently on 3.12
# and 3.13, and a classification that moves when the interpreter is upgraded
# is not a classification.
_RESERVED = (
    ipaddress.ip_network("0.0.0.0/8"),          # "this network", RFC 1122
    ipaddress.ip_network("100.64.0.0/10"),      # carrier grade NAT
    ipaddress.ip_network("192.0.0.0/24"),       # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),       # documentation, TEST-NET-1
    ipaddress.ip_network("198.18.0.0/15"),      # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),    # documentation, TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # documentation, TEST-NET-3
    ipaddress.ip_network("240.0.0.0/4"),        # reserved, never allocated
)


def local_broadcasts(conn=None) -> set:
    """
    The broadcast address of every subnet this app actually sweeps.

    Read from presence_sweep.subnet, because that column is the only place the
    app records what it believes the local network IS. Exact beats the last
    octet guess below: on a /26 the broadcast is x.x.x.63 and no guess would
    ever find it.

    An empty set means we could not look, and classify_entity falls back to the
    guess rather than pretending every address is a host.
    """
    own = conn is None
    ctx = me._get_readonly_conn() if own else None
    conn = ctx.__enter__() if own else conn
    try:
        if not me._table_exists_ro(conn, "presence_sweep"):
            return set()
        out = set()
        # The most recent sweeps rather than DISTINCT over the whole table.
        # presence_sweep grows by a row every tick for as long as the app has
        # been running, and this is on the page load path. Bounded, ordered by
        # the indexed column, and the subnets that matter are the recent ones.
        for row in conn.execute(
                "SELECT subnet FROM presence_sweep WHERE subnet IS NOT NULL "
                "ORDER BY swept_at DESC LIMIT 500").fetchall():
            try:
                net = ipaddress.ip_network(str(row["subnet"]).strip(),
                                           strict=False)
            except ValueError:
                continue
            if net.version == 4 and net.prefixlen < 31:
                out.add(str(net.broadcast_address))
        return out
    except Exception:
        # A classification helper that cannot read must not take the page down
        # with it. An empty set means the guess is used, which is stated.
        return set()
    finally:
        if own and ctx is not None:
            ctx.__exit__(None, None, None)


def classify_entity(value: str, broadcasts: set = None) -> str:
    """
    device      an RFC1918 or IPv6 unique local address, the only kind that
                gets a baseline
    multicast   a group address. Traffic TO it is senders talking, not a device
    broadcast   the all-ones address, the unspecified address, or the broadcast
                address of a subnet this app sweeps
    loopback    this host talking to itself
    link_local  169.254.x, an adapter with no lease. Not a device anyone owns
    reserved    0.0.0.0/8, carrier space, the documentation blocks. Not a host
    remote      a public address. A destination, not something we can baseline
    unknown     could not be parsed, and that is said rather than guessed

    `broadcasts` is the set from local_broadcasts(). Pass it when you have it.
    Without it the fallback is "an RFC1918 address ending in .255", which is
    right on the /24 every home network uses and wrong on a /23. The note on
    the page says so rather than leaving it to be discovered.
    """
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except (ValueError, AttributeError):
        return "unknown"

    if addr.is_loopback:
        return "loopback"
    if addr.is_multicast:
        return "multicast"
    if addr.is_unspecified or str(addr) == "255.255.255.255":
        return "broadcast"
    if broadcasts and str(addr) in broadcasts:
        return "broadcast"
    if addr.is_link_local:
        return "link_local"

    if addr.version == 4 and any(addr in net for net in _RFC1918):
        if not broadcasts and addr.packed[-1] == 255:
            return "broadcast"
        return "device"
    if addr.version == 6 and addr in _ULA:
        return "device"

    if addr.version == 4 and any(addr in net for net in _RESERVED):
        return "reserved"
    if addr.is_private or addr.is_reserved:
        return "reserved"
    return "remote"


# Said once, here, so the page and the model read the same sentence.
NOT_A_DEVICE_NOTE = {
    "remote":     "a public address this network talked to. Its traffic is a measurement of us, not of it, so it has no baseline of its own.",
    "multicast":  "a group address. Packets to it come from many senders at once and it is not a machine that can be busy or quiet.",
    "broadcast":  "a broadcast address. Every device on the network sends to it, so its byte total is everybody's traffic wearing one name.",
    "loopback":   "this host talking to itself.",
    "link_local": "a self-assigned address, an adapter with no lease. Not a device anyone owns or names.",
    "reserved":   "a reserved address block, 0.0.0.0/8 and carrier and documentation space. Not a host on this network, whatever put it on the wire.",
    "unknown":    "the address could not be parsed, so nothing is claimed about it.",
}


def _pref_int(key: str, default: int) -> int:
    try:
        return int(float(me.get_preference(key, str(default))))
    except (TypeError, ValueError):
        return default


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sql_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _sql_ts_iso(dt: datetime) -> str:
    """The SAME INSTANT, in the shape the dns_queries column holds.

    THE HOURLY ROLLUP COULD NOT SEE A SINGLE DNS ROW, and it is a shape
    problem rather than a data one. perf's own columns are written by
    CURRENT_TIMESTAMP, so this file builds its bounds with _sql_ts, which
    emits 'YYYY-MM-DD HH:MM:SS'. The dns_queries column is written by
    tools/dns_monitor and holds an OFFSET-SHAPED ISO string
    ('2026-09-27T07:10:00+00:00'), and the comparison there is TEXT against
    it. 'T' (0x54) sorts after ' ' (0x20), so a DNS row is never LESS than
    the space-shaped upper bound of its own hour and every window selects
    nothing.

    MEASURED on a scratch store, driving this module: one dns row written in
    the store's own shape, the window built as ('2026-09-27 07:00:00',
    '2026-09-27 08:00:00') selected 0 of 1 rows, and the same comparison
    returned `dns_present` False. perf_hourly then wrote NULL for dns_queries
    and dns_failures, which the page and the model read as "no resolver
    importing at all" -- on a machine whose resolver import was actually
    working. This is the section-9 shape defect (the timestamp funnel)
    arriving through a table the funnel does not cover, because the funnel
    is keyed on the QUERY's column and this is a WINDOW built by hand.

    The funnel itself does the conversion, so there is one implementation of
    "what this column holds" rather than a second strftime here that could
    drift from the writers.
    """
    return me._sql_datetime(dt.astimezone(timezone.utc).isoformat(),
                            me.SHAPE_ISO_OFFSET)


def _parse_ts(value):
    if not value:
        return None
    text = str(value).strip().replace("T", " ")
    if text.endswith("Z"):
        text = text[:-1]
    try:
        return datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc)
    except ValueError:
        return None


def _hour_floor(dt: datetime) -> datetime:
    return dt.replace(minute=0, second=0, microsecond=0)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# PORTED FROM THE WINDOWS TREE 2026-09-21, with the reason it was written
# there, because the reason is what makes it necessary rather than tidy.
#
# THE TRAP THIS EXISTS FOR, and it cost an afternoon on Windows. The same hour
# comes out of this module in two spellings: sqlite stores and compares
# '2026-09-18 09:00:00', and memory_engine._rows_to_dicts hands back
# '2026-09-18T09:00:00Z'. Both are correct, both are the same hour, and
# neither matches the other as a string. A grid keyed on one and filled from
# the other lines up perfectly and finds nothing, which looks exactly like a
# device that was silent all day.
#
# So SQL keeps the space spelling, because that is what is in the column, and
# everything in memory is keyed through here.
def _hour_key(value) -> str:
    parsed = _parse_ts(value)
    return _iso(parsed) if parsed else str(value)


def _blank_bucket(hour: str, verdict: str, why: str,
                  coverage: int = None) -> dict:
    """
    A cell for an hour that was NOT measured.

    bytes is None rather than 0, and that is the whole point of the function:
    a zero is a reading and "we could not look" is not one. The page paints a
    None cell grey-striped and a zero cell through the normal baseline test.
    """
    out = {
        "hour_start": hour,
        "bytes": None,
        "packets": None,
        "peers": None,
        "coverage_seconds": coverage,
        "verdict": verdict,
        "why": why,
    }
    return out


def _median_skipping(ordered: list, skip: int = None) -> float:
    """The median of `ordered` with one occurrence left out, by index."""
    if not ordered:
        return 0.0
    if skip is None or skip < 0 or skip >= len(ordered):
        return _median(ordered)
    rest = ordered[:skip] + ordered[skip + 1:]
    return _median(rest)


def _median(values: list) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


# BUILDING THE BUCKETS

def _coverage_seconds(conn, start: str, end: str) -> int:
    """
    How many seconds of this hour the capture was actually running.

    Measured from the stored packets themselves, grouped by capture session,
    because those rows ARE the evidence. An uptime log would answer a
    different question: that the app was running, which is not the same as the
    sniffer having stored anything.

    Same method as core/predictions.capture_coverage. Kept as its own function
    rather than imported because the two have different callers and different
    units, and a shared helper would tempt someone to change the meaning for
    one of them.
    """
    rows = conn.execute("""
        SELECT MIN(captured_at) AS first_seen, MAX(captured_at) AS last_seen
        FROM packets
        WHERE captured_at >= ? AND captured_at < ?
        GROUP BY session_id
    """, (start, end)).fetchall()

    start_dt, end_dt = _parse_ts(start), _parse_ts(end)
    if not rows or not start_dt or not end_dt:
        return 0

    covered = 0.0
    for row in rows:
        first, last = _parse_ts(row["first_seen"]), _parse_ts(row["last_seen"])
        if not first or not last:
            continue
        first = max(first, start_dt)
        last = min(last, end_dt)
        if last > first:
            covered += (last - first).total_seconds()
    return int(min(covered, 3600))


def build_hour(hour_start: datetime, conn=None) -> int:
    """
    Fill one hour's buckets, one row per device seen in it.

    Idempotent: the unique index means a rebuild replaces rather than
    duplicates, so running it twice over the same hour is safe and a rerun
    after more packets arrive corrects the row rather than adding a second.
    """
    own = conn is None
    hour_start = _hour_floor(hour_start)
    start = _sql_ts(hour_start)
    end = _sql_ts(hour_start + timedelta(hours=1))
    now = _sql_ts(_now())

    ctx = me._get_conn() if own else None
    conn = ctx.__enter__() if own else conn
    try:
        coverage = _coverage_seconds(conn, start, end)

        # Outbound, keyed on the device as source.
        out_rows = conn.execute("""
            SELECT src_ip AS ip, COUNT(*) AS packets,
                   COALESCE(SUM(packet_size), 0) AS bytes,
                   COUNT(DISTINCT dst_ip) AS peers
            FROM packets
            WHERE captured_at >= ? AND captured_at < ? AND src_ip IS NOT NULL
            GROUP BY src_ip
        """, (start, end)).fetchall()

        in_rows = conn.execute("""
            SELECT dst_ip AS ip, COUNT(*) AS packets,
                   COALESCE(SUM(packet_size), 0) AS bytes,
                   COUNT(DISTINCT src_ip) AS peers
            FROM packets
            WHERE captured_at >= ? AND captured_at < ? AND dst_ip IS NOT NULL
            GROUP BY dst_ip
        """, (start, end)).fetchall()

        devices = {}
        for row in out_rows:
            d = devices.setdefault(row["ip"], {"bo": 0, "bi": 0, "po": 0,
                                               "pi": 0, "peers": set()})
            d["bo"], d["po"] = row["bytes"], row["packets"]
            d["peer_out"] = row["peers"]
        for row in in_rows:
            d = devices.setdefault(row["ip"], {"bo": 0, "bi": 0, "po": 0,
                                               "pi": 0, "peers": set()})
            d["bi"], d["pi"] = row["bytes"], row["packets"]
            d["peer_in"] = row["peers"]

        # DNS, and NULL when there is no resolver importing at all. Zero
        # failures and no resolver to ask are not the same sentence, and a
        # zero here would read as perfect DNS on a network with no Pi-hole.
        #
        # THE BOUNDS FOR THIS TABLE ARE BUILT IN THE TABLE'S OWN SHAPE. See
        # _sql_ts_iso: dns_queries holds an offset-shaped ISO string while
        # every other filtered column here holds a space-separated one, so a
        # window built with the file's own _sql_ts selected ZERO rows and this
        # flag read False on a working resolver import.
        dns_start, dns_end = _sql_ts_iso(hour_start), _sql_ts_iso(
            hour_start + timedelta(hours=1))
        dns_present = me._table_exists_ro(conn, "dns_queries") and conn.execute(
            "SELECT 1 FROM dns_queries WHERE queried_at >= ? AND queried_at < ? "
            "LIMIT 1", (dns_start, dns_end)).fetchone() is not None
        dns_by_client = {}
        if dns_present:
            for row in conn.execute("""
                SELECT client_ip, COUNT(*) AS total,
                       SUM(CASE WHEN reply_type IN ('NXDOMAIN','NODATA','SERVFAIL')
                                THEN 1 ELSE 0 END) AS failures
                FROM dns_queries
                WHERE queried_at >= ? AND queried_at < ? AND client_ip IS NOT NULL
                GROUP BY client_ip
            """, (dns_start, dns_end)).fetchall():
                dns_by_client[row["client_ip"]] = (row["total"], row["failures"] or 0)

        # Presence, and only sweeps that actually ran. A FAILED sweep is never
        # a denominator, which presence_sweep already distinguishes.
        sweeps = conn.execute("""
            SELECT id FROM presence_sweep
            WHERE swept_at >= ? AND swept_at < ? AND outcome = 'ok'
        """, (start, end)).fetchall()
        sweep_ids = [s["id"] for s in sweeps]
        answered_by_ip = {}
        if sweep_ids:
            placeholders = ",".join("?" for _ in sweep_ids)
            for row in conn.execute(f"""
                SELECT ip, COUNT(*) AS n FROM presence_observation
                WHERE sweep_id IN ({placeholders}) GROUP BY ip
            """, sweep_ids).fetchall():
                answered_by_ip[row["ip"]] = row["n"]

        written = 0
        for ip, d in devices.items():
            dns_total, dns_fail = dns_by_client.get(ip, (None, None))
            if not dns_present:
                dns_total, dns_fail = None, None
            conn.execute("""
                INSERT INTO perf_hourly
                    (entity_value, hour_start, bytes_in, bytes_out,
                     packets_in, packets_out, distinct_peers,
                     dns_queries, dns_failures, sweeps_total, sweeps_answered,
                     coverage_seconds, computed_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(entity_value, hour_start) DO UPDATE SET
                    bytes_in=excluded.bytes_in, bytes_out=excluded.bytes_out,
                    packets_in=excluded.packets_in,
                    packets_out=excluded.packets_out,
                    distinct_peers=excluded.distinct_peers,
                    dns_queries=excluded.dns_queries,
                    dns_failures=excluded.dns_failures,
                    sweeps_total=excluded.sweeps_total,
                    sweeps_answered=excluded.sweeps_answered,
                    coverage_seconds=excluded.coverage_seconds,
                    computed_at=excluded.computed_at
            """, (ip, start, d["bi"], d["bo"], d["pi"], d["po"],
                  max(d.get("peer_in", 0), d.get("peer_out", 0)),
                  dns_total, dns_fail,
                  len(sweep_ids) or None,
                  answered_by_ip.get(ip, 0) if sweep_ids else None,
                  coverage, now))
            written += 1
        return written
    finally:
        if own:
            ctx.__exit__(None, None, None)


def build_recent(hours: int = 6) -> dict:
    """
    Fill the last few completed hours. Called on the rollup cycle.

    THE CURRENT HOUR IS DELIBERATELY SKIPPED. It is not finished, so its
    coverage and its totals are both partial, and a partial bucket painted
    next to complete ones reads as a device going quiet. It gets built on the
    next pass, once it is over.
    """
    now = _now()
    current = _hour_floor(now)
    built, rows = 0, 0
    with me._get_conn() as conn:
        if not me._table_exists_ro(conn, "perf_hourly"):
            return {"built": 0, "rows": 0, "note": "perf_hourly does not exist"}
        for back in range(1, max(1, int(hours)) + 1):
            hour = current - timedelta(hours=back)
            rows += build_hour(hour, conn=conn)
            built += 1
    return {"built": built, "rows": rows}


def backfill(hours: int = 48, skip_existing: bool = True,
             now: datetime = None) -> dict:
    """
    Fill every completed hour in the window that has no buckets yet.

    WHY THIS EXISTS, 2026-09-15. Buckets were built in exactly two places: the
    hourly thread, which sleeps a full hour before its first pass, and clean
    shutdown. Both only reach back six hours. So an app that ran all afternoon
    and was killed with Ctrl+C, or crashed, or was closed by the window button,
    left every hour it observed unbucketed, permanently, once the six hour
    window slid past. The packets for those hours are still sitting in the
    database. Nothing had ever gone back for them.

    That is why the page showed six blocks after two days of use, and why no
    device ever reached the twelve hours of history a baseline needs. Every
    block stayed hollow and the page looked broken when it was starving.

    ONE CONNECTION PER HOUR, deliberately. build_recent holds one connection
    for six hours' work, which is fine for six. Holding one for forty eight
    while the sniffer is trying to write would park the capture behind this.

    skip_existing means the second boot is cheap: an hour that already has rows
    was built from the same packets and does not improve by being rebuilt.
    """
    now = now or _now()
    current = _hour_floor(now)
    hours = max(1, min(int(hours or 48), 720))

    existing = set()
    if skip_existing:
        since = _sql_ts(current - timedelta(hours=hours))
        with me._get_readonly_conn() as conn:
            if not me._table_exists_ro(conn, "perf_hourly"):
                return {"built": 0, "rows": 0, "skipped": 0,
                        "note": "perf_hourly does not exist"}
            existing = {
                str(r["hour_start"]) for r in conn.execute(
                    "SELECT DISTINCT hour_start FROM perf_hourly "
                    "WHERE hour_start >= ?", (since,)).fetchall()
            }

    started = _now()
    built = rows = skipped = 0
    for back in range(1, hours + 1):
        hour = current - timedelta(hours=back)
        if _sql_ts(hour) in existing:
            skipped += 1
            continue
        try:
            rows += build_hour(hour)
            built += 1
        except Exception as e:
            # One bad hour must not cost the other forty seven.
            logger.error("Perf backfill failed for %s: %s", _sql_ts(hour), e)

    # Timed because this reads the largest table in the database. If it ever
    # starts costing real seconds at boot, the number is in the log rather
    # than left to be guessed at.
    seconds = round((_now() - started).total_seconds(), 1)
    return {"built": built, "rows": rows, "skipped": skipped,
            "window_hours": hours, "seconds": seconds}


# READING

def device_view(hours: int = 24, entity_value: str = None,
                now: datetime = None) -> dict:
    """
    One row per device, with its last N hourly buckets and a verdict on each.

    THE VERDICT IS ONE OF FOUR AND THEY ARE NOT DEGREES OF THE SAME THING:
      not_measured  coverage under the floor. We could not look. This is not
                    a quiet hour and must never be painted as one.
      unknown       the device has too little history of its own for "usual"
                    to mean anything yet.
      normal        within its own usual range.
      high / low    well outside it.

    `now` is injectable for the same reason predictions.check_due takes one:
    the window is relative to the clock, and a test that cannot move the clock
    can only test whatever happens to be inside the last few real hours.
    """
    min_cov = _pref_int("perf_min_coverage_seconds", DEFAULT_MIN_COVERAGE_SECONDS)
    min_hist = _pref_int("perf_min_history_hours", DEFAULT_MIN_HISTORY_HOURS)
    hours = max(1, min(int(hours or 24), 168))

    # THE GRID IS LAID OUT FIRST, THEN FILLED. PORTED FROM THE WINDOWS TREE
    # 2026-09-21, and this was a defect here rather than a tidy-up.
    #
    # What stood in this function built a device's buckets ONLY from rows that
    # existed, so an hour with no row produced NO CELL. The row just came out
    # shorter: a 24 hour window showed tracks of 3, 4, 8 and 9 blocks, column 3
    # of one row was a different hour from column 3 of the next, and the grid
    # could not be read across at all.
    #
    # Worse than untidy. This page exists to keep "we could not look" separate
    # from "it was quiet", and a missing cell said neither out loud. It quietly
    # made the evidence shorter, which reads as a calm device.
    #
    # So the hours are laid out first, as a fixed grid, and every device is
    # filled against it:
    #   an hour with no perf rows from ANY device   the app measured nothing
    #                                               then, grey, said in the why
    #   an hour measured, nothing from this device  a real zero, which goes
    #                                               through the same baseline
    #                                               test as any other number
    #
    # THE GRID STOPS AT THE LAST FINISHED HOUR. build_recent starts at back=1
    # and the hour in progress is never bucketed, so including it would paint a
    # fresh grey column across every device for the whole of every hour.
    end_dt = _hour_floor(now or _now())
    since_dt = end_dt - timedelta(hours=hours)
    # The space spelling for SQL, because that is what the column holds. The
    # ISO one for every key and everything returned. See _hour_key.
    since, end = _sql_ts(since_dt), _sql_ts(end_dt)
    grid = [_iso(since_dt + timedelta(hours=i)) for i in range(hours)]

    with me._get_readonly_conn() as conn:
        if not me._table_exists_ro(conn, "perf_hourly"):
            return {"available": False,
                    "note": ("the performance table does not exist yet, so "
                             "nothing has been measured. This is no data, not "
                             "a quiet network."),
                    "not_measured": NOT_MEASURED}

        params = [since, end]
        sql = "SELECT * FROM perf_hourly WHERE hour_start >= ? AND hour_start < ?"
        if entity_value:
            sql += " AND entity_value = ?"
            params.append(entity_value)
        sql += " ORDER BY entity_value ASC, hour_start ASC"
        rows = me._rows_to_dicts(conn.execute(sql, params).fetchall())

        # WHICH HOURS THE APP MEASURED AT ALL, read from the buckets rather
        # than from packets. coverage_seconds is a property of the hour, the
        # same number on every row of it, so the rows already on hand answer
        # it. Asking the packets table again would mean a scan of the biggest
        # table in the database on every page load, which is the thing this
        # module was built to stop doing.
        coverage_by_hour = {}
        cov_sql = ("SELECT hour_start, MAX(coverage_seconds) AS cov "
                   "FROM perf_hourly WHERE hour_start >= ? AND hour_start < ? "
                   "GROUP BY hour_start")
        for row in conn.execute(cov_sql, (since, end)).fetchall():
            coverage_by_hour[_hour_key(row["hour_start"])] = row["cov"] or 0

        # The device's own history, all of it, not just the window on screen,
        # keyed by hour so the hour being judged can be left out of its own
        # median.
        history = {}
        hist_sql = ("SELECT entity_value, hour_start, "
                    "bytes_in + bytes_out AS total "
                    "FROM perf_hourly WHERE coverage_seconds >= ?")
        hist_params = [min_cov]
        if entity_value:
            hist_sql += " AND entity_value = ?"
            hist_params.append(entity_value)
        for row in conn.execute(hist_sql, hist_params).fetchall():
            history.setdefault(row["entity_value"], {})[
                _hour_key(row["hour_start"])] = row["total"] or 0

        names = {}
        if me._table_exists_ro(conn, "known_devices"):
            for row in conn.execute(
                    "SELECT ip, known_as FROM known_devices").fetchall():
                if row["known_as"]:
                    names[row["ip"]] = row["known_as"]

        broadcasts = local_broadcasts(conn)

    # Rows in the window, per address per hour.
    rows_by_ip = {}
    for row in rows:
        rows_by_ip.setdefault(row["entity_value"], {})[
            _hour_key(row["hour_start"])] = row

    # A DEVICE THAT SAID NOTHING ALL WINDOW STILL GETS A ROW. Leaving it off is
    # the same lie as leaving an hour off a track: the reader cannot tell a
    # device that was silent from one that does not exist. Cut off at the
    # silent window so addresses from months ago do not pile up.
    silent_cutoff = _iso(end_dt - timedelta(days=SILENT_DEVICE_DAYS))
    candidates = set(rows_by_ip)
    for ip, hist in history.items():
        if entity_value and ip != entity_value:
            continue
        # `hist` is keyed by HOUR, so the most recent thing this device did is
        # the maximum of its KEYS, not of its values. Comparing the values
        # would ask whether its biggest byte total was recent, which is a
        # different question and would keep a dead device on the page for as
        # long as one of its old hours was busy.
        if not hist or max(hist.keys()) < silent_cutoff:
            continue
        # Devices only. The counts of what was set aside are counts of what
        # was seen IN THIS WINDOW, and a destination nobody talked to this
        # week does not belong in them.
        if classify_entity(ip, broadcasts) == "device":
            candidates.add(ip)

    # Sorted once per address instead of once per cell.
    sorted_history = {ip: sorted(h.values()) for ip, h in history.items()}

    devices = {}
    for ip in candidates:
        hist = history.get(ip, {})
        ordered_samples = sorted_history.get(ip, [])
        entry = {
            "entity_value": ip,
            "name": names.get(ip),
            "kind": classify_entity(ip, broadcasts),
            "buckets": [],
            "bytes_total": 0,
            "hours_measured": 0,
            "hours_blind": 0,
            "hours_silent": 0,
            # How close this device is to having a baseline at all. Without
            # these two numbers a hollow row is indistinguishable from a
            # broken page, which is exactly how it was read.
            "history_hours": len(hist),
            "history_needed": min_hist,
        }
        devices[ip] = entry
        by_hour = rows_by_ip.get(ip, {})

        for hour in grid:
            row = by_hour.get(hour)
            measured = coverage_by_hour.get(hour)

            # 1. NOTHING WAS BUCKETED FOR THAT HOUR, from any device. The app
            #    was not running, or it was running and never wrote the hour.
            #    Either way we could not look, and that is not a quiet hour.
            if measured is None:
                entry["hours_blind"] += 1
                entry["buckets"].append(_blank_bucket(
                    hour, "not_measured",
                    "no buckets were written for that hour, by any device, so "
                    "nothing was measured in it. This is not a quiet hour."))
                continue

            coverage = (row["coverage_seconds"] or 0) if row else measured

            # 2. The hour was bucketed but the capture was barely up.
            if coverage < min_cov:
                entry["hours_blind"] += 1
                entry["buckets"].append(_blank_bucket(
                    hour, "not_measured",
                    f"only {coverage}s of that hour was captured, the floor is "
                    f"{min_cov}s. Nothing can be said about the device from "
                    f"it.", coverage=coverage))
                continue

            # 3. A real measurement, and zero bytes is one of those. An hour
            #    with the capture up and nothing from this device is a fact
            #    about the device, so it goes through the same test as any
            #    other number rather than being dropped off the row.
            total = ((row["bytes_in"] or 0) + (row["bytes_out"] or 0)) if row else 0
            entry["hours_measured"] += 1
            if row is None:
                entry["hours_silent"] += 1

            skip = None
            if hour in hist:
                skip = bisect.bisect_left(ordered_samples, hist[hour])
            typical = _median_skipping(ordered_samples, skip)
            # COUNTED WHOLE, compared with the hour left out, and those are two
            # different questions. "Has this device got a baseline at all" is
            # about the device. "What is its usual" is about the other hours.
            # Subtracting the hour from the count as well put a device sitting
            # exactly on the threshold in the daft position of reading hollow
            # on the hours it spoke and coloured on the hours it did not.
            samples = len(hist)
            seen = ("nothing at all from this device in that hour"
                    if total == 0 else _human(total))

            if samples < min_hist:
                verdict = "unknown"
                why = (f"{samples} hours of history for this device, "
                       f"{min_hist} needed before 'usual' means anything. "
                       f"Measured: {seen}.")
            elif typical > 0 and total > typical * HIGH_MULTIPLIER:
                verdict = "high"
                why = (f"{seen} against a usual {_human(typical)} "
                       f"for this device")
            elif typical > 0 and total < typical / LOW_DIVISOR:
                verdict = "low"
                why = (f"{seen} against a usual {_human(typical)}. "
                       f"Quiet is not automatically wrong, it is just unlike "
                       f"this device.")
            else:
                verdict = "normal"
                why = f"{seen}, usual for this device"

            entry["bytes_total"] += total
            entry["buckets"].append({
                "hour_start": hour,
                "bytes": total,
                "packets": ((row["packets_in"] or 0) + (row["packets_out"] or 0)
                            if row else 0),
                "peers": (row["distinct_peers"] if row else 0),
                "dns_queries": (row["dns_queries"] if row else 0),
                "dns_failures": (row["dns_failures"] if row else 0),
                "sweeps_total": (row["sweeps_total"] if row else 0),
                "sweeps_answered": (row["sweeps_answered"] if row else 0),
                "coverage_seconds": coverage,
                "verdict": verdict,
                "why": why,
            })

    ordered = sorted(devices.values(), key=lambda d: -d["bytes_total"])

    # DEVICES ON THE PAGE, EVERYTHING ELSE COUNTED BESIDE IT. Nothing is
    # hidden: the set-aside entities are reported by kind, with the reason,
    # and the busiest few are named so a reader can see what was left out.
    on_page = [d for d in ordered if d["kind"] == "device"]
    aside = [d for d in ordered if d["kind"] != "device"]
    aside_by_kind = {}
    for d in aside:
        bucket = aside_by_kind.setdefault(d["kind"], {
            "kind": d["kind"],
            "count": 0,
            "why": NOT_A_DEVICE_NOTE.get(d["kind"], ""),
            "examples": [],
        })
        bucket["count"] += 1
        if len(bucket["examples"]) < 5:
            bucket["examples"].append(d["entity_value"])

    # WHY EVERY BLOCK IS HOLLOW, said in one sentence rather than left for the
    # reader to work out from a legend.
    with_baseline = [d for d in on_page
                     if d["history_hours"] >= d["history_needed"]]
    if not on_page:
        baseline_note = ("No device buckets in this window yet. That is no "
                         "data, not a quiet network.")
    elif not with_baseline:
        best = max(d["history_hours"] for d in on_page)
        baseline_note = (
            f"NOTHING IS COLOURED YET AND THAT IS NOT A FAULT. A device needs "
            f"{min_hist} measured hours of its own before 'usual' means "
            f"anything, and the furthest along has {best}. Every block is "
            f"hollow until then, which means 'no baseline yet', not 'quiet'.")
    elif len(with_baseline) == len(on_page):
        baseline_note = (
            f"All {len(on_page)} devices have the {min_hist} measured hours a "
            f"baseline needs, so every block here is a real comparison "
            f"against that device's own median.")
    else:
        baseline_note = (
            f"{len(with_baseline)} of {len(on_page)} devices have the "
            f"{min_hist} hours needed for a baseline. The others stay hollow "
            f"until they get there, which means no baseline yet, not quiet.")

    # THE WINDOW NOTES, PORTED 2026-09-21 WITH THE GRID.
    #
    # These existed on Windows and not here, and every one of them is a
    # sentence the absence of which made the page lie by omission: how many
    # hours were blind, whether the broadcast rule was exact or a guess, and
    # what a grey block actually means. The page's own legend reads
    # coverage_note.
    blind_hours = sum(1 for h in grid if h not in coverage_by_hour)
    if blind_hours == 0:
        coverage_note = (
            f"All {hours} hours in this window were measured, so there are no "
            f"grey columns on this page.")
    else:
        coverage_note = (
            f"{blind_hours} of the {hours} hours in this window were not "
            f"measured, so those columns are grey on every row. They are not "
            f"quiet hours, they are hours nobody was watching.")

    # The subnet broadcast rule, and whether it is exact or a guess. Said out
    # loud because a wrong guess here takes a real device off the page.
    if broadcasts:
        classification_note = (
            "Subnet broadcast addresses are taken from the subnets this app "
            f"sweeps ({', '.join(sorted(broadcasts))}), so they are exact.")
    else:
        classification_note = (
            "No swept subnet is recorded yet, so a private address ending in "
            ".255 is treated as the subnet broadcast. That is right on a /24 "
            "and wrong on a /23, where it would take a real device off this "
            "page. It corrects itself once a presence sweep has run.")

    not_measured_means = (
        "that hour was not measured: either no bucket was written for it at "
        "all, or the capture was running for less than the floor of "
        f"{min_cov}s inside it. Nothing about the device can be read from one "
        "of these and they are NOT quiet hours.")

    return {
        "available": True,
        "hours": hours,
        "not_measured_means": not_measured_means,
        "window_start": _iso(since_dt),
        "window_end": _iso(end_dt),
        # THE HOURS THEMSELVES, so the page can label a column and so a test
        # can assert the grid it drew is the grid the rows carry. Without this
        # the page had to re-derive the window from `hours` and the clock,
        # which is a second opinion about the same fact.
        "hour_grid": grid,
        "hours_not_measured": blind_hours,
        "coverage_note": coverage_note,
        "classification_note": classification_note,
        "devices": on_page,
        "history_needed": min_hist,
        "baseline_note": baseline_note,
        # Recorded, not shown as devices. See classify_entity for why.
        "not_devices": sorted(aside_by_kind.values(),
                              key=lambda x: -x["count"]),
        "not_measured": NOT_MEASURED,
        "how_to_read_this": (
            "Each block is one hour for one device, oldest on the left. Every "
            "row covers the SAME hours, so a column is one hour across the "
            "whole page. GREY means that hour was not measured, either the "
            "capture was not running for enough of it or no bucket was "
            "written at all, so nothing about the device can be read from it, "
            "and it is NOT a quiet hour. Hollow means this device has too "
            "little history of its own for 'usual' to mean anything yet. "
            "Everything else is compared against that device's own median, "
            "never against other devices, because a TV and a workstation have "
            "nothing to say about each other. Two things on this page are not "
            "measured at all and are listed separately rather than shown as "
            "zero. Only devices on this network are listed: public "
            "destinations, multicast groups and the like are counted in "
            "not_devices with the reason, because their traffic measures us "
            "rather than them."),
    }


def _human(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def summary_for_model(hours: int = 24, now: datetime = None) -> dict:
    """
    The same data, trimmed hard, for the model rather than the page.

    ONE LINE PER DEVICE. The full bucket list is thousands of numbers and
    would eat the answer budget without telling the model anything it could
    not get from the summary. It can ask for one device's detail if a line
    looks interesting, which is the same trim rule the owner asked for
    everywhere else.
    """
    view = device_view(hours=hours, now=now)
    if not view.get("available"):
        return view

    lines = []
    for device in view["devices"][:40]:
        verdicts = [b["verdict"] for b in device["buckets"]]
        unusual = [v for v in verdicts if v in ("high", "low")]
        blind = verdicts.count("not_measured")
        name = device["name"] or device["entity_value"]
        lines.append({
            "device": device["entity_value"],
            "name": name,
            "bytes_total": device["bytes_total"],
            "readable": _human(device["bytes_total"]),
            "hours_measured": device["hours_measured"],
            "hours_not_measured": blind,
            # `blind` and `silent` were ONE number until the grid was ported,
            # because without cells for the empty hours there was nothing to
            # count as silent. They are opposite statements and the model has
            # to be able to tell them apart: hours_not_measured is "the
            # capture could not see", hours_silent is "the capture WAS up and
            # this device sent nothing".
            "hours_silent": device["hours_silent"],
            "unusual_hours": len(unusual),
            # Without these the model reads a row of unknowns as a verdict.
            "history_hours": device["history_hours"],
            "history_needed": device["history_needed"],
            "has_baseline": device["history_hours"] >= device["history_needed"],
        })

    return {
        "available": True,
        "hours": hours,
        "devices": lines,
        "history_needed": view["history_needed"],
        "baseline_note": view["baseline_note"],
        "not_devices": view["not_devices"],
        "not_measured": NOT_MEASURED,
        "how_to_read_this": (
            "One line per device, busiest first. hours_not_measured is hours "
            "the capture could not see, and those are NOT quiet hours: a "
            "device with 20 of them has not been observed, whatever its byte "
            "total says. hours_silent is the opposite and you must not mix "
            "the two: the capture WAS up and this device sent nothing. "
            "unusual_hours counts hours well outside that "
            "device's own median. Ask for one device with entity_value to see "
            "its hours. Two signals are not measured at all, they are listed "
            "in not_measured with what it would take to get them, and you "
            "must not report either as healthy. has_baseline false means this "
            "device has too little history of its own for 'usual' to mean "
            "anything: say that, never call it normal or quiet. Only devices "
            "on this network are listed, not_devices counts the public "
            "destinations and multicast groups that were set aside."),
    }
