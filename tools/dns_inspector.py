# tools/dns_inspector.py
# AgentalSec V2, TODO 113.3. DNS inspection: DGA detection and DNS beaconing.
#
# WHY THIS IS SEPARATE FROM dns_monitor
#
# dns_monitor imports rows. This file inspects them. They are different jobs
# with different cadences: import runs every 15 minutes and is bounded only by
# how fast the resolver produces rows. Inspection runs after each import batch
# and looks at the collected data as a whole, which means it needs the batch
# to already be in the database before it starts.
#
# The separation also matches the rule that monitor == collect and inspector ==
# analyse. dns_monitor.py says explicitly at the top that it makes no
# judgements; that is not a gap, it is where this file starts.
#
# WHAT THIS RAISES, AND WHAT IT DOES NOT
#
# DNS-1001  DGA suspected
# A second-level domain label with high Shannon entropy and length > 10 chars,
# queried by the same client more than once. Entropy alone fires on hex strings
# in CDN URLs and long product names, so the count gate is the thing that
# makes it a signal rather than a label printer.
#
# DNS-1002  DNS beacon
# Same (client, domain) pair queried 6+ times in a 4-hour window with a
# coefficient of variation below 0.25. Normal browsing is bursty and irregular.
# A polling loop is not.
#
# DNS-1003 to DNS-1006, ADDED 2026-09-22. READ THIS PART BEFORE CHANGING A
# THRESHOLD BELOW, because most of it is an argument about thresholds.
#
# DNS-1003  DNS tunnel suspected
# Names whose encoded-looking part sits in the labels LEFT of the registered
# domain, rotated often enough to be traffic rather than one hash in a URL.
#
# WHY THE FIRST TWO DID NOT COVER THESE, and it is a scope problem rather than
# a tuning problem. _is_dga_candidate scores _second_level_label, which
# returns EXACTLY ONE LABEL by construction: the one before the TLD. A tunnel
# that writes its payload as <base32blob>.evil.com is therefore not scored
# below a threshold, it is never scored at all, and no change to
# DGA_ENTROPY_THRESHOLD reaches it, because the function that applies that
# threshold is not looking at the blob. The same is true of the beacon check:
# it measures cadence on one name, and a tunnel is interesting precisely when
# it uses MANY names.
#
# DNS-1004  Unusual query volume per client
# DNS-1005  NXDOMAIN burst per client
# DNS-1006  Unusual TXT volume per client
#
# WHERE THE DATA COMES FROM, and the note that used to say it did not.
# These three read query_type and reply_type out of dns_queries. Until
# 2026-09-22 query_dns_inspection told the model they could not be computed
# because "the resolver import does not carry the response code" and "does
# not carry the query type". Both clauses were false: read_pihole decodes
# both, the columns are in the schema, and core/perf.py was already
# aggregating NXDOMAIN per client-hour out of reply_type. The lesson is in
# the register entry for DNS-1003 and it is worth repeating here because this
# file is where the next person will look: a model-facing sentence about what
# the data does not contain is load-bearing. It decides whether the model goes
# looking.
#
# THEY ARE COVERAGE-LIMITED AND THEY SAY SO RATHER THAN GUESSING. Pi-hole's
# database carries both codes; AdGuard's querylog carries neither a reply code
# nor, in this importer, a query type. _client_window_totals counts the rows
# with no code and hands back a sentence, which query_dns_inspection publishes
# and the importer logs at WARNING. An AdGuard install therefore gets a
# finding list that says the NXDOMAIN check examined nothing, rather than a
# reassuring absence of NXDOMAIN findings.
#
# THE THRESHOLDS ARE CHOSEN, NOT MEASURED, AND THE CONSTANTS SAY SO AT THEIR
# DEFINITIONS. At the time these were written dns_queries held 0 rows and
# dns_monitor was off, so this path has never seen real traffic on this
# machine. They are exposed to the model through query_dns_inspection so that
# a reader can see the numbers rather than a bare judgement, and the volume
# check compares each client against the median of the others as well as
# against an absolute floor, which is the part that survives an unknown
# network.
#
# WHAT THIS DOES NOT RAISE
#
# Novelty alone. The dns_monitor comment says it clearly: a name never resolved
# before is the commonest event on any network with a browser. That decision
# stands. 113.4 will add the feed integration: that is where a new name becomes
# a finding, because the combining signal is a match in an external bad-domain
# list rather than entropy or cadence. Keep them separate.
#
# TXT CONTENT, and this one is a decision rather than a gap. The import keeps
# the name and the record type; it does not keep what the record SAID, because
# Pi-hole's queries table does not hold the answer payload. So DNS-1006 counts
# TXT queries and says in its own description that it did not read them.
#
# RULE TWO, applied here
#
# This module tracks which dns_queries rows it last inspected, using an ID
# cursor stored in user_preferences. "I found no DGA" and "I could not
# inspect the table" are kept different at every return path: the first returns
# ran=True with zero findings, the second returns ran=False with a reason.
#
# THE CURSOR COVERS DNS-1001 ONLY. It answers "which ROWS have been decided
# about", which is the right question for a per-row rule. DNS-1002 to DNS-1006
# are windowed claims over the last four hours, so they are idempotent through
# finding_already_open instead: the same open finding absorbs a later identical
# claim, and the cursor advancing past a row does not silence a condition that
# is still true. That is deliberate, and the distinction matters when reading
# a cursor that is level with the log while volume findings are still firing.

import logging
import math
import re
import statistics

from tools.dns_monitor import (
    _cursor_row,
    _cursor_write,
    resolver_sensor_id,
)

logger = logging.getLogger(__name__)

# constants

# DGA gate: the second-level label must be at least this long.
# Below 10 chars: "dropbox", "github", "stripe" all clear it, which is right.
# At 10 chars: we still catch most DGA outputs, which average 12-20 chars.
DGA_MIN_LABEL_LEN = 10

# DGA gate: Shannon entropy per character of the second-level label.
# English words sit around 3.0-3.3. DGA output typically runs 3.7-4.5.
DGA_ENTROPY_THRESHOLD = 3.5

# DGA gate: how many times the same (client, domain) pair must appear before
# we raise. One occurrence can be a CDN one-off. Two means it came back.
DGA_MIN_COUNT = 2

# How many individual DGA rows one client can raise in a single pass.
#
# WHY THERE IS A CAP AT ALL. The finding title now carries the DOMAIN, which
# it did not before, and that fixed a bug where only the FIRST DGA domain per
# client was ever reported (see _check_dga). The other side of that fix is
# that a client genuinely rotating through fifty names would now raise fifty
# rows and bury the alert list under the thing it is reporting.
#
# PAST THE CAP NOTHING IS SILENTLY DROPPED. The individual rows stop and ONE
# summary row says how many there were, which is the stronger signal anyway:
# rotation is what DGA actually looks like.
DGA_MAX_PER_CLIENT_PER_PASS = 5

# Beaconing: minimum queries in the window to measure regularity.
BEACON_MIN_COUNT = 6

# Beaconing: how far back to look, in hours.
BEACON_WINDOW_HOURS = 4

# Beaconing: minimum mean interval in seconds.
# Below this the device is just chatty, not polling on a schedule.
BEACON_MIN_INTERVAL_SECS = 30

# Beaconing: coefficient of variation ceiling.
# CV = stddev / mean. Below 0.25 is more regular than any human-driven pattern.
BEACON_CV_CEILING = 0.25

# Spread (DNS-1007): one destination new and rare in the house, polled on a
# timer by several devices in the same beacon window.
SPREAD_MIN_DEVICES = 2
SPREAD_NEW_DAYS = 7       # first asked for in the house this recently
SPREAD_RARE_DEVICES = 4   # by at most this many devices, ever
# Held spread (DNS-1008): rule fields that name a destination by name.
HELD_NAME_KEYS = ("registered_domain", "domain", "sni", "matched")

# THE VOLUME AND PATTERN CHECKS, ADDED 2026-09-22.
#
# WHY THESE ARRIVED LAST AND WHAT WAS CLAIMED IN THE MEANTIME. Until today,
# query_dns_inspection carried a `not_implemented` list saying the NXDOMAIN
# rate and the TXT volume "were never computed" because "the resolver import
# does not carry the response code" and "does not carry the query type". Both
# clauses were false and had been for as long as anyone can check:
# read_pihole decodes reply_type and query_type out of pihole-FTL, the columns
# are in dns_queries, and core/perf.py was already aggregating NXDOMAIN per
# client-hour from exactly those columns. So the missing part was never the
# data. It was the check, and a note that told the model the data was absent.
#
# THE THRESHOLDS BELOW ARE CHOSEN, NOT MEASURED, AND THEY SAY SO.
# Every other number in this file was measured against a real machine. These
# could not be: at the time they were written dns_queries held ZERO ROWS and
# the sensor was switched off, so this path has never run on real traffic.
# A number invented here and presented as a measurement would be the exact
# dishonesty this project spends its comments preventing, so instead:
#
#   * they are named constants, exposed to the model through
#     query_dns_inspection, so the model can see the numbers it is reasoning
#     about rather than a bare "volume was high";
#   * each carries the arithmetic behind it, so retuning is a calculation
#     rather than a guess;
#   * the two volume checks compare a client against THE MEDIAN OF THE OTHER
#     CLIENTS on this network as well as against an absolute floor. That is
#     what makes them survive an unknown network: on a busy network the
#     absolute floor stops mattering, on a quiet one the relative factor does.
#     A single absolute number would have been right on exactly one network.

# The window these three share, in hours. Deliberately the same 4 as
# BEACON_WINDOW_HOURS so that all four checks describe the same period and a
# reader can put them side by side without translating between windows.
DNS_ACTIVITY_WINDOW_HOURS = 4

# TUNNEL: how long a label has to be before it is worth measuring at all.
# 12 chars of base32 is 60 bits of payload, which is the point at which a
# label stops being a word with digits in it.
TUNNEL_MIN_PAYLOAD_LEN = 12

# TUNNEL: a FLOOR on the entropy of that label, and the honest description of
# it is "a cheap filter, not the discriminator".
#
# MEASURED ON THIS HOST, 2026-09-22, because choosing this number by feel is
# how a rule becomes a random-name printer:
#
#   long English words (len >= 12)   min 2.873  median 3.169  max 3.455
#     "windowsupdate" 3.393, "googlesyndication" 3.455, "microsoftonline" 3.323
#   base32 payload, len 12           min 2.585  median 3.252
#   base32 payload, len 20           min 3.141  median 3.784
#   base32 payload, len 32           min 3.781  median 4.203
#
# READ THAT FIRST BLOCK AGAINST THE SECOND. A 12-character base32 payload
# typically scores BELOW "windowsupdate", so an entropy gate high enough to
# exclude dictionary words would miss the majority of real short tunnel
# payloads, and one low enough to catch them admits the words. No threshold on
# this feature separates the two populations at this label length, and the
# first version of this constant (3.4) was chosen as though it did.
#
# So the gate is 3.0, which is a NOISE FLOOR rather than a classifier: it
# excludes the words at the bottom of that list ("international" 2.873,
# "administration" 3.039) and it lets "windowsupdate" through on purpose,
# because the count below is what carries the claim. It is cheaper to admit a
# word than to build a dictionary into a detector.
TUNNEL_ENTROPY_FLOOR = 3.0

# TUNNEL: DISTINCT encoded payloads from ONE CLIENT ON ONE REGISTERED DOMAIN,
# in the window. THIS is the discriminator, and the grouping is the whole
# argument:
#
#   a TUNNEL is one domain somebody registered, carrying many different
#   encoded labels, because the payload changes on every exfiltration.
#
#   a CDN is MANY registered domains, each carrying one hash, because each
#   asset lives at its own name.
#
#   a signed URL is ONE name fetched repeatedly, which is one distinct
#   payload however many times it is asked for.
#
# Counting distinct payloads per client without the domain grouping would
# merge the first and second of those and fire on ordinary browsing. Counting
# them per (client, registered domain) is the shape that separates them, and
# it is why this check is worth having where a bare "entropy is high" is not.
TUNNEL_MIN_DISTINCT_PER_CLIENT = 5

# TUNNEL: and the same count at the severity that says look now.
TUNNEL_HIGH_DISTINCT_PER_CLIENT = 15

# VOLUME: absolute floor, queries in the window, per client.
# The arithmetic: 3000 in four hours is 12.5 a minute sustained. A browser on
# an active machine runs a few hundred an hour once the cache is warm, and a
# fresh boot or a browser update can burst well past that for a few minutes.
# Nothing ordinary sustains 12.5 a minute for four hours, which is why this is
# a floor rather than a threshold on its own.
VOLUME_MIN_QUERIES = 3000

# VOLUME: and how far above the MEDIAN client this one has to be. The floor
# alone fires on a network of one busy machine; the factor alone fires on a
# two-device network during a backup. Both together is the claim worth making.
VOLUME_MEDIAN_FACTOR = 4.0

# VOLUME: a client has to clear this before it counts toward the median, or a
# network with one idle device would make the median zero and every other
# client a four-fold outlier.
VOLUME_MEDIAN_FLOOR = 50

# NXDOMAIN: count in the window, and the share of that client's own queries.
# 200 names that do not exist is a lot to ask in four hours; 60% of everything
# a device asked for is the part that distinguishes "hunting for a live
# controller" from "resolving a lot of things".
NXDOMAIN_MIN_COUNT = 200
NXDOMAIN_MIN_SHARE = 0.6

# TXT: count in the window. TXT is a rare record type from a client's point of
# view: SPF and DKIM checks, a couple of vendor lookups. A device asking this
# many is either doing something unusual or is being asked to.
TXT_MIN_COUNT = 40

# How many rows one client can raise per check per pass for the volume family.
# One: each of these is a summary about a client, and the counts are inside
# the row, so a second row would be the same sentence twice.
ACTIVITY_MAX_PER_CLIENT_PER_PASS = 1

# Domains whose second-level labels are so well-known that DGA scoring is a
# waste of a finding slot. This is NOT an allowlist for the block feeds.
# It is only a noise filter for the entropy check.
_KNOWN_ROOTS = frozenset([
    # CDN / cloud
    "cloudfront", "akamaiedge", "akamaihd", "fastly", "gstatic", "googleapis",
    "azurewebsites", "azureedge", "cloudflare", "amazonaws", "azurefd",
    # analytics / ad
    "doubleclick", "googlesyndication", "googletagmanager",
    # comms / auth
    "microsoftonline", "windowsupdate", "microsoft", "office365", "live",
    # common subdomains that look high-entropy but are structured
    "googlevideo",
    # hash and UUID names in front of their own domains, one device each
    "apple", "icloud", "aaplimg", "fbcdn", "akadns",
])

# Names no attacker can register: local ones, and the reserved names devices
# use as probes (this-url-does-not-exist.invalid, _dns.resolver.arpa, reverse
# lookups under in-addr.arpa).
_LOCAL_SUFFIXES = (".lan", ".local", ".localdomain", ".home.arpa",
                   ".internal", ".invalid", ".localhost", ".arpa")

# A registered domain this many devices query in the window is shared
# infrastructure. Both rules here describe ONE device talking to a domain, so
# the trade is stated: the same tunnel or DGA on three devices at once is
# not reported by these two rules.
SHARED_DOMAIN_CLIENTS = 3

_VOWELS = frozenset("aeiou")


def _looks_machine_made(label: str) -> bool:
    """
    Whether a label reads as generated rather than as words.

    Entropy cannot do this: "theglobeandmail" scores 3.5 and so does a
    random string. Measured on generated labels: 78% of random a-z at length
    10, 86% at 12, 91% at 16, and over 99% of hex are caught by these three
    tests, while every real site name in a week of this network's queries
    passes. A dictionary-word DGA reads as words and is out of reach here.
    """
    s = label.replace("-", "")
    letters = [ch for ch in s if ch.isalpha()]
    if not letters:
        return False
    vowel_share = sum(ch in _VOWELS for ch in letters) / len(letters)
    longest_run = max((len(m) for m in
                       re.findall(r"[bcdfghjklmnpqrstvwxyz]+", s)), default=0)
    digits = sum(ch.isdigit() for ch in s)
    return vowel_share < 0.28 or longest_run >= 5 or digits >= 3


def _is_local_name(domain: str) -> bool:
    return (domain or "").lower().rstrip(".").endswith(_LOCAL_SUFFIXES)


def _already_handled(client_ip: str, title: str) -> bool:
    """Open already. A dismissal of the same rule is honoured by save_finding."""
    from core import memory_engine as me
    return me.finding_already_open("dns_inspector", "ip", client_ip, title)


def _clients_per_domain(conn) -> dict:
    """Registered domain to the set of devices that queried it in the window."""
    out: dict = {}
    for client_ip, domain in conn.execute("""
        SELECT DISTINCT client_ip, domain FROM dns_queries
        WHERE queried_at >= ? AND client_ip IS NOT NULL AND domain IS NOT NULL
    """, (_window_cutoff(DNS_ACTIVITY_WINDOW_HOURS),)).fetchall():
        reg = _registered_domain(domain)
        if reg:
            out.setdefault(reg, set()).add(client_ip)
    return out

_INSPECT_CURSOR_KEY = "dns_inspect_cursor"


def _get_cursor() -> int:
    """The inspect cursor's value, or 0 when it has never been written."""
    value, _identity = _cursor_row(_INSPECT_CURSOR_KEY)
    try:
        return int(value) if value not in (None, "") else 0
    except (TypeError, ValueError):
        return 0


def _set_cursor(value: int):
    _cursor_write(_INSPECT_CURSOR_KEY, int(value))


def _entropy(label: str) -> float:
    """
    Shannon entropy per character of a string.

    Returns bits per character. An empty string returns 0.0 rather than
    raising, because the caller gates on DGA_MIN_LABEL_LEN and a short or
    empty label should not become a Python error in the inspection loop.
    """
    if not label:
        return 0.0
    counts: dict[str, int] = {}
    for ch in label:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(label)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# The second-level parts of the common two-label public suffixes. Only used
# when the LAST label is a two-character country code, which is what makes
# this safe. The first version of this check was "<=4 chars and all letters"
# and it broke on "abc.evil.com": "evil" is four letters, so it got mistaken
# for a suffix and the entropy check ran on "abc" instead. The test caught it,
# which is the whole reason the failure tests come first.
_SLD_SUFFIXES = frozenset([
    "co", "com", "org", "net", "gov", "edu", "ac", "mil",
    "nom", "sch", "ne", "or", "ltd", "plc", "gob",
])


def _looks_like_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _window_cutoff(hours: float) -> str:
    """A cutoff in the EXACT shape the dns_queries column holds.

    THE SHAPE IS LOAD-BEARING AND THIS MODULE USED TO GET IT WRONG IN TWO
    WAYS, both measured. `datetime.now(timezone.utc).isoformat()` KEEPS the
    microseconds ('.413000+00:00'), and an offset-shaped column compares
    byte-wise, so '.' (0x2E) sorts after '+' (0x2B) and a row AT the same
    second is excluded from its own window. The section-9 addendum fixed
    exactly this shape in core/memory_engine._sql_datetime; this module builds
    its own cutoffs and kept it.

    And it must go through the same funnel the store's own filters use, so
    that a cutoff built here and a cutoff built by a caller who passed
    `since` to query_dns mean the same instant. Measured on this host: the
    three windowed checks selected 0 of 1 for a row 20 minutes old when the
    row carried an AdGuard-style local offset, and the funnel is what
    normalises both sides.
    """
    from core import memory_engine as me
    from datetime import datetime, timezone, timedelta
    raw = (datetime.now(timezone.utc) -
           timedelta(hours=hours)).isoformat()
    return me._sql_datetime(raw, me.SHAPE_ISO_OFFSET)


def _second_level_label(domain: str) -> str:
    """
    The label just before the TLD: for "abc.evil.com" return "evil",
    for "evil.com" return "evil", for a bare IP return "".

    This is where DGA output usually lands, because the attacker registers the
    domain and only controls the left side of the registrar's TLD.

    Not a full public-suffix lookup, and it does not need to be. The two-label
    cases (.co.uk, .com.au) are handled by checking the LAST label for a
    two-character country code AND the one before it against a short list of
    real suffixes. Both conditions, not either, so an ordinary four-letter
    brand name cannot be mistaken for a suffix.
    """
    parts = _domain_parts(domain)
    idx = _registered_index(parts)
    return "" if idx is None else parts[idx]


def _domain_parts(domain: str) -> list:
    """
    The labels of a hostname, lowercased, with the things that are not a
    hostname rejected as an empty list.

    A bare IPv4 address is not a domain, a name that is nothing but digits is
    not a domain, and either of those reaching an entropy measure would score
    a string nobody chose as a name.
    """
    if not domain:
        return []
    cleaned = domain.lower().strip().strip(".")
    if _looks_like_ipv4(cleaned):
        return []
    parts = [p for p in cleaned.split(".") if p]
    if len(parts) < 2:
        return []
    if all(p.isdigit() for p in parts):
        return []
    return parts


def _registered_index(parts: list):
    """
    Where the REGISTERED label sits inside a list of labels, or None.

    Pulled out of _second_level_label on 2026-09-22 so that the tunnel check
    can score the labels to its LEFT using the same idea of where the
    registered domain begins. Two functions deciding that boundary separately
    is how one of them ends up scoring a different part of the name than the
    other and nobody notices, because both of them still return plausible
    words.
    """
    if len(parts) < 2:
        return None
    candidate = len(parts) - 2
    if (len(parts) >= 3
            and len(parts[-1]) == 2 and parts[-1].isalpha()
            and parts[-2] in _SLD_SUFFIXES):
        candidate = len(parts) - 3
    return candidate if candidate >= 0 else None


def _payload_labels(domain: str) -> list:
    """
    The labels to the LEFT of the registered domain: the part of a name an
    attacker can fill with anything, on a domain somebody else registered.

    "aBcDeF123456.evil.com"      -> ["abcdef123456"]
    "x.y.evil.co.uk"             -> ["x", "y"]
    "evil.com"                   -> []   (nothing to the left)

    THIS IS THE SCOPE THE DGA CHECK CANNOT COVER, and it is worth being exact
    about why, because it is not a tuning difference. _is_dga_candidate scores
    the registered label by construction: it calls _second_level_label, which
    returns exactly one label. A tunnel that puts its payload at
    <base32blob>.evil.com is therefore never measured at all, because "evil"
    is what gets hashed, and no threshold change to a function that does not
    read the blob makes it read the blob.
    """
    parts = _domain_parts(domain)
    if not parts:
        return []
    idx = _registered_index(parts)
    if idx is None or idx == 0:
        return []
    return parts[:idx]


def _is_dga_candidate(domain: str) -> bool:
    """
    True when the domain's second-level label passes the entropy + length gate.

    Does NOT check count or novelty. The caller does.
    """
    if _is_local_name(domain):
        return False
    sld = _second_level_label(domain)
    if not sld or len(sld) < DGA_MIN_LABEL_LEN:
        return False
    if sld in _KNOWN_ROOTS:
        return False
    return (_entropy(sld) >= DGA_ENTROPY_THRESHOLD
            and _looks_machine_made(sld))


def _check_dga(conn, since_id: int, session_id: str) -> int:
    """
    Find (client, domain) pairs in new rows that pass the DGA gate.

    Returns the number of findings raised.

    THE BUG THIS WAS CARRYING, found 2026-09-20. The title used to read
    "DGA-profile domain queried by <client>" with NO DOMAIN IN IT.
    finding_already_open matches on the title, so once one DGA domain raised
    for a client, every other one from that client was silently dropped for as
    long as that finding stayed open. Rotating through many names is the whole
    DGA signal, so the detection was suppressing exactly the thing it exists to
    catch. DNS-1002 had the domain in its title all along, which is what made
    this look like a slip rather than a decision.

    The domain is in the title now, and DGA_MAX_PER_CLIENT_PER_PASS is the
    other half of that fix.
    """
    from core import memory_engine as me

    # Aggregate: for each (client_ip, domain) pair in the new batch, get the
    # total count in the whole table (not just the batch), so the DGA_MIN_COUNT
    # gate uses the running total rather than the batch size.
    rows = conn.execute("""
        SELECT DISTINCT client_ip, domain
        FROM dns_queries
        WHERE id > ? AND client_ip IS NOT NULL AND domain IS NOT NULL
    """, (since_id,)).fetchall()

    seen_pairs: set[tuple] = set()
    per_client: dict = {}
    shared = None

    for client_ip, domain in rows:
        if (client_ip, domain) in seen_pairs:
            continue
        seen_pairs.add((client_ip, domain))

        if not _is_dga_candidate(domain):
            continue
        if shared is None:
            shared = _clients_per_domain(conn)
        if len(shared.get(_registered_domain(domain), ())) \
                >= SHARED_DOMAIN_CLIENTS:
            continue

        # Count total queries for this (client, domain) in the whole table.
        total = conn.execute(
            "SELECT COUNT(*) FROM dns_queries "
            "WHERE client_ip = ? AND domain = ?",
            (client_ip, domain)
        ).fetchone()[0]

        if total < DGA_MIN_COUNT:
            continue

        per_client.setdefault(client_ip, []).append((domain, total))

    raised = 0

    for client_ip, hits in per_client.items():
        # Busiest first, so if the cap bites it is the quietest names that go
        # into the summary rather than the ones being queried most.
        hits.sort(key=lambda h: (-h[1], h[0]))

        for domain, total in hits[:DGA_MAX_PER_CLIENT_PER_PASS]:
            title = f"DGA-profile domain queried by {client_ip}: {domain}"
            if _already_handled(client_ip, title):
                continue

            sld = _second_level_label(domain)
            ent = _entropy(sld)

            result = me.save_finding(
                session_id=session_id,
                source="dns_inspector",
                severity="medium",
                entity_type="ip",
                entity_value=client_ip,
                title=title,
                sensor_id=resolver_sensor_id(),
                description=(
                    f"Domain: {domain}\n"
                    f"Second-level label: {sld} "
                    f"({len(sld)} chars, entropy {ent:.2f} bits/char)\n"
                    f"Total queries from this client: {total}\n"
                    f"Other DGA-profile names from this client this pass: "
                    f"{len(hits) - 1}\n"
                    f"DGA domains rotate rapidly to evade block lists. This "
                    f"does not confirm malware, but is worth checking what "
                    f"process queries this name and whether the destination "
                    f"is expected."
                ),
                raw_data={"domain": domain,
                          "registered_domain": _registered_domain(domain),
                          "client_ip": client_ip},
                detection_id="DNS-1001",
            )
            if result.get("saved"):
                raised += 1
                logger.info(f"DNS-1001: DGA candidate {domain!r} queried "
                            f"{total}x by {client_ip} (entropy {ent:.2f})")

        # THE CAP DOES NOT HIDE ANYTHING, it summarises. A client past the cap
        # is the strongest version of this detection, not the quietest one.
        # THE TITLE MUST NOT CARRY A NUMBER THAT MOVES.
        #
        # THIS WAS MEASURED, NOT THEORISED. finding_already_open matches on
        # (source, entity_type, entity_value, title). This summary's title used
        # to carry the count, so on a live network it was a NEW title every
        # pass: measured, a client in the same condition whose count drifted
        # 250 -> 251 -> 252 -> 253 wrote FOUR rows, and the same for the other
        # four windowed checks (the tunnel count, the volume total, the
        # NXDOMAIN pair, the TXT count). The module's own comment claimed "a
        # re-run over the same window collapses onto the same open finding
        # instead of stacking rows" -- true only while the counts happen to be
        # identical, which on a growing query log is never.
        #
        # So the title names the CONDITION and the numbers live in the
        # description, where they can grow without changing the identity.
        extra = len(hits) - DGA_MAX_PER_CLIENT_PER_PASS
        if extra > 0:
            title = (f"{client_ip} is rotating through DGA-profile domains")
            if _already_handled(client_ip, title):
                continue
            names = ", ".join(d for d, _c in hits[:12])
            result = me.save_finding(
                session_id=session_id,
                source="dns_inspector",
                # HIGH, and it is the only DGA row that is. One odd name is a
                # CDN hash more often than it is malware, which is why the
                # individual rows above are medium. A dozen of them from one
                # device in one window is not a CDN, it is the rotation the
                # whole detection is looking for. Declared in core/detections
                # alongside medium so this cannot be raised by accident.
                severity="high",
                entity_type="ip",
                entity_value=client_ip,
                title=title,
                sensor_id=resolver_sensor_id(),
                description=(
                    f"Distinct DGA-profile domains from {client_ip} in this "
                    f"pass: {len(hits)}\n"
                    f"Listed individually above: "
                    f"{DGA_MAX_PER_CLIENT_PER_PASS}\n"
                    f"Not listed individually: {extra}\n"
                    f"First names: {names}"
                    + (" ..." if len(hits) > 12 else "") + "\n\n"
                    f"ROTATION IS THE POINT. One odd-looking name is often a "
                    f"CDN. A device reaching for many of them in one window is "
                    f"the pattern DGA exists to produce, and it is a stronger "
                    f"signal than any single row above.\n\n"
                    f"THE COUNTS ABOVE GROW as the window fills, which is why "
                    f"this row is keyed on the condition and not on the "
                    f"number: a title carrying the count was a new finding "
                    f"every pass.\n\n"
                    f"The rest are capped rather than dropped, so the alert "
                    f"list does not get buried by the thing it is reporting. "
                    f"Every query is still in dns_queries and can be counted "
                    f"there."
                ),
                detection_id="DNS-1001",
            )
            if result.get("saved"):
                raised += 1
                logger.warning(f"DNS-1001: {client_ip} queried {len(hits)} "
                               f"distinct DGA-profile domains this pass.")

    return raised


def _registered_domain(domain: str) -> str:
    """
    The registered domain: the label the attacker registered plus its suffix.
    "aBc123.evil.com" -> "evil.com", "x.y.evil.co.uk" -> "evil.co.uk".

    THIS IS THE GROUPING KEY FOR THE TUNNEL CHECK and it is the load-bearing
    part of that rule. Every payload a tunnel sends rides on the SAME
    registered domain, because the attacker had to register one name to
    control it. Ordinary content delivery is the opposite shape: many
    registered domains, each with one hash in front of it. Grouping by this
    is what separates those two, and grouping by the client alone (the first
    version of this check) merges them and fires on a browser.
    """
    parts = _domain_parts(domain)
    if not parts:
        return ""
    idx = _registered_index(parts)
    if idx is None:
        return ""
    return ".".join(parts[idx:])


def _check_tunnels(conn, session_id: str) -> int:
    """
    Names whose ENCODED-LOOKING part is in the labels left of the registered
    domain, rotated on ONE registered domain often enough to be traffic.

    WHY THIS IS A SEPARATE CHECK FROM THE DGA ONE, in one sentence: the DGA
    check scores one label, the registered one, so a tunnel writing base32
    into the label before it is not below a threshold there, it is outside the
    measurement entirely. That is a scope gap, and scope gaps are not fixed by
    tuning. See _payload_labels.

    WHAT MAKES IT SOUND RATHER THAN LOUD, and this rule was rewritten the same
    day it was written because the first version was too wide. Randomness alone
    is everywhere on a modern network (session tokens, cache busters, signed
    CDN paths), and the entropy measurement done for this file showed a fixed
    entropy gate cannot separate them: a 12-character base32 payload typically
    scores LOWER than "windowsupdate". So entropy is a floor here and not the
    claim. The claim is the SHAPE:

      one registered domain + many distinct encoded labels + one client

    which is what exfiltration over DNS looks like, and is not what a CDN
    looks like (many domains, one hash each) or what a signed URL looks like
    (one name, fetched repeatedly).

    Returns the number of findings raised.
    """
    from core import memory_engine as me

    cutoff = _window_cutoff(DNS_ACTIVITY_WINDOW_HOURS)

    rows = conn.execute("""
        SELECT DISTINCT client_ip, domain
        FROM dns_queries
        WHERE queried_at >= ? AND client_ip IS NOT NULL AND domain IS NOT NULL
    """, (cutoff,)).fetchall()

    # (client, registered domain) -> {encoded payload: first example name}
    per_target: dict = {}

    for client_ip, domain in rows:
        payload = ""
        for label in _payload_labels(domain):
            # The LONGEST label is the candidate, not the first: a tunnel
            # splits its payload across labels and pads with short ones, and
            # scoring the first would score padding. A name with no long label
            # at all is not this rule's business.
            if (len(label) >= TUNNEL_MIN_PAYLOAD_LEN
                    and len(label) > len(payload)):
                payload = label
        if not payload or _is_local_name(domain):
            continue
        # The known roots are a noise filter for an entropy rule, not an
        # allowlist, and the same list the DGA check uses applies here. It
        # names REGISTERED domains, so that is the label it is checked on.
        if _second_level_label(domain) in _KNOWN_ROOTS:
            continue
        if _entropy(payload) < TUNNEL_ENTROPY_FLOOR:
            continue
        registered = _registered_domain(domain)
        if not registered:
            continue
        key = (client_ip, registered)
        per_target.setdefault(key, {})
        per_target[key].setdefault(payload, domain)

    clients_on = {}
    for (client_ip, registered) in per_target:
        clients_on.setdefault(registered, set()).add(client_ip)

    raised = 0
    for (client_ip, registered), payloads in sorted(per_target.items()):
        distinct = len(payloads)
        if distinct < TUNNEL_MIN_DISTINCT_PER_CLIENT:
            continue
        if len(clients_on[registered]) >= SHARED_DOMAIN_CLIENTS:
            continue
        # Payload reads as generated. Service names (action-cards-host-app,
        # assetdelivery) read as words, measured at 7 to 25% machine-made on
        # three services here against over 90% for base32 chunks, so the
        # judgement is made over the domain's names rather than per name.
        machine = sum(_looks_machine_made(p) for p in payloads)
        if machine * 2 < distinct:
            continue

        title = f"Possible DNS tunnel under {registered} from {client_ip}"
        if _already_handled(client_ip, title):
            continue

        severity = ("high" if distinct >= TUNNEL_HIGH_DISTINCT_PER_CLIENT
                    else "medium")
        examples = sorted(payloads.values())[:6]
        result = me.save_finding(
            session_id=session_id,
            source="dns_inspector",
            severity=severity,
            entity_type="ip",
            entity_value=client_ip,
            title=title,
            sensor_id=resolver_sensor_id(),
            description=(
                f"Registered domain: {registered}\n"
                f"Distinct encoded labels in front of it, in the last "
                f"{DNS_ACTIVITY_WINDOW_HOURS}h: {distinct}\n"
                f"Where the encoding was found: the labels LEFT of the "
                f"registered domain, which the second-level-label check does "
                f"not score at all.\n"
                f"Examples: {', '.join(examples)}"
                + (" ..." if distinct > len(examples) else "") + "\n\n"
                f"WHY THE SHAPE IS THE CLAIM, rather than the randomness of "
                f"any one name. A tunnel rides on ONE domain the attacker "
                f"registered, and its label changes with every chunk of data. "
                f"Content delivery is the opposite: many registered domains, "
                f"each with one hash in front of it. Measured for this check, "
                f"the entropy of a short encoded label is LOWER than that of "
                f"an ordinary word like windowsupdate, so no threshold on "
                f"randomness alone tells these apart. One domain carrying "
                f"{distinct} different encoded labels does.\n\n"
                f"THIS TOOL CANNOT READ THE PAYLOAD. It has measured that "
                f"these names are long, high-entropy and rotating under one "
                f"domain, and nothing about what they carry.\n\n"
                f"The ordinary explanation is a CDN, a signed-URL scheme or "
                f"an analytics vendor that put its customer's name under its "
                f"own domain. The test that settles it is whether "
                f"{registered} is a domain the operator recognises: query_dns "
                f"filtered on the client shows every name, and query_tls "
                f"shows what the device connected to afterwards."
            ),
            raw_data={"domain": registered,
                      "registered_domain": registered,
                      "client_ip": client_ip},
            detection_id="DNS-1003",
        )
        if result.get("saved"):
            raised += 1
            logger.warning(f"DNS-1003: {client_ip} sent {distinct} distinct "
                           f"encoded labels under {registered} in "
                           f"{DNS_ACTIVITY_WINDOW_HOURS}h.")

    return raised


def _client_window_totals(conn):
    """
    Per-client counts for the window, in ONE query.

    Returns (rows, note). `rows` is [(client_ip, total, nxdomain, txt)] and
    `note` is None or a sentence saying which halves of it could not be
    counted, because a NULL reply_type and "not NXDOMAIN" are different facts
    and the volume checks must not merge them.
    """
    note = None
    cutoff = _window_cutoff(DNS_ACTIVITY_WINDOW_HOURS)

    try:
        rows = conn.execute("""
            SELECT client_ip,
                   COUNT(*) AS total,
                   SUM(CASE WHEN reply_type = 'NXDOMAIN' THEN 1 ELSE 0 END)
                       AS nxdomain,
                   SUM(CASE WHEN query_type = 'TXT' THEN 1 ELSE 0 END)
                       AS txt,
                   SUM(CASE WHEN reply_type IS NULL THEN 1 ELSE 0 END)
                       AS no_reply_code,
                   SUM(CASE WHEN query_type IS NULL THEN 1 ELSE 0 END)
                       AS no_query_type
            FROM dns_queries
            WHERE queried_at >= ? AND client_ip IS NOT NULL
            GROUP BY client_ip
        """, (cutoff,)).fetchall()
    except Exception as e:
        return [], (f"the per-client totals could not be read ({e}), so "
                    f"volume, NXDOMAIN and TXT were NOT checked this pass")

    # THE COVERAGE SENTENCE. Both columns are populated by the Pi-hole reader
    # and NOT by the AdGuard one: AdGuard's querylog has no reply code and
    # this importer does not copy its query type into reply_type. So on an
    # AdGuard install the NXDOMAIN check has nothing to read, and the honest
    # answer is to say so once rather than to report zero failures as if the
    # resolver had answered everything.
    missing_reply = sum(r[4] or 0 for r in rows)
    missing_type = sum(r[5] or 0 for r in rows)
    totals = sum(r[1] or 0 for r in rows)
    if totals and missing_reply == totals:
        note = ("NO ROW in this window carries a reply code, so the NXDOMAIN "
                "check examined NOTHING. The Pi-hole reader supplies one and "
                "the AdGuard reader does not, which is the usual cause.")
    elif totals and missing_reply:
        note = (f"{missing_reply} of {totals} row(s) in this window carry no "
                f"reply code, so the NXDOMAIN share is computed over the rest "
                f"and is a FLOOR, not the whole picture.")
    if totals and missing_type:
        note = ((note + " " if note else "")
                + f"{missing_type} of {totals} row(s) carry no query type, so "
                  f"the TXT count is a floor as well.")
    return rows, note


def _median(values: list) -> float:
    """The middle value, or 0.0 for an empty list. No numpy, no imports."""
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _median_of_others(totals: dict, client_ip: str) -> float:
    """The median across every OTHER client's window total.

    THE SUBJECT IS EXCLUDED, and that is the whole reason this exists as a
    function rather than as the inline `_median(active)` it replaced. The two
    sentences this rule is published under both say "the median of the OTHER
    clients" -- the VOLUME_MEDIAN_FACTOR comment above and the
    query_dns_inspection description the model reads -- and the code computed
    the median over a list that INCLUDED the subject.

    MEASURED on a scratch store, driving the shipped check: on a two-client
    network, client A made 10000 queries and client B made 60. The code's
    median was 5030.0 (over 2 clients), so A had to reach 20120 to fire, and
    10000 raised NOTHING. The median of the OTHER clients is 60, and A clears
    60 * 4.0 = 240 by two orders of magnitude. THE DEFECT IS LARGEST ON THE
    SMALLEST NETWORK, which is the opposite of what a portable rule is for: a
    home network is one busy machine and one quiet one, and the subject's own
    weight in a two-sample median is half of it.

    Two details kept deliberately:

      * The MEDIAN FLOOR still applies, to the others rather than to the
        subject: an idle device beside a busy one must not drag the baseline
        to zero, and a client that clears the floor is the only kind that
        counts as a comparator. On the measured two-client example (A 10000,
        B 60) the neighbour clears the floor, the median of the others is 60,
        and A fires where the old code raised nothing. A neighbour BELOW the
        floor is not a comparator at all: with A 10000 and B 10 the median of
        the others is 0.0, so the check fires on nothing and SAYS SO in the
        note appended to `out`, because the absolute floor alone is not the
        claim this rule makes. That is the honest reading of one quiet
        neighbour, and it is named rather than silently swallowed.
      * The subject is excluded by ADDRESS, not by removing one index, so a
        client whose total ties with its neighbour still leaves the neighbour
        in the set.
    """
    others = [t for ip, (t, _nx, _tx) in totals.items()
              if ip != client_ip and t >= VOLUME_MEDIAN_FLOOR]
    return _median(others)


def _check_activity(conn, session_id: str) -> dict:
    """
    The three volume-shaped claims, over the same window as everything else.

    VOLUME (DNS-1004), NXDOMAIN BURST (DNS-1005) and TXT VOLUME (DNS-1006)
    share one query and one median, and they are raised separately because
    they are three different facts. A device can be top of the volume chart
    for entirely innocent reasons and still be the one asking for 900 names
    that do not exist.

    THE MEDIAN IS THE PART THAT TRAVELS. An absolute floor is right on the
    network it was chosen on. Comparing a client against the median of the
    OTHER clients on this network is what makes the claim portable, and both
    have to be cleared for volume, because either one alone fires on an
    ordinary machine doing an ordinary thing.

    Returns a dict of counts so the caller can log them without knowing which
    checks exist.
    """
    from core import memory_engine as me

    out = {"volume": 0, "nxdomain": 0, "txt": 0, "note": None,
           "clients_seen": 0}
    rows, note = _client_window_totals(conn)
    out["note"] = note
    if not rows:
        return out

    out["clients_seen"] = len(rows)
    totals = {r[0]: (r[1] or 0, r[2] or 0, r[3] or 0) for r in rows}

    # The median over clients that actually did something. See
    # VOLUME_MEDIAN_FLOOR for why an idle device must not drag it to zero.
    # This one figure is published for a reader; the check itself compares
    # each client against the median of the OTHERS, per client, because a
    # median that contains the subject is not the sentence this rule is
    # published under. See _median_of_others.
    active = [t for (t, _nx, _tx) in totals.values() if t >= VOLUME_MEDIAN_FLOOR]
    out["median_queries"] = _median(active)

    # A client with no qualifying OTHER client has no baseline to compare
    # against, and the rule says so rather than reporting a clean result.
    # Counted here and published below; see the note appended to `out`.
    no_comparator = []

    for client_ip, (total, nxdomain, txt) in sorted(totals.items()):
        median = _median_of_others(totals, client_ip)
        if total >= VOLUME_MIN_QUERIES and median <= 0:
            no_comparator.append(client_ip)

        # DNS-1004, volume.
        if (total >= VOLUME_MIN_QUERIES
                and median > 0
                and total >= median * VOLUME_MEDIAN_FACTOR):
            # THE TITLE NAMES THE CONDITION, NOT THE COUNT. finding_already_open
            # matches on the title, and this title used to carry the window
            # total -- measured on a scratch store, the SAME client in the SAME
            # condition wrote FOUR rows as the count drifted 250 -> 251 -> 252
            # -> 253. The number lives in the description, where it can grow
            # without changing the row's identity. Same shape for the tunnel,
            # NXDOMAIN and TXT titles below.
            title = f"Unusual DNS query volume from {client_ip}"
            if not _already_handled(client_ip, title):
                result = me.save_finding(
                    session_id=session_id,
                    source="dns_inspector",
                    severity=("medium" if total >= median * 8 else "low"),
                    entity_type="ip",
                    entity_value=client_ip,
                    title=title,
                    sensor_id=resolver_sensor_id(),
                    description=(
                        f"Queries in the last {DNS_ACTIVITY_WINDOW_HOURS}h: "
                        f"{total}\n"
                        f"The busiest ordinary client in this window made "
                        f"{int(median)} (the median of the OTHER clients that "
                        f"made more than {VOLUME_MEDIAN_FLOOR}; this client is "
                        f"not in its own baseline).\n"
                        f"Queries in the window that did not exist: "
                        f"{nxdomain}. TXT records: {txt}.\n\n"
                        f"A MEASUREMENT, NOT A CLASSIFICATION. A browser "
                        f"cache flushing, a distribution upgrade, a sync "
                        f"client re-indexing and a resolver loop all look "
                        f"exactly like this. What it is worth is as a place "
                        f"to start: query_dns narrows it to this address, "
                        f"and the names it asked for are the answer to "
                        f"whether this was ordinary."
                    ),
                    detection_id="DNS-1004",
                )
                if result.get("saved"):
                    out["volume"] += 1
                    logger.info(f"DNS-1004: {client_ip} made {total} queries "
                                f"in {DNS_ACTIVITY_WINDOW_HOURS}h (median of "
                                f"the others {int(median)}).")

        # DNS-1005, the failures.
        if total and nxdomain >= NXDOMAIN_MIN_COUNT:
            share = nxdomain / total
            if share >= NXDOMAIN_MIN_SHARE:
                title = f"Most of what {client_ip} asked for does not exist"
                if not _already_handled(client_ip, title):
                    result = me.save_finding(
                        session_id=session_id,
                        source="dns_inspector",
                        severity="medium",
                        entity_type="ip",
                        entity_value=client_ip,
                        title=title,
                        sensor_id=resolver_sensor_id(),
                        description=(
                            f"Names that returned NXDOMAIN in the last "
                            f"{DNS_ACTIVITY_WINDOW_HOURS}h: {nxdomain} of "
                            f"{total} ({share:.0%}).\n\n"
                            f"WHY THE SHARE MATTERS AS MUCH AS THE COUNT. A "
                            f"device that asks for a thousand names and gets "
                            f"a hundred misses is a busy device. A device "
                            f"where most of what it asks for does not exist "
                            f"is doing one of two things: a malware family "
                            f"hunting for the one controller domain that is "
                            f"still alive, or a real misconfiguration. The "
                            f"second is common and easy to check, a device "
                            f"whose search suffix points somewhere that does "
                            f"not resolve, or an app with a hardcoded "
                            f"internal name, produces exactly this and "
                            f"nobody notices.\n\n"
                            f"query_dns on this address shows the names, and "
                            f"the names usually settle which of the two it "
                            f"is in one look."
                        ),
                        detection_id="DNS-1005",
                    )
                    if result.get("saved"):
                        out["nxdomain"] += 1
                        logger.info(f"DNS-1005: {client_ip} had {nxdomain} of "
                                    f"{total} queries return NXDOMAIN.")

        # DNS-1006, TXT.
        if txt >= TXT_MIN_COUNT:
            title = f"Unusual TXT record volume from {client_ip}"
            if not _already_handled(client_ip, title):
                result = me.save_finding(
                    session_id=session_id,
                    source="dns_inspector",
                    severity="medium",
                    entity_type="ip",
                    entity_value=client_ip,
                    title=title,
                    sensor_id=resolver_sensor_id(),
                    description=(
                        f"TXT queries in the last "
                        f"{DNS_ACTIVITY_WINDOW_HOURS}h: {txt} of {total} "
                        f"queries from this device.\n\n"
                        f"TXT is a legitimate record type: mail "
                        f"authentication, domain verification and a few "
                        f"vendor lookups all use it. It is also the record "
                        f"type a resolver will carry arbitrary text in, which "
                        f"makes it the cheapest outbound channel on a network "
                        f"where DNS is the only thing that reliably gets "
                        f"out.\n\n"
                        f"WHAT WAS MEASURED AND WHAT WAS NOT: the count of "
                        f"queries, and nothing about their content. This tool "
                        f"does not read what the records said. query_dns "
                        f"shows the names, and the names are where a "
                        f"legitimate pattern is recognised."
                    ),
                    detection_id="DNS-1006",
                )
                if result.get("saved"):
                    out["txt"] += 1
                    logger.info(f"DNS-1006: {client_ip} made {txt} TXT "
                                f"queries in {DNS_ACTIVITY_WINDOW_HOURS}h.")

    # THE COMPARISON THAT COULD NOT BE MADE, named rather than left as a
    # quiet pass. A client past the absolute floor whose neighbours are all
    # below VOLUME_MEDIAN_FLOOR has no baseline: the median of the others is
    # 0.0, the both-conditions test above cannot be satisfied, and the honest
    # answer is a sentence saying so -- not a clean bill and not a finding.
    # MEASURED before this existed: on a two-client network (one at 10000
    # queries, one at 60) the published rule fired NOTHING and said nothing
    # about why, because the old median contained the subject.
    if no_comparator:
        out["no_comparator"] = len(no_comparator)
        sentence = (f"{len(no_comparator)} client(s) past the "
                    f"{VOLUME_MIN_QUERIES}-query floor had NO comparison "
                    f"baseline in this window (no other client reached "
                    f"VOLUME_MEDIAN_FLOOR={VOLUME_MEDIAN_FLOOR}), so the "
                    f"volume rule could not be evaluated for them: "
                    f"{', '.join(sorted(no_comparator))}. The absolute floor "
                    f"alone is not the claim this check makes.")
        out["note"] = (out["note"] + " " if out["note"] else "") + sentence

    return out


def _check_beacons(conn, session_id: str, pairs: list = None) -> int:
    """
    Find (client, domain) pairs whose query cadence is too regular for a human.

    Looks at the last BEACON_WINDOW_HOURS of data for every (client, domain)
    pair that has at least BEACON_MIN_COUNT queries in that window.

    Returns the number of new findings raised.

    THE datetime IMPORT IS PART OF THIS FUNCTION, and it went missing in the
    port. The twin builds its cutoff inline (`datetime.now(timezone.utc) -
    timedelta(hours=...)`) and imports the three names at the top of this very
    function; the port replaced that line with `_window_cutoff(...)` -- which
    is the right call, it is the funnel -- and took the import with it, while
    the timestamp PARSING below still calls datetime.fromisoformat. So the
    exception was a NameError on the first candidate, raised inside
    analyse_once's try, and DNS-1002 HAS NEVER FIRED ON THIS HOST. MEASURED
    by driving the shipped check: "DNS inspection error: name 'datetime' is
    not defined", with the traceback pointing at this line.

    The lesson is the one this tree keeps recording: replacing a line is not
    the same as replacing what the line DEPENDED ON, and an import is the
    dependency nobody looks at because it has no behaviour.
    """
    from core import memory_engine as me

    raised = 0
    for client_ip, domain, cnt, mean_interval, stddev, cv in (
            pairs if pairs is not None else _beacon_pairs(conn)):
        title = f"DNS beacon: {client_ip} polls {domain} on schedule"
        if _already_handled(client_ip, title):
            continue

        result = me.save_finding(
            session_id=session_id,
            source="dns_inspector",
            severity="medium",
            entity_type="ip",
            entity_value=client_ip,
            title=title,
            sensor_id=resolver_sensor_id(),
            description=(
                f"Domain: {domain}\n"
                f"Queries in last {BEACON_WINDOW_HOURS}h: {cnt}\n"
                f"Mean interval: {mean_interval:.0f}s, "
                f"stddev: {stddev:.0f}s, CV: {cv:.3f}\n"
                f"A CV below {BEACON_CV_CEILING} means the interval is more "
                f"regular than human browsing. Normal causes include backup "
                f"agents and system updaters. Confirm the process querying "
                f"this name is expected."
            ),
            raw_data={"domain": domain,
                      "registered_domain": _registered_domain(domain),
                      "client_ip": client_ip},
            detection_id="DNS-1002",
        )
        if result.get("saved"):
            raised += 1
            logger.info(
                f"DNS-1002: beacon {domain!r} from {client_ip}, "
                f"{cnt} queries, mean {mean_interval:.0f}s, CV {cv:.3f}"
            )

    return raised


def _beacon_pairs(conn) -> list:
    """(client, domain, count, mean, stddev, cv) for every pair in the beacon
    window whose cadence is too regular for a human."""
    # Parsing the stored stamps needs these; the CUTOFF does not, it goes
    # through the funnel. Do not delete this as unused.
    from datetime import datetime, timezone

    cutoff = _window_cutoff(BEACON_WINDOW_HOURS)
    candidates = conn.execute("""
        SELECT client_ip, domain, COUNT(*) as cnt
        FROM dns_queries
        WHERE queried_at >= ? AND client_ip IS NOT NULL AND domain IS NOT NULL
        GROUP BY client_ip, domain
        HAVING cnt >= ?
    """, (cutoff, BEACON_MIN_COUNT)).fetchall()

    out = []
    for client_ip, domain, cnt in candidates:
        if _is_local_name(domain):
            continue
        ts_rows = conn.execute("""
            SELECT queried_at FROM dns_queries
            WHERE client_ip = ? AND domain = ? AND queried_at >= ?
            ORDER BY queried_at ASC
        """, (client_ip, domain, cutoff)).fetchall()
        timestamps = []
        for (ts_str,) in ts_rows:
            if not ts_str:
                continue
            try:
                # Accept ISO strings with or without timezone.
                ts_str = ts_str.replace("Z", "+00:00")
                dt = datetime.fromisoformat(ts_str)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                timestamps.append(dt.timestamp())
            except (ValueError, AttributeError):
                continue
        if len(timestamps) < BEACON_MIN_COUNT:
            continue
        intervals = [timestamps[i + 1] - timestamps[i]
                     for i in range(len(timestamps) - 1)]
        if len(intervals) < 2:
            continue
        mean_interval = statistics.mean(intervals)
        if mean_interval < BEACON_MIN_INTERVAL_SECS:
            # Too fast: this is a burst, not a scheduled poll.
            continue
        stddev = statistics.stdev(intervals)
        cv = stddev / mean_interval if mean_interval > 0 else 1.0
        if cv > BEACON_CV_CEILING:
            # Too irregular to call a beacon.
            continue
        out.append((client_ip, domain, cnt, mean_interval, stddev, cv))
    return out


def _name_clause(name: str, registered: bool) -> tuple:
    """SQL for rows asking for this name, or anything under it."""
    if registered:
        return "(domain = ? OR domain LIKE ?)", (name, f"%.{name}")
    return "domain = ?", (name,)


def _device_label(conn, ip: str) -> str:
    row = conn.execute(
        "SELECT known_as, hostname, vendor FROM known_devices WHERE ip = ? "
        "AND merged_into IS NULL AND retired_at IS NULL ORDER BY "
        "identified_by = 'user' DESC LIMIT 1", (ip,)).fetchone()
    name = next((v for v in (row or ()) if v), None)
    return f"{name} ({ip})" if name else ip


def _check_spread(conn, session_id: str, pairs: list) -> dict:
    """
    DNS-1007. Several devices polling one destination on a timer, when that
    destination is new in the house and few devices ever asked for it: one
    controller reaching more than one device. Raised high, so it is never
    held by a learned rule or sorted by the model.
    """
    from core import memory_engine as me
    from datetime import datetime, timedelta, timezone

    out = {"raised": 0, "unjudged": None}
    by_name: dict = {}
    for client_ip, domain, cnt, mean_interval, _sd, _cv in pairs:
        reg = _registered_domain(domain)
        if reg:
            by_name.setdefault(reg, {})[client_ip] = (domain, cnt,
                                                      mean_interval)
    shared = {k: v for k, v in by_name.items()
              if len(v) >= SPREAD_MIN_DEVICES}
    if not shared:
        return out

    new_since = (datetime.now(timezone.utc) - timedelta(days=SPREAD_NEW_DAYS)) \
        .strftime("%Y-%m-%dT%H:%M:%S+00:00")
    oldest = conn.execute("SELECT MIN(queried_at) FROM dns_queries").fetchone()
    if not oldest or not oldest[0] or oldest[0] > new_since:
        # Too little history to call anything new; said, not guessed.
        out["unjudged"] = (f"{len(shared)} destination(s) polled by several "
                           f"devices, but the DNS record is younger than "
                           f"{SPREAD_NEW_DAYS} days, so whether they are new "
                           f"here cannot be judged yet")
        return out

    for reg, devices in shared.items():
        where, args = _name_clause(reg, True)
        first, ever = conn.execute(
            f"SELECT MIN(queried_at), COUNT(DISTINCT client_ip) FROM "
            f"dns_queries WHERE {where}", args).fetchone()
        if not first or first < new_since or ever > SPREAD_RARE_DEVICES:
            continue
        labels = {ip: _device_label(conn, ip) for ip in devices}
        title = f"Several devices call {reg} on a timer"
        for ip, (domain, cnt, mean_interval) in devices.items():
            if _already_handled(ip, title):
                continue
            others = ", ".join(labels[o] for o in devices if o != ip)
            result = me.save_finding(
                session_id=session_id, source="dns_inspector",
                severity="high", entity_type="ip", entity_value=ip,
                title=title, sensor_id=resolver_sensor_id(),
                description=(
                    f"{labels[ip]} looks up {domain} every "
                    f"{mean_interval:.0f}s ({cnt} times in "
                    f"{BEACON_WINDOW_HOURS}h). So do: {others}.\n"
                    f"{reg} was first asked for here on {first[:16]} and "
                    f"only {ever} device(s) have ever asked for it. One new, "
                    f"rare server checked in on by several devices is how "
                    f"one intruder controlling more than one device looks. "
                    f"Find what on each device makes these lookups."),
                raw_data={"domain": domain, "registered_domain": reg,
                          "client_ip": ip, "devices": sorted(devices),
                          "first_seen": first, "devices_ever": ever},
                detection_id="DNS-1007")
            if result.get("saved"):
                out["raised"] += 1
                logger.warning(f"DNS-1007: {len(devices)} devices poll {reg}")
    return out


def _rule_device_ips(conn, match: dict) -> set:
    """The addresses of the device a rule is pinned to, if it is pinned."""
    raw = match.get("raw") or {}
    ips = {v for v in (match.get("entity"), raw.get("client_ip"),
                       raw.get("src_ip")) if v}
    mac = raw.get("subject")
    if mac:
        ips |= {r[0] for r in conn.execute(
            "SELECT ip FROM known_devices WHERE lower(mac) = lower(?)",
            (mac,))}
    return ips


def _check_held_spread(conn, session_id: str) -> int:
    """
    DNS-1008. A destination a learned rule holds back starts being reached by
    another device. Raised once per rule, naming every new device, because a
    quiet rule must not hide a destination spreading through the house.
    """
    import fnmatch
    import json
    from core import learned_rules
    from core import memory_engine as me

    if not me._table_exists_ro(conn, "learned_rule"):
        return 0
    raised = 0
    rules = conn.execute(
        "SELECT id, detection_id, match_json, created_at, reason FROM "
        "learned_rule WHERE status = 'on' AND (trial_until IS NULL OR kept_at "
        "IS NOT NULL OR trial_until > ?)", (learned_rules._iso(),)).fetchall()
    for rid, did, match_json, created_at, reason in rules:
        title = f"A destination learned rule {rid} holds back is reached by more devices"
        if conn.execute("SELECT 1 FROM findings WHERE detection_id = "
                        "'DNS-1008' AND title = ? LIMIT 1",
                        (title,)).fetchone():
            continue                                # once per rule, ever
        try:
            match = json.loads(match_json)
        except ValueError:
            continue
        raw = match.get("raw") or {}
        key = next((k for k in HELD_NAME_KEYS if raw.get(k)), None)
        if not key:
            continue
        pattern = str(raw[key]).lower()
        registered = key == "registered_domain"
        if any(c in pattern for c in "*?["):
            literal = pattern.replace("*", "%").replace("?", "_")
            where, args = "domain LIKE ?", ("%" + literal.lstrip("%"),)
        else:
            where, args = _name_clause(pattern, registered)
        own = _rule_device_ips(conn, match)
        fresh = []
        for client_ip, domain, first in conn.execute(
                f"SELECT client_ip, MIN(domain), MIN(queried_at) FROM "
                f"dns_queries WHERE {where} AND client_ip IS NOT NULL "
                f"GROUP BY client_ip", args):
            name = _registered_domain(domain) if registered else domain
            if client_ip in own or not fnmatch.fnmatchcase(
                    (name or "").lower(), pattern):
                continue
            if first and first > created_at:
                fresh.append((client_ip, first))
        if not fresh:
            continue
        fresh.sort(key=lambda x: x[1])
        names = ", ".join(f"{_device_label(conn, ip)} from {at[:16]}"
                          for ip, at in fresh)
        result = me.save_finding(
            session_id=session_id, source="dns_inspector", severity="medium",
            entity_type="ip", entity_value=fresh[0][0], title=title,
            sensor_id=resolver_sensor_id(),
            description=(
                f"Learned rule {rid} ({did}) holds back {key} {pattern}: "
                f"{reason}. Since it was made on {created_at[:16]}, devices "
                f"that never asked for it before now do: {names}. Check "
                f"that these devices should reach it; if not, undo the rule "
                f"on the Expectations tab."),
            raw_data={"registered_domain" if registered else "domain":
                      pattern, "client_ip": fresh[0][0], "rule_id": rid,
                      "devices": [ip for ip, _ in fresh]},
            detection_id="DNS-1008")
        if result.get("saved"):
            raised += 1
            logger.warning(f"DNS-1008: rule {rid} destination reached by "
                           f"{len(fresh)} new device(s)")
    return raised


def analyse_once(config: dict, session_id: str) -> dict:
    """
    One inspection pass over the DNS query table.

    Called after each import batch in the DNS importer loop. Returns a dict
    whose 'ran' key is the only reliable signal to the caller:

      ran=True   the table was inspectable, findings may or may not have fired
      ran=False  we could not inspect, reason says why

    This is the whole of rule two for this module: "found nothing" and "could
    not look" must come back as different keys, not different wording in a
    shared field.
    """
    from tools import dns_monitor
    from core import memory_engine as me

    dns_state = dns_monitor.status(config)
    if not dns_state.get("available"):
        return {
            "ran": False,
            "reason": "dns_monitor not available",
            "dga_findings": 0,
            "beacon_findings": 0,
            "tunnel_findings": 0,
            "activity": {},
        }

    cursor = _get_cursor()

    try:
        with me._get_conn() as conn:
            # Highest ID currently in the table.
            max_id_row = conn.execute(
                "SELECT MAX(id) FROM dns_queries"
            ).fetchone()
            max_id = max_id_row[0] if max_id_row and max_id_row[0] else 0

            if max_id == 0:
                return {
                    "ran": True,
                    "reason": "dns_queries is empty",
                    "dga_findings": 0,
                    "beacon_findings": 0,
                    "tunnel_findings": 0,
                    "activity": {},
                    "cursor_before": cursor,
                    "cursor_after": cursor,
                }

            dga_found = _check_dga(conn, since_id=cursor, session_id=session_id)
            pairs = _beacon_pairs(conn)
            beacon_found = _check_beacons(conn, session_id=session_id,
                                          pairs=pairs)
            spread = _check_spread(conn, session_id, pairs)
            held_spread = _check_held_spread(conn, session_id)
            # THE TWO NEW FAMILIES, 2026-09-22. Both are windowed on the whole
            # table rather than cursor-based, and both are idempotent by
            # finding_already_open: they describe a STATE of the last four
            # hours rather than a change since the last pass, so a per-row
            # cursor would be the wrong instrument. The titles carry the
            # client and the numbers, so a re-run over the same window
            # collapses onto the same open finding instead of stacking rows.
            tunnel_found = _check_tunnels(conn, session_id=session_id)
            activity = _check_activity(conn, session_id=session_id)

    except Exception as e:
        logger.error(f"DNS inspection error: {e}", exc_info=True)
        return {
            "ran": False,
            "reason": str(e),
            "dga_findings": 0,
            "beacon_findings": 0,
            "tunnel_findings": 0,
            "activity": {},
        }

    activity_total = sum(activity.get(k, 0)
                         for k in ("volume", "nxdomain", "txt"))
    _set_cursor(max_id)
    logger.info(
        f"DNS inspection: DGA={dga_found}, beacon={beacon_found}, "
        f"spread={spread['raised']}, held spread={held_spread}, "
        f"tunnel={tunnel_found}, volume/nxdomain/txt="
        f"{activity.get('volume', 0)}/{activity.get('nxdomain', 0)}/"
        f"{activity.get('txt', 0)} over {activity.get('clients_seen', 0)} "
        f"client(s); cursor {cursor} -> {max_id}"
    )
    if activity.get("note"):
        logger.warning(f"DNS inspection coverage: {activity['note']}")
    if spread.get("unjudged"):
        logger.info(f"DNS-1007: {spread['unjudged']}")
    return {
        "ran": True,
        "reason": None,
        "dga_findings": dga_found,
        "beacon_findings": beacon_found,
        "spread_findings": spread["raised"],
        "spread_unjudged": spread.get("unjudged"),
        "held_spread_findings": held_spread,
        "tunnel_findings": tunnel_found,
        "activity_findings": activity_total,
        "activity": activity,
        "cursor_before": cursor,
        "cursor_after": max_id,
    }
