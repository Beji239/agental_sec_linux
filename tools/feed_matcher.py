# tools/feed_matcher.py
# AgentalSec V2, TODO 113.4. Known-bad feeds, matched continuously.
#
# WHAT CHANGES HERE, COMPARED TO WHAT WE ALREADY HAD
#
# core/enrichment.py already talks to abuse.ch. It asks about ONE address, when
# somebody (usually the model) asks about that address. That is a lookup.
#
# This is the other shape: pull the whole list down once, keep it locally, and
# check EVERY outbound destination against it as the traffic arrives. Nobody
# has to think to ask. The cost is a few thousand rows in the database and one
# HTTP fetch per feed per refresh window.
#
# THREE SURFACES GET MATCHED, because a bad destination shows up in three
# different places in this app and only one of them is the IP:
#
#   packets.dst_ip      outbound connections, the plain case
#   dns_queries.domain  the name was resolved, maybe the connection followed
#   tls_hello.sni       the name inside the handshake, which survives even
#                       when DNS went somewhere this app cannot see (DoH)
#
# The SNI one is the reason 113.2 was worth doing. A device using encrypted DNS
# hides its lookups from the resolver logs, but the ClientHello still says the
# name in the clear.
#
# RULE TWO, AND THIS MODULE IS THE WORST PLACE TO GET IT WRONG
#
# A feed matcher that could not download its feed will match everything against
# an empty set and find nothing. That reads EXACTLY like a clean network. It is
# the single most dangerous false-calm this app could produce, because the
# quieter it is the more broken it is.
#
# So: match_once returns ran=False when the feed table is empty or has never
# been refreshed. Not ran=True with zero matches. Those are different sentences
# and they stay different at every return path, and status() carries
# feed_age_hours and stale so a reader can tell coverage from cleanliness
# without having to know how this file works.
#
# WHY THE TABLE DOES NOT GROW
#
# A refresh REPLACES that feed's rows, it does not append. So threat_feed
# stays roughly the size of the live feeds forever instead of accumulating
# every indicator abuse.ch has ever published. There is also a per-feed cap,
# so a feed that suddenly publishes a million rows cannot take the database
# with it. This database is already large and none of that is this file's to
# spend.
#
# MISP AND OTX, ADDED 2026-09-23, AND WHY ONE OF THEM IS NOT THE OTHER
#
# The owner's item was "two big community threat feeds", filed beside abuse.ch
# as "more of the same". Measured on this host before a line was written, and
# the two halves are NOT the same shape:
#
#   MISP (CIRCL's OSINT feed, misp.circl.lu) is KEYLESS and can be mirrored
#   like abuse.ch, but it is NOT a list. It is an event archive: a manifest of
#   1,681 events and one JSON file per event, and the files are large --
#   MEASURED at 2.0 MB average, 30 MB for 15 events, 55 MB and 189 seconds for
#   the 40 newest. So it cannot be pulled whole on a 6 hour clock, and this
#   fetcher does not try: it reads the MANIFEST, sorts by the manifest's own
#   timestamp, and fetches the N NEWEST events (default 15, configurable).
#   That is a bounded, honest subset and every surface says so.
#
#   OTX (AlienVault) is NOT a keyless feed at all. MEASURED: every bulk
#   endpoint -- /pulses/subscribed, /pulses/activity, a pulse's indicator list
#   -- answers "Authentication required" with no key. Only the per-indicator
#   lookup and an individual public pulse object work keyless, and neither is
#   a way to mirror a feed. So OTX is written as a KEYED feed
#   (AGENTAL_OTX_KEY) whose absence produces a reason naming the variable,
#   exactly like abuse.ch's own key -- NOT an empty list, which would read as
#   a clean network checked against nothing.
#
# THE ENVELOPE. The MISP manifest and event shapes were read from the live
# service. OTX's /pulses/subscribed envelope could NOT be, because that
# endpoint is one of the ones that refuses without a key, so _parse_otx_pulses
# accepts a bare list AND the {"results": [...]} wrapper rather than assuming
# one, and says in words when it got neither. A guess written as a parser is
# how a feed silently yields zero indicators forever.
#
# PRIVATE ADDRESSES ARE DROPPED, AND THAT IS A MEASURED FILTER, NOT A WORRY.
# The CIRCL OSINT events list 192.0.2.1 and 192.0.2.5 among their indicators --
# somebody's lab, or a mis-tagged internal address. This host's own gateway is
# 192.0.2.1. Storing that row would make every connection to the operator's own
# router match a community C2 list at high severity, which is a false positive
# generator built out of somebody else's typo. So an indicator that is not
# GLOBALLY routable is not stored, and the count dropped is reported rather
# than swallowed, because "not listed" must not quietly mean "we dropped it".

import logging
import os
import re
import threading
import time

logger = logging.getLogger(__name__)

# constants

# How often to re-pull the feeds. abuse.ch updates Feodo every 5 minutes and
# URLhaus continuously, but pulling hourly is plenty for a home network and is
# polite to a free service.
#
# MISP IS THE REASON THIS NUMBER IS NOT SMALLER. A MISP refresh fetches up to
# `misp_max_events` event files at a MEASURED 2.0 MB each, so the default 15
# is ~30 MB and about 100 seconds of download per refresh. On a six hour clock
# that is four refreshes a day. Asking for it hourly would be 750 MB a day
# from a free university service, which is the kind of thing that gets a
# project blocked rather than throttled -- so the cadence is a politeness
# decision as much as a cost one, and the per-feed event cap is the other half
# of it.
DEFAULT_REFRESH_HOURS = 6

# THE MISP WINDOW. See the header: the archive is 1,681 events and cannot be
# mirrored, so the newest N are read from the manifest on every refresh.
# Measured sizes are in the header comment. 15 events / ~30 MB / ~100 s at the
# default cadence; the ceiling stops a config edit from turning a boot into a
# gigabyte of download.
MISP_MAX_EVENTS_DEFAULT = 15
MISP_MAX_EVENTS_CEILING = 60
MISP_MANIFEST_URL = "https://www.circl.lu/doc/misp/feed-osint/manifest.json"
MISP_EVENT_URL = "https://www.circl.lu/doc/misp/feed-osint/{uuid}.json"

# How many pulses to walk when OTX does have a key. Smaller than the MISP
# default on purpose: a pulse carries its indicators INSIDE the same response
# (measured: 86 indicators in one public pulse), so one request is worth a
# pulse rather than a file, and 20 pulses is a few hundred indicators.
OTX_MAX_PULSES_DEFAULT = 20
OTX_MAX_PULSES_CEILING = 100

# Past this age the feed still gets used, but matches drop to medium and the
# status says stale. An old feed is not a useless feed, it is a feed that may
# have missed the last few days of C2 rotation.
FEED_STALE_HOURS = 48

# Per-feed row cap. Keeps one misbehaving feed from eating the budget.
MAX_INDICATORS_PER_FEED = 60000

# HTTP
# (connect, first byte). CIRCL took 29s to its first byte on 2026-09-27 (FM-7).
HTTP_TIMEOUT = (15, 60)
# One response may not exceed these, whoever answers (FM-2). The largest live
# feed measured 2.9 MB on 2026-09-27.
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_RESPONSE_SECONDS = 120
MAX_REDIRECTS = 3
USER_AGENT = "AgentalSec/2 (+homelab security agent; contact via operator)"

# Bookmark keys.
#
# THEY ARE NOT IN user_preferences ANY MORE, and the names are unchanged on
# purpose. See the section below this one: these are keys in the feed_cursor
# table now (schema v46), and keeping the same names means a reader comparing
# two databases sees the same bookmark rather than a new one.
_CUR_PACKETS = "feed_match_cursor_packets"
_CUR_DNS = "feed_match_cursor_dns"
_CUR_TLS = "feed_match_cursor_tls"
# THE REFRESH TIME IS A BOOKMARK TOO, and it took a second pass to see it.
# v46 moved the three cursors out of user_preferences and LEFT THIS ONE BEHIND,
# so a successful refresh still wrote it into the table core/integrity digests
# as THE POLICY. MEASURED on a copy of the live database, after the v46 move:
# one real refresh_once moved the digest and journalled a config_observed row
# whose payload carried 'feed_last_refresh_at': '2026-09-23T07:59:08+00:00'.
# Same defect, same table, one key later -- the shape T2's watcher cursor and
# L3's baselines each already paid for. It lives in feed_cursor now, by the
# same name, and the v46 migration deletes the old row.
_LAST_REFRESH = "feed_last_refresh_at"

# THIS MODULE'S BOOKKEEPING HAS ITS OWN TABLE. v46, 2026-09-23.
#
# The four names above used to be rows in user_preferences, and that is the
# defect T2's watcher cursor and L3's baselines each already paid for. The
# evidence is worth reading because this file was the third one, not the
# first:
#
#   core/integrity.snapshot_config DIGESTS user_preferences as THE POLICY and
#   journals a `config_observed` entry on ANY difference, on the contract that
#   such an entry ALWAYS means the rules changed. match_once advances three
#   cursors on EVERY pass -- every five minutes by default -- so a running
#   matcher wrote a false "the policy in user_preferences has CHANGED" warning
#   into the tamper journal, carrying a JSON blob of feed cursor numbers, in
#   the one record whose whole value is that it does not cry wolf.
#
# MEASURED, on a copy of the live database, before this was changed: writing
# one cursor moved the digest and produced a config_observed row whose payload
# contained 'feed_match_cursor_packets': '123456789'. The live database holds
# 9 config_observed rows and every one of them named a real event (boot,
# retention setup, rollup) -- so the false entries would have been the only
# ones in the journal that meant nothing.
#
# A table rather than a prefix excluded from the digest, for the reason
# local_integrity's migration gives at length: excluding a key pattern would
# make "the policy" mean "user_preferences except the ones starting with
# feed_", which is a rule living in a string comparison that the next person
# has to know about. A table that is not user_preferences cannot be confused
# for policy by anything.
_CURSOR_TABLE = "feed_cursor"
_LAST_RESULT = "feed_last_result"

# Addresses we never raise on, whatever a feed says. A feed listing an RFC1918
# address is a feed bug, not a finding about the owner's LAN, and 0.0.0.0 shows up in
# hostfile-format feeds as the sinkhole target rather than as an indicator.
#
# THIS SET IS NOW THE FALLBACK AND _is_matchable_ip IS THE RULE, added
# 2026-09-23. Four fixed addresses was never a filter, it was a note about the
# four somebody had seen: every parse path now ALSO refuses anything that is
# not globally routable -- 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16,
# 100.64/10 and the documentation ranges -- because a community feed listing
# an internal address (the CIRCL events do, measured: 192.0.2.1, which is this
# host's own gateway) would otherwise raise a HIGH severity finding on the
# operator's own router traffic.
_NEVER_MATCH_IPS = frozenset(["0.0.0.0", "127.0.0.1", "255.255.255.255", "::1"])

# Same idea on the domain side. Hostfile feeds carry these as filler.
_NEVER_MATCH_DOMAINS = frozenset(["localhost", "localhost.localdomain",
                                  "local", "broadcasthost"])

# SHARED HOSTS. Where the PARENT match has to stop. TODO 120, 2026-09-20.
#
# _feed_hit_domain walks a name up to its parents, so "a.b.evil.com" matches a
# feed listing "evil.com". That is right when one person owns evil.com and
# wrong when the parent is a hosting platform: thousands of unrelated people
# own a name under blogspot.com or a .workers.dev subdomain, and feeds DO
# occasionally carry the bare root, by mistake or as shorthand.
#
# One bad row in a feed would then fire a HIGH severity finding on every
# subdomain of a platform the owner uses. These are the only detections in the app
# allowed to be high, on the argument that somebody with far more visibility
# than one home network published the address. That argument does not survive
# being applied to an entire hosting provider.
#
# THE RULE IS NARROW ON PURPOSE. An EXACT match on any of these still fires,
# because a feed listing "evil.pages.dev" means that name. Only the walk
# UPWARDS stops here, and when it stops it is logged, because a listed name
# that produced no finding is exactly the kind of quiet worth explaining.
#
# Not a complete list and it does not need to be. It is the platforms a home
# network actually touches plus the dynamic DNS providers malware favours.
_SHARED_HOST_ROOTS = frozenset([
    # blog and site builders
    "blogspot.com", "wordpress.com", "tumblr.com", "weebly.com",
    "wixsite.com", "squarespace.com", "myshopify.com", "000webhostapp.com",
    # code and app hosting
    "github.io", "gitlab.io", "herokuapp.com", "appspot.com", "web.app",
    "firebaseapp.com", "netlify.app", "vercel.app", "pages.dev",
    "workers.dev", "glitch.me", "repl.co", "replit.dev", "onrender.com",
    "fly.dev", "azurewebsites.net", "cloudapp.azure.com", "amazonaws.com",
    "cloudfront.net", "digitaloceanspaces.com", "r2.dev",
    # tunnels, which malware uses and so do developers
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "serveo.net",
    "loca.lt", "localtunnel.me",
    # dynamic DNS
    "duckdns.org", "no-ip.com", "no-ip.org", "ddns.net", "hopto.org",
    "zapto.org", "sytes.net", "myftp.org", "serveftp.com", "dynu.com",
    "chickenkiller.com", "mooo.com",
    # file and content hosts
    "googleusercontent.com", "dropboxusercontent.com", "sharepoint.com",
    "discordapp.net", "discordapp.com", "pastebin.com", "transfer.sh",
    "anonfiles.com",
])


def _is_shared_host(domain: str) -> bool:
    """Is this a multi-tenant root that many unrelated people sit under."""
    return (domain or "").lower() in _SHARED_HOST_ROOTS


def _is_matchable_ip(value: str) -> bool:
    """
    Would raising on this address be a statement about the world or about home.

    THE RULE, ADDED 2026-09-23, and it is not the fixed four-address list it
    replaces. A known-bad list is a list of things on the INTERNET. An address
    that is not globally routable cannot be one of them: it is somebody's lab,
    a mis-tagged internal address, or the sinkhole target of a hosts file, and
    the operator's own gateway (192.0.2.1) is a real example measured in the
    CIRCL OSINT events. Storing such a row makes every ordinary connection to
    the router match a community C2 list at high severity.

    `is_global` IS THE RIGHT PREDICATE AND IT IS NOT ENOUGH ON ITS OWN.
    MEASURED on this host's Python 3.12:

        192.0.2.1     is_global=False   <- refused, correct
        127.0.0.1    is_global=False   <- refused, correct
        100.64.0.1   is_global=False   <- refused, correct
        224.0.0.1    is_global=True    <- MULTICAST, and it got through
        ff02::1      is_global=True    <- MULTICAST, and it got through

    `is_global` answers "is this in the global unicast space", and multicast
    addresses are global-scope by design, so 224.0.0.0/4 and ff00::/8 pass it.
    A feed listing a multicast group address is either a mistake or a group
    somebody is abusing, and in NEITHER case is it an address this app should
    raise a high severity finding about: nothing "connects to" 224.0.0.1 in a
    way a packet destination can describe. Found by this file's own test, not
    by reading the standard library.

    Returns False for anything that is not an address at all, so the callers
    never have to parse twice.
    """
    import ipaddress

    value = (value or "").strip()
    if not value:
        return False
    if value in _NEVER_MATCH_IPS:
        return False
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    if addr.is_multicast:
        return False
    return bool(addr.is_global)


def _canonical_ip(value: str) -> str:
    """The address as the packet record spells it, or "" if not matchable.

    Stored rows are compared to packet addresses as strings, so an IPv6 row in
    another spelling would never match (FM-3).
    """
    import ipaddress
    if not _is_matchable_ip(value):
        return ""
    return str(ipaddress.ip_address(value.strip()))


def _host_rows(value: str, family: str) -> list:
    """
    A domain, hostname or URL indicator as rows of the right type.

    A URL whose host is an address is an IP indicator. Filing it as a domain
    made it unmatchable: 140 live rows were stored that way (FM-1).
    """
    import ipaddress
    raw = str(value or "").strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    host = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    host = host.rsplit("@", 1)[-1]
    if host.startswith("["):
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:
        host = host.split(":", 1)[0]
    try:
        ipaddress.ip_address(host)
        ip = _canonical_ip(host)
        return [(ip, "ip", family)] if ip else []
    except ValueError:
        pass
    domain = _clean_domain(host)
    if domain and domain not in _NEVER_MATCH_DOMAINS:
        return [(domain, "domain", family)]
    return []


# THE FEEDS
#
# Declared rather than coded, so adding or dropping a feed is a dict entry and
# not a new branch in the refresh loop. Each one says what it gives, how to
# read it, and whether it needs the abuse.ch key.
#
# ON THE KEY: abuse.ch moved its downloads behind an Auth-Key. The key is the
# same one enrichment already uses (AGENTAL_ABUSECH_KEY). We send it on every
# request and a 401 comes back as a plain reason string rather than as silence,
# because a feed that is refusing us must not look like a feed that is clean.
#
# THE FOUR FIELDS EVERY ENTRY CARRIES, and the fourth is the one that matters:
#
#   url        where the list comes from
#   kind       'ip', 'domain', or 'mixed' -- what it lists, for the summary
#   parser     which function turns the response into rows
#   needs_key  True / False, or the NAME OF THE ENVIRONMENT VARIABLE
#
# `needs_key` USED TO BE A BOOLEAN AND THAT WAS FINE FOR ONE KEY. abuse.ch has
# one key and every feed that needed a key needed the same one, so a bool said
# everything there was to say. OTX has its own key, so a bool would have made
# "this feed needs a key" true while "which key" was unanswerable -- and the
# failure that produces is a fetcher that sends the abuse.ch key to OTX, gets a
# 403, and reports it as a bad key. A string is the variable's name, and the
# three shapes are read by _key_for_feed: False means none, a string means that
# variable (a bool True is kept as an alias for the abuse.ch key, because the
# three existing entries and their tests read it that way).

FEEDS = {
    "feodo": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "kind": "ip",
        "parser": "lines_ip",
        "needs_key": True,
        "gives": "Botnet C2 servers that Feodo Tracker currently lists as active.",
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "kind": "domain",
        "parser": "hostfile",
        "needs_key": True,
        "gives": "Hosts currently serving malware, in hosts-file format.",
    },
    "threatfox": {
        "url": "https://threatfox.abuse.ch/export/csv/recent/",
        "kind": "mixed",
        "parser": "threatfox_csv",
        # KEYLESS, MEASURED 2026-09-27. It read True -- the abuse.ch key -- and
        # never had to, because the plaintext export answers without one.
        # MEASURED on this host with AGENTAL_ABUSECH_KEY unset:
        #     https://threatfox.abuse.ch/export/csv/recent/  -> HTTP 200, 2.86 MB
        # while the LIVE STORE's own last_result for this feed read
        # "no key set for this feed. Put AGENTAL_ABUSECH_KEY in .env and
        # restart." and its row count had frozen at whatever the last keyed
        # fetch left (6,952 rows against a live body of 8,925).
        #
        # THE FLAG WAS NOT ONLY REFUSING A FETCH, IT WAS ALSO SENDING THE KEY
        # TO A THIRD PARTY. A declared key is a header this module writes; with
        # no key declared, nothing about the operator's abuse.ch credential is
        # sent to a service that never asked for it. Two defects, one flag.
        "needs_key": False,
        "gives": "Recent IOCs with the malware family attached.",
    },
    # MISP AND OTX, 2026-09-23.
    "misp": {
        # NOT a url, because it is not one request. See fetch_misp_events: the
        # manifest is read first and the newest events are fetched from it.
        # The key is present so a reader asking "where does this come from"
        # gets an answer rather than a blank.
        "url": MISP_MANIFEST_URL,
        "kind": "mixed",
        "parser": "misp_events",
        "needs_key": False,
        "gives": ("Events from CIRCL's OSINT MISP feed, community-published "
                  "reports with the indicators that were in them. The newest "
                  "few events are read on each refresh rather than the whole "
                  "archive, which is too large to mirror."),
    },
    "otx": {
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "kind": "mixed",
        "parser": "otx_pulses",
        # ITS OWN VARIABLE. See the note above FEEDS on why this is a string.
        "needs_key": "AGENTAL_OTX_KEY",
        "gives": ("Pulses from AlienVault OTX, community-published reports "
                  "with their indicators. Needs a free API key; the bulk "
                  "endpoints refuse without one."),
    },
}


# SMALL HELPERS

def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value):
    """ISO string to aware datetime, or None. Never raises."""
    if not value:
        return None
    from datetime import datetime, timezone
    try:
        dt = datetime.fromisoformat(
            str(value).replace(" ", "T").replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _looks_like_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not 0 <= int(p) <= 255:
            return False
    return True


def _key_for_feed(meta: dict) -> tuple:
    """
    Which environment variable this feed's key comes from, and whether we have it.

    Returns (variable_name_or_None, key_or_empty, problem_or_None).

    THE THREE SHAPES of a feed's `needs_key`, decided here and nowhere else:

        False       no key at all. MISP is this case.
        True        the abuse.ch key, by the variable name. This is what the
                    first three entries and their tests were written against,
                    so it is kept as an ALIAS rather than migrated: a bool that
                    meant "the abuse.ch key" for a year cannot start meaning
                    "some key" without every reader having to know.
        "NAME"      that variable, exactly.

    WHY A MISSING KEY IS A PROBLEM STRING RATHER THAN A FALSY KEY. This used to
    return "" from _abusech_key() and the fetch reported "no abuse.ch key set",
    which was right when there was one key. With two keys, a fetcher that
    cannot tell WHICH variable to name sends the reader to the wrong file --
    so the sentence carries the variable name and, where there is one, where to
    get it.
    """
    flag = meta.get("needs_key", False)
    if flag is False or flag is None:
        return None, "", None

    if flag is True:
        var = "AGENTAL_ABUSECH_KEY"
        hint = "Free from auth.abuse.ch."
    else:
        var = str(flag)
        hint = ("A free key from otx.alienvault.com under Settings -> API "
                "key." if var == "AGENTAL_OTX_KEY" else "")

    value = (os.environ.get(var) or "").strip()
    if value:
        return var, value, None
    return var, "", (f"no key set for this feed. Put {var} in .env and "
                     f"restart. {hint}".strip())


# EVERY PROVIDER HAS ITS OWN HEADER NAME, AND IT IS NOT A DETAIL.
#
# `_fetch` sent every key as `Auth-Key`. That is abuse.ch's header and it was
# the only provider for a year, so it was correct. OTX is not abuse.ch: it
# wants `X-OTX-API-KEY`, and MEASURED against the live service on 2026-09-23
# with the owner's own working key:
#
#     X-OTX-API-KEY: <key>   ->  HTTP 200, 9114 pulses
#     OTX-API-Key:   <key>   ->  HTTP 403
#     Auth-Key:      <key>   ->  HTTP 403   <- what this module was sending
#
# So OTX could NEVER have loaded, with any key, however correct -- and the
# failure it produced ("key refused (HTTP 403). Check AGENTAL_OTX_KEY.") sends
# a reader to re-check a key that is fine. That is the sentence-shape this
# project keeps rules about: the message was true about the status code and
# wrong about the cause.
#
# The header is chosen from the VARIABLE NAME rather than from the feed name,
# because the variable is what the caller already passes down and because a new
# feed sharing an existing provider's key must inherit that provider's header
# without anybody remembering to add a branch.
_KEY_HEADERS = {
    "AGENTAL_ABUSECH_KEY": "Auth-Key",
    "AGENTAL_OTX_KEY":     "X-OTX-API-KEY",
}


def _feed_header(var: str) -> str:
    """
    Which HTTP header this provider wants its key in.

    A DEFAULT RATHER THAN A RAISE, and the default is abuse.ch's because that
    is the one this module has always spoken. An unknown variable therefore
    behaves exactly as it did before this function existed -- but the two
    providers this app actually has are named, and a test asserts both, so a
    third one cannot be added quietly against the wrong header.
    """
    return _KEY_HEADERS.get(var, "Auth-Key")


# The old name, kept as an alias for the same reason the old boolean was kept
# as an alias for the abuse.ch key: readers comparing two revisions see the
# same function rather than a new one. See _key_header for the table.
_key_header = _feed_header


# THE LIST'S OWN DATE. Added 2026-09-23 after the Feodo list was found STALE.
#
# MEASURED on this host, 2026-09-23: feodotracker's blocklist answered HTTP 200
# with a well-formed body, parsed cleanly, and wrote FIVE rows -- and its own
# header said:
#
#     # Last updated: 2026-03-04 14:28:39 UTC
#
# Six months old. Nothing in this module could tell that apart from a quiet
# botnet week, because every signal it had was about the RESPONSE and none was
# about the DATA. A refresh that succeeds against a frozen list is the
# module's own "a refusal is never an empty list" defect wearing the other
# mask: not silent, not empty, just out of date, and reported as coverage.
#
# Every one of these three lists carries the same line, in two spellings:
#
#     # Last updated: 2026-03-04 14:28:39 UTC          (feodo, threatfox)
#     # Last updated: 2026-09-23 09:43:16 (UTC)        (urlhaus)
#
# so this reads the line rather than assuming a format, tolerates the
# parentheses, and returns None when there is no such line -- which is the
# honest answer for a format that does not carry one, and must never be
# confused with "fresh".

_LIST_DATE_RE = re.compile(
    r"#\s*Last\s+updated\s*:\s*"
    r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})"
    r"\s*\(?\s*UTC\s*\)?",
    re.IGNORECASE)

# A list whose own header is older than this is reported as STALE, and its
# matches drop to medium severity the same way an old download already does.
#
# WHY 72 HOURS, and it is a measurement rather than a round number. MEASURED
# 2026-09-23: URLhaus and ThreatFox both refreshed within the hour, Feodo was
# 203 days old. The gap between a healthy list and a frozen one is not subtle,
# so the threshold's job is to be safely above ordinary publishing jitter
# (abuse.ch updates continuously but a quiet weekend is normal) and far below
# "six months". Three days does both, and the number is here rather than in
# config because a wrong value is a security decision nobody would remember to
# review.
FEED_LIST_STALE_HOURS = 72


def _list_date(text: str):
    """
    The date the list says IT was last updated, or None. Never raises.

    None means "this feed's format carries no such line", which is a different
    answer from "the list is current" and is reported as such. A regex that
    silently returned today for an unparseable line would be the worst possible
    outcome here: it would make the stale case look fresh, which is exactly the
    defect this function exists to close.
    """
    if not text:
        return None
    m = _LIST_DATE_RE.search(text)
    if not m:
        return None
    return _parse_iso(f"{m.group(1)}T{m.group(2)}+00:00")


def _list_age_hours(text: str):
    """Hours since the list's own stated update, or None. Never raises."""
    stated = _list_date(text)
    if stated is None:
        return None
    from datetime import datetime, timezone
    try:
        return (datetime.now(timezone.utc) - stated).total_seconds() / 3600
    except Exception:
        return None


def _clean_domain(value: str) -> str:
    """
    Normalise a domain for storage and comparison.

    Lowercase, no trailing dot, no scheme, no port, no path. Returns "" for
    anything that does not look like a hostname, which the callers treat as
    "skip this row" rather than as an error.
    """
    if not value:
        return ""
    v = str(value).strip().lower()
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0]
    # Strip a :port, but not an IPv6 literal.
    if v.count(":") == 1:
        v = v.split(":", 1)[0]
    v = v.strip(".")
    if not v or " " in v or "." not in v:
        return ""
    return v


def _domain_and_parents(domain: str) -> list:
    """
    A domain plus the parent domains worth checking against the feed.

    "a.b.evil.com" gives ["a.b.evil.com", "b.evil.com", "evil.com"].

    Stops at two labels so we never check a bare TLD. A feed listing "com"
    would otherwise match the entire internet, and feeds do occasionally carry
    junk rows.
    """
    d = _clean_domain(domain)
    if not d:
        return []
    parts = d.split(".")
    out = []
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate.count(".") >= 1:
            out.append(candidate)
    return out


# PARSERS. One per feed format. Each returns a list of
# (indicator, indicator_type, malware_family).

def _parse_lines_ip(text: str) -> list:
    """One IP per line, # for comments. The Feodo plaintext shape."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ip = _canonical_ip(line)
        if ip:
            out.append((ip, "ip", ""))
    return out


def _parse_hostfile(text: str) -> list:
    """
    Hosts-file format: "0.0.0.0 evil.example.com", # for comments.

    The address on the left is the SINKHOLE TARGET, not an indicator, so it is
    thrown away. Reading it as an IOC would fill the table with 0.0.0.0.
    """
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        out.extend(_host_rows(parts[1], ""))
    return out


def _parse_threatfox_csv(text: str) -> list:
    """
    ThreatFox CSV export. Quoted, comma separated, # for comments.

    The columns we want are ioc_value and malware. Column ORDER is read from
    the header comment when there is one, and falls back to fixed positions
    when there is not, because a silent column shift would file IP addresses
    under malware family and nobody would notice until it printed.
    """
    import csv
    import io

    rows = []
    header_cols = None
    body = []

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            # ThreatFox puts the column names in a comment line.
            lowered = stripped.lstrip("# ").lower()
            if "ioc_value" in lowered:
                header_cols = [c.strip().strip('"')
                               for c in lowered.split(",")]
            continue
        if stripped:
            body.append(line)

    if not body:
        return rows

    try:
        reader = csv.reader(io.StringIO("\n".join(body)), skipinitialspace=True)
    except Exception:
        return rows

    if header_cols and "ioc_value" in header_cols:
        idx_value = header_cols.index("ioc_value")
        # WHICH COLUMN CARRIES THE FAMILY, MEASURED 2026-09-27. The lookup was
        # for a column literally called "malware", and the live export has no
        # such column -- its names are first_seen_utc, ioc_id, ioc_value,
        # ioc_type, threat_type, fk_malware, malware_alias, malware_printable,
        # last_seen_utc, ... So this branch could NEVER fill a family, and
        # MEASURED against the live body it produced 8,925 rows carrying an
        # empty string while the SAME body parsed through the fallback
        # positions below produced 8,925 rows, every one of them carrying a
        # family (apk.cecbot, elf.bashlite, win.asyncrat, ...). The data was
        # always there; only the header branch lost it.
        #
        # malware_printable wins because it is the readable name the feed
        # publishes ("AsyncRAT", "PureHVNC,ResolverRAT"); fk_malware is the
        # internal key ("win.asyncrat") and is used when the readable one is
        # absent, so the column degrades rather than going blank.
        idx_malware = None
        for candidate in ("malware_printable", "fk_malware", "malware"):
            if candidate in header_cols:
                idx_malware = header_cols.index(candidate)
                break
    else:
        # Documented layout at the time of writing, used only when the header
        # comment is missing. THERE IS NO SANITY CHECK ON THESE POSITIONS, and
        # an earlier comment here claimed there was. What actually limits the
        # damage is the filter below: a shifted column yields values that are
        # neither an IPv4 address nor a hostname, and those are skipped. So a
        # shift degrades to FEWER rows rather than to wrong rows, by accident
        # of the filter rather than by design. Worth a real check one day.
        idx_value, idx_malware = 2, 5

    for parts in reader:
        if len(parts) <= idx_value:
            continue
        raw = parts[idx_value].strip().strip('"')
        family = ""
        if idx_malware is not None and len(parts) > idx_malware:
            family = parts[idx_malware].strip().strip('"')[:64]

        if not raw:
            continue
        # ThreatFox writes network IOCs as "1.2.3.4:443".
        head = raw.split(":")[0] if raw.count(":") == 1 else raw
        if _is_matchable_ip(head):
            rows.append((_canonical_ip(head), "ip", family))
            continue
        if _looks_like_ipv4(head):
            # A real address that is not globally routable: an internal one
            # somebody tagged. Counted as skipped by the caller rather than
            # stored -- see _is_matchable_ip. Falling through to the domain
            # branch would be worse than dropping it: "192.0.2.1" would be
            # cleaned into the hostname "192.0.2.1" and stored as a DOMAIN,
            # which matches nothing and hides a bad row rather than reporting
            # it.
            continue
        rows.extend(_host_rows(raw, family))

    return rows


# MISP. CIRCL's OSINT feed, and it is an ARCHIVE, not a list.
#
# The shapes below were read from the live service on this host, not from
# documentation:
#
#   manifest.json   { "<uuid>": {"date": "2026-04-24", "timestamp": 1776...,
#                                "info": "...", "Orgc": {"name": "CIRCL"},
#                                "Tag": [...], "analysis": 2,
#                                "threat_level_id": 4}, ... }
#   <uuid>.json     {"Event": {"Attribute": [{"type": "domain",
#                                             "value": "evil.example",
#                                             "to_ids": true,
#                                             "category": "Network activity"},
#                                            ...],
#                             "Tag": [...], "info": "...", "date": "..."}}
#
# THE `to_ids` FLAG IS THE POINT OF THE FILTER. It is MISP's own field for
# "this attribute is meant to be acted on" -- a report also carries comments,
# filenames, dates and prose, and MEASURED over the newest 12 events the split
# is 12,619 to_ids=True against 98 False. Treating every attribute as an
# indicator would fill the table with filenames and dates.
#
# THE TYPES ARE AN ALLOWLIST, and the same allowlist is what keeps a shifted or
# newly-invented attribute type from becoming a row: only domain, hostname,
# ip-dst, ip-src and url are read, because those are the shapes this app can
# match against traffic it already has (a packet destination, a DNS query, a
# TLS SNI). A composite value like "1.2.3.4|1.2.3.5" is split into its parts
# rather than stored whole, because a stored composite matches nothing.

MISP_INDICATOR_TYPES = ("domain", "hostname", "ip-dst", "ip-src", "url")


def _misp_value_to_rows(value, attr_type: str, family: str) -> list:
    """
    One MISP attribute, as zero or more (indicator, type, family) rows.

    Zero is the common answer and it is not a failure: a SHA256 or a comment
    is not something this app can match against traffic.
    """
    if value is None:
        return []
    out = []
    # Composite values use "|" as the separator: "1.2.3.4|1.2.3.5".
    for part in str(value).split("|"):
        part = part.strip()
        if not part:
            continue
        if attr_type in ("ip-dst", "ip-src"):
            ip = _canonical_ip(part)
            if ip:
                out.append((ip, "ip", family))
        elif attr_type in ("domain", "hostname", "url"):
            # The host inside a URL, which is what this app can match.
            out.extend(_host_rows(part, family))
    return out


def _misp_family_of(event: dict, fallback: str = "") -> str:
    """
    What to call the malware, from MISP's own vocabulary, or ''.

    MISP carries this in TAGS rather than in a field: measured, the event tags
    include 'misp-galaxy:mitre-malware="Kali365 - S9044"'. The galaxy tags are
    read in preference order -- malware, then software, then threat-actor --
    and anything not found gives '' and the event's own info string is NOT used
    as a substitute. An event's title is a sentence somebody wrote, and filing
    it as a malware family would put prose in a field the model reads as a
    classification.
    """
    import re

    best = ""
    for tag in (event.get("Tag") or []):
        name = str((tag or {}).get("name") or "")
        for kind in ("malware", "software", "threat-actor"):
            prefix = f"misp-galaxy:mitre-{kind}="
            if name.startswith(prefix):
                value = name[len(prefix):].strip('"').strip()
                if value and not best:
                    best = value[:64]
        if best:
            break
    return best or (fallback or "")[:64]


def _misp_event_sort_key(uuid: str, meta: dict):
    """
    Newest first, by the manifest's own timestamp, with a UUID tiebreak.

    THE TIEBREAK IS NOT COSMETIC. Several events share a timestamp (measured:
    a batch published together), and without a deterministic second key the
    "newest N" window would reorder between runs -- so a refresh would fetch a
    different set for no reason and the per-event skip logic below would see
    churn where nothing had changed.
    """
    ts = meta.get("timestamp")
    try:
        ts = int(ts)
    except (TypeError, ValueError):
        ts = 0
    return (-ts, str(uuid))


_EVENT_ID_RE = re.compile(r"[A-Za-z0-9-]{1,64}")


def select_misp_events(manifest: dict, max_events: int) -> tuple:
    """
    (uuid, meta) for the newest events, and the total the manifest held.

    Returns a LIST rather than a dict so the order is the contract: a caller
    fetching a bounded window must know which end of it it is reading.
    """
    if not isinstance(manifest, dict):
        return [], 0
    # The key becomes part of a URL path, so only letters, digits and dashes
    # are accepted: no "/", "?", "#" or "@" can reshape it (FM-4).
    items = [(str(u), m) for u, m in manifest.items()
             if isinstance(m, dict) and _EVENT_ID_RE.fullmatch(str(u))]
    items.sort(key=lambda pair: _misp_event_sort_key(pair[0], pair[1]))
    try:
        n = max(1, int(max_events))
    except (TypeError, ValueError):
        n = MISP_MAX_EVENTS_DEFAULT
    n = min(n, MISP_MAX_EVENTS_CEILING)
    return items[:n], len(items)


def _misp_to_ids(value) -> bool:
    """
    Is this attribute marked for detection? Two shapes, both named.

    MEASURED ON THE REAL FEED: all 43,416 to_ids values in the newest 20 events
    are JSON booleans. So `True` is the shape that matters.

    A STRING "1" IS ALSO ACCEPTED, and that is a deliberate second shape rather
    than a truthy fallback. MISP stores this as a boolean in its database and
    serialises it two different ways depending on the export path; a deployment
    answering with `"to_ids": "1"` would, under a strict `is True`, import
    NOTHING from that feed forever -- the sensor runs, reports healthy, and
    every destination comes back clean. That is the failure this whole module
    is written against, so the second shape is admitted by name.

    WHAT IS NOT ACCEPTED: absent, None, False, "0", "false", "" and any other
    value. A missing flag is NOT treated as True: a report's prose fields
    usually carry no to_ids at all, so a permissive default imports every
    comment, date and filename in the archive.
    """
    if value is True:
        return True
    if isinstance(value, str) and value.strip() in ("1", "true", "True"):
        return True
    return False


def parse_misp_event(body: dict, fallback_family: str = "") -> list:
    """
    Rows for one fetched MISP event. Never raises on a malformed shape.
    """
    if not isinstance(body, dict):
        return []
    event = body.get("Event")
    if not isinstance(event, dict):
        # Some MISP deployments return the event at the top level. Read both
        # rather than guessing at one, the same call as the OTX envelope.
        event = body if isinstance(body.get("Attribute"), list) else None
    if not isinstance(event, dict):
        return []

    family = _misp_family_of(event, fallback_family)
    rows = []
    for attr in (event.get("Attribute") or []):
        if not isinstance(attr, dict):
            continue
        # THE FLAG. See _misp_to_ids for the two shapes and why only two.
        if not _misp_to_ids(attr.get("to_ids")):
            continue
        attr_type = str(attr.get("type") or "")
        if attr_type not in MISP_INDICATOR_TYPES:
            continue
        rows.extend(_misp_value_to_rows(attr.get("value"), attr_type, family))
    return rows


# OTX. Pulses, from AlienVault.
#
# READ FROM THE LIVE SERVICE: an individual public pulse is readable without a
# key and carries its indicators INLINE --
#
#   {"id": "...", "name": "...", "public": 1, "TLP": "white",
#    "tags": ["cve-2021-44228", ...], "malware_families": [],
#    "modified": "2022-01-13T00:05:19.097000",
#    "indicators": [{"indicator": "abc123...", "type": "FileHash-MD5",
#                    "is_active": 1, "title": "nspps, CoinMiner"}, ...]}
#
# and MEASURED: 86 indicators in that one pulse, of which the types this app
# can match are 'domain', 'hostname', 'IPv4', 'IPv6' and 'URL'. FileHash-* and
# the rest are skipped, counted, and not stored -- the same allowlist argument
# as MISP's, for the same reason.
#
# THE ENVELOPE IS NOT ASSUMED. /pulses/subscribed is the endpoint that would
# answer with a page of these and it refuses without a key, so its exact
# wrapper could not be read from this host. OTX's documented shape is
# {"results": [...], "count": N, "next": ...}, and a bare list is accepted too,
# and neither being the case produces a REASON rather than an empty list.

OTX_INDICATOR_TYPES = ("domain", "hostname", "IPv4", "IPv6", "URL")


def _otx_value_to_rows(value, ind_type: str, family: str) -> list:
    """One OTX indicator as zero or more rows. Same contract as the MISP one."""
    if value is None:
        return []
    value = str(value).strip()
    if not value:
        return []
    if ind_type in ("IPv4", "IPv6"):
        # The type is OTX's claim about the value, and the value is checked
        # anyway: a mislabelled row (an internal address filed as IPv4) would
        # otherwise be stored on the strength of a third party's type field.
        ip = _canonical_ip(value)
        return [(ip, "ip", family)] if ip else []
    if ind_type in ("domain", "hostname", "URL"):
        return _host_rows(value, family)
    return []


def _otx_pulses_from(body) -> tuple:
    """
    (list_of_pulses, problem_or_None). Accepts both wrappers, assumes neither.
    """
    if isinstance(body, list):
        return body, None
    if isinstance(body, dict):
        results = body.get("results")
        if isinstance(results, list):
            return results, None
        # A dict with no results key is a shape this file has never seen. Say
        # so rather than returning [], which would be read as a pulse feed
        # that contained nothing.
        return [], (f"OTX answered with a dict that has no 'results' list "
                    f"(keys: {sorted(body.keys())[:8]}). The response shape is "
                    f"not one this reader knows.")
    return [], f"OTX answered with {type(body).__name__}, not a list of pulses."


def parse_otx_pulses(body, limit: int = None) -> list:
    """
    Rows from an OTX pulse response. Never raises.

    The per-pulse family comes from `malware_families` when OTX has it, and
    from the indicator's own `title` otherwise, capped. Measured: the public
    Log4Shell pulse has an empty malware_families list while each indicator
    carries 'nspps, CoinMiner' in its title, so title is where the useful name
    actually is for a pulse like that one.
    """
    pulses, problem = _otx_pulses_from(body)
    if problem:
        raise ValueError(problem)

    rows = []
    for pulse in pulses:
        if not isinstance(pulse, dict):
            continue
        fams = pulse.get("malware_families") or []
        pulse_family = ""
        if isinstance(fams, list) and fams:
            first = fams[0]
            if isinstance(first, dict):
                pulse_family = str(first.get("display_name")
                                   or first.get("name") or "")
            else:
                pulse_family = str(first)
        pulse_family = pulse_family[:64]

        for ind in (pulse.get("indicators") or []):
            if not isinstance(ind, dict):
                continue
            ind_type = str(ind.get("type") or "")
            if ind_type not in OTX_INDICATOR_TYPES:
                continue
            family = pulse_family
            if not family:
                family = str(ind.get("title") or "")[:64]
            rows.extend(_otx_value_to_rows(ind.get("indicator"), ind_type,
                                           family))

    if limit:
        try:
            rows = rows[:max(1, int(limit))]
        except (TypeError, ValueError):
            pass
    return rows


_PARSERS = {
    "lines_ip": _parse_lines_ip,
    "hostfile": _parse_hostfile,
    "threatfox_csv": _parse_threatfox_csv,
}

# Parsers that take a BODY rather than text, because they are fed by a
# multi-stage fetcher rather than by one response. Kept in its own dict so
# refresh_once can refuse a feed whose parser is in neither: a name that
# matches nothing is how a feed loads zero indicators forever.
_BODY_PARSERS = {
    "otx_pulses": parse_otx_pulses,
}


# REFRESH

def _fetch(url: str, send_key: bool, key_var: str = None) -> tuple:
    """
    One GET. Returns (text, error). Exactly one of the two is None.

    A refusal is an ERROR STRING, never an empty body. The whole module leans
    on that: an empty body would end up as zero indicators, and zero
    indicators is what a clean feed looks like.

    `send_key` is kept as the boolean it always was, and `key_var` is the
    variable the key comes from so the failure sentence names the RIGHT one.
    Before OTX there was only one key, so a hardcoded AGENTAL_ABUSECH_KEY in
    the 401 branch was correct; with two keys it would send the reader to check
    a variable that was never involved.

    401 AND 403 ARE ANSWERED DIFFERENTLY, and this is a measurement rather than
    a nicety. A key that is ABSENT gives 401; a key that is WRONG -- or a
    header the service does not read -- gives 403, and those two send an
    operator to different places. The shared sentence used to be "key refused
    (HTTP 403). Check <VAR>." for both, which is true about the status code and
    wrong about the cause for the 401 case, where the variable is not set at
    all. MEASURED on this host, 2026-09-27: sending `Auth-Key: <the operator's
    own working OTX key>` to otx.alienvault.com answers 403 while the same key
    in X-OTX-API-KEY answers 200 -- a 403 that names the key sends a reader to
    re-check a credential that is fine. That is the header table's job.
    """
    try:
        import requests
    except ImportError:
        return None, "requests is not installed"

    var = key_var or "AGENTAL_ABUSECH_KEY"
    headers = {"User-Agent": USER_AGENT}
    if send_key:
        key = (os.environ.get(var) or "").strip()
        if not key:
            return None, (f"no key set for this feed. Put {var} in .env and "
                          f"restart.")
        headers[_feed_header(var)] = key

    # Redirects are followed by hand and only on the same host (FM-1b):
    # requests forwards custom key headers like Auth-Key to ANY host a
    # redirect names, and only strips the standard Authorization header.
    from urllib.parse import urljoin, urlsplit
    origin = urlsplit(url)
    try:
        for _hop in range(MAX_REDIRECTS + 1):
            resp = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT,
                                stream=True, allow_redirects=False)
            if resp.status_code not in (301, 302, 303, 307, 308):
                break
            target = urljoin(url, resp.headers.get("Location", ""))
            resp.close()
            t = urlsplit(target)
            if (t.scheme, t.hostname) != (origin.scheme, origin.hostname):
                return None, (f"the feed redirected to {t.scheme}://"
                              f"{t.hostname}, a different host, so it was not "
                              f"followed and no key was sent there.")
            url = target
        else:
            return None, f"more than {MAX_REDIRECTS} redirects"
    except Exception as e:
        return None, f"{type(e).__name__}"

    if resp.status_code == 401:
        if send_key:
            return None, (f"{var} is set but the service answered 401 "
                          f"Unauthorized, so the key was not accepted in the "
                          f"header this module sends it in "
                          f"({_feed_header(var)}). If the key is right, the "
                          f"header is the problem, see _KEY_HEADERS.")
        return None, "HTTP 401, and no key was sent for this feed."
    if resp.status_code == 403:
        if send_key:
            return None, (f"HTTP 403 from the service with {var} sent as "
                          f"{_feed_header(var)}. A 403 is usually the header "
                          f"rather than the key: check the key by name and "
                          f"length, then check _KEY_HEADERS maps this "
                          f"variable to the header this provider reads.")
        return None, "HTTP 403 and no key was sent for this feed."
    if resp.status_code != 200:
        resp.close()
        return None, f"HTTP {resp.status_code}"
    text, err = _read_bounded(resp)
    if err:
        return None, err
    if not text or not text.strip():
        return None, "empty response body"
    return text, None


def _read_bounded(resp) -> tuple:
    """The body as text, refused past MAX_RESPONSE_BYTES or MAX_RESPONSE_SECONDS."""
    started = time.monotonic()
    chunks, total = [], 0
    try:
        for chunk in resp.iter_content(64 * 1024):
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                return None, (f"response larger than "
                              f"{MAX_RESPONSE_BYTES // (1024 * 1024)} MB, refused")
            if time.monotonic() - started > MAX_RESPONSE_SECONDS:
                return None, (f"response took longer than "
                              f"{MAX_RESPONSE_SECONDS}s to arrive, refused")
            chunks.append(chunk)
    except Exception as e:
        return None, f"{type(e).__name__} while reading the body"
    finally:
        resp.close()
    return b"".join(chunks).decode(resp.encoding or "utf-8", errors="replace"), None


def _fetch_json(url: str, send_key: bool = False, key_var: str = None) -> tuple:
    """
    One GET, parsed as JSON. Returns (body, error).

    ITS OWN FUNCTION RATHER THAN A FLAG ON _fetch, because the failure modes
    are different in one way that matters: a body that is not JSON at all. A
    feed answering an HTML error page with HTTP 200 would, through _fetch,
    arrive as "text" and then fail in a parser in a way whose message names the
    wrong problem.
    """
    text, err = _fetch(url, send_key, key_var)
    if err:
        return None, err
    import json
    try:
        return json.loads(text), None
    except ValueError as e:
        return None, (f"the response is not JSON ({e}); first 60 characters: "
                      f"{text[:60]!r}")


def _feed_cap(block: dict, key: str, default: int) -> int:
    """
    A per-feed count from config, clamped, never raising.

    A config typo must not turn a boot into a traceback, and it must not turn a
    bounded fetch into an unbounded one either: the ceiling is applied here as
    well as in the fetch functions, because the value crosses a config boundary
    that a person edits.
    """
    try:
        value = int((block or {}).get(key, default))
    except (TypeError, ValueError):
        return default
    ceiling = (MISP_MAX_EVENTS_CEILING if "misp" in key
               else OTX_MAX_PULSES_CEILING)
    return max(1, min(value, ceiling))


def fetch_misp_events(max_events: int = None) -> tuple:
    """
    The newest MISP events, already parsed. Returns (rows, error, detail).

    WHY THIS IS NOT A URL IN THE FEEDS DICT THAT _fetch CAN READ. MISP is an
    archive of one file per event, so a refresh is a manifest read plus N event
    fetches. A single-URL fetcher cannot express that, and pretending it could
    is how a feed ends up reporting "HTTP 200, 0 indicators" forever.

    IT FETCHES FEWER THAN IT ASKS FOR AND SAYS SO. A single event that fails is
    not a failed refresh: 14 of 15 events is real coverage, and the detail
    carries the counts so a reader can see the window rather than trusting it.
    The error is returned ONLY when nothing at all could be read, because that
    is the state where matching must not claim anything.
    """
    manifest, err = _fetch_json(MISP_MANIFEST_URL)
    if err:
        return [], f"the manifest could not be read: {err}", {}

    window, total = select_misp_events(manifest, max_events
                                       or MISP_MAX_EVENTS_DEFAULT)
    if not window:
        return [], (f"the manifest parsed but held no usable event entries "
                    f"(type {type(manifest).__name__})."), {}

    rows = []
    ok = 0
    failed = []
    empty = 0
    for uuid, meta in window:
        body, e = _fetch_json(MISP_EVENT_URL.format(uuid=uuid))
        if e:
            failed.append(f"{uuid[:8]}: {e}")
            continue
        # The manifest's own info string is the fallback family when an event
        # carries no galaxy tag -- see _misp_family_of for why the info string
        # is not preferred.
        event_rows = parse_misp_event(body, fallback_family="")
        if not event_rows:
            # A real and common case: events that are prose with no attributes
            # at all, MEASURED at 3 of the newest 20. Counted, not called a
            # failure, because an OSINT report with no IOCs is a normal thing
            # to publish.
            empty += 1
            continue
        ok += 1
        rows.extend(event_rows)

    detail = {
        "events_in_archive": total,
        "events_fetched": ok,
        "events_empty": empty,
        "events_failed": len(failed),
        "window": len(window),
        "failures": failed[:3],
        "note": (f"Read the newest {len(window)} of {total} events in CIRCL's "
                 f"OSINT archive. {ok} carried usable indicators, {empty} "
                 f"carried none"
                 + (f", {len(failed)} could not be fetched" if failed else "")
                 + ". The older events were NOT read, so a listed indicator "
                   "from an old event is absent from this table."),
    }

    if not rows and failed:
        return [], (f"no MISP event could be read: {failed[0]}"), detail
    if not rows:
        # THE COUNT IS IN THE SENTENCE ON PURPOSE, and it was added after a
        # boot log made the point. The old wording said "a window of reports
        # with no indicators" without saying WHICH window, so the two causes
        # that look identical from here -- a parse break and a window that
        # landed inside a run of prose -- could not be told apart by a reader.
        # MEASURED on this archive 2026-09-23: 4 of the newest 6 events carried
        # no indicators at all, so at misp_max_events 3 this refusal is the
        # EXPECTED outcome of a correct fetch rather than a symptom. Naming the
        # variable is the difference between raising a number and hunting for
        # a parser bug.
        return [], (f"every one of the {len(window)} newest MISP events parsed "
                    f"to zero usable indicators, so there is nothing to match "
                    f"against and nothing was written. Two causes look the "
                    f"same from here: a parse problem, or a window that landed "
                    f"entirely inside a run of prose reports. The newest events "
                    f"on this archive are often such reports, MEASURED "
                    f"2026-09-23: 4 of the newest 6 carried none, so a small "
                    f"misp_max_events is a real candidate. The window is NOT "
                    f"widened automatically, because looking further back is a "
                    f"bandwidth decision: raise misp_max_events in config.json "
                    f"to do it deliberately."), detail
    return rows, None, detail


def fetch_otx_pulses(max_pulses: int = None, key: str = None) -> tuple:
    """
    Pulses from OTX, already parsed. Returns (rows, error, detail).

    THE LIMIT GOES IN THE REQUEST, so a bounded read is bounded at the service
    rather than after downloading everything. `limit` is OTX's own parameter
    name on /pulses/subscribed.
    """
    try:
        n = int(max_pulses or OTX_MAX_PULSES_DEFAULT)
    except (TypeError, ValueError):
        n = OTX_MAX_PULSES_DEFAULT
    n = max(1, min(n, OTX_MAX_PULSES_CEILING))

    url = f"{FEEDS['otx']['url']}?limit={n}&page=1"
    body, err = _fetch_json(url, send_key=True,
                            key_var="AGENTAL_OTX_KEY")
    if err:
        return [], err, {"requested": n}

    try:
        rows = parse_otx_pulses(body)
    except ValueError as e:
        return [], str(e), {"requested": n}

    pulses, _ = _otx_pulses_from(body)
    detail = {
        "requested": n,
        "pulses": len(pulses),
        "note": (f"Read {len(pulses)} pulse(s) from OTX. An OTX pulse carries "
                 f"its indicators inline, so this is the pulses the API "
                 f"returned for this page rather than a complete mirror of "
                 f"the feed."),
    }
    if not rows:
        return [], ("OTX returned pulses but none carried an indicator this "
                    "app can match (domains, addresses, URLs)."), detail
    return rows, None, detail


def refresh_once(config: dict = None, force: bool = False) -> dict:
    """
    Pull every enabled feed and replace its rows in threat_feed.

    Returns a dict with ran, reason, and a per-feed breakdown. ran=False means
    NOT ONE feed loaded, which is the state where matching must not claim
    anything. A partial success is ran=True with the failures named, because
    two feeds out of three is real coverage and should not be thrown away.
    """
    block = (config or {}).get("threat_feeds", {}) or {}
    if not block.get("enabled", True):
        return {"ran": False, "reason": "threat feeds disabled in config",
                "feeds": {}, "total_indicators": 0}

    # AN EMPTY FEED LIST IS A SILENT OFF, AND IT READS AS A BROKEN MATCHER.
    # MEASURED 2026-09-27: `"feeds": []` fell through the `or` below to mean
    # ALL FIVE FEEDS, which is the opposite of what an empty list says, while
    # this file's own config comment promises "an OMITTED key means all five".
    # An operator who empties the list means "check nothing", gets "check
    # everything", and has no way to tell from config. So it is refused with
    # its own sentence, and the sentence names the way to say it properly:
    # `enabled: false` is a decision the app reports as a decision, while an
    # empty list is a decision the app currently cannot report at all.
    configured = block.get("feeds")
    if configured is not None and not configured:
        return {
            "ran": False,
            "reason": ("config lists no feeds (\"feeds\": []), so nothing was "
                       "fetched and nothing is being checked against the "
                       "known-bad lists. To check nothing on purpose, set "
                       "\"enabled\": false, that is reported as a decision. "
                       "To check everything, remove the \"feeds\" key or name "
                       "the feeds you want."),
            "feeds": {}, "total_indicators": _count_indicators(),
        }

    enabled = configured or list(FEEDS.keys())
    # A NAME IN CONFIG THAT IS NOT A FEED IS REPORTED, never filtered away
    # silently: a typo there is a person believing a list is being pulled.
    unknown = [n for n in enabled if n not in FEEDS]
    enabled = [n for n in enabled if n in FEEDS]
    if not force:
        # THROUGH THE CURSOR TABLE, not user_preferences. This key sat in the
        # policy table until 2026-09-23 and moved a digest the tamper journal
        # watches; see the note above _LAST_REFRESH. `_parse_iso(None)` is None,
        # so a never-refreshed database still takes the "go and fetch" branch.
        last = _parse_iso(_cursor_read(_LAST_REFRESH))
        if last is not None:
            from datetime import datetime, timezone
            age_h = (datetime.now(timezone.utc) - last).total_seconds() / 3600
            interval = float(block.get("refresh_hours", DEFAULT_REFRESH_HOURS))
            if age_h < interval:
                return {"ran": True,
                        "reason": (f"refreshed {age_h:.1f}h ago, interval is "
                                   f"{interval}h"),
                        "skipped": True, "feeds": {},
                        "total_indicators": _count_indicators()}

    results = {}
    any_loaded = False
    total = 0

    for name in enabled:
        meta = FEEDS.get(name)
        if not meta:
            results[name] = {"ok": False, "error": "unknown feed name",
                             "count": 0}
            continue

        # THE TWO-STAGE FEEDS, 2026-09-23.
        #
        # MISP and OTX are not one GET and a parser. MISP is a manifest plus N
        # event files; OTX is a page of pulses whose indicators arrive inline
        # but whose ENVELOPE this host could not observe. Both are read by
        # their own fetcher, above, which owns the staging, the partial-success
        # arithmetic and the detail a reader needs to judge the window.
        #
        # The keyed single-stage path below is unchanged for the three abuse.ch
        # feeds, because those work and there is no reason to move them.
        if name == "misp":
            rows, err, detail = fetch_misp_events(
                _feed_cap(block, "misp_max_events", MISP_MAX_EVENTS_DEFAULT))
        elif name == "otx":
            key_var, key, problem = _key_for_feed(meta)
            if problem:
                rows, err, detail = [], problem, {}
            else:
                rows, err, detail = fetch_otx_pulses(
                    _feed_cap(block, "otx_max_pulses", OTX_MAX_PULSES_DEFAULT))
        else:
            var, key, problem = _key_for_feed(meta)
            if problem:
                results[name] = {"ok": False, "error": problem, "count": 0}
                logger.warning(
                    f"Feed {name} not refreshed: {problem}. Its previous rows "
                    f"are KEPT, so matching still covers what it covered "
                    f"before.")
                continue

            text, err = _fetch(meta["url"], bool(var), key_var=var)
            detail = {}
            rows = None
            if not err:
                parser = _PARSERS.get(meta["parser"])
                if not parser:
                    err = (f"parser {meta['parser']!r} is not one this module "
                           f"knows, so this feed can never load.")
                else:
                    # THE LIST'S OWN DATE, read from the bytes before the rows
                    # are thrown away. See _list_date: a list can answer, parse
                    # and be six months old, and until 2026-09-23 nothing here
                    # could tell. The detail travels into the refresh result and
                    # from there onto the per-feed status.
                    age_h = _list_age_hours(text)
                    if age_h is not None:
                        detail["list_age_hours"] = round(age_h, 1)
                        detail["list_stale"] = age_h > FEED_LIST_STALE_HOURS
                        if detail["list_stale"]:
                            logger.warning(
                                f"Feed {name} served a list dated "
                                f"{age_h / 24:.0f} day(s) ago "
                                f"({age_h:.0f}h), which is older than the "
                                f"{FEED_LIST_STALE_HOURS}h threshold. The "
                                f"download SUCCEEDED and the rows are real, "
                                f"they are just out of date, so matches from "
                                f"this list carry reduced severity and the "
                                f"feed status says so.")
                    try:
                        rows = parser(text)
                    except Exception as e:
                        err = f"parse failed: {e}"

        if err:
            results[name] = {"ok": False, "error": err, "count": 0,
                             "detail": detail}
            logger.warning(f"Feed {name} not refreshed: {err}. "
                           f"Its previous rows are KEPT, so matching still "
                           f"covers what it covered before.")
            continue

        if not rows:
            # Downloaded fine and contained nothing usable. That is a PARSE
            # problem or a genuinely empty feed, and either way we keep the
            # old rows rather than wiping good data for an empty answer.
            results[name] = {"ok": False,
                             "error": "downloaded but yielded 0 indicators",
                             "count": 0, "detail": detail}
            logger.warning(f"Feed {name} yielded no indicators. Old rows kept.")
            continue

        capped = False
        if len(rows) > MAX_INDICATORS_PER_FEED:
            rows = rows[:MAX_INDICATORS_PER_FEED]
            capped = True

        try:
            written = _replace_feed_rows(name, rows)
        except Exception as e:
            results[name] = {"ok": False, "error": f"write failed: {e}",
                             "count": 0, "detail": detail}
            logger.error(f"Feed {name} write failed: {e}")
            continue

        any_loaded = True
        total += written
        results[name] = {"ok": True, "error": None, "count": written,
                         "capped": capped, "detail": detail}
        logger.info(f"Feed {name}: {written} indicators"
                    + (" (capped)" if capped else ""))
        if detail.get("note"):
            logger.info(f"Feed {name}: {detail['note']}")

    if any_loaded:
        _cursor_write(_LAST_REFRESH, _now_iso())

    # WHAT HAPPENED, KEPT WHERE A LATER READER CAN FIND IT. status() serves
    # this per feed so "why is OTX absent from my table" has an answer that
    # outlives the process that watched the failure. Written even when nothing
    # loaded, because that is exactly the case somebody will ask about.
    try:
        import json
        _cursor_write(_LAST_RESULT, json.dumps(results)[:20000])
    except Exception as e:
        logger.debug(f"feed_matcher: could not record the refresh result: {e}")

    out = {
        "ran": any_loaded,
        "reason": (None if any_loaded else
                   "no feed loaded; see the per-feed errors"),
        "feeds": results,
        "total_indicators": _count_indicators(),
    }
    if unknown:
        out["unknown_feed_names"] = unknown
        out["reason"] = ((out["reason"] + "; " if out["reason"] else "")
                         + f"config names feed(s) that do not exist: "
                           f"{', '.join(unknown)}")
        logger.warning(f"threat_feeds config names {unknown}, which are not "
                       f"feeds this app has. Nothing was fetched for them, "
                       f"and a name here is a list somebody believes is "
                       f"being pulled.")
    return out


def _replace_feed_rows(feed: str, rows: list) -> int:
    """
    Swap one feed's rows for the new set, in one transaction.

    Replace and not append, so the table tracks the live feed size instead of
    growing forever. first_added is carried over for indicators that were
    already there, so "how long has this been listed" survives a refresh.
    """
    from core import memory_engine as me

    now = _now_iso()
    with me._get_conn() as conn:
        existing = {
            r[0]: r[1] for r in conn.execute(
                "SELECT indicator, first_added FROM threat_feed WHERE feed = ?",
                (feed,)
            ).fetchall()
        }
        conn.execute("DELETE FROM threat_feed WHERE feed = ?", (feed,))
        payload = [
            (ind, kind, feed, family or "", existing.get(ind, now), now)
            for ind, kind, family in rows
        ]
        conn.executemany(
            "INSERT OR REPLACE INTO threat_feed "
            "(indicator, indicator_type, feed, malware_family, "
            " first_added, last_refreshed) VALUES (?,?,?,?,?,?)",
            payload,
        )
        # COUNT WHAT LANDED, NOT WHAT WAS OFFERED. This used to return
        # len(rows), but the primary key is (indicator, indicator_type, feed)
        # and a feed listing the same indicator twice, which ThreatFox does
        # when one address serves two families, collapses on INSERT OR
        # REPLACE. The old number was the size of the download, reported as
        # the size of the feed.
        written = conn.execute(
            "SELECT COUNT(*) FROM threat_feed WHERE feed = ?", (feed,)
        ).fetchone()[0]
    return written


def _count_indicators() -> int:
    from core import memory_engine as me
    try:
        with me._get_conn() as conn:
            row = conn.execute("SELECT COUNT(*) FROM threat_feed").fetchone()
            return row[0] if row else 0
    except Exception:
        return 0


# STATUS. The honest coverage answer.

def status(config: dict = None) -> dict:
    """
    What the matcher can currently claim.

    Anything printing "nothing matched the threat feeds" must read this first
    and say which of the three states it is in:

      loaded and fresh   the claim is worth something
      loaded but stale   the claim covers up to feed_age_hours ago
      not loaded         there is no claim to make

    THE PER-FEED BREAKDOWN IS PART OF THE ANSWER, added 2026-09-23 with MISP
    and OTX. With three feeds that all load, the summary was enough. With five --
    one keyless, one keyed and probably off -- a bare "1,234 indicators loaded,
    refreshed 2h ago" hides WHICH lists are in it, and "we are covered" against
    abuse.ch is not the same claim as against abuse.ch plus MISP. So the feeds
    each report their own last outcome and their own count, and the ones that
    are not loaded say why.
    """
    count = _count_indicators()
    # From the cursor table since v46; see the note above _LAST_REFRESH.
    last = _parse_iso(_cursor_read(_LAST_REFRESH))

    age_h = None
    if last is not None:
        from datetime import datetime, timezone
        age_h = (datetime.now(timezone.utc) - last).total_seconds() / 3600

    loaded = count > 0
    stale = bool(loaded and (age_h is None or age_h > FEED_STALE_HOURS))

    per_feed = _per_feed_state(config)

    if not loaded:
        note = ("No threat feed indicators are loaded, so nothing has been "
                "checked against them. That is not the same as nothing "
                "being found.")
    elif stale:
        age_txt = "unknown" if age_h is None else f"{age_h:.0f}h"
        note = (f"{count} indicators loaded but last refreshed {age_txt} ago. "
                f"Matches still fire, at reduced severity, and the feed may "
                f"have missed recent C2 rotation.")
    else:
        note = (f"{count} indicators loaded, refreshed {age_h:.1f}h ago.")

    # WHICH LISTS, AND WHAT IS MISSING FROM THEM. A feed that is enabled and
    # reporting zero rows is the case this sentence exists for: it is not a
    # quiet feed, it is a list this app is not checking against.
    #
    # `is True` RATHER THAN A TRUTHY TEST, because enabled is None when this
    # module could not see a config. Reporting an unknown as an OFF would be a
    # sentence invented about a machine nobody asked.
    #
    # NEVER FETCHED AND FETCHED-BUT-EMPTY ARE KEPT APART, which is the OFF
    # versus BROKEN discipline this tree applies everywhere else. A feed whose
    # last refresh errored (no key, refused, parse failure) is not the same as
    # one that answered with nothing usable, and a single "NO INDICATORS FROM:
    # otx, misp" sentence would send a reader hunting for a feed bug when the
    # answer is an unset variable. Each absent feed is named WITH the reason its
    # own last refresh gave.
    absent = [f for f in per_feed if f["enabled"] is True and f["count"] == 0]
    if absent:
        broken = [f for f in absent if f.get("last_error")]
        empty = [f for f in absent if not f.get("last_error")]
        if broken:
            named = "; ".join(f"{f['feed']} ({f['last_error']})"
                              for f in broken)
            note += (f" NOT CHECKED AGAINST: {named}.")
        if empty:
            note += (f" NO INDICATORS FROM: "
                     f"{', '.join(f['feed'] for f in empty)}. That list "
                     f"answered but loaded nothing, so a destination it would "
                     f"have listed is absent from the table rather than "
                     f"checked and clean.")

    disabled = [f["feed"] for f in per_feed if f["enabled"] is False]
    if disabled:
        note += (f" Switched off in config: {', '.join(disabled)}.")

    # A LIST THAT ANSWERED AND IS OUT OF DATE. Added 2026-09-23 with the Feodo
    # finding: feodotracker served a blocklist dated six months earlier, five
    # entries, HTTP 200, and every surface called it a successful refresh.
    # "Loaded" and "current" are different claims and this is where they are
    # kept apart -- the same discipline as never-checked versus checked-empty,
    # one shelf along.
    stale_lists = [f for f in per_feed if f.get("list_stale") is True]
    if stale_lists:
        named = "; ".join(
            f"{f['feed']} ({f.get('list_age_hours', 0) / 24:.0f} days old)"
            for f in stale_lists)
        note += (f" OUT OF DATE: {named}. Those lists answered and their rows "
                 f"are in use, but the date each list publishes for ITSELF is "
                 f"older than {FEED_LIST_STALE_HOURS}h, so a destination absent "
                 f"from one may simply be absent from an old copy of it. "
                 f"Matches from them carry reduced severity.")

    return {
        "feed_loaded": loaded,
        "indicator_count": count,
        "feed_age_hours": round(age_h, 2) if age_h is not None else None,
        "stale": stale,
        "last_refresh_at": _cursor_read(_LAST_REFRESH),
        "feeds_configured": [f["feed"] for f in per_feed],
        "per_feed": per_feed,
        "note": note,
    }


def _per_feed_state(config: dict = None) -> list:
    """
    One row per feed: is it enabled, how many rows does it hold, what happened.

    THE LAST REFRESH RESULT IS KEPT IN THE DATABASE, not in a module global, so
    it survives a restart. A reader asking "why is OTX not in my feed table"
    three days after the key was removed needs an answer that outlives the
    process that watched it fail.

    `enabled` IS READ FROM CONFIG, not assumed. This function's first version
    hardcoded True and wrote a sentence about enabled-but-empty lists, which
    would have been a false statement about a feed the operator had switched
    off on purpose -- the OFF-versus-BROKEN mistake this tree keeps rules
    about. A module-level status() has no config, so it is None and the
    per-feed entry says the state is unknown rather than claiming one.
    """
    from core import memory_engine as me

    counts = {}
    try:
        with me._get_conn() as conn:
            for name, n in conn.execute(
                    "SELECT feed, COUNT(*) FROM threat_feed GROUP BY feed"):
                counts[name] = n
    except Exception:
        counts = {}

    last_result = {}
    try:
        import json
        raw = _cursor_read(_LAST_RESULT)
        if raw:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                last_result = parsed
    except Exception:
        last_result = {}

    out = []
    block = (config or {}).get("threat_feeds", {}) or {}
    configured = block.get("feeds")
    for name, meta in FEEDS.items():
        entry = {
            "feed": name,
            # None means "this call had no config to judge by". See the
            # docstring: an unknown is not an off.
            "enabled": (None if not config
                        else (True if not configured else name in configured)),
            "count": counts.get(name, 0),
            "gives": meta.get("gives", ""),
            "needs_key": meta.get("needs_key", False),
        }
        res = last_result.get(name)
        if isinstance(res, dict):
            entry["last_ok"] = bool(res.get("ok"))
            if not res.get("ok") and res.get("error"):
                entry["last_error"] = str(res["error"])[:300]
            if res.get("detail"):
                entry["last_detail"] = res["detail"]
                # THE LIST'S OWN AGE, lifted out of the detail so a reader
                # does not have to know the detail dict's shape to see it. A
                # feed can be last_ok: True and still be six months out of
                # date -- see _list_date -- and those two facts have to be
                # visible side by side or the first one hides the second.
                if res["detail"].get("list_stale") is not None:
                    entry["list_stale"] = bool(res["detail"]["list_stale"])
                    entry["list_age_hours"] = res["detail"].get("list_age_hours")
        out.append(entry)
    return out


# MATCHING

# CURSOR STORAGE. v46, 2026-09-23.
#
# THE THREE FUNCTIONS BELOW USED TO READ AND WRITE user_preferences, and the
# header of this file explains why that was wrong. The short version, because
# the shape matters more than the history: a cursor is a BOOKMARK, user_
# preferences is THE POLICY, and core/integrity digests that table and journals
# a warning whenever it moves. A bookmark that moves every pass therefore
# wrote "the policy has CHANGED" into the tamper journal four times an hour.
#
# THE NAMES ARE UNCHANGED. `feed_match_cursor_packets` is still the key, and it
# is a key in feed_cursor now. A reader comparing two databases sees the same
# bookmark rather than a new one, and nothing had to be renamed to move it.

def ensure_cursor_table(db_path: str = None) -> bool:
    """
    Create the cursor table if it is not there. Returns whether it is now.

    Called from the migration AND from the readers, because a database can
    reach this module without having run the migration (a hand-run script, a
    test that built its schema from an older Schema.SQL). A reader that raises
    because a table is missing would turn a missing bookmark into a broken
    matcher.
    """
    import sqlite3
    from core import memory_engine as me

    path = db_path or str(me.DB_PATH)
    try:
        conn = sqlite3.connect(path, timeout=10)
        try:
            conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {_CURSOR_TABLE} (
                    name        TEXT PRIMARY KEY,
                    value       TEXT,
                    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
        finally:
            conn.close()
        return True
    except sqlite3.Error as e:
        logger.warning(f"feed_matcher: could not create {_CURSOR_TABLE} in "
                       f"{path}: {type(e).__name__}: {e}")
        return False


def _cursor_read(key: str):
    """
    The stored value, or None. None means THERE HAS NEVER BEEN ONE.

    The distinction the callers branch on: a missing bookmark is not the same
    answer as a bookmark at zero, and conflating them made the first ever pass
    scan every row this app had ever written.
    """
    from core import memory_engine as me

    def _query(conn):
        row = conn.execute(
            f"SELECT value FROM {_CURSOR_TABLE} WHERE name = ?", (key,)
        ).fetchone()
        return row[0] if row else None

    try:
        with me._get_conn() as conn:
            return _query(conn)
    except Exception:
        # The table is missing (an older database, a hand-built schema). Try to
        # create it once and ask again; if that fails, None is the honest
        # answer and match_once seeds rather than scanning history.
        if not ensure_cursor_table():
            return None
        try:
            with me._get_conn() as conn:
                return _query(conn)
        except Exception as e:
            logger.warning(f"feed_matcher: could not read cursor {key}: {e}")
            return None


def _get_cursor(key: str) -> int:
    value = _cursor_read(key)
    try:
        return int(value) if value not in (None, "") else 0
    except (TypeError, ValueError):
        return 0


def _cursor_or_none(key: str):
    """
    The stored cursor, or None when there has never been one.

    THE DIFFERENCE MATTERS AND _get_cursor CANNOT EXPRESS IT. A stored 0 and a
    missing bookmark both came back as 0, so the first ever pass started at the
    beginning of a multi-gigabyte packets table and tried to scan every row
    this app has ever written, inside a read transaction that also blocks WAL
    checkpointing. See match_once for what happens instead.
    """
    value = _cursor_read(key)
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _set_cursor(key: str, value: int):
    """Advance a numeric bookmark. See _cursor_write for the general form."""
    _cursor_write(key, str(int(value)))


def _cursor_write(key: str, text: str):
    """
    Write any text under a key in the cursor table. Never raises.

    The refresh result is stored here too (see refresh_once), and it is a JSON
    blob rather than a number, which is why this exists beside _set_cursor
    rather than inside it: a bookmark and a report are different shapes and
    running one through int() would be a coercion that silently makes a
    malformed report look like a valid bookmark.
    """
    from core import memory_engine as me

    def _do(conn):
        conn.execute(
            f"INSERT INTO {_CURSOR_TABLE} (name, value) VALUES (?, ?) "
            f"ON CONFLICT(name) DO UPDATE SET value = excluded.value, "
            f"updated_at = CURRENT_TIMESTAMP",
            (key, text))

    try:
        with me._get_conn() as conn:
            _do(conn)
        return True
    except Exception as e:
        if not ensure_cursor_table():
            logger.warning(f"Could not write {key} ({e}). The next pass "
                           f"re-checks those rows; finding_already_open drops "
                           f"the duplicates.")
            return False
        try:
            with me._get_conn() as conn:
                _do(conn)
            return True
        except Exception as e2:
            logger.warning(f"Could not write {key} ({e2}). The next pass "
                           f"re-checks those rows; finding_already_open drops "
                           f"the duplicates.")
            return False


def _feed_hit_ip(conn, ip: str):
    """Feed row for this IP, or None. Returns (feed, malware_family)."""
    row = conn.execute(
        "SELECT feed, malware_family FROM threat_feed "
        "WHERE indicator_type = 'ip' AND indicator = ? LIMIT 1",
        (ip,)
    ).fetchone()
    return (row[0], row[1]) if row else None


def _assert_cursor_safe(conn, table: str, since_id: int) -> bool:
    """
    Can a `id > since_id` bookmark skip rows in this table? Read the DDL.

    THE QUESTION THIS ANSWERS, and it is not "is the cursor sensible". A table
    whose id is `INTEGER PRIMARY KEY` WITHOUT AUTOINCREMENT reuses the id of a
    deleted highest row, so a run that prunes its newest rows and then captures
    more puts FRESH rows below a cursor that has already passed that value --
    and every `id > cursor` reader in this module misses them in silence while
    reporting a clean pass. With AUTOINCREMENT, SQLite refuses to go backwards
    and the same `id > cursor` is correct by construction.

    MEASURED 2026-09-27: `packets`, `tls_hello` and `dns_queries` are all
    created WITH AUTOINCREMENT in Schema.SQL, and every writer in this tree
    lets SQLite assign the id (the only ones that name an id at all are tests
    and scripts/verify_duty.py). So this is not a defect today; it is the
    ASSUMPTION the three cursor reads rest on, which nothing checked and
    nothing would have reported if it changed.

    Returns True when reading on is safe. A table with no `id` column at all is
    an error worth seeing rather than a silent skip, so that is False with a
    log line.
    """
    try:
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            (table,)).fetchone()
        ddl = (row[0] if row else "") or ""
        if not ddl:
            logger.warning(
                f"feed_matcher: {table} has no table definition, so this "
                f"pass checked NOTHING and says so rather than reporting a "
                f"clean result.")
            return False
        if "id" not in ddl.lower():
            logger.warning(
                f"feed_matcher: {table} has no id column, so the cursor for it "
                f"means nothing. Nothing was checked.")
            return False
        if "autoincrement" in ddl.lower():
            return True
        logger.warning(
            f"feed_matcher: {table}.id is an INTEGER PRIMARY KEY WITHOUT "
            f"AUTOINCREMENT, so SQLite may reuse the id of a deleted newest "
            f"row. The cursor is at {since_id} and a row written below it "
            f"would never be checked by any pass, with nothing raised. "
            f"Treat this pass as UNSAFE; add AUTOINCREMENT or move the cursor "
            f"to a timestamp column.")
        return False
    except Exception as e:
        logger.warning(f"feed_matcher: could not check the cursor for "
                       f"{table}: {type(e).__name__}: {e}. Nothing checked.")
        return False


def _feed_hit_domain(conn, domain: str):
    """
    Feed row for this domain or one of its parents.

    Returns (matched_name, feed, malware_family) or None. The matched name is
    returned separately because "evil.com is listed" and "a.b.evil.com is
    listed" are different sentences and the finding should say which one we
    actually have.

    A PARENT MATCH ON A SHARED HOST IS REFUSED. See _SHARED_HOST_ROOTS. The
    exact name always counts; only the walk upwards stops, and when it stops
    it is logged rather than swallowed, because a listed name that produced
    no finding is exactly the kind of quiet worth being able to explain.
    """
    candidates = _domain_and_parents(domain)
    for i, candidate in enumerate(candidates):
        row = conn.execute(
            "SELECT feed, malware_family FROM threat_feed "
            "WHERE indicator_type = 'domain' AND indicator = ? LIMIT 1",
            (candidate,)
        ).fetchone()
        if not row:
            continue
        # i == 0 is the name itself, which always counts however shared it is.
        if i > 0 and _is_shared_host(candidate):
            logger.info(
                f"Feed lists {candidate!r}, which is a shared hosting root, "
                f"so {domain!r} was NOT raised on that parent. Thousands of "
                f"unrelated names sit under it and a high severity finding "
                f"on all of them would be wrong. An exact listing of "
                f"{domain!r} would still fire.")
            continue
        return (candidate, row[0], row[1])
    return None


def _keep_payload(src_ip, dst_ip, dst_port, protocol, detection_id,
                  entity, src_port=None):
    """
    Flush the ring for a flow this module just raised a finding about.

    TODO 120. Never raises and never changes the finding: the finding is
    already saved by the time this runs, and losing the bytes is a much
    smaller loss than losing the finding. The reason is logged at debug when
    there was nothing to keep, because the ring holding nothing is its normal
    state and a warning per miss would be noise.

    FED-1002 does NOT call this and that is not an oversight. A DNS row comes
    from the resolver log, not from a packet this sensor captured, so there is
    no flow to flush and pretending otherwise would log a miss every time.
    """
    from tools import payload_ring
    try:
        res = payload_ring.flush_for_finding(
            src_ip, dst_ip, dst_port, protocol or "TCP",
            detection_id, entity, src_port=src_port)
        if res.get("ran"):
            logger.info(f"{detection_id}: kept {res.get('rows')} payload "
                        f"frame(s) for {src_ip} -> {dst_ip}.")
        else:
            logger.debug(f"{detection_id}: no payload kept. "
                         f"{res.get('reason')}")
    except Exception as e:
        logger.debug(f"{detection_id}: payload flush error: {e}")


def _severity_for(stale: bool) -> str:
    """
    High on a fresh feed, medium on a stale one.

    A stale feed can be listing something that was cleaned up last week, so
    the confidence genuinely is lower. Saying so in the severity rather than
    only in the description means a triage view that sorts by severity
    behaves correctly without having to read the prose.
    """
    return "medium" if stale else "high"


def _stale_list_feeds() -> set:
    """
    The feeds whose own published date is older than FEED_LIST_STALE_HOURS.

    WHY THIS EXISTS BESIDE `stale`, and they are not the same question:

      `stale`               the last DOWNLOAD is old, so the app may be
                            matching against a copy it has not refreshed.
      this set              the LIST ITSELF says it has not been updated,
                            however recently we downloaded it.

    MEASURED 2026-09-23, and this is the case that makes the distinction
    necessary: feodotracker answered HTTP 200 minutes ago (so `stale` is False
    and the download is as fresh as it can be) while the file it served is
    dated 2026-03-04 (so every row in it is six months old). A reader told
    "refreshed 2 minutes ago" has been told the truth about the download and a
    lie about the data.

    Read from the stored per-feed result rather than re-fetched, so a match
    pass costs nothing extra and cannot disagree with what the status page
    says. A failure to read it returns an empty set: matches then keep their
    ordinary severity, which is the safe direction -- the alternative would
    silently downgrade real findings on a read error.
    """
    import json
    out = set()
    try:
        raw = _cursor_read(_LAST_RESULT)
        if not raw:
            return out
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            return out
        for name, res in parsed.items():
            if isinstance(res, dict) and (res.get("detail") or {}).get("list_stale") is True:
                out.add(name)
    except Exception:
        return set()
    return out


def _severity_for_feed(feed: str, stale: bool) -> str:
    """
    Severity for a hit from ONE named feed, both clocks considered.

    The feed is named on the finding either way, so a reader can always see
    which list made the claim -- but until this existed the severity was
    computed once for the whole pass, which meant a hit from a fresh list and a
    hit from a six-month-old one were graded identically.
    """
    if stale or feed in _stale_list_feeds():
        return "medium"
    return "high"


def _check_packet_ips(conn, session_id: str, since_id: int, stale: bool) -> int:
    """
    Listed addresses in the packet record, in BOTH directions.

    INBOUND WAS MISSING UNTIL 2026-09-20. Only dst_ip was checked, so a
    connection arriving FROM a listed C2 address never raised anything. On a
    home network that is the rarer case, but "the feed listed it and we saw
    it" is the whole point of this module and the direction it arrived from
    is not a reason to say nothing.
    """
    from core import memory_engine as me

    # THE PORTS ARE SELECTED SO THE FLOW CAN BE FLUSHED, TODO 120. Without
    # them this detection could name a listed destination and keep none of
    # the bytes that went to it, which is the strongest evidence in the app
    # having the weakest record behind it.
    rows = conn.execute("""
        SELECT DISTINCT src_ip, dst_ip, direction, scope, src_port,
                        dst_port, protocol
        FROM packets
        WHERE id > ? AND dst_ip IS NOT NULL AND src_ip IS NOT NULL
          AND (scope IN ('outbound', 'inbound')
               OR direction IN ('outbound', 'inbound'))
    """, (since_id,)).fetchall()

    stale_feeds = _stale_list_feeds()
    raised = 0

    for (src_ip, dst_ip, direction, scope,
         src_port, dst_port, protocol) in rows:
        inbound = (direction == "inbound" or scope == "inbound")
        remote = src_ip if inbound else dst_ip
        local = dst_ip if inbound else src_ip

        if not remote or remote in _NEVER_MATCH_IPS:
            continue
        hit = _feed_hit_ip(conn, remote)
        if not hit:
            continue
        feed, family = hit
        # PER FEED, not per pass. See _severity_for_feed: the download can be
        # minutes old while the list it delivered is months old.
        severity = _severity_for_feed(feed, stale)

        entity = local or remote
        if inbound:
            title = f"A listed C2 address contacted this network: {remote}"
            lead = (
                f"Source: {remote}\n"
                f"Reached: {local or 'not recorded'}\n")
            body = (
                f"This came IN from an address on a live known-bad feed. "
                f"Unsolicited inbound scanning of a home address is constant "
                f"and mostly noise, so the thing worth checking is whether "
                f"anything answered: look for outbound packets to the same "
                f"address around the same time.")
        else:
            title = f"Contacted a listed C2 address: {remote}"
            lead = (
                f"Destination: {remote}\n"
                f"Local device: {local or 'not recorded'}\n")
            body = (
                f"This address is on a live known-bad feed, which is a much "
                f"stronger signal than anything this app works out on its "
                f"own. Worth finding which process on "
                f"{local or 'that device'} opened the connection.")

        if me.finding_already_open("feed_matcher", "ip", entity, title):
            continue

        result = me.save_finding(
            session_id=session_id,
            source="feed_matcher",
            severity=severity,
            entity_type="ip",
            entity_value=entity,
            title=title,
            description=(
                lead
                + f"Listed by: {feed}"
                + (f" as {family}" if family else "") + "\n\n"
                + body
                + ("\n\nNote: the feed is stale, so this listing may be out of "
                   "date. Severity is reduced for that reason." if stale else "")
                + (f"\n\nNote: the list '{feed}' has not been updated by its "
                   f"publisher for over {FEED_LIST_STALE_HOURS}h, so this "
                   f"entry may be a stale listing. Severity is reduced for "
                   f"that reason." if feed in stale_feeds else "")
            ),
            raw_data={"remote_ip": remote, "local_ip": local,
                      "inbound": inbound, "feed": feed,
                      "malware_family": family, "feed_stale": stale,
                      "list_stale": feed in stale_feeds},
            detection_id="FED-1001",
        )
        if result.get("saved"):
            raised += 1
            logger.warning(
                f"FED-1001: {'inbound from' if inbound else 'outbound to'} "
                f"{remote} listed by {feed}")
            _keep_payload(src_ip, dst_ip, dst_port, protocol,
                          "FED-1001", entity, src_port)

    return raised


def _check_dns_domains(conn, session_id: str, since_id: int, stale: bool) -> int:
    from core import memory_engine as me

    rows = conn.execute("""
        SELECT DISTINCT client_ip, domain
        FROM dns_queries
        WHERE id > ? AND domain IS NOT NULL
    """, (since_id,)).fetchall()

    stale_feeds = _stale_list_feeds()
    raised = 0

    for client_ip, domain in rows:
        hit = _feed_hit_domain(conn, domain)
        if not hit:
            continue
        matched, feed, family = hit
        # PER FEED; see _severity_for_feed.
        severity = _severity_for_feed(feed, stale)

        entity = client_ip or "unknown"
        title = f"Resolved a listed malicious domain: {domain}"
        if me.finding_already_open("feed_matcher", "ip", entity, title):
            continue

        result = me.save_finding(
            session_id=session_id,
            source="feed_matcher",
            severity=severity,
            entity_type="ip",
            entity_value=entity,
            title=title,
            description=(
                f"Domain queried: {domain}\n"
                f"Feed entry matched: {matched}\n"
                f"Listed by: {feed}"
                + (f" as {family}" if family else "") + "\n"
                f"Device: {client_ip or 'not recorded'}\n\n"
                f"A DNS query is not proof the connection happened, it is "
                f"proof something asked for the address. That is still worth "
                f"chasing, because nothing asks by accident."
                + ("\n\nNote: the feed is stale, so this listing may be out of "
                   "date. Severity is reduced for that reason." if stale else "")
                + (f"\n\nNote: the list '{feed}' has not been updated by its "
                   f"publisher for over {FEED_LIST_STALE_HOURS}h, so this "
                   f"entry may be a stale listing. Severity is reduced for "
                   f"that reason." if feed in stale_feeds else "")
            ),
            raw_data={"domain": domain, "matched": matched, "feed": feed,
                      "malware_family": family, "feed_stale": stale},
            detection_id="FED-1002",
        )
        if result.get("saved"):
            raised += 1
            logger.warning(f"FED-1002: {client_ip} queried {domain} "
                           f"(matched {matched}, feed {feed})")

    return raised


def _check_tls_sni(conn, session_id: str, since_id: int, stale: bool) -> int:
    from core import memory_engine as me

    rows = conn.execute("""
        SELECT id, src_ip, dst_ip, dst_port, sni
        FROM tls_hello
        WHERE id > ? AND sni_state = 'present' AND sni != ''
    """, (since_id,)).fetchall()

    stale_feeds = _stale_list_feeds()
    raised = 0

    for _row_id, src_ip, dst_ip, dst_port, sni in rows:
        hit = _feed_hit_domain(conn, sni)
        if not hit:
            continue
        matched, feed, family = hit
        # PER FEED; see _severity_for_feed.
        severity = _severity_for_feed(feed, stale)

        entity = src_ip or dst_ip or "unknown"
        title = f"TLS handshake to a listed malicious name: {sni}"
        if me.finding_already_open("feed_matcher", "ip", entity, title):
            continue

        result = me.save_finding(
            session_id=session_id,
            source="feed_matcher",
            severity=severity,
            entity_type="ip",
            entity_value=entity,
            title=title,
            description=(
                f"SNI: {sni}\n"
                f"Feed entry matched: {matched}\n"
                f"Listed by: {feed}"
                + (f" as {family}" if family else "") + "\n"
                f"Device: {src_ip or 'not recorded'} "
                f"to {dst_ip or 'not recorded'}\n\n"
                f"This one is stronger than the DNS version. The name is "
                f"inside a handshake that was actually attempted, so the "
                f"connection was made, not just looked up. It also survives "
                f"encrypted DNS, which is the whole reason the SNI is parsed."
                + ("\n\nNote: the feed is stale, so this listing may be out of "
                   "date. Severity is reduced for that reason." if stale else "")
                + (f"\n\nNote: the list '{feed}' has not been updated by its "
                   f"publisher for over {FEED_LIST_STALE_HOURS}h, so this "
                   f"entry may be a stale listing. Severity is reduced for "
                   f"that reason." if feed in stale_feeds else "")
            ),
            raw_data={"sni": sni, "matched": matched, "feed": feed,
                      "malware_family": family, "dst_ip": dst_ip,
                      "feed_stale": stale},
            detection_id="FED-1003",
        )
        if result.get("saved"):
            raised += 1
            logger.warning(f"FED-1003: {src_ip} handshake to {sni} "
                           f"(matched {matched}, feed {feed})")
            # The ClientHello that carried this name is the single most
            # useful thing to still have, and it is the FIRST packet of the
            # connection. Only the always-on ring can have it.
            _keep_payload(src_ip, dst_ip, dst_port, "TCP",
                          "FED-1003", entity)

    return raised


def match_once(config: dict, session_id: str, backfill: bool = False) -> dict:
    """
    One matching pass over everything new since the last pass.

    ran=False means WE COULD NOT CHECK, and the only way to get zero matches
    reported honestly is ran=True. The commonest ran=False here is an empty
    feed table, which is exactly the state that would otherwise read as a
    clean network.

    THE FIRST PASS SEEDS THE CURSORS RATHER THAN SCANNING HISTORY, 2026-09-20.
    A missing cursor used to read as 0, so the very first pass ran
    SELECT DISTINCT over every packet row this app has ever written. On a
    multi-gigabyte database that is minutes of work inside a read transaction
    that also stops the WAL being checkpointed, and it happens while the
    sensors are starting. Each table with no cursor is set to its current end
    instead, and the return SAYS SO, because a seeded table reporting zero
    matches has not checked anything.

    backfill=True skips the seeding and does scan what is already there. It is
    a deliberate, slow thing to ask for, not the default.

    A BOOKMARK IS NOT ONLY A VALUE, IT IS A COLUMN, AND IT IS CHECKED HERE
    RATHER THAN IN EACH READER. MEASURED 2026-09-27 on a scratch store: a
    packet row carrying an id BELOW the stored cursor is invisible to `id > ?`
    forever, whatever its capture time, and the pass reports a clean result.
    That is safe while ids only grow -- every writer in this tree lets SQLite
    assign them, and DELETE does not reuse them -- but the cursor is only ever
    compared to MAX(id), so nothing would have said so if it stopped being
    safe. The three tables are therefore checked against their own
    AUTOINCREMENT promise once per pass, and a mismatch is LOGGED and the pass
    is named in its own result, rather than being inferred from a quiet one.
    The check is a read of sqlite_master; it costs nothing per pass.
    """
    from core import memory_engine as me

    state = status(config)
    if not state["feed_loaded"]:
        return {
            "ran": False,
            "reason": "no feed indicators loaded, nothing to match against",
            "ip_findings": 0, "dns_findings": 0, "tls_findings": 0,
            "seeded": [], "feed": state,
        }

    stale = state["stale"]

    cur_pkt = _cursor_or_none(_CUR_PACKETS)
    cur_dns = _cursor_or_none(_CUR_DNS)
    cur_tls = _cursor_or_none(_CUR_TLS)

    seeded = []
    unsafe = []

    try:
        with me._get_conn() as conn:
            max_pkt = (conn.execute("SELECT MAX(id) FROM packets")
                       .fetchone() or [0])[0] or 0
            max_dns = (conn.execute("SELECT MAX(id) FROM dns_queries")
                       .fetchone() or [0])[0] or 0
            max_tls = (conn.execute("SELECT MAX(id) FROM tls_hello")
                       .fetchone() or [0])[0] or 0

            # The cursor's own table is checked BEFORE anything reads from it.
            for _table in ("packets", "dns_queries", "tls_hello"):
                if not _assert_cursor_safe(conn, _table, 0):
                    unsafe.append(_table)

            # Per table, not all or nothing. tls_hello arrived at schema v38
            # and has no cursor while packets has had one for hours; seeding
            # the new one must not stop the old one being checked.
            if cur_pkt is None and not backfill:
                cur_pkt = max_pkt
                seeded.append("packets")
            if cur_dns is None and not backfill:
                cur_dns = max_dns
                seeded.append("dns_queries")
            if cur_tls is None and not backfill:
                cur_tls = max_tls
                seeded.append("tls_hello")

            ip_found = _check_packet_ips(conn, session_id, cur_pkt or 0, stale)
            dns_found = _check_dns_domains(conn, session_id, cur_dns or 0, stale)
            tls_found = _check_tls_sni(conn, session_id, cur_tls or 0, stale)

    except Exception as e:
        logger.error(f"Feed match error: {e}", exc_info=True)
        return {
            "ran": False, "reason": str(e),
            "ip_findings": 0, "dns_findings": 0, "tls_findings": 0,
            "seeded": seeded, "feed": state,
        }

    _set_cursor(_CUR_PACKETS, max_pkt)
    _set_cursor(_CUR_DNS, max_dns)
    _set_cursor(_CUR_TLS, max_tls)

    seed_note = None
    if seeded:
        seed_note = (
            f"first pass for {', '.join(seeded)}: the cursor was set to the "
            f"current end of the table, so EXISTING ROWS WERE NOT CHECKED, "
            f"only rows written from here on. Call match_once(backfill=True) "
            f"to scan what is already there, which is slow on a large "
            f"database.")
        logger.warning(f"Feed matching seeded {', '.join(seeded)} at the "
                       f"current end of the table. History was not scanned.")

    # ALL THREE SEEDED MEANS NOTHING WAS CHECKED AT ALL. Reporting that as
    # ran=True with zero matches is precisely the false-calm this module is
    # built against, so it is ran=False with the reason.
    if len(seeded) == 3:
        return {
            "ran": False, "reason": seed_note,
            "ip_findings": 0, "dns_findings": 0, "tls_findings": 0,
            "seeded": seeded, "feed": state,
            "cursor_tables_unsafe": unsafe,
        }

    total = ip_found + dns_found + tls_found
    if total:
        logger.warning(f"Feed matching raised {total} finding(s): "
                       f"ip={ip_found}, dns={dns_found}, tls={tls_found}")
    else:
        logger.info(f"Feed matching: no matches against "
                    f"{state['indicator_count']} indicators.")

    return {
        "ran": True, "reason": seed_note,
        "ip_findings": ip_found,
        "dns_findings": dns_found,
        "tls_findings": tls_found,
        "seeded": seeded,
        "feed": state,
        # Empty on every ordinary pass. Named here so a caller can see that a
        # bookmark which cannot be trusted is a fact about the ANSWER, not
        # only about a log line.
        "cursor_tables_unsafe": unsafe,
    }


# THE LOOP

class FeedMatcher:
    """
    Owns the refresh cadence and the matching cadence.

    Two different clocks on purpose. Refresh is an outbound HTTP call to a free
    service and should be rare. Matching is local SQL and should be often,
    because the point of the whole section is that a bad destination gets
    noticed as it happens rather than when somebody asks.
    """

    def __init__(self, session_id: str, config: dict = None):
        block = (config or {}).get("threat_feeds", {}) or {}
        self.session_id = session_id
        self.config = config or {}
        self.enabled = bool(block.get("enabled", True))
        self.refresh_hours = max(1.0, float(block.get(
            "refresh_hours", DEFAULT_REFRESH_HOURS)))
        self.match_interval = max(60, int(block.get(
            "match_interval_seconds", 300)))
        self._running = False
        self._thread = None

    def start(self):
        if not self.enabled:
            logger.info("Threat feed matching disabled in config.")
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, name="feed-matcher", daemon=True)
        self._thread.start()
        logger.info(f"Feed matcher started, refresh every "
                    f"{self.refresh_hours}h, match every "
                    f"{self.match_interval}s.")

    def stop(self):
        self._running = False

    def status(self) -> dict:
        """
        What the readiness page reads, ADDED 2026-09-21.

        THE CLASS HAD NO status() AT ALL, in this tree and in the Windows one.
        core/settings._module_row falls through to the bare word "loaded." for
        a module that publishes none, and "loaded." only ever meant the import
        worked. So the single most important fact about this sensor was
        invisible on the page that exists to carry it: whether the feeds
        actually downloaded.

        It matters more here than for most modules. An empty threat_feed makes
        every outbound destination come back clean, and a matcher whose
        download failed reports a beautifully quiet network. The module-level
        status() already knows the difference between loaded-and-fresh,
        loaded-but-stale and not-loaded, and it writes a sentence for each.
        This is that answer, plus the two facts only the running object has.
        """
        out = dict(status(self.config))
        out["running"] = self._running
        out["enabled"] = self.enabled
        out["refresh_hours"] = self.refresh_hours
        out["match_interval_seconds"] = self.match_interval
        if not self.enabled:
            # Switched off in config is a decision, and the note says which
            # decision rather than letting the feed state imply a fault.
            out["note"] = ("Threat feed matching is switched off in "
                           "config.json, so nothing is being checked against "
                           "the known-bad lists. " + str(out.get("note") or ""))
        return out

    def _loop(self):
        # First refresh happens immediately at boot, because an app that has
        # been off for a week has a feed a week out of date and should not
        # spend the first six hours matching against it quietly.
        while self._running:
            try:
                r = refresh_once(self.config)
                if not r.get("ran") and not r.get("skipped"):
                    logger.warning(f"Feed refresh failed: {r.get('reason')}. "
                                   f"Matching will use whatever is already "
                                   f"loaded, and say so.")
            except Exception as e:
                logger.error(f"Feed refresh error: {e}")

            # Match several times between refreshes.
            passes = max(1, int((self.refresh_hours * 3600)
                                / self.match_interval))
            for _ in range(passes):
                if not self._running:
                    return
                try:
                    m = match_once(self.config, self.session_id)
                    if not m.get("ran"):
                        logger.warning(
                            f"Feed matching skipped: {m.get('reason')}")
                except Exception as e:
                    logger.error(f"Feed match error: {e}")
                time.sleep(self.match_interval)
