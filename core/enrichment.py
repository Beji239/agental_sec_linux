"""
core/enrichment.py, tier 1 of the research worker. TODO section 35.

WHY THIS EXISTS
`web_search` is DuckDuckGo and nothing else, and when DDG has nothing the
model is left holding nothing. An outbound connection to an address it cannot
name stays unnamed, and worse, the model sometimes reports that it HAS NO
ACCESS to that information, which reads to a user as a missing capability
rather than what it really is, a missing lookup.

Section 35 answered that with three tiers. This file is TIER 1 ONLY, and the
choice to build tier 1 on its own is the important part of the design:

    TIER 1  structured sources, plain API calls, JSON parsing     <- this file
    TIER 2  fetch and read arbitrary pages, a model reads prose   not built
    TIER 3  a real headless browser                               not built

Tier 1 needs no second model, reads no HTML, executes no script and renders
nothing. It is `requests.get` against registries and `json.loads` on what
comes back. That is why it can land now instead of waiting for the privilege
split in item 3.1: 35.5 says a fetcher pulling attacker-controlled content
inside a process running as Administrator is the worst version of this idea,
and that argument is about tier 2 and tier 3. It does not reach a JSON field
from a regional internet registry.

Tier 2 still waits for the sandbox. Nothing here should be read as permission
to add page fetching to it later without one.

WHAT IT IS NOT
There is no worker CONVERSATION in this file. Section 35 described a second
DeepSeek conversation with its own history, and that is still the right shape
for tier 2, where something has to read a vendor advisory and decide what it
said. At tier 1 there is nothing for a model to read: the sources answer in
fields, and a model in the middle would add cost, latency and a place for a
hallucination to enter a record the main agent later reads as fact. So the
worker here is a thread, not an agent.

IT NEVER RETURNS EMPTY. 35.3.
Every job writes a row carrying a status, and the three are different claims:

    resolved     two independent sources answered and agree
    partial      something was learned, and the gap is named explicitly
    unresolved   nothing found, and here is exactly what was tried

`unresolved` with the source list attached is honest data and the model can
use it. Silence is not. This is the same discipline as `sensors.py` and
`oui.py`: the several ways of not knowing are not collapsed into one word.

THE TRUST BOUNDARY. 35.4.
These rows are written from third-party responses and later read by an agent
holding `kill_process` and `block_port`, so:

  * FIELDS ONLY. `_fields_only` drops anything that is not a scalar and caps
    every string at FIELD_MAX_CHARS. RDAP `remarks` and `notices`, which are
    the free-prose parts of an RDAP response, are never read at all. This is
    structural rather than a rule somebody has to remember.
  * Source URLs are kept on every row.
  * Every row and every tool result is marked EXTERNAL INTEL. The model must
    be able to see that this is second-hand and not an observation of this
    network.
  * Both tools are in `sanitize.UNTRUSTED_TOOLS`, so results reach the model
    fenced like packet payloads.
  * Nothing here can approve anything. Enrichment cannot reach the
    Approve/Deny gate.

SOURCES

  NO KEY NEEDED
    RDAP via rdap.org       who owns an address or a domain, redirects to the
                            authoritative RIR
    ip-api.com              the second opinion, plus proxy/hosting/mobile
    CIRCL Vulnerability-Lookup   CVE detail
    NVD                     CVE detail, slower without a key
    the local IEEE file     vendor prefix, no network at all
    LOLBAS                  Windows binaries with a known abuse technique

  KEY IN .env, ADDED 2026-09-02
    AbuseIPDB      AGENTAL_ABUSEIPDB_KEY. Reputation, which nothing else here
                   answers. Free, roughly 1000 checks a day.
    abuse.ch       AGENTAL_ABUSECH_KEY. MalwareBazaar for file hashes,
                   URLhaus for hosts and addresses serving malware. Free from
                   auth.abuse.ch.
    GreyNoise      AGENTAL_GREYNOISE_KEY. Answers the one question none of the
                   others can, is this address scanning everybody or did it
                   pick us, plus the known-business-service list. Ported
                   2026-09-21; it was listed under "still off" until then
                   while the reason given was the account rather than the
                   absent code.

A source with no key says WHICH variable to set rather than just failing, so
"unresolved" never quietly means "you forgot the key".

OWNERSHIP AND REPUTATION ARE DIFFERENT QUESTIONS, and keeping them apart is
the one structural thing to understand here. The ladder corroborates IDENTITY
and stops early when two sources agree. Reputation sources run regardless.
Putting reputation in the ladder would have skipped it exactly when the
identity lookup went well, which is most of the time. See ENRICHERS_BY_KIND.
"""

import ipaddress
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone

import requests

logger = logging.getLogger(__name__)


# WHAT CAN BE LOOKED UP

KINDS = ("ip", "domain", "cve", "mac", "hash", "process")

_CVE_RE  = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_MAC_RE  = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$", re.I)
_HASH_RE = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.I)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$",
    re.I,
)


def classify(indicator: str) -> str | None:
    """
    What KIND of thing is this, decided from its shape.

    Returns None when the string is not a recognisable indicator. A caller
    that cannot name the kind gets a refusal rather than a guess, because a
    guessed kind sends the wrong sources at the wrong question and the answer
    still lands in the database looking authoritative.
    """
    s = (indicator or "").strip()
    if not s:
        return None
    if _CVE_RE.match(s):
        return "cve"
    if _MAC_RE.match(s):
        return "mac"
    if _HASH_RE.match(s):
        return "hash"
    try:
        ipaddress.ip_address(s)
        return "ip"
    except ValueError:
        pass
    # PROGRAM NAMES ARE CHECKED BEFORE DOMAINS, and it has to be that way
    # round. "certutil.exe" matches the domain pattern perfectly well, because
    # "exe" looks exactly like a two-or-three letter TLD, so a domain-first
    # order sends every process name to RDAP as if it were a website.
    #
    # That is safe only because `.com` is deliberately NOT in _PROCESS_RE. It
    # is a real Windows executable extension AND the most common domain suffix
    # there is, and a string that could be either is a domain every time it
    # matters here. None of the other extensions in that pattern are real
    # TLDs, so nothing else collides.
    tail = s.replace("\\", "/").split("/")[-1]
    if _PROCESS_RE.match(s) or _PROCESS_RE.match(tail):
        return "process"
    if _DOMAIN_RE.match(s):
        return "domain"
    return None


# CACHE LIFETIMES. 35.6.
#
# A repeat indicator must cost nothing, or this quietly undoes the reason for
# moving the main loop to local Ollama. The lifetimes differ because the FACTS
# differ, not because somebody picked round numbers:
#
#   ownership and ASN     change rarely, a block is reallocated over years
#   CVE detail            is close to permanent, though NVD does revise scores
#   vendor prefix         the IEEE registry only ever grows
#   anything unresolved   expires fast ON PURPOSE, which is how 35.3's
#                         "requeue it later with a bigger budget" happens
#                         without a scheduler: the next question about the
#                         same indicator finds a stale row and re-runs it.
#
# REPUTATION AGES FASTER THAN OWNERSHIP, and that broke the simple per-kind
# rule once AbuseIPDB was switched on, 2026-09-02. An IP row now carries both:
# who owns the block, which is stable for years, and how many people reported
# it lately, which is not. A month is far too long for the second one, so an
# IP row that carries a reputation field gets the shorter life. The address
# still costs nothing to re-ask; the point is that a stale score does not sit
# there looking current.

TTL_SECONDS = {
    "ip":      30 * 86400,
    "domain":  14 * 86400,
    "cve":     90 * 86400,
    "mac":    365 * 86400,
    "hash":         86400,
    # LOLBAS entries change about as often as Windows ships a new abusable
    # binary, which is not often.
    "process":  30 * 86400,
}

UNRESOLVED_TTL_SECONDS = 6 * 3600

# Applied to any row carrying a reputation field, whatever its kind.
REPUTATION_TTL_SECONDS = 7 * 86400
REPUTATION_FIELDS = ("abuse_confidence_score", "serves_malware", "known_malware")


# CAPS. 35.6.

HTTP_TIMEOUT      = 8       # per request
JOB_WALL_CLOCK    = 30      # per job, across all its sources
MAX_QUEUE_DEPTH   = 200     # refuse beyond this rather than grow without end
FIELD_MAX_CHARS   = 200     # per stored string. prose cannot fit through
MAX_FIELDS        = 40
MAX_ATTEMPTS      = 3       # a job that keeps failing stops being retried

USER_AGENT = "AgentalSec/2 (+homelab security agent; contact via operator)"

# Politeness floors, measured against each source's published limits:
#   rdap.org        10 requests in 10 seconds behind Cloudflare
#   ip-api.com      about 45 a minute on the free tier
#   NVD             5 requests per 30 seconds without a key
#   CIRCL           no published number, so a conservative floor
_MIN_INTERVAL = {
    "rdap":      1.2,
    "ip_api":    1.5,
    "nvd":       6.5,
    "circl":     1.0,
    "abuseipdb": 1.0,   # ~1000 a day is the real limit, not a per-second one
    "abuse_ch":  1.0,
    "lolbas":    2.0,   # one fetch per month in practice, this is a floor
    # GreyNoise publishes per-plan quotas rather than a per-second rate. 1.0
    # is a floor against bursting, not a quota manager: if the plan's daily
    # allowance runs out this will still get a 429, and _greynoise_get says so
    # in words rather than pretending the address came back quiet.
    "greynoise": 1.0,
}
_last_call: dict[str, float] = {}
_throttle_lock = threading.Lock()

# THE NVD API KEY, PORTED 2026-09-21 WITH THE TOOLS BATCH.
#
# NVD's rate limit is the one that bites here: without a key an anonymous
# caller gets roughly five requests per thirty seconds, with one it is fifty.
# This mattered enough to write down on the Windows side because of a single
# caller, tools/kev_cvss, which walks the whole CISA KEV mirror. That is about
# 1700 lookups: close to three hours at the anonymous rate and about twenty
# minutes with a key. Same code either way, so the key is optional and its
# absence slows the backfill down rather than turning anything off.
#
# The value itself lives in .env and never in code. AGENTAL_NVD_API_KEY is the
# same name the Windows tree uses, so one .env works on both.
NVD_KEY_ENV = "AGENTAL_NVD_API_KEY"


def _nvd_key() -> str:
    return os.environ.get(NVD_KEY_ENV, "").strip()


def _nvd_headers() -> dict:
    """The key header, or nothing at all. Never a header with an empty value."""
    key = _nvd_key()
    return {"apiKey": key} if key else {}


def _interval_for(source: str) -> float:
    """The politeness floor for this source, right now."""
    if source == "nvd" and _nvd_key():
        return 0.7
    return _MIN_INTERVAL.get(source, 1.0)


def _throttle(source: str):
    """Sleep just enough that this source is never called faster than agreed."""
    floor = _interval_for(source)
    with _throttle_lock:
        last = _last_call.get(source, 0.0)
        wait = floor - (time.time() - last)
        if wait > 0:
            time.sleep(wait)
        _last_call[source] = time.time()


# THE FIELD FILTER. 35.4.

def _fields_only(raw: dict) -> dict:
    """
    Keep scalars, cap every string, drop everything else.

    This is the boundary rule made structural. "Fields only, no free prose"
    is easy to agree to and easy to forget the first time a source returns a
    genuinely useful description, so the filter is applied to every source's
    output on the way out rather than trusted to each parser.

    Nested structures are dropped rather than flattened. A dropped field is
    visible in the row because it simply is not there; a flattened one would
    smuggle the same prose in under a longer key.
    """
    out = {}
    for key, value in list(raw.items())[:MAX_FIELDS]:
        if value is None or isinstance(value, bool):
            out[key] = value
        elif isinstance(value, (int, float)):
            out[key] = value
        elif isinstance(value, str):
            text = value.strip()
            if len(text) > FIELD_MAX_CHARS:
                text = text[:FIELD_MAX_CHARS] + "...[truncated]"
            out[key] = text or None
    return out


_ORG_NOISE = re.compile(
    r"\b(inc|llc|ltd|limited|corp|corporation|company|co|gmbh|bv|b\.v|sa|"
    r"s\.a|ab|as|oy|plc|group|holdings|technologies|technology|networks|"
    r"network|communications|telecom|services|systems|the)\b\.?",
    re.I,
)


def _org_tokens(name: str) -> set:
    """
    Reduce an organisation name to comparable tokens.

    "Google LLC" and "Google Inc." are the same allocation described by two
    registries with different house style. Stripping the corporate suffixes
    and comparing what is left is crude, and it is deliberately crude: the
    alternative is a fuzzy score with a threshold nobody can justify, and a
    threshold that is wrong in the generous direction manufactures agreement
    where there is none.
    """
    if not name:
        return set()
    cleaned = _ORG_NOISE.sub(" ", name.lower())
    cleaned = re.sub(r"[^a-z0-9 ]+", " ", cleaned)
    return {t for t in cleaned.split() if len(t) > 2}


def _identity_tokens(fields: dict) -> set:
    """
    The network's own identifiers, as opposed to whoever owns it.

    Network name, network handle, ASN, ASN name. These are registry-assigned
    and unique, so an overlap here is a stronger signal than a company name
    match, not a weaker one. Used as the second agreement key.

    The maintainer suffix is stripped, so EXAMPLENET-MNT and EXAMPLENET land on
    the same token instead of being two different words.
    """
    out = set()
    for key in ("network_name", "network_handle", "asn", "asn_name", "organisation"):
        value = fields.get(key)
        if not isinstance(value, str):
            continue
        cleaned = _RDAP_ADMIN_NAME.sub("", value.strip())
        cleaned = re.sub(r"[^a-z0-9 ]+", " ", cleaned.lower())
        out |= {t for t in cleaned.split() if len(t) > 3}
    # Generic words that show up on unrelated allocations and would fake a
    # match. "net" and "the" are already too short to survive the filter.
    return out - {"network", "networks", "hosting", "limited", "telecom",
                  "internet", "services", "communications"}


# SOURCES
#
# Every source returns (fields, url, error). All three matter:
#
#   fields is None and error is None   the source answered and has no record
#   fields is None and error is set    the source did not answer
#
# Those are different facts and the ladder below treats them differently. A
# registry saying "no such allocation" is evidence; a timeout is not.


def _get_json(url: str, source: str, params: dict = None) -> tuple[dict | None, str | None]:
    _throttle(source)
    try:
        resp = requests.get(
            url,
            params=params,
            # The NVD key rides along here rather than being passed in by the
            # caller. One place decides, so a second NVD call added later
            # cannot forget it, and the signature every test stub copies does
            # not move.
            headers={"User-Agent": USER_AGENT, "Accept": "application/json",
                     **(_nvd_headers() if source == "nvd" else {})},
            timeout=HTTP_TIMEOUT,
            # requests forwards custom key headers across hosts on a redirect.
            allow_redirects=source != "nvd",
        )
    except requests.RequestException as e:
        return None, f"{type(e).__name__}"

    if resp.status_code == 404:
        return None, None                      # answered, has no record
    if resp.status_code == 429:
        return None, "rate limited (429)"
    if resp.status_code != 200:
        return None, f"HTTP {resp.status_code}"
    try:
        return resp.json(), None
    except ValueError:
        return None, "unreadable JSON"


# ROLE PRIORITY, and this is not cosmetic.
#
# ARIN's answer for 8.8.8.8 lists the abuse contact FIRST, and its display
# name is the literal string "Abuse". A first-match walk down the entity list
# therefore reports the owner of 8.8.8.8 as "Abuse", which then fails to match
# ip-api's "Google LLC" and grades a completely ordinary lookup as
# sources_disagree. Caught here before it shipped, by reading a real ARIN
# response rather than the RFC.
#
# So roles are ranked and the whole list is searched for each rank in turn.
# `abuse` is not in the list at all: it names a mailbox, not an owner.
_RDAP_ROLE_PRIORITY = ("registrant", "owner", "administrative", "technical")

# RIPE HANDS BACK MAINTAINER OBJECTS, AND THEY ARE NOT OWNERS. Found on a real
# run, 2026-09-02, second failure of the same shape as the ARIN abuse contact.
#
# Asking about an address on a RIPE block came back with "EXAMPLENET-MNT" while
# ip-api said "Example Software LLC", so a completely ordinary lookup graded as
# sources_disagree. Those are the same outfit: the -MNT object is the RIPE
# mntner, which is a permissions record saying who may edit the entry, not a
# statement about who owns the block.
#
# Every European address would have hit this, so it is worth a rule rather
# than a shrug. A name matching this is skipped and the walk carries on to the
# next candidate.
_RDAP_ADMIN_NAME = re.compile(
    r"-(MNT|RIPE|NCC|ADMIN|NOC|ABUSE|TECH|DBM)$|^MNT-|^ORG-.*-RIPE$", re.I)


def _looks_like_admin_object(name: str) -> bool:
    """A registry bookkeeping handle rather than an organisation name."""
    return bool(name and _RDAP_ADMIN_NAME.search(name.strip()))


def _rdap_org(payload: dict) -> str | None:
    """
    Pull the organisation name out of an RDAP entity list.

    RDAP nests the name inside a jCard, which is an array of arrays, so this
    walks rather than indexes. `remarks` and `notices` are the free-text parts
    of the same response and are deliberately never touched.

    Two registries have already tried to hand back something that is not an
    owner: ARIN puts the abuse contact first and calls it "Abuse", RIPE hands
    over the maintainer object. Both are filtered here, and I would expect a
    third one eventually, so the filters are named rather than inlined.
    """
    entities = [e for e in (payload.get("entities") or []) if isinstance(e, dict)][:12]

    def _fn(entity):
        vcard = entity.get("vcardArray")
        if not (isinstance(vcard, list) and len(vcard) > 1):
            return None
        for item in vcard[1]:
            if (isinstance(item, list) and len(item) >= 4 and item[0] == "fn"
                    and isinstance(item[3], str) and item[3].strip()):
                return item[3].strip()
        return None

    fallback = None                       # an admin object, only if nothing better

    for role in _RDAP_ROLE_PRIORITY:
        for entity in entities:
            if role in [r.lower() for r in (entity.get("roles") or [])]:
                name = _fn(entity)
                if not name:
                    continue
                if _looks_like_admin_object(name):
                    fallback = fallback or name
                    continue
                return name

    # No ranked role carried a usable name. Take any entity's name before
    # falling back to a handle, since a handle is a database key not an owner.
    for entity in entities:
        name = _fn(entity)
        if name and not _looks_like_admin_object(name):
            return name

    # Nothing clean anywhere. Returning the maintainer beats returning None:
    # it is still a real string from the registry, the agreement check below
    # now has the ASN to fall back on, and a row saying EXAMPLENET-MNT is more
    # use to a reader than a blank.
    if fallback:
        return fallback
    for entity in entities:
        if entity.get("handle"):
            return str(entity["handle"])
    return None


def src_rdap_ip(ip: str) -> tuple[dict | None, str, str | None]:
    url = f"https://rdap.org/ip/{ip}"
    payload, err = _get_json(url, "rdap")
    if payload is None:
        return None, url, err
    fields = _fields_only({
        "organisation":   _rdap_org(payload),
        "network_name":   payload.get("name"),
        "network_handle": payload.get("handle"),
        "cidr_start":     payload.get("startAddress"),
        "cidr_end":       payload.get("endAddress"),
        "allocation_type": payload.get("type"),
        "registry_country": payload.get("country"),
    })
    if not any(fields.get(k) for k in ("organisation", "network_name", "network_handle")):
        return None, url, None
    return fields, url, None


def src_rdap_domain(domain: str) -> tuple[dict | None, str, str | None]:
    url = f"https://rdap.org/domain/{domain}"
    payload, err = _get_json(url, "rdap")
    if payload is None:
        return None, url, err
    events = {e.get("eventAction"): e.get("eventDate")
              for e in (payload.get("events") or []) if isinstance(e, dict)}
    fields = _fields_only({
        "organisation":  _rdap_org(payload),
        "domain_handle": payload.get("handle"),
        "registered_at": events.get("registration"),
        "expires_at":    events.get("expiration"),
        "last_changed":  events.get("last changed"),
        "status":        ", ".join(payload.get("status") or []) or None,
    })
    if not any(fields.values()):
        return None, url, None
    return fields, url, None


def src_ip_api(ip: str) -> tuple[dict | None, str, str | None]:
    """
    ip-api.com, the same source core/ip_lookup.py already uses.

    HOW INDEPENDENT IS THIS, really. Its ownership fields ultimately derive
    from the same RIR data RDAP serves, so agreement between the two is
    weaker evidence than two genuinely independent sources would be. It is
    still worth having as the second opinion, because it catches a parsing
    failure on either side and because proxy, hosting and mobile come from
    ip-api's own classification rather than from the registry. The docstring
    says so rather than the confidence field overclaiming.
    """
    url = f"http://ip-api.com/json/{ip}"
    payload, err = _get_json(
        url, "ip_api",
        params={"fields": "status,message,country,regionName,city,isp,org,as,"
                          "asname,reverse,proxy,hosting,mobile"},
    )
    if payload is None:
        return None, url, err
    if payload.get("status") != "success":
        return None, url, None
    fields = _fields_only({
        "organisation":       payload.get("org") or payload.get("isp"),
        "isp":                payload.get("isp"),
        "asn":                payload.get("as"),
        "asn_name":           payload.get("asname"),
        "reverse_dns":        payload.get("reverse") or None,
        "registered_country": payload.get("country"),
        "registered_city":    payload.get("city"),
        "is_proxy_or_vpn":    bool(payload.get("proxy")),
        "is_datacentre":      bool(payload.get("hosting")),
        "is_mobile_network":  bool(payload.get("mobile")),
    })
    return fields, url, None


def src_circl_cve(cve: str) -> tuple[dict | None, str, str | None]:
    url = f"https://vulnerability.circl.lu/api/vulnerability/{cve.upper()}"
    payload, err = _get_json(url, "circl")
    if payload is None:
        return None, url, err
    if not isinstance(payload, dict) or not payload:
        return None, url, None

    # The record shape moved when CIRCL became Vulnerability-Lookup, so both
    # the old flat keys and the newer containers are checked. A parser that
    # only knows one shape reports "no record" for a CVE that is right there,
    # which is the failure mode this whole file exists to stop.
    containers = (payload.get("containers") or {}).get("cna") or {}
    metrics = containers.get("metrics") or payload.get("metrics") or []
    score, severity, vector = None, None, None
    if isinstance(metrics, list):
        for m in metrics[:6]:
            if not isinstance(m, dict):
                continue
            for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
                block = m.get(key)
                if isinstance(block, dict):
                    score    = block.get("baseScore", score)
                    severity = block.get("baseSeverity", severity)
                    vector   = block.get("vectorString", vector)
    if score is None:
        score = payload.get("cvss")

    meta = payload.get("cveMetadata") or {}
    fields = _fields_only({
        "cve_id":        meta.get("cveId") or payload.get("id") or cve.upper(),
        "published":     (meta.get("datePublished") or payload.get("published")
                          or payload.get("Published")),
        "modified":      (meta.get("dateUpdated") or payload.get("modified")
                          or payload.get("Modified")),
        "cvss_score":    score,
        "cvss_severity": severity,
        "cvss_vector":   vector,
    })
    if not fields.get("cve_id"):
        return None, url, None
    return fields, url, None


def src_nvd_cve(cve: str) -> tuple[dict | None, str, str | None]:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    payload, err = _get_json(url, "nvd", params={"cveId": cve.upper()})
    if payload is None:
        return None, url, err
    items = payload.get("vulnerabilities") or []
    if not items:
        return None, url, None
    record = (items[0] or {}).get("cve") or {}

    score, severity, vector = None, None, None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        block = (record.get("metrics") or {}).get(key)
        if isinstance(block, list) and block:
            data = block[0].get("cvssData") or {}
            score    = data.get("baseScore", score)
            severity = data.get("baseSeverity") or block[0].get("baseSeverity") or severity
            vector   = data.get("vectorString", vector)
            break

    fields = _fields_only({
        "cve_id":        record.get("id") or cve.upper(),
        "published":     record.get("published"),
        "modified":      record.get("lastModified"),
        "vuln_status":   record.get("vulnStatus"),
        "cvss_score":    score,
        "cvss_severity": severity,
        "cvss_vector":   vector,
    })
    return fields, f"{url}?cveId={cve.upper()}", None


def src_oui_mac(mac: str) -> tuple[dict | None, str, str | None]:
    """
    The local IEEE file. No network, so this one cannot time out or leak.

    core/oui.py already refuses to collapse its four outcomes into "unknown",
    and that distinction is carried through here rather than flattened: a
    randomized address is a POSITIVE fact about the device, an unknown prefix
    means the registry really has no entry, and no_data means nobody looked.
    """
    try:
        from core import oui
    except Exception as e:
        return None, "local:oui", f"oui module unavailable ({type(e).__name__})"

    result = oui.lookup(mac)
    status = result.get("status")
    url = "local:data/oui.csv"

    if status == "resolved":
        return _fields_only({
            "vendor":         result.get("vendor"),
            "registry_block": result.get("source"),
        }), url, None
    if status == "randomized":
        return _fields_only({
            "vendor":            None,
            "address_is_random": True,
            "why":               "locally administered address, no vendor exists",
        }), url, None
    if status == "unknown_prefix":
        return None, url, None
    return None, url, "no local IEEE registry file, run scripts/update_oui.py"


# LOLBAS. THE LAST GAP IN TIER 1, CLOSED 2026-09-02.
#
# Living Off The Land Binaries And Scripts: a catalogue of LEGITIMATE, usually
# Microsoft-signed Windows binaries that attackers use to do something other
# than what the binary is for. certutil.exe is a certificate tool that also
# downloads files. mshta.exe runs HTML applications and also runs whatever an
# attacker points it at.
#
# WHY THIS IS THE RIGHT SOURCE FOR A PROCESS NAME. There is no registry that
# answers "what is svchost.exe" the way RDAP answers "who owns this address",
# so process names were the one indicator kind with nothing but web_search
# behind them. LOLBAS does not answer that question either, and that is fine,
# because it answers a BETTER one for this tool: is this a binary that turns
# up in attacks, and by what technique.
#
# THE MISREADING THIS INVITES, said here and again in the tool description,
# because today has been a lesson in guidance written for the row I pictured.
# A LOLBAS hit means the binary is ABUSABLE. It does not mean this process is
# malicious, and it never means the file is not genuine. certutil.exe is on
# every Windows machine on earth and is signed by Microsoft. The entry is
# about what the binary CAN be used for, not about what this copy of it did.
#
# CACHED ON DISK, unlike core/oui.py which reads a file a script has to
# download. The difference is deliberate: oui.py is offline BY DESIGN, it must
# never reach the network at call time. This module already does nothing but
# reach the network, so making the operator remember a manual update step
# would be friction for no security gain. TODO 36.3 already records the cost
# of that friction, "run update_oui.py once or it reports no_data forever".

LOLBAS_URL = "https://lolbas-project.github.io/api/lolbas.json"
LOLBAS_MAX_AGE_DAYS = 30
LOLBAS_MAX_BYTES = 12 * 1024 * 1024     # the file is a few MB; refuse a surprise

_lolbas_index: dict | None = None
_lolbas_lock = threading.Lock()

# Extensions that mean "this is a program", used by classify(). `.com` is
# DELIBERATELY ABSENT: it is a real Windows executable extension and also the
# most common domain suffix on the internet, and "example.com" is a domain
# every time it matters here.
_PROCESS_RE = re.compile(
    r"^[A-Za-z0-9_.\-]{1,64}\.(exe|dll|ps1|bat|cmd|vbs|js|jse|msi|msc|scr|hta|sys)$",
    re.I,
)


def _lolbas_cache_path():
    from pathlib import Path
    return Path(__file__).resolve().parent.parent / "data" / "lolbas.json"


def _load_lolbas() -> dict | None:
    """
    The catalogue as {lowercase name: entry}. None means it could not be had.

    Returning None rather than an empty dict matters for the same reason it
    does everywhere else in this project: an empty catalogue would report
    every process as "not a known abusable binary", which is a confident and
    completely unearned claim.

    A stale cache is used when a refresh fails. Month-old LOLBAS data is very
    nearly current, and it beats answering nothing because GitHub had a bad
    minute.
    """
    global _lolbas_index
    with _lolbas_lock:
        if _lolbas_index is not None:
            return _lolbas_index

        cache = _lolbas_cache_path()
        raw = None

        fresh = False
        if cache.exists():
            age_days = (time.time() - cache.stat().st_mtime) / 86400
            fresh = age_days < LOLBAS_MAX_AGE_DAYS
            if fresh:
                try:
                    raw = json.loads(cache.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    raw = None

        if raw is None:
            _throttle("lolbas")
            try:
                resp = requests.get(LOLBAS_URL, timeout=20,
                                    headers={"User-Agent": USER_AGENT})
                if resp.status_code == 200 and len(resp.content) <= LOLBAS_MAX_BYTES:
                    raw = resp.json()
                    try:
                        cache.parent.mkdir(parents=True, exist_ok=True)
                        cache.write_text(json.dumps(raw), encoding="utf-8")
                    except OSError as e:
                        # A read-only data dir is survivable. It just means a
                        # download every restart, so say so once.
                        logger.warning(f"[enrichment] could not cache LOLBAS: {e}")
                else:
                    logger.warning(f"[enrichment] LOLBAS fetch: HTTP "
                                   f"{resp.status_code}, {len(resp.content)} bytes")
            except (requests.RequestException, ValueError) as e:
                logger.warning(f"[enrichment] LOLBAS fetch failed: {type(e).__name__}")

            # The refresh failed. Fall back to whatever is on disk, however old.
            if raw is None and cache.exists():
                try:
                    raw = json.loads(cache.read_text(encoding="utf-8"))
                    logger.info("[enrichment] using a stale LOLBAS cache.")
                except (OSError, ValueError):
                    raw = None

        if not isinstance(raw, list) or not raw:
            return None

        index = {}
        for entry in raw:
            if isinstance(entry, dict) and entry.get("Name"):
                index[str(entry["Name"]).strip().lower()] = entry
        _lolbas_index = index or None
        return _lolbas_index


def _uniq_join(values, limit=6) -> str | None:
    """Distinct, order-preserved, joined, capped. None when there is nothing."""
    seen, out = set(), []
    for v in values:
        v = (str(v) if v is not None else "").strip()
        if v and v.lower() not in seen:
            seen.add(v.lower())
            out.append(v)
        if len(out) >= limit:
            break
    return ", ".join(out) or None


def src_lolbas(process_name: str) -> tuple[dict | None, str, str | None]:
    """
    Is this a Windows binary that turns up in attacks, and by what technique.

    Takes a bare name or a full path; only the filename is used, because the
    path a binary was run from is a fact about THIS machine and belongs in the
    observation tables, not in a lookup against a public catalogue.
    """
    name = (process_name or "").strip().replace("\\", "/").split("/")[-1]
    if not name:
        return None, LOLBAS_URL, None

    index = _load_lolbas()
    if index is None:
        return None, LOLBAS_URL, ("the LOLBAS catalogue could not be loaded, so "
                                  "nothing is known either way. This is not a "
                                  "statement about the binary.")

    entry = index.get(name.lower())
    if not entry:
        return None, LOLBAS_URL, None            # answered, no record

    commands = [c for c in (entry.get("Commands") or []) if isinstance(c, dict)]
    fields = _fields_only({
        "abusable_windows_binary": True,
        "binary_name":       entry.get("Name"),
        "what_it_is":        entry.get("Description"),
        "abuse_categories":  _uniq_join(c.get("Category") for c in commands),
        "abuse_usecases":    _uniq_join((c.get("Usecase") for c in commands), limit=3),
        "mitre_ids":         _uniq_join(c.get("MitreID") for c in commands),
        "needs_privileges":  _uniq_join(c.get("Privileges") for c in commands),
        "documented_techniques": len(commands) or None,
    })
    return fields, entry.get("url") or LOLBAS_URL, None


def _lolbas_note(fields: dict) -> str:
    """
    How to read a LOLBAS hit. Generated on read, never stored, same as the
    abuse score note and for the same reason.

    Written from the failure mode rather than from the feature. Three times
    today a note written for the row I pictured was WRONG on the row that
    turned up, so this one leads with the thing that is true of every hit:
    the binary is legitimate.
    """
    name = fields.get("binary_name") or "This binary"
    return (f"{name} is a LEGITIMATE Windows binary, usually signed by "
            f"Microsoft, and it is on the machine because it belongs there. "
            f"LOLBAS lists it because it CAN be misused, not because this copy "
            f"of it did anything. Finding it running is completely ordinary. "
            f"What makes it interesting is the CONTEXT you observed yourself: "
            f"an unusual parent process, a command line matching one of the "
            f"documented techniques, network activity from something that has "
            f"no reason to talk to the internet. Report the observation and "
            f"cite this as the reason it is worth a look. Do NOT report the "
            f"listing on its own as a finding.")


# KEYED SOURCES
#
# Defined so that switching one on is a key in .env and not a design
# conversation, and so a reader can see WHAT IS MISSING rather than infer it
# from an absence. Each carries the reason it is off if it is off.
KEYED_SOURCES = {
    "abuseipdb": {
        "env":   "AGENTAL_ABUSEIPDB_KEY",
        "kinds": ("ip",),
        "gives": "abuse reports, confidence score, whether the address is a known scanner",
        # These notes are read as "why this is off", so they are written for
        # the case where the key is missing. They used to say "Off" flatly and
        # went stale the day the keys were added, 2026-09-02, which is the
        # same prose-drifts-from-state defect SOURCE_CATALOG exists to stop.
        "note":  "free key from abuseipdb.com, about 1000 checks a day. "
                 "Without it nothing here answers whether an address is known "
                 "bad, which is the biggest gap in the keyless set.",
    },
    "abuse_ch": {
        "env":   "AGENTAL_ABUSECH_KEY",
        "kinds": ("hash", "domain", "ip"),
        "gives": "MalwareBazaar sample detail and URLhaus malware distribution URLs",
        "note":  "abuse.ch requires an Auth-Key, free from auth.abuse.ch. "
                 "Without it file hashes have no source at all, since "
                 "MalwareBazaar is the only one.",
    },
    "greynoise": {
        "env":   "AGENTAL_GREYNOISE_KEY",
        "kinds": ("ip",),
        "gives": "whether an address is mass-scanning the internet rather than targeting this host",
        # REWRITTEN 2026-09-21 WITH THE PORT. The previous note here said "not
        # usable on this account. Off.", which was a statement about the
        # operator's account rather than about the code, and it was the second
        # half of a real problem: this tree had no src_greynoise_ip at all, so
        # the source was absent for a reason nobody had written down, and the
        # note gave a reason that was not it.
        "note":  "key required. Quotas are per plan rather than per second, so "
                 "a spent allowance shows up as a 429 and is reported as "
                 "'rate limited', never as a quiet address.",
    },
}


def _keyed_available(name: str) -> bool:
    return bool(_key_for(name))


def _key_for(name: str) -> str:
    return os.environ.get(KEYED_SOURCES[name]["env"], "").strip()


# REPUTATION. A DIFFERENT QUESTION FROM OWNERSHIP.
#
# THE TRAP THIS AVOIDS, and I nearly walked into it. The obvious thing is to
# append AbuseIPDB to the IP source list and let the ladder handle it. That
# would be wrong, and quietly so: the ladder stops the moment two sources
# agree on ownership, and RDAP and ip-api usually do. So the reputation lookup
# would be skipped EXACTLY WHEN EVERYTHING IS WORKING, and only run on the
# addresses whose ownership was already murky.
#
# The fix is to notice that these answer a different question. "Who owns this"
# and "has anybody reported this" are not two opinions about one fact, so they
# do not belong in one ladder. Reputation sources always run when their key is
# present, contribute fields, and take no part in the agreement grading. A
# resolved status still means the OWNERSHIP was corroborated, which is what it
# has always meant.
#
# Filled in below, once the source functions exist.
ENRICHERS_BY_KIND: dict[str, list] = {}


def _abuse_confidence_note(score, fields: dict = None) -> str:
    """
    How to read an AbuseIPDB answer, generated at read time and never stored.

    Same reasoning as `lookup_ip.how_to_read_this`. A score is not a verdict
    and this is the field most likely to be over-read: a busy datacentre
    address collects reports the way a busy road collects litter, and a report
    is one stranger's opinion typed into a form.

    THE REPORT COUNT NEEDED ITS OWN SENTENCE, and I only saw why after
    watching a real answer. 8.8.8.8 came back with score 0, whitelisted true,
    and TOTAL REPORTS 199. Every one of those numbers is correct and they look
    like a contradiction. A reader skimming for a big number sees 199 and
    stops there, which is precisely the misreading this whole note exists to
    stop, just aimed at a different field than the one I had guarded.

    Not stored on the row because it is OUR text rather than the source's, and
    a copy of it on every row is both waste and a slow way to make our own
    prose look like registry data.
    """
    fields = fields or {}
    reports = fields.get("abuse_total_reports")
    whitelisted = fields.get("abuse_is_whitelisted")

    # THE NOTE MUST NOT CONTRADICT THE ROW IT IS ATTACHED TO. Found on a real
    # run, 2026-09-02, and it is the third time this file has been bitten by
    # writing guidance for the case I imagined rather than the row in front of
    # me.
    #
    # A fixed-line ISP address in China came back score 5, one report, AND
    # flagged by URLhaus as actively serving malware. The canned low-score
    # sentence talks about busy DATACENTRE addresses collecting reports like
    # litter, which is true and completely irrelevant here: is_datacentre was
    # False and usage_type was "Fixed Line ISP". So the note read as
    # reassurance sitting directly under a malware hit.
    #
    # Two rules come out of that. A malware flag on the row is said first and
    # the score is explicitly not allowed to soften it. And the datacentre
    # sentence is only used when the row actually says datacentre.
    flagged = fields.get("serves_malware") or fields.get("known_malware")
    is_dc = fields.get("is_datacentre")

    if flagged:
        return ("This indicator is FLAGGED by URLhaus or MalwareBazaar, which "
                "is a separate fact from the score below and a much stronger "
                "one. A low abuse score does not soften a malware hit: they "
                "measure different things, one is who complained and the other "
                "is what was found. "
                + (f"The score is {score} from {reports or 'few'} report(s), "
                   f"which only means few people filed a report, not that "
                   f"little is happening. " if score is not None else "")
                + "Lead with the malware flag.")

    # Said FIRST when it applies, because it is the pair that looks wrong.
    prefix = ""
    if whitelisted:
        prefix = (f"AbuseIPDB has this address whitelisted, meaning it decided "
                  f"the address is something too widely used to act on, a big "
                  f"resolver or a crawler. "
                  + (f"It still shows {reports} reports, and that is NOT a "
                     f"contradiction: the reports exist, the score is held at "
                     f"zero anyway. Do not quote the report count as if it "
                     f"were a finding. "
                     if reports else "")
                  + "Whitelisted is a judgement by AbuseIPDB, not a promise. ")
    elif reports and float(score or 0) == 0:
        prefix = (f"{reports} reports exist but the score is zero, so the "
                  f"reports are old, thin, or from reporters with no standing. "
                  f"The count on its own is not a finding. ")

    try:
        value = float(score)
    except (TypeError, ValueError):
        return prefix + ("No score came back. That is not a clean bill of "
                         "health, it means nobody has answered.")
    if value == 0:
        return prefix + ("A score of zero. Common and unremarkable. It means "
                         "nobody's reports counted, not that the address is "
                         "safe.")
    if value < 25:
        if is_dc:
            return prefix + ("A low score. Busy datacentre and cloud addresses "
                             "collect a few reports the way a busy road "
                             "collects litter. On its own this is not evidence "
                             "of anything.")
        return prefix + ("A low score, so few people have filed a report. That "
                         "is weak evidence in BOTH directions: it does not "
                         "make the address suspicious and it does not clear "
                         "it. Most addresses nobody has bothered to report are "
                         "simply addresses nobody looked at.")
    if value < 75:
        return prefix + ("A middling score. Worth mentioning alongside what you "
                "actually observed, never on its own. Reports are strangers' "
                "opinions typed into a form, and shared hosting means one bad "
                "tenant marks the whole address.")
    return prefix + ("A high score, so many people have reported this address "
            "recently. Still second-hand: say what was reported and what YOU "
            "observed, separately. This does not authorise any action by "
            "itself.")


def src_abuseipdb(ip: str) -> tuple[dict | None, str, str | None]:
    """
    AbuseIPDB. Has anybody complained about this address recently.

    THE ONLY REPUTATION SOURCE HERE, and the reason the keyless build had a
    hole in it. RDAP and ip-api both answer "who owns this" and neither has an
    opinion about behaviour.

    WHAT THE FIELDS ARE NOT.
      * `abuse_confidence_score` is a percentage of REPORTERS who thought
        something, weighted by their history. It is not a probability that
        the address is malicious and it is not a severity.
      * `is_whitelisted` means AbuseIPDB decided the address belongs to
        something too important to report, a big resolver or a search crawler.
        It is not a promise.
      * A datacentre address with a handful of reports is the ordinary state
        of the internet. Shared hosting means one bad tenant marks the address
        for everybody on it.

    90 day window rather than the 30 day default. A homelab asks about an
    address weeks after the traffic, and a report that aged out looks
    identical to a report that never existed.
    """
    key = _key_for("abuseipdb")
    url = "https://api.abuseipdb.com/api/v2/check"
    if not key:
        return None, url, ("no key set. Put AGENTAL_ABUSEIPDB_KEY in .env and "
                           "restart. Nothing else here answers reputation.")

    _throttle("abuseipdb")
    try:
        resp = requests.get(
            url,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json",
                     "User-Agent": USER_AGENT},
            timeout=HTTP_TIMEOUT,
            allow_redirects=False,  # the key must not follow one to another host
        )
    except requests.RequestException as e:
        return None, url, f"{type(e).__name__}"

    if resp.status_code in (401, 403):
        return None, url, ("key refused (HTTP %d). Check AGENTAL_ABUSEIPDB_KEY."
                           % resp.status_code)
    if resp.status_code == 429:
        return None, url, "rate limited, daily quota may be spent"
    if resp.status_code != 200:
        return None, url, f"HTTP {resp.status_code}"
    try:
        data = (resp.json() or {}).get("data") or {}
    except ValueError:
        return None, url, "unreadable JSON"
    if not data:
        return None, url, None

    fields = _fields_only({
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "abuse_total_reports":    data.get("totalReports"),
        "abuse_distinct_reporters": data.get("numDistinctUsers"),
        "abuse_last_reported_at": data.get("lastReportedAt"),
        "abuse_is_whitelisted":   data.get("isWhitelisted"),
        "abuse_is_tor":           data.get("isTor"),
        "abuse_usage_type":       data.get("usageType"),
        "abuse_isp":              data.get("isp"),
        "abuse_domain":           data.get("domain"),
    })
    return fields, f"https://www.abuseipdb.com/check/{ip}", None


def _abusech_post(endpoint: str, payload: dict, source: str
                  ) -> tuple[dict | None, str | None]:
    """
    One POST to an abuse.ch community API.

    NOTE ON THE ENDPOINTS. abuse.ch now has two APIs: the community one at
    mb-api / urlhaus-api with an `Auth-Key` header, and a newer Spamhaus
    hosted one at api.spamhaus.com using a Bearer JWT. The key you get from
    auth.abuse.ch is the community one, so that is what these use. If the
    community endpoints are ever retired, this is the function to move.

    A wrong Auth-Key comes back as HTTP 200 with a query_status, not as a 401,
    so the status has to be read rather than the response code trusted.
    """
    key = _key_for("abuse_ch")
    if not key:
        return None, ("no key set. Put AGENTAL_ABUSECH_KEY in .env and restart. "
                      "Get one free at auth.abuse.ch.")

    _throttle(source)
    try:
        resp = requests.post(
            endpoint, data=payload,
            headers={"Auth-Key": key, "User-Agent": USER_AGENT},
            timeout=HTTP_TIMEOUT,
            allow_redirects=False,  # the key must not follow one to another host
        )
    except requests.RequestException as e:
        return None, f"{type(e).__name__}"

    if resp.status_code in (401, 403):
        return None, f"key refused (HTTP {resp.status_code}). Check AGENTAL_ABUSECH_KEY."
    if resp.status_code != 200:
        return None, f"HTTP {resp.status_code}"
    try:
        data = resp.json() or {}
    except ValueError:
        return None, "unreadable JSON"

    status = (data.get("query_status") or "").lower()
    if status in ("ok", "found"):
        return data, None
    if status in ("no_results", "not_found", "hash_not_found", "url_not_found",
                  "no_results_found"):
        return None, None                       # answered, has no record
    if "auth" in status or "key" in status:
        return None, f"auth rejected ({status}). Check AGENTAL_ABUSECH_KEY."
    if status:
        return None, f"query_status={status}"
    return None, "no query_status in the response"


def src_malwarebazaar(file_hash: str) -> tuple[dict | None, str, str | None]:
    """
    MalwareBazaar. Is this file hash a known malware sample.

    A HIT IS A STRONG SIGNAL, unlike almost everything else in this file. The
    hash either matches a sample somebody uploaded or it does not, and there
    is no interpretation in between. A MISS IS NOT, and that asymmetry is
    worth stating: most malware is not in MalwareBazaar, so no record means
    nobody uploaded it, never that the file is clean.

    file_name and tags are chosen by whoever built the sample, so they are
    attacker text. Capped by _fields_only and fenced by sanitize like
    everything else.
    """
    url = "https://mb-api.abuse.ch/api/v1/"
    data, err = _abusech_post(url, {"query": "get_info", "hash": file_hash},
                              "abuse_ch")
    if data is None:
        return None, url, err

    rows = data.get("data") or []
    if not rows or not isinstance(rows, list):
        return None, url, None
    row = rows[0] if isinstance(rows[0], dict) else {}

    tags = row.get("tags") or []
    fields = _fields_only({
        "known_malware":     True,
        "malware_family":    row.get("signature"),
        "file_type":         row.get("file_type"),
        "file_name":         row.get("file_name"),
        "file_size":         row.get("file_size"),
        "first_seen":        row.get("first_seen"),
        "last_seen":         row.get("last_seen"),
        "sha256":            row.get("sha256_hash"),
        "tags":              ", ".join(str(t) for t in tags[:10]) if tags else None,
        "reporter":          row.get("reporter"),
    })
    return fields, f"https://bazaar.abuse.ch/sample/{row.get('sha256_hash') or file_hash}/", None


def src_urlhaus_host(host: str) -> tuple[dict | None, str, str | None]:
    """
    URLhaus. Has this host or address served malware.

    Takes a domain OR an IPv4 address, which is why it runs for both kinds.
    Reports how many malware URLs have been seen on it, how many are still
    live, and whether Spamhaus DBL or SURBL list it.

    SAME ASYMMETRY AS MALWAREBAZAAR. A hit is a real finding. No record means
    URLhaus has not seen it, which covers almost every host on the internet
    and says nothing at all.
    """
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    data, err = _abusech_post(url, {"host": host}, "abuse_ch")
    if data is None:
        return None, url, err

    urls = [u for u in (data.get("urls") or []) if isinstance(u, dict)]
    online = sum(1 for u in urls if (u.get("url_status") or "").lower() == "online")
    threats = [u.get("threat") for u in urls if u.get("threat")]
    blacklists = data.get("blacklists") or {}

    fields = _fields_only({
        "serves_malware":        True,
        "malware_url_count":     data.get("url_count") or len(urls) or None,
        "malware_urls_online":   online,
        "malware_first_seen":    data.get("firstseen"),
        "malware_threat":        max(set(threats), key=threats.count) if threats else None,
        "spamhaus_dbl":          blacklists.get("spamhaus_dbl"),
        "surbl":                 blacklists.get("surbl"),
    })
    return fields, data.get("urlhaus_reference") or f"https://urlhaus.abuse.ch/host/{host}/", None


def keyed_source_status() -> list[dict]:
    """What the keyed sources would add, and why each one is off."""
    out = []
    for name, meta in KEYED_SOURCES.items():
        out.append({
            "source":     name,
            "enabled":    _keyed_available(name),
            "kinds":      list(meta["kinds"]),
            "would_give": meta["gives"],
            "why_off":    None if _keyed_available(name) else meta["note"],
            "env_var":    meta["env"],
        })
    return out


# THE LADDER. 35.3.

def _merge(results: list[tuple[str, dict]]) -> dict:
    """
    Fold several sources into one field set, first answer wins per field.

    Sources are tried in a fixed order per kind, most authoritative first, so
    "first wins" means the registry beats the aggregator on any field both
    supply. Every field also records which source it came from, because a row
    that says "organisation: Example Software" without saying who claimed that
    is not much better than the search snippet this replaces.
    """
    merged, provenance = {}, {}
    for source_name, fields in results:
        for key, value in (fields or {}).items():
            if value in (None, "") or key in merged:
                continue
            merged[key] = value
            provenance[key] = source_name
    merged["_field_sources"] = provenance
    return merged


# GREYNOISE. IS THIS AIMED AT ME, OR AT EVERYONE.
#
# Added 2026-09-18. The question nothing else in this file could answer.
#
# RDAP and ip-api say who owns an address. AbuseIPDB says whether strangers
# have complained about it. URLhaus says whether it is handing out malware.
# None of them can tell you the one thing that decides whether a hit on your
# firewall is worth your evening: is this address knocking on every door on
# the internet, or did it pick yours.
#
# GreyNoise runs sensors in a lot of places and answers exactly that. It also
# answers the mirror question through what used to be called RIOT: is this a
# known business service, a public resolver, a CDN, a software updater, the
# kind of address that turns up in logs constantly and means nothing.
#
# TWO DATASETS, ONE ENDPOINT. /v3/ip returns both halves in one response and
# either half can be absent. `internet_scanner_intelligence.found` false means
# they have no scan record. `business_service_intelligence.found` false means
# it is not on their known-services list. Both false is the common case and is
# a real answer, not a failure, which is the distinction this whole module
# keeps having to make.
#
# WHAT I COULD NOT VERIFY. api.greynoise.io is not reachable from where this
# was written, so the field names below come from GreyNoise's own Python SDK
# (v3.1.0, the response templates in greynoise/cli/templates) rather than from
# a live call I watched. That is better than guessing and worse than running
# it. scripts/greynoise_check.py exists to close that gap on a machine that
# can actually reach them, and until it has been run once this source should
# be treated as unproven rather than working.
GREYNOISE_API = "https://api.greynoise.io"


def _greynoise_get(path: str, what: str) -> tuple[dict | None, str, str | None]:
    """
    One GET to GreyNoise. Returns (body, url, error) with error None on 404.

    404 IS NOT AN ERROR HERE and that is the whole reason this helper exists
    rather than being inlined twice. "GreyNoise has no record of this" is a
    useful answer that the caller turns into fields. A refused key, a spent
    quota and a network failure are NOT that, and if they collapse into the
    same return value the tool ends up telling someone an address is quiet
    when the truth is nobody asked.
    """
    key = _key_for("greynoise")
    url = f"{GREYNOISE_API}/{path}"
    if not key:
        return None, url, ("no key set. Put AGENTAL_GREYNOISE_KEY in .env and "
                           f"restart. Without it nothing here answers {what}.")

    _throttle("greynoise")
    try:
        resp = requests.get(
            url,
            headers={"key": key, "Accept": "application/json",
                     "User-Agent": USER_AGENT},
            timeout=HTTP_TIMEOUT,
            allow_redirects=False,  # the key must not follow one to another host
        )
    except requests.RequestException as e:
        return None, url, f"{type(e).__name__}"

    if resp.status_code in (401, 403):
        return None, url, ("key refused (HTTP %d). Check AGENTAL_GREYNOISE_KEY, "
                           "and check the plan on the key: some endpoints are "
                           "not included on every tier." % resp.status_code)
    if resp.status_code == 429:
        return None, url, ("rate limited by GreyNoise, the plan's quota may be "
                           "spent. This says nothing about the indicator.")
    if resp.status_code == 404:
        return None, url, None            # a real negative, see the docstring
    if resp.status_code != 200:
        return None, url, f"HTTP {resp.status_code}"
    try:
        body = resp.json() or {}
    except ValueError:
        return None, url, "unreadable JSON"
    return body, url, None


def _tag_names(tags) -> str | None:
    """
    Tag list to one capped string.

    _fields_only drops anything that is not a scalar, so a list of tags would
    vanish silently. Flattened here on purpose rather than left to be dropped,
    because the tags are the most specific thing GreyNoise says: "SSH
    Bruteforcer" is worth more to a reader than classification malicious.
    """
    if not tags:
        return None
    out = []
    for t in tags:
        name = t.get("name") if isinstance(t, dict) else t
        if name:
            out.append(str(name))
    return ", ".join(out[:12]) or None


def src_greynoise_ip(ip: str) -> tuple[dict | None, str, str | None]:
    """
    GreyNoise. Mass scanner, known business service, or neither.

    NOT A REPUTATION SCORE, and this is where it differs from AbuseIPDB in a
    way that is easy to blur. AbuseIPDB aggregates complaints from people.
    GreyNoise reports what its own sensors observed. An address can be busy in
    one and absent from the other without either being wrong, so the two are
    reported side by side and never averaged into a single verdict.

    THE CLASSIFICATION VOCABULARY IS THE TRAP. `benign` does not mean the
    traffic is harmless to you. It means GreyNoise recognises the scanner as a
    known, named, non-hostile one, Shodan and Censys and the like. Something
    can be benign and still be probing a port you did not mean to expose. The
    reading note carries this, see _greynoise_note.
    """
    body, url, err = _greynoise_get(f"v3/ip/{ip}", "whether this is mass scanning")
    if err:
        return None, url, err

    human = f"https://viz.greynoise.io/ip/{ip}"
    if body is None:                       # 404, no record
        return _fields_only({"gn_seen": False}), human, None

    scan = body.get("internet_scanner_intelligence") or {}
    biz  = body.get("business_service_intelligence") or {}
    meta = scan.get("metadata") or {}

    raw = {"gn_seen": bool(scan.get("found"))}

    if scan.get("found"):
        raw.update({
            "gn_classification": scan.get("classification"),
            "gn_actor":          scan.get("actor"),
            "gn_first_seen":     scan.get("first_seen"),
            "gn_last_seen":      scan.get("last_seen_timestamp"),
            "gn_spoofable":      scan.get("spoofable"),
            "gn_bot":            scan.get("bot"),
            "gn_vpn":            scan.get("vpn"),
            "gn_vpn_service":    scan.get("vpn_service"),
            "gn_tor":            scan.get("tor"),
            "gn_tags":           _tag_names(scan.get("tags")),
            "gn_cves":           _tag_names(scan.get("cves")),
            "gn_organization":   meta.get("organization"),
            "gn_asn":            meta.get("asn"),
            "gn_rdns":           meta.get("rdns"),
            "gn_category":       meta.get("category"),
        })

    # The business-service half is reported whether or not the scanner half
    # answered. They are independent lookups that happen to share a response,
    # and an address can be both: a cloud provider that also runs a crawler.
    raw["gn_business_service"] = bool(biz.get("found"))
    if biz.get("found"):
        raw.update({
            "gn_business_name":        biz.get("name"),
            "gn_business_category":    biz.get("category"),
            "gn_business_trust_level": biz.get("trust_level"),
        })

    return _fields_only(raw), human, None


def src_greynoise_cve(cve: str) -> tuple[dict | None, str, str | None]:
    """
    GreyNoise on a CVE. Is anything exploiting this RIGHT NOW.

    WHY THIS IS AN ENRICHER AND NOT A LADDER SOURCE, same reasoning as
    AbuseIPDB one screen up. CIRCL and NVD answer "what is this
    vulnerability", and they corroborate each other on it. GreyNoise answers
    "how many addresses were seen attacking it in the last day", which is not
    a second opinion about the description. Putting it in the ladder would
    mean it gets skipped whenever CIRCL and NVD already agree, which is
    exactly when the runbook row is otherwise complete and this field is the
    only thing left worth knowing.

    THE NUMBER THAT EARNS ITS PLACE is threat_ip_count_1d. A CVSS 10 that
    nothing has touched in a month and a CVSS 7 that four hundred addresses
    hit yesterday are not the same problem, and CVSS alone cannot tell them
    apart. That is the gap this fills in the runbook.
    """
    body, url, err = _greynoise_get(f"v1/cve/{cve}", "live exploitation activity")
    if err:
        return None, url, err

    human = f"https://viz.greynoise.io/cve/{cve}"
    if body is None:
        return None, human, None           # 404, genuinely not in their set

    details = body.get("details") or {}
    if not details:
        # Their own client prints "not found or valid" for this shape. No
        # record is a negative, not a failure.
        return None, human, None

    ex   = body.get("exploitation_details") or {}
    st   = body.get("exploitation_stats") or {}
    act  = body.get("exploitation_activity") or {}

    return _fields_only({
        "gn_exploit_activity_seen": act.get("activity_seen"),
        "gn_threat_ips_1d":         act.get("threat_ip_count_1d"),
        "gn_threat_ips_10d":        act.get("threat_ip_count_10d"),
        "gn_threat_ips_30d":        act.get("threat_ip_count_30d"),
        "gn_benign_ips_1d":         act.get("benign_ip_count_1d"),
        "gn_benign_ips_30d":        act.get("benign_ip_count_30d"),
        "gn_exploit_found":         ex.get("exploit_found"),
        "gn_in_kev":                ex.get("exploitation_registered_in_kev"),
        "gn_epss_score":            ex.get("epss_score"),
        "gn_attack_vector":         ex.get("attack_vector"),
        "gn_available_exploits":    st.get("number_of_available_exploits"),
        "gn_threat_actors":         st.get("number_of_threat_actors_exploiting_vulnerability"),
        "gn_botnets":               st.get("number_of_botnets_exploiting_vulnerability"),
    }), human, None


def _greynoise_note(fields: dict) -> str:
    """
    How to read a GreyNoise answer. Generated at read time, never stored.

    Two misreadings to guard, and they run in opposite directions, which is
    why one sentence cannot cover both.

    ONE, `benign` read as "safe". It means a RECOGNISED scanner, not a
    harmless one. Shodan is benign and Shodan finding your RDP port is still
    something you want to know about.

    TWO, and this is the more dangerous one, "not seen" read as "clean". This
    is the same shape as the AbuseIPDB score problem: a reader skims for the
    reassuring word and stops. GreyNoise sees addresses that scan broadly. An
    attacker who only ever touched this one network is invisible to it BY
    DESIGN. So a quiet answer is evidence about the internet, not about you,
    and on a targeted incident it is the least informative source here.
    """
    fields = fields or {}
    bits = []

    if fields.get("gn_business_service"):
        name = fields.get("gn_business_name") or "a known service"
        bits.append(
            f"KNOWN BUSINESS SERVICE. GreyNoise lists this address as {name}. "
            f"That explains why it turns up in logs and is a good reason not "
            f"to chase it, but it is a statement about who runs the address, "
            f"not a promise about what it did here.")

    if fields.get("gn_seen"):
        cls = (fields.get("gn_classification") or "unknown").lower()
        actor = fields.get("gn_actor")
        who = f" GreyNoise names the actor as {actor}." if actor and actor != "unknown" else ""
        if cls == "benign":
            bits.append(
                "BENIGN HERE MEANS BENIGN SCANNER, not safe. GreyNoise "
                "recognises this as a named, non-hostile scanner such as a "
                "search or research crawler. It is still scanning, and what "
                "it found is still worth knowing. This is not a verdict about "
                "your host." + who)
        elif cls in ("malicious", "suspicious"):
            bits.append(
                f"GreyNoise classes this as {cls} based on its own sensors "
                f"seeing it scan broadly. That is about the address's "
                f"behaviour across the internet, not about what it did to "
                f"this network." + who)
        else:
            bits.append(
                "GreyNoise has seen this address scanning but has not "
                "classified it." + who)
        bits.append(
            "Because it is scanning broadly, traffic from it is most likely "
            "background noise rather than attention aimed at you.")
    else:
        bits.append(
            "NOT SEEN DOES NOT MEAN CLEAN. GreyNoise only sees addresses that "
            "scan the internet broadly enough to hit its sensors. An attacker "
            "who touched only this network would never appear here. So a "
            "quiet answer removes the 'this is just background noise' "
            "explanation, which if anything makes targeted traffic MORE "
            "interesting, not less.")

    if "abuse_confidence_score" in fields:
        bits.append(
            "GreyNoise and AbuseIPDB answer different questions, sensors "
            "observed versus people complained, so they can disagree without "
            "either being wrong. Do not average them.")

    return " ".join(bits)


def _agreement(kind: str, results: list[tuple[str, dict]]) -> tuple[bool | None, str | None]:
    """
    Do two sources actually agree, on the field that matters for this kind.

    Returns (True, None) on agreement, (False, reason) on a real conflict, and
    (None, None) when there is nothing to compare because only one source
    answered. The three-way return is the point: "they disagree" and "only one
    of them spoke" are different situations and the caller grades them
    differently.
    """
    if len(results) < 2:
        return None, None

    if kind in ("ip", "domain"):
        names = [(s, f.get("organisation")) for s, f in results if f.get("organisation")]
        if len(names) < 2:
            return None, None
        first = _org_tokens(names[0][1])
        for source_name, other in names[1:]:
            if first & _org_tokens(other):
                return True, "organisation name"

            # THE ORG NAMES MISSED. TRY THE NETWORK IDENTITY BEFORE CALLING IT
            # A CONFLICT. Added 2026-09-02 off a real run.
            #
            # The two registries describe the same allocation with different
            # vocabulary far more often than they actually disagree. On the
            # address that prompted this, rdap's network_name was EXAMPLENET and
            # ip-api's asn was "AS64500 Example Net AB", which is plainly the
            # same thing, while the organisation strings shared no token at
            # all. Grading that as a conflict is not just noisy, it is wrong.
            #
            # So the second key is the ASN and network name. It is a NARROWER
            # thing to match on than a company name, not a looser one: an ASN
            # number is unique and a network handle is registry-assigned, so
            # this cannot manufacture agreement between two unrelated blocks
            # the way a fuzzy name score would.
            ident = [(s, _identity_tokens(f)) for s, f in results]
            base = ident[0][1]
            if any(base & other_tokens for _, other_tokens in ident[1:] if other_tokens):
                return True, "network name / ASN"

            return False, (f"{names[0][0]} says {names[0][1]!r}, "
                           f"{source_name} says {other!r}")
        return None, None

    if kind == "cve":
        scores = [(s, f.get("cvss_score")) for s, f in results
                  if isinstance(f.get("cvss_score"), (int, float))]
        ids = [f.get("cve_id") for _, f in results if f.get("cve_id")]
        if len(ids) >= 2 and len(set(i.upper() for i in ids)) > 1:
            return False, f"sources returned different CVE ids: {sorted(set(ids))}"
        if len(scores) < 2:
            # Both confirmed the CVE exists, which is agreement on the only
            # thing both were asked. A missing score is a gap, not a conflict.
            return (True, None) if len(ids) >= 2 else (None, None)
        if abs(scores[0][1] - scores[1][1]) <= 0.5:
            return True, None
        return False, (f"{scores[0][0]} scores it {scores[0][1]}, "
                       f"{scores[1][0]} scores it {scores[1][1]}")

    return None, None


# THE LADDER. Sources that answer "what is this", most authoritative first,
# stopping as soon as two of them agree.
SOURCES_BY_KIND = {
    "ip":     [("rdap", src_rdap_ip), ("ip_api", src_ip_api)],
    "domain": [("rdap", src_rdap_domain)],
    "cve":    [("circl", src_circl_cve), ("nvd", src_nvd_cve)],
    "mac":    [("oui", src_oui_mac)],
    # MalwareBazaar is the ONLY hash source, so it is the ladder rather than an
    # enricher. One source means single_source, which is honest: a hash either
    # matches an uploaded sample or it does not, and there is nothing to
    # corroborate it against.
    "hash":   [("malwarebazaar", src_malwarebazaar)],
    # LOLBAS is the only process source and there is nothing to corroborate it
    # against, so a hit grades single_source. That is honest rather than a
    # shortfall: the catalogue either lists the binary or it does not.
    "process": [("lolbas", src_lolbas)],
}

# ALWAYS RUN WHEN THE KEY IS THERE. See the note above ENRICHERS_BY_KIND: these
# answer a different question from the ladder, so the ladder's early stop must
# not skip them.
ENRICHERS_BY_KIND.update({
    "ip":     [("abuseipdb", src_abuseipdb, "abuseipdb"),
               ("urlhaus",   src_urlhaus_host, "abuse_ch"),
               ("greynoise", src_greynoise_ip, "greynoise")],
    "domain": [("urlhaus",   src_urlhaus_host, "abuse_ch")],
    # CVE gets one too. PORTED 2026-09-21. CIRCL and NVD describe the
    # vulnerability and corroborate each other doing it. GreyNoise says how
    # much of the internet is attacking it this week, which no ladder source
    # knows and which is the field that actually sorts a runbook queue.
    "cve":    [("greynoise", src_greynoise_cve, "greynoise")],
})


# THE CATALOGUE. WHICH HOSTS GET CONTACTED, AND WHY EACH ONE.
#
# WHY THIS EXISTS RATHER THAN A PARAGRAPH IN index.html. The dashboard already
# listed source NAMES, in a hardcoded array, which answers "what did you ask"
# and not "who did you talk to". Those are different questions and the second
# one is the one an operator running a security tool on their own network is
# entitled to ask: this module makes outbound requests on their behalf, and
# the screen should name the hosts.
#
# It is derived here rather than written in the page because a list of sources
# kept in the UI is a list that goes stale the first time somebody adds a
# source and does not think about the dashboard. That is not hypothetical in
# this file: the `note` strings in KEYED_SOURCES still said "Off" for two
# sources that had keys, because the prose and the state were kept in
# different places. Same defect, one layer up. The catalogue is keyed by the
# same source ids the ladder and the enrichers use, and `source_catalog()`
# reports a source that has no entry rather than skipping it, so adding a
# source and forgetting to describe it shows up as UNDOCUMENTED on the screen
# instead of as a silent omission.
#
# `host` is the hostname actually contacted, not the vendor's marketing name.
# rdap.org is listed as what it is: a redirector that hands the query to
# whichever RIR is authoritative, which means the query is seen by two parties
# and the screen should say so.
SOURCE_CATALOG = {
    "rdap": {
        "host":    "rdap.org",
        "also":    "redirects to the authoritative registry: ARIN, RIPE, "
                   "APNIC, LACNIC or AFRINIC, depending on who holds the block",
        "answers": "who an address block or a domain is registered to",
        "why":     "the registry is the primary record rather than somebody's "
                   "copy of it, so it is the first rung of the ladder",
        "keyed":   None,
    },
    "ip_api": {
        "host":    "ip-api.com",
        "answers": "ownership and geography again, plus whether the address is "
                   "a proxy, a hosting provider or a mobile carrier",
        "why":     "the ladder grades an answer `resolved` only when two "
                   "independent sources agree, so a second opinion is the "
                   "point of it, not a spare. The proxy and hosting flags are "
                   "also the only place they come from.",
        "keyed":   None,
    },
    "circl": {
        "host":    "vulnerability.circl.lu",
        "answers": "CVE detail",
        "why":     "keyless, fast, and does not rate-limit a home user off the "
                   "service, which is why it is asked before NVD",
        "keyed":   None,
    },
    "nvd": {
        "host":    "services.nvd.nist.gov",
        "answers": "CVE detail",
        "why":     "the authoritative record, and the corroboration for CIRCL. "
                   "Second rung because it is slow without an API key.",
        "keyed":   None,
    },
    "oui": {
        "host":    None,
        "also":    "local file, data/oui.csv, from the IEEE registry",
        "answers": "which vendor owns a MAC prefix",
        "why":     "the one lookup that reaches no network at all. Asking a "
                   "public service which vendor made a device on this LAN "
                   "would leak the question for an answer already on disk.",
        "keyed":   None,
    },
    "lolbas": {
        "host":    "lolbas-project.github.io",
        "answers": "whether a Windows binary has a documented abuse technique",
        "why":     "process names had no structured source before this, so the "
                   "model was left reasoning about them from the name alone. "
                   "Fetched at most monthly and cached at data/lolbas.json, so "
                   "the normal case contacts nothing.",
        "keyed":   None,
    },
    "malwarebazaar": {
        "host":    "mb-api.abuse.ch",
        "answers": "whether a file hash matches a sample somebody has uploaded",
        "why":     "the only hash source here. One source means a hit grades "
                   "`single_source`, which is honest: a hash either matches an "
                   "uploaded sample or it does not, and there is nothing to "
                   "corroborate it against.",
        "keyed":   "abuse_ch",
    },
    "abuseipdb": {
        "host":    "api.abuseipdb.com",
        "answers": "how many people have reported an address, and whether it "
                   "is a known scanner",
        "why":     "reputation is a different question from ownership, so it "
                   "runs alongside the ladder rather than in it. In the ladder "
                   "it would have been skipped exactly when the ownership "
                   "lookup went well, which is most of the time.",
        "keyed":   "abuseipdb",
    },
    "urlhaus": {
        "host":    "urlhaus-api.abuse.ch",
        "answers": "whether a host or address is serving malware",
        "why":     "same reasoning as AbuseIPDB, and a different question "
                   "again: not who owns it and not who complained, but what it "
                   "is currently handing out.",
        "keyed":   "abuse_ch",
    },
    "greynoise": {
        "host":    "api.greynoise.io",
        "answers": "whether an address is mass-scanning the internet rather "
                   "than targeting this host specifically",
        "why":     "would separate background noise from something aimed here, "
                   "which nothing else in the set does.",
        "keyed":   "greynoise",
    },
}


# WHAT IS NEVER SENT. Stated on the screen because an operator cannot verify
# it by watching, and the absence of a request is not something a dashboard
# can show. Kept next to the catalogue so the two are read together.
NEVER_SENT = [
    "Addresses on this network. Private, loopback, link-local, multicast and "
    "reserved addresses are refused before any request is built, because no "
    "public registry knows anything about them and asking leaks the question "
    "for nothing in return.",
    "Packet contents. Only the indicator itself is sent: an address, a domain, "
    "a CVE id, a MAC prefix, a hash or a program name.",
    "Anything at all when the answer is already cached and still inside its "
    "lifetime.",
]


def source_catalog() -> list[dict]:
    """
    Every source this module can contact, what it is asked, and why.

    Built from SOURCES_BY_KIND and ENRICHERS_BY_KIND rather than from a list
    written by hand, so it reports what the code will actually do. A source
    wired up with no catalogue entry comes back marked `documented: False`
    instead of being dropped, because a source contacting the internet without
    a line on the screen explaining it is the exact thing this is for.

    `enabled` is live: a keyed source with no key set is returned OFF, with
    the variable to set, rather than hidden.
    """
    seen: dict[str, dict] = {}

    def note(source_id: str, kind: str, role: str) -> None:
        entry = seen.setdefault(source_id, {
            "source":     source_id,
            "role":       role,
            "kinds":      [],
            "documented": source_id in SOURCE_CATALOG,
        })
        if kind not in entry["kinds"]:
            entry["kinds"].append(kind)
        # A source in both structures is described by the stronger role: the
        # ladder is what grades the answer.
        if role == "ladder":
            entry["role"] = "ladder"

    for kind, sources in SOURCES_BY_KIND.items():
        for source_id, _fn in sources:
            note(source_id, kind, "ladder")
    for kind, enrichers in ENRICHERS_BY_KIND.items():
        for source_id, _fn, _keyed in enrichers:
            note(source_id, kind, "enricher")

    # Sources that are described but not currently wired to anything, which is
    # how an off-by-policy source like GreyNoise stays visible.
    #
    # `wired: False` IS CARRIED, and it is not decoration. Ported from the
    # Windows tree's 2026-09-18 fix, which was written off a real near miss:
    # GreyNoise sat described in the catalogue with a key slot for two weeks
    # while nothing in the file called it, and `enabled` was computed as "a
    # key is present", so the moment a key was pasted in the Sources table
    # would have reported the source ON while no request was ever made to it.
    # The screen would have asserted a capability the code did not have.
    #
    # MEASURED HERE 2026-09-21, on this tree: with AGENTAL_GREYNOISE_KEY set,
    # source_catalog() returned greynoise enabled=True with no src_greynoise_ip
    # in the module at all. So "we do not call this" and "you have not given us
    # a key" are different problems with different fixes, and the row has to
    # be able to say which one it is.
    for source_id, meta in SOURCE_CATALOG.items():
        if source_id in seen:
            continue
        keyed = meta.get("keyed")
        if not keyed:
            continue
        seen[source_id] = {
            "source":     source_id,
            "role":       "enricher",
            "kinds":      list(KEYED_SOURCES.get(keyed, {}).get("kinds", ())),
            "documented": True,
            # Described and given a key slot, with no function behind it.
            # See the note above this loop.
            "wired":      False,
        }

    out = []
    for source_id, entry in seen.items():
        meta  = SOURCE_CATALOG.get(source_id, {})
        keyed = meta.get("keyed")
        # Wired is whether a function exists that the driver will call.
        # has_key is whether the operator supplied a key. enabled is both,
        # never one standing in for the other: they are different problems
        # with different fixes and the row says which it is.
        wired   = entry.get("wired", True)
        has_key = _keyed_available(keyed) if keyed else True
        enabled = bool(wired and has_key)
        out.append({
            **entry,
            "host":       meta.get("host"),
            "also":       meta.get("also"),
            "answers":    meta.get("answers"),
            "why":        meta.get("why"),
            "network":    bool(meta.get("host")),
            "keyed":      keyed,
            "wired":      wired,
            "has_key":    has_key,
            "enabled":    enabled,
            "env_var":    KEYED_SOURCES[keyed]["env"] if keyed else None,
            "why_off":    (None if enabled
                           else ("nothing in core/enrichment.py calls this "
                                 "source, so no request is ever made to it. "
                                 "A key would not turn it on."
                                 if not wired
                                 else KEYED_SOURCES[keyed]["note"]
                                 if keyed else None)),
            "cache_days": {k: round(v / 86400, 2) for k, v in TTL_SECONDS.items()
                           if k in entry["kinds"]},
        })

    # Ladder first, then enrichers, then whatever is off, so the screen reads
    # in the order the code runs.
    order = {"ladder": 0, "enricher": 1}
    out.sort(key=lambda s: (not s["enabled"], order.get(s["role"], 2), s["source"]))
    return out


def _private_address_refusal(indicator: str) -> dict | None:
    """
    A LAN address is not sent to a public registry.

    Same rule as core/ip_lookup.py, and for the same two reasons: no public
    registry knows anything about an address on somebody's LAN, and asking
    leaks the question while returning nothing. Multicast is checked before
    is_global because is_global is TRUE for IPv4 multicast, so 224.0.0.251
    would otherwise sail straight out to a public service.
    """
    try:
        parsed = ipaddress.ip_address(indicator)
    except ValueError:
        return None
    if not (parsed.is_multicast or not parsed.is_global):
        return None
    # Order matters. Python calls loopback and link-local PRIVATE as well, so
    # checking is_private first labels a loopback or a link-local address
    # "private/LAN" and loses the more specific answer. Both kinds turn up in
    # this database with behavioural baselines on them, so the narrower name
    # is the useful one.
    scope = ("multicast" if parsed.is_multicast else
             "loopback" if parsed.is_loopback else
             "link-local" if parsed.is_link_local else
             "private/LAN" if parsed.is_private else "reserved")
    return {
        "status": "unresolved",
        "confidence": "not_applicable",
        "fields": {"scope": scope},
        "sources": [],
        "tried": [],
        "gap": (f"{indicator} is a {scope} address. No public registry knows "
                f"anything about it, so nothing was sent anywhere. Identify it "
                f"with query_known_devices or query_presence."),
    }


def research(indicator: str, kind: str = None) -> dict:
    """
    Run tier 1 for one indicator and return a graded result.

    Never raises and never returns empty. The three statuses are the contract
    with the model, and the `tried` list is what makes `unresolved` usable:
    "nothing found" and "nothing found, having asked RDAP and ip-api, both of
    which timed out" are different things to tell a user.
    """
    indicator = (indicator or "").strip()
    kind = kind or classify(indicator)

    if not indicator or kind not in KINDS:
        return {
            "indicator": indicator,
            "kind": kind,
            "status": "unresolved",
            "confidence": "none",
            "fields": {},
            "sources": [],
            "tried": [],
            "gap": ("Not a recognisable indicator. This takes an IP, a domain, "
                    "a CVE id, a MAC address or a file hash."),
        }

    if kind == "ip":
        refusal = _private_address_refusal(indicator)
        if refusal:
            return dict(refusal, indicator=indicator, kind=kind)

    sources   = SOURCES_BY_KIND.get(kind) or []
    enrichers = [(n, fn) for n, fn, keyed in ENRICHERS_BY_KIND.get(kind, [])
                 if _keyed_available(keyed)]

    if not sources and not enrichers:
        off = [s for s, m in KEYED_SOURCES.items() if kind in m["kinds"]]
        return {
            "indicator": indicator,
            "kind": kind,
            "status": "unresolved",
            "confidence": "none",
            "fields": {},
            "sources": [],
            "tried": [],
            "gap": (f"No source covers {kind} lookups with the keys currently "
                    f"set. "
                    + (f"Turn on {' or '.join(off)} and this becomes answerable."
                       if off else "Use web_search for this one.")),
            "keyed_sources_off": [k for k in keyed_source_status()
                                  if kind in k["kinds"] and not k["enabled"]],
        }

    started = time.time()
    answered, tried, urls, errors, no_record = [], [], [], [], []

    def _run(source_name, fn):
        """Call one source and file its answer. Returns nothing, records everything."""
        if time.time() - started > JOB_WALL_CLOCK:
            errors.append(f"{source_name}: not reached, job time limit")
            return None
        tried.append(source_name)
        try:
            fields, url, err = fn(indicator)
        except Exception as e:                        # a parser bug is not a verdict
            logger.warning(f"[enrichment] {source_name} raised on {indicator}: {e}")
            fields, url, err = None, f"{source_name}", f"parser error ({type(e).__name__})"
        if url:
            urls.append(url)
        if err:
            errors.append(f"{source_name}: {err}")
            return None
        if fields:
            return fields
        no_record.append(source_name)
        return None

    for source_name, fn in sources:
        fields = _run(source_name, fn)
        if fields:
            answered.append((source_name, fields))

        # THE LADDER STOPS ON CONFIDENCE, NOT ON A PAGE COUNT. 35.3.
        # Two sources that agree is the whole answer, so the remaining
        # LADDER sources are not called at all.
        agreed, _ = _agreement(kind, answered)
        if agreed is True:
            break

    # REPUTATION RUNS REGARDLESS. The early stop above is about corroborating
    # an identity, and these are not answering that question, so skipping them
    # because ownership was settled would skip them exactly when the rest of
    # the lookup went well. See the note above ENRICHERS_BY_KIND.
    extra = []
    for source_name, fn in enrichers:
        fields = _run(source_name, fn)
        if fields:
            extra.append((source_name, fields))

    merged = _merge(answered + extra)
    agreed, conflict = _agreement(kind, answered)
    agreed_on = None

    if agreed is True:
        status, confidence, gap = "resolved", "two_sources_agree", None
        # WHAT they agreed on, because it is not always the obvious thing. Two
        # registries matching on the ASN while their organisation strings look
        # nothing alike is a weaker statement than both naming the same
        # company, and a reader deserves to see which one happened.
        agreed_on = conflict
        conflict = None
        # Also into the stored fields, so it survives the round trip without a
        # schema change. fields_json is already free-form per kind.
        if agreed_on:
            merged["_agreed_on"] = agreed_on
    elif agreed is False:
        status, confidence = "partial", "sources_disagree"
        gap = (f"Two sources answered and they do not match: {conflict}. Both "
               f"values are kept above with the source that gave each one. Do "
               f"not present either as settled.")
    elif len(answered) == 1:
        status, confidence = "partial", "single_source"
        only = answered[0][0]
        # SAY WHICH QUESTION IS UNCORROBORATED. 41.7, 2026-09-04.
        #
        # This used to read "Only ip_api answered, so nothing corroborates it"
        # and it got printed on a screen where abuseipdb and urlhaus had both
        # visibly answered, one of them flagging the address as serving
        # malware. Every word was true and it read as "nothing else answered
        # at all", which is the opposite of what happened.
        #
        # The cause is that `answered` is the LADDER only. Corroboration here
        # is about WHO OWNS THIS, and a reputation source is not a second
        # opinion on ownership, which is why it is excluded from the count and
        # should stay excluded. The sentence just never said which question it
        # was about.
        #
        # Same lesson as 41.6, one message over: guarding the field you
        # expected to be misread does not guard the sentence next to it.
        also = [name for name, _ in extra]
        gap = (f"Only {only} answered on WHO OWNS THIS, so that part is "
               f"uncorroborated. "
               + ("The IEEE registry is the only source for a hardware prefix, "
                  "so this is as good as it gets rather than a shortfall."
                  if kind == "mac" else
                  f"Not corroborated: {'; '.join(errors) or 'no second source available'}.")
               + (f" {', '.join(also)} did answer, on reputation and malware, "
                  f"which is a different question and is reported above."
                  if also else ""))
    elif extra:
        # The ladder came back with nothing but a reputation source answered.
        # That is genuinely partial: something is known about this indicator,
        # just not what it IS. Reporting it as unresolved would throw away a
        # malware hit because a registry timed out, which is the wrong way
        # round.
        status, confidence = "partial", "reputation_only"
        gap = (f"No source could say what this {kind} IS. "
               f"{' and '.join(n for n, _ in extra)} did answer about its "
               f"behaviour, and those fields are above. Identity is still "
               f"unknown: {'; '.join(errors) or 'the identity sources had no record'}.")
    elif no_record and not errors:
        status, confidence = "unresolved", "sources_have_no_record"
        gap = (f"{' and '.join(no_record)} answered and have no record of this "
               f"{kind}. That is a real negative result, not a failed lookup.")
        if kind == "process":
            # Worth spelling out, because "unresolved" reads as a shrug and
            # this particular one is a small piece of real information.
            gap += (" For a process name that means it is NOT one of the "
                    "catalogued abusable Windows binaries. It says nothing "
                    "about whether the binary is legitimate, whether it "
                    "belongs on this machine, or what it was doing. LOLBAS "
                    "only covers Windows binaries with a known abuse "
                    "technique.")
    else:
        status, confidence = "unresolved", "none"
        gap = (f"Nothing was learned. Tried {', '.join(tried) or 'nothing'}. "
               f"Failures: {'; '.join(errors) or 'none reported'}. Treat this as "
               f"UNKNOWN, not as 'nothing is there'.")

    # A REPUTATION HIT IS NOT ALLOWED TO RIDE ALONG QUIETLY. If URLhaus or
    # MalwareBazaar had something to say, it belongs in the gap where a reader
    # will see it, whatever the identity lookup did. `resolved` with a malware
    # flag buried in field 14 is exactly how a finding gets missed.
    flagged = [n for n, f in extra if is_flagged(f)]
    if flagged:
        hit = (f"FLAGGED by {' and '.join(flagged)}. This is second-hand and "
               f"about the indicator, not about anything observed here, but do "
               f"not report this row without mentioning it.")
        gap = f"{hit} {gap}" if gap else hit

    return {
        "indicator":  indicator,
        "kind":       kind,
        # Before status on purpose. This dict gets serialised to the model and
        # printed by the check script, and in both places the first thing read
        # should be the dangerous thing rather than the bookkeeping.
        "flagged":    bool(flagged),
        "flagged_by": flagged,
        "flag":       flag_line(merged),
        "status":     status,
        "confidence": confidence,
        "fields":     merged,
        "sources":    [u for u in urls if u],
        "tried":      tried,
        "gap":        gap,
        "agreed_on":  agreed_on,
        "errors":     errors,
        "elapsed_seconds": round(time.time() - started, 2),
    }


# STORAGE

def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.replace(microsecond=0).isoformat()


def _ttl_for(kind: str, status: str, fields: dict = None) -> int:
    if status != "resolved":
        # 35.3's requeue, implemented without a scheduler. An unresolved row
        # goes stale in hours, so the next question about the same indicator
        # asks again instead of reading a shrug back out of the cache.
        return min(UNRESOLVED_TTL_SECONDS, TTL_SECONDS.get(kind, 86400))

    base = TTL_SECONDS.get(kind, 86400)
    # A row carrying reputation expires on the reputation's clock, not the
    # ownership one. The shorter of the two always wins, so this can only ever
    # make a row refresh sooner.
    if fields and any(f in fields for f in REPUTATION_FIELDS):
        return min(base, REPUTATION_TTL_SECONDS)
    return base


def store(result: dict, session_id: str = None) -> dict:
    """Write one graded result. Replaces any earlier row for the same indicator."""
    from core import memory_engine as me

    kind = result.get("kind") or "unknown"
    expires = _now() + timedelta(
        seconds=_ttl_for(kind, result["status"], result.get("fields")))

    with me._get_conn() as conn:
        conn.execute("""
            INSERT INTO enrichment
                (indicator, kind, status, confidence, fields_json, sources_json,
                 tried_json, gap, session_id, fetched_at, expires_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(indicator, kind) DO UPDATE SET
                status=excluded.status,
                confidence=excluded.confidence,
                fields_json=excluded.fields_json,
                sources_json=excluded.sources_json,
                tried_json=excluded.tried_json,
                gap=excluded.gap,
                session_id=excluded.session_id,
                fetched_at=excluded.fetched_at,
                expires_at=excluded.expires_at
        """, (
            result["indicator"], kind, result["status"], result.get("confidence"),
            json.dumps(result.get("fields") or {}),
            json.dumps(result.get("sources") or []),
            json.dumps(result.get("tried") or []),
            result.get("gap"), session_id, _iso(_now()), _iso(expires),
        ))
    return dict(result, expires_at=_iso(expires))


# A MALWARE HIT IS A HEADLINE. TODO 41.7, owner's call 2026-09-04.
#
# THE OWNER'S WORDS: "a malware is a malware, it should raise something."
#
# WHAT WAS WRONG. A live URLhaus hit came back with the headline
# `partial (single_source)`, because `status` describes the OWNERSHIP LADDER
# and rdap had timed out. Every word of that was true, the malware flag was in
# the gap line right under it, and a reader who stops at the status word still
# gets a softer impression than the row deserves.
#
# WHAT I DID NOT DO, and it matters. I did not make a malware hit change
# `status`. status answers "did we work out who this is" and its vocabulary
# (resolved, partial, unresolved) is read by the model, stored in the table
# and used by the ladder. Overloading it to also mean "this is dangerous"
# would give one word two jobs, and the first thing to break would be a
# resolved-and-flagged row, which is a completely ordinary thing to be: we
# know exactly who owns it AND it serves malware.
#
# So the flag is its own field, and it is the first thing printed. Two
# questions, two answers, neither one hiding the other.
#
# ONLY A REAL HIT COUNTS. serves_malware or known_malware, nothing else. An
# AbuseIPDB score is deliberately NOT a flag: the address that prompted this
# scored 4 off a single report, and treating that as a headline is the exact
# misreading _abuse_confidence_note exists to prevent, running the other way.

def is_flagged(fields: dict) -> bool:
    """Did a malware source actually say yes. Not a score, not a suspicion."""
    fields = fields or {}
    return bool(fields.get("serves_malware") or fields.get("known_malware"))


def flag_line(fields: dict) -> str | None:
    """The headline, or None. Written to be read first and quoted as-is."""
    if not is_flagged(fields):
        return None
    what = []
    if fields.get("serves_malware"):
        what.append("distributing malware")
    if fields.get("known_malware"):
        family = fields.get("malware_family")
        what.append(f"a known malware sample ({family})" if family
                    else "a known malware sample")
    return ("MALWARE. A threat intel source lists this indicator as "
            + " and ".join(what)
            + ". This is second-hand and about the indicator, not about "
              "anything observed on this network, and it does not depend on "
              "how well the ownership lookup went.")


def read(indicator: str, kind: str = None) -> dict | None:
    """One stored row, or None. Read through a handle that cannot write."""
    from core import memory_engine as me

    indicator = (indicator or "").strip()
    if not indicator:
        return None
    kind = kind or classify(indicator)

    with me._get_readonly_conn() as conn:
        if kind:
            row = conn.execute(
                "SELECT * FROM enrichment WHERE indicator=? AND kind=?",
                (indicator, kind)).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM enrichment WHERE indicator=? "
                "ORDER BY fetched_at DESC LIMIT 1", (indicator,)).fetchone()
    if not row:
        return None
    return _row_to_dict(dict(row))


def _row_to_dict(row: dict) -> dict:
    stale = False
    try:
        stale = datetime.fromisoformat(row["expires_at"]) < _now()
    except (TypeError, ValueError):
        stale = True
    fields = json.loads(row["fields_json"] or "{}")
    out = {
        "indicator":  row["indicator"],
        "kind":       row["kind"],
        # Derived on read rather than stored, so a row written before this
        # existed still answers correctly and the two paths cannot drift.
        # Same reasoning as the staleness flag two lines down.
        "flagged":    is_flagged(fields),
        "flag":       flag_line(fields),
        "status":     row["status"],
        "confidence": row["confidence"],
        "fields":     fields,
        "sources":    json.loads(row["sources_json"] or "[]"),
        "tried":      json.loads(row["tried_json"] or "[]"),
        "gap":        row["gap"],
        "fetched_at": row["fetched_at"],
        "expires_at": row["expires_at"],
        "stale":      stale,
        "record_type": "external_intel",
    }
    # Generated here, not stored. See _abuse_confidence_note. Only attached
    # when there is actually a score to misread.
    if "abuse_confidence_score" in fields:
        out["how_to_read_the_abuse_score"] = _abuse_confidence_note(
            fields.get("abuse_confidence_score"), fields)
    if fields.get("abusable_windows_binary"):
        out["how_to_read_the_lolbas_listing"] = _lolbas_note(fields)
    # PORTED 2026-09-21 with the GreyNoise block. Only attached when a
    # GreyNoise field is actually present, same rule as the two above: a
    # reading note under a row with no reading is prose about nothing.
    if any(k.startswith("gn_") for k in fields):
        out["how_to_read_the_greynoise_answer"] = _greynoise_note(fields)
    return out


# THE QUEUE

def enqueue(indicator: str, kind: str = None, requested_by: str = "model",
            reason: str = None, session_id: str = None) -> dict:
    """
    Put an indicator on the queue and return immediately.

    Non-blocking on purpose. A model tool that waited eight seconds for RDAP
    would spend the main loop's time on a lookup the loop does not need to
    watch, and MAX_TOOL_ROUNDS is finite. So this returns whatever is already
    cached, plus a note about when to look again.
    """
    from core import memory_engine as me

    indicator = (indicator or "").strip()
    kind = kind or classify(indicator)
    if not indicator or kind not in KINDS:
        return {"queued": False,
                "error": ("Not a recognisable indicator. This takes an IP, a "
                          "domain, a CVE id, a MAC address or a file hash.")}

    cached = read(indicator, kind)
    if cached and not cached["stale"]:
        return {"queued": False, "already_known": True, "result": cached,
                "note": ("Already looked up and still current, nothing was "
                         "queued. Read the result above.")}

    with me._get_conn() as conn:
        depth = conn.execute(
            "SELECT COUNT(*) FROM enrichment_queue WHERE state IN ('queued','running')"
        ).fetchone()[0]
        if depth >= MAX_QUEUE_DEPTH:
            return {"queued": False, "queue_depth": depth,
                    "error": f"Enrichment queue is full ({depth} pending). "
                             f"Nothing was dropped silently; try again later."}

        existing = conn.execute(
            "SELECT id FROM enrichment_queue WHERE indicator=? AND kind=? "
            "AND state IN ('queued','running')", (indicator, kind)).fetchone()
        if existing:
            return {"queued": False, "already_queued": True,
                    "job_id": existing[0], "queue_depth": depth,
                    "note": "This indicator is already in the queue."}

        cur = conn.execute("""
            INSERT INTO enrichment_queue
                (indicator, kind, requested_by, reason, session_id,
                 requested_at, state, attempts)
            VALUES (?,?,?,?,?,?, 'queued', 0)
        """, (indicator, kind, requested_by, reason, session_id, _iso(_now())))
        job_id = cur.lastrowid

    return {
        "queued": True, "job_id": job_id, "indicator": indicator, "kind": kind,
        "queue_depth": depth + 1,
        "stale_result": cached,
        "note": ("Queued. This runs in the background and does not block you. "
                 "Call query_enrichment on the same indicator in a later turn "
                 "to read the answer. It will carry a status of resolved, "
                 "partial or unresolved, it is never empty."),
    }


def _claim_job() -> dict | None:
    from core import memory_engine as me
    with me._get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM enrichment_queue WHERE state='queued' "
            "ORDER BY id LIMIT 1").fetchone()
        if not row:
            return None
        conn.execute(
            "UPDATE enrichment_queue SET state='running', attempts=attempts+1, "
            "started_at=? WHERE id=?", (_iso(_now()), row["id"]))
        return dict(row)


def _finish_job(job_id: int, state: str, note: str = None):
    from core import memory_engine as me
    with me._get_conn() as conn:
        conn.execute(
            "UPDATE enrichment_queue SET state=?, finished_at=?, note=? WHERE id=?",
            (state, _iso(_now()), note, job_id))


def run_one() -> dict | None:
    """
    Take one job off the queue, research it, store the row.

    Split out from the thread so tests and scripts/enrichment_check.py can
    drive a single job without starting anything in the background.
    """
    job = _claim_job()
    if not job:
        return None
    try:
        result = research(job["indicator"], job["kind"])
        stored = store(result, session_id=job.get("session_id"))
        _finish_job(job["id"], "done", note=result["status"])
        logger.info(f"[enrichment] {job['indicator']} -> {result['status']} "
                    f"({result.get('confidence')})")
        return stored
    except Exception as e:
        # A crash still leaves a row, because 35.3 says it never returns
        # empty and a job that vanished is the emptiest possible answer.
        logger.warning(f"[enrichment] job {job['id']} failed: {e}")
        failed = {
            "indicator": job["indicator"], "kind": job["kind"],
            "status": "unresolved", "confidence": "none", "fields": {},
            "sources": [], "tried": [],
            "gap": (f"The lookup itself failed with {type(e).__name__}. This is "
                    f"a fault in this tool, not a statement about the "
                    f"indicator. Treat as UNKNOWN."),
        }
        store(failed, session_id=job.get("session_id"))
        state = "failed" if job["attempts"] >= MAX_ATTEMPTS else "queued"
        _finish_job(job["id"], state, note=f"{type(e).__name__}")
        return failed


# THE WORKER THREAD
#
# One job at a time, by 35.6. A pool would multiply the rate at which this
# hits sources that publish limits in single-digit requests per ten seconds,
# and there is no queue backlog here worth optimising for.

class Enrichment:

    def __init__(self, session_id: str = None, poll_seconds: float = 3.0):
        self.session_id = session_id
        self.poll_seconds = poll_seconds
        self._thread = None
        self._stop = threading.Event()
        self._done = 0

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="enrichment",
                                        daemon=True)
        self._thread.start()
        logger.info("Enrichment worker running (tier 1, keyless sources).")

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            try:
                if run_one() is not None:
                    self._done += 1
                    continue          # drain the queue before sleeping again
            except Exception as e:
                logger.warning(f"[enrichment] worker loop error: {e}")
            self._stop.wait(self.poll_seconds)

    def status(self) -> dict:
        from core import memory_engine as me
        counts, cached = {}, 0
        try:
            with me._get_readonly_conn() as conn:
                for row in conn.execute(
                        "SELECT state, COUNT(*) c FROM enrichment_queue "
                        "GROUP BY state").fetchall():
                    counts[row[0]] = row[1]
                cached = conn.execute("SELECT COUNT(*) FROM enrichment").fetchone()[0]
        except Exception:
            pass
        return {
            "ready":   bool(self._thread and self._thread.is_alive()),
            "tier":    1,
            "queue":   counts,
            "cached":  cached,
            "completed_this_session": self._done,
            "keyed_sources": keyed_source_status(),
        }

    # Thin pass-throughs so tool_registry talks to the module it was handed
    # rather than reaching into this file's globals.
    def enqueue(self, indicator, kind=None, reason=None, requested_by="model"):
        return enqueue(indicator, kind=kind, reason=reason,
                       requested_by=requested_by, session_id=self.session_id)

    def query(self, indicator, kind=None) -> dict:
        row = read(indicator, kind)
        if row:
            return dict(row, found=True)
        return {
            "found": False,
            "indicator": indicator,
            "record_type": "external_intel",
            "note": ("Nothing has been looked up for this indicator yet. "
                     "Call enqueue_enrichment to start one; it runs in the "
                     "background and the answer is here in a later turn. "
                     "Nothing looked up is NOT the same as nothing found, do "
                     "not report this as a clean result."),
        }
