# core/geoip.py
# AgentalSec V2, Offline IP geolocation for the threat map.
#
# Uses DB-IP's IP-to-City Lite database rather than MaxMind GeoLite2.
# Both ship the same MMDB format and both are free, but GeoLite2 now
# requires every user to register an account and generate a licence key
# before they can download anything. For a project people are meant to
# clone and run, that is a real barrier. DB-IP Lite is CC-BY 4.0, needs no
# account, and may be redistributed with attribution.
#
#   Download: https://db-ip.com/db/download/ip-to-city-lite
#   Attribution: "IP geolocation by DB-IP" (https://db-ip.com)
#
# Everything here degrades to None when the database is absent. The map is
# a nice-to-have; nothing in the detection path may depend on it.

import ipaddress
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_reader = None
_status = "not_initialized"
_db_path = None

# Bounded so a long session cannot grow this without limit. Home networks
# talk to a small number of endpoints repeatedly, so the hit rate is high
# and the cap is rarely reached.
_cache: dict = {}
MAX_CACHE = 5000


def init_geoip(config: dict, project_root: Path) -> dict:
    """
    Open the MMDB once at startup. Never raises, a missing database or a
    missing maxminddb package leaves the map empty and logs why.
    """
    global _reader, _status, _db_path

    cfg = config.get("geoip") or {}
    if not cfg.get("enabled", True):
        _status = "disabled in config"
        return status()

    raw = (cfg.get("db_path") or "").strip()
    if not raw:
        _status = "no geoip.db_path set in config.json"
        return status()

    path = Path(raw)
    if not path.is_absolute():
        path = project_root / path
    _db_path = path

    if not path.exists():
        _status = (f"database not found at {path.name}, download the free "
                   f"IP-to-City Lite MMDB from https://db-ip.com/db/download/ip-to-city-lite")
        logger.info(f"GeoIP: {_status}")
        return status()

    try:
        import maxminddb
    except ImportError:
        _status = "maxminddb not installed, run: pip install maxminddb"
        logger.info(f"GeoIP: {_status}")
        return status()

    try:
        _reader = maxminddb.open_database(str(path))
        _status = "ready"
        size_mb = os.path.getsize(path) / (1024 * 1024)
        logger.info(f"GeoIP ready: {path.name} ({size_mb:.0f} MB)")
        note = status().get("note")
        if note:
            logger.warning(f"GeoIP: {note}")
    except Exception as e:
        _reader = None
        _status = f"could not open database: {e}"
        logger.warning(f"GeoIP: {_status}")

    return status()


# A database older than this is reported stale; DB-IP publishes monthly.
STALE_AFTER_DAYS = 60


def status() -> dict:
    out = {
        "ready":   _reader is not None,
        "status":  _status,
        "db_path": str(_db_path) if _db_path else None,
        "cached":  len(_cache),
    }
    # What the file covers and how old it is (CC-4): an IPv4-only database
    # places no IPv6 peer, and an old one places moved ranges wrongly.
    try:
        meta = _reader.metadata() if _reader else None
    except Exception:
        meta = None
    if meta is not None:
        import time
        age = (time.time() - int(meta.build_epoch)) / 86400
        out["built_at"] = time.strftime("%Y-%m-%d", time.gmtime(int(meta.build_epoch)))
        out["age_days"] = round(age)
        out["stale"] = age > STALE_AFTER_DAYS
        out["ip_version"] = int(meta.ip_version)
        notes = []
        if meta.ip_version == 4:
            notes.append("This database covers IPv4 only, so IPv6 addresses "
                         "get no location and are left off the map.")
        if out["stale"]:
            notes.append(f"It was built {round(age)} days ago; DB-IP "
                         f"publishes a new one monthly.")
        if notes:
            out["note"] = " ".join(notes)
    return out


def is_routable(ip: str) -> bool:
    """
    Can this address plausibly appear on the public internet?

    Filters private, loopback, link-local, multicast and reserved space,
    everything the threat map should treat as local rather than remote.
    169.254.x is included here, which is why the APIPA SSDP source never
    shows up as a foreign endpoint.

    MULTICAST IS NOT A HOST, 2026-09-23. `is_multicast` was already in this
    list, so 224.0.0.1, 239.255.255.250 and 224.0.0.251 never became map
    endpoints by this door. They got in through the other one: every one of
    those addresses is written as a packet row with a real captured_at, so
    they appear in the endpoint pairs, and the threat map then reported them
    in `home.ips` -- the list it documents as "the addresses of the local
    network", rendered as a device on the local pin's popup. Measured live:
    `home.ips == ['192.0.2.207', '224.0.0.1']` on this host. See
    is_host_address() below, which is the test the map needed.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def is_host_address(ip: str) -> bool:
    """
    Could a HOST have this address, as opposed to a group or a placeholder?

    False for multicast (224.0.0.0/4, ff00::/8) and the unspecified address,
    which are the two things that reach `local_ips` on a real capture and are
    not devices. Measured on this host: 224.0.0.1 (all-hosts multicast) and
    239.255.255.250 (SSDP) are both written as packet sources, so both were
    eligible for the local-endpoint list.

    Deliberately NOT the same question as is_routable(). Loopback is a real
    address on a real host and belongs in this answer; it is only excluded
    from the MAP because nothing on lo can be geolocated. Two questions, two
    functions, each named for what it answers.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_multicast or addr.is_unspecified)


def lookup(ip: str) -> dict | None:
    """
    Resolve one IP to {lat, lon, city, region, country, country_code}.
    Returns None for private addresses, unknown IPs, or a missing database.
    """
    if not _reader or not is_routable(ip):
        return None

    if ip in _cache:
        return _cache[ip]

    try:
        rec = _reader.get(ip)
    except Exception:
        rec = None

    result = _parse(rec) if rec else None

    if len(_cache) < MAX_CACHE:
        _cache[ip] = result
    return result


def _parse(rec: dict) -> dict | None:
    """
    Normalise a record from either MMDB schema in circulation.

    NESTED (MaxMind GeoIP2-City, and DB-IP's own download):
        {"city": {"names": {"en": "Frankfurt"}},
         "country": {"iso_code": "DE", "names": {"en": "Germany"}},
         "subdivisions": [{"names": {"en": "Hesse"}}],
         "location": {"latitude": 50.11, "longitude": 8.68}}

    FLAT (the ip-location-db repackaging on npm/jsDelivr):
        {"city": "Frankfurt", "country_code": "DE", "state1": "Hesse",
         "latitude": 50.11, "longitude": 8.68}

    Supporting both matters because the two download routes give different
    files: db-ip.com serves the nested one, the no-account CDN mirror serves
    the flat one. Parsing only the nested shape against a flat file returns
    a record for every IP and coordinates for none, an empty map with no
    error anywhere.
    """
    if "location" in rec or isinstance(rec.get("country"), dict):
        loc = rec.get("location") or {}
        lat, lon = loc.get("latitude"), loc.get("longitude")
        country  = rec.get("country") or {}
        subs     = rec.get("subdivisions") or []
        city     = _name(rec.get("city"))
        region   = _name(subs[0]) if subs else ""
        cc       = country.get("iso_code", "")
        cname    = _name(country)
    else:
        lat, lon = rec.get("latitude"), rec.get("longitude")
        city     = rec.get("city") or ""
        region   = rec.get("state1") or rec.get("state2") or ""
        cc       = rec.get("country_code") or ""
        # The flat schema carries no country name, only the ISO code.
        cname    = ""

    if lat is None or lon is None:
        return None

    return {
        "lat":          float(lat),
        "lon":          float(lon),
        "city":         city,
        "region":       region,
        "country":      cname or cc,
        "country_code": cc,
    }


def _name(node) -> str:
    """MMDB stores names per-language; take English and fall back to any."""
    if isinstance(node, str):
        return node
    if not node:
        return ""
    names = node.get("names") or {}
    return names.get("en") or next(iter(names.values()), "")


def label(geo: dict | None) -> str:
    """Human-readable place string for a marker popup."""
    if not geo:
        return "Unknown location"
    parts = [p for p in (geo.get("city"), geo.get("region"), geo.get("country")) if p]
    # City and region are frequently identical for city-states and small
    # territories; dedupe so popups do not read "Singapore, Singapore".
    seen, out = set(), []
    for p in parts:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return ", ".join(out) or "Unknown location"
