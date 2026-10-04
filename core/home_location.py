# core/home_location.py
# Where this machine is, for the threat map's centre pin (TM-6).
#
# Found at run time, never typed in: the public address placed by the local
# GeoIP file, checked against the system timezone. The timezone needs no
# network, and it wins when the two name different countries (a VPN exit).

import ipaddress
import logging
import os
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

ZONEINFO = Path("/usr/share/zoneinfo")
REFRESH_SECONDS = 15 * 60

# IPv4 answers only, the GeoIP file covers IPv4 (CC-8).
PUBLIC_IP_URLS = (
    "https://api.ipify.org",
    "https://ipv4.icanhazip.com",
    "https://v4.ident.me",
)

_lock = threading.Lock()
_current = None
_at = 0.0
_refreshing = False
_zones = None


def system_timezone() -> str | None:
    """The IANA name of this machine's timezone, e.g. 'Asia/Tokyo'."""
    tz = (os.environ.get("TZ") or "").lstrip(":").strip()
    if tz and (ZONEINFO / tz).is_file():
        return tz
    try:
        name = Path("/etc/timezone").read_text(encoding="utf-8").strip()
        if name:
            return name
    except OSError:
        pass
    try:
        real = Path(os.path.realpath("/etc/localtime"))
        return str(real.relative_to(ZONEINFO.resolve()))
    except (OSError, ValueError):
        return None


def _coord(text: str) -> tuple[float, float] | None:
    """zone.tab's ISO 6709 pair, '+3541+13946' or '+353916+1394441'."""
    cut = max(text.rfind("+"), text.rfind("-"))
    if cut <= 0:
        return None
    out = []
    for part, deg_digits in ((text[:cut], 2), (text[cut:], 3)):
        sign = -1 if part[0] == "-" else 1
        d = part[1:]
        try:
            deg = int(d[:deg_digits])
            mins = int(d[deg_digits:deg_digits + 2] or 0)
            secs = int(d[deg_digits + 2:deg_digits + 4] or 0)
        except ValueError:
            return None
        out.append(sign * (deg + mins / 60 + secs / 3600))
    return out[0], out[1]


def _zone_table() -> tuple[dict, dict]:
    """{zone: (cc, lat, lon)} from zone.tab and {cc: country} from iso3166.tab."""
    global _zones
    if _zones is not None:
        return _zones
    zones, countries = {}, {}
    try:
        for line in (ZONEINFO / "zone.tab").read_text(encoding="utf-8").splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) >= 3:
                c = _coord(parts[1])
                if c:
                    zones[parts[2]] = (parts[0], c[0], c[1])
        for line in (ZONEINFO / "iso3166.tab").read_text(encoding="utf-8").splitlines():
            if line.startswith("#") or "\t" not in line:
                continue
            cc, name = line.split("\t", 1)
            countries[cc] = name.strip()
    except OSError as e:
        logger.debug(f"zone tables unreadable: {e}")
    _zones = (zones, countries)
    return _zones


def timezone_place(tz: str | None = None) -> dict | None:
    """
    The place a timezone is named after, with its country, or None.

    An alias such as 'Japan' is matched to its zone by file content. UTC and
    other zones with no place give None.
    """
    tz = tz or system_timezone()
    if not tz:
        return None
    zones, countries = _zone_table()
    name = tz if tz in zones else None
    if name is None:
        try:
            data = (ZONEINFO / tz).read_bytes()
        except OSError:
            return None
        for z in zones:
            try:
                if (ZONEINFO / z).read_bytes() == data:
                    name = z
                    break
            except OSError:
                continue
    if name is None:
        return None
    cc, lat, lon = zones[name]
    return {
        "lat": round(lat, 4), "lon": round(lon, 4),
        "city": name.rsplit("/", 1)[-1].replace("_", " "),
        "region": "", "country": countries.get(cc, cc),
        "country_code": cc, "zone": name,
    }


def public_ip(timeout: float = 4.0) -> str | None:
    """This network's IPv4 address on the internet, asked of a public echo service."""
    try:
        import requests
    except ImportError:
        return None
    for url in PUBLIC_IP_URLS:
        try:
            r = requests.get(url, timeout=timeout)
            text = r.text.strip() if r.ok else ""
            addr = ipaddress.ip_address(text)
        except Exception:
            continue
        if addr.version == 4 and addr.is_global:
            return str(addr)
    return None


def _manual(config: dict) -> dict | None:
    cfg = (config or {}).get("geoip") or {}
    lat, lon = cfg.get("home_lat"), cfg.get("home_lon")
    if lat is None or lon is None:
        return None
    try:
        lat, lon = float(lat), float(lon)
    except (TypeError, ValueError):
        return None
    return {"lat": lat, "lon": lon,
            "label": cfg.get("home_label") or "Home",
            "source": "settings",
            "detail": "Set by hand in Settings; clear it to locate automatically."}


def locate(config: dict, online: bool = True) -> dict | None:
    """
    Work out where this machine is now. {lat, lon, label, source, detail}.

    None only when neither the public address nor the timezone names a place.
    """
    from core import geoip

    manual = _manual(config)
    if manual:
        return manual

    cfg = (config or {}).get("geoip") or {}
    tz = timezone_place()
    ip_geo, why_not = None, None
    if not online:
        why_not = "the public address has not been read yet"
    elif cfg.get("locate_online", True) is False:
        why_not = "online lookup is off in Settings"
    else:
        ip = public_ip()
        if not ip:
            why_not = "the public address could not be read"
        else:
            ip_geo = geoip.lookup(ip)
            if not ip_geo:
                why_not = "the GeoIP file has no place for the public address"

    def answer(place, source, detail):
        return {"lat": place["lat"], "lon": place["lon"],
                "label": geoip.label(place), "source": source,
                "detail": detail,
                "located_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    if ip_geo and tz and ip_geo["country_code"] != tz["country_code"]:
        return answer(tz, "timezone",
                      f"The public address places this machine in "
                      f"{ip_geo['country'] or ip_geo['country_code']}, the "
                      f"timezone says {tz['country']}. A VPN or proxy is the "
                      f"usual reason, so the timezone is used.")
    if ip_geo:
        return answer(ip_geo, "public address",
                      "Placed from this network's public address"
                      + (", and the timezone agrees." if tz else "."))
    if tz:
        return answer(tz, "timezone",
                      f"Placed from the timezone ({tz['zone']}), because "
                      f"{why_not}.")
    return None


def refresh_async(config: dict):
    """Locate again in the background; one refresh at a time."""
    global _refreshing

    with _lock:
        if _refreshing:
            return
        _refreshing = True

    def work():
        global _current, _at, _refreshing
        try:
            found = locate(config)
            with _lock:
                _current = found
            if found:
                logger.info(f"Location: {found['label']} ({found['source']}).")
            else:
                logger.info("Location: could not be worked out.")
        except Exception as e:
            logger.warning(f"Location lookup failed: {e}")
        finally:
            with _lock:
                _at, _refreshing = time.time(), False

    threading.Thread(target=work, name="home-location", daemon=True).start()


def current(config: dict) -> dict | None:
    """
    The last answer, refreshed in the background every REFRESH_SECONDS, so
    a machine carried to another country moves its pin without a restart.
    """
    manual = _manual(config)
    if manual:
        return manual
    with _lock:
        cur, age = _current, time.time() - _at
    if age > REFRESH_SECONDS:
        refresh_async(config)
    if cur is None:
        cur = locate(config, online=False)
    return cur
