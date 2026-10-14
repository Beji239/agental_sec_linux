"""
core/ip_lookup.py
AgentalSec V2, who owns an address, asked directly.

WHY THIS EXISTS, 2026-08-30
A web search is the wrong instrument for a question that has a registry
answer. web_search stays for open questions (what is this CVE, what does this
mDNS service type mean); address ownership comes here, as fields.

WHERE THE ANSWER COMES FROM, since 2026-10-13
Nothing is asked over plain HTTP; a lookup that anyone on the path could
read or change has no place in a security tool. ip-api.com was dropped for
that reason (its free tier is HTTP only).

  * RDAP over HTTPS: who the address is registered to, its network.
  * DB-IP Lite, files on this computer: the AS number and name, the country
    and city. Nothing is sent anywhere.
  * Reverse DNS, through the DNS server this computer already uses.
  * AbuseIPDB over HTTPS, when its key is set: the usage type, which says
    hosting or datacentre, and mobile network.
  * ipapi.is over HTTPS, when its key is set: VPN, proxy, Tor, datacentre
    and mobile. Without a key VPN and proxy are not checked, and said so.

WHAT THIS IS AND IS NOT
Registration data, not a verdict. The city is the registry's claim and is
often wrong for anycast, VPN and cloud addresses; the ASN is the most
reliable field. Datacentre and VPN describe WHAT an address is, never
whether it is a problem: most of the legitimate internet is hosted.

Every field from outside is third-party text and is fenced like every other
attacker-influenceable source. Results are cached in memory for the life of
the process.
"""

import ipaddress
import logging
import socket
import threading

logger = logging.getLogger(__name__)

REVERSE_DNS_SECONDS = 3


def _reverse_dns(ip: str):
    """The name for an address from this computer's own resolver, or None.
    Bounded, because gethostbyaddr has no timeout of its own."""
    out = {}

    def ask():
        try:
            out["name"] = socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError):
            out["name"] = None

    t = threading.Thread(target=ask, daemon=True)
    t.start()
    t.join(REVERSE_DNS_SECONDS)
    return out.get("name")


def _usage_flags(usage_type):
    """AbuseIPDB's usage type as the two flags it can answer."""
    if not usage_type:
        return None, None
    u = usage_type.lower()
    return ("data center" in u or "hosting" in u), ("mobile" in u)


class IPLookup:

    def __init__(self):
        self._cache = {}

    def start(self):
        logger.info("IPLookup ready.")

    def status(self) -> dict:
        return {"ready": True, "cached": len(self._cache)}

    def lookup(self, ip: str) -> dict:
        """
        Registration data for one public address.

        Private and reserved addresses are refused here rather than sent to a
        public registry: nobody outside this network knows anything about
        192.0.2.171, and asking would leak the question while returning
        nothing. query_known_devices is where a local address is identified.
        """
        ip = (ip or "").strip()
        if not ip:
            return {"error": "No address given."}

        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return {"error": f"{ip!r} is not an IP address."}

        # is_global is TRUE for multicast on IPv4, so multicast is checked
        # first, or every mDNS and SSDP group would be sent to a registry.
        if parsed.is_multicast or not parsed.is_global:
            kind = ("multicast" if parsed.is_multicast else
                    "private/LAN" if parsed.is_private else
                    "loopback" if parsed.is_loopback else
                    "link-local" if parsed.is_link_local else
                    "reserved")
            return {
                "ip": ip,
                "looked_up": False,
                "scope": kind,
                "note": (f"{ip} is a {kind} address. No public registry knows "
                         f"anything about it, so this was not sent anywhere. "
                         f"Use query_known_devices, query_router_clients or "
                         f"the device inventory to identify it."),
            }
        ip = str(parsed)

        if ip in self._cache:
            out = dict(self._cache[ip])
            out["cached"] = True
            return out

        from core import enrichment, geoip

        sources, errors = [], []
        rdap, _url, err = enrichment.src_rdap_ip(ip)
        if rdap:
            sources.append("RDAP")
        elif err:
            errors.append(f"RDAP: {err}")
        rdap = rdap or {}

        asn = geoip.asn_lookup(ip) or {}
        geo = geoip.lookup(ip) or {}
        if asn or geo:
            sources.append("DB-IP on this computer")

        abuse = {}
        if enrichment._keyed_available("abuseipdb"):
            got, _url, err = enrichment.src_abuseipdb(ip)
            if got:
                abuse = got
                sources.append("AbuseIPDB")
            elif err:
                errors.append(f"AbuseIPDB: {err}")

        kind = {}
        if enrichment._keyed_available("ipapi_is"):
            got, _url, err = enrichment.src_ipapi_is(ip)
            if got:
                kind = got
                sources.append("ipapi.is")
            elif err:
                errors.append(f"ipapi.is: {err}")

        if not sources:
            # An unreachable registry must not look like a negative result,
            # or the model answers from recall and presents it as checked.
            return {"ip": ip, "looked_up": False,
                    "error": ("No source answered ("
                              + ("; ".join(errors) or "the offline database "
                                 "is not loaded") + "). Treat this as "
                              "UNKNOWN, not as 'nothing found'.")}

        datacentre, mobile = _usage_flags(abuse.get("abuse_usage_type"))
        if kind.get("is_datacentre") is not None:
            datacentre = kind["is_datacentre"]
        if kind.get("is_mobile_network") is not None:
            mobile = kind["is_mobile_network"]
        vpn = None
        if kind.get("is_vpn") is not None or kind.get("is_proxy") is not None:
            vpn = bool(kind.get("is_vpn") or kind.get("is_proxy"))
        out = {
            "ip":            ip,
            "looked_up":     True,
            "sources":       sources,
            "organisation":  rdap.get("organisation") or asn.get("org") or None,
            "network_name":  rdap.get("network_name"),
            "network":       (f"{rdap['cidr_start']} to {rdap['cidr_end']}"
                              if rdap.get("cidr_start") and rdap.get("cidr_end")
                              else None),
            "isp":           abuse.get("abuse_isp"),
            "asn":           asn.get("asn"),
            "asn_name":      asn.get("org") or None,
            "reverse_dns":   _reverse_dns(ip),
            "registered_country": rdap.get("registry_country") or geo.get("country")
                                  or None,
            "registered_city":    geo.get("city") or None,
            "usage_type":         abuse.get("abuse_usage_type"),
            "is_datacentre":      datacentre,
            "is_mobile_network":  mobile,
            "is_proxy_or_vpn":    vpn,
            "is_tor":             kind.get("is_tor"),
            "not_checked": [k for k, v in (("is_proxy_or_vpn", vpn),
                                           ("is_datacentre", datacentre),
                                           ("is_mobile_network", mobile))
                            if v is None],
            "how_to_read_this": (
                "Registration data, not a verdict. The ASN and organisation "
                "are reliable; the city is a database's claim and is often "
                "wrong for anycast, VPN and cloud addresses. is_datacentre "
                "describes WHAT the address is, never whether it is a "
                "problem. A field listed in not_checked was not asked, so it "
                "is unknown, not false."
            ),
        }
        if errors:
            out["partial"] = "; ".join(errors)
        self._cache[ip] = out
        return dict(out, cached=False)
