"""
core/ip_lookup.py
AgentalSec V2, who owns an address, asked directly.

WHY THIS EXISTS, 2026-08-30
The model spent six tool rounds trying to establish what 77.111.246.27 was.
web_search was returning 202s, so it correctly refused to answer from recall
and said so. Meanwhile one 176-byte request answered the whole question:

    {"status":"success","country":"United States","city":"Washington",
     "isp":"Opera Browser VPN","org":"Example Software LLC",
     "as":"AS64500 Example Net AB","proxy":true,"hosting":true}

"Opera Browser VPN". "proxy": true. That was the answer, as fields, from a
registry, not a paragraph on a search page that has to be read and believed.

A search engine is the wrong instrument for a question that has a registry
answer. web_search stays for open questions (what is this CVE, what does this
mDNS service type mean); address ownership comes here.

WHAT THIS IS AND IS NOT
It is registration data: which organisation holds the address, which
autonomous system announces it, roughly where that org says it is.

It is NOT a verdict, and two limits decide how far it can be trusted:

  * GEOLOCATION IS A CLAIM, NOT A MEASUREMENT. "Washington" here means the
    registry says so. Anycast, VPN exits and cloud regions routinely place an
    address thousands of miles from where a database puts it. The city is the
    least reliable field on the response; the ASN is the most.

  * proxy/hosting ARE NOT threat flags. proxy:true on 77.111.246.27 is
    correct AND completely benign, it is the operator's own Opera VPN. A
    datacentre address is where every legitimate service on the internet also
    lives. These fields narrow what a thing is. They never decide whether it
    is a problem.

The response is third-party text, so it is fenced like every other
attacker-influenceable source. Nobody is attacking through an ASN name today,
but an org field is a string somebody else controls, and this codebase does
not make exceptions for sources that seem respectable.

NO KEY, AND A RATE LIMIT
ip-api.com allows roughly 45 requests a minute from one address on the free
tier, over plain HTTP. Results are cached in memory for the life of the
process, because the model asks about the same handful of addresses
repeatedly and registration data does not change between two questions.
"""

import ipaddress
import logging

import requests

logger = logging.getLogger(__name__)

API_URL = "http://ip-api.com/json/"
FIELDS = ("status,message,country,regionName,city,isp,org,as,asname,"
          "reverse,proxy,hosting,mobile")
TIMEOUT = 6


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

        # is_global is TRUE for multicast on IPv4, 224.0.0.251 and
        # 239.255.255.250 both pass it. Caught by a test on 2026-08-30, before
        # this shipped. Multicast is checked first, or every mDNS and SSDP
        # group on the network gets sent to a public registry that has nothing
        # to say about it.
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

        if ip in self._cache:
            out = dict(self._cache[ip])
            out["cached"] = True
            return out

        try:
            resp = requests.get(f"{API_URL}{ip}", params={"fields": FIELDS},
                                timeout=TIMEOUT)
            if resp.status_code == 429:
                return {"ip": ip, "looked_up": False,
                        "error": "Rate limited by ip-api.com. Treat as "
                                 "UNKNOWN, not as 'nothing found'."}
            if resp.status_code != 200:
                return {"ip": ip, "looked_up": False,
                        "error": f"HTTP {resp.status_code}. Treat as UNKNOWN, "
                                 f"not as 'nothing found'."}
            data = resp.json()
        except requests.RequestException as e:
            # Same rule as web_search: an unreachable network must not look
            # like a negative result, or the model answers from recall and
            # presents it as checked.
            return {"ip": ip, "looked_up": False,
                    "error": f"Lookup did not complete ({type(e).__name__}). "
                             f"Treat this as UNKNOWN, not as 'nothing found'."}
        except ValueError:
            return {"ip": ip, "looked_up": False,
                    "error": "Registry returned unreadable JSON. Treat as "
                             "UNKNOWN."}

        if data.get("status") != "success":
            return {"ip": ip, "looked_up": False,
                    "error": f"Registry has no record: "
                             f"{data.get('message', 'unknown reason')}"}

        out = {
            "ip":            ip,
            "looked_up":     True,
            "organisation":  data.get("org") or data.get("isp"),
            "isp":           data.get("isp"),
            "asn":           data.get("as"),
            "asn_name":      data.get("asname"),
            "reverse_dns":   data.get("reverse") or None,
            "registered_country": data.get("country"),
            "registered_city":    data.get("city"),
            "is_proxy_or_vpn":    bool(data.get("proxy")),
            "is_datacentre":      bool(data.get("hosting")),
            "is_mobile_network":  bool(data.get("mobile")),
            "how_to_read_this": (
                "Registration data, not a verdict. The ASN and organisation "
                "are reliable; the city is the registry's claim and is often "
                "wrong for anycast, VPN and cloud addresses. "
                "is_proxy_or_vpn and is_datacentre describe WHAT the address "
                "is, never whether it is a problem, the operator's own VPN "
                "exit sets both, and so does most of the legitimate internet."
            ),
        }
        self._cache[ip] = out
        return dict(out, cached=False)
