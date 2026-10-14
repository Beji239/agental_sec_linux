"""
tests/test_ip_lookup.py, who owns an address, with nothing asked over plain
HTTP.

The sources are stood in for: RDAP, the offline DB-IP files, AbuseIPDB and
reverse DNS. Each answer lands in its field, a field nobody was asked says
"not checked" rather than false, a lookup nobody answered says unknown, LAN
addresses are never sent, and no request anywhere in the IP lookup or the
enrichment ladder goes out over http://.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
_isolate_db.isolate()

import requests  # noqa: E402

from core import enrichment, geoip, ip_lookup  # noqa: E402

fails = []
SENT = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}")
    if not ok:
        fails.append(label)
        print(f"        want {want!r}")


def no_network(*a, **k):
    SENT.append(a[0] if a else k.get("url"))
    raise requests.ConnectionError("no network in this test")


requests.get = requests.post = no_network
requests.Session.request = lambda self, method, url, **k: no_network(url)

RDAP = {"organisation": "Example Org", "network_name": "EXAMPLE-NET",
        "cidr_start": "203.0.113.0", "cidr_end": "203.0.113.255",
        "registry_country": "SE"}
state = {"rdap": RDAP, "asn": {"asn": "AS64500", "org": "Example Net AB"},
         "geo": {"country": "Sweden", "city": "Example City"},
         "abuse": {"abuse_usage_type": "Data Center/Web Hosting/Transit",
                   "abuse_isp": "Example Hosting"}, "key": True}
enrichment.src_rdap_ip = lambda ip: (state["rdap"], "https://rdap.org/ip/" + ip,
                                     None if state["rdap"] else "Timeout")
enrichment.src_abuseipdb = lambda ip: (state["abuse"], "https://api.abuseipdb.com",
                                       None)
state["vpn"] = None
enrichment._keyed_available = lambda name: (state["key"] if name == "abuseipdb"
                                            else state["vpn"] is not None)
enrichment.src_ipapi_is = lambda ip: (state["vpn"], "https://api.ipapi.is", None)
geoip.asn_lookup = lambda ip: state["asn"]
geoip.lookup = lambda ip: state["geo"]
ip_lookup._reverse_dns = lambda ip: "host.example"


def fresh():
    return ip_lookup.IPLookup()


print("Every source answers")
r = fresh().lookup("8.8.8.8")
check("looked up", r["looked_up"], True)
check("who answered", r["sources"], ["RDAP", "DB-IP on this computer", "AbuseIPDB"])
check("the owner from RDAP", r["organisation"], "Example Org")
check("the network range", r["network"], "203.0.113.0 to 203.0.113.255")
check("the ASN from the offline file", (r["asn"], r["asn_name"]),
      ("AS64500", "Example Net AB"))
check("the city from the offline file", r["registered_city"], "Example City")
check("reverse DNS", r["reverse_dns"], "host.example")
check("a datacentre from the AbuseIPDB usage type", r["is_datacentre"], True)
check("not a mobile network", r["is_mobile_network"], False)
check("VPN or proxy is unknown, not false", (r["is_proxy_or_vpn"],
                                             r["not_checked"]),
      (None, ["is_proxy_or_vpn"]))

print("\nNo AbuseIPDB key")
state["key"] = False
r = fresh().lookup("8.8.8.8")
check("the flags it would give are not checked",
      (r["is_datacentre"], r["is_mobile_network"], r["not_checked"]),
      (None, None, ["is_proxy_or_vpn", "is_datacentre", "is_mobile_network"]))
state["key"] = True
state["abuse"] = {"abuse_usage_type": "Mobile ISP"}
check("a mobile network", fresh().lookup("8.8.8.8")["is_mobile_network"], True)

print("\nWith the ipapi.is key")
state["vpn"] = {"is_vpn": True, "is_proxy": False, "is_tor": False,
                "is_datacentre": True, "is_mobile_network": False}
r = fresh().lookup("8.8.8.8")
check("ipapi.is is named", r["sources"][-1], "ipapi.is")
check("a VPN exit says so", (r["is_proxy_or_vpn"], r["is_tor"]), (True, False))
check("nothing is left unchecked", r["not_checked"], [])
state["vpn"] = {"is_vpn": False, "is_proxy": False}
check("not a VPN is false, not unknown",
      fresh().lookup("8.8.8.8")["is_proxy_or_vpn"], False)
state["vpn"] = None

print("\nWhen sources fail")
state["rdap"] = None
r = fresh().lookup("8.8.8.8")
check("RDAP down, the offline file still answers", r["looked_up"], True)
check("and the gap is said", "RDAP" in r.get("partial", ""), True)
state.update(asn={}, geo={}, key=False)
r = fresh().lookup("8.8.8.8")
check("nobody answered: unknown, not nothing found",
      (r["looked_up"], "UNKNOWN" in r["error"]), (False, True))

print("\nAddresses that are never sent")
for ip in ("192.0.2.5", "224.0.0.251", "127.0.0.1", "fe80::1"):
    check(f"{ip} is not looked up", fresh().lookup(ip)["looked_up"], False)
check("garbage is refused", "error" in fresh().lookup("1.2.3.4; id"), True)

print("\nNothing over plain HTTP")
check("the IP ladder holds no ip-api",
      [s for s, _ in enrichment.SOURCES_BY_KIND["ip"]], ["rdap", "dbip"])
check("the offline source names no host", enrichment.SOURCE_CATALOG["dbip"]
      ["host"], None)
src = (ROOT / "core" / "ip_lookup.py").read_text() + \
    (ROOT / "core" / "enrichment.py").read_text()
check("no http:// address in either file",
      [line.strip() for line in src.splitlines()
       if "http://" in line and not line.strip().startswith("#")], [])
check("nothing was sent during this test", SENT, [])

print("\nThe ipapi.is reader itself")
import importlib  # noqa: E402
import os  # noqa: E402
real = importlib.reload(enrichment)
real._throttle = lambda name: None
os.environ["AGENTAL_IPAPI_KEY"] = "test-key-123"
asked = {}


class Answer:
    def __init__(self, code, body):
        self.status_code, self._body = code, body

    def json(self):
        return self._body


def post(url, json=None, **k):
    asked.update(url=url, body=json, redirects=k.get("allow_redirects"))
    return asked["answer"]


real.requests.post = post
asked["answer"] = Answer(200, {"is_vpn": True, "is_proxy": False,
                               "is_tor": False, "is_datacenter": True,
                               "is_mobile": False, "is_abuser": False})
got, url, err = real.src_ipapi_is("8.8.8.8")
check("the flags are read", (got["is_vpn"], got["is_datacentre"], err),
      (True, True, None))
check("over HTTPS", asked["url"].startswith("https://"), True)
check("the key is in the body, not the address",
      ("test-key-123" in asked["url"], asked["body"]["key"]),
      (False, "test-key-123"))
check("no redirect is followed with the key", asked["redirects"], False)
for code, word in ((401, "refused"), (429, "rate limited")):
    asked["answer"] = Answer(code, {})
    got, url, err = real.src_ipapi_is("8.8.8.8")
    check(f"HTTP {code} is an error, not a clean answer",
          (got, word in (err or "")), (None, True))
os.environ.pop("AGENTAL_IPAPI_KEY")
check("without a key nothing is sent", real.src_ipapi_is("8.8.8.8")[0], None)

print(f"\n{'ALL PASSED' if not fails else str(len(fails)) + ' FAILED'}")
sys.exit(1 if fails else 0)
