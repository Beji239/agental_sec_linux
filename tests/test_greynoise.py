"""
tests/test_greynoise.py, the GreyNoise enrichers.

FAILURE CASES FIRST, on purpose. The whole risk with a keyed source is a
function that answers confidently when it could not actually look. GreyNoise
makes that easy to get wrong because "we have never seen this address" is a
normal, useful answer AND is the exact shape a refused key produces if you are
careless. So every could-not-look path gets a test before the happy path does.

The second half is about reading. GreyNoise says "benign" about a lot of
addresses and it does NOT mean what a tired person at 1am reads it as.
"""

import io
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"          got  {got!r}")
        print(f"          want {want!r}")
        fails.append(label)


def check_in(label, needle, haystack):
    ok = needle.lower() in (haystack or "").lower()
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"          {needle!r} not in {haystack!r}")
        fails.append(label)


os.environ.setdefault("AGENTAL_GREYNOISE_KEY", "test-key-not-real")

from core import enrichment as e  # noqa: E402


class FakeResp:
    def __init__(self, status, payload=None, bad_json=False):
        self.status_code = status
        self._payload = payload
        self._bad = bad_json

    def json(self):
        if self._bad:
            raise ValueError("not json")
        return self._payload


def with_response(monkey_resp, fn, arg):
    """Run one enricher with requests.get stubbed. Returns its 3-tuple."""
    real = e.requests.get
    e.requests.get = lambda *a, **k: monkey_resp
    try:
        return fn(arg)
    finally:
        e.requests.get = real


def with_raise(exc, fn, arg):
    real = e.requests.get

    def boom(*a, **k):
        raise exc

    e.requests.get = boom
    try:
        return fn(arg)
    finally:
        e.requests.get = real


print("\n[1] could not look, each failure says which failure it was")

fields, url, err = with_response(FakeResp(401), e.src_greynoise_ip, "45.33.32.156")
check("401 returns no fields", fields, None)
check_in("401 names the key", "key", err)
check("401 is an error, not a negative result", err is not None, True)

fields, url, err = with_response(FakeResp(403), e.src_greynoise_ip, "45.33.32.156")
check_in("403 names the key too", "key", err)

fields, url, err = with_response(FakeResp(429), e.src_greynoise_ip, "45.33.32.156")
check_in("429 says rate limited", "rate limit", err)
check("429 returns no fields", fields, None)

fields, url, err = with_response(FakeResp(500), e.src_greynoise_ip, "45.33.32.156")
check_in("500 reports the status", "500", err)

fields, url, err = with_raise(e.requests.RequestException("boom"),
                              e.src_greynoise_ip, "45.33.32.156")
check("a network error returns no fields", fields, None)
check("a network error is an error", err is not None, True)

fields, url, err = with_response(FakeResp(200, bad_json=True),
                                 e.src_greynoise_ip, "45.33.32.156")
check_in("unreadable body says so", "json", err)

# The one that matters most. No key must never look like "not seen".
real_env = os.environ.pop("AGENTAL_GREYNOISE_KEY", None)
fields, url, err = e.src_greynoise_ip("45.33.32.156")
check("no key returns no fields", fields, None)
check("no key is an error, not a negative", err is not None, True)
check_in("no key names the variable", "AGENTAL_GREYNOISE_KEY", err)
if real_env is not None:
    os.environ["AGENTAL_GREYNOISE_KEY"] = real_env


print("\n[2] a real negative is not an error")

not_seen = {"ip": "45.33.32.156",
            "business_service_intelligence": {"found": False},
            "internet_scanner_intelligence": {"found": False}}
fields, url, err = with_response(FakeResp(200, not_seen),
                                 e.src_greynoise_ip, "45.33.32.156")
check("not seen reports no error", err, None)
check("not seen still returns a field", bool(fields), True)
check("and that field says not seen", fields.get("gn_seen"), False)

# This is the distinction the whole file exists for.
_, _, err_refused = with_response(FakeResp(401), e.src_greynoise_ip, "1.2.3.4")
_, _, err_negative = with_response(FakeResp(200, not_seen),
                                   e.src_greynoise_ip, "1.2.3.4")
check("could not look and found nothing are different sentences",
      err_refused == err_negative, False)


print("\n[3] a scanner answer comes back with the fields that matter")

scanner = {
    "ip": "45.33.32.156",
    "business_service_intelligence": {"found": False},
    "internet_scanner_intelligence": {
        "found": True,
        "classification": "malicious",
        "actor": "unknown",
        "last_seen_timestamp": "2026-09-17T04:00:00Z",
        "first_seen": "2026-01-02",
        "spoofable": False, "bot": False, "vpn": False, "tor": False,
        "tags": [{"name": "SSH Bruteforcer"}, {"name": "Telnet Scanner"}],
        "cves": ["CVE-2021-44228"],
        "metadata": {"asn": "AS63949", "organization": "Akamai",
                     "rdns": "scan.example.net", "category": "hosting"},
    },
}
fields, url, err = with_response(FakeResp(200, scanner),
                                 e.src_greynoise_ip, "45.33.32.156")
check("no error", err, None)
check("seen", fields.get("gn_seen"), True)
check("classification carried", fields.get("gn_classification"), "malicious")
check("organisation carried", fields.get("gn_organization"), "Akamai")
check_in("tags flattened to a string", "SSH Bruteforcer", fields.get("gn_tags"))
check_in("cves flattened too", "CVE-2021-44228", fields.get("gn_cves"))
check("every field is a scalar",
      all(isinstance(v, (str, int, float, bool)) or v is None
          for v in fields.values()), True)


print("\n[4] business service intelligence, the RIOT half")

riot = {
    "ip": "8.8.8.8",
    "business_service_intelligence": {
        "found": True, "name": "Google Public DNS", "category": "public_dns",
        "trust_level": "1", "description": "ignore me"},
    "internet_scanner_intelligence": {"found": False},
}
fields, url, err = with_response(FakeResp(200, riot), e.src_greynoise_ip, "8.8.8.8")
check("no error", err, None)
check("flagged as a known business service",
      fields.get("gn_business_service"), True)
check("named", fields.get("gn_business_name"), "Google Public DNS")
check("trust level carried", fields.get("gn_business_trust_level"), "1")


print("\n[5] the reading note guards the two real misreadings")

benign = {
    "ip": "1.1.1.1",
    "business_service_intelligence": {"found": False},
    "internet_scanner_intelligence": {
        "found": True, "classification": "benign", "actor": "Shodan.io",
        "last_seen_timestamp": "2026-09-17T04:00:00Z",
        "tags": [{"name": "Web Crawler"}], "metadata": {}},
}
fields, _, _ = with_response(FakeResp(200, benign), e.src_greynoise_ip, "1.1.1.1")
note = e._greynoise_note(fields)
check_in("benign is explained as benign SCANNER", "scanner", note)
check_in("and says it is not a verdict about your host", "not", note)

fields_unseen, _, _ = with_response(FakeResp(200, not_seen),
                                    e.src_greynoise_ip, "45.33.32.156")
note_unseen = e._greynoise_note(fields_unseen)
check_in("not seen warns it does not mean clean", "clean", note_unseen)
check_in("and explains why, targeted traffic is invisible to it",
         "targeted", note_unseen)

# A note that says nothing is worse than no note, so it must never be empty
# for a row that has GreyNoise fields on it.
check("the note is never empty when there are fields", bool(note.strip()), True)


print("\n[6] CVE exploitation activity")

cve_hit = {
    "id": "CVE-2021-44228",
    "details": {"vulnerability_name": "Log4Shell", "vendor": "Apache",
                "product": "log4j", "cve_cvss_score": 10.0},
    "exploitation_details": {"exploit_found": True,
                            "exploitation_registered_in_kev": True,
                            "epss_score": 0.97, "attack_vector": "NETWORK"},
    "exploitation_stats": {"number_of_available_exploits": 42,
                          "number_of_threat_actors_exploiting_vulnerability": 9,
                          "number_of_botnets_exploiting_vulnerability": 3},
    "exploitation_activity": {"activity_seen": True,
                             "threat_ip_count_1d": 12, "threat_ip_count_30d": 400,
                             "benign_ip_count_1d": 3, "benign_ip_count_30d": 90},
}
fields, url, err = with_response(FakeResp(200, cve_hit),
                                 e.src_greynoise_cve, "CVE-2021-44228")
check("no error", err, None)
check("activity seen carried", fields.get("gn_exploit_activity_seen"), True)
check("attacking ip count carried", fields.get("gn_threat_ips_30d"), 400)
check("kev flag carried", fields.get("gn_in_kev"), True)

fields, url, err = with_response(FakeResp(404), e.src_greynoise_cve, "CVE-1999-0001")
check("an unknown cve is a negative, not an error", err, None)

fields, url, err = with_response(FakeResp(401), e.src_greynoise_cve, "CVE-1999-0001")
check_in("but a refused key on the cve path still says key", "key", err)


print("\n[7] a source with no function behind it cannot show as enabled")

cat = {s["source"]: s for s in e.source_catalog()}
for name, entry in cat.items():
    if entry.get("enabled"):
        check(f"{name} reports enabled only if something calls it",
              entry.get("wired"), True)

check("greynoise is in the catalogue", "greynoise" in cat, True)
check("and is now wired", cat.get("greynoise", {}).get("wired"), True)


print("\n[8] it is registered where the driver will actually run it")

ip_enrichers = [n for n, _fn, _k in e.ENRICHERS_BY_KIND.get("ip", [])]
cve_enrichers = [n for n, _fn, _k in e.ENRICHERS_BY_KIND.get("cve", [])]
check("greynoise runs on ip lookups", "greynoise" in ip_enrichers, True)
check("greynoise runs on cve lookups", "greynoise" in cve_enrichers, True)
check("it has a politeness floor", "greynoise" in e._MIN_INTERVAL, True)


print()
if fails:
    print(f"FAILED  {len(fails)} check(s): {', '.join(fails)}")
    sys.exit(1)
print("all GreyNoise checks passed")
