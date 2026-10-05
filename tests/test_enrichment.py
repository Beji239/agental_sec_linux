"""
tests/test_enrichment.py, tier 1 of the research worker. TODO 40.

WHAT IS ACTUALLY WORTH TESTING HERE.

Not "does RDAP answer". That is somebody else's uptime and it belongs in
scripts/enrichment_check.py, which hits the real sources on purpose. Every
source here is faked, so this file runs offline and always tells the truth
about the LOGIC rather than about the internet.

The three things that matter, in order:

  1. IT NEVER RETURNS EMPTY. Every path, including a source that raises,
     produces a row with one of the three statuses. TODO 35.3.
  2. THE THREE STATUSES STAY THREE DIFFERENT CLAIMS. Two sources agreeing,
     two sources disagreeing, one source alone, both sources saying "no
     record", and both sources timing out are FIVE different situations and
     they must not collapse into one word. The two that get confused in
     practice are the last two, and confusing them is how a model ends up
     saying "nothing found" about an address nobody could reach.
  3. FIELDS ONLY, NO PROSE. _fields_only is the trust boundary made
     structural, so a source returning a paragraph must not get a paragraph
     into the database.

Run it directly: python tests/test_enrichment.py
"""
import json
import pathlib
import sqlite3
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got):
    check(label, bool(got), True)


# A scratch database with only the two tables this module touches. Building
# it here rather than from Schema.SQL keeps the test from failing for reasons
# that have nothing to do with enrichment.
tmp = pathlib.Path(tempfile.mkdtemp()) / "t.db"
conn = sqlite3.connect(tmp)
conn.executescript("""
CREATE TABLE enrichment (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('ip','domain','cve','mac','hash','process')),
    status TEXT NOT NULL CHECK(status IN ('resolved','partial','unresolved')),
    confidence TEXT, fields_json TEXT NOT NULL DEFAULT '{}',
    sources_json TEXT NOT NULL DEFAULT '[]', tried_json TEXT NOT NULL DEFAULT '[]',
    gap TEXT, session_id TEXT,
    fetched_at TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL,
    UNIQUE(indicator, kind)
);
CREATE TABLE enrichment_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT NOT NULL, kind TEXT NOT NULL,
    requested_by TEXT, reason TEXT, session_id TEXT,
    requested_at TIMESTAMP NOT NULL, started_at TIMESTAMP, finished_at TIMESTAMP,
    state TEXT NOT NULL DEFAULT 'queued'
        CHECK(state IN ('queued','running','done','failed')),
    attempts INTEGER NOT NULL DEFAULT 0, note TEXT
);
""")
conn.commit()
conn.close()

from core import memory_engine as me                 # noqa: E402
me.DB_PATH = tmp

from core import enrichment as en                    # noqa: E402

# No test is allowed to touch the network. Anything that slips past the fakes
# below fails loudly instead of quietly making a real request.
def _no_network(*a, **k):
    raise AssertionError("a test tried to make a real HTTP request")


en.requests.get = _no_network
en._MIN_INTERVAL = {}                                 # no sleeping in tests


def fake(fields, url="https://example.test/x", err=None):
    return lambda indicator: (fields, url, err)


print("\n[1] classify names the kind from the shape, and refuses to guess")
check("an address is an ip",      en.classify("8.8.8.8"), "ip")
check("a v6 address is an ip",    en.classify("2001:4860:4860::8888"), "ip")
check("a CVE id is a cve",        en.classify("cve-2024-38063"), "cve")
check("a hardware address is mac", en.classify("5c:41:5a:12:34:01"), "mac")
check("64 hex is a hash",         en.classify("a" * 64), "hash")
check("a name is a domain",       en.classify("opera.com"), "domain")
# The refusal matters more than any of the above. A guessed kind sends the
# wrong sources at the question and the answer still lands in the database
# looking authoritative.
check("gibberish is refused",     en.classify("not an indicator"), None)
check("empty is refused",         en.classify(""), None)

# PROGRAM NAMES BEFORE DOMAINS, and the order is not arbitrary. "certutil.exe"
# matches the domain pattern perfectly well because "exe" looks like a TLD, so
# a domain-first order sends every process name to RDAP as if it were a
# website.
check("a program name is a process", en.classify("certutil.exe"), "process")
check("a powershell script too",     en.classify("payload.ps1"), "process")
check("a full path uses the filename",
      en.classify("C:\\Windows\\System32\\mshta.exe"), "process")
# The one collision that matters. `.com` is a Windows executable extension AND
# the most common domain suffix there is, so it is deliberately left out of
# the process pattern: a string that could be either is a domain every time it
# matters here.
check("a .com is still a domain",    en.classify("autorun.com"), "domain")
check("and so is a normal one",      en.classify("example.com"), "domain")
check("multi-label domains survive", en.classify("google.co.uk"), "domain")


print("\n[2] two sources that agree -> resolved, and the second is the LAST call")
en.SOURCES_BY_KIND["ip"] = [
    ("rdap",   fake({"organisation": "Google LLC", "network_name": "GOOGLE"})),
    ("ip_api", fake({"organisation": "Google Inc.", "asn": "AS15169 Google LLC"})),
]
r = en.research("8.8.8.8")
check("status", r["status"], "resolved")
check("confidence", r["confidence"], "two_sources_agree")
check("no gap is claimed", r["gap"], None)
check("both were tried", r["tried"], ["rdap", "ip_api"])
# "Google LLC" and "Google Inc." are the same allocation with two house
# styles. If the suffix stripping ever regresses, this goes to partial and
# every ordinary lookup starts hedging.
check("the registry field wins on a clash",
      r["fields"]["organisation"], "Google LLC")
check("and the row says which source gave it",
      r["fields"]["_field_sources"]["organisation"], "rdap")


print("\n[2b] the RDAP entity walk does not report the abuse mailbox as the owner")
# A real trap, caught by reading ARIN's actual answer for 8.8.8.8 rather than
# the RFC. It lists the abuse contact FIRST and its display name is the
# literal string "Abuse". A first-match walk reports the owner of 8.8.8.8 as
# "Abuse", which then fails to match ip-api's "Google LLC" and grades a
# completely ordinary lookup as sources_disagree.
arin_shaped = {
    "name": "GOGL", "handle": "NET-8-8-8-0-2",
    "entities": [
        {"roles": ["abuse"],
         "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                  ["fn", {}, "text", "Abuse"]]]},
        {"roles": ["administrative", "technical"],
         "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]]},
        {"roles": ["registrant"],
         "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]]},
    ],
}
check("registrant wins over the abuse contact",
      en._rdap_org(arin_shaped), "Google LLC")
check("a handle is a last resort, not an owner",
      en._rdap_org({"entities": [{"handle": "NET-1"}]}), "NET-1")
check("no entities at all is None", en._rdap_org({}), None)


print("\n[2d] RIPE hands back a maintainer object, and it is not an owner")
# Second failure of the same shape as the ARIN one above, found on a real run
# rather than in review. Asking about an address on a RIPE block came back
# with "EXAMPLENET-MNT" while ip-api said "Example Software LLC", so an ordinary
# lookup graded as sources_disagree. The -MNT object is the RIPE mntner, which
# says who may EDIT the entry. It is not a statement about who owns the block.
# Every European address would have hit this.
ripe_shaped = {
    "name": "EXAMPLENET", "handle": "77.111.246.0 - 77.111.246.255",
    "entities": [
        {"roles": ["registrant"],
         "vcardArray": ["vcard", [["fn", {}, "text", "EXAMPLENET-MNT"]]]},
        {"roles": ["technical"],
         "vcardArray": ["vcard", [["fn", {}, "text", "Example Software AS"]]]},
    ],
}
check("the maintainer object is skipped",
      en._rdap_org(ripe_shaped), "Example Software AS")
check("a maintainer is recognised", en._looks_like_admin_object("EXAMPLENET-MNT"), True)
check("and so is the other direction", en._looks_like_admin_object("MNT-EXAMPLENET"), True)
check("a real company name is not", en._looks_like_admin_object("Google LLC"), False)
# If the maintainer is genuinely the ONLY name in the response, return it. It
# is a real string from the registry, and the ASN check below can still rescue
# the comparison. A blank helps nobody.
only_mnt = {"entities": [{"roles": ["registrant"],
                          "vcardArray": ["vcard", [["fn", {}, "text", "FOO-MNT"]]]}]}
check("but a lone maintainer still beats a blank", en._rdap_org(only_mnt), "FOO-MNT")


print("\n[2e] when the org names miss, the ASN decides before calling it a conflict")
# The real 77.111.246.10 case, reduced. rdap's network_name was EXAMPLENET and
# ip-api's asn was "AS64500 Example Net AB". Plainly the same allocation, and
# the organisation strings share no token at all.
en.SOURCES_BY_KIND["ip"] = [
    ("rdap",   fake({"organisation": "EXAMPLENET-MNT", "network_name": "EXAMPLENET"})),
    ("ip_api", fake({"organisation": "Example Software LLC",
                     "asn": "AS64500 Example Net AB", "asn_name": "EXAMPLENET"})),
]
r = en.research("185.199.108.1")
check("this is agreement, not a conflict", r["status"], "resolved")
check("and it says WHICH key matched", r["agreed_on"], "network name / ASN")
check("stored with the row", r["fields"]["_agreed_on"], "network name / ASN")

# The ASN key must not become a way to agree about anything. Two unrelated
# allocations that happen to be datacentres share nothing specific, and the
# generic words are filtered out on purpose.
en.SOURCES_BY_KIND["ip"] = [
    ("rdap",   fake({"organisation": "Hetzner Online", "network_name": "HETZNER-NET"})),
    ("ip_api", fake({"organisation": "Digital Ocean",
                     "asn": "AS14061 DigitalOcean", "asn_name": "DIGITALOCEAN"})),
]
r = en.research("185.199.108.2")
check("genuinely different orgs still conflict", r["status"], "partial")
check("confidence", r["confidence"], "sources_disagree")

# And the plain case still reports the plain reason.
en.SOURCES_BY_KIND["ip"] = [
    ("rdap",   fake({"organisation": "Google LLC"})),
    ("ip_api", fake({"organisation": "Google Inc"})),
]
check("a normal match still says organisation name",
      en.research("185.199.108.3")["agreed_on"], "organisation name")


print("\n[2c] the CVE parsers read the shapes the real services actually return")
# Both payloads below are trimmed copies of the real 2026-09-02 responses for
# CVE-2024-38063, keys and nesting intact. Kept here because both services
# have already changed shape once: CIRCL moved to Vulnerability-Lookup and put
# everything under containers.cna, and a parser that only knows the old flat
# keys reports "no record" for a CVE that is sitting right there. That failure
# is invisible, it looks exactly like a CVE nobody has published.
_captured = {}


def _stub_get_json(url, source, params=None):
    return _captured.get(source), None


_real_get_json = en._get_json
en._get_json = _stub_get_json

_captured["nvd"] = {
    "vulnerabilities": [{"cve": {
        "id": "CVE-2024-38063",
        "published": "2024-08-13T18:15:10.007",
        "lastModified": "2026-06-17T07:39:20.200",
        "vulnStatus": "Analyzed",
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
    }}]
}
f, _, err = en.src_nvd_cve("CVE-2024-38063")
check("nvd: no error", err, None)
check("nvd: id", f["cve_id"], "CVE-2024-38063")
check("nvd: score", f["cvss_score"], 9.8)
check("nvd: severity", f["cvss_severity"], "CRITICAL")
check_true("nvd: vector", f["cvss_vector"].startswith("CVSS:3.1/"))

_captured["circl"] = {
    "dataType": "CVE_RECORD",
    "cveMetadata": {"cveId": "CVE-2024-38063",
                    "datePublished": "2024-08-13T17:29:58.392Z",
                    "dateUpdated": "2026-06-17T07:39:20.200Z"},
    "containers": {"cna": {"metrics": [{"cvssV3_1": {
        "baseScore": 9.8, "baseSeverity": "CRITICAL",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}},
}
f, _, err = en.src_circl_cve("CVE-2024-38063")
check("circl: no error", err, None)
check("circl: id out of cveMetadata", f["cve_id"], "CVE-2024-38063")
check("circl: score out of containers.cna", f["cvss_score"], 9.8)
check_true("circl: published date", f["published"].startswith("2024-08-13"))

# And the two of them together are what "resolved" means for a CVE.
r = en.research("CVE-2024-38063")
check("two CVE sources agree", r["status"], "resolved")
en._get_json = _real_get_json


print("\n[3] the ladder stops on confidence, not on a page count")
# TODO 35.3 rejected a flat budget because it stops on a count that has
# nothing to do with whether the question was answered. Proving the opposite
# here: a third source exists and is never called, because two already agreed.
calls = []


def counting(name, fields):
    def fn(indicator):
        calls.append(name)
        return fields, f"https://{name}.test", None
    return fn


en.SOURCES_BY_KIND["ip"] = [
    ("rdap",   counting("rdap",   {"organisation": "Cloudflare"})),
    ("ip_api", counting("ip_api", {"organisation": "Cloudflare Inc"})),
    ("third",  counting("third",  {"organisation": "Cloudflare"})),
]
r = en.research("1.1.1.1")
check("stopped after two", calls, ["rdap", "ip_api"])
check("and still resolved", r["status"], "resolved")


print("\n[4] two sources that DISAGREE -> partial, both values kept, and named")
en.SOURCES_BY_KIND["ip"] = [
    ("rdap",   fake({"organisation": "Hetzner Online"})),
    ("ip_api", fake({"organisation": "Digital Ocean"})),
]
r = en.research("5.5.5.5")
check("status", r["status"], "partial")
check("confidence", r["confidence"], "sources_disagree")
check_true("the gap names both claims",
           "Hetzner" in r["gap"] and "Digital Ocean" in r["gap"])
# The dangerous shortcut would be to pick one and call it resolved. A user
# reading "Hetzner Online" has no way to know a second registry disagreed.
check_true("and it says not to present either as settled",
           "settled" in r["gap"])


print("\n[5] one source alone -> partial, never resolved")
en.SOURCES_BY_KIND["ip"] = [
    ("rdap",   fake({"organisation": "Example Software"})),
    ("ip_api", fake(None, err="Timeout")),
]
r = en.research("185.199.108.4")
check("status", r["status"], "partial")
check("confidence", r["confidence"], "single_source")
check_true("the gap names the failure", "Timeout" in r["gap"])
check("the answer is still there", r["fields"]["organisation"], "Example Software")


print("\n[6] 'they have no record' and 'they did not answer' stay different")
# This is the distinction the whole file is built around, and the one that
# goes wrong in practice. Both look like an empty result to a caller that
# only checks whether fields came back.
en.SOURCES_BY_KIND["ip"] = [
    ("rdap",   fake(None)),          # answered, 404, no allocation
    ("ip_api", fake(None)),
]
r = en.research("185.199.108.153")
check("status", r["status"], "unresolved")
check("confidence", r["confidence"], "sources_have_no_record")
check_true("and it says this is a real negative",
           "real negative result" in r["gap"])

en.SOURCES_BY_KIND["ip"] = [
    ("rdap",   fake(None, err="ConnectionError")),
    ("ip_api", fake(None, err="Timeout")),
]
r = en.research("185.199.108.153")
check("status", r["status"], "unresolved")
check("confidence", r["confidence"], "none")
check_true("and it says UNKNOWN, not 'nothing is there'",
           "UNKNOWN" in r["gap"] and "nothing is there" in r["gap"])
check("what was tried is on the row", r["tried"], ["rdap", "ip_api"])


print("\n[7] a source that RAISES does not take the job down")
def exploding(indicator):
    raise RuntimeError("a parser bug")


en.SOURCES_BY_KIND["ip"] = [
    ("rdap",   exploding),
    ("ip_api", fake({"organisation": "Amazon"})),
]
r = en.research("52.1.1.1")
check("the other source still answered", r["status"], "partial")
check_true("and the crash is reported as OUR fault, not a verdict",
           any("parser error" in e for e in r["errors"]))


print("\n[8] a LAN address is never sent to a public registry")
# Same rule as core/ip_lookup.py. Multicast is checked before is_global
# because is_global is TRUE for IPv4 multicast, so 224.0.0.251 would sail
# straight out to a public service.
en.SOURCES_BY_KIND["ip"] = [("rdap", _no_network)]
# 169.254.0.0 rather than a host on it: any link-local example has to sit in
# 169.254/16 by definition, and scripts/check_no_local_details.py flags a
# private HOST address while letting a network address through. It is still a
# link-local address as far as the code under test is concerned.
for addr, scope in (("192.0.2.10", "private/LAN"),
                    ("224.0.0.251", "multicast"),
                    ("169.254.0.0", "link-local"),
                    ("127.0.0.1", "loopback")):
    r = en.research(addr)
    check(f"{addr} refused", r["status"], "unresolved")
    check(f"{addr} scope named", r["fields"]["scope"], scope)
check_true("and it points at the local tool instead",
           "query_known_devices" in en.research("192.0.2.10")["gap"])


print("\n[9] fields only. prose cannot get through.")
long_text = "x" * 4000
r = en._fields_only({
    "organisation": "Fine",
    "description":  long_text,
    "entities":     [{"handle": "nested"}],
    "remarks":      {"text": "a paragraph"},
    "score":        7.5,
    "flag":         True,
    "empty":        "",
})
check("a scalar survives", r["organisation"], "Fine")
check("a number survives", r["score"], 7.5)
check("a bool survives", r["flag"], True)
check("a list is dropped entirely", "entities" in r, False)
check("a dict is dropped entirely", "remarks" in r, False)
check("a long string is capped",
      len(r["description"]) <= en.FIELD_MAX_CHARS + 20, True)
check("an empty string becomes None", r["empty"], None)


print("\n[10] a source with no key says WHICH key, not just 'failed'")
# Hash lookups go to MalwareBazaar, which needs an abuse.ch Auth-Key. With no
# key in the environment the answer must name the variable to set. "unresolved"
# on its own would read as "this hash is unknown", which is a much stronger and
# completely different claim.
import os                                            # noqa: E402
os.environ.pop("AGENTAL_ABUSECH_KEY", None)
os.environ.pop("AGENTAL_ABUSEIPDB_KEY", None)
r = en.research("a" * 64)
check("status", r["status"], "unresolved")
check_true("it names the env var to set",
           any("AGENTAL_ABUSECH_KEY" in e for e in r["errors"]))
check_true("and says where to get one", "auth.abuse.ch" in "; ".join(r["errors"]))



print("\n[10a] LOLBAS. A hit means the binary is ABUSABLE, never that it is bad.")
# The last gap in tier 1. There is no registry that says what svchost.exe IS,
# so LOLBAS answers a better question instead: is this a binary that turns up
# in attacks, and by what technique.
#
# THE MISREADING THIS INVITES is the whole reason the note exists. certutil.exe
# is on every Windows machine on earth and is signed by Microsoft. A listing is
# about what the binary CAN be used for, not about what this copy did.
en._lolbas_index = {
    "certutil.exe": {
        "Name": "Certutil.exe",
        "Description": "Windows binary used for handling certificates",
        "url": "https://lolbas-project.github.io/lolbas/Binaries/Certutil/",
        "Commands": [
            {"Category": "Download", "Usecase": "Download file from Internet",
             "MitreID": "T1105", "Privileges": "User"},
            {"Category": "Download", "Usecase": "Download file from Internet",
             "MitreID": "T1105", "Privileges": "User"},
            {"Category": "Encode", "Usecase": "Encode a file",
             "MitreID": "T1027", "Privileges": "User"},
        ],
    },
}
f, url, err = en.src_lolbas("certutil.exe")
check("no error", err, None)
check("flagged as abusable", f["abusable_windows_binary"], True)
check("categories are de-duplicated", f["abuse_categories"], "Download, Encode")
check("so are the technique ids", f["mitre_ids"], "T1105, T1027")
check("and the count is of commands, not of categories",
      f["documented_techniques"], 3)
check_true("the entry url is the source", "lolbas-project.github.io" in url)

# A full path is fine. Only the filename is used, because the path a binary ran
# from is a fact about THIS machine and belongs in the observation tables.
f2, _, _ = en.src_lolbas("C:\\Windows\\System32\\certutil.exe")
check("a full path resolves to the same entry", f2["binary_name"], "Certutil.exe")

# The note, which leads with the thing that is true of EVERY hit.
note = en._lolbas_note(f)
check_true("it says legitimate first", "is a LEGITIMATE Windows binary" in note)
check_true("it says finding it running is ordinary",
           "completely ordinary" in note)
check_true("and it says not to report the listing alone",
           "Do NOT report the listing on its own as a finding" in note)

r = en.research("certutil.exe")
check("kind worked out from the shape", r["kind"], "process")
check("one source means single_source", r["confidence"], "single_source")
check("which is partial, not resolved", r["status"], "partial")
en.store(r)
row = en.read("certutil.exe")
check_true("the note is attached on read",
           "how_to_read_the_lolbas_listing" in row)
check("and not stored in the fields",
      "how_to_read_the_lolbas_listing" in row["fields"], False)


print("\n[10a2] a process NOT in the catalogue says what that does and does not mean")
# "unresolved" reads as a shrug, and this particular one is a small piece of
# real information. It is also very easy to over-read in the other direction.
r = en.research("totally-made-up-thing.exe")
check("status", r["status"], "unresolved")
check("confidence", r["confidence"], "sources_have_no_record")
check_true("it says it is not a catalogued abusable binary",
           "NOT one of the catalogued abusable Windows binaries" in r["gap"])
check_true("and refuses to call it legitimate",
           "says nothing about whether the binary is legitimate" in r["gap"])


print("\n[10a3] no catalogue at all is not the same as no record")
# An empty catalogue would report every process as "not a known abusable
# binary", which is a confident and completely unearned claim. So a load
# failure is an ERROR, not a negative result.
en._lolbas_index = None
_real_load = en._load_lolbas
en._load_lolbas = lambda: None
try:
    f, _, err = en.src_lolbas("certutil.exe")
    check("no fields", f, None)
    check_true("and an error, not silence", err is not None)
    check_true("which says it is not a statement about the binary",
               "not a statement about the binary" in err)
    r = en.research("certutil.exe")
    check("the whole lookup is unresolved", r["status"], "unresolved")
    check("and NOT sources_have_no_record", r["confidence"], "none")
finally:
    en._load_lolbas = _real_load
    en._lolbas_index = None


print("\n[10b] reputation runs even when the ladder already stopped early")
# THE TRAP THIS COVERS. The obvious build appends AbuseIPDB to the IP source
# list. The ladder stops as soon as two sources agree on ownership, and RDAP
# and ip-api usually do, so the reputation lookup would be skipped EXACTLY
# WHEN EVERYTHING IS WORKING. Ownership and reputation are different
# questions, so they are not two opinions about one fact.
os.environ["AGENTAL_ABUSEIPDB_KEY"] = "test-key"
os.environ["AGENTAL_ABUSECH_KEY"] = "test-key"
rep_calls = []


def fake_rep(name, fields):
    def fn(indicator):
        rep_calls.append(name)
        return fields, f"https://{name}.test/{indicator}", None
    return fn


en.SOURCES_BY_KIND["ip"] = [
    ("rdap",   fake({"organisation": "Google LLC"})),
    ("ip_api", fake({"organisation": "Google Inc"})),
]
en.ENRICHERS_BY_KIND["ip"] = [
    ("abuseipdb", fake_rep("abuseipdb", {"abuse_confidence_score": 0,
                                         "abuse_total_reports": 0}), "abuseipdb"),
    ("urlhaus",   fake_rep("urlhaus", None), "abuse_ch"),
]
r = en.research("8.8.4.4")
check("ownership is still resolved", r["status"], "resolved")
check("and reputation ran anyway", "abuseipdb" in rep_calls, True)
check("the score is on the row", r["fields"]["abuse_confidence_score"], 0)
check("both were tried", "abuseipdb" in r["tried"] and "urlhaus" in r["tried"], True)


print("\n[10c] a malware hit is never allowed to hide in field fourteen")
# `resolved` with serves_malware buried among twenty fields is how a finding
# gets missed. It goes in the gap, where a reader looks.
en.ENRICHERS_BY_KIND["ip"] = [
    ("urlhaus", fake_rep("urlhaus", {"serves_malware": True,
                                     "malware_url_count": 12,
                                     "malware_urls_online": 3}), "abuse_ch"),
]
r = en.research("8.8.4.5")
check("ownership still resolved", r["status"], "resolved")
check_true("but the gap leads with the flag", r["gap"].startswith("FLAGGED by urlhaus"))
check_true("and says it is second-hand", "second-hand" in r["gap"])


print("\n[10d] reputation alone is partial, not unresolved")
# A malware hit must not be thrown away because a registry timed out. That is
# the wrong way round.
en.SOURCES_BY_KIND["ip"] = [
    ("rdap",   fake(None, err="Timeout")),
    ("ip_api", fake(None, err="Timeout")),
]
r = en.research("8.8.4.6")
check("status", r["status"], "partial")
check("confidence", r["confidence"], "reputation_only")
check("the malware fields survived", r["fields"]["malware_url_count"], 12)
check_true("and it says identity is still unknown", "Identity is still" in r["gap"])


print("\n[10e] how to read an abuse score, generated on read and never stored")
# Same reasoning as lookup_ip.how_to_read_this. A score is the field most
# likely to be over-read: a busy datacentre address collects reports the way a
# busy road collects litter.
check_true("zero is not a clean bill of health",
           "not that the address is safe" in en._abuse_confidence_note(0))
# THE PAIR THAT LOOKS WRONG, from the first real run. 8.8.8.8 came back score
# 0, whitelisted true, total reports 199. All three correct, and a reader
# skimming for a big number stops at 199. So that combination gets said out
# loud rather than left to be worked out.
note = en._abuse_confidence_note(0, {"abuse_total_reports": 199,
                                     "abuse_is_whitelisted": True})
check_true("whitelisted is explained first", note.startswith("AbuseIPDB has this address whitelisted"))
check_true("the report count is named, not left to confuse", "199 reports" in note)
check_true("and it says not to quote it as a finding",
           "Do not quote the report count" in note)
check_true("whitelisted is not sold as a promise", "not a promise" in note)
# Reports with a zero score and no whitelist is a different sentence.
note2 = en._abuse_confidence_note(0, {"abuse_total_reports": 40})
check_true("old or thin reports are named as such",
           "old, thin, or from reporters with no standing" in note2)

# THE NOTE MUST NOT CONTRADICT THE ROW. From the first real URLhaus hit,
# 2026-09-02. A fixed-line ISP address came back score 5, one report, AND
# flagged by URLhaus as actively serving malware. The canned low-score
# sentence talks about busy DATACENTRE addresses collecting reports like
# litter, which is true and irrelevant here, so the note read as reassurance
# sitting directly under a malware hit.
flagged_note = en._abuse_confidence_note(
    5, {"abuse_total_reports": 1, "serves_malware": True, "is_datacentre": False})
check_true("a malware flag is said first", flagged_note.startswith("This indicator is FLAGGED"))
check_true("and the score is not allowed to soften it",
           "does not soften a malware hit" in flagged_note)
check_true("and it says what to lead with", "Lead with the malware flag" in flagged_note)
check("no datacentre litter line on a flagged row",
      "litter" in flagged_note, False)

# The datacentre sentence only when the row actually says datacentre.
isp_note = en._abuse_confidence_note(5, {"is_datacentre": False})
dc_note  = en._abuse_confidence_note(5, {"is_datacentre": True})
check("no datacentre claim on an ISP address", "datacentre" in isp_note, False)
check_true("and it refuses to clear the address either",
           "does not clear it" in isp_note)
check_true("the datacentre line survives where it is true", "litter" in dc_note)
check_true("a low score is not evidence",
           "not evidence of anything" in en._abuse_confidence_note(
               12, {"is_datacentre": True}))
check_true("a high score is still second-hand",
           "second-hand" in en._abuse_confidence_note(95))
check_true("and no score at all is not silence",
           "nobody has answered" in en._abuse_confidence_note(None))

en.ENRICHERS_BY_KIND["ip"] = [
    ("abuseipdb", fake_rep("abuseipdb", {"abuse_confidence_score": 90}), "abuseipdb"),
]
en.SOURCES_BY_KIND["ip"] = [("rdap", fake({"organisation": "Some Host"}))]
en.store(en.research("8.8.4.7"))
row = en.read("8.8.4.7")
check_true("the note is attached on read",
           "how_to_read_the_abuse_score" in row)
check("and NOT stored in the fields",
      "how_to_read_the_abuse_score" in row["fields"], False)


print("\n[10f] a row carrying reputation expires on the reputation clock")
# Ownership is stable for years, a report count is not. The shorter of the two
# always wins, so this can only ever make a row refresh sooner.
check("plain ip row lives a month",
      en._ttl_for("ip", "resolved", {"organisation": "x"}), 30 * 86400)
check("but with a score it is a week",
      en._ttl_for("ip", "resolved", {"abuse_confidence_score": 3}),
      en.REPUTATION_TTL_SECONDS)
check("a malware flag does the same",
      en._ttl_for("ip", "resolved", {"serves_malware": True}),
      en.REPUTATION_TTL_SECONDS)

# Put the environment back so later sections run keyless.
os.environ.pop("AGENTAL_ABUSEIPDB_KEY", None)
os.environ.pop("AGENTAL_ABUSECH_KEY", None)
en.ENRICHERS_BY_KIND["ip"] = []


print("\n[11] storage: the row survives a round trip and is marked second-hand")
en.SOURCES_BY_KIND["ip"] = [
    ("rdap",   fake({"organisation": "Google LLC"}, url="https://rdap.org/ip/8.8.8.8")),
    ("ip_api", fake({"organisation": "Google Inc"}, url="http://ip-api.com/json/8.8.8.8")),
]
en.store(en.research("8.8.8.8"), session_id="test-session")
row = en.read("8.8.8.8")
check("status stored", row["status"], "resolved")
check("kind stored", row["kind"], "ip")
check("fields stored", row["fields"]["organisation"], "Google LLC")
check("source urls kept", len(row["sources"]), 2)
# The model has to be able to see that this is not an observation of this
# network. TODO 37 is what happens when it cannot.
check("marked external intel", row["record_type"], "external_intel")
check("not stale yet", row["stale"], False)


print("\n[12] an unresolved row expires in hours, a resolved one does not")
# This is how TODO 35.3's "requeue it later with a bigger budget" happens
# without a scheduler existing: the next question finds a stale row.
check("resolved ip lives a month",
      en._ttl_for("ip", "resolved"), 30 * 86400)
check("unresolved ip expires in six hours",
      en._ttl_for("ip", "unresolved"), en.UNRESOLVED_TTL_SECONDS)
check("a partial row is retried too",
      en._ttl_for("ip", "partial"), en.UNRESOLVED_TTL_SECONDS)
check("a vendor prefix lasts a year",
      en._ttl_for("mac", "resolved"), 365 * 86400)


print("\n[13] the queue: enqueue is cheap, does not block, and does not duplicate")
q = en.enqueue("cve-2024-38063", reason="runbook check")
check("queued", q["queued"], True)
check("kind worked out", q["kind"], "cve")
again = en.enqueue("cve-2024-38063")
check("a second request does not queue twice", again["queued"], False)
check("and says so", again.get("already_queued"), True)

# Something already known and current is not re-queued at all.
cached = en.enqueue("8.8.8.8")
check("a fresh cached answer is returned instead", cached["queued"], False)
check("and it comes back with the row", cached["result"]["status"], "resolved")

bad = en.enqueue("this is not an indicator")
check("gibberish is refused, not queued", bad["queued"], False)
check_true("with a reason", "recognisable" in bad["error"])


print("\n[14] run_one always leaves a row, even when the whole job blows up")
en.SOURCES_BY_KIND["cve"] = [("circl", exploding), ("nvd", exploding)]
en.run_one()
row = en.read("cve-2024-38063", "cve")
check_true("a row exists", row is not None)
check("and it is unresolved rather than absent", row["status"], "unresolved")

# And when research itself cannot be reached at all. A job that vanishes is
# the emptiest possible answer, which is the one thing TODO 35.3 forbids.
en.enqueue("cve-2020-0001")
real_research = en.research
en.research = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
try:
    en.run_one()
finally:
    en.research = real_research
row = en.read("cve-2020-0001", "cve")
check_true("still a row", row is not None)
check("still unresolved", row["status"], "unresolved")
check_true("and it says the fault was ours",
           "fault in this tool" in row["gap"])


print("\n[15] query on something nobody looked at is not a clean result")
r = en.Enrichment(session_id="t").query("9.9.9.9")
check("found is false", r["found"], False)
check_true("and it says nothing looked, which is not nothing found",
           "NOT the same as nothing found" in r["note"])


print("\n[16] the tools are wired the way the rest of the project expects")
from core import sanitize                            # noqa: E402
check("enqueue_enrichment is fenced",
      sanitize.is_untrusted("enqueue_enrichment"), True)
check("query_enrichment is fenced",
      sanitize.is_untrusted("query_enrichment"), True)

from core import tool_registry as tr                 # noqa: E402
names = {t["name"] for t in tr.TOOL_MANIFEST}
check("enqueue_enrichment is in the manifest", "enqueue_enrichment" in names, True)
check("query_enrichment is in the manifest", "query_enrichment" in names, True)
check("enqueue counts as a write", tr.tool_writes("enqueue_enrichment"), True)
check("query does not", tr.tool_writes("query_enrichment"), False)
# The capability label has to stay honest about the write half. Local mode
# owned this rule until it was removed on 2026-09-14, so the enrichment
# shaped part of it lives here now: a manifest carrying a write tool must
# never be described as read only.
check("the label counts the writes rather than asserting a claim",
      tr.capability_label().endswith("write tools"), True)
check("and enqueue_enrichment is one of the tools it counted",
      "enqueue_enrichment" in tr.write_tools(), True)
check("while the read is not", "query_enrichment" in tr.write_tools(), False)


print("\n[17] the source catalogue matches the sources that actually run")
# TODO 44. The dashboard names the HOSTS this module contacts, and it derives
# that list from SOURCES_BY_KIND and ENRICHERS_BY_KIND rather than holding its
# own copy. This test is the thing that makes the derivation worth trusting:
# it fails when a source is wired up without a line explaining it, which is
# the only way the screen and the code can drift apart again.
catalog = en.source_catalog()
by_id = {s["source"]: s for s in catalog}

wired = set()
for sources in en.SOURCES_BY_KIND.values():
    wired.update(name for name, _fn in sources)
for enrichers in en.ENRICHERS_BY_KIND.values():
    wired.update(name for name, _fn, _keyed in enrichers)

check("every wired source appears in the catalogue", wired - set(by_id), set())
check_true("and every one of them is documented",
           all(by_id[name]["documented"] for name in wired))

# An undocumented source must be REPORTED, not dropped. Same rule as
# "unresolved is not the same as nothing found": a silent omission is the
# failure mode this whole feature exists to prevent.
en.SOURCES_BY_KIND.setdefault("ip", []).append(("bogus_source", lambda i: (None, None, None)))
try:
    probe = {s["source"]: s for s in en.source_catalog()}
    check_true("an undocumented source is still listed", "bogus_source" in probe)
    check("and is flagged rather than described",
          probe["bogus_source"]["documented"], False)
finally:
    en.SOURCES_BY_KIND["ip"] = [s for s in en.SOURCES_BY_KIND["ip"]
                                if s[0] != "bogus_source"]

# Every network source names the host it contacts. A blank host on the screen
# is worse than no screen: it reads as "nothing goes out".
for entry in catalog:
    if entry["network"]:
        check_true(f"{entry['source']} names a host", bool(entry["host"]))
    check_true(f"{entry['source']} says what it answers", bool(entry["answers"]))

# The local one is local. If oui ever starts making requests this flips, and
# the "no network at all" claim on the dashboard stops being true.
check("the IEEE lookup reaches no network", by_id["oui"]["network"], False)

# A keyed source with no key is returned OFF and NAMED, not hidden. This is
# the operator seeing what the tool cannot currently answer.
import os                                            # noqa: E402
saved = os.environ.pop("AGENTAL_ABUSEIPDB_KEY", None)
try:
    off = {s["source"]: s for s in en.source_catalog()}["abuseipdb"]
    check("a keyless source is off", off["enabled"], False)
    check("and says which variable to set", off["env_var"], "AGENTAL_ABUSEIPDB_KEY")
    check_true("and why it is off", bool(off["why_off"]))
finally:
    if saved is not None:
        os.environ["AGENTAL_ABUSEIPDB_KEY"] = saved

check_true("something is stated as never sent", len(en.NEVER_SENT) >= 1)


print("\n[malware is a headline, 41.7]")
# The owner's call, 2026-09-04: "a malware is a malware, it should raise
# something." A live URLhaus hit had printed `partial (single_source)` as its
# headline because status describes the ownership ladder and rdap had timed
# out. True, and softer than the row deserved.
check("a urlhaus hit is flagged",
      en.is_flagged({"serves_malware": True}), True)
check("a malwarebazaar hit is flagged",
      en.is_flagged({"known_malware": True}), True)
check("the family is named when there is one",
      "RemcosRAT" in en.flag_line({"known_malware": True,
                                   "malware_family": "RemcosRAT"}), True)
# THE LINE THAT MATTERS MOST. An AbuseIPDB score is not a malware hit. The
# address that started all this scored 4 off ONE report, and promoting that to
# a headline is the same misreading _abuse_confidence_note exists to stop,
# running the other way.
check("a low abuse score is NOT a flag",
      en.is_flagged({"abuse_confidence_score": 4, "abuse_total_reports": 1}),
      False)
check("nor is a high one",
      en.is_flagged({"abuse_confidence_score": 100}), False)
check("and an unflagged row gets no headline",
      en.flag_line({"abuse_confidence_score": 100}), None)
check("nothing at all is not a flag", en.is_flagged({}), False)
check("neither is None", en.is_flagged(None), False)
# status keeps its own job. Overloading it would break resolved-and-flagged,
# which is an ordinary thing to be: we know exactly who owns it AND it serves
# malware.
check("the flag does not touch the status vocabulary",
      "flagged" in en.VALID_STATUS if hasattr(en, "VALID_STATUS") else False,
      False)

print("\n" + ("ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}"))
sys.exit(1 if fails else 0)
