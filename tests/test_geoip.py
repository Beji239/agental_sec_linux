"""
tests/test_geoip.py, offline places for the threat map.

core/geoip opens a DB-IP file once and answers lookups from it, or says why
it cannot. A stand-in reader covers both record shapes, the caches, the age
note and every way the start can fail; the real file is used too when this
machine has it.

Run it directly: python tests/test_geoip.py
"""
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                      # noqa: E402
_isolate_db.isolate()
import _skip                                            # noqa: E402
from core import geoip as g                             # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


class Meta:
    def __init__(self, days_old, version):
        self.build_epoch = int(time.time() - days_old * 86400)
        self.ip_version = version


class Reader:
    def __init__(self, records, days_old=10, version=6):
        self.records, self.meta = records, Meta(days_old, version)
        self.asked = 0

    def get(self, ip):
        self.asked += 1
        if ip == "1.0.0.1":
            raise ValueError("corrupt node")
        return self.records.get(ip)

    def metadata(self):
        return self.meta


def reset(reader=None, asn=None):
    g._reader, g._asn_reader = reader, asn
    g._cache.clear()
    g._asn_cache.clear()
    g._status = "ready" if reader else "not_initialized"


NESTED = {"city": {"names": {"en": "Frankfurt", "de": "Frankfurt am Main"}},
          "country": {"iso_code": "DE", "names": {"en": "Germany"}},
          "subdivisions": [{"names": {"en": "Hesse"}}],
          "location": {"latitude": 50.11, "longitude": 8.68}}
FLAT = {"city": "Singapore", "country_code": "SG", "state1": "Singapore",
        "latitude": 1.29, "longitude": 103.85}

print("[1] which addresses go on the map")
for ip, routable, host in (("8.8.8.8", True, True), ("10.0.0.5", False, True),
                           ("127.0.0.1", False, True),
                           ("169.254.1.1", False, True),
                           ("224.0.0.251", False, False),
                           ("0.0.0.0", False, False), ("::1", False, True),
                           ("not-an-ip", False, False)):
    check(f"{ip} routable", g.is_routable(ip), routable)
    check(f"{ip} could be a host", g.is_host_address(ip), host)

print("\n[2] both record shapes are read")
reader = Reader({"1.1.1.1": NESTED, "8.8.4.4": FLAT,
                 "9.9.9.9": {"city": "Nowhere"}})
reset(reader)
check("nested", g.lookup("1.1.1.1"),
      {"lat": 50.11, "lon": 8.68, "city": "Frankfurt", "region": "Hesse",
       "country": "Germany", "country_code": "DE"})
flat = g.lookup("8.8.4.4")
check("flat, where the country name falls back to its code",
      (flat["city"], flat["country"], flat["lat"]), ("Singapore", "SG", 1.29))
check("a record with no coordinates is no place", g.lookup("9.9.9.9"),
      None)
check("an address the file does not know", g.lookup("149.112.112.112"), None)
check("a reader error is no place, not a crash", g.lookup("1.0.0.1"),
      None)
check("a private address is never looked up", g.lookup("10.0.0.5"), None)
asked = reader.asked
g.lookup("1.1.1.1")
check("a second lookup comes from the cache", reader.asked, asked)
check("a name in another language when English is missing",
      g._name({"names": {"de": "Wien"}}), "Wien")
check("an empty name", g._name(None), "")

print("\n[3] the popup label")
check("city and region the same are said once",
      g.label({"city": "Singapore", "region": "Singapore", "country": "SG"}),
      "Singapore, SG")
check("nothing known", g.label(None), "Unknown location")
check("all empty", g.label({"city": "", "country": ""}), "Unknown location")

print("\n[4] the status says how old the file is and what it covers")
reset(Reader({}, days_old=90, version=4))
st = g.status()
check("ready", st["ready"], True)
check("old and IPv4 only are both said",
      (st["stale"], st["ip_version"], "IPv4 only" in st["note"],
       "90 days" in st["note"]), (True, 4, True, True))
reset(Reader({}, days_old=5, version=6))
check("a fresh dual-stack file carries no note", "note" in g.status(), False)

print("\n[5] network owners")
asn = Reader({"1.1.1.1": {"autonomous_system_number": 15169,
                              "autonomous_system_organization": "Example"},
              "8.8.4.4": {"autonomous_system_organization": "No number"}})
reset(None, asn)
check("a known network", g.asn_lookup("1.1.1.1"),
      {"asn": "AS15169", "org": "Example"})
check("a record with no number", g.asn_lookup("8.8.4.4"), None)
check("an error", g.asn_lookup("1.0.0.1"), None)
check("a private address", g.asn_lookup("10.0.0.1"), None)
reset()
check("no owner database", g.asn_lookup("1.1.1.1"), None)

print("\n[6] every way the start can go")
with tempfile.TemporaryDirectory() as tmp:
    tmp = pathlib.Path(tmp)
    reset()
    check("switched off", g.init_geoip({"geoip": {"enabled": False}}, tmp)
          ["status"], "disabled in config")
    check("no path", g.init_geoip({"geoip": {}}, tmp)["status"],
          "no geoip.db_path set in config.json")
    st = g.init_geoip({"geoip": {"db_path": "geoip/none.mmdb"}}, tmp)
    check("a missing file names where to get one",
          (st["ready"], "db-ip.com" in st["status"]), (False, True))
    (tmp / "junk.mmdb").write_bytes(b"not a database")
    st = g.init_geoip({"geoip": {"db_path": "junk.mmdb",
                                 "asn_db_path": "junk.mmdb"}}, tmp)
    check("a damaged file says it could not open it",
          (st["ready"], st["status"].startswith("could not open")),
          (False, True))
    check("and so does a damaged owner file",
          g.asn_status()["status"].startswith("could not open"), True)
    g._init_asn({}, tmp)
    check("no owner file says how to fetch one",
          "fetch_geoip.py --asn" in g.asn_status()["status"], True)

print("\n[7] the real file, when this machine has it")
real = ROOT / "geoip" / "dbip-city-lite.mmdb"
if real.exists():
    reset()
    st = g.init_geoip({"geoip": {"db_path": str(real)}}, ROOT)
    check("it opens", st["ready"], True)
    place = g.lookup("8.8.8.8")
    check("a well known address has a country",
          bool(place and place["country_code"]), True)
else:
    _skip.skip_part("no DB-IP file here, python3 scripts/fetch_geoip.py")
reset()

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
