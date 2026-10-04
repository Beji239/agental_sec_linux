"""
tests/test_home_location.py, the map's centre pin finds itself (TM-6).

No network: the public address and its GeoIP place are stubbed. The timezone
tables are the system's own.
"""
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


from core import geoip                    # noqa: E402
from core import home_location as hl      # noqa: E402

AUTO = {"geoip": {"home_lat": None, "home_lon": None}}

print("[1] zone.tab coordinates")
lat, lon = hl._coord("+3541+13946")
check("Tokyo short form", (round(lat, 2), round(lon, 2)), (35.68, 139.77))
lat, lon = hl._coord("-3352+15113")
check("Sydney is south and east", (lat < 0, lon > 0), (True, True))
lat, lon = hl._coord("+404251-0740023")
check("New York long form", (round(lat, 3), round(lon, 3)), (40.714, -74.006))

print("[2] the timezone names a place")
tokyo = hl.timezone_place("Asia/Tokyo")
check("Asia/Tokyo is in Japan", (tokyo["country_code"], tokyo["city"]), ("JP", "Tokyo"))
check("an alias resolves to its zone", (hl.timezone_place("Japan") or {}).get("zone"), "Asia/Tokyo")
check("UTC names no place", hl.timezone_place("UTC"), None)
check("an unknown name is None", hl.timezone_place("Nowhere/Atall"), None)

print("[3] public address and timezone agree")
osaka = {"lat": 34.69, "lon": 135.50, "city": "Osaka", "region": "",
         "country": "Japan", "country_code": "JP"}
hl.timezone_place = lambda tz=None, _f=hl.timezone_place: _f("Asia/Tokyo")
hl.public_ip = lambda timeout=4.0: "203.0.113.7"
geoip.lookup = lambda ip: osaka
r = hl.locate(AUTO)
check("the city-level place wins", (r["label"], r["source"]), ("Osaka, Japan", "public address"))

print("[4] a VPN exit in another country")
geoip.lookup = lambda ip: {"lat": 40.7, "lon": -74.0, "city": "New York",
                           "region": "", "country": "United States",
                           "country_code": "US"}
r = hl.locate(AUTO)
check("the timezone wins", (r["source"], r["label"]), ("timezone", "Tokyo, Japan"))
check("and says why", "VPN" in r["detail"], True)

print("[5] no public address")
hl.public_ip = lambda timeout=4.0: None
r = hl.locate(AUTO)
check("falls back to the timezone", r["source"], "timezone")
check("and names the reason", "could not be read" in r["detail"], True)

print("[6] online lookup switched off")
called = []
hl.public_ip = lambda timeout=4.0: called.append(1) or "203.0.113.7"
r = hl.locate({"geoip": {"locate_online": False}})
check("no network call is made", called, [])
check("timezone used", r["source"], "timezone")

print("[7] a place fixed by hand still wins")
r = hl.locate({"geoip": {"home_lat": 48.85, "home_lon": 2.35, "home_label": "Paris"}})
check("manual", (r["lat"], r["label"], r["source"]), (48.85, "Paris", "settings"))

print("[8] current() answers at once, then refines in the background")
hl.public_ip = lambda timeout=4.0: "203.0.113.7"
geoip.lookup = lambda ip: osaka
hl._current, hl._at = None, 0.0
first = hl.current(AUTO)
check("first answer needs no network", first["source"], "timezone")
for _ in range(50):
    if hl._current:
        break
    time.sleep(0.05)
check("background refresh lands", (hl.current(AUTO) or {}).get("label"), "Osaka, Japan")

print("[9] nothing is hard-coded")
import json                                   # noqa: E402
for name in ("config.linux.example.json",):
    g = json.loads((ROOT / name).read_text(encoding="utf-8"))["geoip"]
    check(f"{name} fixes no place", (g["home_lat"], g["home_lon"]), (None, None))
src = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")
check("the map route asks home_location", "home_location.current(" in src, True)

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
