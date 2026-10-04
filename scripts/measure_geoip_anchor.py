#!/usr/bin/env python3
"""
scripts/measure_geoip_anchor.py — what the threat map's home pin actually says.

WHY THIS EXISTS, 2026-09-23. The map draws every arc from one point, and that
point comes from two numbers in config.json that nothing in this app has ever
checked. Found while auditing the map: this tree's config and the Windows
tree's config carry IDENTICAL coordinates with DIFFERENT labels, so the value
was copied between machines rather than chosen for either, and neither install
can tell you whether it is right. This script reads both files at run time and
reports that, rather than restating either one here.

WHAT CAN AND CANNOT BE MEASURED HERE. There is no GPS on a laptop and this
script makes NO NETWORK CALL — not one. So it does not claim to know where the
machine is; it reports what the configured point implies, what local evidence
can corroborate or contradict it, and what the pin's label actually says. If
the answer is "cannot be established from this host", that is the answer.

    python scripts/measure_geoip_anchor.py

Exit code is 0 when the config is internally consistent and the local evidence
does not contradict it, 1 when it does. It never writes anything.
"""
import json
import math
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# A handful of places local evidence can name, so an answer can be a distance
# rather than a number. Deliberately coarse: this is a sanity check on a city,
# not a geocoder, and a long city list would be a worse lie than a short one.
CITIES = {
    "San Francisco":  (37.7749, -122.4194),
    "Oakland":        (37.8044, -122.2712),
    "San Jose":       (37.3382, -121.8863),
    "Sacramento":     (38.5816, -121.4944),
    "Fresno":         (36.7378, -119.7871),
    "Los Angeles":    (34.0522, -118.2437),
    "Long Beach":     (33.7701, -118.1937),
    "San Diego":      (32.7157, -117.1611),
    "Las Vegas":      (36.1699, -115.1398),
    "Reno":           (39.5296, -119.8138),
    "Portland":       (45.5152, -122.6784),
    "Seattle":        (47.6062, -122.3321),
    "Phoenix":        (33.4484, -112.0740),
    "Salt Lake City": (40.7608, -111.8910),
    "Denver":         (39.7392, -104.9903),
    # Outside the US, because a wrong-continent anchor is worse than a
    # wrong-city one and both look identical in two decimals.
    "Vancouver":      (49.2827, -123.1207),
    "Toronto":        (43.6532, -79.3832),
    "London":         (51.5074, -0.1278),
    "Sydney":         (-33.8688, 151.2093),
}

# The city each IANA timezone's clock is normally set for. A rough anchor's
# whole job is to be in the right region, so this is the one piece of local
# evidence that can be contradicted by the numbers.
TZ_CITY = {
    "America/Los_Angeles": "San Francisco",
    "America/Vancouver":   "Vancouver",
    "America/Toronto":     "Toronto",
    "America/Denver":      "Denver",
    "America/Phoenix":     "Phoenix",
    "Europe/London":       "London",
    "Australia/Sydney":    "Sydney",
}


def km(a, b, c, d):
    """Great-circle distance in km. Nothing here leaves the process."""
    R = 6371.0
    p1, p2 = math.radians(a), math.radians(c)
    dp, dl = p2 - p1, math.radians(d - b)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R * math.asin(math.sqrt(h))


def nearest(lat, lon):
    return min(CITIES.items(), key=lambda kv: km(lat, lon, kv[1][0], kv[1][1]))


def local_timezone():
    for src in (pathlib.Path("/etc/timezone"),
                pathlib.Path("/etc/localtime")):
        try:
            if src.name == "timezone" and src.exists():
                return src.read_text(encoding="utf-8").strip()
            if src.is_symlink():
                return str(src.resolve()).split("zoneinfo/")[-1]
        except Exception:
            pass
    try:
        out = subprocess.run(["timedatectl", "show", "-p", "Timezone",
                              "--value"], capture_output=True, text=True,
                             timeout=5)
        return out.stdout.strip()
    except Exception:
        return ""


def main():
    cfg_path = ROOT / "config.json"
    if not cfg_path.exists():
        print(f"no config.json at {cfg_path}")
        return 1
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    geo = cfg.get("geoip") or {}

    # READ FROM CONFIG, NEVER RESTATED HERE. The gate that guards a release
    # scans this file, and a copy of the operator's own coordinates or label
    # written into it would be a local detail shipped in the tree. It also
    # means this script cannot go stale against a config that changed.
    lat, lon = geo.get("home_lat"), geo.get("home_lon")
    label = geo.get("home_label")

    print("=" * 74)
    print("THE THREAT MAP'S HOME ANCHOR, MEASURED")
    print("=" * 74)
    print(f"\nconfig.json says")
    print(f"    home_lat   {lat!r}")
    print(f"    home_lon   {lon!r}")
    print(f"    home_label {label!r}")
    print(f"    enabled    {geo.get('enabled')!r}")

    if lat is None or lon is None:
        print("\nNO ANCHOR IS SET. The map draws endpoints as dots with no arcs,")
        print("and its own stats line says how to set one. That is a complete,")
        print("honest state and nothing else in this report applies.")
        return 0

    problems = []

    # what the point IS
    city, (clat, clon) = nearest(float(lat), float(lon))
    d = km(float(lat), float(lon), clat, clon)
    print(f"\nthat point is")
    print(f"    {d:.1f} km from {city}, {city} city centre")
    print(f"    inside the box {float(lat)-0.05:.2f}..{float(lat)+0.05:.2f} N, "
          f"{float(lon)-0.05:.2f}..{float(lon)+0.05:.2f} E if it were a building")

    # the local evidence that can contradict it
    tz = local_timezone()
    print(f"\nlocal evidence (no network call is made by this script)")
    print(f"    /etc/timezone or timedatectl : {tz or 'could not be read'}")

    if tz in TZ_CITY:
        want = TZ_CITY[tz]
        wlat, wlon = CITIES[want]
        off = km(float(lat), float(lon), wlat, wlon)
        print(f"    that zone's usual city       : {want} "
              f"({wlat}, {wlon})")
        print(f"    anchor is {off:.0f} km from it")
        if off > 400:
            problems.append(
                f"the anchor is {off:.0f} km from {want}, the city this "
                f"machine's own timezone is set for ({tz}). For an anchor "
                f"whose config comment says 'a rough city is the right "
                f"precision', that is the wrong city.")
            print("    -> CONTRADICTION: this is a different city, not a rough "
                  "version of the right one")
        else:
            print("    -> consistent: same metropolitan area, which is the "
                  "precision the config asks for")
    else:
        print(f"    no city is mapped for timezone {tz!r}, so the anchor")
        print("    cannot be corroborated or contradicted from this host.")

    # the label, which is prose and can be judged on its own
    print(f"\nthe label, which is what the centre pin says")
    if not label:
        print("    empty. The route falls back to 'Local network'.")
    else:
        print(f"    {label!r}")
    if label and re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", str(label)):
        print("    -> it contains an IP address. The pin already lists the")
        print("       local addresses it observed, so the address in the label")
        print("       is a second copy that nothing keeps in step.")
        problems.append("home_label embeds an IP address")
    if label and re.match(r"^[A-Za-z0-9_\- ]+$", str(label)) and \
            not re.search(r"[,|]", str(label)):
        print("    -> it names a MACHINE, not a place. The setting's own")
        print("       description is 'What the centre pin is called on the")
        print("       map', and the pin sits at a city coordinate, so a")
        print("       reader asked 'where did this go' reads a hostname.")

    # and what the Windows tree holds, because that is where it came from
    win_cfg = ROOT.parent / "agental_sec" / "config.json"
    if win_cfg.exists():
        try:
            wgeo = (json.loads(win_cfg.read_text(encoding="utf-8"))
                    .get("geoip") or {})
            same = (wgeo.get("home_lat") == lat and wgeo.get("home_lon") == lon)
            print(f"\nthe Windows tree's own config.json")
            print(f"    home_lat {wgeo.get('home_lat')!r}  "
                  f"home_lon {wgeo.get('home_lon')!r}  "
                  f"home_label {wgeo.get('home_label')!r}")
            if same:
                print("    -> IDENTICAL COORDINATES on both machines. Neither")
                print("       install chose these numbers for itself, so")
                print("       'verified for this host' is something neither")
                print("       file can claim.")
                problems.append("the coordinates are copied between trees")
        except Exception as e:
            print(f"    could not read it: {e}")

    print("\n" + "=" * 74)
    if problems:
        print("WHAT THIS CANNOT CLAIM")
        for p in problems:
            print(f"  * {p}")
        print("\nThe anchor is a RENDERING INPUT, not a detection input: no")
        print("finding, severity or colour depends on it. A wrong anchor puts")
        print("the arcs' origin in the wrong city and changes NOTHING else.")
        print("Nothing has been written by this script. Setting the two")
        print("numbers to a real location is the owner's call.")
        return 1
    print("The anchor is consistent with every piece of local evidence.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
