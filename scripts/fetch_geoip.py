#!/usr/bin/env python3
"""
Download the free IP-to-City geolocation database for the threat map.

    python scripts/fetch_geoip.py
    python scripts/fetch_geoip.py --asn    the network owner database too

No account, no API key, no pricing page. This pulls DB-IP's free Lite files
straight from download.db-ip.com: this month's, or last month's early in a
month. They cover IPv4 and IPv6 in one file. The ip-location-db mirror on
npm and its CDNs is kept as a last resort; it stopped updating in June 2026
and carries IPv4 only.

Why not db-ip.com directly: their download page sells an *API subscription*
alongside the free database, and the two are easy to confuse. The data is
identical; this route just has no upsell in the way.

Licence: CC-BY 4.0. Attribution is already rendered under the threat map.
    https://db-ip.com  ,  "IP Geolocation by DB-IP"
"""

import gzip
import io
import json
import time
import shutil
import sys
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEST = PROJECT_ROOT / "geoip" / "dbip-city-lite.mmdb"

PKG = "@ip-location-db/dbip-city-mmdb"
MEMBER = "dbip-city-ipv4.mmdb"

# Direct CDN copies first, one request, no unpacking. Some corporate
# proxies block these, so the npm registry tarball is the fallback; if npm
# itself works on this machine, so does that route.
DIRECT = [
    f"https://cdn.jsdelivr.net/npm/{PKG}/{MEMBER}",
    f"https://unpkg.com/{PKG}/{MEMBER}",
]

UA = {"User-Agent": "AgentalSec-geoip-fetch"}
MIN_BYTES = 5_000_000          # a real city DB is tens of MB; anything less is an error page


def _dbip_urls(kind: str) -> list:
    """This month's and last month's DB-IP Lite file for city or asn."""
    now = time.gmtime()
    months = [(now.tm_year, now.tm_mon)]
    months.append((now.tm_year, now.tm_mon - 1) if now.tm_mon > 1
                  else (now.tm_year - 1, 12))
    return [f"https://download.db-ip.com/free/dbip-{kind}-lite-{y}-{m:02d}"
            f".mmdb.gz" for y, m in months]


def _download_gz(url: str, out: Path, min_bytes: int) -> bool:
    """A .mmdb.gz from DB-IP: fetched whole first, then unpacked from disk,
    which is many times faster than unpacking off the socket."""
    packed = out.with_suffix(out.suffix + ".gz.part")
    tmp = out.with_suffix(out.suffix + ".part")
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=300) as resp, \
                open(packed, "wb") as f:
            shutil.copyfileobj(resp, f, 1 << 20)
        with gzip.open(packed, "rb") as gz, open(tmp, "wb") as f:
            shutil.copyfileobj(gz, f, 1 << 20)
        got = tmp.stat().st_size
        print(f"    {_human(packed.stat().st_size)} fetched, "
              f"{_human(got)} unpacked")
        if got < min_bytes:
            print(f"    only {_human(got)}, discarding")
            return False
        tmp.replace(out)
        return True
    except (urllib.error.URLError, urllib.error.HTTPError, OSError,
            EOFError) as e:
        print(f"    {e}")
        return False
    finally:
        packed.unlink(missing_ok=True)
        tmp.unlink(missing_ok=True)


def _from_dbip(kind: str, out: Path, min_bytes: int) -> bool:
    for url in _dbip_urls(kind):
        print(f"Trying {url.rsplit('/', 1)[-1]} from download.db-ip.com ...")
        if _download_gz(url, out, min_bytes):
            return True
    return False


def _place(rec) -> str:
    """A city from either record shape, for the verify line."""
    if not rec:
        return "no record"
    city = rec.get("city")
    if isinstance(city, dict):
        city = (city.get("names") or {}).get("en")
    return city or "a record with no city"


def _human(n: int) -> str:
    return f"{n / (1024 * 1024):.0f} MB"


def _download(url: str, out: Path) -> bool:
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=120) as resp:
            total = int(resp.headers.get("Content-Length") or 0)
            if total and total < MIN_BYTES:
                print(f"    too small ({_human(total)}), not a database")
                return False

            tmp = out.with_suffix(out.suffix + ".part")
            got = 0
            with open(tmp, "wb") as f:
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    f.write(chunk)
                    got += len(chunk)
                    if total:
                        pct = got * 100 // total
                        print(f"\r    {pct:3d}%  {_human(got)} / {_human(total)}", end="", flush=True)
            print()

            if got < MIN_BYTES:
                tmp.unlink(missing_ok=True)
                print(f"    only got {_human(got)}, discarding")
                return False

            tmp.replace(out)
            return True
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        print(f"    {e}")
        return False


def _via_npm_tarball(out: Path) -> bool:
    """Resolve the package on the registry and pull the .mmdb from its tarball."""
    try:
        meta_url = f"https://registry.npmjs.org/{PKG.replace('/', '%2f')}/latest"
        with urllib.request.urlopen(urllib.request.Request(meta_url, headers=UA), timeout=60) as r:
            meta = json.load(r)
        tarball = meta["dist"]["tarball"]
        print(f"    {meta.get('version','?')} -> {tarball}")

        with urllib.request.urlopen(urllib.request.Request(tarball, headers=UA), timeout=300) as r:
            blob = io.BytesIO(r.read())

        with tarfile.open(fileobj=blob, mode="r:gz") as tf:
            member = next((m for m in tf.getmembers() if m.name.endswith(MEMBER)), None)
            if not member:
                print(f"    {MEMBER} not found in tarball")
                return False
            src = tf.extractfile(member)
            if src is None:
                return False
            tmp = out.with_suffix(out.suffix + ".part")
            with open(tmp, "wb") as f:
                shutil.copyfileobj(src, f)
            tmp.replace(out)
            return True
    except Exception as e:
        print(f"    {e}")
        return False


ASN_DEST = PROJECT_ROOT / "geoip" / "dbip-asn-lite.mmdb"
ASN_URLS = [
    "https://cdn.jsdelivr.net/npm/@ip-location-db/dbip-asn-mmdb/dbip-asn-ipv4.mmdb",
    "https://unpkg.com/@ip-location-db/dbip-asn-mmdb/dbip-asn-ipv4.mmdb",
]
ASN_MIN_BYTES = 1_000_000


def fetch_asn() -> int:
    """The network owner (ASN) database, used by the map and place baselines."""
    global MIN_BYTES
    ASN_DEST.parent.mkdir(parents=True, exist_ok=True)
    MIN_BYTES, saved = ASN_MIN_BYTES, MIN_BYTES
    try:
        ok = _from_dbip("asn", ASN_DEST, ASN_MIN_BYTES)
        for url in ([] if ok else ASN_URLS):
            print(f"Trying {url.split('/')[2]} ...")
            if _download(url, ASN_DEST):
                ok = True
                break
        if not ok:
            print("Could not download the network owner database.")
            print("Manual route: https://db-ip.com/db/download/ip-to-asn-lite")
            print(f"Save the MMDB as: {ASN_DEST}")
            return 1
    finally:
        MIN_BYTES = saved
    try:
        import maxminddb
        with maxminddb.open_database(str(ASN_DEST)) as reader:
            rec = reader.get("8.8.8.8") or {}
        print(f"Verified: 8.8.8.8 -> AS{rec.get('autonomous_system_number')} "
              f"{rec.get('autonomous_system_organization') or ''}")
        print("Restart AgentalSec to use it.")
    except Exception as e:
        print(f"Downloaded but could not be opened: {e}")
        return 1
    return 0


def main() -> int:
    if "--asn" in sys.argv[1:]:
        return fetch_asn()
    DEST.parent.mkdir(parents=True, exist_ok=True)

    if DEST.exists():
        print(f"Already present: {DEST}  ({_human(DEST.stat().st_size)})")
        if input("Re-download? [y/N] ").strip().lower() != "y":
            return 0

    ok = _from_dbip("city", DEST, MIN_BYTES)
    for url in ([] if ok else DIRECT):
        print(f"Trying {url.split('/')[2]} ...")
        if _download(url, DEST):
            ok = True
            break
    if not ok:
        print("CDNs unavailable, falling back to the npm registry ...")
        if not _via_npm_tarball(DEST):
            print("\nCould not download automatically.")
            print("Manual route: https://db-ip.com/db/download/ip-to-city-lite")
            print(f"Save the MMDB as: {DEST}")
            return 1

    size = DEST.stat().st_size
    print(f"\nSaved {DEST} ({_human(size)})")

    try:
        import maxminddb
    except ImportError:
        print("Now run: pip install maxminddb")
        return 0

    # Prove the file parses before declaring success, a truncated download
    # or an HTML error page saved under the right name would otherwise only
    # surface later as an empty map.
    try:
        with maxminddb.open_database(str(DEST)) as reader:
            rec = reader.get("8.8.8.8")
            v6 = reader.get("2001:4860:4860::8888")
            built = time.strftime("%Y-%m-%d",
                                  time.gmtime(reader.metadata().build_epoch))
        print(f"Verified: 8.8.8.8 -> {_place(rec)}; IPv6 "
              f"{'covered' if v6 else 'NOT covered'}; built {built}")
        print("\nRestart AgentalSec and open the Threat Map tab.")
        print("Attribution (already in the UI): IP Geolocation by DB-IP, https://db-ip.com")
    except Exception as e:
        print(f"Downloaded but could not be opened: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
