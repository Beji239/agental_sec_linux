"""
scripts/update_oui.py, fetch the hardware address registry.

    python scripts/update_oui.py                 # try every source in order
    python scripts/update_oui.py --status        # what is on disk, fetch nothing
    python scripts/update_oui.py --force         # fetch again even if recent
    python scripts/update_oui.py --from-file X   # install a file you downloaded

Downloads into `data/`, which is gitignored. The files are a few MB and they
belong to whoever publishes them, so the repo ships this script rather than
the data.

This is the ONLY part of the vendor lookup that touches the network.
core/oui.py never does, so a device listing cannot hang on a web request and
no hardware address from this network ever leaves the machine.

2026-09-02, AND THIS IS WHY THERE ARE THREE SOURCES. The first real run
against IEEE came back **HTTP 418** on all three files. 418 is what a bot
filter returns when it does not want to say 403, and it is almost always
about the user agent: python's default announces itself as python-requests
and gets filtered. So this now sends a browser user agent, and if IEEE still
refuses it falls through to Wireshark's `manuf`, which carries the same
registrations in one file.

If every source is blocked, `--from-file` is the way out. Download the file
in a browser, which will not be filtered, and point this at it. No shame in
it, and it beats a lookup that reports no_data forever.
"""

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
DATA_DIR = ROOT / "data"

# Announcing python-requests is what gets a 418 or a 403 out of a lot of
# standards sites. This is not evasion, the files are public downloads; it is
# saying "a person's browser" to a filter that only knows how to say no to
# scripts.
#
# THE STRING IS A LINUX BROWSER ON THIS TREE, 2026-09-21. It was the Windows
# one, carried over in the port without being looked at: a Linux host asking
# for a registry file while claiming to be Windows NT 10.0 is a string that
# does not describe anything on the machine it runs on, and the header exists
# precisely so the request looks like an ordinary browser. Checked rather than
# assumed before changing it, on this host, all three IEEE URLs: HTTP 200,
# 3,843,595 bytes for oui.csv, so this filter does not care which desktop it
# is told about. Measured twice with an interval, because a single 200 could
# have been a cached answer.
HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/124.0 Safari/537.36"),
    "Accept": "text/csv,text/plain,*/*",
}

# Tried in order. IEEE first because it is the registry itself; the Wireshark
# file is derived from it and is the fallback.
#
# Each entry: (filename in data/, url, kind). `kind` picks the sanity check,
# because the two formats look nothing alike and writing one over the other
# would load as an empty table.
PRIMARY = (
    ("oui.csv", "https://standards-oui.ieee.org/oui/oui.csv", "csv"),
    ("mam.csv", "https://standards-oui.ieee.org/oui28/mam.csv", "csv"),
    # IEEE does NOT name this one mas.csv, which cost a 404 on the first real
    # run. The MA-S directory is oui36 and so is the file inside it.
    ("mas.csv", "https://standards-oui.ieee.org/oui36/oui36.csv", "csv"),
)

# Only tried when the primary sources came back with nothing usable. Fetching
# it anyway was noise: the first successful run pulled IEEE fine and then
# printed a REFUSED line for a file it did not need, which reads like a
# failure and is not one.
FALLBACK = (
    ("manuf", "https://www.wireshark.org/download/automated/data/manuf",
     "manuf"),
)

SOURCES = PRIMARY + FALLBACK

STALE_AFTER_DAYS = 90


def _age_days(path: Path) -> float:
    return (time.time() - path.stat().st_mtime) / 86400


def _first_real_lines(body: bytes, how_many: int = 40) -> list[str]:
    """
    The first lines that are not comments or blank.

    Written after a real manuf file was REFUSED on 2026-09-02. The check only
    looked at the first 400 bytes, and a manuf file opens with a paragraph of
    `#` comments explaining which TShark build generated it, so the tab
    separated rows had not started yet. Sniffing a format from the first few
    bytes only works for formats that start immediately.
    """
    text = body[:20_000].decode("utf-8", errors="replace")
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        out.append(line)
        if len(out) >= how_many:
            break
    return out


def _looks_like_manuf(body: bytes) -> bool:
    """Tab separated rows whose first field is a hex prefix."""
    for line in _first_real_lines(body):
        if "\t" not in line:
            continue
        prefix = line.split("\t", 1)[0].strip().split("/")[0]
        chars = set(prefix.upper()) - set(":-.")
        if chars and chars <= set("0123456789ABCDEF"):
            return True
    return False


def looks_right(kind: str, body: bytes) -> str | None:
    """
    None if the body is the file we asked for, else why it is not.

    A captive portal, a proxy notice or a WAF challenge is still an HTTP 200
    with HTML in it on plenty of networks. Writing one of those over a good
    registry would break every lookup silently, which is worse than the
    download failing out loud.
    """
    head = body[:400].decode("utf-8", errors="replace")

    if head.lstrip()[:1] == "<":
        first = head.strip().splitlines()[0][:80] if head.strip() else ""
        return f"that is HTML, not the registry. First line: {first!r}"

    if kind == "csv":
        if "Assignment" not in head or "Organization Name" not in head:
            return "no IEEE CSV header in it"
    elif kind == "manuf":
        if not _looks_like_manuf(body):
            return "no tab separated prefix rows in it"

    if len(body) < 10_000:
        return f"only {len(body)} bytes, too small to be the real file"

    return None


MAX_REGISTRY_BYTES = 32_000_000


def install(name: str, body: bytes, kind: str) -> str:
    problem = looks_right(kind, body)
    if problem:
        return f"{name}: REFUSED, {problem}"

    DATA_DIR.mkdir(exist_ok=True)
    path = DATA_DIR / name
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(body)
    tmp.replace(path)
    return f"{name}: {len(body) / 1e6:.1f} MB written"


def fetch(name: str, url: str, kind: str, force: bool) -> tuple[str, bool]:
    """Returns (message, got_something_usable)."""
    path = DATA_DIR / name

    if path.exists() and not force:
        age = _age_days(path)
        if age < STALE_AFTER_DAYS:
            return f"{name}: fresh enough, {age:.0f} days old, skipped", True

    try:
        import requests
    except ImportError:
        return f"{name}: requests is not installed, cannot fetch", False

    try:
        resp = requests.get(url, timeout=60, headers=HEADERS, stream=True)
        resp.raise_for_status()
        # The largest registry is about 4 MB; a body past the cap is refused
        # before it is all in memory.
        chunks, total = [], 0
        for chunk in resp.iter_content(64 * 1024):
            total += len(chunk)
            if total > MAX_REGISTRY_BYTES:
                resp.close()
                return (f"{name}: REFUSED, larger than "
                        f"{MAX_REGISTRY_BYTES // 1_000_000} MB"), False
            chunks.append(chunk)
        body = b"".join(chunks)
    except Exception as e:
        hint = ""
        text = str(e)
        if "418" in text or "403" in text or "429" in text:
            hint = ("  (the site refused the request rather than failed. "
                    "Usually a bot filter. Try --from-file, see below)")
        return f"{name}: FAILED, {e}{hint}", False

    return install(name, body, kind), True


def show_status() -> bool:
    """
    Print what is on disk. RETURNS whether the registry is complete.

    The return value is the whole point of this function now, not a
    decoration: main() uses it for the exit code. It used to print the state
    and return nothing, which is how a run that left no 36 bit registry on
    disk still exited 0.
    """
    print(f"data directory   {DATA_DIR}")
    if not DATA_DIR.exists():
        print("  not created yet, nothing has been fetched")
    else:
        for name, _, _ in SOURCES:
            path = DATA_DIR / name
            if path.exists():
                age = _age_days(path)
                print(f"  {name:<10} {path.stat().st_size / 1e6:>6.1f} MB   "
                      f"{age:.0f} days old"
                      + ("   OVERDUE, a run without --force would fetch it"
                         if age >= STALE_AFTER_DAYS else ""))
            else:
                print(f"  {name:<10} missing")

    try:
        from core import oui
        oui.reload()
        st = oui.status()
        print(f"\nlookup ready: {st['ready']}, "
              f"{st['prefixes']:,} prefixes loaded")
        # A COMPLETE REGISTRY IS NOT A CURRENT ONE, added 2026-09-27. The
        # re-fetch clock is STALE_AFTER_DAYS (90) and no path anywhere warns
        # as that approaches: MEASURED on this host, every file was 5 days old
        # and nothing said when it would next look, so "ready: True" read as
        # "and up to date". The age is a fact this script prints rather than
        # acts on -- an update nobody asked for is not this script's decision.
        oldest = st.get("oldest_days")
        if oldest is not None:
            print(f"registry age: {oldest:.0f} days old (oldest file). A run "
                  f"without --force re-fetches at {STALE_AFTER_DAYS} days.")
        # THREE STATES, KEPT APART. `ready` is measured per prefix length, so
        # a partial registry is not ready and neither is an empty one, and
        # they are not the same problem. Measured 2026-09-21: oui.csv and
        # mam.csv on disk, mas.csv absent, and the old line said "lookup
        # ready: True, 46,804 prefixes loaded" with no mention of the gap.
        if not st["loaded_lengths"]:
            print("Until this says ready, every vendor comes back no_data,")
            print("which is correct and useless. See the notes at the top of")
            print("this file for how to get the data by hand.")
        elif st.get("missing"):
            print(f"\nPARTIAL: {', '.join(st['missing'])} did not arrive, so "
                  f"prefixes finer than 24 bit")
            print("are being answered from their shorter parent. On the "
                  "shipped data that parent")
            print("is usually the registering authority, not the maker. "
                  "Re-run this script, or")
            print("install the file by hand with --from-file.")
        return bool(st["ready"])
    except Exception as e:
        print(f"\ncould not load the lookup: {e}")
        return False


def from_file(raw: str) -> int:
    """
    Install a file the user downloaded themselves.

    The escape hatch for when every source is behind a bot filter. A browser
    is not filtered, so downloading it by hand always works, and this puts it
    where core/oui.py looks with the same sanity checks the fetch path uses.
    """
    src = Path(raw).expanduser()
    if not src.exists():
        print(f"No file at {src}")
        return 1

    body = src.read_bytes()

    # Work out which of ours it is from the content, not the filename the
    # browser happened to save it under.
    head = body[:400].decode("utf-8", errors="replace")
    if "Assignment" in head and "Organization Name" in head:
        name, kind = "oui.csv", "csv"
        if "MA-M" in head:
            name = "mam.csv"
        elif "MA-S" in head:
            name = "mas.csv"
    elif _looks_like_manuf(body):
        name, kind = "manuf", "manuf"
    else:
        print("That does not look like an IEEE CSV or a Wireshark manuf file.")
        print(f"First line: {head.strip().splitlines()[0][:80]!r}"
              if head.strip() else "The file is empty.")
        return 1

    print(f"  {install(name, body, kind)}")
    print()
    show_status()
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true",
                    help="fetch again even if the file is recent")
    ap.add_argument("--status", action="store_true",
                    help="show what is on disk and stop")
    ap.add_argument("--from-file",
                    help="install a registry file you downloaded by hand")
    args = ap.parse_args()

    if args.status:
        return 0 if show_status() else 1

    if args.from_file:
        return from_file(args.from_file)

    any_ok = False
    for name, url, kind in PRIMARY:
        message, ok = fetch(name, url, kind, args.force)
        print(f"  {message}")
        any_ok = any_ok or ok

    # The fallback only exists for the case where IEEE will not talk to us.
    # Pulling it when the registry is already in hand just prints a scary
    # looking line about a file nothing needs.
    #
    # 2026-09-21: IT NOW ALSO RUNS WHEN A PRIMARY TIER FAILED, and that is a
    # real gap this script had. Measured on this host: IEEE answered oui.csv
    # and mam.csv and dropped the connection on mas.csv. any_ok was already
    # True from the first file, so the fallback was skipped, the run exited 0,
    # and the tree was left with no 36 bit registry at all. Wireshark's manuf
    # carries all three lengths in one file (measured on the real download:
    # 39,960 /24 rows, 6,593 /28, 11,768 /36), so it covers the missing tier,
    # and core/oui.py fills in from it without overwriting the IEEE files.
    partial = [name for name, _, _ in PRIMARY if not (DATA_DIR / name).exists()]
    if not any_ok or partial:
        why = ("IEEE gave us nothing" if not any_ok
               else f"{', '.join(partial)} did not arrive")
        print(f"\n  {why}, trying the fallback")
        for name, url, kind in FALLBACK:
            message, ok = fetch(name, url, kind, args.force)
            print(f"  {message}")
            any_ok = any_ok or ok

    print()
    ready = show_status()

    # THE EXIT CODE IS THE ANSWER. It used to be decided by `any_ok`, which is
    # true as soon as ONE file lands, so a half registry exited 0 and anything
    # reading the code was told the job was done.
    if not ready:
        print("\nThe registry is not complete. Every 28 and 36 bit address "
              "is being")
        print("answered from its 24 bit parent until this is fixed.")
        if not any_ok:
            print("\nNothing was fetched. Every source refused or failed.")
            print("Download one of these in a browser and install it by hand:")
            for name, url, _ in SOURCES:
                print(f"    {url}")
            print("\n    python3 scripts/update_oui.py --from-file "
                  "~/Downloads/oui.csv")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
