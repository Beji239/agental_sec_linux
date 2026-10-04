#!/usr/bin/env python3
"""
scripts/whose_mac.py, match a hardware address against what is already known.

The last step of an investigation is usually not a new capture. It is asking
whether the thing just observed is already sitting in a table under a name
somebody gave it months ago.

Read-only. Opens the database with mode=ro.

Usage:
    python scripts/whose_mac.py 00:11:22:33:44:55
    python scripts/whose_mac.py 00:11:22:33:44:55 --db PATH
"""
import argparse
import pathlib
import sqlite3
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def norm(mac: str) -> str:
    """Lowercase, separators stripped, so 00-11-22 and 00:11:22 compare equal."""
    return "".join(c for c in (mac or "").lower() if c in "0123456789abcdef")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mac")
    ap.add_argument("--db", default=str(ROOT / "agental_sec.db"))
    args = ap.parse_args()

    db = pathlib.Path(args.db)
    if not db.exists():
        print(f"No database at {db}")
        return 2

    want = norm(args.mac)
    if len(want) != 12:
        print(f"{args.mac!r} is not a 48-bit hardware address.")
        return 2
    oui = want[:6]

    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    cols = {r["name"] for r in conn.execute("PRAGMA table_info(known_devices)")}
    exact, same_vendor = [], []
    for row in conn.execute("SELECT * FROM known_devices"):
        m = norm(row["mac"] if "mac" in cols else "")
        if not m:
            continue
        (exact if m == want else same_vendor if m[:6] == oui else []).append(row)

    def show(row):
        name = (row["known_as"] if "known_as" in cols else None) or "(unnamed)"
        bits = [f"ip={row['ip']}", f"name={name}"]
        for extra in ("vendor", "device_type", "identified_by", "is_permanent",
                      "first_seen", "last_seen"):
            if extra in cols and row[extra] not in (None, ""):
                bits.append(f"{extra}={row[extra]}")
        print("    " + "  ".join(str(b) for b in bits))

    print(f"\nLooking for {args.mac}  (vendor prefix {oui[:2]}:{oui[2:4]}:{oui[4:6]})")

    if exact:
        print(f"\nEXACT MATCH, this address is already in the inventory:")
        for r in exact:
            show(r)
    else:
        print("\nNo exact match in known_devices.")
        print("That does not make it unknown: the inventory is keyed on what")
        print("answered a scan, and a device can be present without ever having")
        print("been enrolled. Check the vendor prefix below before concluding")
        print("anything, and re-run a scan if the list looks stale.")

    if same_vendor:
        print(f"\nSame vendor prefix, different device ({len(same_vendor)}):")
        for r in same_vendor[:10]:
            show(r)

    # The ARP/neighbour view, if this build records one.
    for table, col in (("arp_cache", "mac"), ("network_devices", "mac"),
                       ("presence_observation", "mac")):
        try:
            rows = [r for r in conn.execute(f"SELECT * FROM {table}")
                    if norm(dict(r).get(col, "")) == want]
        except sqlite3.Error:
            continue
        if rows:
            print(f"\nAlso seen in {table} ({len(rows)} row(s)):")
            for r in rows[:5]:
                print("    " + "  ".join(f"{k}={v}" for k, v in dict(r).items()
                                         if v not in (None, "")))

    print("""
The vendor prefix is assigned by the IEEE and is public. Look it up if the
name above does not settle it. What matters for the router-advertisement
question is only this: does this address belong to the gateway, to a
virtual adapter on this machine, or to something you did not put here.
""")
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
