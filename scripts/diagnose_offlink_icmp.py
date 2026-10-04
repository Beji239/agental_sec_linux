#!/usr/bin/env python3
"""
scripts/diagnose_offlink_icmp.py, evidence for off-link ICMP findings.

WHY THIS EXISTS
A packet whose recorded source is a public address, sending to a link-local
multicast group, is either a real anomaly or a recording error. The two look
identical in a summary and only one of them is worth a human's evening.

This script does not decide. It prints the stored evidence for every such
row and runs three mechanical tests whose answers narrow the question:

  1. Does the row's own raw_summary agree with its src_ip column?
     raw_summary is scapy's rendering of the same packet. If the two
     disagree, something between the capture and the column changed the
     address, and that is a bug in this codebase.

  2. Is the source address the byte-reverse of an address this network
     actually uses? A public source whose octet-reverse is sitting in
     known_devices is not proof of a swap on its own, but it is the single
     cheapest thing to look at, and if it holds for several unrelated
     addresses it stops being a coincidence.

  3. Does the ICMP payload contain an address, and does it agree with the
     source? A router advertisement carries the advertised router address
     in its body. If the body reads correctly while the source does not,
     the two were parsed by different code paths and one of them is wrong.

Every test can come back negative, and a negative result here means the
packets are real and should be investigated as real.

Read-only. Opens the database with mode=ro so it cannot alter anything.

Usage:
    python scripts/diagnose_offlink_icmp.py [--db PATH] [--days N]
"""
import argparse
import ipaddress
import json
import pathlib
import sqlite3
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Scopes that mean "the sender is not on this network". These are the rows
# that turn into findings a human is asked to act on.
OFFLINK_SCOPES = ("foreign_multicast", "public_to_public", "unclassified", "inbound")


def reverse_octets(ip: str) -> str | None:
    """192.0.2.1 -> 1.2.0.192. None if it is not an IPv4 address."""
    try:
        a = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return None
    if a.version != 4:
        return None
    return ".".join(reversed(str(a).split(".")))


def addresses_in_payload(hex_str: str) -> list[str]:
    """
    Every 4-byte window of the payload read as an IPv4 address, both ways.

    Deliberately crude: this is a hint generator, not a parser. A window
    that happens to be four printable bytes will produce a nonsense address
    and that is fine, because the only windows anyone acts on are the ones
    that match something already known.
    """
    out = []
    try:
        raw = bytes.fromhex(hex_str or "")
    except ValueError:
        return out
    for i in range(0, max(0, len(raw) - 3)):
        w = raw[i:i + 4]
        out.append((i, ".".join(str(b) for b in w),
                    ".".join(str(b) for b in reversed(w))))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=str(ROOT / "agental_sec.db"))
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--timeline", action="store_true",
                    help="print every arrival and the gap before it, and stop. "
                         "Answers how long a live capture has to run, and "
                         "whether arrivals cluster.")
    args = ap.parse_args()

    db = pathlib.Path(args.db)
    if not db.exists():
        print(f"No database at {db}")
        return 2

    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    scope_clause = ",".join("?" for _ in OFFLINK_SCOPES)
    rows = conn.execute(
        f"""SELECT id, captured_at, src_ip, dst_ip, protocol, direction, scope,
                   flags, payload_snippet, threat_label, raw_summary
              FROM packets
             WHERE (scope IN ({scope_clause}) OR threat_label LIKE 'icmp_routing%')
               AND protocol = 'ICMP'
               AND captured_at >= datetime('now', ?)
             ORDER BY captured_at DESC""",
        (*OFFLINK_SCOPES, f"-{args.days} days"),
    ).fetchall()

    print(f"\nOff-link ICMP rows in the last {args.days} days: {len(rows)}")
    if not rows:
        print("Nothing to explain. The findings under review did not come from"
              " rows matching this shape, which is itself worth knowing.")
        return 0

    if args.timeline:
        # Written after suggesting a five-minute live capture for packets
        # this table already showed arriving a few times a day. The observed
        # rate was in the data the whole time; the RFC's suggested cadence
        # was quoted instead. Same error as the one this file exists for:
        # a general fact preferred over the specific evidence to hand.
        from datetime import datetime
        per: dict[str, list] = {}
        for r in rows:
            per.setdefault(r["src_ip"], []).append(r["captured_at"])
        for src, stamps in per.items():
            stamps = sorted(stamps)
            print(f"\n{src}  ,  {len(stamps)} arrivals")
            gaps = []
            prev = None
            for s in stamps:
                try:
                    t = datetime.fromisoformat(s)
                except ValueError:
                    print(f"    {s}"); prev = None; continue
                if prev is None:
                    print(f"    {s}")
                else:
                    g = (t - prev).total_seconds()
                    gaps.append(g)
                    print(f"    {s}   +{g/3600:.2f}h")
                prev = t
            if gaps:
                gaps.sort()
                print(f"\n    shortest gap {min(gaps)/60:.1f} min, "
                      f"median {gaps[len(gaps)//2]/3600:.2f}h, "
                      f"longest {max(gaps)/3600:.2f}h")
                print(f"    a live capture wants to run for at least the"
                      f" median, i.e. about {gaps[len(gaps)//2]/3600:.1f} hours,")
                print("    unless an advertisement is actively solicited.")
        # Do two sources arrive together? If they do, they are one emitter,
        # and every question about "two attackers" was the wrong question.
        # Added 2026-08-29 because the pairing was visible in the output but
        # only to a reader who thought to compare two columns by eye.
        if len(per) > 1:
            sets = {s: set(v) for s, v in per.items()}
            names = list(sets)
            print("\nCO-ARRIVAL")
            for i in range(len(names)):
                for j in range(i + 1, len(names)):
                    a, b = names[i], names[j]
                    shared = sets[a] & sets[b]
                    smaller = min(len(sets[a]), len(sets[b]))
                    pct = 100.0 * len(shared) / smaller if smaller else 0.0
                    print(f"  {a} and {b}: {len(shared)} of {smaller} arrivals"
                          f" share a timestamp to the second ({pct:.0f}%)")
                    if pct >= 90:
                        print("    -> these are not two senders. Packets from"
                              " two unrelated hosts do not land in the same")
                        print("       second repeatedly. One device is emitting"
                              " both, once per address it holds.")

        print("""
NOTE ON READING THESE GAPS
The sensor is not running continuously, so these intervals are an upper
bound on how often the packets are sent, not a measurement of it. A cluster
of arrivals close together right after a gap usually means they followed
something, an interface coming up, or a router solicitation, rather
than a timer.
""")
        conn.close()
        return 0

    # what the network already knows about itself
    known = set()
    for t, c in (("known_devices", "ip"), ("packets", "src_ip"), ("packets", "dst_ip")):
        try:
            known |= {r[0] for r in conn.execute(
                f"SELECT DISTINCT {c} FROM {t} WHERE {c} IS NOT NULL") if r[0]}
        except sqlite3.Error:
            pass

    def is_local(ip):
        try:
            a = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return False
        return a.is_private or a.is_loopback or a.is_link_local

    local_known = {ip for ip in known if is_local(ip)}

    # per-source summary
    by_src: dict[str, list] = {}
    for r in rows:
        by_src.setdefault(r["src_ip"], []).append(r)

    print(f"Distinct sources: {len(by_src)}\n" + "=" * 68)

    for src, group in sorted(by_src.items(), key=lambda kv: -len(kv[1])):
        print(f"\nSOURCE {src}   ({len(group)} packets, "
              f"{group[-1]['captured_at']} .. {group[0]['captured_at']})")

        rev = reverse_octets(src)
        if rev:
            verdict = ("IS an address this network uses" if rev in local_known
                       else "is local space but NOT seen on this network" if is_local(rev)
                       else "is not local space either")
            print(f"  test 2  byte-reverse -> {rev}   , {verdict}")
            if rev in local_known:
                seen = conn.execute(
                    "SELECT COUNT(*) FROM packets WHERE src_ip = ?", (rev,)
                ).fetchone()[0]
                print(f"          {rev} appears as a source on {seen} packets"
                      f" in this same table")

        sample = group[0]
        summary = sample["raw_summary"] or ""
        print(f"  test 1  raw_summary: {summary[:110]}")
        if src and summary:
            print(f"          src_ip column {'agrees with' if src in summary else 'DISAGREES with'}"
                  f" scapy's own summary")
            if rev and rev in summary:
                print(f"          !! the summary contains {rev}, not {src}"
                      f", the column was rewritten after capture")

        print(f"  flags:   {sample['flags']}")
        print(f"  scope:   {sample['scope']}   direction: {sample['direction']}")
        print(f"  label:   {sample['threat_label']}")

        pay = sample["payload_snippet"]
        if pay:
            print(f"  test 3  payload {pay[:48]}")
            hits = [(i, fwd, bwd) for (i, fwd, bwd) in addresses_in_payload(pay)
                    if fwd in local_known or bwd in local_known or fwd == src or bwd == src]
            if not hits:
                print("          no window of the payload matches a known address")
            for i, fwd, bwd in hits[:6]:
                tag_f = " <- known here" if fwd in local_known else (" <- the source" if fwd == src else "")
                tag_b = " <- known here" if bwd in local_known else (" <- the source" if bwd == src else "")
                print(f"          byte {i}: forward {fwd}{tag_f} | reversed {bwd}{tag_b}")
        else:
            print("  test 3  no payload stored")

        # Did the correctly-ordered twin also appear, at the same times?
        if rev and rev in local_known:
            same = conn.execute(
                """SELECT COUNT(*) FROM packets
                    WHERE src_ip = ? AND protocol = 'ICMP'
                      AND captured_at >= datetime('now', ?)""",
                (rev, f"-{args.days} days")).fetchone()[0]
            print(f"  extra   ICMP from {rev} in the same window: {same}")
            print("          both present -> two code paths disagree;"
                  " only the reversed one present -> the wire carried it")

    print("\n" + "=" * 68)
    print("""
Reading this:

  If test 1 says the column disagrees with scapy's own summary, this is a
  bug here and the findings are noise. Fix the column, clear the findings.

  If test 1 agrees and test 2 comes back negative, the packets are real.
  A public source on a link-local multicast group is worth investigating
  and the sensor did its job.

  If test 1 agrees and test 2 keeps matching across unrelated sources,
  the reversal happened before this code saw the packet, capture driver,
  adapter, or a tunnel, and that is still a real thing to chase, but it
  is not an attacker.

No conclusion is printed above because the script does not have one.
""")
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
