#!/usr/bin/env python3
"""
scripts/identify_ra_emitter.py, who is sending the router advertisements.

The packets table stores IP addresses, and the whole problem with these
particular packets is that their IP source header cannot be trusted. The
Ethernet source MAC can be: it is written by the sending NIC and it is not
routed, so whatever it says is a device on this segment.

This listens for ICMP router advertisements and prints, for each one, the
sending MAC, the IP source header, and the router address the body actually
advertises. When the last two disagree, the MAC is the only field left that
identifies the sender.

Needs scapy and Administrator. Captures only, writes nothing, touches no
database. Ctrl-C to stop early.

Usage:
    python scripts/identify_ra_emitter.py [--seconds 120] [--iface NAME]
    python scripts/identify_ra_emitter.py --list-interfaces
"""
import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    from scapy.all import sniff, get_if_list, conf, send, Ether, IP, ICMP
except ImportError:
    print("scapy is not installed in this interpreter.")
    sys.exit(2)

import threading
import time

# REPOINTED 2026-09-21. This used to import from tools.packet_sniffer, the
# stale Windows copy, which was the ONLY live consumer of that file in the
# tree. The owner's rule took the file out, and both names it needed are now
# where they belong: the RFC 1256 parser is here, in the capture path that
# actually sees the frames (adapters._ra_addresses, ported with the two
# registered routing-ICMP rules), and the private-address test is the live
# Linux module's own.
from adapters import _ra_addresses as router_advertisement_addresses
from tools.packet_sniffer_linux import _is_private


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=120)
    ap.add_argument("--iface", default=None)
    ap.add_argument("--list-interfaces", action="store_true")
    ap.add_argument("--solicit", action="store_true",
                    help="ASK for an advertisement instead of waiting for one. "
                         "SENDS packets: ICMP router solicitations to 224.0.0.2. "
                         "See the note below before using it.")
    args = ap.parse_args()

    if args.list_interfaces:
        print("\nInterfaces scapy can see:\n")
        for name in get_if_list():
            print(f"  {name}")
        print("\nWhich one is being captured matters: a VirtualBox host-only")
        print("adapter or a VPN tunnel is its own segment, and an advertisement")
        print("seen there says nothing about the physical LAN.")
        print(f"\nDefault scapy would use: {conf.iface}\n")
        return 0

    seen = {}

    def handle(pkt):
        if not (pkt.haslayer(ICMP) and pkt.haslayer(IP)):
            return
        if int(pkt[ICMP].type) != 9:
            return
        mac = pkt[Ether].src if pkt.haslayer(Ether) else "(no ethernet layer)"
        src = pkt[IP].src
        try:
            adv = router_advertisement_addresses(bytes(pkt[ICMP]))
        except Exception:
            adv = []
        key = (mac, src, tuple(adv))
        seen[key] = seen.get(key, 0) + 1
        if seen[key] == 1:
            print(f"\n  MAC        {mac}")
            print(f"  IP source  {src}"
                  f"{'  (not on this network)' if not _is_private(src) else ''}")
            print(f"  advertises {', '.join(adv) if adv else '(body did not parse)'}")
            if adv and ".".join(reversed(src.split("."))) in adv:
                print("  -> the source header is the octet-reverse of the body."
                      " The sender's stack wrote it wrong.")
        else:
            print(f"  ... same again ({seen[key]})", end="\r")

    print(f"\nListening {args.seconds}s for ICMP router advertisements"
          f"{' on ' + args.iface if args.iface else ''}.")
    if not args.solicit:
        print("RFC 1256 suggests every 7 to 10 minutes, but what matters is")
        print("how often YOUR emitter actually sends. Get that from the data")
        print("you already have rather than guessing:")
        print("    python scripts/diagnose_offlink_icmp.py --timeline")
        print("If the median gap there is hours, a passive capture has to run")
        print("for hours, or use --solicit to ask for one directly.\n")

    stop = threading.Event()

    def solicit_loop():
        # RFC 1256 section 3.1: a host may send a router solicitation to
        # 224.0.0.2, and a router that hears it answers with an advertisement
        # within a few seconds rather than waiting for its timer. This is
        # ordinary host behaviour, Windows sends these at interface-up,
        # and it is the difference between a five-minute capture and a
        # six-hour one.
        #
        # It does TRANSMIT, which nothing else in this repository's diagnostic
        # path does, which is why it is behind a flag and not the default.
        # TTL 1: solicitations are link-local and must not be forwarded.
        pkt = IP(dst="224.0.0.2", ttl=1) / ICMP(type=10, code=0)
        for _ in range(max(1, args.seconds // 30)):
            if stop.is_set():
                return
            try:
                send(pkt, verbose=0, **({"iface": args.iface} if args.iface else {}))
                print("  [solicitation sent]")
            except Exception as e:
                print(f"  [could not send solicitation: {e}]")
                return
            stop.wait(30)

    if args.solicit:
        print("--solicit: this SENDS ICMP router solicitations to 224.0.0.2,")
        print("one every 30s. Standard host behaviour, but it is traffic you")
        print("are putting on the wire, and it will appear in your own")
        print("capture. Ctrl-C now if that is not what you want.\n")
        time.sleep(3)
        threading.Thread(target=solicit_loop, daemon=True).start()

    kw = {"prn": handle, "store": False, "timeout": args.seconds,
          "filter": "icmp"}
    if args.iface:
        kw["iface"] = args.iface
    try:
        sniff(**kw)
    except PermissionError:
        print("Permission denied. Run this from an Administrator prompt.")
        return 2
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()

    print("\n" + "=" * 60)
    if not seen:
        print("No router advertisements in that window. Try a longer --seconds,")
        print("or --list-interfaces to check the right adapter is being watched.")
        return 0

    print(f"\n{len(seen)} distinct (MAC, source, advertised) combination(s):\n")
    for (mac, src, adv), n in sorted(seen.items(), key=lambda kv: -kv[1]):
        print(f"  {n:>4}x  {mac}  src={src}  advertises={','.join(adv) or '?'}")

    print("""
Next: look up the MAC's first three octets (the OUI) to get the vendor, and
match the MAC against the device inventory. If it belongs to the router,
this is a firmware bug in its advertisement code and nothing more. If it
belongs to a virtual adapter, VirtualBox, a VPN tunnel, Hyper-V, then
the advertisement is coming from software on this machine and the segment
it is really on matters. If it belongs to something you do not recognise,
that is the case worth taking seriously, and it is the only one of the
three that the original finding would have gotten right by accident.
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
