"""
tests/test_ipv6_capture.py, SNF-10: the packet sensor reads IPv6.

Real scapy frames through the shipped functions and the adapter's own capture
callback. Addresses are made up global prefixes and link-local literals; no
machine's own addresses are used.

Run it directly: python tests/test_ipv6_capture.py
"""
import ipaddress
import pathlib
import sys
import threading

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                      # noqa: E402
_isolate_db.isolate()

import adapters                                         # noqa: E402
from core import memory_engine as me                    # noqa: E402
from tools import packet_sniffer_linux as sn            # noqa: E402

from scapy.all import Ether, IP, TCP, UDP                # noqa: E402
from scapy.layers.inet6 import (                         # noqa: E402
    IPv6, IPv6ExtHdrHopByHop, ICMPv6EchoRequest, ICMPv6ND_NS,
    ICMPv6ND_RA, ICMPv6ND_Redirect)

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


# A host on 2602:fe00:1:2::/64 holding one global and one link-local address.
SELF6 = "2602:fe00:1:2::10"
PEER6 = "2602:fe00:1:2::20"
FAR6 = "2606:4700::1111"
LL_ROUTER = "fe80::1"
sn._LOCAL_ADDRESSES = frozenset({"127.0.0.1", "::1", "192.0.2.10", SELF6,
                                 "fe80::10"})
sn._LOCAL_V6_NETS = (ipaddress.ip_network("2602:fe00:1:2::/64"),)
sn._LOCAL_ADDRESSES_AT = 1.0


def wire(pkt):
    return Ether(bytes(pkt))


print("\n[1] an IPv6 frame is a packet row, not None")
d = sn._analyze_packet(wire(Ether() / IPv6(src=SELF6, dst=FAR6)
                            / TCP(sport=40000, dport=443, flags="S")))
check("it is read", d is not None, True)
check("source", d and d["src_ip"], SELF6)
check("destination", d and d["dst_ip"], FAR6)
check("protocol", d and d["protocol"], "tcp")
check("ports", d and (d["src_port"], d["dst_port"]), (40000, 443))
check("to the internet is outbound", d and d["direction"], "outbound")

d = sn._analyze_packet(wire(Ether() / IPv6(src=SELF6, dst=FAR6)
                            / UDP(sport=5353, dport=4433)))
check("udp over v6", d and d["protocol"], "udp")

d = sn._analyze_packet(wire(Ether() / IPv6(src=SELF6, dst=FAR6)
                            / IPv6ExtHdrHopByHop() / ICMPv6EchoRequest()))
check("icmpv6 found past an extension header", d and d["protocol"], "icmpv6")

d = sn._analyze_packet(wire(Ether() / IP(src="192.0.2.10", dst="198.51.100.7")
                            / TCP(sport=1, dport=2)))
check("IPv4 is unchanged", d and d["protocol"], "tcp")

print("\n[2] a LAN peer's global v6 address is local, not the internet")
check("peer in our prefix", sn.classify_scope(SELF6, PEER6), "private_to_private")
check("far address", sn.classify_scope(SELF6, FAR6), "outbound")
check("far to us", sn.classify_scope(FAR6, SELF6), "inbound")
check("neighbour solicitation to a group",
      sn._analyze_packet(wire(Ether() / IPv6(src="fe80::10", dst="ff02::1:ff00:20")
                              / ICMPv6ND_NS(tgt=PEER6)))["direction"], "internal")

print("\n[3] this host's own v6 addresses are recognised")
check("own global", sn.is_self_address(SELF6), True)
check("own link-local with an interface suffix", sn.is_self_address("fe80::10%eth0"), True)
check("a peer is not us", sn.is_self_address(PEER6), False)
check("no detection about our own address", sn.peer_is_a_host(SELF6)[0], False)
check("a far host is a host", sn.peer_is_a_host(FAR6)[0], True)
check("the v6 no-connection case", sn._is_connection_attempt(
    {"protocol": "icmpv6"})[0], False)

print("\n[4] RFC 4861 routing checks")
check("a real RA passes", sn.icmpv6_routing_verdict(LL_ROUTER, 255, 134), None)
check("a global source fails",
      "not a link-local" in (sn.icmpv6_routing_verdict(FAR6, 255, 134) or ""), True)
check("a hop limit under 255 fails",
      "crossed a router" in (sn.icmpv6_routing_verdict(LL_ROUTER, 64, 137) or ""), True)
check("an echo is not a routing message", sn.icmpv6_routing_verdict(FAR6, 64, 128), None)


def fresh_sniffer():
    x = adapters.LinuxPacketSniffer.__new__(adapters.LinuxPacketSniffer)
    x.session_id = "v6test"
    x._capturing = False
    x._packets_seen = 0
    x._unregistered_counts = {}
    x._started_reason = "test"
    x._cooldowns = {}
    x._lock = threading.Lock()
    x._tls_pending = {}
    x._tls_abandoned = 0
    x._tls_reassembled_this_run = 0
    x._vpn_cache = (0.0, "unknown")
    x._payload = None
    x._lan = None
    return x


saved_packets, saved_findings = [], []
me.save_packet = lambda **kw: saved_packets.append(kw)
me.save_finding = lambda **kw: saved_findings.append(kw)

print("\n[5] through the adapter's own capture callback")
a = fresh_sniffer()
a._on_packet(wire(Ether() / IPv6(src=SELF6, dst=FAR6)
                  / TCP(sport=40001, dport=443, flags="S")))
check("a v6 packet row is written", len(saved_packets), 1)
check("with its v6 source", saved_packets and saved_packets[0]["src_ip"], SELF6)

a._on_packet(wire(Ether() / IPv6(src=LL_ROUTER, dst="ff02::1", hlim=255)
                  / ICMPv6ND_RA()))
check("a proper RA raises nothing", [f["detection_id"] for f in saved_findings], [])

a._on_packet(wire(Ether() / IPv6(src=FAR6, dst="ff02::1", hlim=255)
                  / ICMPv6ND_RA()))
check("an RA from a global source raises PKT-1016",
      [f["detection_id"] for f in saved_findings], ["PKT-1016"])
check("about that source", saved_findings and saved_findings[-1]["entity_value"], FAR6)

a._on_packet(wire(Ether() / IPv6(src=LL_ROUTER, dst="fe80::10", hlim=64)
                  / ICMPv6ND_Redirect(tgt="fe80::9", dst=FAR6)))
check("a redirect that crossed a router raises PKT-1016",
      [f["detection_id"] for f in saved_findings], ["PKT-1016", "PKT-1016"])

print("\n" + "=" * 62)
if fails:
    print(f"{len(fails)} FAILED: " + ", ".join(fails))
    sys.exit(1)
print("ALL CHECKS PASSED")
