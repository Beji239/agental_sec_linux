"""
tests/test_ip_defrag.py, fragmented datagrams are put back together (SNF-11).

No socket and no privilege: fragments are built with scapy and pushed
through the reassembler the capture thread uses.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


from scapy.all import IP, UDP, Ether, Raw, fragment          # noqa: E402
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, fragment6  # noqa: E402
from tools.ip_defrag import Defragmenter                     # noqa: E402
from tools import ip_defrag                                  # noqa: E402

PAYLOAD = bytes(range(256)) * 12


def v4_frags(payload=PAYLOAD, ident=77, size=1000):
    p = IP(src="192.0.2.1", dst="198.51.100.2", id=ident) / \
        UDP(sport=40001, dport=4000) / Raw(payload)
    return [Ether(bytes(Ether() / f)) for f in fragment(p, fragsize=size)]


print("[1] IPv4, in order and out of order")
for name, order in (("in order", lambda x: x), ("reversed", lambda x: x[::-1])):
    d, out = Defragmenter(), []
    for f in order(v4_frags()):
        out += d.push(f)
    check(f"{name}: one datagram comes out", len(out), 1)
    check(f"{name}: its UDP header is read", out[0][UDP].dport, 4000)
    check(f"{name}: the payload is whole", bytes(out[0][Raw].load) == PAYLOAD, True)

print("[2] a short last fragment carries Ethernet padding, which is not data")
frags = v4_frags(PAYLOAD[:1000], size=1000)
# The wire pads a frame to 60 bytes; scapy's build does not, so pad by hand.
frags[-1] = Ether(bytes(frags[-1]) + b"\x00" * (60 - len(bytes(frags[-1]))))
check("the last frame is padded to 60", len(bytes(frags[-1])), 60)
d, out = Defragmenter(), []
for f in frags:
    out += d.push(f)
check("padding is not in the payload", bytes(out[0][Raw].load), PAYLOAD[:1000])

print("[3] IPv6")
p6 = IPv6(src="2001:db8::1", dst="2001:db8::2") / IPv6ExtHdrFragment() / \
    UDP(sport=53, dport=5000) / Raw(PAYLOAD)
d, out = Defragmenter(), []
for f in fragment6(p6, 1280):
    out += d.push(Ether(bytes(Ether() / f)))
check("one datagram", len(out), 1)
check("UDP read and payload whole",
      (out[0][UDP].sport, bytes(out[0][Raw].load) == PAYLOAD), (53, True))

print("[4] a packet that is not a fragment passes straight through")
plain = Ether() / IP() / UDP()
check("same object, at once", Defragmenter().push(plain), [plain])

print("[5] overlapping fragments that disagree are not stitched")
frags = v4_frags()
bad = frags[1].copy()
bad[Raw].load = b"X" * len(bad[Raw].load)
bad = Ether(bytes(bad))
d, out = Defragmenter(), []
for f in [frags[0], frags[1], bad]:
    out += d.push(f)
check("the held frames come out as they were", len(out), 3)
check("and it is counted", d.stats["overlapping"], 1)

print("[6] an incomplete datagram is handed on after the timeout")
now = [0.0]
d = Defragmenter(timeout=30, clock=lambda: now[0])
check("held while incomplete", d.push(v4_frags()[0]), [])
now[0] = 31.0
out = d.push(plain)
check("the held frame and the new packet both come out", len(out), 2)
check("counted as expired", d.stats["expired"], 1)

print("[7] memory stays bounded")
ip_defrag.MAX_PENDING, saved = 4, ip_defrag.MAX_PENDING
d, out = Defragmenter(), []
for i in range(10):
    out += d.push(v4_frags(ident=1000 + i)[0])
check("never more than the cap pending", len(d._pending), 4)
check("the oldest were handed on", len(out), 6)
ip_defrag.MAX_PENDING = saved

print("[8] both capture paths use it")
src = (ROOT / "tools" / "packet_sniffer_linux.py").read_text(encoding="utf-8")
check("two pushes in the sniffer", src.count(".push(pkt)"), 2)

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
