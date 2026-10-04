# tools/ip_defrag.py
# IP fragment reassembly in front of the capture callback (SNF-11).
#
# Fragments are held until the datagram is whole, then one reassembled packet
# is handed on. A datagram that cannot be completed (timeout, overlap, a cap)
# hands on its frames as they arrived, so nothing is lost against the old
# per-frame behaviour. Every bound is fixed, so a flood of fragments cannot
# grow memory.

import time
from collections import OrderedDict

try:
    from scapy.all import IP, Ether, Raw
    from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
except Exception:                                   # pragma: no cover
    IP = Ether = Raw = IPv6 = IPv6ExtHdrFragment = None

MAX_PENDING = 256              # datagrams being put together at once
MAX_FRAGMENTS = 64             # pieces in one datagram
MAX_DATAGRAM = 65535           # IPv4's own ceiling, used for IPv6 too
MAX_HELD_BYTES = 4 * 1024 * 1024
TIMEOUT = 30.0                 # seconds a datagram may stay incomplete


class Defragmenter:
    def __init__(self, timeout=TIMEOUT, clock=time.monotonic):
        self.timeout = timeout
        self.clock = clock
        self._pending = OrderedDict()   # key -> state, oldest first
        self._held_bytes = 0
        self.stats = {"reassembled": 0, "fragments": 0, "expired": 0,
                      "overlapping": 0, "too_big": 0, "evicted": 0}

    def push(self, pkt) -> list:
        """The packets to hand on now, in order. Usually [pkt]."""
        out = self._expire()
        frag = _fragment_info(pkt)
        if frag is None:
            out.append(pkt)
            return out
        self.stats["fragments"] += 1
        key, offset, more, data = frag

        st = self._pending.get(key)
        if st is None:
            while (len(self._pending) >= MAX_PENDING
                   or self._held_bytes + len(data) > MAX_HELD_BYTES) and self._pending:
                out += self._give_up(next(iter(self._pending)), "evicted")
            st = {"started": self.clock(), "pieces": {}, "frames": [],
                  "total": None, "first": None}
            self._pending[key] = st

        st["frames"].append(pkt)
        self._held_bytes += len(data)
        end = offset + len(data)

        for o, d in st["pieces"].items():
            lo, hi = max(o, offset), min(o + len(d), end)
            if lo < hi and d[lo - o:hi - o] != data[lo - offset:hi - offset]:
                return out + self._give_up(key, "overlapping")
        if end > MAX_DATAGRAM or len(st["pieces"]) >= MAX_FRAGMENTS:
            return out + self._give_up(key, "too_big")

        st["pieces"].setdefault(offset, data)
        if offset == 0:
            st["first"] = pkt
        if not more:
            st["total"] = end

        whole = self._assemble(st)
        if whole is None:
            return out
        built = self._build(st, whole)
        self._drop(key)
        if built is None:
            out += st["frames"]
        else:
            self.stats["reassembled"] += 1
            out.append(built)
        return out

    def flush(self) -> list:
        """Hand on everything still held, as it arrived."""
        out = []
        while self._pending:
            out += self._give_up(next(iter(self._pending)), "expired")
        return out

    def _assemble(self, st):
        if st["total"] is None or st["first"] is None:
            return None
        buf, at = bytearray(), 0
        for o in sorted(st["pieces"]):
            d = st["pieces"][o]
            if o > at:
                return None
            buf += d[at - o:]
            at = max(at, o + len(d))
        return bytes(buf) if at >= st["total"] else None

    def _build(self, st, data):
        first = st["first"]
        try:
            if first.haslayer(IP):
                ip = first[IP]
                head = IP(src=ip.src, dst=ip.dst, ttl=ip.ttl, tos=ip.tos,
                          id=ip.id, proto=ip.proto, options=ip.options)
                pkt = IP(bytes(head / Raw(data)))
            else:
                ip6 = first[IPv6]
                nh = first[IPv6ExtHdrFragment].nh
                head = IPv6(src=ip6.src, dst=ip6.dst, hlim=ip6.hlim,
                            tc=ip6.tc, fl=ip6.fl, nh=nh)
                pkt = IPv6(bytes(head / Raw(data)))
            if first.haslayer(Ether):
                eth = first[Ether]
                pkt = Ether(dst=eth.dst, src=eth.src, type=eth.type) / pkt
                pkt = Ether(bytes(pkt))
            pkt.time = st["frames"][-1].time
            for attr in ("sniffed_on", "direction"):
                if getattr(first, attr, None) is not None:
                    setattr(pkt, attr, getattr(first, attr))
            return pkt
        except Exception:
            return None

    def _expire(self) -> list:
        out, now = [], self.clock()
        while self._pending:
            key, st = next(iter(self._pending.items()))
            if now - st["started"] <= self.timeout:
                break
            out += self._give_up(key, "expired")
        return out

    def _give_up(self, key, why) -> list:
        self.stats[why] += 1
        return self._drop(key)["frames"]

    def _drop(self, key):
        st = self._pending.pop(key)
        self._held_bytes -= sum(len(d) for d in st["pieces"].values())
        self._held_bytes = max(0, self._held_bytes)
        return st


def _fragment_info(pkt):
    """(key, offset, more, data) for an IP fragment, else None."""
    if IP is None:
        return None
    try:
        if pkt.haslayer(IP):
            ip = pkt[IP]
            more = bool(int(ip.flags) & 0x1)
            if not more and ip.frag == 0:
                return None
            body = ip.len - ip.ihl * 4 if ip.len else None
            data = bytes(ip.payload)[:body]
            return (("4", ip.src, ip.dst, ip.proto, ip.id),
                    ip.frag * 8, more, data)
        if IPv6 is not None and pkt.haslayer(IPv6ExtHdrFragment):
            ip6, fh = pkt[IPv6], pkt[IPv6ExtHdrFragment]
            after = bytes(fh.payload)
            headers = len(bytes(ip6.payload)) - len(after)
            data = after[:max(0, ip6.plen - headers)]
            return (("6", ip6.src, ip6.dst, fh.id), fh.offset * 8,
                    bool(fh.m), data)
    except Exception:
        return None
    return None
