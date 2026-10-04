"""
tests/test_port_scanner_round3.py, port scanner fixes PS-16 to PS-20.

    PS-16  IPv6 raw sockets deliver the TCP segment with no IP header, and the
           parser expected one, so every IPv6 port read no_answer
    PS-17  the SYN answer window ran from the FIRST SYN, not the last
    PS-18  one engine per pass ran out of source ports after 20,001 SYNs, so
           the 'all' set always fell back mid-run
    PS-19  the connect scan folded refused, timed out and failed into False
    PS-20  a UDP probe answered by an ICMP "prohibited" or "unreachable" was
           read as a local failure instead of as filtered

No root needed. The real-socket SYN checks live in test_port_scanner_syn_scan
(run it inside `unshare -rn` to drive them).
"""
import os
import socket
import struct
import sys
import time
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from tools import port_scanner as ps

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + ("" if ok else f"  (got {got!r}, want {want!r})"))
    if not ok:
        fails.append(label)


print("\n[1] PS-16: a bare IPv6 TCP segment is parsed")
seg = struct.pack("!HHLLBBHHH", 443, 41000, 0xAAAA1111, 0xDEADBEF0, 5 << 4,
                  ps._TCP_SYN | ps._TCP_ACK, 64240, 0, 0)
r = ps.parse_tcp_reply(seg, socket.AF_INET6, src_ip="2001:db8:0::20")
check("the source comes from recvfrom, canonical", r["src_ip"], "2001:db8::20")
check("and the ports and flags from the segment",
      (r["sport"], r["dport"], r["ack"], r["is_syn_ack"]),
      (443, 41000, 0xDEADBEF0, True))
check("a short segment is refused",
      ps.parse_tcp_reply(seg[:12], socket.AF_INET6, src_ip="2001:db8::20"), None)

eng = ps.SynScanEngine()
eng._pending[41000] = ("2001:db8::10", "2001:db8::20", 443, 0xDEADBEEF)
sent = []
fake_sock = mock.Mock(sendto=lambda data, dest: sent.append(dest))
eng._handle_frame(socket.AF_INET6, fake_sock, seg, "2001:db8::20")
check("the engine reads an IPv6 SYN-ACK as open", eng._answers.get(41000), "open")
check("and tears it down", len(sent), 1)


print("\n[2] PS-17: the answer window runs from the last SYN")
eng = ps.SynScanEngine(timeout=0.4)
now = time.monotonic()
eng._first_sent_at, eng._last_sent_at = now - 30, now
t = time.monotonic()
eng.finish()
check("a SYN sent just now still gets its window", time.monotonic() - t >= 0.35, True)


print("\n[3] PS-18: a large pass runs in batches and never runs out of ports")
per_engine = []


class FakeEngine:
    def __init__(self, *a, **k):
        self.n = 0
        self.teardowns = 0
        self.asked = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        per_engine.append(self.n)
        return False

    def family_available(self, family):
        return True

    def refusal_reason(self, family):
        return ""

    def probe(self, family, src, dst, port):
        self.n += 1
        self.asked.append((dst, port))
        return True, None

    def finish(self):
        return {k: "closed" for k in self.asked}


with mock.patch.object(ps, "SynScanEngine", FakeEngine), \
        mock.patch.object(ps, "SYN_PACE_SECONDS", 0):
    out = ps.PortScanner("t")._run_syn_scan("127.0.0.1", list(range(1, 25001)),
                                           "self", False)
probing = [n for n in per_engine if n]
check("every port was sent", out["sent"], 25000)
check("in batches no bigger than SYN_BATCH_PROBES",
      max(probing) <= ps.SYN_BATCH_PROBES, True)
check("and every answer came back", len(out["closed"]), 25000)
check("the batch stays well inside the source-port range",
      ps.SYN_BATCH_PROBES < ps.SYN_SOURCE_PORT_HIGH - ps.SYN_SOURCE_PORT_LOW, True)


print("\n[4] PS-19: the connect scan separates open, closed and silent")
listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen()
open_port = listener.getsockname()[1]
spare = socket.socket()
spare.bind(("127.0.0.1", 0))
closed_port = spare.getsockname()[1]
spare.close()
sc = ps.PortScanner("t", config={"port_scan": {"tcp_method": "connect"}})
tcp = sc._run_tcp_scan("127.0.0.1", [open_port, closed_port], "self", False)
check("the method is connect", tcp["method"], ps.CONNECT_METHOD)
check("the listener is open", [e["port"] for e in tcp["open"]], [open_port])
check("the refused port is closed", [e["port"] for e in tcp["closed"]], [closed_port])
check("sent counts the probes, not the open ports", tcp["sent"], 2)
listener.close()

with mock.patch.object(socket.socket, "connect", side_effect=socket.timeout()):
    check("a timeout is no_answer, not closed",
          ps.PortScanner("t")._probe_port("127.0.0.1", 9)[0], "no_answer")
check("_check_port keeps its bool contract",
      isinstance(ps.PortScanner("t")._check_port("127.0.0.1", closed_port), bool), True)


print("\n[5] PS-20: an ICMP prohibited answer is filtered, not a local failure")
import errno


class RejectingSock:
    def __init__(self, *a, **k):
        pass

    def settimeout(self, t):
        pass

    def connect(self, addr):
        pass

    def send(self, data):
        pass

    def recv(self, n):
        raise OSError(errno.EHOSTUNREACH, "No route to host")

    def close(self):
        pass


with mock.patch.object(ps.socket, "socket", RejectingSock):
    res = ps.PortScanner("t")._check_udp_port("192.0.2.1", 7777)
check("recv's EHOSTUNREACH is filtered", res["state"], "filtered")


class NoRouteSock(RejectingSock):
    def connect(self, addr):
        raise OSError(errno.ENETUNREACH, "Network is unreachable")


with mock.patch.object(ps.socket, "socket", NoRouteSock):
    res = ps.PortScanner("t")._check_udp_port("192.0.2.1", 7777)
check("the same errno at connect is still a local failure", res["state"], "probe_failed")

with mock.patch.object(ps.PortScanner, "_check_udp_port",
                       lambda self, h, p: {"state": "filtered", "probe": "x",
                                           "probed_address": h,
                                           "error": "No route to host"}):
    udp = ps.PortScanner("t")._run_udp_scan("192.0.2.1", [7777], "remote", False)
check("the UDP pass lists it under filtered", [f["port"] for f in udp["filtered"]], [7777])

print("\n" + ("," * 60))
print("All port scanner round 3 checks passed." if not fails else f"{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
