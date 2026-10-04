"""
tests/test_packet_sniffer_round3.py, packet sniffer fixes.

    SNF-18  the PKT-1003 check in the adapter's poll used memory_engine
            without importing it, so it raised whenever drops were seen
    SNF-19  own socket plus iface made scapy open a second socket, so every
            frame was captured twice (the filter check is in
            test_capture_interface.py)
    SNF-20  socket queue drops (PACKET_STATISTICS) now count toward PKT-1003
    SNF-21  _is_listening read /proc/net/tcp only, missing IPv6 and UDP
    SNF-22  every private x.x.x.255 was called a broadcast

No root and no capture. The listener checks bind real loopback sockets.
"""
import ipaddress
import os
import socket
import sys
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import adapters
from tools import packet_sniffer_linux as sn

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + ("" if ok else f"  (got {got!r}, want {want!r})"))
    if not ok:
        fails.append(label)


print("\n[1] SNF-18/20: drops reach PKT-1003 instead of crashing the poll")
saved = []
fake_me = mock.Mock()
fake_me.is_dismissed.return_value = False
fake_me.save_finding.side_effect = lambda **kw: saved.append(kw)
a = adapters.LinuxPacketSniffer("s", {})
a._capturing = True
with mock.patch.dict(sys.modules, {"core.memory_engine": fake_me}), \
        mock.patch("core.memory_engine", fake_me, create=True), \
        mock.patch.object(sn, "capture_state", return_value={"alive": True}), \
        mock.patch.object(sn, "capture_counters", return_value={
            "readable": True, "delta": {"rx_dropped": 0},
            "socket": {"readable": True, "drops": 7, "packets": 100}}), \
        mock.patch.object(sn, "capture_interface", return_value="eth0"):
    try:
        a.poll()
        raised = None
    except Exception as e:                                    # noqa: BLE001
        raised = f"{type(e).__name__}: {e}"
check("the poll does not raise", raised, None)
check("and writes PKT-1003", [f.get("detection_id") for f in saved], ["PKT-1003"])
check("counting the socket's own drops",
      "dropped 7" in (saved[0].get("description") if saved else ""), True)


print("\n[2] SNF-21: listeners over IPv6 and UDP are seen")
t6 = socket.socket(socket.AF_INET6)
t6.bind(("::1", 0))
t6.listen()
p6 = t6.getsockname()[1]
u4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u4.bind(("127.0.0.1", 0))
pu = u4.getsockname()[1]
check("a TCP listener on ::1 is listening", sn._is_listening(p6), True)
check("a bound UDP socket is listening over udp", sn._is_listening(pu, "udp"), True)
check("and the same port is not a TCP listener", sn._is_listening(pu, "tcp"), False)
t6.close()
u4.close()


print("\n[3] SNF-22: a broadcast is judged by the real netmask")
with mock.patch.object(sn, "_LOCAL_V4_NETS",
                       (ipaddress.ip_network("192.0.2.0/23"),
                        ipaddress.ip_network("203.0.113.0/25"))):
    check("a .255 address on a /23 is a host", sn.is_group_address("192.0.2.255"), False)
    check("a /25's broadcast is a group though it is not .255",
          sn.is_group_address("203.0.113.127"), True)
    check("an unknown network keeps the .255 rule",
          sn.is_group_address("198.51.100.255"), True)
    check("traffic to a .255 host is ordinary LAN traffic",
          sn.classify_scope("192.0.2.5", "192.0.2.255"), "private_to_private")

print("\n" + ("," * 60))
print("ALL CHECKS PASSED" if not fails else f"{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
