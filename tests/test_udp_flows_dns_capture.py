"""
tests/test_udp_flows_dns_capture.py, SNF-11: UDP flows, and DNS from the capture.

Real scapy frames through the shipped module and the adapter's own capture
callback, on the isolated scratch store.

Run it directly: python3 tests/test_udp_flows_dns_capture.py
"""
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
from core import sensors as snr                         # noqa: E402
from tools import feed_matcher as fm                    # noqa: E402
from tools import packet_sniffer_linux as sn            # noqa: E402

from scapy.all import Ether, IP, UDP                     # noqa: E402
from scapy.layers.dns import DNS, DNSQR                  # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


LOCAL, FAR = "192.0.2.10", "8.8.8.8"
sn._LOCAL_ADDRESSES = frozenset({"127.0.0.1", "::1", LOCAL})
sn._LOCAL_ADDRESSES_AT = 1.0

print("\n[1] a UDP flow is one conversation, not one event per frame")
sn._udp_flows.clear()
a = sn.udp_flow_note(LOCAL, 40000, FAR, 9999, "outbound", now=0)
b = sn.udp_flow_note(LOCAL, 40000, FAR, 9999, "outbound", now=1)
c = sn.udp_flow_note(FAR, 9999, LOCAL, 40000, "inbound", now=2)
d = sn.udp_flow_note(LOCAL, 40000, FAR, 9999, "outbound", now=2 + sn.UDP_FLOW_IDLE + 1)
check("the first frame starts it", a["new"], True)
check("the second does not", b["new"], False)
check("the reply joins the same flow", c["new"], False)
check("and marks it answered", c["answered"], True)
check("after a quiet spell it starts again", d["new"], True)
for i in range(sn.UDP_FLOW_MAX + 50):
    sn.udp_flow_note(LOCAL, 1000 + i % 60000, FAR, 7, "outbound", now=10 + i)
check("the table stays at its ceiling", len(sn._udp_flows), sn.UDP_FLOW_MAX)

print("\n[2] only a flow's start counts as a UDP connection attempt")
check("start", sn._is_connection_attempt(
    {"protocol": "udp", "dst_port": 9999, "udp_flow": {"new": True}})[0], True)
check("middle", sn._is_connection_attempt(
    {"protocol": "udp", "dst_port": 9999, "udp_flow": {"new": False}})[0], False)

print("\n[3] a dangerous UDP port is one finding per flow, not per frame")
sn._udp_flows.clear()


def frame(sport=40001, dport=4444, dst=FAR):
    return Ether(bytes(Ether() / IP(src=LOCAL, dst=dst) / UDP(sport=sport, dport=dport) / b"x"))


hits = [sn._detect_dangerous_ports(sn._analyze_packet(frame())) for _ in range(5)]
check("the first frame is reported", hits[0] is not None, True)
check("the next four are not", [h for h in hits[1:] if h], [])

print("\n[4] DNS questions from the capture reach the DNS table")
snr_id = snr.LOCAL_SENSOR_ID
me.upsert_sensor(sensor_id=snr_id, label="host", position="host",
                 summary="", can_see="", cannot_see="", notes="test")


def fresh_sniffer():
    x = adapters.LinuxPacketSniffer.__new__(adapters.LinuxPacketSniffer)
    x.session_id = "snf11"
    x.config = {}
    x._capturing = False
    x._packets_seen = 0
    x._unregistered_counts = {}
    x._started_reason = "test"
    x._cooldowns = {}
    x._lock = threading.Lock()
    x._tls_pending = {}
    x._tls_abandoned = 0
    x._tls_reassembled_this_run = 0
    x._tls_batch = []
    x._tls_batch_at = 0.0
    x._dns_batch = []
    x._dns_batch_at = 0.0
    x._dns_saved_this_run = 0
    x._vpn_cache = (0.0, "unknown")
    x._payload = None
    x._lan = None
    return x


def query(name, txid, qtype="A"):
    return Ether(bytes(Ether() / IP(src=LOCAL, dst="192.0.2.1")
                       / UDP(sport=50000 + txid, dport=53)
                       / DNS(id=txid, rd=1, qd=DNSQR(qname=name, qtype=qtype))))


a = fresh_sniffer()
a._on_packet(query("Evil.Example.", 1))
a._on_packet(query("ordinary.example", 2, "AAAA"))
a._on_packet(Ether(bytes(Ether() / IP(src="192.0.2.1", dst=LOCAL)
                         / UDP(sport=53, dport=50001)
                         / DNS(id=1, qr=1, qd=DNSQR(qname="evil.example")))))
a._flush_dns()
with me._get_conn() as conn:
    rows = conn.execute("SELECT client_ip, domain, query_type, source, upstream "
                        "FROM dns_queries ORDER BY id").fetchall()
check("two questions, the reply is not one",
      [tuple(r) for r in rows],
      [(LOCAL, "evil.example", "A", "capture", "192.0.2.1"),
       (LOCAL, "ordinary.example", "AAAA", "capture", "192.0.2.1")])

print("\n[5] and the feed matcher raises on a listed name from them")
with me._get_conn() as conn:
    conn.execute("INSERT INTO threat_feed (indicator, indicator_type, feed, "
                 "malware_family, first_added, last_refreshed) VALUES "
                 "('evil.example','domain','urlhaus','Test',datetime('now'),datetime('now'))")
with me._get_readonly_conn() as conn:
    raised = fm._check_dns_domains(conn, "snf11", 0, False)
check("FED-1002 raised once", raised, 1)

print("\n" + "=" * 62)
if fails:
    print(f"{len(fails)} FAILED: " + ", ".join(fails))
    sys.exit(1)
print("ALL CHECKS PASSED")
