"""
tests/test_packet_sniffer_features.py, the Linux-only capture features.

    SNF-23  DNS answers (A, AAAA, CNAME, NXDOMAIN) into dns_answer; DNS over
            TCP, LLMNR and this host's mDNS questions; encrypted DNS counted
    SNF-24  flows the socket snapshot missed are named from the eBPF camera's
            connect() records, never from an earlier boot's
    SNF-25  QUIC client Initials are decrypted and their ClientHello recorded
            in tls_hello with transport 'quic'
    LAN-1005 to LAN-1007  IPv6 neighbour spoofing, rogue IPv6 routers and
            rogue DHCPv6 servers

Real scapy frames through the adapter's own capture callback, on the isolated
scratch store. Addresses are RFC 5737 / RFC 3849 documentation ranges.
"""
import os
import pathlib
import sqlite3
import ssl
import struct
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                      # noqa: E402
_isolate_db.isolate()

import adapters                                         # noqa: E402
from core import memory_engine as me                    # noqa: E402
from core import sensors as snr                         # noqa: E402
from tools import lan_watch, quic_initial as q          # noqa: E402
from tools import packet_sniffer_linux as sn            # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from scapy.all import Ether, IP, TCP, UDP, Raw          # noqa: E402
from scapy.layers.dns import DNS, DNSQR, DNSRR          # noqa: E402
from scapy.layers.inet6 import (IPv6, ICMPv6ND_NA, ICMPv6ND_RA,  # noqa: E402
                                ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr,
                                ICMPv6NDOptPrefixInfo)
from scapy.layers.dhcp6 import (DHCP6_Advertise, DHCP6OptServerId,  # noqa: E402
                                DUID_LLT)

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


LOCAL, RESOLVER, FAR = "192.0.2.10", "192.0.2.53", "198.51.100.20"
sn._LOCAL_ADDRESSES = frozenset({"127.0.0.1", "::1", LOCAL})
sn._LOCAL_ADDRESSES_AT = 1.0
me.upsert_sensor(sensor_id=snr.LOCAL_SENSOR_ID, label="host", position="host",
                 summary="", can_see="", cannot_see="", notes="test")


def sniffer():
    a = adapters.LinuxPacketSniffer("feat", {})
    a._lan = lan_watch.LanWatch(gateway_ip="192.0.2.1", load_baselines=False)
    a._payload = None
    return a


def frame(pkt):
    return Ether(bytes(pkt))


print("\n[1] SNF-23: DNS answers become dns_answer rows")
a = sniffer()
reply = frame(Ether() / IP(src=RESOLVER, dst=LOCAL) / UDP(sport=53, dport=40000)
              / DNS(id=7, qr=1, qd=DNSQR(qname="www.example.com"),
                    an=[DNSRR(rrname="www.example.com", type="CNAME",
                              rdata="edge.example.net", ttl=30),
                        DNSRR(rrname="edge.example.net", type="A",
                              rdata=FAR, ttl=60),
                        DNSRR(rrname="edge.example.net", type="AAAA",
                              rdata="2001:db8::20", ttl=60)]))
a._on_packet(reply)
a._on_packet(reply)
nx = frame(Ether() / IP(src=RESOLVER, dst=LOCAL) / UDP(sport=53, dport=40001)
           / DNS(id=8, qr=1, rcode=3, qd=DNSQR(qname="qx7kz2.example")))
a._on_packet(nx)
a._flush_dns_answers()
got = me.query_dns_answers(address=FAR)
check("the address resolves back to its name",
      [(r["name"], r["rrtype"], r["client_ip"], r["resolver"]) for r in got["rows"]],
      [("edge.example.net", "A", LOCAL, RESOLVER)])
check("a repeat counts, it does not add a row", got["rows"][0]["times_seen"], 2)
check("the CNAME is kept",
      [r["value"] for r in me.query_dns_answers(name="www.example.com")["rows"]],
      ["edge.example.net"])
check("NXDOMAIN is kept with no value",
      [(r["rrtype"], r["value"]) for r in me.query_dns_answers(rrtype="NXDOMAIN")["rows"]],
      [("NXDOMAIN", "")])
check("and the answer carries its coverage note",
      "encrypted" not in "" and "DoH" in got["coverage"], True)

print("\n[2] SNF-23: DNS over TCP, LLMNR and mDNS questions")
tcp_q = bytes(DNS(id=9, rd=1, qd=DNSQR(qname="tcp.example.org")))
q1 = sn.dns_query_of(frame(Ether() / IP(src=LOCAL, dst=RESOLVER)
                           / TCP(sport=41000, dport=53, flags="PA")
                           / Raw(struct.pack("!H", len(tcp_q)) + tcp_q)))
check("a DNS question over TCP is read", (q1 or {}).get("domain"), "tcp.example.org")
check("and labelled dns-tcp", (q1 or {}).get("protocol"), "dns-tcp")
q2 = sn.dns_query_of(frame(Ether() / IP(src="192.0.2.77", dst="224.0.0.252")
                           / UDP(sport=50000, dport=5355)
                           / Raw(bytes(DNS(qd=DNSQR(qname="fileserv"))))))
check("an LLMNR question is read", (q2 or {}).get("protocol"), "llmnr")
a = sniffer()
a._on_packet(frame(Ether() / IP(src="192.0.2.77", dst="224.0.0.251")
                   / UDP(sport=5353, dport=5353)
                   / DNS(qd=DNSQR(qname="other-printer.local"))))
a._on_packet(frame(Ether() / IP(src=LOCAL, dst="224.0.0.251")
                   / UDP(sport=5353, dport=5353)
                   / DNS(qd=DNSQR(qname="my-printer.local"))))
a._flush_dns()
with me._get_conn() as conn:
    names = [r[0] for r in conn.execute(
        "SELECT domain FROM dns_queries WHERE domain LIKE '%printer.local'")]
check("only this host's own mDNS questions are kept", names, ["my-printer.local"])

print("\n[3] SNF-23: encrypted DNS is counted as a blind spot")
a = sniffer()
a._on_packet(frame(Ether() / IP(src=LOCAL, dst="203.0.113.53")
                   / TCP(sport=42000, dport=853, flags="S")))
a._on_packet(frame(Ether() / IP(src=LOCAL, dst="203.0.113.53")
                   / TCP(sport=42000, dport=853, flags="A")))
a._record_tls(LOCAL, "203.0.113.9", 443, "", None,
              {"sni": "dns.google", "sni_state": "present"})
enc = a.encrypted_dns_state()
check("one DoT connection, not one per frame", enc["dot_flows"], 1)
check("a hello to a known DoH resolver counts", enc["doh_hellos"], 1)
check("and the note says names may be missing", "NOT in dns_queries" in enc["note"], True)


print("\n[4] SNF-25: a QUIC ClientHello split across two Initials is read")


def client_hello(sni):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h3"])
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    s = ctx.wrap_bio(inc, out, server_hostname=sni)
    try:
        s.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()[5:]


def varint(v):
    if v < 64:
        return bytes([v])
    if v < 16384:
        return struct.pack("!H", 0x4000 | v)
    return struct.pack("!I", 0x80000000 | v)


def initial(dcid, frames, pn):
    key, iv, hp = q.client_initial_keys(dcid)
    payload = frames + b"\x00" * max(0, 1150 - len(frames))
    header = (bytes([0xC1]) + q.QUIC_V1.to_bytes(4, "big") + bytes([len(dcid)])
              + dcid + b"\x00" + varint(0)
              + struct.pack("!H", 0x4000 | (2 + len(payload) + 16))
              + pn.to_bytes(2, "big"))
    ct = AESGCM(key).encrypt((int.from_bytes(iv, "big") ^ pn).to_bytes(12, "big"),
                             payload, header)
    mask = q.header_protection_mask(hp, ct[2:18])
    prot = bytearray(header)
    prot[0] ^= mask[0] & 0x0F
    prot[-2] ^= mask[1]
    prot[-1] ^= mask[2]
    return bytes(prot) + ct


key_ok = [k.hex() for k in q.client_initial_keys(bytes.fromhex("8394c8f03e515708"))]
check("RFC 9001 A.1 client keys",
      key_ok, ["1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c",
               "9f50449e04a0e810283a1e9933adedd2"])
check("RFC 9001 A.2 header protection mask",
      q.header_protection_mask(bytes.fromhex(key_ok[2]),
                               bytes.fromhex("d1b1c98dd7689fb8ec11d242b123dc9b"))[:5].hex(),
      "437b9aec36")

ch = client_hello("h3.example.com")
dcid = os.urandom(8)
half = len(ch) // 2


def crypto(off, data):
    return b"\x06" + varint(off) + varint(len(data)) + data


a = sniffer()
for pkt_bytes in (initial(dcid, crypto(half, ch[half:]) + b"\x01", 0),
                  initial(dcid, crypto(0, ch[:half]), 1),
                  initial(dcid, crypto(0, ch[:half]), 2)):     # a retransmit
    a._on_packet(frame(Ether() / IP(src=LOCAL, dst=FAR)
                       / UDP(sport=51000, dport=443) / Raw(pkt_bytes)))
a._flush_tls()
with me._get_conn() as conn:
    rows = conn.execute("SELECT sni, transport, alpn, sni_state, times_seen "
                        "FROM tls_hello WHERE dst_ip = ?", (FAR,)).fetchall()
check("one QUIC hello, read out of order, retransmit ignored",
      [tuple(r) for r in rows], [("h3.example.com", "quic", "h3", "present", 1)])
bad = bytearray(initial(os.urandom(8), crypto(0, ch), 0))
bad[-1] ^= 1
check("a tampered Initial does not decrypt",
      q.decrypt_client_initial(bytes(bad))["ok"], False)


print("\n[5] SNF-24: the eBPF camera names a flow the snapshot missed")
tmp = tempfile.mkdtemp()
camera = os.path.join(tmp, "ebpf_events.db")
c = sqlite3.connect(camera)
c.execute("""CREATE TABLE ebpf_event (id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL, ts_ns INTEGER NOT NULL, pid INTEGER NOT NULL,
    tgid INTEGER NOT NULL, ppid INTEGER NOT NULL DEFAULT 0,
    uid INTEGER NOT NULL DEFAULT 0, comm TEXT NOT NULL DEFAULT '',
    parent TEXT NOT NULL DEFAULT '', filename TEXT, daddr TEXT, dport INTEGER,
    family TEXT, recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
now_ns = int(time.monotonic() * 1e9)
c.execute("INSERT INTO ebpf_event (kind, ts_ns, pid, tgid, comm, daddr, dport, "
          "family) VALUES ('connect', ?, 4242, 4242, 'shortlived', ?, 8443, 'inet')",
          (now_ns - 2 * 10**9, FAR))
c.execute("INSERT INTO ebpf_event (kind, ts_ns, pid, tgid, comm, daddr, dport, "
          "family, recorded_at) VALUES ('connect', ?, 999, 999, 'oldboot', "
          "'203.0.113.7', 443, 'inet', datetime('now', '-3 days'))",
          (now_ns - 10**9,))
c.execute("INSERT INTO ebpf_event (kind, ts_ns, pid, tgid, comm, daddr, dport, "
          "family) VALUES ('connect', ?, 77, 77, 'v6app', "
          "'2001:db8:0:0:0:0:0:20', 443, 'inet6')", (now_ns - 10**9,))
c.commit()
c.close()
sn.set_ebpf_events_db(camera)
sn._conn_index.clear()
sn._conn_index_at = time.monotonic()        # an empty, fresh socket snapshot
out = sn._analyze_packet(frame(Ether() / IP(src=LOCAL, dst=FAR)
                               / TCP(sport=43000, dport=8443, flags="S")))
check("the outbound frame is named from the camera",
      (out["pid"], out["process_name"], out["attributed_by"]),
      (4242, "shortlived", "ebpf_connect"))
back = sn._analyze_packet(frame(Ether() / IP(src=FAR, dst=LOCAL)
                                / TCP(sport=8443, dport=43000, flags="SA")))
check("and so is the reply", back["pid"], 4242)
old = sn._analyze_packet(frame(Ether() / IP(src=LOCAL, dst="203.0.113.7")
                               / TCP(sport=43001, dport=443, flags="S")))
check("an earlier boot's record is never used", old["pid"], None)
check("an expanded IPv6 address in the camera still matches",
      sn._ebpf_owner("2001:db8::20", 443), (77, "v6app"))
sn.set_ebpf_events_db(None)


print("\n[6] LAN-1005 to LAN-1007 through the capture callback")
a = sniffer()
a._lan._gateway_mac = "02:00:00:00:00:01"
written = []
a._emit_lan_hit = lambda hit: written.append(hit["detection_id"])


def ra(src, mac):
    return frame(Ether(src=mac) / IPv6(src=src, dst="ff02::1", hlim=255)
                 / ICMPv6ND_RA(routerlifetime=1800)
                 / ICMPv6NDOptSrcLLAddr(lladdr=mac)
                 / ICMPv6NDOptPrefixInfo(prefix="2001:db8::", prefixlen=64))


a._on_packet(ra("fe80::1", "02:00:00:00:00:01"))
check("the first router, on the gateway's MAC, is learned quietly", written, [])
a._on_packet(ra("fe80::66", "02:00:00:00:00:66"))
check("a second router raises LAN-1006", written, ["LAN-1006"])
written.clear()
for mac in ["02:00:00:00:00:0a", "02:00:00:00:00:0b"] * 3:
    a._on_packet(frame(Ether(src=mac) / IPv6(src="fe80::5", dst="ff02::1")
                       / ICMPv6ND_NA(tgt="2001:db8::5", O=1)
                       / ICMPv6NDOptDstLLAddr(lladdr=mac)))
check("a flapping neighbour binding raises LAN-1005", written[:1], ["LAN-1005"])
written.clear()
b = sniffer()
b._lan._gateway_mac = "02:00:00:00:00:01"
b._emit_lan_hit = lambda hit: written.append((hit["detection_id"],
                                              hit["raw_data"]["server_duid"]))
b._on_packet(frame(Ether(src="02:00:00:00:00:99")
                   / IPv6(src="fe80::99", dst="fe80::2")
                   / UDP(sport=547, dport=546) / DHCP6_Advertise(trid=5)
                   / DHCP6OptServerId(duid=DUID_LLT(lladdr="02:00:00:00:00:99",
                                                    timeval=1))))
check("a first DHCPv6 server that is not the gateway raises LAN-1007",
      written, [("LAN-1007", "000100010000000102000000" + "0099")])

print("\n[7] v56: a fresh schema and a migrated one agree")
from core import migrations                             # noqa: E402
fresh = sqlite3.connect(":memory:")
fresh.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
migrated = sqlite3.connect(":memory:")
migrated.execute("CREATE TABLE _nothing (x INTEGER)")
migrations._migrate_tls_hello(migrated)
migrations._migrate_quic_and_dns_answers(migrated)


def shape(conn, table):
    cols = [tuple(r)[1:5] for r in conn.execute(f"PRAGMA table_info({table})")]
    idx = sorted(r[1] for r in conn.execute(f"PRAGMA index_list({table})")
                 if not r[1].startswith("sqlite_autoindex"))
    return cols, idx


check("dns_answer matches", shape(fresh, "dns_answer"), shape(migrated, "dns_answer"))
check("tls_hello.transport matches",
      [c for c in shape(fresh, "tls_hello")[0] if c[0] == "transport"],
      [c for c in shape(migrated, "tls_hello")[0] if c[0] == "transport"])
check("the migration is idempotent",
      migrations._migrate_quic_and_dns_answers(migrated), 0)

print("\n" + "=" * 62)
if fails:
    print(f"{len(fails)} FAILED: " + ", ".join(fails))
    sys.exit(1)
print("ALL CHECKS PASSED")
