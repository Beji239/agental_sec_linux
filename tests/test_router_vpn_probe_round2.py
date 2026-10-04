"""
tests/test_router_vpn_probe_round2.py, register section 17 second pass.

RVP-14 and RVP-16..RVP-18, PRB-4. Real UDP sockets on loopback for the
exchange, a fake /sys/class/net tree for the tunnel types, and the isolated
scratch store for the sweeps.

Run it directly: python3 tests/test_router_vpn_probe_round2.py
"""
import os
import pathlib
import socket
import sys
import tempfile
import threading
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                      # noqa: E402
_isolate_db.isolate()

from core import memory_engine as me                    # noqa: E402
from tools import probe as pr                           # noqa: E402
from tools import router_monitor as rm                  # noqa: E402
from tools import vpn_state as vs                       # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def oid_of(encoded):
    _, body, _ = rm._read_tlv(encoded, 0)
    return rm._decode_oid(body)


print("\n[RVP-14] identifiers past 2.39 decode as the standard says")
check("88 37 01 is 2.999.1", rm._decode_oid(bytes.fromhex("883701")), (2, 999, 1))
check("and it round-trips", oid_of(rm._encode_oid((2, 999, 1))), (2, 999, 1))
check("MIB-II is unchanged", rm._encode_oid(rm.OID_SYS_DESCR).hex(),
      "06082b06010201010100")
check("1.39 still decodes", oid_of(rm._encode_oid((1, 39, 5))), (1, 39, 5))

print("\n[RVP-16] request ids are not a counter")
sess = rm.SnmpSession("127.0.0.1", "x")
ids = [sess._request_id() for _ in range(50)]
check("fifty ids, none following the last", any(b == a + 1 for a, b in zip(ids, ids[1:])), False)
check("all in range", all(1 <= i < 0x7FFFFFFF for i in ids), True)


def response(request_id):
    bind = rm._tlv(rm.TAG_SEQUENCE, rm._encode_oid(rm.OID_SYS_NAME)
                   + rm._tlv(rm.TAG_OCTETS, b"gw"))
    pdu = rm._tlv(rm.PDU_RESPONSE, rm._encode_int(request_id) + rm._encode_int(0)
                  + rm._encode_int(0) + rm._tlv(rm.TAG_SEQUENCE, bind))
    return rm._tlv(rm.TAG_SEQUENCE, rm._encode_int(1) + rm._tlv(rm.TAG_OCTETS, b"x") + pdu)


def agent(send_first):
    """Answers one request: send_first(request_id, peer, own_socket), then the real reply."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))

    def serve():
        data, peer = s.recvfrom(65535)
        _, body, _ = rm._read_tlv(data, 0)
        i = 0
        for _ in range(2):
            _, _, i = rm._read_tlv(body, i)
        _, pdu, _ = rm._read_tlv(body, i)
        _, raw_id, _ = rm._read_tlv(pdu, 0)
        rid = rm._decode_int(raw_id)
        send_first(rid, peer, s)
        s.sendto(response(rid), peer)

    threading.Thread(target=serve, daemon=True).start()
    return s.getsockname()[1]


port = agent(lambda rid, peer, s: s.sendto(b"\x30\x03\x02\x01", peer))
got = rm.SnmpSession("127.0.0.1", "x", port=port, timeout=2, retries=0).get([rm.OID_SYS_NAME])
check("a malformed datagram first does not end the exchange", got.get(rm.OID_SYS_NAME), b"gw")


def from_other_port(rid, peer, s):
    other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    other.bind(("127.0.0.1", 0))
    bad = bytearray(response(rid))
    bad[bad.rindex(b"gw"):bad.rindex(b"gw") + 2] = b"XX"
    other.sendto(bytes(bad), peer)
    other.close()


port = agent(from_other_port)
got = rm.SnmpSession("127.0.0.1", "x", port=port, timeout=2, retries=0).get([rm.OID_SYS_NAME])
check("a reply from another port is ignored", got.get(rm.OID_SYS_NAME), b"gw")

print("\n[RVP-17] router text and addresses are bounded")
check("a 6-byte MAC", rm._mac(bytes(6)), "00:00:00:00:00:00")
check("a 64 KB 'MAC' is not stored", rm._mac(b"\x01" * 65535), None)
check("control characters are dropped", rm._text(b"gw\x1b[31m\nname"), "gw [31m name")

print("\n[RVP-18] the kernel's word for a tunnel counts, not only its name")
fake = pathlib.Path(tempfile.mkdtemp())
for name, files in {
        "nordlynx": {"uevent": "DEVTYPE=wireguard\nINTERFACE=nordlynx\n", "type": "65534"},
        "proton0": {"tun_flags": "0x1001", "type": "65534"},
        "tapx": {"tun_flags": "0x1002", "type": "1"},
        "zt7": {"type": "65534"},
        "eth9": {"type": "1"}}.items():
    (fake / name).mkdir()
    for f, text in files.items():
        (fake / name / f).write_text(text)
old = vs.SYS_NET
vs.SYS_NET = str(fake)
try:
    kinds = {n: vs.kernel_tunnel_kind(n) for n in ("nordlynx", "proton0", "tapx", "zt7", "eth9")}
    check("kinds", kinds, {"nordlynx": "wireguard", "proton0": "tun", "tapx": "tap",
                           "zt7": "point-to-point", "eth9": None})
    stats = {n: SimpleNamespace(isup=True) for n in kinds}
    found = {t["interface"]: t["seen_by"] for t in vs.VPNState()._tunnels(stats)}
    check("a named-nothing tunnel is found by the kernel",
          found, {"nordlynx": "kernel", "proton0": "kernel", "tapx": "kernel",
                  "zt7": "kernel"})
finally:
    vs.SYS_NET = old

print("\n[PRB-4] sweeps of another network do not retire a home device")
with me._get_conn() as conn:
    for i in range(6):
        conn.execute("INSERT INTO presence_sweep (session_id, subnet, method, outcome) "
                     "VALUES ('t', '192.0.2.0/24', 'icmp+arp', 'ok')")
    for i in range(4):
        conn.execute("INSERT INTO presence_sweep (session_id, subnet, method, outcome) "
                     "VALUES ('t', '198.51.100.0/24', 'icmp+arp', 'ok')")
check("four of the last six were elsewhere", me.sweeps_not_covering("192.0.2.50", 6), 4)
check("a device on the newer network is covered", me.sweeps_not_covering("198.51.100.9", 4), 0)

retired = []
real = (me.query_presence, me.permanent_devices, me.retire_device, me.RETIRE_AFTER_MISSES)
me.query_presence = lambda **k: {"window": {"sweeps_counted": 10}, "devices": []}
me.permanent_devices = lambda: [{"ip": "192.0.2.50"}]
me.retire_device = lambda ip, reason=None: retired.append(ip)
me.RETIRE_AFTER_MISSES = 5
try:
    probe = pr.DeviceProbe.__new__(pr.DeviceProbe)
    probe.session_id = "t"
    probe.retire_absent()
finally:
    me.query_presence, me.permanent_devices, me.retire_device, me.RETIRE_AFTER_MISSES = real
check("the home device is not retired", retired, [])

print("\n" + "=" * 62)
if fails:
    print(f"{len(fails)} FAILED: " + ", ".join(fails))
    sys.exit(1)
print("ALL CHECKS PASSED")
