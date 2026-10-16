"""
tests/test_fuzz_packet_parsers.py, malformed packets never crash or hang a
parser.

Hypothesis feeds random and mutated input to the parsers on the packet side:
the TLS ClientHello reader, QUIC Initial decryption and its frame reader
(with real encrypted Initials, so the fuzz reaches past the AEAD), DNS, LLMNR
and mDNS frames, IP fragment reassembly, auditd log lines, the router's
dnsmasq log and the eBPF camera's ring-buffer records. Each must keep its
promised shape, quickly, whatever arrives. Needs Hypothesis from
scripts/install_test_tools.sh; without it this skips.
"""
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db  # noqa: E402
import _skip  # noqa: E402
import _tools  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "ebpf"))
_isolate_db.isolate()

for site in sorted((_tools.TOOLS_HOME / "venv" / "lib").glob(
        "python3*/site-packages")):
    sys.path.append(str(site))
try:
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st
except ImportError:
    _skip.skip("needs Hypothesis, run ./scripts/install_test_tools.sh")

from tools import auditd_monitor as am  # noqa: E402
from tools import dns_monitor as dm  # noqa: E402
from tools import ip_defrag  # noqa: E402
from tools import packet_sniffer_linux as ps  # noqa: E402
from tools import quic_initial as q  # noqa: E402
from tools import tls_hello as th  # noqa: E402
import ebpf_monitor as em  # noqa: E402

from scapy.all import IP, TCP, UDP, Raw, fragment  # noqa: E402

fails = []
RUNS = settings(max_examples=300, deadline=1000,
                suppress_health_check=list(HealthCheck))
FEW = settings(max_examples=80, deadline=2000,
               suppress_health_check=list(HealthCheck))


def run(label, test):
    try:
        test()
        print(f"  PASS  {label}")
    except Exception as e:                                  # noqa: BLE001
        fails.append(label)
        print(f"  FAIL  {label}: {type(e).__name__}: {str(e)[:400]}")


def mutated(seed: bytes):
    """seed with bytes flipped, cut short, or spliced with random ones."""
    flips = st.lists(st.tuples(st.integers(0, max(0, len(seed) - 1)),
                               st.integers(1, 255)), max_size=8)

    def apply(args):
        changes, cut, tail = args
        b = bytearray(seed)
        for at, x in changes:
            if at < len(b):
                b[at] ^= x
        return bytes(b[:cut]) + tail

    return st.tuples(flips, st.integers(0, len(seed)),
                     st.binary(max_size=40)).map(apply)


# A real ClientHello to start from, built the way tests/test_tls_hello.py does.
def u16(n): return bytes([(n >> 8) & 0xFF, n & 0xFF])
def u24(n): return bytes([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
def ext(t, body): return u16(t) + u16(len(body)) + body


def hello_body():
    name = b"example.com"
    entry = b"\x00" + u16(len(name)) + name
    exts = (ext(0x0000, u16(len(entry)) + entry)
            + ext(0x000A, u16(4) + u16(0x001D) + u16(0x0017))
            + ext(0x000B, b"\x01\x00")
            + ext(0x0010, u16(3) + b"\x02h3"))
    body = (u16(0x0303) + b"\x11" * 32 + b"\x00" + u16(4) + u16(0xC02B)
            + u16(0xC02F) + b"\x01\x00" + u16(len(exts)) + exts)
    return bytes([0x01]) + u24(len(body)) + body


HANDSHAKE = hello_body()
RECORD = bytes([0x16]) + u16(0x0301) + u16(len(HANDSHAKE)) + HANDSHAKE
HELLO_KEYS = {"ok", "reason", "sni_state", "sni", "ja3", "alpn"}

print("TLS ClientHello")


@RUNS
@given(st.one_of(st.binary(max_size=600), mutated(RECORD)))
def tls_hello(data):
    out = th.parse_client_hello(data)
    assert isinstance(out, dict) and HELLO_KEYS <= set(out)
    assert out["sni_state"] in ("present", "absent", "unreadable")


run("parse_client_hello keeps its shape", tls_hello)


print("QUIC Initial")


def varint(v):
    if v < 64:
        return bytes([v])
    if v < 16384:
        return struct.pack("!H", 0x4000 | v)
    return struct.pack("!I", 0x80000000 | v)


def initial(dcid, payload, pn=0):
    """A client Initial, really encrypted, carrying payload as its frames."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key, iv, hp = q.client_initial_keys(dcid)
    payload = payload + b"\x00" * max(0, 20 - len(payload))
    header = (bytes([0xC1]) + q.QUIC_V1.to_bytes(4, "big") + bytes([len(dcid)])
              + dcid + b"\x00" + varint(0)
              + struct.pack("!H", 0x4000 | (2 + len(payload) + 16))
              + pn.to_bytes(2, "big"))
    ct = AESGCM(key).encrypt(
        (int.from_bytes(iv, "big") ^ pn).to_bytes(12, "big"), payload, header)
    mask = q.header_protection_mask(hp, ct[2:18])
    prot = bytearray(header)
    prot[0] ^= mask[0] & 0x0F
    prot[-2] ^= mask[1]
    prot[-1] ^= mask[2]
    return bytes(prot) + ct


FRAMES = (b"\x06" + varint(0) + varint(len(HANDSHAKE)) + HANDSHAKE
          + b"\x00" * 64)
SEED_INITIAL = initial(b"\x83\x94\xc8\xf0\x3e\x51\x57\x08", FRAMES)
QUIC_KEYS = {"ok", "reason", "version", "dcid", "crypto"}


@RUNS
@given(st.one_of(st.binary(max_size=1300), mutated(SEED_INITIAL)))
def quic_datagram(data):
    out = q.decrypt_client_initial(data)
    assert isinstance(out, dict) and QUIC_KEYS <= set(out)


run("decrypt_client_initial keeps its shape on any datagram", quic_datagram)

# Frame bytes that are close to real: frame types, varints at their edges,
# and raw bytes, so the reader meets truncated and oversized frames.
FRAME_PIECES = st.sampled_from([
    b"\x00", b"\x01", b"\x02", b"\x03", b"\x06", b"\x1c", b"\x1d",
    b"\x3f", b"\x40", b"\x7f\xff", b"\xbf\xff\xff\xff",
    b"\xff\xff\xff\xff\xff\xff\xff\xff", b"\x40\x00", HANDSHAKE[:40]])
FRAME_BYTES = st.one_of(st.binary(max_size=300),
                        st.lists(FRAME_PIECES, max_size=30).map(b"".join))


@RUNS
@given(st.binary(min_size=8, max_size=8), FRAME_BYTES)
def quic_frames(dcid, payload):
    out = q.decrypt_client_initial(initial(dcid, payload))
    assert isinstance(out, dict) and QUIC_KEYS <= set(out)
    if out["ok"]:
        asm = q.CryptoAssembler()
        try:
            asm.add(out["crypto"])
        except ValueError:
            return                       # refused past the cap, as promised
        assert asm.bytes_held <= q.MAX_HELLO_BYTES
        rec = asm.hello_record()
        if rec is not None:
            th.parse_client_hello(rec)


run("a decrypted Initial's frames never break the reader", quic_frames)


print("DNS, LLMNR and mDNS frames")
PORTS = st.sampled_from([53, 5353, 5355])


@FEW
@given(PORTS, st.booleans(), st.booleans(),
       st.one_of(st.binary(max_size=300),
                 st.binary(max_size=300).map(lambda b: b"\x00\x01\x81\x80" + b)))
def dns_frames(port, as_reply, tcp, payload):
    sport, dport = (port, 40000) if as_reply else (40000, port)
    if tcp:
        pkt = IP(src="192.0.2.1", dst="192.0.2.2") / TCP(
            sport=sport, dport=dport) / Raw(u16(len(payload)) + payload)
    else:
        pkt = IP(src="192.0.2.1", dst="192.0.2.2") / UDP(
            sport=sport, dport=dport) / Raw(payload)
    for fn in (ps.dns_query_of, ps.dns_answers_of):
        out = fn(pkt)
        assert out is None or isinstance(out, dict)


run("dns_query_of and dns_answers_of never raise", dns_frames)


print("IP fragment reassembly")
FRAG = st.tuples(st.integers(0, 3), st.integers(0, 8191),
                 st.booleans(), st.binary(min_size=8, max_size=96))


@FEW
@given(st.lists(FRAG, max_size=60))
def defrag(pieces):
    d = ip_defrag.Defragmenter()
    for ident, off, more, data in pieces:
        pkt = IP(src="192.0.2.1", dst="192.0.2.2", id=ident, frag=off,
                 flags="MF" if more else 0, proto=17) / Raw(data)
        out = d.push(pkt)
        assert isinstance(out, list)
        assert len(d._pending) <= ip_defrag.MAX_PENDING
        assert d._held_bytes >= 0
    d.flush()
    assert not d._pending


run("the defragmenter never raises and stays bounded", defrag)


@FEW
@given(st.binary(min_size=1, max_size=3000), st.integers(8, 1400))
def defrag_real(payload, size):
    d = ip_defrag.Defragmenter()
    frags = fragment(IP(src="192.0.2.1", dst="192.0.2.2", proto=17)
                     / Raw(payload), fragsize=(size // 8) * 8 or 8)
    out = []
    for f in reversed(frags):
        out += d.push(IP(bytes(f)))
    out += d.flush()
    assert out


run("real fragments in reverse order still come out", defrag_real)


print("auditd and the router's DNS log")
AUDIT = st.sampled_from([
    "type=SYSCALL", "type=PATH", "type=EXECVE", "type=PROCTITLE",
    "msg=audit(", "1760000000.123:42", "):", " ", "=", '"', "a0=", "name=",
    "proctitle=", "2F62696E", "\x1d", "\x00", "%", "(null)", "argc=3",
    "uid=0", "key=", '"agentalsec_exec"', "item=0", "nametype=NORMAL"])
AUDIT_LINE = st.one_of(st.text(max_size=300),
                       st.lists(AUDIT, max_size=30).map("".join))


@RUNS
@given(AUDIT_LINE)
def audit_line(line):
    out = am.parse_record(line)
    if out is not None:
        assert {"type", "msg_id", "at", "fields"} <= set(out)


run("parse_record keeps its shape", audit_line)

DNSMASQ = st.sampled_from([
    "Wed Sep 30 23:09:34 2026 daemon.info dnsmasq[6634]: ",
    "20 192.0.2.7/58476 ", "query[A] ", "query[AAAA] ", "reply ", "forwarded ",
    "cached ", "config ", "example.com", " is ", "<CNAME>", "NXDOMAIN",
    " from 192.0.2.7", " to 198.51.100.1", "\x00", "é", " ", "999999999999"])
DNS_LINES = st.lists(st.one_of(st.text(max_size=200),
                               st.lists(DNSMASQ, max_size=12).map("".join)),
                     max_size=40)


@RUNS
@given(DNS_LINES)
def dnsmasq(lines):
    rows, stats = dm.parse_router_dnslog(lines)
    assert isinstance(rows, list) and isinstance(stats, dict)


run("parse_router_dnslog keeps its shape", dnsmasq)


print("The eBPF camera's ring-buffer records")


@RUNS
@given(st.binary(min_size=em.EVENT_SIZE, max_size=em.EVENT_SIZE),
       st.sampled_from([em.KIND_EXEC, em.KIND_CONNECT, 0, 7]))
def ebpf_record(raw, kind):
    rec = em._decode(struct.pack("<I", kind) + raw[4:])
    assert rec["kind"] in ("exec", "connect")
    assert all(isinstance(rec[k], str) for k in ("comm", "parent"))


run("_decode turns any full-size record into a row", ebpf_record)


class _Sink:
    def __init__(self):
        self.rows = []

    def add(self, row):
        self.rows.append(row)


@RUNS
@given(st.binary(max_size=em.EVENT_SIZE + 64))
def ebpf_callback(raw):
    reader = object.__new__(em.RingBuffer)
    reader.sink, reader._cb_errors, reader._cb_error = _Sink(), 0, None
    reader._on_event(raw)
    if len(raw) < em.EVENT_SIZE:
        assert reader._cb_errors == 1 and not reader.sink.rows
    else:
        assert len(reader.sink.rows) == 1


run("a short record is counted, never parsed", ebpf_callback)


print(f"\n{'ALL PASSED' if not fails else str(len(fails)) + ' FAILED'}")
sys.exit(1 if fails else 0)
