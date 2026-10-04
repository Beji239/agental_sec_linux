"""
tests/test_port_scanner_fixes.py, the 2026-09-25 audit round on
tools/port_scanner.py (register section 10).

WHAT THIS FILE IS FOR. Section 10 was audited for the two questions the
register asks of every tool: is it using what LINUX offers, and what is broken
in it. Nine defects were found by RUNNING the module against this host and its
own services, and this file asserts each fix in BOTH directions -- the shipped
behaviour that must now happen, and the defect that must not come back.

THE HEADLINE, and the reason the file is shaped the way it is. The register's
own line for this section says "self-scans are in its own record as measuring
'bound, not reachable'". MEASURED: a self-scan reports what ANSWERS ON THE ONE
ADDRESS IT WAS GIVEN, which is a smaller set than what is bound. On a test host
the kernel's listener table held seven ports; a scan of 127.0.0.1 found one,
a scan of the LAN address found NOTHING, while a process bound to 0.0.0.0
answered both. So section [2]
below is a controlled matrix rather than a sentence: one listener, three bind
addresses, two vantages, and the sentence the payload writes about it.

THE OTHER FINDING WORTH READING FIRST: a WORKING service reported as silent.
mDNS and LLMNR were both probed by unicast with a MULTICAST service-enumeration
question. Against a live avahi-daemon holding UDP 5353 on this host:

    the shipped enumeration PTR, unicast   -> NO REPLY
    an A query for this host's own name    -> 67 bytes
    a reverse address PTR                  -> 87 bytes

so a responder that was up and answering came back `udp_no_answer`, the one
answer this module's design says must never be confused with absence. Fixed by
asking the question RFC 6762 section 8 requires a responder to answer unicast
-- a reverse address PTR for the address being scanned -- and by giving LLMNR
its own question, because RFC 4795 defines no service enumeration at all.

Section [1] is the payloads, decoded field by field, because three of the nine
defects were packets that were not what their own comments said they were.

Nothing here writes to the owner's store: memory_engine.DB_PATH is pointed at a
throwaway database built from Schema.SQL. The scans in section [2] are REAL
scans of this host's own addresses, which is the subject of that section.
"""
import ipaddress
import pathlib
import socket
import sqlite3
import struct
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def _out(tag, label, extra=""):
    """One check line. THE LABEL IS DELIMITED so the negative-control harness
    can read it back EXACTLY, colons and all -- a regex that guesses where a
    label ends cut two of this file's own labels short, and a control that
    compares a truncated label reports a broken expectation instead of a
    defect. `[` and `]` never appear in a label here."""
    print(f"  {tag}  [{label}]{extra}")


def check(label, got, want):
    ok = got == want
    _out("PASS" if ok else "FAIL", label,
         f": {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, value, detail=None):
    ok = bool(value)
    _out("PASS" if ok else "FAIL", label,
         (f": {detail!r}" if detail is not None else "")
         + ("" if ok else "  (want truthy)"))
    if not ok:
        fails.append(label)


def check_in(label, needle, haystack):
    ok = needle in (haystack or "")
    _out("PASS" if ok else "FAIL", label,
         ("" if ok else f": {needle!r} not in {str(haystack)[:160]!r}"))
    if not ok:
        fails.append(label)


tmp = pathlib.Path(tempfile.mkdtemp())
db = tmp / "t.db"

from core import memory_engine as me          # noqa: E402
me.DB_PATH = db

c = sqlite3.connect(db)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.commit()
c.close()

from core import migrations                   # noqa: E402
migrations.run_migrations(db)
from core import sensors as sn                # noqa: E402
sn.register_local()

from tools import port_scanner as ps          # noqa: E402

SRC = (ROOT / "tools" / "port_scanner.py").read_text(encoding="utf-8")


print("\n[1] THE PAYLOADS: each one is what its own comment says it is")
#
# Three of this round's defects were packets whose bytes did not match the
# sentence above them, and every one of them presented as "the device did not
# answer" -- the reading this module exists to refuse. Each is now asserted
# against the SAME grammar that was used to find it.

print("\n  -- SNMP: a GetRequest for sysDescr.0, and the eight arcs the comment names")
snmp = ps._snmp_get()
try:
    from scapy.layers.snmp import SNMP, SNMPget
    parsed = SNMP(snmp)
    oid_arcs = [int(x) for x in bytes(parsed[SNMPget].varbindlist[0].oid)]
    check("scapy parses it as an SNMP GetRequest", SNMPget in parsed, True)
    # The arcs AS PARSED, not a hex substring: the old packet carried the same
    # five-arc prefix, which is how a check pinning `2b06010201` stayed green
    # over a request for the mib-2 node.
    check("the varbind names sysDescr.0 (scapy reads the arcs, including the"
          " 43 that stands for the leading 1.3)",
          oid_arcs, [6, 8, 43, 6, 1, 2, 1, 1, 1, 0])
    # The arcs above ARE 1.3.6.1.2.1.1.1.0: BER packs the first two arcs into
    # one octet (40*1 + 3 = 43). Asserting the decoded arcs rather than the hex
    # is the point -- a substring check is what stayed green over the broken
    # packet. The dotted form is asserted from the same parse, so the two
    # readings of one packet have to agree.
    check("which is the dotted OID its own comment names",
          str(parsed[SNMPget].varbindlist[0].oid.val), "1.3.6.1.2.1.1.1.0")
    check("its value is a NULL, so nothing is being written",
          type(parsed[SNMPget].varbindlist[0].value).__name__, "ASN1_NULL")
except ImportError:
    # A test that reads a real artifact must SKIP IN WORDS when it is absent.
    print("  SKIP  scapy is not installed on this machine: the SNMP decode "
          "cannot run here (the packet is still checked by hand below)")
check("no SetRequest (0xa3) byte anywhere in the packet",
      b"\xa3" in snmp, False)
check("the whole packet is 43 bytes, the length its octets declare",
      len(snmp), 43)
check_in("and the comment's own claim is on the wire",
          "2b06010201010100", snmp.hex())

print("\n  -- NetBIOS: the 50 bytes RFC 1002 section 4.2.1 lays out")
nb = ps._netbios_status()
check("length is 50, not the 48 that put qtype one field early",
      len(nb), 50)
check("the name-length octet is 0x20 (32 encoded bytes)", nb[12], 0x20)
check("the encoded name field is exactly 32 bytes", len(nb[13:45]), 32)
check("the name terminates with 0x00 at offset 45", nb[45], 0x00)
check("qtype NBSTAT (0x0021) sits at 46", nb[46:48], b"\x00\x21")
check("qclass IN (0x0001) sits at 48", nb[48:50], b"\x00\x01")
check("the wildcard name decodes to '*'",
      nb[14:45].decode("ascii").rstrip(), "K" + "A" * 30)

print("\n  -- DNS: a normal recursive query, and the bits named rather than assumed")
dns = ps._dns_query()
_, dflags, qd, an, ns_, ar = struct.unpack(">HHHHHH", dns[:12])
check("it is a QUERY (QR clear)", (dflags >> 15) & 1, 0)
check("opcode is 0 (standard query)", (dflags >> 11) & 0xF, 0)
check("TC is clear -- bit 9, 0x0200", (dflags >> 9) & 1, 0)
check("RD IS set, the shape a client asks with", (dflags >> 8) & 1, 1)
check("exactly one question", (qd, an, ns_, ar), (1, 0, 0, 0))

print("\n  -- mDNS and LLMNR are different questions, sent to different ports")
q4 = ps._mdns_query("192.0.2.9")
check("the mDNS probe is an address question, not a service list",
      b"_services" in q4, False)
check("its name is the octets REVERSED, then in-addr.arpa",
      q4[12:], b"\x019\x012\x010\x03192\x07in-addr\x04arpa\x00\x00\x0c\x00\x01")
check("RD is clear, which RFC 6762 requires of mDNS", q4[2:4], b"\x00\x00")
# The v6 name is the address's NIBBLES REVERSED, then ip6.arpa -- built from
# the expanded address rather than from a memory of the format. The first
# version of this check asserted the substring 'ip6.arpa' with its length
# prefix, which the shipped name does not carry that way.
_v6_name = ps._mdns_query("2001:db8::1")[12:]
check("the v6 probe ends with the ip6.arpa suffix",
      _v6_name.endswith(b"\x03ip6\x04arpa\x00\x00\x0c\x00\x01"), True)
check("and its first label is the address's LAST nibble",
      _v6_name[0:2], b"\x011")
check("an address the resolver cannot parse yields the fallback NAME, not a"
      " nameless query",
      ps._mdns_query("not-an-address")[12:],
      b"\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01")
ll = ps._llmnr_query("192.0.2.9")
check("the LLMNR probe is NOT the mDNS payload", ll == q4, False)
check("LLMNR sets RD, which RFC 4795 section 2.1 requires", ll[2:4], b"\x01\x00")
check("and it asks the same reverse name",
      ll[12:], q4[12:])

print("\n  -- and the payload table itself says what each port is asked")
check("seven ports carry a real request", sorted(ps.UDP_PROBES),
      [53, 123, 137, 161, 1900, 5353, 5355])
check("eighteen are sent an empty datagram",
      sorted(set(ps.UDP_SCAN_PORTS) - set(ps.UDP_PROBES)),
      [67, 68, 69, 138, 162, 500, 514, 520, 623, 631, 987, 1434, 3074,
       4500, 9296, 9297, 9302, 11211])
name, payload, transport, scope = ps.build_udp_probe(161, "192.0.2.9")
check("the shipped builder names the probe and its scope",
      (name, bool(scope), transport), ("snmp", True, "unicast"))
check("an unprofiled port is an EMPTY datagram and says so",
      ps.build_udp_probe(520, "192.0.2.9")[0], "empty datagram")


print("\n[2] THE VANTAGE MATRIX: one listener, three binds, two self-scans")
#
# The register's line for section 10 claims a self-scan measures what is
# BOUND. This measures which of the bound ones it reports, with a controlled
# listener rather than an inference. The three cases are the three ways a
# socket can be bound, and the point is that the SAME listener is FOUND by one
# vantage and MISSED by the other two -- so `scan_origin: self` is not by
# itself enough to say what a result covers.

LAN = None
for _iface, _addrs in __import__("psutil").net_if_addrs().items():
    for _a in _addrs:
        if (_a.family == socket.AF_INET and not _a.address.startswith("127.")
                and not _a.address.startswith("172.17.")):
            LAN = _a.address
LAN = LAN or "192.0.2.1"          # RFC 5737, if this host has no LAN address


def _serve(bind_addr, port=0, backlog=8):
    """A listener on `bind_addr`. Port 0 asks the kernel for a free one.

    FIXED PORTS WERE A REAL FRAGILITY, measured while this round's negative
    control was running: the control runs this same file inside a copy of the
    tree, and a run that overlapped with another one died of
    `OSError: [Errno 98] Address already in use` -- which the harness correctly
    reports as a crashed subject, sending the round after a defect that is not
    there. An ephemeral port is what the fixture wanted all along; the tests do
    not care WHICH port answers, only which of the two vantages reaches it.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_addr, port))
    s.listen(backlog)

    def loop(sock=s):
        while True:
            try:
                sock.accept()
            except OSError:
                # The socket is closed under this thread when the case ends.
                # Swallowing it keeps a stray traceback out of the output the
                # negative-control harness parses.
                return

    threading.Thread(target=loop, daemon=True).start()
    return s


def _accept_in_background(sock, n):
    """Accept up to n connections, then stop quietly when sock closes."""
    def loop():
        for _ in range(n):
            try:
                sock.accept()
            except OSError:
                return
    threading.Thread(target=loop, daemon=True).start()


def _probe_wire(host, port):
    """The SHIPPED TCP probe, driven for one port only."""
    return ps.PortScanner("matrix")._check_port(host, port)


def _found(host, port):
    sc = ps.PortScanner("matrix")
    sc._check_port = lambda h, p: (p == port) and _probe_wire(h, p)
    sc._check_udp_port = lambda h, p: {"state": "no_answer",
                                       "probe": "stubbed", "banner": None}
    out = sc.scan(host, port_set="common")
    return any(e["port"] == port for e in out["open_ports"]), out


CASES = [
    ("bound to 127.0.0.1 only", "127.0.0.1", 4444),
    ("bound to this host's LAN address", LAN, 6667),
    ("bound to 0.0.0.0 (every interface)", "0.0.0.0", 8888),
]
# THE PORTS ARE FIXED ON PURPOSE: the matrix drives the SHIPPED scan over
# port_set="common", so the port under test has to be one the common set
# actually contains -- an ephemeral port is never probed and every case would
# report "not found" for the wrong reason. That means two copies of this file
# at once (the round's own negative control runs one, inside a copy of the
# tree) can collide. Measured: `OSError: [Errno 98] Address already in use`
# killed the subject mid-run and the control reported a crashed subject. So an
# occupied port is SKIPPED IN WORDS rather than taken, the rule for a test that
# reads a real artifact of the machine it is on.
for label, bind_addr, port in CASES:
    try:
        s = _serve(bind_addr, port)
    except OSError as e:
        print(f"  SKIP  {label}, port {port}: this machine will not give that "
              f"port to the fixture ({e}). The case is asserted in section [2] "
              f"only when the port is free; nothing else here depends on it.")
        continue
    time.sleep(0.15)
    by_loop, out_loop = _found("127.0.0.1", port)
    by_lan, out_lan = _found(LAN, port)
    print(f"  -- {label}, port {port}")
    check("both scans call themselves a self-scan",
          (out_loop["scan_origin"], out_lan["scan_origin"]), ("self", "self"))
    if bind_addr == "0.0.0.0":
        check("bound everywhere: BOTH vantages reach it", (by_loop, by_lan),
              (True, True))
    elif bind_addr == "127.0.0.1":
        check("bound to loopback: the loopback vantage finds it, the LAN one"
              " does not", (by_loop, by_lan), (True, False))
    else:
        check("bound to one interface: only the scan of THAT address finds it",
              (by_loop, by_lan), (False, True))
    s.close()
    time.sleep(0.2)

print("\n  -- the payload says WHICH address it asked, so the matrix is visible")
# Its own port, distinct from the three above, for the same reason they are
# distinct from each other: a socket under a case must not be reused.
out = None
s = None
try:
    s = _serve("0.0.0.0", 9999)
except OSError as e:
    print(f"  SKIP  the payload-address case: port 9999 is taken ({e})")
if s is not None:
    time.sleep(0.15)
    _, out = _found("127.0.0.1", 9999)
    check("the scan names the address it was given", out["host"], "127.0.0.1")
if out is None:
    # Section [8] and [9] read `out` too. They need a scan of SOME sort, and a
    # scan of this host costs nothing here. A skip in section [2] must not take
    # the later sections down with it.
    _, out = _found("127.0.0.1", 9999)
rows = out["udp_no_answer"]
check("every silent row carries the address its probe went to",
      sorted({r.get("probed_address") for r in rows}), ["127.0.0.1"])
# The row for a port that HAS a real probe names it; the row for one that does
# not says so. Read from the row rather than from a list index, because the
# silent list is sorted by port and 67 sorts first.
#
# The wire is STUBBED in _found() for the TCP matrix above, so what this
# asserts is that the probe name the probe returned reaches the ROW -- not that
# the name is 'mdns'. The real probe names are asserted in section [1] against
# the payload table, and the live one in section [3].
by_port = {r["port"]: r for r in rows}
if by_port:
    check("every silent row carries the probe it was asked by",
          sorted({r.get("probe") for r in rows}), ["stubbed"])
check_true("and the rows carry the same address on all of them",
           all(r.get("probed_address") == "127.0.0.1" for r in rows))
# GUARDED, 2026-09-25, AND THIS ONE WAS FOUND BY THE NEGATIVE CONTROL. The
# case above SKIPS IN WORDS when port 9999 is taken, which leaves `s` as None
# -- and the next line closed it anyway, so the whole file died of
# `AttributeError: 'NoneType' object has no attribute 'close'` and every check
# AFTER it stopped running. The harness correctly called that a crashed
# subject, and the round went looking for a defect in the module before
# finding it here: a SKIP path that cannot finish is not a skip.
if s is not None:
    s.close()


print("\n[3] A WORKING mDNS RESPONDER IS NO LONGER REPORTED AS SILENT")
#
# THE DEFECT WAS A QUESTION, NOT A TRANSPORT BUG, and the proof is a live
# responder answering the new question where it did not answer the old one.
# A test that reads a real artifact must SKIP IN WORDS when it is absent, so
# this one says so when nothing is listening on 5353 rather than passing quietly.

probe = ps.build_udp_probe(5353, "127.0.0.1")[1]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)
replied = None
try:
    s.sendto(probe, ("127.0.0.1", 5353))
    data, _addr = s.recvfrom(8192)
    replied = len(data)
except socket.timeout:
    replied = None
except OSError as e:
    replied = f"OSError: {e}"
finally:
    s.close()
if replied is None:
    print("  SKIP  nothing on this machine answered UDP 5353 within 2 s, so "
          "the live half of this check cannot run on this host. The question "
          "the probe asks is asserted in section [1] regardless.")
elif isinstance(replied, str):
    print(f"  SKIP  the probe could not be sent here ({replied})")
else:
    check_true("a live responder ANSWERED the reverse address PTR",
               isinstance(replied, int) and replied > 0,
               f"{replied} bytes")

# The old question is kept as a NEGATIVE control, measured rather than
# remembered: it is the packet that got no reply, and if it ever starts
# answering, the reason for this fix has changed and the round should be told.
old = (b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
       b"\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.5)
old_replied = None
try:
    s.sendto(old, ("127.0.0.1", 5353))
    old_replied = len(s.recvfrom(8192)[0])
except socket.timeout:
    old_replied = None
except OSError:
    old_replied = None
finally:
    s.close()
print(f"  INFO  the SUPERSEDED question got "
      f"{'a reply of %d bytes' % old_replied if old_replied else 'no reply'}"
      f" here (recorded, not asserted: this is the measurement the fix rests on)")


print("\n[4] IPv6: the pass reaches the target at all")
#
# Measured before the fix: _check_udp_port('::1', 53) -> probe_failed with
# "[Errno -9] Address family for hostname not supported", 25 times out of 25,
# because the socket was built AF_INET whatever the target was.
#
# THIS SECTION WAS REWRITTEN AFTER ITS OWN NEGATIVE CONTROL CAUGHT IT, and the
# control's verdict is worth recording because it was right for a reason it did
# not know. The first version asserted OUTCOMES -- "the state is one of open /
# closed / no_answer" and "no probe failed" -- and on this host BOTH hold
# against the pre-fix code as well, because ::1:53 refuses on the v4 path for
# reasons of its own and the failed list happens to stay empty. A check that
# asserts an outcome cannot see a defect that changes only the MECHANISM, so
# the checks below drive the SOCKET FAMILY DIRECTLY and assert the family the
# shipped code actually opened.
#
# THE TCP HALF OF THIS DEFECT IS RETRACTED, and it is recorded here rather than
# deleted. The round claimed "create_connection returns False for a v6 target
# here, so an IPv6 host answered nothing open over both protocols". Re-measured
# on this host: create_connection(('::1', 631)) CONNECTS and ('::1', 59999)
# raises ConnectionRefusedError, so the old call raised on every outcome and its
# False was correct. The round's own record carried `tcp_open=1` for the ::1
# self-scan in the same section as the sentence saying it was zero, and nobody
# read the two against each other. What IS real on the TCP side is the NARROWING
# the first version of this round's OWN fix introduced: `info[0]` alone, where
# the body it replaced walked every answer the resolver returned. That gets its
# own checks below.
#
# AND THE CHECKS FOR THE UDP HALF ARE DRIVEN RATHER THAN INFERRED. The first
# version asserted OUTCOMES ("the state is one of open/closed/no_answer", "no
# probe failed"), and on this host BOTH hold against the pre-fix code as well --
# ::1:53 refuses on the v4 path for reasons of its own, so the state comes back
# `closed` and the failed list stays empty. A check that asserts an outcome
# cannot see a defect that changes only the MECHANISM, so the checks below
# record which socket family the shipped code actually opens.

v6 = ps.PortScanner("v6")
r53 = v6._check_udp_port("::1", 53)
check("a v6 UDP probe is no longer a family failure",
      r53["state"] in ("open", "closed", "no_answer"), True)
check_true("and it is not carrying the address-family errno",
           "Address family" not in (r53.get("error") or ""),
           r53.get("error"))

# THE FAMILY, DRIVEN. Against the pre-fix code these record AF_INET for a ::1
# target and go red; that is the assertion the first version of this section
# did not have.
_opens = []
_real_socket = socket.socket


class _RecordingSocket(_real_socket):
    def __init__(self, family=-1, type=-1, proto=-1, fileno=None):
        _opens.append((int(family), int(type)))
        if fileno is None:
            super().__init__(family, type, proto)
        else:
            super().__init__(family, type, proto, fileno)


socket.socket = _RecordingSocket
try:
    ps.PortScanner("fam")._check_udp_port("::1", 53)
finally:
    socket.socket = _real_socket
_dgram_families = sorted({f for f, t in _opens if t == socket.SOCK_DGRAM})
check("the UDP probe for a ::1 target opens an AF_INET6 datagram socket",
      _dgram_families, [int(socket.AF_INET6)])

_opens.clear()
socket.socket = _RecordingSocket
try:
    ps.PortScanner("fam")._check_port("::1", 631)
finally:
    socket.socket = _real_socket
_stream_families = sorted({f for f, t in _opens if t == socket.SOCK_STREAM})
check("and the TCP probe for a ::1 target opens an AF_INET6 stream socket",
      _stream_families, [int(socket.AF_INET6)])

# THE NARROWING, which is the half of the v6 work that was a REAL regression:
# `info[0]` alone drops the resolver's other answers, and socket.create_connection
# -- the body this replaced -- walks ALL of them. A name resolving to one dead
# and one live address is the case that separates the two, built against a
# listener we own.
print("\n  -- every resolved address is tried, not only the first")
_srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
_srv.bind(("::1", 0))
_srv.listen(8)
_v6port = _srv.getsockname()[1]
_accept_in_background(_srv, 8)
time.sleep(0.15)
_dead = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
try:
    _dead.bind(("::1", 0))
    _deadport = _dead.getsockname()[1]
finally:
    _dead.close()          # bound and released: nothing is listening there now


def _multi_addr_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    """A resolver that answers with a DEAD address first, then a live one."""
    return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "",
             ("::1", _deadport, 0, 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "",
             ("::1", _v6port, 0, 0))]


_real_gai = socket.getaddrinfo
socket.getaddrinfo = _multi_addr_getaddrinfo
try:
    _walked = ps.PortScanner("walk")._check_port("multi.test", 0)
finally:
    socket.getaddrinfo = _real_gai
check("a name whose FIRST answer is dead and whose SECOND is live is FOUND",
      _walked, True)
print("     (this is the check the first version of the fix would fail: it")
print("      read info[0] and returned False on the dead one)")
_srv.close()

check("_check_port reaches a v6 target too (this host has ::1:631 or not, "
      "either way it must not be the family that stops it)",
      isinstance(v6._check_port("::1", 631), bool), True)
check("and it reports this host's own v6 listener as OPEN, measured",
      v6._check_port("::1", 631), True)
out6 = v6.scan("::1", port_set="common")
check("a full self-scan of ::1 reports no failed probes",
      len(out6["udp_probe_failed"]), 0)
check_true("and its TCP half found this host's v6 listener rather than "
           "reporting an empty host",
           out6["tcp_open"] >= 1, out6["tcp_open"])
check("it is still classified as a self-scan", out6["scan_origin"], "self")


print("\n[5] THE SCORING: _is_public answers the platform's question")
#
# The old body was a hand-rolled negation of five narrower flags. Re-measured
# in this host's interpreter (3.12.3), the class it got wrong is CARRIER-GRADE
# NAT, which gets the WAN severity and the WAN note on every port found on it.
#
# TWO CORRECTIONS TO THIS SECTION'S OWN FIRST VERSION, both from reading the
# subject's output instead of the note about it:
#   * the round claimed the old body also called the RFC 2544 range
#     (198.18.0.0/15) public. It does NOT here: that range is in ipaddress's
#     PRIVATE set, so the old body returned False and so does the new one. The
#     checks below still assert the address, but they are pinning a property
#     both bodies share rather than the defect, and they are marked as such.
#   * the first version of the FIX was `bool(addr.is_global)` alone, and
#     is_global is TRUE for MULTICAST on this interpreter -- so it scored a
#     multicast group at the WAN level with "Target is internet-routable." on
#     the row, which the old body got right. The multicast checks are here
#     because of that.

# THE ADDRESSES ARE DERIVED FROM THEIR NETWORKS AT RUN TIME, not written as
# literals, because a bare private-looking literal in a test file is a leak-gate
# hit on every other box too. The ranges are the documented ones and they carry
# the fact; the host address inside each is what the check needs.
def _first_host(net):
    return str(next(ipaddress.ip_network(net).hosts()))


CGNAT = _first_host("100.64.0.0/10")        # RFC 6598 carrier-grade NAT
BENCH = _first_host("198.18.0.0/15")        # RFC 2544 benchmark
DOC = _first_host("192.0.2.0/24")           # RFC 5737 documentation
RESERVED = _first_host("240.0.0.0/4")       # reserved
RFC1918 = _first_host("10.0.0.0/8")         # private
LINK_LOCAL = _first_host("169.254.0.0/16")  # link-local
LOOPBACK = "127.0.0.1"
UNSPEC = "0.0.0.0"

for addr in (CGNAT, BENCH, DOC, RESERVED, RFC1918, LINK_LOCAL, LOOPBACK,
             UNSPEC):
    check(f"{addr} is NOT public", ps._is_public(addr), False)
for addr in ("8.8.8.8", "1.1.1.1"):
    check(f"{addr} IS public", ps._is_public(addr), True)
check("a hostname is not a public ADDRESS, and this answers only about"
      " addresses", ps._is_public("example.com"), False)

print("\n  -- MULTICAST is not a host with reachable ports, and must never")
print("     be scored at the WAN level (is_global alone says True here)")
V4_MCAST = _first_host("224.0.0.0/4")
SSDP_GROUP = "239.255.255.250"              # the SSDP group, a real probe target
for addr in (V4_MCAST, SSDP_GROUP, _first_host("233.252.0.0/24"),
             "ff02::fb", "ff02::1"):
    _ig = ipaddress.ip_address(addr).is_global
    check(f"{addr} is NOT public, though is_global={_ig}",
          ps._is_public(addr), False)
_mc = ps.classify_port(2375, "remote", public=ps._is_public(V4_MCAST))
check("and a port on a multicast target is not scored at the WAN level",
      _mc["risk_level"], "high")
check("nor does its note claim the target is routable",
      "internet-routable" in _mc["note"], False)

# The two must agree, read from ipaddress rather than from a second list.
for addr in (CGNAT, BENCH, "8.8.8.8", RFC1918, _first_host("2001:db8::/32")):
    check(f"{addr}: _is_public agrees with ipaddress.is_global",
          ps._is_public(addr), ipaddress.ip_address(addr).is_global)

print("\n  -- and the note the row carries follows from it")
remote = ps.classify_port(2375, "remote", public=False)
public = ps.classify_port(2375, "remote", public=True)
check("LAN scoring is unchanged for a private target",
      (remote["risk_level"], remote["category"]), ("high", "rce"))
check("a genuinely public target still gets the WAN level",
      (public["risk_level"], "Target is internet-routable." in public["note"]),
      ("critical", True))


print("\n[6] THIS MACHINE BY ITS OWN NAME IS A SELF-SCAN")
#
# Measured before the fix: the hostname resolved to 127.0.1.1, an address the
# psutil walk does not report, so a scan by name was classified `remote` and
# scored at LAN/WAN severity -- a claim about reachability from elsewhere for a
# scan the machine ran on itself.

hostname = socket.gethostname()
local = ps._local_addresses()
check("the machine's own name is in its own address set",
      hostname in local, True)
try:
    resolved = socket.gethostbyname_ex(hostname)[2]
except Exception:
    resolved = []
for addr in resolved:
    check(f"and so is what it resolves to ({addr})", addr in local, True)
check("localhost and the loopback addresses are still there",
      {"localhost", "127.0.0.1", "::1"} <= local, True)

out_local = ps.PortScanner("by-name").scan(hostname, port_set="common")
check("a scan by the machine's own name is recorded as a SELF-scan",
      out_local["scan_origin"], "self")


print("\n[7] A BROKEN LOOKUP DOES NOT POISON THE NEXT SCAN")
#
# Measured before the fix: the error attribute was assigned only on failure and
# never cleared, so one broken sweep made EVERY later self-scan say "COULD NOT
# BE DONE" -- including scans whose own owner blocks were attached correctly
# underneath the sentence.

import tools.port_owner as po                 # noqa: E402
_real_q = po.query_listeners
scanner = ps.PortScanner("sticky")
scanner._check_port = lambda h, p: False
scanner._check_udp_port = lambda h, p: {"state": "no_answer", "probe": "stub",
                                        "banner": None}
try:
    po.query_listeners = lambda *a, **k: (_ for _ in ()).throw(
        RuntimeError("simulated lookup failure"))
    broke = scanner.scan("127.0.0.1")
finally:
    po.query_listeners = _real_q
healthy = scanner.scan("127.0.0.1")
check_in("the broken scan says the lookup could not be done",
         "COULD NOT BE DONE", broke["owner_lookup"])
check("the scan after it does NOT repeat that sentence",
      "COULD NOT BE DONE" in healthy["owner_lookup"], False)
check_in("and it carries the ordinary explanation instead",
         "carries an `owner` block", healthy["owner_lookup"])


print("\n[8] THE RUN RECORD COUNTS EVERY PROBE THE RUN SENDS")
#
# Measured before the fix: 'common' recorded port_count 55 while sending 80
# probes, and the row's own `protocols` column said "tcp,udp".

con = sqlite3.connect(db)
runs = con.execute("SELECT port_set, port_count FROM port_scan_run").fetchall()
check("at least one run was recorded", len(runs) > 0, True)
for set_name in ps.PORT_SET_NAMES:
    counts = sorted({n for s, n in runs if s == set_name})
    if not counts:
        continue
    expected = len(ps._port_set(set_name)) + len(
        set(ps.UDP_SCAN_PORTS)
        | {p for p in ps._port_set(set_name) if p in ps.UDP_PORT_FACTS})
    check(f"{set_name}: port_count is the TCP+UDP total, not the TCP half",
          counts, [expected])

print("\n  -- and the payload publishes both halves as separate counts")
sc = ps.PortScanner("counts")
sc._check_port = lambda h, p: False
sc._check_udp_port = lambda h, p: {"state": "no_answer", "probe": "stub",
                                   "banner": None}
out = sc.scan("127.0.0.1", port_set="common")
check("udp_scanned is the whole UDP set", out["udp_scanned"],
      len(ps.UDP_SCAN_PORTS))
check("udp_with_request plus udp_empty_datagram equals udp_scanned",
      out["udp_with_request"] + out["udp_empty_datagram"], out["udp_scanned"])
check("seven of them carry a real request", out["udp_with_request"], 7)
check("eighteen are empty datagrams", out["udp_empty_datagram"], 18)


print("\n[9] WHAT THE SCOPE SENTENCE CLAIMS, NOW THAT IT CAN BE CHECKED")
#
# The sentence said every UDP port was asked "with a real datagram" while 18 of
# 25 got an empty one. It is read by the MODEL, so a claim it cannot check is a
# claim it will repeat.

scope = out["scan_scope"]
msg = out["message"]
check("the sentence names the number with a real request",
      "7 carry a real request" in scope, True)
check("and the number with an empty datagram",
      "18 were sent an EMPTY datagram" in scope, True)
check("it still refuses to call UDP silence closed",
      "only an ICMP unreachable proves nothing is" in scope, True)
check("and still forbids reporting a silent port as absent",
      "Do not report any of them as absent" in scope, True)
check("a silent row is named WITH its probe",
      all("probe" in row for row in out["udp_no_answer"]), True)
check_true("the sentence says what an empty-datagram silence settles",
           "settles nothing short of an ICMP unreachable" in scope)

print("\n  -- status() publishes the same two lists rather than implying them")
st = ps.PortScanner("st").status()
check("status names the ports with a real request", st["udp_ports_with_request"],
      sorted(ps.UDP_PROBES))
check("and the ports asked with an empty datagram",
      st["udp_ports_empty_datagram"],
      sorted(set(ps.UDP_SCAN_PORTS) - set(ps.UDP_PROBES)))
check("both protocols are still declared", st["protocols"], ["tcp", "udp"])
check("and the UDP scope note is still on it",
      st["udp_scope"] == ps.UDP_SCOPE_NOTE, True)


print("\n[10] THE FOUND-CLEAN LIST: what this round checked and did NOT change")
#
# An audit that lists only defects cannot be told apart from one that only
# looked for them, so the things this round read and left alone are asserted
# here -- if one of them moves, this section says so rather than going quiet.

check("the UDP answers are still separate lists (filtered added, PS-20)",
      sorted(k for k in out if k.startswith("udp_") and isinstance(out[k], list)),
      ["udp_closed_by_icmp", "udp_filtered_by_icmp", "udp_no_answer",
       "udp_not_tested", "udp_probe_failed"])
check("udp_not_tested is computed, not assumed: empty because the pass now"
      " covers every profiled port", out["udp_not_tested"], [])
check("a self-scan is still capped at low severity",
      ps.classify_port(2375, "self")["risk_level"], "low")
check("and it still says WHAT a self-scan proves",
      "this shows the service is bound" in ps.classify_port(2375, "self")["note"],
      True)
check("no finding is raised by a scan, on purpose (TODO 38.5)",
      "save_finding" in SRC.split("def scan(", 1)[1], False)
check("the observation is still recorded",
      "save_port_scan_result" in SRC.split("def scan(", 1)[1], True)
check("the expected-port declaration still silences only the alarm",
      "No finding raised" in SRC, True)
check("an empty datagram is still sent to an unprofiled port, and still"
      " cannot prove open",
      ps.build_udp_probe(520, "192.0.2.9")[1], b"")


print("\n[11] PS-11: THE DEAD EXPORT IS GONE, AND THE SCAN LIST IS NOT IT")
#
# Measured before the fix: `COMMON_PORTS = {port: profile[0] for port, profile
# in PORT_PROFILES.items()}` at tools/port_scanner.py:160, and a grep across
# BOTH trees -- every file type -- returned that one line. Zero consumers.
#
# The name was the vestige of the coupling the 2026-08-19 change removed: the
# scan list and the annotation table used to be the same object, and the scan
# list is `_port_set()` now. So the checks below pin BOTH halves -- the name is
# gone, and the thing it might have been mistaken for is still exactly what it
# was.
#
# THE ASSERTION IS ON THE RUNNING CODE, not on the file's text. A whole-file
# search for the token would match this very comment explaining why it went;
# `hasattr` reads the module that actually imported.
check("the dead export is not an attribute of the module any more",
      hasattr(ps, "COMMON_PORTS"), False)
# THE TOKEN SEARCH IS ON THE RUNNING CODE, NOT THE FILE. A whole-file grep
# matches the comment in port_scanner.py that EXPLAINS why the name was
# deleted -- "an assertion that a token is GONE will match the fix's own
# explanation of why it went", which this project has paid for. So the file's
# comments are stripped first, and the check asserts the stripper did
# something, or it passes for the wrong reason.
_stripped_src = "\n".join(
    line for line in SRC.splitlines() if not line.lstrip().startswith("#"))
check("the stripper is doing something (the token IS in this file's prose)",
      "COMMON_PORTS" in SRC and "COMMON_PORTS" not in _stripped_src, True)
check("and in the RUNNING code the name appears nowhere",
      "COMMON_PORTS" in _stripped_src, False)
_grep = __import__("subprocess").run(
    ["grep", "-rln", "^COMMON_PORTS", str(ROOT),
     "--include=*.py", "--include=*.js", "--include=*.html", "--include=*.sh"],
    capture_output=True, text=True)
check("and no other code file in the tree mentions it at all",
      _grep.stdout.strip(), "")
check("the scan list is still `_port_set`, which is what replaced it",
      len(ps._port_set("common")) > 0 and ps._port_set("common")
      == sorted(ps.PORT_PROFILES), True)
check("and the annotation table still carries the service names",
      ps.PORT_PROFILES[22][0], "SSH")


print("\n[12] PS-14: THE SWITCH THAT NOTHING READ NOW REFUSES (AR-12's shape)")
#
# Measured before the fix: config.json carried
# `"port_scanner": {"enabled": true, "poll_interval": 600}` and a grep across
# main.py, adapters.py, core/ and tools/ found NO READER of either key. The
# module was built directly in main.py and pull-only, so there was no loop for
# the key to gate -- the shape the autoruns round closed as AR-12.
#
# The owner's answer there, taken up here for the same reason, is that the
# switch REFUSES. Both directions are asserted, because a switch that refuses
# everything is as broken as one that refuses nothing.

print("\n  -- the three shapes of the config, read the way every other sensor"
      " reads them")
check("no config at all is ON", ps.scan_enabled({})[0], True)
check("an empty sensors block is ON", ps.scan_enabled({"sensors": {}})[0], True)
check("an empty port_scanner block is ON",
      ps.scan_enabled({"sensors": {"port_scanner": {}}})[0], True)
check("and it names why it could not be switched off",
      ps.scan_enabled({})[1], "no key is set, so it is ON")
check("explicitly false is OFF",
      ps.scan_enabled({"sensors": {"port_scanner": {"enabled": False}}})[0],
      False)
check("  and names the key that switched it off",
      ps.scan_enabled({"sensors": {"port_scanner": {"enabled": False}}})[1],
      "sensors.port_scanner.enabled")

print("\n  -- switched off: the scan REFUSES by name, and reads nothing")
_off_cfg = {"sensors": {"port_scanner": {"enabled": False}}}
_off_scanner = ps.PortScanner("off", config=_off_cfg)

# NOTHING IS READ WHILE OFF. Every enumerator this module has is instrumented
# and the call list must be EMPTY -- a gate that returns early but had already
# probed something is the same defect one layer down, which is the rule the
# AR-12 round wrote down.
_called = []
_real_local, _real_run, _real_udp = (ps._local_addresses, ps.PortScanner._run_scan,
                                     ps.PortScanner._run_udp_scan)
ps._local_addresses = lambda: _called.append("_local_addresses") or set()
ps.PortScanner._run_scan = lambda self, *a, **k: _called.append("_run_scan") or []
ps.PortScanner._run_udp_scan = lambda self, *a, **k: (
    _called.append("_run_udp_scan") or {"open": [], "closed": [], "silent": [],
                                        "failed": []})
_before_runs = sqlite3.connect(db).execute(
    "SELECT COUNT(*) FROM port_scan_run").fetchone()[0]
try:
    _refusal = _off_scanner.scan("127.0.0.1", port_set="common")
finally:
    ps._local_addresses = _real_local
    ps.PortScanner._run_scan = _real_run
    ps.PortScanner._run_udp_scan = _real_udp
check("no enumerator was called at all", _called, [])
check("and no run row was written for a scan that did not happen",
      sqlite3.connect(db).execute(
          "SELECT COUNT(*) FROM port_scan_run").fetchone()[0] - _before_runs, 0)
check("the refusal says it is a switch rather than a finding",
      _refusal.get("off_by_config"), True)
check("it carries no open ports", _refusal["open_ports"], [])
check("and it is not reachable-looking: no origin, no public answer",
      (_refusal["scan_origin"], _refusal["target_public"]), (None, None))
check_true("and the sentence says an empty list here is the SWITCH",
           "BECAUSE SCANNING IS OFF" in (_refusal.get("message") or ""),
           _refusal.get("message"))
check_true("and it names the key that turns it back on",
           "sensors.port_scanner" in (_refusal.get("message") or ""),
           _refusal.get("message"))
check("the refusal is shaped like a real answer, so no caller crashes",
      sorted(set(_refusal) - {"off_by_config", "error"}) ==
      sorted(set(ps.PortScanner("on").scan("127.0.0.1", port_set="common"))
             - {"off_by_config", "error", "owner_lookup", "kernel_view"}), True)

print("\n  -- switched off: status renders OFF rather than green")
_off_status = _off_scanner.status()
check("the status says so by name", _off_status.get("off_by_config"), True)
check("it DROPS the key that would render it green",
      "ready" in _off_status, False)
check("and carries the falsy key the row resolves",
      _off_status.get("available"), False)
check_true("and a reason for the row to print",
           bool(_off_status.get("reason")), _off_status.get("reason"))

from core import settings as st_settings                 # noqa: E402
_row = st_settings._module_row("port_scanner", _off_scanner)
check("the readiness page renders it OFF, not healthy",
      _row.get("state"), "off")

print("\n  -- switched on: unchanged, plus the disclosure of the OTHER key")
_on_cfg = {"sensors": {"port_scanner": {"enabled": True,
                                        "poll_interval": 600}}}
_on_scanner = ps.PortScanner("on", config=_on_cfg)
_on_status = _on_scanner.status()
check("switched ON keeps the key the page reads as running",
      _on_status.get("ready"), True)
check("and says the switch is on", _on_status.get("enabled"), True)
check("and it does NOT claim an off state", "off_by_config" in _on_status, False)
check("the row renders ok when the module is on",
      st_settings._module_row("port_scanner", _on_scanner).get("state"), "ok")
# THE OTHER KEY WAS DISCLOSED AS UNREAD, AND THAT IS NO LONGER TRUE —
# RESTATED 2026-09-25 ON THE OWNER'S ANSWER, not deleted, because the old
# assertion is the record of an intermediate state worth keeping. It read:
#
#   status names poll_interval as UNREAD, so it cannot be mistaken for a control
#   with the operator's own value in the sentence
#
# Both were TRUE of the tree that shipped option (b): the sensor was pull-only
# and the key gated nothing, so status() disclosed it rather than leaving it
# looking like a control. The owner then answered PS-14's design question in
# the owner's own words — "I want you to create that back ground clock" — so option
# (a) is built, poll_interval IS the clock's cadence, and a status that still
# said "read by nothing" would now be the lie of the same shape in the other
# direction. These two assertions replace them and pin the new contract in
# BOTH directions: the key is read, AND the sentence still names the
# operator's own value. The clock itself is governed by
# tests/test_port_scanner_clock.py.
check("status no longer claims poll_interval is unread, because it is now "
      "the clock's cadence",
      "NOT read by anything" in (_on_status.get("poll_interval_note") or ""),
      False)
check("and the clock block reports the operator's own value as the interval "
      "in force",
      _on_status.get("clock_interval_seconds"), 600)
check("  and names the key that decided it",
      _on_status.get("clock_interval_key"),
      "sensors.port_scanner.poll_interval")

# THE CONSTRUCTION SITE IS PART OF THE FIX. A gate inside this class cannot
# fire when the only place that builds it never hands it the config, which is
# measured on the autoruns sensor in the same shape (AR-12).
_main = (ROOT / "main.py").read_text(encoding="utf-8")
main_src = _main.split('modules["port_scanner"]')[1].split("modules[")[0]
main_code = "\n".join(line for line in main_src.splitlines()
                      if not line.lstrip().startswith("#"))
check("main.py hands the module the operator's config, which is the half a "
      "class-internal gate cannot do for itself",
      "config=config," in main_code, True)

# AND THE OWNER'S OWN CONFIG IS UNCHANGED FOR THE OWNER. Read from the owner's live file
# rather than assumed: a key that was always true means this is inert until the owner
# flips it.
import json                                              # noqa: E402
_live_cfg_path = ROOT / "config.json"
if _live_cfg_path.exists():
    _live = json.loads(_live_cfg_path.read_text(encoding="utf-8"))
    _live_on = ps.scan_enabled(_live)[0]
    print(f"  INFO  the operator's own config.json says the switch is "
          f"{'ON, so nothing changes for the owner today' if _live_on else 'OFF'}")
    check("the owner's own install is unaffected until the owner flips it",
          _live_on, True)
else:
    print("  SKIP  no config.json in this tree, so the owner's own setting "
          "cannot be read here")


print("\n[13] PS-12: THE PORTS TAB READS THE STORE, NOT THE CURRENT RUN")
#
# Measured before the fix, live store read mode=ro: port_scan_results held 69
# rows across 19 session ids, /api/ports passed the CURRENT session id, and
# main.py mints a new id on every boot -- so querying with a fresh boot's id
# returned 0 rows and the page said "No port scan results yet." Every other
# growing record on that page (packets, events, findings, the Timeline)
# already passes all_sessions or a since-window. This was the one that did not.
#
# The fix is `all_sessions=True` at the route, with the parameter added to
# memory_engine.query_port_scan mirroring query_packets' one of the same name.

print("\n  -- a row written under one session is visible from another")
_sess_a, _sess_b = "PS12-run-a", "PS12-run-b"
me.save_port_scan_result(session_id=_sess_a, target_host="127.0.0.1",
                         port=42424, state="open", service_guess="fixture",
                         risk_level="low", scan_origin="self",
                         protocol="tcp")
check("the row is NOT in the other session's scoped read",
      [r["port"] for r in me.query_port_scan(target_host="127.0.0.1",
                                             session_id=_sess_b)
       if r["port"] == 42424], [])
check("and IS there once all_sessions is on, which is the whole fix",
      [r["port"] for r in me.query_port_scan(target_host="127.0.0.1",
                                             session_id=_sess_b,
                                             all_sessions=True)
       if r["port"] == 42424], [42424])
check("a scoped read still scopes: session A sees its own row",
      [r["port"] for r in me.query_port_scan(target_host="127.0.0.1",
                                             session_id=_sess_a)
       if r["port"] == 42424], [42424])

print("\n  -- and the ROUTE the page loads is the one that passes it")
from api.server import create_app                        # noqa: E402
from core.tool_registry import init_registry             # noqa: E402
_KEY = "ps12-key"
_MODULES = {"port_scanner": ps.PortScanner("route")}
init_registry(_sess_b, _MODULES)     # the registry's session is the "current" one
_app = create_app({"flask": {"host": "127.0.0.1", "port": 5000}},
                  _MODULES, _sess_b, api_key=_KEY)
_cl = _app.test_client()
_r = _cl.get("/api/ports", headers={"X-API-Key": _KEY})
check("the route answers", _r.status_code, 200)
check("and the row from ANOTHER session is in what the page gets",
      [row["port"] for row in _r.get_json() if row["port"] == 42424], [42424])
check("the route no longer passes a session-scoped query",
      "query_port_scan(session_id=sid, target_host=host" in
      (ROOT / "api" / "routes.py").read_text(encoding="utf-8"), False)

# THE MODEL'S OWN READER KEEPS ITS DEFAULT, which is the deliberate half: a
# fresh process answering "what have I scanned" should say this run, and the
# scope control is how it reaches history. Asserted so neither half drifts.
_reg = (ROOT / "core" / "tool_registry.py").read_text(encoding="utf-8")
_qps_call = _reg.split('if name == "query_port_scan"')[1].split("if name ==")[0]
qps_code = "\n".join(line for line in _qps_call.splitlines()
                     if not line.lstrip().startswith("#"))
check("query_port_scan's model path carries all_sessions through",
      '"all_sessions",' in qps_code, True)
check("and the manifest declares the control the model can set",
      '"all_sessions"' in _reg.split('"name": "query_port_scan"')[1].split(
          '"name": "query_dns_clients"')[0], True)
check("and the description states the default scope, so an empty answer is "
      "read as 'this run' rather than 'never seen'",
      "THIS RUN ONLY" in _reg.split('"name": "query_port_scan"')[1].split(
          '"name": "query_dns_clients"')[0], True)


print("\n[14] PS-13, OPTION (c): THE SYN SCAN EXISTS NOW, AND THE ROW SAYS SO")
#
# THIS SECTION HAS BEEN REWRITTEN TWICE AND THE HISTORY IS THE POINT.
#
# Its first version asserted the row was NONE ("a connect scan needs no
# capability") and that the tree contained no raw-socket scan at all. BOTH of
# those were true and the ROW WAS STILL FALSE, because it generalised
# `_check_port` to the whole module -- the self-scan's owner lookup loses every
# root-owned listener unelevated, measured: 0 of 13. The old assertions are
# quoted here rather than deleted, because a check that was green over a false
# sentence is the thing this project keeps finding:
#
#   the row is NONE: a connect scan needs no capability        -> retired
#   a raw-socket SYN scan really is absent from the tree       -> retired
#   and no longer names CAP_NET_RAW as the reason              -> retired
#
# The owner took the third design in the owner's own words -- "do option C and when
# done report back" -- so the module now carries a real SYN pass, the row is
# DEGRADES with both losses named, and THESE are the assertions that match.

from core import privilege_linux as pv                    # noqa: E402
_req = pv.requires_elevation("port_scanner")
check("the privilege row still does not claim the SYN scan is REQUIRED, "
      "because it is not: the connect fallback still scans",
      "SYN scan requires root" in _req.consequence, False)
check("the level is DEGRADES, which is what a module with a working fallback "
      "and a real loss is",
      _req.level, pv.DEGRADES)
check("and the reason names the capability the SYN pass needs",
      "CAP_NET_RAW" in (_req.reason or ""), True)
check("and the consequence names BOTH losses, starting with the method",
      "connect test" in _req.consequence, True)
check("and the OWNER loss, which the first correction of this row missed",
      "OWNER" in _req.consequence, True)
check("and it is still a REGISTERED module, not a gap",
      "port_scanner" in pv.REQUIREMENTS, True)
# THE MODULE THAT HAD NO ROW AT ALL, fixed in the same pass. ASSERTED BY
# MEMBERSHIP, NOT BY CALLING requires_elevation: that function RAISES for an
# unregistered module (deliberately -- the register's own rule), so a check
# that calls it dies instead of FAILING when the entry is gone, and a check
# that dies measures nothing. The negative control for this very check crashed
# the file before it was written this way.
check("port_owner, which had no privilege entry, now has one",
      "port_owner" in pv.REQUIREMENTS, True)
check("and it declares DEGRADES, not NEEDS and not NONE",
      (pv.REQUIREMENTS.get("port_owner").level
       if "port_owner" in pv.REQUIREMENTS else "MISSING"), pv.DEGRADES)

# A RAW-SOCKET SCAN IS IN THE TREE NOW, and the check is the opposite of the
# one it replaces: the module must OPEN a raw TCP socket BY NAME, and the
# retired assertion searched for its absence. Read the RUNNING code rather
# than the file, so this pass's own explanatory comments cannot satisfy it --
# the tree's rule about a whole-file absence assertion.
import inspect                                            # noqa: E402
_module_src = inspect.getsource(ps)
_stripped = "\n".join(line for line in _module_src.splitlines()
                      if not line.lstrip().startswith("#"))
check("the SYN pass really opens a raw TCP socket",
      "SOCK_RAW" in _stripped and "IPPROTO_TCP" in _stripped, True)
check("and its engine is a real class rather than a comment about one",
      inspect.isclass(ps.SynScanEngine), True)
check("and the module reports a METHOD for the TCP pass on demand",
      ps.tcp_probe_method()[0] in ps.TCP_PROBE_METHODS, True)

# THE METHOD IS ON THE PAYLOAD. This is the assertion that would have caught
# the original defect: the privilege row described a scan the module did not
# have. Whatever method a run used, the payload must name it.
#
# EVERY READ IS `.get()`, AND THAT IS NOT STYLE. The negative control for this
# check removes the key, and a check that INDEXES the payload dies of KeyError
# instead of FAILING -- so the harness reads SUBJECT CRASHED and the control
# measures nothing, which is the tree's rule about a run that crashed not being
# a green run, one layer in.
#
# THIS IS A REAL SCAN of this host's own loopback, with only the UDP pass
# stubbed (25 real probes would cost 25 seconds for a fact another section
# already asserts). The TCP half runs the SHIPPED dispatcher, so on a host
# holding CAP_NET_RAW the SYNs here are real SYNs and on this host they are a
# real connect test. A stubbed dispatcher would prove nothing about which
# method runs.
_sc13 = ps.PortScanner("ps13")
_sc13._check_udp_port = lambda h, p: {"state": "no_answer", "probe": "stub",
                                      "banner": None}
result = _sc13.scan("127.0.0.1", port_set="common")
check("a scan payload carries tcp_method",
      "tcp_method" in result, True)
check("and it is one of the two methods, or None when the operator pinned "
      "the SYN scan and it could not run",
      result.get("tcp_method") in (ps.SYN_METHOD, ps.CONNECT_METHOD, None), True)
if result.get("tcp_method") == ps.CONNECT_METHOD:
    # THIS RUN FELL BACK. A refused connect is the target's RST, so a
    # connect run names closed ports too (PS-19); loopback refuses at once,
    # so the closed list is not empty and nothing reads as no_answer.
    check("a connect run names refused ports as closed",
          len(result.get("tcp_closed_by_rst") or []) > 0, True)
    check("and every closed row says it was a refusal",
          all("refused" in r.get("answered_by", "")
              for r in result.get("tcp_closed_by_rst") or []), True)
    check("and the scope sentence names the method that ran",
          "CONNECT TEST" in (result.get("scan_scope") or ""), True)
    check("and names what a raw socket would have bought",
          "CAP_NET_RAW" in (result.get("scan_scope") or ""), True)
    check("and names the capability the connect test does NOT need",
          "CAP_NET_RAW" in (_req.reason or ""), True)
elif result.get("tcp_method") == ps.SYN_METHOD:
    check("a SYN run's scope sentence names the method that ran",
          "RAW SYN SCAN" in (result.get("scan_scope") or ""), True)
    check("and says an RST is the closed answer",
          "tcp_closed_by_rst" in (result.get("scan_scope") or ""), True)
else:
    check("a pinned-SYN refusal says no TCP probe ran",
          result.get("tcp_refused"), True)

# THE CONFIG KEY, PS-13 option (c): three values, an absent key means auto,
# and an UNREADABLE one is reported rather than silently defaulted.
check("an absent tcp_method key means auto, so no existing config changes",
      ps.tcp_method_setting({})[0], ps.TCP_METHOD_SETTING_AUTO)
check("and an unreadable value is reported, not silently swallowed",
      ps.tcp_method_setting({"port_scan": {"tcp_method": 7}})[2] is not None,
      True)
check("and the three settings are the three documented ones",
      ps.TCP_METHOD_SETTINGS,
      (ps.TCP_METHOD_SETTING_AUTO, ps.SYN_METHOD, ps.CONNECT_METHOD))

check("and the setup guide does not repeat the old claim",
      "SYN scanning need privilege" in
      (ROOT / "SETUP.md").read_text(encoding="utf-8"), False)


print("\n" + "=" * 62)
if fails:
    print(f"{len(fails)} FAILED: " + ", ".join(fails))
    sys.exit(1)
print("All port scanner audit checks passed.")
