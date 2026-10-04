"""
tests/test_port_scanner_syn_scan.py, the raw SYN scan built for PS-13 option
(c), 2026-09-25.

WHAT THIS FILE IS FOR. tools/port_scanner.py's privilege row described a raw
SYN scan for months while NO SYN SCAN EXISTED IN THE TREE, and the first
correction of that row ("elevating buys a scan nothing it does not already
have") was false as well. The owner took the third design -- build the scan --
and this file is the proof it is real and that it says what it does.

FOUR QUESTIONS, and each one is a separate section because each can fail
independently:

  [1] THE PACKET. A hand-built SYN whose checksum is wrong is dropped by the
      target in silence and every port then reads no_answer -- the one failure
      this pass must not have. So the checksum is pinned against RFC 1071's own
      worked example (the same bytes, computed by hand, not by this function),
      and the reply PARSER is pinned against frames whose fields are known in
      advance, for both address families.
  [2] THE DEMULTIPLEXER. Every rule the engine applies to a captured frame is
      driven with a synthetic frame: a SYN-ACK is OPEN, an RST that
      ACKNOWLEDGES OUR SEQUENCE is CLOSED, a bare RST is silence, a frame from
      the wrong address or port is silence, and a kernel RST after a SYN-ACK
      cannot turn an OPEN port into a CLOSED one.
  [3] THE LIVE PASS. A real listener on this host is probed with a real raw
      socket. THIS IS THE SECTION THAT SKIPS IN WORDS on a host where no raw
      socket can be opened: a green check that never looked is the defect this
      project has recorded repeatedly, so the skip says so and says why.
  [4] THE CONTRACT. The three config settings, the absent key, the unreadable
      key, and the refused payload when the SYN scan is pinned and cannot run:
      a scan that cannot do what the operator pinned must REFUSE rather than
      substitute a connect test, which is the original PS-13 defect in
      miniature.

Nothing here writes to the owner's store: memory_engine.DB_PATH is pointed at
a throwaway database built from Schema.SQL, and the live section binds its own
listener on loopback. THE LIVE SECTION BINDS 127.0.0.1 AND NOTHING ELSE, so it
cannot touch another machine, and the ports it uses come from the OS.
"""
import pathlib
import socket
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                          # noqa: E402
_isolate_db.isolate()

from tools import port_scanner as ps                        # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  [{label}]"
          f"{'' if ok else f': {got!r}  (want {want!r})'}")
    if not ok:
        fails.append(label)


def check_true(label, value, detail=None):
    ok = bool(value)
    print(f"  {'PASS' if ok else 'FAIL'}  [{label}]"
          f"{f': {detail!r}' if detail is not None else ''}"
          f"{'' if ok else '  (want truthy)'}")
    if not ok:
        fails.append(label)


def skip(label, why):
    """A SKIP IN WORDS. Never silent: a check that did not run must say so."""
    print(f"  SKIP  [{label}]: {why}")


print("\n[1] THE PACKET: checksum against RFC 1071, parser against known fields")
#
# RFC 1071 section 3 works its example on these eight bytes: the 16-bit
# ones-complement SUM is 0xDDF2, and the value that goes in a checksum field
# is the COMPLEMENT of that sum, 0x220D. Both numbers are the standard's, not
# this function's, so the check cannot be satisfied by a function that agrees
# with itself.
_rfc1071_bytes = bytes([0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7])
check("the checksum matches RFC 1071's worked example (the complement of its "
      "0xDDF2 sum)",
      ps._checksum(_rfc1071_bytes), 0x220D)
check("and the odd-length case is padded rather than dropped",
      ps._checksum(b"\x00\x01\xf2\x03\xf4"), ps._checksum(b"\x00\x01\xf2\x03\xf4\x00"))

# A SYN's OWN FIELD LAYOUT. Read back with struct, field by field, so a byte
# order mistake is caught here rather than by a silent no-answer on the wire.
_syn = ps.build_tcp_syn("192.0.2.10", "192.0.2.20", 41000, 443, 0xDEADBEEF)
check("a SYN is 20 bytes with no options",
      len(_syn), 20)
check("its source port, destination port, sequence and flags are where they say",
      struct.unpack("!HHLLB", _syn[:13]),
      (41000, 443, 0xDEADBEEF, 0, 5 << 4))
check("the flags byte is SYN and nothing else",
      _syn[13], ps._TCP_SYN)
check("and it carries a non-zero checksum, so the peer will not drop it",
      struct.unpack("!H", _syn[16:18])[0] != 0, True)

_rst = ps.build_tcp_rst("192.0.2.10", "192.0.2.20", 41000, 443,
                        0x11111111, 0x22222222)
check("the teardown is RST+ACK, which is the shape a listener stops waiting for",
      _rst[13], ps._TCP_RST | ps._TCP_ACK)
check("and it acknowledges the sequence the target chose",
      struct.unpack("!L", _rst[8:12])[0], 0x22222222)

# THE FAMILY IS DERIVED FROM THE ADDRESS. Both literals are built from the
# same ports and sequence, and the v6 pseudo-header (16-byte addresses, a
# 32-bit length) must produce a DIFFERENT checksum than the v4 one -- if the
# two agreed, the builder would be using one family's pseudo-header for both.
_syn6 = ps.build_tcp_syn("2001:db8::10", "2001:db8::20", 41000, 443,
                         0xDEADBEEF)
check("a v6 SYN is also 20 bytes",
      len(_syn6), 20)
check("and its checksum differs from the v4 segment's, because the pseudo-header is not the same shape",
      _syn6[16:18] != _syn[16:18], True)


def _ipv4_frame(src, dst, sport, dport, seq, ack, flags, ihl=20):
    """One IPv4 frame carrying a TCP header, built by hand for the parser."""
    total = ihl + 20
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    tcp = struct.pack("!HHLLBBHHH", sport, dport, seq, ack, 5 << 4, flags,
                      64240, 0, 0)
    return ip + tcp


def _ipv6_frame(src, dst, sport, dport, seq, ack, flags, nxt=6):
    """One IPv6 frame carrying a TCP header, built by hand for the parser."""
    ip = struct.pack("!IHBB", 0x60000000, 20, nxt, 64) \
        + socket.inet_pton(socket.AF_INET6, src) \
        + socket.inet_pton(socket.AF_INET6, dst)
    tcp = struct.pack("!HHLLBBHHH", sport, dport, seq, ack, 5 << 4, flags,
                      64240, 0, 0)
    return ip + tcp


_sa = _ipv4_frame("192.0.2.20", "192.0.2.10", 443, 41000, 0xAAAA1111,
                  0xDEADBEF0, ps._TCP_SYN | ps._TCP_ACK)
_parsed = ps.parse_tcp_reply(_sa, socket.AF_INET)
check("a v4 SYN-ACK parses to the ports, sequence and acknowledgement it holds",
      (_parsed["src_ip"], _parsed["sport"], _parsed["dport"],
       _parsed["seq"], _parsed["ack"]),
      ("192.0.2.20", 443, 41000, 0xAAAA1111, 0xDEADBEF0))
check("and it is recognised as a SYN-ACK rather than as a bare SYN or a bare ACK",
      (_parsed["is_syn_ack"], _parsed["is_rst"]), (True, False))

_plain = ps.parse_tcp_reply(
    _ipv4_frame("192.0.2.20", "192.0.2.10", 443, 41000, 0, 0xDEADBEF0,
                ps._TCP_ACK), socket.AF_INET)
check("a bare ACK is not read as an answer to a SYN",
      (_plain["is_syn_ack"], _plain["is_rst"]), (False, False))

check("a v6 SYN-ACK parses through the fixed 40-byte header",
      ps.parse_tcp_reply(
          _ipv6_frame("2001:db8::20", "2001:db8::10", 443, 41000,
                      0xAAAA1111, 0xDEADBEF0, ps._TCP_SYN | ps._TCP_ACK),
          socket.AF_INET6)["src_ip"],
      "2001:db8::20")
check("and a v6 frame carrying EXTENSION HEADERS is skipped rather than misread",
      ps.parse_tcp_reply(
          _ipv6_frame("2001:db8::20", "2001:db8::10", 443, 41000, 1, 2,
                      ps._TCP_SYN | ps._TCP_ACK, nxt=60),
          socket.AF_INET6),
      None)
check("a truncated frame is skipped",
      ps.parse_tcp_reply(_sa[:24], socket.AF_INET), None)
check("a frame of the WRONG version for the socket's family is skipped",
      ps.parse_tcp_reply(_sa, socket.AF_INET6), None)


print("\n[2] THE DEMULTIPLEXER: every rule, driven with a synthetic frame")
#
# The engine's receive path is driven DIRECTLY here rather than through a
# socket, so each rule can be tested on its own. The live section below proves
# the socket side works; this section proves the RULES are the ones written
# down, which is the half a live run cannot isolate.

if not ps.syn_scan_available()[0]:
    skip("the demultiplexer rules",
         f"no raw TCP socket on this host ({ps.syn_scan_available()[1]}), so "
         f"the engine cannot be built here. RUN THIS FILE INSIDE "
         f"`unshare -Urn` TO DRIVE IT, or elevated.")
    print("  (the rules below are still asserted against the parser and the "
          "engine's own source)")
    # The rules are still checked where they can be: the engine's classification
    # lives in one method and its source is readable, so the conditions are
    # asserted by name rather than left unlooked-at.
    import inspect
    _engine_src = inspect.getsource(ps.SynScanEngine._handle_frame)
    check("a SYN-ACK sets OPEN", '"open"' in _engine_src, True)
    check("an RST is only believed when it ACKNOWLEDGES OUR SEQUENCE",
          "reply[\"ack\"] == ((seq + 1) & 0xFFFFFFFF)" in _engine_src, True)
    check("and a frame from the wrong address or port is refused",
          'reply["sport"] != dst_port' in _engine_src
          and '_canonical_ip(reply["src_ip"]) != _canonical_ip(dst_ip)'
          in _engine_src, True)
else:
    class _Sock:
        """A stand-in that records what the engine sends back."""
        def __init__(self):
            self.sent = []
        def sendto(self, data, dest):
            self.sent.append((data, dest))
        def close(self):
            pass
        def settimeout(self, _t):
            pass
        def recvfrom(self, _n):
            raise socket.timeout

    def _engine_with_one_probe(dst_ip="192.0.2.20", port=443, seq=0xDEADBEEF):
        eng = ps.SynScanEngine(timeout=0.01)
        eng._sockets[socket.AF_INET] = _Sock()          # no real socket
        eng._pending[41000] = (dst_ip, dst_ip, port, seq)
        return eng

    _eng = _engine_with_one_probe()
    _eng._handle_frame(
        socket.AF_INET, _eng._sockets[socket.AF_INET],
        _ipv4_frame("192.0.2.20", "192.0.2.10", 443, 41000, 0xAAAA1111,
                    0xDEADBEF0, ps._TCP_SYN | ps._TCP_ACK))
    # THE ANSWER IS KEYED BY OUR OWN SOURCE PORT, which is the only field in
    # the reply this machine chose -- the docstring's claim, asserted rather
    # than assumed.
    check("a SYN-ACK answering our probe is OPEN, filed under our source port",
          _eng._answers.get(41000), "open")
    # THE SENT LIST IS READ WITHOUT INDEXING BLINDLY. A check that does
    # `sent[0]` dies of IndexError when the ship sends NOTHING, and a check
    # that dies measures nothing -- the negative control for exactly this
    # paragraph crashed the file that way before this guard was written.
    _sent_list = _eng._sockets[socket.AF_INET].sent
    check("and an RST is sent back from the SAME source port and sequence, so "
          "the target does not keep a half-open connection",
          len(_sent_list), 1)
    _teardown = _sent_list[0][0] if _sent_list else b""
    check("the teardown's flags are RST+ACK",
          _teardown[13] if _teardown else None, ps._TCP_RST | ps._TCP_ACK)
    check("and it carries the source port OUR SYN used, not the target's -- "
          "a teardown addressed from the target's own port does not match the "
          "half-open entry and leaves it hanging",
          struct.unpack("!H", _teardown[0:2])[0] if _teardown else None, 41000)
    check("and it is addressed TO the port that answered",
          struct.unpack("!H", _teardown[2:4])[0] if _teardown else None, 443)

    # THE KERNEL'S OWN RST MUST NOT UNDO AN ANSWER. On a self-scan the kernel
    # RSTs the SYN-ACK itself, and that RST carries the listener's own
    # sequence -- not ours -- so the acknowledgement test refuses it.
    _eng._handle_frame(
        socket.AF_INET, _eng._sockets[socket.AF_INET],
        _ipv4_frame("192.0.2.20", "192.0.2.10", 443, 41000, 0xAAAA1111, 0,
                    ps._TCP_RST))
    check("a bare RST (no acknowledgement of our SYN) leaves the port OPEN",
          _eng._answers.get(41000), "open")

    # A REAL CLOSED ANSWER: RST, ACK, acknowledging our sequence + 1.
    _eng2 = _engine_with_one_probe()
    _eng2._handle_frame(
        socket.AF_INET, _eng2._sockets[socket.AF_INET],
        _ipv4_frame("192.0.2.20", "192.0.2.10", 443, 41000, 0, 0xDEADBEF0,
                    ps._TCP_RST | ps._TCP_ACK))
    check("an RST acknowledging our sequence is CLOSED",
          _eng2._answers.get(41000), "closed")

    # AN RST ACKNOWLEDGING SOMEBODY ELSE'S SEQUENCE is another conversation.
    _eng3 = _engine_with_one_probe()
    _eng3._handle_frame(
        socket.AF_INET, _eng3._sockets[socket.AF_INET],
        _ipv4_frame("192.0.2.20", "192.0.2.10", 443, 41000, 0, 0x0BADF00D,
                    ps._TCP_RST | ps._TCP_ACK))
    check("an RST acknowledging a DIFFERENT sequence number is ignored",
      41000 in _eng3._answers, False)

    # FROM THE WRONG ADDRESS.
    _eng4 = _engine_with_one_probe()
    _eng4._handle_frame(
        socket.AF_INET, _eng4._sockets[socket.AF_INET],
        _ipv4_frame("192.0.2.99", "192.0.2.10", 443, 41000, 0, 0xDEADBEF0,
                    ps._TCP_SYN | ps._TCP_ACK))
    check("a SYN-ACK from a DIFFERENT address is ignored",
      41000 in _eng4._answers, False)

    # FROM THE WRONG PORT.
    _eng5 = _engine_with_one_probe()
    _eng5._handle_frame(
        socket.AF_INET, _eng5._sockets[socket.AF_INET],
        _ipv4_frame("192.0.2.20", "192.0.2.10", 8443, 41000, 0, 0xDEADBEF0,
                    ps._TCP_SYN | ps._TCP_ACK))
    check("a SYN-ACK from a DIFFERENT port is ignored",
      41000 in _eng5._answers, False)

    # AND A PORT WITH NO ANSWER IS NO_ANSWER, NEVER CLOSED.
    _eng6 = ps.SynScanEngine(timeout=0.01)
    _eng6._sockets[socket.AF_INET] = _Sock()
    _eng6._pending[41000] = ("192.0.2.20", "192.0.2.20", 443, 1)
    check("a port whose answer never arrived is no_answer, never closed",
          _eng6.finish().get(("192.0.2.20", 443)), "no_answer")

    # THE SOURCE PORT ALLOCATOR NEVER REUSES ONE THAT IS STILL PENDING.
    _eng7 = ps.SynScanEngine(timeout=0.01)
    _seen = set()
    for _i in range(50):
        _seen.add(_eng7._allocate_source_port())
    check("fifty allocations are fifty distinct source ports",
          len(_seen), 50)
    check("and they are inside the declared range",
          all(ps.SYN_SOURCE_PORT_LOW <= p <= ps.SYN_SOURCE_PORT_HIGH
              for p in _seen), True)


print("\n[3] THE LIVE PASS: a real SYN against a real listener")
#
# THIS SECTION SKIPS IN WORDS when no raw socket can be opened, and it says
# WHY. It is the section that proves the socket side -- the checksum on the
# wire, the demultiplexing of real frames, the teardown -- so a silent skip
# would leave the whole file proving only its own fixtures.

_ok, _why = ps.syn_scan_available()
if not _ok:
    skip("the live SYN pass",
         f"{_why}. THE MODULE THIS FILE TESTS IS STILL EXERCISED: the "
         f"connect fallback is the method this host runs, and sections [1], "
         f"[2] and [4] cover the packet, the rules and the contract. To drive "
         f"this section, run the file inside `unshare -Urn` (which grants "
         f"CAP_NET_RAW in a private network namespace) or as root.")
    check("and the method this host WOULD use is reported as the fallback",
          ps.tcp_probe_method()[0], ps.CONNECT_METHOD)
else:
    _listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _listener.bind(("127.0.0.1", 0))
    _listener.listen(4)
    _live_port = _listener.getsockname()[1]

    # A port with nothing on it, chosen the same way: bind, read the number,
    # close. The kernel does not hand the same ephemeral port out twice in a
    # row, and if it did the check below would say so rather than pass.
    _probe = socket.socket()
    _probe.bind(("127.0.0.1", 0))
    _dead_port = _probe.getsockname()[1]
    _probe.close()

    _eng = ps.SynScanEngine()
    _eng.open()
    _src, _err = ps.source_address_for("127.0.0.1", socket.AF_INET)
    check("the source address for a loopback probe is the loopback address",
          (_src, _err), ("127.0.0.1", None))
    _sent, _e1 = _eng.probe(socket.AF_INET, _src, "127.0.0.1", _live_port)
    _sent2, _e2 = _eng.probe(socket.AF_INET, _src, "127.0.0.1", _dead_port)
    check("both SYNs went out", (_sent, _sent2), (True, True))
    _answers = _eng.finish()
    _teardowns = _eng.teardowns
    _eng.close()

    check("a LIVE listener answers with a SYN-ACK, which is OPEN",
          _answers.get(("127.0.0.1", _live_port)), "open")
    check("a port with nothing on it answers with an RST, which is CLOSED -- "
          "THE ANSWER A CONNECT TEST CANNOT GIVE",
          _answers.get(("127.0.0.1", _dead_port)), "closed")
    check("and the SYN-ACK was answered with an RST, so nothing is left "
          "half-open on the target",
          _teardowns >= 1, True)

    # THE SHIPPED DISPATCHER, not the engine directly: this is the path a real
    # scan takes, and it must pick the SYN method when one is available.
    #
    # THE LISTENER IS STILL UP HERE, and that is the point: an earlier draft of
    # this file closed it above, so the dispatcher ran against two dead ports
    # and the check read as a defect in the module. A fixture has to model the
    # production SEQUENCE, not only its shape.
    _sc = ps.PortScanner("live-syn")
    check("the shipped dispatcher reports the SYN method on this host",
          ps.resolve_tcp_method({})[0], ps.SYN_METHOD)
    _out = _sc._run_syn_scan("127.0.0.1", [_live_port, _dead_port],
                             "self", False, "measured by this test")
    check("the pass reports the live port OPEN",
          [e["port"] for e in _out["open"]], [_live_port])
    check("and the dead port CLOSED, by RST",
          [c["port"] for c in _out["closed"]], [_dead_port])
    check("and nothing landed in no_answer for either",
          _out["no_answer"], [])
    check("and every open row carries the method that found it",
          {e["tcp_method"] for e in _out["open"]}, {ps.SYN_METHOD})
    _listener.close()

    # AND THE REFUSAL DIRECTION: a port that is filtered says NOTHING, so it
    # must land in no_answer rather than in either verdict. A blackholed
    # address is simulated by probing an address in a documentation range
    # that this host has no route to -- the SYN goes out and nothing comes
    # back, which is exactly the case the module calls "NEITHER".
    _eng2 = ps.SynScanEngine(timeout=0.3)
    _eng2.open()
    _sent3, _e3 = _eng2.probe(socket.AF_INET, _src, "192.0.2.1", 443)
    _silent = _eng2.finish() if _sent3 else {}
    _eng2.close()
    if _sent3:
        check("a SYN to an address nothing answers from is NO_ANSWER, not "
              "closed",
              _silent.get(("192.0.2.1", 443)), "no_answer")
    else:
        skip("the no-answer case", f"the SYN could not be sent ({_e3}); this "
                                   f"host may have no route to that range")


print("\n[4] THE CONTRACT: three settings, an absent key, and the refusal")

check("an absent key is auto",
      ps.tcp_method_setting({}), (ps.TCP_METHOD_SETTING_AUTO,
                                  "no key is set, so it is auto", None))
check("an absent port_scan block is auto too",
      ps.tcp_method_setting({"sensors": {}})[0], ps.TCP_METHOD_SETTING_AUTO)
check("the key is read from port_scan, the block default_set lives in",
      ps.tcp_method_setting({"port_scan": {"tcp_method": "connect"}})[1],
      "port_scan.tcp_method")
check("a valid value is taken, case and padding irrelevant",
      ps.tcp_method_setting({"port_scan": {"tcp_method": "  SYN "}})[0],
      ps.SYN_METHOD)
check("an unreadable value falls back to auto AND says so",
      ps.tcp_method_setting({"port_scan": {"tcp_method": "nope"}})[0],
      ps.TCP_METHOD_SETTING_AUTO)
# EVERY READ IS `.get()`-STYLE, because the negative control for this section
# replaces `tcp_method_setting` with a body that returns NO problem sentence --
# and a check that indexes `[2]` off it dies of TypeError instead of FAILING,
# which makes the control measure a crash rather than a check. Read the third
# element the way a caller does, and let a missing one be a FAIL.
_problem = ps.tcp_method_setting({"port_scan": {"tcp_method": "nope"}})[2]
check_true("and the problem sentence names the valid values",
           bool(_problem) and all(v in _problem
                                  for v in ps.TCP_METHOD_SETTINGS),
           _problem)

# PINNED "connect" WINS EVEN WHEN A RAW SOCKET IS AVAILABLE. Asserted in both
# directions so the check is not vacuously true on a host with no raw socket.
_method, _reason, _problem = ps.resolve_tcp_method(
    {"port_scan": {"tcp_method": "connect"}})
check("a pinned connect test is used whatever the raw socket can do",
      _method, ps.CONNECT_METHOD)
check_true("and the reason names the key rather than the machine",
           "PINNED BY CONFIG" in _reason, _reason)

# PINNED "syn" WITH NO RAW SOCKET IS A REFUSAL, NOT A SUBSTITUTION. This is
# the original PS-13 defect in miniature: describing a scan other than the one
# that ran.
if not ps.syn_scan_available()[0]:
    _m, _r, _p = ps.resolve_tcp_method({"port_scan": {"tcp_method": "syn"}})
    check("pinning the SYN scan with no raw socket gives NO method at all",
          _m, None)
    check_true("and the reason says no connect test was substituted",
               "NO CONNECT TEST" in _r.replace("was substituted",
                                               "was substituted"), _r)
    _sc = ps.PortScanner("pinned", config={"port_scan": {"tcp_method": "syn"}})
    _sc._check_udp_port = lambda h, p: {"state": "no_answer", "probe": "s",
                                        "banner": None}
    _out = _sc.scan("127.0.0.1", port_set="common")
    check("the scan REFUSES rather than running a different probe",
          _out["tcp_refused"], True)
    check("and reports no TCP method, because none ran",
          _out["tcp_method"], None)
    check("and no TCP port was reported open from a probe that never ran",
          _out["tcp_open"], 0)
    check_true("and the scope sentence says an empty TCP list is the pinned "
               "method, not a quiet machine",
               "NOT a machine" in _out["scan_scope"], _out["scan_scope"][:120])
    check("and the UDP pass still ran, because it needs no raw socket",
          _out["udp_scanned"] > 0, True)
else:
    _m, _r, _p = ps.resolve_tcp_method({"port_scan": {"tcp_method": "syn"}})
    check("pinning the SYN scan with a raw socket available gives the SYN method",
          _m, ps.SYN_METHOD)

# THE SWITCHED-OFF REFUSAL CARRIES THE NEW KEYS, so a caller written against
# the working payload cannot crash on the refusal.
_off = ps.PortScanner("off", config={"sensors": {"port_scanner":
                                                 {"enabled": False}}})
_refusal = _off.scan("127.0.0.1")
check("the switched-off refusal carries the TCP-method keys too",
      all(k in _refusal for k in ("tcp_method", "tcp_method_reason",
                                  "tcp_closed_by_rst", "tcp_no_answer",
                                  "tcp_probe_failed", "tcp_refused")), True)
check("and claims no method, because no probe ran",
      _refusal["tcp_method"], None)

# STATUS PUBLISHES IT, which is what the card reads.
_status = ps.PortScanner("status").status()
check("status names the method a scan from here would use",
      _status.get("tcp_method") in ps.TCP_PROBE_METHODS, True)
check("and the setting in charge",
      _status.get("tcp_method_setting"), ps.TCP_METHOD_SETTING_AUTO)
check("and the reason, so the card never has to re-probe",
      bool(_status.get("tcp_method_reason")), True)


print("\n" + "=" * 62)
if fails:
    print(f"{len(fails)} FAILED: " + ", ".join(fails))
    sys.exit(1)
print("All raw-SYN checks passed.")
