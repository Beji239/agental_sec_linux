"""
tests/test_udp_scan.py, does the UDP pass say only what it can prove.

TODO 117, 2026-09-17. The owner's words: ports doesn't have UDP port finder
(sock.SOCK_DGRAM) and in that decree I am sure many other important ports are
also left unchecked.

THE FAILURE CASES COME FIRST, and on UDP they are the entire risk. UDP has
three answers and a scanner that knows two of them is worse than no scanner:
silence is the common case, and calling it "closed" fills a page with
confident nothing. That is this project's recurring bug in its purest form, a
sensor that could not tell saying it could.

What is tested, in order:

  1. SILENCE IS NOT CLOSED. A port that says nothing comes back no_answer,
     lands in udp_no_answer, and never appears in open_ports.
  2. A local socket failure is not silence either. Its own state.
  3. Closed comes only from an ICMP unreachable.
  4. Only then the happy path: a real listener answering a real probe becomes
     an open row tagged udp.
  5. The three answers are reported apart and never summed.
  6. An open UDP row is stored with protocol 'udp' and a banner that is a
     length plus hex, not decoded text from whatever replied.
  7. The profiled UDP ports are no longer in udp_not_tested, because they are
     now actually tested.
  8. Every probe payload is well formed, and none of them writes anything.

Run it directly: python tests/test_udp_scan.py
"""
import pathlib
import socket
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                      # noqa: E402
_isolate_db.isolate()

from core import memory_engine as me                    # noqa: E402
from tools import port_scanner as ps                    # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got):
    check(label, bool(got), True)


def check_in(label, needle, haystack):
    ok = needle in (haystack or "")
    print(f"  {'PASS' if ok else 'FAIL'}  {label}"
          + ("" if ok else f": {needle!r} not in {str(haystack)[:160]!r}"))
    if not ok:
        fails.append(label)


scanner = ps.PortScanner("test-session")


# A UDP responder on a free port, so "open" is a real reply rather than a mock.
class Responder:
    def __init__(self, reply=b"AGENTALSEC-TEST-REPLY"):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.reply = reply
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self.sock.sendto(self.reply, addr)
            except OSError:
                return

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except Exception:
            pass


def free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


print("\n[1] SILENCE IS NOT CLOSED.")
#
# A socket BOUND AND SILENT, which is the real world case this rule exists
# for: something is listening and it did not like the probe, or it only speaks
# when spoken to correctly. It must never come back closed.
#
# The first version of this test used an address in RFC 5737 documentation
# space, on the reasoning that nothing would answer. On the machine it was
# written on something did: 198.51.100.9:53 returned a 228 byte DNS reply,
# because that network had a resolver intercepting port 53. A test whose
# assumption is "the internet will stay quiet" is not a test. A local bound
# socket is deterministic and is also the more honest model of the case.

ps.UDP_TIMEOUT = 0.4          # keep the test quick; the logic is unchanged

silent_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
silent_sock.bind(("127.0.0.1", 0))
silent_port = silent_sock.getsockname()[1]

res = scanner._check_udp_port("127.0.0.1", silent_port)
check("a port that says nothing is no_answer", res["state"], "no_answer")
check("and it is not open", res["state"] == "open", False)
check("and it is not closed", res["state"] == "closed", False)
check("nothing was read off the wire", res["banner"], None)


print("\n[2] A local failure is not silence.")

res = scanner._check_udp_port("not-a-real-host.invalid", 53)
check("an unresolvable host is probe_failed, not quiet",
      res["state"], "probe_failed")
check_true("and it says what went wrong", res.get("error"))


print("\n[3] Closed comes from an ICMP unreachable and nowhere else.")
#
# Nothing is bound on this loopback port, so the kernel answers with an
# unreachable, which arrives on a CONNECTED socket as an error. That is why
# the probe connects instead of using sendto: an unconnected socket drops the
# ICMP and this case would be indistinguishable from silence.

dead = free_udp_port()
res = scanner._check_udp_port("127.0.0.1", dead)
check("an unbound local port comes back closed", res["state"], "closed")
check("with nothing claimed about a service", res["banner"], None)


print("\n[4] Only now the happy path: a real listener answers.")

r = Responder()
time.sleep(0.1)
res = scanner._check_udp_port("127.0.0.1", r.port)
check("a reply means open", res["state"], "open")
check_in("the banner says how many bytes came back", "byte reply",
         res["banner"])
check_in("and carries hex, not decoded text",
         b"AGENTALSEC".hex()[:8], res["banner"])
check("the reply text itself is NOT presented as a banner",
      "AGENTALSEC-TEST-REPLY" in (res["banner"] or ""), False)


print("\n[5] A whole scan keeps the three answers apart.")

out = scanner._run_udp_scan("127.0.0.1", [r.port, dead], "self", False)
check("the listener is open", [e["port"] for e in out["open"]], [r.port])
check("the unbound port is closed",
      [e["port"] for e in out["closed"]], [dead])
check("nothing was silent here", out["silent"], [])
check("every open row is tagged udp",
      sorted({e["protocol"] for e in out["open"]}), ["udp"])
check("an open UDP row does not carry the TCP caveat",
      "was found over TCP" in out["open"][0]["note"], False)
check_in("it says it answered a probe", "answered a UDP probe",
         out["open"][0]["note"])


print("\n[6] The row reaches the database tagged udp, with its banner.")
#
# The host sensor has to exist before a port row can point at it: every
# observation in this app names the vantage point it was made from, and
# port_scan_results.sensor_id is a foreign key into sensors. The app registers
# it at boot; a test that calls the writer directly has to do the same. Worth
# a sentence because the FK failure it produces reads like a bug in the
# scanner rather than a missing fixture.
from core import sensors as sn                           # noqa: E402
sn.register_local()

result = scanner._record(
    "127.0.0.1", "test-session", [], "self",
    ports=[80], port_set="common", public=False,
    udp=out, udp_ports=[r.port, dead])

with me._get_readonly_conn() as conn:
    rows = [dict(x) for x in conn.execute(
        "SELECT port, protocol, state, banner FROM port_scan_results "
        "WHERE target_host='127.0.0.1'").fetchall()]

check("one row was stored", len(rows), 1)
check("with the protocol on it", rows[0]["protocol"], "udp")
check("and state open", rows[0]["state"], "open")
check_in("and the banner is the reply size", "byte reply", rows[0]["banner"])

check("the payload counts both protocols apart", result["udp_open"], 1)
check("tcp found nothing here", result["tcp_open"], 0)
check("the closed list is its own field",
      [c["port"] for c in result["udp_closed_by_icmp"]], [dead])
check("and no_answer is its own field", result["udp_no_answer"], [])
check_in("the scope sentence names both protocols", "TWO PROTOCOLS",
         result["scan_scope"])
check_in("and says what UDP silence is not", "only an ICMP unreachable proves",
         result["scan_scope"])
check("protocols_tested says what went out",
      result["protocols_tested"], ["tcp", "udp"])

r.close()


print("\n[7] The UDP services are no longer 'not tested'.")
#
# Before today every one of these came back in udp_not_tested, because the
# only probe in the module was a TCP connect. They are in the UDP scan set
# now, so that list has to be empty for them, and it is computed rather than
# assumed so that adding a UDP fact without adding the port to the scan set
# shows up here instead of going quiet.

facts = sorted(ps.UDP_PORT_FACTS)
missing = [p for p in facts if p not in set(ps.UDP_SCAN_PORTS)]
check("every port with a UDP caveat is in the UDP scan set", missing, [])

res2 = scanner._record(
    "192.0.2.10", "test-session", [], "remote",
    ports=facts, port_set="common", public=False,
    udp={"open": [], "closed": [], "silent": [], "failed": []},
    udp_ports=facts)
check("so nothing is reported as untested", res2["udp_not_tested"], [])


print("\n[8] The probes themselves: well formed, and read only.")

# RESTATED 2026-09-25. The entry grew from (name, builder) to
# (name, builder, transport, scope) when the scope sentence stopped claiming
# every UDP port gets a real request. The old two-tuple unpack was asserting
# the SHAPE of the table rather than the property that matters, so it is
# rewritten to read the fields by name and to assert what the round added:
# every payload is non-empty, and the entry says which transport it is.
#
# TWO PROBES NOW TAKE THE TARGET ADDRESS -- mDNS and LLMNR ask a reverse
# address question, because a responder does not answer the old service
# enumeration unicast. They are built through ps.build_udp_probe, which is the
# shipped path and the only place a payload is constructed, so this check
# drives the same function the scan does rather than a second implementation.
for port, entry in sorted(ps.UDP_PROBES.items()):
    name, builder, transport, scope = entry
    check(f"{port} {name} builds bytes through the shipped builder",
          isinstance(ps.build_udp_probe(port, "192.0.2.9")[1], bytes), True)
    payload = ps.build_udp_probe(port, "192.0.2.9")[1]
    check(f"{port} {name} is not an empty datagram", len(payload) > 0, True)
    check(f"{port} {name} declares a transport and a scope",
          (bool(transport), bool(scope)), (True, True))

# The two that have a fixed shape, checked against the shape rather than
# against themselves.
check("the NTP probe is a 48 byte client packet",
      (len(ps._ntp_query()), ps._ntp_query()[0]), (48, 0x1b))
check("the DNS probe asks a question and expects a recursive answer",
      ps._dns_query()[2:4], b"\x01\x00")
check("the SSDP probe is an M-SEARCH and nothing else",
      ps._ssdp_msearch().startswith(b"M-SEARCH * HTTP/1.1"), True)
# Nothing in a probe may be a write. SNMP is the one that could be: a SetRequest
# is 0xa3, a GetRequest is 0xa0, and the difference is one byte.
check("the SNMP probe is a GetRequest, not a Set",
      0xa3 in ps._snmp_get(), False)
# RESTATED 2026-09-25 with the rest of the OID. This used to assert the first
# five arcs, `2b06010201`, which was exactly the extent of the defect: the
# request named mib-2 (1.3.6.1.2.1) while its own comment said sysDescr.0. The
# check passed on the broken packet because it pinned the broken prefix. It now
# asserts the WHOLE OID the comment claims, so the two can never disagree again.
check_in("and it reads sysDescr.0 and not just the mib-2 node",
          "2b06010201010100", ps._snmp_get().hex())
check("the varbind's OID is the eight arcs sysDescr.0 needs",
      ps._snmp_get().hex().count("2b06010201010100"), 1)

# The NetBIOS packet is the one whose SHAPE was wrong rather than its payload:
# it was two bytes short, so the qtype and qclass landed one field early.
# RFC 1002 4.2.1: header 12, name-length octet 1, name 32, terminator 1,
# qtype 2, qclass 2 = 50.
nb = ps._netbios_status()
check("the NetBIOS packet is the 50 bytes RFC 1002 lays out",
      len(nb), 50)
check("its name terminates where the spec says (offset 45)",
      nb[45], 0x00)
check("its qtype is NBSTAT at offset 46",
      nb[46:48], b"\x00\x21")
check("its qclass is IN at offset 48", nb[48:50], b"\x00\x01")

# mDNS and LLMNR are no longer the same question. The old file asserted
# 5355 shared the mDNS payload; that is now a defect rather than a fact,
# because RFC 4795 defines no multicast service enumeration.
check("the mDNS probe asks for the ADDRESS, not a service list",
      b"_services" in ps._mdns_query("192.0.2.9"), False)
# The reverse name, byte for byte: labels are the address octets REVERSED --
# 9, 2, 0, 192 -- then in-addr.arpa. A check that only asserted the absence of
# the old service list would pass on an empty packet, so the presence of the
# right name is asserted as well. This is the first shape of this check and it
# was WRONG (it expected the octets in order); the run caught it, which is why
# the expectation is read out of the builder's own output rather than typed.
check("the reverse-PTR name is the octets in reverse, then in-addr.arpa",
      ps._mdns_query("192.0.2.9")[12:],
      b"\x019\x012\x010\x03192\x07in-addr\x04arpa\x00\x00\x0c\x00\x01")
check("the LLMNR probe is NOT the mDNS payload",
      ps._llmnr_query("192.0.2.9") == ps._mdns_query("192.0.2.9"), False)
check("LLMNR sets RD, which RFC 4795 requires of a name query",
      ps._llmnr_query("192.0.2.9")[2:4], b"\x01\x00")

# The counting fields the round added, read from the shipped payload table.
check("the count of UDP ports with a real request matches the table",
      len(ps.UDP_PROBES), 7)
check("and the empty-datagram count is the rest of the scan set",
      len(ps.UDP_SCAN_PORTS) - len(ps.UDP_PROBES), 18)


print("\n" + "=" * 62)
if fails:
    print(f"{len(fails)} FAILED: " + ", ".join(fails))
    sys.exit(1)
print("All UDP scan checks passed.")
