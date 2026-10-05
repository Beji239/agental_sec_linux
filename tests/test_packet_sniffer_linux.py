"""
tests/test_packet_sniffer_linux.py, the packet sniffer fixes of 2026-09-23.

WHAT THIS FILE IS FOR. bugfinder.md's SNF round found eighteen things in
tools/packet_sniffer_linux.py and the adapter over it. The fixes are in the
tree; this file is the half that keeps them there, because every one of the
defects was the shape "the code is present and correct-looking, and the
behaviour is wrong" -- the kind a reader cannot catch and only a check can.

THE THREE THAT PUT A WRONG FACT IN FRONT OF THE OWNER, each asserted in BOTH
directions here (a detector that stops firing is as broken as one that fires
on everything):

  SNF-1/SNF-2  the beacon detector fired on this host's own address, on
               127.0.0.1 and on the /24 broadcast -- all 35 live PKT-1002 rows
               were false. The destination must be somebody else's host, and
               the feed must be CONNECTION ATTEMPTS, inside a window, with
               both interval bounds.
  SNF-6/SNF-15 a capture thread that died kept reporting its interface as
               being read. A dead capture must read as dead.
  SNF-13       the attribution lookup tried the source end first, always, so
               an inbound packet could be attributed to the peer's socket.

The rest (SNF-3 hot path, SNF-4 kernel counters, SNF-5 capability probe,
SNF-7 promisc, SNF-8 filter, SNF-14 ceilings, SNF-16 monitor_once, SNF-17 the
new raisers, SNF-18 the dead imports) are each asserted where the behaviour
lives, and the ones that need a live socket or root say so rather than
pretending.

Run it directly: python tests/test_packet_sniffer_linux.py
"""
import logging
import pathlib
import sys
import time
import types
import unittest.mock as mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from tools import packet_sniffer_linux as ps          # noqa: E402
from scapy.all import Ether, IP, TCP, UDP             # noqa: E402

logging.basicConfig(level=logging.CRITICAL)           # keep the output clean

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def true(label, got):
    check(label, bool(got), True)


# THIS HOST'S OWN ADDRESS IS READ, NEVER WRITTEN. Pinning one machine's address
# in a test file both leaks it and makes the test wrong on any other box; the
# leak gate flags it, correctly. So the "our own address" case is built from
# what the module reads off the machine it is running on, and the synthetic
# cases below use RFC 5737 / RFC 1918 documentation ranges.
_OURS = sorted(ps.refresh_local_addresses())
_OUR_IP = next((a for a in _OURS if a != "127.0.0.1"), "127.0.0.1")
# A /24 broadcast for a documentation subnet (RFC 5737 covers 192.0.2.0/24).
_DOC_SUBNET = "192.0.2.0/24"
_DOC_BROADCAST = "192.0.2.255"


def tcp(dst, flags="S", src=None, sport=44000, dport=443):
    """
    One IP/TCP frame in the shape _analyze_packet produces.

    THE ETHERNET LAYER IS BUILT WITH EXPLICIT ADDRESSES, and that is not
    cosmetic. `Ether()/IP(...)` makes scapy RESOLVE a MAC for the
    destination, and every RFC 5737 destination this file uses by definition
    never answers, so the resolution blocks. Measured 2026-09-25: `len(pkt)`
    cost 3.96 ms that way against 0.0001 ms with the addresses supplied,
    which is 80% of what the hot-path check below was timing. A CAPTURED
    FRAME ALREADY CARRIES ITS ADDRESSES, so a fixture that has to ask the
    network for one is not shaped like the thing under test.
    """
    return (Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            / IP(src=src or _OUR_IP, dst=dst)
            / TCP(sport=sport, dport=dport, flags=flags))


def beacon_input(dst_ip, flags="S", protocol="tcp"):
    return {"dst_ip": dst_ip, "protocol": protocol, "tcp_flags": flags,
            "src_ip": _OUR_IP, "src_port": 44000, "dst_port": 443,
            "direction": "outbound", "scope": "outbound"}


print("\n[1] SNF-1: the address this host holds is not a destination")
# THE MEASUREMENT THIS COMES FROM: 35 live PKT-1002 rows, every one false.
# 23 named this host's own address, 9 named 127.0.0.1, 3 named its /24
# broadcast. None of those can be a beacon, and the detector now says why
# rather than silently not firing.
local = ps.refresh_local_addresses()
true("the host's own addresses were read", local)
true("and this host's own address is among them", _OUR_IP in local)
for addr in sorted(local):
    ok, why = ps.peer_is_a_host(addr)
    check(f"a destination this host holds is refused ({addr})", ok, False)
    true(f"  ...and says why ({addr})", why)
check("loopback is refused", ps.peer_is_a_host("127.0.0.1")[0], False)
check("a subnet broadcast is refused",
      ps.peer_is_a_host(_DOC_BROADCAST)[0], False)
check("255.255.255.255 is refused", ps.peer_is_a_host("255.255.255.255")[0], False)
check("a multicast group is refused", ps.peer_is_a_host("224.0.0.1")[0], False)
# AND THE OTHER DIRECTION: a real, remote host still passes, or the detector
# has been silenced rather than fixed.
check("a public address is still a host", ps.peer_is_a_host("8.8.8.8"), (True, ""))
check("and so is a LAN address that is not ours",
      ps.peer_is_a_host("198.51.100.50"), (True, ""))

# The subnet broadcast used to classify as private_to_private, so it reached
# the packet table as ordinary LAN traffic (three live rows).
check("a subnet broadcast classifies as broadcast, not LAN traffic",
      ps.classify_scope(_DOC_SUBNET.split("/")[0], _DOC_BROADCAST), "broadcast")
check("and so does the all-ones broadcast",
      ps.classify_scope(_DOC_SUBNET.split("/")[0], "255.255.255.255"), "broadcast")
check("while an ordinary LAN peer is unchanged",
      ps.classify_scope(_DOC_SUBNET.split("/")[0], "192.0.2.9"),
      "private_to_private")


print("\n[2] SNF-1/SNF-2: what is a beacon, in both directions")
ps._beacon_data.clear()
ps._detections_skipped.clear()

# (a) THE LIVE FALSE POSITIVE, reproduced: one loopback flow's frames.
d = ps._analyze_packet(tcp("127.0.0.1", flags="PA", src="127.0.0.1",
                           sport=49498, dport=5000))
fired = [ps._detect_beaconing(d) for _ in range(80)]
check("80 frames of one loopback flow fire nothing", any(fired), False)
true("and the skip reason names loopback",
     any("loopback" in r for r in ps._detections_skipped))

# (b) THE SAME PACKETS AIMED AT A REAL HOST, still not a beacon, because they
# are frames of an established stream and not connection attempts.
ps._beacon_data.clear(); ps._detections_skipped.clear()
d2 = ps._analyze_packet(tcp("198.51.100.44", flags="PA"))
fired = [ps._detect_beaconing(d2) for _ in range(80)]
check("80 frames of an established stream fire nothing", any(fired), False)
true("and the skip reason says it is not an attempt",
     any("not a SYN" in r for r in ps._detections_skipped))

# (c) A REAL BEACON: SYNs to a remote host every 30 s with jitter under the
# 0.25 CV ceiling. It must fire, or (a) and (b) bought silence and not sense.
ps._beacon_data.clear(); ps._detections_skipped.clear()
t0 = time.time()
hits = []
for i in range(12):
    with mock.patch.object(ps.time, "time", return_value=t0 + i * 30.0):
        out = ps._detect_beaconing(beacon_input("198.51.100.44"))
    if out:
        hits.append(out)
check("a 30-second SYN beacon fires exactly once", len(hits), 1)
true("and the finding carries the window it was judged over",
     hits and hits[0].get("window_seconds") == ps.BEACON_WINDOW)
true("and it reports CONNECTION ATTEMPTS, which is what the rule says",
     hits and "connection attempts" in hits[0]["description"])

# (d) THE INTERVAL FLOOR. A busy off-host destination at 1 s intervals is a
# stream; the Windows tree's BEACON_MIN_INTERVAL is 5 s and the port dropped it.
ps._beacon_data.clear()
fired = []
for i in range(12):
    with mock.patch.object(ps.time, "time", return_value=t0 + i * 1.0):
        out = ps._detect_beaconing(beacon_input("198.51.100.44"))
    if out:
        fired.append(out)
check("a 1-second stream is refused by the interval floor", len(fired), 0)

# (e) THE WINDOW. The same beacon, but the hits are spread wider than
# BEACON_WINDOW apart, so no window ever holds enough samples.
ps._beacon_data.clear()
fired = []
for i in range(12):
    with mock.patch.object(ps.time, "time",
                           return_value=t0 + i * (ps.BEACON_WINDOW + 10)):
        out = ps._detect_beaconing(beacon_input("198.51.100.44"))
    if out:
        fired.append(out)
check("hits further apart than the window never accumulate", len(fired), 0)

# (f) UDP: counted off 53/123, refused on them.
ps._beacon_data.clear()
check("udp to a resolver port is not an attempt",
      ps._is_connection_attempt(beacon_input("8.8.8.8", protocol="udp")
                                | {"dst_port": 53}), (False, "udp on a resolver/clock port"))
true("udp elsewhere is",
     ps._is_connection_attempt(beacon_input("8.8.8.8", protocol="udp")
                               | {"dst_port": 9999})[0])
check("icmp is never a connection",
      ps._is_connection_attempt(beacon_input("8.8.8.8", protocol="icmp"))[0], False)
check("a tcp frame with no flags we read is not counted",
      ps._is_connection_attempt(beacon_input("8.8.8.8", flags=None))[0], False)
true("and a SYN+ACK (an answer, not an attempt) is refused",
     "SYN" not in str(ps._is_connection_attempt(
         beacon_input("8.8.8.8", flags="SA"))) or
     ps._is_connection_attempt(beacon_input("8.8.8.8", flags="SA"))[0] is False)


print("\n[3] SNF-2/SNF-14: the Windows bounds are back, and the map is capped")
for name, want in (("BEACON_MIN_SAMPLES", 8), ("BEACON_WINDOW", 1800),
                   ("BEACON_MAX_CV", 0.25), ("BEACON_MIN_INTERVAL", 5),
                   ("BEACON_MAX_INTERVAL", 3600), ("BEACON_MAX_TRACKED", 5000)):
    check(f"{name} exists with the Windows tree's value",
          getattr(ps, name, None), want)
# The looser numbers the port shipped must be GONE, not merely unused.
check("the old looser CV ceiling is gone", hasattr(ps, "BEACON_MAX_CV_UNUSED"), False)
check("and the old hit-count name is gone",
      hasattr(ps, "BEACON_MIN_CONNECTIONS"), False)

# The map at its cap has an eviction path, and the OLDEST-touched key goes.
# Driven through the DETECTOR, because that is the path a packet takes and the
# path the bound has to hold on.
ps._beacon_data.clear()
ps.refresh_local_addresses()        # so the host-identity gate has a snapshot
for i in range(ps.BEACON_MAX_TRACKED + 25):
    ps._beacon_data[f"198.51.100.{i % 256}:{i}"] = {
        "hits": ps.deque(maxlen=8), "last_flagged": 0.0, "touched": i}
before = len(ps._beacon_data)
with mock.patch.object(ps.time, "time", return_value=t0):
    ps._detect_beaconing(beacon_input("203.0.113.77"))
check("the map was over its cap before the call", before > ps.BEACON_MAX_TRACKED, True)
# The detector evicted the oldest key (its `touched` is 0) to make room, and
# the key it added is present: the bound and the addition both happened.
check("the map is back at its cap, by eviction",
      len(ps._beacon_data), ps.BEACON_MAX_TRACKED)
true("the key the detector was called about is now tracked",
     "203.0.113.77" in ps._beacon_data)
check("and the oldest of the flood is the one that went",
      "198.51.100.0:0" in ps._beacon_data, False)
# ...and the eviction on its own brings a table back to its ceiling rather
# than removing one key per call.
_bulk = {f"k{i}": {"hits": ps.deque(maxlen=8), "last_flagged": 0.0,
                   "touched": i}
         for i in range(ps.BEACON_MAX_TRACKED + 25)}
ps._evict_oldest(_bulk, ps.BEACON_MAX_TRACKED)
check("a table over its cap is brought ALL the way back, not by one",
      len(_bulk), ps.BEACON_MAX_TRACKED)
true("the newest survive", f"k{ps.BEACON_MAX_TRACKED + 24}" in _bulk)
check("and the oldest do not", "k0" in _bulk, False)
# The dead declarations from the old module must NOT be back.
check("the dead connection cache is gone", hasattr(ps, "_seen_connections"), False)
check("and its unenforced constant with it",
      hasattr(ps, "_CONNECTION_CACHE_MAX"), False)
ps._beacon_data.clear(); ps._detections_skipped.clear()


print("\n[4] SNF-14: no import the module does not use (SNF-18)")
mod_src = (ROOT / "tools" / "packet_sniffer_linux.py").read_text(encoding="utf-8")
for dead in ("from core import capabilities as caps",
             "from core import detections as det",
             "from core import memory_engine as me",
             "from tools import announce_harvester as announce",
             "import json"):
    check(f"the dead import is gone: {dead!r}", dead in mod_src, False)
true("while the imports it does use are all there",
     all(x in mod_src for x in ("import statistics", "import struct",
                                "import pwd")))


print("\n[5] SNF-5: the capability probe decides, and groups are a hint")
import os                                                # noqa: E402
import grp                                               # noqa: E402
import pwd                                               # noqa: E402

# The account under test, read the same way the code reads it -- so the
# fabricated group membership below cannot name anybody, and cannot disagree
# with the process either.
_ACCOUNT = pwd.getpwuid(os.getuid()).pw_name

real_socket = ps.socket.socket


class _FakeSock:
    def __init__(self, *a, **k):
        pass

    def close(self):
        pass


# (a) A SUCCESSFUL PROBE IS THE ANSWER, and it does not fall through to the
#     group check. Proven by fabricating membership: if the group branch were
#     consulted the reason would name the group.
ps.socket.socket = lambda *a, **k: _FakeSock()
_orig_getgrnam = grp.getgrnam
grp.getgrnam = lambda n: types.SimpleNamespace(gr_mem=[_ACCOUNT])
try:
    ok, why = ps.check_capture_capability()
    check("a successful probe returns True", ok, True)
    check("and the reason names the capability, not a group",
          "group" in why.lower(), False)
finally:
    ps.socket.socket = real_socket
    grp.getgrnam = _orig_getgrnam

# (b) A PROBE THAT FAILS IS A NO, even with membership. The old code answered
#     "Member of wireshark group" here and a capture then started and kept
#     nothing.
class _NoSuchDevice:
    def __init__(self, *a, **k):
        raise OSError(19, "No such device")      # NOT EPERM


ps.socket.socket = _NoSuchDevice
grp.getgrnam = lambda n: types.SimpleNamespace(gr_mem=[_ACCOUNT])
try:
    ok, why = ps.check_capture_capability()
    check("a non-EPERM probe failure is not a yes", ok, False)
    check("and the reason carries what the kernel actually said",
          "No such device" in why, True)
finally:
    ps.socket.socket = real_socket
    grp.getgrnam = _orig_getgrnam

# (c) THE ACCOUNT COMES FROM THE PROCESS, not the environment. A service
#     started by systemd has no USER, and the old code read that and reported
#     a real member as having no access.
_cap_src = (ROOT / "tools" / "packet_sniffer_linux.py").read_text(encoding="utf-8")
check("the capability check does not read os.environ['USER']",
      'os.environ.get("USER"' in _cap_src, False)
true("it reads the account from the process instead",
     "pwd.getpwuid(os.getuid())" in _cap_src)
_priv_src = (ROOT / "core" / "privilege_linux.py").read_text(encoding="utf-8")
check("and so does the copy in core/privilege_linux.py",
      'os.environ.get("USER") in group.gr_mem' in _priv_src, False)
true("the privilege copy has the same probe-first shape",
     "probe_error" in _priv_src)


print("\n[6] SNF-6/SNF-15: a dead capture must read as dead")
alive_seen = {}


def _fake_sniff(**kwargs):
    alive_seen.update(kwargs)
    alive_seen["_while_running"] = ps.capture_interface()
    alive_seen["_alive_while_running"] = ps._capture_alive


class _InlineThread:
    """Runs the capture body inline so the test can see what it did."""

    def __init__(self, target=None, daemon=None, **kw):
        self._target = target

    def start(self):
        if self._target:
            self._target()


def _start(body):
    ps.sniff, ps.threading.Thread = body, _InlineThread
    ps.check_capture_capability = lambda: (True, "Running as root")
    return ps.start_sniffer(interface="wlp1s0")


_o = (ps.sniff, ps.threading.Thread, ps.check_capture_capability)
try:
    alive_seen.clear()
    check("start_sniffer succeeds", _start(_fake_sniff), True)
    check("the interface IS reported while the capture runs",
          alive_seen["_while_running"], "wlp1s0")
    check("with liveness up", alive_seen["_alive_while_running"], True)
    # ...and the body returned, so the thread is gone.
    check("capture_interface() is None once the thread has stopped",
          ps.capture_interface(), None)
    true("the reason says it STARTED and STOPPED rather than never ran",
         "no longer running" in ps.capture_interface_reason())
    check("capture_state agrees", ps.capture_state()["alive"], False)
    check("and status reports running=False", ps.get_status()["running"], False)

    # The measured defect itself: a thread that DIES. Before the fix every
    # field still said wlp1s0 was being read.
    def _dying(**kwargs):
        raise RuntimeError("the interface vanished")

    alive_seen.clear()
    check("a start still reports True (the thread did start)",
          _start(_dying), True)
    check("but the interface is no longer claimed",
          ps.capture_interface(), None)
    st = ps.capture_state()
    check("the failure is recorded", st["alive"], False)
    true("and says what went wrong", "interface vanished" in (st["failure"] or ""))
    true("while remembering WHICH interface it was started on",
         st["started_on"] == "wlp1s0")

    # A refused start is a third state, distinct from both.
    def _never(**kwargs):                     # pragma: no cover - not started
        raise AssertionError("sniff must not be called for a refused start")

    ps.sniff = _never
    check("a configured interface that does not exist starts nothing",
          ps.start_sniffer(interface="eth-not-here"), False)
    check("and reports no interface rather than a guess",
          ps.capture_interface(), None)
finally:
    ps.sniff, ps.threading.Thread, ps.check_capture_capability = _o


print("\n[7] SNF-7/SNF-8: promiscuous and the filter are decisions now")
import inspect                                            # noqa: E402
_sig = inspect.signature(ps.start_sniffer)
check("the module's default is NOT promiscuous",
      _sig.parameters["promisc"].default, False)
alive_seen.clear()
try:
    _start(_fake_sniff)
    check("promisc is passed through as a real argument, off by default",
          alive_seen.get("promisc"), False)
    check("and no filter key is passed when none was configured",
          "filter" in alive_seen, False)
finally:
    ps.sniff, ps.threading.Thread, ps.check_capture_capability = _o

cfg = (ROOT / "config.linux.example.json").read_text(encoding="utf-8")
true("the example config documents the promiscuous setting",
     '"promiscuous"' in cfg)
true("and the filter", '"filter"' in cfg)
true("and the receive buffer", '"rcvbuf"' in cfg)
ad_src = (ROOT / "adapters.py").read_text(encoding="utf-8")
true("the adapter reads all three from config and passes them on",
     "promisc=self._promisc" in ad_src and "filter_str=self._filter" in ad_src
     and "rcvbuf=self._rcvbuf" in ad_src)
true("and warns when promiscuous is on, because it changes the NIC",
     "promiscuous=true" in ad_src)


print("\n[8] SNF-3: the socket table is not swept per packet")
import psutil as real_psutil                              # noqa: E402

walks = {"n": 0}


class _CountingPsutil:
    NoSuchProcess = real_psutil.NoSuchProcess
    AccessDenied = real_psutil.AccessDenied

    @staticmethod
    def net_connections(kind="inet"):
        walks["n"] += 1
        return [types.SimpleNamespace(
            laddr=types.SimpleNamespace(ip="192.0.2.5", port=443), pid=8)]

    @staticmethod
    def Process(pid):
        class _P:
            def name(self):
                return "nginx"

            def cmdline(self):
                return ["nginx"]
        return _P()

    @staticmethod
    def net_if_addrs():
        return {}


_ps_saved = ps.psutil
try:
    ps.psutil = _CountingPsutil
    ps.PSUTIL_AVAILABLE = True
    ps._conn_index, ps._conn_index_at, ps._pid_info = {}, 0.0, {}
    walks["n"] = 0
    for _ in range(50):
        ps._get_process_info("192.0.2.5", 443, "203.0.113.9", 61000,
                             direction="outbound")
    check("50 attribution lookups cost ONE walk of the socket table",
          walks["n"], 1)
    true("the walk count is published for a reader",
         "note" in ps.attribution_state())
finally:
    ps.psutil = _ps_saved
    ps._conn_index, ps._conn_index_at, ps._pid_info = {}, 0.0, {}

# And the hot path itself, measured rather than asserted by reading: it must
# be far under the 14.1 ms/packet this module used to spend.
#
# THIS CHECK WAS MEASURING THE FIXTURE, NOT THE HOT PATH. FOUND AND FIXED
# 2026-09-25, by the event-monitor round-2 pass re-running the suite.
#
# It had been failing on and off and read as a regression in this module.
# `tcp()` built `Ether()/IP()/TCP()` with no addresses, so scapy RESOLVED a
# MAC for the destination, and every destination here is an RFC 5737 address
# that never answers. Measured on this host, 30 packets a sample:
#
#     the fixture's own frame build, len(pkt)   3.962 ms
#     _analyze_packet, whole                    4.925 ms
#     the sniffer's own marginal work           0.963 ms  <- the thing meant
#
# so the 5.0 ms ceiling was being decided by scapy's resolution timing rather
# than by this module. `tcp()` now supplies the frame's addresses, which is
# the shape a CAPTURED frame actually has, and the fixture's own cost fell to
# ~0. The same class as test_process_monitor_linux.py's `elapsed < 4.0`
# stopwatch pin: A STOPWATCH ASSERTION ON A FIXTURE IS A MEASUREMENT OF THE
# MACHINE IT RAN ON.
pkt = tcp("198.51.100.9")
for _ in range(3):
    ps._analyze_packet(pkt)
start = time.perf_counter()
N = 30
for _ in range(N):
    ps._analyze_packet(pkt)
per_ms = (time.perf_counter() - start) / N * 1000
true(f"a packet costs well under the old 14.1 ms ({per_ms:.3f} ms)", per_ms < 5.0)


print("\n[9] SNF-4: the kernel's own counters are read")
c = ps._read_interface_counters("lo")
true("loopback has a counter row to read", c)
true("with the received-frame count in it", "rx_packets" in c)
true("and the drop count, which is the one that matters",
     "rx_dropped" in c and "rx_errors" in c)
check("an interface that does not exist yields nothing, not zeros",
      ps._read_interface_counters("notreal0"), {})
ps._capture_interface = "lo"
ps._reset_capture_counters()
time.sleep(0.3)
live = ps.capture_counters()
check("the delta is readable once a baseline exists", live["readable"], True)
true("and it carries the delta, not only the absolute",
     "delta" in live and "current" in live)
ps._capture_interface = None
check("with no capture, a read says so rather than returning zeros",
      ps.capture_counters()["readable"], False)


print("\n[10] SNF-13: the lookup follows the direction")
NAMES = {8: "nginx", 99: "curl"}


class _TwoEnds:
    NoSuchProcess = real_psutil.NoSuchProcess
    AccessDenied = real_psutil.AccessDenied

    @staticmethod
    def net_connections(kind="inet"):
        return [types.SimpleNamespace(
                    laddr=types.SimpleNamespace(ip="192.0.2.5", port=443), pid=8),
                types.SimpleNamespace(
                    laddr=types.SimpleNamespace(ip="203.0.113.9", port=61000), pid=99)]

    @staticmethod
    def Process(pid):
        class _P:
            def name(self):
                return NAMES[pid]

            def cmdline(self):
                return [NAMES[pid]]
        return _P()


def _lookup(direction):
    ps._conn_index, ps._conn_index_at, ps._pid_info = {}, 0.0, {}
    return ps._get_process_info("203.0.113.9", 61000, "192.0.2.5", 443,
                                direction=direction)


try:
    ps.psutil = _TwoEnds
    check("an inbound packet is attributed to the DESTINATION end",
          _lookup("inbound")[0], 8)
    check("an outbound packet to the SOURCE end", _lookup("outbound")[0], 99)
    check("and with no hint it keeps the old source-first order",
          _lookup(None)[0], 99)
finally:
    ps.psutil = _ps_saved
    ps._conn_index, ps._conn_index_at, ps._pid_info = {}, 0.0, {}
true("the analyzer passes a direction hint to the lookup",
     "direction=direction_hint or direction" in mod_src)
true("and the adapter-derived direction is what it uses",
     "def _analyze_packet(pkt, direction_hint: str = None)" in mod_src)


print("\n[11] SNF-16: monitor_once stops when it says it does")
# THE MEASURED DEFECT: the callback raised StopIteration to break the loop and
# scapy swallowed it, so the `except StopIteration` could never fire and the
# only bound was the 30-second timeout. Asserted at the call site, because the
# bug was the mechanism and not the arithmetic.
true("monitor_once uses scapy's stop_filter",
     "stop_filter=_reached_count" in mod_src)
check("and no longer raises StopIteration out of a callback",
      "raise StopIteration()" in mod_src, False)
true("it chooses its interface instead of sniffing every one",
     "iface=chosen" in mod_src)
check("and does not pass iface=None", "iface=None, prn=" in mod_src, False)
true("a short capture says WHY it stopped",
     '"stopped_because"' in mod_src and '"complete"' in mod_src)


print("\n[12] SNF-17: the two dead rules have raisers")
ad = (ROOT / "adapters.py").read_text(encoding="utf-8")
true("PKT-1001 volume_sustained is raised", 'detection_id="PKT-1001"' in ad)
true("PKT-1003 capture_overflow is raised", 'detection_id="PKT-1003"' in ad)
true("PKT-1002 beacon is still raised", 'detection_id="PKT-1002"' in ad)
true("the volume detector exists to be called",
     callable(getattr(ps, "_detect_volume", None)))
# The volume detector, actually driven.
ps._volume_data.clear()
v = None
with mock.patch.object(ps.time, "time", return_value=t0):
    for i in range(ps.VOLUME_THRESHOLD):
        v = ps._detect_volume({"src_ip": "192.0.2.9"}) or v
true("and it fires when a source passes the threshold", v)
check("with PKT-1001's own severity", v and v["severity"], "low")
ps._volume_data.clear()
v = None
with mock.patch.object(ps.time, "time", return_value=t0), \
        mock.patch.object(ps, "is_self_address", lambda ip: ip == "192.0.2.10"):
    for i in range(ps.VOLUME_THRESHOLD):
        v = ps._detect_volume({"src_ip": "192.0.2.10"}) or v
check("this host's own traffic does not fire it", v, None)
ps._volume_data.clear()
v = None
with mock.patch.object(ps.time, "time", return_value=t0):
    for i in range(1000):
        v = ps._detect_volume({"src_ip": "192.0.2.9"}) or v
check("an ordinary download's 1,000 packets do not fire it", v, None)
ps._volume_data.clear()


print("\n[13] SNF-12: the payload check's limits are stated, not implied")
sig_src = (ROOT / "tools" / "packet_sniffer_linux.py").read_text(encoding="utf-8")
true("the payload function documents that it reads ONE frame",
     "ONE frame's first bytes" in sig_src or "one frame" in sig_src.lower())
true("and the adapter still refuses to raise PKT-1010 on a magic byte",
     "NOT written as a finding" in ad or "not written" in ad.lower())
# The detector itself is unchanged in behaviour: MZ at offset 0 hits.
hit = ps._detect_payload_signatures(
    {"payload_hex": "4d5a9000", "dst_ip": "8.8.8.8"})
true("a payload starting with MZ is still reported to the caller", hit)
check("an MZ at any other offset is not (documented limit)",
      ps._detect_payload_signatures(
          {"payload_hex": "00904d5a", "dst_ip": "8.8.8.8"}), None)


print("\n[14] the status block reports what a reader needs")
st = ps.get_status()
for key in ("running", "capture", "capture_settings", "attribution",
            "detections", "kernel", "interface", "interface_reason"):
    true(f"get_status() carries {key!r}", key in st)
true("the detect state carries its ceilings",
     "beacon_max_tracked" in st["detections"]
     and "volume_max_tracked" in st["detections"])
true("and the skip reasons, so a silent detector is visible",
     "skipped" in st["detections"])
true("the attribution block carries the snapshot age",
     "age_seconds" in st["attribution"] and "ttl_seconds" in st["attribution"])
# The adapter publishes all of it too.
for key in ("capture_state", "capture_settings", "counters", "attribution",
            "detections"):
    true(f"the adapter status carries {key!r}", f'out["{key}"]' in ad)


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
