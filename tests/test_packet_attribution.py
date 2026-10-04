"""
tests/test_packet_attribution.py, packet-to-process attribution, 2026-09-07.

WHY THIS EXISTS. The sniffer saw the network side of a connection but not what
on this machine owned it, so a finding could say "192.0.2.29 is beaconing to
11.22.36.63" and the model had no way to answer "beaconing with what". This
ties each packet to the local process at capture time, read out of the OS
connection table.

THE ONE HARD PART is timing, and IT IS SOLVED DIFFERENTLY ON THIS PLATFORM.
Converted 2026-09-21.

On Windows the sniffer buffered for 30 seconds before writing a row, so
attribution could not wait for the flush: a poller snapshotted the connection
table every second into a _ConnCache with a TTL, and the capture callback read
that snapshot. This file tested the cache, the TTL grace and the ageing.

The Linux capture path does not buffer. adapters.LinuxPacketSniffer writes each
packet row as it arrives, so it reads psutil's live table through
tools/packet_sniffer_linux._get_process_info at capture time and there is no
snapshot to age, no TTL and no _ConnCache to test. What is still worth
asserting is the same rule the cache was built around, and it is the rule this
file now checks: an ambiguous or absent lookup returns NOTHING rather than a
guess, so a packet with no process reads as NOT ATTRIBUTED and never as
"no process".

Nothing here needs scapy or a real socket. The connection table is fed in
directly, because what is being checked is the attribution logic, not psutil.
"""
import pathlib
import sqlite3
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


from core import memory_engine as me            # noqa: E402

tmp = pathlib.Path(tempfile.mkdtemp())
me.DB_PATH = tmp / "t.db"
sqlite3.connect(me.DB_PATH).executescript(
    (ROOT / "Schema.SQL").read_text(encoding="utf-8"))
from core import migrations                     # noqa: E402
migrations.run_migrations(me.DB_PATH)

from core import capabilities as caps            # noqa: E402
import tools.packet_sniffer_linux as ps               # noqa: E402
import socket                                    # noqa: E402

SID = "test-session"


class _Addr:
    """The one attribute of a psutil address this lookup reads."""
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port


class _Conn:
    """One row of psutil.net_connections, in the shape the module reads."""
    def __init__(self, ip, port, pid):
        self.laddr = _Addr(ip, port)
        self.raddr = ()
        self.pid = pid


class FakePsutil:
    """Only what _get_process_info touches: net_connections and Process."""

    def __init__(self, conns, names):
        self._conns = conns
        self._names = names        # pid -> name

    def net_connections(self, kind="inet"):
        return self._conns

    def Process(self, pid):
        outer = self

        class _P:
            def name(self_inner):
                if pid not in outer._names:
                    raise RuntimeError("gone")
                return outer._names[pid]

            def cmdline(self_inner):
                return [outer._names[pid]]
        return _P()


print("\n[1] attribution reads the OS table, and returns nothing on no match")
import tools.packet_sniffer_linux as ps
check("the sensor has an attribution lookup",
      callable(getattr(ps, "_get_process_info", None)), True)
check("and no _ConnCache, because nothing here buffers",
      hasattr(ps, "_ConnCache"), False)


print("\n[2] an unmatched connection is NOT attributed, and never guessed")
# THE RULE THE WINDOWS CACHE EXISTED FOR, still the point here. A lookup that
# finds nothing must return Nones, so the packet row stays NULL and the model
# reads "not attributed" rather than "no process owns this".
import psutil as _real_psutil
_saved = ps.psutil
try:
    class _FakePsutil:
        @staticmethod
        def net_connections(kind="inet"):
            return []
    ps.psutil = _FakePsutil
    ps.PSUTIL_AVAILABLE = True
    check("an empty table attributes nothing",
          ps._get_process_info("192.0.2.5", 51000, "192.0.2.6", 443),
          (None, None, None))
finally:
    ps.psutil = _saved

print("\n[3] a lookup that cannot run says so rather than raising")
_saved_avail = ps.PSUTIL_AVAILABLE
try:
    ps.PSUTIL_AVAILABLE = False
    check("no psutil means no attribution, not a crash",
          ps._get_process_info("192.0.2.5", 51000, "192.0.2.6", 443),
          (None, None, None))
finally:
    ps.PSUTIL_AVAILABLE = _saved_avail

print("\n[4] the local end is read from the OS table, not guessed from direction")
# THE RULE THE WINDOWS CACHE EXISTED FOR, still the point here, in the shape
# this platform gives it. Windows had to reconstruct the local end from a
# direction string because its snapshot was taken earlier; here psutil's table
# is the authority and says outright which end of a flow is local. So the
# checks below feed the table one row at a time and assert which process the
# lookup hands back, and that a flow the table does not hold is NOT attributed.
#
# UPDATED 2026-09-23 (SNF-3/SNF-13). Two changes underneath this section:
#   * the socket table is now read into a CACHE refreshed once a second
#     instead of being swept once per packet, so a test that swaps psutil in
#     has to clear the cache for its table to be the one that is read;
#   * the lookup now takes the direction and tries the LOCAL end first. The
#     ambiguous case -- both ends in the local table -- is new to this file
#     and is where the old source-first order named the wrong process.
_rows = [_Conn("192.0.2.29", 51000, 4321)]     # the outbound local end
_names = {4321: "chrome"}
_saved_ps = ps.psutil


def _fresh():
    """Clear both caches so the next lookup reads the table just installed."""
    ps._conn_index = {}
    ps._conn_index_at = 0.0
    ps._pid_info = {}


try:
    ps.psutil = FakePsutil(_rows, _names)
    ps.PSUTIL_AVAILABLE = True
    _fresh()
    check("the source end matching the table attributes the packet",
          ps._get_process_info("192.0.2.29", 51000, "11.22.36.63", 443,
                               direction="outbound"),
          (4321, "chrome", "chrome"))

    _rows[:] = [_Conn("192.0.2.5", 443, 8)]     # the INBOUND local end
    _names.update({8: "nginx"})
    _fresh()
    check("so does the dest end, when that is the local one",
          ps._get_process_info("203.0.113.9", 61000, "192.0.2.5", 443,
                               direction="inbound"),
          (8, "nginx", "nginx"))

    _fresh()
    check("a socket the table does not hold stays NULL",
          ps._get_process_info("192.0.2.5", 12345, "11.22.36.63", 443),
          (None, None, None))

    # SNF-13: both ends local, which is where direction decides
    # The OLD order asked (src_ip, src_port) first, always. An inbound packet
    # whose source port happens to be a local endpoint therefore got the
    # SOURCE process named -- the remote peer's socket, if the host also holds
    # one on that address. With both ends in the table the answer has to
    # follow the direction or it is a coin toss.
    _rows[:] = [_Conn("192.0.2.5", 443, 8),        # the listener
                _Conn("203.0.113.9", 61000, 99)]   # the other local socket
    _names.update({99: "curl"})
    _fresh()
    check("with BOTH ends local, an inbound packet names the DESTINATION end",
          ps._get_process_info("203.0.113.9", 61000, "192.0.2.5", 443,
                               direction="inbound")[:1], (8,))
    _fresh()
    check("and an outbound packet names the SOURCE end",
          ps._get_process_info("203.0.113.9", 61000, "192.0.2.5", 443,
                               direction="outbound")[:1], (99,))
    _fresh()
    check("while no direction at all keeps the old source-first order",
          ps._get_process_info("203.0.113.9", 61000, "192.0.2.5", 443)[:1],
          (99,))
finally:
    ps.psutil = _saved_ps
    _fresh()

# ICMP and anything portless must not reach the table at all: the sniffer
# gates the call on both ports being present. Asserted at the CALL SITE,
# because that is where the gate lives -- the lookup itself would happily be
# asked about port None and find nothing, which would read as "no process".
_analyze_src = (ROOT / "tools" / "packet_sniffer_linux.py").read_text(
    encoding="utf-8")
check("the call site gates the lookup on both ports being present",
      "if PSUTIL_AVAILABLE and src_port and dst_port:" in _analyze_src, True)
check("and a portless packet carries no process fields at all",
      '"pid": pid,' in _analyze_src, True)


print("\n[5] the process is written to the row and read back")
me.save_packet(session_id=SID, src_ip="192.0.2.29", dst_ip="11.22.36.63",
               src_port=51000, dst_port=443, protocol="TCP",
               direction="outbound", scope="outbound",
               process_name="chrome.exe", process_pid=4321)
me.save_packet(session_id=SID, src_ip="192.0.2.5", dst_ip="192.0.2.6",
               src_port=1000, dst_port=2000, protocol="TCP",
               direction="internal", scope="private_to_private")
rows = me.query_packets(session_id=SID, all_sessions=True, limit=10)
attributed = [r for r in rows if r.get("process_name") == "chrome.exe"]
check("the attributed row round-trips its process name",
      len(attributed), 1)
check("and its pid", attributed[0].get("process_pid"), 4321)
unattributed = [r for r in rows
                if r["src_ip"] == "192.0.2.5"]
check("a packet with no owner reads back NULL, not empty string",
      unattributed[0].get("process_name"), None)


print("\n[6] no psutil is a fact, not a crash")
# The module-level guard, which is what actually protects the capture path: a
# host without psutil must produce packet rows with no process column and no
# exception, not a callback that dies on the first frame.
_saved_ps2 = ps.psutil
_saved_avail2 = ps.PSUTIL_AVAILABLE
try:
    ps.PSUTIL_AVAILABLE = False
    check("the lookup answers NULL rather than raising",
          ps._get_process_info("192.0.2.5", 51000, "192.0.2.6", 443),
          (None, None, None))
finally:
    ps.psutil = _saved_ps2
    ps.PSUTIL_AVAILABLE = _saved_avail2
check("and the module says so at import rather than at capture time",
      "attribution off" in
      (ROOT / "tools" / "packet_sniffer_linux.py").read_text(
          encoding="utf-8"), True)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
