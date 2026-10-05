# tools/packet_sniffer_linux.py
# AgentalSec Linux - Live packet capture via AF_PACKET/libpcap
#
# Linux equivalent of Windows packet_sniffer.py
# Uses AF_PACKET sockets (native Linux) or libpcap via scapy
#
# Runs in background, writes to packets and findings tables.
# Model reads those tables via query_packets and query_findings tools.

import ipaddress
import logging
import os
import pwd
import socket
import statistics
import struct
import threading
import time
import warnings
from collections import OrderedDict, deque
from datetime import datetime, timezone

warnings.filterwarnings("ignore", category=RuntimeWarning)
logging.getLogger("scapy").setLevel(logging.ERROR)

from tools.ip_defrag import Defragmenter
logger = logging.getLogger(__name__)

# THE IMPORT THAT DISABLED PACKET CAPTURE. Fixed 2026-09-17.
#
# This was ONE try/except around a list of eleven names, and AF_PACKET is not
# one scapy exports from scapy.all on Linux: it lives in scapy.data (and is
# really socket.AF_PACKET). So the ImportError fired on that one name, the
# except caught it, and SCAPY_AVAILABLE was set False on a machine where every
# other scapy import works perfectly.
#
# The consequence was not "capture is off". It was that the packet sniffer
# reported blind_reason "Scapy not installed", which is a FALSE STATEMENT
# about this host: scapy 2.7.0 is installed. Every tool that depends on
# capture then carried a caveat naming the wrong cause, and the fix a reader
# would try, installing scapy, was already done.
#
# Splitting the import means a missing name costs that ONE name. AF_PACKET is
# imported where it is actually used and guarded separately, because capture
# does not need it to sniff, only to open a raw socket by hand.
try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, Raw,
        get_if_list, get_if_hwaddr, get_if_addr,
    )
    SCAPY_AVAILABLE = True
except ImportError as e:
    SCAPY_AVAILABLE = False
    logger.warning(f"scapy not available, packet sniffer running in stub "
                   f"mode: {e}")

try:
    from scapy.all import Ether
except ImportError:
    Ether = None

# DNS, read from the capture itself (SNF-11). Optional like the others.
try:
    from scapy.layers.dns import DNS, dnsqtypes
except ImportError:
    DNS = None
    dnsqtypes = {}

# IPv6 is optional in its own right, so a scapy without it costs only v6 (SNF-10).
try:
    from scapy.layers.inet6 import IPv6, _ICMPv6 as ICMPv6
except ImportError:
    IPv6 = None
    ICMPv6 = None

# TODO 113.5, PORTED 2026-09-21. ARP AND DHCP ARE SEPARATE, OPTIONAL IMPORTS.
#
# MEASURED ON THIS HOST BEFORE THIS WAS ADDED: the module exported Ether, IP,
# TCP, UDP, ICMP and Raw, and NOT ARP, BOOTP or DHCP. The three LAN detections
# added with the tools port look those layers up by name, so without these
# imports LAN-1001 to LAN-1004 would have been wired to a dict of Nones and
# would never have fired on any frame. A silent detector is worse than an
# absent one, because the page shows the feature as present.
#
# Separately guarded rather than folded into the main import block, which is
# the Windows tree's decision and the right one here for the same reason: a
# scapy build without the DHCP layer should cost LAN-1003 and nothing else. If
# these were in the same try/except, a missing BOOTP would set SCAPY_AVAILABLE
# False and take the whole capture down, which is the exact bug this file's own
# header is about (AF_PACKET, 2026-09-17).
try:
    from scapy.all import ARP
except ImportError:
    ARP = None
    logger.warning("scapy ARP layer unavailable, ARP detections off "
                   "(LAN-1001, LAN-1002 will not fire)")

try:
    from scapy.all import BOOTP, DHCP
except ImportError:
    BOOTP = None
    DHCP = None
    logger.warning("scapy DHCP layer unavailable, rogue DHCP detection off "
                   "(LAN-1003 will not fire)")

# IPv6 neighbour discovery and DHCPv6, for the IPv6 LAN checks (LAN-1005 to
# LAN-1007). Guarded on their own so a scapy without them costs only those.
try:
    from scapy.layers.inet6 import (ICMPv6ND_NA, ICMPv6ND_RA,
                                    ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr,
                                    ICMPv6NDOptPrefixInfo)
except ImportError:
    ICMPv6ND_NA = ICMPv6ND_RA = None
    ICMPv6NDOptDstLLAddr = ICMPv6NDOptSrcLLAddr = ICMPv6NDOptPrefixInfo = None
try:
    from scapy.layers.dhcp6 import DHCP6_Advertise, DHCP6_Reply, DHCP6OptServerId
except ImportError:
    DHCP6_Advertise = DHCP6_Reply = DHCP6OptServerId = None

# AF_PACKET is optional and separately guarded. It is socket.AF_PACKET, and
# scapy re-exports it from scapy.data rather than scapy.all on some versions.
try:
    from scapy.data import AF_PACKET
except ImportError:
    try:
        from socket import AF_PACKET
    except ImportError:
        AF_PACKET = None    # not a Linux-style socket family

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not available, packet-to-process attribution off")

# Linux-specific: common interface prefixes
LINUX_INTERFACE_PREFIXES = {
    "eth": "Ethernet",
    "enp": "Ethernet (predictable)",
    "ens": "Ethernet (predictable)",
    "eno": "Ethernet (onboard)",
    "wlan": "WiFi",
    "wlp": "WiFi (predictable)",
    "wlx": "WiFi (USB MAC)",
    "lo": "Loopback",
    "docker": "Docker bridge",
    "veth": "Virtual Ethernet",
    "br": "Bridge",
    "tun": "TUN/TAP",
    "tap": "TAP",
}

# Detection thresholds.
#
# THE BEACON BOUNDS WERE THE WINDOWS TREE'S AND THE PORT DROPPED ALL BUT
# TWO OF THEM. Restored 2026-09-23, and the numbers are the Windows tree's
# own measured values, not new ones (agental_sec/tools/packet_sniffer.py:438).
#
# WHAT WAS WRONG BEFORE. The port kept a hit count and a CV ceiling and lost:
#
#   * the FEED. Windows records a candidate on connection ESTABLISHMENT (SYN
#     without ACK) plus UDP off 53/123, and says why in its own comment,
#     because counting every packet made a single large download look like a
#     beacon. The port fed on every IP packet, so one busy socket at CV 0.299
#     cleared a 0.30 ceiling and was written as "Regular beaconing".
#   * the INTERVAL BOUNDS. Without a floor, a 9.5 packets/s stream is
#     eligible; without a ceiling, this cannot distinguish a 10-second
#     check-in from a 5-minute one.
#   * the WINDOW. Windows keeps 30 minutes per destination and drops what
#     falls out of it; the port kept 100 hits per destination with no clock
#     at all.
#   * the CAP. BEACON_MAX_TRACKED bounds how many destinations a device can
#     make this module remember. The port's map had no eviction path.
#
# MEASURED ON THE LIVE EVIDENCE STORE BEFORE THIS FIX, and this is what it
# bought: 35 PKT-1002 findings, every one false — 23 naming this host's own
# address, 9 naming 127.0.0.1, 3 naming the /24 broadcast, and a
# mean_interval_seconds of 0.105 on a loopback row (CV 0.299). A beacon, per
# this register's own text ("repeated connection attempts to one destination
# at a near-constant interval"), is a sentence about CONNECTION ATTEMPTS.
# None of those 35 rows was one.
BEACON_MIN_SAMPLES   = 8      # deltas needed before a variance means anything
BEACON_WINDOW        = 1800   # 30 minutes of history per destination
BEACON_MAX_CV        = 0.25   # <= 25% variation is suspiciously metronomic
BEACON_MIN_INTERVAL  = 5      # faster than this is a stream, not a beacon
BEACON_MAX_INTERVAL  = 3600   # slower than this is not visible in one window
BEACON_MAX_TRACKED   = 5000   # bound memory, keyed by what a peer chooses

# Measured over 7 days of stored packets: the busiest source other than this
# host peaked at 9,076 in a window (the router, while it was polled every
# second), and 1,000 fired on every download. 20,000 is twice that peak.
VOLUME_THRESHOLD     = 20000  # packets from one source per window (PKT-1001)
VOLUME_WINDOW        = 300    # the window that threshold is measured over
VOLUME_MAX_TRACKED   = 2000   # bound the per-source map the same way

DANGEROUS_PORTS = {4444, 5555, 6666, 31337, 12345, 54321}


def _addr(ip: str):
    """Parse to an ipaddress object."""
    try:
        return ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return None


def _is_private(ip: str) -> bool:
    """Check if address is private/local.

    IPv6 has no NAT, so a LAN peer carries a global address; an address in one
    of this host's own on-link prefixes counts as local too (SNF-10).
    """
    a = _addr(ip)
    if a is None:
        return False
    if a.is_private or a.is_loopback or a.is_link_local:
        return True
    if a.version == 6:
        local_addresses()
        return str(a) in _LOCAL_ADDRESSES or any(a in n for n in _LOCAL_V6_NETS)
    return False


# WHAT THIS HOST IS CALLED, AND WHY A DETECTOR NEEDS TO KNOW. 2026-09-23.
#
# A sensor that watches its own host needs to recognise its own addresses,
# because "this host talked to X" and "this host talked to ITSELF" are
# different facts and only one of them can be a beacon. The module did not
# know either, and the live evidence store is the measurement: 35 PKT-1002
# rows, 23 of them naming this host's own address and 9 naming 127.0.0.1.
#
# THE READ IS A SNAPSHOT, and it has to be, because the addresses on a laptop
# change (a dock, a different WiFi, a VPN coming up). So it is refreshed on
# every capture start and can be refreshed by hand; a stale snapshot can only
# cost a false NEGATIVE (a beacon to an address we used to hold), never a
# false positive, which is the safe direction for a detector to be wrong in.
_LOCAL_ADDRESSES = frozenset()
_LOCAL_ADDRESSES_AT = 0.0
_LOCAL_V6_NETS = ()
_LOCAL_V4_NETS = ()


def _v6_text(raw: str) -> str:
    """Canonical form of a v6 address, without any %interface suffix."""
    a = _addr((raw or "").split("%")[0])
    return str(a) if a is not None else ""


def _read_local_v6_networks() -> tuple:
    """
    The IPv6 prefixes this host is on-link for, from psutil netmasks and the
    kernel's on-link routes. Link-local and multicast are left out, they are
    already local by their own shape.
    """
    nets = set()

    def keep(net):
        if 0 < net.prefixlen < 128 and not (net.is_link_local or net.is_multicast):
            nets.add(net)

    try:
        if PSUTIL_AVAILABLE:
            for _iface, addrs in (psutil.net_if_addrs() or {}).items():
                for a in addrs:
                    if a.family == socket.AF_INET6 and a.address and a.netmask:
                        keep(ipaddress.ip_network(
                            f"{_v6_text(a.address)}/{a.netmask}", strict=False))
    except (ValueError, OSError) as e:
        logger.debug(f"v6 prefix read via psutil failed: {e}")
    try:
        with open("/proc/net/ipv6_route", encoding="utf-8") as f:
            for line in f:
                cols = line.split()
                if len(cols) < 10:
                    continue
                # RTF_GATEWAY (0x2) means reached through a router, not on-link.
                if int(cols[8], 16) & 0x2 or cols[9] == "lo":
                    continue
                dest = ipaddress.IPv6Address(bytes.fromhex(cols[0]))
                keep(ipaddress.ip_network(f"{dest}/{int(cols[1], 16)}",
                                          strict=False))
    except (ValueError, OSError) as e:
        logger.debug(f"v6 prefix read via /proc/net/ipv6_route failed: {e}")
    return tuple(sorted(nets))


def _read_local_v4_networks() -> tuple:
    """The IPv4 networks this host has an address on, from psutil netmasks."""
    nets = set()
    try:
        if PSUTIL_AVAILABLE:
            for _iface, addrs in (psutil.net_if_addrs() or {}).items():
                for a in addrs:
                    if a.family == socket.AF_INET and a.address and a.netmask:
                        net = ipaddress.ip_network(
                            f"{a.address}/{a.netmask}", strict=False)
                        if 0 < net.prefixlen < 31 and not net.is_loopback:
                            nets.add(net)
    except (ValueError, OSError) as e:
        logger.debug(f"v4 network read via psutil failed: {e}")
    return tuple(sorted(nets))


def _read_local_addresses() -> frozenset:
    """
    Every address this host currently holds, read from the kernel.

    FOUR SOURCES, in this order, because no single one is complete:
      * psutil.net_if_addrs() -- the normal path, and it covers VPN and
        container interfaces;
      * /proc/net/fib_trie -- the kernel's own prefix table, which is what is
        left when psutil cannot enumerate (it needs no privilege, but a
        locked-down /proc can still refuse);
      * socket.gethostbyname_ex(hostname) -- the address a peer would reach
        this host on, which is the one that matters most for "is this me";
      * the loopback literals, always, because a loopback capture is never a
        network vantage and the address has to be recognisable either way.

    A failed read contributes NOTHING rather than raising: an empty set means
    "we could not learn our own addresses", and the caller treats that as a
    reason to skip the host-identity check and say so, never as evidence that
    no address is ours.
    """
    found = set()
    try:
        if PSUTIL_AVAILABLE:
            for _iface, addrs in (psutil.net_if_addrs() or {}).items():
                for a in addrs:
                    if a.family == socket.AF_INET and a.address:
                        found.add(a.address)
                    elif a.family == socket.AF_INET6 and _v6_text(a.address):
                        found.add(_v6_text(a.address))
    except Exception as e:
        logger.debug(f"local address read via psutil failed: {e}")
    try:
        with open("/proc/net/if_inet6", encoding="utf-8") as f:
            for line in f:
                cols = line.split()
                if cols:
                    found.add(str(ipaddress.IPv6Address(bytes.fromhex(cols[0]))))
    except (ValueError, OSError) as e:
        logger.debug(f"local address read via /proc/net/if_inet6 failed: {e}")
    try:
        with open("/proc/net/fib_trie", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # The local-host rows are the ones marked "/32 host LOCAL".
                if line.endswith("host LOCAL") or "host LOCAL" in line:
                    cand = line.split()[0]
                    if _addr(cand):
                        found.add(cand)
    except OSError as e:
        logger.debug(f"local address read via /proc/net/fib_trie failed: {e}")
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if _addr(ip):
                found.add(ip)
    except OSError as e:
        logger.debug(f"local address read via hostname failed: {e}")
    found.update({"127.0.0.1", "::1"})
    return frozenset(found)


def refresh_local_addresses() -> frozenset:
    """Re-read this host's addresses and remember them. Returns the set."""
    global _LOCAL_ADDRESSES, _LOCAL_ADDRESSES_AT, _LOCAL_V6_NETS, _LOCAL_V4_NETS
    _LOCAL_ADDRESSES = _read_local_addresses()
    _LOCAL_V6_NETS = _read_local_v6_networks()
    _LOCAL_V4_NETS = _read_local_v4_networks()
    _LOCAL_ADDRESSES_AT = time.time()
    return _LOCAL_ADDRESSES


def local_addresses() -> frozenset:
    """
    The cached set, read once if it has never been read.

    A detector calls this per packet, so it must not do the read per packet:
    psutil's net_if_addrs is cheap but not free, and the set only changes when
    the machine's network changes.
    """
    if not _LOCAL_ADDRESSES:
        return refresh_local_addresses()
    return _LOCAL_ADDRESSES


def local_addresses_read_at() -> float:
    """When the snapshot was taken (0.0 = never). Reported, never guessed."""
    return _LOCAL_ADDRESSES_AT


def is_self_address(ip: str) -> bool:
    """Is this address one THIS host holds?"""
    if not ip:
        return False
    return ip in local_addresses() or (":" in ip and _v6_text(ip) in local_addresses())


def is_group_address(ip: str) -> bool:
    """
    A multicast or broadcast address: reachable, but not a device.

    Broadcast comes in three spellings and all three arrive as real
    destinations on a capture: 255.255.255.255, a subnet broadcast such as
    192.0.2.255 (which is what the live PKT-1002 rows name), and IPv6's
    all-nodes ff02::1. `geoip.is_host_address()` is the app's older half of
    this question and answers for multicast; the broadcast cases are handled
    here because a /24 broadcast is not multicast and is not loopback, so it
    slipped through every existing check.
    """
    a = _addr(ip)
    if a is None:
        return False
    if a.is_multicast:
        return True
    if a.version != 4:
        return False
    if str(a) == "255.255.255.255":
        return True
    # On a network this host is on, the netmask says which address is the
    # broadcast; x.x.x.255 is a real host on a /23 or wider (SNF-22).
    for net in _LOCAL_V4_NETS:
        if a in net:
            return a == net.broadcast_address
    # Elsewhere the netmask is unknown, so a private .255 is taken as one.
    return bool(a.is_private and str(a).endswith(".255"))


def peer_is_a_host(ip: str) -> tuple[bool, str]:
    """
    Could the address a packet was aimed at be a HOST, and is it not us?

    Returns (True, "") for a destination that could be a device somewhere
    else, and (False, reason) for the three kinds of destination no detection
    in this module may raise a finding about:

        this host's own address     the traffic is the host talking to itself
        127.0.0.1 / ::1             the same sentence, spelled differently
        multicast / broadcast       a group is not a device

    THE REASON IS RETURNED RATHER THAN LOGGED, because the caller's answer
    ("did we skip this packet") has to be readable by a test and by the status
    block, and a detector that silently skips is the failure this whole round
    is about.

    AN EMPTY ADDRESS SNAPSHOT IS NOT A PASS. If the host's own addresses
    could not be read, this cannot tell self-traffic from remote traffic, and
    the honest answer is (False, ...) with the reason saying the read failed —
    not a green that lets the detection run on a guess.
    """
    a = _addr(ip)
    if a is None:
        return False, "the destination is not an address this module can parse"
    # READ THE SNAPSHOT BEFORE JUDGING IT. `local_addresses()` reads once and
    # caches; asking it here means the FIRST call (before any capture has
    # started) triggers that read instead of falling into the empty-set branch
    # below, which would refuse every destination on the first packet and
    # silently disable every detection that runs before a capture. That was a
    # real bug in the first version of this function.
    known = local_addresses()
    if not known:
        return False, ("this host's own addresses could not be read, so a "
                       "destination cannot be told from this host's own "
                       "traffic; no detection ran on this packet")
    if a.is_loopback:
        return False, "the destination is loopback: the host talking to itself"
    if ip in known or str(a) in known:
        return False, "the destination is an address THIS HOST holds"
    if is_group_address(ip):
        return False, "the destination is a multicast or broadcast group, not a host"
    return True, ""


def classify_scope(src: str, dst: str) -> str:
    """Classify packet scope (same logic as Windows version)."""
    s, d = _addr(src), _addr(dst)
    if s is None or d is None:
        return "unclassified"
    
    if d.is_loopback and s.is_loopback:
        return "loopback"
    
    if d.is_multicast:
        return "local_multicast" if _is_private(src) else "foreign_multicast"
    
    if str(d) == "255.255.255.255":
        return "broadcast"

    # A subnet broadcast (192.0.2.255 and its shape) is not 255.255.255.255 and
    # is not multicast, so before this line it fell through to
    # private_to_private and was recorded as ordinary LAN traffic. Three live
    # PKT-1002 rows name one, which is how it was found.
    if is_group_address(dst) and str(d) != "255.255.255.255":
        return "broadcast"

    s_priv, d_priv = _is_private(src), _is_private(dst)
    if s_priv and d_priv:
        return "private_to_private"
    if s_priv and not d_priv:
        return "outbound"
    if d_priv and not s_priv:
        return "inbound"
    return "public_to_public"


def _get_direction(scope: str) -> str:
    """Map scope to direction for database."""
    mapping = {
        "private_to_private": "internal",
        "loopback": "internal",
        "local_multicast": "internal",
        "broadcast": "internal",
        "outbound": "outbound",
        "inbound": "inbound",
        "foreign_multicast": "inbound",
        "public_to_public": "inbound",
        "unclassified": "inbound",
    }
    return mapping.get(scope, "inbound")


# THE ATTRIBUTION CACHE. 2026-09-23, SNF-3 and SNF-13.
#
# WHAT THIS REPLACES AND WHY. `_analyze_packet` called `_get_process_info`,
# which called `psutil.net_connections(kind='inet')` ONCE PER CAPTURED PACKET.
# That call is a full sweep of the system's socket table. Measured on this
# workstation, idle, 16 sockets:
#
#     psutil.net_connections(kind='inet')    10.0 - 11.2 ms per walk
#     _analyze_packet, as shipped             14.1 ms per packet
#     _analyze_packet, walk stubbed out        0.589 ms per packet
#     -> capture ceiling                      71 packets/s
#
# A saturated 1 GbE link with small packets is about a million packets a
# second. The sensor was three to four orders of magnitude below the link it
# was listening to, and the CPU it burned doing it was inside the capture
# thread, which is the one thread that must never block.
#
# So: ONE walk every ATTRIBUTION_TTL seconds, built into a dict, and the
# per-packet cost becomes two dict lookups. The TTL is a real trade and it is
# stated rather than buried: a connection that starts and finishes between two
# walks is not attributed, and a socket that closes keeps its name until the
# next walk. On a laptop that costs the attribution on short-lived flows, and
# the row still says "not attributed" instead of guessing.
#
# THE DIRECTION ARGUMENT IS SNF-13. `_get_process_info` tried `(src_ip,
# src_port)` first and `(dst_ip, dst_port)` second, in that order, always --
# so for a packet this host RECEIVED it looked up the REMOTE peer's address
# first and, if the local table happened to hold a socket on that address, it
# named the wrong process. It did not know which end was local, because
# `_analyze_packet` did not tell it. Now the caller passes the direction and
# the lookup tries the local end FIRST, which is the end the packet's own
# scope already says it is.
ATTRIBUTION_TTL = 1.0        # seconds a socket snapshot is trusted
PID_INFO_TTL = 5.0           # seconds a pid's name/cmdline is reused
PID_INFO_MAX = 2048          # ceiling on the pid description cache

_conn_index = {}             # (ip, port) -> pid
_conn_index_at = 0.0
_conn_index_lock = threading.Lock()
_conn_index_note = "never built"
_pid_info = {}               # pid -> (name, cmdline, read_at)


def _walk_connections() -> tuple[dict, str]:
    """
    One sweep of the OS socket table, as a dict keyed by (address, port).

    Returns (index, note). The note is a sentence and it is always set: an
    empty index with an unreadable table ("AccessDenied") is a different fact
    from an empty index on a machine with no sockets, and the caller's status
    block prints it rather than letting both read as "nothing is connected".
    """
    if not PSUTIL_AVAILABLE:
        return {}, "psutil is not available, so no packet can be attributed"
    index = {}
    try:
        for conn in psutil.net_connections(kind="inet"):
            pid = conn.pid
            laddr = getattr(conn, "laddr", None)
            if not laddr or pid is None:
                continue
            ip = getattr(laddr, "ip", None)
            port = getattr(laddr, "port", None)
            if not ip or port is None:
                continue
            if ":" in ip:
                ip = _v6_text(ip) or ip
            # First writer wins for a repeated (ip, port): a listening socket
            # and an accepted socket can share a port, and the listener is the
            # process that OWNS the flow for attribution purposes.
            index.setdefault((ip, port), pid)
    except Exception as e:
        return {}, f"the socket table could not be read ({e})"
    return index, f"{len(index)} local endpoints indexed"


def _refresh_conn_index() -> tuple[dict, str]:
    """Rebuild the snapshot if it is older than ATTRIBUTION_TTL."""
    global _conn_index, _conn_index_at, _conn_index_note
    now = time.monotonic()
    with _conn_index_lock:
        if _conn_index_at and (now - _conn_index_at) < ATTRIBUTION_TTL:
            return _conn_index, _conn_index_note
        index, note = _walk_connections()
        _conn_index, _conn_index_at, _conn_index_note = index, now, note
        return _conn_index, _conn_index_note


def attribution_state() -> dict:
    """
    What the attribution cache is doing, for the status block.

    Published rather than inferred, the same rule as `capture_interface()`:
    a sensor reading with no process column has to be readable as "not
    looked" or "looked and found nothing", and the age of the snapshot is the
    part a reader needs.
    """
    index, note = _refresh_conn_index()
    return {
        "index_size": len(index),
        "age_seconds": (None if not _conn_index_at
                        else round(time.monotonic() - _conn_index_at, 2)),
        "ttl_seconds": ATTRIBUTION_TTL,
        "pid_cache_size": len(_pid_info),
        "pid_cache_ttl_seconds": PID_INFO_TTL,
        "note": note,
    }


def _describe_pid(pid):
    """
    (name, cmdline) for a pid, or (None, None) with the reason logged.

    CACHED, because this reads /proc/<pid>/{comm,cmdline} twice per call and it
    is called once per captured packet. Measured after the socket-snapshot
    cache went in, the remaining 1.0 ms of a packet's 1.015 ms was this
    function: the snapshot made the LOOKUP free and left the DESCRIPTION
    expensive. A pid's name and command line do not change while it lives, so
    the entry is reused for PID_INFO_TTL seconds; a pid that dies and is
    reused inside that window is the one way this can be stale, and the
    process that inherits it will have been gone less than five seconds.
    """
    if pid is None:
        return None, None
    now = time.monotonic()
    hit = _pid_info.get(pid)
    if hit and (now - hit[2]) < PID_INFO_TTL:
        return hit[0], hit[1]
    try:
        proc = psutil.Process(pid)
        name, cmdline = proc.name(), " ".join(proc.cmdline())
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        logger.debug(f"pid {pid} could not be described: {e}")
        name, cmdline = None, None
    except Exception as e:
        logger.debug(f"pid {pid} lookup failed: {e}")
        name, cmdline = None, None
    _pid_info[pid] = (name, cmdline, now)
    if len(_pid_info) > PID_INFO_MAX:
        oldest = min(_pid_info, key=lambda k: _pid_info[k][2])
        _pid_info.pop(oldest, None)
    return name, cmdline



def _get_process_info(src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                      direction: str = None):
    """
    The process owning a flow, from the cached snapshot.

    Args:
        direction: "outbound" means this host is the SOURCE end, "inbound"
            means it is the DESTINATION end, and None means "we were not
            told", in which case both ends are tried in order and the first
            hit wins -- the old behaviour, kept for callers that genuinely do
            not know, and reported as such in the log.

    Returns (pid, name, cmdline) or (None, None, None). Nothing is guessed:
    an absent entry returns Nones so the packet row stays NULL and reads as
    "not attributed", which is the rule tests/test_packet_attribution.py
    exists to hold.
    """
    if not PSUTIL_AVAILABLE:
        return None, None, None
    index, _note = _refresh_conn_index()

    local_first = ([(src_ip, src_port), (dst_ip, dst_port)]
                   if direction != "inbound"
                   else [(dst_ip, dst_port), (src_ip, src_port)])
    if direction is None:
        logger.debug("attribution was asked without a direction; trying both "
                     "ends with the source first, which can name the remote "
                     "peer's process on an inbound packet")

    for key in local_first:
        if not key[0] or key[1] is None:
            continue
        pid = index.get(key)
        if pid is None:
            continue
        name, cmdline = _describe_pid(pid)
        return pid, name, cmdline
    return None, None, None


# SECOND SOURCE: THE eBPF CAMERA'S connect() RECORDS (SNF-24). The socket
# snapshot above is taken once a second, so a flow that opens and closes
# between two snapshots has no owner. The camera records every connect(2) with
# its pid as it happens, in a read-only sidecar file, so an outbound flow the
# snapshot missed can still be named. Its clock is CLOCK_MONOTONIC, the same
# one time.monotonic() reads.
EBPF_ATTRIB_REFRESH = 1.0      # seconds between reads of the sidecar
EBPF_ATTRIB_WINDOW = 120.0     # how long a connect() may name a flow
EBPF_ATTRIB_MAX = 8192         # destinations held at once
EBPF_ATTRIB_BATCH = 5000       # rows read per refresh

_ebpf_db = None
_ebpf_index = {}               # (address, port) -> (monotonic secs, pid, comm)
_ebpf_state = {"last_id": 0, "read_at": 0.0, "rows_read": 0,
               "note": "the eBPF camera file has not been configured"}
_attribution_counts = {"socket_table": 0, "ebpf_connect": 0, "none": 0}


def set_ebpf_events_db(path: str | None) -> None:
    """Point attribution at the camera's sidecar file, or None to stop."""
    global _ebpf_db
    _ebpf_db = path or None
    _ebpf_index.clear()
    _ebpf_state.update(last_id=0, read_at=0.0, rows_read=0,
                       note=("configured" if path else
                             "the eBPF camera is switched off"))


def _refresh_ebpf_index(now: float = None) -> None:
    """Read connect() rows newer than the last one read, at most once a second."""
    now = time.monotonic() if now is None else now
    if not _ebpf_db or now - _ebpf_state["read_at"] < EBPF_ATTRIB_REFRESH:
        return
    _ebpf_state["read_at"] = now
    if not os.path.exists(_ebpf_db):
        _ebpf_state["note"] = "the eBPF camera file does not exist"
        return
    try:
        from tools import ebpf_events
        conn = ebpf_events._ro_connect(_ebpf_db)
        try:
            newest = int(conn.execute(
                "SELECT MAX(id) FROM ebpf_event").fetchone()[0] or 0)
            if not _ebpf_state["last_id"]:
                # First read: start near the end by id, a key range, rather
                # than scanning a table that holds the camera's whole history.
                _ebpf_state["last_id"] = max(0, newest - EBPF_ATTRIB_BATCH)
            floor_ns = int(max(0.0, now - EBPF_ATTRIB_WINDOW) * 1e9)
            # "+kind" keeps SQLite on the id range instead of the (kind, ts_ns)
            # index, which walks every connect ever recorded. ts_ns restarts
            # at each boot, so recorded_at, the camera's wall clock, keeps an
            # earlier boot's rows out of the window.
            rows = conn.execute(
                "SELECT id, pid, comm, daddr, dport, ts_ns FROM ebpf_event "
                "WHERE id > ? AND id <= ? AND +kind = 'connect' "
                "AND ts_ns BETWEEN ? AND ? "
                "AND recorded_at >= datetime('now', ?) "
                "ORDER BY id ASC LIMIT ?",
                (_ebpf_state["last_id"], newest, floor_ns, int(now * 1e9) + 10**9,
                 f"-{int(EBPF_ATTRIB_WINDOW) + 5} seconds",
                 EBPF_ATTRIB_BATCH)).fetchall()
        finally:
            conn.close()
    except Exception as e:                                    # noqa: BLE001
        _ebpf_state["note"] = f"the eBPF camera file could not be read ({e})"
        return
    for row_id, pid, comm, daddr, dport, ts_ns in rows:
        _ebpf_state["last_id"] = max(_ebpf_state["last_id"], int(row_id))
        addr = _v6_text(daddr) if daddr and ":" in str(daddr) else str(daddr or "")
        if addr and dport:
            _ebpf_index[(addr, int(dport))] = (int(ts_ns) / 1e9, pid, comm)
    if len(rows) < EBPF_ATTRIB_BATCH:
        # Everything up to `newest` was looked at, matching or not.
        _ebpf_state["last_id"] = max(_ebpf_state["last_id"], newest)
    _ebpf_state["rows_read"] += len(rows)
    if len(_ebpf_index) > EBPF_ATTRIB_MAX:
        for key in sorted(_ebpf_index, key=lambda k: _ebpf_index[k][0])[
                :len(_ebpf_index) - EBPF_ATTRIB_MAX // 2]:
            del _ebpf_index[key]
    _ebpf_state["note"] = f"{len(_ebpf_index)} recent connect() destinations held"


def _ebpf_owner(remote_ip: str, remote_port: int, now: float = None):
    """(pid, comm) of the recent connect() to this remote end, or (None, None)."""
    if not _ebpf_db or not remote_ip or not remote_port:
        return None, None
    now = time.monotonic() if now is None else now
    _refresh_ebpf_index(now)
    key = (_v6_text(remote_ip) if ":" in remote_ip else remote_ip, int(remote_port))
    hit = _ebpf_index.get(key)
    if not hit or now - hit[0] > EBPF_ATTRIB_WINDOW:
        return None, None
    return hit[1], hit[2]


def ebpf_attribution_state() -> dict:
    """What the camera-based attribution is doing, for the status block."""
    return {"events_db": _ebpf_db, "held": len(_ebpf_index),
            "window_seconds": EBPF_ATTRIB_WINDOW,
            "rows_read": _ebpf_state["rows_read"], "note": _ebpf_state["note"],
            "packets_attributed_by": dict(_attribution_counts)}


def _analyze_packet(pkt, direction_hint: str = None):
    """
    Extract information from a captured packet.

    `direction_hint` is what the caller already knows and the packet does not:
    which end of this flow is local. It is passed to the attribution lookup so
    the local end is tried first (SNF-13); when it is None the lookup falls
    back to trying both ends, which is what this used to do for every packet.

    Returns dict with packet data or None if not an IPv4 or IPv6 packet.
    """
    if not SCAPY_AVAILABLE:
        return None

    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
    elif IPv6 is not None and pkt.haslayer(IPv6):
        ip_layer = pkt[IPv6]
    else:
        return None
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    
    # Get transport layer
    protocol = "unknown"
    src_port = None
    dst_port = None
    payload = None
    tcp_flags = None
    
    if pkt.haslayer(TCP):
        protocol = "tcp"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        # The flag blob is NOT decoration: everything downstream that wants a
        # "connection attempt" rather than a frame (the beacon feed, PKT-1002)
        # reads it. Dropping it here is what forced the old detector to count
        # packets instead, and a packet count cannot tell a check-in from a
        # download.
        try:
            tcp_flags = str(pkt[TCP].flags)
        except Exception:
            tcp_flags = None
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)[:256].hex()
    elif pkt.haslayer(UDP):
        protocol = "udp"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)[:256].hex()
    elif pkt.haslayer(ICMP):
        protocol = "icmp"
    elif icmpv6_layer(pkt) is not None:
        protocol = "icmpv6"
    
    # Classify scope
    scope = classify_scope(src_ip, dst_ip)
    direction = _get_direction(scope)
    
    # Get process info, from the cached snapshot, with the local end first.
    pid, proc_name, cmdline = None, None, None
    attributed_by = None
    if PSUTIL_AVAILABLE and src_port and dst_port:
        pid, proc_name, cmdline = _get_process_info(
            src_ip, src_port, dst_ip, dst_port,
            direction=direction_hint or direction)
        if pid is not None:
            attributed_by = "socket_table"
    # A flow the snapshot missed: the camera's connect() to the remote end.
    # The remote end is whichever side is not this host, which also covers
    # LAN flows whose scope is "internal".
    if pid is None and src_port and dst_port and _ebpf_db:
        if is_self_address(src_ip):
            pid, proc_name = _ebpf_owner(dst_ip, dst_port)
        elif is_self_address(dst_ip):
            pid, proc_name = _ebpf_owner(src_ip, src_port)
        if pid is not None:
            attributed_by = "ebpf_connect"
    _attribution_counts[attributed_by or "none"] += 1
    
    # Get packet length
    pkt_len = len(pkt)

    udp_flow = (udp_flow_note(src_ip, src_port, dst_ip, dst_port, direction)
                if protocol == "udp" and src_port and dst_port else None)

    return {
        "udp_flow": udp_flow,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "direction": direction,
        "scope": scope,
        "length": pkt_len,
        "payload_hex": payload,
        "tcp_flags": tcp_flags,
        "pid": pid,
        "process_name": proc_name,
        "process_cmdline": cmdline,
        "attributed_by": attributed_by,
        "interface": getattr(pkt, "iface", "unknown"),
    }


# DETECTION STATE. 2026-09-23, SNF-1, SNF-2, SNF-14, SNF-17.
#
# THREE TABLES, each keyed by what a remote device chooses to send, each with
# a ceiling, and each with an eviction path. The old module had one
# unbounded dict (`_beacon_data`), one dead declaration (`_seen_connections`
# / `_CONNECTION_CACHE_MAX`, each appearing exactly once in the file -- its
# own declaration) and no volume counter at all despite the register carrying
# PKT-1001 for it.
#
# THE EVICTION RULE IS THE SAME FOR ALL THREE and it is not LRU: when the map
# is at its cap, the OLDEST-TOUCHED key is dropped, because the thing being
# protected against is a peer that floods new keys to grow this module's
# memory. An LRU drops the quiet long-term beacon in favour of the flood, which
# is backwards for this job.
_beacon_data = {}             # dst -> {"hits": deque[(t, flags)], "last_flagged": t}
_volume_data = {}            # src -> deque[t]
_detections_skipped = {}     # why a packet was not considered, counted


def icmpv6_layer(pkt):
    """The ICMPv6 layer of a frame, past any extension headers, or None."""
    if ICMPv6 is None:
        return None
    layer = pkt
    while layer:
        if isinstance(layer, ICMPv6):
            return layer
        layer = layer.payload if layer.payload else None
    return None


# ICMPv6 router advertisement and redirect (RFC 4861).
ICMPV6_ROUTING_TYPES = {134: "router advertisement", 137: "redirect"}


def icmpv6_routing_verdict(src: str, hop_limit: int, icmp_type: int) -> str | None:
    """
    Why an IPv6 router advertisement or redirect cannot be from this link, or
    None when it can. RFC 4861 requires a link-local source and a hop limit of
    255 on both, so anything else was forged or crossed a router (PKT-1016).
    """
    kind = ICMPV6_ROUTING_TYPES.get(icmp_type)
    if kind is None:
        return None
    a = _addr(_v6_text(src))
    reasons = []
    if a is None or not a.is_link_local:
        reasons.append(f"its source {src} is not a link-local address")
    if hop_limit != 255:
        reasons.append(f"its hop limit is {hop_limit}, not 255, so it crossed a router")
    if not reasons:
        return None
    return (f"An IPv6 {kind} arrived that cannot have come from this network: "
            + " and ".join(reasons) + ". A real router on this link always "
            "sends both right, so this one was forged or relayed from outside.")


# UDP FLOWS (SNF-11). UDP has no handshake, so a flow is the 5-tuple seen
# within UDP_FLOW_IDLE seconds of its last frame. Bounded like every other
# table here; the oldest-touched flow is dropped first.
UDP_FLOW_IDLE = 120.0
UDP_FLOW_MAX = 4096
_udp_flows = OrderedDict()
_udp_flows_lock = threading.Lock()


def udp_flow_note(src_ip, src_port, dst_ip, dst_port, direction,
                  now: float = None) -> dict:
    """
    Record one UDP frame and say where it sits in its flow.

    Returns {"new": bool, "answered": bool, "frames": int}. `new` is True for
    the first frame of a flow and for the first after it was idle; `answered`
    is True once frames have gone both ways.
    """
    now = time.monotonic() if now is None else now
    # Keyed local end first, so a query and its reply land on one flow.
    if direction == "inbound":
        key, outgoing = (dst_ip, dst_port, src_ip, src_port), False
    elif direction == "outbound":
        key, outgoing = (src_ip, src_port, dst_ip, dst_port), True
    else:
        a, b = (src_ip, src_port), (dst_ip, dst_port)
        key = a + b if a <= b else b + a
        outgoing = (a <= b)
    with _udp_flows_lock:
        flow = _udp_flows.get(key)
        new = flow is None or now - flow["last"] > UDP_FLOW_IDLE
        if new:
            flow = {"first": now, "last": now, "out": 0, "in": 0}
            _udp_flows[key] = flow
        flow["last"] = now
        flow["out" if outgoing else "in"] += 1
        _udp_flows.move_to_end(key)
        while len(_udp_flows) > UDP_FLOW_MAX:
            _udp_flows.popitem(last=False)
        return {"new": new, "answered": bool(flow["out"] and flow["in"]),
                "frames": flow["out"] + flow["in"]}


# DNS by port: plain DNS, and the two local name protocols (SNF-11, SNF-23).
DNS_PORTS = {53: "dns", 5353: "mdns", 5355: "llmnr"}

# Encrypted DNS. A host using these resolves names this sensor cannot read,
# so they are counted as a blind spot rather than looked through.
DOT_PORT = 853
DOH_HOSTS = frozenset({
    "dns.google", "dns.google.com", "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com",
    "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com",
    "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
    "doh.opendns.com", "dns.nextdns.io", "doh.cleanbrowsing.org",
    "dns.adguard.com", "dns.adguard-dns.com", "doh.mullvad.net",
    "dns.mullvad.net", "freedns.controld.com",
})

_DNS_NAME_MAX = 253


def _dns_message(pkt):
    """
    (parsed DNS, protocol label, is_response_port) from a frame on a DNS
    port, or None. Parsed from the transport payload rather than scapy's own
    layer binding, which differs for LLMNR and for DNS over TCP.
    """
    if DNS is None:
        return None
    if pkt.haslayer(UDP):
        sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
        raw = bytes(pkt[UDP].payload)
        tcp = False
    elif pkt.haslayer(TCP):
        sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
        raw = bytes(pkt[TCP].payload)
        tcp = True
    else:
        return None
    port = dport if dport in DNS_PORTS else sport if sport in DNS_PORTS else None
    if port is None or (tcp and port != 53) or len(raw) < 12:
        return None
    if tcp:
        # DNS over TCP carries a two-byte length; only a segment that holds
        # one whole message is read.
        n = int.from_bytes(raw[:2], "big")
        if n < 12 or len(raw) < 2 + n:
            return None
        raw = raw[2:2 + n]
    try:
        msg = DNS(raw)
    except Exception:                                         # noqa: BLE001
        return None
    label = DNS_PORTS[port] + ("-tcp" if tcp else "")
    return msg, label


def _dns_name(value) -> str:
    """A DNS name as lower-case text without the trailing dot, or ''."""
    try:
        name = value.decode("ascii", errors="replace") if isinstance(
            value, bytes) else str(value)
    except Exception:                                         # noqa: BLE001
        return ""
    name = name.rstrip(".").lower()
    return name if 0 < len(name) <= _DNS_NAME_MAX else ""


def dns_query_of(pkt) -> dict | None:
    """
    The question in a DNS, LLMNR or mDNS query frame, or None.

    Queries only (QR=0). DNS over UDP and TCP port 53, LLMNR on 5355 and mDNS
    on 5353. The name is lower-cased, the trailing dot dropped and anything
    past 253 characters refused, since a name is chosen by whoever sent it.
    """
    got = _dns_message(pkt)
    if got is None:
        return None
    dns, label = got
    if dns.qr != 0 or not dns.qd:
        return None
    q = dns.qd[0] if isinstance(dns.qd, list) else dns.qd
    name = _dns_name(q.qname)
    if not name:
        return None
    return {"domain": name,
            "query_type": dnsqtypes.get(int(q.qtype), str(int(q.qtype))),
            "txid": int(dns.id), "protocol": label}


_ANSWER_TYPES = {1: "A", 28: "AAAA", 5: "CNAME"}
_MAX_ANSWERS = 32


def dns_answers_of(pkt) -> dict | None:
    """
    What a DNS, LLMNR or mDNS response said, or None.

    Returns {"protocol", "rcode", "question", "answers": [(name, rrtype,
    value, ttl)]}. A, AAAA and CNAME records only; an NXDOMAIN reply comes
    back as one ("<question>", "NXDOMAIN", "", None) answer, since the name
    not existing is the fact worth keeping.
    """
    got = _dns_message(pkt)
    if got is None:
        return None
    dns, label = got
    if dns.qr != 1:
        return None
    question = ""
    if dns.qd:
        q = dns.qd[0] if isinstance(dns.qd, list) else dns.qd
        question = _dns_name(q.qname)
    answers = []
    if int(dns.rcode) == 3:
        if question:
            answers.append((question, "NXDOMAIN", "", None))
    else:
        for rr in list(dns.an or [])[:_MAX_ANSWERS]:
            rrtype = _ANSWER_TYPES.get(int(getattr(rr, "type", 0) or 0))
            name = _dns_name(getattr(rr, "rrname", b""))
            if not rrtype or not name:
                continue
            value = rr.rdata
            value = _dns_name(value) if rrtype == "CNAME" else str(value)
            if rrtype != "CNAME" and _addr(value) is None:
                continue
            if value:
                answers.append((name, rrtype, value, int(rr.ttl or 0)))
    if not answers:
        return None
    return {"protocol": label, "rcode": int(dns.rcode),
            "question": question, "answers": answers}


def encrypted_dns_of(packet_data: dict, sni: str = None) -> str | None:
    """
    'dot', 'doq' or 'doh' when a flow is DNS this sensor cannot read, else
    None. DoT and DoQ are port 853; DoH is HTTPS to a known resolver name.
    """
    if sni and sni.lower().rstrip(".") in DOH_HOSTS:
        return "doh"
    if packet_data.get("dst_port") != DOT_PORT:
        return None
    if packet_data.get("protocol") == "tcp":
        flags = packet_data.get("tcp_flags") or ""
        return "dot" if ("S" in flags and "A" not in flags) else None
    if packet_data.get("protocol") == "udp":
        flow = packet_data.get("udp_flow")
        return "doq" if flow is None or flow.get("new") else None
    return None


def _note_skip(reason: str):
    """Count a skipped packet by reason, so the skips are readable."""
    _detections_skipped[reason] = _detections_skipped.get(reason, 0) + 1


def detection_state() -> dict:
    """
    The three tables' sizes, ceilings and every skip reason with its count.

    A detector that silently skips packets is the failure this whole round is
    about, so the skip counts are part of the sensor's own report rather than
    a debug line nobody reads.
    """
    return {
        "beacon_tracked": len(_beacon_data),
        "beacon_max_tracked": BEACON_MAX_TRACKED,
        "volume_tracked": len(_volume_data),
        "volume_max_tracked": VOLUME_MAX_TRACKED,
        "udp_flows_tracked": len(_udp_flows),
        "udp_flows_max_tracked": UDP_FLOW_MAX,
        "skipped": dict(_detections_skipped),
    }


def _evict_oldest(table: dict, cap: int):
    """
    Bring a table back to its ceiling by dropping the oldest-touched keys.

    A `while`, not an `if`: the direct-insert path (a caller building the table
    without going through the detector) can arrive over the cap by more than
    one, and an eviction that removes one key per insert is a bound that only
    holds if every caller is well behaved. Evicting to the cap is the same cost
    amortised and is a bound that is actually a bound.
    """
    while len(table) > cap:
        oldest = min(table, key=lambda k: table[k].get("touched", 0)
                     if isinstance(table[k], dict) else 0)
        table.pop(oldest, None)


def _is_connection_attempt(packet_data: dict) -> tuple[bool, str]:
    """
    Is this frame the START of a connection, rather than one frame of a stream?

    This is the feed rule the Windows sniffer states and the port dropped:
    "Only count a beacon candidate on connection ESTABLISHMENT (SYN without
    ACK), not on every packet in a stream. Counting every packet made a single
    large download look like a beacon."

    THE MEASUREMENT THAT FORCED IT BACK, 2026-09-23: 35 live PKT-1002 rows,
    all false. Nine name 127.0.0.1 with a mean interval of 0.105 s and a CV of
    0.299 -- one TCP flow's packets, not 100 check-ins.

    Returns (is_attempt, reason_when_not).
    """
    protocol = (packet_data.get("protocol") or "").lower()
    if protocol == "tcp":
        flags = packet_data.get("tcp_flags")
        if not flags:
            # No flags means the frame did not carry a TCP header we read.
            # That is "could not tell", not "not an attempt", and the answer
            # to "could not tell" here is to not count it.
            return False, "tcp frame with no readable flags"
        if "S" in flags and "A" not in flags:
            return True, ""
        return False, "tcp frame of an established stream (not a SYN)"
    if protocol == "udp":
        dport = packet_data.get("dst_port")
        if dport in (53, 123):
            return False, "udp on a resolver/clock port"
        # A UDP flow's start is its first frame, or the first after it went
        # quiet; every other frame is the same conversation (SNF-11).
        flow = packet_data.get("udp_flow")
        if flow is not None and not flow.get("new"):
            return False, "udp frame of an ongoing flow (not its start)"
        return True, ""
    if protocol in ("icmp", "icmpv6"):
        return False, f"{protocol} has no connection to establish"
    return False, f"protocol {protocol or 'unknown'} is not a connection"


def _detect_beaconing(packet_data: dict) -> dict | None:
    """
    Detect beaconing: repeated CONNECTION ATTEMPTS to one destination at a
    near-constant interval.

    The bounds are the Windows tree's (see the constants) and every one of
    them is load-bearing:

        BEACON_MIN_SAMPLES   eight deltas, because a regularity score over
                             four numbers is a coincidence with a decimal
        BEACON_WINDOW        hits older than 30 minutes leave the window,
                             so a destination's history cannot grow forever
        BEACON_MAX_CV        and the ceiling is 0.25, not 0.30: a live row at
                             0.299 was written as "Regular beaconing" under
                             the looser number
        BEACON_MIN_INTERVAL  faster than 5 s is a stream, not a check-in
        BEACON_MAX_INTERVAL  slower than an hour is not visible in one window

    AND THE DESTINATION HAS TO BE A HOST. A beacon to this host's own address,
    to loopback, or to a broadcast group is not a beacon; it is the host's own
    traffic, and the three of those were 35 of 35 live rows.
    """
    dst = packet_data.get("dst_ip")
    if not dst:
        return None

    # is the destination a host that is not us?
    is_host, why_not = peer_is_a_host(dst)
    if not is_host:
        _note_skip(f"beacon: {why_not}")
        return None

    is_attempt, why_not_attempt = _is_connection_attempt(packet_data)
    if not is_attempt:
        _note_skip(f"beacon: {why_not_attempt}")
        return None

    now = time.time()
    entry = _beacon_data.get(dst)
    if entry is None:
        _evict_oldest(_beacon_data, BEACON_MAX_TRACKED - 1)
        entry = {"hits": deque(maxlen=BEACON_MIN_SAMPLES * 4),
                 "last_flagged": 0.0, "touched": now}
        _beacon_data[dst] = entry
    entry["touched"] = now

    hits = entry["hits"]
    hits.append(now)
    # Drop what fell out of the window. This is the clock the port never had.
    cutoff = now - BEACON_WINDOW
    while hits and hits[0] < cutoff:
        hits.popleft()

    timestamps = list(hits)
    deltas = [timestamps[i + 1] - timestamps[i]
              for i in range(len(timestamps) - 1)]
    if len(deltas) < BEACON_MIN_SAMPLES:
        return None

    mean_delta = statistics.mean(deltas)
    if mean_delta <= 0:
        return None
    std_delta = statistics.stdev(deltas)
    cv = std_delta / mean_delta

    if not (BEACON_MIN_INTERVAL <= mean_delta <= BEACON_MAX_INTERVAL):
        return None
    if cv > BEACON_MAX_CV:
        return None
    if now - entry["last_flagged"] <= 300:
        return None

    entry["last_flagged"] = now
    return {
        "type": "beaconing_detected",
        "dst_ip": dst,
        "connection_count": len(timestamps),
        "avg_interval": mean_delta,
        "coefficient_of_variation": cv,
        "window_seconds": BEACON_WINDOW,
        "severity": "medium",
        "description": (f"{len(timestamps)} connection attempts to {dst} at a "
                        f"near-constant {mean_delta:.1f}s interval "
                        f"(CV={cv:.2f}, window {BEACON_WINDOW}s)"),
    }


def _detect_volume(packet_data: dict) -> dict | None:
    """
    PKT-1001: one source sustained a packet rate over the threshold for a
    whole window.

    THE RULE WAS REGISTERED AND HAD NO RAISER. `VOLUME_THRESHOLD` sat in this
    module with no reader and `PKT-1001 volume_sustained` was declared in
    core/detections.py and raised by nothing, which is the same shape as the
    ICMP rules before they were ported: the Detections page showed the rule as
    present because the register is the only source it reads.

    Counted per SOURCE address (which direction it travels in is the packet's
    business; the rule's text says "one source"), over a real sliding window,
    with the table capped like the beacon table.
    """
    src = packet_data.get("src_ip")
    # This host's own traffic is the operator working, and the host sensors
    # already attribute it per process.
    if not src or is_self_address(src):
        return None
    now = time.time()
    hits = _volume_data.get(src)
    if hits is None:
        _evict_oldest_lru(_volume_data, VOLUME_MAX_TRACKED - 1)
        hits = deque(maxlen=VOLUME_THRESHOLD * 2)
        _volume_data[src] = hits
    hits.append(now)
    cutoff = now - VOLUME_WINDOW
    while hits and hits[0] < cutoff:
        hits.popleft()

    if len(hits) < VOLUME_THRESHOLD:
        return None
    return {
        "type": "volume_sustained",
        "src_ip": src,
        "packet_count": len(hits),
        "window_seconds": VOLUME_WINDOW,
        "severity": "low",     # PKT-1001 declares {"low"}
        "description": (f"{src} sent {len(hits)} packets in {VOLUME_WINDOW}s, "
                        f"above the {VOLUME_THRESHOLD}-packet threshold. A "
                        f"measurement, not a classification; backups look the "
                        f"same."),
    }


def _evict_oldest_lru(table: dict, cap: int):
    """Drop oldest-first until a timestamp-deque table is back at its cap."""
    while len(table) > cap:
        oldest = min(table, key=lambda k: table[k][0] if table[k] else 0)
        table.pop(oldest, None)


def _detect_dangerous_ports(packet_data: dict) -> dict | None:
    """
    Detect connections to known dangerous ports.

    TWO THINGS THIS NOW REFUSES, both of which it used to say:

      * a destination that is not a host (this host's own address, loopback,
        a broadcast group) or not routable. The live row this fixes is
        `127.0.0.1 | Connection to dangerous port 4444 (outbound)` -- the app's
        own dashboard traffic, described as an outbound connection to a
        command-and-control port. PKT-1014's summary is "this host reached OUT
        to a dangerous port on a PUBLIC ADDRESS", so a private or loopback
        destination was never what the rule meant.
      * a port that nothing on this host is actually listening on. A TCP SYN to
        a closed port is a connection ATTEMPT, and its address is the local
        host's own; the rule's summary is about something being reached. The
        listener is read from /proc/net/tcp (no privilege) at flag time.
    """
    dst_port = packet_data.get("dst_port")
    if not dst_port or dst_port not in DANGEROUS_PORTS:
        return None
    # One UDP conversation is one event, not one per frame (SNF-11).
    flow = packet_data.get("udp_flow")
    if flow is not None and not flow.get("new"):
        return None

    dst = packet_data.get("dst_ip")
    direction = packet_data.get("direction")

    if direction == "inbound":
        # Something reached for us. The question "is anything listening" is
        # what separates a connection from an attempt, and the register's own
        # words for PKT-1013 are "something outside reached for a port on this
        # host that should not be exposed".
        listening = _is_listening(dst_port,
                                  packet_data.get("protocol") or "tcp")
        if not listening:
            _note_skip(f"dangerous_port: nothing is listening on {dst_port}")
            return None
        return {
            "type": "dangerous_port_connection",
            "dst_ip": dst,
            "dst_port": dst_port,
            "severity": "low",
            "description": (f"Inbound connection to dangerous port {dst_port}; "
                            f"a listener for it is open on this host"),
        }

    is_host, why_not = peer_is_a_host(dst)
    if not is_host:
        _note_skip(f"dangerous_port: {why_not}")
        return None
    try:
        import ipaddress as _ip
        if not _ip.ip_address(dst).is_global:
            _note_skip(f"dangerous_port: {dst} is not a public address, and "
                       f"PKT-1014 is about a public destination")
            return None
    except ValueError:
        _note_skip("dangerous_port: destination is not a parseable address")
        return None

    return {
        "type": "dangerous_port_connection",
        "dst_ip": dst,
        "dst_port": dst_port,
        "severity": "high",     # PKT-1014 declares {"high"}
        "description": (f"Outbound connection to dangerous port {dst_port} on "
                        f"the public address {dst}"),
    }


def _is_listening(port: int, protocol: str = "tcp") -> bool:
    """
    Is anything on this host listening on that port, over IPv4 or IPv6?

    Reads the kernel's own tables, no privilege needed. A TCP listener is
    state 0A; a UDP socket bound and not connected is state 07 with no remote
    port. Earlier this read /proc/net/tcp alone, so IPv6 and UDP listeners
    were never seen (SNF-21). A failed read counts as "no", which only ever
    costs a finding, and it is counted in the skip reasons.
    """
    udp = (protocol or "").lower() == "udp"
    tables = ("/proc/net/udp", "/proc/net/udp6") if udp else \
        ("/proc/net/tcp", "/proc/net/tcp6")
    for table in tables:
        try:
            with open(table, encoding="utf-8") as f:
                next(f, None)
                for line in f:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    try:
                        lport = int(parts[1].rsplit(":", 1)[1], 16)
                        rport = int(parts[2].rsplit(":", 1)[1], 16)
                    except (IndexError, ValueError):
                        continue
                    if lport != port:
                        continue
                    if udp and parts[3] == "07" and rport == 0:
                        return True
                    if not udp and parts[3] == "0A":
                        return True
        except OSError as e:
            logger.debug(f"could not read {table} ({e}); treating port "
                         f"{port} as having no listener there")
            _note_skip(f"dangerous_port: {table} could not be read")
    return False


def _detect_payload_signatures(packet_data: dict) -> dict | None:
    """
    Suspicious payload patterns in ONE frame's first bytes.

    KEPT, AND ITS LIMITS ARE THE POINT. This is a three-signature check over
    the first 256 bytes of a single frame's Raw layer, and it stays that way:
    the app's documented position is that payload matching is where the
    Windows tree's deeper engine lives and that this tree spends the network
    vantage on destinations rather than on content (see
    wiki/concepts/network-visibility-limits.md, and adapters.py's own
    docstring for why a hit here is counted and NOT raised as PKT-1010).

    WHAT IT CANNOT DO, stated so nobody has to infer it: a signature split
    across two TCP segments is never seen and an offset other than zero is
    never seen. IP fragments are reassembled before this runs (SNF-11).
    Callers must not read a miss as "nothing executable crossed the wire".
    """
    payload = packet_data.get("payload_hex")
    if not payload:
        return None

    signatures = {
        "4d5a": "MZ executable header",
        "7f454c46": "ELF executable header",
        "504b0304": "ZIP archive (could be malicious)",
    }

    payload_lower = payload.lower()
    for sig, desc in signatures.items():
        if payload_lower.startswith(sig):
            return {
                "type": "suspicious_payload",
                "signature": sig,
                "description": desc,
                "dst_ip": packet_data["dst_ip"],
                "severity": "low",
                "frame_only": True,
            }

    return None


def _packet_callback(pkt):
    """
    Scapy callback for each captured packet.

    This is the module's own callback and it stays a LOGGER: the adapter
    replaces it with one that writes (see adapters.LinuxPacketSniffer.start).
    Kept working, and kept honest, so a caller that runs this module bare
    still gets the same three detectors and the same skip counting.
    """
    try:
        packet_data = _analyze_packet(pkt)
        if not packet_data:
            return

        findings = []
        beacon = _detect_beaconing(packet_data)
        if beacon:
            findings.append(beacon)
        volume = _detect_volume(packet_data)
        if volume:
            findings.append(volume)
        port_find = _detect_dangerous_ports(packet_data)
        if port_find:
            findings.append(port_find)
        payload_find = _detect_payload_signatures(packet_data)
        if payload_find:
            findings.append(payload_find)

        for finding in findings:
            logger.info(f"Packet finding: {finding['type']} - "
                        f"{finding['description']}")

    except Exception as e:
        logger.debug(f"Packet analysis error: {e}")


def _operstate(name: str):
    """
    The kernel's own up/down word for an interface, or None if unreadable.

    None IS NOT FALSE. sysfs can refuse (a name that vanished between listing
    and reading, a container without /sys/class/net), and "I could not read
    this" must not come back as "this interface is down" -- that would drop a
    perfectly good uplink from the candidate list and report the machine as
    having no network. Rule two: a failed read says it failed.
    """
    try:
        with open(f"/sys/class/net/{name}/operstate", encoding="utf-8") as f:
            return f.read().strip().lower()
    except OSError:
        return None


def is_loopback_interface(name: str) -> bool:
    """
    True for the loopback device and its aliases.

    A CAPTURE ON lo IS NOT A NETWORK VANTAGE. The host's traffic to its own
    addresses never leaves the machine, so no address on it is ever routable,
    nothing on it can be geolocated, and a sniffer watching it records the
    host talking to itself while the page reports the sensor as running.
    That is the defect this function exists to keep out of the auto-detect:
    before it, `interfaces[0]` on this workstation was lo.
    """
    return name == "lo" or name.startswith("lo:")


# Interfaces that are real enough to open but are not an uplink. Ordered by
# prefix; matched with startswith. Kept here rather than folded into
# LINUX_INTERFACE_PREFIXES because that table is for DISPLAY (it names the
# type on the dashboard) and this one decides CAPTURE.
VIRTUAL_INTERFACE_PREFIXES = (
    "docker", "podman", "veth", "br-", "virbr", "vb-",
    "tun", "tap", "tailscale", "wg", "zt", "utun",
    "vmnet", "vboxnet", "dummy", "sit", "gre", "lxc", "cni",
)


def is_virtual_interface(name: str) -> bool:
    """
    True for bridges, tunnels, containers and other synthetic links.

    Not a reason to refuse -- on a machine whose only uplink is a VPN tunnel
    this is the only interface there is, and refusing it would report no
    network on a connected host. It is a reason to lose a tie-break against
    a real NIC, because docker0 is `down` on this workstation and a bridge
    carries the machine's own traffic in a way that flatters a packet count.
    """
    return name.startswith(VIRTUAL_INTERFACE_PREFIXES)


def _has_usable_ip(ip) -> bool:
    """
    A real, routable-looking address on the interface.

    Deliberately not a full is_routable check (core.geoip owns that): this
    only has to separate "an interface carrying an address that could reach
    the internet" from an empty one or an APIPA self-assignment, which is
    what a NIC with no DHCP lease looks like and which would capture nothing.
    """
    if not ip:
        return False
    return not (ip.startswith("127.") or ip.startswith("169.254.")
                or ip.startswith("::1") or ip.startswith("fe80:"))


def _default_route_interface():
    """
    The interface the kernel sends unrouted traffic through, or None.

    /proc/net/route is the kernel's own table: no subprocess, no privilege.
    The flags field has 0x0002 (RTF_GATEWAY) set on the default row, and the
    destination column reads 00000000 for it. Field 0 is the interface name,
    which is the part wanted here -- adapters._default_gateway reads the same
    file for the gateway's ADDRESS, and this is the same row.
    """
    try:
        with open("/proc/net/route", encoding="utf-8") as f:
            next(f, None)                          # header
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                if parts[1] != "00000000":
                    continue
                if not (int(parts[3], 16) & 0x0002):
                    continue
                return parts[0]
    except (OSError, ValueError) as e:
        logger.debug(f"Could not read the default route interface: {e}")
    return None


def select_capture_interface(configured=None, interfaces=None,
                             default_iface=None):
    """
    Which interface to capture on: (name, reason) or (None, reason).

    ORDER OF AUTHORITY, and each step is a decision rather than a fallback:

      1. `configured` -- what the operator put in config.json. Honoured even
         when it names lo, because an instruction that gets quietly replaced
         is worse than an odd one. A name that does not exist on this machine
         captures NOTHING and says so; it does not silently capture some
         other interface, which would put a run's packets under a heading
         nobody chose.
      2. The default-route interface -- the kernel's answer to "which link
         carries this machine's traffic". This is the step that would have
         chosen wlp1s0 on this workstation.
      3. The first real NIC that is up, not loopback and not virtual.
      4. The first thing that is up and not loopback, virtual interfaces
         included, because a VPN-only machine has a usable uplink.
      5. Nothing, with the reason said out loud.

    Returns a reason string in every case, including success: the caller logs
    it and the dashboard shows it, so "which interface, and why that one" is
    never left to be inferred from a name.
    """
    if interfaces is None:
        interfaces = get_available_interfaces()
    if default_iface is None:
        default_iface = _default_route_interface()

    def named(name):
        for i in interfaces:
            if i.get("name") == name:
                return i
        return None

    def is_up(i):
        # None means unreadable, which is NOT down. See _operstate.
        return i.get("up") is not False

    def is_lo(i):
        return i.get("loopback", is_loopback_interface(i.get("name") or ""))

    def is_virt(i):
        return i.get("virtual", is_virtual_interface(i.get("name") or ""))

    # 1. the operator's choice
    if configured:
        hit = named(configured)
        if not hit:
            return None, (
                f"config.json names interface {configured!r} and this "
                f"machine has no such interface "
                f"(present: {', '.join(i['name'] for i in interfaces) or 'none'}). "
                f"No capture was started. A different interface was NOT "
                f"chosen in its place.")
        if is_lo(hit):
            return configured, (
                f"{configured} was named in config.json and it is the "
                f"LOOPBACK device. Capturing here records this host talking "
                f"to itself and NOTHING else: no address on lo is routable, "
                f"so the threat map cannot place a single endpoint. Capturing "
                f"because the operator asked, and saying what it means.")
        return configured, f"{configured} named in config.json"

    # 2. the kernel's answer
    if default_iface:
        hit = named(default_iface)
        if hit and not is_lo(hit) and is_up(hit):
            return default_iface, (
                f"{default_iface} carries the default route "
                f"(/proc/net/route), so this is the link this machine's "
                f"traffic actually leaves through")

    # 3. a real NIC
    real = [i for i in interfaces
            if not is_lo(i) and is_up(i) and not is_virt(i)]
    if real:
        # A NIC with no lease (empty address, or APIPA) captures nothing
        # useful; one with a real address sorts first.
        real.sort(key=lambda i: not _has_usable_ip(i.get("ip")))
        pick = real[0]
        return pick["name"], (
            f"{pick['name']} is an up, non-loopback interface carrying "
            f"{pick.get('ip') or 'no address'}")

    # 4. a tunnel or bridge, if that is all there is
    any_up = [i for i in interfaces if not is_lo(i) and is_up(i)]
    if any_up:
        pick = any_up[0]
        return pick["name"], (
            f"{pick['name']} is the only usable interface this machine has. "
            f"It is a virtual link ({pick.get('type') or 'virtual'}), so it "
            f"carries tunnel or bridged traffic rather than a physical "
            f"uplink. Capture is on it because the alternative is none.")

    # 5. nothing
    present = ", ".join(i["name"] for i in interfaces) or "none"
    return None, (
        f"no capturable interface: every interface this machine has is "
        f"loopback, down, or absent (present: {present}). Loopback is not a "
        f"network vantage, so capturing there would record this host talking "
        f"to itself and would place nothing on the threat map. NO CAPTURE "
        f"WAS STARTED.")


def get_available_interfaces():
    """
    Get list of available network interfaces.

    Each entry carries the three things the chooser needs beyond the name:
    up/down, whether it is loopback, and whether it is virtual. They are
    read here, once, so select_capture_interface and the dashboard agree
    about what this machine has instead of each deciding for itself.
    """
    if not SCAPY_AVAILABLE:
        return []
    
    try:
        interfaces = []
        for iface in get_if_list():
            try:
                mac = get_if_hwaddr(iface)
                ip = get_if_addr(iface)
                iface_type = "unknown"
                for prefix, type_name in LINUX_INTERFACE_PREFIXES.items():
                    if iface.startswith(prefix):
                        iface_type = type_name
                        break
                
                interfaces.append({
                    "name": iface,
                    "mac": mac,
                    "ip": ip,
                    "type": iface_type,
                    "up": _operstate(iface) != "down",
                    "loopback": is_loopback_interface(iface),
                    "virtual": is_virtual_interface(iface),
                })
            except Exception:
                interfaces.append({
                    "name": iface, "mac": None, "ip": None,
                    "type": "unknown",
                    # Unreadable, not down. See _operstate.
                    "up": None,
                    "loopback": is_loopback_interface(iface),
                    "virtual": is_virtual_interface(iface),
                })
        
        return interfaces
    except Exception as e:
        logger.error(f"Failed to list interfaces: {e}")
        return []


def check_capture_capability() -> tuple[bool, str]:
    """
    Check if packet capture is possible.

    Returns (can_capture, reason)

    THREE DEFECTS IN ONE FUNCTION, FIXED 2026-09-23 (SNF-5). All three were
    copied into core/privilege_linux.check_packet_capture_capability too.

      (a) THE PROBE NOW DECIDES AND NOTHING ELSE IS ASKED AFTER IT. The socket
          open is the real permission test on Linux: it either works or the
          kernel refuses. The old order was probe, then -- only if the probe
          failed -- a group-membership check, which is the wrong way round:
          a successful probe RETURNED before the group branch, so the branch
          was dead code exactly when it would be right, and it was the answer
          whenever the probe failed for some other reason.

      (b) GROUP MEMBERSHIP IS NOT EVIDENCE, so it is no longer a green. A
          group name proves the account was put in a group; it does not prove
          anything was INSTALLED for that group. Measured on this workstation:
          /usr/bin/dumpcap is 0755 root:root with no setuid bit and no file
          capability, there is no `wireshark` group, and `netdev` exists with
          an empty member list -- a group-only check would have called this
          host capture-capable on a machine where nothing can capture.

      (c) THE ACCOUNT IS READ FROM THE PROCESS, not the environment. The old
          code asked os.environ["USER"], so a service started by systemd (no
          USER in its environment) reported a real member as having no access.
          os.getuid() is the fact; the environment is a guess.
    """
    if not SCAPY_AVAILABLE:
        return False, "Scapy not installed"

    # (a) the real test, first and last
    probe_error = None
    try:
        test_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                    socket.htons(0x0003))
        test_socket.close()
        if os.geteuid() == 0:
            return True, "Running as root"
        return True, "Has CAP_NET_RAW capability"
    except PermissionError as e:
        probe_error = f"EPERM ({e})"
    except OSError as e:
        # NOT EPERM: no AF_PACKET family, no such device, a seccomp filter.
        # This is the branch that used to fall down into the group check and
        # come back green. It must not: the kernel did not refuse for lack of
        # privilege, it refused because it will not do this at all.
        probe_error = f"{type(e).__name__} ({e})"

    # (b) groups are reported as a HINT, never as a yes
    groups = _capture_groups()
    hint = (f" This account is in {', '.join(groups)}, which only helps if "
            f"something is installed for that group, on this host that is "
            f"not the case unless dumpcap or a helper carries the privilege."
            if groups else "")

    return False, (
        f"No raw socket access ({probe_error}). Capture needs root or "
        f"CAP_NET_RAW: run with sudo, or grant the capability to the "
        f"interpreter with `sudo setcap cap_net_raw+ep $(readlink -f $(which "
        f"python3))`.{hint}")


def _capture_groups() -> list:
    """The capture-related groups THIS PROCESS's account is a member of."""
    groups = []
    try:
        import grp
        # (c) the account, not the environment: getuid(), not $USER.
        user = pwd.getpwuid(os.getuid()).pw_name
        primary = os.getgid()
        for g in os.getgroups() + [primary]:
            try:
                if grp.getgrgid(g).gr_name in ("wireshark", "pcap", "netdev"):
                    groups.append(grp.getgrgid(g).gr_name)
            except KeyError:
                continue
        for name in ("wireshark", "pcap", "netdev"):
            try:
                if user in grp.getgrnam(name).gr_mem and name not in groups:
                    groups.append(name)
            except KeyError:
                continue
    except Exception as e:
        logger.debug(f"group lookup failed: {e}")
    return groups


# WHAT CAPTURE IS DOING HERE, AND WHY IT CAN NOW SAY "IT STOPPED".
# 2026-09-23, SNF-6 and SNF-15.
#
# Module state for the same reason _reader is in core/geoip: the dashboard
# asks "what is this sensor doing" from a different thread than the one that
# started it.
#
# THE DEFECT THIS FIXES, measured: with a sniff() that raises, the thread
# body logged "Packet capture failed" once and every field the app could read
# still said the sensor was reading wlp1s0 -- capture_interface() returned the
# name, get_status()["can_capture"] was True, and nothing anywhere said the
# thread was gone. A dead capture is the strongest possible "could not look",
# so it must not read as a healthy interface.
#
# So the module now keeps its OWN liveness: the thread clears the flag in a
# finally, and every reader sees None plus the reason once it is dead.
_capture_interface = None
_capture_interface_reason = "capture not started"
_capture_alive = False
_capture_started_at = 0.0
_capture_stopped_at = 0.0
_capture_failure = None

# What the last start was asked for, published so the status block can report
# it rather than the operator having to infer it from the config file.
_capture_promisc = None
_capture_filter = None
_capture_rcvbuf = None


# THE KERNEL'S OWN COUNTERS. SNF-4, 2026-09-23.
#
# The kernel has counted every frame it received, dropped and errored on for
# every interface, from boot, at no privilege: /proc/net/dev. This app read it
# NOWHERE (grep for /proc/net/dev, snmp6, PACKET_STATISTICS: no hits), so "the
# network was quiet" and "the kernel dropped 40% of the frames" were the same
# sentence on the dashboard, and `packets_this_run` had nothing to compare
# against.
#
# `capture_counters()` reports the delta since capture started; the drop and
# error deltas are the two numbers that make PKT-1003 ("the capture buffer hit
# its ceiling and packets were counted but not stored, so this window is
# incomplete and cannot be called quiet") raisable.
_counters_baseline = {}
_counters_baseline_at = 0.0


def _read_interface_counters(iface: str) -> dict:
    """
    /proc/net/dev's row for one interface: bytes, packets, drop, err.

    The file's own header names the columns; this reads by name rather than by
    fixed offset, because a kernel that adds a column would otherwise silently
    shift every number read here.
    """
    try:
        with open("/proc/net/dev", encoding="utf-8") as f:
            lines = f.readlines()[2:]        # two header lines
        for line in lines:
            name, _, rest = line.partition(":")
            if name.strip() != iface:
                continue
            nums = rest.split()
            if len(nums) < 16:
                return {}
            rx = nums[:8]        # rcv: bytes packets errs drop fifo frame compressed multicast
            tx = nums[8:16]      # txm: bytes packets errs drop fifo colls carrier compressed
            return {
                "rx_bytes": int(rx[0]), "rx_packets": int(rx[1]),
                "rx_errors": int(rx[2]), "rx_dropped": int(rx[3]),
                "tx_bytes": int(tx[0]), "tx_packets": int(tx[1]),
                "tx_errors": int(tx[2]), "tx_dropped": int(tx[3]),
            }
    except (OSError, ValueError, IndexError) as e:
        logger.debug(f"could not read /proc/net/dev for {iface}: {e}")
    return {}


def _reset_capture_counters():
    """Take the baseline the delta is measured from."""
    global _counters_baseline, _counters_baseline_at
    with _socket_stats_lock:
        _socket_stats.update(packets=0, drops=0, readable=False)
    if not _capture_interface:
        return
    _counters_baseline = _read_interface_counters(_capture_interface)
    _counters_baseline_at = time.time()


def capture_counters() -> dict:
    """
    Frames the interface carried, and frames the kernel dropped, since start.

    Every number is (delta, baseline, current) so a reader can see both the
    change and the absolute, and a failed read returns `readable: False` with
    the reason rather than zeros -- a zero here has to mean zero.
    """
    if not _capture_interface:
        return {"iface": None, "readable": False,
                "note": "no capture has been started, so there is no baseline"}
    if not _counters_baseline:
        return {"iface": _capture_interface, "readable": False,
                "note": ("the baseline read of /proc/net/dev failed at start; "
                         "frame counts for this run cannot be compared")}
    now = _read_interface_counters(_capture_interface)
    if not now:
        return {"iface": _capture_interface, "readable": False,
                "note": f"/proc/net/dev no longer has a row for "
                        f"{_capture_interface}"}
    delta = {k: now[k] - _counters_baseline.get(k, 0) for k in now}
    return {
        "iface": _capture_interface,
        "readable": True,
        "since": _counters_baseline_at,
        "delta": delta,
        "current": now,
        # The capture socket's own receive and drop counts since start.
        "socket": _read_socket_stats(),
    }


def capture_interface() -> str | None:
    """
    The interface capture is reading, or None if none is being read.

    None HAS THREE MEANINGS AND THEY ARE TOLD APART by
    `capture_interface_reason()` and `capture_state()`: never started, refused
    before starting, or started and the thread has since stopped. Before
    2026-09-23 the third case returned the interface name, which is the
    strongest wrong answer this function could give.
    """
    if not _capture_alive:
        return None
    return _capture_interface


def capture_interface_reason() -> str:
    """Why that interface, or why none. Always a sentence, never blank."""
    if _capture_interface and not _capture_alive:
        return (f"capture STARTED on {_capture_interface} and the thread is no "
                f"longer running"
                + (f": {_capture_failure}" if _capture_failure else
                   " (it ended on its own, with no exception recorded)")
                + ". The interface below is the one it was started on, NOT "
                  "one being read.")
    return _capture_interface_reason


def capture_state() -> dict:
    """
    This module's own answer to "is the sensor reading right now".

    The adapter owns the app-facing `running` key; this is the half that knows
    whether the THREAD is alive, which the adapter could not ask before.
    """
    return {
        "interface": _capture_interface if _capture_alive else None,
        "started_on": _capture_interface,
        "alive": _capture_alive,
        "started_at": _capture_started_at or None,
        "stopped_at": _capture_stopped_at or None,
        "failure": _capture_failure,
        "reason": capture_interface_reason(),
    }


def start_sniffer(interface: str = None, filter_str: str = None,
                  timeout: int = None, promisc: bool = False,
                  rcvbuf: int = None):
    """
    Start packet capture in a background thread.

    Args:
        interface: Network interface to capture on. None = CHOOSE ONE, by the
            order of authority in select_capture_interface -- NOT "all
            interfaces". See the note below.
        filter_str: BPF filter string (e.g., "not port 22"). Passed through to
            the kernel when given, so frames it would drop are never copied to
            userspace at all. The adapter reads this from config; the default
            is None because a narrow filter would starve the ARP, DHCP and TLS
            parsers, and which detections matter is the operator's call.
        timeout: Capture timeout in seconds (None = indefinite)
        promisc: put the NIC in promiscuous mode. DEFAULT IS False, and that is
            a change: the module never decided, so scapy's own default (True)
            applied and every run silently promiscuous-mode'd the interface.
            Measured on this host, conf.sniff_promisc is True. A security
            monitor that changes the visibility of the NIC it watches should
            be told to, not inherit it. On a switched network promisc mostly
            buys other stations' flooded frames; it is set in the config, not
            here, and the status block reports which way it went.
        rcvbuf: the AF_PACKET socket's receive buffer, in bytes. When None the
            kernel default applies; scapy asks for 0, which the kernel reads as
            "the minimum" -- measured 2304 bytes on this host against a default
            of 212,992, for the receive queue of the entire capture path.

    THE INTERFACE WAS CHOSEN BY ACCIDENT. Fixed 2026-09-22.

    This used to prefer a name starting with "eth" or "en", and otherwise
    take interfaces[0]. On this workstation the NIC is `wlp1s0`, so the
    first rule matched nothing and the second handed back lo, because
    scapy's get_if_list() returns it first. Every one of the 31 capture
    starts in the logs chose lo, and the resulting 153,816 packet rows were
    ALL scope 'internal' with not one routable address among them. The
    threat map had nothing to place, and the reason on record was that
    GeoIP was not loaded -- which was wrong; it was ready.

    The choice now goes through select_capture_interface, which refuses
    loopback outright and reports why it chose what it chose. A machine with
    no capturable interface captures NOTHING and says so, which is the
    honest outcome: a sniffer reading lo is not a quiet network, it is a
    sensor pointed at the wrong place.
    """
    global _capture_interface, _capture_interface_reason
    global _capture_alive, _capture_started_at, _capture_stopped_at
    global _capture_failure, _capture_promisc, _capture_filter, _capture_rcvbuf
    global _capture_thread, _capture_stop_event

    if not SCAPY_AVAILABLE:
        _capture_interface, _capture_interface_reason = (
            None, "scapy not available")
        _capture_alive, _capture_failure = False, "scapy not available"
        logger.warning("Cannot start sniffer: scapy not available")
        return False
    
    can_capture, reason = check_capture_capability()
    if not can_capture:
        _capture_interface, _capture_interface_reason = None, reason
        _capture_alive, _capture_failure = False, reason
        logger.warning(f"Cannot capture packets: {reason}")
        return False

    chosen, why = select_capture_interface(configured=interface)
    _capture_interface, _capture_interface_reason = chosen, why

    if not chosen:
        # Refused, and the refusal is the result. Starting a thread that
        # captures nothing and calls itself up is the failure mode this
        # whole file is written against.
        logger.warning(f"Packet capture NOT started: {why}")
        _capture_alive, _capture_failure = False, why
        return False

    # The address snapshot the detectors use to recognise this host's own
    # traffic. Taken here because this is the moment the machine's network
    # matters: a laptop that changed WiFi between runs has a different set.
    addrs = refresh_local_addresses()
    logger.info(f"Starting packet capture on {chosen}: {why} "
                f"({len(addrs)} local address(es) known; promiscuous="
                f"{bool(promisc)}; filter={filter_str or 'none'})")

    _capture_started_at = time.time()
    _capture_stopped_at = 0.0
    _capture_failure = None
    _capture_alive = True
    _capture_promisc = bool(promisc)
    _capture_filter = filter_str or None
    _capture_rcvbuf = rcvbuf

    # The kernel-side counters, read once so a later delta has a baseline.
    # Without this, "the network was quiet" and "the kernel dropped frames" are
    # the same sentence on the dashboard (SNF-4).
    _reset_capture_counters()

    stop_event = threading.Event()
    _capture_stop_event = stop_event
    callback = _packet_callback
    global _defrag
    _defrag = Defragmenter()
    defrag = _defrag

    def deliver(pkt):
        # Frames already queued when a stop is asked for are not handled.
        if not stop_event.is_set():
            # Fragments wait here until their datagram is whole (SNF-11).
            for whole in defrag.push(pkt):
                callback(whole)

    def capture_thread():
        global _capture_alive, _capture_stopped_at, _capture_failure
        global _capture_socket, _capture_socket_note
        sock = None
        try:
            kwargs = {
                "prn": deliver,
                "timeout": timeout,
                "store": False,
                "stop_filter": lambda _pkt: stop_event.is_set(),
            }
            try:
                sock = _open_capture_socket(chosen, rcvbuf, promisc, filter_str)
                _capture_socket_note = "own AF_PACKET socket"
            except Exception as e:                            # noqa: BLE001
                _capture_socket_note = (f"own socket could not be opened "
                                        f"({type(e).__name__}: {e}); scapy's "
                                        f"default socket is used, with no "
                                        f"receive buffer and no drop counts")
                logger.warning(f"packet capture: {_capture_socket_note}")
            if sock is not None:
                # Never with iface: scapy then opens a second socket on the
                # same interface and every frame arrives twice (SNF-19).
                kwargs["opened_socket"] = sock
                _capture_socket = sock
            else:
                kwargs.update(iface=chosen, promisc=bool(promisc))
                # An empty filter string is not legal in scapy, None is.
                if filter_str:
                    kwargs["filter"] = filter_str
            sniff(**kwargs)
        except Exception as e:
            _capture_failure = f"{type(e).__name__}: {e}"
            logger.error(f"Packet capture failed on {chosen}: {_capture_failure}")
        finally:
            # A capture thread that exits for any reason clears its own
            # liveness, so capture_interface() stops naming the interface.
            if sock is not None:
                _read_socket_stats(sock)
                if _capture_socket is sock:
                    _capture_socket = None
                try:
                    sock.close()
                except Exception:                             # noqa: BLE001
                    pass
            if _capture_stop_event is stop_event:
                _capture_alive = False
                _capture_stopped_at = time.time()

    thread = threading.Thread(target=capture_thread, daemon=True,
                              name="packet-capture")
    _capture_thread = thread
    thread.start()
    return True


_capture_thread = None
_capture_stop_event = None
_capture_socket = None
_capture_socket_note = "capture not started"
_defrag = None                    # the running capture's reassembler (SNF-11)

# Frames the capture socket itself received and dropped, from the kernel's
# PACKET_STATISTICS. Reading the counters resets them, so they are summed here.
_SOL_PACKET = getattr(socket, "SOL_PACKET", 263)
_PACKET_STATISTICS = 6
_socket_stats = {"packets": 0, "drops": 0, "readable": False}
_socket_stats_lock = threading.Lock()


def _read_socket_stats(sock=None) -> dict:
    """
    Add the socket's PACKET_STATISTICS to the running totals. These are the
    frames lost because this sensor's own queue overflowed, which
    /proc/net/dev does not count (SNF-20).
    """
    sock = sock if sock is not None else _capture_socket
    with _socket_stats_lock:
        if sock is not None:
            try:
                raw = sock.ins.getsockopt(_SOL_PACKET, _PACKET_STATISTICS, 8)
                packets, drops = struct.unpack("II", raw)
                _socket_stats["packets"] += packets
                _socket_stats["drops"] += drops
                _socket_stats["readable"] = True
            except (OSError, AttributeError, struct.error) as e:
                logger.debug(f"PACKET_STATISTICS read failed: {e}")
        return dict(_socket_stats)


def _open_capture_socket(iface, rcvbuf, promisc, filter_str=None):
    """
    The capture's own AF_PACKET socket: the BPF filter attached, promiscuous
    mode as configured, and the receive buffer sized when asked.

    scapy's socket asks for SO_RCVBUF 0, which Linux reads as its minimum
    (2304 bytes measured against a default of 212,992). The buffer is clamped
    to rmem_max because setsockopt clamps silently. Raises on failure so the
    caller can fall back to scapy's own socket.
    """
    from scapy.arch.linux import L2ListenSocket
    sock = L2ListenSocket(iface=iface, promisc=bool(promisc), type=0x0003,
                          filter=filter_str or None)
    if not rcvbuf:
        return sock
    try:
        rmem_max = int(open("/proc/sys/net/core/rmem_max").read().strip())
    except (OSError, ValueError):
        rmem_max = 212992
    want = min(int(rcvbuf), rmem_max)
    try:
        sock.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, want)
        got = sock.ins.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        logger.info(f"capture socket receive buffer set to {want} bytes "
                    f"(kernel granted {got}; rmem_max {rmem_max})")
    except OSError as e:
        logger.warning(f"could not size the capture socket buffer ({e})")
    return sock


def stop_sniffer():
    """
    Stop packet capture. The capture loop ends at its next frame and nothing
    after the stop is handed to the callback, so no rows are written after it.
    """
    global _capture_alive, _capture_stopped_at
    if _capture_stop_event is not None:
        _capture_stop_event.set()
    if _capture_alive:
        _capture_alive = False
        _capture_stopped_at = time.time()
    logger.info(f"Packet capture stop requested; {capture_interface_reason()}")


def get_status() -> dict:
    """
    Get current sniffer status.

    `interface` and `interface_reason` are here since 2026-09-22: the module
    knew which device it opened only as a log line, so a capture on lo looked
    identical to a capture on the NIC from anywhere in the app.

    2026-09-23 adds the parts a reader could not get before: `running` (the
    module's own thread liveness, SNF-6/SNF-15), `attribution` (the socket
    snapshot's age and size, SNF-3/SNF-13), `detections` (the three tables'
    sizes, ceilings and skip reasons, SNF-1/SNF-2/SNF-17), `kernel` (the
    interface counters and drop deltas, SNF-4) and `capture_settings` (promisc
    and the filter, SNF-7/SNF-8).
    """
    can_capture, reason = check_capture_capability()
    interfaces = get_available_interfaces()

    # What the chooser WOULD pick right now, so the dashboard can show the
    # interface even before capture starts and can show None plus a sentence
    # on a machine with nothing capturable.
    would_pick, would_reason = select_capture_interface(interfaces=interfaces)

    started_on = capture_interface()
    return {
        "available": SCAPY_AVAILABLE,
        "can_capture": can_capture,
        "reason": reason,
        "interfaces": interfaces,
        "would_capture_on": would_pick,
        "would_capture_reason": would_reason,
        "interface": started_on or would_pick,
        "interface_reason": (capture_interface_reason()
                             if started_on else
                             ("capture is not running; " + would_reason)),
        # the new half
        "running": _capture_alive,
        "capture": capture_state(),
        "capture_settings": {
            "promiscuous": _capture_promisc,
            "filter": _capture_filter,
            "rcvbuf": _capture_rcvbuf,
            "socket": _capture_socket_note,
        },
        "ip_reassembly": dict(_defrag.stats) if _defrag else None,
        "attribution": attribution_state(),
        "attribution_ebpf": ebpf_attribution_state(),
        "detections": detection_state(),
        "kernel": capture_counters(),
    }


def monitor_once(count: int = 100, interface: str = None) -> dict:
    """
    Capture a limited number of packets for immediate analysis.

    TWO THINGS THIS USED TO DO WRONG. Fixed 2026-09-23 (SNF-16).

      * THE EARLY STOP DID NOT STOP THE CAPTURE. The callback raised
        StopIteration to break the loop, and scapy 2.7 calls `prn(p)` inside
        no try/except -- measured on the offline path, which runs the same
        AsyncSniffer._run loop: the exception is swallowed and the engine keeps
        delivering frames until `count` or the 30-second timeout. So the
        `except StopIteration` here could never fire and the only real bound
        was the timeout. `stop_filter` is the mechanism scapy provides for
        this, and it is what this uses now.

      * `iface=None` MEANS EVERY INTERFACE INCLUDING LOOPBACK. That is the
        exact thing select_capture_interface was written to refuse, and this
        one-shot helper bypassed it -- so the helper and the background sensor
        disagreed about what a capture is, and the module's own history
        (153,816 loopback rows, all scope 'internal') is the same mistake one
        layer up. The interface is now chosen the same way the long-running
        capture chooses it.

    Returns dict with packet summary.
    """
    if not SCAPY_AVAILABLE:
        return {"error": "Scapy not available", "searched": False}
    
    can_capture, reason = check_capture_capability()
    if not can_capture:
        return {"error": reason, "searched": False}

    chosen, why = select_capture_interface(configured=interface)
    if not chosen:
        return {"error": f"no capturable interface: {why}", "searched": False}

    packets = []
    stopped = {"how": None}

    defrag = Defragmenter()

    def capture_callback(pkt):
        for whole in defrag.push(pkt):
            data = _analyze_packet(whole)
            if data:
                packets.append(data)

    def _reached_count(pkt) -> bool:
        if len(packets) >= count:
            stopped["how"] = "reached the requested count"
            return True
        return False

    try:
        sniff(iface=chosen, prn=capture_callback, count=count, store=False,
              timeout=30, stop_filter=_reached_count)
    except Exception as e:
        logger.error(f"Capture failed on {chosen}: {e}")
        return {"error": str(e), "searched": False, "interface": chosen}

    if stopped["how"] is None:
        stopped["how"] = ("the 30-second timeout, without reaching the "
                          "requested count")

    # Summarize
    protocols = {}
    destinations = {}
    for pkt in packets:
        protocols[pkt["protocol"]] = protocols.get(pkt["protocol"], 0) + 1
        destinations[pkt["dst_ip"]] = destinations.get(pkt["dst_ip"], 0) + 1
    
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "packet_count": len(packets),
        # WHY IT STOPPED is part of the answer: "100 packets" and "40 packets
        # because the timeout ran out" are the same shape otherwise, and a
        # short count is exactly the fact a reader must not have to infer.
        "requested": count,
        "stopped_because": stopped["how"],
        "complete": len(packets) >= count,
        "interface": chosen,
        "interface_reason": why,
        "protocols": protocols,
        "top_destinations": dict(sorted(destinations.items(),
                                        key=lambda x: -x[1])[:10]),
        "searched": True,
    }

