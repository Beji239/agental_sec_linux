# tools/network_scanner.py
# AgentalSec V2, ping sweep + neighbour cache network scanner.
# No raw packets, no admin needed.
#
# THE ONE SENTENCE THIS MODULE IS BUILT AROUND, AND IT IS WHY THE 2026-09-24
# AUDIT ROUND REWROTE ITS TWO ENTRY POINTS:
#
#   A NEIGHBOUR CACHE ENTRY IS MEMORY; AN ICMP REPLY IS EVIDENCE.
#
# Before this round `scan()` reported an address as a DEVICE when its ICMP
# sweep got no answer and the ARP cache still held an entry for it, with a
# `via` field that did not exist and nothing anywhere saying the two are
# different claims. Measured on this host before the fix: the ARP cache held
# 7 addresses, ICMP answered for 2, and the device list showed those 2 — the
# other 5, among them two devices the app had swept every 15 minutes for a
# week, appeared nowhere. The presence sweep DID use the union of the two, so
# the same host answered two different questions in two different places, one
# of them silently smaller.
#
# So the union is right and it is now the same union in both entry points, it
# carries WHY each address is on the list, and the sweep that could not run is
# a fact in the payload rather than a silent subtraction.
#
# AND THE SECOND SENTENCE, because it is what makes the first one safe:
#
#   AN ARP ENTRY IS ONLY REACHABILITY WHEN SOMETHING ACTUALLY TRIED TO REACH.
#
# An unresolved neighbour entry expires in seconds. A RESOLVED one lives in
# the kernel's table for minutes while the device is gone, and the app's own
# sweep traffic is what keeps it warm. So a sweep that could not run at all —
# `ping` missing, `ping` refusing, the binary present but not permitted — would
# otherwise report the whole LAN as present on the strength of the cache the
# previous sweep filled. Measured before this round: with a PATH that has no
# ping, a sweep reported 254 targets, 7 responders, outcome "ok", and wrote
# that as a normal sweep. The prober's own answer is read now, and nothing it
# did not probe is counted as reachable.

import logging
import os
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

from core import memory_engine as me
from core import finding_policy as fp

# OUI VENDOR MAP
#
# THIS IS THE FALLBACK NOW, NOT THE ANSWER. The app ships the IEEE registry
# (data/oui.csv, mam.csv, mas.csv, 54,000 prefixes on this host) behind
# core/oui.py, and that is what this module asks first. The map below is kept
# for the one case the registry cannot cover: a fresh install whose data
# folder has not been fetched yet, where it still answers what it always did.
#
# Measured before this round, the hardcoded answer for a live device here was
# "Unknown" while the registry the app already ships resolves the same address
# to its registrant, and 38 of the 39 entries below disagree with the registry
# entry for the same prefix (mostly in punctuation, but not all: see the
# round's write-up in bugfinder.md for the four that are a different company
# rather than a different spelling).
OUI_MAP = {
    "00:50:56": "VMware",          "00:0c:29": "VMware",
    "00:1a:11": "Google",          "94:eb:2c": "Google",
    "b8:27:eb": "Raspberry Pi",    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "00:17:88": "Philips Hue",     "ec:b5:fa": "Philips Hue",
    "18:b4:30": "Nest",            "64:16:66": "Nest",
    "fc:65:de": "Roku",            "b0:a7:37": "Roku",
    "44:27:45": "LG Electronics",  "a8:23:fe": "LG Electronics",
    "b4:e6:2d": "Apple",           "f0:18:98": "Apple",
    "3c:22:fb": "Apple",           "00:17:f2": "Apple",
    "18:65:90": "Apple",
    "00:50:f2": "Microsoft",       "28:18:78": "Microsoft",
    "70:85:c2": "Amazon",          "fc:a1:83": "Amazon",
    "74:c2:46": "Amazon",          "f0:81:73": "Amazon",
    "cc:9e:a2": "Belkin",
    "00:11:32": "Synology",
    "00:e0:4c": "Realtek",
    "00:23:69": "Cisco",           "00:1b:54": "Cisco",
    "00:50:c2": "ASUS",            "04:d4:c4": "ASUS",
    "24:4b:fe": "Ubiquiti",        "44:d9:e7": "Ubiquiti",
    "68:72:51": "Eero",
    "00:26:b9": "Dell",
    "d4:be:d9": "Intel",           "8c:8d:28": "Intel",
}

# Milliseconds, and ONLY the Windows command takes milliseconds. The Linux
# command wants seconds and converts. The name is kept because the Windows
# twin's flag is `-w <ms>` and the two are deliberately not normalised: they
# disagree about what the same letter means, which is how this module first
# failed on Linux. See the ping/arp block below.
PING_TIMEOUT    = 200
PING_WORKERS    = 100

# PTR lookups get their own, smaller pool. They block on a resolver that is
# usually local and always slower than a ping, and 254 simultaneous lookups
# against a home router's DNS is a small flood rather than a measurement.
LOOKUP_WORKERS  = 32

# Where the sweep looks. DEFAULT_SWEEP_INTERVAL_MINUTES is the last resort
# behind two config keys; see sweep_interval_seconds().
DEFAULT_SWEEP_INTERVAL_MINUTES = 15

# The widest range a sweep will be cut down to, and the reason it is /24 rather
# than "whatever the interface says". Measured: a neighbour table on this
# class of host holds tens of addresses, so 254 probes answer the question. On
# a /16 that is 65,534 addresses and hours of wall clock for the same table.
MAX_SWEEP_PREFIX = 24

_TRUE = ("1", "true", "yes", "on")

# A scan's own PTR lookups are ON by default, because a device's own name is
# the cheapest identifying fact on a LAN and memory_engine stamps it onto
# every device row. They are the SLOWEST thing in the scan by two orders of
# magnitude, though, and on a network whose resolver refuses to answer they
# are the difference between a three second scan and a forty minute one
# (measured here: 0.112 s per unresolvable address, glibc's own ceiling 10 s).
# The switch is an environment variable rather than a config key so that it
# does not become a third name for something, and status() publishes which
# way it is set.
RESOLVE_HOSTNAMES = os.environ.get(
    "AGENTALSEC_RESOLVE_HOSTNAMES", "1").strip().lower() not in ("0", "false", "no", "off")


def _oui_lookup(mac: str) -> str:
    """
    Who made this hardware address, or "Unknown".

    The registry first. core/oui.py has four different ways to not have a
    vendor (resolved / randomized / unknown_prefix / no_data) and this
    function has one return type, so the three not-resolved ones collapse —
    but only after the registry has been ASKED. `no_data` is the single case
    the local map is allowed to answer, because a map is a better nothing than
    a blank on an install that has never fetched the registry.

    A randomized address gets "Unknown" and that is correct rather than a
    gap: there is no vendor to find. The row carries identity_class for it.
    """
    if not mac:
        return "Unknown"
    try:
        from core import oui
        found = oui.lookup(mac)
        if found.get("status") == "resolved" and found.get("vendor"):
            return str(found["vendor"]).strip()
        if found.get("status") != "no_data":
            # randomized, or genuinely not in the registry. Either way the
            # map cannot improve on it: it is a 39 entry subset of the same
            # registry and would only answer a prefix the big file lacks.
            return "Unknown"
    except Exception as e:                                  # noqa: BLE001
        # Never fatal: a vendor name is the least important fact about a
        # device and it must not be able to stop a scan.
        logger.debug(f"oui registry unavailable, falling back to the map: {e}")

    prefix = mac[:8].lower().replace("-", ":")
    return OUI_MAP.get(prefix, "Unknown")


# THE LOCAL NETWORK, READ FROM THE KERNEL RATHER THAN GUESSED AT
#
# WHAT WAS WRONG WITH THE OLD ONE. `_get_local_subnet()` opened a UDP socket,
# connected it to a public resolver, read the source address off it, and
# returned the first three octets. Two faults, both measured:
#
#   * The socket connect is a probe of the DEFAULT ROUTE, and there may not be
#     one. On a LAN with no uplink (the homelab case this app is built for) it
#     raises, the function returns "", and the sweep reports "could not
#     determine this machine's subnet" — while the interface, its address and
#     the entire neighbour table are sitting in /proc/net/* the whole time.
#   * It also put a route lookup for a question about the LOCAL LINK through a
#     public resolver's address, which needs no network at all.
#
# The kernel answers this without a packet and without a subprocess, two ways,
# and both are used here because they answer different halves:
#
#   /proc/net/route     which interface carries the default route. Columns are
#                       fixed and the addresses are LITTLE-ENDIAN HEX, which
#                       is why they are decoded rather than read.
#   SIOCGIFADDR and     each interface's own address and netmask, through
#   SIOCGIFNETMASK      ioctl(2) on a UDP socket. This is the ABI `ip addr`
#                       itself reads; it needs no netlink library, no parsing
#                       and no privileges, and it reports the REAL prefix
#                       length, which matters: a host on a /16 and a host on a
#                       /26 cannot be swept the same way.

import fcntl
import ipaddress
import struct

_SIOCGIFADDR    = 0x8915
_SIOCGIFNETMASK = 0x891B


def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError as e:
        logger.debug(f"{path} not readable: {e}")
        return ""


def _dotted(hex_le: str) -> str:
    """The kernel stores IPv4 addresses little-endian, in hex."""
    try:
        value = int(hex_le, 16)
    except (TypeError, ValueError):
        return ""
    return ".".join(str((value >> shift) & 0xFF) for shift in (0, 8, 16, 24))


def default_route() -> dict:
    """
    {iface, gateway} for the default route, out of /proc/net/route.

    {} when there is no default route, which is a legitimate state (an
    isolated LAN) and NOT a reason to refuse to sweep. Destination and mask
    both zero is the kernel's way of writing "default".
    """
    for line in _read_text("/proc/net/route").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue
        iface, dest, gateway, mask = parts[0], parts[1], parts[2], parts[7]
        if dest == "00000000" and mask == "00000000":
            return {"iface": iface, "gateway": _dotted(gateway)}
    return {}


def _ioctl_addr(name: str, request: int) -> str:
    """
    One interface's address or netmask, via ioctl. "" when it has none.

    A struct ifreq is a 16 byte name plus a socket address union; only the
    first four bytes of the union are read here, which is the IPv4 address.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        packed = fcntl.ioctl(sock.fileno(), request,
                             struct.pack("256s", name[:15].encode("utf-8")))
        return socket.inet_ntoa(packed[20:24])
    except OSError:
        return ""
    finally:
        if sock is not None:
            sock.close()


def local_addresses() -> list[dict]:
    """
    [{iface, ip, prefix}] for every routable IPv4 address this machine holds.

    Loopback and link-local are dropped: neither is a network to sweep, and
    a 169.254 address means the interface failed to get a lease rather than
    that a LAN exists. An isolated LAN with NO default route still appears
    here, which is the whole reason this replaced the UDP probe — the same
    call answers on a laptop on a train as in a datacentre.

    The prefix is computed from the netmask, so it is the interface's real
    one: /16, /24 and /26 hosts all come out right, and the sweep range is
    built from this rather than assumed.
    """
    out = []
    try:
        names = [name for _index, name in socket.if_nameindex()]
    except OSError as e:
        logger.debug(f"could not list interfaces: {e}")
        return out

    for name in names:
        ip = _ioctl_addr(name, _SIOCGIFADDR)
        if not ip or ip.startswith("127.") or ip.startswith("169.254."):
            continue
        mask = _ioctl_addr(name, _SIOCGIFNETMASK)
        prefix = MAX_SWEEP_PREFIX
        if mask:
            try:
                prefix = ipaddress.ip_network(f"0.0.0.0/{mask}",
                                              strict=False).prefixlen
            except ValueError:
                prefix = MAX_SWEEP_PREFIX
        out.append({"iface": name, "ip": ip, "prefix": prefix})

    def rank(entry):
        # The default route's interface first, then anything that is UP, and
        # a routable /24-ish network before a wide one: on a box with docker
        # and a wifi card, the docker bridge must not win the sweep.
        return (entry["iface"] != default_route().get("iface"),
                0 if 16 <= entry["prefix"] <= 30 else 1,
                -entry["prefix"], entry["iface"])

    out.sort(key=rank)
    return out


def _get_local_subnet() -> str:
    """
    The /24 prefix this machine sits on, as a string like "192.0.2".

    Kept as a string because it is what the sweep builds addresses from and
    what the presence record has always carried. Empty means the machine
    holds no routable IPv4 address at all, and the caller reports that.

    Order, and each step is a measurement rather than a preference:
      1. the address on the interface that carries the DEFAULT ROUTE, when
         there is one, because it is the interface a sweep is about;
      2. otherwise the first local address the kernel reports, so an isolated
         LAN still gets swept;
      3. the old UDP probe as a last resort, for a host whose /proc and
         interface list are both unreadable — a worse answer than 1 or 2 but
         still an answer.

    There used to be a hardcoded fallback prefix here, taken from the network
    this was written on. Anywhere else it would have quietly swept 254
    addresses belonging to nobody and reported zero devices, which looks
    identical to a clean network.
    """
    locals_ = local_addresses()
    if locals_:
        return ".".join(locals_[0]["ip"].split(".")[:3])

    probe = None
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # connect() on a UDP socket sends nothing. It makes the OS choose a
        # route and bind a source address, which is the only thing wanted
        # here. The destination is a well-known public resolver used purely
        # as a routing hint, and this is the LAST resort rather than the
        # first: it needs a route and it needs egress.
        probe.connect(("8.8.8.8", 80))
        ip = probe.getsockname()[0]
        parts = ip.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3])
    except OSError as e:
        logger.warning(f"Could not determine the local subnet: {e}")
    finally:
        if probe is not None:
            probe.close()
    return ""


def host_netmask_prefix(subnet: str) -> int:
    """
    The prefix length the machine reports for the network this /24 belongs to.

    Only used to say the truth out loud: a host on a /16 whose sweep is a /24
    is being told that, rather than being left to read the sweep as complete.
    """
    for entry in local_addresses():
        if _in_subnet(entry["ip"], subnet):
            return entry["prefix"]
    return MAX_SWEEP_PREFIX


def own_hardware_address(subnet: str = "") -> str:
    """
    This machine's own MAC on the interface the sweep uses, or "".

    WHY IT IS READ AT ALL: the app's own address gets a device row like every
    other address, and that row was carrying NO hardware address — so
    identity_class called this host `no_hardware_address`, and a row with no
    address cannot be matched against anything later. Measured on this host
    before the fix: the app's own row had mac NULL while /sys/class/net held
    the truth for the same interface. This is the same correction the T5 round
    made for file ownership: read it off the machine, never from a guess.
    """
    iface = default_route().get("iface")
    if not iface or not _ioctl_addr(iface, _SIOCGIFADDR):
        for entry in local_addresses():
            if not subnet or _in_subnet(entry["ip"], subnet):
                iface = entry["iface"]
                break
    if not iface:
        return ""
    mac = _read_text(f"/sys/class/net/{iface}/address").strip()
    if re.match(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", mac):
        return mac.lower()
    return ""


def _sweep_range(subnet: str) -> dict:
    """
    The addresses a sweep will actually probe, and what it left out.

    THE RANGE IS THE INTERFACE'S OWN, up to a /24. A host on a /26 has 62
    usable addresses and sweeping 254 of them probes 192 addresses belonging
    to somebody else's subnet, so the range is derived from the real prefix
    rather than fixed at 254. A host on a /16 is CLAMPED to the /24 around its
    own address — measured: a /16 is 65,534 probes and hours of wall clock for
    the same neighbour table that a /24 fills in seconds — and `clamped_from`
    carries the real prefix so the payload can say so and name what it costs.

    THE NETWORK IS BUILT FROM THE MACHINE'S OWN ADDRESS, not from a zeroed
    last octet, and that is not cosmetic. Measured while writing this: a host
    at 192.0.2.130 on a /25 built as "192.0.2.0/25" gives the network
    192.0.2.0-127 — THE OTHER HALF — and would have swept 126 addresses none
    of which is a neighbour, while reporting a clean LAN. The own address is
    what makes the network the RIGHT /25, and when the machine cannot say
    which address it holds, the /24 around the zeroed octet is the fallback.
    """
    real = host_netmask_prefix(subnet)
    own = ""
    for entry in local_addresses():
        if _in_subnet(entry["ip"], subnet):
            own = entry["ip"]
            break

    try:
        net = ipaddress.ip_network(f"{own or subnet + '.0'}/{real}",
                                   strict=False)
    except ValueError:
        net = ipaddress.ip_network(f"{subnet}.0/24", strict=False)

    # KEEP THE INTERFACE'S OWN PREFIX. Overwriting `real` below is what makes
    # a /16 report itself as an unclamped /24 and say nothing about the
    # addresses outside the range it swept — measured: clamped_from None and
    # no note at all for a host on a /16.
    interface_prefix = real
    if net.num_addresses > 256:
        net = ipaddress.ip_network(f"{own or subnet + '.0'}/24", strict=False)

    targets = [str(h) for h in net.hosts()]
    if own and own in targets:
        targets.remove(own)          # a host cannot ping itself into the list

    note = ""
    if interface_prefix < MAX_SWEEP_PREFIX:
        note = (
            f"This machine's interface reports a /{interface_prefix}, and the "
            f"/24 around its own address ({net}) is what was swept. The wider "
            f"range holds {2 ** (32 - interface_prefix) - 2:,} addresses, "
            f"which is hours of probing for the same neighbour table. A device "
            f"outside this /24 that is talking to this LAN is not on this "
            f"list.")
    return {"targets": targets, "cidr": str(net),
            "clamped_from": interface_prefix if interface_prefix < MAX_SWEEP_PREFIX
            else None,
            "own": own, "note": note}


def _in_subnet(addr: str, subnet: str) -> bool:
    """
    Does this address fall inside the /24 named by `subnet`.

    `addr.startswith(subnet + ".")` is not the check, and the difference is
    not academic: the string "192.0.2." is a prefix of "192.0.2.1", which is
    correct, and also of "192.0.2.1.example" and "192.0.2.1234", which are
    not. A prefix that is only safe because the caller remembered the trailing
    dot is one edit away from matching a neighbour from another network.
    Parsed once and compared as integers instead, and a malformed address on
    either side returns False rather than raising mid-sweep.
    """
    try:
        want = [int(x) for x in str(subnet).split(".")]
        have = [int(x) for x in str(addr).split(".")]
    except ValueError:
        return False
    return len(want) == 3 and len(have) == 4 and have[:3] == want


# PING AND ARP, PER PLATFORM. Fixed 2026-09-17, and the exit code fixed
# 2026-09-24.
#
# Both of the external commands below were written for Windows and copied
# into the Linux tree unchanged. That is why "scan network" failed: it was
# running `ping -n 1 -w 200 <addr>` and `arp -a` on Linux, and neither means
# what the Windows flag set means.
#
#   ping: -n is "numeric output" on Linux and takes no argument, -w is the
#         DEADLINE IN SECONDS for the whole command, not a per-reply
#         millisecond timeout. So `-n 1` made ping treat "1" as a hostname,
#         then "-w 200" gave it a 200 second deadline, and `-w` also silently
#         enabled record-route, which needs privileges and is refused. The
#         command exited non-zero having sent no packet, so every address on
#         the network read as absent while the scan reported success.
#         Linux wants: -c <count> -W <per-reply timeout, seconds>
#         Windows wants: -n <count> -w <per-reply timeout, milliseconds>
#
#   arp: `arp -a` DOES work on Linux net-tools and prints
#         "_gateway (192.0.2.1) at 02:00:00:00:00:01 [ether] on eth0"
#         while Windows prints "  192.0.2.1    02-00-00-00-00-01  dynamic".
#         The parser here split on whitespace and took parts[0] as the address
#         and parts[1] as the MAC, which on Linux gives "(192.0.2.1)" and
#         "at". The IP regex then rejected "(192.0.2.1)" and the MAC column
#         came back empty for every device, so the inventory had addresses
#         with no hardware identity.
#
# ip neigh is preferred on Linux where it exists: its output is stable,
# machine-readable, and it is the command the kernel actually maintains.
_IS_WINDOWS = sys.platform.startswith("win")

# THE THREE ANSWERS A PROBE CAN GIVE, and the third one is the point.
ANSWERED = "answered"     # the address replied: evidence
SILENT   = "silent"       # the probe ran and nothing came back
NOT_PROBED = "not_probed"  # no probe could run, so this address is unknown

# ping's own exit codes on both platforms. Anything that is not one of these
# means the COMMAND failed rather than the address being absent, and the two
# must never be collapsed: see NET-13 in bugfinder.md, where a missing ping
# binary produced 254 "absent" addresses and a successful sweep.
_PING_NO_REPLY = 1
_PING_OK = 0


def _probe(ip: str) -> dict:
    """
    One address, one probe. {"verdict", "detail"}.

    `detail` is only meaningful for NOT_PROBED, and it is the sentence the
    payload prints when the sweep could not run. Measured on this host:
    a PATH with no `ping` produced an "ok" sweep of 254 targets with 7
    responders, of which every one came from the ARP cache — the sweep looked
    like a quiet network rather than a broken tool.
    """
    if _IS_WINDOWS:
        # -n count, -w per-reply timeout in milliseconds
        cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT), ip]
    else:
        # -c count, -W per-reply timeout in SECONDS. PING_TIMEOUT is in
        # milliseconds on both platforms, so it is converted rather than
        # reused; passing 200 here would be a 200 second wait per address.
        secs = max(1, int(round(PING_TIMEOUT / 1000.0)))
        cmd = ["ping", "-c", "1", "-W", str(secs), "-n", ip]

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=5)
    except FileNotFoundError:
        return {"verdict": NOT_PROBED,
                "detail": ("the `ping` command is not on PATH for this "
                           "process, so no address was probed")}
    except PermissionError as e:
        return {"verdict": NOT_PROBED,
                "detail": (f"`ping` refused to run ({e}), so no address was "
                           f"probed")}
    except subprocess.TimeoutExpired:
        return {"verdict": NOT_PROBED,
                "detail": ("`ping` did not finish within 5 seconds, so this "
                           "address was not probed")}
    except OSError as e:
        return {"verdict": NOT_PROBED,
                "detail": f"`ping` could not be run ({e})"}

    if result.returncode == _PING_OK:
        return {"verdict": ANSWERED, "detail": ""}
    if result.returncode == _PING_NO_REPLY:
        return {"verdict": SILENT, "detail": ""}
    # 2 on both platforms: a usage or resolution error, i.e. the command
    # itself failed. Not an absence.
    return {"verdict": NOT_PROBED,
            "detail": ("`ping` exited with code "
                       f"{result.returncode}, which is the command failing "
                       "rather than the address being silent")}


def _ping(ip: str) -> bool:
    """
    One address, one probe. True only if it ANSWERED.

    Kept as a bool for callers that want one; a probe that could not run is
    False here and NOT_PROBED in _probe(), and the two entry points use the
    three-valued form so the difference reaches the payload.
    """
    return _probe(ip)["verdict"] == ANSWERED


def _read_arp_cache() -> dict[str, str]:
    """
    {ip: mac} for every neighbour this machine knows.

    Three sources, tried in order, because each one is absent somewhere:
    /proc/net/arp (Linux, no subprocess at all), `ip neigh` (Linux, handles
    IPv6 and namespaces), and `arp -a` parsed for whichever platform it is.
    """
    if not _IS_WINDOWS:
        macs = _read_proc_net_arp()
        if macs:
            return macs
        macs = _read_ip_neigh()
        if macs:
            return macs

    return _read_arp_command()


def _read_proc_net_arp() -> dict[str, str]:
    """
    /proc/net/arp, the cheapest source on Linux.

    Columns are fixed: IP, HW type, Flags, HW address, Mask, Device. A row
    with flags 0x0 is an INCOMPLETE entry, which means the kernel asked and
    nobody answered. Those are skipped: an entry that is not resolved is not
    evidence the device is there.
    """
    macs = {}
    try:
        with open("/proc/net/arp", encoding="utf-8") as f:
            next(f, None)                      # header
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                ip, _hwtype, flags, mac = parts[0], parts[1], parts[2], parts[3]
                if not re.match(r"(\d{1,3}\.){3}\d{1,3}$", ip):
                    continue
                if mac == "00:00:00:00:00:00" or flags == "0x0":
                    continue
                macs[ip] = mac.lower()
    except OSError as e:
        logger.debug(f"/proc/net/arp not readable: {e}")
    return macs


def _read_ip_neigh() -> dict[str, str]:
    """
    `ip neigh`, which is what the kernel tooling itself reports.

    Format: "192.0.2.1 dev X lladdr 02:00:00:00:00:01 REACHABLE"
    Lines without an lladdr are states like FAILED or INCOMPLETE, and those
    are skipped for the same reason as above.

    IPv4 only, and the IPv6 rows this command does print are dropped by the
    address check rather than mis-parsed: every entity this app stores is an
    IPv4 address, so an fe80:: entry has nowhere to go.
    """
    macs = {}
    try:
        result = subprocess.run(["ip", "neigh"], capture_output=True,
                                text=True, timeout=5)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5 or "lladdr" not in parts:
                continue
            ip = parts[0]
            if not re.match(r"(\d{1,3}\.){3}\d{1,3}$", ip):
                continue
            mac = parts[parts.index("lladdr") + 1]
            if mac == "00:00:00:00:00:00":
                continue
            macs[ip] = mac.lower()
    except Exception as e:
        logger.debug(f"ip neigh read error: {e}")
    return macs


def _read_arp_command() -> dict[str, str]:
    """
    `arp -a`, parsed per platform.

    THE PARSER IS THE POINT. The Windows and Linux outputs share no column
    layout, and the version of this function that only understood Windows
    silently produced an empty MAC column on every Linux host.
    """
    macs = {}
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True,
                                text=True, timeout=5)
        for line in result.stdout.splitlines():
            if _IS_WINDOWS:
                # "  192.0.2.249     02-00-00-00-00-01     dynamic"
                parts = line.split()
                if len(parts) >= 2:
                    ip, mac = parts[0].strip(), parts[1].strip()
                    if re.match(r"(\d{1,3}\.){3}\d{1,3}$", ip):
                        macs[ip] = mac.replace("-", ":").lower()
                continue

            # Linux net-tools:
            # "_gateway (192.0.2.1) at 14:c0:3e:93:80:01 [ether] on wlp1s0"
            # The address is in brackets, the MAC follows "at".
            addr = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", line)
            if not addr:
                continue
            mac = re.search(r"at ([0-9a-fA-F:]{17})", line)
            if not mac:
                # "at <incomplete>" means the lookup did not resolve.
                continue
            macs[addr.group(1)] = mac.group(1).lower()
    except Exception as e:
        logger.debug(f"ARP cache read error: {e}")
    return macs


def _resolve_hostname(ip: str) -> str:
    """
    The name this address answers to, or "".

    Blocking, and glibc's own ceiling is what bounds it, not this function.
    It is called from a pool rather than in a loop, because in a loop it is
    the whole cost of a scan: measured 0.112 s here for an address with no
    PTR, which is 28 seconds of a 254 address scan spent waiting on a
    resolver, one address at a time.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# THE SWEEP CLOCK, IN ONE PLACE
#
# Two config keys and a default used to be three answers to one question, and
# the module's own block (`sensors.network_scanner.poll_interval`) was read by
# nothing at all — a documented control with no consumer, which is worse than
# no control. It means something here: the interval between presence sweeps.
# The general block wins when it is set, because it is what main.py has always
# read and a config written before this round must keep working; the specific
# one wins when the general one is absent; the default is last.
#
# The winner's NAME is returned with the number so status() can publish which
# key is in charge, rather than leaving an operator to work it out.

def sweep_interval_seconds(config: dict) -> tuple[int, str]:
    """(seconds, which key answered) for the presence sweep."""
    config = config or {}
    specific = ((config.get("sensors", {}) or {})
                .get("network_scanner", {}) or {})
    general = config.get("presence_sweep", {}) or {}

    for value, source in ((general.get("interval_minutes"),
                           "presence_sweep.interval_minutes"),
                          (specific.get("poll_interval"),
                           "sensors.network_scanner.poll_interval")):
        try:
            minutes = int(value)
        except (TypeError, ValueError):
            continue
        if minutes > 0:
            return max(1, minutes) * 60, source

    return (DEFAULT_SWEEP_INTERVAL_MINUTES * 60,
            "the built-in default, because neither key is set")


def sweep_enabled(config: dict) -> tuple[bool, str]:
    """
    (enabled, which key said so). An ABSENT key means ON.

    Both shapes have to be covered or a config written before this round
    quietly loses its scanner: an empty block, a block without the key, and no
    sensors block at all are all ON. That is what every other sensor in this
    tree does and it is the reason this is spelled out rather than defaulted
    inline.
    """
    config = config or {}
    specific = ((config.get("sensors", {}) or {})
                .get("network_scanner", {}) or {})
    general = config.get("presence_sweep", {}) or {}

    if "enabled" in specific:
        return bool(specific.get("enabled")), "sensors.network_scanner.enabled"
    if "enabled" in general:
        return bool(general.get("enabled")), "presence_sweep.enabled"
    return True, "no key is set, so it is ON"


class NetworkScanner:

    # An absent device stays absent, and the sweep runs every fifteen
    # minutes. Without a cooldown one unplugged printer writes 96 identical
    # findings a day, which is exactly how linux_monitor's process check
    # became a burial tool. One finding per device per day.
    ABSENCE_COOLDOWN_SECONDS = 86400

    def __init__(self, session_id: str, config: dict = None):
        self.session_id   = session_id
        self.config       = config or {}
        self._last_result = []
        self._absence_emitted: dict[str, float] = {}
        # What the last sweep and the last scan each did, so status() can
        # answer "when did this last look, and at what" instead of "nothing
        # is wrong as far as I know". Never persisted: a restart is a
        # legitimate reason to have no answer yet, and the readiness row says
        # exactly that rather than implying a measurement.
        self._last_sweep: dict = {}
        self._last_scan: dict = {}
        self._off_logged = False

    def start(self):
        logger.info("NetworkScanner ready.")

    # CONFIG

    def _enabled(self) -> tuple[bool, str]:
        return sweep_enabled(self.config)

    def status(self) -> dict:
        """
        What this module can honestly say about itself right now.

        THE ROW THIS FEEDS IS THE REASON FOR EVERY KEY BELOW. Before this
        round the answer was `{"ready": True, "last_scan_count": 0}` for a
        freshly loaded module, which core/settings resolves to a GREEN row
        reading "running." — measured on this host, for a module that had
        swept nothing, in a process that had not started a sweeper, with the
        operator's own config switching sweeps off in the one case that
        mattered. `ready` means the object exists and its functions are
        callable; that is what it says now, and nothing more.
        """
        enabled, which_key = self._enabled()
        out = {
            "ready": True,
            "last_scan_count": len(self._last_result),
            "hostname_lookup": RESOLVE_HOSTNAMES,
        }

        if not enabled:
            # THE SHAPE THAT RENDERS OFF, NOT GREEN. core/settings._module_row
            # picks its verdict with `running`, then `ready`, then
            # `available`, so a dict that keeps `ready: True` paints the row
            # green and prints "running." directly beside the note saying the
            # sensor is switched off — the defect the switch exists to remove,
            # reintroduced by the switch. The key that was carrying the truth
            # has to GO rather than go false, which is the rule the autoruns
            # round wrote down when its own adapter shipped this defect.
            out.pop("ready", None)
            out["available"] = False
            out["off_by_config"] = True
            out["enabled"] = False
            out["reason"] = (
                f"SWITCHED OFF IN CONFIG ({which_key}). No sweep runs, no "
                f"sweep is recorded, and the device list is whatever was last "
                f"stored. An empty answer here is the switch, NOT a quiet "
                f"network.")
            out["note"] = (
                f"Sweeping is off by config ({which_key} in config.json). "
                f"Nothing is being looked at, so an empty device list is "
                f"NOT a quiet network.")
            return out

        out["enabled"] = True
        if self._last_sweep:
            out["last_presence_sweep"] = self._last_sweep
            out["reachable"] = True
        else:
            # THREE-VALUED, AND THE THIRD VALUE IS THE POINT. `reachable: None`
            # means we have not tried, and core/settings prints exactly that
            # rather than the bare word "running." — which is the row this
            # module was printing for a process that had swept nothing.
            out["reachable"] = None
        if self._last_scan:
            out["last_scan"] = self._last_scan

        # WHICH CLOCK IS IN CHARGE, AND WHAT THE OTHER ONE SAYS.
        #
        # The owner's own config has BOTH keys: `presence_sweep.interval_minutes`
        # at 15 and `sensors.network_scanner.poll_interval` at 300 seconds —
        # the same number twice, which is a coincidence rather than a
        # convention. The general key is the one this app has always read, so
        # it wins and the owner's behaviour is unchanged. What is new is that the
        # module SAYS which key is live and what the losing one says, so a
        # future setting of one of them cannot go on being silently inert.
        interval, interval_key = sweep_interval_seconds(self.config)
        out["sweep_interval_minutes"] = interval // 60
        out["sweep_interval_source"] = interval_key
        try:
            _specific = int(((self.config.get("sensors", {}) or {})
                             .get("network_scanner", {}) or {})
                            .get("poll_interval") or 0)
        except (TypeError, ValueError):
            _specific = 0
        if _specific and interval_key != "sensors.network_scanner.poll_interval":
            out["sweep_interval_note"] = (
                f"Two keys are set and only one can be in charge: "
                f"{interval_key} = {interval // 60} minute(s) is what the "
                f"sweeper uses, and sensors.network_scanner.poll_interval = "
                f"{_specific} seconds is NOT being read. Set the general key, "
                f"or clear it to let the specific one take over.")

        # THE LOUDEST RULE THIS MODULE OWNS, AND WHETHER IT HAS ANYTHING TO
        # COMPARE AGAINST. NET-1002 (a declared always-on device has stopped
        # answering) fires only for devices the operator declared, and after
        # the v22 split nothing is declared until somebody says so. So on a
        # fresh install that rule is SILENT for a reason that has nothing to
        # do with the network, and the only place that said so was a log line.
        try:
            declared = len(me.always_on_devices())
        except Exception as e:                              # noqa: BLE001
            declared = None
            logger.debug(f"could not read the always-on declarations: {e}")
        if declared == 0:
            out["always_on_declared"] = 0
            out["note"] = (
                "No device is declared always-on, so the absence rule has "
                "nothing to compare against and will report nothing. That is "
                "not a statement that every device is present. Declare one "
                "with scripts/set_always_on.py.")
        elif declared:
            out["always_on_declared"] = declared

        if not self._last_sweep:
            out["note"] = (
                (out.get("note", "") + " ").lstrip()
                + "No presence sweep has completed in this process yet, so "
                  "nothing has been measured either way. The sweeps are on a "
                  "timer and the first one lands within the interval.")

        return out

    # SCAN

    def scan(self, session_id: str = None,
             resolve_hostnames: bool = None) -> dict:
        """
        The expensive, identifying pass: who is on this network, and what is
        each address.

        CALLED BY THE MODEL and by nothing on a clock. It upserts
        known_devices and raises NET-1001 for an address it has no row for,
        which is why the presence sweeper is a separate entry point: a tick
        that raised findings every fifteen minutes would be switched off
        within a day.

        WHAT COUNTS AS BEING HERE, 2026-09-24. `answered` is an ICMP reply.
        `arp_reached` is a neighbour entry the kernel resolved during a sweep
        that actually probed. Both are devices; the difference is carried in
        `via` on every row and in `probe` on the payload, because an ARP entry
        is memory and a reply is evidence and a reader is entitled to know
        which one they are looking at. An entry the kernel resolved while NO
        probe could run is recorded as `arp_unprobed` and is NOT counted as
        reachable — see the module header for the measurement.
        """
        sid    = session_id or self.session_id
        subnet = _get_local_subnet()

        enabled, which_key = self._enabled()
        if not enabled:
            return self._off_answer(which_key)

        if not subnet:
            # Refusing beats sweeping the wrong range and reporting nothing.
            return {
                "error": ("Could not determine this machine's subnet, so there "
                          "is nothing safe to scan. Check that a network "
                          "interface is up. No addresses were probed."),
                "subnet": None,
                "devices_found": 0,
                "unidentified": 0,
                "unidentified_transient_clients": 0,
                "devices": [],
                "probe": {"probed": 0, "answered": 0, "silent": 0,
                          "not_probed": 0,
                          "note": ("No interface address could be read, so no "
                                   "probe was attempted at all. This is not an "
                                   "empty network.")},
            }

        plan = _sweep_range(subnet)
        hosts = plan["targets"]
        logger.info(f"Network scan starting: {plan['cidr']}")

        import time as _time
        started = _time.monotonic()
        answered, silent, unprobed = self._probe_hosts(hosts)
        arp_cache = _read_arp_cache()

        # A NEIGHBOUR ENTRY IS REACHABILITY ONLY WHERE SOMETHING PROBED.
        #
        # `a in probed` and NOT `a not in unprobed`, and the difference was
        # measured by this round's own negative control: with that test the
        # first version counted an ARP entry for an address OUTSIDE the swept
        # range as reachable — a neighbour the sweep never asked about, whose
        # entry was only warm because some other traffic had touched it. An
        # address that was not a target of this sweep is not evidence this
        # sweep collected, so it cannot be a responder in it.
        probed = answered | silent
        arp_present = {a for a in arp_cache if _in_subnet(a, subnet)}
        arp_reached = {a for a in arp_present if a in probed}
        arp_unprobed = {a for a in arp_present if a not in probed}

        live = answered | arp_reached

        # ONE READ FOR EVERY DEVICE, not one per device. The loop below used
        # to call me.query_known_devices(ip=...) once per address, which opens
        # its own read-only connection each time: measured 11 ms each, so a
        # scan that found fifty devices spent half a second opening the same
        # table fifty times.
        existing_by_ip = {}
        try:
            for row in (me.query_known_devices() or []):
                existing_by_ip[row.get("ip")] = row
        except Exception as e:                              # noqa: BLE001
            logger.warning(f"Could not read the device inventory: {e}")

        names = self._resolve_names(live) if (
            RESOLVE_HOSTNAMES if resolve_hostnames is None else resolve_hostnames
        ) else {}

        devices   = []
        unidentified = 0

        for ip in sorted(live, key=lambda x: int(x.split(".")[-1])):
            mac      = arp_cache.get(ip, "")
            vendor   = _oui_lookup(mac)
            hostname = names.get(ip, "")
            via = ("icmp" if ip in answered and ip not in arp_reached
                   else "both" if ip in answered
                   else "arp")

            prior    = existing_by_ip.get(ip) or {}
            is_new   = ip not in existing_by_ip
            known_as = (prior.get("known_as") or "").strip()

            device = {
                "ip":       ip,
                "mac":      mac,
                "vendor":   vendor,
                "hostname": hostname,
                # Carried through so a caller reading the scan result does not
                # have to make a second lookup to find out whether this address
                # means anything. Vendor is not a label: an OUI says who made
                # the network chip, which for most consumer hardware is not who
                # made the device.
                "known_as":     known_as or None,
                "device_type":  prior.get("device_type"),
                "identified":   bool(known_as),
                # HOW THIS ADDRESS WAS SEEN, on the row itself. "both" is a
                # reply AND a neighbour entry; "icmp" is a reply the cache did
                # not keep; "arp" is a resolved neighbour entry during a sweep
                # that probed, which is weaker evidence than a reply and is the
                # only way a device that blocks ICMP is ever visible.
                "via":          via,
                # Whether this address can stand for a device at all. See
                # memory_engine.identity_class.
                "identity_class": me.identity_class(mac),
            }
            devices.append(device)
            if not known_as:
                unidentified += 1

            me.save_known_device(
                ip=ip,
                mac=mac or None,
                vendor=vendor if vendor != "Unknown" else None,
                hostname=hostname or None,
            )

            if is_new:
                self._raise_new_device(sid, device, mac, vendor, hostname,
                                       randomized=me.is_randomized_mac(mac),
                                       via=via)

        # THIS HOST'S OWN ROW, WITH ITS HARDWARE ADDRESS. It has a device row
        # like every other address and the row was arriving with no MAC at
        # all, because a host does not ARP itself and an ICMP reply carries no
        # hardware address. /sys knows it. Filled rather than invented, and
        # left alone when the machine will not say.
        own_mac = own_hardware_address(subnet)
        if own_mac:
            for entry in local_addresses():
                if not _in_subnet(entry["ip"], subnet):
                    continue
                try:
                    me.save_known_device(ip=entry["ip"], mac=own_mac)
                except Exception as e:                      # noqa: BLE001
                    logger.debug(f"could not record this host's own MAC: {e}")

        self._last_result = devices
        duration = int((_time.monotonic() - started) * 1000)
        self._last_scan = {"at": _utc_now(), "count": len(devices),
                           "cidr": plan["cidr"], "duration_ms": duration,
                           "probed": len(probed),
                           "arp_only": sum(1 for d in devices if d["via"] == "arp")}
        logger.info(
            f"Network scan complete: {len(devices)} devices found, "
            f"{unidentified} without a recorded identification"
        )
        transient = sum(1 for d in devices
                        if d["identity_class"] == "transient_client"
                        and not d["identified"])

        notes = [
            f"{unidentified} of {len(devices)} devices have no recorded "
            f"identification. Seen is not the same as known. Do not describe "
            f"an unidentified device as belonging to anything; ask, then call "
            f"identify_device with what you were told."
            if unidentified else
            "Every device found has a recorded identification."
        ]
        if transient:
            notes.append(
                f"{transient} of the unidentified are at RANDOMIZED addresses "
                f"(identity_class 'transient_client'), which is what phones "
                f"and laptops do. Those are appearances rather than devices "
                f"and several of them may be the same handset. Count and "
                f"report the stable-address ones separately."
            )
        arp_only = sum(1 for d in devices if d["via"] == "arp")
        if arp_only:
            notes.append(
                f"{arp_only} of these were seen only in the neighbour cache "
                f"during this sweep (via 'arp'): this machine had a resolved "
                f"ARP entry and the device did not answer ICMP. That is "
                f"weaker evidence than a reply and can outlive a device that "
                f"has just left.")
        if plan["note"]:
            notes.append(plan["note"])
        probe_note = self._probe_note(probed, answered, unprobed, arp_unprobed)
        if probe_note:
            notes.append(probe_note)

        return {
            "subnet":        plan["cidr"],
            "devices_found": len(devices),
            "unidentified":  unidentified,
            "unidentified_transient_clients": transient,
            "devices":       devices,
            "note":          " ".join(notes),
            "probe": {
                "probed":        len(probed),
                "answered":      len(answered),
                "silent":        len(silent),
                "not_probed":    len(unprobed),
                "arp_unprobed":  sorted(arp_unprobed),
                "duration_ms":   duration,
            },
        }

    def _probe_hosts(self, hosts: list) -> tuple[set, set, dict]:
        """
        Probe every address. (answered, silent, {ip: why not}) — the third one
        is what stops a sweep that could not run from reading as a quiet LAN.
        """
        answered, silent, unprobed = set(), set(), {}
        with ThreadPoolExecutor(max_workers=min(PING_WORKERS, max(1, len(hosts)))) as ex:
            futures = {ex.submit(_probe, ip): ip for ip in hosts}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    verdict = future.result()
                except Exception as e:                      # noqa: BLE001
                    unprobed[ip] = f"the probe raised {type(e).__name__}: {e}"
                    continue
                if verdict["verdict"] == ANSWERED:
                    answered.add(ip)
                elif verdict["verdict"] == SILENT:
                    silent.add(ip)
                else:
                    unprobed[ip] = verdict["detail"]
        return answered, silent, unprobed

    def _probe_note(self, probed: set, answered: set, unprobed: dict,
                    arp_unprobed: set) -> str:
        """
        The sentence a sweep that could not run owes its reader.

        Silence here is how a broken prober becomes a clean network, which is
        the exact fault this round exists for, so it is a sentence in the
        payload and not a log line.
        """
        if not unprobed:
            return ""
        why = ""
        for detail in unprobed.values():
            if detail:
                why = detail
                break
        if len(unprobed) == len(probed) + len(unprobed):
            return (
                f"NOT ONE ADDRESS WAS PROBED ({len(unprobed)} of them): {why}. "
                f"Nothing on this list came from an ICMP reply, so treat it as "
                f"the neighbour cache and nothing more. A network with no "
                f"devices and a scanner that cannot probe look identical here.")
        return (
            f"{len(unprobed)} of {len(probed) + len(unprobed)} addresses were "
            f"NOT PROBED ({why})."
            + (f" {len(arp_unprobed)} of them had a resolved neighbour entry "
               f"and are reported as NOT reachable, because nothing asked."
               if arp_unprobed else "")
        )

    def _resolve_names(self, ips: set) -> dict:
        """
        PTR names for a set of addresses, in parallel and bounded.

        In series this was the whole cost of a scan (measured 0.112 s per
        unresolvable address, 254 of them). In a pool it is one resolver
        round-trip, and the pool is deliberately smaller than the ping pool
        because a home router answering 254 simultaneous PTR queries is a
        flood, not a measurement.
        """
        names = {}
        if not ips:
            return names
        with ThreadPoolExecutor(max_workers=min(LOOKUP_WORKERS, len(ips))) as ex:
            futures = {ex.submit(_resolve_hostname, ip): ip for ip in sorted(ips)}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    name = future.result()
                except Exception:                           # noqa: BLE001
                    name = ""
                if name:
                    names[ip] = name
        return names

    def _raise_new_device(self, sid: str, device: dict, mac: str, vendor: str,
                          hostname: str, randomized: bool, via: str) -> None:
        """
        The finding for an address with no device row. Unchanged in what it
        says, with the one addition: how the address was seen.
        """
        # A NEW ROW IS NOT ALWAYS A NEW DEVICE.
        #
        # known_devices is keyed on IP, so a device that takes a
        # different lease arrives here as a new row. A phone that
        # randomizes its hardware address looks like a new client to
        # the DHCP server every time it rotates, and therefore takes a
        # new lease routinely. Left unsaid, that reads as an unknown
        # machine appearing on the network, over and over, for a phone
        # the user has owned for two years.
        #
        # The severity is NOT lowered for it. A randomized address is
        # what a phone does and also what someone hiding would do, and
        # deciding between those is a judgement, not arithmetic. What
        # changes is that the finding carries the fact, so the reader
        # weighs it instead of guessing. Suppressing the finding here
        # would be Python deciding, which is the thing this codebase
        # keeps a rule against.
        identity_note = (
            "This address is RANDOMIZED (the locally administered bit "
            "is set), so it is not a stable identity. The most common "
            "cause by far is a phone or laptop already on this network "
            "presenting a new address, which also gets it a new DHCP "
            "lease and therefore a new row here. Check whether a "
            "device the user already knows about went quiet around now "
            "before treating this as an arrival. It is worth noting "
            "that hiding also looks like this, so the address does not "
            "settle the question either way."
            if randomized else
            "This address is burned in rather than randomized, so it "
            "is a usable identity: if this device returns, it should "
            "return as the same address. That makes it worth naming."
        )
        seen_note = {
            "arp": ("It was seen only in this machine's neighbour cache, "
                    "meaning the device did not answer ICMP. That is enough to "
                    "know something holds this address and not enough to know "
                    "it is still there."),
            "icmp": "It answered an ICMP probe.",
            "both": ("It answered an ICMP probe and also had a neighbour "
                     "entry."),
        }.get(via, "")

        me.save_finding(
            session_id=sid,
            source="network_scanner",
            detection_id="NET-1001",
            severity="medium",
            entity_type="ip",
            entity_value=device["ip"],
            title=(f"New device row: {device['ip']}"
                   + (" (randomized address)" if randomized else "")),
            description=(
                f"MAC: {mac or 'unknown'}, Vendor: {vendor}, "
                f"Hostname: {hostname or 'none'}. "
                f"This device has no recorded identification. Vendor "
                f"comes from the MAC prefix and names whoever made the "
                f"network chip, which is often not who made the device. "
                f"\n\n{seen_note}\n\n{identity_note}\n\n"
                f"Ask the user what it is, then record the answer with "
                f"identify_device so the next session does not have to "
                f"work it out again.\n\n"
                f"If the user does NOT recognise it, that is what an "
                f"intruder looks like: block_device bans it, and it "
                f"asks the user before it does anything. Never ban on "
                f"your own reading of how ordinary the device looks."
            ),
            raw_data={**device, "randomized_mac": randomized, "via": via},
        )

    def get_last_result(self) -> list:
        return self._last_result

    def _off_answer(self, which_key: str) -> dict:
        """
        The refusal, shaped like a real answer.

        Every key a caller already handles is here, plus `off_by_config`,
        which is the one that says this is a switch rather than a finding —
        the same shape the autorun sensor's refusal uses, so a caller written
        against the good path cannot crash on it.
        """
        if not self._off_logged:
            self._off_logged = True
            logger.info(f"Network scanning is OFF by config ({which_key}).")
        return {
            "subnet": None,
            "devices_found": 0,
            "unidentified": 0,
            "unidentified_transient_clients": 0,
            "devices": [],
            "off_by_config": True,
            "error": (f"SWITCHED OFF IN CONFIG ({which_key}). No address was "
                      f"probed and no device was looked up."),
            "note": (
                f"THE DEVICE LIST IS EMPTY BECAUSE SWEEPING IS OFF, NOT "
                f"BECAUSE THE NETWORK IS. It is switched off by "
                f"{which_key}. This is NOT A CLEAN MACHINE and not an empty "
                f"network: set `enabled` to true in "
                f"sensors.network_scanner in config.json and restart, or "
                f"leave it off and read the stored inventory with "
                f"query_known_devices."),
            "probe": {"probed": 0, "answered": 0, "silent": 0, "not_probed": 0,
                      "note": "the switch is off, so nothing was probed"},
        }

    # PRESENCE SWEEP
    #
    # A SECOND CADENCE, NOT A SECOND SCANNER.
    #
    # scan() above identifies: it upserts known_devices, raises a finding for
    # anything new, and is expensive enough to be fired occasionally, usually
    # because the model asked. That is the right shape for "what is on this
    # network".
    #
    # It is the wrong shape for "is the thing that is always here still
    # here". Absence only means something when it is sampled on a regular
    # tick, because a device missing from an irregular sample is ambiguous
    # between gone and nobody-looked. So this runs on a timer, records what
    # answered and what the sweep cost, and deliberately does NOT identify,
    # does NOT upsert known_devices and does NOT raise findings. A tick that
    # raised a finding every fifteen minutes would be switched off by the user
    # within a day, and the series would die with it.
    #
    # Python decides when this runs. That is what makes the result a
    # measurement: the model cannot choose when to look, so it cannot choose
    # what the record shows.
    #
    # WHAT CHANGED HERE, 2026-09-24: the responders are the same UNION the scan
    # now uses (a reply, or a neighbour entry resolved during a sweep that
    # actually probed), and each one still carries `via` so the two are told
    # apart in storage and on every page that reads them. The two entry points
    # describe the same network now, which they did not before: the sweep had
    # the union and the scan had the replies, so the same host answered two
    # different questions in two different places.

    def sweep_presence(self, session_id: str = None) -> dict:
        """
        Record who answered, right now. Cheap, quiet, and always written.

        Writes a row even when it fails, with the reason. A sweep that could
        not run must not be silently missing from the record, or a stretch
        where the scanner was broken becomes indistinguishable from a stretch
        where the network was quiet.
        """
        import time as _time

        sid     = session_id or self.session_id
        started = _time.monotonic()

        enabled, which_key = self._enabled()
        if not enabled:
            reason = (f"Sweeping is switched off in config "
                      f"({which_key}), so no addresses were probed.")
            if not self._off_logged:
                self._off_logged = True
                logger.info(f"Presence sweep skipped: {reason}")
            return {"outcome": "off", "off_by_config": True,
                    "detail": reason, "responded": 0}

        subnet  = _get_local_subnet()

        if not subnet:
            reason = ("Could not determine this machine's subnet, so no "
                      "addresses were probed.")
            me.record_presence_sweep(
                session_id=sid, method="icmp+arp", outcome="failed",
                detail=reason, targets=0,
                duration_ms=int((_time.monotonic() - started) * 1000),
            )
            logger.warning(f"Presence sweep failed: {reason}")
            return {"outcome": "failed", "detail": reason, "responded": 0}

        plan  = _sweep_range(subnet)
        hosts = plan["targets"]

        try:
            answered, silent, unprobed = self._probe_hosts(hosts)
            arp_cache = _read_arp_cache()
        except Exception as e:
            # An exception here is the case that most needs a row written.
            # Without one, the failure looks exactly like an empty network.
            me.record_presence_sweep(
                session_id=sid, method="icmp+arp", outcome="failed",
                subnet=plan["cidr"], detail=f"Sweep error: {e}",
                targets=len(hosts),
                duration_ms=int((_time.monotonic() - started) * 1000),
            )
            logger.error(f"Presence sweep error: {e}")
            return {"outcome": "failed", "detail": str(e), "responded": 0}

        # An ARP entry is not equivalent to an ICMP reply, and the two are
        # kept apart all the way into storage. ICMP means the device answered.
        # ARP means this machine still remembers it, which outlives the device
        # for as long as the cache entry lives. Collapsing them here would
        # make a stale cache look like a live host with no way to tell
        # afterwards.
        #
        # The union is the same one scan() uses. What is NOT in it: an address
        # whose only evidence is a neighbour entry from a sweep that probed
        # nothing, because then the cache is the app's own traffic echoing
        # back rather than anything answering.
        arp_present  = {a for a in arp_cache if _in_subnet(a, subnet)}
        arp_reached  = {a for a in arp_present if a in (answered | silent)}
        arp_unprobed = {a for a in arp_present if a not in (answered | silent)}
        responders   = []

        for addr in sorted(answered | arp_reached,
                           key=lambda x: int(x.split(".")[-1])):
            in_icmp = addr in answered
            in_arp  = addr in arp_reached
            responders.append({
                "ip":  addr,
                "mac": arp_cache.get(addr, ""),
                "via": "both" if (in_icmp and in_arp)
                       else ("icmp" if in_icmp else "arp"),
            })

        duration = int((_time.monotonic() - started) * 1000)
        # THE METHOD COLUMN NOW MEANS SOMETHING. It was the constant string
        # "icmp+arp" for a sweep that may have probed nothing at all, and
        # nothing reads it — which is exactly why it can carry the truth
        # cheaply: a future reader (and this round's own write-up) can tell a
        # measured run from an ARP-only one out of the record itself.
        method = "icmp+arp" if len(unprobed) < len(hosts) else "arp-only"
        me.record_presence_sweep(
            session_id=sid, method=method, outcome="ok",
            subnet=plan["cidr"], targets=len(hosts),
            duration_ms=duration, responders=responders,
        )

        note = self._probe_note(answered | silent, answered, unprobed,
                                arp_unprobed)
        self._last_sweep = {
            "at": _utc_now(), "cidr": plan["cidr"], "targets": len(hosts),
            "responded": len(responders), "duration_ms": duration,
            "probed": len(answered | silent), "not_probed": len(unprobed),
            "arp_only": sum(1 for r in responders if r["via"] == "arp"),
            "method": method,
        }
        logger.debug(
            f"Presence sweep: {len(responders)} of {len(hosts)} addresses "
            f"answered in {duration} ms"
        )
        if note:
            logger.warning(f"Presence sweep was incomplete: {note}")
        if plan["note"]:
            logger.info(f"Presence sweep range: {plan['note']}")

        try:
            self._report_absent_permanent(sid)
        except Exception as e:
            logger.warning(f"Absence check failed: {e}")
        out = {
            "outcome":     "ok",
            "subnet":      plan["cidr"],
            "method":      method,
            "targets":     len(hosts),
            "responded":   len(responders),
            "duration_ms": duration,
            "probed":      len(answered | silent),
            "not_probed":  len(unprobed),
        }
        if note:
            out["note"] = note
        if plan["note"]:
            out["range_note"] = plan["note"]
        return out

    # ABSENCE OF A DECLARED-PERMANENT DEVICE

    def _report_absent_permanent(self, session_id: str) -> int:
        """
        Raise a finding when a device the USER declared ALWAYS ON stops
        answering. Returns how many were raised.

        THIS IS THE ONE PLACE THE PRESENCE SWEEP IS ALLOWED TO BE LOUD, and
        the licence comes from the declared-expectation rule in memory_engine:
        the user said this device should be answering, so reporting that it is
        not is arithmetic against their own statement rather than Python
        forming an opinion about what a quiet device means.

        v22, 2026-09-01. THIS READ is_permanent UNTIL TODAY, AND THAT WAS THE
        WRONG DECLARATION.

        is_permanent means the device belongs on this network. It was being
        read as "should always be answering", so marking a TV as a member of
        the network silently also signed it up to stay awake, and every quiet
        evening produced a medium finding. The owner put it plainly: those
        devices are off because nobody is using them, which is the ordinary
        case and not an event.

        So availability is its own flag now. A device nobody declared
        always-on is never reported here, however long it has been away, and
        that includes every device the user vouched for as a member.

        Deduped by entity, so a device that stays away produces one finding
        rather than one every fifteen minutes, the failure that made
        linux_monitor's process check a burial tool.
        """
        raised = 0
        presence = me.query_presence(max_sweeps=max(me.RETIRE_AFTER_MISSES, 200))
        window   = presence.get("window") or {}

        # Too few sweeps for a streak to mean anything yet. Reporting absence
        # from two samples would train the user to ignore this on day one.
        if (window.get("sweeps_counted") or 0) < me.ABSENCE_FINDING_AFTER:
            return 0

        by_ip = {d["ip"]: d for d in presence.get("devices", [])}
        held  = 0   # observed and below the bar: counted, not discarded

        # SILENCE HERE MUST BE EXPLAINED, NOT ASSUMED.
        #
        # After v22 nothing is declared always-on until somebody says so, so
        # this check legitimately raises nothing on a fresh upgrade. That is
        # indistinguishable from "everything is present" unless it says which
        # one it is, and the whole project exists to stop absence being read
        # as calm. Logged once per pass, cheaply — and since 2026-09-24 also
        # published by status(), so it is on the readiness row and not only in
        # a log nobody is tailing.
        declared = me.always_on_devices()
        if not declared:
            logger.info(
                "No device is declared always-on, so the absence check has "
                "nothing to compare against and will report nothing. This is "
                "not a statement that every device is present. Declare one "
                "with scripts/set_always_on.py.")
            return 0

        for device in declared:
            row    = by_ip.get(device["ip"])
            streak = (row or {}).get("absent_streak")
            if streak is None:
                streak = window.get("sweeps_counted") or 0
            # TODO 8.4. The threshold is still ABSENCE_FINDING_AFTER; what
            # changed is that the register is now the thing that says so, and
            # a HOLD is visible rather than a silent `continue`.
            verdict = fp.should_raise("presence_absence", streak)
            if verdict["decision"] != fp.RAISE:
                held += 1
                continue
            # Silence on another network is not absence (PRB-4).
            if streak and me.sweeps_not_covering(device["ip"], streak):
                held += 1
                continue

            # A DISMISSAL OF THE ADDRESS SILENCES EVERY RULE ABOUT IT, and
            # for an absence that is a whole class of silence rather than one
            # finding: the user quieting "this device showed up new" also
            # stops "this device has gone". Left as it is, deliberately —
            # closing it means changing what a dismissal MEANS across two
            # rules, which is the owner's call and not this round's. Recorded
            # with its measurement in bugfinder.md (NET-9).
            if me.is_dismissed("ip", device["ip"]):
                continue

            if not self._absence_due(device["ip"]):
                continue

            label = device.get("known_as") or device["ip"]
            me.save_finding(
                session_id=session_id,
                source="network_scanner",
                detection_id="NET-1002",
                severity="medium",
                entity_type="ip",
                entity_value=device["ip"],
                title=f"Always-on device is absent: {label}",
                description=(
                    f"You declared this device should always be answering. "
                    f"It has not answered the last {streak} presence sweeps, "
                    f"out of {window.get('sweeps_counted')} that ran.\n\n"
                    f"Presence sweeps only run while AgentalSec is running, "
                    f"so check first_sweep_at and last_sweep_at before "
                    f"treating this as continuous. A device that is merely "
                    f"switched off looks identical to one that has been "
                    f"removed; what separates them is whether you expected it "
                    f"to be off.\n\n"
                    f"A sweep that could not probe anything does not count "
                    f"here: an address is only missed by a sweep that "
                    f"actually asked.\n\n"
                    f"If it is simply switched off and that is fine, clear "
                    f"its always-on flag; being a permanent member of this "
                    f"network is a separate thing and it keeps that. If it is "
                    f"gone for good, clear its permanent flag too. It will "
                    f"otherwise be retired automatically after "
                    f"{me.RETIRE_AFTER_MISSES} misses."
                ),
                raw_data={"absent_streak": streak,
                          "sweeps_counted": window.get("sweeps_counted"),
                          "last_present_at": (row or {}).get("last_present_at")},
            )
            raised += 1

        if held:
            logger.debug(
                f"{held} declared device(s) are below the absence threshold "
                f"({me.ABSENCE_FINDING_AFTER} misses) and were held rather "
                f"than reported.")
        return raised

    def _absence_due(self, ip: str) -> bool:
        """
        True at most once per cooldown per device.

        In-memory rather than persisted on purpose: a restart is a legitimate
        reason to be told again, because the operator is present and looking
        at the log at exactly that moment.
        """
        import time as _t
        now  = _t.monotonic()
        last = self._absence_emitted.get(ip)
        if last is not None and (now - last) < self.ABSENCE_COOLDOWN_SECONDS:
            return False
        self._absence_emitted[ip] = now
        return True


def _utc_now() -> str:
    """
    UTC, in the same shape the store uses, so two answers to one question
    cannot be hours apart. See the T5 round's rule on the time base.
    """
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
