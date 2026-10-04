"""
tests/test_capture_interface.py, the packet sniffer captured on loopback.

FOUND 2026-09-22 by reading the database rather than the dashboard.

The threat map drew nothing, and the reason written down was "GeoIP is not
loaded". It is loaded: core/geoip.init_geoip returned ready at 02:29:27 that
morning and live lookups resolve (8.8.8.8 -> Mountain View, 1.1.1.1 ->
Sydney). The real reason is one line earlier in the same boot log:

    [tools.packet_sniffer_linux] INFO: Starting packet capture on lo

and that line is in ALL 31 capture starts the logs hold. The consequence is
not "no rows". It is 153,816 rows, every one of them scope 'internal'
(142,735 loopback + 11,051 private_to_private + 30 local_multicast), with
NOT ONE routable address in the entire table. api/routes.threatmap builds
its endpoints from query_endpoint_pairs and then drops every pair where
neither side is routable, so it had nothing to place on the globe. Empty
map, zero errors, sensor reporting [OK] -- because the sensor WAS running.

THE DEFECT. start_sniffer() picked an interface only when the caller passed
none, and then:

    for iface in interfaces:
        if iface["name"].startswith("eth") or iface["name"].startswith("en"):
            interface = iface["name"]; break
    if not interface and interfaces:
        interface = interfaces[0]["name"]

This workstation's NIC is `wlp1s0` (WiFi, predictable naming), so the first
pass matches nothing. scapy's get_if_list() returns ['lo', 'wlp1s0',
'docker0'], so `interfaces[0]` is the loopback device. `en` was meant to
catch enp/ens/eno and does; `wl` was never in the list at all.

Loopback is not a network vantage. A host's own traffic to its own addresses
never leaves the machine, so nothing on it can ever be geolocated, and the
one sensor whose whole job is "who does this host talk to" was watching the
host talk to itself.

The failure cases run FIRST, per the rule of 2026-09-13. Section [1] is the
live machine; the rest are deterministic and inject their own interface
lists so they do not depend on this host's hardware.

Run it directly: python tests/test_capture_interface.py
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from tools import packet_sniffer_linux as sn          # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def iface(name, ip="198.51.100.5", up=True, loopback=None, virtual=None):
    """
    One entry in the shape get_available_interfaces() hands to the chooser.

    loopback and virtual default to being derived from the name the same way
    the module derives them, so a fixture cannot disagree with the code about
    what `lo` is.
    """
    if loopback is None:
        loopback = sn.is_loopback_interface(name)
    if virtual is None:
        virtual = sn.is_virtual_interface(name)
    return {"name": name, "ip": ip, "mac": "00:11:22:33:44:55",
            "up": up, "loopback": loopback, "virtual": virtual}


print("\n[1] THE DEFECT: this host's own interface list must never yield lo")
# This is the exact list scapy reports on the workstation, in the exact order.
# Under the old code the answer here was 'lo'.
live = sn.get_available_interfaces()
print(f"      scapy reports: {[i['name'] for i in live]}")
chosen, reason = sn.select_capture_interface(interfaces=live)
check("the auto-detected interface is not loopback", chosen == "lo", False)
check("and it is a real, non-empty choice", bool(chosen), True)
check("and the reason travels with it rather than being implied",
      isinstance(reason, str) and bool(reason.strip()), True)

# The specific defect, asserted directly: lo is first in the list, and being
# first is what selected it.
host_shape = [iface("lo", "127.0.0.1"), iface("wlp1s0", "198.51.100.207"),
              iface("docker0", "203.0.113.1")]
chosen, reason = sn.select_capture_interface(interfaces=host_shape)
check("a WiFi-only laptop with lo listed first picks the WiFi NIC",
      chosen, "wlp1s0")
check("docker0 is not chosen over the real NIC", chosen == "docker0", False)


print("\n[2] the default route decides when several real interfaces exist")
# A machine with both a docked Ethernet and WiFi: the kernel's own table says
# which one actually carries traffic, and that is a better answer than
# whichever name sorts first.
both = [iface("lo", "127.0.0.1"), iface("eth0", "192.0.2.50"),
        iface("wlp1s0", "198.51.100.207")]
chosen, reason = sn.select_capture_interface(interfaces=both,
                                             default_iface="wlp1s0")
check("the default-route interface wins", chosen, "wlp1s0")
chosen, _ = sn.select_capture_interface(interfaces=both,
                                        default_iface="eth0")
check("and swapping the route swaps the choice", chosen, "eth0")


print("\n[3] an explicitly configured interface is honoured")
chosen, reason = sn.select_capture_interface(
    configured="wlp1s0", interfaces=both, default_iface="eth0")
check("config outranks the route", chosen, "wlp1s0")
check("and the reason says it came from config", "config" in reason.lower(), True)

# Explicit means explicit. An operator who names lo gets lo, because the one
# thing worse than an odd instruction is an instruction quietly ignored.
chosen, reason = sn.select_capture_interface(
    configured="lo", interfaces=both, default_iface="eth0")
check("naming lo on purpose is not second-guessed", chosen, "lo")

# A config that names an interface this machine does not have. Silently
# capturing a DIFFERENT one would put a run's packets under a heading the
# operator did not ask for; capturing none and saying why is the honest half.
chosen, reason = sn.select_capture_interface(
    configured="eth0", interfaces=[iface("lo", "127.0.0.1"),
                                   iface("wlp1s0", "198.51.100.207")])
check("a configured interface that does not exist starts no capture",
      chosen, None)
check("and the reason names the interface it could not find",
      "eth0" in reason, True)


print("\n[4] when there is nothing real to capture, it says so")
# Rule two: "no match" and "I could not search" are different sentences. A
# loopback-only machine must produce the second one, not a running sniffer
# that stores its own chatter.
chosen, reason = sn.select_capture_interface(interfaces=[iface("lo", "127.0.0.1")])
check("a loopback-only interface list chooses nothing", chosen, None)
check("and the reason explains what was refused",
      "loopback" in reason.lower(), True)

chosen, reason = sn.select_capture_interface(interfaces=[])
check("an empty interface list chooses nothing", chosen, None)
check("and says so", bool(reason.strip()), True)

# A down interface is not a vantage either. docker0 sits `down` on this
# workstation and is not chosen.
chosen, reason = sn.select_capture_interface(
    interfaces=[iface("lo", "127.0.0.1"), iface("docker0", "203.0.113.1", up=False)])
check("a down container bridge is not chosen", chosen, None)


print("\n[5] virtual interfaces lose to real ones but are better than nothing")
# The precedence has to be total, or a machine whose only uplink is a VPN
# tunnel reports "no interface" while holding a perfectly usable one.
virt = [iface("lo", "127.0.0.1"), iface("tailscale0", "100.64.0.1")]
chosen, reason = sn.select_capture_interface(interfaces=virt)
check("a tunnel interface is chosen when it is all there is", chosen,
      "tailscale0")

mixed = [iface("lo", "127.0.0.1"), iface("docker0", "203.0.113.1"),
         iface("wlp1s0", "198.51.100.207")]
chosen, _ = sn.select_capture_interface(interfaces=mixed)
check("but a real NIC still outranks it", chosen, "wlp1s0")


print("\n[6] the naming rules follow the kernel's, not a guess")
check("lo is loopback", sn.is_loopback_interface("lo"), True)
check("lo:1 is loopback", sn.is_loopback_interface("lo:1"), True)
check("wlp1s0 is not loopback", sn.is_loopback_interface("wlp1s0"), False)
check("docker0 is virtual", sn.is_virtual_interface("docker0"), True)
check("veth9a1b is virtual", sn.is_virtual_interface("veth9a1b"), True)
check("wlp1s0 is not virtual", sn.is_virtual_interface("wlp1s0"), False)


print("\n[7] the caller that starts capture passes the config through")
# The adapter called sn.start_sniffer() with NO arguments, so even a config
# that named an interface was never read. sensors.packet_sniffer.interface is
# null in the shipped config, which is why nobody noticed.
#
# UPDATED 2026-09-23. The fake thread below runs the capture body inline, and
# the body now ends in a `finally` that clears the module's liveness flag
# (SNF-6/SNF-15: a dead capture used to keep reporting its interface). So an
# inline run returns WITH the flag down, which is correct behaviour and makes
# `capture_interface()` None here -- the point of this section is still what
# was passed to sniff(), and that is what it asserts.
started_with = {}
_alive_seen = {}


def _fake_sniff(**kwargs):
    started_with.update(kwargs)
    # Observed from inside the capture body, which is the only place the flag
    # is up: this is what a status poll DURING a live capture would see.
    _alive_seen["alive"] = sn._capture_alive
    _alive_seen["interface"] = sn.capture_interface()


class _FakeThread:
    """
    A thread that runs its target synchronously instead of spawning.

    The real capture thread is a daemon that calls sniff() and blocks forever;
    a test cannot wait on that. Running the body inline is what lets the
    assertions below see the arguments sniff() was actually called with --
    which is the whole point of this section, since the defect was that the
    adapter passed the WRONG interface (or none at all) rather than none.
    """

    def __init__(self, target=None, daemon=None, **kwargs):
        self._target = target

    def start(self):
        if self._target is not None:
            self._target()


_orig_sniff, _orig_thread = sn.sniff, sn.threading.Thread
_orig_cap = sn.check_capture_capability
_orig_open = sn._open_capture_socket


def _no_own_socket(*a, **k):
    raise PermissionError("no raw socket in this test")


sn.sniff = _fake_sniff
sn.threading.Thread = _FakeThread
sn.check_capture_capability = lambda: (True, "Running as root")
# The checks below cover the fallback path, where scapy opens the socket.
sn._open_capture_socket = _no_own_socket
try:
    ok = sn.start_sniffer(interface="wlp1s0")
    check("start_sniffer returns True when a real interface is chosen", ok, True)
    check("and sniffs the interface it was given",
          started_with.get("iface"), "wlp1s0")
    check("and the chosen interface is reported WHILE the capture runs",
          _alive_seen.get("interface"), "wlp1s0")
    check("with the module's own liveness flag up",
          _alive_seen.get("alive"), True)
    # ...and down once the body has returned, which is the fix: the old module
    # reported the interface as being read forever.
    check("and once the capture body returns, it stops claiming the interface",
          sn.capture_interface(), None)
    check("with a reason that says it STARTED and STOPPED, not that none ran",
          "no longer running" in sn.capture_interface_reason(), True)

    started_with.clear()
    ok = sn.start_sniffer()
    check("the no-argument call still refuses loopback",
          started_with.get("iface") == "lo", False)
    check("and reports which interface it settled on",
          started_with.get("iface"), "wlp1s0")
    check("and passes NO filter when none was configured",
          "filter" in started_with, False)
    check("and promiscuous is OFF unless asked for",
          started_with.get("promisc"), False)

    started_with.clear()
    ok = sn.start_sniffer(interface="eth-not-here")
    check("a configured interface that is absent starts nothing", ok, False)
    check("and does not sniff anything at all", started_with, {})

    # SNF-7/SNF-8: the two settings that used to be inherited rather than
    # chosen. Both are passed through when given.
    started_with.clear()
    ok = sn.start_sniffer(interface="wlp1s0", filter_str="not port 22",
                          promisc=True)
    check("a configured BPF filter reaches sniff()",
          started_with.get("filter"), "not port 22")
    check("and a configured promiscuous setting reaches sniff()",
          started_with.get("promisc"), True)

    # SNF-19: with our own socket, sniff() must NOT also get iface, or scapy
    # opens a second socket and every frame is captured twice.
    _opened = {}

    class _FakeSock:
        def close(self):
            pass

    def _fake_open(iface, rcvbuf, promisc, filter_str=None):
        _opened.update(iface=iface, rcvbuf=rcvbuf, promisc=promisc,
                       filter=filter_str)
        return _FakeSock()

    sn._open_capture_socket = _fake_open
    started_with.clear()
    ok = sn.start_sniffer(interface="wlp1s0", filter_str="not port 22",
                          promisc=True, rcvbuf=4194304)
    check("the own socket is opened on the chosen interface with the filter",
          (_opened.get("iface"), _opened.get("filter"), _opened.get("promisc")),
          ("wlp1s0", "not port 22", True))
    check("and sniff() reads that socket", "opened_socket" in started_with, True)
    check("and is NOT also given an interface to open a second socket on",
          "iface" in started_with, False)
    check("and a stop_filter is passed so a stop takes effect",
          callable(started_with.get("stop_filter")), True)
finally:
    sn._open_capture_socket = _orig_open
    sn.sniff = _orig_sniff
    sn.threading.Thread = _orig_thread
    sn.check_capture_capability = _orig_cap


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
