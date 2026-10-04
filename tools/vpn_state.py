# tools/vpn_state.py
# AgentalSec V2, is a VPN tunnel up on this host, and how do we know.
#
# REPLACES tools/vpn_manager.py, 2026-09-03. TODO 8.3, which had been parked
# since 2026-08-28 waiting for exactly this conversation.
#
# WHY THE CONTROLS ARE GONE
#
# The old module could connect and disconnect WireGuard, and both were model
# operable through the permission gate. Four reasons that is gone:
#
#   1. A VPN on this host tunnels this host's traffic, so the sensor that
#      watches this host stops seeing what it was put there to see. The
#      single action that most reduces this tool's visibility was a button
#      the tool could press.
#
#   2. Blinding is the threat model. Connecting a tunnel changes what every
#      sensor sees at once, and it does it through a control we added
#      ourselves. Gated is better than ungated, absent is better than gated.
#      Same argument as the local-mode manifest: a tool that does not exist
#      cannot be argued for by text arriving in a packet payload.
#
#   3. It cost a config file holding a tunnel private key, sitting in the
#      project root. That key was already in a screenshot once. Deleting the
#      feature deletes the whole category of mistake.
#
#   4. It was 2 KB wrapping an external executable. There was no depth to
#      lose.
#
# Sensors report on the machine as they find it. They do not reconfigure it.
# If you want the tunnel up, run WireGuard yourself, the way you would any
# other program on your own computer.
#
# WHY THE STATE STAYED, AND WHY IT HAD TO BE REWRITTEN TO STAY
#
# packet_sniffer._flush stamps every packet batch with vpn_state, and that is
# worth keeping. A packet captured while a tunnel was up is a different fact
# from one captured while it was down, and the model should be able to tell
# them apart.
#
# But the old state was not a measurement. VPNManager._state was a variable
# we set when WE called connect or disconnect, and nothing else ever touched
# it. So:
#
#   * you start WireGuard yourself      -> we said disconnected
#   * you restart AgentalSec mid-tunnel -> we said disconnected
#   * the tunnel drops on its own       -> we said connected
#
# and every packet row got stamped with that, looking exactly as measured as
# the packet's own source address. That is the assumed-versus-measured
# failure this project keeps finding in other people's tools, sitting in ours.
# It is also the most likely explanation for the 8.3 symptom where the
# dashboard and the status pill disagreed.
#
# So this asks the operating system instead. An interface either exists and
# is up, or it does not. No memory, no bookkeeping, nothing to drift.
#
# WHAT IT CAN AND CANNOT TELL YOU
#
#   CAN     a tunnel interface is present and up, and which one
#   CANNOT  whether YOUR traffic is going through it. Routing decides that,
#           and a split-tunnel setup can have the interface up while most
#           traffic still goes out the normal way. "up" is the honest word
#           and the one used here.
#   CANNOT  see a VPN that is not a tunnel at all. That is the one people
#           get caught by, so it gets its own paragraph.
#
# THE PROXY BLIND SPOT. ADDED 2026-09-05, TODO 48.2.
#
# Plenty of things sold as a VPN never create an interface. Opera's built-in
# VPN is the example that caused this entry: it is a proxy inside the
# browser, so that browser's traffic leaves the machine somewhere else
# entirely while the interface list looks exactly like a machine with no VPN
# on it. Browser extensions, system HTTP and SOCKS proxies, and some
# commercial apps behave the same way.
#
# So "disconnected" here means ONE thing: no tunnel interface is up. It does
# NOT mean no VPN is in use. Reading it as "no VPN here" is a wrong answer
# produced by a correct measurement, which is the worst kind, and it already
# happened once in a real transcript.
#
# The notes say so now and status() carries a blind_to list, because a limit
# that only lives in a comment is read by whoever wrote it and nobody else.
# Anything that renders this state is expected to carry the words somewhere,
# not just the colour.
#
# Needs no elevation. Listing interfaces is something any process can do,
# which is why core/privilege_linux.py moved this module from NEEDS to NONE.

import logging
import os
import re

from core.voice import for_you

logger = logging.getLogger(__name__)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not available, VPN state cannot be read")


# Interface names that mean "a tunnel". Matched case-insensitively against
# the whole name, not as substrings of arbitrary words, because "tun" inside
# some vendor's adapter name is not a tunnel.
#
# Windows names its adapters things like "wg0" or "WireGuard Tunnel", macOS
# and Linux use wg0 / tun0 / utun3. This list is patterns rather than exact
# names on purpose: AgentalSec is meant to run on machines it has never seen,
# so an adapter naming scheme we did not think of has to be addable in
# config.json rather than in code.
DEFAULT_PATTERNS = [
    r"^wg\d*$",              # wg0, wg1, wireguard's usual
    r"^tun\d*$",             # OpenVPN, generic tun
    r"^utun\d*$",            # macOS
    r"^tap\d*$",             # OpenVPN in tap mode
    r"wireguard",            # "WireGuard Tunnel", Windows
    r"openvpn",
    r"\bvpn\b",
    r"wintun",
]


SYS_NET = "/sys/class/net"
ARPHRD_NONE = 65534


def kernel_tunnel_kind(name: str) -> str | None:
    """
    What the kernel says this interface is, when that is a tunnel.

    'wireguard' from the device type in uevent, 'tun' or 'tap' when the tun
    driver's tun_flags file exists, 'ipsec' for an xfrm/vti device, and
    'point-to-point' for any other device of type ARPHRD_NONE (65534), which
    is what a layer-3 tunnel reports. None when it is not a tunnel or cannot
    be read. Linux only; elsewhere the paths do not exist.
    """
    base = os.path.join(SYS_NET, name)
    try:
        with open(os.path.join(base, "uevent"), encoding="utf-8") as f:
            uevent = f.read()
    except OSError:
        uevent = ""
    for kind in ("wireguard", "xfrm", "vti", "ipip", "gre"):
        if f"DEVTYPE={kind}" in uevent:
            return "ipsec" if kind in ("xfrm", "vti") else kind
    try:
        with open(os.path.join(base, "tun_flags"), encoding="utf-8") as f:
            flags = int(f.read().strip(), 16)
        return "tap" if flags & 0x0002 else "tun"
    except (OSError, ValueError):
        pass
    try:
        with open(os.path.join(base, "type"), encoding="utf-8") as f:
            if int(f.read().strip()) == ARPHRD_NONE:
                return "point-to-point"
    except (OSError, ValueError):
        pass
    return None


class VPNState:
    """
    Read-only. There is no connect() and no disconnect(), on purpose.
    See the header.
    """

    def __init__(self, extra_patterns=None):
        patterns = list(DEFAULT_PATTERNS) + list(extra_patterns or [])
        self._patterns = []
        for p in patterns:
            try:
                self._patterns.append(re.compile(p, re.I))
            except re.error as e:
                # A bad pattern in config must not take the module down. Say
                # which one and carry on with the rest.
                logger.warning(f"vpn.interface_patterns: skipping {p!r} ({e})")
        # WHY THIS ATTRIBUTE EXISTS. Reading the interface list can FAIL —
        # psutil raises, or the platform refuses — and until 2026-09-27 the
        # failure was indistinguishable from a machine with no tunnel on it.
        # See _read_interfaces and status().
        self.reading_error = None

    def start(self):
        logger.info("VPN state reader ready (read-only, no VPN control).")

    def _read_interfaces(self):
        """
        The interface table, or None with self.reading_error set.

        THE WHOLE POINT OF THE PAIR. `psutil.net_if_stats()` raising used to
        be swallowed by a `return found` inside _tunnels, so a refusal to
        read produced an EMPTY TUNNEL LIST, and an empty tunnel list is what
        status() turns into "disconnected, measured: true". That is this
        module's own headline limit stated in reverse: the header says a
        correct measurement read as "no VPN here" is the worst kind of wrong
        answer, and a FAILED read was producing exactly that, with the
        reassuring word `measured` on it.

        MEASURED 2026-09-27, driving the shipped reader against a stubbed
        refusal: state='disconnected', measured=True, interfaces=[], note
        'No tunnel interface is up. Read from the interface list just now'.
        Nothing in that answer was true.
        """
        self.reading_error = None
        try:
            return psutil.net_if_stats()
        except Exception as e:
            self.reading_error = f"{type(e).__name__}: {e}"
            logger.warning(f"net_if_stats refused, so the tunnel state could "
                           f"not be read: {self.reading_error}")
            return None

    def _tunnels(self, stats) -> list[dict]:
        """Every interface that looks like a tunnel, with whether it is up.

        A name match OR the kernel's own word for it: clients such as
        nordlynx, proton0 or tailscale0 match no name pattern (RVP-18).
        """
        if not stats:
            return []
        out = []
        for name, st in stats.items():
            by_name = any(p.search(name) for p in self._patterns)
            kernel = kernel_tunnel_kind(name)
            if by_name or kernel:
                out.append({"interface": name, "up": bool(st.isup),
                            "seen_by": "name" if by_name else "kernel",
                            **({"kernel_kind": kernel} if kernel else {})})
        return out

    # What this reader cannot see, in the words it should be repeated in.
    # One string, so the note, the dashboard and anything else quoting it
    # cannot end up describing the limit three slightly different ways.
    #
    # TODO 113.1, 2026-09-18. This is a FIELD FOR THE MODEL, and it used to
    # arrive sounding like a sentence to read out, so it got read out, on
    # every VPN answer including the ones where it changed nothing. It says
    # so itself now. The fact is unchanged.
    BLIND_TO = for_you(
        "This reader sees tunnel interfaces. A VPN that works as a proxy "
        "rather than a tunnel, Opera's built-in one, a browser extension, or "
        "a system HTTP or SOCKS proxy, never creates an interface and is "
        "invisible here whatever this says. Say it only when the answer would "
        "otherwise be read as 'no VPN is in use'."
    )

    # The one short line that IS for the operator, used where 'disconnected'
    # would otherwise be read as 'no VPN'. Scope, not apology.
    SCOPE_LINE = (
        "Measured on this host's interfaces, which a proxy style VPN does not "
        "create."
    )

    def status(self) -> dict:
        """
        {state, interfaces, measured, blind_to, note}

        state is one of:
          connected      a tunnel interface exists and is up
          disconnected   NO TUNNEL INTERFACE IS UP. Not the same claim as
                         "no VPN is in use", see blind_to and the header.
          unknown        we could not look. NOT the same as disconnected,
                         and never reported as it. A tool that cannot see
                         must say so rather than answer 'no'.

        blind_to is on every answer, including the connected one, because
        the limit does not depend on the result.
        """
        if not PSUTIL_AVAILABLE:
            return {
                "state":      "unknown",
                "interfaces": [],
                "measured":   False,
                "blind_to":   self.BLIND_TO,
                "note": ("psutil is not installed, so the interface list "
                         "could not be read. This is not the same as no "
                         "tunnel being up."),
            }

        stats = self._read_interfaces()
        if stats is None:
            # THE SECOND DOOR INTO 'unknown', ADDED 2026-09-27.
            #
            # The missing-psutil branch above was the only way this module
            # could ever answer 'unknown', and it is the branch that cannot
            # occur on a machine where the module was imported at all (the
            # import above sets PSUTIL_AVAILABLE). So in practice 'unknown'
            # was UNREACHABLE, and every refusal to read the interface list
            # was published as 'disconnected' with measured=True. Measured
            # against a stubbed refusal: the reader answered disconnected
            # about a list it never saw. 'unknown' is not a no, and this is
            # the branch that keeps them apart.
            return {
                "state":      "unknown",
                "interfaces": [],
                "measured":   False,
                "blind_to":   self.BLIND_TO,
                "note": (f"The interface list could not be read "
                         f"({self.reading_error}), so whether a tunnel "
                         f"interface is up is not known. This is the same "
                         f"answer as a missing psutil and is NOT the same as "
                         f"no tunnel being up."),
            }

        tunnels = self._tunnels(stats)
        up = [t for t in tunnels if t["up"]]

        if up:
            names = ", ".join(t["interface"] for t in up)
            return {
                "state":      "connected",
                "interfaces": tunnels,
                "measured":   True,
                "blind_to":   self.BLIND_TO,
                "note": (f"Tunnel interface up: {names}. This says the "
                         f"interface is up, NOT that your traffic is going "
                         f"through it, routing decides that, and a split "
                         f"tunnel can have both be true at once."),
            }

        return {
            "state":      "disconnected",
            "interfaces": tunnels,
            "measured":   True,
            "blind_to":   self.BLIND_TO,
            # The wording is deliberate. "No tunnel interface is up" is what
            # was measured. "No VPN" is a different and unsupported claim,
            # and it was made once already off this exact reading.
            "note": ("No tunnel interface is up. Read from the interface "
                     "list just now, not remembered from earlier."
                     + (f" Present but down: "
                        f"{', '.join(t['interface'] for t in tunnels)}."
                        if tunnels else "")
                     + " " + self.SCOPE_LINE),
        }
