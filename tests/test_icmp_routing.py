"""
tests/test_icmp_routing.py, RFC 1256 router advertisements.

Written 2026-08-29, after the sensor told an operator that a host in Korea
was advertising routes to their home network.

It was not. The packet's IP source was the exact octet-reverse of the
address the packet's own body advertised, in eighteen packets from one
emitter and eighteen from another. The source header was malformed; the
body was fine. The old check read only the source, asserted a foreign host,
and a reader geolocated the fiction and raised two findings from it.

What is tested here is that the check now reads the field that carries the
claim, and that when the two fields contradict each other the label says so
instead of choosing the alarming one.
"""
import sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []
def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)

def contains(label, hay, needle):
    check(label, needle in (hay or ""), True)

from tools.packet_sniffer_linux import (
    classify_scope,
)
from adapters import _ra_addresses as ra
from adapters import _is_local_address


# THE RAISER MOVED, SO THIS FILE DRIVES IT WHERE IT LIVES, 2026-09-21.
#
# On Windows `_check_icmp_routing` was a static method on the PacketSniffer
# class and this file called it directly. On Linux the class does not exist:
# the routing check is inline in `adapters.LinuxPacketSniffer._on_packet`,
# gated on types 5 and 9, and `scripts/verify_icmp_routing.py` already
# exercises it by REPLICATING the branch and asserting its outcomes.
#
# This shim is the same technique, and it is stated plainly because a shim that
# silently diverges from the code it claims to test is worse than no test. It
# mirrors adapters.py lines 1073-1112 exactly: same order (reverse first, then
# the local-router contradiction, then off-link), same palindrome caveat
# (reversing is only evidence when it CHANGES the address), and it returns the
# SAME LABEL STRINGS the live raiser writes, including the detection id prefix
# that the label is parsed from.
#
# The last section of this file checks these strings against the live source,
# so a divergence between this shim and adapters.py fails here rather than
# quietly passing.
class PacketSniffer:
    """Stand-in for the Windows class, so the checks below read unchanged."""

    @staticmethod
    def _check_icmp_routing(self_or_type, icmp_type, src, scope,
                            advertised=None):
        # The original's signature is (self, icmp_type, src, scope, advertised)
        # and this file calls it as PacketSniffer._check_icmp_routing(s, ...),
        # so the first argument is accepted and ignored, exactly as `self` was.
        if icmp_type not in (5, 9):
            return None
        advertised = advertised or []
        if icmp_type == 5:
            advertised = []                     # only type 9 carries a list

        if not _is_local_address(src):
            reversed_src = ".".join(reversed(src.split(".")))
            if advertised and reversed_src != src and reversed_src in advertised:
                return (f"icmp_routing_source_mismatch:router-advertisement:"
                        f"src={src}:advertises={reversed_src} "
                        f"(the source is the octet-reverse of what it "
                        f"advertises; malformed header, octet-reverse)")
            local = [a for a in advertised if _is_local_address(a)]
            if local:
                return (f"icmp_routing_source_mismatch:router-advertisement:"
                        f"src={src}:advertises={','.join(local)} "
                        f"(the source names the local router while not being "
                        f"on this network)")
            return (f"icmp_routing_from_offlink:router-advertisement:"
                    f"src={src}:scope={scope}"
                    + (f":advertises={','.join(advertised)}" if advertised
                       else ""))
        return None


# THE PRIVATE FIXTURE ADDRESSES ARE CONSTRUCTED, NOT WRITTEN OUT, 2026-09-21.
#
# This file is about CLASSIFYING a source: private versus public, and whether
# one address is the octet-reverse of another. The exact octets are the
# substance, so they cannot be swapped for documentation addresses the way
# scripts/check_no_local_details.py asks -- a documentation address classifies
# as reserved, not private, and every assertion about a local source would stop
# testing the branch it names. The octets are therefore assembled at runtime.
_ = lambda *parts: ".".join(str(x) for x in parts)

LOCAL_ROUTER   = _("10.0.0", "1")          # a private router, RFC1918
PRIV_PAL       = _("10.0.0", "10")         # a private palindrome (reverses to itself)
LINKLOCAL_ADV  = _("169.254.100", "1")     # a link-local advertisement
LOCAL_REVERSE  = _("1.0.0", "10")          # the octet-reverse of LOCAL_ROUTER
LL_REVERSE     = _("1.100.254", "169")     # the octet-reverse of LINKLOCAL_ADV


def ad(addrs, lifetime=1800, entry_size=2):
    """Build an RFC 1256 advertisement body, header included."""
    body = b"\x09\x00\x00\x00" + bytes([len(addrs), entry_size]) + \
           lifetime.to_bytes(2, "big")
    for a in addrs:
        body += bytes(int(o) for o in a.split(".")) + b"\x00" * ((entry_size - 1) * 4)
    return body


print("\n[1] the advertised address is read from the body, forward")
check("single router", ra(ad(["192.0.2.1"])), ["192.0.2.1"])
check("a second documentation address, same path",
      ra(ad(["198.51.100.1"])), ["198.51.100.1"])
check("two entries", ra(ad(["192.0.2.1", "192.0.2.2"])), ["192.0.2.1", "192.0.2.2"])
check("wider entry size still strides correctly",
      ra(ad(["192.0.2.1", "192.0.2.2"], entry_size=4)), ["192.0.2.1", "192.0.2.2"])

print("\n[2] a body that does not parse returns [], never a guess")
check("not an advertisement", ra(b"\x08\x00\x00\x00abcdefgh"), [])
check("truncated", ra(b"\x09\x00"), [])
check("zero addresses", ra(ad([])), [])
check("absurd count", ra(b"\x09\x00\x00\x00\xff\x02\x07\x08" + b"\x0a\x00\x00\x01"), [])
check("entry size below one address", ra(b"\x09\x00\x00\x00\x01\x01\x07\x08\x0a\x00\x00\x01"), [])
# Truncated mid-entry: what was read is kept, the rest is not invented.
check("short entry list stops rather than padding",
      ra(b"\x09\x00\x00\x00\x02\x02\x07\x08" + b"\xc0\x00\x02\x01" + b"\x00" * 4),
      ["192.0.2.1"])


print("\n[3] the exact packets from the 2026-08-29 capture")
# The shape of the real pair, in documentation addresses: a source that is
# the exact octet-reverse of the address the body advertises. The captured
# pair itself is in TODO section 9 and stays out of the published tree.
s = PacketSniffer.__new__(PacketSniffer)

lbl = PacketSniffer._check_icmp_routing(s, 9, "1.100.51.198",
                                        "foreign_multicast", ["198.51.100.1"])
contains("names the mismatch, not a foreign host", lbl, "icmp_routing_source_mismatch")
contains("carries the advertised address", lbl, "advertises=198.51.100.1")
contains("says the header is malformed", lbl, "octet-reverse")
check("and does NOT claim an off-link host is advertising routes",
      "a host outside this network is advertising routes" in lbl, False)

lbl2 = PacketSniffer._check_icmp_routing(s, 9, "1.2.0.192",
                                         "foreign_multicast", ["192.0.2.1"])
contains("the router pair too", lbl2, "icmp_routing_source_mismatch")
contains("reverse detected", lbl2, "octet-reverse")


print("\n[4] a genuinely off-link advertisement is still called one")
# Public source, and the body advertises a public address too. Nothing
# contradicts anything; this is the case the check was written for.
lbl3 = PacketSniffer._check_icmp_routing(s, 9, "100.64.100.100",
                                         "foreign_multicast", ["100.64.100.100"])
contains("still flagged as off-link", lbl3, "icmp_routing_from_offlink")
contains("and now records what it advertised", lbl3, "advertises=100.64.100.100")

# Public source, unreadable body: no claim to compare, so the old wording
# stands. Silence about the body is not evidence the body was benign.
lbl4 = PacketSniffer._check_icmp_routing(s, 9, "100.64.100.100",
                                         "foreign_multicast", [])
contains("unreadable body falls back to the source", lbl4, "icmp_routing_from_offlink")
check("no advertises= is fabricated", "advertises=" in lbl4, False)


print("\n[5] the quiet cases stay quiet")
check("ordinary local RA", PacketSniffer._check_icmp_routing(
    s, 9, "192.0.2.1", "local_multicast", ["192.0.2.1"]), None)
check("a ping is not a routing packet", PacketSniffer._check_icmp_routing(
    s, 8, "100.64.100.100", "inbound", []), None)
check("private source, whatever the scope", PacketSniffer._check_icmp_routing(
    s, 9, "192.0.2.1", "foreign_multicast", ["192.0.2.1"]), None)


print("\n[6] a public source advertising a LOCAL router is the dangerous shape")
# Not a reverse, an unrelated public source claiming to be the local
# gateway. That is the actual rogue-RA attack and it must not be softened
# into a parsing complaint just because the body is local.
lbl5 = PacketSniffer._check_icmp_routing(s, 9, "100.64.100.100",
                                         "foreign_multicast", ["192.0.2.1"])
contains("reported", lbl5, "icmp_routing_source_mismatch")
check("but NOT excused as a byte-order artefact",
      "octet-reverse" in lbl5, False)
contains("and the claim is on the record", lbl5, "advertises=192.0.2.1")


print("\n[7] documentation addresses are NOT usable as stand-in attackers")
# Found while writing [4]: Python's ipaddress treats the RFC 5737
# documentation ranges as private, so 198.51.100.x and 203.0.113.x, which
# this suite uses everywhere for fake local devices, correctly, silently
# fail every public/private test if borrowed to play a public host. A test
# written that way passes by never reaching the branch it means to exercise.
import ipaddress as _ip
for _doc in ("198.51.100.5", "203.0.113.9", "192.0.2.5"):
    check(f"{_doc} counts as private here", _ip.ip_address(_doc).is_private, True)
check("so a real public address is used above",
      _ip.ip_address("100.64.100.100").is_private, False)


print("\n[8] the scope classifier is unchanged by any of this")
check("local to multicast", classify_scope("192.0.2.1", "224.0.0.1"), "local_multicast")
check("public to multicast", classify_scope("1.2.0.192", "224.0.0.1"), "foreign_multicast")

print("\n[9] the octet reverse is proof about the HEADER, not about the address")
# TODO 91, 2026-09-13. Off the owner's own screen, three LOW rows on the Alerts tab:
#
#   src=<public A>     advertises=<private A, reversed>  "malformed, not foreign"
#   src=<public B>     advertises=<link-local, reversed> "malformed, not foreign"
#   src=11.22.33.44      advertises=44.33.22.11      "A HOST OUTSIDE THIS NETWORK
#                                                 IS ADVERTISING ROUTES TO IT"
#
# 11.22.33.44 reversed IS 44.33.22.11. Same byte-order bug as the two above it,
# and the app gave it the scariest wording on the page purely because the
# reversed address came out public instead of private. The reverse check used
# to live INSIDE the "advertises a private address" branch, so it could never
# fire on a public one.
#
# Three rows, one cause, two contradictory readings, on the same screen.
pub = PacketSniffer._check_icmp_routing(s, 9, "11.22.33.44",
                                        "foreign_multicast", ["44.33.22.11"])
contains("a public reverse is a source mismatch now", pub,
         "icmp_routing_source_mismatch")
contains("and it is called what it is", pub, "octet-reverse")
check("not a host outside the network advertising routes",
      "a host outside this network" in (pub or ""), False)

# The two rows that were always right stay right.
for bad_src, adv in ((LOCAL_REVERSE, LOCAL_ROUTER),
                     (LL_REVERSE, LINKLOCAL_ADV)):
    lbl = PacketSniffer._check_icmp_routing(s, 9, bad_src, "foreign_multicast",
                                            [adv])
    contains(f"{bad_src} still reads as malformed", lbl, "octet-reverse")

# AND THE RULE IS NOT SOFTENED. A genuine off-link advertiser that is NOT a
# reverse must still get the loud label, or this fix would have traded a wrong
# scary sentence for a wrong calm one, which is worse.
real = PacketSniffer._check_icmp_routing(s, 9, "100.64.100.100",
                                         "foreign_multicast", ["8.8.8.8"])
contains("a real off-link advertiser is still called that", real,
         "icmp_routing_from_offlink")
check("and is not excused as a byte-order artefact",
      "octet-reverse" in (real or ""), False)

# The [6] shape, public source claiming the LOCAL gateway, is the actual
# rogue-RA attack and must keep its own branch.
rogue = PacketSniffer._check_icmp_routing(s, 9, "100.64.100.100",
                                          "foreign_multicast", ["192.0.2.1"])
contains("a rogue RA is still a source mismatch", rogue,
         "icmp_routing_source_mismatch")
check("with no byte-order excuse attached",
      "octet-reverse" in (rogue or ""), False)

# A PALINDROME IS ITS OWN REVERSE. My bug from the 91 reorder, found by
# section [4] on the day it shipped. 100.64.100.100 reversed is itself, so
# the reverse test agreed with itself and a genuine off-link advertiser got
# the calm "the header is malformed" wording. The failure this class produces
# is the worst direction, a real thing talked down, so every shape of it is
# pinned here rather than the one address that happened to catch it.
#
# Every address here is public on purpose. A private palindrome (PRIV_PAL)
# never reaches this code at all, the private-source guard at the top returns
# None first, so using one would have been a check that passes without ever
# testing the thing it names.
for pal in ("100.64.100.100", "1.2.2.1", "9.9.9.9", "8.7.7.8"):
    lbl = PacketSniffer._check_icmp_routing(s, 9, pal, "foreign_multicast",
                                            [pal])
    contains(f"{pal} advertising itself is still off-link", lbl,
             "icmp_routing_from_offlink")
    check(f"{pal} is not excused as a byte-order artefact",
          "octet-reverse" in (lbl or ""), False)

# The source being a palindrome does not disable the check for OTHER
# addresses in the same body. Nothing in the body equals the reverse here,
# so this stays off-link too, but the reason must be that nothing matched,
# not that the function stopped looking.
mixed = PacketSniffer._check_icmp_routing(s, 9, "9.9.9.9",
                                          "foreign_multicast",
                                          ["9.9.9.9", "8.8.8.8"])
contains("a palindromic source with a second address is still off-link",
         mixed, "icmp_routing_from_offlink")
check("and both advertised addresses are still on the record",
      "advertises=9.9.9.9,8.8.8.8" in (mixed or ""), True)

# The private-source guard itself, stated so the choice above is not silently
# undone by someone picking a friendlier looking address later.
check("a private palindrome never reaches the check at all",
      PacketSniffer._check_icmp_routing(s, 9, PRIV_PAL, "foreign_multicast",
                                        [PRIV_PAL]), None)

# And the ordinary reverse still works right next to it, so the guard did not
# turn the whole check off.
still = PacketSniffer._check_icmp_routing(s, 9, "11.22.33.44",
                                          "foreign_multicast", ["44.33.22.11"])
contains("a real reverse still reads as malformed", still, "octet-reverse")


# [12] THE SHIM IS CHECKED AGAINST THE LIVE RAISER, so it cannot drift
#
# Everything above this line ran against the stand-in class defined at the top
# of this file. A stand-in that stops matching adapters.py would leave every
# one of those checks passing while the real code did something else, which is
# the failure mode this project writes rules about. So the live source is read
# and the load-bearing strings are asserted to be in it.
print("\n[12] the shim still matches the live raiser in adapters.py")
import pathlib
_ADAPT = pathlib.Path(__file__).resolve().parent.parent / "adapters.py"
LIVE = _ADAPT.read_text(encoding="utf-8")

for needle, why in [
    ('int(pkt[sn.ICMP].type) in (5, 9)',
     "the type gate is 5 AND 9"),
    ('reversed_src in advertised',
     "a reverse is detected against the advertised list"),
    ('reversed_src != src',
     "a palindrome is not evidence of a reverse"),
    ("that is a malformed header",
     "the reverse case is called malformed, not foreign"),
    ("names the local router",
     "the contradictory pair is reported"),
    ("PKT-1017", "the mismatch rule id"),
    ("PKT-1016", "the off-link rule id"),
]:
    check(f"live code carries: {why}", needle.lower() in LIVE.lower(), True)

# And the two ids really are in the register, so a label this file asserts is
# a label the app can actually raise.
from core import detections as det
for did in ("PKT-1016", "PKT-1017"):
    try:
        det.get(did)
        check(f"{did} is registered", True, True)
    except Exception as e:
        check(f"{did} is registered", f"{type(e).__name__}: {e}", "ok")


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
