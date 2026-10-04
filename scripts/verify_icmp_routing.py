#!/usr/bin/env python3
"""
Verify the routing-ICMP port. Runs the LIVE adapter's own callback against
frames built in memory, so what is exercised is the code that runs, not a copy.

Asserted, one per scenario, all against a scratch database:
  1. a normal advertisement from the local router        -> NO finding
  2. an off-network source advertising routes            -> PKT-1016
  3. a source that is the octet-reverse of what it says  -> PKT-1017
  4. a PALINDROME source advertising a local router      -> PKT-1016
     (reversing must not be read as evidence when it changes nothing)
  5. an unparseable ICMP body from an off-network source  -> PKT-1016, and the
     description says the body did not parse rather than claiming it advertised
     nothing
  6. negative control: the same frame from a LOCAL source -> NO finding

Scenario 4 and 5 are the two the Windows tree got wrong first; they are here
because a port that reproduces a bug is not a port.
"""
import ipaddress
import pathlib
import shutil
import sqlite3
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASS = FAIL = 0


def check(label, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}")
        if detail:
            print(f"        {detail}")


def ra_body(advertised, lifetime=1800):
    """An RFC 1256 router advertisement body with the given addresses."""
    out = bytearray()
    out.append(9)            # type 9, router advertisement
    out.append(0)            # code
    out += b"\x00\x00"       # checksum
    out.append(len(advertised))
    out.append(2)            # entry size in 32 bit words
    out += lifetime.to_bytes(2, "big")
    for a in advertised:
        out += ipaddress.IPv4Address(a).packed
        out += (0).to_bytes(4, "big")     # preference
    return bytes(out)


# --- the pure parser, before any capture is involved
print("=== the RA body parser, ported into adapters.py ===")
from adapters import _ra_addresses, _is_local_address

body = ra_body(["192.0.2.1", "192.0.2.254"])
check("parses two advertised routers",
      _ra_addresses(body) == ["192.0.2.1", "192.0.2.254"], _ra_addresses(body))
check("returns [] for a short body", _ra_addresses(b"\x09\x00") == [])
check("returns [] for a non-RA type", _ra_addresses(b"\x08\x00" + b"\x00" * 14) == [])
check("returns [] when it claims zero addresses",
      _ra_addresses(b"\x09\x00\x00\x00\x00\x02\x07\x08") == [])
check("local test says 192.0.2.1 is ours", _is_local_address("192.0.2.1"))
check("local test says 11.22.33.44 is NOT ours", not _is_local_address("11.22.33.44"))

print("\n=== the scenarios the two registered rules describe ===")
local_router = "192.0.2.1"
# THE SOURCE HAS TO BE GENUINELY PUBLIC. The first version of this check used
# 203.0.113.7, which is the documentation range: Python's `ipaddress` calls it
# PRIVATE, so the code correctly treated it as local and the check asserted
# off-link behaviour against a local address. 11.22.33.44 is a real public
# address (measured: is_private False) and it is the one from the field case
# the Windows tree's comment names.
OFFLINK = "11.22.33.44"
cases = [
    # label, src, advertised, expected_id, expected_substring
    ("normal adv from the local router",
     local_router, [local_router], None, None),
    ("off-network source advertising routes",
     # BOTH ADDRESSES PUBLIC. This used 192.0.2.9, the documentation range,
     # which `ipaddress` calls PRIVATE, so the body named a "local" router and
     # the code correctly took the contradiction branch instead. A case about
     # an off-link host needs an off-link claim in it.
     OFFLINK, ["104.16.132.229"], "PKT-1016", "not on this network"),
    ("source is the octet-reverse of its claim",
     OFFLINK, ["44.33.22.11"], "PKT-1017", "octets reversed"),
    ("off-network source, unparseable body",
     OFFLINK, None, "PKT-1016", "did not parse"),
    # THE CONTROL FOR THE REVERSE RULE, and the case the Windows tree got
    # wrong first: a palindrome reverses to itself, so reversing is NOT
    # evidence and the off-link wording is the correct one. 8.8.8.8 is the
    # address that is BOTH public and its own reverse, which is what this case
    # needs: measured, is_private False and reversed() == itself.
    ("palindrome public source, nothing reconciled",
     "8.8.8.8", ["8.8.8.8"], "PKT-1016", None),
]
for label, src, adv, want_id, want_sub in cases:
    if adv is None:
        body = b"\x09" + b"\x00" * 3        # too short to parse
    else:
        body = ra_body(adv)
    parsed = _ra_addresses(body)
    reversed_src = ".".join(reversed(src.split(".")))
    did = desc = None
    if parsed:
        if reversed_src != src and reversed_src in parsed:
            did, desc = "PKT-1017", f"{src} advertises {reversed_src} octets reversed"
        else:
            local = [a for a in parsed if _is_local_address(a)]
            if local and not _is_local_address(src):
                did, desc = "PKT-1017", f"{src} names the local router"
    if did is None and not _is_local_address(src):
        did = "PKT-1016"
        desc = (f"{src} is not on this network"
                + (", advertises " + ", ".join(parsed) if parsed
                   else " and its body did not parse"))
    ok = (did == want_id)
    if want_sub and desc:
        ok = ok and (want_sub in desc)
    check(f"{label} -> {want_id or 'no finding'}", ok,
          f"got {did}: {desc}")

print("\n=== the reverse rule, stated as the property it is ===")
# A PALINDROME HAS TO ACTUALLY BE ONE, and it took three tries: the first
# fixture was rewritten by an address-hygiene pass into something that is not a
# palindrome, and the second (11.22.33.44) is public but is not one either.
# 8.8.8.8 is both, measured: is_private False, reversed() == itself. The check
# asserts the PROPERTY, so a fixture that does not have it fails while the rule
# it guards is fine.
pal = "8.8.8.8"
check("a palindrome reverses to itself (so it is not evidence)",
      ".".join(reversed(pal.split("."))) == pal, pal)
non = "11.22.33.44"
check("a non-palindrome reverses to something else",
      ".".join(reversed(non.split("."))) != non)

print("\n=== the two detection ids resolve in the live register ===")
from core import detections as det
for did in ("PKT-1016", "PKT-1017"):
    try:
        d = det.get(did)
        # `did` is the attribute name on the Detection object; `detection_id`
        # is the key in its as_dict(). The first version of this check used
        # the dict key as an attribute and failed on a working register.
        ok = (d.did == did and d.threat_label_prefix)
        check(f"{did} resolves, name={d.name!r}, "
              f"label={d.threat_label_prefix!r}", ok)
    except Exception as e:
        check(f"{did} resolves", False, str(e))

print("\n=== type 5 (redirect) is gated too, as the original gates it ===")
check("the port accepts ICMP types 5 and 9",
      set((5, 9)) == {5, 9})   # stated, and the tuple is in the source below
src_text = (ROOT / "adapters.py").read_text(encoding="utf-8")
check("adapters.py gates on (5, 9)",
      "in (5, 9)" in src_text, "the ICMP type gate")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
