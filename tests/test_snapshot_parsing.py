"""
tests/test_snapshot_parsing.py, the before/after snapshot's field parsing.

Written 2026-08-29, an hour after shipping the script, because the first run
on a real machine reported gateway_mac and lan_subnet as unreadable, the
two pinned fields the whole comparison depends on.

The cause: `Default Gateway ... : <address>` was matched on the labelled line
only. Windows puts the IPv6 gateway there and the IPv4 one on an indented
continuation beneath it, so the pattern found nothing.

The script did do the one important thing right. It reported those fields as
unreadable rather than comparing None to None and printing a clean bill of
health. A verification tool that cannot verify must say so; that is the
difference between a bug and a silent lie. This suite pins both the parsing
and that behaviour.
"""
import sys, pathlib, json, tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

fails = []
def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)

import network_state_snapshot as ns

# The shape that broke it: IPv6 first on the labelled line, IPv4 indented
# beneath, several DNS servers spread over continuation lines.
IPCONFIG = """
Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : example.invalid
   Description . . . . . . . . . . . : Gigabit Network Adapter
   Physical Address. . . . . . . . . : 00-11-22-33-44-55
   DHCP Enabled. . . . . . . . . . . : Yes
   IPv6 Address. . . . . . . . . . . : 2001:db8::1234
   IPv4 Address. . . . . . . . . . . : 192.0.2.44(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::1234:5678:9abc:def0%13
                                       192.0.2.1
   DHCP Server . . . . . . . . . . . : 192.0.2.1
   DNS Servers . . . . . . . . . . . : 2001:db8::1
                                       192.0.2.1
                                       100.64.100.100
"""

ROUTES = """
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0        192.0.2.1      192.0.2.44     25
        127.0.0.0        255.0.0.0         On-link       127.0.0.1    331
"""


print("\n[1] the continuation line is read, which is where the IPv4 lives")
check("gateway", ns._labelled_block("Default Gateway", IPCONFIG), ["192.0.2.1"])
check("the IPv6 on the labelled line is not mistaken for one",
      "fe80" in str(ns._labelled_block("Default Gateway", IPCONFIG)), False)
check("every DNS server, across lines",
      ns._labelled_block("DNS Servers", IPCONFIG),
      ["192.0.2.1", "100.64.100.100"])
check("dhcp server", ns._labelled_block("DHCP Server", IPCONFIG), ["192.0.2.1"])


print("\n[2] the old single-line pattern is gone from the source")
src = (ROOT / "scripts" / "network_state_snapshot.py").read_text(encoding="utf-8")
check("no bare Default Gateway regex remains",
      'r"Default Gateway[ .:]*(' in src, False)


print("\n[3] a label that is genuinely absent yields [], not a wrong guess")
check("missing label", ns._labelled_block("Default Gateway", "nothing here"), [])
check("unreadable input", ns._labelled_block("DNS Servers", ns.UNREADABLE), [])


print("\n[4] unreadable is never treated as unchanged")
# The failure this guards against: two snapshots that both failed to read a
# pinned field comparing equal, and the tool reporting a clean restore.
before = {"_taken_at": "t0", "gateway_mac": ns.UNREADABLE,
          "firewall_rule_count": 400, "lan_subnet": "192.0.2.0",
          "firewall_profiles": {"Public": "ON"}, "router_dhcp_scope": "192.0.2.1",
          "host_ipv4": "192.0.2.44", "default_gateway": "192.0.2.1",
          "dns_servers": ["192.0.2.1"]}
after = dict(before); after["_taken_at"] = "t1"

import io, contextlib
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    rc = ns.compare(before, after)
out = buf.getvalue()
check("an unreadable pinned field is listed as uncomparable",
      "COULD NOT COMPARE" in out, True)
check("and gateway_mac is named there", "gateway_mac" in out, True)
check("the clean-bill line is qualified, not bare",
      "prove nothing either way" in out, True)


print("\n[5] a tampered pinned field is loud, and sets a non-zero exit")
bad = dict(after); bad["firewall_rule_count"] = 402
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    rc_bad = ns.compare(before, bad)
out_bad = buf.getvalue()
check("reported under the loud heading",
      "CHANGED, AND SHOULD NOT HAVE" in out_bad, True)
check("exit code is non-zero so a script can gate on it", rc_bad, 1)

good_rc = rc
check("a clean comparison exits zero", good_rc, 0)


print("\n[6] a restore that did not finish is separated from one that did")
half = dict(after); half["default_gateway"] = "198.51.100.1"
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    ns.compare(before, half)
out_half = buf.getvalue()
check("named as not back", "CHANGED, AND NOT BACK" in out_half, True)
check("and NOT confused with tampering",
      "CHANGED, AND SHOULD NOT HAVE" in out_half, False)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
