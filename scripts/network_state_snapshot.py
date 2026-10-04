#!/usr/bin/env python3
"""
scripts/network_state_snapshot.py, prove the network came back unchanged.

WHY THIS EXISTS
Before rearranging a network for a test, the honest question is not "will I
remember to put it back" but "how will I KNOW it went back". Memory is not
evidence. This takes a snapshot of everything observable about this host's
network position, and can diff two snapshots later.

It reads. It changes nothing, configures nothing, and never contacts the
router's admin interface.

TWO CLASSES OF FACT, AND THE DISTINCTION IS THE POINT
  PINNED    things that must be identical before and after. The firewall
            profiles and rule count, the gateway's hardware address, the LAN
            subnet. A difference here means something was altered that the
            test had no business altering, and it is reported loudly.
  EXPECTED  things the test is supposed to change and then restore: this
            host's address, its default gateway, its DNS servers. A
            difference here during the test is correct; a difference
            afterwards means the restore is incomplete.

Anything the script could not read is reported as unreadable, never as
absent. A blank where a firewall rule count should be is not "no rules".

Usage:
    python scripts/network_state_snapshot.py --save before.json
    ... do the thing, undo the thing ...
    python scripts/network_state_snapshot.py --save after.json
    python scripts/network_state_snapshot.py --compare before.json after.json
"""
import argparse
import json
import pathlib
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone

# Facts that must survive the exercise untouched. Everything else is
# informational or expected to move.
PINNED = [
    "firewall_profiles", "firewall_rule_count", "gateway_mac",
    "lan_subnet", "router_dhcp_scope",
]
EXPECTED_TO_MOVE = ["host_ipv4", "default_gateway", "dns_servers"]

UNREADABLE = "<unreadable>"


def run(cmd: list[str]) -> str:
    """Run a command and return its output, or the unreadable marker."""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return UNREADABLE
    if out.returncode != 0 and not out.stdout.strip():
        return UNREADABLE
    return out.stdout


def _first(pattern: str, text: str, group: int = 1):
    if text == UNREADABLE:
        return UNREADABLE
    m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    return m.group(group).strip() if m else None


def _labelled_block(label: str, text: str) -> list[str]:
    """
    Every IPv4 address on a labelled ipconfig line AND its continuation lines.

    2026-08-29, fixing a defect in the first version of this script. It
    matched `Default Gateway ... : <ipv4>` on the labelled line only. Windows
    puts the IPv6 gateway on the labelled line and the IPv4 one on an
    indented continuation beneath it, so the pattern found nothing and both
    gateway_mac and lan_subnet came back unreadable, the two pinned fields
    that matter most, silently absent from the very comparison they exist for.

    The script reported them as unreadable rather than as unchanged, which is
    the one thing it got right: it said it could not vouch for them instead
    of quietly comparing None to None and printing a clean bill of health.
    """
    if text == UNREADABLE:
        return []
    m = re.search(rf"^\s*{label}[ .]*:\s*(.*(?:\n\s{{6,}}\S.*)*)",
                  text, re.IGNORECASE | re.MULTILINE)
    if not m:
        return []
    return re.findall(r"[0-9]+(?:\.[0-9]+){3}", m.group(1))


def snapshot_windows() -> dict:
    ipcfg = run(["ipconfig", "/all"])
    routes = run(["route", "print", "-4"])
    arp = run(["arp", "-a"])
    fw = run(["netsh", "advfirewall", "show", "allprofiles"])
    fwcount = run(["powershell", "-NoProfile", "-Command",
                   "(Get-NetFirewallRule | Measure-Object).Count"])

    # Firewall profile states, each named. A profile that could not be read
    # is recorded as unreadable rather than dropped, because a missing entry
    # would silently compare equal to another missing entry.
    profiles = {}
    if fw != UNREADABLE:
        for name in ("Domain", "Private", "Public"):
            m = re.search(rf"{name} Profile Settings.*?State\s+(\w+)",
                          fw, re.IGNORECASE | re.DOTALL)
            profiles[name] = m.group(1) if m else UNREADABLE
    else:
        profiles = {n: UNREADABLE for n in ("Domain", "Private", "Public")}

    # The routing table is the authority on which gateway is actually in use,
    # and it names the interface address that reaches it. ipconfig lists every
    # adapter including virtual ones, so picking "the first IPv4 address" from
    # it is a guess. The 0.0.0.0/0 route is not.
    gw = ipv4 = None
    if routes != UNREADABLE:
        m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+(\S+)\s+\d+",
                      routes, re.MULTILINE)
        if m:
            gw, ipv4 = m.group(1), m.group(2)
    if gw is None:
        block = _labelled_block("Default Gateway", ipcfg)
        gw = block[0] if block else None
    if ipv4 is None:
        ipv4 = _first(r"IPv4 Address[ .:]*([0-9]+(?:\.[0-9]+){3})", ipcfg)

    dns = _labelled_block("DNS Servers", ipcfg) or (
        UNREADABLE if ipcfg == UNREADABLE else [])
    dhcp = _labelled_block("DHCP Server", ipcfg)
    mask = _first(r"Subnet Mask[ .:]*([0-9]+(?:\.[0-9]+){3})", ipcfg)

    # The gateway's hardware address, from the neighbour table. This is the
    # single best evidence that the SAME router is in place afterwards and
    # was not reset or swapped, an address can be re-handed out, a MAC
    # cannot be coincidental.
    gw_mac = None
    if gw and arp != UNREADABLE:
        m = re.search(rf"{re.escape(gw)}\s+([0-9a-f]{{2}}(?:-[0-9a-f]{{2}}){{5}})",
                      arp, re.IGNORECASE)
        gw_mac = m.group(1).lower().replace("-", ":") if m else None

    count = None
    if fwcount != UNREADABLE:
        digits = re.search(r"\d+", fwcount)
        count = int(digits.group(0)) if digits else UNREADABLE

    return {
        "host_ipv4":          ipv4,
        "subnet_mask":        mask,
        "default_gateway":    gw,
        "dns_servers":        dns,
        "gateway_mac":        gw_mac,
        "lan_subnet":         (f"{gw.rsplit('.', 1)[0]}.0" if gw else None),
        "firewall_profiles":  profiles,
        "firewall_rule_count": count,
        "router_dhcp_scope":  dhcp[0] if dhcp else None,
        "route_default_count": (len(re.findall(r"^\s*0\.0\.0\.0\s", routes,
                                               re.MULTILINE))
                                if routes != UNREADABLE else UNREADABLE),
    }


def snapshot_posix() -> dict:
    """
    The Linux half. REWRITTEN 2026-09-21, because it was reporting answers it
    did not have.

    This function existed before the rewrite and it ran on this host, which is
    exactly what made it worth fixing rather than recording. Measured on THIS
    machine, 2026-09-21:

      host_ipv4     the loopback address  WRONG, and confidently so. It took
                                the FIRST `inet <addr>/` in `ip -4 addr`,
                                which is lo's. The host's real address is on
                                the wireless interface and appears second.

      subnet_mask   absent      the IPv4 form of a mask is not printed by
                                `ip -4 addr` at all; it shows CIDR.

      route_default_count  absent  the pattern is the Windows `route print`
                                layout (0.0.0.0 columns), which `ip route`
                                does not produce in any form.

      firewall_profiles      UNREADABLE   hardcoded, on a host where ufw is
      firewall_rule_count    UNREADABLE   installed and /etc/ufw/ufw.conf says
                                          ENABLED=yes. The two PINNED fields
                                          that matter most came back
                                          unreadable without being asked for.

      router_dhcp_scope      None       hardcoded, and the one field whose
                                        absence reads as 'no DHCP scope'.

    A script whose whole stated purpose is "how will I KNOW it went back"
    cannot take its four most important readings from the wrong interface, by
    asking a tool that does not print them. Each field below now comes from a
    source that carries it, and a field that genuinely cannot be read says so
    rather than being filled with a default.

    THE FIREWALL IS READ THROUGH THE LAYER OF RECORD, which is a decision
    this project already made and wrote down in tools/iptables_manager.py:
    ufw when it is installed AND /etc/ufw/ufw.conf says ENABLED=yes, because
    that is the surface the owner actually reads. `nft list ruleset` answers
    on a ufw-managed box too, and rules written there are invisible to
    `ufw status`. A probe that answers is not a probe that owns.
    """
    ipa   = run(["ip", "-4", "addr"])
    route = run(["ip", "route"])
    neigh = run(["ip", "neigh"])

    resolv = ""
    try:
        resolv = pathlib.Path("/etc/resolv.conf").read_text()
    except OSError:
        resolv = UNREADABLE

    gw = _first(r"default via ([0-9]+(?:\.[0-9]+){3})", route)
    gw_mac = None
    if gw and neigh != UNREADABLE:
        m = re.search(rf"{re.escape(gw)}\s+.*?lladdr\s+([0-9a-f:]{{17}})",
                      neigh, re.IGNORECASE)
        gw_mac = m.group(1).lower() if m else None

    # THE ADDRESS OF THE INTERFACE THAT ACTUALLY CARRIES THE DEFAULT ROUTE,
    # not the first address the kernel happens to print. `ip route` names it
    # outright on the default line (`... dev <if> proto dhcp src <address>`),
    # which is the kernel's own answer to "what address would this packet
    # leave from", so nothing has to be guessed and nothing can come off
    # loopback.
    host_ipv4 = None
    if route != UNREADABLE:
        host_ipv4 = _first(r"^default\s+.*?\bsrc\s+([0-9]+(?:\.[0-9]+){3})",
                           route)
    if host_ipv4 is None and route != UNREADABLE and ipa != UNREADABLE:
        # No `src` on the default line, so find the interface it names.
        # The lookahead is anchored on the `N: name:` header shape, NOT on
        # whitespace: a continuation line (`    inet ...`) starts with a
        # space, so a loose `^\S*\s` lookahead ends the block on its first
        # line and finds nothing. That was measured, not reasoned.
        dev = _first(r"^default\s+via\s+\S+\s+dev\s+(\S+)", route)
        if dev:
            block = re.search(rf"^\d+:\s+{re.escape(dev)}:.*?(?=^\d+:\s|\Z)",
                              ipa, re.MULTILINE | re.DOTALL)
            if block:
                host_ipv4 = _first(r"inet ([0-9]+(?:\.[0-9]+){3})/",
                                   block.group(0))
    if host_ipv4 is None:
        # No default route, or the interface could not be named. Every GLOBAL
        # address except loopback, so a reading is never taken off lo.
        global_addrs = re.findall(
            r"inet ([0-9]+(?:\.[0-9]+){3})/\d+\s+scope global", ipa) \
            if ipa != UNREADABLE else []
        host_ipv4 = global_addrs[0] if global_addrs else (
            UNREADABLE if ipa == UNREADABLE or route == UNREADABLE else None)

    # The mask as the CIDR prefix, which is the form `ip` prints. The
    # Windows-style dotted quad does not exist on this side at all, so
    # printing one would be inventing a reading.
    mask = None
    if host_ipv4 and ipa != UNREADABLE:
        m = re.search(rf"inet {re.escape(host_ipv4)}/(\d+)", ipa)
        if m:
            mask = f"/{m.group(1)}"
    if mask is None and ipa != UNREADABLE:
        # Fall back to the prefix on the first NON-loopback global address,
        # which is the LAN's own mask in every layout this host uses.
        m = re.search(r"inet (?:[0-9]+(?:\.[0-9]+){3})/(\d+)\s+"
                      r"(?:brd \S+\s+)?scope global", ipa)
        if m:
            mask = f"/{m.group(1)}"

    profiles, count = _firewall_layer_of_record()

    # THE DHCP SERVER, read from the lease rather than from a DHCP console,
    # because there is no DHCP console on a Linux client. Its absence is
    # recorded as None and the caller already refuses to read None as
    # 'unchanged'.
    dhcp = None
    for lease in ("/var/lib/NetworkManager", "/var/lib/dhcp"):
        p = pathlib.Path(lease)
        if not p.is_dir():
            continue
        try:
            hits = sorted(p.glob("**/*.lease"))[:20]
        except OSError:
            hits = []
        for f in hits:
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            m = re.search(r"option dhcp-server-identifier\s+"
                          r"([0-9]+(?:\.[0-9]+){3})", text)
            if m:
                dhcp = m.group(1)
                break
        if dhcp:
            break

    return {
        "host_ipv4":          host_ipv4,
        "subnet_mask":        mask,
        "default_gateway":    gw,
        "dns_servers":        (re.findall(r"nameserver\s+(\S+)", resolv)
                               if resolv != UNREADABLE else UNREADABLE),
        "gateway_mac":        gw_mac,
        "lan_subnet":         (f"{gw.rsplit('.', 1)[0]}.0" if gw else None),
        "firewall_profiles":  profiles,
        "firewall_rule_count": count,
        "router_dhcp_scope":  dhcp,
        "route_default_count": (len(re.findall(r"^default\s", route,
                                               re.MULTILINE))
                                if route != UNREADABLE else UNREADABLE),
    }


def _firewall_layer_of_record() -> tuple[dict | str, int | str]:
    """
    The firewall as the OWNER reads it, not as the kernel could answer.

    Returns (profiles, rule_count). ufw is the layer of record when it is
    installed and enabled, which is the rule tools/iptables_manager.py
    already follows on this tree. Each value is read back from a command, and
    anything that cannot be read comes back UNREADABLE rather than as a
    default: a blank where a rule count should be is not "no rules".
    """
    conf = pathlib.Path("/etc/ufw/ufw.conf")
    ufw_on = False
    try:
        ufw_on = bool(re.search(r"^\s*ENABLED\s*=\s*yes", conf.read_text(),
                                re.IGNORECASE | re.MULTILINE))
    except OSError:
        ufw_on = False

    if ufw_on:
        status = run(["ufw", "status"])
        if status == UNREADABLE:
            return UNREADABLE, UNREADABLE
        # ufw prints one line per profile it can see, in this shape:
        #   Status: active
        #   Logging: on (low)
        #   Default: deny (incoming), allow (outgoing), disabled (routed)
        #   New profiles: skip
        state = _first(r"^Status:\s*(\w+)", status) or UNREADABLE
        rules = len([ln for ln in status.splitlines()
                     if re.match(r"^\s*\[\s*\d+\]", ln)])
        # The three profiles are ufw's own defaults block rather than three
        # named profiles, so the one state ufw reports is what goes here and
        # the key says which backend it came from.
        return ({"layer_of_record": "ufw", "Status": state}, rules)

    # No ufw, so nftables then iptables, the same order the manager uses.
    nft = run(["nft", "list", "ruleset"])
    if nft != UNREADABLE:
        rules = len([ln for ln in nft.splitlines()
                     if re.match(r"^\s*(tcp|udp|ip|meta|ct|iifname|oifname|"
                                 r"accept|drop|reject|jump|return|counter)",
                                 ln)])
        return ({"layer_of_record": "nftables",
                 "Status": "readable"}, rules) if rules else \
               ({"layer_of_record": "nftables", "Status": UNREADABLE},
                UNREADABLE)

    ipt = run(["iptables", "-L", "-n"])
    if ipt != UNREADABLE:
        rules = len([ln for ln in ipt.splitlines()
                     if ln.startswith("ACCEPT") or ln.startswith("DROP")
                     or ln.startswith("REJECT")])
        if rules:
            return {"layer_of_record": "iptables", "Status": "readable"}, rules
        # A readable ruleset with no rules in it is a real state and it is
        # reported as zero, which is different from unreadable.
        return {"layer_of_record": "iptables", "Status": "readable"}, 0

    return UNREADABLE, UNREADABLE


def take() -> dict:
    body = (snapshot_windows() if platform.system() == "Windows"
            else snapshot_posix())
    body["_taken_at"] = datetime.now(timezone.utc).isoformat()
    body["_platform"] = platform.system()
    return body


def compare(before: dict, after: dict) -> int:
    print(f"\nbefore: {before.get('_taken_at')}")
    print(f"after:  {after.get('_taken_at')}\n")

    keys = sorted(set(before) | set(after) - {"_taken_at"})
    problems, restored, moved, unreadable = [], [], [], []

    for k in keys:
        if k.startswith("_"):
            continue
        b, a = before.get(k), after.get(k)
        same = b == a
        if UNREADABLE in (b, a) or b is None or a is None:
            unreadable.append((k, b, a))
            continue
        if k in PINNED and not same:
            problems.append((k, b, a))
        elif k in EXPECTED_TO_MOVE:
            (restored if same else moved).append((k, b, a))
        elif not same:
            moved.append((k, b, a))

    if problems:
        print("CHANGED, AND SHOULD NOT HAVE:")
        for k, b, a in problems:
            print(f"  {k}\n      before {b}\n      after  {a}")
        print("\n  These are the facts the exercise had no business touching.")
        print("  Investigate before doing anything else.\n")

    if moved:
        print("CHANGED, AND NOT BACK:")
        for k, b, a in moved:
            print(f"  {k}: {b}  ->  {a}")
        print("  Expected to move during the test; these have not returned.\n")

    if restored:
        print("MOVED AND RESTORED:")
        for k, b, a in restored:
            print(f"  {k}: {b}")
        print()

    if unreadable:
        print("COULD NOT COMPARE:")
        for k, b, a in unreadable:
            print(f"  {k}: before={b!r} after={a!r}")
        print("  Not the same as 'unchanged'. If one of these is a firewall")
        print("  field, check it by hand before calling the restore clean.\n")

    if not problems and not moved:
        print("Everything pinned matched and everything expected to move came"
              " back.")
        if unreadable:
            print("Subject to the unreadable fields above, which prove"
                  " nothing either way.")
    return 1 if problems or moved else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--save", metavar="FILE")
    ap.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"))
    ap.add_argument("--show", action="store_true")
    args = ap.parse_args()

    if args.compare:
        b = json.loads(pathlib.Path(args.compare[0]).read_text())
        a = json.loads(pathlib.Path(args.compare[1]).read_text())
        return compare(b, a)

    snap = take()
    if args.save:
        pathlib.Path(args.save).write_text(json.dumps(snap, indent=2))
        print(f"\nSaved to {args.save}")
    if args.show or not args.save:
        print(json.dumps(snap, indent=2))

    missing = [k for k in PINNED
               if snap.get(k) in (None, UNREADABLE)
               or (isinstance(snap.get(k), dict)
                   and UNREADABLE in snap[k].values())]
    if missing:
        print("\nWARNING, these pinned fields could not be read, so a later"
              " comparison\nwill not be able to vouch for them:")
        for k in missing:
            print(f"  {k}")
        # PER PLATFORM, because the way out is not the same one. The Windows
        # advice is an Administrator prompt; on Linux, `ufw status` refuses
        # non-root outright and prints a sentence saying so, which
        # run() records as UNREADABLE rather than as an empty ruleset.
        if platform.system() == "Windows":
            print("Run from an Administrator prompt if the firewall fields"
                  " are among them.")
        else:
            print("The firewall fields need root: `ufw status` answers a"
                  " non-root caller with\n'You need to be root to run this"
                  " script' and nothing else, so it is recorded\nas could not"
                  " read rather than as no rules. Re-run under sudo to pin"
                  " them.")
        if "gateway_mac" in missing:
            print("gateway_mac reads the neighbour table, which ages out."
                  " Ping the")
            print("gateway once and re-run, an empty ARP entry is not the"
                  " same as no router.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
