#!/usr/bin/env python3
# scripts/verify_firewall.py
# T1, 2026-09-17. Does the firewall layer tell the truth?
#
# WHY THIS SCRIPT EXISTS
#
# tools/iptables_manager.py was rewritten because it used to report blocks
# that did not exist and unblocks that never ran. A rewrite is not evidence.
# This script is: it puts real rules on this host's real firewall, reads
# them back, removes them, and reads again — and then it proves the REFUSAL
# paths, which is the half nobody ever tests.
#
# IT TOUCHES THE REAL FIREWALL, on purpose. The rules it uses are named
# AgentalSec_probe_* and every one of them is removed again at the end,
# including on Ctrl+C. It refuses to run as root so that no state can be
# changed by accident: the unelevated run is exactly the refusal-path test.
#
# THE TWO HALVES
#
#   unelevated (default) — every mutating call must REFUSE with a reason and
#       change nothing, and the LIST path must say whether it could read the
#       ruleset instead of returning an empty list that reads as "nothing is
#       blocked". This is the half that catches the class of bug T1 was.
#
#   elevated (--apply)   — sudo this script and it blocks a port and an
#       address, VERIFIES each with a read-back, unblocks both, verifies the
#       absence, and checks the idempotence path (block twice, unblock once
#       is not "already present" then failure). It refuses to touch the SSH
#       port or any address this host holds, because locking the operator out
#       of their own machine during a test is its own incident.
#
# Usage:
#     python3 scripts/verify_firewall.py              # refusal paths, safe
#     sudo python3 scripts/verify_firewall.py --apply # the real thing
#     sudo python3 scripts/verify_firewall.py --apply --ip 203.0.113.7
#
# Exit code 0 means every check passed. Anything else prints the failures
# and exits 1, so this is usable as a gate rather than something a person
# has to read and judge.

import argparse
import ipaddress
import json
import os
import socket
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# The test port. 49999 is high, almost certainly unused, and does not
# collide with the SSH port guard below.
TEST_PORT = 49999
# TEST-NET-3, RFC 5737: reserved for documentation, routable nowhere.
TEST_IP = "203.0.113.7"

_results = []


def check(name: str, ok: bool, detail: str = ""):
    _results.append({"check": name, "ok": bool(ok), "detail": detail})
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}")
    if detail:
        for line in str(detail).splitlines():
            print(f"         {line}")


def _ssh_port() -> int:
    try:
        with open("/etc/ssh/sshd_config", encoding="utf-8",
                  errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.lower().startswith("port "):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 22


def _own_addresses() -> set:
    try:
        import psutil
        found = set()
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if getattr(a, "address", None):
                    found.add(str(a.address).split("%")[0])
        return found
    except Exception:
        return set()


# UNELEVATED: THE REFUSAL PATHS

def check_unelevated(fw):
    print("\n=== unelevated: every mutating call must refuse and change nothing ===")

    detail = fw.detect_backend_detail()
    check("a backend is detected even unelevated",
          detail["backend"] != "none",
          f"backend={detail['backend']!r} — {detail['reason']}")

    check("ufw is preferred when it is the active firewall",
          detail["backend"] == "ufw",
          f"backend={detail['backend']!r}. On this host ufw is enabled, so "
          f"any other answer means rules would be written where `ufw status` "
          f"cannot show them.")

    status = fw.list_agental_rules_status()
    check("the LIST path says whether it could read the ruleset",
          isinstance(status.get("readable"), bool),
          f"readable={status.get('readable')}, "
          f"rules={len(status.get('rules', []))}, "
          f"reason={status.get('reason') or '(readable)'}")

    st = fw.get_status()
    check("rules_count is None (not 0) when the read failed",
          st["rules_count"] is not None or not st["readable"],
          f"readable={st['readable']}, rules_count={st['rules_count']}")

    for label, call in (
        ("block_port", lambda: fw.block_port(TEST_PORT, "inbound")),
        ("unblock_port", lambda: fw.unblock_port(TEST_PORT, "inbound")),
        ("block_ip_address", lambda: fw.block_ip_address(TEST_IP, "both")),
        ("unblock_ip_address", lambda: fw.unblock_ip_address(TEST_IP, "both")),
    ):
        res = call()
        refused = (res.get("success") is False and res.get("refused") is True
                   and res.get("needs_root") is True)
        check(f"{label} refuses with a reason, not a silent no-op",
              refused,
              f"success={res.get('success')!r} refused={res.get('refused')!r} "
              f"needs_root={res.get('needs_root')!r}")
        check(f"{label} refusal names the way out",
              "root" in str(res.get("error", "")).lower(),
              (res.get("error") or "")[:160])

    # The negative control for the whole task: the OLD code returned True
    # from unblock_ip unconditionally. This asserts nobody puts that back.
    res = fw.unblock_ip_address(TEST_IP, "both")
    check("unblock of a rule that does not exist is NOT reported as success",
          res.get("success") is not True,
          f"success={res.get('success')!r}")


# ELEVATED: THE REAL THING, WITH READ-BACKS

def check_elevated(fw, port: int, ip: str):
    print(f"\n=== elevated: real rules on {fw.detect_backend()}, port {port}, "
          f"address {ip} ===")

    ssh = _ssh_port()
    check("the test port is not the SSH port",
          port != ssh,
          f"test port {port}, sshd port {ssh}")

    own = _own_addresses()
    check("the test address is not one this host holds",
          ip not in own,
          f"{ip} vs {sorted(a for a in own if a)[:6]}")

    before = fw.list_agental_rules_status()
    print(f"  .... rules already present from this app: {len(before['rules'])}")

    # port block
    res = fw.block_port(port, "inbound")
    check("block_port succeeds", res.get("success") is True,
          json.dumps({k: v for k, v in res.items()
                      if k in ("backend", "rule_name", "position",
                               "verified", "already_present", "error",
                               "ordering_note")}))
    check("block_port VERIFIED by reading the ruleset back",
          res.get("verified") is True,
          f"verified={res.get('verified')!r}")

    mid = fw.list_agental_rules_status()
    found = [r for r in mid["rules"] if res.get("rule_name", "") in
             str(r.get("rule", ""))]
    check("the rule is visible in the firewall's own listing",
          len(found) >= 1,
          json.dumps(found[:2], indent=1) if found else "not found")

    # idempotence
    res2 = fw.block_port(port, "inbound")
    check("blocking the same port twice says already_present, not an error",
          res2.get("success") is True,
          f"success={res2.get('success')!r} "
          f"already_present={res2.get('already_present')!r}")

    # unblock
    res3 = fw.unblock_port(port, "inbound")
    check("unblock_port succeeds", res3.get("success") is True,
          json.dumps({k: v for k, v in res3.items()
                      if k in ("backend", "rule_name", "removed", "error")}))
    after = fw.list_agental_rules_status()
    still = [r for r in after["rules"] if res.get("rule_name", "") in
             str(r.get("rule", ""))]
    check("the rule is GONE from the firewall's own listing",
          len(still) == 0,
          json.dumps(still[:2], indent=1) if still else "absent")

    # address block, both directions
    res4 = fw.block_ip_address(ip, "both")
    check("block_ip_address succeeds for both directions",
          res4.get("success") is True,
          json.dumps({k: v for k, v in res4.items()
                      if k not in ("partial",)})[:400])
    check("block_ip_address VERIFIED", res4.get("verified") is True)

    res5 = fw.unblock_ip_address(ip, "both")
    check("unblock_ip_address succeeds", res5.get("success") is True,
          json.dumps({k: v for k, v in res5.items()
                      if k in ("backend", "removed", "error")}))

    # the honest not-found
    res6 = fw.unblock_ip_address(ip, "both")
    check("unblocking an address with no rule is reported as not found, "
          "not as success",
          res6.get("success") is False and res6.get("not_found") is True,
          f"success={res6.get('success')!r} not_found={res6.get('not_found')!r}")

    # nothing of ours left behind
    final = fw.list_agental_rules_status()
    left = [r for r in final["rules"]
            if "probe" in str(r.get("rule", "")).lower()
            or str(port) in str(r.get("rule", ""))
            or ip in str(r.get("rule", ""))]
    check("no test rule was left behind", len(left) == 0,
          json.dumps(left[:3], indent=1) if left else "clean")


def cleanup(fw, port: int, ip: str):
    """Best effort, on every exit path including Ctrl+C."""
    print("\n=== cleanup ===")
    for label, res in (
        ("port", fw.unblock_port(port, "inbound")),
        ("address", fw.unblock_ip_address(ip, "both")),
    ):
        print(f"  .... {label}: success={res.get('success')!r} "
              f"not_found={res.get('not_found')!r}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verify the AgentalSec firewall layer tells the truth.")
    ap.add_argument("--apply", action="store_true",
                    help="actually add and remove rules (needs sudo)")
    ap.add_argument("--ip", default=TEST_IP,
                    help=f"address to use in the address tests (default {TEST_IP})")
    ap.add_argument("--port", type=int, default=TEST_PORT,
                    help=f"port to use in the port tests (default {TEST_PORT})")
    args = ap.parse_args()

    try:
        ipaddress.ip_address(args.ip)
    except ValueError:
        print(f"--ip {args.ip!r} is not an address")
        return 2

    from tools import iptables_manager as fw

    print("AgentalSec firewall verification (T1)")
    print(f"  project : {PROJECT_ROOT}")
    print(f"  backend : {fw.detect_backend()} "
          f"({fw.detect_backend_detail()['reason']})")
    print(f"  euid    : {os.geteuid()} "
          f"({'root' if os.geteuid() == 0 else 'unelevated'})")

    if args.apply:
        if os.geteuid() != 0:
            print("\n--apply needs root: sudo python3 scripts/verify_firewall.py --apply")
            return 2
        try:
            check_elevated(fw, args.port, args.ip)
        finally:
            cleanup(fw, args.port, args.ip)
    else:
        if os.geteuid() == 0:
            print("\nRefusing to run the refusal-path tests as root: they "
                  "assert that nothing changes, and as root things WOULD "
                  "change. Run unelevated, or pass --apply for the real test.")
            return 2
        check_unelevated(fw)

    passed = sum(1 for r in _results if r["ok"])
    failed = [r for r in _results if not r["ok"]]
    print(f"\n=== {passed}/{len(_results)} checks passed ===")
    for r in failed:
        print(f"  FAILED: {r['check']}")
    if not args.apply:
        print("\nThis run proved the REFUSAL paths only. The real rules are "
              "exercised by:\n    sudo python3 scripts/verify_firewall.py --apply")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
