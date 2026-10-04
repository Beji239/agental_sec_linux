"""
scripts/expect_port.py, say a port is normal on a device, once.

    python scripts/expect_port.py --list
    python scripts/expect_port.py 192.0.2.124 8888 --reason "Echo devices listen here"
    python scripts/expect_port.py 192.0.2.124 8888 --remove

WHY THIS EXISTS, 2026-09-02.

The owner identified a device, told the tool it was the owner's, and the open-port
finding stayed at high anyway. Naming a device says nothing about which of its
ports are normal, so the tool asked the owner about the same port three sessions
running. A tool that keeps asking a question you already answered is a tool
you stop reading, and that is the unread review queue in 4A arriving by a
different road.

This is how the owner answers it. Once, for one port, on one device.

WHAT IT IS NOT
  * NOT dismiss_entity. That is keyed on the entity, so dismissing port 8888
    silences 8888 on EVERY device here. This is one port on one device.
  * NOT a suppression of the observation. The port still appears in
    port_scan_results and on the device row, with the reason attached. What
    stops is the FINDING.
  * NOT available to the model. There is no tool for this and there should
    not be one: a model that can mark its own findings expected has a path to
    silencing itself, which is 8.1F one layer up. The owner declares it.

Declaring CLEARS the findings already raised for that port on that device,
added 2026-09-04 as TODO 39.5. Before that it only stopped new ones, so you
answered the question and the question stayed on screen, which is the unread
queue arriving by a different road.

WHAT KEEPS RAISING, and this is the part worth reading before using it:
  * any OTHER port on the same device
  * this port on any OTHER device
  * the device going missing, changing hardware address, or drifting
  * everything behavioural. This touches port findings and nothing else

A reason is required. A port that stopped raising findings with no recorded
why is worse than one that never raised, because six months from now nobody
can tell whether it was a decision or an accident.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import memory_engine as me  # noqa: E402


def show_list() -> int:
    devices = me.query_known_devices()
    any_found = False

    for device in devices:
        raw = device.get("expected_ports")
        if not raw:
            continue
        try:
            declared = json.loads(raw) if isinstance(raw, str) else raw
        except Exception:
            print(f"  {device['ip']:<16} expected_ports is not readable JSON")
            continue
        if not declared:
            continue

        any_found = True
        label = device.get("known_as") or "unnamed"
        print(f"\n{device['ip']}  {label}")
        for port, entry in sorted(declared.items(), key=lambda kv: int(kv[0])):
            print(f"    port {port:<6} declared by "
                  f"{entry.get('declared_by', 'unknown')} "
                  f"on {str(entry.get('declared_at', ''))[:19]}")
            print(f"                 {entry.get('reason', 'no reason given')}")

    if not any_found:
        print("Nothing declared. Every port on every device raises normally.")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ip", nargs="?", help="device address, must be in the inventory")
    ap.add_argument("port", nargs="?", type=int)
    ap.add_argument("--reason", help="why this port is normal here. Required.")
    ap.add_argument("--remove", action="store_true",
                    help="withdraw a declaration, so the port raises again")
    ap.add_argument("--list", action="store_true",
                    help="show everything declared, then stop")
    args = ap.parse_args()

    if args.list or not args.ip:
        return show_list()

    if args.port is None:
        print("Which port? e.g. expect_port.py 198.51.100.124 8888 --reason ...")
        return 1

    if args.remove:
        if me.undeclare_expected_port(args.ip, args.port):
            print(f"Withdrawn. {args.ip}:{args.port} raises findings again.")
            return 0
        print(f"Nothing was declared for {args.ip}:{args.port}.")
        return 1

    if not args.reason:
        print("A --reason is required.")
        print("Six months from now this is the only thing that says whether")
        print("the port stopped raising because somebody decided it, or")
        print("because somebody was tired.")
        return 1

    try:
        entry = me.declare_expected_port(args.ip, args.port, args.reason)
    except ValueError as e:
        print(e)
        return 1

    print(f"Recorded. {args.ip}:{args.port} will not raise a port finding.")
    print(f"  reason      {entry['reason']}")
    print(f"  declared by {entry['declared_by']}")
    print(f"  at          {entry['declared_at'][:19]}")
    print()
    print("Still watched: every other port on this device, this port on any")
    print("other device, the device going missing or changing hardware, and")
    print("everything behavioural. The port stays visible in the Ports tab")
    print("with this reason attached.")
    print()
    cleared = (entry.get("cleared") or {}).get("count", 0)
    if cleared:
        print(f"Cleared {cleared} finding(s) already raised for this port on")
        print("this device. New scans will not raise more.")
    else:
        print("Nothing was already raised for it, so there was nothing to clear.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
