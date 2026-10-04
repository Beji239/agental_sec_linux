#!/usr/bin/env python3
"""
scripts/accept_gateway_mac.py

Move the LAN sensor's gateway MAC baseline DELIBERATELY.

    python scripts/accept_gateway_mac.py                 # show the baseline
    python scripts/accept_gateway_mac.py --accept <MAC>  # trust this one now

WHY THIS SCRIPT EXISTS, AND IT IS A DEFECT THAT IT DID NOT (register
section 13, 2026-09-26). The LAN-1002 finding has pointed at THIS PATH in
its own text since the detection was written -- "if you did replace the
router, accept the new address so this stops: scripts/accept_gateway_mac.py,
or call lan_watch.accept_gateway_mac" -- and the file did not exist in either
tree. A finding that tells an operator to run a script that is not there
sends the owner looking for a thing that was never built, which is worse than
saying "call the function". The Windows tree carries the same promise in its
twin's text; that tree is reference-only and is not fixed.

WHY A SCRIPT AND NOT A MODEL TOOL. `accept_gateway_mac` moves the baseline
that decides what this app trusts about the network's most important
address, and the module is explicit that it only ever moves when a PERSON
says so. A model that could call it could turn a spoof into the trusted
baseline by deciding to. So the same reason scripts/set_always_on.py gives:
the statement comes from a person, and the model gets no tool for it.

WHAT IT WRITES. One row in the `lan_baseline` table (name "gateway_mac") --
NOT a user_preferences key, which core/integrity hashes as the policy and
journals as a rules change. That move is v53; see tools/lan_watch.py.

WHEN TO RUN IT: the LAN-1002 finding says the gateway is answering from a
different hardware address and that you changed the router, or the mesh node
took the gateway role, or a failover happened. If you did NOT change
anything, do not run this -- that is the finding being right.
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--accept", metavar="MAC",
                    help="trust this MAC as the gateway baseline from now on")
    args = ap.parse_args()

    from tools import lan_watch

    # The live watcher when a capture is running, so the change takes effect
    # for the running sensor and not only at the next boot. A fresh instance
    # otherwise, which persists the baseline the same way.
    watcher = lan_watch.active()
    if watcher is None:
        watcher = lan_watch.LanWatch(load_baselines=True)
        print("No capture is running, so this changes the STORED baseline. "
              "The next run will start from it.")

    if not args.accept:
        st = watcher.status()
        print(f"gateway address : {st['gateway_ip'] or '(not known)'}")
        print(f"recorded MAC    : {st['gateway_mac'] or '(never learned yet)'}")
        print(f"DHCP servers    : {', '.join(st['dhcp_servers']) or '(none seen)'}")
        print()
        print("To trust a new gateway MAC: "
              "python scripts/accept_gateway_mac.py --accept <MAC>")
        print("Only do that if YOU changed the router. If you did not, a "
              "changed gateway MAC is the finding working as intended.")
        return 0

    result = watcher.accept_gateway_mac(args.accept)
    if not result.get("accepted"):
        print(f"REFUSED: {result.get('reason')}")
        return 1
    print(f"Gateway MAC baseline moved: {result['old_mac'] or 'none'} -> "
          f"{result['new_mac']}")
    if not result.get("persisted"):
        print("WARNING: the new baseline could NOT be written to the store, "
              "so it holds for this run only and will be relearned at the "
              "next start. A change across that restart would be missed.")
        return 1
    print("LAN-1002 will not raise for this address again. It will raise "
          "again if the gateway answers from a third address.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
