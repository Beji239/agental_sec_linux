# scripts/retract_baseline.py
# Withdraw what a baseline LEARNED about an entity.
#
# TODO 93, 2026-09-13. Closes the gap 45.5 named: supersede_observation could
# withdraw an observation, but rollup reads current observations only, so the
# withdrawal kept the row out of future merges and did nothing about the
# baseline that had already eaten it. You could retract the sentence and not
# the belief it produced.
#
# This is an OWNER action, deliberately not a model tool. A model that can
# erase what it learned can also erase what it learned about an intruder.
#
# Nothing is deleted. The row keeps its identity and gains a reason, and the
# session count restarts so the next observation rebuilds from scratch rather
# than coming straight back at the old confidence.
#
#     python scripts/retract_baseline.py --list 192.0.2.249
#     python scripts/retract_baseline.py 192.0.2.249 --reason "measured on a blind run"
#     python scripts/retract_baseline.py 192.0.2.249 --key active_hours --reason "..."

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from core import memory_engine as me     # noqa: E402


def show(entity_type, entity_value):
    rows = me.query_behavioral_baseline(entity_type=entity_type,
                                        entity_value=entity_value)
    if not rows:
        print(f"No baseline rows for {entity_type} {entity_value}.")
        return 0
    print(f"\n{len(rows)} baseline row(s) for {entity_type} {entity_value}\n")
    for r in rows:
        mark = "  RETRACTED" if r.get("retracted_at") else ""
        print(f"  {r['behavior_key']:<24} samples={r.get('sample_count', 0):<4} "
              f"confidence={r.get('confidence')}"
              f"{'  SUPPRESSING' if r.get('alert_suppressed') else ''}{mark}")
        if r.get("retracted_reason"):
            print(f"      withdrawn: {r['retracted_reason']}")
    print()
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("entity_value", help="the ip, process name, port or user")
    ap.add_argument("--type", default="ip",
                    choices=["ip", "process", "port", "user"])
    ap.add_argument("--key", default=None,
                    help="one behavior key. Omit to retract every key for it.")
    ap.add_argument("--reason", default=None,
                    help="why. Required unless --list.")
    ap.add_argument("--list", action="store_true",
                    help="show what is on file and change nothing")
    args = ap.parse_args()

    if args.list:
        return show(args.type, args.entity_value)

    if not (args.reason or "").strip():
        # Same rule as supersede_observation. A retraction with no explanation
        # is indistinguishable from tampering, and the whole point of keeping
        # the row is that somebody can read why.
        sys.exit("--reason is required. State what was wrong and how it is known.")

    print("Before:")
    show(args.type, args.entity_value)

    out = me.retract_baseline(args.type, args.entity_value, args.key,
                              args.reason)
    if not out.get("success"):
        sys.exit(out.get("error", "failed"))

    print(f"Retracted {out['retracted']} baseline row(s), "
          f"cleared {out['sessions_cleared']} counted session(s).")
    print(out["note"])
    print("\nAfter:")
    show(args.type, args.entity_value)
    return 0


if __name__ == "__main__":
    sys.exit(main())
