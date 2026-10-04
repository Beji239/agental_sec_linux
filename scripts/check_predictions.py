#!/usr/bin/env python3
# scripts/check_predictions.py, read the prediction ledger from the command
# line, and optionally score anything whose deadline has passed.
#
# PREREQUISITES
#   python 3.10 or newer. Run it from anywhere, it finds the project root from
#   its own path. It reads the real database, so run it beside main.py or with
#   AGENTALSEC_TEST_DB pointing somewhere else.
#
#   python scripts/check_predictions.py              # just show me
#   python scripts/check_predictions.py --check      # score what is due
#   python scripts/check_predictions.py --only miss  # one outcome
#
# READ-ONLY BY DEFAULT. --check is the only thing here that writes, and even
# then it cannot decide an answer: it asks core/predictions.py to run, and that
# refuses to look at a prediction whose horizon has not passed. So running it
# twice, or ten times, cannot change a single outcome.

import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import predictions as pr                    # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="score any prediction whose deadline has passed")
    ap.add_argument("--only", choices=["hit", "miss", "unverifiable", "pending"],
                    help="show one outcome only")
    ap.add_argument("--limit", type=int, default=40)
    args = ap.parse_args()

    if args.check:
        result = pr.check_due()
        if not result["checked"]:
            # The honest empty. "Nothing was due" and "nothing changed" are
            # different sentences, and printing a cheerful summary of an empty
            # run reads as a reassurance about a check that had nothing to
            # check. That exact shape has been a bug in this project before.
            print("Nothing was due. Every open prediction still has time "
                  "left on it.\n")
        else:
            print(f"Checked {result['checked']}: {result['hit']} right, "
                  f"{result['miss']} wrong, {result['unverifiable']} could "
                  f"not be checked.\n")

    s = pr.score(recent=1)
    if not s.get("available"):
        print(s.get("note", "No prediction data."))
        return 0

    print("THE MODEL'S RECORD")
    print(f"  right            {s['hit']}")
    print(f"  wrong            {s['miss']}")
    print(f"  could not check  {s['unverifiable']}")
    print(f"  still open       {s['pending']}")
    rate = "-" if s["hit_rate"] is None else f"{s['hit_rate'] * 100:.0f}%"
    print(f"  hit rate         {rate}   (over the {s['checked']} checked, "
          f"and ONLY those)")
    print(f"\n  {s['how_to_read_this']}\n")

    if s["why_unverifiable"]:
        print("WHY IT COULD NOT CHECK")
        for row in s["why_unverifiable"]:
            print(f"  {row['n']} x {row['reason']}")
        print()

    rows = pr.query_predictions(outcome=args.only, limit=args.limit)
    if not rows:
        print("No predictions match.")
        return 0

    print("THE LEDGER")
    for r in rows:
        label = {"hit": "right", "miss": "WRONG",
                 "unverifiable": "could not check"}.get(r["outcome"], "open")
        print(f"  [{label:>15}]  {r['statement']}")
        print(f"                     {r['entity_value']}  "
              f"{r['claim_kind']}  due {r['horizon_ends_at']}")
        if r.get("outcome_reason"):
            print(f"                     {r['outcome_reason']}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
