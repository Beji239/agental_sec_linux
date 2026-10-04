"""
scripts/setup_retention.py

The 23.5 setup question, on demand. Pick how much disk AgentalSec may use for
its database, and whether it is allowed to prune itself.

    python scripts/setup_retention.py              # ask
    python scripts/setup_retention.py --show       # what is set now, no changes
    python scripts/setup_retention.py --preset homelab
    python scripts/setup_retention.py --off        # never prune automatically

main.py asks this same question once, on a real terminal, the first time it
boots without an answer on file. This script exists for the other cases: the
app started from a shortcut or a scheduled task where nothing can be typed,
somebody who pressed Enter to decide later, or anybody changing their mind
afterwards.

WHAT IT DOES NOT DO
It never deletes anything. It writes three preferences and stops. The prune
itself runs at a clean shutdown of the app, or by hand through prune_db.py,
and both of those will tell you what they are about to do first.

For a number that is not one of the three presets, prune_db.py takes exact
values:

    python scripts/prune_db.py --set-trigger 8GB --set-floor 6GB
"""

import argparse
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
DB = ROOT / "agental_sec.db"

from core import retention  # noqa: E402


def show(db_path):
    st = retention.status(db_path)
    print(f"Database        {st['size_human']}")
    print(f"Budget          {st['trigger_human']}")
    print(f"Prunes back to  {st['floor_human']}")
    print(f"Capture runs    {st['capture_runs']}"
          + (f", oldest {st['oldest_run_at']}" if st['oldest_run_at'] else ""))
    print()

    if not st["configured"]:
        print("Automatic pruning: NOT SET UP. Nothing is being deleted.")
    elif st["auto_prune"]:
        print("Automatic pruning: ON. Runs at a clean shutdown, only when the")
        print("database is over the budget, and only by whole capture run.")
    else:
        print("Automatic pruning: OFF, by choice. Use prune_db.py by hand.")

    print()
    print(st["note"])
    if not st["limits_ok"]:
        print(f"PROBLEM: {st['limits_reason']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--show", action="store_true",
                    help="print what is set now and stop")
    ap.add_argument("--preset", help="occasional, homelab or business")
    ap.add_argument("--off", action="store_true",
                    help="never prune automatically")
    ap.add_argument("--db", default=str(DB))
    args = ap.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"No database at {db_path}")
        return 1

    if args.show:
        show(db_path)
        return 0

    if args.off:
        retention.decline(db_path)
        print("Automatic pruning is off. Run scripts/prune_db.py when you want")
        print("to reclaim disk. Nothing has been deleted.")
        return 0

    if args.preset:
        result = retention.apply_choice(db_path, args.preset, turn_on=True)
        if not result["ok"]:
            print(f"Not saved: {result.get('reason')}")
            return 1
        print(f"Set to {retention.human_bytes(result['trigger'])}, pruning "
              f"back to {retention.human_bytes(result['floor'])}.")
        print("This happens at a clean shutdown, never mid-session.")
        return 0

    # Interactive. Unlike main.py, this script has no reason to be careful
    # about blocking: somebody typed its name.
    for line in retention.choice_lines(db_path):
        print(line)

    try:
        answer = input("Pick 1 to 4: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nNothing changed.")
        return 1

    if not answer:
        print("Nothing changed.")
        return 1

    if answer == "4":
        retention.decline(db_path)
        print("Automatic pruning stays off. Run scripts/prune_db.py when you")
        print("want to reclaim disk.")
        return 0

    result = retention.apply_choice(db_path, answer, turn_on=True)
    if not result["ok"]:
        print(f"Not saved: {result.get('reason')}")
        return 1

    print()
    print(f"Set to {retention.human_bytes(result['trigger'])}, pruning back to "
          f"{retention.human_bytes(result['floor'])}.")
    print("It runs at a clean shutdown, only when the database is over the")
    print("budget, and only ever by whole capture run. Nothing has been")
    print("deleted right now.")
    print()
    print("To see what it would delete before it ever runs:")
    print("    python scripts/prune_db.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
