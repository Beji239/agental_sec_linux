#!/usr/bin/env python3
"""
scripts/resolve_false_findings.py, close deviations that were never real.

A finding raised on a premise that turned out to be wrong should not be
silently deleted and should not be left sitting in the queue either. Both
teach the wrong thing: deletion loses the record that the sensor misfired,
and leaving it teaches the operator that the queue is full of noise they
are allowed to skip.

So this resolves them as false_positive WITH the reason attached, which is
what resolve_deviation was built to record.

Dry by default. Prints exactly what it would change and writes nothing
until --confirm is passed.

Usage:
    python scripts/resolve_false_findings.py --entity 192.0.2.1 --entity 192.0.2.9 \\
        --reason "why this was not real"
    python scripts/resolve_false_findings.py --entity ... --reason "..." --confirm
"""
import argparse
import pathlib
import sqlite3
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

OPEN_STATES = (None, "", "unreviewed", "investigating")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--entity", action="append", required=True,
                    help="entity_value to resolve; repeat for several")
    ap.add_argument("--reason", required=True,
                    help="recorded as user_response. Say what was actually "
                         "found, not just 'false positive'.")
    ap.add_argument("--confirm", action="store_true",
                    help="actually write. Without it nothing is changed.")
    args = ap.parse_args()

    from core import memory_engine as me

    conn = sqlite3.connect(f"file:{me.DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    placeholders = ",".join("?" for _ in args.entity)
    rows = conn.execute(
        f"""SELECT id, detected_at, entity_type, entity_value, behavior_key,
                   severity, resolved_as, observed_value
              FROM behavioral_deviation
             WHERE entity_value IN ({placeholders})
             ORDER BY detected_at""", args.entity).fetchall()
    conn.close()

    if not rows:
        print("\nNo deviations match those entity values. Nothing to do.")
        print("If you expected some, check the entity_value spelling against")
        print("the review queue, it may be recorded under a different key.")
        return 0

    already = [r for r in rows if r["resolved_as"] not in OPEN_STATES]
    to_fix = [r for r in rows if r["resolved_as"] in OPEN_STATES]

    print(f"\n{len(rows)} deviation(s) found; {len(to_fix)} still open.\n")
    for r in rows:
        state = r["resolved_as"] or "unreviewed"
        mark = "  " if r in to_fix else "  (already resolved, left alone) "
        print(f"{mark}#{r['id']}  {r['detected_at']}  {r['severity']:<8}"
              f" {r['entity_value']}  {r['behavior_key']}  [{state}]")

    if already:
        print(f"\n{len(already)} already carry a resolution and are not touched."
              " Re-resolving would overwrite whatever a human decided.")

    if not to_fix:
        return 0

    print(f"\nWould resolve {len(to_fix)} as false_positive, with:")
    print(f"    {args.reason}")

    if not args.confirm:
        print("\nDry run. Nothing written. Re-run with --confirm to apply.")
        return 0

    done = 0
    for r in to_fix:
        try:
            me.resolve_deviation(r["id"], "false_positive",
                                 user_response=args.reason)
            done += 1
        except Exception as e:
            print(f"  #{r['id']} failed: {e}")
    print(f"\nResolved {done} of {len(to_fix)}.")
    print("The rows remain in the table with the reason attached, which is")
    print("the point, a sensor's misfires are evidence about the sensor.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
