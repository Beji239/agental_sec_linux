"""
scripts/backfill_intervals.py

Measure contact spacing from the packets that are ALREADY in the database,
and write the summary onto the baselines. Run this BEFORE any pruning.

Why it exists: going forward, rollup_engine measures intervals every time it
runs. But there are about twelve days of packets sitting in the database right
now that no rollup will ever revisit, and they are the evidence for every
baseline written so far. Pruning without reading them first throws away the
only record of how regular anything was.

    python scripts/backfill_intervals.py            # look, change nothing
    python scripts/backfill_intervals.py --write    # write it to the baselines

DRY RUN IS THE DEFAULT ON PURPOSE. This writes to the model's own tables. A
script that modifies the record by default is one you run once by accident.

It only touches beacon_destinations rows, only fills value_mean / stddev /
min / max and beacon_detail, and never changes confidence, sample_count,
flagged_as_normal or alert_suppressed. Measuring something is not a reason to
revisit a decision somebody made about it.
"""

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
DB = ROOT / "agental_sec.db"

from core import intervals  # noqa: E402


def human(sec):
    if sec is None:
        return "?"
    if sec >= 86400:
        return f"{sec / 86400:.1f} days"
    if sec >= 3600:
        return f"{sec / 3600:.1f} hours"
    if sec >= 60:
        return f"{sec / 60:.1f} min"
    return f"{sec:.0f} sec"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true",
                    help="actually write to the baselines")
    ap.add_argument("--entity", help="only this IP")
    args = ap.parse_args()

    if not DB.exists():
        print(f"No database at {DB}")
        return 1

    mode = "ro" if not args.write else "rw"
    conn = sqlite3.connect(f"file:{DB}?mode={mode}", uri=True)

    if "beacon_detail" not in {r[1] for r in conn.execute(
            "PRAGMA table_info(behavioral_baseline)")}:
        print("beacon_detail column is missing. Start main.py once so the v20 "
              "migration runs, then re-run this.")
        return 1

    q = ("SELECT id, entity_value FROM behavioral_baseline "
         "WHERE behavior_key='beacon_destinations' AND entity_type='ip'")
    p = []
    if args.entity:
        q += " AND entity_value = ?"
        p.append(args.entity)
    rows = conn.execute(q, p).fetchall()

    print(f"{len(rows)} beacon_destinations baseline(s).")
    print(f"Mode: {'WRITE' if args.write else 'dry run, nothing is changed'}\n")

    measured_n = skipped = 0
    for bid, ip in rows:
        res = intervals.contact_intervals(conn, ip)
        mr = res["most_regular"]
        if not mr:
            skipped += 1
            print(f"  {ip:<18} no destination contacted often enough "
                  f"(needs {intervals.MIN_CONTACTS}+ separate contacts)")
            continue

        measured_n += 1
        print(f"  {ip}")
        for d in res["destinations"][:4]:
            flag = "  steadiest" if d is mr else ""
            print(f"      -> {d['destination']:<18} "
                  f"every {human(d['mean_seconds']):<10} "
                  f"cv={d['cv']:<6} contacts={d['contacts']} "
                  f"gaps={d.get('gaps_used')} in {d.get('sessions')} run(s){flag}")

        if args.write:
            detail = json.dumps({
                "measured_at": datetime.now(timezone.utc).isoformat(),
                "unit": "seconds_between_contacts",
                "source": "backfill from existing packets",
                "most_regular": mr,
                "destinations": res["destinations"][:8],
                "note": intervals.describe(mr),
            })
            conn.execute(
                "UPDATE behavioral_baseline SET value_mean=?, value_stddev=?, "
                "value_min=?, value_max=?, beacon_detail=? WHERE id=?",
                (mr["mean_seconds"], mr["stddev_seconds"], mr["min_seconds"],
                 mr["max_seconds"], detail, bid))

    if args.write:
        conn.commit()
        print(f"\nWritten. {measured_n} baseline(s) now carry measured spacing.")
    else:
        print(f"\nDry run. {measured_n} would be written, {skipped} skipped.")
        print("Re-run with --write once the numbers above look sane.")

    print("\nReminder: a steady interval is normal for updaters, NTP and")
    print("keepalives. This is a measurement, not a verdict.")
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
