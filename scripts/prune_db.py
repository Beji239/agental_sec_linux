"""
scripts/prune_db.py

Keep the database under its size limit by deleting the oldest WHOLE capture
sessions. Dry run by default.

    python scripts/prune_db.py                 # look, change nothing
    python scripts/prune_db.py --write         # actually prune and vacuum
    python scripts/prune_db.py --status        # sizes and sessions, no plan
    python scripts/prune_db.py --set-trigger 5GB --set-floor 4GB

DRY RUN IS THE DEFAULT ON PURPOSE, for the same reason backfill_intervals.py
gives: this one deletes, and deletion is the only irreversible thing this
application does. Read the plan, then pass --write.

WHAT IT WILL NEVER DO
  * delete part of a capture session
  * delete the run that is happening right now, or the newest run on record
  * delete anything in the keep-list
  * touch the behavioural tables, the integrity journal, findings, the
    inventory or the presence series
  * compare a timestamp against the wall clock, which is the bug TODO.md 23.9
    exists to prevent

Run it with the app STOPPED. VACUUM takes an exclusive lock, and pruning under
a live packet sniffer means competing for the same write lock for no reason.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
DB = ROOT / "agental_sec.db"

from core import retention  # noqa: E402


def parse_size(text: str) -> int:
    """Accept 2GB, 2.5 gb, 1500MB, or a plain byte count."""
    t = str(text).strip().lower().replace(" ", "")
    mult = 1
    for suffix, m in (("tb", 1000 ** 4), ("gb", 1000 ** 3),
                      ("mb", 1000 ** 2), ("kb", 1000), ("b", 1)):
        if t.endswith(suffix):
            t, mult = t[:-len(suffix)], m
            break
    return int(float(t) * mult)


def show_status(conn, db_path):
    size = retention.database_bytes(db_path)
    lim = retention.limits(conn)
    print(f"Database   {retention.human_bytes(size['total'])}")
    for name, n in size["parts"].items():
        if n:
            print(f"    {name:<28} {retention.human_bytes(n)}")
    print(f"Trigger    {retention.human_bytes(lim['trigger'])}")
    print(f"Floor      {retention.human_bytes(lim['floor'])}")
    if not lim["ok"]:
        print(f"  REFUSING: {lim['reason']}")
    print()

    inv = retention.session_inventory(conn)
    print(f"{len(inv)} capture session(s) holding prunable rows, "
          f"oldest first:")
    for s in inv:
        print(f"  {s['session_id']}  {s['rows']:>9} rows  "
              f"{retention.human_bytes(s['bytes_estimate']):>9}  "
              f"{s['first_at']} .. {s['last_at']}")
    print("\nSizes per session are a measured payload estimate, not page "
          "usage.")
    print("The real check is the file size after the vacuum.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true",
                    help="actually delete and vacuum")
    ap.add_argument("--status", action="store_true",
                    help="show sizes and sessions, then stop")
    ap.add_argument("--session", help="current session id, so it is protected")
    ap.add_argument("--set-trigger", help="e.g. 5GB")
    ap.add_argument("--set-floor", help="e.g. 4GB")
    ap.add_argument("--db", default=str(DB))
    args = ap.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"No database at {db_path}")
        return 1

    import sqlite3
    conn = sqlite3.connect(db_path)

    if args.set_trigger or args.set_floor:
        for key, raw in ((retention.PREF_TRIGGER, args.set_trigger),
                         (retention.PREF_FLOOR, args.set_floor)):
            if raw:
                conn.execute(
                    "INSERT INTO user_preferences(key, value) VALUES(?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                    "updated_at=CURRENT_TIMESTAMP",
                    (key, str(parse_size(raw))))
        conn.commit()
        lim = retention.limits(conn)
        print(f"Trigger {retention.human_bytes(lim['trigger'])}, "
              f"floor {retention.human_bytes(lim['floor'])}")
        if not lim["ok"]:
            print(f"REFUSED: {lim['reason']}")
            conn.close()
            return 1
        # Journal it HERE rather than claiming the app will. Writing to
        # user_preferences from outside the app leaves no entry until the next
        # time snapshot_config happens to run, and a security tool that says
        # "this is recorded" when it is not yet recorded is the specific kind
        # of false claim this project keeps finding in itself.
        try:
            from core import integrity
            entry = integrity.snapshot_config(
                reason="retention limits changed", conn=conn)
            # snapshot_config only commits when it opened the connection
            # itself. Passed one, it leaves the commit to the caller, and
            # closing without one silently discards the journal entry. Found
            # by checking the row count instead of trusting the return value.
            conn.commit()
            print("Saved, and recorded in the integrity journal."
                  if entry else
                  "Saved. No journal entry was written, the values were "
                  "already what the last snapshot recorded.")
        except Exception as e:
            print(f"Saved, but the integrity journal was NOT updated: {e}")
        conn.close()
        return 0

    if args.status:
        show_status(conn, db_path)
        conn.close()
        return 0
    conn.close()

    mode = "WRITE" if args.write else "dry run, nothing is changed"
    print(f"Mode: {mode}\n")
    report = retention.run(db_path, current_session_id=args.session,
                           dry_run=not args.write, progress=print)

    print()
    if report.get("reason"):
        print(report["reason"])
    if report["deleted_sessions"]:
        verb = "Deleted" if args.write else "Would delete"
        print(f"{verb} {len(report['deleted_sessions'])} whole session(s).")
        if report["rows_removed"]:
            for t, n in report["rows_removed"].items():
                print(f"    {t:<20} {n} rows")
        if not args.write:
            print("\nRe-run with --write once the plan above looks right.")
    if report.get("size_after") is not None:
        print(f"\nSize now {retention.human_bytes(report['size_after'])}")

    print("\nReminder from TODO.md 23.6: a smaller database is a shorter")
    print("memory, and this tool cannot see a pattern slower than a single")
    print("capture run. Keeping more days does less than running longer.")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
