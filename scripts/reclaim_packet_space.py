"""
scripts/reclaim_packet_space.py

Give back the disk that TODO 34 measured. Dry run by default.

    python scripts/reclaim_packet_space.py            # look, change nothing
    python scripts/reclaim_packet_space.py --write    # do it

WHAT IT DOES, and both numbers below are from scripts/db_breakdown.py run
against the real 1.6 GB database on 2026-09-01, not from arithmetic:

  1. NULLs payload_snippet on every UNFLAGGED row.
     566.7 MB, 56.5% of the packets table. It sat on 1,304,740 rows of
     2,018,479, and 242 of those rows were flagged. Nothing outside
     save_packet ever read one: the signature checks run on the LIVE bytes
     at capture time, so a payload that mattered already has a threat_label.
     Flagged rows KEEP their payload, which is the only time anyone wants one.

  2. DROPs the raw_summary column.
     124.0 MB. It held scapy's summary() line, rebuilt from src_ip, dst_ip,
     protocol and flags, every one of which is a separate column on the same
     row. No reader anywhere in the codebase.

  3. VACUUMs, which is the only step that actually shrinks the file.

The application stopped WRITING both of these the same day. This script is
only about the rows that already exist, which is why it is a one-off you run
by hand and not part of boot.

WHY IT IS NOT A MIGRATION. core/migrations.py:_migrate_packet_scope already
wrote the rule down: on this table, ALTER TABLE ADD COLUMN is free but
anything that rewrites 2 million rows is not, and boot is the wrong place for
it. DROP COLUMN rewrites every row and VACUUM cannot run inside a transaction
at all, so neither belongs in run_migrations. There is no schema version bump
either: a database that has run this and one that has not both work, because
nothing reads raw_summary in either.

IRREVERSIBLE. The payloads on unflagged rows are gone afterwards, and so is
the column. Read the dry run first. Run it with the app STOPPED, VACUUM takes
an exclusive lock.
"""

import argparse
import shutil
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
DB = ROOT / "agental_sec.db"

from core import retention  # noqa: E402

BATCH = 50_000
MIN_SQLITE_FOR_DROP = (3, 35, 0)


def _has_column(conn, table, column) -> bool:
    return column in {r[1] for r in
                      conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _measure(conn) -> dict:
    """What is actually on disk right now. Measured, not assumed."""
    total = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
    unflagged_payloads = conn.execute(
        "SELECT COUNT(*), COALESCE(SUM(LENGTH(payload_snippet)), 0) "
        "FROM packets "
        "WHERE threat_label IS NULL AND payload_snippet IS NOT NULL"
    ).fetchone()
    flagged_payloads = conn.execute(
        "SELECT COUNT(*) FROM packets "
        "WHERE threat_label IS NOT NULL AND payload_snippet IS NOT NULL"
    ).fetchone()[0]

    raw_present = _has_column(conn, "packets", "raw_summary")
    raw_bytes = 0
    if raw_present:
        raw_bytes = conn.execute(
            "SELECT COALESCE(SUM(LENGTH(raw_summary)), 0) FROM packets"
        ).fetchone()[0]

    return {
        "rows": total,
        "unflagged_payload_rows": unflagged_payloads[0],
        "unflagged_payload_bytes": unflagged_payloads[1],
        "flagged_payload_rows": flagged_payloads,
        "raw_summary_present": raw_present,
        "raw_summary_bytes": raw_bytes,
    }


def _preflight(db_path: Path, m: dict, want_write: bool) -> list:
    """Reasons to refuse. Empty list means go."""
    problems = []

    if want_write and m["raw_summary_present"]:
        if sqlite3.sqlite_version_info < MIN_SQLITE_FOR_DROP:
            problems.append(
                f"This Python's SQLite is {sqlite3.sqlite_version}. "
                f"DROP COLUMN needs 3.35.0 or newer. The payload step below "
                f"would still work, so re-run with --skip-drop to do that "
                f"half now."
            )

    if want_write:
        # VACUUM writes a whole second copy before swapping. Running out of
        # disk halfway through a VACUUM is not a situation worth being in.
        size = db_path.stat().st_size
        free = shutil.disk_usage(db_path.parent).free
        if free < size * 1.2:
            problems.append(
                f"VACUUM needs room for a full second copy. "
                f"Database is {retention.human_bytes(size)}, free space is "
                f"{retention.human_bytes(free)}. Want at least "
                f"{retention.human_bytes(int(size * 1.2))}."
            )

    return problems


def _locked(db_path: Path) -> bool:
    """Is something else holding the write lock, i.e. is the app running."""
    try:
        probe = sqlite3.connect(db_path, timeout=1.0)
        probe.execute("BEGIN IMMEDIATE")
        probe.rollback()
        probe.close()
        return False
    except sqlite3.OperationalError:
        return True


def _null_unflagged_payloads(conn, total_rows, progress=print) -> int:
    """
    One ordered pass by rowid, committing as it goes.

    A single UPDATE over 1.3 million rows would hold the whole change in the
    WAL until it committed, which on this table is most of a gigabyte of
    write-ahead log before anything lands. Batching by rowid range keeps the
    WAL small and means an interrupted run has simply done part of the job
    rather than none of it. Re-running finishes it.
    """
    last_rowid = 0
    cleared = 0
    started = time.time()

    while True:
        rows = conn.execute(
            "SELECT rowid FROM packets WHERE rowid > ? ORDER BY rowid LIMIT ?",
            (last_rowid, BATCH)
        ).fetchall()
        if not rows:
            break

        lo, hi = rows[0][0], rows[-1][0]
        cur = conn.execute(
            "UPDATE packets SET payload_snippet = NULL "
            "WHERE rowid BETWEEN ? AND ? "
            "  AND threat_label IS NULL "
            "  AND payload_snippet IS NOT NULL",
            (lo, hi)
        )
        conn.commit()
        cleared += cur.rowcount
        last_rowid = hi

        if total_rows:
            pct = min(100, int(hi * 100 / total_rows))
            progress(f"    {pct:>3}%  {cleared:,} payloads cleared")

    progress(f"    done in {time.time() - started:.0f}s")
    return cleared


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true",
                    help="actually change the database")
    ap.add_argument("--skip-drop", action="store_true",
                    help="clear payloads but leave the raw_summary column")
    ap.add_argument("--skip-vacuum", action="store_true",
                    help="change the rows but do not reclaim the file yet")
    ap.add_argument("--db", default=str(DB))
    args = ap.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"No database at {db_path}")
        return 1

    if args.write and _locked(db_path):
        print("Something else is holding the write lock. Stop the app first.")
        return 1

    size_before = db_path.stat().st_size
    conn = sqlite3.connect(db_path)
    m = _measure(conn)

    print(f"FILE ON DISK   {retention.human_bytes(size_before)}")
    print(f"packets        {m['rows']:,} rows\n")

    print("WHAT IS RECLAIMABLE")
    print(f"    payloads on unflagged rows   {m['unflagged_payload_rows']:>12,} rows   "
          f"{retention.human_bytes(m['unflagged_payload_bytes'])}")
    print(f"    payloads on FLAGGED rows     {m['flagged_payload_rows']:>12,} rows   "
          f"KEPT")
    if m["raw_summary_present"]:
        print(f"    raw_summary column           {'whole column':>12}   "
              f"{retention.human_bytes(m['raw_summary_bytes'])}")
    else:
        print("    raw_summary column           already gone")

    reclaimable = m["unflagged_payload_bytes"] + m["raw_summary_bytes"]
    print(f"\n    column data recovered        "
          f"{retention.human_bytes(reclaimable)}")
    print("    The file will shrink by more than that, because page overhead")
    print("    and index entries go with it. The real number is the file size")
    print("    after the vacuum, which is why this prints it at the end.")

    problems = _preflight(db_path, m, args.write)
    if problems:
        print("\nREFUSING")
        for p in problems:
            print(f"    {p}")
        conn.close()
        return 1

    if not args.write:
        print("\nDry run, nothing was changed.")
        print("This is IRREVERSIBLE. The payloads on unflagged rows and the")
        print("raw_summary column are gone afterwards. Re-run with --write")
        print("once the numbers above look right, and with the app stopped.")
        conn.close()
        return 0

    print("\nWRITING\n")

    print("  1. clearing payloads on unflagged rows")
    cleared = _null_unflagged_payloads(conn, m["rows"])

    dropped = False
    if m["raw_summary_present"] and not args.skip_drop:
        print("  2. dropping the raw_summary column")
        print("     (this rewrites every row, it takes a while)")
        started = time.time()
        conn.execute("ALTER TABLE packets DROP COLUMN raw_summary")
        conn.commit()
        dropped = True
        print(f"     done in {time.time() - started:.0f}s")
    else:
        print("  2. raw_summary: skipped")

    if not args.skip_vacuum:
        print("  3. vacuuming, this is the step that shrinks the file")
        started = time.time()
        conn.isolation_level = None          # VACUUM cannot run in a transaction
        conn.execute("VACUUM")
        print(f"     done in {time.time() - started:.0f}s")
    else:
        print("  3. vacuum: skipped, the file will not shrink until you run one")

    # Same reasoning as prune_db.py: a maintenance job that changed 1.3 million
    # rows and left no trace is exactly the kind of unrecorded change the
    # journal exists to make visible. Non-fatal if it fails, but say so.
    # record() never raises and returns None when it declined, so the return
    # value is the only thing that says whether an entry exists. Printing
    # "recorded" without checking it is the same false claim prune_db.py went
    # out of its way not to make.
    try:
        from core import integrity
        # Pass the connection we already have. Without it record() opens
        # memory_engine.DB_PATH, which is the WRONG database whenever --db
        # pointed somewhere else, and the entry would land in a file this run
        # never touched.
        entry = integrity.record(
            operation="packet_space_reclaimed",
            table_name="packets",
            row_ref=f"{cleared} payloads cleared, raw_summary dropped={dropped}",
            conn=conn,
        )
        # record() only commits when it opened the connection itself.
        conn.commit()
        print("\n  recorded in the integrity journal" if entry else
              "\n  integrity journal NOT updated: the entry was declined")
    except Exception as e:
        print(f"\n  integrity journal NOT updated: {e}")

    conn.close()

    size_after = db_path.stat().st_size
    saved = size_before - size_after
    print(f"\nFILE ON DISK   {retention.human_bytes(size_before)} -> "
          f"{retention.human_bytes(size_after)}")
    if saved > 0:
        print(f"               {retention.human_bytes(saved)} recovered "
              f"({saved * 100 // max(size_before, 1)}%)")

    print("\nNEXT: re-run scripts/db_breakdown.py. The new bytes-per-hour is")
    print("what the retention budget should be set from, not the old 200 MB.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
