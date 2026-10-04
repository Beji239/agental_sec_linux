#!/usr/bin/env python3
# scripts/clean_test_pollution.py, find what the test suite wrote into the
# real database, and remove it only when told to.
#
# TODO 108, 2026-09-14.
#
# WHY THIS EXISTS. Until today, two test files wrote to the project's real
# database on every run of the suite. That is fixed, but the rows already
# written are still there and the database on this machine is 1.6 GB, so
# nobody should be hand typing DELETE statements against it.
#
#   test_pcap_detection      inserted 9 rows into `sensors` per run. Each
#                            analyse call registers an offline sensor with a
#                            fresh random id, so the rows ACCUMULATE across
#                            runs instead of replacing each other.
#   test_process_inspection  inserted 1 row into `enrichment_queue` per run,
#                            queueing whichever python binary ran the tests.
#
# WHAT THIS SCRIPT WILL AND WILL NOT CLAIM, because the distinction matters
# here more than usual.
#
# The sensor rows can be identified exactly. The offline sensor summary is a
# fixed string written by the code, the ids are generated, and a real offline
# sensor comes from importing a capture file, which also sets a label. So a
# row with that exact summary, no label and no notes is test output, and this
# script says so.
#
# The enrichment rows CANNOT be identified exactly, and the script does not
# pretend otherwise. A genuine inspect_process call on a real python process
# on this machine produces a row that looks the same. So those are LISTED for
# a human to read, never deleted, whatever flags you pass.
#
# USE
#   python scripts/clean_test_pollution.py              # count only, no writes
#   python scripts/clean_test_pollution.py --delete     # remove the sensors
#   python scripts/clean_test_pollution.py --db <path>  # another database
#
# It opens read-only unless --delete is given, so the default cannot damage
# anything even if this script is wrong about what it is looking at.

import argparse
import pathlib
import sqlite3
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# The exact string tools/pcap_analyzer writes for an offline sensor. If this
# ever stops matching, the script finds nothing and says so, which is the
# correct failure: it will not guess with a LIKE and delete something else.
OFFLINE_SUMMARY = "A capture file analysed after the fact."

SENSOR_WHERE = ("position = 'offline' AND summary = ? "
                "AND label IS NULL AND notes IS NULL")


def _referencing(conn, summary):
    """Every table holding rows that point at the sensors we would delete.

    Discovered from the live schema rather than from a list written here, so
    a table added later is included without anybody remembering to add it.
    Returns [(table, count)] for the ones with a non-zero count.
    """
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' "
        "AND name <> 'sensors' ORDER BY name")]
    found = []
    for t in tables:
        cols = [r[1] for r in conn.execute(f'PRAGMA table_info("{t}")')]
        if "sensor_id" not in cols:
            continue
        n = conn.execute(
            f'SELECT COUNT(*) FROM "{t}" WHERE sensor_id IN '
            f"(SELECT sensor_id FROM sensors WHERE {SENSOR_WHERE})",
            (summary,)).fetchone()[0]
        if n:
            found.append((t, n))
    return found


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Report, and optionally remove, rows the test suite "
                    "wrote into the real database. See TODO 108.")
    ap.add_argument("--db", default="",
                    help="database to look at, default the project one")
    ap.add_argument("--delete", action="store_true",
                    help="actually remove the invented sensor rows")
    args = ap.parse_args()

    if args.db:
        db = pathlib.Path(args.db)
    else:
        from core import memory_engine as me
        db = pathlib.Path(me.DB_PATH)

    if not db.exists():
        print(f"No database at {db}. Nothing to look at.")
        return 1

    print(f"Database: {db}")
    print(f"Size:     {db.stat().st_size / 1_000_000_000:.2f} GB\n")

    uri = f"file:{db}?mode=ro" if not args.delete else str(db)
    conn = sqlite3.connect(uri, uri=not args.delete)
    conn.row_factory = sqlite3.Row
    try:
        total = conn.execute("SELECT COUNT(*) FROM sensors").fetchone()[0]
        n = conn.execute(f"SELECT COUNT(*) FROM sensors WHERE {SENSOR_WHERE}",
                         (OFFLINE_SUMMARY,)).fetchone()[0]
        print(f"sensors: {total} rows in total")
        print(f"  {n} of them are the pcap test's invented offline sensors")
        if n:
            # Dates matter to whoever is deciding. A spread of dates says the
            # suite has been run on several days; one date says once.
            days = conn.execute(
                f"SELECT substr(first_seen,1,10) AS d, COUNT(*) AS c "
                f"FROM sensors WHERE {SENSOR_WHERE} GROUP BY d ORDER BY d",
                (OFFLINE_SUMMARY,)).fetchall()
            for r in days:
                print(f"    {r['d']}  {r['c']}")

        # WHAT ELSE POINTS AT THESE ROWS
        #
        # Added 2026-09-14 after the first real run of this script, which
        # found 207 rows across 23 suite runs. Deleting a sensor is not a
        # local act: thirteen tables carry a sensor_id REFERENCES
        # sensors(sensor_id), which is the app's whole story about where a
        # piece of evidence was seen from. Removing a sensor that something
        # still points at turns "seen from the host sensor" into a dangling
        # id, and the honest reading of a dangling vantage point is that the
        # app no longer knows where the evidence came from.
        #
        # Expected to be zero here, because the pcap test registers the
        # sensor and then throws the analysis away without storing packets or
        # results. Expected is not the same as checked. If it is not zero,
        # the script says so and refuses, because at that point somebody has
        # to decide what those rows mean, and it is not this script.
        orphans = _referencing(conn, OFFLINE_SUMMARY) if n else []
        print()
        if not n:
            # Caught on the first clean run, 2026-09-14. This used to print
            # "nothing else points at those rows, checked, not assumed" even
            # when there were no rows to point at. True, and meaningless, and
            # it reads as a reassurance about a check that had nothing to
            # check. Same fault as a search saying "it is not there" when it
            # could not search.
            print("No sensor rows to check for references, there are none "
                  "left to delete.")
        elif orphans:
            print("OTHER TABLES POINT AT THOSE SENSOR ROWS:")
            for table, count in orphans:
                print(f"    {table}: {count} rows")
            print("  Deleting the sensors would leave those pointing at "
                  "nothing, so the app")
            print("  would no longer know where that evidence was seen from. "
                  "Not deleting.")
        else:
            print("Nothing else in the database points at those sensor rows. "
                  "Checked, not assumed.")

        print()
        q = conn.execute(
            "SELECT id, indicator, reason, requested_at, state "
            "FROM enrichment_queue WHERE requested_by = 'inspect_process' "
            "AND reason LIKE 'process python%' ORDER BY requested_at"
        ).fetchall()
        print(f"enrichment_queue: {len(q)} rows that MIGHT be the test's")
        print("  These are not deleted by this script and never will be. A "
              "real inspect_process")
        print("  call on a python process on this machine writes a row that "
              "looks the same,")
        print("  so only you can tell them apart. Read them and decide.")
        for r in q:
            print(f"    id={r['id']}  {r['requested_at']}  {r['state']}  "
                  f"{r['reason']}")

        if not args.delete:
            print("\nNothing was changed. The database was opened read only.")
            if n and not orphans:
                print("Run again with --delete to remove the "
                      f"{n} sensor rows above.")
            elif n and orphans:
                print("--delete will REFUSE while other tables point at "
                      "those rows.")
            return 0

        if not n:
            print("\nNo sensor rows to remove.")
            return 0

        if orphans:
            # The whole reason the check runs before the delete. Better to
            # leave 207 harmless rows in place than to break the one thing
            # the sensors table exists for, which is being able to say where
            # a piece of evidence was seen from.
            print("\nREFUSING. Rows in other tables point at these sensors, "
                  "listed above.")
            print("Deleting them would leave the app unable to say where "
                  "that evidence came from.")
            print("Nothing was changed.")
            return 1

        cur = conn.execute(f"DELETE FROM sensors WHERE {SENSOR_WHERE}",
                           (OFFLINE_SUMMARY,))
        conn.commit()
        left = conn.execute(f"SELECT COUNT(*) FROM sensors WHERE "
                            f"{SENSOR_WHERE}", (OFFLINE_SUMMARY,)).fetchone()[0]
        print(f"\nDeleted {cur.rowcount} rows. {left} matching rows remain.")
        print("enrichment_queue was not touched.")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
