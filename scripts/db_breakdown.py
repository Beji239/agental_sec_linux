"""
scripts/db_breakdown.py

Where the database size actually goes. Read only, changes nothing, ever.

    python scripts/db_breakdown.py                 # the fast pass
    python scripts/db_breakdown.py --pages         # add real page usage, SLOW
    python scripts/db_breakdown.py --db other.db

WHY THIS EXISTS

TODO section 34. The owner's number: about 8 hours of running produced 1.6 GB,
so roughly 200 MB per hour. Section 23.5 had assumed 100 MB per calendar day,
which is out by a mile, and every duration figure that came from it is wrong.

Before anyone changes what a packet row stores, we should know what a packet
row actually costs. This project's own retention rule is measure first, and
rows already written cannot be un-shrunk, so guessing here would be the same
class of mistake as a prune that deletes too much.

WHAT IT DOES NOT DO
No deletes, no vacuum, no writes of any kind. It opens the file read only at
the SQLite level, so a bug in here cannot damage anything even if it tried.
Safe to run while the app is up, though the numbers move under you a little
if the sniffer is busy.

THE TWO PASSES
The fast pass counts rows and adds up column lengths. On a 1.6 GB file expect
a minute or so, because it reads every row.

--pages uses the dbstat virtual table, which walks every page in the file and
gives the REAL cost including indexes. It is much slower, several minutes,
and it is the only way to find out whether an index is worth what it takes.
Not every Python ships with dbstat compiled in; if yours does not, the script
says so instead of pretending.
"""

import argparse
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
DB = ROOT / "agental_sec.db"

from core import retention as rt  # noqa: E402  (human_bytes, _payload_expr)


def open_ro(path):
    """
    Read only at the SQLite level, not by convention.

    Same reasoning as memory_engine._get_readonly_conn: a write attempted
    through this handle fails inside SQLite whatever the calling code meant.
    A comment saying "does not write" is a request. This is a fact.
    """
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


def file_sizes(path):
    out, total = {}, 0
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(path) + suffix)
        n = p.stat().st_size if p.exists() else 0
        if n:
            out[p.name] = n
        total += n
    return out, total


def tables(conn):
    return [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name")]


def column_costs(conn, table):
    """Average and total stored length, per column, for one table."""
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
    if not cols:
        return 0, []
    parts = ", ".join(
        f"SUM(COALESCE(LENGTH(CAST({c} AS BLOB)),0))" for c in cols)
    row = conn.execute(f"SELECT COUNT(*), {parts} FROM {table}").fetchone()
    n = row[0] or 0
    sizes = [(c, row[i + 1] or 0) for i, c in enumerate(cols)]
    sizes.sort(key=lambda t: -t[1])
    return n, sizes


def page_usage(conn):
    """
    Real bytes per table AND per index, from dbstat.

    This is the only way to see what an index costs. It is slow because it
    walks the whole file, and it is not always available.
    """
    try:
        rows = conn.execute(
            "SELECT name, SUM(pgsize) FROM dbstat GROUP BY name "
            "ORDER BY 2 DESC").fetchall()
    except sqlite3.OperationalError as e:
        return None, str(e)
    return rows, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=str(DB))
    ap.add_argument("--pages", action="store_true",
                    help="real page usage including indexes. SLOW.")
    ap.add_argument("--top", type=int, default=8,
                    help="how many columns to show per table (default 8)")
    args = ap.parse_args()

    path = Path(args.db)
    if not path.exists():
        print(f"No database at {path}")
        return 1

    parts, total = file_sizes(path)
    print(f"\nFILE ON DISK   {rt.human_bytes(total)}")
    for name, n in parts.items():
        print(f"    {name:<44} {rt.human_bytes(n)}")
    print("\nThe -wal file counts. In WAL mode committed data can sit there a")
    print("long time before a checkpoint moves it into the main file.")

    conn = open_ro(path)
    try:
        print("\n\nROWS AND STORED COLUMN LENGTH, BY TABLE")
        print("Column lengths are the DATA only. Indexes and page overhead")
        print("are not in this number, so the totals here will come out")
        print("BELOW the file size. That gap is what --pages measures.\n")

        summary = []
        for t in tables(conn):
            try:
                n, sizes = column_costs(conn, t)
            except sqlite3.Error as e:
                print(f"  {t:<26} could not measure: {e}")
                continue
            payload = sum(s for _, s in sizes)
            summary.append((payload, t, n, sizes))

        summary.sort(reverse=True)
        for payload, t, n, sizes in summary:
            if not n:
                continue
            share = (payload / total * 100) if total else 0
            print(f"  {t:<26} {n:>10,} rows   "
                  f"{rt.human_bytes(payload):>10}   {share:5.1f}% of file"
                  f"   {rt.human_bytes(payload / n if n else 0)}/row")

        # The one everybody actually wants. Broken out per column so the
        # question "what is a packet row made of" has an answer rather than
        # an argument.
        for payload, t, n, sizes in summary:
            if t != "packets" or not n:
                continue
            print(f"\n\nINSIDE A PACKET ROW  ({n:,} rows)")
            print("Biggest columns first. This is the table that decides the")
            print("size of the whole file.\n")
            for col, size in sizes[:args.top]:
                pct = (size / payload * 100) if payload else 0
                print(f"  {col:<20} {rt.human_bytes(size):>10}   "
                      f"{pct:5.1f}% of the table   "
                      f"{rt.human_bytes(size / n):>9}/row")

            # payload_snippet is stored as hex, so it is twice the bytes it
            # describes. Worth saying out loud because "256 bytes of payload"
            # sounds small and 512 characters of text is not.
            snip = dict(sizes).get("payload_snippet", 0)
            if snip:
                filled = conn.execute(
                    "SELECT COUNT(*) FROM packets "
                    "WHERE payload_snippet IS NOT NULL").fetchone()[0]
                flagged = conn.execute(
                    "SELECT COUNT(*) FROM packets "
                    "WHERE payload_snippet IS NOT NULL "
                    "AND threat_label IS NOT NULL").fetchone()[0]
                unflagged = filled - flagged
                print(f"\n  payload_snippet is on {filled:,} of {n:,} rows "
                      f"({filled / n * 100:.0f}%).")
                print(f"  Of those, {flagged:,} are on a FLAGGED row.")

                # Since 2026-09-01 the sniffer only stores a payload on a
                # flagged row, so on a database that has had
                # scripts/reclaim_packet_space.py run there is nothing left to
                # offer. Saying "you could save about 0 B" is technically true
                # and reads like the script is confused, so say the useful
                # thing instead. See TODO 34.
                if unflagged:
                    print("  It is stored as hex, so it costs twice the bytes")
                    print("  it describes. Dropping it from unflagged rows")
                    print(f"  would save about "
                          f"{rt.human_bytes(snip * unflagged / filled)} of "
                          f"column data,")
                    print("  before counting whatever the indexes give back.")
                    print("  scripts/reclaim_packet_space.py does exactly "
                          "that.")
                else:
                    print("  Every one of them is flagged, so there is nothing")
                    print("  here to reclaim. This is what the table should")
                    print("  look like. See TODO 34.")

        if args.pages:
            print("\n\nREAL PAGE USAGE, TABLES AND INDEXES")
            print("Walking every page. This takes a while on a big file.\n")
            rows, err = page_usage(conn)
            if err:
                print(f"  dbstat is not available in this Python: {err}")
                print("  Not a problem with the database. The fast numbers")
                print("  above still stand, they just exclude indexes.")
            else:
                # Anything under half a percent is noise. A real database has
                # dozens of tiny autoindexes and printing them all buries the
                # three lines that matter.
                shown = 0
                hidden_bytes = 0
                for name, size in rows:
                    share = (size / total * 100) if total else 0
                    if share < 0.5 and shown >= 3:
                        hidden_bytes += size
                        continue
                    kind = "index" if "idx_" in name or "autoindex" in name \
                           else "table"
                    print(f"  {name:<34} {kind:<6} "
                          f"{rt.human_bytes(size):>10}  {share:5.1f}%")
                    shown += 1
                if hidden_bytes:
                    print(f"  {'everything else':<34} {'':<6} "
                          f"{rt.human_bytes(hidden_bytes):>10}  "
                          f"{hidden_bytes / total * 100:5.1f}%")
                print("\n  An index costing more than the rows it points at is")
                print("  worth a conversation. Do not drop one from this list")
                print("  alone though: check what queries use it first.")
        else:
            print("\n\nIndexes are NOT counted above. Run again with --pages")
            print("to see them, it is slow but it is the honest number.")
    finally:
        conn.close()

    print("\n\nNothing was changed. This script only reads.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
