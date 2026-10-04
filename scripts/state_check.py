"""
scripts/state_check.py

Read-only look at the database. Answers two questions we had open:

  1. is the config snapshot actually being written to the integrity journal
  2. what is actually filling up 1.2 GB

Run it from the project root:

    python scripts/state_check.py

Written as a file on purpose. The one-liner version of this got mangled by
PowerShell twice, because PowerShell eats quotes and treats < > as
redirection. Same lesson as the verify_integrity.py usage line: this project
runs on Windows first, so anything meant to be pasted goes in a file.

Opens the database read-only. It cannot change anything.
"""

import os
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "agental_sec.db"


def main():
    if not DB.exists():
        print(f"No database at {DB}")
        return 1

    size_gb = DB.stat().st_size / (1024 ** 3)
    print(f"Database: {DB.name}  ({size_gb:.2f} GB)\n")

    conn = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)

    # 1. CONFIG SNAPSHOTS
    print("=" * 60)
    print("CONFIG SNAPSHOTS (integrity journal)")
    print("=" * 60)
    try:
        rows = conn.execute(
            "SELECT id, recorded_at, row_ref FROM integrity_journal "
            "WHERE operation = 'config_observed' ORDER BY id"
        ).fetchall()
        if not rows:
            print("  NONE. The boot snapshot is not running. Needs looking at.")
        else:
            for r in rows:
                print(f"  #{r[0]}  {r[1]}  ({r[2]})")
            print(f"\n  {len(rows)} snapshot(s).")
            if len(rows) == 1:
                print("  One is correct so far: it only writes when the "
                      "config CHANGES.")
            else:
                print("  More than one means the preferences changed between "
                      "boots. Worth knowing why.")
    except sqlite3.Error as e:
        print(f"  Could not read the journal: {e}")

    # Whole journal, for context.
    try:
        print("\n  Everything else in the journal:")
        for op, n in conn.execute(
                "SELECT operation, COUNT(*) FROM integrity_journal "
                "GROUP BY operation ORDER BY COUNT(*) DESC"):
            print(f"    {op:24} {n}")
    except sqlite3.Error:
        pass

    # 2. WHAT IS ACTUALLY BIG
    print("\n" + "=" * 60)
    print("ROW COUNTS, BIGGEST FIRST")
    print("=" * 60)
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name")]

    counts = []
    for t in tables:
        try:
            counts.append((t, conn.execute(
                f"SELECT COUNT(*) FROM {t}").fetchone()[0]))
        except sqlite3.Error as e:
            counts.append((t, f"error: {e}"))

    counts.sort(key=lambda x: x[1] if isinstance(x[1], int) else -1,
                reverse=True)
    total = sum(c for _, c in counts if isinstance(c, int))
    for t, c in counts:
        if isinstance(c, int) and total:
            print(f"  {t:26} {c:>12,}   {c / total * 100:5.1f}%")
        else:
            print(f"  {t:26} {c}")
    print(f"  {'TOTAL':26} {total:>12,}")

    # 3. HOW FAR BACK DOES THE BIG STUFF GO
    print("\n" + "=" * 60)
    print("AGE OF THE BIGGEST TABLES")
    print("=" * 60)
    print("How much of this is old enough that retention would delete it.\n")

    # Column names checked against Schema.SQL, not guessed.
    time_col = {
        "packets":            "captured_at",
        "events":             "occurred_at",
        "dns_queries":        "queried_at",
        "findings":           "found_at",
        "behavioral_session": "observed_at",
        "session_log":        "logged_at",
        "presence_sweep":     "swept_at",
        "port_scan_results":  "scanned_at",
    }

    for t, c in counts[:10]:
        if not isinstance(c, int) or c == 0:
            continue
        col = time_col.get(t)
        if col is None:
            continue
        try:
            lo, hi = conn.execute(
                f"SELECT MIN({col}), MAX({col}) FROM {t}").fetchone()
            older = conn.execute(
                f"SELECT COUNT(*) FROM {t} "
                f"WHERE {col} < datetime('now', '-7 days')").fetchone()[0]
            older4 = conn.execute(
                f"SELECT COUNT(*) FROM {t} "
                f"WHERE {col} < datetime('now', '-4 days')").fetchone()[0]
            print(f"  {t}")
            print(f"    oldest row      {lo}")
            print(f"    newest row      {hi}")
            print(f"    older than 7d   {older:,}  ({older / c * 100:.0f}%)")
            print(f"    older than 4d   {older4:,}  ({older4 / c * 100:.0f}%)")
        except sqlite3.Error as e:
            print(f"  {t}: could not read {col} ({e})")

    conn.close()
    print("\nDone. Nothing was changed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
