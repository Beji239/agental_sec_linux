#!/usr/bin/env python3
"""
Print behavioral observations in full, read-only, so a person can decide what
to do with them before anything is written.

    python scripts/show_observations.py 131 132 133 134
    python scripts/show_observations.py --range 131 134
    python scripts/show_observations.py --unrecorded

No angle brackets in the usage above on purpose: this project runs on Windows
first and PowerShell treats < and > as redirection operators. Same point as
TODO 17a.

WHY THIS EXISTS. TODO 43.6 leaves four rows needing a human decision, and the
28.2 process failure says why one is needed: a withdrawal that gets typed from
a summary withdraws real data. scripts/find_availability_notes.py already
printed the command and refused to run it; this is the same shape, one step
earlier, it shows the whole row, including the fields query_behavioral_session
does not return, so the decision is made against the row and not against a
description of it.

THIS SCRIPT NEVER WRITES. It opens the database read-only, at the URI level,
so a bug in it cannot become a bug in the data. It does not run migrations
either, deliberately: migrations are a write, and a script whose only job is
to show you something has no business taking a lock on an 800MB database while
the app may be running. A missing column is reported as missing.

WHAT THE ROLLUP FOOTER IS FOR. Withdrawing a session observation marks that
row and nothing else. run_rollup reads current observations only, so a
withdrawal keeps the row out of FUTURE merges, but behavioral_baseline is
cumulative and forward-only, and there is no back-out path. If the row has
already been merged, the baseline it fed keeps the count it gained. The footer
tells you whether that has happened yet, because that is the difference
between withdrawing a row and actually retracting what it caused.
"""

import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "agental_sec.db"

FIELDS = [
    "id", "session_id", "observed_at", "entity_type", "entity_value",
    "behavior_key", "behavior_value", "context", "written_by",
    "basis", "basis_ref",
    "evidence_untrusted", "evidence_sources", "sensor_id",
    "superseded_by", "superseded_reason",
]


def open_ro() -> sqlite3.Connection:
    if not DB_PATH.exists():
        print(f"No database at {DB_PATH}.")
        sys.exit(1)
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def available_columns(conn: sqlite3.Connection) -> list[str]:
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(behavioral_session)")}
    missing = [f for f in FIELDS if f not in cols]
    if missing:
        print(f"NOTE: this database has no {', '.join(missing)} column yet, so "
              f"those are not shown. Start AgentalSec once to migrate.\n")
    return [f for f in FIELDS if f in cols]


def show(conn: sqlite3.Connection, ids: list[int]) -> None:
    cols = available_columns(conn)
    placeholders = ",".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT {', '.join(cols)} FROM behavioral_session "
        f"WHERE id IN ({placeholders}) ORDER BY id",
        ids,
    ).fetchall()

    found = {r["id"] for r in rows}
    for missing_id in [i for i in ids if i not in found]:
        print(f"--- {missing_id}: no such observation ---\n")

    for row in rows:
        print("=" * 78)
        state = "WITHDRAWN" if row["superseded_by"] is not None else "current"
        basis = row["basis"] if "basis" in row.keys() else None
        print(f"observation {row['id']}   [{state}]   "
              f"basis: {basis or 'NULL, unrecorded, never counted as measured'}")
        print("=" * 78)
        for col in cols:
            if col in ("id", "basis"):
                continue
            value = row[col]
            if value is None or value == "":
                continue
            text = str(value)
            if len(text) > 2000:
                text = text[:2000] + f"  ... [{len(str(value))} chars total]"
            print(f"  {col:<18} {text}")
        rollup_footer(conn, row)
        print()


def rollup_footer(conn: sqlite3.Connection, row: sqlite3.Row) -> None:
    """Has this observation already been merged into the baseline it feeds?"""
    try:
        seen = conn.execute(
            "SELECT COUNT(*) AS n FROM baseline_session_seen "
            "WHERE entity_type = ? AND entity_value = ? AND behavior_key = ? "
            "AND session_id = ?",
            (row["entity_type"], row["entity_value"],
             row["behavior_key"], row["session_id"]),
        ).fetchone()["n"]
        base = conn.execute(
            "SELECT sample_count, confidence FROM behavioral_baseline "
            "WHERE entity_type = ? AND entity_value = ? AND behavior_key = ?",
            (row["entity_type"], row["entity_value"], row["behavior_key"]),
        ).fetchone()
    except sqlite3.OperationalError as e:
        print(f"  (could not check the rollup state: {e})")
        return

    print("  " + "-" * 74)
    if seen:
        print("  ALREADY ROLLED UP. This session counted toward the baseline for "
              "this key.")
        print("  Withdrawing the row keeps it out of future merges. It does NOT "
              "remove what")
        print("  it already contributed, behavioral_baseline is cumulative and "
              "forward-only.")
    else:
        print("  Not yet merged into behavioral_baseline for this key. Withdrawing "
              "now is clean.")
    if base:
        print(f"  baseline for this key: sample_count={base['sample_count']}, "
              f"confidence={base['confidence']}")


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0

    conn = open_ro()

    if args[0] == "--unrecorded":
        rows = conn.execute(
            "SELECT id FROM behavioral_session WHERE basis IS NULL "
            "AND superseded_by IS NULL ORDER BY id"
        ).fetchall()
        if not rows:
            print("No current observations are missing a basis.")
            return 0
        ids = [r["id"] for r in rows]
        print(f"{len(ids)} current observations carry no basis: "
              f"{', '.join(str(i) for i in ids)}\n")
        show(conn, ids)
        return 0

    if args[0] == "--range":
        if len(args) < 3:
            print("--range needs a first and last id.")
            return 1
        ids = list(range(int(args[1]), int(args[2]) + 1))
    else:
        try:
            ids = [int(a) for a in args]
        except ValueError:
            print("Arguments must be observation ids, or --range FIRST LAST.")
            return 1

    show(conn, ids)
    print("Nothing was written. Withdraw with scripts/withdraw_observation.py "
          "once you have read the rows.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
