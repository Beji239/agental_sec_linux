# scripts/split_diag.py
# What did the last few runs actually record.
#
# Written 2026-09-08. The two hour split run ended with a frozen terminal and
# a reboot, and the log could not say whether the sensors had been doing any
# work at all in that time. query_packets said zero for that run while history
# held 3.3 million rows, and zero has two very different meanings: nothing
# happened on the network, or nobody was looking. This tells them apart.
#
# READ ONLY. Opens the database in SQLite's read only mode on purpose, so
# this can be run while the app is up without any chance of it being the
# thing that corrupts a 1.4 GB file.
#
# Run it from the project root:
#     python scripts/split_diag.py
#     python scripts/split_diag.py --sessions 12

import argparse
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_DB = os.path.join(ROOT, "agental_sec.db")

# table, its session column, its timestamp column, what to call it on screen.
# Kept as data rather than as five near identical queries, so adding a table
# later is one line and not a copy paste.
TABLES = [
    ("packets", "session_id", "captured_at", "packets"),
    ("findings", "session_id", "found_at", "findings"),
    ("events", "session_id", "occurred_at", "events"),
    ("behavioral_session", "session_id", "observed_at", "observations"),
]


def connect(path):
    if not os.path.exists(path):
        sys.exit(f"No database at {path}")
    uri = "file:" + path.replace("\\", "/") + "?mode=ro"
    return sqlite3.connect(uri, uri=True)


def has_table(conn, name):
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


def columns(conn, table):
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def recent_sessions(conn, limit):
    """
    The last N session ids, newest first, by the newest row any table holds
    for them. Built as a union rather than from one table, because a run that
    captured nothing would be invisible if we only looked at packets, and a
    run that captured nothing is the exact thing we are hunting.
    """
    parts = []
    for table, sid, ts, _label in TABLES:
        if not has_table(conn, table):
            continue
        cols = columns(conn, table)
        if sid not in cols or ts not in cols:
            continue
        parts.append(f"SELECT {sid} AS sid, MAX({ts}) AS last_at FROM {table} GROUP BY {sid}")

    if not parts:
        return []

    sql = ("SELECT sid, MAX(last_at) AS last_at FROM (" + " UNION ALL ".join(parts) +
           ") GROUP BY sid ORDER BY last_at DESC LIMIT ?")
    return conn.execute(sql, (limit,)).fetchall()


def counts_for(conn, sid):
    out = {}
    for table, sidcol, ts, label in TABLES:
        if not has_table(conn, table):
            out[label] = None
            continue
        cols = columns(conn, table)
        if sidcol not in cols:
            out[label] = None
            continue
        if ts in cols:
            row = conn.execute(
                f"SELECT COUNT(*), MIN({ts}), MAX({ts}) FROM {table} WHERE {sidcol}=?",
                (sid,)).fetchone()
            out[label] = {"count": row[0], "first": row[1], "last": row[2]}
        else:
            row = conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE {sidcol}=?", (sid,)).fetchone()
            out[label] = {"count": row[0], "first": None, "last": None}
    return out


def masquerading(conn, sid):
    """
    The known step 4 false positives. Genuine Windows binaries flagged as
    masquerading because psutil hands back a path with no drive letter under
    the restricted token, so the System32 comparison fails.

    Counted separately because seventeen of these in a session is a very
    different story from seventeen real ones, and the count alone does not
    say which.
    """
    if not has_table(conn, "findings"):
        return None
    rows = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE session_id=? AND "
        "(title LIKE '%masquerad%' OR raw_data LIKE '%masquerading_system_binary%')",
        (sid,)).fetchone()
    total = rows[0]
    if not total:
        return {"total": 0, "no_drive_letter": 0}

    # A path starting with a backslash and no drive letter is the tell.
    nodrive = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE session_id=? AND "
        "(title LIKE '%masquerad%' OR raw_data LIKE '%masquerading_system_binary%') AND "
        "raw_data LIKE '%\"\\\\Windows\\\\%'",
        (sid,)).fetchone()[0]
    return {"total": total, "no_drive_letter": nodrive}


def main():
    ap = argparse.ArgumentParser(description="What the last few runs recorded.")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--sessions", type=int, default=8)
    args = ap.parse_args()

    conn = connect(args.db)
    size_mb = os.path.getsize(args.db) / (1024.0 * 1024.0)
    print(f"\n{args.db}")
    print(f"{size_mb:,.0f} MB\n")

    sessions = recent_sessions(conn, args.sessions)
    if not sessions:
        print("No sessions found in any table.")
        return

    for sid, last_at in sessions:
        c = counts_for(conn, sid)
        pk = c.get("packets") or {}
        span = ""
        if pk.get("first") and pk.get("last"):
            span = f"  {pk['first']} to {pk['last']}"

        print(f"session {sid}   last row {last_at}")
        for _t, _s, _ts, label in TABLES:
            info = c.get(label)
            if info is None:
                print(f"    {label:14} table not present")
                continue
            print(f"    {label:14} {info['count']:>8,}")

        if pk.get("count") == 0:
            print("    NOTE: zero packets. Either nothing was on the wire, or "
                  "the sniffer could not see. The log's blind flag is the "
                  "thing that tells those apart.")
        elif span:
            print(f"    packets ran{span}")

        m = masquerading(conn, sid)
        if m and m["total"]:
            print(f"    masquerading findings {m['total']:,}, of which "
                  f"{m['no_drive_letter']:,} have a path with no drive letter "
                  f"(the known step 4 false positive)")
        print()

    conn.close()


if __name__ == "__main__":
    main()
