# scripts/alerts_diag.py
# Where did the alerts on the Alerts tab come from, and WHEN.
#
# Written 2026-09-13. The Alerts tab went from quiet to 28 CRITICAL rows
# between two boots on the same evening, and the amber fix landed between
# them. That is a fair thing to suspect, and suspecting it is not the same as
# knowing, so this measures instead of arguing.
#
# The specific question it answers: were these findings written TONIGHT, or
# have they been in the database for days and something only just stopped
# hiding them. Those two answers point at completely different causes and
# nothing on the screen tells them apart.
#
# READ ONLY. Opens the database in SQLite's read only mode, same as
# split_diag.py, so it is safe to run while the app is up.
#
# Run it from the project root:
#     python scripts/alerts_diag.py
#     python scripts/alerts_diag.py --days 10

import argparse
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_DB = os.path.join(ROOT, "agental_sec.db")


def connect(path):
    if not os.path.exists(path):
        sys.exit(f"No database at {path}")
    uri = "file:" + path.replace("\\", "/") + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def rule(title):
    print()
    print(title)
    print("," * len(title))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--days", type=int, default=14)
    args = ap.parse_args()

    conn = connect(args.db)

    # REMEMBER: sqlite stores UTC and the log prints local. A 7 hour gap
    # between this output and the log is the timezone, not a bug. That cost a
    # round of confusion on 2026-09-08.
    print(f"Database: {args.db}")
    print("Times below are UTC, the way sqlite stored them. The app log is "
          "local, so expect an offset.")

    rule("1. What is actually ON the Alerts tab right now")
    # The tab shows undismissed findings, so that is what gets counted here.
    # Counting every row including dismissed ones would answer a question
    # nobody asked and would not match the badge.
    rows = conn.execute("""
        SELECT severity, COUNT(*) AS n
        FROM findings WHERE dismissed = 0
        GROUP BY severity ORDER BY n DESC
    """).fetchall()
    total = sum(r["n"] for r in rows)
    print(f"   {total} active finding(s)")
    for r in rows:
        print(f"     {r['severity']:>8}: {r['n']}")

    rule("2. Active findings by title, biggest first")
    for r in conn.execute("""
        SELECT title, source, severity, COUNT(*) AS n,
               MIN(found_at) AS first_seen, MAX(found_at) AS last_seen
        FROM findings WHERE dismissed = 0
        GROUP BY title, source, severity
        ORDER BY n DESC LIMIT 20
    """):
        print(f"   {r['n']:>4}  {r['severity']:>8}  {r['source']}")
        print(f"         {r['title'][:90]}")
        print(f"         first {r['first_seen']}   last {r['last_seen']}")

    rule("3. THE QUESTION: are the Defender rows new, or old?")
    # If these go back days, the code that writes them did not change tonight
    # and the amber fix is not in the frame. If they all landed tonight, then
    # either Defender scanned something today or something did change.
    d = conn.execute("""
        SELECT COUNT(*) AS n,
               COUNT(DISTINCT entity_value) AS threats,
               COUNT(DISTINCT session_id) AS sessions,
               MIN(found_at) AS first_seen,
               MAX(found_at) AS last_seen
        FROM findings
        WHERE title LIKE 'Defender detection:%'
    """).fetchone()
    print(f"   {d['n']} Defender finding(s) in the whole database, ever")
    print(f"   across {d['sessions']} session(s), {d['threats']} distinct ThreatID(s)")
    print(f"   earliest {d['first_seen']}")
    print(f"   latest   {d['last_seen']}")
    if not d["n"]:
        print("   None at all. Then the Alerts tab is showing something else.")

    rule("4. Defender findings per day")
    for r in conn.execute("""
        SELECT DATE(found_at) AS day, COUNT(*) AS n,
               SUM(CASE WHEN dismissed = 0 THEN 1 ELSE 0 END) AS active
        FROM findings
        WHERE title LIKE 'Defender detection:%'
        GROUP BY DATE(found_at) ORDER BY day DESC LIMIT ?
    """, (args.days,)):
        print(f"   {r['day']}   {r['n']:>4} written, {r['active']:>4} still active")

    rule("5. Defender findings per session, newest first")
    # Two boots in one evening is the case that matters here, so the session
    # is the unit, not the day.
    for r in conn.execute("""
        SELECT session_id, COUNT(*) AS n,
               MIN(found_at) AS first_seen, MAX(found_at) AS last_seen
        FROM findings
        WHERE title LIKE 'Defender detection:%'
        GROUP BY session_id ORDER BY MAX(found_at) DESC LIMIT 10
    """):
        print(f"   {r['session_id'][:8]}  {r['n']:>4}  "
              f"{r['first_seen']} to {r['last_seen']}")

    rule("6. ALL findings per session, so the Defender ones have a scale")
    for r in conn.execute("""
        SELECT session_id, COUNT(*) AS n,
               SUM(CASE WHEN dismissed = 0 THEN 1 ELSE 0 END) AS active,
               MIN(found_at) AS started, MAX(found_at) AS ended
        FROM findings
        GROUP BY session_id ORDER BY MAX(found_at) DESC LIMIT 10
    """):
        print(f"   {r['session_id'][:8]}  {r['n']:>5} written, "
              f"{r['active']:>5} active   {r['started']} to {r['ended']}")

    rule("7. Was anything dismissed, and when")
    # A wave of alerts that were always there but got un-hidden would show up
    # as old rows with dismissed = 0. This is the check for that.
    r = conn.execute("""
        SELECT COUNT(*) AS n, MAX(dismissed_at) AS last
        FROM findings WHERE dismissed = 1
    """).fetchone()
    print(f"   {r['n']} finding(s) dismissed in total, most recent {r['last']}")

    rule("8. The masquerading rows, since they were the other flood")
    r = conn.execute("""
        SELECT COUNT(*) AS n,
               SUM(CASE WHEN dismissed = 0 THEN 1 ELSE 0 END) AS active
        FROM findings WHERE title LIKE 'Suspicious process%'
    """).fetchone()
    print(f"   {r['n']} suspicious-process finding(s), {r['active']} still active")

    print()
    print("HOW TO READ THIS. If section 3 says the earliest Defender row is "
          "days old, then the writer did not change tonight and the amber fix "
          "is not the cause. If every one of them is from tonight's second "
          "boot, that is worth chasing properly.")


if __name__ == "__main__":
    main()
