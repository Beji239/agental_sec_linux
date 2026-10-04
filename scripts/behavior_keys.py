"""
scripts/behavior_keys.py

What is the model ACTUALLY writing into the behavioural tables?

The retention question turns on one thing: when raw packets are deleted, does
the baseline still hold enough to answer "this device beacons every N hours"?
If the model is already writing a timing style behaviour key, retention costs
us almost nothing and the job is small. If it is not, we have to decide
whether to add one before anything gets pruned.

This does not guess. It reads what is in the database.

Run from the project root:

    python scripts/behavior_keys.py

Opens the database read-only. It cannot change anything.
"""

import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "agental_sec.db"

# Words that would mean the model is recording SPACING, not just presence.
TIMING_WORDS = ("interval", "beacon", "gap", "period", "cadence", "freq",
                "rate", "per_hour", "per_day", "spacing", "regular")


def section(title):
    print("\n" + "=" * 64)
    print(title)
    print("=" * 64)


def main():
    if not DB.exists():
        print(f"No database at {DB}")
        return 1
    conn = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    # 1. THE KEYS THEMSELVES
    section("BEHAVIOUR KEYS IN behavioral_baseline")
    keys = conn.execute(
        "SELECT behavior_key, COUNT(*) n, "
        "       COUNT(DISTINCT entity_value) entities, "
        "       SUM(sample_count) samples "
        "FROM behavioral_baseline GROUP BY behavior_key "
        "ORDER BY n DESC").fetchall()
    if not keys:
        print("  none yet")
    for r in keys:
        mark = "  <-- timing" if any(
            w in (r["behavior_key"] or "").lower() for w in TIMING_WORDS) else ""
        print(f"  {r['behavior_key']:<34} rows={r['n']:<5} "
              f"entities={r['entities']:<4} samples={r['samples']}{mark}")

    section("BEHAVIOUR KEYS IN behavioral_session (raw observations)")
    for r in conn.execute(
            "SELECT behavior_key, COUNT(*) n FROM behavioral_session "
            "GROUP BY behavior_key ORDER BY n DESC"):
        mark = "  <-- timing" if any(
            w in (r["behavior_key"] or "").lower() for w in TIMING_WORDS) else ""
        print(f"  {r['behavior_key']:<34} {r['n']}{mark}")

    # 2. IS TIMING CAPTURED ANYWHERE
    section("IS SPACING / TIMING RECORDED ANYWHERE?")
    hits = [r["behavior_key"] for r in keys
            if any(w in (r["behavior_key"] or "").lower() for w in TIMING_WORDS)]
    if hits:
        print("  YES. These keys look like timing:")
        for h in hits:
            print(f"    {h}")
        print("\n  If these hold real numbers, retention costs us very little.")
    else:
        print("  NO timing-shaped key found in behavior_key.")
        print("  Checking whether the model wrote it into notes instead...")
        n = 0
        for r in conn.execute(
                "SELECT entity_value, behavior_key, model_notes "
                "FROM behavioral_baseline WHERE model_notes IS NOT NULL"):
            note = r["model_notes"] or ""
            if re.search(r"\b\d+\s*(m|min|minute|h|hr|hour|s|sec|second)s?\b"
                         r"|every\s+\d+|interval|beacon", note, re.I):
                print(f"    {r['entity_value']} / {r['behavior_key']}")
                print(f"      {note[:220]}")
                n += 1
                if n >= 6:
                    break
        if n == 0:
            print("    Nothing in the notes either.")

    # 3. WHAT A REAL ROW LOOKS LIKE
    section("SAMPLE BASELINE ROWS, HIGHEST CONFIDENCE FIRST")
    for r in conn.execute(
            "SELECT * FROM behavioral_baseline "
            "ORDER BY CASE confidence WHEN 'high' THEN 3 WHEN 'medium' THEN 2 "
            "ELSE 1 END DESC, sample_count DESC LIMIT 5"):
        print(f"\n  {r['entity_type']}:{r['entity_value']}  [{r['behavior_key']}]")
        print(f"    confidence   {r['confidence']}  "
              f"(sessions={r['sample_count']}, suppressed={r['alert_suppressed']})")
        print(f"    mean/stddev  {r['value_mean']} / {r['value_stddev']}  "
              f"min={r['value_min']} max={r['value_max']}")
        print(f"    hours        {r['typical_hours']}")
        print(f"    dest ports   {r['typical_dest_ports']}")
        print(f"    dest ips     {str(r['typical_dest_ips'])[:150]}")
        print(f"    first seen   {r['first_seen']}")
        notes = (r["model_notes"] or "")[:300]
        print(f"    notes        {notes}")

    # 4. WHAT THE PACKETS TABLE COULD STILL GIVE US
    section("WHAT WE WOULD LOSE, MEASURED")
    print("The top talkers, and whether their spacing is regular enough to")
    print("be worth keeping after the raw rows go.\n")
    try:
        rows = conn.execute("""
            SELECT dst_ip, COUNT(*) n,
                   MIN(captured_at) first_at, MAX(captured_at) last_at
            FROM packets
            WHERE dst_ip IS NOT NULL
            GROUP BY dst_ip ORDER BY n DESC LIMIT 8
        """).fetchall()
        for r in rows:
            print(f"  {str(r['dst_ip']):<20} {r['n']:>9,} packets   "
                  f"{r['first_at']}  to  {r['last_at']}")
    except sqlite3.Error as e:
        print(f"  could not read packets: {e}")
        print("  (column names may differ, check Schema.SQL)")

    conn.close()
    print("\nDone. Nothing was changed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
