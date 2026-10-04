"""
scripts/find_availability_notes.py

Find behavioural observations that recorded the AVAILABILITY RULE, so they can
be withdrawn now that the rule lives in the inventory.

    python scripts/find_availability_notes.py

READ ONLY. It prints candidates and the exact withdraw command for each. It
withdraws nothing itself, on purpose: which rows are the rule and which are
genuine data is a judgement about content, and this script cannot see the
difference between "the router is always present" written as a policy note and
an active_hours observation that happens to mention the same words.

WHY THESE ROWS EXIST AT ALL, WHICH IS NOT THE MODEL'S FAULT

Told that permanent does not mean always on, the model tried to record the
rule and found no valid behaviour key for it. It said so out loud, twice, then
used active_hours with the real content in the context field, which was the
best available move.

The content was right. The location was not. active_hours for the gateway now
holds prose about policy rather than hours, and a future session reading that
key for what it says on the tin gets a sentence instead of a number.

v22 gave the rule a proper home: known_devices.expected_always_on, carried
into every enriched row, so nothing has to write it down to remember it.

NOTHING IS DELETED WHEN YOU WITHDRAW. The row keeps its text, timestamp and
author, gains a reason, stops being returned as current, and stays readable
with include_superseded. The log is append-only by design and that matters
more than the tidiness.
"""

import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
DB = ROOT / "agental_sec.db"

# Words that suggest a row is talking about availability policy rather than
# recording a measurement. Deliberately WIDE: this produces candidates for a
# person to read, so a false positive costs one glance and a miss costs a row
# left in the wrong place.
HINTS = ("always", "absence", "absent", "powered", "switched off",
         "may be off", "permanent", "unused", "not in use")

SUGGESTED_REASON = (
    "Availability is an inventory fact, not an observation. Recorded here "
    "under active_hours because no valid behaviour key existed at the time; "
    "v22 moved it to known_devices.expected_always_on, which every enriched "
    "row now carries."
)


def main() -> int:
    if not DB.exists():
        print(f"No database at {DB}")
        return 1

    conn = sqlite3.connect(f"file:{DB.as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    cols = {r[1] for r in
            conn.execute("PRAGMA table_info(behavioral_session)")}
    superseded = "superseded_by" in cols

    sql = ("SELECT id, observed_at, entity_value, behavior_key, "
           "       behavior_value, context, written_by "
           "FROM behavioral_session")
    if superseded:
        sql += " WHERE superseded_by IS NULL"
    sql += " ORDER BY id DESC LIMIT 400"

    rows = conn.execute(sql).fetchall()
    conn.close()

    hits = []
    for row in rows:
        blob = f"{row['behavior_value'] or ''} {row['context'] or ''}".lower()
        if any(h in blob for h in HINTS):
            hits.append(row)

    if not hits:
        print("No candidates found. Either they were already withdrawn, or "
              "they are older than the 400 rows this looks at.")
        return 0

    print(f"{len(hits)} candidate observation(s). READ EACH ONE before "
          f"withdrawing it.\n")
    for row in hits:
        print("," * 74)
        print(f"  id {row['id']}   {row['observed_at']}   "
              f"by {row['written_by']}")
        print(f"  entity : {row['entity_value']}")
        print(f"  key    : {row['behavior_key']}")
        print(f"  value  : {str(row['behavior_value'] or '')[:200]}")
        ctx = str(row["context"] or "").replace("\n", " ")
        print(f"  context: {ctx[:400]}")
        print()

    print("," * 74)
    print("\nTo withdraw one, with the reason on a single line:\n")
    # NO ANGLE BRACKETS. TODO 17a: PowerShell treats < and > as redirection
    # operators, so a placeholder pasted verbatim fails to parse. That note was
    # written in August and this script repeated the mistake in September.
    print('    python scripts/withdraw_observation.py ID '
          f'"{SUGGESTED_REASON}"')
    print('\n    replacing ID with the number from the row above.')
    print("\nOnly withdraw the rows that are the RULE. A row under "
          "active_hours that genuinely records hours is data, and it stays.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
