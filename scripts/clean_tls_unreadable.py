#!/usr/bin/env python3
"""
scripts/clean_tls_unreadable.py, TODO 113.2. Read-only by default.

PORTED TO LINUX 2026-09-21, from agental_sec/scripts/clean_tls_unreadable.py.
Nothing in it was Windows specific, so this is the Windows file with its two
platform references checked rather than rewritten.

WHY THIS EXISTS. Version one of the TLS capture read a ClientHello out of a
single packet. That misses every hello that spans two TCP segments, which was
123 of the first 124 handshakes on the owner's machine, because a browser
offering post-quantum key exchange sends a hello bigger than one segment.

Those rows are not wrong. Each one records a TLS connection to a real address
whose NAME we genuinely could not read at the time, and the destination is
still on the row. They are just permanently pessimistic: the coverage line on
the Network page counts them forever, so after the reassembly fix the card
keeps reporting a blindness that no longer exists.

So this offers to remove them, and it is deliberately narrow:

  * only rows with sni_state = 'unreadable'
  * only rows whose parse_reason is a TRUNCATION, which is the failure
    reassembly fixed. A hello that was malformed, or oversized, or came from
    something that is not TLS at all, is a different fact and is left alone.
  * nothing is touched without --delete.

WHAT IT WILL NOT DO. It will not delete a readable row, it will not touch any
other table, and it does not pretend a deleted row's destination was never
contacted: the packets table still holds every one of those connections, which
is where that evidence belongs.

WHY IT IS WORTH RUNNING HERE AT ALL, and this is the check rather than a
courtesy. The column it matches on is only filled when the caller maps the
parser's `reason` onto the writer's `parse_reason`. That mapping was MISSING
in this tree until 2026-09-21, so every unreadable row carried an empty
reason: running this script on a database full of truncations would have
printed "Nothing to remove", which reads as a clean database and is the exact
shape of lie this project is built against. If the counts it prints are zero
while the database has unreadable rows, that is not a clean result, it is the
mapping having come undone again.

    python scripts/clean_tls_unreadable.py            # look
    python scripts/clean_tls_unreadable.py --delete   # remove
"""
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import memory_engine as me                   # noqa: E402

# The failures reassembly fixed. Matched as a prefix on the reason the parser
# wrote, which is why the parser sets an explicit flag rather than leaving
# callers to guess from wording.
TRUNCATION_PREFIXES = (
    "truncated TLS record",
    "truncated ClientHello body",
    "truncated extension block",
    "truncated:",
)


def main(delete: bool) -> int:
    db = Path(me.DB_PATH)
    if not db.exists():
        print(f"No database at {db}. Nothing to do.")
        return 0

    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row

    tbl = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='tls_hello'"
    ).fetchone()
    if not tbl:
        print("No tls_hello table yet. Nothing to do, and this is not an error.")
        return 0

    rows = conn.execute(
        "SELECT id, parse_reason, dst_ip, times_seen FROM tls_hello "
        "WHERE sni_state = 'unreadable'").fetchall()

    targets = [r for r in rows
               if str(r["parse_reason"]).startswith(TRUNCATION_PREFIXES)]
    others = [r for r in rows if r not in targets]

    print(f"unreadable rows in total: {len(rows)}")
    print(f"  truncation, which reassembly now handles: {len(targets)}")
    print(f"  other reasons, LEFT ALONE: {len(others)}")
    for r in others[:5]:
        print(f"      kept: {r['parse_reason'][:70]}")

    # THE EMPTY-REASON CASE, WHICH LOOKS EXACTLY LIKE A CLEAN DATABASE.
    # Added with the Linux port. An unreadable row with no reason at all is
    # not a row this script has a verdict about: it is a row that cannot be
    # classified, and saying "Nothing to remove" over it would be reading a
    # missing column for a clean bill of health.
    unexplained = [r for r in rows if not str(r["parse_reason"]).strip()]
    if unexplained:
        print()
        print(f"{len(unexplained)} unreadable row(s) carry NO reason at all.")
        print("  That is not the same as 'nothing to remove'. The reason is")
        print("  written by the capture path mapping tools/tls_hello.py's")
        print("  `reason` onto the writer's `parse_reason`; if it is empty on")
        print("  every row, that mapping has come undone and this script")
        print("  cannot tell a truncation from anything else. Fix the capture")
        print("  path, then re-run this.")

    readable = conn.execute(
        "SELECT COUNT(*) FROM tls_hello WHERE sni_state != 'unreadable'"
    ).fetchone()[0]
    print(f"readable rows, untouched either way: {readable}")

    if not targets:
        print("\nNothing to remove.")
        return 0

    if not delete:
        print("\nRead-only. Re-run with --delete to remove the truncation rows.")
        print("The connections themselves stay in the packets table.")
        return 0

    conn.executemany("DELETE FROM tls_hello WHERE id = ?",
                     [(r["id"],) for r in targets])
    conn.commit()
    left = conn.execute(
        "SELECT COUNT(*) FROM tls_hello WHERE sni_state = 'unreadable'"
    ).fetchone()[0]
    # Counted after the fact rather than assumed from the delete. A statement
    # that ran is not the same as a row that went.
    print(f"\nDeleted {len(targets)}. Unreadable rows remaining: {left}")
    return 0


if __name__ == "__main__":
    sys.exit(main("--delete" in sys.argv))
