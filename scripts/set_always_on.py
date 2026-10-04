"""
scripts/set_always_on.py

Declare which devices should ALWAYS be answering. That declaration, and
nothing else, licenses the absence finding.

    python scripts/set_always_on.py                     # show declarations
    python scripts/set_always_on.py --set 192.0.2.1     # declare one
    python scripts/set_always_on.py --clear 192.0.2.1   # withdraw it

WHY THIS IS A SCRIPT AND NOT A MODEL TOOL

Same reason there is no set_device_permanence in the manifest. This is the
statement that makes a quiet device loud, so it has to come from a person. A
model that can declare a device always-on can manufacture a finding about any
device it likes, and one that can clear the flag can go quiet about the one
device that mattered. Neither belongs in a tool the model can call.

WHY IT IS SEPARATE FROM PERMANENCE

is_permanent means "this belongs on my network". It was doing double duty as
"this should always be on", so vouching for a TV silently signed it up to stay
awake, and every quiet evening produced a finding. A device switched off
because nobody is using it is the ordinary case, not an event.

So most devices should carry NEITHER flag, many should carry permanence only,
and very few should carry this one. On a home network it is usually the
gateway and nothing else. A long list here rebuilds the noise the split was
made to remove.
"""

import argparse
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
DB = ROOT / "agental_sec.db"

from core import memory_engine as me  # noqa: E402


def show():
    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        cols = {r[1] for r in conn.execute("PRAGMA table_info(known_devices)")}
        if "expected_always_on" not in cols:
            print("This database has not run the v22 migration yet. Start "
                  "main.py once, then re-run this.")
            return 1
        rows = conn.execute(
            "SELECT ip, known_as, device_type, is_permanent, "
            "       expected_always_on, retired_at "
            "FROM known_devices ORDER BY ip").fetchall()

    on = [r for r in rows if r["expected_always_on"] and not r["retired_at"]]
    print(f"{len(on)} device(s) declared always-on:")
    for r in on:
        print(f"  {r['ip']:<16} {r['known_as'] or '(unnamed)'}")
    if not on:
        print("  none. The absence check will report nothing at all, which is")
        print("  NOT the same as every device being present.")

    print(f"\n{len(rows)} device(s) in the inventory:")
    for r in rows:
        marks = []
        if r["is_permanent"]:
            marks.append("member")
        if r["expected_always_on"]:
            marks.append("always-on")
        if r["retired_at"]:
            marks.append("retired")
        print(f"  {r['ip']:<16} {(r['known_as'] or '(unnamed)'):<28} "
              f"{', '.join(marks) or '-'}")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", metavar="IP",
                    help="declare this device always-on")
    ap.add_argument("--clear", metavar="IP", help="withdraw the declaration")
    args = ap.parse_args()

    if not DB.exists():
        print(f"No database at {DB}")
        return 1

    if not args.set and not args.clear:
        return show()

    ip = args.set or args.clear
    result = me.set_device_always_on(ip, bool(args.set))
    if not result["ok"]:
        print(result["reason"])
        return 1

    label = result["known_as"] or ip
    if result["expected_always_on"]:
        print(f"{label} ({ip}) is now declared ALWAYS-ON.")
        print("Its absence from presence sweeps will now raise a finding.")
        if not result["is_permanent"]:
            print("Note: it is not marked as a permanent member. That is "
                  "allowed, they are separate statements, but it is unusual.")
    else:
        print(f"{label} ({ip}) is no longer declared always-on.")
        print("Its absence will no longer raise anything. It keeps its "
              "membership flag if it had one.")
    print("Recorded in the integrity journal.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
