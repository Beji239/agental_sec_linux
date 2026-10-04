#!/usr/bin/env python3
"""
Withdraw a behavioral observation that turned out to be wrong.

    python scripts/withdraw_observation.py ID "why it was wrong"
    python scripts/withdraw_observation.py ID "why" --replaced-by OTHER_ID
    python scripts/withdraw_observation.py --list

ID is the observation number from --list. No angle brackets in the usage above
on purpose: this project runs on Windows first, PowerShell treats < and > as
redirection operators, and a placeholder pasted verbatim fails to parse. See
TODO 17a, which made the same point about a different script.

Written for one specific cleanup and kept because it will be wanted again.

On 2026-08-19 the agent decoded a UDP broadcast reading

    SEARCH BSDP/0.1
    DEVICE=0
    SERVICE=1

matched the letters BSDP to Apple's Boot Service Discovery Protocol, and
recorded an observation that a LAN device was an Apple Mac NetBoot host. Apple's
BSDP is a binary extension of DHCP carried in options 43 and 60; it is not a
text protocol on port 15600. That payload is Samsung's proprietary TV
discovery, documented on Samsung's own support forum. The device is a Samsung
television, which is also why its MAC sits in a Samsung OUI block.

The agent then wrote a second observation correcting itself, which was the
right instinct and not enough on its own. Two rows sat side by side with
nothing linking them, so whether a later session believed the correction
depended on it reading both and noticing.

NOTHING IS DELETED HERE. The row keeps its text, timestamp and author, and
gains a reason it was withdrawn. It stops being returned as current and stays
readable with include_superseded. Deleting it would destroy the evidence that
the mistake happened, and that evidence is worth more than the tidiness.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import memory_engine as me


def ensure_schema() -> bool:
    """
    Bring the database up to date before touching it.

    Migrations normally run at boot from main.py, so a standalone script that
    goes straight to the database finds whatever schema the last boot left.
    The first version of this script did exactly that and died on a missing
    column, which is a confusing way to learn that the app needs restarting.

    run_migrations is idempotent and transactional, so calling it here is
    free when there is nothing to do.
    """
    try:
        from core.migrations import run_migrations
        result = run_migrations(me.DB_PATH)
        if result.get("status") == "migrated":
            print(f"Database migrated to schema v{result.get('version')} "
                  f"before proceeding.\n")
        return True
    except Exception as e:
        print(f"Could not bring the database up to date: {e}")
        print("Start AgentalSec once (python main.py) and try again.")
        return False


def list_recent(limit: int = 40) -> int:
    result = me.query_behavioral_session(limit=limit, include_superseded=True)
    rows = result["observations"] if isinstance(result, dict) else result

    if not rows:
        print("No observations recorded yet.")
        return 0

    print(f"{'id':>5}  {'when':<22} {'entity':<18} {'key':<24} value")
    print("," * 100)
    for row in rows:
        mark = "  [withdrawn]" if row.get("superseded_by") else ""
        value = str(row.get("behavior_value", ""))[:60].replace("\n", " ")
        print(f"{row.get('id'):>5}  {str(row.get('observed_at','')):<22} "
              f"{str(row.get('entity_value','')):<18} "
              f"{str(row.get('behavior_key','')):<24} {value}{mark}")
    return 0


def main() -> int:
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0

    if not ensure_schema():
        return 1

    if args[0] == "--list":
        return list_recent()

    if len(args) < 2:
        print("Need an observation id and a reason.\n")
        print(__doc__)
        return 1

    try:
        observation_id = int(args[0])
    except ValueError:
        print(f"'{args[0]}' is not an observation id. Use --list to find "
              f"one. If you pasted the usage line literally, replace ID with "
              f"the number.")
        return 1

    reason = args[1]
    replaced_by = None
    if "--replaced-by" in args:
        try:
            replaced_by = int(args[args.index("--replaced-by") + 1])
        except (IndexError, ValueError):
            print("--replaced-by needs an observation id after it.")
            return 1

    result = me.supersede_observation(observation_id, reason, superseded_by=replaced_by)

    if not result.get("success"):
        print(f"FAILED: {result.get('error')}")
        return 1

    print(f"Observation {observation_id} withdrawn.")
    print(f"  was: {str(result.get('withdrawn_text',''))[:200]}")
    print(f"  why: {reason}")
    if replaced_by:
        print(f"  replaced by observation {replaced_by}")
    print("\nStill on disk and readable with include_superseded. "
          "No longer returned as current.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
