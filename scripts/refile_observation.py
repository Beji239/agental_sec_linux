#!/usr/bin/env python3
"""
Re-file an observation that was written before the basis column existed.

    python scripts/refile_observation.py --list
    python scripts/refile_observation.py ID measured "why you know"
    python scripts/refile_observation.py ID external_intel "why" --ref enrichment:1.2.3.4
    python scripts/refile_observation.py ID measured "why" --dry-run

ID is the observation number from --list. No angle brackets in the usage above
on purpose, PowerShell treats < and > as redirection and a pasted placeholder
just fails to parse. Same point as TODO 17a.

WHAT IT DOES

Copies the row into a NEW one with the basis filled in, then withdraws the old
one pointing at the new. Two rows, linked, both readable.

WHY NOT JUST UPDATE THE OLD ROW

It would be less code and I still think it is the wrong move. That table is
append only for a reason, and stamping a basis onto a two week old row makes
it look like somebody answered the question at the time, when really we
answered it later with hindsight. The pair reads honestly, "this is what was
filed, this is what we later said it was".

It is also invisible. An UPDATE leaves nothing behind. The supersede path
journals, so there is a line saying when and why.

WHO DECIDES

You do. There is deliberately no model tool for this, same call as
scripts/expect_port.py. The model is the thing that filed these rows without a
basis, so it is not the right one to grade them, and TODO 37.4 is still open.

WHAT IT WILL NOT DO

  * touch a row that already has a basis, unless you pass --force
  * touch a row that is already withdrawn
  * accept external_intel without a --ref
  * pretend the new row was written by the model. It goes in as 'system',
    which is the closest honest thing the schema allows.

MY ESTIMATE ON THE BASELINE, and it is worth knowing before you run this.
Withdrawing does NOT pull anything back out of behavioral_baseline. That table
is cumulative and forward only and there is no retract for it. So a re-file
fixes the record going forward, it does not rewind what the old row already
contributed. The script says so per row rather than leaving you to find out.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import memory_engine as me


BASIS_HELP = {
    "measured": "a packet, a sensor, a scan. This tool watched it happen.",
    "external_intel": "somebody else's database said so. Needs --ref.",
    "model_conclusion": "the model reasoned to it. Nothing else behind it.",
}


def ensure_schema() -> bool:
    """
    Same guard as withdraw_observation.py, and for the same reason.

    Migrations run at boot from main.py, so a script that goes straight at the
    database finds whatever the last boot left. Dying on a missing column is a
    confusing way to learn the app needs restarting. run_migrations is
    idempotent so calling it costs nothing when there is nothing to do.
    """
    try:
        from core.migrations import run_migrations
        result = run_migrations(me.DB_PATH)
        if result.get("status") == "migrated":
            print(f"Database migrated to schema v{result.get('version')} "
                  f"first.\n")
        return True
    except Exception as e:
        print(f"Could not bring the database up to date: {e}")
        print("Start AgentalSec once (python main.py) and try again.")
        return False


def fetch(observation_id: int):
    # _get_readonly_conn already hands back sqlite3.Row, both on the read-only
    # handle and on the fallback, so nothing to set here.
    with me._get_readonly_conn() as conn:
        return conn.execute(
            "SELECT * FROM behavioral_session WHERE id = ?",
            (observation_id,)).fetchone()


def list_unrecorded() -> int:
    """Current rows with no basis. These are the ones this script is for."""
    with me._get_readonly_conn() as conn:
        rows = conn.execute(
            "SELECT id, observed_at, entity_value, behavior_key, behavior_value "
            "FROM behavioral_session "
            "WHERE basis IS NULL AND superseded_by IS NULL "
            "ORDER BY id").fetchall()

    if not rows:
        print("Every current observation has a basis. Nothing to re-file.")
        return 0

    print(f"{len(rows)} current observations carry no basis:\n")
    print(f"{'id':>5}  {'when':<21} {'entity':<18} {'key':<22} value")
    print("," * 96)
    for r in rows:
        value = str(r["behavior_value"] or "")[:44].replace("\n", " ")
        print(f"{r['id']:>5}  {str(r['observed_at'] or ''):<21} "
              f"{str(r['entity_value'] or ''):<18} "
              f"{str(r['behavior_key'] or ''):<22} {value}")
    print("\nRead the whole row first: python scripts/show_observations.py ID")
    return 0


def check_ref(ref: str) -> str | None:
    """
    If the ref points at an enrichment row, say whether that row is still there.

    TODO 43.4 settled this: an observation citing a lookup that is no longer in
    the enrichment table counts as STALE, not as fine, because the claim is
    still here and the thing it rested on is gone. Better to hear that now than
    to file a row that reads as sourced and is not.

    A warning, never a refusal. The ref may legitimately point at something
    other than enrichment.
    """
    if not ref or not ref.startswith("enrichment:"):
        return None
    indicator = ref.split(":", 1)[1].strip()
    try:
        with me._get_readonly_conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM enrichment WHERE indicator = ?",
                (indicator,)).fetchone()
    except Exception as e:
        return f"could not check the enrichment table ({e})"
    if row:
        return None
    return (f"there is no enrichment row for {indicator} right now, so this "
            f"will read as STALE straight away. Queue the lookup first if you "
            f"want it to land sourced.")


def baseline_note(row) -> str:
    """Has this row already fed the long term baseline."""
    try:
        with me._get_readonly_conn() as conn:
            seen = conn.execute(
                "SELECT COUNT(*) FROM baseline_session_seen "
                "WHERE entity_type = ? AND entity_value = ? "
                "AND behavior_key = ? AND session_id = ?",
                (row["entity_type"], row["entity_value"],
                 row["behavior_key"], row["session_id"])).fetchone()[0]
    except Exception:
        return ""
    if not seen:
        return "Not merged into the baseline yet, so this is clean."
    return ("Already merged into the baseline. The re-file fixes the record "
            "from here on, it does not rewind what the old row contributed. "
            "There is no retract for behavioral_baseline.")


def refile(observation_id: int, basis: str, reason: str,
           ref: str = None, force: bool = False, dry_run: bool = False) -> int:
    row = fetch(observation_id)
    if row is None:
        print(f"No observation with id {observation_id}.")
        return 1
    if row["superseded_by"] is not None:
        print(f"Observation {observation_id} is already withdrawn. "
              f"Reason on file: {row['superseded_reason']}")
        return 1
    if row["basis"] and not force:
        print(f"Observation {observation_id} already has basis "
              f"{row['basis']!r}. Pass --force if you really mean to change it.")
        return 1

    basis = basis.strip().lower()
    if basis not in me.VALID_OBSERVATION_BASIS:
        print(f"basis must be one of {sorted(me.VALID_OBSERVATION_BASIS)}.")
        for name, help_text in BASIS_HELP.items():
            print(f"  {name:<17} {help_text}")
        return 1
    if basis == "external_intel" and not ref:
        print("external_intel needs --ref saying where it came from, normally "
              "enrichment:INDICATOR. An external claim with no source is the "
              "thing the column exists to stop.")
        return 1

    warning = check_ref(ref)

    # The new row says where it came from, in its own context. Somebody reading
    # it in six months should not have to work out why there are two.
    carried = row["context"] or ""
    new_context = (f"{carried}\n\n[re-filed from observation {observation_id} "
                   f"on a person's call, basis={basis}"
                   + (f", ref={ref}" if ref else "") + "]").strip()

    print("=" * 74)
    print(f"observation {observation_id}, {row['entity_value']} "
          f"{row['behavior_key']}")
    print("=" * 74)
    print(f"  value        {str(row['behavior_value'])[:400]}")
    print(f"  basis now    {row['basis'] or 'NULL, unrecorded'}")
    print(f"  basis after  {basis}" + (f"  ref={ref}" if ref else ""))
    print(f"  {baseline_note(row)}")
    if warning:
        print(f"  HEADS UP: {warning}")

    if dry_run:
        print("\n--dry-run, nothing was written.")
        return 0

    # The copy. Written directly rather than through
    # write_behavioral_observation, because that one hardcodes
    # written_by='model' and asks agent_loop what was in context. Neither is
    # true here: a person filed this, and the provenance belongs to the
    # ORIGINAL row, so it is carried across rather than recomputed.
    with me._get_conn() as conn:
        cursor = conn.execute("""
            INSERT INTO behavioral_session
                (session_id, observed_at, entity_type, entity_value,
                 behavior_key, behavior_value, context, written_by,
                 evidence_untrusted, evidence_sources, sensor_id,
                 basis, basis_ref)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'system', ?, ?, ?, ?, ?)
        """, (row["session_id"], row["observed_at"], row["entity_type"],
              row["entity_value"], row["behavior_key"], row["behavior_value"],
              new_context,
              row["evidence_untrusted"], row["evidence_sources"],
              row["sensor_id"], basis, ref))
        new_id = cursor.lastrowid

    result = me.supersede_observation(
        observation_id,
        reason or f"re-filed as {basis} by a person, see observation {new_id}.",
        superseded_by=new_id)

    if not result.get("success"):
        # The copy is already in. Say so plainly rather than leaving two rows
        # that look like a duplicate.
        print(f"\nThe copy went in as observation {new_id}, but withdrawing "
              f"{observation_id} FAILED: {result.get('error')}")
        print(f"Both rows are current right now. Fix it with:\n"
              f"  python scripts/withdraw_observation.py {observation_id} "
              f"\"re-filed\" --replaced-by {new_id}")
        return 1

    print(f"\nDone. New observation {new_id} carries basis={basis}"
          + (f" ref={ref}" if ref else "") + ".")
    print(f"Observation {observation_id} is withdrawn and points at it. "
          f"Still on disk, readable with include_superseded.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("id", nargs="?")
    p.add_argument("basis", nargs="?")
    p.add_argument("reason", nargs="?", default=None)
    p.add_argument("--ref", default=None)
    p.add_argument("--force", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--list", action="store_true")
    p.add_argument("-h", "--help", action="store_true")
    args = p.parse_args()

    if args.help or (not args.list and not args.id):
        print(__doc__)
        return 0

    if not ensure_schema():
        return 1

    if args.list:
        return list_unrecorded()

    try:
        observation_id = int(args.id)
    except ValueError:
        print(f"'{args.id}' is not an observation id. Try --list. If you "
              f"pasted the usage line as is, replace ID with the number.")
        return 1

    if not args.basis:
        print("Need a basis. One of:")
        for name, help_text in BASIS_HELP.items():
            print(f"  {name:<17} {help_text}")
        return 1

    return refile(observation_id, args.basis, args.reason,
                  ref=args.ref, force=args.force, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
