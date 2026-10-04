#!/usr/bin/env python3
"""
scripts/remove_em24_false_findings.py — delete the 84 false LNX-1013/LNX-1014
rows the service-burst counting bug wrote into the owner's store (EM2-4).

THE INSTRUCTION: delete all 84 entries.

WHAT THESE ROWS ARE. Every one of them was raised by a counting defect, not by
the machine: one service start counted as many as three times (systemd's
"Starting"/"Started" pair, the same line arriving from journald and from
syslog, and a lagging cursor re-reading what it had already read), and the
burst window running on the READ clock instead of the line's own time. The
measurement is in bugfinder.md, section "THE SERVICE-BURST COUNTING ROUND
(EM2-4)". The detection itself is right and stays; the rows are wrong.

DELETE, NOT DISMISS, and the reason is in core/integrity.py's JOURNALLED
entry for `findings_removed`: a dismissal is a person deciding an alert should
stay quiet, and these were never evidence of anything. Leaving 84 dismissed
rows would keep the false history on the record.

SAFETY, in this order, and every one of them is checked rather than intended:
  1. every row is read and LISTED before anything is written, and the list is
     written to a JSON file beside the backup so the delete is reversible by
     hand;
  2. only rows whose detection_id is in the round's set AND which the fixed
     counting says are false are touched -- the set is bounded by an explicit
     id list, not a pattern;
  3. incidents whose whole finding set is among these rows are dismissed with
     a note (never deleted -- the ledger keeps them);
  4. the journal entry is appended AFTER the delete, carrying the ids;
  5. the chain is verified before and after, and a break is reported rather
     than hidden;
  6. with --apply absent, EVERYTHING runs against a throwaway copy and the
     owner's store is not opened for writing at all.

Run:  python3 scripts/remove_em24_false_findings.py            # dry run
      python3 scripts/remove_em24_false_findings.py --apply    # for real
"""
import argparse
import json
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

LIVE_DB = ROOT / "agental_sec.db"

DETECTION_IDS = ("LNX-1013", "LNX-1014")
REASON = ("EM2-4: raised by the service-burst counting defect (one service "
          "start counted as a pair, again from the second source, and again "
          "on a re-read; window on the read clock). Removed on the owner's "
          "instruction, 2026-09-27.")


def open_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{path}?mode=rw", uri=True, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def list_rows(conn) -> list:
    rows = []
    for det_id in DETECTION_IDS:
        for r in conn.execute(
                "SELECT id, detection_id, found_at, entity_type, entity_value,"
                " title, description, raw_data FROM findings"
                " WHERE detection_id = ? AND dismissed = 0 ORDER BY id",
                (det_id,)):
            rows.append(dict(r))
    return rows


def incidents_for(conn, ids: list) -> list:
    """
    Incidents whose finding set is ENTIRELY among `ids`.

    Those opened on nothing but false rows and should stop being shown. An
    incident that also carries a real finding is left alone -- its own note
    would then be false, which is the same class of defect as the rows.
    """
    if not ids:
        return []
    idset = set(ids)
    out = []
    for r in conn.execute("SELECT id, incident_key, detection_id, status,"
                          " finding_ids_json FROM incident"):
        try:
            fids = set(json.loads(r["finding_ids_json"] or "[]"))
        except (ValueError, TypeError):
            fids = set()
        if fids and fids.issubset(idset) and r["status"] != "dismissed":
            out.append({"id": r["id"], "detection_id": r["detection_id"],
                        "status": r["status"], "findings": sorted(fids)})
    return out


def remove(db_path: Path, ids: list, apply: bool) -> dict:
    """Delete exactly `ids` and journal it. Returns what it did."""
    from core import integrity as ig

    conn = open_db(db_path)
    try:
        if not ids:
            return {"deleted": 0, "journal": None}

        marks = ",".join("?" * len(ids))
        # THE ROWS ARE RE-READ HERE, inside the same connection that deletes
        # them, so what is journalled is what was actually there.
        present = [r["id"] for r in conn.execute(
            f"SELECT id FROM findings WHERE id IN ({marks})", ids)]
        missing = sorted(set(ids) - set(present))
        if missing:
            return {"error": f"{len(missing)} of the named rows are not in "
                             f"this database: {missing[:10]}"}

        entry = ig.record(
            "findings_removed", "findings", f"{DETECTION_IDS[0]}..{DETECTION_IDS[-1]}",
            {"count": len(present), "ids": present,
             "detection_ids": list(DETECTION_IDS), "reason": REASON,
             "by": "agent, on the owner's instruction 2026-09-27"},
            conn=conn)
        if entry is None:
            return {"error": "the journal refused the entry; nothing deleted"}

        conn.execute(f"DELETE FROM findings WHERE id IN ({marks})", present)
        conn.commit()
        return {"deleted": len(present), "journal": entry["entry_hash"][:16],
                "ids": present}
    finally:
        conn.close()


def dismiss_incidents(db_path: Path, incidents: list) -> int:
    """
    Dismiss the incidents opened on nothing but the false rows.

    CORRECTED 2026-09-27, and this one was found by running the dry run and
    then READING THE LIVE STORE instead of trusting the script's own closing
    line. The first version called core.incident.set_status(), which opens its
    OWN connection through core.memory_engine.DB_PATH -- the LIVE database --
    so a rehearsal that had printed "the owner's store is NOT opened for
    writing by this run" wrote two incident rows to it. The rows were ones
    this round was going to dismiss anyway and the outcome is right, but a
    rehearsal that writes is the exact class of false reading this project
    keeps recording, and it was mine.

    The fix points the incident module at the database under work for the
    duration, and restores it in a `finally` so a failure cannot leave the
    live path swapped.
    """
    from core import incident as inc
    from core import memory_engine as me

    saved = me.DB_PATH
    me.DB_PATH = str(db_path)
    try:
        n = 0
        for row in incidents:
            r = inc.set_status(row["id"], "dismissed", by="user", note=REASON)
            if r.get("success"):
                n += 1
        return n
    finally:
        me.DB_PATH = saved


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true",
                    help="write to the owner's store; without it everything "
                         "happens on a throwaway copy")
    ap.add_argument("--copy-only", action="store_true",
                    help="rehearse on a copy even with --apply present")
    args = ap.parse_args()

    if not LIVE_DB.exists():
        print(f"no database at {LIVE_DB}")
        return 2

    from core import integrity as ig

    work = LIVE_DB
    scratch = None
    if not args.apply or args.copy_only:
        scratch = Path(tempfile.mkdtemp(prefix="em24_removal_"))
        work = scratch / "agental_sec.db"
        shutil.copy2(LIVE_DB, work)
        print(f"DRY RUN -- working on a copy: {work}")
        print("(the owner's store is NOT opened for writing by this run)")

    print(f"chain before: {ig.verify_chain(db_path=work)['status']}")

    conn = open_db(work)
    try:
        rows = list_rows(conn)
        incidents = incidents_for(conn, [r["id"] for r in rows])
    finally:
        conn.close()

    print(f"rows to remove: {len(rows)}  (detection ids {DETECTION_IDS})")
    for r in rows[:5]:
        print(f"   id {r['id']:>5}  {r['detection_id']}  {r['found_at']}  "
              f"{r['entity_value']}")
    if len(rows) > 5:
        print(f"   ... and {len(rows) - 5} more")
    print(f"incidents to dismiss (their whole finding set is these rows): "
          f"{len(incidents)}")
    for i in incidents:
        print(f"   incident {i['id']}  {i['detection_id']}  {i['status']}  "
              f"{len(i['findings'])} finding(s)")

    listing = Path("/tmp/em24_removed/rows_removed.json")
    listing.parent.mkdir(parents=True, exist_ok=True)
    # NEVER OVERWRITE A LISTING THAT HAS ROWS WITH ONE THAT HAS NONE.
    # Found by running this script twice: the apply run wrote the 84-row
    # listing, and a later dry run -- finding nothing left to remove --
    # replaced it with an empty file, destroying the only per-row record of a
    # delete that had already happened. The ids survive in the journal entry,
    # but the reversible copy must not depend on somebody thinking to look
    # there. A run that would write an empty list now writes to its own name
    # and says why.
    if listing.exists() and not rows:
        try:
            existing = json.loads(listing.read_text()).get("rows") or []
        except (ValueError, TypeError):
            existing = []
        if existing:
            listing = listing.with_name("rows_removed.dryrun_empty.json")
            print(f"(a listing of {len(existing)} row(s) already exists and is "
                  f"NOT overwritten; this empty one goes to {listing})")
    listing.write_text(json.dumps({"detection_ids": list(DETECTION_IDS),
                                   "reason": REASON, "rows": rows},
                                  indent=1))
    print(f"the full row list is written to {listing} (reversible by hand)")

    result = remove(work, [r["id"] for r in rows], apply=True)
    if result.get("error"):
        print(f"REFUSED: {result['error']}")
        return 1
    print(f"deleted: {result['deleted']}  journalled as findings_removed "
          f"{result['journal']}")

    n = dismiss_incidents(work, incidents)
    print(f"incidents dismissed: {n}")

    conn = open_db(work)
    try:
        left = 0
        for det_id in DETECTION_IDS:
            left += conn.execute(
                "SELECT COUNT(*) c FROM findings WHERE detection_id = ?",
                (det_id,)).fetchone()["c"]
        total = conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]
    finally:
        conn.close()
    print(f"rows left under those ids: {left}  (store total: {total})")
    print(f"chain after:  {ig.verify_chain(db_path=work)['status']}")

    if scratch is not None:
        print(f"\nDRY RUN complete. Nothing in {LIVE_DB} was written.")
        print("Re-run with --apply when the list above is what you expect.")
    else:
        print("\nAPPLIED to the owner's store.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
