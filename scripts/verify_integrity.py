#!/usr/bin/env python3
"""
scripts/verify_integrity.py, check the journal, or take an anchor.

    python scripts/verify_integrity.py                 verify
    python scripts/verify_integrity.py --anchor        take a new anchor
    python scripts/verify_integrity.py --head HASH     verify against an anchor
    python scripts/verify_integrity.py --agent-record  the agent's own rows

HASH is the 64-character value --anchor printed. Written as HASH rather than
in angle brackets because PowerShell treats < and > as redirection operators
and refuses the line outright if a placeholder is pasted verbatim, which is
exactly what happened the first time this was used.

Read-only in both modes except --anchor, which writes only the anchor file.

The anchor is the part that matters. Without one, a clean result means the
chain is internally coherent, which is also true of a chain an attacker
rebuilt. Take an anchor and keep the hash somewhere this machine cannot
reach.

--agent-record CHECKS THE SEAL OVER THE AGENT'S OWN ROWS, added 2026-09-23.
The chain says the journal was not edited; this says whether the runs,
reports, prompts and action proposals it witnesses still read what they read
when they were sealed. Both are run by default in verify mode, because a
reader who asks "is this record believable" is asking both questions at once
and answering only the first is how a tampered report reads as fine.
"""
import argparse, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--head", metavar="HASH",
                help="the 64-character hash a previous --anchor run printed")
    ap.add_argument("--anchor", action="store_true")
    ap.add_argument("--agent-record", action="store_true",
                    help="check only the seal over the agent's own record")
    ap.add_argument("--anchor-file", default=str(ROOT / "integrity_anchor.json"))
    args = ap.parse_args()

    from core import integrity

    if args.anchor:
        a = integrity.anchor(out_path=args.anchor_file)
        if a.get("status") == "no_journal":
            print("No journal table. Run the app once to migrate.")
            return 2
        print(f"\nhead     {a['head']}")
        print(f"entries  {a['entries']}")
        print(f"taken    {a['taken_at']}")
        print(f"file     {a['written_to']}")
        print(f"\n{a['note']}\n")
        return 0

    rc = 0

    if args.agent_record:
        return _report_sealed(integrity)

    v = integrity.verify_chain(expected_head=args.head)
    print()
    for k in ("status", "verified_entries", "first_break_id", "reason",
              "operation", "table_name", "row_ref", "recorded_at", "anchor",
              "head"):
        if k in v:
            print(f"  {k:18} {v[k]}")
    if v.get("detail"):
        print(f"\n  {v['detail']}")
    if v.get("note"):
        print(f"\n  {v['note']}")
    print()
    if v.get("status") != "intact":
        rc = 1

    # THE SEALED ROWS TOO. Two different questions, both asked: the chain can
    # be untouched while a row it witnesses was rewritten, because the digest
    # lives in the journal and the row lives in its own table.
    sealed_rc = _report_sealed(integrity)
    return max(rc, sealed_rc)


def _report_sealed(integrity) -> int:
    """Print the row-witness result. Returns an exit code."""
    s = integrity.verify_sealed_rows()
    print("  ── the agent's own record " + "─" * 40)
    print(f"  {'status':18} {s.get('status')}")
    for k in ("verified_rows", "edited_rows", "deleted_rows",
              "deleted_expected"):
        if k in s:
            print(f"  {k:18} {s[k]}")
    for table, info in (s.get("by_table") or {}).items():
        print(f"  {'':18} {table:16} sealed={info['entries']:5} "
              f"verified={info['verified']:5} edited={info['edited']:3} "
              f"deleted={info['deleted']:3} "
              f"trimmed={info.get('deleted_expected', 0):3} "
              f"unsealed={info['unsealed']:5}")
    problems = s.get("problems") or []
    if problems:
        print(f"\n  PROBLEMS ({s.get('problems_total', len(problems))}):")
        for p in problems[:20]:
            print(f"    - {p['detail']}")
        if s.get("problems_total", 0) > len(problems):
            print(f"    ... and {s['problems_total'] - len(problems)} more.")
    if s.get("truncated"):
        print(f"\n  {s['truncated']}")
    if s.get("unsealed"):
        print("\n  UNSEALED ROWS (unknown, NOT clean):")
        for table, info in s["unsealed"].items():
            print(f"    - {table}: {info['count']}")
    if s.get("note"):
        print(f"\n  {s['note']}")
    print()
    return 0 if s.get("status") == "intact" else 1


if __name__ == "__main__":
    sys.exit(main())
