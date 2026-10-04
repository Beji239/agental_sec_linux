#!/usr/bin/env python3
"""
Correct the evidence sources on observations written before the LOOP-1 fix.

    python scripts/refile_provenance.py            show what would change
    python scripts/refile_provenance.py --apply    file the corrected copies

Before LOOP-1 the loop recorded the TRUSTED tools a turn read and dropped the
untrusted ones, so evidence_sources on those rows names the wrong tools. The
flag itself was right: every such turn also read fenced tools (LOOP-3).

Each turn's tools are rebuilt from the app log: the "Tool result [name]" lines
between the session_log stamps that close the turn before and the turn itself.
A corrected copy is filed as 'system' and the old row is withdrawn pointing at
it, same as scripts/refile_observation.py. Nothing is deleted.
"""

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import memory_engine as me          # noqa: E402
from core import sanitize                     # noqa: E402

LOG = ROOT / "logs" / "agental_sec_linux.log"
# The loop's own write tool is not evidence; LOOP-1 recorded it by mistake.
NOT_EVIDENCE = {"write_behavioral_observation"}
# Lines that end a turn without a session_log stamp: an app start, or a chat
# request whose browser went away before the turn was logged.
BOUNDARY_RE = re.compile(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) .*("
                         r"AgentalSec Linux starting|Client disconnected while "
                         r"serving /api/chat)")
RESULT_RE = re.compile(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \[core\.agent_loop\] "
                       r"INFO: Tool result \[(\w+)\]")


def _when(text: str) -> dt.datetime:
    return dt.datetime.strptime(str(text)[:19], "%Y-%m-%d %H:%M:%S")


def _log_offset() -> dt.timedelta:
    """UTC minus local, since the log is written in local time."""
    now = dt.datetime.now().astimezone()
    return -now.utcoffset()


def _read_log(offset):
    """(tool results, turn boundaries) from the app log, in UTC."""
    results, bounds = [], []
    with open(LOG, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = RESULT_RE.match(line)
            if m:
                results.append((_when(m.group(1)) + offset, m.group(2)))
                continue
            b = BOUNDARY_RE.match(line)
            if b:
                bounds.append(_when(b.group(1)) + offset)
    return results, bounds


def candidates(conn):
    """Current rows whose flag is set but whose sources hold no fenced tool."""
    rows = []
    for r in conn.execute(
            "SELECT * FROM behavioral_session WHERE superseded_by IS NULL "
            "AND evidence_untrusted = 1 ORDER BY id"):
        srcs = json.loads(r["evidence_sources"] or "[]")
        if not any(t in sanitize.UNTRUSTED_TOOLS for t in srcs):
            rows.append(r)
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[1])
    ap.add_argument("--apply", action="store_true",
                    help="write the corrected copies; without it nothing is written")
    args = ap.parse_args(argv)

    offset = _log_offset()
    results, bounds = _read_log(offset)
    with me._get_readonly_conn() as conn:
        rows = candidates(conn)
        turn_ends = {}
        for sid, t in conn.execute(
                "SELECT session_id, logged_at FROM session_log "
                "WHERE role = 'user' ORDER BY logged_at"):
            turn_ends.setdefault(sid, []).append(_when(t))

    all_ends = sorted([e for v in turn_ends.values() for e in v] + bounds)
    if not rows:
        print("No current observation has this defect. Nothing to do.")
        return 0

    plan = []
    for r in rows:
        at = _when(r["observed_at"])
        ends = turn_ends.get(r["session_id"], [])
        # The turn opens where the previous one closed, in any session: the
        # first turn of a session has no earlier stamp of its own.
        start = max((e for e in all_ends if e < at), default=None)
        end = min((e for e in ends if e >= at), default=None)
        if start is None or end is None:
            print(f"  {r['id']:>4}  SKIPPED, the turn has no closing stamp in "
                  f"session_log, so its tools cannot be rebuilt.")
            continue
        read = sorted({n for ts, n in results if start < ts <= end})
        fenced = [n for n in read if n in sanitize.UNTRUSTED_TOOLS
                  and n not in NOT_EVIDENCE]
        old = json.loads(r["evidence_sources"] or "[]")
        print(f"  {r['id']:>4}  {r['entity_value']:<22} {r['behavior_key']:<20}"
              f" recorded {old}  ->  read {fenced or 'NO fenced tool'}")
        if fenced:
            plan.append((r, fenced))

    print(f"\n{len(plan)} of {len(rows)} row(s) can be corrected from the log.")
    if not args.apply:
        print("Nothing written. Run again with --apply.")
        return 0

    for r, fenced in plan:
        note = (f"[re-filed from observation {r['id']} for LOOP-3: its "
                f"evidence_sources named the trusted tools the turn read "
                f"(the LOOP-1 inversion). The untrusted tools below were "
                f"rebuilt from the app log for that turn.]")
        with me._get_conn() as conn:
            cur = conn.execute("""
                INSERT INTO behavioral_session
                    (session_id, observed_at, entity_type, entity_value,
                     behavior_key, behavior_value, context, written_by,
                     evidence_untrusted, evidence_sources, sensor_id,
                     basis, basis_ref)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'system', 1, ?, ?, ?, ?)
            """, (r["session_id"], r["observed_at"], r["entity_type"],
                  r["entity_value"], r["behavior_key"], r["behavior_value"],
                  ((r["context"] or "") + "\n\n" + note).strip(),
                  json.dumps(fenced), r["sensor_id"], r["basis"],
                  r["basis_ref"]))
            new_id = cur.lastrowid
        out = me.supersede_observation(
            r["id"], f"LOOP-3: evidence sources corrected in observation {new_id}.",
            superseded_by=new_id)
        state = "done" if out.get("success") else f"WITHDRAW FAILED: {out.get('error')}"
        print(f"  {r['id']:>4} -> {new_id}  {state}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
