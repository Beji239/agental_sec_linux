"""
scripts/untrusted_split.py, how much of the baseline was written after
reading attacker-controllable text. READ ONLY, changes nothing.

    python scripts/untrusted_split.py
    python scripts/untrusted_split.py --suppressed

WHY THIS EXISTS, and read this before deciding anything from it.

Item 8.1F says the largest known gap here is that `write_behavioral_observation`
is ungated and uncapped in both model modes, and that the fix is not a cap: it
is making the baseline WEIGH untrusted evidence differently. Half of that is
already built. Every observation records `evidence_untrusted`, and
`observation_provenance` already reports the three populations honestly. What
does not read the flag is the ROLLUP, which is the thing that promotes an
entity to high confidence and, at high confidence, stops alerting on it.

So the obvious fix is to stop untrusted observations counting toward
promotion. The obvious fix may also be a disaster, and that is what this
script is for.

`query_packets` is in `sanitize.UNTRUSTED_TOOLS`, and rightly so: a packet
payload is chosen by whoever sent it. But the model reads packets before
writing almost any observation about an address, so a large share of a
perfectly healthy baseline is going to carry the flag. If that share is most
of it, then a rule saying untrusted evidence cannot reach high confidence does
not harden this tool, it switches suppression off and buries the owner in
alerts about their own television.

MEASURE FIRST. The number below decides which rule is safe to write. There is
no recommendation in this file on purpose, because the recommendation depends
entirely on what it prints.

WHAT THE THREE POPULATIONS MEAN
  untrusted  written in a turn where the model had read fenced sensor text
  clean      written with no fenced text in that turn
  unknown    written before schema v17, so the question was never asked.
             NOT clean, and never counted as clean.
"""

import argparse
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import memory_engine as me  # noqa: E402


def _conn():
    conn = sqlite3.connect(f"file:{me.DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def overall(conn) -> None:
    rows = conn.execute(
        "SELECT evidence_untrusted AS f, COUNT(*) AS n "
        "FROM behavioral_session GROUP BY f").fetchall()
    counts = {"untrusted": 0, "clean": 0, "unknown": 0}
    for r in rows:
        if r["f"] is None:
            counts["unknown"] += r["n"]
        elif r["f"]:
            counts["untrusted"] += r["n"]
        else:
            counts["clean"] += r["n"]

    total = sum(counts.values())
    print("\nOBSERVATIONS, ALL TIME")
    if not total:
        print("  none recorded yet.")
        return
    for name in ("clean", "untrusted", "unknown"):
        n = counts[name]
        print(f"  {name:<10} {n:>7}  {100 * n / total:5.1f}%")
    print(f"  {'total':<10} {total:>7}")

    asked = counts["clean"] + counts["untrusted"]
    if not asked:
        print("\n  Every row predates schema v17, so the flag says nothing yet.")
        return
    share = 100 * counts["untrusted"] / asked
    print(f"\n  Of the rows where the question WAS asked, {share:.1f}% are "
          f"untrusted.")
    print("  This is the number that decides the rule. Nothing here recommends")
    print("  one: read it, then decide, and write the decision into 8.1F.")

    # Which sources, because "untrusted" with no source list is just a scary
    # word. If it is all query_packets, that is the benign explanation.
    sources = Counter()
    for r in conn.execute(
            "SELECT evidence_sources FROM behavioral_session "
            "WHERE evidence_untrusted = 1 AND evidence_sources IS NOT NULL"):
        try:
            for s in json.loads(r["evidence_sources"] or "[]"):
                sources[s] += 1
        except (ValueError, TypeError):
            continue
    if sources:
        print("\n  WHAT WAS BEING READ when those were written:")
        for name, n in sources.most_common():
            print(f"    {name:<24} {n}")


def by_confidence(conn) -> None:
    """
    The half that actually matters. A baseline at high confidence is one this
    tool has stopped alerting on, so untrusted evidence sitting under a high
    row is the exact shape 8.1F is worried about.
    """
    print("\nBASELINE ROWS BY CONFIDENCE, AND WHAT IS UNDER THEM")
    rows = conn.execute(
        "SELECT entity_type, entity_value, behavior_key, confidence, "
        "       alert_suppressed FROM behavioral_baseline").fetchall()
    if not rows:
        print("  no baseline rows yet.")
        return

    buckets = {}
    for b in rows:
        obs = conn.execute(
            "SELECT evidence_untrusted AS f FROM behavioral_session "
            " WHERE entity_type = ? AND entity_value = ? AND behavior_key = ?",
            (b["entity_type"], b["entity_value"], b["behavior_key"])).fetchall()
        untrusted = sum(1 for o in obs if o["f"])
        clean     = sum(1 for o in obs if o["f"] == 0)
        key = (b["confidence"] or "low", bool(b["alert_suppressed"]))
        slot = buckets.setdefault(key, {"rows": 0, "no_clean": 0,
                                        "untrusted": 0, "clean": 0})
        slot["rows"] += 1
        slot["untrusted"] += untrusted
        slot["clean"] += clean
        if untrusted and not clean:
            slot["no_clean"] += 1

    for (conf, suppressed), slot in sorted(buckets.items()):
        tag = "SUPPRESSED" if suppressed else "alerting"
        print(f"\n  confidence {conf:<7} {tag:<11} {slot['rows']} row(s)")
        print(f"    supporting observations: {slot['clean']} clean, "
              f"{slot['untrusted']} untrusted")
        # THE ONE FIGURE TO LOOK AT. A row resting on untrusted evidence and
        # nothing else is a claim this tool believes on the strength of text
        # somebody else chose.
        print(f"    rows with NO clean observation at all: {slot['no_clean']}")


def suppressed_detail(conn) -> None:
    print("\nEVERY SUPPRESSED BASELINE, WITH ITS EVIDENCE")
    rows = conn.execute(
        "SELECT entity_type, entity_value, behavior_key, confidence "
        "  FROM behavioral_baseline WHERE alert_suppressed = 1").fetchall()
    if not rows:
        print("  nothing is suppressed.")
        return
    for b in rows:
        prov = me.observation_provenance(
            b["entity_type"], b["entity_value"], b["behavior_key"])
        print(f"\n  {b['entity_type']}:{b['entity_value']} "
              f"[{b['behavior_key']}] confidence {b['confidence']}")
        # The note is already written for a human by memory_engine. Printing
        # it rather than restating it is the same rule as the settings panel
        # reading .env.example: one place says what this means.
        print(f"    {prov.get('note') or prov}")


def impact(conn) -> None:
    """
    What the rule built on 2026-09-04 would actually change here. DRY RUN.

    Worth running before a restart rather than after. A security control that
    turns out to move a hundred rows is one somebody switches off in a hurry
    and never switches back on, so the honest order is measure, decide, see
    what the decision costs, and only then run it.
    """
    print("\nWHAT THE RULE WOULD CHANGE (dry run, nothing is written)")
    rows = conn.execute(
        "SELECT entity_type, entity_value, behavior_key, confidence, "
        "       alert_suppressed FROM behavioral_baseline").fetchall()
    if not rows:
        print("  no baseline rows yet.")
        return

    held, already_quiet, unchanged = [], [], 0
    for b in rows:
        gate = me.evidence_gate(b["entity_type"], b["entity_value"],
                                b["behavior_key"])
        label = f"{b['entity_type']}:{b['entity_value']} [{b['behavior_key']}]"
        moved = False
        if b["confidence"] == "high" and not gate["may_reach_high"]:
            held.append((label, gate["clean_sessions"], gate["required"]))
            moved = True
        # An already-suppressed row is NOT un-suppressed by this. The rule
        # gates the ACT of suppressing, not rows that are already quiet.
        # Silently un-suppressing a pile of baselines on a restart is the kind
        # of surprise that makes an operator distrust the tool, so they are
        # listed for a person to decide about instead.
        if b["alert_suppressed"] and not gate["may_suppress"]:
            already_quiet.append(label)
            moved = True
        if not moved:
            unchanged += 1

    print(f"  {unchanged} row(s) unaffected.")
    if held:
        print(f"\n  {len(held)} row(s) would be held at medium instead of high,")
        print(f"  at the next rollup. Nothing is rewritten by this script:")
        for label, clean, need in held:
            print(f"    {label}  ({clean} clean session(s), {need} needed)")
    if already_quiet:
        print(f"\n  {len(already_quiet)} row(s) are ALREADY suppressed on "
              f"evidence this rule would now refuse.")
        print("  They are NOT un-suppressed automatically. Read them and")
        print("  decide, in the Review tab or with revert_suppression:")
        for label in already_quiet:
            print(f"    {label}")
    if not held and not already_quiet:
        print("  Nothing moves. The rule is already satisfied everywhere here.")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suppressed", action="store_true",
                    help="list every suppressed baseline with its evidence note")
    ap.add_argument("--impact", action="store_true",
                    help="dry run: what the 8.1F rule would change here")
    args = ap.parse_args()

    if not Path(me.DB_PATH).exists():
        print(f"No database at {Path(me.DB_PATH).name}. Nothing to measure.")
        return 1

    with _conn() as conn:
        overall(conn)
        by_confidence(conn)
        if args.impact:
            impact(conn)
        if args.suppressed:
            suppressed_detail(conn)

    print("\nRead-only. Nothing was changed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
