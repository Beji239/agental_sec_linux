"""
scripts/detection_report.py, what the register says and what the database did.

READ ONLY. Nothing in this file writes to the database, and --backfill-preview
is named preview because that is all it does.

Three questions it answers:

  1. Which rules exist, and which have never actually fired.
  2. Which findings carry no detection id, because they were raised before ids
     existed, and what an exact title match WOULD claim them to be.
  3. Whether the sniffer's classifier has grown a threat label that nobody
     registered, which the app survives on purpose and would otherwise never
     mention.

WHY THE BACKFILL IS A PREVIEW AND NOT A COMMAND. Old rows record the rule that
raised them only as an English sentence. Matching "Threat detected:
dangerous_port_inbound" to PKT-1013 is right almost every time, and almost is
the problem: the rows where the guess is wrong would be indistinguishable from
the rows where it is right, and the whole point of the id is that it can be
trusted. So this prints the numbers and stops. Stamping them is a decision
with the counts in front of you, not a default.

USE:
    python scripts/detection_report.py
    python scripts/detection_report.py --backfill-preview
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import detections as det          # noqa: E402
from core import memory_engine as me        # noqa: E402


# The title each detection's call site writes, up to the first variable. Used
# ONLY by the preview: this is the inference, kept in one visible place rather
# than scattered so that anyone reading the preview can see what it rests on.
_TITLE_HINTS = {
    "PKT-1001": "Sustained high traffic volume:",
    "PKT-1002": "Regular-interval beaconing:",
    "PKT-1003": "Packet capture overflowed:",
    "EVT-1001": "Brute force detected:",
    "PRC-1001": "Suspicious process:",
    "LNX-1003": "Possible SSH break-in on",
    "LNX-1002": "SSH brute force against",
    "LNX-1004": "SSH log intake unavailable on",
    "LNX-1006": "Crontab changed on",
    "LNX-1007": "File changed on",
    "LNX-1008": "New SUID binary on",
    # T2, 2026-09-17. The three event categories and the three process types
    # that got ids. Their titles are built at the call site in adapters.py
    # rather than restated here: the two event ones prefix the id itself, so a
    # preview match on them would be matching the id against itself and would
    # claim rows that were never stamped. They are listed with the forms the
    # adapter writes so the preview is honest about what it WOULD claim.
    "LNX-1009": "LNX-1009 account created:",
    "LNX-1010": "LNX-1010 account deleted:",
    "LNX-1011": "LNX-1011 ssh key added:",
    # LNX-1101/1102/1103 are deliberately NOT here. The adapter writes the
    # process monitor's own description as the title ("Suspicious path: ..."
    # and so on), so there is no fixed prefix to match and any guess would be
    # the preview inventing a form the code never writes. Absent is the honest
    # answer; the preview says nothing about those rows rather than wrong.
    "NET-1001": "New device row:",
    "NET-1002": "Always-on device is absent:",
    "PRB-1001": "Enrolled device changed:",
    "PRB-1002": "Permanent device retired:",
    "REM-1001": "Process killed:",
    "REM-1002": "Port blocked:",
    "REM-1003": "Port unblocked:",
    "REM-1004": "Device blocked at this host:",
    "REM-1005": "Device ban lifted:",
    "REM-1006": "File quarantined:",
    "REM-1007": "File restored:",
}


def main():
    preview = "--backfill-preview" in sys.argv

    ov = me.detection_overview()
    if not ov["counted"]:
        print("THE FINDINGS TABLE COULD NOT BE READ.")
        print(ov["count_note"])
        print("Everything below is the register only. No counts, not zeroes.")
        print()

    live = [d for d in ov["detections"]
            if d["kind"] == "detection" and not d["retired"]]
    acts = [d for d in ov["detections"] if d["kind"] == "action_record"]
    gone = [d for d in ov["detections"] if d["retired"]]

    print(f"{len(live)} detections, {len(acts)} action records, "
          f"{len(gone)} retired "
          f"{'number' if len(gone) == 1 else 'numbers'}.")
    print()

    by_source = {}
    for d in live:
        by_source.setdefault(d["source"], []).append(d)

    for source in sorted(by_source):
        print(f"  {source}")
        for d in sorted(by_source[source], key=lambda x: x["detection_id"]):
            fired = ("never" if ov["counted"] and not d["findings_total"]
                     else ("?" if not ov["counted"]
                           else f"{d['findings_total']}"))
            sup = d["suppressions"]
            tail = ""
            if sup:
                where = ", ".join(
                    ("everywhere" if s["entity_value"] == "*"
                     else s["entity_value"]) for s in sup)
                tail = f"   SILENCED for {where}"
            print(f"    {d['detection_id']} r{d['rev']:<3} "
                  f"{d['name']:<30} fired {fired}{tail}")
        print()

    if ov["unstamped_findings"]:
        print(f"{ov['unstamped_findings']} findings carry no detection id.")
        print(ov["unstamped_note"])
        if not preview:
            print("Run with --backfill-preview to see what a title match "
                  "would claim them to be. It writes nothing.")
        print()

    # Has the classifier grown a label nobody registered. The app raises those
    # under PKT-1099 rather than losing them, which means nothing on screen
    # says the register is behind. This is the thing that says it.
    try:
        with me._get_conn() as c:
            labels = [r[0] for r in c.execute(
                "SELECT DISTINCT threat_label FROM packets "
                "WHERE threat_label IS NOT NULL").fetchall()]
    except Exception as e:
        labels = None
        print(f"Could not read threat labels: {e}")
        print("So this run cannot say whether the register is behind the "
              "classifier. That is not the same as saying it is not.")
        print()

    if labels is not None:
        unmapped = det.unmapped_threat_prefixes(labels)
        if unmapped:
            print("THREAT LABELS WITH NO REGISTERED DETECTION:")
            for u in unmapped:
                print(f"  {u}")
            print("These raise findings under PKT-1099. Add them to "
                  "core/detections._REGISTER.")
        elif labels:
            print(f"Every threat label in the database ({len(labels)} "
                  f"distinct) maps to a registered detection.")
        else:
            # THE SAME FAULT AS TODO 108's cleanup script, which printed
            # "Nothing else points at those sensor rows. Checked, not
            # assumed." on a run with nothing to check. True, empty, and it
            # reads as a reassurance. With no labels stored there is no
            # evidence either way and the line has to say so.
            print("No threat labels are stored yet, so this run cannot say "
                  "whether the register is behind the classifier. Not a "
                  "clean bill of health, just nothing to compare.")
        print()

    if preview:
        print("BACKFILL PREVIEW. NOTHING IS WRITTEN.")
        print("What an exact title-prefix match would claim, for the rows "
              "that carry no id:")
        print()
        try:
            with me._get_conn() as c:
                rows = c.execute(
                    "SELECT id, title FROM findings "
                    "WHERE detection_id IS NULL").fetchall()
        except Exception as e:
            print(f"  Could not read them: {e}")
            return

        claimed, unclaimed = {}, 0
        for r in rows:
            title = r["title"] or ""
            hit = None
            for did, prefix in _TITLE_HINTS.items():
                if title.startswith(prefix):
                    hit = did
                    break
            if hit is None and title.startswith("Threat detected: "):
                hit = det.detection_for_threat(
                    title[len("Threat detected: "):]) or "PKT-1099"
            if hit:
                claimed[hit] = claimed.get(hit, 0) + 1
            else:
                unclaimed += 1

        for did in sorted(claimed):
            d = det.DETECTIONS.get(did)
            print(f"  {did}  {claimed[did]:>6}  {d.name if d else '?'}")
        print(f"  no match  {unclaimed:>6}  would stay NULL")
        print()
        print("THE HONEST CAVEAT, and it is why this stops here. A title "
              "prefix is not a record of which rule ran, it is a sentence "
              "that rule happened to write. Two rules that ever shared a "
              "wording, or one whose wording changed, produce rows that are "
              "confidently wrong and indistinguishable from the right ones. "
              "NULL already says 'raised before this existed', which is true "
              "about every one of them.")


if __name__ == "__main__":
    main()
