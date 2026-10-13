#!/usr/bin/env python3
# scripts/security_review.py
# Refreshes tests/security_reviewed.json from what the scanners find now.
# Reasons already written are kept, entries the code no longer has are
# dropped, and a new finding gets its rule's standing reason or UNREVIEWED,
# which fails the suite until someone writes why it is fine.
#
#     python3 scripts/security_review.py                 every scanner
#     python3 scripts/security_review.py bandit semgrep  just these

import collections
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

import _scan_review as sr  # noqa: E402
import _scanners  # noqa: E402
import _skip  # noqa: E402


def main(argv):
    tools = argv or list(_scanners.SCANNERS)
    old = sr.load()
    keep = [e for e in old if e["tool"] not in tools]
    reasons = collections.defaultdict(list)
    for e in old:
        reasons[sr.key(e)].append(e.get("reason") or sr.UNREVIEWED)
    for tool in tools:
        try:
            if tool == "pip-audit":
                found = (_scanners.pip_audit() + _scanners.pip_audit(installed=True))
            else:
                found = _scanners.SCANNERS[tool]()
        except (_scanners.Unavailable, SystemExit) as e:
            print(f"{tool}: not run ({e}), its entries are kept as they were")
            keep += [e for e in old if e["tool"] == tool]
            continue
        new = 0
        for f in found:
            k = sr.key(f)
            reason = (reasons[k].pop(0) if reasons[k]
                      else sr.RULE_REASONS.get((tool, f["rule"]), sr.UNREVIEWED))
            new += reason == sr.UNREVIEWED
            keep.append({"tool": tool, "rule": f["rule"], "path": f["path"],
                         "text": sr.norm(f["text"]), "reason": reason})
        print(f"{tool}: {len(found)} finding(s), {new} need a reason")
    keep.sort(key=lambda e: (e["tool"], e["path"], e["rule"], e["text"]))
    sr.REVIEWED.write_text(json.dumps(keep, indent=1) + "\n", encoding="utf-8")
    left = [e for e in keep if e["reason"] == sr.UNREVIEWED]
    print(f"\n{len(keep)} entries in {sr.REVIEWED.relative_to(ROOT)}, "
          f"{len(left)} marked {sr.UNREVIEWED}.")
    for e in left[:30]:
        print(f"  {e['tool']} {e['rule']} {e['path']}: {e['text'][:80]}")


if __name__ == "__main__":
    main(sys.argv[1:])
