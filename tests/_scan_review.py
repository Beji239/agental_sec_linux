# tests/_scan_review.py
# What the security scanners found and was looked at, with why it is fine.
# A finding is known by tool, rule, file and the text of the flagged line,
# so moving code does not matter but changing the line means a new look.
# The list is tests/security_reviewed.json; scripts/security_review.py
# refreshes it and keeps the reasons already written.

import collections
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
REVIEWED = ROOT / "tests" / "security_reviewed.json"
UNREVIEWED = "UNREVIEWED"

# Reasons that hold for every hit of a rule, written once after looking at
# all of them. A hit of these rules still has to be in the list.
RULE_REASONS = {
    ("bandit", "B608"): "SQL text from pieces; tests/test_sql_injection.py checks each one",
    ("bandit", "B105"): "a dictionary key or a detection token, not a password",
    ("bandit", "B108"): "a temp folder named as a place to watch, not a file written there",
    ("bandit", "B104"): "an address compared with the wildcard, not a bind; the dashboard binds 127.0.0.1",
    ("bandit", "B404"): "imports subprocess",
    ("bandit", "B603"): "an argument list with no shell",
    ("bandit", "B607"): "a system program found on PATH",
    ("bandit", "B110"): "an error ignored on purpose",
    ("bandit", "B112"): "an error ignored on purpose",
    ("bandit", "B601"): "a fixed agent verb or a checked path over SSH",
    ("bandit", "B507"): "the first key is pinned in KNOWN_HOSTS and a changed key refused; tests/test_linux_monitor_host_keys.py",
    ("bandit", "B305"): "AES-ECB as RFC 9001 header protection requires",
}


def norm(text: str) -> str:
    return " ".join((text or "").split())[:200]


def key(f: dict) -> tuple:
    return (f["tool"], f["rule"], f["path"], norm(f["text"]))


def load() -> list:
    try:
        return json.loads(REVIEWED.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []


def compare(tool: str, findings: list) -> dict:
    """New findings, stale entries, and entries still marked unreviewed."""
    entries = [e for e in load() if e["tool"] == tool]
    have = collections.Counter(key(e) for e in entries)
    got = collections.Counter(key(f) for f in findings)
    new = [k for k in got for _ in range(got[k] - have.get(k, 0))]
    stale = [k for k in have for _ in range(have[k] - got.get(k, 0))]
    unreviewed = [key(e) for e in entries
                  if not e.get("reason") or e["reason"] == UNREVIEWED]
    return {"new": new, "stale": stale, "unreviewed": unreviewed,
            "known": sum(min(got[k], have.get(k, 0)) for k in got)}


def report(check, tool: str, findings: list):
    """Run the three checks every scanner test makes."""
    r = compare(tool, findings)
    check(f"{tool}: no finding outside the reviewed list "
          f"({r['known']} reviewed)", not r["new"],
          "New:\n        " + "\n        ".join(map(str, r["new"][:20]))
          + "\n        Fix it, or run scripts/security_review.py and write "
            "why it is fine.")
    check(f"{tool}: every reviewed entry has a reason", not r["unreviewed"],
          "\n        ".join(map(str, r["unreviewed"][:20])))
    check(f"{tool}: no reviewed entry is left over", not r["stale"],
          "Gone from the code, remove with scripts/security_review.py:\n"
          "        " + "\n        ".join(map(str, r["stale"][:20])))
    return r
