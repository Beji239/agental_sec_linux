#!/usr/bin/env python3
"""
scripts/control_threat_feeds_fixes.py — the negative control for register
section 16, the threat feeds round (tools/feed_matcher.py, tools/kev_cvss.py,
tools/runbook.py, core/oui.py, core/tool_registry.py), 2026-09-27.

WHAT A CONTROL IS FOR. tests/test_threat_feeds_fixes.py passing proves the NEW
code works. It does NOT prove the test can SEE the defects it was written for —
a check that cannot see a defect keeps passing after the fix is reverted. So
this harness puts the OLD behaviour back, one at a time, runs the round's own
test file in a copy of the tree, and requires the checks written for that
defect to go RED. A control that stays green means the check is broken, not
that the code is fine.

IT READS BACK WHAT IT WROTE. A patch that silently did not land — an anchor
that moved since the reversion was authored — produces a "GREEN" that means
nothing and looks exactly like a check that cannot see the defect. Every
reversion is verified against the bytes on disk, and one that did not change
them exits HARNESS BROKEN with its own code.

IT REQUIRES THE SUBJECT'S OWN CLOSING LINE. A subject that CRASHES prints no
closing line at all, and a missing line is not a green one: such a control
gets its own verdict and its own exit code, never confused with the outcome
this harness wants (checks red, rc 1, closing line present).

IT COMPARES THE COPIED SUBJECT AGAINST THE ORIGINAL before quoting any run,
because a harness that ran against a stale copy measures the wrong bytes.

METHOD. Textual replacements against the CURRENT source, each anchored on a
snippet asserted UNIQUE in its file. The old bodies are QUOTED from the
pre-round source; a behaviour that cannot be restored without also restoring
something the round's fixtures drive is moved at the LAYER the checks read,
and the control says in its own comment which layer it moved.

SIXTEEN OF THE CHECKS ARE MADE RED BY A FILE THE SUBJECT DOES NOT IMPORT
(scripts/update_oui.py is read as text, core/tool_registry.py's note is read
as text), so their controls patch the TEXT the check reads, which is the same
layer the check measures.

Run: python3 scripts/control_threat_feeds_fixes.py
"""
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUBJECT = "tests/test_threat_feeds_fixes.py"

HARNESS_BROKEN = 3
SUBJECT_CRASHED = 4


def die(msg: str) -> None:
    print(f"\nHARNESS BROKEN: {msg}")
    sys.exit(HARNESS_BROKEN)


def copy_tree(dst: Path) -> None:
    """A working copy; caches and the big database are left out."""
    def ignore(_dir, names):
        skip = {"__pycache__", ".git", "logs", ".pytest_cache"}
        return [n for n in names
                if n in skip or n.endswith(".db") or n.startswith("agental_sec.db")
                or n.endswith(".db-wal") or n.endswith(".db-shm")]
    shutil.copytree(ROOT, dst, symlinks=True, ignore=ignore)


def run_subject(tree: Path) -> tuple:
    proc = subprocess.run([sys.executable, SUBJECT], cwd=str(tree),
                          capture_output=True, text=True, timeout=1800)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def failed_labels(out: str) -> set:
    """Every label the subject printed as FAIL, read OUT of its own output.

    THE LABEL IS THE TEXT BETWEEN THE BRACKETS. The subject prints
    `FAIL  [T6] the label: value`, so a `\\[(.*?)\\]` capture keeps the `[T6]`
    prefix and can never equal a label written without it -- MEASURED on this
    harness's first run, every expectation came back MISSING while the output
    showed it red. The prefix is dropped here, and both spellings of the
    label are admitted so a future section marker cannot break the match.
    """
    out_labels = set()
    for m in re.finditer(r"^  FAIL  \[(.*?)\]: ", out, re.M):
        label = m.group(1).strip()
        out_labels.add(label)
        stripped = re.sub(r"^\[\w+\]\s*", "", label)
        if stripped != label:
            out_labels.add(stripped)
    return out_labels


def completed(out: str) -> bool:
    """The subject reached one of its OWN two endings."""
    return ("ALL CHECKS PASSED" in out) or ("FAILED  (" in out)


def apply_reversion(tree: Path, rel: str, old: str, new: str,
                    label: str) -> None:
    path = tree / rel
    if not path.exists():
        die(f"no such file for {label}: {rel}")
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        die(f"{label}: the anchor appears {count} times in {rel}, not once. "
            f"A reversion this ambiguous measures neither site.")
    patched = text.replace(old, new)
    if patched == text:
        die(f"{label}: the replacement changed nothing in {rel}")
    path.write_text(patched, encoding="utf-8")
    if path.read_text(encoding="utf-8") == text:
        die(f"{label}: the write did not land in {rel}")
    print(f"    patched {rel} ({len(old)} chars -> {len(new)})")


# THE REVERSIONS. Each names the defect it restores and the checks that must
# go red because of it. The IDs are the round's own: FED-1..FED-18, as written
# up in bugfinder.md and register section 16.
CONTROLS = [
    {
        "name": "C1 -- the family column lookup goes back to 'malware' (FED-4)",
        "file": "tools/feed_matcher.py",
        "patch": {
            "old": '        idx_malware = None\n'
                   '        for candidate in ("malware_printable", "fk_malware", "malware"):\n'
                   '            if candidate in header_cols:\n'
                   '                idx_malware = header_cols.index(candidate)\n'
                   '                break',
            "new": '        idx_malware = (header_cols.index("malware")\n'
                   '                       if "malware" in header_cols else None)',
        },
        "expect_failed": [
            "and the family is READ, not blank",
        ],
    },
    {
        "name": "C2 -- threatfox needs the abuse.ch key again (FED-6)",
        "file": "tools/feed_matcher.py",
        "patch": {
            "old": '        "needs_key": False,\n'
                   '        "gives": "Recent IOCs with the malware family attached.",',
            "new": '        "needs_key": True,\n'
                   '        "gives": "Recent IOCs with the malware family attached.",',
        },
        "expect_failed": [
            "needs_key is False now",
            "so no variable is required",
            "and there is no problem to report",
        ],
    },
    {
        "name": "C3 -- the 401 shares the 403 sentence again (FED-6)",
        "file": "tools/feed_matcher.py",
        "patch": {
            "old": '    if resp.status_code == 401:\n'
                   '        if send_key:\n'
                   '            return None, (f"{var} is set but the service answered 401 "',
            "new": '    if resp.status_code == 401:\n'
                   '        if send_key:\n'
                   '            return None, (f"key refused (HTTP 401). Check {var}.") or (f"{var} is set but the service answered 401 "',
        },
        "expect_failed": [
            "401 points at the HEADER",
            "the refusal does not share one sentence with the other status",
        ],
    },
    {
        "name": "C4 -- an empty feeds list widens to all five again (FED-7)",
        "file": "tools/feed_matcher.py",
        "patch": {
            "old": '    configured = block.get("feeds")\n'
                   '    if configured is not None and not configured:',
            "new": '    configured = block.get("feeds")\n'
                   '    if False:',
        },
        "expect_failed": [
            "it does not run",
            "the reason names the empty list",
        ],
    },
    {
        "name": "C5 -- match_once stops checking the cursor tables (FED-8)",
        "file": "tools/feed_matcher.py",
        "patch": {
            "old": '            for _table in ("packets", "dns_queries", "tls_hello"):\n'
                   '                if not _assert_cursor_safe(conn, _table, 0):\n'
                   '                    unsafe.append(_table)',
            "new": '            pass',
        },
        "expect_failed": [
            "match_once checks all three tables before reading them",
        ],
    },
    {
        "name": "C6 -- the pass stops naming an unsafe table (FED-8)",
        "file": "tools/feed_matcher.py",
        "patch": {
            "old": "        'cursor_tables_unsafe': unsafe,\n    }",
            "new": "    }",
        },
        "expect_failed": [
            "the pass names a table whose cursor cannot be trusted",
        ],
    },
    {
        "name": "C8 -- a table without AUTOINCREMENT passes the guard (FED-8)",
        "file": "tools/feed_matcher.py",
        "patch": {
            "old": '        if "autoincrement" in ddl.lower():\n            return True',
            "new": '        return True',
        },
        "expect_failed": [
            "a reused-id table is refused",
        ],
    },
    {
        "name": "C9 -- the model's note drops the reduced-severity sentence (FED-9)",
        "file": "core/tool_registry.py",
        "patch": {
            "old": '        out["severity_if_seen"] = severity\n        out["note"] = (\n            "This is on a live known-bad list. That is stronger evidence "\n            "than anything this app works out on its own, because it comes "\n            "from somebody with far more visibility than one home network."\n            + (f" The severity this app would raise for it is {severity}, not "',
            "new": '        out["severity_if_seen"] = severity\n        out["note"] = (\n            "This is on a live known-bad list. That is stronger evidence "\n            "than anything this app works out on its own, because it comes "\n            "from somebody with far more visibility than one home network."\n            + (f"Raised at {severity}." if False else\n               (f" The severity this app would raise for it is {severity}, not "',
        },
        "expect_failed": [
            "the model-facing note explains a reduced severity",
        ],
    },
    {
        "name": "C10 -- an empty work list claims completion again (FED-13)",
        "file": "tools/kev_cvss.py",
        "patch": {
            "old": '        if remaining == 0 and self._due_blocked:\n'
                   '            return f"Not running, and NOT complete: {self._due_blocked}"\n',
            "new": '',
        },
        "expect_failed": [
            "and the note says NOT complete",
            "and names the reason",
        ],
    },
    {
        "name": "C12 -- the rate sentence loses the quantity (FED-14)",
        "file": "tools/kev_cvss.py",
        "patch": {
            "old": '        if remaining is None:\n'
                   '            return head\n'
                   '        if remaining == 0:\n'
                   '            return head + " Nothing is waiting to be looked up."\n'
                   '        hours = remaining * per_cve / 3600 if per_cve else 0\n'
                   '        return (head + f" The {remaining} row(s) still waiting are about "\n'
                   '                       f"{hours:.1f} h ({hours * 60:.0f} min) of that.")',
            "new": '        return head',
        },
        "expect_failed": [
            "with nothing waiting, it says so",
        ],
    },
    {
        "name": "C13 -- the runbook note asserts an empty table again (FED-15)",
        "file": "tools/runbook.py",
        "patch": {
            "old": '        elif kept:\n'
                   '            note = (f"The CISA KEV mirror has NOT synced this run. That does "\n'
                   '                    f"not empty it: the table still holds the {kept:,} "\n'
                   '                    f"entries the last successful sync wrote, and Sync CISA KEV "\n'
                   '                    f"on that tab refreshes them.")',
            "new": '        elif kept:\n'
                   '            note = ("The CISA KEV mirror has NOT synced this run, so the "\n'
                   '                    "Runbook tab is showing the static entries only. ")',
        },
        "expect_failed": [
            "a run with no sync does not claim an empty table",
            "it names what the table still holds",
        ],
    },
    {
        "name": "C14 -- the runbook counts with a possibly-empty read (FED-15)",
        "file": "tools/runbook.py",
        "patch": {
            "old": '            return int(row[0]) if row else 0',
            "new": '            return 0 if row is None else 0',
        },
        "expect_failed": [
            "and reports the count as a field",
        ],
    },
    {
        "name": "C15 -- the authority-parent warning is removed (FED-16)",
        "file": "core/oui.py",
        "patch": {
            "old": '            if _names_authority(org) and not shorter:',
            "new": '            if False:',
        },
        "expect_failed": [
            "and the note says the block was subdivided",
            "naming the authority as the delegator",
        ],
    },
    {
        "name": "C16 -- the authority warning fires on every answer (FED-16)",
        "file": "core/oui.py",
        "patch": {
            "old": "            if _names_authority(org) and not shorter:\n"
                   "                longer_loaded = [n for n in sorted(loaded, reverse=True)\n"
                   "                                 if n > length]\n"
                   "                if longer_loaded:",
            "new": "            if not shorter:\n"
                   "                longer_loaded = [n for n in sorted(loaded, reverse=True)\n"
                   "                                 if n > length]\n"
                   "                if longer_loaded:",
        },
        "expect_failed": [
            "a real /28 registrant gets no warning",
        ],
    },
    {
        "name": "C17 -- the manuf overlap goes silent again (FED-17)",
        "file": "core/oui.py",
        "patch": {
            "old": '                    if bucket[key][0].strip().lower() != org.lower():\n'
                   '                        logger.info(\n'
                   '                            f"oui: {path.name} calls {key} {org!r}, while "\n'
                   '                            f"{bucket[key][1]} calls it {bucket[key][0]!r}. "\n'
                   '                            f"The IEEE file wins, by this function\'s own rule.")',
            "new": '                    pass',
        },
        "expect_failed": [
            "and the DISAGREEMENT is reported, with both names",
            "naming the files behind each",
        ],
    },
    {
        "name": "C18 -- the fallback overwrites the IEEE row again (FED-17)",
        "file": "core/oui.py",
        "patch": {
            "old": '                if key in bucket:\n'
                   '                    skipped_because_ieee += 1',
            "new": '                if False:\n'
                   '                    skipped_because_ieee += 1',
        },
        "expect_failed": [
            "the IEEE row is not overwritten by the fallback",
        ],
    },
    {
        "name": "C19 -- oui.status stops reporting the registry's age (FED-18)",
        "file": "core/oui.py",
        "patch": {
            "old": '        "file_age_days": ages,\n        "oldest_days": oldest,',
            "new": '',
        },
        "expect_failed": [
            "status() reports the registry's age",
            "and the per-file ages",
        ],
    },
    {
        "name": "C20 -- the update script stops printing the age (FED-18)",
        "file": "scripts/update_oui.py",
        "patch": {
            "old": '            print(f"registry age: {oldest:.0f} days old (oldest file). A run "',
            "new": '            print(f"age: {oldest:.0f} days. A run "',
        },
        "expect_failed": [
            "the update script reports the registry's age",
        ],
    },
    {
        "name": "C21 -- .env.example promises the key to threatfox again (FED-6)",
        "file": ".env.example",
        "patch": {
            "old": "# NOT THREATFOX, since 2026-09-27.",
            "new": "# ThreatFox also uses this key.",
        },
        "expect_failed": [
            ".env.example stops promising the key to threatfox",
        ],
    },
    {
        "name": "C22 -- the example config calls threatfox keyed again (FED-6)",
        "file": "config.linux.example.json",
        "patch": {
            "old": '      "  threatfox KEYLESS (corrected 2026-09-27, this line said \\"keyed\\"):",',
            "new": '      "  threatfox keyed (corrected 2026-09-27):",',
        },
        "expect_failed": [
            "the example config no longer calls threatfox keyed",
        ],
    },
]


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="s16_control_"))
    print("negative control for register section 16 (the threat feeds)")
    print(f"subject:  {SUBJECT}")
    print(f"workdir:  {work}\n")

    print("== baseline: the PRISTINE copy must be green before any control ==")
    base_tree = work / "baseline"
    copy_tree(base_tree)
    rc, out = run_subject(base_tree)
    base_failed = failed_labels(out)
    if rc != 0 or base_failed or not completed(out):
        print(out[-3000:])
        die(f"the pristine copy is not green (rc={rc}, "
            f"failed={sorted(base_failed)}, completed={completed(out)}). "
            f"Every control below would be measuring this, not the reversion.")
    print(f"    pristine copy: rc 0, 0 failures. "
          f"{len(re.findall(r'^  PASS', out, re.M))} checks pass.\n")

    summary = []
    for spec in CONTROLS:
        print(f"== {spec['name']} ==")
        tree = work / spec["name"].split(" ")[0]
        copy_tree(tree)
        apply_reversion(tree, spec["file"], spec["patch"]["old"],
                        spec["patch"]["new"], spec["name"])
        # The copy must really be a copy before this run is quoted.
        if subprocess.run(["diff", "-q", str(tree / SUBJECT),
                           str(ROOT / SUBJECT)],
                          capture_output=True).returncode != 0:
            die(f"{spec['name']}: the copied subject differs from the "
                f"original before the run; refusing to quote this control.")

        rc, out = run_subject(tree)
        if not completed(out):
            print(f"   SUBJECT PRINTED NO CLOSING LINE (rc={rc}). "
                  f"A crashed subject measures nothing.")
            print(out[-1500:])
            summary.append((spec["name"], "SUBJECT CRASHED"))
            continue

        got = failed_labels(out)
        missing = [e for e in spec["expect_failed"] if e not in got]
        if missing:
            print(f"   SUBJECT rc={rc}, red labels: {sorted(got)}")
            print(f"   MISSING EXPECTATIONS: {missing}")
            summary.append((spec["name"], "BROKEN EXPECTATION"))
            continue

        extra = sorted(got - set(spec["expect_failed"]))
        verdict = "RED AS INTENDED" if rc != 0 else "GREEN -- CHECK IS BLIND"
        print(f"   subject rc={rc}; the expected checks went red: "
              f"{len(spec['expect_failed'])} of {len(spec['expect_failed'])}")
        if extra:
            print(f"   (also red, and not claimed as this control's: {extra})")
        summary.append((spec["name"], verdict))

    print("\n" + "=" * 66)
    bad = [s for s in summary if s[1] != "RED AS INTENDED"]
    for name, verdict in summary:
        print(f"  {verdict:<24} {name}")
    print("=" * 66)
    if bad:
        print(f"\n{len(bad)} control(s) did not red their own checks. A "
              f"control that agrees with the fix is broken, or the check is "
              f"blind.")
        return 1
    print(f"\nAll {len(summary)} controls held: each defect's checks go red "
          f"when the defect is put back.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
