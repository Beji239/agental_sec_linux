#!/usr/bin/env python3
"""
scripts/control_question_truth.py -- the negative control for the question-truth round.

WHAT A CONTROL IS FOR. tests/test_question_truth.py passing proves the NEW code
works. It does NOT prove the test can SEE the defects it was written for -- a
check that cannot see a defect keeps passing after the fix is reverted. So this
harness puts the OLD bodies back, one at a time, runs the round's own test file
in a copy of the tree, and requires the checks written for that defect to go
RED. A control that stays green means the check is broken, not that the code is
fine.

IT ALSO READS BACK WHAT IT WROTE. A patch that silently did not land -- an
import that raised, a string that changed shape since the reversion was
authored -- produces a "GREEN" that means nothing and looks exactly like a
check that cannot see the defect. Every reversion here is verified by reading
the file off disk; a reversion that did not change the bytes exits HARNESS
BROKEN with its own code, which is never confused with a defect.

METHOD. Two patch kinds, chosen by what the check reads:
  * a textual replacement, for the checks that read SOURCE (the four sites
    that carried the false claim);
  * an appended whole-body replacement, for the checks that CALL the function
    (the grammar, the hints, the refusal payload).

Run: python3 scripts/control_question_truth.py
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUBJECT = "tests/test_question_truth.py"

HARNESS_BROKEN = 3


def die(msg: str) -> None:
    print(f"\nHARNESS BROKEN: {msg}")
    sys.exit(HARNESS_BROKEN)


def copy_tree(dst: Path) -> None:
    """
    A working copy, symlinks preserved, caches and the big database left out.

    `symlinks=True` because a dangling link ABORTS the copy before a control
    runs, and the database because it is 1.4 GB and no check here needs it.
    """
    def ignore(_dir, names):
        skip = {"__pycache__", ".git", "logs"}
        return [n for n in names
                if n in skip or n.endswith(".db") or n.startswith("agental_sec.db")]
    shutil.copytree(ROOT, dst, symlinks=True, ignore=ignore)


def run_subject(tree: Path) -> tuple:
    """Run the round's test file in the copy. Returns (rc, stdout+stderr)."""
    proc = subprocess.run([sys.executable, SUBJECT], cwd=str(tree),
                          capture_output=True, text=True, timeout=900)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def failed_labels(out: str) -> set:
    """Every label the subject printed as FAIL, read OUT of its own output."""
    return {m.group(1).strip()
            for m in re.finditer(r"^  FAIL  (.*?): ", out, re.M)}


def apply_reversion(tree: Path, rel: str, old: str, new: str, label: str) -> None:
    """One textual replacement, verified by reading the file back off disk."""
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
    print(f"    patched {rel} ({label}, {len(old)} chars -> {len(new)})")


# THE REVERSIONS. Each names the defect it restores and the checks that must
# go red because of it. The old bodies are QUOTED from git history / the
# pre-round source, never paraphrased.

CONTROLS = [
    {
        "name": "C1 -- the md5sums grammar is a paraphrase of dpkg again",
        "kind": "text",
        "what": ("local_integrity._md5sums_ok restored to 'exactly two spaces' "
                 "and the 60-character slice with no marker"),
        "patch": {
            "rel": "tools/local_integrity.py",
            "old": '''    if _MD5SUMS_DIGEST is None:
        import re
        _MD5SUMS_DIGEST = re.compile(r"^[0-9a-fA-F]{32}")
        _MD5SUMS_LINE_OK = re.compile(r"^[0-9a-fA-F]{32}  +\\S.*$")''',
            "new": '''    if _MD5SUMS_DIGEST is None:
        import re
        # REVERTED FOR THE CONTROL: exactly two spaces, dpkg's rule replaced
        # by a paraphrase of it.
        _MD5SUMS_DIGEST = re.compile(r"^[0-9a-fA-F]{32}")
        _MD5SUMS_LINE_OK = re.compile(r"^[0-9a-fA-F]{32}  \\S.*$")''',
        },
        "expect_failed": [
            "THREE spaces are accepted too (dpkg rc 0) -- the old check "
            "refused this, which is dpkg's rule being paraphrase",
        ],
    },
    {
        "name": "C2 -- the reason is a bare 60-char slice again",
        "kind": "text",
        "what": "the marked ellipsis restored to the unmarked slice",
        "patch": {
            "rel": "tools/local_integrity.py",
            "old": '''        shown = line if len(line) <= 60 else line[:60] + f"...[{len(line)} chars]"''',
            "new": '''        shown = line[:60]   # REVERTED FOR THE CONTROL: unmarked slice''',
        },
        "expect_failed": [
            "and the evidence is MARKED as cut, so a complete file cannot "
            "be read as a truncated one",
        ],
    },
    {
        "name": "C3 -- the finding tells the owner a reinstall will fix it again",
        "kind": "text",
        "what": "the corrected sentence restored to the false advice",
        "patch": {
            "rel": "tools/local_integrity.py",
            "old": '''        f"WHAT ACTUALLY REPAIRS IT, measured rather than assumed: the "''',
            "new": '''        f"Reinstalling the package rewrites its control file and restores "
        f"coverage. WHAT ACTUALLY REPAIRS IT: the "''',
        },
        "expect_failed": [
            "the false instruction is GONE",
        ],
    },
    {
        "name": "C4 -- the hints fall back to 'ip' for anything unclassified",
        "kind": "text",
        "what": "core/questions._research_hints restored to the 'or \"ip\"' default",
        "patch": {
            "rel": "core/questions.py",
            "old": '''        kind = kind or enrichment.classify(entity_value)
        kind_known = bool(kind)''',
            "new": '''        kind = kind or enrichment.classify(entity_value) or "ip"
        kind_known = True   # REVERTED FOR THE CONTROL: everything is an IP''',
        },
        "expect_failed": [
            "a package name gets no IP lookups",
            "and it says the app could not classify it, rather than leaving "
            "an empty list to read as 'nowhere to look'",
        ],
    },
    {
        "name": "C5 -- the refusal forgets what was asked and how long it waited",
        "kind": "text",
        "what": "the enriched refusal restored to the four-field version",
        "patch": {
            "rel": "core/questions.py",
            "old": '''                "question_id": existing["id"],
                "asked_at": existing["asked_at"],''',
            "new": '''                "question_id": existing["id"],
                # REVERTED FOR THE CONTROL: the bare refusal.
                "asked_at": None,''',
        },
        "expect_failed": [
            "and when it was asked",
        ],
    },
    {
        "name": "C6 -- 'nothing has been looked up yet' covers the refusal again",
        "kind": "text",
        "what": "core/questions._what_was_tried restored to the single sentence",
        "patch": {
            "rel": "core/questions.py",
            "old": """            if not enrichment.classify(entity_value):
                return ([{"source": "enrichment",""",
            "new": """            if False:   # REVERTED FOR THE CONTROL
                return ([{"source": "enrichment",""",
        },
        "expect_failed": [
            "an unclassifiable thing says the worker REFUSED it",
        ],
    },
]


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="qt_control_"))
    print(f"negative control for the question-truth round")
    print(f"subject:  {SUBJECT}")
    print(f"workdir:  {work}\n")

    print("== baseline: the PRISTINE copy must be green before any control ==")
    base_tree = work / "baseline"
    copy_tree(base_tree)
    rc, out = run_subject(base_tree)
    base_failed = failed_labels(out)
    if rc != 0 or base_failed:
        print(out[-3000:])
        die(f"the pristine copy is not green (rc={rc}, failed={sorted(base_failed)}). "
            f"Every control below would be measuring this, not the reversion.")
    print(f"    pristine copy: rc 0, 0 failures. "
          f"{len(re.findall(r'^  PASS', out, re.M))} checks pass.\n")

    summary = []
    for spec in CONTROLS:
        print(f"== {spec['name']} ==")
        print(f"   {spec['what']}")
        tree = work / spec["name"].split(" ")[0]
        copy_tree(tree)
        apply_reversion(tree, spec["patch"]["rel"], spec["patch"]["old"],
                        spec["patch"]["new"], spec["name"])

        rc, out = run_subject(tree)
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
        print(f"\n{len(bad)} control(s) did not red their own checks. A control "
              f"that agrees with the fix is broken, or the check is blind.")
        shutil.rmtree(work, ignore_errors=True)
        return 1
    print(f"\nAll {len(summary)} controls held: each defect's checks go red "
          f"when the defect is put back.")
    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
