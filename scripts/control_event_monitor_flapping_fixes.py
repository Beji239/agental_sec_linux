#!/usr/bin/env python3
"""
scripts/control_event_monitor_flapping_fixes.py — the negative control for
EM2-4, the service-burst counting round (2026-09-27).

WHAT A CONTROL IS FOR. tests/test_event_monitor_flapping_fixes.py passing
proves the NEW code works. It does NOT prove the test can SEE the defects it
was written for — a check that cannot see a defect keeps passing after the fix
is reverted. So this harness puts the OLD behaviour back, one at a time, runs
the round's own test file in a copy of the tree, and requires the checks
written for that defect to go RED. A control that stays green means the check
is broken, not that the code is fine.

IT ALSO READS BACK WHAT IT WROTE. A patch that silently did not land produces
a "GREEN" that means nothing; every reversion here is verified by reading the
file off disk, and a reversion that did not change the bytes exits HARNESS
BROKEN with its own code, never confused with a defect.

AND IT REQUIRES THE SUBJECT'S OWN CLOSING LINE. A subject that CRASHES prints
no closing line, and a missing line is not a green one: the harness fails such
a control with its own code, distinguishing a crash from the outcome it wants
(checks red, rc 1, closing line present).

METHOD. Textual replacements against the CURRENT source, each anchored on a
unique snippet, each verified by re-reading. The subject is copied and
`diff -q`-compared against the original before any run is quoted.

Run: python3 scripts/control_event_monitor_flapping_fixes.py
"""
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUBJECT = "tests/test_event_monitor_flapping_fixes.py"

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
                if n in skip or n.endswith(".db")
                or n.startswith("agental_sec.db")
                or n.endswith(".db-wal") or n.endswith(".db-shm")]
    shutil.copytree(ROOT, dst, symlinks=True, ignore=ignore)


def run_subject(tree: Path) -> tuple:
    proc = subprocess.run([sys.executable, SUBJECT], cwd=str(tree),
                          capture_output=True, text=True, timeout=900)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def failed_before_closing(out: str) -> set:
    """
    The labels the subject printed as FAIL BEFORE its own closing line.

    A crash leaves no closing line at all, so the whole output is searched;
    a completed run is cut at the closing line so a stale traceback that
    happens to contain the word FAIL is not read as a red check.
    """
    for marker in ("ALL PASS", "FAILED: ["):
        idx = out.find(marker)
        if idx != -1:
            out = out[:idx]
    return {m.group(1).strip()
            for m in re.finditer(r"^  FAIL  (.*?): ", out, re.M)}


def completed(out: str) -> bool:
    return ("ALL PASS" in out) or ("FAILED: [" in out)


def patch_file(path: Path, old: str, new: str) -> bool:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        return False
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    return True


# THE REVERSIONS. Each is the OLD behaviour, restored exactly, anchored on
# the current text. The label lists the checks that MUST go red for it.
CONTROLS = [
    (
        "C1 the PAIR is counted twice again (both lines counted)",
        "tools/event_monitor_linux.py",
        # Count the "Starting" form as a start as well, the way the old
        # _unit_of(message) call site did -- one start then counts twice.
        '        m = _UNIT_STARTED_LINE.search(message)\n'
        '        unit = m.group(1) if m else ""\n'
        '        if unit:\n'
        '            n = _burst((manager, unit), _service_starts, _service_start_seen,',
        '        m = _UNIT_STARTED_LINE.search(message)\n'
        '        if "Starting " in message:\n'
        '            m = None\n'
        '        unit = m.group(1) if m else (_unit_of(message) if "Starting " in message else "")\n'
        '        if unit:\n'
        '            n = _burst((manager, unit), _service_starts, _service_start_seen,',
        ["two starts (their four lines) do NOT fire"],
    ),
    (
        "C2 the mark is gone (the same line counts every time it is read)",
        "tools/event_monitor_linux.py",
        "    if mark is not None:\n"
        "        if mark in seen:\n"
        "            return 0\n"
        "        seen[mark] = True",
        "    if False:\n"
        "        if mark in seen:\n"
        "            return 0\n"
        "        seen[mark] = True",
        ["and reading the identical lines again fires NOTHING",
         "nor does the SAME line from the second source double it"],
    ),
    (
        "C3 the READ clock is used again (the backlog lands in one window)",
        "tools/event_monitor_linux.py",
        "    event_now = _event_seconds(entry) or now",
        "    event_now = now",
        ["a start two hours before the window is not in it"],
    ),
    (
        "C4 the MANAGER is dropped again (one name, every instance merged)",
        "tools/event_monitor_linux.py",
        "    manager = _manager_of(entry)",
        "    manager = \"\"",
        ["three managers starting one unit each do NOT fire"],
    ),
    (
        "C5 the failure rule counts 'Failed to start' again (both forms)",
        "tools/event_monitor_linux.py",
        '        m = _UNIT_FAILED_LINE.search(message)\n'
        '        unit = m.group(1) if m else ""\n',
        '        m = _UNIT_FAILED_LINE.search(message)\n'
        '        unit = m.group(1) if m else _unit_of(message)\n',
        ["three 'Failed to start' lines alone do NOT fire"],
    ),
    (
        "C6 the start rule counts a form a restart loop never writes",
        "tools/event_monitor_linux.py",
        # Anchored on the ONE character pair that differs, so this file
        # never has to re-embed the line's own escaping.
        r'r"^Started\s+([\w@.\-]+',
        r'r"^Starting\s+([\w@.\-]+',
        ["a unit started five times inside the window fires ONCE",
         "six starts are TWO findings of three, not one silent run"],
    ),
]


def main() -> int:
    subject_src = ROOT / SUBJECT
    if not subject_src.exists():
        die(f"the subject {SUBJECT} does not exist")

    print(f"control harness for {SUBJECT}")
    print(f"subject sha256: {__import__('hashlib').sha256(subject_src.read_bytes()).hexdigest()[:16]}"
          f"  ({subject_src.stat().st_size} bytes)")

    tmp = Path(tempfile.mkdtemp(prefix="em24_control_"))
    print(f"scratch: {tmp}\n")

    green = 0
    for label, rel, old, new, must_red in CONTROLS:
        tree = tmp / label.split()[0]
        copy_tree(tree)
        target = tree / rel
        # THE SUBJECT IN THE COPY MUST BE THE SUBJECT MEASURED: compared
        # before a run is quoted, or the harness measures the wrong bytes.
        if subprocess.run(["diff", "-q", str(subject_src),
                           str(tree / SUBJECT)]).returncode != 0:
            die(f"{label}: the copied subject differs from the original")

        before = target.read_text(encoding="utf-8")
        if not patch_file(target, old, new):
            die(f"{label}: the anchor was not found in {rel} -- the source "
                f"moved since this control was written; it would have tested "
                f"NOTHING")
        after = target.read_text(encoding="utf-8")
        if after == before:
            die(f"{label}: the patch did not change the bytes of {rel}")

        rc, out = run_subject(tree)
        if not completed(out):
            print(f"  {label}: SUBJECT CRASHED (rc {rc}) -- not a result")
            print((out or "")[-400:])
            return SUBJECT_CRASHED

        reds = failed_before_closing(out)
        missing = [m for m in must_red if not any(m in r for r in reds)]
        if rc != 1:
            print(f"  {label}: rc {rc} (expected 1 for a red run)")
            missing.append("rc 1")
        if missing:
            print(f"  {label}: STILL GREEN -- the check cannot see this "
                  f"defect: {missing}")
            print(f"    reds seen: {sorted(reds)}")
            green += 1
        else:
            print(f"  {label}: red as intended -- {len(must_red)} check(s) "
                  f"caught it")

    print(f"\n{len(CONTROLS) - green} of {len(CONTROLS)} controls red as "
          f"intended")
    if green:
        print(f"{green} CONTROL(S) DID NOT GO RED -- the checks named above "
              f"cannot see their defect")
        return 1
    print("ALL CONTROLS RED AS INTENDED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
