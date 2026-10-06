#!/usr/bin/env python3
# scripts/run_tests.py, run every test in tests/, one command.
#
# Written 2026-09-05. There are 40-odd files in tests/ and the README named
# two of them, so "run the tests" meant remembering which ones existed. That
# is how a test stops being run: not by being deleted, by being forgotten.
#
# PREREQUISITES
#   python 3.10 or newer, and whatever each test itself imports.
#   Run it from anywhere. It finds the project root from its own path.
#
#   python scripts/run_tests.py
#   python scripts/run_tests.py --only enrichment
#   python scripts/run_tests.py --list
#   python scripts/run_tests.py --strict          # a skip is a failure
#
# HOW THE TESTS IN THIS PROJECT WORK, since they are not pytest.
# Every file in tests/ is a standalone script. It prints its own checks, then
# exits 0 when they all passed and 1 when any did not. So this runner does not
# need to understand any of them, it only has to start them and read the exit
# code. Adding a test file is enough to get it run, there is no list to update.
#
# WHY A SKIP IS ITS OWN RESULT, AND NOT A PASS.
# Some of these need Windows, some need a database, some need a host to be up.
# Python exits 1 for a failed assertion and also for a missing import, so
# treating every 1 as a failure buries the real ones under environment noise,
# and treating them as passes is worse: a test that never ran reads as green.
# So a run that died on an import is SKIPPED, printed in its own list at the
# end, and --strict turns those into failures for CI, where nothing should be
# unrunnable.
#
# The obvious alternative was a skip marker inside each test file. It would be
# more precise and it means editing 40 files, and any file that did not get
# the marker silently goes back to looking like a failure. Reading the reason
# out of the traceback is less tidy and needs nothing from the tests.

import argparse
import atexit
import os
import pathlib
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"

# Matched against the tail of stderr. These mean the environment could not
# run the test, not that the code under test is wrong.
CANNOT_RUN = [
    (r"ModuleNotFoundError: No module named '([^']+)'", "needs {0}"),
    (r"ImportError: DLL load failed", "needs a library this platform lacks"),
    (r"ImportError: cannot import name '([^']+)'", "cannot import {0}"),
    (r"sqlite3.OperationalError: unable to open database", "needs the database"),
    (r"FileNotFoundError: .*agental_sec\.db", "needs the database"),
]


def why_skipped(stderr: str):
    """The reason this could not run here, or None if it actually failed."""
    for pattern, template in CANNOT_RUN:
        m = re.search(pattern, stderr)
        if m:
            return template.format(*m.groups()) if m.groups() else template
    return None


def _child_env() -> dict:
    """
    The child's environment, with its output forced to UTF-8.

    THIS WAS A BUG IN THIS FILE, found on the first real run, 2026-09-05.
    test_api_hardening feeds "١٢٣" to a route on purpose and prints it in the
    check label. Reading a child's output through a pipe makes Python use the
    locale encoding for stdout, which on Windows is cp1252, so the test died
    with UnicodeEncodeError while PRINTING a check that had passed. The runner
    then reported a failure the test does not have.

    Worth the note because of what it nearly cost. A runner that invents
    failures is worse than no runner: the first thing anybody does with a red
    result they cannot reproduce by hand is stop trusting the tool.

    PYTHONIOENCODING covers every version; PYTHONUTF8 is belt and braces on
    3.7 and later. Neither changes what the test does, only how its output is
    written down.
    """
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    env["AGENTALSEC_TEST_DB"] = str(_scratch_db())
    env["TMPDIR"] = str(_test_tmp())
    return env


_TEST_TMP = None


def _test_tmp() -> pathlib.Path:
    """
    The children's temp directory, under the user's state directory.

    Tests start throwaway programs from tempfile directories, and under /tmp
    the live eBPF sensor reported each one as a program run from a staging
    directory. Not inside the project either: remediation refuses to touch
    files in the app's own folder, so its tests need a path outside it. Tests
    that need a real staging path ask for /tmp by name.
    """
    global _TEST_TMP
    if _TEST_TMP is None:
        state = os.environ.get("XDG_STATE_HOME") or os.path.expanduser(
            "~/.local/state")
        base = pathlib.Path(state) / "agentalsec-tests"
        base.mkdir(parents=True, exist_ok=True)
        _TEST_TMP = pathlib.Path(tempfile.mkdtemp(prefix="run-", dir=base))
        atexit.register(shutil.rmtree, _TEST_TMP, True)
    return _TEST_TMP


_SCRATCH = None


def _scratch_db() -> pathlib.Path:
    """
    A throwaway database, built once per run, that the children use instead of
    the real one.

    TODO 108, 2026-09-14. WHY THIS IS HERE.

    Five test files were writing to, or reading from, the project's actual
    database. Not on purpose and not mentioned anywhere in them: they exercise
    code that goes through memory_engine.DB_PATH, and DB_PATH is the file
    beside main.py, which on a working install is the evidence store. On the
    machine this was found on that file is 1.6 GB.

    Two of them inserted rows on every single run. test_pcap_detection put
    nine sensors in `sensors`, one per analyse call, each with a fresh random
    id so repeated runs pile up rather than replace. test_process_inspection
    queued the test runner's own python binary for hash enrichment.

    NEITHER TEST WAS WRONG ABOUT ANYTHING IT CHECKS. That is what made it
    invisible: they passed, they still pass, and the damage was a side effect
    nobody was looking at. It was found because an empty database left behind
    in a sandbox made a THIRD test fail on the next run, which is the only
    reason anyone looked.

    So rather than fix the five and trust the sixth, the runner takes the real
    database off the table for every child it starts. A test that forgets to
    isolate itself now writes to a temp file that is thrown away.

    THE HONEST LIMIT. This covers tests started BY THIS RUNNER. A test run by
    hand, `python tests/test_x.py`, still sees the real DB_PATH. The two known
    offenders repoint it themselves for that reason, and a new one will not.
    A test that cares must not rely on this.
    """
    global _SCRATCH
    if _SCRATCH is not None:
        return _SCRATCH
    d = pathlib.Path(tempfile.mkdtemp(prefix="agentalsec_tests_"))
    _SCRATCH = d / "scratch.db"
    schema = ROOT / "Schema.SQL"
    if schema.exists():
        # Built from the real schema so a test that reads finds tables rather
        # than "no such table", which is a different and much more confusing
        # failure than the one it is meant to produce.
        conn = sqlite3.connect(_SCRATCH)
        try:
            conn.executescript(schema.read_text(encoding="utf-8"))
            conn.commit()
        finally:
            conn.close()
    return _SCRATCH


def run_one(path: pathlib.Path, timeout: int):
    started = time.time()
    try:
        p = subprocess.run(
            [sys.executable, str(path)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            env=_child_env(),
        )
    except subprocess.TimeoutExpired:
        return {
            "name": path.name, "state": "TIMEOUT", "secs": time.time() - started,
            "reason": f"still running after {timeout}s", "output": "",
        }

    secs = time.time() - started
    out = (p.stdout or "") + (p.stderr or "")

    if p.returncode == 0:
        return {"name": path.name, "state": "PASS", "secs": secs,
                "reason": "", "output": out}

    # Exit 77 is a test saying it cannot run here (tests/_skip.py).
    if p.returncode == 77:
        said = re.findall(r"^SKIP: (.+)$", p.stderr or "", re.M)
        return {"name": path.name, "state": "SKIP", "secs": secs,
                "reason": said[-1] if said else "the test said it cannot run here",
                "output": out}

    reason = why_skipped(p.stderr or "")
    if reason:
        return {"name": path.name, "state": "SKIP", "secs": secs,
                "reason": reason, "output": out}

    return {"name": path.name, "state": "FAIL", "secs": secs,
            "reason": f"exit {p.returncode}", "output": out}


def main():
    ap = argparse.ArgumentParser(
        description="Run every standalone test in tests/.")
    ap.add_argument("--only", default="",
                    help="substring of the filename, run just those")
    ap.add_argument("--list", action="store_true",
                    help="print what would run and stop")
    ap.add_argument("--timeout", type=int, default=180,
                    help="seconds per test, default 180")
    ap.add_argument("--strict", action="store_true",
                    help="a skipped test counts as a failure")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print the output of passing tests too")
    args = ap.parse_args()

    if not TESTS.is_dir():
        print(f"No tests directory at {TESTS}")
        return 2

    files = sorted(TESTS.glob("test_*.py"))
    if args.only:
        files = [f for f in files if args.only.lower() in f.name.lower()]

    if not files:
        print("Nothing matched." if args.only else "No test files found.")
        return 2

    if args.list:
        for f in files:
            print(f"  {f.name}")
        print(f"\n{len(files)} files")
        return 0

    print(f"Running {len(files)} test files from {TESTS}")
    print(f"Python {sys.version.split()[0]}, timeout {args.timeout}s each\n")

    live = sys.stdout.isatty()
    results = []
    for f in files:
        # Printed before the run, not after, so a hang names the file it hung
        # on instead of leaving you with the last line that finished.
        # The "now running" line only overwrites itself on a terminal. Piped
        # into a file or a CI log the carriage return is not honoured and you
        # get both lines jammed together, so there it just does not print.
        if live:
            print(f"  ...      {f.name}", end="", flush=True)
        r = run_one(f, args.timeout)
        results.append(r)
        tail = f" ({r['reason']})" if r["reason"] else ""
        if live:
            print("\r" + " " * 78, end="\r")
        print(f"  {r['state']:<8} {r['name']:<40}{r['secs']:5.1f}s{tail}")

        if r["state"] in ("FAIL", "TIMEOUT") or (args.verbose and r["output"]):
            for line in r["output"].rstrip().splitlines():
                print(f"        {line}")
            print()

    passed = [r for r in results if r["state"] == "PASS"]
    failed = [r for r in results if r["state"] in ("FAIL", "TIMEOUT")]
    skipped = [r for r in results if r["state"] == "SKIP"]

    print("\n" + "," * 60)
    print(f"{len(passed)} passed, {len(failed)} failed, {len(skipped)} skipped")

    # Skips get named every time. A count on its own is the thing people stop
    # reading, and then a test is unrunnable for a month and nobody notices.
    if skipped:
        print("\nCould not run here:")
        for r in skipped:
            print(f"  {r['name']:<40}{r['reason']}")
        if not args.strict:
            print("  These did not fail the run. Use --strict in CI.")

    if failed:
        print("\nFailed:")
        for r in failed:
            print(f"  {r['name']:<40}{r['reason']}")

    print("\nNot included here, run it separately, it is a release gate and\n"
          "not a test: python scripts/check_no_local_details.py --release <copy>")

    bad = len(failed) + (len(skipped) if args.strict else 0)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
