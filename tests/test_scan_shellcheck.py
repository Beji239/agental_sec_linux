"""
tests/test_scan_shellcheck.py, ShellCheck over every shell script, warnings and errors.

Every finding must be fixed or in tests/security_reviewed.json with the
reason it is fine. Needs the tools from scripts/install_test_tools.sh; without
them this is a skip.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _scan_review  # noqa: E402
import _scanners  # noqa: E402
import _skip  # noqa: E402

failures = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        failures.append(label)
        if detail:
            print(f"        {detail}")


try:
    found = _scanners.shellcheck()
    _scan_review.report(check, "shellcheck", found)
except _scanners.Unavailable as e:
    _skip.skip(str(e))

print(f"\n{'FAILED' if failures else 'ALL PASSED'}")
sys.exit(1 if failures else 0)
