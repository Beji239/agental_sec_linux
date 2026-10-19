"""
tests/test_scan_trivy.py, Trivy over the Docker image, for known flaws and secrets.
runner-timeout: 2400, the build and the vulnerability database take minutes.

A flaw with a fix available fails: rebuild the image (its apt-get upgrade
takes Debian's fixes) or raise the package floor. Flaws Debian has not fixed
yet are counted only. Needs docker and the tools from
scripts/install_test_tools.sh; without them, or without a Dockerfile in this
folder, this is a skip.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
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
    found = _scanners.trivy()
    check("no flaw with a fix available, and no secret, in the image",
          not found,
          "\n        ".join(f"{f['rule']} {f['path']}: {f['text']}"
                             for f in found[:30]))
    print(f"  {_scanners.trivy.unfixed} flaw(s) wait on a fix from the "
          f"distribution; counted, not failed.")
except _scanners.Unavailable as e:
    _skip.skip(str(e))

print(f"\n{'FAILED' if failures else 'ALL PASSED'}")
sys.exit(1 if failures else 0)
