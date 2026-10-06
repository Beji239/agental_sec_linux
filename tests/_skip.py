# tests/_skip.py
# A test that cannot run on this machine says why and exits 77. The runner
# reports that as a skip, so a fresh clone is not mistaken for broken code.

import sys

SKIP_EXIT = 77
_reasons = []


def skip(reason: str):
    """Nothing in this test can run here."""
    print(f"SKIP: {reason}", file=sys.stderr)
    sys.exit(SKIP_EXIT)


def skip_part(reason: str):
    """One section cannot run here, the rest still does."""
    _reasons.append(reason)
    print(f"  SKIP  {reason}")


def skipped() -> bool:
    return bool(_reasons)


def exit_if_skipped():
    """Call after a clean run: a test with a missing section is not a pass."""
    if _reasons:
        skip("; ".join(_reasons))
