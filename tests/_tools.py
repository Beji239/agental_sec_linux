# tests/_tools.py
# Finds a security test tool from scripts/install_test_tools.sh, or skips the
# test with a reason that names that script.

import os
import pathlib
import shutil

import _skip

TOOLS_HOME = pathlib.Path(os.environ.get("AGENTAL_TEST_TOOLS") or (
    pathlib.Path(os.environ.get("XDG_DATA_HOME")
                 or pathlib.Path.home() / ".local" / "share")
    / "agentalsec-test-tools"))


def find(name: str):
    """Path of the tool, or None."""
    for p in (TOOLS_HOME / "venv" / "bin" / name, TOOLS_HOME / "bin" / name):
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    return shutil.which(name)


def need(name: str) -> str:
    """Path of the tool; skips the test when it is not installed."""
    path = find(name)
    if not path:
        _skip.skip(f"needs {name}, install with ./scripts/install_test_tools.sh")
    return path
