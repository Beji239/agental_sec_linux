# core/version.py
# The version this folder runs. VERSION at the project root is the only place
# the number is written; a folder with git history adds the commits made since
# that release's tag, as "2.6.0 +2".

import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
_cached = None


def read_file(root: Path = None) -> str | None:
    """The number in VERSION, or None when it is missing or malformed."""
    try:
        text = ((root or ROOT) / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return text if _SEMVER.match(text) else None


def parse_describe(text: str) -> tuple | None:
    """'v2.6.0-11-g32cca04' into ('2.6.0', 11), or None."""
    m = re.fullmatch(r"v?(\d+\.\d+\.\d+)-(\d+)-g[0-9a-f]+", (text or "").strip())
    return (m.group(1), int(m.group(2))) if m else None


def _describe(root: Path) -> str | None:
    git = shutil.which("git")
    if not git or not (root / ".git").exists():
        return None
    try:
        out = subprocess.run(
            [git, "-C", str(root), "describe", "--tags", "--long",
             "--match", "v[0-9]*"],
            capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def info(root: Path = None) -> dict:
    """{'version', 'commits', 'label'}. Commits after the tag are counted only
    when the tag is this version's own, so a stale tag never shows."""
    root = root or ROOT
    version = read_file(root)
    commits = 0
    found = parse_describe(_describe(root) or "")
    if version and found and found[0] == version:
        commits = found[1]
    label = (version or "unknown") + (f" +{commits}" if commits else "")
    return {"version": version, "commits": commits, "label": label}


def current() -> dict:
    """info() for this folder, read once per run."""
    global _cached
    if _cached is None:
        _cached = info()
    return _cached
