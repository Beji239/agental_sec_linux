# core/own_activity.py
# Was a process started by this app's own test run? Answered from the
# kernel's process tree, never from a name or a path, because whoever starts a
# process chooses both. A process counts when one of its ancestors, under this
# same account, is Python running this project's scripts/run_tests.py or one
# of its tests/test_*.py files.

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAX_DEPTH = 32


def _read(pid: int, name: str) -> bytes | None:
    try:
        with open(f"/proc/{pid}/{name}", "rb") as f:
            return f.read()
    except OSError:
        return None


def _ppid(pid: int) -> int | None:
    """The parent from /proc/<pid>/stat. The name field can hold spaces and
    brackets, so the fields are read after its last ')'."""
    stat = _read(pid, "stat")
    if not stat:
        return None
    try:
        return int(stat[stat.rindex(b")") + 2:].split()[1])
    except (ValueError, IndexError):
        return None


def _uid(pid: int) -> int | None:
    status = _read(pid, "status")
    for line in (status or b"").splitlines():
        if line.startswith(b"Uid:"):
            try:
                return int(line.split()[1])
            except (ValueError, IndexError):
                return None
    return None


def _test_script(pid: int) -> str | None:
    """The project test script this process runs, as a path inside the
    project, or None."""
    raw = _read(pid, "cmdline")
    if not raw:
        return None
    argv = [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]
    if not argv:
        return None
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = ""
    if not (Path(argv[0]).name.startswith("python")
            or Path(exe).name.startswith("python")):
        return None
    # The script is the first argument that is not an option.
    script = next((a for a in argv[1:] if not a.startswith("-")), None)
    if not script:
        return None
    path = Path(script)
    if not path.is_absolute():
        try:
            path = Path(os.readlink(f"/proc/{pid}/cwd")) / path
        except OSError:
            return None
    try:
        path = path.resolve()
    except OSError:
        return None
    tests = ROOT / "tests"
    if path == ROOT / "scripts" / "run_tests.py" or (
            path.parent == tests and path.name.startswith("test_")
            and path.suffix == ".py"):
        return str(path.relative_to(ROOT))
    return None


def _account() -> int:
    """The account the tests run under: this one, or the project's owner when
    the app runs as root."""
    uid = os.getuid()
    if uid:
        return uid
    try:
        return ROOT.stat().st_uid
    except OSError:
        return -1


def test_run(pid=None, ppid=None) -> str | None:
    """
    Why this process is one of the app's own test runs, or None.

    Starts at pid, or at ppid when the process has already exited, and walks
    up the tree. It stops at the first ancestor under another account, so a
    root or system process can never vouch for anything.
    """
    me = _account()
    start = pid if pid and os.path.exists(f"/proc/{pid}") else ppid
    try:
        cur = int(start) if start else None
    except (TypeError, ValueError):
        return None
    seen = set()
    for _ in range(MAX_DEPTH):
        if not cur or cur <= 1 or cur in seen:
            return None
        seen.add(cur)
        if _uid(cur) != me:
            return None
        script = _test_script(cur)
        if script:
            return f"started by this app's own test run, {script} (pid {cur})"
        cur = _ppid(cur)
    return None
