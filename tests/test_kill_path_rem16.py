"""
tests/test_kill_path_rem16.py, REM-16: what the kill path did not do.

Real processes started by this test, signalled through the shipped module.

Run it directly: python3 tests/test_kill_path_rem16.py
"""
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import psutil                                           # noqa: E402
from core import capabilities as caps                   # noqa: E402
from tools import remediation_linux as rl               # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def alive(pid):
    try:
        return psutil.Process(pid).status() not in ("zombie", "dead")
    except psutil.NoSuchProcess:
        return False


def detached(cmd):
    """A process this test is not the parent of, so kill_process sees a non-child."""
    p = subprocess.Popen(["setsid", "sh", "-c", f"{cmd} & echo $!"],
                         stdout=subprocess.PIPE, text=True)
    pid = int(p.stdout.readline())
    p.wait()
    time.sleep(0.3)
    return pid


print("\n[1] a pidfd refuses a process whose start time does not match")
target = detached("sleep 60")
proc = psutil.Process(target)


class Recycled:
    pid = target

    def create_time(self):
        return proc.create_time() - 100


try:
    caps.open_pidfd(Recycled())
    check("refused", False, True)
except caps.CapabilityError as e:
    check("refused as a recycled pid", "reused" in str(e), True)
fd = caps.open_pidfd(proc)
check("the real process pins", fd is not None, True)
os.close(fd)

print("\n[2] the shim refuses a start time that does not match")
try:
    caps.get().process_kill(target, proc.name(), expected_started=proc.create_time() - 100)
    check("refused", False, True)
except caps.CapabilityError as e:
    check("refused", "started at a different time" in str(e), True)
check("and the process was not touched", alive(target), True)

print("\n[3] an ordinary kill still works, through the pinned path")
out = rl.kill_process(target)
check("success", out.get("success"), True)
check("gone", alive(target), False)

print("\n[4] include_children ends the tree, and only the tree")
bystander = detached("sleep 60")
parent = detached("sh -c 'sleep 60 & sleep 60 & wait'")
time.sleep(0.3)
kids = [c.pid for c in psutil.Process(parent).children(recursive=True)]
check("the tree has two children", len(kids), 2)
out = rl.kill_process(parent, include_children=True)
check("success", out.get("success"), True)
check("both children ended", sorted(out.get("children", {}).get("ended", [])), sorted(kids))
check("no child survived", [k for k in kids if alive(k)], [])
check("the parent is gone", alive(parent), False)
check("a process outside the tree is untouched", alive(bystander), True)

print("\n[4b] without the flag, a child is left running (the old behaviour)")
parent = detached("sh -c 'sleep 60 & wait'")
time.sleep(0.3)
kid = psutil.Process(parent).children()[0].pid
rl.kill_process(parent)
check("the child still runs", alive(kid), True)
rl.kill_process(kid)
rl.kill_process(bystander)

print("\n[5] a deleted program file is named on the answer")
tmp = pathlib.Path(tempfile.mkdtemp())
copy = tmp / "sleepcopy"
shutil.copy(shutil.which("sleep"), copy)
copy.chmod(0o755)
pid = detached(f"{copy} 60")
copy.unlink()
out = rl.kill_process(pid)
check("killed", out.get("success"), True)
check("flagged", out.get("exe_deleted"), True)
check("with a sentence", "deleted" in out.get("exe_note", ""), True)
pid = detached("sleep 60")
check("an ordinary process carries no flag", "exe_deleted" in rl.kill_process(pid), False)

print("\n[6] a survivor through the shim reports instead of crashing")
real_get = caps.get


class DoNothingShim:
    def process_kill(self, *a, **k):
        return {"killed": True, "forced": False}


caps.get = lambda: DoNothingShim()
try:
    pid = detached("sleep 60")
    stopped = psutil.Process(pid)
    stopped.suspend()
    orig = rl._confirm_gone
    rl._confirm_gone = lambda p, t: (False, "sleeping")
    out = rl.kill_process(pid, force=True)
    rl._confirm_gone = orig
    check("an answer, not a NameError", "is still" in out.get("error", ""), True)
finally:
    caps.get = real_get
    rl.kill_process(pid, force=True)

print("\n[7] the vault root is made owner-only")
old_root = rl.STAGING_ROOT
rl.STAGING_ROOT = pathlib.Path(tempfile.mkdtemp()) / "vault"
rl.STAGING_ROOT.mkdir(mode=0o755)
os.chmod(rl.STAGING_ROOT, 0o755)
rl._private_vault_root()
check("narrowed to 0700", oct(stat.S_IMODE(rl.STAGING_ROOT.stat().st_mode)), "0o700")
fresh = rl.STAGING_ROOT.parent / "fresh" / "vault"
rl.STAGING_ROOT = fresh
rl._private_vault_root()
check("a new one is 0700", oct(stat.S_IMODE(fresh.stat().st_mode)), "0o700")
rl.STAGING_ROOT = old_root

print("\n" + "=" * 62)
if fails:
    print(f"{len(fails)} FAILED: " + ", ".join(fails))
    sys.exit(1)
print("ALL CHECKS PASSED")
