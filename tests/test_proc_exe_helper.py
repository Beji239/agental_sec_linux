"""
tests/test_proc_exe_helper.py: PROC-6, another account's exe through the helper.

The read helper's proc_exe verb lists every process's running file with its
start time. process_monitor_linux asks it once per pass, only for rows whose
exe was refused, and takes a path only when pid AND start time match.
"""
import importlib.util
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import local_integrity as li            # noqa: E402
from tools import process_monitor_linux as pml     # noqa: E402

fails = []


def check(label, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f": {detail}" if detail else ""))
    if not ok:
        fails.append(label)


HELPER = ROOT / "tools" / "read_helper.py"
spec = importlib.util.spec_from_file_location("read_helper", HELPER)
rh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rh)


print("\n[1] THE VERB, run directly (unelevated it can read its own process)")
out = rh.verb_proc_exe()
me = str(os.getpid())
mine = out["processes"].get(me) or {}
check("its own process is listed with the real file",
      mine.get("exe") == os.readlink(f"/proc/{me}/exe"), repr(mine))
check("with the same start time the sensor reads",
      mine.get("start_ticks") == pml._own_start_ticks(os.getpid()))
kthread = out["processes"].get("2") or {}
check("a kernel thread has no exe and says why",
      kthread.get("exe") is None and bool(kthread.get("reason")), repr(kthread))
check("the verb is in the table and the handlers",
      "proc_exe" in rh.VERBS and rh.HANDLERS.get("proc_exe") is rh.verb_proc_exe)


print("\n[2] NO ARGUMENT REACHES IT: `proc_exe 1` is refused")
p = subprocess.run([sys.executable, str(HELPER), "proc_exe", "1"],
                   capture_output=True, text=True, timeout=30)
check("exit 1", p.returncode == 1, str(p.returncode))
check("and nothing was read", json.loads(p.stdout or "{}").get("ok") is False)


print("\n[3] THE SENSOR'S FILL, with the helper stubbed")
pid1_ticks = pml._own_start_ticks(1)


def row(pid=1):
    return {"pid": pid, "exe": None,
            "unreadable": {"exe": "this account was REFUSED exe"}}


calls = {"n": 0}


def stub(status, data=None):
    li.helper_status = lambda *a, **k: status

    def call(verb, timeout=0):
        calls["n"] += 1
        return {"ok": True, "data": data, "reason": None}
    li.helper_call = call


orig_status, orig_call, orig_elev = li.helper_status, li.helper_call, pml.ELEVATED
pml.ELEVATED = False
avail = {"available": True, "verbs": ["proc_exe", "sudoers"]}

stub(avail, {"processes": {"1": {"exe": "/usr/lib/systemd/systemd",
                                 "start_ticks": pid1_ticks}}})
r = row()
rep = pml._fill_exe_from_helper([r])
check("a matching pid and start time fills the path",
      r["exe"] == "/usr/lib/systemd/systemd", repr(r))
check("marked as read through the helper", r.get("exe_via") == "read_helper")
check("and the refusal note is gone", "exe" not in r["unreadable"])
check("the report counts it", rep["filled"] == 1 and rep["asked"], repr(rep))

stub(avail, {"processes": {"1": {"exe": "/tmp/other",
                                 "start_ticks": (pid1_ticks or 0) + 1}}})
r = row()
pml._fill_exe_from_helper([r])
check("a reused pid (start time differs) is NOT filled", r["exe"] is None, repr(r))

stub({"available": False, "reason": "not installed"})
calls["n"] = 0
r = row()
rep = pml._fill_exe_from_helper([r])
check("no helper: nothing asked, reason carried",
      calls["n"] == 0 and rep["reason"] == "not installed", repr(rep))

stub({"available": True, "verbs": ["sudoers"]})
rep = pml._fill_exe_from_helper([row()])
check("an older helper without the verb says to reinstall",
      "install_read_helper" in (rep["reason"] or ""), repr(rep))

stub(avail, {"processes": {}})
calls["n"] = 0
pml._fill_exe_from_helper([{"pid": 1, "exe": "/bin/x", "unreadable": {}}])
check("no refused row: the helper is not called", calls["n"] == 0)

pml.ELEVATED = True
calls["n"] = 0
pml._fill_exe_from_helper([row()])
check("an elevated sensor does not call it", calls["n"] == 0)
pml.ELEVATED = False


print("\n[4] THE PASS REPORTS IT, and the caller's allowlist accepts the verb")
stub({"available": False, "reason": "not installed"})
res = pml.monitor_once()
check("monitor_once carries exe_from_helper",
      res.get("exe_from_helper", {}).get("reason") == "not installed",
      repr(res.get("exe_from_helper")))

li.helper_call = orig_call
real_run = li.subprocess.run


class _Done:
    returncode = 0
    stdout = json.dumps({"ok": True, "processes": {}})
    stderr = ""


li.subprocess.run = lambda *a, **k: _Done()
res = li.helper_call("proc_exe", timeout=5)
li.subprocess.run = real_run
check("helper_call accepts proc_exe", res.get("ok") is True, repr(res))

li.helper_status, li.helper_call, pml.ELEVATED = orig_status, orig_call, orig_elev

print()
if fails:
    print(f"{len(fails)} FAILED: {fails}")
    sys.exit(1)
print("all passed")
