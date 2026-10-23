"""
tests/test_own_activity.py, the app knows its own test runs.

The tests plant fake tools on purpose, and the live sensors kept raising them.
A process now counts as the app's own only when the kernel's process tree
leads to this project's own test runner. A name or a folder proves nothing.
Only /bin/sleep is started here, so the live sensors have nothing to raise.
"""
import os
import pathlib
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import own_activity as oa                  # noqa: E402

fails = []
procs = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def detached(argv) -> int:
    """Start argv outside this process tree and return its pid."""
    out = tempfile.mktemp(prefix="ownact.pid.")
    subprocess.run(["sh", "-c", f'{" ".join(argv)} >/dev/null 2>&1 & '
                    f'echo $! > {out}'], check=True)
    for _ in range(50):
        try:
            pid = int(pathlib.Path(out).read_text().strip())
            os.unlink(out)
            return pid
        except (OSError, ValueError):
            time.sleep(0.05)
    raise RuntimeError("the detached process did not start")


def alive(pid):
    return os.path.exists(f"/proc/{pid}")


try:
    print("\n[1] A child of this test is the app's own")
    child = subprocess.Popen(["/bin/sleep", "20"])
    procs.append(child.pid)
    got = oa.test_run(child.pid)
    check("named as a test run", bool(got) and "tests/test_own_activity.py" in got,
          True)
    check("the gone process is judged by its parent",
          bool(oa.test_run(999999999, os.getpid())), True)

    print("\n[2] Outside the tree it is not")
    loose = detached(["/bin/sleep", "20"])
    procs.append(loose)
    check("a process that left the tree", oa.test_run(loose), None)
    check("pid 1 vouches for nothing", oa.test_run(1), None)
    check("no pid at all", oa.test_run(None, None), None)

    print("\n[3] A test file elsewhere proves nothing")
    fake = pathlib.Path(tempfile.mkdtemp(prefix="ownact.")) / "tests"
    fake.mkdir()
    pidfile = fake / "child.pid"
    (fake / "test_fake.py").write_text(
        "import subprocess, sys, time\n"
        "p = subprocess.Popen(['/bin/sleep', '20'])\n"
        f"open({str(pidfile)!r}, 'w').write(str(p.pid))\n"
        "time.sleep(20)\n")
    runner = detached([sys.executable, str(fake / "test_fake.py")])
    procs.append(runner)
    for _ in range(60):
        if pidfile.exists() and pidfile.read_text().strip():
            break
        time.sleep(0.05)
    grandchild = int(pidfile.read_text().strip())
    procs.append(grandchild)
    check("its child is not the app's own", oa.test_run(grandchild), None)

    print("\n[4] The sensors hold the app's own back, and say so")
    import adapters                                       # noqa: E402
    from core import memory_engine as me                  # noqa: E402
    saved = []
    real_save, real_cov = me.save_finding, me.dismissal_covers
    me.save_finding = lambda **kw: saved.append(kw)
    me.dismissal_covers = lambda *a, **k: {"covered": False, "compared": False,
                                            "reason": None}
    from tools import process_monitor_linux as pm         # noqa: E402
    real_once = pm.monitor_once
    pm.monitor_once = lambda: {"findings": [
        {"type": "suspicious_process_name", "pid": child.pid,
         "name": "linux-exploit-suggester", "exe": "/x/linux-exploit-suggester"},
        {"type": "suspicious_process_name", "pid": loose,
         "name": "linux-exploit-suggester", "exe": "/x/linux-exploit-suggester"},
    ], "process_count": 2, "finding_count": 2}
    try:
        mon = adapters.LinuxProcessMonitor("test-session", {})
        mon.poll()
        st = mon.status()
    finally:
        me.save_finding, me.dismissal_covers = real_save, real_cov
        pm.monitor_once = real_once
    check("only the one outside the tree is written",
          [s["raw_data"]["pid"] for s in saved], [loose])
    check("the held back one is counted", st.get("held_back_own_test_runs"), 1)

    from tools import ebpf_events as ee                   # noqa: E402
    rows = [(1, child.pid, child.pid, os.getpid(), os.getuid(), "cron", "python3",
             "/tmp/ownact/cron", 0),
            (2, loose, loose, 1, os.getuid(), "cron", "sh", "/tmp/ownact2/cron", 0)]
    out, _ = ee._staging_findings(rows, {"path_allowlist": []})
    check("the camera raises only the one outside the tree",
          [f["raw_data"]["pid"] for f in out], [loose])
finally:
    for pid in procs:
        try:
            if alive(pid):
                os.kill(pid, 9)
        except OSError:
            pass

print("\nALL PASS" if not fails else f"\n{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
