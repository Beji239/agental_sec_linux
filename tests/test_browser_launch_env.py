# tests/test_browser_launch_env.py
# A privileged start drops to the user to open Firefox. sudo strips the
# session bus and runtime directory, and without them a second Firefox cannot
# hand its URL to the open one and shows "Firefox is already running".

import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

import main                                           # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


uid = os.getuid()
runtime = f"/run/user/{uid}"
if not os.path.exists(os.path.join(runtime, "bus")):
    print("SKIP: no session bus for this user")
    sys.exit(0)

print("the environment handed to the dropped Firefox")
env = main._user_session_env(uid)
check("runtime directory", env.get("XDG_RUNTIME_DIR"), runtime)
check("session bus", env.get("DBUS_SESSION_BUS_ADDRESS"), f"unix:path={runtime}/bus")

import pwd                                            # noqa: E402
pw = pwd.getpwuid(uid)
main._real_user_account = lambda: (pw.pw_name, pw.pw_dir, pw.pw_name, uid)
plans = main._browser_launch_plans("http://127.0.0.1:5000")
if not plans:
    print("SKIP: no Firefox installed")
    sys.exit(0 if not fails else 1)
check("every plan carries the session bus",
      all(p[1].get("DBUS_SESSION_BUS_ADDRESS") for p in plans), True)

if os.environ.get("DISPLAY") and shutil.which("firefox") and \
        os.environ.get("AGENTALSEC_BROWSER_LIVE") == "1":
    print("a second Firefox hands its URL to the open one (live)")
    prof = tempfile.mkdtemp()
    stripped = {"HOME": pw.pw_dir, "USER": pw.pw_name, "LOGNAME": pw.pw_name,
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "DISPLAY": main._x_display() or ":0"}
    xauth = os.path.join(pw.pw_dir, ".Xauthority")
    if os.path.exists(xauth):
        stripped["XAUTHORITY"] = xauth
    first = subprocess.Popen(["firefox", "-profile", prof, "about:blank"],
                             env=dict(os.environ), start_new_session=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(8)
    second = subprocess.Popen(["firefox", "-profile", prof, "about:logo"],
                              env=dict(stripped, **main._user_session_env(uid)),
                              start_new_session=True,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        rc = second.wait(timeout=6)
    except subprocess.TimeoutExpired:
        rc = "still running"
        os.killpg(second.pid, signal.SIGTERM)
    check("the second Firefox exits at once", rc, 0)
    os.killpg(first.pid, signal.SIGTERM)
    time.sleep(2)
    shutil.rmtree(prof, ignore_errors=True)

print()
if fails:
    print(f"{len(fails)} FAILED: {fails}")
    sys.exit(1)
print("all passed")
