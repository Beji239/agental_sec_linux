# tests/test_notify_as_user.py
# Running as root under sudo, a desktop notice is sent as the desktop user on
# that user's bus. Not root, or no user to name, and nothing changes.

import os
import pathlib
import pwd
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import actions                              # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


calls = []


class _Done:
    returncode = 0
    stdout = stderr = ""


def fake_run(cmd, **kw):
    calls.append(kw)
    return _Done()


actions._notifications_enabled = lambda: True
actions.shutil.which = lambda name: "/usr/bin/notify-send"
actions.subprocess.run = fake_run

ME = os.getuid()
MY = pwd.getpwuid(ME)


def send(euid, env):
    calls.clear()
    for k in ("SUDO_UID", "PKEXEC_UID", "DBUS_SESSION_BUS_ADDRESS"):
        os.environ.pop(k, None)
    os.environ.update(env)
    actions.os.geteuid = lambda: euid
    out = actions.notify("t", "b")
    return out, calls[0]


print("[1] root under sudo sends as the desktop user")
out, kw = send(0, {"SUDO_UID": str(ME)})
check("it was sent", out, {"sent": True})
check("as that user and group, with root's groups dropped",
      (kw.get("user"), kw.get("group"), kw.get("extra_groups")), (ME, MY.pw_gid, []))
check("on that user's bus", kw["env"]["DBUS_SESSION_BUS_ADDRESS"],
      f"unix:path=/run/user/{ME}/bus")
check("with that user's runtime dir and home",
      (kw["env"]["XDG_RUNTIME_DIR"], kw["env"]["HOME"]), (f"/run/user/{ME}", MY.pw_dir))
check("a stale bus address from root's environment is replaced",
      send(0, {"SUDO_UID": str(ME), "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/0/bus"})
      [1]["env"]["DBUS_SESSION_BUS_ADDRESS"], f"unix:path=/run/user/{ME}/bus")
check("pkexec names the user too", send(0, {"PKEXEC_UID": str(ME)})[1].get("user"), ME)

print("[2] nobody to send as, nothing changes")
check("not root", "user" in send(ME, {"SUDO_UID": str(ME)})[1], False)
check("root with no sudo user", "user" in send(0, {})[1], False)
check("sudo from root itself", "user" in send(0, {"SUDO_UID": "0"})[1], False)
check("a SUDO_UID that is not a number", "user" in send(0, {"SUDO_UID": "x"})[1], False)

print()
print("ALL CHECKS PASSED" if not fails else f"FAILED: {fails}")
sys.exit(1 if fails else 0)
