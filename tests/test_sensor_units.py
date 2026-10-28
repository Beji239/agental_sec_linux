"""
tests/test_sensor_units.py, the sensor services start with the app and stop
when it quits.

systemctl is replaced by a recorder, so nothing on this machine is touched.

Run it directly: python tests/test_sensor_units.py
"""
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import sensor_units as su                     # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


calls = []
answer = {"code": 0, "err": ""}


def fake_run(cmd, **kw):
    calls.append(cmd[1:])
    return subprocess.CompletedProcess(cmd, answer["code"], "", answer["err"])


units = pathlib.Path(tempfile.mkdtemp(prefix="sensorunits."))
su.UNIT_DIR = units
su.shutil.which = lambda name: "/bin/systemctl"
su.subprocess.run = fake_run
su.atexit.register = lambda fn: None

print("[1] nothing installed, nothing started")
check("no units, no call", (su.start(), calls), ([], []))

print("\n[2] only the installed units, names helper first")
for u in ("agentalsec-capture.service", "agentalsec-names.service"):
    (units / u).write_text("[Unit]\n")
check("started", su.start(),
      ["agentalsec-names.service", "agentalsec-capture.service"])
check("never waits for a password", calls[-1][:2], ["start", "--no-ask-password"])

print("\n[3] stopped once, in reverse order")
su.stop()
check("stop call", calls[-1], ["stop", "--no-ask-password",
                               "agentalsec-capture.service",
                               "agentalsec-names.service"])
n = len(calls)
su.stop()
check("a second stop does nothing", len(calls), n)

print("\n[4] a refused start leaves nothing to stop")
answer.update(code=1, err="Access denied")
check("refused", su.start(), [])
n = len(calls)
su.stop()
check("no stop for units it never started", len(calls), n)

print("\n[5] a boot link from an older install is noticed")
(units / "multi-user.target.wants").mkdir()
(units / "multi-user.target.wants" / "agentalsec-names.service").symlink_to(
    units / "agentalsec-names.service")
check("boot_enabled", su.boot_enabled(), ["agentalsec-names.service"])

print("\n[6] the installers write the rule and keep the units off the boot list")
for name in ("install_capture_service.sh", "install_ebpf_camera.sh"):
    text = (ROOT / "scripts" / name).read_text()
    check(f"{name} has no systemctl enable", "systemctl enable" in text, False)
    check(f"{name} writes a polkit rule",
          "RULE_CONTENT" in text and "/etc/polkit-1/rules.d/" in text, True)
    check(f"{name} rule allows only start and stop",
          '"start"' in text and '"stop"' in text and '"restart"' not in text,
          True)

print()
if fails:
    print(f"FAILED: {len(fails)}")
    sys.exit(1)
print("ALL PASS")
