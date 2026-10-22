"""
tests/test_package_owner_cache.py, package owners asked in batches.

A watched folder used to run one dpkg-query per file inside it, a few
seconds each, so one folder hit held the audit reader for half an hour.
dpkg-query is faked here and every call is counted.
"""
import pathlib
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import package_activity as pa              # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


tmp = pathlib.Path(tempfile.mkdtemp(prefix="pkgown."))
folder = tmp / "conf.d"
folder.mkdir()
for i in range(15):
    (folder / f"part{i}.conf").write_text(f"setting={i}\n")
(folder / "inner").mkdir()
for i in range(5):
    (folder / "inner" / f"deep{i}.conf").write_text(f"deep={i}\n")
status = tmp / "status"
status.write_text("")
info = tmp / "info"
info.mkdir()
pa.DPKG_STATUS = str(status)
pa.DPKG_INFO = str(info)

OWNED = {str(folder / "part3.conf"): "example-tools",
         str(folder / "part4.conf"): "example-tools, other-tools"}
calls = []


class Done:
    def __init__(self, stdout):
        self.stdout = stdout
        self.returncode = 0


def fake_run(cmd, **kw):
    calls.append(cmd)
    if cmd[:2] == ["dpkg-query", "-S"]:
        lines = [f"{OWNED[p]}: {p}" for p in cmd[2:] if p in OWNED]
        lines.append(f"diversion by example-tools from: {cmd[-1]}")
        return Done("\n".join(lines) + "\n")
    return Done("")


subprocess_run = subprocess.run
pa.subprocess.run = fake_run
pa._actions = lambda: [(datetime.now(timezone.utc) - timedelta(days=30),
                        "install", "example-tools")]

print("\n[1] Answers")
check("the one owner", pa.owner(str(folder / "part3.conf")), "example-tools")
check("two owners is no owner", pa.owner(str(folder / "part4.conf")), None)
check("a diversion line is not an owner",
      pa.owner(str(folder / "part9.conf")), None)

print("\n[2] One query per folder level")
calls.clear()
pa.explains(str(folder) + "/", datetime.now(timezone.utc))
owner_queries = [c for c in calls if c[:2] == ["dpkg-query", "-S"]]
check("queries for a folder and its subfolder", len(owner_queries), 1)
calls.clear()
pa.explains(str(folder) + "/", datetime.now(timezone.utc))
check("the same folder again asks nothing", calls, [])

print("\n[3] Kept until dpkg changes")
calls.clear()
status.write_text("changed\n")
pa.os.utime(status, (1, 1))
pa.owner(str(folder / "part3.conf"))
check("a changed database is asked again", len(calls), 1)

print("\n[4] A failed query is not remembered")
pa._owner_cache.update(key=None, owners={}, conffiles={})


def broken_run(cmd, **kw):
    calls.append(cmd)
    raise subprocess.TimeoutExpired(cmd, 30)


pa.subprocess.run = broken_run
calls.clear()
check("no owner when dpkg times out", pa.owner(str(folder / "part3.conf")),
      None)
pa.subprocess.run = fake_run
check("and the next call asks again", pa.owner(str(folder / "part3.conf")),
      "example-tools")

pa.subprocess.run = subprocess_run
print("\nALL PASS" if not fails else f"\n{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
