"""
tests/test_memory_savers.py, the main app stays light.

scapy is only imported when a capture file is analysed or a capture starts,
dpkg's file lists are read for the paths asked about instead of kept whole,
and malloc tuning does nothing where it cannot.
"""
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


print("\n[1] No scapy at load")
probe = (
    "import sys; sys.path.insert(0, %r)\n"
    "import tools.pcap_analyzer, core.capabilities, tools.process_monitor\n"
    "import core.evidence, core.sensor_health, tools.local_integrity\n"
    "print('scapy' in sys.modules)\n" % str(ROOT))
r = subprocess.run([sys.executable, "-c", probe], capture_output=True,
                   text=True, cwd=str(ROOT), timeout=120)
check("main app modules leave scapy unloaded", r.stdout.strip(), "False")

from core import capabilities as caps                 # noqa: E402
calls = []
real = caps._scapy_sniff
caps._scapy_sniff = lambda **kw: calls.append(kw)
try:
    caps.get().capture_open(lambda f: None, timeout=1)
except Exception as e:                                  # noqa: BLE001
    calls.append(f"raised {e}")
caps._scapy_sniff = real
check("a fake sniff is still used", len(calls) == 1 and "prn" in calls[0],
      True)

print("\n[2] dpkg owners for the asked paths")
from tools import local_integrity as li               # noqa: E402
tmp = pathlib.Path(tempfile.mkdtemp(prefix="dpkgown."))
info = tmp / "info"
info.mkdir()
(info / "alpha-tools.list").write_text("/.\n/etc\n/etc/alpha\n/etc/alpha/a.conf\n")
(info / "beta-tools:amd64.list").write_text("/.\n/etc\n/usr/lib/beta.so\n")
real_path = li.Path
li.Path = lambda p: info if p == "/var/lib/dpkg/info" else real_path(p)
try:
    got = li.dpkg_owners_for_paths(
        ["/etc/alpha/a.conf", "/usr/lib/beta.so", "/etc/alpha/new.conf",
         "/etc/hosts", "/opt/none"])
finally:
    li.Path = real_path
check("a listed file", got["/etc/alpha/a.conf"], "alpha-tools")
check("a multiarch name is kept", got["/usr/lib/beta.so"], "beta-tools:amd64")
check("an unlisted file takes its folder's owner",
      got["/etc/alpha/new.conf"], "alpha-tools")
check("a shared folder goes to the first in name order", got["/etc/hosts"],
      "alpha-tools")
check("no owner at all", got["/opt/none"], "")
check("nothing asked reads nothing", li.dpkg_owners_for_paths([]), {})
check("the whole table is gone", hasattr(li, "_dpkg_owning_map"), False)

print("\n[3] malloc tuning")
from core import malloc_tune                          # noqa: E402
os.environ["MALLOC_ARENA_MAX"] = "4"
check("the environment wins", malloc_tune.limit_arenas(), False)
del os.environ["MALLOC_ARENA_MAX"]
real_libc = malloc_tune._libc
malloc_tune._libc = False
check("off glibc the cap does nothing", malloc_tune.limit_arenas(), False)
check("off glibc the trim does nothing", malloc_tune.trim(), False)
malloc_tune._libc = real_libc

print("\nALL PASS" if not fails else f"\n{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
