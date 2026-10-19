"""
tests/test_hardening.py, the installed system is as locked down as it was.

Reads this machine, writes nothing. Each part is skipped with its reason when
what it checks is not installed here, so a fresh clone passes with skips.
The helpers' own verb tables are tested in test_read_helper and
test_containment_verbs.

Run it directly: python tests/test_hardening.py
"""
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _skip                                            # noqa: E402
from core import own_install                            # noqa: E402
from tools import read_helper                           # noqa: E402

fails = []

# The exposure each service scores today, from systemd-analyze security.
# Lower is safer; a rise fails until someone decides it is fine.
EXPOSURE_CEILING = {
    "agentalsec-blocks.service": 1.8,
    "agentalsec-names.service": 3.4,
    "agentalsec-capture.service": 4.0,
    "agentalsec-ebpf-camera.service": 4.0,
}


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


print("[1] each installed service scores no worse than today")
if not shutil.which("systemd-analyze"):
    _skip.skip_part("systemd-analyze is not installed")
else:
    found = 0
    for unit, ceiling in EXPOSURE_CEILING.items():
        if not os.path.exists(f"/etc/systemd/system/{unit}"):
            continue
        found += 1
        out = subprocess.run(["systemd-analyze", "security", unit,
                              "--no-pager"], capture_output=True, text=True,
                             timeout=60).stdout
        m = re.search(r"Overall exposure level for \S+: ([\d.]+)", out)
        score = float(m.group(1)) if m else None
        check(f"{unit} exposure {score} at most {ceiling}",
              score is not None and score <= ceiling, True)
    if not found:
        _skip.skip_part("no AgentalSec service is installed here")

print("\n[2] the app's private files are its owner's alone")
private = [(ROOT / ".env", 0o600), (ROOT / "logs", 0o700)]
private += [(p, 0o600) for p in sorted(ROOT.glob("agental_sec.db*"))
            if not p.name.endswith((".empty_backup",))]
conf = pathlib.Path.home() / ".config" / "agental_sec"
if conf.is_dir():
    private.append((conf, 0o700))
    private += [(p, 0o600) for p in sorted(conf.iterdir())
                if not p.name.endswith(".pub")]
import tempfile                                          # noqa: E402
from core import migrations                              # noqa: E402
with tempfile.TemporaryDirectory() as tmp:
    fresh = pathlib.Path(tmp) / "fresh.db"
    migrations.create_fresh_database(fresh)
    check("a database built on first start is its owner's alone",
          oct(stat.S_IMODE(fresh.stat().st_mode)), oct(0o600))
present = [(p, m) for p, m in private if p.exists()]
if not present:
    _skip.skip_part("no database, .env or logs here yet")
for path, most in present:
    mode = stat.S_IMODE(path.stat().st_mode)
    check(f"{path.name} is {oct(mode)}, nothing beyond {oct(most)}",
          mode & ~most == 0 and path.stat().st_uid == os.getuid(), True)

print("\n[3] every root-installed file is root's and closed to others")
installed = [p for p in own_install.expected(ROOT) if os.path.lexists(p)]
if not installed:
    _skip.skip_part("no root helper is installed here")
for path in installed:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        continue
    check(f"{path} root-owned, not group or world writable",
          st.st_uid == 0 and not (stat.S_IMODE(st.st_mode) & 0o022), True)
# Every folder above an installed file too, or the file can be swapped.
folders = sorted({str(pathlib.Path(p).parent) for p in installed})
for folder in folders:
    for parent in [pathlib.Path(folder), *pathlib.Path(folder).parents]:
        st = os.lstat(parent)
        if not (st.st_uid == 0 and not (stat.S_IMODE(st.st_mode) & 0o022)):
            check(f"{parent} root-owned, not group or world writable",
                  False, True)
            break

print("\n[4] the only password-free root command is the read helper's verbs")
try:
    listing = subprocess.run(["sudo", "-n", "-l"], capture_output=True,
                             text=True, timeout=30)
except (OSError, subprocess.SubprocessError) as e:
    listing = None
    _skip.skip_part(f"sudo could not list the rules: {e}")
if listing is not None and listing.returncode != 0:
    _skip.skip_part("sudo will not list the rules without a password here")
elif listing is not None:
    helper = "/usr/local/lib/agentalsec/read_helper.py"
    allowed = {f"{helper} {v}" for v in read_helper.VERBS} | {
        f"{helper} --verbs"}
    ours = []
    for line in listing.stdout.splitlines():
        if "NOPASSWD:" in line and "agentalsec" in line:
            ours += [c.strip() for c in
                     line.split("NOPASSWD:", 1)[1].split(",")]
    if not ours:
        _skip.skip_part("the read helper is not installed here")
    else:
        check("every password-free agentalsec command is a fixed helper verb",
              sorted(c for c in ours if c not in allowed), [])
        check("and none takes a wildcard",
              [c for c in ours if "*" in c], [])

print("\n[5] the dashboard listens on this computer only")
try:
    cfg = json.loads((ROOT / "config.json").read_text())
except (OSError, ValueError):
    cfg = None
    _skip.skip_part("no config.json here")
if cfg is not None:
    flask = cfg.get("flask") or {}
    host, port = flask.get("host", "127.0.0.1"), flask.get("port", 5000)
    check(f"configured to bind {host}",
          host in ("127.0.0.1", "localhost", "::1"), True)
    ss = shutil.which("ss")
    if ss:
        out = subprocess.run([ss, "-ltnH"], capture_output=True, text=True,
                             timeout=30).stdout
        bound = [ln.split()[3] for ln in out.splitlines()
                 if ln.split() and ln.split()[3].rsplit(":", 1)[-1]
                 == str(port)]
        if not bound:
            print(f"  (nothing listens on {port} now; the app is not running)")
        check("and nothing listens on that port beyond loopback",
              [b for b in bound
               if not b.startswith(("127.", "[::1]", "localhost"))], [])

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
