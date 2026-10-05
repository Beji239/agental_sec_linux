"""
tests/test_suid_prune.py, the SUID scan does not walk backup snapshots.

WHERE THIS CAME FROM, 2026-09-06, a real run on the real box. The first SUID
scan raised EIGHT high findings and all eight were inside
/timeshift/snapshots/<date>/localhost/usr/..., every one of them a copy of a
binary already in the baseline at its normal path.

A system snapshot is a photograph of the filesystem, so of course it contains
sudo and pppd and Xorg.wrap. None of it is privilege escalation, and eight
highs about a backup directory is exactly the noise that gets a real high
scrolled past. Same family as 39.5 and 38.5: the finding was true and useless.

Checked here without SSH, because the command is built by its own method and
the find semantics are the part that is easy to get wrong.
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


from tools.linux_monitor import LinuxMonitor      # noqa: E402

cmd = LinuxMonitor._suid_command(LinuxMonitor)


print("\n[1] the command prunes the backup trees")
check("timeshift is pruned", "-path /timeshift -prune" in cmd, True)
check("snapper too", "/.snapshots" in cmd, True)
check("container images too", "/var/lib/docker" in cmd, True)
check("it still looks for setuid files", "-perm -4000" in cmd, True)
check("and still only files", "-type f" in cmd, True)
# The whole point of pruning at the find rather than filtering after: a
# snapshot directory is a second copy of the entire filesystem and it was
# being walked in full on every slow check.
check("the prune happens in the find, not afterwards",
      cmd.index("-prune") < cmd.index("-perm"), True)


print("\n[2] the find semantics actually work")
# -path X -prune -o -print is easy to write and easy to get subtly wrong, so
# this runs the real thing against a small tree rather than trusting the
# shape of the string.
if os.name == "nt":
    print("  SKIP  needs a POSIX find, the command runs on the remote host")
else:
    with tempfile.TemporaryDirectory() as d:
        base = pathlib.Path(d)
        (base / "usr" / "bin").mkdir(parents=True)
        (base / "timeshift" / "snapshots" / "x" / "usr" / "bin").mkdir(parents=True)
        real = base / "usr" / "bin" / "real"
        copy = base / "timeshift" / "snapshots" / "x" / "usr" / "bin" / "copy"
        for f in (real, copy):
            f.write_text("x")
            os.chmod(f, 0o4755)

        local = (f"find . \\( -path ./timeshift -prune \\) -o "
                 f"\\( -perm -4000 -type f -print \\) 2>/dev/null")
        out = subprocess.run(local, shell=True, cwd=str(base),
                             capture_output=True, text=True).stdout.split()

        check("the live binary is found", "./usr/bin/real" in out, True)
        check("the snapshot copy is not",
              any("timeshift" in line for line in out), False)


print("\n[3] nothing a real attacker uses got hidden")
# A SUID binary inside a read-only snapshot does not run as root on the live
# system, and one planted at a real path still shows up. Guard against
# somebody adding a broad prune later that does.
for dangerous in ("/usr", "/bin", "/sbin", "/opt", "/home", "/tmp", "/var/tmp"):
    check(f"{dangerous} is still walked",
          f"-path {dangerous} -prune" in cmd, False)


print("\n[4] the local sweep walks the scratch trees too (LI-12)")
from tools import local_integrity as li
for scratch in ("/tmp", "/var/tmp"):
    check(f"{scratch} is walked by the local sweep", scratch in li.SUID_PRUNE, False)
check("the snapshot prune is still there", "/timeshift" in li.SUID_PRUNE, True)


print("\n[5] the containerd image store is pruned, and pruning it is quiet")
# Docker on the containerd store keeps image layers under /var/lib/containerd.
# Every image build or delete raised a batch of setuid highs about chfn and
# chage inside a layer.
check("the local sweep prunes it", "/var/lib/containerd" in li.SUID_PRUNE, True)
check("the remote find prunes it", "-path /var/lib/containerd -prune" in cmd, True)
_layer = ("/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/"
          "snapshots/23/fs/usr/bin/chfn")
_old = {"suid": {_layer: "aaaa", "/usr/bin/passwd": "bbbb"}, "sgid": {}}
_new = {"suid": {}, "sgid": {}}
_titles = [f["title"] for f in li.diff_sweep(_old, _new)]
check("a baseline path under a pruned tree is not reported removed",
      any("containerd" in t for t in _titles), False)
check("a real setuid removal still is",
      "Setuid bit removed: /usr/bin/passwd" in _titles, True)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
