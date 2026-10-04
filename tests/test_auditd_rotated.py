"""
tests/test_auditd_rotated.py, AD11: the rest of a rotated audit log is read.

auditd renames audit.log to audit.log.1 and starts a new file. The renamed
file keeps its inode, so the reader finds it and finishes it first.

Run it directly: python3 tests/test_auditd_rotated.py
"""
import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import auditd_monitor as am                  # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def line(msg_id):
    return (f'type=SYSCALL msg=audit({time.time():.3f}:{msg_id}): arch=c000003e '
            f'syscall=257 ppid=1 pid=4242 auid=1000 uid=0 comm="vim" '
            f'exe="/usr/bin/vim" key="identity"')


def ids(read):
    return [r.get("serial") or r.get("msg_id") or r.get("id") for r in read["records"]]


d = pathlib.Path(tempfile.mkdtemp())
log = d / "audit.log"
log.write_text("\n".join(line(i) for i in (1, 2, 3)) + "\n")

print("\n[1] the first pass reads the live file")
first = am.read_new(str(log))
check("three records", len(first["records"]), 3)
offset, inode = first["offset"], first["inode"]

print("\n[2] more is written, then auditd rotates")
with open(log, "a") as f:
    f.write("\n".join(line(i) for i in (4, 5)) + "\n")
os.rename(log, d / "audit.log.1")
log.write_text("\n".join(line(i) for i in (6, 7, 8, 9, 10, 11)) + "\n")
check("the new file has outgrown the old offset", log.stat().st_size > offset, True)

second = am.read_new(str(log), after_offset=offset, after_inode=inode)
check("the tail of audit.log.1 is read", len(second["records"]), 2)
check("from the rotated file", second.get("reading_rotated"), str(d / "audit.log.1"))
check("the cursor stays on the old file", second["inode"], inode)
check("and says more is waiting", second["more_available"], True)

third = am.read_new(str(log), after_offset=second["offset"], after_inode=second["inode"])
check("then the whole new file", len(third["records"]), 6)
check("and it says nothing was skipped", "nothing was skipped" in (third["reason"] or ""), True)

fourth = am.read_new(str(log), after_offset=third["offset"], after_inode=third["inode"])
check("then nothing new", (len(fourth["records"]), fourth["rotated"]), (0, False))

print("\n[3] a compressed or missing old file is still named as not read")
d2 = pathlib.Path(tempfile.mkdtemp())
log2 = d2 / "audit.log"
log2.write_text("\n".join(line(i) for i in (1, 2)) + "\n")
r = am.read_new(str(log2))
os.rename(log2, d2 / "audit.log.1.gz")
log2.write_text("\n".join(line(i) for i in (3, 4, 5, 6, 7, 8)) + "\n")
lost = am.read_new(str(log2), after_offset=r["offset"], after_inode=r["inode"])
check("the new file is read", len(lost["records"]), 6)
check("and the gap is named", "NOT read" in (lost["reason"] or ""), True)

print("\n" + "=" * 62)
if fails:
    print(f"{len(fails)} FAILED: " + ", ".join(fails))
    sys.exit(1)
print("ALL CHECKS PASSED")
