"""
tests/test_restore_containment.py, the undo has to be as careful as the act.

WHY THIS EXISTS. quarantine_file resolves its source and refuses anything
under QUARANTINE_DENY_ROOTS. restore_file checked its folder argument and the
manifest's `destination`, which is the staged copy, i.e. where the file
comes FROM, and never looked at `original_path`, which is where the file
goes TO. That path comes out of a MANIFEST.json sitting in a user-writable
folder on the Desktop.

The sharp part was never the missing check on its own, it was the
`target.parent.mkdir(parents=True)` two lines later. Writing into an existing
system folder needs that folder to exist; creating parents meant an approved
restore could build a directory chain that nobody had ever written to and drop
a file into it. On Windows that ran as Administrator and could reach under
C:\\Windows; here the deny-root loop catches /etc and /usr first, so the
reachable case is a fabricated path under the operator's own home -- which is
exactly where the quarantined file's REAL parent would have been, so it is the
same defect with a smaller blast radius.

It always needed a tampered manifest AND a human approving the restore, so it
was not a standalone exploit. It was still the exact asymmetry the
quarantine_file docstring calls backwards, pointing the other way.

This file is the fence. Every check below is a refusal, because the only
thing worth asserting about a guard is what it says no to.

CONVERTED TO THE LINUX MODULE, 2026-09-21. It used to import
`tools.remediation` -- the Windows class, which moved OUT of this tree with
the L5 pass -- and construct it with `__new__` to skip its constructor. On
this platform the guards live in module-level functions in
`tools/remediation_linux.py`, which is the module `main.py` actually loads for
the remediation role, and `restore_file` takes the quarantined FILE's path
rather than a dated folder name. The ASSERTIONS ARE UNCHANGED IN MEANING: each
one is still a refusal with a reason, and the four that matter are the four
the Windows tree carries.

THE TWO REASONS THIS FILE EARNED ITS KEEP, both found here rather than by
reading: the version of this module that shipped was missing the
never-overwrite-into-the-staging-area refusal AND the do-not-build-a-path
refusal, so a tampered manifest could create three directories in a home
folder and leave a quarantined file in them. Both are fixed and both are
asserted below.
"""
import json
import pathlib
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


import sqlite3                                  # noqa: E402

tmp = pathlib.Path(tempfile.mkdtemp())

# A real database, because a successful restore writes a finding and an
# audit row. Stubbing those out would test a version of restore_file that
# does not exist.
db = tmp / "t.db"
from core import memory_engine as me            # noqa: E402
me.DB_PATH = db
_c = sqlite3.connect(db)
_c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
_c.commit(); _c.close()
from core import migrations                     # noqa: E402
migrations.run_migrations(db)
from core import sensors as sn                  # noqa: E402
sn.register_local()

import tools.remediation_linux as rem           # noqa: E402

# Point the staging root at a temp dir so the test never touches the real
# quarantine folder on somebody's Desktop.
rem.STAGING_ROOT = tmp / "quarantine"
rem.STAGING_ROOT.mkdir(parents=True)


def staged(folder, original_path):
    """Build a quarantine folder whose manifest claims `original_path`."""
    d = rem.STAGING_ROOT / folder
    d.mkdir(parents=True, exist_ok=True)
    payload = d / "thing.exe"
    payload.write_bytes(b"quarantined content")
    (d / "manifest.json").write_text(json.dumps({
        "original_path": str(original_path),
        "quarantine_path": str(payload),
        "reason": "test",
    }), encoding="utf-8")
    return payload


print("\n[1] a normal restore still works")
home_dir = tmp / "userdir"
home_dir.mkdir(parents=True)
home_file = home_dir / "wanted.exe"
payload = staged("2026-09-03", home_file)
out = rem.restore_file(str(payload))
check("restored", out.get("success"), True)
check("and it actually landed", home_file.exists(), True)


print("\n[2] THE FIX: a manifest pointing into a system root is refused")
# The whole attack in one line. quarantine_file would never have taken a file
# from /etc or /usr, so a manifest claiming one came from there has been
# edited. The deny list holds both this platform's roots and the project's own
# tree; the check below picks one that is really absolute HERE, because a
# Windows path on Linux is RELATIVE and would resolve under the working
# directory, which would make this test check something else entirely.
DENY_ROOT = next(p for p in rem.QUARANTINE_DENY_ROOTS if p.is_absolute())
deny = DENY_ROOT / "subdir" / "never_existed.dll"
payload = staged("2026-09-03-a", deny)
out = rem.restore_file(str(payload))
check("refused", out.get("success"), False)
check("and says why", "manifest has been edited" in (out.get("error") or ""), True)
check("the file stays in quarantine",
      (rem.STAGING_ROOT / "2026-09-03-a" / "thing.exe").exists(), True)
check("and nothing was created on the way",
      deny.parent.exists(), False)
check("the root it refused is a real absolute one",
      DENY_ROOT.is_absolute(), True)


print("\n[3] and it will not write into AgentalSec's own tree either")
payload = staged("2026-09-03-b", rem.PROJECT_ROOT_GUARD / "core" / "planted.py")
out = rem.restore_file(str(payload))
check("refused", out.get("success"), False)
check("names the project's own tree", "inside" in (out.get("error") or ""), True)


print("\n[4] nor back into quarantine, which would be a loop")
# THE REFUSAL THIS MODULE WAS MISSING until 2026-09-21, and the one the
# measurement in this file found: it used to move the file into its own
# staging area and return success.
payload = staged("2026-09-03-c", rem.STAGING_ROOT / "somewhere" / "loop.exe")
out = rem.restore_file(str(payload))
check("refused", out.get("success"), False)
check("names the loop", "loop" in (out.get("error") or "").lower(), True)


print("\n[5] the mkdir was the sharp end, so a missing parent is refused too")
# A file that was really quarantined came out of a folder that existed. A
# missing parent means the manifest is describing somewhere else, and
# building the path to make it fit is how a write reaches a new location.
# THE SECOND REFUSAL THIS MODULE WAS MISSING: it used to create the chain and
# return success, which is what the measurement at the top of this file shows.
ghost = tmp / "no" / "such" / "place" / "thing.exe"
payload = staged("2026-09-03-d", ghost)
out = rem.restore_file(str(payload))
check("refused", out.get("success"), False)
check("says it will not build the path",
      "Refusing to create directories" in (out.get("error") or ""), True)
check("and did not build it", ghost.parent.exists(), False)


print("\n[6] the old refusals still hold")
payload = staged("2026-09-03-e", tmp / "userdir" / "already_here.exe")
(tmp / "userdir" / "already_here.exe").write_bytes(b"do not clobber me")
out = rem.restore_file(str(payload))
check("never overwrites", out.get("success"), False)
check("and the existing file is untouched",
      (tmp / "userdir" / "already_here.exe").read_bytes(), b"do not clobber me")

# THE PATH ARGUMENT IS UNTRUSTED TOO. The staging area is user-writable, so
# the path handed in can point anywhere; it is resolved and checked before
# anything moves, exactly as the folder name was on the Windows side.
#
# REWRITTEN 2026-09-24 (REM-4). The sentence asserted here used to read "not
# inside the quarantine area", and the 2026-09-24 remediation round changed it
# for a measured reason: the vault is a LIST of roots now (the XDG state
# directory this app writes to, plus the Desktop path earlier versions used),
# because the single path was measured resolving differently per account and
# naming a GUI folder that does not exist for root. The CHECK is the same
# check — a path outside every vault is refused, and the refusal NAMES the
# areas — so the assertion reads for the fact rather than for one wording.
out = rem.restore_file("../../etc/passwd")
check("a path outside the staging area is refused", out.get("success"), False)
check("and the reason says which area it must be inside",
      "not inside a quarantine area" in (out.get("error") or ""), True)
check("and it names the areas it checked",
      all(str(r) in (out.get("error") or "") for r in rem.staging_roots()), True)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
