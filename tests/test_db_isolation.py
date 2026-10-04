"""
tests/test_db_isolation.py, no test may touch the real database. TODO 108,
2026-09-14.

WHAT HAPPENED. The suite was green on two machines. It was also writing to the
project's live database on every run.

  test_pcap_detection      nine rows into `sensors`, one per analyse call,
                           each with a fresh random id so runs ACCUMULATE.
  test_process_inspection  one row into `enrichment_queue`, naming whichever
                           python was running the tests.

Three more files read from it: test_process_lookup, test_retention and
test_retention_plumbing. On the machine this was found on, that file is 1.6 GB
of collected evidence.

HOW IT WAS FOUND, which is the uncomfortable part. Not by looking. An empty
database left behind in a sandbox made test_baseline_retract fail on the NEXT
run, with "no such table: behavioral_session", and only then did anyone ask
where that file came from. Nothing was watching for this, and the two writing
tests were correct about every single thing they check. Their write was a side
effect of code they were exercising for other reasons, and side effects are
not what anyone reads a passing test for.

THE SECOND LESSON IS ABOUT test_baseline_retract. It monkeypatches
me._get_conn and thought it was isolated. observation_provenance uses
_get_readonly_conn, which it did not patch, so it was reading the real file
all along and passing BECAUSE the real file had the tables in it. An isolation
that works by patching one of two entry points is an isolation that holds
until someone adds a third.

SO THE FIX IS NOT PER TEST. DB_PATH itself is now overridable by
AGENTALSEC_TEST_DB, scripts/run_tests.py points it at a throwaway for every
child it starts, and tests/_isolate_db.py covers the case the runner cannot,
which is a file run by hand.

This file checks the mechanism, then checks the two known offenders against a
sentinel, which is the only part that would catch a NEW offender of the same
kind. It cannot catch all of them, and the honest reason is that proving it
would mean re-running the whole suite from inside one test.
"""
import os
import pathlib
import sqlite3
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


def _child(code, env_extra=None):
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    env.pop("AGENTALSEC_TEST_DB", None)
    env.update(env_extra or {})
    p = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT),
                       capture_output=True, text=True, timeout=120,
                       encoding="utf-8", errors="replace", env=env)
    return (p.stdout or "").strip(), (p.stderr or "").strip(), p.returncode


PRINT_PATH = ("import sys; sys.path.insert(0, r'%s');"
              "from core import memory_engine as me; print(me.DB_PATH)" % ROOT)


print("\n[1] FAILURE CASE FIRST. With nothing set, DB_PATH is the real one.")
# If this ever stops being true the override has taken over production, which
# is a far worse bug than the one it was added to fix.
out, err, rc = _child(PRINT_PATH)
check("the child ran", rc, 0)
check("and points at the project database",
      pathlib.Path(out).resolve() if out else None,
      (ROOT / "agental_sec.db").resolve())


print("\n[2] the override moves it, and only when it has a value")
tmpdir = pathlib.Path(tempfile.mkdtemp(prefix="agentalsec_isolation_"))
elsewhere = tmpdir / "elsewhere.db"
out, err, rc = _child(PRINT_PATH, {"AGENTALSEC_TEST_DB": str(elsewhere)})
check("a set variable is honoured",
      pathlib.Path(out).resolve() if out else None, elsewhere.resolve())

out, err, rc = _child(PRINT_PATH, {"AGENTALSEC_TEST_DB": "   "})
check("whitespace is not a path, so the real one stands",
      pathlib.Path(out).resolve() if out else None,
      (ROOT / "agental_sec.db").resolve())

out, err, rc = _child(PRINT_PATH, {"AGENTALSEC_TEST_DB": ""})
check("neither is empty",
      pathlib.Path(out).resolve() if out else None,
      (ROOT / "agental_sec.db").resolve())


print("\n[3] the runner sets it for every child it starts")
# Checked as source rather than by running the suite from inside the suite.
runner = (ROOT / "scripts" / "run_tests.py").read_text(encoding="utf-8")
check("run_tests names the variable", "AGENTALSEC_TEST_DB" in runner, True)
check("and sets it in the child environment, not just mentions it",
      'env["AGENTALSEC_TEST_DB"]' in runner, True)
check("and builds the scratch file from the real schema",
      "Schema.SQL" in runner, True)


print("\n[4] the by-hand helper exists and is not collected as a test")
helper = ROOT / "tests" / "_isolate_db.py"
check("_isolate_db.py is there", helper.exists(), True)
check("and the runner's glob cannot pick it up",
      helper.name.startswith("test_"), False)


print("\n[5] THE REGRESSION. The two that were writing do not write now.")
# A sentinel database at the real path, with the real schema, so the children
# find what they expect. If either one touches it, the bytes change.
sentinel = ROOT / "agental_sec.db"
existed = sentinel.exists()
if existed:
    # Never write over a real database to run a test. On a working install
    # this file is the evidence store, and this check is not worth it.
    print("  SKIP  a database already exists at the real path, not touched")
    check("(nothing written to the real database by this test)", True, True)
else:
    conn = sqlite3.connect(sentinel)
    try:
        conn.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
        conn.commit()
    finally:
        conn.close()
    try:
        before = sentinel.read_bytes()
        for name in ("test_pcap_detection.py", "test_process_inspection.py"):
            p = subprocess.run([sys.executable, str(ROOT / "tests" / name)],
                               cwd=str(ROOT), capture_output=True, text=True,
                               timeout=300, encoding="utf-8", errors="replace",
                               env={**os.environ, "PYTHONIOENCODING": "utf-8",
                                    "PYTHONUTF8": "1",
                                    "AGENTALSEC_TEST_DB": ""})
            check(f"{name} left the real database byte for byte alone",
                  sentinel.read_bytes() == before, True)
        # And prove the sentinel would have caught it: the rows they used to
        # write are simply not there.
        conn = sqlite3.connect(sentinel)
        try:
            check("no sensors were invented",
                  conn.execute("SELECT COUNT(*) FROM sensors").fetchone()[0], 0)
            check("nothing was queued for enrichment",
                  conn.execute("SELECT COUNT(*) FROM enrichment_queue"
                               ).fetchone()[0], 0)
        finally:
            conn.close()
    finally:
        sentinel.unlink(missing_ok=True)


print("\n[6] the isolated helper really redirects, it does not just claim to")
code = (
    "import sys, pathlib\n"
    f"sys.path.insert(0, r'{ROOT}')\n"
    f"sys.path.insert(0, r'{ROOT / 'tests'}')\n"
    "import _isolate_db\n"
    "db = _isolate_db.isolate()\n"
    "from core import memory_engine as me\n"
    "print(me.DB_PATH == db, db.exists())\n"
)
out, err, rc = _child(code)
check("DB_PATH follows the helper and the file was built",
      out.splitlines()[-1] if out else err[-200:], "True True")


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
