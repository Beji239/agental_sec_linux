"""
tests/test_pkg_hash_parallel.py, the first Processes pass finishes (PM-C1).

Packaged executables are hashed once each, on several threads, inside the
same deadline. Driven with a stub hash so the timing is the test's own.
"""
import pathlib
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


from tools import process_monitor as pm      # noqa: E402

calls, lock = [], threading.Lock()


def slow_md5(path):
    with lock:
        calls.append(path)
    time.sleep(0.2)
    return "d" * 32, None


pm._md5_of = slow_md5
paths = [f"/opt/x/bin{i % 10}" for i in range(40)]      # 10 files, 40 processes
owners = {p: "pkg" for p in paths}
fresh = [(p, (p, 1, 1)) for p in paths]

print("[1] each file is hashed once")
t = time.time()
got = pm._hash_in_parallel(fresh, owners)
took = time.time() - t
check("ten hashes for forty processes", len(calls), 10)
check("every file has an answer", len(got), 10)
check("in parallel, well under ten times 0.2 s", took < 1.0, True)

print("[2] the deadline still holds")
calls.clear()
pm._PKG_CHECK_DEADLINE, saved = 0.3, pm._PKG_CHECK_DEADLINE
many = [(f"/opt/y/bin{i}", (f"/opt/y/bin{i}", 1, 1)) for i in range(200)]
t = time.time()
got = pm._hash_in_parallel(many, {p: "pkg" for p, _k in many})
check("returns at the deadline", time.time() - t < 1.0, True)
check("and leaves the rest out, for 'not checked yet'", len(got) < 200, True)
pm._PKG_CHECK_DEADLINE = saved

print("[3] unowned files are not hashed")
calls.clear()
check("nothing to do", pm._hash_in_parallel([("/tmp/a", ("/tmp/a", 1, 1))], {}), {})
check("no hash taken", calls, [])

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
