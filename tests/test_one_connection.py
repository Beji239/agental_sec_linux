# tests/test_one_connection.py
# Inside memory_engine.one_connection() a thread reuses one write and one
# read-only connection. Each block still commits or rolls back on its own,
# a nested block opens its own, reads see what was committed, and outside
# the block nothing changes.

import pathlib
import sqlite3
import sys
import threading

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import memory_engine as me                  # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


with me._get_conn() as conn:
    conn.execute("CREATE TABLE IF NOT EXISTS t1 (v INTEGER)")
    conn.execute("DELETE FROM t1")

opened = []
real_connect = sqlite3.connect


def counting_connect(*a, **k):
    opened.append(a[0] if a else k.get("database"))
    return real_connect(*a, **k)


me.sqlite3.connect = counting_connect

print("outside the block every call opens its own")
for _ in range(3):
    with me._get_conn() as conn:
        conn.execute("SELECT 1")
check("three blocks, three connections", len(opened), 3)

print("inside the block")
opened.clear()
with me.one_connection():
    ids = set()
    for i in range(5):
        with me._get_conn() as conn:
            ids.add(id(conn))
            conn.execute("INSERT INTO t1 VALUES (?)", (i,))
        with me._get_readonly_conn() as ro:
            seen = ro.execute("SELECT COUNT(*) FROM t1").fetchone()[0]
    check("one write and one read connection for ten blocks", len(opened), 2)
    check("the same write connection each time", len(ids), 1)
    check("reads see every committed write", seen, 5)

    try:
        with me._get_conn() as conn:
            conn.execute("INSERT INTO t1 VALUES (99)")
            raise RuntimeError("stop")
    except RuntimeError:
        pass
    with me._get_readonly_conn() as ro:
        check("a failed block rolls back only itself",
              ro.execute("SELECT COUNT(*) FROM t1").fetchone()[0], 5)

    with me._get_conn() as outer:
        with me._get_conn() as inner:
            check("a nested block gets its own connection", inner is outer, False)
            inner.execute("INSERT INTO t1 VALUES (7)")
        outer.execute("INSERT INTO t1 VALUES (8)")

    other = {}

    def from_another_thread():
        with me._get_conn() as conn:
            other["conn"] = conn
    th = threading.Thread(target=from_another_thread)
    th.start()
    th.join()
    check("another thread is not given this thread's connection",
          other.get("conn") is not None and id(other["conn"]) not in ids, True)

with me._get_readonly_conn() as ro:
    check("both nested writes landed", ro.execute("SELECT COUNT(*) FROM t1").fetchone()[0], 7)
check("the shared set is gone after the block", getattr(me._shared, "conns", None), None)

me.sqlite3.connect = real_connect

print()
if fails:
    print(f"FAILED: {len(fails)}")
    for f in fails:
        print(f"  {f}")
    sys.exit(1)
print("ALL PASSED")
