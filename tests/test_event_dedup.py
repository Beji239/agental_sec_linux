"""
tests/test_event_dedup.py, v21, one source record makes one event row.

The bug this covers is a side effect of a decision that is correct and stays
correct. EventMonitor will not advance its high-water mark when a burst caps a
pass, because a skipped 4720 is gone forever and a re-read one is not. The
cost is that the newest records get read again next poll, and they were being
stored again too, which quietly inflates any count a baseline is built from.

So the checks are:
  the same source record twice makes ONE row
  a genuinely different record still lands
  a different source with the same record number is NOT a duplicate
  rows with no source id at all still insert, as many times as they are sent
  the migration adds the index to a populated table without losing anything
"""
import pathlib
import sqlite3
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


tmp = pathlib.Path(tempfile.mkdtemp())
db = tmp / "t.db"

from core import memory_engine as me       # noqa: E402
me.DB_PATH = db

c = sqlite3.connect(db)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.commit()
c.close()

from core import migrations                # noqa: E402
migrations.run_migrations(db)
from core import sensors as sn             # noqa: E402
sn.register_local()

SID = "test-session"


def save(record_id, event_id="4720", source="windows_event_log"):
    me.save_event(session_id=SID, source=source, event_id=event_id,
                  event_type="account_created", severity="high",
                  source_record_id=record_id)


def rows():
    with sqlite3.connect(db) as c:
        return c.execute("SELECT COUNT(*) FROM events").fetchone()[0]


print("\n[1] the schema carries the column and the index")
with sqlite3.connect(db) as c:
    cols = {r[1] for r in c.execute("PRAGMA table_info(events)")}
    idx = {r[1] for r in c.execute("PRAGMA index_list(events)")}
check("source_record_id exists", "source_record_id" in cols, True)
check("unique index exists", "idx_events_source_record" in idx, True)
check("schema version is at least 21", migrations.SCHEMA_VERSION >= 21, True)


print("\n[2] THE CENTRAL ONE: the same record twice makes one row")
# This is the capped-pass case. The monitor re-reads the newest records on the
# next poll on purpose, and that must not become a second row.
save(5000)
save(5000)
save(5000)
check("three writes, one row", rows(), 1)


print("\n[3] a genuinely new record still lands")
save(5001)
check("two rows now", rows(), 2)


print("\n[4] the same number from a DIFFERENT source is not a duplicate")
# Record numbers are only unique within the log they came from. Two sources
# that both happen to number a record 5000 are two different events.
save(5000, source="linux_auth")
check("three rows now", rows(), 3)


print("\n[5] a caller that passes no record id behaves exactly as before")
# NULLs are distinct in a SQLite unique index, so nothing that predates this
# column, and no source without an id of its own, is affected.
me.save_event(session_id=SID, source="process_monitor",
              event_id="x", event_type="process_launch", severity="info")
me.save_event(session_id=SID, source="process_monitor",
              event_id="x", event_type="process_launch", severity="info")
check("both un-ided rows landed", rows(), 5)


print("\n[6] ON CONFLICT is narrow, it does not swallow other errors")
# INSERT OR IGNORE would have hidden a bad severity as well, and a write that
# silently drops rows for reasons nobody chose is worse than the duplicate it
# was meant to fix.
before = rows()
raised = False
try:
    me.save_event(session_id=SID, source="windows_event_log", event_id="9999",
                  event_type="nonsense", severity="not-a-severity",
                  source_record_id=6000)
except sqlite3.IntegrityError:
    raised = True
check("a bad severity still raises", raised, True)
check("and nothing was written", rows(), before)


print("\n[7] the migration is safe on a table that already has rows")
# The real database has thousands of events with no source_record_id. Every
# one gets NULL, no two NULLs collide, so the index builds without a fight.
db2 = tmp / "old.db"
c = sqlite3.connect(db2)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.execute("DROP INDEX IF EXISTS idx_events_source_record")
# Rebuild the table the way v20 had it, then fill it.
c.execute("ALTER TABLE events DROP COLUMN source_record_id")
c.executemany(
    "INSERT INTO events(session_id, source, event_id, event_type, severity) "
    "VALUES(?,?,?,?,?)",
    [(SID, "windows_event_log", "4625", "failed_login", "medium")] * 500)
c.commit()
before = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
c.execute("PRAGMA user_version = 20")
c.commit()
c.close()

added = None
try:
    c = sqlite3.connect(db2)
    added = migrations._migrate_event_record_id(c)
    c.commit()
    after = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    nulls = c.execute("SELECT COUNT(*) FROM events "
                      "WHERE source_record_id IS NULL").fetchone()[0]
    c.close()
except Exception as e:
    after = nulls = f"raised {e}"
check("column was added", added, 1)
check("no rows lost", after, before)
check("every old row is NULL and none collided", nulls, before)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
