"""
tests/test_retention.py, section 23, size-based retention.

Retention is the only feature in this project that DELETES, so the suite is
weighted towards the ways it could destroy something rather than the ways it
could fail to run.

In order of importance:
  a session is never left half deleted, whatever else happens
  the current run, the newest run and anything marked are never touched
  the file actually shrinks, or the caller prunes forever until it is empty
  an interrupted delete is finished rather than measured from
  the never-pruned tables stay exactly as they were

Built against the real Schema.SQL and the real migrations, because a test
that invents its own tables proves the test's schema works.
"""
import json
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


from core import retention as rt          # noqa: E402
from core import migrations               # noqa: E402

SCHEMA = (ROOT / "Schema.SQL").read_text(encoding="utf-8")


def make_db(sessions, row_bytes=400):
    """A fresh database holding the given {session_id: (rows, day)}."""
    tmp = pathlib.Path(tempfile.mkdtemp())
    db = tmp / "t.db"
    c = sqlite3.connect(db)
    c.executescript(SCHEMA)
    c.commit()
    c.close()
    migrations.run_migrations(db)

    c = sqlite3.connect(db)
    blob = "x" * row_bytes
    for sid, (n, day) in sessions.items():
        # 2026-09-05: this wrote into raw_summary, which TODO 34 retired from
        # the schema on 2026-09-01, so every run since has died on "table
        # packets has no column named raw_summary". Nothing ran the tests as a
        # set until scripts/run_tests.py, so it was red for four days.
        #
        # payload_snippet is the right substitute, not just the nearest one:
        # the blob is here to give a row real bulk so the size budget can be
        # exercised, and payload_snippet is now the column that carries bulk.
        c.executemany(
            "INSERT INTO packets(session_id, captured_at, src_ip, dst_ip, "
            "protocol, direction, packet_size, payload_snippet) "
            "VALUES(?,?,?,?,?,?,?,?)",
            [(sid, f"2026-08-{day:02d} {i % 24:02d}:00:00", "192.0.2.10",
              "192.0.2.20", "TCP", "outbound", 100, blob) for i in range(n)])
        c.execute(
            "INSERT INTO events(session_id, occurred_at, source, event_type, "
            "description, severity) VALUES(?,?,?,?,?,?)",
            (sid, f"2026-08-{day:02d} 01:00:00", "windows_event_log",
             "process_launch", blob, "info"))
    c.commit()
    c.close()
    return db


def set_limits(db, trigger, floor, keep=None):
    c = sqlite3.connect(db)
    pairs = [(rt.PREF_TRIGGER, str(trigger)), (rt.PREF_FLOOR, str(floor))]
    if keep is not None:
        pairs.append((rt.PREF_KEEP, keep))
    for k, v in pairs:
        c.execute("INSERT INTO user_preferences(key,value) VALUES(?,?) "
                  "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                  (k, v))
    c.commit()
    c.close()


def counts(db, table="packets"):
    c = sqlite3.connect(db)
    out = dict(c.execute(
        f"SELECT session_id, COUNT(*) FROM {table} GROUP BY session_id"))
    c.close()
    return out


print("\n[1] under the trigger, nothing happens at all")
db = make_db({"a": (100, 10), "b": (100, 11)})
set_limits(db, 10 ** 9, 10 ** 8)
r = rt.run(db, dry_run=False)
check("nothing deleted", r["deleted_sessions"], [])
check("says why", "under the" in (r["reason"] or ""), True)


print("\n[2] the trigger and floor must be a usable pair")
# Prune to 1.99 of a 2.0 trigger and it fires on every check forever. The gap
# is a requirement, not a style preference, so an unusable pair is REFUSED
# rather than quietly widened.
db = make_db({"a": (10, 10)})
set_limits(db, 1000, 999)
c = sqlite3.connect(db)
check("floor too close is refused", rt.limits(c)["ok"], False)
c.close()
set_limits(db, 1000, 2000)
c = sqlite3.connect(db)
check("floor above trigger is refused", rt.limits(c)["ok"], False)
c.close()


print("\n[3] THE CENTRAL ONE: no session is ever left half deleted")
# TODO.md 23.2: an interval recomputed from half a run is DISTORTED rather
# than absent, which is the worse of the two failures.
db = make_db({"a": (400, 10), "b": (400, 11), "c": (400, 12), "d": (400, 13)})
size = rt.database_bytes(db)["total"]
set_limits(db, int(size * 0.5), int(size * 0.25))
rt.run(db, dry_run=False)
pk, ev = counts(db, "packets"), counts(db, "events")
check("every surviving session kept ALL its packets",
      all(n == 400 for n in pk.values()), True)
check("every surviving session kept its events",
      all(ev.get(s) == 1 for s in pk), True)
check("something survived", bool(pk), True)


print("\n[4] oldest first, and the newest run is never touched")
db = make_db({"old": (400, 10), "mid": (400, 11), "new": (400, 12)})
size = rt.database_bytes(db)["total"]
set_limits(db, int(size * 0.4), int(size * 0.2))
r = rt.run(db, dry_run=False)
check("oldest went", "old" in r["deleted_sessions"], True)
check("newest stayed", "new" in r["deleted_sessions"], False)


print("\n[5] the current run is protected even when it is the oldest")
db = make_db({"live": (600, 10), "b": (400, 11), "c": (400, 12)})
size = rt.database_bytes(db)["total"]
set_limits(db, int(size * 0.4), int(size * 0.2))
r = rt.run(db, current_session_id="live", dry_run=False)
check("live run not deleted", "live" in r["deleted_sessions"], False)
check("live rows all present", counts(db).get("live"), 600)


print("\n[6] a keep mark is honoured, and the model can only ever protect")
db = make_db({"a": (400, 10), "b": (400, 11), "c": (400, 12), "d": (400, 13)})
size = rt.database_bytes(db)["total"]
set_limits(db, int(size * 0.5), int(size * 0.2), keep=json.dumps(["a"]))
r = rt.run(db, dry_run=False)
check("marked session survived", "a" in r["deleted_sessions"], False)


print("\n[7] an unreadable keep-list stops the prune")
# Treating a broken keep-list as empty deletes exactly what somebody asked to
# protect, and it does it silently. Refusing is the safe direction.
db = make_db({"a": (400, 10), "b": (400, 11)})
size = rt.database_bytes(db)["total"]
set_limits(db, int(size * 0.5), int(size * 0.2), keep="{not json")
r = rt.run(db, dry_run=False)
check("refused", r["ok"], False)
check("deleted nothing", r["deleted_sessions"], [])


print("\n[8] dry run plans but changes nothing")
db = make_db({"a": (400, 10), "b": (400, 11), "c": (400, 12)})
size = rt.database_bytes(db)["total"]
set_limits(db, int(size * 0.4), int(size * 0.2))
before = sum(counts(db).values())
r = rt.run(db, dry_run=True)
check("row count unchanged", sum(counts(db).values()), before)
check("still produced a plan", bool(r["deleted_sessions"]), True)


print("\n[9] the file actually shrinks, which is what stops the prune loop")
# TODO.md 23.3: SQLite does not shrink on DELETE. Without the vacuum the size
# check reads the same number afterwards and the caller prunes until empty.
db = make_db({"a": (2000, 10), "b": (2000, 11), "c": (2000, 12)})
before = rt.database_bytes(db)["total"]
set_limits(db, int(before * 0.5), int(before * 0.3))
rt.run(db, dry_run=False)
after = rt.database_bytes(db)["total"]
check("file is smaller than before", after < before, True)


print("\n[10] an interrupted delete is finished, not measured from")
db = make_db({"a": (400, 10), "b": (400, 11)})
c = sqlite3.connect(db)
c.execute("INSERT INTO user_preferences(key,value) VALUES(?,?)",
          (rt.PREF_PARTIAL, "a"))
c.execute("DELETE FROM packets WHERE session_id='a' AND id % 2 = 0")
c.commit()
COUNT_A = "SELECT COUNT(*) FROM packets WHERE session_id='a'"
half = c.execute(COUNT_A).fetchone()[0]
c.close()
check("setup really left a half session", 0 < half < 400, True)
c = sqlite3.connect(db)
check("resume reports the session", rt.resume_interrupted(c), "a")
check("session is now fully gone", c.execute(COUNT_A).fetchone()[0], 0)
check("marker cleared",
      c.execute("SELECT value FROM user_preferences WHERE key=?",
                (rt.PREF_PARTIAL,)).fetchone(), None)
c.close()


print("\n[11] the never-pruned tables are untouched")
db = make_db({"a": (600, 10), "b": (400, 11), "c": (400, 12)})
c = sqlite3.connect(db)
c.execute("INSERT INTO behavioral_session(session_id, entity_type, "
          "entity_value, behavior_key, behavior_value) "
          "VALUES('a','ip','192.0.2.10','beacon_destinations','x')")
c.execute("INSERT INTO findings(session_id, source, severity, title) "
          "VALUES('a','packet_sniffer','high','keep me')")
c.execute("INSERT INTO integrity_journal(prev_hash, entry_hash, operation, "
          "payload_digest) VALUES('0','1','finding_saved','d')")
c.commit()
c.close()
size = rt.database_bytes(db)["total"]
set_limits(db, int(size * 0.4), int(size * 0.2))
rt.run(db, dry_run=False)
c = sqlite3.connect(db)
check("behavioural row survived",
      c.execute("SELECT COUNT(*) FROM behavioral_session").fetchone()[0], 1)
check("finding survived",
      c.execute("SELECT COUNT(*) FROM findings").fetchone()[0], 1)
check("integrity journal survived",
      c.execute("SELECT COUNT(*) FROM integrity_journal").fetchone()[0], 1)
c.close()


print("\n[12] the size estimate follows the schema, not a hardcoded list")
# A migration that adds a column must not silently make every estimate too
# small, which is why the estimate is built from PRAGMA table_info.
db = make_db({"a": (50, 10)})
c = sqlite3.connect(db)
before = rt.session_inventory(c)[0]["bytes_estimate"]
c.execute("ALTER TABLE packets ADD COLUMN owning_process TEXT")
c.execute("UPDATE packets SET owning_process='chrome.exe'")
c.commit()
after = rt.session_inventory(c)[0]["bytes_estimate"]
c.close()
check("new column counted", after > before, True)


print("\n[13] a session with no timestamps sorts LAST, not first")
# NULL is unknown age. Deleting an unknown-age run ahead of a known-old one
# is a guess wearing an ordering's clothes.
db = make_db({"dated": (10, 10)})
c = sqlite3.connect(db)
c.executemany("INSERT INTO packets(session_id, captured_at, src_ip) "
              "VALUES('undated', NULL, '192.0.2.10')", [()] * 10)
c.commit()
order = [s["session_id"] for s in rt.session_inventory(c)]
c.close()
check("undated is last", order[-1], "undated")


print("\n[14] in WAL mode the size after VACUUM is the rebuilt file alone")
# With another connection open, VACUUM leaves its rebuilt copy in the -wal
# and the size read next counted it twice.
import os                                              # noqa: E402
wal_db = pathlib.Path(tempfile.mkdtemp()) / "wal.db"
other = sqlite3.connect(wal_db)
other.execute("PRAGMA journal_mode=WAL")
other.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, b BLOB)")
other.executemany("INSERT INTO t(b) VALUES(?)", [(os.urandom(4000),)] * 3000)
other.commit()
other.execute("DELETE FROM t WHERE id > 300")
other.commit()
v = rt.vacuum(wal_db, dry_run=False)
after = rt.database_bytes(wal_db)
other.close()
check("the -wal is emptied after the vacuum",
      after["parts"]["wal.db-wal"], 0)
check("so the size freed is a positive number", v["freed"] > 0, True)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
