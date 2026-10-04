"""
tests/_isolate_db.py, a test must not be able to touch the real database.

TODO 108, 2026-09-14. Not a test. The leading underscore keeps it out of the
runner's glob, which is test_*.py.

WHY IT EXISTS, and the short version is that five test files were reading and
two were WRITING to the project's live database without saying so anywhere.

memory_engine.DB_PATH is the file beside main.py. On a working install that is
the evidence store, 1.6 GB of it on the machine this was found on. A test that
exercises any code path going through DB_PATH, and does not repoint it, hits
that file. Nothing in those tests mentions a database because none of them
think they are using one:

  test_pcap_detection    PcapAnalyzer.analyze registers an offline sensor, so
                         nine analyse calls wrote nine rows to `sensors`, each
                         with a fresh random id, so runs accumulated.
  test_process_inspection  inspect_process queues an unknown binary for hash
                         enrichment, so it queued the test runner's own python.

Both tests were RIGHT about everything they check, which is exactly why this
went unseen for as long as it did. They passed. They still pass. The side
effect was never the thing anyone was reading.

scripts/run_tests.py now points AGENTALSEC_TEST_DB at a throwaway file for
every child it starts, which covers the suite. This module covers the other
way tests get run, which is by hand, one file at a time, while working on it.
That is when a test is run most often and it is the case the runner cannot
help with.

USE:
    import _isolate_db          # after sys.path has the tests dir on it
    _isolate_db.isolate()       # before anything writes

It is safe to call twice and it never touches the real file, including to
check whether it exists.
"""
import pathlib
import sqlite3
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

_done = None


def isolate() -> pathlib.Path:
    """Repoint memory_engine.DB_PATH at a fresh database built from Schema.SQL.

    Returns the path, so a test that wants to look at what it wrote can.
    """
    global _done
    if _done is not None:
        return _done

    sys.path.insert(0, str(ROOT))
    from core import memory_engine as me

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="agentalsec_isolated_"))
    db = tmp / "isolated.db"

    schema = ROOT / "Schema.SQL"
    conn = sqlite3.connect(db)
    try:
        # From the REAL schema, so a read finds empty tables rather than "no
        # such table". Those two failures look nothing alike to a reader and
        # the second one sends you hunting in the wrong file.
        conn.executescript(schema.read_text(encoding="utf-8"))
        conn.commit()
    finally:
        conn.close()

    me.DB_PATH = db
    _done = db
    return db
