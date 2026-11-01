"""Inventory migrated and module tables, with valid fixtures for each store."""
import pathlib
import sqlite3
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import _isolate_db
from _prompt_fixtures import prepare, seed
from modules.remote.store import Store

db = _isolate_db.isolate()
prepare(db)
remote = db.parent / 'remote-fixture.db'
store = Store(remote)
store._db.close()
failures = []
for label, path in [('main', db), ('remote', remote)]:
    report = seed(path)
    with sqlite3.connect(path) as conn:
        actual = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        present = set(report['seeded']) | set(report['excluded']) | set(report['failed'])
        ok = actual == present and not report['failed']
        for table in report['seeded']:
            ok = ok and conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0] > 0
    print(label, 'seeded', len(report['seeded']), 'excluded', report['excluded'],
          'failed', report['failed'])
    if label == 'main':
        required = {'operator_question', 'action_request', 'review_hold', 'rule_trial',
                    'learned_rule', 'sensor_service', 'case_index', 'case_fts'}
    else:
        required = {'people', 'events', 'settings', 'sent', 'strangers'}
    ok = ok and required <= set(report['seeded'])
    print(f"{'PASS' if ok else 'FAIL'} {label}, every application table has a populated fixture")
    if not ok:
        failures.append(label)
sys.exit(bool(failures))
