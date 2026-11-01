"""Disposable migrated stores and explicit fixture seeding for text-boundary tests."""
import json
import re
import sqlite3

MARKER = 'PROMPTCANARY'


def prepare(path):
    from core import migrations
    migrations.run_migrations(path)


def seed(path):
    result = {'seeded': [], 'excluded': {}, 'failed': {}}
    with sqlite3.connect(path) as conn:
        tables = conn.execute("SELECT name, sql FROM sqlite_master WHERE type='table'").fetchall()
        virtual = {name for name, sql in tables if 'VIRTUAL TABLE' in (sql or '').upper()}
        for table, sql in tables:
            if table.startswith('sqlite_'):
                result['excluded'][table] = 'SQLite internal state'
                continue
            if any(table.startswith(v + '_') for v in virtual):
                result['excluded'][table] = 'SQLite full text shadow storage'
                continue
            cols = conn.execute(f'PRAGMA table_info("{table}")').fetchall()
            names = [row[1] for row in cols]
            values = []
            for _, name, kind, required, default, pk in cols:
                kind = (kind or '').upper()
                if pk and name == 'id' and 'INT' in kind:
                    value = None
                elif name.endswith('_json') or name in ('match_json', 'payload'):
                    value = json.dumps({'marker': MARKER})
                elif name == 'dismissed':
                    value = 0
                elif name in ('id', 'incident_id', 'finding_id') or 'INT' in kind or 'REAL' in kind:
                    value = 1
                elif name.endswith(('_at', '_time', 'timestamp', 'since')):
                    value = '2026-10-01 12:00:00'
                elif name.endswith('ip') or name in ('ip_address', 'entity_value'):
                    value = '203.0.113.5'
                elif name == 'session_id':
                    value = 'fence-test'
                else:
                    value = f'{MARKER} {table} {name}'
                values.append(value)
            for attempt in range(len(cols) + 2):
                try:
                    conn.execute(f'INSERT INTO "{table}" VALUES ({", ".join("?" for _ in values)})', values)
                    result['seeded'].append(table)
                    break
                except sqlite3.IntegrityError as e:
                    enum = re.search(r"(?:\b|\()(\w+)\s+IN\s*\(\s*'([^']*)'", str(e), re.I)
                    if enum and enum[1] in names:
                        index = names.index(enum[1])
                        if values[index] != enum[2]:
                            values[index] = enum[2]
                            continue
                    result['failed'][table] = str(e)
                    break
                except sqlite3.Error as e:
                    result['failed'][table] = str(e)
                    break
            else:
                result['failed'][table] = 'Fixture retries exhausted'
        conn.commit()
    return result
