# bf_check.py, quick read-only look at what linux_monitor logged
# run it from the agental_sec folder:  python scripts\bf_check.py
# it only reads the db, never writes.

import os
import sqlite3

here = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(here, "..", "agental_sec.db")

con = sqlite3.connect(db_path)
con.row_factory = sqlite3.Row
cur = con.cursor()


def cols(table):
    # so this keeps working even if column names shift
    return [r[1] for r in cur.execute(f"PRAGMA table_info({table})")]


print("db:", os.path.abspath(db_path))
print()

print("== last 10 linux_monitor findings ==")
fcols = cols("findings")
for r in cur.execute(
    "select * from findings where source='linux_monitor' order by rowid desc limit 10"
):
    d = dict(r)
    ts = d.get("created_at") or d.get("timestamp") or ""
    print(ts, ",", d.get("severity"), ",", d.get("title"))
    if d.get("description"):
        print("      ", str(d.get("description"))[:200])
print()

print("== last 15 linux_monitor events (failed / invalid logins) ==")
for r in cur.execute(
    "select * from events where source='linux_monitor' order by rowid desc limit 15"
):
    d = dict(r)
    ts = d.get("created_at") or d.get("timestamp") or ""
    print(ts, ",", d.get("event_type"), ",", d.get("src_ip"), ",", str(d.get("description"))[:110])

con.close()
