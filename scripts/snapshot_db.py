#!/usr/bin/env python3
# scripts/snapshot_db.py <source.db> <copy.db>
# A consistent copy of a database the running app is writing to. A plain cp
# of a WAL database can catch it half written and boot a malformed copy.
import sqlite3
import sys

if len(sys.argv) != 3:
    sys.exit("usage: snapshot_db.py <source.db> <copy.db>")
src = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True, timeout=60)
dst = sqlite3.connect(sys.argv[2])
src.backup(dst)
dst.close()
src.close()
