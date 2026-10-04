"""
tests/test_expected_port_clearing.py, declaring a port clears its backlog,
and clears nothing else.

WHY THIS FILE EXISTS. 39 shipped the declaration and left 39.5 open: findings
already raised were not cleared, so the owner answered the question and the
question stayed on screen. That is the unread review queue arriving by a
different road, which is the exact failure 39 was built to stop.

Fixing it means writing to `findings.dismissed`, and a bug in that direction
is invisible: over-clearing does not throw, it just quietly removes an alert
somebody should have seen. So most of what is fenced here is what must SURVIVE
a declaration, not what must go.

Runs against a real schema built by Schema.SQL plus migrations, on a temp
database. Touches nothing of the owner's.
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


tmp = pathlib.Path(tempfile.mkdtemp(prefix="agental_ports_"))
DB = tmp / "test.db"

from core import memory_engine as me            # noqa: E402
me.DB_PATH = str(DB)

conn = sqlite3.connect(DB)
conn.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
conn.commit()
conn.close()

from core import migrations                     # noqa: E402
migrations.run_migrations(DB)


def add_device(ip, name):
    with sqlite3.connect(DB) as c:
        c.execute("INSERT INTO known_devices (ip, known_as) VALUES (?,?)",
                  (ip, name))


def add_port_finding(port, host, title=None, with_host=True):
    """A port finding. with_host=False writes one the OLD way, no host in
    raw_data, which is every finding written before 2026-09-04."""
    raw = {"port": port, "risk_level": "high"}
    if with_host:
        raw["host"] = host
    with sqlite3.connect(DB) as c:
        cur = c.execute(
            """INSERT INTO findings
                 (session_id, source, severity, entity_type, entity_value,
                  title, raw_data)
               VALUES ('s', 'port_scanner', 'high', 'port', ?, ?, ?)""",
            (str(port),
             title or f"Scan found something listening on {host}:{port}",
             json.dumps(raw)))
        return cur.lastrowid


def is_dismissed(fid):
    with sqlite3.connect(DB) as c:
        return c.execute("SELECT dismissed FROM findings WHERE id = ?",
                         (fid,)).fetchone()[0]


add_device("192.0.2.23", "Echo")
add_device("192.0.2.24", "LG TV")

target      = add_port_finding(8888, "192.0.2.23")
same_dev    = add_port_finding(22,   "192.0.2.23")
other_dev   = add_port_finding(8888, "192.0.2.24")
legacy      = add_port_finding(8888, "192.0.2.23", with_host=False)
legacy_other = add_port_finding(8888, "192.0.2.24", with_host=False)


print("\n[1] declaring clears the backlog for that port on that device")
entry = me.declare_expected_port("192.0.2.23", 8888, "Echo devices listen here")
check("the declaration is recorded", entry["reason"], "Echo devices listen here")
check("and it reports what it cleared", entry["cleared"]["count"], 2)
check("the matching finding is dismissed", is_dismissed(target), 1)
# The fallback half. Anything written before the host column went into
# raw_data can only be matched on its title, and refusing to clear those
# would mean telling the owner their old findings are stuck.
check("an old finding with no host in raw_data is matched by title",
      is_dismissed(legacy), 1)


print("\n[2] what a declaration must NOT touch")
# This is the half worth having a test for. Over-clearing is silent: it does
# not throw, it just removes an alert somebody should have seen.
check("another port on the SAME device still stands", is_dismissed(same_dev), 0)
check("the same port on ANOTHER device still stands", is_dismissed(other_dev), 0)
check("including the old-style row for another device",
      is_dismissed(legacy_other), 0)
# And it must not have reached for dismiss_entity, which is keyed on the port
# number and would have silenced 8888 everywhere, forever.
with sqlite3.connect(DB) as c:
    n = c.execute("SELECT COUNT(*) FROM dismissed_findings").fetchone()[0]
check("no entity-wide dismissal was created", n, 0)


print("\n[3] the reason survives, because that is the whole point")
with sqlite3.connect(DB) as c:
    why = c.execute("SELECT dismissed_reason FROM findings WHERE id = ?",
                    (target,)).fetchone()[0]
check("the cleared row records why", "Echo devices listen here" in (why or ""), True)
check("and it is journaled",
      bool(list(sqlite3.connect(DB).execute(
          "SELECT 1 FROM integrity_journal WHERE operation = 'port_findings_cleared'"))),
      True)


print("\n[4] declaring again clears nothing, because nothing is left")
again = me.declare_expected_port("192.0.2.23", 8888, "same again")
check("second declaration finds an empty backlog", again["cleared"]["count"], 0)


print("\n[5] withdrawing turns the alarm back on, and resurrects nothing")
# Undoing a silence should mean future scans raise again. It should NOT put
# back a queue the owner has already read and answered.
check("withdrawn", me.undeclare_expected_port("192.0.2.23", 8888), True)
check("the port is no longer expected",
      me.is_port_expected("192.0.2.23", 8888) or None, None)
check("and the cleared finding stays cleared", is_dismissed(target), 1)


print("\n[6] a reason is still required")
try:
    me.declare_expected_port("192.0.2.23", 9999, "   ")
    check("empty reason refused", False, True)
except me.BadInput:
    check("empty reason refused", True, True)

try:
    me.declare_expected_port("192.0.2.99", 80, "not in the inventory")
    check("unknown device refused", False, True)
except me.BadInput:
    check("unknown device refused", True, True)


print("\n[7] clearing never takes the declaration down with it")
# A clear that fails must not lose the thing the owner actually asked for.
broken = me.clear_port_findings("192.0.2.23", 8888, "x")
check("a clear with nothing to do is not an error", broken["count"], 0)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
