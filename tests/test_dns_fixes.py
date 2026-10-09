#!/usr/bin/env python3
"""
tests/test_dns_fixes.py — REGISTER SECTION 15, the dns round
(tools/dns_monitor.py + tools/dns_inspector.py), 2026-09-27.

ONE SECTION PER DEFECT, each asserted in the direction that FAILS if the
defect comes back. Every check drives the SHIPPED functions — the readers on
real files, the checks on a scratch store, the store's own funnel, the
importer's own log — or the shipped file's own text where the defect WAS
text. Nothing here reimplements the code under test.

The defects were measured on THIS host before they were fixed. The
measurements are in bugfinder.md, section "2026-09-27 — THE DNS PAIR" and
register section 15 of toolaudit.md. The measurement scripts are /tmp/s15/m1..
m8 with their outputs m1.txt .. m8.txt.

THE FIXTURES NAME NOBODY AND NO MACHINE. Addresses are RFC 5737
documentation ranges; names are example style; the store is the isolated
scratch built by _isolate_db. The one live figure quoted in a comment is a
row COUNT.

SECTIONS MARKED "RECORDED, NOT FIXED" assert the state of something the
round deliberately did not change, so the record is testable and a later
round's fix will visibly move them. They are not claims that the behaviour is
correct.

Run it directly: python3 tests/test_dns_fixes.py
"""

import json
import logging
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import integrity                            # noqa: E402
from core import memory_engine as me                  # noqa: E402
from core import perf                                 # noqa: E402
from core import sensors as sn                        # noqa: E402
from tools import dns_monitor as dm                   # noqa: E402
from tools import dns_inspector as di                 # noqa: E402

fails = []
TMP = pathlib.Path(tempfile.mkdtemp(prefix="agentalsec_dns_fixes_"))

# The scratch store gets the two sensor rows a real boot writes, because the
# findings path refuses a foreign key it cannot satisfy.
me.upsert_sensor(sensor_id=sn.LOCAL_SENSOR_ID, label="host", position="host",
                 summary="", can_see="", cannot_see="", notes="harness")
RESOLVER_SENSOR = dm.register_resolver_sensor({"dns_monitor": {}})


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  [{label}]: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, condition):
    check(label, bool(condition), True)


def guard(fn, *a, **kw):
    """A call that can raise becomes a value, so a raising check prints FAIL
    instead of stopping every check after it."""
    try:
        return fn(*a, **kw)
    except Exception as e:
        return f"RAISED {type(e).__name__}: {e}"


def stripped(path):
    """A module's source with comments and docstrings removed.

    WHY: an absence check greps text, and the FIX'S OWN COMMENT explains the
    defect by naming it, so a plain substring check reads the explanation and
    fails on it — the trap this tree has recorded three times now. The
    docstring strip uses the AST so a wrapped docstring cannot survive it.
    """
    import ast
    src = pathlib.Path(path).read_text(encoding="utf-8")
    tree = ast.parse(src)
    lines = src.splitlines()
    drop = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)) and node.body:
            first = node.body[0]
            if (isinstance(first, ast.Expr)
                    and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)):
                for ln in range(first.lineno - 1, (first.end_lineno or
                                                   first.lineno)):
                    drop.add(ln)
    kept = []
    for i, line in enumerate(lines):
        if i in drop:
            continue
        if line.lstrip().startswith("#"):
            continue
        kept.append(line.split("#")[0] if "#" in line else line)
    return "\n".join(kept)


def insert_dns(rows):
    """rows: (queried_at, client_ip, domain, query_type, reply_type)"""
    with me._get_conn() as c:
        c.executemany(
            "INSERT INTO dns_queries (queried_at, client_ip, domain,"
            " query_type, reply_type, source, source_row_id, sensor_id)"
            " VALUES (?,?,?,?,?,'pihole',?,?)",
            [(r[0], r[1], r[2], r[3], r[4], f"nd-{i}", RESOLVER_SENSOR)
             for i, r in enumerate(rows)])
        c.commit()


def clear_findings():
    with me._get_conn() as c:
        c.execute("DELETE FROM findings")
        c.execute("DELETE FROM dismissed_findings")
        c.commit()


def clear_dns():
    with me._get_conn() as c:
        c.execute("DELETE FROM dns_queries")
        c.commit()


def findings_for(detection_id):
    with me._get_conn() as c:
        return [tuple(r) for r in c.execute(
            "SELECT entity_value, title, sensor_id FROM findings WHERE"
            " detection_id = ?", (detection_id,)).fetchall()]


def adguard_line(name, when, ip="198.51.100.5", qt="A", reason=None,
                 filt=False):
    e = {"QH": name, "T": when, "IP": ip, "QT": qt,
         "Result": {"IsFiltered": filt}}
    if reason is not None:
        e["Result"]["Reason"] = reason
    return json.dumps(e)


NOW = datetime.now(timezone.utc)

# ═════════════════════════════════════════════════════════════════════════
print("\n[1] THE INSPECTION THAT COULD NOT RUN (main.py's importer thread)")
# ═════════════════════════════════════════════════════════════════════════
# THE DEFECT: _start_dns_importer's signature had lost session_id while the
# loop body kept passing it, so every pass raised NameError and the SECOND
# HALF OF THE DNS SENSOR never ran. MEASURED: "DNS inspection error: name
# 'session_id' is not defined", once per pass.
#
# The check drives the SHIPPED function, extracted by AST because main.py
# boots the app on import, with the inspector's own analysis function
# replaced by a recorder — so what is asserted is the CALL and its argument,
# not a source string.
import ast                                                    # noqa: E402
import threading                                              # noqa: E402

_main_src = (ROOT / "main.py").read_text(encoding="utf-8")
_main_tree = ast.parse(_main_src)
_importer = next((n for n in _main_tree.body
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "_start_dns_importer"), None)
check_true("main.py still has _start_dns_importer",
           _importer is not None)
_seg = ast.get_source_segment(_main_src, _importer) if _importer else ""

check_true("its signature takes session_id",
           "def _start_dns_importer(config: dict, dns_monitor,"
           " session_id: str)" in _seg)

# And the body RESOLVES it rather than merely naming it: symtable reports
# which free names the loop reads, and session_id must not be among them.
import symtable                                              # noqa: E402
_st = symtable.symtable(_seg, "main.py", "exec")
_func_scope = next(c for c in _st.get_children()
                   if c.get_name() == "_start_dns_importer")
_loop_scope = next(c for c in _func_scope.get_children()
                   if c.get_name() != "_start_dns_importer")
# And the body RESOLVES it: the function's own symbol table must bind
# session_id as a PARAMETER. The defect was the name reading as an unresolved
# global that does not exist, which is what raised NameError on every pass.
_sess = [s for s in _func_scope.get_symbols() if s.get_name() == "session_id"]
check("the function binds session_id at its own scope", len(_sess), 1)
check_true("and it is bound as a PARAMETER, not read from a global",
           bool(_sess) and _sess[0].is_parameter())
check_true("so nothing in the function reads it as free or global",
           not any(s.is_free() or s.is_global() for s in _sess))

# Drive it. The call must ARRIVE with the value the caller passed.
_seen = []


def _fake_analyse(config, session_id):
    _seen.append(session_id)
    return {"ran": True, "dga_findings": 0, "beacon_findings": 0,
            "reason": None}


_real_analyse = di.analyse_once
_import_logging = logging
_ns = {"__name__": "main", "__file__": str(ROOT / "main.py"),
       "logger": logging.getLogger("main"), "logging": logging,
       "time": __import__("time"), "threading": threading}
exec(compile(_seg, str(ROOT / "main.py"), "exec"), _ns)

_records = []


class _Cap(logging.Handler):
    def emit(self, record):
        _records.append(record.getMessage())


logging.getLogger().addHandler(_Cap())
# The importer's own line is INFO, and the root level defaults to WARNING:
# without this the capture collects nothing and every check in section 8
# would fail for a reason that has nothing to do with the code under test.
logging.getLogger().setLevel(logging.DEBUG)


class _FakeMonitor:
    # The importer asks status() each pass, to tell waiting from failing.
    def status(self, config):
        return {"available": True, "source": "pihole", "path": None,
                "reason": None}

    def import_once(self, config):
        return {"ran": True, "more_available": False, "inserted": 0,
                "read": 0, "cursor": 0, "source": "pihole", "reason": None}


di.analyse_once = _fake_analyse
try:
    _ns["_start_dns_importer"](
        {"dns_monitor": {"enabled": True, "source": "pihole",
                         "path": "/nonexistent", "interval_minutes": 1}},
        _FakeMonitor(), "sess-dns-fixes")
    __import__("time").sleep(2.0)
finally:
    di.analyse_once = _real_analyse

check("the inspection was REACHED on the first pass", len(_seen), 1)
check("and received the caller's session_id",
      _seen[0] if _seen else None, "sess-dns-fixes")
check("no NameError about session_id is logged",
      [m for m in _records if "session_id" in m], [])

# ═════════════════════════════════════════════════════════════════════════
print("\n[2] THE CURSORS ARE NOT THE POLICY ANY MORE (schema v54)")
# ═════════════════════════════════════════════════════════════════════════
# THE DEFECT: both bookmarks lived in user_preferences, which
# core/integrity.snapshot_config digests as THE POLICY. MEASURED: one
# _set_cursor call produced a false "the policy has CHANGED" journal entry
# carrying nothing but a row number. THE SIXTH TIME THIS TREE PAID FOR IT.
with me._get_conn() as c:
    c.execute("DELETE FROM dns_cursor")
    c.execute("DELETE FROM integrity_journal WHERE operation ="
              " 'config_observed'")
    c.commit()

integrity.snapshot_config("dns-fixes-seed")
with me._get_conn() as c:
    _before = c.execute("SELECT COUNT(*) FROM integrity_journal WHERE"
                        " operation='config_observed'").fetchone()[0]

dm._set_cursor("pihole", 1234, "9999")
di._set_cursor(99)

_state = integrity.snapshot_config("dns-fixes-after")
with me._get_conn() as c:
    _after = c.execute("SELECT COUNT(*) FROM integrity_journal WHERE"
                       " operation='config_observed'").fetchone()[0]
    _curs = [tuple(r) for r in c.execute(
        "SELECT name, value, identity FROM dns_cursor ORDER BY name")]
    _dns_keys = [r[0] for r in c.execute(
        "SELECT key FROM user_preferences WHERE key LIKE '%dns%'")]

check("a cursor write does NOT move the policy digest", _state, None)
check("and writes NO config_observed journal entry",
      _after - _before, 0)
check("both cursors live in dns_cursor, value AND identity",
      _curs, [("dns_import_cursor_pihole", "1234", "9999"),
              ("dns_inspect_cursor", "99", None)])
check("and NOT ONE dns key is left in the policy table", _dns_keys, [])

_src_mon = stripped(ROOT / "tools" / "dns_monitor.py")
_src_ins = stripped(ROOT / "tools" / "dns_inspector.py")
check_true("the stripper is doing something (the migration note is in the "
           "raw file and gone from the stripped one)",
           "user_preferences" in (ROOT / "tools" / "dns_monitor.py").read_text()
           and "user_preferences" not in _src_mon)
check_true("no RUNNING line in either module writes a preference",
           "set_preference" not in _src_mon
           and "set_preference" not in _src_ins)

# ═════════════════════════════════════════════════════════════════════════
print("\n[3] THE ADGUARD READER: ROTATION, GROWTH, A HALF-WRITTEN LINE")
# ═════════════════════════════════════════════════════════════════════════
# (a) ROTATION. A renamed-away log whose replacement is ALREADY BIGGER than
# the stored offset passes every size guard. MEASURED: 3 of 12 rows skipped,
# no note anywhere. The inode is what tells the two files apart.
#
# DRIVEN THROUGH import_once, not through a re-statement of its own branch:
# the identity comparison lives in the importer, and a check that reimplements
# the branch measures this file's model of it rather than the code.
rot = TMP / "rot.json"
with open(rot, "w", encoding="utf-8") as fh:
    for i in range(3):
        fh.write(adguard_line(f"a{i}.example",
                              f"2026-09-26T19:31:0{i}+03:00") + "\n")
_rot_cfg = {"dns_monitor": {"enabled": True, "source": "adguard",
                            "path": str(rot), "interval_minutes": 15}}
clear_dns()
_first = guard(dm.import_once, _rot_cfg)
check_true("import_once ran against the AdGuard log",
           isinstance(_first, dict) and _first.get("ran") is True)
check("pass 1 stored its 3 rows", _first.get("inserted"), 3)
check("the cursor carried the file's identity with the offset",
      dm._cursor_row(dm._CURSOR_KEY.format(source="adguard"))[1] is not None,
      True)

rot.rename(TMP / "rot.json.1")
with open(rot, "w", encoding="utf-8") as fh:
    for i in range(12):
        fh.write(adguard_line(f"b{i}.example",
                              f"2026-09-26T20:31:0{i % 10}+03:00") + "\n")
_new_size = rot.stat().st_size
_curs = dm._cursor_row(dm._CURSOR_KEY.format(source="adguard"))
# GUARDED, because the control that puts the cursor back into the policy table
# leaves this read returning (None, None) — and an unguarded int(None) made
# the SUBJECT DIE instead of printing a FAIL, which the harness then reported
# as a crashed run that measured nothing. A check that crashes is the check's
# own fault.
try:
    _curs_off = int(_curs[0]) if _curs and _curs[0] is not None else None
except (TypeError, ValueError):
    _curs_off = None
check_true("the replacement IS already past the stored offset (the case the "
           "size guard cannot see)",
           _curs_off is not None and _new_size > _curs_off)
check_true("file_identity tells the two files apart",
           dm.file_identity(TMP / "rot.json.1") != dm.file_identity(rot))

_second = guard(dm.import_once, _rot_cfg)
check("pass 2 reads the ROTATED file from the start: all 12 rows land",
      _second.get("inserted"), 12)
check_true("and the pass SAYS a rotation happened",
           _second.get("rotated") is True)
with me._get_conn() as c:
    _stored = c.execute("SELECT COUNT(*) FROM dns_queries WHERE source="
                        "'adguard'").fetchone()[0]
check("the store holds 3 + 12, not 3 + the rows past the old offset",
      _stored, 15)

# (b) A HALF-WRITTEN LAST LINE. MEASURED: the rest arrived, the completed
# line sat BEHIND the cursor, and no pass ever read it.
half = TMP / "half.json"
with open(half, "wb") as fh:
    fh.write(b'{"QH":"c1.example","T":"2026-09-26T21:00:00Z",'
             b'"IP":"198.51.100.7","QT":"A"}\n')
    fh.write(b'{"QH":"c2.example","T":"2026-09-26T21:00:01Z",'
             b'"IP":"198.51.100.7","QT"')
_r3, _o3, _n3 = dm.read_adguard(half, after_offset=0)
check("the half-written line is NOT consumed", (len(_r3), _o3),
      (1, half.stat().st_size - len(
          b'{"QH":"c2.example","T":"2026-09-26T21:00:01Z",'
          b'"IP":"198.51.100.7","QT"')))
with open(half, "ab") as fh:
    fh.write(b':"A"}\n')
_r4, _o4, _n4 = dm.read_adguard(half, after_offset=_o3)
check("when the rest arrives the completed line IS read",
      [r["domain"] for r in _r4], ["c2.example"])
check("and the cursor ends at the file's end", _o4, half.stat().st_size)

# (c) A CORRUPT line that is NOT the last one is counted, not passed over.
bad = TMP / "bad.json"
with open(bad, "w", encoding="utf-8") as fh:
    fh.write(adguard_line("d1.example", "2026-09-26T22:00:00Z") + "\n")
    fh.write("this is not json\n")
    fh.write(adguard_line("d2.example", "2026-09-26T22:00:01Z") + "\n")
_r5, _o5, _n5 = dm.read_adguard(bad, after_offset=0)
check("a malformed line is COUNTED in the notes", _n5.get("line_skipped"), 1)
check("and the good rows on both sides are still read", len(_r5), 2)

# ═════════════════════════════════════════════════════════════════════════
print("\n[4] THE WINDOWED CHECKS: TITLES AND TIMESTAMP SHAPE")
# ═════════════════════════════════════════════════════════════════════════
# (a) AN UNCHANGED CONDITION MUST NOT WRITE A NEW ROW. MEASURED before the
# fix: a client in the same condition whose count drifted 250 -> 251 -> 252
# -> 253 wrote FOUR rows, because the title carried the count.
clear_dns()
clear_findings()
for drift in (250, 251, 252, 253):
    clear_dns()
    base = NOW - timedelta(minutes=30)
    insert_dns([((base + timedelta(seconds=i)).isoformat(), "192.0.2.60",
                 f"nx{i}.example", "A", "NXDOMAIN") for i in range(drift)])
    di._check_activity(sqlite3.connect(me.DB_PATH), "sess-dns-fixes")
check("four passes of ONE unchanged condition write ONE row",
      len(findings_for("DNS-1005")), 1)
check_true("and its title carries no count",
           all("(" not in t[1] for t in findings_for("DNS-1005")))

# The other three moving titles, driven the same way.
clear_dns()
clear_findings()
base = NOW - timedelta(minutes=30)
for drift in (40, 41):
    clear_dns()
    insert_dns([((base + timedelta(seconds=i)).isoformat(), "192.0.2.61",
                 f"u{i}.example", "A", "IP") for i in range(100)]
               + [((base + timedelta(seconds=100 + i)).isoformat(),
                   "192.0.2.61", f"t{i}.example", "TXT", "IP")
                  for i in range(drift)])
    di._check_activity(sqlite3.connect(me.DB_PATH), "sess-dns-fixes")
check("the TXT title does not move with its count either",
      len(findings_for("DNS-1006")), 1)

clear_dns()
clear_findings()
base = NOW - timedelta(minutes=20)
for drift in (5, 6):
    clear_dns()
    insert_dns([((base + timedelta(seconds=i)).isoformat(), "192.0.2.62",
                 f"mf4gk3ljhq2xw7zb{i}.tunnel.example", "A", "IP")
                for i in range(drift)])
    di._check_tunnels(sqlite3.connect(me.DB_PATH), "sess-dns-fixes")
check("the tunnel title does not move with its count",
      len(findings_for("DNS-1003")), 1)

clear_dns()
clear_findings()
base = NOW - timedelta(minutes=25)
for drift in (9000, 9001):
    clear_dns()
    insert_dns([((base + timedelta(seconds=i)).isoformat(), "192.0.2.63",
                 f"v{i}.example", "A", "IP") for i in range(drift)]
               + [((base + timedelta(seconds=i)).isoformat(), "192.0.2.64",
                   f"w{i}.example", "A", "IP") for i in range(200)])
    di._check_activity(sqlite3.connect(me.DB_PATH), "sess-dns-fixes")
check("the VOLUME title does not move with its count either",
      len(findings_for("DNS-1004")), 1)

_ins_code = stripped(ROOT / "tools" / "dns_inspector.py")
check_true("no RUNNING title in the inspector interpolates a count",
           not any(t in _ins_code for t in (
               'title = (f"Possible DNS tunnel: {client_ip} sent {distinct}',
               'title = (f"Unusual DNS query volume from {client_ip}: {total}',
               'title = (f"Most of what {client_ip} asked for does not exist'
               ' ({nxdomain}',
               'title = (f"Unusual TXT record volume from {client_ip}: {txt}',
               'title = (f"{client_ip} is rotating through DGA-profile'
               ' domains: {extra}',
           )))
for _bad_title in ('title = (f"Possible DNS tunnel: {client_ip} sent',
                   'title = (f"Unusual DNS query volume from {client_ip}:'
                   ' {total}',
                   'title = (f"Most of what {client_ip} asked for does not "',
                   'title = (f"Unusual TXT record volume from {client_ip}:'
                   ' {txt}'):
    check_true(f"the old moving title is gone: {_bad_title[8:46]}...",
               _bad_title not in _ins_code)

# (b) THE TIMESTAMP SHAPE. MEASURED: a row 20 minutes old, written the way
# AdGuard writes it, was selected by 0 of 1 four-hour windows, because its
# LOCAL date sorted behind the UTC cutoff. Every west-of-Greenwich resolver
# lost its local-evening rows to every windowed check.
check("an AdGuard local stamp is normalised to UTC",
      dm._iso_from_text("2026-09-26T23:40:22.363412-07:00"),
      "2026-09-27T06:40:22+00:00")
check("an east-of-Greenwich stamp resolves to the same instant",
      dm._iso_from_text("2026-09-26T19:31:01.376690873+03:00"),
      "2026-09-26T16:31:01+00:00")
check("a Pi-hole fractional stamp loses the fraction",
      dm._iso(1758915061.5), "2025-09-26T19:31:01+00:00")

clear_dns()
# CORRECTED 2026-09-27, REGISTER SECTION 17 (RVP-C1), IN PLACE.
#
# This block used to insert the FIXED literal "2026-09-27T06:40:22+00:00" —
# the normalisation of a stamp written at 23:40 local, twenty minutes before
# the round that wrote it — and then assert that it fell inside a 4-hour
# window whose cutoff moves with the clock. MEASURED at 11:02 UTC on the day
# after that round: the cutoff was 07:02, the literal was behind it, and the
# check read "1 (want 2)" — a GREEN-WHEN-WRITTEN test that goes red a few
# hours later and reads as a regression in the DNS sensor.
#
# The instant under test is now REBUILT THE SAME WAY THE READER BUILDS IT,
# from a stamp twenty minutes in the past carrying its OWN offset, so the row
# is always inside the window and what is being tested is the SHAPE (an
# offset-bearing stamp normalises to UTC and lands in the window), not a date.
# THE WEST-OF-GREENWICH CASE IS STILL EXERCISED: the offset is applied to a
# real instant rather than dropped, which is exactly what DNS-6 was about.
_adguard_now = (NOW - timedelta(minutes=20)).astimezone(
    timezone(timedelta(hours=-7)))
check("an AdGuard local stamp, normalised, lands inside the window",
      dm._iso_from_text(_adguard_now.isoformat()), 
      (NOW - timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%S+00:00"))
insert_dns([(dm._iso_from_text(_adguard_now.isoformat()),
             "192.0.2.9", "west.example", "A", "IP"),
            ((NOW - timedelta(minutes=20)).isoformat(), "192.0.2.10",
             "recent.example", "A", "IP")])
_conn = sqlite3.connect(me.DB_PATH, isolation_level=None)
_conn.row_factory = sqlite3.Row
_cutoff = di._window_cutoff(4.0)
_n = _conn.execute("SELECT COUNT(*) AS n FROM dns_queries WHERE queried_at"
                   " >= ?", (_cutoff,)).fetchone()["n"]
check("the window now selects BOTH rows (the local one is inside it)", _n, 2)
check_true("the cutoff's shape is the column's own (whole second, +00:00)",
           _cutoff.endswith("+00:00") and "." not in _cutoff
           and len(_cutoff) == len(me._sql_datetime(
               "2026-01-01T00:00:00", me.SHAPE_ISO_OFFSET)))
check_true("and the funnel is what builds it, not a second strftime",
           "me._sql_datetime(raw, me.SHAPE_ISO_OFFSET)" in stripped(
               ROOT / "tools" / "dns_inspector.py"))

# ═════════════════════════════════════════════════════════════════════════
print("\n[5] THE VOLUME RULE'S MEDIAN EXCLUDES THE SUBJECT")
# ═════════════════════════════════════════════════════════════════════════
# MEASURED: A=10000, B=60 gave a median of 5030 (over 2 clients), so A had
# to reach 20120 and raised NOTHING — while the rule's own published words
# say "the median of the OTHER clients". The defect is LARGEST on the
# smallest network.
check("the median of the others for A=10000, B=60",
      di._median_of_others({"192.0.2.70": (10000, 0, 0),
                            "192.0.2.71": (60, 0, 0)}, "192.0.2.70"), 60.0)

clear_dns()
clear_findings()
base = NOW - timedelta(minutes=30)
insert_dns([((base + timedelta(seconds=i)).isoformat(), "192.0.2.70",
             f"a{i}.example", "A", "IP") for i in range(10000)]
           + [((base + timedelta(seconds=i)).isoformat(), "192.0.2.71",
               f"b{i}.example", "A", "IP") for i in range(60)])
_out = di._check_activity(sqlite3.connect(me.DB_PATH), "sess-dns-fixes")
check("the two-client network now FIRES where the old code was silent",
      _out["volume"], 1)
check("and the finding names the resolver sensor",
      set(t[2] for t in findings_for("DNS-1004")), {RESOLVER_SENSOR})

# A neighbour BELOW the comparator floor is not a baseline, and the check
# says so rather than reporting a clean result.
clear_dns()
clear_findings()
insert_dns([((base + timedelta(seconds=i)).isoformat(), "192.0.2.72",
             f"c{i}.example", "A", "IP") for i in range(10000)]
           + [((base + timedelta(seconds=i)).isoformat(), "192.0.2.73",
               f"d{i}.example", "A", "IP") for i in range(10)])
_out2 = di._check_activity(sqlite3.connect(me.DB_PATH), "sess-dns-fixes")
check("a neighbour below the floor raises nothing", _out2["volume"], 0)
check("and the check NAMES the comparison it could not make",
      _out2.get("no_comparator"), 1)
check_true("the sentence says what was missing",
           "NO comparison baseline" in (_out2.get("note") or ""))

# The floor itself still does its job: a genuinely idle neighbour stays out.
check("a client below the floor is not a comparator",
      di._median_of_others({"192.0.2.74": (10000, 0, 0),
                            "192.0.2.75": (10, 0, 0)}, "192.0.2.74"), 0.0)

# ═════════════════════════════════════════════════════════════════════════
print("\n[6] THE FINDING IS FILED UNDER THE RESOLVER SENSOR")
# ═════════════════════════════════════════════════════════════════════════
# MEASURED: the rows were stored under <host>-resolver while every finding
# fell back to the HOST row, whose declared scope is this machine's own
# traffic — the wrong scope sentence for something the resolver saw.
clear_dns()
clear_findings()
insert_dns([((base + timedelta(seconds=i)).isoformat(), "192.0.2.80",
             f"e{i}.example", "A", "NXDOMAIN") for i in range(250)])
di._check_activity(sqlite3.connect(me.DB_PATH), "sess-dns-fixes")
_row_sensors = set(t[2] for t in findings_for("DNS-1005"))
check("the NXDOMAIN finding names the resolver sensor", _row_sensors,
      {RESOLVER_SENSOR})
check_true("which is NOT the host sensor",
           RESOLVER_SENSOR != sn.LOCAL_SENSOR_ID)
check("and it is the sensor the rows are stored under",
      set(r[0] for r in sqlite3.connect(me.DB_PATH).execute(
          "SELECT DISTINCT sensor_id FROM dns_queries")), {RESOLVER_SENSOR})

# Every raising site, not just the one that was measured: the DGA pair, the
# beacon, the tunnel and the three volume checks.
_ins_code = stripped(ROOT / "tools" / "dns_inspector.py")
check("all SEVEN raising sites pass the resolver sensor",
      _ins_code.count("sensor_id=resolver_sensor_id(),"), 7)
check_true("and the importer and inspector share one naming function",
           "def resolver_sensor_id()" in stripped(
               ROOT / "tools" / "dns_monitor.py"))

# ═════════════════════════════════════════════════════════════════════════
print("\n[7] THE RESOLVER'S OWN WORDS, AND THE CODES BEYOND ITS OLD MAP")
# ═════════════════════════════════════════════════════════════════════════
# MEASURED: a blocked AdGuard query was stored as the bare integer 4 in a
# text column nobody can read, and Pi-hole's status 18 (in FTL's OWN blocked
# set) was published as "code_18" and counted as answered.
check("an AdGuard reason is stored as the VENDOR's own name",
      dm._adguard_reason(4), "filtered_safe_browsing")
check("an absent reason is the ordinary answer, not a gap",
      dm._adguard_reason(None), "answered")
check("an undocumented code passes through AS ITS NUMBER",
      dm._adguard_reason(99), "reason_99")

# And the ROW the reader builds carries it, which is what actually lands in
# the column: the decoder being right is not the same as the reader using it.
_status_log = TMP / "status.json"
with open(_status_log, "w", encoding="utf-8") as fh:
    fh.write(adguard_line("blocked.example", "2026-09-26T19:31:01Z",
                          reason=3, filt=True) + "\n")
    fh.write(adguard_line("plain.example", "2026-09-26T19:31:02Z") + "\n")
_srows, _soff, _snotes = dm.read_adguard(_status_log, after_offset=0)
check("the reader stores the vendor's NAME, not the bare code",
      [(r["domain"], r["status"]) for r in _srows],
      [("blocked.example", "filtered_block_list"),
       ("plain.example", "answered")])
check("and the blocked flag comes from the vendor's own field",
      [r["blocked"] for r in _srows], [True, False])
check("Pi-hole status 18 (EXTERNAL_BLOCKED_EDE15) is decoded",
      dm._decode(dm._PIHOLE_STATUS, 18), "blocked_upstream_ede15")
check("  and it is COUNTED AS BLOCKED (FTL's own set includes it)",
      dm._is_pihole_blocked(18), True)
check("status 16 (SPECIAL_DOMAIN) is decoded",
      dm._decode(dm._PIHOLE_STATUS, 16), "blocked_special_domain")
check("reply 13 (BLOB) is decoded",
      dm._decode(dm._PIHOLE_REPLY, 13), "BLOB")
check("type 16 (HTTPS) is decoded",
      dm._decode(dm._PIHOLE_TYPES, 16), "HTTPS")
check("a code nobody has documented still reads as unknown",
      dm._decode(dm._PIHOLE_STATUS, 99), "code_99")

# The decoder is TRANSCRIPTION, so the numbers are pinned to the vendor's
# own enums rather than to whatever the map happens to say today.
check("the Pi-hole type map matches FTL's enums.h arity (TYPE_HTTPS = 16)",
      max(dm._PIHOLE_TYPES), 16)
check("the blocked set holds exactly the codes FTL marks blocked",
      dm._PIHOLE_BLOCKED,
      {1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18})

# ═════════════════════════════════════════════════════════════════════════
print("\n[8] THE IMPORTER SAYS WHAT EVERY PASS READ")
# ═════════════════════════════════════════════════════════════════════════
# MEASURED: a pass that ran and found 0 rows logged NOTHING at all, so "the
# sensor is working and the resolver is quiet" and "the thread died" produced
# identical logs.
slog = TMP / "pihole-FTL.db"
_c = sqlite3.connect(slog)
_c.execute("CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp REAL,"
           " type INTEGER, status INTEGER, domain TEXT, client TEXT,"
           " forward TEXT, reply_type INTEGER)")
_c.commit()
_c.close()

_records.clear()
_state = guard(dm.import_once, {"dns_monitor": {"enabled": True,
                                                "source": "pihole",
                                                "path": str(slog)}})
check_true("import_once ran against an EMPTY source", isinstance(_state, dict)
           and _state.get("ran") is True)
check("a pass that read nothing still logs its own line",
      len([m for m in _records if "DNS import:" in m]), 1)
check_true("and the line carries the counts",
           any("0 new of 0 stored" in m for m in _records
               if "DNS import:" in m))

# more_available must follow the SOURCE's count, not the rows that survived
# the reader's filters. MEASURED: 15,000 of 20,010 rows returned (under
# BATCH_LIMIT) so more_available read False with 10 rows still waiting.
big = TMP / "big.db"
_c = sqlite3.connect(big)
_c.execute("CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp REAL,"
           " type INTEGER, status INTEGER, domain TEXT, client TEXT,"
           " forward TEXT, reply_type INTEGER)")
_ts = 1758915061.0
# ids run 1..1001: the reader asks for `id > after_row_id`, so a fixture that
# starts at 0 loses its own first row and reports one fewer than it wrote.
_c.executemany("INSERT INTO queries (id, timestamp, type, status, domain,"
               " client, reply_type) VALUES (?,?,1,2,?,?,4)",
               [(i, _ts, f"r{i}.example" if i % 4 else None,
                 "198.51.100.9") for i in range(1, 1002)])
_c.commit()
_c.close()
_rowsb, _offb, _notesb = dm.read_pihole(big, after_row_id=0, limit=1000)
check("a source with a FULL batch reports hit_limit from its own count",
      _notesb["hit_limit"], True)
check("rows_read is the SOURCE's count, not the reader's survivors",
      _notesb["rows_read"], 1000)
check("and the dropped rows are counted beside it",
      _notesb["rows_dropped"], 250)
check("the returned rows are what survived", len(_rowsb), 750)

# ═════════════════════════════════════════════════════════════════════════
print("\n[9] core/perf.py CAN SEE A DNS ROW")
# ═════════════════════════════════════════════════════════════════════════
# MEASURED: perf built its window with the file's own space-shaped
# _sql_ts, the dns_queries column holds an offset-shaped ISO string, and the
# window selected 0 of 1 rows — so dns_present read False and perf_hourly
# wrote NULL, which the page and the model read as "no resolver importing at
# all" on a machine whose resolver import was working.
clear_dns()
clear_findings()
hour_start = NOW.replace(minute=0, second=0, microsecond=0)
insert_dns([((hour_start + timedelta(minutes=10)).isoformat(),
             "192.0.2.90", "perf.example", "A", "IP")])
with me._get_conn() as c:
    c.execute("DELETE FROM perf_hourly")
    c.execute("INSERT INTO packets (session_id, captured_at, src_ip, dst_ip,"
              " protocol, packet_size, src_port, dst_port, sensor_id)"
              " VALUES ('s-pkt', ?, '192.0.2.90', '192.0.2.91', 'TCP', 100,"
              " 1234, 80, ?)",
              (perf._sql_ts(hour_start + timedelta(minutes=5)),
               sn.LOCAL_SENSOR_ID))
    c.commit()
_built = guard(perf.build_hour, hour_start)
check_true("build_hour ran and wrote at least one bucket",
           isinstance(_built, int) and _built >= 1)
with me._get_conn() as c:
    _bucket = c.execute("SELECT dns_queries, dns_failures FROM perf_hourly"
                        " WHERE entity_value = '192.0.2.90'").fetchone()
check("the hour's bucket carries the DNS row that fell inside it",
      None if _bucket is None else tuple(_bucket), (1, 0))
check("perf's DNS bounds are built in the COLUMN's own shape",
      perf._sql_ts_iso(hour_start),
      me._sql_datetime(hour_start.isoformat(), me.SHAPE_ISO_OFFSET))
check_true("and the ISO builder goes through the store's funnel",
           "me._sql_datetime(dt.astimezone(timezone.utc).isoformat(),"
           in (ROOT / "core" / "perf.py").read_text(encoding="utf-8"))

# ═════════════════════════════════════════════════════════════════════════
print("\n[11] DNS-1002 COULD NOT FIRE — the import the port left behind")
# ═════════════════════════════════════════════════════════════════════════
# FOUND BY RUNNING THE PRE-EXISTING FILE (tests/test_dns_inspection.py) after
# this round's title change, which is the only reason it surfaced: the port
# replaced the beacon's inline cutoff with _window_cutoff(...) -- the right
# call -- and deleted the local `from datetime import ...` that the cutoff
# had been the only user of, while the timestamp PARSING below still calls
# datetime.fromisoformat. MEASURED: the exception is raised on the first
# candidate, inside analyse_once's try, and the module's own log carries
# "DNS inspection error: name 'datetime' is not defined". The beacon check
# had NEVER run on this host.
clear_dns()
clear_findings()
base = NOW - timedelta(minutes=30)
# 8 queries, 60 s apart, on ONE name: regular enough to be a beacon.
insert_dns([((base + timedelta(seconds=60 * i)).isoformat(), "192.0.2.95",
             "poll.example", "A", "IP") for i in range(8)])
_beacon = guard(di._check_beacons, sqlite3.connect(me.DB_PATH),
                "sess-dns-fixes")
check("the beacon check RUNS and returns a count", _beacon, 1)
check("and DNS-1002 is in the store",
      len(findings_for("DNS-1002")), 1)

# The import is asserted at the layer it lives at, so a later tidy-up that
# removes it as "unused" reds this check rather than the whole sensor.
_beacon_src = pathlib.Path(ROOT / "tools" / "dns_inspector.py").read_text(
    encoding="utf-8")
import ast as _ast2
_beacon_fn = next(n for n in _ast2.walk(_ast2.parse(_beacon_src))
                  if isinstance(n, _ast2.FunctionDef)
                  and n.name == "_check_beacons")
_beacon_imports = {a.name for n in _ast2.walk(_beacon_fn)
                   if isinstance(n, _ast2.ImportFrom)
                   for a in n.names}
check("_check_beacons imports what it parses with",
      sorted(_beacon_imports & {"datetime", "timezone"}),
      ["datetime", "timezone"])

# ═════════════════════════════════════════════════════════════════════════
print("\n[12] RECORDED, NOT FIXED — the round's own open items")
# ═════════════════════════════════════════════════════════════════════════
# These assert the state of things this round did NOT change, so the record
# is testable and a later round's fix visibly moves them. They are NOT claims
# that the behaviour is right.
_r = dm.import_once({"dns_monitor": {"enabled": False, "source": "pihole",
                                     "path": ""}})
check("with the resolver switched off, import says so and does nothing",
      (_r["ran"], _r["reason"], _r["inserted"]),
      (False, "disabled in config.json", 0))
check("status() names the SAME reason a person would see",
      dm.status({"dns_monitor": {"enabled": False}})["reason"],
      "disabled in config.json")

# The live store's own state, read mode=ro: the resolver import is off and
# this table is empty on this host, which is why every threshold in the
# inspector is a CHOSEN number and says so at its definition.
check_true("the inspector's constants still say they were chosen, not"
           " measured",
           "THE THRESHOLDS BELOW ARE CHOSEN, NOT MEASURED, AND THEY SAY SO"
           in (ROOT / "tools" / "dns_inspector.py").read_text(
               encoding="utf-8"))

# ═════════════════════════════════════════════════════════════════════════
print()
print("=" * 72)
print(f"{len(fails)} failure(s)")
if fails:
    print(f"FAILURES: {fails}")
    sys.exit(1)
print("ALL CHECKS PASSED")
sys.exit(0)
