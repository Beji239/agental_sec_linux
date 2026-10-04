"""
tests/test_packet_scope_filters.py, the scope block counted the wrong thing.
TODO 98, 2026-09-14.

WHERE THIS CAME FROM. The full code pass read packet_search_scope, which is
the function this project has twice held up as the pattern that works, and
found it was doing the one thing _with_total's own comment forbids: building
a count from a second, similar looking WHERE.

It took src_ip and dst_ip. The dispatcher was handing query_packets since,
until, port, direction, scope, process_pid and process_name and handing this
function none of them. So on any search with a filter that was not an address,
the rows answered the model's question and the count answered "how many
packets are there".

Three symptoms, and the third is the expensive one:

  * the total was described as matching and was really the whole table
  * complete said false on answers that were whole
  * the hint said "N more matching packets exist in earlier runs, call again
    with all_sessions=true". The model did, got the newest rows of anything,
    and none of them matched.

That last one is the six round loop this function was written to prevent, so
the fix is not cosmetic. The failure cases below run FIRST and they are what
this file is for; the happy path is at the end.

Runs anywhere. Builds its own database from the real Schema.SQL.
"""
import io
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


from core import memory_engine as me            # noqa: E402

SCHEMA = io.open(ROOT / "Schema.SQL", encoding="utf-8").read()
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
me.DB_PATH = _tmp.name
_c = sqlite3.connect(me.DB_PATH)
_c.executescript(SCHEMA)
_c.commit()
_c.close()


def add_packet(session, src, dst, sport, dport, when, direction="outbound"):
    with me._get_conn() as conn:
        conn.execute(
            "INSERT INTO packets (session_id, captured_at, src_ip, dst_ip, "
            "src_port, dst_port, protocol, direction, packet_size) "
            "VALUES (?,?,?,?,?,?,'TCP',?,64)",
            (session, when, src, dst, sport, dport, direction))


# THE SHAPE OF THE DATA, and it is chosen to make the old bug visible.
#
# 300 packets of ordinary traffic on port 443 in this run, and exactly TWO on
# port 4444, one in this run and one in an earlier one. A question about 4444
# has a true answer of 1 row here and 1 row elsewhere. The old code counted
# 302 and 300 of them had nothing to do with the question.
for i in range(300):
    add_packet("run2", "192.0.2.5", "93.184.216.34", 50000 + i, 443,
               f"2026-09-14T10:{i % 60:02d}:00")
add_packet("run2", "192.0.2.5", "203.0.113.9", 51000, 4444,
           "2026-09-14T11:00:00")
add_packet("run1", "192.0.2.5", "203.0.113.9", 51001, 4444,
           "2026-09-01T11:00:00")


print("\n[0] THE BUG, PROVEN RATHER THAN ASSUMED. The old count is rebuilt")
print("    here exactly as it was, src_ip and dst_ip only, and run against")
print("    the same data. If this stops lying, this whole file is pointless.")


def old_count(src_ip=None, dst_ip=None):
    """core/memory_engine.packet_search_scope as it stood before 2026-09-14."""
    conds, params = [], []
    if src_ip:
        conds.append("src_ip = ?"); params.append(src_ip)
    if dst_ip:
        conds.append("dst_ip = ?"); params.append(dst_ip)
    where = ("WHERE " + " AND ".join(conds)) if conds else ""
    with me._get_conn() as conn:
        return conn.execute(
            f"SELECT COUNT(*) FROM packets {where}", params).fetchone()[0]


# The model asks about port 4444. One row in this run, one in an earlier run.
old_total = old_count()                 # port was never passed, so: everything
check("the old count for a port question was the whole table", old_total, 302)
check("the old answer would have said complete=false on a whole answer",
      old_total <= 1, False)
check("and would have offered 301 rows that do not match",
      old_total - 1, 301)
print("    is what matched. This is the number the model quotes.")

scope = me.packet_search_scope(session_id="run2", all_sessions=False,
                               port=4444, returned=1)
check("the count is the number matching THIS filter", scope["matching_in_this_search"], 1)
check("not the size of the table", scope["matching_in_this_search"] == 302, False)
check("history count is also filtered", scope["matching_in_whole_history"], 2)
check("no key called matching_rows_in_whole_history survives",
      "matching_rows_in_whole_history" in scope, False)


print("\n[2] FAILURE CASE. A complete answer must not be called incomplete.")
print("    One row matched, one row came back, that is everything.")

check("complete is true", scope["complete"], True)
check("and nothing claims the limit cut it", "cut_by_limit" in scope, False)


print("\n[3] FAILURE CASE. The earlier-runs hint has to be about rows that")
print("    would actually come back. This is the six round loop.")

check("elsewhere counts only matching rows", scope["elsewhere"], 1)
check("and the hint says so", "1 more packet(s) matching this same filter"
      in scope["hint"], True)
check("and it does not claim the limit cut anything",
      "The LIMIT cut this" in scope["hint"], False)

# The old code, on this exact call, would have said 302 and 2 and told the
# model to go and fetch 301 more. Pinned as a number so a regression is
# obvious rather than arguable.
with me._get_conn() as conn:
    unfiltered = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
check("(for the record, the unfiltered table is this big)", unfiltered, 302)
check("and the scope block no longer reports it",
      scope["matching_in_whole_history"] != unfiltered, True)


print("\n[4] FAILURE CASE. Nothing matching anywhere must say so, and that")
print("    branch was unreachable while the count ignored the filter.")

none = me.packet_search_scope(session_id="run2", all_sessions=False,
                              port=9999, returned=0)
check("in-scope count is zero", none["matching_in_this_search"], 0)
check("history count is zero", none["matching_in_whole_history"], 0)
check("and the vantage point sentence fires",
      "not just in this run" in none["hint"], True)
check("and it mentions query_sensors", "query_sensors" in none["hint"], True)


print("\n[5] FAILURE CASE. A count that could not run must not leave")
print("    `complete` behind to be read as an answer. Rule two.")

_real = me._get_conn


class _Broken:
    def __enter__(self):
        raise sqlite3.OperationalError("no such table: packets")

    def __exit__(self, *a):
        return False


me._get_conn = lambda *a, **k: _Broken()
try:
    broken = me.packet_search_scope(session_id="run2", port=443, returned=10)
finally:
    me._get_conn = _real

check("complete is absent, not False", "complete" in broken, False)
check("it says it could not count", "COULD NOT COUNT" in broken["hint"], True)
check("and it names the error", "no such table" in broken["scope_note_failed"], True)
check("and it warns against reading empty as quiet",
      "quiet network" in broken["hint"], True)


print("\n[6] The limit cut it, which is a DIFFERENT sentence from elsewhere.")

cut = me.packet_search_scope(session_id="run2", all_sessions=False,
                             port=443, returned=50)
check("in-scope count is the 443 rows only", cut["matching_in_this_search"], 300)
check("complete is false", cut["complete"], False)
check("cut_by_limit is the gap", cut["cut_by_limit"], 250)
check("the hint says the limit did it", "The LIMIT cut this" in cut["hint"], True)
check("and does not send it to all_sessions for rows that are not there",
      "all_sessions=true" in cut["hint"], False)


print("\n[7] BOTH can be true at once, and both have to be said.")

both = me.packet_search_scope(session_id="run2", all_sessions=False,
                              dst_ip="203.0.113.9", returned=0)
check("one matches in this run", both["matching_in_this_search"], 1)
check("two match in history", both["matching_in_whole_history"], 2)
check("the limit sentence is there", "The LIMIT cut this" in both["hint"], True)
check("and the earlier-runs sentence too",
      "exist in EARLIER RUNS" in both["hint"], True)


print("\n[8] all_sessions=true. There is no elsewhere to report.")

wide = me.packet_search_scope(session_id="run2", all_sessions=True,
                              port=4444, returned=2)
check("it counted both runs", wide["matching_in_this_search"], 2)
check("complete", wide["complete"], True)
check("and nothing points at earlier runs", "elsewhere" in wide, False)


print("\n[9] HAPPY PATH, and the one that proves the two WHEREs agree.")
print("    Same filters to both, rows and count must match exactly.")

for kwargs in ({"port": 4444},
               {"dst_ip": "203.0.113.9"},
               {"since": "2026-09-14T10:30:00"},
               {"direction": "outbound"},
               {"port": 443, "since": "2026-09-14T10:30:00"}):
    rows = me.query_packets(session_id="run2", limit=500, **kwargs)
    sc = me.packet_search_scope(session_id="run2", all_sessions=False,
                                returned=len(rows), **kwargs)
    check(f"rows and count agree for {kwargs}",
          sc["matching_in_this_search"], len(rows))
    check(f"and complete is true for {kwargs}", sc["complete"], True)


print("\n[10] The DISPATCH really passes them. A fixed function called with")
print("     two arguments is the bug still shipped.")

src = (ROOT / "core" / "tool_registry.py").read_text(encoding="utf-8")
block = src.split("packet_search_scope(")[1][:700]
for field in ("since", "until", "port", "direction", "process_pid",
              "process_name", "src_ip", "dst_ip"):
    check(f"the dispatch forwards {field}", f'"{field}"' in block, True)
check("and it builds them from pkt_params rather than re-listing values",
      "pkt_params.items()" in block, True)


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
