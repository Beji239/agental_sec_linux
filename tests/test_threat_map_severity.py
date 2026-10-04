"""
tests/test_threat_map_severity.py, a flagged address drawn as ordinary
traffic. TODO 98, 2026-09-14.

WHERE THIS CAME FROM. The threat map colours each endpoint from the findings
table, and its own how_to_read_this says an endpoint with severity null has
nothing recorded against it. The dictionary behind that was built from
query_findings(entity_type="ip", limit=500). 500 is MAX_QUERY_LIMIT, so it was
the largest ask available, and it was still a cap with nothing saying so.

Past the cap an address came back with no severity, and the map then told the
reader it was ordinary. On a database with 14,676 findings that is reachable.

TODO 94 fixed the ENDPOINT LIST completeness in that same function, gave it
endpoints_complete and unlocated_complete, and walked past this join. Same
function, same audit, different list.

The fix is an aggregate rather than a bigger number: one row per address, no
limit to hit, nothing to admit. And it lives in memory_engine so the model's
copy of the map and the dashboard's copy read the same thing, which is the
only reason a fix to one reaches the other.

Failure cases first. Runs anywhere, builds its own database from Schema.SQL.
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


def add_finding(ip, severity, title, session="s1", dismissed=0,
                entity_type="ip", when="2026-09-14T10:00:00"):
    with me._get_conn() as conn:
        conn.execute(
            "INSERT INTO findings (session_id, severity, entity_type, "
            "entity_value, title, dismissed, found_at) VALUES (?,?,?,?,?,?,?)",
            (session, severity, entity_type, ip, title, dismissed, when))


# THE SHAPE THAT MAKES THE BUG VISIBLE, and it is the owner's own database in
# miniature: one noisy detection repeated hundreds of times, and the thing
# that actually matters sitting behind it.
#
# 600 low findings on chatty addresses, then ONE critical on 203.0.113.66.
# 600 is past MAX_QUERY_LIMIT, so under the old read the critical was never in
# the dictionary and that address drew as ordinary traffic.
for i in range(600):
    add_finding(f"198.51.100.{i % 254}", "low", f"beaconing {i}",
                when=f"2026-09-14T09:{i % 60:02d}:00")
add_finding("203.0.113.66", "critical", "C2 callback",
            when="2026-09-14T08:00:00")


print("\n[0] THE BUG, PROVEN RATHER THAN ASSUMED. The old read is rebuilt")
print("    here exactly as it was and run against the same rows.")

RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
old_flagged = {}
for f in me.query_findings(session_id="s1", entity_type="ip", limit=500):
    ip = f.get("entity_value")
    sev = f.get("severity") or "low"
    if ip and RANK.get(sev, 0) >= RANK.get(
            old_flagged.get(ip, {}).get("severity", "info"), 0):
        old_flagged[ip] = {"severity": sev, "title": f.get("title") or ""}

check("the old read stopped at the cap", len(old_flagged) <= 500, True)
check("and the critical address was NOT in it",
      "203.0.113.66" in old_flagged, False)
check("so the map would have drawn it with no severity at all",
      old_flagged.get("203.0.113.66"), None)


print("\n[1] FAILURE CASE. The aggregate has to find it, cap or no cap.")

flagged = me.worst_finding_by_entity("ip", session_id="s1")
check("the critical address is there", "203.0.113.66" in flagged, True)
check("with its severity", flagged["203.0.113.66"]["severity"], "critical")
check("and its title", flagged["203.0.113.66"]["title"], "C2 callback")
# One row per DISTINCT address, and the row count it was built from is past
# the cap. That is the property that matters: the number of FINDINGS can be
# anything and the answer still has every address in it.
with me._get_conn() as conn:
    total_findings = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE entity_type='ip'").fetchone()[0]
    distinct_ips = conn.execute(
        "SELECT COUNT(DISTINCT entity_value) FROM findings "
        "WHERE entity_type='ip'").fetchone()[0]
check("there are more findings than the old cap allowed",
      total_findings > me.MAX_QUERY_LIMIT, True)
check("and the aggregate returns one row per address", len(flagged), distinct_ips)


print("\n[2] FAILURE CASE. The WORST severity per address, not an arbitrary")
print("    one. A medium sitting on top of a critical is the same lie.")

add_finding("203.0.113.66", "low", "noisy follow up",
            when="2026-09-14T23:59:00")
add_finding("203.0.113.66", "medium", "another one",
            when="2026-09-14T23:58:00")
again = me.worst_finding_by_entity("ip", session_id="s1")
check("newer, lower rows do not displace it",
      again["203.0.113.66"]["severity"], "critical")
check("and the title still belongs to the worst row",
      again["203.0.113.66"]["title"], "C2 callback")


print("\n[3] FAILURE CASE. A dismissed finding must not colour the map, and")
print("    a finding of another entity type must not either.")

add_finding("203.0.113.77", "critical", "dismissed one", dismissed=1)
add_finding("203.0.113.88", "critical", "about a process",
            entity_type="process")
third = me.worst_finding_by_entity("ip", session_id="s1")
check("a dismissed row is not on the map", "203.0.113.77" in third, False)
check("a process finding is not on the ip map", "203.0.113.88" in third, False)
check("but asking for processes finds it",
      me.worst_finding_by_entity("process", session_id="s1")
      .get("203.0.113.88", {}).get("severity"), "critical")


print("\n[4] FAILURE CASE. A read that FAILED must not come back as an empty")
print("    map, because empty means 'nothing is flagged'. Rule two.")

_real = me._get_conn


class _Broken:
    def __enter__(self):
        raise sqlite3.OperationalError("no such table: findings")

    def __exit__(self, *a):
        return False


me._get_conn = lambda *a, **k: _Broken()
raised = None
try:
    me.worst_finding_by_entity("ip", session_id="s1")
except sqlite3.Error as e:
    raised = str(e)
finally:
    me._get_conn = _real
check("it raises rather than returning {}", raised is not None, True)
check("and names what went wrong", "no such table" in (raised or ""), True)


print("\n[5] and BOTH copies of the map catch that and say so on the page.")

def strip_comments(text):
    """Code only. The rule is 'no capped CALL', not 'never say the words'."""
    out = []
    for line in text.splitlines():
        cut = line.find("#")
        out.append(line if cut < 0 else line[:cut])
    return "\n".join(out)


def _fn_body(text, opener):
    """
    A function's text, from its `def` to the next top-level def/class/route.

    EXISTS BECAUSE A CHARACTER WINDOW LIES. Two checks in this file and two in
    test_query_totals.py used `text.split("def foo")[1][:N]`, and that lesson
    has now been paid for three times -- LOOP-2 in test_sensor_hardening, PROC-2
    in test_process_inspection, and here. A window that is too small fails
    loudly; one that is merely big enough silently stops asserting the half
    past the cut while still printing PASS on the half before it. A function's
    own end cannot drift.
    """
    import re
    if opener not in text:
        return ""
    tail = text.split(opener)[1]
    end = re.search(r"\n(?:def |class |@app\.route|@require_api_key)", tail)
    return tail[:end.start()] if end else tail


# The stripper is self-tested, so this section cannot pass for the wrong
# reason. Same trap as test_capability_shim [7] hit on 2026-09-13, where a new
# COMMENT tripped a ban on a string.
check("(the comment stripper works)",
      strip_comments("code()  # query_findings(limit=500)").strip(), "code()")

reg = (ROOT / "core" / "tool_registry.py").read_text(encoding="utf-8")
# BOUNDED BY THE FUNCTION'S OWN END, not by a character count. This line used
# to say [:12000] and it failed when the function grew past it -- TWICE, and
# both times the check had silently stopped asserting the second half of what
# it claimed to test while still printing PASS on the first. LOOP-2 and PROC-2
# are the same defect in two other files. A window that is too small fails
# loudly; a window that is merely large enough stops testing without saying so,
# which is how this class survives.
tm = strip_comments(_fn_body(reg, "def _query_threat_map"))
check("the window really holds the whole function",
      "attribution" in tm, True)
check("the model's map uses the aggregate",
      'worst_finding_by_entity' in tm and 'worst_finding_by_entity_with_rule' in tm,
      True)
check("and no longer reads a capped finding list",
      'entity_type="ip", limit=500' in tm, False)
check("it catches a failed read", "severity_error = str(e)" in tm, True)
check("it reports which it got", '"severity_read": severity_error is None' in tm, True)
check("and says in words that nothing was checked",
      "NOTHING HERE" in tm and "WAS CHECKED" in tm, True)

routes = strip_comments(
    (ROOT / "api" / "routes.py").read_text(encoding="utf-8"))
check("the dashboard map uses the same aggregate",
      "worst_finding_by_entity" in routes, True)
check("and it has stopped reading a capped list too",
      'entity_type="ip", limit=500' in routes, False)
check("and the route reports whether the severities were read",
      '"severity_read":' in routes, True)


print("\n[6] HAPPY PATH. A small, ordinary database still colours correctly.")

_t2 = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_t2.close()
me.DB_PATH = _t2.name
_c2 = sqlite3.connect(me.DB_PATH)
_c2.executescript(SCHEMA)
_c2.commit()
_c2.close()

add_finding("8.8.8.8", "medium", "odd resolver traffic", session="s2")
small = me.worst_finding_by_entity("ip", session_id="s2")
check("one address, one row", len(small), 1)
check("with the right severity", small["8.8.8.8"]["severity"], "medium")
check("and an address with nothing against it is simply absent",
      "1.1.1.1" in small, False)
check("a session with nothing in it comes back empty rather than raising",
      me.worst_finding_by_entity("ip", session_id="nosuch"), {})


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
