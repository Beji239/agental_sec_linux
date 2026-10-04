"""
tests/test_rollup_reads_everything.py, the baseline was built from a sample.

FOUND 2026-09-13, and the owner found the shape of it before I did.

The owner said the model is the analyst, so a model that reasons from fifty rows out
of fourteen thousand has no real information about the network. The owner was talking
about the model's view. Checking that led somewhere worse, in Python, nowhere
near the model:

run_rollup merged session observations into behavioral_baseline by calling
query_behavioral_session(limit=500). _validate_limit clamps every limit to
MAX_QUERY_LIMIT, which is 500. So on any session producing more than 500
observations, the baseline, the thing this app calls NORMAL and decides
suppression from, was built from the newest 500. The rest were never merged.
Not delayed. Dropped.

And it was worst exactly where it matters most, because the sessions that
produce more than 500 observations are the busy ones.

Nothing said so. The rollup logged how many entities it processed and that
number read like the whole thing, which is the same disease as everything
else found this week: a real number sitting next to a partial one with
nothing connecting them.

THE RULE THIS RESTORES: a cap belongs where there is a context window on the
other end of it. Python reading its own table to compute an aggregate is not
that, and the two were being served by one function.

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

BUSY = 1300          # a session with more observations than the old cap
SESSION = "busy-session"


def seed(n, session=SESSION):
    with me._get_conn() as conn:
        for i in range(n):
            conn.execute(
                "INSERT INTO behavioral_session (session_id, entity_type, "
                "entity_value, behavior_key, behavior_value, observed_at) "
                "VALUES (?,'ip',?,'port_set',?,?)",
                (session, f"10.0.0.{i % 250}", str(443 + (i % 7)),
                 f"2026-09-13T{(i // 60) % 24:02d}:{i % 60:02d}:00"))


print("\n[1] THE BUG. The capped path cannot see a busy session.")
seed(BUSY)

capped = me.query_behavioral_session(session_id=SESSION, limit=500)
check("the session really has more than the cap",
      me.query_behavioral_session(session_id=SESSION, limit=500,
                                  with_total=True)["matching_total"], BUSY)
check("but the capped read returns only the cap", capped["count"], 500)
# The number the old rollup would have merged, against the number that exists.
check("so the old rollup merged this many", capped["count"], 500)
check("out of this many", BUSY, 1300)
check("and it dropped this many silently", BUSY - capped["count"], 800)

# The cap cannot be raised past it either, which is what made this invisible.
# Asking for everything and getting 500 looks identical to there being 500.
asked_for_all = me.query_behavioral_session(session_id=SESSION, limit=100000)
check("asking for 100000 still returns 500, because of MAX_QUERY_LIMIT",
      asked_for_all["count"], 500)
check("and MAX_QUERY_LIMIT is what does it", me.MAX_QUERY_LIMIT, 500)


print("\n[2] THE FIX. The rollup's own read has no cap.")
every = me.all_session_observations(SESSION)
check("it returns every observation", len(every), BUSY)
check("not the cap", len(every) != 500, True)

# Oldest first. The old path handed the rollup the NEWEST 500 in reverse, and
# a baseline reads forward in time.
check("ordered oldest first",
      every[0]["observed_at"] < every[-1]["observed_at"], True)

# Paging has to be right at the boundaries or it drops or repeats a row.
ids = [r["id"] for r in every]
check("no row is repeated", len(ids), len(set(ids)))
check("no row is skipped, ids are in order", ids == sorted(ids), True)
check("and it covers the whole id range",
      (ids[0], ids[-1]), (min(ids), max(ids)))


print("\n[3] the page boundary itself, where an off by one would live")
# PAGE is 1000 inside the function, so these sizes sit either side of it.
for n in (999, 1000, 1001, 2000, 2001):
    sess = f"boundary-{n}"
    seed(n, session=sess)
    check(f"a session of exactly {n} comes back whole",
          len(me.all_session_observations(sess)), n)

check("a session with nothing in it returns an empty list, not an error",
      me.all_session_observations("no-such-session"), [])


print("\n[4] withdrawn observations stay out, the same as before")
# supersede exists so a wrong observation can be withdrawn. The uncapped read
# must not quietly resurrect them into the baseline.
with me._get_conn() as conn:
    conn.execute("UPDATE behavioral_session SET superseded_by = 'x' "
                 "WHERE session_id = ? AND id % 2 = 0", (SESSION,))
    withdrawn = conn.execute(
        "SELECT COUNT(*) FROM behavioral_session WHERE session_id = ? "
        "AND superseded_by IS NOT NULL", (SESSION,)).fetchone()[0]

live = me.all_session_observations(SESSION)
check("some were withdrawn", withdrawn > 0, True)
check("and they are not in the default read", len(live), BUSY - withdrawn)
check("but they are still there when asked for",
      len(me.all_session_observations(SESSION, include_superseded=True)), BUSY)


print("\n[5] the rollup asks for the uncapped one, and says so")
src = (ROOT / "core" / "rollup_engine.py").read_text(encoding="utf-8")
check("the rollup calls the uncapped read",
      "me.all_session_observations(session_id)" in src, True)
check("and no longer calls the capped one",
      "query_behavioral_session(session_id=session_id, limit=500)" in src, False)
check("and logs the real number it read",
      "all of them, no cap" in src, True)
# The reason has to survive in the file, or somebody optimises it back.
#
# My first version of this check looked for a phrase that WRAPS across two
# comment lines, so it could never have matched however right the file was.
# The comment markers and the wrapping are stripped before looking, which is
# the same lesson as the [7] stripper in test_capability_shim: a source check
# has to read the words, not the layout.
prose = " ".join(l.strip().lstrip("#").strip() for l in src.splitlines())
check("and the file explains why a cap was wrong here",
      "context window on the other end of it" in prose, True)
check("and says plainly what was dropped",
      "the rest were never merged at all" in prose, True)

eng = (ROOT / "core" / "memory_engine.py").read_text(encoding="utf-8")
check("and the engine says the model facing path stays capped on purpose",
      "THE MODEL FACING PATH STAYS CAPPED" in eng, True)


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
