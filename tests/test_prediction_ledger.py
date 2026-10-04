"""
tests/test_prediction_ledger.py, can this app tell the model it was wrong.

The failure cases come FIRST in this file, on purpose. Five bugs in one night
on 2026-09-13 were all the same shape: code that works on the happy path and
lies on the failure path. A search that says "it is not there" when it could
not search. So the first thing tested here is the case where the checker
CANNOT LOOK, because that is the case that decides whether this feature is
worth having.

The specific lie this feature could tell: "no traffic from the TV between 2am
and 6am" is trivially true if the sniffer was off at 3am. Score that as a hit
and the hit rate is built out of our own blind spots, which is worse than no
hit rate at all, because somebody would believe it.

What is tested, in order:

  1. A claim nothing can check is refused at write time.
  2. A window with no capture in it is unverifiable. Never a hit.
  3. A device this sensor has never seen is unverifiable. Never a hit.
  4. A presence claim with no successful sweep is unverifiable.
  5. Only then, the happy path: a real hit and a real miss.
  6. The three outcomes are never summed, and the hit rate is over checked
     predictions only.
  7. The model has no way to write an outcome.
  8. Checking a prediction writes nothing to the tables that decide alerts.

Run it directly: python tests/test_prediction_ledger.py
"""
import pathlib
import sys
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import memory_engine as me                  # noqa: E402
from core import predictions as pr                    # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got):
    check(label, bool(got), True)


SID = "test-session"
NOW = datetime(2026, 9, 14, 12, 0, 0, tzinfo=timezone.utc)


def ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def file_row(kind, value, start, end, threshold=None, detail=None,
             statement="test claim"):
    """Insert a prediction directly, so the window can be controlled."""
    with me._get_conn() as c:
        cur = c.execute("""
            INSERT INTO prediction
                (session_id, made_at, horizon_ends_at, claim_kind,
                 entity_type, entity_value, threshold, detail, statement)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (SID, ts(start), ts(end), kind,
              "ip" if kind not in ("no_finding", "finding_expected") else "ip",
              value, threshold, detail, statement))
        return cur.lastrowid


def packets(ip, at, n=1, session="cap-1"):
    with me._get_conn() as c:
        for i in range(n):
            c.execute("""INSERT INTO packets
                         (session_id, captured_at, src_ip, dst_ip, protocol)
                         VALUES (?,?,?,?, 'TCP')""",
                      (session, ts(at + timedelta(seconds=i)), ip, "192.0.2.1"))


def outcome_of(pid):
    with me._get_conn() as c:
        row = c.execute("SELECT outcome, outcome_reason FROM prediction "
                        "WHERE id = ?", (pid,)).fetchone()
        return row["outcome"], row["outcome_reason"]


print("\n[1] FAILURE FIRST: a claim nothing can check is refused")
# A prediction that cannot be graded is not a prediction. The quiet failure
# here would be a ledger full of untestable sentences that never get an
# outcome, making the pending count look like work in progress.

r = pr.write_prediction(SID, "the vibes will be off", "ip", "192.0.2.5",
                        "something feels wrong", horizon_hours=2)
check("an unknown claim kind is refused", r["success"], False)
check_true("and it lists the ones that work", "no_traffic" in r["error"])

r = pr.write_prediction(SID, "no_traffic", "ip", "192.0.2.5",
                        "nothing from the TV tonight")
check("no horizon is refused", r["success"], False)
check_true("and it says why a deadline is required",
           "never be checked" in r["error"])

r = pr.write_prediction(SID, "no_traffic", "ip", "192.0.2.5", "",
                        horizon_hours=2)
check("no statement is refused", r["success"], False)

r = pr.write_prediction(SID, "traffic_above", "ip", "192.0.2.5",
                        "it will be busy", horizon_hours=2)
check("traffic_above with no threshold is refused", r["success"], False)

r = pr.write_prediction(SID, "no_traffic", "process", "chrome.exe",
                        "quiet", horizon_hours=2)
check("a traffic claim about a process is refused", r["success"], False)
check_true("and it says what is checkable", "entity_type must be 'ip'"
           in r["error"])

r = pr.write_prediction(SID, "no_traffic", "ip", "192.0.2.5", "quiet",
                        horizon_minutes=1)
check("a horizon shorter than the check cycle is refused", r["success"], False)

r = pr.write_prediction(SID, "no_traffic", "ip", "192.0.2.5", "quiet",
                        horizon_hours=24 * 400)
check("a horizon past retention is refused", r["success"], False)
check_true("and it says the answer would be unverifiable anyway",
           "unverifiable" in r["error"])

r = pr.write_prediction(SID, "no_traffic", "ip", "192.0.2.5",
                        "no traffic from the TV overnight", horizon_hours=6,
                        reasoning="it has been dark since Tuesday")
check("a checkable claim is accepted", r["success"], True)
check_true("and it says the model does not grade it",
           "you do not get to grade it" in r["note"])


print("\n[2] THE ONE THAT MATTERS: no capture in the window is not a hit")
# This is the whole reason the third outcome exists. Zero packets stored
# across the window is exactly what an off sniffer looks like, and from here
# it is indistinguishable from a genuinely silent network.

start = NOW - timedelta(hours=6)
end = NOW - timedelta(hours=1)
pid = file_row("no_traffic", "192.0.2.24", start, end,
               statement="the TV stays quiet")
res = pr.check_due(now=NOW)
o, why = outcome_of(pid)
check("scored unverifiable, NOT hit", o, "unverifiable")
check_true("and the reason names the missing capture",
           "no packets are stored" in why or "below the" in why)
check("the run counted it as unverifiable", res["unverifiable"], 1)
check("and did not count it as a hit", res["hit"], 0)


print("\n[3] a device this sensor has never seen is not a hit either")
# A host-position sensor cannot observe two other devices talking to each
# other. Silence from a games console is a fact about our vantage point.
# Capture is running fine here, so this is the OTHER blindness, not coverage.

start = NOW - timedelta(hours=4)
end = NOW - timedelta(hours=1)
# Plenty of capture across the window, from some other address entirely.
packets("192.0.2.29", start + timedelta(minutes=1), n=3)
packets("192.0.2.29", end - timedelta(minutes=1), n=3)

pid = file_row("no_traffic", "192.0.2.25", start, end,
               statement="the other TV stays quiet")
pr.check_due(now=NOW)
o, why = outcome_of(pid)
check("scored unverifiable, NOT hit", o, "unverifiable")
check_true("and it names the vantage point, not the device",
           "never produced a single packet" in why)
check_true("and points at the document that explains it",
           "SENSOR_PLACEMENT" in why)


print("\n[4] a presence claim with no sweep is nobody having knocked")
start = NOW - timedelta(hours=3)
end = NOW - timedelta(hours=1)
pid = file_row("device_absent", "192.0.2.26", start, end,
               statement="the linux box is off tonight")
pr.check_due(now=NOW)
o, why = outcome_of(pid)
check("no successful sweep means unverifiable", o, "unverifiable")
check_true("and it says nobody asked",
           "nobody having knocked" in why)

# A sweep that FAILED is not a denominator either.
with me._get_conn() as c:
    c.execute("""INSERT INTO presence_sweep
                 (session_id, swept_at, method, outcome, detail)
                 VALUES (?,?,'icmp+arp','failed','no raw socket')""",
              (SID, ts(start + timedelta(minutes=30))))
pid = file_row("device_absent", "192.0.2.26", start, end,
               statement="the linux box is off tonight")
pr.check_due(now=NOW)
o, _ = outcome_of(pid)
check("a FAILED sweep is still not a denominator", o, "unverifiable")


print("\n[5] only now, the happy path")
start = NOW - timedelta(hours=4)
end = NOW - timedelta(hours=1)

# 192.0.2.29 has been seen (section 3 put packets in), and the capture covers
# the window, so a genuine silence from a DIFFERENT seen address can score.
packets("192.0.2.22", NOW - timedelta(days=2), n=1, session="cap-old")
pid = file_row("no_traffic", "192.0.2.22", start, end,
               statement="99 stays quiet this evening")
pr.check_due(now=NOW)
o, why = outcome_of(pid)
check("a real silence from a seen device is a HIT", o, "hit")
check_true("and the reason carries the count", "0 packets" in why)

pid = file_row("no_traffic", "192.0.2.29", start, end,
               statement="249 stays quiet this evening")
pr.check_due(now=NOW)
o, why = outcome_of(pid)
check("traffic where none was predicted is a MISS", o, "miss")

pid = file_row("traffic_above", "192.0.2.29", start, end, threshold=100,
               statement="249 will be very busy")
pr.check_due(now=NOW)
check("a threshold claim that did not hold is a MISS", outcome_of(pid)[0], "miss")

pid = file_row("traffic_below", "192.0.2.29", start, end, threshold=100,
               statement="249 will be quiet-ish")
check_true("a threshold claim that held is a HIT",
           (pr.check_due(now=NOW), outcome_of(pid)[0] == "hit")[1])

# Findings, including the rule that a dismissal afterwards cannot rewrite it.
with me._get_conn() as c:
    c.execute("""INSERT INTO findings
                 (session_id, found_at, source, severity, entity_type,
                  entity_value, title, dismissed)
                 VALUES (?,?,'packet_sniffer','high','ip','192.0.2.11',
                         'something', 1)""",
              (SID, ts(start + timedelta(minutes=10))))
pid = file_row("no_finding", "192.0.2.11", start, end, detail="medium",
               statement="nothing will fire on 42")
pr.check_due(now=NOW)
o, why = outcome_of(pid)
check("a finding that was raised then dismissed still counts", o, "miss")

pid = file_row("finding_expected", "192.0.2.11", start, end, detail="medium",
               statement="something will fire on 42")
pr.check_due(now=NOW)
check("and the same row scores the opposite claim as a hit",
      outcome_of(pid)[0], "hit")

# Presence, with a sweep that actually ran.
with me._get_conn() as c:
    cur = c.execute("""INSERT INTO presence_sweep
                       (session_id, swept_at, method, outcome, targets, responded)
                       VALUES (?,?,'icmp+arp','ok',10,1)""",
                    (SID, ts(start + timedelta(minutes=5))))
    c.execute("""INSERT INTO presence_observation (sweep_id, ip, via)
                 VALUES (?, '192.0.2.26', 'icmp')""", (cur.lastrowid,))
pid = file_row("device_present", "192.0.2.26", start, end,
               statement="the linux box answers")
pr.check_due(now=NOW)
check("a device that answered a real sweep is a HIT", outcome_of(pid)[0], "hit")


print("\n[6] the three outcomes are never summed")
s = pr.score()
check_true("the score is available", s["available"])
check("checked is hits plus misses only", s["checked"], s["hit"] + s["miss"])
check_true("unverifiable is reported on its own", s["unverifiable"] > 0)
check_true("and is NOT in checked", s["checked"] < (
    s["hit"] + s["miss"] + s["unverifiable"]))
check("the hit rate is over checked only",
      s["hit_rate"], round(s["hit"] / s["checked"], 3))
check_true("and the reading says so in words",
           "never folded into the rate" in s["how_to_read_this"])
check_true("the blind reasons are grouped so a pattern is visible",
           len(s["why_unverifiable"]) >= 1)

# A prediction already scored is never looked at again.
before = pr.score()
again = pr.check_due(now=NOW + timedelta(hours=1))
check("re-running the checker scores nothing twice", again["checked"], 0)
check("and the counts are unchanged", pr.score()["hit"], before["hit"])


print("\n[7] the model cannot grade itself")
from core import tool_registry as tr                  # noqa: E402
names = {t["name"] for t in tr.TOOL_MANIFEST}
check_true("it can file one", "write_prediction" in names)
check_true("it can read its own record", "query_prediction_score" in names)
schema = next(t for t in tr.TOOL_MANIFEST if t["name"] == "write_prediction")
props = set(schema["input_schema"]["properties"])
check("there is no outcome field on the write tool",
      "outcome" in props, False)
check("nor observed_value", "observed_value" in props, False)
check_true("and the description says Python does the checking",
           "check" in schema["description"].lower())


print("\n[8] a prediction never reaches the tables that decide alerts")
# The wall. A guess is allowed to be wrong at no cost, and that is only safe
# while being wrong cannot touch baselines, deviations or findings.
WALLED = ("behavioral_session", "behavioral_baseline",
          "behavioral_deviation", "findings",
          # The integrity journal is in this list for a different reason. The
          # first version of predictions.py called _journal and the allow-list
          # refused it, logging a warning on every single prediction. A journal
          # warning that fires on an ordinary operation teaches people to
          # ignore journal warnings, so the calls came out. If a later change
          # decides predictions DO belong in the chain, this check is the thing
          # that will fail, and that is the moment to have the argument.
          "integrity_journal")
with me._get_conn() as c:
    before_counts = {
        t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        for t in WALLED
    }

pr.write_prediction(SID, "no_traffic", "ip", "192.0.2.22",
                    "quiet again tomorrow", horizon_minutes=20)
pr.check_due(now=NOW + timedelta(days=1))

with me._get_conn() as c:
    after_counts = {
        t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        for t in WALLED
    }
check("filing and checking wrote nothing to the alerting tables",
      after_counts, before_counts)

# And the daily cap, which exists so the model has to choose.
me.set_preference("prediction_daily_cap", "1")
r = pr.write_prediction(SID, "no_traffic", "ip", "192.0.2.22",
                        "one too many", horizon_hours=2)
check("the daily cap refuses the next one", r["success"], False)
check_true("and says what the cap is for", "worth making" in r["error"])



print("\n[9] the operator can actually see it")
# A ledger the model reads and nobody else does is a private scorecard. The
# whole argument for building this was that the person gets to watch the model
# being right and wrong over time.
UI = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check_true("there is a nav tab", 'data-page="predictions"' in UI)
check_true("and a page behind it", 'id="page-predictions"' in UI)
check_true("and something loads it",
           "if (name === 'predictions')" in UI)
check_true("the three counts are three separate tiles",
           "Could not check" in UI and "Still open" in UI)
check_true("and the hit rate says what it is over",
           "of the ${s.checked} checked" in UI)

ROUTES = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")
check_true("the ledger is served", '"/api/predictions"' in ROUTES)
check_true("so is the score", '"/api/predictions/score"' in ROUTES)

# THE IMPORTANT ONE, and the first version of this check was wrong in a way
# worth recording. It searched for the STRING "outcome =", which matches
# `outcome = request.args.get("outcome")` in the route (reading a filter) and
# `const outcome = r.outcome` in the page (reading a row). Both went red while
# neither writes anything. A check that fires on the word rather than on the
# act is noise, and noise is how a real red result gets waved through.
#
# So the check is about the WRITE. core/predictions.py is the only file in
# this project allowed to contain an UPDATE of that table. If a second one
# ever appears, this goes red and whoever added it makes the argument first.
writers = []
for path in ROOT.rglob("*.py"):
    if "__pycache__" in str(path):
        continue
    body = path.read_text(encoding="utf-8", errors="ignore")
    if "UPDATE prediction" in body and path.name != "test_prediction_ledger.py":
        writers.append(path.name)
check("exactly one file writes an outcome", writers, ["predictions.py"])

for door, text in (("the API", ROUTES), ("the page", UI)):
    check(f"{door} contains no write to the ledger",
          "UPDATE prediction" in text, False)


print("\n[10] a gap can hide an event but never invent one")
g_start = NOW - timedelta(days=5)
g_end = g_start + timedelta(hours=48)
with me._get_conn() as c:
    c.execute("""INSERT INTO findings
                 (session_id, found_at, source, severity, entity_type,
                  entity_value, title)
                 VALUES (?,?,'process_monitor','high','process','gapproc',
                         'fired while barely watched')""",
              (SID, ts(g_start + timedelta(hours=1))))


def file_proc(kind, value, detail="medium"):
    with me._get_conn() as c:
        return c.execute("""
            INSERT INTO prediction
                (session_id, made_at, horizon_ends_at, claim_kind,
                 entity_type, entity_value, detail, statement)
            VALUES (?,?,?,?, 'process', ?,?, 'gap test')
        """, (SID, ts(g_start), ts(g_end), kind, value, detail)).lastrowid


pid = file_proc("no_finding", "gapproc")
pr.check_due(now=NOW)
check("a finding seen in a mostly unwatched window is still a MISS",
      outcome_of(pid)[0], "miss")
pid = file_proc("finding_expected", "gapproc")
pr.check_due(now=NOW)
check("and the opposite claim is a HIT", outcome_of(pid)[0], "hit")
pid = file_proc("no_finding", "quietproc")
pr.check_due(now=NOW)
check("a quiet, mostly unwatched window stays unverifiable",
      outcome_of(pid)[0], "unverifiable")

# Rows scored before the fix are repaired, and only the coverage ones.
with me._get_conn() as c:
    old = c.execute("""
        INSERT INTO prediction
            (session_id, made_at, horizon_ends_at, claim_kind, entity_type,
             entity_value, detail, statement, outcome, outcome_reason)
        VALUES (?,?,?,'no_finding','process','gapproc','medium','old row',
                'unverifiable', 'the capture covered about 3% of that window,
                 which is below the 50% floor.')
    """, (SID, ts(g_start), ts(g_end))).lastrowid
    other = c.execute("""
        INSERT INTO prediction
            (session_id, made_at, horizon_ends_at, claim_kind, entity_type,
             entity_value, detail, statement, outcome, outcome_reason)
        VALUES (?,?,?,'no_finding','process','gapproc','medium','old row',
                'unverifiable', 'some other reason')
    """, (SID, ts(g_start), ts(g_end))).lastrowid
pr.recheck_unverifiable()
check("an old coverage-only unverifiable is re-scored", outcome_of(old)[0], "miss")
check("an unverifiable for another reason is left alone",
      outcome_of(other)[0], "unverifiable")

me.set_preference("prediction_daily_cap", "100")
first = pr.write_prediction(SID, "no_finding", "process", "dupproc",
                            "nothing on dupproc", horizon_hours=2,
                            detail="medium")
again = pr.write_prediction(SID, "no_finding", "process", "dupproc",
                            "nothing on dupproc", horizon_hours=2,
                            detail="medium")
check("the first claim is filed", first["success"], True)
check("the identical open claim is refused", again["success"], False)
check("and points at the one already open",
      again.get("existing_prediction_id"), first.get("prediction_id"))


print("\n" + ("ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}"))
sys.exit(1 if fails else 0)
