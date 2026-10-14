"""
tests/test_rule_trials.py, a rule fix tried for two weeks.

On a scratch database: with no trial a listed file host still raises
FED-1002; once the trial is on it is held back and counted, while a listed
name off the shared hosts still fires. Before and after are counted from the
incidents and their verdicts, the self-check runs on the feed table, and
keeping or undoing the fix is journalled.
"""
import pathlib
import sys
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
db = _isolate_db.isolate()

from core import incident  # noqa: E402
from core import memory_engine as me  # noqa: E402
from core import migrations  # noqa: E402
from core import rule_trials as rt  # noqa: E402
from tools import feed_matcher as fm  # noqa: E402

migrations.run_migrations(db)

failures = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        failures.append(label)
        print(f"        {detail}")


NOW = datetime.now(timezone.utc).replace(microsecond=0)
_qid = [0]


def feed(*rows):
    with me._get_conn() as conn:
        for name, family in rows:
            conn.execute(
                "INSERT INTO threat_feed (indicator, indicator_type, feed, "
                "malware_family, first_added, last_refreshed) VALUES "
                "(?, 'domain', 'threatfox', ?, ?, ?)",
                (name, family, rt._iso(NOW), rt._iso(NOW)))
        conn.commit()


def lookups(*pairs):
    """Resolver rows, then one matching pass over just these."""
    with me._get_conn() as conn:
        start = conn.execute("SELECT COALESCE(MAX(id), 0) FROM dns_queries"
                             ).fetchone()[0]
        for client, name in pairs:
            _qid[0] += 1
            conn.execute(
                "INSERT INTO dns_queries (queried_at, client_ip, domain, "
                "source, source_row_id) VALUES (?, ?, ?, 'test', ?)",
                (rt._sql(NOW), client, name, f"q{_qid[0]}"))
        conn.commit()
        return fm._check_dns_domains(conn, "t", start, False)


def resolve_open():
    """A fresh finding needs the last one closed, as an incident would be."""
    with me._get_conn() as conn:
        conn.execute("UPDATE findings SET dismissed = 1")
        conn.commit()


feed(("cdn.jsdelivr.net", "ClearFake"), ("github.com", "Overlord RAT"),
     ("bad.example", "Emotet"))

print("Matching names")
check("a listed file host is a file host", rt.is_file_host("cdn.jsdelivr.net"))
check("a name under one is too", rt.is_file_host("alive.github.com"))
check("a look-alike is not", not rt.is_file_host("github.com.evil.example"))
check("FED-1001 addresses are never held",
      not rt.would_hold("FED-1001", "cdn.jsdelivr.net"))

print("\nNo trial: alarms as before")
n = lookups(("192.0.2.20", "cdn.jsdelivr.net"))
check("the file host still raises FED-1002", n == 1, n)

print("\nThe fix proposed from a false alarm")
with me._get_conn() as conn:
    cur = conn.execute(
        "INSERT INTO incident (incident_key, detection_id, entity_type, "
        "entity_value, severity, title, first_seen_at, last_seen_at, status, "
        "status_at, status_by) VALUES ('FED-1002:192.0.2.20', 'FED-1002', "
        "'ip', '192.0.2.20', 'high', 'Listed domain', ?, ?, 'new', ?, "
        "'watcher')", (rt._sql(NOW), rt._sql(NOW), rt._sql(NOW)))
    conn.commit()
    inc = cur.lastrowid
ov = rt.overview(now=NOW + timedelta(minutes=1))
t = ov["trials"][0]
check("without a verdict it is not proposed", not t["proposed"], t["sentence"])
check("the replay says the fix would hold it back", t["before_held"] == 1, t)
incident.set_verdict(inc, "false_alarm")
t = rt.overview(now=NOW + timedelta(minutes=1))["trials"][0]
check("marked false, it is proposed", t["proposed"] and
      t["sentence"].startswith("Worth a trial"), t["sentence"])
check("the self-check finds a listed name off the shared hosts",
      t["self_check"].get("still_matches") and
      t["self_check"]["listed"] == "bad.example", t["self_check"])

print("\nThe trial")
time.sleep(1.1)
START = datetime.now(timezone.utc).replace(microsecond=0)
r = rt.start("fed_file_hosts", now=START)
check("it starts", r["success"], r)
check("not twice", not rt.start("fed_file_hosts")["success"])
check("an unknown fix is refused", not rt.start("nope")["success"])
resolve_open()
n = lookups(("192.0.2.20", "cdn.jsdelivr.net"),
            ("192.0.2.21", "alive.github.com"))
check("file hosts are held back", n == 0, n)
n = lookups(("192.0.2.22", "bad.example"))
check("a listed name off the shared hosts still fires", n == 1, n)
later = START + timedelta(days=3, minutes=1)
t = rt.overview(now=later)["trials"][0]
check("held back hits are counted", t["held_total"] == 2, t)
check("and named", set(t["held_names"]) == {"cdn.jsdelivr.net", "github.com"},
      t["held_names"])
check("the real hit counts after the start", t["after_total"] == 1, t)
check("15 day slots, the future ones empty",
      len(t["after"]) == rt.TRIAL_DAYS + 1 and t["after"][-1]["future"]
      and not t["after"][-1]["dots"], t["after"][-1])
check("the sentence carries the day and the numbers",
      t["sentence"].startswith("Day 4 of 14") and "2 hits held back"
      in t["sentence"], t["sentence"])
t = rt.overview(now=START + timedelta(days=15))["trials"][0]
check("at the end it asks to keep or undo", t["over"]
      and t["sentence"].endswith("Keep the fix or undo it."), t["sentence"])

print("\nKeep, then undo")
check("keep", rt.end("fed_file_hosts", keep=True)["success"])
check("kept twice is refused", not rt.end("fed_file_hosts", keep=True)["success"])
resolve_open()
check("a kept fix still holds",
      lookups(("192.0.2.20", "cdn.jsdelivr.net")) == 0)
check("undo", rt.end("fed_file_hosts", keep=False)["success"])
resolve_open()
check("undone, the file host raises again",
      lookups(("192.0.2.20", "cdn.jsdelivr.net")) == 1)
check("nothing left to end", not rt.end("fed_file_hosts", keep=False)["success"])
with me._get_conn() as conn:
    ops = [r[0] for r in conn.execute(
        "SELECT operation FROM integrity_journal WHERE table_name = "
        "'rule_trial' ORDER BY id")]
check("start and both ends are journalled",
      ops == ["rule_trial_started", "rule_trial_ended", "rule_trial_ended"],
      ops)

print("\nA broken store lets the alarm through")
real = rt.holds_back
rt.holds_back = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
check("the matcher keeps the alarm", not fm._held_back("FED-1002",
                                                      "cdn.jsdelivr.net", "x"))
rt.holds_back = real

print(f"\n{'FAILED' if failures else 'ALL PASSED'}"
      f"{f': {len(failures)} check(s)' if failures else ''}")
sys.exit(1 if failures else 0)
