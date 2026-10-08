"""
tests/test_report_expiry.py, agent reports are kept one week and the list
shows the current run.

The owner's rule (2026-10-08): reports leave the database after a week, and
the Agents tab shows this run's reports unless earlier runs are asked for.

Run it directly: python tests/test_report_expiry.py
"""
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


tmp = pathlib.Path(tempfile.mkdtemp(prefix="expiry_"))
DB = tmp / "t.db"
DB.write_text("")
sqlite3.connect(DB).executescript(
    (ROOT / "Schema.SQL").read_text(encoding="utf-8"))

from core import memory_engine as me            # noqa: E402
me.DB_PATH = DB
from core import migrations                     # noqa: E402
migrations.run_migrations(DB)
from core import duty, integrity                # noqa: E402


def _report(session, body):
    return duty.write_report(
        session, "regular", "verify", body=body, hypothesis="h",
        evidence="e", verdict="no_action", saw="what it saw",
        coverage={"complete": True, "note": "everything readable"})["report_id"]


def _age(report_id, days):
    with sqlite3.connect(DB) as c:
        c.execute("UPDATE duty_report SET created_at = datetime('now', ?) "
                  "WHERE id = ?", (f"-{days} days", report_id))


def _ids():
    with sqlite3.connect(DB) as c:
        return sorted(r[0] for r in c.execute("SELECT id FROM duty_report"))


print("\n[1] the list shows one run, or every run of the week")
old_run = _report("run-a", "from an earlier run")
this_run = _report("run-b", "from this run")
check("this run only", [r["id"] for r in duty.query_reports(session_id="run-b")],
      [this_run])
check("every run", [r["id"] for r in duty.query_reports()], [this_run, old_run])

print("\n[2] a report past the week is not listed, even before the delete")
stale = _report("run-a", "eight days old")
edge = _report("run-a", "six days old")
_age(stale, 8)
_age(edge, 6)
check("not in the list", stale in [r["id"] for r in duty.query_reports()], False)
check("still readable by id until deleted",
      [r["id"] for r in duty.query_reports(report_id=stale)], [stale])

print("\n[3] the delete removes only what is older than a week")
check("one report deleted", duty.expire_old_reports(), 1)
check("the old one is gone, the rest stay", _ids(),
      sorted([old_run, this_run, edge]))
check("a second pass deletes nothing", duty.expire_old_reports(), 0)

print("\n[4] the delete is journalled, so the tamper check does not cry wolf")
with sqlite3.connect(DB) as c:
    n = c.execute("SELECT COUNT(*) FROM integrity_journal WHERE operation = "
                  "'agent_report_expired' AND row_ref = ?",
                  (str(stale),)).fetchone()[0]
check("one expiry entry for the deleted report", n, 1)
v = integrity.verify_sealed_rows(db_path=DB)
check("no unexplained deletes", v["deleted_rows"], 0)
check("the expiry is reported as expected", v.get("deleted_expected"), 1)
check("the chain is still intact", integrity.verify_chain(db_path=DB)["status"],
      "intact")

print("\n[5] a delete the app did not journal is still caught")
with sqlite3.connect(DB) as c:
    c.execute("DELETE FROM duty_report WHERE id = ?", (edge,))
check("a foreign delete is counted",
      integrity.verify_sealed_rows(db_path=DB)["deleted_rows"], 1)

print("\n[6] writing a report runs the delete too")
_age(old_run, 9)
_report("run-b", "a new report")
check("the nine day old report went with the write", old_run in _ids(), False)

print("\n[7] the page and the route are wired to the run scope")
page = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
routes = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")
main = (ROOT / "main.py").read_text(encoding="utf-8")
check("the page has the earlier runs toggle", 'id="agent-show-earlier"' in page,
      True)
check("and asks for runs=all with it", "'runs=all'" in page, True)
check("the route filters by session", "session_id=sid" in routes, True)
check("dismiss all sends the listed ids, not all_open",
      "report_ids: ids, note: 'dismiss all" in page, True)
check("boot runs the delete", "expire_old_reports()" in main, True)

print("\n" + "=" * 62)
if fails:
    print(f"{len(fails)} FAILED: " + ", ".join(fails))
    sys.exit(1)
print("All report expiry checks passed.")
