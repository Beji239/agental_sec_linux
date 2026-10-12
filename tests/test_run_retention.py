"""
tests/test_run_retention.py, the wake-up list on the Agents tab.

Wake-up lines older than a week are deleted like the reports, each delete is
journalled so the tamper check reads it as housekeeping, a ticked line is
dismissed (hidden, not deleted) and can be restored, and the dismissal
columns stay outside the row seal. Runs on a scratch database.
"""
import pathlib
import sqlite3
import sys
import tempfile
from datetime import timedelta

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


tmp = pathlib.Path(tempfile.mkdtemp(prefix="runret_"))
DB = tmp / "t.db"
DB.write_text("")
sqlite3.connect(DB).executescript(
    (ROOT / "Schema.SQL").read_text(encoding="utf-8"))

from core import memory_engine as me            # noqa: E402
me.DB_PATH = DB
from core import migrations                     # noqa: E402
migrations.run_migrations(DB)
from core import duty, integrity                # noqa: E402

cols = {r[1] for r in sqlite3.connect(DB).execute("PRAGMA table_info(duty_run)")}
check("duty_run has the dismissal columns",
      {"dismissed_at", "dismissed_by"} <= cols, True)
spec = integrity.SEALED_TABLES["duty_run"]
check("they stay outside the seal",
      {"dismissed_at", "dismissed_by"} <= set(spec["excluded"]), True)
check("and every column is either sealed or excluded",
      set(spec["columns"]) | set(spec["excluded"]) | {spec["key"]}, cols)

now = duty._now()
ids = []
for days_ago in (10, 9, 8, 2, 1, 0):
    ids.append(duty._record_run("s", "regular", "idle", detail="t",
                                at=now - timedelta(days=days_ago, minutes=5)))

print("\nthe week")
check("three lines are older than a week", duty.expire_old_runs(), 3)
left = [r[0] for r in sqlite3.connect(DB).execute(
    "SELECT id FROM duty_run ORDER BY id")]
check("the newer three stay", left, ids[3:])
journal = sqlite3.connect(DB).execute(
    "SELECT COUNT(*) FROM integrity_journal WHERE operation = "
    "'agent_run_expired'").fetchone()[0]
check("each delete is journalled", journal, 3)
v = integrity.verify_sealed_rows(DB)
run_tab = (v.get("tables") or v.get("by_table") or {}).get("duty_run", {})
check("the tamper check reads them as housekeeping",
      (run_tab.get("deleted"), run_tab.get("deleted_expected")), (0, 3))
check("a new report runs the same delete",
      "expire_old_runs(days)" in (ROOT / "core" / "duty.py").read_text(), True)

print("\ndismissing")
out = duty.dismiss_runs([ids[3], ids[4]])
check("two ticked lines are dismissed", out["changed"], 2)
check("the list hides them", [r["id"] for r in duty.query_runs()], [ids[5]])
check("Show dismissed lists them",
      sorted(r["id"] for r in duty.query_runs(dismissed=True)),
      [ids[3], ids[4]])
check("the summary counts them", duty.summary().get("dismissed_runs"), 2)
check("nothing was deleted", sqlite3.connect(DB).execute(
    "SELECT COUNT(*) FROM duty_run").fetchone()[0], 3)
v = integrity.verify_sealed_rows(DB)
run_tab = (v.get("tables") or v.get("by_table") or {}).get("duty_run", {})
check("dismissing does not break a seal", run_tab.get("edited"), 0)
check("restore brings one back",
      duty.dismiss_runs([ids[3]], restore=True)["changed"], 1)
try:
    duty.dismiss_runs([])
    check("an empty tick list is refused", False, True)
except duty.BadDutyInput:
    check("an empty tick list is refused", True, True)

print("\nthe API and the page")
from api.server import create_app, allowed_hosts   # noqa: E402
KEY = "0" * 64
app = create_app({"flask": {"host": "127.0.0.1", "port": 5000}}, {}, "t",
                 api_key=KEY)
app.config["AGENTAL_ALLOWED_HOSTS"] = allowed_hosts({"flask": {"host": "127.0.0.1"}})
web = app.test_client()
H = {"X-API-Key": KEY}
r = web.post("/api/agents/runs/dismiss", headers=H, json={"run_ids": [ids[5]]})
check("the route dismisses", (r.status_code, r.get_json().get("changed")), (200, 1))
got = web.get("/api/agents?runs_show=dismissed", headers=H).get_json()
check("and the page can ask for the dismissed ones",
      sorted(x["id"] for x in got["runs"]), [ids[4], ids[5]])
check("an empty request is a 400", web.post(
    "/api/agents/runs/dismiss", headers=H, json={}).status_code, 400)
ui = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check("each wake-up line has a tick box and the controls exist",
      all(x in ui for x in ('class="run-tick"', "dismissTickedRuns()",
                            "/api/agents/runs/dismiss", "agent-runs-dismissed",
                            "restoreRun(", "runs_show=dismissed")), True)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
