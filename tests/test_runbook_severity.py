"""
tests/test_runbook_severity.py: the Runbook tab could only ever show critical.

Rows sort most severe first and the page asked for the default 20, so with
hundreds of critical entries every row on screen was critical and nothing said
it was a slice. The query now filters by severity and reports the total.
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
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


db = pathlib.Path(tempfile.mkdtemp()) / "t.db"
from core import memory_engine as me  # noqa: E402
me.DB_PATH = db
c = sqlite3.connect(db)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.commit()
c.close()
from core import migrations  # noqa: E402
migrations.run_migrations(db)

rows = [("critical", None)] * 30 + [("high", None)] * 5 + [("medium", None)] * 3 \
     + [(None, "low")] * 2 + [(None, "unknown")] * 4
with sqlite3.connect(db) as conn:
    for i, (cvss, feed) in enumerate(rows):
        conn.execute("INSERT INTO runbook (cve_id, vulnerability, severity, cvss_severity) "
                     "VALUES (?,?,?,?)", (f"CVE-2026-{9000 + i}", "SevProbe", feed or "unknown", cvss))

top = me.query_runbook(limit=20, with_total=True)
check("the default page is all critical, which is why a count is needed",
      {r["cvss_severity"] for r in top["entries"]}, {"critical"})
check("and the total says it is a slice", (top["matching_total"], top["complete"]), (44, False))
for sev, n in (("critical", 30), ("high", 5), ("medium", 3), ("low", 2), ("unrated", 4)):
    got = me.query_runbook(limit=100, with_total=True, severity=sev)
    check(f"{sev} filter", got["matching_total"], n)
check("filter combines with search",
      me.query_runbook(search_term="SevProbe", limit=100, with_total=True,
                       severity="high")["matching_total"], 5)
check("an unknown severity is ignored, not an error",
      me.query_runbook(limit=100, with_total=True, severity="bogus")["matching_total"], 44)
html = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check("the page has the severity filter and the count line",
      'id="runbook-severity"' in html and 'id="runbook-count"' in html, True)

print()
if fails:
    print(f"{len(fails)} FAILED: {fails}")
    sys.exit(1)
print("all passed")
