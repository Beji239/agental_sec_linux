"""
tests/test_runbook_search.py, a confident negative has to be earned.

WHY THIS EXISTS. On 2026-09-03 somebody asked the agent about "CVE-59822".
The runbook held CVE-2026-59822, a KEV entry with a due date twelve days
out, and query_runbook returned nothing, because "CVE-59822" is not a
substring of "CVE-2026-59822". The tool did exactly what it was written to
do and the answer was still wrong.

The typo is not the interesting part. "Not in the runbook" is a NEGATIVE, the
model says it plainly, and nobody goes and re-checks a confident negative. A
missing year in a question must not manufacture one.

So this file is mostly about what the search must NOT start doing. Widening a
lookup is easy and it pays for a rare miss with a steady stream of wrong
hits, which is the worse trade in a tool whose whole value is that its
answers can be believed.
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


tmp = tempfile.mkdtemp()
db = pathlib.Path(tmp) / "t.db"

from core import memory_engine as me            # noqa: E402
me.DB_PATH = db
conn = sqlite3.connect(db)
conn.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
conn.commit()
conn.close()
from core import migrations                     # noqa: E402
migrations.run_migrations(db)
from core import sensors as sn                  # noqa: E402
sn.register_local()

with me._get_conn() as c:
    c.execute("""INSERT INTO runbook
                 (cve_id, product, vulnerability, description, severity,
                  known_ports, source)
                 VALUES (?,?,?,?,?,?,?)""",
              ("CVE-2026-59822", "LiteLLM",
               "BerriAI LiteLLM Improper Authentication Vulnerability",
               "Auth bypass on the MCP Streamable HTTP endpoint.",
               "high", "", "cisa_kev"))
    # A near neighbour whose number CONTAINS the one above. If the search
    # ever goes loose, this is the row that shows up wrongly.
    c.execute("""INSERT INTO runbook
                 (cve_id, product, vulnerability, description, severity,
                  known_ports, source)
                 VALUES (?,?,?,?,?,?,?)""",
              ("CVE-2019-598220", "SomethingElse", "Unrelated entry",
               "A near neighbour. Its own text deliberately avoids the\n"
               "digits under test, or it would match by ordinary substring\n"
               "and prove nothing about the anchoring.", "low",
               "", "static"))
    # Port 443 lives in known_ports, to prove a bare number is untouched.
    c.execute("""INSERT INTO runbook
                 (cve_id, product, vulnerability, description, severity,
                  known_ports, source)
                 VALUES (?,?,?,?,?,?,?)""",
              ("CVE-2020-11111", "SomeWebThing", "TLS thing",
               "Test row.", "medium", "443", "static"))


def ids(term):
    return sorted(r["cve_id"] for r in me.query_runbook(search_term=term))


print("\n[1] the full identifier still works, obviously")
check("exact id", ids("CVE-2026-59822"), ["CVE-2026-59822"])


print("\n[2] THE FIX: a yearless CVE reaches the row anyway")
check("CVE-59822 finds it", ids("CVE-59822"), ["CVE-2026-59822"])
check("lowercase too", ids("cve-59822"), ["CVE-2026-59822"])
check("and with a space instead of a dash", ids("CVE 59822"), ["CVE-2026-59822"])


print("\n[3] and it does NOT drag in the neighbour whose number contains it")
# The match is anchored on the trailing digits. Loose matching would return
# CVE-2019-598220 here, and a wrong hit on a security lookup is worse than
# the miss this fix exists to remove.
check("no false neighbour", "CVE-2019-598220" in ids("CVE-59822"), False)


print("\n[4] a bare number is left alone, as it always was")
# 443 has to keep matching ports and text. If somebody ever 'improves' this
# by treating any number as a CVE fragment, this fails.
check("443 still finds the port row", "CVE-2020-11111" in ids("443"), True)
# A bare number stays a PLAIN SUBSTRING search, which means it matches both
# rows here, because "598220" contains "59822". That is not a defect and it
# is not new: it is what this tool did before the change and what a search
# box is expected to do. The point of asserting it is that the yearless-CVE
# special case must not leak out and start anchoring bare numbers too, which
# would quietly break every port and keyword search in the runbook.
check("a bare number is still an ordinary substring search",
      ids("59822"), ["CVE-2019-598220", "CVE-2026-59822"])


print("\n[5] a genuine miss is still a miss")
check("nothing invented", ids("CVE-1999-00001"), [])
check("nor for nonsense", ids("zzzz-not-a-thing"), [])

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
