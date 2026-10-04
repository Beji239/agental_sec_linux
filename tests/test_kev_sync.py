"""
tests/test_kev_sync.py, a mirrored row must not read like a finding.

WHY THIS EXISTS. On 2026-09-16 somebody asked about a CISA KEV entry for
Cisco Identity Services Engine. The network it was asked about has fifteen
consumer devices on it and no Cisco hardware at all. The row was in the
runbook because the runbook mirrors the entire KEV catalogue with no
filtering, which is fine and is the design, but the row itself carried
nothing that said so:

  applies_to      NULL
  verify_hint     NULL
  entry_kind      NULL
  severity        'high', hardcoded on the way in for all ~1500 rows

So a row that knew nothing about this network looked exactly like a row that
had checked. That is the same shape as the EternalBlue-on-Windows-11 bug the
five STATIC entries were fixed for, one population over, and the fix for
those never reached the mirror.

The failure cases are first in this file, deliberately. Every one of them is
a way the code could pass a happy-path test and still lie:

  [1] a resync silently overwriting a hand-written row
  [2] a severity that was never read from anything
  [3] a scopeless row reading as though it had scope
  [4] counts reporting work that did not happen

The happy path is [5] onward and it is the easy part.
"""
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

import _isolate_db                                # noqa: E402
_isolate_db.isolate()

from core import memory_engine as me              # noqa: E402
from core import migrations                       # noqa: E402

migrations.run_migrations(me.DB_PATH)

from tools import runbook as rb                   # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got):
    check(label, bool(got), True)


def row(cve_id):
    with me._get_conn() as c:
        r = c.execute("SELECT * FROM runbook WHERE cve_id = ?", (cve_id,)).fetchone()
    return dict(r) if r else None


def feed_entry(cve_id, **over):
    """One entry shaped exactly like the real CISA feed gives it."""
    e = {
        "cveID": cve_id,
        "vendorProject": "Cisco",
        "product": "Identity Services Engine",
        "vulnerabilityName": "Cisco ISE Incorrect Use of Privileged APIs",
        "shortDescription": "Unauthenticated remote attacker can bypass the "
                            "web-based management interface.",
        "requiredAction": "Apply mitigations in accordance with vendor instructions.",
        "dateAdded": "2026-09-16",
        "dueDate": "2026-09-19",
        "knownRansomwareCampaignUse": "Unknown",
    }
    e.update(over)
    return e


def sync(entries):
    """Run the writer directly, so no test in here ever touches the network."""
    return rb.Runbook("test-session")._write_kev_rows(entries)


# FAILURE CASES FIRST

print("\n[1] FAILURE: the mirror must never overwrite a hand-written row")
# The whole reason the old code used INSERT OR IGNORE was to protect these.
# Moving to an upsert is the fix for CISA corrections not propagating, and it
# is also the exact change that could clobber a static entry by accident. If
# this ever fails, the guard on the DO UPDATE is gone and the five priors are
# being rewritten by a feed.
rb.Runbook("test-session")._load_static_entries()
before = row("STATIC-001")
check_true("static row is loaded to begin with", before)

hostile = feed_entry("STATIC-001",
                     vendorProject="NotMicrosoft",
                     product="NotSMB",
                     vulnerabilityName="A feed row wearing a static id",
                     knownRansomwareCampaignUse="Known")
res = sync([hostile])
after = row("STATIC-001")

check("static row keeps its source",        after["source"],        "static")
check("static row keeps its vendor",        after["vendor"],        before["vendor"])
check("static row keeps its product",       after["product"],       before["product"])
check("static row keeps its vulnerability", after["vulnerability"], before["vulnerability"])
check("static row keeps its severity",      after["severity"],      before["severity"])
check("static row keeps its applies_to",    after["applies_to"],    before["applies_to"])
check("static row keeps its known_ports",   after["known_ports"],   before["known_ports"])
# And it is reported, not swallowed. A collision that produces silence is how
# you find out about it two years later.
check("the collision is counted as skipped, not inserted", res["skipped"], 1)
check("and not counted as an insert",                      res["inserted"], 0)
check("and not counted as an update",                      res["updated"],  0)


print("\n[2] FAILURE: severity must never be a word nobody read")
# The old writer put 'high' on every row. A 2004 IOS telnet DoS and a fresh
# pre-auth bypass got the same rating, so the column carried zero information
# while looking like it carried some. The feed has no CVSS in it at all, so
# the only two honest answers are the one signal it does give, and 'unknown'.
sync([feed_entry("CVE-2026-70001", knownRansomwareCampaignUse="Unknown")])
check("no feed signal means unrated, not high",
      row("CVE-2026-70001")["severity"], "unknown")

sync([feed_entry("CVE-2026-70002", knownRansomwareCampaignUse="")])
check("a blank field is also unrated",
      row("CVE-2026-70002")["severity"], "unknown")

missing = feed_entry("CVE-2026-70004")
missing.pop("knownRansomwareCampaignUse")
sync([missing])
check("a missing field is unrated too, not a crash and not a default high",
      row("CVE-2026-70004")["severity"], "unknown")

# The one case that earns a rating, because the feed actually says it.
sync([feed_entry("CVE-2026-70005", knownRansomwareCampaignUse="Known")])
check("ransomware use, which the feed does state, is rated",
      row("CVE-2026-70005")["severity"], "high")


print("\n[3] FAILURE: a row with no scope must not read as though it had one")
r = row("CVE-2026-70001")
check_true("applies_to is filled at all", r["applies_to"])
check_true("verify_hint is filled at all", r["verify_hint"])
check("entry_kind is written, not left to a default", r["entry_kind"], "vulnerability")
# The words matter more than the non-NULL. "scope unknown" and "does not
# apply" are different sentences and the row has to say the first one.
check_true("applies_to says the scope is unknown",
           "SCOPE UNKNOWN" in r["applies_to"])
check_true("applies_to names what the feed DID give",
           "Cisco" in r["applies_to"] and "Identity Services Engine" in r["applies_to"])
check_true("applies_to rules out the 'all versions' reading",
           "all versions" in r["applies_to"])
check_true("verify_hint says exploited somewhere is not present here",
           "not that it is present here" in r["verify_hint"])
check_true("verify_hint forbids a confident negative",
           "could not check" in r["verify_hint"])
# A feed row that names neither vendor nor product still has to produce a
# sentence rather than a half-built one with a dangling slash.
sync([feed_entry("CVE-2026-70006", vendorProject="", product="")])
check_true("a nameless row still gets a readable applies_to",
           "not named" in row("CVE-2026-70006")["applies_to"])


print("\n[4] FAILURE: the counts must describe work that happened")
# 'inserted' used to be incremented once per row the loop reached, including
# the ones INSERT OR IGNORE threw on the floor, so the second sync of the day
# reported fifteen hundred inserts and performed none.
fresh = [feed_entry("CVE-2026-71001"), feed_entry("CVE-2026-71002")]
first  = sync(fresh)
second = sync(fresh)
check("first pass inserts",            first["inserted"], 2)
check("first pass updates nothing",    first["updated"],  0)
check("second pass inserts nothing",   second["inserted"], 0)
check("second pass reports updates",   second["updated"],  2)

# The same id twice inside ONE feed payload. The second copy is an update, not
# a second insert.
dupes = sync([feed_entry("CVE-2026-71003"), feed_entry("CVE-2026-71003")])
check("a duplicated id counts once as an insert", dupes["inserted"], 1)
check("and once as an update",                    dupes["updated"],  1)

# A row with no id is rejected, and rejected is its own number.
bad = sync([feed_entry(""), feed_entry("   "), feed_entry("CVE-2026-71004")])
check("rows with no cve id are rejected", bad["rejected"], 2)
check("and the good one still lands",     bad["inserted"], 1)


# NOW THE HAPPY PATH

print("\n[5] a CISA correction now reaches the database")
# This is the bug that started it. INSERT OR IGNORE meant a re-sync could
# never carry an upstream fix, so a description CISA corrected stayed wrong
# here forever.
sync([feed_entry("CVE-2026-72001",
                 shortDescription="First wording, which CISA later fixed.",
                 dueDate="2026-09-19")])
check("the original wording lands",
      row("CVE-2026-72001")["description"],
      "First wording, which CISA later fixed.")

sync([feed_entry("CVE-2026-72001",
                 shortDescription="Corrected wording from CISA.",
                 dueDate="2026-10-01",
                 knownRansomwareCampaignUse="Known")])
r = row("CVE-2026-72001")
check("the correction propagates", r["description"], "Corrected wording from CISA.")
check("a corrected due date propagates too", r["due_date"], "2026-10-01")
check("and a newly flagged ransomware entry gets rated", r["severity"], "high")
# And back down again, because a correction can go either way and a rating
# that only ever climbs is not reading the feed either.
sync([feed_entry("CVE-2026-72001", knownRansomwareCampaignUse="Unknown")])
check("a withdrawn ransomware flag drops the rating back to unrated",
      row("CVE-2026-72001")["severity"], "unknown")


print("\n[6] the row survives a round trip through query_runbook")
hits = me.query_runbook(search_term="CVE-2026-70001")
check("exactly one hit", len(hits), 1)
h = hits[0]
check("source says where it came from", h["source"], "cisa_kev")
check("severity reaches the model as unknown", h["severity"], "unknown")
check_true("applies_to reaches the model", "SCOPE UNKNOWN" in h["applies_to"])
check_true("verify_hint reaches the model", "could not check" in h["verify_hint"])


print("\n[7] ordering is by severity, not by the alphabet")
# ORDER BY severity sorted the WORD, which put low ahead of medium. It only
# ever looked correct because every KEV row said 'high', so there was nothing
# to sort. With 'unknown' in the mix that stops being harmless.
with me._get_conn() as c:
    for cve, sev in (("CVE-2030-00001", "low"),
                     ("CVE-2030-00002", "medium"),
                     ("CVE-2030-00003", "critical"),
                     ("CVE-2030-00004", "unknown"),
                     ("CVE-2030-00005", "high")):
        c.execute("INSERT INTO runbook (cve_id, product, severity, source, date_added) "
                  "VALUES (?,?,?,?,?)",
                  (cve, "OrderingProbe", sev, "cisa_kev", "2030-01-01"))

got = [r["severity"] for r in me.query_runbook(search_term="OrderingProbe", limit=10)]
check("critical, high, medium, low, then unrated last",
      got, ["critical", "high", "medium", "low", "unknown"])


print("\n[8] the migration repairs rows that were already in the database")
# The next sync would fix these anyway, but it needs the network and CISA to
# both be up. Until then the rows sit there being read.
with me._get_conn() as c:
    c.execute("INSERT INTO runbook (cve_id, vendor, product, vulnerability, "
              "severity, source, entry_kind, applies_to, verify_hint) "
              "VALUES (?,?,?,?,?,?,?,?,?)",
              ("CVE-2004-1464", "Cisco", "IOS", "Telnet DoS",
               "high", "cisa_kev", None, None, None))

with me._get_conn() as c:
    out = migrations._migrate_kev_row_content(c)

r = row("CVE-2004-1464")
check("the hardcoded high is cleared", r["severity"], "unknown")
check("entry_kind is set", r["entry_kind"], "vulnerability")
check_true("applies_to is filled with the same sentence the writer uses",
           "SCOPE UNKNOWN" in r["applies_to"] and "Cisco" in r["applies_to"])
check_true("verify_hint is filled", "could not check" in r["verify_hint"])
check_true("the migration reports what it touched", out["qualifiers_filled"] >= 1)

# And it must not touch the static rows on its way past.
static_after = row("STATIC-001")
check("STATIC-001 severity untouched by the migration", static_after["severity"], "low")
check("STATIC-001 applies_to untouched by the migration",
      static_after["applies_to"], before["applies_to"])

# Running it twice changes nothing more, because a migration that is not
# idempotent is a migration that half-runs after a crash.
with me._get_conn() as c:
    again = migrations._migrate_kev_row_content(c)
check("second run fills nothing further", again["qualifiers_filled"], 0)


print("\n[9] FAILURE: the table must not paint an unrated row as a warning")
# The data fix is only half of it. The Runbook tab built its severity badge as
#     sev-${r.severity==='critical'?'critical':'high'}
# so the class was ALWAYS critical or high, whatever the row said. A 'low'
# entry already rendered the word low in high-severity amber, and the moment
# KEV rows started saying 'unknown' the page would have shown about fifteen
# hundred unrated entries dressed as warnings. The text was correct the whole
# time and the colour was lying over the top of it, which is worse than either
# being wrong on its own, because the colour is what gets read first.
ui     = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
routes = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")

check("the hardcoded badge ternary is gone",
      "r.severity==='critical'?'critical':'high'" in ui, False)
# 2026-09-17: the cell moved into cvssCell(), which picks between a fetched
# CVSS rating and the feed's own word and labels which one it is showing. The
# check here is unchanged in intent, only in where it looks: the class must
# still come from the VALUE through sevClass, never from a literal.
check_true("the severity cell is built by cvssCell", "cvssCell(r)" in ui)
check_true("the badge class is derived from the value",
           "sevClass(word)" in ui and "sevClass(feed)" in ui)
check_true("a row with no fetched score still shows the feed's word",
           "const feed  = String(r.severity || '').toLowerCase();" in ui)
check_true("unrecognised values fall back to the quiet class, not a loud one",
           "SEV_CLASSES.has(v) ? v : 'info'" in ui)
check_true("'unknown' is a class the whitelist knows", "'unknown'" in ui)
check_true("and it has CSS, so it is not an unstyled badge", ".sev-unknown" in ui)
# Every class the whitelist allows has to actually exist in the stylesheet, or
# the fallback quietly produces a badge with no styling at all.
for cls in ("critical", "high", "medium", "low", "info", "unknown"):
    check_true(f"CSS exists for sev-{cls}", f".sev-{cls}" in ui)

print("\n[10] the sync button is wired end to end")
check_true("the button is on the Runbook tab", 'onclick="syncRunbook()"' in ui)
check_true("it posts to the sync route", "'/api/runbook/sync'" in ui)
check_true("the route exists", '@app.route("/api/runbook/sync", methods=["POST"])' in routes)
# It disables while running, because the call fetches the whole feed and
# upserts ~1500 rows, and a button that looks idle for six seconds gets
# clicked again.
check_true("the button disables while the sync runs", "btn.disabled = true" in ui)
check_true("and comes back afterwards, including on failure",
           "finally {" in ui and "btn.disabled    = false" in ui)
# A failure has to say WHAT failed. "Sync failed" on its own sends you to the
# log to find out whether the network was down or the feed was refused.
check_true("a failure reports the reason", "'Sync failed: '" in ui)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
