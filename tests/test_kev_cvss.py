"""
tests/test_kev_cvss.py, a CVSS score must never be a number nobody fetched.

WHY THIS EXISTS. 2026-09-17. The Runbook tab showed UNKNOWN on every visible
KEV row and the owner read that as a broken sync button. The button was fine:
the CISA KEV feed carries no severity at all, so tools/runbook.py writes
'unknown' for every row except the ones the feed flags for ransomware use.
Honest, and useless for triage, because the column then says nothing about
1400 of the 1700 rows.

The fix is to go and GET a rating from a source that has one, which means a
network lookup per CVE, which means four new ways to lie:

  [1] a lookup that could not happen turning into a score anyway
  [2] 'nobody publishes a score' reading the same as 'we could not ask'
  [3] a row nobody has looked at yet reading as a row that came back empty
  [4] progress counters describing work that did not happen

Those are the first four sections, on purpose. The happy path is [6] onward
and it is the easy part.

RULE TWO, from 2026-09-13: "no match" and "I could not search" must stay
different sentences. That rule is the whole design of the cvss_state column,
and sections [1] to [3] are what hold it in place.
"""
import json
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

import _isolate_db                                # noqa: E402
_isolate_db.isolate()

from core import memory_engine as me              # noqa: E402
from core import migrations                       # noqa: E402

migrations.run_migrations(me.DB_PATH)

from tools import kev_cvss                        # noqa: E402
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


def seed(cve_id, source="cisa_kev", severity="unknown", date_added="2026-09-17"):
    """One KEV row as tools/runbook.py would have written it."""
    with me._get_conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO runbook "
            "(cve_id, vendor, product, vulnerability, severity, source, date_added) "
            "VALUES (?,?,?,?,?,?,?)",
            (cve_id, "Acme", "Widget", "Widget auth bypass", severity, source, date_added))


def clear_runbook():
    with me._get_conn() as c:
        c.execute("DELETE FROM runbook")


def fixed_lookup(**by_cve):
    """A lookup function that answers from a dict instead of the network."""
    def look(cve):
        return by_cve[cve]
    return look


OK = {"state": "ok", "score": 9.8, "severity": "critical",
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "source": "nvd", "note": None}


# FAILURE CASES FIRST

print("\n[1] FAILURE: a lookup that could not happen must not become a score")
clear_runbook()
seed("CVE-2026-90001")
bf = kev_cvss.CvssBackfill(lookup=fixed_lookup(**{
    "CVE-2026-90001": {"state": "error", "score": None, "severity": None,
                       "vector": None, "source": None,
                       "note": "nvd: rate limited (429); circl: ReadTimeout"},
}))
out = bf.run_once()
r = row("CVE-2026-90001")
check("state records that the lookup failed", r["cvss_state"], "error")
check("no score is invented",                 r["cvss_score"], None)
check("no severity word is invented",         r["cvss_severity"], None)
check("no source is claimed",                 r["cvss_source"], None)
check_true("the note says what failed", "rate limited" in (r["cvss_note"] or ""))
# The feed-derived severity is a different column and a failed lookup has no
# business touching it.
check("the feed severity is left alone", r["severity"], "unknown")
check("the failure is counted as a failure", out["written"]["error"], 1)
check("and not as a success",                out["written"]["ok"], 0)

# An error must not overwrite a score that an earlier pass DID fetch. We did
# not learn anything this time, so nothing we knew gets thrown away.
clear_runbook()
seed("CVE-2026-90002")
kev_cvss.CvssBackfill(lookup=fixed_lookup(**{"CVE-2026-90002": OK})).run_once()
check("the good score landed first", row("CVE-2026-90002")["cvss_score"], 9.8)
kev_cvss.CvssBackfill(lookup=fixed_lookup(**{
    "CVE-2026-90002": {"state": "error", "score": None, "severity": None,
                       "vector": None, "source": None, "note": "nvd: HTTP 503"},
}), recheck_ok_after_days=0).run_once()
r = row("CVE-2026-90002")
check("a failed recheck keeps the score we already had", r["cvss_score"], 9.8)
check("and says the last attempt failed",                r["cvss_state"], "error")
check_true("and says which attempt failed", "503" in (r["cvss_note"] or ""))


print("\n[2] FAILURE: 'nobody has a score' must not read like 'we could not ask'")
clear_runbook()
seed("CVE-2026-91001")
seed("CVE-2026-91002")
seed("CVE-2026-91003")
kev_cvss.CvssBackfill(lookup=fixed_lookup(**{
    # The CVE exists upstream, nobody has published a base score for it yet.
    "CVE-2026-91001": {"state": "no_score", "score": None, "severity": None,
                       "vector": None, "source": "nvd",
                       "note": "nvd has the record and no CVSS metrics on it"},
    # Upstream has never heard of it.
    "CVE-2026-91002": {"state": "not_found", "score": None, "severity": None,
                       "vector": None, "source": "nvd",
                       "note": "nvd and circl both answered, neither has a record"},
    # We never got to ask.
    "CVE-2026-91003": {"state": "error", "score": None, "severity": None,
                       "vector": None, "source": None, "note": "circl: ConnectTimeout"},
})).run_once()
check("a record with no score is its own state",  row("CVE-2026-91001")["cvss_state"], "no_score")
check("no record upstream is its own state",      row("CVE-2026-91002")["cvss_state"], "not_found")
check("a lookup that failed is its own state",    row("CVE-2026-91003")["cvss_state"], "error")
# Three states, three sentences. If any two of these ever collapse into one
# word, the row starts asserting something nobody established.
sentences = {kev_cvss.state_sentence(s)
             for s in ("no_score", "not_found", "error")}
check("the three states read as three different sentences", len(sentences), 3)
check_true("only the error sentence says we could not look",
           "could not" in kev_cvss.state_sentence("error")
           and "could not" not in kev_cvss.state_sentence("no_score")
           and "could not" not in kev_cvss.state_sentence("not_found"))
# Every attempt is stamped, including the ones that came back empty. Without
# this, 'checked and empty' and 'never checked' are the same row.
for cve in ("CVE-2026-91001", "CVE-2026-91002", "CVE-2026-91003"):
    check_true(f"{cve} records when it was attempted", row(cve)["cvss_checked_at"])


print("\n[3] FAILURE: a row nobody looked at must not read as a row that came back empty")
clear_runbook()
seed("CVE-2026-92001")
r = row("CVE-2026-92001")
check("an untouched row has no state at all", r["cvss_state"], None)
check("and no attempt timestamp",             r["cvss_checked_at"], None)
check("never looked is its own sentence",
      kev_cvss.state_sentence(None),
      kev_cvss.state_sentence("never_checked"))
check_true("and it says nobody has looked",
           "not been looked up" in kev_cvss.state_sentence(None))
check_true("which is not the same sentence as no_score",
           kev_cvss.state_sentence(None) != kev_cvss.state_sentence("no_score"))


print("\n[4] FAILURE: the counters must describe work that happened")
clear_runbook()
for i in range(4):
    seed(f"CVE-2026-93{i:03d}")
answers = {f"CVE-2026-93{i:03d}": OK for i in range(4)}
bf = kev_cvss.CvssBackfill(lookup=fixed_lookup(**answers))
out = bf.run_once(limit=2)
check("a limited pass attempts only what it was asked for", out["attempted"], 2)
check("and writes only that many",                          out["written"]["ok"], 2)
check("and says how many rows are still waiting",           out["remaining"], 2)
check("and does not claim to have finished",                out["complete"], False)
out = bf.run_once()
check("the second pass finishes the rest",   out["attempted"], 2)
check("and now nothing is waiting",          out["remaining"], 0)
check("and it says so",                      out["complete"], True)

# A stop mid-run reports stopped, not complete. A run that was cut short and
# claims to be done is the same bug as a step cap that ends with nothing
# written and reports success.
clear_runbook()
for i in range(5):
    seed(f"CVE-2026-94{i:03d}")
stop_bf = kev_cvss.CvssBackfill(lookup=fixed_lookup(**{
    f"CVE-2026-94{i:03d}": OK for i in range(5)}))


def stop_after_two(cve):
    if stop_bf.status()["attempted"] >= 2:
        stop_bf.stop()
    return OK


stop_bf._lookup = stop_after_two
out = stop_bf.run_once()
check("a stopped run says it stopped",        out["stopped"], True)
check("a stopped run does not claim to be complete", out["complete"], False)
check_true("and it wrote only what it reached", out["attempted"] <= 3)
check_true("and the rest are still waiting",    out["remaining"] >= 2)


print("\n[5] FAILURE: the backfill must not wander outside the KEV mirror")
clear_runbook()
rb.Runbook("test-session")._load_static_entries()
seed("CVE-2026-95001")
seen = []


def recording_lookup(cve):
    seen.append(cve)
    return OK


kev_cvss.CvssBackfill(lookup=recording_lookup).run_once()
check("only the KEV row was looked up", seen, ["CVE-2026-95001"])
check("the static rows were not touched", row("STATIC-001")["cvss_state"], None)
check("and their own severity is untouched", row("STATIC-001")["severity"], "low")


# NOW THE HAPPY PATH

print("\n[6] a real score lands with everything needed to check it later")
clear_runbook()
seed("CVE-2026-96001")
kev_cvss.CvssBackfill(lookup=fixed_lookup(**{"CVE-2026-96001": OK})).run_once()
r = row("CVE-2026-96001")
check("score",      r["cvss_score"], 9.8)
check("severity",   r["cvss_severity"], "critical")
check("source",     r["cvss_source"], "nvd")
check("state",      r["cvss_state"], "ok")
check_true("vector, so the score can be argued with", "AV:N" in (r["cvss_vector"] or ""))
check_true("and when it was fetched", r["cvss_checked_at"])
check("the feed severity is still the feed's", r["severity"], "unknown")


print("\n[7] a second pass skips what is done and retries what failed")
clear_runbook()
seed("CVE-2026-97001")
seed("CVE-2026-97002")
kev_cvss.CvssBackfill(lookup=fixed_lookup(**{
    "CVE-2026-97001": OK,
    "CVE-2026-97002": {"state": "error", "score": None, "severity": None,
                       "vector": None, "source": None, "note": "nvd: ReadTimeout"},
})).run_once()

second = []


def watch(cve):
    second.append(cve)
    return OK


# retry_error_after_hours=0 so the failed row is due again immediately.
kev_cvss.CvssBackfill(lookup=watch, retry_error_after_hours=0).run_once()
check("the successful row is not fetched again", second, ["CVE-2026-97002"])
check("and the retry lands",  row("CVE-2026-97002")["cvss_state"], "ok")


print("\n[8] the model sees the score through query_runbook")
hits = me.query_runbook(search_term="CVE-2026-97001")
check("one hit", len(hits), 1)
check("the score reaches the model", hits[0]["cvss_score"], 9.8)
check("with its state",              hits[0]["cvss_state"], "ok")

# Ordering prefers the fetched rating over the feed's blank. A scored critical
# has to outrank an unrated row, or the sort is still sorting on a constant.
clear_runbook()
with me._get_conn() as c:
    for cve, sev, cvss_sev, score in (
            ("CVE-2031-00001", "unknown", "critical", 9.9),
            ("CVE-2031-00002", "high",    None,       None),
            ("CVE-2031-00003", "unknown", "medium",   5.1),
            ("CVE-2031-00004", "unknown", None,       None)):
        c.execute("INSERT INTO runbook (cve_id, product, severity, source, "
                  "date_added, cvss_severity, cvss_score, cvss_state) "
                  "VALUES (?,?,?,?,?,?,?,?)",
                  (cve, "OrderProbe", sev, "cisa_kev", "2031-01-01",
                   cvss_sev, score, "ok" if cvss_sev else None))
got = [r["cve_id"] for r in me.query_runbook(search_term="OrderProbe", limit=10)]
check("fetched critical, then feed high, then fetched medium, then unrated",
      got, ["CVE-2031-00001", "CVE-2031-00002", "CVE-2031-00003", "CVE-2031-00004"])


print("\n[9] the migration adds the columns and can be run twice")
cols = None
with me._get_conn() as c:
    out1 = migrations._migrate_kev_cvss(c)
    cols = {r["name"] for r in c.execute("PRAGMA table_info(runbook)")}
for col in ("cvss_score", "cvss_severity", "cvss_vector", "cvss_source",
            "cvss_state", "cvss_note", "cvss_checked_at", "ransomware_use"):
    check_true(f"{col} exists", col in cols)
check("a second run adds nothing", out1, 0)


print("\n[10] the feed's one real signal is kept as its own field")
# knownRansomwareCampaignUse is the only severity-ish thing the feed states.
# It was being read into severity and then thrown away, so the row could not
# show WHY it was rated.
clear_runbook()
rb.Runbook("test-session")._write_kev_rows([{
    "cveID": "CVE-2026-98001", "vendorProject": "Acme", "product": "Widget",
    "vulnerabilityName": "Widget RCE", "shortDescription": "d",
    "requiredAction": "patch", "dateAdded": "2026-09-01", "dueDate": "2026-09-22",
    "knownRansomwareCampaignUse": "Known",
}])
r = row("CVE-2026-98001")
check("the ransomware flag is stored as itself", r["ransomware_use"], "known")
check("and still drives the feed severity",      r["severity"], "high")
check("and the due date is there for the table", r["due_date"], "2026-09-22")


print("\n[11] NVD is asked politely, and faster only when a key says it may be")
import os                                          # noqa: E402
from core import enrichment                        # noqa: E402

os.environ.pop("AGENTAL_NVD_API_KEY", None)
check("no key means the published anonymous floor",
      enrichment._interval_for("nvd"), 6.5)
check_true("and no key header is sent", enrichment._nvd_headers() == {})
os.environ["AGENTAL_NVD_API_KEY"] = "test-key-not-real"
check_true("a key raises the rate, and stays under the published limit",
           0.6 <= enrichment._interval_for("nvd") <= 1.0)
check("and the key travels in the header NVD documents",
      enrichment._nvd_headers(), {"apiKey": "test-key-not-real"})
os.environ.pop("AGENTAL_NVD_API_KEY", None)
# Other sources are not sped up by an NVD key.
check("circl keeps its own floor", enrichment._interval_for("circl"), 1.0)


print("\n[12] the tab is wired end to end")
ui     = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
routes = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")

check_true("there is a button to start the backfill",
           'onclick="startCvssBackfill()"' in ui)
check_true("it posts to the start route", "'/api/runbook/cvss/start'" in ui)
check_true("the start route exists",
           '@app.route("/api/runbook/cvss/start", methods=["POST"])' in routes)
check_true("the status route exists",
           '@app.route("/api/runbook/cvss/status")' in routes)
check_true("the stop route exists",
           '@app.route("/api/runbook/cvss/stop", methods=["POST"])' in routes)
check_true("the table shows the ransomware flag", "<th>Ransomware</th>" in ui)
check_true("the table shows the due date",        "<th>Due</th>" in ui)
# The severity cell has to say WHERE its rating came from, or a fetched
# critical and a feed-derived guess look identical.
check_true("the severity cell is built from both ratings",
           "cvssCell(r)" in ui)
check_true("a fetched score is labelled as fetched", "CVSS" in ui)
check_true("an unfetched row says so rather than showing a bare word",
           "stateSentence(" in ui)
# The progress line must not say finished when the run was stopped or is
# still going. Same bug as the counters in [4], one layer up.
check_true("the progress line reads the real state", "out.complete" in ui)
check_true("and reports a stop as a stop", "out.stopped" in ui)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
