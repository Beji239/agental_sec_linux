# tools/kev_cvss.py
# AgentalSec V2, fetch a real CVSS rating for the mirrored CISA KEV rows.

import logging
import threading
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# WHY THIS EXISTS
#
# The CISA KEV feed publishes no severity. Not a CVSS score, not a rating, not
# a band. tools/runbook.py used to paper over that by writing 'high' on all
# ~1700 rows, which was fixed on 2026-09-16 so the column now says 'unknown'
# unless the feed flags ransomware use.
#
# That fix was right and it left the Runbook tab showing UNKNOWN on about 1400
# rows, which the owner read as a broken sync button on 2026-09-17. Fair
# reading. A column that is a constant for most rows carries no information
# whether the constant is a lie or a blank, and "we did not look it up" is not
# a triage answer.
#
# So this module goes and asks. core/enrichment.py already knows how to look a
# CVE up, against CIRCL and NVD, with throttling, a cache and source
# provenance, so this is a loop over the mirror plus the one thing enrichment
# cannot decide for us: what a row is allowed to say afterwards.
#
# FOUR OUTCOMES, FOUR NAMES. This is the whole point of the module and it is
# rule two from 2026-09-13 applied to a column instead of a function:
#
#   'ok'         a source answered with a base score. It is in cvss_score,
#                with the vector next to it so it can be argued with.
#   'no_score'   the record exists upstream and carries no base score. A real
#                negative, and NOT an error.
#   'not_found'  the sources answered and have no record of this CVE at all.
#                Also a real negative, and a different one.
#   'error'      we could not ask, or no answer arrived. We learned NOTHING.
#                This state must never produce a number and must never be
#                summarised as "no score available".
#
# cvss_checked_at is stamped on every attempt, empty ones included, so a row
# that came back empty and a row nobody has touched stay distinguishable. A
# NULL state means nobody has looked, which is its own fifth sentence.
#
# WHAT AN ERROR IS NOT ALLOWED TO DO. If a previous pass fetched a score and
# today's recheck fails, the score stays and the state records the failed
# attempt. Deleting a fact we established because a later lookup timed out
# would be throwing away the only real information in the row.

STATE_OK        = "ok"
STATE_NO_SCORE  = "no_score"
STATE_NOT_FOUND = "not_found"
STATE_ERROR     = "error"

# How long before a row is due again. An error is a transient thing most of
# the time, so it comes back round quickly; a fetched score is close to
# permanent, though NVD does revise scores, so it is rechecked eventually.
RETRY_ERROR_AFTER_HOURS = 6
RECHECK_OK_AFTER_DAYS   = 30

_SENTENCES = {
    "never_checked": ("This row has not been looked up yet, so there is no "
                      "score to show. Nobody has asked."),
    STATE_OK:        ("A published CVSS base score was fetched for this row. "
                      "The vector is stored with it."),
    STATE_NO_SCORE:  ("The vulnerability sources have this CVE and publish no "
                      "base score for it. That is a real answer, not a "
                      "missing one."),
    STATE_NOT_FOUND: ("The vulnerability sources answered and have no record "
                      "of this CVE. Also a real answer."),
    STATE_ERROR:     ("The last lookup could not be completed, so nothing is "
                      "known either way. This is not evidence that the CVE is "
                      "minor or absent."),
}


def state_sentence(state) -> str:
    """
    What a cvss_state means, in one sentence, for a human reading the table.

    Kept here rather than in the page so the words cannot drift between the
    two. index.html mirrors these strings and tests/test_kev_cvss.py checks
    that the three "we have no score" states still read as three different
    sentences, because the moment any two of them collapse the table starts
    asserting something nobody established.
    """
    if not state:
        state = "never_checked"
    return _SENTENCES.get(state, _SENTENCES["never_checked"])


# ONE LOOKUP

def _band(score):
    """
    The CVSS v3 band for a published score. Arithmetic on their number, not an
    opinion about it, which is why it is allowed at all: the band is defined by
    the spec, so deriving it adds no claim. It is only used when the source
    gave a score and no word, and the note says it was derived.
    """
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "none"


def _numeric(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


_SEVERITY_WORDS = {"none", "low", "medium", "high", "critical"}


def _from_result(result: dict) -> dict:
    """
    Turn one enrichment result into the four-outcome shape this module writes.

    The ordering of the branches is the careful part. A failed source is
    checked BEFORE "no score", because when one source errored and the other
    had no number, the honest reading is that we could not finish asking, not
    that the answer is no. Guessing the softer of the two would be the exact
    failure this module is built around.
    """
    fields = (result.get("fields") or {})
    score  = _numeric(fields.get("cvss_score"))
    # A CVSS base score is 0.0 to 10.0; anything else is not one (FM-5).
    if score is not None and not 0.0 <= score <= 10.0:
        score = None
    gap    = (result.get("gap") or "")[:400] or None

    errors = result.get("errors")
    if errors is None:
        # A cached row does not carry the per-source error list. Its
        # confidence does carry whether anything was learned.
        errors = ([gap] if (result.get("status") == "unresolved"
                            and result.get("confidence") == "none") else [])

    if score is not None:
        provenance = (fields.get("_field_sources") or {})
        severity   = (fields.get("cvss_severity") or "").strip().lower() or None
        note       = None
        if severity not in _SEVERITY_WORDS:
            severity = None
        if not severity:
            severity = _band(score)
            note = ("The source published a score and no severity word. The "
                    "band above is the CVSS v3 band for that score.")
        return {
            "state":    STATE_OK,
            "score":    score,
            "severity": severity,
            "vector":   fields.get("cvss_vector"),
            "source":   provenance.get("cvss_score") or provenance.get("cve_id"),
            "note":     note,
        }

    if errors:
        return {"state": STATE_ERROR, "score": None, "severity": None,
                "vector": None, "source": None,
                "note": "; ".join(str(e) for e in errors)[:400]}

    if result.get("confidence") == "sources_have_no_record":
        return {"state": STATE_NOT_FOUND, "score": None, "severity": None,
                "vector": None, "source": None, "note": gap}

    return {"state": STATE_NO_SCORE, "score": None, "severity": None,
            "vector": None, "source": None,
            "note": gap or ("The sources answered about this CVE and none of "
                            "them publishes a base score for it.")}


def lookup_cve(cve: str) -> dict:
    """
    The default lookup. Cache first, then the network through enrichment.

    Injectable, because every test in tests/test_kev_cvss.py passes its own so
    the suite never touches the network.
    """
    from core import enrichment

    try:
        cached = enrichment.read(cve, "cve")
    except Exception:
        cached = None
    if cached and not cached.get("stale"):
        return _from_result(cached)

    result = enrichment.research(cve, "cve")
    try:
        enrichment.store(result)
    except Exception as e:
        # A cache write failing is not a lookup failing. Say so in the log and
        # use the answer we already have.
        logger.warning(f"[kev_cvss] could not cache {cve}: {e}")
    return _from_result(result)


# THE BACKFILL

def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.isoformat(timespec="seconds")


def _parse(stamp):
    """Aware datetime or None; a stamp with no zone is read as UTC, so the
    comparison with _now() cannot raise (FM-6)."""
    try:
        dt = datetime.fromisoformat(stamp)
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class CvssBackfill:
    """
    Walk the KEV mirror and fetch a rating for every row that needs one.

    NOT STARTED AT BOOT, on purpose. It is ~1700 outbound lookups, which is
    about fifty minutes with an NVD key and three and a half hours without
    one, and a monitoring tool should not open hours of third party traffic on
    its own because somebody restarted it. The Runbook tab has a button.

    Resumable by construction: the work list is computed from the table on
    every pass, so a stop, a crash or a closed laptop costs the row in flight
    and nothing else.
    """

    def __init__(self, lookup=None,
                 retry_error_after_hours: int = RETRY_ERROR_AFTER_HOURS,
                 recheck_ok_after_days: int = RECHECK_OK_AFTER_DAYS):
        self._lookup = lookup or lookup_cve
        self._retry_error_after = timedelta(hours=retry_error_after_hours)
        self._recheck_ok_after  = timedelta(days=recheck_ok_after_days)

        self._lock   = threading.Lock()
        self._stop   = threading.Event()
        self._thread = None
        self._state  = self._blank_state()
        # WHY THE WORK LIST CAME BACK EMPTY, when it did not come back empty
        # because the table is finished. See _due and _state_note.
        self._due_blocked = None

    # state

    def _blank_state(self) -> dict:
        return {
            "running":     False,
            "stopped":     False,
            "complete":    False,
            "started_at":  None,
            "finished_at": None,
            "attempted":   0,
            "written":     {STATE_OK: 0, STATE_NO_SCORE: 0,
                            STATE_NOT_FOUND: 0, STATE_ERROR: 0},
            "current":     None,
            "last_error":  None,
            "remaining":   None,
        }

    def status(self) -> dict:
        with self._lock:
            snap = dict(self._state)
            snap["written"] = dict(self._state["written"])
        if snap["remaining"] is None:
            try:
                snap["remaining"] = len(self._due())
            except Exception:
                snap["remaining"] = None
        snap["rate"] = self._rate_note(snap.get("remaining"))
        snap["note"] = self._state_note(snap)
        return snap

    def _state_note(self, snap: dict) -> str:
        """
        What 'not running' actually means today.

        The readiness row reads not running and prints it, which is correct
        and hides the only number that decides whether you care: a backfill
        with nothing left to rate and one with 1700 rows unrated are the
        same amber row. Never started and finished look alike too.
        """
        remaining = snap.get("remaining")
        if snap.get("running"):
            left = "an unknown number" if remaining is None else str(remaining)
            return (f"Running. {snap.get('attempted', 0)} looked up so far, "
                    f"{left} to go.")
        # A WORK LIST THAT COULD NOT BE BUILT IS NOT AN EMPTY ONE. MEASURED
        # 2026-09-27 on a scratch store whose runbook predates the cvss
        # columns: _due() refuses with a log line and returns [], and this
        # function then printed "every KEV row already has a rating" over two
        # rows nobody had ever looked up. The count is only evidence of
        # completion when the count was actually taken.
        if remaining == 0 and self._due_blocked:
            return f"Not running, and NOT complete: {self._due_blocked}"
        if remaining == 0:
            return "Not running, and every KEV row already has a rating."
        if remaining is None:
            return ("Not running. The number of unrated rows could not be "
                    "read, so this is not a claim that there are none.")
        return (f"Not running. {remaining} KEV row(s) still have no severity, "
                f"so the Runbook table cannot be triaged on it. Fetch CVSS on "
                f"the Runbook tab starts it.")

    def _rate_note(self, remaining: int = None) -> str:
        """
        How fast this can go and why.

        The numbers are READ OFF the throttle, not restated here, so the screen
        cannot claim a rate the code is not using. Both floors are counted
        because the ladder asks CIRCL and then NVD for the same CVE, one after
        the other, so a lookup costs roughly the sum of the two waits and
        quoting the NVD figure alone would flatter it.

        THE WORK LIST IS PASSED IN, when the caller has it. _state_note already
        holds `remaining` and this sentence used to say "about N CVEs an hour"
        with no word on what N was for; MEASURED 2026-09-27, with NVD unkeyed:
        480 CVEs an hour, so the 1,726 rows this module's own docstring quotes
        are 3.6 h rather than the "fifty minutes" the docstring claims. The
        number in the sentence is the rows actually waiting, because a rate
        with no quantity is not a time and an operator reading "about 480 an
        hour" has to go and find the other half themselves.
        """
        try:
            from core import enrichment
            per_cve = (enrichment._interval_for("circl")
                       + enrichment._interval_for("nvd"))
            keyed   = bool(enrichment._nvd_key())
        except Exception:
            return "Lookup rate unknown, the enrichment module did not load."
        per_hour = int(3600 / per_cve) if per_cve else 0
        if keyed:
            head = (f"An NVD API key is set. At the agreed rate that is about "
                    f"{per_hour} CVEs an hour.")
        else:
            head = (f"No NVD API key is set, so NVD is asked at its anonymous "
                    f"rate: about {per_hour} CVEs an hour. A free key from "
                    f"nvd.nist.gov in AGENTAL_NVD_API_KEY makes it roughly "
                    f"four times faster.")
        if remaining is None:
            return head
        if remaining == 0:
            return head + " Nothing is waiting to be looked up."
        hours = remaining * per_cve / 3600 if per_cve else 0
        return (head + f" The {remaining} row(s) still waiting are about "
                       f"{hours:.1f} h ({hours * 60:.0f} min) of that.")

    # the work list

    def _due(self, limit: int = None) -> list:
        """
        Which rows need a lookup, most deserving first.

        Never-looked-at rows come first, newest KEV entries first inside that,
        because a row nobody has ever rated is worth more than a recheck of one
        that already has a score. Then failed attempts that are due a retry,
        then old successes.

        Restricted to the mirror. The five STATIC-* priors are hand-written
        code with reasoned severities on them, and a CVSS number has no
        business landing on an 'exposure' row like "port 4444 is the
        Metasploit default", which is a convention and not a defect.
        """
        from core.memory_engine import _get_conn

        now = _now()
        fresh, retry, recheck = [], [], []
        self._due_blocked = None

        with _get_conn() as conn:
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(runbook)")}
            if "cvss_state" not in cols:
                # RECORDED AS WELL AS LOGGED, because status() reports the
                # number this returns. A refusal that only reaches the log is
                # a refusal the page cannot see; see _state_note.
                self._due_blocked = (
                    "the runbook table has no cvss_state column yet, so there "
                    "is nothing to fill and NOTHING WAS CHECKED. Run "
                    "migrations first.")
                logger.warning(
                    "runbook has no cvss_state column yet, so there is nothing "
                    "to fill. Run migrations first.")
                return []
            rows = conn.execute(
                "SELECT cve_id, cvss_state, cvss_checked_at, date_added "
                "FROM runbook WHERE source = 'cisa_kev' AND cve_id LIKE 'CVE-%' "
                "ORDER BY date_added DESC"
            ).fetchall()

        for r in rows:
            state   = r["cvss_state"]
            checked = _parse(r["cvss_checked_at"])
            if not state or not checked:
                fresh.append(r["cve_id"])
            elif state == STATE_ERROR:
                if now - checked >= self._retry_error_after:
                    retry.append(r["cve_id"])
            elif now - checked >= self._recheck_ok_after:
                recheck.append(r["cve_id"])

        due = fresh + retry + recheck
        return due[:limit] if limit else due

    # the write

    def _write(self, cve: str, res: dict):
        """
        One row's outcome.

        Every branch stamps cvss_state, cvss_note and cvss_checked_at, so an
        attempt is always visible. What differs is what happens to the SCORE:

          ok                    all fields written.
          no_score / not_found  the score fields are cleared, because the
                                source's current answer is that there is none
                                and a leftover number would outlive its source.
          error                 the score fields are NOT touched. We learned
                                nothing, so we discard nothing.
        """
        from core.memory_engine import _get_conn

        state = res.get("state") or STATE_ERROR
        stamp = _iso(_now())

        with _get_conn() as conn:
            if state == STATE_OK:
                conn.execute(
                    "UPDATE runbook SET cvss_score = ?, cvss_severity = ?, "
                    "cvss_vector = ?, cvss_source = ?, cvss_state = ?, "
                    "cvss_note = ?, cvss_checked_at = ? WHERE cve_id = ?",
                    (res.get("score"),
                     (res.get("severity") or "").strip().lower() or None,
                     res.get("vector"), res.get("source"), state,
                     res.get("note"), stamp, cve))
            elif state in (STATE_NO_SCORE, STATE_NOT_FOUND):
                conn.execute(
                    "UPDATE runbook SET cvss_score = NULL, cvss_severity = NULL, "
                    "cvss_vector = NULL, cvss_source = NULL, cvss_state = ?, "
                    "cvss_note = ?, cvss_checked_at = ? WHERE cve_id = ?",
                    (state, res.get("note"), stamp, cve))
            else:
                conn.execute(
                    "UPDATE runbook SET cvss_state = ?, cvss_note = ?, "
                    "cvss_checked_at = ? WHERE cve_id = ?",
                    (STATE_ERROR, res.get("note"), stamp, cve))

    # the loop

    def run_once(self, limit: int = None) -> dict:
        """
        Work the list once, synchronously. Returns the status snapshot.

        Used directly by the tests and by the background thread. The counters
        it returns describe rows this pass actually wrote, and `complete` is
        true only when the work list is genuinely empty afterwards, never
        because the loop ran out of batch.
        """
        with self._lock:
            self._state = self._blank_state()
            self._state["running"]    = True
            self._state["started_at"] = _iso(_now())
        self._stop.clear()

        due = self._due(limit)

        for cve in due:
            if self._stop.is_set():
                break
            with self._lock:
                self._state["current"]   = cve
                self._state["attempted"] += 1

            try:
                res = self._lookup(cve)
            except Exception as e:
                # A lookup that raised is an error state, not a crash and not a
                # skipped row. It gets written like any other failure so the
                # row says an attempt happened.
                res = {"state": STATE_ERROR, "note": f"lookup raised ({type(e).__name__})"}
                logger.warning(f"[kev_cvss] {cve} lookup raised: {e}")

            state = res.get("state") or STATE_ERROR
            try:
                self._write(cve, res)
            except Exception as e:
                logger.warning(f"[kev_cvss] could not write {cve}: {e}")
                with self._lock:
                    self._state["last_error"] = f"{cve}: write failed ({type(e).__name__})"
                continue

            with self._lock:
                if state in self._state["written"]:
                    self._state["written"][state] += 1
                if state == STATE_ERROR:
                    self._state["last_error"] = f"{cve}: {res.get('note')}"

        stopped   = self._stop.is_set()
        remaining = len(self._due())

        with self._lock:
            self._state["running"]     = False
            self._state["stopped"]     = stopped
            self._state["current"]     = None
            self._state["finished_at"] = _iso(_now())
            self._state["remaining"]   = remaining
            # Complete means the table has nothing left to look up. A pass that
            # was stopped, or that hit its batch limit, is not complete however
            # well it went.
            self._state["complete"]    = (not stopped) and remaining == 0
            snap = dict(self._state)
            snap["written"] = dict(self._state["written"])

        logger.info(
            f"[kev_cvss] pass finished: {snap['attempted']} attempted, "
            f"{snap['written'][STATE_OK]} scored, "
            f"{snap['written'][STATE_NO_SCORE]} have no published score, "
            f"{snap['written'][STATE_NOT_FOUND]} not found upstream, "
            f"{snap['written'][STATE_ERROR]} could not be looked up, "
            f"{remaining} still waiting")
        snap["rate"] = self._rate_note(snap.get("remaining"))
        return snap

    def start(self, limit: int = None) -> dict:
        """Run a pass in the background. Refuses to start a second one."""
        with self._lock:
            if self._state["running"]:
                return {"started": False,
                        "error": "a backfill pass is already running",
                        "status": dict(self._state)}
            self._state["running"] = True
            self._state["started_at"] = _iso(_now())

        def run():
            try:
                self.run_once(limit)
            except Exception as e:
                logger.error(f"[kev_cvss] pass failed: {e}", exc_info=True)
                with self._lock:
                    self._state["running"]    = False
                    self._state["last_error"] = f"pass failed ({type(e).__name__})"

        self._thread = threading.Thread(target=run, name="kev-cvss", daemon=True)
        self._thread.start()
        return {"started": True, "status": self.status()}

    def stop(self) -> dict:
        """Ask the loop to finish the row in flight and stop."""
        self._stop.set()
        return {"stopping": True, "status": self.status()}
