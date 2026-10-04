# core/web_search.py
# AgentalSec V2, DuckDuckGo web search, no API key needed.
#
# The model calls this via the web_search tool to check things it would
# otherwise answer from memory: mDNS service types, MAC vendors, whether a
# runbook entry applies to this host's OS version, what an unknown IP belongs
# to. Recall is where this system has been wrong most often, so this path is
# load-bearing rather than decorative.
#
# Results are attacker-influenceable (a search page is not a trusted source),
# so web_search is listed in sanitize.UNTRUSTED_TOOLS and its output reaches
# the model fenced.
#
# GET, NOT POST. 2026-08-30.
# Both html and lite were called with POST and both had started answering 202
# with a holding page, so every search reported "did not complete" and the
# model correctly refused to answer from recall, round after round of it.
# The honest reporting built into search() below is what made this findable:
# it said "did not complete" rather than returning an empty list, so the
# failure was visible instead of looking like a network with nothing on it.
# The same queries over GET return 200 and real results. Diagnosed with
# scripts/websearch_check.py, which is kept for the next time this breaks,
# and it will break again, because it depends on someone else's front end.
#
# IT BROKE AGAIN, THE OTHER WAY ROUND, 2026-09-05. Measured on the real
# machine, one run, one query:
#
#   html over GET   HTTP 202, holding page
#   html over POST  HTTP 200, 28 KB, 8 results parsed
#
# The exact reverse of five days ago. So "use GET" was never the lesson, it
# was one day's weather written down as a rule, and pinning the module to
# either method just picks which day it breaks on.
#
# BOTH ARE TRIED NOW, per endpoint, first one that returns results wins, and
# whichever worked is remembered so the next search does not pay for the
# blocked one again. It costs a second request only when the first fails,
# which is exactly when there is something to gain.
#
# For "what is this address", prefer lookup_ip. A search engine is the wrong
# instrument for a question that has a registry answer.
#
# TODO 8.7, 2026-09-05. THE HOLE THAT WAS LEFT, AND IT WAS A REAL ONE.
#
# The 2026-08-30 work only caught a blocking page that arrives with a
# non-200 status. A holding page that arrives with HTTP 200 went straight
# past it: the parser found nothing in it, no error was recorded, and with
# all three backends doing that the answer fell into the branch that says
# "Search completed but returned no results. This is a genuine empty result,
# not a failure."
#
# So the tool written specifically to stop a block being read as an empty
# internet was producing exactly that sentence, in the shape of failure a
# scraped front end uses most. Nothing was broken in it. It just had one
# failure it could not see, and it answered confidently about it anyway.
#
# WHAT CHANGED. A backend now returns a KIND, not just an optional error, and
# zero results is no longer one thing:
#
#   ok            results came back
#   empty         the page SAYS there were no matches. A real negative.
#   unrecognised  200, and it is not a results page we can read. Could be a
#                 holding page we have no marker for, could be a redesign.
#                 Either way it is not evidence of an empty internet.
#   blocked       a bot or challenge page, by marker or by status code
#   rate_limited / refused / timed_out / unreachable / bad_response
#
# "Genuine empty" is now only returned when EVERY backend said empty in its
# own page. Anything else is reported as unresolved with the kind named. The
# rule underneath it is the one this project keeps arriving at: a tool that
# cannot see must say so rather than answer no.
#
# WHY unrecognised RATHER THAN GUESSING blocked. Calling an unreadable page a
# block is a specific claim about someone else's server made off no evidence,
# and it would hide a DDG redesign behind a wrong diagnosis. The honest answer
# is that the search did not resolve and here is what came back. A holding
# page carrying a marker we DO know is called blocked, because then we have
# actually seen something.

import html as html_mod
import logging
import os
import re
import time

import requests

logger = logging.getLogger(__name__)

DDG_INSTANT_URL = "https://api.duckduckgo.com/"
DDG_HTML_URL    = "https://html.duckduckgo.com/html/"
DDG_LITE_URL    = "https://lite.duckduckgo.com/lite/"
TIMEOUT         = 8
MAX_RESULTS     = 8

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
}

# The vocabulary. One list, so the per-backend record, the top level answer
# and scripts/websearch_check.py all use the same words for the same thing.
OK           = "ok"
EMPTY        = "empty"
UNRECOGNISED = "unrecognised"
BLOCKED      = "blocked"
RATE_LIMITED = "rate_limited"
REFUSED      = "refused"
TIMED_OUT    = "timed_out"
UNREACHABLE  = "unreachable"
BAD_RESPONSE = "bad_response"
# Not a failure. A request deliberately not made, recorded so the attempts
# list does not read as if an endpoint answered nothing. Never the headline,
# so it is not in KIND_PRIORITY.
NOT_TRIED    = "not_tried"

# MINIMUM GAP BETWEEN SEARCHES. Measured 2026-09-05, see TODO 52.9.
#
# Six probes fired back to back got the module challenged on everything. The
# same six probes two seconds apart did not, and the module resolved before
# and after them. So what this address is refused for is RATE, not the number
# of requests, and two seconds of spacing was enough to stay under it.
#
# One search is at most three requests and usually two, so a single search
# does not trip it. What can is the model calling web_search several times in
# a row while it works through a question, and nothing anywhere paced across
# searches. This is that gap.
MIN_SECONDS_BETWEEN_SEARCHES = 2.0

# How long to wait before trying the other method on an endpoint that just
# challenged us. Short enough that a search does not feel stuck, long enough
# that the two requests are not one burst. Not a retry policy, there is only
# ever one wait.
BACKOFF_AFTER_BLOCK = 1.5

# Which kind gets reported when the backends disagree. Ordered by what the
# operator would do about it rather than by severity: a block is a thing to
# act on, an unreadable page is a thing to go and look at, a timeout is a
# thing to retry.
KIND_PRIORITY = [BLOCKED, RATE_LIMITED, REFUSED, UNRECOGNISED,
                 TIMED_OUT, UNREACHABLE, BAD_RESPONSE, EMPTY]

# Which HTTP method to try first against a scraped endpoint with no history.
# GET stays first only because it is the cheaper thing to be wrong about;
# see the header for why neither of them is the answer.
METHOD_ORDER_DEFAULT = ("get", "post")

WHAT_THE_KIND_MEANS = {
    EMPTY:        "the search ran and the page said there were no matches",
    UNRECOGNISED: ("the endpoint answered 200 with something that is not a "
                   "results page we can read. An unmarked holding page and a "
                   "site redesign both look like this, so it is NOT evidence "
                   "that nothing exists"),
    BLOCKED:      "a bot or challenge page came back instead of results",
    RATE_LIMITED: "too many requests, back off and retry later",
    REFUSED:      "the endpoint refused the request outright",
    TIMED_OUT:    f"no answer within {TIMEOUT} seconds",
    UNREACHABLE:  "could not connect at all, check the network",
    BAD_RESPONSE: "the answer arrived but could not be parsed",
    NOT_TRIED:    "not asked, on purpose. See the detail on that row",
}

# Only markers that mean one thing. A page containing the word "captcha" is
# not evidence of a captcha, it is evidence somebody searched for captchas,
# and this list is checked against pages we failed to parse, which is exactly
# when a loose marker would fire on a real results page.
#
# CHECKED AGAINST THE REAL PAGE 2026-09-05, and two of them were wrong.
# websearch_check --dump caught a live DuckDuckGo holding page and it contains
# "bots use duckduckgo", "anomaly.js" and "challenge-form". The list said
# "anomaly.html" and "challenge-platform", both written from memory, neither
# of them in the page. One marker out of three carried the whole detection.
#
# Corrected here from the file rather than from another guess. The generic
# ones are kept because they belong to other providers and cost nothing.
BLOCK_MARKERS = (
    "bots use duckduckgo",          # seen 2026-09-05
    "anomaly.js",                   # seen 2026-09-05, the form it posts to
    "challenge-form",               # seen 2026-09-05
    "cc=botnet",                    # seen 2026-09-05, in the same form action
    "challenge-platform",           # Cloudflare, not seen here
    "captcha-delivery",             # DataDome, not seen here
    "/turnstile/",                  # Cloudflare, not seen here
    "unusual traffic from your computer",
)

# DuckDuckGo's own way of saying nothing matched, on both front ends.
NO_RESULT_MARKERS = (
    "no results found for",
    "no-results",
    "results--message",
    ">no results.",
)

# Markup that means "this IS a results page", used to tell a redesign apart
# from a holding page. Both end up unrecognised, only the detail differs, and
# the detail is what someone reads before deciding where to look.
RESULT_MARKERS = ("result__a", "result-link", "result__snippet", "results.tbl")


# KEYED BACKENDS, 2026-09-06. TODO 53.1.
#
# WHY THESE EXIST. Everything above this line reads somebody else's front end
# with a browser user agent, and that front end does not want to be read that
# way. Two reversals in six days, see 51.5 and 52.9, and by 09-05 the shape of
# the source was one working path out of four with no spare. On 09-06 a real
# answer about a CVE went out saying search was unavailable.
#
# WHAT THEY ARE NOT: a paid service. The owner's call and it is the right one, the
# model is already a bill and the VPN was cut for cost. Every one of these has
# a free tier that needs a key and no card:
#
#   google_cse  100 queries a DAY, and the day resets. More than this app uses.
#   tavily      1000 credits a month, built for agents.
#   serpapi     250 searches a month.
#
# HOW THEY FIT. They are ordinary backends in the same loop, returning the
# same KIND vocabulary, so nothing about 8.7 changes. No key means the backend
# is simply ABSENT, exactly like every keyed enrichment source: never a
# failure row, never a reason for the answer to be unresolved.
#
# THEY GO FIRST, and that is the quiet win. A keyed backend that answers means
# the scraper is never asked, so the requests that were earning us a rate
# limit stop being made at all. The scraper stays as the no-key path, which is
# what somebody cloning this repo gets before they sign up for anything.
KEYED_BACKENDS = {
    "google_cse": {
        "env":       "AGENTAL_GOOGLE_CSE_KEY",
        "also_env":  "AGENTAL_GOOGLE_CSE_CX",
        "free_tier": "100 queries a day, no card",
        "gives":     "Google's own index, through the Programmable Search "
                     "JSON API",
        "signup":    "https://developers.google.com/custom-search/v1/overview "
                     "for the key, https://programmablesearchengine.google.com "
                     "for the engine id. Set the engine to search the whole "
                     "web, or it only searches the sites you list.",
    },
    "tavily": {
        "env":       "AGENTAL_TAVILY_KEY",
        "free_tier": "1000 credits a month, no card",
        "gives":     "a search API built for agents, snippets already "
                     "summarised",
        "signup":    "https://tavily.com",
    },
    "serpapi": {
        "env":       "AGENTAL_SERPAPI_KEY",
        "free_tier": "250 searches a month, no card",
        "gives":     "Google results through a scraping service that carries "
                     "the blocking problem for us",
        "signup":    "https://serpapi.com",
    },
}


def keyed_backend_status() -> list[dict]:
    """
    One row per keyed backend, for the settings panel and the key catalogue.

    Same shape and same rule as enrichment's keyed sources: it reports whether
    a key is present and what its absence costs, and it never returns a value.
    """
    rows = []
    for name, meta in KEYED_BACKENDS.items():
        have = bool(os.environ.get(meta["env"], "").strip())
        also = meta.get("also_env")
        have_also = bool(os.environ.get(also, "").strip()) if also else True
        rows.append({
            "backend":    name,
            "env_var":    meta["env"],
            "also_env":   also,
            "enabled":    have and have_also,
            "free_tier":  meta["free_tier"],
            "would_give": f"{meta['gives']}. Free tier: {meta['free_tier']}.",
            "why_off": (
                "" if have and have_also else
                (f"no {meta['env']} set, so this backend is not asked. "
                 f"Sign up: {meta['signup']}"
                 if not have else
                 f"{also} is not set, so the key alone cannot be used. "
                 f"{meta['signup']}")
            ),
        })
    return rows


def _http_kind(code: int) -> tuple[str, str]:
    """
    Name what a status code means here instead of echoing the number.

    202 is the one that matters. DuckDuckGo answers an automated POST with
    202 Accepted and a 14 KB page that is not results, not an error, not a
    refusal, just a shrug. Measured on the real machine 2026-08-30: both POST
    backends returned 202 while the SAME query over GET returned 200 and 23 KB
    of actual results. The endpoints were never down. We were asking wrong.

    The old message was "HTTP 202", which is true and tells the operator
    nothing about what to do.
    """
    if code == 202:
        return BLOCKED, ("HTTP 202, DuckDuckGo accepted the request and "
                         "returned a holding page instead of results. This is "
                         "its automated-traffic response, not an outage")
    if code == 429:
        return RATE_LIMITED, "HTTP 429, rate limited, back off and retry later"
    if code in (401, 403):
        return REFUSED, f"HTTP {code}, refused outright"
    if code >= 500:
        return UNREACHABLE, f"HTTP {code}, the endpoint is having trouble"
    return UNRECOGNISED, f"HTTP {code}"


def _exception_kind(e: Exception) -> tuple[str, str]:
    """Requests exceptions, named the way an operator would name them."""
    if isinstance(e, requests.Timeout):
        return TIMED_OUT, f"no answer within {TIMEOUT}s"
    if isinstance(e, requests.ConnectionError):
        return UNREACHABLE, f"could not connect ({type(e).__name__})"
    return BAD_RESPONSE, f"{type(e).__name__}"


def _clean(text: str) -> str:
    """Strip tags and decode entities so snippets read as prose."""
    return html_mod.unescape(re.sub(r"<[^>]+>", "", text or "")).strip()


def classify_page(text: str, parsed: int) -> tuple[str, str]:
    """
    A 200 came back and we parsed `parsed` results out of it. What is it?

    Public on purpose. scripts/websearch_check.py runs the same judgement
    against a live fetch, and a diagnostic that classifies pages differently
    from the tool it is diagnosing is worse than no diagnostic.
    """
    if parsed > 0:
        return OK, f"{parsed} results parsed"

    low = (text or "").lower()

    for marker in BLOCK_MARKERS:
        if marker in low:
            return BLOCKED, f"holding page, matched {marker!r}"

    for marker in NO_RESULT_MARKERS:
        if marker in low:
            return EMPTY, "the page says there were no matches"

    if any(m in low for m in RESULT_MARKERS):
        return UNRECOGNISED, ("looks like a results page but nothing parsed "
                              "out of it, so the markup has probably changed")

    return UNRECOGNISED, (f"200 with {len(text or '')} bytes that are not a "
                          f"results page and carry no no-results message")


class WebSearch:

    def __init__(self):
        # Consecutive unresolved searches, and what the last one was. The
        # settings panel readiness row reads status(), and until now this
        # module answered ready: True whatever was happening to it, which is
        # the "quietly stopped working" case 2.3 exists for. Counters only,
        # no query text: a search string can carry anything the model was
        # handed by a packet, and this ends up on a page.
        self._consecutive_unresolved = 0
        self._last_kind = None
        self._last_unresolved_at = None
        self._searches = 0

        # Which HTTP method last WORKED against each scraped endpoint, so the
        # next search starts with it instead of paying for the blocked one
        # again. Only ever set on an answer that produced results, never on a
        # guess, and dropped the moment that method stops working. Empty at
        # start, which means try the default order and find out.
        self._method_hint = {}

        # When the last search STARTED, for the gap above. Monotonic, because
        # the wall clock can jump and a clock change should not turn into a
        # long sleep or a missing one.
        self._last_search_at = 0.0

    def _pace(self) -> float:
        """
        Hold back if the last search was moments ago. Returns seconds waited.

        Deliberately blocking rather than a queue or a token bucket. There is
        one caller, the model, and it is waiting for the answer either way, so
        the simple thing is also the honest one: the wait is visible in the
        response time rather than hidden in a background thread.
        """
        now = time.monotonic()
        gap = now - self._last_search_at
        waited = 0.0
        if self._last_search_at and gap < MIN_SECONDS_BETWEEN_SEARCHES:
            waited = MIN_SECONDS_BETWEEN_SEARCHES - gap
            logger.debug(f"[WebSearch] pacing, waiting {waited:.1f}s")
            time.sleep(waited)
        self._last_search_at = time.monotonic()
        return waited

    def start(self):
        logger.info("WebSearch ready.")

    def status(self) -> dict:
        """
        The readiness row. Ready still means loaded and callable, which is all
        it ever meant. The note is the useful part, because a scraper that is
        being blocked is loaded, callable and useless, and those three words
        on their own hide that.
        """
        keyed = [r["backend"] for r in keyed_backend_status() if r["enabled"]]
        # WHICH BACKENDS ARE ON belongs in the readiness row, because "search
        # is failing" reads completely differently depending on whether the
        # only path left is a scraped one.
        with_keys = (f" Keyed backends on: {', '.join(keyed)}." if keyed else
                     " No keyed backend has a key, so the scraped front end is "
                     "the only path. See KEYED_BACKENDS for three free ones.")

        if self._searches == 0:
            note = "Loaded. No search has run yet this session." + with_keys
        elif self._consecutive_unresolved == 0:
            note = (f"Last search resolved. {self._searches} run this "
                    f"session." + with_keys)
        elif keyed:
            n = self._consecutive_unresolved
            note = (f"The last {n} search{'es' if n > 1 else ''} did not "
                    f"resolve, most recently: {self._last_kind}. A keyed "
                    f"backend is configured, so this is worth looking at "
                    f"rather than shrugging off: check the key and its "
                    f"quota.{with_keys} Read an unresolved search as unknown, "
                    f"never as nothing found.")
        else:
            n = self._consecutive_unresolved
            note = (f"The last {n} search{'es' if n > 1 else ''} did not "
                    f"resolve, most recently: {self._last_kind}. This scrapes "
                    f"someone else's front end, so expect it, and read it as "
                    f"unknown rather than as nothing found." + with_keys)
        return {
            "ready": True,
            "searches_this_session":  self._searches,
            "consecutive_unresolved": self._consecutive_unresolved,
            "last_failure_kind":      self._last_kind,
            "last_unresolved_at":     self._last_unresolved_at,
            "keyed_backends":         keyed,
            "note": note,
        }

    def search(self, query: str) -> dict:
        """
        Returns {query, results, count, engine, searched, failure_kind,
        attempts, error}.

        `searched` distinguishes "the search ran and found nothing" from "the
        search never completed". The old version returned count=0 and
        error=None for both, because every failure path swallowed its
        exception into logger.debug and returned an empty list. That is the
        worst possible shape for this tool: the model asks a question
        precisely when it is unsure, gets an empty answer, and falls back to
        the recall the search was meant to check. An unreachable network must
        look different from an empty result set.

        `failure_kind` is 8.7 part one. Blocked, timed out and genuinely
        nothing there are three different facts and they used to arrive
        looking the same, glued into one prose string the model had to read
        carefully to tell apart. They have names now, and `attempts` carries
        the per-backend record behind the headline.
        """
        if not query or not query.strip():
            return {"query": query, "results": [], "count": 0,
                    "engine": None, "searched": False,
                    "failure_kind": None, "attempts": [],
                    "error": "Empty query"}

        query = query.strip()
        logger.info(f"[WebSearch] {query}")
        self._searches += 1
        self._pace()

        attempts = []

        # KEYED FIRST, SCRAPED AFTER. See KEYED_BACKENDS for why. A backend
        # with no key is not in this list at all, so its absence never shows
        # up as a failed attempt.
        for engine, fn in self._backends():
            results, kind, detail = fn(query)
            attempts.append({"engine": engine, "kind": kind, "detail": detail})

            if results:
                self._consecutive_unresolved = 0
                return {
                    "query":        query,
                    "results":      results[:MAX_RESULTS],
                    "count":        min(len(results), MAX_RESULTS),
                    "engine":       engine,
                    "searched":     True,
                    "failure_kind": None,
                    "attempts":     attempts,
                    "error":        None,
                }

            # STOP DIGGING. 2026-09-05.
            #
            # A scraped endpoint reports BLOCKED only when BOTH its methods
            # were challenged, which is not a fact about that endpoint, it is
            # a fact about this address right now. The other endpoint is the
            # same provider seen from the same IP, so carrying on adds two
            # more challenged requests to a burst that is already the reason
            # we are being challenged.
            #
            # This came out of a real run. The diagnostic probed both
            # endpoints over both methods, got 200 and 8 results out of html
            # twice, and then the module ran straight after and was blocked on
            # everything. Same machine, same query, seconds apart. The most
            # likely reading is that the requests before it earned the block.
            #
            # So the worst case drops from five requests to three, and the
            # cheap instant-answer call still happens first because it is a
            # different host.
            # Scraped endpoints only. The argument is about one provider
            # seeing one address, so it says nothing about a keyed API, and
            # stopping the whole search because a key ran out of quota would
            # skip the backend that still works.
            if (kind in (BLOCKED, RATE_LIMITED)
                    and engine.startswith("ddg_") and engine != "ddg_instant"):
                attempts.append({
                    "engine": "ddg_lite" if engine == "ddg_html" else "(none)",
                    "kind": NOT_TRIED,
                    "kind_meaning": WHAT_THE_KIND_MEANS[NOT_TRIED],
                    "detail": ("skipped on purpose: the previous endpoint was "
                               "challenged on both methods, so this address is "
                               "being rate limited and another request would "
                               "make it worse, not better"),
                })
                break

        kinds = [a["kind"] for a in attempts]

        # THE ONLY PATH THAT MAY CLAIM AN EMPTY INTERNET. Every backend has to
        # have said so in its own page. One unreadable answer in the set is
        # enough to make this unresolved instead, because that backend might
        # have been the one holding the result.
        if kinds and all(k == EMPTY for k in kinds):
            self._consecutive_unresolved = 0
            return {
                "query":        query,
                "results":      [],
                "count":        0,
                "engine":       "ddg",
                "searched":     True,
                "failure_kind": None,
                "attempts":     attempts,
                "error":        None,
                "note": ("Search completed and every backend reported no "
                         "matches in its own page. This is a genuine empty "
                         "result, not a failure."),
            }

        kind = next((k for k in KIND_PRIORITY if k in kinds), UNRECOGNISED)
        self._consecutive_unresolved += 1
        self._last_kind = kind
        self._last_unresolved_at = time.strftime("%Y-%m-%d %H:%M:%S")

        detail = "; ".join(f"{a['engine']}: {a['kind']} ({a['detail']})"
                           for a in attempts)
        logger.warning(f"[WebSearch] unresolved [{kind}] for {query!r}: {detail}")

        return {
            "query":        query,
            "results":      [],
            "count":        0,
            "engine":       None,
            "searched":     False,
            "failure_kind": kind,
            "attempts":     attempts,
            "error": (f"Search did not resolve: {kind}, "
                      f"{WHAT_THE_KIND_MEANS.get(kind, 'no detail')}. "
                      f"Backends: {detail}. Treat this as 'unknown', NOT as "
                      f"'nothing found'. Do not fall back to assumption and "
                      f"present it as verified."),
        }

    # THE BACKEND LIST

    def _backends(self) -> list[tuple]:
        """
        Which backends this install actually has, in the order to ask them.

        Read per search rather than cached at start, so a key pasted into the
        settings panel works on the next question instead of at the next
        restart. The panel already promises 'live' for keys and this is what
        makes that true here.
        """
        keyed = []
        if self._key("google_cse"):
            keyed.append(("google_cse", self._google_cse))
        if self._key("tavily"):
            keyed.append(("tavily", self._tavily))
        if self._key("serpapi"):
            keyed.append(("serpapi", self._serpapi))

        return keyed + [
            ("ddg_instant", self._instant_answer),
            ("ddg_html",    self._html_search),
            ("ddg_lite",    self._lite_search),
        ]

    @staticmethod
    def _key(backend: str) -> str:
        """The key for a keyed backend, or empty. Never logged, never returned."""
        meta = KEYED_BACKENDS[backend]
        value = os.environ.get(meta["env"], "").strip()
        also  = meta.get("also_env")
        if also and not os.environ.get(also, "").strip():
            # Half a credential is not a credential. Google needs both a key
            # and an engine id, and asking with one of them produces a 400
            # that reads like the service being broken.
            return ""
        return value

    def _keyed_call(self, engine: str, fn) -> tuple[list[dict], str, str]:
        """
        Run one keyed backend and turn whatever happened into the vocabulary.

        THE POINT OF THE WRAPPER is that a keyed API fails in different words
        from a scraped page, and those words have to land on the same kinds.
        A quota that ran out is RATE_LIMITED, a key that is wrong is REFUSED,
        and neither of them is EMPTY, because EMPTY is a claim about the
        internet and these are claims about our account.
        """
        try:
            resp = fn()
        except Exception as e:
            kind, detail = _exception_kind(e)
            return [], kind, detail

        if resp.status_code == 429:
            return [], RATE_LIMITED, ("the free tier for this key is used up "
                                      "for now, or the requests were too "
                                      "fast. Nothing is wrong with the key")
        if resp.status_code in (401, 403):
            return [], REFUSED, (f"HTTP {resp.status_code}, the key was "
                                 f"refused or its quota is exhausted. Check "
                                 f"{KEYED_BACKENDS[engine]['env']}")
        if resp.status_code != 200:
            return [], *_http_kind(resp.status_code)

        try:
            payload = resp.json()
        except Exception:
            return [], BAD_RESPONSE, "the answer was 200 but not JSON"

        results = self._parse_keyed(engine, payload)
        if results:
            return results, OK, f"{len(results)} results"

        # An empty from a keyed API IS an empty. It answered, it has an index,
        # and it said nothing matched. That is the one thing the scraped path
        # can almost never establish on its own.
        return [], EMPTY, "the API answered and returned no matches"

    @staticmethod
    def _parse_keyed(engine: str, payload: dict) -> list[dict]:
        """Three JSON shapes, one result shape. Nothing clever."""
        out = []
        if engine == "google_cse":
            rows = payload.get("items") or []
            for r in rows[:MAX_RESULTS]:
                out.append({"title":   _clean(r.get("title")),
                            "url":     r.get("link") or "",
                            "snippet": _clean(r.get("snippet"))})
        elif engine == "tavily":
            rows = payload.get("results") or []
            for r in rows[:MAX_RESULTS]:
                out.append({"title":   _clean(r.get("title")),
                            "url":     r.get("url") or "",
                            "snippet": _clean(r.get("content"))})
        elif engine == "serpapi":
            rows = payload.get("organic_results") or []
            for r in rows[:MAX_RESULTS]:
                out.append({"title":   _clean(r.get("title")),
                            "url":     r.get("link") or "",
                            "snippet": _clean(r.get("snippet"))})
        return [r for r in out if r["url"] and r["title"]]

    def _google_cse(self, query: str) -> tuple[list[dict], str, str]:
        """Programmable Search JSON API. 100 a day, and the day resets."""
        return self._keyed_call("google_cse", lambda: requests.get(
            "https://www.googleapis.com/customsearch/v1",
            params={
                "key": os.environ.get("AGENTAL_GOOGLE_CSE_KEY", "").strip(),
                "cx":  os.environ.get("AGENTAL_GOOGLE_CSE_CX", "").strip(),
                "q":   query,
                "num": min(MAX_RESULTS, 10),
            },
            timeout=TIMEOUT,
        ))

    def _tavily(self, query: str) -> tuple[list[dict], str, str]:
        """Tavily. The key goes in a header, not the query string."""
        return self._keyed_call("tavily", lambda: requests.post(
            "https://api.tavily.com/search",
            json={"query": query, "max_results": MAX_RESULTS},
            headers={"Authorization":
                     f"Bearer {os.environ.get('AGENTAL_TAVILY_KEY', '').strip()}",
                     "Content-Type": "application/json"},
            timeout=TIMEOUT,
        ))

    def _serpapi(self, query: str) -> tuple[list[dict], str, str]:
        """SerpAPI. Somebody else takes the scraping problem, for 250 a month."""
        return self._keyed_call("serpapi", lambda: requests.get(
            "https://serpapi.com/search.json",
            params={
                "api_key": os.environ.get("AGENTAL_SERPAPI_KEY", "").strip(),
                "q":       query,
                "engine":  "google",
                "num":     MAX_RESULTS,
            },
            timeout=TIMEOUT,
        ))

    def _instant_answer(self, query: str) -> tuple[list[dict], str, str]:
        """
        The instant-answer API is a disambiguation service, not an index, so
        it legitimately has nothing for most queries. Its empty IS an empty
        for this backend, and that is exactly why the genuine-empty branch
        above needs all three to agree rather than trusting any one of them.
        """
        try:
            resp = requests.get(
                DDG_INSTANT_URL,
                params={"q": query, "format": "json", "no_html": "1"},
                headers=HEADERS, timeout=TIMEOUT,
            )
            if resp.status_code != 200:
                kind, detail = _http_kind(resp.status_code)
                return [], kind, detail

            data = resp.json()
            results = []

            if data.get("AbstractText"):
                results.append({
                    "title":   data.get("Heading", query),
                    "url":     data.get("AbstractURL", ""),
                    "snippet": data.get("AbstractText", ""),
                })

            for topic in data.get("RelatedTopics", [])[:5]:
                if "Text" in topic and "FirstURL" in topic:
                    results.append({
                        "title":   topic["Text"][:80],
                        "url":     topic["FirstURL"],
                        "snippet": topic["Text"],
                    })

            if results:
                return results, OK, f"{len(results)} results parsed"
            return [], EMPTY, "the instant-answer API had no entry for this"
        except requests.RequestException as e:
            kind, detail = _exception_kind(e)
            return [], kind, detail
        except ValueError as e:
            return [], BAD_RESPONSE, f"bad JSON ({e})"

    def _method_order(self, url: str) -> tuple:
        """Whichever method last worked here, then the other one."""
        hint = self._method_hint.get(url)
        if hint == "post":
            return ("post", "get")
        return METHOD_ORDER_DEFAULT

    def _fetch_scraped(self, url: str, params: dict, parse) -> tuple[list, str, str]:
        """
        Ask one scraped endpoint, over both HTTP methods if it takes it.

        WHY BOTH. See the header. On 2026-08-30 POST was challenged and GET
        worked; on 2026-09-05 GET was challenged and POST worked, same
        endpoint, same query. Neither method is the right one, and a module
        pinned to either just picks which day it goes dark on. This tries the
        remembered good one first, falls back to the other, and remembers a
        method only when it actually returned results.

        The second request costs a round trip and only happens when the first
        failed, which is exactly when the round trip is worth something.
        """
        attempts = []

        for i, method in enumerate(self._method_order(url)):
            # Wait before the second try if the first was challenged. Firing
            # the fallback immediately makes the pair look like one burst,
            # which is the shape being refused in the first place.
            if i and attempts and attempts[-1][1] in (BLOCKED, RATE_LIMITED):
                time.sleep(BACKOFF_AFTER_BLOCK)
            try:
                if method == "get":
                    resp = requests.get(url, params=params,
                                        headers=HEADERS, timeout=TIMEOUT)
                else:
                    # POST wants the same fields as form data rather than as a
                    # query string. Same query, different envelope.
                    resp = requests.post(url, data=params,
                                         headers=HEADERS, timeout=TIMEOUT)
            except requests.RequestException as e:
                kind, detail = _exception_kind(e)
                attempts.append((method, kind, detail))
                continue

            if resp.status_code != 200:
                kind, detail = _http_kind(resp.status_code)
                attempts.append((method, kind, detail))
                continue

            results = parse(resp.text)
            kind, detail = classify_page(resp.text, len(results))
            attempts.append((method, kind, detail))

            if results:
                self._method_hint[url] = method
                return results, kind, f"over {method.upper()}, {detail}"

        # Nothing came back with results. Drop any hint: whatever is stored
        # is no longer working, and a stale hint costs a wasted first request
        # on every search from here on.
        self._method_hint.pop(url, None)

        kinds = [k for _, k, _ in attempts]
        # AN EMPTY PAGE WINS OVER A BLOCK. If one method was challenged and
        # the other came back with DuckDuckGo's own "no results" page, we did
        # get an answer to the question, and it was no. The page that answered
        # is the authority; the one that refused to talk is not evidence about
        # anything except itself.
        if EMPTY in kinds:
            kind = EMPTY
        else:
            kind = next((k for k in KIND_PRIORITY if k in kinds), UNRECOGNISED)

        detail = "; ".join(f"{m.upper()}: {k} ({d})" for m, k, d in attempts)
        return [], kind, detail

    def _html_search(self, query: str) -> tuple[list[dict], str, str]:
        return self._fetch_scraped(DDG_HTML_URL, {"q": query, "kl": "us-en"},
                                   self._parse_html)

    def _lite_search(self, query: str) -> tuple[list[dict], str, str]:
        """
        The lite endpoint renders a plain table and survives markup changes
        that break the class-name parsing above. Kept as a second shot so a
        DDG redesign degrades this tool instead of silently emptying it.

        NOTE 2026-09-05: on the run that found the GET/POST reversal, lite
        answered 200 with 23 KB and this parser got nothing out of it, which
        is reported as unrecognised. So the second shot is currently not a
        second shot. Fixing it needs the actual page, not a guess at the
        markup, and scripts/websearch_check.py --dump is there to get one.
        """
        return self._fetch_scraped(DDG_LITE_URL, {"q": query, "kl": "us-en"},
                                   self._parse_lite)

    @staticmethod
    def _parse_lite(text: str) -> list[dict]:
        """Every off-site link on the lite page, in order."""
        results = []
        for m in re.finditer(
            r'<a[^>]+href="(https?://[^"]+)"[^>]*>(.*?)</a>', text, re.DOTALL
        ):
            url, title = m.group(1), _clean(m.group(2))
            if not title or "duckduckgo.com" in url:
                continue
            results.append({"title": title[:120], "url": url, "snippet": ""})
            if len(results) >= MAX_RESULTS:
                break
        return results

    def _parse_html(self, text: str) -> list[dict]:
        """
        Parse the html endpoint. Two patterns: the paired title+snippet form
        first, then a title-only fallback, because DDG has changed these class
        names before and a single brittle regex is how this tool would go
        quietly empty again.
        """
        results = []

        paired = re.compile(
            r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>.*?'
            r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>',
            re.DOTALL,
        )
        for m in paired.finditer(text):
            url, title, snippet = m.group(1), _clean(m.group(2)), _clean(m.group(3))
            if url and title:
                results.append({"title": title, "url": url, "snippet": snippet})
            if len(results) >= MAX_RESULTS:
                return results

        if results:
            return results

        loose = re.compile(r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
                           re.DOTALL)
        for m in loose.finditer(text):
            url, title = m.group(1), _clean(m.group(2))
            if url and title:
                results.append({"title": title, "url": url, "snippet": ""})
            if len(results) >= MAX_RESULTS:
                break

        return results
