"""
tests/test_web_search_failure_kind.py, TODO 8.7, 2026-09-05.

THE BUG THIS EXISTS FOR.

web_search was written to stop a block being read as an empty internet. It
caught a block that arrives with a non-200 status and missed the one that
arrives with HTTP 200 and a holding page: nothing parsed out of it, no error
recorded, and the answer landed in the branch that says "This is a genuine
empty result, not a failure."

So the load-bearing check has to be the negative one. A page that is not a
results page must NEVER come back as a genuine empty, whatever it looks like.

No network. Every case here is a fixed page handed to the classifier, or a
fake requests.get. A test that needs DuckDuckGo to be up tests DuckDuckGo.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import web_search as ws

# The module waits before retrying an endpoint that just challenged it, which
# is right in production and is 13 seconds of nothing in a test. Zeroed here,
# and section 5 asserts the real value is still a real value, so turning it
# off for the test cannot quietly turn it off for good.
REAL_BACKOFF = ws.BACKOFF_AFTER_BLOCK
ws.BACKOFF_AFTER_BLOCK = 0
REAL_GAP = ws.MIN_SECONDS_BETWEEN_SEARCHES
ws.MIN_SECONDS_BETWEEN_SEARCHES = 0

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


# The page that caused this. A real DDG anomaly page is longer, the marker is
# the part that matters and the rest is padding.
HOLDING_PAGE = """<!DOCTYPE html><html><head><title>DuckDuckGo</title></head>
<body><div class="anomaly-modal__title">Unfortunately, bots use DuckDuckGo too.
</div><p>Please try again later.</p></body></html>"""

# 200, not a results page, and carrying no marker we know. This is the shape
# a NEW holding page arrives in, and it is the one that must still not be
# called empty.
UNMARKED_PAGE = """<!DOCTYPE html><html><head><title>Just a moment</title></head>
<body><p>Checking your browser before you continue.</p></body></html>"""

REAL_NO_RESULTS = """<html><body><div class="results--message">
No results found for that query.</div></body></html>"""

REAL_RESULTS = """<html><body>
<a class="result__a" href="https://example.com/one">First hit</a>
<a class="result__snippet">a snippet about the first hit</a>
<a class="result__a" href="https://example.com/two">Second hit</a>
<a class="result__snippet">a snippet about the second hit</a>
</body></html>"""

# Results page markup we cannot parse. A redesign, not a block, and the two
# must not be reported as the same thing.
REDESIGNED = """<html><body><ol><li class="result__a-new">
<a href="https://example.com">something</a></li></ol>
<span class="result__snippet"></span></body></html>"""


print("\n[1] the classifier tells the four cases apart")
check("real results parse", ws.classify_page(REAL_RESULTS, 2)[0], ws.OK)
check("a known holding page is BLOCKED",
      ws.classify_page(HOLDING_PAGE, 0)[0], ws.BLOCKED)
check("a real no-results page is EMPTY",
      ws.classify_page(REAL_NO_RESULTS, 0)[0], ws.EMPTY)
check("an unmarked non-results page is UNRECOGNISED, not empty",
      ws.classify_page(UNMARKED_PAGE, 0)[0], ws.UNRECOGNISED)
check("a redesign is UNRECOGNISED too",
      ws.classify_page(REDESIGNED, 0)[0], ws.UNRECOGNISED)

# The one that would have caught the original bug on its own.
check("NOTHING unparseable is ever called EMPTY",
      [ws.classify_page(p, 0)[0] for p in (HOLDING_PAGE, UNMARKED_PAGE, REDESIGNED)],
      [ws.BLOCKED, ws.UNRECOGNISED, ws.UNRECOGNISED])

check("a redesign says where to look",
      "markup" in ws.classify_page(REDESIGNED, 0)[1], True)


print("\n[2] status codes get a kind, not just a number")
check("202 is a block, which is the whole 2026-08-30 lesson",
      ws._http_kind(202)[0], ws.BLOCKED)
check("429 is rate limited", ws._http_kind(429)[0], ws.RATE_LIMITED)
check("403 is refused", ws._http_kind(403)[0], ws.REFUSED)
check("503 is unreachable", ws._http_kind(503)[0], ws.UNREACHABLE)


print("\n[3] end to end, with the network faked")


class FakeResponse:
    def __init__(self, code, text="", payload=None):
        self.status_code = code
        self.text = text
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


def with_fake_get(fn):
    """
    Swap BOTH requests.get and requests.post for one search.

    Both, because since 2026-09-05 a scraped endpoint that fails over one
    method retries over the other. Patching only get left the fallback
    reaching the real internet from inside a unit test, which is slow, flaky
    and exactly the kind of thing that gets a test suite ignored.
    """
    real_get, real_post = ws.requests.get, ws.requests.post
    ws.requests.get = fn
    ws.requests.post = lambda url, data=None, **kw: fn(url, **kw)
    try:
        return ws.WebSearch().search("what is 192.0.2.1")
    finally:
        ws.requests.get, ws.requests.post = real_get, real_post


def all_pages(page):
    def fake(url, **kw):
        if url == ws.DDG_INSTANT_URL:
            return FakeResponse(200, payload={})
        return FakeResponse(200, text=page)
    return fake


# THE REGRESSION. Instant has nothing (normal), both scraped endpoints return
# a 200 holding page. Before today this answered "genuine empty result".
out = with_fake_get(all_pages(HOLDING_PAGE))
check("a 200 holding page does NOT report as searched", out["searched"], False)
check("and names the kind", out["failure_kind"], ws.BLOCKED)
check("and does not say genuine empty", "genuine empty" in (out.get("note") or ""), False)
check("and tells the model to treat it as unknown",
      "NOT as 'nothing found'" in out["error"], True)
check("and every backend is recorded", len(out["attempts"]), 3)

out = with_fake_get(all_pages(UNMARKED_PAGE))
check("an unmarked 200 page is unresolved too", out["searched"], False)
check("reported honestly as unrecognised, not guessed as blocked",
      out["failure_kind"], ws.UNRECOGNISED)

# The genuine empty still has to work, or the fix has just made the tool
# unable to report a true negative, which is its own kind of dishonesty.
def real_empty(url, **kw):
    if url == ws.DDG_INSTANT_URL:
        return FakeResponse(200, payload={})
    return FakeResponse(200, text=REAL_NO_RESULTS)

out = with_fake_get(real_empty)
check("all three saying no matches IS a genuine empty", out["searched"], True)
check("with no failure kind", out["failure_kind"], None)
check("and it says so", "genuine empty" in out["note"], True)

# One readable backend is enough. The instant API having nothing must not
# drag a good answer down.
def one_good(url, **kw):
    if url == ws.DDG_INSTANT_URL:
        return FakeResponse(200, payload={})
    if url == ws.DDG_HTML_URL:
        return FakeResponse(200, text=REAL_RESULTS)
    return FakeResponse(200, text=UNMARKED_PAGE)

out = with_fake_get(one_good)
check("results win over an empty instant answer", out["searched"], True)
check("count", out["count"], 2)
check("engine named", out["engine"], "ddg_html")

# Mixed failures report the one worth acting on.
def mixed(url, **kw):
    if url == ws.DDG_INSTANT_URL:
        return FakeResponse(429)
    if url == ws.DDG_HTML_URL:
        return FakeResponse(200, text=UNMARKED_PAGE)
    return FakeResponse(200, text=HOLDING_PAGE)

out = with_fake_get(mixed)
check("blocked outranks rate limited and unrecognised",
      out["failure_kind"], ws.BLOCKED)


print("\n[3b] both HTTP methods get tried, because either can be the blocked one")
# Measured on the real machine 2026-09-05: html over GET came back 202 with a
# holding page while the SAME query over POST came back 200 with 8 results.
# The exact reverse of 2026-08-30. So the module must not be pinned to either.


def get_blocked_post_works(url, **kw):
    """GET is challenged everywhere, POST answers on the html endpoint."""
    if url == ws.DDG_INSTANT_URL:
        return FakeResponse(200, payload={})
    return FakeResponse(202, text=HOLDING_PAGE)


def post_works(url, data=None, **kw):
    if url == ws.DDG_HTML_URL:
        return FakeResponse(200, text=REAL_RESULTS)
    return FakeResponse(200, text=HOLDING_PAGE)


real = ws.requests.get
real_post = ws.requests.post
ws.requests.get = get_blocked_post_works
ws.requests.post = post_works
try:
    w = ws.WebSearch()
    out = w.search("what is 192.0.2.1")
finally:
    ws.requests.get = real
    ws.requests.post = real_post

check("the POST fallback rescues a blocked GET", out["searched"], True)
check("results came through", out["count"], 2)
check("and the record says which method worked",
      "over POST" in [a["detail"] for a in out["attempts"] if a["kind"] == ws.OK][0],
      True)
check("the working method is remembered for next time",
      w._method_hint.get(ws.DDG_HTML_URL), "post")


# An empty page beats a block. If one method is challenged and the other
# returns DDG's own no-results page, we did get an answer and it was no.
def get_blocked_post_empty(url, **kw):
    if url == ws.DDG_INSTANT_URL:
        return FakeResponse(200, payload={})
    return FakeResponse(202, text=HOLDING_PAGE)


def post_empty(url, data=None, **kw):
    return FakeResponse(200, text=REAL_NO_RESULTS)


ws.requests.get = get_blocked_post_empty
ws.requests.post = post_empty
try:
    out = ws.WebSearch().search("nothing matches this")
finally:
    ws.requests.get = real
    ws.requests.post = real_post

check("a real no-results page outranks the blocked method", out["searched"], True)
check("and it reports as a genuine empty", out["failure_kind"], None)


# A hint that stops working must not cost a wasted first request forever.
ws.requests.get = get_blocked_post_works
ws.requests.post = post_works
try:
    w = ws.WebSearch()
    w.search("first")
    check("hint set after a win", w._method_hint.get(ws.DDG_HTML_URL), "post")
    ws.requests.post = lambda url, data=None, **kw: FakeResponse(202, text=HOLDING_PAGE)
    w.search("second")
    check("hint dropped once nothing works",
          ws.DDG_HTML_URL in w._method_hint, False)
finally:
    ws.requests.get = real
    ws.requests.post = real_post


print("\n[4] the readiness row stops saying 'ready' and nothing else")
w = ws.WebSearch()
check("before any search", "No search has run yet" in w.status()["note"], True)

real, real_post2 = ws.requests.get, ws.requests.post
ws.requests.get = all_pages(HOLDING_PAGE)
ws.requests.post = lambda url, data=None, **kw: all_pages(HOLDING_PAGE)(url, **kw)
try:
    w.search("one")
    w.search("two")
finally:
    ws.requests.get, ws.requests.post = real, real_post2

check("consecutive count", w.status()["consecutive_unresolved"], 2)
check("last kind surfaced", w.status()["last_failure_kind"], ws.BLOCKED)
check("and the note says it plainly",
      "did not resolve" in w.status()["note"], True)
check("no query text in the row, it can carry anything a packet handed us",
      "one" in str(w.status()) and "two" in str(w.status()), False)



print("\n[5] the block markers were checked against a REAL holding page")
# websearch_check --dump caught one on 2026-09-05. Two of the markers in the
# list had been written from memory and were not in it: the page says
# "anomaly.js" and "challenge-form", the list said "anomaly.html" and
# "challenge-platform". One marker out of three was carrying the detection.
#
# This is a fragment of that page, kept so the correction cannot be undone by
# somebody tidying the list later.
REAL_DDG_BLOCK_PAGE = """<!DOCTYPE html><html lang="en"><head>
<link rel="canonical" href="https://duckduckgo.com/"></head><body>
<iframe name="ifr" border="0" class="hidden"></iframe>
<form id="img-form" action="//duckduckgo.com/anomaly.js?sv=lite&cc=botnet&ti=1"
 target="ifr" method="POST"></form>
<form id="challenge-form" action="//duckduckgo.com/anomaly.js?sv=lite&cc=botnet"
 target="ifr" method="POST"></form>
<p>Unfortunately, bots use DuckDuckGo too. Please try again later.</p>
</body></html>"""

check("the real page classifies as blocked",
      ws.classify_page(REAL_DDG_BLOCK_PAGE, 0)[0], ws.BLOCKED)
hits = [m for m in ws.BLOCK_MARKERS if m in REAL_DDG_BLOCK_PAGE.lower()]
check("and more than one marker catches it, not just the lucky one",
      len(hits) >= 3, True)
check("the guessed anomaly.html is gone", "anomaly.html" in ws.BLOCK_MARKERS, False)
check("the real anomaly.js is in", "anomaly.js" in ws.BLOCK_MARKERS, True)
check("and challenge-form", "challenge-form" in ws.BLOCK_MARKERS, True)

# The backoff is zeroed at the top of this file so the test does not sleep.
# This is the check that stops that from becoming permanent.
check("the real backoff is a real wait", REAL_BACKOFF >= 1, True)
check("and so is the gap between searches", REAL_GAP >= 1, True)

# The pacing itself, measured rather than assumed, with the real value put
# back for the length of one check. 2026-09-05: six requests back to back got
# this address challenged and the same six spaced two seconds apart did not,
# so what gets refused is rate. A single search is two or three requests and
# is fine; several searches in a row is the case this covers.
import time as _time                              # noqa: E402
ws.MIN_SECONDS_BETWEEN_SEARCHES = 0.4
_w = ws.WebSearch()
check("the first search does not wait", _w._pace() < 0.05, True)
_started = _time.monotonic()
_waited = _w._pace()
check("the second one does", _waited > 0.2, True)
check("and it actually slept, not just reported it",
      _time.monotonic() - _started > 0.2, True)
_time.sleep(0.5)
check("a search after a real gap is not delayed again", _w._pace() < 0.05, True)
ws.MIN_SECONDS_BETWEEN_SEARCHES = 0


print("\n[6] a challenged address is not hit again on the next endpoint")
# 2026-09-05. The diagnostic probed both endpoints over both methods, got two
# clean 200s out of html, and the module ran seconds later and was blocked on
# everything. The requests before it are the likeliest reason. So once one
# scraped endpoint is challenged on BOTH methods, the next one is not asked:
# that is the same provider seen from the same address, and another request
# makes the burst worse rather than answering the question.
calls = []


def counted(url, **kw):
    calls.append(url)
    if url == ws.DDG_INSTANT_URL:
        return FakeResponse(200, payload={})
    return FakeResponse(202, text=HOLDING_PAGE)


real_g, real_p = ws.requests.get, ws.requests.post
ws.requests.get = counted
ws.requests.post = lambda url, data=None, **kw: counted(url, **kw)
try:
    out = ws.WebSearch().search("anything at all")
finally:
    ws.requests.get, ws.requests.post = real_g, real_p

check("lite was never asked", ws.DDG_LITE_URL in calls, False)
check("three requests, not five", len(calls), 3)
check("still reported as blocked", out["failure_kind"], ws.BLOCKED)
check("and the skip is on the record, not silent",
      any(a["kind"] == ws.NOT_TRIED for a in out["attempts"]), True)
check("the skipped row says why",
      "make it worse" in [a["detail"] for a in out["attempts"]
                          if a["kind"] == ws.NOT_TRIED][0], True)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
