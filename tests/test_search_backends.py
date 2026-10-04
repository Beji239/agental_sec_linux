"""
tests/test_search_backends.py, TODO 53.1, the free keyed backends.

THE DECISION THIS IS BUILT ON, 2026-09-06. No paid search API. The model is
already a bill and the paid VPN was cut for exactly this reason, so the answer
to a scraped front end that keeps changing its mind is not a third bill, it is
free tiers with a key and no card.

WHAT MATTERS HERE, and none of it is "does Google answer":
  no key means the backend is ABSENT, never a failure row
  a key means it is asked FIRST, so the scraper is not asked at all
  a quota that ran out is rate_limited, a bad key is refused, neither is empty
  the scraped stop-digging rule does not stop a keyed backend
  and no key value ever leaves the module

Nothing here reaches the network. Every backend is faked, because a test that
needs a live API is a test that goes red when somebody else has an outage.
"""
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


from core import web_search as ws                # noqa: E402


class FakeResponse:
    def __init__(self, code=200, payload=None):
        self.status_code = code
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


def clear_keys():
    for meta in ws.KEYED_BACKENDS.values():
        os.environ.pop(meta["env"], None)
        if meta.get("also_env"):
            os.environ.pop(meta["also_env"], None)


clear_keys()


print("\n[1] with no key, a backend is absent rather than failing")
w = ws.WebSearch()
names = [n for n, _ in w._backends()]
check("only the scraped path is listed",
      names, ["ddg_instant", "ddg_html", "ddg_lite"])
rows = {r["backend"]: r for r in ws.keyed_backend_status()}
check("the panel row says it is off", rows["tavily"]["enabled"], False)
check("and says how to turn it on",
      "tavily.com" in rows["tavily"]["why_off"], True)


print("\n[2] a key puts the backend FIRST, ahead of the scraper")
# This is the quiet win. A keyed backend that answers means the requests that
# were earning us a rate limit are never made.
os.environ["AGENTAL_TAVILY_KEY"] = "tvly-not-a-real-key"
w = ws.WebSearch()
names = [n for n, _ in w._backends()]
check("tavily is asked first", names[0], "tavily")
check("and the scraper is still there behind it",
      names[-3:], ["ddg_instant", "ddg_html", "ddg_lite"])


print("\n[3] half a credential is not a credential")
# Google needs a key AND an engine id. Asking with one of them produces a 400
# that reads like the service being broken, which is the wrong thing to teach
# somebody who has just pasted a key in.
os.environ["AGENTAL_GOOGLE_CSE_KEY"] = "AIza-not-a-real-key"
w = ws.WebSearch()
check("the key alone does not enable it",
      "google_cse" in [n for n, _ in w._backends()], False)
os.environ["AGENTAL_GOOGLE_CSE_CX"] = "0123:abcd"
w = ws.WebSearch()
check("the pair does", "google_cse" in [n for n, _ in w._backends()], True)
check("and google goes before tavily, because its quota resets daily",
      [n for n, _ in w._backends()][:2], ["google_cse", "tavily"])


print("\n[4] the API's failures land on the right words")
w = ws.WebSearch()

results, kind, detail = w._keyed_call("tavily", lambda: FakeResponse(429))
check("a used up quota is rate_limited", kind, ws.RATE_LIMITED)
check("and does not blame the key",
      "nothing is wrong with the key" in detail.lower(), True)

results, kind, _ = w._keyed_call("tavily", lambda: FakeResponse(401))
check("a bad key is refused", kind, ws.REFUSED)

# THE ONE THAT MATTERS. An API that answered and found nothing is the one
# thing the scraped path can almost never establish, so it has to be EMPTY
# and not unresolved.
results, kind, _ = w._keyed_call("tavily",
                                 lambda: FakeResponse(200, {"results": []}))
check("an answered nothing is empty", kind, ws.EMPTY)

results, kind, _ = w._keyed_call(
    "tavily", lambda: FakeResponse(200, {"results": [
        {"title": "a page", "url": "https://example.com/a", "content": "text"},
    ]}))
check("results come back parsed", kind, ws.OK)
check("in the same shape as every other backend",
      sorted(results[0]), ["snippet", "title", "url"])


print("\n[5] the three JSON shapes are read correctly")
g = ws.WebSearch._parse_keyed("google_cse", {"items": [
    {"title": "g", "link": "https://example.com/g", "snippet": "s"}]})
check("google", g, [{"title": "g", "url": "https://example.com/g",
                     "snippet": "s"}])
t = ws.WebSearch._parse_keyed("tavily", {"results": [
    {"title": "t", "url": "https://example.com/t", "content": "s"}]})
check("tavily", t, [{"title": "t", "url": "https://example.com/t",
                     "snippet": "s"}])
sp = ws.WebSearch._parse_keyed("serpapi", {"organic_results": [
    {"title": "s", "link": "https://example.com/s", "snippet": "s"}]})
check("serpapi", sp, [{"title": "s", "url": "https://example.com/s",
                       "snippet": "s"}])
check("a row with no url is dropped rather than half rendered",
      ws.WebSearch._parse_keyed("tavily", {"results": [{"title": "x"}]}), [])


print("\n[6] a keyed answer means the scraper is never asked")
w = ws.WebSearch()
asked = []


def fake_backend(name, results, kind):
    def fn(query):
        asked.append(name)
        return results, kind, "fake"
    return fn


w._backends = lambda: [
    ("google_cse", fake_backend("google_cse",
                                [{"title": "t", "url": "u", "snippet": ""}],
                                ws.OK)),
    ("ddg_html", fake_backend("ddg_html", [], ws.BLOCKED)),
]
answer = w.search("anything")
check("it answered", answer["count"], 1)
check("from the keyed backend", answer["engine"], "google_cse")
check("and the scraper was never called", asked, ["google_cse"])


print("\n[7] a blocked keyed backend does not stop the search")
# The stop-digging rule is about one provider seeing one address. Applying it
# to a keyed API would skip the backend that still works.
asked.clear()
w = ws.WebSearch()
w._backends = lambda: [
    ("google_cse", fake_backend("google_cse", [], ws.RATE_LIMITED)),
    ("tavily", fake_backend("tavily",
                            [{"title": "t", "url": "u", "snippet": ""}],
                            ws.OK)),
]
answer = w.search("anything")
check("the next backend was still asked", asked, ["google_cse", "tavily"])
check("and it answered", answer["engine"], "tavily")


print("\n[8] no key value ever leaves the module")
os.environ["AGENTAL_TAVILY_KEY"] = "test-secret-value-here"
blob = repr(ws.keyed_backend_status()) + repr(ws.WebSearch().status())
check("not in the panel rows or the readiness note",
      "test-secret-value-here" in blob, False)
check("the readiness note does name which backends are on",
      "tavily" in ws.WebSearch().status()["note"], True)

clear_keys()

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
