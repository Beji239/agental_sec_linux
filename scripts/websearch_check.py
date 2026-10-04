"""
scripts/websearch_check.py

Why does web_search keep saying it did not complete?

The module already reports honestly, it distinguishes "ran and found
nothing" from "never completed", which is the right shape and was clearly
built on purpose. What it does NOT say is which backend failed and how, and
without that there is nothing to fix.

This calls each DuckDuckGo endpoint directly, prints the raw status and the
first part of the body, and then runs the real WebSearch class so you can see
what the model actually received.

    python scripts/websearch_check.py
    python scripts/websearch_check.py "some other query"
    python scripts/websearch_check.py --dump

--dump writes each 200 body to logs/websearch_<n>.html. Added 2026-09-05,
because that run turned up a page this tool could see was wrong and could not
say why: lite answered 200 with 23 KB and the parser got nothing out of it.
UNRECOGNISED is the honest report and it is not a fix, and a parser rewritten
from a guess about markup nobody looked at is worse than the broken one. Dump
it, read it, then change the regex.

logs/ is gitignored and holds real traffic already, so a search results page
is not a new class of thing to leave there.

Read-only apart from --dump. Touches nothing but the network.
"""

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import requests  # noqa: E402
from core import web_search as ws  # noqa: E402

args  = [a for a in sys.argv[1:] if a != "--dump"]
DUMP  = "--dump" in sys.argv
QUERY = args[0] if args else "77.111.246.27 Hern Labs AB"
DUMP_DIR = ROOT / "logs"

# Gap between the raw probes. Six back to back is a burst, and a burst is what
# gets challenged, so an unpaced diagnostic measures its own impatience.
PAUSE = 2.0


def line():
    print("=" * 68)


def dump(n, name, text):
    """Write one body to logs/ so a parser can be fixed from the real page."""
    try:
        DUMP_DIR.mkdir(exist_ok=True)
        path = DUMP_DIR / f"websearch_{n}.html"
        path.write_text(text, encoding="utf-8", errors="replace")
        print(f"  dumped {len(text):,} bytes to {path}")
    except OSError as e:
        print(f"  could not dump: {e}")


def show(n, name, fn, parser=None):
    """
    2026-09-05: this used to make its own judgement about each page, in its
    own wording. web_search.classify_page decides now and this calls it,
    because a diagnostic that classifies a page differently from the tool it
    is diagnosing sends you looking in the wrong place.

    `parser` is the module's own parser for that endpoint, so the parsed count
    handed to classify_page is the real one rather than an assumed zero.
    """
    print(f"\n{n}. {name}")
    if n > 1:
        time.sleep(PAUSE)
    try:
        r = fn()
        print(f"  HTTP {r.status_code}   {len(r.text):,} bytes")

        if r.status_code != 200:
            kind, detail = ws._http_kind(r.status_code)
            print(f"  {kind.upper():<14}{detail}")
            print(f"  body: {r.text[:200].replace(chr(10), ' ')}")
            if DUMP:
                dump(n, name, r.text)
            return r.status_code

        if parser is not None:
            parsed = len(parser(r.text))
            kind, detail = ws.classify_page(r.text, parsed)
            print(f"  {kind.upper():<14}{detail}")
            if kind in (ws.UNRECOGNISED, ws.BLOCKED) and len(r.text) < 1500:
                print(f"  body: {r.text[:300].replace(chr(10), ' ')}")
        if DUMP:
            dump(n, name, r.text)
        return r.status_code
    except requests.RequestException as e:
        kind, detail = ws._exception_kind(e)
        print(f"  {kind.upper():<14}{detail}")
        return None


def module_run():
    """What the model actually gets. Runs FIRST now, see main()."""
    line()
    print("WHAT THE MODEL ACTUALLY GETS")
    line()
    r = ws.WebSearch().search(QUERY)
    print(f"  searched     : {r['searched']}")
    print(f"  failure_kind : {r.get('failure_kind')}")
    print(f"  count        : {r['count']}")
    print(f"  engine       : {r['engine']}")
    print(f"  note         : {r.get('note')}")
    print(f"  error        : {r.get('error')}")
    print("  attempts:")
    for a in r.get("attempts", []):
        print(f"    {a['engine']:<14}{a['kind']:<14}{a['detail']}")
    for item in r["results"][:3]:
        print(f"    - {item['title'][:70]}")

    # THE CHECK THAT MATTERS, and it is the bug this script would have missed
    # too until today. searched=True with count=0 is a claim that the internet
    # has nothing, and it is only allowed when every backend said so itself.
    if r["searched"] and r["count"] == 0:
        kinds = [a["kind"] for a in r.get("attempts", [])]
        if all(k == ws.EMPTY for k in kinds):
            print("\n  OK: a real empty. Every backend reported no matches.")
        else:
            print("\n  WRONG: this reports as a completed search with nothing "
                  f"found, but the backends said {kinds}. That is the 8.7 bug "
                  "back again.")
    return r


def main():
    print(f"Query: {QUERY}\n")

    # THE MODULE GOES FIRST. 2026-09-05, and this was a real mistake.
    #
    # It used to run last, after six raw probes. On the 09-05 run the probes
    # got 200 and 8 parsed results out of html twice, and then the module ran
    # seconds later and was blocked on everything. Same machine, same query.
    # The likeliest reading is that this script earned the block and then
    # reported it as the module's problem, which is a diagnostic causing the
    # fault it diagnoses, and the same shape as the self-induced port scan
    # findings in TODO 38.
    #
    # So the thing being diagnosed gets the clean shot, and the probes run
    # afterwards where their own burst can only mislead about themselves.
    # PAUSE between the raw probes for the same reason.
    module_first = module_run()

    print()
    line()
    print("EACH BACKEND, RAW. BOTH METHODS, BECAUSE EITHER CAN BE THE BLOCKED ONE.")
    print(f"Paced {PAUSE}s apart, and they run AFTER the module on purpose.")
    line()

    _p_html = ws.WebSearch()._parse_html
    _p_lite = ws.WebSearch()._parse_lite

    show(1, "instant answer (GET api.duckduckgo.com)",
         lambda: requests.get(ws.DDG_INSTANT_URL,
                              params={"q": QUERY, "format": "json",
                                      "no_html": "1"},
                              headers=ws.HEADERS, timeout=ws.TIMEOUT))

    # 2 to 5 are the same two endpoints over both methods, which is what the
    # module does since 2026-09-05. It used to probe GET on one and POST on
    # the other and call the second a control, which only answers the question
    # if you already know which one is currently broken. On 08-30 POST was
    # blocked and GET worked; on 09-05 it was the other way round.
    show(2, "html over GET",
         lambda: requests.get(ws.DDG_HTML_URL,
                              params={"q": QUERY, "kl": "us-en"},
                              headers=ws.HEADERS, timeout=ws.TIMEOUT),
         parser=_p_html)

    show(3, "html over POST",
         lambda: requests.post(ws.DDG_HTML_URL,
                               data={"q": QUERY, "kl": "us-en"},
                               headers=ws.HEADERS, timeout=ws.TIMEOUT),
         parser=_p_html)

    show(4, "lite over GET",
         lambda: requests.get(ws.DDG_LITE_URL, params={"q": QUERY, "kl": "us-en"},
                              headers=ws.HEADERS, timeout=ws.TIMEOUT),
         parser=_p_lite)

    show(5, "lite over POST",
         lambda: requests.post(ws.DDG_LITE_URL, data={"q": QUERY, "kl": "us-en"},
                               headers=ws.HEADERS, timeout=ws.TIMEOUT),
         parser=_p_lite)

    # A purpose-built lookup, for comparison. Most of what the model asks
    # this tool is "what is this address", which is not really a web search.
    show(6, "ip-api.com (an actual IP lookup, no key needed)",
         lambda: requests.get("http://ip-api.com/json/77.111.246.27"
                              "?fields=status,country,city,isp,org,as,proxy,hosting",
                              timeout=ws.TIMEOUT))

    print()
    line()
    print("THE MODULE AGAIN, AFTER ALL THAT TRAFFIC")
    line()
    print("Six more requests have just gone out from this address. If the run")
    print("at the top resolved and this one does not, the burst is the cause,")
    print("not the code, and that is the 8.7 conversation rather than a bug.")
    second = ws.WebSearch().search(QUERY)
    print(f"  first run  : searched={module_first['searched']}, "
          f"kind={module_first.get('failure_kind')}, "
          f"count={module_first['count']}")
    print(f"  second run : searched={second['searched']}, "
          f"kind={second.get('failure_kind')}, count={second['count']}")
    if module_first["searched"] and not second["searched"]:
        print("\n  THE BURST DID IT. Clean first, blocked after six probes.")
        print("  Nothing to fix in the module. Pace the callers, or get a key.")
    elif not module_first["searched"] and not second["searched"]:
        print("\n  Blocked before any of our own traffic, so this address is")
        print("  already being challenged. Not a pacing problem.")

    print()
    line()
    print("READING THIS")
    line()
    print("  1 to 5 all fail            -> network or DNS, not DuckDuckGo.")
    print("  OK on any of 2 to 5 but    -> the burst. Compare the two module")
    print("  the module was blocked        runs above. This script makes six")
    print("                                requests; the module makes three.")
    print("                                DDG counts them all.")
    print("  BLOCKED on one method,     -> normal, and the module handles it:")
    print("  OK on the other               it tries both and remembers the")
    print("                                one that worked.")
    print("  BLOCKED on both methods,   -> DDG is challenging this address.")
    print("  both endpoints                Nothing to fix in the code, this is")
    print("                                the 8.7 'keyed search API' talk.")
    print("  UNRECOGNISED               -> 200 came back and it is not a page")
    print("                                we can read. Re-run with --dump and")
    print("                                READ the file. A challenge page")
    print("                                needs a new marker in BLOCK_MARKERS,")
    print("                                a redesign needs the parser changed.")
    print("                                Do not guess at the markup.")
    print("  6 works while 1 to 5 fail  -> network is fine, DDG is the")
    print("                                problem, and for IP questions a")
    print("                                lookup beats a search anyway.")
    if not DUMP:
        print("\n  Re-run with --dump to write each body into logs/.")


if __name__ == "__main__":
    main()
