"""
scripts/enrichment_check.py, does tier 1 actually answer, today?

WHY THIS IS A SCRIPT AND NOT A TEST
tests/test_enrichment.py fakes every source, so it proves the LOGIC and runs
offline. This one hits the real registries on purpose, and it exists for the
same reason scripts/websearch_check.py does: these sources are somebody else's
front end and they will break. On 2026-08-30 DuckDuckGo started answering 202
to every POST and the only reason it was findable was a tool that reported
"did not complete" instead of returning an empty list. Same discipline here.

Run it when a lookup starts coming back unresolved and you want to know
whether the problem is this code or the internet:

    python scripts/enrichment_check.py
    python scripts/enrichment_check.py 77.111.246.10 CVE-2024-38063

It writes NOTHING to the database. It calls the source functions directly, so
a failure here is about the source or the parser and never about the queue.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Load .env the same way main.py does, or every keyed source reports "no key"
# when run from a shell and you spend ten minutes wondering why.
from core.secret_store import load_dotenv    # noqa: E402
load_dotenv(ROOT / ".env")

from core import enrichment as en            # noqa: E402

DEFAULTS = [
    "8.8.8.8",              # a boring allocation every source should know
    "CVE-2024-38063",       # a CVE both CVE sources should have
    "5c:41:5a:12:34:01",    # a hardware prefix, local file, no network
    "certutil.exe",         # a LOLBAS listing. First run downloads the catalogue.
]

# NO SAMPLE HASH IN HERE ON PURPOSE. A 64 character hex string is
# indistinguishable from an API key, and scripts/check_no_local_details.py
# flags it as one, correctly. Both keys get exercised by 8.8.8.8 anyway:
# AbuseIPDB and URLhaus both run on every address. To test a hash, pass one:
#     python scripts/enrichment_check.py <sha256>


def show(result: dict):
    print(f"\n  {result['indicator']}  [{result['kind']}]")
    # ABOVE THE STATUS LINE, deliberately. 41.7. A live URLhaus hit printed
    # "partial (single_source)" as its headline, because status describes the
    # ownership ladder and rdap had timed out. True, and softer than the row
    # deserved. They answer different questions and the dangerous one goes
    # first.
    if result.get("flag"):
        print(f"    ** {result['flag']}")
    print(f"    status      {result['status']} ({result['confidence']})"
          + ("   [ownership lookup only]" if result.get("flagged") else ""))
    if result.get("agreed_on"):
        # Worth showing. Two registries matching on the ASN while their
        # company names look nothing alike is a weaker statement than both
        # naming the same outfit, and you should be able to see which it was.
        print(f"    agreed on   {result['agreed_on']}")
    print(f"    tried       {', '.join(result['tried']) or 'nothing'}")
    for key, value in (result.get("fields") or {}).items():
        if key == "_field_sources":
            continue
        # Keys starting with _ are ours, not a source's. Printing "[?]" beside
        # them made it look like a source we could not identify, which is a
        # different and worse thing to say.
        if key.startswith("_"):
            print(f"      {key:<20} {value}")
            continue
        source = (result["fields"].get("_field_sources") or {}).get(key, "?")
        print(f"      {key:<20} {value}   [{source}]")
    if result.get("errors"):
        for line in result["errors"]:
            print(f"    ! {line}")
    if (result.get("fields") or {}).get("abusable_windows_binary"):
        print(f"    reading     {en._lolbas_note(result['fields'])}")
    if "abuse_confidence_score" in (result.get("fields") or {}):
        print(f"    reading     "
              f"{en._abuse_confidence_note(result['fields']['abuse_confidence_score'], result['fields'])}")
    if result.get("gap"):
        print(f"    gap         {result['gap']}")
    print(f"    took        {result.get('elapsed_seconds')}s")


def main():
    targets = sys.argv[1:] or DEFAULTS

    print("Keyed sources:")
    for row in en.keyed_source_status():
        state = "ON" if row["enabled"] else "off"
        print(f"  {row['source']:<12} {state:<4} {row['why_off'] or row['would_give']}")
    if not any(r["enabled"] for r in en.keyed_source_status()):
        print("  (all off. .env was read, so if you just added a key check it "
              "was SAVED, and that the variable name matches exactly.)")

    print("\nRunning tier 1 against the real sources. Nothing is written.")
    bad = []
    for target in targets:
        try:
            result = en.research(target)
        except Exception as e:
            print(f"\n  {target}: RAISED {type(e).__name__}: {e}")
            bad.append(target)
            continue
        show(result)
        # unresolved is only a failure here when the sources did not ANSWER.
        # "no record" is a legitimate result and must not read as an outage,
        # which is the same distinction the tool itself makes.
        if result["status"] == "unresolved" and result.get("errors"):
            bad.append(target)

    print()
    if bad:
        print(f"NOT ANSWERED: {', '.join(bad)}")
        print("Check the errors above before assuming the indicator is unknown. "
              "A source that did not answer is not a source that said no.")
        return 1
    print("All targets answered.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
