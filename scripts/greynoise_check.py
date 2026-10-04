"""
scripts/greynoise_check.py, does the GreyNoise key actually work, today?

PORTED TO LINUX 2026-09-21. Nothing in it was Windows specific, so this is the
Windows file with its own situation corrected. What WAS missing here is the
thing it checks: this tree had no src_greynoise_ip, src_greynoise_cve or
_greynoise_note at all, so there was nothing to point a check at. The block
was ported from the Windows tree in the same pass, and this is its proof.

READ THIS BEFORE TRUSTING THE SOURCE. The GreyNoise enrichers were written on
2026-09-18 from GreyNoise's own Python SDK (v3.1.0, the response templates it
ships) rather than from a live call, because api.greynoise.io was not
reachable from where they were written. Field names are therefore evidence,
not observation. Until this script has been run once against the real API and
printed a hit, treat the source as unproven.

Same discipline as scripts/enrichment_check.py and scripts/websearch_check.py:
it calls the source functions directly, writes NOTHING to the database, and
reports what it could not do rather than returning an empty answer.

    python scripts/greynoise_check.py
    python scripts/greynoise_check.py 45.33.32.156 CVE-2021-44228

What a good run looks like:
  * the key is accepted, no 401
  * at least one address comes back seen, with a classification and tags
  * 8.8.8.8 comes back as a known business service
  * an address nobody scans comes back NOT SEEN with no error, which is the
    case most likely to be broken and least likely to look broken

WHAT THIS HOST MEASURED, 2026-09-21, with no key set: api.greynoise.io ANSWERS
from here (an unauthenticated /ping returns HTTP 401 {"message":
"unauthorized"}), so the network half of the original caveat no longer
applies. The response SHAPES are still the SDK's, not something watched, and
that is what this script is for.
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.secret_store import load_dotenv    # noqa: E402
load_dotenv(ROOT / ".env")

from core import enrichment as en            # noqa: E402

# 8.8.8.8 should hit the business service list. The scanner address is a
# long-lived research scanner, so it is the one most likely to be "seen".
# The third is this machine's own public-ish neighbour space, expected quiet.
DEFAULT_IPS  = ["8.8.8.8", "45.33.32.156"]
DEFAULT_CVES = ["CVE-2021-44228"]


def show(title, fields, url, err):
    print(f"\n,,, {title}")
    print(f"    reference : {url}")
    if err:
        # The whole point. An error is printed as an error and never as an
        # empty result, so "the key is wrong" cannot be read as "nothing found".
        print(f"    COULD NOT LOOK : {err}")
        return False
    if not fields:
        print("    no record, and no error. That is a real negative result.")
        return True
    for k, v in fields.items():
        print(f"    {k:26} {v}")
    note = en._greynoise_note(fields)
    if note:
        print("\n    how to read it:")
        for line in _wrap(note, 68):
            print(f"      {line}")
    return True


def _wrap(text, width):
    words, line, out = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line)
            line = w
        else:
            line = f"{line} {w}".strip()
    if line:
        out.append(line)
    return out


def main(argv):
    args = argv[1:]
    ips = [a for a in args if not a.upper().startswith("CVE-")] or DEFAULT_IPS
    cves = [a for a in args if a.upper().startswith("CVE-")] or DEFAULT_CVES

    key = en._key_for("greynoise")
    print("GreyNoise check")
    print(f"  key present : {'yes, ending ' + key[-4:] if key else 'NO'}")
    if not key:
        print("  Set AGENTAL_GREYNOISE_KEY in .env, or use the Settings tab, "
              "then restart.")
        return 2
    print(f"  endpoint    : {en.GREYNOISE_API}")

    ok = True
    for ip in ips:
        got, url, err = en.src_greynoise_ip(ip)
        ok = show(f"IP {ip}", got, url, err) and ok
    for cve in cves:
        got, url, err = en.src_greynoise_cve(cve)
        ok = show(f"CVE {cve}", got, url, err) and ok

    print("\n" + "=" * 70)
    if not ok:
        print("At least one lookup could not be made. The reason is printed "
              "above it. This is NOT the same as GreyNoise having no data.")
        return 1
    print("Every lookup completed. Where a field is missing above, GreyNoise "
          "genuinely had nothing, which is an answer.")
    print("\nIf this printed real fields, the source is proven and the note "
          "at the top of this file can come out.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
