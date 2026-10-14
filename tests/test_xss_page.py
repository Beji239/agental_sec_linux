"""
tests/test_xss_page.py, outside text cannot become markup on the dashboard.

1. The page's esc() turns every character that can open a tag or close an
   attribute into an entity (run in node).
2. Every field read placed into HTML, as ${x.field} in a template or
   '<td>' + x.field in a string, is escaped, is a number, or is on the
   reviewed list below with the reason it cannot carry outside text.
   A new raw read of a text field fails here.
"""
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGE = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
LINES = PAGE.split("\n")
fails = []


def check(label, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)
        print(f"        {str(detail)[:1500]}")


# Field names that hold numbers, counts or ids, never text.
NUMERIC = re.compile(
    r"\.(length|id|pid|ppid|uid|port|dport|seen|needed|count|total|n|ms|"
    r"duration_ms|attempted|tool_count|ports|ok|off|hits|size|bytes|score|pct|"
    r"days|hit|miss|pending|checked|unverifiable|busy|problem|capture_runs|"
    r"present_in|of_sweeps|days_since_last|interval_days|max_per_pass|"
    r"exclusions|unknown|x|y|r|cx|cy|width|height|top|left|open|answered|"
    r"do_not_know|expired|packet_count|duration_seconds|connections|_count|"
    r"clients_seen|clients_new|entities_processed|baselines_updated|"
    r"baselines_created|config_changed|pairs_read|without_geo|sweeps_counted|"
    r"sweeps_failed_and_excluded|edited_rows|deleted_rows|entries|cleared|"
    r"remaining|inserted|updated|skipped|rejected|rows|exe_refusals|"
    r"acknowledged|status|merged)$")

# Raw reads that cannot carry outside text, and why.
REVIEWED = {
    "f.severity": "the database allows only critical, high, medium, low, info",
    "SEV_COLOR[k]": "a colour from the page's own table",
    "counts[k]": "a number counted by the page",
    "colour[r.state]": "a colour from the page's own table",
}

FIELD = r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\[[^\]]+\])+"
TEMPLATE = re.compile(r"\$\{\s*\(?(" + FIELD + r")\)?(?:\s*(?:\|\||\?\?)\s*"
                      r"(?:'[^']*'|\"[^\"]*\"|[\w.]+))*\s*\}")
CONCAT = re.compile(r"""['"][^'"]*<[^'"]*['"]\s*\+\s*(""" + FIELD + r""")(?![\w.$]"""
                    "|" + r"""\s*\()""" + "|" + r"""(""" + FIELD
                    + r""")\s*\+\s*['"][^'"]*<""")


def raw_reads():
    out = []
    for i, line in enumerate(LINES, 1):
        if "<" not in line or "textContent" in line:
            continue
        found = [m.group(1) for m in TEMPLATE.finditer(line)]
        found += [m.group(1) or m.group(2) for m in CONCAT.finditer(line)]
        for x in found:
            if NUMERIC.search(x) or x in REVIEWED or x.endswith(".map"):
                continue
            out.append(f"{i}: {x}")
    return out


print("esc() in the page")
node = shutil.which("node")
if not node:
    print("  SKIP  node is not installed")
else:
    start = PAGE.index("function esc(str)")
    end = PAGE.index("\n}\n", start) + 3
    js = PAGE[start:end] + """
const bad = '<img src=x onerror="a(1)"> \\' ` &';
const out = esc(bad);
console.log(JSON.stringify({out, empty: esc(null), num: esc(0)}));"""
    r = subprocess.run([node, "-e", js], capture_output=True, text=True,
                       timeout=30)
    import json
    got = json.loads(r.stdout or "{}")
    out = got.get("out", "")
    check("no character that opens a tag or closes an attribute is left",
          not any(c in out for c in "<>\"'`"), out)
    check("an ampersand becomes an entity", "&amp;" in out, out)
    check("nothing is an empty string", got.get("empty") == "", got)

print("\nField reads placed into HTML")
left = raw_reads()
check("every text field is escaped, numeric or reviewed", not left,
      "\n        ".join(left))
check("the reviewed list still matches something",
      all(any(k in line for line in LINES) for k in REVIEWED),
      [k for k in REVIEWED if not any(k in line for line in LINES)])

print(f"\n{'ALL PASSED' if not fails else str(len(fails)) + ' FAILED'}")
sys.exit(1 if fails else 0)
