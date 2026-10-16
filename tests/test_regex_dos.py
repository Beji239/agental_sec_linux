"""
tests/test_regex_dos.py, no pattern run on outside data can be made slow.

Every compiled pattern at module level in the code that reads outside data
(logs, DNS, feeds, router answers, packets, process names, the API's input)
is run against long hostile strings: one character repeated, two alternating,
the pattern's own punctuation repeated, each ending in a character that makes
the match fail late. A pattern with nested repetition takes seconds or never
finishes on these. It runs in a child process, because a regex in progress
cannot be interrupted from Python, and the child is killed if it overruns.
"""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

fails = []


def check(label, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)
        if detail:
            print(f"        {str(detail)[:2000]}")


CHILD = r'''
import importlib, json, re, sys, time, logging
sys.path.insert(0, sys.argv[1])
sys.path.insert(0, sys.argv[1] + "/tests")
import _isolate_db; _isolate_db.isolate()
logging.disable(logging.CRITICAL)
MODULES = sys.argv[2].split(",")
N = 10000
slow, counted, unreadable = [], 0, []
for name in MODULES:
    try:
        mod = importlib.import_module(name)
    except Exception as e:
        unreadable.append(f"{name}: {type(e).__name__}")
        continue
    for attr, pat in vars(mod).items():
        if not isinstance(pat, re.Pattern) or not isinstance(pat.pattern, str):
            continue
        counted += 1
        punct = sorted(set(c for c in pat.pattern if not c.isalnum()
                           and c not in "\\()[]{}^$|?*+"))[:6] or ["="]
        tails = ["\x00", "!", "\n"]
        bodies = ["a" * N, " " * N, "a " * (N // 2), "1." * (N // 2),
                  "\t" * N, "aA1" * (N // 3)]
        bodies += [p * N for p in punct] + [("a" + p) * (N // 2) for p in punct]
        worst = 0.0
        print(f"START {name}.{attr}", flush=True)
        for body in bodies:
            for tail in tails:
                t = time.perf_counter()
                pat.search(body + tail)
                worst = max(worst, time.perf_counter() - t)
        print(f"DONE {worst:.3f}", flush=True)
        if worst > 0.5:
            slow.append(f"{name}.{attr} {worst:.2f}s  {pat.pattern[:90]!r}")
print(json.dumps({"counted": counted, "slow": slow, "unreadable": unreadable}))
'''

MODULES = [
    "tools.auditd_monitor", "tools.dns_monitor", "tools.dns_inspector",
    "tools.feed_matcher", "tools.gateway", "tools.router_monitor",
    "tools.event_monitor_linux", "tools.process_monitor_linux",
    "tools.packet_sniffer_linux", "tools.tls_hello", "tools.av_scanner",
    "tools.systemd_units", "tools.network_scanner", "tools.port_scanner",
    "tools.software_inventory_linux", "tools.local_integrity",
    "tools.ebpf_events", "tools.lan_live", "core.sanitize", "core.enrichment",
    "core.web_search", "core.ip_lookup", "core.memory_engine", "core.duty",
    "core.alert_review", "core.evidence", "api.routes", "adapters",
]
try:
    p = subprocess.run([sys.executable, "-c", CHILD, str(ROOT),
                        ",".join(MODULES)], capture_output=True, text=True,
                       timeout=170)
    out = p.stdout
except subprocess.TimeoutExpired as e:
    out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
    lines = out.splitlines()
    timed = [(float(b[5:]), a[6:]) for a, b in zip(lines, lines[1:])
             if a.startswith("START ") and b.startswith("DONE ")]
    started = [ln[6:] for ln in lines if ln.startswith("START ")]
    worst = ", ".join(f"{n} {t:.1f}s" for t, n in sorted(timed)[-4:])
    check("the patterns finish", False,
          f"still inside {started[-1] if started else 'the imports'} after "
          f"170 s; slowest finished: {worst}")
    sys.exit(1)
try:
    res = json.loads(out.strip().splitlines()[-1])
except (json.JSONDecodeError, IndexError):
    print(out[-1500:], p.stderr[-1500:])
    check("the patterns were run", False)
    sys.exit(1)
print(f"  {res['counted']} patterns in {len(MODULES)} modules, "
      f"each against 18 or more hostile strings of 10 000 characters")
check("every module could be read", not res["unreadable"], res["unreadable"])
check("no pattern takes over half a second", not res["slow"],
      "\n        ".join(res["slow"]))
print(f"\n{'ALL PASSED' if not fails else str(len(fails)) + ' FAILED'}")
sys.exit(1 if fails else 0)
