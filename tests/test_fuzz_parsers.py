# runner-timeout: 900, takes three to six minutes on a busy machine.
"""
tests/test_fuzz_parsers.py, malformed input never crashes or hangs a parser.

Hypothesis feeds random and hostile text to the parsers that read outside
data: the router agent's answers (counters, block hits, connections, leases,
neighbours) and the threat feeds (ThreatFox CSV, host files, address lists,
domains). Each must return its usual shape, quickly, whatever arrives.
Needs Hypothesis from scripts/install_test_tools.sh; without it this skips.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db  # noqa: E402
import _skip  # noqa: E402
import _tools  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
_isolate_db.isolate()

# Hypothesis lives in the test tools' own environment, added LAST so the
# app's own packages still come from where the app gets them.
for site in sorted((_tools.TOOLS_HOME / "venv" / "lib").glob(
        "python3*/site-packages")):
    sys.path.append(str(site))
try:
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st
except ImportError:
    _skip.skip("needs Hypothesis, run ./scripts/install_test_tools.sh")

from tools import feed_matcher as fm  # noqa: E402
from tools import gateway as gw  # noqa: E402

fails = []
RUNS = settings(max_examples=300, deadline=1000,
                suppress_health_check=list(HealthCheck))

# Text that looks a little like the real thing: digits, dots, colons,
# separators, quotes, and now and then anything at all.
PIECES = st.sampled_from(["192.0.2.1", "2001:db8::1", "aa:bb:cc:dd:ee:ff",
                          "src=", "dst=", "bytes=", "packets=", "ESTABLISHED",
                          "tcp", "udp", "6", "17", " ", "  ", "\t", ",", '"',
                          "#", "=", "-", "--", ":", "0", "99999999999999999999",
                          "-1", "nan", "\x00", "‮", "é", "<b>", "%s"])
LINE = st.one_of(st.text(max_size=200),
                 st.lists(PIECES, max_size=25).map("".join))
LINES = st.lists(LINE, max_size=40)


def run(label, test):
    try:
        test()
        print(f"  PASS  {label}")
    except Exception as e:                                  # noqa: BLE001
        fails.append(label)
        print(f"  FAIL  {label}: {type(e).__name__}: {str(e)[:400]}")


print("The router agent's answers")


@RUNS
@given(LINES)
def counters(lines):
    out = gw.parse_counters(lines)
    assert isinstance(out, dict)
    for v in out.values():
        assert all(isinstance(v[k], int) and v[k] >= 0 for k in v)


@RUNS
@given(LINES)
def block_hits(lines):
    out = gw.parse_block_hits(lines)
    assert isinstance(out, dict)
    assert all(v["packets"] >= 0 and v["bytes"] >= 0 for v in out.values())


@RUNS
@given(LINES)
def flows(lines):
    assert isinstance(gw.parse_flows(lines), list)


@RUNS
@given(LINES, st.sampled_from(["nf", "pf", "junk"]))
def conntrack(lines, fmt):
    assert isinstance(gw.parse_conntrack(lines, fmt), dict)


@RUNS
@given(LINES, st.text(max_size=40))
def leases(lines, lease_file):
    assert isinstance(gw.parse_leases(lines, lease_file), list)


@RUNS
@given(LINES, st.sampled_from(["ip", "bsd", "junk"]))
def neighbors(lines, fmt):
    assert isinstance(gw.parse_neighbors(lines, fmt), list)


for name, fn in (("counters", counters), ("block hits", block_hits),
                 ("connections", flows), ("connection table", conntrack),
                 ("leases", leases), ("neighbours", neighbors)):
    run(name, fn)

print("\nThreat feeds")


def rows_ok(rows):
    assert isinstance(rows, list)
    for r in rows:
        assert len(r) == 3 and r[1] in ("ip", "domain")


@RUNS
@given(LINES)
def threatfox(lines):
    rows_ok(fm._parse_threatfox_csv("\n".join(lines)))


@RUNS
@given(LINES)
def hostfile(lines):
    rows_ok(fm._parse_hostfile("\n".join(lines)))


@RUNS
@given(LINES)
def ip_lines(lines):
    rows_ok(fm._parse_lines_ip("\n".join(lines)))


@RUNS
@given(LINE)
def host_rows(value):
    rows_ok(fm._host_rows(value, "family"))


@RUNS
@given(LINE)
def domains(value):
    d = fm._clean_domain(value)
    assert isinstance(d, str)
    parents = fm._domain_and_parents(value)
    assert all("." in p for p in parents)


for name, fn in (("ThreatFox CSV", threatfox), ("host files", hostfile),
                 ("address lists", ip_lines), ("URLs and hosts", host_rows),
                 ("domains and parents", domains)):
    run(name, fn)

print(f"\n{'ALL PASSED' if not fails else str(len(fails)) + ' FAILED: ' + ', '.join(fails)}")
sys.exit(1 if fails else 0)
