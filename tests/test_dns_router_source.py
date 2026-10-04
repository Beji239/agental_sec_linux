# tests/test_dns_router_source.py
# The router source of dns_monitor: dnsmasq log lines from the gateway agent
# become dns_queries rows, re-reads are no-ops, and a rolled log is reported.

import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
_tmp = tempfile.mkdtemp()
os.environ["AGENTALSEC_TEST_DB"] = os.path.join(_tmp, "test.db")
os.environ.setdefault("TZ", "PST8PDT")
sys.path.insert(0, str(ROOT))

from core import memory_engine as me  # noqa: E402
from tools import dns_monitor as dm  # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


LOG = [
    "Wed Sep 30 23:09:34 2026 daemon.info dnsmasq[6634]: 20 192.0.2.7/58476 query[A] Example.COM. from 192.0.2.7",
    "Wed Sep 30 23:09:34 2026 daemon.info dnsmasq[6634]: 20 192.0.2.7/58476 forwarded example.com to 198.51.100.1",
    "Wed Sep 30 23:09:34 2026 daemon.info dnsmasq[6634]: 20 192.0.2.7/58476 reply example.com is <CNAME>",
    "Wed Sep 30 23:09:34 2026 daemon.info dnsmasq[6634]: 20 192.0.2.7/58476 reply edge.example.net is 203.0.113.5",
    "Wed Sep 30 23:09:35 2026 daemon.info dnsmasq[6634]: 21 192.0.2.7/59193 query[AAAA] example.com from 192.0.2.7",
    "Wed Sep 30 23:09:35 2026 daemon.info dnsmasq[6634]: 21 192.0.2.7/59193 config example.com is NODATA-IPv6",
    "Wed Sep 30 23:09:36 2026 daemon.info dnsmasq[6634]: 22 192.0.2.8/40000 query[A] bad.example.org from 192.0.2.8",
    "Wed Sep 30 23:09:36 2026 daemon.info dnsmasq[6634]: 22 192.0.2.8/40000 config bad.example.org is NXDOMAIN",
    "Wed Sep 30 23:09:37 2026 daemon.info dnsmasq[6634]: 23 192.0.2.8/40001 query[A] seen.example.org from 192.0.2.8",
    "Wed Sep 30 23:09:37 2026 daemon.info dnsmasq[6634]: 23 192.0.2.8/40001 cached seen.example.org is 203.0.113.9",
    "Wed Sep 30 23:09:38 2026 daemon.info dnsmasq[700]: query[A] plain.example.org from 192.0.2.9",
    "Wed Sep 30 23:09:38 2026 daemon.info dnsmasq[6634]: something that is not a query line",
    "garbage",
]

print("parse")
rows, notes = dm.parse_router_dnslog(LOG)
by = {(r["domain"], r["query_type"]): r for r in rows}
check("one row per query line", len(rows), 5)
check("unparseable lines counted", notes["line_skipped"], 1)
a = by[("example.com", "A")]
check("name lowercased, root dot dropped", a["domain"], "example.com")
check("logread local time stored as UTC", a["queried_at"], "2026-10-01T06:09:34+00:00")
check("forwarded keeps its status", a["status"], "forwarded")
check("upstream from the forwarded line", a["upstream"], "198.51.100.1")
check("CNAME chain ends at an address", a["reply_type"], "IP")
check("client taken from the query", a["client_ip"], "192.0.2.7")
aaaa = by[("example.com", "AAAA")]
check("AAAA filter is not a block", (aaaa["status"], aaaa["reply_type"], aaaa["blocked"]),
      ("config", "NODATA", False))
check("local NXDOMAIN is a block", by[("bad.example.org", "A")]["blocked"], True)
check("cached answer", by[("seen.example.org", "A")]["status"], "cached")
plain = by[("plain.example.org", "A")]
check("line without serial still parsed", (plain["client_ip"], plain["status"]), ("192.0.2.9", None))
check("row identities distinct", len({r["source_row_id"] for r in rows}), 5)
ans = {(x["name"], x["value"]) for x in notes["answers"]}
check("answers filed under the asked name, through a CNAME",
      ("example.com", "203.0.113.5") in ans, True)
check("cached answers kept, NODATA and NXDOMAIN are not addresses",
      sorted(ans), [("example.com", "203.0.113.5"), ("seen.example.org", "203.0.113.9")])

print("import")
from core import migrations  # noqa: E402
migrations.run_migrations(me.DB_PATH)
cfg = {"dns_monitor": {"enabled": True, "source": "router"},
       "gateway": {"enabled": True, "host": "192.0.2.1"}}
check("status needs no path", dm.status(cfg)["available"], True)
check("status refuses without a gateway",
      dm.status({"dns_monitor": {"enabled": True, "source": "router"}})["available"], False)

feed = {"lines": LOG}
dm.read_router = lambda config: dm.parse_router_dnslog(feed["lines"])
r1 = dm.import_once(cfg)
check("first pass inserts every query", (r1["ran"], r1["inserted"]), (True, 5))
r2 = dm.import_once(cfg)
check("re-read is a no-op", r2["inserted"], 0)
check("no backlog to chase", r2["more_available"], False)

old_limit = dm.ROUTER_LOG_LINES
dm.ROUTER_LOG_LINES = 2
feed["lines"] = [
    "Thu Oct  1 08:00:00 2026 daemon.info dnsmasq[6634]: 90 192.0.2.7/1 query[A] new1.example.com from 192.0.2.7",
    "Thu Oct  1 08:00:01 2026 daemon.info dnsmasq[6634]: 91 192.0.2.7/2 query[A] new2.example.com from 192.0.2.7",
]
r3 = dm.import_once(cfg)
check("a full read of only new rows reports a gap", r3["possible_gap"], True)
r4 = dm.import_once(cfg)
check("overlap with stored rows is not a gap", r4["possible_gap"], False)
dm.ROUTER_LOG_LINES = old_limit

print()
if fails:
    print(f"{len(fails)} FAILED: {fails}")
    sys.exit(1)
print("all passed")
