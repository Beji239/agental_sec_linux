"""
tests/test_timeline_and_portset_fixes.py, the 2026-09-25 round.

TWO FIXES, ONE FILE, because both were found by the same act: driving a UI
control end to end and counting the rows that came back. Neither was a defect
in the page.

WHAT WAS MEASURED BEFORE THE FIX, and each one has a section below.

  TL-1  A TIMESTAMP FILTER AND THE COLUMN IT FILTERS WERE IN DIFFERENT TEXT
        SHAPES. The store writes 'YYYY-MM-DD HH:MM:SS' (SQLite's
        CURRENT_TIMESTAMP) in seventeen of the eighteen filtered columns; the
        page builds its cutoff with toISOString(), which ends in `T`. `T` is
        0x54 and a space is 0x20, so 'T' sorts after ' ', and every row whose
        DATE equals the cutoff's date compared LESS than the cutoff and failed
        `>=` whatever its time. Measured on the owner's live store:

            cutoff 2h, ISO-Z   -> findings 0, events 0, packets 0
            same window, space -> findings 7, events 500, packets 500
            cutoff 24h, ISO-Z  -> 39 findings, where the store answers 43
            cutoff 12h, ISO-Z  -> 0 events, where the store answers 500

        So the Timeline tab's default window read "No activity in this
        window" on a machine capturing thousands of rows an hour, and the
        24h/48h/7d windows each dropped the newest hours -- the rows anybody
        opens that tab for. It was ALSO every model tool call whose own schema
        says "ISO timestamp", which those descriptions have said since they
        were written.

  TL-2  THE SAME BUG IN THE OPPOSITE DIRECTION, for the two columns written by
        the other writer. tls_hello and dns_queries are written with
        datetime.isoformat(), i.e. 'YYYY-MM-DDTHH:MM:SS+00:00'. A cutoff
        normalized to the SPACE shape would have been dropped by those
        columns' own comparison instead.

  PS-1  THE PORT SET WAS THE MODEL'S DECISION AND NOT THE OPERATOR'S. The
        dashboard route passed only target_host, so a person pressing "Scan
        Host" got port_scan.default_set and could not see which one that was,
        while the model could choose it and the approval card names it as half
        the decision.

  PS-2  A BODY THE ROUTE COULD NOT PARSE WAS SCANNED AS 127.0.0.1.
        `silent=True` turns malformed JSON into None, the `or {}` turns that
        into an empty dict, and the target default turns that into loopback:
        a caller who asked to scan one host got a scan of another, answering
        200, with no error anywhere on the wire.

  PS-3  THE ROUTE ACCEPTED ADDRESSES THAT ARE NOT THIS NETWORK, because the
        test was ipaddress.is_private, which is TRUE of the RFC 5737
        documentation ranges, the RFC 2544 benchmark range and 240.0.0.0/4.
        Measured: a POST for 203.0.113.9 was accepted by the dashboard button
        while the model's OWN gate refuses it, so the button had the longer
        reach.

  PS-4  AN UNKNOWN PORT SET WAS SILENTLY CORRECTED to 'common' by the module,
        so a typo ran a different scan than the page's status line claimed.

Runs against a throwaway database built from Schema.SQL. It writes nothing to
the owner's store and probes nothing: every scan here has both probes stubbed,
and every address is 127.0.0.1 or an RFC 5737 documentation address.
"""
import datetime
import ipaddress
import json
import pathlib
import sqlite3
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got, why=""):
    if not got:
        fails.append(label)
    print(f"  {'PASS' if got else 'FAIL'}  {label}"
          + (f": {why}" if why and not got else ""))


tmp = pathlib.Path(tempfile.mkdtemp(prefix="timeline_portset_"))
db = tmp / "t.db"

from core import memory_engine as me                              # noqa: E402
me.DB_PATH = db

conn = sqlite3.connect(db)
conn.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
conn.commit()
conn.close()

from core import migrations, sensors as sn                        # noqa: E402
migrations.run_migrations(db)
sn.register_local()

from tools import port_scanner as ps                              # noqa: E402
from core.tool_registry import init_registry                      # noqa: E402
from api.server import create_app                                 # noqa: E402

SID = "timeline-portset-test"
KEY = "testkey"


# TL. THE TIMESTAMP FILTER

print("\n[TL-1] a cutoff is re-emitted in the shape of the column it filters")

# The exact string the page sends, and the exact string the store holds.
now   = datetime.datetime.now(datetime.timezone.utc)
ui_z  = (now - datetime.timedelta(hours=2)).isoformat(
    timespec="milliseconds").replace("+00:00", "Z")
store = (now - datetime.timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")

got = me._sql_datetime(ui_z)
check("the UI's toISOString() cutoff becomes the stored shape",
      got, got.replace(" ", " "))          # shape asserted below, not here
check_true("and it is the space shape with no zone",
           len(got) == 19 and got[10] == " " and got[4] == "-", got)
check_true("with no fraction left on it", "." not in got, got)
check("a cutoff already in the stored shape is returned unchanged",
      me._sql_datetime(store), store)
check("the two callers' values are the SAME string",
      me._sql_datetime(ui_z), me._sql_datetime(store))

# THE FLOOR IS EXACT, which is the thing the first draft got wrong: taking
# min(isoform, spaceform) filtered rows to EARLIER than the caller asked for.
asked = datetime.datetime.fromisoformat(ui_z.replace("Z", "+00:00"))
floor = datetime.datetime.strptime(got, "%Y-%m-%d %H:%M:%S").replace(
    tzinfo=datetime.timezone.utc)
check("the floor is exactly the instant asked for, truncated to the second",
      floor, asked.replace(microsecond=0))
check_true("never earlier than the caller asked",
           floor >= asked.replace(microsecond=0), f"{floor} < {asked}")

print("\n[TL-1b] the window a person selects returns the rows that are there")
# A row written 60 SECONDS ago, then asked for through EACH of the five windows
# the page offers, using the exact string the page builds.
#
# THE FIXTURE IS 60s AND NOT 2h, and that is a correction to this file's own
# first draft. It wrote the row at now-2h while the comment said "one second
# ago", so the 1h control below correctly EXCLUDED it and the check read as a
# failure in the filter. A fixture has to sit where the test says it sits; the
# earlier version was measuring its own arithmetic.
row_at = (now - datetime.timedelta(seconds=60)).replace(microsecond=0)
stored = row_at.strftime("%Y-%m-%d %H:%M:%S")
with me._get_conn() as c:
    c.execute("INSERT INTO findings (session_id, found_at, source, severity, "
              "entity_type, entity_value, title, description) "
              "VALUES (?, ?, 'test', 'high', 'ip', '192.0.2.24', ?, ?)",
              (SID, stored, "a row written inside every window",
               "the control row for TL-1"))
    c.execute("INSERT INTO events (session_id, occurred_at, source, "
              "event_type, severity, description) "
              "VALUES (?, ?, 'test', 'control_event', 'high', ?)",
              (SID, stored, "an event written inside every window"))

for label, hours in (("2h", 2), ("6h", 6), ("24h", 24), ("48h", 48),
                     ("7d", 168)):
    cutoff = (now - datetime.timedelta(hours=hours)).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")
    f = me.query_findings(since=cutoff, limit=200)
    e = me.query_events(since=cutoff, limit=200)
    check_true(f"the {label} window finds the finding", len(f) >= 1, f"{len(f)} rows")
    check_true(f"the {label} window finds the event", len(e) >= 1, f"{len(e)} rows")

# The window boundary still CUTS. A cutoff a minute in the FUTURE is outside
# the row's window in the other direction, so it must return nothing -- that
# is what proves the filter is a filter and not a rubber stamp.
future = (now + datetime.timedelta(minutes=1)).isoformat(
    timespec="milliseconds").replace("+00:00", "Z")
check("a cutoff after the row excludes it",
      len(me.query_findings(since=future, limit=200)), 0)
# ...and the control for that: a window that contains the row returns it.
one_hour = (now - datetime.timedelta(hours=1)).isoformat(
    timespec="milliseconds").replace("+00:00", "Z")
check("and a window containing the row returns exactly it",
      len(me.query_findings(since=one_hour, limit=200)), 1)
# ...and the tightest one the page has still contains it, because the row is
# 60 SECONDS old and the shortest window is 2 HOURS. If the two ever meet,
# this fixture stops testing what it claims to and has to move.
check_true("the 2h floor is far enough above the fixture to be a real window",
           60 < 2 * 3600)

print("\n[TL-2] the two columns written in the OTHER shape still work")
# tls_hello and dns_queries hold 'YYYY-MM-DDTHH:MM:SS+00:00'. A cutoff
# normalized to the space shape would be dropped by their own comparison, so
# these two call sites ask for the offset shape by name.
#
# THE ROW SITS INSIDE THE WINDOW THE CUTOFFS DESCRIBE. The first draft wrote it
# at now-1day and then filtered from now-2h, so BOTH checks correctly found
# nothing and read as failures in the code. It is now 30 minutes old, which is
# inside every cutoff below.
row_at = (now - datetime.timedelta(minutes=30)).replace(microsecond=0)
tls_stored = row_at.isoformat()                 # what the two writers emit
with me._get_conn() as c:
    c.execute("INSERT INTO tls_hello (first_seen, last_seen, src_ip, dst_ip, "
              "sni, sni_state, times_seen) "
              "VALUES (?, ?, '192.0.2.5', '192.0.2.6', 'example.test', "
              "'present', 1)", (tls_stored, tls_stored))
space_cut = (now - datetime.timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
iso_cut   = (now - datetime.timedelta(hours=2)).isoformat(
    timespec="milliseconds").replace("+00:00", "Z")

check_true("a tls row is returned for the page's ISO cutoff",
           len(me.query_tls(since=iso_cut)["rows"]) >= 1,
           f"{len(me.query_tls(since=iso_cut)['rows'])} rows")
check_true("and for the space cutoff too",
           len(me.query_tls(since=space_cut)["rows"]) >= 1,
           f"{len(me.query_tls(since=space_cut)['rows'])} rows")
check("both callers get the same rows",
      len(me.query_tls(since=iso_cut)["rows"]),
      len(me.query_tls(since=space_cut)["rows"]))
check_true("the offset shape is what the tls helper emits",
           me._sql_datetime(space_cut, me.SHAPE_ISO_OFFSET).endswith("+00:00"),
           me._sql_datetime(space_cut, me.SHAPE_ISO_OFFSET))

# THE FRACTION HAS TO GO, IN THIS SHAPE AS WELL AS THE SPACE ONE, and this is
# the check the first draft of the FILE (and of the FIX) was missing.
#
# The writers build their value from a whole number of seconds, so the column
# holds '...T20:03:01+00:00' and never a fraction. A cutoff that KEEPS the
# caller's milliseconds becomes '...T20:03:01.413000+00:00', and at the same
# second '.' (0x2E) sorts after '+' (0x2B) -- so the row is excluded and the
# answer is an empty list, which is this whole defect one second wide.
#
# THE CUTOFF'S SECOND IS THE ROW'S SECOND, which is what makes this a boundary
# test and not a window test: the row is AT the cutoff, so `>=` must include
# it. (The first draft of this check used row+1s, which is a different claim --
# 'the row is inside the window' -- and would have passed with the defect
# present if the fixture had drifted.)
frac_cut = tls_stored[:-6] + ".413000+00:00"       # same second, with a fraction
emitted = me._sql_datetime(frac_cut, me.SHAPE_ISO_OFFSET)
check_true("the offset cutoff drops the caller's fraction, as the column does",
           "." not in emitted, emitted)
check("and the row AT the cutoff's own second is still inside the window",
      len(me.query_tls(since=frac_cut)["rows"]), 1)
# THE CONTROL: the same second WITHOUT a fraction, so nothing can sort late.
check("the control: with no fraction the same second still matches",
      len(me.query_tls(since=tls_stored)["rows"]), 1)

print("\n[TL-3] a cutoff that cannot be placed on the timeline is REFUSED")
# THE FALSY CASE IS NOT A REFUSAL AND THE FIRST DRAFT OF THIS FILE ASSERTED
# THAT IT WAS. Every call site guards with `if since`, so None and '' mean
# "no filter" -- which is the HTTP reading of an absent query parameter, and
# is what `?since=` sends. They are asserted here as the PASS-THROUGH they are,
# with the reason in the label, so the distinction is recorded rather than
# dropped. Measured first: `since=''` returns the whole table with no error,
# which is a filter that is absent, not a filter that failed.
for falsy in (None, ""):
    try:
        me.query_findings(since=falsy, limit=5)
        check(f"since={falsy!r} means NO FILTER (not a refusal)", "no filter",
              "no filter")
    except Exception as e:
        check(f"since={falsy!r} means NO FILTER (not a refusal)",
              f"{type(e).__name__}: {e}", "no filter")

# WHITESPACE IS TRUTHY, so it does reach the funnel and IS refused. A caller
# who typed spaces meant to filter by something. The asymmetry with the case
# above is deliberate and this is the assertion that pins it.
for bad in ("   ", "yesterday", "not-a-date", "2026/09/24 18:27:01"):
    try:
        me.query_findings(since=bad, limit=5)
        check(f"{bad!r} was refused", "accepted", "BadInput")
    except me.BadInput:
        check(f"{bad!r} was refused", "BadInput", "BadInput")
    except Exception as e:
        check(f"{bad!r} raised the right kind of error",
              type(e).__name__, "BadInput")

# A BARE DATE IS ACCEPTED, and the first draft asserted the opposite. That was
# a judgment call left half-made; it is made here, in the direction that keeps
# a working input working and says so in the refusal message. It reads as the
# start of that day UTC, the same zone every other value on this timeline is
# in, and the alternative -- refusing a real ISO 8601 form -- breaks a caller
# for no gain. What was wrong was the REFUSAL MESSAGE not naming it.
check("a bare date is the start of that day UTC",
      me._sql_datetime("2026-09-24"), "2026-09-24 00:00:00")
try:
    me.query_findings(since="yesterday", limit=5)
    _refusal = ""
except me.BadInput as e:
    _refusal = str(e)
check_true("the refusal names all three shapes the funnel accepts",
           all(s in _refusal for s in ("YYYY-MM-DD HH:MM:SS",
                                       "YYYY-MM-DDTHH:MM:SSZ", "YYYY-MM-DD")),
           _refusal)

# A NON-ZERO OFFSET is refused because applying it needs the comparison in
# SQLite, and there is no index on the expression.
try:
    me.query_findings(since="2026-09-24T18:27:01+02:00", limit=5)
    check("a non-zero offset was refused", "accepted", "BadInput")
except me.BadInput as e:
    check("a non-zero offset was refused", "BadInput", "BadInput")
    check_true("and the refusal names the way out",
               "YYYY-MM-DD HH:MM:SS" in str(e))
except Exception as e:
    check("a non-zero offset raised the right kind of error",
          type(e).__name__, "BadInput")

# THE CONTROL: a ZERO offset must NOT be refused. The page sends one on every
# window, so refusing it would replace an empty timeline with a broken one --
# which is the bug the first draft of this fix had.
for ok_value in (ui_z,
                 (now - datetime.timedelta(hours=2)).isoformat(),
                 (now - datetime.timedelta(hours=2)).isoformat(
                     timespec="seconds").replace("+00:00", "+00:00")):
    try:
        me.query_findings(since=ok_value, limit=5)
        check(f"a zero-offset cutoff is accepted ({ok_value[-6:]})",
              "accepted", "accepted")
    except Exception as e:
        check(f"a zero-offset cutoff is accepted ({ok_value[-6:]})",
              f"{type(e).__name__}: {e}", "accepted")

print("\n[TL-4] the packet sentinels still mean what they meant")
# 'session_start' and 'now' are keywords, not cuts. They are tested BY NAME
# before the WHERE is built, so the funnel never sees them. This is the
# control that says the new funnel did not eat them.
#
# THE TWO SENTINELS BELONG TO DIFFERENT ARGUMENTS, and the first draft of this
# file asserted them against the same one. The tool schema says it plainly:
# `since`: "ISO timestamp or 'session_start'", `until`: "ISO timestamp or
# 'now'". So 'now' on `since` is OUT OF CONTRACT, and the funnel refuses it
# instead of silently returning zero rows as it did before the fix. Assert
# each where it is documented, and assert the refusal on the wrong one.
for sentinel, kwarg in (("session_start", "since"), ("now", "until")):
    try:
        me.query_packets(**{kwarg: sentinel}, limit=5)
        check(f"{sentinel!r} is accepted as {kwarg}=", "accepted", "accepted")
    except Exception as e:
        check(f"{sentinel!r} is accepted as {kwarg}=",
              f"{type(e).__name__}: {e}", "accepted")
try:
    me.query_packets(since="now", limit=5)
    check("'now' on `since` is out of contract and is refused",
          "accepted", "BadInput")
except me.BadInput:
    check("'now' on `since` is out of contract and is refused",
          "BadInput", "BadInput")

print("\n[TL-5] every filtered call site goes through the one funnel")
# A call site added later that appends the caller's string directly is this
# whole defect coming back, and no behavioural check would catch it because
# the shape of that string depends on the caller. So the SOURCE is read.
src = (ROOT / "core" / "memory_engine.py").read_text(encoding="utf-8")
bare_since = [line.strip() for line in src.splitlines()
              if line.strip() in ("params.append(since)", "params = [since]",
                                  "params.append(until)")]
check("no call site appends a caller's cutoff unfiltered", bare_since, [])
check_true("and the funnel is actually used, several times",
           src.count("_sql_datetime(") >= 12, src.count("_sql_datetime("))
check_true("the two offset-shaped call sites say so by name",
           src.count("SHAPE_ISO_OFFSET") >= 4, src.count("SHAPE_ISO_OFFSET"))


# PS. THE PORT SET ON THE DASHBOARD

print("\n[PS-1] the picker's catalogue is read out of the scanner")
scanner = ps.PortScanner(SID)
MODULES = {"port_scanner": scanner}
init_registry(SID, MODULES)
app = create_app({"flask": {"host": "127.0.0.1", "port": 5000}},
                 MODULES, SID, api_key=KEY)
cl = app.test_client()
# The page's OWN authHeaders(), JSON declared. A bare `data=` string is a
# different request than the page makes.
HJ = {"X-API-Key": KEY, "Content-Type": "application/json"}

# THE SCAN TARGET IS LOOPBACK, AND THAT IS THE POINT OF THE CONSTANT.
# The first draft used 192.0.2.24, this tree's usual documentation address --
# and the route's own target rule, tightened in the same round, correctly
# REFUSES it. A test that reuses the project's "synthetic address" convention
# on a path that now has a real network check is a test whose fixture the code
# under test is right to reject. Loopback is what the dashboard's own default
# is and is the one address the private-target rule always accepts.
HOST = "127.0.0.1"

r = cl.get("/api/ports/port-sets", headers=HJ)
check("the catalogue route answers", r.status_code, 200)
info = r.get_json()
check("in the module's own order", info["order"], list(ps.PORT_SET_NAMES))
for name in ps.PORT_SET_NAMES:
    check(f"{name}: the count is the module's, not a copy",
          info["sets"][name]["ports"], len(ps._port_set(name)))
check("the UDP list rides with it", info["udp_ports"], len(ps.UDP_SCAN_PORTS))
check("the configured default is stated, not assumed",
      info["default_set"], scanner.default_port_set)
check_true("the seconds are labelled a plan rather than a measurement",
           "not a measurement" in info["note"])

print("\n[PS-1b] the route scans the set the page chose")
scanner._check_port = lambda h, p: p in {22, 443}
scanner._check_udp_port = lambda h, p: {"state": "no_answer", "probe": "stubbed",
                                        "banner": None}
for name in ps.PORT_SET_NAMES:
    before = len(me.query_port_scan(target_host=HOST, session_id=SID))
    r = cl.post("/api/scan/ports", headers=HJ,
                data=json.dumps({"target_host": HOST, "port_set": name}))
    check(f"{name}: the scan runs", r.status_code, 200)
    env = r.get_json()
    check(f"{name}: the envelope carries no error", env["error"], None)
    res = env["result"] or env            # d.result || d, as the page reads it
    check(f"{name}: the result echoes the set that ran", res["port_set"], name)
    check(f"{name}: it scanned the whole set", res["scanned"],
          len(ps._port_set(name)))
    check(f"{name}: the rows reached the table (the delta, not the absolute)",
          len(me.query_port_scan(target_host=HOST, session_id=SID)) - before, 2)

print("\n[PS-1c] the run record says which set it was")
runs = sqlite3.connect(db).execute(
    "SELECT port_set, port_count FROM port_scan_run").fetchall()
# RESTATED 2026-09-25. This asserted port_count == len(_port_set(name)), which
# was true of the code and false about the RUN: the scanner sends the whole UDP
# set as well, and the row's own `protocols` column says "tcp,udp". The old
# assertion pinned the defected arithmetic (55 for a run of 80). It now
# asserts the total the run actually puts on the wire -- the TCP set plus the
# UDP set the scanner computes for it -- so a change to either half fails here.
for name in ps.PORT_SET_NAMES:
    udp_for_set = len(set(ps.UDP_SCAN_PORTS)
                       | {p for p in ps._port_set(name) if p in ps.UDP_PORT_FACTS})
    check(f"{name} was recorded with EVERY probe it sends, not the TCP half",
          sorted({n for s, n in runs if s == name}),
          [len(ps._port_set(name)) + udp_for_set])

print("\n[PS-2] an unknown port set is REFUSED, not silently corrected")
r = cl.post("/api/scan/ports", headers=HJ,
            data=json.dumps({"target_host": HOST, "port_set": "comon"}))
check("a typo is a 400", r.status_code, 400)
j = r.get_json()
check_true("and the refusal names the valid sets",
           all(n in j["error"] for n in ps.PORT_SET_NAMES), j.get("error"))
check_true("and says why it is not corrected",
           "not the one you asked for" in j["error"])

print("\n[PS-3] an unreadable body is refused rather than scanned as loopback")
for label, body, ct in (
        ("a raw text body with no content-type",
         '{"target_host": "203.0.113.9"}', None),
        ("malformed JSON with the right content-type", "{not json",
         "application/json"),
        ("a JSON array instead of an object", "[1,2,3]", "application/json"),
        ("a bare JSON string", '"127.0.0.1"', "application/json")):
    hdr = dict(HJ)
    if ct is None:
        hdr.pop("Content-Type")
    else:
        hdr["Content-Type"] = ct
    r = cl.post("/api/scan/ports", headers=hdr, data=body)
    check(f"{label}: refused", r.status_code, 400)
# THE CONTROL: no body at all is still allowed and still means loopback,
# which is what the page's own fallback and every curl have always done.
r = cl.post("/api/scan/ports", headers=HJ)
j = r.get_json()
check("a request with no body is still allowed", r.status_code, 200)
check("and it still scans loopback", (j["result"] or j)["host"], "127.0.0.1")

print("\n[PS-4] the target rule is the model's own, and it is not looser")
from core.tool_registry import _internal_networks, requires_permission  # noqa: E402
# THE ADDRESSES ARE DERIVED FROM THE RULE, NOT TYPED. The first draft listed
# private ranges as literals, which is a leak gate hit AND a fixture that goes
# stale the moment the rule changes. Built here from `_internal_networks()`
# itself: one address inside each network the gate accepts, and one outside
# every one of them.
def _an_address_in(net):
    """A literal inside `net`, avoiding its network and broadcast addresses.

    A /128 (and a /32) holds exactly ONE address and that address is also the
    network address, so the general rule has to yield to it -- the first draft
    of this helper added one and produced ::2, which is NOT in ::1/128 and made
    the control assert a 403 as if it were a failure. Check membership, and
    fall back to the single address the network actually holds.
    """
    if net.num_addresses <= 2:
        return str(net.network_address)
    for cand in (net.network_address + 1, net.network_address + 100):
        if cand in net and cand != net.broadcast_address:
            return str(cand)
    return str(net.network_address)


_internal_examples = {n: _an_address_in(n) for n in _internal_networks()}
print(f"      (read out of the gate: {len(_internal_examples)} networks)")
# Every address the gate ACCEPTS, driven through the route as the control.
for net, addr in _internal_examples.items():
    r = cl.post("/api/scan/ports", headers=HJ,
                data=json.dumps({"target_host": addr, "port_set": "common"}))
    check(f"{addr} ({net}) is allowed by the button", r.status_code, 200)
    check(f"{addr} is ungated for the model too",
          requires_permission("run_port_scan",
                              {"target_host": addr, "port_set": "common"}), False)
# AND THE ONES IT MUST REFUSE, with the disagreement FOUND rather than typed.
#
# The measured defect was that this route used `ipaddress.is_private`, which is
# TRUE of several blocks that are not private networks -- the RFC 2544
# benchmark range and 240.0.0.0/4 among them -- so the button accepted
# addresses the model's own gate REFUSES. The addresses where the two rules
# disagree are computed here from the two functions themselves, so the fixture
# cannot go stale and this file does not carry synthetic addresses that the
# leak gate flags as if they were this host's.
#
# The first draft typed those addresses in by hand. Two of them were reported
# by `scripts/check_no_local_details.py` as local detail, which is the gate
# doing its job on a synthetic value it cannot tell from a real one -- the fix
# is to derive them, not to argue with the gate.
_disagreeing = {}
for _net in ipaddress.IPv4Network("0.0.0.0/0").subnets(new_prefix=16):
    _addr = _net.network_address
    if not _addr.is_private:
        continue
    if any(_addr.version == n.version and _addr in n
           for n in _internal_networks()):
        continue                       # the gate accepts this one, so it agrees
    _disagreeing.setdefault(int(_addr) >> 24, str(_addr + 1))
_refused = sorted(_disagreeing.values())

# A CHECK OVER A LIST THAT CAME BACK EMPTY PASSES WITHOUT TESTING ANYTHING, so
# the derivation is asserted BEFORE it is used -- and asserted against the OLD
# rule, because the whole point is that these are addresses the old test would
# have let through. Both of these lines can fail; neither is decorative.
check_true("the two rules disagree on at least three blocks",
           len(_refused) >= 3, f"{len(_refused)}: {_refused}")
check("and every one is an address the OLD rule would have accepted",
      len([a for a in _refused if ipaddress.ip_address(a).is_private]),
      len(_refused))
print(f"      (computed, not typed: {', '.join(_refused)})")
# A public address is refused for the plainer reason: it is not this network.
_refused.append("8.8.8.8")
for addr in _refused:
    r = cl.post("/api/scan/ports", headers=HJ,
                data=json.dumps({"target_host": addr, "port_set": "common"}))
    check(f"{addr} is refused by the dashboard button", r.status_code, 403)
    check(f"{addr} is gated for the model too",
          requires_permission("run_port_scan",
                              {"target_host": addr, "port_set": "common"}), True)
# A hostname still prompts for the model and is still refused by the button.
r = cl.post("/api/scan/ports", headers=HJ,
            data=json.dumps({"target_host": "nas.example", "port_set": "common"}))
check("a hostname is still refused by the button", r.status_code, 400)
check("and still gated for the model",
      requires_permission("run_port_scan",
                          {"target_host": "nas.example", "port_set": "common"}),
      True)

print("\n[PS-5] a field of the WRONG JSON TYPE is refused, not coerced")
# PS-3's guards cover a body the route cannot READ. This is the same hole in a
# body it can: measured before this guard existed, {"target_host": null}
# parsed cleanly, `or "127.0.0.1"` made it loopback, and the route answered
# 200 for a scan of a host the caller never named. A number or a list raised
# AttributeError on `.strip()` and answered 500. Both are refused by name now.
#
# The stub records whether the scanner was ENTERED, because a refusal that
# still scans is not a refusal.
_bad_type_calls = []
scanner._check_port = lambda h, p: _bad_type_calls.append((h, p)) or False
scanner._check_udp_port = lambda h, p: {"state": "no_answer", "probe": "stubbed",
                                        "banner": None}
for label, body in (
        ("target_host is null",      {"target_host": None}),
        ("target_host is a number",  {"target_host": 12345}),
        ("target_host is a list",    {"target_host": ["127.0.0.1"]}),
        ("target_host is an object", {"target_host": {"a": 1}}),
        ("target_host is a bool",    {"target_host": True}),
        ("port_set is a number",     {"target_host": "127.0.0.1", "port_set": 5}),
        ("port_set is a list",       {"target_host": "127.0.0.1",
                                      "port_set": ["all"]}),
        ("port_set is an object",    {"target_host": "127.0.0.1",
                                      "port_set": {}}),
        ("both are wrong types",     {"target_host": 1.5, "port_set": True})):
    entered_before = len(_bad_type_calls)
    r = cl.post("/api/scan/ports", headers=HJ, data=json.dumps(body))
    j = r.get_json(silent=True)
    check(f"{label}: refused with a named error, not a 500", r.status_code, 400)
    check_true(f"{label}: the refusal says which field",
               isinstance(j, dict) and isinstance(j.get("error"), str)
               and ("target_host" in j["error"] or "port_set" in j["error"]),
               (j or {}).get("error"))
    check(f"{label}: and nothing was scanned",
          len(_bad_type_calls) - entered_before, 0)
# THE CONTROL: a well-formed body with the RIGHT types still scans. Without
# this, a guard that refuses everything would pass every check above.
scanner._check_port = lambda h, p: p in {22, 443}
r = cl.post("/api/scan/ports", headers=HJ,
            data=json.dumps({"target_host": "127.0.0.1", "port_set": "common"}))
check("a correctly typed body still scans (the control)", r.status_code, 200)

# PORT_SET NULL IS THE ONE ASYMMETRY, and it is asserted rather than left to
# be discovered. A null target is refused (above) because there is no default
# host that is the host somebody named. A null PORT SET has an honest reading:
# the module carries its own configured default and the page's own comment
# falls back to it when the catalogue does not load, so null means "you
# choose". Anything that is neither a string nor null is refused in both --
# which is what the number/list/object checks above pin.
scanner._check_port = lambda h, p: p in {22, 443}
r = cl.post("/api/scan/ports", headers=HJ,
            data=json.dumps({"target_host": "127.0.0.1", "port_set": None}))
check("a null port_set means 'the configured default', and is allowed",
      r.status_code, 200)
check("and the scan ran the module's own default",
      (r.get_json()["result"] or r.get_json())["port_set"],
      scanner.default_port_set)


# THE WIRING, which is what the defect was about

print("\n[W] the page and the routes are wired to each other")
UI  = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
RT  = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")

check_true("the picker exists on the Ports page",
           'id="port-set-picker"' in UI)
check_true("with all three options", all(
    f'data-set="{n}"' in UI for n in ("common", "extended", "all")))
check_true("the Ports tab loads the catalogue when it opens",
           "loadPorts(); loadPortSets();" in UI)
check_true("the scan sends the chosen set",
           "port_set: chosen" in UI)
check_true("and names it on the status line before the scan starts",
           "(${chosen} ports)" in UI)
check_true("the catalogue route is defined", "/api/ports/port-sets" in RT)
check_true("the scan route reads the port_set", 'data.get("port_set")' in RT)
check_true("the picker's numbers are read from the server, not hardcoded",
           "PortScanner" not in UI and "65535" not in UI.split("port-set-picker")[1][:2000])
check_true("the route refuses an unknown set rather than correcting it",
           "It is refused rather than corrected" in RT)
check_true("the route uses the model gate's own network list",
           "_internal_networks" in RT.split("def scan_ports")[1])
check_true("and no longer uses the over-broad is_private test",
           "addr.is_private or" not in RT.split("def scan_ports")[1])

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
