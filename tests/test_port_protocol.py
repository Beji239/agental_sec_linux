"""
tests/test_port_protocol.py, a port result has to say which protocol it is
about, and a TCP silence is not allowed to speak for UDP.

WHY THIS EXISTS, 2026-09-15.

The owner asked whether the port scanner covers UDP. It does not, and never
has: _check_port is socket.create_connection, a TCP connect, and it is the only
probe in the codebase. The owner had been reading the tool as covering both, which is
the only reasonable reading of a result that prints "port 500 open" with no
protocol on it anywhere.

So this is the same defect the project already has two rules about, one layer
lower than the last five times:

  the happy path was fine, the failure path lied. A TCP probe of a UDP service
  comes back quiet on a host that is running that service perfectly, and the
  scan reported that silence the same way it reports a port nothing listens on.
  "No match" and "I could not ask" were the same sentence again.

THE FAILURE TESTS COME FIRST IN THIS FILE, deliberately, sections [1] to [4].
Rule one: write the test for the lie before the test for the feature. Sections
[5] onward check the ordinary path only after that.

UPDATED 2026-09-17, TODO 117, because the scanner sends UDP now.

Section [11] of this file used to assert "no UDP socket in this module", and
that check did exactly the job it was written for: it was a tripwire saying
that adding a UDP prober had to be a deliberate change here rather than a
string edit that left half the rows mislabelled. This is that deliberate
change. What the file asserts now:

  a TCP silence still speaks only for TCP;
  a UDP silence speaks for NOTHING, and is never reported as closed;
  every row, every entry and every run says which protocol it is about.

The behaviour of the UDP probe itself lives in tests/test_udp_scan.py. Here
the wire is stubbed on both protocols, so these checks are about what the
scanner SAYS rather than about what the network did. That split was made
after the first run of the new test went green against a sandbox resolver
that answered UDP 53 for an address nobody was running.
"""
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


tmp = pathlib.Path(tempfile.mkdtemp())
db = tmp / "t.db"

from core import memory_engine as me          # noqa: E402
me.DB_PATH = db

c = sqlite3.connect(db)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.commit()
c.close()

from core import migrations                   # noqa: E402
migrations.run_migrations(db)
from core import sensors as sn                # noqa: E402
sn.register_local()

from tools import port_scanner as ps          # noqa: E402

HOST = "192.0.2.24"
SESSION = "test-protocol"


def scan_with(open_set, port_set="common", host=HOST, udp=None):
    """
    Run a real scan with BOTH wires replaced.

    open_set is what answers TCP. udp maps a port to one of the three UDP
    answers; anything not named stays silent, which is the realistic default
    and the case that matters most.
    """
    udp = udp or {}
    scanner = ps.PortScanner(session_id=SESSION)
    scanner._check_port = lambda h, p: p in open_set

    def fake_udp(h, p):
        state = udp.get(p, "no_answer")
        return {"state": state, "probe": "stubbed",
                "banner": ("7 byte reply to a stubbed probe, first bytes "
                           "00112233") if state == "open" else None}

    scanner._check_udp_port = fake_udp
    return scanner.scan(host, session_id=SESSION, port_set=port_set)


# THE FAILURE PATHS, FIRST

print("\n[1] a quiet UDP port is never reported as closed or absent")
# The bug this file was written for, now one layer along. 500 IKE and 5353
# mDNS do not listen on TCP at all. They are probed over UDP as of TODO 117,
# and when that probe comes back silent the result must still refuse to call
# them closed: silence on UDP means listening and quiet, filtered, or the
# wrong payload, and those are not "nothing there".
res = scan_with(set())
silent = {u["port"] for u in res["udp_no_answer"]}
check("nothing answered on TCP", res["tcp_open"], 0)
check("and nothing answered on UDP either", res["udp_open"], 0)
check("IKE 500 is reported as silent", 500 in silent, True)
check("mDNS 5353 is reported as silent", 5353 in silent, True)
check("SSDP 1900 is reported as silent", 1900 in silent, True)
check("none of them is in the closed list",
      {c["port"] for c in res["udp_closed_by_icmp"]} & {500, 5353, 1900},
      set())
check("and none of them is in the open list",
      {e["port"] for e in res["open_ports"]} & {500, 5353, 1900}, set())

# The wording matters as much as the field. This message is what the model
# reads back to the owner.
msg = res["message"].lower()
check("the answer names both protocols", "two protocols" in msg, True)
check("and says what a UDP silence is not",
      "only an icmp unreachable proves" in msg, True)
check("and names the silent ports", "did not answer" in msg, True)


print("\n[2] a TCP service that stayed quiet is NOT excused")
# The other direction, and the reason the UDP list is a list rather than
# everything. 22 and 3389 are TCP services. A silence there is a real answer
# about TCP and must not be dressed up as "could not ask", or the caveat
# becomes noise that hides the cases where it is true.
check("SSH 22 is not in the UDP scan set", 22 in set(ps.UDP_SCAN_PORTS), False)
check("RDP 3389 is not in the UDP scan set",
      3389 in set(ps.UDP_SCAN_PORTS), False)
check("and neither is reported as silent on UDP",
      {22, 3389} & silent, set())
check("nothing is reported as untested any more, because it is tested",
      res["udp_not_tested"], [])


print("\n[3] the database refuses a row that does not say its protocol")
# A bad value must fail at the call site. Left to SQLite it surfaces as an
# IntegrityError three frames down, and on an older database with no CHECK it
# would not fail at all.
for bad in ("sctp", "TCP ", "", None):
    try:
        me.save_port_scan_result(session_id=SESSION, target_host=HOST,
                                 port=22, protocol=bad)
        check(f"protocol {bad!r} was rejected", "accepted", "BadInput")
    except me.BadInput:
        check(f"protocol {bad!r} was rejected", "BadInput", "BadInput")

try:
    me.query_port_scan(target_host=HOST, protocol="icmp")
    check("querying a bogus protocol was rejected", "accepted", "BadInput")
except me.BadInput:
    check("querying a bogus protocol was rejected", "BadInput", "BadInput")


print("\n[4] the three UDP answers are never summed")
# The discipline this whole module is built on, and the one a reader is most
# likely to undo by writing a convenient total. open plus closed plus silent
# is not a meaningful number about anything.
res3 = scan_with(set(), udp={53: "open", 161: "closed", 123: "no_answer"})
check("open is its own count", res3["udp_open"], 1)
check("closed is its own list",
      [c["port"] for c in res3["udp_closed_by_icmp"]], [161])
check("silent includes the quiet one",
      123 in {s["port"] for s in res3["udp_no_answer"]}, True)
check("and the closed port is not in the silent list",
      161 in {s["port"] for s in res3["udp_no_answer"]}, False)
check("nothing in the payload adds them up",
      "udp_total" in res3 or "udp_count" in res3, False)


# THE ORDINARY PATH

print("\n[5] every open port says WHICH protocol, everywhere it is written")
res = scan_with({22, 443, 500}, udp={5353: "open"})
check("the TCP entries say tcp",
      {e["protocol"] for e in res["open_ports"] if e["port"] != 5353}, {"tcp"})
check("the UDP entry says udp",
      [e["protocol"] for e in res["open_ports"] if e["port"] == 5353], ["udp"])
check("the result says what it tested",
      res["protocols_tested"], ["tcp", "udp"])

rows = me.query_port_scan(target_host=HOST, session_id=SESSION)
check("every stored row carries a protocol",
      all(r["protocol"] in ("tcp", "udp") for r in rows), True)
udp_rows = me.query_port_scan(target_host=HOST, protocol="udp")
# Membership, not equality: earlier sections in this file wrote UDP rows to
# the same host, and a test that demands the table hold nothing else is
# asserting the order its own sections run in.
check("the udp filter returns the udp row",
      5353 in {r["port"] for r in udp_rows}, True)
check("and returns only udp rows",
      {r["protocol"] for r in udp_rows}, {"udp"})
check("the run recorded what it put on the wire",
      sqlite3.connect(db).execute(
          "SELECT protocols FROM port_scan_run ORDER BY id DESC LIMIT 1"
      ).fetchone()[0], "tcp,udp")


print("\n[6] each row's note matches the question that was actually asked")
# 500 answered on TCP here, which is unusual and real, and the row says the
# result came from a TCP connect. 5353 answered a UDP probe, so the TCP caveat
# must NOT be printed on it: the caveat exists because a question went
# unasked, and on that row it was asked and answered.
ike = [e for e in res["open_ports"] if e["port"] == 500][0]
mdns = [e for e in res["open_ports"] if e["port"] == 5353][0]
check("the TCP row says it was found over TCP",
      "found over TCP" in ike["note"], True)
check("and still carries the UDP fact about that service",
      "IKE is a UDP service" in ike["note"], True)
check("the UDP row says it answered a probe",
      "answered a UDP probe" in mdns["note"], True)
check("and does not carry the TCP caveat",
      "found over TCP" in mdns["note"], False)
check("the silent ports still travel in the message",
      "did not answer" in res["message"].lower(), True)


print("\n[7] no coverage was lost fixing this")
# The other way to fix a false 'closed' is to stop scanning those ports, which
# trades a lie for a blind spot. They are all still probed.
scanned = set(ps._port_set("common"))
for p in (500, 4500, 1900, 5353, 53, 631):
    check(f"{p} is still scanned over TCP", p in scanned, True)


print("\n[8] the fingerprint says which protocols it is talking about")
# device drift compares open_ports as bare numbers, so that shape is left
# alone on purpose. The qualification sits beside it.
fp = me.build_device_fingerprint(HOST)
check("open_ports is still plain numbers",
      all(isinstance(p, int) for p in fp["ports_observed"]["open_ports"]), True)
check("with the protocols named next to it",
      sorted(fp["ports_observed"]["protocols_checked"]), ["tcp", "udp"])

never = me.build_device_fingerprint("192.0.2.30")
check("a never-scanned host claims no protocols",
      never["ports_observed"]["protocols_checked"], [])
check("and says it was never scanned",
      never["ports_observed"]["scanned"], False)


print("\n[9] an old database gets the column, and old rows read tcp")
# Not a guess. The connect scanner is the only writer this table has ever had,
# so every historical row IS a TCP result. The migration is stating a fact
# about the code, not inventing one about the network.
old = tmp / "old.db"
oc = sqlite3.connect(old)
oc.execute("""
    CREATE TABLE port_scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        target_host TEXT NOT NULL,
        port INTEGER NOT NULL,
        state TEXT,
        risk_level TEXT)
""")
oc.execute("CREATE TABLE port_scan_run (id INTEGER PRIMARY KEY AUTOINCREMENT, "
           "session_id TEXT, target_host TEXT)")
oc.execute("INSERT INTO port_scan_results (session_id, target_host, port, "
           "state, risk_level) VALUES ('old','192.0.2.5',445,'open','low')")
oc.commit()

added = migrations._migrate_port_protocol(oc)
oc.commit()
check("the migration did something", added, 2)
check("the row now says tcp", oc.execute(
    "SELECT protocol FROM port_scan_results WHERE port = 445").fetchone()[0],
    "tcp")
check("the run table got its column too",
      "protocols" in {r[1] for r in oc.execute(
          "PRAGMA table_info(port_scan_run)").fetchall()}, True)
check("running it twice adds nothing", migrations._migrate_port_protocol(oc), 0)
oc.close()


print("\n[10] the tool description tells the model the limit")
# The model is the one that turns a row into a sentence for the owner. If the
# limit is only in the code, the sentence will not have it.
from core import tool_registry as tr           # noqa: E402
by_name = {t["name"]: t for t in tr.TOOL_MANIFEST}
check("run_port_scan says it tests two protocols",
      "TWO PROTOCOLS" in by_name["run_port_scan"]["description"], True)
check("and tells the model silence is not closed",
      "Never report a udp_no_answer" in by_name["run_port_scan"]["description"],
      True)
check("and names all three UDP answers",
      all(k in by_name["run_port_scan"]["description"]
          for k in ("open_ports", "udp_closed_by_icmp", "udp_no_answer")),
      True)
check("query_port_scan says what a row's protocol is", 
      "EVERY ROW IS TCP OR UDP" in by_name["query_port_scan"]["description"], True)
# RESTATED 2026-09-25, register PS-12, and the old assertion is worth writing
# down because it pinned a claim that was already false. It read "EVERY ROW IS
# TCP" against a description saying "the connect scanner is the only thing that
# has ever written to this table" -- while THIS FILE's own section [5] writes a
# UDP row and asserts it comes back from the udp filter. Since TODO 117
# (2026-09-17) the scanner runs a UDP pass, so the description was telling the
# model that a table of UDP rows held none. The replacement asserts the two
# things a reader of that description needs, in both directions.
check("and it does not deny the UDP rows this file itself writes",
      "only thing that has ever written" in
      by_name["query_port_scan"]["description"], False)
check("and it tells the model the scope, which is what PS-12 was about",
      "THIS RUN ONLY" in by_name["query_port_scan"]["description"]
      and "all_sessions=true" in by_name["query_port_scan"]["description"], True)
check("and the filter is reachable",
      "protocol" in by_name["query_port_scan"]["input_schema"]["properties"],
      True)
check("and so is the scope control it now shares with query_packets",
      "all_sessions" in
      by_name["query_port_scan"]["input_schema"]["properties"], True)


print("\n[11] the second protocol is declared, not implied")
# This section used to assert there was no UDP socket in the module, as a
# tripwire against one appearing quietly. It appeared deliberately on
# 2026-09-17, so the tripwire becomes the declaration check: the protocols a
# run claims must be exactly the ones the module actually speaks, in one
# place, with the UDP limit stated rather than left to be discovered.
src = (ROOT / "tools" / "port_scanner.py").read_text(encoding="utf-8")
check("there is one constant per protocol",
      (src.count('SCAN_PROTOCOL = "tcp"'), src.count('UDP_PROTOCOL = "udp"')),
      (1, 1))
check("the UDP prober really uses a datagram socket",
      "SOCK_DGRAM" in src, True)
check("and it connects, so an ICMP unreachable is visible",
      "sock.connect(" in src, True)
status = ps.PortScanner(session_id=SESSION).status()
check("status reports both protocols", status["protocols"], ["tcp", "udp"])
check("and names the UDP scope rather than implying a full sweep",
      "not a full sweep" in status["udp_scope"], True)
check("the declared list matches what a run records",
      list(ps.PROTOCOLS_TESTED), ["tcp", "udp"])


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
