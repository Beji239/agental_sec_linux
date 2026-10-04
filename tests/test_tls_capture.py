"""
tests/test_tls_capture.py, TODO 113.2. Storing what the ClientHello said,
and never letting the list of names look complete when it is not.

tests/test_tls_hello.py covers the parser on bytes. This file covers
everything after it: the table, the upsert, the tool the model calls, and the
one property the whole feature stands on.

THE PROPERTY. A ClientHello that spans two TCP segments cannot be read from a
single packet. That is normal, it is common, and it means the app sees a TLS
connection whose destination name it does not know. If those get quietly
dropped, query_tls returns a tidy list of domains and the model reads it as
"this is what the machine talks to". It is not. It is what we could parse.

So the unreadable ones are stored, kept OUT of the rows, and counted in a
coverage block that travels with every answer. Section [1] drives that first,
before anything about the happy path, per the rule from 2026-09-13.

Run it directly: python tests/test_tls_capture.py
"""
import pathlib
import sqlite3
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
DB = _isolate_db.isolate()

from core import memory_engine as me                  # noqa: E402
from core import tool_registry as tr                  # noqa: E402
from core import sensor_health as sh                  # noqa: E402
from core import voice                                # noqa: E402
from tools import tls_hello as th                     # noqa: E402

fails = []
def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def hello(sni=None, state="present", ja3="771,1-2,0,29,0", md5="a" * 32,
          src="192.0.2.5", dst="93.184.216.34", port=443, proc="chrome.exe",
          reason="parsed", pid=1234):
    return {
        "src_ip": src, "dst_ip": dst, "dst_port": port,
        "sni": sni, "sni_state": state, "ja3": ja3, "ja3_md5": md5,
        "alpn": ["h2"], "legacy_version": "TLS 1.2",
        "cipher_count": 2, "ext_count": 1,
        "process_name": proc, "process_pid": pid, "parse_reason": reason,
    }


print("\n[1] FAILURE CASE: a hello we could not read is not a domain we did not visit")
res = me.save_tls_hellos([
    hello(sni="example.com"),
    hello(sni=None, state="unreadable", md5="",
          reason="truncated TLS record, the hello spans segments",
          dst="1.2.3.4"),
    hello(sni=None, state="unreadable", md5="",
          reason="truncated TLS record, the hello spans segments",
          dst="5.6.7.8"),
])
check("all three were stored", res["seen"], 3)
check("and the unreadable ones are counted as such", res["unreadable"], 2)

out = me.query_tls()
check("the unreadable ones are NOT in the rows", len(out["rows"]), 1)
check("the one readable row is the one with a name",
      out["rows"][0]["sni"], "example.com")
check("but they are in coverage, where an answer can see them",
      out["coverage"]["hellos_unreadable"], 2)
check("with the readable count beside it", out["coverage"]["hellos_read"], 1)
check("and the share, so it is one number to read",
      out["coverage"]["read_share"], 0.333)
check("the reasons are grouped rather than guessed at",
      out["coverage"]["why_unreadable"][0]["rows_"], 2)
check("the coverage note is addressed to the model, not the operator",
      voice.is_marked(out["coverage"]["note"]), True)
print(f"       read {out['coverage']['hellos_read']}, "
      f"unreadable {out['coverage']['hellos_unreadable']}")

# THE COVERAGE NUMBERS ARE NOT FILTERED BY THE SEARCH. A narrow search must
# not be able to look better covered than a wide one, which is what would
# happen if the unreadable count respected the where clause.
narrow = me.query_tls(sni="example")
check("a narrow search reports the SAME sensor coverage",
      narrow["coverage"]["hellos_unreadable"], 2)


print("\n[2] FAILURE CASE: an empty table is not a machine that speaks no TLS")
# Nothing here can distinguish those two states from the rows alone, which is
# exactly why the coverage block and the tool description carry the sentence.
# What is testable: the answer never claims completeness it has not earned.
empty = me.query_tls(sni="nothing-like-this-was-ever-seen")
check("no rows", empty["rows"], [])
check("matching is 0 and says so", empty["matching"], 0)
check("and the coverage block is still there to be read",
      "hellos_unreadable" in empty["coverage"], True)


print("\n[3] repeats fold into a counter instead of a new row")
before = me.query_tls(sni="example.com")["rows"][0]
check("first sighting counts once", before["times_seen"], 1)
me.save_tls_hellos([hello(sni="example.com")] * 5)
after = me.query_tls(sni="example.com")
check("still one row", len(after["rows"]), 1)
check("with the repeats counted", after["rows"][0]["times_seen"], 6)
check("and the same id, so nothing was replaced",
      after["rows"][0]["id"], before["id"])
check("last_seen moved", after["rows"][0]["last_seen"] >= before["last_seen"], True)


print("\n[4] what makes a row distinct is the whole combination")
me.save_tls_hellos([
    hello(sni="example.com", proc="firefox.exe"),          # other process
    hello(sni="example.com", md5="b" * 32),                # other fingerprint
    hello(sni="example.com", src="192.0.2.8"),              # other device
    hello(sni="example.com", port=8443),                   # other port
])
rows = me.query_tls(sni="example.com")["rows"]
check("four new rows, one per differing field", len(rows), 5)
check("and none of them merged into the original",
      sorted(r["times_seen"] for r in rows), [1, 1, 1, 1, 6])

# THE '' RULE. SQLite lets duplicate NULLs through a UNIQUE index, so a
# nullable key column is not a key. Two hellos with no process attribution
# must still fold together.
me.save_tls_hellos([hello(sni="noproc.test", proc=""),
                    hello(sni="noproc.test", proc="")])
noproc = me.query_tls(sni="noproc.test")["rows"]
check("two unattributed hellos are ONE row", len(noproc), 1)
check("counted twice", noproc[0]["times_seen"], 2)


print("\n[5] the filters answer the questions they are named for")
check("by domain", len(me.query_tls(sni="noproc")["rows"]), 1)
check("by process", len(me.query_tls(process_name="firefox")["rows"]), 1)
check("by fingerprint", len(me.query_tls(ja3_md5="b" * 32)["rows"]), 1)
check("by device", len(me.query_tls(src_ip="192.0.2.8")["rows"]), 1)
check("by destination", len(me.query_tls(dst_ip="93.184.216.34")["rows"]) >= 5, True)
check("an unknown fingerprint matches nothing and says so",
      me.query_tls(ja3_md5="f" * 32)["matching"], 0)


print("\n[6] the model can actually reach it, through the real dispatcher")
# The guardrail that caught the three prediction tools in 109: a tool in the
# manifest with no sensor_health.DEPENDS entry raises UnregisteredTool at
# execute_tool, so every call would have been a 500 in the owner's app.
names = [t["name"] for t in tr.TOOL_MANIFEST]
check("query_tls is in the manifest", "query_tls" in names, True)
check("it is registered in DEPENDS", "query_tls" in sh.DEPENDS, True)
check("and it is classified as a READ", tr.tool_writes("query_tls"), False)

out = tr.execute_tool("query_tls", {"sni": "example.com"})
check("the call succeeds", out.get("error"), None)
check("and the payload carries the rows", len(out["result"]["rows"]), 5)
check("and the coverage block survives the envelope",
      "coverage" in out["result"], True)

# The description has to warn about the thing that will otherwise be misread.
desc = next(t for t in tr.TOOL_MANIFEST if t["name"] == "query_tls")["description"]
check("the description tells the model to read coverage first",
      "hellos_unreadable" in desc, True)
check("and says a ja3 is not a verdict", "NOT a verdict" in desc, True)
check("and says the name is attacker-authored text",
      "untrusted" in desc, True)


print("\n[7] a fresh database and a migrated one end up the same shape")
# The standard check since v30. A table created by Schema.SQL and the same
# table created by the migration must not drift, or a fresh install and an
# upgraded one behave differently and only one of them is ever tested.
from core import migrations                           # noqa: E402

fresh = sqlite3.connect(":memory:")
fresh.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))

migrated = sqlite3.connect(":memory:")
migrated.execute("CREATE TABLE _nothing (x INTEGER)")
migrations._migrate_tls_hello(migrated)
# v56 adds the transport column to the same table.
migrations._migrate_quic_and_dns_answers(migrated)

def shape(conn):
    cols = [(r[1], r[2], r[3], r[4]) for r in
            conn.execute("PRAGMA table_info(tls_hello)")]
    idx = sorted(r[1] for r in conn.execute("PRAGMA index_list(tls_hello)")
                 if not r[1].startswith("sqlite_autoindex"))
    return cols, idx

fc, fi = shape(fresh)
mc, mi = shape(migrated)
check("same columns, same types, same nullability", fc, mc)
check("same named indexes", fi, mi)
check("and the table is not empty of columns", len(fc) > 10, True)

# Idempotent: running it twice must not raise and must not add a second table.
check("the migration is idempotent", migrations._migrate_tls_hello(migrated), 0)

# THE CHECK CONSTRAINT IS REAL. v32 found three constraints written as
# `x IN (a,b,NULL)`, which enforce nothing, because a CHECK passes on NULL.
try:
    migrated.execute(
        "INSERT INTO tls_hello (first_seen,last_seen,src_ip,dst_ip,sni_state) "
        "VALUES ('t','t','1.1.1.1','2.2.2.2','banana')")
    refused = False
except sqlite3.IntegrityError:
    refused = True
check("an invented sni_state is refused by the database", refused, True)


print("\n[8] end to end: bytes in, domain out")
def u16(n): return bytes([(n >> 8) & 0xFF, n & 0xFF])
name = b"cdn.example.net"
entry = b"\x00" + u16(len(name)) + name
sni_ext = b"\x00\x00" + u16(len(entry) + 2) + u16(len(entry)) + entry
body = (u16(0x0303) + b"\x11" * 32 + b"\x00"
        + u16(2) + u16(0xC02F) + b"\x01\x00" + u16(len(sni_ext)) + sni_ext)
handshake = b"\x01" + bytes([0, 0, len(body)]) + body
wire = b"\x16" + u16(0x0301) + u16(len(handshake)) + handshake

parsed = th.parse_client_hello(wire)
check("the wire bytes parse", parsed["ok"], True)
me.save_tls_hellos([{**parsed, "src_ip": "192.0.2.5", "dst_ip": "203.0.113.9",
                     "dst_port": 443, "process_name": "curl.exe",
                     "process_pid": 99}])
got = me.query_tls(sni="cdn.example.net")["rows"]
check("and the domain comes back out of the database", got[0]["sni"], "cdn.example.net")
check("with the fingerprint that was computed from the bytes",
      got[0]["ja3_md5"], parsed["ja3_md5"])
check("and the process that opened it", got[0]["process_name"], "curl.exe")
check("no payload was stored anywhere on the row",
      any("16030" in str(v) for v in got[0].values()), False)


print("\n[9] the sniffer's own path, reassembly included")
# Not a mock of the wiring, the wiring. Sections 109 and 112 both shipped a
# feature whose plumbing was broken in a way no unit test touched, and both
# were caught by exercising the real call instead of the pieces.
#
# CONVERTED TO THIS PLATFORM, 2026-09-21. The Windows sniffer took six
# positional arguments and BUFFERED finished hellos in `_tls_buffer`, flushed
# separately. The Linux one takes `(payload, data)` where `data` is the
# analyzed packet dict, and WRITES EACH FINISHED HELLO STRAIGHT THROUGH to
# memory_engine -- there is no buffer and no flush on this side, which is why
# `_tls_buffer` does not appear below and the checks read the TABLE instead.
# The reassembly itself is identical and is the part that mattered.
def hello_wire(host, pad_bytes=0):
    """A real ClientHello on the wire, optionally padded past one segment."""
    def u16b(n): return bytes([(n >> 8) & 0xFF, n & 0xFF])
    nm = host.encode()
    entry = b"\x00" + u16b(len(nm)) + nm
    sni_x = b"\x00\x00" + u16b(len(entry) + 2) + u16b(len(entry)) + entry
    exts = sni_x
    if pad_bytes:
        exts += b"\x00\x15" + u16b(pad_bytes) + b"\x00" * pad_bytes
    bdy = (u16b(0x0303) + b"\x11" * 32 + b"\x00" + u16b(2) + u16b(0xC02F)
           + b"\x01\x00" + u16b(len(exts)) + exts)
    hsk = b"\x01" + bytes([(len(bdy) >> 16) & 0xFF, (len(bdy) >> 8) & 0xFF,
                           len(bdy) & 0xFF]) + bdy
    return b"\x16" + u16b(0x0301) + u16b(len(hsk)) + hsk


from adapters import LinuxPacketSniffer as Sniffer     # noqa: E402


def _pkt(src, dst, sport, dport=443, proc="", pid=None):
    """The analyzed-packet dict _handle_tls reads, for one segment."""
    return {"src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport,
            "process_name": proc, "pid": pid}


print("\n[9a] a hello that arrives in one packet goes straight to the table")
snif = Sniffer("test-session")
snif._handle_tls(hello_wire("single-segment.test"), {
    "src_ip": "192.0.2.5", "dst_ip": "203.0.113.20",
    "src_port": 51000, "dst_port": 443,
    "process_name": "chrome.exe", "pid": 4242})

snif._flush_tls()                  # rows are batched (TP-17)
landed = me.query_tls(sni="single-segment.test")["rows"]
check("a finished hello reaches the table", len(landed), 1)
check("stamped with the session that captured it",
      landed[0]["session_id"], "test-session")
check("and attributed to the process that sent it",
      landed[0]["process_name"], "chrome.exe")
st = snif.status()
check("the status tile counts what was read", st["tls_hellos_this_run"], 1)
check("and nothing is held or abandoned",
      (st["tls_pending"], st["tls_abandoned_this_run"]), (0, 0))


print("\n[9b] a hello that parses but carries NO NAME is 'absent', not "
      "'unreadable'")
# THE DISTINCTION THE WHOLE FEATURE RESTS ON, and the one _unreadable()'s
# docstring calls out: 'unreadable' says we could not finish parsing, 'absent'
# says the hello parsed cleanly and carried no server name. The two must never
# collapse into one another, because the first means LOOK AGAIN and the second
# means there is nothing there.
#
# (A hello that is merely INCOMPLETE is neither: it is HELD, awaiting the rest
# of its bytes, and section [11] covers what happens when they never come.)
def hello_no_sni():
    """A real ClientHello with no server_name extension at all."""
    def u16b(n): return bytes([(n >> 8) & 0xFF, n & 0xFF])
    bdy = (u16b(0x0303) + b"\x11" * 32 + b"\x00" + u16b(2) + u16b(0xC02F)
           + b"\x01\x00" + u16b(0))
    hsk = b"\x01" + bytes([(len(bdy) >> 16) & 0xFF, (len(bdy) >> 8) & 0xFF,
                           len(bdy) & 0xFF]) + bdy
    return b"\x16" + u16b(0x0301) + u16b(len(hsk)) + hsk


snif_b = Sniffer("absent-session")
snif_b._handle_tls(hello_no_sni(), _pkt("192.0.2.5", "203.0.113.30", 51002,
                                        proc="curl", pid=99))
snif_b._flush_tls()                  # rows are batched (TP-17)
landed_b = me.query_tls(dst_ip="203.0.113.30")["rows"]
check("it IS a row, because the hello was read", len(landed_b), 1)
check("and its state is 'absent', not 'unreadable'",
      landed_b[0]["sni_state"], "absent")
check("and it does not add to the unreadable count",
      snif_b.status()["tls_unreadable_this_run"], 0)
check("but it does count as read", snif_b.status()["tls_hellos_this_run"], 1)


print("\n[10] THE ONE THAT MATTERED: a hello that arrives in two packets")
# MEASURED, NOT IMAGINED. Ten minutes of capture on the owner's machine on
# 2026-09-19, the first run with this feature live: 124 hellos, ONE parsed,
# 123 truncated. Post-quantum key exchange is why. A browser offering
# X25519MLKEM768 sends a key share over a kilobyte long, so its ClientHello
# does not fit in a 1460 byte segment.
#
# Version one of this feature read a single packet. It therefore read a
# vendor updater and missed every browser on the machine, while reporting
# that perfectly honestly and being nearly useless. This section is the fix.
import time                                            # noqa: E402

wire = hello_wire("postquantum.example", pad_bytes=2000)
check("the hello really is bigger than one segment", len(wire) > 1460, True)

# First, the proof that ONE packet is not enough. This is what the owner's machine
# was doing 123 times out of 124.
one_packet = th.parse_client_hello(wire[:1460])
check("one segment alone cannot be parsed", one_packet["ok"], False)
check("and it says so as truncation, not as a missing name",
      (one_packet["truncated"], one_packet["sni_state"]),
      (True, "unreadable"))
snif2 = Sniffer("reassembly-test")
snif2._handle_tls(wire[:1460], _pkt("192.0.2.5", "203.0.113.20", 50001,
                                    proc="chrome.exe", pid=4242))
check("the first segment is HELD, not written off", len(snif2._tls_pending), 1)
snif2._flush_tls()                  # rows are batched (TP-17)
check("and nothing reached the table yet",
      me.query_tls(sni="postquantum")["rows"], [])

# The continuation carries no process of its own, deliberately: by the time
# the second segment arrives the socket can already be gone from the
# connection table, so attribution has to come from the FIRST one.
snif2._handle_tls(wire[1460:], _pkt("192.0.2.5", "203.0.113.20", 50001))
check("the second segment completes it", len(snif2._tls_pending), 0)
snif2._flush_tls()                  # rows are batched (TP-17)
queued = me.query_tls(sni="postquantum")["rows"]
check("and it reaches the table once, not twice", len(queued), 1)
check("with the name that was only readable across both packets",
      queued[0]["sni"], "postquantum.example")
check("and the process from the first segment, not the empty second",
      (queued[0]["process_name"], queued[0]["process_pid"]),
      ("chrome.exe", 4242))
check("and it reaches the table as readable",
      queued[0]["sni_state"], "present")
check("with the reassembly counted, because one packet was not enough",
      snif2.status()["tls_reassembled_this_run"], 1)


print("\n[11] a continuation that never comes is still counted")
# The other half of rule two. Holding bytes forever would quietly lose the
# fact that a handshake happened at all, so an abandoned flow becomes one
# unreadable row with its reason, not silence.
snif3 = Sniffer("reap-test")
snif3._handle_tls(wire[:1460], _pkt("192.0.2.5", "198.51.100.30", 50002,
                                    proc="firefox.exe", pid=7))
check("held", len(snif3._tls_pending), 1)
check("nothing reaped while it is still young", snif3._reap_pending_tls(), 0)

# Reach in and age it rather than sleeping ten seconds in a test.
for k in snif3._tls_pending:
    snif3._tls_pending[k]["at"] -= 999
check("an aged flow is given up on", snif3._reap_pending_tls(), 1)
# THIS TREE HAS NO FLUSH BUFFER, so the record to read is the coverage block
# on the table -- which is exactly where an answer would look for it. The
# Windows file read `_tls_buffer[0]`; the assertions below are the same facts
# read from the table instead.
# Filtered by THIS section's destination, because query_tls has no session
# filter and earlier sections' rows are still in the same isolated database.
snif3._flush_tls()                  # rows are batched (TP-17)
aged = me.query_tls(dst_ip="198.51.100.30")["rows"]
check("and it is recorded rather than dropped",
      me.query_tls()["coverage"]["hellos_unreadable"] >= 1, True)
check("as unreadable, kept OUT of the rows", aged, [])
why = me.query_tls()["coverage"]["why_unreadable"]
check("with a reason that says the rest never came",
      any("never arrived" in str(r.get("reason", "")) for r in why), True)
_st = snif3.status()
check("and the status tile counts it as unreadable too",
      _st["tls_unreadable_this_run"], 1)


print("\n[12] the held bytes are bounded three ways")
# This buffer is keyed on what a device chooses to send, so it is something
# an attacker on the LAN could try to grow. Flows, bytes per flow, and age
# are all capped, and going over any of them records a row rather than
# vanishing. THE CAPS LIVE ON THE SNIFFER CLASS here, not in
# packet_sniffer_linux: the reassembly is in adapters.py on this platform.
check("there is a flow cap", Sniffer.MAX_PENDING_HELLOS > 0, True)
check("a byte cap", Sniffer.MAX_PENDING_BYTES > 0, True)
check("and a time cap", Sniffer.PENDING_TTL_SEC > 0, True)

snif4 = Sniffer("cap-test")
# Over the byte cap in one go: recorded as unreadable, never held.
snif4._handle_tls(
    b"\x16\x03\x01\xff\xff\x01" + b"\x00" * (Sniffer.MAX_PENDING_BYTES + 10),
    _pkt("192.0.2.5", "203.0.113.40", 50003, proc="huge.exe", pid=1))
check("an oversized hello is not held", len(snif4._tls_pending), 0)
snif4._flush_tls()                  # rows are batched (TP-17)
check("it is recorded instead", snif4.status()["tls_unreadable_this_run"], 1)
check("kept out of the rows for that destination too",
      me.query_tls(dst_ip="203.0.113.40")["rows"], [])
_huge_why = me.query_tls()["coverage"]["why_unreadable"]
check("as unreadable with the size named",
      any("larger than" in str(r.get("reason", "")) for r in _huge_why), True)

# Over the flow cap: the oldest is evicted AND counted.
snif5 = Sniffer("flood-test")
for i in range(Sniffer.MAX_PENDING_HELLOS + 5):
    snif5._handle_tls(wire[:1460],
                      _pkt("192.0.2.5", "203.0.113.50", 40000 + i,
                           proc="flood.exe", pid=i))
check("held flows never exceed the cap",
      len(snif5._tls_pending) <= Sniffer.MAX_PENDING_HELLOS, True)
check("and the evictions are counted, not silent",
      snif5.status()["tls_abandoned_this_run"] >= 5, True)
check("the status tile shows what is currently half-read",
      snif5.status()["tls_pending"], Sniffer.MAX_PENDING_HELLOS)


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
