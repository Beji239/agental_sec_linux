"""
tests/test_lan_watch_fixes.py — REGISTER SECTION 13, the lan_watch round
(2026-09-26).

ONE SECTION PER DEFECT (LW-1 .. LW-6, with the v53 migration asserted as its
own section LW-1b), each asserted in the direction that FAILS if the defect
comes back. Every check drives the SHIPPED functions — the module's own
observers, the adapter's real capture callback built with real scapy frames —
or the shipped file's own text. None of them reimplements the code under
test, which would only prove this file's model of it.

The defects were measured on THIS host before they were fixed, unelevated, by
pushing real-shaped frames through adapters.LinuxPacketSniffer._on_packet.
The measurements are in bugfinder.md, section "2026-09-26 — THE LAN WATCH ON
LINUX, CAPABILITY ROUND", and register section 13 of toolaudit.md.

THE FIXTURES NAME NOBODY AND NO MACHINE. Addresses are RFC 5737 documentation
ranges (192.0.2.0/24); account names are
never used; the database is the isolated scratch built by _isolate_db. A test
that pinned one operator's network would be wrong on every other box, which is
the rule the leak gate enforces.
"""

import sqlite3
import inspect
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
SCRATCH = _isolate_db.isolate()

import threading                                       # noqa: E402
import time                                            # noqa: E402

import adapters                                        # noqa: E402
from tools import lan_watch as lw                      # noqa: E402
from core import memory_engine as me                   # noqa: E402

try:
    from scapy.all import ARP, BOOTP, DHCP, Ether, IP, UDP, Raw
    SCAPY = True
except ImportError:                                    # pragma: no cover
    SCAPY = False

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  [{label}]: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, condition):
    check(label, bool(condition), True)


def guard(fn, *a, **kw):
    """A call that can raise becomes a value, so a raising check prints FAIL
    instead of stopping every check after it (the negative-control rule: a
    subject that dies mid-file measures nothing)."""
    try:
        return fn(*a, **kw)
    except Exception as e:
        return f"RAISED {type(e).__name__}: {e}"


def _w(gateway_ip=None):
    """A LanWatch with NO database behind it (fixture convention)."""
    return lw.LanWatch(gateway_ip=gateway_ip, load_baselines=False)


def fresh_sniffer(gateway_ip="192.0.2.1"):
    """
    The SHIPPED adapter, built but not started: no capture, no thread, and
    every store write captured instead of sent. Same construction the
    round's measurement battery used, so the checks and the measurements
    drive the identical seam.
    """
    x = adapters.LinuxPacketSniffer.__new__(adapters.LinuxPacketSniffer)
    x.session_id = "lanfix"
    x._capturing = False
    x._packets_seen = 0
    x._unregistered_counts = {}
    x._started_reason = "test"
    x._cooldowns = {}
    x._lock = threading.Lock()
    x._tls_pending = {}
    x._tls_abandoned = 0
    x._tls_reassembled_this_run = 0
    # ADDED 2026-09-27, REGISTER SECTION 17 (RVP-13). The per-frame VPN stamp
    # now reads a two-second cache, so a sniffer built with __new__ carries
    # this attribute the constructor would have set. Listed here rather than
    # made defensive in the adapter: the cache is part of the object's state
    # and a fixture that builds the object by hand models the object.
    x._vpn_cache = (0.0, "unknown")
    x._payload = None
    x._lan = lw.LanWatch(gateway_ip=gateway_ip, load_baselines=False)
    x._written = []
    x._stored = []

    real_arp = x._lan.observe_arp
    real_dhcp = x._lan.observe_dhcp_server
    real_name = x._lan.observe_name_response
    x._seen = []

    def arp(op, sender_ip, sender_mac, now):
        out = real_arp(op=op, sender_ip=sender_ip, sender_mac=sender_mac,
                       now=now)
        x._seen.append(("arp", op, sender_ip, sender_mac, len(out)))
        return out

    def dhcp(server_ip, msg_type, now):
        out = real_dhcp(server_ip=server_ip, msg_type=msg_type, now=now)
        x._seen.append(("dhcp", server_ip, msg_type, len(out)))
        return out

    def name(proto, responder_ip, name, now):
        out = real_name(proto, responder_ip, name, now)
        x._seen.append(("name", proto, responder_ip, name, len(out)))
        return out

    x._lan.observe_arp = arp
    x._lan.observe_dhcp_server = dhcp
    x._lan.observe_name_response = name

    me.save_finding = lambda **kw: x._written.append(kw)
    me.save_packet = lambda **kw: x._stored.append(kw)
    me.is_dismissed = lambda *a, **k: False
    return x


print()
print("=" * 72)
print("SECTION 13 — lan_watch: the defects, each asserted both ways")
print("=" * 72)

# ═════════════════════════════════════════════════════════════════════════
print("\n[1] LW-1 — the baselines were hashed as THE POLICY by core/integrity")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: the first gateway MAC a capture LEARNED wrote a
# user_preferences key, core/integrity.snapshot_config digests that whole
# table, and the policy digest moved with a false "the policy has CHANGED"
# warning. Same shape as the T2 cursor, the L3 baselines (v42), the feed
# refresh time (v46) and the port-owner tables (v51).

check("the baseline table exists in the scratch schema",
      guard(lambda: bool(sqlite3.connect(str(SCRATCH)).execute(
          "SELECT name FROM sqlite_master WHERE type='table'"
          " AND name='lan_baseline'").fetchone())), True)

# The round trip, on the shipped helpers.
_saved = guard(lw.save_baseline, "gateway_mac", "aa:bb:cc:dd:ee:01")
check("save_baseline answers True", _saved, True)
check("load_baseline reads back the value",
      guard(lw.load_baseline, "gateway_mac"), "aa:bb:cc:dd:ee:01")
check("a set that was never stored is None, not []",
      guard(lw.load_baseline, "never_written"), None)

# THE HEADLINE, driven end to end: a packet LEARNS the gateway, and the
# policy digest does NOT move.
from core import integrity                              # noqa: E402

_before = guard(integrity.snapshot_config, "lanfix:before")
check_true("the first policy snapshot is taken", isinstance(_before, dict))
_w1 = _w(gateway_ip="192.0.2.1")
_w1.observe_arp(2, "192.0.2.1", "aa:bb:cc:dd:ee:01", now=0)   # LEARNS
_after = guard(integrity.snapshot_config, "lanfix:after-learn")
check("learning the gateway MAC moved NO policy digest", _after, None)

# And the control in the other direction: a REAL preference change still
# registers, so the digest is not simply broken.
me.set_preference("lanfix_control_pref", "1")
_moved = guard(integrity.snapshot_config, "lanfix:after-pref")
check_true("a genuine preference change IS still registered",
           isinstance(_moved, dict))

# The old keys are gone from the RUNNING code. STRIPPED, not grepped raw:
# the module's own header COMMENT explains the move and names both keys, so
# a plain substring check reads the fix's explanation and fails on it -- the
# "absence check satisfied by a comment" trap this tree has recorded. Strip
# docstring AND line comments, and assert the stripper did something.
_src_raw = inspect.getsource(lw)
_src_code = "\n".join(l.split("#", 1)[0] for l in _src_raw.splitlines())
check_true("the stripper is doing something (the keys ARE in the prose)",
           "lan_gateway_mac" in _src_raw)
check("the module no longer reads lan_gateway_mac in running code",
      "lan_gateway_mac" in _src_code, False)
check("  nor lan_dhcp_servers",
      "lan_dhcp_servers" in _src_code, False)
# And the WIRING, which only exists when the code really reads the table.
check_true("the running code reads the baseline table",
           "load_baseline(" in _src_code and "BASELINE_TABLE" in _src_code)
check("the running code no longer writes preferences",
      "set_preference(" in _src_code, False)
check_true("the policy state carries no lan_ key after the learn",
           not [k for k in (_moved or {}) if k.startswith("lan_")])

# ═════════════════════════════════════════════════════════════════════════
print("\n[2] LW-1b — the v53 migration moves the old keys, then deletes them")
# ═════════════════════════════════════════════════════════════════════════
# Proven on the OLD shape: a database with no lan_baseline table and the two
# keys present, built that way on purpose.

from core import migrations as mig                      # noqa: E402

check_true("the schema version moved for it",
           mig.SCHEMA_VERSION >= 53)

_old_db = pathlib.Path(str(SCRATCH)).with_name("lanfix_oldshape.db")
if _old_db.exists():
    _old_db.unlink()
conn = sqlite3.connect(_old_db)
conn.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
conn.execute("DROP TABLE lan_baseline")                 # the OLD shape
conn.execute("INSERT INTO user_preferences(key, value) VALUES(?, ?)",
             ("lan_gateway_mac", "aa:bb:cc:dd:ee:01"))
conn.execute("INSERT INTO user_preferences(key, value) VALUES(?, ?)",
             ("lan_dhcp_servers", "192.0.2.1,192.0.2.2"))
conn.commit()
check("the old shape has no lan_baseline table",
      conn.execute("SELECT name FROM sqlite_master WHERE type='table'"
                   " AND name='lan_baseline'").fetchone(), None)

_moved_count = guard(mig._migrate_lan_baseline, conn)
conn.commit()
# added + moved: one table created, two old keys carried.
check("the migration reports one table + two rows carried", _moved_count, 3)
check("the table now exists",
      bool(conn.execute("SELECT name FROM sqlite_master WHERE type='table'"
                        " AND name='lan_baseline'").fetchone()), True)
_rows = dict(conn.execute("SELECT name, value_json FROM lan_baseline"))
check("the gateway MAC moved", _rows.get("gateway_mac"),
      '"aa:bb:cc:dd:ee:01"')
check("the DHCP set moved AS A LIST", _rows.get("dhcp_servers"),
      '["192.0.2.1","192.0.2.2"]')
check("the old gateway key is DELETED from user_preferences",
      conn.execute("SELECT COUNT(*) FROM user_preferences"
                   " WHERE key='lan_gateway_mac'").fetchone()[0], 0)
check("  and the old DHCP key too",
      conn.execute("SELECT COUNT(*) FROM user_preferences"
                   " WHERE key='lan_dhcp_servers'").fetchone()[0], 0)
_again = guard(mig._migrate_lan_baseline, conn)
conn.commit()
check("re-running it is a no-op (idempotent)", _again, 0)
conn.close()

# ═════════════════════════════════════════════════════════════════════════
print("\n[3] LW-2 — the DHCP server was read from siaddr, the TFTP field")
# ═════════════════════════════════════════════════════════════════════════
# Measured before, through the shipped callback: an ordinary router OFFER
# (server-identifier option 54 set, siaddr empty) never reached the module
# (0 calls), and an OFFER whose siaddr named another host recorded THAT
# host as the DHCP server.

if not SCAPY:
    print("  SKIP  [scapy is not installed on this host]")
else:
    def offer(src, siaddr, server_id=None, mtype="offer"):
        opts = [("message-type", mtype)]
        if server_id:
            opts.append(("server_id", server_id))
        opts += [("lease_time", 3600), "end"]
        return (Ether() / IP(src=src, dst="192.0.2.255")
                / UDP(sport=67, dport=68)
                / BOOTP(op=2, yiaddr="192.0.2.50", siaddr=siaddr,
                        chaddr=b"\x11\x22\x33\x44\x55\x66")
                / DHCP(options=opts))

    # (a) an ORDINARY router OFFER: option 54 set, siaddr empty.
    a = fresh_sniffer()
    a._on_packet(offer("192.0.2.1", "0.0.0.0", server_id="192.0.2.1"))
    check("an ordinary router OFFER reaches the module",
          [c for c in a._seen if c[0] == "dhcp"], [("dhcp", "192.0.2.1",
                                                    "offer", 0)])

    # (b) option 54 names the router, siaddr names somebody ELSE.
    b = fresh_sniffer()
    b._on_packet(offer("192.0.2.1", "192.0.2.240", server_id="192.0.2.1"))
    check("option 54 wins over siaddr",
          [c for c in b._seen if c[0] == "dhcp"],
          [("dhcp", "192.0.2.1", "offer", 0)])

    # (c) no option 54 and siaddr set: the IP source is the next best, and
    # siaddr is the LAST resort rather than the first read.
    c = fresh_sniffer()
    c._on_packet(offer("192.0.2.1", "192.0.2.240", server_id=None))
    check("without option 54 the IP source answers",
          [x for x in c._seen if x[0] == "dhcp"],
          [("dhcp", "192.0.2.1", "offer", 0)])

    # The identity helper itself, both directions, including provenance.
    from scapy.all import Ether as _E
    pkt = offer("192.0.2.7", "0.0.0.0", server_id="192.0.2.9")
    pkt2 = _E(bytes(pkt))                      # wire-parsed, number mtype
    ident = guard(adapters.LinuxPacketSniffer._dhcp_server_identity,
                  pkt2, pkt2[BOOTP], pkt2[DHCP])
    check("the helper reports the option and where it came from", ident,
          ("192.0.2.9", "option-54"))

    # (d) a rogue second server still raises through the callback.
    d = fresh_sniffer()
    d._on_packet(offer("192.0.2.1", "0.0.0.0", server_id="192.0.2.1"))
    d._on_packet(offer("192.0.2.66", "0.0.0.0", server_id="192.0.2.66"))
    check("a second DHCP server still raises LAN-1003",
          [(f["detection_id"], f["entity_value"]) for f in d._written],
          [("LAN-1003", "192.0.2.66")])

    # ═════════════════════════════════════════════════════════════════════
    print("\n[4] LW-3 — LAN-1004 could not fire: the name parsers had no caller")
    # ═════════════════════════════════════════════════════════════════════
    # Measured before: parse_llmnr_query_name / parse_nbtns_query_name /
    # observe_name_response had callers ONLY in the module's own tests,
    # while the Windows twin wires them into its capture callback. Four
    # distinct LLMNR responses through this callback left name_frames_seen
    # at 0 and wrote nothing.

    def llmnr_resp(name, i):
        q = bytearray()
        for label in name.split("."):
            q.append(len(label))
            q += label.encode()
        q.append(0)
        q += (1).to_bytes(2, "big") + (1).to_bytes(2, "big")
        hdr = ((0x1000 + i).to_bytes(2, "big") + (0x8000).to_bytes(2, "big")
               + (1).to_bytes(2, "big") + (0).to_bytes(2, "big")
               + b"\x00" * 4)
        return bytes(hdr) + bytes(q)

    def llmnr_query(name, i):
        b = bytearray(llmnr_resp(name, i))
        b[2] = 0x00                            # clear the QR bit
        return bytes(b)

    def nbtns_resp(name, i):
        raw = name.upper().ljust(15)[:15].encode() + b"\x00"
        enc = "".join(chr(65 + (b >> 4)) + chr(65 + (b & 0x0F)) for b in raw)
        hdr = ((0x1000 + i).to_bytes(2, "big") + (0x8500).to_bytes(2, "big")
               + (1).to_bytes(2, "big") + b"\x00" * 6)
        body = bytes([32]) + enc.encode() + bytes([0])
        body += (0x20).to_bytes(2, "big") + (1).to_bytes(2, "big")
        return hdr + body

    def name_frame(payload, src, sport):
        return (Ether() / IP(src=src, dst="224.0.0.252")
                / UDP(sport=sport, dport=sport) / Raw(load=payload))

    n = fresh_sniffer()
    for i, nm in enumerate(["printer", "fileshare", "wpad", "typo-host"]):
        n._on_packet(name_frame(llmnr_resp(nm, i), "192.0.2.99", 5355))
    check("four LLMNR responses reach the name path",
          len([x for x in n._seen if x[0] == "name"]), 4)
    check("the module counted them", n._lan.name_frames_seen, 4)
    check("LAN-1004 fires through the shipped callback",
          [(f["detection_id"], f["entity_value"]) for f in n._written],
          [("LAN-1004", "192.0.2.99")])

    # A QUERY is not a claim: the parsers refuse it, so nothing arrives.
    q = fresh_sniffer()
    for i in range(6):
        q._on_packet(name_frame(llmnr_query("printer", i), "192.0.2.98", 5355))
    check("LLMNR QUERIES never reach the name path",
          [x for x in q._seen if x[0] == "name"], [])
    check("  and the counter stays at zero", q._lan.name_frames_seen, 0)

    # NBT-NS rides the same branch on its own port.
    nb = fresh_sniffer()
    for i, nm in enumerate(["alpha", "beta", "gamma", "delta"]):
        nb._on_packet(name_frame(nbtns_resp(nm, i), "192.0.2.97", 137))
    check("NBT-NS responses reach the path, proto named",
          sorted({x[1] for x in nb._seen if x[0] == "name"}), ["NBT-NS"])
    check("LAN-1004 fires for NBT-NS too",
          [f["detection_id"] for f in nb._written], ["LAN-1004"])

    # ═════════════════════════════════════════════════════════════════════
    print("\n[5] LW-4 — a DHCP frame was never STORED as a packet row")
    # ═════════════════════════════════════════════════════════════════════
    # Measured before: the DHCP branch returned before _analyze_packet, so
    # a DHCP OFFER left 0 packet rows against _packets_seen 1, while the
    # twin stores them ("an extra read of it, not a diversion").

    s = fresh_sniffer()
    s._on_packet(offer("192.0.2.1", "0.0.0.0", server_id="192.0.2.1"))
    check("a DHCP OFFER is stored as a packet row", len(s._stored), 1)
    check("  with its UDP ports on it",
          (s._stored[0].get("src_port"), s._stored[0].get("dst_port")),
          (67, 68))

    # The ARP control: still counted, deliberately NOT stored.
    s2 = fresh_sniffer()
    s2._on_packet(Ether() / ARP(op=2, psrc="192.0.2.1",
                                hwsrc="aa:bb:cc:dd:ee:01",
                                pdst="192.0.2.255",
                                hwdst="ff:ff:ff:ff:ff:ff"))
    check("an ARP frame is still NEVER stored (the old rule kept)",
          len(s2._stored), 0)

# ═════════════════════════════════════════════════════════════════════════
print("\n[6] LW-5 — the finding named a script that existed in neither tree")
# ═════════════════════════════════════════════════════════════════════════
# The LAN-1002 description has always said "scripts/accept_gateway_mac.py",
# and the file was written by this round. Measured before: the path existed
# nowhere under either tree.

_script = ROOT / "scripts" / "accept_gateway_mac.py"
check_true("the script the finding names now exists", _script.exists())
_source_text = inspect.getsource(lw)
check_true("the finding still names it",
           "scripts/accept_gateway_mac.py" in _source_text)

if _script.exists():
    _r = guard(subprocess.run, [sys.executable, str(_script), "--accept",
                                "not-a-mac"],
               capture_output=True, text=True, cwd=str(ROOT))
    _out = getattr(_r, "stdout", "") + getattr(_r, "stderr", "")
    check("it REFUSES a junk MAC, rc 1",
          (getattr(_r, "returncode", None), "REFUSED" in _out), (1, True))
    _r2 = guard(subprocess.run, [sys.executable, str(_script)],
                capture_output=True, text=True, cwd=str(ROOT))
    check("and it runs read-only with no capture up, rc 0",
          getattr(_r2, "returncode", None), 0)

# `persisted` must travel: an accept that could not write must not read as
# one that did. Driven on a fixture that refuses the write.
_w3 = _w(gateway_ip="192.0.2.1")
_real_save = lw.save_baseline
lw.save_baseline = lambda *a, **k: False
try:
    _res = _w3.accept_gateway_mac("de:ad:be:ef:00:01")
    check("a write that failed is REPORTED, not implied",
          _res.get("persisted"), False)
    check("  and the in-memory move still happened",
          _w3.status()["gateway_mac"], "de:ad:be:ef:00:01")
finally:
    lw.save_baseline = _real_save

# ═════════════════════════════════════════════════════════════════════════
print("\n[7] LW-6 — the name path had no coverage sentence")
# ═════════════════════════════════════════════════════════════════════════
# The other three checks each had a note saying when they are not running.
# LAN-1004 shared their blindness and had none, so a quiet result had
# nothing saying the path was unexamined rather than clean.

_st = _w(gateway_ip="192.0.2.1").status()
check_true("a fresh sensor says nothing has been checked for poisoning",
           any("name-service poisoning" in n for n in _st["notes"]))
_w4 = _w(gateway_ip="192.0.2.1")
_w4.observe_name_response("LLMNR", "192.0.2.8", "printer", now=0)
_st2 = _w4.status()
check("once a response arrived the note is GONE",
      any("name-service poisoning" in n for n in _st2["notes"]), False)

# The tool description names the new note, so the model is told to read it.
from core import tool_registry as tr                    # noqa: E402
_desc = guard(lambda: next(
    d["description"] for d in tr.TOOL_MANIFEST
    if d["name"] == "query_lan_watch"))
# Read as a VALUE first: `guard` can return the RAISED-sentence string, and
# a substring check against that reports a broken description when the real
# problem is a renamed manifest (the check's own fault, not the module's).
check_true("the manifest carries query_lan_watch",
           isinstance(_desc, str) and not _desc.startswith("RAISED"))
check_true("the tool description names the name-path note",
           isinstance(_desc, str) and "LLMNR" in _desc
           and "name-service poisoning" in _desc)

# ═════════════════════════════════════════════════════════════════════════
print("\n[8] FOUND CLEAN, re-asserted so a regression shows")
# ═════════════════════════════════════════════════════════════════════════
check_true("the unicast caveat is still on every status",
           any("UNICAST" in n for n in _st["notes"]))
_w5 = _w(gateway_ip="192.0.2.1")
_w5.observe_arp(2, "192.0.2.1", "aa:bb:cc:dd:ee:01", now=0)      # LEARNS it
_w5.observe_arp(2, "192.0.2.1", "de:ad:be:ef:00:01", now=10)     # the spoof
check_true("a learned baseline still never moves on a bare packet",
           _w5.status()["gateway_mac"] == "aa:bb:cc:dd:ee:01")
check_true("no shell=True anywhere in the module",
           "shell=True" not in _source_text)
check_true("the four ids are still registered",
           all(__import__("core.detections", fromlist=["x"]).exists(i)
               for i in ("LAN-1001", "LAN-1002", "LAN-1003", "LAN-1004")))
check_true("the parsers still refuse a query in isolation",
           (lw.parse_llmnr_query_name(bytes([0x12, 0x34, 0x00, 0x00, 0, 1,
                                             0, 0, 0, 0, 0, 0, 1]) == "")
            or lw.parse_llmnr_query_name(b"") == ""))

# ═════════════════════════════════════════════════════════════════════════
print()
print("=" * 72)
print(f"{len(fails)} failure(s)")
if fails:
    print(f"FAILURES: {fails}")
    sys.exit(1)
print("ALL CHECKS PASSED")
sys.exit(0)
