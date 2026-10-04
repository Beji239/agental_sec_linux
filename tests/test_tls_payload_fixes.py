"""
tests/test_tls_payload_fixes.py — REGISTER SECTION 14, the tls_hello /
payload_ring round (2026-09-26).

ONE SECTION PER DEFECT, each asserted in the direction that FAILS if the
defect comes back. Every check drives the SHIPPED functions — the parser on
hand-built bytes, the ring on real appends, the adapter's real _handle_tls and
a real stop() — or the shipped file's own text where the defect WAS text.
None of them reimplements the code under test, which would only prove this
file's model of it.

The defects were measured on THIS host before they were fixed, unelevated,
against a WAL-correct copy of the operator's own store. The measurements are
in bugfinder.md, section "2026-09-26 — THE CAPTURE-SIDE PARSERS (tls_hello /
payload_ring)", and register section 14 of toolaudit.md. The measurement
scripts are /tmp/s14/s14_measure*.py with their outputs m2..m5.txt.

THE FIXTURES NAME NOBODY AND NO MACHINE. Addresses are RFC 5737 documentation
ranges; the names are example.test style; the database is the isolated scratch
built by _isolate_db. The one live-store figure quoted in a comment is a
COUNT, read mode=ro, with no address, name or row from the operator's store.

SECTIONS MARKED "RECORDED, NOT FIXED" assert the state of a defect that is
still open, so the round's record is testable and a later fix will visibly
change them. They are not claims that the behaviour is correct.
"""

import pathlib
import sqlite3
import struct
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
SCRATCH = _isolate_db.isolate()

from core import memory_engine as me                  # noqa: E402
from core import tool_registry as tr                  # noqa: E402
from core import sanitize                             # noqa: E402
from tools import payload_ring as pr                  # noqa: E402
from tools import tls_hello as th                     # noqa: E402
import adapters                                       # noqa: E402

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
    instead of stopping every check after it (a subject that dies mid-file
    measures nothing)."""
    try:
        return fn(*a, **kw)
    except Exception as e:
        return f"RAISED {type(e).__name__}: {e}"


def stripped(path):
    """A module's source with comments and docstrings removed.

    WHY: an absence check greps text, and the FIX'S OWN COMMENT explains the
    defect by naming it. A plain substring check reads the explanation and
    fails on it -- the "absence check satisfied by a comment" trap this tree
    has recorded (register section 13). Both halves are asserted here: that
    the stripper is doing something, and that the stripped code says what the
    check claims."""
    src = pathlib.Path(path).read_text(encoding="utf-8")
    out, in_doc = [], False
    for line in src.splitlines():
        s = line.strip()
        if s.startswith('"""') or s.startswith("'''"):
            in_doc = not in_doc
            if s.count('"""') == 2 or s.count("'''") == 2:
                in_doc = False
            continue
        if in_doc:
            continue
        out.append(line.split("#", 1)[0])
    return "\n".join(out)


# BYTE BUILDERS. Every fixture is a real ClientHello, hand-assembled.

def u16b(n):
    return struct.pack(">H", n)


def u24b(n):
    return struct.pack(">I", n)[1:]


def ext(etype, body):
    return u16b(etype) + u16b(len(body)) + body


def sni_ext_raw(raw_name, declared_len=None):
    decl = len(raw_name) if declared_len is None else declared_len
    entry = b"\x00" + u16b(decl) + raw_name
    return ext(0x0000, u16b(len(entry)) + entry)


def groups_ext_raw(body):
    return ext(0x000A, body)


def build_hello(exts, legacy=0x0303):
    ciphers = [0x1301, 0x1302, 0xC02B]
    cb = b"".join(u16b(c) for c in ciphers)
    body = (u16b(legacy) + b"\x11" * 32 + b"\x00" + u16b(len(cb)) + cb
            + b"\x01\x00" + u16b(len(exts)) + exts)
    hs = b"\x01" + u24b(len(body)) + body
    return b"\x16\x03\x01" + u16b(len(hs)) + hs


def hello_with_sni(name_bytes, extra=b""):
    return build_hello(sni_ext_raw(name_bytes) + extra)


def hello_sni_last(name_bytes, pad=1600):
    """A hello whose key_share-shaped extension comes FIRST and the SNI
    LAST, so the name sits past the first 1460-byte segment. This is the
    shape the retransmission defect (TP-19) actually corrupts."""
    exts = ext(0x0033, u16b(0x001D) + u16b(pad) + b"\x22" * pad)
    exts += groups_ext_raw(u16b(4) + u16b(0x001D) + u16b(0x0017))
    exts += sni_ext_raw(name_bytes)
    return build_hello(exts)


print()
print("=" * 72)
print("SECTION 14 — tls_hello / payload_ring: the defects, each asserted")
print("=" * 72)

# ═════════════════════════════════════════════════════════════════════════
print("\n[1] TP-1 — the SNI was stored DECODED, not as the wire carried it")
# ═════════════════════════════════════════════════════════════════════════
# MEASURED before: `xn--80ak6aa92e.com` on the wire went into the SNI column
# as a Cyrillic homograph, because an all-ASCII name was decoded with IDNA.
# Every feed row and DNS row in the store holds A-labels, so a known-bad
# feed hit on an executed handshake could not match: measured both
# directions through the shipped _feed_hit_domain. An attacker-controlled
# name defeated the app's strongest evidence path by making the row
# un-matchable, and left a homograph in the record.

_A_LABEL = b"xn--80ak6aa92e.com"
info = guard(th.parse_client_hello, hello_with_sni(_A_LABEL))
check("the A-label is stored AS THE WIRE CARRIED IT",
      info["sni"], "xn--80ak6aa92e.com")
check_true("and it is plain ASCII", info["sni"].isascii())
check("the state is 'present', a real reading", info["sni_state"], "present")
check_true("the stored name is NOT the Cyrillic homograph",
           "\u0430" not in info["sni"])

# The other direction: a raw NON-ASCII name is refused, not decoded. RFC 6066
# requires an ASCII label sequence, so this app must not invent a Unicode
# name out of bytes a device chose.
info_uni = guard(th.parse_client_hello,
                 hello_with_sni("\u0435xample.com".encode()))
check("a raw non-ASCII name is REFUSED", info_uni["sni"], None)
check("and is reported as unreadable, not absent",
      info_uni["sni_state"], "unreadable")
check_true("with a reason saying the extension had no readable name",
           "no readable name" in (info_uni.get("reason") or ""))

# THE PAYOFF, driven through the shipped matcher on an isolated database:
# a feed row holding the A-label MATCHES the stored string now. Before the
# fix this lookup answered None against the homograph column.
with me._get_conn() as conn:
    conn.execute("DELETE FROM threat_feed")
    conn.execute(
        "INSERT INTO threat_feed (indicator, indicator_type, feed, "
        "malware_family, first_added, last_refreshed) VALUES (?,?,?,?,?,?)",
        ("xn--80ak6aa92e.com", "domain", "testfeed", "TestFamily",
         "2026-01-01", "2026-01-01"))
    from tools import feed_matcher as fm               # noqa: E402
    hit = guard(fm._feed_hit_domain, conn, info["sni"])
check("a feed listing the A-label MATCHES the stored name",
      (hit[0] if isinstance(hit, tuple) else hit), "xn--80ak6aa92e.com")

# ═════════════════════════════════════════════════════════════════════════
print("\n[2] TP-2 — every frame is cut to 512 bytes and NOTHING SAID SO")
# ═════════════════════════════════════════════════════════════════════════
# MEASURED before: a 2,700 byte frame went in, the ring held 512 bytes, and
# the coverage note's loudest clause read "the conversation from its first
# captured byte". wrapped=False and frames_dropped=0 said nothing was lost.
# 2,188 bytes were thrown away at the door with no counter and no sentence.

ring = pr.PayloadRing("s14-t2", {})
frame = b"x" * 2700
ring.append("198.51.100.7", "203.0.113.9", 443, "TCP", "outbound", frame,
            now=time.time(), src_port=51001)
cov = guard(ring.coverage, "198.51.100.7", "203.0.113.9", 443, "TCP",
            src_port=51001)
check("the held bytes are the head only", cov["bytes_held"],
      pr.FRAME_HEAD_BYTES)
check("the bytes never held are PUBLISHED", cov["bytes_unheld"], 2700 - 512)
check("and the cut frames are counted", cov["frames_cut"], 1)
check_true("the note NAMES the untaken bytes",
           "2188 byte(s) of the frames held here were never taken"
           in cov["note"])
check_true("the old overclaim is gone from the note",
           "from its first captured byte" not in cov["note"]
           or "never taken" in cov["note"])

# A negative search must carry the same number beside it: a miss on a frame
# that was cut is a statement about the head only.
res = guard(ring.search, b"needle-past-offset-512", "198.51.100.7",
            "203.0.113.9", 443, "TCP", src_port=51001)
check("a miss is reported", res["matched"], False)
check("and carries how much was never held", res["bytes_unheld"], 2188)

st = guard(ring.status)
check("status publishes the ring-wide figure", st["bytes_unheld"], 2188)
check("and names the cut size", st["frames_cut_at"], pr.FRAME_HEAD_BYTES)

# ═════════════════════════════════════════════════════════════════════════
print("\n[3] TP-3 — search(b'') returned matched=True")
# ═════════════════════════════════════════════════════════════════════════
# MEASURED before: the empty needle is a substring of everything, so the one
# function built to never give a wrong answer gave the loudest one possible.

res = guard(ring.search, b"", "198.51.100.7", "203.0.113.9", 443, "TCP",
            src_port=51001)
check("an empty needle is REFUSED, not answered", res["searched"], False)
check("matched is None, never False or True", res["matched"], None)
check_true("with its own reason",
           "empty search string" in (res.get("reason") or ""))
check("and its own matched_by value",
      res["coverage"]["matched_by"], "empty_needle")

# ═════════════════════════════════════════════════════════════════════════
print("\n[4] TP-4 — the flush wrote the CALLER's port, not the flow's")
# ═════════════════════════════════════════════════════════════════════════
# MEASURED before: a detector that fired on an inbound frame holds the
# client's ephemeral port. The flush found the flow by address pair, and the
# row was written with dst_port=51001 while its bytes came off the 443
# conversation -- bytes filed under a port they were never seen on.

ring4 = pr.PayloadRing("s14-t4", {})
ring4.append("198.51.100.7", "203.0.113.7", 443, "TCP", "outbound",
             b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
             now=time.time(), src_port=51001)
out = guard(ring4.flush, "198.51.100.7", "203.0.113.7", 51001, "TCP",
            "FED-1003", src_port=None)
check("the flow was located on the address pair",
      out["coverage"]["matched_by"], "pair")
with me._get_conn() as conn:
    rows = conn.execute(
        "SELECT dst_port FROM payload_capture WHERE trigger_detection_id = ?",
        ("FED-1003",)).fetchall()
check("the row carries the FLOW's service port, not the caller's",
      [r["dst_port"] for r in rows], [443])
check("and the coverage says which port that was",
      out["coverage"]["port"], 443)

# ═════════════════════════════════════════════════════════════════════════
print("\n[5] TP-5 — arm() reported ARMED for destinations that cannot match")
# ═════════════════════════════════════════════════════════════════════════
# MEASURED before: arm("google.com") -> armed=True, arm("203.0.113.999") ->
# armed=True, arm("203.0.113.9/24") -> armed=True. The list is compared against
# frame addresses by string equality, so none of those could ever match, and
# the operator had approved writing real network content for a destination
# nobody was watching. A comma split the persisted list into two entries.

ring5 = pr.PayloadRing("s14-t5", {})
ring5._save_armed = lambda: None
check("a hostname is REFUSED", guard(ring5.arm, "google.com")["armed"], False)
check("an impossible v4 is refused",
      guard(ring5.arm, "203.0.113.999")["armed"], False)
check("a CIDR range is refused",
      guard(ring5.arm, "203.0.113.9/24")["armed"], False)
check("a host:port pair is refused",
      guard(ring5.arm, "203.0.113.9:443")["armed"], False)
check("a comma is refused (the persisted list is comma-joined)",
      guard(ring5.arm, "203.0.113.1,203.0.113.2")["armed"], False)
check("the empty string is still refused",
      guard(ring5.arm, "")["armed"], False)
check("a real v4 IS accepted", guard(ring5.arm, "203.0.113.9")["armed"], True)
check("a real v6 IS accepted", guard(ring5.arm, "2001:db8::1")["armed"],
      True)
_refusal = guard(ring5.arm, "google.com")
check_true("and the refusal says WHY in words",
           "not an IP address" in (_refusal.get("reason") or ""))

# ═════════════════════════════════════════════════════════════════════════
print("\n[6] TP-6 — eviction lost a name with NO ROW (the reaper wrote one)")
# ═════════════════════════════════════════════════════════════════════════
# MEASURED before: the make-room branch popped the oldest half-hello and
# incremented a counter no surface read. The TTL reaper records an unreadable
# row per abandoned flow; this path recorded nothing, so the coverage count
# understated how many handshakes the sensor saw and could not read.

def half_hello(host):
    """A first segment: valid so far, truncated on purpose."""
    wire = hello_with_sni(host.encode(), extra=groups_ext_raw(
        u16b(4000) + b"\x00" * 4000))
    return wire[:1460]


snif6 = adapters.LinuxPacketSniffer("s14-t6")
before = me.query_tls()["coverage"]["hellos_unreadable"]
for i in range(snif6.MAX_PENDING_HELLOS):
    snif6._handle_tls(half_hello(f"evict{i}.example"), {
        "src_ip": "198.51.100.7", "dst_ip": "203.0.113.9",
        "src_port": 40000 + i, "dst_port": 443,
        "process_name": "", "pid": None})
check("the pending table is at its cap",
      len(snif6._tls_pending), snif6.MAX_PENDING_HELLOS)
snif6._handle_tls(half_hello("one-more.example"), {
    "src_ip": "198.51.100.7", "dst_ip": "203.0.113.9",
    "src_port": 41000, "dst_port": 443, "process_name": "", "pid": None})
snif6._flush_tls()                      # rows are batched since TP-17
after = me.query_tls()["coverage"]["hellos_unreadable"]
check("making room WROTE A ROW rather than only counting", after - before, 1)
_why = me.query_tls()["coverage"]["why_unreadable"]
check_true("and the row names the eviction as the reason",
           any("evicted from the pending table" in str(r.get("reason", ""))
               for r in _why))
check("the counter moved too", snif6.status()["tls_abandoned_this_run"], 1)

# ═════════════════════════════════════════════════════════════════════════
print("\n[7] TP-13 — stop() dropped half-read hellos with no row")
# ═════════════════════════════════════════════════════════════════════════
# MEASURED before: the TTL reaper wrote an unreadable row per abandoned
# flow, the make-room branch writes one since TP-6, and stop() wrote
# nothing -- so a hello whose second segment was in flight at shutdown
# vanished from the coverage count the model is told to trust.

snif7 = adapters.LinuxPacketSniffer("s14-t7")
snif7._handle_tls(half_hello("inflight.example"), {
    "src_ip": "198.51.100.7", "dst_ip": "198.51.100.30",
    "src_port": 50002, "dst_port": 443,
    "process_name": "curl", "pid": 7})
before7 = me.query_tls()["coverage"]["hellos_unreadable"]
check("the hello is held, young enough that the TTL would NOT reap it",
      len(snif7._tls_pending), 1)
snif7.stop()
check("stop() reaped it", len(snif7._tls_pending), 0)
after7 = me.query_tls()["coverage"]["hellos_unreadable"]
check("and WROTE the unreadable row", after7 - before7, 1)
_why7 = me.query_tls()["coverage"]["why_unreadable"]
check_true("with a reason naming the stop, not the TTL",
           any("sensor stopped before the rest of this hello" in
               str(r.get("reason", "")) for r in _why7))

# ═════════════════════════════════════════════════════════════════════════
print("\n[8] TP-10 / TP-11 — the two parsers that served a value in part")
# ═════════════════════════════════════════════════════════════════════════
# TP-11 (below): parse_client_hello's docstring has always said "[] if none
# offered, None if we could not read them", and _read_alpn returned [] on
# every failure, so a present-but-unreadable extension was published as "the
# client offered no protocols" -- a statement about the client made out of
# a parse failure.
# TP-10: a name whose declared length overruns its extension used to be
# served WITH THE BYTES THAT FOLLOW IT -- a partial hostname is a DIFFERENT
# name, and a feed match against it is a false negative reported as a miss.
# THE FIXTURE HAS TO CARRY PRINTABLE TRAILING BYTES, or the reversion cannot
# be told from the fix: with control characters after it, the old code's
# stolen bytes trip the control-character refusal and both versions answer
# None. Measured both ways in the control harness (C2).
_sni_over = ext(0x0000,
                u16b(11)                    # the list holds one 11-byte entry
                + b"\x00" + u16b(20)        # host_name, declares 20 bytes
                + b"evil.com" + b"A" * 12)  # 8 real bytes + 12 printable
info_over = guard(th.parse_client_hello, build_hello(_sni_over))
check("a name whose length overruns the extension is REFUSED",
      info_over["sni"], None)
check("reported unreadable, not absent", info_over["sni_state"], "unreadable")
check_true("and it did NOT become the stolen-bytes name",
           info_over["sni"] != "evil.comaaaaaaaaaaaa")

alpn_none = guard(th.parse_client_hello,
                  build_hello(sni_ext_raw(b"a.example")))
check("no ALPN extension reads as [] (a real negative)",
      alpn_none["alpn"], [])
alpn_good = guard(th.parse_client_hello, build_hello(
    sni_ext_raw(b"a.example") + ext(0x0010, u16b(12) + b"\x02h2\x08http/1.1")))
check("a readable ALPN list comes back whole", alpn_good["alpn"],
      ["h2", "http/1.1"])
alpn_liar = guard(th.parse_client_hello, build_hello(
    sni_ext_raw(b"a.example") + ext(0x0010, u16b(9) + b"\x02h2")))
check("a present but UNREADABLE ALPN is None, not []",
      alpn_liar["alpn"], None)

# ═════════════════════════════════════════════════════════════════════════
print("\n[9] TP-12 — the ring was built with NO config; five keys unreachable")
# ═════════════════════════════════════════════════════════════════════════
# MEASURED before: adapters constructed PayloadRing(self.session_id), so the
# payload_capture block -- enabled, ring_bytes_per_flow, armed_bytes_per_flow,
# max_total_bytes, max_flows -- could not be supplied by ANY file in the tree.
# A control that reads as present and cannot be set.

_ring_cfg = pr.PayloadRing("s14-t9",
                           {"payload_capture": {"ring_bytes_per_flow": 2048,
                                                "max_flows": 7,
                                                "enabled": False}})
check("the block is honoured when it is supplied",
      (_ring_cfg.ring_bytes, _ring_cfg.max_flows, _ring_cfg.enabled),
      (2048, 7, False))

_ad_code = stripped(ROOT / "adapters.py")
check_true("and the ADAPTER supplies it (the wiring, in running code)",
           "PayloadRing(\n                self.session_id,\n"
           "                (self.config or {}).get(\"payload_capture\"))"
           in _ad_code)

# ═════════════════════════════════════════════════════════════════════════
print("\n[10] TP-8 / TP-9 — the card that said nothing, and the claim of three")
# ═════════════════════════════════════════════════════════════════════════
# TP-8 MEASURED before: permission_summary("arm_payload_capture", {...})
# returned exactly the string 'arm_payload_capture' -- the one approval in
# this app that puts the user's own plaintext on disk was the one whose card
# explained nothing.
# TP-9: "arming flushes on its own" lived in the module header, the arm note
# and status(); nothing implemented it, on either platform.

card = guard(tr.permission_summary, "arm_payload_capture",
             {"destination": "203.0.113.9", "reason": "suspected C2"})
check_true("the card is no longer the bare tool name",
           card != "arm_payload_capture" and "RAISED" not in card)
check_true("it names the ADDRESS the operator is deciding about",
           "203.0.113.9" in card)
check_true("it says nothing is written by arming alone",
           "nothing is written by arming" in card.lower())
check_true("and it repeats the operator's own reason",
           "suspected C2" in card)

_pr_code = stripped(ROOT / "tools" / "payload_ring.py")
check("the false claim is gone from the running code",
      "flushes on its own" in _pr_code, False)
check_true("the stripper saw the words in the prose (it is stripping)",
           "flushes on its own" in pathlib.Path(
               ROOT / "tools" / "payload_ring.py").read_text(
                   encoding="utf-8").split("FLUSHING IS THE DETECTOR'S JOB")[1]
           [:400])
check_true("status() says an armed flow still waits for a detection",
           (lambda r: (r._save_armed, r.arm("203.0.113.99"),
                       any("an armed flow still waits for a detection "
                           "to flush" in n for n in r.status()["notes"]))[-1])(
               pr.PayloadRing("s14-t10")))
check_true("the arm tool text tells the model NOT to say it records",
           "do not tell the user their traffic is being recorded" in
           next(d["description"] for d in tr.TOOL_MANIFEST
                if d["name"] == "arm_payload_capture"))

# ═════════════════════════════════════════════════════════════════════════
print("\n[11] TP-14/15/16 — three more false claims, corrected in place")
# ═════════════════════════════════════════════════════════════════════════
# Each was measured false the same round: there is no clear path (the only
# DELETE against payload_capture is the retention prune), the seven-day
# window is enforced by a prune that runs at BOOT and SHUTDOWN only, and
# rows reach the table ONE way (arming writes nothing).

_tr_code = stripped(ROOT / "core" / "tool_registry.py")
_mig_code = stripped(ROOT / "core" / "migrations.py")
# THE CHECK MUST NOT TRIP OVER THE CORRECTION ITSELF. The in-place rule
# quotes the old words beside the new ones, so a bare substring test for the
# old phrase passes on the CORRECTION -- the "absence check satisfied by the
# prose about the defect" trap, one step further in than a comment. What is
# asserted is the OPERATIVE SENTENCE, read as the source's own adjacent
# string literals are laid out (the strings are split across lines in the
# file, so a check must read the PIECE, not a spanning phrase).
_tr_raw = (ROOT / "core" / "tool_registry.py").read_text(encoding="utf-8")
check("the old disarm advice sentence is gone",
      "the payload retention window, or the user can clear them." in _tr_code,
      False)
check_true("the operative sentence now names the prune schedule",
           "\"the payload retention window, which is pruned at boot and at \""
           in _tr_raw)
check("the old payload-note advice sentence is gone",
      "seven days by default: it is the only table" in _tr_code, False)
check_true("the operative note now names boot and shutdown",
           "\"runs at BOOT and at SHUTDOWN: a run that is never restarted \""
           in _tr_raw)
check("'ROWS ARRIVE ONLY TWO WAYS' is gone from the running code",
      "ROWS ARRIVE ONLY TWO WAYS" in _mig_code, False)

_text_raw = (ROOT / "core" / "tool_registry.py").read_text(encoding="utf-8")
_mig_raw = (ROOT / "core" / "migrations.py").read_text(encoding="utf-8")
check_true("the disarm text carries the correction and the old words",
           "CORRECTED 2026-09-26" in _text_raw
           and "'... or the user can clear them'" in _text_raw)
check_true("the payload note carries its correction",
           "of the prune schedule only, not of any running process"
           in _text_raw)
check_true("the migration note carries its correction and says ONE way",
           "CORRECTED 2026-09-26" in _mig_raw
           and "ROWS ARRIVE ONE WAY" in _mig_raw)

# ═════════════════════════════════════════════════════════════════════════
print("\n[12] FOUND CLEAN, re-asserted so a regression shows")
# ═════════════════════════════════════════════════════════════════════════
# These were checked during the round and came back right. They are pinned
# so a later edit that breaks them is seen.

# The JA3 version field is the ClientHello's OWN legacy_version, NOT the
# highest supported_versions. THIS WAS SUSPECTED AND THEN SETTLED AGAINST
# THE REFERENCE IMPLEMENTATION (salesforce/ja3 + dpkt, salesforce's own
# `ja3 = [str(client_handshake.version)]`): the tree MATCHES the published
# format. Both compute the same field, so the fingerprint is comparable to
# public feeds. The check below pins the field, not the suspicion.
_ja3 = guard(th.parse_client_hello, build_hello(sni_ext_raw(b"j.example")))
check("JA3 field one is the hello's legacy version",
      _ja3["ja3"].split(",")[0], "771")
check_true("and the md5 is the md5 of that string",
           len(_ja3["ja3_md5"]) == 32)

# save_tls_hellos classifies new/repeats correctly, both directions.
_base = dict(sni="clean.example", sni_state="present", ja3="1,2,3,4,5",
             ja3_md5="b" * 32, alpn=["h2"], legacy_version="TLS 1.2",
             cipher_count=1, ext_count=1, process_name="p", process_pid=1,
             parse_reason="parsed", src_ip="198.51.100.7",
             dst_ip="203.0.113.7", dst_port=443)
r1 = guard(me.save_tls_hellos, [dict(_base)])
r2 = guard(me.save_tls_hellos, [dict(_base)])
check("first sighting is new", (r1["new"], r1["repeats"]), (1, 0))
check("the second is a repeat", (r2["new"], r2["repeats"]), (0, 1))

# The two fences that keep raw payload and device-authored names away from
# the model as instruction.
check_true("query_payload is fenced as untrusted",
           "query_payload" in sanitize.UNTRUSTED_TOOLS)
check_true("query_tls is fenced as untrusted",
           "query_tls" in sanitize.UNTRUSTED_TOOLS)
check_true("the arm tool carries a reason requirement in its schema",
           "reason" in tr.tool_schema("arm_payload_capture").get(
               "required", []))
check_true("arming remains permission-gated",
           "arm_payload_capture" in tr.PERMISSION_GATED)
check_true("disarming remains ungated (the direction that keeps less)",
           "disarm_payload_capture" not in tr.PERMISSION_GATED)

# The unicast/coverage style rule for this round: search returns None for
# matched when nothing was looked at -- checked on a flow the ring does NOT
# hold, the common case.
res_miss = guard(ring.search, b"x", "198.51.100.9", "198.51.100.10", 443, "TCP")
check("a flow that is not held gives searched=False", res_miss["searched"],
      False)
check("with matched None, never False", res_miss["matched"], None)

# ═════════════════════════════════════════════════════════════════════════
print("\n[13] TP-7 / TP-17 / TP-18 / TP-19, fixed")
# ═════════════════════════════════════════════════════════════════════════

# TP-7: the counters have a reader, the TLS route and card.
_c7 = guard(snif6.tls_run_counts)
check_true("TP-7 the adapter hands the five counts to a reader",
           isinstance(_c7, dict) and all(k in _c7 for k in (
               "read", "unreadable", "reassembled", "pending", "abandoned")))
_routes = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")
_ui = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check_true("the TLS route serves them", "tls_run_counts()" in _routes)
check_true("and the TLS card prints them", "d.this_run" in _ui)

# TP-17: hellos are queued and saved in one call.
snif17 = adapters.LinuxPacketSniffer("s14-t17")
_calls = []
_orig_save = me.save_tls_hellos
me.save_tls_hellos = lambda rows, **kw: (_calls.append(len(rows)),
                                         _orig_save(rows, **kw))[1]
try:
    snif17.TLS_BATCH_SECS = 999
    for i in range(3):
        snif17._handle_tls(hello_with_sni(f"batch{i}.example".encode()), {
            "src_ip": "198.51.100.7", "dst_ip": f"203.0.113.{170 + i}",
            "src_port": 46000 + i, "dst_port": 443,
            "process_name": "", "pid": None})
    check("TP-17 nothing is written per hello", _calls, [])
    check("the three wait in the batch", len(snif17._tls_batch), 3)
    snif17._flush_tls()
    check("and are saved in ONE call", _calls, [3])
    check("the run counter counts them", snif17.tls_run_counts()["read"], 3)
finally:
    me.save_tls_hellos = _orig_save

# TP-18: a second flush for the same detection writes only new frames, and
# seq runs on instead of restarting.
ring18 = pr.PayloadRing("s14-t18", {})
ring18._save_armed = lambda: None
ring18.arm("203.0.113.9")
ring18.append("198.51.100.7", "203.0.113.9", 443, "TCP", "outbound",
              b"frame-one", now=time.time(), src_port=42000)
guard(ring18.flush, "198.51.100.7", "203.0.113.9", 443, "TCP", "FED-1001",
      src_port=42000)
_again = guard(ring18.flush, "198.51.100.7", "203.0.113.9", 443, "TCP",
               "FED-1001", src_port=42000)
check("TP-18 a repeat flush with nothing new writes nothing",
      _again.get("rows") if isinstance(_again, dict) else _again, 0)
ring18.append("198.51.100.7", "203.0.113.9", 443, "TCP", "outbound",
              b"frame-two", now=time.time(), src_port=42000)
guard(ring18.flush, "198.51.100.7", "203.0.113.9", 443, "TCP", "FED-1001",
      src_port=42000)
with me._get_conn() as conn:
    _seqs = [r[0] for r in conn.execute(
        "SELECT seq FROM payload_capture "
        "WHERE trigger_detection_id = 'FED-1001' ORDER BY id")]
check("each frame is written once, seq running on", _seqs, [0, 1])
guard(ring18.flush, "198.51.100.7", "203.0.113.9", 443, "TCP", "FED-1002",
      src_port=42000)
with me._get_conn() as conn:
    _n2 = conn.execute("SELECT COUNT(*) FROM payload_capture "
                       "WHERE trigger_detection_id = 'FED-1002'").fetchone()[0]
check("a different detection still gets the whole flow", _n2, 2)

# TP-19: a retransmitted first segment no longer corrupts the reassembly,
# with and without a TCP sequence number.
_w19 = hello_sni_last(b"rx.example")
seg1_19, seg2_19 = _w19[:1460], _w19[1460:]
check_true("the fixture really puts the name past the first segment",
           len(_w19) > 1460
           and th.parse_client_hello(_w19)["sni"] == "rx.example")


def _rx_rows(snif, dst):
    snif._flush_tls()
    with me._get_conn() as conn:
        return [(r["sni"], r["sni_state"]) for r in conn.execute(
            "SELECT sni, sni_state FROM tls_hello WHERE dst_ip = ?", (dst,))]


for label, seqs, dst in (("no seq", (None, None, None), "198.51.100.42"),
                         ("with seq", (1000, 1000, 2460), "198.51.100.43")):
    snif19 = adapters.LinuxPacketSniffer("s14-t19")
    for seg, sq in ((seg1_19, seqs[0]), (seg1_19, seqs[1]),
                    (seg2_19, seqs[2])):
        _p = {"src_ip": "198.51.100.7", "dst_ip": dst, "src_port": 45000,
              "dst_port": 443, "process_name": "", "pid": None}
        if sq is not None:
            _p["tcp_seq"] = sq
        snif19._handle_tls(seg, _p)
    check(f"TP-19 ({label}) a retransmit then the real rest reads the name",
          _rx_rows(snif19, dst), [("rx.example", "present")])
    check(f"and nothing is left held ({label})", len(snif19._tls_pending), 0)

# A partial overlap is trimmed, and a gap is recorded, not guessed.
snif19b = adapters.LinuxPacketSniffer("s14-t19b")
_pb = {"src_ip": "198.51.100.7", "dst_ip": "198.51.100.44", "src_port": 45001,
       "dst_port": 443, "process_name": "", "pid": None}
snif19b._handle_tls(seg1_19, dict(_pb, tcp_seq=5000))
snif19b._handle_tls(_w19[1000:], dict(_pb, tcp_seq=6000))
check("an overlapping segment is trimmed and completes the hello",
      _rx_rows(snif19b, "198.51.100.44"), [("rx.example", "present")])
snif19c = adapters.LinuxPacketSniffer("s14-t19c")
_pc = dict(_pb, dst_ip="198.51.100.45", src_port=45002)
snif19c._handle_tls(seg1_19, dict(_pc, tcp_seq=7000))
snif19c._handle_tls(seg2_19[100:], dict(_pc, tcp_seq=7000 + 1560))
_gap = _rx_rows(snif19c, "198.51.100.45")
check("a missing segment is recorded unreadable, not stitched",
      [st for _n, st in _gap], ["unreadable"])

# ═════════════════════════════════════════════════════════════════════════
print()
print("=" * 72)
print(f"{len(fails)} failure(s)")
if fails:
    print(f"FAILURES: {fails}")
    sys.exit(1)
print("ALL CHECKS PASSED")
sys.exit(0)
