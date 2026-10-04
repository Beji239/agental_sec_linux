"""
tests/test_tls_hello.py, TODO 113.2. Reading the one packet of a TLS
handshake that is not encrypted.

WHY THE FAILURE CASES COME FIRST HERE, sections [1] to [4].

The happy path for this parser is easy and it is not where the damage lives.
A ClientHello with a long extension block does not fit in one TCP segment.
The first segment parses perfectly right up to the point where the extensions
are cut off, and a parser written happy-path-first answers "no SNI" for it,
confidently, on exactly the connections whose SNI is most worth having.

That is rule two, 2026-09-13, in a byte parser: "no server name was sent" and
"I could not finish reading this" are different sentences and the code is
never allowed to merge them. So sni_state has three values, not two, and the
first four sections of this file drive the ways it must come back
'unreadable'.

Everything here is built from hand-assembled bytes. No network, no scapy, no
database, no fixtures on disk.
"""
import sys, pathlib, hashlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []
def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)

from tools import tls_hello as th


# A ClientHello builder, so every test drives real bytes

def u16(n):  return bytes([(n >> 8) & 0xFF, n & 0xFF])
def u24(n):  return bytes([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])

def ext(etype, body):
    return u16(etype) + u16(len(body)) + body

def sni_ext(host):
    name = host.encode()
    entry = b"\x00" + u16(len(name)) + name          # host_name
    return ext(0x0000, u16(len(entry)) + entry)

def alpn_ext(protos):
    body = b"".join(bytes([len(p)]) + p.encode() for p in protos)
    return ext(0x0010, u16(len(body)) + body)

def groups_ext(groups):
    body = b"".join(u16(g) for g in groups)
    return ext(0x000A, u16(len(body)) + body)

def points_ext(points):
    return ext(0x000B, bytes([len(points)]) + bytes(points))

def build_hello(ciphers=(0xC02B, 0xC02F), extensions=b"", version=0x0303,
                session_id=b"", with_ext_block=True):
    body = (u16(version)
            + b"\x11" * 32
            + bytes([len(session_id)]) + session_id
            + u16(len(ciphers) * 2) + b"".join(u16(c) for c in ciphers)
            + b"\x01\x00")                            # one compression method
    if with_ext_block:
        body += u16(len(extensions)) + extensions
    handshake = bytes([0x01]) + u24(len(body)) + body
    return bytes([0x16]) + u16(0x0301) + u16(len(handshake)) + handshake

STD_EXTS = (sni_ext("example.com")
            + groups_ext([0x001D, 0x0017])
            + points_ext([0])
            + alpn_ext(["h2", "http/1.1"]))


print("\n[1] FAILURE CASE: the hello is cut off mid record")
# The real shape: a segment carrying the first 40 bytes of a 300 byte hello.
full = build_hello(extensions=STD_EXTS)
cut = full[:40]
r = th.parse_client_hello(cut)
check("it does not claim success", r["ok"], False)
check("and it does NOT say the SNI is absent", r["sni_state"], "unreadable")
check("it says why", "truncated" in r["reason"], True)
check("and how short it was", isinstance(r["truncated_by"], int) and r["truncated_by"] > 0, True)
print(f"       reason: {r['reason']}")

# The same bytes complete parse fine, which is what makes the check above
# meaningful rather than a parser that fails on everything.
check("the SAME hello parses when it is all there",
      th.parse_client_hello(full)["sni"], "example.com")


print("\n[2] FAILURE CASE: the extension block itself is short")
# Record and handshake lengths lie about a longer extension block than is
# present. A parser that trusts the outer length and then walks the inner one
# reads whatever is next in memory, or reports 'absent'.
bad = bytearray(build_hello(extensions=STD_EXTS))
# claim 200 more bytes of extensions than exist
ext_off = 5 + 4 + 2 + 32 + 1 + 2 + 4 + 2
bad[ext_off:ext_off + 2] = u16(len(STD_EXTS) + 200)
r = th.parse_client_hello(bytes(bad))
check("caught, not answered", r["ok"], False)
check("and not reported as absent", r["sni_state"], "unreadable")
check("truncation is named", "truncated" in r["reason"], True)


print("\n[3] FAILURE CASE: not a ClientHello at all")
r = th.parse_client_hello(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
check("plain HTTP is refused", r["ok"], False)
check("with the right reason", "not a TLS handshake record" in r["reason"], True)
check("and no invented SNI", r["sni"], None)

server_hello = bytearray(build_hello(extensions=STD_EXTS))
server_hello[5] = 0x02                                # ServerHello
r = th.parse_client_hello(bytes(server_hello))
check("a ServerHello is refused", r["ok"], False)
check("named as such", "not a ClientHello" in r["reason"], True)

check("empty bytes are refused", th.parse_client_hello(b"")["ok"], False)
check("and one byte too", th.parse_client_hello(b"\x16")["ok"], False)


print("\n[4] FAILURE CASE: the extension is there and the name is not readable")
# A server_name extension carrying a name with a control character in it.
# Device-authored text, so it is checked rather than trusted, and the answer
# is 'unreadable' rather than 'absent': the client DID send something.
junk = b"\x00" + u16(5) + b"ab\x01cd"
bad_sni = ext(0x0000, u16(len(junk)) + junk)
r = th.parse_client_hello(build_hello(extensions=bad_sni + groups_ext([0x001D])))
check("the hello still parses", r["ok"], True)
check("the name is not invented", r["sni"], None)
check("and absent is not claimed", r["sni_state"], "unreadable")
check("we still get a fingerprint out of it", bool(r["ja3_md5"]), True)


print("\n[5] a REAL absent SNI, which is a real negative")
# An IP-only TLS connection sends no server_name. This must be 'absent', a
# fact, and not lumped in with the failures above.
r = th.parse_client_hello(build_hello(extensions=groups_ext([0x001D]) + points_ext([0])))
check("parsed", r["ok"], True)
check("absent means absent", r["sni_state"], "absent")
check("no name", r["sni"], None)
check("alpn offered nothing, which is [] not None", r["alpn"], [])
check("and the fingerprint is still there", len(r["ja3_md5"]), 32)

# No extension block at all, the old-style hello. Still not a failure.
r = th.parse_client_hello(build_hello(with_ext_block=False))
check("a hello with no extension block parses", r["ok"], True)
check("and reports absent", r["sni_state"], "absent")
check("its ja3 has the empty fields, separators and all",
      r["ja3"].count(","), 4)


print("\n[6] the happy path, and the fields it is supposed to hand over")
r = th.parse_client_hello(build_hello(extensions=STD_EXTS))
check("sni", r["sni"], "example.com")
check("sni_state", r["sni_state"], "present")
check("alpn", r["alpn"], ["h2", "http/1.1"])
check("legacy version is labelled as legacy", r["legacy_version"], "TLS 1.2")
check("cipher count", r["cipher_count"], 2)
# JA3 by construction: version,ciphers,extensions,curves,points
want = "771,49195-49199,0-10-11-16,29-23,0"
check("the ja3 string is the published field order", r["ja3"], want)
check("and the md5 is the md5 of that string",
      r["ja3_md5"], hashlib.md5(want.encode()).hexdigest())
print(f"       ja3: {r['ja3']}")
print(f"       md5: {r['ja3_md5']}")


print("\n[7] GREASE is stripped, or the fingerprint is worthless")
# RFC 8701. Chrome injects random-but-invalid values on every connection. Two
# hellos from the SAME client differ only in those values. If they survive
# into the JA3 then every connection has a new fingerprint and the whole
# feature is noise.
a = build_hello(ciphers=(0x0A0A, 0xC02B, 0xC02F),
                extensions=ext(0x1A1A, b"") + STD_EXTS)
b = build_hello(ciphers=(0x3A3A, 0xC02B, 0xC02F),
                extensions=ext(0x7A7A, b"") + STD_EXTS)
ra, rb = th.parse_client_hello(a), th.parse_client_hello(b)
check("both parse", (ra["ok"], rb["ok"]), (True, True))
check("same client, same fingerprint", ra["ja3_md5"], rb["ja3_md5"])
check("and it matches the GREASE-free hello",
      ra["ja3_md5"], th.parse_client_hello(build_hello(extensions=STD_EXTS))["ja3_md5"])
check("grease ciphers are not counted", ra["cipher_count"], 2)
check("the grease detector knows the whole family",
      [th._is_grease(v) for v in (0x0A0A, 0x1A1A, 0xFAFA, 0x2A2A)],
      [True, True, True, True])
check("and does not eat real values",
      [th._is_grease(v) for v in (0xC02B, 0x0000, 0x000A, 0x0A0B, 0x1A0A)],
      [False, False, False, False, False])


print("\n[8] a different client gives a different fingerprint")
other = build_hello(ciphers=(0x1301, 0x1302),
                    extensions=sni_ext("example.com") + groups_ext([0x0017]))
check("different cipher and extension lists, different hash",
      th.parse_client_hello(other)["ja3_md5"] !=
      th.parse_client_hello(build_hello(extensions=STD_EXTS))["ja3_md5"], True)
check("but the same bytes twice are stable",
      th.parse_client_hello(other)["ja3_md5"],
      th.parse_client_hello(other)["ja3_md5"])


print("\n[9] the cheap gate that runs on every packet")
check("says yes to a hello", th.looks_like_client_hello(full), True)
check("no to HTTP", th.looks_like_client_hello(b"GET / HTTP/1.1\r\n"), False)
check("no to a ServerHello", th.looks_like_client_hello(bytes(server_hello)), False)
check("no to empty", th.looks_like_client_hello(b""), False)
check("no to a short fragment", th.looks_like_client_hello(b"\x16\x03\x01"), False)
# It is ALLOWED to say yes to something that later fails to parse. That is
# what 'unreadable' is for, and a gate that tried to be sure would have to
# parse, which is the work it exists to avoid.
check("yes to a truncated hello, which the parser then rejects properly",
      th.looks_like_client_hello(cut), True)


print("\n[10] the hostname is treated as device-authored text")
check("case is folded",
      th.parse_client_hello(build_hello(extensions=sni_ext("EXAMPLE.COM")))["sni"],
      "example.com")
check("a trailing root dot is dropped",
      th.parse_client_hello(build_hello(extensions=sni_ext("example.com.")))["sni"],
      "example.com")
long_name = ("a" * 300) + ".com"
got = th.parse_client_hello(build_hello(extensions=sni_ext(long_name)))["sni"]
check("an over-long name is capped, not stored whole", len(got) <= 253, True)
check("a name that is only a dot is not a name",
      th.parse_client_hello(build_hello(extensions=sni_ext(".")))["sni"], None)


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
