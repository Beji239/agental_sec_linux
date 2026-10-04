# tools/tls_hello.py
# AgentalSec V2, TODO 113.2. Read the first packet of a TLS handshake.

"""
WHAT THIS IS FOR

Every TLS connection starts with a ClientHello, and a ClientHello is sent in
the clear. It is the one place where an encrypted session tells you, without
any decryption at all, two things this app could never see before:

  SNI  the DOMAIN the client asked for. Until now the packet record held an
       IP and nothing else, so "what is my machine talking to" was answered
       with 11.22.36.63 and a shrug, and enrichment had to go and ask a
       registry who owns it. The client already told us. We were throwing the
       packet away.

  JA3  a fingerprint of HOW the client says hello: its TLS version, its
       cipher list, its extension list, its curves, its point formats, in the
       order the client chose them. Different software builds that list
       differently, so the same JA3 turning up under a different process
       name, or a brand new JA3 from a process that has always used one, is a
       real signal. This is the "C2 fingerprinting" that was written off as
       out of scope. It is a few hundred lines and no decryption.

PARSE, DO NOT STORE. This module takes bytes and returns small fields. It
never keeps the payload, it never writes anything, and it has no database and
no scapy import, which is also what makes it testable with a handful of
hand-built byte strings.

MOST MODERN HELLOS DO NOT FIT IN ONE PACKET, and this was measured rather
than assumed. On the owner's machine, 2026-09-19, the first ten minutes of
capture produced 124 hellos: ONE parsed and 123 were truncated. The reason is
post-quantum key exchange. A browser offering X25519MLKEM768 sends a key share
of over a kilobyte, so its ClientHello runs past a normal 1460 byte segment
and arrives in two packets. The one that parsed was a small updater using a
classic hello.

So a parser that only ever sees one packet reads the software nobody cares
about and misses every browser on the machine. The sniffer reassembles across
segments for exactly this reason, and this module stays per-buffer: it is
handed bytes and it says whether it needs more, through `truncated`.

RULE TWO, and it is the whole design here.

A ClientHello can be larger than one TCP segment, GREASE values are random by
design, and a middlebox can mangle what arrives. So "this connection has no
SNI" and "I could not read this ClientHello" are completely different facts
and they are never allowed to become the same field.

  sni_state = 'present'      a name was read, it is in `sni`
              'absent'       the hello parsed cleanly and carried NO server
                             name extension. A real negative. Happens for
                             plain IP connections and some internal services.
              'unreadable'   we could not finish parsing. NOT a negative.
                             `reason` says which way it failed.

Anything downstream that reports "no SNI seen" has to check sni_state, and
the test file drives every one of these states on purpose.

GREASE. RFC 8701. Chrome and others inject deliberately invalid values into
the cipher, extension and curve lists to keep middleboxes honest. Those values
are random per connection, so leaving them in gives a fingerprint that changes
every time and is worth nothing. They are stripped from the JA3 string, which
is what every other JA3 implementation does, so our hashes can be compared
with a public feed's.
"""

import hashlib
import logging

logger = logging.getLogger(__name__)

# Record and handshake type bytes.
RECORD_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01

# Extension numbers we care about. The rest are recorded by number only,
# because the LIST of extension numbers is itself half the fingerprint.
EXT_SERVER_NAME      = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A   # elliptic curves, in JA3 terms
EXT_EC_POINT_FORMATS = 0x000B
EXT_ALPN             = 0x0010

# TLS version bytes to a name, for the record column. The ClientHello's own
# version field has been frozen at 1.2 for years and the real version is
# negotiated in the supported_versions extension, so this is labelled
# `legacy_version` rather than `version` on purpose.
_VERSION_NAMES = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


def _is_grease(value: int) -> bool:
    """
    RFC 8701 GREASE values: 0x0a0a, 0x1a1a, 0x2a2a ... 0xfafa.

    Both bytes equal, and the low nibble of each is 'a'. One expression
    rather than a table of sixteen constants.
    """
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


class _Reader:
    """
    Bounds-checked walk over the bytes.

    Every read goes through here, and running off the end raises rather than
    returning short data, so a truncated hello becomes 'unreadable' in one
    place instead of becoming a half-parsed result that looks complete.
    """

    class Short(Exception):
        pass

    def __init__(self, data: bytes):
        self.d = data
        self.i = 0

    def need(self, n: int) -> bytes:
        if n < 0 or self.i + n > len(self.d):
            raise _Reader.Short(
                f"wanted {n} bytes at offset {self.i}, only "
                f"{len(self.d) - self.i} left")
        out = self.d[self.i:self.i + n]
        self.i += n
        return out

    def u8(self) -> int:
        return self.need(1)[0]

    def u16(self) -> int:
        b = self.need(2)
        return (b[0] << 8) | b[1]

    def u24(self) -> int:
        b = self.need(3)
        return (b[0] << 16) | (b[1] << 8) | b[2]

    @property
    def left(self) -> int:
        return len(self.d) - self.i


def looks_like_client_hello(payload: bytes) -> bool:
    """
    Cheap gate, run on every packet with a payload before anything else.

    Three bytes: a handshake record, a plausible TLS version. This is called
    on every single captured packet, so it does no allocation and no parsing.
    It is deliberately allowed to say yes to something that later fails to
    parse; that is what 'unreadable' is for.
    """
    if not payload or len(payload) < 6:
        return False
    if payload[0] != RECORD_HANDSHAKE:
        return False
    if payload[1] != 0x03:            # every TLS record version starts 0x03xx
        return False
    return payload[5] == HANDSHAKE_CLIENT_HELLO


def parse_client_hello(payload: bytes) -> dict:
    """
    Pull SNI, ALPN and the JA3 fingerprint out of a ClientHello.

    Always returns a dict. Never raises, never returns None, because a caller
    inside the packet loop that has to write a try/except around this is a
    caller that will one day swallow something else with it.

    Keys, always present:
      ok            bool, did we get a fingerprint out of it
      reason        why not, or 'parsed'
      sni_state     'present' | 'absent' | 'unreadable'   see the header
      sni           the server name, or None
      ja3           the JA3 string, or None
      ja3_md5       its md5, the form everyone else publishes, or None
      alpn          list of protocols the client offered, [] if none offered,
                    None if we could not read them
      legacy_version  the version byte in the hello itself, as a name
      cipher_count  how many real (non GREASE) ciphers were offered
      ext_count     how many real extensions were offered
      truncated_by  how many bytes short we were, when that is why we failed
    """
    out = {
        "ok": False,
        "reason": "",
        "sni_state": "unreadable",
        "sni": None,
        "ja3": None,
        "ja3_md5": None,
        "alpn": None,
        "legacy_version": None,
        "cipher_count": 0,
        "ext_count": 0,
        "truncated_by": None,
        # EXPLICIT, so no caller ever has to match on the wording of
        # `reason` to find out whether more bytes would help. Four times this
        # project has been bitten by something keyed off the exact shape of a
        # string. True means: the bytes so far are a valid beginning and the
        # rest is elsewhere. Retry with more.
        "truncated": False,
    }

    if not payload:
        out["reason"] = "no payload"
        return out

    r = _Reader(payload)
    try:
        if r.u8() != RECORD_HANDSHAKE:
            out["reason"] = "not a TLS handshake record"
            return out

        rec_version = r.u16()
        rec_len = r.u16()

        # THE TRUNCATION CHECK, and it is the reason this module exists in a
        # readable state. A ClientHello with a long extension block does not
        # fit in one segment, and the first segment parses happily right up to
        # the point where the extensions are cut off. Without this the answer
        # would be "no SNI" on exactly the connections whose SNI is most
        # interesting.
        if r.left < rec_len:
            out["reason"] = "truncated TLS record, the hello spans segments"
            out["truncated_by"] = rec_len - r.left
            out["truncated"] = True
            return out

        if r.u8() != HANDSHAKE_CLIENT_HELLO:
            out["reason"] = "handshake, but not a ClientHello"
            return out

        hs_len = r.u24()
        if r.left < hs_len:
            out["reason"] = "truncated ClientHello body"
            out["truncated_by"] = hs_len - r.left
            out["truncated"] = True
            return out

        legacy_version = r.u16()
        out["legacy_version"] = _VERSION_NAMES.get(
            legacy_version, f"0x{legacy_version:04x}")

        r.need(32)                                  # client random
        r.need(r.u8())                              # legacy session id

        ciphers = []
        cipher_bytes = r.u16()
        if cipher_bytes % 2:
            out["reason"] = "odd cipher list length"
            return out
        for _ in range(cipher_bytes // 2):
            c = r.u16()
            if not _is_grease(c):
                ciphers.append(c)

        r.need(r.u8())                              # compression methods

        # Extensions are optional in the format. An SSLv3-era hello with none
        # is a real thing, it is not a parse failure, and it still produces a
        # valid JA3 with three empty fields.
        exts, groups, points = [], [], []
        sni = None
        sni_seen = False
        alpn = []
        alpn_seen = False

        if r.left >= 2:
            ext_total = r.u16()
            if r.left < ext_total:
                out["reason"] = "truncated extension block"
                out["truncated_by"] = ext_total - r.left
                out["truncated"] = True
                return out

            end = r.i + ext_total
            while r.i + 4 <= end:
                etype = r.u16()
                elen = r.u16()
                body = r.need(elen)

                if not _is_grease(etype):
                    exts.append(etype)

                if etype == EXT_SERVER_NAME:
                    sni_seen = True
                    sni = _read_sni(body)
                elif etype == EXT_SUPPORTED_GROUPS:
                    groups = _read_u16_list(body, skip_grease=True)
                elif etype == EXT_EC_POINT_FORMATS:
                    points = list(body[1:1 + body[0]]) if body else []
                elif etype == EXT_ALPN:
                    alpn_seen = True
                    alpn = _read_alpn(body)

    except _Reader.Short as e:
        out["reason"] = f"truncated: {e}"
        out["truncated"] = True
        return out
    except Exception as e:                          # malformed, not truncated
        logger.debug(f"ClientHello parse error: {e}")
        out["reason"] = f"malformed ClientHello: {e}"
        return out

    # JA3, the published field order. Versions and lists are decimal, joined
    # with '-', the five fields joined with ','. An empty list is an empty
    # field, which is why the separators are still there.
    ja3 = ",".join([
        str(legacy_version),
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in exts),
        "-".join(str(g) for g in groups),
        "-".join(str(p) for p in points),
    ])

    out["ok"] = True
    out["reason"] = "parsed"
    out["ja3"] = ja3
    out["ja3_md5"] = hashlib.md5(ja3.encode()).hexdigest()
    out["cipher_count"] = len(ciphers)
    out["ext_count"] = len(exts)
    # THREE ANSWERS. alpn_seen False -> [] (no ALPN extension, a real
    # negative). alpn_seen True with a list -> the protocols. alpn_seen True
    # with None -> the extension was there and could not be read, which
    # _read_alpn now returns instead of collapsing into "none offered".
    out["alpn"] = alpn if alpn_seen else []

    # The three-state answer. sni_seen with no name means the extension was
    # there and we could not read a name out of it, which is its own kind of
    # odd and is NOT the same as the client not sending one.
    if sni:
        out["sni_state"] = "present"
        out["sni"] = sni
    elif sni_seen:
        out["sni_state"] = "unreadable"
        out["reason"] = "server_name extension present but no readable name"
    else:
        out["sni_state"] = "absent"

    return out


def _read_sni(body: bytes) -> str | None:
    """
    The server_name extension. A list, in the spec, that in practice always
    holds exactly one host_name entry.

    Returns None rather than raising, because a server_name we cannot read is
    reported through sni_state rather than through an exception.

    THE NAME IS KEPT AS THE WIRE CARRIES IT, IN ASCII. THIS IS THE FIX FOR
    THE WORST DEFECT OF THE 2026-09-26 ROUND. This used to decode an all-ASCII
    name with `name.decode("idna")`, which turns a PUNYCODE name into a
    unicode one: the wire bytes `xn--80ak6aa92e.com` were stored as
    `аррӏе.com` (Cyrillic а, р, ӏ). MEASURED, on this host, 2026-09-26:

      * the SNI column held unicode while every other name column in this
        store (dns_queries.domain, threat_feed.indicator) holds A-labels,
        which is what the DNS carries and what every public feed publishes;
      * feed matching looks the STORED string up, so a feed row for
        `xn--80ak6aa92e.com` did not match the connection that used it --
        measured both directions through the shipped `_feed_hit_domain`;
      * and the decoded labels are visually identical to Latin ones, so a
        reader (or a model) comparing `аррӏе.com` with `apple.com` cannot tell
        them apart while the lookup silently fails.

    That is an attacker-controlled name defeated the app's strongest evidence
    path -- a live known-bad feed hit on an executed handshake -- by making
    the row un-matchable, and turning the whole thing into a homograph. Two
    changes, matching this module's own rule two:

      * an all-ASCII name is kept as ASCII, lowercased, one trailing dot
        removed. No IDNA decode. `xn--` names stay `xn--` names;
      * a name that is NOT all ASCII is REFUSED rather than decoded, because
        a raw non-ASCII SNI is not a valid DNS name (RFC 6066 requires the
        host_name to be an ASCII label sequence), and this app has no
        business inventing a Unicode name out of bytes a device chose.

    The 253-byte cap and the control-character refusal below are unchanged.
    """
    try:
        r = _Reader(body)
        list_len = r.u16()
        end = min(r.i + list_len, len(body))
        while r.i + 3 <= end:
            name_type = r.u8()
            name_len = r.u16()
            # A name whose declared length overruns the extension is refused
            # rather than served in part: a partial hostname is a different
            # name, and matching a feed against a truncated one would be a
            # false negative reported as a miss. short=False keeps the reason
            # inside _read_sni (see the docstring above) rather than letting
            # it escape as truncation.
            if r.i + name_len > end:
                return None
            name = r.need(name_len)
            if name_type == 0:                       # host_name
                if not _is_ascii(name):
                    # Not decoded, refused. See the docstring.
                    return None
                try:
                    text = name.decode("ascii", errors="strict")
                except Exception:
                    return None
                text = text.strip().rstrip(".").lower()
                # A hostname with a space or a control character in it is not
                # a hostname. Device-authored text reaches the database from
                # here, so it is checked rather than trusted.
                if not text or any(ord(c) < 33 for c in text):
                    return None
                return text[:253]
    except Exception:
        return None
    return None


def _is_ascii(b: bytes) -> bool:
    return all(c < 128 for c in b)


def _read_u16_list(body: bytes, skip_grease: bool = False) -> list[int]:
    """A two byte length followed by that many bytes of 16 bit values."""
    out = []
    try:
        r = _Reader(body)
        n = r.u16()
        for _ in range(min(n // 2, r.left // 2)):
            v = r.u16()
            if skip_grease and _is_grease(v):
                continue
            out.append(v)
    except Exception:
        pass
    return out


def _read_alpn(body: bytes) -> list[str] | None:
    """
    ALPN: a list of length-prefixed protocol names, h2, http/1.1, and so on.

    THREE ANSWERS, NOT TWO, and the middle one was unreachable until
    2026-09-26. parse_client_hello's docstring has always said "[] if none
    offered, None if we could not read them" -- and this function returned []
    on every failure, so a PRESENT ALPN extension whose inside lengths did not
    add up (MEASURED: a body whose list length claims 9 bytes and carries 3)
    was reported as "the client offered no protocols", which is a statement
    about the client made out of a parse failure. One function over from the
    sni_state rule, same shape.

      []    parsed cleanly, no protocols offered      a real negative
      None  present and NOT readable                  could not look
    """
    out = []
    try:
        r = _Reader(body)
        declared = r.u16()                           # list length
        end = r.i + declared
        if end > len(body):
            # The list length overruns the extension it lives in. Not "none
            # offered": unreadable.
            return None
        while r.i < end:
            n = r.u8()
            if n == 0 or r.i + n > end:
                return None
            out.append(r.need(n).decode("ascii", errors="replace")[:16])
    except Exception:
        return None
    return out
