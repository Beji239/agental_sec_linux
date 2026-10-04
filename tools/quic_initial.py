# tools/quic_initial.py
# The TLS ClientHello inside a QUIC client Initial packet.
#
# QUIC (HTTP/3, UDP 443) encrypts even its first packet, so the TCP-only
# hello reader never saw the server name of any browser connection that used
# it. The Initial keys are not secret, though: RFC 9001 section 5.2 derives
# them from the destination connection ID the client puts in the clear, so
# any observer can decrypt a client Initial and read its CRYPTO frames.
#
# Pure module like tools/tls_hello.py: bytes in, dicts out, no capture and no
# database. Supports QUIC v1 (RFC 9000/9001) and v2 (RFC 9369).

import hashlib
import hmac
import logging
import struct

logger = logging.getLogger(__name__)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:                                           # pragma: no cover
    CRYPTO_AVAILABLE = False

QUIC_V1 = 0x00000001
QUIC_V2 = 0x6B3343CF

# version -> (initial salt, label prefix, long-header type bits of Initial)
_VERSIONS = {
    QUIC_V1: (bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
              "quic", 0),
    QUIC_V2: (bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
              "quicv2", 1),
}

# A ClientHello bigger than this is not one; bounds what a flow can make us
# hold. Post-quantum key shares push real ones past one packet, not past this.
MAX_HELLO_BYTES = 16384

_FRAME_PADDING = 0x00
_FRAME_PING = 0x01
_FRAME_ACK = (0x02, 0x03)
_FRAME_CRYPTO = 0x06
_FRAME_CLOSE = (0x1C, 0x1D)


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand_label(secret: bytes, label: str, length: int) -> bytes:
    """TLS 1.3 HKDF-Expand-Label with an empty context (RFC 8446 7.1)."""
    full = b"tls13 " + label.encode("ascii")
    info = struct.pack("!HB", length, len(full)) + full + b"\x00"
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def client_initial_keys(dcid: bytes, version: int = QUIC_V1) -> tuple:
    """(key, iv, hp) protecting a client's Initial packets for this DCID."""
    salt, prefix, _ = _VERSIONS[version]
    client = _hkdf_expand_label(_hkdf_extract(salt, dcid), "client in", 32)
    return (_hkdf_expand_label(client, f"{prefix} key", 16),
            _hkdf_expand_label(client, f"{prefix} iv", 12),
            _hkdf_expand_label(client, f"{prefix} hp", 16))


def header_protection_mask(hp: bytes, sample: bytes) -> bytes:
    """AES-ECB of the 16-byte sample under the hp key (RFC 9001 5.4.3)."""
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    return enc.update(sample) + enc.finalize()


def _varint(buf: bytes, i: int) -> tuple:
    """(value, next index) of a QUIC variable-length integer."""
    first = buf[i]
    n = 1 << (first >> 6)
    if i + n > len(buf):
        raise ValueError("truncated varint")
    value = first & 0x3F
    for b in buf[i + 1:i + n]:
        value = (value << 8) | b
    return value, i + n


def looks_like_initial(datagram: bytes) -> bool:
    """Cheap gate: a long-header packet of a version this module decrypts."""
    if not datagram or len(datagram) < 7 or (datagram[0] & 0xC0) != 0xC0:
        return False
    version = int.from_bytes(datagram[1:5], "big")
    spec = _VERSIONS.get(version)
    return spec is not None and ((datagram[0] >> 4) & 0x03) == spec[2]


def decrypt_client_initial(datagram: bytes) -> dict:
    """
    Decrypt the first QUIC packet in a UDP datagram, if it is a client Initial.

    Always returns a dict with `ok` and `reason`. On success it also carries
    `version`, `dcid` (hex) and `crypto`, a list of (offset, bytes) CRYPTO
    frame pieces, which a ClientHello can be split across, in any order.
    """
    out = {"ok": False, "reason": "", "version": None, "dcid": None,
           "crypto": []}
    if not CRYPTO_AVAILABLE:
        out["reason"] = "the cryptography package is not installed"
        return out
    if not looks_like_initial(datagram):
        out["reason"] = "not a QUIC Initial packet of a known version"
        return out
    try:
        version = int.from_bytes(datagram[1:5], "big")
        i = 5
        dcid_len = datagram[i]
        dcid = datagram[i + 1:i + 1 + dcid_len]
        i += 1 + dcid_len
        if dcid_len > 20 or len(dcid) != dcid_len:
            raise ValueError("bad destination connection ID")
        scid_len = datagram[i]
        i += 1 + scid_len
        token_len, i = _varint(datagram, i)
        i += token_len
        length, pn_offset = _varint(datagram, i)
        end = pn_offset + length
        if end > len(datagram) or length < 20:
            raise ValueError("packet length runs past the datagram")

        key, iv, hp = client_initial_keys(dcid, version)
        mask = header_protection_mask(hp, datagram[pn_offset + 4:pn_offset + 20])
        first = datagram[0] ^ (mask[0] & 0x0F)
        pn_len = (first & 0x03) + 1
        pn_bytes = bytes(b ^ m for b, m in
                         zip(datagram[pn_offset:pn_offset + pn_len], mask[1:]))
        header = bytes([first]) + datagram[1:pn_offset] + pn_bytes
        pn = int.from_bytes(pn_bytes, "big")
        nonce = (int.from_bytes(iv, "big") ^ pn).to_bytes(12, "big")
        plain = AESGCM(key).decrypt(nonce, datagram[pn_offset + pn_len:end],
                                    header)
    except Exception as e:                                    # noqa: BLE001
        # A server Initial, a corrupted frame and a non-QUIC datagram all end
        # here; the AEAD tag is what tells them apart from a real one.
        out["reason"] = f"could not decrypt: {type(e).__name__}: {e}"
        return out

    out.update(version=version, dcid=dcid.hex())
    try:
        out["crypto"] = _crypto_frames(plain)
    except ValueError as e:
        out["reason"] = f"decrypted, but the frames did not parse: {e}"
        return out
    out["ok"] = True
    out["reason"] = "decrypted"
    return out


def _crypto_frames(plain: bytes) -> list:
    """The CRYPTO frame pieces in a decrypted Initial payload."""
    pieces, i = [], 0
    while i < len(plain):
        ftype = plain[i]
        if ftype == _FRAME_PADDING or ftype == _FRAME_PING:
            i += 1
        elif ftype == _FRAME_CRYPTO:
            offset, i = _varint(plain, i + 1)
            size, i = _varint(plain, i)
            if i + size > len(plain):
                raise ValueError("CRYPTO frame runs past the packet")
            pieces.append((offset, plain[i:i + size]))
            i += size
        elif ftype in _FRAME_ACK:
            i += 1
            for _ in range(2):                  # largest, delay
                _, i = _varint(plain, i)
            ranges, i = _varint(plain, i)
            _, i = _varint(plain, i)            # first range
            for _ in range(2 * ranges):
                _, i = _varint(plain, i)
            if ftype == 0x03:
                for _ in range(3):              # ECN counts
                    _, i = _varint(plain, i)
        elif ftype in _FRAME_CLOSE:
            break
        else:
            # Anything else is not allowed in an Initial; stop reading rather
            # than guess at its length.
            break
    return pieces


class CryptoAssembler:
    """
    Puts a ClientHello back together from CRYPTO pieces, which browsers split
    across packets and send out of order on purpose. Bounded by
    MAX_HELLO_BYTES.
    """

    def __init__(self):
        self._pieces = {}
        self.bytes_held = 0

    def add(self, pieces: list) -> None:
        for offset, data in pieces:
            if offset + len(data) > MAX_HELLO_BYTES:
                raise ValueError(f"CRYPTO data past {MAX_HELLO_BYTES} bytes")
            if offset not in self._pieces or len(data) > len(self._pieces[offset]):
                self.bytes_held += len(data) - len(self._pieces.get(offset, b""))
                self._pieces[offset] = data

    def contiguous(self) -> bytes:
        """The bytes from offset 0 with no gap."""
        buf = b""
        for offset in sorted(self._pieces):
            data = self._pieces[offset]
            if offset > len(buf):
                break
            buf += data[len(buf) - offset:]
        return buf

    def hello_record(self) -> bytes | None:
        """The complete ClientHello as a TLS record, or None while incomplete."""
        return client_hello_record(self.contiguous())


def client_hello_record(stream: bytes) -> bytes | None:
    """
    Wrap a complete handshake ClientHello in a TLS record header, so
    tools/tls_hello.parse_client_hello reads it exactly as it reads TCP.
    None when the stream does not yet hold the whole message.
    """
    if len(stream) < 4 or stream[0] != 0x01:
        return None
    total = 4 + int.from_bytes(stream[1:4], "big")
    if total > MAX_HELLO_BYTES or len(stream) < total:
        return None
    return b"\x16\x03\x01" + struct.pack("!H", total) + stream[:total]
