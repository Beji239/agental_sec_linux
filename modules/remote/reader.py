# modules/remote/reader.py
# Private messages: the text is sealed here with a key only this computer and
# the person's phone hold, and travels inside the Read button's link. The
# reader page opens it on the phone; Telegram carries only scrambled text.

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import urllib.parse
import urllib.request
import zlib
from pathlib import Path

VERSION = 1
AAD = b"agentalsec-reader-1"
QR_PREFIX = "agentalsec-key:1:"
CHECK_LABEL = b"agentalsec-reader-check"
FLAG_DEFLATE = 1
# Longer links are cut before sealing; Telegram does not publish a limit.
URL_MAX = 4000
DEFAULT_URL = "https://beji239.github.io/agental_sec_linux/modules/remote/reader/"
PAGE_FILES = ("index.html", "reader.js", "reader.css")
PAGE_DIR = Path(__file__).resolve().parent / "reader"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def new_key() -> bytes:
    return secrets.token_bytes(32)


def key_id(key: bytes) -> bytes:
    return hashlib.sha256(key).digest()[:4]


def check_code(key: bytes) -> str:
    """Six characters the phone shows once it saved the key, typed back at
    the computer to prove it is the same key."""
    mac = hmac.new(key, CHECK_LABEL, hashlib.sha256).digest()
    return base64.b32encode(mac).decode("ascii")[:6]


def qr_text(key: bytes) -> str:
    return QR_PREFIX + _b64(key)


def seal(key: bytes, title: str, body: str, kind: str = "", now: float = None) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    plain = json.dumps({"v": VERSION, "k": kind, "t": title, "b": body,
                        "at": int(now or time.time())},
                       ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    packed = zlib.compress(plain, 9, wbits=-15)
    flags = 0
    if len(packed) < len(plain):
        plain, flags = packed, FLAG_DEFLATE
    nonce = os.urandom(12)
    head = bytes([VERSION, flags]) + key_id(key)
    sealed = AESGCM(key).encrypt(nonce, plain, AAD + head)
    return _b64(head + nonce + sealed)


def open_sealed(key: bytes, blob: str) -> dict:
    """The page's job, here for the tests."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw = _unb64(blob)
    head, nonce, sealed = raw[:6], raw[6:18], raw[18:]
    plain = AESGCM(key).decrypt(nonce, sealed, AAD + head)
    if head[1] & FLAG_DEFLATE:
        plain = zlib.decompress(plain, wbits=-15)
    return json.loads(plain)


def link(base: str, blob: str) -> str:
    return base + ("&" if "?" in base else "?") + "m=" + blob


def enrol_link(base: str) -> str:
    return base + ("&" if "?" in base else "?") + "enrol=1"


def url_problem(url: str) -> str | None:
    try:
        parts = urllib.parse.urlsplit(url or "")
    except ValueError:
        return "That is not a web address."
    if parts.scheme != "https" or not parts.hostname:
        return "The reader page needs an https:// address."
    if parts.fragment or len(url) > 300:
        return "Give the page's address without a # part, under 300 characters."
    if not re.fullmatch(r"[A-Za-z0-9._~:/?=&%-]+", url):
        return "The address has characters that do not belong in it."
    return None


def page_hashes() -> dict:
    out = {}
    for name in PAGE_FILES:
        try:
            out[name] = hashlib.sha256((PAGE_DIR / name).read_bytes()).hexdigest()
        except OSError:
            out[name] = None
    return out


def check_hosted(base: str, timeout: float = 15) -> dict:
    """Fetches the hosted page and compares it byte for byte with the copy
    that came with the module, so a changed page is noticed."""
    base = base if base.endswith("/") else base.rsplit("/", 1)[0] + "/"
    local = page_hashes()
    files = {}
    for name in PAGE_FILES:
        url = base + name
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AgentalSec-Remote"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                got = hashlib.sha256(resp.read(2_000_000)).hexdigest()
            files[name] = "same" if got == local.get(name) else "different"
        except Exception as e:                          # noqa: BLE001
            files[name] = f"could not read: {type(e).__name__}"
    return {"ok": all(v == "same" for v in files.values()), "files": files}
