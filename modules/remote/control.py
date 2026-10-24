# modules/remote/control.py
# What control from the phone checks: the PIN, the authenticator code and
# the panic word. PINs and panic words are kept only as scrypt hashes, the
# authenticator secrets encrypted with a key bound to this machine.

import base64
import getpass
import hashlib
import hmac
import os
import re
import secrets
import struct
import time
import urllib.parse

STEP = 30
DIGITS = 6
ISSUER = "AgentalSec"
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}


def _scrypt(text: str, salt: bytes) -> bytes:
    return hashlib.scrypt(text.encode("utf-8"), salt=salt, dklen=32, **_SCRYPT)


def _hash(text: str) -> str:
    salt = secrets.token_bytes(16)
    return f"scrypt${salt.hex()}${_scrypt(text, salt).hex()}"


def _matches(text: str, stored: str) -> bool:
    try:
        kind, salt, want = (stored or "").split("$")
    except ValueError:
        return False
    if kind != "scrypt":
        return False
    return hmac.compare_digest(_scrypt(text, bytes.fromhex(salt)).hex(), want)


def pin_problem(pin: str) -> str | None:
    """Why a PIN is refused, or None when it is fine."""
    if not re.fullmatch(r"\d{6,12}", pin or ""):
        return "The PIN is 6 to 12 digits."
    if len(set(pin)) == 1 or pin in "01234567890123" or pin in "98765432109876":
        return "That PIN is too easy to guess."
    return None


def hash_pin(pin: str) -> str:
    return _hash(pin)


def pin_ok(pin: str, stored: str) -> bool:
    return _matches((pin or "").strip(), stored)


def clean_word(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def word_problem(word: str, pin: str = "") -> str | None:
    w = clean_word(word)
    if not 4 <= len(w) <= 40:
        return "The panic word is 4 to 40 characters."
    if w.isdigit() or w.startswith("/"):
        return "The panic word needs letters, so it is never taken for a PIN or a command."
    if pin and w == pin:
        return "The panic word must not be the PIN."
    return None


def hash_word(word: str) -> str:
    return _hash(clean_word(word))


def word_ok(text: str, stored: str) -> bool:
    w = clean_word(text)
    return 4 <= len(w) <= 40 and _matches(w, stored)


# Authenticator codes (RFC 6238, the kind Aegis and Google Authenticator make)

def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def totp(secret: str, step: int) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    num = struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF
    return str(num % 10 ** DIGITS).zfill(DIGITS)


def code_step(secret: str, code: str, last_step: int = 0, now: float = None) -> int | None:
    """The time step a code belongs to, allowing one step of clock drift
    either way. A step at or before last_step is refused: each code works
    once."""
    code = re.sub(r"\s", "", code or "")
    if not re.fullmatch(r"\d{6}", code):
        return None
    cur = int((now or time.time()) // STEP)
    for step in (cur, cur - 1, cur + 1):
        if step > int(last_step or 0) and hmac.compare_digest(totp(secret, step), code):
            return step
    return None


def otpauth_uri(name: str, secret: str) -> str:
    label = urllib.parse.quote(f"{ISSUER}:{name}", safe=":")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={ISSUER}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP}")


def spaced(secret: str) -> str:
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))


# The authenticator secrets at rest

class SecretBox:
    """Fernet with a key from this machine's id, this account and a random
    salt kept beside the database. A copied database alone is useless; it is
    not protection from a program already running as this account."""

    def __init__(self, folder):
        from cryptography.fernet import Fernet
        salt_file = os.path.join(str(folder), "control.salt")
        try:
            with open(salt_file, "rb") as fh:
                salt = fh.read()
        except FileNotFoundError:
            salt = secrets.token_bytes(32)
            fd = os.open(salt_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(salt)
        machine = ""
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                with open(path) as fh:
                    machine = fh.read().strip()
                break
            except OSError:
                continue
        try:
            user = getpass.getuser()
        except Exception:                               # noqa: BLE001
            user = str(os.getuid())
        key = hashlib.scrypt(f"{machine}:{user}".encode(), salt=salt, dklen=32,
                             **_SCRYPT)
        self._f = Fernet(base64.urlsafe_b64encode(key))

    def seal(self, text: str) -> str:
        return self._f.encrypt(text.encode()).decode("ascii")

    def open(self, token: str) -> str:
        return self._f.decrypt(token.encode("ascii")).decode()
