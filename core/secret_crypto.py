# core/secret_crypto.py
# AgentalSec, at-rest encryption for the values in .env.
#
# WHAT THIS IS FOR
#   .env holds the model provider key, the app's own API key, and SSH keys.
#   This module encrypts values using Fernet (symmetric encryption) with a
#   key derived from the machine ID and a user-specific salt.
#
# WHAT IT IS NOT
#   It is not protection from root or from processes running as the same user.
#   It raises the cost of a copied .env file and protects against accidental
#   disclosure. A determined attacker with user-level access can still decrypt.
#
# THE FORMAT
#   An encrypted value is stored as:   fernet:v1:<base64>
#   A plain value is stored as itself. Hand-editing .env with plain keys works.
#
# THE FAILURE THAT MATTERS
#   Move .env to another machine and decryption fails. The error message
#   explains why rather than saying "bad key".
#
# WHY THIS FILE IS CALLED secret_crypto AND NOT dpapi_linux. 2026-09-25.
#
# It was core/dpapi_linux.py, named after the WINDOWS API it was written as
# the Linux alternative to, and core/dpapi.py -- the real Windows DPAPI
# module, ctypes against crypt32.dll -- was sitting beside it in the tree
# while nothing but the Settings card imported it. That is the shape this
# round exists to remove: a Windows file in a Linux build, reached by a live
# code path, which is how the card came to tell the operator the owner's secrets were
# "stored in plain text, Windows only" on a machine where they are encrypted.
#
# So: the Windows module moved to agental_sec_win32_reference/core/dpapi.py,
# this file got a name that says what it does rather than what it replaces, and
# the two callers (core/settings.py, core/secret_store.py) read THIS one.

import base64
import hashlib
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

MARKER = "fernet:v1:"

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.warning("cryptography not available, .env values will be plain text")


def _get_machine_key() -> bytes:
    """
    Derive a stable key from machine-specific information.

    On Linux, we use:
    - /etc/machine-id (stable across boots)
    - The account's OWN name, from the kernel rather than the environment
    - A static salt (prevents rainbow tables)

    THE ACCOUNT COMES FROM pwd, NOT FROM $USER, AND THAT IS A FIX RATHER THAN
    A TIDY-UP. This read os.environ["USER"] with a "default" fallback, and
    $USER IS EMPTY UNDER systemd and cron -- the two places a monitor service
    actually runs. Measured 2026-09-25 on this host: a value sealed with $USER
    SET could not be unsealed with $USER unset, because the fallback produced a
    different key. A secret that becomes unreadable the first time the app is
    started from a unit file is worse than one that was never encrypted,
    because by then the plain value is gone. (The measurement is reproduced in
    tests/test_secret_crypto.py [3] as a subprocess with $USER unset, which is
    the form that belongs in a file that ships.)

    This is NOT cryptographically random - it's a key derivation for
    binding encrypted values to this machine+user combination.
    """
    salt = b"AgentalSec_Linux_v1_Machine_Binding_Salt_2026"

    # Try machine-id first (systemd-based systems)
    machine_id = ""
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
        if Path(path).exists():
            try:
                machine_id = Path(path).read_text().strip()
                break
            except Exception:
                pass

    # Fallback to hostname if no machine-id
    if not machine_id:
        import socket
        machine_id = socket.gethostname()

    # THE ACCOUNT, from the kernel. pwd.getpwuid(os.getuid()) answers
    # identically with $USER set or unset, which is the whole point.
    try:
        import pwd
        username = pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        username = os.environ.get("USER", os.environ.get("USERNAME", "default"))

    # Combine and hash
    combined = f"{machine_id}:{username}:{salt.decode()}".encode('utf-8')
    key_material = hashlib.sha256(combined).digest()

    # Fernet requires a 32-byte URL-safe base64-encoded key
    return base64.urlsafe_b64encode(key_material)


def _get_fernet() -> Fernet | None:
    """Get a Fernet instance or None if cryptography unavailable."""
    if not CRYPTO_AVAILABLE:
        return None
    
    try:
        key = _get_machine_key()
        return Fernet(key)
    except Exception as e:
        logger.debug(f"Could not initialize Fernet: {e}")
        return None


def available() -> bool:
    """True when this machine can encrypt values."""
    return CRYPTO_AVAILABLE and _get_fernet() is not None


def enabled() -> bool:
    """
    True when new values SHOULD be written encrypted.
    
    Escape hatch: AGENTAL_ENV_PLAINTEXT=1 forces plain text.
    """
    if os.environ.get("AGENTAL_ENV_PLAINTEXT", "").strip() in ("1", "true", "yes"):
        return False
    return available()


def is_protected(value: str) -> bool:
    """Check if a value is encrypted."""
    return isinstance(value, str) and value.startswith(MARKER)


def protect(plain: str) -> str:
    """
    Encrypt one value and return it in fernet:v1: form.
    
    Empty string returns as empty string (clearing a key must be simple).
    Already-protected values pass through (no double-wrapping).
    """
    if not plain:
        return plain
    if is_protected(plain):
        return plain
    
    fernet = _get_fernet()
    if not fernet:
        raise SecretCryptoError(
            "This machine cannot encrypt .env values. "
            "Install 'cryptography' package: pip install cryptography"
        )
    
    try:
        encrypted = fernet.encrypt(plain.encode('utf-8'))
        return MARKER + base64.b64encode(encrypted).decode('ascii')
    except Exception as e:
        raise SecretCryptoError(f"Encryption failed: {e}")


def unprotect(value: str) -> str:
    """
    Turn a fernet:v1: value back into the key.
    
    Plain values pass through unchanged (hand-edited .env works).
    Raises SecretCryptoError with human-readable message on failure.
    """
    if not is_protected(value):
        return value
    
    fernet = _get_fernet()
    if not fernet:
        raise SecretCryptoError(
            "This value was encrypted with Fernet and cryptography is not "
            "available. Install 'cryptography' package or put the plain key "
            "in .env on this machine."
        )
    
    try:
        encrypted_data = base64.b64decode(value[len(MARKER):], validate=True)
        decrypted = fernet.decrypt(encrypted_data)
        return decrypted.decode('utf-8')
    except base64.binascii.Error:
        raise SecretCryptoError(
            "The fernet: value in .env is not valid base64. "
            "It looks truncated or hand-edited."
        )
    except Exception as e:
        # Decryption fails if the key doesn't match (wrong machine/user)
        raise SecretCryptoError(
            f"Could not decrypt this value. This normally means it was "
            f"encrypted on a DIFFERENT machine or by a DIFFERENT user. "
            f"The key itself is probably fine, it's just unreadable here. "
            f"Re-enter it in Settings on this machine, or copy the plain "
            f"value into .env. (Error: {e})"
        )


class SecretCryptoError(Exception):
    """
    Encrypt or decrypt failed. The message is written to be read by a person.

    IT WAS CALLED DpapiError until 2026-09-25, after the Windows API this
    module was written as an alternative to. A Linux-only tree raising a
    DPAPI error for a Fernet failure names a component that is not here --
    the same defect as the card's Windows rows, one layer down.
    """


def status() -> dict:
    """One small dict for the settings panel and boot line."""
    return {
        "available": available(),
        "enabled": enabled(),
        "why": (
            "Values written from the settings panel are encrypted against "
            "this machine and user combination."
            if enabled() else
            "Values are stored in plain text. Install 'cryptography' package "
            "or set AGENTAL_ENV_PLAINTEXT=1 deliberately."
        ),
    }
