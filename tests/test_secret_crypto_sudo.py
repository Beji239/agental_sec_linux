"""
tests/test_secret_crypto_sudo.py, a key saved from the privileged launcher
still opens in a normal run.

Under sudo the process is root and SUDO_UID names the person. The key must
be sealed for that person, and a value an older version sealed for root must
still open.
"""
import os
import pathlib
import pwd
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import secret_crypto as sc  # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}")
    if not ok:
        fails.append(label)


if not sc.available():
    print("SKIP: the cryptography package is not installed")
    sys.exit(0)

me = pwd.getpwuid(os.getuid()).pw_name
real_getuid = os.getuid


def as_root(sudo_uid):
    os.getuid = lambda: 0
    if sudo_uid is None:
        os.environ.pop("SUDO_UID", None)
    else:
        os.environ["SUDO_UID"] = str(sudo_uid)


def as_me():
    os.getuid = real_getuid
    os.environ.pop("SUDO_UID", None)


print("Saved from the privileged launcher")
as_root(real_getuid())
check("the key belongs to the person behind sudo", sc._account(), me)
sealed = sc.protect("example-secret-1")
as_me()
check("it opens in a normal run", sc.unprotect(sealed), "example-secret-1")

print("\nSealed for root by an older version")
old = "fernet:v1:" + __import__("base64").b64encode(
    sc._get_fernet("root").encrypt(b"example-secret-2")).decode()
check("it still opens in a normal run", sc.unprotect(old), "example-secret-2")

print("\nRoot with no sudo, a service started as root")
as_root(None)
check("the key is root's", sc._account(), "root")
as_me()

print("\nA value from another machine still fails plainly")
other = "fernet:v1:" + __import__("base64").b64encode(
    __import__("cryptography.fernet", fromlist=["Fernet"]).Fernet(
        __import__("cryptography.fernet", fromlist=["Fernet"]).Fernet
        .generate_key()).encrypt(b"x")).decode()
try:
    sc.unprotect(other)
    check("refused", "opened", "refused")
except sc.SecretCryptoError as e:
    check("refused with a sentence", "Could not decrypt" in str(e), True)

print(f"\n{'ALL PASSED' if not fails else str(len(fails)) + ' FAILED'}")
sys.exit(1 if fails else 0)
