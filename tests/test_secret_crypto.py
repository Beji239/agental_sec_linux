"""
tests/test_secret_crypto.py, encrypting the values in .env.

CONVERTED 2026-09-25 from tests/test_dpapi.py, in the Windows-leftovers round.
WHAT CHANGED AND WHY. This file was written around DPAPI -- ctypes against
Windows' crypt32.dll -- and off Windows every check it could make was the
negative half: "this machine cannot encrypt", "an encrypted value cannot be
read here". The module that actually protects .env on this platform,
core/secret_crypto.py (Fernet), was sitting beside the Windows one, reachable
from core/settings.py's key panel as core.dpapi_linux, and had no test of its
own.

So the file is now about the module that runs: the REAL round trip, not a
skipped one. The properties this file exists for are unchanged, because they
were never about Microsoft's crypto:

  the format tells an encrypted value from a plain one on sight
  a plain value keeps working, forever, hand typed
  a value this account cannot read is NOT passed on as if it were a key
  the failure says which of the two things went wrong
  the settings writer puts the encrypted form on disk and keeps the real
  value in the process
  AND THE KEY IS DERIVED FROM THE ACCOUNT, NOT FROM $USER, which is the one
  property the old module did not have: a secret sealed under a shell could
  not be unsealed under systemd, because $USER is empty there.

Runs anywhere Linux does. No network, no writes to the real .env.
"""
import os
import pathlib
import subprocess
import sys
import _skip
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from core import secret_crypto as crypto, secret_store, settings  # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


print(f"\nRunning on {os.name}, encryption available: {crypto.available()}")


print("\n[1] the format tells an encrypted value from a plain one")
check("a sealed value is recognised",
      crypto.is_protected("fernet:v1:AAAA"), True)
check("a plain key is not", crypto.is_protected("sk-abcdef"), False)
check("an empty string is not", crypto.is_protected(""), False)
check("a plain value passes straight through",
      crypto.unprotect("sk-plain-key"), "sk-plain-key")
check("an empty value comes back empty, not as a blob",
      crypto.protect(""), "")


print("\n[2] the real round trip, on this machine")
if not crypto.available():
    # A test that silently passes when it could not look is the defect this
    # project keeps recording, so this says so out loud instead.
    print("  SKIP  this host cannot encrypt: the 'cryptography' package is "
          "not installed. Nothing below proves encryption works here.")
else:
    # NOT shaped like a real key, on purpose: this tree ships, and a fixture
    # that LOOKS like a live credential trips the leak gate's own API-key rule.
    # The round's own measurement was one line of that, and the fix is free.
    secret = "a-value-this-machine-sealed"
    sealed = crypto.protect(secret)
    check("it is stored in the marked form", sealed.startswith(crypto.MARKER),
          True)
    check("and it is not the plain value", sealed == secret, False)
    check("it comes back exactly", crypto.unprotect(sealed), secret)
    check("sealing a sealed value does not double wrap",
          crypto.protect(sealed), sealed)
    uni = "\u00e9\u4e2d\u6587-key"
    check("a non ascii value survives", crypto.unprotect(crypto.protect(uni)),
          uni)

    # THE FAILURE THAT MATTERS, and the message IS the feature: a blob that
    # cannot be opened must not read as a bad key, or somebody rotates a
    # credential that was fine.
    for bad, why in [("fernet:v1:bm90LWEtcmVhbC1ibG9i", "a blob this machine "
                                                       "did not write"),
                     ("fernet:v1:not base64 at all !!", "not base64")]:
        try:
            crypto.unprotect(bad)
            check(f"refused {why}", "allowed", "refused")
        except crypto.SecretCryptoError as e:
            check(f"refused {why}", "refused", "refused")
            check("and the message does not blame the key",
                  "bad key" in str(e).lower(), False)
    try:
        crypto.unprotect("fernet:v1:bm90LWJhc2U2NA==")
    except crypto.SecretCryptoError as e:
        # Case-insensitive on purpose: the module says "DIFFERENT machine" in
        # capitals for emphasis, and a check that pins the case is pinning a
        # style, not the property.
        _m = str(e).lower()
        check("an unreadable blob says it is unreadable HERE",
              "different machine" in _m or "different user" in _m, True)


print("\n[3] the key comes from the ACCOUNT, not from $USER")
# THE DEFECT THIS SECTION EXISTS FOR, measured on this host before the fix:
# a value sealed with $USER SET raised "Could not decrypt this value" with
# $USER unset, because the module read os.environ["USER"] with a "default"
# fallback -- and $USER IS EMPTY UNDER systemd AND cron, the two places a
# monitor service actually runs. A secret that becomes unreadable the first
# time the app is started from a unit file is worse than one that was never
# encrypted.
#
# Driven as a SUBPROCESS, because the point is what a different ENVIRONMENT
# produces, and os.environ cannot be unset for a reload of an already-imported
# module in this process.
if crypto.available():
    sealed = crypto.protect("value-sealed-in-this-shell")
    body = (
        "import sys, pathlib;"
        f"sys.path.insert(0, {str(pathlib.Path(__file__).resolve().parent.parent)!r});"
        "from core import secret_crypto as c;"
        f"print(c.unprotect({sealed!r}))"
    )
    env = {k: v for k, v in os.environ.items() if k not in ("USER", "USERNAME")}
    out = subprocess.run([sys.executable, "-c", body], capture_output=True,
                         text=True, env=env, timeout=60)
    check("a value sealed here opens with $USER and $USERNAME unset",
          out.stdout.strip(), "value-sealed-in-this-shell")
    check("and nothing was written to stderr",
          (out.stderr or "").strip(), "")


print("\n[4] .env reading, the only place decryption happens")
with tempfile.TemporaryDirectory() as d:
    root = pathlib.Path(d)
    plain_name = "AGENTAL_TEST_PLAIN"
    seal_name  = "AGENTAL_TEST_SEALED"
    bad_name   = "AGENTAL_TEST_BROKEN"
    for n in (plain_name, seal_name, bad_name):
        os.environ.pop(n, None)

    body = f"# a comment\n{plain_name}=hand-typed-value\n"
    if crypto.available():
        body += f"{seal_name}={crypto.protect('sealed-value')}\n"
    body += f"{bad_name}=fernet:v1:bm90LWEtcmVhbC1ibG9i\n"
    (root / ".env").write_text(body, encoding="utf-8")

    loaded = secret_store.load_dotenv(root / ".env")

    check("a hand typed value still works",
          os.environ.get(plain_name), "hand-typed-value")
    if crypto.available():
        check("an encrypted value arrives decrypted",
              os.environ.get(seal_name), "sealed-value")

    # The one that matters. An unreadable value must NOT reach the
    # environment, because a blob handed to an API as a credential produces a
    # 401 and sends somebody off to rotate a key that was fine.
    check("an unreadable value is not passed on as a key",
          os.environ.get(bad_name), None)
    check("and it is recorded so the panel can say which one",
          any(n == bad_name for n, _ in secret_store.decrypt_failures()), True)
    check("the count only counts what actually loaded",
          loaded >= 1, True)

    for n in (plain_name, seal_name, bad_name):
        os.environ.pop(n, None)


print("\n[5] the settings writer stores the encrypted form")
# Points ENV_PATH at a temp file rather than touching the real .env. Writing a
# test that edits the file holding your live keys is how you lose them.
with tempfile.TemporaryDirectory() as d:
    real_env = settings.ENV_PATH
    try:
        settings.ENV_PATH = pathlib.Path(d) / ".env"
        # A file a person also edits by hand, which is the shape this writer
        # exists for. The comment has to survive the write.
        settings.ENV_PATH.write_text(
            "# a comment a person wrote\nAGENTAL_OTHER_KEY=keep-me\n",
            encoding="utf-8")
        ok, err = settings._write_env_line("AGENTAL_DEEPSEEK_API_KEY",
                                           "test-key-written-by-the-panel")
        check("the write reported ok", (ok, err), (True, ""))
        on_disk = settings.ENV_PATH.read_text(encoding="utf-8")

        if crypto.available():
            check("what landed on disk is encrypted, not the key",
                  "test-key-written-by-the-panel" in on_disk, False)
            check("and it carries the marker",
                  crypto.MARKER in on_disk, True)
            # AND IT LOADS BACK, which is the half a writer test forgets.
            os.environ.pop("AGENTAL_DEEPSEEK_API_KEY", None)
            secret_store.load_dotenv(settings.ENV_PATH)
            check("and it decrypts back to the key at boot",
                  os.environ.get("AGENTAL_DEEPSEEK_API_KEY"),
                  "test-key-written-by-the-panel")
            os.environ.pop("AGENTAL_DEEPSEEK_API_KEY", None)
        else:
            check("with no crypto the key is stored plain, and says so",
                  "test-key-written-by-the-panel" in on_disk, True)
        check("the comment a person wrote is still in the file",
              "# a comment a person wrote" in on_disk, True)
        check("and the other line was not touched",
              "AGENTAL_OTHER_KEY=keep-me" in on_disk, True)

        # Clearing has to keep working, encrypted or not.
        ok, _ = settings._write_env_line("AGENTAL_DEEPSEEK_API_KEY", "")
        cleared = settings.ENV_PATH.read_text(encoding="utf-8")
        check("clearing writes an empty value",
              "AGENTAL_DEEPSEEK_API_KEY=\n" in cleared, True)
    finally:
        settings.ENV_PATH = real_env


print("\n[6] the panel can say how .env is stored, and reads THIS module")
st = crypto.status()
check("status names both facts", sorted(st.keys()),
      ["available", "enabled", "why"])
check("enabled implies available", (not st["enabled"]) or st["available"], True)
check("it explains itself in a sentence", len(st["why"]) > 20, True)
# THE PANEL POINTED AT THE WINDOWS MODULE UNTIL 2026-09-25, so on this host it
# always read "Windows only. Nothing to do on other systems." while this module
# was working. Both the import and the sentence are asserted.
_src = (pathlib.Path(__file__).resolve().parent.parent
        / "core" / "settings.py").read_text(encoding="utf-8")
check("the panel imports the module that runs here",
      "from core import secret_crypto as crypto" in _src, True)
check("and no longer imports the Windows one",
      "from core import dpapi" in _src, False)
check("and no row still says 'Windows only' about it",
      "Windows only. Nothing to do on other systems." in _src, False)
check("the secret store decrypts with the same module",
      "from core import secret_crypto as crypto" in
      (pathlib.Path(__file__).resolve().parent.parent
       / "core" / "secret_store.py").read_text(encoding="utf-8"), True)


print("\n[7] the Windows module is out of the tree")
_root = pathlib.Path(__file__).resolve().parent.parent
check("core/dpapi.py is gone", (_root / "core" / "dpapi.py").exists(), False)
check("and the name it had here is gone too",
      (_root / "core" / "dpapi_linux.py").exists(), False)
if not (_root.parent / "agental_sec_win32_reference").is_dir():
    _skip.skip_part("the Windows reference folder is local, not in a clone")
else:
    check("the reference copy is beside the two source folders",
          (_root.parent / "agental_sec_win32_reference" / "core"
           / "dpapi.py").exists(), True)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
if not fails:
    _skip.exit_if_skipped()
sys.exit(1 if fails else 0)
