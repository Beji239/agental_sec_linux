"""
tests/test_secret_store.py, where the keys live and how they are read.

core/secret_store reads .env into the environment, falls back to config.json
for old installs and says so, mints and saves the app's own key, and writes
the .env template. All in a scratch folder; the environment is put back
after each part.

Run it directly: python tests/test_secret_store.py
"""
import os
import pathlib
import stat
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                      # noqa: E402
_isolate_db.isolate()

from core import secret_crypto as crypto                # noqa: E402
from core import secret_store as ss                     # noqa: E402

fails = []
NAMES = ["AGENTAL_API_KEY", "AGENTAL_APP_API_KEY", "AGENTAL_ROUTER_COMMUNITY",
         "T_PLAIN", "T_QUOTED", "T_SINGLE", "T_EXPORTED", "T_KEPT", "T_SEALED",
         "T_BROKEN", "T_EMPTY"]
SAVED = {n: os.environ.get(n) for n in NAMES}


def restore():
    for n, v in SAVED.items():
        if v is None:
            os.environ.pop(n, None)
        else:
            os.environ[n] = v


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


work = pathlib.Path(tempfile.mkdtemp(prefix="secrets."))
for n in NAMES:
    os.environ.pop(n, None)

try:
    print("[1] reading .env")
    os.environ["T_KEPT"] = "from the environment"
    sealed = None
    if crypto.available():
        try:
            sealed = crypto.protect("opened")
        except Exception:                               # noqa: BLE001
            sealed = None
    env = work / ".env"
    env.write_text("# a comment\n\nT_PLAIN=one\nT_QUOTED=\"two words\"\n"
                   "T_SINGLE='three'\nexport T_EXPORTED=four\n"
                   "T_KEPT=from the file\nno equals sign here\n=nameless\n"
                   + (f"T_SEALED={sealed}\n" if sealed else "")
                   + f"T_BROKEN={crypto.MARKER}not-a-real-token\n")
    loaded = ss.load_dotenv(env)
    check("plain, quoted and exported values",
          [os.environ.get(n) for n in ("T_PLAIN", "T_QUOTED", "T_SINGLE",
                                       "T_EXPORTED")],
          ["one", "two words", "three", "four"])
    check("a real environment variable beats the file",
          os.environ["T_KEPT"], "from the environment")
    if sealed:
        check("an encrypted value is opened on the way in",
              os.environ.get("T_SEALED"), "opened")
    check("one that cannot be opened is skipped, never passed on as a key",
          ("T_BROKEN" in os.environ,
           any(k == "T_BROKEN" for k, _ in ss.decrypt_failures())),
          (False, True))
    check("and the count says what was loaded", loaded, 5 if sealed else 4)
    check("no file loads nothing", ss.load_dotenv(work / "none.env"), 0)
    restore()

    print("\n[2] resolving the keys")
    for n in NAMES:
        os.environ.pop(n, None)
    proj = work / "proj"
    proj.mkdir()
    (proj / ".env").write_text("AGENTAL_API_KEY=sk-from-env\n")
    out = ss.resolve({"provider": {"api_key": "sk-from-config"}}, proj)
    check(".env wins over config.json", out["api_key"], "sk-from-env")
    minted = out["app_api_key"]
    check("an app key is minted when there is none",
          len(minted) == 64 and all(c in "0123456789abcdef" for c in minted),
          True)
    text = (proj / ".env").read_text()
    check("and saved, so it survives a restart",
          f"AGENTAL_APP_API_KEY={minted}" in text, True)
    check("in a file only its owner can read",
          oct(stat.S_IMODE((proj / ".env").stat().st_mode)), oct(0o600))
    check("the other lines are kept", "AGENTAL_API_KEY=sk-from-env" in text,
          True)
    for n in NAMES:
        os.environ.pop(n, None)
    old = work / "old"
    old.mkdir()
    out = ss.resolve({"api_key": "a" * 64,
                      "provider": {"api_key": "sk-old"}}, old)
    check("an old install's keys in config.json still work, and are named",
          (out["api_key"], out["app_api_key"], sorted(out["legacy"])),
          ("sk-old", "a" * 64, ["app API key", "model provider API key"]))
    restore()

    print("\n[3] writing one value")
    f = work / "w.env"
    f.write_text("# keep me\nAGENTAL_APP_API_KEY=old\nOTHER=x\n")
    ss.persist_env_value(f, "AGENTAL_APP_API_KEY", "new")
    check("an existing line is replaced, never doubled",
          f.read_text().count("AGENTAL_APP_API_KEY="), 1)
    check("with the new value, comments kept",
          ("AGENTAL_APP_API_KEY=new" in f.read_text(),
           "# keep me" in f.read_text()), (True, True))
    check("a folder that is not there is a refusal, not a crash",
          ss.persist_env_value(work / "no" / "dir" / ".env", "X", "y"), False)

    print("\n[4] config.json and the template")
    cfg = {"api_key": "k", "provider": {"api_key": "p", "model": "m"},
           "flask": {"port": 5000}}
    check("secrets still in config.json are listed",
          ss.secrets_in_config(cfg),
          [("model provider API key", "AGENTAL_API_KEY"),
           ("app API key", "AGENTAL_APP_API_KEY")])
    cleaned, changed = ss.strip_from_config(cfg)
    check("and stripped for saving, the rest untouched",
          (cleaned, changed),
          ({"provider": {"model": "m"}, "flask": {"port": 5000}}, True))
    check("a clean config is left as it is",
          ss.strip_from_config({"flask": {}}), ({"flask": {}}, False))
    tpl = work / ".env.example"
    check("the template is written", ss.write_env_template(tpl), True)
    body = tpl.read_text()
    values = dict(ln.split("=", 1) for ln in body.splitlines()
                  if ln and not ln.startswith("#") and "=" in ln)
    check("it names every key the app reads",
          {"AGENTAL_API_KEY", "AGENTAL_APP_API_KEY",
           "AGENTAL_ROUTER_COMMUNITY"} <= set(values), True)
    check("and holds no value beyond a placeholder",
          [k for k, v in values.items() if v not in ("", "sk-your-key-here")],
          [])
    check("an unwritable template is a refusal",
          ss.write_env_template(work / "no" / "x"), False)
    os.environ["AGENTAL_ROUTER_COMMUNITY"] = "  readonly  "
    check("the router community is read fresh and trimmed",
          ss.router_community(), "readonly")
finally:
    restore()

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
