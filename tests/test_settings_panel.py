"""
tests/test_settings_panel.py, the settings panel writes to the right file.

WHY THIS FILE EXISTS. The panel from 2.3 + 8.5 handles secrets, and the one
thing it must never do is put one in config.json. That split is the whole
reason config.json is safe to commit, and a settings screen that fills the
wrong file undoes it silently: nothing breaks, nothing logs, and the mistake
surfaces the day somebody runs git add.

So most of what is fenced here is REFUSALS. A writer is worth what it says no
to. The rest is the two properties the panel promises out loud: it never hands
a key back, and it never quietly corrects a value somebody typed.

Runs with no database, no network and no app. Everything touching disk is
pointed at a temp directory first.
"""
import json
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import settings as st        # noqa: E402
# REPOINTED 2026-09-25, THE WINDOWS-LEFTOVERS ROUND. This imported core.dpapi
# -- ctypes against Windows' crypt32.dll -- and the runner reported this whole
# file as SKIP ("cannot import dpapi") from the day that module left the tree.
# A SKIP IS NOT A PASSPORT: the file has assertions about the settings panel
# and about what lands in .env, and none of them had run since.
#
# core.dpapi is in agental_sec_win32_reference/ now and core/secret_crypto.py
# (Fernet) is the module that actually protects .env here, so the two calls
# below are the same two calls the panel itself makes. Nothing else changed.
from core import secret_crypto as crypto   # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def env_value(name):
    """
    What NAME is actually set to in .env, read the way the app reads it.

    NOT a string search of the file any more. TODO 2.2 encrypts values on
    Windows, so 'the plain key is in the file' stopped being what correct
    looks like, and four checks here went red on the day it landed. Asserting
    the stored SHAPE was the mistake, same lesson as the two stale tests in
    50.1: assert what the thing does, which is that the value comes back.
    """
    for line in st.ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("export "):
            line = line[7:].lstrip()
        if not line.startswith(f"{name}="):
            continue
        value = line.split("=", 1)[1].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        return crypto.unprotect(value) if crypto.is_protected(value) else value
    return None


tmp = pathlib.Path(tempfile.mkdtemp(prefix="agental_settings_"))
st.ENV_PATH     = tmp / ".env"
st.CONFIG_PATH  = tmp / "config.json"
st.ENV_EXAMPLE  = tmp / ".env.example"

st.ENV_EXAMPLE.write_text(
    "# AgentalSec secrets. Copy to .env and fill in.\n"
    "\n"
    "# Model provider API key.\n"
    "# Only needed in API mode.\n"
    "AGENTAL_API_KEY=\n"
    "\n"
    "# AgentalSec's own REST API key.\n"
    "AGENTAL_APP_API_KEY=\n"
    "\n"
    "AGENTAL_NOBODY_READS_THIS=\n",
    encoding="utf-8")


print("\n[1] the template is read, not restated")
# The list of keys is already written down twice, in .env.example and in
# enrichment.KEYED_SOURCES. A third copy in the panel is what went stale in 44.
notes = st.env_example_notes()
check("a key's comment block is picked up",
      "Only needed in API mode." in notes.get("AGENTAL_API_KEY", ""),
      True)
check("a multi-line block joins into one note",
      notes.get("AGENTAL_API_KEY", "").startswith("Model provider API key"),
      True)
check("the file header is not attached to the first key",
      "Copy to .env" in notes.get("AGENTAL_API_KEY", ""), False)

drift = st.key_drift()
check("a template entry nothing reads is reported as drift",
      "AGENTAL_NOBODY_READS_THIS" in drift["template_only"], True)


print("\n[2] the catalogue never carries a value")
import os                                        # noqa: E402
os.environ["AGENTAL_ABUSEIPDB_KEY"] = "abcdef0123456789"
cat = st.key_catalog()
check("every enrichment source appears",
      {"AGENTAL_ABUSEIPDB_KEY", "AGENTAL_ABUSECH_KEY"} <= {k["env"] for k in cat},
      True)
row = next(k for k in cat if k["env"] == "AGENTAL_ABUSEIPDB_KEY")
check("no row has a value field", any("value" in k for k in cat), False)
check("the raw key is nowhere in the payload",
      "abcdef0123456789" in json.dumps(cat), False)
check("present is reported", row["present"], True)
check("and the last four, which reconstruct nothing", row["last4"], "6789")
# A short string is not a real key, and four characters of a six character
# value is most of it.
os.environ["AGENTAL_ABUSEIPDB_KEY"] = "short"
check("a too-short value gets no tail at all",
      next(k for k in st.key_catalog()
           if k["env"] == "AGENTAL_ABUSEIPDB_KEY")["last4"], "")
os.environ.pop("AGENTAL_ABUSEIPDB_KEY")


print("\n[3] .env: written, updated, and the comments survive")
st.ENV_PATH.write_text(
    "# A comment somebody wrote by hand.\n"
    "AGENTAL_API_KEY=old-value\n"
    "\n"
    "# Another one.\n"
    "AGENTAL_ROUTER_COMMUNITY=\n",
    encoding="utf-8")

r = st.set_key("AGENTAL_ROUTER_COMMUNITY", "readonly123")
check("a known key is accepted", r["ok"], True)
body = st.ENV_PATH.read_text(encoding="utf-8")
check("the value landed", env_value("AGENTAL_ROUTER_COMMUNITY"), "readonly123")
if crypto.enabled():
    check("and the key itself is not sitting in the file",
          "readonly123" in body, False)
check("hand-written comments are still there",
      "# A comment somebody wrote by hand." in body and "# Another one." in body,
      True)
check("the other key was not touched",
      "AGENTAL_API_KEY=old-value" in body, True)
check("and os.environ is in step, so 'applies immediately' is true",
      os.environ.get("AGENTAL_ROUTER_COMMUNITY"), "readonly123")

r = st.set_key("AGENTAL_ROUTER_COMMUNITY", "")
check("an empty value clears it", r["present"], False)
check("cleared in the file", "AGENTAL_ROUTER_COMMUNITY=\n"
      in st.ENV_PATH.read_text(encoding="utf-8"), True)
check("and out of the environment",
      "AGENTAL_ROUTER_COMMUNITY" in os.environ, False)

# A key not yet in the file is appended, not silently dropped.
r = st.set_key("AGENTAL_ABUSECH_KEY", "aabbccdd11223344")
check("a missing key is appended", r["ok"], True)
check("and is readable back", env_value("AGENTAL_ABUSECH_KEY"),
      "aabbccdd11223344")
os.environ.pop("AGENTAL_ABUSECH_KEY", None)


print("\n[4] .env: the refusals")
check("an unknown variable is refused",
      st.set_key("AGENTAL_NOT_A_THING", "x")["ok"], False)
check("nothing was written for it",
      "AGENTAL_NOT_A_THING" in st.ENV_PATH.read_text(encoding="utf-8"), False)
# The realistic failure is a paste that brought a newline with it, which would
# otherwise inject a second line into a secrets file.
check("a newline in the value is refused",
      st.set_key("AGENTAL_ABUSECH_KEY", "abc\nAGENTAL_APP_API_KEY=hijack")["ok"],
      False)
check("no injected line survived",
      "hijack" in st.ENV_PATH.read_text(encoding="utf-8"), False)
check("a quote character is refused",
      st.set_key("AGENTAL_ABUSECH_KEY", 'ab"cd')["ok"], False)
check("an absurdly long value is refused",
      st.set_key("AGENTAL_ABUSECH_KEY", "a" * 900)["ok"], False)


print("\n[5] the generated app key")
r = st.generate_app_key()
check("it generates one", r["ok"], True)
check("64 hex characters", len(env_value("AGENTAL_APP_API_KEY") or ""), 64)
# It must NOT take effect now: app.config holds the key this process started
# with and the open page carries it, so swapping it live 401s the operator.
check("it says the next start, not now", r["effect"], "restart")
check("and the value is not handed back", "key" in r, False)


print("\n[6] config.json: a secret cannot be addressed here at all")
# This is the property the whole file exists for. The config writer's
# allow-list is a fixed list of non-secret paths, so there is no request that
# gets a secret into config.json even if somebody posts one.
suspicious = [f["path"] for f in st.CONFIG_FIELDS
              if any(w in f["path"].lower()
                     for w in ("key", "secret", "token", "community",
                               "password", "api_key"))]
check("no writable field names a credential", suspicious, [])
check("posting a secret path is refused",
      st.set_config("deepseek.api_key", "sk-nope")["ok"], False)
check("so is the top-level legacy one",
      st.set_config("api_key", "sk-nope")["ok"], False)
check("and an unlisted path is refused even when it is harmless",
      st.set_config("flask.host", "0.0.0.0")["ok"], False)


print("\n[7] config.json: writes land, refusals do not correct")
st.CONFIG_PATH.write_text(json.dumps({
    "_comment": ["kept"],
    "flask": {"port": 5000, "auto_open_browser": True},
    "presence_sweep": {"enabled": True, "interval_minutes": 15},
    "geoip": {"enabled": True, "home_lat": None},
}, indent=2), encoding="utf-8")

check("an int in range is written",
      st.set_config("presence_sweep.interval_minutes", 30)["ok"], True)
raw = json.loads(st.CONFIG_PATH.read_text(encoding="utf-8"))
check("the value is there", raw["presence_sweep"]["interval_minutes"], 30)
check("and the file's own comments survived", raw["_comment"], ["kept"])

# REFUSES rather than clamps. Silently changing an operator's number is how a
# tool ends up sweeping every ten seconds because somebody typed a zero.
r = st.set_config("presence_sweep.interval_minutes", 0)
check("a value below the floor is refused", r["ok"], False)
check("and was not clamped to the floor instead",
      json.loads(st.CONFIG_PATH.read_text(encoding="utf-8"))
          ["presence_sweep"]["interval_minutes"], 30)
check("a non-number is refused",
      st.set_config("presence_sweep.interval_minutes", "soon")["ok"], False)
check("a bool field refuses a string",
      st.set_config("presence_sweep.enabled", "yes")["ok"], False)
check("a bool field takes a bool",
      st.set_config("presence_sweep.enabled", False)["ok"], True)
check("an unknown choice is refused",
      st.set_config("sensor.position", "somewhere")["ok"], False)
check("a real sensor position is accepted",
      st.set_config("sensor.position", "host")["ok"], True)
# A blank latitude means 'not set', which is a real answer for this field.
check("a blank float clears rather than erroring",
      st.set_config("geoip.home_lat", None)["ok"], True)
check("an out-of-range latitude is refused",
      st.set_config("geoip.home_lat", 200)["ok"], False)


print("\n[8] the display name is bounded")
check("an overlong name is refused",
      st.set_display_name("x" * 200)["ok"], False)
check("a line break is refused",
      st.set_display_name("Ada\nrm -rf")["ok"], False)


print("\n[9] readiness: a broken health check is a finding, not a crash")
# 2.3 started because collectors were silently not running. A status() that
# throws must not put us back there by taking the panel down with it.
class Exploding:
    def status(self):
        raise RuntimeError("no")


class Dead:
    def status(self):
        return {"running": True, "reachable": False,
                "last_success_age_seconds": 3600}


class Backlogged:
    def status(self):
        return {"running": True, "backlog": 31000}


check("an exploding status is a problem row",
      st._module_row("boom", Exploding())["state"], "problem")
check("and names the exception",
      "RuntimeError" in st._module_row("boom", Exploding())["detail"], True)
# Section 31 in one sentence: the tile said running while nothing was read.
check("unreachable beats running", st._module_row("linux", Dead())["state"],
      "problem")
check("a backlog is a problem, not a healthy tile",
      st._module_row("event", Backlogged())["state"], "problem")
check("a module that never loaded is off, not broken",
      st._module_row("probe", None)["state"], "off")

rows = [{"state": "ok"}, {"state": "off"}, {"state": "off"},
        {"state": "problem"}]
s = st.summary([dict(r, area="a", title="t", detail="d", fix="") for r in rows])
check("off is never counted as a problem", (s["ok"], s["off"], s["problem"]),
      (1, 2, 1))


print("\n[10] the app key has a floor, because it is the one we issue")
# Every other key here was issued by somebody else and we are in no position
# to judge its shape. This one guards every tool in the manifest, so a typed
# word is not a value to accept politely.
check("a short app key is refused",
      st.set_key("AGENTAL_APP_API_KEY", "test123")["ok"], False)
check("and the refusal points at Generate",
      "Generate" in st.set_key("AGENTAL_APP_API_KEY", "test123")["reason"], True)
check("a real length is accepted",
      st.set_key("AGENTAL_APP_API_KEY", "b" * 64)["ok"], True)
# Clearing it stays possible: an empty value means "mint one at the next
# start", which is a legitimate thing to want.
check("but clearing it is still allowed",
      st.set_key("AGENTAL_APP_API_KEY", "")["ok"], True)


print("\n[11] the config panel reads the FILE, not the booted dict")
# The bug: the app holds the config it booted with, nothing updates that dict
# when the panel writes, so the panel rendered the OLD value straight after a
# successful save. Saving worked and looked like it had not.
st.CONFIG_PATH.write_text(json.dumps({
    "flask": {"port": 5001},
    "presence_sweep": {"interval_minutes": 30},
}, indent=2), encoding="utf-8")
booted = {"flask": {"port": 5000}, "presence_sweep": {"interval_minutes": 30}}
rows = {f["path"]: f for f in st.config_fields(booted)}
check("the field shows what is on disk", rows["flask.port"]["value"], 5001)
check("and names what this session is still running",
      rows["flask.port"]["running_value"], 5000)
# No stale banner where nothing changed, or every row wears one forever.
check("a field that agrees carries no running_value",
      "running_value" in rows["presence_sweep.interval_minutes"], False)


print("\n[12] one writer at a time")
# Read-modify-write on eight server threads. The loser of a race silently
# reverts the winner, and in .env the thing that reverts is a credential.
import threading                                 # noqa: E402
st.ENV_PATH.write_text("", encoding="utf-8")
names = ["AGENTAL_ABUSEIPDB_KEY", "AGENTAL_ABUSECH_KEY",
         "AGENTAL_ROUTER_COMMUNITY", "AGENTAL_API_KEY"]
threads = [threading.Thread(target=st.set_key, args=(n, n.lower() + "0000"))
           for n in names for _ in range(4)]
for t in threads:
    t.start()
for t in threads:
    t.join()
body = st.ENV_PATH.read_text(encoding="utf-8")
check("every concurrent write survived",
      sorted(n for n in names if env_value(n) == n.lower() + "0000"),
      sorted(names))
# One line per key, not four. A racing appender writes duplicates, and .env
# duplicates are the kind of thing nobody notices until the wrong one wins.
check("and none of them was written twice",
      [n for n in names if body.count(f"\n{n}=") > 1], [])
for n in names:
    os.environ.pop(n, None)


print("\n[13] the routes refuse what the module refuses")
# The module can be right and the HTTP layer still be looser, which is what
# 8.9 was. Same refusals, through the real route table.
try:
    from flask import Flask
except ImportError:
    print("  SKIP  flask not installed")
else:
    sys.path.insert(0, str(ROOT))
    import api.routes as routes                  # noqa: E402
    app = Flask(__name__, template_folder="../ui")
    app.config.update({
        "AGENTAL_API_KEY": "k" * 64,
        "AGENTAL_CONFIG": {"flask": {"port": 5000}},
        "AGENTAL_MODULES": {},
        "AGENTAL_SESSION_ID": "test",
        "AGENTAL_ALLOWED_HOSTS": {"localhost"},
    })
    routes.register_routes(app)
    c = app.test_client()
    H = {"X-API-Key": "k" * 64}
    B = "http://localhost"

    def post(path, body):
        return c.post(path, headers=H, base_url=B, json=body)

    check("the panel answers", c.get("/api/settings", headers=H,
                                     base_url=B).status_code, 200)
    check("an unauthenticated read is refused",
          c.get("/api/settings", base_url=B).status_code, 401)
    check("an unknown variable is a 400",
          post("/api/settings/key", {"env": "X", "value": "y"}).status_code, 400)
    check("a secret path into config.json is a 400",
          post("/api/settings/config",
               {"path": "deepseek.api_key", "value": "sk"}).status_code, 400)
    check("an out-of-range number is a 400",
          post("/api/settings/config",
               {"path": "flask.port", "value": 999999}).status_code, 400)
    check("an overlong name is a 400",
          post("/api/settings/name", {"name": "x" * 99}).status_code, 400)
    # The whole payload, not just the key rows. Nothing anywhere in what the
    # panel returns should be a credential.
    os.environ["AGENTAL_ABUSEIPDB_KEY"] = "supersecretvalue1234"
    payload = c.get("/api/settings", headers=H, base_url=B).get_data(as_text=True)
    check("no key value appears anywhere in the response",
          "supersecretvalue1234" in payload, False)
    os.environ.pop("AGENTAL_ABUSEIPDB_KEY", None)


print("\n[14] reading the panel leaves nothing behind")
# sqlite3.connect CREATES an empty file at a missing path, so both the size
# measurement and the display-name read used to bring a database into being
# just by rendering this page. An empty database is worse than no database:
# it reads as a tool with nothing to report.
import sqlite3                                   # noqa: E402
from core import memory_engine as me             # noqa: E402

created = []
_real_connect = sqlite3.connect


def _spy(*a, **k):
    path = str(a[0]) if a else ""
    if path.endswith(".db") and not os.path.exists(path):
        created.append(path)
    return _real_connect(*a, **k)


sqlite3.connect = _spy
try:
    me.DB_PATH = str(tmp / "does_not_exist.db")
    st.display_name()
    st._retention_rows()
finally:
    sqlite3.connect = _real_connect
check("no database was conjured by reading", created, [])


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
