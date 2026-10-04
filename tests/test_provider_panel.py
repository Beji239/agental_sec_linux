"""
tests/test_provider_panel.py, changing provider is a thing you can DO from
the dashboard. 2026-09-15, the second half of TODO 111.

WHY THIS EXISTS.

The key could already be changed from the settings panel, live. The endpoint
and the model could not: they were read from config.json once, at boot. So
"use my OpenRouter key instead of my DeepSeek one" meant editing a file and
restarting, on an app whose whole point is that the provider does not matter.
A capability nobody can reach is the same as a capability nobody built, which
is the lesson test_ui_wiring exists for.

The other half is the pill. /api/status caches its provider check for 30
seconds. You press Save, it really did connect, and the topbar goes on saying
NO KEY for half a minute, which reads as the save having failed. A correct
backend plus a stale label is still a tool that lied to you.

Failure cases first. [1] to [3] are what was wrong or what can go wrong:
a save that claims to be live without anything applying it, a save that
cannot be applied and must say so, and an endpoint that would break chat.
"""
import asyncio
import json
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


from core import settings as st                  # noqa: E402
from core import agent_loop as al                # noqa: E402


# A config.json of our own. NEVER the real one: set_config writes the file it
# is pointed at, and a test that edits the user's provider settings while
# checking that it can edit provider settings is TODO 108 all over again.
_tmp = pathlib.Path(tempfile.mkdtemp(prefix="agentalsec_cfg_"))
_cfg = _tmp / "config.json"
_cfg.write_text(json.dumps({
    "provider": {"model": "model-chat",
                 "api_url": "https://api.example.com/v1/chat/completions"},
    "sensor": {"position": "host", "label": None},
}, indent=2), encoding="utf-8")
_real_cfg_path = st.CONFIG_PATH
st.CONFIG_PATH = _cfg


def on_disk():
    return json.loads(_cfg.read_text(encoding="utf-8"))["provider"]


try:
    print("\n[1] FAILURE FIRST. 'live' is not a word a field may just claim.")
    # A field carrying effect live with nothing wired to apply it would put
    # "in use now" on screen over a value the running process never saw. The
    # panel drops the claim back to restart rather than making it.
    real_apply = dict(st._LIVE_APPLY)
    try:
        st._LIVE_APPLY.clear()
        row = next(f for f in st.config_fields({}) if f["path"] == "provider.model")
        check("with nothing to apply it, the row says restart",
              row["effect"], "restart")
        r = st.set_config("provider.model", "some-model")
        check("and so does the save", r["effect"], "restart")
    finally:
        st._LIVE_APPLY.clear()
        st._LIVE_APPLY.update(real_apply)
    check("(the real wiring is back)",
          sorted(st._LIVE_APPLY), ["provider.api_style", "provider.api_url",
                      "provider.model"])

    print("\n[2] FAILURE FIRST. A save that could not be applied says so.")
    # The file write succeeded and the handover did not. Reporting that as
    # live would be the panel asserting something it could not do.
    def _refuse(path, value):
        return False, "the agent was not listening"
    st._LIVE_APPLY["provider.model"] = _refuse
    try:
        r = st.set_config("provider.model", "written-anyway")
        check("the save still succeeded", r["ok"], True)
        check("it is on disk", on_disk()["model"], "written-anyway")
        check("but it does NOT claim to be live", r["effect"], "restart")
        check("and it says what went wrong",
              "not listening" in r.get("reason", ""), True)
    finally:
        st._LIVE_APPLY["provider.model"] = real_apply["provider.model"]

    print("\n[3] FAILURE FIRST. An endpoint that would break chat is refused.")
    before = on_disk()["api_url"]
    al.apply_provider(api_url=before)
    for bad, why in [("", "empty"), ("   ", "spaces only"),
                     ("api.openai.com/v1/chat", "no scheme"),
                     ("ftp://example.test/v1", "wrong scheme"),
                     ("https://example .test/v1", "a space in it")]:
        r = st.set_config("provider.api_url", bad)
        check(f"refused, {why}", r["ok"], False)
    check("and the file was not touched by any of them",
          on_disk()["api_url"], before)
    check("the running endpoint is untouched too", al._api_url, before)

    print("\n[4] the provider really is editable from the panel now")
    paths = [f["path"] for f in st.config_fields({})]
    check("the endpoint is on the allow-list", "provider.api_url" in paths, True)
    check("the model is too", "provider.model" in paths, True)
    check("and they come first, because that is the setting a new user "
          "has to change", paths[:2], ["provider.api_url", "provider.model"])
    rows = {f["path"]: f for f in st.config_fields({})}
    check("both are marked live", [rows[p]["effect"] for p in
                                   ("provider.api_url", "provider.model")],
          ["live", "live"])
    check("and both offer a test", [rows[p].get("testable") for p in
                                    ("provider.api_url", "provider.model")],
          [True, True])
    # A live field must not also wear the amber "restart to pick it up" note,
    # because for these two saving IS applying.
    check("a live row claims no saved-versus-running gap",
          any("running_value" in rows[p] for p in
              ("provider.api_url", "provider.model")), False)

    print("\n[5] saving it changes the RUNNING process, not just the file")
    al.init_agent({"provider": {"model": "old-model",
                                "api_url": "https://old.test/v1/chat/completions"}},
                  "test-key")
    r = st.set_config("provider.api_url", "https://gateway.example.com/api/v1/chat/completions")
    check("saved", r["ok"], True)
    check("and it says it is live", r["effect"], "live")
    check("the running endpoint moved", al._api_url,
          "https://gateway.example.com/api/v1/chat/completions")
    r = st.set_config("provider.model", "vendor-a/model-c4")
    check("the running model moved too", al._model, "vendor-a/model-c4")
    check("the file agrees", on_disk(), {
        "model": "vendor-a/model-c4",
        "api_url": "https://gateway.example.com/api/v1/chat/completions"})
    check("and the label follows without anyone being told",
          al.model_status()["display_name"], "model-c4")
    check("a blank model is allowed, it means not chosen",
          st.set_config("provider.model", None)["ok"], True)
    check("and the app says so rather than picking one",
          al.model_status()["model_set"], False)

    print("\n[6] the stale pill. A provider change invalidates the check.")
    # The number itself means nothing. What matters is that it MOVES on every
    # kind of provider change, because that is what the status cache compares.
    e0 = al.provider_epoch()
    al.apply_api_key("another-key")
    e1 = al.provider_epoch()
    check("a new key moves it", e1 > e0, True)
    st.set_config("provider.model", "model-chat")
    e2 = al.provider_epoch()
    check("a new model moves it", e2 > e1, True)
    st.set_config("provider.api_url", "https://api.example.com/v1/chat/completions")
    check("a new endpoint moves it", al.provider_epoch() > e2, True)

    # And the cache in routes.py really compares it, rather than only the
    # clock. Checked as source: standing up Flask here would be a heavier
    # test that proves the same one line.
    ROUTES = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")
    cache = ROUTES.split("def _cached_model_check")[1][:1200]
    check("the cache reads the epoch", "provider_epoch()" in cache, True)
    check("it compares it before serving a cached answer",
          '_model_check_cache["epoch"] == epoch' in cache, True)
    check("and stores it with the answer", '"epoch": epoch' in cache, True)

    print("\n[7] Test does not save, and answers with the state it found")
    al.init_agent({"provider": {"model": "saved-model",
                                "api_url": "https://saved.test/v1/chat/completions"}},
                  "test-key")

    class _Resp:
        def __init__(self, status, body):
            self.status_code, self._b = status, body

        def json(self):
            return self._b

    class _Client:
        status, body, asked = 200, {"data": []}, None

        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, headers=None):
            _Client.asked = url
            return _Resp(_Client.status, _Client.body)

    _real_httpx = al.httpx
    al.httpx = type("_F", (), {"AsyncClient": _Client})
    try:
        _Client.body = {"data": [{"id": "vendor-b/model-o"}]}
        r = asyncio.run(al.check_provider(
            api_url="https://typed.test/v1/chat/completions", model="vendor-b/model-o"))
        check("it tested what was typed", _Client.asked,
              "https://typed.test/v1/models")
        check("and found it", r["state"], "ok")
        check("the answer describes the typed model", r["model"], "vendor-b/model-o")
        check("NOTHING was saved, the running model is untouched",
              al._model, "saved-model")
        check("nor the running endpoint", al._api_url,
              "https://saved.test/v1/chat/completions")

        # A test of an unsaved value must not touch the state the SAVED
        # settings use, or one test would silence the log warning that
        # belongs to the provider the app is really running on.
        al._model_list_warned = None
        asyncio.run(al.check_provider(api_url="https://typed.test/v1/chat/completions",
                                      model="not-there"))
        check("a failed test leaves the saved warning state alone",
              al._model_list_warned, None)
    finally:
        al.httpx = _real_httpx

    print("\n[8] the panel stopped calling it the DeepSeek key")
    cat = {k["env"]: k for k in st.key_catalog()}
    row = cat.get("AGENTAL_API_KEY", {})
    check("the variable is the neutral one, the old one is still read",
          ("AGENTAL_API_KEY" in cat, row.get("legacy_env")),
          (True, "AGENTAL_DEEPSEEK_API_KEY"))
    check("but the label names no vendor",
          "deepseek" in (row.get("label") or "").lower(), False)
    check("it says what it is instead", row.get("label"),
          "Model provider API key")

finally:
    st.CONFIG_PATH = _real_cfg_path


print("\n[9] the page can reach all of it")
UI = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
UI_CODE = "\n".join(l for l in UI.splitlines() if not l.lstrip().startswith("//"))
ROUTES = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")
check("the test route exists",
      '"/api/settings/provider-test"' in ROUTES, True)
check("and the page calls it",
      "'/api/settings/provider-test'" in UI_CODE, True)
check("a testable field gets a Test button", "f.testable ?" in UI_CODE, True)
check("the save message asks the server which effect it was",
      "d.effect === 'live'" in UI_CODE, True)
check("saving a key refreshes the pill rather than waiting for the cache",
      UI_CODE.split("async function postKey")[1][:900].count("updateStatusPills()"), 1)
check("and so does saving a config field",
      UI_CODE.split("async function saveConfigField")[1][:1400]
        .count("updateStatusPills()"), 1)


print("\n[10] the config writer still cannot reach a secret")
# The rule this whole file is fenced by. Adding two writable paths is exactly
# when somebody adds a third by accident.
for secret in ("provider.api_key", "api_key", "AGENTAL_DEEPSEEK_API_KEY"):
    check(f"{secret} is refused", st.set_config(secret, "x")["ok"], False)
check("no allow-listed path names a key",
      [f["path"] for f in st.CONFIG_FIELDS if "key" in f["path"].lower()], [])


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
