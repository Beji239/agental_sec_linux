"""
tests/test_provider_agnostic.py, the app runs on ANY provider, with ANY key,
and shows the model's REAL name. 2026-09-15.

WHY THIS EXISTS, and it is a requirement that was stated from day one and
then quietly not held.

The request path was always generic: endpoint, key and model name all come
from config, and the body is the plain OpenAI chat shape, so a gateway like
OpenRouter or a server on the user's own machine works. That part was fine.

Everything that DESCRIBES the model was written around one vendor:

  1. The topbar did (name || '').replace('deepseek-','') to shorten the
     label. That is a substring replace, not a prefix strip, and it takes the
     FIRST occurrence anywhere in the string. A gateway calls the same model
     "vendor/model-chat", so the pill rendered VENDOR/MODEL-CHAT, a model
     name that exists nowhere, permanently, in the topbar.

  2. The health check returned connected=False for ANY non-200 from the
     /models URL. Most local servers and some gateways do not publish a model
     list at all, so a working setup showed a red AI: OFFLINE. Rule two: "it
     is not there" and "I could not look" are different sentences.

  3. A missing deepseek.model fell back to the hardcoded string
     "model-chat", so a config that named no model still showed a
     confident name on screen and sent it in the request.

  4. When the configured name was not in the provider's list, the warning
     printed every available name. On DeepSeek that is two. On a gateway it
     is several hundred, in one log line.

None of the four stops the app talking to another provider. All four make it
LIE about which model is running, which on this app is the one label that
changes how every answer should be read.

Failure cases first, as always. Sections [1] to [4] are the four bugs above,
each driven with the input that produced it.
"""
import asyncio
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


from core import agent_loop as al                 # noqa: E402


# A stand-in for httpx that answers the model-list GET with whatever this
# test wants. No network, no key, no provider.
class _FakeResponse:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class _FakeClient:
    status = 200
    body = {"data": []}
    asked = None

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, headers=None):
        _FakeClient.asked = {"url": url, "headers": headers}
        return _FakeResponse(_FakeClient.status, _FakeClient.body)


def provider_check(status=200, body=None, names=None):
    """Run the real check_provider against a canned model-list answer."""
    if names is not None:
        body = {"data": [{"id": n} for n in names]}
    _FakeClient.status = status
    _FakeClient.body = {"data": []} if body is None else body
    _FakeClient.asked = None
    al._model_list_warned = None
    return asyncio.run(al.check_provider())


def configure(model, url="https://gateway.example.com/api/v1/chat/completions",
              key="test-key"):
    al.init_agent({"deepseek": {"model": model, "api_url": url}}, key)


_real_httpx = al.httpx
al.httpx = type("_FakeHttpx", (), {"AsyncClient": _FakeClient})

try:
    print("\n[1] FAILURE FIRST. The gateway name the old code mangled.")
    # The exact input that produced VENDOR/MODEL-CHAT on screen. The short label
    # must be the MODEL, and the vendor in front of it is not part of the
    # model's name.
    check("vendor/model-chat shortens to the model, not to a fragment",
          al.model_display_name("vendor/model-chat"), "model-chat")
    check("and the old substring replace really did produce the bad one "
          "(this is the bug, reproduced)",
          "vendor/model-chat".replace("deepseek-", ""), "vendor/chat")

    print("\n[1b] and the rule is about slashes, not about any vendor")
    # Every one of these is a real id from a real provider. Not one of them
    # is special-cased anywhere in the code.
    for raw, want in [
            ("model-chat",                     "model-chat"),
            ("model-o",                            "model-o"),
            ("vendor-b/model-o",                     "model-o"),
            ("vendor-a/model-c4",         "model-c4"),
            ("vendor/model-405b-instruct", "model-405b-instruct"),
            ("vendor/model-flash-001",       "model-flash-001"),
            ("vendor/model-large",           "model-large"),
            ("model-q:14b",                         "model-q:14b"),
            ("  spaced-out  ",                    "spaced-out"),
    ]:
        check(f"{raw!r}", al.model_display_name(raw), want)

    # Things that must be passed through rather than cleaned up. A suffix is
    # part of what the user chose, and trimming it would be bug 1 again with
    # a different provider's habits baked in.
    check("a free tier suffix is kept",
          al.model_display_name("vendor/model-r1:free"), "model-r1:free")
    check("a dated version is kept",
          al.model_display_name("vendor/model-c-20241022"),
          "model-c-20241022")
    check("a nested path keeps everything after the LAST slash",
          al.model_display_name("a/b/c-model"), "c-model")
    check("a trailing slash does not produce an empty label",
          al.model_display_name("openai/"), "openai/")
    check("nothing configured is an empty label, not a guess",
          al.model_display_name(""), "")

    print("\n[2] FAILURE FIRST. No model list is NOT the same as offline.")
    # A local server, and some gateways, answer 404 on /models. The old code
    # returned connected=False and the topbar went red on a setup that works.
    configure("local-model", "http://127.0.0.1:8080/v1/chat/completions")
    for code in (404, 405, 501):
        r = provider_check(status=code)
        check(f"HTTP {code} is 'unverified', not 'offline'", r["state"], "unverified")
        check(f"HTTP {code} does not claim the model was checked",
              r["verified"], False)
        check(f"HTTP {code} says which of the two happened",
              "could not be checked" in (r["error"] or ""), True)
    check("and the name still reaches the screen while unverified",
          provider_check(status=404)["display"], "local-model")

    # A 200 whose body cannot be read is the same shape of not-knowing.
    r = provider_check(status=200, body=ValueError("not json"))
    check("an unreadable model list is unverified too", r["state"], "unverified")
    check("and it does not claim the model was found", r["verified"], False)
    r = provider_check(names=[])
    check("an empty model list is unverified, not a missing model",
          r["state"], "unverified")

    print("\n[3] FAILURE FIRST. No model configured must not become a name.")
    # The fallback used to be the literal "model-chat", so a config with no
    # model key produced a confident label for a model nobody chose, and sent
    # that name in the request.
    # The real shape of it: the key is absent from config, not empty. Under
    # the old code this line alone produced "model-chat".
    al.init_agent({"deepseek": {"api_url": "https://example.test/v1"}}, "test-key")
    check("a config with NO model key invents nothing", al._model, "")
    configure("", key="test-key")
    check("an empty model key invents nothing either", al._model, "")
    check("the status payload says it is not set",
          al.model_status()["model_set"], False)
    check("and carries no name to print", al.model_status()["display_name"], "")
    r = provider_check()
    check("the check refuses before asking anyone", r["state"], "no_model")
    check("and nothing was sent", _FakeClient.asked, None)
    check("the source has no vendor model name as a default",
          '"model-chat")' in
          (ROOT / "core" / "agent_loop.py").read_text(encoding="utf-8"), False)

    print("\n[4] FAILURE FIRST. A gateway's model list is sampled, not dumped.")
    many = [f"vendor{i}/model-{i}" for i in range(320)]
    configure("not-on-this-gateway")
    r = provider_check(names=many)
    check("the key and service are still good", r["state"], "ok")
    check("the mismatch is reported", "is not in the provider's" in r["error"], True)
    check("but not by listing 320 names",
          r["error"].count(",") < 20, True)
    check("and it says how many it did not show",
          "and 310 more" in r["error"], True)

    print("\n[5] a key the provider REFUSES is offline, and says so")
    # The opposite of [2]. Here we did look, and the answer was no. This one
    # must stay red.
    configure("some-model")
    for code in (401, 403):
        r = provider_check(status=code)
        check(f"HTTP {code} is offline", r["state"], "offline")
        check(f"HTTP {code} names the key as the reason",
              "key" in r["error"], True)
    r = provider_check(status=500)
    check("a 500 is offline", r["state"], "offline")
    configure("some-model", key="")
    check("no key at all is its own state", provider_check()["state"], "no_key")

    print("\n[6] the happy path, on a provider this app was never written for")
    configure("vendor-a/model-c4")
    r = provider_check(names=["vendor-a/model-c4", "vendor-b/model-o"])
    check("state", r["state"], "ok")
    check("checked against the real list", r["verified"], True)
    check("no complaint", r["error"], None)
    check("the full id is carried", r["model"], "vendor-a/model-c4")
    check("and the short label is the model", r["display"], "model-c4")
    check("the model list URL is derived from the chat URL",
          _FakeClient.asked["url"], "https://gateway.example.com/api/v1/models")
    check("and the key goes with it",
          _FakeClient.asked["headers"]["Authorization"], "Bearer test-key")

    print("\n[7] the model list URL is derived, for any shape of endpoint")
    for url, want in [
            ("https://api.example.com/v1/chat/completions",
             "https://api.example.com/v1/models"),
            ("https://gateway.example.com/api/v1/chat/completions",
             "https://gateway.example.com/api/v1/models"),
            ("http://127.0.0.1:11434/v1/chat/completions",
             "http://127.0.0.1:11434/v1/models"),
            ("https://example.test/v1",
             "https://example.test/v1/models"),
    ]:
        configure("m", url)
        check(f"{url}", al._models_url(), want)

finally:
    al.httpx = _real_httpx


print("\n[8] the page does not shorten the name itself any more")
UI = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")

# CODE ONLY. The comment above the rewritten block quotes the old expression
# on purpose, so that anyone reading it knows what was wrong. Checking the
# raw file would fail on that note, and the obvious "fix" is to delete the
# explanation, which is backwards. Whole-line // comments are dropped and
# nothing else is, so a URL with // in it survives.
UI_CODE = "\n".join(l for l in UI.splitlines()
                    if not l.lstrip().startswith("//"))
check("(the comment stripper drops a note and keeps code)",
      [l for l in ["  // note", "  const x = 1;"]
       if not l.lstrip().startswith("//")], ["  const x = 1;"])
check("the vendor strip is gone from the page",
      ".replace('deepseek-','')" in UI_CODE, False)
check("and the explanation of why is still there",
      ".replace('deepseek-','')" in UI, True)
check("the page prints the label the server derived",
      "d.model_display" in UI_CODE, True)
check("and it reads the five-state field, not the boolean",
      "d.model_state" in UI_CODE, True)
check("'could not check' is not drawn as OFFLINE",
      "unverified: ['warn'" in UI_CODE, True)
check("a long name cannot push the topbar apart",
      ".pill-label {" in UI, True)


print("\n[9] nothing in the request path names a provider")
SRC = (ROOT / "core" / "agent_loop.py").read_text(encoding="utf-8")
code_only = "\n".join(l.split("#")[0] for l in SRC.splitlines())
# The DEFAULT endpoint is allowed to be a real URL, somebody has to be first,
# and it is one line that a config overrides. What must not exist is a model
# name, or a vendor test, anywhere in the logic.
check("no vendor name is tested against in code",
      any(s in code_only for s in ('"deepseek" in ', "'deepseek' in ",
                                   '.startswith("deepseek',
                                   ".startswith('deepseek")), False)
check("the model sent is the configured one, read from a variable",
      '"model":       _model,' in code_only, True)
check("and the endpoint is too",
      'client.stream("POST", _api_url' in code_only, True)


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
