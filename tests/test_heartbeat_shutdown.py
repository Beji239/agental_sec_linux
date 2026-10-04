"""
tests/test_heartbeat_shutdown.py, the two things that came out of the frozen
terminal on 2026-09-08.

That evening a two hour split run ended with a console window that would not
come back from minimised. Ctrl+C was the only way to stop the app, the window
was the only way to reach Ctrl+C, so the machine got shut down instead and the
final rollup and retention never ran.

Two separate problems, one test file:

  1. The run left NOTHING behind about itself. We could only prove the app was
     healthy by reasoning about logging handler order after the fact, on a
     machine that had already been rebooted. core/heartbeat.py fixes that.

  2. There was only one door. api/routes.py /api/shutdown is the second one,
     and the dashboard was demonstrably still answering when the terminal was
     not, so it is a door that actually works in the case that produced it.

Most of the assertions below are about WORDING, same as the process
inspection suite. A heartbeat that prints numbers nobody can read is the same
failure as the grey rows with the reason hidden in a tooltip.
"""
import sys, tempfile, sqlite3, pathlib, threading, time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []
def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


from core import heartbeat


print("\n[1] a beat says the three things a long run needs")
state = {"started_at": time.time() - 3600}
lines = heartbeat.beat(state)
first = lines[0]
check("there is a line", bool(first), True)
check("it says how long the run has been up", "up 1h 0m" in first, True)
check("it reports threads", "threads" in first, True)
check("it reports memory or says plainly that it cannot",
      ("memory" in first), True)


print("\n[2] the second beat compares against the first, it does not start over")
state2 = dict(state)
lines2 = heartbeat.beat(state2)
check("since start and since last are both there",
      "since start" in lines2[0] and "since last" in lines2[0], True)


print("\n[3] a new thread is NAMED, not just counted")
# A count going from 8 to 9 in a log file at 3am is not information. The
# name is.
ev = threading.Event()
t = threading.Thread(target=ev.wait, name="a-thread-that-leaked", daemon=True)
t.start()
time.sleep(0.05)
lines3 = heartbeat.beat(state2)
named = any("a-thread-that-leaked" in ln for ln in lines3)
check("the new thread is named", named, True)
ev.set()
t.join(timeout=2)
time.sleep(0.05)
lines4 = heartbeat.beat(state2)
check("and so is the one that ended",
      any("a-thread-that-leaked" in ln and "ended" in ln for ln in lines4), True)


print("\n[4] growth gets called a leak out loud, once, not left as arithmetic")
grown = {"started_at": time.time(), "first_rss": 100.0, "last_rss": 100.0,
         "threads": set()}
real_rss = heartbeat._rss_mb
heartbeat._rss_mb = lambda: 400.0
try:
    got = heartbeat.beat(grown)
    said = [ln for ln in got if "leak" in ln]
    check("it uses the word leak", len(said), 1)
    check("it quotes both numbers so the claim can be checked",
          "100.0 MB" in said[0] and "400.0 MB" in said[0], True)
    again = heartbeat.beat(grown)
    check("and it does not say it again every five minutes forever",
          any("leak" in ln for ln in again), False)
finally:
    heartbeat._rss_mb = real_rss


print("\n[5] psutil missing is said plainly, it is not silently no memory line")
missing = {"started_at": time.time()}
heartbeat._rss_mb = lambda: None
try:
    got = heartbeat.beat(missing)
    check("says why there is no number",
          "psutil is not installed" in got[0], True)
finally:
    heartbeat._rss_mb = real_rss


print("\n[6] and there is no helper to report, because this platform has none")
# CONVERTED 2026-09-25, THE WINDOWS-LEFTOVERS ROUND. WHAT THIS SECTION USED TO
# DO AND WHY IT IS NOW THE OTHER WAY ROUND.
#
# It substituted three fake capability shims into core.capabilities through
# `set_instance` -- a dead helper, a live one, and a plain local one -- and
# asserted the heartbeat said HELPER GONE / helper alive / nothing. All three
# were exercising a branch that could not fire on this host: the privileged
# HELPER PROCESS is the Windows design (core/helper_server.py and its client
# live in agental_sec_win32_reference/), and on Linux the rights question is
# answered by capabilities on the binary. `caps.get()` has always returned a
# plain Capabilities(), `getattr(inst, "alive")` was therefore always None, and
# `_helper_note()` returned None on every beat this app has ever made.
#
# So the fake shims were testing the fixtures, not the app. THE PROPERTY IS
# STILL ASSERTED, in the direction that is true here: a beat says nothing about
# a helper, and the shim has no helper to ask about. The loud-dead-thing rule
# lives in tests/test_capability_shim.py (the shim's refusals) and in the
# readiness card's failing-polls branch (RT-4), which is the surface this
# platform actually has.
from core import capabilities as caps
check("the shim is a plain Capabilities, with no helper to be alive or dead",
      hasattr(caps.get(), "alive"), False)
check("and nothing can swap one in behind it",
      hasattr(caps, "set_instance"), False)
got = heartbeat.beat({"started_at": time.time()})
check("a beat says nothing about a helper", "helper" in got[0].lower(), False)


def _code_only(text):
    """
    The source with its line comments stripped.

    THE COMMENT EXPLAINING A REMOVAL NAMES WHAT WAS REMOVED, so a whole-file
    search for "HELPER GONE" finds the paragraph that says the branch is gone
    and calls it a survivor. Same fault as the comment about a banned call
    failing the assertion that the call is not made -- and the same fix the
    capability shim's own file uses.
    """
    out = []
    for line in text.splitlines():
        head = line.split("#", 1)[0]
        if head.strip():
            out.append(head)
    return "\n".join(out)


hb_code = _code_only((ROOT / "core" / "heartbeat.py").read_text(encoding="utf-8"))
check("and the module cannot call one any more",
      "_helper_note" in hb_code or "HELPER GONE" in hb_code, False)
# The stripper has to actually strip, or this goes green for the wrong reason.
check("a commented-out helper call does not count",
      "_helper_note" in _code_only("# _helper_note()"), False)
check("but a real one still would",
      "_helper_note" in _code_only("x = _helper_note()"), True)


print("\n[7] the shutdown endpoint: key required, POST only, and it really calls")
tmp = tempfile.mkdtemp()
db  = pathlib.Path(tmp) / "t.db"

from core import memory_engine as me
me.DB_PATH = db
schema = (ROOT / 'Schema.SQL').read_text(encoding='utf-8')
c = sqlite3.connect(db); c.executescript(schema); c.commit(); c.close()
from core import migrations; migrations.run_migrations(db)
from core import sensors as sn; sn.register_local()

from api.server import create_app, allowed_hosts

API_KEY = "0" * 64
app = create_app({"flask": {"host": "127.0.0.1", "port": 5000}}, {}, "test-session",
                 api_key=API_KEY)
app.config["AGENTAL_ALLOWED_HOSTS"] = allowed_hosts({"flask": {"host": "127.0.0.1"}})
client = app.test_client()
H = {"X-API-Key": API_KEY}

r = client.post("/api/shutdown")
check("no key is 401", r.status_code, 401)
r = client.post("/api/shutdown", headers={"X-API-Key": "wrong"})
check("wrong key is 401", r.status_code, 401)

r = client.get("/api/shutdown", headers=H)
check("GET is refused, so nothing stops the app by prefetching a link",
      r.status_code, 405)

print("\n[8] no hook means an honest refusal, NOT a cheerful 200")
# This is the one that matters. A 200 here would have the page report a
# shutdown that literally nobody is performing, which is the same family as
# every quiet-failure bug in this project.
r = client.post("/api/shutdown", headers=H)
check("status", r.status_code, 501)
check("stopping is false", r.get_json().get("stopping"), False)
check("and it says what to do instead",
      "Ctrl+C" in r.get_json().get("error", ""), True)

print("\n[9] with a hook, it is called, with a reason that names the caller")
called = []
app.config["AGENTAL_SHUTDOWN"] = lambda reason: called.append(reason)
r = client.post("/api/shutdown", headers=H)
check("status", r.status_code, 200)
check("stopping is true", r.get_json().get("stopping"), True)
check("the hook actually ran", len(called), 1)
check("the reason says where it came from", "dashboard" in called[0], True)
check("the answer warns that retention takes a while",
      "minutes" in r.get_json().get("note", ""), True)


print("\n[10] the UI has the button, and it waits for the app to really go")
ui = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check("there is a stop button", "stopApp()" in ui, True)
check("it POSTs, matching the route", "'/api/shutdown', { method: 'POST'" in ui, True)
check("it asks first", "confirm(" in ui, True)
# The fetch returning is not the app being gone. Retention is still running.
# A page that says "stopped" at that moment is lying by about four minutes.
check("it keeps polling until the server stops answering",
      "still shutting down" in ui, True)


print("\n[11] the status check does not send a paid completion")
# 2026-09-08. /api/status ran a REAL chat completion ("ping", max_tokens 5)
# behind a 30 second cache, so an open dashboard tab billed about two calls a
# minute forever. 174 of them on the day it was found. The money was cents.
# The reasons it had to go are that it held one of eight waitress threads for
# up to ten seconds on a health check sharing this process with the sensors
# and the rollup engine, and that it is a paid call nobody asked for, on a
# loop, in an app meant to be handed to other people.
import asyncio                                              # noqa: E402
from core import agent_loop as al                           # noqa: E402

loop_src = (ROOT / "core" / "agent_loop.py").read_text(encoding="utf-8")

# THE ANCHOR IS CHECKED BEFORE IT IS USED, and it is checked because this is
# exactly how this section broke.
#
# It used to be `loop_src.split("async def check_deepseek", 1)[-1]`. TODO 111
# renamed that function to check_provider, so the anchor stopped matching, and
# split with a missing separator RETURNS THE WHOLE STRING WITH NO ERROR. The
# slice then scanned all 89,000 characters of agent_loop.py, which is how
# "and never sends a message body" went red: the word "messages" is obviously
# somewhere in a file that talks to a chat API.
#
# The two checks either side of it still said PASS, and they were meaningless
# too. That is the worse half. A test that cannot find what it is looking at
# must say so, not answer a wider question and call it the same answer. Rule
# two, inside a test, about a rename I did myself.
_ANCHOR = "async def check_provider"
_END = "def untrusted_sources_this_turn"
check("the function this section reads is still called what we think",
      _ANCHOR in loop_src, True)
check("and the section has an end marker", _END in loop_src, True)
after = loop_src.split(_ANCHOR, 1)[-1].split(_END, 1)[0] \
    if (_ANCHOR in loop_src and _END in loop_src) else ""
check("the check no longer posts anything", "client.post" in after, False)
check("it asks for the model list instead", "client.get" in after, True)
check("and never sends a message body", '"messages"' in after, False)
# No check on "max_tokens" here on purpose: the docstring above the function
# quotes the old billed call to explain why it went, so the words are still in
# the file and always will be. Asserting their absence would force somebody to
# delete the explanation to make the test pass, which is backwards.

# Derived from the chat URL, not hardcoded, so a config pointing at another
# OpenAI-shaped endpoint still works.
al._api_url = "https://api.example.com/v1/chat/completions"
check("the models URL is derived from the configured one",
      al._models_url(), "https://api.example.com/v1/models")
al._api_url = "https://example.test/openai/v1/chat/completions"
check("and it follows the config rather than assuming deepseek",
      al._models_url(), "https://example.test/openai/v1/models")


class _Resp:
    def __init__(self, code, body):
        self.status_code = code
        self._body = body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class _Client:
    """Records the call so the test can see it was a GET with no body."""
    seen = {}

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, headers=None, **kw):
        _Client.seen = {"url": url, "headers": headers, "kwargs": kw}
        return _Client.reply

    async def post(self, *a, **kw):
        raise AssertionError("the status check must not POST")


_real_client = al.httpx.AsyncClient
al.httpx.AsyncClient = _Client
_real_key, _real_model = al._api_key, al._model
try:
    al._api_key = "test-key"
    al._model = "model-chat"
    al._api_url = "https://api.example.com/v1/chat/completions"

    _Client.reply = _Resp(200, {"data": [{"id": "model-chat"},
                                         {"id": "model-reasoner"}]})
    out = asyncio.run(al.check_provider())
    check("a healthy answer is connected", out["connected"], True)
    check("with no error", out["error"], None)
    check("it hit the model list", _Client.seen["url"],
          "https://api.example.com/v1/models")
    check("carrying the key", "Bearer test-key",
          _Client.seen["headers"]["Authorization"])
    check("and nothing else, no body of any kind", _Client.seen["kwargs"], {})

    # The third question the ping could never answer.
    al._model = "not-a-real-model"
    out = asyncio.run(al.check_provider())
    check("a model missing from the list is still CONNECTED", out["connected"],
          True)
    check("but it says so", "not in the provider's model list" in
          (out["error"] or ""), True)
    check("and names what is there", "model-reasoner" in (out["error"] or ""),
          True)

    # A stale or paginated list must never black out a working install. That
    # would be this app's own favourite bug, a check answering a narrower
    # question than it appears to.
    al._model = "model-chat"
    _Client.reply = _Resp(200, ValueError("not json"))
    out = asyncio.run(al.check_provider())
    check("a 200 we cannot parse still proves the key and the service",
          out["connected"], True)

    _Client.reply = _Resp(401, {})
    out = asyncio.run(al.check_provider())
    check("a bad key is not connected", out["connected"], False)
    check("and the status code reaches the caller", "401" in (out["error"] or ""),
          True)

    al._api_key = ""
    out = asyncio.run(al.check_provider())
    check("no key at all is answered without a request", out["connected"], False)
finally:
    al.httpx.AsyncClient = _real_client
    al._api_key, al._model = _real_key, _real_model


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
