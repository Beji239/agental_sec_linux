# tests/test_stop_state.py
# While the app shuts down, /api/status says so, and the page greys what it
# shows instead of leaving the last answer on screen; once the app stops
# answering the page says it is not running, and nothing stays green.

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from api.server import create_app                     # noqa: E402
from core import agent_loop                           # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


KEY = "k" * 64
app = create_app({"flask": {"host": "127.0.0.1", "port": 5091}}, {}, "test", api_key=KEY)
client = app.test_client()
H = {"X-API-Key": KEY}

print("the status says when the app is shutting down")
agent_loop._shutting_down = False
check("running", client.get("/api/status", headers=H).get_json().get("shutting_down"), False)
agent_loop._shutting_down = True
check("shutting down", client.get("/api/status", headers=H).get_json().get("shutting_down"), True)
agent_loop._shutting_down = False

print("the page has the stopping and stopped states")
page = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check("a status request has a time limit", "signal: ctl.signal" in page and "STATUS_WAIT_MS" in page, True)
check("two misses mean not answering", "APP.fails >= 2" in page, True)
check("a refused sign-in still counts as an answer", "if (!r.ok) { appAnswered(false); return; }" in page, True)
check("the shutting-down flag is read", "appAnswered(!!d.shutting_down)" in page, True)
check("PROTECTED gives way", "'NOT RUNNING' : 'STOPPING'" in page, True)
check("the pills and sensor views are greyed", "body.app-down #status-pills .pill" in page
      and "body.app-down #hl-hero" in page and "body.app-down #settings-readiness" in page, True)
check("the page reloads once the app is back", "if (APP.state !== 'up') location.reload();" in page, True)

print()
if fails:
    print(f"FAILED: {len(fails)}")
    for f in fails:
        print(f"  {f}")
    sys.exit(1)
print("ALL PASSED")
