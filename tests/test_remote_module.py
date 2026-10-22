# tests/test_remote_module.py
# The Remote module end to end: its real process against the app's routes and
# a fake Telegram. Off means no process, pairing needs the person's own number.

import json
import os
import pathlib
import socket
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "modules" / "remote"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from werkzeug.serving import make_server              # noqa: E402

from api.server import create_app                     # noqa: E402
from core import incident, module_host                # noqa: E402
import store as remote_store                          # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(fn, seconds=8.0):
    end = time.time() + seconds
    while time.time() < end:
        got = fn()
        if got:
            return got
        time.sleep(0.1)
    return fn()


print("alert text")
import bot as remote_bot                              # noqa: E402
_b = remote_bot.Bot.__new__(remote_bot.Bot)
check("a raise says raised to",
      "raised to CRITICAL" in _b._alert_text([{"severity": "critical", "raised": True,
                                               "title": "t", "entity_type": "process",
                                               "entity_value": "x"}]), True)

print("phone numbers")
check("local and full number match",
      remote_store.phones_match("07700 900123", "447700900123"), True)
check("plus and 00 prefixes match",
      remote_store.phones_match("+44 7700 900456", "0044 7700 900456"), True)
check("a different number does not",
      remote_store.phones_match("07700 900123", "447700900124"), False)
check("too short to trust a tail match",
      remote_store.phones_match("900123", "447700900123"), False)
check("code cleaning", remote_store.clean_code(" abcd-efgh "), "ABCDEFGH")


# A fake Telegram: getMe, getUpdates with a short wait, sendMessage recorded.
class FakeTelegram:
    def __init__(self):
        self.updates = []
        self.sent = []
        self.next_id = 1
        self.cond = threading.Condition()

    def push(self, message):
        with self.cond:
            self.updates.append({"update_id": self.next_id, "message": message})
            self.next_id += 1
            self.cond.notify_all()

    def to(self, chat_id):
        return [m for m in self.sent if m["chat_id"] == chat_id]


fake = FakeTelegram()


class TgHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        method = self.path.rsplit("/", 1)[-1]
        token_ok = self.path.startswith("/bot123:TESTTOKEN/")
        if not token_ok:
            out = {"ok": False, "error_code": 401, "description": "Unauthorized"}
        elif method == "getMe":
            out = {"ok": True, "result": {"id": 9, "is_bot": True, "username": "test_home_bot"}}
        elif method == "getUpdates":
            offset = body.get("offset") or 0
            with fake.cond:
                fake.cond.wait_for(lambda: any(u["update_id"] >= offset for u in fake.updates),
                                   timeout=0.5)
                got = [u for u in fake.updates if u["update_id"] >= offset]
            out = {"ok": True, "result": got}
        elif method == "sendMessage":
            fake.sent.append(body)
            out = {"ok": True, "result": {"message_id": len(fake.sent)}}
        else:
            out = {"ok": False, "error_code": 404, "description": "Not Found"}
        raw = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        try:
            self.wfile.write(raw)
        except OSError:
            pass


tg_port = free_port()
tg_server = ThreadingHTTPServer(("127.0.0.1", tg_port), TgHandler)
threading.Thread(target=tg_server.serve_forever, daemon=True).start()

# The app's routes on a real port, as the module reaches them.
KEY = "k" * 64
app_port = free_port()
app = create_app({"flask": {"host": "127.0.0.1", "port": app_port}}, {}, "test",
                  api_key=KEY)
app_server = make_server("127.0.0.1", app_port, app, threaded=True)
threading.Thread(target=app_server.serve_forever, daemon=True).start()
client = app.test_client()
H = {"X-API-Key": KEY}

scratch = pathlib.Path(tempfile.mkdtemp(prefix="modhost-"))
module_host.DATA_DIR = scratch / "module_data"
module_host.SWITCHES = module_host.DATA_DIR / "switches.json"
module_host.LOG_DIR = scratch / "logs"
module_host.configure({"flask": {"host": "127.0.0.1", "port": app_port}})
module_host._ENV_PASS = module_host._ENV_PASS + ("AGENTAL_REMOTE_TG_BASE",
                                                 "AGENTAL_REMOTE_ALERT_EVERY")
os.environ["AGENTAL_REMOTE_TG_BASE"] = f"http://127.0.0.1:{tg_port}"
os.environ["AGENTAL_REMOTE_ALERT_EVERY"] = "1"
os.environ.pop("AGENTAL_REMOTE_BOT_TOKEN", None)
# The token goes to .env through settings; a scratch .env here.
from core import settings as st                       # noqa: E402
st.ENV_PATH = scratch / ".env"


def call(path, method="GET", body=None):
    if method == "GET":
        r = client.get(f"/api/module-host/remote/call{path}", headers=H)
    else:
        r = client.post(f"/api/module-host/remote/call{path}", headers=H, json=body or {})
    return r.status_code, r.get_json()


try:
    print("off means off")
    r = client.get("/api/module-host/list", headers=H)
    mods = {m["name"]: m for m in r.get_json()["modules"]}
    check("remote is installed", "remote" in mods, True)
    check("it starts off", mods["remote"]["on"], False)
    check("nothing runs while off", mods["remote"]["running"], False)
    check("its page code is served", client.get("/module-ui/remote/ui.js").status_code, 200)
    check("unknown module page is 404", client.get("/module-ui/nope/ui.js").status_code, 404)
    check("the list needs the key", client.get("/api/module-host/list").status_code, 401)
    check("a call while off says so", call("/state")[0], 503)

    print("switch on")
    r = client.post("/api/module-host/remote/switch", headers=H, json={"on": True})
    check("switch on works", r.status_code, 200)
    check("saved as on", module_host.is_on("remote"), True)
    st_code, state = wait_for(lambda: (lambda c: c if c[0] == 200 else None)(call("/state")))
    check("the module answers", st_code, 200)
    check("no token yet", state["bot"]["token_present"], False)
    pid = module_host._running["remote"]["proc"].pid
    rss = module_host._rss_mb(pid)
    print(f"  note  module memory: {rss} MB")
    check("memory under the 40 MB target", rss is not None and rss < 40, True)

    print("feed needs the module's own token")
    check("no token is refused", client.get("/api/module-feed/status").status_code, 401)
    check("the app key is not a module token",
          client.get("/api/module-feed/status", headers={"X-Module-Token": KEY}).status_code, 401)
    tok = module_host._running["remote"]["token"]
    check("the run's token is accepted",
          client.get("/api/module-feed/status", headers={"X-Module-Token": tok}).status_code, 200)

    print("bot token")
    r = client.post("/api/module-host/remote/secret", headers=H,
                    json={"env": "AGENTAL_API_KEY", "value": "x" * 20})
    check("a key the module does not use is refused", r.status_code, 400)
    r = client.post("/api/module-host/remote/secret", headers=H,
                    json={"env": "AGENTAL_REMOTE_BOT_TOKEN", "value": "123:TESTTOKEN"})
    check("the bot token is saved", r.get_json().get("ok"), True)
    check("the module restarted with it", r.get_json().get("restarted"), True)
    env_text = (scratch / ".env").read_text()
    check("the token is in .env", "AGENTAL_REMOTE_BOT_TOKEN=" in env_text, True)
    child_env = open(f"/proc/{module_host._running['remote']['proc'].pid}/environ", "rb").read()
    check("the module does not get the app key", b"AGENTAL_APP_API_KEY" in child_env, False)
    check("the module does not get the model key", b"AGENTAL_API_KEY=" in child_env, False)
    connected = wait_for(lambda: (lambda c: c[1]["bot"].get("username") if c[0] == 200 else None)(call("/state")))
    check("connected as the bot", connected, "test_home_bot")

    print("pairing")
    code_, out = call("/people/add", "POST", {"name": "Sam", "phone": "07700 900123"})
    check("person added", code_, 200)
    code = out["code"]
    check("code is 8 characters", len(code), 8)
    code_, dup = call("/people/add", "POST", {"name": "Twin", "phone": "+44 7700 900123"})
    check("same number twice is refused", code_, 400)

    sam = {"id": 111, "is_bot": False, "first_name": "Sam"}
    chat = {"id": 111, "type": "private"}
    fake.push({"message_id": 1, "from": sam, "chat": chat, "text": f"/start {code.lower()}"})
    got = wait_for(lambda: fake.to(111))
    check("the bot asks for the number", bool(got) and "share your phone number" in got[-1]["text"], True)
    check("with the contact button",
          got[-1].get("reply_markup", {}).get("keyboard", [[{}]])[0][0].get("request_contact"), True)

    fake.push({"message_id": 2, "from": sam, "chat": chat,
               "contact": {"user_id": 999, "phone_number": "447700900123"}})
    time.sleep(1.5)
    check("someone else's contact is refused",
          "someone else's contact" in fake.to(111)[-1]["text"], True)

    fake.push({"message_id": 3, "from": sam, "chat": chat,
               "contact": {"user_id": 111, "phone_number": "447700900123"}})
    paired = wait_for(lambda: [p for p in call("/state")[1]["people"] if p["state"] == "paired"])
    check("Sam is paired", [p["name"] for p in paired], ["Sam"])
    told = wait_for(lambda: [m for m in fake.to(111) if "Two-Step Verification" in m["text"]])
    check("told about Two-Step Verification", bool(told), True)

    print("strangers")
    before = len(fake.sent)
    eve = {"id": 222, "is_bot": False, "first_name": "Eve", "username": "eve"}
    fake.push({"message_id": 4, "from": eve, "chat": {"id": 222, "type": "private"},
               "text": "/status"})
    fake.push({"message_id": 5, "from": eve, "chat": {"id": 222, "type": "private"},
               "text": "ZZZZZZZZ"})
    time.sleep(1.5)
    check("a stranger gets no answer", len(fake.to(222)), 0)
    events = call("/events")[1]["events"]
    check("the stranger is in the history", any(e["kind"] == "stranger" and "@eve" in (e["person"] or "")
                                                for e in events), True)
    check("the wrong code is in the history", any(e["kind"] == "code_refused" for e in events), True)
    check("nothing else was sent", len(fake.sent), before)

    print("wrong number")
    _, out2 = call("/people/add", "POST", {"name": "Kim", "phone": "07700 900789"})
    kim = {"id": 333, "is_bot": False, "first_name": "Kim"}
    kchat = {"id": 333, "type": "private"}
    fake.push({"message_id": 6, "from": kim, "chat": kchat, "text": out2["code"]})
    wait_for(lambda: fake.to(333))
    fake.push({"message_id": 7, "from": kim, "chat": kchat,
               "contact": {"user_id": 333, "phone_number": "447700900999"}})
    wait_for(lambda: len(fake.to(333)) >= 2)
    check("a different number stops pairing", "does not match" in fake.to(333)[-1]["text"], True)
    people = {p["name"]: p for p in call("/state")[1]["people"]}
    check("Kim stays unpaired", people["Kim"]["state"], "waiting")
    check("and the code is spent", people["Kim"]["code_live"], False)

    print("commands")
    fake.push({"message_id": 8, "from": sam, "chat": chat, "text": "/status"})
    wait_for(lambda: "Open incidents" in fake.to(111)[-1]["text"])
    check("/status answers", "Open incidents" in fake.to(111)[-1]["text"], True)
    fake.push({"message_id": 9, "from": sam, "chat": chat, "text": "/pending"})
    wait_for(lambda: "decision" in fake.to(111)[-1]["text"])
    check("/pending answers", "decision" in fake.to(111)[-1]["text"], True)

    print("alerts")
    incident._config_cache = {"incident_watcher": {"notify": True}}
    n_before = len(fake.to(111))
    incident.write_incident("PRC-1002", "process", "evil", "medium", "Medium thing")
    incident.write_incident("PRC-1001", "process", "other", "medium", "Other medium")
    time.sleep(2.5)
    check("medium stays quiet at the high floor", len(fake.to(111)), n_before)
    incident.write_incident("LNX-1011", "process", "worse", "high", "High thing happened")
    got = wait_for(lambda: [m for m in fake.to(111) if "High thing happened" in m["text"]])
    check("a new high incident reaches Sam", bool(got), True)
    check("it says new and HIGH", bool(got) and "new, HIGH" in got[0]["text"], True)
    n_before = len(fake.to(111))
    incident.write_incident("PRC-1001", "process", "other", "high", "Other medium")
    waiting = wait_for(lambda: call("/state")[1]["alerts"]["waiting"])
    check("a second high within the gap waits to be grouped", waiting, 1)
    check("and is not sent yet", len(fake.to(111)), n_before)
    incident.write_incident("PRC-1002", "process", "evil", "critical", "Medium thing")
    got = wait_for(lambda: [m for m in fake.to(111) if "2 urgent incidents" in m["text"]])
    check("critical does not wait for the gap", bool(got), True)
    check("and takes the waiting one along",
          bool(got) and "Other medium" in got[0]["text"] and "CRITICAL" in got[0]["text"], True)
    check("Kim, not paired, got no alert",
          any("urgent" in m["text"] for m in fake.to(333)), False)

    print("revoke")
    code_, out = call("/revoke", "POST")
    check("revoke works", out.get("removed"), 2)
    check("Sam is told", "revoked" in fake.to(111)[-1]["text"], True)
    check("nobody is left", call("/state")[1]["people"], [])

    print("switch off")
    proc = module_host._running["remote"]["proc"]
    r = client.post("/api/module-host/remote/switch", headers=H, json={"on": False})
    check("switch off works", r.status_code, 200)
    check("the process is gone", proc.poll() is not None, True)
    check("nothing is left running", "remote" in module_host._running, False)
    check("the socket is removed", module_host.socket_path("remote").exists(), False)
    check("saved as off", module_host.is_on("remote"), False)
    check("its token no longer works",
          client.get("/api/module-feed/status", headers={"X-Module-Token": tok}).status_code, 401)

    print("the app going away")
    module_host.start("remote")
    proc = module_host._running["remote"]["proc"]
    proc.stdin.close()
    proc.wait(6)
    check("closing stdin stops the module", proc.returncode, 0)
    module_host._running.pop("remote", None)
finally:
    module_host.stop_all()
    app_server.shutdown()
    tg_server.shutdown()

print()
if fails:
    print(f"FAILED: {len(fails)}")
    for f in fails:
        print(f"  {f}")
    sys.exit(1)
print("ALL PASSED")
