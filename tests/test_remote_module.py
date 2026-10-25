# tests/test_remote_module.py
# The Remote module end to end: its real process against the app's routes and
# a fake Telegram. Off means no process, pairing needs the person's own number,
# deciding and chatting need the PIN and an authenticator code, private
# messages open only with the phone's key.

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
from core import actions, device_hold, incident, module_feed, module_host, questions  # noqa: E402
from core import memory_engine as me                  # noqa: E402
import control as remote_control                      # noqa: E402
import qr as remote_qr                                # noqa: E402
import reader as remote_reader                        # noqa: E402
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
      "Raised to CRITICAL" in _b._alert_text([{"severity": "critical", "raised": True,
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

print("control helpers")
_rfc = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
check("authenticator code matches RFC 6238", remote_control.totp(_rfc, 1111111109 // 30), "081804")
check("a code is accepted once", remote_control.code_step(_rfc, "287082", 0, now=59), 1)
check("and not again", remote_control.code_step(_rfc, "287082", 1, now=59), None)
check("an easy PIN is refused", bool(remote_control.pin_problem("123456")), True)
check("a short PIN is refused", bool(remote_control.pin_problem("4802")), True)
check("a digits-only panic word is refused", bool(remote_control.word_problem("123456")), True)
_h = remote_control.hash_word("Red Balloon")
check("the panic word ignores case and spaces", remote_control.word_ok("  red   balloon ", _h), True)
check("QR codes grow with the text", (len(remote_qr.matrix("hi")), len(remote_qr.matrix("x" * 100))),
      (21, 41))

print("private messages")
_k = remote_reader.new_key()
_blob = remote_reader.seal(_k, "Title", "Body \u00e9 " * 200, "alert", now=1000)
check("a sealed message opens with its key",
      remote_reader.open_sealed(_k, _blob), {"v": 1, "k": "alert", "t": "Title",
                                             "b": "Body \u00e9 " * 200, "at": 1000})
check("long text is packed small", len(_blob) < 400, True)
try:
    remote_reader.open_sealed(remote_reader.new_key(), _blob)
    check("another key cannot open it", "opened", "refused")
except Exception:
    check("another key cannot open it", "refused", "refused")
_raw = bytearray(remote_reader._unb64(_blob))
_raw[2] ^= 1
try:
    remote_reader.open_sealed(_k, remote_reader._b64(bytes(_raw)))
    check("a changed header is refused", "opened", "refused")
except Exception:
    check("a changed header is refused", "refused", "refused")
check("the check code is six characters", len(remote_reader.check_code(_k)), 6)
check("an http reader page is refused", bool(remote_reader.url_problem("http://example.org/r/")), True)
check("an https one is fine", remote_reader.url_problem("https://example.org/r/"), None)
check("the page files come with the module", all(remote_reader.page_hashes().values()), True)

# The real reader page in node, with a fake Telegram bridge and a fake page.
_harness = r"""
const fs = require('fs'), vm = require('vm');
const [src, url, keyB64, qrText] = process.argv.slice(2);
const els = {};
const el = id => els[id] || (els[id] = { id, hidden: true, textContent: '', className: '', onclick: null });
const store = {};
const out = { posts: [] };
let ctx;
function reply(type, data) { setTimeout(() => ctx.window.Telegram.WebView.receiveEvent(type, data), 0); }
const proxy = { postEvent(name, json) {
  const p = JSON.parse(json); out.posts.push(name);
  if (name === 'web_app_secure_storage_get_key') reply('secure_storage_key_received', { req_id: p.req_id, value: store[p.key] || null });
  if (name === 'web_app_secure_storage_save_key') { store[p.key] = p.value; reply('secure_storage_key_saved', { req_id: p.req_id }); }
  if (name === 'web_app_open_scan_qr_popup') reply('qr_text_received', { data: qrText });
} };
if (keyB64) store.agentalsec_reader_key = keyB64;
const u = new URL(url);
const window = { TelegramWebviewProxy: proxy, addEventListener() {}, parent: { postMessage() {} } };
ctx = { window, document: { getElementById: el, documentElement: { style: { setProperty() {} } } },
        location: { hash: u.hash, search: u.search }, crypto: globalThis.crypto, TextEncoder, TextDecoder,
        URLSearchParams, Blob, Response, DecompressionStream, atob, btoa, setTimeout, clearTimeout,
        Uint8Array, Date, JSON, Math, Number, String, Object, Error, Promise };
window.window = window;
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(src, 'utf8'), ctx);
setTimeout(() => { if (el('scan').onclick) el('scan').onclick(); }, 50);
setTimeout(() => {
  out.note = el('note').textContent; out.title = el('msg-title').textContent;
  out.body = el('msg-body').textContent; out.check = el('check').textContent;
  out.saved = store.agentalsec_reader_key || null;
  console.log(JSON.stringify(out));
}, 400);
"""
import shutil as _shutil, subprocess as _sp      # noqa: E402
if _shutil.which("node"):
    _hfile = pathlib.Path(tempfile.mkdtemp(prefix="reader-")) / "harness.js"
    _hfile.write_text(_harness)
    _page = str(ROOT / "modules" / "remote" / "reader" / "reader.js")
    _base = "https://example.org/reader/"
    _tg = "#tgWebAppVersion=9.1&tgWebAppPlatform=android"

    def _run_page(url, key=b"", qr=""):
        got = _sp.run(["node", str(_hfile), _page, url,
                       remote_reader._b64(key) if key else "", qr],
                      capture_output=True, text=True, timeout=30)
        try:
            return json.loads(got.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            print(got.stderr[-800:])
            return {}

    _sealed = remote_reader.seal(_k, "HIGH: new incident", "Line one <b>\nLine two & more", "alert")
    page = _run_page(remote_reader.link(_base, _sealed) + _tg, _k)
    check("the page opens a sealed message", (page.get("title"), page.get("body")),
          ("HIGH: new incident", "Line one <b>\nLine two & more"))
    check("it tells the phone it is ready", "web_app_ready" in page.get("posts", []), True)
    page = _run_page(remote_reader.link(_base, _sealed) + _tg, remote_reader.new_key())
    check("with another key it says so", "different key" in page.get("note", ""), True)
    page = _run_page(remote_reader.link(_base, _sealed) + "#tgWebAppVersion=7.0", _k)
    check("an old Telegram is told to update", "too old" in page.get("note", ""), True)
    page = _run_page(remote_reader.enrol_link(_base) + _tg, b"", remote_reader.qr_text(_k))
    check("scanning the key saves it in secure storage", page.get("saved"), remote_reader._b64(_k))
    check("and shows the check code", page.get("check"), remote_reader.check_code(_k))
else:
    print("  SKIP  node is not installed, the reader page was not run")

print("an older database gets the control columns")
_old = pathlib.Path(tempfile.mkdtemp(prefix="remote-old-")) / "remote.db"
import sqlite3                                        # noqa: E402
_c = sqlite3.connect(_old)
_c.execute("CREATE TABLE people (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, "
           "phone TEXT NOT NULL, phone_digits TEXT NOT NULL, state TEXT NOT NULL, code_hash TEXT, "
           "code_expires REAL, pairing_user_id INTEGER, pairing_until REAL, tg_user_id INTEGER UNIQUE, "
           "chat_id INTEGER, tg_username TEXT, created_at REAL NOT NULL, paired_at REAL)")
_c.execute("INSERT INTO people (name, phone, phone_digits, state, created_at) "
           "VALUES ('Old', '1', '1', 'paired', 0)")
_c.commit()
_c.close()
_s = remote_store.Store(_old)
check("old rows survive with control off", [(p["name"], p["enrolled"]) for p in _s.people()],
      [("Old", False)])


# A fake Telegram: getMe, getUpdates with a short wait, sendMessage recorded.
class FakeTelegram:
    def __init__(self):
        self.updates = []
        self.sent = []
        self.calls = []
        self.next_id = 1
        self.cond = threading.Condition()

    def push(self, message, kind="message"):
        with self.cond:
            self.updates.append({"update_id": self.next_id, kind: message})
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
        elif method in ("setMyCommands", "setMyDescription", "setMyShortDescription",
                        "answerCallbackQuery", "deleteMessage", "sendChatAction"):
            fake.calls.append((method, body))
            out = {"ok": True, "result": True}
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
    wait_for(lambda: any(c[0] == "setMyCommands" for c in fake.calls))
    menu = [c[1] for c in fake.calls if c[0] == "setMyCommands"]
    check("the command menu is set",
          bool(menu) and [m["command"] for m in menu[-1]["commands"]],
          ["status", "pending", "control", "done", "check", "new", "help"])
    check("the description is set", any(c[0] == "setMyDescription" for c in fake.calls), True)

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
    wait_for(lambda: [m for m in fake.to(111) if "Tap a button" in m["text"]])

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
    check("answers carry the view buttons",
          [b["callback_data"] for b in fake.to(111)[-1]["reply_markup"]["inline_keyboard"][0]],
          ["status", "pending"])
    check("every message is HTML", all(m.get("parse_mode") == "HTML" for m in fake.sent), True)

    print("buttons")
    n_before = len(fake.to(111))
    fake.push({"id": "q1", "from": sam, "data": "status",
               "message": {"message_id": 5, "chat": chat}}, kind="callback_query")
    wait_for(lambda: len(fake.to(111)) > n_before)
    check("the Status button answers", "Open incidents" in fake.to(111)[-1]["text"], True)
    check("the press is acknowledged",
          any(c[0] == "answerCallbackQuery" and c[1]["callback_query_id"] == "q1"
              for c in fake.calls), True)
    fake.push({"id": "q2", "from": eve, "data": "status",
               "message": {"message_id": 6, "chat": {"id": 222, "type": "private"}}},
              kind="callback_query")
    time.sleep(1.5)
    check("a stranger's press gets nothing", len(fake.to(222)), 0)

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
    check("it says new and HIGH", bool(got) and "HIGH: new incident" in got[0]["text"], True)
    n_before = len(fake.to(111))
    incident.write_incident("PRC-1001", "process", "other", "high", "Other medium")
    waiting = wait_for(lambda: call("/state")[1]["alerts"]["waiting"])
    check("a second high within the gap waits to be grouped", waiting, 1)
    check("and is not sent yet", len(fake.to(111)), n_before)
    incident.write_incident("PRC-1002", "process", "evil", "critical", "Medium thing")
    got = wait_for(lambda: [m for m in fake.to(111) if "2 urgent incidents" in m["text"]])
    check("critical does not wait for the gap", bool(got), True)
    check("and takes the waiting one along",
          bool(got) and "Other medium" in got[0]["text"] and "\U0001F534" in got[0]["text"], True)
    incident.write_incident("PRC-1002", "process", "<b>x</b> & y", "critical", "Title <i>with</i> tags & more")
    got = wait_for(lambda: [m for m in fake.to(111) if "with" in m["text"] and "tags" in m["text"]], 15)
    check("outside text is escaped, never markup",
          bool(got) and "Title &lt;i&gt;with&lt;/i&gt; tags &amp; more" in got[0]["text"]
          and "&lt;b&gt;x&lt;/b&gt; &amp; y" in got[0]["text"], True)
    check("Kim, not paired, got no alert",
          any("incident" in m["text"] for m in fake.to(333)), False)

    print("control: setup at the computer")
    sam_id = next(p["id"] for p in call("/state")[1]["people"] if p["name"] == "Sam")
    kim_id = next(p["id"] for p in call("/state")[1]["people"] if p["name"] == "Kim")
    msg_id = [100]

    def say_as(person, text):
        msg_id[0] += 1
        fake.push({"message_id": msg_id[0], "from": person, "chat": chat, "text": text})
        return msg_id[0]

    def press(person, data):
        msg_id[0] += 1
        fake.push({"id": f"c{msg_id[0]}", "from": person, "data": data,
                   "message": {"message_id": msg_id[0], "chat": chat}}, kind="callback_query")

    def next_to_sam(after, needle, seconds=8):
        got = wait_for(lambda: [m for m in fake.to(111)[after:] if needle in m["text"]], seconds)
        return got[0] if got else None

    n = len(fake.to(111))
    say_as(sam, "/control")
    check("control before setup explains how", bool(next_to_sam(n, "set up at the computer")), True)

    code_, out = call("/control/enrol", "POST", {"id": kim_id, "pin": "480215", "pin2": "480215",
                                                 "word": "red balloon"})
    check("someone not paired cannot get control", code_, 400)
    code_, out = call("/control/enrol", "POST", {"id": sam_id, "pin": "123456", "pin2": "123456",
                                                 "word": "red balloon"})
    check("an easy PIN is refused at setup", code_, 400)
    code_, out = call("/control/enrol", "POST", {"id": sam_id, "pin": "480215", "pin2": "480216",
                                                 "word": "red balloon"})
    check("two different PINs are refused", code_, 400)
    code_, out = call("/control/enrol", "POST", {"id": sam_id, "pin": "480215", "pin2": "480215",
                                                 "word": "Red Balloon"})
    check("setup starts", code_, 200)
    secret = out["key"].replace(" ", "")
    check("the key is shown for typing", len(secret), 32)
    check("with a QR picture", out["svg"].startswith("<svg"), True)
    check("not enrolled before the first code",
          next(p for p in call("/state")[1]["people"] if p["id"] == sam_id)["enrolled"], False)

    # Codes from three steps in a row, all inside the allowed drift: setup,
    # the session, and the second ask. Start early in a step so none runs out.
    if time.time() % 30 > 12:
        time.sleep(30 - time.time() % 30 + 0.5)
    step0 = int(time.time() // 30)
    code_, out = call("/control/confirm", "POST", {"id": sam_id, "code": "000000"})
    check("a wrong first code is refused", code_, 400)
    n = len(fake.to(111))
    code_, out = call("/control/confirm", "POST",
                      {"id": sam_id, "code": remote_control.totp(secret, step0 - 1)})
    check("the first code finishes setup", code_, 200)
    sam_row = next(p for p in call("/state")[1]["people"] if p["id"] == sam_id)
    check("Sam can take control", sam_row["enrolled"], True)
    check("the tab never sees the PIN hash or secret",
          any(k in sam_row for k in ("pin_hash", "word_hash", "totp_sealed", "totp_pending")), False)
    check("Sam is told it is set up", bool(next_to_sam(n, "Control from the phone is set up")), True)
    db_text = (module_host.DATA_DIR / "remote" / "remote.db").read_bytes()
    check("the secret is not stored in plain", secret.encode() in db_text, False)
    check("nor the PIN", b"480215" in db_text, False)

    print("control: the app's side")
    a1 = actions.write_request("block_device", {"ip": "203.0.113.9"}, "Seen scanning")["request_id"]
    a2 = actions.write_request("block_port", {"port": 4444, "direction": "inbound"},
                               "Reverse shell port")["request_id"]
    q1 = questions.file_question("test", "identify_device", "ip", "192.0.2.77",
                                 "Is 192.0.2.77 your printer?")["question_id"]
    with me._get_conn() as conn:
        device_hold.ensure_tables(conn)
        conn.execute("INSERT INTO device_hold (mac, ip, vendor, held_at, status) VALUES "
                     "('00:00:5e:00:53:01', '192.0.2.50', 'Acme', '2026-10-23T10:00:00', 'held')")
    lifted = []

    class FakeGateway:
        def unblock_mac(self, mac, reason=None, ip=None):
            lifted.append(mac)
            return {"success": True}
    device_hold._gateway = lambda: FakeGateway()
    module_feed.ASK_AGAIN = frozenset({"block_port"})
    incident.write_incident("LNX-1011", "process", "verdict-me", "high", "Something to judge")
    from core import expectations
    with me._get_conn() as conn:
        expectations.ensure_tables(conn)

    check("the feed's decide needs a token",
          client.post("/api/module-feed/decide", json={"kind": "verdict"}).status_code, 401)
    tok = module_host._running["remote"]["token"]
    check("a kind the manifest does not list is refused",
          client.post("/api/module-feed/decide", headers={"X-Module-Token": tok},
                      json={"kind": "delete_everything", "ref": 1, "choice": "x",
                            "person": "x"}).status_code, 403)

    print("control: take control from the phone")
    n = len(fake.to(111))
    press(sam, "pending")
    m = next_to_sam(n, "Waiting for your decision")
    check("outside a session the list offers Decide now",
          bool(m) and m["reply_markup"]["inline_keyboard"][0][0]["callback_data"], "ctl")

    n = len(fake.to(111))
    press(sam, f"a:{a1}:y")
    check("a decision button outside a session asks for the PIN", bool(next_to_sam(n, "Send your <b>PIN</b>")), True)
    deleted_before = sum(1 for c in fake.calls if c[0] == "deleteMessage")
    n = len(fake.to(111))
    bad = say_as(sam, "999999")
    check("a wrong PIN says how many tries are left", bool(next_to_sam(n, "2 tries left")), True)
    check("and the PIN is deleted from the chat",
          any(c[0] == "deleteMessage" and c[1]["message_id"] == bad for c in fake.calls), True)
    n = len(fake.to(111))
    say_as(sam, "480215")
    check("the right PIN asks for the code", bool(next_to_sam(n, "6-digit code")), True)
    n = len(fake.to(111))
    say_as(sam, remote_control.totp(secret, step0 - 1))
    check("the code used at setup does not work again", bool(next_to_sam(n, "already used")), True)
    n = len(fake.to(111))
    say_as(sam, remote_control.totp(secret, step0))
    check("a fresh code opens control", bool(next_to_sam(n, "Control is on")), True)
    check("then each waiting item comes with buttons",
          bool(wait_for(lambda: [m for m in fake.to(111)[n:] if f"Action #{a1}" in m["text"]])), True)
    check("the PIN and codes were all deleted",
          sum(1 for c in fake.calls if c[0] == "deleteMessage") - deleted_before, 4)

    print("control: deciding")
    n = len(fake.to(111))
    press(sam, f"a:{a1}:y")
    check("approve reaches the app", bool(next_to_sam(n, f"Approved action #{a1}")), True)
    row = actions.query_requests(request_id=a1, limit=1)[0]
    check("the request is approved", row["state"], "approved")
    check("by a person, noted as from the phone",
          (row["decided_by"], row["decision_note"]), ("user", "From the phone by Sam."))
    n = len(fake.to(111))
    press(sam, f"a:{a1}:y")
    check("deciding twice says it is gone", bool(next_to_sam(n, "already decided")), True)

    n = len(fake.to(111))
    press(sam, f"q:{q1}:t")
    check("Type an answer waits for text", bool(next_to_sam(n, "Type your answer")), True)
    n = len(fake.to(111))
    say_as(sam, "Yes, the office printer")
    check("the typed answer is filed", bool(next_to_sam(n, f"Answered question #{q1}")), True)
    check("the question is answered",
          [q["state"] for q in questions.query_questions() if q["id"] == q1], ["answered"])

    n = len(fake.to(111))
    press(sam, "r:00:00:5e:00:53:01")
    check("Let it in releases the device", bool(next_to_sam(n, "Let in Acme")), True)
    check("through the router", lifted, ["00:00:5e:00:53:01"])
    with me._get_readonly_conn() as conn:
        rel = conn.execute("SELECT status, released_by FROM device_hold").fetchone()
    check("recorded with who", tuple(rel), ("released", "phone: Sam"))

    with me._get_readonly_conn() as conn:
        inc_id = conn.execute("SELECT id FROM incident WHERE entity_value = 'verdict-me'").fetchone()[0]
    n = len(fake.to(111))
    press(sam, f"v:{inc_id}:fa")
    check("a verdict from the alert's button", bool(next_to_sam(n, f"Incident #{inc_id}: false alarm")), True)
    with me._get_readonly_conn() as conn:
        v = conn.execute("SELECT verdict, verdict_note FROM incident WHERE id = ?", (inc_id,)).fetchone()
    check("the incident has the verdict", tuple(v), ("false_alarm", "From the phone by Sam."))

    print("control: what cannot be undone asks again")
    n = len(fake.to(111))
    press(sam, f"a:{a2}:y")
    check("it says it cannot be undone", bool(next_to_sam(n, "cannot be undone")), True)
    check("and asks for the PIN even in a session", bool(next_to_sam(n, "Send your <b>PIN</b>")), True)
    check("nothing decided yet", actions.query_requests(request_id=a2, limit=1)[0]["state"], "pending")
    n = len(fake.to(111))
    say_as(sam, "480215")
    next_to_sam(n, "6-digit code")
    n = len(fake.to(111))
    say_as(sam, remote_control.totp(secret, step0 + 1))
    check("PIN and a fresh code approve it", bool(next_to_sam(n, f"Approved action #{a2}")), True)
    check("the app has it approved", actions.query_requests(request_id=a2, limit=1)[0]["state"], "approved")

    print("control: history says who")
    events = call("/events")[1]["events"]
    decisions = [e for e in events if e["kind"] == "decision"]
    check("every phone decision is in the history", len(decisions), 5)
    check("each with who made it", {e["person"] for e in decisions}, {"Sam"})

    print("chat with the agent")
    from core import agent_loop
    asked = []
    reply = {"answers": ["All **quiet**. <none> & `ok`"], "tool_calls": ["query_sensor_health"],
             "usage": {"total_tokens": 1200, "estimated": False}, "error": None}

    def fake_turn(instruction, session_id, allowlist=None, extra_system="",
                  max_rounds=None, history=None):
        asked.append({"text": instruction, "allow": allowlist, "system": extra_system,
                      "rounds": max_rounds, "history": list(history or [])})
        return dict(reply)
    real_turn = agent_loop.run_unattended
    agent_loop.run_unattended = fake_turn

    n = len(fake.to(111))
    say_as(sam, "how are things at home?")
    check("chat starts off", bool(next_to_sam(n, "Chat with the agent is off")), True)
    check("and nothing reached the agent", asked, [])
    check("a silly allowance is refused",
          call("/settings", "POST", {"chat_on": True, "chat_limit": 10})[0], 400)
    check("chat turned on in the tab",
          call("/settings", "POST", {"chat_on": True, "chat_limit": 5000})[0], 200)
    check("the module may chat", module_host.may_chat("remote"), True)
    check("the chat feed needs a token",
          client.post("/api/module-feed/chat", json={"person": "x", "text": "y"}).status_code, 401)

    n = len(fake.to(111))
    say_as(sam, "how are things at home?")
    m = next_to_sam(n, "quiet")
    check("the agent's answer comes back", bool(m), True)
    check("its bold and code are kept, the rest escaped",
          bool(m) and "<b>quiet</b>" in m["text"] and "&lt;none&gt; &amp; <code>ok</code>" in m["text"], True)
    check("with the tokens it used", bool(m) and "1,200 tokens; 1,200 of 5,000 used today" in m["text"], True)
    check("the question reached the agent", asked and asked[0]["text"], "how are things at home?")
    check("read tools only, plus filing a request",
          bool(asked) and "file_action_request" in asked[0]["allow"]
          and not {"learn_quiet_rule", "undo_learned_rule", "ask_operator", "kill_process"}
          & set(asked[0]["allow"]), True)
    check("the agent is told who asks and that it is a phone",
          bool(asked) and "Sam" in asked[0]["system"] and "PHONE" in asked[0]["system"], True)
    check("a few rounds only", bool(asked) and asked[0]["rounds"], 6)
    check("the first question has no history", bool(asked) and asked[0]["history"], [])

    n = len(fake.to(111))
    say_as(sam, "and the router?")
    next_to_sam(n, "quiet")
    check("the next one carries the conversation",
          [h["role"] for h in asked[-1]["history"]], ["user", "assistant"])

    n, before = len(fake.to(111)), len(asked)
    pin_msg = say_as(sam, "480 215")
    check("digits alone never reach the agent", bool(next_to_sam(n, "looked like a PIN")), True)
    check("and are deleted",
          any(c[0] == "deleteMessage" and c[1]["message_id"] == pin_msg for c in fake.calls), True)
    check("nothing asked", len(asked), before)

    n = len(fake.to(111))
    press(sam, "checks")
    m = next_to_sam(n, "Checks")
    check("Checks offers ready-made questions",
          bool(m) and m["reply_markup"]["inline_keyboard"][0][0]["callback_data"], "k:sensors")
    reply["tool_calls"] = ["query_incidents", "file_action_request"]
    n = len(fake.to(111))
    press(sam, "k:sensors")
    check("a check says what it checks", bool(next_to_sam(n, "Checking: <b>Sensors</b>")), True)
    m = next_to_sam(n, "filed a request")
    check("a filed request is pointed out", bool(m), True)
    check("the check's question went to the agent", "sensors running" in asked[-1]["text"], True)
    check("the tab counts the tokens", call("/state")[1]["chat"]["used_today"], 3600)

    for q in ("one more?", "and one more?"):
        n = len(fake.to(111))
        say_as(sam, q)
        next_to_sam(n, "quiet")
    n = len(fake.to(111))
    say_as(sam, "and another?")
    check("over the allowance chat stops for the day", bool(next_to_sam(n, "allowance of 5,000 tokens is used up")), True)
    call("/settings", "POST", {"chat_limit": 100000})
    n = len(fake.to(111))
    say_as(sam, "/new")
    check("/new starts fresh", bool(next_to_sam(n, "Fresh chat")), True)
    n = len(fake.to(111))
    say_as(sam, "fresh question")
    next_to_sam(n, "quiet")
    check("without the earlier messages", asked[-1]["history"], [])

    reply.update(answers=[], usage={"total_tokens": 300}, error="no API key is configured")
    n = len(fake.to(111))
    say_as(sam, "will this work?")
    check("a failed turn says why", bool(next_to_sam(n, "could not answer: no API key")), True)
    events = call("/events")[1]["events"]
    check("chats are in the history with who asked",
          {e["person"] for e in events if e["kind"] == "chat"}, {"Sam"})
    check("and the failed one too", any(e["kind"] == "chat_failed" for e in events), True)
    reply.update(answers=["All **quiet**."], usage={"total_tokens": 100}, error=None)

    print("private messages: setup")
    check("an http reader page is refused in the tab",
          call("/reader/url", "POST", {"url": "http://example.org/r/"})[0], 400)
    check("a page of your own can be set",
          call("/reader/url", "POST", {"url": "https://example.org/r/"})[1].get("url"),
          "https://example.org/r/")
    check("empty goes back to the default", call("/reader/url", "POST", {"url": ""})[1]["url"],
          remote_reader.DEFAULT_URL)
    check("someone not paired cannot get it", call("/private/start", "POST", {"id": kim_id})[0], 400)
    n = len(fake.to(111))
    code_, out = call("/private/start", "POST", {"id": sam_id})
    check("setup starts with a QR picture", (code_, out["svg"].startswith("<svg")), (200, True))
    m = next_to_sam(n, "Private messages")
    check("Sam gets the reader to scan with",
          bool(m) and m["reply_markup"]["inline_keyboard"][0][0]["web_app"]["url"],
          remote_reader.enrol_link(remote_reader.DEFAULT_URL))
    box = remote_control.SecretBox(module_host.DATA_DIR / "remote")
    pend = sqlite3.connect(module_host.DATA_DIR / "remote" / "remote.db").execute(
        "SELECT reader_pending FROM people WHERE id = ?", (sam_id,)).fetchone()[0]
    pkey = remote_reader._unb64(box.open(pend))
    check("the key is not stored in plain",
          remote_reader._b64(pkey).encode() in (module_host.DATA_DIR / "remote" / "remote.db").read_bytes(),
          False)
    check("a wrong check code is refused", call("/private/confirm", "POST", {"id": sam_id, "code": "AAAAAA"})[0], 400)
    n = len(fake.to(111))
    check("the phone's check code finishes it",
          call("/private/confirm", "POST", {"id": sam_id,
                                            "code": remote_reader.check_code(pkey).lower()})[0], 200)
    check("the tab shows it", next(p for p in call("/state")[1]["people"] if p["id"] == sam_id)["private"], True)

    def opened(msg):
        url = msg["reply_markup"]["inline_keyboard"][0][0]["web_app"]["url"]
        return remote_reader.open_sealed(pkey, url.split("?m=", 1)[1])

    m = next_to_sam(n, "Private messages are on")
    check("the first sealed message opens with the phone's key",
          bool(m) and "Private messages work" in opened(m)["b"], True)

    print("private messages: sealed")
    n = len(fake.to(111))
    press(sam, "status")
    m = next_to_sam(n, "<b>Status</b>")
    check("status comes sealed, nothing of it in the clear",
          bool(m) and m["text"].startswith("\U0001F512") and "Open incidents" not in m["text"], True)
    check("and opens to the status", bool(m) and "Open incidents" in opened(m)["b"], True)
    check("its buttons stay under it",
          bool(m) and [b.get("callback_data") for b in m["reply_markup"]["inline_keyboard"][1]],
          ["pending", "end"])
    n = len(fake.to(111))
    say_as(sam, "secret question")
    m = next_to_sam(n, "The agent answered")
    check("the agent's answer comes sealed", bool(m) and "quiet" not in m["text"], True)
    check("and opens to the answer", bool(m) and opened(m)["b"], "All quiet.")
    reply["answers"] = ["word " * 2000]
    n = len(fake.to(111))
    say_as(sam, "a long one")
    m = next_to_sam(n, "The agent answered")
    check("a long answer still fits the button",
          bool(m) and len(m["reply_markup"]["inline_keyboard"][0][0]["web_app"]["url"]) <= remote_reader.URL_MAX,
          True)
    reply["answers"] = ["All **quiet**."]
    n = len(fake.to(111))
    check("plain again at the computer", call("/private/remove", "POST", {"id": sam_id})[0], 200)
    next_to_sam(n, "turned off")
    n = len(fake.to(111))
    press(sam, "status")
    check("then status is in plain", bool(next_to_sam(n, "Open incidents")), True)

    print("control: the session ends")
    rdb = sqlite3.connect(module_host.DATA_DIR / "remote" / "remote.db")
    n = len(fake.to(111))
    rdb.execute("UPDATE people SET session_until = ? WHERE id = ?", (time.time() + 200, sam_id))
    rdb.commit()
    check("a notice before the end", bool(next_to_sam(n, "Control ends in")), True)
    n = len(fake.to(111))
    rdb.execute("UPDATE people SET session_until = ? WHERE id = ?", (time.time() - 1, sam_id))
    rdb.commit()
    check("and when it runs out", bool(next_to_sam(n, "Control session ended")), True)
    a3 = actions.write_request("block_device", {"ip": "203.0.113.10"}, "Again")["request_id"]
    n = len(fake.to(111))
    press(sam, f"a:{a3}:n")
    check("after the end a button asks for the PIN again", bool(next_to_sam(n, "Send your <b>PIN</b>")), True)
    check("and decides nothing", actions.query_requests(request_id=a3, limit=1)[0]["state"], "pending")
    n = len(fake.to(111))
    say_as(sam, "/new")
    next_to_sam(n, "Fresh chat")
    n, before = len(fake.to(111)), len(asked)
    say_as(sam, "anything new?")
    m = next_to_sam(n, "Chatting with the agent needs control")
    check("chat outside a session asks to take control",
          bool(m) and m["reply_markup"]["inline_keyboard"][0][0]["callback_data"], "ctlc")
    check("and asks the agent nothing yet", len(asked), before)
    n = len(fake.to(111))
    press(sam, "ctlc")
    check("Take control there asks for the PIN", bool(next_to_sam(n, "Send your <b>PIN</b>")), True)
    agent_loop.run_unattended = real_turn

    print("control: lockout")
    for _ in range(2):
        n = len(fake.to(111))
        say_as(sam, "111222")
        next_to_sam(n, "Wrong PIN")
    n = len(fake.to(111))
    say_as(sam, "111333")
    check("a third wrong try locks control", bool(next_to_sam(n, "Control is locked")), True)
    check("the tab shows it locked",
          next(p for p in call("/state")[1]["people"] if p["id"] == sam_id)["locked"], True)
    n = len(fake.to(111))
    say_as(sam, "/control")
    check("a locked person cannot take control", bool(next_to_sam(n, "locked for you")), True)
    check("unlock at the computer", call("/control/unlock", "POST", {"id": sam_id})[0], 200)
    check("unlocked", next(p for p in call("/state")[1]["people"] if p["id"] == sam_id)["locked"], False)

    print("control: panic word")
    n = len(fake.to(111))
    word_msg = say_as(sam, "red BALLOON")
    check("the panic word turns control off", bool(next_to_sam(n, "Panic word received")), True)
    check("and is deleted from the chat",
          bool(wait_for(lambda: any(c[0] == "deleteMessage" and c[1]["message_id"] == word_msg
                                    for c in fake.calls))), True)
    check("the tab shows it", call("/state")[1]["control"]["panic"], True)
    n = len(fake.to(111))
    say_as(sam, "/control")
    check("nobody can take control after it", bool(next_to_sam(n, "since the panic word")), True)
    check("turned back on at the computer", call("/control/resume", "POST")[0], 200)
    check("panic is off", call("/state")[1]["control"]["panic"], False)

    print("control: removed at the computer")
    check("remove control", call("/control/remove", "POST", {"id": sam_id})[0], 200)
    check("Sam is back to alerts only",
          next(p for p in call("/state")[1]["people"] if p["id"] == sam_id)["enrolled"], False)
    rdb.close()

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
