"""
tests/test_gateway_messages.py: messages to a device through the router.

Runs the agent under busybox sh inside a private network namespace, as
tests/test_gateway.py does, with a stand-in for uhttpd. The page script the
agent writes is then run the way uhttpd would run it: a GET shows the message
escaped, a POST keeps the answer, and OK lifts a one-time message but not one
made with messagekeep.
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

if os.environ.get("GW_TEST_IN_NS") != "1":
    if not (shutil.which("unshare") and shutil.which("busybox") and shutil.which("nft")):
        print("SKIP: unshare, busybox or nft is not available")
        sys.exit(0)
    env = dict(os.environ, GW_TEST_IN_NS="1")
    sys.exit(subprocess.run(["unshare", "-rn", sys.executable, __file__],
                            env=env).returncode)

sys.path.insert(0, str(ROOT))
from tools import gateway as gw  # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def sh(*argv):
    return subprocess.run(argv, check=False, capture_output=True, text=True)


DEVICE = "aa:bb:cc:00:00:01"
KEEPER = "aa:bb:cc:00:00:02"
sh("ip", "link", "set", "lo", "up")
sh("ip", "link", "add", "br-lan", "type", "veth", "peer", "name", "lanpeer")
sh("ip", "addr", "add", "192.0.2.1/24", "dev", "br-lan")
sh("ip", "link", "set", "br-lan", "up")
sh("ip", "link", "set", "lanpeer", "up")
sh("ip", "route", "add", "default", "via", "192.0.2.254")
sh("ip", "neigh", "add", "192.0.2.10", "lladdr", DEVICE, "dev", "br-lan")
sh("ip", "neigh", "add", "192.0.2.11", "lladdr", KEEPER, "dev", "br-lan")

tmp = pathlib.Path(tempfile.mkdtemp())
state = tmp / "state"
bin_dir = tmp / "bin"
bin_dir.mkdir()
pidfile = tmp / "uhttpd.pid"
fake = bin_dir / "uhttpd"
fake.write_text(f"""#!/bin/sh
case " $* " in *" -h "*) [ $# -eq 1 ] && {{ echo "  -E string  404 error handler"; exit 0; }} ;; esac
( while :; do sleep 1; done ) </dev/null >/dev/null 2>&1 &
echo $! > {pidfile}
""")
fake.chmod(0o755)

src = (ROOT / "tools" / "gateway_agent.sh").read_text()
src = src.replace("/etc/agentalsec", str(state))
src = src.replace("PATH=/usr/sbin:", f"PATH={bin_dir}:/usr/sbin:", 1)
src = src.replace("for p in $(pidof uhttpd 2>/dev/null); do",
                  f"for p in $(cat {pidfile} 2>/dev/null); do", 1)
src = src.replace("if have logread; then", "if false; then")
src = src.replace("elif have journalctl; then", "elif false; then")
agent = tmp / "agent.sh"
agent.write_text(src)
PATH = f"{bin_dir}:{os.environ['PATH']}"


def run(command):
    env = {"SSH_ORIGINAL_COMMAND": command, "SSH_CLIENT": "192.0.2.50 40000 22",
           "SSH_CONNECTION": "192.0.2.50 40000 192.0.2.1 22", "PATH": PATH}
    return subprocess.run(["busybox", "sh", str(agent)], env=env,
                          capture_output=True, text=True, timeout=60).stdout


g = gw.Gateway({"gateway": {"host": "192.0.2.1"}}, transport=run)
page = state / "portal" / "cgi-bin" / "msg"


def visit(ip, method="GET", body=""):
    env = {"REMOTE_ADDR": ip, "REQUEST_METHOD": method,
           "CONTENT_LENGTH": str(len(body)), "PATH": PATH}
    out = subprocess.run(["busybox", "sh", str(page)], env=env, input=body,
                         capture_output=True, text=True, timeout=30).stdout
    return out


def portal_chain():
    return sh("nft", "list", "chain", "inet", "agentalsec_gw", "portal").stdout


print("\n[1] the probe offers messages when nft and uhttpd are there")
caps = g.probe()["capabilities"]
check("message is a capability", "message" in caps, True)

print("\n[2] a message to one device")
text = 'Dinner is ready <b>now</b> & "come" — café'
out = g.message(DEVICE, text)
check("it is in force and read back", (out.get("target"), out.get("verified")), (DEVICE, "read_back"))
check("the page server is running", out.get("server"), "running")
chain = portal_chain()
check("port 80 from that device goes to the page", "dnat ip to 192.0.2.1:2050" in chain and "@msgmac" in chain, True)
listed = g.messages()["messages"]
check("the list gives the text back", [(m["target"], m["text"], m["keep"]) for m in listed],
      [(DEVICE, text, False)])
shown = visit("192.0.2.10")
check("the page shows it, escaped", "Dinner is ready &lt;b&gt;now&lt;/b&gt; &amp; &quot;come&quot; — café" in shown, True)
check("with an OK button and a reply box", ('value="ok"' in shown, "<textarea" in shown), (True, True))
check("and no raw markup from the message", "<b>now" in shown, False)
check("a device with no message sees none", "No message" in visit("192.0.2.99"), True)

print("\n[3] a reply and OK")
visit("192.0.2.10", "POST", "action=reply&reply=Coming+in+5%21")
reps = g.replies()
check("the reply is kept, decoded", [(r["mac"], r["action"], r["text"]) for r in reps],
      [(DEVICE, "reply", "Coming in 5!")])
hostile = "action=reply&reply=" + "%3Cscript%3E" + "x" * 3000
visit("192.0.2.10", "POST", hostile)
check("an oversized reply is cut, not refused", len(g.replies()), 2)
visit("192.0.2.10", "POST", "action=ok")
check("OK lifts a one-time message", g.messages()["messages"], [])
check("and takes the device out of the redirect",
      DEVICE in sh("nft", "list", "set", "inet", "agentalsec_gw", "msgmac").stdout, False)
for r in g.replies():
    g.clear_reply(r["id"])
check("replies can be cleared", g.replies(), [])

print("\n[4] a message that stays, for a device cut off by hardware address")
g.block_mac(KEEPER)
g.message(KEEPER, "This device is cut off. Ask the owner.", keep=True)
pre = sh("nft", "list", "chain", "inet", "agentalsec_gw", "prerouting").stdout.splitlines()
rules = [l.strip() for l in pre if "@blockedmac" in l]
check("the page is let through ahead of the block",
      bool(rules) and "@portalip" in rules[0] and "accept" in rules[0], True)
visit("192.0.2.11", "POST", "action=ok")
check("OK does not lift it", [m["target"] for m in g.messages()["messages"]], [KEEPER])
g.unmessage(KEEPER)
check("unmessage does", g.messages()["messages"], [])

print("\n[5] every device")
g.message("all", "The internet goes off at 22:00.")
chain = portal_chain()
check("one rule redirects every device that has not said OK",
      ('comment "msgall"' in chain, "@msgdone" in chain), (True, True))
check("on the LAN interface", 'iifname "br-lan"' in chain, True)
visit("192.0.2.10", "POST", "action=ok")
check("a device that says OK is let through",
      DEVICE in sh("nft", "list", "set", "inet", "agentalsec_gw", "msgdone").stdout, True)
check("and counted", g.messages()["messages"][0]["acknowledged"] >= 1, True)
g.unmessage("all")
check("lifting it removes the rule", 'comment "msgall"' in portal_chain(), False)

print("\n[6] refusals")
for label, call in (("text that is not hex", lambda: run("message " + DEVICE + " zz")),
                    ("a message over 600 bytes", lambda: run("message " + DEVICE + " " + "41" * 601)),
                    ("messagekeep for every device", lambda: run("messagekeep all 41")),
                    ("a bad reply id", lambda: run("clearreply ../x")),
                    ("the router's own address", lambda: run("message 00:00:00:00:00:00 41"))):
    check(f"{label} is refused", call().startswith("ERR"), True)
try:
    g.message(DEVICE, "x" * 601)
    check("the client refuses an oversized message before sending", False, True)
except gw.GatewayError:
    check("the client refuses an oversized message before sending", True, True)

print("\n[7] restore puts a message back after a reboot")
g.message(DEVICE, "Still here after a reboot.")
sh("nft", "delete", "table", "inet", "agentalsec_gw")
pidfile.unlink()
r = run("restore")
check("restore answers", r.startswith("OK restore"), True)
check("the device is redirected again",
      DEVICE in sh("nft", "list", "set", "inet", "agentalsec_gw", "msgmac").stdout, True)
check("and the page server is back", pidfile.exists(), True)

print("\n[8] the dashboard routes")
sys.path.insert(0, str(ROOT / "tests"))
import _isolate_db                                    # noqa: E402
_isolate_db.isolate()
from core import memory_engine as me                  # noqa: E402
from core import migrations                           # noqa: E402
migrations.run_migrations(me.DB_PATH)
from flask import Flask                               # noqa: E402
from api import routes                                # noqa: E402
import adapters                                       # noqa: E402


class FakeGatewayModule(adapters.LinuxGateway):
    def __init__(self):
        self.session_id = "t"
        self.cfg = {"enabled": True, "host": "192.0.2.1"}
        self._gw = g

    def _gateway(self):
        return g


app = Flask(__name__)
app.config.update(AGENTAL_CONFIG={}, AGENTAL_MODULES={"gateway": FakeGatewayModule()},
                  AGENTAL_SESSION_ID="t", AGENTAL_API_KEY="k",
                  AGENTAL_ALLOWED_HOSTS={"localhost"})
routes.register_routes(app)
client = app.test_client()
h = {"X-API-Key": "k", "Host": "localhost"}
res = client.get("/api/lan/messages", headers=h).get_json()
check("the list says messages are supported", (res.get("supported"), res.get("max_bytes")), (True, 600))
res = client.post("/api/lan/message", json={"target": KEEPER, "text": "Off for tonight.", "keep": True}, headers=h)
check("a message is sent from the dashboard", (res.status_code, res.get_json().get("keep")), (200, "yes"))
res = client.post("/api/lan/message", json={"target": "not-a-mac", "text": "x"}, headers=h)
check("a bad target is refused with a reason", (res.status_code, bool(res.get_json().get("error"))), (409, True))
res = client.post("/api/lan/unblock", json={"mac": KEEPER, "ip": "192.0.2.11"}, headers=h).get_json()
check("restoring the device lifts its message", (res.get("success"), res.get("message_lifted")), (True, True))
check("and it is gone from the router", [m["target"] for m in g.messages()["messages"]], [DEVICE])
visit("192.0.2.10", "POST", "action=reply&reply=ok+thanks")
rid = client.get("/api/lan/messages", headers=h).get_json()["replies"][0]["id"]
res = client.post("/api/lan/reply/clear", json={"id": rid}, headers=h)
check("a reply is deleted from the dashboard",
      (res.status_code, rid in [r["id"] for r in g.replies()]), (200, False))
res = client.post("/api/lan/unmessage", json={"target": DEVICE}, headers=h)
check("and a message removed", (res.status_code, g.messages()["messages"]), (200, []))

try:
    os.kill(int(pidfile.read_text()), 9)
except (OSError, ValueError):
    pass
shutil.rmtree(tmp, ignore_errors=True)
print()
print("ALL CHECKS PASSED" if not fails else f"FAILED: {fails}")
sys.exit(1 if fails else 0)
