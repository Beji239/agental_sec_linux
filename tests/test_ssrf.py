"""
tests/test_ssrf.py, a redirect cannot send this app's requests into the LAN.

A compromised feed or lookup host answering with a redirect could point the
app at the router, the dashboard or another device. Two local servers stand in
for that host and the place it points to. Then every outbound call in the app
is checked to go through core/safe_http or to refuse redirects outright.

Run it directly: python tests/test_ssrf.py
"""
import ast
import http.server
import json
import pathlib
import sys
import threading

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import requests                                         # noqa: E402

from core import safe_http                              # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


print("[1] which addresses count as local")
for host, want in (("127.0.0.1", True), ("10.1.2.3", True),
                   ("192.168.0.1", True), ("172.16.0.9", True),
                   ("169.254.169.254", True), ("100.64.0.1", True),
                   ("::1", True), ("fe80::1", True), ("fd00::5", True),
                   ("0.0.0.0", True), ("localhost", True), ("", True),
                   ("8.8.8.8", False), ("2606:4700:4700::1111", False)):
    check(f"{host or '(empty)'}", safe_http.is_local(host), want)

print("\n[2] a redirect into the network is refused")
hits = []


class Target(http.server.BaseHTTPRequestHandler):
    def _answer(self):
        size = int(self.headers.get("content-length") or 0)
        hits.append({"method": self.command, "path": self.path,
                     "key": self.headers.get("Key"),
                     "body": self.rfile.read(size).decode() if size else ""})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"secret")

    do_GET = do_POST = _answer

    def log_message(self, *a):
        pass


def serve(handler):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


target = serve(Target)
where = {"code": 302, "to": f"http://127.0.0.1:{target.server_port}/secret"}


class Bouncer(http.server.BaseHTTPRequestHandler):
    def _answer(self):
        size = int(self.headers.get("content-length") or 0)
        self.rfile.read(size)
        self.send_response(where["code"])
        self.send_header("Location", where["to"])
        self.end_headers()

    do_GET = do_POST = _answer

    def log_message(self, *a):
        pass


bouncer = serve(Bouncer)
start = f"http://127.0.0.1:{bouncer.server_port}/feed"

requests.get(start, timeout=5)
check("plain requests follows it, which is the hole", len(hits), 1)
hits.clear()
try:
    safe_http.get(start, timeout=5)
    refused = False
except safe_http.RedirectRefused:
    refused = True
check("safe_http refuses it", refused, True)
check("and the local address was never asked", hits, [])
check("a refusal is a requests error, so callers' handlers catch it",
      issubclass(safe_http.RedirectRefused, requests.RequestException), True)

print("\n[3] a redirect to a public address still works, keys stay home")
real_local = safe_http.is_local
safe_http.is_local = lambda host: False
try:
    r = safe_http.get(start, timeout=5, headers={"Key": "k1"})
    check("followed", (r.status_code, r.text), (200, "secret"))
    check("the key header was not carried to the other host",
          hits[-1]["key"], None)
    where["to"] = f"http://localhost:{target.server_port}/secret"
    try:
        safe_http.get(start, timeout=5, same_host=True)
        moved = True
    except safe_http.RedirectRefused:
        moved = False
    check("a keyed request may not leave its host", moved, False)
    where["to"] = f"http://127.0.0.1:{target.server_port}/secret"
    hits.clear()
    safe_http.post(start, timeout=5, json={"q": 1})
    check("a POST answered with 302 goes on as a GET without its body",
          (hits[-1]["method"], hits[-1]["body"]), ("GET", ""))
    where["code"] = 307
    safe_http.post(start, timeout=5, json={"q": 1})
    check("a 307 keeps the method and the body",
          (hits[-1]["method"], json.loads(hits[-1]["body"])), ("POST", {"q": 1}))
    where["to"] = "file:///etc/passwd"
    try:
        safe_http.get(start, timeout=5)
        other = True
    except safe_http.RedirectRefused:
        other = False
    check("a redirect to another scheme is refused", other, False)
finally:
    safe_http.is_local = real_local
    target.shutdown()
    bouncer.shutdown()

print("\n[4] every outbound call in the app is covered")
METHODS = {"get", "post", "put", "patch", "delete", "head", "request"}
loose = []
for path in sorted([*ROOT.glob("core/*.py"), *ROOT.glob("tools/*.py"),
                    *ROOT.glob("api/*.py"), ROOT / "adapters.py",
                    ROOT / "main.py"]):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not (isinstance(f, ast.Attribute) and f.attr in METHODS
                and isinstance(f.value, ast.Name)
                and f.value.id in ("requests", "httpx")):
            continue
        if path.name == "safe_http.py":
            continue
        kw = {k.arg: k.value for k in node.keywords}
        flag = "follow_redirects" if f.value.id == "httpx" else "allow_redirects"
        val = kw.get(flag)
        safe = (isinstance(val, ast.Constant) and val.value is False) or (
            f.value.id == "httpx" and val is None)
        if not safe:
            loose.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "follow_redirects" \
                and not (isinstance(node.value, ast.Constant)
                         and node.value.value is False):
            loose.append(f"{path.relative_to(ROOT)}:{node.value.lineno} "
                         f"follow_redirects")
check("no requests or httpx call follows redirects unchecked", loose, [])

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
