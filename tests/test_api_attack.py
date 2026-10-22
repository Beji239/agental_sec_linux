"""
tests/test_api_attack.py, every route of the API attacked from outside.

Section 4 of the security plan, the part that needs no outside tool. Every
route is called without credentials, with a wrong key and a forged session,
with a foreign Host header and a foreign Origin, with the wrong method, with
malformed bodies and with hostile query strings. Nothing may answer 500 (503, a module not loaded here, is honest),
nothing but the public routes may answer without a credential, and no
answer may grant another origin.

The app runs from a throwaway copy of the code, with its own home folder and
no network (unshare -rn), so a route that writes a setting or tries a lookup
does it there and nowhere else.
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _skip  # noqa: E402

if not shutil.which("unshare"):
    _skip.skip("needs unshare, to run the app with no network")

fails = []


def check(label, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)
        if detail:
            print(f"        {str(detail)[:4000]}")


CHILD = r'''
import json, pathlib, sqlite3, sys
root = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(root))
from core import memory_engine as me
db = root / "t.db"
c = sqlite3.connect(db); c.executescript((root / "Schema.SQL").read_text()); c.close()
me.DB_PATH = db
from core import migrations; migrations.run_migrations(db)
import logging; logging.disable(logging.CRITICAL)
from api.server import create_app
from api import dashboard_session as ds
from api import routes as _routes

KEY = "ab" * 32
app = create_app({"flask": {"host": "127.0.0.1", "port": 5000}}, {}, "attack",
                 api_key=KEY)
app.config["PROPAGATE_EXCEPTIONS"] = False
client = app.test_client()
LOCAL = {"HTTP_HOST": "127.0.0.1:5000"}
PUBLIC = {"/", "/open", "/ui/<path:filename>", "/module-ui/<name>/ui.js"}

def url(rule):
    out = []
    for part in rule.split("/"):
        if part.startswith("<"):
            kind = part[1:-1].split(":")[0] if ":" in part else "string"
            out.append("1" if kind == "int" else "x")
        else:
            out.append(part)
    return "/".join(out)

routes = []
for r in app.url_map.iter_rules():
    if r.endpoint == "static":
        continue
    for m in sorted(r.methods - {"HEAD", "OPTIONS"}):
        routes.append((r.rule, m))

def reset():
    _routes._auth_fails.clear(); _routes._auth_locked.clear()

res = {"routes": len(routes), "open": [], "wrong_key": [], "forged": [],
       "foreign_host": [], "cors": [], "e500": [], "html": [],
       "wrong_method": []}
forged = ds.new_session("cd" * 32)
expired = ds.new_session(KEY, now=1_000_000)

for rule, m in routes:
    u = url(rule)
    call = getattr(client, m.lower())
    if rule not in PUBLIC:
        reset()
        for label, headers in (("open", {}),
                               ("wrong_key", {"X-API-Key": "f" * 64}),
                               ("forged", {ds.HEADER: forged}),
                               ("forged", {ds.HEADER: expired})):
            r = call(u, headers=headers, environ_overrides=LOCAL)
            if r.status_code not in (401, 429):
                res[label].append(f"{m} {rule} {r.status_code}")
    reset()
    r = call(u, headers={"X-API-Key": KEY},
             environ_overrides={"HTTP_HOST": "evil.example:5000"})
    if r.status_code != 403:
        res["foreign_host"].append(f"{m} {rule} {r.status_code}")
    r = call(u, headers={"X-API-Key": KEY, "Origin": "http://evil.example"},
             environ_overrides=LOCAL)
    if r.headers.get("Access-Control-Allow-Origin"):
        res["cors"].append(f"{m} {rule}")

reset()
# The wrong method is a 405, never an error page from inside a handler.
for rule, m in routes:
    other = "post" if m == "GET" else "get"
    if (rule, other.upper()) in routes:
        continue
    r = getattr(client, other)(url(rule), headers={"X-API-Key": KEY},
                               environ_overrides=LOCAL)
    if r.status_code != 405:
        res["wrong_method"].append(f"{other.upper()} {rule} {r.status_code}")

H = {"X-API-Key": KEY}
BODIES = [("text", "not json at all", "text/plain"),
          ("broken json", "{\"a\": ", "application/json"),
          ("a list", "[1, 2, 3]", "application/json"),
          ("a string", "\"x\"", "application/json"),
          ("null", "null", "application/json"),
          ("deep", "[" * 5000 + "]" * 5000, "application/json")]
HOSTILE = {"ip": ["../../etc/passwd"], "port": {"a": 1}, "id": "1 OR 1=1",
           "limit": -1, "target": "\x00\r\nX-Injected: 1",
           "name": "<script>x</script>" * 50, "path": "../" * 40 + "etc/shadow",
           "key": None, "value": [None], "domain": "a" * 5000,
           "direction": {"$ne": 1}, "reason": 12345, "message": ["x"]}
QUERY = ("limit=-1&offset=abc&ip=..%2F..%2Fetc&q=%27%20OR%201%3D1--&"
         "severity=%00&since=9999999999999&entity=" + "A" * 4000)

skip_post = {"/api/shutdown"}
import time as _t
slow = []
for rule, m in routes:
    u = url(rule)
    _t0 = _t.time()
    if m == "POST" and rule not in skip_post:
        reset()
        cases = [(n, dict(data=b, content_type=t)) for n, b, t in BODIES]
        cases.append(("hostile fields", dict(json=HOSTILE)))
        for name, kw in cases:
            r = client.post(u, headers=H, environ_overrides=LOCAL, **kw)
            if r.status_code >= 500 and r.status_code != 503:
                res["e500"].append(f"POST {rule} [{name}] {r.status_code} "
                                   f"{r.get_data(as_text=True)[:160]}")
            elif rule.startswith("/api/") and "html" in (r.content_type or ""):
                res["html"].append(f"POST {rule} [{name}]")
    elif m == "GET":
        reset()
        r = client.get(f"{u}?{QUERY}", headers=H, environ_overrides=LOCAL)
        if r.status_code >= 500 and r.status_code != 503:
            res["e500"].append(f"GET {rule} [hostile query] {r.status_code} "
                               f"{r.get_data(as_text=True)[:160]}")
    slow.append((round(_t.time() - _t0, 2), m, rule))
res["slow"] = sorted(slow, reverse=True)[:8]
print(json.dumps(res))
'''

tmp = pathlib.Path(tempfile.mkdtemp(prefix="agentalsec_attack_"))
try:
    app_root = tmp / "app"
    app_root.mkdir()
    for d in ("api", "core", "tools", "ui", "data", "geoip"):
        if (ROOT / d).is_dir():
            shutil.copytree(ROOT / d, app_root / d, ignore=shutil.ignore_patterns(
                "__pycache__", "*.db", "*.db-*"))
    for f in ("adapters.py", "Schema.SQL", "config.linux.example.json"):
        if (ROOT / f).exists():
            shutil.copy2(ROOT / f, app_root / f)
    # Routes that save a setting write config.json; this one is the copy's.
    shutil.copy2(ROOT / "config.linux.example.json", app_root / "config.json")
    script = tmp / "child.py"
    script.write_text(CHILD, encoding="utf-8")
    import site
    # A new HOME would hide the packages under ~/.local, so their base stays.
    env = dict(os.environ, HOME=str(tmp / "home"),
               PYTHONUSERBASE=site.getuserbase(),
               XDG_STATE_HOME=str(tmp / "state"),
               XDG_CONFIG_HOME=str(tmp / "config"),
               XDG_DATA_HOME=str(tmp / "share"))
    for k in ("AGENTAL_API_KEY", "AGENTAL_APP_API_KEY"):
        env.pop(k, None)
    p = subprocess.run(["unshare", "-rn", sys.executable, str(script),
                        str(app_root)], capture_output=True, text=True,
                       timeout=170, env=env, cwd=app_root)
    last = (p.stdout.strip().splitlines() or [""])[-1]
    try:
        res = json.loads(last)
    except json.JSONDecodeError:
        print(p.stdout[-2000:], p.stderr[-3000:])
        check("the attacking app ran", False)
        sys.exit(1)

    print(f"Every route, {res['routes']} route and method pairs")
    print(f"  slowest: {res.get('slow')}")
    check("none answers without a credential", not res["open"], res["open"])
    check("none answers a wrong key", not res["wrong_key"], res["wrong_key"])
    check("none answers a forged or expired session", not res["forged"],
          res["forged"])
    check("none answers a foreign Host, the public ones included",
          not res["foreign_host"], res["foreign_host"])
    check("none grants another origin", not res["cors"], res["cors"])
    check("the wrong method is a 405", not res["wrong_method"],
          res["wrong_method"])
    print("Malformed bodies and hostile queries, with the right key")
    check("nothing answers 500", not res["e500"],
          "\n        ".join(e.split(" <")[0] for e in res["e500"]))
    check("every API answer is JSON, never an HTML error page",
          not res["html"], res["html"])
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{'ALL PASSED' if not fails else str(len(fails)) + ' FAILED'}")
sys.exit(1 if fails else 0)
