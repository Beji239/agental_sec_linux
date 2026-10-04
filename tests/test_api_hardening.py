"""
tests/test_api_hardening.py, the backend hardening pass of 2026-08-28.

Covers the fixes recorded as S11 through S18 in TODO.md section 1.9 and 2.5.
Weighted towards the refusals, as the other suites are: what these changes buy
is that bad input is answered rather than crashed on, and that a path the model
can be argued into naming cannot reach an arbitrary file.
"""
import sys, tempfile, sqlite3, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []
def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)

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


print("\n[1] S11: a malformed limit is answered, not crashed on")
for bad in ["abc", "", "9e9", "-", "0x10", "١٢٣"]:
    r = client.get(f"/api/findings?limit={bad}", headers=H)
    check(f"limit={bad!r} -> not a 500", r.status_code != 500, True)

r = client.get("/api/findings?limit=999999", headers=H)
check("absurd limit clamped, still 200", r.status_code, 200)

print("\n[2] S11: an invalid enum is a 400 that says why, not a 500")
r = client.get("/api/findings?severity=notaseverity", headers=H)
check("status", r.status_code, 400)
check("carries the reason", "Invalid severity" in r.get_json().get("detail", ""), True)

print("\n[3] S12: a non-ASCII key is 401, not 500")
r = client.get("/api/findings", headers={"X-API-Key": "ééé"})
check("status", r.status_code, 401)
r = client.get("/api/findings", headers={"X-API-Key": "wrong"})
check("a plain wrong key is still 401", r.status_code, 401)
r = client.get("/api/findings")
check("no key is 401", r.status_code, 401)

print("\n[4] S13: the IPv6 loopback is accepted, and foreign hosts still are not")
r = client.get("/api/findings", headers=H, environ_overrides={"HTTP_HOST": "[::1]:5000"})
check("[::1]:5000 accepted", r.status_code, 200)
r = client.get("/api/findings", headers=H, environ_overrides={"HTTP_HOST": "127.0.0.1:5000"})
check("127.0.0.1 still accepted", r.status_code, 200)
r = client.get("/api/findings", headers=H, environ_overrides={"HTTP_HOST": "evil.com"})
check("rebinding host still refused", r.status_code, 403)
r = client.get("/api/findings", headers=H, environ_overrides={"HTTP_HOST": "localhost.evil.com"})
check("suffix trick refused", r.status_code, 403)

print("\n[5] the pending permissions route, and what it is allowed to be")
# THIS USED TO ASSERT A 404. 2026-09-08 it came back, and it is a different
# route that happens to share the path.
#
# The one deleted in S14 read a variable nothing ever assigned, so it answered
# "nothing pending" for its whole life. The one here reads the real open-card
# register, and it exists because cards no longer time out: a card can be on
# screen when the page reloads, and the reload kills the turn that was holding
# it. This route is how the fresh page says that out loud.
#
# So the assertion is not "it is gone" any more, it is "it can only report a
# LOSS". Everything it returns is a dead card, and the moment somebody hangs
# an approve path off it we are back to a button that quietly does nothing,
# which is what got the old one deleted.
resp = client.get("/api/permissions/pending", headers=H)
check("it answers rather than 404ing", resp.status_code, 200)
body = resp.get_json() or {}
check("and what it returns is named a LOSS, not a pending decision",
      "lost" in body, True)
check("it never says pending, which is the word the dead one used",
      "pending" in body, False)

routes = {str(rule.rule) for rule in app.url_map.iter_rules()}
check("approve still present", "/api/permissions/approve" in routes, True)
check("deny still present", "/api/permissions/deny" in routes, True)
check("and nothing actionable hangs off pending",
      sorted(x for x in routes if x.startswith("/api/permissions/pending/")),
      [])

print("\n[6] S17: read_code_file refuses a sibling directory")
from core import tool_registry as tr
out = tr.execute_tool("read_code_file", {"file_path": "../agental_sec_old/config.py"})
check("refused", "error" in out and out["error"] is not None
      or "error" in (out.get("result") or {}), True)
out = tr.execute_tool("read_code_file", {"file_path": "/etc/passwd"})
check("absolute path refused", out["error"] is not None
      or "error" in (out.get("result") or {}), True)
out = tr.execute_tool("read_code_file", {"file_path": "main.py"})
check("a real project file still reads", (out.get("result") or {}).get("error"), None)

print("\n[7] S18: pcap analysis refuses anything not named like a capture")
from tools.pcap_analyzer import PcapAnalyzer
pa = PcapAnalyzer("test-session")

secret = pathlib.Path(tmp) / ".env"
# Deliberately NOT shaped like a credential. The point of the file is its
# NAME, .env is what pcap analysis must refuse to open, and a realistic
# secret here would trip check_no_local_details, correctly.
secret.write_text("THIS_FILE_MUST_NEVER_BE_READ_BY_THE_PCAP_TOOL\n", encoding="utf-8")

res = pa.analyze(str(secret))
check("refused by name", "Refusing to read" in res.get("error", ""), True)
check("and says nothing about existence",
      "not found" in res.get("error", "").lower(), False)

missing_pcap = pathlib.Path(tmp) / "nope.pcap"
res = pa.analyze(str(missing_pcap))
check("a real capture name that is absent reports absence",
      "File not found" in res.get("error", ""), True)

res = pa.analyze(str(pathlib.Path(tmp) / "x.pcap"), max_packets="lots")
check("non-integer max_packets refused",
      "must be an integer" in res.get("error", ""), True)
res = pa.analyze(str(pathlib.Path(tmp) / "x.pcap"), max_packets=0)
check("zero max_packets refused", "at least 1" in res.get("error", ""), True)

check("the packet cap exists", PcapAnalyzer.MAX_PACKET_CAP <= 200_000, True)
check("the size cap exists", PcapAnalyzer.MAX_PCAP_BYTES <= 512 * 1024 * 1024, True)

big = pathlib.Path(tmp) / "big.pcap"
with open(big, "wb") as fh:
    fh.truncate(PcapAnalyzer.MAX_PCAP_BYTES + 1)
res = pa.analyze(str(big))
check("an oversized capture is refused before it is parsed",
      "over the" in res.get("error", ""), True)

print("\n[8] CSP: the page that carries the key says what may run on it")
r = client.get("/", environ_overrides={"HTTP_HOST": "127.0.0.1:5000"})
csp = r.headers.get("Content-Security-Policy", "")
check("the header is there", bool(csp), True)
# connect-src is the one that matters. Injected script could still read the
# key, it just has nowhere off this machine to send it.
check("connect-src is self only", "connect-src 'self'" in csp, True)
check("no plugin content", "object-src 'none'" in csp, True)
check("cannot be framed", "frame-ancestors 'none'" in csp, True)
check("no base tag rewriting", "base-uri 'none'" in csp, True)
# Honest negative. 'unsafe-inline' is still in script-src because the page has
# inline onclick handlers. This asserts the CURRENT state, so the day somebody
# removes those handlers this test fails and gets updated on purpose, rather
# than the policy quietly staying weaker than it needs to be.
check("script-src still allows inline, and we know it",
      "'unsafe-inline'" in csp.split("script-src")[1].split(";")[0], True)

check("api answers are not cached",
      client.get("/api/findings", headers=H).headers.get("Cache-Control"), "no-store")
check("api answers are not sniffed",
      client.get("/api/findings", headers=H).headers.get("X-Content-Type-Options"),
      "nosniff")

print("\n[9] failed key throttle: guessing gets slower, the real user never does")
from api import routes as _routes
_routes._auth_fails.clear(); _routes._auth_locked.clear()

codes = [client.get("/api/findings", headers={"X-API-Key": "wrong"}).status_code
         for _ in range(_routes._AUTH_FAIL_MAX + 2)]
check("the first wrong keys are plain 401s",
      codes[:_routes._AUTH_FAIL_MAX], [401] * _routes._AUTH_FAIL_MAX)
check("then the door shuts", codes[-1], 429)

r = client.get("/api/findings", headers={"X-API-Key": "wrong"})
check("a locked out caller gets Retry-After", bool(r.headers.get("Retry-After")), True)

# THE IMPORTANT ONE. Everything here is loopback, so the dashboard and anything
# guessing at it share 127.0.0.1. If a lockout could refuse a correct key, any
# process on this box could hold the door shut on the real user for as long as
# it liked, just by guessing wrong on purpose.
check("a correct key still works during a lockout",
      client.get("/api/findings", headers=H).status_code, 200)

_routes._auth_fails.clear(); _routes._auth_locked.clear()

print("\n[10] bad input is a 400, a real defect is still a 500")
# The handler used to catch plain ValueError, so ANY ValueError raised during
# a request came back as "Bad request" with the internal message attached.
# That tells the caller they were wrong when the server was the thing that
# broke, and it buries real defects behind a status nobody investigates.
#
# Two fake routes rather than a real endpoint: the point is which EXCEPTION
# maps to which status, and this says it in two lines without depending on
# some other feature staying broken. Its own app, because Flask will not let
# you add routes to one that has already served a request.
app2 = create_app({"flask": {"host": "127.0.0.1", "port": 5000}}, {},
                  "test-session-2", api_key=API_KEY)
app2.config["AGENTAL_ALLOWED_HOSTS"] = allowed_hosts({"flask": {"host": "127.0.0.1"}})
app2.config["PROPAGATE_EXCEPTIONS"] = False


@app2.route("/api/_test_badinput")
def _test_badinput():
    raise me.BadInput("you passed nonsense")


@app2.route("/api/_test_internal")
def _test_internal():
    raise ValueError("a real defect deep in a sensor")


client2 = app2.test_client()

r = client2.get("/api/_test_badinput", headers=H)
check("BadInput is a 400", r.status_code, 400)
check("and the reason reaches the caller",
      "nonsense" in r.get_json().get("detail", ""), True)

# This one WOULD log a traceback, and that is exactly right in production: a
# defect should look like a defect in the log rather than like the caller's
# typo. Muted here only so a passing test run does not print a scary stack
# that somebody then goes looking for.
import logging                                   # noqa: E402
app2.logger.setLevel(logging.CRITICAL)
r = client2.get("/api/_test_internal", headers=H)
check("a plain ValueError is a 500 again", r.status_code, 500)
check("BadInput is still a ValueError, so old handlers keep working",
      issubclass(me.BadInput, ValueError), True)


print("\n[11] the body limit is the control, the message length is a courtesy")
# 2026-09-13. /api/chat measured the MESSAGE at 2000 characters and nothing
# measured the BODY. Flask parses the whole body before route code runs, so
# the character check fired after the work was already done, and the app had
# no size control at all. The two are separated now.
from api.server import max_body_bytes, DEFAULT_MAX_BODY_BYTES  # noqa: E402
from api.routes import MAX_CHAT_CHARS                          # noqa: E402

# THE FAILURE CASES FIRST, because a size limit that silently reads as
# "no limit" is worse than not having one.
check("a missing setting gives the default",
      max_body_bytes({}), DEFAULT_MAX_BODY_BYTES)
check("zero does NOT become unlimited",
      max_body_bytes({"flask": {"max_body_mb": 0}}), DEFAULT_MAX_BODY_BYTES)
check("a negative does not either",
      max_body_bytes({"flask": {"max_body_mb": -5}}), DEFAULT_MAX_BODY_BYTES)
check("nonsense does not either",
      max_body_bytes({"flask": {"max_body_mb": "lots"}}), DEFAULT_MAX_BODY_BYTES)
check("and neither does something absurdly large",
      max_body_bytes({"flask": {"max_body_mb": 5000}}), DEFAULT_MAX_BODY_BYTES)
check("a real value is honoured",
      max_body_bytes({"flask": {"max_body_mb": 4}}), 4 * 1024 * 1024)

check("the app actually carries the limit",
      app.config.get("MAX_CONTENT_LENGTH"), DEFAULT_MAX_BODY_BYTES)

# An over-size body must be refused, and refused as JSON. Flask's own 413 is
# an HTML page, and every caller here reads JSON, so an HTML refusal reaches
# the dashboard as nothing at all.
big = client.post("/api/chat", headers=H, json={"message": "x" * (2 * 1024 * 1024)})
check("an over-size body is refused", big.status_code, 413)
check("and the refusal is JSON, not an HTML page",
      big.headers.get("Content-Type", "").startswith("application/json"), True)
check("and it says what was refused",
      "too large" in (big.get_json() or {}).get("error", "").lower(), True)

# The message cap. It refuses rather than truncating, and says both numbers,
# because "part of it went through" is the belief that has to be impossible.
over = client.post("/api/chat", headers=H,
                   json={"message": "x" * (MAX_CHAT_CHARS + 1)})
check("a message over the cap is a 400", over.status_code, 400)
body = over.get_json() or {}
check("the cap is named in the error", str(MAX_CHAT_CHARS) in body.get("error", ""), True)
check("and so is the actual length",
      str(MAX_CHAT_CHARS + 1) in body.get("detail", ""), True)
check("and it says nothing was shortened",
      "shortened" in body.get("detail", "").lower(), True)
check("an empty message is still refused",
      client.post("/api/chat", headers=H, json={"message": "   "}).status_code, 400)

# The number itself, so a later edit that quietly drops it back has to argue
# with a test rather than with a comment.
check("the cap is the raised one, not the old 2000", MAX_CHAT_CHARS, 16000)
check("and it is still far below the context budget",
      MAX_CHAT_CHARS < 128000, True)


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
