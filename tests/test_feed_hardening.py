"""
tests/test_feed_hardening.py, register section 16 second pass (FM-1 .. FM-6).

Drives the shipped fetch against real local HTTP servers, and the shipped
parsers on the trimmed live bodies in tests/fixtures/feeds/.

Run it directly: python3 tests/test_feed_hardening.py
"""
import http.server
import pathlib
import re
import sys
import threading

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                      # noqa: E402
_isolate_db.isolate()

from tools import feed_matcher as fm                    # noqa: E402
from tools import kev_cvss as kc                        # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


# Two local servers: "near" redirects, "far" records what it was sent.
received = {}


class Near(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/away":
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{FAR}/x")
        elif self.path == "/same":
            self.send_response(302)
            self.send_header("Location", "/list")
        elif self.path == "/big":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"1.1.1.1\n" * 4000)
            return
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"8.8.8.8\n")
            return
        self.end_headers()

    def log_message(self, *a):
        pass


class Far(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        received.update(dict(self.headers))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"8.8.4.4\n")

    def log_message(self, *a):
        pass


def serve(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


NEAR, FAR = serve(Near), serve(Far)
import os                                               # noqa: E402
os.environ["AGENTAL_ABUSECH_KEY"] = "key-under-test"

print("\n[FM-1b] the key does not follow a redirect to another host")
text, err = fm._fetch(f"http://127.0.0.1:{NEAR}/away", send_key=True)
check("the other host was never asked", received, {})
check("and the refusal says why", "different host" in (err or ""), True)
text, err = fm._fetch(f"http://127.0.0.1:{NEAR}/same", send_key=True)
check("a same-host redirect is still followed", (text or "").strip(), "8.8.8.8")

print("\n[FM-2] a response past the size cap is refused")
old = fm.MAX_RESPONSE_BYTES
fm.MAX_RESPONSE_BYTES = 10_000
text, err = fm._fetch(f"http://127.0.0.1:{NEAR}/big", send_key=False)
fm.MAX_RESPONSE_BYTES = old
check("no text", text, None)
check("and it says it was too large", "larger than" in (err or ""), True)
text, err = fm._fetch(f"http://127.0.0.1:{NEAR}/big", send_key=False)
check("the same body under the real cap is read", len((text or "").split()), 4000)

print("\n[FM-1] a URL whose host is an address is an IP row, not a domain")
check("url with an address", fm._host_rows("http://8.8.8.8:8080/a", "x"),
      [("8.8.8.8", "ip", "x")])
check("url with an internal address is dropped",
      fm._host_rows("http://192.0.2.1/a", "x"), [])
check("bracketed v6 url", fm._host_rows("https://[2606:4700:0:0::1111]:443/", ""),
      [("2606:4700::1111", "ip", "")])
check("user info is not part of the host",
      fm._host_rows("http://someone@evil.example/p", ""),
      [("evil.example", "domain", "")])
check("a plain domain is unchanged", fm._host_rows("Evil.Example.", ""),
      [("evil.example", "domain", "")])
check("OTX URL type goes the same way",
      fm._otx_value_to_rows("http://8.8.8.8/x", "URL", ""), [("8.8.8.8", "ip", "")])
check("MISP url type goes the same way",
      fm._misp_value_to_rows("http://8.8.8.8/x", "url", ""), [("8.8.8.8", "ip", "")])

tf = (ROOT / "tests" / "fixtures" / "feeds" / "threatfox.csv").read_text(encoding="utf-8")
rows = fm._parse_threatfox_csv(tf)
as_domain = [i for i, t, _f in rows if t == "domain" and re.fullmatch(r"[0-9.]+", i)]
check("the live ThreatFox body stores no address as a domain", as_domain, [])
check("and its URL addresses land as IP rows",
      sum(1 for _i, t, _f in rows if t == "ip") > 0, True)

print("\n[FM-3] IPv6 rows use the spelling the packet record uses")
check("feodo-style line", fm._parse_lines_ip("2606:4700:0000:0000::1111\n"),
      [("2606:4700::1111", "ip", "")])
check("upper case", fm._canonical_ip("2606:4700::ABCD"), "2606:4700::abcd")
check("not globally routable is refused", fm._canonical_ip("fe80::1"), "")

print("\n[FM-4] a MISP manifest key cannot reshape the event URL")
window, total = fm.select_misp_events(
    {"good-1": {"timestamp": 1}, "../../x?y": {"timestamp": 2},
     "a/b": {"timestamp": 3}, "evil@host": {"timestamp": 4}}, 10)
check("only the plain id is kept", [u for u, _ in window], ["good-1"])

print("\n[FM-5] a CVSS score or word outside the spec is not stored as one")
bad = kc._from_result({"fields": {"cvss_score": 42, "cvss_severity": "critical"}})
check("a score of 42 is not a score", bad["score"], None)
odd = kc._from_result({"fields": {"cvss_score": 7.5, "cvss_severity": "pwned"}})
check("an unknown word falls back to the band", odd["severity"], "high")

print("\n[FM-6] a stamp with no zone does not break the due list")
check("read as UTC", kc._parse("2026-09-01T00:00:00").tzinfo is not None, True)

print("\n" + "=" * 62)
if fails:
    print(f"{len(fails)} FAILED: " + ", ".join(fails))
    sys.exit(1)
print("ALL CHECKS PASSED")
