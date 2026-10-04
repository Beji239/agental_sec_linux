"""
tests/test_port_scanner_round4.py, port scanner fixes PS-25 to PS-29.

    PS-25  the self/remote test matched the typed string exactly, so this
           machine in capitals, a mapped literal or another loopback address
           read as remote
    PS-26  an expected port matched only under the spelling it was declared
           with, so the same device under another name still raised
    PS-27  a SYN pass that stopped after sending fell back saying no SYN was
           sent, and what it sent and heard was lost
    PS-28  every SYN engine opened both families' raw sockets, whatever the
           target needed
    PS-29  the SYN probe's source port and sequence came from the shared PRNG

No root needed. Every scan here runs on a throwaway database.
"""
import inspect
import os
import pathlib
import socket
import sqlite3
import sys
import tempfile
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import memory_engine as me       # noqa: E402

tmp = pathlib.Path(tempfile.mkdtemp())
db = tmp / "t.db"
me.DB_PATH = db
c = sqlite3.connect(db)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.commit()
c.close()
from core import migrations                # noqa: E402
migrations.run_migrations(db)
from core import sensors as sn             # noqa: E402
sn.register_local()

from tools import port_scanner as ps       # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + ("" if ok else f"  (got {got!r}, want {want!r})"))
    if not ok:
        fails.append(label)


_real_gai = socket.getaddrinfo


def fake_gai(table):
    def gai(host, port, family=0, type=0, proto=0, flags=0):
        if host in table:
            return [(socket.AF_INET6 if ":" in a else socket.AF_INET,
                     socket.SOCK_STREAM, 6, "", (a, 0)) for a in table[host]]
        return _real_gai(host, port, family, type, proto, flags)
    return gai


def scan_with(host, tcp_open=(), origin_hint="self"):
    """A full scan() with the probes stubbed, so only the bookkeeping runs."""
    def tcp(self, target, ports, scan_origin, public):
        rows = []
        for port in tcp_open:
            e = ps.classify_port(port, scan_origin, public)
            e.update(port=port, state="open", protocol="tcp", host=target)
            rows.append(e)
        return {"open": rows, "closed": [], "no_answer": [], "failed": [],
                "method": ps.CONNECT_METHOD, "method_reason": "stub",
                "sent": len(ports), "teardowns": 0}
    udp = {"open": [], "closed": [], "silent": [], "failed": []}
    with mock.patch.object(ps.PortScanner, "_run_tcp_scan", tcp), \
            mock.patch.object(ps.PortScanner, "_run_udp_scan",
                              lambda *a, **k: dict(udp)), \
            mock.patch.object(ps, "kernel_view", lambda *a, **k: {}):
        return ps.PortScanner("t").scan(host, port_set="common")


print("\n[1] PS-25: this machine under any spelling is a self-scan")
local = ps._local_addresses()
host = socket.gethostname()
for spelling in (host.upper(), "LOCALHOST", "::ffff:127.0.0.1", "127.0.0.2",
                 "[::1]", "::", "Localhost"):
    check(f"{spelling!r} is self", ps._is_self_target(spelling, local), True)
check("a documentation address is remote",
      ps._is_self_target("192.0.2.1", local), False)
check("a name that does not resolve stays remote",
      ps._is_self_target("no-such-host.invalid", local), False)
with mock.patch.object(socket, "getaddrinfo",
                       fake_gai({"split.test": ["127.0.0.1", "192.0.2.9"]})):
    check("a name resolving partly elsewhere is remote",
          ps._is_self_target("split.test", local), False)
with mock.patch.object(socket, "getaddrinfo",
                       fake_gai({"me.test": ["127.0.1.1"]})):
    check("a name resolving only to this machine is self",
          ps._is_self_target("me.test", local), True)
check("a mapped loopback is not public", ps._is_public("::ffff:127.0.0.1"), False)
check("a mapped public address is still public",
      ps._is_public("::ffff:8.8.8.8"), True)
out = scan_with("::ffff:127.0.0.1")
check("on the production path the mapped literal records origin=self",
      out["scan_origin"], "self")
out = scan_with(host.upper())
check("and so does the hostname in capitals", out["scan_origin"], "self")


print("\n[2] PS-26: a declaration holds under every spelling of the device")
me.save_known_device(ip="127.0.0.1", mac="00:00:00:00:00:01", known_as="this host")
me.declare_expected_port("127.0.0.1", 8888, "test listener", clear_existing=False)
for spelling in ("localhost", "127.0.0.2", host, "::ffff:127.0.0.1"):
    out = scan_with(spelling, tcp_open=(8888,))
    row = (out["open_ports"] or [{}])[0]
    check(f"declared on 127.0.0.1, scanned as {spelling!r}: expected",
          bool(row.get("expected")), True)

me.save_known_device(ip="localhost", mac="00:00:00:00:00:02", known_as="alias row")
me.declare_expected_port("localhost", 9999, "declared on the alias",
                         clear_existing=False)
out = scan_with("127.0.0.1", tcp_open=(9999,))
check("declared on 'localhost', scanned as 127.0.0.1: expected",
      bool((out["open_ports"] or [{}])[0].get("expected")), True)
out = scan_with("127.0.0.1", tcp_open=(7777,))
check("an undeclared port still raises", (out["open_ports"] or [{}])[0].get("expected"), None)

with mock.patch.object(socket, "getaddrinfo",
                       fake_gai({"echo.test": ["192.0.2.23"]})):
    keys = ps._device_keys("echo.test", "remote")
check("a remote name is looked up under its resolved address too",
      keys[0] == "echo.test" and "192.0.2.23" in keys, True)
check("a remote scan never borrows this machine's declarations",
      "127.0.0.1" in ps._device_keys("192.0.2.23", "remote"), False)


print("\n[3] PS-27: a SYN pass that dies after sending says what it sent")
engines = []


class DyingEngine:
    """The first batch sends and hears; the second cannot open."""
    def __init__(self, *a, families=None, **k):
        self.families = families
        self.teardowns = 0
        self.asked = []
        engines.append(self)

    def __enter__(self):
        if len(engines) > 2:
            raise PermissionError("raw socket refused on the second batch")
        return self

    def __exit__(self, *a):
        return False

    def family_available(self, family):
        return True

    def refusal_reason(self, family):
        return ""

    def probe(self, family, src, dst, port):
        self.asked.append((dst, port))
        return True, None

    def finish(self):
        return {k: ("open" if k[1] == 22 else "closed") for k in self.asked}


ports = list(range(1, ps.SYN_BATCH_PROBES + 501))
syn = (ps.SYN_METHOD, "raw socket available", None)
with mock.patch.object(ps, "SynScanEngine", DyingEngine), \
        mock.patch.object(ps, "SYN_PACE_SECONDS", 0), \
        mock.patch.object(ps, "resolve_tcp_method", lambda cfg: syn), \
        mock.patch.object(ps, "tcp_method_setting", lambda cfg: ("auto", "k", None)), \
        mock.patch.object(ps.PortScanner, "_run_scan", lambda *a, **k: []):
    res = ps.PortScanner("t")._run_tcp_scan("127.0.0.1", ports, "self", False)
check("it fell back to connect", res["method"], ps.CONNECT_METHOD)
check("the reason no longer says no SYN was sent",
      "No SYN was sent" in res["method_reason"], False)
check("it names how many were sent",
      f"already sent {ps.SYN_BATCH_PROBES} SYNs" in res["method_reason"], True)
partial = res.get("syn_before_fallback") or {}
check("the SYN half's count travels", partial.get("sent"), ps.SYN_BATCH_PROBES)
check("and its answers", (partial.get("open"), len(partial.get("closed") or [])),
      ([22], ps.SYN_BATCH_PROBES - 1))
check("the run's sent counts both halves", res["sent"],
      len(ports) + ps.SYN_BATCH_PROBES)

engines.clear()


class DeadEngine(DyingEngine):
    def __enter__(self):
        raise PermissionError("no raw socket at all")


with mock.patch.object(ps, "SynScanEngine", DeadEngine), \
        mock.patch.object(ps, "resolve_tcp_method", lambda cfg: syn), \
        mock.patch.object(ps, "tcp_method_setting", lambda cfg: ("auto", "k", None)), \
        mock.patch.object(ps.PortScanner, "_run_scan", lambda *a, **k: []):
    res = ps.PortScanner("t")._run_tcp_scan("127.0.0.1", [22], "self", False)
check("a pass that sent nothing still says so",
      "No SYN was sent" in res["method_reason"], True)
check("and carries no SYN half", res.get("syn_before_fallback"), None)

run_id = me.start_port_scan_run("t", "127.0.0.1", port_count=80)
me.finish_port_scan_run(run_id, port_count=10080)
with sqlite3.connect(db) as c:
    got = c.execute("SELECT port_count, finished_at IS NOT NULL FROM port_scan_run "
                    "WHERE id = ?", (run_id,)).fetchone()
check("the run row takes the corrected count", tuple(got), (10080, 1))
run_id = me.start_port_scan_run("t", "127.0.0.1", port_count=80)
me.finish_port_scan_run(run_id)
with sqlite3.connect(db) as c:
    got = c.execute("SELECT port_count FROM port_scan_run WHERE id = ?",
                    (run_id,)).fetchone()[0]
check("and keeps its own count when none is given", got, 80)


def tcp_after_fallback(self, target, ports, scan_origin, public):
    return {"open": [], "closed": [], "no_answer": [], "failed": [],
            "method": ps.CONNECT_METHOD, "method_reason": "stub",
            "sent": len(ports) + 500, "teardowns": 0,
            "syn_before_fallback": {"sent": 500, "teardowns": 0, "open": [],
                                    "closed": [], "error": "stub"}}


with mock.patch.object(ps.PortScanner, "_run_tcp_scan", tcp_after_fallback), \
        mock.patch.object(ps.PortScanner, "_run_udp_scan",
                          lambda *a, **k: {"open": [], "closed": [], "silent": [],
                                           "failed": []}), \
        mock.patch.object(ps, "kernel_view", lambda *a, **k: {}):
    out = ps.PortScanner("t").scan("127.0.0.1", port_set="common")
planned = out["scanned"] + out["udp_scanned"]
with sqlite3.connect(db) as c:
    got = c.execute("SELECT port_count FROM port_scan_run ORDER BY id DESC "
                    "LIMIT 1").fetchone()[0]
check("a scan that fell back records both halves on its run row", got, planned + 500)
check("and the payload carries the SYN half",
      (out.get("tcp_syn_before_fallback") or {}).get("sent"), 500)


print("\n[4] PS-28: an engine opens only the families its pass needs")
eng = ps.SynScanEngine(families=[socket.AF_INET])
try:
    eng.open()
except PermissionError:
    pass
tried = set(eng._refused) | set(eng._sockets)
eng.close()
check("a v4 engine never touches the v6 family", tried, {socket.AF_INET})

engines.clear()


class CountingEngine(DyingEngine):
    def __enter__(self):
        return self


with mock.patch.object(ps, "SynScanEngine", CountingEngine), \
        mock.patch.object(ps, "SYN_PACE_SECONDS", 0), \
        mock.patch.object(ps, "source_address_for", lambda a, f: ("127.0.0.1", None)):
    ps.PortScanner("t")._run_syn_scan("127.0.0.1", [22, 80], "self", False)
check("every engine of a v4 pass asked for v4 only",
      {tuple(e.families or ()) for e in engines}, {(socket.AF_INET,)})


print("\n[5] PS-29: the probe identity does not come from the shared PRNG")
src = inspect.getsource(ps.SynScanEngine)
check("no module-level random call in the engine",
      "random.randint" in src or "random.getrandbits" in src, False)
check("the engine's source is the OS", isinstance(ps._SYN_RNG, ps.random.SystemRandom), True)
import random                               # noqa: E402
seen = set()
for _ in range(4):
    random.seed(1234)
    seen.add(ps.SynScanEngine()._next_port)
check("seeding the shared PRNG does not fix the source port", len(seen) > 1, True)


print("\n" + ("," * 60))
print("All port scanner round 4 checks passed." if not fails else f"{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
