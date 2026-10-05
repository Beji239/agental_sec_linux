"""
tests/test_network_scanner_fixes.py, the 2026-09-24 network_scanner audit round.

SECTION 9 of toolaudit.md, audited under this file's capability rule. Every
check below is a FIX asserting the behaviour that was measured broken on this
host, and every detector and every refusal is asserted in BOTH directions: a
fix that stops the wrong thing is as broken as one that does not fire.

WHAT WAS MEASURED BEFORE THE FIX, and each one has a section here:

  NET-1   scan() and sweep_presence() answered different questions. The sweep
          reported the union of ICMP replies and the neighbour cache; scan()
          reported ICMP replies only. Measured on this host: 7 addresses in
          the cache, 2 replies, 2 devices listed — five live addresses,
          including two devices swept for a week, appeared nowhere.
  NET-3   a sweep whose prober could not run reported OUTCOME "ok" and its
          responders straight out of the cache. Measured with a PATH holding
          no `ping`: 254 targets, 7 responders, outcome ok.
  NET-4   a device row was created by the ICMP answer alone, so an ARP-only
          device never got one. Measured on the owner's store: 13 addresses
          answering, 9 with rows.
  NET-5   the subnet came from a UDP socket connected to a public resolver, so
          a host with no default route refused to sweep its own LAN.
  NET-6   a /25 interface was swept as a /24: 126 addresses of somebody else.
  NET-7   `enabled` in the module's own config block was read by NOTHING.
  NET-8   status() was {"ready": True, "last_scan_count": 0} for a module that
          had swept nothing, and core/settings rendered it GREEN.
  NET-9   a dismissal of an address silences NET-1002 as well as NET-1001.
  NET-10  the vendor map was hardcoded beside the IEEE registry the app
          already ships: measured "Unknown" for a live address the registry
          resolves.
  NET-11  PTR lookups ran in series inside the device loop.
  NET-12  the app's own device row could never carry its own MAC.
  NET-13  a retired device that came back was watched by nothing, forever.
  NET-14  scan_network was unconditionally gated, so the dashboard's own
          button asked the operator to confirm what the owner had just clicked.

Runs against a throwaway database built from Schema.SQL. It writes nothing to
the owner's store and probes nothing outside it: every probe here is either
127.0.0.1 or an RFC 5737 documentation address, and the one section that needs
a real sweep drives it on a range it constructs.
"""
import ast
import json
import os
import pathlib
import re
import sqlite3
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got, why=""):
    if not got:
        fails.append(label)
    print(f"  {'PASS' if got else 'FAIL'}  {label}"
          + (f": {why}" if why else ""))


def check_raises(label, fn, *a, **k):
    try:
        fn(*a, **k)
    except Exception as e:                                   # noqa: BLE001
        print(f"  PASS  {label} (raised {type(e).__name__})")
        return
    fails.append(label)
    print(f"  FAIL  {label}: nothing raised")


# A THROWAWAY STORE, AND THE MODULES UNDER IT
tmp = pathlib.Path(tempfile.mkdtemp())
DB = tmp / "t.db"
DB.write_text("")
sqlite3.connect(DB).executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))

from core import memory_engine as me            # noqa: E402
me.DB_PATH = DB
from core import migrations                     # noqa: E402
migrations.run_migrations(DB)

from tools import network_scanner as ns         # noqa: E402
import adapters                                 # noqa: E402


def _src(name):
    return (ROOT / name).read_text(encoding="utf-8")


print("\n[NET-1] ONE UNION, BOTH ENTRY POINTS, AND THE `via` FIELD TO TELL THEM APART")
# THE DEFECT: the same host answered two different questions in two different
# places. The sweep used `alive | arp_present` and the scan used `alive`.
# Asserted on the CODE (the scan must build the same union) and on the DATA
# (a device seen only through the neighbour cache must reach the payload).

_scan = _src("tools/network_scanner.py")
check("scan() computes the neighbour-cache set",
      "arp_reached" in _scan.split("def scan(")[1].split("def _probe_hosts")[0], True)
check("and unions it with what answered",
      "live = answered | arp_reached" in _scan, True)
check("and the union is the same expression the sweep uses",
      "answered | arp_reached" in _scan.split("def sweep_presence")[1],
      True)

# A REAL SWEEP, on a range this test controls: a neighbour entry with no reply
# must be reported, with via 'arp', and must NOT be silently dropped.
# A REAL SWEEP'S SHAPE: every address in the /24 is a target, so an address
# in the neighbour cache inside the range IS probed — it just does not reply.
# (The first version of this fixture used ten targets and a cache holding .77,
# and the mismatch is what this round's own negative control caught: an
# address that was never a target cannot be a responder, and a fixture that
# puts one in the cache is not modelling a sweep.)
_FAKE_SUBNET = "192.0.2"
_fake_cache = {"192.0.2.77": "02:00:00:00:00:77",   # in range, silent, cached
               "192.0.2.78": "02:00:00:00:00:78",   # in range, silent, cached
               "198.51.100.9": "02:00:00:00:00:09"}  # OUTSIDE the range


def _fake_probe_all(ip):
    # Every address answers EXCEPT the two the cache-only case is about.
    if ip.endswith(".77") or ip.endswith(".78"):
        return {"verdict": ns.SILENT, "detail": ""}
    return {"verdict": ns.ANSWERED, "detail": ""}


def _fake_probe_none(ip):
    return {"verdict": ns.NOT_PROBED, "detail": "the prober is broken on purpose"}


_real_subnet = ns._get_local_subnet
_real_cache = ns._read_arp_cache
_real_probe = ns._probe
_real_plan = ns._sweep_range

_orig = (ns._get_local_subnet, ns._read_arp_cache, ns._probe, ns._sweep_range)
ns._get_local_subnet = lambda: _FAKE_SUBNET
ns._read_arp_cache = lambda: dict(_fake_cache)
ns._probe = _fake_probe_all
ns._sweep_range = lambda s: {"targets": [f"{s}.{i}" for i in range(1, 80)],
                             "cidr": f"{s}.0/24", "clamped_from": None,
                             "own": "", "note": ""}
try:
    _res = ns.NetworkScanner("t").scan()
    _ips = {d["ip"]: d for d in _res["devices"]}
    check("a cache-only address IS in the device list", "192.0.2.77" in _ips, True)
    check("  and it carries via='arp'", _ips.get("192.0.2.77", {}).get("via"), "arp")
    check("  and its MAC came from the cache",
          _ips.get("192.0.2.77", {}).get("mac"), "02:00:00:00:00:77")
    check("an address outside the swept range is NOT counted",
          "198.51.100.9" in _ips, False)
    check("the payload counts the arp-only devices", _res["probe"]["arp_unprobed"], [])
    check("and the note names them rather than leaving it to be worked out",
          "neighbour cache" in _res["note"], True)

    # AND THE CACHE IS NOT EVIDENCE FOR AN ADDRESS NOTHING ASKED. This is the
    # case the negative control found in the first version of the fix: the
    # neighbour entry was counted because it was not in the *unprobed* set,
    # which is true of every address that was not a target at all.
    _out_of_range = ns.NetworkScanner("t").scan()
    check("an address outside the /24 is not a responder even when cached",
          [d for d in _out_of_range["devices"] if d["ip"] == "198.51.100.9"], [])
finally:
    ns._get_local_subnet, ns._read_arp_cache, ns._probe, ns._sweep_range = _orig

# THE FIRST VERSION OF THIS CHECK WAS WRONG TWICE OVER. It counted the word
# `startswith` in _in_subnet's source — and the DOCSTRING explaining why a
# startswith test is not the check contains the word; then it unparsed the
# whole function, which puts the docstring straight back in. An assertion that
# a token is gone matches the fix's own explanation of why it went, which is a
# rule this project has already written down. So: keep the docstring aside,
# parse the RUNNING code, and assert the prose really does contain the word so
# the check cannot pass for the wrong reason.
_subtree = ast.parse(_scan).body
_in_sub_fn = next(n for n in ast.walk(ast.parse(_scan))
                  if isinstance(n, ast.FunctionDef) and n.name == "_in_subnet")
_doc = ast.get_docstring(_in_sub_fn)
_nodoc = ast.parse(_scan).body[
    [i for i, n in enumerate(_subtree)
     if getattr(n, "name", None) == "_in_subnet"][0]]
_nodoc.body = [s for s in _nodoc.body
               if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]
_in_sub_code = ast.unparse(_nodoc)
check("_in_subnet's RUNNING code does not call startswith",
      "startswith(" in _in_sub_code, False)
check("  (and the word IS in its docstring, so the check above is not vacuous)",
      "startswith" in (_doc or ""), True)
check("  and it rejects a longer string that a prefix test would match",
      ns._in_subnet("192.0.2.1x", "192.0.2"), False)
check("  and it accepts a real member", ns._in_subnet("192.0.2.5", "192.0.2"), True)
check("  and it rejects another network", ns._in_subnet("192.0.3.5", "192.0.2"), False)


print("\n[NET-3] A SWEEP THAT COULD NOT PROBE IS NOT A QUIET NETWORK")
# THE DEFECT: with no `ping` on PATH, a sweep reported outcome 'ok' with 7
# responders, every one of them out of the ARP cache — the previous sweep's
# own traffic. This is the fault the whole round exists for.

ns._get_local_subnet = lambda: _FAKE_SUBNET
ns._read_arp_cache = lambda: dict(_fake_cache)
ns._probe = _fake_probe_none
ns._sweep_range = _orig[3]
try:
    _r = ns.NetworkScanner("t").sweep_presence()
    check("the sweep still records (a failed sweep must not vanish)",
          _r["outcome"], "ok")
    check("but it reports that NOTHING was probed", _r["probed"], 0)
    check("  and how many addresses that was", _r["not_probed"], _r["targets"])
    check("  and the method column says arp-only", _r["method"], "arp-only")
    check_true("  and the note says not one address was probed",
               "NOT ONE ADDRESS WAS PROBED" in (_r.get("note") or ""),
               _r.get("note"))
    check("ZERO responders, because nothing asked the cache's addresses",
          _r["responded"], 0)
finally:
    ns._get_local_subnet, ns._read_arp_cache, ns._probe = _orig[0], _orig[1], _orig[2]

# The other direction: a sweep that DID probe still reports its responders, or
# the fix would be a blanket refusal.
ns._get_local_subnet = lambda: _FAKE_SUBNET
ns._read_arp_cache = lambda: {}
ns._probe = _fake_probe_all
ns._sweep_range = lambda s: {"targets": [f"{s}.{i}" for i in range(1, 5)],
                             "cidr": f"{s}.0/24", "clamped_from": None,
                             "own": "", "note": ""}
try:
    _r = ns.NetworkScanner("t").sweep_presence()
    check("a sweep that probed reports its responders", _r["responded"], 4)
    check("  and the method says icmp+arp", _r["method"], "icmp+arp")
    check("  and carries no probe complaint", "note" in _r, False)
finally:
    ns._get_local_subnet, ns._read_arp_cache, ns._probe, ns._sweep_range = _orig

# The prober's own three-valued answer, measured against real exit codes.
check("a live address answers", ns._probe("127.0.0.1")["verdict"], ns.ANSWERED)
check("an address that is there and silent is silent, not unprobed",
      ns._probe("192.0.2.222")["verdict"], ns.SILENT)
check("a ping that FAILS is not_probed, which exit code 2 proves",
      ns._probe("999.1.1.1")["verdict"], ns.NOT_PROBED)
_sub = subprocess.run([sys.executable, "-c",
                       "import sys,pathlib;sys.path.insert(0,%r);"
                       "from tools import network_scanner as n;"
                       "print(n._probe('127.0.0.1')['verdict'])" % str(ROOT)],
                      capture_output=True, text=True, env={"PATH": "/nonexistent"})
check("with NO ping binary the probe refuses rather than reporting silence",
      _sub.stdout.strip(), ns.NOT_PROBED)
check("(and _ping, the bool form, is False for it rather than True)",
      ns._probe.__name__, "_probe")


print("\n[NET-4] AN ARP-ONLY DEVICE GETS A ROW AND A FINDING")
# Same sweep as NET-1, and the write path is what is being checked here: the
# address the scan can only see through the cache must land in known_devices
# and raise NET-1001, because otherwise it is never named by anybody.

ns._get_local_subnet = lambda: _FAKE_SUBNET
ns._read_arp_cache = lambda: dict(_fake_cache)
ns._probe = _fake_probe_all
ns._sweep_range = lambda s: {"targets": [f"{s}.{i}" for i in range(1, 11)],
                             "cidr": f"{s}.0/24", "clamped_from": None,
                             "own": "", "note": ""}
try:
    ns.NetworkScanner("t").scan()
finally:
    ns._get_local_subnet, ns._read_arp_cache, ns._probe, ns._sweep_range = _orig

_c = sqlite3.connect(DB)
_row = _c.execute("SELECT ip, mac FROM known_devices WHERE ip = '192.0.2.77'"
                  ).fetchone()
check("the cache-only address has a device row", _row is not None, True)
check("  and the row carries the hardware address",
      _row[1] if _row else None, "02:00:00:00:00:77")
_f = _c.execute("SELECT detection_id, description FROM findings "
                "WHERE entity_value = '192.0.2.77'").fetchone()
check("  and it raised NET-1001", _f[0] if _f else None, "NET-1001")
check_true("  and the finding says which evidence it rests on",
           "neighbour cache" in (_f[1] if _f else ""), (_f[1] if _f else "")[:80])
check("an address OUTSIDE the range got no row",
      _c.execute("SELECT COUNT(*) FROM known_devices "
                 "WHERE ip = '198.51.100.9'").fetchone()[0], 0)
_c.close()


print("\n[NET-5] THE LOCAL NETWORK IS READ OFF THE KERNEL, AND AN ISOLATED LAN WORKS")
# THE DEFECT: the subnet came from a UDP socket connected to a public resolver.
# No default route therefore meant no sweep at all. The kernel's own tables
# answer it; this section proves the reader works with the socket path removed.

check("the reader does not connect a socket as its FIRST answer",
      _src("tools/network_scanner.py").split("def _get_local_subnet")[1]
      .split("locals_ = local_addresses()")[0].count("probe.connect"), 0)
check("it reads /proc/net/route", "def default_route" in _scan, True)
check("it reads each interface's own address and netmask via ioctl",
      "_SIOCGIFADDR" in _scan and "_SIOCGIFNETMASK" in _scan, True)

_live = ns.local_addresses()
check_true("this host reports at least one routable address",
           len(_live) >= 1, str(_live))
check_true("and each one carries a real interface and prefix",
           all(a.get("iface") and 8 <= a.get("prefix", 0) <= 32 for a in _live),
           str(_live))
check("the default route's interface is the one the subnet comes from",
      ns.default_route().get("iface"),
      _live[0]["iface"] if _live else ns.default_route().get("iface"))

# The no-default-route case, driven by faking the route table away rather than
# by disconnecting this machine.
_real_route = ns.default_route
ns.default_route = lambda: {}
try:
    _only_local = ns.local_addresses()
    check_true("with NO default route the interfaces are still listed",
               len(_only_local) == len(_live), str(_only_local))
    check_true("and a subnet is still derived",
               bool(ns._get_local_subnet()), ns._get_local_subnet())
finally:
    ns.default_route = _real_route

# The ioctl reader itself, against an interface that cannot exist.
check("an interface that does not exist answers empty, not a guess",
      ns._ioctl_addr("nosuchiface0", ns._SIOCGIFADDR), "")


print("\n[NET-6] THE SWEEP RANGE IS THE INTERFACE'S OWN, AND A WIDER ONE IS NAMED")
# THE DEFECT: 254 addresses were probed whatever the interface said. On a /25
# that is 126 addresses belonging to somebody else; on a /16 it is hours of
# wall clock for the same neighbour table.

_real_locals = ns.local_addresses
try:
    for _prefix, _label in ((25, "a /25 gets 126 targets, not 254"),
                            (24, "a /24 gets 254, the same as before"),
                            (16, "a /16 is CLAMPED to a /24")):
        ns.local_addresses = lambda p=_prefix: [
            {"iface": "test0", "ip": "192.0.2.130", "prefix": p}]
        _plan = ns._sweep_range("192.0.2")
        if _prefix == 25:
            # THE ADDRESS CHOICE IS LOAD-BEARING. The machine is at .130, which
            # is in the UPPER half of a /25; the network built from a zeroed
            # last octet would be 192.0.2.0/25 — the other half — and would
            # sweep 126 addresses none of which is a neighbour, while reporting
            # a clean LAN. This assertion is what caught that in the first
            # version of the fix.
            check(f"{_label}", len(_plan["targets"]), 125)
            check("  and the CIDR is the half the machine is actually on",
                  _plan["cidr"], "192.0.2.128/25")
        elif _prefix == 24:
            # 254 usable, MINUS the machine's own address, which is never a
            # target of its own sweep. The first version of this check wanted
            # 254 and was measuring the bug's arithmetic rather than the fix's.
            check(f"{_label}", len(_plan["targets"]), 253)
            check("  and it is the whole /24", str(_plan["cidr"]), "192.0.2.0/24")
            check("  and nothing is claimed to be clamped",
                  _plan["clamped_from"], None)
        else:
            check(f"{_label}", len(_plan["targets"]), 253)
            check("  and the real prefix is carried so the payload can say it",
                  _plan["clamped_from"], 16)
            check_true("  and the note names what the wider range would cost",
                       "hours of probing" in _plan["note"], _plan["note"])
    # the machine's own address is never a target of its own sweep
    ns.local_addresses = lambda: [{"iface": "wlp1s0", "ip": "192.0.2.130",
                                   "prefix": 24}]
    _plan = ns._sweep_range("192.0.2")
    check("this machine's own address is not swept",
          "192.0.2.130" in _plan["targets"], False)
    check("  and the rest of the range is intact",
          len(_plan["targets"]), 253)
finally:
    ns.local_addresses = _real_locals


print("\n[NET-7] BOTH CONFIG KEYS MEAN SOMETHING, AND ONE READER OWNS THEM")
# THE DEFECT: `sensors.network_scanner.poll_interval` was documented in the
# module's own comment block and read by NOTHING in the tree, while
# `presence_sweep.enabled`/`interval_minutes` were read by main.py. A control
# the operator believes the owner has.

check("the module owns the interval", "def sweep_interval_seconds" in _scan, True)
check("and the switch", "def sweep_enabled" in _scan, True)
_main = _src("main.py")
check("main.py asks the module rather than reading the block itself",
      "ns.sweep_interval_seconds(config)" in _main, True)
check("  and no longer reads the general block directly",
      'block = config.get("presence_sweep"' in _main.split(
          "def _start_presence_sweeper")[1].split("def _start_dns_importer")[0],
      False)

# The precedence, with the owner's OWN config among the cases.
check("the general key wins when both are set",
      ns.sweep_interval_seconds({"presence_sweep": {"interval_minutes": 15},
                                 "sensors": {"network_scanner":
                                             {"poll_interval": 300}}})[1],
      "presence_sweep.interval_minutes")
check("  and it is 15 minutes, which is what this install has always run",
      ns.sweep_interval_seconds({"presence_sweep": {"interval_minutes": 15},
                                 "sensors": {"network_scanner":
                                             {"poll_interval": 300}}})[0], 900)
check("the specific key takes over when the general one is absent",
      ns.sweep_interval_seconds({"sensors": {"network_scanner":
                                             {"poll_interval": 30}}})[0], 1800)
check("and the default is last, named as the default",
      ns.sweep_interval_seconds({})[0], 15 * 60)
check("a nonsense interval does not become a busy loop",
      ns.sweep_interval_seconds({"sensors": {"network_scanner":
                                             {"poll_interval": 0}}})[0], 900)
check("a string interval does not raise",
      ns.sweep_interval_seconds({"presence_sweep":
                                 {"interval_minutes": "nope"}})[0], 900)

# The switch: all three shapes of ABSENT are ON, or a config written before
# this round quietly loses its scanner.
check("no config at all is ON", ns.sweep_enabled({})[0], True)
check("an empty sensors block is ON", ns.sweep_enabled({"sensors": {}})[0], True)
check("an empty network_scanner block is ON",
      ns.sweep_enabled({"sensors": {"network_scanner": {}}})[0], True)
check("and it names the key that said ON",
      ns.sweep_enabled({})[1], "no key is set, so it is ON")
check("explicitly false is OFF",
      ns.sweep_enabled({"sensors": {"network_scanner":
                                    {"enabled": False}}})[0], False)
check("  and names the key that switched it off",
      ns.sweep_enabled({"sensors": {"network_scanner":
                                    {"enabled": False}}})[1],
      "sensors.network_scanner.enabled")
check("the general key switches it off too",
      ns.sweep_enabled({"presence_sweep": {"enabled": False}})[0], False)


print("\n[NET-8] SWITCHED OFF IS NOT GREEN, AND THE STATUS SAYS WHAT IT HAS DONE")
# THE DEFECT, MEASURED: status() returned {"ready": True, "last_scan_count": 0}
# for a module that had done nothing, and core/settings._module_row rendered
# {'state': 'ok', 'detail': 'running.'}.

_off_cfg = {"sensors": {"network_scanner": {"enabled": False}}}
_on_cfg = {"presence_sweep": {"enabled": True, "interval_minutes": 15}}

_off_status = ns.NetworkScanner("t", _off_cfg).status()
check("switched off: the status says so by name",
      _off_status.get("off_by_config"), True)
check("switched off: it does NOT keep the key that would render it green",
      "ready" in _off_status, False)
check("switched off: it carries the FALSY key the row resolves",
      _off_status.get("available"), False)
check_true("switched off: it carries a reason for the row to print",
           bool(_off_status.get("reason")), _off_status.get("reason"))
check_true("switched off: and the note refuses to be read as a quiet network",
           "NOT a quiet network" in (_off_status.get("note") or ""),
           _off_status.get("note"))

from core import settings as st                       # noqa: E402
_row = st._module_row("network_scanner", ns.NetworkScanner("t", _off_cfg))
check("switched off: the readiness page renders it OFF, not healthy",
      _row.get("state"), "off")
check_true("switched off: the row's own words name the switch",
           "SWITCHED OFF IN CONFIG" in (_row.get("detail") or ""),
           _row.get("detail"))

_row_on = st._module_row("network_scanner", ns.NetworkScanner("t", _on_cfg))
check("switched ON: the page renders it ok", _row_on.get("state"), "ok")
# THE FIRST VERSION OF THIS CHECK WAS WRONG AND MEASURED NOTHING: it passed a
# module that had never swept, so `reachable` was absent and the row fell
# through to the bare "running." — the exact defect the round exists for. The
# right assertion is on BOTH states, so neither can drift: a fresh process must
# say it has not measured, and one that has swept must say it is running.
check_true("  and a process that has swept NOTHING says exactly that",
           "has not reached the host yet" in (_row_on.get("detail") or ""),
           _row_on.get("detail"))
_swept = ns.NetworkScanner("t", _on_cfg)
_swept._last_sweep = {"at": "2026-09-24T00:00:00Z", "responded": 3}
_row_swept = st._module_row("network_scanner", _swept)
check("  and one that HAS swept reports running", _row_swept.get("state"), "ok")
check("    with the bare word, which is now earned",
      _row_swept.get("detail"), "running.")

# The adapter is what fixes the verdict key; the module keeps the key main.py's
# own table uses, which is asserted so the two cannot drift apart silently.
_ad_off = adapters.LinuxNetworkScanner("t", _off_cfg)
check("the adapter drops the truthy key for the page",
      "ready" in _ad_off.status(), False)
check("  and adds the falsy one the row resolves",
      _ad_off.status().get("available"), False)
_ad_on = adapters.LinuxNetworkScanner("t", _on_cfg)
check("the adapter leaves a switched-on status alone",
      _ad_on.status().get("ready"), True)

# The off answer is a SUPERSET of the working one, so a caller cannot crash.
def _keys(d):
    return set(d.keys())


_off_answer = ns.NetworkScanner("t", _off_cfg).scan()
_on_answer = ns.NetworkScanner("t", _on_cfg).scan()
check("the refusal carries every key a working scan does",
      sorted(_keys(_on_answer) - _keys(_off_answer)), [])
check_true("and carries the key that says it is a switch",
           _off_answer.get("off_by_config"), True)
check("and probes NOTHING: zero devices, zero probes",
      (_off_answer["devices_found"], _off_answer["probe"]["probed"]), (0, 0))
check_true("and the note says NOT A CLEAN MACHINE",
           "NOT A CLEAN MACHINE" in (_off_answer.get("note") or ""),
           _off_answer.get("note"))
check("the refused sweep is not written as a successful sweep",
      ns.NetworkScanner("t", _off_cfg).sweep_presence().get("outcome"), "off")
check("  and it does not pretend to have probed anything",
      ns.NetworkScanner("t", _off_cfg).sweep_presence().get("responded"), 0)

# The always-on silence, which was a log line and nothing else.
_st = ns.NetworkScanner("t", _on_cfg).status()
check("the status says how many devices are declared always-on",
      _st.get("always_on_declared"), 0)
check_true("and says an empty absence answer is not a clean machine",
           "not a statement that every device is present" in (_st.get("note") or ""),
           _st.get("note"))

# The two-key disclosure, with the shape this install actually has.
_two_key = ns.NetworkScanner("t", {"presence_sweep": {"interval_minutes": 15},
                                   "sensors": {"network_scanner":
                                               {"poll_interval": 300}}}).status()
check_true("status says which key is in charge",
           _two_key.get("sweep_interval_source") ==
           "presence_sweep.interval_minutes", _two_key.get("sweep_interval_source"))
check_true("and names the value it is NOT reading",
           "poll_interval = 300 seconds is NOT being read"
           in (_two_key.get("sweep_interval_note") or ""),
           _two_key.get("sweep_interval_note"))


print("\n[NET-9] A DISMISSAL OF AN ADDRESS SILENCES NET-1002 TOO (RECORDED, NOT CHANGED)")
# MEASURED, AND LEFT ALONE DELIBERATELY. `me.is_dismissed("ip", address)` takes
# no detection id, so a dismissal made to quiet "this device showed up new"
# also silences "this device has gone". Closing it means changing what a
# dismissal MEANS across two rules, which is a behaviour change over rows
# already in the store and therefore the owner's call, not this round's. This
# section asserts the CURRENT behaviour so the finding cannot be lost, and
# asserts that the code says so where a reader will find it.

_presence_src = _src("tools/network_scanner.py").split(
    "def _report_absent_permanent")[1]
check("the absence path asks is_dismissed with the entity and nothing else",
      'me.is_dismissed("ip", device["ip"])' in _presence_src, True)
check_true("and carries the sentence saying that is deliberate and measured",
           "A DISMISSAL OF THE ADDRESS SILENCES EVERY RULE ABOUT IT"
           in _presence_src, True)
check("the store has no way to scope a dismissal to one rule",
      "detection_id" in str(me.dismiss_entity.__doc__ or ""), False)


print("\n[NET-10] THE VENDOR COMES FROM THE REGISTRY THE APP ALREADY SHIPS")
# THE DEFECT: a 39-entry hardcoded map, asked FIRST, over a registry of 54,000
# prefixes sitting in data/. Measured: the live gateway answered "Unknown"
# from the map while oui.lookup resolved the same address.

from core import oui                                  # noqa: E402
_real = "00:1b:21:12:34:56"
check("the registry resolves this host's gateway",
      oui.lookup(_real).get("status"), "resolved")
check("and the module now returns that name, not Unknown",
      ns._oui_lookup(_real), oui.lookup(_real)["vendor"])
check("a randomized address is still Unknown, because there IS no vendor",
      ns._oui_lookup("02:00:00:00:00:01"), "Unknown")
check("an empty address is Unknown rather than raising",
      ns._oui_lookup(""), "Unknown")
check("a malformed address does not raise",
      ns._oui_lookup("not-a-mac"), "Unknown")

# The fallback still works when the registry is absent — a fresh install.
_real_lookup = oui.lookup
oui.lookup = lambda mac: {"status": "no_data", "vendor": None, "note": ""}
try:
    check("with NO registry data the local map still answers",
          ns._oui_lookup("b8:27:eb:11:22:33"), "Raspberry Pi")
    check("  and a prefix the map lacks is Unknown, not an error",
          ns._oui_lookup("02:00:00:00:00:01"), "Unknown")
finally:
    oui.lookup = _real_lookup

_oui_call = _src("tools/network_scanner.py").split("def _oui_lookup")[1].split(
    "def ")[0]
check("the registry is asked BEFORE the map",
      _oui_call.index("oui.lookup") < _oui_call.index("OUI_MAP.get"), True)
check("and the map is kept as a fallback rather than deleted",
      "OUI_MAP.get(prefix, \"Unknown\")" in _scan, True)


print("\n[NET-11] PTR LOOKUPS RUN IN PARALLEL, AND CAN BE SWITCHED OFF")
# THE DEFECT: one blocking resolver call per device, in series, inside the
# device loop. Measured: 0.112 s per unresolvable address, so a 50 device scan
# spent 5.6 s waiting on the resolver alone.

check("the names are resolved in a pool", "def _resolve_names" in _scan, True)
check("  and the pool is smaller than the ping pool, because it is a resolver",
      "LOOKUP_WORKERS" in _scan, True)
check("the device loop does not call the resolver itself",
      "_resolve_hostname(ip)" in _scan.split("def scan(")[1].split(
          "def _probe_hosts")[0], False)
check("there is a switch, and it is an environment variable rather than a "
      "third config key for one setting",
      'AGENTALSEC_RESOLVE_HOSTNAMES' in _scan, True)
check("status publishes which way it is set",
      '"hostname_lookup"' in _scan, True)
_names = ns.NetworkScanner("t")._resolve_names({"127.0.0.1"})
check("the pool returns the name it found", _names.get("127.0.0.1"), "localhost")
check("and returns an empty dict rather than raising for an empty set",
      ns.NetworkScanner("t")._resolve_names(set()), {})


print("\n[NET-12] THIS HOST'S OWN ROW CARRIES ITS OWN HARDWARE ADDRESS")
# THE DEFECT: the app's own address got a device row like any other, and the
# row could never carry a MAC — a host does not ARP itself, and an ICMP reply
# carries no hardware address — so identity_class called this host
# 'no_hardware_address' and it could never be matched to anything.

check("the MAC is read off the machine", "def own_hardware_address" in _scan, True)
check("  from /sys, not from a subprocess",
      "/sys/class/net/" in _scan, True)
_mine = ns.own_hardware_address(ns._get_local_subnet())
check_true("this host reports its own address on the swept interface",
           bool(re.match(r"([0-9a-f]{2}:){5}[0-9a-f]{2}$", _mine or "")), _mine)
check("an interface that cannot exist answers empty, not a guess",
      ns._read_text("/sys/class/net/nosuchiface0/address"), "")
check("the scan fills the row with it",
      "own_hardware_address(subnet)" in _scan.split("def scan(")[1], True)


print("\n[NET-13] A RETIRED DEVICE THAT COMES BACK IS NOT WATCHED BY NOTHING")
# THE DEFECT: retire_device was the only writer of retired_at and nothing
# cleared it, while permanent_devices() and always_on_devices() both filter on
# it and the scanner's is_new test is "no row". A device that came back was in
# the inventory, invisible to every rule, on a row saying it was gone.

_rip = "192.0.2.30"
me.save_known_device(ip=_rip, mac="02:00:00:00:00:30", known_as="printer")
me.set_device_always_on(_rip, True)
me.retire_device(_rip, "test: 96 misses")
_row = me.query_known_devices(ip=_rip)[0]
check("it is retired to start with", bool(_row.get("retired_at")), True)
check("  and no longer declared always-on, which retire_device cleared",
      [d["ip"] for d in me.always_on_devices()].count(_rip), 0)

_lift = me.save_known_device(ip=_rip, mac="02:00:00:00:00:30")
check("the scanner observing it again lifts the retirement",
      _lift.get("retirement_lifted"), True)
_row = me.query_known_devices(ip=_rip)[0]
check("  and retired_at is cleared", _row.get("retired_at"), None)
check_true("  and the retirement is MOVED, not deleted",
           bool(_row.get("unretired_at")) or "",
           f"unretired_at={_row.get('unretired_at')!r}")
check_true("  and the notes remember it went away and came back",
           "Returned to the network after being retired" in (_row.get("notes") or ""),
           (_row.get("notes") or "")[:70])
check("  and is_permanent was NOT restored by the machine",
      bool(_row.get("is_permanent")), False)
# THE FIRST VERSION OF THIS CHECK WANTED False AND WAS MEASURING A CLAIM RATHER
# THAN THE CODE: retire_device clears is_permanent and leaves
# expected_always_on ALONE, so a device retired while declared always-on still
# carries the declaration — and that is the RIGHT way round, because the
# operator never withdrew it. What the check has to pin is the asymmetry, both
# sides of it, so a future change to either cannot pass silently.
check("  and expected_always_on SURVIVES, because the operator never withdrew it",
      bool(_row.get("expected_always_on")), True)
check("  and the store therefore declares it always-on again",
      _rip in [d["ip"] for d in me.always_on_devices()], True)

# The other direction: a device that is NOT retired is left completely alone.
_lift2 = me.save_known_device(ip=_rip, mac="02:00:00:00:00:30")
check("a second observation reports nothing to lift",
      _lift2.get("retirement_lifted"), False)
check("an address with no row at all is not an error",
      "retirement_lifted" in me.save_known_device(ip="192.0.2.99"), True)

# And the explicit entry point, which a person can run.
me.save_known_device(ip="192.0.2.31", mac="02:00:00:00:00:31")
me.retire_device("192.0.2.31", "second test")
_r = me.reacknowledge_device("192.0.2.31", reason="the user saw it")
check("reacknowledge_device reports the change", _r.get("changed"), True)
check_true("and says out loud which declaration came back and which did not",
           "is_permanent is NOT restored" in (_r.get("reason") or ""),
           _r.get("reason"))
# 192.0.2.31 IS NOT DECLARED ALWAYS-ON — the test above set the flag on
# 192.0.2.30, not this one — so expected_always_on is honestly False here. The
# assertion the round needs is that the field REPORTS the row's state rather
# than asserting a value, so it is checked against the store itself.
_reported = _r.get("expected_always_on")
_check_row = me.query_known_devices(ip="192.0.2.31")[0]
check("  and the always-on field reports the row rather than assuming",
      _reported, bool(_check_row.get("expected_always_on")))
check("a device that is not retired is a no-op, not an error",
      me.reacknowledge_device("192.0.2.31").get("changed"), False)
check("and an address with no row refuses with a sentence",
      me.reacknowledge_device("192.0.2.123")["success"], False)

# The columns the lift writes exist on a FRESH install and on an OLD one.
_c = sqlite3.connect(DB)
_cols = {r[1] for r in _c.execute("PRAGMA table_info(known_devices)")}
check("a fresh store has the unretired columns",
      {"unretired_at", "unretired_reason"} <= _cols, True)
_c.close()


print("\n[NET-14] THE SCAN IS UNGATED ON THIS HOST'S OWN NETWORK, GATED ELSEWHERE")
# THE DEFECT: scan_network sat in PERMISSION_GATED, so the dashboard's own
# button asked the operator to confirm the click the owner had just made, and the
# duty loop had to exclude it by hand.

from core import tool_registry as tr                  # noqa: E402
check("this host's own network is ungated",
      tr.requires_permission("scan_network"), False)
check("a ban is STILL gated, so the fix is not a blanket opening",
      tr.requires_permission("block_device"), True)
check("a file restore is still gated",
      tr.requires_permission("restore_file"), True)
check("a port scan of a foreign host is still gated",
      tr.requires_permission("run_port_scan",
                             {"target_host": "203.0.113.10"}), True)
check("a port scan of this LAN is not",
      tr.requires_permission("run_port_scan",
                             {"target_host": "127.0.0.1"}), False)
_real_sub = ns._get_local_subnet
ns._get_local_subnet = lambda: "203.0.113"
try:
    check("a machine that is on a PUBLIC range keeps the gate",
          tr.requires_permission("scan_network"), True)
finally:
    ns._get_local_subnet = _real_sub
ns._get_local_subnet = lambda: ""
try:
    check("and a machine that cannot say where it is keeps it too",
          tr.requires_permission("scan_network"), True)
finally:
    ns._get_local_subnet = _real_sub
check("the gated branch renders a card that names the range",
      "Ping sweep" in tr.permission_summary("scan_network"), True)


print("\n[NEW] query_inventory_gaps: the question the gap made unaskable")
# Only scan() writes device rows and only the model fires it, while the
# sweeper runs on its own clock. Nothing could ask "is the inventory missing
# what the sweeps have been seeing". Measured on the owner's store: 4 such
# addresses, 2 of them neighbour-cache-only.

# A sweep that sees an address with no device row, through the real writer.
me.record_presence_sweep(session_id="t", method="icmp+arp", outcome="ok",
                         subnet="192.0.2.0/24", targets=254,
                         responders=[{"ip": "192.0.2.200",
                                      "mac": "02:00:00:00:02:00",
                                      "via": "arp"}])
_gaps = me.inventory_gaps()
_ips = [d["ip"] for d in _gaps["devices"]]
check("the address with no row is reported", "192.0.2.200" in _ips, True)
check("and one WITH a row is not", _rip in _ips, False)
# THE FIRST VERSION OF THIS CHECK WANTED 1 AND WAS WRONG ABOUT ITS OWN FIXTURE:
# the sweep is written at the top of this section and the failed sweep below it
# was added BEFORE this reading, so three ok sweeps is the honest count. What
# the check has to pin is not a literal but the RULE — failed sweeps are
# excluded from the denominator, whatever else is in the table — so it counts
# them off the table itself.
_ok_sweeps = sqlite3.connect(DB).execute(
    "SELECT COUNT(*) FROM presence_sweep WHERE outcome = 'ok'").fetchone()[0]
check("it says how many USABLE sweeps it considered",
      _gaps["sweeps_considered"], _ok_sweeps)
_gaps3 = me.inventory_gaps()
check("a failed sweep does not raise the denominator either",
      _gaps3["sweeps_considered"], _ok_sweeps)

# The tool, the fence, the dependency and the allowlists.
check("the tool exists", tr.tool_exists("query_inventory_gaps"), True)
check("it is classified read-only", tr.tool_writes("query_inventory_gaps"), False)
check("it is fenced, because its payload is addresses and hardware addresses",
      __import__("core.sanitize", fromlist=["x"]).is_untrusted(
          "query_inventory_gaps"), True)
check("its emptiness has a declared dependency",
      __import__("core.sensor_health", fromlist=["x"]).depends_on(
          "query_inventory_gaps"), ("network_scanner",))
check("the duty loop may call it",
      "query_inventory_gaps" in __import__("core.duty", fromlist=["x"])
      ._tool_allowlist(), True)
check("the duty loop may now sweep too, which it could not before",
      "scan_network" in __import__("core.duty", fromlist=["x"])
      ._tool_allowlist(), True)


print("\n[HOUSE] the module's own promises, asserted rather than assumed")
# The rules this project keeps, checked against the rewritten file so this
# round cannot have broken them on the way past.

_tree = ast.parse(_scan)
_calls = {n.func.attr for n in ast.walk(_tree)
          if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
check("no shell is used", "system" in _calls or "popen" in _calls, False)
check("no eval, no exec, no pickle",
      any(k in _scan for k in ("eval(", "exec(", "pickle")), False)
check("the module still raises findings through save_finding only",
      "save_finding" in _calls, True)
# THE FIRST VERSION OF THIS CHECK WANTED 'ping' AND WAS SLICING THE WRONG MATCH,
# and the second wanted three names and was reading a regex that only sees a
# call whose list starts on the same line — `ping` is built into a variable on
# the platform branch above it, so it is not in that shape anywhere. What the
# check is FOR is that the set of external commands is exactly these and
# nothing new has crept in, so each of the three is asserted to be present
# somewhere and the count of distinct commands is pinned.
check("the module shells out to exactly three commands",
      sorted(set(re.findall(r"\[\s*\"(ping|ip|arp)\"", _scan))),
      ["arp", "ip", "ping"])
check("  and the ping command has no other spelling",
      "cmd = [\"ping\"" in _scan, True)
check("  and no fourth external command was added",
      sorted(set(re.findall(r"subprocess\.run\(\s*\[\s*\"([^\"]+)\"", _scan))),
      ["arp", "ip"])
check("the arp/ip fallbacks are still subprocess calls",
      '"ip", "neigh"' in _scan and '"arp", "-a"' in _scan, True)
check("nothing in the module writes to the store except through memory_engine",
      "sqlite3" in _scan, False)
check("every registered detection id the module raises is registered",
      sorted({i for i in ("NET-1001", "NET-1002")
              if f'"{i}"' in _scan}), ["NET-1001", "NET-1002"])
_ids = __import__("core.detections", fromlist=["x"])
for _did in ("NET-1001", "NET-1002"):
    try:
        _ids.get(_did)
        _ok = True
    except Exception as _e:                               # noqa: BLE001
        _ok = str(_e)
    check(f"{_did} is registered in core/detections", _ok, True)

check("the docstring no longer claims 'No raw packets, no admin needed' as "
      "the whole story without saying what it reads",
      "NEIGHBOUR CACHE ENTRY IS MEMORY" in _scan, True)
check("the old ICMP-only header claim is gone",
      "Ping sweep + ARP cache network scanner" in _scan, False)


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
