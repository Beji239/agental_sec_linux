# tests/test_router_reader.py
# The router reader: a failed or slow read says "could not read", never
# "nothing changed"; polling is 30 to 60 seconds; reads in the same second
# share one SSH login.

import ipaddress
import pathlib
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import memory_engine as me                  # noqa: E402
from core import migrations                           # noqa: E402
migrations.run_migrations(me.DB_PATH)

from tools import gateway as gw                       # noqa: E402
from tools import lan_live                            # noqa: E402

fails = []
# A private range that is nobody's real LAN; the monitor only counts private
# addresses as devices.
LAN = ipaddress.ip_network("10.9.8.0/24")
ROUTER, DEV = str(LAN[1]), str(LAN[10])


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def c(up, down):
    return {"up_packets": 1, "up_bytes": up, "down_packets": 1, "down_bytes": down}


class Router:
    """Answers like the agent until told to fail."""

    def __init__(self):
        self.fail = None
        self.ctr = {}

    def probe(self):
        return {"capabilities": ["counters", "conntrack", "leases"]}

    def has(self, cap):
        return cap in ("counters", "conntrack", "leases")

    def _maybe_fail(self):
        if self.fail:
            raise self.fail

    def counters(self):
        self._maybe_fail()
        return {"devices": {k: dict(v) for k, v in self.ctr.items()}}

    def flows(self, ip=None):
        self._maybe_fail()
        return [{"proto": "tcp", "state": "ESTABLISHED", "src": DEV,
                 "dst": "203.0.113.7", "sport": 40000, "dport": 443,
                 "bytes_out": 1, "packets_out": 1, "bytes_in": 1,
                 "packets_in": 1, "nat_src": None, "unreplied": False}]

    def leases(self):
        self._maybe_fail()
        return [{"ip": DEV, "mac": "aa:bb:cc:00:00:10", "hostname": "pc"}]


def unreadable(label, snap, dev):
    check(f"{label}: the status says could not read", snap["status"]["read"], "could not read")
    check(f"{label}: not reported as ok", snap["status"]["ok"], False)
    check(f"{label}: the error sentence starts with Could not read",
          (snap["status"]["error"] or "").startswith("Could not read"), True)
    check(f"{label}: no rate is shown, not zero, not the old one",
          (dev["up_bps"], dev["down_bps"]), (None, None))
    check(f"{label}: no connection count is shown", dev["connections"], None)


print("a failed read")
r = Router()
cfg = {"gateway": {"enabled": True, "host": ROUTER}}
m = lan_live.LanLive(cfg, gateway=r, store=False)
r.ctr = {DEV: c(0, 0)}
m.poll_once(1000.0)
r.ctr = {DEV: c(30000, 60000)}
m.poll_once(1030.0)
snap = m.snapshot(now=1031.0)
check("a good read is ok", (snap["status"]["ok"], snap["status"]["read"]), (True, "ok"))
check("a good read has its rate", snap["devices"][0]["up_bps"], 1000)
r.fail = gw.GatewayError("The router could not be reached: timed out")
m.poll_once(1060.0)
snap = m.snapshot(now=1061.0)
unreadable("after a failed read", snap, snap["devices"][0])
d = m.device(DEV)
check("the device view says could not read", d["read"], "could not read")
check("the device view shows no rate", (d["up_bps"], d["down_bps"]), (None, None))
check("the device view lists no stale destinations", d["destinations"], [])

print("an unexpected error is a failed read too")
r.fail = RuntimeError("parse blew up")
m.poll_once(1090.0)
snap = m.snapshot(now=1091.0)
unreadable("after an exception", snap, snap["devices"][0])

print("recovery")
r.fail = None
r.ctr = {DEV: c(60000, 60000)}
m.poll_once(1120.0)
snap = m.snapshot(now=1121.0)
check("a read after the failure is ok again", snap["status"]["read"], "ok")
check("the rate is back", snap["devices"][0]["up_bps"] is not None, True)

print("a read that has not come back in time")
snap = m.snapshot(now=1121.0 + 3 * m.cfg["poll_seconds"])
unreadable("when the last good read is too old", snap, snap["devices"][0])


print("a slow answer from the router")


class SlowChannel:
    """Sends one byte, then sleeps past any deadline."""

    def __init__(self, trickle):
        self.trickle = list(trickle)
        self.timeout = None

    def settimeout(self, t):
        self.timeout = t

    def recv(self, n):
        if self.trickle:
            time.sleep(0.05)
            return self.trickle.pop(0)
        import socket
        time.sleep(min(self.timeout or 0, 0.2))
        raise socket.timeout("timed out")


t0 = time.monotonic()
try:
    gw._read_all(SlowChannel([b"O"] * 100), gw.MAX_OUTPUT, 0.3)
    check("a slow answer is refused", "returned", "raised")
except gw.GatewayError as e:
    check("a slow answer says could not read", "could not read" in str(e).lower(), True)
check("the deadline holds", time.monotonic() - t0 < 2.0, True)
check("a whole answer within the deadline is read",
      gw._read_all(SlowChannel([b"OK version\n", b""]), gw.MAX_OUTPUT, 5.0),
      b"OK version\n")


print("polling is 30 to 60 seconds")
s = lan_live.settings({})
check("traffic every 30 to 60 s", 30 <= s["poll_seconds"] <= 60, True)
check("names every 30 to 60 s", 30 <= s["dns_poll_seconds"] <= 60, True)
check("devices every 30 to 60 s", 30 <= s["inventory_poll_seconds"] <= 60, True)
s = lan_live.settings({"lan_live": {"poll_seconds": 2, "dns_poll_seconds": 5,
                                    "inventory_poll_seconds": 1}})
check("an old fast setting is raised to 30 s",
      (s["poll_seconds"], s["dns_poll_seconds"], s["inventory_poll_seconds"]),
      (30, 30, 30))


print("reads in the same second share one login")


class FakeChannel:
    def __init__(self, data):
        self.data = [data, b""]

    def settimeout(self, t):
        pass

    def recv(self, n):
        return self.data.pop(0) if self.data else b""

    def close(self):
        pass


class FakeStdout:
    def __init__(self, data):
        self.channel = FakeChannel(data)


class FakeTransport:
    def __init__(self, client):
        self.client = client

    def is_active(self):
        return not self.client.closed


class FakeClient:
    def __init__(self, log):
        self.log = log
        self.closed = False
        self.commands = []

    def get_transport(self):
        return FakeTransport(self)

    def exec_command(self, command, timeout=None):
        time.sleep(0.01)
        self.commands.append(command)
        verb = command.split()[0]
        return None, FakeStdout(f"OK {verb}\n".encode()), None

    def close(self):
        self.closed = True


logins = []


def fake_connect(cfg, known, key):
    client = FakeClient(logins)
    logins.append(client)
    return client


tmp = pathlib.Path(tempfile.mkdtemp())
(tmp / "known").write_text("")
(tmp / "key").write_text("")
real_connect = gw._connect
gw._connect = fake_connect
try:
    tcfg = gw.settings({"gateway": {"host": "192.0.2.1",
                                    "known_hosts": str(tmp / "known"),
                                    "key_path": str(tmp / "key")}})
    run = gw.ssh_transport(tcfg)
    run("counters")
    run("conntrack")
    check("two reads in a row, one login", len(logins), 1)
    check("both ran on it", logins[0].commands, ["counters", "conntrack"])
    other = gw.ssh_transport(tcfg)
    other("leases")
    check("another reader of the same router shares it", len(logins), 1)

    out = []
    threads = [threading.Thread(target=lambda v=v: out.append(run(v)))
               for v in ("leases", "neighbors")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check("two readers at once, still one login", len(logins), 1)
    check("each got its own answer", sorted(o.split()[1] for o in out),
          ["leases", "neighbors"])

    time.sleep(gw.REUSE_SECONDS + 0.5)
    check("an idle login is closed", logins[0].closed, True)
    run("counters")
    check("a read later logs in again", len(logins), 2)

    logins[-1].closed = True
    run("counters")
    check("a dropped login is not reused", len(logins), 3)
finally:
    gw._connect = real_connect
    gw._close_all()


print()
if fails:
    print(f"FAILED {len(fails)}: {fails}")
    sys.exit(1)
print("ALL PASS")
