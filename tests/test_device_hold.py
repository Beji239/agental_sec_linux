"""
tests/test_device_hold.py, new devices held until the owner checks them in.

On a scratch database with a stand-in router: nothing is held while the
switch is off or for devices already here; a new hardware address is blocked
at the router, once, with a notice; a device the owner named is never held;
a router that cannot be reached leaves the device online and says so; naming
a held device, letting it in, or turning the switch off lifts the block. The
router collector hands every new device to the hold.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
db = _isolate_db.isolate()

from core import actions  # noqa: E402
from core import device_hold as dh  # noqa: E402
from core import memory_engine as me  # noqa: E402
from core import migrations  # noqa: E402
from tools import router_monitor  # noqa: E402

migrations.run_migrations(db)

failures = []
notices = []
actions.notify = lambda title, body, urgency="normal": notices.append(
    (title, body)) or {"sent": True}


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        failures.append(label)
        print(f"        {detail}")


class Router:
    def __init__(self, up=True):
        self.up, self.blocked = up, set()

    def block_mac(self, mac, reason, ip=None):
        if not self.up:
            return {"success": False, "error": "router did not answer"}
        self.blocked.add(mac)
        return {"success": True}

    def unblock_mac(self, mac, reason, ip=None):
        if not self.up:
            return {"success": False, "error": "router did not answer"}
        if mac not in self.blocked:
            return {"success": False, "error": "The router held no block"}
        self.blocked.discard(mac)
        return {"success": True}


router = Router()
dh._gateway = lambda: router


def seen(ip, mac, when="CURRENT_TIMESTAMP"):
    with me._get_conn() as c:
        c.execute(f"INSERT INTO router_clients (router_host, ip, mac, source, "
                  f"first_seen, last_seen) VALUES ('192.0.2.1', ?, ?, 'test', "
                  f"{when}, CURRENT_TIMESTAMP)", (ip, mac))
    return {"ip": ip, "mac": mac, "vendor": "Example Corp"}


def status(mac):
    return {r["mac"]: r["status"] for r in dh.state()["devices"]}.get(mac)


OLD = "00:00:5e:00:53:01"
NEW = "00:00:5e:00:53:02"

print("\n[1] Off by default")
check("the switch starts off", dh.state()["on"] is False)
check("nothing is held while it is off",
      dh.consider(seen("192.0.2.30", NEW))["held"] is False
      and not router.blocked)

print("\n[2] On: only devices first seen after it went on")
old = seen("192.0.2.31", OLD, "'2020-01-01 00:00:00'")
dh.set_switch(True)
check("a device already here keeps its internet",
      dh.consider(old)["held"] is False and OLD not in router.blocked)
with me._get_conn() as c:
    c.execute("DELETE FROM router_clients WHERE mac = ?", (NEW,))
out = dh.consider(seen("192.0.2.32", NEW))
check("a new device is blocked at the router", out["held"]
      and NEW in router.blocked and status(NEW) == "held", out)
check("with one notice that names it", len(notices) == 1
      and NEW in notices[0][1] and "Devices tab" in notices[0][1], notices)
check("once only", dh.consider({"ip": "192.0.2.32", "mac": NEW})["held"]
      is False and len(notices) == 1)

print("\n[3] Never held: a device the owner named")
NAMED = "00:00:5e:00:53:03"
with me._get_conn() as c:
    c.execute("INSERT INTO known_devices (ip, mac, known_as, identified_by) "
              "VALUES ('192.0.2.33', ?, 'Printer', 'user')", (NAMED,))
check("it is left alone", dh.consider(seen("192.0.2.33", NAMED))["held"]
      is False and NAMED not in router.blocked)

print("\n[4] The router cannot be reached: the device stays online")
DOWN = "00:00:5e:00:53:04"
router.up = False
out = dh.consider(seen("192.0.2.34", DOWN))
check("not held, and why", out["status"] == "not_held"
      and "did not answer" in out["error"], out)
check("the notice says it is online", "could not be held" in notices[-1][0]
      and "is online" in notices[-1][1], notices[-1])
dh._gateway = lambda: None
NOAGENT = "00:00:5e:00:53:05"
check("no router agent at all says so",
      "no router agent" in (dh.consider(seen("192.0.2.35", NOAGENT))
                            .get("error") or ""))
dh._gateway = lambda: router
router.up = True

print("\n[5] Checking in lifts the block")
named = me.identify_device(ip="192.0.2.32", known_as="Front desk laptop",
                           evidence="named by the owner", identified_by="user")
check("naming it lets it in", NEW not in router.blocked
      and status(NEW) == "released" and named.get("hold_released"), named)
LETIN = "00:00:5e:00:53:06"
dh.consider(seen("192.0.2.36", LETIN))
check("or letting it in unnamed", dh.release(LETIN)["success"]
      and LETIN not in router.blocked and status(LETIN) == "released")
router.up = False
STUCK = "00:00:5e:00:53:07"
router.up = True
dh.consider(seen("192.0.2.37", STUCK))
router.up = False
stuck = dh.release(STUCK)
check("a release the router cannot take keeps the row held",
      not stuck["success"] and status(STUCK) == "held", stuck)
router.up = True

print("\n[6] Turning it off lets every waiting device in")
off = dh.set_switch(False)
check("all released", not router.blocked and status(STUCK) == "released"
      and len(off["released"]) == 1, off)
check("and the switch is off", dh.state()["on"] is False)

print("\n[7] The router collector hands new devices to the hold")
dh.set_switch(True)
LATE = "00:00:5e:00:53:08"
seen("192.0.2.38", LATE)
router_monitor._raise_client_findings(
    [{"ip": "192.0.2.38", "mac": LATE, "vendor": "Example Corp",
      "entry_type": "dynamic"}], "192.0.2.1", "t", None)
check("held through the collector", LATE in router.blocked
      and status(LATE) == "held")
with me._get_readonly_conn() as c:
    ops = {r[0] for r in c.execute("SELECT operation FROM integrity_journal")}
check("holds, releases and the switch are journalled",
      {"device_held", "device_released", "device_hold_on",
       "device_hold_off"} <= ops, ops)

print("\nALL PASSED" if not failures else f"\nFAILED: {failures}")
sys.exit(1 if failures else 0)
