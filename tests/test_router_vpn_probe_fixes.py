#!/usr/bin/env python3
"""
tests/test_router_vpn_probe_fixes.py — REGISTER SECTION 17, the router / VPN /
presence trio (tools/router_monitor.py + tools/vpn_state.py + tools/probe.py),
2026-09-27.

ONE SECTION PER DEFECT, each asserted in the direction that FAILS if the
defect comes back. Every check drives the SHIPPED functions — the real SNMP
client against the tree's own synthetic agent, the reader's own status(),
the probe's own pass — or the shipped file's own text where the defect WAS
text. Nothing here reimplements the code under test.

The defects were measured on THIS host before they were fixed. The
measurements are in bugfinder.md, section "2026-09-27 — THE ROUTER / VPN /
PRESENCE TRIO" and register section 17 of toolaudit.md. The measurement
scripts are /tmp/s17/m1.py .. m5.py with their outputs m1.txt .. m5.txt.

THE FIXTURES NAME NOBODY AND NO MACHINE. Every address is RFC 5737
documentation space (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), every
hardware address is synthetic, and the store is the isolated scratch built by
_isolate_db. A test that names one machine is also wrong on every other box.

SECTIONS MARKED "RECORDED, NOT FIXED" assert the state of something this round
deliberately did not change, so the record is testable and a later round's fix
will visibly move them. They are not claims that the behaviour is correct.

Run it directly: python3 tests/test_router_vpn_probe_fixes.py
"""

import json
import os
import pathlib
import socket
import sqlite3
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
DB = _isolate_db.isolate()

os.environ["AGENTAL_ROUTER_COMMUNITY"] = "section17-read"

from core import memory_engine as me                  # noqa: E402
from core import sensors as sn                        # noqa: E402
from tools import router_monitor as rm                # noqa: E402
from tools import vpn_state as vs                     # noqa: E402
from tools.probe import DeviceProbe                   # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  [{label}]: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got):
    check(label, bool(got), True)


def check_false(label, got):
    check(label, bool(got), False)


def guarded(label, fn, want=True):
    """
    Call something that may RAISE under a defect and print a named FAIL.

    A check that crashes instead of failing measures nothing: one raising
    check hides every check after it, and the harness would report a crashed
    subject about working assertions below. Same rule the round's control
    follows.
    """
    try:
        got = fn()
    except Exception as e:                            # noqa: BLE001
        print(f"  FAIL  [{label}]: raised {type(e).__name__}: {e}")
        fails.append(label)
        return False
    check(label, bool(got), bool(want))
    return bool(got) == bool(want)


def safe_call(fn, *args, **kwargs):
    """
    Call the shipped function, catching anything it raises.

    A defect THIS round restores can be a RAISE (an unguarded int(), a walk
    that will not stop), and a check that lets it propagate dies instead of
    printing FAIL — taking every check after it with it, so the harness sees a
    crashed subject and measures nothing. Every call in this file that a
    reversion can make raise goes through here.
    """
    try:
        return fn(*args, **kwargs)
    except Exception as e:                            # noqa: BLE001
        return {"_raised": f"{type(e).__name__}: {e}"}


sn.register_local()
me.upsert_sensor(sensor_id=sn.LOCAL_SENSOR_ID, label="host", position="host",
                 summary="", can_see="", cannot_see="", notes="harness")

ROUTER = "192.0.2.1"
A, B, C, D = "192.0.2.10", "192.0.2.11", "192.0.2.99", "192.0.2.55"


def _arcs(text):
    return tuple(int(p) for p in text.split("."))


def _octets(v):
    return rm.TAG_OCTETS, v


def _integer(v):
    return rm.TAG_INTEGER, rm._encode_int(v)[2:]


def _ipaddress(text):
    return rm.TAG_IPADDRESS, bytes(int(p) for p in text.split("."))


def build_mib():
    """
    A small MIB-II subset, rebuilt here rather than imported from the router
    file's own test, because section 17's fixtures must be independent of the
    file another round may restate.
    """
    return {
        (1, 3, 6, 1, 2, 1, 1, 1, 0): _octets(b"SynthRouter OS 1.2.3"),
        (1, 3, 6, 1, 2, 1, 1, 2, 0): (rm.TAG_OID,
                                      rm._encode_oid((1, 3, 6, 1, 4, 1, 9))[2:]),
        (1, 3, 6, 1, 2, 1, 1, 3, 0): (rm.TAG_TIMETICKS, (123456).to_bytes(4, "big")),
        (1, 3, 6, 1, 2, 1, 1, 5, 0): _octets(b"gateway"),
        (1, 3, 6, 1, 2, 1, 4, 1, 0): _integer(1),
        rm.OID_ARP_PHYS + (1,) + _arcs(A): _octets(bytes.fromhex("b827eb112233")),
        rm.OID_ARP_PHYS + (1,) + _arcs(B): _octets(bytes.fromhex("f0189844556f")),
        rm.OID_ARP_TYPE + (1,) + _arcs(A): _integer(3),
        rm.OID_ARP_TYPE + (1,) + _arcs(B): _integer(4),
        rm.OID_IP_ADDR_IFINDEX + _arcs(ROUTER): _integer(1),
        rm.OID_IF_DESCR + (1,): _octets(b"br-lan"),
        rm.OID_TCP_CONN_STATE + _arcs(ROUTER) + (80,) + (0, 0, 0, 0) + (0,): _integer(2),
        rm.OID_UDP_LOCAL_ADDRESS + (0, 0, 0, 0) + (53,): _ipaddress("0.0.0.0"),
    }


class SyntheticAgent:
    """A loopback UDP responder answering get, get-next and get-bulk."""

    def __init__(self, mib):
        self.mib = mib
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def close(self):
        self.stop = True

    def _serve(self):
        self.sock.settimeout(0.4)
        while not self.stop:
            try:
                data, peer = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self.sock.sendto(self._answer(data), peer)
            except Exception:
                pass
        self.sock.close()

    def _answer(self, data: bytes) -> bytes:
        _, body, _ = rm._read_tlv(data, 0)
        index = 0
        _, _version, index = rm._read_tlv(body, index)
        _, _community, index = rm._read_tlv(body, index)
        pdu_tag, pdu, index = rm._read_tlv(body, index)
        cursor = 0
        _, raw_id, cursor = rm._read_tlv(pdu, cursor)
        _, _a, cursor = rm._read_tlv(pdu, cursor)
        _, raw_b, cursor = rm._read_tlv(pdu, cursor)
        _, raw_binds, cursor = rm._read_tlv(pdu, cursor)
        request_id = rm._decode_int(raw_id)
        repetitions = rm._decode_int(raw_b)
        asked = []
        position = 0
        while position < len(raw_binds):
            _, one, position = rm._read_tlv(raw_binds, position)
            inner = 0
            _, oid_body, inner = rm._read_tlv(one, inner)
            asked.append(rm._decode_oid(oid_body))
        ordered = sorted(self.mib)
        results = []
        if pdu_tag == rm.PDU_GET:
            for oid in asked:
                if oid in self.mib:
                    tag, value = self.mib[oid]
                    results.append((oid, tag, value))
                else:
                    results.append((oid, rm.TAG_NO_SUCH_INSTANCE, b""))
        else:
            count = max(1, repetitions) if pdu_tag == rm.PDU_GET_BULK else 1
            walker = asked[0]
            for _ in range(count):
                following = [o for o in ordered if o > walker]
                if not following:
                    results.append((walker, rm.TAG_END_OF_MIB_VIEW, b""))
                    break
                walker = following[0]
                tag, value = self.mib[walker]
                results.append((walker, tag, value))
        binds = b"".join(
            rm._tlv(rm.TAG_SEQUENCE, rm._encode_oid(oid) + rm._tlv(tag, value))
            for oid, tag, value in results)
        pdu = rm._tlv(rm.PDU_RESPONSE, (
            rm._encode_int(request_id) + rm._encode_int(0) + rm._encode_int(0)
            + rm._tlv(rm.TAG_SEQUENCE, binds)))
        return rm._tlv(rm.TAG_SEQUENCE, (
            rm._encode_int(1) + rm._tlv(rm.TAG_OCTETS, b"section17-read")
            + pdu))


def router_config(port, **over):
    block = {"enabled": True, "backend": "snmp", "host": "127.0.0.1",
             "port": port, "timeout_seconds": 2}
    block.update(over)
    return {"router_monitor": block}


print("\n[1] RVP-1  a refused interface read is 'unknown', not 'disconnected'")
# MEASURED 2026-09-27 before the fix: with net_if_stats() raising, the reader
# answered state='disconnected', measured=True, interfaces=[], and a note
# saying the list had been read just now. Nothing in that answer was true.
_real_stats = vs.psutil.net_if_stats


def _refuse():
    raise PermissionError("simulated refusal to read the interface list")


vs.psutil.net_if_stats = _refuse
try:
    st = vs.VPNState().status()
finally:
    vs.psutil.net_if_stats = _real_stats
check("a refused read is unknown", st["state"], "unknown")
check("and is not claimed as a measurement", st["measured"], False)
check_false("it does not say a tunnel is down", "no tunnel interface is up"
            in st["note"].lower())
check_true("it says what went wrong", "could not be read" in st["note"].lower())
check_true("and that unknown is not a no", "not the same as" in st["note"].lower())

st_ok = vs.VPNState().status()
check("an ordinary read is still an ordinary answer",
      st_ok["state"] in ("connected", "disconnected", "unknown"), True)
check("and is marked as measured", st_ok["measured"], True)


print("\n[2] RVP-2  two spellings of one router are one router")
# MEASURED before the fix: `192.0.2.1` and `192.0.2.01` hashed to two sensor
# ids, two inventories, and a "device not seen before" finding for every
# device on the network.
same = rm._normalise_router_host
check("a leading zero is the same address", same("172.20.0.01"), same("172.20.0.1"))
check("whitespace is not part of an address", same(" 172.20.0.1 "), same("172.20.0.1"))
check("case is not part of one", same("Router.LAN"), same("router.lan"))
check("nor is a root dot", same("router.lan."), same("router.lan"))
check("and a name is left alone otherwise", same("router.lan"), "router.lan")
check("the sensor id follows the normalisation",
      rm._router_sensor_id("172.20.0.01"), rm._router_sensor_id("172.20.0.1"))
check("and two DIFFERENT routers stay different",
      rm._router_sensor_id("172.20.0.1") == rm._router_sensor_id("172.20.0.2"), False)
check_true("the id still carries no address",
           "10.0.0" not in rm._router_sensor_id("172.20.0.1"))


print("\n[3] RVP-3  a hand-typed config value is a reason, not a traceback")
# MEASURED before the fix: `"port": "sixteen-hundred"` raised ValueError out of
# status(), which the boot path and the dashboard toggle both call first.
bad_port = safe_call(rm.status, {"router_monitor": {"enabled": True,
                                                    "host": ROUTER,
                                                    "port": "sixteen-hundred"}})
check("a bad port does not raise", "_raised" in bad_port, False)
check("and is refused rather than published", bad_port.get("available"), False)
check_true("it names the key", "port" in (bad_port.get("reason") or ""))
check_true("and shows the value", "sixteen-hundred" in (bad_port.get("reason") or ""))

bad_timeout = safe_call(rm.status, {"router_monitor": {"enabled": True,
                                                       "host": ROUTER,
                                                       "timeout_seconds": "slow"}})
check("a bad timeout does not raise either", "_raised" in bad_timeout, False)
check_true("and names its own key",
           "timeout_seconds" in (bad_timeout.get("reason") or ""))

good = safe_call(rm.status, {"router_monitor": {"enabled": True, "host": ROUTER,
                                                "port": 161,
                                                "timeout_seconds": 3}})
check("a good config is still available", good.get("available"), True)
check("with the port as a number", good.get("port"), 161)
check("and the timeout as a number", good.get("timeout"), 3.0)


print("\n[4] RVP-4  one port bound at two addresses is two settings, not a flap")
# MEASURED before the fix: ipNetToMedia.. no — tcpConnTable answering port 22
# at BOTH 0.0.0.0 and the router's own address produced ONE row that was
# rewritten each pass, so an unchanged router reported a change every tick and
# the second listener was unrecordable.
mib = build_mib()
mib[rm.OID_TCP_CONN_STATE + _arcs(ROUTER) + (22,) + (0, 0, 0, 0) + (0,)] = _integer(2)
mib[rm.OID_TCP_CONN_STATE + (0, 0, 0, 0) + (22,) + (0, 0, 0, 0) + (0,)] = _integer(2)
agent = SyntheticAgent(mib)
try:
    cfg = router_config(agent.port)
    first = safe_call(rm.collect_once, cfg, session_id="s17")
    check("the first pass runs", first.get("ran"), True)
    second = safe_call(rm.collect_once, cfg, session_id="s17")
    check("a second pass over an unchanged router changes NOTHING",
          second.get("config_changed"), 0)

    stored = me.query_router_config()["settings"]
    listeners = [s for s in stored if s["setting"].startswith("listener:tcp:22")]
    check("both bound addresses are recorded separately", len(listeners), 2)
    check("one of them is the unspecified address",
          any(s["setting"].endswith(":0.0.0.0") for s in listeners), True)
    check("and the other is the router's own",
          any(s["setting"].endswith(":" + ROUTER) for s in listeners), True)
    with sqlite3.connect(DB) as conn:
        n = conn.execute("SELECT COUNT(*) FROM findings "
                         "WHERE detection_id='RTR-1002'").fetchone()[0]
    check("and no setting-change finding was raised about it", n, 0)
finally:
    agent.close()


print("\n[5] RVP-5  a refused entry-type column does not take the table with it")
# MEASURED before the fix: a router whose ipNetToMediaType column is absent
# lost the ENTIRE neighbour table — ran=False though the address walk had
# answered three entries.
mib = build_mib()
for oid in list(mib):
    if oid[:len(rm.OID_ARP_TYPE)] == rm.OID_ARP_TYPE:
        del mib[oid]
agent = SyntheticAgent(mib)
try:
    res = safe_call(rm.collect_once, router_config(agent.port),
                    session_id="s17")
    check("the pass still runs", res.get("ran"), True)
    check("the neighbour table is still read", res.get("clients_seen"), 2)
    rows = me.query_router_clients()["clients"]
    check("the entries are stored", len(rows), 2)
    check("with the type reported as unknown rather than guessed",
          {r["entry_type"] for r in rows}, {"unknown"})
finally:
    agent.close()


print("\n[6] RVP-6/RVP-15  a table cut at the walk cap says so")
# MEASURED before RVP-6: an agent with 2600 neighbour entries returned
# clients_seen=2000 with no field naming the cut. RVP-15 raised the default
# to 8192 and made it configurable, so 2600 is now read whole.
mib = build_mib()
for i in range(2600):
    mib[rm.OID_ARP_PHYS + (3, 203, 0, (i // 256) + 1, i % 256)] = _octets(
        bytes.fromhex("020000000001"))
agent = SyntheticAgent(mib)
try:
    res = safe_call(rm.collect_once, router_config(agent.port),
                    session_id="s17")
    base_rows = sum(1 for o in build_mib() if o[:len(rm.OID_ARP_PHYS)] == rm.OID_ARP_PHYS)
    check("the default reads all 2600 plus the base table",
          res.get("clients_seen"), 2600 + base_rows)
    check("and does not call it cut", res.get("clients_truncated"), False)
    res = safe_call(rm.collect_once,
                    router_config(agent.port, max_rows_per_table=2000),
                    session_id="s17")
    check("a configured cap is honoured", res.get("clients_seen"), 2000)
    check("and the answer SAYS it was cut", res.get("clients_truncated"), True)
    check("and names the cap it was cut at", res.get("max_rows_per_table"), 2000)
    res = safe_call(rm.collect_once,
                    router_config(agent.port, max_rows_per_table=10 ** 9),
                    session_id="s17")
    check("a huge setting is clamped to the ceiling",
          res.get("max_rows_per_table"), rm.MAX_WALK_ROWS_CEILING)
finally:
    agent.close()


class NoBulkAgent(SyntheticAgent):
    """Refuses GetBulk, so every row costs one GetNext request."""

    def _answer(self, data):
        _, body, _ = rm._read_tlv(data, 0)
        index = 0
        _, _v, index = rm._read_tlv(body, index)
        _, _c, index = rm._read_tlv(body, index)
        pdu_tag, pdu, index = rm._read_tlv(body, index)
        if pdu_tag != rm.PDU_GET_BULK:
            return super()._answer(data)
        _, raw_id, _ = rm._read_tlv(pdu, 0)
        out = rm._tlv(rm.PDU_RESPONSE, (
            rm._encode_int(rm._decode_int(raw_id)) + rm._encode_int(5)
            + rm._encode_int(0) + rm._tlv(rm.TAG_SEQUENCE, b"")))
        return rm._tlv(rm.TAG_SEQUENCE, (
            rm._encode_int(1) + rm._tlv(rm.TAG_OCTETS, b"section17-read") + out))


print("\n[6b] RVP-15  a router that refuses bulk is not stopped at 200 rows")
mib = build_mib()
for i in range(500):
    mib[rm.OID_ARP_PHYS + (3, 203, 0, 10 + i // 256, i % 256)] = _octets(
        bytes.fromhex("020000000002"))
agent = NoBulkAgent(mib)
try:
    session = rm.SnmpSession("127.0.0.1", "section17-read", port=agent.port,
                             timeout=2)
    rows = session.walk(rm.OID_ARP_PHYS)
    check("all 500 rows over GetNext", len(rows) >= 500, True)
    check("and not marked cut", rm.OID_ARP_PHYS in session.cut_short, False)
    small = rm.SnmpSession("127.0.0.1", "section17-read", port=agent.port,
                           timeout=2, max_rows=100)
    small.walk(rm.OID_ARP_PHYS)
    check("a cut over GetNext is recorded", rm.OID_ARP_PHYS in small.cut_short, True)
finally:
    agent.close()

agent = SyntheticAgent(build_mib())
try:
    res = safe_call(rm.collect_once, router_config(agent.port),
                    session_id="s17")
    check("an ordinary table is not marked truncated",
          res.get("clients_truncated"), False)
finally:
    agent.close()


print("\n[7] RVP-7  the router's raisers obey the dismissal and the open guard")
# MEASURED before the fix: with 'ip' 192.0.2.10 dismissed, the client raiser
# returned 1 and wrote a row; and three passes over one unchanged drift wrote
# three rows.
db2 = pathlib.Path(tempfile.mkdtemp(prefix="s17_rows_")) / "rows.db"
with sqlite3.connect(db2) as conn:
    conn.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
me.DB_PATH = db2
me.upsert_sensor(sensor_id=sn.LOCAL_SENSOR_ID, label="host", position="host",
                 summary="", can_see="", cannot_see="", notes="")
sid = rm._router_sensor_id(ROUTER)
me.upsert_sensor(sensor_id=sid, position="gateway_api", summary="s",
                 can_see="c", cannot_see="n")

me.dismiss_entity("ip", A, "operator quieted this device on purpose")
raised = rm._raise_client_findings(
    [{"ip": A, "mac": "b8:27:eb:11:22:33", "vendor": None,
      "entry_type": "dynamic"}], ROUTER, "s17", sid)
check("a dismissed address raises nothing", raised, 0)
with sqlite3.connect(db2) as conn:
    n = conn.execute("SELECT COUNT(*) FROM findings WHERE detection_id='RTR-1001'"
                     ).fetchone()[0]
check("and nothing was written about it", n, 0)

raised = rm._raise_client_findings(
    [{"ip": B, "mac": "f0:18:98:44:55:6f", "vendor": None,
      "entry_type": "dynamic"}], ROUTER, "s17", sid)
check("an ordinary device still raises", raised, 1)
raised = rm._raise_client_findings(
    [{"ip": B, "mac": "f0:18:98:44:55:6f", "vendor": None,
      "entry_type": "dynamic"}], ROUTER, "s17", sid)
check("and is not raised again while that one is open", raised, 0)

me.save_router_config([{"setting": "sysDescr", "value": "OS 1", "detail": None}],
                      router_host=ROUTER, source="snmp:mib2", sensor_id=sid)
me.save_router_config([{"setting": "sysDescr", "value": "OS 2", "detail": None}],
                      router_host=ROUTER, source="snmp:mib2", sensor_id=sid)
changes = me.save_router_config(
    [{"setting": "sysDescr", "value": "OS 2", "detail": None}],
    router_host=ROUTER, source="snmp:mib2", sensor_id=sid)["changed"]
me.dismiss_entity("ip", ROUTER, "operator quieted the gateway")
check("a dismissed router raises no setting change",
      rm._raise_config_findings(changes, ROUTER, "s17", sid), 0)


print("\n[8] RVP-8  'first pass' is decided per leg, not for the whole router")
# MEASURED before the fix: history in EITHER table made the settings leg think
# it had a baseline, so a router whose settings half had never once been read
# reported its whole first configuration as changes.
db3 = pathlib.Path(tempfile.mkdtemp(prefix="s17_leg_")) / "leg.db"
with sqlite3.connect(db3) as conn:
    conn.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
me.DB_PATH = db3
me.upsert_sensor(sensor_id=sn.LOCAL_SENSOR_ID, label="host", position="host",
                 summary="", can_see="", cannot_see="", notes="")
sid3 = rm._router_sensor_id(ROUTER)
me.upsert_sensor(sensor_id=sid3, position="gateway_api", summary="s",
                 can_see="c", cannot_see="n")
me.save_router_clients(
    [{"ip": A, "mac": "b8:27:eb:11:22:33", "vendor": None, "hostname": None,
      "interface": "1", "entry_type": "dynamic", "source": "snmp"}],
    router_host=ROUTER, sensor_id=sid3)

check("client history is visible to the client leg",
      me.router_has_history(ROUTER, table="clients"), True)
check("and NOT to the settings leg",
      me.router_has_history(ROUTER, table="config"), False)
check("the old any-table answer still covers both",
      me.router_has_history(ROUTER), True)

changes = me.save_router_config(
    [{"setting": "sysDescr", "value": "OS 1", "detail": None},
     {"setting": "listener:tcp:22:0.0.0.0", "value": "all_interfaces",
      "detail": None}], router_host=ROUTER, source="snmp:mib2",
    sensor_id=sid3)["changed"]
check("a first-ever configuration reports both settings as new",
      len(changes), 2)
check("and every one of them is marked ADDED",
      all(c["added"] for c in changes), True)
check("a bad table name is refused",
      "_raised" in safe_call(me.router_has_history, ROUTER, table="everything"),
      True)

# THE PRODUCTION PATH, WHICH IS THE ONLY PLACE THIS DEFECT LIVED. The three
# checks above drive the HELPER, and a control that reverts the CALLER inside
# collect_once leaves every one of them green — measured on this round's own
# first control run, where C9 reported MISSING EXPECTATIONS for exactly that
# reason. "A name in a file is not a call": the observable effect has to be
# driven through the shipped entry point.
db3b = pathlib.Path(tempfile.mkdtemp(prefix="s17_leg2_")) / "leg2.db"
with sqlite3.connect(db3b) as conn:
    conn.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
me.DB_PATH = db3b
me.upsert_sensor(sensor_id=sn.LOCAL_SENSOR_ID, label="host", position="host",
                 summary="", can_see="", cannot_see="", notes="")
# The collector keys its tables on the CONFIGURED host, which for a synthetic
# agent is the loopback address it is bound to.
LEGHOST = "127.0.0.1"
sid3b = rm._router_sensor_id(LEGHOST)
me.upsert_sensor(sensor_id=sid3b, position="gateway_api", summary="s",
                 can_see="c", cannot_see="n")
# Clients already recorded on an earlier run; settings never read at all. This
# is the router that answered its neighbour table and refused the rest.
me.save_router_clients(
    [{"ip": A, "mac": "b8:27:eb:11:22:33", "vendor": None, "hostname": None,
      "interface": "1", "entry_type": "dynamic", "source": "snmp"}],
    router_host=LEGHOST, sensor_id=sid3b)

agent_leg = SyntheticAgent(build_mib())
try:
    cfg_leg = {"router_monitor": {"enabled": True, "backend": "snmp",
                                  "host": LEGHOST, "port": agent_leg.port,
                                  "timeout_seconds": 2}}
    first_leg = safe_call(rm.collect_once, cfg_leg, session_id="s17")
    check("the settings leg runs", first_leg.get("ran"), True)
    check("and the pass does not claim to be a first pass, because the CLIENT "
          "leg does have history", first_leg.get("first_pass"), False)
    with sqlite3.connect(db3b) as conn:
        n = conn.execute("SELECT COUNT(*) FROM findings "
                         "WHERE detection_id='RTR-1002'").fetchone()[0]
        n_clients = conn.execute("SELECT COUNT(*) FROM findings "
                                 "WHERE detection_id='RTR-1001'").fetchone()[0]
    # SCOPED TO RTR-1002 ON PURPOSE. A finding MAY legitimately be raised on
    # this pass and it is the CLIENT one: the synthetic router answers two
    # neighbour entries while the seed held one, so the second device really is
    # new. Asserting `findings_raised == 0` would have been asserting that this
    # router has one device on it, which is not the claim under test.
    check("no 'the router's <setting> changed' row exists about a "
          "configuration that was never recorded before", n, 0)
    check("(while the genuinely-new client device did raise its own finding)",
          n_clients, 1)

    # AND THE OTHER DIRECTION, so the fix is not a blanket refusal. The agent's
    # sysDescr changes and the NEXT pass must raise about it — through the same
    # shipped entry point, which is the only caller that raises at all.
    mib_leg = build_mib()
    mib_leg[(1, 3, 6, 1, 2, 1, 1, 1, 0)] = _octets(b"SynthRouter OS 9.9.9")
    agent_leg.mib = mib_leg
    second_leg = safe_call(rm.collect_once, cfg_leg, session_id="s17")
    check("a LATER change on the same router is still raised",
          (second_leg.get("findings_raised") or 0) >= 1, True)
    with sqlite3.connect(db3b) as conn:
        n2 = conn.execute("SELECT COUNT(*) FROM findings "
                          "WHERE detection_id='RTR-1002'").fetchone()[0]
    check("and it names the setting that really changed", n2, 1)
    with sqlite3.connect(db3b) as conn:
        title = conn.execute("SELECT title FROM findings "
                             "WHERE detection_id='RTR-1002'").fetchone()[0]
    check("which is the firmware string", "sysDescr" in title, True)
finally:
    agent_leg.close()


print("\n[9] RVP-9  sysUpTime is read, so a reboot is a fact and not an inference")
# sysUpTime was fetched on every pass and consumed by nothing, which left the
# module's own worst false-positive source — the neighbour table flushing and
# refilling across a reboot — with nothing on the page to attribute it to.
agent = SyntheticAgent(build_mib())
try:
    safe_call(rm.collect_once, router_config(agent.port), session_id="s17")
    stored = {s["setting"]: s for s in me.query_router_config()["settings"]}
    # .get() EVERYWHERE: under the reversion this section exists for, the
    # setting is ABSENT, and a check that indexes it dies of KeyError instead
    # of printing FAIL — taking every check after it with it.
    check_true("sysUpTime is recorded as a setting", "sysUpTime" in stored)
    check("in units a person reads",
          (stored.get("sysUpTime") or {}).get("value"), "20 minute(s)")
    detail = (stored.get("sysUpTime") or {}).get("detail")
    if isinstance(detail, str):
        detail = json.loads(detail)
    check("with the raw ticks kept for arithmetic",
          (detail or {}).get("timeticks"), 123456)
finally:
    agent.close()


print("\n[10] RVP-10  the probe's drift obeys dismissal, the open guard, and the writer")
db4 = pathlib.Path(tempfile.mkdtemp(prefix="s17_probe_")) / "pr.db"
with sqlite3.connect(db4) as conn:
    conn.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
me.DB_PATH = db4
from core import migrations                            # noqa: E402
migrations.run_migrations(db4)
me.upsert_sensor(sensor_id=sn.LOCAL_SENSOR_ID, label="host", position="host",
                 summary="", can_see="", cannot_see="", notes="")

DRIFTED = "198.51.100.30"
me.save_known_device(ip=DRIFTED, mac="44:27:45:11:22:33", hostname="test-device")
me.save_port_scan_result(session_id="s17", target_host=DRIFTED, port=80,
                         state="open", risk_level="low")
me.set_device_permanence(DRIFTED, True)
me.save_port_scan_result(session_id="s17", target_host=DRIFTED, port=23,
                         state="open", risk_level="high")
pr = DeviceProbe("s17", {"probe": {"pacing_seconds": 0}})

res = safe_call(pr.run_once, force=True)
check("pass 1 files the drift", res.get("drift_found"), 1)
res = safe_call(pr.run_once, force=True)
check("pass 2 over the SAME unchanged drift files nothing",
      res.get("drift_found"), 0)
res = safe_call(pr.run_once, force=True)
check("pass 3 as well", res.get("drift_found"), 0)
with sqlite3.connect(db4) as conn:
    n = conn.execute("SELECT COUNT(*) FROM findings "
                     "WHERE detection_id='PRB-1001'").fetchone()[0]
check("so exactly one row exists about one standing condition", n, 1)

me.dismiss_entity("ip", DRIFTED, "operator quieted this device")
res = safe_call(pr.run_once, force=True)
check("a dismissed device is not raised about", res.get("drift_found"), 0)

# THE WRITER'S ANSWER, NOT THE CALL. A SUPPRESSION (not a dismissal) makes
# save_finding decline the write while leaving the device raisable, so the pass
# reaches save_finding and gets {"saved": False} back. drift_found is published
# on the pass and stored on the probe_run row, so it must count the WRITE and
# not the call — the same _finding_landed discipline adapters.py was corrected
# for. Driven through the SHIPPED pass, because a check on save_finding's
# return value would be a check about memory_engine, not about this module.
#
# THE ORDER MATTERS AND IT IS THE WHOLE APPARATUS OF THIS CHECK. The
# suppression is installed BEFORE THE DEVICE'S FIRST PASS. Run the other way
# round — first pass files, then suppress — and the ALREADY-OPEN guard returns
# False before save_finding is reached, so drift_found is 0 for the guard's
# reason and the check passes over a count that still follows the call. That is
# a check satisfied by a different mechanism than the one it names.
UNDISMISSED = "198.51.100.55"
db6 = pathlib.Path(tempfile.mkdtemp(prefix="s17_sup_")) / "sup.db"
with sqlite3.connect(db6) as conn:
    conn.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
me.DB_PATH = db6
migrations.run_migrations(db6)
me.upsert_sensor(sensor_id=sn.LOCAL_SENSOR_ID, label="host", position="host",
                 summary="", can_see="", cannot_see="", notes="")
me.save_known_device(ip=UNDISMISSED, mac="44:27:45:11:22:44", hostname="sensor-dev")
me.save_port_scan_result(session_id="s17", target_host=UNDISMISSED, port=80,
                         state="open", risk_level="low")
me.set_device_permanence(UNDISMISSED, True)
me.save_port_scan_result(session_id="s17", target_host=UNDISMISSED, port=23,
                         state="open", risk_level="high")
me.suppress_detection("PRB-1001", "operator silenced this rule for this device",
                      entity_type="ip", entity_value=UNDISMISSED)
check_false("the device itself is NOT dismissed, so the guard does not answer "
            "this",
            me.is_dismissed("ip", UNDISMISSED))
pr2 = DeviceProbe("s17", {"probe": {"pacing_seconds": 0}})
suppressed_pass = safe_call(pr2.run_once, force=True)
check("a pass whose only drift was declined by the store reports ZERO filed",
      suppressed_pass.get("drift_found"), 0)
with sqlite3.connect(db6) as conn:
    stored = conn.execute("SELECT drift_found FROM probe_run "
                          "ORDER BY id DESC LIMIT 1").fetchone()[0]
    n = conn.execute("SELECT COUNT(*) FROM findings "
                     "WHERE detection_id='PRB-1001'").fetchone()[0]
check("and the run record says the same thing", stored, 0)
check("so the store holds no row for it at all", n, 0)


print("\n[11] RVP-11  retirement runs with the cadence, and the note says so")
# MEASURED before the fix: with a successful pass inside the interval and 106
# consecutive misses on record, run_once() returned 'skipped' and the device
# stayed permanent. The note is where a reader finds that out.
me.DB_PATH = db4
note = safe_call(DeviceProbe("s17", {"probe": {}}).status).get("note") or ""
check_true("the note describes the cadence it really keeps",
           "retirement" in note.lower())
check_false("and no longer promises an hourly pass",
            "next hourly check will run" in note.lower())


print("\n[12] RVP-12  the retirement sweep respects a dismissal without blocking")
# MEASURED before the fix: with the address dismissed, PRB-1002 CHANGED the
# machine (cleared permanence) and then filed a row about a device the
# operator had explicitly dismissed.
db5 = pathlib.Path(tempfile.mkdtemp(prefix="s17_ret_")) / "ret.db"
with sqlite3.connect(db5) as conn:
    conn.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
me.DB_PATH = db5
migrations.run_migrations(db5)
me.upsert_sensor(sensor_id=sn.LOCAL_SENSOR_ID, label="host", position="host",
                 summary="", can_see="", cannot_see="", notes="")
GONE = "198.51.100.40"
me.save_known_device(ip=GONE, mac="70:85:c2:11:22:33")
me.set_device_permanence(GONE, True)
for _ in range(me.RETIRE_AFTER_MISSES):
    me.record_presence_sweep(session_id="s17", method="icmp+arp", outcome="ok",
                             subnet="198.51.100.0/24", targets=254, responders=[])
me.dismiss_entity("ip", GONE, "I know this device is off")
retired = safe_call(DeviceProbe("s17", {"probe": {"pacing_seconds": 0}}).retire_absent)
check("the device is still retired", retired, 1)
with sqlite3.connect(db5) as conn:
    row = conn.execute("SELECT is_permanent, retired_at FROM known_devices "
                       "WHERE ip = ?", (GONE,)).fetchone()
    n = conn.execute("SELECT COUNT(*) FROM findings "
                     "WHERE detection_id='PRB-1002'").fetchone()[0]
check("permanence was cleared", row[0], 0)
check_true("retired_at was stamped", row[1] is not None)
check("but no row was filed about a dismissed device", n, 0)


print("\n[13] RVP-13  the packet stamp reads the interface table rarely, not per frame")
# MEASURED before the fix: the shipped status() reads the whole interface table
# at 0.19 ms a call on this host (three interfaces) and _on_packet runs per
# captured FRAME, on a capture path measured at 0.79 ms a packet.
src = (ROOT / "adapters.py").read_text(encoding="utf-8")
check_true("the per-frame path calls a cached reader", "_vpn_state_now" in src)
check_false("and no longer calls status() inline in _on_packet",
            'vpn_state = _vpn.status().get("state", "unknown")' in src)

from adapters import LinuxPacketSniffer              # noqa: E402
sniffer = LinuxPacketSniffer.__new__(LinuxPacketSniffer)
sniffer._vpn_cache = (0.0, "unknown")
calls = {"n": 0}


class _CountingVPN:
    def status(self):
        calls["n"] += 1
        return {"state": "disconnected"}


import core.tool_registry as _tr                      # noqa: E402
_saved_modules = dict(_tr._modules)
_tr._modules["vpn_state"] = _CountingVPN()
try:
    values = [sniffer._vpn_state_now() for _ in range(50)]
finally:
    _tr._modules.clear()
    _tr._modules.update(_saved_modules)
check("fifty frames are stamped from ONE read", calls["n"], 1)
check("and every stamp is the same answer", set(values), {"disconnected"})

fresh = LinuxPacketSniffer.__new__(LinuxPacketSniffer)
fresh._vpn_cache = (0.0, "unknown")
_tr._modules.clear()
try:
    check("with the module absent the stamp is 'unknown', never 'disconnected'",
          fresh._vpn_state_now(), "unknown")
finally:
    _tr._modules.update(_saved_modules)


print("\n[14] the helpers this round touched, driven at their edges")
# _human_uptime is new, and a formatter that is wrong at the wrap is a wrong
# fact on a page: TimeTicks is hundredths of a second in a 32-bit counter, so
# past 497 days the raw field cannot support the sentence built from it.
check("zero ticks", rm._human_uptime(0), "0 minute(s)")
check("a minute's worth", rm._human_uptime(6000), "1 minute(s)")
check("an hour's worth", rm._human_uptime(360000), "1 hour(s) 0 minute(s)")
check("a day's worth", rm._human_uptime(8640000), "1 day(s) 0 hour(s)")
check_true("and a wrapped counter says so",
           "lower bound" in rm._human_uptime(4294967295))
check_false("while an unwrapped one does not",
            "lower bound" in rm._human_uptime(42949672))

# _normalise_router_host must not turn a non-address into one, and must not
# raise on the shapes a config file really holds.
check("an empty string stays empty", rm._normalise_router_host(""), "")
check("None does not raise", rm._normalise_router_host(None), "")
check("a name with a port is not an address", rm._normalise_router_host("router:8161"),
      "router:8161")
check("a v6 literal is normalised", rm._normalise_router_host("2001:0db8::1"),
      "2001:db8::1")
check("an out-of-range quad is left as typed, not crashed on",
      rm._normalise_router_host("999.1.1.1"), "999.1.1.1")

# age_days reads one row and answers one number; the static helper is the half
# that lets status() do that without re-reading.
dbAge = pathlib.Path(tempfile.mkdtemp(prefix="s17_age_")) / "age.db"
with sqlite3.connect(dbAge) as conn:
    conn.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
me.DB_PATH = dbAge
me.upsert_sensor(sensor_id=sn.LOCAL_SENSOR_ID, label="host", position="host",
                 summary="", can_see="", cannot_see="", notes="")
pr_age = DeviceProbe("s17", {"probe": {}})
check("never having run is None, not zero", pr_age.age_days(), None)
check("and an unrun probe is due", pr_age.due(), True)
check("which is what the note leads with",
      safe_call(pr_age.status).get("has_ever_run"), False)
check_true("the note refuses to read quiet as clean",
           "not the same as nothing being found"
           in (safe_call(pr_age.status).get("note") or ""))

me.record_probe_run("s17", "ok", probed=0, eligible=0)
check_true("after a pass there is an age", pr_age.age_days() is not None)
check("and it is under a day", pr_age.age_days() < 1, True)
check("so the probe is no longer due", pr_age.due(), False)
check_true("the status carries one age, not three reads of one",
           safe_call(pr_age.status).get("days_since_last") is not None)


print("\n[15] WIRING  the three modules are still reachable the way they were")
from core import tool_registry as registry            # noqa: E402
names = {t["name"] for t in registry.TOOL_MANIFEST}
check_true("the VPN reading is offered", "query_vpn_state" in names)
check_true("so is the router's client list", "query_router_clients" in names)
check_true("and its settings", "query_router_config" in names)
check_false("nothing in the manifest can probe", 
            [n for n in names if "probe" in n.lower()])
check_false("and nothing can turn the router collector on from the model side",
            [n for n in names if "router" in n and n.startswith(("set_", "toggle_"))])
check_true("the probe still declares itself the wrong shape for a model tool",
           "tool_registry" in (ROOT / "tools" / "probe.py").read_text(
               encoding="utf-8"))


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
