#!/usr/bin/env python3
"""
Tests for tools/router_monitor.py and the router tables behind it.

Run:

    python tests/test_router_monitor.py

Exit code 0 = everything behaved. Also importable by pytest if pytest is ever
added; on its own it needs nothing outside the standard library, because the
collector deliberately has no SNMP dependency to install.


WHY A SYNTHETIC AGENT AND NOT A MOCK

Nothing here is patched at a module boundary. A real UDP socket serves real
BER-encoded responses, the collector's real parser reads them off the wire,
and the rows land in a real SQLite database built from Schema.SQL. A mock
would test that the code calls the functions the test expects it to call,
which is the same statement twice. The thing worth checking is whether the
decoder survives bytes.

Every address is RFC 5737 documentation space, and the agent binds loopback,
so this touches nothing outside the process.


WHY THE ENCODER IS CHECKED AGAINST HAND-COMPUTED BYTES FIRST

The synthetic agent below builds its responses with the same encoder the
collector uses to build requests. On its own that arrangement would agree
with itself no matter how wrong it was. So the first group of checks compares
the encoder against BER worked out by hand from the specification, and only
after that is the agent trusted to speak for a router.


WHAT THIS IS ACTUALLY FOR

The passing cases are the cheap half. The ones that matter are the refusals:

  A quiet pass writes NO rows. A collector on a ten minute timer that grows
  the database every tick is a collector the operator turns off, and then the
  tool is blind and looks fine.

  A FIRST pass reports nothing as new. With an empty table everything is new,
  and reporting that is a wall of findings saying only that the tool started.

  An unreachable router reports WHY rather than reporting no devices. Those
  two produce the same empty table and the whole project turns on keeping
  them apart.

  A write operation cannot be built. The credential is the reason the module
  hand-rolls SNMP instead of importing a library, and "we do not call the
  write function" is a promise rather than a property.
"""

from __future__ import annotations

import os
import socket
import sqlite3
import sys
import tempfile
import threading
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Set before the collector is imported. This is the process's own environment
# and never touches .env on disk.
os.environ["AGENTAL_ROUTER_COMMUNITY"] = "test-read-only"

from tools import router_monitor as rm   # noqa: E402

ROUTER   = "192.0.2.1"
DEVICE_A = "192.0.2.10"
DEVICE_B = "192.0.2.11"
DEVICE_C = "192.0.2.99"
DEVICE_D = "192.0.2.55"
REMOTE   = "198.51.100.7"


# THE SYNTHETIC AGENT

def _octets(value):
    return rm.TAG_OCTETS, value


def _integer(value):
    return rm.TAG_INTEGER, rm._encode_int(value)[2:]


def _ipaddress(text):
    return rm.TAG_IPADDRESS, bytes(int(part) for part in text.split("."))


def _arcs(text):
    return tuple(int(part) for part in text.split("."))


def build_mib() -> dict:
    """
    A small but realistic MIB-II subset.

    Includes two things that exist to be EXCLUDED rather than found: an
    established TCP connection, which must not be recorded as a listener, and
    a hardware address prefix nobody has a vendor for, which must stay empty
    instead of being given a plausible name.
    """
    return {
        (1, 3, 6, 1, 2, 1, 1, 1, 0): _octets(b"SynthRouter OS 1.2.3 build 7788"),
        (1, 3, 6, 1, 2, 1, 1, 2, 0): (rm.TAG_OID, rm._encode_oid(
            (1, 3, 6, 1, 4, 1, 2021, 250, 10))[2:]),
        (1, 3, 6, 1, 2, 1, 1, 3, 0): (rm.TAG_TIMETICKS, (123456).to_bytes(4, "big")),
        (1, 3, 6, 1, 2, 1, 1, 5, 0): _octets(b"gateway"),
        (1, 3, 6, 1, 2, 1, 4, 1, 0): _integer(1),

        # ipNetToMediaTable, indexed by interface then the four address arcs.
        rm.OID_ARP_PHYS + (1,) + _arcs(DEVICE_A): _octets(bytes.fromhex("b827eb112233")),
        rm.OID_ARP_PHYS + (1,) + _arcs(DEVICE_B): _octets(bytes.fromhex("f0189844556f")),
        # THIS PREFIX HAD TO MOVE ON 2026-09-25, AND THE FIXTURE WAS THE THING
        # THAT WAS WRONG. It used to be 00:11:22:33:44:55, chosen because the
        # 39-entry hardcoded vendor map this tree used to carry did not list
        # it. `_stamp_vendor` now asks the IEEE registry the app SHIPS, and
        # that registry — read out of `data/oui.csv`, MA-L 001122 — assigns it
        # to "CIMSYS Inc". So the row correctly came back with a vendor and the
        # assertion below ("stays empty") read a WORKING lookup as a defect.
        # The rule this tree already carries applies: never widen the
        # production code to satisfy a fixture that encodes the old, narrower
        # world. The address is now one from a block the registry genuinely
        # does not carry (first octet 0x04 is unassigned, status
        # "unknown_prefix"), so the assertion tests what it says it tests.
        rm.OID_ARP_PHYS + (2,) + _arcs(DEVICE_C): _octets(bytes.fromhex("040000000001")),
        rm.OID_ARP_TYPE + (1,) + _arcs(DEVICE_A): _integer(3),
        rm.OID_ARP_TYPE + (1,) + _arcs(DEVICE_B): _integer(4),
        rm.OID_ARP_TYPE + (2,) + _arcs(DEVICE_C): _integer(3),

        rm.OID_IP_ADDR_IFINDEX + _arcs(ROUTER): _integer(1),
        rm.OID_IF_DESCR + (1,): _octets(b"br-lan"),
        rm.OID_IF_DESCR + (2,): _octets(b"eth-wan"),

        # tcpConnTable: local address, local port, remote address, remote port.
        rm.OID_TCP_CONN_STATE + _arcs(ROUTER) + (80,) + (0, 0, 0, 0) + (0,): _integer(2),
        rm.OID_TCP_CONN_STATE + (0, 0, 0, 0) + (22,) + (0, 0, 0, 0) + (0,): _integer(2),
        # Established, not listening. Must not appear as a listener.
        rm.OID_TCP_CONN_STATE + _arcs(ROUTER) + (443,) + _arcs(REMOTE) + (5522,): _integer(5),

        rm.OID_UDP_LOCAL_ADDRESS + (0, 0, 0, 0) + (53,): _ipaddress("0.0.0.0"),
    }


class SyntheticAgent:
    """A loopback UDP responder answering get, get-next and get-bulk."""

    def __init__(self, mib: dict, refuse_bulk: bool = False):
        self.mib = mib
        self.refuse_bulk = refuse_bulk
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.stop = False
        self.next_requests = 0
        self.bulk_requests = 0
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
        _, _raw_a, cursor = rm._read_tlv(pdu, cursor)
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

        if pdu_tag == rm.PDU_GET_BULK and self.refuse_bulk:
            self.bulk_requests += 1
            return self._response(request_id, 5, [])      # genErr

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
            if pdu_tag == rm.PDU_GET_BULK:
                self.bulk_requests += 1
                count = max(1, repetitions)
            else:
                self.next_requests += 1
                count = 1
            walker = asked[0]
            for _ in range(count):
                following = [o for o in ordered if o > walker]
                if not following:
                    results.append((walker, rm.TAG_END_OF_MIB_VIEW, b""))
                    break
                walker = following[0]
                tag, value = self.mib[walker]
                results.append((walker, tag, value))

        return self._response(request_id, 0, results)

    @staticmethod
    def _response(request_id: int, error_status: int, results: list) -> bytes:
        binds = b"".join(
            rm._tlv(rm.TAG_SEQUENCE, rm._encode_oid(oid) + rm._tlv(tag, value))
            for oid, tag, value in results
        )
        pdu = rm._tlv(rm.PDU_RESPONSE, (
            rm._encode_int(request_id)
            + rm._encode_int(error_status)
            + rm._encode_int(0)
            + rm._tlv(rm.TAG_SEQUENCE, binds)
        ))
        return rm._tlv(rm.TAG_SEQUENCE, (
            rm._encode_int(1)
            + rm._tlv(rm.TAG_OCTETS, b"test-read-only")
            + pdu
        ))


# THE CHECKS

def _encoding_checks(fail):
    # Worked out by hand from the specification, not from this module.
    # 1.3 packs into a single byte as 1 * 40 + 3, which is 0x2b.
    fail("sysDescr identifier encodes to known bytes",
         rm._encode_oid((1, 3, 6, 1, 2, 1, 1, 1, 0))
         == bytes.fromhex("06082b0601020101" "0100"))

    # 2021 is 0b11111100101, which is 15 then 101 in seven-bit groups.
    fail("an arc above 127 uses continuation bytes",
         rm._encode_oid((1, 3, 6, 1, 4, 1, 2021)).endswith(bytes.fromhex("8f65")))

    fail("128 keeps a leading zero so it stays positive",
         rm._encode_int(128) == bytes.fromhex("02020080"))
    fail("127 does not need one", rm._encode_int(127) == bytes.fromhex("02017f"))
    fail("zero encodes as a single zero byte",
         rm._encode_int(0) == bytes.fromhex("020100"))
    fail("a length of 200 uses the long form",
         rm._encode_length(200) == bytes.fromhex("81c8"))
    fail("a length of 5 does not", rm._encode_length(5) == b"\x05")
    fail("identifiers survive a round trip",
         rm._decode_oid(rm._encode_oid((1, 3, 6, 1, 4, 1, 2021, 250, 10))[2:])
         == (1, 3, 6, 1, 4, 1, 2021, 250, 10))


def _parser_refusal_checks(fail):
    """
    The decoder reads bytes off the network from a device that could be
    lying, so every one of these is a length field chosen to make a trusting
    decoder read past its buffer.
    """
    for label, blob in (
        ("a length longer than the buffer", bytes.fromhex("3082ffff00")),
        ("a truncated header", b"\x30"),
        ("an unsupported length form", bytes.fromhex("30880000000000000001")),
    ):
        try:
            rm._read_tlv(blob, 0)
            fail(f"the decoder refuses {label}", False)
        except rm.SnmpError:
            fail(f"the decoder refuses {label}", True)
        except Exception:
            fail(f"the decoder refuses {label} with the right error", False)


def _write_operation_checks(fail):
    fail("only get, get-next and get-bulk are permitted",
         rm._READ_ONLY_PDUS == frozenset({rm.PDU_GET, rm.PDU_GET_NEXT,
                                          rm.PDU_GET_BULK}))
    fail("no module constant carries the write tag",
         not [name for name, value in vars(rm).items()
              if type(value) is int and value == 0xA3])

    session = rm.SnmpSession(ROUTER, "unused")
    try:
        session._build(0xA3, 1, [(1, 3, 6, 1)])
        fail("the builder refuses a write request", False)
    except rm.SnmpError:
        fail("the builder refuses a write request", True)


def _fresh_database() -> Path:
    directory = tempfile.mkdtemp(prefix="agental_router_test_")
    path = Path(directory) / "test.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        (PROJECT_ROOT / "Schema.SQL").read_text(encoding="utf-8"))
    connection.commit()
    connection.close()
    return path


def run() -> list:
    failures = []

    def fail(label, condition, detail=""):
        if not condition:
            failures.append(f"{label} {detail}".strip())

    _encoding_checks(fail)
    _parser_refusal_checks(fail)
    _write_operation_checks(fail)

    from core import memory_engine as me
    me.DB_PATH = _fresh_database()

    mib = build_mib()
    agent = SyntheticAgent(mib)
    config = {"router_monitor": {
        "enabled": True, "backend": "snmp", "host": "127.0.0.1",
        "port": agent.port, "timeout_seconds": 2, "label": "test-gateway",
    }}

    try:
        # AVAILABILITY. Three states that must never look alike.
        fail("available when address and community are both set",
             rm.status(config)["available"])

        public = rm.public_status(config)
        fail("public status carries no community string",
             "community" not in public)
        fail("public status carries no address", "host" not in public)

        os.environ["AGENTAL_ROUTER_COMMUNITY"] = ""
        without = rm.status(config)
        fail("unavailable without a community", not without["available"])
        fail("and names the missing variable",
             "AGENTAL_ROUTER_COMMUNITY" in (without["reason"] or ""))
        fail("but still reports itself configured", without["configured"])
        os.environ["AGENTAL_ROUTER_COMMUNITY"] = "test-read-only"

        config["router_monitor"]["enabled"] = False
        fail("switched off is reported as the switch, not a missing credential",
             rm.status(config)["reason"] == "turned off in config.json")
        config["router_monitor"]["enabled"] = True

        # FIRST PASS.
        first = rm.collect_once(config, session_id="test-session")
        fail("the first pass ran", first.get("ran"), str(first.get("reason")))
        fail("all three neighbour entries were read",
             first.get("clients_seen") == 3, str(first.get("clients_seen")))
        fail("it knows it was a first pass", first.get("first_pass") is True)
        fail("and raises nothing, because everything would be new",
             first.get("findings_raised") == 0)

        result = me.query_router_clients()
        by_address = {row["ip"]: row for row in result["clients"]}
        fail("addresses come out of the identifier index",
             set(by_address) == {DEVICE_A, DEVICE_B, DEVICE_C},
             str(sorted(by_address)))
        fail("hardware addresses are decoded",
             by_address[DEVICE_A]["mac"] == "b8:27:eb:11:22:33")
        # THESE TWO ASSERTIONS WERE RESTATED ON 2026-09-24, AND THE OLD ONES
        # WERE MEASURING A WEAKER ANSWER. `_oui_lookup` used to consult a
        # 39-entry hardcoded map, which happens to spell this prefix
        # "Raspberry Pi"; it now asks the IEEE registry the app already ships,
        # which spells it "Raspberry Pi Foundation" — the registrant's own
        # name, from the file, which is what the device row is supposed to
        # carry. The fixture's address is unchanged; the assertion was pinning
        # the map's spelling rather than the fact that a vendor is produced.
        # The unknown-prefix case is UNCHANGED and still the important one: a
        # prefix nobody registered must stay empty rather than be guessed at.
        fail("a known prefix produces the registry's own name for the vendor",
             by_address[DEVICE_A]["vendor"] == "Raspberry Pi Foundation",
             str(by_address[DEVICE_A]["vendor"]))
        fail("an unknown prefix stays empty rather than being guessed at",
             by_address[DEVICE_C]["vendor"] is None)
        fail("the entry type is decoded",
             by_address[DEVICE_B]["entry_type"] == "static")
        fail("the interface comes out of the index",
             by_address[DEVICE_C]["interface"] == "2")
        fail("devices no host sensor has seen are flagged as such",
             len(result["not_seen_by_any_host_sensor"]) == 3)
        fail("the note refuses to let absence mean anything",
             "absence means nothing" in result["note"].lower())

        # VANTAGE POINT.
        sensors = me.query_sensors()
        gateway_api = [s for s in sensors if s["position"] == "gateway_api"]
        fail("registered at gateway_api rather than gateway",
             len(gateway_api) == 1)
        if gateway_api:
            fail("its scope states that it sees no traffic",
                 "any traffic whatsoever" in gateway_api[0]["cannot_see"].lower())
            fail("its identifier carries no address",
                 "127.0.0.1" not in gateway_api[0]["sensor_id"])

        # SETTINGS.
        settings = me.query_router_config()
        names = {s["setting"] for s in settings["settings"]}
        values = {s["setting"]: s["value"] for s in settings["settings"]}
        # RESTATED 2026-09-27, REGISTER SECTION 17 (RVP-4). These pins used the
        # bare `listener:tcp:<port>` name, which was THE DEFECT: a router
        # answering one port at two addresses wrote two rows under one name and
        # `router_config` is UNIQUE(router_host, setting), so the second
        # overwrote the first and the stored value flip-flopped on every pass.
        # The name now carries the bound address, so the assertion names the
        # binding it means. The old pins were not wrong about the FACT (a
        # listening port is recorded); they were asserting a name that made the
        # fact unrecordable twice.
        fail("the firmware description is recorded", "sysDescr" in names)
        fail("a listening port is recorded",
             "listener:tcp:80:" + ROUTER in names, str(sorted(names)))
        fail("a second one is too", "listener:tcp:22:0.0.0.0" in names,
             str(sorted(names)))
        fail("an ESTABLISHED connection is not recorded as a listener",
             not any(n.startswith("listener:tcp:443") for n in names))
        fail("a udp listener is recorded", "listener:udp:53:0.0.0.0" in names,
             str(sorted(names)))
        fail("a listener on the unspecified address reads as all_interfaces",
             values.get("listener:tcp:22:0.0.0.0") == "all_interfaces")
        fail("a listener on a private address reads as private",
             values.get("listener:tcp:80:" + ROUTER) == "private")
        fail("no severity is attached to any setting",
             not any("severity" in s for s in settings["settings"]))

        # A QUIET PASS MUST WRITE NOTHING. The single most important check
        # here: a collector that grows the database on every tick is one the
        # operator switches off, and then the tool is blind and looks healthy.
        with sqlite3.connect(me.DB_PATH) as connection:
            before = connection.execute(
                "SELECT COUNT(*) FROM router_clients").fetchone()[0]
        second = rm.collect_once(config, session_id="test-session")
        with sqlite3.connect(me.DB_PATH) as connection:
            after = connection.execute(
                "SELECT COUNT(*) FROM router_clients").fetchone()[0]
            quiet_findings = connection.execute(
                "SELECT COUNT(*) FROM findings").fetchone()[0]
        fail("a quiet pass writes no new rows", before == after,
             f"{before} then {after}")
        fail("a quiet pass reports nothing new", second.get("clients_new") == 0)
        fail("a quiet pass reports no drift", second.get("config_changed") == 0)
        fail("a quiet pass raises no findings", quiet_findings == 0)
        fail("and it is no longer a first pass",
             second.get("first_pass") is False)

        # CHANGE.
        mib[rm.OID_ARP_PHYS + (1,) + _arcs(DEVICE_D)] = _octets(
            bytes.fromhex("dca632aabbcc"))
        mib[rm.OID_ARP_TYPE + (1,) + _arcs(DEVICE_D)] = _integer(3)
        mib[(1, 3, 6, 1, 2, 1, 1, 1, 0)] = _octets(b"SynthRouter OS 1.3.0 build 9001")
        del mib[rm.OID_TCP_CONN_STATE + (0, 0, 0, 0) + (22,) + (0, 0, 0, 0) + (0,)]

        third = rm.collect_once(config, session_id="test-session")
        fail("a device that appears is reported once",
             third.get("clients_new") == 1, str(third.get("clients_new")))
        fail("a changed value and a vanished listener are both drift",
             third.get("config_changed") == 2, str(third.get("config_changed")))

        drift = {s["setting"]: s
                 for s in me.query_router_config(changed_only=True)["settings"]}
        fail("the previous value is kept",
             "1.2.3" in (drift["sysDescr"]["previous_value"] or ""))
        # RESTATED 2026-09-27 with the two listener pins above (RVP-4).
        fail("a vanished setting is marked absent rather than deleted",
             drift["listener:tcp:22:0.0.0.0"]["present"] is False)

        with sqlite3.connect(me.DB_PATH) as connection:
            found = connection.execute(
                "SELECT severity, entity_value FROM findings").fetchall()
        fail("three findings were raised", len(found) == 3, str(len(found)))
        fail("the new device is named in one of them",
             any(row[1] == DEVICE_D for row in found))
        fail("nothing was raised above medium",
             all(row[0] == "medium" for row in found))

        # ADOPTING A SELF-REPORTED NAME.
        refused = me.adopt_router_hostname(DEVICE_A)
        fail("adoption refuses when no name was reported",
             not refused["success"])
        fail("and explains that standard SNMP carries none",
             "does not carry device names" in refused["error"])

        with sqlite3.connect(me.DB_PATH) as connection:
            connection.execute(
                "UPDATE router_clients SET hostname = ? WHERE ip = ?",
                ("living-room-tv", DEVICE_A))
        adopted = me.adopt_router_hostname(DEVICE_A)
        fail("adoption works once a name exists", adopted.get("success"))
        if adopted.get("success"):
            fail("and records that the device chose the name itself",
                 "Self-reported" in (adopted["device"]["evidence"] or ""))

        # THE FALLBACK PATH.
        stubborn = SyntheticAgent(mib, refuse_bulk=True)
        config["router_monitor"]["port"] = stubborn.port
        fallback = rm.collect_once(config, session_id="test-session")
        fail("a router that refuses get-bulk is still read completely",
             fallback.get("clients_seen") == 4,
             str(fallback.get("clients_seen")))
        fail("and get-next was actually used", stubborn.next_requests > 0)
        stubborn.close()

        # AN UNREACHABLE ROUTER. This must never resemble an empty network.
        config["router_monitor"]["port"] = 9
        config["router_monitor"]["timeout_seconds"] = 0.4
        unreachable = rm.collect_once(config, session_id="test-session")
        fail("an unreachable router does not report a successful run",
             not unreachable.get("ran"))
        fail("and says the router did not answer",
             "did not answer" in (unreachable.get("reason") or ""))
    finally:
        agent.close()

    # WIRING. Cheap to check and expensive to get wrong quietly.
    from core import sanitize
    from core import tool_registry as registry

    fail("adopting a self-reported name is gated",
         registry.requires_permission("adopt_router_hostname", {"ip": DEVICE_A}))
    fail("reading the client list is not",
         not registry.requires_permission("query_router_clients", {}))
    fail("both query tools are fenced as untrusted",
         sanitize.is_untrusted("query_router_clients")
         and sanitize.is_untrusted("query_router_config"))
    fail("the client list is a real tool",
         registry.tool_exists("query_router_clients"))
    fail("and so is the gated one, which is why the gate is what protects it",
         registry.tool_exists("adopt_router_hostname"))
    fail("NO tool can turn the collector on",
         not [t for t in registry.TOOL_MANIFEST
              if "router" in t["name"] and t["name"].startswith(
                  ("set_", "enable_", "toggle_"))])

    card = registry.permission_summary("adopt_router_hostname", {"ip": DEVICE_A})
    fail("the permission card shows the name being adopted",
         "living-room-tv" in card, card)
    fail("and says the device chose it", "chosen by the device" in card)

    return failures


def test_router_monitor():
    """Pytest entry point, if pytest is ever added."""
    failures = run()
    assert not failures, "\n".join(failures)


def main() -> int:
    print("ROUTER MONITOR TESTS")
    failures = run()
    if not failures:
        print("\nEverything behaved.")
        return 0
    print(f"\n{len(failures)} FAILURE(S):\n")
    for failure in failures:
        print(f"  {failure}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
