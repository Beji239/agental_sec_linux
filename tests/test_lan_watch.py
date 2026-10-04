# tests/test_lan_watch.py
# AgentalSec V2, TODO 113.5. Tests for tools/lan_watch.
#
# RULE ONE: failure cases first. Sections 1 to 5 are every way this can
# decline to fire or fail to look, and they come before anything that checks
# it catches an attack.
#
# THE ONE THAT MATTERS MOST here is section 5, the learning cases. All three
# stateful detections compare against a baseline, and a baseline that is
# invented on first sight would alert on a healthy network every time the app
# started. A baseline that is silently relearned at every restart is the
# opposite fault and is just as bad: it can never be violated, so the
# detection runs forever and cannot fire.

import pathlib
import sys

# THE ROOT INSERTION, added 2026-09-21. See the note in test_feed_matcher.py
# for the full reason: this file had no `sys.path` setup because it was only
# ever run through `python -m pytest`, which puts the current directory on the
# path. scripts/run_tests.py runs it as a standalone script and does not, so
# the import below failed and the runner reported the file as needing pytest.
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db                              # noqa: E402
_isolate_db.isolate()

import pytest

from tools import lan_watch as lw


def _w(gateway_ip=None):
    """A LanWatch with no database behind it."""
    return lw.LanWatch(gateway_ip=gateway_ip, load_baselines=False)


# SECTION 1. FAILURE: junk input must never become a finding.

def test_normalise_mac_rejects_non_macs():
    assert lw._normalise_mac("") == ""
    assert lw._normalise_mac(None) == ""
    assert lw._normalise_mac("not a mac") == ""
    assert lw._normalise_mac("aa:bb:cc") == ""
    assert lw._normalise_mac("zz:zz:zz:zz:zz:zz") == ""


def test_normalise_mac_accepts_both_separators_and_cases():
    assert lw._normalise_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert lw._normalise_mac("aa-bb-cc-dd-ee-ff") == "aa:bb:cc:dd:ee:ff"
    assert lw._normalise_mac("a:b:c:d:e:f") == "0a:0b:0c:0d:0e:0f"


def test_arp_with_a_junk_mac_is_ignored():
    w = _w()
    assert w.observe_arp(2, "192.0.2.5", "garbage", now=0) == []
    assert w.status()["tracked_arp_bindings"] == 0


def test_arp_with_the_unspecified_address_is_ignored():
    w = _w()
    assert w.observe_arp(1, "0.0.0.0", "aa:bb:cc:dd:ee:01", now=0) == []
    assert w.status()["tracked_arp_bindings"] == 0


def test_dhcp_with_no_server_address_is_ignored():
    w = _w()
    assert w.observe_dhcp_server("", "offer", now=0) == []
    assert w.observe_dhcp_server("0.0.0.0", "offer", now=0) == []
    assert w.status()["dhcp_servers"] == []


def test_name_response_with_no_name_is_ignored():
    w = _w()
    assert w.observe_name_response("LLMNR", "192.0.2.8", "", now=0) == []
    assert w.observe_name_response("LLMNR", "", "printer", now=0) == []


def test_nbtns_decode_rejects_junk():
    assert lw.decode_nbtns_name("") == ""
    assert lw.decode_nbtns_name("ABC") == ""        # odd length
    assert lw.decode_nbtns_name("AB1C") == ""       # not all letters


def test_nbtns_decode_round_trip():
    # "FRED" encodes to EGFCFFFE plus a service byte, padded with CA (space).
    def encode(name, pad_to=16):
        raw = name.ljust(pad_to - 1)[:pad_to - 1].encode() + b"\x00"
        return "".join(
            chr(65 + (b >> 4)) + chr(65 + (b & 0x0F)) for b in raw)

    assert lw.decode_nbtns_name(encode("FRED")) == "fred"


# SECTION 2. FAILURE: ARP that is ordinary must stay quiet.

def test_first_arp_sighting_is_never_a_finding():
    w = _w()
    assert w.observe_arp(2, "192.0.2.5", "aa:bb:cc:dd:ee:01", now=0) == []


def test_repeating_the_same_binding_is_never_a_finding():
    w = _w()
    for i in range(50):
        out = w.observe_arp(2, "192.0.2.5", "aa:bb:cc:dd:ee:01", now=i)
        assert out == []


def test_one_binding_change_is_a_dhcp_lease_not_a_spoof():
    """
    THE TUNING DECISION. One change is what a lease moving to a new device
    looks like, and firing on it would make this detection useless on any
    network with DHCP, which is all of them.
    """
    w = _w()
    w.observe_arp(2, "192.0.2.5", "aa:bb:cc:dd:ee:01", now=0)
    out = w.observe_arp(2, "192.0.2.5", "aa:bb:cc:dd:ee:02", now=10)
    assert out == []


def test_two_changes_is_still_below_the_threshold():
    w = _w()
    macs = ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"]
    out = []
    for i, m in enumerate(macs):
        out = w.observe_arp(2, "192.0.2.5", m, now=i * 10)
    assert out == []            # 2 changes, threshold is 3


def test_changes_outside_the_window_do_not_accumulate():
    """
    A device that changes hands once a month is not flapping. Old changes
    fall out of the window, so they cannot add up over a long uptime.
    """
    w = _w()
    w.observe_arp(2, "192.0.2.5", "aa:bb:cc:dd:ee:01", now=0)
    out = []
    for i in range(1, 6):
        # Each change is a full window apart.
        out = w.observe_arp(
            2, "192.0.2.5", f"aa:bb:cc:dd:ee:0{i + 1}",
            now=i * (lw.ARP_FLAP_WINDOW_SECS + 60))
    assert out == []


def test_different_ips_changing_once_each_do_not_combine():
    """The counter is per address, not global."""
    w = _w()
    out = []
    for n in range(10):
        ip = f"10.0.0.{n}"
        w.observe_arp(2, ip, "aa:bb:cc:dd:ee:01", now=0)
        out = w.observe_arp(2, ip, "aa:bb:cc:dd:ee:02", now=1)
    assert out == []


# SECTION 3. FAILURE: the gateway check when it cannot run.

def test_no_gateway_ip_means_the_check_is_off_and_says_so():
    """
    The failure that matters. With no gateway address the highest value
    detection in this module cannot run, and status() has to SAY it is not
    running rather than reporting a quiet network.
    """
    w = _w(gateway_ip=None)
    s = w.status()
    assert s["can_check_gateway_mac"] is False
    assert any("NOT RUNNING" in n for n in s["notes"])


def test_gateway_traffic_with_no_gateway_ip_raises_nothing():
    w = _w(gateway_ip=None)
    w.observe_arp(2, "192.0.2.1", "aa:bb:cc:dd:ee:01", now=0)
    out = w.observe_arp(2, "192.0.2.1", "ff:ff:ff:ff:ff:fe", now=1)
    assert out == []            # flap threshold not met, gateway check off


def test_status_says_nothing_has_looked_on_a_fresh_instance():
    w = _w(gateway_ip="192.0.2.1")
    s = w.status()
    assert s["has_looked"] is False
    assert s["total_frames_seen"] == 0
    assert any("not the same as nothing being found" in n for n in s["notes"])


def test_status_always_carries_the_unicast_caveat():
    """
    A targeted ARP spoof is unicast and this sensor never sees it. That
    caveat must be on EVERY status, including a busy healthy one, or a quiet
    result gets read as proof.
    """
    w = _w(gateway_ip="192.0.2.1")
    for i in range(100):
        w.observe_arp(2, f"10.0.0.{i % 20}", "aa:bb:cc:dd:ee:01", now=i)
    s = w.status()
    assert s["has_looked"] is True
    assert any("UNICAST" in n for n in s["notes"])


# SECTION 4. FAILURE: name responses that are normal.

def test_a_host_answering_for_its_own_name_never_fires():
    """
    A normal machine answers LLMNR for exactly one name, its own, however
    much traffic it generates. Volume must not be the gate.
    """
    w = _w()
    out = []
    for i in range(500):
        out = w.observe_name_response("LLMNR", "192.0.2.8", "laptop", now=i)
    assert out == []


def test_three_distinct_names_is_below_the_threshold():
    w = _w()
    out = []
    for i, n in enumerate(["a", "b", "c"]):
        out = w.observe_name_response("LLMNR", "192.0.2.8", n, now=i)
    assert out == []


def test_names_outside_the_window_expire():
    """
    Four names spread over a long uptime is not a poisoner. They have to be
    inside the same window to count.
    """
    w = _w()
    out = []
    for i, n in enumerate(["a", "b", "c", "d", "e"]):
        out = w.observe_name_response(
            "LLMNR", "192.0.2.8", n, now=i * (lw.POISON_WINDOW_SECS + 60))
    assert out == []


def test_distinct_names_are_counted_per_responder():
    """Four hosts answering for one name each is four normal machines."""
    w = _w()
    out = []
    for i, n in enumerate(["a", "b", "c", "d", "e", "f"]):
        out = w.observe_name_response("LLMNR", f"10.0.0.{i}", n, now=i)
    assert out == []


# SECTION 5. THE LEARNING CASES. First sighting is learned, not judged.

def test_first_gateway_mac_is_learned_silently(monkeypatch):
    saved = {}
    w = _w(gateway_ip="192.0.2.1")
    monkeypatch.setattr(w, "_save_gateway_mac",
                        lambda m: saved.update(mac=m))

    out = w.observe_arp(2, "192.0.2.1", "aa:bb:cc:dd:ee:01", now=0)

    assert out == []
    assert saved["mac"] == "aa:bb:cc:dd:ee:01"


def test_first_dhcp_server_is_learned_silently(monkeypatch):
    w = _w()
    monkeypatch.setattr(w, "_save_dhcp_servers", lambda: None)

    out = w.observe_dhcp_server("192.0.2.1", "offer", now=0)

    assert out == []
    assert w.status()["dhcp_servers"] == ["192.0.2.1"]


def test_the_same_dhcp_server_never_fires_again(monkeypatch):
    w = _w()
    monkeypatch.setattr(w, "_save_dhcp_servers", lambda: None)
    w.observe_dhcp_server("192.0.2.1", "offer", now=0)

    for i in range(20):
        assert w.observe_dhcp_server("192.0.2.1", "ack", now=i) == []


def test_a_baseline_that_cannot_be_read_is_logged_not_swallowed(monkeypatch,
                                                                caplog):
    """
    A baseline we could not READ is different from one that does not exist
    yet. Starting silently from nothing means never alerting on a change,
    which is the detection running forever and never firing.

    RESTATED 2026-09-26 (register section 13). This patched
    memory_engine.get_preference, which is not the read path any more: the
    baselines moved out of user_preferences into the lan_baseline table (it
    was being hashed as the policy by core/integrity -- see the module
    header). A fixture that patches the old seam would pass while the real
    path went unmeasured, so it patches the connection helper instead and
    asserts the READER's own warning.
    """
    import core.memory_engine as me

    def boom(*a, **k):
        raise RuntimeError("db locked")

    monkeypatch.setattr(me, "_get_conn", boom)

    with caplog.at_level("WARNING"):
        lw.LanWatch(gateway_ip="192.0.2.1", load_baselines=True)

    assert any("could not be read" in r.message for r in caplog.records)


# SECTION 6. HAPPY PATH. Only now.

def test_arp_flap_fires_at_the_threshold():
    w = _w()
    macs = ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
            "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
    out = []
    for i, m in enumerate(macs):
        out = w.observe_arp(2, "192.0.2.5", m, now=i * 10)

    assert len(out) == 1
    assert out[0]["detection_id"] == "LAN-1001"
    assert out[0]["severity"] == "high"
    assert out[0]["entity_value"] == "192.0.2.5"
    assert out[0]["raw_data"]["changes"] >= lw.ARP_FLAP_THRESHOLD


def test_gateway_mac_change_fires(monkeypatch):
    w = _w(gateway_ip="192.0.2.1")
    monkeypatch.setattr(w, "_save_gateway_mac",
                        lambda m: setattr(w, "_gateway_mac", m))

    w.observe_arp(2, "192.0.2.1", "aa:bb:cc:dd:ee:01", now=0)
    out = w.observe_arp(2, "192.0.2.1", "de:ad:be:ef:00:01", now=10)

    gw = [f for f in out if f["detection_id"] == "LAN-1002"]
    assert len(gw) == 1
    assert gw[0]["severity"] == "high"
    assert gw[0]["raw_data"]["old_mac"] == "aa:bb:cc:dd:ee:01"
    assert gw[0]["raw_data"]["new_mac"] == "de:ad:be:ef:00:01"


def test_gateway_mac_change_does_not_repeat(monkeypatch):
    """
    One finding per wrong address, not one per frame forever.

    REWRITTEN 2026-09-20. This used to say the baseline moves after raising,
    and that was the bug: it meant a spoofer's address became the trusted one.
    The repeat is held down in memory now and the baseline stays put, which is
    what test_the_baseline_does_not_move_after_a_change checks.
    """
    w = _w(gateway_ip="192.0.2.1")
    monkeypatch.setattr(w, "_save_gateway_mac",
                        lambda m: setattr(w, "_gateway_mac", m))

    w.observe_arp(2, "192.0.2.1", "aa:bb:cc:dd:ee:01", now=0)
    first = w.observe_arp(2, "192.0.2.1", "de:ad:be:ef:00:01", now=10)
    assert any(f["detection_id"] == "LAN-1002" for f in first)

    for i in range(20):
        again = w.observe_arp(2, "192.0.2.1", "de:ad:be:ef:00:01", now=20 + i)
        assert not any(f["detection_id"] == "LAN-1002" for f in again)


def test_second_dhcp_server_fires(monkeypatch):
    w = _w()
    monkeypatch.setattr(w, "_save_dhcp_servers", lambda: None)

    w.observe_dhcp_server("192.0.2.1", "offer", now=0)
    out = w.observe_dhcp_server("192.0.2.18", "offer", now=10)

    assert len(out) == 1
    assert out[0]["detection_id"] == "LAN-1003"
    assert out[0]["entity_value"] == "192.0.2.18"
    assert "192.0.2.1" in out[0]["raw_data"]["known_servers"]


def test_second_dhcp_server_does_not_repeat(monkeypatch):
    w = _w()
    monkeypatch.setattr(w, "_save_dhcp_servers", lambda: None)
    w.observe_dhcp_server("192.0.2.1", "offer", now=0)
    w.observe_dhcp_server("192.0.2.18", "offer", now=10)

    for i in range(10):
        assert w.observe_dhcp_server("192.0.2.18", "ack", now=20 + i) == []


def test_name_poisoning_fires_at_the_distinct_threshold():
    w = _w()
    out = []
    for i, n in enumerate(["printer", "fileshare", "wpad", "typo-server"]):
        out = w.observe_name_response("LLMNR", "192.0.2.8", n, now=i)

    assert len(out) == 1
    assert out[0]["detection_id"] == "LAN-1004"
    assert out[0]["entity_value"] == "192.0.2.8"
    assert out[0]["raw_data"]["distinct_names"] == 4


def test_nbtns_poisoning_fires_too():
    w = _w()
    out = []
    for i, n in enumerate(["a", "b", "c", "d"]):
        out = w.observe_name_response("NBT-NS", "192.0.2.8", n, now=i)
    assert out and out[0]["raw_data"]["protocol"] == "NBT-NS"


def test_counters_move_so_status_can_be_believed():
    w = _w(gateway_ip="192.0.2.1")
    w.observe_arp(2, "192.0.2.5", "aa:bb:cc:dd:ee:01", now=0)
    w.observe_dhcp_server("192.0.2.1", "offer", now=0)
    w.observe_name_response("LLMNR", "192.0.2.8", "x", now=0)

    s = w.status()
    assert s["arp_frames_seen"] == 1
    assert s["dhcp_frames_seen"] == 1
    assert s["name_frames_seen"] == 1
    assert s["has_looked"] is True


# SECTION 7. Memory is bounded.

def test_arp_binding_table_is_bounded():
    """A spoofer spraying a made-up range must not grow the dict forever."""
    w = _w()
    for i in range(lw.ARP_MAX_TRACKED * 2):
        w.observe_arp(2, f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}",
                      "aa:bb:cc:dd:ee:01", now=0)
    assert w.status()["tracked_arp_bindings"] <= lw.ARP_MAX_TRACKED + 1


# SECTION 8. Every id this module emits is in the register.

def test_lan_detections_are_registered():
    from core import detections

    for did in ("LAN-1001", "LAN-1002", "LAN-1003", "LAN-1004"):
        assert detections.exists(did), f"{did} is not in the register"
        d = detections.get(did)
        # The SOURCE is packet_sniffer, not lan_watch: this module holds the
        # logic but packet_sniffer is what raises.
        assert d.source == "packet_sniffer"
        assert d.entity_type == "ip"
        assert "high" in d.severities


def test_every_severity_emitted_is_declared():
    """
    A finding raised at a severity the register does not declare is refused by
    save_finding, so the two have to agree here rather than at runtime.
    """
    from core import detections

    w = _w(gateway_ip="192.0.2.1")
    emitted = []

    macs = ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
            "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
    for i, m in enumerate(macs):
        emitted += w.observe_arp(2, "192.0.2.5", m, now=i * 10)

    w2 = _w()
    for i, n in enumerate(["a", "b", "c", "d"]):
        emitted += w2.observe_name_response("LLMNR", "192.0.2.8", n, now=i)

    assert emitted
    for f in emitted:
        d = detections.get(f["detection_id"])
        assert f["severity"] in d.severities


# SECTION 9. The wire parsers. Bytes in, name out.
#
# These are the part most likely to be wrong, which is why they were moved
# out of packet_sniffer and into a module that takes bytes. A misparse here
# does not produce a wrong name, it produces an EXTRA name, and LAN-1004 is a
# count of distinct names.

def _llmnr(name: str, response: bool = True) -> bytes:
    flags = 0x8000 if response else 0x0000
    out = bytearray()
    out += (0x1234).to_bytes(2, "big")
    out += flags.to_bytes(2, "big")
    out += (1).to_bytes(2, "big")       # qdcount
    out += b"\x00" * 6                  # an, ns, ar
    for label in name.split("."):
        out.append(len(label))
        out += label.encode()
    out.append(0)
    out += (1).to_bytes(2, "big")       # qtype
    out += (1).to_bytes(2, "big")       # qclass
    return bytes(out)


def test_llmnr_parser_reads_a_response():
    assert lw.parse_llmnr_query_name(_llmnr("printer")) == "printer"
    assert lw.parse_llmnr_query_name(_llmnr("wpad.local")) == "wpad.local"


def test_llmnr_parser_refuses_a_query():
    """A query is what somebody looked for. Only a response is a claim."""
    assert lw.parse_llmnr_query_name(_llmnr("printer", response=False)) == ""


def test_llmnr_parser_refuses_junk():
    assert lw.parse_llmnr_query_name(b"") == ""
    assert lw.parse_llmnr_query_name(b"\x00" * 5) == ""
    assert lw.parse_llmnr_query_name(None) == ""


def test_llmnr_parser_refuses_a_truncated_label():
    """
    A label claiming more bytes than are present must return '', not the
    bytes that happen to be there.
    """
    buf = bytearray(_llmnr("printer"))
    buf[12] = 200                       # label length past the end
    assert lw.parse_llmnr_query_name(bytes(buf)) == ""


def test_llmnr_parser_refuses_a_compression_pointer():
    buf = bytearray(_llmnr("printer"))
    buf[12] = 0xC0                      # pointer where a length belongs
    assert lw.parse_llmnr_query_name(bytes(buf)) == ""


def _nbtns(name: str, response: bool = True) -> bytes:
    raw = name.upper().ljust(15)[:15].encode() + b"\x00"
    encoded = "".join(
        chr(65 + (b >> 4)) + chr(65 + (b & 0x0F)) for b in raw)
    flags = 0x8400 if response else 0x0000
    out = bytearray()
    out += (0x1234).to_bytes(2, "big")
    out += flags.to_bytes(2, "big")
    out += (1).to_bytes(2, "big")
    out += b"\x00" * 6
    out.append(32)
    out += encoded.encode()
    out.append(0)
    out += (0x20).to_bytes(2, "big")
    out += (1).to_bytes(2, "big")
    return bytes(out)


def test_nbtns_parser_reads_a_response():
    assert lw.parse_nbtns_query_name(_nbtns("FILESRV")) == "filesrv"


def test_nbtns_parser_refuses_a_query():
    assert lw.parse_nbtns_query_name(_nbtns("FILESRV", response=False)) == ""


def test_nbtns_parser_refuses_a_wrong_label_length():
    buf = bytearray(_nbtns("FILESRV"))
    buf[12] = 16                        # NBT-NS names are always 32
    assert lw.parse_nbtns_query_name(bytes(buf)) == ""


def test_nbtns_parser_refuses_junk():
    assert lw.parse_nbtns_query_name(b"") == ""
    assert lw.parse_nbtns_query_name(b"\x00" * 13) == ""


# SECTION 12. THE BASELINE IS NOT WRITTEN BY THE WIRE. 2026-09-20.
#
# FAILURE FIRST, and this is the worst thing that was in this file. Both
# LAN-1002 and LAN-1003 raised a finding and then wrote the value that caused
# it into the saved baseline. During a live attack that persisted the
# ATTACKER'S value as the trusted one: after a restart the spoof looked normal
# and the real router looked like the attack, and a rogue DHCP server was
# permanently treated as known good.

def test_the_gateway_baseline_does_not_move_after_a_change(monkeypatch):
    """THE BUG. A spoofer's address must not become the recorded one."""
    saves = []
    w = _w(gateway_ip="192.0.2.1")
    monkeypatch.setattr(w, "_save_gateway_mac",
                        lambda m: saves.append(m) or
                        setattr(w, "_gateway_mac", m))

    w.observe_arp(2, "192.0.2.1", "aa:bb:cc:dd:ee:01", now=0)     # learn
    w.observe_arp(2, "192.0.2.1", "de:ad:be:ef:00:01", now=10)    # spoof

    assert w.status()["gateway_mac"] == "aa:bb:cc:dd:ee:01"
    assert saves == ["aa:bb:cc:dd:ee:01"], "only the first learn may be saved"


def test_the_real_gateway_coming_back_is_not_a_finding(monkeypatch):
    """
    The other half of the same bug. With the baseline moved to the attacker,
    the genuine router answering again raised LAN-1002 about itself.
    """
    w = _w(gateway_ip="192.0.2.1")
    monkeypatch.setattr(w, "_save_gateway_mac",
                        lambda m: setattr(w, "_gateway_mac", m))

    w.observe_arp(2, "192.0.2.1", "aa:bb:cc:dd:ee:01", now=0)
    w.observe_arp(2, "192.0.2.1", "de:ad:be:ef:00:01", now=10)
    back = w.observe_arp(2, "192.0.2.1", "aa:bb:cc:dd:ee:01", now=20)

    assert not any(f["detection_id"] == "LAN-1002" for f in back)


def test_a_second_different_wrong_mac_does_raise(monkeypatch):
    """A spoofer cycling addresses is a new fact each time, not a repeat."""
    w = _w(gateway_ip="192.0.2.1")
    monkeypatch.setattr(w, "_save_gateway_mac",
                        lambda m: setattr(w, "_gateway_mac", m))

    w.observe_arp(2, "192.0.2.1", "aa:bb:cc:dd:ee:01", now=0)
    w.observe_arp(2, "192.0.2.1", "de:ad:be:ef:00:01", now=10)
    second = w.observe_arp(2, "192.0.2.1", "de:ad:be:ef:00:02", now=20)

    assert any(f["detection_id"] == "LAN-1002" for f in second)


def test_the_gateway_finding_says_the_baseline_stayed(monkeypatch):
    w = _w(gateway_ip="192.0.2.1")
    monkeypatch.setattr(w, "_save_gateway_mac",
                        lambda m: setattr(w, "_gateway_mac", m))

    w.observe_arp(2, "192.0.2.1", "aa:bb:cc:dd:ee:01", now=0)
    out = w.observe_arp(2, "192.0.2.1", "de:ad:be:ef:00:01", now=10)
    gw = [f for f in out if f["detection_id"] == "LAN-1002"][0]

    assert gw["raw_data"]["baseline_moved"] is False
    assert "HAS NOT BEEN CHANGED" in gw["description"]


def test_accepting_a_gateway_mac_is_the_only_way_it_moves(monkeypatch):
    w = _w(gateway_ip="192.0.2.1")
    monkeypatch.setattr(w, "_save_gateway_mac",
                        lambda m: setattr(w, "_gateway_mac", m))

    w.observe_arp(2, "192.0.2.1", "aa:bb:cc:dd:ee:01", now=0)
    res = w.accept_gateway_mac("de:ad:be:ef:00:01")

    assert res["accepted"] is True
    assert w.status()["gateway_mac"] == "de:ad:be:ef:00:01"
    assert w.observe_arp(2, "192.0.2.1", "de:ad:be:ef:00:01", now=20) == []


def test_accepting_junk_is_refused(monkeypatch):
    w = _w(gateway_ip="192.0.2.1")
    monkeypatch.setattr(w, "_save_gateway_mac", lambda m: None)
    assert w.accept_gateway_mac("not-a-mac")["accepted"] is False


def test_a_rogue_dhcp_server_is_not_added_to_the_known_set(monkeypatch):
    """THE BUG. Reporting it used to be the same act as trusting it."""
    w = _w()
    monkeypatch.setattr(w, "_save_dhcp_servers", lambda: None)

    w.observe_dhcp_server("192.0.2.1", "offer", now=0)
    out = w.observe_dhcp_server("192.0.2.18", "offer", now=10)

    assert out[0]["raw_data"]["recorded"] is False
    assert w.status()["dhcp_servers"] == ["192.0.2.1"]


def test_a_rogue_dhcp_server_raises_again_after_a_restart(monkeypatch):
    """
    The in-memory suppression is deliberate. A rogue still answering tomorrow
    is worth saying again, and persisting the suppression would be the old bug
    wearing a different hat.
    """
    monkeypatch.setattr(lw.LanWatch, "_save_dhcp_servers", lambda self: None)

    w1 = _w()
    w1.observe_dhcp_server("192.0.2.1", "offer", now=0)
    assert w1.observe_dhcp_server("192.0.2.18", "offer", now=10)

    w2 = _w()
    w2._dhcp_servers = {"192.0.2.1"}           # what persistence would restore
    assert w2.observe_dhcp_server("192.0.2.18", "offer", now=20)


def test_accepting_a_dhcp_server_silences_it(monkeypatch):
    w = _w()
    monkeypatch.setattr(w, "_save_dhcp_servers", lambda: None)
    w.observe_dhcp_server("192.0.2.1", "offer", now=0)
    w.observe_dhcp_server("192.0.2.18", "offer", now=10)

    assert w.accept_dhcp_server("192.0.2.18")["accepted"] is True
    assert w.observe_dhcp_server("192.0.2.18", "ack", now=20) == []


def test_a_first_dhcp_server_that_is_not_the_gateway_is_flagged(monkeypatch):
    """
    The first-run hole. If the app starts while a rogue is answering, that
    rogue becomes the baseline. The gateway is the one hint available.
    """
    w = _w(gateway_ip="192.0.2.1")
    monkeypatch.setattr(w, "_save_dhcp_servers", lambda: None)

    out = w.observe_dhcp_server("192.0.2.18", "offer", now=0)

    assert len(out) == 1
    assert out[0]["detection_id"] == "LAN-1003"
    assert out[0]["raw_data"]["is_first_seen"] is True
    assert w.status()["dhcp_servers"] == ["192.0.2.18"]


def test_a_first_dhcp_server_that_is_the_gateway_stays_silent(monkeypatch):
    w = _w(gateway_ip="192.0.2.1")
    monkeypatch.setattr(w, "_save_dhcp_servers", lambda: None)
    assert w.observe_dhcp_server("192.0.2.1", "offer", now=0) == []


# SECTION 13. The bounds that were missing. 2026-09-20.

def test_the_responder_table_is_bounded():
    """
    ARP had ARP_MAX_TRACKED and this had nothing, so spoofed source addresses
    grew it without limit inside the capture callback.
    """
    w = _w()
    for i in range(lw.NAME_MAX_RESPONDERS * 2):
        w.observe_name_response("LLMNR", f"10.1.{i // 256}.{i % 256}",
                                "wpad", now=i)
    assert len(w._name_answers) <= lw.NAME_MAX_RESPONDERS


def test_a_zero_mac_is_not_a_binding():
    """An ARP probe carries 00:00:00:00:00:00. Treating it as a binding
    invents a MAC change, and three invented changes is a flap finding."""
    assert lw._normalise_mac("00:00:00:00:00:00") == ""
    assert lw._normalise_mac("ff:ff:ff:ff:ff:ff") == ""


def test_a_zero_mac_does_not_produce_a_flap():
    w = _w()
    real = "aa:bb:cc:dd:ee:01"
    for i in range(10):
        w.observe_arp(2, "192.0.2.12", real, now=i * 2)
        out = w.observe_arp(1, "192.0.2.12", "00:00:00:00:00:00", now=i * 2 + 1)
        assert not any(f["detection_id"] == "LAN-1001" for f in out)


# RUN AS A SCRIPT, because that is how this project runs its tests.
#
# FOUND 2026-09-20, TODO 120, AND IT IS THE WORST KIND OF GREEN. Every other
# file in tests/ is a standalone script that prints its checks and exits 1 if
# any failed, and scripts/run_tests.py reads nothing but the exit code. This
# file is written for pytest, so running it as a script DEFINED A PILE OF
# FUNCTIONS, CALLED NONE OF THEM, AND EXITED 0. The whole file read as passing
# in the suite while asserting nothing at all.
#
# NO PYTEST IS A FAILURE HERE, NOT A SKIP. A skip would put this straight back
# where it was: a file that ran nothing, reported nothing wrong, and looked
# fine in the summary. One pip install is a much smaller price than a test
# file that quietly does nothing for weeks.
if __name__ == "__main__":
    import sys
    try:
        import pytest as _pytest
    except ImportError:
        print("FAILURE: pytest is not installed, so NONE of the checks in "
              "this file ran. This is reported as a failure and not a skip "
              "on purpose: a file that runs nothing must not read as green. "
              "Fix with: pip install pytest")
        sys.exit(1)
    sys.exit(_pytest.main([__file__, "-q"]))
