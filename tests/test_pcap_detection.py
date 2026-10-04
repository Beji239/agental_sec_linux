#!/usr/bin/env python3
"""
Detection tests for tools/pcap_analyzer.py.

Run:

    python tests/test_pcap_detection.py

Exit code 0 = every detection behaved. Also importable by pytest if pytest
is ever added; on its own it needs only scapy, which is already in
requirements.txt because the analyzer cannot work without it.


WHY THE CAPTURES ARE BUILT HERE RATHER THAN CHECKED IN

A .pcap fixture is an opaque binary. Six months from now nobody can tell
what is in it, whether it still matches what the test claims, or whether an
assertion drifted away from the file. Building each capture in code means
the traffic and the expectation sit next to each other and disagree loudly
if either changes.

It also keeps the repo honest. A checked-in capture from a real network is
somebody's real traffic, which is precisely what design rule 1 exists to
keep out of this tree. Every address below is RFC 5737 documentation space.


WHAT THIS IS FOR

Findings are what the whole tool produces, and until now nothing checked
that any of them fire. The value is not in the passing cases. It is in the
negative ones: NORMAL traffic that must NOT be reported. A detector that
flags everything passes every positive test ever written.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# TODO 108, 2026-09-14. This file was writing to the REAL database. Every
# analyse call registers an offline sensor, and there are nine of them here,
# so every run of this file added nine rows to `sensors` with fresh random
# ids. Nothing here is about sensors and nothing here mentions a database,
# which is why it went unnoticed. Repointed before anything runs.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate_db                                # noqa: E402
_isolate_db.isolate()

try:
    from scapy.all import IP, TCP, UDP, Raw, wrpcap
    SCAPY = True
except ImportError:
    SCAPY = False

# Documentation addresses, never anybody's real network.
VICTIM   = "192.0.2.10"
ATTACKER = "198.51.100.7"
SERVER   = "203.0.113.20"


# CAPTURE BUILDERS

def _write(packets, path: Path) -> str:
    wrpcap(str(path), packets)
    return str(path)


def capture_c2_beacon(path: Path, count: int = 10, interval: float = 30.0) -> str:
    """
    A textbook implant callback: same pair, same port, metronome timing.

    This is what beaconing means. Not "talked repeatedly", but "talked on a
    schedule", which is the part a human cannot fake by browsing.
    """
    packets = []
    for i in range(count):
        pkt = IP(src=VICTIM, dst=ATTACKER) / TCP(sport=50000 + i, dport=4444)
        pkt.time = 1000.0 + i * interval
        packets.append(pkt)
    return _write(packets, path)


def capture_normal_burst(path: Path) -> str:
    """
    An ordinary page load: many packets, close together, irregular gaps.

    THE MOST IMPORTANT CAPTURE IN THIS FILE. It is what a laptop does every
    few seconds all day. If this is reported as beaconing then beaconing
    means nothing, because the alert fires constantly and gets ignored on
    exactly the day it is real.
    """
    gaps = [0.02, 0.31, 0.05, 0.44, 0.02, 0.02, 1.20, 0.08, 0.03, 0.61,
            0.02, 0.05, 2.40, 0.02, 0.09, 0.33, 0.02, 0.02, 0.77, 0.14]
    packets = []
    now = 2000.0
    for i, gap in enumerate(gaps):
        now += gap
        pkt = IP(src=VICTIM, dst=SERVER) / TCP(sport=51000 + i, dport=443)
        pkt.time = now
        packets.append(pkt)
    return _write(packets, path)


def capture_slow_regular(path: Path) -> str:
    """
    Regular, but slower than the beacon window: a checkin every 10 minutes.

    Not reported, and that is a real limitation rather than an oversight, so
    it is asserted here. A
    patient implant beats an interval threshold by being patient.
    """
    packets = []
    for i in range(8):
        pkt = IP(src=VICTIM, dst=ATTACKER) / TCP(sport=52000 + i, dport=8080)
        pkt.time = 3000.0 + i * 600.0
        packets.append(pkt)
    return _write(packets, path)


def capture_short_regular(path: Path) -> str:
    """
    Perfectly regular, but only seven contacts: below BEACON_MIN_HITS.

    The other half of the threshold raised on 2026-08-22. Seven metronome
    callbacks are not NAMED a beacon, because six intervals is where a
    regularity score stops being a coincidence and this sits under it. They
    are still MEASURED: the pair must appear in repeated_contacts with a
    coefficient of variation of zero, so nothing is hidden, only unnamed.

    If this ever starts appearing in `beaconing`, the thresholds moved.
    """
    packets = []
    for i in range(7):
        pkt = IP(src=VICTIM, dst=ATTACKER) / TCP(sport=53000 + i, dport=4444)
        pkt.time = 5000.0 + i * 30.0
        packets.append(pkt)
    return _write(packets, path)


def capture_signature(path: Path, payload: bytes, dport: int = 80) -> str:
    pkt = IP(src=ATTACKER, dst=VICTIM) / TCP(sport=40000, dport=dport) / Raw(load=payload)
    pkt.time = 4000.0
    return _write([pkt], path)


def capture_volume(path: Path, count: int = 520) -> str:
    packets = []
    for i in range(count):
        pkt = IP(src=ATTACKER, dst=VICTIM) / UDP(sport=40000 + (i % 100), dport=53)
        pkt.time = 5000.0 + i * 0.01
        packets.append(pkt)
    return _write(packets, path)


def capture_non_ip(path: Path) -> str:
    """Frames the analyzer must skip without falling over."""
    from scapy.all import Ether, ARP
    packets = []
    for i in range(4):
        pkt = Ether() / ARP(pdst=VICTIM)
        pkt.time = 6000.0 + i
        packets.append(pkt)
    return _write(packets, path)


# HARNESS

def _analyzer():
    """
    A PcapAnalyzer whose database write is stubbed out.

    A test must never touch the real database. save_pcap_result is replaced
    rather than mocked at the module level so the rest of the analyzer runs
    exactly as it does in production.
    """
    from core import memory_engine as me
    me.save_pcap_result = lambda **kwargs: -1

    from tools.pcap_analyzer import PcapAnalyzer
    return PcapAnalyzer("test-session")


def _beacons_between(result: dict, src: str, dst: str) -> list[dict]:
    return [b for b in result.get("beaconing", [])
            if b["src"] == src and b["dst"] == dst]


def run() -> list[str]:
    """Every failure found, empty if the detectors all behaved."""
    if not SCAPY:
        return ["scapy is not installed, so no detection test could run. "
                "pip install -r requirements.txt"]

    failures: list[str] = []
    analyzer = _analyzer()
    tmp = Path(tempfile.mkdtemp())

    def check(name: str, condition: bool, detail: str = ""):
        if condition:
            print(f"   [pass] {name}")
        else:
            print(f"   [FAIL] {name}")
            failures.append(f"{name}: {detail}")

    print("\nPOSITIVE: things that must be reported\n")

    result = analyzer.analyze(capture_c2_beacon(tmp / "beacon.pcap"))
    beacons = _beacons_between(result, VICTIM, ATTACKER)
    check("a 30-second beacon is reported", bool(beacons),
          "regular callbacks to a known implant port produced no beaconing entry")
    if beacons:
        check("the beacon reports its interval",
              abs(beacons[0]["interval_avg_secs"] - 30.0) < 0.1,
              f"expected about 30s, got {beacons[0]['interval_avg_secs']}")
    check("port 4444 is flagged as dangerous",
          any(d["port"] == 4444 for d in result.get("dangerous_ports", [])),
          "4444 is in DANGEROUS_PORTS but was not reported")

    for label, payload, kind in [
        ("a NOP sled is caught",   b"A" * 10 + b"\x90\x90\x90\x90" + b"B" * 10, "metasploit"),
        ("SQL injection is caught", b"GET /?id=1 UNION SELECT pw FROM users", "sqli"),
        ("reflected script is caught", b"GET /?q=<script>alert(1)</script>", "xss"),
    ]:
        r = analyzer.analyze(capture_signature(tmp / f"sig_{kind}.pcap", payload))
        check(label, any(h["type"] == kind for h in r.get("signature_hits", [])),
              f"payload containing a {kind} signature produced no hit")

    r = analyzer.analyze(capture_volume(tmp / "volume.pcap"))
    check("a 520-packet flood raises a volume alert",
          any(v["ip"] == ATTACKER for v in r.get("volume_alerts", [])),
          "sender well past VOLUME_THRESHOLD was not reported")

    print("\nNEGATIVE: things that must NOT be reported\n")

    r = analyzer.analyze(capture_normal_burst(tmp / "normal.pcap"))
    burst_beacons = _beacons_between(r, VICTIM, SERVER)
    check("an ordinary page load is not called beaconing", not burst_beacons,
          f"20 irregular packets over ~7s were reported as beaconing: {burst_beacons}")
    check("an ordinary page load raises no signature hit",
          not r.get("signature_hits"),
          "clean traffic produced a signature hit")
    check("port 443 is not called dangerous",
          not any(d["port"] == 443 for d in r.get("dangerous_ports", [])),
          "HTTPS was flagged as a dangerous port")

    print("\nBOUNDARIES: known limits, asserted so they stay known\n")

    r = analyzer.analyze(capture_slow_regular(tmp / "slow.pcap"))
    check("a 10-minute beacon is missed, as documented",
          not _beacons_between(r, VICTIM, ATTACKER),
          "behaviour changed, this is now caught")

    r = analyzer.analyze(capture_short_regular(tmp / "short.pcap"))
    check("a seven-contact series is not named a beacon",
          not _beacons_between(r, VICTIM, ATTACKER),
          "below BEACON_MIN_HITS but reported as beaconing: thresholds moved")
    check("but it is still measured in repeated_contacts",
          any(c["src"] == VICTIM and c["dst"] == ATTACKER and c["hit_count"] == 7
              for c in r.get("repeated_contacts", [])),
          "raising BEACON_MIN_HITS also shrank the facts list, which it must not")

    r = analyzer.analyze(capture_non_ip(tmp / "arp.pcap"))
    check("non-IP frames do not crash the analyzer",
          "error" not in r and r.get("packet_count", 0) >= 0,
          f"analyzer errored on ARP-only traffic: {r.get('error')}")

    r = analyzer.analyze(str(tmp / "does_not_exist.pcap"))
    check("a missing file is an error, not an empty result",
          bool(r.get("error")),
          "a missing file returned something other than an error, which reads "
          "as a capture containing nothing")

    return failures


def test_pcap_detection():
    """Pytest entry point, if pytest is ever added."""
    failures = run()
    assert not failures, "\n".join(failures)


def main() -> int:
    print("PCAP DETECTION TESTS")
    failures = run()
    if not failures:
        print("\nAll detections behaved.")
        return 0
    print(f"\n{len(failures)} FAILURE(S):\n")
    for failure in failures:
        print(f"  {failure}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
