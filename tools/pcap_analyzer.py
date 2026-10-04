# tools/pcap_analyzer.py
# AgentalSec V2, PCAP file analyzer
# Python parses, extracts raw records. Model reasons on the result.

import logging
import time
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from scapy.all import rdpcap, IP, TCP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from core import memory_engine as me

# SIGNATURES

DANGEROUS_PORTS = {
    23, 445, 3389, 4444, 5900, 6667, 1433, 3306,
    5432, 27017, 6379, 9200, 2375, 5985, 5986,
}

METASPLOIT_SIGS = [b"\x90\x90\x90\x90", b"\xfc\xe8\x82", b"\x31\xc0\x50\x68"]
SQLI_SIGS       = [b"SELECT ", b"UNION ", b"DROP TABLE", b"OR 1=1"]
XSS_SIGS        = [b"<script>", b"javascript:", b"onerror="]

# HOW MANY CONTACTS BEFORE TIMING MEANS ANYTHING
#
# Raised from 5 to 8 on 2026-08-22. Five contacts is four intervals, and a
# coefficient of variation computed over four numbers is not a measurement
# of a rhythm; it is a coincidence with a decimal point. Four gaps landing
# close together is ordinary in bursty traffic, and every accidental hit
# spends credibility the alert needs on the day it is real. That is the same
# failure the CV test was added to fix, one order down.
#
# Eight contacts is seven intervals, which is enough that staying inside a
# quarter of the mean has to be deliberate. It stays below any real callback
# series worth calling a pattern, so nothing that was a beacon before stops
# being one, the 30-second case in tests/test_pcap_detection.py sends ten.
#
# The cost, stated rather than hidden: an implant that calls back seven
# times inside one capture and then stops is now measured but not named.
#
# That cost is only acceptable because raising the NAMING threshold does not
# raise the REPORTING one. REPEAT_MIN_HITS stays at 5, so the seven-contact
# series still appears in repeated_contacts with its raw timing and can be
# judged by something that reads numbers. Raising both would have made the
# stricter definition into a smaller facts list, which is the opposite of
# what this split exists for.
BEACON_MIN_HITS     = 8
REPEAT_MIN_HITS     = 5
BEACON_MAX_INTERVAL = 60
VOLUME_THRESHOLD    = 500

# REGULARITY, THE PART THAT MAKES A BEACON A BEACON
#
# Scope stated inline so a wrong value is checkable. This is the coefficient
# of variation: the standard deviation of the gaps divided by their mean. A
# metronome scores 0. Human-driven traffic scores near or above 1, because
# people pause, read and click at no particular rate.
#
# 0.25 means the gaps stay within roughly a quarter of their own average.
#
# Until 2026-08-19 there was no such test. stddev was computed on the line
# above and then never read, so the only conditions were "five or more
# packets" and "average gap under a minute". An ordinary page load meets
# both. Every browser tab was a beacon, which is worse than not looking:
# the alert fires constantly, gets ignored, and is still being ignored on
# the day it is real.
#
# Real implants jitter deliberately to defeat exactly this test, so a wide
# jitter window still slips through. That is a documented limit rather than
# a claim to catch everything, and loosening the threshold to chase it costs
# the negative case again.
BEACON_MAX_CV = 0.25


class PcapAnalyzer:

    def __init__(self, session_id: str):
        self.session_id  = session_id
        self._last_result = None

    def start(self):
        logger.info("PcapAnalyzer ready.")

    def status(self) -> dict:
        return {
            "ready":       SCAPY_AVAILABLE,
            "scapy":       SCAPY_AVAILABLE,
            "last_file":   self._last_result.get("file") if self._last_result else None,
        }

    # ANALYSIS

    # S18, 2026-08-28. THIS TOOK ANY PATH AND ANY PACKET COUNT.
    #
    # analyze() checked only that the file existed, then handed it to rdpcap.
    # Both the dashboard route and run_pcap_analysis reach it, and
    # run_pcap_analysis is a MODEL tool that is itself in UNTRUSTED_TOOLS,
    # so its argument can be influenced by text arriving inside a capture.
    # Three separate problems, none theoretical:
    #
    # 1. Any file on the machine could be named. rdpcap fails on most of
    #    them, but the failure MESSAGE differed between "File not found" and
    #    "Failed to read PCAP", which is an existence oracle over the user's
    #    disk, offered to the one component that can be argued with.
    # 2. max_packets came straight from params unbounded. rdpcap loads that
    #    many packets into memory before returning.
    # 3. No size check, so a multi-gigabyte file was memory exhaustion in one
    #    call, in the process that also runs the sensors and the dashboard.
    #
    # The suffix allowlist is the containment that does the most work for the
    # least cost. It is NOT a directory restriction, so the user can still
    # point this at a capture anywhere on their machine, which is the real
    # workflow. But nothing sensitive is named .pcap, so the
    # arbitrary-file-read shape disappears entirely.
    PCAP_SUFFIXES  = {".pcap", ".pcapng", ".cap"}
    MAX_PCAP_BYTES = 512 * 1024 * 1024
    MAX_PACKET_CAP = 200_000

    # WHY AN IMPORT NEEDS A VANTAGE POINT, 24.2, 2026-08-31.
    #
    # Everything below this line measures a file that this machine did not
    # capture. core/sensors.py already says the rule: the scope of an imported
    # file is unknown to this tool unless a human records it, so absence in a
    # capture supports no conclusion by itself.
    #
    # Until today nothing acted on that. pcap_results.sensor_id existed and
    # was never filled, so an imported capture landed with no position at all,
    # and the model read its findings with nothing to tell it these were not
    # observations of this network.
    #
    # So every analysis now registers an 'offline' sensor and stamps the row.
    # The operator's description of where the capture came from rides along in
    # notes as a CLAIM, and never becomes the position. See
    # sensors.register_offline for why that separation is the whole safety
    # property.

    def _capture_key(self, path: Path, size: int) -> str:
        """
        Identifies one capture without hashing half a gigabyte.

        Name, size and modification time. Two different files would have to
        agree on all three to collide, and the cost of a collision here is one
        shared sensor row rather than anything unsafe. Content hashing a
        512 MB file on every analysis is not worth that.
        """
        try:
            mtime = int(path.stat().st_mtime)
        except OSError:
            mtime = 0
        return f"{path.name}:{size}:{mtime}"

    def analyze(self, file_path: str, max_packets: int = 10000,
                origin: str = None) -> dict:
        # ARGUMENT VALIDATION RUNS BEFORE THE SCAPY CHECK, on purpose.
        #
        # It was written the other way round first and the test caught it: on
        # a machine without scapy every guard below was skipped, so the
        # refusals only existed where the optional dependency happened to be
        # installed. A check that runs only when a library is present is a
        # check that can silently not run, which is the same shape as the
        # sensor failures this project keeps rules about.
        #
        # Whether the argument is acceptable is a question about the request.
        # Whether scapy is installed is a question about the machine. The
        # first does not depend on the second.
        try:
            max_packets = int(max_packets)
        except (TypeError, ValueError):
            return {"error": f"max_packets must be an integer, got {max_packets!r}"}
        if max_packets < 1:
            return {"error": f"max_packets must be at least 1, got {max_packets}"}
        capped = min(max_packets, self.MAX_PACKET_CAP)

        path = Path(file_path or "")

        # Refused BEFORE the existence check, deliberately. Answering "that
        # file does not exist" for an arbitrary path is the oracle described
        # above; refusing on the name alone tells the caller nothing about
        # what is on the disk.
        if path.suffix.lower() not in self.PCAP_SUFFIXES:
            return {"error": (
                f"Refusing to read {path.name or file_path!r}: this tool reads "
                f"packet captures, so the file must be named "
                f"{', '.join(sorted(self.PCAP_SUFFIXES))}. This is not a "
                f"statement about whether that file exists."
            )}

        if not path.exists():
            return {"error": f"File not found: {file_path}"}
        if not path.is_file():
            return {"error": f"Not a regular file: {file_path}"}

        try:
            size = path.stat().st_size
        except OSError as e:
            return {"error": f"Could not stat {file_path}: {e}"}
        if size > self.MAX_PCAP_BYTES:
            return {"error": (
                f"Capture is {size // (1024 * 1024)} MB, over the "
                f"{self.MAX_PCAP_BYTES // (1024 * 1024)} MB limit. rdpcap loads "
                f"into memory, and this process also runs the sensors and the "
                f"dashboard. Split the capture first."
            )}

        if not SCAPY_AVAILABLE:
            return {"error": "scapy not available"}

        logger.info(f"Analyzing PCAP: {path.name} ({size // 1024} KB, "
                    f"up to {capped} packets)")

        try:
            packets = rdpcap(str(path), count=capped)
        except Exception as e:
            return {"error": f"Failed to read PCAP: {e}"}

        total         = len(packets)
        protocols     = defaultdict(int)
        src_counts    = defaultdict(int)
        dst_counts    = defaultdict(int)
        port_hits     = defaultdict(int)
        timestamps    = []
        beacon_data   = defaultdict(lambda: defaultdict(list))
        sig_hits      = []
        dangerous     = []
        volume_alerts = []

        for pkt in packets:
            if not pkt.haslayer(IP):
                continue

            src = pkt[IP].src
            dst = pkt[IP].dst
            src_counts[src] += 1
            dst_counts[dst] += 1

            ts = float(pkt.time)
            timestamps.append(ts)

            if pkt.haslayer(TCP):
                protocols["TCP"] += 1
                dport = pkt[TCP].dport
                port_hits[dport] += 1
                beacon_data[src][dst].append(ts)
                if dport in DANGEROUS_PORTS:
                    dangerous.append({"src": src, "dst": dst, "port": dport, "proto": "TCP"})
            elif pkt.haslayer(UDP):
                protocols["UDP"] += 1
                dport = pkt[UDP].dport
                port_hits[dport] += 1
            else:
                protocols["OTHER"] += 1

            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                for sig in METASPLOIT_SIGS:
                    if sig in payload:
                        sig_hits.append({"type": "metasploit", "src": src, "dst": dst})
                        break
                for sig in SQLI_SIGS:
                    if sig in payload:
                        sig_hits.append({"type": "sqli", "src": src, "dst": dst})
                        break
                for sig in XSS_SIGS:
                    if sig in payload:
                        sig_hits.append({"type": "xss", "src": src, "dst": dst})
                        break

        # BEACONING DETECTION

        # Two lists, on purpose.
        #
        # repeated_contacts is the facts: every pair that talked enough times
        # to measure, with its raw timing, regular or not. beaconing is the
        # subset that is actually periodic.
        #
        # Splitting them keeps this module to collecting and measuring while
        # leaving the judgement visible and arguable. A model that disagrees
        # with the threshold can read the numbers and say so, instead of
        # having to trust a list it cannot see behind.
        beaconing = []
        repeated_contacts = []

        for src, dsts in beacon_data.items():
            for dst, times in dsts.items():
                # The facts floor, not the naming floor. Anything above this
                # gets measured and reported; only the stricter
                # BEACON_MIN_HITS below decides what gets CALLED a beacon.
                if len(times) < REPEAT_MIN_HITS:
                    continue
                times.sort()
                intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
                if not intervals:
                    continue

                avg_interval = sum(intervals) / len(intervals)
                stddev = (sum((x - avg_interval)**2 for x in intervals) / len(intervals)) ** 0.5
                # Guard the divide. Identical timestamps give a zero mean,
                # which is perfectly regular rather than undefined.
                cv = (stddev / avg_interval) if avg_interval > 0 else 0.0

                record = {
                    "src":               src,
                    "dst":               dst,
                    "hit_count":         len(times),
                    "interval_avg_secs": round(avg_interval, 2),
                    "interval_stddev":   round(stddev, 2),
                    "interval_cv":       round(cv, 3),
                }
                repeated_contacts.append(record)

                if (len(times) >= BEACON_MIN_HITS
                        and avg_interval <= BEACON_MAX_INTERVAL
                        and cv <= BEACON_MAX_CV):
                    beaconing.append({
                        **record,
                        "why": (f"{len(times)} contacts averaging "
                                f"{avg_interval:.1f}s apart with a variation of "
                                f"{cv:.2f}, which is regular enough to be "
                                f"machine-timed rather than human-driven."),
                    })

        # VOLUME ALERTS

        for ip, count in src_counts.items():
            if count >= VOLUME_THRESHOLD:
                volume_alerts.append({"ip": ip, "packet_count": count})

        duration = (max(timestamps) - min(timestamps)) if len(timestamps) >= 2 else 0

        top_src = sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_dst = sorted(dst_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_ports = sorted(port_hits.items(), key=lambda x: x[1], reverse=True)[:20]

        result = {
            "file":             str(path),
            "packet_count":     total,
            "duration_seconds": round(duration, 2),
            "protocols":        dict(protocols),
            "top_src_ips":      [{"ip": ip, "count": c} for ip, c in top_src],
            "top_dst_ips":      [{"ip": ip, "count": c} for ip, c in top_dst],
            "top_ports":        [{"port": p, "count": c} for p, c in top_ports],
            "dangerous_ports":  dangerous[:50],
            "beaconing":        beaconing,
            "repeated_contacts": sorted(repeated_contacts,
                                        key=lambda r: r["interval_cv"])[:50],
            "signature_hits":   sig_hits[:50],
            "volume_alerts":    volume_alerts,
        }

        # Register the vantage point BEFORE saving, so the row can never
        # exist without one. If this fails the analysis still returns, because
        # refusing to report findings over a bookkeeping error would be the
        # wrong trade, but the result says plainly that the scope is unknown.
        sensor_id = None
        try:
            from core import sensors as sn
            sensor_id = sn.register_offline(self._capture_key(path, size),
                                            origin=origin)
            scope = sn.describe("offline")
        except Exception as e:
            logger.warning(f"Could not register a sensor for this capture "
                           f"({e}); it will be stored without a vantage "
                           f"point.")
            scope = {"summary": "Unrecognised position.",
                     "can_see": "Unknown.",
                     "cannot_see": "Unknown. Treat every absence from this "
                                   "capture as uninformative."}

        # The scope travels WITH the findings, in the same dict, on purpose.
        # A model that has to make a second call to learn what a capture could
        # not see is a model that will sometimes not make it.
        result["sensor_id"] = sensor_id
        result["position"]  = "offline"
        result["can_see"]    = scope["can_see"]
        result["cannot_see"] = scope["cannot_see"]
        result["origin_claim"] = (
            origin.strip() if origin and origin.strip() else None)
        result["scope_note"] = (
            "This is an IMPORTED capture, not something this host observed. "
            "Where it was taken decides what is in it, and that was "
            + (f"described by the operator as: {result['origin_claim']}. That "
               f"is their account, not a measurement, and it does not change "
               f"what this tool can verify."
               if result["origin_claim"] else
               "NOT recorded. Nothing missing from this file supports any "
               "conclusion.")
        )

        self._last_result = result

        pcap_id = me.save_pcap_result(
            session_id=self.session_id,
            file_path=str(path),
            packet_count=total,
            duration_seconds=duration,
            result_json=result,
            sensor_id=sensor_id,
        )

        result["pcap_result_id"] = pcap_id
        logger.info(f"PCAP analysis complete: {total} packets, {len(sig_hits)} sig hits, {len(beaconing)} beacons")
        return result

    def get_last_result(self) -> dict | None:
        return self._last_result