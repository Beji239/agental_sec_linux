# tools/port_scanner.py
# AgentalSec V2, pure socket port scanner, no Nmap needed.
#
# IT RUNS A REAL RAW SYN SCAN NOW, 2026-09-25, and it is the fallback the
# connect scan never was. PS-13, option (c), on the owner's instruction:
# "do option C and when done report back". The privilege row for this module
# used to claim a SYN scan that did not exist in the tree; the row was
# corrected once (to "needs nothing") and that correction was itself false for
# the module as a whole, because a self-scan's OWNER LOOKUP loses every root
# process unelevated. So both halves exist now, and both are stated on the
# row: with a raw socket this pass sends SYNs and reads the answers; without
# one it falls back to the TCP connect scan and SAYS SO on the payload rather
# than describing different code than it runs (the original defect).
#
# THE TWO PASSES AND WHAT EACH CAN PROVE, which is the whole reason this
# module now carries two:
#
#   SYN       a raw socket. One SYN per port, no handshake completed. A
#             SYN-ACK means OPEN, an RST means CLOSED, silence means NEITHER
#             (filtered, rate-limited, or the answer was lost). Every SYN-ACK
#             is answered with an RST, so nothing is left half-open on the
#             target -- see the teardown note below.
#   connect   the fallback, socket.create_connection. True means a handshake
#             was completed; False covers refused, filtered, timed out and
#             "wrong protocol", all at once. It cannot tell CLOSED from
#             FILTERED, which is exactly the distinction the SYN pass buys.
#
# NEITHER PASS IS ALLOWED TO LIE ABOUT WHICH ONE RAN. The payload carries
# `tcp_method` and `tcp_method_reason`; the scope sentence names the method;
# and a run whose raw socket was refused says so there rather than implying
# the scan was the same thing it is when elevated.

#
# IT SENDS UDP NOW, 2026-09-17. TODO 117.
#
# The owner's words on 2026-09-17: ports doesn't have UDP port finder
# (sock.SOCK_DGRAM) and in that decree I am sure many other important ports
# are also left unchecked. Both halves were right. This file now runs a second
# pass with real UDP datagrams, and the section below is the old TCP-only
# write-up kept because the reasoning still governs every result row.
#
# WHAT A UDP RESULT CAN AND CANNOT SAY, and this is the whole design:
#
#   a reply came back          OPEN. Something is listening and it answered.
#   ICMP port unreachable      CLOSED. The host said nothing is there.
#   silence                    NEITHER. Open and quiet, or filtered, or the
#                              probe was not the payload that service wanted.
#
# The third case is most of UDP and it is reported as its own list with its
# own sentence. Calling silence "closed" would be the exact bug this project
# keeps fixing: a sensor that could not tell, saying it could.
#
# THE PROBES ARE REAL PAYLOADS, not empty datagrams. An empty packet to UDP 53
# gets nothing back from a working resolver, so an empty-datagram scanner
# reports every UDP service on the network as silent and is worse than not
# scanning, because it produces a page full of confident nothing. Each port
# in UDP_PROBES carries the smallest well-formed request that service answers.
#
# THE OLD HEADER, 2026-09-15, still true of the TCP pass:
#
# _check_port is a TCP connect, socket.create_connection, and it was the only
# probe in this file until today.
#
# That was true from the first commit and was written down nowhere. The result
# rows said "port 500 open", the Ports tab said "500", the model was handed
# "500", and every one of those reads as a statement about the port rather than
# about TCP. The owner read the tool as covering UDP as well, which is a fair
# reading of what it printed, and it was wrong.
#
# Two changes come out of that, and they are the whole of what this file does
# differently now:
#
#   1. Every result carries protocol='tcp', in the database, in the returned
#      dict and in the scope sentence. Nothing leaves here as a bare number.
#   2. Ports whose service is a UDP service are named in udp_not_tested when
#      they do not answer on TCP. They are still probed, so no coverage is
#      lost, but a silent port on 500 or 5353 can no longer be read as "not
#      there". It means "TCP said no, and nothing asked UDP".
#
# Rule two of this project, in its original words: "no match" and "I could not
# search" must stay different sentences. A TCP connect to a UDP service is the
# second sentence wearing the first one's clothes.

import errno
import ipaddress
import logging
import random
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

from core import memory_engine as me

# PORT PROFILES
#
# The old model was two sets, HIGH_RISK_PORTS and MED_RISK_PORTS, mapping
# a port number straight to critical/high/low. That made 445 'critical' on
# every Windows machine ever scanned, which is the default configuration of
# the operating system and not a finding. Meanwhile SSH on 22 and Redis on
# 6379 came out at the same level, despite one being the correct way to
# administer a box and the other historically shipping with no password.
#
# A port number does not carry risk. Three things do, and each is separated
# below:
#
#   notable  , is this worth a human's attention at all?
#   lan      , how bad it is when reachable from another host on the LAN
#   wan      , how bad it is when reachable from the internet
#
# The split between lan and wan is the important one. SMB on a home LAN is
# file sharing; SMB reachable from the internet is how networks get owned.
# Same port, two different findings, and the scanner can tell them apart by
# looking at the address it scanned.
#
# `note` is written for a human reading the Ports tab, and is what the model
# receives instead of a bare severity word.

PORT_PROFILES = {
    # Remote administration, expected on servers, worth confirming on a desktop
    22:    ("SSH",           "admin",     "low",    "high",     "Encrypted remote admin. Normal on servers; confirm key-only auth if internet-facing."),
    3389:  ("RDP",           "admin",     "medium", "critical", "Remote desktop. Should never be internet-facing without a VPN."),
    5900:  ("VNC",           "admin",     "medium", "critical", "Remote desktop. A listening port says nothing about whether auth is set."),
    5901:  ("VNC-1",         "admin",     "medium", "critical", "Second VNC display. Same caveats as 5900."),
    5985:  ("WinRM",         "admin",     "medium", "critical", "Windows Remote Management over HTTP. Normal in domains, not on the internet."),
    5986:  ("WinRM-HTTPS",   "admin",     "low",    "high",     "WinRM over TLS. Expected in managed Windows environments."),

    # Windows file sharing, the default state of a Windows host
    445:   ("SMB",           "filesharing","low",   "critical", "Windows file and printer sharing. Open by default on Windows; normal on a LAN, serious if internet-facing."),
    139:   ("NetBIOS",       "filesharing","low",   "critical", "Legacy NetBIOS session service. Ships with Windows file sharing."),
    135:   ("MSRPC",         "filesharing","low",   "critical", "Windows RPC endpoint mapper. Core OS plumbing; blocking it locally breaks DCOM."),

    # Plaintext credentials, a protocol-level defect, true on any host
    23:    ("Telnet",        "plaintext", "high",   "critical", "Credentials sent in the clear. No version of this is safe. Common on IoT and network gear."),
    21:    ("FTP",           "plaintext", "medium", "high",     "Credentials in the clear unless FTPS. Prefer SFTP."),
    110:   ("POP3",          "plaintext", "low",    "medium",   "Plaintext mail retrieval unless wrapped in TLS."),
    143:   ("IMAP",          "plaintext", "low",    "medium",   "Plaintext mail access unless wrapped in TLS."),

    # Data stores, several historically shipped with no authentication
    6379:  ("Redis",         "database",  "high",   "critical", "Historically no auth by default. An open Redis is often a full compromise."),
    11211: ("Memcached",     "database",  "high",   "critical", "No authentication by design. Also a large UDP amplification vector."),
    27017: ("MongoDB",       "database",  "high",   "critical", "Older builds bound to all interfaces with no auth."),
    9200:  ("Elasticsearch", "database",  "high",   "critical", "No auth in older builds. Frequently exposes everything indexed."),
    1433:  ("MSSQL",         "database",  "medium", "critical", "Database. Should not be reachable beyond its application tier."),
    3306:  ("MySQL",         "database",  "medium", "critical", "Database. Should not be reachable beyond its application tier."),
    5432:  ("PostgreSQL",    "database",  "medium", "critical", "Database. Should not be reachable beyond its application tier."),
    1521:  ("Oracle",        "database",  "medium", "critical", "Database. Should not be reachable beyond its application tier."),
    2181:  ("Zookeeper",     "database",  "medium", "high",     "Coordination service, typically unauthenticated."),
    50070: ("Hadoop",        "database",  "medium", "high",     "Hadoop NameNode UI, historically unauthenticated."),

    # Remote code execution surfaces
    2375:  ("Docker",        "rce",       "high",   "critical", "Unauthenticated Docker API. Equivalent to root on the host."),
    2376:  ("Docker-TLS",    "rce",       "medium", "high",     "Docker API with TLS. Verify client certs are actually required."),
    8888:  ("Jupyter",       "rce",       "high",   "critical", "Notebook server. Arbitrary code execution if no token is set."),

    # Convention, not vulnerability. Direction and behaviour matter more.
    #
    # LOWERED FROM medium TO low ON 2026-08-19, AFTER AUDIT.
    #
    # Both sat at medium, which is the threshold that raises a finding, and
    # both earned it by association with a tool rather than by any defect in
    # the service. That is the STATIC-001 pattern exactly: a severity that
    # describes what attackers like, rather than what is wrong here.
    #
    # Underneath it is a direction error. A reverse shell and a botnet client
    # both CONNECT OUT. A port scan sees LISTENERS. The genuinely alarming
    # case on these ports is traffic this sensor never looks at, so alerting
    # on the listener trained attention onto the wrong evidence while the
    # interesting case went unmentioned.
    #
    # low keeps them on the Ports tab with the note intact and stops them
    # manufacturing findings. Nothing is hidden. The note carries everything
    # the severity used to imply and says where to look instead.
    4444:  ("Port-4444",     "convention","low",    "medium",   "Metasploit's default reverse-shell port, and also an ordinary high port used by legitimate software. A LISTENER here is weak evidence on its own. The alarming case is an OUTBOUND connection to 4444, which a port scan cannot see: check process_monitor and the packet record instead. Identify the owning process before drawing any conclusion."),
    6667:  ("IRC",           "convention","low",    "medium",   "Classic botnet C2 channel, and also just IRC. A listener means something here is running an IRC SERVER, which is unusual but not an attack. A bot CONNECTS OUT to 6667, and that is the case worth chasing; it shows up in packet data, not in a port scan. Identify the process."),

    # Ordinary services
    80:    ("HTTP",          "web",       "low",    "low",      "Unencrypted web. Fine for a LAN device UI; prefer TLS."),
    443:   ("HTTPS",         "web",       "low",    "low",      "Encrypted web. Expected almost everywhere."),
    8080:  ("HTTP-Alt",      "web",       "low",    "medium",   "Alternate HTTP. Often an admin UI or dev server."),
    8443:  ("HTTPS-Alt",     "web",       "low",    "low",      "Alternate HTTPS. Common on appliances and smart TVs."),
    53:    ("DNS",           "infra",     "low",    "medium",   "DNS. An open resolver on the internet is an amplification risk."),
    25:    ("SMTP",          "infra",     "low",    "medium",   "Mail transfer. Verify it is not an open relay if internet-facing."),
    993:   ("IMAPS",         "infra",     "low",    "low",      "IMAP over TLS."),
    995:   ("POP3S",         "infra",     "low",    "low",      "POP3 over TLS."),
    500:   ("IKE",           "infra",     "low",    "low",      "IPSec key exchange. Expected on VPN endpoints."),
    4500:  ("IPSec-NAT-T",   "infra",     "low",    "low",      "IPSec NAT traversal. Expected on VPN endpoints."),
    9090:  ("Prometheus",    "infra",     "low",    "medium",   "Metrics server. Usually unauthenticated and can leak topology."),
    9100:  ("NodeExporter",  "infra",     "low",    "medium",   "Host metrics. Usually unauthenticated and can leak topology."),
}

# COMMON_PORTS WAS HERE AND WAS DELETED, 2026-09-25 (register PS-11). It was
# `{port: profile[0] for port, profile in PORT_PROFILES.items()}` and a grep
# across both trees returned that one line and nothing else: zero consumers in
# either tree, the vestige of the days when the scan list and the annotation
# table were the same object. `_port_set()` is the scan list now and
# PORT_PROFILES is the annotation table, so nothing was importing it. The
# Windows twin still carries the line; this tree does not.

# WHAT GETS SCANNED
#
# The scan loop used to iterate PORT_PROFILES directly, which quietly made the
# scan list identical to the annotation table. The scanner could only look at
# ports somebody had already written a description for.
#
# That is backwards. Finding a service and knowing what it is are separate
# jobs, and classify_port has always handled an unprofiled port fine: it
# returns "not in the profile table, identify the listening service", which is
# a true and useful thing to say. Coupling them meant a games console was
# unscannable because nobody had written a paragraph about port 9295.
#
# So the two are separated. PORT_PROFILES stays curated and stays small.
# The scan range is a choice, made here, with its cost stated.

# Consumer and device ports. Added as IDENTIFICATION AIDS, not risk findings.
# Every one is 'low' on the LAN because a console answering on a console port
# is a console working correctly. They earn their place by telling you what a
# device IS, which is the thing the inventory actually needs.
CONSUMER_PORTS = {
    987:   ("PS-RemotePlay",  "console", "low", "low", "PlayStation Remote Play and discovery. Expected on a console."),
    1900:  ("SSDP",           "discovery","low","medium","UPnP discovery. Normal on a LAN; an internet-facing 1900 is a reflection source."),
    5353:  ("mDNS",           "discovery","low","low",  "Bonjour and multicast DNS. How Apple and Cast devices announce themselves."),
    8008:  ("Cast-HTTP",      "media",   "low", "medium","Google Cast setup endpoint. Unauthenticated by design; answers /setup/eureka_info."),
    8009:  ("Cast-TLS",       "media",   "low", "medium","Google Cast control channel over TLS. Present on Chromecast and on TVs with Cast built in."),
    8060:  ("Roku-ECP",       "media",   "low", "medium","Roku external control. Unauthenticated on the LAN by design."),
    9295:  ("PS-RP-Control",  "console", "low", "low",  "PlayStation Remote Play control channel."),
    9296:  ("PS-RP-Data",     "console", "low", "low",  "PlayStation Remote Play data channel."),
    9297:  ("PS-RP-Stream",   "console", "low", "low",  "PlayStation Remote Play video stream."),
    9302:  ("PS-Discovery",   "console", "low", "low",  "PlayStation discovery broadcast."),
    631:   ("IPP",            "printer", "low", "medium","Internet Printing Protocol. Normal for a printer; do not expose it."),
    5000:  ("UPnP-HTTP",      "discovery","low","medium","UPnP or a dev server. Identify the process before judging."),
    32400: ("Plex",           "media",   "low", "high", "Plex media server. Fine on a LAN; internet-facing means your library is published."),
    3074:  ("Xbox-Live",      "console", "low", "low",  "Xbox Live services. Expected on an Xbox."),
    1935:  ("RTMP",           "media",   "low", "medium","Streaming. Used by consoles and broadcast software."),
}

for _port, _profile in CONSUMER_PORTS.items():
    PORT_PROFILES.setdefault(_port, _profile)


# PORTS WHERE A TCP SILENCE PROVES NOTHING
#
# Some of the services in the table above do not speak TCP at all. IKE, SSDP
# and mDNS are UDP services. A TCP connect to them will fail on a host that is
# running them perfectly, every time, and the scan then reports the same thing
# it reports for a port nothing is listening on.
#
# That is the failure this project keeps a rule about, so these ports are named
# rather than silently dropped.
#
# THEY ARE STILL SCANNED. Removing them would lose the odd device that really
# does answer on TCP there, and the cost of probing a port we already have in
# the list is nothing. What changes is only what a NEGATIVE result is allowed
# to say: for these ports it says "not tested", not "closed".
#
#   udp_only  the service is a UDP service. A TCP connect is not the test.
#   udp_also  the service commonly runs on both. TCP silence is a real TCP
#             answer, and still says nothing about UDP.
#
# The list is deliberately short and only covers ports in the profile table. A
# scan over 'extended' or 'all' sweeps thousands of ports that carry UDP
# services nobody here has profiled, and the scope sentence says so rather than
# this dict pretending to be complete.
UDP_PORT_FACTS = {
    500:   ("udp_only", "IKE is a UDP service. It does not listen on TCP 500, so a TCP result here is not the test that settles it."),
    4500:  ("udp_only", "IPSec NAT traversal is a UDP service. TCP 4500 is not where it lives."),
    1900:  ("udp_only", "SSDP is UDP. UPnP control lives on other TCP ports, but discovery on 1900 is UDP only."),
    5353:  ("udp_only", "mDNS is UDP. Apple and Cast devices announce over UDP 5353 and nothing listens on TCP there."),
    987:   ("udp_only", "PlayStation Remote Play registration is documented as UDP."),
    9296:  ("udp_only", "PlayStation Remote Play data channel is documented as UDP."),
    9297:  ("udp_only", "PlayStation Remote Play stream is documented as UDP."),
    9302:  ("udp_only", "PlayStation discovery broadcasts over UDP."),
    53:    ("udp_also", "DNS answers on both. Most resolvers take UDP queries and only fall back to TCP for large answers, so a quiet TCP 53 is common on a working resolver."),
    3074:  ("udp_also", "Xbox Live uses both TCP and UDP 3074."),
    631:   ("udp_also", "IPP serves over TCP, and printer discovery also uses UDP 631."),
    11211: ("udp_also", "Memcached listens on both, and the amplification abuse everyone worries about is the UDP side."),
}


def udp_caveat(port: int) -> tuple:
    """
    ('udp_only' | 'udp_also' | None, reason). None means nothing here has a
    reason to doubt what a TCP result says about this port.
    """
    kind, reason = UDP_PORT_FACTS.get(port, (None, ""))
    return kind, reason

# The three choices, with their real cost at MAX_WORKERS and SCAN_TIMEOUT.
#
#   common   the profiled set. Fast, and blind to anything nobody profiled.
#   extended every well-known port 1-1024 plus everything profiled. About six
#            seconds a host, and catches the overwhelming majority of real
#            listeners without pretending to be exhaustive.
#   all      1-65535. Roughly five and a half minutes PER HOST, so about an
#            hour for a thirteen-device network. It is also loud: it looks
#            like an attack, some IoT devices fall over under it, and this
#            tool's own sniffer will see the traffic it generates.
def _port_set(name: str) -> list[int]:
    name = (name or "common").strip().lower()
    if name == "all":
        return list(range(1, 65536))
    if name == "extended":
        return sorted(set(range(1, 1025)) | set(PORT_PROFILES))
    return sorted(PORT_PROFILES)


PORT_SET_NAMES = ("common", "extended", "all")

SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]

# THE SWITCH AND THE CLOCK KEY, READ FROM THE OPERATOR'S CONFIG
#
# `sensors.port_scanner.enabled` and `poll_interval` were documented in
# config.json and read by NOTHING until 2026-09-25 (register PS-14). This
# sensor is built directly in main.py, so there was no loop for either key to
# gate -- the same shape the autoruns round closed as AR-12.
#
# TWO DESIGNS WERE ON THE TABLE and the register carried the choice as PENDING
# THE OWNER'S WORD, because finishing the section is not an answer to the question
# inside it:
#
#   (a) give this module a real clock, so the key gates a loop and the sensor
#       measures the owner's own machine on a schedule nobody has to ask for;
#   (b) keep it pull-only and make the switch REFUSE the call.
#
# (b) was built first as the reversible direction; (a) was NOT, and was
# recorded as untouched work. **THE OWNER ANSWERED IN THE OWNER'S OWN WORDS, 2026-09-25:
# "I want you to create that back ground clock". OPTION (a) IS WHAT THIS FILE
# CARRIES NOW** -- see THE CLOCK below. It is not a reversal of (b): the switch
# still REFUSES, and OFF still stops both the clock and the call, which is what
# a switch in a sensor's own config block has to mean.
#
# AN ABSENT KEY MEANS ON. All three shapes are ON: an empty block, a block
# without the key, and no sensors block at all. Spelled out rather than
# defaulted inline, because a config written before this change must keep its
# scanner, and that is what every other sensor in this tree does.

def scan_enabled(config: dict) -> tuple[bool, str]:
    """
    (enabled, which key said so) for the port scanner's own switch.

    The winner's NAME is returned so status() can publish which key is in
    charge rather than leaving an operator to work it out. There is one key
    here, so "no key is set" is the ON answer's name.
    """
    block = ((config or {}).get("sensors", {}) or {}).get("port_scanner", {}) or {}
    if "enabled" in block:
        return bool(block.get("enabled")), "sensors.port_scanner.enabled"
    return True, "no key is set, so it is ON"


# THE CLOCK -- OPTION (a), THE OWNER'S ANSWER, 2026-09-25
#
# THE OWNER'S WORDS, and they are why this section exists: **"I want you to
# create that back ground clock"**. PS-14 offered two designs -- (a) a real
# clock on this module, (b) pull-only with the switch refusing -- and the
# register carried the choice as PENDING THE OWNER'S WORD because finishing the
# section is not an answer to the question inside it. (b) was built first as
# the reversible direction; (a) was NOT, and was recorded as untouched work.
# The owner has now answered, so the clock is here. The switch and the refusal both
# STAY: OFF stops the clock AND the call, which is what a switch in a
# sensor's own config block has to mean.
#
# WHAT THE CLOCK DOES, and there is exactly one answer: every
# `sensors.port_scanner.poll_interval` seconds it runs THE SAME scan() every
# other caller uses, against SELF_SCAN_TARGET (127.0.0.1), session-scoped to
# the boot that is running. It is not a second scanner and not a shortcut:
# the payload, the owner lookup, the finding policy and the run record are
# the shipped ones, because a clock that scanned "more cheaply" would be a
# second implementation of the same question.
#
# WHY 127.0.0.1 AND NOT "the machine's addresses". A scan measures what
# ANSWERS ON THE ONE ADDRESS IT WAS GIVEN, which is the measurement section
# 10's own audit wrote down (a scan of loopback finds 631; a scan of the LAN
# address finds a different set). Loopback is the address that reaches the
# MOST of this host's own listeners -- measured on this host, the kernel's
# listener table holds 53 (two sockets), 631 and 5353 on addresses loopback
# reaches, while 5000 answers only because this app binds it there -- and it
# is the only address that is THIS MACHINE on every host without asking the
# resolver. The row that lands in the store says origin=self and carries the
# bound-not-reachable note, so nothing it records can be read as exposure.
#
# THE CLOCK IS WALL-CLOCK, NOT UPTIME. The due test reads WHEN THE LAST
# SELF-SCAN WAS RECORDED out of the run table -- not a counter this process
# owns -- so a restart inside the window does not double-scan and a pass due
# while the machine was asleep fires on the next start instead of drifting
# one reboot further behind. Same rule and same reader shape as
# tools/port_owner.sweep_due, which is where this project paid for it.
#
# A FLOOR IN CODE. A config cannot ask for a permanently busy scanner; the
# measured cost of one pass is in the comment on MIN_CLOCK_SECONDS.
#
# THE INTERVAL KEY IS THE ONE THAT HAD NO READER. `poll_interval` was
# documented in the operator's own block and read by nothing (PS-14). It is
# read HERE now, and its winner's NAME travels so the status card and the
# boot log can say which key is in charge rather than leaving an operator to
# work it out.

# MEASURED ON THIS HOST, 2026-09-25, before the floor was chosen: one pass
# of scan("127.0.0.1", port_set="common") is 55 TCP probes + 25 UDP probes
# and took 0.54 s wall (0.32 s on the warm second pass), writing 3 rows in
# port_scan_results and 1 row in port_scan_run. At the floor of 60 s that is
# under 1% of a core; at the owner's own 600 s it is under 0.1%. The floor
# exists for the config that asks for 5.
MIN_CLOCK_SECONDS = 60

# What the clock runs on when the key is absent or unreadable. 600 is the
# value the operator's own config.json already carries, so an absent key and
# the owner's file land in the same place.
DEFAULT_CLOCK_SECONDS = 600

# The address the clock measures. See the block above for why it is this
# one; it is a constant rather than a config key because a second key here
# would be a second thing to explain, and the vantage question it settles is
# answered by the origin=self note on every row.
SELF_SCAN_TARGET = "127.0.0.1"

# How often the loop WAKES to ask whether a pass is due, when the interval is
# longer than this. It is not the cadence -- the cadence is the operator's
# key -- it is the resolution of the due check, so a restart does not push a
# due pass a whole interval away. A wake-up that decides not to scan costs
# one SQL read.
CLOCK_WAKE_SECONDS = 60


def clock_interval_seconds(config: dict) -> tuple:
    """
    (seconds, which key answered / why the default did) for the clock.

    One reader, one order, so the value that is USED is always the value that
    was READ: sensors.port_scanner.poll_interval first (the block every other
    sensor uses, and the key the operator's own config.json already carries),
    then the default. The winner's NAME is returned so status() can publish
    which key is in charge.

    AN UNREADABLE VALUE IS REPORTED AND DEFAULTED, never swallowed: a clock
    nobody can read is not a clock, and the operator who typed "600s" instead
    of 600 needs to see that the string did not take. Same reading as
    tcp_method_setting above and as port_owner.sweep_interval_seconds.
    """
    block = ((config or {}).get("sensors", {}) or {}).get("port_scanner", {}) or {}
    if "poll_interval" not in block:
        return (DEFAULT_CLOCK_SECONDS,
                "the built-in default, because sensors.port_scanner."
                "poll_interval is not set")
    value = block["poll_interval"]
    try:
        secs = int(value)
    except (TypeError, ValueError):
        logger.warning(
            f"port_scanner: sensors.port_scanner.poll_interval is {value!r}, "
            f"which is not a number of seconds. Using the default "
            f"({DEFAULT_CLOCK_SECONDS}s) and SAYING SO, because a clock "
            f"nobody can read is not a clock.")
        return (DEFAULT_CLOCK_SECONDS,
                "default (unreadable sensors.port_scanner.poll_interval)")
    if secs < MIN_CLOCK_SECONDS:
        logger.warning(
            f"port_scanner: sensors.port_scanner.poll_interval is {secs}s, "
            f"below the floor of {MIN_CLOCK_SECONDS}s. Using the floor; it "
            f"exists so a config cannot ask for a permanently busy scanner.")
        return (MIN_CLOCK_SECONDS,
                "sensors.port_scanner.poll_interval (raised to the floor)")
    return secs, "sensors.port_scanner.poll_interval"


def last_self_scan_at(target_host: str = SELF_SCAN_TARGET):
    """
    When this app last recorded a self-scan of `target_host`, as epoch
    seconds -- or None, which means LOOK NOW.

    READ FROM THE RUN RECORD, not from a counter this process owns: a scan
    asked for by the model or by the Scan Host button stamps the same row, so
    the clock defers to a measurement somebody else just took rather than
    duplicating it a minute later. `scan_origin = 'self'` because the clock's
    question is when this HOST was last measured from itself; a remote scan
    is a different measurement.

    THE CONVERSION IS SQLITE'S OWN strftime, so the store's UTC shape is read
    the way it was written -- the naive-string trap core/intervals documents
    does not get a chance to apply. A row whose timestamp cannot be read
    yields NULL, which lands here as None, which means DUE: "I could not tell
    when I last looked" is a reason to look now, never a reason to wait. Same
    rule as port_owner.sweep_due.
    """
    try:
        from core import memory_engine as me
        with me._get_readonly_conn() as conn:
            row = conn.execute(
                "SELECT MAX(strftime('%s', started_at)) FROM port_scan_run "
                "WHERE target_host = ? AND scan_origin = 'self'",
                (target_host,)).fetchone()
    except Exception as e:                                   # noqa: BLE001
        logger.warning(f"port_scanner clock: could not read the last "
                       f"self-scan from the run record ({e}), so the due "
                       f"check will treat this as due and look now.")
        return None
    value = row[0] if row else None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def clock_due(last_at, interval_seconds: int, now: float = None) -> tuple:
    """
    (due: bool, waited_seconds: float | None). The clock's arithmetic, in ONE
    place so the loop, the status card and the tests cannot disagree.

    A RECORD THAT IS NOT THERE IS DUE -- first boot of an install, or the
    store was pruned -- and that first pass is a SEED: it records the state
    and raises nothing (scans raise no findings at all, TODO 38.5), so a
    machine nobody has looked at does not get a page of news about listeners
    that predate the app.

    The interval is floored HERE as well as at the reader, because a caller
    that hands this function a raw number is the same caller that would hand
    the loop a raw number.
    """
    if last_at is None:
        return True, None
    now = time.time() if now is None else now
    waited = now - float(last_at)
    return waited >= max(MIN_CLOCK_SECONDS, int(interval_seconds)), waited


# The clock's own state, module-level for the same reason port_owner's is:
# ONE answer to "is this module measuring right now", read by status(), by
# the readiness page and by the boot log, instead of three surfaces keeping
# three copies. `ticks` is THIS RUN's count and is named so it cannot be read
# as the database's own number of scans.
_clock_state = {
    "running": False,
    "interval": DEFAULT_CLOCK_SECONDS,
    "interval_key": "not started",
    "ticks": 0,
    "last_at": None,
    "last_error": None,
    "consecutive_failures": 0,
}


def clock_state() -> dict:
    """A copy of the clock's state, so a reader cannot mutate the original."""
    return dict(_clock_state)


def set_clock_running(running: bool, interval: int = None,
                      interval_key: str = None) -> None:
    """
    Called by main.py when it arms the clock, and by nothing else.

    The clock does not arm itself: a module that starts its own thread on
    import would scan the operator's machine the first time anything
    imported it, including a test run. Arming is the boot's decision and it
    is visible in the boot log, which is where a reader looks to find out
    whether this is running.
    """
    _clock_state["running"] = bool(running)
    if interval is not None:
        _clock_state["interval"] = int(interval)
    if interval_key is not None:
        _clock_state["interval_key"] = str(interval_key)


def _now() -> str:
    """UTC, the shape the store writes. Same reader helper port_owner uses."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# WHICH TCP METHOD THIS MODULE IS ALLOWED TO USE
#
# PS-13 option (c). The module now has two TCP probes and the operator gets to
# say which one is acceptable on THE OWNER'S network, because the two are not the same
# thing:
#
#   "auto"     (default, and the absent key) SYN where a raw socket opens,
#              the connect test where it does not. Nothing changes for a
#              config written before this key existed.
#   "syn"      SYN ONLY. If no raw socket can be opened the TCP pass REFUSES
#              BY NAME rather than quietly scanning a different way. This is
#              the setting for an operator who wants the payload to be
#              uniform, or whose network would rather see SYNs than
#              handshakes.
#   "connect"  THE CONNECT TEST ONLY, even when a raw socket is available.
#              For a host where raw TCP traffic from this process is unwelcome
#              or where something upstream inspects handshakes and would
#              rather see complete ones.
#
# AN UNREADABLE VALUE IS REFUSED, NOT DEFAULTED SILENTLY, and this is the rule
# python-coding-hints §1.9/S7 paid for once already: a switch nobody can read
# is not a switch. The refusal names the valid values and the key, and the
# scan proceeds on "auto" ONLY because a typo must not make the scanner dead
# -- the status call reports the refusal so an operator sees it.
SYN_METHOD       = "syn"
CONNECT_METHOD   = "connect"
TCP_PROBE_METHODS = (SYN_METHOD, CONNECT_METHOD)

# What a SYN pass would do, whether it may, and why not -- all decided here.
TCP_METHOD_SETTING_AUTO = "auto"
TCP_METHOD_SETTINGS = (TCP_METHOD_SETTING_AUTO, SYN_METHOD, CONNECT_METHOD)


def tcp_method_setting(config: dict) -> tuple[str, str, str]:
    """
    (setting, which key, problem). `problem` is None unless the value was
    unreadable, in which case the setting is "auto" and the reason travels.

    Read from `port_scan.tcp_method` -- the block the port SET already lives
    in (`port_scan.default_set`) rather than the sensors block, because this
    is a property of the scan a caller asked for, not of whether the sensor
    is enabled at all. An absent key means "auto": every config written
    before this shipped keeps the behaviour it had.
    """
    block = (config or {}).get("port_scan") or {}
    if "tcp_method" not in block:
        return TCP_METHOD_SETTING_AUTO, "no key is set, so it is auto", None
    value = block["tcp_method"]
    if isinstance(value, str) and value.strip().lower() in TCP_METHOD_SETTINGS:
        return (value.strip().lower(), "port_scan.tcp_method", None)
    problem = (
        f"port_scan.tcp_method is {value!r}, which is not one of "
        f"{', '.join(TCP_METHOD_SETTINGS)}. Using 'auto' for this scan so a "
        f"typo does not stop the scanner, but NOTHING about the TCP pass is "
        f"pinned by it: fix the key to pin the method.")
    return TCP_METHOD_SETTING_AUTO, "port_scan.tcp_method (unreadable)", problem


def resolve_tcp_method(config: dict = None) -> tuple[str, str, str | None]:
    """
    (method, reason, problem) for the TCP pass -- THE ONE PLACE THIS IS
    DECIDED, read by the scan, by status() and by every sentence either of
    them prints, so the page, the payload and the log cannot describe three
    different scans.

    `method` is SYN_METHOD, CONNECT_METHOD, or None when the operator pinned
    the SYN scan and no raw socket can be opened. None is a real answer and
    the caller must refuse on it: "syn" was asked for BY NAME, and quietly
    running a different probe would be the original PS-13 defect -- a
    description of code other than the code that ran -- reintroduced as a
    convenience.
    """
    setting, which_key, problem = tcp_method_setting(config)
    ok, why = syn_scan_available()

    if setting == CONNECT_METHOD:
        return CONNECT_METHOD, (
            f"THE CONNECT TEST, PINNED BY CONFIG ({which_key}). A raw socket "
            f"IS available here ({why}), and no SYN is sent because the "
            f"operator's own key says not to. A connect test cannot separate "
            f"a CLOSED port from a FILTERED one: refused and silent are the "
            f"same answer to it."), problem
    if setting == SYN_METHOD:
        if ok:
            return SYN_METHOD, (
                f"A RAW SYN SCAN, PINNED BY CONFIG ({which_key}). {why}. "
                f"Each port gets one SYN and the answer is read: SYN-ACK is "
                f"OPEN, RST is CLOSED, silence is NEITHER."), problem
        return None, (
            f"TCP PROBES REFUSED: {which_key} pins the SYN scan and it cannot "
            f"run here ({why}). NO TCP PORT WAS PROBED AND NO CONNECT TEST "
            f"WAS SUBSTITUTED, because that is what pinning the method means. "
            f"An empty TCP list on this run is the pinned method, NOT a "
            f"machine with nothing open."), problem
    # "auto": SYN where possible, the connect test where it is not.
    if ok:
        return SYN_METHOD, (
            f"A RAW SYN SCAN. {why}. Each port gets one SYN and the answer is "
            f"read: SYN-ACK is OPEN, RST is CLOSED, silence is NEITHER."), problem
    return CONNECT_METHOD, (
        f"FALLING BACK TO THE CONNECT TEST: {why}. The connect test still "
        f"finds open ports. What it cannot do is separate a CLOSED port from "
        f"a FILTERED one, refused and silent are the same answer to it, and "
        f"this run cannot tell them apart."), problem

# Only surface a finding at this level or above. An open 445 on the machine
# AgentalSec runs on is not worth an alert; it is worth a row in the Ports tab.
FINDING_FLOOR = "medium"

MAX_WORKERS  = 100
SCAN_TIMEOUT = 0.5

# The protocol the CONNECT pass speaks. Every row that pass writes is stamped
# with this. Kept as a constant for the reason the old comment gave, which
# turned out to be right: adding the UDP prober was a visible change in one
# place rather than a string edit in five.
SCAN_PROTOCOL = "tcp"
UDP_PROTOCOL = "udp"

# What a run puts on the wire now. Stored on the run row, so a scan from
# before today still says tcp and is not retroactively credited with a UDP
# pass it never made.
PROTOCOLS_TESTED = (SCAN_PROTOCOL, UDP_PROTOCOL)

# UDP PROBES, TODO 117, 2026-09-17.
#
# One well-formed request per service, the smallest that gets an answer. An
# empty datagram is not a probe: a working DNS resolver ignores it, so an
# empty-packet scanner reports every live UDP service as silent, which is
# worse than not scanning because the page then looks authoritative.
#
# Every payload here is a plain read or discovery request. Nothing writes,
# nothing configures, nothing floods: one datagram per port.
def _dns_query() -> bytes:
    # A standard query for the root NS record. Smallest thing every resolver
    # answers, and it asks nothing about the network it is asked from.
    #
    # THE FLAGS WORD IS 0x0100 = RD SET, AND THAT WAS CHECKED RATHER THAN
    # ASSUMED, 2026-09-25. RFC 1035 puts TC at bit 9 (0x0200) and RD at bit 8
    # (0x0100), so `01 00` is a normal recursive client query -- the first
    # reading of this payload, in an earlier draft of this round, called it
    # TC and "fixed" a working probe. Measured against this host's own
    # resolver: rcode 0, ancount 13, tc=0. The bits are named here so the next
    # reader does not have to re-derive them.
    return (b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x02\x00\x01")


def _ntp_query() -> bytes:
    # A 48 byte client packet, LI 0, version 3, mode 3.
    return b"\x1b" + b"\x00" * 47


def _snmp_get() -> bytes:
    # SNMPv2c GetRequest for sysDescr.0 with the community 'public'. This is a
    # read of one string, and 'public' is the default that matters: a device
    # that answers it is the finding.
    #
    # THE OID WAS `1.3.6.1.2.1` AND THE COMMENT SAID sysDescr.0, 2026-09-25.
    # The two disagreed by five sub-identifiers and the comment was the part
    # that was right about the intent: 1.3.6.1.2.1 is the `mib-2` NODE, not a
    # leaf any agent has a value for, so an agent that answered at all
    # answered noSuchObject, which reads on the wire exactly like a device
    # with no SNMP at all. Decoded with scapy from the shipped bytes:
    #
    #     SNMPget varbindlist[0].oid = 1.3.6.1.2.1   (five arcs)
    #     sysDescr.0 is                1.3.6.1.2.1.1.1.0 (eight arcs)
    #
    # A GetRequest is 0xa0 and a SetRequest is 0xa3, one byte apart, and this
    # stays a GET: one read of one string per port, nothing written. The OID is
    # five bytes longer than the one it replaces and every enclosing length
    # octet moves with it, which is why the whole packet is rebuilt here rather
    # than patched:
    #
    #   OID            06 08 2b06010201010100        10 bytes
    #   varbind     30 0c + OID + NULL                14 bytes
    #   varbindlist 30 0e + varbind                    16 bytes
    #   GetRequest  a0 1c + id + errs + vbl            30 bytes
    #   message     30 29 + version + community + PDU  43 bytes
    #
    # The first draft of this fix shipped 0x2a/0x1d/0x0f/0x0d and scapy refused
    # it ("Got 41 bytes while expecting 42"), which is the whole argument for
    # re-parsing a rebuilt BER packet instead of trusting the arithmetic.
    return bytes.fromhex(
        "302902010104067075626c6963a01c0204" "12345678"
        "020100020100300e300c06082b06010201010100" "0500")


def _netbios_status() -> bytes:
    # NetBIOS node status request for the wildcard name '*'.
    #
    # THIS PACKET WAS TWO BYTES SHORT, 2026-09-25, and the two missing bytes
    # were the terminator and the top half of the qtype. RFC 1002 section
    # 4.2.1 lays the name service packet out as:
    #
    #     [0:12]   header (id, flags, qd/an/ns/ar counts)
    #     [12]     0x20, the length of the encoded name
    #     [13:45]  the 32 encoded name bytes
    #     [45]     0x00, end of name
    #     [46:48]  0x0021, qtype = NBSTAT
    #     [48:50]  0x0001, qclass = IN
    #
    # The shipped bytes put 0x21 at [45] and 0x00 0x01 at [46:48], so a
    # responder reading it by offset saw the qtype bytes at the qclass offset
    # and the name never terminated where the spec says it does. Measured
    # length 48 against the layout's 50. A node-status reply is one of the
    # strongest identification signals this scanner has and it was being asked
    # for with a malformed question, which is indistinguishable from a host
    # that does not answer.
    #
    # A 32-byte name field holds the name '*' padded with spaces and encoded
    # two characters to a byte: 'CK' + 30 spaces -> 43 4b then 30 x 0x41.
    return (b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20\x43\x4b" + b"\x41" * 30 +
            b"\x00\x00\x21\x00\x01")


def _ssdp_msearch() -> bytes:
    return (b"M-SEARCH * HTTP/1.1\r\n"
            b"HOST: 239.255.255.250:1900\r\n"
            b'MAN: "ssdp:discover"\r\n'
            b"MX: 1\r\n"
            b"ST: ssdp:all\r\n\r\n")


def _ptr_qname(address: str) -> bytes:
    """
    The reverse-DNS name of an ADDRESS, as DNS labels.

    RFC 6762 section 8 names this as THE way to ask a host about itself by
    unicast: "an mDNS responder MUST respond to a reverse address mapping PTR
    query for the address on the interface it was received on". That is the
    only question in that spec a responder is REQUIRED to answer off its
    multicast group, which makes it the right probe for a scanner that can
    only send unicast.
    """
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        return b""
    if addr.version == 4:
        labels = list(reversed(str(addr).split("."))) + ["in-addr", "arpa"]
    else:
        nibbles = str(addr.exploded).replace(":", "")
        labels = list(reversed(nibbles)) + ["ip6", "arpa"]
    out = b""
    for label in labels:
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def _ptr_query(name: bytes, qclass: int = 1) -> bytes:
    """
    A PTR question for one name. ID 0, RD 0 -- a query a RESPONDER answers.

    THE TRANSPORT IS THE DEFECT THIS REPLACES, 2026-09-25. The module used to
    send one mDNS question -- `_services._dns-sd._udp.local` PTR -- UNICAST to
    the target, for both 5353 and 5355. Measured on this host against a
    working avahi-daemon holding UDP 5353 on 0.0.0.0:

        the shipped enumeration PTR, unicast  -> NO REPLY
        the shipped enumeration PTR, multicast -> NO REPLY
        an A query for this host's own name, unicast -> 67 bytes
        a reverse PTR for this host's address, unicast -> 87 bytes

    so a responder that was up and answering was reported as `udp_no_answer`,
    the one answer this module's whole design says must never be confused with
    absence of a service. Service enumeration is a MULTICAST question by
    design; a unicast scanner cannot ask it and must ask something else, which
    is why this is an address question rather than a service-type list.
    """
    return (b"\x00\x00"  # id 0
            b"\x00\x00"  # flags: no QR, no opcode, no RD (mDNS forbids RD)
            b"\x00\x01"  # qdcount
            b"\x00\x00\x00\x00\x00\x00"  # an/ns/ar
            + name +
            b"\x00\x0c" + qclass.to_bytes(2, "big"))  # qtype PTR, qclass


def _mdns_query(address: str = None) -> bytes:
    """
    The mDNS (5353) probe: a reverse address PTR for the ADDRESS being
    scanned, which RFC 6762 section 8 requires a responder to answer unicast.

    An absent or UNPARSEABLE address keeps the service-enumeration question, so
    every caller gets a well-formed packet rather than a nameless one; the scan
    path always passes an address it has already resolved.
    """
    name = _ptr_qname(address) if address else b""
    if not name:
        name = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
    return _ptr_query(name)


def _llmnr_query(address: str = None) -> bytes:
    """
    The LLMNR (5355) probe. LLMNR is NOT mDNS: RFC 4795 has no multicast
    service enumeration and no reverse address PTR requirement, so the mDNS
    service-list question was never a question this protocol could answer.
    What LLMNR does define is a name query, so this asks for the NAME of the
    address being scanned -- `1.0.0.127.in-addr.arpa` -- with RD set, which is
    the ordinary recursive-client shape RFC 4795 section 2.1 allows (and
    requires: "the RD bit MUST be set").

    An absent or unparseable address falls back to the service-enumeration
    NAME, so the packet stays well formed; it is not a better question, and the
    scan path never reaches this branch.
    """
    name = _ptr_qname(address) if address else b""
    if not name:
        name = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
    return (b"\x00\x00"                          # id 0
            b"\x01\x00"                          # flags: RD set, as RFC 4795 requires
            b"\x00\x01"
            b"\x00\x00\x00\x00\x00\x00"
            + name +
            b"\x00\x0c\x00\x01")


UDP_PROBES = {
    # port: (name, builder, transport, scope)
    #
    # `scope` is on every probe now, 2026-09-25, because the SCOPE SENTENCE
    # was claiming more than the pass delivers: it said all 25 UDP ports were
    # asked "with a real datagram" while 18 of them were sent an EMPTY one,
    # which this module's own header calls worse than not scanning at all. A
    # port whose entry reads 'empty' is a port where only an ICMP unreachable
    # can settle anything, and the reader is told so on the row rather than
    # left to infer it from a sentence that says otherwise.
    #
    # `transport` says whether the question is one a responder answers when it
    # arrives unicast at that host. Both mDNS and LLMNR probes are built for
    # the ADDRESS being scanned, so the builder takes the host; a builder
    # declared with no argument is still accepted and called with none.
   53:    ("dns",  _dns_query,      "unicast", "well-formed query for the root NS record"),
    123:   ("ntp",  _ntp_query,      "unicast", "48-byte client packet, mode 3"),
    137:   ("netbios-ns", _netbios_status, "unicast", "NBSTAT node-status request for the wildcard name"),
    161:   ("snmp", _snmp_get,       "unicast", "GetRequest for sysDescr.0 with community 'public'"),
    1900:  ("ssdp", _ssdp_msearch,   "unicast", "M-SEARCH for ssdp:all; multicast by convention, answered unicast by UPnP devices"),
    5353:  ("mdns", _mdns_query,    "unicast", "reverse address PTR, which RFC 6762 section 8 requires a responder to answer unicast"),
    5355:  ("llmnr", _llmnr_query,  "unicast", "name query with RD set, the shape RFC 4795 defines"),
}

# Probes whose builder wants the target address. Everything else is called
# with no arguments, which is what every existing caller and test assumes.
UDP_ADDRESSED_PROBES = ("mdns", "llmnr")


def build_udp_probe(port: int, host: str = None) -> tuple:
    """
    (probe_name, payload, transport, scope) for one UDP port.

    The single place a payload is built, so the scan path and any reader asking
    "what does this port get asked" cannot disagree. An unprofiled port gets an
    empty datagram and the scope says so.
    """
    entry = UDP_PROBES.get(port)
    if not entry:
        return ("empty datagram", b"", "unicast",
                "no request shape is known for this port, so only an ICMP "
                "unreachable can settle anything about it")
    name, builder, transport, scope = entry
    if name in UDP_ADDRESSED_PROBES and host:
        return (name, builder(host), transport, scope)
    return (name, builder(), transport, scope)

# The UDP ports the pass covers even when nothing profiled them. The owner's point on
# 2026-09-17 was the second half of the complaint: the important UDP services
# were never going to appear just because the TCP list happened to include the
# number. A port here with no entry in UDP_PROBES is still probed, with an
# empty datagram, and silence on it is reported as silence rather than as a
# result. That is worth doing because ICMP unreachable still proves CLOSED,
# which is real information about a port nobody is serving.
UDP_SCAN_PORTS = sorted({
    53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 623, 631,
    1434, 1900, 3074, 4500, 5353, 5355, 11211, 987, 9296, 9297, 9302,
    *UDP_PORT_FACTS,
})

# Longer than the TCP timeout on purpose. A UDP reply comes back from a
# service that had to parse the request, and some IoT stacks are slow; a 0.5
# second window turns a working device into a silent one.
UDP_TIMEOUT = 1.0

# IP_RECVERR: the kernel keeps each ICMP error on the socket's error queue
# with its type, code and sender, so a UDP answer says which ICMP message it
# was and who sent it (a router refusing for the target is not the target).
_IP_RECVERR = getattr(socket, "IP_RECVERR", 11)
_IPV6_RECVERR = getattr(socket, "IPV6_RECVERR", 25)
_MSG_ERRQUEUE = getattr(socket, "MSG_ERRQUEUE", 0x2000)
_SO_EE_ORIGIN_ICMP, _SO_EE_ORIGIN_ICMP6 = 2, 3

_ICMP4_UNREACH = {0: "network unreachable", 1: "host unreachable",
                  2: "protocol unreachable", 3: "port unreachable",
                  9: "network administratively prohibited",
                  10: "host administratively prohibited",
                  13: "communication administratively prohibited"}
_ICMP6_UNREACH = {0: "no route to destination",
                  1: "communication administratively prohibited",
                  3: "address unreachable", 4: "port unreachable",
                  5: "source address failed policy", 6: "reject route"}


def _enable_recverr(sock, family) -> bool:
    try:
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, _IPV6_RECVERR, 1)
        else:
            sock.setsockopt(socket.IPPROTO_IP, _IP_RECVERR, 1)
        return True
    except (OSError, AttributeError):
        return False


def read_icmp_error(sock) -> dict | None:
    """
    The ICMP message behind a UDP socket error, from its error queue:
    {"type", "code", "from", "meaning", "port_unreachable"}, or None.
    """
    try:
        _data, anc, _flags, _addr = sock.recvmsg(512, 512, _MSG_ERRQUEUE)
    except (OSError, AttributeError):
        return None
    for _level, _type, data in anc:
        if len(data) < 16:
            continue
        _errno, origin, itype, code, _pad, _info, _d = struct.unpack_from(
            "=IBBBBII", data)
        if origin not in (_SO_EE_ORIGIN_ICMP, _SO_EE_ORIGIN_ICMP6):
            continue
        sender = None
        off = data[16:]
        try:
            fam = struct.unpack_from("=H", off)[0]
            if fam == socket.AF_INET and len(off) >= 8:
                sender = socket.inet_ntop(socket.AF_INET, off[4:8])
            elif fam == socket.AF_INET6 and len(off) >= 24:
                sender = socket.inet_ntop(socket.AF_INET6, off[8:24])
        except (struct.error, ValueError, OSError):
            sender = None
        v6 = origin == _SO_EE_ORIGIN_ICMP6
        table = _ICMP6_UNREACH if v6 else _ICMP4_UNREACH
        unreach = (itype == 1) if v6 else (itype == 3)
        meaning = (table.get(code, f"unreachable code {code}") if unreach
                   else f"ICMP{'v6' if v6 else ''} type {itype} code {code}")
        return {"type": itype, "code": code, "from": sender,
                "meaning": meaning,
                "port_unreachable": unreach and code == (4 if v6 else 3)}
    return None


# What Linux raises on a connected UDP socket's recv() for an ICMP unreachable
# other than "port unreachable": host, network or administratively prohibited.
_ICMP_FILTER_ERRNOS = {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EACCES,
                       errno.EPERM}

# A full UDP sweep is not offered and this says why rather than leaving it to
# be discovered. 65535 UDP probes at one second each, with nothing useful to
# send to most of them, is hours per host for answers that would nearly all be
# silence. The list above is the honest scope.
UDP_SCOPE_NOTE = (
    "The UDP pass covers a fixed list of real UDP services, not a full sweep. "
    "A port that is not on that list was not asked about over UDP, and a port "
    "on it that stayed silent is not closed. Only a reply proves open, and "
    "only an ICMP unreachable proves closed.")


# THE RAW SYN SCAN -- PS-13 OPTION (c), BUILT 2026-09-25
#
# WHY THIS EXISTS. The privilege row for this module used to say "TCP SYN scan
# requires root. Falls back to TCP connect() scan" and NO SYN SCAN EXISTED
# anywhere in this tree -- the row described code nobody had written. It was
# corrected to "needs nothing" (register PS-13, first closure) and that
# correction was itself FALSE for the module as a whole, because a self-scan
# attaches tools/port_owner's answer to every open port and that answer loses
# every root-owned listener unelevated (measured: 0 of 13 matched). The owner
# was given three designs and took the third: "do option C and when done
# report back" -- build the scan, so elevation buys both the raw scan and the
# owners.
#
# WHAT A SYN SCAN BUYS THAT A CONNECT SCAN CANNOT. The connect test is a
# COMPLETED HANDSHAKE: True means something accepted, and False covers
# refused, filtered, timed out and "that is a UDP service" all at once. A SYN
# pass reads the ANSWERS themselves and separates two of those:
#
#     SYN-ACK   OPEN.   Something is listening and it answered.
#     RST       CLOSED. The host said nothing is there. THIS is the answer the
#                       connect scan cannot give: "the host refused me" and
#                       "nothing came back" are different facts about a port
#                       and only this pass tells them apart.
#     silence   NEITHER. Filtered, rate-limited, or the answer was lost. NOT
#                       closed, and it is never reported as closed.
#
# THE TEARDOWN IS OURS, NOT THE KERNEL'S LUCK. Every SYN-ACK is answered with
# an RST so the target never holds a half-open connection. On Linux the kernel
# would usually do this for us (there is no socket in SYN-SENT, so it RSTs the
# SYN-ACK), and a scanner that relied on that would be describing an incidental
# kernel behaviour as its own design. The RST is sent here by name.
#
# AND THE PASS IS ONE SHARED WINDOW. A connect pass pays its timeout per probe
# across MAX_WORKERS threads; a SYN pass sends its SYNs and then waits ONCE
# for answers to come back, because the answers are demultiplexed from the raw
# socket rather than from a socket per port. That is what makes 'extended' and
# 'all' affordable, and it is why SYN_TIMEOUT is not SCAN_TIMEOUT.
#
# WHAT THE RAW SOCKET SEES. An AF_INET/SOCK_RAW socket with IPPROTO_TCP
# receives TCP segments addressed to this host -- and on a SELF-SCAN the
# packets this pass sends also match, so the parser is not allowed to believe
# a frame it cannot attribute. A reply counts only when it is FROM the address
# probed, FROM the port probed, TO the source port this pass allocated, and it
# is either a SYN-ACK or an RST that ACKNOWLEDGES OUR SEQUENCE NUMBER. The
# kernel's own RST after a SYN-ACK carries a different acknowledgement, which
# is exactly what keeps it from being read as "closed" on a port that just
# answered. That check was measured on this host before it was written here:
# a live listener on loopback answered SYN-ACK in 1.1 ms, a dead port answered
# RST with ack == our_seq + 1 in 0.3 ms.
#
# THE LIMITS, STATED RATHER THAN DISCOVERED:
#   * a raw socket needs CAP_NET_RAW or root. Unelevated this whole section is
#     unreachable and the connect test runs instead, WITH THE METHOD NAMED ON
#     THE PAYLOAD. That is the original PS-13 defect in reverse: the payload
#     may never describe a scan other than the one that ran.
#   * IPv6 frames are parsed with the fixed 40-byte header only. A v6 reply
#     carrying extension headers is SKIPPED rather than misread, and a port
#     whose only reply was an extension-header frame reads no_answer -- the
#     conservative direction.
#   * a bare RST (no ACK) is left as silence for the same reason: it cannot be
#     attributed to our SYN rather than to some other traffic on the machine.

# The one shared window a SYN pass waits for answers. Longer than
# SCAN_TIMEOUT on purpose: it is not paid per port, and a LAN device that
# answers in 700 ms is open, not silent.
SYN_TIMEOUT = 1.5

# Probes one engine sends before it waits for answers and closes. Well under
# the source-port range, so a pass never runs out of ports.
SYN_BATCH_PROBES = 10000

# The probe's source port and sequence come from the OS, not the shared PRNG (PS-29).
_SYN_RNG = random.SystemRandom()

# A short pause every few SYNs, so the receiver drains its socket before the
# answers overflow it; unpaced, thousands of loopback answers were lost.
SYN_PACE_EVERY = 64
SYN_PACE_SECONDS = 0.004

# The source ports this pass allocates. High and away from the ports being
# scanned so a reply cannot be confused with a probe.
SYN_SOURCE_PORT_LOW  = 40000
SYN_SOURCE_PORT_HIGH = 60000

# How much of a captured frame is read, and how long a receiver sleeps
# between checks of its stop flag.
SYN_RECV_SIZE   = 65535
SYN_RECV_POLL   = 0.2
SYN_RECV_BUFFER = 1 << 20

# TCP flags this pass cares about. Named so the parser never writes a bare
# hex literal and the next reader never has to re-derive which bit is which.
_TCP_FIN = 0x01
_TCP_SYN = 0x02
_TCP_RST = 0x04
_TCP_ACK = 0x10


def syn_scan_available() -> tuple:
    """
    (True, why) if a raw TCP socket can be opened, else (False, why).

    A PROBE, NOT A GUESS -- the same rule SNF-5 and EM-9 fixed elsewhere in
    this tree: `is_elevated()` is not the question, because CAP_NET_RAW can be
    attached to the binary and root can still be refused by a hardened kernel
    (or the process can be inside a user namespace that holds it). The only
    thing that answers "may I open a raw socket" is opening one.
    """
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                              socket.IPPROTO_TCP)
    except OSError as e:
        return False, (f"a raw TCP socket was refused "
                       f"({e.strerror or e}, errno {e.errno})")
    except Exception as e:                                    # noqa: BLE001
        return False, (f"a raw TCP socket could not be opened "
                       f"({type(e).__name__}: {e})")
    probe.close()
    return True, "a raw TCP socket opened, so the TCP pass can send SYNs"


def tcp_probe_method() -> tuple:
    """
    (method, reason) for the TCP pass when nothing is configured -- decided in
    ONE place, read by every surface.

    KEPT AS A THIN WRAPPER over resolve_tcp_method rather than a second
    implementation: it is what the module's existing callers (and the tests
    written before PS-13 option (c)) ask, it takes no config because those
    callers have none, and "the default reading of an absent key" is exactly
    what a config-less caller deserves. The scan path asks
    resolve_tcp_method(self.config) instead, which is the same function with
    the operator's own key in hand.
    """
    method, reason, _problem = resolve_tcp_method(None)
    # A config-less caller can never be in the pinned-"syn"-refused state as
    # anything but the fallback: an absent key means "auto", so the answer is
    # always a method. Asserted rather than assumed, because the day that
    # stops being true the caller below would silently report None as a scan.
    if method is None:
        return CONNECT_METHOD, reason
    return method, reason


def _checksum(data: bytes) -> int:
    """
    The internet checksum, RFC 1071.

    Odd lengths are padded, the carries are folded, and the result is
    complemented. A wrong checksum here is not a crash: the target's stack
    drops the segment in silence and every port reads no_answer, which is the
    one failure this pass must not have. So the tests pin it against a
    checksum computed by hand for a known segment rather than against a shape.
    """
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def build_tcp_segment(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                      seq: int, ack: int, flags: int,
                      window: int = 0) -> bytes:
    """
    One TCP segment with its checksum, for the family of the two literals.

    THE FAMILY IS DERIVED FROM THE ADDRESS, not passed in and not assumed:
    the pseudo-header differs between v4 and v6 (4-byte addresses and a zero
    pad versus 16-byte addresses and a 32-bit length), and a segment built
    with the wrong one is silently dropped by the peer. Both literals are
    already addresses by the time this is called.
    """
    header = struct.pack("!HHLLBBHHH", src_port & 0xFFFF, dst_port & 0xFFFF,
                         seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                         5 << 4, flags & 0xFF, window & 0xFFFF, 0, 0)
    if ":" in src_ip:
        pseudo = (socket.inet_pton(socket.AF_INET6, src_ip)
                  + socket.inet_pton(socket.AF_INET6, dst_ip)
                  + struct.pack("!I", len(header))
                  + b"\x00\x00\x00\x06" + header)
    else:
        pseudo = (socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
                  + b"\x00\x06" + struct.pack("!H", len(header)) + header)
    csum = _checksum(pseudo)
    return struct.pack("!HHLLBBHHH", src_port & 0xFFFF, dst_port & 0xFFFF,
                       seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                       5 << 4, flags & 0xFF, window & 0xFFFF, csum, 0)


def build_tcp_syn(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                  seq: int) -> bytes:
    """The probe: one SYN, our sequence number, a normal client window."""
    return build_tcp_segment(src_ip, dst_ip, src_port, dst_port, seq, 0,
                             _TCP_SYN, window=64240)


def build_tcp_rst(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                  seq: int, ack: int) -> bytes:
    """
    The teardown: an RST acknowledging the SYN-ACK, so the target does not
    hold a half-open connection because of this pass.
    """
    return build_tcp_segment(src_ip, dst_ip, src_port, dst_port, seq, ack,
                             _TCP_RST | _TCP_ACK)


def parse_tcp_reply(frame: bytes, family: int, src_ip: str = None) -> dict:
    """
    One captured frame -> the fields this pass needs, or None.

    RETURNS None FOR ANYTHING IT CANNOT READ CONFIDENTLY, and that is the
    whole contract: a parser that guesses here turns unrelated traffic on a
    busy machine into answers about the target. Skipped: a non-TCP frame, a
    frame whose version byte does not match the socket's family, a v6 frame
    with extension headers (the 40-byte fixed header is all this reads, so
    the TCP header would be at an offset this function does not compute), a
    truncated frame.

    The addresses come back as STRINGS through inet_ntop, so the caller
    compares them against the literal it probed rather than against bytes it
    would have to remember the endianness of.
    """
    if family == socket.AF_INET6 and src_ip is not None:
        return _parse_bare_tcp(frame, src_ip)
    try:
        if family == socket.AF_INET:
            if len(frame) < 20 or (frame[0] >> 4) != 4:
                return None
            ihl = (frame[0] & 0x0F) * 4
            if ihl < 20 or len(frame) < ihl + 20 or frame[9] != 6:
                return None
            src_ip = socket.inet_ntoa(frame[12:16])
            dst_ip = socket.inet_ntoa(frame[16:20])
            offset = ihl
        else:
            if len(frame) < 40 or (frame[0] >> 4) != 6:
                return None
            # next-header == 6 means TCP immediately follows the fixed header.
            # A 60 or 43 here is a hop-by-hop or routing header and is SKIPPED,
            # see the docstring.
            if frame[6] != 6 or len(frame) < 60:
                return None
            src_ip = socket.inet_ntop(socket.AF_INET6, frame[8:24])
            dst_ip = socket.inet_ntop(socket.AF_INET6, frame[24:40])
            offset = 40
        sport, dport, seq, ack = struct.unpack(
            "!HHLL", frame[offset:offset + 12])
        flags = frame[offset + 13]
    except (struct.error, ValueError, OSError):
        return None
    return {
        "src_ip": src_ip, "dst_ip": dst_ip,
        "sport": sport, "dport": dport,
        "seq": seq, "ack": ack, "flags": flags,
        "is_syn_ack": bool(flags & _TCP_SYN and flags & _TCP_ACK),
        "is_rst":     bool(flags & _TCP_RST),
    }


def _parse_bare_tcp(segment: bytes, src_ip: str) -> dict:
    """
    A TCP segment with no IP header in front of it, which is what a Linux
    IPv6 raw socket delivers (measured: 20 bytes for a bare SYN-ACK). The
    source comes from recvfrom. Reading these as full frames made every IPv6
    port read no_answer (PS-16).
    """
    if len(segment) < 20:
        return None
    try:
        sport, dport, seq, ack = struct.unpack("!HHLL", segment[:12])
        flags = segment[13]
        src = str(ipaddress.ip_address(src_ip.split("%")[0]))
    except (struct.error, ValueError):
        return None
    return {
        "src_ip": src, "dst_ip": None,
        "sport": sport, "dport": dport,
        "seq": seq, "ack": ack, "flags": flags,
        "is_syn_ack": bool(flags & _TCP_SYN and flags & _TCP_ACK),
        "is_rst":     bool(flags & _TCP_RST),
    }


def source_address_for(dst_ip: str, family: int) -> tuple:
    """
    (src_ip, error): the address this machine would reach dst_ip FROM.

    Asked of the ROUTING TABLE by connecting a UDP socket, which sends
    nothing and picks the same source the kernel would use for the real
    segment. Guessing from the interface list would be wrong on a multi-homed
    host -- the pseudo-header checksum is computed over the source, so a
    wrong source is a silently dropped SYN and a port that reads no_answer.
    """
    try:
        probe = socket.socket(family, socket.SOCK_DGRAM)
    except OSError as e:
        return None, f"could not build a socket for {dst_ip} ({e})"
    try:
        if family == socket.AF_INET6:
            probe.connect((dst_ip, 9, 0, 0))
        else:
            probe.connect((dst_ip, 9))
        return probe.getsockname()[0], None
    except OSError as e:
        return None, (f"no route to {dst_ip} from here "
                      f"({e.strerror or e})")
    finally:
        probe.close()


def _raw_send_dest(family: int, ip: str) -> tuple:
    """
    The destination tuple a raw socket's sendto takes for one address.

    MEASURED ON THIS HOST, not assumed: an AF_INET6 raw socket REFUSES a
    4-tuple destination ("[Errno 22] Invalid argument") and accepts the
    2-tuple the v4 socket takes. Both families send to `(ip, 0)` -- the port
    in a raw destination is not what routes the segment, the IP header is.
    """
    return (ip, 0)


def _canonical_ip(value: str) -> str:
    """One spelling per address, so '::1' and '0:0::1' compare equal."""
    try:
        return str(ipaddress.ip_address((value or "").split("%")[0]))
    except ValueError:
        return value or ""


class SynPassAborted(RuntimeError):
    """A SYN pass that stopped after sending; carries what it sent and heard (PS-27)."""

    def __init__(self, cause: Exception, partial: dict):
        super().__init__(str(cause))
        self.cause = cause
        self.partial = partial


class SynScanEngine:
    """
    ONE PASS OF RAW SYN PROBES: send SYNs, demultiplex the answers.

    A context manager. The sockets, the demultiplexing and the teardown live
    here; deciding which ports to ask, what to do with the answers and how to
    score them lives in PortScanner, which is where every other pass in this
    module keeps its scoring.

    THE JOIN KEY IS OUR OWN SOURCE PORT, allocated uniquely per probe. It is
    the only field in a reply that this machine chose and nobody else
    controls, so it cannot collide with another conversation's ports the way
    the destination port can (a scan of two hosts both running 631 would
    otherwise have one answer stand in for the other).
    """

    def __init__(self, timeout: float = SYN_TIMEOUT, families=None):
        self.timeout = float(timeout)
        # Only the families this pass will probe; None means both (PS-28).
        self._families = list(families) if families else None
        self._lock = threading.Lock()
        self._sockets = {}       # family -> raw socket
        self._refused = {}       # family -> why it could not be opened
        self._pending = {}       # our source port -> (src_ip, dst_ip, dst_port, seq)
        self._answers = {}       # our source port -> 'open' or 'closed'
        self._threads = []
        self._stop = threading.Event()
        self._next_port = _SYN_RNG.randint(SYN_SOURCE_PORT_LOW,
                                           SYN_SOURCE_PORT_HIGH)
        self._first_sent_at = None
        self._last_sent_at = None
        self.sent = 0
        self.teardowns = 0
        self.refused_sends = []

    # open / close

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *_exc):
        self.close()
        return False

    def open(self) -> None:
        """
        One raw socket per family that will open, and a receiver per socket.

        A family that refuses is REMEMBERED WITH ITS REASON rather than
        raising: on a v6-less kernel, or where only one family is permitted,
        the pass can still be useful, and the ports it could not ask are
        reported with the reason.
        """
        families = self._families
        if families is None:
            families = [socket.AF_INET]
            if getattr(socket, "AF_INET6", None):
                families.append(socket.AF_INET6)
        for family in families:
            try:
                sock = socket.socket(family, socket.SOCK_RAW,
                                     socket.IPPROTO_TCP)
            except OSError as e:
                self._refused[family] = (f"{e.strerror or e} "
                                         f"(errno {e.errno})")
                continue
            except Exception as e:                            # noqa: BLE001
                self._refused[family] = f"{type(e).__name__}: {e}"
                continue
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                                SYN_RECV_BUFFER)
            except OSError:
                pass
            sock.settimeout(SYN_RECV_POLL)
            self._sockets[family] = sock
            thread = threading.Thread(target=self._receive_loop,
                                      args=(family, sock), daemon=True,
                                      name=f"syn-recv-{family}")
            thread.start()
            self._threads.append(thread)
        if not self._sockets:
            raise PermissionError(
                "no raw socket could be opened for either address family: "
                + "; ".join(f"{fam}: {why}"
                            for fam, why in self._refused.items()))

    def close(self) -> None:
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=SYN_RECV_POLL * 3)
        for sock in self._sockets.values():
            try:
                sock.close()
            except OSError:
                pass
        self._sockets.clear()

    # sending

    def family_available(self, family: int) -> bool:
        return family in self._sockets

    def refusal_reason(self, family: int) -> str:
        return self._refused.get(family, "no raw socket for this family")

    def _allocate_source_port(self) -> int:
        """
        A source port nothing else in this pass is using.

        Collisions are not cosmetic here: two probes sharing a source port
        would make one answer ambiguous between them, and the demultiplexer
        keys on exactly this field.
        """
        span = SYN_SOURCE_PORT_HIGH - SYN_SOURCE_PORT_LOW
        for _ in range(span + 1):
            port = self._next_port
            self._next_port = SYN_SOURCE_PORT_LOW + (
                (self._next_port - SYN_SOURCE_PORT_LOW + 1) % (span + 1))
            if port not in self._pending:
                return port
        raise RuntimeError("every source port in the range is in use")

    def probe(self, family: int, src_ip: str, dst_ip: str, dst_port: int) -> tuple:
        """
        Send one SYN. (sent: bool, error: str|None).

        Never raises: a send that the kernel refuses is one port this pass
        could not ask, and that is reported where the port is, not as a dead
        scan.
        """
        sock = self._sockets.get(family)
        if sock is None:
            return False, self.refusal_reason(family)
        with self._lock:
            src_port = self._allocate_source_port()
            seq = _SYN_RNG.getrandbits(32)
            self._pending[src_port] = (src_ip, dst_ip, dst_port, seq)
        try:
            sock.sendto(build_tcp_syn(src_ip, dst_ip, src_port, dst_port, seq),
                        _raw_send_dest(family, dst_ip))
        except OSError as e:
            with self._lock:
                self._pending.pop(src_port, None)
            return False, f"the SYN could not be sent ({e.strerror or e})"
        with self._lock:
            self.sent += 1
            self._last_sent_at = time.monotonic()
            if self._first_sent_at is None:
                self._first_sent_at = self._last_sent_at
        return True, None

    # receiving

    def _receive_loop(self, family: int, sock) -> None:
        """
        Every frame this socket sees, until close().

        An OSError mid-pass stops THIS loop quietly rather than tearing the
        scan down: a receiver that dies must not take the demultiplexing with
        it -- the answers already read stay read, and the ports whose answers
        never arrived stay no_answer, which is the honest reading of both.
        """
        while not self._stop.is_set():
            try:
                frame, addr = sock.recvfrom(SYN_RECV_SIZE)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self._handle_frame(family, sock, frame,
                                   addr[0] if family == socket.AF_INET6 else None)
            except Exception:                                 # noqa: BLE001
                continue

    def _handle_frame(self, family: int, sock, frame: bytes,
                      peer: str = None) -> None:
        # `peer` is set for IPv6, whose raw frames carry no IP header.
        reply = parse_tcp_reply(frame, family, src_ip=peer)
        if not reply:
            return
        teardown = None
        with self._lock:
            pending = self._pending.get(reply["dport"])
            if not pending:
                return
            src_ip, dst_ip, dst_port, seq = pending
            # IT MUST BE FROM THE ADDRESS AND PORT PROBED. A scan of a busy
            # host sees plenty of TCP that has nothing to do with it.
            if reply["sport"] != dst_port or \
                    _canonical_ip(reply["src_ip"]) != _canonical_ip(dst_ip):
                return
            if reply["is_syn_ack"]:
                # OPEN IS STICKY: the kernel's own RST follows a SYN-ACK on a
                # self-scan, and it must not overwrite the answer that arrived
                # first with a "closed" this pass caused itself.
                self._answers[reply["dport"]] = "open"
                # THE TEARDOWN'S PORTS ARE THE MIRROR OF THE REPLY'S, and this
                # was the ONE DEFECT this round's own checks found in the new
                # code: the RST goes FROM OUR SOURCE PORT (the reply's
                # destination) TO THE PORT WE PROBED (the reply's source). With
                # them the other way round the segment is addressed from the
                # target's own port and the half-open entry on the target is
                # not matched at all -- so the port this pass opened stays
                # open, which is the one thing the teardown exists to prevent.
                # The check that caught it asserts the teardown's source port
                # is the port the SYN used.
                teardown = (src_ip, dst_ip, reply["dport"], reply["sport"],
                            reply["ack"], (reply["seq"] + 1) & 0xFFFFFFFF)
            elif (reply["is_rst"] and reply["flags"] & _TCP_ACK
                  and reply["ack"] == ((seq + 1) & 0xFFFFFFFF)):
                # AN ANSWER TO OUR SYN, and the acknowledgement is what proves
                # it: a bare RST, or one acknowledging somebody else's
                # sequence number, is left as silence rather than read as a
                # statement about this port.
                if self._answers.get(reply["dport"]) != "open":
                    self._answers[reply["dport"]] = "closed"
        if teardown:
            # THE TEARDOWN GOES OUT FROM THE SAME ADDRESS, SOURCE PORT AND
            # SEQUENCE THE SYN USED -- a different source would not match the
            # half-open entry on the target and would leave it hanging, which
            # is the one thing this RST exists to prevent.
            (src_ip, dst_ip, src_port, dst_port,
             seq, ack) = teardown
            try:
                sock.sendto(build_tcp_rst(src_ip, dst_ip, src_port, dst_port,
                                          seq, ack),
                            _raw_send_dest(family, dst_ip))
            except OSError:
                return
            with self._lock:
                self.teardowns += 1

    # reading it back

    def finish(self) -> dict:
        """
        Wait out the single shared window, stop the receivers, and answer.

        {(dst_ip, port): 'open'|'closed'|'no_answer'}. A port with no answer
        of any kind is NO_ANSWER, never closed: this pass refuses to fold
        silence into either verdict, which is the rule the UDP pass already
        lives by and the reason the connect fallback is the weaker method.
        """
        # The window runs from the LAST SYN: timed from the first, the ports
        # sent last on a big set got little or no time to answer (PS-17).
        if self._last_sent_at is not None:
            remaining = self.timeout - (time.monotonic() - self._last_sent_at)
            if remaining > 0:
                time.sleep(remaining)
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=SYN_RECV_POLL * 3)
        for sock in self._sockets.values():
            try:
                sock.close()
            except OSError:
                pass
        self._sockets.clear()
        out = {}
        with self._lock:
            for src_port, pending in self._pending.items():
                _src_ip, dst_ip, dst_port, _seq = pending
                out[(dst_ip, dst_port)] = self._answers.get(src_port,
                                                            "no_answer")
        return out


def _target_addresses(target_host: str) -> set:
    """Every address a name resolves to, canonical, v4-mapped unwrapped."""
    out = set()
    try:
        for *_rest, sockaddr in socket.getaddrinfo(target_host, None):
            a = _canonical_ip(sockaddr[0])
            out.add(a[7:] if a.startswith("::ffff:") and "." in a else a)
    except socket.gaierror:
        pass
    return out


def _probe_reaches(bound: str, targets: set) -> bool:
    """Could a probe of these target addresses reach a socket bound here?"""
    b = (bound or "").split("%")[0]
    if b.startswith("::ffff:") and "." in b:
        b = b[7:]
    if b in ("0.0.0.0", "*"):
        return any("." in t for t in targets)
    if b == "::":
        return bool(targets)             # dual-stack unless v6only; a close call
    return _canonical_ip(b) in targets


def kernel_view(target_host: str, ports: list, udp_ports: list,
                tcp_open: list, udp_open: list, port_set: str) -> dict:
    """
    A self-scan checked against the kernel's own listener table (PS-21).

    The probes only see what answers on the scanned address. The kernel lists
    every bound socket, so everything it holds that the probes did not see is
    named with the reason: bound to another address, outside the port set, a
    UDP service that stayed silent, or SCTP, which is not probed. Each open
    port also gets the firewall's verdict on whether other machines can reach
    it. Raw and packet sockets, which listen without any port, are counted.
    """
    from tools import socket_census
    try:
        cen = socket_census.census()
    except Exception as e:                                    # noqa: BLE001
        return {"available": False, "reason": f"{type(e).__name__}: {e}"}
    targets = _target_addresses(target_host)
    tcp_seen = {e["port"] for e in tcp_open}
    udp_seen = {e["port"] for e in udp_open}
    scanned = {"tcp": set(ports), "udp": set(udp_ports)}
    missed, seen = [], []
    for row in cen["listeners"]:
        proto, port = row["proto"], row["local_port"]
        entry = {"proto": proto, "address": row["local_address"], "port": port,
                 "owner": row.get("comm"), "pid": row.get("pid"),
                 "owner_status": row.get("owner_status"),
                 "exposure": row.get("exposure"), "exposure_basis": row.get("basis")}
        if (proto == "tcp" and port in tcp_seen) or (proto == "udp" and port in udp_seen):
            seen.append(entry)
            continue
        if proto == "sctp":
            why = "SCTP is not probed by this scanner"
        elif not _probe_reaches(row["local_address"], targets):
            why = (f"bound to {row['local_address']} only, and the scan asked "
                   f"{', '.join(sorted(targets)) or target_host}")
        elif port not in scanned.get(proto, set()):
            why = f"port {port} is outside the '{port_set}' {proto} set"
        elif proto == "udp":
            why = "a UDP service that did not answer the probe"
        else:
            why = "bound where the probe went, and the probe did not see it"
        entry["why_missed"] = why
        missed.append(entry)
    for e in tcp_open + udp_open:
        rows = [r for r in cen["listeners"] if r["proto"] == e.get("protocol")
                and r["local_port"] == e["port"]]
        if rows:
            order = ["reachable", "reachable_from_some", "undetermined",
                     "unknown", "firewalled", "loopback_only"]
            best = min(rows, key=lambda r: order.index(r.get("exposure", "unknown"))
                       if r.get("exposure") in order else 3)
            e["exposure"] = best.get("exposure")
            e["exposure_basis"] = best.get("basis")
    hidden = cen["hidden"]
    return {
        "available": True,
        "kernel_listeners": len(cen["listeners"]),
        "seen_by_probe": len(seen),
        "missed_by_probe": missed,
        "hidden_sockets": [{k: h.get(k) for k in (
            "kind", "protocol_name", "interface", "family", "pid", "comm", "exe",
            "owner_status", "concern")} for h in hidden["sockets"]],
        "hidden_concerning": len(hidden["concerning"]),
        "firewall": cen["firewall"],
        "sctp": cen["sctp_note"],
        "coverage": cen["coverage"],
        "note": (f"The kernel holds {len(cen['listeners'])} listening socket(s); "
                 f"the probes saw {len(seen)}. Each one they missed is in "
                 f"missed_by_probe with the reason. {len(hidden['sockets'])} raw "
                 f"or packet socket(s) receive traffic with no port at all and "
                 f"are listed in hidden_sockets."),
    }


def _local_addresses() -> set:
    """
    Every address that belongs to this machine, so a scan of ourselves can be
    recognised as such.

    This matters more than it looks. Windows does not firewall traffic that
    never leaves the host, so scanning your own IP finds every service that is
    BOUND, including ones no other machine can reach. Reporting that as
    exposure is how an open 445 on the tool's own host became a critical
    finding. If we cannot tell the two apart we cannot score them differently.

    THE MACHINE'S OWN NAME IS ONE OF ITS OWN ADDRESSES, 2026-09-25, and it was
    missing. `socket.gethostname()` and everything it resolves to were absent
    from this set, so a scan of the machine by its own name -- which is what a
    person types, and what `localhost` already covers for the loopback case --
    was classified `remote` and scored as reachability from somewhere else.
    Measured on this host: the hostname resolves through /etc/hosts to
    127.0.1.1, an address the psutil walk never reports (it is held by the
    loopback interface, which the walk does list, under 127.0.0.1), so a scan
    by that name recorded origin=remote with a lan/wan severity on every port
    it found. `localhost` was in the set from the start; the machine's actual
    name was not.

    The resolve is inside its own try and its failure is not an error: a host
    whose name does not resolve simply keeps the set it had.
    """
    addrs = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}
    try:
        import psutil
        for iface in psutil.net_if_addrs().values():
            for a in iface:
                if a.family in (socket.AF_INET, getattr(socket, "AF_INET6", None)):
                    addrs.add((a.address or "").split("%")[0])
    except Exception:
        pass
    try:
        hostname = socket.gethostname()
        if hostname:
            addrs.add(hostname)
            addrs.update(socket.gethostbyname_ex(hostname)[2])
    except Exception:
        pass
    return {a for a in addrs if a}


def _normalise_host(host: str) -> str:
    """One spelling per target: lower case, no brackets or zone, mapped v4 unwrapped (PS-25)."""
    h = (host or "").strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        addr = ipaddress.ip_address(h.split("%")[0])
    except ValueError:
        return h
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


def _is_own_address(addr: str, local: set) -> bool:
    """A normalised address that is this machine: a local one, loopback or the any-address."""
    if addr in local:
        return True
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


def _is_self_target(host: str, local: set) -> bool:
    """
    True when the target names this machine under any spelling (PS-25).

    A name not in the local set counts as self only if every address it
    resolves to is this machine's; a name that does not resolve stays remote.
    """
    local = {_normalise_host(a) for a in local}
    h = _normalise_host(host)
    if _is_own_address(h, local):
        return True
    try:
        ipaddress.ip_address(h)
        return False
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(h, None, 0, socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return False
    resolved = {_normalise_host(i[4][0]) for i in infos}
    return bool(resolved) and all(_is_own_address(a, local) for a in resolved)


def _device_keys(target_host: str, scan_origin: str) -> list:
    """
    Every spelling a declaration for this device can be stored under (PS-26).

    The typed name first, then for a self-scan every name and address of this
    machine, and for a remote scan the addresses the name resolves to.
    """
    keys = [target_host, _normalise_host(target_host)]
    if scan_origin == "self":
        keys += [SELF_SCAN_TARGET, "localhost", "::1"] + sorted(_local_addresses())
    else:
        try:
            infos = socket.getaddrinfo(target_host, None, 0, socket.SOCK_STREAM)
            keys += [_normalise_host(i[4][0]) for i in infos]
        except (OSError, UnicodeError):
            pass
    out = []
    for k in keys:
        if k and k not in out:
            out.append(k)
    return out


def _is_public(host: str) -> bool:
    """
    True only for a genuinely internet-routable target.

    HAND-ROLLED NEGATION REPLACED WITH THE PLATFORM'S OWN ANSWER, 2026-09-25,
    AND THEN CORRECTED THE SAME DAY, because the first version of the fix was
    wrong in the other direction.

    The body was `not (is_private or is_loopback or is_link_local or
    is_multicast or is_reserved)`, and each of those five flags answers a
    NARROWER question than the one the note needs. Measured in this host's own
    interpreter (3.12.3):

        the OLD body   _is_public("100.64.0.1")   -> True
                       (carrier-grade NAT: the ISP's other customers, not an
                       address this app may describe as internet-routable)
        is_global      _is_public("100.64.0.1")   -> False   <- the fix

    `is_global` ALONE IS NOT THE WHOLE ANSWER EITHER: on this interpreter it is
    True for MULTICAST, which the old body got right by excluding it.

        is_global alone  _is_public("224.0.0.1")       -> True    <- wrong
        is_global alone  _is_public("239.255.255.250") -> True    <- wrong
        is_global alone  _is_public("ff02::fb")        -> True    <- wrong

    and that is not cosmetic: `public` decides whether every port found on the
    target is scored at its WAN severity, and it is what puts "Target is
    internet-routable." on the row. A multicast GROUP is not a host with
    reachable ports, so the two bodies were each wrong about a different class
    and the answer below is what each one got right.

    WHAT WAS NOT MEASURED, and is written down here because an earlier version
    of this comment claimed it: the RFC 2544 benchmark range (198.18.0.0/15)
    and the documentation ranges are in ipaddress's PRIVATE set on this
    interpreter, so the old body returned False for them and so does this one.
    The claim that the old body called them public does not reproduce here, and
    api/routes.py and core/tool_registry.py both already carry the correct
    statement about that set.

    True means every port found on such a target is scored at its WAN severity
    with "Target is internet-routable." on the row. The platform's single answer
    to "routable on the open internet" is `is_global`, it is version-independent,
    and the same reasoning already moved the model-facing gate onto it --
    core/tool_registry._internal_networks carries a comment explaining why
    is_private was wrong for the LAN question. This is that correction on the
    SCORING side, where the note is written, WITH multicast excluded.
    """
    try:
        addr = ipaddress.ip_address(_normalise_host(host))
    except ValueError:
        return False
    return bool(addr.is_global) and not addr.is_multicast


def classify_port(port: int, scan_origin: str = "remote", public: bool = False,
                  protocol: str = SCAN_PROTOCOL) -> dict:
    """
    Score one open port from what was actually observed.

    scan_origin 'self' means the scanner ran on the target, so the result
    proves the service is bound, not that anything else can reach it. That
    caps severity at low and says why, the alternative is scoring a
    tautology as a critical finding.

    protocol says which pass found it, TODO 117. The note it writes is
    different for each: a UDP reply on 5353 settles the question that a TCP
    silence on 5353 could not, so the caveat has to go away when the answer
    arrives rather than being printed on every row about that port.
    """
    service, category, lan, wan, note = PORT_PROFILES.get(
        port, (f"port-{port}", "unknown", "low", "medium",
               "Not in the profile table. Identify the listening service.")
    )

    udp_kind, udp_reason = udp_caveat(port)
    if protocol == UDP_PROTOCOL:
        # It ANSWERED over UDP. That is the strongest thing this scanner can
        # say about a UDP service, and the TCP caveat does not belong on it.
        note = (f"{note} PROTOCOL NOTE: this answered a UDP probe, so "
                f"something is listening and it replied.")
    elif udp_kind:
        # An OPEN result on a port whose service is mostly UDP is still a real
        # observation, and it is also half the picture. Say so on the row
        # rather than leaving the reader to know it.
        note = (f"{note} PROTOCOL NOTE: this was found over TCP. {udp_reason}")

    if scan_origin == "self":
        return {
            "service_guess": service,
            "category":      category,
            "risk_level":    "low",
            "note":          (f"{note} SCANNED FROM THE HOST ITSELF, so this shows the "
                              f"service is bound, not that it is reachable from anywhere "
                              f"else. Re-scan from another machine to measure exposure."),
        }

    return {
        "service_guess": service,
        "category":      category,
        "risk_level":    wan if public else lan,
        "note":          note + (" Target is internet-routable." if public else ""),
    }


class PortScanner:

    # default_port_set is what scan() uses when the caller names no set.
    #
    # It lives in config.json under port_scan.default_set, not in code,
    # because how loud a scan is allowed to be is a fact about the network it
    # runs on and not a judgement this module gets to make. main.py has passed
    # it since 2026-08-20; this constructor did not accept it, so the module
    # failed to build and try_load turned that into one WARNING line. Same
    # shape as the three bugs of 2026-08-20: caller changed, callee did not,
    # failure silent.
    #
    # An unrecognised name falls back to 'common' and says so. Guessing wrong
    # in the other direction means scanning 65535 ports on every host.
    #
    # `config` ARRIVED 2026-09-25, REGISTER PS-14.
    #
    # `sensors.port_scanner.enabled` was documented in config.json and read by
    # NOTHING, because this sensor is built directly in main.py and pull-only,
    # so there was no loop for the key to gate -- the same shape the autoruns
    # round closed as AR-12. The owner's answer there, and the design taken up
    # here for the same reason, is the second of the two offered: keep the
    # sensor PULL-ONLY and make the switch REFUSE the call, rather than give
    # it a background clock that would write self-scan rows into the owner's evidence
    # store every 600 seconds forever.
    #
    # THE CONSTRUCTION SITE IS PART OF THE FIX: main.py builds this class
    # WITHOUT config today, so a gate written inside the class could not fire
    # however it was written (the AR-12 lesson, measured there). main.py passes
    # `config` now, and the test asserts BOTH halves -- the gate, and the
    # caller that hands it the operator's own config.
    #
    # AND `config` GETS ITS SECOND READER HERE, 2026-09-25.
    #
    # PS-13 option (c) adds `port_scan.tcp_method` -- whether this module is
    # allowed to send SYNs, and what to do when it may not. See
    # tcp_method_setting below; the constructor is only the store.
    def __init__(self, session_id: str, default_port_set: str = "common",
                 config: dict = None):
        self.session_id  = session_id
        self.config      = config or {}
        self._last_result = {}
        # Set when a self-scan's port→process lookup fails, so the payload can
        # say "COULD NOT BE DONE" instead of leaving an absent key that reads
        # as "nothing owns it". See scan().
        self._owner_lookup_error = None
        # The OFF notice is logged once, the same latch every other switched
        # sensor in this tree keeps.
        self._off_logged = False

        name = (default_port_set or "common").strip().lower()
        if name not in PORT_SET_NAMES:
            logger.warning(
                f"Unknown default port set {default_port_set!r}. Using "
                f"'common'. Valid names: {', '.join(PORT_SET_NAMES)}."
            )
            name = "common"
        self.default_port_set = name

    def start(self):
        logger.info("PortScanner ready.")

    # THE CLOCK'S TICK -- ONE PASS, AND THE ANSWER SAID OUT LOUD
    #
    # main.py's loop calls this; the arithmetic of WHEN lives in
    # clock_due()/last_self_scan_at() above so the loop, the status card and
    # the tests ask the same question. This method is the DOING half: it
    # refuses when the operator has switched the sensor off (so OFF stops
    # the clock as well as the call -- a key that stops only one of two
    # paths is the shape AR-12 exists for), runs the SHIPPED scan, and
    # returns a dict that says what happened, including the refusals, which
    # is what main.py logs.
    #
    # IT NEVER RAISES. A clock thread that dies quietly on one bad pass is
    # the failure mode this project has fixed three times (a daemon thread
    # that stops and says nothing). The exception is caught, counted,
    # recorded in _clock_state and returned.
    #
    # THE REFUSAL IS NOT AN ERROR. When the raw-socket method is pinned and
    # cannot run (port_scan.tcp_method = "syn" unelevated), scan() returns a
    # payload with tcp_refused set rather than raising: the UDP half still
    # ran and the row is written, so the tick reports it as a scan that ran
    # with no TCP probe rather than as a failure. That is the pinned key
    # doing its job, and the boot log carries the reason on every pass.
    def clock_tick(self, session_id: str = None, reason: str = "interval",
                   target_host: str = SELF_SCAN_TARGET) -> dict:
        sid = session_id or self.session_id
        started = time.time()

        enabled, which_key = self._enabled()
        if not enabled:
            _clock_state["last_error"] = None
            logger.info(
                f"PortScanner clock: switched OFF in config ({which_key}), so "
                f"NOTHING is scanned and no row is written. An empty port "
                f"answer is this switch, not a quiet machine.")
            return {"ran": False, "reason": f"switched off in config "
                                            f"({which_key})",
                    "skipped": True}

        # A SECOND FAILED TICK IN A ROW IS A FACT AN OPERATOR NEEDS, and the
        # first failure is not -- it is usually a transient (a store being
        # written, a sweep in flight). Same floor and same reasoning as the
        # rest of this tree.
        try:
            result = self.scan(target_host, session_id=sid,
                               port_set=self.default_port_set)
        except Exception as e:                               # noqa: BLE001
            _clock_state["consecutive_failures"] += 1
            _clock_state["last_error"] = f"{type(e).__name__}: {e}"
            logger.error(
                f"PortScanner clock: the pass FAILED "
                f"({_clock_state['consecutive_failures']} in a row): "
                f"{type(e).__name__}: {e}")
            return {"ran": False, "reason": f"{type(e).__name__}: {e}",
                    "duration_ms": int((time.time() - started) * 1000),
                    "consecutive_failures":
                        _clock_state["consecutive_failures"]}

        _clock_state["consecutive_failures"] = 0
        _clock_state["last_error"] = None
        _clock_state["ticks"] += 1
        _clock_state["last_at"] = _now()
        ran_sentence = (
            f"PortScanner clock: {reason}, {result.get('count', 0)} open "
            f"(tcp {result.get('tcp_open', 0)}, udp {result.get('udp_open', 0)}), "
            f"recorded.")
        if result.get("tcp_refused"):
            ran_sentence += (" NO TCP PROBE RAN: port_scan.tcp_method pins the "
                             "SYN scan and no raw socket is available, so the "
                             "UDP half ran alone. The pin is doing its job; "
                             "the reason is on the payload.")
        logger.info(ran_sentence)
        return {"ran": True, "reason": reason,
                "target_host": target_host,
                "open": result.get("count", 0),
                "tcp_open": result.get("tcp_open", 0),
                "tcp_method": result.get("tcp_method"),
                "tcp_refused": bool(result.get("tcp_refused")),
                "udp_open": result.get("udp_open", 0),
                "off_by_config": bool(result.get("off_by_config")),
                "duration_ms": int((time.time() - started) * 1000)}

    # THE SWITCH, READ FROM THE OPERATOR'S CONFIG
    #
    # `config_for()`'s shape, kept here as a function of the config alone so a
    # test can drive all three shapes without building a scanner: an absent
    # key, an absent block and no config at all are all ON. That is what every
    # other sensor in this tree does, and it is why it is spelled out rather
    # than defaulted inline.
    def _enabled(self) -> tuple[bool, str]:
        return scan_enabled(self.config)

    def status(self) -> dict:
        # WHICH TCP METHOD THIS RUN WOULD USE, PS-13 option (c): decided by
        # resolve_tcp_method from the operator's own key plus a raw-socket
        # probe, and published so the Settings card and any health reader can
        # say whether a scan from here would separate a closed port from a
        # filtered one. Same rule as every other status field in this tree:
        # the answer is decided in ONE place and read here.
        _method, _method_reason, _method_problem = resolve_tcp_method(self.config)
        _setting, _setting_key, _ = tcp_method_setting(self.config)
        out = {
            "ready": True,
            "last_scan_host": self._last_result.get("host"),
            # Stated in status so a health reader can see the scope without
            # reading this file. Both protocols since TODO 117, with the UDP
            # limit named rather than implied.
            "protocols": list(PROTOCOLS_TESTED),
            "tcp_method": _method,
            "tcp_method_reason": _method_reason,
            "tcp_method_setting": _setting,
            "tcp_method_setting_key": _setting_key,
            "tcp_methods_available": list(TCP_PROBE_METHODS),
            "syn_timeout": SYN_TIMEOUT,
            "udp_scope": UDP_SCOPE_NOTE,
            # WHICH UDP PORTS ARE ASKED A REAL QUESTION, 2026-09-25. The scope
            # sentence said "a real datagram" for every port in the pass while
            # 18 of the 25 were sent an empty one, so the count and the names
            # are published here rather than left to be inferred from the
            # builder table. Same rule the port-set counts follow: a figure a
            # reader needs is read from the code that owns it.
            "udp_ports_with_request": sorted(UDP_PROBES),
            "udp_ports_empty_datagram": sorted(set(UDP_SCAN_PORTS)
                                               - set(UDP_PROBES)),
        }

        # SWITCHED OFF IS ITS OWN STATE, AND THE PAGE HAS TO SEE IT.
        #
        # PS-14, 2026-09-25, and the shape is the autoruns round's AR-12 and
        # network_scanner's NET-8: `ready: True` kept here paints the row GREEN
        # reading \"running.\" directly beside the note saying the sensor is
        # switched off, because core/settings._module_row resolves
        # running -> ready -> available. The key that carries the truth has to
        # GO rather than go false.
        #
        # AND OFF STOPS THE CLOCK TOO. `clock_running: False` is set here for
        # the same reason: the row must not read green off a thread that is
        # still scanning behind a switch the operator flipped. The clock's
        # loop checks the switch on every tick as well -- this is the status
        # half, that is the doing half, and a switch that stopped only one of
        # the two would be the AR-12 shape one layer down.
        enabled, which_key = self._enabled()
        if not enabled:
            out.pop("ready", None)
            out["available"] = False
            out["off_by_config"] = True
            out["enabled"] = False
            out["clock_running"] = False
            out["reason"] = (
                f"SWITCHED OFF IN CONFIG ({which_key}). No scan runs, the "
                f"background clock is stopped, nothing is recorded, and the "
                f"port list is whatever was last stored. An empty answer here "
                f"is the switch, NOT a quiet machine.")
            out["note"] = (
                f"Port scanning is off by config ({which_key} in config.json). "
                f"run_port_scan REFUSES rather than answering, and the "
                f"background clock does not run either, so a scan asked for "
                f"now happens nowhere and writes nothing.")
            return out

        out["enabled"] = True

        # THE CLOCK, REPORTED AS THE OPERATOR WILL MEET IT.
        #
        # THE KEY THAT HAD NO READER NOW HAS ONE, 2026-09-25, on the owner's
        # answer -- "I want you to create that back ground clock" (PS-14's
        # option (a)). `poll_interval` is the clock's cadence, read by
        # clock_interval_seconds above; this branch publishes the winner's
        # name, the effective number and what the clock is actually doing, so
        # the Settings card, the boot log and the model cannot describe three
        # different clocks.
        #
        # THE TWO STATES THE ROW WAS PAINTING AS ONE are `running: True` here
        # and `running: False` beside it: if this process never armed the
        # clock (a test, a tool calling status() on a bare object), the key
        # must say so rather than let the row read green off a thread that
        # does not exist. The page's verdict comes from the alive flags
        # below; this dict is the fact.
        clock = clock_state()
        _interval, _interval_key = clock_interval_seconds(self.config)
        out["clock_running"] = bool(clock["running"])
        out["clock_interval_seconds"] = _interval
        out["clock_interval_key"] = _interval_key
        out["clock_target"] = SELF_SCAN_TARGET
        out["clock_ticks_this_run"] = clock["ticks"]
        if clock["last_error"]:
            out["clock_last_error"] = clock["last_error"]
        out["clock_note"] = (
            f"The background clock runs a self-scan of {SELF_SCAN_TARGET} "
            f"every {_interval} second(s) ({_interval_key}) and records it, "
            f"so the port record moves without anybody asking. A pass taken "
            f"in the last {_interval} second(s) by anything else, the Scan "
            f"Host button or the model, postpones the next one, because the "
            f"due check reads when this host was last measured rather than a "
            f"counter of its own.")
        return out

    # SCAN

    def _off_refusal(self, which_key: str, target_host: str, port_set: str) -> dict:
        """
        The answer scan() gives when the operator switched it off.

        SHAPED LIKE A REAL PAYLOAD ON PURPOSE -- every key a caller already
        handles is here, so a caller written against the working path cannot
        crash on it -- plus `off_by_config`, which is the one that says this is
        a switch rather than a finding. The shape is the autoruns sensor's
        refusal (adapters.LinuxAutorunMonitor._off_refusal) and the network
        scanner's (tools.network_scanner.NetworkScanner._off_answer), because a
        third shape for the same idea is a third thing to learn.
        """
        if not getattr(self, "_off_logged", False):
            self._off_logged = True
            logger.info(
                f"PortScanner: switched OFF in config ({which_key}), so NOTHING "
                f"is scanned. run_port_scan refuses by name rather than "
                f"returning an empty port list, because an empty list here "
                f"reads as a machine with nothing exposed.")
        return {
            "host": target_host,
            "open_ports": [],
            "count": 0,
            "tcp_open": 0,
            "udp_open": 0,
            "scanned": 0,
            "udp_scanned": 0,
            "port_set": port_set,
            "protocols_tested": list(PROTOCOLS_TESTED),
            # The TCP-method keys are here for the same reason as every other
            # key: a caller written against the working path must not crash on
            # the refusal. They are None rather than a method, because NO
            # method ran -- claiming one would be the PS-13 defect in its
            # original form, a payload describing a scan that did not happen.
            "tcp_method": None,
            "tcp_method_reason": None,
            "tcp_method_problem": None,
            "tcp_refused": False,
            "tcp_syn_before_fallback": None,
            "tcp_closed_by_rst": [],
            "tcp_no_answer": [],
            "tcp_probe_failed": [],
            "udp_closed_by_icmp": [],
            "udp_no_answer": [],
            "udp_filtered_by_icmp": [],
            "udp_probe_failed": [],
            "udp_scope": UDP_SCOPE_NOTE,
            "udp_with_request": 0,
            "udp_empty_datagram": 0,
            "udp_not_tested": [],
            "scan_origin": None,
            "target_public": None,
            "off_by_config": True,
            "scan_scope": (
                "SWITCHED OFF IN CONFIG. No address was resolved, no packet was "
                "sent, no run was recorded and no port was probed. An empty "
                "port list here is the operator's switch, NOT a machine with "
                "nothing exposed."),
            "error": (f"SWITCHED OFF IN CONFIG ({which_key}). No packet was "
                      f"sent and no port was probed."),
            "message": (
                "THE PORT LIST IS EMPTY BECAUSE SCANNING IS OFF, NOT BECAUSE "
                "NOTHING IS LISTENING. It is switched off by "
                f"{which_key}. This is NOT a machine with nothing exposed and "
                f"not a clean scan. The dashboard's own Scan Host button goes "
                f"through this same module, so it refuses too: set `enabled` "
                f"to true in sensors.port_scanner in config.json and restart "
                f"to turn it back on."),
        }

    def scan(self, target_host: str, session_id: str = None,
             port_set: str = None) -> dict:
        sid = session_id or self.session_id
        port_set = (port_set or self.default_port_set or 'common').strip().lower()
        if port_set not in PORT_SET_NAMES:
            port_set = 'common'
        ports = _port_set(port_set)

        # OFF MEANS OFF, AND IT REFUSES BY NAME (PS-14, AR-12's shape).
        #
        # Checked BEFORE anything is read, deliberately: before _local_addresses(),
        # before the target's address family is resolved, before the run row is
        # written. A gate that returns early but had already probed something is
        # the same defect one layer down, so the test asserts the enumerators
        # were not called at all.
        #
        # A STALE ANSWER IS NOT SERVED WHILE OFF. `_last_result` is deliberately
        # NOT consulted here -- a reading from before the switch, handed out as
        # if it were current, is the shape this whole register is written
        # against. The refusal names how to turn it back on instead.
        enabled, which_key = self._enabled()
        if not enabled:
            return self._off_refusal(which_key, target_host, port_set)

        # Establish what this scan can actually prove BEFORE scoring anything.
        local       = _local_addresses()
        scan_origin = "self" if _is_self_target(target_host, local) else "remote"
        public      = _is_public(target_host)

        logger.info(f"Port scan starting: {target_host} (origin={scan_origin}, public={public})")
        if scan_origin == "self":
            logger.info(
                "Scanning this host from itself: results show services BOUND, "
                "not reachable from elsewhere. Severity capped at low."
            )

        # THE UDP SET IS NOT THE TCP SET. TODO 117.
        #
        # The owner's second point on 2026-09-17 was that important ports go
        # unchecked, and this is where that was true: the UDP services worth
        # asking about do not appear just because the requested TCP set
        # happens to contain the number. So the pass covers the fixed UDP
        # service list, plus any port in the requested set that has a UDP
        # fact against it. A full UDP sweep is deliberately not offered, see
        # UDP_SCOPE_NOTE.
        #
        # COMPUTED BEFORE THE RUN IS RECORDED, because the run's own row
        # carries the total probe count now and a count that says 55 for a run
        # that sent 80 is the defect this line moved up to fix. Order matters
        # here: the run is still written before a packet goes out, which is the
        # property that comment is about.
        udp_ports = sorted(set(UDP_SCAN_PORTS)
                           | {p for p in ports if p in UDP_PORT_FACTS})

        # Recorded BEFORE a single packet goes out, and closed in a finally
        # below. A scan that crashes still put traffic on the wire, and the
        # window that explains that traffic has to survive the crash. See
        # TODO 37.2: the model read the reply leg of its own scan as the
        # device attacking this host.
        run_id = me.start_port_scan_run(
            session_id=sid,
            target_host=target_host,
            # WHAT THE RUN PUT ON THE WIRE, not one protocol's worth of it.
            # This was `len(ports)` -- the TCP count -- while the same row's
            # `protocols` column said "tcp,udp" and a further 25 UDP probes went
            # out. Measured: 'common' recorded 55 against 80 probes sent,
            # 'extended' 1062 against 1087, 'all' 65535 against 65560. The
            # column's own reader (memory_engine's port_scan_run reader, which
            # exists so packets near a scan can be attributed to it) has no way
            # to tell a UDP probe from a TCP connect, so the window it draws is
            # short by the UDP half of the pass.
            port_count=len(ports) + len(udp_ports),
            port_set=port_set,
            scan_origin=scan_origin,
            # What this run actually put on the wire. Not a plan, not a
            # capability, what it sent. See the header.
            protocols=",".join(PROTOCOLS_TESTED),
        )

        open_ports = []
        udp = {"open": [], "closed": [], "silent": [], "failed": []}
        tcp = {"open": [], "closed": [], "no_answer": [], "failed": [],
               "method": None, "method_reason": None, "sent": 0,
               "teardowns": 0}
        try:
            tcp = self._run_tcp_scan(target_host, ports, scan_origin, public)
            open_ports = tcp.get("open") or []
            udp = self._run_udp_scan(target_host, udp_ports,
                                     scan_origin, public)
        finally:
            # The SYN half of a fallback is part of this run's traffic (PS-27).
            syn_extra = (tcp.get("syn_before_fallback") or {}).get("sent", 0)
            me.finish_port_scan_run(
                run_id, port_count=(len(ports) + len(udp_ports) + syn_extra
                                    if syn_extra else None))

        # WHEN THE TARGET IS THIS HOST, SAY WHAT HOLDS EACH OPEN PORT.
        #
        # Added 2026-09-25 on the owner's instruction: "agent now has to have
        # access to ports and processes finding in this machine to be able to
        # report which port relates to which process". A scan of this machine
        # produces a list of open ports and has never been able to say WHAT
        # opened them, which left every self-scan result one question short.
        #
        # ONLY FOR A SELF-SCAN, and that is not a limitation -- it is the only
        # case where the answer exists. A port open on another device is held
        # by a process on THAT device, and this app has no way to read it. The
        # scan_origin test above is already the app's own line between those two
        # cases, and this reuses it rather than inventing a second test.
        #
        # The correlation is tools/port_owner's, NOT a second implementation:
        # its row for a port is looked up and attached, and its own coverage is
        # carried up so a reader can see how many of these were readable. Where
        # no row is found the entry simply has no `owner` key, which reads as
        # "this app did not match it" rather than as "nothing owns it".
        #
        # THE ERROR IS CLEARED AT THE START OF EVERY LOOKUP, 2026-09-25. It was
        # assigned only on failure, so ONE broken sweep marked every self-scan
        # for the life of the process as "COULD NOT BE DONE" -- including scans
        # whose lookup had just worked. Measured by driving the shipped scanner
        # with port_owner.query_listeners broken on the first call and healthy
        # on the second: both payloads carried the failure sentence, and the
        # second one's own owner blocks were attached and correct underneath it.
        # A stale error is the same shape as the stale `last_sweep_at` this
        # module's sibling recorded, and it lies in the reassuring-to-alarming
        # direction, which is the one an operator acts on.
        self._owner_lookup_error = None
        if scan_origin == "self":
            try:
                from tools import port_owner
                holders = {r.get("local_port"): r
                           for r in (port_owner.query_listeners(limit=1000)
                                     .get("listeners") or [])}
                for entry in list(open_ports) + list(udp.get("open") or []):
                    row = holders.get(entry.get("port"))
                    if row:
                        entry["owner"] = {
                            "pid": row.get("pid"),
                            "comm": row.get("comm"),
                            "exe": row.get("exe"),
                            "status": row.get("owner_status"),
                        }
            except Exception as e:                       # noqa: BLE001
                # A self-scan that cannot name its holders is still a valid
                # scan. The absence is REPORTED on the payload rather than
                # silent, because "no owner key" and "the lookup failed" look
                # identical to a reader otherwise.
                logger.warning(f"port_scanner: could not attach port owners: "
                               f"{e}")
                self._owner_lookup_error = f"{type(e).__name__}: {e}"

        # The kernel's view first, so open ports carry their exposure when
        # _record stores them (PS-21).
        view = None
        if scan_origin == "self":
            view = kernel_view(target_host, ports, udp_ports, open_ports,
                               udp.get("open") or [], port_set)
        # ports and port_set are PASSED, not reached for. See _record.
        result = self._record(target_host, sid, open_ports, scan_origin,
                              ports=ports, port_set=port_set, public=public,
                              udp=udp, udp_ports=udp_ports, tcp=tcp)
        if view is not None:
            result["kernel_view"] = view
        if scan_origin == "self":
            if getattr(self, "_owner_lookup_error", None):
                result["owner_lookup"] = (
                    f"COULD NOT BE DONE: {self._owner_lookup_error}. The open "
                    f"ports below are real; which process holds them is "
                    f"UNKNOWN for this scan, not empty.")
            else:
                result["owner_lookup"] = (
                    "Each open port on this host carries an `owner` block "
                    "where this app could match it. A port with no owner block "
                    "was not matched. `status: unreadable_as_user` means the "
                    "holder is another account's process and an elevated run "
                    "resolves it.")
        return result

    def _run_scan(self, target_host: str, ports, scan_origin: str,
                  public: bool) -> list:
        open_ports = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = {
                ex.submit(self._check_port, target_host, port): port
                for port in ports
            }
            for future in as_completed(futures):
                port   = futures[future]
                if future.result():
                    entry = classify_port(port, scan_origin, public)
                    entry["port"]  = port
                    entry["state"] = "open"
                    # WHICH PROTOCOL. Known at probe time since the first
                    # commit, written down since 2026-09-15. An open port
                    # without this is a claim the scanner cannot support.
                    entry["protocol"] = SCAN_PROTOCOL
                    # WHICH DEVICE. Added 2026-09-04 with TODO 39.5.
                    #
                    # This entry becomes the finding's raw_data, and the host
                    # appeared nowhere in it. The finding carries entity_type
                    # 'port' and entity_value '8888', so the only record of
                    # WHICH machine had 8888 open was the sentence in the
                    # title. Anything wanting to act on "this port on this
                    # device" had to parse prose, and 39.5 is exactly that
                    # job. A finding should not need its own title read back
                    # to it to say what it is about.
                    entry["host"]  = target_host
                    # WHICH METHOD FOUND IT. This pass IS the connect test,
                    # and saying so on the row is what keeps a payload from
                    # describing a SYN scan it did not run.
                    entry["tcp_method"] = CONNECT_METHOD
                    open_ports.append(entry)

        open_ports.sort(key=lambda x: x["port"])
        return open_ports

    def _run_syn_scan(self, target_host: str, ports, scan_origin: str,
                      public: bool, method_reason: str = None) -> dict:
        """
        THE RAW SYN PASS. Same shape as the UDP pass: open rows plus the lists
        that keep the other answers apart.

        Returns {"open", "closed", "no_answer", "failed", "method",
        "method_reason", "sent", "teardowns"}.

        EVERY RESOLVED ADDRESS IS WALKED, like the connect pass, because a
        name can resolve to several and a live port behind the resolver's
        second answer is still open. An address the raw socket cannot reach
        (a v6 target with only a v4 socket open) is reported as probe_failed
        WITH THE REASON rather than quietly re-probed by the other method --
        one run speaks one method, and the payload says which.
        """
        try:
            infos = socket.getaddrinfo(target_host, None, 0, socket.SOCK_STREAM)
        except socket.gaierror as e:
            return {"open": [], "closed": [], "no_answer": [], "failed": [],
                    "method": SYN_METHOD, "method_reason": method_reason,
                    "sent": 0, "teardowns": 0,
                    "error": (f"the target {target_host!r} could not be "
                              f"resolved: {e}")}
        if not infos:
            return {"open": [], "closed": [], "no_answer": [], "failed": [],
                    "method": SYN_METHOD, "method_reason": method_reason,
                    "sent": 0, "teardowns": 0,
                    "error": f"the target {target_host!r} resolved to nothing"}

        answers, failed, sent, teardowns = {}, [], 0, 0
        unreachable_families = set()

        # THE TARGETS ARE NORMALISED ONCE and used for both the probe and the
        # answer lookup. An IPv4-mapped v6 address (`::ffff:a.b.c.d`) is
        # unwrapped to v4 and probed over v4 -- the same reading the UDP pass
        # makes -- so the key the answer arrives under is the address that was
        # actually asked, not the shape the resolver happened to return.
        targets = []
        for family, _socktype, _proto, _canon, sockaddr in infos:
            addr = sockaddr[0]
            if (family == socket.AF_INET6 and addr.lower().startswith("::ffff:")
                    and "." in addr):
                family, addr = socket.AF_INET, addr[7:]
            if (family, addr) not in targets:
                targets.append((family, addr))
        if not targets:
            return {"open": [], "closed": [], "no_answer": [], "failed": [],
                    "method": SYN_METHOD, "method_reason": method_reason,
                    "sent": 0, "teardowns": 0,
                    "error": f"the target {target_host!r} resolved to nothing "
                             f"a SYN could be sent to"}

        # Addresses the pass can reach, and the source each is reached from.
        # The source is asked of the routing table per address, because the
        # checksum is computed over whichever one the kernel would use.
        probes = []
        needed = sorted({family for family, _addr in targets})
        with SynScanEngine(families=needed) as engine:
            for family, addr in targets:
                if not engine.family_available(family):
                    why = engine.refusal_reason(family)
                    unreachable_families.add((family, why))
                    for port in ports:
                        failed.append({"port": port, "probed_address": addr,
                                       "error": why})
                    continue
                src_ip, err = source_address_for(addr, family)
                if err:
                    unreachable_families.add((family, err))
                    for port in ports:
                        failed.append({"port": port, "probed_address": addr,
                                       "error": err})
                    continue
                probes.extend((family, src_ip, addr, port) for port in ports)

        # IN BATCHES, each with its own engine. One engine holds one source
        # port per probe for the whole pass, so the 'all' set ran out of
        # source ports after 20,001 SYNs and fell back mid-run (PS-18).
        answered = {}
        try:
            for start in range(0, len(probes), SYN_BATCH_PROBES):
                batch = probes[start:start + SYN_BATCH_PROBES]
                with SynScanEngine(
                        families=sorted({p[0] for p in batch})) as engine:
                    try:
                        for n, (family, src_ip, addr, port) in enumerate(batch, 1):
                            if n % SYN_PACE_EVERY == 0:
                                time.sleep(SYN_PACE_SECONDS)
                            ok, send_err = engine.probe(family, src_ip, addr, port)
                            if ok:
                                sent += 1
                            else:
                                failed.append({"port": port,
                                               "probed_address": addr,
                                               "error": send_err})
                    finally:
                        # Answers to SYNs already sent are kept even if the batch dies.
                        answered.update(engine.finish())
                        teardowns += engine.teardowns
        except (PermissionError, OSError, RuntimeError) as e:
            if not sent:
                raise
            raise SynPassAborted(e, {
                "sent": sent,
                "teardowns": teardowns,
                "open": sorted({p for (_a, p), st in answered.items()
                                if st == "open"}),
                "closed": sorted({p for (_a, p), st in answered.items()
                                  if st == "closed"}),
                "error": f"{type(e).__name__}: {e}",
            }) from e

        open_ports, closed, silent = [], [], []
        for port in ports:
            verdict, where = "no_answer", None
            for _family, addr in targets:
                state = answered.get((addr, port))
                if state == "open":
                    verdict, where = "open", addr
                    break
                if state == "closed" and verdict != "closed":
                    # CLOSED IS KEPT BUT AN OPEN ON ANOTHER ADDRESS WINS --
                    # every address here is the same host, so one of them
                    # saying "listening" outranks another saying "refused".
                    verdict, where = "closed", addr
            if verdict == "open":
                entry = classify_port(port, scan_origin, public)
                entry["port"] = port
                entry["state"] = "open"
                entry["protocol"] = SCAN_PROTOCOL
                entry["host"] = target_host
                # WHICH METHOD, AND WHICH ADDRESS ANSWERED. The connect pass
                # never needed the address because a completed handshake was
                # its own proof; a SYN-ACK is a frame, and a frame came from
                # an address.
                entry["tcp_method"] = SYN_METHOD
                entry["probed_address"] = where
                open_ports.append(entry)
            elif verdict == "closed":
                closed.append({"port": port, "probed_address": where,
                               "answered_by": "RST acknowledging the SYN"})
            else:
                silent.append({"port": port, "probed_address": None,
                               "error": "no SYN-ACK and no RST within "
                                        "SYN_TIMEOUT"})

        open_ports.sort(key=lambda x: x["port"])
        return {
            "open": open_ports,
            "closed": sorted(closed, key=lambda x: x["port"]),
            "no_answer": sorted(silent, key=lambda x: x["port"]),
            "failed": sorted(failed, key=lambda x: x["port"]),
            "method": SYN_METHOD,
            "method_reason": method_reason,
            "sent": sent,
            "teardowns": teardowns,
            "unreachable_families": sorted(
                f"{'v6' if fam == socket.AF_INET6 else 'v4'}: {why}"
                for fam, why in unreachable_families),
        }

    def _run_tcp_scan(self, target_host: str, ports, scan_origin: str,
                      public: bool) -> dict:
        """
        THE TCP PASS: SYN where a raw socket is available, connect where it is
        not, and THE METHOD IS NAMED IN THE RESULT either way.

        This dispatcher exists because the module now has two TCP methods and
        a payload that did not say which one ran would be the original PS-13
        defect (a description of code other than the code that ran) moved from
        the privilege row onto every scan result. `resolve_tcp_method` decides
        -- the operator's `port_scan.tcp_method` key and the raw-socket probe
        together -- and this records what it decided.
        """
        method, reason, problem = resolve_tcp_method(self.config)
        partial = None
        if method is None:
            # THE OPERATOR PINNED THE SYN SCAN AND IT CANNOT RUN HERE. No
            # connect test is substituted: "syn" was asked for by name, and
            # quietly running a different probe is exactly the defect this
            # whole entry is about. The refusal travels on the payload the
            # same way the switched-off refusal does.
            return {"open": [], "closed": [], "no_answer": [], "failed": [],
                    "method": None, "method_reason": reason,
                    "method_problem": problem, "sent": 0, "teardowns": 0,
                    "tcp_refused": True}
        if method == SYN_METHOD:
            try:
                result = self._run_syn_scan(target_host, ports, scan_origin,
                                            public, reason)
                result["method_problem"] = problem
                return result
            except (PermissionError, OSError, RuntimeError) as e:
                # The probe said yes and the pass could not open its socket
                # anyway, or ran out of source ports. With "auto" the
                # fallback is the right direction -- a scan that can still
                # find open ports beats one that refuses -- but the reason
                # travels, because the two methods do not prove the same
                # things. With "syn" pinned there is no fallback at all.
                setting, _which, _problem = tcp_method_setting(self.config)
                # What the SYN half already put on the wire, if anything (PS-27).
                partial = getattr(e, "partial", None)
                syn_sent = partial["sent"] if partial else 0
                if partial:
                    syn_said = (f"The SYN pass had already sent {syn_sent} "
                                f"SYNs; they and their answers are under "
                                f"syn_before_fallback.")
                else:
                    syn_said = "No SYN was sent."
                if setting == SYN_METHOD:
                    return {"open": [], "closed": [], "no_answer": [],
                            "failed": [], "method": None,
                            "method_reason": (
                                f"TCP PROBES REFUSED: port_scan.tcp_method "
                                f"pins the SYN scan and the pass could not "
                                f"run ({e}). {syn_said} No connect test was "
                                f"substituted."),
                            "method_problem": problem, "sent": syn_sent,
                            "teardowns": partial["teardowns"] if partial else 0,
                            "tcp_refused": True,
                            "syn_before_fallback": partial}
                reason = (f"FELL BACK TO THE CONNECT TEST MID-RUN: the SYN "
                          f"pass could not run ({e}). {syn_said} Nothing "
                          f"about the connect results separates a closed "
                          f"port from a filtered one.")
        self._connect_lock = threading.Lock()
        self._connect_answers = {}
        try:
            open_ports = self._run_scan(target_host, ports, scan_origin, public)
            answers = self._connect_answers
        finally:
            self._connect_answers = None
        closed, silent, failed = [], [], []
        for port in ports:
            state, addr, err = answers.get((target_host, port),
                                           (None, None, None))
            if state == "closed":
                closed.append({"port": port, "probed_address": addr,
                               "answered_by": "connection refused, which is "
                                              "the target's RST"})
            elif state == "no_answer":
                silent.append({"port": port, "probed_address": addr,
                               "error": "the connect timed out after "
                                        "SCAN_TIMEOUT"})
            elif state == "failed":
                failed.append({"port": port, "probed_address": addr,
                               "error": err})
        return {"open": open_ports, "closed": closed, "no_answer": silent,
                "failed": failed, "method": CONNECT_METHOD,
                "method_reason": reason, "method_problem": problem,
                "sent": len(ports) + (partial["sent"] if partial else 0),
                "teardowns": partial["teardowns"] if partial else 0,
                "tcp_refused": False, "syn_before_fallback": partial}

    def _record(self, target_host: str, sid: str, open_ports: list,
                scan_origin: str, ports: list, port_set: str,
                public: bool, udp: dict = None,
                udp_ports: list = None, tcp: dict = None) -> dict:
        """
        FIXED 2026-09-03, and this one had teeth.

        The scope paragraph below reads `port_set` and `ports`, and neither
        was a parameter or an attribute. They are locals of scan(), so every
        call landed on `NameError: name 'port_set' is not defined`, which
        execute_tool turned into "Execution error" and handed back as a
        string. The port scanner was completely dead, from the dashboard and
        from the model, and it looked like a tool answering rather than a
        tool crashing.

        Nothing caught it. The port tests exercise _port_set, the severity
        table and the self/remote distinction, all of which are fine; none of
        them ran an actual scan end to end, so the one line joining the parts
        was never executed. Worth remembering the next time a suite is green:
        a passing test says the tested path works, and nothing at all about
        the path nobody wrote a test for.

        `public` was the same mistake in the same method, one line further
        down, and it only surfaced after the first two were fixed.

        All three are required arguments rather than defaulted ones on
        purpose. A default would let this break again silently, with the
        scope line quietly describing the wrong port set.
        """
        floor = SEVERITY_ORDER.index(FINDING_FLOOR)
        udp = udp or {"open": [], "closed": [], "silent": [], "failed": []}
        udp_ports = udp_ports or []
        udp_open = udp.get("open") or []

        # WHICH TCP METHOD RAN, TAKEN FROM THE PASS ITSELF AND NEVER
        # RE-DECIDED HERE. PS-13 option (c): the module has two TCP methods
        # now, and a payload that does not name the one that ran is the
        # original defect -- a row describing code other than the code that
        # executed -- moved onto every scan result. The pass decides (see
        # _run_tcp_scan); this records.
        tcp = tcp or {"open": list(open_ports), "closed": [], "no_answer": [],
                      "failed": [], "method": None, "method_reason": None,
                      "sent": len(open_ports), "teardowns": 0}
        tcp_method = tcp.get("method")
        tcp_refused = bool(tcp.get("tcp_refused"))
        tcp_method_problem = tcp.get("method_problem")
        tcp_closed = tcp.get("closed") or []
        tcp_no_answer = tcp.get("no_answer") or []
        tcp_failed = tcp.get("failed") or []

        # HOW MANY UDP PORTS GET A REAL REQUEST, counted rather than claimed.
        # The scope sentence below used to say every UDP port was asked "with a
        # real datagram" while 18 of the 25 got an empty one. Both numbers are
        # computed here from the probe table so neither can drift from the
        # payloads, and the sentence the model reads carries them.
        real_udp_probes = sum(1 for p in udp_ports if p in UDP_PROBES)
        empty_udp_probes = len(udp_ports) - real_udp_probes

        # ONE LOOP FOR BOTH PASSES, TODO 117. A UDP service that answered is
        # an open port on this device and gets the same treatment as a TCP
        # one: the same expected-port check, the same finding floor, its own
        # row. The protocol travels on the entry, so nothing downstream has to
        # know which pass it came from except where it changes the sentence.
        all_open = list(open_ports) + list(udp_open)
        device_keys = _device_keys(target_host, scan_origin) if all_open else []

        for entry in all_open:
            port    = entry["port"]
            risk    = entry["risk_level"]
            service = entry["service_guess"]

            # Only findings at or above the floor. Every open port used to
            # become a finding, so scanning a Windows box manufactured three
            # alerts about its own default configuration, the noise that
            # makes a real one easy to miss.
            # THE OWNER SAID THIS PORT IS NORMAL HERE. Schema v24, TODO 39.
            #
            # Naming a device says nothing about which of its ports belong to
            # it, so an identified Echo kept raising a high finding on 8888
            # and the tool asked about it three sessions running. This is the
            # owner answering that, once, for one port on one device.
            #
            # It is checked AFTER the port is recorded as open and BEFORE the
            # finding, which is the whole distinction: the observation stands,
            # the alarm does not. Any other port on this device raises
            # normally, and so does this port on any other device.
            # Under any spelling of the same device, not just the typed one (PS-26).
            expected = None
            for key in device_keys:
                expected = me.is_port_expected(key, port)
                if expected:
                    break
            if expected:
                logger.info(
                    f"{target_host}:{port} is open and declared expected by "
                    f"{expected.get('declared_by')} on "
                    f"{expected.get('declared_at')}. No finding raised. "
                    f"Reason given: {expected.get('reason')}")
                entry["expected"] = expected

            # OUR OWN SCAN NO LONGER RAISES A FINDING. TODO 38.5, decided
            # by the owner 2026-09-06 after it was written up and left open on
            # 09-04.
            #
            # The question was whether an active scan should create findings
            # at all, and the answer is no. A finding here is this tool
            # reporting a condition it went looking for, landing in the review
            # queue beside things that came from WATCHING. It got surfaced to
            # the owner as an open high severity finding minutes after the
            # tool generated it, and the queue gave nobody a way to tell the
            # difference. Section 38 already carries the same lesson about
            # self-induced packets.
            #
            # NOTHING IS LOST. Every open port is still recorded in
            # port_scan_results with its risk and its note, the Ports tab
            # still shows it, and query_port_scan still answers about it. What
            # goes away is the alarm, not the observation.
            #
            # WHAT RAISES INSTEAD, per the same decision: an unidentified
            # DEVICE. network_scanner already does that, and it ends in the
            # user being asked, then either identify_device or block_device.
            # That is the queue this belongs in.
            if not expected and SEVERITY_ORDER.index(risk) >= floor:
                logger.info(
                    f"{target_host}:{port} open, {risk} risk, recorded but NOT "
                    f"raised as a finding: this was an active scan, see TODO "
                    f"38.5. It is in port_scan_results and on the Ports tab.")
                entry["finding_raised"] = False
            # Was wrapped in `try: ... except Exception: pass` around a
            # function-level import of a function that did not exist. Every
            # scan raised ImportError here and threw it away, so the Ports
            # tab was fed by a table nothing ever wrote to. Findings still
            # saved, which is why scans looked half-working rather than
            # broken. Logged now instead of swallowed.
            try:
                me.save_port_scan_result(
                    session_id=sid,
                    target_host=target_host,
                    port=port,
                    state="open",
                    service_guess=service,
                    risk_level=risk,
                    # On the TCP pass banner stays NULL, because nothing was
                    # read off the wire: _check_port connects and closes
                    # without receiving a byte, and writing the profile note
                    # here made annotation look like something the service
                    # said about itself.
                    #
                    # On the UDP pass there IS a reply, so the banner carries
                    # its size and a hex head. Not decoded text: those bytes
                    # come from whatever is listening and are exactly the kind
                    # of attacker-controllable string this project fences
                    # everywhere else.
                    banner=entry.get("banner"),
                    service_note=(
                        entry["note"] if not entry.get("expected") else
                        f"DECLARED EXPECTED on this device by "
                        f"{entry['expected'].get('declared_by')} on "
                        f"{entry['expected'].get('declared_at')}. Reason: "
                        f"{entry['expected'].get('reason')}. No finding is "
                        f"raised for it. The port is still recorded here and "
                        f"a change to it is still visible.\n\n"
                        + entry["note"]
                    ),
                    scan_origin=scan_origin,
                    protocol=entry.get("protocol", SCAN_PROTOCOL),
                )
            except Exception as e:
                logger.error(f"Failed to persist port {port} for {target_host}: {e}")

        self._last_result = {"host": target_host, "open_ports": all_open}
        logger.info(
            "Port scan complete: %s, %d open TCP, %d answering UDP, %d UDP "
            "closed by ICMP, %d UDP silent",
            target_host, len(open_ports), len(udp_open),
            len(udp.get("closed") or []), len(udp.get("silent") or []))

        # WHAT A SILENCE ON THIS RUN IS NOT ALLOWED TO MEAN.
        #
        # Built from the ports actually scanned, minus the ones that answered,
        # keeping only those with a UDP caveat. Those are exactly the ports
        # where a reader would otherwise take "not in the open list" as "not
        # running". Ports that DID answer are left out: they are in the open
        # list with protocol tcp on them and there is nothing ambiguous left.
        # NOW IT MEANS SOMETHING NARROWER, because UDP really is probed.
        # A port keeps this caveat only when the UDP pass did not cover it,
        # which after TODO 117 is a port with a UDP fact that is somehow not
        # in the UDP set. That should be empty, and it is computed rather than
        # assumed empty so that adding a UDP fact without adding the port to
        # the scan set shows up here instead of going quiet.
        answered = {e["port"] for e in open_ports} | {e["port"] for e in udp_open}
        udp_covered = set(udp_ports)
        udp_not_tested = []
        for p in sorted(set(ports) - answered):
            kind, reason = udp_caveat(p)
            if not kind or p in udp_covered:
                continue
            service = PORT_PROFILES.get(p, (f"port-{p}",))[0]
            udp_not_tested.append({
                "port":     p,
                "service":  service,
                "kind":     kind,
                "protocol_not_tested": "udp",
                "reason":   reason,
            })

        # A host with nothing listening is a real result, not a failure. The
        # UI cannot tell "scan found nothing" from "scan never ran" unless
        # this is reported explicitly, and a clean host is the common case
        # on a home LAN, so that ambiguity looked like a broken button.
        if open_ports or udp_open:
            base = (f"{len(open_ports)} open TCP and {len(udp_open)} answering "
                    f"UDP on {target_host}")
        else:
            base = (f"No open TCP ports and no UDP replies from {target_host} "
                    f"({len(ports)} ports over TCP, {len(udp_ports)} over UDP)")

        # Said in the answer, not only in the log, because the model is the
        # one that has to not read silence as safety.
        base += (". A scan raises no findings, on purpose: this is a thing "
                 "we went looking for, not a thing we observed. The open "
                 "ports are recorded and readable with query_port_scan. If "
                 "this device is one nobody can account for, that is the "
                 "finding, and it is a question for the user")

        if scan_origin == "self":
            base += (", scanned from this host, so these are services BOUND "
                     "locally, not proof they are reachable from other machines")

        # WHAT WAS LOOKED AT, NOT JUST WHAT WAS FOUND.
        #
        # This list is server and administrative services: SSH, SMB, RDP,
        # databases, web. That is the right list for a host you administer and
        # the wrong one for most things on a home network.
        #
        # A games console listens on 987 and 9295 to 9302. A printer answers on
        # 631. A phone and a smart speaker mostly listen on nothing at all.
        # None of that is in this list, so scanning any of them returns zero,
        # and zero reads as "nothing exposed" when it means "we did not look
        # where this kind of device lives".
        #
        # That misread happened. A console that had been powered on for two
        # hours came back with zero open ports, and the absence was explained
        # as rest mode. It was not rest mode. It was the port list.
        #
        # So the result says what it covered. The scope travels with the
        # number, and a zero can no longer be quoted on its own.
        if port_set == "all":
            covered = "every port from 1 to 65535"
        elif port_set == "extended":
            covered = ("every well-known port from 1 to 1024, plus every port "
                       "in the profile table including console, printer and "
                       "media device ports")
        else:
            covered = ("the profiled set: server and admin services, plus "
                       "console, printer and media device ports")

        # THE PROTOCOL SENTENCE IS NOT OPTIONAL AND IT GOES FIRST.
        #
        # The port set caveat below was written because a zero on 'common' was
        # read as "nothing exposed". This is the same mistake one level down:
        # a zero on TCP read as "nothing listening". Both belong in the same
        # paragraph, because both are the scan's shape being quoted as the
        # device's state.
        # TWO PASSES, AND EACH ONE'S SILENCE MEANS SOMETHING DIFFERENT.
        #
        # This paragraph used to open with "TCP ONLY", which was honest and is
        # no longer true. What has NOT changed is why it goes first: a zero
        # here is the scan's shape being quoted as the device's state, and the
        # reader has to have the shape in the same breath as the number.
        #
        # THE TCP METHOD IS PART OF THAT SHAPE, PS-13 option (c). How much the
        # TCP half proves depends on which method ran:
        #
        #   syn      a completed SYN-ACK exchange, and the pass can separate
        #            CLOSED from FILTERED because it reads the answers.
        #   connect  a bare False covers refused, filtered, timed out and the
        #            wrong protocol at once. It cannot make that separation,
        #            and an unelevated run using it must SAY so rather than
        #            reading as the same scan with a luckier network.
        if tcp_refused:
            # THE OPERATOR PINNED THE SYN SCAN AND IT COULD NOT RUN. No TCP
            # port was probed and none is reported, and that is a REFUSAL --
            # the same shape as the switched-off payload, so a caller cannot
            # read an empty TCP list as a machine with nothing open.
            method_sentence = (
                f"NO TCP PROBE RAN ON THIS SCAN. {tcp.get('method_reason')} "
                f"The empty TCP result is the pinned method, NOT a machine "
                f"with nothing listening. The UDP pass below is unaffected: "
                f"it needs no raw socket. ")
        elif tcp_method == SYN_METHOD:
            method_sentence = (
                f"THE TCP PASS USED A RAW SYN SCAN, which sends one SYN per "
                f"port and reads the answers: a SYN-ACK is OPEN, an RST is "
                f"CLOSED, and silence is NEITHER. {len(tcp_closed)} port(s) "
                f"answered with an RST and are named in tcp_closed_by_rst; "
                f"{len(tcp_no_answer)} said nothing at all and are named in "
                f"tcp_no_answer, which is NOT closed. Every SYN-ACK was "
                f"answered with an RST so no half-open connection is left on "
                f"the target. ")
        elif tcp_method == CONNECT_METHOD:
            method_sentence = (
                f"THE TCP PASS USED A CONNECT TEST, NOT A SYN SCAN. A refused "
                f"connection is the target's RST, so {len(tcp_closed)} "
                f"port(s) are named in tcp_closed_by_rst as CLOSED; "
                f"{len(tcp_no_answer)} timed out and are named in "
                f"tcp_no_answer, which is NOT closed. Unlike a SYN scan, every "
                f"open port here saw a completed handshake, which the service "
                f"may log. A raw SYN scan needs CAP_NET_RAW or root. ")
        else:
            method_sentence = (
                "THE TCP METHOD WAS NOT RECORDED for this run, so nothing "
                "here says whether an RST would have separated a closed port "
                "from a filtered one. ")

        protocol_scope = (
            method_sentence
            + f"TWO PROTOCOLS. {len(ports)} ports were tested over TCP, and "
            f"{len(udp_ports)} over UDP. Of the UDP set, "
            f"{real_udp_probes} carry a real request built for that service, "
            f"and {empty_udp_probes} were sent an EMPTY datagram: for those, "
            f"only an ICMP unreachable can settle anything, because silence in "
            f"reply to an empty packet is what a working service does. "
            f"A TCP port missing from the open list is not proven closed: it "
            f"either refused or ignored the probe, and the method above says "
            f"which of those a run can tell apart. "
            f"A UDP port is different and the difference matters: "
            f"only a reply proves something is listening, and only an ICMP "
            f"unreachable proves nothing is. UDP silence is neither, and it is "
            f"reported separately as udp_no_answer rather than folded into "
            f"either, with the probe each port was asked by. {UDP_SCOPE_NOTE} "
        )

        scope = (
            protocol_scope
            + f"The TCP set ({port_set}) was: {covered}. "
            + ("" if port_set == "all" else
               "Ports outside that set were NOT checked, so zero open here "
               "means nothing was found AMONG THE PORTS LOOKED AT. Re-run with "
               "port_set='extended' or 'all' before concluding a device exposes "
               "nothing. ")
            + "A device answering on its own expected ports is that device "
              "working correctly, not a finding."
        )

        if udp_not_tested:
            named = ", ".join(
                f"{u['port']} {u['service']}" for u in udp_not_tested)
            scope += (
                f" NAMED PORTS THAT WERE NOT ACTUALLY TESTED: {named}. Each is "
                f"a UDP service, so the TCP probe that came back quiet was "
                f"never the right question. Do not report any of these as "
                f"closed or absent. See udp_not_tested for the reason on each. "
                f"This list only covers profiled ports; a wider port set "
                f"sweeps plenty of other UDP services nobody here has "
                f"profiled, and the same caveat covers them silently.")

        silent = udp.get("silent") or []
        if silent:
            named = ", ".join(
                f"{s['port']} {s['service']} ({s.get('probe') or 'empty datagram'})"
                for s in silent[:12])
            addresses = sorted({s.get("probed_address") for s in silent
                                if s.get("probed_address")})
            scope += (
                f" UDP PORTS THAT DID NOT ANSWER: {named}"
                f"{' and more' if len(silent) > 12 else ''}. Those are NOT "
                f"closed. Each was sent the probe named beside it, to "
                f"{', '.join(addresses) if addresses else 'the target address'}"
                f", and said nothing, which on UDP means listening and quiet, "
                f"filtered, or a service that wanted a different payload. A "
                f"probe reading 'empty datagram' was not a question that "
                f"service answers, so silence on those settles nothing short "
                f"of an ICMP unreachable; a named probe IS a real request and "
                f"its silence is stronger evidence, still not proof. Do not "
                f"report any of them as absent.")

        return {
            "host":          target_host,
            # Both passes, each row carrying its own protocol. A reader that
            # wants one protocol filters on it; a reader that wants "what is
            # open on this device" gets the true answer by default, which it
            # did not before today.
            "open_ports":    all_open,
            "count":         len(all_open),
            "tcp_open":      len(open_ports),
            "udp_open":      len(udp_open),
            "scanned":       len(ports),
            "udp_scanned":   len(udp_ports),
            "port_set":      port_set,
            "protocols_tested": list(PROTOCOLS_TESTED),
            # WHICH TCP METHOD RAN. PS-13 OPTION (c), 2026-09-25.
            #
            # The module keeps two TCP methods now -- a raw SYN pass where
            # CAP_NET_RAW or root is available, and the connect test where it
            # is not -- and the difference is what a reader is allowed to
            # conclude. So it travels on every payload under a name, with the
            # reason, rather than being left to the reader to infer from a
            # severity or a sentence.
            "tcp_method":        tcp_method,
            "tcp_method_reason": tcp.get("method_reason"),
            # A KEY THAT COULD NOT BE READ IS ITS OWN FACT (the rule PS-15
            # paid for): "the operator's tcp_method key is nonsense" and
            # "the method is auto" are different sentences, and a reader who
            # set the key needs to see the first one.
            "tcp_method_problem": tcp_method_problem,
            "tcp_refused":        tcp_refused,
            # A SYN half that ran before a fallback, or None (PS-27).
            "tcp_syn_before_fallback": tcp.get("syn_before_fallback"),
            # THE THREE TCP ANSWERS, KEPT APART, exactly as the UDP pass keeps
            # its own. Only a SYN pass can fill the first two; a connect run
            # reports them empty and says so in the scope sentence, because
            # "no RSTs were seen" and "this method cannot see an RST" are
            # different sentences and a reader must never get the first one
            # when the second is true.
            "tcp_closed_by_rst": tcp_closed,
            "tcp_no_answer":     tcp_no_answer,
            "tcp_probe_failed":  tcp_failed,
            # The three UDP answers, kept apart. Summing any two of them is
            # the thing this module exists to refuse.
            "udp_closed_by_icmp": udp.get("closed") or [],
            "udp_no_answer":      silent,
            # An ICMP unreachable other than port unreachable: a host or
            # firewall on the path refused the probe. Not open, not closed.
            "udp_filtered_by_icmp": udp.get("filtered") or [],
            "udp_probe_failed":   udp.get("failed") or [],
            "udp_scope":          UDP_SCOPE_NOTE,
            # What the pass ACTUALLY sent, so a reader can tell a real request
            # from an empty packet without reading this module. Counted here;
            # real + empty == udp_scanned.
            "udp_with_request":   real_udp_probes,
            "udp_empty_datagram": empty_udp_probes,
            # Ports with a UDP caveat that the UDP pass still did not cover.
            # Should be empty now, and is computed rather than assumed.
            "udp_not_tested": udp_not_tested,
            "scan_scope":    scope,
            "scan_origin":   scan_origin,
            "target_public": public,
            # scope rides along whenever a reader could get the wrong idea from
            # the number alone: nothing found, or something found while other
            # ports went untested. scan_scope always carries it in full.
            "message": (base if (all_open and not udp_not_tested and not silent)
                        else f"{base} {scope}"),
        }

    def _check_udp_port(self, host: str, port: int) -> dict:
        """
        One UDP probe. Returns the state and what came back.

        THREE ANSWERS, NEVER TWO:
          open       a datagram came back. Something is listening.
          closed     ICMP port unreachable. On a CONNECTED UDP socket the OS
                     surfaces that as ConnectionResetError on Windows and
                     ConnectionRefusedError on Linux, which is why connect()
                     is used here rather than sendto: an unconnected socket
                     silently drops the ICMP and the closed case becomes
                     indistinguishable from silence.
          no_answer  nothing came back. NOT closed. Open and quiet, filtered
                     upstream, or the wrong payload for that service. Reported
                     as its own list with its own sentence, because this is
                     most of UDP and collapsing it into either of the other
                     two is the lie this whole module is organised against.

        The probe is a real request where one exists, see UDP_PROBES, and an
        empty datagram otherwise. The empty case is still worth sending: it
        cannot prove open, and an ICMP unreachable in reply still proves
        closed.

        THE FAMILY IS DERIVED, IT IS NOT ALWAYS AF_INET, 2026-09-25. This
        socket was built `socket.socket(socket.AF_INET, socket.SOCK_DGRAM)`
        whatever the target was, so a scan of an IPv6 address failed at
        connect() twenty-five times out of twenty-five and every failure
        arrived as one errno the caller folded into `udp_probe_failed`:

            _check_udp_port('::1', 53)
              -> probe_failed: [Errno -9] Address family for hostname not supported

        sockaddr's own family is the authority; IPv4-mapped v6 targets are
        unwrapped to v4 because a connected v4 socket reaches them.

        EVERY RESOLVED ADDRESS IS TRIED, one thing at a time: a name that
        resolves to more than one address used to have its remaining answers
        dropped (`info[0]` alone), so a service listening on the resolver's
        SECOND answer was reported as silence. Silence and an ICMP refusal are
        ANSWERS ABOUT A SPECIFIC ADDRESS, so the first one of those wins and
        stops the walk; only a LOCAL failure (no route, family refused, a
        blocked socket) moves on to the resolver's next answer, because that
        answer says nothing about the port. The address a probe actually used
        is returned as `probed_address` so the row can name the address it
        asked rather than the name it was handed.
        """
        try:
            infos = socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM,
                                       socket.IPPROTO_UDP)
        except socket.gaierror as e:
            return {"state": "probe_failed", "probe": "unresolvable",
                    "banner": None,
                    "error": (f"the target address {host!r} could not be "
                              f"resolved for a UDP probe: {e}")}
        if not infos:
            return {"state": "probe_failed", "probe": "unresolvable",
                    "banner": None,
                    "error": (f"the target address {host!r} resolved to "
                              f"nothing to probe")}

        name, payload, transport, scope = build_udp_probe(port, host)
        last_failure = None
        for family, _socktype, _proto, _canon, sockaddr in infos:
            if family == socket.AF_INET6:
                addr = sockaddr[0]
                if addr.lower().startswith("::ffff:") and "." in addr:
                    family, sockaddr = socket.AF_INET, (addr[7:], sockaddr[1])
            asked = sockaddr[0]
            sock = socket.socket(family, socket.SOCK_DGRAM)
            stage = "local"
            _enable_recverr(sock, family)
            try:
                sock.settimeout(UDP_TIMEOUT)
                sock.connect(sockaddr)
                sock.send(payload)
                stage = "answer"
                data = sock.recv(2048)
                return {
                    "state": "open",
                    "probe": name,
                    "probe_scope": scope,
                    "transport": transport,
                    "probed_address": asked,
                    # A SHORT, HONEST BANNER. The bytes a service sent back are
                    # attacker-controllable text, so what is stored is the size
                    # and a hex head, never decoded prose pretending to be a
                    # banner the way a TCP read might.
                    "banner": (f"{len(data)} byte reply to a "
                               f"{name} probe ({scope}), first bytes "
                               f"{data[:12].hex()}"),
                }
            except (ConnectionResetError, ConnectionRefusedError):
                icmp = read_icmp_error(sock)
                out = {"state": "closed", "probe": name,
                       "probe_scope": scope, "transport": transport,
                       "probed_address": asked, "banner": None}
                if icmp:
                    out["icmp"] = icmp
                    if icmp["from"] and _canonical_ip(icmp["from"]) != \
                            _canonical_ip(asked):
                        # A port unreachable sent by something other than the
                        # target is a device on the path refusing for it.
                        out["state"] = "filtered"
                        out["error"] = (f"{icmp['meaning']} from {icmp['from']}, "
                                        f"not from the target")
                return out
            except socket.timeout:
                return {"state": "no_answer", "probe": name,
                        "probe_scope": scope, "transport": transport,
                        "probed_address": asked, "banner": None}
            except OSError as e:
                if stage == "answer" and e.errno in _ICMP_FILTER_ERRNOS:
                    # An ICMP unreachable other than "port unreachable" came
                    # back: a host or firewall on the path refused the probe.
                    # That is an answer about this address (PS-20).
                    icmp = read_icmp_error(sock)
                    out = {"state": "filtered", "probe": name,
                           "probe_scope": scope, "transport": transport,
                           "probed_address": asked, "banner": None,
                           "error": (f"{icmp['meaning']} from {icmp['from']}"
                                     if icmp else str(e))}
                    if icmp:
                        out["icmp"] = icmp
                    return out
                # A local failure, not a statement about the port. Kept apart
                # from no_answer so a blocked socket cannot read as a quiet
                # host, and it is the ONE answer that moves the walk on.
                last_failure = {"state": "probe_failed", "probe": name,
                                "probe_scope": scope, "transport": transport,
                                "probed_address": asked, "banner": None,
                                "error": str(e)}
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        # Every resolved address failed locally: report the local failure
        # rather than a silence this probe never measured.
        return last_failure or {"state": "probe_failed", "probe": name,
                                "probe_scope": scope, "transport": transport,
                                "probed_address": None, "banner": None,
                                "error": "no address could be probed"}

    def _run_udp_scan(self, host: str, ports, scan_origin: str,
                      public: bool) -> dict:
        """
        The UDP pass. Returns the open rows plus the two lists that say what
        could not be settled, which the caller reports rather than folds in.
        """
        open_ports, closed, silent, failed, filtered = [], [], [], [], []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = {ex.submit(self._check_udp_port, host, p): p
                       for p in ports}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    res = future.result()
                except Exception as e:
                    failed.append({"port": port, "error": str(e)})
                    continue
                service = PORT_PROFILES.get(port, (f"port-{port}",))[0]
                if res["state"] == "open":
                    entry = classify_port(port, scan_origin, public,
                                          protocol=UDP_PROTOCOL)
                    entry["port"] = port
                    entry["state"] = "open"
                    entry["protocol"] = UDP_PROTOCOL
                    entry["host"] = host
                    entry["banner"] = res["banner"]
                    entry["probe"] = res["probe"]
                    entry["probe_scope"] = res.get("probe_scope")
                    open_ports.append(entry)
                elif res["state"] == "closed":
                    closed.append({"port": port, "service": service,
                                   "probe": res["probe"],
                                   "probe_scope": res.get("probe_scope"),
                                   "icmp": res.get("icmp")})
                elif res["state"] == "filtered":
                    filtered.append({"port": port, "service": service,
                                     "probe": res.get("probe"),
                                     "probed_address": res.get("probed_address"),
                                     "answered_by": res.get("error"),
                                     "icmp": res.get("icmp")})
                elif res["state"] == "probe_failed":
                    failed.append({"port": port, "service": service,
                                   "probe": res.get("probe"),
                                   "error": res.get("error")})
                else:
                    # WHICH ADDRESS WAS ASKED, AND WITH WHAT, on the row.
                    # Added 2026-09-25: a silent row used to carry only the
                    # port and its service name, and the one fact a reader
                    # needs to judge it -- that the question went to ONE
                    # address of a possibly multi-homed host -- lived nowhere
                    # but the payload's top-level "host". Measured here: two
                    # scans of the same machine (127.0.0.1 and its LAN address)
                    # return different silent sets against the same listeners,
                    # because a UDP socket is bound to an address and only the
                    # address it was bound to answers.
                    #
                    # THE ADDRESS COMES FROM THE PROBE, not from the name the
                    # caller typed: a name can resolve to several addresses and
                    # the probe is the only thing that knows which one it
                    # asked. `host` is the fallback for a result shape that
                    # predates the field.
                    silent.append({"port": port, "service": service,
                                   "probe": res["probe"],
                                   "probe_scope": res.get("probe_scope"),
                                   "transport": res.get("transport"),
                                   "probed_address": (res.get("probed_address")
                                                      or host)})

        open_ports.sort(key=lambda x: x["port"])
        return {"open": open_ports, "closed": sorted(closed,
                                                     key=lambda x: x["port"]),
                "silent": sorted(silent, key=lambda x: x["port"]),
                "filtered": sorted(filtered, key=lambda x: x["port"]),
                "failed": sorted(failed, key=lambda x: x["port"])}

    def _check_port(self, host: str, port: int) -> bool:
        """
        THE CONNECT TEST -- one of this module's two TCP probes since
        2026-09-25, and no longer the only one.

        It WAS the only one, and the privilege row described a SYN scan that
        did not exist (register PS-13). Option (c) built the SYN scan; see
        `_run_tcp_scan` for the dispatcher that decides which method a run
        uses. This function is the FALLBACK, taken when no raw socket can be
        opened, and a run that used it says so on its payload.

        True means a TCP handshake completed. False means it did not, and that
        covers refused, filtered, timed out and "this is a UDP service and
        nothing is listening on the TCP side". Those are four different facts
        and this function cannot tell them apart -- WHICH IS PRECISELY WHAT
        THE SYN PASS ADDS: it reads the answers, so an RST (closed) and
        silence (filtered or lost) come back as different values. The caller
        never writes a 'closed' row from a False, and the scope sentence names
        the method that ran.

        Scoring moved out to classify_port(), because severity depends on where
        the scan was run from and whether the target is routable, neither of
        which this function can see.

        THE ADDRESS FAMILY COMES FROM getaddrinfo, 2026-09-25, AND EVERY
        RESOLVED ADDRESS IS TRIED, which is the half the first version of this
        fix dropped. `socket.create_connection` resolves the name, then loops
        over EVERY result the resolver returned, returning the first one that
        connects and raising the last failure only when all of them are dead.
        The first version of this function read `info[0]` and tried that alone,
        so on a name that resolves to more than one address it could report a
        live port as closed whenever the FIRST address happened to be the dead
        one -- a false negative on the one probe this module exists to make,
        and narrower than the code it replaced.

        This was `socket.create_connection((host, port))` alone, and on this
        host a target of `::1` does not raise -- the call returns False for the
        ::1:631 case it was measured on, so an IPv6 host reported zero open
        ports over both protocols with nothing anywhere saying the family was
        the reason. Resolving first and then connecting to each sockaddr in
        turn keeps the same True/False contract while making a v6 target
        actually reachable, and keeps the
        DNS-RESOLUTION-INSIDE-THE-PROBE behaviour the gate's own comment
        depends on (see core/tool_registry._port_scan_requires_permission:
        a hostname still prompts, so nothing here has to get the rebinding
        question right).
        """
        state, addr, err = self._probe_port(host, port)
        answers = getattr(self, "_connect_answers", None)
        if answers is not None:
            with self._connect_lock:
                answers[(host, port)] = (state, addr, err)
        return state == "open"

    def _probe_port(self, host: str, port: int) -> tuple:
        """
        (state, address, error) for one connect probe, over every address the
        name resolves to.

        A refused connect is the target's RST, so it is CLOSED; a timeout is
        NO_ANSWER; a local error (no route) is FAILED. Open on any address
        wins, then closed, then no_answer (PS-19: this used to fold all of
        them into False).
        """
        try:
            infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        except socket.gaierror as e:
            return "failed", None, f"the target could not be resolved: {e}"
        if not infos:
            return "failed", None, "the target resolved to nothing"
        closed = silent = failed = None
        for family, socktype, proto, _canon, sockaddr in infos:
            try:
                s = socket.socket(family, socktype, proto)
                try:
                    s.settimeout(SCAN_TIMEOUT)
                    s.connect(sockaddr)
                    return "open", sockaddr[0], None
                finally:
                    s.close()
            except ConnectionRefusedError:
                closed = closed or sockaddr[0]
            except socket.timeout:
                silent = silent or sockaddr[0]
            except Exception as e:                            # noqa: BLE001
                failed = failed or (sockaddr[0], f"{type(e).__name__}: {e}")
        if closed:
            return "closed", closed, None
        if silent:
            return "no_answer", silent, None
        return "failed", failed[0] if failed else None, \
            failed[1] if failed else "no address could be probed"