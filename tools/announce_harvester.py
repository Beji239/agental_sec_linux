# tools/announce_harvester.py
# AgentalSec V2, identity from traffic that is addressed to everybody.
#
# WHY THIS EXISTS
# The host position's worst blind spot is devices that never talk to this
# host. A phone and a television exchanging packets never come near this
# machine's network card, and no amount of analysis recovers what was never
# seen. The usual fix is hardware: put a sensor where the traffic goes.
#
# But a large amount of what those devices SAY is broadcast or multicast,
# addressed to everybody on the segment, by design, as part of how the
# protocols work. This host hears all of it legitimately, on any network,
# behind any gateway, with no configuration, no credentials, no permission
# and no purchase. That traffic is already being captured and classified by
# packet_sniffer as `local_multicast`, and then everything inside it is
# thrown away.
#
# This module reads what is inside it:
#
#   DHCP  (67/68, broadcast)   the hardware address and the hostname a device
#                              ASKS FOR, at the moment it joins the network.
#                              Catches an arrival even if it never speaks to
#                              us again.
#   mDNS  (5353, multicast)    service instance names, and frequently model
#                              and manufacturer strings.
#   SSDP  (1900, multicast)    UPnP announcements: server string, device
#                              type, and a URL to a fuller description.
#   NBNS  (137, broadcast)     NetBIOS names on older Windows networks.
#
# THE CONSTRAINT THAT MATTERS MORE THAN THE FEATURE
#
# EVERY STRING HERE IS CHOSEN BY THE DEVICE, WHICH MEANS CHOSEN BY WHOEVER
# CONTROLS THE DEVICE.
#
# core/sanitize already makes this argument about DHCP and mDNS names, and it
# applies with full force to a module whose entire job is turning
# device-authored text into inventory records the model will read. A device
# can name itself anything, including text shaped like an instruction. That
# is not a hypothetical: it is the cheapest injection channel on a home
# network, because it needs no compromise of this host at all, just one
# cheap device with a settable hostname.
#
# So: the query tools that expose this data are in sanitize.UNTRUSTED_TOOLS,
# every harvested string is length-capped, and NOTHING here is ever treated
# as identification. It is a CLAIM. A device claiming to be a printer is
# recorded as having claimed that, not as being one. The distinction is the
# whole reason the inventory has an `identified_by` column.
#
# WHAT THIS IS NOT
# It is not a replacement for a gateway sensor. It reveals that devices
# exist and what they say about themselves. It says nothing about what they
# send to each other. Anyone reading this module's output as "now we can see
# the network" has made the same mistake this codebase keeps documenting.

import logging
import re
import struct

logger = logging.getLogger(__name__)

# A device-chosen string is untrusted input of unbounded length. Cap it here,
# at the boundary, rather than hoping every downstream reader remembers.
MAX_STRING = 128

# Ports whose payloads this module understands. Everything else is ignored
# rather than guessed at.
DHCP_PORTS = {67, 68}
MDNS_PORT  = 5353
SSDP_PORT  = 1900
NBNS_PORT  = 137

# DHCP option numbers we read. Deliberately few: these are the ones that
# carry identity, and parsing more options means more attack surface for no
# additional inventory value.
DHCP_OPT_HOSTNAME  = 12
DHCP_OPT_VENDOR    = 60   # vendor class identifier, e.g. "android-dhcp-14"
DHCP_OPT_MSG_TYPE  = 53
DHCP_OPT_PARAM_REQ = 55   # the fingerprint-ish list of options requested

DHCP_MSG_TYPES = {1: "discover", 2: "offer", 3: "request", 4: "decline",
                  5: "ack", 6: "nak", 7: "release", 8: "inform"}


def _clean(raw) -> str | None:
    """
    Make a device-authored byte string safe to store and show.

    Control characters out, length capped, whitespace collapsed. This does
    NOT make the content trustworthy, nothing can. It makes it safe to put
    in a database column and render in a table. The fence in core/sanitize is
    what keeps it distinguishable from instructions once it reaches the model.
    """
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = raw.decode("utf-8", "replace")
        except Exception:
            return None
    text = re.sub(r"[\x00-\x1f\x7f]", "", str(raw))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:MAX_STRING] or None


def _mac(raw: bytes) -> str | None:
    if not raw or len(raw) < 6:
        return None
    return ":".join(f"{b:02x}" for b in raw[:6])


def parse_dhcp(payload: bytes) -> dict | None:
    """
    Client hardware address, requested hostname and vendor class from a
    BOOTP/DHCP message.

    The interesting frames are DISCOVER and REQUEST, which clients broadcast.
    They carry the name the device wants to be called before it has an
    address at all, which makes this the earliest possible notice that
    something new has joined.
    """
    # Fixed BOOTP header is 236 bytes, then a 4-byte magic cookie, then
    # variable options. Anything shorter is not a DHCP message.
    if len(payload) < 240:
        return None
    if payload[236:240] != b"\x63\x82\x53\x63":
        return None

    out = {"mac": _mac(payload[28:34]), "source": "dhcp"}

    i = 240
    end = len(payload)
    while i < end:
        opt = payload[i]
        if opt == 255:          # end
            break
        if opt == 0:            # pad
            i += 1
            continue
        if i + 1 >= end:
            break
        length = payload[i + 1]
        val = payload[i + 2:i + 2 + length]
        if len(val) < length:   # truncated: stop, do not guess
            break

        if opt == DHCP_OPT_HOSTNAME:
            out["claimed_hostname"] = _clean(val)
        elif opt == DHCP_OPT_VENDOR:
            out["claimed_vendor_class"] = _clean(val)
        elif opt == DHCP_OPT_MSG_TYPE and length == 1:
            out["dhcp_message"] = DHCP_MSG_TYPES.get(val[0], f"type-{val[0]}")
        elif opt == DHCP_OPT_PARAM_REQ:
            # The SET of options a client asks for is fairly characteristic of
            # its OS. Stored as observed digits, not resolved to an OS name:
            # turning this into "Android 14" is a guess, and a guess recorded
            # as a fact is the failure this codebase is built around.
            out["param_request_list"] = ",".join(str(b) for b in val[:32])

        i += 2 + length

    return out if out.get("mac") else None


def parse_ssdp(payload: bytes) -> dict | None:
    """
    Manufacturer, model and device type from a UPnP NOTIFY or M-SEARCH reply.

    SSDP is HTTP-shaped text over UDP, so this is header parsing. The SERVER
    header conventionally carries OS and product strings; USN and NT carry
    the device or service type.
    """
    try:
        text = payload[:2048].decode("utf-8", "replace")
    except Exception:
        return None
    if not re.match(r"^(NOTIFY|M-SEARCH|HTTP/1\.[01])", text):
        return None

    out = {"source": "ssdp"}
    for header, key in (("SERVER", "claimed_server"),
                        ("NT", "claimed_device_type"),
                        ("ST", "claimed_device_type"),
                        ("USN", "claimed_usn"),
                        ("LOCATION", "description_url")):
        m = re.search(rf"^{header}\s*:\s*(.+)$", text,
                      re.IGNORECASE | re.MULTILINE)
        if m and key not in out:
            out[key] = _clean(m.group(1))
    # LOCATION is a URL on the device. It is recorded, never fetched here:
    # fetching a URL a stranger's device supplied, from the monitor, is a
    # request-forgery primitive handed over for free.
    return out if len(out) > 1 else None


def parse_mdns(payload: bytes) -> dict | None:
    """
    Service instance names from a multicast DNS response.

    Only the question and answer NAMES are read, not full record data.
    Names are enough for identity ("_airplay._tcp", an instance called
    "Living Room TV") and reading less means parsing less attacker-supplied
    structure.
    """
    if len(payload) < 12:
        return None
    try:
        qd, an = struct.unpack(">HH", payload[4:8])
    except struct.error:
        return None
    if qd == 0 and an == 0:
        return None

    names, i, guard = [], 12, 0
    while i < len(payload) and guard < 64:
        guard += 1
        labels, j = [], i
        hops = 0
        while j < len(payload):
            ln = payload[j]
            if ln == 0:
                j += 1
                break
            if ln & 0xC0 == 0xC0:       # compression pointer
                if hops > 8:            # pointer loop; stop rather than spin
                    return None
                hops += 1
                if j + 1 >= len(payload):
                    return None
                j = ((ln & 0x3F) << 8) | payload[j + 1]
                continue
            if j + 1 + ln > len(payload):
                return None
            labels.append(payload[j + 1:j + 1 + ln].decode("utf-8", "replace"))
            j += 1 + ln
        if labels:
            name = _clean(".".join(labels))
            if name and name not in names:
                names.append(name)
        if hops:
            break
        i = j + 4
        if i >= len(payload):
            break

    if not names:
        return None
    services = [n for n in names if n.startswith("_") or "._" in n]
    return {
        "source": "mdns",
        "claimed_names": names[:12],
        "claimed_services": services[:12] or None,
    }


def parse_nbns(payload: bytes) -> dict | None:
    """NetBIOS name service: the name a Windows host broadcasts for itself."""
    if len(payload) < 14:
        return None
    ln = payload[12]
    if ln != 32 or len(payload) < 13 + 32:
        return None
    encoded = payload[13:13 + 32]
    try:
        decoded = "".join(
            chr(((encoded[k] - 0x41) << 4) | (encoded[k + 1] - 0x41))
            for k in range(0, 32, 2))
    except (IndexError, ValueError):
        return None
    name = _clean(decoded.rstrip(" \x00"))
    return {"source": "nbns", "claimed_hostname": name} if name else None


def harvest(payload: bytes, src_port: int, dst_port: int) -> dict | None:
    """
    Route a payload to the right parser by port, or return None.

    Ports this module does not understand are IGNORED, not guessed at. A
    parser applied to the wrong protocol produces confident nonsense, which
    is worse than silence and much harder to notice.
    """
    if not payload:
        return None
    try:
        if src_port in DHCP_PORTS or dst_port in DHCP_PORTS:
            return parse_dhcp(payload)
        if dst_port == MDNS_PORT or src_port == MDNS_PORT:
            return parse_mdns(payload)
        if dst_port == SSDP_PORT or src_port == SSDP_PORT:
            return parse_ssdp(payload)
        if dst_port == NBNS_PORT or src_port == NBNS_PORT:
            return parse_nbns(payload)
    except Exception as e:
        # A malformed announcement is expected, frequently, and is not an
        # error worth a finding. It is also exactly what a hostile device
        # would send to see what breaks.
        logger.debug(f"announce parse failed ({src_port}->{dst_port}): {e}")
        return None
    return None


def describe(record: dict) -> str:
    """
    One line for a human, phrased as a CLAIM throughout.

    The wording is load-bearing. "Claims to be a printer" and "is a printer"
    are different facts, and only one of them is supported by a broadcast
    that anyone on the segment could have sent.
    """
    if not record:
        return ""
    bits = []
    if record.get("claimed_hostname"):
        bits.append(f"calls itself {record['claimed_hostname']!r}")
    if record.get("claimed_vendor_class"):
        bits.append(f"vendor class {record['claimed_vendor_class']!r}")
    if record.get("claimed_server"):
        bits.append(f"server string {record['claimed_server']!r}")
    if record.get("claimed_device_type"):
        bits.append(f"announces {record['claimed_device_type']!r}")
    if record.get("claimed_services"):
        bits.append("offers " + ", ".join(record["claimed_services"][:3]))
    if not bits:
        return ""
    return (f"via {record['source']}, unverified and device-chosen: "
            + "; ".join(bits))
