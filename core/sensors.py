# core/sensors.py
# AgentalSec V2, Vantage points. Where an observation was made from.
#
# WHY THIS EXISTS
#
# Every sensor in this project sees a subset of the network, decided by where
# it sits, not by how well it is written. A capture running on this host sees
# this host's traffic, plus broadcast and multicast. Unicast between two other
# devices is forwarded only to the port the destination MAC was learned on, so
# it never reaches this network card. That is IEEE 802.1D forwarding, and no
# amount of code on this machine changes it.
#
# Until now that fact lived in prose:
# several tool descriptions repeat it, because the model had no field to
# reason from. Repeating a warning is not the same as making it checkable.
# The model was told absence of packets is not a finding, and still had to
# take that on trust every single time.
#
# With a vantage point recorded per observation, absence becomes readable
# instead of merely forbidden. The model can look up the sensor, read what
# that position structurally cannot see, and say the honest sentence itself:
# no traffic was observed from this device, by a sensor that cannot observe
# this device's traffic, therefore nothing follows from the silence.
#
# RULE 2 HOLDS. Python states where a sensor sits and what that position can
# and cannot see. Those are facts about network topology, true on every
# network, and they are not judgements. Weighing them is still the model's
# job.
#
# This also makes a second sensor possible later. Two sensors reporting the
# same conversation is a deduplication problem only once both rows know where
# they came from.

import hashlib
import logging
import socket
import uuid

logger = logging.getLogger(__name__)


# POSITIONS
#
# Six positions, each a statement about topology rather than about hardware.
# can_see and cannot_see are stored on the sensor row and returned to the
# model verbatim. They are deliberately blunt.
#
# Do not add a position without being able to say, in one sentence each, what
# it structurally can and cannot observe. A position whose scope cannot be
# stated is a position that will be used to justify a conclusion later.

POSITIONS = {
    # WHY 'host' CARVES OUT BRIDGED GUESTS.
    #
    # The scope below used to say, flatly, that this position cannot see any
    # other device's traffic to the internet. That is right for a separate
    # physical machine and wrong for a virtual machine bridged to this host's
    # adapter, because a bridged guest puts its own frames on the wire through
    # this network card. The guest holds its own address from the same DHCP
    # server and shows up here as a device in its own right, and its traffic
    # is genuinely captured.
    #
    # This was not theoretical. The model captured a bridged guest's outbound
    # sessions, then in a later turn talked itself back out of that evidence
    # by quoting the old cannot_see line at itself, and reported the host as
    # unobservable. That is the same failure this file exists to prevent, only
    # running the other way: instead of reading silence as proof of calm, it
    # read a scope statement as proof that real captured packets could not
    # exist. A scope that is wider than stated is not the safe direction to be
    # wrong in, it just moves the mistake.
    #
    # The carve-out is narrow on purpose. Bridged only. A NAT'd guest is
    # rewritten to this host's address before it leaves, so it has no separate
    # presence here and nothing about it can be attributed. Which mode a guest
    # is in is not something this file can know, so both are described and the
    # model is left to work out which one it is looking at.
    "host": {
        "summary": "Running on the machine it monitors.",
        "can_see": (
            "Traffic to and from this host in both directions. Broadcast, "
            "which is flooded to the whole subnet, so ARP and DHCP are "
            "visible. Multicast, subject to IGMP snooping, so mDNS, SSDP and "
            "LLMNR are usually visible. Unknown-unicast flooding, which is "
            "transient and cannot be relied on. Traffic from a virtual "
            "machine bridged to this host's adapter, in both directions and "
            "including its traffic to the internet, because a bridged guest "
            "sends its frames through this network card; the guest carries "
            "its own address and its own hardware address, so it appears here "
            "as a device of its own and its packets are real observations of "
            "that device."
        ),
        "cannot_see": (
            "Unicast traffic between two other physical devices. Any other "
            "physical device's traffic to the internet. A switch forwards a "
            "unicast frame only to the port it learned the destination MAC "
            "on, so those frames never reach this network card. Promiscuous "
            "mode does not help; the packets are not on the wire here to be "
            "captured. Silence from another device is therefore a statement "
            "about this sensor's position and not about that device. A "
            "virtual machine running NAT'd on this host is also invisible as "
            "a device, but for the opposite reason: its traffic does pass "
            "through here, rewritten to this host's address, so it is "
            "captured and then misattributed to the host rather than lost. "
            "Neither of those applies to a bridged guest on this host, whose "
            "traffic does arrive here under its own address, so silence from "
            "one of those is a real absence and worth asking about rather "
            "than explaining away with this field."
        ),
    },
    "gateway": {
        "summary": "Running on, or fed by, the router or firewall.",
        "can_see": (
            "All routed traffic, which includes every device's traffic to the "
            "internet, with per-device attribution if observed on the LAN "
            "side before NAT."
        ),
        "cannot_see": (
            "Traffic between two devices on the same subnet, which is "
            "switched and never reaches the router. Traffic between two "
            "devices on the same access point, which is bridged inside the "
            "access point. If observed on the WAN side, per-device "
            "attribution is destroyed by NAT and every flow appears to come "
            "from the gateway."
        ),
    },
    # WHY THIS IS NOT 'gateway'.
    #
    # It sits at the gateway, so the obvious thing is to reuse that position.
    # That would be wrong, and wrong in the direction this file exists to
    # prevent. The 'gateway' entry above promises "all routed traffic, which
    # includes every device's traffic to the internet". A management query to
    # the router delivers none of that. It reads the CONTROL PLANE, being
    # tables the router keeps about itself, and never sees a packet.
    #
    # Register this collector as 'gateway' and every query_sensors lookup
    # downstream starts overstating what the tool can see, which is exactly
    # the failure local_position() refuses an unknown value over. A position
    # names where the sensor sits AND which plane it reads, because those two
    # together are what decide scope.
    "gateway_api": {
        "summary": "Querying the router's own management interface, not its "
                   "traffic.",
        "can_see": (
            "Tables the router keeps about itself: its neighbour or ARP "
            "table, which names every device the router has exchanged "
            "traffic with recently together with that device's address and "
            "hardware address; the addresses and interfaces the router "
            "itself holds; the ports the router itself is listening on; and "
            "its own firmware description. The per-device attribution here "
            "is the router's own, so it does not depend on this host being "
            "able to reach or overhear the device at all."
        ),
        "cannot_see": (
            "Any traffic whatsoever. Nothing here says what a device sent, "
            "to where, how much of it, or whether it has communicated at all "
            "since the row was written. A neighbour table entry AGES OUT, "
            "typically in minutes to a few hours, so a device that is "
            "powered off drops out of it; presence in the table means recent "
            "contact, not presence now, and absence from it is not absence "
            "from the network. It is also not a DHCP lease table: a device "
            "with a static address that is talking WILL appear, and a device "
            "holding a lease that is not talking will NOT. Devices on a "
            "segment this router does not route for, and devices behind a "
            "second router, never appear at all. Any name a device is listed "
            "under was chosen by that device."
        ),
    },
    "mirror": {
        "summary": "Fed by a switch SPAN port or a network TAP.",
        "can_see": (
            "Everything crossing the mirrored ports, including same-segment "
            "unicast between two other devices, which is the traffic no other "
            "position reaches."
        ),
        "cannot_see": (
            "Traffic on switches or ports that are not mirrored. A SPAN "
            "session is also a low-priority task on the switch, so packet "
            "timing is approximate and frames may be dropped under load; "
            "treat interval measurements from a SPAN feed with more caution "
            "than from a TAP."
        ),
    },
    "inline": {
        "summary": "A transparent bridge in the path, commonly between "
                   "modem and router.",
        "can_see": (
            "All traffic crossing that link, for every device, with no "
            "client configuration required."
        ),
        "cannot_see": (
            "Any traffic that does not cross the link. On a combined router "
            "and access point, device-to-device traffic is bridged inside "
            "that box and never appears here at all."
        ),
    },
    "resolver": {
        "summary": "The network's DNS resolver.",
        "can_see": (
            "The name every device asked for, per client, including devices "
            "nothing can be installed on. The name is the identity that a "
            "destination address is not, because shared hosting and content "
            "delivery networks put thousands of unrelated names behind one "
            "address on purpose."
        ),
        "cannot_see": (
            "Devices using DNS over HTTPS or DNS over TLS, which resolve "
            "elsewhere. Devices with a hardcoded public resolver that ignore "
            "the address handed out by DHCP. Repeat connections served from "
            "the client's cache, which produce no query, so query counts "
            "undercount connections. Connections made to a literal address "
            "with no lookup at all. Nothing here says whether the connection "
            "that followed a lookup actually happened, or how much data it "
            "carried."
        ),
    },
    "offline": {
        "summary": "A capture file analysed after the fact.",
        "can_see": (
            "Whatever the capture contains, which is decided by wherever and "
            "whenever it was taken, not by this tool."
        ),
        "cannot_see": (
            "Anything outside the capture window or outside the position the "
            "capture was taken from. The scope of an imported file is unknown "
            "to this tool unless a human records it, so absence in a capture "
            "file supports no conclusion by itself."
        ),
    },
}

VALID_POSITIONS = set(POSITIONS)

DEFAULT_POSITION = "host"


# LOCAL SENSOR IDENTITY

def _stable_local_id() -> str:
    """
    A stable id for the sensor running in this process.

    Derived at runtime from the hostname and the interface MAC so it survives
    restarts and stays distinct when a second sensor is added later. Hashed
    and truncated so that no hostname or MAC is ever written into a row, a
    log line, or anything the model reads back. scripts/check_no_local_details
    would fail the build on the raw values, and it would be right to.

    Falls back to a random id if either lookup fails. A random id per boot is
    worse than a stable one, but it is still better than two different
    machines colliding on the same row.
    """
    try:
        raw = f"{socket.gethostname()}:{uuid.getnode():012x}"
        return "sensor-" + hashlib.sha256(raw.encode()).hexdigest()[:12]
    except Exception as e:
        logger.warning(f"Could not derive a stable sensor id ({e}); "
                       f"using a random one for this run.")
        return "sensor-" + uuid.uuid4().hex[:12]


LOCAL_SENSOR_ID = _stable_local_id()


def local_position(config: dict = None) -> str:
    """
    Where this instance sits, per config.json.

    Defaults to 'host', which is the only position this tool can verify for
    itself. Anything else is the operator telling us where they put it, and a
    wrong answer here makes every scope statement downstream wrong, so it is
    validated loudly rather than silently accepted.
    """
    if not config:
        return DEFAULT_POSITION
    position = (config.get("sensor", {}) or {}).get("position", DEFAULT_POSITION)
    if position not in VALID_POSITIONS:
        logger.warning(
            f"config.json sets sensor.position to '{position}', which is not "
            f"one of {sorted(VALID_POSITIONS)}. Falling back to "
            f"'{DEFAULT_POSITION}'. Scope statements will describe a host "
            f"sensor until this is corrected."
        )
        return DEFAULT_POSITION
    return position


def describe(position: str) -> dict:
    """The scope text for a position. Unknown positions return a scope that
    admits it does not know, rather than an empty string that reads as
    'nothing is hidden from this sensor'."""
    entry = POSITIONS.get(position)
    if entry:
        return dict(entry)
    return {
        "summary": "Unrecognised position.",
        "can_see": "Unknown.",
        "cannot_see": (
            "Unknown. Treat every absence from this sensor as uninformative "
            "until its position is recorded."
        ),
    }


def offline_sensor_id(capture_key: str) -> str:
    """
    A stable id for one imported capture file.

    Hashed for the same reason LOCAL_SENSOR_ID is: a file path names a folder
    on somebody's machine, and scripts/check_no_local_details would be right
    to fail a build over one sitting in a database row.

    Stable per capture, so importing the same file twice reuses one sensor
    rather than growing a new row every time somebody re-runs the analysis.
    """
    return "offline-" + hashlib.sha256(capture_key.encode()).hexdigest()[:12]


def register_offline(capture_key: str, origin: str = None,
                     label: str = None) -> str:
    """
    Register the sensor for an imported capture, and return its id.

    THE POSITION IS ALWAYS 'offline'. THAT IS THE WHOLE POINT, SO IT IS NOT A
    PARAMETER.

    It is tempting to let the caller say the capture came from a SPAN port and
    register it at 'mirror', because that is genuinely more informative. Do
    not.
    A position is what the model reads to decide what an absence means, and
    'mirror' promises that same-segment unicast between two other devices WAS
    visible. Believing that about a file nobody here produced turns "not in the
    capture" into "did not happen", from a claim typed into a text box.

    So where the operator says it came from is stored as a CLAIM, in notes, in
    their own words. It is shown to the model beside the scope rather than
    instead of it. The scope keeps saying that the reach of an imported file is
    unknown to this tool, because that stays true no matter how confident the
    sentence next to it is.

    An import with no origin recorded is allowed, and says so. Refusing it
    would just teach people to type anything to get past the prompt, and a
    made-up origin is worse than a missing one.

    RE-IMPORTING WITHOUT AN ORIGIN DOES NOT ERASE ONE THAT WAS RECORDED.
    Found by running it twice. The first import stored "SPAN port on the
    office switch"; the second, from a script that passed no origin, replaced
    it with "NOT recorded". Nobody typed anything wrong and a fact a person
    supplied was gone. So a blank origin passes notes=None and upsert_sensor's
    COALESCE keeps whatever is already there. The position's own scope text
    still says the reach is unknown, which is the sentence that actually
    matters, so nothing is being papered over by staying quiet here.
    """
    from core import memory_engine as me

    sensor_id = offline_sensor_id(capture_key)
    scope = describe("offline")
    note = (f"Imported capture. Operator says it was taken: {origin.strip()}"
            if origin and origin.strip() else None)
    me.upsert_sensor(
        sensor_id=sensor_id,
        label=label,
        position="offline",
        summary=scope["summary"],
        can_see=scope["can_see"],
        cannot_see=scope["cannot_see"],
        notes=note,
    )
    logger.info(f"Offline sensor registered for an imported capture: "
                f"{sensor_id}")
    return sensor_id


def register_local(config: dict = None, label: str = None) -> str:
    """
    Write this process's sensor row and return its id. Idempotent; called at
    boot from main.py, before any collector starts.
    """
    from core import memory_engine as me

    position = local_position(config)
    scope = describe(position)
    me.upsert_sensor(
        sensor_id=LOCAL_SENSOR_ID,
        label=label or (config or {}).get("sensor", {}).get("label"),
        position=position,
        summary=scope["summary"],
        can_see=scope["can_see"],
        cannot_see=scope["cannot_see"],
    )
    logger.info(f"Sensor registered: {LOCAL_SENSOR_ID} at position "
                f"'{position}'.")
    return LOCAL_SENSOR_ID
