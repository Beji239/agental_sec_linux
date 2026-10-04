# tools/lan_watch.py
# AgentalSec V2, TODO 113.5. LAN protocol abuse.
#
# ARP spoofing, gateway MAC changes, rogue DHCP servers, and LLMNR / NBT-NS
# poisoning. All four are single packet, plaintext, no stream state, and all
# four are actually relevant on a flat home LAN, which is why this section
# survived when 113.6 did not.
#
# WHY THIS IS A PURE MODULE WITH NO CAPTURE AND NO DATABASE
#
# Same shape as tools/tls_hello.py, and for the same two reasons.
#
# ONE CAPTURE. packet_sniffer already has the NIC open, and that open goes
# through core/capabilities so the privileged helper can own it. A second
# capture would mean a second privileged open for no gain, and would put this
# file on the wrong side of the privilege split.
#
# TESTABLE WITHOUT A NETWORK. Every entry point here takes plain values, not
# scapy objects. packet_sniffer does the frame decoding and calls in with
# strings and ints, so the whole of the detection logic can be tested with no
# NIC, no root and no scapy.
#
# This module RETURNS findings. It does not save them. packet_sniffer owns the
# cooldown, the dismissal check and the write, exactly as it does for its own
# detections.
#
# WHAT THIS CANNOT SEE, AND IT IS A BIG ONE
#
# A COMPETENT ARP SPOOF IS UNICAST. The attacker sends ARP replies addressed
# straight to the victim and straight to the gateway. On a switched network
# those frames are never flooded, so a host sensor sitting on a third machine
# NEVER SEES THEM. What this module catches is the noisy case: broadcast ARP,
# gratuitous ARP, and the tools that spray replies at everybody.
#
# That is not a reason to skip it. Most real-world ARP spoofing on a home LAN
# comes from tools that are exactly that noisy. But it IS a reason that a
# quiet result from this module must never be printed as "no ARP spoofing on
# this network". It means "nothing that reached this sensor". The coverage
# note in status() is what says so, and anything summarising this module has
# to carry it.
#
# The mirror-port case is the fix and it is already documented in
# SENSOR_PLACEMENT.md: a sensor on a SPAN port sees the unicast frames too.
# Nothing here changes on that vantage, it just sees more.

import json
import logging

logger = logging.getLogger(__name__)

# ARP

# How many times an IP's MAC has to change inside the window before it is
# called a fight rather than a lease.
#
# ONE CHANGE IS NOT A FINDING and that is the whole tuning decision here. DHCP
# hands an address to a new device all the time, and a phone rejoining the
# wifi looks identical to the first packet of a spoof. What does NOT happen
# normally is the binding changing back and forth, because that is two
# machines both insisting they own the address.
ARP_FLAP_THRESHOLD = 3
ARP_FLAP_WINDOW_SECS = 600

# Bound on how many IPs we track bindings for. A /24 is 254, so this is
# generous, and it stops a spoofer spraying a made-up range from growing the
# dict without limit.
ARP_MAX_TRACKED = 2048

# LLMNR and NBT-NS

# How many DISTINCT names one host has to answer for before it is a poisoner.
#
# THE SIGNAL IS THE DISTINCT COUNT, NOT THE VOLUME. A normal machine answers
# LLMNR for exactly one name: its own. Responder and its relatives answer for
# EVERY name asked, because the whole technique is to say yes to a typo. So a
# host answering for four different names in ten minutes is not a busy
# machine, it is a machine doing something a normal machine cannot do.
POISON_NAME_THRESHOLD = 4
POISON_WINDOW_SECS = 600

# Bound on how many DISTINCT RESPONDERS we hold name sets for.
#
# THIS WAS MISSING AND ARP HAD IT. _arp_binding has ARP_MAX_TRACKED and this
# dict had nothing, so a host spraying LLMNR responses with spoofed source
# addresses grew it without limit, inside the capture callback, on the same
# machine the app is meant to be protecting. A /24 has 254 addresses, so 512
# is generous for anything honest.
NAME_MAX_RESPONDERS = 512

LLMNR_PORT = 5355
NBTNS_PORT = 137

# IPv6 has its own versions of the ARP and DHCP attacks: a neighbour
# advertisement claims an address the way an ARP reply does, a router
# advertisement makes a host its default router, and DHCPv6 hands out DNS
# servers (mitm6 answers it on networks that never had a DHCPv6 server).
NDP_FLAP_THRESHOLD = ARP_FLAP_THRESHOLD
NDP_FLAP_WINDOW_SECS = ARP_FLAP_WINDOW_SECS
NDP_MAX_TRACKED = ARP_MAX_TRACKED

# WHERE THE BASELINES LIVE, CORRECTED 2026-09-26 (register section 13).
#
# These were two user_preferences keys ("lan_gateway_mac",
# "lan_dhcp_servers"). user_preferences is the table core/integrity hashes as
# THE POLICY and journals a config_observed entry about on ANY difference, on
# the contract that such an entry ALWAYS MEANS THE RULES CHANGED.
#
# MEASURED 2026-09-26, driving the SHIPPED code on a scratch database: the
# FIRST gateway MAC a capture learns -- a packet, no person involved -- wrote
# a preference and the policy digest MOVED; a learned DHCP server did the
# same; a person's accept moved it again. Each one journalled a false "the
# policy in user_preferences has CHANGED" warning in the one journal whose
# whole value is that it does not cry wolf. On a machine capturing a home LAN
# that is a false entry every time the gateway is legitimately relearned.
#
# It is the FIFTH time this project has paid for this shape: the T2 watcher
# cursor, the L3 baselines that became local_integrity_baseline in v42, the
# feeds' refresh time in v46, and the agent-seal counter all had it, and each
# was fixed the same way v53 fixes this one. A table that is not
# user_preferences cannot be mistaken for policy by anything, and nothing has
# to remember a key prefix to exclude -- a prefix rule lives in a string
# comparison, and the integrity journal is the last place that should depend
# on somebody remembering.
#
# THE OLD KEYS ARE MOVED by the v53 migration, not left behind: leaving them
# would leave the policy snapshot telling a story about a sensor's
# bookkeeping. Nothing is backfilled beyond that move -- a baseline that was
# never written stays unwritten, and the first value seen is LEARNED.
BASELINE_TABLE = "lan_baseline"
_BASELINE_GATEWAY = "gateway_mac"
_BASELINE_DHCP = "dhcp_servers"
_BASELINE_V6_ROUTERS = "ipv6_routers"
_BASELINE_DHCP6 = "dhcpv6_servers"


def load_baseline(name: str):
    """
    The stored baseline for one set, or None when there has never been one.

    None and {} ARE DIFFERENT ANSWERS and the callers depend on it: None
    means "this has never been stored", so the first value seen is LEARNED
    rather than judged. A stored value that cannot be read is a different
    answer again and is logged as such, because starting silently from
    nothing would mean silently never alerting on a change.
    """
    from core import memory_engine as me
    try:
        with me._get_conn() as conn:
            row = conn.execute(
                f"SELECT value_json FROM {BASELINE_TABLE} WHERE name = ?",
                (name,)).fetchone()
    except Exception as e:
        logger.warning(f"LAN baseline {name!r} could not be read ({e}). "
                       f"Treating this as a first run, which means the first "
                       f"value seen will be LEARNED rather than checked.")
        return None
    if row is None:
        return None
    try:
        return json.loads(row["value_json"])
    except (ValueError, TypeError) as e:
        logger.warning(f"LAN baseline {name!r} could not be parsed ({e}). "
                       f"Treating it as absent, which relearns it.")
        return None


def save_baseline(name: str, value) -> bool:
    """Persist one baseline. Returns whether it was written."""
    from core import memory_engine as me
    try:
        with me._get_conn() as conn:
            conn.execute(
                f"INSERT INTO {BASELINE_TABLE}(name, value_json) VALUES(?, ?) "
                f"ON CONFLICT(name) DO UPDATE SET "
                f"value_json=excluded.value_json, "
                f"recorded_at=CURRENT_TIMESTAMP",
                (name, json.dumps(value, separators=(",", ":"))))
        return True
    except Exception as e:
        logger.warning(f"Could not persist the LAN baseline {name!r} ({e}). "
                       f"It will be relearned at the next start, so a change "
                       f"across that restart would be missed.")
        return False


# Neither of these is anybody's hardware address. All-zero rides on ARP
# probes and on a DHCP client that has no address yet; broadcast rides on a
# request. Accepting either as a BINDING invents a MAC change that never
# happened, and three invented changes is an ARP flap finding about nothing.
_PLACEHOLDER_MACS = frozenset(["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"])


# THE ACTIVE WATCHER. TODO 120, 2026-09-20.
#
# The LanWatch instance lives inside PacketSniffer, which is right: the
# sniffer owns the capture. The problem is that status() is the ONLY honest
# answer to "is the network clean of ARP spoofing", because a quiet result
# from this module means nothing reached the sensor and not that nothing
# happened. With no handle, the model could not read it, so the caveat that
# makes the whole module readable had no reader.
#
# Registered by the sniffer, cleared when it stops. A stale handle would
# answer with counters from a sensor that is no longer running, which is the
# exact confusion this module's notes exist to prevent.
_ACTIVE = None


def set_active(watcher):
    """Register the live watcher. None clears it."""
    global _ACTIVE
    _ACTIVE = watcher


def active():
    """The live watcher, or None when no capture is running."""
    return _ACTIVE


def _normalise_mac(mac: str) -> str:
    """Lowercase, colon separated, or '' if it is not a usable MAC."""
    if not mac:
        return ""
    m = str(mac).strip().lower().replace("-", ":")
    parts = m.split(":")
    if len(parts) != 6:
        return ""
    try:
        out = ":".join(f"{int(p, 16):02x}" for p in parts)
    except ValueError:
        return ""
    return "" if out in _PLACEHOLDER_MACS else out


def decode_nbtns_name(encoded: str) -> str:
    """
    Undo NetBIOS first-level encoding.

    Each byte of the real name is split into two nibbles and each nibble is
    added to the letter 'A', so "FOO" becomes "EGFPFP..." padded to 16 bytes.
    Returns the decoded name stripped of padding, or '' if it does not decode.

    Small and self-contained on purpose: the alternative was pulling in a
    NetBIOS library to read one field.
    """
    if not encoded:
        return ""
    e = str(encoded).strip().upper()
    # Drop a scope suffix if one rode along.
    e = e.split(".")[0]
    if len(e) % 2 or not e.isalpha():
        return ""
    try:
        out = bytes(
            ((ord(e[i]) - 65) << 4) | (ord(e[i + 1]) - 65)
            for i in range(0, len(e), 2)
        )
    except (ValueError, IndexError):
        return ""
    # The last byte is the service type, not part of the name.
    name = out[:-1].decode("ascii", errors="ignore").strip()
    return name.lower()


# WIRE PARSERS. Bytes in, name out.
#
# These live here rather than in packet_sniffer for the reason stated at the
# top of this file: they take BYTES, so they can be tested with no NIC, no
# root and no scapy. Leaving them in the sniffer would have made the one part
# most likely to be wrong the one part hardest to test.
#
# THEY RETURN '' ON ANYTHING UNEXPECTED, and never a guess. The whole of
# LAN-1004 is a count of DISTINCT names, so a misparse that invents names is
# not a cosmetic bug, it is a false positive generator.


def parse_llmnr_query_name(buf: bytes) -> str:
    """
    The queried name out of an LLMNR RESPONSE, or ''.

    LLMNR is DNS wire format: a 12 byte header, then the question name as
    length-prefixed labels. We read the QUESTION and not the answer record,
    because the question is what was ASKED FOR, and that is the thing a
    poisoner is lying about.

    Queries return '' as well as malformed packets. Only a response carries a
    claim.
    """
    try:
        if not buf or len(buf) < 13:
            return ""
        # QR bit, high bit of byte 2. 0 is a query.
        if not (buf[2] & 0x80):
            return ""
        labels = []
        i = 12
        while i < len(buf):
            length = buf[i]
            if length == 0:
                break
            # A compression pointer in the question section is malformed.
            # Refuse rather than guess: see the note above.
            if length & 0xC0:
                return ""
            i += 1
            if i + length > len(buf):
                return ""
            labels.append(buf[i:i + length].decode("ascii", "ignore"))
            i += length
        return ".".join(l for l in labels if l).strip().lower()
    except Exception:
        return ""


def parse_nbtns_query_name(buf: bytes) -> str:
    """
    The queried name out of an NBT-NS RESPONSE, or ''.

    Same header layout as DNS. The single question label is always exactly 32
    characters of first-level-encoded NetBIOS name, which is why the length
    is checked rather than trusted.
    """
    try:
        if not buf or len(buf) < 14:
            return ""
        if not (buf[2] & 0x80):
            return ""
        if buf[12] != 32 or 13 + 32 > len(buf):
            return ""
        return decode_nbtns_name(buf[13:45].decode("ascii", "ignore"))
    except Exception:
        return ""


def _binding_flap(binding: dict, change_log: dict, ip: str, mac: str,
                  now: float, max_tracked: int, window: float) -> tuple:
    """
    Record ip -> mac and return (recent change times, previous mac). Shared by
    ARP and IPv6 neighbour discovery, which make the same claim.

    Past max_tracked the oldest half is dropped: a spray defence, since losing
    old bindings only costs spotting a slow flap.
    """
    previous = binding.get(ip)
    binding[ip] = mac
    if previous is None:
        if len(binding) > max_tracked:
            keep = list(binding.items())[max_tracked // 2:]
            binding.clear()
            binding.update(keep)
            for k in [k for k in change_log if k not in binding]:
                del change_log[k]
        return [], None
    if previous == mac:
        return [], previous
    changes = change_log.setdefault(ip, [])
    changes.append(now)
    changes[:] = [t for t in changes if t >= now - window]
    return changes, previous


class LanWatch:
    """
    State for the four LAN detections.

    One instance per sniffer. Everything it holds is in memory and per run,
    EXCEPT the gateway MAC and the DHCP server set, which are read from and
    written to the `lan_baseline` TABLE so that they survive a restart. That
    distinction is the point: a spoof in progress is a live condition and
    in-memory state is right for it, but "what the gateway's MAC has always
    been" is a baseline, and a baseline relearned at every boot can never be
    violated.

    CORRECTED 2026-09-26 (register section 13): these two baselines used to
    live in user_preferences, which core/integrity hashes as THE POLICY --
    so the FIRST gateway MAC a capture learned from a packet journalled a
    false "the policy has CHANGED" warning. They are their own table now
    (v53); see the block comment above `BASELINE_TABLE`.
    """

    def __init__(self, gateway_ip: str = None, load_baselines: bool = True):
        self.gateway_ip = (gateway_ip or "").strip()

        # ip -> current mac
        self._arp_binding = {}
        # ip -> list of change timestamps
        self._arp_changes = {}

        # responder ip -> {name: last_seen_ts}
        self._name_answers = {}

        self._gateway_mac = ""
        self._dhcp_servers = set()

        # WHY THESE TWO SETS EXIST, 2026-09-20. THE WORST BUG IN THIS FILE.
        #
        # Both LAN-1002 and LAN-1003 used to raise a finding and then WRITE
        # THE NEW VALUE INTO THE BASELINE. The reason given was good, stop
        # one finding per frame forever, and the cost was not seen: during a
        # live attack the ATTACKER'S OWN VALUE became the saved baseline.
        #
        #   The gateway MAC: a spoofer's address was persisted as the trusted
        #   gateway. After a restart the spoof looked normal, and the real
        #   router coming back looked like the attack.
        #
        #   The DHCP server: a rogue server was added to the known-good set
        #   and the finding text said "this will not raise again". It never
        #   did, on this run or any run after it.
        #
        # A detection that lets attacker controlled data overwrite its own
        # baseline is not a detection. The baseline now only ever moves when
        # somebody says so, through accept_gateway_mac or accept_dhcp_server,
        # and the repeat is held down by these two IN MEMORY sets instead.
        #
        # THEY ARE DELIBERATELY NOT PERSISTED. Held in memory, a restart
        # re-raises a condition that is still going on, which is right: if
        # the wrong MAC is still answering for the gateway tomorrow, that is
        # worth saying again. Persisting them would rebuild the same bug in
        # a different shape.
        self._gateway_reported = set()
        self._dhcp_reported = set()

        # IPv6. Bindings and flap times are per run; the router and DHCPv6
        # server sets are baselines, and the reported sets hold repeats down
        # without moving them, for the same reason as the two above.
        self._nd_binding = {}
        self._nd_changes = {}
        self._v6_routers = {}          # router address -> mac
        self._dhcp6_servers = {}       # server identity -> address
        self._v6_router_reported = set()
        self._dhcp6_reported = set()

        # Counters for status(). A module that cannot say how much it looked
        # at cannot be read honestly when it says it found nothing.
        self.arp_frames_seen = 0
        self.dhcp_frames_seen = 0
        self.name_frames_seen = 0
        self.nd_frames_seen = 0
        self.ra_frames_seen = 0
        self.dhcp6_frames_seen = 0

        if load_baselines:
            self._load_baselines()

    # BASELINES

    def _load_baselines(self):
        try:
            self._gateway_mac = _normalise_mac(
                load_baseline(_BASELINE_GATEWAY) or "")
            raw = load_baseline(_BASELINE_DHCP) or []
            self._dhcp_servers = {str(s) for s in raw if str(s).strip()}
            routers = load_baseline(_BASELINE_V6_ROUTERS) or {}
            self._v6_routers = {str(k): _normalise_mac(v) for k, v in
                                routers.items()} if isinstance(routers, dict) else {}
            servers = load_baseline(_BASELINE_DHCP6) or {}
            self._dhcp6_servers = {str(k): str(v) for k, v in
                                   servers.items()} if isinstance(servers, dict) else {}
        except Exception as e:
            # A missing baseline is NOT an error, it is a first run. A baseline
            # we could not READ is different, and it gets a log line, because
            # silently starting from nothing would mean silently never
            # alerting on a change.
            logger.warning(f"LAN baselines not loaded ({e}). Treating this as "
                           f"a first run, which means the first gateway MAC "
                           f"and DHCP server seen will be LEARNED rather than "
                           f"checked.")

    def _save_gateway_mac(self, mac: str):
        self._gateway_mac = mac
        save_baseline(_BASELINE_GATEWAY, mac)

    def _save_dhcp_servers(self):
        save_baseline(_BASELINE_DHCP, sorted(self._dhcp_servers))

    # ARP

    def observe_arp(self, op: int, sender_ip: str, sender_mac: str,
                    now: float) -> list:
        """
        One ARP frame. Returns a list of finding dicts, usually empty.

        op is the ARP opcode: 1 is a request, 2 is a reply. Only REPLIES carry
        a claim worth checking. A request also carries the sender's own
        binding, and gratuitous ARP is sent as either, so both are recorded,
        but the claim being tested is "this MAC says it owns this IP".
        """
        self.arp_frames_seen += 1

        mac = _normalise_mac(sender_mac)
        ip = (sender_ip or "").strip()
        if not mac or not ip or ip == "0.0.0.0":
            return []

        findings = []

        # THE GATEWAY CHECK FIRST, because it is the one that matters. An
        # attacker in the middle has to claim the gateway's address, so a
        # gateway MAC that changes is the single highest value signal on a
        # flat LAN.
        if self.gateway_ip and ip == self.gateway_ip:
            findings.extend(self._check_gateway_mac(mac, now))

        findings.extend(self._check_arp_flap(ip, mac, now))
        return findings

    def _check_gateway_mac(self, mac: str, now: float) -> list:
        if not self._gateway_mac:
            # FIRST SIGHTING IS LEARNING, NOT A FINDING. There is nothing to
            # compare against and saying so is better than inventing a
            # baseline and alerting on it.
            self._save_gateway_mac(mac)
            logger.info(f"Gateway {self.gateway_ip} MAC learned as {mac}. "
                        f"A change from here on raises LAN-1002.")
            return []

        if mac == self._gateway_mac:
            return []

        # ONE FINDING PER NEW ADDRESS, and the baseline DOES NOT MOVE. See the
        # block comment in __init__ for what moving it cost. A second, third
        # and hundredth frame from the same wrong MAC are held down here; a
        # DIFFERENT wrong MAC is a new fact and raises again, which is what a
        # spoofer cycling addresses looks like.
        if mac in self._gateway_reported:
            return []
        self._gateway_reported.add(mac)

        old = self._gateway_mac

        # NOTE 2026-09-26 (register section 13): this description has always
        # pointed at scripts/accept_gateway_mac.py, and the script existed in
        # NEITHER tree until this round wrote it. The finding sent an
        # operator looking for a file that was never built; the promise is
        # now kept rather than deleted, because the sentence is the right
        # instruction and the file was the missing half.
        return [{
            "detection_id": "LAN-1002",
            "dedup_key": f"gwmac:{self.gateway_ip}",
            "severity": "high",
            "entity_type": "ip",
            "entity_value": self.gateway_ip,
            "title": f"Default gateway MAC changed: {self.gateway_ip}",
            "description": (
                f"Gateway: {self.gateway_ip}\n"
                f"Was: {old}\n"
                f"Now: {mac}\n\n"
                f"This is the position an attacker takes to sit between this "
                f"network and everything outside it, so it is worth checking "
                f"rather than assuming.\n\n"
                f"THE INNOCENT EXPLANATIONS ARE REAL AND COMMON: a replaced "
                f"or rebooted router, a failover to a second WAN device, or a "
                f"mesh node taking over the gateway role. What separates them "
                f"from the other case is whether you changed anything.\n\n"
                f"THE RECORDED ADDRESS HAS NOT BEEN CHANGED. It is still "
                f"{old}. That is on purpose: moving it here would mean an "
                f"attacker's address quietly becoming the trusted one. This "
                f"will not repeat for {mac}, but it will raise again if the "
                f"gateway answers from a different address again, and after a "
                f"restart if the condition is still going on.\n\n"
                f"If you did replace the router, accept the new address so "
                f"this stops: scripts/accept_gateway_mac.py, or call "
                f"lan_watch.accept_gateway_mac."
            ),
            "raw_data": {"gateway_ip": self.gateway_ip,
                         "old_mac": old, "new_mac": mac,
                         "baseline_moved": False},
        }]

    def accept_gateway_mac(self, mac: str) -> dict:
        """
        Move the gateway baseline DELIBERATELY. The only way it moves.

        This is what the finding points at when the answer is "yes, I swapped
        the router". It is a separate call rather than an automatic step for
        the reason in __init__: whatever moves this baseline decides what the
        app trusts, and a packet off the wire does not get to be that.

        `persisted` travels in the reply (CORRECTED 2026-09-26, register
        section 13): it used to answer accepted: True whether or not the
        write landed, so a person told "it moved" about a value that would be
        relearned at the next start. The move still counts for THIS run --
        the in-memory baseline moved, which is real -- and the caller is told
        which of the two happened.
        """
        m = _normalise_mac(mac)
        if not m:
            return {"accepted": False, "reason": f"{mac!r} is not a MAC"}
        old = self._gateway_mac
        self._gateway_mac = m
        persisted = save_baseline(_BASELINE_GATEWAY, m)
        self._gateway_reported.discard(m)
        logger.info(f"Gateway MAC baseline accepted: {old or 'none'} -> {m}.")
        return {"accepted": True, "old_mac": old or None, "new_mac": m,
                "persisted": persisted}

    def _check_arp_flap(self, ip: str, mac: str, now: float) -> list:
        changes, previous = _binding_flap(
            self._arp_binding, self._arp_changes, ip, mac, now,
            ARP_MAX_TRACKED, ARP_FLAP_WINDOW_SECS)
        if len(changes) < ARP_FLAP_THRESHOLD:
            return []

        return [{
            "detection_id": "LAN-1001",
            "dedup_key": f"arpflap:{ip}",
            "severity": "high",
            "entity_type": "ip",
            "entity_value": ip,
            "title": f"ARP binding for {ip} changed repeatedly",
            "description": (
                f"Address: {ip}\n"
                f"Hardware address changes in the last "
                f"{ARP_FLAP_WINDOW_SECS // 60} minutes: {len(changes)}\n"
                f"Most recent: {previous} then {mac}\n\n"
                f"One change is ordinary, it is what a DHCP lease moving to a "
                f"new device looks like. Changing repeatedly is not: that is "
                f"two machines both claiming the address, which is what ARP "
                f"spoofing looks like from the outside.\n\n"
                f"WHAT THIS DOES NOT PROVE: a duplicate static address, or two "
                f"interfaces on one machine answering for the same IP, produce "
                f"the same pattern and are not attacks."
            ),
            "raw_data": {"ip": ip, "changes": len(changes),
                         "previous_mac": previous, "current_mac": mac},
        }]

    # DHCP

    def observe_dhcp_server(self, server_ip: str, msg_type: str,
                            now: float) -> list:
        """
        A DHCP message that came FROM a server: an OFFER or an ACK.

        Requests and discovers come from clients and say nothing about who is
        handing out leases, so packet_sniffer only calls in for the server
        side.

        THE FIRST SERVER IS LEARNED, NOT JUDGED, same as the gateway MAC. On a
        home LAN there is normally exactly one, so a SECOND one is the finding,
        and "second" cannot mean anything until a first is on record.
        """
        self.dhcp_frames_seen += 1

        ip = (server_ip or "").strip()
        if not ip or ip == "0.0.0.0":
            return []

        if ip in self._dhcp_servers:
            return []

        first_ever = not self._dhcp_servers

        if first_ever:
            # The first server IS the baseline, so it is recorded. It is
            # the only address that ever gets written here.
            self._dhcp_servers.add(ip)
            self._save_dhcp_servers()
            logger.info(f"DHCP server learned as {ip}. Another one from here "
                        f"on raises LAN-1003.")

            # A FIRST RUN CAN STILL BE LEARNING THE WRONG THING. If the app
            # first starts while a rogue is answering, that rogue becomes the
            # baseline and nothing ever raises. There is no external truth to
            # check against on a home LAN, but there is one strong hint: the
            # thing handing out leases is almost always the default gateway.
            # When it is not, say so rather than learning in silence.
            if self.gateway_ip and ip != self.gateway_ip:
                self._dhcp_reported.add(ip)
                return [{
                    "detection_id": "LAN-1003",
                    "dedup_key": f"dhcp:{ip}",
                    "severity": "high",
                    "entity_type": "ip",
                    "entity_value": ip,
                    "title": (f"DHCP is being served by {ip}, which is not "
                              f"the default gateway"),
                    "description": (
                        f"DHCP server: {ip} ({msg_type})\n"
                        f"Default gateway: {self.gateway_ip}\n\n"
                        f"This is the FIRST DHCP server this sensor has seen, "
                        f"so it has been recorded as the baseline. It is "
                        f"flagged because on almost every home network the "
                        f"router is both the gateway and the DHCP server, and "
                        f"here it is not.\n\n"
                        f"THE INNOCENT EXPLANATIONS ARE COMMON: a separate "
                        f"DHCP server by design, a pi-hole or router handing "
                        f"out leases while another device routes, or a mesh "
                        f"setup. Any of those make this normal.\n\n"
                        f"WHAT IT IS GUARDING AGAINST: if the app happened to "
                        f"start while a rogue server was answering, that rogue "
                        f"would have become the baseline and nothing would "
                        f"ever have raised. This is the one chance to catch "
                        f"that, which is why it is said out loud instead of "
                        f"being learned quietly."
                    ),
                    "raw_data": {"server_ip": ip, "msg_type": msg_type,
                                 "gateway_ip": self.gateway_ip,
                                 "is_first_seen": True},
                }]
            return []

        # A SECOND SERVER IS NOT RECORDED AND NOT TRUSTED. It used to be added
        # to the known-good set and persisted, which permanently allowlisted a
        # rogue across restarts. See __init__. The repeat is held down in
        # memory instead.
        if ip in self._dhcp_reported:
            return []
        self._dhcp_reported.add(ip)

        others = sorted(self._dhcp_servers)
        return [{
            "detection_id": "LAN-1003",
            "dedup_key": f"dhcp:{ip}",
            "severity": "high",
            "entity_type": "ip",
            "entity_value": ip,
            "title": f"A second DHCP server is answering: {ip}",
            "description": (
                f"New DHCP server: {ip} ({msg_type})\n"
                f"Already known: {', '.join(others)}\n\n"
                f"A home network normally has exactly one device handing out "
                f"addresses, and it is the router. A second one can hand a "
                f"client its own address as the gateway and its own address "
                f"as the DNS server, which puts it in the middle of "
                f"everything that client does.\n\n"
                f"THE INNOCENT EXPLANATIONS: a second router plugged into the "
                f"LAN by its WAN-less side, a travel router, a hypervisor's "
                f"host-only network bridged by accident, or a device in "
                f"access-point mode that was never switched out of router "
                f"mode. All of those are worth finding anyway, because all of "
                f"them break addressing sooner or later.\n\n"
                f"THIS ADDRESS HAS NOT BEEN ADDED TO THE KNOWN LIST. It used "
                f"to be, which meant a rogue server was permanently treated "
                f"as normal from the moment it was reported, on this run and "
                f"every run after it. It will not repeat while the app is up, "
                f"and it will raise again after a restart if it is still "
                f"answering.\n\n"
                f"If this server is meant to be here, accept it so it stops: "
                f"lan_watch.accept_dhcp_server."
            ),
            "raw_data": {"server_ip": ip, "msg_type": msg_type,
                         "known_servers": others, "recorded": False},
        }]

    def accept_dhcp_server(self, server_ip: str) -> dict:
        """
        Add a DHCP server to the known-good set DELIBERATELY.

        Same reasoning as accept_gateway_mac: the trusted set only grows when
        a person says so, never because a packet arrived.
        """
        ip = (server_ip or "").strip()
        if not ip:
            return {"accepted": False, "reason": "no address given"}
        self._dhcp_servers.add(ip)
        self._dhcp_reported.discard(ip)
        persisted = save_baseline(_BASELINE_DHCP, sorted(self._dhcp_servers))
        logger.info(f"DHCP server {ip} accepted as known good.")
        return {"accepted": True, "server_ip": ip,
                "known_servers": sorted(self._dhcp_servers),
                "persisted": persisted}

    # LLMNR AND NBT-NS

    def _prune_name_answers(self, now: float):
        """
        Make room in the responder table. Expired first, then the oldest half.

        Same trade as the ARP one: losing old entries costs the ability to
        spot a slow poisoner, and running out of memory costs the sensor
        entirely. This is a spray defence, not a correctness feature.
        """
        cutoff = now - POISON_WINDOW_SECS
        for k in [k for k, v in self._name_answers.items()
                  if not v or max(v.values()) < cutoff]:
            del self._name_answers[k]

        if len(self._name_answers) < NAME_MAX_RESPONDERS:
            return

        by_age = sorted(self._name_answers.items(),
                        key=lambda kv: max(kv[1].values()) if kv[1] else 0)
        for k, _v in by_age[:max(1, len(by_age) // 2)]:
            del self._name_answers[k]
        logger.warning(
            f"LLMNR/NBT-NS responder table hit its cap of "
            f"{NAME_MAX_RESPONDERS} and was halved. That many distinct "
            f"responders inside {POISON_WINDOW_SECS // 60} minutes is itself "
            f"unusual on a home LAN: it usually means source addresses are "
            f"being spoofed.")

    def observe_name_response(self, proto: str, responder_ip: str,
                              name: str, now: float) -> list:
        """
        A host ANSWERED an LLMNR or NBT-NS query for a given name.

        Only responses count. A query says what somebody was looking for; a
        response says who claimed to be it, and the claim is the thing that
        can be a lie.

        THE GATE IS DISTINCT NAMES PER RESPONDER. A normal machine answers for
        its own name, so it has a distinct count of one no matter how much
        traffic it generates. A poisoner answers for whatever was asked,
        because saying yes to a typo is the entire technique.
        """
        self.name_frames_seen += 1

        ip = (responder_ip or "").strip()
        n = (name or "").strip().lower()
        if not ip or not n:
            return []

        # BOUND FIRST, THEN RECORD. Without this a host spraying responses
        # with spoofed source addresses grew this dict without limit, inside
        # the capture callback. ARP has had ARP_MAX_TRACKED all along and this
        # had nothing.
        if ip not in self._name_answers and \
                len(self._name_answers) >= NAME_MAX_RESPONDERS:
            self._prune_name_answers(now)

        seen = self._name_answers.setdefault(ip, {})
        seen[n] = now

        cutoff = now - POISON_WINDOW_SECS
        for key in [k for k, ts in seen.items() if ts < cutoff]:
            del seen[key]

        if len(seen) < POISON_NAME_THRESHOLD:
            return []

        names = sorted(seen.keys())
        return [{
            "detection_id": "LAN-1004",
            "dedup_key": f"poison:{ip}",
            "severity": "high",
            "entity_type": "ip",
            "entity_value": ip,
            "title": f"{ip} is answering name queries for many names",
            "description": (
                f"Responder: {ip}\n"
                f"Protocol: {proto}\n"
                f"Distinct names answered for in the last "
                f"{POISON_WINDOW_SECS // 60} minutes: {len(seen)}\n"
                f"Names: {', '.join(names[:12])}"
                + (" ..." if len(names) > 12 else "") + "\n\n"
                f"{proto} is the fallback Windows uses when DNS has no answer, "
                f"which most often means somebody mistyped a name. It has no "
                f"authentication at all: whoever replies first wins.\n\n"
                f"A normal machine answers for ONE name, its own. Answering "
                f"for many is the signature of a credential-capture tool, "
                f"which replies to everything and collects the authentication "
                f"attempt that follows.\n\n"
                f"WORTH KNOWING EITHER WAY: turning LLMNR and NBT-NS off "
                f"entirely is standard hardening and costs nothing on a "
                f"network that has working DNS."
            ),
            "raw_data": {"responder_ip": ip, "protocol": proto,
                         "distinct_names": len(seen), "names": names[:32]},
        }]

    # IPV6 NEIGHBOUR DISCOVERY

    def observe_neighbor_advert(self, target_ip: str, target_mac: str,
                                now: float) -> list:
        """
        One neighbour advertisement: "target_ip is at target_mac". The IPv6
        form of an ARP reply, and spoofed the same way (LAN-1005).
        """
        self.nd_frames_seen += 1
        mac = _normalise_mac(target_mac)
        ip = (target_ip or "").strip().lower()
        if not mac or not ip or ip == "::":
            return []
        changes, previous = _binding_flap(
            self._nd_binding, self._nd_changes, ip, mac, now,
            NDP_MAX_TRACKED, NDP_FLAP_WINDOW_SECS)
        if len(changes) < NDP_FLAP_THRESHOLD:
            return []
        return [{
            "detection_id": "LAN-1005",
            "dedup_key": f"ndpflap:{ip}",
            "severity": "high",
            "entity_type": "ip",
            "entity_value": ip,
            "title": f"IPv6 neighbour binding for {ip} changed repeatedly",
            "description": (
                f"Address: {ip}\n"
                f"Hardware address changes in the last "
                f"{NDP_FLAP_WINDOW_SECS // 60} minutes: {len(changes)}\n"
                f"Most recent: {previous} then {mac}\n\n"
                f"Neighbour advertisements are IPv6's ARP. Changing back and "
                f"forth is two machines both claiming the address, which is "
                f"what neighbour spoofing looks like from outside.\n\n"
                f"WHAT THIS DOES NOT PROVE: two interfaces of one machine, or "
                f"a duplicate static address, produce the same pattern."
            ),
            "raw_data": {"ip": ip, "changes": len(changes),
                         "previous_mac": previous, "current_mac": mac},
        }]

    def observe_router_advert(self, router_ip: str, router_mac: str,
                              lifetime: int, prefixes: list,
                              now: float) -> list:
        """
        One router advertisement with a non-zero router lifetime, which makes
        the sender a default router for every host that hears it (LAN-1006).

        The first router is learned. It is still flagged when its MAC is not
        the IPv4 gateway's, because on a home network the router is usually
        one box, and an IPv6 router appearing on a network that had none is
        how a host takes over IPv6 traffic.
        """
        self.ra_frames_seen += 1
        ip = (router_ip or "").strip().lower()
        mac = _normalise_mac(router_mac)
        if not ip or not lifetime or int(lifetime) <= 0:
            return []
        if ip in self._v6_routers:
            return []
        prefixes = [str(p) for p in (prefixes or [])][:8]
        first_ever = not self._v6_routers
        if first_ever:
            self._v6_routers[ip] = mac
            save_baseline(_BASELINE_V6_ROUTERS, self._v6_routers)
            logger.info(f"IPv6 router learned as {ip} ({mac or 'no MAC'}). "
                        f"Another one from here on raises LAN-1006.")
            if not (self._gateway_mac and mac and mac != self._gateway_mac):
                return []
            why = (f"It is the FIRST IPv6 router this sensor has seen, so it "
                   f"was recorded as the baseline. It is flagged because its "
                   f"hardware address {mac} is not the IPv4 gateway's "
                   f"({self._gateway_mac}).")
        else:
            if ip in self._v6_router_reported:
                return []
            why = (f"Already known: "
                   f"{', '.join(sorted(self._v6_routers))}. This one was NOT "
                   f"added to the known list.")
        self._v6_router_reported.add(ip)
        return [{
            "detection_id": "LAN-1006",
            "dedup_key": f"ra:{ip}",
            "severity": "high",
            "entity_type": "ip",
            "entity_value": ip,
            "title": f"A new IPv6 router is advertising itself: {ip}",
            "description": (
                f"Router: {ip} ({mac or 'MAC not carried'})\n"
                f"Router lifetime: {lifetime}s\n"
                f"Prefixes: {', '.join(prefixes) or 'none'}\n\n"
                f"{why}\n\n"
                f"A router advertisement makes every host that hears it route "
                f"IPv6 through the sender, and most systems prefer IPv6. A "
                f"rogue one puts the sender in the middle of that traffic.\n\n"
                f"THE INNOCENT EXPLANATIONS: a second router or mesh node "
                f"with IPv6 on, a phone sharing its connection, or a "
                f"virtual machine host. If it is meant to be here, accept it: "
                f"lan_watch.accept_ipv6_router."
            ),
            "raw_data": {"router_ip": ip, "router_mac": mac,
                         "lifetime": int(lifetime), "prefixes": prefixes,
                         "known_routers": sorted(self._v6_routers),
                         "is_first_seen": first_ever},
        }]

    def accept_ipv6_router(self, router_ip: str, router_mac: str = "") -> dict:
        """Add an IPv6 router to the known set, the only way the set grows."""
        ip = (router_ip or "").strip().lower()
        if not ip:
            return {"accepted": False, "reason": "no address given"}
        self._v6_routers[ip] = _normalise_mac(router_mac)
        self._v6_router_reported.discard(ip)
        persisted = save_baseline(_BASELINE_V6_ROUTERS, self._v6_routers)
        return {"accepted": True, "router_ip": ip,
                "known_routers": sorted(self._v6_routers),
                "persisted": persisted}

    # DHCPV6

    def observe_dhcpv6_server(self, server_ip: str, server_mac: str,
                              server_duid: str, msg_type: str,
                              now: float) -> list:
        """
        A DHCPv6 ADVERTISE or REPLY, which only a server sends (LAN-1007).

        Identified by its DUID when it carries one, since the address can
        change. The first server is learned, and flagged when its MAC is not
        the IPv4 gateway's: that is mitm6, which answers DHCPv6 on networks
        that never had a server and hands out itself as the DNS server.
        """
        self.dhcp6_frames_seen += 1
        ip = (server_ip or "").strip().lower()
        mac = _normalise_mac(server_mac)
        ident = (server_duid or "").strip().lower() or ip
        if not ident:
            return []
        if ident in self._dhcp6_servers:
            return []
        first_ever = not self._dhcp6_servers
        if first_ever:
            self._dhcp6_servers[ident] = ip
            save_baseline(_BASELINE_DHCP6, self._dhcp6_servers)
            logger.info(f"DHCPv6 server learned as {ip} ({ident}). Another "
                        f"one from here on raises LAN-1007.")
            if not (self._gateway_mac and mac and mac != self._gateway_mac):
                return []
            why = (f"It is the FIRST DHCPv6 server this sensor has seen, so it "
                   f"was recorded as the baseline. It is flagged because its "
                   f"hardware address {mac} is not the IPv4 gateway's "
                   f"({self._gateway_mac}).")
        else:
            if ident in self._dhcp6_reported:
                return []
            why = (f"Already known: "
                   f"{', '.join(sorted(set(self._dhcp6_servers.values())))}. "
                   f"This one was NOT added to the known list.")
        self._dhcp6_reported.add(ident)
        return [{
            "detection_id": "LAN-1007",
            "dedup_key": f"dhcp6:{ident}",
            "severity": "high",
            "entity_type": "ip",
            "entity_value": ip or ident,
            "title": f"A new DHCPv6 server is answering: {ip or ident}",
            "description": (
                f"Server: {ip} ({mac or 'MAC not carried'})\n"
                f"Server DUID: {server_duid or 'not carried'}\n"
                f"Message: {msg_type}\n\n"
                f"{why}\n\n"
                f"A DHCPv6 server can hand hosts its own address as their DNS "
                f"server, and Windows asks DHCPv6 even on networks with no "
                f"IPv6. That is exactly how the mitm6 tool takes over name "
                f"resolution on an IPv4 network.\n\n"
                f"THE INNOCENT EXPLANATIONS: a router with DHCPv6 switched "
                f"on that is not the IPv4 gateway, or a second router. If it "
                f"is meant to be here, accept it: "
                f"lan_watch.accept_dhcpv6_server."
            ),
            "raw_data": {"server_ip": ip, "server_mac": mac,
                         "server_duid": server_duid, "msg_type": msg_type,
                         "known_servers": sorted(self._dhcp6_servers),
                         "is_first_seen": first_ever},
        }]

    def accept_dhcpv6_server(self, identity: str, server_ip: str = "") -> dict:
        """Add a DHCPv6 server (DUID or address) to the known set."""
        ident = (identity or "").strip().lower()
        if not ident:
            return {"accepted": False, "reason": "no identity given"}
        self._dhcp6_servers[ident] = (server_ip or ident).strip().lower()
        self._dhcp6_reported.discard(ident)
        persisted = save_baseline(_BASELINE_DHCP6, self._dhcp6_servers)
        return {"accepted": True, "identity": ident,
                "known_servers": sorted(self._dhcp6_servers),
                "persisted": persisted}

    # STATUS

    def status(self) -> dict:
        """
        What this module has actually been able to look at.

        RULE TWO LIVES HERE for this module. None of the four detections can
        fire on traffic that never reached the sensor, and the commonest
        reason for a quiet result is a switched network rather than a clean
        one. Anything printing "no LAN attacks found" has to read this and say
        which it means.
        """
        looked = (self.arp_frames_seen + self.dhcp_frames_seen
                  + self.name_frames_seen + self.nd_frames_seen
                  + self.ra_frames_seen + self.dhcp6_frames_seen)

        notes = []
        if self.arp_frames_seen == 0:
            notes.append(
                "No ARP frames have reached this sensor. Either the capture "
                "filter is not passing ARP, or this vantage point does not "
                "see the broadcast domain. Nothing has been checked for ARP "
                "spoofing, which is not the same as nothing being found.")
        if not self.gateway_ip:
            notes.append(
                "The default gateway address is not known, so the gateway MAC "
                "check (LAN-1002) is NOT RUNNING. That is the highest value "
                "check in this module.")
        elif not self._gateway_mac:
            notes.append(
                f"The gateway MAC for {self.gateway_ip} has not been learned "
                f"yet, so there is no baseline to violate.")
        if not self._dhcp_servers:
            notes.append(
                "No DHCP server has been seen yet, so a rogue one cannot be "
                "told from the real one. The first server observed is learned, "
                "not judged.")

        # ADDED 2026-09-26 (register section 13).
        #
        # THE NAME PATH HAD NO COVERAGE SENTENCE AT ALL. The other three
        # checks have one and LAN-1004 did not, while sharing the same
        # blindness: it cannot fire on a response that never reached this
        # sensor. Measured before the wiring landed -- and the wiring itself
        # was the defect (parse_llmnr_query_name had no production caller) --
        # so a quiet LAN-1004 also had nothing anywhere saying the path was
        # unexamined rather than clean. Same rule as the ARP note above.
        if self.name_frames_seen == 0:
            notes.append(
                "No LLMNR or NBT-NS responses have reached this sensor, so "
                "nothing has been checked for name-service poisoning "
                "(LAN-1004). That is not the same as a quiet network: a host "
                "answering for many names can only be seen by a sensor that "
                "saw it answer.")

        if self.nd_frames_seen + self.ra_frames_seen == 0:
            notes.append(
                "No IPv6 neighbour or router advertisements have reached this "
                "sensor, so IPv6 spoofing and rogue IPv6 routers (LAN-1005, "
                "LAN-1006) have not been checked.")
        if not self._v6_routers:
            notes.append(
                "No IPv6 router has been seen yet, so the first one is learned, "
                "not judged, unless its MAC differs from the IPv4 gateway's.")

        notes.append(
            "A targeted ARP spoof uses UNICAST replies, which a host sensor on "
            "a switched network never sees. What this catches is the noisy "
            "case. A quiet result means nothing reached this sensor.")

        return {
            "arp_frames_seen": self.arp_frames_seen,
            "dhcp_frames_seen": self.dhcp_frames_seen,
            "name_frames_seen": self.name_frames_seen,
            "total_frames_seen": looked,
            "gateway_ip": self.gateway_ip or None,
            "gateway_mac": self._gateway_mac or None,
            "dhcp_servers": sorted(self._dhcp_servers),
            "tracked_arp_bindings": len(self._arp_binding),
            "nd_frames_seen": self.nd_frames_seen,
            "ra_frames_seen": self.ra_frames_seen,
            "dhcp6_frames_seen": self.dhcp6_frames_seen,
            "ipv6_routers": sorted(self._v6_routers),
            "dhcpv6_servers": sorted(self._dhcp6_servers),
            "tracked_nd_bindings": len(self._nd_binding),
            "can_check_gateway_mac": bool(self.gateway_ip),
            "has_looked": looked > 0,
            "notes": notes,
        }
