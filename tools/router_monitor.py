# tools/router_monitor.py
# AgentalSec V2, Read the router's own tables over SNMP.
#
# WHY THIS SENSOR EXISTS
#
# Every inventory in this project until now was built from what THIS HOST
# could reach or overhear, and both of those are narrow. network_scanner
# sweeps the subnet and records whoever answered ICMP inside a 200 ms window,
# which is a different set from whoever is on the network: a device that drops
# ICMP, or that was asleep for that fraction of a second, is written down as
# absent, and absent looks exactly like not there. packet_sniffer sees less
# still, because a switch forwards a unicast frame only to the port that owns
# the destination hardware address.
#
# The router has neither problem. It exchanged the traffic itself, so its
# neighbour table is per-device attribution that does not depend on this host
# reaching anything. That is the whole value here and it is worth being
# precise about, because it is easy to overclaim.
#
# WHAT THIS IS NOT
#
# It is NOT a traffic sensor. Nothing read here is a packet. It cannot say
# what a device sent, to where, how much, or whether it communicated at all
# since the row was written. The sensor is registered at position
# 'gateway_api' rather than 'gateway' for exactly that reason: 'gateway'
# promises all routed traffic, and reusing it would make every downstream
# scope statement overstate the tool.
#
# It is NOT a DHCP lease table, which is the thing people assume when they
# hear "the router's client list". SNMP has no standard MIB for DHCP leases;
# what is standard, and what is read here, is ipNetToMediaTable, the router's
# neighbour or ARP table. The practical differences both matter:
#
#   A device with a STATIC address that is talking DOES appear.
#   A device holding a lease that is NOT talking does NOT appear.
#   Entries AGE OUT, typically minutes to a few hours.
#
# So presence in this table means recent contact, and absence from it means
# nothing at all. Both of those are written onto the sensor row so the model
# reads them as data rather than being told them in prose it has to remember.
#
# READ ONLY BY CONSTRUCTION, NOT BY PROMISE
#
# This module speaks SNMP v2c directly rather than through a library, and the
# reason is not dependency count. A library that can also write is a library
# one wrong call away from writing, and "we do not call setCmd" is a promise
# in a comment. Here the SET protocol data unit is not implemented, and the
# send path asserts the request tag is one of three read operations before a
# byte reaches the socket. There is no code path in this file that can change
# anything on the router, which is the property that made it acceptable to
# hand this tool a credential at all.
#
# It also keeps the clean-install path at exactly the dependencies already in
# requirements.txt, which core/secret_store.py argues for on the same grounds:
# it matters more for a security tool that people are asked to run as
# Administrator.
#
# THE PARSER IS THE ATTACK SURFACE, so it is bounded rather than trusted. The
# response comes over the network from a device that could be lying. Every
# length is checked against the remaining buffer, the datagram is capped, the
# number of rows per table is capped, and identifier arcs are range checked.
# Pure Python cannot be made to corrupt memory; what it can be made to do is
# loop or allocate, and the caps are there for that.
#
# THIS MODULE MAKES NO JUDGEMENTS. It records what the router said and, for
# settings, that a value CHANGED from the one previously recorded. Whether a
# listener on every interface is alarming is the model's job. A severity
# written into Python here would be PORT_PROFILES again with a smaller table.

import hashlib
import logging
import socket
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

SOURCE_SNMP = "snmp"
VALID_BACKENDS = {SOURCE_SNMP}

# BOUNDS
#
# Every one of these exists because the input is a datagram from a device this
# tool does not control.

MAX_DATAGRAM     = 65535   # a UDP payload cannot exceed this anyway
# Rows read per table. Configurable as router_monitor.max_rows_per_table,
# clamped to the ceiling; 2000 cut a 2600-entry table short (RVP-15).
MAX_WALK_ROWS    = 8192
MAX_WALK_ROWS_CEILING = 65536
MAX_BINDS_PER_DATAGRAM = 2000
MAX_WALK_REQUESTS = 200    # floor on requests per walk; see walk()
MAX_STRING_BYTES = 512     # sysDescr and friends, before storage
MAX_OID_ARCS     = 128
DEFAULT_TIMEOUT  = 3.0
DEFAULT_RETRIES  = 2
BULK_REPETITIONS = 20


# BER, THE MINIMUM SUBSET

TAG_INTEGER   = 0x02
TAG_OCTETS    = 0x04
TAG_NULL      = 0x05
TAG_OID       = 0x06
TAG_SEQUENCE  = 0x30

TAG_IPADDRESS = 0x40
TAG_COUNTER32 = 0x41
TAG_GAUGE32   = 0x42
TAG_TIMETICKS = 0x43
TAG_OPAQUE    = 0x44
TAG_COUNTER64 = 0x46

# The three "there is nothing here" answers a v2c agent can give in place of a
# value. They are decoded as an explicit sentinel rather than as None, because
# None also means the NULL we sent in the request, and a walk that cannot tell
# those apart runs forever.
TAG_NO_SUCH_OBJECT   = 0x80
TAG_NO_SUCH_INSTANCE = 0x81
TAG_END_OF_MIB_VIEW  = 0x82
_EXCEPTION_TAGS = {TAG_NO_SUCH_OBJECT, TAG_NO_SUCH_INSTANCE, TAG_END_OF_MIB_VIEW}

PDU_GET      = 0xA0
PDU_GET_NEXT = 0xA1
PDU_RESPONSE = 0xA2
PDU_GET_BULK = 0xA5

# THE INVARIANT. Asserted on every send. SNMP's SetRequest is 0xA3 and Trap,
# InformRequest and Report are 0xA4, 0xA6 and 0xA8; none of them is buildable
# by this module, and none of them is permitted through the socket either. Two
# independent statements of the same rule, because the expensive failure would
# be a future edit that adds a writer and leaves the comment above intact.
_READ_ONLY_PDUS = frozenset({PDU_GET, PDU_GET_NEXT, PDU_GET_BULK})


class SnmpError(Exception):
    """Anything that stopped a query. Carries text meant for a person."""


def _encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = b""
    while n:
        body = bytes([n & 0xFF]) + body
        n >>= 8
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(body)) + body


def _encode_int(value: int) -> bytes:
    """
    Non-negative integers only. Every integer this module sends is a request
    identifier, a version number, a repetition count or a zero, so refusing
    negatives costs nothing and removes the two's complement edge cases.
    """
    if value < 0:
        raise ValueError("negative integers are not sent by this module")
    width = (value.bit_length() // 8) + 1
    return _tlv(TAG_INTEGER, value.to_bytes(width, "big"))


def _encode_oid(oid: tuple) -> bytes:
    if len(oid) < 2:
        raise ValueError("an object identifier needs at least two arcs")
    body = bytearray()
    # The first two arcs share one sub-identifier, base-128 like the rest, so
    # 2.999 is two bytes, not one (RVP-14).
    for arc in (oid[0] * 40 + oid[1],) + tuple(oid[2:]):
        if arc < 0:
            raise ValueError("negative arc")
        if arc < 0x80:
            body.append(arc)
            continue
        chunk = bytearray()
        while arc:
            chunk.insert(0, (arc & 0x7F) | 0x80)
            arc >>= 7
        chunk[-1] &= 0x7F
        body.extend(chunk)
    return _tlv(TAG_OID, bytes(body))


def _read_tlv(buf: bytes, index: int) -> tuple:
    """
    One tag/length/value at `index`. Returns (tag, body, next_index).

    Every bound is checked against the actual buffer. A crafted length field
    is the obvious way to make a hand-written decoder read past its input, and
    the answer is to verify rather than to trust the sender.
    """
    if index + 2 > len(buf):
        raise SnmpError("response truncated in a tag header")
    tag = buf[index]
    length = buf[index + 1]
    index += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4:
            raise SnmpError("response uses an unsupported length form")
        if index + count > len(buf):
            raise SnmpError("response truncated in a length field")
        length = int.from_bytes(buf[index:index + count], "big")
        index += count
    if length > len(buf) or index + length > len(buf):
        raise SnmpError("response declares more bytes than it carries")
    return tag, buf[index:index + length], index + length


def _decode_int(body: bytes) -> int:
    return int.from_bytes(body, "big", signed=True) if body else 0


def _decode_oid(body: bytes) -> tuple:
    if not body:
        return ()
    arcs = []
    value = 0
    # S27, 2026-08-28. The bound has to apply PER BYTE, not per completed arc.
    #
    # MAX_OID_ARCS was checked only inside `if not byte & 0x80`, the branch
    # that closes an arc. A body of pure continuation bytes never closes one,
    # so the guard never ran: `value` grew by a 7-bit group per byte and every
    # shift copied the whole integer. Measured at 0.34 seconds of CPU for a
    # 60 KB body of 0xff.
    #
    # walk() allows MAX_WALK_REQUESTS per table and _collect_config walks
    # five, so a gateway answering every request with one maximum-size varbind
    # of continuation bytes costs minutes of CPU per collection pass, every
    # ten minutes. Low severity, because a hostile router has cheaper ways to
    # be unhelpful, chiefly not answering at all. Fixed anyway: the router is
    # explicitly inside this module's threat model, so the cost of a hostile
    # answer should be bounded rather than assumed reasonable.
    #
    # Eight bytes per arc is already far past anything legitimate.
    max_encoded = MAX_OID_ARCS * 8
    for index, byte in enumerate(body):
        if index > max_encoded:
            raise SnmpError("response carries an implausibly long identifier")
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            if not arcs:
                # The first sub-identifier carries two arcs (RVP-14).
                first = 0 if value < 40 else 1 if value < 80 else 2
                arcs.extend((first, value - 40 * first))
            else:
                arcs.append(value)
            value = 0
            if len(arcs) > MAX_OID_ARCS:
                raise SnmpError("response carries an implausibly long identifier")
    return tuple(arcs)


def _decode_value(tag: int, body: bytes):
    """
    A varbind value as something Python can store.

    Unknown tags come back as raw bytes rather than as a guess. A decoder that
    invents a type for a tag it does not know is the lookup-table failure in
    miniature, and the caller here can tell bytes from anything else.
    """
    if tag in _EXCEPTION_TAGS:
        return _MIB_EXCEPTION
    if tag == TAG_INTEGER:
        return _decode_int(body)
    if tag in (TAG_COUNTER32, TAG_GAUGE32, TAG_TIMETICKS, TAG_COUNTER64):
        return int.from_bytes(body, "big") if body else 0
    if tag == TAG_OCTETS or tag == TAG_OPAQUE:
        return body
    if tag == TAG_NULL:
        return None
    if tag == TAG_OID:
        return _decode_oid(body)
    if tag == TAG_IPADDRESS:
        return ".".join(str(b) for b in body) if len(body) == 4 else body
    return body


class _MibException:
    """Distinct from None, which is what a NULL in our own request decodes to."""
    def __repr__(self):
        return "<no such object>"


_MIB_EXCEPTION = _MibException()


# SESSION

class SnmpSession:
    """
    One read-only SNMP v2c conversation with one agent.

    Not a connection. UDP has none; this holds the address, the community and
    the request counter, and each call is an independent datagram exchange
    with its own retries.
    """

    def __init__(self, host: str, community: str, port: int = 161,
                 timeout: float = DEFAULT_TIMEOUT,
                 retries: int = DEFAULT_RETRIES,
                 max_rows: int = MAX_WALK_ROWS):
        self.max_rows  = max(1, min(int(max_rows), MAX_WALK_ROWS_CEILING))
        # Every base whose walk stopped at a limit rather than at its end.
        self.cut_short = set()
        self.host      = host
        self.port      = int(port)
        self.community = community
        self.timeout   = float(timeout)
        self.retries   = max(0, int(retries))
        self._next_id  = 1
        self._family   = None

    def _request_id(self) -> int:
        # Wraps well below the 32-bit signed ceiling. The identifier only has
        # to distinguish this request from the last few, since a reply that
        # arrives after its retry has already been answered is discarded on
        # this check rather than parsed as the wrong answer.
        # Random, not sequential, so a forged reply cannot guess it (RVP-16).
        import secrets
        return secrets.randbelow(0x7FFFFFFE) + 1

    def _resolve(self):
        if self._family is None:
            infos = socket.getaddrinfo(self.host, self.port,
                                       proto=socket.IPPROTO_UDP)
            if not infos:
                raise SnmpError("the configured router address did not resolve")
            self._family, _, _, _, self._sockaddr = infos[0]
        return self._family, self._sockaddr

    def _build(self, pdu_tag: int, request_id: int, oids: list,
               field_a: int = 0, field_b: int = 0) -> bytes:
        if pdu_tag not in _READ_ONLY_PDUS:
            # See _READ_ONLY_PDUS. Unreachable unless someone adds a writer,
            # which is precisely when it needs to fire.
            raise SnmpError("this module only builds read operations")
        varbinds = b"".join(
            _tlv(TAG_SEQUENCE, _encode_oid(oid) + _tlv(TAG_NULL, b""))
            for oid in oids
        )
        pdu = _tlv(pdu_tag, (
            _encode_int(request_id)
            + _encode_int(field_a)
            + _encode_int(field_b)
            + _tlv(TAG_SEQUENCE, varbinds)
        ))
        return _tlv(TAG_SEQUENCE, (
            _encode_int(1)                                      # 1 means v2c
            + _tlv(TAG_OCTETS, self.community.encode("utf-8"))
            + pdu
        ))

    @staticmethod
    def _parse(data: bytes) -> tuple:
        tag, body, _ = _read_tlv(data, 0)
        if tag != TAG_SEQUENCE:
            raise SnmpError("reply is not an SNMP message")
        index = 0
        _, _version, index   = _read_tlv(body, index)
        _, _community, index = _read_tlv(body, index)
        pdu_tag, pdu, index  = _read_tlv(body, index)
        if pdu_tag != PDU_RESPONSE:
            raise SnmpError(f"reply carried protocol data unit 0x{pdu_tag:02x}, "
                            f"not a response")

        cursor = 0
        _, raw_id, cursor    = _read_tlv(pdu, cursor)
        _, raw_error, cursor = _read_tlv(pdu, cursor)
        _, raw_index, cursor = _read_tlv(pdu, cursor)
        _, raw_binds, cursor = _read_tlv(pdu, cursor)

        varbinds = []
        position = 0
        while position < len(raw_binds):
            _, one, position = _read_tlv(raw_binds, position)
            inner = 0
            oid_tag, oid_body, inner = _read_tlv(one, inner)
            val_tag, val_body, inner = _read_tlv(one, inner)
            if oid_tag != TAG_OID:
                raise SnmpError("a variable binding did not start with an "
                                "object identifier")
            varbinds.append((_decode_oid(oid_body),
                             _decode_value(val_tag, val_body)))
            if len(varbinds) > MAX_BINDS_PER_DATAGRAM:
                raise SnmpError("reply carries more bindings than this tool "
                                "will read in one datagram")

        return (_decode_int(raw_id), _decode_int(raw_error),
                _decode_int(raw_index), varbinds)

    def _exchange(self, payload: bytes, request_id: int) -> tuple:
        family, sockaddr = self._resolve()
        last_error = None

        for _attempt in range(self.retries + 1):
            sock = socket.socket(family, socket.SOCK_DGRAM)
            try:
                sock.settimeout(self.timeout)
                sock.sendto(payload, sockaddr)
                deadline_hits = 0
                while deadline_hits < 4:
                    data, peer = sock.recvfrom(MAX_DATAGRAM)
                    # A datagram from anywhere else is discarded rather than
                    # parsed. Spoofing a UDP source is not hard, but accepting
                    # a reply from an address we never asked is free to avoid.
                    if peer[0] != sockaddr[0] or peer[1] != sockaddr[1]:
                        deadline_hits += 1
                        continue
                    # A datagram that does not parse is dropped and the wait
                    # goes on: one forged packet must not end the collection
                    # (RVP-16).
                    try:
                        parsed = self._parse(data)
                    except SnmpError as e:
                        last_error = e
                        deadline_hits += 1
                        continue
                    if parsed[0] != request_id:
                        # A late reply to a previous attempt. Keep waiting for
                        # the one that answers this request.
                        deadline_hits += 1
                        continue
                    return parsed
                last_error = last_error or SnmpError(
                    "no reply matched the request that was sent")
            except socket.timeout:
                last_error = last_error or SnmpError(
                    "the router did not answer in time")
            except (ConnectionResetError, ConnectionRefusedError) as e:
                # NOTHING IS LISTENING. 2026-09-05.
                #
                # UDP with no listener gets an ICMP port-unreachable back, and
                # the socket surfaces that as a reset. On Windows it reads
                # "[WinError 10054] An existing connection was forcibly closed
                # by the remote host", which for a UDP request to a router that
                # is not running SNMP is a sentence describing something that
                # never happened.
                #
                # It is still the same fact as a timeout: the router did not
                # answer. It just said so faster. So the message leads with
                # that, and the platform's own words come after, for whoever
                # is actually debugging.
                #
                # Found by tests/test_router_monitor.py, which points the
                # client at a dead port and asserts the phrase "did not
                # answer". It got the WinError sentence instead, so the test
                # was red on Windows and would have passed on Linux, which is
                # its own small warning about where this has been run.
                last_error = SnmpError(
                    f"the router did not answer: nothing is listening on that "
                    f"port, or a firewall refused it ({e})")
            except OSError as e:
                last_error = SnmpError(f"network error talking to the router: {e}")
            except SnmpError as e:
                # A malformed reply is not worth retrying; the agent will send
                # the same thing again.
                raise e
            finally:
                sock.close()

        raise last_error or SnmpError("the router did not answer")

    def get(self, oids: list) -> dict:
        """One GetRequest. Returns {oid tuple: value} for what came back."""
        request_id = self._request_id()
        payload = self._build(PDU_GET, request_id, oids)
        _, error_status, error_index, varbinds = self._exchange(payload, request_id)
        if error_status:
            # noSuchName on a GET means one identifier is unsupported, which is
            # ordinary across vendors. Report empty rather than failing the
            # whole collection over an optional field.
            logger.debug(f"SNMP get returned error status {error_status} "
                         f"at index {error_index}")
            return {}
        return {oid: value for oid, value in varbinds
                if not isinstance(value, _MibException)}

    def walk(self, base: tuple, max_rows: int = None) -> list:
        """
        Every row under `base`, as a list of (oid tuple, value).

        GetBulk first because a neighbour table is a round trip per row
        otherwise, falling back to GetNext when the agent refuses bulk, which
        some consumer firmware does despite answering as v2c.

        THE LOOP TERMINATES ON FOUR SEPARATE CONDITIONS: leaving the subtree,
        an end-of-view marker, a returned identifier that is not greater than
        the one asked for, and a hard request cap. The third is the one that
        matters, because a buggy or hostile agent that keeps answering with
        the same identifier is otherwise an infinite loop, and that has been a
        real failure mode in SNMP tooling for decades.
        """
        max_rows = self.max_rows if max_rows is None else max_rows
        rows = []
        cursor = base
        use_bulk = True
        requests = 0
        # An agent that refuses bulk answers one row per request, so the
        # request limit has to cover the row limit (RVP-15).
        request_cap = max(MAX_WALK_REQUESTS, max_rows + 10)

        while requests < request_cap:
            requests += 1
            request_id = self._request_id()
            if use_bulk:
                payload = self._build(PDU_GET_BULK, request_id, [cursor],
                                      field_a=0, field_b=BULK_REPETITIONS)
            else:
                payload = self._build(PDU_GET_NEXT, request_id, [cursor])

            _, error_status, _, varbinds = self._exchange(payload, request_id)

            if error_status and use_bulk:
                logger.debug("Agent refused GetBulk; falling back to GetNext.")
                use_bulk = False
                continue
            if error_status:
                break
            if not varbinds:
                break

            advanced = False
            for oid, value in varbinds:
                if oid[:len(base)] != base:
                    return rows                     # left the subtree
                if isinstance(value, _MibException):
                    return rows                     # end of view
                if oid <= cursor:
                    # Not moving forward. Stop rather than ask again.
                    return rows
                cursor = oid
                advanced = True
                rows.append((oid, value))
                if len(rows) >= max_rows:
                    logger.warning(
                        f"SNMP walk stopped at the {max_rows} row cap. The "
                        f"table is larger than this tool will read in one pass."
                    )
                    self.cut_short.add(base)
                    return rows
            if not advanced:
                break
        else:
            logger.warning(f"SNMP walk stopped after {request_cap} requests "
                           f"with {len(rows)} rows read; the table was not "
                           f"finished.")
            self.cut_short.add(base)

        return rows


# OBJECT IDENTIFIERS
#
# Standard MIB-II only. Nothing vendor specific, because Rule 1 says this has
# to run on networks it has never seen, and a private identifier that means
# one thing on one vendor's firmware and something else on another is the
# lookup-table failure with a numeric label instead of a name.

OID_SYS_DESCR     = (1, 3, 6, 1, 2, 1, 1, 1, 0)
OID_SYS_OBJECT_ID = (1, 3, 6, 1, 2, 1, 1, 2, 0)
OID_SYS_UPTIME    = (1, 3, 6, 1, 2, 1, 1, 3, 0)
OID_SYS_NAME      = (1, 3, 6, 1, 2, 1, 1, 5, 0)
OID_IP_FORWARDING = (1, 3, 6, 1, 2, 1, 4, 1, 0)

# ipNetToMediaTable. Index is ifIndex followed by the four arcs of the address,
# so both are read straight out of the identifier and neither is a guess.
OID_ARP_PHYS = (1, 3, 6, 1, 2, 1, 4, 22, 1, 2)
OID_ARP_TYPE = (1, 3, 6, 1, 2, 1, 4, 22, 1, 4)

# ipAddrTable, the addresses the router itself holds. Index is the address.
OID_IP_ADDR_IFINDEX = (1, 3, 6, 1, 2, 1, 4, 20, 1, 2)
OID_IP_ADDR_NETMASK = (1, 3, 6, 1, 2, 1, 4, 20, 1, 3)

OID_IF_DESCR = (1, 3, 6, 1, 2, 1, 2, 2, 1, 2)

# tcpConnTable state column. Index is local address, local port, remote
# address, remote port. State 2 is listen.
OID_TCP_CONN_STATE = (1, 3, 6, 1, 2, 1, 6, 13, 1, 1)
TCP_STATE_LISTEN = 2

# udpTable local address column. Index is local address followed by port.
OID_UDP_LOCAL_ADDRESS = (1, 3, 6, 1, 2, 1, 7, 5, 1, 1)

ARP_TYPES = {1: "other", 2: "invalid", 3: "dynamic", 4: "static"}


# HELPERS

def _text(value, limit: int = MAX_STRING_BYTES) -> str:
    """A router-supplied byte string as text, bounded, never raising."""
    if value is None or isinstance(value, _MibException):
        return None
    if isinstance(value, bytes):
        value = value[:limit].decode("utf-8", errors="replace")
    else:
        value = str(value)
    # Control characters are dropped: this text reaches logs and findings,
    # and the router chooses it (RVP-17).
    value = "".join(c if c.isprintable() else " " for c in value).strip()
    return value[:limit] or None


def _mac(value) -> str:
    """A physical address as lower-case colon-separated hex, or None."""
    # 6 bytes, or 8 for EUI-64; anything else is not a hardware address
    # and is not stored (RVP-17).
    if not isinstance(value, bytes) or len(value) not in (6, 8):
        return None
    return ":".join(f"{b:02x}" for b in value)


def _human_uptime(ticks: int) -> str:
    """
    SNMP TimeTicks as something a person reads.

    TimeTicks is hundredths of a second and wraps at 2^32, so the raw number
    is unreadable and, past 497 days, is also meaningless without saying so.
    """
    seconds = max(0, int(ticks)) / 100.0
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        text = f"{days} day(s) {hours} hour(s)"
    elif hours:
        text = f"{hours} hour(s) {minutes} minute(s)"
    else:
        text = f"{minutes} minute(s)"
    if seconds >= 42949672.95:
        # The counter has wrapped at least once, so the number is a LOWER
        # bound and saying "up N days" without that would be a claim the
        # router's own field cannot support.
        text += " (the counter has wrapped; this is a lower bound)"
    return text


def _address_from_arcs(arcs: tuple) -> str:
    """Four identifier arcs as a dotted address, or None if they are not one."""
    if len(arcs) != 4 or any(not 0 <= a <= 255 for a in arcs):
        return None
    return ".".join(str(a) for a in arcs)


def _bound_scope(address: str) -> str:
    """
    What an address a service is bound to means, as a fact rather than a
    verdict. 'all_interfaces' is the one worth naming: a listener on the
    unspecified address is reachable on every interface the router has,
    including whichever one faces the internet. Whether that is wrong here
    depends on which service it is and what the router is for, and that
    judgement is not Python's to make.
    """
    import ipaddress
    if not address:
        return "unknown"
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        return "unknown"
    if addr.is_unspecified:
        return "all_interfaces"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private or addr.is_link_local:
        return "private"
    return "public"


def _router_sensor_id(host: str) -> str:
    """
    A stable sensor identifier for one router, carrying no address.

    Hashed for the same reason core/sensors._stable_local_id hashes the
    hostname: the identifier ends up in rows, in logs, and in anything the
    model reads back, and scripts/check_no_local_details would fail the build
    on a private address appearing in source. It should fail on one appearing
    in a row too.

    IT HASHES THE NORMALISED ADDRESS, NOT THE STRING IN config.json. RVP-2,
    2026-09-27. Hashed raw, `192.0.2.1` and `192.0.2.01` produced two different
    sensors, two different inventories and a "device not seen before" finding
    for every device on the network — measured by driving _router_sensor_id
    and save_router_clients with both spellings. The configured address is
    typed by a person, and a person who types a leading zero, a trailing
    space or a trailing dot means the same router every time.
    """
    from core import sensors as sn
    digest = hashlib.sha256(
        _normalise_router_host(host).encode("utf-8")).hexdigest()[:8]
    return f"{sn.LOCAL_SENSOR_ID}-gwapi-{digest}"


def _normalise_router_host(host: str) -> str:
    """
    One spelling per router, so two spellings cannot become two inventories.

    Rules, in order, and each one is a way a real config file gets written:
      * surrounding whitespace and case are not part of an address;
      * a fully qualified name with its root dot ('router.lan.') is the same
        host as 'router.lan';
      * an IPv4 quad with leading zeros is the same address, and is turned
        into the canonical form rather than left as typed. `ipaddress` refuses
        a leading-zero quad outright, so the zeros are collapsed first and the
        result is parsed back to prove it is still an address;
      * anything else is returned lower-cased and stripped, which is all that
        can be said about it without a resolver.
    """
    import ipaddress

    text = (host or "").strip().lower()
    if not text:
        return ""
    if len(text) > 1 and text.endswith("."):
        text = text[:-1]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    parts = text.split(".")
    if len(parts) == 4 and all(p.isdigit() and len(p) <= 3 for p in parts):
        try:
            return str(ipaddress.ip_address(".".join(str(int(p)) for p in parts)))
        except ValueError:
            return text
    return text


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# CONFIGURATION AND AVAILABILITY

def status(config: dict) -> dict:
    """
    Is router monitoring configured and usable, and if not, exactly why?

    The reason string is the point. A collector that is off and a collector
    that ran and found nothing produce the same empty table, and the whole
    project turns on keeping those two apart; web_search reports
    searched=false for the same reason. The dashboard shows this text, and the
    model is told the collector is unavailable rather than being left to read
    an empty table as an empty network.

    THE ADDRESS IS NEVER ECHOED BACK. It is in config.json, which is
    gitignored because it is a map of the operator's network, and a reason
    string reaches logs and the model.

    A TYPED VALUE THAT IS NOT A NUMBER IS A REASON, NOT A TRACEBACK. RVP-3,
    2026-09-27. `int(port)` and `float(timeout)` were called unguarded here,
    and this function is the FIRST thing the boot path calls for this module
    (main.py), the first thing the dashboard toggle calls, and the first thing
    ensure_collector's loop calls on every tick. MEASURED with a config
    carrying `"port": "sixteen-hundred"`: ValueError. And with
    `"timeout_seconds": "slow"`: ValueError. So a typo in a hand-edited
    config.json did not produce a sentence saying what was wrong with it — it
    produced a traceback in the boot log, where the operator's own mistake
    is reported as a crash of the tool, and the panel had nothing to show.
    """
    from core import secret_store

    block = (config or {}).get("router_monitor", {}) or {}

    if not block.get("enabled"):
        return {"available": False, "configured": bool(block.get("host")),
                "reason": "turned off in config.json"}

    backend = block.get("backend", SOURCE_SNMP)
    if backend not in VALID_BACKENDS:
        return {"available": False, "configured": False,
                "reason": (f"backend must be one of {sorted(VALID_BACKENDS)}, "
                           f"got {backend!r}")}

    host = (block.get("host") or "").strip()
    if not host:
        return {"available": False, "configured": False,
                "reason": "no router address set in config.json"}

    try:
        port = int(block.get("port", 161))
    except (TypeError, ValueError):
        return {"available": False, "configured": True,
                "reason": (f"router_monitor.port is not a number: "
                           f"{block.get('port')!r}")}

    try:
        timeout = float(block.get("timeout_seconds", DEFAULT_TIMEOUT))
    except (TypeError, ValueError):
        return {"available": False, "configured": True,
                "reason": (f"router_monitor.timeout_seconds is not a number: "
                           f"{block.get('timeout_seconds')!r}")}

    try:
        max_rows = max(1, min(int(block.get("max_rows_per_table", MAX_WALK_ROWS)),
                              MAX_WALK_ROWS_CEILING))
    except (TypeError, ValueError):
        return {"available": False, "configured": True,
                "reason": (f"router_monitor.max_rows_per_table is not a "
                           f"number: {block.get('max_rows_per_table')!r}")}

    community = secret_store.router_community()
    if not community:
        return {
            "available": False, "configured": True,
            "reason": (f"no read community string. Set "
                       f"{secret_store.ENV_ROUTER_COMMUNITY} in .env"),
        }

    return {
        "available": True,
        "configured": True,
        "backend": backend,
        "host": host,
        "port": port,
        "community": community,
        "timeout": timeout,
        "max_rows": max_rows,
        "reason": None,
    }


def public_status(config: dict) -> dict:
    """
    status() with the credential and the address removed, for the dashboard
    and the REST layer. Two functions rather than one with a flag, because a
    flag defaults wrong exactly once and the value it leaks is a credential.
    """
    state = status(config)
    return {
        "available":  state["available"],
        "configured": state.get("configured", False),
        "backend":    state.get("backend", SOURCE_SNMP),
        "reason":     state.get("reason"),
    }


# COLLECTION

def _collect_clients(session: SnmpSession) -> list:
    """
    The router's neighbour table, one entry per row.

    Physical addresses and entry types are walked separately and joined on the
    identifier suffix, because the suffix IS the index: interface number
    followed by the four arcs of the network address. Reading the address out
    of the index rather than out of a second column means the join cannot
    silently pair the wrong two values.

    THE TYPE WALK CANNOT TAKE THE LIST DOWN WITH IT. RVP-5, 2026-09-27.
    Both walks used to sit inside one `SnmpError` handler in collect_once, so
    a router that refuses ipNetToMediaType — an optional column, and one a
    consumer firmware is free to omit — lost the ENTIRE neighbour table,
    which is the only reason this sensor exists. Measured by pointing the
    shipped collector at an agent with the type column removed: the address
    walk answered three entries and `ran` came back False. The type is
    decoration; the addresses are the inventory. A failure in the decoration
    now costs exactly the decoration and is COUNTED so it is visible.
    """
    from tools.network_scanner import _oui_lookup

    prefix = len(OID_ARP_PHYS)
    physical, types = {}, {}

    for oid, value in session.walk(OID_ARP_PHYS):
        suffix = oid[prefix:]
        if len(suffix) != 5:
            continue
        physical[suffix] = value

    types_readable = True
    try:
        for oid, value in session.walk(OID_ARP_TYPE):
            suffix = oid[prefix:]
            if len(suffix) == 5:
                types[suffix] = value
    except SnmpError as e:
        types_readable = False
        logger.info(f"Router entry types could not be read ({e}); the "
                    f"neighbour table is still being recorded, with the entry "
                    f"type reported as unknown rather than guessed at.")

    clients = []
    for suffix, raw in sorted(physical.items()):
        address = _address_from_arcs(suffix[1:])
        if not address:
            continue
        mac = _mac(raw)
        vendor = _oui_lookup(mac) if mac else "Unknown"
        clients.append({
            "ip":         address,
            "mac":        mac,
            "hostname":   None,   # standard MIB-II carries no device name
            "vendor":     vendor if vendor != "Unknown" else None,
            "interface":  str(suffix[0]),
            "entry_type": (ARP_TYPES.get(types.get(suffix), "unknown")
                           if types_readable else "unknown"),
            "source":     "snmp:ipNetToMediaTable",
        })
    return clients


def _collect_config(session: SnmpSession) -> list:
    """
    The router's own settings, as settings rather than as prose.

    One row per thing, so that a change to any one of them is a change to one
    row and the previous value is recoverable. A single blob would make every
    collection look like a change to everything.
    """
    settings = []

    system = session.get([OID_SYS_DESCR, OID_SYS_OBJECT_ID,
                          OID_SYS_NAME, OID_SYS_UPTIME, OID_IP_FORWARDING])

    description = _text(system.get(OID_SYS_DESCR))
    if description:
        settings.append({
            "setting": "sysDescr",
            "value":   description,
            "detail":  {"note": ("The router's own description of its firmware. "
                                 "A version string here is a PRIOR to look up, "
                                 "not a vulnerability. Nothing in this tool "
                                 "matches it against a vulnerability list, for "
                                 "the same reason software_inventory does not.")},
        })

    name = _text(system.get(OID_SYS_NAME))
    if name:
        settings.append({"setting": "sysName", "value": name, "detail": None})

    object_id = system.get(OID_SYS_OBJECT_ID)
    if isinstance(object_id, tuple) and object_id:
        settings.append({
            "setting": "sysObjectID",
            "value": ".".join(str(a) for a in object_id),
            "detail": {"note": "The vendor's own identifier for this model."},
        })

    forwarding = system.get(OID_IP_FORWARDING)
    if isinstance(forwarding, int):
        settings.append({
            "setting": "ipForwarding",
            "value": "forwarding" if forwarding == 1 else "not_forwarding",
            "detail": {"raw": forwarding},
        })

    # sysUpTime WAS FETCHED ON EVERY PASS AND READ BY NOTHING, RVP-10,
    # 2026-09-27. It is in the GET list above and no branch ever consumed it,
    # so the one value that says "this router rebooted" was being collected and
    # dropped. That matters more here than the field's size suggests, because
    # a REBOOT IS THIS MODULE'S WORST FALSE-POSITIVE SOURCE: the neighbour
    # table flushes and refills with devices this store already holds, and the
    # setting changes a firmware update or a reboot produces are the ones RTR
    # findings keep asking the reader to attribute. Measured before the fix:
    # a reboot with the table refilling produced no finding at all in one
    # direction (nothing named the reboot) and the config leg reported a whole
    # first configuration in the other. Recorded as a setting so its own
    # change is one row like every other, with the value in human units
    # because "3 years" is read and "108,000,000" is not.
    uptime_ticks = system.get(OID_SYS_UPTIME)
    if isinstance(uptime_ticks, int):
        settings.append({
            "setting": "sysUpTime",
            "value": _human_uptime(uptime_ticks),
            "detail": {
                "timeticks": uptime_ticks,
                "seconds": uptime_ticks / 100.0,
                "note": ("How long the router says it has been up. A change "
                         "here that is not a change in its firmware or its "
                         "settings is a REBOOT, and a reboot is what makes the "
                         "neighbour table flush and refill: the same devices "
                         "reappearing afterwards are not arrivals."),
            },
        })

    # The router's own addresses. Useful on its own, and it is what lets a
    # reader tell a listener bound to the inside from one bound to the outside.
    prefix = len(OID_IP_ADDR_IFINDEX)
    own_addresses = []
    for oid, value in session.walk(OID_IP_ADDR_IFINDEX):
        address = _address_from_arcs(oid[prefix:])
        if address:
            own_addresses.append({"address": address, "interface": str(value)})
    if own_addresses:
        settings.append({
            "setting": "ownAddresses",
            "value": str(len(own_addresses)),
            "detail": {"addresses": own_addresses},
        })

    interfaces = {}
    for oid, value in session.walk(OID_IF_DESCR):
        label = _text(value, limit=64)
        if label:
            interfaces[str(oid[-1])] = label
    if interfaces:
        settings.append({
            "setting": "interfaces",
            "value": str(len(interfaces)),
            "detail": {"interfaces": interfaces},
        })

    # What the router itself is listening on. This is the closest a standard
    # MIB gets to "is the administration interface exposed", and it stops
    # short of answering it: a listener on every interface MAY be reachable
    # from outside, and whether it actually is depends on rules this cannot
    # see. Recorded as an observation for that reason, with no severity.
    #
    # THE SETTING NAME CARRIES THE BOUND ADDRESS, RVP-4, 2026-09-27.
    #
    # It used to be `listener:tcp:{port}` and the bound address was only in
    # the detail JSON, so TWO ROWS WITH ONE NAME were being written in the
    # same pass whenever a router answered the same port at more than one
    # address: `router_config` is UNIQUE(router_host, setting), so the second
    # row UPDATED the first and each pass flip-flopped the stored value.
    # MEASURED against an agent answering tcp/22 at both 0.0.0.0 and the
    # router's own address: after the first pass the row read 'private' with
    # previous 'all_interfaces', and every later pass over an UNCHANGED router
    # reported it as changed again — four RTR-1002 rows over three passes on
    # a router that never changed, and that router genuinely has an
    # administration port open on a second address that this could never
    # report. The name is now the listener's own identity, so each one gets
    # its own row and its own previous value.
    prefix = len(OID_TCP_CONN_STATE)
    for oid, value in session.walk(OID_TCP_CONN_STATE):
        if value != TCP_STATE_LISTEN:
            continue
        suffix = oid[prefix:]
        if len(suffix) != 10:
            continue
        local = _address_from_arcs(suffix[0:4])
        port = suffix[4]
        if not local or not 0 <= port <= 65535:
            continue
        scope = _bound_scope(local)
        settings.append({
            "setting": f"listener:tcp:{port}:{local}",
            "value": f"{scope}",
            "detail": {"protocol": "tcp", "port": port,
                       "bound_to": local, "scope": scope,
                       "note": ("bound_to is where the router says the service "
                                "is listening. 'all_interfaces' means every "
                                "interface the router has, which includes the "
                                "one facing the internet, but whether it is "
                                "reachable from there depends on filtering "
                                "this tool cannot observe.")},
        })

    prefix = len(OID_UDP_LOCAL_ADDRESS)
    for oid, _value in session.walk(OID_UDP_LOCAL_ADDRESS):
        suffix = oid[prefix:]
        if len(suffix) != 5:
            continue
        local = _address_from_arcs(suffix[0:4])
        port = suffix[4]
        if not local or not 0 <= port <= 65535:
            continue
        settings.append({
            "setting": f"listener:udp:{port}:{local}",
            "value": f"{_bound_scope(local)}",
            "detail": {"protocol": "udp", "port": port, "bound_to": local},
        })

    return settings


def collect_once(config: dict, session_id: str = None) -> dict:
    """
    One collection pass. Safe to call repeatedly; finding nothing new writes
    no rows.

    Registers its own sensor at position 'gateway_api' rather than reusing the
    host sensor, because it is a different vantage point with a completely
    different blind spot. A device silent in the neighbour table and a device
    silent in packets are silent for unrelated reasons, and only the sensor
    row says which.
    """
    from core import memory_engine as me
    from core import sensors as sn

    state = status(config)
    if not state["available"]:
        return {"ran": False, "reason": state["reason"],
                "clients_new": 0, "clients_seen": 0, "config_changed": 0}

    host = state["host"]
    sensor_id = _router_sensor_id(host)
    scope = sn.describe("gateway_api")
    me.upsert_sensor(
        sensor_id=sensor_id,
        # None here does NOT erase a label: upsert_sensor's own
        # `COALESCE(excluded.label, sensors.label)` carries the stored one
        # over, and the dashboard's label control writes through that same
        # function. Measured 2026-09-27 both ways before leaving this alone.
        label=(config.get("router_monitor", {}) or {}).get("label"),
        position="gateway_api",
        summary=scope["summary"],
        can_see=scope["can_see"],
        cannot_see=scope["cannot_see"],
        notes=("Read from a router's management interface over SNMP v2c by "
               "tools/router_monitor.py. Read operations only; this collector "
               "implements no write operation."),
    )

    session = SnmpSession(host, state["community"], port=state["port"],
                          timeout=state["timeout"],
                          max_rows=state.get("max_rows", MAX_WALK_ROWS))

    try:
        clients = _collect_clients(session)
    except SnmpError as e:
        logger.warning(f"Router client collection failed: {e}")
        return {"ran": False, "reason": str(e),
                "clients_new": 0, "clients_seen": 0, "config_changed": 0}

    try:
        settings = _collect_config(session)
    except SnmpError as e:
        # A router that answers the neighbour table but refuses the rest is
        # common, and half a collection is worth keeping.
        logger.info(f"Router configuration collection incomplete: {e}")
        settings = []

    # THE FIRST PASS IS NOT A SET OF CHANGES, AND "FIRST PASS" IS PER LEG.
    # RVP-8, 2026-09-27. A single `router_has_history(host)` covers both
    # tables, so it is TRUE as soon as either one holds a row — and a router
    # whose client list was recorded on an earlier run, while its SETTINGS
    # half failed (a router that answers the neighbour table and refuses the
    # rest is named in this file as common), produced one RTR-1002 per setting
    # on the next run: measured, three findings reading "The router's sysDescr
    # changed" about a value no earlier pass had ever held. The client leg is
    # therefore baselined on the CLIENT table and the settings leg on the
    # SETTINGS table, which is what the sentence below has always claimed.
    clients_baseline = me.router_has_history(host, table="clients")
    config_baseline = me.router_has_history(host, table="config")

    client_result = me.save_router_clients(clients, router_host=host,
                                           sensor_id=sensor_id)
    config_result = me.save_router_config(settings, router_host=host,
                                          source=f"{SOURCE_SNMP}:mib2",
                                          sensor_id=sensor_id)

    findings = 0
    if session_id:
        if clients_baseline:
            findings += _raise_client_findings(
                client_result["new"], host, session_id, sensor_id)
        elif client_result["new"]:
            logger.info(
                f"Router collection: first pass for this router, "
                f"{len(client_result['new'])} neighbour entries recorded as "
                f"the baseline. Nothing is reported as new on a first pass, "
                f"because everything would be.")
        if config_baseline:
            findings += _raise_config_findings(
                config_result["changed"], host, session_id, sensor_id)
        elif config_result["changed"]:
            logger.info(
                f"Router collection: first pass for this router's SETTINGS, "
                f"{len(config_result['changed'])} setting(s) recorded as the "
                f"baseline. A router that answered its neighbour table on an "
                f"earlier pass and refused the rest is the case this covers.")

    logger.info(
        f"Router collection: {client_result['seen']} neighbour entries, "
        f"{len(client_result['new'])} not seen before, "
        f"{len(config_result['changed'])} setting(s) changed."
    )

    return {
        "ran": True,
        "reason": None,
        "sensor_id": sensor_id,
        "clients_seen": client_result["seen"],
        "clients_new": len(client_result["new"]),
        # A TABLE THIS TOOL STOPPED READING AT ITS CAP IS NOT A COMPLETE
        # TABLE, RVP-9, 2026-09-27. walk() caps a table at MAX_WALK_ROWS and
        # logs a WARNING, and nothing on the result said so: measured against
        # an agent with 2600 neighbour entries, `clients_seen` came back 2000
        # with no field anywhere naming the cut. A reader — the panel, or the
        # model — sees a number and has no way to tell a 2000-row network from
        # a table that was cut short, which is this project's oldest shape.
        "clients_truncated": OID_ARP_PHYS in session.cut_short,
        "max_rows_per_table": session.max_rows,
        "config_settings": config_result["seen"],
        "config_changed": len(config_result["changed"]),
        "findings_raised": findings,
        "first_pass": not (clients_baseline or config_baseline),
        "collected_at": _now_iso(),
    }


# THE COLLECTOR THREAD
#
# The thread is owned here rather than in main.py because the dashboard's
# toggle has to be able to start one, and a collector that can only be started
# at boot means the toggle is a setting the operator has to restart to apply.
#
# WHAT THE TOGGLE TURNS ON IS THIS LOOP, NOT THE CREDENTIAL. The community
# string lives in .env and is never written, cleared or read by the toggle. A
# switch that manages a credential is a switch that can lose one, and it
# conflates two states that have to stay apart: configured, and running.

_collector_thread = None


def collector_running() -> bool:
    return _collector_thread is not None and _collector_thread.is_alive()


def ensure_collector(config: dict, session_id: str) -> bool:
    """
    Start the collection loop if it is not already running. Idempotent.

    Returns whether a loop is running afterwards. Nothing is started when the
    collector is unavailable, so a toggle flipped on without a credential
    behaves the same as one that was never flipped: nothing happens, and
    status() says why.
    """
    global _collector_thread

    if collector_running():
        return True
    if not status(config)["available"]:
        return False

    import threading

    block = (config or {}).get("router_monitor", {}) or {}
    interval = max(1, int(block.get("interval_minutes", 10))) * 60

    def loop():
        while True:
            try:
                # config is read every pass rather than captured, so turning
                # the collector off in the dashboard stops the work on the
                # next tick instead of needing the thread killed.
                if not status(config)["available"]:
                    logger.info("Router collection paused; the collector is "
                                "no longer available or has been turned off.")
                    return
                result = collect_once(config, session_id=session_id)
                if not result.get("ran"):
                    logger.warning(f"Router collection skipped: "
                                   f"{result.get('reason')}")
                elif result.get("first_pass"):
                    logger.info(
                        f"Router collection: first pass, "
                        f"{result.get('clients_seen', 0)} neighbour entries "
                        f"recorded as the baseline. Nothing is reported as "
                        f"new on a first pass, because everything would be."
                    )
            except Exception as e:
                logger.error(f"Router collection error: {e}")
            time.sleep(interval)

    _collector_thread = threading.Thread(
        target=loop, name="router-collector", daemon=True)
    _collector_thread.start()
    logger.info(f"Router collector started, every {interval // 60} minute(s).")
    return True


def _raise_client_findings(new_clients: list, host: str, session_id: str,
                           sensor_id: str) -> int:
    """
    One finding per device the router names that this store has never held.

    THE ROUTER'S OWN RAISERS OBEY THE TWO RULES EVERY SIBLING OBEYS, and
    until 2026-09-27 they obeyed neither. RVP-7.

      * A DISMISSED ADDRESS IS NOT RAISED ABOUT. Every other raiser in this
        tree asks is_dismissed first (adapters.py at ten call sites,
        network_scanner, linux_monitor); these two did not, so an operator
        who dismissed a device to quiet a scan finding kept getting the same
        device back from the router on every collection. Measured: with
        'ip' '192.0.2.10' dismissed, _raise_client_findings returned 1 and
        wrote a row anyway.
      * A CONDITION ALREADY OPEN IS NOT RAISED AGAIN. memory_engine's
        finding_already_open is what keeps a standing condition to one row —
        it is why the DNS round had to de-number its titles (DNS-7). This
        sensor's titles carry no numbers, so the guard is all that was
        missing. MEASURED on a persistent drift with the guard absent:
        three passes over one unchanged device wrote three rows.

    The count returned is the number of rows that LANDED, not the number the
    loop walked past — the same distinction adapters.py's _finding_landed was
    written for, and the reason its router counts must not repeat the defect
    one file over.
    """
    from core import memory_engine as me

    raised = 0
    for client in new_clients:
        if me.is_dismissed("ip", client["ip"]):
            logger.debug(f"RTR-1001 not raised for {client['ip']}: dismissed")
            continue
        title = f"Router reports a device not seen before: {client['ip']}"
        if me.finding_already_open("router_monitor", "ip", client["ip"], title):
            logger.debug(f"RTR-1001 not raised for {client['ip']}: already "
                         f"open")
            continue
        res = me.save_finding(
            session_id=session_id,
            source="router_monitor",
            detection_id="RTR-1001",
            severity="medium",
            entity_type="ip",
            entity_value=client["ip"],
            title=title,
            description=(
                f"Hardware address {client.get('mac') or 'unknown'}, vendor "
                f"{client.get('vendor') or 'unknown'}, entry type "
                f"{client.get('entry_type')}.\n\n"
                f"THIS CAME FROM THE ROUTER, NOT FROM THIS HOST. The router "
                f"exchanged traffic with this device, which means the device "
                f"is real and reachable regardless of whether a scan from "
                f"here can see it. It does NOT mean the device did anything "
                f"in particular; a neighbour table records contact, not "
                f"content.\n\n"
                f"The vendor above is derived from the hardware address "
                f"prefix and names whoever made the network chip, which for "
                f"most consumer hardware is not who made the device. It is "
                f"not an identification. Ask what this is, then record the "
                f"answer with identify_device so the next session does not "
                f"have to work it out again."
            ),
            raw_data=client,
            sensor_id=sensor_id,
        )
        if not (isinstance(res, dict) and res.get("saved") is False):
            raised += 1
    return raised


def _raise_config_findings(changes: list, host: str, session_id: str,
                           sensor_id: str) -> int:
    """One finding per setting that changed, or disappeared.

    Same two rules as _raise_client_findings above, and the same measurement:
    a dismissed router address must not be raised about, and a change that is
    still the newest value on its row must not be re-raised on the next tick.
    """
    from core import memory_engine as me

    raised = 0
    for change in changes:
        setting = change["setting"]
        before = change.get("previous_value")
        after = change.get("value")
        gone = change.get("removed")

        if gone:
            headline = f"The router stopped reporting {setting}"
            body = (f"It last held {before!r}. A setting that disappears is a "
                    f"change in the same way a new one is; a service that "
                    f"stopped listening and a firmware update that renamed "
                    f"the entry look identical here.")
        else:
            headline = f"The router's {setting} changed"
            body = (f"It was {before!r} and is now {after!r}.")

        if me.is_dismissed("ip", host):
            logger.debug(f"RTR-1002 not raised for {host}: dismissed")
            continue
        # THE TITLE IS THE DEDUPE KEY, and it is built ONCE above so the guard
        # and the write cannot drift apart. finding_already_open compares the
        # STORED title, so a key assembled from anything else (a composite of
        # setting, value and flag) never matches a row that exists and the
        # guard would be dead code that reads as protection.
        #
        # A SETTING APPEARING FOR THE FIRST TIME IS STILL A CHANGE, by this
        # module's own documented design ("a setting appearing for the first
        # time" is one of the three cases save_router_config lists), and it is
        # a real event: a service that started listening is worth knowing
        # about. What was wrong was the BASELINE, not this branch — see the
        # per-leg fix at collect_once.
        if me.finding_already_open("router_monitor", "ip", host, headline):
            logger.debug(f"RTR-1002 not raised for {setting}: already open")
            continue

        res = me.save_finding(
            session_id=session_id,
            source="router_monitor",
            detection_id="RTR-1002",
            severity="medium",
            entity_type="ip",
            entity_value=host,
            title=headline,
            description=(
                f"{body}\n\n"
                f"WHAT THIS IS AND IS NOT. This is a measurement against a "
                f"value recorded earlier, not an opinion about what the "
                f"setting means. Nothing in Python here decided that this "
                f"change is bad. Read the setting, the two values, and what "
                f"the router is for, and say plainly if the change is "
                f"explainable by an update or a reboot.\n\n"
                f"WHY THE GATEWAY IS WORTH THE ATTENTION. It is the one "
                f"device whose compromise defeats this tool rather than "
                f"merely evading it: change the resolver addresses handed out "
                f"by DHCP and the resolver sensor is watching a resolver "
                f"nothing uses, and open a port inward and no sensor at "
                f"position 'host' can observe it."
            ),
            raw_data=change,
            sensor_id=sensor_id,
        )
        if not (isinstance(res, dict) and res.get("saved") is False):
            raised += 1
    return raised
