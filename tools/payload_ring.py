# tools/payload_ring.py
# AgentalSec V2, TODO 113.6. Targeted payload capture with a ring buffer.
# THE OWNER'S IDEA, 2026-09-15. Built 2026-09-20.
#
# THE PROBLEM THE OWNER NAMED, WHICH IS THE ONLY REASON THIS IS NOT JUST A FLAG
#
# The database-size objection to keeping payload goes away if capture can be
# switched on for ONE destination instead of for everything. That part is
# easy. The hard part is the timing:
#
#   You only decide to capture AFTER something looks interesting. By then the
#   bytes that made you curious are already gone.
#
# It is worse for TLS, where the ClientHello is the FIRST packet of the
# connection. Flipping capture on after a detection catches the next
# connection and never the one that raised the question. The owner's words, and they
# are the whole design constraint.
#
# THE FIX, ALSO THE OWNER'S: a small always-on ring in memory, capped, overwritten
# constantly, NEVER written to disk. When a detector fires, flush that flow's
# ring into the database. You get the bytes that CAUSED the alert rather than
# the bytes after it.
#
# So there are two mechanisms here and they are not the same thing:
#
#   THE RING       always on, every flow, tiny, memory only, overwritten.
#                  Its job is to still be holding the interesting bytes at
#                  the moment a detector decides they were interesting.
#
#   ARMING         off by default, one destination at a time and a much
#                  bigger ring for that address, so a flow to it is kept
#                  longer and given more room than the ordinary ring allows.
#
# FLUSHING IS THE DETECTOR'S JOB, IN BOTH CASES. This header used to say
# arming "flushes on its own rather than waiting for a detection" -- and that
# was never true on either platform. MEASURED 2026-09-26 (register section
# 14): PayloadRing has no clock, `flush()` takes a flow the caller names, and
# the only callers in the tree are feed_matcher's two detections, both
# detection-triggered. An address could be armed, the model told "full
# payload ... is now written to disk", and not one row would reach
# payload_capture for it unless a detector happened to fire on that flow.
# The claim is corrected here, in tool_registry's arm note and in status();
# the capability itself is recorded as a finding rather than built, because
# "flush everything for this address every N seconds" is a design decision
# (which flows, how often, how much disk) that belongs to the owner.
#
# DESTINATION ONLY. NOT PROCESS. THE OWNER'S INSTRUCTION AND IT STANDS.
#
# Arming by process would need a TCP-table lookup at capture time, and short
# lived connections vanish before the lookup can run. Different job, different
# failure mode, and bundling them would mean one feature that works reliably
# and one that fails silently wearing the same name. arm() takes an address.
#
# THE TWO CONSTRAINTS THE OWNER ATTACHED
#
# 1. CAPTURED PAYLOAD GETS ITS OWN SHORT RETENTION, unlike the behavioural
#    tables which are never pruned. This is the ONE THING in this database
#    that can contain the owner's own plaintext session data, and it is the only
#    table in the app with a default lifetime measured in days.
#
# 2. RULE TWO APPLIES HARD. "No match in payload" and "capture was not on for
#    this flow" must stay different sentences, and every payload-based answer
#    carries whether capture was active and covering.
#
#    That second one is not decoration. This module's normal state is NOT
#    HOLDING ANYTHING, because the ring is tiny and most flows fall out of it
#    within seconds. A search function that returned False for "no match" and
#    False for "this flow was never in the ring" would be wrong the large
#    majority of the time it was asked. So search() returns a SEARCHED flag
#    before it returns a MATCHED flag, and nothing here ever returns a bare
#    boolean.
#
#    The prediction ledger's coverage check is the pattern being reused.

import logging
import threading
import time

logger = logging.getLogger(__name__)

# BOUNDS. These are the numbers that keep this from being a memory leak.
#
# THE RING IS DELIBERATELY TOO SMALL TO BE USEFUL AS A RECORDING. It is not a
# capture buffer, it is a regret buffer: just enough to answer "what were the
# first bytes of the thing that just fired".
#
# THE HEAD IS WHAT IS KEPT, PER FRAME, AND THE REST IS NEVER HELD. This
# comment used to say "16 KB is about eleven full-size frames, which covers a
# TLS ClientHello, an HTTP request line with headers, or the opening exchange
# of almost any protocol" -- and the last clause was false as written, because
# every frame is cut to FRAME_HEAD_BYTES before it is stored. MEASURED
# 2026-09-26 (register section 14): a 2,700 byte frame went in and the ring
# held 512 bytes of it, with wrapped=False and frames_dropped=0 -- so the
# coverage note said "this is the conversation from its first captured byte"
# about a frame whose remaining 2,188 bytes were thrown away at the door.
#
# The head is the right thing to keep: banners, request lines and handshakes
# live at the front, and the tail of a data transfer is the user's actual
# content. What was wrong was that nothing SAID SO. The ring now counts the
# bytes it never held, per flow, and coverage() publishes them, so a negative
# search result comes back with "and N bytes of these frames were never kept"
# rather than as a clean "not there".
RING_BYTES_PER_FLOW = 16 * 1024

# An ARMED flow gets a real buffer, because somebody asked for this address
# specifically and is expecting to be able to read what happened.
ARMED_BYTES_PER_FLOW = 256 * 1024

# Hard ceiling across everything. Checked on every append, not periodically:
# a burst can cross this between two timer ticks, and the whole point of a
# hard cap is that there is no window in which it is not enforced.
MAX_TOTAL_BYTES = 8 * 1024 * 1024

# Flows tracked at once. Evicted least-recently-touched first, and an ARMED
# flow is never evicted, because being evicted is exactly the failure that
# arming is supposed to prevent.
MAX_FLOWS = 512

# Per-flow frame count cap, on top of the byte cap. A flood of tiny packets
# would otherwise make a very long deque inside the byte budget.
MAX_FRAMES_PER_FLOW = 64

# How long a flow sits in the ring untouched before it is dropped. Not a
# retention policy, just hygiene: a finished connection holding bytes is
# holding the owner's plaintext for no reason.
FLOW_IDLE_SECS = 300

# Bytes kept from any one frame. The head is where protocol banners,
# request lines and handshakes live, and the tail of a data transfer is the owner's
# actual content.
FRAME_HEAD_BYTES = 512

# retention. THE OWNER'S FIRST CONSTRAINT.
#
# The only default lifetime in days anywhere in this database. Behavioural
# tables are never pruned because a packet row is four numbers and a
# timestamp. A payload row can be a fragment of something the owner typed.
DEFAULT_PAYLOAD_RETENTION_DAYS = 7

_PREF_ARMED = "payload_armed_destinations"
_PREF_RETENTION_DAYS = "payload_retention_days"


def _looks_like_address(value: str) -> bool:
    """
    Is this the kind of string the armed list is compared against?

    The list is matched against `str(src_ip)` and `str(dst_ip)` of every frame,
    so the ONLY thing that can ever match is a textual IP address. v4 and v6
    both count; a hostname, a CIDR range, a bare number and a host:port pair
    do not, and each of those was accepted before 2026-09-26 while reporting
    armed=True. See arm() for the measurement.

    NARROW ON PURPOSE, and it refuses rather than warns: this is the one
    function in the module whose whole job is to keep a promise from being
    made that the capture cannot keep.
    """
    import ipaddress
    text = str(value or "").strip()
    if not text:
        return False
    # "203.0.113.9:443" is a host:port pair, not an address, and ip_address()
    # would accept the v6-looking "203.0.113.9:443" ... it would not, but the
    # refusal is worth naming: this shape reaches here from an operator
    # reading an address off a report with its port attached.
    if text.rsplit(":", 1)[-1].isdigit() and text.count(":") == 1:
        return False
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _service_port(src_port, dst_port) -> int:
    """
    The one port number that identifies a conversation from either end.

    A TCP or UDP connection has one well known port and one ephemeral one. The
    well known one is nearly always the lower number, and, far more
    importantly, it is THE SAME NUMBER IN BOTH DIRECTIONS. That is the only
    property this needs.

    THE BUG THIS EXISTS TO FIX, found 2026-09-20. The first version keyed on
    dst_port alone. An outbound frame carried 443 and the reply carried the
    client's ephemeral port, so the two halves of one conversation went into
    two different rings, and a flush got half a conversation. The test missed
    it because it passed 443 for BOTH directions, which packet_sniffer never
    does. A test written to suit the function rather than to match its caller.

    Both ports zero (ICMP, and anything portless) gives 0, which is correct:
    those flows are then keyed on the address pair alone.
    """
    a = int(src_port or 0)
    b = int(dst_port or 0)
    if a and b:
        return min(a, b)
    return a or b


def _flow_key(ip_a, ip_b, port, protocol):
    """
    The flow identity used everywhere in this module.

    DIRECTION IS NOT PART OF IT. A request and its reply are one conversation
    and flushing half of it would be worse than useless, so the two addresses
    are SORTED and the SERVICE port is used, because that number is the same
    whichever end sent the frame. The per-frame direction field is what says
    which way any given frame went.
    """
    lo, hi = sorted((str(ip_a or ""), str(ip_b or "")))
    return (lo, hi, int(port or 0), str(protocol or "").upper())


class PayloadRing:
    """
    The always-on ring, plus the arming list.

    Thread safety is real here and not defensive habit: append() is called
    from inside the scapy capture callback and flush() is called from the
    detection path, which is a different thread on the same data.
    """

    def __init__(self, session_id: str, config: dict = None):
        block = (config or {}).get("payload_capture", {}) or {}

        self.session_id = session_id
        self.enabled = bool(block.get("enabled", True))
        self.ring_bytes = int(block.get("ring_bytes_per_flow",
                                        RING_BYTES_PER_FLOW))
        self.armed_bytes = int(block.get("armed_bytes_per_flow",
                                         ARMED_BYTES_PER_FLOW))
        self.max_total = int(block.get("max_total_bytes", MAX_TOTAL_BYTES))
        self.max_flows = int(block.get("max_flows", MAX_FLOWS))

        self._lock = threading.Lock()

        # flow key -> {"frames": [...], "bytes": n, "touched": ts,
        #              "dropped": n, "dropped_bytes": n, "first_seen": ts}
        self._flows = {}
        self._total_bytes = 0

        # Armed DESTINATIONS, as plain address strings. Not flows: the user
        # says "watch 203.0.113.9", not "watch this four-tuple", because the
        # four-tuple does not exist yet at the moment they ask.
        self._armed = set()

        # Counters, so status() can say how much it has actually held rather
        # than only what it is holding now.
        self.frames_seen = 0
        self.frames_held = 0
        self.frames_dropped = 0
        # Bytes that arrived and were never held, because a frame was longer
        # than FRAME_HEAD_BYTES. Separate from frames_dropped: that one means
        # the ring wrapped, this one means the frame was cut to its head at
        # the door. A reader acting on a negative search result needs both.
        self.bytes_unheld = 0
        self.flows_evicted = 0
        self.flushes = 0

        self._load_armed()

    # ARMING

    def _load_armed(self):
        try:
            from core import memory_engine as me
            raw = me.get_preference(_PREF_ARMED) or ""
            self._armed = {a.strip() for a in raw.split(",") if a.strip()}
            if self._armed:
                logger.info(f"Payload capture armed for "
                            f"{len(self._armed)} destination(s).")
        except Exception as e:
            logger.warning(
                f"Armed destination list not loaded ({e}). Capture is running "
                f"as ring-only, so an address armed in a previous run is NOT "
                f"being captured now.")

    def _save_armed(self):
        try:
            from core import memory_engine as me
            me.set_preference(_PREF_ARMED, ",".join(sorted(self._armed)))
        except Exception as e:
            logger.warning(f"Could not persist armed destinations ({e}). "
                           f"They will be lost at the next restart.")

    def arm(self, destination: str) -> dict:
        """
        Start capturing everything to and from one address.

        Returns a dict rather than a bool, because "already armed" and "just
        armed" are different answers and a caller showing this to the user
        should be able to say which.

        THE DESTINATION IS CHECKED AGAINST THE ONE THING IT WILL BE COMPARED
        TO, and this was missing until 2026-09-26. _is_armed() tests
        `str(src_ip) in self._armed or str(dst_ip) in self._armed`, so the
        armed list holds IP ADDRESSES and nothing else. arm() accepted any
        non-empty string. MEASURED: arm("google.com") returned armed=True,
        arm("203.0.113.999") returned armed=True, arm("203.0.113.9/24") returned
        armed=True -- the tool reported ARMED to the model and to the
        operator's approval card, and not one frame could ever match. That is
        this project's oldest shape: a control that cannot fire reads exactly
        like one with nothing to say, and here it also wrote real network
        content to disk for a destination nobody was watching.

        A v6 literal IS accepted (flows carry v6 addresses as strings and the
        comparison is textual, so it works). A hostname is REFUSED with the
        reason: what arrives here is an address, and arming a name would be
        a promise this module cannot keep. A comma is refused because the
        armed list is persisted as a comma-joined string (see _save_armed).
        """
        d = str(destination or "").strip()
        if not d:
            return {"armed": False, "reason": "no destination given"}
        if "," in d:
            return {"armed": False, "destination": d,
                    "reason": ("a destination may not contain a comma: the "
                               "armed list is stored as one comma-joined "
                               "string, so a comma in an address would come "
                               "back as two destinations after a restart.")}
        if not _looks_like_address(d):
            return {"armed": False, "destination": d,
                    "reason": (f"{d!r} is not an IP address. Arming compares "
                               f"its list against the src and dst addresses "
                               f"of each frame, so a hostname here could "
                               f"never match anything while reporting that "
                               f"it was capturing. Resolve the name first "
                               f"and arm the address, or ask about the "
                               f"traffic by name with query_packets.")}
        with self._lock:
            already = d in self._armed
            self._armed.add(d)
        if not already:
            self._save_armed()
            logger.info(f"Payload capture ARMED for {d}. Its flows now get "
                        f"{self.armed_bytes // 1024} KB each and are "
                        f"released to the table when a detector flushes "
                        f"that flow.")
        return {"armed": True, "already": already, "destination": d,
                "armed_count": len(self._armed)}

    def disarm(self, destination: str) -> dict:
        """
        Stop capturing an address, and GIVE BACK WHAT IT WAS HOLDING.

        THE SECOND HALF WAS MISSING, found 2026-09-20. flow["armed"] was set
        once and never cleared, and an armed flow is never evicted and never
        idle swept. So disarming stopped new capture but left every flow that
        address had touched pinned in the ring for the rest of the process:
        the memory was never handed back and those flows could not be aged
        out. The flag is cleared here for any flow that was armed only because
        of this destination.
        """
        d = str(destination or "").strip()
        cleared = 0
        with self._lock:
            was = d in self._armed
            self._armed.discard(d)
            if was:
                for k, f in self._flows.items():
                    if f.get("armed") and not self._key_is_armed(k):
                        f["armed"] = False
                        cleared += 1
        if was:
            self._save_armed()
            logger.info(f"Payload capture disarmed for {d}. {cleared} flow(s) "
                        f"released back to the ordinary ring.")
        return {"armed": False, "was_armed": was, "destination": d,
                "flows_released": cleared,
                "armed_count": len(self._armed)}

    def armed(self) -> list:
        with self._lock:
            return sorted(self._armed)

    def _is_armed(self, src_ip, dst_ip) -> bool:
        return (str(src_ip) in self._armed) or (str(dst_ip) in self._armed)

    def _key_is_armed(self, key) -> bool:
        """Is either end of this flow key still on the armed list."""
        return key[0] in self._armed or key[1] in self._armed

    def _locate(self, key, ip_a, ip_b, protocol):
        """
        The flow for this key. ASSUMES THE LOCK IS HELD.

        Returns (flow, how, found_key) where how is 'exact', 'pair', 'none' or
        'ambiguous'.

        THE FALLBACK, and why it is deliberately narrow. A caller asking about
        a flow does not always know the service port: a detector that fired on
        an INBOUND frame has the client's ephemeral port in hand, not 443. So
        when the exact key misses, one flow for the same address pair and
        protocol is accepted. TWO OR MORE IS NOT, because picking between them
        would be inventing an answer, and inventing one here means attaching
        the wrong bytes to a finding. That case comes back as 'ambiguous' and
        says so rather than guessing.

        found_key IS THE KEY THE FLOW WAS ACTUALLY FOUND UNDER, and it exists
        because of TP-4 (2026-09-26): on the 'pair' path the caller's key is
        NOT the flow's key, and flush() was writing rows with the caller's
        port while the bytes came off the flow keyed on 443. A reader
        filtering the table by port then found bytes filed under a port they
        were never seen on. The resolved key travels back so the row can be
        written from it rather than from what was asked.
        """
        flow = self._flows.get(key)
        if flow is not None:
            return flow, "exact", key

        lo, hi = sorted((str(ip_a or ""), str(ip_b or "")))
        proto = str(protocol or "").upper()
        matches = [(k, f) for k, f in self._flows.items()
                   if k[0] == lo and k[1] == hi and k[3] == proto and f["frames"]]
        if len(matches) == 1:
            found_key, found_flow = matches[0]
            return found_flow, "pair", found_key
        if len(matches) > 1:
            return None, "ambiguous", None
        return None, "none", None

    # THE RING

    def append(self, src_ip, dst_ip, dst_port, protocol, direction,
               data: bytes, now: float = None, src_port=None) -> None:
        """
        One frame's payload into the ring. Called from the capture callback.

        src_port IS OPTIONAL BUT THE REAL CALLER PASSES IT. Without it the
        service port falls back to dst_port, which is right for an outbound
        frame and wrong for the reply, and wrong here means the two halves of
        one conversation land in different rings. packet_sniffer has both
        ports in hand and hands both over.

        RETURNS NOTHING AND RAISES NOTHING. This runs on the capture thread,
        where an exception does not lose one frame, it can take the capture
        loop with it. Anything that goes wrong here is swallowed, because a
        sniffer that has gone quiet is the failure this whole app exists to
        avoid, and losing payload is a much smaller loss than losing capture.
        """
        if not self.enabled or not data:
            return
        try:
            now = now if now is not None else time.time()
            key = _flow_key(src_ip, dst_ip,
                            _service_port(src_port, dst_port), protocol)
            is_armed = self._is_armed(src_ip, dst_ip)
            cap = self.armed_bytes if is_armed else self.ring_bytes
            chunk = data[:FRAME_HEAD_BYTES]
            # THE BYTES THROWN AWAY AT THE DOOR. Not overwritten later, not
            # evicted, not wrapped: never held at all because the frame was
            # longer than FRAME_HEAD_BYTES. Counted per flow so coverage()
            # can say it, and counted separately from `dropped` because that
            # one means "the ring wrapped" and this one means "the frame was
            # longer than we keep", which are different facts a reader acts
            # on differently. MEASURED 2026-09-26: before this, a 2,700 byte
            # frame came back as 512 bytes held, wrapped=False, and a note
            # saying it was the conversation from its first captured byte.
            unheld = max(0, len(data) - len(chunk))

            with self._lock:
                self.frames_seen += 1
                self.bytes_unheld += unheld

                flow = self._flows.get(key)
                if flow is None:
                    self._evict_if_needed(now, protect=key)
                    flow = {"frames": [], "bytes": 0, "touched": now,
                            "first_seen": now, "dropped": 0,
                            "dropped_bytes": 0, "unheld_bytes": 0,
                            "armed": is_armed}
                    self._flows[key] = flow

                flow["touched"] = now
                flow["armed"] = flow["armed"] or is_armed
                flow["unheld_bytes"] += unheld
                flow["frames"].append((now, str(direction or ""), chunk))
                flow["bytes"] += len(chunk)
                self._total_bytes += len(chunk)
                self.frames_held += 1

                # THE OVERWRITE. Oldest out first, and every drop is COUNTED,
                # because "this flow wrapped" is the difference between a
                # flush that holds the start of the conversation and one that
                # holds the middle of it. A reader has to be told which.
                while (flow["bytes"] > cap
                       or len(flow["frames"]) > MAX_FRAMES_PER_FLOW):
                    self._drop_oldest(flow)

                # The global cap, checked on every append rather than on a
                # timer, so there is no window in which it is not enforced.
                while self._total_bytes > self.max_total:
                    if not self._relieve_pressure(protect=key):
                        break
        except Exception as e:
            logger.debug(f"Payload ring append error: {e}")

    def _drop_oldest(self, flow) -> bool:
        if not flow["frames"]:
            return False
        _ts, _dir, chunk = flow["frames"].pop(0)
        flow["bytes"] -= len(chunk)
        flow["dropped"] += 1
        flow["dropped_bytes"] += len(chunk)
        self._total_bytes -= len(chunk)
        self.frames_dropped += 1
        return True

    def _relieve_pressure(self, protect=None) -> bool:
        """
        Free bytes when the global cap is hit. Returns False if it could not.

        Takes from the LARGEST UNARMED flow, not the oldest. Under pressure
        the thing to give up is the flow hogging the budget, and an armed flow
        is never touched here: somebody asked for that address by name, which
        is the one promise this module makes.
        """
        candidates = [(f["bytes"], k) for k, f in self._flows.items()
                      if not f["armed"] and k != protect and f["frames"]]
        if not candidates:
            # Nothing unarmed and unprotected is left holding bytes. Take from
            # the biggest flow still holding anything rather than blow the cap.
            fallback = [(f["bytes"], k) for k, f in self._flows.items()
                        if f["frames"]]
            if not fallback:
                return False
            # THE LOG LINE USED TO ASSERT SOMETHING IT HAD NOT CHECKED. It
            # said every remaining flow was ARMED, which is untrue when the
            # only flow left is the one currently being written to, and that
            # is the common case. Check before saying it.
            if all(self._flows[k]["armed"] for _b, k in fallback):
                logger.warning(
                    "Payload ring is at its global cap and every flow holding "
                    "bytes is ARMED. Dropping from an armed flow. Too many "
                    "destinations are armed for the configured budget.")
            else:
                logger.debug(
                    "Payload ring at its global cap with only the flow being "
                    "written left to take from. Dropping its oldest frame.")
            candidates = fallback
        candidates.sort(reverse=True)
        return self._drop_oldest(self._flows[candidates[0][1]])

    def _evict_if_needed(self, now: float, protect=None):
        """Make room for a new flow. Armed flows are never evicted."""
        # Idle flows first. A finished connection holding the owner's plaintext for no
        # reason is the thing to drop before anything else.
        stale = [k for k, f in self._flows.items()
                 if not f["armed"] and now - f["touched"] > FLOW_IDLE_SECS]
        for k in stale:
            self._forget(k)
            # Counted, same as a capacity eviction. An idle drop that nothing
            # counts makes status() understate how much has moved through the
            # ring, and that number is the only evidence the ring is working.
            self.flows_evicted += 1

        if len(self._flows) < self.max_flows:
            return

        evictable = [(f["touched"], k) for k, f in self._flows.items()
                     if not f["armed"] and k != protect]
        if not evictable:
            return
        evictable.sort()
        for _ts, k in evictable[:max(1, len(evictable) // 8)]:
            self._forget(k)
            self.flows_evicted += 1

    def _forget(self, key):
        flow = self._flows.pop(key, None)
        if flow:
            self._total_bytes -= flow["bytes"]

    # COVERAGE. RULE TWO LIVES HERE.

    def coverage(self, src_ip, dst_ip, dst_port=0, protocol="TCP",
                 src_port=None) -> dict:
        """
        What this module can and cannot say about one flow, right now.

        ANY ANSWER DERIVED FROM PAYLOAD HAS TO CARRY THIS. The normal state of
        this module is NOT HOLDING ANYTHING, because the ring is deliberately
        tiny and most flows fall out of it in seconds. An answer of "nothing
        found in the payload" is therefore usually a statement about the ring
        and not about the traffic, and printing it without this dict attached
        would be the app lying by omission.

        'covering' is the only key worth branching on. It is True only when
        the ring is on AND this flow is in it AND it holds at least one frame.
        """
        with self._lock:
            cov, _frames = self._coverage_locked(
                src_ip, dst_ip, dst_port, protocol, src_port)
        return cov

    def _coverage_locked(self, src_ip, dst_ip, dst_port, protocol, src_port):
        """
        coverage(), plus that flow's frames, under ONE lock acquisition.

        THE RACE THIS CLOSES, found 2026-09-20. search() called coverage(),
        let the lock go, then took it again to read the frames. A flow evicted
        in that gap came back as searched=True with matched=False, which is
        "I could not look" printed as "it is not there", the one sentence this
        whole module exists to keep separate. One acquisition, one answer.
        """
        key = _flow_key(src_ip, dst_ip,
                        _service_port(src_port, dst_port), protocol)
        armed = self._is_armed(src_ip, dst_ip)

        if not self.enabled:
            return {
                "covering": False, "ring_enabled": False,
                "flow_present": False, "armed": armed,
                "frames_held": 0, "bytes_held": 0,
                "frames_dropped": 0, "wrapped": False,
                "matched_by": "none",
                "note": ("Payload capture is switched off, so NOTHING has "
                         "been kept for any flow. Any statement about "
                         "payload content is about the absence of a "
                         "buffer, not about the traffic."),
            }, []

        flow, how, found_key = self._locate(key, src_ip, dst_ip, protocol)

        if how == "ambiguous":
            return {
                "covering": False, "ring_enabled": True,
                "flow_present": False, "armed": armed,
                "frames_held": 0, "bytes_held": 0,
                "frames_dropped": 0, "wrapped": False,
                "matched_by": "ambiguous",
                "note": (
                    "Several flows are held between these two addresses on "
                    "this protocol and the port given matches none of them, "
                    "so WHICH ONE YOU MEAN CANNOT BE TOLD APART. Nothing is "
                    "returned rather than guessing, because a guess here "
                    "attaches the wrong bytes to a finding. Ask again with "
                    "the service port of the connection."),
            }, []

        if flow is None:
            return {
                "covering": False, "ring_enabled": True,
                "flow_present": False, "armed": armed,
                "frames_held": 0, "bytes_held": 0,
                "frames_dropped": 0, "wrapped": False,
                "matched_by": "none",
                "note": (
                    "This flow is not in the ring. It either never carried "
                    "a payload the sensor saw, or it has aged out: the "
                    "ring is small on purpose and holds seconds, not "
                    "history. NOTHING CAN BE CONCLUDED about what these "
                    "bytes contained."
                    + (" This destination IS armed, so future flows to it "
                       "will be captured." if armed else "")),
            }, []

        wrapped = flow["dropped"] > 0
        unheld = flow.get("unheld_bytes", 0)
        cov = {
            "covering": bool(flow["frames"]),
            "ring_enabled": True,
            "flow_present": True,
            "armed": flow["armed"],
            # THE FLOW'S OWN SERVICE PORT, not the caller's. Published because
            # flush() has to write the row with the port the bytes were
            # actually seen on (see flush's comment, TP-4). found_key is the
            # key the flow was FOUND under, which on the 'pair' path is not
            # the key that was asked for.
            "port": (found_key[2] if found_key else key[2]),
            "frames_held": len(flow["frames"]),
            "bytes_held": flow["bytes"],
            "frames_dropped": flow["dropped"],
            "wrapped": wrapped,
            # THE THIRD WAY BYTES GO MISSING, and it was not published at all
            # until 2026-09-26. `wrapped` says the ring overwrote earlier
            # frames; this says the frames IT HOLDS were longer than
            # FRAME_HEAD_BYTES and their tails were never taken. A negative
            # search that does not carry this number is a half-truth in
            # exactly the way the wrapped flag already exists to prevent.
            "bytes_unheld": unheld,
            "frames_cut": sum(1 for _t, _d, c in flow["frames"]
                              if len(c) == FRAME_HEAD_BYTES),
            "first_seen": flow["first_seen"],
            "matched_by": how,
            "note": (
                f"Holding {len(flow['frames'])} frame(s), "
                f"{flow['bytes']} bytes"
                + (f". THE RING WRAPPED: {flow['dropped']} earlier "
                   f"frame(s) were overwritten, so this is the MIDDLE of "
                   f"the conversation and not its start."
                   if wrapped else
                   ". Nothing has been overwritten, so this is the "
                   "conversation from its first captured byte.")
                + (f" EACH FRAME IS KEPT ONLY TO ITS FIRST "
                   f"{FRAME_HEAD_BYTES} BYTES: {unheld} byte(s) of the "
                   f"frames held here were never taken, so anything said "
                   f"in the part of a frame past that offset was NOT "
                   f"examined and its absence proves nothing."
                   if unheld else "")
                + ("" if how == "exact" else
                   " Matched on the address pair rather than the port, "
                   "because the port asked for is not the one this flow is "
                   "keyed on and only one flow exists between these two.")),
        }
        return cov, list(flow["frames"])

    def search(self, needle: bytes, src_ip, dst_ip, dst_port=0,
               protocol="TCP", src_port=None) -> dict:
        """
        Look for a byte sequence in one flow's held payload.

        THE SHAPE OF THE RETURN IS THE POINT. 'searched' comes before
        'matched', and a caller that reads 'matched' without reading
        'searched' has made the exact mistake this module was built to make
        impossible: reading "I could not look" as "it is not there".

        matched is None, not False, when searched is False. A None cannot be
        printed as "no" by accident.

        AN EMPTY NEEDLE IS REFUSED, not answered. MEASURED 2026-09-26:
        `search(b'')` returned searched=True, matched=True, because the empty
        bytes are a substring of every string. A caller that filtered a
        parameter down to nothing and searched anyway would be told the flow
        CONTAINS what it was looking for -- the loudest possible wrong answer,
        out of the one function built to never give one.
        """
        if not needle:
            return {
                "searched": False, "matched": None,
                "reason": ("An empty search string was given, so nothing "
                           "meaningful could be looked for. This is NOT a "
                           "negative result: ask again with the bytes you "
                           "actually mean to find."),
                "coverage": {"covering": False, "ring_enabled": self.enabled,
                             "flow_present": False,
                             "matched_by": "empty_needle"},
            }

        with self._lock:
            cov, frames = self._coverage_locked(
                src_ip, dst_ip, dst_port, protocol, src_port)

        if not cov["covering"]:
            return {"searched": False, "matched": None,
                    "reason": cov["note"], "coverage": cov}

        hit = any(needle in chunk for _ts, _dir, chunk in frames)
        return {
            "searched": True,
            "matched": hit,
            "reason": None,
            "coverage": cov,
            # Repeated deliberately. A "no match" that does not carry the
            # wrapped flag next to it is a half-truth: the bytes may have
            # been in the part that was overwritten.
            "searched_frames": len(frames),
            "wrapped": cov["wrapped"],
            # And the same argument for the bytes that were never taken.
            # Without this, "not found" on a frame held as its first 512
            # bytes reads as "was not sent".
            "bytes_unheld": cov.get("bytes_unheld", 0),
        }

    # FLUSH

    def flush(self, src_ip, dst_ip, dst_port, protocol,
              trigger_detection_id: str, trigger_entity: str = "",
              src_port=None) -> dict:
        """
        Write one flow's held bytes to the database. THE POINT OF THE MODULE.

        Called when a detector fires, which is why the bytes it writes are the
        ones that CAUSED the alert rather than the ones that came after it.
        The ring keeps the flow alive after a flush rather than clearing it,
        because a second detection on the same flow moments later should not
        find an empty buffer that this call emptied.

        Returns ran/reason like everything else, and NEVER a bare count: zero
        rows written because the flow was not in the ring and zero rows
        written because the flow carried no payload are different facts.
        """
        # One lock acquisition for the verdict AND the bytes, same reason as
        # search(). The database write below is deliberately OUTSIDE the lock:
        # this is called from the detection path and holding the ring shut for
        # the length of a disk write would stall the capture thread.
        with self._lock:
            cov, frames = self._coverage_locked(
                src_ip, dst_ip, dst_port, protocol, src_port)
            was_armed = bool(cov.get("armed")) and cov.get("flow_present")
            # THE PORT THE FLOW IS ACTUALLY KEYED ON, not the one the caller
            # asked with. MEASURED 2026-09-26: a detector that fired on an
            # INBOUND frame has the client's ephemeral port in hand, not 443,
            # and the 'pair' fallback correctly finds the flow -- then the row
            # was written with dst_port=51001 while its bytes came off the 443
            # conversation. `matched_by` said 'pair' on the coverage block and
            # the stored row did not, so a later reader filtering the table by
            # port got bytes filed under a port they were never seen on.
            # `cov["port"]` is the flow's own service port; the caller's value
            # is kept only when no flow was located.
            flow_port = cov.get("port") or int(dst_port or 0)

            # Frames already written for this trigger are not written again
            # (TP-18). seq is the frame's position in the flow, so it runs on
            # across flushes instead of restarting at 0.
            flow, _how, _k = self._locate(
                _flow_key(src_ip, dst_ip, _service_port(src_port, dst_port),
                          protocol), src_ip, dst_ip, protocol)
            first_n = flow["dropped"] if flow is not None else 0
            done = (flow.get("flushed", {}).get(str(trigger_detection_id), 0)
                    if flow is not None else 0)
            skip = max(0, done - first_n)
            already_written = min(skip, len(frames))
            frames = frames[skip:]
            start_seq = first_n + skip

        if not cov["covering"]:
            return {"ran": False, "reason": cov["note"],
                    "rows": 0, "coverage": cov}

        if not frames:
            reason = ("every frame held was already written by an earlier "
                      "flush for this detection"
                      if already_written else
                      "flow held no frames at flush time")
            return {"ran": False, "reason": reason,
                    "rows": 0, "coverage": cov}

        try:
            rows = self._write_frames(
                frames, src_ip, dst_ip, flow_port, protocol,
                trigger_detection_id, trigger_entity, was_armed,
                start_seq=start_seq)
        except Exception as e:
            logger.error(f"Payload flush failed: {e}")
            return {"ran": False, "reason": f"write failed: {e}",
                    "rows": 0, "coverage": cov}

        with self._lock:
            self.flushes += 1
            if flow is not None:
                flow.setdefault("flushed", {})[str(trigger_detection_id)] = \
                    start_seq + rows

        logger.info(f"Payload flush: {rows} frame(s) for {src_ip} -> "
                    f"{dst_ip}:{flow_port} on {trigger_detection_id}"
                    + (" (ARMED)" if was_armed else "")
                    + ("" if flow_port == int(dst_port or 0) else
                       f" (matched on the address pair, flow service port "
                       f"{flow_port}; the {dst_port} asked for was the "
                       f"caller's end)"))
        return {"ran": True, "reason": None, "rows": rows,
                "coverage": cov, "was_armed": was_armed}

    def _write_frames(self, frames, src_ip, dst_ip, dst_port, protocol,
                      trigger_detection_id, trigger_entity, was_armed,
                      start_seq: int = 0) -> int:
        from core import memory_engine as me
        from datetime import datetime, timezone

        flushed_at = datetime.now(timezone.utc).isoformat()
        payload = []
        for seq, (ts, direction, chunk) in enumerate(frames, start_seq):
            captured_at = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            payload.append((
                self.session_id, flushed_at, captured_at,
                str(src_ip), str(dst_ip), int(dst_port or 0),
                str(protocol), str(direction), seq,
                chunk.hex(), 1 if was_armed else 0,
                str(trigger_detection_id), str(trigger_entity or ""),
            ))

        with me._get_conn() as conn:
            conn.executemany(
                "INSERT INTO payload_capture "
                "(session_id, flushed_at, captured_at, src_ip, dst_ip, "
                " dst_port, protocol, direction, seq, data_hex, was_armed, "
                " trigger_detection_id, trigger_entity) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                payload)
        return len(payload)

    # STATUS

    def status(self) -> dict:
        with self._lock:
            flows = len(self._flows)
            held = self._total_bytes
            armed = sorted(self._armed)

        notes = [
            "The ring is deliberately small. It holds SECONDS of each flow, "
            "not history, and its only job is to still be holding the "
            "interesting bytes at the moment a detector decides they were "
            "interesting.",
            "Nothing in the ring is on disk. Bytes reach the database when a "
            "detector flushes the flow it fired on, and NEVER on their own: "
            "arming gives an address a bigger buffer and nothing else.",
            f"Every frame is kept only to its first {FRAME_HEAD_BYTES} bytes. "
            f"Anything past that offset is never held, so a negative search "
            f"result covers the heads of these frames and nothing more.",
        ]
        if not self.enabled:
            notes.insert(0, "PAYLOAD CAPTURE IS OFF. No flow is covered, so "
                            "no statement about payload content means "
                            "anything right now.")
        if not armed:
            notes.append("No destination is armed. Capture is ring-only, so a "
                         "flow is kept only until it is overwritten.")
        else:
            notes.append(
                f"{len(armed)} destination(s) are armed, which gives their "
                f"flows {self.armed_bytes // 1024} KB each instead of "
                f"{self.ring_bytes // 1024} KB. It does NOT write anything by "
                f"itself: an armed flow still waits for a detection to flush "
                f"it.")

        return {
            "enabled": self.enabled,
            "flows_in_ring": flows,
            "bytes_held": held,
            "max_total_bytes": self.max_total,
            "pressure_pct": round(100.0 * held / self.max_total, 1)
                            if self.max_total else 0.0,
            "armed_destinations": armed,
            "frames_seen": self.frames_seen,
            "frames_held": self.frames_held,
            "frames_dropped": self.frames_dropped,
            # Published so a reader of status() can tell "the ring is quiet"
            # from "the ring was told more than it keeps".
            "bytes_unheld": self.bytes_unheld,
            "frames_cut_at": FRAME_HEAD_BYTES,
            "flows_evicted": self.flows_evicted,
            "flushes": self.flushes,
            "retention_days": retention_days(),
            "notes": notes,
        }


# RETENTION. THE OWNER'S FIRST CONSTRAINT.

# THE ACTIVE RING. How a detector on another thread reaches the bytes.
#
# TODO 120, 2026-09-20. The ring lives inside the PacketSniffer instance,
# because the sniffer owns the capture and that is right. The problem is that
# feed_matcher and dns_inspector run on their own threads and raise findings
# about flows the sniffer captured, and they had no way to reach it. So the
# two detections in this app with the STRONGEST evidence behind them, a
# destination on a live known-bad feed, were the two that kept no bytes.
#
# ONE PROCESS, ONE CAPTURE, ONE RING, so a module-level handle is the honest
# shape rather than a singleton pretending to be something cleverer. The
# sniffer registers its ring when it starts and clears it when it stops.
#
# CLEARING ON STOP IS THE POINT, not tidiness. A stale handle would answer
# questions about a ring nothing is filling any more, and "nothing was held"
# would then mean "the sensor is off" while reading as "the traffic was
# empty". That is the one sentence this module exists to keep apart.

_ACTIVE = None
_ACTIVE_LOCK = threading.Lock()


def set_active(ring):
    """Register the ring the capture thread is filling. None clears it."""
    global _ACTIVE
    with _ACTIVE_LOCK:
        _ACTIVE = ring


def active():
    """The live ring, or None when no capture is running."""
    with _ACTIVE_LOCK:
        return _ACTIVE


def flush_for_finding(src_ip, dst_ip, dst_port, protocol, detection_id,
                      entity_value="", src_port=None) -> dict:
    """
    Keep the bytes behind a finding raised from OUTSIDE the sniffer.

    Same contract as PayloadRing.flush: ran/reason, never a bare count, and
    the coverage dict comes back either way.

    NO RING IS A REASON, NOT A ZERO. If the capture sensor is not running
    there is nothing to flush and nothing was ever held, and saying "0 rows"
    would read as "this flow carried no payload". The two are different facts
    and they get different sentences here.
    """
    ring = active()
    if ring is None:
        return {
            "ran": False,
            "rows": 0,
            "reason": ("No payload ring is registered, which means the packet "
                       "sensor is not running in this process. Nothing has "
                       "been held for any flow, so the absence of payload "
                       "here says nothing about the traffic."),
            "coverage": {"covering": False, "ring_enabled": False,
                         "flow_present": False, "matched_by": "no_ring"},
        }
    try:
        return ring.flush(src_ip, dst_ip, dst_port, protocol,
                          trigger_detection_id=detection_id,
                          trigger_entity=entity_value or str(src_ip or ""),
                          src_port=src_port)
    except Exception as e:
        logger.debug(f"Payload flush for {detection_id} failed: {e}")
        return {"ran": False, "rows": 0, "reason": f"flush failed: {e}",
                "coverage": {"covering": False, "matched_by": "error"}}


def retention_days() -> int:
    try:
        from core import memory_engine as me
        value = me.get_preference(_PREF_RETENTION_DAYS)
        return int(value) if value else DEFAULT_PAYLOAD_RETENTION_DAYS
    except (TypeError, ValueError):
        return DEFAULT_PAYLOAD_RETENTION_DAYS
    except Exception:
        return DEFAULT_PAYLOAD_RETENTION_DAYS


def prune(days: int = None) -> dict:
    """
    Delete payload rows older than the retention window.

    THE ONLY TABLE IN THIS APP WITH A DEFAULT LIFETIME IN DAYS. The
    behavioural tables are never pruned because a packet row is four numbers
    and a timestamp. A payload row can be a fragment of something the owner typed,
    and it does not get to sit there for a year because nobody thought about
    it.

    Returns ran/reason. A prune that could not run must not report zero
    deleted, because zero deleted is what a clean table looks like.
    """
    from core import memory_engine as me
    from datetime import datetime, timezone, timedelta

    d = days if days is not None else retention_days()
    if d <= 0:
        return {"ran": False, "reason": "retention disabled (days <= 0)",
                "deleted": 0}

    cutoff = (datetime.now(timezone.utc) - timedelta(days=d)).isoformat()
    try:
        with me._get_conn() as conn:
            cur = conn.execute(
                "DELETE FROM payload_capture WHERE flushed_at < ?", (cutoff,))
            deleted = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
    except Exception as e:
        logger.error(f"Payload prune failed: {e}")
        return {"ran": False, "reason": str(e), "deleted": 0}

    if deleted:
        logger.info(f"Payload prune: {deleted} row(s) older than {d} day(s).")
    return {"ran": True, "reason": None, "deleted": deleted,
            "retention_days": d, "cutoff": cutoff}
