# tests/test_payload_ring.py
# AgentalSec V2, TODO 113.6. Tests for tools/payload_ring.
#
# RULE ONE: failure cases first. Sections 1 to 4 are every way this declines
# to hold or declines to answer, and they come before anything that checks it
# keeps bytes.
#
# THE SECTION THAT MATTERS MOST IS 3, the coverage and search contract. This
# module's NORMAL state is not holding anything, because the ring is tiny on
# purpose. A search that returned False for "no match" and False for "this
# flow was never in the ring" would be wrong the large majority of the time
# it was asked. So search() returns matched=None when searched is False, and
# a None cannot be printed as "no" by accident.
#
# SECTION 5 is the memory bound. This module runs inside the capture callback
# on every packet with a payload, so an unbounded dict here is not a slow leak,
# it is the app taking the machine down.

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

from tools import payload_ring as pr


def _ring(**kw):
    """A ring with no database behind it."""
    cfg = {"payload_capture": kw} if kw else None
    r = pr.PayloadRing("sess-test", cfg)
    r._armed = set()
    r._save_armed = lambda: None
    return r


# SECTION 1. FAILURE: nothing to hold, or holding switched off.

def test_append_of_empty_data_holds_nothing():
    r = _ring()
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", b"", now=0)
    assert r.status()["flows_in_ring"] == 0


def test_disabled_ring_holds_nothing():
    r = _ring(enabled=False)
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", b"hello", now=0)
    s = r.status()
    assert s["enabled"] is False
    assert s["flows_in_ring"] == 0


def test_disabled_ring_says_so_in_coverage():
    """
    Switched off must not read as a clean flow. The note has to say the
    statement is about the buffer and not about the traffic.
    """
    r = _ring(enabled=False)
    cov = r.coverage("192.0.2.5", "1.2.3.4", 443, "TCP")
    assert cov["covering"] is False
    assert cov["ring_enabled"] is False
    assert "switched off" in cov["note"].lower()


def test_append_never_raises_on_junk():
    """
    This runs inside the capture callback. An exception here does not lose
    one frame, it can take the capture loop with it, and a sniffer that has
    gone quiet is the failure the whole app exists to avoid.
    """
    r = _ring()
    r.append(None, None, None, None, None, b"x", now=0)
    r.append("192.0.2.5", "1.2.3.4", "not-a-port", "TCP", "out", b"x", now=0)
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "out", "a string", now=0)
    # No assertion on state. The assertion is that we got here.


# SECTION 2. FAILURE: flush when there is nothing to flush.

def test_flush_of_an_unknown_flow_is_ran_false_not_zero_rows():
    """
    Zero rows because the flow was never in the ring, and zero rows because
    the flow carried no payload, are DIFFERENT FACTS. Only ran distinguishes
    them, so a bare count must never be the answer.
    """
    r = _ring()
    out = r.flush("192.0.2.5", "1.2.3.4", 443, "TCP", "PKT-1001")
    assert out["ran"] is False
    assert out["rows"] == 0
    assert "not in the ring" in out["reason"]
    assert out["coverage"]["covering"] is False


def test_flush_on_a_disabled_ring_is_ran_false():
    r = _ring(enabled=False)
    out = r.flush("192.0.2.5", "1.2.3.4", 443, "TCP", "PKT-1001")
    assert out["ran"] is False
    assert out["rows"] == 0


def test_flush_write_failure_is_ran_false(monkeypatch):
    r = _ring()
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", b"hello", now=0)

    def boom(*a, **k):
        raise RuntimeError("db locked")

    monkeypatch.setattr(r, "_write_frames", boom)
    out = r.flush("192.0.2.5", "1.2.3.4", 443, "TCP", "PKT-1001")

    assert out["ran"] is False
    assert out["rows"] == 0
    assert "db locked" in out["reason"]


def test_prune_with_retention_disabled_is_ran_false():
    out = pr.prune(days=0)
    assert out["ran"] is False
    assert out["deleted"] == 0


# SECTION 3. THE COVERAGE CONTRACT. Rule two, and the reason this module
# has a shape at all.

def test_search_of_an_uncovered_flow_returns_matched_none():
    """
    THE SINGLE MOST IMPORTANT ASSERTION IN THIS FILE.

    matched must be None and not False when we could not look. A False here
    would be printed as "not found in the payload", which is a claim about
    traffic that was never examined.
    """
    r = _ring()
    out = r.search(b"password", "192.0.2.5", "1.2.3.4", 443, "TCP")

    assert out["searched"] is False
    assert out["matched"] is None
    assert out["matched"] is not False
    assert out["reason"]


def test_search_of_a_covered_flow_with_no_hit_is_a_real_no():
    r = _ring()
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound",
             b"GET / HTTP/1.1\r\n", now=0)

    out = r.search(b"password", "192.0.2.5", "1.2.3.4", 443, "TCP")

    assert out["searched"] is True
    assert out["matched"] is False
    assert out["reason"] is None


def test_search_carries_the_wrapped_flag_next_to_the_answer():
    """
    A "no match" on a flow whose start was overwritten is a half-truth: the
    bytes may have been in the part that is gone. The flag has to sit next to
    the answer, not two dicts away.
    """
    r = _ring(ring_bytes_per_flow=1024)
    for i in range(40):
        r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound",
                 bytes([i % 256]) * 256, now=i)

    out = r.search(b"nothing-like-this", "192.0.2.5", "1.2.3.4", 443, "TCP")

    assert out["searched"] is True
    assert out["matched"] is False
    assert out["wrapped"] is True
    assert "wrapped" in out["coverage"]["note"].lower()


def test_coverage_of_an_unseen_flow_refuses_to_conclude():
    r = _ring()
    cov = r.coverage("192.0.2.5", "1.2.3.4", 443, "TCP")
    assert cov["covering"] is False
    assert cov["flow_present"] is False
    assert "NOTHING CAN BE CONCLUDED" in cov["note"]


def test_coverage_says_when_the_conversation_start_is_intact():
    r = _ring()
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", b"hello", now=0)
    cov = r.coverage("192.0.2.5", "1.2.3.4", 443, "TCP")
    assert cov["covering"] is True
    assert cov["wrapped"] is False
    assert "first captured byte" in cov["note"]


def test_coverage_mentions_arming_on_a_flow_not_yet_seen():
    r = _ring()
    r.arm("1.2.3.4")
    cov = r.coverage("192.0.2.5", "1.2.3.4", 443, "TCP")
    assert cov["covering"] is False
    assert cov["armed"] is True
    assert "armed" in cov["note"].lower()


def test_flush_result_always_carries_coverage():
    """
    A finding that says "no payload kept" without saying why is exactly the
    half-truth this module exists to prevent, so the coverage dict rides on
    both the success and the failure path.
    """
    r = _ring()
    miss = r.flush("192.0.2.5", "1.2.3.4", 443, "TCP", "PKT-1001")
    assert "coverage" in miss

    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", b"hi", now=0)
    r._write_frames = lambda *a, **k: 1
    hit = r.flush("192.0.2.5", "1.2.3.4", 443, "TCP", "PKT-1001")
    assert "coverage" in hit


# SECTION 4. The flow key. Both directions must land in one ring.

def test_both_directions_share_one_flow():
    """
    A request and its reply are one conversation. Flushing half of it would
    be worse than useless.
    """
    r = _ring()
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", b"req", now=0)
    r.append("1.2.3.4", "192.0.2.5", 443, "TCP", "inbound", b"resp", now=1)

    assert r.status()["flows_in_ring"] == 1
    cov = r.coverage("192.0.2.5", "1.2.3.4", 443, "TCP")
    assert cov["frames_held"] == 2


def test_coverage_is_reachable_from_either_direction():
    r = _ring()
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", b"req", now=0)

    a = r.coverage("192.0.2.5", "1.2.3.4", 443, "TCP")
    b = r.coverage("1.2.3.4", "192.0.2.5", 443, "TCP")
    assert a["covering"] is True
    assert b["covering"] is True


def test_different_ports_are_different_flows():
    r = _ring()
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", b"a", now=0)
    r.append("192.0.2.5", "1.2.3.4", 80, "TCP", "outbound", b"b", now=0)
    assert r.status()["flows_in_ring"] == 2


# SECTION 5. THE MEMORY BOUND. This runs on every payload packet.

def test_a_single_flow_cannot_exceed_its_cap():
    cap = 4096
    r = _ring(ring_bytes_per_flow=cap)
    for i in range(200):
        r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound",
                 b"x" * 512, now=i)
    cov = r.coverage("192.0.2.5", "1.2.3.4", 443, "TCP")
    assert cov["bytes_held"] <= cap


def test_a_flow_cannot_exceed_the_frame_count_cap():
    r = _ring()
    for i in range(500):
        r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", b"x", now=i)
    cov = r.coverage("192.0.2.5", "1.2.3.4", 443, "TCP")
    assert cov["frames_held"] <= pr.MAX_FRAMES_PER_FLOW


def test_the_global_cap_holds_across_many_flows():
    """
    The cap is checked on EVERY append, not on a timer, because a burst can
    cross it between two ticks and a hard cap with a window is not a cap.
    """
    total = 64 * 1024
    r = _ring(max_total_bytes=total, ring_bytes_per_flow=8192, max_flows=200)
    for i in range(3000):
        r.append(f"10.0.{i // 256}.{i % 256}", "1.2.3.4", 443, "TCP",
                 "outbound", b"y" * 512, now=float(i))
    assert r.status()["bytes_held"] <= total


def test_flow_count_is_bounded():
    r = _ring(max_flows=32)
    for i in range(1000):
        r.append(f"10.0.{i // 256}.{i % 256}", "1.2.3.4", 443, "TCP",
                 "outbound", b"z", now=float(i))
    assert r.status()["flows_in_ring"] <= 32


def test_idle_flows_are_forgotten():
    """
    A finished connection holding the owner's plaintext for no reason is the first
    thing to drop. This is hygiene, not retention.
    """
    r = _ring(max_flows=4)
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", b"old", now=0)
    for i in range(8):
        r.append(f"10.0.1.{i}", "1.2.3.4", 443, "TCP", "outbound", b"new",
                 now=pr.FLOW_IDLE_SECS + 100 + i)
    assert r.coverage("192.0.2.5", "1.2.3.4", 443, "TCP")["covering"] is False


def test_dropped_frames_are_counted_not_silently_lost():
    """
    "This flow wrapped" is the difference between a flush holding the start
    of the conversation and one holding the middle. Losing the count would
    lose the ability to say which.
    """
    r = _ring(ring_bytes_per_flow=1024)
    for i in range(50):
        r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound",
                 b"q" * 256, now=i)
    cov = r.coverage("192.0.2.5", "1.2.3.4", 443, "TCP")
    assert cov["frames_dropped"] > 0
    assert cov["wrapped"] is True
    assert r.status()["frames_dropped"] > 0


def test_oversized_frames_are_truncated_at_the_head():
    r = _ring()
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound",
             b"H" * 100000, now=0)
    cov = r.coverage("192.0.2.5", "1.2.3.4", 443, "TCP")
    assert cov["bytes_held"] == pr.FRAME_HEAD_BYTES


# SECTION 6. ARMING. Destination only, never process.

def test_arm_with_no_destination_is_refused():
    r = _ring()
    out = r.arm("")
    assert out["armed"] is False
    assert r.armed() == []


def test_arm_reports_already_armed_separately():
    r = _ring()
    first = r.arm("1.2.3.4")
    second = r.arm("1.2.3.4")
    assert first["already"] is False
    assert second["already"] is True


def test_disarm_reports_whether_it_was_armed():
    r = _ring()
    assert r.disarm("1.2.3.4")["was_armed"] is False
    r.arm("1.2.3.4")
    assert r.disarm("1.2.3.4")["was_armed"] is True
    assert r.armed() == []


def test_an_armed_flow_gets_the_bigger_buffer():
    r = _ring(ring_bytes_per_flow=1024, armed_bytes_per_flow=16384)

    r.append("192.0.2.5", "9.9.9.9", 443, "TCP", "outbound", b"p" * 512, now=0)
    r.arm("1.2.3.4")
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", b"p" * 512, now=0)

    for i in range(1, 20):
        r.append("192.0.2.5", "9.9.9.9", 443, "TCP", "outbound",
                 b"p" * 512, now=i)
        r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound",
                 b"p" * 512, now=i)

    plain = r.coverage("192.0.2.5", "9.9.9.9", 443, "TCP")
    armed = r.coverage("192.0.2.5", "1.2.3.4", 443, "TCP")
    assert armed["bytes_held"] > plain["bytes_held"]
    assert armed["armed"] is True


def test_an_armed_flow_is_never_evicted():
    """
    Being evicted is exactly the failure arming is supposed to prevent.
    Somebody asked for this address by name.
    """
    r = _ring(max_flows=8)
    r.arm("1.2.3.4")
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", b"keep", now=0)

    for i in range(400):
        r.append(f"10.9.{i // 256}.{i % 256}", "8.8.8.8", 53, "UDP",
                 "outbound", b"noise", now=float(i))

    assert r.coverage("192.0.2.5", "1.2.3.4", 443, "TCP")["covering"] is True


def test_an_armed_flow_survives_idle_sweeping():
    r = _ring(max_flows=4)
    r.arm("1.2.3.4")
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", b"keep", now=0)

    for i in range(8):
        r.append(f"10.0.1.{i}", "8.8.8.8", 53, "UDP", "outbound", b"n",
                 now=pr.FLOW_IDLE_SECS + 100 + i)

    assert r.coverage("192.0.2.5", "1.2.3.4", 443, "TCP")["covering"] is True


def test_arming_matches_either_endpoint():
    """A reply from an armed address is as interesting as a request to it."""
    r = _ring()
    r.arm("1.2.3.4")
    r.append("1.2.3.4", "192.0.2.5", 443, "TCP", "inbound", b"reply", now=0)
    assert r.coverage("192.0.2.5", "1.2.3.4", 443, "TCP")["armed"] is True


# SECTION 7. HAPPY PATH. The timing hole is actually closed.

def test_the_bytes_that_caused_the_alert_are_still_there(monkeypatch):
    """
    THE WHOLE FEATURE, IN ONE TEST.

    The ClientHello arrives. Some frames later a detector fires. The flush
    must return the ClientHello, not the traffic that came after the
    decision, because the ClientHello is the first packet of the connection
    and switching capture on afterwards would have missed it forever.
    """
    written = {}
    r = _ring()
    monkeypatch.setattr(
        r, "_write_frames",
        lambda frames, *a, **k: written.update(frames=list(frames))
        or len(frames))

    hello = b"\x16\x03\x01\x00\xf0CLIENTHELLO-MARKER"
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", hello, now=0)
    for i in range(1, 6):
        r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound",
                 b"later-traffic", now=i)

    out = r.flush("192.0.2.5", "1.2.3.4", 443, "TCP", "PKT-1004", "192.0.2.5")

    assert out["ran"] is True
    assert out["rows"] == 6
    held = b"".join(chunk for _ts, _d, chunk in written["frames"])
    assert b"CLIENTHELLO-MARKER" in held


def test_flush_does_not_empty_the_ring(monkeypatch):
    """
    A second detection on the same flow moments later must not find a buffer
    that the first flush emptied.
    """
    r = _ring()
    monkeypatch.setattr(r, "_write_frames", lambda frames, *a, **k: len(frames))
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", b"data", now=0)

    first = r.flush("192.0.2.5", "1.2.3.4", 443, "TCP", "PKT-1001")
    second = r.flush("192.0.2.5", "1.2.3.4", 443, "TCP", "PKT-1002")

    assert first["ran"] is True
    assert second["ran"] is True
    assert second["rows"] == first["rows"]


def test_flush_records_whether_the_flow_was_armed(monkeypatch):
    """
    A row flushed by a detection and a row captured because somebody asked
    are different things, and the difference cannot be reconstructed later
    because the armed list changes.
    """
    seen = {}
    r = _ring()
    monkeypatch.setattr(
        r, "_write_frames",
        lambda frames, s, d, p, pr_, td, te, was_armed, start_seq=0:
            seen.update(armed=was_armed) or len(frames))

    r.arm("1.2.3.4")
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", b"x", now=0)
    r.flush("192.0.2.5", "1.2.3.4", 443, "TCP", "PKT-1001")

    assert seen["armed"] is True


def test_frames_keep_their_order_and_direction(monkeypatch):
    written = {}
    r = _ring()
    monkeypatch.setattr(
        r, "_write_frames",
        lambda frames, *a, **k: written.update(frames=list(frames))
        or len(frames))

    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", b"one", now=0)
    r.append("1.2.3.4", "192.0.2.5", 443, "TCP", "inbound", b"two", now=1)
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", b"three", now=2)
    r.flush("192.0.2.5", "1.2.3.4", 443, "TCP", "PKT-1001")

    chunks = [c for _t, _d, c in written["frames"]]
    dirs = [d for _t, d, _c in written["frames"]]
    assert chunks == [b"one", b"two", b"three"]
    assert dirs == ["outbound", "inbound", "outbound"]


def test_search_finds_a_marker_that_is_held():
    r = _ring()
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound",
             b"POST /login HTTP/1.1", now=0)

    out = r.search(b"/login", "192.0.2.5", "1.2.3.4", 443, "TCP")
    assert out["searched"] is True
    assert out["matched"] is True


# SECTION 8. RETENTION. The owner's first constraint.

def test_retention_default_is_days_not_forever():
    """
    The only default lifetime in days anywhere in this database, and that is
    on purpose: this is the one table that can hold the owner's own plaintext.
    """
    assert pr.DEFAULT_PAYLOAD_RETENTION_DAYS > 0
    assert pr.DEFAULT_PAYLOAD_RETENTION_DAYS <= 30


def test_retention_days_falls_back_on_a_junk_preference(monkeypatch):
    import core.memory_engine as me
    monkeypatch.setattr(me, "get_preference",
                        lambda k, default=None: "not-a-number")
    assert pr.retention_days() == pr.DEFAULT_PAYLOAD_RETENTION_DAYS


def test_retention_days_reads_the_preference(monkeypatch):
    import core.memory_engine as me
    monkeypatch.setattr(me, "get_preference", lambda k, default=None: "3")
    assert pr.retention_days() == 3


def test_status_reports_the_retention_window():
    r = _ring()
    assert r.status()["retention_days"] > 0


def test_status_notes_say_nothing_is_on_disk():
    r = _ring()
    notes = " ".join(r.status()["notes"]).lower()
    assert "not on disk" in notes or "nothing in the ring is on disk" in notes


def test_status_warns_when_capture_is_off():
    r = _ring(enabled=False)
    notes = " ".join(r.status()["notes"])
    assert "PAYLOAD CAPTURE IS OFF" in notes


# SECTION 8. THE REGRESSION, 2026-09-20. The flow key as the SNIFFER calls it.
#
# FAILURE FIRST, and this section only exists because section 4 was green while
# the feature was broken. Section 4 passes 443 as dst_port for BOTH directions.
# packet_sniffer never does that: it passes the real dst_port off the frame, so
# the outbound frame carries 443 and the reply carries the client's ephemeral
# port. The two halves of one conversation went into two different rings and a
# flush got half a conversation.
#
# Every test here calls append the way packet_sniffer calls it, with both ports.

def _as_sniffer_sees_it(ring, client, server, cport, sport, now_out, now_in):
    """One request and one reply, ported exactly as the capture callback is."""
    ring.append(client, server, sport, "TCP", "outbound", b"GET / HTTP/1.1",
                now=now_out, src_port=cport)
    ring.append(server, client, cport, "TCP", "inbound", b"HTTP/1.1 200 OK",
                now=now_in, src_port=sport)


def test_service_port_is_the_same_number_from_either_end():
    assert pr._service_port(51000, 443) == pr._service_port(443, 51000) == 443


def test_service_port_survives_a_missing_port():
    assert pr._service_port(None, 443) == 443
    assert pr._service_port(51000, None) == 51000
    assert pr._service_port(None, None) == 0


def test_real_port_pairing_lands_in_one_ring():
    """
    THE BUG. Outbound 443 and a reply from an ephemeral port are one
    conversation. Keyed on dst_port alone they were two.
    """
    r = _ring()
    _as_sniffer_sees_it(r, "192.0.2.29", "142.250.1.1", 51000, 443, 0, 1)
    assert r.status()["flows_in_ring"] == 1


def test_real_port_pairing_is_reachable_from_the_service_port():
    r = _ring()
    _as_sniffer_sees_it(r, "192.0.2.29", "142.250.1.1", 51000, 443, 0, 1)
    cov = r.coverage("192.0.2.29", "142.250.1.1", 443, "TCP")
    assert cov["covering"] is True
    assert cov["frames_held"] == 2
    assert cov["matched_by"] == "exact"


def test_a_detector_holding_the_ephemeral_port_still_finds_the_flow():
    """
    A detector that fired on an INBOUND frame has the client's ephemeral port,
    not the service port. One flow between the pair, so it is not a guess.
    """
    r = _ring()
    _as_sniffer_sees_it(r, "192.0.2.29", "142.250.1.1", 51000, 443, 0, 1)
    cov = r.coverage("142.250.1.1", "192.0.2.29", 51000, "TCP")
    assert cov["covering"] is True
    assert cov["matched_by"] == "pair"


def test_two_flows_between_the_same_pair_refuse_to_guess():
    """
    RULE TWO. Two conversations between the same two addresses and a port that
    matches neither is not answerable. Returning one of them would attach the
    wrong bytes to a finding, so nothing comes back and the note says why.
    """
    r = _ring()
    _as_sniffer_sees_it(r, "192.0.2.29", "142.250.1.1", 51000, 443, 0, 1)
    _as_sniffer_sees_it(r, "192.0.2.29", "142.250.1.1", 51001, 80, 2, 3)
    cov = r.coverage("192.0.2.29", "142.250.1.1", 9999, "TCP")
    assert cov["covering"] is False
    assert cov["matched_by"] == "ambiguous"
    assert "CANNOT BE TOLD APART" in cov["note"]


def test_search_on_an_ambiguous_pair_is_not_a_no_match():
    r = _ring()
    _as_sniffer_sees_it(r, "192.0.2.29", "142.250.1.1", 51000, 443, 0, 1)
    _as_sniffer_sees_it(r, "192.0.2.29", "142.250.1.1", 51001, 80, 2, 3)
    res = r.search(b"GET", "192.0.2.29", "142.250.1.1", 9999, "TCP")
    assert res["searched"] is False
    assert res["matched"] is None


def test_a_flush_from_either_direction_gets_the_whole_conversation(monkeypatch):
    written = []

    r = _ring()
    monkeypatch.setattr(r, "_write_frames",
                        lambda frames, *a, **k: written.append(len(frames))
                        or len(frames))

    _as_sniffer_sees_it(r, "192.0.2.29", "142.250.1.1", 51000, 443, 0, 1)

    out = r.flush("192.0.2.29", "142.250.1.1", 443, "TCP", "PKT-1001")
    assert out["ran"] is True
    assert out["rows"] == 2, "a flush must not get half a conversation"


def test_different_service_ports_are_still_different_flows():
    r = _ring()
    _as_sniffer_sees_it(r, "192.0.2.29", "142.250.1.1", 51000, 443, 0, 1)
    _as_sniffer_sees_it(r, "192.0.2.29", "142.250.1.1", 51001, 80, 2, 3)
    assert r.status()["flows_in_ring"] == 2


# SECTION 9. Disarming gives the memory back. 2026-09-20.
#
# FAILURE FIRST: an armed flow is never evicted and never idle swept. The flag
# was set once and never cleared, so disarming stopped new capture and left
# every flow that address had touched pinned for the life of the process.

def test_disarm_clears_the_sticky_flag_on_held_flows():
    r = _ring()
    r.arm("1.2.3.4")
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", b"x",
             now=0, src_port=51000)
    assert r.coverage("192.0.2.5", "1.2.3.4", 443, "TCP")["armed"] is True

    res = r.disarm("1.2.3.4")
    assert res["flows_released"] == 1
    assert r.coverage("192.0.2.5", "1.2.3.4", 443, "TCP")["armed"] is False


def test_disarm_leaves_flows_armed_by_another_destination_alone():
    r = _ring()
    r.arm("1.2.3.4")
    r.arm("5.6.7.8")
    r.append("1.2.3.4", "5.6.7.8", 443, "TCP", "outbound", b"x",
             now=0, src_port=51000)

    r.disarm("1.2.3.4")
    assert r.coverage("1.2.3.4", "5.6.7.8", 443, "TCP")["armed"] is True


def test_a_released_flow_can_be_idle_swept_again():
    """The point of clearing the flag: the memory comes back."""
    r = _ring()
    r.arm("1.2.3.4")
    r.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound", b"x",
             now=0, src_port=51000)
    r.disarm("1.2.3.4")

    # A new flow far in the future triggers the idle sweep.
    r.append("192.0.2.8", "9.9.9.9", 443, "TCP", "outbound", b"y",
             now=pr.FLOW_IDLE_SECS + 10, src_port=51001)
    assert r.coverage("192.0.2.5", "1.2.3.4", 443, "TCP")["flow_present"] is False


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
