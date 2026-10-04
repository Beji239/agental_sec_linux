# tests/test_detector_tools.py
# AgentalSec V2, TODO 120, 2026-09-20. The model's tools for 113.3 to 113.6.
#
# WHY THESE EXIST AT ALL. The four detectors shipped with no tools, so the
# model could see the FINDINGS they raised and could not ask them anything.
# Worse: every one of those modules computes a coverage answer whose whole job
# is to keep "I found nothing" apart from "I could not look", and none of
# those answers had a reader. The rule-two machinery was talking to itself.
#
# RULE ONE. Every section here tests the SENSOR-DOWN and NOTHING-LOADED case
# before it tests the case where there is something to find, because those are
# the answers that go wrong quietly. A tool that says "not listed" when no
# feed loaded, or "no payload" when no capture is running, is the exact lie
# these tools were added to make impossible.

import pathlib
import sys

# THE ROOT INSERTION, added 2026-09-21, and it is what makes this file a CHECK
# rather than a file that only passes when it is invoked a particular way.
#
# This file was ported from the Windows tree as-is, and it had no `sys.path`
# setup because there it was only ever run through `python -m pytest`, which
# puts the CURRENT DIRECTORY on the path. scripts/run_tests.py runs every file
# as a standalone script with the project root as cwd but does NOT put it on
# sys.path, so `from core import tool_registry` raised ModuleNotFoundError and
# the runner listed the file under "Could not run here: needs pytest".
#
# That read as a missing dependency for a suite that was installed. Five files
# were in that state. A test that cannot run must not look like a test that
# needs a package, and the fix is the same two lines the other ninety files
# in this folder already carry.
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db                              # noqa: E402
_isolate_db.isolate()

import pytest

from core import tool_registry as tr


# SECTION 1. The tools are actually reachable.

NEW_TOOLS = [
    "query_threat_feed", "query_payload", "query_lan_watch",
    "query_dns_inspection", "arm_payload_capture", "disarm_payload_capture",
]


@pytest.mark.parametrize("name", NEW_TOOLS)
def test_the_tool_is_in_the_manifest(name):
    assert name in {t["name"] for t in tr.TOOL_MANIFEST}


@pytest.mark.parametrize("name", NEW_TOOLS)
def test_the_tool_declares_what_it_rests_on(name):
    """An undeclared tool raises when executed. See core/sensor_health."""
    from core import sensor_health as sh
    assert name in sh.DEPENDS


def test_the_reads_are_classified_as_reads():
    for name in ["query_threat_feed", "query_payload", "query_lan_watch",
                 "query_dns_inspection"]:
        assert tr.tool_writes(name) is False


def test_arming_is_gated_and_disarming_is_not():
    """
    The undo direction is free, same as every other undo in this app. Arming
    writes real network content to disk, which is why it asks.
    """
    assert "arm_payload_capture" in tr.PERMISSION_GATED
    assert "disarm_payload_capture" not in tr.PERMISSION_GATED


def test_payload_and_feed_output_is_fenced():
    """
    query_payload returns raw bytes off the wire and query_threat_feed
    returns a malware family string somebody else wrote. Both are text this
    project did not author.
    """
    from core import sanitize
    assert "query_payload" in sanitize.UNTRUSTED_TOOLS
    assert "query_threat_feed" in sanitize.UNTRUSTED_TOOLS


# SECTION 2. FAILURE: no feed loaded. The worst lie this app could tell.

def _feed_state(monkeypatch, loaded, stale=False, count=10):
    from tools import feed_matcher as fm
    monkeypatch.setattr(fm, "status", lambda config=None: {
        "feed_loaded": loaded, "indicator_count": count if loaded else 0,
        "feed_age_hours": 1.0 if loaded else None, "stale": stale,
        "last_refresh_at": "now",
        "note": "loaded" if loaded else "nothing loaded",
    })


def test_an_unloaded_feed_answers_null_not_false(monkeypatch):
    """
    listed=False would read as "this address is fine". Nothing looked at it.
    """
    _feed_state(monkeypatch, loaded=False)
    out = tr._query_threat_feed("203.0.113.9")

    assert out["feed_loaded"] is False
    assert out["listed"] is None
    assert "NOT CHECKED" in out["reason"]


def test_an_unloaded_feed_says_so_with_no_indicator(monkeypatch):
    _feed_state(monkeypatch, loaded=False)
    out = tr._query_threat_feed()
    assert out["feed_loaded"] is False
    assert "listed" not in out


def test_a_feed_read_error_answers_null_too(monkeypatch):
    import contextlib
    import core.memory_engine as me
    _feed_state(monkeypatch, loaded=True)

    @contextlib.contextmanager
    def _boom():
        raise RuntimeError("table gone")
        yield
    monkeypatch.setattr(me, "_get_conn", _boom)

    out = tr._query_threat_feed("203.0.113.9")
    assert out["listed"] is None
    assert "could not be read" in out["reason"]


def test_a_miss_is_never_called_clean(monkeypatch):
    import contextlib
    import core.memory_engine as me
    from tools import feed_matcher as fm
    _feed_state(monkeypatch, loaded=True)
    monkeypatch.setattr(fm, "_feed_hit_ip", lambda conn, ip: None)

    @contextlib.contextmanager
    def _conn():
        yield object()
    monkeypatch.setattr(me, "_get_conn", _conn)

    out = tr._query_threat_feed("203.0.113.9")
    assert out["listed"] is False
    assert "NOT A CLEAN BILL" in out["note"]


def test_a_hit_carries_the_feed_and_the_family(monkeypatch):
    import contextlib
    import core.memory_engine as me
    from tools import feed_matcher as fm
    _feed_state(monkeypatch, loaded=True)
    monkeypatch.setattr(fm, "_feed_hit_ip",
                        lambda conn, ip: ("feodo", "Qakbot"))

    @contextlib.contextmanager
    def _conn():
        yield object()
    monkeypatch.setattr(me, "_get_conn", _conn)

    out = tr._query_threat_feed("203.0.113.9")
    assert out["listed"] is True
    assert out["feed"] == "feodo"
    assert out["malware_family"] == "Qakbot"
    assert out["severity_if_seen"] == "high"


def test_a_stale_feed_drops_the_severity(monkeypatch):
    import contextlib
    import core.memory_engine as me
    from tools import feed_matcher as fm
    _feed_state(monkeypatch, loaded=True, stale=True)
    monkeypatch.setattr(fm, "_feed_hit_ip", lambda conn, ip: ("feodo", ""))

    @contextlib.contextmanager
    def _conn():
        yield object()
    monkeypatch.setattr(me, "_get_conn", _conn)

    out = tr._query_threat_feed("203.0.113.9")
    assert out["severity_if_seen"] == "medium"
    assert "stale" in out["note"]


# SECTION 3. FAILURE: no capture running. "No payload" vs "no sensor".

def _no_db(monkeypatch):
    """The stored half unreadable, so only the ring half is under test."""
    import contextlib
    import core.memory_engine as me

    @contextlib.contextmanager
    def _boom():
        raise RuntimeError("no database here")
        yield
    monkeypatch.setattr(me, "_get_conn", _boom)


def test_no_capture_is_a_reason_not_an_empty_payload(monkeypatch):
    from tools import payload_ring as pr
    monkeypatch.setattr(pr, "_ACTIVE", None)
    _no_db(monkeypatch)

    out = tr._query_payload({"src_ip": "192.0.2.5", "dst_ip": "1.2.3.4",
                             "dst_port": 443})
    assert out["capture_running"] is False
    assert out["coverage"]["covering"] is False
    assert "not about the traffic" in out["coverage"]["note"]


def test_an_unreadable_table_is_not_an_empty_table(monkeypatch):
    from tools import payload_ring as pr
    monkeypatch.setattr(pr, "_ACTIVE", None)
    _no_db(monkeypatch)

    out = tr._query_payload({})
    assert out["stored"] is None
    assert "NOT an empty table" in out["stored_reason"]


def test_a_search_with_no_capture_is_not_a_no_match(monkeypatch):
    from tools import payload_ring as pr
    monkeypatch.setattr(pr, "_ACTIVE", None)
    _no_db(monkeypatch)

    out = tr._query_payload({"src_ip": "192.0.2.5", "dst_ip": "1.2.3.4",
                             "dst_port": 443, "contains": "password"})
    # No ring at all, so no search block is produced and coverage says why.
    assert "search" not in out
    assert out["coverage"]["covering"] is False


def test_a_search_on_an_empty_ring_returns_null_not_false(monkeypatch):
    from tools import payload_ring as pr
    _no_db(monkeypatch)

    ring = pr.PayloadRing("sess-test", None)
    ring._armed = set()
    ring._save_armed = lambda: None
    monkeypatch.setattr(pr, "_ACTIVE", ring)

    out = tr._query_payload({"src_ip": "192.0.2.5", "dst_ip": "1.2.3.4",
                             "dst_port": 443, "contains": "password"})
    assert out["search"]["searched"] is False
    assert out["search"]["matched"] is None


def test_a_real_hit_is_found_through_the_tool(monkeypatch):
    from tools import payload_ring as pr
    _no_db(monkeypatch)

    ring = pr.PayloadRing("sess-test", None)
    ring._armed = set()
    ring._save_armed = lambda: None
    ring.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound",
                b"GET /secret HTTP/1.1", now=0, src_port=51000)
    monkeypatch.setattr(pr, "_ACTIVE", ring)

    out = tr._query_payload({"src_ip": "192.0.2.5", "dst_ip": "1.2.3.4",
                             "dst_port": 443, "contains": "secret"})
    assert out["search"]["searched"] is True
    assert out["search"]["matched"] is True
    assert out["coverage"]["covering"] is True


def test_a_real_miss_is_a_real_miss(monkeypatch):
    from tools import payload_ring as pr
    _no_db(monkeypatch)

    ring = pr.PayloadRing("sess-test", None)
    ring._armed = set()
    ring._save_armed = lambda: None
    ring.append("192.0.2.5", "1.2.3.4", 443, "TCP", "outbound",
                b"GET / HTTP/1.1", now=0, src_port=51000)
    monkeypatch.setattr(pr, "_ACTIVE", ring)

    out = tr._query_payload({"src_ip": "192.0.2.5", "dst_ip": "1.2.3.4",
                             "dst_port": 443, "contains": "password"})
    assert out["search"]["searched"] is True
    assert out["search"]["matched"] is False


# SECTION 4. Arming, through the dispatch, both directions.

def test_arming_with_no_capture_refuses_rather_than_pretending(monkeypatch):
    """
    Recording an arm that captures nothing is worse than refusing: the user
    approved a capture and would get an empty table with no explanation.
    """
    from tools import payload_ring as pr
    monkeypatch.setattr(pr, "_ACTIVE", None)

    out = tr._dispatch("arm_payload_capture",
                       {"destination": "1.2.3.4", "reason": "suspicious"})
    assert out["armed"] is False
    assert "not running" in out["reason"]


def test_arming_works_and_says_how_long_it_keeps(monkeypatch):
    from tools import payload_ring as pr
    ring = pr.PayloadRing("sess-test", None)
    ring._armed = set()
    ring._save_armed = lambda: None
    monkeypatch.setattr(pr, "_ACTIVE", ring)
    monkeypatch.setattr(pr, "retention_days", lambda: 7)

    out = tr._dispatch("arm_payload_capture",
                       {"destination": "1.2.3.4", "reason": "beaconing"})
    assert out["armed"] is True
    assert out["reason_given"] == "beaconing"
    assert out["retention_days"] == 7
    assert "1.2.3.4" in ring.armed()


def test_disarming_releases_and_says_rows_are_kept(monkeypatch):
    from tools import payload_ring as pr
    ring = pr.PayloadRing("sess-test", None)
    ring._armed = set()
    ring._save_armed = lambda: None
    monkeypatch.setattr(pr, "_ACTIVE", ring)

    tr._dispatch("arm_payload_capture",
                 {"destination": "1.2.3.4", "reason": "x"})
    out = tr._dispatch("disarm_payload_capture", {"destination": "1.2.3.4"})

    assert out["was_armed"] is True
    assert "not deleted" in out["note"]
    assert ring.armed() == []


def test_disarming_with_no_capture_does_not_claim_it_knows(monkeypatch):
    from tools import payload_ring as pr
    monkeypatch.setattr(pr, "_ACTIVE", None)

    out = tr._dispatch("disarm_payload_capture", {"destination": "1.2.3.4"})
    assert out["was_armed"] is None, "whether it WAS armed cannot be read"


# SECTION 5. The LAN sensor. The unicast caveat has to survive the tool.

def test_no_sensor_says_nothing_was_examined(monkeypatch):
    from tools import lan_watch as lw
    monkeypatch.setattr(lw, "_ACTIVE", None)

    out = tr._query_lan_watch()
    assert out["running"] is False
    assert out["has_looked"] is False
    assert any("not the same as nothing being found" in n
               for n in out["notes"])


def test_a_running_sensor_still_carries_the_unicast_caveat(monkeypatch):
    from tools import lan_watch as lw
    w = lw.LanWatch(gateway_ip="192.0.2.1", load_baselines=False)
    monkeypatch.setattr(lw, "_ACTIVE", w)

    out = tr._query_lan_watch()
    assert out["running"] is True
    assert any("UNICAST" in n for n in out["notes"]), \
        "a clean run must never be quotable as proof"


def test_the_tool_says_the_baselines_do_not_move(monkeypatch):
    from tools import lan_watch as lw
    w = lw.LanWatch(gateway_ip="192.0.2.1", load_baselines=False)
    monkeypatch.setattr(lw, "_ACTIVE", w)

    assert "never move on" in tr._query_lan_watch()["baseline_note"]


# SECTION 6. DNS inspection coverage. The cursor IS the coverage answer.

class _DnsConn:
    def __init__(self, max_id, rows):
        self.max_id, self.rows = max_id, rows

    def execute(self, sql, params=()):
        s = " ".join(sql.split())

        class _C:
            def __init__(self, v):
                self.v = v

            def fetchone(self_inner):
                return self_inner.v
        if "MAX(id)" in s:
            return _C((self.max_id,))
        return _C((self.rows,))

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


def _wire_dns(monkeypatch, conn, cursor):
    import contextlib
    import core.memory_engine as me
    from tools import dns_inspector as di
    monkeypatch.setattr(di, "_get_cursor", lambda: cursor)

    @contextlib.contextmanager
    def _c():
        yield conn
    monkeypatch.setattr(me, "_get_conn", _c)


def test_an_unreadable_log_is_not_zero_coverage(monkeypatch):
    import contextlib
    import core.memory_engine as me
    from tools import dns_inspector as di
    monkeypatch.setattr(di, "_get_cursor", lambda: 0)

    @contextlib.contextmanager
    def _boom():
        raise RuntimeError("locked")
        yield
    monkeypatch.setattr(me, "_get_conn", _boom)

    out = tr._query_dns_inspection()
    assert out["inspected"] is None
    assert "UNKNOWN" in out["reason"]


def test_a_backlog_is_reported_as_uncovered(monkeypatch):
    _wire_dns(monkeypatch, _DnsConn(max_id=500, rows=500), cursor=100)

    out = tr._query_dns_inspection()
    assert out["rows_not_yet_inspected"] == 400
    assert "have NOT been looked at" in out["coverage_note"]


def test_being_level_with_the_log_says_so(monkeypatch):
    _wire_dns(monkeypatch, _DnsConn(max_id=500, rows=500), cursor=500)

    out = tr._query_dns_inspection()
    assert out["rows_not_yet_inspected"] == 0
    assert "covers everything imported" in out["coverage_note"]


def test_the_encrypted_dns_blind_spot_is_always_stated(monkeypatch):
    _wire_dns(monkeypatch, _DnsConn(max_id=1, rows=1), cursor=1)
    assert "encrypted DNS" in tr._query_dns_inspection()["blind_spot"]


def test_the_unbuilt_checks_are_named_not_implied(monkeypatch):
    """
    The two lists answer two different questions and must not be collapsed.

    REWRITTEN 2026-09-22, and the old version of this test was asserting a
    falsehood. It required "NXDOMAIN" and "TXT" to appear in `not_implemented`,
    on the belief that those checks could not be built. They could: the data
    was in the table the whole time, the checks now exist (DNS-1005, DNS-1006),
    and this test was the thing that would have gone red on the day somebody
    built them -- which is the correct behaviour for a test, and worth saying
    because it is how the stale claim survived: the code was wrong, the note
    repeated the wrong reason, and the test pinned the note.

    What is required now is the distinction itself:
      not_implemented  a check that does not exist. Nothing may imply it ran.
      coverage_limits   a check that exists but could not read what it needed.
    A tool that stayed quiet about either would let the model present an
    unchecked thing as a checked one.
    """
    _wire_dns(monkeypatch, _DnsConn(max_id=1, rows=1), cursor=1)
    out = tr._query_dns_inspection()

    # The checks that were missing are now named as CHECKS, not as gaps.
    checks = " ".join(out["checks"])
    assert "DNS-1005" in checks and "NXDOMAIN" in checks
    assert "DNS-1006" in checks and "TXT" in checks

    # And `not_implemented` no longer claims the data is absent, which was the
    # sentence that told the model not to look.
    text = " ".join(out["not_implemented"])
    assert "does not carry the response code" not in text
    assert "does not carry the query type" not in text
    assert "coverage_limits" in out


if __name__ == "__main__":
    import sys
    try:
        import pytest as _pytest
    except ImportError:
        print("FAILURE: pytest is not installed, so NONE of the checks in "
              "this file ran. Fix with: pip install pytest")
        sys.exit(1)
    sys.exit(_pytest.main([__file__, "-q"]))
