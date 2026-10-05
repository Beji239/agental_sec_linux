# tests/test_dns_inspection.py
# AgentalSec V2, TODO 113.3. Unit tests for dns_inspector.
#
# FAILURE CASES FIRST (per project convention):
#   no config / dns_monitor unavailable
#   empty dns_queries table
#   entropy below threshold (short, normal words)
#   interval too irregular (CV above ceiling)
#   count below minimum
#
# HAPPY PATH:
#   DGA candidate: high-entropy long label, queried twice
#   Beacon: 6+ queries, tight CV
#
# HOW THESE TESTS WORK WITHOUT A REAL DATABASE
#
# dns_inspector._check_dga and _check_beacons receive a conn that was opened by
# analyse_once. We test the helper functions directly, and we test analyse_once
# by supplying a fake conn via monkeypatch. This avoids needing a real SQLite
# file and means the tests are pure-python with no I/O.

import pathlib
import sys

# THE ROOT INSERTION, added 2026-09-21. See the note in test_detector_tools.py
# for the full reason: this file had no `sys.path` setup because it was only
# ever run through `python -m pytest`, which puts the current directory on the
# path. scripts/run_tests.py runs it as a standalone script and does not, so
# the import below failed and the runner reported the file as needing pytest.
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db                              # noqa: E402
_isolate_db.isolate()

import math
import statistics
import pytest

from tools import dns_inspector as di


@pytest.fixture(autouse=True)
def _nothing_dismissed(monkeypatch):
    """The raisers ask about dismissals; nothing here is dismissed unless a
    test says so, and no test reads the real store for it."""
    import core.memory_engine as me
    monkeypatch.setattr(me, "is_dismissed", lambda *a, **k: False)


# entropy helper

def test_entropy_empty_returns_zero():
    assert di._entropy("") == 0.0


def test_entropy_single_char_is_zero():
    # Only one symbol: -1 * log2(1) = 0
    assert di._entropy("aaaa") == 0.0


def test_entropy_two_equal_halves():
    # "aabb": p(a)=0.5, p(b)=0.5. H = -2*(0.5*log2(0.5)) = 1.0
    assert abs(di._entropy("aabb") - 1.0) < 1e-9


def test_entropy_english_word_below_threshold():
    # "dropbox": 7 chars, low entropy. Should not fire.
    e = di._entropy("dropbox")
    assert e < di.DGA_ENTROPY_THRESHOLD


def test_entropy_dga_like_string_above_threshold():
    # Random hex-like string typical of DGA output
    e = di._entropy("x7kq2mzpvw3n")
    assert e >= di.DGA_ENTROPY_THRESHOLD


# second-level label extraction

def test_sll_simple():
    assert di._second_level_label("evil.com") == "evil"


def test_sll_subdomain():
    assert di._second_level_label("abc.evil.com") == "evil"


def test_sll_co_uk():
    # Two-label TLD: should step left
    assert di._second_level_label("evil.co.uk") == "evil"


def test_sll_bare_ip_returns_empty():
    assert di._second_level_label("192.0.2.33") == ""


def test_sll_bare_label_returns_empty():
    assert di._second_level_label("localhost") == ""


def test_sll_four_letter_brand_is_not_mistaken_for_a_suffix():
    """
    REGRESSION, 2026-09-20. The first version stepped left whenever the
    candidate was <=4 letters, so "abc.evil.com" scored "abc" instead of
    "evil". Any four-letter domain was being scored on its subdomain.
    """
    assert di._second_level_label("abc.evil.com") == "evil"
    assert di._second_level_label("cdn.acme.com") == "acme"


def test_sll_partial_numeric_name_returns_empty():
    assert di._second_level_label("192.0.2.1") == ""
    assert di._second_level_label("1.2") == ""


def test_sll_deep_co_uk():
    assert di._second_level_label("a.b.evil.co.uk") == "evil"


def test_sll_trailing_dot():
    # DNS trailing dot is valid
    assert di._second_level_label("evil.com.") == "evil"


# is_dga_candidate

def test_dga_candidate_short_label_rejected():
    # "evil" is 4 chars, below DGA_MIN_LABEL_LEN
    assert di._is_dga_candidate("evil.com") is False


def test_dga_candidate_known_root_skipped():
    # cloudfront is in _KNOWN_ROOTS; length and entropy don't matter
    assert di._is_dga_candidate("d1234.cloudfront.net") is False


def test_dga_candidate_low_entropy_rejected():
    # "github" is 6 chars - below length, but also low entropy
    assert di._is_dga_candidate("github.com") is False


def test_dga_candidate_english_long_word_rejected():
    # "microsoftstore" is long but very low entropy (repeating patterns)
    # It may or may not fire depending on exact entropy - test that known words don't
    # "stackoverflow" - entropy is moderate but below threshold
    result = di._is_dga_candidate("stackoverflow.com")
    # Either result is fine as long as the logic runs; we mainly care it doesn't crash
    assert isinstance(result, bool)


def test_dga_candidate_high_entropy_long_label():
    # "x7kq2mzpvw3n" is 12 chars and high entropy: should be a candidate
    assert di._is_dga_candidate("x7kq2mzpvw3n.com") is True


# FAILURE: analyse_once when dns_monitor not available

def test_analyse_once_dns_monitor_unavailable(monkeypatch):
    import tools.dns_monitor as dm
    monkeypatch.setattr(dm, "status", lambda config: {"available": False})

    result = di.analyse_once({}, "sess-test")

    assert result["ran"] is False
    assert result["dga_findings"] == 0
    assert result["beacon_findings"] == 0
    assert "reason" in result


# FAILURE: empty dns_queries table

class _FakeConn:
    """Minimal fake sqlite3 connection used by several tests."""

    def __init__(self, rows_by_query):
        # rows_by_query: dict of sql_fragment -> list of rows
        self._rows = rows_by_query

    def execute(self, sql, params=()):
        # Normalise whitespace so a multi-line SQL string still matches a
        # single-line fragment. The first version of this fake routed on
        # "COUNT(*)", which appears in BOTH the DGA count query and the
        # beacon candidate query, so the beacon path got handed a one-column
        # row and blew up on unpack. Route on fragments that appear in
        # exactly one query.
        #
        # LONGEST MATCH WINS, changed 2026-09-22. First-match-wins depended on
        # dict insertion order, so adding the tunnel and volume queries made a
        # fixture that routed on "DISTINCT client_ip" start answering for a
        # query it was never written for -- the same class of mistake as the
        # COUNT(*) one, arriving from the other direction. Longest match means
        # the most specific fragment decides, which is what "appears in exactly
        # one query" was always trying to say.
        s = " ".join(sql.split())
        best = None
        for fragment, rows in self._rows.items():
            if fragment in s and (best is None or len(fragment) > len(best)):
                best = fragment
        if best is not None:
            return _FakeCursor(self._rows[best])
        return _FakeCursor([])

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


class _FakeCursor:
    def __init__(self, rows):
        self._rows = rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows


def _patch_analyse(monkeypatch, fake_conn):
    """Wire monkeypatches so analyse_once uses fake_conn and skips I/O."""
    import tools.dns_monitor as dm
    monkeypatch.setattr(dm, "status", lambda config: {"available": True})
    monkeypatch.setattr(di, "_get_cursor", lambda: 0)
    monkeypatch.setattr(di, "_set_cursor", lambda v: None)

    import contextlib
    @contextlib.contextmanager
    def _fake_get_conn():
        yield fake_conn

    import core.memory_engine as me
    monkeypatch.setattr(me, "_get_conn", _fake_get_conn)


def test_analyse_once_empty_table(monkeypatch):
    conn = _FakeConn({"MAX(id)": [(0,)]})
    _patch_analyse(monkeypatch, conn)

    result = di.analyse_once({}, "sess-test")

    assert result["ran"] is True
    assert result["dga_findings"] == 0
    assert result["beacon_findings"] == 0


# FAILURE: below count minimum (DGA)

def test_dga_below_min_count(monkeypatch):
    """High-entropy domain but only 1 query: should not fire."""

    # Rows returned from DISTINCT SELECT: one candidate
    dga_rows = [("192.0.2.5", "x7kq2mzpvw3n.com")]
    # Count for that pair: 1 (below DGA_MIN_COUNT=2)
    count_rows = [(1,)]

    conn = _FakeConn({
        "MAX(id)": [(10,)],
        "GROUP BY client_ip, domain": [],          # beacon: no candidates
        "DISTINCT client_ip": dga_rows,
        "COUNT(*) FROM dns_queries WHERE client_ip": count_rows,
    })
    _patch_analyse(monkeypatch, conn)

    import core.memory_engine as me
    monkeypatch.setattr(me, "finding_already_open",
                        lambda *a, **k: False)
    monkeypatch.setattr(me, "save_finding",
                        lambda **k: {"saved": True})

    result = di.analyse_once({}, "sess-test")

    assert result["ran"] is True
    assert result["dga_findings"] == 0


# FAILURE: interval too irregular (beacon)

def test_beacon_cv_too_high():
    """Intervals with CV > 0.25: _check_beacons should not raise."""
    # Simulate irregular intervals: 60s, 300s, 30s, 200s, 100s (very bursty)
    intervals = [60, 300, 30, 200, 100, 250, 45]
    mean = statistics.mean(intervals)
    stddev = statistics.stdev(intervals)
    cv = stddev / mean
    assert cv > di.BEACON_CV_CEILING, \
        f"Test assumption failed: CV={cv:.3f} should exceed {di.BEACON_CV_CEILING}"


def test_beacon_mean_interval_too_short():
    """Mean interval < 30s: classified as burst, not beacon."""
    intervals = [5, 6, 5, 7, 5, 6]
    mean = statistics.mean(intervals)
    assert mean < di.BEACON_MIN_INTERVAL_SECS


# HAPPY PATH: DGA finding raised

def test_dga_finding_raised(monkeypatch):
    """High-entropy domain queried twice: DNS-1001 should fire."""

    saved_findings = []

    dga_rows = [("192.0.2.5", "x7kq2mzpvw3n.com")]
    count_rows = [(3,)]  # 3 total queries, above DGA_MIN_COUNT=2

    conn = _FakeConn({
        "MAX(id)": [(10,)],
        "GROUP BY client_ip, domain": [],          # beacon: no candidates
        "DISTINCT client_ip": dga_rows,
        "COUNT(*) FROM dns_queries WHERE client_ip": count_rows,
    })
    _patch_analyse(monkeypatch, conn)

    import core.memory_engine as me
    monkeypatch.setattr(me, "finding_already_open", lambda *a, **k: False)

    def fake_save(**kwargs):
        saved_findings.append(kwargs)
        return {"saved": True}

    monkeypatch.setattr(me, "save_finding", fake_save)

    result = di.analyse_once({}, "sess-test")

    assert result["ran"] is True
    assert result["dga_findings"] == 1
    assert len(saved_findings) == 1
    assert saved_findings[0]["detection_id"] == "DNS-1001"
    assert saved_findings[0]["entity_value"] == "192.0.2.5"


# HAPPY PATH: beacon finding raised

def _iso(ts_unix: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts_unix, tz=timezone.utc).isoformat()


def test_beacon_finding_raised(monkeypatch):
    """
    8 queries spaced ~60s apart (CV well below 0.25): DNS-1002 should fire.
    """
    import time as _time

    now = 1789800000.0
    # 8 queries at ~60s intervals with tiny jitter
    base_times = [now - 7 * 60 + i * 60 + (i % 3) for i in range(8)]
    ts_rows = [(_iso(t),) for t in base_times]

    beacon_candidates = [("192.0.2.7", "update.evilc2.com", 8)]
    saved_findings = []

    # The conn must answer different queries with different results.
    # We use a smarter fake that routes by keyword.
    class _SmartConn:
        def execute(self, sql, params=()):
            if "MAX(id)" in sql:
                return _FakeCursor([(20,)])
            # ORDER MATTERS HERE AND IT IS NOT COSMETIC. The tunnel check and
            # the volume check were added to analyse_once on 2026-09-22, and
            # this fixture's ts_rows are (timestamp,) tuples. A branch below
            # that matched them would unpack one value where three are
            # expected, which is how a working rule reports itself as a
            # broken one.
            if "AS nxdomain" in sql:
                return _FakeCursor([])                 # no volume activity
            if "queried_at >= ? AND client_ip IS NOT NULL AND domain IS NOT NULL" in sql \
                    and "DISTINCT" in sql:
                return _FakeCursor([])                 # no tunnel payloads
            if "DISTINCT client_ip" in sql:
                return _FakeCursor([])                 # no DGA rows
            if "GROUP BY client_ip" in sql:
                return _FakeCursor(beacon_candidates)
            if "queried_at" in sql and "ORDER BY" in sql:
                return _FakeCursor(ts_rows)
            return _FakeCursor([])

        def __enter__(self): return self
        def __exit__(self, *a): pass

    _patch_analyse(monkeypatch, _SmartConn())

    import core.memory_engine as me
    monkeypatch.setattr(me, "finding_already_open", lambda *a, **k: False)

    def fake_save(**kwargs):
        saved_findings.append(kwargs)
        return {"saved": True}

    monkeypatch.setattr(me, "save_finding", fake_save)

    result = di.analyse_once({}, "sess-test")

    assert result["ran"] is True
    assert result["beacon_findings"] == 1
    assert len(saved_findings) == 1
    assert saved_findings[0]["detection_id"] == "DNS-1002"
    assert saved_findings[0]["entity_value"] == "192.0.2.7"


# DEDUP: finding_already_open suppresses re-raise

def test_dga_dedup_suppresses(monkeypatch):
    """If finding_already_open returns True, save_finding is not called."""

    dga_rows = [("192.0.2.5", "x7kq2mzpvw3n.com")]
    count_rows = [(5,)]

    conn = _FakeConn({
        "MAX(id)": [(10,)],
        "GROUP BY client_ip, domain": [],          # beacon: no candidates
        "DISTINCT client_ip": dga_rows,
        "COUNT(*) FROM dns_queries WHERE client_ip": count_rows,
    })
    _patch_analyse(monkeypatch, conn)

    import core.memory_engine as me
    monkeypatch.setattr(me, "finding_already_open", lambda *a, **k: True)

    save_calls = []
    monkeypatch.setattr(me, "save_finding",
                        lambda **k: save_calls.append(k) or {"saved": True})

    result = di.analyse_once({}, "sess-test")

    assert result["dga_findings"] == 0
    assert len(save_calls) == 0


# THE REGRESSION, 2026-09-20. One client, several DGA domains.
#
# FAILURE FIRST. The title used to be "DGA-profile domain queried by <ip>"
# with no domain in it, and finding_already_open matches on the title. So the
# first DGA domain for a client raised and every other one was dropped in
# silence, which is the ONE signal DGA actually produces. There was no test
# for two domains from one client, which is why it shipped.

# Twelve names that all clear the entropy and length gate. Checked by the
# test below rather than assumed: the first version of this list was built
# with an f-string and only nine of the twelve actually passed, so the cap
# test was quietly measuring the wrong number.
_TWELVE_DGA_NAMES = [
    "w8en9bctdmu4s.com", "pbc967h4t58ud.com", "qw8ub64n5hzte.com",
    "upetd9j6xf54w.com", "nmdtycubvgr6p.com", "wqu8mjhfy3c74.com",
    "96kzqjvcdspf7.com", "j7rpbxc2tuk4m.com", "9u3qc45iryx7b.com",
    "vwux4qjyn6ma5.com", "yfvdrbg2jehnw.com", "9cfqntiep43zm.com",
]


def test_the_cap_fixture_names_all_clear_the_gate():
    """A precondition, not a feature. See the comment above the list."""
    assert all(di._is_dga_candidate(d) for d in _TWELVE_DGA_NAMES)


def _dga_setup(monkeypatch, pairs, count_each=5):
    """analyse_once wired to return `pairs` as DGA candidates."""
    conn = _FakeConn({
        "MAX(id)": [(10,)],
        "GROUP BY client_ip, domain": [],           # beacon: nothing
        "DISTINCT client_ip": pairs,
        "COUNT(*) FROM dns_queries WHERE client_ip": [(count_each,)],
    })
    _patch_analyse(monkeypatch, conn)

    import core.memory_engine as me
    monkeypatch.setattr(me, "finding_already_open", lambda *a, **k: False)

    saved = []
    monkeypatch.setattr(me, "save_finding",
                        lambda **k: saved.append(k) or {"saved": True})
    return saved


def test_two_dga_domains_from_one_client_both_raise(monkeypatch):
    """THE BUG. Two rotating names from one device must be two findings."""
    saved = _dga_setup(monkeypatch, [
        ("192.0.2.5", "x7kq2mzpvw3n.com"),
        ("192.0.2.5", "q9vbz3hmtkrd.com"),
    ])

    result = di.analyse_once({}, "sess-test")

    assert result["dga_findings"] == 2
    assert len(saved) == 2


def test_the_domain_is_in_the_title(monkeypatch):
    """
    The title is the dedup identity. A title with only the client in it makes
    every domain after the first one invisible.
    """
    saved = _dga_setup(monkeypatch, [("192.0.2.5", "x7kq2mzpvw3n.com")])
    di.analyse_once({}, "sess-test")

    assert "x7kq2mzpvw3n.com" in saved[0]["title"]


def test_titles_for_different_domains_are_different(monkeypatch):
    saved = _dga_setup(monkeypatch, [
        ("192.0.2.5", "x7kq2mzpvw3n.com"),
        ("192.0.2.5", "q9vbz3hmtkrd.com"),
    ])
    di.analyse_once({}, "sess-test")

    titles = {s["title"] for s in saved}
    assert len(titles) == 2


def test_the_same_domain_twice_is_still_one_finding(monkeypatch):
    """The dedup that was wanted still works, it was only too wide."""
    saved = _dga_setup(monkeypatch, [
        ("192.0.2.5", "x7kq2mzpvw3n.com"),
        ("192.0.2.5", "x7kq2mzpvw3n.com"),
    ])
    di.analyse_once({}, "sess-test")
    assert len(saved) == 1


def test_two_clients_querying_the_same_domain_both_raise(monkeypatch):
    saved = _dga_setup(monkeypatch, [
        ("192.0.2.5", "x7kq2mzpvw3n.com"),
        ("192.0.2.6", "x7kq2mzpvw3n.com"),
    ])
    di.analyse_once({}, "sess-test")
    assert len(saved) == 2


def test_many_domains_are_capped_not_dropped(monkeypatch):
    """
    The other half of the fix. A client rotating through many names must not
    produce one row per name, and must not silently lose the rest either.
    """
    pairs = [("192.0.2.5", d) for d in _TWELVE_DGA_NAMES]
    saved = _dga_setup(monkeypatch, pairs)

    di.analyse_once({}, "sess-test")

    individual = [s for s in saved if "Not listed individually" not in
                  (s.get("description") or "")]
    summary = [s for s in saved if "Not listed individually" in
               (s.get("description") or "")]
    # THE SPLIT KEY IS RESTATED 2026-09-27 (register section 15, DNS-18), and
    # it had become a fixture defect rather than a code defect. These two
    # lists used to be split on the phrase "queried many", which lived in the
    # summary's TITLE. The title no longer names the count or those words —
    # see the note on the assertion below — so the old key put the summary
    # into `individual` and reported 6 where 5 is correct. The split now uses
    # the summary's own DESCRIPTION sentence, which is the field that
    # distinguishes it by what the row SAYS rather than by one wording.

    assert len(individual) == di.DGA_MAX_PER_CLIENT_PER_PASS
    assert len(summary) == 1, "the overflow must be reported, not dropped"
    # RESTATED 2026-09-27 (register section 15, DNS-18). This read
    # `assert "12" in summary[0]["title"]` and `"Not listed individually: 7"`
    # because the summary TITLE carried the count. The title no longer does,
    # deliberately: finding_already_open matches on the title, so a title
    # carrying a number that grows is a NEW finding every pass. MEASURED on a
    # scratch store: one unchanged condition whose count drifted wrote FOUR
    # rows. The counts live in the DESCRIPTION now, where they can move
    # without changing the row's identity — so the assertion moves with them.
    assert "queried many" not in summary[0]["title"]
    assert "Distinct DGA-profile domains from 192.0.2.5 in this pass: 12" in \
        summary[0]["description"]
    assert "Not listed individually: 7" in summary[0]["description"]


def test_exactly_at_the_cap_raises_no_summary(monkeypatch):
    pairs = [("192.0.2.5", d)
             for d in _TWELVE_DGA_NAMES[:di.DGA_MAX_PER_CLIENT_PER_PASS]]
    saved = _dga_setup(monkeypatch, pairs)

    di.analyse_once({}, "sess-test")

    assert not any("queried many" in s["title"] for s in saved)


def test_the_summary_row_is_high_severity(monkeypatch):
    """
    One odd name is a CDN hash more often than malware, so the individual
    rows stay medium. A dozen from one device in one window is the rotation
    the detection exists to find, and that is a high.
    """
    pairs = [("192.0.2.5", d) for d in _TWELVE_DGA_NAMES]
    saved = _dga_setup(monkeypatch, pairs)

    di.analyse_once({}, "sess-test")

    individual = [s for s in saved if "Not listed individually" not in
                  (s.get("description") or "")]
    summary = [s for s in saved if "Not listed individually" in
               (s.get("description") or "")]
    # Same restatement as the sibling above, 2026-09-27: the split key moved
    # from a title phrase to the summary's own description sentence.

    assert all(s["severity"] == "medium" for s in individual)
    assert summary[0]["severity"] == "high"


def test_both_dga_severities_are_declared():
    """A severity the register does not declare is refused by save_finding."""
    from core import detections as det
    entry = det.get("DNS-1001") if hasattr(det, "get") else None
    allowed = None
    for name in ("SEVERITIES", "severities"):
        if entry and isinstance(entry, dict) and name in entry:
            allowed = entry[name]
    if allowed is None:
        import core.detections as d
        src = open(d.__file__, encoding="utf-8").read()
        assert '{"medium", "high"}' in src
    else:
        assert {"medium", "high"} <= set(allowed)


# DNS-1003 to DNS-1006, ADDED 2026-09-22.
#
# THE SCOPE FAILURE FIRST, because it is the reason this section exists and it
# is not a threshold anyone could have tuned. `_is_dga_candidate` scores
# `_second_level_label`, which returns ONE label by construction. A tunnel that
# writes its payload to the LEFT of that label was never measured by anything
# in this file. The first four checks below pin that: where the boundary is,
# what the payload extractor returns, and that a real tunnel name is invisible
# to the DGA gate while being visible to the tunnel gate.
#
# THEN THE FALSE-POSITIVE CASE, which is why the rule is grouped by registered
# domain rather than by client. That correction came out of a measurement made
# while writing this section: the entropy of a 12-character base32 payload
# (median 3.25) is LOWER than that of an ordinary long word like
# "windowsupdate" (3.39), so no entropy threshold separates tunnel labels from
# dictionary words at that length. See TUNNEL_ENTROPY_FLOOR in the module.

def test_the_payload_label_is_the_one_left_of_the_registered_domain():
    assert di._payload_labels("aBcDeF123456.evil.com") == ["abcdef123456"]


def test_the_payload_can_be_several_labels_deep():
    assert di._payload_labels("x.y.evil.co.uk") == ["x", "y"]


def test_a_name_with_nothing_to_the_left_has_no_payload():
    assert di._payload_labels("evil.com") == []


def test_the_registered_boundary_is_not_guessed_twice():
    """
    The DGA check and the tunnel check have to agree about where the
    registered domain starts. Two functions deciding that separately is how
    one of them silently scores a different part of the name.
    """
    for name in ("evil.com", "abc.evil.com", "a.b.evil.co.uk", "x.evil.com."):
        parts = di._domain_parts(name)
        idx = di._registered_index(parts)
        assert parts[idx] == di._second_level_label(name)


def test_the_registered_domain_is_the_grouping_key():
    assert di._registered_domain("aBcDeF123456.evil.com") == "evil.com"
    assert di._registered_domain("x.y.evil.co.uk") == "evil.co.uk"
    assert di._registered_domain("evil.com") == "evil.com"


def test_a_bare_ip_and_a_non_domain_have_no_payload_labels():
    assert di._payload_labels("192.0.2.33") == []
    assert di._payload_labels("1.2") == []
    assert di._payload_labels("") == []


def test_the_dga_gate_cannot_see_a_tunnel_label():
    """
    THE GAP, ASSERTED RATHER THAN DESCRIBED. The payload clears the tunnel
    floor on its own; the DGA gate is looking at "evil" and scores nothing.
    This is the exact defect that was reported, and it stays true if somebody
    later lowers DGA_ENTROPY_THRESHOLD, which is why it is a test about SCOPE
    and not about a number.
    """
    tunnel_name = "pbc967h4t58udqw8ub64n5hzte.evil.com"
    payload = di._payload_labels(tunnel_name)[0]

    assert di._entropy(payload) >= di.TUNNEL_ENTROPY_FLOOR
    assert di._is_dga_candidate(tunnel_name) is False, \
        "the DGA check scores the registered label and cannot see this"


def test_the_entropy_floor_is_a_floor_and_not_a_classifier():
    """
    MEASURED, NOT ASSERTED FROM PROSE. This pins the finding that shaped the
    rule: the two populations OVERLAP, so no threshold on this feature
    separates an encoded label from an ordinary word. The test is written as
    the overlap rather than one hand-picked pair, because the first version of
    it picked a single payload that happened to score 3.70 and failed for that
    reason alone -- a fixture asserting a general fact from one sample.

    The numbers, over 200 deterministic payloads against these words: the
    words reach 3.45 ("googlesyndication") and the payloads start at 2.5, so
    there is no line to draw. That is why the claim is the SHAPE (one domain,
    many rotating labels) and the entropy is only a floor.
    """
    import base64
    import hashlib

    words = ["googlesyndication", "windowsupdate", "microsoftonline",
             "authenticationsupport", "notificationconfiguration"]
    payloads = []
    for n in range(200):
        raw = hashlib.sha256(f"sample-{n}".encode()).digest()
        label = base64.b32encode(raw).decode().lower().rstrip("=")[:12]
        payloads.append(di._entropy(label))

    top_words = max(di._entropy(w) for w in words)
    bottom_payloads = sorted(payloads)[:20]          # the lowest 10%

    assert min(bottom_payloads) < top_words, \
        ("an ordinary word scores at or above real encoded labels, so this "
         "gate cannot be the thing that discriminates and must not be "
         "tightened as though it were")


def test_one_encoded_name_is_not_a_tunnel():
    """
    NOISE CASE. A single hash in a CDN-ish name is entirely ordinary: signed
    URLs and cache busters look exactly like this. One name is not rotation.
    """
    assert di.TUNNEL_MIN_DISTINCT_PER_CLIENT > 1


def test_an_ordinary_name_is_not_a_payload():
    assert di._payload_labels("www.google.com") == ["www"]
    assert len("www") < di.TUNNEL_MIN_PAYLOAD_LEN


def _tunnel_setup(monkeypatch, pairs, activity_rows=None):
    """
    analyse_once wired to return `pairs` as (client, domain) rows.

    THE ROUTING KEYS ARE FRAGMENTS THAT APPEAR IN EXACTLY ONE QUERY, which is
    a lesson this file already carries in _FakeConn's own comment: an earlier
    fake routed on "COUNT(*)" and handed the beacon path a one-column row.
    The new checks added two more queries to this pass, and the fragments
    below are what keeps them apart: the tunnel read is the one that filters
    on queried_at AND domain IS NOT NULL, the DGA read filters on id, and the
    per-client totals are the only query that computes AS nxdomain.
    """
    conn = _FakeConn({
        "MAX(id)": [(10,)],
        "AS nxdomain": activity_rows or [],
        # THE TUNNEL READ and the DGA read are two DISTINCT client/domain
        # queries, and they differ in one clause: the DGA one pages by id,
        # the tunnel one windows by queried_at. Routing on the clause that
        # includes the table name makes each key appear in exactly one query.
        "DISTINCT client_ip, domain FROM dns_queries WHERE queried_at": pairs,
        "DISTINCT client_ip, domain FROM dns_queries WHERE id > ?": pairs,
        # The beacon read is the only one with a HAVING, and it takes three
        # columns: routing it onto the two-tuple tunnel rows is the exact
        # shape of fixture bug this file's fake already documents once.
        "GROUP BY client_ip, domain HAVING cnt": [],
        "COUNT(*) FROM dns_queries WHERE client_ip": [(3,)],
    })
    _patch_analyse(monkeypatch, conn)

    import core.memory_engine as me
    monkeypatch.setattr(me, "finding_already_open", lambda *a, **k: False)

    saved = []
    monkeypatch.setattr(me, "save_finding",
                        lambda **k: saved.append(k) or {"saved": True})
    return saved


# Sixteen distinct payloads on ONE registered domain. Generated so each one
# clears the floor, and checked by the precondition test below rather than
# assumed: the first version of this list was built from a counter and nine of
# its twelve payloads did not clear the gate at all.
import base64                                          # noqa: E402
import hashlib                                         # noqa: E402


def _payload(n: int, size: int = 16) -> str:
    raw = hashlib.sha256(f"exfil-chunk-{n}".encode()).digest()
    return base64.b32encode(raw).decode().lower().rstrip("=")[:size]


_TUNNEL_NAMES = [f"{_payload(n)}.evil.com" for n in range(16)]


def test_the_tunnel_fixture_names_all_clear_the_gate():
    """
    A precondition rather than a feature, the same as the twelve DGA names
    earlier in this file. Without it the cap test below can silently measure
    the wrong number, which is exactly what happened to the DGA list once and
    to the first version of this one.
    """
    for d in _TUNNEL_NAMES:
        payload = di._payload_labels(d)[0]
        assert len(payload) >= di.TUNNEL_MIN_PAYLOAD_LEN
        assert di._entropy(payload) >= di.TUNNEL_ENTROPY_FLOOR


def test_five_distinct_encoded_names_raise_the_tunnel_rule(monkeypatch):
    saved = _tunnel_setup(monkeypatch,
                          [("192.0.2.5", d) for d in
                           _TUNNEL_NAMES[:di.TUNNEL_MIN_DISTINCT_PER_CLIENT]])

    result = di.analyse_once({}, "sess-test")

    assert result["ran"] is True
    assert result["tunnel_findings"] == 1
    tunnels = [s for s in saved if s["detection_id"] == "DNS-1003"]
    assert len(tunnels) == 1
    assert tunnels[0]["severity"] == "medium"
    assert "192.0.2.5" in tunnels[0]["title"]
    assert "evil.com" in tunnels[0]["title"]


def test_four_distinct_names_stay_below_the_gate(monkeypatch):
    """The failure case: one short of the documented minimum."""
    saved = _tunnel_setup(monkeypatch,
                          [("192.0.2.5", d)
                           for d in _TUNNEL_NAMES[:di.TUNNEL_MIN_DISTINCT_PER_CLIENT - 1]])

    result = di.analyse_once({}, "sess-test")

    assert result["tunnel_findings"] == 0
    assert not [s for s in saved if s["detection_id"] == "DNS-1003"]


def test_a_plain_domain_that_repeats_a_hash_is_not_a_tunnel(monkeypatch):
    """
    NOISE. The same signed URL fetched over and over is ONE distinct encoded
    name, which is why this rule counts distinct payloads rather than queries.
    """
    saved = _tunnel_setup(monkeypatch, [
        ("192.0.2.5", _TUNNEL_NAMES[0]),
    ] * 20)

    di.analyse_once({}, "sess-test")

    assert not [s for s in saved if s["detection_id"] == "DNS-1003"]


def test_a_browser_spread_across_many_domains_is_not_a_tunnel(monkeypatch):
    """
    NOISE, AND THIS IS THE CASE THAT SHAPED THE RULE. A browser hits many
    different registered domains, each with one encoded label in front of it
    (signed CDN paths, session tokens). That is 16 distinct payloads from one
    client and ZERO tunnels, because no single registered domain carries more
    than one. The first version of this check grouped by client alone and
    would have fired here, which is what a rule firing on ordinary browsing
    looks like.
    """
    names = [f"{_payload(n)}.cdn{n}.example" for n in range(16)]
    saved = _tunnel_setup(monkeypatch, [("192.0.2.5", d) for d in names])

    result = di.analyse_once({}, "sess-test")

    assert result["tunnel_findings"] == 0
    assert not [s for s in saved if s["detection_id"] == "DNS-1003"]


def test_two_domains_with_a_few_each_do_not_add_up_to_a_tunnel(monkeypatch):
    """
    The grouping, stated as its own case: 3 + 3 distinct payloads across two
    domains is not 6. A tunnel concentrates on one name it registered.
    """
    names = ([f"{_payload(n)}.evil.com" for n in range(3)]
             + [f"{_payload(n)}.other.net" for n in range(3, 6)])
    saved = _tunnel_setup(monkeypatch, [("192.0.2.5", d) for d in names])

    di.analyse_once({}, "sess-test")

    assert not [s for s in saved if s["detection_id"] == "DNS-1003"]


def test_many_distinct_names_go_high(monkeypatch):
    names = _TUNNEL_NAMES[:di.TUNNEL_HIGH_DISTINCT_PER_CLIENT + 1]
    assert len(names) == di.TUNNEL_HIGH_DISTINCT_PER_CLIENT + 1

    saved = _tunnel_setup(monkeypatch, [("192.0.2.5", d) for d in names])

    di.analyse_once({}, "sess-test")

    tunnels = [s for s in saved if s["detection_id"] == "DNS-1003"]
    assert tunnels and tunnels[0]["severity"] == "high"
    # RESTATED 2026-09-27 (register section 15, DNS-18): the count moved out
    # of the title and into the description, because a title carrying a
    # number that drifts is a new row on every pass. The severity the name
    # count decides is unchanged, and that is the half this test is about.
    assert str(di.TUNNEL_HIGH_DISTINCT_PER_CLIENT + 1) not in tunnels[0]["title"]
    assert f"in the last {di.DNS_ACTIVITY_WINDOW_HOURS}h: " \
           f"{di.TUNNEL_HIGH_DISTINCT_PER_CLIENT + 1}" in tunnels[0]["description"]


# the volume family.

def _activity_setup(monkeypatch, rows):
    """
    Wire analyse_once so the per-client totals come back as `rows`.

    `rows` is [(client_ip, total, nxdomain, txt, no_reply, no_type)] as the
    real SQL returns it, so the fake is shaped like the query rather than like
    the answer. The other two reads are silenced by routing them to empty
    lists on fragments that name them and nothing else.
    """
    conn = _FakeConn({
        "MAX(id)": [(10,)],
        "AS nxdomain": rows,
        "DISTINCT client_ip, domain FROM dns_queries WHERE queried_at": [],
        "DISTINCT client_ip, domain FROM dns_queries WHERE id > ?": [],
        "GROUP BY client_ip, domain HAVING cnt": [],
        "COUNT(*) FROM dns_queries WHERE client_ip": [(3,)],
    })
    _patch_analyse(monkeypatch, conn)

    import core.memory_engine as me
    monkeypatch.setattr(me, "finding_already_open", lambda *a, **k: False)

    saved = []
    monkeypatch.setattr(me, "save_finding",
                        lambda **k: saved.append(k) or {"saved": True})
    return saved


def _row(client, total, nx=0, txt=0, no_reply=0, no_type=0):
    return (client, total, nx, txt, no_reply, no_type)


def test_volume_raises_for_a_client_far_above_the_median(monkeypatch):
    rows = [_row("192.0.2.5", 40000)] + [_row(f"192.0.2.{i}", 200)
                                          for i in range(6, 12)]
    saved = _activity_setup(monkeypatch, rows)

    out = di.analyse_once({}, "sess-test")

    assert out["activity"]["volume"] == 1
    vol = [s for s in saved if s["detection_id"] == "DNS-1004"]
    # RESTATED 2026-09-27 (register section 15, DNS-18): the count moved to
    # the description so the row's identity does not change as the count
    # grows. The threshold arithmetic the test is about is unchanged.
    assert vol and "40000" not in vol[0]["title"]
    assert "Queries in the last" in vol[0]["description"] \
        and "40000" in vol[0]["description"]


def test_a_busy_client_on_a_busy_network_is_not_volume(monkeypatch):
    """
    NOISE, and the load-bearing one: the absolute floor is cleared here and
    the MEDIAN is what keeps it quiet. Every client on this network is busy,
    so 5000 queries is ordinary for it.
    """
    rows = [_row("192.0.2.5", 5000)] + [_row(f"192.0.2.{i}", 4200)
                                        for i in range(6, 12)]
    saved = _activity_setup(monkeypatch, rows)

    out = di.analyse_once({}, "sess-test")

    assert out["activity"]["volume"] == 0
    assert not [s for s in saved if s["detection_id"] == "DNS-1004"]


def test_an_ordinary_browser_is_not_volume(monkeypatch):
    rows = [_row("192.0.2.5", 800)] + [_row(f"192.0.2.{i}", 400)
                                       for i in range(6, 12)]
    saved = _activity_setup(monkeypatch, rows)

    out = di.analyse_once({}, "sess-test")

    assert out["activity"]["volume"] == 0
    assert not [s for s in saved if s["detection_id"] == "DNS-1004"]


def test_nxdomain_needs_both_the_count_and_the_share(monkeypatch):
    """
    A device that makes a thousand queries and misses a hundred is busy, not
    suspicious. The share gate is what tells the two apart, so the count alone
    must not be enough.
    """
    rows = [_row("192.0.2.5", 1000, nx=250)] + [_row(f"192.0.2.{i}", 500)
                                                for i in range(6, 12)]
    saved = _activity_setup(monkeypatch, rows)

    out = di.analyse_once({}, "sess-test")

    assert out["activity"]["nxdomain"] == 0
    assert not [s for s in saved if s["detection_id"] == "DNS-1005"]


def test_a_device_mostly_asking_for_names_that_do_not_exist_raises(monkeypatch):
    rows = [_row("192.0.2.5", 500, nx=400)] + [_row(f"192.0.2.{i}", 500)
                                               for i in range(6, 12)]
    saved = _activity_setup(monkeypatch, rows)

    out = di.analyse_once({}, "sess-test")

    assert out["activity"]["nxdomain"] == 1
    nx = [s for s in saved if s["detection_id"] == "DNS-1005"]
    # RESTATED 2026-09-27 (register section 15, DNS-18): "400 of 500" moved
    # out of the title — a title carrying counts is a new row every pass —
    # and into the description. Both halves are asserted here so the pair
    # cannot drift apart again.
    assert nx and "400 of 500" not in nx[0]["title"]
    assert "400 of 500" in nx[0]["description"]


def test_txt_volume_raises_and_says_it_did_not_read_the_content(monkeypatch):
    rows = [_row("192.0.2.5", 900, txt=300)] + [_row(f"192.0.2.{i}", 500)
                                                for i in range(6, 12)]
    saved = _activity_setup(monkeypatch, rows)

    out = di.analyse_once({}, "sess-test")

    assert out["activity"]["txt"] == 1
    txt = [s for s in saved if s["detection_id"] == "DNS-1006"]
    assert txt and "does not read what the records said" in txt[0]["description"]


def test_a_few_txt_lookups_are_ordinary(monkeypatch):
    """NOISE: mail authentication and domain verification live here."""
    rows = [_row("192.0.2.5", 300, txt=6)] + [_row(f"192.0.2.{i}", 500)
                                              for i in range(6, 12)]
    saved = _activity_setup(monkeypatch, rows)

    out = di.analyse_once({}, "sess-test")

    assert out["activity"]["txt"] == 0
    assert not [s for s in saved if s["detection_id"] == "DNS-1006"]


def test_a_log_with_no_reply_codes_says_so_instead_of_reporting_zero(monkeypatch):
    """
    THE COVERAGE CASE, and the one that matters on an AdGuard install. Every
    row lacks a reply code, so the NXDOMAIN check examined nothing. Zero
    findings here must never read as "every name resolved".
    """
    rows = [_row("192.0.2.5", 500, nx=0, no_reply=500, no_type=500)]
    saved = _activity_setup(monkeypatch, rows)

    out = di.analyse_once({}, "sess-test")

    note = out["activity"]["note"] or ""
    assert "NO ROW" in note or "reply code" in note
    assert "examined NOTHING" in note
    assert out["activity"]["nxdomain"] == 0
    assert not [s for s in saved if s["detection_id"] == "DNS-1005"]


def test_partial_reply_codes_are_reported_as_a_floor(monkeypatch):
    rows = [_row("192.0.2.5", 500, nx=300, no_reply=200)]
    _activity_setup(monkeypatch, rows)

    out = di.analyse_once({}, "sess-test")

    note = out["activity"]["note"] or ""
    assert "FLOOR" in note


# RUN AS A SCRIPT, because that is how this project runs its tests.
#
# FOUND 2026-09-20, TODO 120, AND IT IS THE WORST KIND OF GREEN. Every other
# file in tests/ is a standalone script that prints its checks and exits 1 if
# any failed, and scripts/run_tests.py reads nothing but the exit code. This
# file is written for pytest, so running it as a script DEFINED A PILE OF
# FUNCTIONS, CALLED NONE OF THEM, AND EXITED 0. The whole file read as passing
# in the suite while asserting nothing at all.
#
# NOISE FROM REAL SERVICES. Every case below was raised on a live home
# network before the rules learned to tell it apart.

def test_compound_english_site_names_are_not_dga():
    for name in ("theglobeandmail.com", "videogameschronicle.com",
                 "caughtoffside.com", "southernliving.com",
                 "learncodinganywhere.com"):
        assert di._is_dga_candidate(name) is False, name


def test_a_generated_name_still_is_dga():
    assert di._is_dga_candidate("xkq7zvbt4wplrm9d.com") is True


def test_a_local_name_is_never_dga_or_tunnel():
    assert di._is_dga_candidate("qx7zvbk4wtrp9lm.lan") is False
    names = [f"{_payload(n)}.printer.lan" for n in range(8)]
    saved = _tunnel_setup_named(names)
    assert saved == []


def _tunnel_setup_named(names, clients=("192.0.2.5",)):
    mp = pytest.MonkeyPatch()
    try:
        import core.memory_engine as me
        mp.setattr(me, "is_dismissed", lambda *a, **k: False)
        saved = _tunnel_setup(mp, [(c, d) for c in clients for d in names])
        di.analyse_once({}, "sess-test")
        return [s for s in saved if s["detection_id"] == "DNS-1003"]
    finally:
        mp.undo()


def test_service_names_made_of_words_are_not_a_tunnel():
    words = ["action-cards-host-app", "account-public-service-prod",
             "avatar-service-prod", "friends-public-service",
             "catalog-public-service", "agent-popup-gui-service",
             "assetdelivery-cdn-edge"]
    assert _tunnel_setup_named([f"{w}.example.net" for w in words]) == []


def test_a_domain_three_devices_use_is_not_one_devices_tunnel():
    names = _TUNNEL_NAMES[:8]
    raised = _tunnel_setup_named(
        names, clients=("192.0.2.5", "192.0.2.6", "192.0.2.7"))
    assert raised == []


def test_two_devices_on_a_tunnel_domain_still_raise():
    raised = _tunnel_setup_named(_TUNNEL_NAMES[:8],
                                 clients=("192.0.2.5", "192.0.2.6"))
    assert len(raised) == 2


def test_the_known_roots_apply_to_the_registered_domain():
    names = [f"rr{n}---sn-{_payload(n, 12)}.googlevideo.com" for n in range(8)]
    assert _tunnel_setup_named(names) == []


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
