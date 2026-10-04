# tests/test_feed_matcher.py
# AgentalSec V2, TODO 113.4. Tests for tools/feed_matcher.
#
# RULE ONE: failure cases first. Sections 1 to 6 are all the ways this can
# fail to look, and they come before any test that checks it finds something.
#
# THE ONE THAT MATTERS MOST is section 4. A feed matcher whose download failed
# will match every packet against an empty set and report a beautifully clean
# network. That is the single worst lie this module could tell, so it gets
# tested before the happy path and it gets tested three ways.

import pathlib
import sys

# THE ROOT INSERTION, added 2026-09-21, and it is what makes this file a CHECK
# rather than a file that only passes when it is invoked a particular way.
#
# This file was ported from the Windows tree as-is, and it had no `sys.path`
# setup because there it was only ever run through `python -m pytest`, which
# puts the CURRENT DIRECTORY on the path. scripts/run_tests.py runs every file
# as a standalone script with the project root as cwd but does NOT put it on
# sys.path, so `from tools import feed_matcher` raised ModuleNotFoundError and
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

from tools import feed_matcher as fm


# SECTION 1. FAILURE: the fetch cannot happen at all.

class _StreamedResp:
    """The parts of a streamed requests response that _fetch reads."""
    headers = {}
    encoding = "utf-8"

    def iter_content(self, size):
        yield (self.text or "").encode()

    def close(self):
        pass


def test_fetch_without_key_is_an_error_not_an_empty_body(monkeypatch):
    """No key must produce a REASON, never an empty feed."""
    monkeypatch.delenv("AGENTAL_ABUSECH_KEY", raising=False)
    text, err = fm._fetch("https://example.invalid/x", send_key=True)
    assert text is None
    assert err and "key" in err.lower()


def test_fetch_network_error_returns_reason(monkeypatch):
    import requests

    class Boom(requests.RequestException):
        pass

    def explode(*a, **k):
        raise Boom("no route")

    monkeypatch.setenv("AGENTAL_ABUSECH_KEY", "test-key")
    monkeypatch.setattr(requests, "get", explode)

    text, err = fm._fetch("https://example.invalid/x", send_key=True)
    assert text is None
    assert err is not None


def test_fetch_401_says_key_refused(monkeypatch):
    """
    A key that is set and not accepted is a 401, and the sentence must say so.

    2026-09-27, SECTION 16. This asserted the word "refused", which was right
    for the old shared sentence ("key refused (HTTP 401). Check VAR.") and is
    no longer the claim: 401 and 403 are now answered differently, because a
    key that is ABSENT and a key that is not accepted in the header this module
    sends are two different problems with two different fixes. The check is
    RESTATED to the new assertion rather than the old one being kept alive --
    what it guards is the same property, that a 401 never comes back as
    silence and never names the key as the cause without naming the header.
    The old assertion, quoted: assert "refused" in err.lower()
    """
    import requests

    class Resp(_StreamedResp):
        status_code = 401
        text = ""

    monkeypatch.setenv("AGENTAL_ABUSECH_KEY", "bad-key")
    monkeypatch.setattr(requests, "get", lambda *a, **k: Resp())

    text, err = fm._fetch("https://example.invalid/x", send_key=True)
    assert text is None
    assert "401" in err
    assert "header" in err.lower()


def test_fetch_200_with_empty_body_is_an_error(monkeypatch):
    """
    A 200 with nothing in it is a FAILURE, not an empty feed.

    This is the subtle one. Letting an empty body through as valid would wipe
    the previous rows on refresh and leave the matcher with nothing while
    still reporting success.
    """
    import requests

    class Resp(_StreamedResp):
        status_code = 200
        text = "   \n  "

    monkeypatch.setenv("AGENTAL_ABUSECH_KEY", "test-key")
    monkeypatch.setattr(requests, "get", lambda *a, **k: Resp())

    text, err = fm._fetch("https://example.invalid/x", send_key=True)
    assert text is None
    assert "empty" in err.lower()


# SECTION 2. FAILURE: the parsers, given junk.

def test_lines_ip_ignores_comments_and_blanks():
    text = "# comment\n\n1.2.3.4\n   \n# another\n5.6.7.8\n"
    rows = fm._parse_lines_ip(text)
    assert [r[0] for r in rows] == ["1.2.3.4", "5.6.7.8"]
    assert all(r[1] == "ip" for r in rows)


def test_lines_ip_rejects_non_addresses():
    text = "not.an.ip.at.all\n999.1.1.1\n1.2.3\n1.2.3.4\n"
    rows = fm._parse_lines_ip(text)
    assert [r[0] for r in rows] == ["1.2.3.4"]


def test_lines_ip_drops_the_never_match_set():
    text = "0.0.0.0\n127.0.0.1\n8.8.8.8\n"
    rows = fm._parse_lines_ip(text)
    assert [r[0] for r in rows] == ["8.8.8.8"]


def test_hostfile_throws_away_the_sinkhole_address():
    """
    The left column is 0.0.0.0, the sinkhole target. Reading it as an
    indicator would fill the table with one useless row repeated.
    """
    text = "# header\n0.0.0.0 evil.example.com\n0.0.0.0 bad.example.net\n"
    rows = fm._parse_hostfile(text)
    assert [r[0] for r in rows] == ["evil.example.com", "bad.example.net"]
    assert all(r[1] == "domain" for r in rows)
    assert "0.0.0.0" not in [r[0] for r in rows]


def test_hostfile_ignores_short_lines():
    text = "0.0.0.0\nonlyonefield\n0.0.0.0 good.example.com\n"
    rows = fm._parse_hostfile(text)
    assert [r[0] for r in rows] == ["good.example.com"]


def test_threatfox_csv_empty_input():
    assert fm._parse_threatfox_csv("") == []
    assert fm._parse_threatfox_csv("# only a comment\n") == []


def test_threatfox_csv_splits_ip_from_port():
    text = (
        '# first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type, malware\n'
        '"2026-01-01", "1", "1.2.3.4:443", "ip:port", "botnet_cc", "Qakbot"\n'
    )
    rows = fm._parse_threatfox_csv(text)
    assert rows == [("1.2.3.4", "ip", "Qakbot")]


def test_threatfox_csv_handles_domains():
    text = (
        '# first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type, malware\n'
        '"2026-01-01", "2", "bad.example.com", "domain", "botnet_cc", "Emotet"\n'
    )
    rows = fm._parse_threatfox_csv(text)
    assert rows == [("bad.example.com", "domain", "Emotet")]


# SECTION 3. FAILURE: domain handling that would over-match.

def test_parents_never_reach_a_bare_tld():
    """
    A feed carrying a junk row like "com" must not be able to match the whole
    internet. The parent walk stops at two labels.
    """
    parents = fm._domain_and_parents("a.b.evil.com")
    assert parents == ["a.b.evil.com", "b.evil.com", "evil.com"]
    assert "com" not in parents


def test_parents_of_a_two_label_domain():
    assert fm._domain_and_parents("evil.com") == ["evil.com"]


def test_parents_of_junk_is_empty():
    assert fm._domain_and_parents("") == []
    assert fm._domain_and_parents("localhost") == []
    assert fm._domain_and_parents(None) == []


def test_clean_domain_strips_scheme_port_and_path():
    assert fm._clean_domain("https://Evil.COM:8443/path") == "evil.com"
    assert fm._clean_domain("evil.com.") == "evil.com"


def test_clean_domain_rejects_things_with_no_dot():
    assert fm._clean_domain("localhost") == ""
    assert fm._clean_domain("some thing.com") == ""


# SECTION 4. THE IMPORTANT ONE.
# An empty feed must NOT report a clean network.

def test_status_on_empty_feed_says_it_cannot_claim(monkeypatch):
    monkeypatch.setattr(fm, "_count_indicators", lambda: 0)
    # _cursor_read, NOT me.get_preference: the last-refresh time moved out of
    # user_preferences with v46 and out of the policy table's reach entirely.
    monkeypatch.setattr(fm, "_cursor_read", lambda k: None)

    s = fm.status({})
    assert s["feed_loaded"] is False
    assert s["indicator_count"] == 0
    # The note must not read as reassurance.
    assert "not the same as nothing being found" in s["note"]


def test_match_once_refuses_on_empty_feed(monkeypatch):
    """
    ran=False, not ran=True with zero findings. This is the whole of rule two
    for this module.
    """
    monkeypatch.setattr(fm, "status", lambda config=None: {
        "feed_loaded": False, "indicator_count": 0,
        "feed_age_hours": None, "stale": True,
        "last_refresh_at": None, "note": "nothing loaded",
    })

    result = fm.match_once({}, "sess-test")

    assert result["ran"] is False
    assert result["ip_findings"] == 0
    assert result["dns_findings"] == 0
    assert result["tls_findings"] == 0
    assert "no feed indicators loaded" in result["reason"]


def test_refresh_reports_ran_false_when_every_feed_fails(monkeypatch):
    # THE FEED LIST IS EXPLICIT, added 2026-09-23. With no config, refresh_once
    # takes every feed in FEEDS -- which now includes MISP, a KEYLESS feed that
    # would be fetched for REAL from inside a unit test. A test that reaches
    # the network is slow, flaky and dependent on somebody else's uptime, so
    # the three abuse.ch feeds are named here and the two-stage fetchers are
    # stubbed as well.
    monkeypatch.setattr(fm, "_fetch",
                        lambda url, send_key, key_var=None: (None, "HTTP 500"))
    monkeypatch.setattr(fm, "fetch_misp_events",
                        lambda max_events=None: ([], "stubbed", {}))
    monkeypatch.setattr(fm, "_count_indicators", lambda: 0)

    import core.memory_engine as me
    monkeypatch.setattr(me, "get_preference", lambda k, default=None: None)
    monkeypatch.setattr(me, "set_preference", lambda k, v: None)

    result = fm.refresh_once(
        {"threat_feeds": {"feeds": ["feodo", "urlhaus", "threatfox"]}}, force=True)

    assert result["ran"] is False
    assert all(not f["ok"] for f in result["feeds"].values())
    assert set(result["feeds"]) == {"feodo", "urlhaus", "threatfox"}


def test_refresh_partial_success_is_still_ran_true(monkeypatch):
    """
    Two feeds out of three is real coverage. Throwing it away because one
    failed would be the other direction of the same mistake.

    A KEY IS SET HERE, added 2026-09-23. refresh_once now resolves each feed's
    key BEFORE fetching, so with no key in the environment it refuses all three
    abuse.ch feeds without ever calling _fetch -- and this test's fake fetch
    would never run. That check is the right order (a keyless feed must not
    attempt a request), so the test supplies a key: its subject is partial
    success, and key handling has its own section above.
    """
    monkeypatch.setenv("AGENTAL_ABUSECH_KEY", "test-key")

    def fake_fetch(url, send_key, key_var=None):
        if "feodo" in url:
            return None, "HTTP 500"
        if "hostfile" in url:
            return "0.0.0.0 bad.example.com\n", None
        return ('# first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type, malware\n'
                '"2026-01-01", "1", "9.9.9.9:80", "ip:port", "botnet_cc", "X"\n'), None

    written = {}

    monkeypatch.setattr(fm, "_fetch", fake_fetch)
    monkeypatch.setattr(fm, "_replace_feed_rows",
                        lambda feed, rows: written.setdefault(feed, len(rows)))
    monkeypatch.setattr(fm, "_count_indicators", lambda: 2)

    import core.memory_engine as me
    monkeypatch.setattr(me, "get_preference", lambda k, default=None: None)
    monkeypatch.setattr(me, "set_preference", lambda k, v: None)

    result = fm.refresh_once(
        {"threat_feeds": {"feeds": ["feodo", "urlhaus", "threatfox"]}}, force=True)

    assert result["ran"] is True
    assert result["feeds"]["feodo"]["ok"] is False
    assert result["feeds"]["urlhaus"]["ok"] is True
    assert result["feeds"]["threatfox"]["ok"] is True


def test_refresh_keeps_old_rows_when_a_feed_parses_to_nothing(monkeypatch):
    """
    Downloaded fine, yielded zero indicators. Do NOT wipe the previous rows:
    an empty answer is more likely a parse break than a genuinely empty feed.
    """
    monkeypatch.setenv("AGENTAL_ABUSECH_KEY", "test-key")   # see the note above
    monkeypatch.setattr(fm, "_fetch",
                        lambda url, send_key, key_var=None:
                        ("# only comments\n", None))
    calls = []
    monkeypatch.setattr(fm, "_replace_feed_rows",
                        lambda feed, rows: calls.append(feed))
    monkeypatch.setattr(fm, "_count_indicators", lambda: 0)

    import core.memory_engine as me
    monkeypatch.setattr(me, "get_preference", lambda k, default=None: None)
    monkeypatch.setattr(me, "set_preference", lambda k, v: None)

    result = fm.refresh_once(
        {"threat_feeds": {"feeds": ["feodo", "urlhaus", "threatfox"]}}, force=True)

    assert calls == []          # nothing was overwritten
    assert result["ran"] is False


# SECTION 5. FAILURE: staleness must show up in the severity.

def test_severity_drops_when_the_feed_is_stale():
    assert fm._severity_for(stale=False) == "high"
    assert fm._severity_for(stale=True) == "medium"


def test_status_marks_an_old_feed_stale(monkeypatch):
    from datetime import datetime, timezone, timedelta

    old = (datetime.now(timezone.utc)
           - timedelta(hours=fm.FEED_STALE_HOURS + 10)).isoformat()

    monkeypatch.setattr(fm, "_count_indicators", lambda: 1234)
    # See the note in test_status_on_empty_feed_says_it_cannot_claim.
    monkeypatch.setattr(fm, "_cursor_read", lambda k: old)

    s = fm.status({})
    assert s["feed_loaded"] is True
    assert s["stale"] is True
    assert s["feed_age_hours"] > fm.FEED_STALE_HOURS


def test_status_fresh_feed_is_not_stale(monkeypatch):
    from datetime import datetime, timezone, timedelta

    recent = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    monkeypatch.setattr(fm, "_count_indicators", lambda: 5000)
    # See the note in test_status_on_empty_feed_says_it_cannot_claim.
    monkeypatch.setattr(fm, "_cursor_read", lambda k: recent)

    s = fm.status({})
    assert s["feed_loaded"] is True
    assert s["stale"] is False


# SECTION 6. FAILURE: disabled in config.

def test_refresh_disabled_returns_ran_false():
    result = fm.refresh_once({"threat_feeds": {"enabled": False}}, force=True)
    assert result["ran"] is False
    assert "disabled" in result["reason"]


# SECTION 7. HAPPY PATH. Only now.

class _Cursor:
    def __init__(self, rows):
        self._rows = rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows


class _Conn:
    """Routes queries by keyword. Enough to exercise the three checkers."""

    def __init__(self, packets=(), dns=(), tls=(), feed_ip=None,
                 feed_domain=None):
        self.packets = list(packets)
        self.dns = list(dns)
        self.tls = list(tls)
        self.feed_ip = feed_ip or {}
        self.feed_domain = feed_domain or {}

    def execute(self, sql, params=()):
        s = " ".join(sql.split())
        if "MAX(id) FROM packets" in s:
            return _Cursor([(100,)])
        if "MAX(id) FROM dns_queries" in s:
            return _Cursor([(200,)])
        if "MAX(id) FROM tls_hello" in s:
            return _Cursor([(300,)])
        if "FROM threat_feed" in s and "'ip'" in s:
            hit = self.feed_ip.get(params[0])
            return _Cursor([hit] if hit else [])
        if "FROM threat_feed" in s and "'domain'" in s:
            hit = self.feed_domain.get(params[0])
            return _Cursor([hit] if hit else [])
        # THE CURSOR IS HONOURED HERE, added 2026-09-20. This fake used to
        # return its rows whatever `id > ?` was, so a test asserting that a
        # seeded cursor skips history was really only testing the fake. Every
        # fixture row sits at the table's max id, so a cursor at the end sees
        # nothing, which is what the real query does.
        if "FROM packets" in s:
            return _Cursor(self.packets if self._after(params, 100) else [])
        if "FROM dns_queries" in s:
            return _Cursor(self.dns if self._after(params, 200) else [])
        if "FROM tls_hello" in s:
            return _Cursor(self.tls if self._after(params, 300) else [])
        return _Cursor([])

    @staticmethod
    def _after(params, max_id):
        """Would `id > ?` still return the fixture rows."""
        if not params:
            return True
        return int(params[0]) < max_id

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


def _wire(monkeypatch, conn, saved, stale=False):
    import contextlib
    import core.memory_engine as me

    monkeypatch.setattr(fm, "status", lambda config=None: {
        "feed_loaded": True, "indicator_count": 10,
        "feed_age_hours": 1.0, "stale": stale,
        "last_refresh_at": "now", "note": "ok",
    })
    monkeypatch.setattr(fm, "_get_cursor", lambda k: 0)
    monkeypatch.setattr(fm, "_cursor_or_none", lambda k: 0)
    monkeypatch.setattr(fm, "_set_cursor", lambda k, v: None)

    @contextlib.contextmanager
    def _conn():
        yield conn

    monkeypatch.setattr(me, "_get_conn", _conn)
    monkeypatch.setattr(me, "finding_already_open", lambda *a, **k: False)

    def save(**kwargs):
        saved.append(kwargs)
        return {"saved": True}

    monkeypatch.setattr(me, "save_finding", save)


def test_packet_ip_match_raises_fed_1001(monkeypatch):
    saved = []
    conn = _Conn(
        packets=[("192.0.2.5", "203.0.113.9", "outbound", "outbound", 51000, 443, "TCP")],
        feed_ip={"203.0.113.9": ("feodo", "Qakbot")},
    )
    _wire(monkeypatch, conn, saved)

    result = fm.match_once({}, "sess-test")

    assert result["ran"] is True
    assert result["ip_findings"] == 1
    assert saved[0]["detection_id"] == "FED-1001"
    assert saved[0]["severity"] == "high"
    assert saved[0]["entity_value"] == "192.0.2.5"


def test_dns_domain_match_raises_fed_1002_on_a_parent(monkeypatch):
    """The feed lists evil.example. The query was a.b.evil.example."""
    saved = []
    conn = _Conn(
        dns=[("192.0.2.6", "a.b.evil.example")],
        feed_domain={"evil.example": ("urlhaus", "Emotet")},
    )
    _wire(monkeypatch, conn, saved)

    result = fm.match_once({}, "sess-test")

    assert result["dns_findings"] == 1
    assert saved[0]["detection_id"] == "FED-1002"
    assert saved[0]["raw_data"]["matched"] == "evil.example"
    assert saved[0]["raw_data"]["domain"] == "a.b.evil.example"


def test_tls_sni_match_raises_fed_1003(monkeypatch):
    saved = []
    conn = _Conn(
        tls=[(1, "192.0.2.7", "198.51.100.4", 443, "bad.example.net")],
        feed_domain={"bad.example.net": ("threatfox", "Cobalt Strike")},
    )
    _wire(monkeypatch, conn, saved)

    result = fm.match_once({}, "sess-test")

    assert result["tls_findings"] == 1
    assert saved[0]["detection_id"] == "FED-1003"
    assert saved[0]["entity_value"] == "192.0.2.7"


def test_stale_feed_downgrades_the_finding(monkeypatch):
    saved = []
    conn = _Conn(
        packets=[("192.0.2.5", "203.0.113.9", "outbound", "outbound", 51000, 443, "TCP")],
        feed_ip={"203.0.113.9": ("feodo", "Qakbot")},
    )
    _wire(monkeypatch, conn, saved, stale=True)

    fm.match_once({}, "sess-test")

    assert saved[0]["severity"] == "medium"
    assert saved[0]["raw_data"]["feed_stale"] is True
    assert "stale" in saved[0]["description"].lower()


def test_clean_pass_reports_ran_true_with_zero(monkeypatch):
    """
    The counterpart to section 4. A LOADED feed that matched nothing really
    does get to say zero, and it must say ran=True when it does.
    """
    saved = []
    conn = _Conn(packets=[("192.0.2.5", "8.8.8.8", "outbound", "outbound", 51000, 443, "TCP")], feed_ip={})
    _wire(monkeypatch, conn, saved)

    result = fm.match_once({}, "sess-test")

    assert result["ran"] is True
    assert result["ip_findings"] == 0
    assert saved == []


def test_dedup_suppresses_a_repeat(monkeypatch):
    saved = []
    conn = _Conn(
        packets=[("192.0.2.5", "203.0.113.9", "outbound", "outbound", 51000, 443, "TCP")],
        feed_ip={"203.0.113.9": ("feodo", "Qakbot")},
    )
    _wire(monkeypatch, conn, saved)

    import core.memory_engine as me
    monkeypatch.setattr(me, "finding_already_open", lambda *a, **k: True)

    result = fm.match_once({}, "sess-test")

    assert result["ip_findings"] == 0
    assert saved == []


# SECTION 8. The register agrees with what this module raises.

def test_fed_detections_are_registered():
    from core import detections

    for did in ("FED-1001", "FED-1002", "FED-1003"):
        # exists() first, because get() is deliberately fatal and an
        # UnknownDetection traceback is a worse test failure message than
        # a plain assert naming the id.
        assert detections.exists(did), f"{did} is not in the register"
        d = detections.get(did)
        assert d.source == "feed_matcher"
        assert d.entity_type == "ip"
        assert "high" in d.severities
        assert "medium" in d.severities


# SECTION 9. THE FIRST PASS DOES NOT SCAN HISTORY. 2026-09-20.
#
# FAILURE FIRST, and this one is a performance failure that reads as a
# correctness one. A missing cursor used to come back as 0, so the very first
# pass did SELECT DISTINCT over every packet row ever written, on a 3 GB file,
# inside a read transaction that also stops the WAL being checkpointed, while
# the sensors were starting.
#
# The fix seeds the cursor to the end of the table, and the ONLY thing that
# makes that acceptable is that the result says so. A seeded table reporting
# zero matches has not checked anything.

def _wire_unseeded(monkeypatch, conn, saved, present=()):
    """Like _wire, but the named cursors are the only ones that exist."""
    import contextlib
    import core.memory_engine as me

    monkeypatch.setattr(fm, "status", lambda config=None: {
        "feed_loaded": True, "indicator_count": 10,
        "feed_age_hours": 1.0, "stale": False,
        "last_refresh_at": "now", "note": "ok",
    })
    monkeypatch.setattr(fm, "_cursor_or_none",
                        lambda k: 0 if k in present else None)
    written = {}
    monkeypatch.setattr(fm, "_set_cursor",
                        lambda k, v: written.__setitem__(k, v))

    @contextlib.contextmanager
    def _conn():
        yield conn

    monkeypatch.setattr(me, "_get_conn", _conn)
    monkeypatch.setattr(me, "finding_already_open", lambda *a, **k: False)
    monkeypatch.setattr(me, "save_finding",
                        lambda **k: saved.append(k) or {"saved": True})
    return written


def test_a_first_ever_pass_is_not_reported_as_a_clean_network(monkeypatch):
    """
    THE FALSE CALM. Nothing was checked, so ran must be False.
    """
    saved = []
    conn = _Conn(packets=[("192.0.2.5", "203.0.113.9", "outbound", "outbound", 51000, 443, "TCP")],
                 feed_ip={"203.0.113.9": ("feodo", "Qakbot")})
    _wire_unseeded(monkeypatch, conn, saved)

    result = fm.match_once({}, "sess-test")

    assert result["ran"] is False
    assert set(result["seeded"]) == {"packets", "dns_queries", "tls_hello"}
    assert "WERE NOT CHECKED" in result["reason"]


def test_a_first_ever_pass_writes_the_cursors_to_the_end(monkeypatch):
    """The whole point: the next pass starts from here, not from row 1."""
    saved = []
    conn = _Conn()
    written = _wire_unseeded(monkeypatch, conn, saved)

    fm.match_once({}, "sess-test")

    assert written[fm._CUR_PACKETS] == 100
    assert written[fm._CUR_DNS] == 200
    assert written[fm._CUR_TLS] == 300


def test_a_first_ever_pass_raises_nothing_from_history(monkeypatch):
    saved = []
    conn = _Conn(packets=[("192.0.2.5", "203.0.113.9", "outbound", "outbound", 51000, 443, "TCP")],
                 feed_ip={"203.0.113.9": ("feodo", "Qakbot")})
    _wire_unseeded(monkeypatch, conn, saved)

    fm.match_once({}, "sess-test")
    assert saved == []


def test_one_new_table_does_not_stop_the_others_being_checked(monkeypatch):
    """
    tls_hello arrived at schema v38 with no cursor while packets had one.
    Seeding the new table must not silence the old ones.
    """
    saved = []
    conn = _Conn(packets=[("192.0.2.5", "203.0.113.9", "outbound", "outbound", 51000, 443, "TCP")],
                 feed_ip={"203.0.113.9": ("feodo", "Qakbot")})
    _wire_unseeded(monkeypatch, conn, saved,
                   present=(fm._CUR_PACKETS, fm._CUR_DNS))

    result = fm.match_once({}, "sess-test")

    assert result["ran"] is True
    assert result["seeded"] == ["tls_hello"]
    assert result["ip_findings"] == 1
    assert "WERE NOT CHECKED" in result["reason"], \
        "a partial seed still has to say what it skipped"


def test_backfill_refuses_to_seed_and_scans_history(monkeypatch):
    saved = []
    conn = _Conn(packets=[("192.0.2.5", "203.0.113.9", "outbound", "outbound", 51000, 443, "TCP")],
                 feed_ip={"203.0.113.9": ("feodo", "Qakbot")})
    _wire_unseeded(monkeypatch, conn, saved)

    result = fm.match_once({}, "sess-test", backfill=True)

    assert result["ran"] is True
    assert result["seeded"] == []
    assert result["ip_findings"] == 1


# SECTION 10. Inbound from a listed address. 2026-09-20.
#
# Only dst_ip was checked, so a connection arriving FROM a listed C2 raised
# nothing at all. The feed listed it and we saw it; the direction it came from
# is not a reason to stay quiet.

def test_an_inbound_packet_from_a_listed_address_raises(monkeypatch):
    saved = []
    conn = _Conn(packets=[("203.0.113.9", "192.0.2.5", "inbound", "inbound", 443, 51000, "TCP")],
                 feed_ip={"203.0.113.9": ("feodo", "Qakbot")})
    _wire(monkeypatch, conn, saved)

    result = fm.match_once({}, "sess-test")

    assert result["ip_findings"] == 1
    assert "contacted this network" in saved[0]["title"]
    assert saved[0]["raw_data"]["inbound"] is True


def test_an_inbound_packet_is_attributed_to_the_local_device(monkeypatch):
    saved = []
    conn = _Conn(packets=[("203.0.113.9", "192.0.2.5", "inbound", "inbound", 443, 51000, "TCP")],
                 feed_ip={"203.0.113.9": ("feodo", "")})
    _wire(monkeypatch, conn, saved)

    fm.match_once({}, "sess-test")
    assert saved[0]["entity_value"] == "192.0.2.5"


def test_an_inbound_packet_from_a_clean_address_raises_nothing(monkeypatch):
    saved = []
    conn = _Conn(packets=[("8.8.8.8", "192.0.2.5", "inbound", "inbound", 443, 51000, "TCP")],
                 feed_ip={})
    _wire(monkeypatch, conn, saved)

    assert fm.match_once({}, "sess-test")["ip_findings"] == 0


def test_outbound_still_reads_the_destination(monkeypatch):
    """The direction split must not have swapped the ends over."""
    saved = []
    conn = _Conn(packets=[("192.0.2.5", "203.0.113.9", "outbound", "outbound", 51000, 443, "TCP")],
                 feed_ip={"203.0.113.9": ("feodo", "")})
    _wire(monkeypatch, conn, saved)

    fm.match_once({}, "sess-test")
    assert saved[0]["entity_value"] == "192.0.2.5"
    assert "Contacted a listed" in saved[0]["title"]


# SECTION 11. The parent walk stops at shared hosts. 2026-09-20, TODO 120.
#
# FAILURE FIRST. One feed row carrying a bare hosting root used to fire a HIGH
# severity finding on every subdomain of that platform. These are the only
# detections in the app allowed to be high, on the argument that somebody with
# far more visibility published the address, and that argument does not
# survive being applied to a whole hosting provider.

def test_a_parent_match_on_a_shared_host_is_refused(monkeypatch):
    saved = []
    conn = _Conn(dns=[("192.0.2.5", "someones-blog.blogspot.com")],
                 feed_domain={"blogspot.com": ("urlhaus", "")})
    _wire(monkeypatch, conn, saved)

    assert fm.match_once({}, "sess-test")["dns_findings"] == 0
    assert saved == []


def test_an_exact_match_on_a_shared_host_still_fires(monkeypatch):
    """Only the walk UPWARDS stops. The name itself always counts."""
    saved = []
    conn = _Conn(dns=[("192.0.2.5", "evil.pages.dev")],
                 feed_domain={"evil.pages.dev": ("urlhaus", "Qakbot")})
    _wire(monkeypatch, conn, saved)

    assert fm.match_once({}, "sess-test")["dns_findings"] == 1


def test_a_parent_match_on_an_ordinary_domain_still_fires(monkeypatch):
    """The guard must not have switched parent matching off altogether."""
    saved = []
    conn = _Conn(dns=[("192.0.2.5", "a.b.evil.com")],
                 feed_domain={"evil.com": ("urlhaus", "")})
    _wire(monkeypatch, conn, saved)

    assert fm.match_once({}, "sess-test")["dns_findings"] == 1
    assert saved[0]["raw_data"]["matched"] == "evil.com"


def test_a_deeper_parent_under_a_shared_host_still_fires(monkeypatch):
    """
    "attacker.pages.dev" listed, "login.attacker.pages.dev" seen. The listed
    name is the tenant, not the platform, so this is a real parent match.
    """
    saved = []
    conn = _Conn(dns=[("192.0.2.5", "login.attacker.pages.dev")],
                 feed_domain={"attacker.pages.dev": ("urlhaus", "")})
    _wire(monkeypatch, conn, saved)

    assert fm.match_once({}, "sess-test")["dns_findings"] == 1


def test_the_shared_host_list_is_checked_by_name_not_by_suffix():
    assert fm._is_shared_host("pages.dev") is True
    assert fm._is_shared_host("PAGES.DEV") is True
    assert fm._is_shared_host("notpages.dev") is False
    assert fm._is_shared_host("") is False


# SECTION 12. Feed findings keep the bytes. 2026-09-20, TODO 120.
#
# FAILURE FIRST: with no capture running there is no ring, and that has to
# come back as a REASON rather than as zero rows. The two detections with the
# strongest evidence in the app were the two keeping no bytes at all, because
# this module runs on its own thread and had no handle on the sniffer's ring.

def test_no_ring_is_a_reason_not_a_zero(monkeypatch):
    from tools import payload_ring as pr
    monkeypatch.setattr(pr, "_ACTIVE", None)

    res = pr.flush_for_finding("192.0.2.5", "203.0.113.9", 443, "TCP",
                               "FED-1001")
    assert res["ran"] is False
    assert res["rows"] == 0
    assert "not running" in res["reason"]
    assert res["coverage"]["covering"] is False


def test_a_feed_ip_finding_flushes_the_flow(monkeypatch):
    from tools import payload_ring as pr

    calls = []

    class _FakeRing:
        def flush(self, *a, **k):
            calls.append((a, k))
            return {"ran": True, "rows": 3, "reason": None, "coverage": {}}

    monkeypatch.setattr(pr, "_ACTIVE", _FakeRing())

    saved = []
    conn = _Conn(packets=[("192.0.2.5", "203.0.113.9", "outbound", "outbound",
                           51000, 443, "TCP")],
                 feed_ip={"203.0.113.9": ("feodo", "Qakbot")})
    _wire(monkeypatch, conn, saved)

    fm.match_once({}, "sess-test")

    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[0] == "192.0.2.5" and args[1] == "203.0.113.9"
    assert kwargs["src_port"] == 51000
    assert kwargs["trigger_detection_id"] == "FED-1001"


def test_a_tls_sni_finding_flushes_the_flow(monkeypatch):
    from tools import payload_ring as pr
    calls = []

    class _FakeRing:
        def flush(self, *a, **k):
            calls.append(k)
            return {"ran": True, "rows": 1, "reason": None, "coverage": {}}

    monkeypatch.setattr(pr, "_ACTIVE", _FakeRing())

    saved = []
    conn = _Conn(tls=[(1, "192.0.2.7", "198.51.100.4", 443, "bad.example.net")],
                 feed_domain={"bad.example.net": ("urlhaus", "")})
    _wire(monkeypatch, conn, saved)

    fm.match_once({}, "sess-test")
    assert len(calls) == 1
    assert calls[0]["trigger_detection_id"] == "FED-1003"


def test_a_dns_finding_does_not_try_to_flush(monkeypatch):
    """
    A DNS row comes from the resolver log, not from a packet this sensor
    captured. There is no flow, so asking for one would log a miss every time.
    """
    from tools import payload_ring as pr
    calls = []

    class _FakeRing:
        def flush(self, *a, **k):
            calls.append(k)
            return {"ran": True, "rows": 1, "reason": None, "coverage": {}}

    monkeypatch.setattr(pr, "_ACTIVE", _FakeRing())

    saved = []
    conn = _Conn(dns=[("192.0.2.5", "bad.example.net")],
                 feed_domain={"bad.example.net": ("urlhaus", "")})
    _wire(monkeypatch, conn, saved)

    fm.match_once({}, "sess-test")
    assert calls == []


def test_a_failed_flush_never_loses_the_finding(monkeypatch):
    from tools import payload_ring as pr

    class _BoomRing:
        def flush(self, *a, **k):
            raise RuntimeError("ring exploded")

    monkeypatch.setattr(pr, "_ACTIVE", _BoomRing())

    saved = []
    conn = _Conn(packets=[("192.0.2.5", "203.0.113.9", "outbound", "outbound",
                           51000, 443, "TCP")],
                 feed_ip={"203.0.113.9": ("feodo", "")})
    _wire(monkeypatch, conn, saved)

    assert fm.match_once({}, "sess-test")["ip_findings"] == 1


# SECTION 13. MISP. 2026-09-23. Failure cases first, as everywhere here.
#
# MISP is an ARCHIVE of one JSON file per event, so the two ways it fails look
# nothing like a bad download: a manifest that cannot be read, and a window of
# events that parse to nothing. Both must produce a REASON rather than an empty
# list, because an empty list is what a clean network looks like.

def _misp_event(*attrs, tags=None):
    return {"Event": {"info": "a report", "date": "2026-08-13",
                      "Attribute": list(attrs), "Tag": tags or []}}


def _attr(value, attr_type="domain", to_ids=True):
    return {"type": attr_type, "value": value, "to_ids": to_ids,
            "category": "Network activity"}


def test_misp_manifest_unreadable_is_a_reason_not_an_empty_feed(monkeypatch):
    monkeypatch.setattr(fm, "_fetch_json",
                        lambda url, send_key=False, key_var=None:
                        (None, "HTTP 503"))
    rows, err, detail = fm.fetch_misp_events(3)
    assert rows == []
    assert err and "manifest" in err
    assert "HTTP 503" in err


def test_misp_event_with_no_attributes_is_counted_not_a_failure(monkeypatch):
    """
    MEASURED ON THE REAL FEED: 3 of the newest 20 events carry no attributes at
    all. An OSINT report with no indicators is a normal thing to publish, so
    this is counted in the detail rather than reported as a broken feed.
    """
    manifest = {"aaa-1": {"timestamp": 100}, "bbb-2": {"timestamp": 200}}

    def fake_json(url, send_key=False, key_var=None):
        if url.endswith("manifest.json"):
            return manifest, None
        return _misp_event(), None          # no attributes

    monkeypatch.setattr(fm, "_fetch_json", fake_json)
    rows, err, detail = fm.fetch_misp_events(2)
    assert rows == []
    assert err is not None and "zero usable indicators" in err
    assert detail["events_empty"] == 2
    assert detail["events_fetched"] == 0


def test_misp_partial_event_failure_keeps_the_events_that_worked(monkeypatch):
    """
    14 of 15 is real coverage. The failure is NAMED in the detail rather than
    thrown away with the batch.
    """
    manifest = {"aaa-1": {"timestamp": 100}, "bbb-2": {"timestamp": 200}}

    def fake_json(url, send_key=False, key_var=None):
        if url.endswith("manifest.json"):
            return manifest, None
        if "aaa-1" in url:
            return None, "HTTP 500"
        return _misp_event(_attr("evil.example")), None

    monkeypatch.setattr(fm, "_fetch_json", fake_json)
    rows, err, detail = fm.fetch_misp_events(2)
    assert err is None
    assert rows == [("evil.example", "domain", "")]
    assert detail["events_failed"] == 1
    assert detail["events_fetched"] == 1
    assert "could not be fetched" in detail["note"]


def test_misp_window_asks_for_the_newest_and_says_what_it_left(monkeypatch):
    """
    THE HONEST WINDOW. The archive holds 1,681 events and this reads a few, so
    the detail has to say how many were NOT read -- otherwise "no match in the
    feed" reads as a complete claim.
    """
    manifest = {f"ev-{i}": {"timestamp": i} for i in range(50)}
    monkeypatch.setattr(fm, "_fetch_json",
                        lambda url, send_key=False, key_var=None:
                        (manifest, None) if url.endswith("manifest.json")
                        else (_misp_event(_attr("evil.example")), None))

    rows, err, detail = fm.fetch_misp_events(5)
    assert err is None
    assert detail["events_in_archive"] == 50
    assert detail["window"] == 5
    assert "newest 5 of 50" in detail["note"]
    assert "were NOT read" in detail["note"]


def test_misp_window_is_clamped_to_its_ceiling(monkeypatch):
    """A config edit must not turn a boot into a gigabyte of download."""
    manifest = {f"ev-{i}": {"timestamp": i} for i in range(500)}
    seen = {}

    def fake_json(url, send_key=False, key_var=None):
        if url.endswith("manifest.json"):
            return manifest, None
        seen["n"] = seen.get("n", 0) + 1
        return _misp_event(_attr("evil.example")), None

    monkeypatch.setattr(fm, "_fetch_json", fake_json)
    _, _, detail = fm.fetch_misp_events(10_000)
    assert detail["window"] == fm.MISP_MAX_EVENTS_CEILING
    assert seen["n"] == fm.MISP_MAX_EVENTS_CEILING


def test_misp_sort_is_newest_first_and_deterministic_on_a_tie():
    """
    Several events share a timestamp on the real feed. Without a stable second
    key the window would reorder between refreshes and churn for no reason.
    """
    manifest = {"zzz": {"timestamp": 100}, "aaa": {"timestamp": 100},
                "mid": {"timestamp": 200}}
    window, total = fm.select_misp_events(manifest, 2)
    assert total == 3
    assert [u for u, _ in window] == ["mid", "aaa"]
    # and again, to prove it is stable
    again, _ = fm.select_misp_events(manifest, 2)
    assert [u for u, _ in again] == ["mid", "aaa"]


def test_misp_keeps_only_to_ids_attributes():
    """
    THE FLAG IS THE FILTER. MEASURED over the newest 12 events: 12,619
    to_ids=True against 98 False. Reading every attribute would fill the table
    with filenames, dates and prose.

    MEASURED AGAIN over the newest 20, for the TYPE: every one of 43,416
    to_ids values on the real feed is a JSON boolean, not the string "1". The
    check is therefore `is True` rather than a truthy test -- a test that
    accepted "0" would import every attribute MISP explicitly marked as not
    for detection.
    """
    body = _misp_event(_attr("keep.example", to_ids=True),
                       _attr("drop.example", to_ids=False),
                       {"type": "domain", "value": "nolabel.example"})
    rows = fm.parse_misp_event(body)
    assert [r[0] for r in rows] == ["keep.example"]


def test_misp_to_ids_admits_the_string_shape_and_nothing_else():
    """
    THE SECOND SHAPE, NAMED. MEASURED on the real feed: all 43,416 values are
    booleans. But MISP serialises this field two ways depending on the export
    path, and a deployment answering "1" under a strict `is True` would import
    NOTHING -- a sensor that runs, reports healthy, and says every destination
    is clean. Both shapes are admitted by name; everything else is refused,
    because a missing flag treated as True imports every comment in the
    archive.
    """
    for yes in (True, "1", "true"):
        assert fm._misp_to_ids(yes) is True, yes
    for no in (False, "0", "false", "", None, 0, 1, "yes", "no"):
        assert fm._misp_to_ids(no) is False, no

    # and the parser end to end: a string "1" attribute is kept
    body = _misp_event({"type": "domain", "value": "evil.example",
                        "to_ids": "1"})
    assert fm.parse_misp_event(body) == [("evil.example", "domain", "")]


def test_misp_ignores_attribute_types_it_cannot_match():
    """
    An allowlist, not a denylist: a hash or a comment is not something this app
    can look up against traffic, and a NEW type somebody invents must not
    become a row.
    """
    body = _misp_event(_attr("d41d8cd98f00b204e9800998ecf8427e", "md5"),
                       _attr("just a comment", "comment"),
                       _attr("2026-08-13", "datetime"),
                       _attr("keep.example", "domain"))
    assert [r[0] for r in fm.parse_misp_event(body)] == ["keep.example"]


def test_misp_reads_the_family_out_of_its_galaxy_tags():
    """
    MISP carries the family in TAGS, not a field. MEASURED on the real feed:
    'misp-galaxy:mitre-malware="Kali365 - S9044"'.
    """
    body = _misp_event(
        _attr("evil.example"),
        tags=[{"name": "type:OSINT"},
              {"name": 'misp-galaxy:mitre-malware="Kali365 - S9044"'},
              {"name": "tlp:white"}])
    rows = fm.parse_misp_event(body)
    assert rows == [("evil.example", "domain", "Kali365 - S9044")]


def test_misp_prose_is_not_used_as_a_family():
    """
    An event's info string is a sentence somebody wrote. Filing it as a malware
    family puts prose in a field the model reads as a classification.
    """
    body = {"Event": {"info": "NEW KIT BEING ABUSED IN THE WILD",
                      "Attribute": [_attr("evil.example")], "Tag": []}}
    rows = fm.parse_misp_event(body)
    assert rows == [("evil.example", "domain", "")]


def test_misp_splits_composite_values():
    """MISP writes '1.2.3.4|5.6.7.8'. A stored composite matches nothing."""
    body = _misp_event(_attr("8.8.8.8|9.9.9.9", "ip-dst"))
    rows = fm.parse_misp_event(body)
    assert [r[0] for r in rows] == ["8.8.8.8", "9.9.9.9"]
    assert all(r[1] == "ip" for r in rows)


def test_misp_takes_the_domain_out_of_a_url_attribute():
    body = _misp_event(_attr("http://evil.example/a/b?c=d", "url"))
    assert fm.parse_misp_event(body) == [("evil.example", "domain", "")]


def test_misp_does_not_read_an_event_at_the_wrong_level():
    """A body with no Event and no Attribute is not an event."""
    assert fm.parse_misp_event({"nothing": "here"}) == []
    assert fm.parse_misp_event(None) == []
    assert fm.parse_misp_event([1, 2, 3]) == []


def test_misp_accepts_a_bare_event_without_the_envelope():
    """Some deployments return the event at the top level. Both are read."""
    body = {"Attribute": [_attr("evil.example")], "Tag": []}
    assert fm.parse_misp_event(body) == [("evil.example", "domain", "")]


# SECTION 14. OTX. 2026-09-23. Keyless is a REASON, never an empty feed.
#
# MEASURED ON THE LIVE SERVICE: /pulses/subscribed, /pulses/activity and a
# pulse's /indicators sub-resource all answer HTTP 403 "Authentication
# required" with no key. OTX is therefore a KEYED feed, and the absence of the
# key has to read as a missing key rather than as a feed that found nothing.

def test_otx_without_a_key_names_its_own_variable(monkeypatch):
    monkeypatch.delenv("AGENTAL_OTX_KEY", raising=False)
    monkeypatch.setenv("AGENTAL_ABUSECH_KEY", "an-abusech-key")   # the wrong one
    rows, err, detail = fm.fetch_otx_pulses(3)
    assert rows == []
    assert err and "AGENTAL_OTX_KEY" in err
    # and it must NOT send the abuse.ch key, nor tell the reader to check it
    assert "AGENTAL_ABUSECH_KEY" not in err


def test_otx_key_lookup_is_per_feed():
    """
    The bug this prevents: a fetcher that sends the abuse.ch key to OTX, gets a
    403, and reports it as a bad key for the wrong provider.
    """
    var, _, problem = fm._key_for_feed(fm.FEEDS["otx"])
    assert var == "AGENTAL_OTX_KEY"
    var2, _, _ = fm._key_for_feed(fm.FEEDS["feodo"])
    assert var2 == "AGENTAL_ABUSECH_KEY"
    var3, _, problem3 = fm._key_for_feed(fm.FEEDS["misp"])
    assert var3 is None and problem3 is None      # MISP needs no key


def test_otx_raises_a_reason_for_an_unknown_envelope():
    """
    /pulses/subscribed could not be observed from this host, so the envelope is
    NOT assumed. A shape this reader does not know has to say so, because []
    would be read as a pulse feed that contained nothing.
    """
    try:
        fm.parse_otx_pulses({"unexpected": "shape"})
        assert False, "an unknown envelope must raise"
    except ValueError as e:
        assert "results" in str(e)


def test_otx_accepts_both_documented_envelopes():
    pulse = {"indicators": [{"indicator": "evil.example", "type": "domain"}],
             "malware_families": []}
    assert fm.parse_otx_pulses({"results": [pulse]}) == \
        [("evil.example", "domain", "")]
    assert fm.parse_otx_pulses([pulse]) == [("evil.example", "domain", "")]


def test_otx_ignores_indicator_types_it_cannot_match():
    pulse = {"indicators": [
        {"indicator": "d41d8cd98f00b204e9800998ecf8427e", "type": "FileHash-MD5"},
        {"indicator": "evil.example", "type": "domain"},
        {"indicator": "8.8.8.8", "type": "IPv4"},
        {"indicator": "9.9.9.9", "type": "somethingnew"},
    ]}
    rows = fm.parse_otx_pulses([pulse])
    assert sorted(r[0] for r in rows) == ["8.8.8.8", "evil.example"]


def test_otx_uses_the_pulse_family_then_the_indicator_title():
    """
    MEASURED: the public Log4Shell pulse has an EMPTY malware_families list
    while each indicator carries 'nspps, CoinMiner' in its title, so the title
    is where the useful name actually is for a pulse like that one.
    """
    with_field = [{"indicators": [{"indicator": "evil.example",
                                   "type": "domain"}],
                   "malware_families": [{"display_name": "Qakbot"}]}]
    assert fm.parse_otx_pulses(with_field)[0][2] == "Qakbot"

    with_title = [{"indicators": [{"indicator": "evil.example",
                                   "type": "domain",
                                   "title": "nspps, CoinMiner"}],
                   "malware_families": []}]
    assert fm.parse_otx_pulses(with_title)[0][2] == "nspps, CoinMiner"


def test_otx_checks_the_value_not_only_the_type_it_claims():
    """
    The type is OTX's claim about the value. A mislabelled internal address
    must not be stored on the strength of a third party's type field.
    """
    pulse = {"indicators": [
        {"indicator": "172.20.0.1", "type": "IPv4"},
        {"indicator": "8.8.8.8", "type": "IPv4"},
    ]}
    assert [r[0] for r in fm.parse_otx_pulses([pulse])] == ["8.8.8.8"]


def test_an_ip_that_is_not_globally_routable_is_never_matchable():
    """
    THE MEASURED FILTER. The CIRCL OSINT events list 192.0.2.1 and 192.0.2.5 --
    and 192.0.2.1 is THIS host's own gateway. Storing it would make every
    connection to the operator's router match a community C2 list at high
    severity.
    """
    for bad in ("172.20.0.1", "192.168.1.5", "172.16.0.1", "127.0.0.1",
                "169.254.1.1", "224.0.0.1", "0.0.0.0", "100.64.0.1",
                "198.51.100.7", "203.0.113.9", "::1", "fe80::1",
                "2001:db8::1", "not-an-ip"):
        assert fm._is_matchable_ip(bad) is False, bad
    for good in ("8.8.8.8", "45.155.205.233", "1.1.1.1", "2606:4700::1111"):
        assert fm._is_matchable_ip(good) is True, good


def test_the_public_range_is_matchable_even_though_it_is_special():
    """
    A PRECONDITION CHECK FOR THE FIXTURES, and it is the counterpart of the
    rule above: 203.0.113.0/24 is the documentation range, and Python's
    `is_global` is False for it. Every MATCH-path fixture in this file uses
    203.0.113.9, and those still work -- the injected `_Conn` fake answers the
    lookup directly, so the parse filter never sees them. This asserts the fact
    those fixtures rest on, so a later change to the filter cannot silently
    turn the match tests into tests of nothing.
    """
    assert fm._is_matchable_ip("203.0.113.9") is False


def test_the_parse_paths_drop_an_internal_address(monkeypatch):
    """The filter is applied at the PARSE, for every feed, not only for MISP."""
    assert fm._parse_lines_ip("172.20.0.1\n8.8.8.8\n") == [("8.8.8.8", "ip", "")]
    body = _misp_event(_attr("172.20.0.5", "ip-dst"), _attr("8.8.8.8", "ip-dst"))
    assert [r[0] for r in fm.parse_misp_event(body)] == ["8.8.8.8"]


def test_threatfox_drops_an_internal_address_without_turning_it_into_a_domain():
    """
    The trap: '192.0.2.1' falling through to the domain branch would be cleaned
    into the hostname '192.0.2.1' and stored as a DOMAIN, which matches nothing
    and hides the bad row rather than reporting it.
    """
    text = ('# first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type, malware\n'
            '"2026-01-01", "1", "172.20.0.1:443", "ip:port", "botnet_cc", "X"\n'
            '"2026-01-01", "2", "8.8.8.8:443", "ip:port", "botnet_cc", "X"\n')
    rows = fm._parse_threatfox_csv(text)
    assert rows == [("8.8.8.8", "ip", "X")]


# SECTION 15. The refresh loop with the new feeds in it. 2026-09-23.

def test_a_config_feed_name_that_does_not_exist_is_reported(monkeypatch):
    """
    A typo in the feed list is a person believing a list is being pulled.
    Filtering it silently is how that belief survives.
    """
    monkeypatch.setattr(fm, "_count_indicators", lambda: 0)
    monkeypatch.setattr(fm, "_fetch",
                        lambda url, send_key, key_var=None: (None, "stubbed"))
    import core.memory_engine as me
    monkeypatch.setattr(me, "get_preference", lambda k, default=None: None)
    monkeypatch.setattr(me, "set_preference", lambda k, v: None)

    result = fm.refresh_once(
        {"threat_feeds": {"feeds": ["feodo", "fedo", "misp2"]}}, force=True)

    assert set(result["feeds"]) == {"feodo"}
    assert result["unknown_feed_names"] == ["fedo", "misp2"]
    assert "do not exist" in result["reason"]


def test_misp_refreshes_through_refresh_once(monkeypatch):
    monkeypatch.setattr(fm, "fetch_misp_events",
                        lambda max_events=None: ([("evil.example", "domain", "X")],
                                                 None,
                                                 {"note": "the window"}))
    written = {}
    monkeypatch.setattr(fm, "_replace_feed_rows",
                        lambda feed, rows: written.update({feed: len(rows)}) or 1)
    monkeypatch.setattr(fm, "_count_indicators", lambda: 1)
    import core.memory_engine as me
    monkeypatch.setattr(me, "get_preference", lambda k, default=None: None)
    monkeypatch.setattr(me, "set_preference", lambda k, v: None)

    result = fm.refresh_once({"threat_feeds": {"feeds": ["misp"]}}, force=True)

    assert result["ran"] is True
    assert result["feeds"]["misp"]["ok"] is True
    assert written == {"misp": 1}
    assert result["feeds"]["misp"]["detail"]["note"] == "the window"


def test_otx_failing_on_its_key_does_not_stop_misp(monkeypatch):
    """
    Partial success is real coverage. One feed refused for a missing key must
    not throw away another feed's rows -- the same argument the abuse.ch path
    has carried since it was written.
    """
    monkeypatch.delenv("AGENTAL_OTX_KEY", raising=False)
    monkeypatch.setattr(fm, "fetch_misp_events",
                        lambda max_events=None: ([("evil.example", "domain", "")],
                                                 None, {}))
    monkeypatch.setattr(fm, "_replace_feed_rows", lambda feed, rows: len(rows))
    monkeypatch.setattr(fm, "_count_indicators", lambda: 1)
    import core.memory_engine as me
    monkeypatch.setattr(me, "get_preference", lambda k, default=None: None)
    monkeypatch.setattr(me, "set_preference", lambda k, v: None)

    result = fm.refresh_once(
        {"threat_feeds": {"feeds": ["misp", "otx"]}}, force=True)

    assert result["ran"] is True
    assert result["feeds"]["misp"]["ok"] is True
    assert result["feeds"]["otx"]["ok"] is False
    assert "AGENTAL_OTX_KEY" in result["feeds"]["otx"]["error"]


def test_status_names_a_feed_that_was_never_checked_against(monkeypatch):
    """
    THE OFF VERSUS BROKEN DISTINCTION, on the summary line. A feed that is
    enabled and whose last refresh ERRORED gets its reason printed; a feed that
    answered but held nothing gets the other sentence. One sentence for both
    would send a reader hunting for a feed bug when the answer is an unset
    variable.
    """
    monkeypatch.setattr(fm, "_count_indicators", lambda: 500)
    monkeypatch.setattr(fm, "_per_feed_state", lambda config=None: [
        {"feed": "feodo", "enabled": True, "count": 500, "needs_key": True},
        {"feed": "otx", "enabled": True, "count": 0,
         "needs_key": "AGENTAL_OTX_KEY", "last_ok": False,
         "last_error": "no key set for this feed."},
        {"feed": "misp", "enabled": True, "count": 0, "needs_key": False,
         "last_ok": True},
        {"feed": "urlhaus", "enabled": False, "count": 0, "needs_key": True},
    ])
    # See the note in test_status_on_empty_feed_says_it_cannot_claim.
    monkeypatch.setattr(fm, "_cursor_read", lambda k: None)

    s = fm.status({"threat_feeds": {"enabled": True}})

    assert "NOT CHECKED AGAINST" in s["note"] and "otx" in s["note"]
    assert "NO INDICATORS FROM" in s["note"] and "misp" in s["note"]
    assert "Switched off in config: urlhaus" in s["note"]
    # and the broken one's reason travels with it
    assert "no key set for this feed." in s["note"]


def test_status_without_a_config_does_not_claim_a_feed_is_switched_off(monkeypatch):
    """
    A module-level status() has no config to judge by. Reporting an unknown as
    an OFF is a sentence invented about a machine nobody asked.
    """
    monkeypatch.setattr(fm, "_count_indicators", lambda: 10)
    monkeypatch.setattr(fm, "_per_feed_state", lambda config=None: [
        {"feed": "feodo", "enabled": None, "count": 10, "needs_key": True},
    ])
    # See the note in test_status_on_empty_feed_says_it_cannot_claim.
    monkeypatch.setattr(fm, "_cursor_read", lambda k: None)

    s = fm.status(None)

    assert "Switched off in config" not in s["note"]
    assert "NOT CHECKED AGAINST" not in s["note"]
    assert s["per_feed"][0]["enabled"] is None


# SECTION 16. The cursors live in their own table. 2026-09-23.
#
# THE DEFECT THIS SECTION LOCKS DOWN. The three match cursors and the refresh
# time were rows in user_preferences. core/integrity.snapshot_config digests
# that table as THE POLICY and journals a `config_observed` entry on ANY
# difference, on the contract that such an entry always means the rules
# changed. match_once advances three cursors every pass -- every five minutes
# by default -- so a running matcher wrote a false "the policy has CHANGED"
# warning into the tamper journal forever. MEASURED before the move: writing
# one cursor moved the digest and produced a config_observed row carrying
# 'feed_match_cursor_packets': '123456789'.

def test_a_cursor_write_does_not_move_the_policy_digest(monkeypatch):
    """
    The whole point of the move, asserted the way the v42 and v45 migrations
    assert theirs: snapshot the digest, write a sensor's bookkeeping, snapshot
    again, and prove the journal did not move. Then make a REAL policy change
    and prove THAT one does -- or the check is not strict, it is broken.
    """
    import _isolate_db
    _isolate_db.isolate()
    import sqlite3
    from core import integrity as ig
    import core.memory_engine as me

    conn = sqlite3.connect(str(me.DB_PATH))
    try:
        ig.snapshot_config("test-before", conn=conn)      # establish a baseline
        before = conn.execute(
            "SELECT payload_digest FROM integrity_journal"
            " WHERE operation='config_observed' ORDER BY id DESC LIMIT 1"
        ).fetchone()

        # The bookkeeping a matcher writes four times an hour.
        fm._set_cursor(fm._CUR_PACKETS, 123456789)
        fm._set_cursor(fm._CUR_DNS, 42)
        fm._set_cursor(fm._CUR_TLS, 7)

        # THE NEGATIVE CONTROL. A genuine policy change must still register, or
        # this test proves only that nothing is being journalled at all.
        conn.execute("INSERT OR REPLACE INTO user_preferences(key, value)"
                     " VALUES ('alert_suppression_at', 'medium')")
        conn.commit()
        ig.snapshot_config("test-after-real-change", conn=conn)

        after = conn.execute(
            "SELECT payload_digest FROM integrity_journal"
            " WHERE operation='config_observed' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()

    assert before is not None
    assert after is not None
    assert before[0] != after[0], \
        "a real policy change must still move the digest"


def test_cursors_are_not_written_to_user_preferences():
    """
    Read from the DATABASE, not from the module: the claim is about where the
    value lands.
    """
    import _isolate_db
    _isolate_db.isolate()
    from core import memory_engine as me

    fm._set_cursor(fm._CUR_PACKETS, 99)

    with me._get_conn() as conn:
        prefs = conn.execute(
            "SELECT COUNT(*) FROM user_preferences WHERE key LIKE 'feed_%'"
        ).fetchone()[0]
        in_table = conn.execute(
            f"SELECT value FROM {fm._CURSOR_TABLE} WHERE name = ?",
            (fm._CUR_PACKETS,)).fetchone()
    assert prefs == 0, "bookkeeping is back in the policy table"
    assert in_table and int(in_table[0]) == 99


def test_a_missing_cursor_is_not_the_same_as_a_cursor_at_zero():
    """
    The distinction the whole seeding path rests on. A missing bookmark must
    come back None so the first pass SEEDS; a bookmark at zero means a pass has
    run and reached the start of the table.
    """
    import _isolate_db
    _isolate_db.isolate()

    assert fm._cursor_or_none("never_written_anywhere") is None
    fm._set_cursor("never_written_anywhere", 0)
    assert fm._cursor_or_none("never_written_anywhere") == 0


def test_the_cursor_table_is_created_by_the_readers_if_it_is_missing():
    """
    A database can reach this module without the migration having run. A reader
    that raises would turn a missing bookmark into a broken matcher.
    """
    import _isolate_db
    _isolate_db.isolate()
    from core import memory_engine as me
    import sqlite3

    with sqlite3.connect(str(me.DB_PATH)) as conn:
        conn.execute(f"DROP TABLE IF EXISTS {fm._CURSOR_TABLE}")

    fm._set_cursor(fm._CUR_PACKETS, 5)          # must recreate rather than fail

    with me._get_conn() as conn:
        row = conn.execute(
            f"SELECT value FROM {fm._CURSOR_TABLE} WHERE name = ?",
            (fm._CUR_PACKETS,)).fetchone()
    assert row and int(row[0]) == 5


def test_the_last_refresh_result_survives_in_the_database(monkeypatch):
    """
    status() serves the last per-feed outcome so "why is OTX absent from my
    table" has an answer that outlives the process that watched it fail.
    """
    import _isolate_db
    _isolate_db.isolate()
    from core import memory_engine as me
    monkeypatch.setattr(me, "get_preference", lambda k, default=None: None)
    monkeypatch.setattr(me, "set_preference", lambda k, v: None)
    monkeypatch.setattr(fm, "_count_indicators", lambda: 0)
    monkeypatch.setattr(fm, "fetch_misp_events",
                        lambda max_events=None: ([], "a stubbed reason", {}))

    fm.refresh_once({"threat_feeds": {"feeds": ["misp"]}}, force=True)

    # A FRESH READ, from the database rather than from anything in memory.
    stored = fm._cursor_read(fm._LAST_RESULT)
    assert stored and "misp" in stored and "stubbed" in stored


def test_the_refresh_time_moved_out_of_the_policy_table(monkeypatch):
    """
    THE DEFECT THIS LOCKS DOWN, found on 2026-09-23 by running a real refresh
    against a copy of the live database rather than by reading the code.

    v46 moved the three match cursors out of user_preferences and LEFT
    `feed_last_refresh_at` BEHIND, so the module's bookkeeping was only
    two-thirds moved. MEASURED on the copy, after the v46 migration: one real
    refresh_once moved the policy digest and journalled a config_observed row
    whose payload carried 'feed_last_refresh_at': '2026-09-23T07:59:08+00:00'.

    core/integrity digests user_preferences as THE POLICY and journals a
    warning on ANY difference, on the contract that such an entry ALWAYS means
    the rules changed. A refresh happens four times a day on a successful feed,
    so this was four more false "the policy has CHANGED" entries a day in the
    one journal whose whole value is that it does not cry wolf.

    WRITTEN FAILURE-FIRST: the assertion is about where the value LANDS, read
    from the database, because "the digest did not move" alone would also be
    satisfied by bookkeeping that was never written at all.
    """
    import _isolate_db
    _isolate_db.isolate()
    from core import memory_engine as me

    fm._cursor_write(fm._LAST_REFRESH, "2026-09-23T08:00:00+00:00")

    with me._get_conn() as conn:
        in_prefs = conn.execute(
            "SELECT COUNT(*) FROM user_preferences WHERE key = ?",
            (fm._LAST_REFRESH,)).fetchone()[0]
        in_cursors = conn.execute(
            f"SELECT value FROM {fm._CURSOR_TABLE} WHERE name = ?",
            (fm._LAST_REFRESH,)).fetchone()

    assert in_prefs == 0, \
        "the refresh time is back in the policy table, so every refresh " \
        "writes a false 'the policy has CHANGED' entry into the tamper journal"
    assert in_cursors is not None and in_cursors[0] == "2026-09-23T08:00:00+00:00"


def test_status_reads_the_refresh_time_from_the_cursor_table(monkeypatch):
    """
    The other half of the same move: a reader that still asked
    user_preferences would report every feed as never refreshed once the
    migration deleted the old row.
    """
    from datetime import datetime, timezone, timedelta
    import _isolate_db
    _isolate_db.isolate()

    recent = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    fm._cursor_write(fm._LAST_REFRESH, recent)
    monkeypatch.setattr(fm, "_count_indicators", lambda: 10)

    s = fm.status({})
    assert s["last_refresh_at"] == recent
    assert s["stale"] is False

    # AND THE OTHER DIRECTION, or the check proves only that a value is
    # returned: an old stamp must read as stale through the same path.
    old = (datetime.now(timezone.utc)
           - timedelta(hours=fm.FEED_STALE_HOURS + 5)).isoformat()
    fm._cursor_write(fm._LAST_REFRESH, old)
    s = fm.status({})
    assert s["stale"] is True


def test_a_refresh_does_not_move_the_policy_digest(monkeypatch):
    """
    END TO END, through the real refresh_once, and it is the check the old
    cursor test could not make: that one wrote cursors by hand, so a key the
    refresh path alone touches was invisible to it.

    A STUBBED FETCH AND A REAL WRITE. refresh_once is pointed at one abuse.ch
    feed whose download is faked, so the refresh runs its whole real path --
    key resolution, parse, the row swap, the refresh stamp -- without reaching
    the network.
    """
    import _isolate_db, sqlite3
    _isolate_db.isolate()
    from core import integrity as ig
    import core.memory_engine as me

    monkeypatch.setenv("AGENTAL_ABUSECH_KEY", "test-key")
    monkeypatch.setattr(fm, "_fetch",
                        lambda url, send_key, key_var=None: ("1.2.3.4\n", None))

    def digest():
        with me._get_conn() as conn:
            row = conn.execute(
                "SELECT payload_digest FROM integrity_journal"
                " WHERE operation='config_observed' ORDER BY id DESC LIMIT 1"
            ).fetchone()
            return row[0] if row else None

    # TWO SNAPSHOTS, ONE ON EITHER SIDE OF THE REFRESH, and BOTH COMMITTED.
    # This is what makes the check causal rather than decorative, and the first
    # draft of this test got it wrong: with only a "before" snapshot there is
    # no second entry for the refresh to have moved, so it passed against the
    # very defect it was written for. Proved by running it against the old code
    # and watching it stay green, which is how the flaw was found.
    #
    # Handed a connection, snapshot_config leaves the commit to the caller --
    # see scripts/prune_db.py, which carries the same note from being bitten by
    # it. A held transaction here locks the very writes this test is about.
    def snapshot(reason):
        conn = sqlite3.connect(str(me.DB_PATH))
        try:
            ig.snapshot_config(reason, conn=conn)
            conn.commit()
        finally:
            conn.close()
        return digest()

    before = snapshot("test-before")

    result = fm.refresh_once(
        {"threat_feeds": {"feeds": ["feodo"], "refresh_hours": 0}}, force=True)
    assert result["ran"] is True, result

    after = snapshot("test-after")
    assert before is not None and after is not None
    assert before == after, \
        "a successful refresh moved the policy digest, so the tamper journal " \
        "was told the rules changed by a feed bookmark"

    # THE WRITES DID HAPPEN -- otherwise this passes on a refresh that wrote
    # nothing, which is the vacuous-green shape this project keeps rules about.
    with me._get_conn() as conn:
        stamp = conn.execute(
            f"SELECT value FROM {fm._CURSOR_TABLE} WHERE name = ?",
            (fm._LAST_REFRESH,)).fetchone()
        rows = conn.execute(
            "SELECT COUNT(*) FROM threat_feed WHERE feed='feodo'").fetchone()[0]
    assert stamp is not None, "the refresh never recorded when it ran"
    assert rows == 1, f"expected 1 indicator written, found {rows}"


def test_each_provider_gets_its_own_header_and_not_abusech_s(monkeypatch):
    """
    THE DEFECT THIS LOCKS DOWN, found on 2026-09-23 with the owner's own live
    OTX key in .env.

    `_fetch` sent EVERY key as `Auth-Key`. That is abuse.ch's header, and while
    abuse.ch was the only provider it was right. OTX wants `X-OTX-API-KEY`:

        X-OTX-API-KEY: <key>   ->  HTTP 200, 9114 pulses   (measured)
        OTX-API-Key:   <key>   ->  HTTP 403                (measured)
        Auth-Key:      <key>   ->  HTTP 403                (measured)

    So with a perfect key, OTX could never load, and the refusal it produced
    told the reader to check a variable that was fine. Asserted on the HEADER
    the fetcher builds, because that is the value that was wrong; a test on the
    parsed rows would pass for the wrong reason (a 403 produces an empty row
    list and an error, which looks like the keyless state).
    """
    seen = {}

    class _Resp(_StreamedResp):
        status_code = 200
        text = '{"results": []}'

    def fake_get(url, headers=None, timeout=None, **kw):
        seen["headers"] = dict(headers or {})
        seen["url"] = url
        return _Resp()

    import requests
    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setenv("AGENTAL_OTX_KEY", "otx-key-under-test")
    monkeypatch.setenv("AGENTAL_ABUSECH_KEY", "abusech-key-under-test")

    fm.fetch_otx_pulses(3)
    assert seen["headers"].get("X-OTX-API-KEY") == "otx-key-under-test", \
        "OTX's key was sent under the wrong header, which is a guaranteed 403"
    assert "Auth-Key" not in seen["headers"], \
        "the abuse.ch header was sent to OTX, which refuses it"

    # THE OTHER DIRECTION: abuse.ch must still get ITS header, or the fix
    # moved the defect rather than closing it.
    fm._fetch("https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
              send_key=True, key_var="AGENTAL_ABUSECH_KEY")
    assert seen["headers"].get("Auth-Key") == "abusech-key-under-test"
    assert "X-OTX-API-KEY" not in seen["headers"]

    # AND THE MAP ITSELF, so a third provider cannot be added quietly against
    # somebody else's header.
    assert fm._key_header("AGENTAL_OTX_KEY") == "X-OTX-API-KEY"
    assert fm._key_header("AGENTAL_ABUSECH_KEY") == "Auth-Key"


def test_a_stale_list_is_read_from_its_own_header(monkeypatch):
    """
    THE DEFECT THIS LOCKS DOWN, found 2026-09-23 on a live refresh.

    feodotracker answered HTTP 200 with a well-formed body, parsed cleanly, and
    wrote FIVE rows. Its own header said:

        # Last updated: 2026-03-04 14:28:39 UTC

    Six months old, and every surface called it a successful refresh -- because
    it WAS a successful refresh, of a list that had stopped being updated. The
    module had signals about the RESPONSE and none about the DATA.

    The two spellings are both real, measured from the live services: feodo and
    threatfox say "UTC", urlhaus says "(UTC)".
    """
    feodo = "# Last updated: 2026-03-04 14:28:39 UTC\r\n1.2.3.4\r\n"

    # CORRECTED 2026-09-26. The urlhaus line used to be the LIVE response
    # captured on 2026-09-23, "# Last updated: 2026-09-23 09:43:16 (UTC)",
    # and two assertions were made against it: that the month parsed as 9,
    # and that its AGE was under FEED_LIST_STALE_HOURS. The second was a
    # TIME BOMB and it went off on 2026-09-26 09:43 UTC, exactly 72 hours
    # later: the fixture pasted a real service's date and then compared it
    # to a wall-clock threshold, so the check was measuring how long ago the
    # test was written, not whether a fresh list reads as fresh. The code
    # was right the whole time; the fixture was the thing that moved. The
    # stamp is now DERIVED from the clock, so the property (a current list
    # is under the threshold) holds on every run instead of for 72 hours.
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz
    _fresh = (_dt.now(_tz.utc) - _td(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
    urlhaus = f"# Last updated: {_fresh} (UTC)  #\r\n0.0.0.0 x.com\r\n"

    d = fm._list_date(feodo)
    assert d is not None and d.year == 2026 and d.month == 3 and d.day == 4
    assert d.tzinfo is not None, "a naive datetime would compare wrong"

    # The "(UTC)" spelling, read back as the value that was written.
    d2 = fm._list_date(urlhaus)
    assert d2 is not None and d2.strftime("%Y-%m-%d %H:%M:%S") == _fresh

    # AND WHAT MUST NOT BE READ AS A DATE. A format with no such line, and an
    # empty body, are both None -- never "now". A parser that defaulted to now
    # would make every stale list look fresh, which is the defect itself.
    assert fm._list_date("# no date in this header\n") is None
    assert fm._list_date("") is None
    assert fm._list_date(None) is None

    # The age is derived from the date and the threshold is applied to it.
    age = fm._list_age_hours(feodo)
    assert age is not None and age > fm.FEED_LIST_STALE_HOURS, \
        "a six-month-old list must exceed the threshold"
    assert (fm._list_age_hours(urlhaus) or 1e9) < fm.FEED_LIST_STALE_HOURS


def test_a_refresh_records_the_lists_own_age(monkeypatch):
    """
    The age has to travel: refresh -> the stored result -> the per-feed status.
    A value computed and dropped is the 'clock nobody winds' shape.
    """
    import _isolate_db
    _isolate_db.isolate()
    import core.memory_engine as me
    monkeypatch.setenv("AGENTAL_ABUSECH_KEY", "test-key")
    monkeypatch.setattr(me, "get_preference", lambda k, default=None: None)
    monkeypatch.setattr(me, "set_preference", lambda k, v: None)
    monkeypatch.setattr(fm, "_count_indicators", lambda: 1)
    monkeypatch.setattr(fm, "_replace_feed_rows",
                        lambda feed, rows: len(rows))
    monkeypatch.setattr(fm, "_fetch", lambda url, send_key, key_var=None: (
        "# Last updated: 2026-01-01 00:00:00 UTC\r\n9.9.9.9\r\n", None))

    result = fm.refresh_once(
        {"threat_feeds": {"feeds": ["feodo"]}}, force=True)

    detail = result["feeds"]["feodo"]["detail"]
    assert detail["list_stale"] is True
    assert detail["list_age_hours"] > fm.FEED_LIST_STALE_HOURS

    # AND IT REACHES THE STATUS, which is what a person actually reads.
    per = {f["feed"]: f for f in fm._per_feed_state(
        {"threat_feeds": {"feeds": ["feodo"]}})}
    assert per["feodo"]["list_stale"] is True
    assert per["feodo"]["list_ok"] if "list_ok" in per["feodo"] else True


def test_status_says_a_list_is_out_of_date_and_keeps_loaded_apart_from_current(monkeypatch):
    """
    THE SENTENCE. 'N indicators loaded' was true and misleading: feodo had
    loaded and its list was six months old. Loaded and current are different
    claims, kept apart here the same way never-checked and checked-empty are.
    """
    monkeypatch.setattr(fm, "_count_indicators", lambda: 500)
    monkeypatch.setattr(fm, "_cursor_read", lambda k: "2026-09-23T00:00:00+00:00")
    monkeypatch.setattr(fm, "_per_feed_state", lambda config=None: [
        {"feed": "urlhaus", "enabled": True, "count": 495, "needs_key": True,
         "last_ok": True, "list_stale": False, "list_age_hours": 0.2},
        {"feed": "feodo", "enabled": True, "count": 5, "needs_key": True,
         "last_ok": True, "list_stale": True, "list_age_hours": 4867.3},
    ])

    s = fm.status({"threat_feeds": {"enabled": True}})

    assert "OUT OF DATE" in s["note"], \
        "a six-month-old list passed as coverage without saying so"
    assert "feodo" in s["note"] and "203 days old" in s["note"]
    # URLhaus is current and must NOT be named in that sentence, or the
    # warning becomes noise that gets ignored.
    assert "urlhaus (0 days old)" not in s["note"]


def test_a_match_from_a_stale_list_is_downgraded_and_a_fresh_one_is_not(monkeypatch):
    """
    THE SEVERITY, per feed rather than per pass. Before this, every hit in a
    pass was graded the same, so a five-entry six-month-old list and a
    seven-thousand-entry list updated this hour carried equal weight.
    """
    import _isolate_db
    _isolate_db.isolate()
    monkeypatch.setattr(fm, "_cursor_read", lambda k: (
        '{"feodo": {"ok": true, "detail": {"list_stale": true}}}'
        if k == fm._LAST_RESULT else None))

    assert fm._stale_list_feeds() == {"feodo"}
    assert fm._severity_for_feed("feodo", stale=False) == "medium", \
        "a hit from a six-month-old list kept high severity"
    assert fm._severity_for_feed("urlhaus", stale=False) == "high"
    # The old download-staleness path still works, and still wins.
    assert fm._severity_for_feed("urlhaus", stale=True) == "medium"

    # A READ FAILURE MUST NOT DOWNGRADE ANYTHING. Empty set means ordinary
    # severity, which is the safe direction: silently reducing the severity of
    # real findings because a cursor read failed would be the worse error.
    monkeypatch.setattr(fm, "_cursor_read", lambda k: None)
    assert fm._stale_list_feeds() == set()
    assert fm._severity_for_feed("feodo", stale=False) == "high"


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
