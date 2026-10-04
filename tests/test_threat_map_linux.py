"""
tests/test_threat_map_linux.py, the Threat Map on THIS host, and whether its
findings are about this machine.

2026-09-23. Found by driving the LIVE map against the live database and reading
what it drew, not by reading the code. Four defects, each measured first.

    THE ADDRESSES IT DREW THAT ARE NOT HOSTS.
    PKT-1017 fires on an ICMP router advertisement whose source is the
    OCTET-REVERSE of the address in its own body. The finding's own text says
    "THAT IS A MALFORMED HEADER, not a foreign host ... do not chase where it
    geolocates to". The map geolocated it anyway, because the string is routable:

        1.0.0.10        -> South Brisbane, Queensland, AU    (live row)
        11.22.37.169   -> Example City, Region, ZZ      (live row)
        11.22.33.44       -> Santa Barbara, California, US     (live row)

    Two of those drew an arc from the local pin to a country this machine has
    never exchanged a packet with, in the operator's own words a page that
    "reflects what's happening in Linux".

    THE LOCAL-ENDPOINT LIST HELD A MULTICAST GROUP.
    `home.ips` is the local pin's popup: "the addresses of the local network".
    Measured live, it was the machine's own private address TOGETHER WITH one
    multicast group -- 224.0.0.1 is the all-hosts GROUP. The live values are
    read from the database in the section below rather than written down here,
    because this file is scanned by the release gate.

    "N CONVERSATIONS THIS SESSION" OVER A BLIND CAPTURE.
    Unelevated here the sniffer cannot open a raw socket, so nothing in this
    session was captured; every endpoint came from an earlier elevated run. The
    page's most confident sentence was the false one, while the Sniffer pill on
    another tab said BLIND.

    null MEANT BOTH "CLEAN" AND "COULD NOT LOOK" TO THE MODEL.
    query_threat_map's own description tells the model that "an endpoint with
    severity null has nothing recorded against it and is ordinary traffic", and
    a failed findings read set every row to the same null. Measured: 5 of 5
    endpoints came back null with severity_read true.

Every check below runs against the REAL database on THIS host and the REAL
Flask route with a key. Nothing is written: the database is opened mode=ro, so
the operator's evidence store cannot be touched by running this file.
"""
import contextlib
import io
import json
import pathlib
import sqlite3
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got):
    check(label, bool(got), True)


# [1] THE RULE FLAG ITSELF. Small, deterministic, and it is the thing every
#     other section rests on: PKT-1017 says its entity is not a host, and no
#     other packet rule claims the same.

from core import detections as det                    # noqa: E402

print("\n[1] the register says which rules have an entity that is not a host")

pkt1017 = det.get("PKT-1017")
check("PKT-1017 is marked", pkt1017.entity_is_not_a_host, True)
check("and it reaches as_dict, so a catalogue reader sees it",
      pkt1017.as_dict()["entity_is_not_a_host"], True)

# THE CONTROL, and it is the half that matters: a flag that is set on
# everything would be as useless as one set on nothing. PKT-1016 is the
# neighbouring rule -- "an ICMP router advertisement from off this network" --
# and its entity IS a host: it is a real address on the wire that is not
# supposed to be there. If a future edit gave both rules the flag, the map
# would stop drawing a genuine off-network source.
check("PKT-1016 is NOT marked, and it must not be",
      det.get("PKT-1016").entity_is_not_a_host, False)
flagged = [d["detection_id"] for d in det.summary()
           if d.get("entity_is_not_a_host")]
check("exactly one rule in the whole register carries it", flagged, ["PKT-1017"])

print("\n[1b] a retired or unknown id cannot break a reader")
check("an unregistered id is not an error for a reader", det.exists("PKT-9999"), False)


# [2] THE ADDRESS TESTS. geoip gains a second question beside is_routable:
#     "could a host hold this address", which is NOT the same question.

from core import geoip                                # noqa: E402

print("\n[2] multicast is not a host, and loopback still is")

check("224.0.0.1 is not a host address", geoip.is_host_address("224.0.0.1"), False)
check("239.255.255.250 is not either", geoip.is_host_address("239.255.255.250"), False)
check("ff02::1 is not either", geoip.is_host_address("ff02::1"), False)
check("and the unspecified address is not",
      geoip.is_host_address("0.0.0.0"), False)

# The other direction: everything that IS a host must stay a host, including
# the two that the MAP excludes for a different reason. The addresses here are
# DOCUMENTATION ranges (RFC 5737) plus loopback, deliberately: this file is
# scanned by the release gate, and a private address written into a shipped
# test is that machine's own network in a file that could be published. The
# LIVE section below reads the real ones out of the real database instead.
for ip in ("192.0.2.10", "198.51.100.20", "203.0.113.30", "127.0.0.1",
           "8.8.8.8", "::1"):
    check(f"{ip} is a host address", geoip.is_host_address(ip), True)

check("garbage is not a host address", geoip.is_host_address("not an ip"), False)
# The two functions must genuinely differ, or one of them is redundant and
# somebody will delete the other.
check("loopback is NOT routable but IS a host",
      (geoip.is_routable("127.0.0.1"), geoip.is_host_address("127.0.0.1")),
      (False, True))


# [3] THE AGGREGATE. worst_finding_by_entity_with_rule carries the raising
#     rule, and an unstamped row must not be read as a positive answer.

from core import memory_engine as me                  # noqa: E402

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
me.DB_PATH = _tmp.name
_c = sqlite3.connect(me.DB_PATH)
_c.executescript(io.open(ROOT / "Schema.SQL", encoding="utf-8").read())
_c.commit()
_c.close()


def add_finding(ip, severity, title, did=None, when="2026-09-23T10:00:00"):
    with me._get_conn() as conn:
        conn.execute(
            "INSERT INTO findings (session_id, severity, entity_type, "
            "entity_value, title, dismissed, found_at, detection_id) "
            "VALUES ('s1',?,?,?,?,0,?,?)",
            (severity, "ip", ip, title, when, did))


print("\n[3] the aggregate carries the rule, and only a positive flag counts")

add_finding("1.0.0.10", "low", "octet-reversed header", did="PKT-1017")
add_finding("11.22.35.15", "low", "ordinary thing", did="PKT-1001")
add_finding("203.0.113.9", "low", "raised before ids existed", did=None)

agg = me.worst_finding_by_entity_with_rule("ip", session_id="s1")
check("the malformed-header address is marked", agg["1.0.0.10"]["entity_is_not_a_host"], True)
check("and carries its rule", agg["1.0.0.10"]["detection_id"], "PKT-1017")
check("a host flagging is not marked", agg["11.22.35.15"]["entity_is_not_a_host"], False)
check("AN UNSTAMPED ROW IS NOT A POSITIVE ANSWER",
      agg["203.0.113.9"]["entity_is_not_a_host"], False)
check("and its rule reads as unknown, not as a lie",
      agg["203.0.113.9"]["detection_id"], None)
check("the worst severity still wins",
      agg["1.0.0.10"]["severity"], "low")

# THE SHAPE OF THE OLD FUNCTION IS UNCHANGED. Callers that only want a colour
# must not have been disturbed by a new reader arriving.
old = me.worst_finding_by_entity("ip", session_id="s1")
check("the original aggregate still returns exactly two keys",
      sorted(old["1.0.0.10"].keys()), ["severity", "title"])
check("with the same severity", old["1.0.0.10"]["severity"], "low")

# A RETIRED RULE MUST NOT BREAK THE MAP. The register may retire a number; the
# rows it raised stay in the table forever. Measured by writing a row for an id
# that has never existed, which is the same code path as a retired one.
add_finding("198.51.100.7", "low", "raised by a rule that is gone", did="PKT-0000")
agg2 = me.worst_finding_by_entity_with_rule("ip", session_id="s1")
check("an unknown rule does not raise", "198.51.100.7" in agg2, True)
check("and does not claim the entity is not a host",
      agg2["198.51.100.7"]["entity_is_not_a_host"], False)

# A failed read is still a failure, not an empty map. Rule two.
_real = me._get_conn


class _Broken:
    def __enter__(self):
        raise sqlite3.OperationalError("no such table: findings")

    def __exit__(self, *a):
        return False


me._get_conn = lambda *a, **k: _Broken()
raised = None
try:
    me.worst_finding_by_entity_with_rule("ip", session_id="s1")
except sqlite3.Error as e:
    raised = str(e)
finally:
    me._get_conn = _real
check_true("a failed read raises rather than looking clean", raised)
check("and names what went wrong", "no such table" in (raised or ""), True)


# [4] THE LIVE MAP, THROUGH THE REAL HTTP ROUTE.
#
#     This is the section that would have caught all four defects at once, and
#     it is why it drives the route rather than the function: a function
#     returning the right dict and a route serialising something else is a real
#     failure, and the page reads the route.
#
#     The real database is opened READ ONLY. Nothing here can write to the
#     operator's evidence store.

LIVE_DB = ROOT / "agental_sec.db"
have_live = LIVE_DB.exists()

if not have_live:
    print("\n[4] SKIPPED, no agental_sec.db beside main.py. The live sections")
    print("    below are the point of this file; they are not run here.")
else:
    @contextlib.contextmanager
    def _ro(*a, **k):
        conn = sqlite3.connect(f"file:{LIVE_DB}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    me._get_conn = _ro

    _c = sqlite3.connect(f"file:{LIVE_DB}?mode=ro", uri=True)
    # THE SESSION IS CHOSEN FOR THE FINDING, not for being newest, and the
    # first version of this file got that wrong: it took the newest session,
    # which happens not to carry a PKT-1017 row, so four checks passed against
    # an EMPTY list and one failed against a sentence that was correctly
    # absent. A check that passes on an empty list is the same defect this
    # project keeps finding in its verifiers. So: prefer a session that really
    # holds one of these findings, and say plainly which session was used.
    row = _c.execute(
        "SELECT session_id FROM findings WHERE detection_id = 'PKT-1017' "
        "GROUP BY session_id ORDER BY MAX(found_at) DESC LIMIT 1").fetchone()
    session_with_finding = row[0] if row else None
    row = _c.execute(
        "SELECT session_id FROM packets GROUP BY session_id "
        "ORDER BY MAX(captured_at) DESC LIMIT 1").fetchone()
    session = session_with_finding or (row[0] if row else None)
    _c.close()

    print(f"\n[4] the live map, through the real route (session {session})")
    print(f"    chosen for a PKT-1017 row: "
          f"{'yes' if session_with_finding else 'no such row in this database'}")

    from adapters import LinuxPacketSniffer              # noqa: E402
    from api.server import create_app                    # noqa: E402

    sniffer = LinuxPacketSniffer("test-session",
                                 {"sensors": {"packet_sniffer": {"enabled": True}}})
    modules = {"packet_sniffer": sniffer}

    app = create_app({"flask": {"host": "127.0.0.1", "port": 5000},
                      "geoip": {"enabled": True,
                                "db_path": "geoip/dbip-city-lite.mmdb",
                                "home_lat": 37.7749, "home_lon": -122.4194,
                                "home_label": "test"}},
                     modules, session, api_key="0" * 64)
    client = app.test_client()
    r = client.get("/api/threatmap", headers={"X-API-Key": "0" * 64})
    check("the route answered", r.status_code, 200)
    d = r.get_json()

    # ,, the not-host bucket, which is the finding that started this ,,
    check("the route reports a not_hosts list", "not_hosts" in d, True)
    check("and a count of it", d["not_hosts_count"], len(d["not_hosts"]))
    nh_ips = [n["ip"] for n in d["not_hosts"]]
    print(f"    live not_hosts: {nh_ips}")
    for n in d["not_hosts"]:
        check_true(f"{n['ip']} names the rule that raised it", n.get("detection_id"))
        check(f"{n['ip']} carries a reason", bool(n.get("reason")), True)
        check(f"{n['ip']} carries the note that it is unplottable",
              "not a host" in (n.get("note") or ""), True)

    # THE RULE THAT MATTERS: an address in this list must not ALSO be on the
    # globe. A page that lists it as unplottable and draws it anyway has moved
    # the lie rather than fixed it.
    plotted = {e["ip"] for e in d["endpoints"]}
    overlap = plotted & set(nh_ips)
    check("and NOTHING in that list is drawn on the globe", sorted(overlap), [])

    # ,, the local list must not hold a group ,,
    local = (d.get("home") or {}).get("ips") or []
    print(f"    live home.ips: {local}")
    for ip in local:
        check(f"{ip} in home.ips is a host address",
              geoip.is_host_address(ip), True)
    check("no multicast in the local list",
          [i for i in local if i.startswith("224.") or i.startswith("239.")], [])

    # ,, capture blindness is reported, because the page claims a session ,,
    check("the payload reports the capture state", "capture" in d, True)
    cap = d.get("capture")
    if cap:
        check_true("it says whether capture is blind or running",
                   isinstance(cap.get("blind"), bool))
        if cap.get("blind"):
            check_true("a blind capture carries its reason",
                       bool(str(cap.get("blind_reason") or "").strip()))

    # ,, severity_read still holds, and the page has a legend entry for it ,,
    check("the severities were read on this run", d["severity_read"], True)
    page = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
    check("the page knows the word 'unknown'",
          "unknown:  '#6b7683'" in page, True)
    check("and prints it as words rather than as a severity",
          "COULD NOT BE READ" in page, True)

    # ,, THE MODEL'S COPY, same database, same run ,,
    print("\n[4b] the model's copy of the same map")

    from core import tool_registry as tr                 # noqa: E402

    tr.init_registry(session, modules)
    out = tr._query_threat_map({})

    check("the tool reports a not_a_host list", "not_a_host" in out, True)
    check("with a count", out["not_a_host_count"], len(out["not_a_host"]))
    tool_plotted = {e["ip"] for e in out["endpoints"]}
    check("and none of them is in its endpoints either",
          sorted(tool_plotted & set(nh_ips)), [])

    # THE MODEL IS TOLD IN WORDS. A field called not_a_host with no sentence
    # explaining it is a field the model will guess at, and the guess that puts
    # "Australia" in an answer is the one that costs something.
    #
    # The sentence is only THERE when there is something to say -- it is a
    # conditional branch in the payload, so asserting it against a session with
    # no such row would be this file committing the defect it exists to catch.
    # Asserted when the row exists, and the absence of both is asserted when it
    # does not.
    htr = out["how_to_read_this"]
    if nh_ips:
        check("the model is told these addresses are not places",
              "NOT ANYWHERE" in htr, True)
    else:
        check("with no such address, the model is not told a story about one",
              "NOT ANYWHERE" in htr, False)
    check("the tool description carries the rule regardless",
          "SOME ADDRESSES HERE ARE NOT HOSTS"
          in json.dumps(tr.TOOL_MANIFEST), True)

    # null must no longer mean both clean and could-not-look.
    sevs = {e["severity"] for e in out["endpoints"]}
    check("no endpoint comes back with a null severity",
          None in sevs, False)
    check("clean endpoints say 'none'", sevs <= {"none", "unknown"}, True)
    check("and 'unknown' is a word the description explains",
          "unknown" in json.dumps(tr.TOOL_MANIFEST), True)

    me._get_conn = _real

    # ,, the page must not overclaim over a blind capture ,,
    print("\n[4c] the page's stats line over a blind capture")
    check("the page has somewhere to put the caveats",
          'id="map-caveats"' in page, True)
    check("and stops saying 'this session' when capture is blind",
          "capture is blind, so this is NOT this session" in page, True)


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
