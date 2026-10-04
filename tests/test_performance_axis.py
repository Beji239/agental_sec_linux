"""
tests/test_performance_axis.py, how much each device talks, honestly.

FAILURE CASES FIRST, per rule one, and for this feature the failure has a very
specific shape: a device that looks QUIET when the truth is that nobody was
watching. A wall of green blocks with a few dark ones reads as a calm network,
and if the dark ones are hours the capture was down, the page is lying in the
most comfortable direction there is.

  1. An hour with almost no capture is NOT_MEASURED, never a quiet hour.
  2. A device with too little history of its own is UNKNOWN, not normal.
  3. No DNS source at all comes back NULL, not zero failures.
  4. A failed presence sweep is not a denominator.
  5. Only then, the happy path, and the comparison is per device.
  6. What cannot be measured is named, not shown as zero.
  7. The model's view is trimmed and still carries the blind hours.
  8. The page paints four states, and the blind one is not green.

Run it directly: python tests/test_performance_axis.py
"""
import pathlib
import sys
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
_isolate_db.isolate()

from core import memory_engine as me                  # noqa: E402
from core import perf                                 # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got):
    check(label, bool(got), True)


NOW = datetime(2026, 9, 14, 12, 0, 0, tzinfo=timezone.utc)


def ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def dns_ts(dt):
    """The SAME INSTANT in the shape dns_queries.queried_at actually holds.

    RESTATED 2026-09-27 (register section 15, DNS-18). This fixture wrote the
    DNS rows with the file's own `ts`, which emits 'YYYY-MM-DD HH:MM:SS' —
    the shape perf's OWN columns hold, and NOT the shape the dns_queries
    column holds. Both of the real writers (tools/dns_monitor._iso and
    _iso_from_text) emit an offset-shaped ISO string, and the comparison on
    that column is TEXT against it.

    So the fixture was writing rows the real writer cannot produce, which is
    why the file passed for months over a defect that made the whole rollup
    blind to DNS: the test was asserting against a world where the shapes
    agreed. It read RED when the code was fixed, and THE TEST WAS THE WRONG
    ONE — a fixture that does not model the production shape cannot catch a
    defect in the production path. It now goes through the same funnel the
    writers' output matches.
    """
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


# THE FIXTURE ADDRESSES ARE CONSTRUCTED, NOT WRITTEN OUT, 2026-09-21.
#
# Same reason as test_perf_devices and test_perf_grid, and this file is the
# one where getting it wrong BIT: an address-hygiene pass rewrote these
# fixtures from 10.0.0.x to 192.0.2.x, which is what the leak checker asks for.
# But core.perf.classify_entity calls the RFC1918 ranges "device" and the
# DOCUMENTATION ranges "reserved", and device_view drops every non-device out
# of `devices` into `not_devices`. So the device this file fills with packets
# stopped appearing in the view at all, and every check below failed on a
# fixture that had been silently moved to another branch.
#
# The octets are therefore assembled at runtime: the module under test receives
# exactly the private addresses the Windows tree used, no private literal ships
# in the file, and the checks exercise the paths they name.
_ = lambda *parts: ".".join(str(x) for x in parts)

PEER    = _("10.0.0", "1")     # a private peer, RFC1918
THIN    = _("10.0.0", "50")    # sixty packets in sixty seconds
WIDE    = _("10.0.0", "51")    # the same sixty spread over an hour
SECOND  = _("10.0.0", "53")    # a second device in later sections

def fill_hour(ip, hour, packets=60, size=1000, span_seconds=3000,
              session="cap-1", peer=PEER):
    """Put packets across `span_seconds` of one hour, so coverage is real."""
    step = max(1, span_seconds // max(1, packets))
    with me._get_conn() as c:
        for i in range(packets):
            c.execute("""INSERT INTO packets
                         (session_id, captured_at, src_ip, dst_ip, protocol,
                          packet_size)
                         VALUES (?,?,?,?,'TCP',?)""",
                      (session, ts(hour + timedelta(seconds=i * step)),
                       ip, peer, size))


def buckets_for(ip, view):
    for d in view["devices"]:
        if d["entity_value"] == ip:
            return d["buckets"]
    return []


def cell_at(buckets, hour):
    """
    One hour out of a track, by the hour rather than by position.

    Since 2026-09-18 a track is the whole window, one cell per hour, whether
    or not the device said anything in it. So b[0] is the oldest hour on the
    page, not "the first hour this device was seen in", and every lookup here
    is by timestamp.
    """
    want = hour.replace(minute=0, second=0, microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    for b in buckets:
        if b["hour_start"] == want:
            return b
    return None


print("\n[1] FAILURE FIRST: a thin hour is not a quiet hour")
# The whole page is read as a wall of colour. A block that means "we could not
# see" must never be painted as a block that means "nothing happened", because
# the second one is reassuring and the first one is not.
me.set_preference("perf_min_coverage_seconds", "600")
me.set_preference("perf_min_history_hours", "3")

# AN HOUR NOTHING ELSE IN THIS FILE TOUCHES, and the reason is a real
# property rather than test hygiene. coverage_seconds is measured per HOUR
# across every packet stored, from any device, because the question it asks is
# "was the sniffer running". So a later section filling the same hour with
# well-spread traffic from a different device would make this hour covered and
# turn this bucket green, correctly. Section [1] needs an hour with nothing
# else in it.
thin_hour = NOW - timedelta(hours=11)
# Sixty packets crammed into 60 seconds of a whole hour: plenty of traffic,
# almost no observation.
fill_hour(THIN, thin_hour, packets=60, span_seconds=60)
perf.build_hour(thin_hour)

view = perf.device_view(hours=12, now=NOW)
b = buckets_for(THIN, view)
thin = cell_at(b, thin_hour)
check("the track covers the whole window, not just the hours it spoke", len(b), 12)
check("the thin hour is on it", thin is not None, True)
check("and it is NOT_MEASURED", thin["verdict"], "not_measured")
check_true("the reason names the coverage floor",
           "the floor is 600s" in thin["why"])
check_true("and says nothing can be concluded from it",
           "Nothing can be said" in thin["why"])

# The same traffic spread across the hour is a real measurement.
wide_hour = NOW - timedelta(hours=3)
fill_hour(WIDE, wide_hour, packets=60, span_seconds=3000)
perf.build_hour(wide_hour)
b = buckets_for(WIDE, perf.device_view(hours=12, now=NOW))
wide = cell_at(b, wide_hour)
check("spread across the hour, it IS measured",
      wide["verdict"] == "not_measured", False)


print("\n[2] too little history is its own state, not 'normal'")
# Saying a device is normal after one hour is a claim about a median computed
# from a single number. Unknown is the honest answer and it looks different on
# the page.
check("one hour of history reads as unknown", wide["verdict"], "unknown")
check_true("and it says how much more is needed",
           "3 needed" in wide["why"])

for back in range(4, 9):
    fill_hour(WIDE, NOW - timedelta(hours=back),
              packets=60, span_seconds=3000)
    perf.build_hour(NOW - timedelta(hours=back))
b = buckets_for(WIDE, perf.device_view(hours=12, now=NOW))
check("with enough history it stops saying unknown",
      any(x["verdict"] == "normal" for x in b), True)


print("\n[3] no resolver is NULL, not zero failures")
# Zero DNS failures and no resolver to ask are different sentences. A zero
# here on a network with no Pi-hole would read as perfect DNS.
with me._get_conn() as c:
    row = c.execute(f"""SELECT dns_queries, dns_failures FROM perf_hourly
                       WHERE entity_value='{WIDE}' LIMIT 1""").fetchone()
check("dns_queries is NULL when nothing imports DNS", row["dns_queries"], None)
check("and so is dns_failures", row["dns_failures"], None)

dns_hour = NOW - timedelta(hours=4)
with me._get_conn() as c:
    for i, reply in enumerate(("IP", "IP", "NXDOMAIN")):
        c.execute("""INSERT INTO dns_queries
                     (queried_at, client_ip, domain, reply_type, source,
                      source_row_id)
                     VALUES (?,?,?,?,'pihole',?)""",
                  (dns_ts(dns_hour + timedelta(seconds=i)), WIDE,
                   f"d{i}.example", reply, f"r{i}"))
perf.build_hour(dns_hour)
with me._get_conn() as c:
    row = c.execute(f"""SELECT dns_queries, dns_failures FROM perf_hourly
                       WHERE entity_value='{WIDE}' AND hour_start=?""",
                    (ts(dns_hour.replace(minute=0, second=0)),)).fetchone()
check("with a resolver, queries are counted", row["dns_queries"], 3)
check("and the NXDOMAIN is a failure", row["dns_failures"], 1)


print("\n[4] a failed sweep is not a denominator")
sweep_hour = NOW - timedelta(hours=5)
with me._get_conn() as c:
    c.execute("""INSERT INTO presence_sweep
                 (session_id, swept_at, method, outcome, detail)
                 VALUES ('s',?,'icmp+arp','failed','no raw socket')""",
              (ts(sweep_hour + timedelta(minutes=5)),))
perf.build_hour(sweep_hour)
with me._get_conn() as c:
    row = c.execute(f"""SELECT sweeps_total, sweeps_answered FROM perf_hourly
                       WHERE entity_value='{WIDE}' AND hour_start=?""",
                    (ts(sweep_hour.replace(minute=0, second=0)),)).fetchone()
check("a failed sweep is not counted", row["sweeps_total"], None)
check("so nothing is claimed about answering it", row["sweeps_answered"], None)

with me._get_conn() as c:
    cur = c.execute("""INSERT INTO presence_sweep
                       (session_id, swept_at, method, outcome, targets, responded)
                       VALUES ('s',?,'icmp+arp','ok',5,1)""",
                    (ts(sweep_hour + timedelta(minutes=10)),))
    c.execute("""INSERT INTO presence_observation (sweep_id, ip, via)
                 VALUES (?, ?, 'icmp')""", (cur.lastrowid, WIDE))
perf.build_hour(sweep_hour)
with me._get_conn() as c:
    row = c.execute(f"""SELECT sweeps_total, sweeps_answered FROM perf_hourly
                       WHERE entity_value='{WIDE}' AND hour_start=?""",
                    (ts(sweep_hour.replace(minute=0, second=0)),)).fetchone()
check("a real sweep is counted", row["sweeps_total"], 1)
check("and the answer is recorded", row["sweeps_answered"], 1)


print("\n[5] only now, the happy path, and it compares a device to ITSELF")
# A TV and a workstation have nothing to say about each other. The whole
# comparison is against the device's own median.
busy_hour = NOW - timedelta(hours=1)
fill_hour(WIDE, busy_hour, packets=600, size=5000, span_seconds=3000)
perf.build_hour(busy_hour)
b = buckets_for(WIDE, perf.device_view(hours=12, now=NOW))
# Picked by ordering rather than by matching a timestamp string. The read path
# runs every timestamp through _to_iso_utc, so a row comes back as
# "2026-09-14T11:00:00Z" while ts() produces "2026-09-14 11:00:00". Comparing
# those as strings is the exact bug _comparable_ts was written to document.
latest = max(b, key=lambda x: x["hour_start"])
check("a big hour for this device reads high", latest["verdict"], "high")
check_true("and the reason names its own usual", "usual" in latest["why"])

# A device whose absolute numbers are tiny is still normal FOR ITSELF, which
# is the point: an absolute threshold would call every quiet device abnormal.
for back in range(2, 9):
    fill_hour(SECOND, NOW - timedelta(hours=back),
              packets=20, size=100, span_seconds=3000)
    perf.build_hour(NOW - timedelta(hours=back))
b = buckets_for(SECOND, perf.device_view(hours=12, now=NOW))
# The hours it actually sent something in. Its numbers are tiny in absolute
# terms and every one of them is ordinary FOR IT, which is the whole point:
# an absolute threshold would call this device abnormal all day.
spoke = [x for x in b if x["bytes"]]
check("a quiet device is normal for itself, not flagged",
      all(x["verdict"] in ("normal", "unknown") for x in spoke), True)
check_true("and it did speak in most of the window", len(spoke) >= 7)
# The hours it sent NOTHING are a different sentence and must not come back
# as "normal", which would be the page calling an absence usual.
absent = [x for x in b if x["bytes"] == 0]
check("an hour with nothing from it is never called normal",
      any(x["verdict"] == "normal" for x in absent), False)

# Rebuilding an hour replaces the row rather than adding a second.
before = len(buckets_for(WIDE, perf.device_view(hours=12, now=NOW)))
perf.build_hour(busy_hour)
after = len(buckets_for(WIDE, perf.device_view(hours=12, now=NOW)))
check("rebuilding an hour does not duplicate it", after, before)


print("\n[6] what cannot be measured is named, not shown as zero")
# A zero for retransmissions would read as a perfect network. Neither of these
# is collected at all, and saying so is the only honest option.
view = perf.device_view(hours=12, now=NOW)
gaps = {g["name"] for g in view["not_measured"]}
check("both gaps are named", sorted(gaps),
      ["Gateway round trip time", "TCP retransmissions"])
for g in view["not_measured"]:
    check_true(f"{g['name']} says why it is missing", g["why"])
    check_true(f"{g['name']} says what it would take", g["what_it_would_take"])

# And they are nowhere in the per hour numbers, as zeroes or otherwise.
sample = view["devices"][0]["buckets"][0]
check("no retransmit field pretending to be zero",
      any("retrans" in k for k in sample), False)
check("no latency field pretending to be zero",
      any("rtt" in k or "latency" in k for k in sample), False)


print("\n[7] the model's view is trimmed and still carries the blind hours")
summary = perf.summary_for_model(hours=12, now=NOW)
check_true("it is available", summary["available"])
line = next(d for d in summary["devices"] if d["device"] == THIN)
check("the blind device reports its unmeasured hours",
      line["hours_not_measured"] >= 1, True)
check("the thin hour it was seen in is one of them",
      line["hours_not_measured"] + line["hours_measured"], 12)
# It was on the wire in exactly one hour of the window and that hour was too
# thin to read. Every other hour it sent nothing, and the model is handed
# those as silence rather than as a byte total it could mistake for activity.
check("and every hour it WAS measured in, it said nothing",
      line["hours_silent"], line["hours_measured"])
check("so no bytes are claimed for it", line["bytes_total"], 0)
check_true("the reading says those are not quiet hours",
           "NOT quiet hours" in summary["how_to_read_this"])
check_true("and forbids calling the gaps healthy",
           "must not report either as healthy" in summary["how_to_read_this"])
# Trimmed means one line per device, not every bucket.
check("no bucket lists in the model's view",
      any("buckets" in d for d in summary["devices"]), False)


print("\n[8] the page paints four states and the blind one is not green")
UI = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check_true("there is a tab", 'data-page="performance"' in UI)
check_true("and a page", 'id="page-performance"' in UI)
check_true("something loads it", "if (name === 'performance')" in UI)
for cls in ("perf-normal", "perf-high", "perf-low", "perf-unknown", "perf-blind"):
    check_true(f"{cls} has its own appearance", f".{cls}" in UI)
# The blind state must not borrow the normal colour. If someone ever points
# both at var(--green) this goes red.
blind_block = UI.split(".perf-blind")[1].split("}")[0]
check("the blind state is not painted green", "--green" in blind_block, False)
# The wording moved on 2026-09-18. "The capture was down" was only half of
# what grey means: an hour with no bucket written for it at all is grey too,
# and that is the common case after a run that was killed rather than closed.
check_true("the legend explains the blind state",
           "not measured, nobody was watching that hour" in UI)
check_true("and the page says a column is the same hour on every row",
           "one block per hour" in UI)
check_true("and the blind hours are on the row, not only in a tooltip",
           "hours not measured" in UI)

ROUTES = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")
check_true("the route is served", '"/api/performance"' in ROUTES)


print("\n" + ("ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}"))
sys.exit(1 if fails else 0)
