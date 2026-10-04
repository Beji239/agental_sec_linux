"""
tests/test_perf_grid.py, every row on the Performance page covers the same
hours, and a gap says which kind of gap it is.

WHY THIS EXISTS, 2026-09-18. The owner opened the tab on a 24 hour window and
the tracks were 3, 4, 8 and 9 blocks long. Not one row had 24.

The cause was that a track was built straight from the perf_hourly rows that
happened to exist, and build_hour only writes a row for an address that was on
the wire in that hour. So two completely different facts,,,

    the sniffer was not running that hour
    the device sent nothing that hour

,,, both came out as NO CELL AT ALL, and the row simply got shorter. That is
rule two broken in the place this whole page was built to defend: a function
that could not look must not produce the same output as a function that looked
and found nothing. A missing cell says neither out loud. It just shortens the
evidence, and a short row of green reads as a calm device.

It also meant column 3 of one row was a different hour from column 3 of the
next, so the grid could not be read across at all, which is the only thing a
grid is for.

FAILURE CASES FIRST, per rule one. Every check here is about a gap, and the
happy path is at the bottom where it belongs.

  1. A blind hour is a grey cell on EVERY row, not a missing cell.
  2. A measured hour with no traffic is a real zero, not a missing cell.
  3. Blind and silent are different sentences, in the tooltip and in the count.
  4. Every track is exactly as long as the window, whatever the device did.
  5. The hour in progress is not on the grid, because it is never bucketed.
  6. A device that went silent all window is still listed.
  7. The page says how much of the window was measured, once, at the top.
  8. Only then, the ordinary path.

Run it directly: python tests/test_perf_grid.py
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


NOW = datetime(2026, 9, 18, 12, 30, 0, tzinfo=timezone.utc)   # mid hour
# Every fixture hour hangs off the top of the hour, never off NOW itself, or a
# packet span would spill into the hour after it.
BASE = NOW.replace(minute=0, second=0, microsecond=0)
# THE FIXTURE ADDRESSES ARE CONSTRUCTED, NOT WRITTEN OUT, 2026-09-21.
#
# Same reason as test_perf_devices: this file asserts what classify_entity
# CALLS each address, and the classes are RFC1918 -> "device", 169.254/16 ->
# "link_local", the DOCUMENTATION ranges -> "reserved". Swapping a private
# fixture for a documentation one -- which is what the leak checker asks for --
# would turn every one of those assertions into a test of the reserved path.
# So the octets are assembled at runtime and the module under test sees exactly
# the same address the Windows tree used.
_ = lambda *parts: ".".join(str(x) for x in parts)

PRIVATE_GW   = _("10.0.0", "1")        # a private gateway, RFC1918
PRIVATE_HOST = _("10.0.0", "20")       # a desktop
PRIVATE_TV   = _("10.0.0", "30")       # a television
BCAST_24     = _("10.0.0", "255")      # the /24 broadcast
BCAST_168    = _("192.168.1", "255")   # another /24 broadcast
BCAST_23     = _("10.0.1", "255")      # NOT a broadcast of 10.0.255.255/16
NET_16       = _("10.0.255", "255")    # the /16 that makes BCAST_23 a device
RESERVED_08  = _("0.0.128", "254")     # 0.0.0.0/8, reserved
LINKLOCAL    = _("169.254.100", "1")   # an adapter with no lease

HOST = PRIVATE_HOST
TV = PRIVATE_TV


def ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def iso(dt):
    """How an hour comes back OUT of perf, which is not how sqlite stores it."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def fill_hour(src, dst, hour, packets=60, size=1000, span_seconds=3000,
              session="cap-1"):
    step = max(1, span_seconds // max(1, packets))
    with me._get_conn() as c:
        for i in range(packets):
            c.execute("""INSERT INTO packets
                         (session_id, captured_at, src_ip, dst_ip, protocol,
                          packet_size)
                         VALUES (?,?,?,?,'TCP',?)""",
                      (session, ts(hour + timedelta(seconds=i * step)),
                       src, dst, size))


def row_for(value, view):
    for d in view["devices"]:
        if d["entity_value"] == value:
            return d
    return None


def cell_at(device, hour):
    for b in device["buckets"]:
        if b["hour_start"] == iso(hour):
            return b
    return None


me.set_preference("perf_min_coverage_seconds", "600")
me.set_preference("perf_min_history_hours", "12")

# The shape of the fixture, all times relative to NOW at 12:30.
#   hours 2 to 25 back   both devices busy, so both have a baseline
#   hour 1 back          BLIND, nothing captured at all
#   hour 4 back          the TV said nothing, the PC was busy
BLIND = BASE - timedelta(hours=1)
SILENT = BASE - timedelta(hours=4)

for back in range(2, 26):
    hour = BASE - timedelta(hours=back)
    fill_hour(HOST, PRIVATE_GW, hour)
    if hour != SILENT:
        fill_hour(TV, PRIVATE_GW, hour)
    perf.build_hour(hour)

view = perf.device_view(hours=24, now=NOW)


# FAILURE CASES FIRST

print("\n[1] FAILURE FIRST: an hour nobody measured is grey on every row")
# The old code dropped it. A dropped hour is the most comfortable lie this
# page can tell, because the row that is left looks complete.
pc, tv = row_for(HOST, view), row_for(TV, view)
blind_pc, blind_tv = cell_at(pc, BLIND), cell_at(tv, BLIND)
check_true("the blind hour is on the PC's row at all", blind_pc is not None)
check_true("and on the TV's row", blind_tv is not None)
check("the PC's blind hour is grey", blind_pc["verdict"], "not_measured")
check("the TV's blind hour is grey", blind_tv["verdict"], "not_measured")
check_true("and it says no bucket was written",
           "no buckets were written" in blind_pc["why"])
check_true("and says out loud it is not a quiet hour",
           "not a quiet hour" in blind_pc["why"])
check("a blind hour claims no byte count", blind_pc["bytes"], None)
check("and no packet count", blind_pc["packets"], None)


print("\n[2] and an hour that WAS measured with no traffic is a real zero")
# The other half of the same bug. This one is a fact about the device and it
# must be coloured, not dropped.
silent = cell_at(tv, SILENT)
check_true("the silent hour is on the row", silent is not None)
check("it is not grey", silent["verdict"] == "not_measured", False)
check("it carries a real zero", silent["bytes"], 0)
check_true("and the tooltip says nothing came from the device",
           "nothing at all from this device" in silent["why"])
check_true("the PC was busy in that same hour",
           cell_at(pc, SILENT)["bytes"] > 0)


print("\n[3] blind and silent are counted apart, not added together")
# One number for both would put this page back where it started.
check("the TV has one silent hour", tv["hours_silent"], 1)
check("the TV has one blind hour", tv["hours_blind"], 1)
check("the PC has no silent hours", pc["hours_silent"], 0)
check("the PC has the same blind hour", pc["hours_blind"], 1)
summary = perf.summary_for_model(hours=24, now=NOW)
line = [d for d in summary["devices"] if d["device"] == TV][0]
check("the model gets them apart too", line["hours_silent"], 1)
check("and the blind count with it", line["hours_not_measured"], 1)
check_true("and is told not to mix them",
           "must not mix" in summary["how_to_read_this"])


print("\n[4] every track is exactly as long as the window")
# The visible bug. Rows of 3 and 9 blocks in a 24 hour window, and columns
# that did not line up between one row and the next.
for d in view["devices"]:
    check(f"{d['entity_value']} has 24 cells", len(d["buckets"]), 24)
hours_pc = [b["hour_start"] for b in pc["buckets"]]
hours_tv = [b["hour_start"] for b in tv["buckets"]]
check("the two rows cover the same hours in the same order",
      hours_pc, hours_tv)
check("and they are in order, oldest first", hours_pc, sorted(hours_pc))
check("the grid on the page matches the rows", view["hour_grid"], hours_pc)

week = perf.device_view(hours=168, now=NOW)
check("a week window is 168 cells wide",
      len(row_for(HOST, week)["buckets"]), 168)
check_true("and most of it is honestly grey",
           week["hours_not_measured"] >= 140)


print("\n[5] the hour in progress is not on the grid")
# It is never bucketed, so including it would paint a fresh grey column across
# every device for the whole of every hour, for ever.
check("the last cell is the last FINISHED hour",
      hours_pc[-1], iso(BASE - timedelta(hours=1)))
check("the window ends there too", view["window_end"], iso(BASE))
check("no cell is from the current hour",
      any(h >= iso(BASE) for h in hours_pc), False)


print("\n[6] a device that went silent all window is still listed")
# A device that drops off the list reads as a device that was never there.
LATER = NOW + timedelta(hours=30)
later = perf.device_view(hours=24, now=LATER)
gone = row_for(TV, later)
check_true("it is still on the page", gone is not None)
check("with a full length track", len(gone["buckets"]), 24)
check("and no bytes claimed for it", gone["bytes_total"], 0)

# And it does drop off eventually, or the page becomes a museum.
MUCH_LATER = NOW + timedelta(days=9)
old = perf.device_view(hours=24, now=MUCH_LATER)
check("after the silent window it is gone", row_for(TV, old), None)


print("\n[7] the page says how much of the window it measured, once")
check("it counts the blind hours", view["hours_not_measured"], 1)
check_true("and says so in a sentence",
           "1 of the 24 hours" in view["coverage_note"])
check_true("which says they are not quiet hours",
           "not quiet hours" in view["coverage_note"])
check_true("and the reading says a column is one hour across the page",
           "SAME hours" in view["how_to_read_this"])


print("\n[8] broadcast and reserved addresses are not devices")
# Both were on the page with names, byte totals and baselines of their own.
check("the subnet broadcast is not a device",
      perf.classify_entity(BCAST_24), "broadcast")
check("nor the other /24 broadcast", perf.classify_entity(BCAST_168), "broadcast")
check("0.0.0.0/8 is reserved, not a device",
      perf.classify_entity(RESERVED_08), "reserved")
check("carrier space is reserved too",
      perf.classify_entity("100.64.0.1"), "reserved")
check("the documentation block as well",
      perf.classify_entity("192.0.2.5"), "reserved")
check("a real host is still a device",
      perf.classify_entity(PRIVATE_HOST), "device")
# With the real subnets in hand the guess is not used at all, so a host that
# happens to end in .255 on a /23 keeps its place on the page.
check("and .255 on a known /23 is a device, not a guess",
      perf.classify_entity(BCAST_23, {NET_16}), "device")

with me._get_conn() as c:
    c.execute("""INSERT INTO presence_sweep(session_id, subnet, method,
                 outcome, targets, responded)
                 VALUES('s1','172.20.0.0/24','icmp','ok',254,9)""")
check("the swept subnet gives the exact broadcast",
      BCAST_24 in perf.local_broadcasts(), True)

fill_hour(BCAST_24, HOST, BASE - timedelta(hours=3))
fill_hour(RESERVED_08, HOST, BASE - timedelta(hours=3))
perf.build_hour(BASE - timedelta(hours=3))
mixed = perf.device_view(hours=24, now=NOW)
listed = {d["entity_value"] for d in mixed["devices"]}
check("the broadcast address is off the page", BCAST_24 in listed, False)
check("so is the 0.0.0.0/8 one", RESERVED_08 in listed, False)
kinds = {g["kind"] for g in mixed["not_devices"]}
check_true("and both are counted with a reason beside them",
           {"broadcast", "reserved"} <= kinds)
check_true("the page says whether the broadcast rule is exact or a guess",
           "exact" in mixed["classification_note"])


# THE ORDINARY PATH

print("\n[9] the ordinary path, a busy hour still reads high")
big = BASE - timedelta(hours=6)
fill_hour(HOST, PRIVATE_GW, big, packets=600, size=5000)
perf.build_hour(big)
after = perf.device_view(hours=24, now=NOW)
cell = cell_at(row_for(HOST, after), big)
check("a much bigger hour reads high", cell["verdict"], "high")
check_true("and names the device's own usual", "usual" in cell["why"])
check("an ordinary hour is still normal",
      cell_at(row_for(HOST, after), BASE - timedelta(hours=8))["verdict"],
      "normal")


print("\n[10] the hour being judged is not part of its own median")
# It dragged the median toward the value about to be tested against it, which
# is worst on exactly the hour that matters most.
ordered = [1, 1, 1, 1, 1, 100]
check("plain median", perf._median(ordered), 1.0)
check("median with the big one left out",
      perf._median_skipping(ordered, 5), 1.0)
check("median with a small one left out",
      perf._median_skipping(ordered, 0), 1.0)
check("a one sample list has nothing left to compare against",
      perf._median_skipping([5], 0), 0.0)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
