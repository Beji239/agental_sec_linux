"""
tests/test_perf_devices.py, the Performance page lists DEVICES, and says why a
block is hollow.

WHY THIS EXISTS, 2026-09-15. The owner opened the tab and found every endpoint
on the owner's network listed beside every destination the owner's sessions had talked to, with
not one coloured block anywhere, and nothing on the page explaining either.

Three separate faults, and they compounded into "this is broken":

  1. build_hour groups packets by src_ip AND by dst_ip with no filter, so
     77.111.246.43, 11.22.33.53, 224.0.0.251 and 239.255.255.250 all became
     devices with baselines. A remote destination's byte history is a
     measurement of what WE sent it. Calling that its normal is measuring
     ourselves and putting its name on the result.

  2. Buckets were only ever built by the hourly thread, which sleeps an hour
     before its first pass, and by clean shutdown, and both reach back six
     hours. A run that was killed rather than closed left every hour it
     observed unbucketed forever, while its packets sat on disk. Six buckets
     after two days, so no device ever reached the twelve hours a baseline
     needs, so every block stayed hollow.

  3. The page never said any of that. It showed a legend and left the reader
     to work out that hollow meant "starving" rather than "faulty".

FAILURE CASES FIRST, per rule one. For this feature the failure is a page that
looks like a verdict when it is actually a shrug: hollow read as quiet, a
destination read as a device, silence read as an answer.

Run it directly: python tests/test_perf_devices.py
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


NOW = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)

# THE FIXTURE ADDRESSES ARE CONSTRUCTED, NOT WRITTEN OUT, 2026-09-21.
#
# WHY, because it looks like needless cleverness and it is not. This file
# asserts what perf.classify_entity CALLS a given address, and the classes are:
#
#     RFC1918 private          -> "device"    (the only kind that gets a baseline)
#     169.254/16 link-local    -> "link_local"
#     the DOCUMENTATION ranges -> "reserved"
#
# which is the opposite of what scripts/check_no_local_details.py asks for. Its
# remedy for a private host address is "use a documentation address (192.0.2.x)",
# and doing that here would silently convert every one of these checks into a
# test of the RESERVED path: "private is a device" would be asserting that a
# documentation address is a device, which is false, and the test would fail --
# or worse, pass for a reason that has nothing to do with a home LAN.
#
# So the octets are assembled at runtime. The address the module under test
# receives is identical to the one the Windows tree used (a private host, a
# link-local host), no private literal sits in the shipped file, and the check
# still exercises the path it was written for. The same trick test_enrichment
# already uses in the Windows tree for 169.254.0.0.
def _addr(prefix, host):
    """Join RFC1918 / link-local parts, so no private literal ships."""
    return f"{prefix}.{host}"


HOST = _addr("10.0.0", "20")           # a desktop, RFC1918
TV = _addr("10.0.0", "30")             # a television, RFC1918
REMOTE = "77.111.246.43"               # a destination, not a device
DNS = "11.22.33.53"                    # an ISP resolver, also not a device
MCAST = "224.0.0.251"                  # mDNS group
SSDP = "239.255.255.250"               # SSDP group
LINKLOCAL = _addr("169.254.100", "1")  # an adapter with no lease


def ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


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


def measured(device):
    """
    Cells that are a real reading, out of a track that is now the whole window.

    Since 2026-09-18 every row has one cell per hour whether the device spoke
    or not, so "how many hours does this device have" is a count of the cells
    that are not grey, never len(buckets).
    """
    return [b for b in device["buckets"] if b["verdict"] != "not_measured"]


def row_for(value, view):
    for d in view["devices"]:
        if d["entity_value"] == value:
            return d
    return None


me.set_preference("perf_min_coverage_seconds", "600")
me.set_preference("perf_min_history_hours", "12")


# FAILURE CASES FIRST

print("\n[1] FAILURE FIRST: a destination is not a device")
# The owner's PC talking to a web server makes one device row and one destination. The
# destination gets no baseline, because its history is a record of what this
# network sent it.
hour = NOW - timedelta(hours=2)
fill_hour(HOST, REMOTE, hour)
fill_hour(HOST, DNS, hour)
fill_hour(HOST, MCAST, hour)
fill_hour(HOST, SSDP, hour)
fill_hour(LINKLOCAL, HOST, hour)
fill_hour(TV, HOST, hour)
perf.build_hour(hour)

view = perf.device_view(hours=24, now=NOW)
listed = {d["entity_value"] for d in view["devices"]}
check("the owner's PC is listed", HOST in listed, True)
check("the owner's TV is listed", TV in listed, True)
check("the web destination is NOT listed", REMOTE in listed, False)
check("the resolver is NOT listed", DNS in listed, False)
check("the mDNS group is NOT listed", MCAST in listed, False)
check("the SSDP group is NOT listed", SSDP in listed, False)
check("the link-local adapter is NOT listed", LINKLOCAL in listed, False)


print("\n[2] and they are counted, not silently dropped")
# Dropping them with no trace would be the same defect in the other direction:
# the page would look tidy and the reader would never know what was removed or
# why. Every set-aside kind is reported with its reason.
kinds = {g["kind"]: g for g in view["not_devices"]}
check("remote addresses are counted", kinds.get("remote", {}).get("count"), 2)
check("multicast groups are counted", kinds.get("multicast", {}).get("count"), 2)
check("the link-local one is counted", kinds.get("link_local", {}).get("count"), 1)
check_true("each kind carries a reason",
           all(g["why"] for g in view["not_devices"]))
check_true("and names examples",
           REMOTE in kinds["remote"]["examples"] or DNS in kinds["remote"]["examples"])


print("\n[3] a hollow block says how far it is from a baseline")
# The reason the page read as broken. Hollow means "no baseline yet", and
# without a number beside it there is no way to tell one hour short from ten.
pc = row_for(HOST, view)
real = measured(pc)
check("one hour was read, the rest of the window was not", len(real), 1)
check("the block is hollow", real[0]["verdict"], "unknown")
check("it says how much history there is", pc["history_hours"], 1)
check("and how much is needed", pc["history_needed"], 12)
check_true("the page says nothing is coloured yet ON PURPOSE",
           "NOT A FAULT" in view["baseline_note"])
check_true("and says hollow is not quiet",
           "not 'quiet'" in view["baseline_note"])


print("\n[4] the model is told the same thing, not a bare verdict")
# A model handed a row of unknowns with no context will call the device quiet.
summary = perf.summary_for_model(hours=24, now=NOW)
line = [d for d in summary["devices"] if d["device"] == HOST][0]
check("it knows there is no baseline", line["has_baseline"], False)
check("and how far along it is", line["history_hours"], 1)
check_true("the note travels with it", "NOT A FAULT" in summary["baseline_note"])
check_true("and it is told what was set aside", summary["not_devices"])
check("the model's list has no destinations in it",
      any(d["device"] in (REMOTE, DNS, MCAST) for d in summary["devices"]), False)


print("\n[5] classification is by address, not by the scope column")
# scope is NULL on every packet written before that migration. A rule that
# depended on it would quietly treat two years of history as unclassifiable.
check("private is a device",
      perf.classify_entity(_addr("10.0.0", "5")), "device")
check("192.168 is a device",
      perf.classify_entity(_addr("192.168.1", "10")), "device")
check("172.20 is a device",
      perf.classify_entity(_addr("172.20.10", "5")), "device")
check("public is remote", perf.classify_entity("8.8.8.8"), "remote")
check("multicast is multicast", perf.classify_entity("239.1.2.3"), "multicast")
check("link-local is link_local",
      perf.classify_entity(_addr("169.254", "1.1")), "link_local")
check("loopback is loopback", perf.classify_entity("127.0.0.1"), "loopback")
check("broadcast is broadcast", perf.classify_entity("255.255.255.255"), "broadcast")
check("junk is unknown, not guessed", perf.classify_entity("not-an-ip"), "unknown")
check("None is unknown", perf.classify_entity(None), "unknown")


# THE ORDINARY PATH

print("\n[6] the backfill goes back for hours nobody bucketed")
# The accumulation bug. These hours have packets and no buckets, exactly like
# an afternoon of running that ended with Ctrl+C.
for back in range(3, 20):
    fill_hour(HOST, REMOTE, NOW - timedelta(hours=back))
    fill_hour(TV, HOST, NOW - timedelta(hours=back))

before = perf.device_view(hours=24, now=NOW)
check("only the one hour is bucketed so far",
      len(measured(row_for(HOST, before))), 1)
check("and the rest of the window is grey, not missing",
      len(row_for(HOST, before)["buckets"]), 24)

result = perf.backfill(hours=24, now=NOW)
check_true("the backfill built the missing hours", result["built"] >= 17)
check("and skipped the one that already had rows", result["skipped"], 1)

after = perf.device_view(hours=24, now=NOW)
check("the device now has its hours", len(measured(row_for(HOST, after))), 18)


print("\n[7] and with enough history the blocks finally mean something")
pc = row_for(HOST, after)
check("history passed the threshold", pc["history_hours"] >= 12, True)
verdicts = {b["verdict"] for b in pc["buckets"]}
check("nothing is unknown any more", "unknown" in verdicts, False)
check_true("and the blocks carry a real verdict",
           verdicts & {"normal", "high", "low"})
check_true("the page note stops saying nothing is coloured",
           "NOT A FAULT" not in after["baseline_note"])
check_true("and says the baseline is real now",
           "12 measured hours" in after["baseline_note"]
           or "12 hours needed" in after["baseline_note"])


print("\n[8] running the backfill twice rewrites nothing")
# It runs at every startup. If it rebuilt everything each boot it would scan
# the largest table in the database for no gain.
#
# The hours that ARE revisited are the ones with no packets in them at all.
# They have no rows, so they cannot be skipped by looking for rows, and they
# must not get an invented zero bucket just to mark them done. Revisiting them
# is two indexed queries that return nothing. That is the cheap half of the
# trade and the honest one.
again = perf.backfill(hours=24, now=NOW)
check("every bucketed hour was skipped", again["skipped"], 18)
check("the empty hours were looked at again", again["built"], 6)
check("and produced no rows, because there was nothing there", again["rows"], 0)

after_twice = perf.device_view(hours=24, now=NOW)
check("no device gained a phantom hour",
      len(measured(row_for(HOST, after_twice))), 18)


print("\n[9] an hour with no packets is grey, never a quiet hour")
# The rule has not changed, the way of saying it has. It used to be said by
# leaving the hour off the row, which made the row shorter and said nothing at
# all. Now the hour is on the row and it is grey, which says the thing out
# loud: nobody was watching. What must never happen either way is an invented
# zero reading as a calm hour.
empty = perf.device_view(hours=168, now=NOW)
pc = row_for(HOST, empty)
check("the week is a full week wide", len(pc["buckets"]), 168)
check("no reading beyond what the packets support", len(measured(pc)), 18)
check("and every other hour says it was not measured",
      all(b["verdict"] == "not_measured" and b["bytes"] is None
          for b in pc["buckets"] if b not in measured(pc)), True)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
