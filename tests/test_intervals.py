"""
tests/test_intervals.py, how regularly one address contacts another.

core/intervals turns packets into contacts and measures the spacing between
them, inside one capture session only. Built on an in-memory table shaped
like packets, so it needs no database file.

Run it directly: python tests/test_intervals.py
"""
import pathlib
import sqlite3
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import intervals as iv                        # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def ts(seconds):
    """A SQLite style UTC string, seconds after a fixed start."""
    from datetime import datetime, timedelta
    t = datetime(2026, 10, 1, 0, 0, 0) + timedelta(seconds=seconds)
    return t.strftime("%Y-%m-%d %H:%M:%S")


def db(rows):
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE packets (src_ip TEXT, dst_ip TEXT, "
                 "captured_at TEXT, session_id TEXT)")
    conn.executemany("INSERT INTO packets VALUES (?,?,?,?)", rows)
    return conn


SRC = "192.0.2.10"

print("[1] timestamps in every shape the store writes")
base = iv._parse("2026-10-01 00:00:00")
check("naive SQLite text is UTC", base, 1790812800.0)
check("with a T and a Z", iv._parse("2026-10-01T00:00:00Z"), base)
check("with +00:00", iv._parse("2026-10-01T00:00:00+00:00"), base)
check("with fractions", iv._parse("2026-10-01 00:00:00.250"), base + 0.25)
check("a number passes through", iv._parse(12), 12.0)
check("None stays None", iv._parse(None), None)
check("junk is None, not a guess", iv._parse("yesterday"), None)

print("\n[2] packets become contacts, gaps stay inside a session")
rows = [(0, "s1"), (5, "s1"), (30, "s1"), (200, "s1"), (230, "s1"),
        (240, "s2")]
contacts = iv._collapse(rows)
check("a burst under a minute is one contact, a new session starts one",
      contacts, [(0, "s1"), (200, "s1"), (240, "s2")])
check("the gap across sessions is dropped, not measured",
      iv._gaps_within_sessions(contacts), [200])
st = iv._stats([100, 100, 100])
check("identical gaps have no spread", (st["mean_seconds"], st["cv"]),
      (100.0, 0.0))
check("one gap has a spread of 0", iv._stats([42])["stddev_seconds"], 0.0)

print("\n[3] a beacon on a timer comes out regular")
beacon = [(SRC, "198.51.100.7", ts(i * 600), "s1") for i in range(10)]
browse = [(SRC, "203.0.113.9", ts(t), "s1")
          for t in (0, 90, 1500, 1700, 4000, 4300, 9000, 9200)]
noise = [(SRC, "224.0.0.251", ts(i * 300), "s1") for i in range(20)]
out = iv.contact_intervals(db(beacon + browse + noise), SRC)
mr = out["most_regular"]
check("the steadiest destination is the beacon",
      (mr["destination"], mr["mean_seconds"], mr["cv"]),
      ("198.51.100.7", 600.0, 0.0))
check("browsing is measured too, and is far less regular",
      [d["destination"] for d in out["destinations"]],
      ["198.51.100.7", "203.0.113.9"])
check("multicast chatter is never measured",
      "224.0.0.251" in [d["destination"] for d in out["destinations"]], False)
check("the description gives the rhythm and no verdict",
      iv.describe(mr).startswith("198.51.100.7: 10 contacts, every 10.0 "
                                 "minutes") and "not a finding" in
      iv.describe(mr), True)

print("\n[4] too little evidence reports nothing")
few = [(SRC, "198.51.100.8", ts(i * 600), "s1") for i in range(4)]
check("four contacts are not enough",
      iv.contact_intervals(db(few), SRC)["most_regular"], None)
split = [(SRC, "198.51.100.9", ts(i * 600), f"s{i}") for i in range(8)]
check("eight contacts, each in its own session, give no gaps to use",
      iv.contact_intervals(db(split), SRC)["destinations"], [])
check("since cuts the window",
      iv.contact_intervals(db(beacon), SRC, since=ts(5 * 600))
      ["most_regular"], None)
check("nothing to measure says so", iv.describe(None),
      "no destination contacted often enough to measure")

print("\n[5] units and failure")
check("hours", "every 6.0 hours" in iv.describe(
    {"destination": "x", "contacts": 7, "mean_seconds": 21600, "cv": 0.1}),
      True)
check("seconds", "every 30.0 seconds" in iv.describe(
    {"destination": "x", "contacts": 7, "mean_seconds": 30, "cv": 0.1}),
      True)
broken = sqlite3.connect(":memory:")
check("a missing table never raises into the rollup",
      iv.contact_intervals(broken, SRC),
      {"destinations": [], "most_regular": None})

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
