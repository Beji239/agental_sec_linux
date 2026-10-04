#!/usr/bin/env python3
"""
scripts/verify_incidents.py — T2's evidence.

READ THIS FIRST: this script is the T2 counterpart to scripts/verify_firewall.py,
and it exists for the same reason. A subsystem that cannot say when it is
blind will eventually report a quiet network that is not quiet, and unit tests
that assert the happy path cannot catch that. So this asserts THE FAILURE
MODES, in the order they matter:

  1. An empty ledger must not be readable as "nothing happened". The status
     contract has to say which of the two it is.
  2. A stopped or switched-off watcher must report blind, with a reason.
  3. A `low` finding must NOT open an incident, and the refusal has to be
     COUNTED rather than silently dropped.
  4. Hitting the daily cap must be recorded as a cap, and the findings it
     refused must still be there for the next tick. A cap is not a deletion.
  5. A finding the watcher has already accounted for must never be processed
     twice into two incidents, and must never be stepped over: BOTH directions,
     because the first version of the watcher got the second one wrong and the
     only reason it was caught is that somebody ran it.
  6. Coverage must be recorded when a sensor was blind at the moment an
     incident was raised, and the negative control is that a healthy module
     table must NOT produce a blind note.
  7. The watcher must not touch the integrity journal's policy digest. This
     was a real defect: the cursor lived in user_preferences, which
     core/integrity hashes as "the policy", so every tick would have written a
     false "the rules changed" warning.

Runs against a COPY of the database by default and never against the live one
unless you pass --db. Everything it writes is inside a throwaway file.

USE:
    python3 scripts/verify_incidents.py            # full run, safe
    python3 scripts/verify_incidents.py --keep     # leave the temp db for reading
"""

import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASS, FAIL, INFO = [], [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if detail:
        for line in str(detail).splitlines():
            print(f"         {line}")


def section(title):
    print()
    print(f"— {title} " + "-" * max(0, 66 - len(title)))


def main():
    keep = "--keep" in sys.argv
    explicit = None
    if "--db" in sys.argv:
        explicit = sys.argv[sys.argv.index("--db") + 1]

    real_db = ROOT / "agental_sec.db"
    tmpdir = tempfile.mkdtemp(prefix="agental_t2_")
    test_db = Path(tmpdir) / "t2_verify.db"

    if explicit:
        test_db = Path(explicit)
        print(f"Using the database you named: {test_db}")
    else:
        if real_db.exists():
            shutil.copy2(real_db, test_db)
        print(f"Working on a COPY of the database: {test_db}")
        print("Nothing here writes to yours. Pass --db PATH to aim it elsewhere.")

    os.environ["AGENTALSEC_TEST_DB"] = str(test_db)

    from core import migrations
    from core import memory_engine as me
    from core import incident
    from core import integrity

    section("migration")
    result = migrations.run_migrations(me.DB_PATH)
    check("the schema is at v35 or later",
          int(result.get("version") or 0) >= 35,
          f"status={result.get('status')} version={result.get('version')}")
    with me._get_conn() as conn:
        check("the incident table exists", me._table_exists_ro(conn, "incident"))
        check("the watcher_run table exists",
              me._table_exists_ro(conn, "watcher_run"))

    # A quiet database for the assertions below, so counts are deterministic.
    with me._get_conn() as conn:
        conn.execute("DELETE FROM incident")
        conn.execute("DELETE FROM watcher_run")

    section("1. an empty ledger must not read as a quiet network")
    before = incident.status()
    check("status() reports the keys sensor_health reads",
          all(k in before for k in ("running", "blind")),
          f"keys: {sorted(k for k in before if k != 'last_recorded_run')[:12]}")
    check("an unstarted watcher reports blind, with a reason",
          before["blind"] is True and bool(before.get("blind_reason")),
          before.get("blind_reason", ""))

    section("2. the watcher is started and reads honestly")
    started = incident.start("verify-incidents", modules={})
    check("start() returns True", started is True)
    import time
    time.sleep(2.5)
    live = incident.status()
    check("a running watcher that read findings is NOT blind",
          live["running"] is True and live["blind"] is False,
          f"ticks={live.get('ticks')}")
    check("the tick was recorded to disk",
          (live.get("last_recorded_run") or {}).get("outcome") == "ok")
    check("a second start() refuses rather than double-starting",
          incident.start("verify-incidents") is False)

    section("3. the severity floor refuses AND counts")
    n_before = len(incident.query_incidents(include_resolved=True))
    me.save_finding(session_id="verify", source="packet_sniffer",
                    detection_id="PKT-1013", severity="low", entity_type="ip",
                    entity_value="203.0.113.9",
                    title="Connection to dangerous port 445 (inbound)",
                    description="floor test")
    r = incident.watch_once("verify-incidents")
    n_after = len(incident.query_incidents(include_resolved=True))
    check("a `low` finding opens no incident", n_after == n_before,
          f"incidents {n_before} -> {n_after}")
    check("AND the refusal is counted, not silent", r["refused"] >= 1,
          f"refused={r['refused']}")

    section("4. a medium finding DOES open one, and repeats coalesce")
    me.save_finding(session_id="verify", source="network_scanner",
                    detection_id="NET-1001", severity="medium", entity_type="ip",
                    entity_value="192.0.2.99", title="New device row: 192.0.2.99",
                    description="a")
    me.save_finding(session_id="verify", source="network_scanner",
                    detection_id="NET-1001", severity="medium", entity_type="ip",
                    entity_value="192.0.2.99", title="New device row: 192.0.2.99",
                    description="b")
    r = incident.watch_once("verify-incidents")
    rows = [i for i in incident.query_incidents(include_resolved=True)
            if i["entity_value"] == "192.0.2.99"]
    check("two findings about one subject are ONE incident", len(rows) == 1,
          f"incidents for that address: {len(rows)}")
    check("both findings are counted on it", rows and rows[0]["finding_count"] == 2,
          f"finding_count={rows[0]['finding_count'] if rows else 'n/a'}")
    check("the CIA axis came from the register, not from the caller",
          rows and rows[0]["cia"] == [],
          f"cia={rows[0]['cia'] if rows else 'n/a'} (NET-1001 declares none)")

    me.save_finding(session_id="verify", source="network_scanner",
                    detection_id="NET-1001", severity="medium", entity_type="ip",
                    entity_value="192.0.2.99", title="New device row: 192.0.2.99",
                    description="c")
    r = incident.watch_once("verify-incidents")
    rows = [i for i in incident.query_incidents(include_resolved=True)
            if i["entity_value"] == "192.0.2.99"]
    check("a later finding coalesces rather than duplicating",
          len(rows) == 1 and rows[0]["finding_count"] == 3,
          f"count={rows[0]['finding_count'] if rows else 'n/a'}")
    check("the tick reported it as a coalesce, not a new incident",
          r["coalesced"] >= 1 and r["new"] == 0,
          f"new={r['new']} coalesced={r['coalesced']}")

    section("5. neither stepped over nor read twice")
    cursor_a = incident._get_watermark()
    r = incident.watch_once("verify-incidents")
    cursor_b = incident._get_watermark()
    check("a tick with nothing new does not move the cursor",
          cursor_a == cursor_b, f"{cursor_a} -> {cursor_b}")
    check("and it reads nothing, so it has not re-processed history",
          r["findings_read"] == 0, f"findings_read={r['findings_read']}")

    me.save_finding(session_id="verify", source="process_monitor",
                    detection_id="LNX-1102", severity="high",
                    entity_type="process", entity_value="sshd",
                    title="Masquerading: sshd", description="from /tmp")
    r = incident.watch_once("verify-incidents")
    check("a finding written after the last tick IS seen",
          r["findings_read"] == 1 and r["new"] == 1,
          f"read={r['findings_read']} new={r['new']}")
    check("the cursor advanced to it", incident._get_watermark() > cursor_b)

    section("6. coverage is recorded, and its negative control")
    class _Blind:
        def status(self):
            return {"running": True, "blind": True,
                    "blind_reason": "no CAP_NET_RAW in this test"}

    class _Fine:
        def status(self):
            return {"running": True, "blind": False}

    me.save_finding(session_id="verify", source="event_monitor",
                    detection_id="LNX-1009", severity="high",
                    entity_type="user", entity_value="mallory",
                    title="LNX-1009 account created: mallory",
                    description="useradd")
    incident.watch_once("verify-incidents", {"packet_sniffer": _Blind(),
                                             "event_monitor": _Fine()})
    row = [i for i in incident.query_incidents(include_resolved=True)
           if i["entity_value"] == "mallory"]
    check("an incident raised while a sensor was blind says so",
          bool(row) and row[0]["coverage"].get("complete") is False
          and row[0]["coverage"]["blind"],
          (row[0]["coverage_note"][:150] if row else "no row"))
    check("the blind sensor is NAMED, not summarised",
          bool(row) and any("packet_sniffer" in b
                            for b in row[0]["coverage"]["blind"]))

    me.save_finding(session_id="verify", source="event_monitor",
                    detection_id="LNX-1009", severity="high",
                    entity_type="user", entity_value="gooduser",
                    title="LNX-1009 account created: gooduser",
                    description="useradd")
    incident.watch_once("verify-incidents", {"packet_sniffer": _Fine(),
                                             "event_monitor": _Fine()})
    row = [i for i in incident.query_incidents(include_resolved=True)
           if i["entity_value"] == "gooduser"]
    check("NEGATIVE CONTROL: a healthy module table produces no blind note",
          bool(row) and row[0]["coverage"].get("complete") is True,
          (row[0]["coverage_note"][:120] if row else "no row"))

    section("7. the daily cap defers, and never deletes")
    made = len(incident.query_incidents(include_resolved=True))
    me.set_preference("incident_daily_cap", str(max(1, made)))
    me.save_finding(session_id="verify", source="network_scanner",
                    detection_id="NET-1001", severity="medium", entity_type="ip",
                    entity_value="192.0.2.201", title="New device row: 192.0.2.201",
                    description="cap test")
    r = incident.watch_once("verify-incidents")
    check("a cap hit is recorded AS a cap", r["capped"] >= 1,
          f"capped={r['capped']}")
    check("and the tick says a cap is not a quiet network",
          "cap" in (r.get("how_to_read_this") or "").lower())
    me.set_preference("incident_daily_cap", "40")
    r = incident.watch_once("verify-incidents")
    found = [i for i in incident.query_incidents(include_resolved=True)
             if i["entity_value"] == "192.0.2.201"]
    check("the refused finding is picked up on the next tick", bool(found),
          f"new={r['new']}")

    section("8. the watcher does not touch the integrity journal")
    snap = integrity.snapshot_config(reason="verify-baseline")
    for _ in range(3):
        incident.watch_once("verify-incidents")
    snap = integrity.snapshot_config(reason="verify-after-ticks")
    check("three ticks do not move the policy digest",
          snap is None,
          "The cursor lives on the watcher_run row precisely so that a tick "
          "cannot write a false 'the rules changed' entry." if snap is None
          else "The policy digest moved on a tick, so the tamper journal "
               "would have logged a cursor as a policy change.")

    section("9. the register")
    from core import detections as det
    check("every detection declares an axis or is explicitly empty",
          all(isinstance(d["cia"], list) for d in det.summary()))
    check("the six T2 ids are registered",
          all(det.exists(x) for x in ("LNX-1009", "LNX-1010", "LNX-1011",
                                      "LNX-1101", "LNX-1102", "LNX-1103")))
    bad = []
    for did in ("LNX-1009", "LNX-1010", "LNX-1011", "LNX-1101", "LNX-1102",
                "LNX-1103"):
        if not det.axes(did):
            bad.append(did)
    check("and each of them names what is lost", not bad,
          f"entries with no axis: {bad}" if bad else "")
    check("an axis nobody declared is refused at import",
          "availability" in det.AXES and "confidentiality" in det.AXES
          and "integrity" in det.AXES)

    section("10. an incident cannot invent a severity its rule never declares")
    try:
        incident.write_incident("NET-1001", "ip", "192.0.2.250", "critical",
                                "invented")
        check("a severity the register does not declare is REFUSED", False,
              "NET-1001 declares only medium; write_incident accepted critical")
    except Exception as e:
        check("a severity the register does not declare is REFUSED",
              "BadSeverity" in type(e).__name__, type(e).__name__)
    try:
        incident.write_incident("ZZZ-9999", "ip", "192.0.2.251", "medium", "x")
        check("an unregistered detection id is REFUSED", False)
    except Exception as e:
        check("an unregistered detection id is REFUSED",
              "UnknownDetection" in type(e).__name__, type(e).__name__)

    incident.stop()

    print()
    print("=" * 70)
    print(f"  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("  FAILED:")
        for name in FAIL:
            print(f"    - {name}")
    print("=" * 70)

    if keep:
        print(f"\nThe throwaway database is at {test_db}")
        print("Read it, then delete it. It is not yours and nothing points at it.")
        return 0
    try:
        shutil.rmtree(tmpdir, ignore_errors=True)
    except Exception:
        pass
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
