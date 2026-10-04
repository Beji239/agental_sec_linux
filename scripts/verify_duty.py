#!/usr/bin/env python3
"""
scripts/verify_duty.py — T4's evidence.

READ THIS FIRST: this is the T4 counterpart to verify_incidents.py and
verify_actions.py, and it exists for the same reason. A component that spends
money unattended and is ALLOWED TO DO NOTHING will eventually report a quiet
network that is not quiet, or spend past a ceiling nobody was watching. Unit
tests that assert the happy path cannot catch either. So this asserts THE
FAILURE MODES, in the order they matter:

  1. THE BUDGETS ARE HARD STOPS. At the ceiling, a tick examines NOTHING and
     records `budget`. It does not examine a cheap one and it does not start
     and give up. Asserted by putting the spend over the ceiling in the
     database and calling a real tick — the model must not be called at all.

  2. `idle` AND `budget` ARE DIFFERENT FACTS and are never the same row. One
     is "I looked and there was nothing"; the other is "I was stopped before
     I looked at anything". The sentences are asserted to differ.

  3. A STOPPED LOOP IS NOT AN EMPTY ONE. status() reports blind with a reason
     when it is not running, and the reason says which of the two it is.

  4. EVERY TICK LEAVES A RECORD, including the ones that did nothing. There is
     no exit path from run_once that writes no duty_run row, and this asserts
     that by driving every path it has.

  5. A `no_action` VERDICT WITH NO `saw` IS REFUSED. "Nothing needed doing"
     with nothing behind it is an absence; the writer will not store it.

  6. THE EMERGENCY CHECK CANNOT SEE WHAT IT CANNOT SEE. With the capture blind
     it returns `blind` with a reason, NOT a quiet negative. And with a
     healthy capture but no flood it returns a negative that carries the
     busiest peer, so the negative is a measurement.

  7. THE LOOP CANNOT REACH REMEDIATION DIRECTLY. The unattended turn refuses a
     gated tool with a sentence and records the refusal; the way to propose an
     action is file_action_request.

  8. IT DOES NOT WRITE FINDINGS AND IT DOES NOT TOUCH THE CHAT HISTORY.

  9. THE PICKER TAKES TWO FINDINGS FROM DIFFERENT TOOLS. Two rows from one
     sensor is one fact repeated; the owner's instruction was two different
     tools.

  10. THE MODEL'S OWN SPEND IS WHAT FILLS THE CEILING. A run row's
      tokens_spent is a provider-reported number when the provider sent one
      and is MARKED ESTIMATED when it did not.

IT MAKES NO MODEL CALLS BY DEFAULT. The model is stubbed (see --live to use
the real one), because a verification script that costs money every time it is
run is a script that stops being run, and because the failure modes above are
about THIS code rather than about the provider.

Runs against a COPY of the database by default and never against the live one
unless you pass --db. Everything it writes is inside a throwaway file.

USE:
    python3 scripts/verify_duty.py             # full run, no model calls
    python3 scripts/verify_duty.py --live      # plus one REAL model call
    python3 scripts/verify_duty.py --keep      # leave the temp db
"""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASS, FAIL = [], []


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
    live = "--live" in sys.argv
    explicit = None
    if "--db" in sys.argv:
        explicit = sys.argv[sys.argv.index("--db") + 1]

    real_db = ROOT / "agental_sec.db"
    tmpdir = tempfile.mkdtemp(prefix="agental_t4_")
    test_db = Path(tmpdir) / "t4_verify.db"

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
    from core import duty
    from core import agent_loop
    from core import tool_registry as tr
    from core import settings, secret_store

    cfg = json.loads(settings.CONFIG_PATH.read_text())
    resolved = secret_store.resolve(cfg, ROOT)
    # THE MODEL IS CONFIGURED BUT STUBBED, so the "no model call was made"
    # assertions below are meaningful: run_unattended would happily make one.
    agent_loop.init_agent(cfg, api_key=resolved["api_key"])
    tr.init_registry("verify-duty", {})

    model_calls = {"n": 0}

    def stub_model(answer):
        """Replace the unattended turn with a recording stub."""
        def _fake(prompt, session_id, allowlist=None, extra_system=""):
            model_calls["n"] += 1
            model_calls["allowlist"] = allowlist
            model_calls["prompt"] = prompt
            return {
                "answers": [json.dumps(answer)] if isinstance(answer, dict)
                           else [answer],
                "tool_calls": [], "refused_calls": [],
                "usage": {"calls": 2, "prompt_tokens": 1234,
                          "completion_tokens": 56, "total_tokens": 1290,
                          "estimated": False},
                "error": None,
            }
        duty._run_unattended = _fake

    real_run_unattended = duty._run_unattended

    section("migration")
    result = migrations.run_migrations(me.DB_PATH)
    check("the schema is at v37 or later",
          int(result.get("version") or 0) >= 37,
          f"status={result.get('status')} version={result.get('version')}")
    with me._get_conn() as conn:
        check("the duty_run table exists",
              me._table_exists_ro(conn, "duty_run"))
        check("the duty_report table exists",
              me._table_exists_ro(conn, "duty_report"))

    with me._get_conn() as conn:
        conn.execute("DELETE FROM duty_run")
        conn.execute("DELETE FROM duty_report")

    section("1. a stopped loop is not an empty one")
    me.set_preference("duty_daily_token_ceiling", "2000000")
    before = duty.status()
    check("status() reports the keys sensor_health reads",
          all(k in before for k in ("running", "blind")),
          f"keys: {sorted(k for k in before)[:10]}")
    check("an unstarted loop reports blind, with a reason",
          before["blind"] is True and bool(before.get("blind_reason")),
          before.get("blind_reason", ""))
    check("and the reason says nothing is investigating",
          "nothing is investigating" in
          (before.get("blind_reason") or "").lower())

    section("2. the budgets are HARD STOPS, checked before anything is picked")
    me.set_preference("duty_daily_token_ceiling", "10")
    with me._get_conn() as conn:
        conn.execute("""
            INSERT INTO duty_run (session_id, ran_at, ended_at, trigger,
                outcome, tokens_spent, tokens_estimated, model_calls)
            VALUES ('verify', datetime('now'), datetime('now'), 'regular',
                    'reported', 5000, 0, 3)
        """)
    stub_model({"hypothesis": "should never run", "evidence": "n/a",
                "verdict": "no_action", "saw": "n/a", "report": "n/a"})
    calls_before = model_calls["n"]
    out = duty.run_once("verify-duty", "manual", modules={})
    check("a tick over the token ceiling is refused", out["outcome"] == "budget",
          f"outcome={out.get('outcome')} reasons={out.get('budget', {}).get('reasons')}")
    check("AND THE MODEL WAS NOT CALLED AT ALL",
          model_calls["n"] == calls_before,
          f"model calls before={calls_before} after={model_calls['n']}")
    with me._get_readonly_conn() as conn:
        row = conn.execute("SELECT outcome, detail FROM duty_run "
                           "ORDER BY id DESC LIMIT 1").fetchone()
    check("the refusal is RECORDED as `budget`, not as idle",
          row["outcome"] == "budget", f"recorded outcome={row['outcome']}")
    check("and the record says nothing was examined",
          "NOTHING WAS EXAMINED" in (row["detail"] or "").upper())
    check("budget_state() agrees with the tick that acted on it",
          duty.budget_state()["may_spend"] is False,
          "; ".join(duty.budget_state()["reasons"]))
    me.set_preference("duty_daily_token_ceiling", "2000000")
    check("and the loop may spend again once the window is clear",
          duty.budget_state()["may_spend"] is True)

    section("3. the hourly cap, separately from the token ceiling")
    me.set_preference("duty_max_investigations_per_hour", "1")
    with me._get_conn() as conn:
        conn.execute("DELETE FROM duty_run")
        for _ in range(2):
            conn.execute("""
                INSERT INTO duty_run (session_id, ran_at, ended_at, trigger,
                    outcome, tokens_spent, model_calls)
                VALUES ('verify', datetime('now'), datetime('now'),
                        'regular', 'investigated', 100, 1)
            """)
    out = duty.run_once("verify-duty", "manual", modules={})
    check("the hourly cap refuses when it is reached",
          out["outcome"] == "budget",
          f"outcome={out.get('outcome')} reasons={out.get('budget', {}).get('reasons')}")
    check("and the reason NAMES the hourly cap, not the token ceiling",
          any("this hour" in r for r in out.get("budget", {}).get("reasons", [])),
          str(out.get("budget", {}).get("reasons")))
    me.set_preference("duty_max_investigations_per_hour", "3")

    section("4. every tick leaves a record, including the ones that do nothing")
    with me._get_conn() as conn:
        conn.execute("DELETE FROM duty_run")
        conn.execute("DELETE FROM duty_report")
        conn.execute("UPDATE incident SET status = 'triaged'")
        conn.execute("UPDATE findings SET dismissed = 1")
    stub_model({"hypothesis": "h", "evidence": "e", "verdict": "no_action",
                "saw": "looked at the ledger and the findings table",
                "report": "nothing to do"})
    out = duty.run_once("verify-duty", "manual", modules={})
    runs = duty.query_runs(limit=10)
    check("a tick with nothing eligible ends `idle`", out["outcome"] == "idle",
          f"outcome={out.get('outcome')} reason={out.get('reason')}")
    check("AND it still wrote a duty_run row", len(runs) >= 1,
          f"run rows: {len(runs)}")
    check("the idle record says what it looked for",
          "nothing eligible" in (runs[0].get("detail") or "").lower(),
          runs[0].get("detail"))

    section("5. idle and budget are different sentences")
    idle_detail = runs[0].get("detail") or ""
    with me._get_conn() as conn:
        conn.execute("""
            INSERT INTO duty_run (session_id, ran_at, ended_at, trigger,
                outcome, tokens_spent, detail)
            VALUES ('verify', datetime('now'), datetime('now'), 'regular',
                    'budget', 0, 'Refused by a budget: x. NOTHING WAS EXAMINED.')
        """)
    budget_detail = duty.query_runs(limit=1)[0].get("detail") or ""
    check("idle does not claim a budget stopped it",
          "budget" not in idle_detail.lower())
    check("budget does not claim it looked",
          "nothing eligible" not in budget_detail.lower()
          and "NOTHING WAS EXAMINED" in budget_detail)
    with me._get_conn() as conn:
        conn.execute("DELETE FROM duty_run")

    section("6. a no_action verdict with no `saw` is REFUSED")
    try:
        duty.write_report("verify", "regular", "manual", "body text",
                          verdict="no_action", saw=None, coverage={})
        check("a no_action report with no `saw` is refused", False,
              "write_report accepted a no_action verdict with saw=None")
    except duty.BadDutyInput as e:
        check("a no_action report with no `saw` is refused", True, str(e)[:120])
    try:
        duty.write_report("verify", "regular", "manual", "",
                          verdict="benign", coverage={})
        check("an empty report body is refused", False)
    except duty.BadDutyInput:
        check("an empty report body is refused", True)
    try:
        duty.write_report("verify", "regular", "manual", "b", verdict="benign",
                          action_taken="killed", coverage={})
        check("an invented action_taken is refused", False)
    except duty.BadDutyInput:
        check("an invented action_taken is refused", True)
    # The negative control: a good report IS accepted.
    rep = duty.write_report("verify", "regular", "manual",
                            "the body, in the app's voice",
                            verdict="benign", saw="checked X and Y",
                            coverage={"complete": True,
                                      "note": "all sensors could see"})
    check("NEGATIVE CONTROL: a well-formed report is accepted",
          bool(rep.get("report_id")))
    with me._get_conn() as conn:
        conn.execute("DELETE FROM duty_report")

    section("7. the emergency check cannot see what it cannot see")
    class _Blind:
        def status(self):
            return {"running": True, "blind": True,
                    "blind_reason": "no CAP_NET_RAW in this test"}

    ec = duty.emergency_check({"packet_sniffer": _Blind()})
    check("a blind capture returns blind, with a reason",
          ec.get("blind") is True and bool(ec.get("blind_reason")),
          ec.get("blind_reason", "")[:160])
    check("and it does NOT return a quiet negative",
          ec.get("emergency") is False and "reason" not in ec)
    check("the blind answer names the sensor that could not see",
          "packet_sniffer" in (ec.get("blind_reason") or ""))

    # THE MEASUREMENT HALF, DRIVEN ON ITS OWN. The health gate above cannot be
    # satisfied unelevated on this host — AF_PACKET genuinely cannot be
    # opened, so a healthy capture is not constructible here — and a test that
    # needs the machine to be privileged to check its arithmetic would be
    # skipped on the machine it matters on. So the two halves are asserted
    # separately, which is also the honest description: "could I look" and
    # "what did I see" fail in different ways.
    #
    # KNOWN HARNESS LIMITATION, found by running it 2026-09-23, NOT a
    # defect in the app. The next check and the one after it assume the
    # `packets` table is EMPTY: the negative control wants a null peer over a
    # window with no traffic, and the positive path wants only its own
    # synthetic 203.0.113.66 row to be above the threshold. This script copies
    # the LIVE database, and on 2026-09-23 that file held 362,085 real packet
    # rows, so the "365 days ago" window is anything but empty and the
    # synthetic row is nowhere near the busiest peer. Both checks then fail
    # while the app is behaving correctly.
    #
    # MEASURED BOTH WAYS to be sure: against a consistent copy of the live
    # database, 84/2; against the same copy with `packets` emptied, 86/0. So
    # the app's arithmetic is right and the FIXTURE is what needs a decision
    # (truncate packets, or scope the window). Not fixed here because it is a
    # harness question, not a tamper-seal one, and quietly rewriting another
    # subsystem's evidence script is how a verifier stops meaning anything.
    own = duty._own_addresses()
    measured = duty._emergency_measure(own, duty._sql_ts(
        duty._now() - __import__("datetime").timedelta(hours=48)))
    check("the measurement runs against the real packets table",
          "thresholds" in measured and "since" in measured,
          f"window={measured['window_minutes']}m")
    check("a NEGATIVE carries the busiest peer of each kind, so the negative "
          "is a measurement rather than an absence",
          all(k in measured for k in
              ("busiest_inbound_peer", "busiest_udp_peer",
               "busiest_two_way_peer")),
          f"busiest inbound={measured['busiest_inbound_peer']}, "
          f"udp={measured['busiest_udp_peer']}")
    # ...and the negative control: the measurement is over a window with NO
    # traffic in it, which must produce an explicitly empty reading rather than
    # a claim.
    old = duty._emergency_measure(own, duty._sql_ts(
        duty._now() - __import__("datetime").timedelta(days=365)))
    check("NEGATIVE CONTROL: a window with no traffic reports null peers, "
          "not zeroes dressed up as facts",
          old["busiest_inbound_peer"] is None,
          f"over an empty window: {old['busiest_inbound_peer']}")
    check("and the thresholds it is comparing against are named in the result",
          set(measured["thresholds"]) == {"inbound_packets", "udp_packets",
                                          "two_way_packets"},
          str(measured["thresholds"]))

    # THE POSITIVE PATH, asserted with real rows: a peer above the UDP
    # threshold must trip it. Written into the real (copied) packets table.
    with me._get_conn() as conn:
        conn.execute("""
            INSERT INTO packets (session_id, captured_at, src_ip, dst_ip,
                                 protocol, direction, packet_size, sensor_id)
            SELECT 'verify-duty', datetime('now'), '203.0.113.66', '192.0.2.207',
                   'udp', 'inbound', 60, sensor_id
              FROM (SELECT sensor_id FROM packets LIMIT 1)
        """)
        for _ in range(duty.EMERGENCY_UDP_PACKETS + 5):
            conn.execute("""
                INSERT INTO packets (session_id, captured_at, src_ip, dst_ip,
                                     protocol, direction, packet_size)
                VALUES ('verify-duty', datetime('now'), '203.0.113.66',
                        '192.0.2.207', 'udp', 'inbound', 60)
            """)
    # A healthy sniffer, so the POSITIVE path is genuinely exercised. The
    # capability half of the health gate is stubbed for this one assertion and
    # NOT bypassed in the production code: AF_PACKET really cannot be opened
    # unelevated on this host, so without stubbing, the positive path is
    # unreachable here and the arithmetic below would never be tested on the
    # machine it matters on. The stub touches the health INPUT, not the check.
    class _Healthy:
        def status(self):
            return {"running": True, "blind": False, "packets_this_run": 999}

    from core import sensor_health as _sh
    real_warnings = _sh.warnings_for
    _sh.warnings_for = lambda tool, modules: []
    try:
        pos = duty.emergency_check({"packet_sniffer": _Healthy()})
    finally:
        _sh.warnings_for = real_warnings
    if pos.get("blind"):
        check("a healthy capture returns a measured answer, not blind", False,
              pos.get("blind_reason", "")[:200])
    else:
        check("a healthy capture returns a measured answer, not blind", True)
        check("a UDP flood from one peer TRIPS the emergency trigger",
              pos.get("emergency") is True,
              pos.get("reason", "")[:200])
        check("and the trigger names the peer and the count",
              "203.0.113.66" in (pos.get("reason") or ""),
              pos.get("reason", "")[:200])

        # THE CAPABILITY HALF IS ALSO REAL, and this asserts it directly rather
        # than through the stub above: on THIS host, unelevated, the health gate
        # genuinely reports the capture as unmeasurable. If somebody grants the
        # capability later this check will fail, and that is correct — it is a
        # statement about this machine that deserves to be re-read rather than
        # silently inherited.
        real_problems = real_warnings("query_packets", {"packet_sniffer": _Healthy()})
        print(f"  [INFO] capability check on this host: "
              f"{str(real_problems)[:180] or 'no problems reported'}")

    section("8. the unattended turn refuses a gated tool")
    # The REAL run_unattended is restored for this one, because the refusal is
    # in agent_loop and a stub would prove nothing about it.
    duty._run_unattended = real_run_unattended
    src = Path(agent_loop.__file__).read_text(encoding="utf-8")
    check("the unattended path checks requires_permission before executing",
          "requires_permission(name, params)" in src,
          "the belt under the allowlist")
    check("and it refuses with a sentence pointing at file_action_request",
          "unattended" in src and "file_action_request" in src
          and "approval-gated" in src,
          "the refusal sentence names the alternative")
    allow = set(duty._tool_allowlist())
    gated = [n for n in ("kill_process", "block_port", "block_device",
                         "quarantine_file", "unblock_device", "restore_file",
                         "dismiss_entity", "run_port_scan", "scan_network")
             if n in allow]
    check("NO gated tool is in the unattended allowlist", not gated,
          f"gated tools present: {gated}" if gated else "")
    check("file_action_request IS in it — that is how the loop proposes",
          "file_action_request" in allow)
    check("and write_prediction is, so what it concludes can be graded",
          "write_prediction" in allow)
    missing = [n for n in duty.DUTY_TOOL_ALLOWLIST if n not in allow]
    check("every name in the allowlist answers to a real tool", not missing,
          f"dropped: {missing}" if missing else "")

    section("9. it does not write findings and does not touch chat history")
    with me._get_conn() as conn:
        conn.execute("DELETE FROM duty_run")
        conn.execute("DELETE FROM duty_report")
    findings_before = None
    with me._get_conn() as conn:
        findings_before = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    history_before = list(agent_loop._history)
    stub_model({"hypothesis": "h", "evidence": "e", "verdict": "benign",
                "saw": "", "report": "a report body"})
    duty.run_once("verify-duty", "manual", modules={})
    duty._run_unattended = real_run_unattended
    with me._get_conn() as conn:
        findings_after = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    check("a duty run writes NO findings", findings_before == findings_after,
          f"findings {findings_before} -> {findings_after}")
    check("a duty run does NOT append to the chat history",
          agent_loop._history == history_before,
          f"history went {len(history_before)} -> {len(agent_loop._history)}")

    section("10. the picker takes two findings from different tools")
    with me._get_conn() as conn:
        conn.execute("UPDATE findings SET dismissed = 0")
    picked = duty.pick_findings(2)
    sources = [p.get("source") for p in picked]
    check("it picks at most two", len(picked) <= 2, f"picked {len(picked)}")
    check("they come from DIFFERENT tools", len(set(sources)) == len(sources),
          f"sources: {sources}")
    with me._get_conn() as conn:
        conn.execute("UPDATE findings SET dismissed = 1")
    check("dismissed findings are not picked",
          all(f.get("dismissed") in (0, None)
              for f in duty.pick_findings(2)) or duty.pick_findings(2) == [])

    section("11. the model's spend is what fills the ceiling")
    with me._get_conn() as conn:
        conn.execute("DELETE FROM duty_run")
        conn.execute("""
            INSERT INTO duty_run (session_id, ran_at, ended_at, trigger,
                outcome, tokens_prompt, tokens_completion, tokens_spent,
                tokens_estimated, model_calls)
            VALUES ('verify', datetime('now'), datetime('now'), 'regular',
                    'reported', 1000, 500, 1500, 1, 2)
        """)
    spend = duty.spend_in_window(24)
    check("the ceiling is summed from the run rows themselves",
          spend["spent"] == 1500, json.dumps(spend))
    check("an estimated spend is FLAGGED as estimated",
          spend["estimated_rows"] == 1 and
          duty.budget_state()["spend_is_estimated"] is True)

    section("12. the schedule is the owner's local hours")
    sched = duty._next_regular_moment()
    check("four regular wake-ups are configured", len(sched["hours"]) == 4,
          f"hours={sched['hours']}")
    check("they are the local hours, not UTC",
          sched["local_hour"] == __import__("datetime").datetime.now().hour,
          f"reported local hour {sched['local_hour']}")
    check("a next moment is always named", sched.get("next_hour") is not None)

    # THE GATE ITSELF, WHICH IS THE DEFECT THE OWNER FOUND.
    #
    # "the agent was supposed to run only 4 to max 5 times a day, its
    # constantly running now." Measured on the owner's live database before this
    # section existed: 62 duty_run rows in 2h10m, eight runs that called the
    # model for 2,216,938 tokens, and a `budget` row EVERY SIXTY SECONDS once
    # the daily ceiling was crossed. `_next_regular_moment()` had the right
    # answer and NOTHING ASKED IT — the daemon called run_once every minute.
    #
    # So the assertions below are about whether a POLL becomes a WAKE-UP, and
    # they drive the real _tick_once with the clock passed in, on a copy of
    # the database. The model is stubbed and its call count is the evidence:
    # "no wake-up happened" has to mean THE MODEL WAS NOT CALLED, not merely
    # that a dict had the word not_due in it.
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    local_zone = _dt.now().astimezone().tzinfo

    def _at_local(hour, minute=0):
        """A UTC datetime whose LOCAL rendering is today at hour:minute."""
        local = _dt.now().astimezone().replace(hour=hour, minute=minute,
                                               second=0, microsecond=0)
        return local.astimezone(_tz.utc)

    hours = duty._wake_hours()
    off_hour = next(h for h in range(24) if h not in hours)

    stub_model({"hypothesis": "h", "evidence": "e", "verdict": "benign",
                "saw": "", "report": "a body"})

    with me._get_conn() as conn:
        conn.execute("DELETE FROM duty_run")
        conn.execute("DELETE FROM duty_report")
        conn.execute("UPDATE incident SET status = 'triaged'")
        conn.execute("UPDATE findings SET dismissed = 1")
    calls_before = model_calls["n"]
    out = duty._tick_once("verify-gate", modules={}, now=_at_local(off_hour))
    check("A POLL IN AN UNSCHEDULED HOUR IS NOT A WAKE-UP",
          out["outcome"] == "not_due",
          f"outcome={out.get('outcome')} hour={off_hour}")
    check("and it called the model ZERO times",
          model_calls["n"] == calls_before,
          f"model calls before={calls_before} after={model_calls['n']}")
    check("and it wrote NO run row — the table is the record of wakes",
          duty.query_runs(limit=5) == [],
          f"rows: {len(duty.query_runs(limit=5))}")

    with me._get_conn() as conn:
        conn.execute("UPDATE incident SET status = 'triaged'")
        conn.execute("UPDATE findings SET dismissed = 1")
    out = duty._tick_once("verify-gate", modules={}, now=_at_local(hours[0]))
    check("A POLL IN A SCHEDULED HOUR IS a wake-up",
          out.get("outcome") not in (None, "not_due"),
          f"outcome={out.get('outcome')} hour={hours[0]}")
    check("and it wrote exactly ONE run row",
          len(duty.query_runs(limit=5)) == 1,
          f"rows={len(duty.query_runs(limit=5))}")
    first_calls = model_calls["n"]

    out = duty._tick_once("verify-gate", modules={}, now=_at_local(
        hours[0], minute=5))
    check("the SAME HOUR does not wake it again",
          out["outcome"] == "not_due",
          f"outcome={out.get('outcome')} at :05 of hour {hours[0]}")
    check("and the model was not called a second time for that hour",
          model_calls["n"] == first_calls,
          f"model calls {first_calls} -> {model_calls['n']}")
    check("ONE WAKE PER HOUR, not one per poll",
          len(duty.query_runs(limit=5)) == 1,
          f"rows after two polls in one hour: "
          f"{len(duty.query_runs(limit=5))}")

    # THE NEGATIVE CONTROL FOR THE ROW COUNT: a DIFFERENT scheduled hour must
    # wake again. Without this, an implementation that only ever ran once a
    # session would pass everything above.
    with me._get_conn() as conn:
        conn.execute("UPDATE incident SET status = 'triaged'")
        conn.execute("UPDATE findings SET dismissed = 1")
    out = duty._tick_once("verify-gate", modules={},
                          now=_at_local(hours[1] if len(hours) > 1
                                        else hours[0]))
    check("NEGATIVE CONTROL: the NEXT scheduled hour wakes it again",
          out.get("outcome") not in (None, "not_due"),
          f"outcome={out.get('outcome')} hour={hours[1]}")

    # AND A REFUSED WAKE STILL COUNTS AS THE HOUR'S ATTEMPT. Otherwise the
    # budget refusal above would re-fire every sixty seconds, which is what
    # the owner's database showed: one `budget` row per minute for a whole hour.
    with me._get_conn() as conn:
        conn.execute("DELETE FROM duty_run")
        conn.execute("""INSERT INTO duty_run (session_id, ran_at, ended_at,
                trigger, outcome, tokens_spent, model_calls)
            VALUES ('verify-gate', ?, ?, 'regular', 'budget', 0, 0)""",
            (duty._sql_ts(_at_local(hours[0])), duty._sql_ts(_at_local(hours[0]))))
    sched = duty._next_regular_moment(now=_at_local(hours[0], minute=20))
    check("an hour that was ATTEMPTED is not due again, whatever it decided",
          sched["due_now"] is False,
          f"due_now={sched['due_now']} with a row already written this hour")

    # THE HOUR BOUNDARY IS EXACT. A run written at :00:00 must belong to that
    # hour; the first version's cutoff landed seconds into the hour and lost
    # it.
    with me._get_conn() as conn:
        conn.execute("DELETE FROM duty_run")
        conn.execute("""INSERT INTO duty_run (session_id, ran_at, ended_at,
                trigger, outcome, tokens_spent, model_calls)
            VALUES ('verify-gate', ?, ?, 'regular', 'reported', 10, 1)""",
            (duty._sql_ts(_at_local(hours[0])),
             duty._sql_ts(_at_local(hours[0]))))
    sched = duty._next_regular_moment(now=_at_local(hours[0], minute=59))
    check("a wake-up written at the TOP of the hour serves that whole hour",
          sched["due_now"] is False,
          f"due_now={sched['due_now']} at :59 with a run at :00")

    # AND THE EMERGENCY STILL OUTRANKS THE CLOCK. The schedule gate must not
    # be able to suppress the one trigger the owner said cannot wait.
    #
    # MEASURED ON THE ENABLED PATH ONLY, and that distinction cost this
    # assertion its first version. The switched-off branch legally consults
    # the clock before anything else (a disabled loop investigates nothing by
    # design), so a whole-function scan finds `due_now` first and fails on
    # correct code. The question is what the ENABLED path decides first.
    src = Path(duty.__file__).read_text(encoding="utf-8")
    gate = src[src.index("def _tick_once("):src.index("def _usage_dict(")]
    enabled_path = gate[gate.rindex("schedule = _next_regular_moment(now)"):]
    check("on the enabled path the emergency check runs BEFORE the schedule "
          "gate is consulted",
          enabled_path.index("emergency_check") <
              enabled_path.index("due_now"),
          "a flood must be able to promote an unscheduled minute")
    check("and the due-gate cannot be reached around it: a due hour is only "
          "checked AFTER the emergency promoted or passed",
          enabled_path.index("if emergency.get(\"emergency\")") <
              enabled_path.index("if not schedule.get(\"due_now\")"),
          "the gate is after the emergency, not around it")
    check("and a triggered emergency leaves with the EMERGENCY trigger, not "
          "as an ordinary regular wake",
          "_run(\"emergency\"" in enabled_path)

    with me._get_conn() as conn:
        conn.execute("DELETE FROM duty_run")
        conn.execute("DELETE FROM duty_report")
        conn.execute("UPDATE incident SET status = 'triaged'")
        conn.execute("UPDATE findings SET dismissed = 1")

    section("12b. status() separates polls from wake-ups")
    # A RUNNING LOOP MUST NOT LOOK DEAD BETWEEN MOMENTS. With the gate in
    # place most minutes write nothing, so `ticks` alone is 0 for most of the
    # session — the same picture as a loop that never started. `polls` is the
    # evidence the schedule is being watched, and both travel in status().
    duty._duty_state.update({"polls": 0, "last_poll": None,
                             "last_skip": None, "last_skip_at": None})
    duty._tick_once_state({"outcome": "not_due",
                           "schedule": {"local_hour": 10, "next_hour": 13,
                                        "next_is_tomorrow": False,
                                        "hours": [9, 13, 17, 21]}})
    st = duty.status()
    check("a skipped poll increments `polls` and not `ticks`",
          st["polls"] == 1 and st["ticks"] == 0,
          f"polls={st['polls']} ticks={st['ticks']}")
    check("and the skip is readable, with WHY and when the next one is",
          bool(st.get("last_skip")) and st["last_skip"].get("reason") == "not due"
          and st["last_skip"].get("next_hour") == 13,
          f"last_skip={st.get('last_skip')}")
    check("and `last_skip_at` says when that look happened",
          bool(st.get("last_skip_at")),
          f"last_skip_at={st.get('last_skip_at')}")
    duty._tick_once_state({"outcome": "reported", "report_id": 1})
    st2 = duty.status()
    check("a wake-up CLEARS the stale skip, so the page cannot describe an "
          "old hour beside new work",
          st2.get("last_skip") is None and st2.get("last_skip_at") is None,
          f"last_skip={st2.get('last_skip')}")
    duty._duty_state.update({"polls": 0, "last_poll": None})

    section("12c. the poll is cheap and quiet")
    # THE POLL RUNS 1,440 TIMES A DAY NOW, so two things must be true that
    # did not matter when a tick was a model call: it must be FAST (it runs
    # inside the loop thread), and it must not CHATTER (an undamped warning
    # here is a log filled with one sentence).
    import time as _time
    me.set_preference("duty_wake_hours",
                      __import__("json").dumps([off_hour]))
    try:
        duty._tick_once("verify-poll", modules={})           # warm
        t0 = _time.perf_counter()
        N = 10
        for _ in range(N):
            duty._tick_once("verify-poll", modules={})
        per_poll = (_time.perf_counter() - t0) / N
    finally:
        me.set_preference("duty_wake_hours",
                          __import__("json").dumps(list(hours)))
    check("a poll costs a small fraction of the tick interval",
          per_poll < duty._tick_seconds() / 10,
          f"{per_poll*1000:.0f} ms per poll against a "
          f"{duty._tick_seconds()}s interval")

    # THE DRIFT WARNING IS DAMPED. The knobs are read every poll; the same
    # drift must warn ONCE, or the durable log becomes 1,440 copies of it.
    import logging as _logging

    class _Counter(_logging.Handler):
        def __init__(self):
            super().__init__()
            self.lines = []

        def emit(self, record):
            # getMessage() ALREADY applies record.args. Formatting again here
            # throws inside emit, and logging swallows it into a "Logging
            # error" on stderr while the handler collects nothing — which is
            # how this assertion failed the first time it was written.
            self.lines.append(record.getMessage())

    counter = _Counter()
    duty.logger.addHandler(counter)
    duty.logger.setLevel(_logging.WARNING)
    duty._CONFIG_DRIFT_WARNED.clear()
    me.set_preference("duty_max_investigations_per_hour", "99")   # drift it
    try:
        for _ in range(25):
            duty._max_per_hour()
    finally:
        with me._get_conn() as conn:
            conn.execute("DELETE FROM user_preferences "
                         "WHERE key = 'duty_max_investigations_per_hour'")
    duty.logger.removeHandler(counter)
    check("an unchanged config/live drift warns ONCE, not once per poll",
          len(counter.lines) == 1,
          f"{len(counter.lines)} warning line(s) over 25 reads: "
          f"{counter.lines[:1]}")
    check("and the warning still NAMES both values and which one wins",
          counter.lines and "THE LIVE VALUE WINS" in counter.lines[0]
          and "99" in counter.lines[0],
          (counter.lines[0][:160] if counter.lines else "no warning at all"))
    # NEGATIVE CONTROL: the warning must not be silenced outright. A changed
    # drift is a new fact and must be said.
    duty._CONFIG_DRIFT_WARNED.clear()
    counter2 = _Counter()
    duty.logger.addHandler(counter2)
    me.set_preference("duty_max_investigations_per_hour", "42")
    try:
        duty._max_per_hour()
    finally:
        with me._get_conn() as conn:
            conn.execute("DELETE FROM user_preferences "
                         "WHERE key = 'duty_max_investigations_per_hour'")
    duty.logger.removeHandler(counter2)
    check("NEGATIVE CONTROL: a NEW drift is still reported",
          len(counter2.lines) == 1,
          f"{len(counter2.lines)} line(s) for the changed value")
    duty._CONFIG_DRIFT_WARNED.clear()

    section("13. the tool is declared where it must be")
    check("query_agent_reports is in the manifest",
          tr.tool_exists("query_agent_reports"))
    check("it is classed as a READ tool (it only reads our own record)",
          tr.tool_writes("query_agent_reports") is False)
    from core import sanitize
    check("its output is fenced (it re-serves finding text)",
          sanitize.is_untrusted("query_agent_reports"))
    from core import sensor_health
    check("it declares what it depends on",
          sensor_health.depends_on("query_agent_reports") == ())
    env = tr.execute_tool("query_agent_reports", {"limit": 3})
    check("it dispatches through the real dispatcher",
          env.get("error") is None and isinstance(env.get("result"), dict),
          json.dumps(env.get("error"))[:160])
    check("and it carries the loop's health with the list",
          "duty_loop" in (env.get("result") or {}))

    section("14. a started loop refuses to double-start, and reports honestly")
    with me._get_conn() as conn:
        conn.execute("DELETE FROM duty_run")
    started = duty.start("verify-duty", modules={})
    check("start() returns True", started is True)
    import time
    time.sleep(1.5)
    st = duty.status()
    check("a running loop that can measure its spend is NOT blind",
          st["running"] is True and st["blind"] is False,
          f"blind={st['blind']} reason={st.get('blind_reason')}")
    check("a second start() refuses rather than double-starting",
          duty.start("verify-duty") is False)
    # THE LOOP NOW POLLS WITHOUT WAKING, AND THE CHECK HAD TO CHANGE WITH IT.
    # The old assertion was "its ticks were recorded to disk" — that every
    # tick leaves a row — which is exactly the defect the owner found: a row a
    # minute forever. What must be true instead is that the loop LOOKED, and
    # that it did not write a row per look while nothing was due.
    check("the loop is POLLING even when no wake-up is due",
          st.get("polls", 0) >= 1,
          f"polls={st.get('polls')} last_poll={st.get('last_poll')}")
    check("and a run row is written ONLY for a wake-up, so the table stays "
          "the record of wakes rather than of clock checks",
          len(duty.query_runs(limit=10)) ==
          len([r for r in duty.query_runs(limit=10)
               if r.get("outcome") != "not_due"]),
          f"rows={len(duty.query_runs(limit=10))}")
    check("the schedule travels in its status",
          "schedule" in st and "hours" in st["schedule"])
    check("its budget travels in its status", "budget" in st)
    # AN IN-FLIGHT TICK IS ITS OWN STATE. Found by watching the live app: a
    # two-minute investigation showed `ticks: 0` and no run rows for its whole
    # duration, which is the same picture as a stopped loop. The state must
    # exist and must be absent when nothing is running.
    check("`busy` is absent when no tick is in flight",
          not st.get("busy") and st.get("busy_since") is None,
          f"busy={st.get('busy')} since={st.get('busy_since')}")
    _duty_state_probe = duty._duty_state
    _duty_state_probe["tick_started_at"] = duty._sql_ts(duty._now())
    busy = duty.status()
    check("and it IS reported while a tick is in flight",
          busy.get("busy") is True and bool(busy.get("busy_since")),
          f"busy_since={busy.get('busy_since')}")
    _duty_state_probe["tick_started_at"] = None

    duty.stop()

    section("15. a live model call, when asked for (--live)")
    if not live:
        print("  [SKIP] --live not passed. The 14 sections above made no "
              "model calls and cost nothing.")
    else:
        with me._get_conn() as conn:
            conn.execute("DELETE FROM duty_run")
            conn.execute("DELETE FROM duty_report")
            conn.execute("UPDATE incident SET status = 'new'")
            conn.execute("UPDATE findings SET dismissed = 0")
        out = duty.run_once("verify-duty-live", "manual", modules={})
        print(f"  outcome={out.get('outcome')} verdict={out.get('verdict')} "
              f"tokens={(out.get('usage') or {}).get('total_tokens')}")
        check("a real unattended turn produces a report",
              out.get("report_id") is not None,
              json.dumps(out, default=str)[:300])
        rows = duty.query_reports(limit=1)
        if rows:
            r = rows[0]
            check("the report carries hypothesis, evidence and a verdict",
                  bool(r.get("hypothesis")) and bool(r.get("evidence"))
                  and bool(r.get("verdict")),
                  f"verdict={r.get('verdict')}")
            check("its spend is recorded on the run AND the report",
                  (r.get("tokens_spent") or 0) > 0)
            check("its coverage is recorded (a report from a blind run says so)",
                  r.get("coverage") is not None or r.get("coverage_note"),
                  (r.get("coverage_note") or "")[:140])
        runs = duty.query_runs(limit=1)
        check("the spend is marked measured or estimated, never blank",
              runs and runs[0].get("tokens_estimated") in (0, 1))

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
