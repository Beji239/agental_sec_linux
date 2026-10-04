#!/usr/bin/env python3
"""
scripts/verify_duty_schedule.py — the live proof for the schedule gate.

WHY THIS EXISTS. The owner's report, 2026-09-18: *"the agent was supposed to
run only 4 to max 5 times a day, its constantly running now."* The owner was right,
and the cause was that `_next_regular_moment()` answered "is a wake-up due"
correctly and NOTHING EVER ASKED IT — the daemon called `run_once` every sixty
seconds and every minute was a regular moment. On the owner's live database that
looked like 62 run rows in 2h10m, eight runs that called the model for
2,216,938 tokens, and a `budget` row EVERY SIXTY SECONDS once the ceiling was
crossed.

`verify_duty.py` asserts the gate's LOGIC with the clock passed in. This
script asserts something the unit-level suite cannot: that THE DAEMON THREAD
ITSELF — the real `duty.start()`, the real loop, the real tick timing — polls
without waking, wakes exactly once when a moment is due, and does not wake
again for the same hour. It runs against a COPY of the database and never
against the live one.

THE REAL TICK IS SHORTENED FOR THE OBSERVATION (5s instead of the configured
60s) and that is stated where it happens. The subject is the GATE, not the
interval; the shipping interval is read from config and printed, not changed.

IT MAKES NO MODEL CALLS. The unattended turn is replaced with a recorder, so
"it did not wake" is an assertion about the model not being called, and
"it woke once" is an assertion about a call that actually happened.

USE:
    python3 scripts/verify_duty_schedule.py            # ~45s
    python3 scripts/verify_duty_schedule.py --keep     # leave the temp db
"""

import json
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
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
    print(f"— {title} " + "-" * max(0, 62 - len(title)))


def main():
    keep = "--keep" in sys.argv

    real_db = ROOT / "agental_sec.db"
    tmpdir = tempfile.mkdtemp(prefix="agental_sched_")
    test_db = Path(tmpdir) / "schedule_verify.db"
    shutil.copy2(real_db, test_db)
    print(f"Working on a COPY of the database: {test_db}")
    print("Nothing here writes to yours.")

    import os
    os.environ["AGENTALSEC_TEST_DB"] = str(test_db)

    from core import memory_engine as me
    from core import settings, secret_store
    from core import duty
    from core import agent_loop
    from core import tool_registry as tr

    cfg = json.loads(settings.CONFIG_PATH.read_text())
    resolved = secret_store.resolve(cfg, ROOT)
    agent_loop.init_agent(cfg, api_key=resolved["api_key"])
    tr.init_registry("verify-schedule", {})

    # THE MODEL IS STUBBED WITH A RECORDER. This is what makes the assertions
    # below meaningful: an unstubbed run_unattended would happily spend money,
    # so "was it called" is the real question rather than "did a dict say
    # not_due".
    calls = {"n": 0, "when": []}

    def _recorder(prompt, session_id, allowlist=None, extra_system=""):
        calls["n"] += 1
        calls["when"].append(duty._sql_ts(duty._now()))
        return {
            "answers": [json.dumps({"hypothesis": "h", "evidence": "e",
                                    "verdict": "benign", "saw": "",
                                    "report": "a body"})],
            "tool_calls": [], "refused_calls": [],
            "usage": {"calls": 2, "prompt_tokens": 100, "completion_tokens": 10,
                      "total_tokens": 110, "estimated": False},
            "error": None,
        }

    duty._run_unattended = _recorder

    local_hour = datetime.now().astimezone().hour
    hours = duty._wake_hours()
    print(f"local hour now  : {local_hour}")
    print(f"wake hours      : {list(hours)}")
    print(f"shipping tick   : {duty._tick_seconds()}s (config duty_loop.tick_seconds)")

    # A THROWAWAY HOUR THAT IS NOT A WAKE HOUR, so phase 1 is a poll-heavy
    # observation. If the current hour happens to BE a wake hour the phases
    # swap places and that is handled below rather than assumed away.
    unscheduled = next(h for h in range(24) if h not in hours)

    # The gate reads the schedule from the live preference table; point it at
    # the hour this observation needs, in the COPY only.
    def set_wake_hours(hs):
        me.set_preference("duty_wake_hours", json.dumps(list(hs)))

    # SHORTEN THE TICK FOR THE OBSERVATION. The subject is the gate, not the
    # interval; 5s lets several polls land inside a few seconds. This patches
    # the RUNNING harness only — core/duty.py is untouched.
    duty._tick_seconds = lambda: 5

    with me._get_conn() as conn:
        conn.execute("DELETE FROM duty_run")
        conn.execute("DELETE FROM duty_report")

    section("phase 1 — many polls in an UNSCHEDULED hour, none may wake")
    set_wake_hours([unscheduled])
    print(f"  (the copy's wake hours are now [{unscheduled}]; this test runs in "
          f"local hour {local_hour})")
    started = duty.start("verify-schedule", modules={})
    check("the real daemon thread started", started is True)

    time.sleep(18)
    st = duty.status()
    rows_after_polls = duty.query_runs(limit=50)
    check("the daemon POLLED several times", st.get("polls", 0) >= 3,
          f"polls={st.get('polls')} last_poll={st.get('last_poll')}")
    check("and took ZERO wake-ups", st.get("ticks", 0) == 0,
          f"ticks={st.get('ticks')}")
    check("and the model was NEVER called", calls["n"] == 0,
          f"model calls={calls['n']}")
    check("and it wrote NO run row — the table is the record of wakes, not "
          "of clock checks",
          rows_after_polls == [],
          f"rows={len(rows_after_polls)}")
    check("and the skip is readable with the next moment named",
          bool(st.get("last_skip"))
          and st["last_skip"].get("next_hour") is not None,
          f"last_skip={st.get('last_skip')}")

    section("phase 2 — a poll IN a wake hour wakes it exactly once")
    set_wake_hours([local_hour])
    time.sleep(16)
    st2 = duty.status()
    rows = duty.query_runs(limit=50)
    wake_rows = [r for r in rows if r.get("outcome") != "not_due"]
    check("it woke when the hour matched", st2.get("ticks", 0) >= 1,
          f"ticks={st2.get('ticks')}")
    check("EXACTLY ONE run row was written for that hour",
          len(wake_rows) == 1,
          f"wake rows={[(r.get('outcome'), r.get('ran_at')) for r in wake_rows]}")
    check("and the model was called for it (the wake-up did real work)",
          calls["n"] >= 1, f"model calls={calls['n']}")
    check("a report was left behind", bool(duty.query_reports(limit=1)),
          f"reports={len(duty.query_reports(limit=1))}")

    section("phase 3 — the same hour does NOT wake it again")
    polls_at_phase3 = duty.status().get("polls", 0)
    time.sleep(16)
    st3 = duty.status()
    rows3 = duty.query_runs(limit=50)
    wake_rows3 = [r for r in rows3 if r.get("outcome") != "not_due"]
    check("it kept polling", st3.get("polls", 0) > polls_at_phase3,
          f"polls {polls_at_phase3} -> {st3.get('polls')}")
    check("and did NOT wake a second time in the same hour",
          len(wake_rows3) == 1,
          f"wake rows after more polls: {len(wake_rows3)}")
    check("and the model was not called again",
          calls["n"] == 1, f"model calls={calls['n']}")
    check("the hour's one attempt is the standing record",
          len(rows3) == 1,
          f"total rows={len(rows3)} (1 wake, everything else was a poll)")

    duty.stop()
    time.sleep(1)

    section("summary")
    total_polls = duty.status().get("polls", 0)
    print(f"  {total_polls} polls produced {len(rows3)} run row(s) and "
          f"{calls['n']} model call(s).")
    print("  The owner's requirement was four moments a day; this is what "
          "four moments a day looks like from inside the loop.")

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
    shutil.rmtree(tmpdir, ignore_errors=True)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
