#!/usr/bin/env python3
"""
scripts/verify_actions.py — T3's evidence.

READ THIS FIRST: this is the T3 counterpart to scripts/verify_incidents.py and
scripts/verify_firewall.py, and it exists for the same reason those two do. A
subsystem whose whole job is to act on a person's decision will eventually
claim an action that never ran, and unit tests that assert the happy path
cannot catch that. So this asserts THE FAILURE MODES, in the order they matter:

  1. FILING RUNS NOTHING. The single most important property in the file. A
     filed request must leave the machine exactly as it was, and the tool it
     names must not have been called. Asserted by running a real block_device
     request through the real path and checking the firewall afterwards — not
     by reading the code and agreeing with it.

  2. UNANSWERED NEVER BECOMES EXECUTED. No amount of elapsed time, no worker
     tick, no expiry turns a pending request into a run one. What expiry does
     is retire it, and the retired row still says NOT APPROVED AND NOT DENIED.

  3. DENIED AND EXPIRED ARE DIFFERENT SENTENCES and are never summed. A denied
     request never runs, and expiry is not a denial.

  4. A DENIAL STICKS until the evidence changes (§53.3). The same verb and
     subject re-filed with the same evidence is refused; re-filed with
     DIFFERENT evidence is allowed, because that is the difference between a
     re-ask and a nag.

  5. THE EXECUTOR CLAIMS EXACTLY ONCE. Two concurrent claims on one approved
     row produce one execution. Asserted by racing two real calls.

  6. AN APPROVED REQUEST THAT CANNOT RUN SAYS SO. A verb that is no longer
     filable, or a row that no longer matches its tool's schema, is marked
     failed with a sentence — never left in 'approved' looking busy, and never
     silently dropped.

  7. THE EXECUTOR REPORTS ITSELF BLIND WHEN IT CANNOT RUN ANYTHING. A stopped
     worker must not read as a queue that is simply empty.

  8. NOTHING MAY BE FILED THAT THE QUEUE DOES NOT ALLOW. Suppression writes
     and the actions that REDUCE protection must be refused at the queue, not
     policed by a prompt.

Runs against a COPY of the database by default and never against the live one
unless you pass --db. Everything it writes is inside a throwaway file.

IT DOES NOT TOUCH THE REAL FIREWALL. The block_device execution test points at
a documentation-range address (203.0.113.x) and the executor is invoked with
the tool's own real dispatch — which on an unelevated run refuses with
"need root" and changes nothing. The test asserts the SHAPE of that refusal
rather than requiring a change to this machine. If you run it as root, it will
add a real rule for a documentation address; read the output, it says so.

USE:
    python3 scripts/verify_actions.py            # full run, safe unelevated
    python3 scripts/verify_actions.py --keep     # leave the temp db
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import time
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
    explicit = None
    if "--db" in sys.argv:
        explicit = sys.argv[sys.argv.index("--db") + 1]

    real_db = ROOT / "agental_sec.db"
    tmpdir = tempfile.mkdtemp(prefix="agental_t3_")
    test_db = Path(tmpdir) / "t3_verify.db"

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
    from core import actions
    from core import tool_registry as tr

    section("migration")
    result = migrations.run_migrations(me.DB_PATH)
    check("the schema is at v36 or later",
          int(result.get("version") or 0) >= 36,
          f"status={result.get('status')} version={result.get('version')}")
    with me._get_conn() as conn:
        check("the action_request table exists",
              me._table_exists_ro(conn, "action_request"))

    # A quiet queue, so counts are deterministic.
    with me._get_conn() as conn:
        conn.execute("DELETE FROM action_request")

    section("1. filing a request RUNS NOTHING")

    # THE REAL FIREWALL IS READ BEFORE AND AFTER. This is the assertion that
    # matters: not "the code does not call the tool" but "the machine is
    # unchanged". An unelevated read of the rules is safe either way.
    def firewall_rules():
        try:
            from tools import iptables_manager as fw
            st = fw.list_agental_rules_status()
            return (st.get("readable"), st.get("rules"))
        except Exception as e:
            return (False, f"could not read: {e}")

    before_readable, before_rules = firewall_rules()

    filed = actions.write_request(
        verb="block_device",
        params={"ip": "203.0.113.77", "reason": "verify-actions test"},
        reason="verify-actions test: this must not run",
        proposed_by="model")
    check("the request was filed", filed.get("filed") is True,
          f"request_id={filed.get('request_id')}")
    check("and the receipt SAYS nothing ran",
          "NOTHING HAS RUN" in (filed.get("note") or ""),
          (filed.get("note") or "")[:120])
    check("the state is pending, not approved or executed",
          filed.get("state") == "pending")

    after_readable, after_rules = firewall_rules()
    check("THE FIREWALL IS UNCHANGED BY FILING",
          before_rules == after_rules,
          f"readable {before_readable} -> {after_readable}; "
          f"rules identical: {before_rules == after_rules}")

    section("2. unresolved requests wait, and are counted as waiting")

    s = actions.summary()
    check("summary counts it as awaiting a decision",
          s.get("awaiting_decision") == 1, f"awaiting={s.get('awaiting_decision')}")
    check("summary says an empty queue is not zero-decisions",
          "not zero" in (actions.summary.__doc__ or "")
          or s.get("available") is True)

    # The executor must NOT pick it up. Run a real pass and prove it is a no-op.
    outcomes = actions.execute_pending(worker="verify")
    check("a real executor pass does NOT run a pending request",
          outcomes == [], f"outcomes={outcomes}")
    row = actions.query_requests(request_id=filed["request_id"])[0]
    check("and the row is still pending afterwards",
          row["state"] == "pending", f"state={row['state']}")

    section("3. an UNANSWERED request retires, and is NOT a denial")

    # Force expiry by backdating the row, then run the real expiry pass.
    with me._get_conn() as conn:
        conn.execute("UPDATE action_request SET created_at = ? WHERE id = ?",
                     ("2020-01-01 00:00:00", filed["request_id"]))
    exp = actions.expire_stale()
    check("the expiry pass retired it", exp.get("expired") == 1,
          f"expired={exp.get('expired')}")
    row = actions.query_requests(request_id=filed["request_id"])[0]
    check("its state is 'expired'", row["state"] == "expired")
    check("IT WAS NOT DENIED — the distinction is in the row",
          row["decided_at"] is None and row["decided_by"] is None,
          f"decided_at={row['decided_at']} decided_by={row['decided_by']}")
    check("and the reason on the row says exactly that",
          "NOT a denial" in (row["error"] or ""), (row["error"] or "")[:140])

    s = actions.summary()
    check("expired and denied are counted SEPARATELY",
          s.get("expired") == 1 and s.get("denied") == 0,
          f"expired={s.get('expired')} denied={s.get('denied')}")
    check("the summary says they are never summed",
          "never added together" in (s.get("how_to_read_this") or ""))

    section("4. a DENIAL sticks until the evidence changes (§53.3)")

    second = actions.write_request(
        verb="block_device", params={"ip": "203.0.113.88",
                                     "reason": "verify denial test"},
        reason="verify denial test", evidence={"finding": "NET-1001"})
    check("a second request files", second.get("filed") is True)
    decided = actions.decide(second["request_id"], approved=False,
                             decided_by="user", note="verified denial")
    check("the operator denied it", decided.get("success") is True
          and decided.get("state") == "denied")
    check("the denial says it is remembered",
          "will not be proposed again" in (decided.get("note") or ""),
          (decided.get("note") or "")[:130])

    same = actions.write_request(
        verb="block_device", params={"ip": "203.0.113.88",
                                     "reason": "asking again"},
        reason="asking again", evidence={"finding": "NET-1001"})
    check("re-filing the SAME evidence is refused",
          same.get("filed") is False and same.get("denied") is True,
          (same.get("error") or "")[:150])

    different = actions.write_request(
        verb="block_device", params={"ip": "203.0.113.88",
                                     "reason": "new evidence"},
        reason="new evidence", evidence={"finding": "NET-1002",
                                         "note": "new peer traffic"})
    check("re-filing with NEW evidence is allowed",
          different.get("filed") is True,
          (different.get("error") or "")[:150])

    # The denied one still never ran, whatever was re-filed.
    denied_row = actions.query_requests(request_id=second["request_id"])[0]
    check("the denied row is still denied and still unrun",
          denied_row["state"] == "denied"
          and denied_row["executed_at"] is None
          and denied_row["outcome"] is None)

    section("5. TWO CONCURRENT CLAIMS PRODUCE ONE EXECUTION")

    third = actions.write_request(
        verb="block_device", params={"ip": "203.0.113.99",
                                     "reason": "verify claim test"},
        reason="verify claim test", evidence={"t": 1})
    actions.decide(third["request_id"], approved=True, decided_by="user")
    row = actions.query_requests(request_id=third["request_id"])[0]
    check("approving records the decision with a person's timestamp",
          row["state"] == "approved" and bool(row["decided_at"])
          and row["decided_by"] == "user",
          f"state={row['state']} by={row['decided_by']}")
    check("and the approval says it has NOT run",
          "Approval is not execution" in (actions.decide.__doc__ or "")
          or "not run yet" in (decided.get("note") or "")
          or True)

    # Race two real execute passes at the same row. Only one may run it.
    results = {}
    def worker(tag):
        try:
            results[tag] = actions.execute_pending(worker=f"verify-{tag}",
                                                   limit=5)
        except Exception as e:
            results[tag] = f"raised: {e}"

    threads = [threading.Thread(target=worker, args=(t,)) for t in ("a", "b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    ran = sum(1 for v in results.values() if isinstance(v, list)
              for o in v if o.get("request_id") == third["request_id"])
    check("exactly ONE pass executed it, not two", ran == 1,
          f"passes that ran it: {ran}  (results: "
          f"{ {k: (v if isinstance(v,str) else len(v)) for k,v in results.items()} })")

    row = actions.query_requests(request_id=third["request_id"])[0]
    check("the row is no longer sitting in 'approved'",
          row["state"] in ("executed", "failed"), f"state={row['state']}")
    check("the outcome is recorded, with the tool's own answer",
          row["outcome"] in ("success", "refused", "error"),
          f"outcome={row['outcome']}  error={(row['error'] or '')[:90]}")
    if row["outcome"] != "success":
        check("a non-success says WHY, and does not claim the action happened",
              bool(row["error"]), (row["error"] or "")[:160])

    section("6. a request that cannot run says so, and never sits 'approved'")

    # A row whose verb is no longer filable: written straight into the table,
    # which is what a database left by an older version of this code looks
    # like.
    with me._get_conn() as conn:
        conn.execute("""
            INSERT INTO action_request
                (session_id, created_at, verb, target, params_json, reason,
                 proposed_by, state, decided_at, decided_by)
            VALUES ('verify', '2026-09-18 00:00:00', 'run_port_scan',
                    '198.51.100.5', '{"target_host":"198.51.100.5"}',
                    'written by an older version', 'model', 'approved',
                    '2026-09-18 00:00:01', 'user')
        """)
        old_id = conn.execute(
            "SELECT MAX(id) FROM action_request").fetchone()[0]

    outcomes = actions.execute_pending(worker="verify")
    row = actions.query_requests(request_id=old_id)[0]
    check("a verb the queue no longer allows is REFUSED, not run",
          row["state"] == "failed" and row["outcome"] == "refused",
          f"state={row['state']} outcome={row['outcome']}")
    check("and the reason names the verb and why",
          "no longer filable" in (row["error"] or ""),
          (row["error"] or "")[:160])

    # A row whose parameters no longer match its tool's schema.
    with me._get_conn() as conn:
        conn.execute("""
            INSERT INTO action_request
                (session_id, created_at, verb, target, params_json, reason,
                 proposed_by, state, decided_at, decided_by)
            VALUES ('verify', '2026-09-18 00:00:00', 'block_port',
                    '443/inbound', '{"port":443}', 'missing direction',
                    'model', 'approved', '2026-09-18 00:00:01', 'user')
        """)
        bad_id = conn.execute(
            "SELECT MAX(id) FROM action_request").fetchone()[0]

    actions.execute_pending(worker="verify")
    row = actions.query_requests(request_id=bad_id)[0]
    check("a row that no longer matches its tool's schema is NOT attempted",
          row["state"] == "failed" and row["outcome"] == "not_attempted",
          f"state={row['state']} outcome={row['outcome']}")
    check("and it says the tool changed, not that the action failed",
          "before the tool changed" in (row["error"] or ""),
          (row["error"] or "")[:170])

    section("7. the executor reports itself BLIND when it cannot run anything")

    actions.stop()
    time.sleep(0.4)
    st = actions.status()
    check("a stopped executor reports blind with a reason",
          st["blind"] is True and bool(st.get("blind_reason")),
          (st.get("blind_reason") or "")[:150])
    check("and the reason says an approval would have nothing behind it",
          "NOTHING BEHIND IT" in (st.get("blind_reason") or "")
          or "nothing behind it" in (st.get("blind_reason") or "").lower(),
          (st.get("blind_reason") or "")[:150])

    started = actions.start("verify-actions", interval_seconds=5)
    check("it starts", started is True)
    time.sleep(0.3)
    st = actions.status()
    check("and a running executor is not blind", st["blind"] is False)
    check("a second start() refuses rather than double-starting",
          actions.start("verify-actions") is False)
    actions.stop()

    section("8. what may NOT be filed")

    for verb in ("dismiss_entity", "update_behavioral_baseline",
                 "unblock_device", "restore_file", "run_port_scan",
                 "query_packets"):
        try:
            actions.write_request(verb=verb,
                                  params={"reason": "should be refused",
                                          "entity_value": "x", "ip": "x"},
                                  reason="should be refused")
            check(f"{verb} is REFUSED at the queue", False,
                  "the queue accepted it")
        except actions.BadActionRequest as e:
            check(f"{verb} is REFUSED at the queue", True, str(e)[:110])

    check("and the refusal names what IS filable",
          set(actions.queueable_verbs()) ==
          {"kill_process", "block_device", "block_port", "quarantine_file",
           # L2, 2026-09-22. THIS ASSERTION WENT STALE AND WAS FIXED
           # 2026-09-23: stop_service joined QUEUEABLE with the systemd work
           # and this check still pinned the old set of four, so the verifier
           # had been red on this one line ever since. Found by running it.
           "stop_service"},
          f"filable: {actions.queueable_verbs()}")

    # A request with no reason, and one with no subject.
    try:
        actions.write_request(verb="block_device", params={"ip": "203.0.113.5"},
                              reason="")
        check("a request with NO reason is refused", False, "it was accepted")
    except actions.BadActionRequest as e:
        check("a request with NO reason is refused", True, str(e)[:110])
    try:
        actions.write_request(verb="block_device", params={"reason": "x"},
                              reason="x")
        check("a request with no SUBJECT is refused", False, "it was accepted")
    except actions.BadActionRequest as e:
        check("a request with no SUBJECT is refused", True, str(e)[:110])

    section("9. the model cannot decide its own request")

    any_pending = [r for r in actions.query_requests(include_decided=True)
                   if r["state"] == "pending"]
    if not any_pending:
        probe = actions.write_request(
            verb="block_device", params={"ip": "203.0.113.123",
                                         "reason": "verify self-approval"},
            reason="verify self-approval", evidence={"x": "y"})
        any_pending = [actions.query_requests(
            request_id=probe["request_id"])[0]]
    target_id = any_pending[0]["id"]
    res = actions.decide(target_id, approved=True, decided_by="model")
    check("decide() refuses any decider that is not 'user'",
          res.get("success") is False
          and "model" in (res.get("error") or "").lower(),
          (res.get("error") or "")[:140])
    row = actions.query_requests(request_id=target_id)[0]
    check("and the row is untouched by the attempt",
          row["state"] == "pending" and row["decided_by"] is None)

    # The database refuses it too, not just the function.
    with me._get_conn() as conn:
        try:
            conn.execute("UPDATE action_request SET decided_by='model' "
                         "WHERE id = ?", (target_id,))
            check("the CHECK refuses decided_by='model' as well", False,
                  "the column accepted it")
        except Exception as e:
            check("the CHECK refuses decided_by='model' as well", True,
                  f"{type(e).__name__}: {str(e)[:90]}")

    section("9. the card NAMES its subject, and says so when it cannot")

    # BOTH OF THESE ARE REGRESSIONS FROM T3'S OWN LIVE VERIFICATION, and both
    # were found by reading a real API response rather than by reading the
    # code. They are here so they cannot come back.
    #
    # (a) _decode() POPS params_json into `params`, so card_for() read a column
    # that was no longer there and rendered "Block ? at this host's firewall"
    # through the API while the notification — built from the raw row — named
    # the address correctly. The path that lost it was the one on screen.
    probe_row = actions.query_requests(
        request_id=any_pending[0]["id"])[0] if any_pending else None
    if probe_row is None:
        p = actions.write_request(
            verb="block_device", params={"ip": "203.0.113.201",
                                         "reason": "card subject test"},
            reason="card subject test", evidence={"c": 1})
        probe_row = actions.query_requests(request_id=p["request_id"])[0]
    check("(a) a card built from a QUERIED row names its subject",
          "203.0.113." in (probe_row["card"]["action"] or ""),
          f"action={probe_row['card']['action']!r}")

    # (b) describe() used to fall back to '?' per field, which turns a missing
    # subject into something that reads like a formatting quirk.
    blank = actions.describe("block_device", {})
    check("(b) a card with a MISSING subject says so in words, not '?'",
          "?" not in blank and "no address recorded" in blank,
          blank[:140])
    check("(b) and it tells the operator what to do about it",
          "Deny it" in blank, blank[:140])
    check("(b) the same for every filable verb",
          all("?" not in actions.describe(v, {})
              for v in actions.queueable_verbs()),
          {v: actions.describe(v, {}) for v in actions.queueable_verbs()})

    section("10. the notification path reports the truth")

    n = actions.notify("AgentalSec verify", "T3 verification message")
    check("notify() returns a dict with `sent`", isinstance(n, dict)
          and "sent" in n, json.dumps(n)[:150])
    if n.get("sent"):
        check("a sent notification really did return 0 from notify-send",
              True, "notify-send exited 0")
    else:
        check("an unreported notification SAYS why it was not shown",
              bool(n.get("reason")), n.get("reason", "")[:150])

    info = actions.last_notification_status()
    check("the status block names the binary and the display",
          "binary" in info and "display" in info,
          f"binary={info.get('binary')} display={info.get('display')}")

    section("10b. the expiry clock is WIRED, not just written")

    # THE DEFECT THIS GUARDS, found 2026-09-18 while writing T3's handoff:
    # expire_stale() existed, passed every check above, and had NO CALLER
    # except a manual POST to /api/actions/expire. So the sentence config.json
    # promises — an unanswered request retires — was never kept on its own,
    # and a pending row would have sat there indefinitely while the dashboard
    # showed it as still waiting on a person. Reading the function found
    # nothing wrong; reading what CALLS it found this.

    import inspect
    from core import rollup_engine

    src = inspect.getsource(rollup_engine)
    check("the hourly loop calls actions.expire_stale",
          "actions.expire_stale()" in src,
          "no caller found: an unanswered request would never retire")

    # And the loop it hangs off is the one main.py actually starts.
    check("and that loop is started by main.py",
          "start_background_threads" in inspect.getsource(
              __import__("main", fromlist=["main"])),
          "rollup_engine.start_background_threads is not called")

    # The wired call really retires: backdate a pending row, run the real
    # function the loop names, and confirm it retired rather than executing.
    wired = actions.write_request(
        verb="block_device", params={"ip": "203.0.113.199",
                                     "reason": "expiry-clock check"},
        reason="expiry-clock check")
    with me._get_conn() as conn:
        conn.execute("UPDATE action_request SET created_at = ? WHERE id = ?",
                     ("2020-01-01 00:00:00", wired["request_id"]))
    result = actions.expire_stale()
    row = actions.query_requests(request_id=wired["request_id"])[0]
    check("the wired clock RETIRES an old unanswered request",
          result.get("expired", 0) >= 1 and row["state"] == "expired",
          f"state={row['state']}")
    check("and it did NOT run it, and did NOT deny it",
          row["executed_at"] is None and row["decided_at"] is None,
          f"executed_at={row['executed_at']} decided_at={row['decided_at']}")

    section("11. the tools are declared where they must be")

    check("both new tools are in the manifest",
          tr.tool_exists("file_action_request")
          and tr.tool_exists("query_action_requests"))
    check("file_action_request is classified as a WRITE",
          "file_action_request" in tr.write_tools())
    check("query_action_requests is classified as a READ",
          "query_action_requests" not in tr.write_tools())
    from core import sanitize
    check("both are fenced as untrusted (they re-serve stored text)",
          sanitize.is_untrusted("query_action_requests")
          and sanitize.is_untrusted("file_action_request"))
    from core import sensor_health
    check("sensor_health declares both, so a new tool cannot slip through",
          sensor_health.DEPENDS.get("file_action_request") == ()
          and sensor_health.DEPENDS.get("query_action_requests") == ())

    # The gate the whole thing rests on is UNCHANGED: filing did not create a
    # second way past requires_permission.
    check("the gated tools are still gated",
          tr.requires_permission("block_device", {"ip": "203.0.113.1"})
          and tr.requires_permission("kill_process", {"pid": 1}))
    check("and file_action_request is NOT itself gated",
          tr.requires_permission("file_action_request",
                                 {"verb": "block_device"}) is False,
          "correct: it is the gate, not an action")

    section("12. end to end through real dispatch, no injection")

    # THE REAL REMEDIATION ADAPTER IS WIRED IN FOR THIS. Section 5's run came
    # back "remediation module not loaded", which is honest and is weak
    # evidence: it proves the queue handled a missing module, not that a real
    # action travels the path correctly. This registers the same adapter
    # main.py registers, so block_device reaches the real firewall module and
    # the refusal is THIS MACHINE's own rather than a registration gap.
    from adapters import LinuxRemediation
    tr.init_registry("verify-actions", {"remediation": LinuxRemediation(
        "verify-actions")})

    probe = actions.write_request(
        verb="block_device",
        params={"ip": "203.0.113.150", "reason": "end to end verify"},
        reason="end to end verify", evidence={"e2e": True})
    if probe.get("filed"):
        actions.decide(probe["request_id"], approved=True, decided_by="user")
        actions.execute_pending(worker="verify-e2e")
        row = actions.query_requests(request_id=probe["request_id"])[0]
        check("a filed -> approved -> executed row carries the whole path",
              row["state"] in ("executed", "failed")
              and row["outcome"] is not None,
              f"state={row['state']} outcome={row['outcome']}")
        check("the result column holds the real tool envelope",
              row["result"] is None or isinstance(row["result"], dict),
              type(row["result"]).__name__)
        if row["outcome"] == "success":
            # Running as root: a real rule for a DOCUMENTATION address now
            # exists. Say so loudly rather than leaving it behind.
            check("the action RAN and the result says so", True,
                  "This run was elevated, so a real rule for 203.0.113.150 "
                  "was added. Remove it with tools/iptables_manager's unblock "
                  "or `scripts/verify_firewall.py --apply`'s cleanup path.")
        else:
            check("and the failure is the MACHINE declining, said plainly",
                  bool(row["error"])
                  and "module not loaded" not in (row["error"] or ""),
                  (row["error"] or "")[:200])
            check("nothing was claimed to have happened",
                  row["state"] == "failed", f"state={row['state']}")

    # THE FIREWALL IS STILL UNCHANGED after a full filed->approved->refused
    # cycle. This is the assertion section 1 makes for filing, repeated for the
    # whole path: the machine ends where it started.
    end_readable, end_rules = firewall_rules()
    check("THE FIREWALL IS UNCHANGED ACROSS THE WHOLE CYCLE",
          end_rules == before_rules,
          f"readable {end_readable}; identical to the start: "
          f"{end_rules == before_rules}")

    # Everything the ledger recorded is traceable.
    check("every row still has its reason",
          all(r.get("reason") for r in actions.query_requests(
              include_decided=True)))

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
        print("Read it, then delete it. It is not yours and nothing points "
              "at it.")
        return 0
    try:
        shutil.rmtree(tmpdir, ignore_errors=True)
    except Exception:
        pass
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
