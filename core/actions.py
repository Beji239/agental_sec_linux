# core/actions.py
# The action queue, the executor and the card that approves them.
#
#   queue     write_request() files a row. Nothing runs.
#   executor  runs APPROVED rows outside any chat turn, exactly once, through
#             the same tool_registry.execute_tool the chat uses.
#   card      the permission card, rendered from this queue, plus notify-send.
#
# Rules: silence never becomes an approval (expiry only retires); a denial
# sticks until the evidence changes; every execution re-validates its
# parameters; an action that could not run says why.

import json
import logging
import os
import pwd
import shutil
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone

from core import memory_engine as me

logger = logging.getLogger(__name__)


class BadActionRequest(ValueError):
    """A caller asked the queue for something it will not do."""


# VOCABULARIES. Every one of these is a CHECK in the schema as well, because a
# typo in a status string is how a row becomes invisible to every reader that
# filters on it.

# States. expired (nobody answered) and denied (a person said no) are both
# "did not run" and are never summed.
REQUEST_STATES = ("pending", "approved", "denied", "executed",
                  "failed", "expired")

# The outcome of an execution attempt, when there is one.
EXECUTION_OUTCOMES = ("success", "refused", "error", "not_attempted")

# A claim is a timestamp and an owner; one older than this is released.
CLAIM_STALE_SECONDS = 300

# Unanswered requests retire after this many days. Retiring means "never ran".
DEFAULT_EXPIRY_DAYS = 10

# What may be filed for unattended approval. Deliberately not every gated
# tool: suppressions, unblock/restore (they reduce protection) and port
# scans are decided live in the chat. A verb absent here cannot be filed.
QUEUEABLE = {
    "kill_process": {
        # expected_name is filled in at filing time and checked before the
        # kill, so a pid reused between filing and approval is refused.
        "required": ("pid", "reason", "expected_name"),
        "needs":    ("pid",),
        "blurb":    "Terminate a running process at this host.",
    },
    # Stopping a service is what actually ends one on a systemd host. Its own
    # adapter refuses this app's units and the journal.
    "stop_service": {
        "required": ("unit", "reason"),
        "needs":    ("unit",),
        "blurb":    "Stop one systemd unit. This is what actually ends a "
                    "service, where killing its process only makes systemd "
                    "start it again.",
    },
    "block_device": {
        "required": ("ip", "reason"),
        "needs":    ("ip",),
        "blurb":    "Block one address at this host's firewall, both "
                    "directions.",
    },
    "block_port": {
        "required": ("port", "direction", "reason"),
        "needs":    ("port", "direction"),
        "blurb":    "Block one port at this host's firewall.",
    },
    "quarantine_file": {
        "required": ("file_path", "reason"),
        "needs":    ("file_path",),
        "blurb":    "Move one file out of its location into the quarantine "
                    "folder, with a manifest and a hash.",
    },
    # The router's own enforcement, T9. Their undos are not filable, for the
    # same reason unblock and restore are not: they lower protection.
    "gateway_block_device": {
        "required": ("ip", "reason"),
        "needs":    ("ip",),
        "blurb":    "Block one address at the router, which takes it off the "
                    "internet and other subnets, until the router reboots.",
    },
    "gateway_sinkhole_domain": {
        "required": ("domain", "reason"),
        "needs":    ("domain",),
        "blurb":    "Make the router's resolver answer one domain with "
                    "nothing, for every device that uses it.",
    },
    # Containment through the root helper. Their undos are not filable.
    "remove_ssh_key": {
        "required": ("user", "fingerprint", "reason"),
        "needs":    ("user", "fingerprint"),
        "blurb":    "Take one SSH key, by fingerprint, out of an account's "
                    "authorized_keys.",
    },
    "lock_account": {
        "required": ("user", "reason"),
        "needs":    ("user",),
        "blurb":    "Lock an account so it cannot log in by password or key.",
    },
    "remove_group_member": {
        "required": ("user", "group", "reason"),
        "needs":    ("user", "group"),
        "blurb":    "Take an account out of a group that can become root.",
    },
    "disable_cron_line": {
        "required": ("path", "line", "reason"),
        "needs":    ("path", "line"),
        "blurb":    "Comment out one cron line, keeping its text.",
    },
    "disable_service": {
        "required": ("unit", "reason"),
        "needs":    ("unit",),
        "blurb":    "Stop, disable and mask a systemd unit so it does not "
                    "start again at boot.",
    },
}

# The verbs the model can file and the owner can read, in one place, so the
# card, the tool description and the docs cannot drift apart.
def queueable_verbs() -> list[str]:
    return sorted(QUEUEABLE)


def _pref_int(key: str, default: int) -> int:
    try:
        return int(float(me.get_preference(key, str(default))))
    except (TypeError, ValueError):
        return default


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sql_ts(dt: datetime) -> str:
    """The shape SQLite's CURRENT_TIMESTAMP writes, so string compares work."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _parse_ts(value):
    if not value:
        return None
    text = str(value).strip().replace("T", " ").rstrip("Z")[:19]
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc)
    except ValueError:
        return None


def _table_ready(conn, name: str = "action_request") -> bool:
    return me._table_exists_ro(conn, name)


def _config() -> dict:
    try:
        from core import incident
        return incident._config()
    except Exception:
        return {}


def _queue_enabled() -> bool:
    block = (_config().get("action_queue") or {})
    return bool(block.get("enabled", True))


def _notifications_enabled() -> bool:
    block = (_config().get("action_queue") or {})
    return bool(block.get("notify", True))


def _expiry_days() -> int:
    """
    Days an unanswered request waits, from config; clamped to at least 1.
    """
    block = (_config().get("action_queue") or {})
    try:
        days = int(block.get("expiry_days", DEFAULT_EXPIRY_DAYS))
    except (TypeError, ValueError):
        days = DEFAULT_EXPIRY_DAYS
    return max(1, days)


# Evidence fingerprint: a denial sticks until the evidence changes. The
# caller supplies the evidence; this is a stable digest of it.
def evidence_fingerprint(evidence) -> str:
    """
    A stable digest of the caller's evidence; '' means none was offered.
    """
    if evidence is None:
        return ""
    if isinstance(evidence, str):
        text = evidence
    else:
        try:
            text = json.dumps(evidence, sort_keys=True, default=str)
        except (TypeError, ValueError):
            text = str(evidence)
    text = text.strip()
    if not text:
        return ""
    import hashlib
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:32]


# VALIDATION — before a row exists, and again before anything runs

def _validated_params(verb: str, params: dict) -> dict:
    """
    Keep only the parameters the verb declares and require its subject and a
    reason. Raises BadActionRequest with a sentence.
    """
    if verb not in QUEUEABLE:
        raise BadActionRequest(
            f"{verb!r} cannot be filed for approval. Filable verbs: "
            f"{', '.join(queueable_verbs())}. Gated tools that are NOT filable "
            f"are the suppression writes and the actions that REDUCE "
            f"protection (unblock_*, restore_file), because those have to be "
            f"decided while looking at the evidence rather than from a queue.")

    spec = QUEUEABLE[verb]
    params = params or {}
    keep = set(spec["required"])
    narrowed = {k: v for k, v in params.items()
                if k in keep and v is not None and v != ""}

    missing = [k for k in spec["needs"] if k not in narrowed]
    if missing:
        raise BadActionRequest(
            f"{verb} needs {', '.join(spec['needs'])}. Missing: "
            f"{', '.join(missing)}. A request without its subject cannot be "
            f"shown to anybody as a decision.")

    if not str(narrowed.get("reason") or "").strip():
        # A reason is required: the card is all a person sees.
        raise BadActionRequest(
            "A reason is required. The card is the whole of what a person "
            "sees, and 'block this' with no stated why is a decision nobody "
            "can actually make.")

    return narrowed


def _validate_against_schema(verb: str, params: dict) -> tuple:
    """
    Re-check a stored row against the tool's current schema before running.
    Returns (ok, error). Accepts the schema wrapped or bare.
    """
    try:
        from core import tool_registry as tr
        schema = tr.tool_schema(verb) or {}
    except Exception as e:
        return False, (f"the tool manifest could not be read ({e}), so this "
                       f"request was not run. That is not the same as the "
                       f"action being refused.")

    if "input_schema" in schema:
        schema = schema.get("input_schema") or {}
    required = schema.get("required") or []
    missing = [k for k in required if k not in params]
    if missing:
        return False, (f"{verb} now requires {', '.join(required)} and this "
                       f"request does not carry {', '.join(missing)}. It was "
                       f"written before the tool changed. Nothing was run.")
    return True, None


# FILING A REQUEST

def _open_duplicate(conn, verb: str, target: str) -> dict | None:
    """An open request for the same verb and subject, if one exists."""
    row = conn.execute("""
        SELECT * FROM action_request
         WHERE verb = ? AND target = ? AND state = 'pending'
         ORDER BY id DESC LIMIT 1
    """, (verb, target)).fetchone()
    return dict(row) if row else None


def _denied_since(conn, verb: str, target: str) -> dict | None:
    """
    The latest denial for this verb and subject, if any.
    """
    row = conn.execute("""
        SELECT * FROM action_request
         WHERE verb = ? AND target = ? AND state = 'denied'
         ORDER BY id DESC LIMIT 1
    """, (verb, target)).fetchone()
    return dict(row) if row else None


def _target_of(verb: str, params: dict) -> str:
    """
    The request's subject as one string (block_port: port/direction).
    """
    spec = QUEUEABLE.get(verb) or {}
    needs = spec.get("needs") or ()
    if verb == "block_port":
        return f"{params.get('port')}/{params.get('direction')}"
    if len(needs) == 1:
        return str(params.get(needs[0]))
    return "|".join(f"{k}={params.get(k)}" for k in needs)


def write_request(verb: str, params: dict, reason: str,
                  incident_id: int = None, proposed_by: str = "model",
                  evidence=None, session_id: str = None) -> dict:
    """
    File a request; nothing runs. Refuses a verb that may not be queued
    (raises), a duplicate of a pending request, and a re-proposal of a denied
    one without new evidence (both returned as refusals).
    """
    params = dict(params or {})
    reason = (reason or "").strip()
    if reason:
        params["reason"] = reason

    narrowed = _validated_params(verb, params)
    if verb == "kill_process":
        # Always read here, never taken from the caller, so the card names
        # the process that really holds the pid.
        try:
            import psutil
            narrowed["expected_name"] = psutil.Process(int(narrowed["pid"])).name()
        except Exception as e:                      # noqa: BLE001
            raise BadActionRequest(
                f"pid {narrowed.get('pid')} could not be read now ({e}), so "
                f"the card could not name the process it would kill. Nothing "
                f"was filed.")
    target = _target_of(verb, narrowed)
    fp = evidence_fingerprint(evidence)
    now = _sql_ts(_now())

    with me._get_conn() as conn:
        if not _table_ready(conn):
            raise BadActionRequest(
                "The action_request table does not exist. Run the migrations "
                "(core/migrations.run_migrations) before filing anything. "
                "Nothing was filed and nothing is waiting on you.")

        dup = _open_duplicate(conn, verb, target)
        if dup:
            return {
                "filed": False, "duplicate": True,
                "request_id": dup["id"],
                "state": dup["state"],
                "error": (f"This is already waiting on the operator "
                          f"(request {dup['id']}, filed "
                          f"{dup['created_at']}). Filing it again would put "
                          f"two cards on the screen for one decision. Do not "
                          f"file it again; the first one is what runs."),
            }

        denial = _denied_since(conn, verb, target)
        if denial:
            if not fp or fp == (denial.get("evidence_fingerprint") or ""):
                return {
                    "filed": False, "denied": True,
                    "request_id": denial["id"],
                    "denied_at": denial["decided_at"],
                    "error": (
                        f"The operator already DENIED this on "
                        f"{denial.get('decided_at')}. A denial is a decision "
                        f"and it stands until the evidence changes: this call "
                        f"carries "
                        + ("no evidence fingerprint" if not fp else
                           "the same evidence the denial was made against")
                        + ", so it is the same request and it would get the "
                          "same answer. If something NEW has happened, a "
                          "different finding, a new peer, traffic that was "
                          "not there before, file it again carrying that as "
                          "evidence and the operator can judge it afresh."),
                }

    with me._get_conn() as conn:
        cur = conn.execute("""
            INSERT INTO action_request
                (session_id, created_at, verb, target, params_json, reason,
                 evidence_json, evidence_fingerprint, proposed_by,
                 incident_id, state)
            VALUES (?,?,?,?,?,?,?,?,?,?, 'pending')
        """, (session_id or "unknown", now, verb, target,
              json.dumps(narrowed), narrowed.get("reason"),
              json.dumps(evidence, default=str) if evidence is not None
              else None,
              fp, proposed_by, incident_id))
        new_id = cur.lastrowid

        # The proposal is sealed in the same transaction as the row, so what was
        # filed cannot be rewritten before it is approved.
        try:
            from core import integrity
            integrity.seal_row("action_request", new_id, conn=conn)
        except Exception as e:                      # noqa: BLE001
            # Never fatal: the request is filed and that is the important
            # half, the same call this file already makes about the incident
            # link a few lines down.
            logger.error(f"Filed request {new_id} but could not seal it: {e}")

        row = conn.execute("SELECT * FROM action_request WHERE id = ?",
                           (new_id,)).fetchone()

        # The incident moves to action_pending and records the proposal.
        if incident_id:
            try:
                conn.execute("""
                    UPDATE incident
                       SET status = 'action_pending',
                           status_at = ?, status_by = 'model',
                           actions_json = ?
                     WHERE id = ?
                """, (now, json.dumps([{"request_id": new_id, "verb": verb,
                                        "target": target, "state": "pending",
                                        "filed_at": now}]),
                      incident_id))
            except Exception as e:
                # The request is filed and that is the important half. Say so
                # rather than unwinding it: a lost ledger link is a reporting
                # problem and losing the filed request would be a real one.
                logger.error(f"Filed request {new_id} but could not attach it "
                             f"to incident {incident_id}: {e}")

    logger.info("Action request %s filed: %s %s", new_id, verb, target)

    out = {
        "filed": True,
        "request_id": new_id,
        "verb": verb,
        "target": target,
        "state": "pending",
        "params": narrowed,
        "created_at": now,
        "note": (
            "FILED FOR APPROVAL. NOTHING HAS RUN AND NOTHING IS RUNNING. "
            "This is on the operator's screen as a card and it waits for a "
            "person, for as long as it takes. If nobody answers it, it is "
            "never executed, an unanswered request retires and the record "
            "says it was not approved, which is a different sentence from "
            "being denied. Do not report this action as done, attempted, or "
            "agreed, and do not wait for it inside this turn: the result "
            "appears on the request itself when somebody decides."),
    }
    return out


# The decision: only a person, through the API key. No tool calls decide().

def decide(request_id: int, approved: bool, decided_by: str = "user",
           note: str = None) -> dict:
    """
    Record a person's approval or denial of a pending request. Only
    decided_by='user' is accepted, and a request is decided once.
    """
    if decided_by != "user":
        # Kept as a parameter so the caller is explicit, and refused for
        # anything else so this cannot quietly become a model-reachable path.
        return {"success": False,
                "error": ("Only 'user' may decide an action request. A model "
                          "decision here would be the model approving itself, "
                          "which is the thing the gate exists to prevent.")}

    now = _sql_ts(_now())
    with me._get_conn() as conn:
        if not _table_ready(conn):
            return {"success": False,
                    "error": "the action_request table does not exist"}
        row = conn.execute("SELECT * FROM action_request WHERE id = ?",
                           (request_id,)).fetchone()
        if row is None:
            return {"success": False,
                    "error": f"no action request with id {request_id}"}
        if row["state"] not in ("pending",):
            return {"success": False,
                    "decided": True,
                    "state": row["state"],
                    "error": (f"request {request_id} is already "
                              f"{row['state']} (decided "
                              f"{row['decided_at'] or 'at execution'}). This "
                              f"decision changed nothing.")}

        cur = conn.execute("""
            UPDATE action_request
               SET state = ?, decided_at = ?, decided_by = ?, decision_note = ?
             WHERE id = ? AND state = 'pending'
        """, ("approved" if approved else "denied", now, decided_by, note,
              request_id))
        if not cur.rowcount:
            # Another decision landed between the read and this write.
            return {"success": False, "decided": True,
                    "error": (f"request {request_id} was decided by another "
                              f"click a moment ago. This decision changed "
                              f"nothing.")}

    state = "approved" if approved else "denied"
    logger.info("Action request %s was %s by %s", request_id, state,
                decided_by)

    # Journal the decision after the write, outside the connection, so the
    # journal can never roll back the decision it records.
    me._journal("action_approved" if approved else "action_rejected",
                "action_request", request_id,
                {"verb": (row["verb"] if row is not None else None),
                 "noted": note})

    out = {
        "success": True,
        "request_id": request_id,
        "state": state,
        "decided_at": now,
    }
    if approved:
        out["note"] = (
            "Approved. It is now waiting on the executor, which runs OUTSIDE "
            "any chat turn. The result lands on the request itself, read it "
            "there rather than assuming the action worked. Approval is not "
            "execution, and execution is not success.")
    else:
        out["note"] = (
            "DENIED and recorded. Nothing runs, ever, for this request. The "
            "same action will not be proposed again unless it comes with "
            "materially new evidence.")
    return out


# THE EXECUTOR — the piece that did not exist

_executor_thread = None
_executor_stop = threading.Event()
_executor_state = {
    "running": False,
    "last_error": None,
    "consecutive_failures": 0,
    "last_run_at": None,
    "last_result": None,
    "runs": 0,
    "executed": 0,
    "failed": 0,
    "refused": 0,
}
_executor_lock = threading.Lock()


def _claim(conn, worker: str) -> dict | None:
    """
    Claim one approved request for this worker, or None.
    """
    stale_before = _sql_ts(_now() - timedelta(seconds=CLAIM_STALE_SECONDS))
    conn.execute("""
        UPDATE action_request
           SET claim_at = NULL, claimed_by = NULL
         WHERE state = 'approved'
           AND claim_at IS NOT NULL
           AND claim_at < ?
    """, (stale_before,))

    # The row is returned by its id. Looking it up by (worker, second) used to
    # hand back an already finished row when two claims fell in one second,
    # which ran that request twice and left the other one parked.
    now = _sql_ts(_now())
    pick = conn.execute("""
        SELECT id FROM action_request
         WHERE state = 'approved' AND claim_at IS NULL
         ORDER BY decided_at ASC, id ASC
         LIMIT 1
    """).fetchone()
    if pick is None:
        return None
    cur = conn.execute("""
        UPDATE action_request
           SET claim_at = ?, claimed_by = ?
         WHERE id = ? AND state = 'approved' AND claim_at IS NULL
    """, (now, worker, pick["id"]))
    if not cur.rowcount:
        return None
    row = conn.execute("SELECT * FROM action_request WHERE id = ?",
                       (pick["id"],)).fetchone()
    return dict(row) if row else None


def _finish(conn, request_id: int, state: str, outcome: str,
            result: dict, error: str = None):
    """
    Write the outcome down, whatever it was.
    """
    now = _sql_ts(_now())
    try:
        payload = json.dumps(result, default=str) if result is not None else None
    except (TypeError, ValueError):
        payload = json.dumps({"unserialisable": str(result)[:2000]})

    conn.execute("""
        UPDATE action_request
           SET state = ?, executed_at = ?, outcome = ?,
               result_json = ?, error = ?
         WHERE id = ?
    """, (state, now, outcome, payload, error, request_id))


def execute_pending(worker: str = "action-executor",
                    limit: int = 5) -> list[dict]:
    """
    Run approved requests one at a time, up to limit. Each re-validates its
    parameters and runs through tool_registry.execute_tool.
    """
    outcomes = []
    worker_tag = f"{worker}:{os.getpid()}"

    for _ in range(max(1, limit)):
        with me._get_conn() as conn:
            if not _table_ready(conn):
                break
            row = _claim(conn, worker_tag)

        if row is None:
            break

        request_id = row["id"]
        verb = row["verb"]
        try:
            params = json.loads(row["params_json"] or "{}")
        except (TypeError, ValueError) as e:
            params = None
            parse_error = str(e)
        else:
            parse_error = None

        # 1. the row has to still make sense
        if params is None:
            with me._get_conn() as conn:
                _finish(conn, request_id, "failed", "error", None,
                        f"The stored parameters could not be read ({parse_error})."
                        f" Nothing was run.")
            outcomes.append({"request_id": request_id, "state": "failed",
                             "outcome": "error"})
            continue

        ok, why = _validate_against_schema(verb, params)
        if not ok:
            with me._get_conn() as conn:
                _finish(conn, request_id, "failed", "not_attempted", None, why)
            outcomes.append({"request_id": request_id, "state": "failed",
                             "outcome": "not_attempted"})
            logger.warning("Action request %s not run: %s", request_id, why)
            continue

        if verb not in QUEUEABLE:
            # A verb no longer filable is refused, not run.
            why = (f"{verb} is no longer filable for unattended execution, so "
                   f"this old request was refused rather than run. Decide it "
                   f"in the chat, where the evidence is on the card.")
            with me._get_conn() as conn:
                _finish(conn, request_id, "failed", "refused", None, why)
            outcomes.append({"request_id": request_id, "state": "failed",
                             "outcome": "refused"})
            continue

        # 2. run it, through the same dispatcher the chat path uses
        logger.info("Executing approved request %s: %s %s",
                    request_id, verb, row["target"])
        started = time.time()
        try:
            from core import tool_registry as tr
            envelope = tr.execute_tool(verb, params)
            error = envelope.get("error")
            inner = envelope.get("result")
            success = (error is None
                       and isinstance(inner, dict)
                       and inner.get("success") is True)
            outcome = ("success" if success
                       else ("refused" if error is None else "error"))
            state = "executed" if success else "failed"
            detail = (error or (inner or {}).get("error")
                      if not success else None)
            with me._get_conn() as conn:
                _finish(conn, request_id, state, outcome, envelope, detail)
        except Exception as e:
            logger.error("Action request %s raised: %s", request_id, e,
                         exc_info=True)
            with me._get_conn() as conn:
                _finish(conn, request_id, "failed", "error", None,
                        f"{type(e).__name__}: {e}")
            state, outcome = "failed", "error"

        outcomes.append({
            "request_id": request_id,
            "verb": verb,
            "target": row["target"],
            "state": state,
            "outcome": outcome,
            "ms": int((time.time() - started) * 1000),
        })

    if outcomes:
        logger.info("Action executor ran %d request(s): %s", len(outcomes),
                    [f"#{o['request_id']} {o['state']}/{o.get('outcome')}"
                     for o in outcomes])

    # The effect is journalled separately from the decision, including the
    # endings that ran nothing.
    for o in outcomes:
        me._journal("action_executed", "action_request", o.get("request_id"),
                    {"verb": o.get("verb"), "state": o.get("state"),
                     "outcome": o.get("outcome"), "ms": o.get("ms")})

    return outcomes


def _record_execution(outcomes: list):
    _executor_state["last_run_at"] = _sql_ts(_now())
    _executor_state["last_result"] = outcomes[-1] if outcomes else None
    for o in outcomes:
        _executor_state["runs"] += 1
        if o.get("state") == "executed":
            _executor_state["executed"] += 1
        elif o.get("outcome") == "refused":
            _executor_state["refused"] += 1
        else:
            _executor_state["failed"] += 1


def start(session_id: str = None, interval_seconds: int = None) -> bool:
    """
    Start the executor thread. Refuses when the queue is off or the table
    is missing, rather than running a worker that can do nothing.
    """
    global _executor_thread

    with _executor_lock:
        if _executor_state["running"]:
            return False

        if not _queue_enabled():
            logger.info("Action queue is switched off in config.json, so "
                        "nothing executes approved requests. Approvals will "
                        "accumulate and be reported as unexecuted.")
            return False

        try:
            with me._get_readonly_conn() as conn:
                if not _table_ready(conn):
                    logger.warning(
                        "Action executor NOT started: the action_request "
                        "table does not exist. Run the migrations. Approved "
                        "requests would sit unexecuted until this is fixed.")
                    return False
        except Exception as e:
            logger.warning(f"Action executor NOT started, database "
                           f"unreadable: {e}")
            return False

        interval = int(interval_seconds
                       or (_config().get("action_queue") or {}).get(
                           "poll_seconds", 15))
        interval = max(5, interval)

        _executor_state.update({"running": True, "last_error": None,
                                "consecutive_failures": 0})
        _executor_stop.clear()

        def loop():
            logger.info("Action executor started, every %ss.", interval)
            while not _executor_stop.is_set():
                try:
                    outcomes = execute_pending()
                    _record_execution(outcomes)
                    _executor_state["last_error"] = None
                    _executor_state["consecutive_failures"] = 0
                except Exception as e:
                    _executor_state["consecutive_failures"] += 1
                    _executor_state["last_error"] = f"{type(e).__name__}: {e}"
                    logger.error(f"Action executor pass failed: {e}")
                _executor_stop.wait(interval)
            _executor_state["running"] = False
            logger.info("Action executor stopped.")

        _executor_thread = threading.Thread(target=loop, name="action-executor",
                                            daemon=True)
        _executor_thread.start()
        return True


def stop():
    _executor_stop.set()


def status() -> dict:
    """
    Executor health for sensor_health. blind means an approved action
    would not run.
    """
    out = {
        "running": _executor_state["running"],
        "role": "action_executor",
        "blind": False,
        "runs": _executor_state["runs"],
        "executed": _executor_state["executed"],
        "failed": _executor_state["failed"],
        "refused": _executor_state["refused"],
        "last_run_at": _executor_state["last_run_at"],
        "queueable_verbs": queueable_verbs(),
    }

    if _executor_state["consecutive_failures"]:
        out["consecutive_failures"] = _executor_state["consecutive_failures"]
    if _executor_state["last_error"]:
        out["last_error"] = _executor_state["last_error"]

    if not _queue_enabled():
        out["blind"] = True
        out["blind_reason"] = (
            "The action queue is switched off in config.json. NOTHING WILL "
            "EXECUTE AN APPROVED REQUEST. Anything the operator approves sits "
            "there un-run, which is a statement about this app's "
            "configuration and not about the actions being safe to skip.")
    elif not _executor_state["running"]:
        out["blind"] = True
        out["blind_reason"] = (
            "The action executor is not running, so an approval has NOTHING "
            "BEHIND IT: the card would say approved and the action would "
            "never run. Requests can still be filed and decided; none of "
            "them will execute.")

    try:
        with me._get_readonly_conn() as conn:
            if _table_ready(conn):
                counts = {"pending": 0, "approved": 0, "denied": 0,
                          "executed": 0, "failed": 0, "expired": 0}
                for row in conn.execute(
                        "SELECT state, COUNT(*) n FROM action_request "
                        "GROUP BY state"):
                    counts[row["state"]] = row["n"]
                out["counts"] = counts
                out["awaiting_decision"] = counts["pending"]
                out["awaiting_execution"] = counts["approved"]
    except Exception as e:
        out["blind"] = True
        out["blind_reason"] = (f"The action queue could not be read at all "
                               f"({e})")
    return out


# EXPIRY — the clock that retires, and never the clock that approves

def expire_stale(session_id: str = "expiry") -> dict:
    """
    Retire pending requests older than the expiry window. They never run.
    """
    days = _expiry_days()
    cutoff = _sql_ts(_now() - timedelta(days=days))
    now = _sql_ts(_now())

    with me._get_conn() as conn:
        if not _table_ready(conn):
            return {"expired": 0, "note": "the action_request table does not "
                                          "exist"}
        cur = conn.execute("""
            UPDATE action_request
               SET state = 'expired', executed_at = NULL,
                   outcome = 'not_attempted',
                   error = ?
             WHERE state = 'pending' AND created_at < ?
        """, (f"Nobody answered this within {days} days. It was NOT "
              f"executed and it is NOT a denial, no decision was made. "
              f"Retired {now}.", cutoff))
        count = cur.rowcount or 0

    if count:
        logger.info("Retired %d unanswered action request(s) older than %d "
                    "days. None of them ran.", count, days)
    return {"expired": count, "after_days": days,
            "note": ("Expired means NOT APPROVED AND NOT DENIED. An expired "
                     "request never executed and never will.")}


# READING THE QUEUE

def _decode(row: dict) -> dict:
    for field, key in (("params_json", "params"),
                       ("evidence_json", "evidence"),
                       ("result_json", "result")):
        if field in row:
            try:
                row[key] = json.loads(row.pop(field) or "null")
            except (TypeError, ValueError):
                row[key] = None
    return row


def query_requests(state: str = None, request_id: int = None,
                   limit: int = 50, include_decided: bool = True) -> list:
    """
    The queue, newest first, each row with its card.
    """
    where, params = [], []
    if request_id is not None:
        where.append("id = ?")
        params.append(int(request_id))
    elif state:
        where.append("state = ?")
        params.append(state)
    elif not include_decided:
        where.append("state IN ('pending','approved')")

    sql = "SELECT * FROM action_request"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(int(limit or 50), 500)))

    with me._get_readonly_conn() as conn:
        if not _table_ready(conn):
            return []
        rows = me._rows_to_dicts(conn.execute(sql, params).fetchall())

    out = []
    for row in rows:
        row = _decode(row)
        row["card"] = card_for(row)
        out.append(row)
    return out


# The card: the same shape the chat's permission card uses, built from a
# database row, plus when it was proposed and what it rests on.

def card_for(request_row: dict) -> dict:
    """
    One stored request as the permission card the page already renders.
    Reads params and evidence in either stored shape.
    """
    verb = request_row.get("verb")
    params = request_row.get("params")
    if not isinstance(params, dict):
        try:
            params = json.loads(request_row.get("params_json") or "{}")
        except (TypeError, ValueError):
            params = {}

    action = describe(verb, params)
    reason = (request_row.get("reason") or "").strip() or "No reason given."
    created = request_row.get("created_at")

    card = {
        # req- prefix, so a queue card can never be posted to the chat approval route.
        "call_id":   f"req-{request_row.get('id')}",
        "request_id": request_row.get("id"),
        "tool":      verb,
        "action":    action,
        "params":    params,
        "reason":    reason,
        "kind":      "queued",
        "source":    "action_queue",
        "proposed_by": request_row.get("proposed_by") or "model",
        "proposed_at": created,
        "state":     request_row.get("state"),
        "requires_admin": verb in ("kill_process", "block_port",
                                   "block_device"),
    }

    # What the request rests on, shown because the person deciding needs it.
    evidence = request_row.get("evidence")
    if evidence is None:
        try:
            evidence = json.loads(request_row.get("evidence_json") or "null")
        except (TypeError, ValueError):
            evidence = None
    if evidence:
        card["evidence"] = evidence

    incident_id = request_row.get("incident_id")
    if incident_id:
        card["incident_id"] = incident_id

    # THE LINE THAT MAKES A QUEUE CARD HONEST. It is not holding anybody's
    # chat open, so the ordinary reason a card is urgent does not apply, and
    # there is exactly as much time as the operator wants.
    card["waiting_note"] = (
        "Nothing is waiting on this. No chat turn is open, nothing is "
        "mid-action, and there is no clock counting down. Look it up before "
        "you decide."
    )

    if verb == "block_device":
        # The limit, on the card, for the same reason the chat card carries it:
        # a host-level ban reads as "thrown off the network" and it is not.
        card["warning"] = (
            "This blocks that address at THIS machine's firewall, both "
            "directions. It does not cut the device off the internet and it "
            "does not stop it reaching your other devices, because that "
            "traffic does not pass through here. Only the router can do that.")
    return card


# THE ACTION LINE, one implementation, shared by the card, the dashboard table
# and the desktop notification.
def unit_warning_line(facts: dict) -> str:
    """
    The sentence about a pid's systemd unit, shared by the chat and queue cards.
    """
    if not isinstance(facts, dict):
        return ""
    verdict = facts.get("verdict")
    unit = facts.get("unit")
    if verdict == "supervised" and unit:
        return (f". WARNING: this process belongs to {unit}, which is set to "
                f"RESTART IT, so killing it will NOT stop the service. "
                f"Refusing this and using stop_service on that unit is what "
                f"actually ends it")
    if verdict == "supervised_no_restart" and unit:
        return (f". It is part of {unit}, which does not restart it, so this "
                f"kill holds")
    if verdict == "unknown":
        return (f". WHETHER IT STAYS KILLED IS UNKNOWN: "
                f"{facts.get('verdict_reason')}")
    return ""


def _kill_unit_warning(pid, name: str = None) -> str:
    """
    The unit sentence for a pid, read live. Never raises.
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return ""
    try:
        from tools import systemd_units as sd
        facts = sd.unit_state(pid)
    except Exception as e:                                  # noqa: BLE001
        logger.debug(f"Could not read the unit for PID {pid}: {e}")
        return ""
    return unit_warning_line(facts)


def describe(verb: str, params: dict) -> str:
    """
    One sentence saying what the request would do. A missing subject is
    said in words, never rendered as '?'.
    """
    params = params or {}

    def missing(field):
        return (f"{verb or 'this action'} has no {field} recorded. THIS CARD "
                f"CANNOT TELL YOU WHAT WOULD BE AFFECTED. Deny it and ask for "
                f"the request to be filed again.")

    if verb == "kill_process":
        pid = params.get("pid")
        if pid in (None, ""):
            return missing("pid")
        # Asked live when the card is rendered: whether the pid's unit would restart
        # it, so a queued kill never looks like a stop.
        name = params.get("expected_name")
        label = f"{name} (PID {pid})" if name else f"PID {pid}"
        return f"Kill process {label}" + _kill_unit_warning(pid)
    if verb == "block_device":
        ip = params.get("ip")
        return (f"Block {ip} at this host's firewall" if ip not in (None, "")
                else missing("address"))
    if verb == "block_port":
        port, direction = params.get("port"), params.get("direction")
        if port in (None, "") or direction in (None, ""):
            return missing("port or direction")
        return f"Block port {port} ({direction})"
    if verb == "quarantine_file":
        path = params.get("file_path")
        return (f"Quarantine file: {path}" if path not in (None, "")
                else missing("file path"))
    if verb == "gateway_block_device":
        ip = params.get("ip")
        return (f"Block {ip} at the router" if ip not in (None, "")
                else missing("address"))
    if verb == "gateway_sinkhole_domain":
        domain = params.get("domain")
        return (f"Sinkhole {domain} at the router's resolver"
                if domain not in (None, "") else missing("domain"))
    if verb in ("remove_ssh_key", "lock_account", "remove_group_member",
                "disable_cron_line", "disable_service"):
        from core import tool_registry
        need = QUEUEABLE[verb]["needs"]
        gap = [k for k in need if params.get(k) in (None, "")]
        return (missing(" and ".join(gap)) if gap
                else tool_registry.permission_summary(verb, params))
    if verb == "stop_service":
        unit = params.get("unit")
        return (f"Stop the systemd unit {unit}"
                + (f" (reason: {params.get('reason')})"
                   if params.get("reason") else "")
                if unit not in (None, "") else missing("unit name"))
    return f"{verb or 'unknown action'} {params or ''}".strip()


# Desktop notification. A doorbell, not a control: every failure (no
# notify-send, no session, non-zero exit) is reported, never assumed sent.

_notify_warned = {}


def _desktop_user():
    """(uid, gid, home) of the user who ran sudo, when this runs as root.

    Root has no session bus of its own, so a notice sent as root reaches
    nobody. None when not root or when no desktop user can be named.
    """
    if os.geteuid() != 0:
        return None
    raw = os.environ.get("SUDO_UID") or os.environ.get("PKEXEC_UID") or ""
    try:
        uid = int(raw)
        pw = pwd.getpwuid(uid)
    except (ValueError, KeyError):
        return None
    if uid == 0:
        return None
    return uid, pw.pw_gid, pw.pw_dir


def notify(title: str, body: str, urgency: str = "normal") -> dict:
    """
    Show a desktop notification. Returns {'sent': bool, 'reason': ...};
    never raises and never claims success without exit code 0.
    """
    if not _notifications_enabled():
        return {"sent": False, "reason": "notifications are switched off in "
                                         "config.json (action_queue.notify)"}

    binary = shutil.which("notify-send")
    if not binary:
        if not _notify_warned.get("missing"):
            _notify_warned["missing"] = True
            logger.warning(
                "notify-send is not installed, so desktop notifications for "
                "action requests CANNOT be shown. The cards are still on the "
                "Action Queue tab and that is where the decision is made.")
        return {"sent": False,
                "reason": ("notify-send is not installed on this machine, so "
                           "nothing was shown on the desktop.")}

    # The display and session bus are passed explicitly: a launcher, cron or
    # sudo does not always inherit them.
    env = dict(os.environ)
    env.setdefault("DISPLAY", ":0")
    as_user = _desktop_user()
    run_as = {}
    if as_user:
        # Running as root under sudo: send it as the desktop user, on that
        # user's own bus.
        uid, gid, home = as_user
        runtime = f"/run/user/{uid}"
        env.update(XDG_RUNTIME_DIR=runtime, HOME=home,
                   DBUS_SESSION_BUS_ADDRESS=f"unix:path={runtime}/bus")
        run_as = {"user": uid, "group": gid, "extra_groups": []}
    elif not env.get("DBUS_SESSION_BUS_ADDRESS"):
        runtime = env.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
        bus = os.path.join(runtime, "bus")
        if os.path.exists(bus):
            env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus}"

    cmd = [binary,
           "--app-name=AgentalSec",
           f"--urgency={urgency}",
           title, body]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10,
                              env=env, **run_as)
    except Exception as e:
        logger.warning(f"notify-send could not be run: {e}")
        return {"sent": False, "reason": f"notify-send could not be run: {e}"}

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[:300]
        logger.warning("notify-send exited %s: %s", proc.returncode, detail)
        return {"sent": False, "returncode": proc.returncode,
                "reason": (f"notify-send exited {proc.returncode}"
                           + (f": {detail}" if detail else "")
                           + ". Nothing was shown on the desktop.")}

    return {"sent": True}


def announce(request_row: dict) -> dict:
    """
    Notify that a request is waiting.
    """
    card = card_for(request_row)
    title = "AgentalSec: an action needs your approval"
    body = card["action"]
    if card.get("reason"):
        body += f"\n{card['reason'][:140]}"
    return notify(title, body, urgency="normal")


def announce_result(request_row: dict, outcome: str,
                    detail: str = None) -> dict:
    """
    Notify how an approved request ended: ran, refused or failed.
    """
    if outcome == "success":
        title = "AgentalSec: approved action ran"
    elif outcome == "refused":
        title = "AgentalSec: approved action was REFUSED"
    else:
        title = "AgentalSec: approved action FAILED"

    body = describe(request_row.get("verb"), request_row.get("params") or {})
    if detail:
        body += f"\n{str(detail)[:160]}"
    urgency = "critical" if outcome != "success" else "normal"
    return notify(title, body, urgency=urgency)


# THE DASHBOARD'S READ

def pending_count() -> int:
    """
    Requests waiting on the operator. 0 on a failed read.
    """
    try:
        with me._get_readonly_conn() as conn:
            if not _table_ready(conn):
                return 0
            return conn.execute(
                "SELECT COUNT(*) FROM action_request WHERE state = 'pending'"
            ).fetchone()[0]
    except Exception as e:
        logger.debug(f"pending_count could not read the queue: {e}")
        return 0


def summary() -> dict:
    """
    Counts per state for the badge, never summed together.
    """
    with me._get_readonly_conn() as conn:
        if not _table_ready(conn):
            return {"available": False,
                    "note": ("the action_request table does not exist yet, so "
                             "nothing has been filed. This is not zero "
                             "requests awaiting a decision.")}
        counts = {s: 0 for s in REQUEST_STATES}
        for row in conn.execute(
                "SELECT state, COUNT(*) n FROM action_request GROUP BY state"):
            counts[row["state"]] = row["n"]

        waiting = me._rows_to_dicts(conn.execute("""
            SELECT id, verb, target, reason, created_at, proposed_by,
                   incident_id
              FROM action_request
             WHERE state = 'pending'
             ORDER BY id DESC LIMIT 20
        """).fetchall())

    return {
        "available": True,
        **counts,
        "awaiting_decision": counts["pending"],
        "awaiting_execution": counts["approved"],
        "pending_list": waiting,
        "how_to_read_this": (
            "pending is waiting on the operator and nothing has run. approved "
            "is waiting on the executor, approval is a decision, NOT the "
            "action. executed ran and the outcome on the row says whether it "
            "worked. denied and expired both mean it did NOT run and they are "
            "never added together: denied is a person saying no, expired is "
            "nobody saying anything."),
    }


def last_notification_status() -> dict:
    """What the notification path last did, for the settings page."""
    return {
        "enabled": _notifications_enabled(),
        "binary": shutil.which("notify-send"),
        "display": os.environ.get("DISPLAY") or ":0",
        "note": ("A notification is a doorbell and not a control. Nothing is "
                 "decided from a bubble: the card is on the Action Queue tab, "
                 "and that is where it is approved or denied."),
    }
