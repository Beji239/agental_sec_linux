# core/module_feed.py
# What a module may read from the app: urgent incidents, a short status and
# the open decisions. Read only, built from the same tables the tabs use,
# except decide(), which goes through the same calls as the console.

import json
import logging
import re
import threading

from core import memory_engine as me

logger = logging.getLogger(__name__)

_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _rank(severity) -> int:
    return _RANK.get(str(severity or "").lower(), 3)


def _ready(conn, table: str) -> bool:
    return me._table_exists_ro(conn, table)


def alerts(after_id: int = None, since: str = None, floor: str = "high",
           limit: int = 50) -> dict:
    """Incidents at or above the floor: new ones after after_id, plus older
    ones seen again since `since`, so a raised severity reaches the module
    too. Times are whole seconds, so `since` itself is included; the module
    skips what it already sent."""
    floor_rank = _rank(floor)
    limit = max(1, min(int(limit or 50), 200))
    cols = ("id, detection_id, entity_type, entity_value, severity, "
            "severity_rank, title, first_seen_at, last_seen_at, status, "
            "finding_count")
    with me._get_readonly_conn() as conn:
        if not _ready(conn, "incident"):
            return {"available": False, "max_id": 0, "max_seen": None,
                    "incidents": []}
        max_id, max_seen = conn.execute(
            "SELECT COALESCE(MAX(id), 0), MAX(last_seen_at) FROM incident"
        ).fetchone()
        if after_id is None:
            return {"available": True, "max_id": max_id,
                    "max_seen": max_seen, "incidents": []}
        rows = me._rows_to_dicts(conn.execute(
            f"SELECT {cols} FROM incident WHERE id > ? AND severity_rank >= ? "
            f"AND suppressed = 0 AND status != 'dismissed' ORDER BY id LIMIT ?",
            (int(after_id), floor_rank, limit)).fetchall())
        if since:
            rows += me._rows_to_dicts(conn.execute(
                f"SELECT {cols} FROM incident WHERE id <= ? AND severity_rank >= ? "
                f"AND suppressed = 0 AND status IN ('new','triaged','action_pending') "
                f"AND last_seen_at >= ? ORDER BY id LIMIT ?",
                (int(after_id), floor_rank, str(since), limit)).fetchall())
    return {"available": True, "max_id": max_id, "max_seen": max_seen,
            "incidents": rows}


def status() -> dict:
    """A few lines for /status on the phone."""
    out = {"version": None, "incidents": None, "worst_open": [],
           "actions_waiting": 0, "questions_open": 0, "devices_held": 0}
    try:
        from core import version
        out["version"] = version.current().get("label")
    except Exception as e:                              # noqa: BLE001
        logger.debug(f"version unreadable for the module feed: {e}")
    with me._get_readonly_conn() as conn:
        if _ready(conn, "incident"):
            counts = {r["status"]: r["n"] for r in conn.execute(
                "SELECT status, COUNT(*) n FROM incident GROUP BY status")}
            out["incidents"] = {
                "open": sum(counts.get(s, 0) for s in
                            ("new", "triaged", "action_pending")),
                "new": counts.get("new", 0),
            }
            out["worst_open"] = me._rows_to_dicts(conn.execute(
                "SELECT id, severity, title, last_seen_at FROM incident "
                "WHERE status IN ('new','triaged','action_pending') "
                "AND suppressed = 0 "
                "ORDER BY severity_rank DESC, last_seen_at DESC LIMIT 3").fetchall())
            last = conn.execute("SELECT MAX(last_seen_at) FROM incident").fetchone()[0]
            out["last_incident_at"] = last
        if _ready(conn, "action_request"):
            out["actions_waiting"] = conn.execute(
                "SELECT COUNT(*) FROM action_request WHERE state = 'pending'"
            ).fetchone()[0]
        if _ready(conn, "operator_question"):
            out["questions_open"] = conn.execute(
                "SELECT COUNT(*) FROM operator_question WHERE state = 'open'"
            ).fetchone()[0]
        if _ready(conn, "device_hold"):
            out["devices_held"] = conn.execute(
                "SELECT COUNT(*) FROM device_hold WHERE status = 'held'"
            ).fetchone()[0]
    return out


# Verbs that cannot be undone. The phone asks for the PIN and a fresh code
# again for these, even inside a control session. The deletion list comes
# with the antivirus module; nothing filable today deletes.
ASK_AGAIN = frozenset({"delete_file"})
_DETAIL_KEYS = ("file_path", "path", "name", "sha256", "hash", "unit", "user",
                "ip", "domain", "pid", "expected_name")


def pending(limit: int = 10) -> dict:
    """Open decisions, with what the phone needs to offer each one."""
    limit = max(1, min(int(limit or 10), 30))
    out = {"actions": [], "questions": [], "devices": []}
    with me._get_readonly_conn() as conn:
        if _ready(conn, "action_request"):
            has_inc = "incident_id" in {r[1] for r in conn.execute(
                "PRAGMA table_info(action_request)")}
            rows = me._rows_to_dicts(conn.execute(
                "SELECT id, verb, target, params_json, reason, created_at"
                + (", incident_id " if has_inc else " ") +
                "FROM action_request WHERE state = 'pending' "
                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall())
            from core import actions
            for r in rows:
                try:
                    params = json.loads(r.get("params_json") or "{}")
                    what = actions.describe(r["verb"], params)
                except Exception:                       # noqa: BLE001
                    params = {}
                    what = f"{r['verb']} {r['target']}"
                detail = {k: str(params[k])[:300] for k in _DETAIL_KEYS
                          if params.get(k) not in (None, "")}
                out["actions"].append({"id": r["id"], "verb": r["verb"],
                                       "what": what, "detail": detail,
                                       "asks_again": r["verb"] in ASK_AGAIN,
                                       "incident_id": r.get("incident_id"),
                                       "reason": (r["reason"] or "")[:300],
                                       "created_at": r["created_at"]})
        if _ready(conn, "operator_question"):
            out["questions"] = me._rows_to_dicts(conn.execute(
                "SELECT id, topic, entity_type, entity_value, question, "
                "why_stuck, asked_at FROM operator_question "
                "WHERE state = 'open' ORDER BY id DESC LIMIT ?", (limit,)).fetchall())
        if _ready(conn, "device_hold"):
            cols = {r[1] for r in conn.execute("PRAGMA table_info(device_hold)")}
            pick = [c for c in ("mac", "ip", "vendor", "hostname", "held_at") if c in cols]
            if pick:
                out["devices"] = me._rows_to_dicts(conn.execute(
                    f"SELECT {', '.join(pick)} FROM device_hold "
                    f"WHERE status = 'held' LIMIT ?", (limit,)).fetchall())
    return out


def incident(incident_id: int) -> dict:
    """One incident, for the phone to show again before a verdict."""
    with me._get_readonly_conn() as conn:
        if not _ready(conn, "incident"):
            return {}
        cols = {r[1] for r in conn.execute("PRAGMA table_info(incident)")}
        pick = [c for c in ("id", "detection_id", "entity_type", "entity_value",
                            "severity", "title", "status", "last_seen_at",
                            "verdict") if c in cols]
        row = conn.execute(f"SELECT {', '.join(pick)} FROM incident WHERE id = ?",
                           (int(incident_id),)).fetchone()
    return dict(row) if row else {}


def _who(person) -> str:
    return re.sub(r"[^\w .'-]", "", str(person or ""))[:40].strip() or "someone"


def decide(kind: str, ref, choice: str, person: str, text: str = None) -> dict:
    """A decision from a phone, through the same calls the console uses.
    The module has already checked the PIN and code; this checks the rest."""
    who = _who(person)
    note = f"From the phone by {who}."
    try:
        if kind == "action":
            if choice not in ("approve", "deny"):
                return {"ok": False, "detail": "approve or deny"}
            from core import actions
            if choice == "deny":
                note += " " + ((text or "").strip()[:300] or "No reason given.")
            out = actions.decide(int(ref), approved=choice == "approve",
                                 decided_by="user", note=note)
            return {"ok": bool(out.get("success")),
                    "detail": out.get("error") or out.get("state"), "result": out}
        if kind == "question":
            from core import questions
            if choice == "dont_know":
                out = questions.answer(int(ref), do_not_know=True)
            elif choice in ("yes", "no"):
                out = questions.answer(int(ref), answer_text=choice.title(),
                                       verdict=choice)
            elif choice == "text" and (text or "").strip():
                out = questions.answer(int(ref), answer_text=text.strip()[:1000])
            else:
                return {"ok": False, "detail": "yes, no, dont_know or text"}
            return {"ok": bool(out.get("success")),
                    "detail": out.get("error") or out.get("state"), "result": out}
        if kind == "verdict":
            from core import incident as inc
            out = inc.set_verdict(int(ref), str(choice), by="owner", note=note)
            return {"ok": bool(out.get("success")),
                    "detail": out.get("error") or out.get("verdict"), "result": out}
        if kind == "release":
            if choice != "release":
                return {"ok": False, "detail": "release"}
            from core import device_hold
            out = device_hold.release(str(ref), by=f"phone: {who}")
            return {"ok": bool(out.get("success")),
                    "detail": out.get("error") or "released", "result": out}
    except (TypeError, ValueError) as e:
        return {"ok": False, "detail": f"bad reference: {e}"}
    return {"ok": False, "detail": f"unknown kind {kind}"}


# Chat from the phone. The agent gets the duty loop's read tools and
# file_action_request; what it files waits in /pending like anything else.
# It does not learn quiet rules or ask questions from here.
PHONE_LEAVES_OUT = frozenset({"learn_quiet_rule", "undo_learned_rule", "ask_operator"})
PHONE_ROUNDS = 6
PHONE_HISTORY = 8
PHONE_ANSWER_CHARS = 3500
PHONE_ADDENDUM = """

THIS TURN COMES FROM A PHONE. {who} is enrolled in the Remote module and has
a control session open; they are writing to you through a Telegram bot.
Answer in plain text, short enough to read on a phone: a few lines, no
tables, no headings. Telegram is not end to end encrypted, so never put a
key, password, token or the contents of a file in the answer. You cannot
change anything from here. If something should be done, file it with
file_action_request and say so; they can approve it from the phone with
/pending. Say plainly what you did not get to check."""

_phone_lock = threading.Lock()


def chat(person, text: str, history=None) -> dict:
    """One question from a phone, through the unattended turn. One at a
    time: a second question while one runs is turned away, not queued."""
    who = _who(person)
    text = (text or "").strip()
    if not text:
        return {"ok": False, "detail": "an empty question"}
    if not _phone_lock.acquire(blocking=False):
        return {"ok": False, "busy": True,
                "detail": "the agent is still answering another question from a phone"}
    try:
        from core import agent_loop, duty
        allow = tuple(n for n in duty._tool_allowlist() if n not in PHONE_LEAVES_OUT)
        earlier = []
        for m in (history or [])[-PHONE_HISTORY:]:
            if isinstance(m, dict) and m.get("role") in ("user", "assistant") \
                    and isinstance(m.get("content"), str):
                earlier.append({"role": m["role"], "content": m["content"][:4000]})
        out = agent_loop.run_unattended(
            text[:2000], agent_loop.get_session_id(), allow,
            extra_system=PHONE_ADDENDUM.format(who=who),
            max_rounds=PHONE_ROUNDS, history=earlier)
    except Exception as e:                              # noqa: BLE001
        logger.error(f"phone chat failed: {e}", exc_info=True)
        return {"ok": False, "detail": f"{type(e).__name__}: {e}"}
    finally:
        _phone_lock.release()
    answers = [a.strip() for a in out.get("answers") or [] if a.strip()]
    answer = answers[-1] if answers else ""
    if len(answer) > PHONE_ANSWER_CHARS:
        answer = answer[:PHONE_ANSWER_CHARS].rstrip() + "\n[cut short; the rest is too long for the phone]"
    usage = out.get("usage") or {}
    tools = out.get("tool_calls") or []
    logger.info(f"Phone chat for {who}: {len(tools)} tool call(s), "
                f"{usage.get('total_tokens', 0)} tokens"
                f"{', error: ' + out['error'] if out.get('error') else ''}")
    return {"ok": bool(answer), "answer": answer,
            "detail": out.get("error") or (None if answer else "the agent gave no answer"),
            "tokens": int(usage.get("total_tokens") or 0),
            "estimated": bool(usage.get("estimated", True)),
            "tools": tools[:40],
            "filed": tools.count("file_action_request")}
