# tools/background_actions_linux.py
# Block, disable and undo for background apps on Linux.
#
#   * safe_to_block may be blocked or disabled, block_not_disable only blocked,
#     leave never touched. A refusal happens here, before any approval card.
#   * disable: `systemctl disable` plus stop for a service or timer; for an
#     autostart entry, a copy in the user's ~/.config/autostart with
#     Hidden=true (what the desktop's Startup Applications does). Nothing is
#     uninstalled or masked.
#   * block: systemd's own IPAddressDeny=any (localhost still allowed) on the
#     service. systemd applies it at every start, so it holds across restarts
#     and reboots and works on a stopped service. Only system services.
#   * Every change is written to background_change BEFORE it runs, and every
#     step carries the step that undoes it, built from what was there before.
#   * The plan is always built from a fresh read, never from the caller's
#     words: the caller names an app, nothing else.

import base64
import json
import logging
import os
import pathlib
from datetime import datetime, timezone

from core import memory_engine as me
from tools import background_apps_linux as ba

logger = logging.getLogger(__name__)

ACTIONS = ("block", "disable")
STALE_MINUTES = 10
ENABLED_STATES = ("enabled", "enabled-runtime")
SHARED_PROGRAMS = {"sh", "bash", "python3", "python", "perl", "env", "dbus-daemon"}


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _is_stale(created_at) -> bool:
    try:
        t = datetime.strptime(str(created_at), "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc)
    except ValueError:
        return False
    return (datetime.now(timezone.utc) - t).total_seconds() > STALE_MINUTES * 60


def _fresh_snapshot(name=None):
    ba.invalidate_cache()
    return ba.snapshot(limit=ba.MAX_LIMIT, name=name)


def _is_root() -> bool:
    return os.geteuid() == 0


# What a row allows

def _disable_why_not(row):
    kind, t = row.get("owner_kind"), row.get("target") or {}
    if kind in ("service", "timer"):
        state = t.get("unit_file_state")
        if state in ENABLED_STATES:
            return None if _is_root() else "AgentalSec is not running as root, so it cannot change system units"
        if state in ("disabled", "masked") and t.get("active") != "active":
            return "it is already off"
        if state in ("static", "indirect", "generated", "transient", "alias"):
            return (f"its unit file is {state}: something else starts it, so "
                    f"there is no switch to turn off without masking it, and "
                    f"masking is not done here")
        return f"its unit file state ({state!r}) was not read, so it could not be put back"
    if kind == "autostart":
        if not t.get("enabled"):
            return "it is already off at login"
        return None if ba.user_autostart_dir() else "the desktop user could not be found"
    return f"a {kind} cannot be disabled from here"


def _block_why_not(row):
    if row.get("owner_kind") != "service":
        return ("only system services can be blocked on Linux: the network "
                "is cut per service, not per program")
    if not _is_root():
        return "AgentalSec is not running as root, so it cannot change system units"
    return None


def unit_ip_rules(unit):
    """(allow, deny) as systemd reports them now, or raises."""
    import subprocess
    p = subprocess.run(["systemctl", "show", "-p", "IPAddressAllow,IPAddressDeny",
                        unit], capture_output=True, text=True, timeout=30,
                       stdin=subprocess.DEVNULL)
    if p.returncode != 0:
        raise RuntimeError((p.stderr or "").strip() or "systemctl show failed")
    props = dict(line.split("=", 1) for line in p.stdout.splitlines() if "=" in line)
    return props.get("IPAddressAllow", "").strip(), props.get("IPAddressDeny", "").strip()


def active_changes() -> dict:
    """{(owner_kind, owner_name lower, action): change id} for changes in force."""
    try:
        with me._get_readonly_conn() as conn:
            rows = conn.execute(
                "SELECT id, owner_kind, owner_name, action FROM background_change "
                "WHERE state IN ('active','undo_failed','pending')").fetchall()
    except Exception:                                 # noqa: BLE001
        return {}
    return {(r[1], (r[2] or "").lower(), r[3]): r[0] for r in rows}


def done_note(row, active=None):
    active = active or {}
    out = []
    for action, word in (("block", "blocked"), ("disable", "disabled")):
        cid = active.get((row.get("owner_kind"),
                          (row.get("owner_name") or "").lower(), action))
        if cid:
            out.append(f"{word}, change #{cid}, see Undo")
    return "; ".join(out) or None


def allowed(row, active=None) -> list:
    """Which of block and disable this row allows. plan() checks again on the press."""
    active = active or {}
    tier = row.get("tier")
    want = {"safe_to_block": ["block", "disable"],
            "block_not_disable": ["block"]}.get(tier, [])
    out = [a for a in want
           if (_block_why_not(row) if a == "block" else _disable_why_not(row)) is None]
    key = (row.get("owner_kind"), (row.get("owner_name") or "").lower())
    return [a for a in out if (key[0], key[1], a) not in active]


def why_not(row) -> dict:
    """The reason each action is unavailable, for the page."""
    return {"block": _block_why_not(row), "disable": _disable_why_not(row)}


# The plan

def _find(snap, kind, name):
    k, n = (kind or "").strip().lower(), (name or "").strip().lower()
    for row in snap.get("actionable") or []:
        if row["owner_kind"] == k and (row["owner_name"] or "").lower() == n:
            return row, None
    for row in (snap.get("apps") or []) + (snap.get("not_running") or []):
        if row["owner_kind"] == k and (row["owner_name"] or "").lower() == n:
            return None, row
    return None, None


def _active_change(kind, name, action):
    try:
        with me._get_readonly_conn() as conn:
            r = conn.execute(
                "SELECT id, state, created_at FROM background_change WHERE "
                "owner_kind=? AND lower(owner_name)=lower(?) AND action=? AND "
                "state IN ('active','undo_failed','pending') ORDER BY id DESC LIMIT 1",
                (kind, name, action)).fetchone()
    except Exception as e:                            # noqa: BLE001
        raise RuntimeError(f"the change journal could not be read ({e})")
    return (r[0], r[1], r[2]) if r else None


def _refuse(msg):
    return {"ok": False, "error": msg, "steps": [], "row": None, "effect": None}


def _autostart_override_path(row):
    d = ba.user_autostart_dir()
    return str(d / (row["target"].get("file") or row["owner_name"] + ".desktop"))


def plan(action, owner_kind, owner_name, snap=None, ip_rules=None) -> dict:
    """What block or disable would do, step by step, with each undo. Changes nothing."""
    if action not in ACTIONS:
        return _refuse(f"Only block and disable exist here, got {action!r}. "
                       f"Uninstall and mask were left out on purpose.")
    snap = snap if snap is not None else _fresh_snapshot(owner_name)
    lst = (snap.get("sources") or {}).get("list") or {}
    if not lst.get("read"):
        return _refuse("The app list could not be read, so nothing may be "
                       "changed. " + (lst.get("why_not") or ""))

    row, other = _find(snap, owner_kind, owner_name)
    if row is None and other is not None:
        return _refuse(f"{owner_name} is Leave it ({other.get('tier_basis')}). "
                       f"Nothing here may block or disable it.")
    if row is None:
        need = {"service": "services", "timer": "timers",
                "autostart": "autostart"}.get((owner_kind or "").lower())
        if need and need in (snap.get("incomplete") or []):
            return _refuse(f"{owner_name} could not be looked up, because "
                           f"{ba.SOURCE_WORDS[need]} could not be read. That is "
                           f"not the same as it not being there. Nothing was changed.")
        return _refuse(f"{owner_name} ({owner_kind}) was not found in a fresh "
                       f"read of this machine, so nothing was planned.")

    if action == "disable" and row["tier"] == "block_not_disable":
        return _refuse(f"{owner_name} is Block, do not disable "
                       f"({row.get('tier_note') or row.get('tier_basis')}).")
    if action not in allowed(row):
        why = (_block_why_not(row) if action == "block"
               else _disable_why_not(row))
        if why is None and row["tier"] == "leave":
            why = "it is Leave it"
        if why:
            return _refuse(f"{owner_name} cannot be {action}ed: {why}.")

    try:
        prior = _active_change(row["owner_kind"], row["owner_name"], action)
    except RuntimeError as e:
        return _refuse(f"{e}, so it could not be checked whether this is "
                       f"already done. Nothing was changed.")
    if prior:
        cid, state, at = prior
        if state == "pending" and _is_stale(at):
            return _refuse(f"Change #{cid} on {owner_name} was cut off before it "
                           f"finished. Undo it first, then try again.")
        if state == "pending":
            return _refuse(f"{owner_name} is being changed right now (change #{cid}).")
        return _refuse(f"{owner_name} is already {action}ed (change #{cid}). "
                       f"Undo that first to redo it.")

    t = row.get("target") or {}
    kind = row["owner_kind"]
    steps = []
    if action == "block":
        unit = t["unit"]
        try:
            allow, deny = (ip_rules or unit_ip_rules)(unit)
        except Exception as e:                        # noqa: BLE001
            return _refuse(f"The network settings of {unit} could not be read "
                           f"({e}), so they could not be put back. Nothing was changed.")
        if allow or deny:
            return _refuse(f"{unit} already has its own address rules "
                           f"(IPAddressAllow={allow or '-'}, IPAddressDeny={deny or '-'}). "
                           f"They were set outside AgentalSec and are left alone.")
        steps.append({
            "desc": f"cut the network of the {unit} service (systemd "
                    f"IPAddressDeny=any, localhost still allowed)",
            "do": {"op": "unit_net", "unit": unit, "cut": True},
            "undo": {"op": "unit_net", "unit": unit, "cut": False}})
    elif kind in ("service", "timer"):
        unit, before = t["unit"], t.get("unit_file_state")
        steps.append({
            "desc": f"stop {unit} starting at boot (it was {before})",
            "do": {"op": "unit_file", "unit": unit, "state": "disable"},
            "undo": {"op": "unit_file", "unit": unit, "state": "enable"}})
        if t.get("active") == "active":
            steps.append({
                "desc": f"stop {unit} now",
                "do": {"op": "unit_run", "unit": unit, "action": "stop"},
                "undo": {"op": "unit_run", "unit": unit, "action": "start"},
                # A disabled unit is enabled again before it is started.
                "undo_last": True})
    elif kind == "autostart":
        path = _autostart_override_path(row)
        try:
            before = pathlib.Path(path).read_bytes()
        except FileNotFoundError:
            before = None
        except OSError as e:
            return _refuse(f"{path} could not be read ({e}), so it could not be "
                           f"put back. Nothing was changed.")
        steps.append({
            "desc": f"switch off {row.get('display_name') or owner_name} at login "
                    f"(Hidden=true in {path})",
            "do": {"op": "autostart_hide", "path": path,
                   "source": t.get("path")},
            "undo": {"op": "autostart_restore", "path": path,
                     "content_b64": (base64.b64encode(before).decode()
                                     if before is not None else None)}})
        for pid in row.get("pids") or []:
            proc = next((p for p in (snap.get("apps") or [])
                         if p["owner_name"] == row["owner_name"]), None)
            name = next((p["name"] for p in (proc or {}).get("processes", [])
                         if p["pid"] == pid), t.get("program"))
            if (name or "").lower() in SHARED_PROGRAMS:
                continue
            steps.append({
                "desc": f"end the running copy, {name} pid {pid}",
                "do": {"op": "process_end", "pid": pid, "expected_name": name},
                "undo": {"op": "noop"}, "soft": True})

    if not steps:
        return _refuse(f"Nothing to do for {owner_name}.")

    if action == "block":
        what = ("\n\nBlock cuts its network. The service keeps running, it just "
                "cannot reach anything but this machine, and that holds across "
                "restarts and reboots.")
    elif kind == "autostart":
        what = "\n\nIt will not start at your next login."
    else:
        what = "\n\nIt will not start at the next boot either."
    effect = ("This will:\n" + "\n".join(f"  {i + 1}. {s['desc']}"
                                        for i, s in enumerate(steps))
              + what
              + f"\n\nTier: {row['tier_label']}. {row.get('tier_note') or ''}".rstrip()
              + "\n\nUndo puts every setting back the way it was. Nothing is "
                "uninstalled.")
    return {"ok": True, "error": None, "steps": steps, "row": row,
            "effect": effect}


# Running it

class Executor:
    """The real side effects. Tests hand in a fake with the same methods."""

    def _systemctl(self, *args):
        import subprocess
        p = subprocess.run(["systemctl", *args], capture_output=True,
                           text=True, timeout=60, stdin=subprocess.DEVNULL)
        if p.returncode != 0:
            raise RuntimeError((p.stderr or p.stdout or "").strip()[:300]
                               or f"systemctl {' '.join(args)} exited {p.returncode}")

    def unit_file(self, unit, state):
        self._systemctl(state, unit)

    def unit_run(self, unit, action):
        self._systemctl(action, unit)

    def unit_net(self, unit, cut):
        if cut:
            self._systemctl("set-property", unit, "IPAddressAllow=localhost",
                            "IPAddressDeny=any")
        else:
            self._systemctl("set-property", unit, "IPAddressAllow=",
                            "IPAddressDeny=")
            # set-property leaves drop-ins behind; remove ours so nothing lingers.
            d = pathlib.Path("/etc/systemd/system.control") / f"{unit}.d"
            for name in ("50-IPAddressAllow.conf", "50-IPAddressDeny.conf"):
                (d / name).unlink(missing_ok=True)
            try:
                d.rmdir()
            except OSError:
                pass
            self._systemctl("daemon-reload")
        allow, deny = unit_ip_rules(unit)
        if cut and not deny:
            raise RuntimeError(f"systemd accepted the change but {unit} reports "
                               f"no IPAddressDeny, so it is not reported as cut")
        if not cut and (allow or deny):
            raise RuntimeError(f"{unit} still reports IPAddressAllow={allow!r} "
                               f"IPAddressDeny={deny!r}")

    def _own(self, path):
        acct = ba.owner_account()
        if acct and _is_root():
            os.chown(path, acct.pw_uid, acct.pw_gid)

    def autostart_hide(self, path, source):
        p = pathlib.Path(path)
        if p.exists():
            text = p.read_text(encoding="utf-8", errors="replace")
        elif source and pathlib.Path(source).exists():
            text = pathlib.Path(source).read_text(encoding="utf-8", errors="replace")
        else:
            text = "[Desktop Entry]\nType=Application\n"
        lines = [line for line in text.splitlines()
                 if not line.startswith("Hidden=")]
        at = next((i for i, line in enumerate(lines)
                   if line.strip() == "[Desktop Entry]"), None)
        if at is None:
            lines = ["[Desktop Entry]", "Hidden=true"] + lines
        else:
            lines.insert(at + 1, "Hidden=true")
        new_dir = not p.parent.exists()
        p.parent.mkdir(parents=True, exist_ok=True)
        if new_dir:
            self._own(p.parent)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self._own(p)

    def autostart_restore(self, path, content_b64):
        p = pathlib.Path(path)
        if content_b64 is None:
            p.unlink(missing_ok=True)
        else:
            p.write_bytes(base64.b64decode(content_b64))
            self._own(p)

    def process_end(self, pid, expected_name):
        import psutil
        proc = psutil.Process(pid)
        if expected_name and proc.name() != expected_name:
            raise RuntimeError(f"pid {pid} is now {proc.name()}, not "
                               f"{expected_name}, so it was left alone")
        proc.terminate()


def _run_op(ex, op):
    """(ok, error) for one step. Never raises."""
    name = op["op"]
    try:
        if name == "noop":
            return True, None
        if name == "process_end":
            try:
                ex.process_end(op["pid"], op.get("expected_name"))
            except Exception as e:                    # noqa: BLE001
                if type(e).__name__ == "NoSuchProcess":
                    return True, None
                raise
            return True, None
        fn = getattr(ex, name, None)
        if fn is None:
            return False, f"unknown step {name!r}"
        fn(**{k: v for k, v in op.items() if k != "op"})
        return True, None
    except Exception as e:                            # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"


def _undo_order(steps):
    rev = list(reversed(steps))
    return [s for s in rev if not s.get("undo_last")] + \
           [s for s in rev if s.get("undo_last")]


def _journal_insert(p, action, reason, requested_by):
    row = p["row"]
    with me._get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO background_change (created_at, requested_by, action, "
            "owner_kind, owner_name, display_name, tier, reason, steps_json, "
            "state) VALUES (?,?,?,?,?,?,?,?,?,'pending')",
            (_now(), requested_by, action, row["owner_kind"], row["owner_name"],
             row.get("display_name"), row["tier"], reason,
             json.dumps(p["steps"])))
        return cur.lastrowid


def _journal_update(cid, **fields):
    cols = ", ".join(f"{k}=?" for k in fields)
    with me._get_conn() as conn:
        conn.execute(f"UPDATE background_change SET {cols} WHERE id=?",
                     list(fields.values()) + [cid])


def _record(event, cid, payload):
    try:
        from core import integrity
        integrity.record(event, table_name="background_change", row_ref=cid,
                         payload=payload)
    except Exception as e:                            # noqa: BLE001
        logger.warning("integrity record for %s failed: %s", event, e)


def apply(action, owner_kind, owner_name, reason=None, requested_by="agent",
          snap=None, executor=None, ip_rules=None) -> dict:
    """Plan again from a fresh read, write the record, then run the steps.
    A failed step rolls back the ones before it."""
    if requested_by not in ("user", "agent"):
        requested_by = "agent"
    p = plan(action, owner_kind, owner_name, snap=snap, ip_rules=ip_rules)
    if not p["ok"]:
        return {"ok": False, "error": p["error"]}
    try:
        cid = _journal_insert(p, action, reason, requested_by)
    except Exception as e:                            # noqa: BLE001
        return {"ok": False, "error": (f"The change record could not be written "
                                       f"({e}), so nothing was changed.")}
    ex = executor or Executor()
    done, notes = [], []
    for step in p["steps"]:
        ok, err = _run_op(ex, step["do"])
        if ok:
            done.append(step)
            continue
        if step.get("soft"):
            notes.append(f"Could not end {step['do'].get('expected_name')} pid "
                         f"{step['do'].get('pid')} ({err}). The setting stands; "
                         f"it stops for good at the next login.")
            continue
        back = []
        for d in _undo_order(done):
            ok2, err2 = _run_op(ex, d["undo"])
            if not ok2:
                back.append(f"putting back '{d['desc']}' also failed: {err2}")
        rolled = ("The steps before it were rolled back." if not back
                  else "Rollback was not clean: " + "; ".join(back))
        msg = f"'{step['desc']}' failed: {err}. {rolled}"
        _journal_update(cid, state="failed", error=msg, finished_at=_now())
        _record("background_change_failed", cid,
                {"action": action, "owner": owner_name, "error": msg})
        ba.invalidate_cache()
        return {"ok": False, "change_id": cid, "error": msg}
    _journal_update(cid, state="active", finished_at=_now(),
                    error=(" ".join(notes) or None))
    _record("background_change_applied", cid,
            {"action": action, "owner_kind": owner_kind, "owner": owner_name,
             "by": requested_by, "steps": [s["desc"] for s in p["steps"]]})
    ba.invalidate_cache()
    return {"ok": True, "change_id": cid, "effect": p["effect"],
            "note": (" ".join(notes) + " " if notes else "")
                    + "Done. It shows in the undo list on the Processes tab."}


def undo(change_id, reason=None, executor=None) -> dict:
    """Put one change back, step by step, in reverse."""
    try:
        cid = int(change_id)
    except (TypeError, ValueError):
        return {"ok": False, "error": f"change_id must be a number, got {change_id!r}"}
    with me._get_readonly_conn() as conn:
        row = conn.execute("SELECT * FROM background_change WHERE id=?",
                           (cid,)).fetchone()
    if row is None:
        return {"ok": False, "error": f"No change #{cid} on record."}
    if row["state"] == "pending" and not _is_stale(row["created_at"]):
        return {"ok": False, "error": f"Change #{cid} is still running."}
    if row["state"] not in ("active", "undo_failed", "pending"):
        return {"ok": False, "error": (f"Change #{cid} is {row['state']}. Only "
                                       f"an active change can be undone.")}
    ex = executor or Executor()
    errors = []
    for step in _undo_order(json.loads(row["steps_json"] or "[]")):
        ok, err = _run_op(ex, step["undo"])
        if not ok:
            errors.append(f"'{step['desc']}': {err}")
    ba.invalidate_cache()
    if errors:
        msg = "Could not put back " + "; ".join(errors)
        _journal_update(cid, state="undo_failed", undo_error=msg,
                        undo_reason=reason, undone_at=_now())
        _record("background_change_undo_failed", cid, {"error": msg})
        return {"ok": False, "change_id": cid, "error": msg}
    _journal_update(cid, state="undone", undo_reason=reason, undone_at=_now(),
                    undo_error=None)
    _record("background_change_undone", cid,
            {"owner": row["owner_name"], "reason": reason})
    return {"ok": True, "change_id": cid,
            "note": f"{row['owner_name']} is back the way it was."}


def list_changes(limit=50) -> dict:
    try:
        with me._get_readonly_conn() as conn:
            rows = [dict(r) for r in conn.execute(
                "SELECT id, created_at, requested_by, action, owner_kind, "
                "owner_name, display_name, tier, reason, state, error, "
                "finished_at, undone_at, undo_error, steps_json FROM "
                "background_change ORDER BY id DESC LIMIT ?",
                (max(1, min(int(limit or 50), 500)),)).fetchall()]
    except Exception as e:                            # noqa: BLE001
        return {"read": False, "why_not": str(e), "changes": []}
    for r in rows:
        r["steps"] = [s.get("desc") for s in json.loads(r.pop("steps_json") or "[]")]
        r["stale"] = r["state"] == "pending" and _is_stale(r["created_at"])
        r["can_undo"] = r["state"] in ("active", "undo_failed") or r["stale"]
        r["note"] = ("cut off before it finished. Some steps may be in force; "
                     "Undo puts back anything it had done." if r["stale"] else None)
    return {"read": True, "why_not": None, "changes": rows}
