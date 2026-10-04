# tools/action_broker.py
# The app's side of the root action helper (tools/action_helper.py).
#
# One password per run of the app. The first approved action that needs root
# starts the helper through pkexec, which asks for the operator's password,
# and the helper then stays up as a broker until the app exits, reading one
# request per line from a pipe only this process holds. No socket file, so no
# other process running as the operator can reach it.
#
# The session also closes after a cap (duty preference
# action_session_max_age_hours, default 12, 0 means the whole run). The app
# is an always-on monitor that can run for weeks; the cap means a root session
# is at most a day old when something asks it to act.

import json
import logging
import os
import select
import subprocess
import threading
import time

logger = logging.getLogger(__name__)

HELPER_PATH = "/usr/local/lib/agentalsec/action_helper.py"
LAUNCHER = ["pkexec"]

# ONLY THE RUNNING APP MAY OPEN A ROOT SESSION. main.py sets this at startup;
# nothing else does, so a test or a script that reaches a remediation path is
# refused before pkexec starts. Measured 2026-09-29: with the helper
# installed, the suite's device-ban test opened a password prompt on the
# operator's desktop and, once answered, blocked a documentation address on
# the real firewall.
LIVE = False
POLICY_PATH = "/usr/share/polkit-1/actions/org.agentalsec.action-helper.policy"
DEFAULT_MAX_AGE_HOURS = 12.0
PASSWORD_WAIT_SECONDS = 300
CALL_TIMEOUT_SECONDS = 180

_lock = threading.Lock()
_state = {"proc": None, "started_at": None, "max_age_hours": None,
          "next_id": 0, "last_error": None, "calls": 0}


def _max_age_hours() -> float:
    try:
        from core import memory_engine as me
        return max(0.0, float(me.get_preference(
            "action_session_max_age_hours", str(DEFAULT_MAX_AGE_HOURS))))
    except Exception:
        return DEFAULT_MAX_AGE_HOURS


def installed() -> dict:
    """Whether the helper and its polkit policy are in place, and why not."""
    problems = []
    try:
        st = os.stat(HELPER_PATH)
        if st.st_uid != 0:
            problems.append(f"{HELPER_PATH} is not owned by root")
        if st.st_mode & 0o022:
            problems.append(f"{HELPER_PATH} is group- or world-writable")
    except FileNotFoundError:
        problems.append(f"{HELPER_PATH} is not installed")
    if not os.path.exists(POLICY_PATH):
        problems.append(f"the polkit policy {POLICY_PATH} is not installed")
    return {"installed": not problems, "problems": problems,
            "fix": "sudo scripts/install_action_helper.sh --apply"}


def _not_live() -> str:
    """Why a root session may not be opened from this process, or ""."""
    if not LIVE:
        return ("The root action helper is only used by the running app, and "
                "this process is not it (a test or a script). This action "
                "needs root. Nothing was changed.")
    if os.environ.get("AGENTALSEC_TEST_DB", "").strip():
        return ("AGENTALSEC_TEST_DB is set, so this is a test run and the root "
                "helper is not used. This action needs root. Nothing was "
                "changed.")
    return ""


def status() -> dict:
    proc = _state["proc"]
    alive = proc is not None and proc.poll() is None
    return {**installed(), "session_open": alive,
            "started_at": _state["started_at"] if alive else None,
            "max_age_hours": _state["max_age_hours"] if alive else _max_age_hours(),
            "calls": _state["calls"], "last_error": _state["last_error"]}


def _readline(proc, timeout: float):
    ready, _, _ = select.select([proc.stdout], [], [], timeout)
    if not ready:
        return None
    return proc.stdout.readline()


def _open_session():
    """Start the broker. Asks for the password. Returns None or a refusal."""
    hours = _max_age_hours()
    try:
        proc = subprocess.Popen(
            LAUNCHER + [HELPER_PATH, "serve", "--max-age-hours", f"{hours:g}"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1, close_fds=True)
    except OSError as e:
        return f"pkexec could not be started: {type(e).__name__}: {e}"
    line = _readline(proc, PASSWORD_WAIT_SECONDS)
    if not line:
        if proc.poll() is None:
            proc.kill()
            return (f"No password was entered within {PASSWORD_WAIT_SECONDS}s, "
                    f"so the root session did not open. Nothing ran.")
        err = (proc.stderr.read() or "").strip()[:300]
        if proc.returncode in (126, 127):
            return ("The password prompt was dismissed or the password was "
                    "not accepted, so the root session did not open. Nothing "
                    f"ran. {err}").strip()
        return f"The helper exited with {proc.returncode}: {err}. Nothing ran."
    try:
        hello = json.loads(line)
    except ValueError:
        hello = {}
    if not hello.get("ready"):
        proc.kill()
        return f"The helper did not start: {line.strip()[:300]}. Nothing ran."
    _state.update({"proc": proc, "max_age_hours": hours,
                   "started_at": time.strftime("%Y-%m-%d %H:%M:%S")})
    logger.info("Root action session opened (cap %sh; 0 means this run).",
                f"{hours:g}")
    return None


def call(verb: str, *args) -> dict:
    """
    Ask the helper to do one thing. Returns the helper's reply, or
    {"ok": False, "refused": "..."} saying why it could not be asked.
    Serialised: one request at a time on the one pipe.
    """
    refusal = _not_live()
    if refusal:
        return {"ok": False, "not_installed": True, "refused": refusal}
    check = installed()
    if not check["installed"]:
        return {"ok": False, "not_installed": True,
                "refused": ("The root action helper is not installed: "
                            + "; ".join(check["problems"]) + f". This action "
                            f"needs root and the app is unelevated. Run "
                            f"{check['fix']}. Nothing was changed.")}
    with _lock:
        for attempt in (1, 2):
            proc = _state["proc"]
            if proc is None or proc.poll() is not None:
                refusal = _open_session()
                if refusal:
                    _state["last_error"] = refusal
                    return {"ok": False, "refused": refusal}
                proc = _state["proc"]
            _state["next_id"] += 1
            req = {"id": _state["next_id"], "verb": verb,
                   "args": [str(a) for a in args]}
            try:
                proc.stdin.write(json.dumps(req) + "\n")
                proc.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                # Never delivered, so asking a fresh session is safe.
                proc.kill()
                continue
            line = _readline(proc, CALL_TIMEOUT_SECONDS)
            if line:
                reply = json.loads(line)
                if reply.get("expired"):
                    # The cap was reached. The next attempt opens a new
                    # session, which asks for the password again.
                    proc.wait(timeout=5)
                    continue
                _state["calls"] += 1
                return reply
            # DELIVERED AND NOT ANSWERED. It is not resent: a kill or a
            # quarantine that ran once must not run twice.
            if proc.poll() is None:
                proc.kill()
            return {"ok": False, "unknown": True, "refused": (
                f"The helper received {verb} and did not answer within "
                f"{CALL_TIMEOUT_SECONDS}s. Whether it ran is UNKNOWN; check "
                f"/var/log/agentalsec/action_helper.log before trying again.")}
        return {"ok": False, "refused": "The root session closed and could "
                "not be reopened. Nothing ran."}


def close():
    """End the session. Called at app exit; closing the pipe ends the broker."""
    proc = _state["proc"]
    if proc is not None and proc.poll() is None:
        try:
            proc.stdin.close()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    _state["proc"] = None


import atexit  # noqa: E402
atexit.register(close)
