# core/updater.py
# Updates from GitHub. Once a day the app asks GitHub's public releases
# address for the latest AgentalSec release and compares it with VERSION;
# nothing about this machine or its network is sent. The Update button then
# installs it: the code and Python packages through scripts/update.sh, the
# root helpers and sensors that fell behind through scripts/refresh_helpers.sh
# behind one password, then the app restarts on the new code.
#
# The check only tells. Nothing is installed until the owner presses the
# button, and every step says what it did or why it stopped.

import json
import logging
import os
import re
import select
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
REPO = "Beji239/agental_sec_linux"
LATEST_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPO}/releases"

CHECK_EVERY = 24 * 3600
RETRY_AFTER_FAILURE = 3 * 3600
FIRST_DELAY = 120
LOOP_TICK = 600
PREF_KEY = "update_check"
JOB_KEY = "update_last_job"
NOTES_MAX = 6000
LOG_MAX = 400
UPDATE_TIMEOUT = 1800
PASSWORD_WAIT = 300
ROOT_STEP_TIMEOUT = 1800
AUDIT_RULES = "/etc/audit/rules.d/agentalsec.rules"

# Set by main.py. Only the running app checks GitHub or installs anything,
# so a test or a script reaching these paths changes nothing.
LIVE = False
# main.py's clean stop followed by a start on the new code.
RESTART = None

_VER = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")
_SECURITY = re.compile(r"\bsecurity\b", re.I)


class CheckFailed(Exception):
    """The check could not get an answer; the message says why."""


def parse_version(text) -> tuple | None:
    m = _VER.fullmatch((text or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None


def kind_of(current, latest) -> str | None:
    """'major', 'minor', 'patch', or 'none' when latest is not newer.
    None when either number cannot be read."""
    a, b = parse_version(current), parse_version(latest)
    if not a or not b:
        return None
    if b <= a:
        return "none"
    if b[0] != a[0]:
        return "major"
    if b[1] != a[1]:
        return "minor"
    return "patch"


def summarise(release: dict) -> dict:
    """The parts of a GitHub release the page shows. A release counts as a
    security fix when its title has the word security in it."""
    if not isinstance(release, dict):
        raise CheckFailed("GitHub's answer was not a release")
    tag = str(release.get("tag_name") or "")
    version = parse_version(tag)
    if not version:
        raise CheckFailed(f"the latest release's tag {tag[:40]!r} is not a "
                          f"version number")
    title = str(release.get("name") or tag)[:200]
    url = str(release.get("html_url") or "")
    if not url.startswith(f"https://github.com/{REPO}/"):
        url = RELEASES_PAGE
    return {"version": "%d.%d.%d" % version, "tag": tag[:40], "title": title,
            "notes": str(release.get("body") or "")[:NOTES_MAX],
            "url": url,
            "published_at": str(release.get("published_at") or "")[:40],
            "security": bool(_SECURITY.search(title))}


def _not_live() -> str:
    if not LIVE:
        return ("Only the running app checks for updates or installs them, "
                "and this process is not it. Nothing was done.")
    if os.environ.get("AGENTALSEC_TEST_DB", "").strip():
        return ("AGENTALSEC_TEST_DB is set, so this is a test run. Nothing "
                "was done.")
    return ""


def _fetch_latest() -> dict:
    """GitHub's latest release. Only the address is asked; no key is sent."""
    from core import safe_http
    try:
        r = safe_http.get(LATEST_URL, timeout=15, headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "AgentalSec-update-check"})
    except Exception as e:                              # noqa: BLE001
        raise CheckFailed(f"GitHub could not be reached ({type(e).__name__})")
    if r.status_code == 404:
        raise CheckFailed("GitHub lists no release for AgentalSec yet")
    if r.status_code in (403, 429):
        raise CheckFailed("GitHub's hourly limit for requests without an "
                          "account is used up here; the next check tries "
                          "again")
    if r.status_code != 200:
        raise CheckFailed(f"GitHub answered HTTP {r.status_code}")
    try:
        return r.json()
    except ValueError:
        raise CheckFailed("GitHub's answer was not readable")


def enabled() -> bool:
    """updates.check_daily in config.json, on unless set false. Read fresh,
    so the switch works without a restart."""
    try:
        from core import settings
        cfg = json.loads(settings.CONFIG_PATH.read_text(encoding="utf-8"))
        value = (cfg.get("updates") or {}).get("check_daily", True)
    except (OSError, ValueError, AttributeError):
        return True
    return value is not False


def set_enabled(on: bool) -> str | None:
    """Saves the daily check switch. An error sentence, or None."""
    from core import settings
    return settings.persist_config_value("updates", "check_daily", bool(on))


def _load() -> dict:
    try:
        from core import memory_engine as me
        data = json.loads(me.get_preference(PREF_KEY, "{}") or "{}")
        return data if isinstance(data, dict) else {}
    except Exception:                                   # noqa: BLE001
        return {}


def _save(data: dict):
    try:
        from core import memory_engine as me
        me.set_preference(PREF_KEY, json.dumps(data))
    except Exception as e:                              # noqa: BLE001
        logger.warning(f"Update check result not saved: {e}")


def check_now(fetch=None) -> dict:
    """Asks GitHub now and keeps the answer. A failed check keeps the last
    good answer and says it could not check, never "up to date"."""
    if fetch is None:
        refusal = _not_live()
        if refusal:
            return {"ok": False, "error": refusal}
        fetch = _fetch_latest
    state = _load()
    state["checked_at"] = time.time()
    try:
        release = summarise(fetch())
    except CheckFailed as e:
        state.update(ok=False, error=str(e))
        logger.info(f"Update check: could not check, {e}.")
    except Exception as e:                              # noqa: BLE001
        state.update(ok=False, error=f"{type(e).__name__}: {e}"[:200])
        logger.warning(f"Update check failed: {e}")
    else:
        state.update(ok=True, error="", release=release,
                     release_checked_at=state["checked_at"])
        from core import version
        k = kind_of(version.current().get("version"), release["version"])
        if k and k != "none":
            logger.info(f"Update check: AgentalSec {release['version']} is "
                        f"out ({k}{', security fix' if release['security'] else ''}).")
    _save(state)
    return {"ok": state["ok"], "error": state.get("error", "")}


def _due(state: dict, now: float) -> bool:
    last = state.get("checked_at") or 0
    wait = CHECK_EVERY if state.get("ok") else RETRY_AFTER_FAILURE
    return now - last >= wait or last > now


def _loop():
    time.sleep(FIRST_DELAY)
    while True:
        try:
            if enabled() and _due(_load(), time.time()):
                check_now()
        except Exception as e:                          # noqa: BLE001
            logger.warning(f"Update check loop: {e}")
        time.sleep(LOOP_TICK)


_started = False


def start():
    """The daily check, on a daemon thread. Asks at most once a day, however
    often the app restarts, since the time of the last ask is kept."""
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_loop, name="update-check", daemon=True).start()


# The Update button.

_lock = threading.Lock()
_job = {"running": False, "what": None, "started_at": None,
        "finished_at": None, "step": "", "log": [], "ok": None,
        "result": "", "todo": [], "restarting": False}


def can_update(root: Path = None) -> dict:
    """Whether the button can update this folder, and why not."""
    root = Path(root or ROOT)
    if not (root / ".git").exists():
        return {"ok": False, "reason": (
            "This folder is not a git clone, so it cannot update itself. "
            "Clone the repository again (SETUP.md step 2) and move "
            "config.json, .env and agental_sec.db into the new folder.")}
    if not shutil.which("git"):
        return {"ok": False, "reason": "git is not installed: sudo apt install git"}
    if not (root / "scripts" / "update.sh").is_file():
        return {"ok": False, "reason": "scripts/update.sh is missing from this folder."}
    if os.geteuid() == 0:
        return {"ok": False, "reason": (
            "AgentalSec is running as root, and the update installs the "
            "Python packages for your own account. Start it from the normal "
            "icon, or run ./scripts/update.sh in a terminal.")}
    return {"ok": True, "reason": ""}


def helpers_behind(root: Path = None) -> list:
    """Installers whose root-owned copies differ from this folder, as far as
    this account can read them. Run as root, refresh_helpers.sh also sees the
    sudoers file, which only root can read."""
    root = Path(root or ROOT)
    names = set()
    try:
        from core import root_copies
        for row in root_copies.check(root):
            if row["installed"] and not row["matches"]:
                names.add(Path(row["fix"].split()[1]).name)
    except Exception as e:                              # noqa: BLE001
        logger.debug(f"root copies not compared: {e}")
    try:
        from core import own_install
        names.update(own_install.stale(root))
    except Exception as e:                              # noqa: BLE001
        logger.debug(f"installed files not compared: {e}")
    return sorted(names)


def status() -> dict:
    """Everything the page shows about updates, in one answer."""
    from core import version
    current = version.current()
    state = _load()
    release = state.get("release") or None
    kind = None
    if release:
        kind = kind_of(current.get("version"), release.get("version"))
    with _lock:
        job = {**_job, "log": list(_job["log"]), "todo": list(_job["todo"])}
    if not job["running"] and not job["finished_at"]:
        job = _last_job() or job
    return {
        "enabled": enabled(),
        "current": current,
        "checked_at": state.get("checked_at"),
        "check_ok": state.get("ok"),
        "check_error": state.get("error") or "",
        "release": release,
        "release_checked_at": state.get("release_checked_at"),
        "kind": kind,
        "available": kind in ("patch", "minor", "major"),
        "security": bool(release and release.get("security")
                         and kind in ("patch", "minor", "major")),
        "can_update": can_update(),
        "helpers_behind": helpers_behind(),
        "releases_page": RELEASES_PAGE,
        "job": job,
    }


def _log(line: str):
    with _lock:
        _job["log"].append(line.rstrip()[:500])
        del _job["log"][:-LOG_MAX]


def _step(text: str):
    with _lock:
        _job["step"] = text
    _log("")
    _log("== " + text)
    logger.info(f"Update: {text}")


def _run(cmd, timeout: float, first_line_wait: float = None, env=None):
    """Runs cmd, each output line into the job log. (exit code, output).
    first_line_wait ends it when nothing is printed in that time, which is a
    password dialog that never appeared or was left open."""
    try:
        proc = subprocess.Popen(cmd, cwd=str(ROOT), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, env=env,
                                close_fds=True, start_new_session=True)
    except OSError as e:
        _log(f"could not start {cmd[0]}: {e}")
        return None, ""
    lines, buf = [], b""
    start = time.time()
    got_output = False
    timed_out = None
    fd = proc.stdout.fileno()
    while True:
        limit = timeout
        if first_line_wait is not None and not got_output:
            limit = first_line_wait
        left = limit - (time.time() - start)
        if left <= 0:
            timed_out = "no_output" if not got_output and first_line_wait else "timeout"
            break
        ready, _, _ = select.select([fd], [], [], min(left, 1.0))
        if not ready:
            continue
        chunk = os.read(fd, 4096)
        if not chunk:
            break
        got_output = True
        buf += chunk
        while b"\n" in buf:
            raw, buf = buf.split(b"\n", 1)
            text = raw.decode("utf-8", "replace")
            lines.append(text)
            _log(text)
    if timed_out:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except OSError:
            proc.kill()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
        proc.stdout.close()
        return timed_out, "\n".join(lines)
    if buf:
        text = buf.decode("utf-8", "replace")
        lines.append(text)
        _log(text)
    proc.stdout.close()
    try:
        code = proc.wait(30)
    except subprocess.TimeoutExpired:
        proc.kill()
        code = proc.wait()
    return code, "\n".join(lines)


# Lines of update.sh's "What is left" that the button does itself.
_HANDLED = re.compile(
    r"^(Restart AgentalSec|Start AgentalSec|The database updates itself"
    r"|Your config\.json is not changed"
    r"|The launchers changed"
    r"|The audit watches changed"
    r"|Run: sudo \./scripts/install_(action_helper|read_helper|ebpf_camera|capture_service)\.sh --apply)")


def leftover(output: str) -> list:
    """update.sh's "What is left" lines the button does not do itself."""
    out, inside = [], False
    for line in output.splitlines():
        if line.startswith("Done. What is left:"):
            inside = True
            continue
        if not inside:
            continue
        text = line.strip()
        if text.startswith("- "):
            text = text[2:]
        if text and not _HANDLED.match(text):
            out.append(text)
    return out


def _root_refresh(audit: bool) -> tuple:
    """refresh_helpers.sh --apply through pkexec, one password. (ok, why)."""
    script = ROOT / "scripts" / "refresh_helpers.sh"
    by_hand = f"sudo {script} --apply" + (" --audit" if audit else "")
    pkexec = shutil.which("pkexec")
    if not pkexec:
        return False, f"pkexec is not installed. Run in a terminal: {by_hand}"
    cmd = [pkexec, str(script), "--apply"] if os.access(script, os.X_OK) \
        else [pkexec, "/bin/bash", str(script), "--apply"]
    if audit:
        cmd.append("--audit")
    _log("A password dialog asks for your password now.")
    code, _ = _run(cmd, ROOT_STEP_TIMEOUT, first_line_wait=PASSWORD_WAIT)
    if code == 0:
        return True, ""
    if code == "no_output":
        return False, (f"No password was given within {PASSWORD_WAIT // 60} "
                       f"minutes, or no password dialog could open on this "
                       f"desktop. Run in a terminal: {by_hand}")
    if code is None:
        return False, f"pkexec could not be started. Run in a terminal: {by_hand}"
    if code in (126, 127):
        return False, ("The password dialog was closed or the password was "
                       f"not accepted. Run in a terminal: {by_hand}")
    return False, f"An installer failed (exit {code}); its messages are above. Run in a terminal: {by_hand}"


def _finish(ok: bool, result: str, todo=None, restart=False):
    with _lock:
        _job.update(running=False, ok=ok, result=result,
                    todo=list(todo or []), finished_at=time.time(),
                    step="", restarting=bool(restart))
    _log("")
    _log(("Done: " if ok else "Not finished: ") + result)
    (logger.info if ok else logger.warning)(f"Update: {result}")
    # Kept, so the page shows the outcome after the restart too.
    try:
        from core import memory_engine as me
        with _lock:
            kept = {k: _job[k] for k in ("what", "started_at", "finished_at",
                                         "ok", "result", "todo", "log")}
        me.set_preference(JOB_KEY, json.dumps(kept))
    except Exception as e:                              # noqa: BLE001
        logger.warning(f"Update outcome not saved: {e}")


def _last_job() -> dict | None:
    try:
        from core import memory_engine as me
        data = json.loads(me.get_preference(JOB_KEY, "") or "null")
    except Exception:                                   # noqa: BLE001
        return None
    if not isinstance(data, dict):
        return None
    return {"running": False, "step": "", "restarting": False, **data}


def _do_update():
    from core import version
    before = version.current().get("label")
    _step("Getting the new code and Python packages (scripts/update.sh)")
    env = dict(os.environ, AGENTALSEC_FROM_APP="1")
    code, out = _run(["bash", str(ROOT / "scripts" / "update.sh")],
                     UPDATE_TIMEOUT, env=env)
    if code != 0:
        why = "it took too long and was stopped" if code == "timeout" \
            else f"exit {code}"
        return _finish(False, f"scripts/update.sh did not finish ({why}). "
                       "Its messages are above. Nothing after it ran.")
    changed = "Already up to date" not in out
    todo = leftover(out)

    if "The launchers changed" in out:
        _step("Installing the new launchers")
        c, _ = _run(["bash", str(ROOT / "scripts" / "install_launchers.sh")], 300)
        if c != 0:
            todo.append("The launchers did not install. Run: ./scripts/install_launchers.sh")

    audit = "The audit watches changed" in out and os.path.exists(AUDIT_RULES)
    behind = helpers_behind()
    needs_root = bool(behind) or audit \
        or "These root helpers need installing again" in out
    helpers_ok = True
    if needs_root:
        what = ", ".join(behind) if behind else "the helpers this update changed"
        _step(f"Installing the root helpers and sensors again ({what})")
        helpers_ok, why = _root_refresh(audit)
        if not helpers_ok:
            todo.insert(0, why)
    elif "The audit watches changed" in out:
        todo.append("The audit watches changed. Run: sudo ./scripts/install_audit_rules.sh --apply")

    after = version.info(ROOT).get("label")
    if not changed:
        msg = f"Already up to date, AgentalSec {after}."
        if needs_root:
            msg += (" The root helpers were brought level." if helpers_ok
                    else " The root helpers are still behind.")
        return _finish(helpers_ok, msg, todo)

    restart = callable(RESTART)
    msg = (f"Updated from {before} to {after}." if before != after
           else f"Updated to the latest code, AgentalSec {after}.")
    if not helpers_ok:
        msg += " The root helpers are still behind, see below."
    if restart:
        msg += " AgentalSec was restarted on the new code."
    else:
        todo.insert(0, "Restart AgentalSec: close it, then start it again from its icon.")
    _finish(helpers_ok, msg, todo, restart=restart)
    if restart:
        time.sleep(3)
        RESTART("Restarting on the updated code")


def _do_helpers():
    behind = helpers_behind()
    _step("Installing the root helpers and sensors again ("
          + (", ".join(behind) or "the ones root finds behind") + ")")
    ok, why = _root_refresh(False)
    if ok:
        _finish(True, "The root helpers and sensors match this folder again.")
    else:
        _finish(False, why)


def _worker(what: str):
    try:
        (_do_update if what == "update" else _do_helpers)()
    except Exception as e:                              # noqa: BLE001
        logger.exception("Update failed")
        _finish(False, f"The update stopped on an error: {type(e).__name__}: {e}")


def start_job(what: str) -> dict:
    """Starts the update ('update') or the helper reinstall ('helpers') on a
    thread. {'started': bool, 'reason': str}."""
    if what not in ("update", "helpers"):
        return {"started": False, "reason": "unknown job; known: update, helpers"}
    refusal = _not_live()
    if refusal:
        return {"started": False, "reason": refusal}
    if what == "update":
        can = can_update()
        if not can["ok"]:
            return {"started": False, "reason": can["reason"]}
    with _lock:
        if _job["running"]:
            return {"started": False, "reason": "An update is already running."}
        _job.update(running=True, what=what, started_at=time.time(),
                    finished_at=None, step="starting", log=[], ok=None,
                    result="", todo=[], restarting=False)
    threading.Thread(target=_worker, args=(what,), name="update-job",
                     daemon=True).start()
    return {"started": True, "reason": ""}
