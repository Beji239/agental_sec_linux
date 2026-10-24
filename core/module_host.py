# core/module_host.py
# Where add-on modules plug in. Each lives in modules/<name>/ with a manifest
# and runs as its own process only while switched on; off frees everything.

import http.client
import json
import logging
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULES_DIR = PROJECT_ROOT / "modules"
DATA_DIR = PROJECT_ROOT / "module_data"
LOG_DIR = PROJECT_ROOT / "logs"
SWITCHES = DATA_DIR / "switches.json"

TOKEN_HEADER = "X-Module-Token"
_NAME = re.compile(r"^[a-z][a-z0-9_]{1,30}$")
_ENV_NAME = re.compile(r"^AGENTAL_[A-Z0-9_]{3,60}$")
_SAFE_VALUE = re.compile(r"^[\x21-\x7e]*$")
_VALUE_MAX = 512
# What a module may decide through /api/module-feed/decide, when its
# manifest asks for it. Everything else in the feed only reads.
DECISION_KINDS = ("action", "question", "verdict", "release")
LOG_MAX_BYTES = 2 * 1024 * 1024
STOP_WAIT = 4.0
CALL_TIMEOUT = 15.0

# Passed to a module from the app's own environment. Nothing else is, so a
# module never sees the model key or the dashboard key.
_ENV_PASS = ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE",
             "SSL_CERT_DIR")

_lock = threading.RLock()
_running = {}
_host = {"url": None}


def configure(config: dict) -> None:
    """Where modules reach the app's own routes."""
    flask_cfg = (config or {}).get("flask") or {}
    host = str(flask_cfg.get("host", "127.0.0.1"))
    if host in ("0.0.0.0", "::", ""):
        host = "127.0.0.1"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    _host["url"] = f"http://{host}:{int(flask_cfg.get('port', 5000))}"


def _version_tuple(text: str) -> tuple:
    try:
        return tuple(int(p) for p in str(text).strip().split("."))
    except ValueError:
        return ()


def _app_version() -> str:
    from core import version
    return version.read_file() or "0.0.0"


def _read_manifest(folder: Path) -> dict | None:
    try:
        data = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        logger.warning(f"Module folder {folder.name} has no readable manifest: {e}")
        return None
    name = data.get("name")
    if not isinstance(name, str) or not _NAME.match(name) or name != folder.name:
        logger.warning(f"Module folder {folder.name}: the manifest name must "
                       f"match the folder name.")
        return None
    entry = data.get("entry") or "service.py"
    if "/" in entry or not (folder / entry).is_file():
        logger.warning(f"Module {name}: entry file {entry} is missing.")
        return None
    secrets_ = [s for s in (data.get("secrets") or [])
                if isinstance(s, str) and _ENV_NAME.match(s)]
    ui = data.get("ui")
    if ui and ("/" in ui or not (folder / ui).is_file()):
        ui = None
    decides = [k for k in (data.get("decides") or []) if k in DECISION_KINDS]
    need = str(data.get("app_min") or "0.0.0")
    fits = _version_tuple(_app_version()) >= _version_tuple(need)
    return {
        "name": name,
        "title": str(data.get("title") or name.title())[:40],
        "tab": str(data.get("tab") or data.get("title") or name.title())[:16],
        "version": str(data.get("version") or "0.0.0")[:20],
        "summary": str(data.get("summary") or "")[:600],
        "ram_mb": data.get("ram_mb"),
        "needs": [str(n)[:120] for n in (data.get("needs") or [])][:8],
        "secrets": secrets_,
        "decides": decides,
        "entry": entry,
        "ui": ui,
        "app_min": need,
        "fits": fits,
        "folder": folder,
    }


def discover() -> dict:
    """Every installed module, by name. A folder without a valid manifest is
    skipped and logged, never half loaded."""
    found = {}
    if not MODULES_DIR.is_dir():
        return found
    for folder in sorted(MODULES_DIR.iterdir()):
        if folder.is_dir() and _NAME.match(folder.name):
            man = _read_manifest(folder)
            if man:
                found[man["name"]] = man
    return found


def _read_switches() -> dict:
    try:
        data = json.loads(SWITCHES.read_text(encoding="utf-8"))
        return {k: bool(v) for k, v in data.items() if isinstance(k, str)}
    except (OSError, ValueError, AttributeError):
        return {}


def _write_switches(data: dict) -> None:
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = SWITCHES.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, SWITCHES)


def is_on(name: str) -> bool:
    return _read_switches().get(name, False)


def data_dir(name: str) -> Path:
    path = DATA_DIR / name
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def socket_path(name: str) -> Path:
    """The module's socket. A Unix socket path has to stay short, so a deep
    install uses the account's private runtime folder instead."""
    path = DATA_DIR / name / "module.sock"
    if len(str(path)) < 100:
        return path
    run = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    if not os.path.isdir(run):
        return path
    folder = Path(run) / "agentalsec-modules"
    folder.mkdir(mode=0o700, exist_ok=True)
    return folder / f"{name}.sock"


def _rotate_log(path: Path) -> None:
    try:
        if path.stat().st_size > LOG_MAX_BYTES:
            os.replace(path, path.with_suffix(".log.1"))
    except OSError:
        pass


def _child_env(man: dict, token: str) -> dict:
    env = {k: os.environ[k] for k in _ENV_PASS if os.environ.get(k)}
    for name in man["secrets"]:
        if os.environ.get(name):
            env[name] = os.environ[name]
    env.update({
        "AGENTAL_MODULE_NAME": man["name"],
        "AGENTAL_MODULE_HOST": _host["url"] or "http://127.0.0.1:5000",
        "AGENTAL_MODULE_TOKEN": token,
        "AGENTAL_MODULE_DATA": str(data_dir(man["name"])),
        "AGENTAL_MODULE_SOCKET": str(socket_path(man["name"])),
        "AGENTAL_APP_VERSION": _app_version(),
    })
    return env


def start(name: str) -> dict:
    """Start one module's process. Already running is fine."""
    with _lock:
        man = discover().get(name)
        if not man:
            return {"ok": False, "reason": f"No module called {name} is installed."}
        if not man["fits"]:
            return {"ok": False,
                    "reason": (f"{man['title']} needs AgentalSec {man['app_min']} "
                               f"or newer; this is {_app_version()}.")}
        run = _running.get(name)
        if run and run["proc"].poll() is None:
            return {"ok": True, "pid": run["proc"].pid, "already": True}

        sock = socket_path(name)
        try:
            sock.unlink()
        except OSError:
            pass
        token = secrets.token_urlsafe(32)
        LOG_DIR.mkdir(exist_ok=True)
        log_path = LOG_DIR / f"module-{name}.log"
        _rotate_log(log_path)
        try:
            log = open(log_path, "ab")
            # stdin stays open for the module's whole life: when the app goes,
            # even killed, the pipe closes and the module stops by itself.
            proc = subprocess.Popen(
                [sys.executable, "-B", "-s", "-E", str(man["folder"] / man["entry"])],
                cwd=str(man["folder"]), env=_child_env(man, token),
                stdin=subprocess.PIPE, stdout=log, stderr=log,
                close_fds=True)
            log.close()
        except OSError as e:
            logger.error(f"Module {name} could not start: {e}")
            return {"ok": False, "reason": f"It could not start: {e}"}
        _running[name] = {"proc": proc, "token": token,
                          "started_at": time.time(), "log": log_path}
        logger.info(f"Module {name} started, pid {proc.pid}")
        return {"ok": True, "pid": proc.pid}


def stop(name: str) -> dict:
    """Stop one module and wait until it is gone."""
    with _lock:
        run = _running.pop(name, None)
    if not run:
        return {"ok": True, "was_running": False}
    proc = run["proc"]
    try:
        if proc.stdin:
            proc.stdin.close()
    except OSError:
        pass
    try:
        proc.wait(STOP_WAIT)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(2)
    try:
        socket_path(name).unlink()
    except OSError:
        pass
    logger.info(f"Module {name} stopped (exit {proc.returncode})")
    return {"ok": True, "was_running": True, "exit": proc.returncode}


def switch(name: str, on: bool) -> dict:
    """The tab's switch: saved, then the process started or stopped."""
    if name not in discover():
        return {"ok": False, "reason": f"No module called {name} is installed."}
    with _lock:
        data = _read_switches()
        data[name] = bool(on)
        _write_switches(data)
    result = start(name) if on else stop(name)
    if on and not result.get("ok"):
        with _lock:
            data = _read_switches()
            data[name] = False
            _write_switches(data)
    return {**result, "on": is_on(name)}


def start_switched_on() -> list:
    """At app start: the modules left on last time."""
    started = []
    switches = _read_switches()
    for name in discover():
        if switches.get(name):
            if start(name).get("ok"):
                started.append(name)
    return started


def stop_all() -> None:
    for name in list(_running):
        try:
            stop(name)
        except Exception as e:                          # noqa: BLE001
            logger.warning(f"Module {name} did not stop cleanly: {e}")


def _rss_mb(pid: int) -> float | None:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return round(int(line.split()[1]) / 1024, 1)
    except (OSError, ValueError, IndexError):
        pass
    return None


def _last_log_line(path: Path) -> str:
    try:
        with open(path, "rb") as fh:
            fh.seek(max(0, fh.seek(0, 2) - 4096))
            lines = [ln for ln in fh.read().decode("utf-8", "replace").splitlines()
                     if ln.strip()]
        return lines[-1][:300] if lines else ""
    except OSError:
        return ""


def describe(name: str, man: dict = None) -> dict:
    """What the tab shows above the module's own part."""
    man = man or discover().get(name)
    if not man:
        return {"name": name, "installed": False}
    on = is_on(name)
    run = _running.get(name)
    out = {k: v for k, v in man.items() if k != "folder"}
    out.update(installed=True, on=on, running=False, pid=None, ram_mb=None,
               ram_target_mb=man.get("ram_mb"), started_at=None, problem=None,
               secrets=secret_status(name, man))
    if run:
        code = run["proc"].poll()
        if code is None:
            out.update(running=True, pid=run["proc"].pid,
                       ram_mb=_rss_mb(run["proc"].pid),
                       started_at=run["started_at"])
        elif on:
            out["problem"] = (f"It stopped by itself (exit {code}). Last log "
                              f"line: {_last_log_line(run['log']) or 'none'}")
    elif on:
        out["problem"] = "It is switched on but not running."
    return out


def list_modules() -> list:
    return [describe(n, m) for n, m in discover().items()]


def token_ok(name: str, token: str) -> bool:
    import hmac
    run = _running.get(name)
    if not run or not token or run["proc"].poll() is not None:
        return False
    return hmac.compare_digest(run["token"].encode(),
                               str(token).encode("utf-8", "surrogateescape"))


def may_decide(name: str, kind: str) -> bool:
    man = discover().get(name) or {}
    return kind in (man.get("decides") or [])


def module_for_token(token: str) -> str | None:
    for name in list(_running):
        if token_ok(name, token):
            return name
    return None


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._path)


def call(name: str, method: str, path: str, body: dict = None) -> tuple:
    """One request from the tab to the module's own routes, over its private
    socket. (status, json)."""
    run = _running.get(name)
    if not run or run["proc"].poll() is not None:
        return 503, {"error": "not running",
                     "detail": "The module is not running. Switch it on first."}
    if not re.match(r"^/[A-Za-z0-9_/\-]*(\?[A-Za-z0-9_=&\-]*)?$", path or ""):
        return 400, {"error": "Bad request", "detail": "Unexpected path."}
    conn = _UnixConnection(str(socket_path(name)), CALL_TIMEOUT)
    try:
        payload = json.dumps(body or {}).encode() if method == "POST" else None
        conn.request(method, path, body=payload,
                     headers={"Content-Type": "application/json",
                              TOKEN_HEADER: run["token"]})
        resp = conn.getresponse()
        raw = resp.read(1024 * 1024)
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            data = {"error": "The module answered something that is not JSON."}
        return resp.status, data
    except (OSError, http.client.HTTPException) as e:
        if time.time() - run["started_at"] < 10:
            return 503, {"error": "starting",
                         "detail": "The module is still starting."}
        return 502, {"error": "no answer", "detail": f"The module did not answer: {e}"}
    finally:
        conn.close()


def _last4(value: str) -> str:
    v = (value or "").strip()
    return v[-4:] if len(v) >= 8 else ""


def secret_status(name: str, man: dict = None) -> list:
    man = man or discover().get(name) or {}
    return [{"env": env, "present": bool(os.environ.get(env, "").strip()),
             "last4": _last4(os.environ.get(env, ""))}
            for env in man.get("secrets", [])]


def set_secret(name: str, env: str, value: str) -> dict:
    """Save one of the module's own keys in .env, encrypted like the others,
    and restart the module so it uses it. Empty clears it."""
    man = discover().get(name)
    if not man:
        return {"ok": False, "reason": f"No module called {name} is installed."}
    if env not in man["secrets"]:
        return {"ok": False, "reason": f"{env} is not a key this module uses."}
    val = (value or "").strip()
    if len(val) > _VALUE_MAX or not _SAFE_VALUE.match(val):
        return {"ok": False,
                "reason": ("That does not look like a key. Check for a stray "
                           "space or newline from the copy and paste.")}
    from core import settings as st
    ok, err = st._write_env_line(env, val)
    if not ok:
        return {"ok": False, "reason": err}
    if val:
        os.environ[env] = val
    else:
        os.environ.pop(env, None)
    restarted = False
    if name in _running:
        stop(name)
        restarted = bool(start(name).get("ok"))
    return {"ok": True, "present": bool(val), "last4": _last4(val),
            "restarted": restarted}


def ui_path(name: str) -> Path | None:
    man = discover().get(name)
    if not man or not man.get("ui"):
        return None
    return man["folder"] / man["ui"]
