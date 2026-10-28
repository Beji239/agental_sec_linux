"""
The sensor services run only while the app runs: started when it opens,
stopped when it quits. A polkit rule from their installers lets this account
start and stop just these units, so neither needs a password.
"""
import atexit
import logging
import os
import shutil
import subprocess
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

UNIT_DIR = Path("/etc/systemd/system")
# The names helper first: the capture service reads its file.
UNITS = ("agentalsec-names.service", "agentalsec-capture.service",
         "agentalsec-ebpf-camera.service")
FIX = ("Reinstall helpers in Settings, or run: "
       "sudo ./scripts/refresh_helpers.sh --apply")

_lock = threading.Lock()
_started = []


def installed() -> list:
    return [u for u in UNITS if (UNIT_DIR / u).exists()]


def _systemctl(verb: str, units: list) -> tuple:
    """(ok, why). --no-ask-password: with no rule it fails at once
    instead of waiting for a password nobody is asked for."""
    exe = shutil.which("systemctl")
    if not exe:
        return False, "systemctl is not on this machine"
    try:
        done = subprocess.run([exe, verb, "--no-ask-password", *units],
                              capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"{type(e).__name__}: {e}"
    return done.returncode == 0, (done.stderr or "").strip()


def start() -> list:
    """Start every installed sensor unit. Returns the ones started."""
    units = installed()
    if not units:
        return []
    ok, why = _systemctl("start", units)
    if not ok:
        logger.warning(f"[SKIP] sensor services: could not start "
                       f"{', '.join(units)}: {why or 'no reason given'}. "
                       f"{FIX}")
        return []
    with _lock:
        _started[:] = units
    atexit.register(stop)
    logger.info(f"[OK] sensor services started: {', '.join(units)}")
    return units


def stop() -> None:
    """Stop the units this run started. Safe to call twice."""
    with _lock:
        units, _started[:] = list(_started), []
    if not units:
        return
    ok, why = _systemctl("stop", list(reversed(units)))
    if ok:
        logger.info(f"Sensor services stopped: {', '.join(units)}")
    else:
        logger.warning(f"Could not stop the sensor services: "
                       f"{why or 'no reason given'}. {FIX}")


def boot_enabled() -> list:
    """Units still set to start at boot, from an install before this."""
    wants = UNIT_DIR / "multi-user.target.wants"
    return [u for u in installed() if os.path.lexists(wants / u)]
