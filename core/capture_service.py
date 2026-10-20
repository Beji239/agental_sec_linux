# core/capture_service.py
# Packet capture as its own service. `main.py --capture` runs only the packet
# sensor and the LAN checks, under systemd with the two network capture
# rights and nothing else, and reports its state here every few seconds. The
# core runs as the owner with no special rights and reads those reports in
# place of a sensor of its own. A report that stops coming says so.

import json
import logging
import os
import pwd
import signal
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from core import memory_engine as me

logger = logging.getLogger(__name__)

ROLE = "capture"
UNIT_NAME = "agentalsec-capture.service"
UNIT_PATH = Path("/etc/systemd/system") / UNIT_NAME
REPORT_SECONDS = 15
STALE_SECONDS = 90
MODES = ("auto", "service", "in_process")
PROJECT = Path(__file__).resolve().parent.parent
# Files whose change means the service is running old code. systemd starts
# it again at once (Restart=always), so an update reaches it by itself.
CODE_FILES = ("VERSION", "main.py", "adapters.py", "core/capture_service.py",
              "tools/packet_sniffer_linux.py", "tools/lan_watch.py",
              "tools/payload_ring.py", ".git/HEAD", ".git/packed-refs")

DDL = (
    """CREATE TABLE IF NOT EXISTS sensor_service (
    role         TEXT PRIMARY KEY,
    pid          INTEGER,
    user         TEXT,
    started_at   TEXT,
    reported_at  TEXT,
    stopped_at   TEXT,
    status_json  TEXT
)""",
)


def ensure_tables(conn) -> int:
    added = 0 if me._table_exists_ro(conn, "sensor_service") else 1
    for ddl in DDL:
        conn.execute(ddl)
    return added


def _iso(ts: float = None) -> str:
    return datetime.fromtimestamp(ts or time.time(), timezone.utc) \
        .strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _age(stamp: str) -> float | None:
    try:
        return time.time() - datetime.fromisoformat(stamp).timestamp()
    except (TypeError, ValueError):
        return None


def report(status: dict, started_at: float, stopped: bool = False,
           role: str = ROLE) -> None:
    """The service's state, written over the previous one."""
    with me._get_conn() as conn:
        ensure_tables(conn)
        conn.execute(
            "INSERT INTO sensor_service (role, pid, user, started_at, "
            "reported_at, stopped_at, status_json) VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(role) DO UPDATE SET pid = excluded.pid, user = "
            "excluded.user, started_at = excluded.started_at, reported_at = "
            "excluded.reported_at, stopped_at = excluded.stopped_at, "
            "status_json = excluded.status_json",
            (role, os.getpid(), pwd.getpwuid(os.geteuid()).pw_name,
             _iso(started_at), _iso(), _iso() if stopped else None,
             json.dumps(status, default=str)))


def latest(role: str = ROLE) -> dict | None:
    """The last report, with its age in seconds, or None if none ever came."""
    try:
        with me._get_readonly_conn() as conn:
            if not me._table_exists_ro(conn, "sensor_service"):
                return None
            row = conn.execute("SELECT * FROM sensor_service WHERE role = ?",
                               (role,)).fetchone()
    except Exception as e:                                  # noqa: BLE001
        logger.warning(f"capture service report not read: {e}")
        return None
    if row is None:
        return None
    out = dict(row)
    try:
        out["status"] = json.loads(out.pop("status_json") or "{}")
    except ValueError:
        out["status"] = {}
    out["age_seconds"] = _age(out.get("reported_at"))
    return out


def reporting() -> bool:
    """Is the capture service running and reporting right now."""
    last = latest()
    return bool(last and not last.get("stopped_at")
                and (last.get("age_seconds") or 1e9) <= STALE_SECONDS)


def mode(config: dict) -> str:
    """service when the capture service does the capturing, in_process when
    this process captures itself (started as root, the old way)."""
    chosen = str(((config or {}).get("capture") or {}).get("mode") or "auto")
    if chosen in ("service", "in_process"):
        return chosen
    # Once the service is installed it does the capturing, even for a core
    # started as root, so packets are never captured twice.
    if UNIT_PATH.exists():
        return "service"
    last = latest()
    if last and not last.get("stopped_at") and \
            (last["age_seconds"] or 1e9) < STALE_SECONDS:
        return "service"
    return "in_process"


class RemoteCapture:
    """Stands in for the packet sensor in the core, from the service's
    reports. Blind, with the reason, when the reports stop."""

    role = "packet_sniffer"

    def __init__(self):
        self.label = None

    def start(self):
        pass

    def stop(self):
        pass

    def _report(self) -> tuple[dict | None, str | None]:
        last = latest()
        if last is None:
            return None, (f"the capture service has never reported. Install "
                          f"it with sudo scripts/install_capture_service.sh")
        if last.get("stopped_at"):
            return last, f"the capture service stopped at {last['stopped_at']}"
        age = last.get("age_seconds")
        if age is None or age > STALE_SECONDS:
            return last, (f"the capture service has not reported for "
                          f"{int(age or 0)} s; check: systemctl status "
                          f"{UNIT_NAME}")
        return last, None

    def status(self) -> dict:
        last, trouble = self._report()
        st = dict(((last or {}).get("status") or {}).get("sniffer") or {})
        st["role"] = self.role
        st["where"] = (f"the capture service, process {last['pid']} as "
                       f"{last['user']}" if last else "the capture service")
        if trouble:
            st.update(blind=True, blind_reason=trouble, running=False)
        return st

    def liveness(self) -> dict:
        last, trouble = self._report()
        lv = dict(((last or {}).get("status") or {}).get("liveness") or {})
        if trouble or not lv:
            lv.update(started=last is not None, running=False,
                      thread_alive=False, last_error=trouble)
        return lv

    def tls_run_counts(self) -> dict | None:
        last, trouble = self._report()
        return None if trouble else (last["status"].get("tls_run_counts"))

    def encrypted_dns_state(self) -> dict | None:
        st = self.status()
        return st.get("encrypted_dns")

    def lan_watch_status(self) -> dict | None:
        last, trouble = self._report()
        if trouble:
            return None
        return last["status"].get("lan_watch")


def code_stamp(root: Path = PROJECT) -> tuple:
    """When the code this service runs last changed, as file times."""
    paths = [root / p for p in CODE_FILES]
    heads = root / ".git" / "refs" / "heads"
    if heads.is_dir():
        paths += sorted(heads.rglob("*"))
    out = []
    for p in paths:
        try:
            out.append((str(p), p.stat().st_mtime_ns))
        except OSError:
            continue
    return tuple(out)


def _snapshot(sniffer) -> dict:
    from tools import lan_watch
    out = {"sniffer": sniffer.status(), "liveness": sniffer.liveness()}
    try:
        out["tls_run_counts"] = sniffer.tls_run_counts()
    except Exception as e:                                  # noqa: BLE001
        out["tls_run_counts"] = {"error": str(e)}
    watcher = lan_watch.active()
    out["lan_watch"] = watcher.status() if watcher is not None else None
    return out


def _refresh() -> None:
    """Pick up what the owner changed in the core: armed destinations and the
    LAN baselines live in the database."""
    from tools import lan_watch, payload_ring
    ring = payload_ring.active()
    if ring is not None:
        ring._load_armed()
    watcher = lan_watch.active()
    if watcher is not None and hasattr(watcher, "_load_baselines"):
        watcher._load_baselines()


def run(config: dict, report_seconds: int = REPORT_SECONDS,
        stop_after: float = None) -> int:
    """The service: start the packet sensor, report until told to stop."""
    import uuid
    from adapters import LinuxPacketSniffer
    from core import tool_registry
    from tools import vpn_state

    session_id = str(uuid.uuid4())
    started = time.time()
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, lambda *_: stop.set())
        except ValueError:
            pass                                # not the main thread (tests)
    modules = {}
    try:
        modules["vpn_state"] = vpn_state.VPNState(
            extra_patterns=(config.get("vpn") or {}).get("interface_patterns"))
    except Exception as e:                                  # noqa: BLE001
        logger.warning(f"vpn state not loaded, rows say unknown: {e}")
    tool_registry.init_registry(session_id, modules)
    sniffer = LinuxPacketSniffer(session_id, config)
    sniffer.start()
    stamp = code_stamp()
    restarting = False
    logger.info(f"Capture service started, process {os.getpid()} as "
                f"{pwd.getpwuid(os.geteuid()).pw_name}.")
    try:
        while not stop.is_set():
            try:
                _refresh()
                report(_snapshot(sniffer), started)
            except Exception as e:                          # noqa: BLE001
                logger.error(f"capture service report failed: {e}")
            if stop_after is not None and time.time() - started >= stop_after:
                break
            if code_stamp() != stamp:
                logger.info("The app's code changed; stopping so systemd "
                            "starts the service again on the new code.")
                restarting = True
                break
            stop.wait(report_seconds)
    finally:
        try:
            sniffer.stop()
        finally:
            # A restart on new code is back in seconds, so the last report
            # stands and the core does not go blind or raise for it. If the
            # new process never reports, that report goes stale in
            # STALE_SECONDS and the core says so.
            if restarting:
                logger.info("Capture service stopped for the restart; its "
                            "last report stands until the new one.")
            else:
                try:
                    report(_snapshot(sniffer), started, stopped=True)
                except Exception as e:                      # noqa: BLE001
                    logger.error(f"capture service final report failed: {e}")
                logger.info("Capture service stopped.")
    return 0
