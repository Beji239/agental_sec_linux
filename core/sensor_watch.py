# core/sensor_watch.py
# The sensor watchdog. Once a minute it reads every polling sensor's own
# liveness and status, says which ones are collecting, records the stretches
# when one was not (sensor_gaps), and raises SYS-1001 when a sensor that was
# collecting goes quiet and SYS-1002 when it comes back.
#
# A high finding becomes an incident, which wakes the duty loop and sends a
# desktop notice, so nothing here talks to either directly.

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from core import memory_engine as me

logger = logging.getLogger(__name__)

SOURCE = "sensor_watch"
CHECK_SECONDS = 60
# Quiet once no poll has succeeded for this many intervals, and never sooner
# than the floor, so a slow pass is not called a stopped sensor.
GRACE_MULTIPLE = 3
GRACE_FLOOR_SECONDS = 300
# A longer silence between two checks means the app itself was not running.
APP_OFF_SECONDS = 180
KEEP_DAYS = 30
# A sensor that keeps dropping out raises SYS-1001 at most once an hour.
ALERT_COOLDOWN_SECONDS = 3600
FAILURE_FLOOR = 3
APP = "agentalsec"

_lock = threading.Lock()
_watch = None


def _sql(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _last_beat() -> int:
    try:
        with me._get_conn() as conn:
            row = conn.execute(
                "SELECT at FROM sensor_watch_beat WHERE id = 1").fetchone()
        return int(row["at"]) if row else 0
    except Exception as e:
        logger.debug(f"sensor watch could not read its last check: {e}")
        return 0


def _beat(ts: float):
    try:
        with me._get_conn() as conn:
            conn.execute("INSERT INTO sensor_watch_beat (id, at, first_at) "
                         "VALUES (1, ?, ?) "
                         "ON CONFLICT(id) DO UPDATE SET at = excluded.at",
                         (int(ts), int(ts)))
    except Exception as e:
        logger.debug(f"sensor watch could not store its check time: {e}")


def _label(name: str) -> str:
    return name.replace("_", " ")


def _minutes(seconds: float) -> str:
    m = max(1, int(round(seconds / 60)))
    return f"{m} minute{'s' if m != 1 else ''}"


def assess(name: str, mod, now: float = None) -> dict | None:
    """
    One sensor: {"sensor", "state", "reason"}, state ok, quiet or off.
    None for a module that is not a polling sensor.
    """
    now = time.time() if now is None else now
    live = getattr(mod, "liveness", None)
    if mod is None or not callable(live):
        return None
    try:
        lv = live()
    except Exception as e:
        return {"sensor": name, "state": "quiet",
                "reason": f"could not report its own health ({type(e).__name__})"}
    try:
        st = mod.status() if callable(getattr(mod, "status", None)) else {}
    except Exception as e:
        st = {"_error": f"{type(e).__name__}: {e}"}
    st = st if isinstance(st, dict) else {}

    def row(state, reason):
        return {"sensor": name, "state": state, "reason": reason}

    if st.get("off_by_config"):
        return row("off", "switched off in Settings")
    if st.get("idle_reason"):
        return row("off", st["idle_reason"])
    eng = st.get("engine")
    if isinstance(eng, dict) and eng.get("installed") is False:
        return row("off", "its scanning engine is not installed")
    if st.get("_error"):
        return row("quiet", f"could not report its own health ({st['_error']})")
    if st.get("blind"):
        return row("quiet", f"cannot see: {st.get('blind_reason') or 'no reason given'}")
    if not lv.get("started"):
        return row("off", st.get("reason") or st.get("note") or "not started")
    if not lv.get("running"):
        return row("quiet", "stopped")
    if not lv.get("thread_alive"):
        return row("quiet", "its polling thread has ended")
    cap = st.get("capture_state")
    if isinstance(cap, dict) and cap.get("alive") is False:
        return row("quiet", "packet capture has stopped"
                   + (f" ({cap['failure']})" if cap.get("failure") else ""))
    fails = lv.get("consecutive_failures") or 0
    if fails >= FAILURE_FLOOR:
        return row("quiet", f"the last {fails} polls failed"
                   + (f" ({lv['last_error']})" if lv.get("last_error") else ""))
    interval = max(1, int(lv.get("interval") or 60))
    grace = max(GRACE_MULTIPLE * interval, GRACE_FLOOR_SECONDS)
    since = lv.get("last_ok_at") or lv.get("started_at") or now
    if now - since > grace:
        err = lv.get("last_error")
        return row("quiet", f"no good poll for {_minutes(now - since)}, "
                            f"expected every {_minutes(interval)}"
                            + (f" ({err})" if err else ""))
    return row("ok", "collecting")


class LoopTracker:
    """Liveness for a plain loop thread that is not an adapter. status()
    returns idle_reason while the collector has nothing to read."""

    def __init__(self, interval: int, idle=None):
        self.interval = max(1, int(interval))
        self._idle = idle or (lambda: None)
        self.thread = None
        self.started_at = None
        self.last_ok_at = None
        self.failures = 0
        self.last_error = None

    def begin(self, thread):
        self.thread = thread
        self.started_at = time.time()

    def ok(self):
        self.last_ok_at = time.time()
        self.failures = 0
        self.last_error = None

    def failed(self, err):
        self.failures += 1
        self.last_error = str(err)

    def liveness(self) -> dict:
        t = self.thread
        return {"started": t is not None,
                "thread_alive": bool(t is not None and t.is_alive()),
                "running": t is not None, "interval": self.interval,
                "started_at": self.started_at, "last_ok_at": self.last_ok_at,
                "consecutive_failures": self.failures,
                "last_error": self.last_error}

    def status(self) -> dict:
        try:
            why = self._idle()
        except Exception as e:
            return {"_error": f"{type(e).__name__}: {e}"}
        return {"idle_reason": why} if why else {}


class SensorWatch:
    def __init__(self, modules: dict, session_id: str = None, save=None,
                 extras=None):
        self.modules = modules
        # Sensors outside the module list, as a callable returning name -> obj.
        self._extras = extras or (lambda: {})
        self.stopped = False
        self.session_id = session_id or SOURCE
        self._save = save or me.save_finding
        self._state = {}        # sensor -> last assessment
        self._alerted = {}      # sensor -> when SYS-1001 was last raised
        self._open_alert = set()  # quiet episodes that raised SYS-1001
        self._checked_at = None
        self._booted = False
        self._started = time.time()

    def check_once(self, now: float = None) -> dict:
        now = time.time() if now is None else now
        if self.stopped:
            return self.current()
        if not self._booted:
            self._boot(now)
        sensors = dict(self.modules or {})
        try:
            sensors.update({k: v for k, v in self._extras().items()
                            if v is not None})
        except Exception as e:
            logger.debug(f"sensor watch could not list the extra sensors: {e}")
        rows = []
        for name, mod in sorted(sensors.items()):
            if self.stopped:
                break
            try:
                a = assess(name, mod, now)
            except Exception as e:
                logger.warning(f"sensor watch could not assess {name}: {e}")
                continue
            if a is None:
                continue
            rows.append(a)
            self._transition(a, now)
        self._checked_at = now
        if self.stopped:
            return self.current()
        _beat(now)
        return summary(rows, now)

    def _boot(self, now: float):
        """Close what the last run left open and record the time it was off."""
        self._booted = True
        last = _last_beat()
        try:
            with me._get_conn() as conn:
                if last:
                    conn.execute("UPDATE sensor_gaps SET ended_at = ? "
                                 "WHERE ended_at IS NULL", (_sql(last),))
                    if now - last > APP_OFF_SECONDS:
                        conn.execute(
                            "INSERT INTO sensor_gaps (sensor, reason, "
                            "started_at, ended_at, session_id) "
                            "VALUES (?,?,?,?,?)",
                            (APP, "AgentalSec was not running", _sql(last),
                             _sql(min(now, self._started)), self.session_id))
                else:
                    conn.execute("UPDATE sensor_gaps SET ended_at = started_at "
                                 "WHERE ended_at IS NULL")
                conn.execute("DELETE FROM sensor_gaps WHERE started_at < ?",
                             (_sql(now - KEEP_DAYS * 86400),))
        except Exception as e:
            logger.warning(f"sensor watch could not tidy its gap list: {e}")

    def _transition(self, a: dict, now: float):
        name, state = a["sensor"], a["state"]
        prev = self._state.get(name)
        self._state[name] = a
        prev_state = prev["state"] if prev else None
        if prev_state == state:
            return
        if state == "quiet":
            self._open_gap(name, a["reason"], now)
            last = self._alerted.get(name, 0)
            if prev_state == "ok" and now - last >= ALERT_COOLDOWN_SECONDS:
                self._alerted[name] = now
                self._open_alert.add(name)
                self._raise("SYS-1001", "high", name,
                            f"Sensor went quiet: {_label(name)}",
                            f"{_label(name)} was collecting and has stopped: "
                            f"{a['reason']}. Until it comes back, nothing it "
                            f"watches is being recorded, so a quiet stretch "
                            f"on the Timeline is not a calm one.", a)
        elif prev_state == "quiet":
            self._close_gap(name, now)
            if state == "ok" and name in self._open_alert:
                self._open_alert.discard(name)
                self._raise("SYS-1002", "info", name,
                            f"Sensor recovered: {_label(name)}",
                            f"{_label(name)} is collecting again after "
                            f"being quiet ({prev['reason']}).", a)

    def _open_gap(self, name, reason, now):
        try:
            with me._get_conn() as conn:
                conn.execute(
                    "INSERT INTO sensor_gaps (sensor, reason, started_at, "
                    "session_id) VALUES (?,?,?,?)",
                    (name, reason, _sql(now), self.session_id))
        except Exception as e:
            logger.warning(f"sensor watch could not record a gap: {e}")

    def _close_gap(self, name, now):
        try:
            with me._get_conn() as conn:
                conn.execute("UPDATE sensor_gaps SET ended_at = ? "
                             "WHERE sensor = ? AND ended_at IS NULL",
                             (_sql(now), name))
        except Exception as e:
            logger.warning(f"sensor watch could not close a gap: {e}")

    def _raise(self, did, severity, name, title, description, a):
        value = f"sensor:{name}"
        try:
            self._save(session_id=self.session_id, source=SOURCE,
                       severity=severity, entity_type="process",
                       entity_value=value, title=title,
                       description=description,
                       raw_data={"sensor": name, "state": a["state"],
                                 "reason": a["reason"]},
                       detection_id=did)
        except Exception as e:
            logger.warning(f"sensor watch could not raise {did} for {name}: {e}")

    def current(self) -> dict:
        return summary(list(self._state.values()), self._checked_at)


def summary(rows: list, checked_at: float = None) -> dict:
    quiet = [r for r in rows if r["state"] == "quiet"]
    if checked_at is None:
        label = "Sensors not checked yet"
    elif quiet:
        label = f"{len(quiet)} sensor{'s' if len(quiet) != 1 else ''} quiet"
    else:
        label = "All sensors OK"
    return {"label": label, "quiet": len(quiet),
            "ok": sum(1 for r in rows if r["state"] == "ok"),
            "off": sum(1 for r in rows if r["state"] == "off"),
            "checked_at": _sql(checked_at) if checked_at else None,
            "sensors": sorted(rows, key=lambda r: (r["state"] != "quiet",
                                                   r["state"] != "ok",
                                                   r["sensor"]))}


def gaps(since_sql: str, until_sql: str) -> list:
    """Gaps that overlap the window, cut to it. Oldest first."""
    try:
        with me._get_conn() as conn:
            found = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='sensor_gaps'").fetchone()
            if not found:
                return []
            rows = conn.execute(
                "SELECT sensor, reason, started_at, ended_at FROM sensor_gaps "
                "WHERE started_at < ? AND (ended_at IS NULL OR ended_at > ?) "
                "ORDER BY started_at", (until_sql, since_sql)).fetchall()
    except Exception as e:
        logger.warning(f"sensor gaps unreadable: {e}")
        return []
    out = []
    for r in rows:
        start = max(r["started_at"], since_sql)
        end = min(r["ended_at"] or until_sql, until_sql)
        out.append({"sensor": r["sensor"], "label": (
                        "AgentalSec" if r["sensor"] == APP
                        else _label(r["sensor"])),
                    "reason": r["reason"], "start": start, "end": end,
                    "open": r["ended_at"] is None})
    return out


def stop():
    """Stop judging, first thing at shutdown, so stopped sensors are not
    reported as quiet. The last check time is stored for the next boot."""
    with _lock:
        w = _watch
    if w is None:
        return
    w.stopped = True
    if w._booted:
        _beat(time.time())


def watched_since() -> str | None:
    """The first check ever made. Before it, nothing was checked."""
    try:
        with me._get_conn() as conn:
            row = conn.execute(
                "SELECT first_at FROM sensor_watch_beat WHERE id = 1").fetchone()
        return _sql(row["first_at"]) if row else None
    except Exception as e:
        logger.debug(f"sensor watch start time unreadable: {e}")
        return None


def current() -> dict:
    with _lock:
        w = _watch
    if w is None:
        return summary([], None)
    return w.current()


def start(modules: dict, session_id: str = None, extras=None) -> SensorWatch:
    """Start the once-a-minute check on a daemon thread."""
    global _watch
    with _lock:
        if _watch is not None:
            return _watch
        _watch = SensorWatch(modules, session_id, extras=extras)

    def loop():
        # Let the sensors take their first poll before judging them.
        time.sleep(CHECK_SECONDS)
        while not _watch.stopped:
            try:
                _watch.check_once()
            except Exception as e:
                logger.warning(f"sensor watch pass failed: {e}")
            time.sleep(CHECK_SECONDS)

    threading.Thread(target=loop, name="sensor-watch", daemon=True).start()
    logger.info("Sensor watch started, checking every minute.")
    return _watch
