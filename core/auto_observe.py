# core/auto_observe.py
# Measured observations from the app's own sensors, written before each
# rollup, so what is normal for each device, process and port is learned
# every session rather than only when the model writes something down.
#
#   LAN devices, from the router (lan_traffic_minute, lan_flow):
#       active_hours, volume_per_hour, connection_count,
#       typical_dest_ports, typical_dest_ips
#   processes on this host (psutil): typical_parent, typical_paths,
#       typical_network_ports
#   listening ports on this host: typical_process
#
# Rows are basis "measured", written_by "system". A value is written once
# per session and again only when it changes, so the table grows by a few
# hundred rows a session, not every hour.

import ipaddress
import logging
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

from core import memory_engine as me

logger = logging.getLogger(__name__)

DEFAULT_WINDOW_MINUTES = 60
MAX_WINDOW_MINUTES = 120
TOP_N = 8
_LAN = [ipaddress.ip_network(n) for n in
        ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]

_written = {}            # (session, entity_type, value, key) -> last value
_last_run = {}           # session -> unix time of the last pass


def _private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _LAN)


def _write(session_id, entity_type, entity_value, key, value, context, counts):
    value = str(value)[:300]
    mark = (session_id, entity_type, entity_value, key)
    if _written.get(mark) == value:
        return
    try:
        out = me.write_behavioral_observation(
            entity_type=entity_type, entity_value=entity_value,
            behavior_key=key, behavior_value=value, session_id=session_id,
            context=context, basis="measured", written_by="system")
    except Exception as e:                              # noqa: BLE001
        counts["refused"] += 1
        logger.debug(f"auto_observe: {entity_type}:{entity_value} {key} refused: {e}")
        return
    if out.get("success"):
        _written[mark] = value
        counts["written"] += 1
    else:
        counts["refused"] += 1


def _lan(session_id, since_iso, hours, counts):
    with me._get_readonly_conn() as conn:
        if not me._table_exists_ro(conn, "lan_traffic_minute"):
            return
        minutes = conn.execute(
            "SELECT ip, minute, up_bytes, down_bytes FROM lan_traffic_minute "
            "WHERE minute >= ?", (since_iso,)).fetchall()
        flows = []
        if me._table_exists_ro(conn, "lan_flow"):
            flows = conn.execute(
                "SELECT device_ip, dst, dst_name, dport, bytes_out, bytes_in "
                "FROM lan_flow WHERE last_seen >= ?", (since_iso,)).fetchall()
    per = {}
    for ip, minute, up, down in minutes:
        if not _private(ip) or not (up or down):
            continue
        d = per.setdefault(ip, {"bytes": 0, "hours": set()})
        d["bytes"] += (up or 0) + (down or 0)
        try:
            local = datetime.fromisoformat(minute).astimezone()
            d["hours"].add(local.hour)
        except ValueError:
            pass
    dests, ports, conns = {}, {}, Counter()
    for device, dst, name, dport, out_b, in_b in flows:
        if not _private(device):
            continue
        conns[device] += 1
        weight = (out_b or 0) + (in_b or 0)
        dests.setdefault(device, Counter())[name or dst] += weight
        if dport:
            ports.setdefault(device, Counter())[int(dport)] += weight
    ctx = "measured through the router by the live LAN monitor"
    for ip, d in per.items():
        if d["hours"]:
            _write(session_id, "ip", ip, "active_hours",
                   ",".join(str(h) for h in sorted(d["hours"])), ctx, counts)
        _write(session_id, "ip", ip, "volume_per_hour",
               int(d["bytes"] / max(hours, 1 / 60)), ctx, counts)
    for ip, n in conns.items():
        _write(session_id, "ip", ip, "connection_count", n, ctx, counts)
        top = [str(p) for p, _ in ports.get(ip, Counter()).most_common(TOP_N)
               if 1 <= p <= 65535]
        if top:
            _write(session_id, "ip", ip, "typical_dest_ports", ",".join(top), ctx, counts)
        names = [str(x) for x, _ in dests.get(ip, Counter()).most_common(TOP_N)]
        if names:
            _write(session_id, "ip", ip, "typical_dest_ips", ",".join(names), ctx, counts)


def _host(session_id, counts):
    try:
        import psutil
    except ImportError:
        return
    seen = {}
    for p in psutil.process_iter(["pid", "name", "exe", "ppid"]):
        info = p.info
        name = (info.get("name") or "").strip()
        if not name or name in seen:
            continue
        parent = None
        try:
            if info.get("ppid"):
                parent = psutil.Process(info["ppid"]).name()
        except (psutil.Error, OSError):
            pass
        seen[name] = {"exe": info.get("exe"), "parent": parent, "ports": set()}
    listening = {}
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.Error, OSError):
        conns = []
    for c in conns:
        if c.pid is None:
            continue
        try:
            name = psutil.Process(c.pid).name()
        except (psutil.Error, OSError):
            continue
        if c.status == psutil.CONN_LISTEN and c.laddr:
            listening.setdefault(c.laddr.port, name)
            port = c.laddr.port
        elif c.raddr:
            port = c.raddr.port
        else:
            continue
        if name in seen and 1 <= port <= 65535:
            seen[name]["ports"].add(port)
    ctx = "measured on this host from the process table"
    for name, d in seen.items():
        if d["parent"]:
            _write(session_id, "process", name, "typical_parent", d["parent"], ctx, counts)
        if d["exe"]:
            _write(session_id, "process", name, "typical_paths", d["exe"], ctx, counts)
        if d["ports"]:
            _write(session_id, "process", name, "typical_network_ports",
                   ",".join(str(x) for x in sorted(d["ports"])[:TOP_N]), ctx, counts)
    for port, name in listening.items():
        _write(session_id, "port", str(port), "typical_process", name,
               "measured on this host from the socket table", counts)


def observe(session_id: str, now: float = None) -> dict:
    """One pass. Never raises; returns what it wrote."""
    now = now or time.time()
    last = _last_run.get(session_id)
    window = DEFAULT_WINDOW_MINUTES if last is None else \
        min(MAX_WINDOW_MINUTES, max(1, (now - last) / 60))
    _last_run[session_id] = now
    since = datetime.fromtimestamp(now, tz=timezone.utc) - timedelta(minutes=window)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:00+00:00")
    counts = {"written": 0, "refused": 0}
    for step in (lambda: _lan(session_id, since_iso, window / 60, counts),
                 lambda: _host(session_id, counts)):
        try:
            step()
        except Exception as e:                          # noqa: BLE001
            logger.warning(f"auto_observe: a pass step failed: {e}")
    if len(_written) > 200000:
        _written.clear()
    return counts
