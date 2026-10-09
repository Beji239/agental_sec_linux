# tools/lan_live.py
# The live LAN monitor. Polls the router every 30 seconds and keeps, in
# memory, each device's current upload and download rate, a short rate
# history, and its open connections with byte counts and destination names.
#
# Live data never goes to the database. What is kept: per-device totals each
# minute (lan_traffic_minute) and one row per finished connection (lan_flow).
# No payload is read or stored anywhere.
#
# Totals come from the router's per-device counters, which count every byte
# it forwards. Destinations come from its connection table, so a connection
# that opens and closes between two polls is in the totals but not in the
# destination list.

import ipaddress
import logging
import re
import threading
import time
from collections import deque
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

DEFAULTS = {
    "enabled": True,
    "poll_seconds": 30,
    "history_minutes": 30,
    "dns_poll_seconds": 30,
    "inventory_poll_seconds": 60,
    # Findings worth waking the agent for, see tools/lan_alerts.py.
    "alerts": True,
    "upload_floor_mb": 250,
}
# Each poll is an SSH login on the router, so no setting polls faster.
MIN_POLL_SECONDS = 30
UNREAD = "could not read"
MAX_QUERIES_PER_DEVICE = 200
PROBE_SECONDS = 300
# How often the router copies app addresses from its query log into the sets.
APP_REFRESH_SECONDS = 60
MAX_NAMES = 50000
_MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def settings(config: dict) -> dict:
    block = dict(DEFAULTS)
    block.update((config or {}).get("lan_live") or {})
    for k in ("poll_seconds", "dns_poll_seconds", "inventory_poll_seconds"):
        block[k] = max(MIN_POLL_SECONDS, float(block[k] or 0))
    return block


# Home network ranges only. ipaddress.is_private also covers documentation
# and reserved ranges, which are destinations, not devices.
_LAN_NETS = [ipaddress.ip_network(n) for n in
             ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


def _private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _LAN_NETS)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _minute(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:00+00:00")


class LanLive:
    """One router, watched live. Thread-safe reads through snapshot()."""

    def __init__(self, config: dict, gateway=None, store=True,
                 session_id: str = None, alerts=None):
        from tools import gateway as gw
        self.config = config
        self.cfg = settings(config)
        self.g = gateway or gw.Gateway(config)
        self.store = store
        if alerts is None and store and self.cfg["alerts"]:
            from tools import lan_alerts
            alerts = lan_alerts.LanAlerts(session_id, self.cfg["upload_floor_mb"])
        self.alerts = alerts
        self.router_ip = (config.get("gateway") or {}).get("host")
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._history_len = max(10, int(self.cfg["history_minutes"] * 60
                                        / max(1, self.cfg["poll_seconds"])))
        self.devices = {}        # ip -> live state
        self.flows = {}          # flow key -> last seen flow with rates
        self.names = {}          # (client, address) and address -> name
        self.queries = {}        # client -> deque of recent lookups
        self._query_ids = set()
        self.inventory = {}      # ip -> {mac, hostname}
        self.blocked = set()     # ips and macs
        self.app_blocks = {}     # mac -> [app]
        self.app_state = {"mode": None, "known": [], "learned": {}, "error": None}
        self._last_app_refresh = 0.0
        self.minute = {}         # ip -> bytes this minute
        self.minute_key = None
        self.finished = []       # flows to write
        self._pending_minutes = []   # (minute, {ip: counts}) to write
        self.status = {"ok": False, "read": UNREAD, "error": None,
                       "last_poll": None, "polls": 0, "counters": None}
        self._last_ok = None
        self._started_at = None
        self._last_counters = None
        self._last_dns = 0.0
        self._last_inventory = 0.0
        self._last_probe = 0.0

    # The loop

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._started_at = time.time()
        self._thread = threading.Thread(target=self._loop, name="lan-live",
                                        daemon=True)
        self._thread.start()

    def liveness(self) -> dict:
        """Is the poll loop alive and recent. Read by core/sensor_watch."""
        t = self._thread
        with self._lock:
            err = self.status.get("error")
        return {"started": t is not None,
                "thread_alive": bool(t is not None and t.is_alive()),
                "running": not self._stop.is_set(),
                "interval": int(self.cfg["poll_seconds"]),
                "started_at": self._started_at, "last_ok_at": self._last_ok,
                "consecutive_failures": 0, "last_error": err}

    def stop(self, wait: float = 5.0):
        self._stop.set()
        # A poll under way finishes first, so its records are in this flush.
        t = self._thread
        if t and t.is_alive() and t is not threading.current_thread():
            t.join(wait)
        self._flush(force=True)

    def _loop(self):
        while not self._stop.is_set():
            started = time.time()
            self.poll_once(started)
            self._stop.wait(max(0.5, self.cfg["poll_seconds"]
                                - (time.time() - started)))

    def poll_once(self, now: float = None):
        """One poll. A failed read is recorded as unread, never as quiet."""
        try:
            self.tick(now)
        except Exception as e:
            with self._lock:
                self.status.update(ok=False, read=UNREAD,
                                   error=f"Could not read the router: {e}")
            logger.warning(f"Live LAN poll could not read the router: {e}")

    def tick(self, now: float = None):
        now = now or time.time()
        # Re-probed now and then, so a router agent upgraded while the app
        # runs is picked up without a restart.
        if self.status["counters"] is None or now - self._last_probe >= PROBE_SECONDS:
            self.g.probe()
            self._last_probe = now
            self.status["counters"] = self.g.has("counters")
        if now - self._last_inventory >= self.cfg["inventory_poll_seconds"]:
            self._refresh_inventory()
            self._last_inventory = now
        if now - self._last_dns >= self.cfg["dns_poll_seconds"] and \
                self.g.has("dnslog"):
            self._refresh_names()
            self._last_dns = now
        if self.app_blocks and now - self._last_app_refresh >= APP_REFRESH_SECONDS:
            self._last_app_refresh = now
            try:
                self.g.app_refresh()
            except Exception as e:
                logger.debug(f"App address refresh failed: {e}")
        counters = self.g.counters()["devices"] if self.status["counters"] else None
        flows = self.g.flows()
        with self._lock:
            self._apply(now, counters, flows)
            self.status.update(ok=True, read="ok", error=None,
                               last_poll=_now_iso(),
                               polls=self.status["polls"] + 1)
            self._last_ok = now
        self._flush()
        self._run_alerts(now)

    def _run_alerts(self, now):
        """Hand this poll to the alert checks, outside the lock."""
        if not self.alerts:
            return
        with self._lock:
            inventory = {ip: dict(v) for ip, v in self.inventory.items()}
            blocked = set(self.blocked)
            devices = {ip: {"up_total": d["up_total"]}
                       for ip, d in self.devices.items()}
            flows = [{k: f[k] for k in ("device", "remote", "port", "proto")}
                     for f in self.flows.values()]
            names = {k: self.names[k] for f in flows
                     for k in ((f["device"], f["remote"]), f["remote"])
                     if k in self.names}
        try:
            self.alerts.check(now, inventory, blocked, devices, flows, names)
        except Exception as e:
            logger.warning(f"Live LAN alerts failed: {e}")

    # Inputs

    def _refresh_inventory(self):
        # Neighbours count only on the interface the leased devices sit on,
        # so the router's upstream side is not listed as a device.
        inv = {}
        leases = [r for r in (self.g.leases() if self.g.has("leases") else [])
                  if _private(r["ip"])]
        neigh = self.g.neighbors() if self.g.has("neighbors") else []
        leased = {r["ip"] for r in leases}
        lan_ifaces = {r.get("interface") for r in neigh if r["ip"] in leased}
        for r in neigh:
            if _private(r["ip"]) and (not lan_ifaces or r.get("interface") in lan_ifaces):
                inv.setdefault(r["ip"], {})["mac"] = r["mac"]
        for r in leases:
            inv[r["ip"]] = {"mac": r["mac"], "hostname": r["hostname"]}
        self.lan_prefixes = {ip.rsplit(".", 1)[0] for ip in inv if "." in ip}
        blocked = set(self.g.blocks()) if self.g.has("block") else set()
        apps, app_state = {}, {"mode": None, "known": [], "learned": {}, "error": None}
        if self.g.has("appblock"):
            try:
                a = self.g.app_blocks()
                apps = a["blocks"]
                app_state.update(mode=a["mode"], known=a["known"], learned=a["learned"])
            except Exception as e:
                app_state["error"] = str(e)
        with self._lock:
            self.inventory = inv
            self.blocked = blocked
            self.app_blocks = apps
            self.app_state = app_state

    def _refresh_names(self):
        from tools import dns_monitor as dm
        rows, notes = dm.parse_router_dnslog(self.g.dnslog(dm.ROUTER_LOG_LINES))
        with self._lock:
            if len(self.names) > MAX_NAMES:
                self.names.clear()
            for a in notes["answers"]:
                self.names[(a["client_ip"], a["value"])] = a["name"]
                self.names[a["value"]] = a["name"]
            if len(self._query_ids) > MAX_NAMES:
                self._query_ids.clear()
            for r in rows:
                if r["source_row_id"] in self._query_ids:
                    continue
                self._query_ids.add(r["source_row_id"])
                q = self.queries.setdefault(
                    r["client_ip"], deque(maxlen=MAX_QUERIES_PER_DEVICE))
                q.append({"id": r["source_row_id"], "at": r["queried_at"],
                          "domain": r["domain"], "type": r["query_type"],
                          "blocked": r["blocked"]})

    def _name_for(self, device: str, address: str):
        return self.names.get((device, address)) or self.names.get(address)

    # The arithmetic

    def _device(self, ip: str) -> dict:
        d = self.devices.get(ip)
        if d is None:
            d = self.devices[ip] = {
                "ip": ip, "up_bps": 0.0, "down_bps": 0.0,
                "up_total": 0, "down_total": 0,
                "history": deque(maxlen=self._history_len),
                "first_seen": _now_iso(), "last_active": None}
        return d

    def _apply(self, now, counters, flows):
        elapsed = None
        if self._last_counters is not None:
            elapsed = max(0.001, now - self._last_counters[0])

        # Flows: rates from the change in each connection's byte counts.
        seen = {}
        per_device_flow_rate = {}
        for f in flows:
            src, dst = f["src"], f["dst"]
            if self.router_ip in (src, dst):
                continue
            if _private(src) and not _private(dst):
                device, remote = src, dst
                out_b, in_b = f["bytes_out"], f["bytes_in"]
                out_p, in_p = f["packets_out"], f["packets_in"]
            elif _private(dst) and not _private(src):
                device, remote = dst, src
                out_b, in_b = f["bytes_in"], f["bytes_out"]
                out_p, in_p = f["packets_in"], f["packets_out"]
            else:
                continue
            key = (f["proto"], src, f["sport"], dst, f["dport"])
            prev = self.flows.get(key)
            if prev and elapsed:
                r_out = max(0, out_b - prev["bytes_out"]) / elapsed
                r_in = max(0, in_b - prev["bytes_in"]) / elapsed
            else:
                r_out = r_in = 0.0
            port = f["dport"] if device == src else f["sport"]
            seen[key] = {
                "device": device, "remote": remote, "proto": f["proto"],
                "port": port, "bytes_out": out_b, "bytes_in": in_b,
                "packets_out": out_p, "packets_in": in_p,
                "out_bps": r_out, "in_bps": r_in,
                "first_seen": prev["first_seen"] if prev else _now_iso(),
                "last_seen": _now_iso(), "state": f["state"],
            }
            acc = per_device_flow_rate.setdefault(device, [0.0, 0.0])
            acc[0] += r_out
            acc[1] += r_in

        for key, prev in self.flows.items():
            if key not in seen:
                self.finished.append(prev)
        self.flows = seen

        # Devices: exact totals from the counters, or the flow sums without.
        ips = set(self.inventory) | set(per_device_flow_rate)
        if counters is not None:
            ips |= set(counters)
        prefixes = getattr(self, "lan_prefixes", None)
        for ip in ips:
            if not _private(ip) or ip == self.router_ip:
                continue
            if prefixes and "." in ip and ip.rsplit(".", 1)[0] not in prefixes:
                continue
            d = self._device(ip)
            if counters is not None and ip in counters:
                c = counters[ip]
                last = (self._last_counters[1].get(ip)
                        if self._last_counters else None)
                if last and elapsed:
                    du = c["up_bytes"] - last["up_bytes"]
                    dd = c["down_bytes"] - last["down_bytes"]
                    dup = c["up_packets"] - last["up_packets"]
                    ddp = c["down_packets"] - last["down_packets"]
                    if du < 0 or dd < 0:
                        du = dd = dup = ddp = 0
                else:
                    du = dd = dup = ddp = 0
                d["up_bps"] = du / elapsed if elapsed else 0.0
                d["down_bps"] = dd / elapsed if elapsed else 0.0
            else:
                rates = per_device_flow_rate.get(ip, [0.0, 0.0])
                d["up_bps"], d["down_bps"] = rates
                du = int(rates[0] * (elapsed or 0))
                dd = int(rates[1] * (elapsed or 0))
                dup = ddp = 0
            d["up_total"] += du
            d["down_total"] += dd
            if du or dd:
                d["last_active"] = _now_iso()
            d["history"].append((int(now), round(d["up_bps"]), round(d["down_bps"])))
            m = self.minute.setdefault(ip, [0, 0, 0, 0])
            m[0] += du; m[1] += dd; m[2] += dup; m[3] += ddp

        if counters is not None:
            self._last_counters = (now, counters)
        else:
            self._last_counters = (now, {})

        key = _minute(now)
        if self.minute_key is None:
            self.minute_key = key
        elif key != self.minute_key:
            self._pending_minutes.append((self.minute_key, self.minute))
            self.minute, self.minute_key = {}, key

    # What is kept

    # What a failed write keeps for the next try, so a database that stays
    # locked or broken cannot grow memory without end.
    MAX_PENDING_MINUTES = 120
    MAX_PENDING_FLOWS = 20000

    def _flush(self, force: bool = False):
        if not self.store:
            with self._lock:
                self._pending_minutes = []
                self.finished = []
            return
        with self._lock:
            if force and self.minute:
                # Cleared once taken, so a later poll in the same minute
                # adds to it rather than writing it twice.
                self._pending_minutes.append((self.minute_key, self.minute))
                self.minute = {}
            pending, self._pending_minutes = self._pending_minutes, []
            finished, self.finished = self.finished, []
            inv = dict(self.inventory)
            names = {f["remote"]: self._name_for(f["device"], f["remote"])
                     for f in finished}
        if not pending and not finished:
            return
        try:
            from core import memory_engine as me
            with me._get_conn() as conn:
                for minute, data in pending:
                    conn.executemany("""
                        INSERT INTO lan_traffic_minute
                            (minute, ip, mac, up_bytes, down_bytes,
                             up_packets, down_packets)
                        VALUES (?,?,?,?,?,?,?)
                        ON CONFLICT(minute, ip) DO UPDATE SET
                            up_bytes = up_bytes + excluded.up_bytes,
                            down_bytes = down_bytes + excluded.down_bytes,
                            up_packets = up_packets + excluded.up_packets,
                            down_packets = down_packets + excluded.down_packets
                    """, [(minute, ip, (inv.get(ip) or {}).get("mac"),
                           v[0], v[1], v[2], v[3])
                          for ip, v in data.items() if v[0] or v[1]])
                if finished:
                    conn.executemany("""
                        INSERT INTO lan_flow
                            (device_ip, device_mac, proto, dst, dport,
                             dst_name, bytes_out, bytes_in, packets_out,
                             packets_in, first_seen, last_seen, sensor_id)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, [(f["device"], (inv.get(f["device"]) or {}).get("mac"),
                           f["proto"], f["remote"], f["port"],
                           names.get(f["remote"]), f["bytes_out"],
                           f["bytes_in"], f["packets_out"], f["packets_in"],
                           f["first_seen"], f["last_seen"], "gateway-live")
                          for f in finished])
        except Exception as e:
            # The write rolled back as a whole, so all of it is put back to
            # retry on the next poll.
            with self._lock:
                self._pending_minutes[:0] = pending
                self.finished[:0] = finished
                dropped = (max(0, len(self._pending_minutes)
                               - self.MAX_PENDING_MINUTES),
                           max(0, len(self.finished) - self.MAX_PENDING_FLOWS))
                if dropped[0]:
                    del self._pending_minutes[:dropped[0]]
                if dropped[1]:
                    del self.finished[:dropped[1]]
            lost = ""
            if any(dropped):
                lost = (f" Over the limit kept in memory, so the oldest "
                        f"{dropped[0]} minute(s) and {dropped[1]} connection(s) "
                        f"were dropped.")
            logger.error(f"Live LAN monitor could not store its records, "
                         f"keeping them to retry: {e}.{lost}")

    # Reads

    def _read_status(self, now: float = None) -> dict:
        """The status, with a last good read too old to be current shown as
        unread. Call with the lock held."""
        st = dict(self.status)
        now = time.time() if now is None else now
        if st["ok"] and (self._last_ok is None
                         or now - self._last_ok > 2 * self.cfg["poll_seconds"]):
            age = 0 if self._last_ok is None else int(now - self._last_ok)
            st.update(ok=False, read=UNREAD,
                      error=f"Could not read the router: no answer for {age} s.")
        return st

    def snapshot(self, now: float = None) -> dict:
        with self._lock:
            status = self._read_status(now)
            readable = status["ok"]
            rows = []
            for ip, d in self.devices.items():
                inv = self.inventory.get(ip) or {}
                mac = inv.get("mac")
                conns = [f for f in self.flows.values() if f["device"] == ip]
                rows.append({
                    "ip": ip, "mac": mac, "hostname": inv.get("hostname"),
                    "present": ip in self.inventory,
                    "blocked": bool(ip in self.blocked or (mac and mac in self.blocked)),
                    "blocked_by": ("mac" if mac and mac in self.blocked
                                   else "ip" if ip in self.blocked else None),
                    "apps_blocked": list(self.app_blocks.get(mac) or []),
                    "up_bps": round(d["up_bps"]), "down_bps": round(d["down_bps"]),
                    "up_total": d["up_total"], "down_total": d["down_total"],
                    "connections": len(conns),
                    "destinations": len({f["remote"] for f in conns}),
                    "last_active": d["last_active"],
                    "spark": [(t, u + dn) for t, u, dn in list(d["history"])[-60:]],
                })
            rows.sort(key=lambda r: (-(r["up_bps"] + r["down_bps"]),
                                     -(r["up_total"] + r["down_total"])))
            if not readable:
                for r in rows:
                    r.update(up_bps=None, down_bps=None, connections=None,
                             destinations=None)
            return {"status": status, "devices": rows,
                    "poll_seconds": self.cfg["poll_seconds"],
                    "blocked_macs": sorted(b for b in self.blocked if _MAC.match(b)),
                    "blocked_ips": sorted(b for b in self.blocked if not _MAC.match(b)),
                    "apps": dict(self.app_state)}

    def device(self, ip: str, now: float = None) -> dict:
        with self._lock:
            d = self.devices.get(ip)
            if d is None:
                return {"error": f"{ip} is not a device the live monitor has seen"}
            status = self._read_status(now)
            dests = {}
            for f in self.flows.values():
                if f["device"] != ip:
                    continue
                k = (f["remote"], f["port"], f["proto"])
                x = dests.setdefault(k, {
                    "address": f["remote"], "port": f["port"], "proto": f["proto"],
                    "name": self._name_for(ip, f["remote"]),
                    "out_bps": 0.0, "in_bps": 0.0, "bytes_out": 0,
                    "bytes_in": 0, "connections": 0, "since": f["first_seen"]})
                x["out_bps"] += f["out_bps"]; x["in_bps"] += f["in_bps"]
                x["bytes_out"] += f["bytes_out"]; x["bytes_in"] += f["bytes_in"]
                x["connections"] += 1
                x["since"] = min(x["since"], f["first_seen"])
            dest_rows = sorted(dests.values(), key=lambda x: (
                -(x["out_bps"] + x["in_bps"]), -(x["bytes_out"] + x["bytes_in"])))
            for x in dest_rows:
                x["out_bps"] = round(x["out_bps"]); x["in_bps"] = round(x["in_bps"])
            inv = self.inventory.get(ip) or {}
            readable = status["ok"]
            return {
                "ip": ip, "mac": inv.get("mac"), "hostname": inv.get("hostname"),
                "read": status["read"], "read_error": status["error"],
                "up_bps": round(d["up_bps"]) if readable else None,
                "down_bps": round(d["down_bps"]) if readable else None,
                "up_total": d["up_total"], "down_total": d["down_total"],
                "history": list(d["history"]),
                "destinations": dest_rows[:300] if readable else [],
                "lookups": list(reversed(self.queries.get(ip, [])))[:100],
                "apps_blocked": list(self.app_blocks.get(inv.get("mac")) or []),
                "apps": dict(self.app_state),
            }


# One monitor per process, started by main.py when the gateway is enabled.
_monitor = None


def get() -> "LanLive | None":
    return _monitor


def start(config: dict, session_id: str = None) -> dict:
    global _monitor
    cfg = settings(config)
    gw_block = (config or {}).get("gateway") or {}
    if not (cfg["enabled"] and gw_block.get("enabled") and gw_block.get("host")):
        return {"started": False, "reason": "gateway or lan_live is not enabled"}
    if _monitor is None:
        _monitor = LanLive(config, session_id=session_id)
    _monitor.start()
    return {"started": True}
