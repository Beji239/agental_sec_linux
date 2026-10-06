# tools/lan_alerts.py
# Findings from the live LAN monitor worth waking the agent for. lan_live
# calls check() after each poll with what it read from the router:
#
#   LAN-1008  a hardware address the inventory has never held
#   LAN-1009  a device uploading far more than its own history
#   LAN-1010  a device connected to an address or domain on a threat feed
#   LAN-1011  a blocked device back under a new address
#
# High findings wake the duty loop through the incident watcher. Each alert
# is rate limited here, and a dismissed address raises nothing.

import logging
import re
import statistics
import time
from collections import deque

from core import memory_engine as me

logger = logging.getLogger(__name__)

SOURCE = "lan_live"
KNOWN_REFRESH_SECONDS = 60
UPLOAD_WINDOW_SECONDS = 600
UPLOAD_COOLDOWN_SECONDS = 6 * 3600
BASELINE_REFRESH_SECONDS = 3600
BASELINE_DAYS = 7
# A device needs a day of minutes before its own history is trusted.
BASELINE_MIN_MINUTES = 24 * 60
FEED_RECHECK_SECONDS = 3600
FEED_COOLDOWN_SECONDS = 24 * 3600
MB = 1024 * 1024
_MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


class LanAlerts:
    def __init__(self, session_id: str = None, upload_floor_mb: float = 250,
                 save=None):
        self.session_id = session_id or SOURCE
        self.upload_floor = max(10, float(upload_floor_mb)) * MB
        self._save = save or me.save_finding
        self._known_macs = None
        self._known_ip_mac = {}
        self._known_at = 0.0
        self._alerted_macs = set()
        self._last_ip = {}            # mac -> ip last seen in the inventory
        self._blocked_mac_of = {}     # blocked ip -> its hardware address
        self._returned = set()        # (mac, ip) already raised
        self._uploads = {}            # ip -> deque of (ts, up_total)
        self._upload_alerted = {}     # ip -> ts
        self._baselines = {}          # ip -> (ts, bytes per minute or None)
        self._feed_seen = {}          # remote -> ts it was last looked up
        self._feed_alerted = {}       # (device, remote) -> ts

    # One pass

    def check(self, now: float, inventory: dict, blocked: set, devices: dict,
              flows: list, names: dict) -> list:
        """Raise what this poll shows. Returns the findings raised."""
        self._refresh_known(now)
        raised = []
        for step in (lambda: self._new_devices(inventory),
                     lambda: self._returned_devices(inventory, blocked),
                     lambda: self._uploads_check(now, devices),
                     lambda: self._feed_contacts(now, flows, names)):
            try:
                raised += step()
            except Exception as e:
                logger.warning(f"Live LAN alert check failed: {e}")
        for mac_ip in ((v.get("mac"), ip) for ip, v in inventory.items()):
            if mac_ip[0]:
                self._last_ip[mac_ip[0].lower()] = mac_ip[1]
        return raised

    def _raise(self, detection_id, severity, ip, title, description, raw):
        if me.is_dismissed("ip", ip):
            return None
        if me.finding_already_open(SOURCE, "ip", ip, title):
            return None
        self._save(session_id=self.session_id, source=SOURCE,
                   severity=severity, entity_type="ip", entity_value=ip,
                   title=title, description=description, raw_data=raw,
                   detection_id=detection_id)
        return {"detection_id": detection_id, "severity": severity,
                "ip": ip, "title": title}

    def _refresh_known(self, now):
        if self._known_macs is not None and \
                now - self._known_at < KNOWN_REFRESH_SECONDS:
            return
        try:
            rows = me.query_known_devices()
        except Exception as e:
            logger.debug(f"Inventory unreadable for live alerts: {e}")
            return
        self._known_macs = {r["mac"].lower() for r in rows if r.get("mac")}
        self._known_ip_mac = {r["ip"]: r["mac"].lower() for r in rows
                              if r.get("ip") and r.get("mac")}
        self._known_at = now

    # LAN-1008

    def _new_devices(self, inventory) -> list:
        # Without a readable inventory every device would look new.
        if self._known_macs is None:
            return []
        out = []
        for ip, entry in inventory.items():
            mac = (entry.get("mac") or "").lower()
            if not mac or mac in self._known_macs or mac in self._alerted_macs:
                continue
            self._alerted_macs.add(mac)
            from core import oui
            v = oui.lookup(mac)
            maker = v.get("vendor") or ("a private, randomized address"
                                        if v.get("status") == "randomized"
                                        else "an unregistered maker")
            name = entry.get("hostname") or "no name given"
            hit = self._raise(
                "LAN-1008", "high", ip,
                f"New device on the network: {ip} ({mac})",
                (f"The router lists {ip} with hardware address {mac}, which "
                 f"the device inventory has never held. Maker: {maker}. Name "
                 f"it gave the router: {name}.\n\nA new device is often a "
                 f"guest or a new purchase. If nobody here recognises it, "
                 f"look at what it connects to on the Live LAN tab, and cut "
                 f"it off at the router if needed."),
                {"ip": ip, "mac": mac, "hostname": entry.get("hostname"),
                 "vendor": v.get("vendor"), "oui_status": v.get("status")})
            if hit:
                out.append(hit)
        return out

    # LAN-1011

    def _returned_devices(self, inventory, blocked) -> list:
        blocked_macs = {b.lower() for b in blocked if _MAC.match(b.lower())}
        blocked_ips = {b for b in blocked if b.lower() not in blocked_macs}
        for ip in blocked_ips:
            mac = ((inventory.get(ip) or {}).get("mac")
                   or self._known_ip_mac.get(ip))
            if mac:
                self._blocked_mac_of[ip] = mac.lower()
        out = []
        for ip, entry in inventory.items():
            mac = (entry.get("mac") or "").lower()
            if not mac or ip in blocked_ips or (mac, ip) in self._returned:
                continue
            old_ips = [b for b, m in self._blocked_mac_of.items() if m == mac]
            by_mac = mac in blocked_macs
            moved = by_mac and self._last_ip.get(mac) not in (None, ip)
            if not old_ips and not moved:
                continue
            self._returned.add((mac, ip))
            if old_ips and not by_mac:
                severity = "high"
                state = (f"Its old address {', '.join(sorted(old_ips))} is "
                         f"blocked, the new one is NOT, so it is online again. "
                         f"Block it by hardware address at the router to keep "
                         f"it off whatever address it takes.")
            else:
                severity = "medium"
                state = ("The router blocks it by hardware address, so it is "
                         "still cut off. It asked for a new address, which is "
                         "worth knowing about.")
            hit = self._raise(
                "LAN-1011", severity, ip,
                f"Blocked device back under a new address: {ip} ({mac})",
                (f"A device that was blocked has come back as {ip} with "
                 f"hardware address {mac}. {state}"),
                {"ip": ip, "mac": mac, "blocked_ips": sorted(old_ips),
                 "blocked_by_mac": by_mac,
                 "previous_ip": self._last_ip.get(mac)})
            if hit:
                out.append(hit)
        return out

    # LAN-1009

    def _baseline(self, now, ip):
        """A high minute for this device, from its own last week, or None."""
        cached = self._baselines.get(ip)
        if cached and now - cached[0] < BASELINE_REFRESH_SECONDS:
            return cached[1]
        value = None
        try:
            with me._get_readonly_conn() as conn:
                rows = [r[0] for r in conn.execute(
                    "SELECT up_bytes FROM lan_traffic_minute WHERE ip = ? AND "
                    "minute >= strftime('%Y-%m-%dT%H:%M:00+00:00', 'now', ?)",
                    (ip, f"-{BASELINE_DAYS} days")).fetchall()]
            if len(rows) >= BASELINE_MIN_MINUTES:
                value = statistics.quantiles(rows, n=100)[98]
        except Exception as e:
            logger.debug(f"No upload history for {ip}: {e}")
        self._baselines[ip] = (now, value)
        return value

    def _uploads_check(self, now, devices) -> list:
        out = []
        for ip, d in devices.items():
            total = d.get("up_total")
            if total is None:
                continue
            q = self._uploads.setdefault(ip, deque())
            if q and total < q[-1][1]:
                q.clear()          # counters restarted
            q.append((now, total))
            while q and now - q[0][0] > UPLOAD_WINDOW_SECONDS:
                q.popleft()
            if len(q) < 2 or now - q[0][0] < UPLOAD_WINDOW_SECONDS * 0.8:
                continue
            sent = q[-1][1] - q[0][1]
            if sent < self.upload_floor:
                continue
            if ip in self._upload_alerted and \
                    now - self._upload_alerted[ip] < UPLOAD_COOLDOWN_SECONDS:
                continue
            minute = self._baseline(now, ip)
            minutes = (q[-1][0] - q[0][0]) / 60
            if minute is not None:
                limit = max(self.upload_floor, 5 * minute * minutes)
                basis = (f"its busiest minutes over the last {BASELINE_DAYS} "
                         f"days send about {minute / MB:.1f} MB, so five times "
                         f"that over {minutes:.0f} minutes is "
                         f"{limit / MB:.0f} MB")
            else:
                limit = 2 * self.upload_floor
                basis = (f"it has under a day of history, so only the fixed "
                         f"limit of {limit / MB:.0f} MB applies")
            if sent < limit:
                continue
            self._upload_alerted[ip] = now
            hit = self._raise(
                "LAN-1009", "high", ip,
                f"Unusual upload from {ip}: {sent / MB:.0f} MB in "
                f"{minutes:.0f} minutes",
                (f"{ip} sent {sent / MB:.0f} MB out through the router in the "
                 f"last {minutes:.0f} minutes, and {basis}. A backup or a "
                 f"video call can do this; so can data being taken. The Live "
                 f"LAN tab shows where it is going."),
                {"ip": ip, "sent_bytes": sent, "window_minutes": round(minutes, 1),
                 "limit_bytes": int(limit), "baseline_minute_bytes": minute})
            if hit:
                out.append(hit)
        return out

    # LAN-1010

    def _feed_contacts(self, now, flows, names) -> list:
        from tools import feed_matcher as fm
        fresh = [f for f in flows if f["remote"] not in self._feed_seen
                 or now - self._feed_seen[f["remote"]] >= FEED_RECHECK_SECONDS]
        if not fresh:
            return []
        out = []
        with me._get_readonly_conn() as conn:
            for f in fresh:
                device, remote = f["device"], f["remote"]
                self._feed_seen[remote] = now
                hit, what = fm._feed_hit_ip(conn, remote), remote
                matched = None
                name = names.get((device, remote)) or names.get(remote)
                if not hit and name:
                    found = fm._feed_hit_domain(conn, name)
                    if found:
                        matched, feed, family = found
                        hit, what = (feed, family), f"{name} ({remote})"
                if not hit:
                    continue
                key = (device, remote)
                if key in self._feed_alerted and \
                        now - self._feed_alerted[key] < FEED_COOLDOWN_SECONDS:
                    continue
                self._feed_alerted[key] = now
                feed, family = hit
                severity = fm._severity_for_feed(feed, False)
                r = self._raise(
                    "LAN-1010", severity, device,
                    f"{device} connected to a listed address: {what}",
                    (f"{device} has a connection through the router to {what}, "
                     f"port {f.get('port')}, which is on the {feed} feed"
                     + (f" ({family})" if family else "")
                     + (f", matched as {matched}" if matched and matched != name else "")
                     + ". A feed hit from a device is a strong signal: find "
                       "what on that device opened it, and cut it off at the "
                       "router if it cannot be explained."),
                    {"device": device, "remote": remote, "name": name,
                     "port": f.get("port"), "proto": f.get("proto"),
                     "feed": feed, "family": family, "matched": matched})
                if r:
                    out.append(r)
        return out
