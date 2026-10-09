# tools/place_watch.py
# Learns which countries and networks each program and device normally
# reaches, and raises GEO-1001 (new country) and GEO-1002 (new network) when
# one reaches somewhere new after its learning period.
#
# Subjects: a program on this machine (from packet attribution), this machine
# itself for traffic no program could be named for, and each device on the
# network (from the router's connection log, keyed by hardware address).
# Without a router agent only the first two are learned.

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from core import geoip
from core import memory_engine as me

logger = logging.getLogger(__name__)

ROLE = "place_watch"
DEFAULTS = {"enabled": True, "interval_seconds": 300, "learn_hours": 72,
            "max_alerts_per_pass": 20, "batch_rows": 200000,
            "max_batches": 5, "seed_hours": 24}
TRAFFIC_KEEP_DAYS = 8
THIS_MACHINE = "this machine"

_instance = None


def settings(config: dict) -> dict:
    out = dict(DEFAULTS)
    out.update((config or {}).get("place_watch") or {})
    return out


def _csv_union(a, b) -> str:
    """Two comma lists as one, for the tally's ports and protocols."""
    items = {x for x in f"{a or ''},{b or ''}".split(",") if x}
    return ",".join(sorted(items))


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _parse(value) -> datetime | None:
    try:
        text = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


class PlaceWatch:
    def __init__(self, config: dict, session_id: str = None):
        self.cfg = settings(config)
        self.session_id = session_id
        self._stop = threading.Event()
        self._tally = {}
        self._thread = None
        self.last_pass = None
        self._started_at = None
        self._last_ok_at = None

    # Thread

    def start(self) -> bool:
        if not self.cfg.get("enabled"):
            return False
        self._started_at = time.time()
        self._thread = threading.Thread(target=self._loop, name="place_watch",
                                        daemon=True)
        self._thread.start()
        return True

    def stop(self, wait: float = 5.0):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=wait)

    def liveness(self) -> dict:
        """Is the learning loop alive and recent. Read by core/sensor_watch."""
        t = self._thread
        err = (self.last_pass or {}).get("error")
        return {"started": t is not None,
                "thread_alive": bool(t is not None and t.is_alive()),
                "running": not self._stop.is_set(),
                "interval": int(self.cfg["interval_seconds"]),
                "started_at": self._started_at, "last_ok_at": self._last_ok_at,
                "consecutive_failures": 0, "last_error": err}

    def _loop(self):
        while not self._stop.wait(5 if self.last_pass is None
                                  else self.cfg["interval_seconds"]):
            try:
                self.learn_once()
            except Exception as e:                          # noqa: BLE001
                logger.error(f"place_watch: pass failed: {e}", exc_info=True)
                self.last_pass = {"at": _iso(datetime.now(timezone.utc)),
                                  "error": str(e)}

    # Reading

    def _cursor(self, conn, source: str, table: str, time_col: str,
                now: datetime) -> int:
        row = conn.execute("SELECT last_id FROM place_cursor WHERE source = ?",
                           (source,)).fetchone()
        if row is not None:
            return int(row[0])
        # First run: learn from the last day rather than from all history.
        seed = now - timedelta(hours=self.cfg["seed_hours"])
        stamp = (seed.strftime("%Y-%m-%d %H:%M:%S") if table == "packets"
                 else _iso(seed))
        first = conn.execute(f"SELECT MIN(id) FROM {table} WHERE "
                             f"{time_col} >= ?", (stamp,)).fetchone()[0]
        if first is None:
            first = (conn.execute(f"SELECT MAX(id) FROM {table}").fetchone()[0]
                     or 0) + 1
        return int(first) - 1

    def _read(self, conn, now: datetime) -> tuple[list, dict]:
        """
        Observations since the cursors: (subject_type, subject, label, ip).
        The packet read also fills self._tally, the hourly destination tally
        the Threat Map reads.
        """
        obs, cursors = [], {}
        self._tally = {}
        own = None
        if me._table_exists_ro(conn, "packets") \
                and me._table_exists_ro(conn, "place_traffic"):
            start = self._cursor(conn, "traffic", "packets", "captured_at", now)
            top, batch = start, int(self.cfg["batch_rows"])
            for _ in range(int(self.cfg["max_batches"])):
                rows = conn.execute("""
                    SELECT substr(captured_at, 1, 13) || ':00:00' AS hour,
                           src_ip, dst_ip, process_name,
                           COUNT(*) AS packets,
                           COALESCE(SUM(packet_size), 0) AS bytes,
                           GROUP_CONCAT(DISTINCT dst_port) AS ports,
                           GROUP_CONCAT(DISTINCT protocol) AS protocols,
                           GROUP_CONCAT(DISTINCT threat_label) AS labels,
                           MAX(id) AS top
                      FROM (SELECT id, captured_at, src_ip, dst_ip,
                                   process_name, packet_size, dst_port,
                                   protocol, threat_label
                              FROM packets WHERE id > ? ORDER BY id LIMIT ?)
                     GROUP BY hour, src_ip, dst_ip, process_name""",
                    (top, batch)).fetchall()
                if not rows:
                    break
                read = sum(r["packets"] for r in rows)
                top = max(r["top"] for r in rows)
                for r in rows:
                    self._count(r, obs)
                if read < batch:
                    break
            cursors["traffic"] = top
        if me._table_exists_ro(conn, "lan_flow"):
            from core import place_map
            own = place_map.own_addresses()
            labels = place_map.device_labels()
            start = self._cursor(conn, "lan_flow", "lan_flow", "last_seen", now)
            rows = conn.execute("""
                SELECT device_ip, MAX(device_mac) AS mac, dst, MAX(id) AS top
                  FROM (SELECT id, device_ip, device_mac, dst FROM lan_flow
                         WHERE id > ? ORDER BY id LIMIT ?)
                 GROUP BY device_ip, dst""",
                (start, self.cfg["batch_rows"])).fetchall()
            top = start
            for r in rows:
                top = max(top, r["top"])
                if r["device_ip"] in own or not geoip.is_routable(r["dst"]):
                    continue
                mac = (r["mac"] or "").lower()
                name = place_map._label(labels, r["device_ip"], mac)
                obs.append(("device", mac or r["device_ip"],
                            name or r["device_ip"], r["dst"]))
            cursors["lan_flow"] = top
        return obs, cursors

    def _count(self, r, obs: list) -> None:
        """One grouped packet row into the observations and the tally."""
        for near, far in ((r["src_ip"], r["dst_ip"]),
                          (r["dst_ip"], r["src_ip"])):
            if not far or not geoip.is_routable(far):
                continue
            proc = r["process_name"] or ""
            if proc:
                obs.append(("program", proc, proc, far))
            else:
                obs.append(("device", THIS_MACHINE, THIS_MACHINE, far))
            key = (r["hour"], far, near or "", proc)
            t = self._tally.setdefault(key, [0, 0, set(), set(), set()])
            t[0] += r["packets"] or 0
            t[1] += r["bytes"] or 0
            for i, col in ((2, "ports"), (3, "protocols"), (4, "labels")):
                t[i] |= {x for x in str(r[col] or "").split(",") if x}
            return

    # Learning

    def learn_once(self, now: datetime = None) -> dict:
        now = now or datetime.now(timezone.utc)
        stamp = _iso(now)
        learn = timedelta(hours=self.cfg["learn_hours"])

        # Read and decide on a read-only connection, then write in one short
        # transaction, so the other writers in the app are not held up.
        with me._get_readonly_conn() as conn:
            if not me._table_exists_ro(conn, "place_baseline"):
                return {"ran": False, "reason": "place_baseline table missing"}
            obs, cursors = self._read(conn, now)
            known, subj_first, anywhere = set(), {}, set()
            for r in conn.execute("SELECT subject_type, subject, place_type, "
                                  "place, first_seen FROM place_baseline"):
                known.add((r[0], r[1], r[2], r[3]))
                anywhere.add((r[2], r[3]))
                key = (r[0], r[1])
                if subj_first.get(key) is None or r[4] < subj_first[key]:
                    subj_first[key] = r[4]

        # Place lookups once per address.
        places_by_ip = {}
        for _, _, _, ip in obs:
            if ip in places_by_ip:
                continue
            geo, net = geoip.lookup(ip), geoip.asn_lookup(ip)
            p = []
            if geo and geo.get("country_code"):
                p.append(("country", geo["country_code"],
                          geo.get("country") or geo["country_code"]))
            if net:
                p.append(("network", net["asn"],
                          f"{net['asn']} {net['org']}".strip()))
            places_by_ip[ip] = p

        updates, inserts, new = [], [], []
        seen_pairs = set()
        for stype, subj, label, ip in obs:
            for ptype, place, plabel in places_by_ip[ip]:
                key = (stype, subj, ptype, place)
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                if key in known:
                    updates.append((stamp, stype, subj, ptype, place))
                    continue
                inserts.append((stype, subj, ptype, place, plabel, ip,
                                stamp, stamp))
                first = _parse(subj_first.get((stype, subj)))
                if first is not None and now - first >= learn:
                    new.append({"subject_type": stype, "subject": subj,
                                "label": label, "place_type": ptype,
                                "place": place, "place_label": plabel,
                                "ip": ip,
                                "home_first": (ptype, place) not in anywhere})
                anywhere.add((ptype, place))
        learned = len(inserts)

        with me._get_conn() as conn:
            conn.executemany(
                "UPDATE place_baseline SET hits = hits + 1, last_seen = ? "
                "WHERE subject_type = ? AND subject = ? AND place_type = ? "
                "AND place = ?", updates)
            conn.executemany(
                "INSERT OR IGNORE INTO place_baseline (subject_type, subject, "
                "place_type, place, place_label, example_ip, hits, "
                "first_seen, last_seen) VALUES (?,?,?,?,?,?,1,?,?)", inserts)
            conn.executemany(
                "INSERT INTO place_cursor (source, last_id) VALUES (?, ?) "
                "ON CONFLICT(source) DO UPDATE SET last_id = excluded.last_id",
                list(cursors.items()))
            conn.create_function("csv_union", 2, _csv_union)
            conn.executemany(
                "INSERT INTO place_traffic (hour, remote_ip, local_ip, process, "
                "packets, bytes, ports, protocols, threat_labels) "
                "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(hour, remote_ip, "
                "local_ip, process) DO UPDATE SET "
                "packets = packets + excluded.packets, "
                "bytes = bytes + excluded.bytes, "
                "ports = csv_union(ports, excluded.ports), "
                "protocols = csv_union(protocols, excluded.protocols), "
                "threat_labels = csv_union(threat_labels, excluded.threat_labels)",
                [(k[0], k[1], k[2], k[3], v[0], v[1], ",".join(sorted(v[2])),
                  ",".join(sorted(v[3])), ",".join(sorted(v[4])))
                 for k, v in self._tally.items()])
            if self._tally or "traffic" in cursors:
                keep = (now - timedelta(days=TRAFFIC_KEEP_DAYS)).strftime(
                    "%Y-%m-%d %H:00:00")
                conn.execute("DELETE FROM place_traffic WHERE hour < ?", (keep,))
                # The learner's old packet cursor, replaced by "traffic".
                conn.execute("DELETE FROM place_cursor WHERE source = 'packets'")

        raised = self._raise(new)
        # Refresh the map picture while we are here, so opening it is quick.
        try:
            from core import place_map
            place_map.gather(session_id=self.session_id, fresh=True)
        except Exception as e:                              # noqa: BLE001
            logger.debug(f"place_watch: map refresh failed: {e}")
        self.last_pass = {"at": stamp, "observations": len(obs),
                          "new_places": learned,
                          "alerts": raised, "cursors": cursors}
        self._last_ok_at = time.time()
        return {"ran": True, **self.last_pass}

    def _raise(self, new: list) -> int:
        cap = int(self.cfg["max_alerts_per_pass"])
        raised = 0
        for n in new[:cap]:
            country = n["place_type"] == "country"
            did = "GEO-1001" if country else "GEO-1002"
            sev = "medium" if country and n["home_first"] else "low"
            who = ("Program " if n["subject_type"] == "program"
                   else "Device ") + n["label"]
            kind = "country" if country else "network"
            first_home = (" Nothing in this home had reached it before."
                          if n["home_first"] else "")
            try:
                me.save_finding(
                    session_id=self.session_id, source=ROLE, severity=sev,
                    entity_type="ip", entity_value=n["ip"], detection_id=did,
                    title=f"{who} reached a new {kind}: {n['place_label']}",
                    description=(f"{who} reached {n['ip']} in "
                                 f"{n['place_label']}, a {kind} it had not "
                                 f"reached before.{first_home} A new place is "
                                 f"a prompt to look, not a verdict."),
                    raw_data=n)
                raised += 1
            except Exception as e:                          # noqa: BLE001
                logger.error(f"place_watch: could not raise {did}: {e}")
        if len(new) > cap:
            logger.warning(
                f"place_watch: {len(new)} new places this pass, {cap} raised. "
                f"The rest are recorded in place_baseline and listed in the "
                f"map summary, not raised as alerts.")
        return raised

    def status(self) -> dict:
        out = {"enabled": bool(self.cfg.get("enabled")),
               "learn_hours": self.cfg["learn_hours"],
               "network_db": geoip.asn_status(), "last_pass": self.last_pass}
        try:
            with me._get_readonly_conn() as conn:
                if me._table_exists_ro(conn, "place_baseline"):
                    out["subjects"] = conn.execute(
                        "SELECT COUNT(DISTINCT subject_type || ':' || subject) "
                        "FROM place_baseline").fetchone()[0]
        except Exception as e:                              # noqa: BLE001
            out["error"] = str(e)
        return out


def places_for(subject: str, limit: int = 60) -> dict:
    """The places one program or device normally reaches."""
    subject = (subject or "").strip()
    try:
        with me._get_readonly_conn() as conn:
            if not me._table_exists_ro(conn, "place_baseline"):
                return {"subject": subject, "places": [],
                        "note": "Place learning has not run on this database."}
            rows = conn.execute(
                "SELECT subject_type, subject, place_type, place, place_label, "
                "hits, first_seen, last_seen FROM place_baseline "
                "WHERE subject = ? OR subject = LOWER(?) "
                "ORDER BY place_type, hits DESC LIMIT ?",
                (subject, subject, limit)).fetchall()
    except Exception as e:                                  # noqa: BLE001
        return {"subject": subject, "places": [], "error": str(e)}
    return {"subject": subject, "places": [dict(r) for r in rows],
            "learn_hours": DEFAULTS["learn_hours"]}


def get() -> "PlaceWatch | None":
    return _instance


def start(config: dict, session_id: str = None) -> dict:
    global _instance
    _instance = PlaceWatch(config, session_id)
    if not _instance.start():
        return {"started": False, "reason": "disabled in config"}
    return {"started": True, "learn_hours": _instance.cfg["learn_hours"],
            "network_db": geoip.asn_status()["status"]}
