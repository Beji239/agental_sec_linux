# core/place_map.py
# One picture of where this home's traffic goes. The Threat Map page, the
# agent's map tool, the wake digest and the place learner all read it here.
#
# Two sources. This machine's own capture (packets, with the program behind
# each when it could be attributed) always. The router's finished
# connections (lan_flow, from the OpenWrt router agent) when they exist,
# with the device named on each. Without a router agent the map still shows
# this machine's destinations, and says the rest of the home is not covered.

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from core import geoip
from core import memory_engine as me

logger = logging.getLogger(__name__)

ROUTER_WINDOW_HOURS = 24
NAMES_PER_POINT = 5


def _split(v):
    return {x for x in (v or "").split(",") if x}


def _iso_hours_ago(hours: float) -> str:
    t = datetime.now(timezone.utc) - timedelta(hours=hours)
    return t.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _size(n: int) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def own_addresses() -> set:
    """Every address this machine holds."""
    import socket
    found = set()
    try:
        import psutil
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family in (socket.AF_INET, socket.AF_INET6) and a.address:
                    found.add(str(a.address).split("%")[0])
    except Exception as e:                                  # noqa: BLE001
        logger.debug(f"place_map: could not read local addresses: {e}")
    return found


def device_labels() -> dict:
    """{"mac": {...}, "ip": {...}} from the device inventory, never raises."""
    by_mac, by_ip = {}, {}
    try:
        with me._get_readonly_conn() as conn:
            rows = [dict(r) for r in conn.execute(
                "SELECT ip, mac, known_as, hostname, vendor, device_type, "
                "retired_at, merged_into FROM known_devices").fetchall()]
        for d in rows:
            name = (d.get("known_as") or d.get("hostname") or d.get("vendor")
                    or "")
            row = {"name": name, "mac": (d.get("mac") or "").lower(),
                   "type": d.get("device_type")}
            if row["mac"]:
                by_mac[row["mac"]] = row
            if d.get("ip") and not d.get("retired_at") \
                    and not d.get("merged_into"):
                by_ip[d["ip"]] = row
    except Exception as e:                                  # noqa: BLE001
        logger.debug(f"place_map: device inventory unavailable: {e}")
    return {"mac": by_mac, "ip": by_ip}


def _label(labels: dict, ip: str, mac: str) -> str:
    row = (labels["mac"].get((mac or "").lower())
           or labels["ip"].get(ip or ""))
    return (row or {}).get("name") or ""


def router_flows(hours: float = ROUTER_WINDOW_HOURS, dst: str = None) -> dict:
    """
    The router's connections in the window, one row per device and remote
    address. available False with a reason when there is no router data.
    """
    since = _iso_hours_ago(hours)
    try:
        with me._get_readonly_conn() as conn:
            if not me._table_exists_ro(conn, "lan_flow"):
                return {"available": False, "rows": [], "hours": hours,
                        "reason": "No router connection data. The rest of "
                                  "the home appears here once the OpenWrt "
                                  "router agent is set up."}
            sql = """
                SELECT device_ip, MAX(device_mac) AS device_mac, dst,
                       GROUP_CONCAT(DISTINCT dport) AS ports,
                       GROUP_CONCAT(DISTINCT proto) AS protocols,
                       MAX(dst_name) AS dst_name,
                       SUM(bytes_out) AS bytes_out, SUM(bytes_in) AS bytes_in,
                       SUM(packets_out + packets_in) AS packets,
                       MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen
                  FROM lan_flow WHERE last_seen >= ?"""
            args = [since]
            if dst:
                sql += " AND dst = ?"
                args.append(dst)
            sql += " GROUP BY device_ip, dst"
            rows = [dict(r) for r in conn.execute(sql, args).fetchall()]
    except Exception as e:                                  # noqa: BLE001
        return {"available": False, "rows": [], "hours": hours,
                "reason": f"The router connection table could not be read: {e}"}
    if not rows and not dst:
        return {"available": False, "rows": [], "hours": hours,
                "reason": f"No router connections in the last {hours:g} "
                          f"hours. Without the OpenWrt router agent only "
                          f"this machine's own traffic is on the map."}
    return {"available": True, "rows": rows, "hours": hours, "reason": None}


def process_pairs(session_id: str = None, since: str = None,
                  ip: str = None) -> list:
    """Packets this machine captured, by program, for each address pair."""
    where, args = ["process_name IS NOT NULL"], []
    if session_id:
        where.append("session_id = ?")
        args.append(session_id)
    if since:
        where.append("captured_at >= ?")
        args.append(me._sql_datetime(since))
    if ip:
        where.append("(src_ip = ? OR dst_ip = ?)")
        args += [ip, ip]
    sql = (f"SELECT src_ip, dst_ip, process_name, COUNT(*) AS packets, "
           f"COALESCE(SUM(packet_size), 0) AS bytes FROM packets "
           f"WHERE {' AND '.join(where)} "
           f"GROUP BY src_ip, dst_ip, process_name")
    try:
        with me._get_readonly_conn() as conn:
            return [dict(r) for r in conn.execute(sql, args).fetchall()]
    except Exception as e:                                  # noqa: BLE001
        logger.debug(f"place_map: process attribution unreadable: {e}")
        return []


def traffic_rows(since_iso: str) -> list | None:
    """
    This machine's destinations from the hourly tally, or None when there is
    no tally to read (old database, learner off, or nothing tallied yet).
    """
    hour = since_iso.replace("T", " ")[:13] + ":00:00"
    try:
        with me._get_readonly_conn() as conn:
            if not me._table_exists_ro(conn, "place_traffic"):
                return None
            rows = [dict(r) for r in conn.execute("""
                SELECT remote_ip, local_ip, process,
                       SUM(packets) AS packets, SUM(bytes) AS bytes,
                       GROUP_CONCAT(ports) AS ports,
                       GROUP_CONCAT(protocols) AS protocols,
                       GROUP_CONCAT(threat_labels) AS threat_labels
                  FROM place_traffic WHERE hour >= ?
                 GROUP BY remote_ip, local_ip, process""", (hour,)).fetchall()]
    except Exception as e:                                  # noqa: BLE001
        logger.debug(f"place_map: traffic tally unreadable: {e}")
        return None
    return rows or None


def names_for(ips) -> dict:
    """{ip: [names]} from the DNS answers this app captured."""
    ips = [i for i in set(ips or []) if i]
    out = {}
    if not ips:
        return out
    try:
        with me._get_readonly_conn() as conn:
            if not me._table_exists_ro(conn, "dns_answer"):
                return out
            for i in range(0, len(ips), 500):
                chunk = ips[i:i + 500]
                marks = ",".join("?" * len(chunk))
                for r in conn.execute(
                        f"SELECT value, name FROM dns_answer WHERE value IN "
                        f"({marks}) GROUP BY value, name "
                        f"ORDER BY MAX(last_seen) DESC", chunk):
                    lst = out.setdefault(r["value"], [])
                    if len(lst) < NAMES_PER_POINT and r["name"] not in lst:
                        lst.append(r["name"].rstrip("."))
    except Exception as e:                                  # noqa: BLE001
        logger.debug(f"place_map: DNS names unreadable: {e}")
    return out


# The picture is kept for a minute; the place learner refreshes it on each
# pass, so opening the map rarely rebuilds it inside a busy app.
CACHE_SECONDS = 60
_cache: dict = {}
_cache_lock = threading.Lock()


def gather(session_id: str = None, since: str = None,
           router_hours: float = ROUTER_WINDOW_HOURS,
           fresh: bool = False) -> dict:
    """
    Every external endpoint, merged from both sources, with who reached it.
    Served from a short cache unless fresh is set.
    """
    key = (session_id, since, router_hours)
    with _cache_lock:
        hit = _cache.get(key)
        if hit and not fresh and time.monotonic() - hit[0] < CACHE_SECONDS:
            return hit[1]
        out = _gather(session_id, since, router_hours)
        out["computed_at"] = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S+00:00")
        if len(_cache) > 8:
            _cache.clear()
        _cache[key] = (time.monotonic(), out)
        return out


def _gather(session_id: str, since: str, router_hours: float) -> dict:
    """
    The work behind gather(). The router's rows for this machine's own
    addresses are left out, because this machine's capture already counts
    that traffic.
    """
    # This machine: the hourly tally when the learner keeps one, else the
    # current run's packets (the old, slower path).
    window_start = since or _iso_hours_ago(router_hours)
    tally = traffic_rows(window_start)
    if tally is not None:
        pairs = [{"src_ip": r["local_ip"], "dst_ip": r["remote_ip"], **r}
                 for r in tally]
        covers = f"the last {router_hours:g} hours"
    else:
        pairs = me.query_endpoint_pairs(session_id=session_id, since=since)
        covers = "this run"

    severity_error = None
    try:
        # Alerts of any run colour a point, since the map covers a day.
        flagged = me.worst_finding_by_entity_with_rule(
            "ip", session_id=None if tally is not None else session_id)
    except Exception as e:                                  # noqa: BLE001
        flagged = {}
        severity_error = str(e)
        logger.warning(f"Threat map could not read finding severities: {e}")

    endpoints, not_hosts, local_ips = {}, {}, set()

    def _not_host(far, hit, packets, nbytes):
        n = not_hosts.setdefault(far, {
            "ip": far, "packets": 0, "bytes": 0,
            "reason": hit.get("title") or "",
            "detection_id": hit.get("detection_id"),
            "severity": hit.get("severity"),
            "note": ("The address in this finding is the sender's own "
                     "malformed header, not a host: it is not plotted, and "
                     "where it geolocates is not a fact about anything that "
                     "talked to this machine."),
        })
        n["packets"] += packets or 0
        n["bytes"] += nbytes or 0

    def _endpoint(far):
        return endpoints.setdefault(far, {
            "packets": 0, "bytes": 0, "ports": set(), "protocols": set(),
            "threat_labels": set(), "peers": set(), "processes": {},
            "devices": {}, "names": set(), "sources": set(),
        })

    for p in pairs:
        src, dst = p.get("src_ip"), p.get("dst_ip")
        for near, far in ((src, dst), (dst, src)):
            if not far or not geoip.is_routable(far):
                continue
            hit = flagged.get(far)
            if hit and hit.get("entity_is_not_a_host"):
                _not_host(far, hit, p.get("packets"), p.get("bytes"))
                break
            # Multicast groups are not devices on this network.
            if near and not geoip.is_routable(near) \
                    and geoip.is_host_address(near):
                local_ips.add(near)
            e = _endpoint(far)
            e["packets"] += p.get("packets") or 0
            e["bytes"] += p.get("bytes") or 0
            e["ports"] |= _split(p.get("ports"))
            e["protocols"] |= _split(p.get("protocols"))
            e["threat_labels"] |= _split(p.get("threat_labels"))
            e["sources"].add("this_machine")
            if near:
                e["peers"].add(near)
            break

    procs = ([{"src_ip": r["local_ip"], "dst_ip": r["remote_ip"],
               "process_name": r["process"], "packets": r["packets"],
               "bytes": r["bytes"]} for r in tally if r["process"]]
             if tally is not None
             else process_pairs(session_id=session_id, since=since))
    for r in procs:
        for far in (r["dst_ip"], r["src_ip"]):
            if far in endpoints:
                pr = endpoints[far]["processes"].setdefault(
                    r["process_name"], {"packets": 0, "bytes": 0})
                pr["packets"] += r["packets"] or 0
                pr["bytes"] += r["bytes"] or 0
                break

    router = router_flows(router_hours)
    mine = own_addresses() | local_ips
    labels = device_labels() if router["available"] else {"mac": {}, "ip": {}}
    for f in router["rows"]:
        far, dev = f.get("dst"), f.get("device_ip")
        if not far or not geoip.is_routable(far) or dev in mine:
            continue
        hit = flagged.get(far)
        if hit and hit.get("entity_is_not_a_host"):
            _not_host(far, hit, f.get("packets"),
                      (f.get("bytes_out") or 0) + (f.get("bytes_in") or 0))
            continue
        e = _endpoint(far)
        nbytes = (f.get("bytes_out") or 0) + (f.get("bytes_in") or 0)
        e["packets"] += f.get("packets") or 0
        e["bytes"] += nbytes
        e["ports"] |= _split(str(f.get("ports") or ""))
        e["protocols"] |= {x.lower() for x in _split(f.get("protocols"))}
        e["sources"].add("router")
        e["peers"].add(dev)
        if f.get("dst_name"):
            e["names"].add(f["dst_name"].rstrip("."))
        d = e["devices"].setdefault(dev, {
            "ip": dev, "mac": (f.get("device_mac") or "").lower(),
            "name": _label(labels, dev, f.get("device_mac")),
            "bytes_out": 0, "bytes_in": 0, "packets": 0})
        d["bytes_out"] += f.get("bytes_out") or 0
        d["bytes_in"] += f.get("bytes_in") or 0
        d["packets"] += f.get("packets") or 0

    for ip, names in names_for(list(endpoints)).items():
        endpoints[ip]["names"].update(names)

    return {
        "endpoints": endpoints,
        "not_hosts": not_hosts,
        "local_ips": local_ips,
        "pairs_read": len(pairs),
        "this_machine_covers": covers,
        "flagged": flagged,
        "severity_error": severity_error,
        "router": {k: v for k, v in router.items() if k != "rows"},
    }


def who(e: dict, limit: int = 5) -> dict:
    """The programs and devices behind one endpoint, biggest first."""
    procs = sorted(({"name": k, **v} for k, v in e["processes"].items()),
                   key=lambda x: -x["packets"])
    devs = sorted(e["devices"].values(),
                  key=lambda x: -(x["bytes_out"] + x["bytes_in"]))
    return {"processes": procs[:limit], "processes_total": len(procs),
            "devices": devs[:limit], "devices_total": len(devs),
            "names": sorted(e["names"])[:NAMES_PER_POINT],
            "sources": sorted(e["sources"])}


def _tally_for(ip: str) -> list | None:
    """One address's rows from the tally for the last day, or None."""
    hour = _iso_hours_ago(ROUTER_WINDOW_HOURS).replace("T", " ")[:13] + ":00:00"
    try:
        with me._get_readonly_conn() as conn:
            if not me._table_exists_ro(conn, "place_traffic"):
                return None
            rows = [dict(r) for r in conn.execute(
                "SELECT process, SUM(packets) AS packets, SUM(bytes) AS bytes "
                "FROM place_traffic WHERE remote_ip = ? AND hour >= ? "
                "GROUP BY process", (ip, hour)).fetchall()]
    except Exception:                                       # noqa: BLE001
        return None
    return rows or None


def point(ip: str, session_id: str = None) -> dict:
    """Everything the map's side panel shows about one address."""
    geo = geoip.lookup(ip)
    net = geoip.asn_lookup(ip)
    out = {"ip": ip, "routable": geoip.is_routable(ip),
           "place": geoip.label(geo) if geo else "Not in the location database",
           "country_code": (geo or {}).get("country_code") or "",
           "network": net, "network_status": geoip.asn_status()}

    procs = {}
    rows = _tally_for(ip)
    if rows is None:
        rows = [{"process": r["process_name"], "packets": r["packets"],
                 "bytes": r["bytes"]}
                for r in process_pairs(session_id=session_id, ip=ip)]
    for r in rows:
        if not r["process"]:
            continue
        pr = procs.setdefault(r["process"], {"packets": 0, "bytes": 0})
        pr["packets"] += r["packets"] or 0
        pr["bytes"] += r["bytes"] or 0
    out["processes"] = sorted(({"name": k, **v} for k, v in procs.items()),
                              key=lambda x: -x["packets"])

    router = router_flows(dst=ip)
    labels = device_labels()
    mine = own_addresses()
    devs = []
    names = set(names_for([ip]).get(ip, []))
    for f in router["rows"]:
        if f["device_ip"] in mine:
            continue
        if f.get("dst_name"):
            names.add(f["dst_name"].rstrip("."))
        devs.append({"ip": f["device_ip"],
                     "mac": (f.get("device_mac") or "").lower(),
                     "name": _label(labels, f["device_ip"], f.get("device_mac")),
                     "bytes_out": f.get("bytes_out") or 0,
                     "bytes_in": f.get("bytes_in") or 0,
                     "ports": sorted(_split(str(f.get("ports") or ""))),
                     "last_seen": f.get("last_seen")})
    out["devices"] = sorted(devs, key=lambda d: -(d["bytes_out"] + d["bytes_in"]))
    out["router"] = {"available": router["available"] or bool(devs),
                     "reason": router.get("reason")}
    out["names"] = sorted(names)[:NAMES_PER_POINT * 2]

    try:
        out["findings"] = me.query_findings(entity_type="ip", entity_value=ip,
                                            limit=20)
        out["findings_read"] = True
    except Exception as e:                                  # noqa: BLE001
        out["findings"], out["findings_read"] = [], False
        out["findings_error"] = str(e)
    return out


def context_for_chat(ip: str, session_id: str = None) -> str:
    """A short, factual preface for a chat opened from one map point."""
    p = point(ip, session_id=session_id)
    lines = [f"Destination {ip}, located: {p['place']}."]
    if p.get("network"):
        lines.append(f"Network owner: {p['network']['asn']} "
                     f"{p['network']['org']}.")
    if p["names"]:
        lines.append("Names seen for it: " + ", ".join(p["names"]) + ".")
    if p["processes"]:
        lines.append("Programs on this machine that reached it: " + ", ".join(
            f"{x['name']} ({x['packets']} packets)" for x in p["processes"][:5])
            + ".")
    if p["devices"]:
        lines.append("Devices on the network that reached it: " + ", ".join(
            f"{d['name'] or d['ip']} ({d['ip']})" for d in p["devices"][:5])
            + ".")
    if not p["router"]["available"]:
        lines.append("No router data, so other devices are not covered.")
    if p["findings"]:
        lines.append("Alerts about it: " + "; ".join(
            f"{f.get('detection_id') or '?'} {f.get('severity')}: "
            f"{f.get('title')}" for f in p["findings"][:5]) + ".")
    else:
        lines.append("No alerts are recorded about it.")
    return " ".join(lines)


def digest(since: str = None, session_id: str = None, top: int = 5) -> str:
    """
    A few lines for the duty loop's wake prompt instead of the full map:
    new places since the last wake, what could not be placed, the biggest
    endpoints, and any endpoint with an alert.
    """
    lines = ["THREAT MAP SUMMARY (the full map is query_threat_map)."]
    try:
        g = gather(session_id=session_id)
    except Exception as e:                                  # noqa: BLE001
        return (f"THREAT MAP SUMMARY: the map could not be read ({e}). Say so "
                f"rather than describing the traffic as quiet.")

    try:
        with me._get_readonly_conn() as conn:
            if me._table_exists_ro(conn, "place_baseline"):
                rows = conn.execute(
                    "SELECT subject_type, subject, place_type, place, "
                    "place_label, example_ip FROM place_baseline "
                    "WHERE first_seen >= ? ORDER BY first_seen DESC LIMIT ?",
                    (since or _iso_hours_ago(24), top * 2)).fetchall()
            else:
                rows = []
        if rows:
            lines.append("  New places since the last wake:")
            for r in rows:
                lines.append(f"  - {r['subject_type']} {r['subject']} reached "
                             f"{r['place_type']} {r['place_label'] or r['place']}"
                             f" (example {r['example_ip']})")
        else:
            lines.append("  No new country or network for any program or "
                         "device since the last wake.")
    except Exception as e:                                  # noqa: BLE001
        lines.append(f"  New places could not be read: {e}.")

    eps = g["endpoints"]
    unlocated = [ip for ip in eps if not geoip.lookup(ip)]
    if unlocated:
        lines.append(f"  {len(eps)} external endpoint(s); {len(unlocated)} "
                     f"could not be placed on the map, so a claim that some "
                     f"country is absent is unproven.")
    else:
        lines.append(f"  {len(eps)} external endpoint(s), all placed on the "
                     f"map.")
    if not g["router"].get("available"):
        lines.append(f"  Router data: {g['router'].get('reason')}")

    def _who(ip):
        w = who(eps[ip], limit=2)
        bits = [x["name"] for x in w["processes"]] + [
            d["name"] or d["ip"] for d in w["devices"]]
        return ", ".join(bits) or "unattributed"

    big = sorted(eps, key=lambda ip: -eps[ip]["bytes"])[:top]
    if big:
        lines.append("  Biggest by data:")
        for ip in big:
            geo = geoip.lookup(ip)
            lines.append(f"  - {ip} {geoip.label(geo) if geo else 'unlocated'}"
                         f", {_size(eps[ip]['bytes'])}, by {_who(ip)}")

    flagged = [ip for ip in eps if ip in g["flagged"]]
    if g["severity_error"]:
        lines.append(f"  Alerts could not be read ({g['severity_error']}), so "
                     f"nothing above was checked against them.")
    elif flagged:
        rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        flagged.sort(key=lambda ip: -rank.get(g["flagged"][ip]["severity"], 0))
        lines.append("  Endpoints with an alert:")
        for ip in flagged[:top]:
            h = g["flagged"][ip]
            lines.append(f"  - {ip} {h['severity']} "
                         f"{h.get('detection_id') or ''}: {h.get('title')}")
        if len(flagged) > top:
            lines.append(f"  ...and {len(flagged) - top} more.")
    else:
        lines.append("  No endpoint on the map has an alert.")
    return "\n".join(lines)
