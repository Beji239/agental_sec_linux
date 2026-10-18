# core/evidence.py
# The model proposes, Python verifies. When the model calls an alert normal it
# must name one reason below, and Python checks that reason against facts an
# attacker cannot write into the alert: the package database, the network
# owner, the router's DNS log, the ports in the router's connection log, this
# app's own endpoints. Text inside an alert (names, titles) is never evidence.

import ipaddress
import json
import logging
import re

from core import memory_engine as me

logger = logging.getLogger(__name__)

REASONS = {
    "package_install": "a package install or upgrade put this file there",
    "cloud_network": "the destination is in a big cloud or CDN network",
    "named_lookup": "the device looked the destination up by name first",
    "time_server": "a time server (NTP, port 123)",
    "peer_traffic": "a call or game peer on high UDP ports",
    "own_traffic": "this app's own traffic",
    "reserved_name": "a reserved name nobody can register",
}

# Never closed or held without the owner: threat list hits, the app's own
# health, and anything high or critical.
NEVER_PREFIXES = ("FED-", "LAN-1010", "SYS-", "DNS-1007", "DNS-1008")
NEVER_SEVERITIES = ("high", "critical")

# Wording that addresses a reader rather than describing traffic. In fields a
# device or program wrote, it is a sign somebody is trying to steer the model.
INJECTION = re.compile(
    r"ignore (all |any )?(previous|prior|above|earlier)|disregard|"
    r"(mark|treat|classify) (this|it|them|the alert)[^.]{0,20}"
    r"(benign|safe|normal|harmless)|you are (an? )?(ai|assistant|model|llm)|"
    r"system prompt|new instructions?|do not (alert|report|raise|flag)|"
    r"not malicious|false positive|allow-?list|whitelist",
    re.IGNORECASE)

IP_KEYS = ("ip", "remote", "dst_ip", "destination", "server_ip", "dst")
DOMAIN_KEYS = ("domain", "registered_domain", "name", "sni", "matched")
PATH_KEYS = ("path", "exe", "realpath")


def raw_of(item: dict) -> dict:
    raw = item.get("raw_data")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw or "{}")
        except ValueError:
            raw = {}
    return raw if isinstance(raw, dict) else {}


def _is_ip(value) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def ips_of(item: dict) -> list:
    raw = raw_of(item)
    out = [item.get("entity_value")] + [raw.get(k) for k in IP_KEYS]
    seen = []
    for v in out:
        if v and _is_ip(v) and v not in seen:
            seen.append(str(v))
    return seen


def domains_of(item: dict) -> list:
    raw = raw_of(item)
    return [str(raw[k]).lower().rstrip(".") for k in DOMAIN_KEYS
            if raw.get(k) and isinstance(raw.get(k), str)]


def paths_of(item: dict) -> list:
    raw = raw_of(item)
    out = [raw.get(k) for k in PATH_KEYS]
    if raw.get("dir") and raw.get("entry"):
        out.append(f"{raw['dir']}/{raw['entry']}")
    if item.get("entity_type") == "file":
        out.append(item.get("entity_value"))
    return [p for p in out if p and str(p).startswith("/")]


def tampered(item: dict) -> str | None:
    """Instruction-like wording in a field a device or program wrote."""
    raw = raw_of(item)
    texts = [str(item.get("entity_value") or "")]
    texts += [str(v) for v in raw.values() if isinstance(v, str)]
    for t in texts:
        m = INJECTION.search(t)
        if m:
            return m.group(0)
    return None


def closable(item: dict) -> tuple[bool, str]:
    """May the model close or hold this alert without the owner."""
    did = str(item.get("detection_id") or "")
    if did.startswith(NEVER_PREFIXES):
        return False, f"{did} alerts always go to the owner"
    if item.get("severity") in NEVER_SEVERITIES:
        return False, f"{item.get('severity')} alerts always go to the owner"
    hit = tampered(item)
    if hit:
        return False, (f"the alert carries instruction-like wording "
                       f"({hit!r}), a sign of tampering")
    return True, ""


def _listed(conn, ip=None, domain=None) -> bool:
    from tools import feed_matcher
    try:
        if ip and feed_matcher._feed_hit_ip(conn, ip):
            return True
        if domain and feed_matcher._feed_hit_domain(conn, domain):
            return True
    except Exception as e:                                  # noqa: BLE001
        logger.debug(f"evidence: feed check failed: {e}")
    return False


def _flow_ports(conn, ip: str) -> set:
    if not me._table_exists_ro(conn, "lan_flow"):
        return set()
    return {f"{r[0]}/{r[1]}" for r in conn.execute(
        "SELECT DISTINCT proto, dport FROM lan_flow WHERE dst = ? LIMIT 50",
        (ip,))}


def _answers(conn, domain: str) -> list:
    if not me._table_exists_ro(conn, "dns_answer"):
        return []
    return [r[0] for r in conn.execute(
        "SELECT DISTINCT value FROM dns_answer WHERE name = ? AND rrtype IN "
        "('A', 'AAAA') LIMIT 10", (domain,))]


def _names(conn, ip: str) -> list:
    if not me._table_exists_ro(conn, "dns_answer"):
        return []
    return [r[0] for r in conn.execute(
        "SELECT DISTINCT name FROM dns_answer WHERE value = ? LIMIT 3", (ip,))]


def verify(kind: str, item: dict) -> tuple[bool, str]:
    """(confirmed, what Python found). Never raises."""
    if kind not in REASONS:
        return False, f"{kind!r} is not a reason Python can check"
    try:
        return _verify(kind, item)
    except Exception as e:                                  # noqa: BLE001
        return False, f"the check failed: {e}"


def _verify(kind, item):
    ips, domains, paths = ips_of(item), domains_of(item), paths_of(item)
    if kind == "package_install":
        from core import package_activity
        for p in paths:
            hit = package_activity.explains(p)
            if hit:
                return True, hit["how"]
        return False, "no file here is owned by a package installed close by"

    if kind == "reserved_name":
        from tools import dns_inspector
        for d in domains:
            if dns_inspector._is_local_name(d):
                return True, f"{d} is a reserved name"
        return False, "no reserved name in this alert"

    if kind == "own_traffic":
        from tools import packet_sniffer_linux as sn
        own_hosts = {a for a, _p in sn._own_endpoints}
        for ip in ips:
            if ip in own_hosts:
                return True, f"{ip} is this app's own scheduled endpoint"
        return False, "no address here is one of this app's own endpoints"

    from core import geoip
    from tools import place_watch
    with me._get_readonly_conn() as conn:
        if kind == "cloud_network":
            targets = list(ips)
            for d in domains:
                targets += _answers(conn, d)
            for ip in targets:
                net = geoip.asn_lookup(ip)
                if place_watch.is_cloud(net) and not _listed(conn, ip=ip):
                    return True, f"{ip} is in {net['asn']} {net['org']}"
            return False, "no address here is in a big cloud or CDN network"

        if kind == "named_lookup":
            for ip in ips:
                names = _names(conn, ip)
                if names and not any(_listed(conn, domain=n) for n in names):
                    return True, f"{ip} was looked up as {names[0]}"
            for d in domains:
                if _answers(conn, d) and not _listed(conn, domain=d):
                    return True, f"{d} was answered by the router's resolver"
            return False, "no name lookup for this destination in the DNS log"

        if kind in ("time_server", "peer_traffic"):
            for ip in ips:
                ports = _flow_ports(conn, ip)
                raw_port = raw_of(item).get("port")
                if raw_port:
                    ports.add(f"{raw_of(item).get('proto') or 'udp'}/{raw_port}")
                if not ports:
                    continue
                if kind == "time_server" and all(
                        p.endswith("/123") for p in ports):
                    return True, f"{ip} is reached on port 123 only"
                if kind == "peer_traffic" and all(
                        p.startswith("udp/") and p[4:].isdigit()
                        and int(p[4:]) >= 1024 for p in ports):
                    return True, f"{ip} is reached on high UDP ports only"
            return False, "the router's connection log does not show that"
    return False, "unknown reason"


# Which fields a quiet rule may match. Titles, hostnames and process names are
# written by whatever raised the alert and are never allowed.
TRUSTED_RAW = frozenset({
    "place", "place_type", "matched", "feed", "domain", "registered_domain",
    "sni", "ip", "remote", "dst_ip", "destination", "server_ip", "port",
    "proto", "package", "client_ip", "dir",
})
_MAC = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.IGNORECASE)


def check_pattern(match: dict, example: dict, owner_said: bool) -> str | None:
    """Why this pattern is not allowed, or None. A device's hardware address
    must come with another field; a path only on the owner's word or when a
    package owns it."""
    if match.get("title"):
        return ("a rule cannot match the alert title: it carries names a "
                "device or program chose. Use raw fields such as domain, "
                "place, matched or a package-owned path")
    others = 0
    for key, pattern in (match.get("raw") or {}).items():
        if key in TRUSTED_RAW:
            others += 1
            continue
        if key == "subject":
            if not _MAC.match(str(raw_of(example).get("subject") or "")):
                return ("subject is a program name here, which the program "
                        "chose; it cannot be matched")
            continue
        if key in PATH_KEYS:
            if owner_said:
                others += 1
                continue
            err = _path_err(pattern)
            if err:
                return err
            others += 1
            continue
        return f"raw field {key!r} is not one a rule may match"
    if "entity" in match:
        ent = str(match["entity"])
        if _is_ip(ent):
            others += 1
        elif ent.startswith("/") and (owner_said or not _path_err(ent)):
            others += 1
        else:
            return ("the entity may be matched only as an exact address or a "
                    "package-owned path")
    if (match.get("raw") or {}).get("subject") and others == 0:
        return ("a hardware address can be copied by another device, so pair "
                "it with another field such as place or domain")
    return None


def _path_err(pattern) -> str | None:
    p = str(pattern)
    if any(c in p for c in "*?["):
        return "a path in a rule must be exact unless the owner asked for it"
    from core import package_activity
    if not package_activity.owner(p):
        return ("a path no package owns can be written by anyone, so only "
                "the owner can quiet it")
    return None
