# tools/gateway.py
# The app's side of the router agent (tools/gateway_agent.sh).
#
# NO BRAND IS NAMED ANYWHERE BELOW. The agent reports what the router can do
# (`probe`), and every feature here is offered because a capability was
# reported, never because of what the router is. An OpenWrt box, a Turris, a plain
# Linux box routing for the house or an OPNsense firewall are the same thing
# to this file when they answer the same capabilities. The OS string is kept
# for the operator to read and is never branched on.
#
# THE TRANSPORT is SSH with one key that the router's authorized_keys line
# pins to the agent script, and a host key pinned at enrollment
# (scripts/install_gateway_agent.sh). There is no trust on first use here: a
# router whose host key is not in the pinned file is refused.
#
# EVERYTHING THE ROUTER RETURNS IS UNTRUSTED. Hostnames in a lease file are
# chosen by the devices, log lines are written by anything on the router, and
# the router itself may be the compromised box. Output is capped, parsed with
# bounded rules, and served to the model fenced.

import logging
import os
import re
import socket
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)
# paramiko's per-connection INFO lines would bury the app log.
logging.getLogger("paramiko").setLevel(logging.WARNING)

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

CONFIG_DIR = Path.home() / ".config" / "agental_sec"
DEFAULTS = {
    "enabled": False,
    "host": "",
    "port": 22,
    "user": "root",
    "key_path": str(CONFIG_DIR / "gateway_ed25519"),
    "known_hosts": str(CONFIG_DIR / "gateway_known_hosts"),
    "interval_minutes": 5,
    "label": None,
}

MAX_OUTPUT = 4 * 1024 * 1024
TIMEOUT = 30
# Reads within this many seconds of each other share one SSH login.
REUSE_SECONDS = 1.0
CAPABILITIES = ("block", "sinkhole", "leases", "neighbors", "conntrack",
                "log", "dnslog", "blockmac", "counters", "persist",
                "appblock")
VERBS = {"probe", "version", "leases", "neighbors", "conntrack", "log",
         "dnslog", "blocks", "block", "unblock", "sinkholes", "sinkhole",
         "unsinkhole", "blockmac", "unblockmac", "counters", "restore",
         "apps", "blockapp", "unblockapp", "apprefresh"}
# What the dashboard calls each app the agent knows. An app the agent
# reports and this table lacks is shown by its agent name.
APP_LABELS = {
    "whatsapp": "WhatsApp", "facebook": "Facebook and Messenger",
    "instagram": "Instagram", "tiktok": "TikTok", "youtube": "YouTube",
    "snapchat": "Snapchat", "telegram": "Telegram", "discord": "Discord",
    "netflix": "Netflix", "twitch": "Twitch", "roblox": "Roblox",
    "fortnite": "Fortnite and Epic Games", "x": "X (Twitter)",
    "steam": "Steam", "reddit": "Reddit", "signal": "Signal",
}
_APP_RE = re.compile(r"^[a-z0-9]{1,32}$")
_ARG_RE = re.compile(r"^[A-Za-z0-9.:_-]{1,253}$")
_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


class GatewayError(Exception):
    """The router could not be asked, or refused. Carries a sentence."""


def settings(config: dict) -> dict:
    block = dict(DEFAULTS)
    block.update((config or {}).get("gateway") or {})
    return block


# The transport

def _connect(cfg: dict, known: Path, key: Path):
    client = paramiko.SSHClient()
    client.load_host_keys(str(known))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(cfg["host"], port=int(cfg["port"]),
                       username=cfg["user"], key_filename=str(key),
                       look_for_keys=False, allow_agent=False,
                       timeout=10, banner_timeout=10, auth_timeout=10)
    except Exception:
        client.close()
        raise
    return client


def _read_all(channel, limit: int, seconds: float) -> bytes:
    """Read until the agent closes the channel. An answer not finished within
    `seconds` is a failed read, not a short one."""
    end = time.monotonic() + seconds
    buf = bytearray()
    while len(buf) <= limit:
        left = end - time.monotonic()
        if left <= 0:
            raise GatewayError(f"Could not read the router: it did not finish "
                               f"answering within {seconds:g} s.")
        channel.settimeout(left)
        try:
            chunk = channel.recv(65536)
        except socket.timeout:
            raise GatewayError(f"Could not read the router: it did not finish "
                               f"answering within {seconds:g} s.")
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


class _Session:
    """One SSH login to one router, kept open while reads keep coming."""

    def __init__(self):
        self.lock = threading.Lock()
        self.client = None
        self.last = 0.0
        self.timer = None

    def close(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None

    def _close_if_idle(self):
        with self.lock:
            if time.monotonic() - self.last >= REUSE_SECONDS:
                self.close()

    def arm(self):
        if self.timer:
            self.timer.cancel()
        self.timer = threading.Timer(REUSE_SECONDS, self._close_if_idle)
        self.timer.daemon = True
        self.timer.start()

    def usable(self) -> bool:
        if self.client is None or time.monotonic() - self.last > REUSE_SECONDS:
            return False
        t = self.client.get_transport()
        return bool(t and t.is_active())


_sessions = {}
_sessions_lock = threading.Lock()


def _session_for(cfg: dict, key: Path) -> _Session:
    ident = (cfg["host"], int(cfg["port"]), cfg["user"], str(key))
    with _sessions_lock:
        return _sessions.setdefault(ident, _Session())


def _close_all():
    with _sessions_lock:
        sessions = list(_sessions.values())
    for s in sessions:
        with s.lock:
            s.close()


def ssh_transport(cfg: dict):
    """A callable(command) -> str that runs one agent verb over SSH. Every
    reader of the same router shares one login while reads come within
    REUSE_SECONDS of each other; the key and its forced command are as
    enrolled, each verb is its own run of the agent."""
    if not PARAMIKO_AVAILABLE:
        raise GatewayError("paramiko is not installed, so the router cannot "
                           "be reached.")
    known = Path(cfg["known_hosts"])
    key = Path(cfg["key_path"])
    if not known.exists():
        raise GatewayError(f"No pinned host key for the router ({known} is "
                           f"missing). Enroll it with "
                           f"scripts/install_gateway_agent.sh.")
    if not key.exists():
        raise GatewayError(f"The router key {key} is missing. Enroll the "
                           f"router with scripts/install_gateway_agent.sh.")
    session = _session_for(cfg, key)

    def run(command: str) -> str:
        with session.lock:
            try:
                if not session.usable():
                    session.close()
                    session.client = _connect(cfg, known, key)
                _, stdout, _ = session.client.exec_command(command,
                                                           timeout=TIMEOUT)
                try:
                    data = _read_all(stdout.channel, MAX_OUTPUT, TIMEOUT)
                finally:
                    stdout.channel.close()
            except GatewayError:
                session.close()
                raise
            except Exception as e:
                session.close()
                if PARAMIKO_AVAILABLE and isinstance(e, paramiko.BadHostKeyException):
                    raise GatewayError(
                        f"THE ROUTER'S HOST KEY HAS CHANGED since it was "
                        f"enrolled. Either the router was reset or "
                        f"reinstalled, or something is answering in its "
                        f"place. Nothing was sent. Check the router, then "
                        f"enroll it again.")
                if PARAMIKO_AVAILABLE and isinstance(e, paramiko.SSHException):
                    raise GatewayError(f"SSH to the router failed: {e}")
                if isinstance(e, OSError):
                    raise GatewayError(f"The router could not be reached: {e}")
                raise
            session.last = time.monotonic()
            session.arm()
        if len(data) > MAX_OUTPUT:
            logger.warning("The router returned more than %s bytes for %r; "
                           "the rest was dropped.", MAX_OUTPUT,
                           command.split()[0])
            data = data[:MAX_OUTPUT]
        return data.decode("utf-8", errors="replace")

    return run


# The client

class Gateway:
    """One router, asked through the agent. Thread-safe."""

    def __init__(self, config: dict, transport=None):
        self.cfg = settings(config)
        self._transport = transport
        self._lock = threading.Lock()
        self.probe_result = None
        self.probed_at = None

    def _run(self, verb: str, *args) -> dict:
        if verb not in VERBS:
            raise GatewayError(f"{verb!r} is not an agent verb.")
        for a in args:
            if not _ARG_RE.match(str(a)):
                raise GatewayError(f"{a!r} is not an argument the agent "
                                   f"accepts.")
        transport = self._transport or ssh_transport(self.cfg)
        with self._lock:
            text = transport(" ".join([verb] + [str(a) for a in args]))
        lines = text.splitlines()
        head = lines[0] if lines else ""
        if head.startswith("ERR "):
            raise GatewayError(f"The router refused {verb}: {head[4:]}")
        if head != f"OK {verb}":
            raise GatewayError(f"The router's answer to {verb} did not start "
                               f"with the agent's reply line: {head[:120]!r}. "
                               f"Is the agent installed and the key pinned "
                               f"to it?")
        fields, body, in_body = {}, [], False
        caps = []
        for line in lines[1:]:
            if in_body:
                body.append(line)
            elif line == "--":
                in_body = True
            elif "=" in line:
                k, _, v = line.partition("=")
                if k == "cap":
                    caps.append(v)
                else:
                    fields[k] = v
        return {"fields": fields, "caps": caps, "body": body}

    # Capabilities

    def probe(self) -> dict:
        r = self._run("probe")
        caps = sorted(c for c in r["caps"] if c in CAPABILITIES)
        self.probe_result = {
            "capabilities": caps,
            "os": r["fields"].get("os"),
            "os_release": r["fields"].get("os_release"),
            "kernel": r["fields"].get("kernel"),
            "firewall": r["fields"].get("firewall"),
            "dns": r["fields"].get("dns"),
            "log_source": r["fields"].get("log_source"),
            "lease_file": r["fields"].get("lease_file"),
            "agent_version": r["fields"].get("agent_version"),
            "portal_tools": (r["fields"].get("portal_tools") or "").split(),
            "appblock": r["fields"].get("appblock") or "none",
            "apps": [a for a in (r["fields"].get("apps") or "").split()
                     if _APP_RE.match(a)],
        }
        self.probed_at = time.time()
        return self.probe_result

    def has(self, capability: str) -> bool:
        if self.probe_result is None:
            self.probe()
        return capability in self.probe_result["capabilities"]

    def _need(self, capability: str):
        if not self.has(capability):
            raise GatewayError(
                f"This router did not report the '{capability}' capability, "
                f"so it is not offered. What it reported: "
                f"{', '.join(self.probe_result['capabilities']) or 'nothing'}.")

    # Reads

    def leases(self) -> list:
        self._need("leases")
        r = self._run("leases")
        return parse_leases(r["body"], r["fields"].get("lease_file", ""))

    def neighbors(self) -> list:
        self._need("neighbors")
        r = self._run("neighbors")
        return parse_neighbors(r["body"], r["fields"].get("format", "ip"))

    def conntrack(self, ip: str = None) -> dict:
        self._need("conntrack")
        r = self._run("conntrack", *([ip] if ip else []))
        return parse_conntrack(r["body"], r["fields"].get("format", "nf"))

    def flows(self, ip: str = None) -> list:
        """Every connection with its byte and packet counts, one dict each."""
        self._need("conntrack")
        r = self._run("conntrack", *([ip] if ip else []))
        return parse_flows(r["body"])

    def counters(self) -> dict:
        """Exact forwarded bytes per LAN device since the counter was made."""
        self._need("counters")
        r = self._run("counters")
        return {"restored": r["fields"].get("restored") == "yes",
                "mac_rules": r["fields"].get("mac_rules") != "no",
                "devices": parse_counters(r["body"])}

    def log(self, lines: int = 200) -> list:
        self._need("log")
        return self._run("log", int(lines))["body"]

    def dnslog(self, lines: int = 200) -> list:
        self._need("dnslog")
        return self._run("dnslog", int(lines))["body"]

    # Enforcement

    def blocks(self) -> list:
        self._need("block")
        return [b for b in self._run("blocks")["body"] if b.strip()]

    def block(self, ip: str) -> dict:
        self._need("block")
        return self._run("block", ip)["fields"]

    def unblock(self, ip: str) -> dict:
        self._need("block")
        return self._run("unblock", ip)["fields"]

    def block_mac(self, mac: str) -> dict:
        self._need("blockmac")
        return self._run("blockmac", _mac(mac))["fields"]

    def unblock_mac(self, mac: str) -> dict:
        self._need("blockmac")
        return self._run("unblockmac", _mac(mac))["fields"]

    def restore(self) -> dict:
        self._need("persist")
        return self._run("restore")["fields"]

    def sinkholes(self) -> list:
        self._need("sinkhole")
        return [s for s in self._run("sinkholes")["body"] if s.strip()]

    def sinkhole(self, domain: str) -> dict:
        self._need("sinkhole")
        return self._run("sinkhole", domain)["fields"]

    def unsinkhole(self, domain: str) -> dict:
        self._need("sinkhole")
        return self._run("unsinkhole", domain)["fields"]

    # One app on one device: the device keeps everything else.

    def app_blocks(self) -> dict:
        """{"mode", "known", "blocks": {mac: [app]}, "learned": {app: n}}"""
        self._need("appblock")
        r = self._run("apps")
        blocks = {}
        for line in r["body"][:5000]:
            parts = line.split()
            if len(parts) == 2 and _MAC_RE.match(parts[0]) and _APP_RE.match(parts[1]):
                blocks.setdefault(parts[0], []).append(parts[1])
        learned = {k[len("learned_"):]: int(v) for k, v in r["fields"].items()
                   if k.startswith("learned_") and v.isdigit()}
        return {"mode": r["fields"].get("mode"),
                "known": (r["fields"].get("known") or "").split(),
                "blocks": blocks, "learned": learned}

    def block_app(self, mac: str, app: str) -> dict:
        self._need("appblock")
        return self._run("blockapp", _mac(mac), _app(app))["fields"]

    def unblock_app(self, mac: str, app: str) -> dict:
        self._need("appblock")
        return self._run("unblockapp", _mac(mac), _app(app))["fields"]

    def app_refresh(self) -> dict:
        self._need("appblock")
        return self._run("apprefresh")["fields"]


# Parsers. Bounded, and every value is kept as text the device chose.

def _clean(value: str, limit: int = 64) -> str:
    return "".join(ch for ch in (value or "") if ch.isprintable())[:limit]


def _mac(value: str) -> str:
    mac = (value or "").strip().lower().replace("-", ":")
    if not _MAC_RE.match(mac):
        raise GatewayError(f"{value!r} is not a hardware address.")
    return mac


def _app(value: str) -> str:
    app = (value or "").strip().lower()
    if not _APP_RE.match(app):
        raise GatewayError(f"{value!r} is not an app name.")
    return app


def parse_counters(lines: list) -> dict:
    """'ip up_pkts up_bytes down_pkts down_bytes' lines, keyed by ip."""
    out = {}
    for line in lines[:5000]:
        parts = line.split()
        if len(parts) != 5 or not all(p.isdigit() for p in parts[1:]):
            continue
        up_p, up_b, dn_p, dn_b = (int(p) for p in parts[1:])
        out[_clean(parts[0], 45)] = {"up_packets": up_p, "up_bytes": up_b,
                                     "down_packets": dn_p, "down_bytes": dn_b}
    return out


_KV = re.compile(r"(\w+)=(\S+)")


def parse_flows(lines: list) -> list:
    """/proc/net/nf_conntrack lines into flows. The first tuple is the
    original direction, so its src is the side that opened the connection,
    and its bytes are what that side sent."""
    out = []
    names = ("tcp", "udp", "icmp", "icmpv6", "sctp", "gre", "udplite")
    for line in lines[:20000]:
        tokens = line.split()
        if len(tokens) < 4:
            continue
        proto = next((t for t in tokens[:4] if t in names), None)
        if proto is None:
            continue
        orig, reply = {}, {}
        for k, v in _KV.findall(line):
            target = orig if k not in orig else reply
            if k in target:
                continue
            target[k] = v
        if "src" not in orig or "dst" not in orig:
            continue
        state = next((t for t in tokens[4:6] if t.isupper()), None)
        def num(d, k):
            v = d.get(k, "0")
            return int(v) if v.isdigit() else 0
        out.append({
            "proto": proto,
            "state": state,
            "src": _clean(orig["src"], 45), "dst": _clean(orig["dst"], 45),
            "sport": num(orig, "sport"), "dport": num(orig, "dport"),
            "bytes_out": num(orig, "bytes"), "packets_out": num(orig, "packets"),
            "bytes_in": num(reply, "bytes"), "packets_in": num(reply, "packets"),
            "nat_src": _clean(reply.get("dst", ""), 45) or None,
            "unreplied": "[UNREPLIED]" in line,
        })
    return out


def parse_leases(lines: list, lease_file: str = "") -> list:
    """dnsmasq ('expiry mac ip hostname clientid') or Kea CSV."""
    out = []
    kea = lease_file.endswith(".csv")
    for line in lines[:5000]:
        if kea:
            parts = line.split(",")
            if len(parts) < 9 or parts[0] == "address":
                continue
            ip, mac, host = parts[0], parts[1].lower(), parts[8]
        else:
            parts = line.split()
            if len(parts) < 4:
                continue
            ip, mac, host = parts[2], parts[1].lower(), parts[3]
        if not _MAC_RE.match(mac):
            mac = None
        out.append({"ip": _clean(ip, 45), "mac": mac,
                    "hostname": None if host in ("*", "") else _clean(host),
                    "entry_type": "dhcp_lease", "source": "gateway"})
    return out


def parse_neighbors(lines: list, fmt: str = "ip") -> list:
    """`ip neigh` lines, or BSD `arp -an` / `ndp -an` lines."""
    out = []
    for line in lines[:5000]:
        parts = line.split()
        if not parts:
            continue
        if fmt == "ip":
            if "lladdr" not in parts:
                continue
            ip = parts[0]
            mac = parts[parts.index("lladdr") + 1].lower()
            iface = parts[parts.index("dev") + 1] if "dev" in parts else None
            state = parts[-1]
        else:
            m = re.match(r"^\? \(([^)]+)\) at ([0-9a-f:]+) on (\S+)", line)
            if m:
                ip, mac, iface, state = m.group(1), m.group(2), m.group(3), "arp"
            elif len(parts) >= 3 and ":" in parts[0]:
                ip, mac, iface, state = parts[0].split("%")[0], parts[1], parts[2], "ndp"
            else:
                continue
        if not _MAC_RE.match(mac):
            continue
        out.append({"ip": _clean(ip, 45), "mac": mac,
                    "interface": _clean(iface or "", 32) or None,
                    "entry_type": f"neighbor_{_clean(state, 16).lower()}",
                    "source": "gateway"})
    return out


def parse_conntrack(lines: list, fmt: str = "nf") -> dict:
    """Counts per source address and a small sample. Never the whole table."""
    per_src, protocols, total = {}, {}, 0
    names = ("tcp", "udp", "icmp", "icmpv6", "sctp", "gre", "udplite")
    for line in lines[:20000]:
        tokens = line.split()
        if not tokens:
            continue
        total += 1
        proto = next((t for t in tokens[:4] if t in names), "?")
        if fmt == "nf":
            src = re.search(r"\bsrc=(\S+)", line)
            key = src.group(1) if src else "?"
        else:
            # pf: "all tcp 192.0.2.10:5000 -> 203.0.113.5:443 STATE"
            key = tokens[2] if len(tokens) > 2 else "?"
            key = re.sub(r"(\[\d+\]|:\d+)$", "", key) if key.count(":") <= 1 \
                else re.sub(r"\[\d+\]$", "", key)
        per_src[key] = per_src.get(key, 0) + 1
        protocols[proto] = protocols.get(proto, 0) + 1
    top = sorted(per_src.items(), key=lambda kv: -kv[1])[:20]
    return {"connections": total,
            "busiest_sources": [{"ip": _clean(k, 45), "connections": v}
                                for k, v in top],
            "by_protocol": protocols,
            "sample": [_clean(x, 300) for x in lines[:20]]}


# Status for the sensor contract

def describe_capabilities(caps: list) -> dict:
    """What the reported capabilities let this app see and do, in words."""
    sees, does = [], []
    if "leases" in caps:
        sees.append("the router's DHCP leases: every device given an address, "
                    "with its hardware address and the hostname it asked for")
    if "neighbors" in caps:
        sees.append("the router's neighbour table: devices it exchanged "
                    "traffic with recently")
    if "conntrack" in caps:
        sees.append("the router's connection table: which device has open "
                    "connections to where, counted, not their contents")
    if "log" in caps:
        sees.append("the router's own log")
    if "dnslog" in caps:
        sees.append("DNS queries the router's resolver answered, per device")
    if "counters" in caps:
        sees.append("exact bytes each device sent and received through the "
                    "router, not counting device to device traffic on the LAN")
    if "block" in caps:
        does.append("block a device at the router, which cuts it off the "
                    "internet and from other subnets"
                    + (", kept across a router reboot" if "persist" in caps
                       else ", until the router reboots"))
    if "blockmac" in caps:
        does.append("block a device by its hardware address, so a new IP "
                    "address does not get it back online")
    if "sinkhole" in caps:
        does.append("sinkhole a domain at the router's resolver for every "
                    "device that uses it, until the router reboots")
    if "appblock" in caps:
        does.append("block one app, such as WhatsApp, on one device and "
                    "leave the rest of its internet alone, kept across a "
                    "router reboot")
    return {"can_see": sees, "can_do": does}
