# tools/socket_census.py
# Everything the kernel says is listening on this host, and whether the
# firewall lets the outside reach it.
#
# A self-scan only sees what answers on the address it probes. The kernel's
# own tables see every bound socket: listeners on a LAN address or on ::1,
# silent UDP services, SCTP, and the raw and packet sockets a backdoor such
# as BPFDoor listens on without opening any port at all. tools/port_owner
# already reads TCP and UDP and maps inodes to processes; this module adds
# the rest and the firewall verdict, and reuses port_owner for the join.
#
# The firewall is read two ways, because ufw writes through iptables-nft and
# `nft -j` shows its conntrack, addrtype and multiport matches as opaque
# "xt" blobs: iptables-save for the iptables-managed tables, nft JSON for
# native nftables tables. Both need root; unelevated the answer says so.

import ipaddress
import json
import logging
import os
import shlex
import subprocess

logger = logging.getLogger(__name__)

# Ethertypes worth naming on a packet socket.
ETHERTYPES = {
    0x0003: "all frames (ETH_P_ALL)", 0x0800: "IPv4", 0x86DD: "IPv6",
    0x0806: "ARP", 0x888E: "EAPOL (802.1X)", 0x890D: "TDLS",
    0x88CC: "LLDP", 0x8035: "RARP",
}
IP_PROTOCOLS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 58: "ICMPv6",
                255: "raw IP (IPPROTO_RAW)", 0: "all (IPPROTO_IP)"}

# Where a program's bytes should not live (same prefixes as the eBPF rule).
STAGING_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")

_CMD_TIMEOUT = 10


# KERNEL TABLES

def _ifname(index: int) -> str:
    """Interface name for an ifindex, or '' (0 means every interface)."""
    if not index:
        return "any"
    try:
        for name in os.listdir("/sys/class/net"):
            with open(f"/sys/class/net/{name}/ifindex") as fh:
                if int(fh.read().strip()) == index:
                    return name
    except (OSError, ValueError):
        pass
    return f"ifindex {index}"


def read_raw_sockets() -> tuple:
    """(rows, notes) from /proc/net/raw and raw6. The 'port' column is the IP protocol."""
    from tools import port_owner as po
    rows, notes = [], []
    for path, v6 in (("/proc/net/raw", False), ("/proc/net/raw6", True)):
        parsed, note = po._read_proc_net(path)
        if note:
            notes.append(note)
        for r in parsed:
            rows.append({
                "kind": "raw", "family": "ipv6" if v6 else "ipv4",
                "protocol": r["port"],
                "protocol_name": IP_PROTOCOLS.get(r["port"], f"IP protocol {r['port']}"),
                "local_address": po._decode_address(r["laddr_hex"], v6),
                "inode": r["inode"], "uid": r["uid"],
            })
    return rows, notes


def read_packet_sockets() -> tuple:
    """(rows, notes) from /proc/net/packet: link-layer sockets that see frames directly."""
    rows = []
    try:
        with open("/proc/net/packet", encoding="ascii") as fh:
            next(fh, None)
            for line in fh:
                p = line.split()
                if len(p) < 9:
                    continue
                try:
                    proto = int(p[3], 16)
                    rows.append({
                        "kind": "packet",
                        "socket_type": {"2": "dgram", "3": "raw"}.get(p[2], p[2]),
                        "protocol": proto,
                        "protocol_name": ETHERTYPES.get(proto, f"ethertype 0x{proto:04x}"),
                        "interface": _ifname(int(p[4])),
                        "running": p[5] == "1",
                        "uid": p[7], "inode": p[8],
                    })
                except (ValueError, IndexError):
                    continue
    except OSError as e:
        return [], [f"/proc/net/packet could not be read ({e.strerror or e})"]
    return rows, []


def read_sctp_listeners() -> tuple:
    """
    (rows, note) from /proc/net/sctp/eps. The file only exists while the SCTP
    module is loaded, and the module loads when any SCTP socket is made, so
    its absence means no SCTP socket exists.
    """
    path = "/proc/net/sctp/eps"
    if not os.path.exists("/proc/net/sctp"):
        return [], "the SCTP module is not loaded, so no SCTP socket exists"
    rows = []
    try:
        with open(path, encoding="ascii") as fh:
            next(fh, None)
            for line in fh:
                p = line.split()
                # ENDPT SOCK STY SST HBKT LPORT UID INODE LADDRS...
                if len(p) < 8:
                    continue
                try:
                    for addr in p[8:] or ["*"]:
                        rows.append({"proto": "sctp", "scope": "listen",
                                     "local_address": addr,
                                     "local_port": int(p[5]), "uid": p[6],
                                     "inode": p[7]})
                except ValueError:
                    continue
    except OSError as e:
        return [], f"{path} could not be read ({e.strerror or e})"
    return rows, None


def _attach_owner(rows: list, walked: dict) -> None:
    """Fill pid, comm, exe and owner_status the way port_owner does."""
    from tools import port_owner as po
    owners = walked["owners"]
    denied = bool(walked["denied"])
    for row in rows:
        pids = owners.get(row["inode"]) or []
        row.update(pid=None, comm=None, exe=None)
        if pids:
            d = po.process_detail(pids[0])
            row.update(pid=pids[0], comm=d["comm"], exe=d["exe"],
                       holder_count=len(pids), owner_status=po.OWNER_IDENTIFIED)
        elif denied:
            row["owner_status"] = po.OWNER_UNREADABLE
        else:
            row["owner_status"] = po.OWNER_NO_HOLDER


def staged_location(exe: str) -> str | None:
    """Why this executable path is suspicious, or None."""
    if not exe:
        return None
    if exe.endswith(" (deleted)"):
        return "its binary has been deleted from disk while it runs"
    real = exe
    try:
        real = os.path.realpath(exe)
    except OSError:
        pass
    for prefix in STAGING_PREFIXES:
        if real.startswith(prefix):
            return f"it runs from {prefix}, a staging directory"
    return None


def hidden_listeners(walked: dict = None) -> dict:
    """
    Raw and packet sockets with their owners. These receive traffic without
    any port, so no scan can see them. Each row carries `concern` when its
    holder runs from a staging directory or a deleted binary.
    """
    from tools import port_owner as po
    walked = walked or po.socket_owners()
    raw, raw_notes = read_raw_sockets()
    packet, pkt_notes = read_packet_sockets()
    rows = raw + packet
    _attach_owner(rows, walked)
    me = os.getpid()
    for row in rows:
        row["concern"] = None
        if row.get("pid") == me:
            row["note"] = "held by this app (the packet sniffer or a scan)"
            continue
        row["concern"] = staged_location(row.get("exe"))
    return {
        "sockets": rows,
        "concerning": [r for r in rows if r.get("concern")],
        "notes": raw_notes + pkt_notes,
        "unattributed": sum(1 for r in rows if r.get("pid") is None),
        "coverage": ("Owners of sockets held by other accounts cannot be read "
                     "unelevated, so an unattributed row is unknown, not clean."
                     if walked["denied"] else "Every process was readable."),
    }


# Raw and packet sockets already reported this run, so one holder is one
# finding. Kept in memory: a restart re-reports a condition still going on.
_reported_hidden = set()


def check_hidden(session_id: str) -> dict:
    """
    Raise LNX-5001 for each raw or packet socket held by a program running
    from a staging directory or a deleted binary: a listener with no port,
    in the place malware keeps itself. Called on the port owner sweep's tick.
    """
    from core import memory_engine as me
    found = hidden_listeners()
    raised = 0
    for row in found["concerning"]:
        key = (row.get("pid"), row.get("exe"), row["kind"], row["protocol"])
        if key in _reported_hidden:
            continue
        entity = row.get("exe") or row.get("comm") or f"pid {row.get('pid')}"
        if me.is_dismissed("process", entity):
            _reported_hidden.add(key)
            continue
        what = (f"a packet socket for {row['protocol_name']} on "
                f"{row.get('interface')}" if row["kind"] == "packet" else
                f"a raw {row['family']} socket for {row['protocol_name']}")
        res = me.save_finding(
            session_id=session_id, source="port_owner",
            detection_id="LNX-5001", severity="high",
            entity_type="process", entity_value=entity,
            title=f"Portless listener held by a staged program: {row.get('comm') or entity}",
            description=(
                f"Process {row.get('pid')} ({row.get('comm')}, {row.get('exe')}) "
                f"holds {what}. That receives traffic without any open port, "
                f"so no port scan can find it, and {row['concern']}.\n\n"
                f"This is how BPFDoor-style backdoors wait for a trigger "
                f"packet. Legitimate holders (DHCP clients, wpa_supplicant, "
                f"packet capture tools) run from system directories."),
            raw_data={k: row.get(k) for k in (
                "kind", "family", "protocol", "protocol_name", "interface",
                "socket_type", "pid", "comm", "exe", "uid", "inode", "concern")},
        )
        _reported_hidden.add(key)
        if res:
            raised += 1
    return {"checked": len(found["sockets"]), "concerning": len(found["concerning"]),
            "raised": raised, "unattributed": found["unattributed"]}


# FIREWALL: READING

def _run(argv: list) -> tuple:
    try:
        r = subprocess.run(argv, capture_output=True, text=True,
                           timeout=_CMD_TIMEOUT)
    except FileNotFoundError:
        return None, f"{argv[0]} is not installed"
    except subprocess.TimeoutExpired:
        return None, f"{argv[0]} did not answer within {_CMD_TIMEOUT}s"
    if r.returncode != 0:
        why = (r.stderr or r.stdout or "").strip().splitlines()
        return None, (why[-1] if why else f"{argv[0]} failed rc={r.returncode}")
    return r.stdout, None


def _read_kv(path: str) -> dict:
    out = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip().strip('"')
    except OSError:
        return {}
    return out


def ufw_hint() -> dict:
    """What the world-readable ufw files say. The allow rules themselves are root-only."""
    conf = _read_kv("/etc/ufw/ufw.conf")
    default = _read_kv("/etc/default/ufw")
    if not conf:
        return {"present": False}
    return {"present": True,
            "enabled": conf.get("ENABLED", "").lower() == "yes",
            "default_input_policy": (default.get("DEFAULT_INPUT_POLICY") or "").lower() or None}


class Rule:
    __slots__ = ("matches", "verdict", "target", "text")

    def __init__(self, matches, verdict, target, text):
        self.matches, self.verdict, self.target, self.text = matches, verdict, target, text


class Chain:
    def __init__(self, name, hook=None, prio=0, policy=None, family="ip",
                 table=""):
        self.name, self.hook, self.prio = name, hook, prio
        self.policy, self.family, self.table = policy, family, table
        self.rules = []


def parse_iptables_save(text: str, family: str) -> list:
    """
    Tables from iptables-save output as Chains. Only the filter table's
    INPUT hook decides whether a new inbound connection is accepted, but
    every chain is kept so jumps resolve.
    """
    tables, table, chains = [], None, {}
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table, chains = line[1:], {}
            continue
        if line == "COMMIT":
            if table == "filter":
                tables.append(chains)
            table = None
            continue
        if line.startswith(":"):
            name, policy = line[1:].split()[:2]
            hook = "input" if name == "INPUT" else None
            chains[name] = Chain(name, hook=hook, prio=0,
                                 policy=None if policy == "-" else policy.lower(),
                                 family=family, table=table)
            continue
        if line.startswith("-A "):
            try:
                tokens = shlex.split(line)
            except ValueError:
                tokens = line.split()
            name = tokens[1]
            chain = chains.setdefault(name, Chain(name, family=family, table=table))
            chain.rules.append(_iptables_rule(tokens[2:], line))
    out = []
    for chains in tables:
        for c in chains.values():
            c.table = "filter"
        out.append(chains)
    return out


def _iptables_rule(tokens: list, text: str) -> Rule:
    matches, verdict, target = [], None, None
    i, neg = 0, False
    modules = []
    while i < len(tokens):
        t = tokens[i]
        if t == "!":
            neg = True
            i += 1
            continue
        arg = tokens[i + 1] if i + 1 < len(tokens) else ""
        if t in ("-j", "--jump", "-g", "--goto"):
            name = arg
            if name in ("ACCEPT", "DROP", "REJECT", "RETURN"):
                verdict = name.lower()
            elif name in ("LOG", "NFLOG", "ULOG", "AUDIT", "MARK", "CONNMARK",
                          "TRACE", "CT", "NOTRACK"):
                verdict = None
            else:
                verdict, target = ("goto" if t in ("-g", "--goto") else "jump"), name
            i += 2
            continue
        if t == "-m":
            modules.append(arg)
            if arg not in ("tcp", "udp", "sctp", "comment", "icmp", "icmp6",
                           "ipv6-icmp", "conntrack", "state", "multiport",
                           "addrtype", "limit", "hashlimit", "recent", "pkttype",
                           "set", "mark", "connmark"):
                matches.append(("unknown", f"-m {arg}", neg))
            i += 2
            neg = False
            continue
        if t in ("--comment",):
            i += 2
            continue
        # Options that take one argument.
        takes = {"-p", "--protocol", "-s", "--source", "-d", "--destination",
                 "-i", "--in-interface", "-o", "--out-interface", "--dport",
                 "--destination-port", "--sport", "--source-port", "--dports",
                 "--destination-ports", "--sports", "--ports", "--ctstate",
                 "--state", "--dst-type", "--src-type", "--limit",
                 "--limit-burst", "--pkt-type", "--icmp-type",
                 "--icmpv6-type", "--seconds", "--hitcount", "--name",
                 "--hashlimit", "--hashlimit-upto", "--hashlimit-name",
                 "--hashlimit-mode", "--hashlimit-burst", "--mask",
                 "--match-set", "--mark", "--reject-with", "--log-prefix",
                 "--log-level", "--rsource", "--rdest"}
        if t in ("--set", "--update", "--rcheck", "--remove"):
            matches.append(("recent", t, neg))
            i += 1
            neg = False
            continue
        if t in ("--rsource", "--rdest", "--limit-iface-in", "--limit-iface-out",
                 "--log-uid", "--syn"):
            if t == "--syn":
                matches.append(("syn", "", neg))
            i += 1
            neg = False
            continue
        if t in takes:
            key = {"--protocol": "-p", "--source": "-s", "--destination": "-d",
                   "--in-interface": "-i", "--out-interface": "-o",
                   "--destination-port": "--dport", "--source-port": "--sport",
                   "--destination-ports": "--dports"}.get(t, t)
            if key in ("--limit", "--limit-burst", "--seconds", "--hitcount",
                       "--name", "--log-prefix", "--log-level", "--reject-with",
                       "--hashlimit", "--hashlimit-upto", "--hashlimit-name",
                       "--hashlimit-mode", "--hashlimit-burst", "--mask",
                       "--mark"):
                pass                               # rate, name, or target option
            elif key == "--match-set":
                matches.append(("unknown", f"--match-set {arg}", neg))
                i += 3
                neg = False
                continue
            else:
                matches.append((key, arg, neg))
            i += 2
            neg = False
            continue
        matches.append(("unknown", t, neg))
        i += 1
        neg = False
    return Rule(matches, verdict, target, text)


def parse_nft_json(doc: dict, skip_tables: set) -> list:
    """Chains from `nft -j list ruleset`, leaving out tables iptables-save covers."""
    items = (doc or {}).get("nftables") or []
    sets, chains = {}, {}
    for it in items:
        if "set" in it:
            s = it["set"]
            sets[(s.get("family"), s.get("table"), s.get("name"))] = s.get("elem") or []
    for it in items:
        if "chain" in it:
            c = it["chain"]
            key = (c.get("family"), c.get("table"))
            if key in skip_tables:
                continue
            chains[(c["family"], c["table"], c["name"])] = Chain(
                c["name"], hook=c.get("hook"), prio=c.get("prio") or 0,
                policy=c.get("policy"), family=c["family"], table=c["table"])
    for it in items:
        if "rule" not in it:
            continue
        r = it["rule"]
        chain = chains.get((r.get("family"), r.get("table"), r.get("chain")))
        if chain is None:
            continue
        chain.rules.append(_nft_rule(r, sets))
    grouped = {}
    for (fam, tab, _name), c in chains.items():
        grouped.setdefault((fam, tab), {})[c.name] = c
    return list(grouped.values())


def _nft_rule(rule: dict, sets: dict) -> Rule:
    matches, verdict, target = [], None, None
    text = rule.get("comment") or f"{rule.get('family')} {rule.get('table')} " \
        f"{rule.get('chain')} handle {rule.get('handle')}"
    for e in rule.get("expr") or []:
        if "match" in e:
            m = e["match"]
            right = m.get("right")
            if isinstance(right, str) and right.startswith("@"):
                elems = sets.get((rule.get("family"), rule.get("table"), right[1:]))
                right = {"set": elems} if elems is not None else right
            matches.append(("nft", {"left": m.get("left"), "op": m.get("op", "=="),
                                    "right": right}, False))
        elif "xt" in e:
            if (e["xt"] or {}).get("type") == "match":
                matches.append(("unknown", f"xt {e['xt'].get('name')}", False))
        elif any(k in e for k in ("accept", "drop", "return")):
            verdict = next(k for k in ("accept", "drop", "return") if k in e)
        elif "reject" in e:
            verdict = "reject"
        elif "jump" in e or "goto" in e:
            kind = "jump" if "jump" in e else "goto"
            verdict, target = kind, (e[kind] or {}).get("target")
        elif "vmap" in e:
            matches.append(("vmap", e["vmap"], False))
            verdict = "vmap"
        elif "limit" in e or "counter" in e or "log" in e or "meta" in e \
                or "mangle" in e or "ct" in e and "match" not in e:
            continue
    return Rule(matches, verdict, target, text)


def read_firewall() -> dict:
    """
    The input-hook chains this host enforces, or why they could not be read.
    Returns {"readable", "chainsets", "sources", "notes", "ufw"}.
    """
    chainsets, sources, notes = [], [], []
    covered = set()
    for cmd, family in (("iptables-save", "ip"), ("ip6tables-save", "ip6")):
        out, err = _run([cmd])
        if out is None:
            notes.append(f"{cmd}: {err}")
            continue
        for chains in parse_iptables_save(out, family):
            if any(c.rules or c.policy for c in chains.values()):
                chainsets.append(chains)
        # iptables owns these tables; nft would only show their rules as
        # opaque xt blobs, so they are read from iptables-save alone.
        covered.update((family, t) for t in
                       ("filter", "mangle", "raw", "security", "nat"))
        sources.append(cmd)
    out, err = _run(["nft", "-j", "list", "ruleset"])
    if out is None:
        notes.append(f"nft: {err}")
    else:
        try:
            chainsets.extend(parse_nft_json(json.loads(out), covered))
            sources.append("nft")
        except (ValueError, KeyError, TypeError) as e:
            notes.append(f"nft output could not be parsed ({e})")
    return {"readable": bool(sources), "chainsets": chainsets,
            "sources": sources, "notes": notes, "ufw": ufw_hint()}


# FIREWALL: EVALUATING

MAX_PATHS = 256


class Packet:
    """A NEW inbound connection from somewhere else to a local port."""

    def __init__(self, family: str, proto: str, dport: int, daddr: str = None):
        self.family, self.proto, self.dport, self.daddr = family, proto, dport, daddr


def _port_in(spec, port: int):
    """True/False for an iptables port spec like '22', '1000:2000', '22,80'."""
    try:
        for part in str(spec).split(","):
            if ":" in part:
                lo, hi = part.split(":", 1)
                if int(lo or 0) <= port <= int(hi or 65535):
                    return True
            elif int(part) == port:
                return True
    except ValueError:
        return None
    return False


def _neg(value, neg: bool):
    if value is None or isinstance(value, tuple):
        return value if not neg or value is None else ("cond", f"not {value[1]}")
    return (not value) if neg else value


def _eval_ipt(kind, arg, neg, pkt: Packet):
    """One iptables match: True, False, None (unknown) or ('cond', text)."""
    if kind == "-p":
        p = str(arg).lower()
        v = p in ("all", "0") or p == pkt.proto or \
            (p in ("ipv6-icmp", "icmpv6", "icmp") and False)
        return _neg(v, neg)
    if kind in ("--dport", "--dports", "--ports"):
        return _neg(_port_in(arg, pkt.dport), neg)
    if kind in ("--sport", "--sports"):
        return ("cond", f"{'not ' if neg else ''}from source port {arg}")
    if kind == "-i":
        if arg == "lo":
            return _neg(False, neg)
        return ("cond", f"{'not ' if neg else ''}arriving on interface {arg}")
    if kind == "-o":
        return _neg(True, neg)
    if kind == "-s":
        if arg in ("0.0.0.0/0", "::/0"):
            return _neg(True, neg)
        try:
            if ipaddress.ip_network(arg, strict=False).is_loopback:
                return _neg(False, neg)
        except ValueError:
            pass
        return ("cond", f"{'not ' if neg else ''}from {arg}")
    if kind == "-d":
        if arg in ("0.0.0.0/0", "::/0"):
            return _neg(True, neg)
        if pkt.daddr:
            try:
                return _neg(ipaddress.ip_address(pkt.daddr)
                            in ipaddress.ip_network(arg, strict=False), neg)
            except ValueError:
                pass
        return ("cond", f"{'not ' if neg else ''}addressed to {arg}")
    if kind in ("--ctstate", "--state"):
        states = {s.strip().upper() for s in str(arg).split(",")}
        return _neg("NEW" in states, neg)
    if kind == "--dst-type":
        types = {s.strip().upper() for s in str(arg).split(",")}
        return _neg("LOCAL" in types or "UNICAST" in types, neg)
    if kind == "--src-type":
        types = {s.strip().upper() for s in str(arg).split(",")}
        if types & {"LOCAL", "BROADCAST", "MULTICAST"} and not types & {"UNICAST"}:
            return _neg(False, neg)
        return _neg(True, neg)
    if kind == "--pkt-type":
        return _neg(str(arg).lower() in ("unicast", "host"), neg)
    if kind == "recent":
        # A first connection is recorded (--set) and is not yet a repeat.
        return _neg(arg == "--set", neg)
    if kind == "syn":
        return _neg(pkt.proto == "tcp", neg)
    if kind in ("--icmp-type", "--icmpv6-type"):
        return _neg(False, neg)
    return None


def _nft_value_matches(right, value):
    """Does a nft right-hand side contain value? True/False/None."""
    if isinstance(right, dict):
        if "set" in right:
            items = right["set"]
            results = [_nft_value_matches(x, value) for x in items]
            return True if any(r is True for r in results) else \
                (None if any(r is None for r in results) else False)
        if "range" in right:
            lo, hi = right["range"]
            try:
                return int(lo) <= int(value) <= int(hi)
            except (TypeError, ValueError):
                return None
        if "prefix" in right:
            return None
        return None
    if isinstance(right, list):
        return _nft_value_matches({"set": right}, value)
    if isinstance(right, (int, float)) or (isinstance(right, str) and right.isdigit()):
        try:
            return int(right) == int(value)
        except (TypeError, ValueError):
            return None
    if isinstance(right, str):
        return right == str(value)
    return None


def _eval_nft(m: dict, pkt: Packet):
    left, op, right = m.get("left") or {}, m.get("op", "=="), m.get("right")
    neg = op == "!="
    if "payload" in left:
        field = left["payload"].get("field")
        proto = left["payload"].get("protocol")
        if field == "dport":
            if proto in ("tcp", "udp", "sctp") and proto != pkt.proto:
                return False
            return _neg(_nft_value_matches(right, pkt.dport), neg)
        if field == "sport":
            return ("cond", "from a specific source port")
        if field in ("protocol", "nexthdr"):
            return _neg(_nft_value_matches(right, pkt.proto), neg)
        # An ip match never sees an IPv6 packet, and an ip6 match never an IPv4 one.
        if (proto == "ip" and pkt.family != "ipv4") or \
                (proto == "ip6" and pkt.family != "ipv6"):
            return False
        if field == "saddr":
            return ("cond", f"{'not ' if neg else ''}from {_describe(right)}")
        if field == "daddr":
            return ("cond", f"{'not ' if neg else ''}addressed to {_describe(right)}")
        if proto in ("tcp", "udp", "sctp") and proto != pkt.proto:
            return False
        return None
    if "meta" in left:
        key = left["meta"].get("key")
        if key in ("l4proto",):
            return _neg(_nft_value_matches(right, pkt.proto), neg)
        if key in ("nfproto",):
            want = "ipv4" if pkt.family == "ipv4" else "ipv6"
            return _neg(_nft_value_matches(right, want), neg)
        if key in ("iifname", "iif"):
            hit = _nft_value_matches(right, "lo")
            if hit is True:
                return _neg(False, neg)
            return ("cond", f"{'not ' if neg else ''}arriving on {_describe(right)}")
        if key in ("pkttype",):
            return _neg(_nft_value_matches(right, "host"), neg)
        return None
    if "ct" in left and left["ct"].get("key") == "state":
        hit = _nft_value_matches(right, "new")
        if op == "in" or op == "==":
            return hit
        return _neg(hit, neg)
    if "fib" in left:
        if "type" in (left["fib"].get("result") or ""):
            return _neg(_nft_value_matches(right, "local") or
                        _nft_value_matches(right, "unicast"), neg)
        return None
    return None


def _describe(value) -> str:
    if isinstance(value, dict) and "prefix" in value:
        return f"{value['prefix'].get('addr')}/{value['prefix'].get('len')}"
    if isinstance(value, dict) and "set" in value:
        return "{" + ", ".join(_describe(v) for v in value["set"]) + "}"
    return str(value)


def _eval_match(match, pkt: Packet):
    kind, arg, neg = match
    if kind == "unknown":
        return None
    if kind == "nft":
        return _eval_nft(arg, pkt)
    if kind == "vmap":
        return True
    return _eval_ipt(kind, arg, neg, pkt)


def _vmap_verdict(vmap: dict, pkt: Packet):
    key = vmap.get("key") or {}
    field = ((key.get("payload") or {}).get("field"))
    if field != "dport":
        return None, None
    for entry in (vmap.get("data") or {}).get("set") or []:
        if isinstance(entry, list) and len(entry) == 2 and \
                _nft_value_matches(entry[0], pkt.dport) is True:
            v = entry[1]
            for k in ("accept", "drop", "reject", "return"):
                if k in v:
                    return k, None
            for k in ("jump", "goto"):
                if k in v:
                    return k, v[k].get("target")
    return "continue", None


def _run_chain(chains: dict, chain, pkt, conds, unknowns, depth, budget) -> list:
    """
    Every outcome of this chain for the packet: (verdict, conditions,
    unknowns). verdict is accept, drop or fallthrough.
    """
    if depth > 16 or budget[0] <= 0:
        return [("unknown", conds, unknowns + ["the rules nest too deeply to follow"])]
    outcomes = []
    paths = [(0, conds, unknowns)]
    while paths:
        idx, c, u = paths.pop()
        budget[0] -= 1
        if budget[0] <= 0:
            outcomes.append(("unknown", c, u + ["too many branches to follow"]))
            continue
        while idx < len(chain.rules):
            rule = chain.rules[idx]
            idx += 1
            state = True
            branch_note = None
            for m in rule.matches:
                r = _eval_match(m, pkt)
                if r is False:
                    state = False
                    break
                if r is None:
                    state = None
                    branch_note = ("u", f"cannot read {m[1] if m[0] == 'unknown' else 'a match'} "
                                        f"in: {rule.text}")
                elif isinstance(r, tuple) and state is True:
                    state = "cond"
                    branch_note = ("c", r[1])
            if state is False or rule.verdict is None:
                continue
            if state is not True:
                # Fork: the path where it did not match carries on here.
                paths.append((idx, c, u))
                if branch_note[0] == "c":
                    c = c + [branch_note[1]]
                else:
                    u = u + [branch_note[1]]
            verdict, target = rule.verdict, rule.target
            if verdict == "vmap":
                vm = next(m[1] for m in rule.matches if m[0] == "vmap")
                verdict, target = _vmap_verdict(vm, pkt)
                if verdict is None:
                    u = u + [f"a verdict map in: {rule.text}"]
                    outcomes.append(("unknown", c, u))
                    break
                if verdict == "continue":
                    continue
            if verdict in ("accept", "drop", "reject"):
                outcomes.append(("drop" if verdict == "reject" else verdict, c, u))
                break
            if verdict == "return":
                outcomes.append(("fallthrough", c, u))
                break
            if verdict in ("jump", "goto"):
                sub = chains.get(target)
                if sub is None:
                    outcomes.append(("unknown", c, u + [f"jump to missing chain {target}"]))
                    break
                results = _run_chain(chains, sub, pkt, c, u, depth + 1, budget)
                for v, c2, u2 in results:
                    if v == "fallthrough" and verdict == "jump":
                        paths.append((idx, c2, u2))
                    else:
                        outcomes.append((v, c2, u2))
                break
        else:
            outcomes.append(("fallthrough", c, u))
    return outcomes


def _base_chain_outcomes(chains: dict, chain, pkt) -> list:
    budget = [MAX_PATHS]
    out = []
    for v, c, u in _run_chain(chains, chain, pkt, [], [], 0, budget):
        if v == "fallthrough":
            v = chain.policy or "accept"
            v = "drop" if v == "reject" else v
        out.append((v, c, u))
    return out


def evaluate(fw: dict, family: str, proto: str, port: int, daddr: str = None) -> dict:
    """
    Would the firewall accept a new inbound connection to this port?

    Returns {"verdict": "blocked" | "allowed" | "allowed_from" | "undetermined",
             "only_from": [...], "why": [...], "chains": [...]}.
    """
    pkt = Packet(family, proto, port, daddr)
    fams = {"ipv4": ("ip", "inet"), "ipv6": ("ip6", "inet")}[family]
    bases = []
    for chains in fw.get("chainsets") or []:
        for c in chains.values():
            if c.hook == "input" and c.family in fams:
                bases.append((chains, c))
    if not bases:
        return {"verdict": "allowed", "only_from": [], "chains": [],
                "why": ["no input filtering is configured for this address family"]}
    bases.sort(key=lambda b: b[1].prio)
    verdict_parts, why, only_from, used = [], [], [], []
    for chains, c in bases:
        outcomes = _base_chain_outcomes(chains, c, pkt)
        used.append(f"{c.family} {c.table} {c.name}")
        kinds = {v for v, _c, _u in outcomes}
        if kinds == {"accept"} and not any(cond for _v, cond, _u in outcomes):
            verdict_parts.append("allowed")
        elif kinds == {"drop"}:
            verdict_parts.append("blocked")
            why.append(f"{c.family} {c.table} {c.name} drops it")
        elif "unknown" not in kinds and not any(u for _v, _c, u in outcomes):
            plain = [v for v, cond, _u in outcomes if not cond]
            if plain and all(v == "drop" for v in plain) and "accept" in kinds:
                verdict_parts.append("allowed_from")
                only_from += sorted({"; ".join(cond) for v, cond, _u in outcomes
                                     if v == "accept" and cond})
            elif plain and all(v == "accept" for v in plain):
                verdict_parts.append("allowed")
            else:
                verdict_parts.append("undetermined")
                why.append(f"{c.family} {c.table} {c.name}: accepted or dropped "
                           f"depending on conditions this check cannot settle")
        else:
            verdict_parts.append("undetermined")
            why += sorted({x for _v, _c, u in outcomes for x in u})[:4]
    if "blocked" in verdict_parts:
        verdict = "blocked"
    elif "undetermined" in verdict_parts:
        verdict = "undetermined"
    elif "allowed_from" in verdict_parts:
        verdict = "allowed_from"
    else:
        verdict = "allowed"
    return {"verdict": verdict, "only_from": only_from, "why": why, "chains": used}


# THE CENSUS

def _is_loopback(address: str) -> bool:
    a = (address or "").split("%")[0]
    if a.startswith("::ffff:"):
        a = a[7:]
    try:
        return ipaddress.ip_address(a).is_loopback
    except ValueError:
        return False


def exposure_for(listener: dict, fw: dict) -> dict:
    """How reachable one listener is from other machines, with the basis."""
    addr = listener.get("local_address") or ""
    proto = listener.get("proto")
    port = listener.get("local_port")
    if _is_loopback(addr):
        return {"exposure": "loopback_only",
                "basis": f"bound to {addr}, which only this host can reach"}
    if not fw.get("readable"):
        ufw = fw.get("ufw") or {}
        if ufw.get("enabled") and ufw.get("default_input_policy") in ("drop", "deny", "reject"):
            basis = ("ufw is on with a default DROP policy for incoming "
                     "connections, but its allow rules are root-only, so "
                     "this port may or may not be allowed")
        elif ufw.get("present") and not ufw.get("enabled"):
            basis = ("ufw is installed and switched off, and no other rules "
                     "could be read as this account")
        else:
            basis = "the firewall rules need root to read"
        return {"exposure": "unknown", "basis": basis}
    families = []
    if addr in ("0.0.0.0",) or ("." in addr and ":" not in addr):
        families = ["ipv4"]
    elif addr.startswith("::ffff:"):
        families = ["ipv4"]
    elif addr in ("::", "*"):
        families = ["ipv4", "ipv6"]
    else:
        families = ["ipv6"]
    daddr = None if addr in ("0.0.0.0", "::", "*") else addr.replace("::ffff:", "")
    results = {f: evaluate(fw, f, proto, port, daddr) for f in families}
    order = ["allowed", "allowed_from", "undetermined", "blocked"]
    worst = min((r["verdict"] for r in results.values()), key=order.index)
    return {"exposure": {"allowed": "reachable", "allowed_from": "reachable_from_some",
                         "undetermined": "undetermined", "blocked": "firewalled"}[worst],
            "per_family": results,
            "basis": "; ".join(f"{f}: {r['verdict']}"
                               + (f" (only from {', '.join(r['only_from'])})" if r["only_from"] else "")
                               + (f" ({'; '.join(r['why'][:2])})" if r["why"] else "")
                               for f, r in results.items())}


def census(include_exposure: bool = True) -> dict:
    """
    Every listener the kernel knows (TCP, UDP, SCTP) with its owner and its
    exposure, plus the raw and packet sockets that listen without a port.
    """
    from tools import port_owner as po
    corr = po.correlate()
    listeners = [dict(r) for r in corr["sockets"] if r["scope"] == po.SCOPE_LISTEN]
    walked = po.socket_owners()
    sctp, sctp_note = read_sctp_listeners()
    _attach_owner(sctp, walked)
    listeners += sctp
    fw = read_firewall() if include_exposure else {"readable": False, "ufw": ufw_hint()}
    if include_exposure:
        for row in listeners:
            row.update(exposure_for(row, fw))
    hidden = hidden_listeners(walked)
    exposed = [r for r in listeners if r.get("exposure") in ("reachable", "reachable_from_some")]
    return {
        "listeners": listeners,
        "hidden": hidden,
        "firewall": {"readable": fw.get("readable"), "sources": fw.get("sources", []),
                     "notes": fw.get("notes", []), "ufw": fw.get("ufw")},
        "sctp_note": sctp_note,
        "counts": {"listeners": len(listeners),
                   "reachable_from_outside": len(exposed),
                   "hidden_sockets": len(hidden["sockets"]),
                   "hidden_concerning": len(hidden["concerning"])},
        "coverage": po.coverage_sentence(corr["counts"], corr["coverage"]),
    }
