# tools/port_owner.py
# AgentalSec, T9, 2026-09-25. WHICH PROCESS OWNS WHICH PORT ON THIS HOST.
#
# WHY THIS EXISTS
#
# The owner's instruction, 2026-09-25: "agent now has to have access to ports
# and processes finding in this machine to be able to report which port relates
# to which process ... python should execute the scan on set intervals".
#
# Both halves of that sentence already existed separately and NEITHER answered
# the question:
#
#   * port_scan_results says port 8080 is open. It cannot say what opened it.
#     It is also a record of what a SCAN found, which is a different thing from
#     what is open right now: a scan is a moment somebody asked for, and the
#     gaps between scans are where a listener lives its life.
#   * process_monitor_linux says a process is running. It reads psutil's
#     connection list where it can, but it does not own the correlation and it
#     has no table to put one in.
#
# So the question "which process is listening on 631" had no answer anywhere in
# this app, and a report that could not answer it had to describe a port as an
# anonymous hole. This module is that answer, and it is a MEASUREMENT module:
# it raises no findings (see the note on that below).
#
# HOW IT ANSWERS, AND WHY THIS WAY
#
# The kernel already knows. /proc/net/tcp, /proc/net/tcp6, /proc/net/udp and
# /proc/net/udp6 list every socket with its state, its local and remote
# address, and -- the important column -- its SOCKET INODE. That inode is the
# join key: /proc/<pid>/fd/* are symlinks, and a socket's symlink target is
# literally "socket:[<inode>]". So walking the fd tables once gives the owning
# pid for every readable socket, with no privilege beyond reading /proc.
#
# THE ALTERNATIVES, AND WHY NOT THEM:
#
#   * `ss -tulpn` is one process and it is a better tool when it works, and it
#     is exactly what main.py already uses for the "port is occupied" refusal.
#     It is NOT the one used here, deliberately: its output is a table meant
#     for a person, its columns move between iproute2 versions, and a parser
#     over its text would be a second implementation of what the kernel hands
#     over in a documented format. It is also not present on every install,
#     which is the same argument main.py's own fallback makes.
#   * psutil.net_connections(kind="inet") does the same walk and returns
#     Python objects. It is a real dependency of this tree and it is a fair
#     choice -- but it does NOT return the socket inode, so it cannot be
#     joined against a /proc/net row when the two disagree, and it raises
#     AccessDenied for another account's processes where /proc's own fd
#     directory answers EACCES on a PER-PROCESS basis that this module counts.
#     Counting the refusals is the whole point of the coverage block below.
#
# MEASURED ON THIS HOST, 2026-09-25, before the interval was chosen: 29
# listening sockets, 3.6 ms to read the four /proc/net files, 60.8 ms to walk
# 249 processes and 1,805 fds, 9 of the 29 sockets resolved to a pid as the
# desktop user, 148 process fd directories refused. About 65 ms a pass.
#
# THE LIMIT THAT MUST NEVER BE QUIET: 9 OF 29
#
# That measurement is the most important number in this file. Unelevated, THIS
# HOST could not name the owner of 20 of its own listening sockets, because
# they belong to root (cups, systemd-resolved, the privileged half of the
# desktop). A row that says "port 631, process: none" would then be read as
# "nothing owns this port", which is FALSE and is exactly the shape of defect
# this project has fixed eleven times: an empty answer standing in for an
# answer nobody could get.
#
# So every socket carries `owner_status`, and the three values are three
# different facts:
#
#   identified            a pid was read for this socket's inode
#   unreadable_as_user    at least one fd directory was refused, so the owner
#                         MAY exist and could not be read from here. Running
#                         the app elevated resolves these; nothing else does.
#   no_holder_found       every fd directory was readable and no process held
#                         this inode. Usually a socket that closed between the
#                         two reads -- the only honest reading is "it is not
#                         held any more", never "no process is responsible".
#
# AND THE COVERAGE TRAVELS WITH THE ANSWER. The sweep row carries the counts,
# so a reader of any payload from here can see 9-of-29 without asking a second
# question. "The agent could not see the owners" and "there were no owners" are
# different sentences and this module exists in part to keep them apart.
#
# IT RAISES NO FINDINGS, ON PURPOSE
#
# The finding rule in this project (honesty-rules): Python raises a finding
# ONLY when it can point to an expectation the USER EXPLICITLY DECLARED. This
# host's own listeners are the machine working correctly: cups listening on
# 631 is what a desktop is, systemd-resolved on 53 is what a resolver is. A
# rule keyed on "a port I have not seen before" is novelty, and novelty was
# already decided against (dns_novelty, and NET-1002's absence rule keyed on a
# declaration rather than on surprise).
#
# What this module produces instead is the EVIDENCE an unattended report is
# written from: what is listening, what owns it, what changed since the last
# look, and what could not be read from here. The duty loop puts that in the
# report (see core/duty.build_host_survey_block) and the model writes about it.
# The owner asked for it in the REPORT PAGE and that is where it goes.
#
# STORAGE SHAPE: BOUNDED BY CONSTRUCTION
#
# A pass every five minutes over ~30 sockets is 8,640 rows a day if every
# socket is written every time, which is a table that grows without ever being
# read and is the same shape the packets table had to be pruned over. So it
# does not work that way:
#
#   port_owner_sweep    ONE row per pass. The heartbeat, and the coverage.
#   port_owner_socket   ONE row per IDENTITY -- (proto, scope, local address,
#                       local port, pid, exe) -- carrying first_seen_at,
#                       last_seen_at, seen_count and whether it is still
#                       there. An ordinary machine has a few dozen.
#   port_owner_change   ONE row per TRANSITION: appeared, owner_changed,
#                       bind_changed, disappeared. This is the table a report
#                       reads, and a quiet machine writes nothing to it.
#
# The identity includes pid and exe and NOT the socket inode, because the inode
# changes every time the socket is recreated while pid+exe is what a person
# means by "the same listener". The inode is still stored on the socket row so
# two rows for one pid can be told apart, and so a reader can see a socket that
# was recreated underneath an unchanged process.
#
# NOTHING IS BACKFILLED and nothing here deletes. A listener that goes away
# gets active=0 and a `disappeared` change row; the record of it having been
# there stays, because "the port was open for three weeks and then stopped" is
# a sentence somebody will need and this is the only place it can come from.

import logging
import os
import time
from pathlib import Path
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# The four kernel tables. tcp/udp are IPv4, the 6 files are IPv6 including
# v4-mapped addresses, which is how a lot of software binds now.
PROC_NET_FILES = (
    ("tcp", "/proc/net/tcp",  "tcp"),
    ("tcp6", "/proc/net/tcp6", "tcp"),
    ("udp", "/proc/net/udp",  "udp"),
    ("udp6", "/proc/net/udp6", "udp"),
)

# Kernel socket states, from include/net/tcp_states.h. Only the ones this
# module reports on are named; an unlisted state is carried through as its own
# hex string rather than guessed at.
STATE_TCP_LISTEN = "0A"
STATE_TCP_ESTABLISHED = "01"
STATE_UDP_UNCONNECTED = "07"     # UDP's "listening" -- no peer bound
STATE_UDP_ESTABLISHED = "01"

# The scopes this module reports. A listener bound to 127.0.0.1 and one bound
# to 0.0.0.0 are different claims about a machine and the difference is the
# entire LAN question, so it is a stored field rather than something a reader
# has to decode out of the address string.
SCOPE_LISTEN = "listen"
SCOPE_ESTABLISHED = "established"

# owner_status values. See the header: these are three different facts.
OWNER_IDENTIFIED = "identified"
OWNER_UNREADABLE = "unreadable_as_user"
OWNER_NO_HOLDER = "no_holder_found"

# Change kinds.
CHANGE_APPEARED = "appeared"
CHANGE_DISAPPEARED = "disappeared"
CHANGE_OWNER = "owner_changed"
CHANGE_BIND = "bind_changed"

# A floor in code, so a config cannot ask for a permanently busy walk. The
# measured cost is ~65 ms a pass; at 30 s that is 0.2% of a core, which is the
# most this file will let an operator ask for.
MIN_SWEEP_SECONDS = 30
DEFAULT_SWEEP_SECONDS = 300


# READING THE KERNEL'S OWN TABLES

def _hex_to_ipv4(hexaddr: str) -> str:
    """
    '0100007F' -> '127.0.0.1'.

    The kernel writes the 32-bit address LITTLE-ENDIAN, so the four bytes come
    out in reverse and have to be flipped back. This is the classic off-by-a-
    byte-order mistake in /proc parsing and it is asserted in the tests against
    addresses whose correct reading is known in advance.
    """
    try:
        raw = bytes.fromhex(hexaddr)
        if len(raw) != 4:
            return ""
        return ".".join(str(b) for b in reversed(raw))
    except ValueError:
        return ""


def _hex_to_ipv6(hexaddr: str) -> str:
    """
    The 32-hex-digit form, four 8-digit groups each little-endian.

    Linux stores an IPv6 address as four u32 words in host byte order, so each
    group of 8 hex characters is reversed on ITS OWN and then the groups are
    concatenated in order. Reversing the whole string instead produces an
    address that looks plausible and is wrong, which is why the tests pin a
    known v4-mapped address ('::ffff:127.0.0.1') rather than a shape.

    A V4-MAPPED ADDRESS IS PRESENTED DOTTED, and the docstring said so before
    the code did. The first version ended at `str(ipaddress.IPv6Address(...))`
    on the assumption that the stdlib renders ::ffff:127.0.0.1 the way a person
    writes it. IT DOES NOT -- Python renders the dotted-quad tail as hex, so
    this function answered `::ffff:7f00:1` for a socket the kernel had written
    as ::ffff:127.0.0.1. That is a wrong fact on the page with a correct
    docstring sitting over it: found by running the decoder against an address
    whose reading was known, which is exactly why the test pins one.

    The measured kernel bytes for a socket bound to ::ffff:127.0.0.1, taken
    from /proc/net/tcp6 on this host:
        0000000000000000FFFF00000100007F   ->   ::ffff:127.0.0.1
    """
    if len(hexaddr) != 32:
        return ""
    groups = []
    for i in range(0, 32, 8):
        chunk = hexaddr[i:i + 8]
        try:
            groups.append(bytes.fromhex(chunk)[::-1].hex())
        except ValueError:
            return ""
    full = "".join(groups)
    # Present it the way a person reads it: dotted for v4-mapped, else the
    # canonical compressed form via the stdlib's own formatter.
    try:
        import ipaddress
        addr = ipaddress.IPv6Address(int(full, 16))
        # ipv4_mapped is the ::ffff:0:0/96 block and is None for everything
        # else, including the v6 loopback and the deprecated v4-COMPATIBLE
        # range -- which is the right distinction: only the mapped form is a
        # v4 address the kernel is carrying through a v6 socket.
        if addr.ipv4_mapped is not None:
            return f"::ffff:{addr.ipv4_mapped}"
        return str(addr)
    except (ValueError, ImportError):
        return full


def _decode_address(hexaddr: str, ipv6: bool) -> str:
    return _hex_to_ipv6(hexaddr) if ipv6 else _hex_to_ipv4(hexaddr)


def _scope_for(address: str, state: str, proto: str) -> str:
    """listen or established, from the kernel's state code."""
    if proto == "tcp":
        return SCOPE_LISTEN if state == STATE_TCP_LISTEN else SCOPE_ESTABLISHED
    return (SCOPE_LISTEN if state == STATE_UDP_UNCONNECTED
            else SCOPE_ESTABLISHED)


def _read_proc_net(path: str) -> tuple:
    """
    One /proc/net file -> (rows, note).

    A REFUSED OR ABSENT FILE IS REPORTED, never swallowed into an empty list.
    /proc/net/udp6 is absent on a kernel built without IPv6 and is unreadable
    in some hardened configurations; either way "no UDP sockets exist" and "I
    could not read the UDP table" are different sentences, and this module
    never lets the second one wear the first one's clothes.
    """
    rows = []
    try:
        with open(path, encoding="ascii") as fh:
            next(fh, None)                       # the header line
            for line in fh:
                parts = line.split()
                if len(parts) < 10:
                    continue
                try:
                    local, remote, state = parts[1], parts[2], parts[3]
                    laddr, _, lport = local.rpartition(":")
                    raddr, _, rport = remote.rpartition(":")
                    rows.append({
                        "state":  state,
                        "uid":    parts[7],
                        "inode":  parts[9],
                        "laddr_hex": laddr,
                        "raddr_hex": raddr,
                        "port":   int(lport, 16),
                        "remote_port": int(rport, 16),
                    })
                except (ValueError, IndexError):
                    # A malformed line in a kernel file. Skipped, counted by
                    # the caller's row total against its own header line, and
                    # never allowed to abort the pass.
                    continue
    except OSError as e:
        return [], f"{path} could not be read ({e.strerror or e})"
    return rows, None


def list_sockets() -> dict:
    """
    Every socket the kernel will tell us about, in this module's shape.

    Returns {"sockets": [...], "coverage": {...}}. The coverage block names the
    tables that could not be read, because a run that read three of the four
    files is a partial answer and a reader has to be able to see that.
    """
    sockets, unreadable = [], []
    for _key, path, proto in PROC_NET_FILES:
        rows, note = _read_proc_net(path)
        if note:
            unreadable.append(note)
        is_v6 = path.endswith("6")
        for r in rows:
            scope = _scope_for(r["laddr_hex"], r["state"], proto)
            sockets.append({
                "proto":         proto,
                "scope":         scope,
                "kernel_state":  r["state"],
                "local_address": _decode_address(r["laddr_hex"], is_v6),
                "local_port":    r["port"],
                "remote_address": (_decode_address(r["raddr_hex"], is_v6)
                                   if scope == SCOPE_ESTABLISHED else ""),
                "remote_port":   (r["remote_port"]
                                  if scope == SCOPE_ESTABLISHED else 0),
                "inode":         r["inode"],
                "uid":           r["uid"],
            })
    return {
        "sockets": sockets,
        "coverage": {
            "tables_read": len(PROC_NET_FILES) - len(unreadable),
            "tables_total": len(PROC_NET_FILES),
            "unreadable": unreadable,
        },
    }


def socket_owners() -> dict:
    """
    inode -> [pid, ...], by walking every readable /proc/<pid>/fd.

    Returns {"owners": {...}, "denied": [pid...], "processes": n, "fds": n}.

    THE DENIED LIST IS THE POINT. A pid whose fd directory answers EACCES is a
    process whose sockets cannot be attributed from here, and the count of
    those is what turns 20 unattributed sockets into "unreadable as this user"
    instead of "nothing owns them".
    """
    owners: dict = {}
    denied = []
    processes = fds = 0
    try:
        entries = os.listdir("/proc")
    except OSError as e:
        return {"owners": {}, "denied": [], "processes": 0, "fds": 0,
                "readable": False,
                "note": f"/proc could not be listed ({e.strerror or e})"}
    for pid in entries:
        if not pid.isdigit():
            continue
        processes += 1
        fd_dir = f"/proc/{pid}/fd"
        try:
            fd_names = os.listdir(fd_dir)
        except OSError:
            denied.append(pid)
            continue
        for fd in fd_names:
            fds += 1
            try:
                target = os.readlink(f"{fd_dir}/{fd}")
            except OSError:
                continue                     # raced with the process exiting
            if target.startswith("socket:[") and target.endswith("]"):
                owners.setdefault(target[8:-1], []).append(int(pid))
    return {"owners": owners, "denied": denied, "processes": processes,
            "fds": fds, "readable": True, "note": None}


def process_detail(pid: int) -> dict:
    """
    The identity of one pid, read straight out of /proc.

    `comm` IS NOT A NAME A READER MAY TRUST -- it is 15 bytes the process sets
    for itself with prctl(PR_SET_NAME), the same fact the kernel camera's
    register entry spends a paragraph on. It is carried because it is what a
    person sees in `top`, and it is carried BESIDE the exe path, which is the
    kernel's answer and not the process's. `exe` is a readlink and may end in
    " (deleted)" for a binary replaced under a running process; that marker is
    kept verbatim rather than stripped, because a binary that is no longer the
    file on disk is a real and interesting fact.
    """
    out = {"pid": pid, "comm": None, "exe": None, "cmdline": None,
           "readable": False, "note": None}
    try:
        with open(f"/proc/{pid}/comm", encoding="utf-8",
                  errors="replace") as fh:
            out["comm"] = fh.read().strip() or None
    except OSError as e:
        out["note"] = f"comm unreadable ({e.strerror or e})"
    try:
        out["exe"] = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        # A kernel thread has no exe, and another account's process refuses.
        # Both leave exe None, which the caller reports as its own fact.
        pass
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            raw = fh.read(4096)
        cmd = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace")
        out["cmdline"] = cmd.strip() or None
    except OSError:
        pass
    out["readable"] = bool(out["comm"] or out["exe"])
    return out


# THE SWEEP

def _is_loopback(address: str) -> bool:
    if not address:
        return False
    if address in ("127.0.0.1", "::1"):
        return True
    return address.startswith("127.") or address.startswith("::ffff:127.")


def _is_wildcard(address: str) -> bool:
    return address in ("0.0.0.0", "::")


# Unit directories, highest precedence first.
_UNIT_DIRS = ("/etc/systemd/system", "/run/systemd/system",
              "/run/systemd/generator", "/usr/local/lib/systemd/system",
              "/usr/lib/systemd/system", "/lib/systemd/system",
              "/run/systemd/generator.late")
_socket_units_cache = {"at": 0.0, "units": {}}


def _socket_unit_ports(name: str) -> tuple:
    """(ports, service) for one .socket unit, from its file and drop-ins."""
    main = next((Path(d) / name for d in _UNIT_DIRS
                 if (Path(d) / name).is_file()), None)
    if main is None:
        return [], None
    dropins = {}
    for d in reversed(_UNIT_DIRS):
        for f in (Path(d) / f"{name}.d").glob("*.conf"):
            dropins[f.name] = f
    listens, service, section = [], None, None
    for f in [main] + [dropins[k] for k in sorted(dropins)]:
        try:
            lines = f.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if line.startswith("["):
                section = line
            elif section == "[Socket]" and "=" in line:
                key, _, value = (x.strip() for x in line.partition("="))
                if key in ("ListenStream", "ListenDatagram", "ListenSequentialPacket"):
                    if not value:
                        listens = []
                    else:
                        listens.append(value)
                elif key == "Service" and value:
                    service = value
    ports = []
    for v in listens:
        tail = v.rpartition(":")[2] if ":" in v else v
        if tail.isdigit():
            ports.append(int(tail))
    return ports, service or name[:-len(".socket")] + ".service"


def socket_units() -> dict:
    """Port to (socket unit, service it starts), read from the unit files.
    Cached for a minute; empty where systemd is not the init."""
    if time.time() - _socket_units_cache["at"] < 60:
        return _socket_units_cache["units"]
    names = set()
    for d in _UNIT_DIRS:
        names.update(f.name for f in Path(d).glob("*.socket") if "@" not in f.name)
    units = {}
    for name in sorted(names):
        ports, service = _socket_unit_ports(name)
        for port in ports:
            units.setdefault(port, (name, service))
    _socket_units_cache.update(at=time.time(), units=units)
    return units


def correlate() -> dict:
    """
    ONE PASS, no writes: every socket, with its owner where one was read.

    Returns {"sockets": [...], "coverage": {...}, "duration_ms": n}. Every
    socket row carries `owner_status` and, when identified, pid/comm/exe. This
    is the function the tools and the report block both read, so there is one
    implementation of "which process owns this port" in the tree.
    """
    started = time.perf_counter()
    listed = list_sockets()
    walked = socket_owners()
    owners = walked["owners"]
    denied_any = bool(walked["denied"])

    out = []
    for s in listed["sockets"]:
        pids = owners.get(s["inode"]) or []
        row = dict(s)
        row["pid"] = None
        row["comm"] = None
        row["exe"] = None
        row["owner_note"] = None
        if pids:
            # MULTIPLE HOLDERS ARE REAL: a forked child inherits the listening
            # socket, so a web server with workers shows the fd in several
            # pids. The kernel has no "the" owner to give; the first pid is
            # taken as the representative and the count is kept, because
            # "4 processes hold this socket" is a fact about a preforking
            # server that a reader may want.
            # systemd holds a socket-activated port alongside the daemon it
            # started, so the daemon is the better name when both hold it.
            rep = next((p for p in pids if p != 1), pids[0])
            row["pid"] = rep
            row["holder_count"] = len(pids)
            detail = process_detail(rep)
            row["comm"] = detail["comm"]
            row["exe"] = detail["exe"]
            row["owner_status"] = OWNER_IDENTIFIED
            if rep == 1 and row["scope"] == SCOPE_LISTEN:
                unit = socket_units().get(row["local_port"])
                if unit:
                    row["socket_unit"], row["activates"] = unit
                    row["owner_note"] = (
                        f"held by systemd for socket activation ({unit[0]}); "
                        f"it starts {unit[1]} when a connection arrives, so "
                        f"that service is what answers on this port")
        elif denied_any:
            row["owner_status"] = OWNER_UNREADABLE
            row["owner_note"] = ("at least one process's fd table was refused; "
                                 "the owner may exist and is not readable from "
                                 "this account. Elevated runs resolve these.")
        else:
            row["owner_status"] = OWNER_NO_HOLDER
            row["owner_note"] = ("every fd table was readable and no process "
                                 "held this socket, so it closed between the "
                                 "two reads. Not held is not the same as not "
                                 "owned.")
        out.append(row)

    listeners = [r for r in out if r["scope"] == SCOPE_LISTEN]
    identified = [r for r in listeners if r["owner_status"] == OWNER_IDENTIFIED]
    unread = [r for r in listeners if r["owner_status"] == OWNER_UNREADABLE]
    orphan = [r for r in listeners if r["owner_status"] == OWNER_NO_HOLDER]
    wild = [r for r in listeners if _is_wildcard(r["local_address"])]
    duration_ms = int((time.perf_counter() - started) * 1000)

    coverage = {
        "tables_read": listed["coverage"]["tables_read"],
        "tables_total": listed["coverage"]["tables_total"],
        "unreadable_tables": listed["coverage"]["unreadable"],
        "processes_seen": walked["processes"],
        "fds_seen": walked["fds"],
        "processes_denied": len(walked["denied"]),
        "proc_readable": walked["readable"],
    }
    return {
        "sockets": out,
        "coverage": coverage,
        "counts": {
            "sockets": len(out),
            "listeners": len(listeners),
            "established": len(out) - len(listeners),
            "listeners_with_owner": len(identified),
            "listeners_unreadable": len(unread),
            "listeners_no_holder": len(orphan),
            "listeners_on_all_interfaces": len(wild),
        },
        "duration_ms": duration_ms,
    }


def coverage_sentence(counts: dict, coverage: dict) -> str:
    """
    ONE sentence saying how much of this answer is an answer.

    It is a function rather than a string in three places because the three
    surfaces that show this (the report block, the tool payload, the status
    card) must not be able to describe the same run differently -- the lesson
    new-sensor-wiring.md names as "decide the state string once and have every
    other surface read it".
    """
    listeners = counts.get("listeners", 0)
    known = counts.get("listeners_with_owner", 0)
    unread = counts.get("listeners_unreadable", 0)
    if not coverage.get("proc_readable", True):
        return ("NOTHING COULD BE ATTRIBUTED THIS PASS: /proc could not be "
                "read, so no listener below has an owner and that is a reader "
                "failure, not a machine with no processes.")
    base = (f"{known} of {listeners} listening socket(s) were matched to a "
            f"process")
    if unread:
        base += (f"; {unread} belong to an account this run cannot read "
                 f"(root-owned services do this unelevated, and an elevated "
                 f"run resolves them)")
    if counts.get("listeners_no_holder"):
        base += (f"; {counts['listeners_no_holder']} closed between the two "
                 f"reads")
    if coverage.get("unreadable_tables"):
        base += (f". NOT FULLY READ: "
                 f"{'; '.join(coverage['unreadable_tables'])}")
    return base + "."


def coverage_sentence_for_row(row: dict) -> str:
    """
    The coverage sentence for a STORED sweep row.

    Exists so that a reader with a row in hand -- the report block, the page,
    a script -- renders the identical sentence the sweep wrote when it ran,
    without reconstructing the two dicts by hand. The row's own `note` is
    preferred where it exists, because it is what was actually written at the
    time (and on a seed pass it carries an extra sentence this function cannot
    know about).
    """
    if not row:
        return "no sweep has been recorded"
    if row.get("note"):
        return row["note"]
    return coverage_sentence(
        {"listeners": row.get("listeners") or 0,
         "listeners_with_owner": row.get("listeners_with_owner") or 0,
         "listeners_unreadable": row.get("listeners_unreadable") or 0,
         "listeners_no_holder": row.get("listeners_no_holder") or 0},
        {"proc_readable": True, "unreadable_tables": []})


# STORING THE SWEEP

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _identity(row: dict) -> tuple:
    """
    THE SOCKET TABLE'S KEY: one row per HOLDER of one binding.

    pid and exe are in it on purpose. `systemctl restart` ends one holder and
    starts another, and the socket table is a record of holders, so that is
    exactly what it should say. What must NOT do this is the change feed --
    see _port_key below.
    """
    return (row["proto"], row["scope"], row["local_address"],
            row["local_port"], row.get("pid"), row.get("exe") or "",
            row.get("remote_address") or "", row.get("remote_port") or 0)


def _port_key(row: dict) -> tuple:
    """
    THE PORT'S KEY: (proto, port number). This is what the change feed runs on.

    THE ADDRESS IS NOT PART OF IT, and that is the fix this key exists for. A
    listener that moves from 127.0.0.1:45995 to 0.0.0.0:45995 is the SAME PORT
    bound at a new address -- it is the classic quiet reconfiguration, a
    service being exposed to the LAN without its port number moving. Keyed by
    the address it reads as one listener arriving and another departing, and
    the fact that matters is lost inside two facts that are wrong.

    The port NUMBER alone can be shared by two addresses (this host runs
    listeners on 127.0.0.1:631 and ::1:631, and on 0.0.0.0:5353 and :::5353),
    which is why the port-level verdict is decided from the rows' PID SETS and
    not from any one row: two addresses held by processes that were all there
    last pass is a machine that did not change.
    """
    return (row["proto"], row["local_port"])


def _bind_key(row: dict) -> tuple:
    """THE BINDING'S KEY: (proto, address, port). One row per bind address."""
    return (row["proto"], row["local_address"], row["local_port"])


def record_sweep(session_id: str, correlated: dict = None) -> dict:
    """
    One pass, written: a heartbeat row, socket rows, and change rows.

    RETURNS A DICT AND NEVER RAISES, because this runs on a timer and a
    measurement that can kill the thread it runs on is a measurement that gets
    deleted the first time it misbehaves -- the argument core/intervals.py
    makes about itself, applied to the same shape of code. A failure is
    reported in the returned dict and in the log, and the sweep row is still
    written if the tables could be written at all.
    """
    from core import memory_engine as me

    correlated = correlated or correlate()
    counts = correlated["counts"]
    coverage = correlated["coverage"]
    at = _now()

    try:
        with me._get_conn() as conn:
            if not _tables_ready(conn):
                return {"ran": False,
                        "reason": ("port_owner_sweep does not exist yet, "
                                   "the migration has not been applied")}

            # THE FIRST PASS SEEDS AND REPORTS NOTHING.
            #
            # MEASURED, on this host, on the first run of this function: 16
            # `appeared` rows for a machine that had not changed at all --
            # cups, the resolver, mDNS, the desktop's own sockets. Every one of
            # them was there before this code existed, and reporting them as
            # arrivals would have put a page of news in a report about a host
            # sitting still. That is the defect references/new-sensor-wiring.md
            # names ("the first pass SEEDS and raises nothing... reporting it
            # as findings teaches the reader to skim the sensor before it has
            # ever been useful"), and the fix here is the same: record the
            # state, write NO change rows, and say in the sweep row that this
            # is what happened.
            #
            # Unlike the file-integrity sensors there is no exception case
            # here. Those raise on the seed pass for a state with no safe
            # reading at all (a world-writable key file); a listening socket
            # has no such state. A port being open is a fact, not an alarm,
            # and this module raises no findings by design.
            prior = conn.execute(
                "SELECT COUNT(*) FROM port_owner_sweep").fetchone()[0]
            seeding = (prior == 0)

            note = coverage_sentence(counts, coverage)
            if seeding:
                note += (" THIS IS THE FIRST PASS: it recorded what was "
                         "already listening as the starting state and raised "
                         "no arrivals, because none of these listeners "
                         "appeared while this app was watching.")

            cur = conn.execute("""
                INSERT INTO port_owner_sweep
                    (session_id, taken_at, sockets, listeners, established,
                     listeners_with_owner, listeners_unreadable,
                     listeners_no_holder, all_interface_listeners,
                     processes_denied, duration_ms, note)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                session_id, at, counts["sockets"], counts["listeners"],
                counts["established"], counts["listeners_with_owner"],
                counts["listeners_unreadable"], counts["listeners_no_holder"],
                counts["listeners_on_all_interfaces"],
                coverage["processes_denied"], correlated["duration_ms"],
                note,
            ))
            sweep_id = cur.lastrowid

            # ONLY LISTENERS ARE TRACKED, AND THAT IS THE WHOLE REASON
            # THIS TABLE IS SMALL ENOUGH TO KEEP.
            #
            # Measured on this host: 29 listening sockets against a few
            # hundred established ones, and the established set turns over
            # every time a browser opens a tab. Tracking those would write
            # thousands of rows an hour, every one of them a socket that
            # closed before anybody read it -- the packets-table problem in a
            # second table. A LISTENER is the durable fact: it is what a port
            # BEING OPEN means, it is what "which process owns this port"
            # asks about, and it is what the owner's report needs.
            #
            # The established sockets are still COUNTED (port_owner_sweep
            # carries that number) because "this host has 400 connections and
            # 29 listeners" is a different machine from "29 and 29", and the
            # count costs one integer.
            listeners_now = [r for r in correlated["sockets"]
                             if r["scope"] == SCOPE_LISTEN]

            prev = _current_sockets(conn)
            now_keys = {}
            for row in listeners_now:
                now_keys[_identity(row)] = row

            # THE TRANSITIONS ARE CLASSIFIED ON THE PORT, NOT ON THE IDENTITY.
            #
            # THIS WAS THE DEFECT, measured before it was fixed by this file's
            # own test: identity IS pid+exe, so `systemctl restart` changes
            # identity by definition and a per-identity diff reported every
            # ordinary restart as an arrival AND a departure. Two change rows,
            # both of them wrong, about the most routine event on a desktop.
            #
            # THE RULE, one clause per shape a real machine produces:
            #
            #   A PORT THAT CHANGED HANDS IS ONE FACT, NOT TWO. When the pids
            #   behind a port number have none in common with the pids that were
            #   there last pass, the listener behind it is a different thing:
            #   ONE `owner_changed` row. The rows that left and arrived under it
            #   are suppressed, because the same event told three times is the
            #   per-identity defect one layer down.
            #   A JOINING WORKER IS AN ARRIVAL. When the pid sets DO intersect,
            #   nobody lost the port: a preforking server has another worker
            #   today, and that worker's row is genuinely new, so it is
            #   `appeared`. The other direction is deliberately NOT symmetric --
            #   a worker exiting says nothing about a port that is still held,
            #   and this feed does not narrate a server's worker count.
            #   A MOVE IS A BIND CHANGE, and only for the same process. Same
            #   port number, different address: loopback to 0.0.0.0 exposes a
            #   service to the LAN without moving a port, which is the quiet
            #   half of a reconfiguration. Two DIFFERENT processes at two
            #   different addresses is a change of hands, not a move.
            #   AN UNREADABLE OWNER IS NOT A CHANGE. A port this run cannot
            #   attribute has no pid on either side, and a transition invented
            #   out of two blanks reports a privilege limit as an event.
            #   A DEPARTURE IS A BINDING HELD BY NOBODY. The socket rows are per
            #   HOLDER, so a server with four workers has four; the change is
            #   one line saying the binding stopped being held, written once,
            #   when the last holder of it goes.
            #
            # AND A SEED PASS WRITES NO CHANGE ROW AT ALL, whatever it finds --
            # see the seeding note above. The `appeared` COUNT still reports how
            # many holder rows were recorded, because "16 listeners were written
            # down for the first time" is a fact about the pass, and "16
            # arrivals happened" is the sentence the seed pass exists to
            # prevent.
            #
            # THE SOCKET TABLE STILL TRACKS IDENTITY and that is not in
            # conflict: it is a record of identities, so a restart correctly
            # ends one row and starts another. It is the CHANGE FEED that must
            # describe the port, because the change feed is what a report is
            # written from.
            prev_by_bind, now_by_bind = {}, {}
            prev_by_port, now_by_port = {}, {}
            for row in prev.values():
                prev_by_bind.setdefault(_bind_key(row), []).append(row)
                prev_by_port.setdefault(_port_key(row), []).append(row)
            for row in now_keys.values():
                now_by_bind.setdefault(_bind_key(row), []).append(row)
                now_by_port.setdefault(_port_key(row), []).append(row)

            # THE PORT'S VERDICT for every port, decided BEFORE a row is
            # touched: the row loop below needs it in hand to know whether an
            # arrival or a departure is news or is the same news said twice.
            #
            # THE BIND TEST IS PER PID, NOT A CROSS PRODUCT. Two addresses can
            # share one port number on this host (127.0.0.1:631 and ::1:631,
            # 0.0.0.0:5353 and :::5353), so comparing every old row against
            # every new one would find a difference between two addresses that
            # both simply did not move, and call a still machine a moved one.
            # The question is only ever "did THIS process's address change",
            # so it is asked of each pid's own address set.
            verdict = {}
            for port_key, rows in now_by_port.items():
                olds = prev_by_port.get(port_key)
                if not olds:
                    continue                  # a new port, not a transition
                old_pids = {o["pid"] for o in olds if o.get("pid")}
                now_pids = {r["pid"] for r in rows if r.get("pid")}
                if not old_pids or not now_pids:
                    continue                  # unreadable either side: silence
                if not (old_pids & now_pids):
                    verdict[port_key] = CHANGE_OWNER
                    continue
                where_by_pid = {}
                for o in olds:
                    if o.get("pid"):
                        where_by_pid.setdefault(o["pid"], set()).add(
                            o["local_address"])
                if any(r.get("pid") in where_by_pid
                       and r["local_address"] not in where_by_pid[r["pid"]]
                       for r in rows):
                    verdict[port_key] = CHANGE_BIND

            appeared = vanished = reheld = moved = 0

            # THE PORT'S OWN ROW, once, for the ports that have a verdict.
            if not seeding:
                for port_key, kind in verdict.items():
                    _log_change(conn, sweep_id, kind, now_by_port[port_key][0],
                                at, previous=prev_by_port[port_key][0])
                    if kind == CHANGE_OWNER:
                        reheld += 1
                    else:
                        moved += 1

            # THE HOLDER ROWS: touched, inserted, or deactivated -- and an
            # arrival is reported only when the port's own verdict did not
            # already describe it.
            #
            # A HOLDER THAT IS GONE IS DEACTIVATED EVEN WHEN ITS BINDING IS
            # STILL HELD, and this is not bookkeeping: the rows are read back as
            # `active = 1` to build the next pass's `prev`, so a holder that is
            # never switched off stays in that set forever. Measured on the
            # restart case before this line existed: the pid that had been
            # replaced was still in the table two passes later, the pid sets
            # kept intersecting, and the next genuine change of hands on that
            # port read as "the same process is still there". A stale row is
            # how a detector stops working without saying anything.
            now_identities = set(now_keys)
            for identity, old in prev.items():
                if identity in now_identities:
                    continue
                conn.execute("UPDATE port_owner_socket SET active = 0 "
                             "WHERE id = ?", (old["id"],))

            for port_key, rows in now_by_port.items():
                for r in rows:
                    if _identity(r) in prev:
                        conn.execute("""
                            UPDATE port_owner_socket
                               SET last_seen_at = ?,
                                   seen_count = seen_count + 1,
                                   active = 1, inode = ?, owner_status = ?
                             WHERE id = ?
                        """, (at, r.get("inode"), r["owner_status"],
                              prev[_identity(r)]["id"]))
                        continue
                    conn.execute("""
                        INSERT INTO port_owner_socket
                            (proto, scope, local_address, local_port,
                             remote_address, remote_port, pid, comm, exe,
                             owner_status, inode, first_seen_at, last_seen_at,
                             seen_count, active)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1,1)
                    """, (r["proto"], r["scope"], r["local_address"],
                          r["local_port"], r.get("remote_address") or "",
                          r.get("remote_port") or 0, r.get("pid"),
                          r.get("comm"), r.get("exe"), r["owner_status"],
                          r.get("inode"), at, at))
                    appeared += 1
                    if seeding or port_key in verdict:
                        continue
                    _log_change(conn, sweep_id, CHANGE_APPEARED, r, at,
                                previous=None)

            # THE DEPARTURES: a binding that is no longer in the kernel's
            # table. One change row says the binding stopped being held, and
            # the rows were switched off by the loop above -- NOTHING IS
            # DELETED, and the record of it having been there is the only place
            # "the port was open for three weeks and then stopped" can come
            # from.
            for bind_key, olds in prev_by_bind.items():
                if bind_key in now_by_bind:
                    continue
                if seeding or _port_key(olds[0]) in verdict:
                    continue
                vanished += 1
                _log_change(conn, sweep_id, CHANGE_DISAPPEARED, olds[0], at,
                            previous=olds[0])

            conn.commit()
    except Exception as e:                                   # noqa: BLE001
        logger.error(f"port_owner: sweep could not be written: {e}")
        return {"ran": False, "reason": f"{type(e).__name__}: {e}"}

    logger.info(
        f"port_owner sweep #{sweep_id}"
        + (" (SEED: state recorded, no arrivals reported)" if seeding else "")
        + f": {counts['listeners']} listener(s), "
        f"{counts['listeners_with_owner']} owned, "
        f"{counts['listeners_unreadable']} unreadable, "
        f"{appeared} holder row(s) written, {reheld} owner_changed, "
        f"{moved} bind_changed, {vanished} disappeared, "
        f"{correlated['duration_ms']} ms")
    return {"ran": True, "sweep_id": sweep_id, "counts": counts,
            "coverage": coverage, "appeared": appeared,
            "owner_changed": reheld, "bind_changed": moved,
            "disappeared": vanished,
            "seeding": seeding, "note": note}


def _tables_ready(conn) -> bool:
    for name in ("port_owner_sweep", "port_owner_socket", "port_owner_change"):
        try:
            conn.execute(f"SELECT 1 FROM {name} LIMIT 1")
        except Exception:                                    # noqa: BLE001
            return False
    return True


def _current_sockets(conn) -> dict:
    rows = conn.execute("""
        SELECT * FROM port_owner_socket WHERE active = 1
    """).fetchall()
    out = {}
    for r in rows:
        d = dict(r)
        out[_identity(d)] = d
    return out


def _log_change(conn, sweep_id, kind, row, at, previous=None) -> None:
    import json as _json
    conn.execute("""
        INSERT INTO port_owner_change
            (sweep_id, detected_at, kind, proto, scope, local_address,
             local_port, pid, comm, exe, previous_json, note)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        sweep_id, at, kind, row.get("proto"), row.get("scope"),
        row.get("local_address"), row.get("local_port"), row.get("pid"),
        row.get("comm"), row.get("exe"),
        _json.dumps(previous, default=str) if previous else None,
        _change_note(kind, row),
    ))


def _change_note(kind: str, row: dict) -> str:
    where = f"{row.get('proto')} {row.get('local_address')}:{row.get('local_port')}"
    who = row.get("comm") or row.get("exe") or "an unidentified process"
    if kind == CHANGE_APPEARED:
        return (f"A listener appeared on {where}, held by {who}"
                + (f" (pid {row['pid']})" if row.get("pid") else
                   " whose owner could not be read from this account"))
    if kind == CHANGE_DISAPPEARED:
        return f"The listener on {where} is gone; it was held by {who}."
    if kind == CHANGE_OWNER:
        return f"{where} is now held by {who} instead of the process before it."
    if kind == CHANGE_BIND:
        return f"{where} changed its bind address."
    return f"{where}: {kind}"


def _owner_and_bind_changes(conn, sweep_id: int, at: str, prev: dict,
                            now_keys: dict) -> int:
    """
    REMOVED, 2026-09-25. It was the FIRST ATTEMPT at the transition rule, and
    it was dead code from the moment it was written: the sweep inlines the
    classification (see the block above `_tables_ready`), so nothing ever
    called this, and it carried the defect it was meant to fix.

    Kept as a named tombstone rather than deleted silently, because the
    register's rule is that a removed thing says so: this function keys its
    diff on (proto, ADDRESS, port), which reads a listener moving from
    loopback to 0.0.0.0 as one listener vanishing and another arriving. The
    live classifier keys on the PORT NUMBER so that the move IS the event,
    which is what the test asserts.

    NOTHING CALLS THIS. If a future caller arrives, take it from the sweep's
    own block instead.
    """
    raise NotImplementedError(
        "_owner_and_bind_changes was superseded by the port-keyed classifier "
        "inside record_sweep and has no callers. Do not re-add a second "
        "implementation of the transition rule; see record_sweep.")


# READING IT BACK

def query_listeners(include_inactive: bool = False, proto: str = None,
                    limit: int = 200) -> dict:
    """
    What is listening now, with its owner, and the coverage of the last sweep.

    THE COVERAGE IS NOT OPTIONAL IN THIS PAYLOAD. It is attached to every
    answer for the same reason sensor_health attaches itself to every degraded
    tool result: an empty or partial list from here must not be readable as
    "nothing is listening".
    """
    from core import memory_engine as me
    limit = max(1, min(int(limit or 200), 1000))
    where, params = ["scope = 'listen'"], []
    if not include_inactive:
        where.append("active = 1")
    if proto:
        where.append("proto = ?")
        params.append(proto)
    with me._get_readonly_conn() as conn:
        if not _tables_ready(conn):
            return {"available": False,
                    "note": ("the port_owner tables do not exist yet, so "
                             "nothing has ever swept this host. That is NOT a "
                             "host with nothing listening."),
                    "listeners": []}
        rows = me._rows_to_dicts(conn.execute(
            f"SELECT * FROM port_owner_socket WHERE {' AND '.join(where)} "
            f"ORDER BY local_port, proto LIMIT ?", params + [limit]).fetchall())
        last = conn.execute(
            "SELECT * FROM port_owner_sweep ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return {
        "available": True,
        "listeners": rows,
        "count": len(rows),
        "requested_limit": limit,
        "at_limit": len(rows) == limit,
        # THE SWEEP ROW GOES THROUGH THE SAME READER as the listeners, so its
        # timestamps arrive in the one shape this store publishes everywhere
        # else (_rows_to_dicts stamps them UTC). A payload with two timestamp
        # shapes in it is how a page ends up comparing a T against a space --
        # the defect T8 was written for -- and this module must not be the
        # second place that shape is decided.
        "last_sweep": (me._rows_to_dicts([last])[0] if last else None),
        "coverage": coverage_sentence_for_row(dict(last) if last else None),
    }


def query_changes(since: str = None, limit: int = 100) -> list:
    """Listener transitions, newest first. The report reads this."""
    from core import memory_engine as me
    limit = max(1, min(int(limit or 100), 500))
    sql = "SELECT * FROM port_owner_change"
    params = []
    if since:
        sql += " WHERE detected_at >= ?"
        params.append(me._sql_datetime(since) if hasattr(me, "_sql_datetime")
                      else since)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with me._get_readonly_conn() as conn:
        if not _tables_ready(conn):
            return []
        return me._rows_to_dicts(conn.execute(sql, params).fetchall())


def latest_sweep() -> dict:
    """The newest sweep row, timestamps in the store's published shape."""
    from core import memory_engine as me
    with me._get_readonly_conn() as conn:
        if not _tables_ready(conn):
            return {}
        row = conn.execute(
            "SELECT * FROM port_owner_sweep ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return me._rows_to_dicts([row])[0] if row else {}


def status() -> dict:
    """
    The state string, decided ONCE here and read by every other surface.

    See new-sensor-wiring.md: four callers need to know which empty this is
    (the boot log, the adapter's headline, the tool payload, the coverage
    block), and four copies of the same if-cascade is how four surfaces end up
    describing one machine differently. The ORDER is the decision:
    blind (a real failure) outranks stale (a timer problem) outranks unowned
    (a privilege limit, which is a coverage fact and NOT a failure).

    `last_sweep_at` COMES FROM THE RECORD, NOT FROM THIS MODULE'S MEMORY, and
    that was a defect found by running it: the first version reported
    `last_sweep_at: null` next to a note describing 16 listeners, because it
    read a module-level variable that is only set by the ADAPTER's thread --
    and this function is also called by tools, by the verification script and
    on a run where no thread has ever started. Two sources for one fact, and
    the one that answered was the one with no data in it.
    """
    out = {"role": "port_owner", "running": _state["running"],
           "interval_seconds": _state["interval"],
           "last_error": _state["last_error"]}
    try:
        last = latest_sweep()
    except Exception as e:                                   # noqa: BLE001
        out["blind"] = True
        out["blind_reason"] = (f"the sweep history could not be read ({e}), so "
                               f"nothing can be said about what is listening.")
        return out
    if not last:
        out["blind"] = True
        out["last_sweep_at"] = None
        out["blind_reason"] = ("no sweep has ever been recorded: nothing has "
                               "correlated a port with a process on this host.")
        return out
    out["last_sweep_at"] = last.get("taken_at")
    # THIS RUN's count, named so it cannot be read against the database's own.
    # The process has done 0 sweeps on a machine with 40 recorded, and a key
    # called `sweeps` would be read as the second number.
    out["sweeps_this_run"] = _state["sweeps"]
    out["listeners"] = last.get("listeners")
    out["listeners_with_owner"] = last.get("listeners_with_owner")
    out["listeners_unreadable"] = last.get("listeners_unreadable")
    out["note"] = last.get("note")
    if _state["last_error"]:
        out["blind"] = False
        out["reachable"] = False
    if last.get("listeners_with_owner") == 0 and (last.get("listeners") or 0):
        # Every listener unowned is either a privilege wall or a broken walk.
        # It is reported as its own state rather than as blind, because the
        # sweep itself worked: what it could not do is named in the sentence.
        out["unowned"] = True
    return out


# THE CLOCK, AND THE SWITCH, BOTH READ FROM ONE PLACE

_state = {"running": False, "interval": DEFAULT_SWEEP_SECONDS,
          "last_at": None, "last_error": None, "sweeps": 0}


def sweep_interval_seconds(config: dict) -> tuple:
    """
    (seconds, which key it came from). Floored, and the floor is in code.

    Two keys, checked in one order, so the value that is USED is always the
    value that was READ: sensors.port_owner.poll_interval first (the block
    every other sensor uses), then sensors.port_owner.sweep_interval, then the
    default. The floor exists so a config cannot ask for a permanently busy
    walk; the measured cost is in the module header.
    """
    block = ((config or {}).get("sensors", {}) or {}).get("port_owner", {}) or {}
    for key in ("poll_interval", "sweep_interval"):
        if key in block:
            try:
                secs = int(block[key])
            except (TypeError, ValueError):
                logger.warning(
                    f"port_owner: sensors.port_owner.{key} is {block[key]!r}, "
                    f"which is not a number of seconds. Using the default "
                    f"({DEFAULT_SWEEP_SECONDS}s).")
                return DEFAULT_SWEEP_SECONDS, "default (unreadable config)"
            if secs < MIN_SWEEP_SECONDS:
                logger.warning(
                    f"port_owner: sensors.port_owner.{key} is {secs}s, below "
                    f"the floor of {MIN_SWEEP_SECONDS}s. Using the floor; the "
                    f"floor exists so a config cannot ask for a permanently "
                    f"busy /proc walk.")
                return MIN_SWEEP_SECONDS, f"{key} (raised to the floor)"
            return secs, f"sensors.port_owner.{key}"
    return DEFAULT_SWEEP_SECONDS, "default"


def sweep_now(session_id: str, reason: str = "on demand") -> dict:
    """
    ONE PASS, NOW, for a caller that cannot wait for the timer.

    THIS IS THE HALF OF THE OWNER'S INSTRUCTION THE TIMER CANNOT DO: "whenever
    the agent wakes up to do a full check and report back in the report page,
    it should be able to deploy python". A duty tick runs at an hour the
    schedule picked and the sweep runs every five minutes; between them there
    is a window where the report is written from a picture up to five minutes
    old. Five minutes is nothing for a machine that has been listening on 631
    since boot, and it is everything for a listener that appeared in the last
    minute -- which is the one worth writing about.

    So the duty loop calls this before it builds a report prompt, and the
    result travels into the report as a fact about when the picture was taken.
    It is the same `record_sweep` the timer calls, deliberately: a second path
    that correlated sockets would be a second implementation of the same
    question, and this project has a rule about that (python-coding-hints:
    "one question, one implementation").

    `reason` is carried into the log line only. It is NOT written to the
    database: the sweep row records WHAT was seen, and a column saying which
    caller asked for the pass would be a field nothing reads, which is the
    shape AR-12 was about.

    NEVER RAISES. A report that cannot be written because the port sweep
    failed would be a monitoring tool that stops monitoring when a convenience
    fails, so a failure here returns a dict the caller can put in the report.
    """
    started = time.time()
    try:
        result = record_sweep(session_id)
    except Exception as e:                                   # noqa: BLE001
        logger.error(f"port_owner: on-demand sweep failed ({reason}): {e}")
        return {"ran": False, "reason": f"{type(e).__name__}: {e}",
                "duration_ms": int((time.time() - started) * 1000)}
    _state["last_at"] = _now()
    _state["sweeps"] += 1
    result["reason"] = reason
    return result


def sweep_due(last_at: str, interval_seconds: int,
              now: float = None) -> tuple:
    """
    (due: bool, waited_seconds: float | None). The clock, answered in ONE
    place so the adapter's thread and its status card cannot disagree.

    WALL CLOCK, NOT UPTIME -- the rule core/intervals.py and the whole time
    section of python-coding-hints are built on. The comparison is between two
    stored timestamps rather than against a monotonic counter this process
    owns, so a pass due while the machine was asleep fires on the next start
    instead of drifting one reboot further behind. Cadence that only advances
    while the app is running gets slower the less the machine is used, which
    is backwards for a monitoring tool.

    A TIMESTAMP THAT CANNOT BE READ IS DUE. The alternative is a sweep that
    stops forever because one row has a shape the parser does not know, and
    "I could not tell when I last looked" is a reason to look now rather than
    a reason to wait.
    """
    then = _parse_ts(last_at)
    if then is None:
        return True, None
    now = time.time() if now is None else now
    waited = now - then
    return waited >= max(MIN_SWEEP_SECONDS, int(interval_seconds)), waited


def _parse_ts(value):
    """
    A stored timestamp -> epoch seconds, or None.

    Handles the two shapes this database writes (a space-separated SQL string
    from SQLite's own CURRENT_TIMESTAMP, and the one this module writes) and
    treats a naive string as UTC, which is what the writers meant. This is the
    same reading core/intervals._parse documents at length: naive
    .timestamp() applies the MACHINE's zone, which was a seven-hour error once
    already.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip().replace("T", " ")
    if s.endswith("Z"):
        s = s[:-1]
    if "+" in s[10:]:
        s = s[:10] + s[10:].split("+")[0]
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(
                tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def sweep_enabled(config: dict) -> tuple:
    """
    (enabled, which key). `enabled` is compared with `is True`/`is False`
    semantics rather than truthiness: the string "false" is truthy, and this
    project has already walked a suppression gate past exactly that
    (python-coding-hints, §1.9/S7).
    """
    block = ((config or {}).get("sensors", {}) or {}).get("port_owner", {}) or {}
    if "enabled" not in block:
        return True, "default (no enabled key)"
    value = block["enabled"]
    if value is True:
        return True, "sensors.port_owner.enabled"
    if value is False:
        return False, "sensors.port_owner.enabled"
    logger.warning(
        f"port_owner: sensors.port_owner.enabled is {value!r}, which is "
        f"neither true nor false. Treated as OFF: a switch nobody can read is "
        f"not a switch, and a sensor that ran anyway would make the switch a "
        f"lie.")
    return False, "sensors.port_owner.enabled (unreadable, treated as off)"
