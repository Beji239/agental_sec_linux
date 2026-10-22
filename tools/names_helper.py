#!/usr/bin/env python3
# tools/names_helper.py
# The names helper. Runs as root under systemd and does one thing: every
# second it reads the kernel's socket tables and writes which program owns
# each local address and port to one file. The capture service, which runs
# without root, reads that file to name the program behind every packet,
# root's programs included.
#
# It accepts nothing: no commands, no network, no input but the kernel's own
# /proc tables. It never sees a packet. Standard library only, because root's
# Python does not carry the app's packages.
#
# Usage:
#     names_helper.py --out /var/lib/agental_sec/names.json
#     names_helper.py --once --out FILE     one snapshot, then exit
#     names_helper.py --check               print what it can read, exit

import argparse
import json
import os
import socket
import struct
import sys
import time

TABLES = (("tcp", socket.AF_INET), ("tcp6", socket.AF_INET6),
          ("udp", socket.AF_INET), ("udp6", socket.AF_INET6))
INTERVAL = 1.0
MAX_CMDLINE = 300
NAMES_FILE = "/var/lib/agental_sec/names.json"
FRESH_SECONDS = 5.0


def _addr(hexaddr: str, family) -> tuple:
    """A /proc/net address field as (text address, port)."""
    host, port = hexaddr.split(":")
    raw = bytes.fromhex(host)
    if family == socket.AF_INET:
        ip = socket.inet_ntop(family, struct.pack("<I", struct.unpack(">I",
                                                                      raw)[0]))
    else:
        words = struct.unpack(">4I", raw)
        ip = socket.inet_ntop(family, struct.pack("<4I", *words))
    return ip, int(port, 16)


def socket_inodes() -> dict:
    """inode to (proto, local ip, local port) for every socket in /proc/net."""
    out = {}
    for name, family in TABLES:
        try:
            with open(f"/proc/net/{name}", encoding="ascii") as f:
                next(f, None)
                for line in f:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    try:
                        ip, port = _addr(parts[1], family)
                    except (ValueError, OSError, struct.error):
                        continue
                    inode = parts[9]
                    if inode != "0":
                        out[inode] = (name.rstrip("6"), ip, port)
        except OSError:
            continue
    return out


def _read(path: str, limit: int = 4096) -> str:
    try:
        with open(path, "rb") as f:
            return f.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def owners(inodes: dict) -> tuple[dict, dict, dict, int]:
    """(endpoint owners, socket inode owners, program details, processes
    not readable)."""
    endpoints, by_inode, programs, unreadable = {}, {}, {}, 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            fds = os.listdir(f"/proc/{pid}/fd")
        except OSError:
            unreadable += 1
            continue
        mine = []
        for fd in fds:
            try:
                target = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            if target.startswith("socket:["):
                inode = target[8:-1]
                hit = inodes.get(inode)
                if hit:
                    mine.append(hit)
                    by_inode.setdefault(inode, []).append(int(pid))
        if not mine:
            continue
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            exe = None
        try:
            uid = os.stat(f"/proc/{pid}").st_uid
        except OSError:
            uid = None
        programs[pid] = {
            "comm": _read(f"/proc/{pid}/comm").strip(),
            "cmdline": _read(f"/proc/{pid}/cmdline").replace("\0", " ")
                       .strip()[:MAX_CMDLINE],
            "exe": exe, "uid": uid}
        for proto, ip, port in mine:
            endpoints.setdefault(f"{proto} {ip} {port}", int(pid))
    return endpoints, by_inode, programs, unreadable


def snapshot() -> dict:
    endpoints, by_inode, programs, unreadable = owners(socket_inodes())
    return {"written_at": time.time(), "helper_pid": os.getpid(),
            "endpoints": endpoints, "inodes": by_inode, "programs": programs,
            "processes_unreadable": unreadable}


def read(path: str = None) -> tuple[dict | None, str | None]:
    """The helper's last snapshot, for the app: (data, None) when fresh,
    else (None, why not)."""
    path = path or NAMES_FILE
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return None, ("the names helper is not installed (sudo "
                      "scripts/install_capture_service.sh --apply)")
    except (OSError, ValueError) as e:
        return None, f"the names helper's file could not be read ({e})"
    age = time.time() - float(data.get("written_at") or 0)
    if age > FRESH_SECONDS:
        return None, f"the names helper has not written for {int(age)} s"
    return data, None


def write(path: str, data: dict) -> None:
    """Atomically, so a reader never sees half a file."""
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, separators=(",", ":"))
    # Group-readable once the folder hands new files the app's group; an
    # older install still has root's group, so it stays readable there.
    os.chmod(tmp, 0o640 if os.stat(tmp).st_gid else 0o644)
    os.replace(tmp, path)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="AgentalSec names helper")
    ap.add_argument("--out", default="/var/lib/agental_sec/names.json")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    if args.check:
        snap = snapshot()
        print(json.dumps({"ok": True, "euid": os.geteuid(),
                          "endpoints": len(snap["endpoints"]),
                          "programs": len(snap["programs"]),
                          "processes_unreadable":
                              snap["processes_unreadable"]}))
        return 0
    while True:
        try:
            write(args.out, snapshot())
        except Exception as e:                              # noqa: BLE001
            print(f"names helper: snapshot not written: {e}", file=sys.stderr)
        if args.once:
            return 0
        time.sleep(INTERVAL)


if __name__ == "__main__":
    sys.exit(main())
