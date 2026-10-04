#!/usr/bin/env python3
"""
ebpf/ebpf_monitor.py -- the userspace half of the kernel camera.

WHAT THIS IS, IN ONE LINE. It loads ebpf_monitor.bpf.o into the kernel, attaches
the two tracepoints, reads events off a ring buffer, and writes them into a
SQLite database at a path it is given. Nothing else.

WHY THIS IS A SEPARATE PROCESS AND NOT PART OF THE APP

THE SAME ARGUMENT TIER D ALREADY WON, applied to a bigger privilege. Three
measured facts decide it:

  1. Loading a BPF program requires root on this host. MEASURED: the sysctls
     are `kernel.unprivileged_bpf_disabled = 2` (unprivileged loading fully
     disabled, not just defaulted off) and `kernel.perf_event_paranoid = 4`,
     and /sys/kernel/tracing is mode 700 root-only. There is no unprivileged
     path at all, and no passwordless sudo.

  2. The app PARSES ATTACKER-WRITTEN BYTES in 32 call sites across three
     modules -- counted when tier D was decided. Command lines, process names,
     filenames, log lines. A parser bug in a process running as root is a root
     bug; the same bug in a process running as the operator is an inconvenience.

  3. The app currently runs as root ONLY because the owner launched the
     privileged icon, and it must keep working when the owner launches the normal one.
     A design that only functions under the privileged launcher would make the
     camera's availability a function of which icon the owner clicked, which is not a
     property any sensor should have.

So the root is confined to this file, whose ONLY inputs are raw kernel structs
copied out of a ring buffer, and whose ONLY outputs are rows in a SQLite table
with bound parameters. It does not import the app, does not read the app's
config, does not touch the app's database (it writes a sidecar file the app
then READS), and never parses a string as anything but a string to be stored.

A read-only SQLite connection would still be a parser; a SEPARATE FILE with a
one-way write is not, which is why the handoff is a file rather than a socket
or a direct write into agental_sec.db.

THE HONESTY RULES THIS FILE IS BUILT AROUND

RULE TWO APPLIES TO EVERY EXIT. "I could not look" and "nothing happened" are
different sentences, and this program is the one with the most ways to be
unable to look: no root, no BTF, no clang at build time, the kernel refusing
the load, a tracepoint missing on this kernel, the ring buffer full. Every one
of those produces a NAMED refusal on stderr and a nonzero exit, and the app's
reader turns that into a coverage note. None of them produces an empty file
that would read as a quiet hour.

A DROPPED EVENT IS COUNTED AND REPORTED, never silently lost. The BPF side
increments a per-cpu counter when the ring is full; this side reads it out on
every flush and writes it into the same table it writes events into, as a row
of its own. A reader that finds drops can then say "this window is incomplete"
instead of implying it saw everything.

IT REFUSES TO RUN TWICE. Two copies would attach the same tracepoints twice,
double every event, and fight over the output file. A pidfile plus a liveness
check, and a refusal that names the holder.

USAGE

    sudo python3 ebpf/ebpf_monitor.py --out /var/lib/agental_sec/ebpf_events.db

Options:
    --out PATH        where to write events (required)
    --object PATH     the compiled .bpf.o (default: beside this file)
    --duration SEC    how long to run; 0 means until SIGTERM (default 0)
    --check           report what this host supports and exit, WITHOUT
                      loading anything and WITHOUT needing root for most of it
    --json            with --check, print the report as JSON

--check IS THE IMPORTANT ONE FOR AN OPERATOR. It answers "can this machine run
the camera" before anything is installed and before a password is typed.
"""

import argparse
import ctypes
import json
import os
import signal
import sqlite3
import struct
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

# WHAT THE KERNEL AND THE BUILD NEED
#
# These are checked and REPORTED rather than assumed, because every one of them
# has a different remedy and a single "it did not work" would send the operator
# looking in the wrong place.

REQUIRED_SYSCTLS = {
    # 0 = unprivileged loading allowed, 1 = default off, 2 = fully disabled.
    # 2 is fine for us and is what this host has: WE run as root.
    #
    # THIS DICT IS DOCUMENTATION AND NOT CONFIGURATION, and the distinction is
    # written here because the audit round that found it (bugfinder, E-5) is
    # the fourth time this project has paid for the shape: it was declared,
    # read by nothing, and it is the kind of name a reader assumes is checked.
    # The two sysctls that actually decide whether the kernel will take a
    # program are read INDIVIDUALLY below, by path, out of /proc/sys, and each
    # one carries its own remedy in the sentence it produces. A dict here
    # would be a second copy of that knowledge that can drift from the first.
    "kernel.unprivileged_bpf_disabled": None,
}
MIN_KERNEL = (5, 8)      # ringbuf landed in 5.8; CO-RE needs BTF

# The event struct, exactly as the BPF program defines it. Kept in one place
# and asserted by a test against the sizes the kernel reports, because a struct
# that drifts from the C definition produces garbage with no error anywhere --
# the worst possible failure for a component whose whole point is accuracy.
#
# THIS FORMAT WAS WRONG BY FOUR BYTES AND IT WOULD HAVE BEEN INVISIBLE.
#
# It read "<IIIQII16s16s256sIHH16s": three u32 before the u64. C does not pack
# a u64 immediately after three u32s -- it aligns an 8-byte member to an
# 8-byte boundary -- so the compiler inserts FOUR BYTES OF PADDING after ppid,
# and the kernel's struct is 344 bytes while this format described 340.
#
# MEASURED, both numbers, with two commands:
#
#   struct.calcsize("<IIIQII16s16s256sIHH16s")  -> 340
#   sizeof(struct event_t) compiled from the C   -> 344
#
# and MEASURED AGAIN, directly and better, in the 2026-09-23 audit round:
#
#   bpftool btf dump file ebpf_monitor.bpf.o  ->  event_t size_bytes = 344
#
# which is the compiler's own answer rather than this file's arithmetic about
# it. tests/test_ebpf_events.py computes the same 344 from the C source, and
# tests/test_ebpf_fixes.py asks the BTF, so a future field that shifts the
# layout fails in two independent places.
#
# WHAT THAT WOULD HAVE DONE, and why it is the worst failure this file can
# have: struct.unpack does not fail on a short format. It would have read the
# first 340 bytes of every 344-byte record and returned a dict in which ts_ns
# was built from `ppid`, uid from the TOP HALF OF ts_ns, comm from the padding
# plus the first twelve bytes of the real comm -- and every field from daddr
# onward shifted four bytes off, so an IPv4 address would decode one octet
# short and an IPv6 address would decode as garbage. Every row would look
# plausible. There is no exception to catch, no log line, and the camera would
# report confidently wrong addresses and times.
#
# The declaration now carries the four bytes as a REAL MEMBER in both halves
# -- `__u32 reserved;` in the C and one `I` here -- which is what the compiler
# does implicitly and what the kernel's ABI therefore already contains. It is
# named `reserved` rather than `_pad` for the reason that slot exists in an
# ABI that is already deployed: a future field belongs HERE, carved out of the
# bytes both sides already send, and not appended, which would change the size
# and silently shift every record read by an older loader.
EVENT_FMT = "<IIIIQII16s16s256sIHH16s"
EVENT_SIZE = struct.calcsize(EVENT_FMT)
KIND_EXEC, KIND_CONNECT = 1, 2


def check_support() -> dict:
    """
    What this host can and cannot do, without loading anything.

    Everything here is readable unelevated except the tracepoint list, so an
    operator can run this before deciding. It never raises.
    """
    out = {"ok": False, "problems": [], "notes": [], "euid": os.geteuid()}

    # 1. kernel version
    try:
        release = os.uname().release
        parts = []
        for chunk in release.split("-")[0].split("."):
            digits = "".join(c for c in chunk if c.isdigit())
            parts.append(int(digits) if digits else 0)
        while len(parts) < 3:
            parts.append(0)
        out["kernel"] = release
        if tuple(parts[:2]) < MIN_KERNEL:
            out["problems"].append(
                f"kernel {release} is older than "
                f"{MIN_KERNEL[0]}.{MIN_KERNEL[1]}, which is where BPF ring "
                f"buffers arrived. This machine cannot run the camera.")
    except Exception as e:                              # noqa: BLE001
        out["problems"].append(f"could not read the kernel version: {e}")

    # 2. BTF -- CO-RE needs it, and its absence is a kernel build choice
    btf = Path("/sys/kernel/btf/vmlinux")
    out["btf_present"] = btf.exists()
    if not btf.exists():
        out["problems"].append(
            "/sys/kernel/btf/vmlinux is absent, so this kernel was built "
            "without BTF and a CO-RE program cannot be loaded. Nothing can be "
            "done about this from userspace; the kernel would have to be "
            "replaced.")

    # 3. the sysctls
    try:
        val = Path("/proc/sys/kernel/unprivileged_bpf_disabled").read_text().strip()
        out["unprivileged_bpf_disabled"] = val
        if val != "0":
            out["notes"].append(
                f"kernel.unprivileged_bpf_disabled is {val}, so BPF programs "
                f"can ONLY be loaded by root here. This program is designed to "
                f"run as root; the note is here so the requirement is explicit "
                f"rather than discovered by a permission error.")
    except Exception:                                   # noqa: BLE001
        pass

    try:
        val = Path("/proc/sys/kernel/perf_event_paranoid").read_text().strip()
        out["perf_event_paranoid"] = val
    except Exception:                                   # noqa: BLE001
        pass

    # 4. lockdown. integrity lockdown does NOT block BPF tracing, but a
    # confidentiality lockdown does, and saying which one is on saves an
    # operator from a confusing failure.
    try:
        lockdown = Path("/sys/kernel/security/lockdown").read_text().strip()
        out["lockdown"] = lockdown
        if "confidentiality" in lockdown and "[confidentiality]" in lockdown:
            out["problems"].append(
                "the kernel is in CONFIDENTIALITY lockdown, which blocks BPF "
                "tracing of kernel internals. The camera cannot run.")
    except Exception:                                   # noqa: BLE001
        pass

    # 5. the tracepoints we attach to.
    #
    # os.path AND NOT pathlib, AND THIS WAS A REAL BUG FOUND BY RUNNING.
    # `/sys/kernel/tracing` is mode 700 root-only on this host, so
    # Path(...).exists() RAISES PermissionError rather than answering False --
    # and it took `--check`, the one command an operator runs BEFORE typing a
    # password, down with a traceback. os.path.exists swallows the refusal and
    # answers False, which is what the surrounding logic wants. The project's
    # own wiring notes carry this pitfall for a directory walk; here it was a
    # single stat.
    tracing_root = "/sys/kernel/tracing"
    tracing_readable = os.path.isdir(tracing_root) and os.access(
        tracing_root, os.R_OK | os.X_OK)
    for tp in ("sched/sched_process_exec", "syscalls/sys_enter_connect"):
        p = os.path.join(tracing_root, "events", tp)
        if os.path.exists(p):
            out.setdefault("tracepoints_present", []).append(tp)
        elif not tracing_readable:
            # UNREADABLE AND ABSENT ARE DIFFERENT FACTS, and collapsing them
            # would either invent a problem on a good host or hide one on a
            # bad kernel. Unelevated this is the normal answer and it is not a
            # problem; the attach step proves the truth.
            out.setdefault("tracepoints_unverifiable", []).append(tp)
        else:
            out["problems"].append(
                f"tracepoint {tp} is not present on this kernel, so the "
                f"camera would attach to nothing.")

    # 6. the compiled object
    obj = HERE / "ebpf_monitor.bpf.o"
    out["object_present"] = obj.exists()
    if not obj.exists():
        out["notes"].append(
            f"{obj.name} is not built yet. Run ebpf/build.sh, which needs "
            f"clang; see the build script's own header for what it does when "
            f"clang is missing.")

    out["ok"] = not out["problems"]
    return out


class EventSink:
    """
    Where events land. Its OWN database file, deliberately not the app's.

    The app reads this. This never reads the app. That one-way street is the
    security property: nothing that runs as root here ever opens
    agental_sec.db, so a malformed row cannot become a malformed query in a
    process that has root.
    """

    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), timeout=15)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        # E-1, 2026-09-23. WAL AND AN OPEN FOOTPRINT ARE A FILE THE APP CANNOT
        # READ, IN SILENCE. MEASURED on this host, with the write pattern that
        # was here before this round: a live camera file left open by its
        # writer, WAL mode, no checkpoint. The table lives in the -wal file
        # until a checkpoint.
        #
        #     immutable=1 (what tools/ebpf_events.py uses)  no table at all
        #     mode=ro     (the comparison)                  5 rows, fine
        #
        # and the app then reported, in words:
        #
        #     "<path> exists and opens, but it has no ebpf_event table, so it
        #      is not a camera file. Something else owns that path."
        #
        # The table was not on the last checkpoint; it was in a WAL the reader
        # is told to ignore, and NOTHING anywhere said so. The two halves of
        # this feature have never actually met: the camera has never been run
        # as root on this host, so the reader has never been handed a file a
        # CAMERA wrote -- only fixtures, which checkpoint themselves when the
        # writing process exits.
        #
        # THE FIX is a flush that lands the whole database in the main file and
        # empties the WAL, on the same clock as the commit that is already
        # there. MEASURED cost on a 5000-row camera file: 17.3 ms for one
        # wal_checkpoint(TRUNCATE). It runs once a second, so it costs ~1.7% of
        # one core on a desktop and it is the price of a reader that can
        # actually see the data. A writer in WAL mode with no checkpoint is not
        # a performance choice here; it is a file nobody else can open.
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS ebpf_event (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                kind      TEXT NOT NULL,
                ts_ns     INTEGER NOT NULL,
                pid       INTEGER NOT NULL,
                tgid      INTEGER NOT NULL,
                ppid      INTEGER NOT NULL DEFAULT 0,
                uid       INTEGER NOT NULL DEFAULT 0,
                comm      TEXT NOT NULL DEFAULT '',
                parent    TEXT NOT NULL DEFAULT '',
                filename  TEXT,
                daddr     TEXT,
                dport     INTEGER,
                family    TEXT,
                -- THE HOST'S OWN CLOCK, so a reader does not have to trust a
                -- monotonic kernel timestamp to know when this arrived.
                recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_ebpf_kind_time
                ON ebpf_event(kind, ts_ns);
            CREATE INDEX IF NOT EXISTS idx_ebpf_pid ON ebpf_event(tgid);
            CREATE INDEX IF NOT EXISTS idx_ebpf_comm ON ebpf_event(comm);
            CREATE INDEX IF NOT EXISTS idx_ebpf_daddr ON ebpf_event(daddr);

            -- Drops and stalls are ROWS, not log lines. A reader that queries
            -- this table can always find out whether the camera was keeping up
            -- for the window it is asking about, which is the difference
            -- between "no exec happened" and "no exec was recorded".
            --
            -- callback_errors is the third way this camera can lose a fact and
            -- it was the one with no column: a ring-buffer record this loader
            -- could not decode. It was counted in memory and read by nobody
            -- (E-7); it is a column now so the number outlives the process.
            CREATE TABLE IF NOT EXISTS ebpf_health (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                dropped_exec    INTEGER NOT NULL DEFAULT 0,
                dropped_connect INTEGER NOT NULL DEFAULT 0,
                events_written  INTEGER NOT NULL DEFAULT 0,
                callback_errors INTEGER NOT NULL DEFAULT 0,
                note       TEXT
            );
        """)
        # A CAMERA FILE FROM BEFORE THIS ROUND HAS THE OLD SHAPE, and ALTER
        # TABLE ADD COLUMN is how a reader of the OLD file keeps working: the
        # app asks for this column by name, so a missing one is a read error in
        # the reader rather than a cosmetic gap. Guarded by PRAGMA table_info
        # rather than by version numbers, because a file can be any age.
        try:
            have = {r[1] for r in self.conn.execute(
                "PRAGMA table_info(ebpf_health)")}
            if "callback_errors" not in have:
                self.conn.execute(
                    "ALTER TABLE ebpf_health ADD COLUMN callback_errors "
                    "INTEGER NOT NULL DEFAULT 0")
        except sqlite3.Error as e:                      # noqa: BLE001
            print(f"ERROR: could not bring ebpf_health up to the current "
                  f"shape ({type(e).__name__}: {e}). The camera will keep "
                  f"recording; its own loss counters may not be readable by "
                  f"the app.", file=sys.stderr)
        self.conn.commit()
        self.written = 0
        # Set by run() from the ring-buffer reader's own count. Kept on the
        # sink because the sink is what writes the health row (E-7).
        self.callback_errors = 0

    def add(self, rec: dict):
        self.conn.execute("""
            INSERT INTO ebpf_event
                (kind, ts_ns, pid, tgid, ppid, uid, comm, parent, filename,
                 daddr, dport, family)
            VALUES (:kind,:ts_ns,:pid,:tgid,:ppid,:uid,:comm,:parent,:filename,
                    :daddr,:dport,:family)
        """, rec)
        self.written += 1

    def commit(self):
        """
        Land what has been written where ANOTHER PROCESS can see it.

        The app now reads with mode=ro, which sees the WAL, and only falls
        back to immutable=1 when the camera is stopped. The checkpoint stays
        so that fallback finds everything in the main file.

        A PLAIN commit() IS NOT ENOUGH IN WAL MODE, and this is the whole of
        E-1. In WAL the committed rows live in the -wal file until a
        checkpoint, and the app reads this database through
        `immutable=1` -- deliberately, because the writer runs as root and a
        reader must not touch a root-owned writer's files. `immutable=1` tells
        SQLite to ignore the WAL. So a commit that does not checkpoint is a
        commit NOTHING ELSE CAN SEE, and the reader's honest sentence about it
        ("it is not a camera file") is about a file that is working perfectly.

        TRUNCATE rather than PASSIVE: PASSIVE copies the pages back but leaves
        the WAL at its current size, and the point here is a reader that finds
        the schema in the MAIN file. TRUNCATE is what makes the main file
        complete.
        """
        self.conn.commit()
        try:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error as e:                      # noqa: BLE001
            # A FAILED CHECKPOINT IS SAID OUT LOUD. The rows are committed and
            # the camera keeps recording, but the app cannot see them, and this
            # is exactly the class of failure this file refuses to swallow.
            print(f"ERROR: the camera could not land its data where the app "
                  f"reads it ({type(e).__name__}: {e}). The rows ARE written; "
                  f"the reader will report a file with no events until this "
                  f"succeeds. THE CAMERA IS RECORDING AND NOTHING CAN SEE IT.",
                  file=sys.stderr)

    def size_bytes(self) -> int:
        total = 0
        for p in (self.path, Path(str(self.path) + "-wal")):
            try:
                total += p.stat().st_size
            except OSError:
                pass
        return total

    def wipe_if_over(self, max_bytes: int) -> bool:
        """
        Empty the event table once the file reaches max_bytes.

        The app reads events within about a minute, so by 250 MB it has long
        since analysed them. DELETE keeps sqlite_sequence, so ids keep rising
        and the app's cursor stays valid. Health rows are kept.
        """
        size = self.size_bytes()
        if not max_bytes or size < max_bytes:
            return False
        try:
            self.conn.commit()
            n = self.conn.execute("SELECT COUNT(*) FROM ebpf_event").fetchone()[0]
            self.conn.execute("DELETE FROM ebpf_event")
            self.conn.commit()
            self.conn.execute("VACUUM")
            self.commit()
        except sqlite3.Error as e:                      # noqa: BLE001
            print(f"ERROR: the camera file is {size // (1024 * 1024)} MB and "
                  f"could not be emptied ({type(e).__name__}: {e}). It will "
                  f"keep growing.", file=sys.stderr)
            return False
        note = (f"size cap reached at {size // (1024 * 1024)} MB, "
                f"{n} events deleted")
        print(f"ebpf_monitor: {note}", flush=True)
        self.conn.execute("INSERT INTO ebpf_health (events_written, note) "
                          "VALUES (?, ?)", (self.written, note))
        self.commit()
        return True

    def record_health(self, dropped_exec: int, dropped_connect: int, note=None):
        self.conn.execute("""
            INSERT INTO ebpf_health
                (dropped_exec, dropped_connect, events_written,
                 callback_errors, note)
            VALUES (?,?,?,?,?)
        """, (dropped_exec, dropped_connect, self.written,
              self.callback_errors, note))
        self.commit()

    def close(self):
        try:
            self.conn.close()
        except Exception:                               # noqa: BLE001
            pass


def _decode(raw: bytes) -> dict:
    """
    One ring-buffer record into a row.

    EVERY FIELD IS TYPED HERE AND NOTHING IS INTERPRETED. The comm and filename
    are bytes chosen by whoever ran the process; they are decoded with
    errors='replace' so a malformed byte cannot raise inside the reader loop and
    take the camera down, and they are stored verbatim. No judgement, no
    parsing, no classification.
    """
    (kind, pid, tgid, ppid, ts_ns, uid, _pad, comm, parent, filename,
     daddr, dport, family, addr6) = struct.unpack(EVENT_FMT, raw)

    def s(b):
        return b.split(b"\x00", 1)[0].decode("utf-8", "replace")

    rec = {
        "kind": "exec" if kind == KIND_EXEC else "connect",
        "ts_ns": ts_ns, "pid": pid, "tgid": tgid, "ppid": ppid, "uid": uid,
        "comm": s(comm), "parent": s(parent),
        "filename": None, "daddr": None, "dport": None, "family": None,
    }
    if kind == KIND_EXEC:
        rec["filename"] = s(filename)
    elif kind == KIND_CONNECT:
        if family == 2:
            rec["daddr"] = ".".join(str((daddr >> shift) & 0xFF)
                                    for shift in (0, 8, 16, 24))
        elif family == 10:
            # 8 groups of 4 hex digits, the conventional short form
            rec["daddr"] = ":".join(
                f"{int.from_bytes(addr6[i:i+2], 'big'):x}"
                for i in range(0, 16, 2))
        else:
            rec["daddr"] = None
        rec["dport"] = dport
        rec["family"] = {2: "inet", 10: "inet6"}.get(family, str(family))
    return rec


class RingBuffer:
    """
    The smallest correct libbpf ring-buffer client.

    WRITTEN BY HAND RATHER THAN VIA A GENERATED SKELETON, and the reason is the
    build. bpftool's `gen skeleton` is available and would be the tidier path,
    but it bakes the object file INTO A GENERATED C FILE, which means the repo
    would carry both a .c and a .bpf.o that must be rebuilt together and can
    silently disagree after an edit. Loading the .o through libbpf's own API
    keeps ONE artifact -- the object the build produced -- and this class is the
    price. It is about sixty lines and every line is in libbpf.h.
    """

    def __init__(self, object_path: Path):
        self.object_path = object_path
        self.bpf = None
        self.obj = None
        self._progs = {}
        self._links = []
        self._events_map = None
        self._drops_map = None

    def load(self):
        lib = _libbpf()
        self.bpf = lib

        # libbpf is a C library whose structures are large and versioned. The
        # fields read below are the documented STABLE prefix of bpf_object
        # (the same ones every loader uses); the padding makes the allocation
        # safe regardless of what the installed version appends.
        class bpf_object_opts(ctypes.Structure):
            _fields_ = [("sz", ctypes.c_size_t),
                        ("_pad", ctypes.c_ubyte * 256)]

        opts = bpf_object_opts()
        opts.sz = ctypes.sizeof(bpf_object_opts)
        lib.bpf_object__open_file.restype = ctypes.c_void_p
        lib.bpf_object__open_file.argtypes = [ctypes.c_char_p,
                                             ctypes.POINTER(bpf_object_opts)]
        self.obj = lib.bpf_object__open_file(
            str(self.object_path).encode(), ctypes.byref(opts))
        if not self.obj:
            # libbpf_get_error AND NOT bpf_get_error. MEASURED on this host:
            # libbpf.so.1 exports `libbpf_get_error` and does NOT export
            # `bpf_get_error` at all -- that name was the pre-1.0 alias and
            # this library dropped it. ctypes raises AttributeError for a
            # symbol that is not there, so a loader that reached for the old
            # name would die with "undefined symbol: bpf_get_error" instead of
            # saying what libbpf said, which is the difference between a
            # diagnosable failure and a confusing one.
            err = lib.libbpf_get_error(ctypes.c_void_p(self.obj))
            raise RuntimeError(
                f"libbpf refused to open {self.object_path.name} "
                f"(error {err}). The object is either not a BPF object or was "
                f"built for a different target.")

        lib.bpf_object__load.argtypes = [ctypes.c_void_p]
        rc = lib.bpf_object__load(self.obj)
        if rc:
            raise RuntimeError(
                f"the KERNEL REFUSED THE PROGRAM (libbpf error {rc}). This is "
                f"the verifier rejecting it, and the usual causes are: this "
                f"kernel is older than the program assumes, the BTF it was "
                f"built against does not match, or a lockdown policy is in "
                f"force. Run --check for this host's state.")

        # Maps by name, so a rename in the C file is caught here rather than
        # producing an empty result set that looks like a quiet machine.
        lib.bpf_object__find_map_by_name.restype = ctypes.c_void_p
        lib.bpf_object__find_map_by_name.argtypes = [ctypes.c_void_p,
                                                     ctypes.c_char_p]
        self._events_map = lib.bpf_object__find_map_by_name(
            self.obj, b"events")
        self._drops_map = lib.bpf_object__find_map_by_name(
            self.obj, b"dropped")
        if not self._events_map or not self._drops_map:
            raise RuntimeError(
                "the loaded object has no 'events' and/or 'dropped' map. The "
                "object does not match this loader (was it built from "
                "ebpf_monitor.bpf.c?).")

        lib.bpf_object__find_program_by_name.restype = ctypes.c_void_p
        lib.bpf_object__find_program_by_name.argtypes = [ctypes.c_void_p,
                                                         ctypes.c_char_p]
        for tp, name in (("sched/sched_process_exec", b"handle_exec"),
                         ("syscalls/sys_enter_connect", b"handle_connect")):
            prog = lib.bpf_object__find_program_by_name(self.obj, name)
            if not prog:
                raise RuntimeError(
                    f"the object has no program named {name.decode()}")
            self._progs[tp] = prog

    def attach(self):
        lib = self.bpf
        lib.bpf_program__attach_tracepoint.restype = ctypes.c_void_p
        lib.bpf_program__attach_tracepoint.argtypes = [ctypes.c_void_p,
                                                       ctypes.c_char_p,
                                                       ctypes.c_char_p]
        for tp, prog in self._progs.items():
            category, _, name = tp.partition("/")
            link = lib.bpf_program__attach_tracepoint(
                prog, category.encode(), name.encode())
            if not link:
                err = lib.libbpf_get_error(ctypes.c_void_p(link))
                raise RuntimeError(
                    f"could not ATTACH to tracepoint {tp} (libbpf error "
                    f"{err}). The program loaded, so the kernel is willing; "
                    f"this is usually the tracepoint not existing under that "
                    f"name on this kernel.")
            self._links.append(link)

    def create_ring(self, ctypes_libc):
        lib = self.bpf
        lib.ring_buffer__new.restype = ctypes.c_void_p
        lib.ring_buffer__new.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                         ctypes.c_void_p, ctypes.c_void_p]

        # The callback signature libbpf calls: (void *ctx, void *data, size_t
        # len). It may NOT block and may NOT raise; the exception is carried
        # out in an attribute instead, because an exception inside a C callback
        # is undefined behaviour.
        #
        # AND THE ATTRIBUTE HAS TO BE READ, WHICH IT WAS NOT. E-7, 2026-09-23.
        # MEASURED before this round: `_cb_error` was written by the trampoline
        # and by `_on_event`, and read by NOTHING -- grep found its three
        # assignments and no consumer. So a record the loader could not decode
        # (a struct mismatch, which is the one failure this component must
        # never have silently) was recorded in a variable and dropped on the
        # floor while the camera reported itself healthy.
        #
        # Both halves are now counted and BOTH ARE PUBLISHED: `callback_errors`
        # in the health row and in the exit summary, so the number survives the
        # process. The first error is kept in full because it is the one that
        # names the cause; the count is what says how much was lost.
        self._cb_error = None
        self._cb_errors = 0
        self._cb_count = 0

        def _trampoline(ctx, data, size):
            try:
                raw = ctypes.string_at(data, size)
                self._on_event(raw)
                self._cb_count += 1
            except Exception as e:                      # noqa: BLE001
                self._cb_errors += 1
                if self._cb_error is None:
                    self._cb_error = f"{type(e).__name__}: {e}"
                return 0
            return 0

        self._cb = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p,
                                    ctypes.c_void_p, ctypes.c_size_t)(_trampoline)

        lib.bpf_map__fd.restype = ctypes.c_int
        lib.bpf_map__fd.argtypes = [ctypes.c_void_p]
        ev_fd = lib.bpf_map__fd(self._events_map)
        if ev_fd < 0:
            raise RuntimeError("could not get the events map's file descriptor")

        self.ring = lib.ring_buffer__new(ev_fd, self._cb, None, None)
        if not self.ring:
            raise RuntimeError(
                "could not create the ring buffer over the events map. The "
                "map exists (it is what the program loaded with), so this is "
                "a memory failure in libbpf.")
        return self.ring

    def _on_event(self, raw: bytes):
        if len(raw) < EVENT_SIZE:
            # A short record is a struct mismatch between the C file and this
            # loader. Counted as a drop rather than parsed, because parsing it
            # would produce plausible garbage. COUNTED, and the count is
            # published -- see the note in create_ring (E-7).
            self._cb_errors += 1
            if self._cb_error is None:
                self._cb_error = (f"a {len(raw)}-byte record arrived but the "
                                  f"loader expects {EVENT_SIZE}; the object "
                                  f"and this file disagree")
            return
        self.sink.add(_decode(raw[:EVENT_SIZE]))

    def _possible_cpus(self) -> int:
        """
        How many CPUs the per-cpu map has slots for, which is NOT os.cpu_count().

        MEASURED LESSON: a BPF per-cpu map is sized by the number of POSSIBLE
        CPUs, not the number ONLINE. Python's os.cpu_count() answers the online
        set. On this host both are 4 so the two agree and the bug would never
        show -- but on a machine with an offlined core, os.cpu_count() is one
        short, the syscall fills fewer slots than the buffer expects, and the
        drop counts read back WRONG with no error. A camera that under-reports
        its own drops is the exact failure this counter exists to prevent.
        """
        try:
            text = Path("/sys/devices/system/cpu/possible").read_text().strip()
            total = 0
            for part in text.split(","):
                part = part.strip()
                if "-" in part:
                    low, high = part.split("-", 1)
                    total += int(high) - int(low) + 1
                elif part:
                    total += 1
            if total > 0:
                return total
        except OSError:
            pass
        return max(1, os.cpu_count() or 1)

    def dropped_counts(self) -> dict:
        """
        The per-cpu drop counters, summed, WITH THE REASON when they cannot be.

        Read through the map's fd and the BPF_MAP_LOOKUP_ELEM syscall, because
        libbpf's typed accessors are for its own abstractions. Summed across
        CPUs because per-cpu is how the BPF side can increment without a lock.

        Returns {"exec": int|None, "connect": int|None, "error": str|None}.
        None means UNREADABLE and that is reported as such: a counter that
        cannot be read must never be summed as zero, or a camera with no idea
        how many events it lost would report that it lost none.
        """
        lib = self.bpf
        lib.bpf_map__fd.restype = ctypes.c_int
        lib.bpf_map__fd.argtypes = [ctypes.c_void_p]
        fd = lib.bpf_map__fd(self._drops_map)

        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.syscall.restype = ctypes.c_long

        # __NR_bpf, and NOT HARDCODED ACROSS ARCHITECTURES. It is 321 on
        # x86_64 and a different number on arm64, and a wrong number here is
        # an ENOSYS that would read as "the counter is unreadable" forever.
        #
        # `machine` IS IMPORTED AT THE TOP OF THIS FUNCTION on purpose, and the
        # reason is that `platform.machine()` is a call into the interpreter's
        # own platform module rather than a name of this file's. It is used on
        # every drop-counter read (once per 10-second health beat), so it is a
        # function-local import of a module Python has already loaded, not a
        # per-call lookup into the import system.
        from platform import machine
        machine = machine()
        if machine not in ("x86_64", "amd64"):
            return {"exec": None, "connect": None,
                    "error": (f"the BPF syscall number is not known for "
                              f"{machine!r} in this loader, so the drop "
                              f"counters could not be read. The events "
                              f"themselves are unaffected; only the count of "
                              f"what was LOST is unknown.")}
        SYS_bpf = 321

        n_cpus = self._possible_cpus()
        out = {"exec": None, "connect": None, "error": None}

        try:
            values = (ctypes.c_uint64 * n_cpus)()
        except (MemoryError, OverflowError) as e:
            out["error"] = f"could not allocate {n_cpus} counters: {e}"
            return out

        for key, label in ((0, "exec"), (1, "connect")):
            keybuf = ctypes.c_uint32(key)

            # union bpf_attr for BPF_MAP_LOOKUP_ELEM. ctypes applies C's own
            # alignment rules to this Structure, so the four bytes of padding
            # the kernel's union has after map_fd are here too; a hand-packed
            # version would shift key and value by four and the syscall would
            # return EFAULT against a correct map.
            #
            # E-2, 2026-09-23. THE TWO INDIRECT MEMBERS WERE POINTERS THE
            # KERNEL NEVER RECEIVED. MEASURED on this host before the fix, with
            # the shipped code and no map attached (the state a refusal leaves
            # behind):
            #
            #     AttributeError: 'LP_c_ulong' object has no attribute 'value'
            #
            # `attr->key` and `attr->value` are `__aligned_u64` in the kernel's
            # own header -- two fields whose SIZE is 8 and whose CONTENT is an
            # ADDRESS. This code assigned an INTEGER: `.value` on a
            # pointer-typed field returns the pointed-to array, and writing a
            # number into a POINTER field stores that number AS the address.
            # The kernel was therefore handed key = address 0 or 1 -- and it
            # READS THAT ADDRESS, as root's process on a kernel-facing path.
            # The syscall could not succeed whatever the map state, so the drop
            # counter -- the one number that says how much of this camera's
            # record is missing -- was unreadable on every host, always, and
            # the camera would have reported that it could not read its own
            # loss counter forever.
            #
            # With no map at all it is worse than a refusal: bpf_map__fd(None)
            # returns 0, the kernel answers EBADF, and the counter reads
            # UNKNOWN -- but the FIRST thing reached is ctypes' own error, so
            # the syscall never even ran. Fixed by keeping the key in a
            # c_uint32, the value in the array, and letting CTYPES take the
            # addresses: both are `void *` in the syscall's own signature.
            class attr_lookup(ctypes.Structure):
                _fields_ = [("map_fd", ctypes.c_uint32),
                            ("key", ctypes.c_void_p),
                            ("value", ctypes.c_void_p),
                            ("flags", ctypes.c_uint64)]
            a = attr_lookup()
            a.map_fd = fd
            a.key = ctypes.cast(ctypes.byref(keybuf), ctypes.c_void_p)
            a.value = ctypes.cast(values, ctypes.c_void_p)

            ctypes.set_errno(0)
            rc = libc.syscall(SYS_bpf, 1, ctypes.byref(a), ctypes.sizeof(a))
            if rc:
                err = ctypes.get_errno()
                out["error"] = (
                    f"the kernel refused BPF_MAP_LOOKUP_ELEM on the {label} "
                    f"drop counter (errno {err}: {os.strerror(err)}). The "
                    f"number of {label} events the camera DROPPED is therefore "
                    f"UNKNOWN, which is not the same as zero.")
            else:
                out[label] = sum(values)

        # os.cpu_count() is NOT used above; see _possible_cpus. The count that
        # was used is reported so a mismatch with /sys is visible rather than
        # arithmetic nobody can check.
        out["cpus_counted"] = n_cpus
        return out


_LIBBPF = None


def _libbpf():
    """
    libbpf, loaded once.

    A MISSING LIBRARY IS A NAMED REFUSAL. Measured: libbpf.so.1 is present on
    this host. On a host without it the honest answer is a sentence naming the
    package, not an ImportError out of a background thread.
    """
    global _LIBBPF
    if _LIBBPF is not None:
        return _LIBBPF
    for name in ("libbpf.so.1", "libbpf.so"):
        try:
            lib = ctypes.CDLL(name, use_errno=True)
            break
        except OSError:
            continue
    else:
        raise RuntimeError(
            "libbpf is not installed on this host. It is the library that "
            "loads a BPF object, and without it nothing here can work. "
            "Install it with: sudo apt-get install libbpf1  (the loader also "
            "needs the program to have been built; see ebpf/build.sh).")

    # PM-10, 2026-09-23. THE CAMERA CRASH-LOOPED FOR A NAME, NOT FOR A REASON.
    #
    # MEASURED on this host, before this was changed. The installed unit was
    # `enabled` and `failed`: five restarts, then "Start request repeated too
    # quickly", and every attempt printed
    #
    #     ERROR: /lib/x86_64-linux-gnu/libbpf.so.1: undefined symbol: bpf_get_error
    #
    # and then
    #
    #     ERROR: NOTHING WAS RECORDED. This is a failure to LOOK, which is not
    #     the same as a quiet machine.
    #
    # The message is ctypes' own AttributeError text, raised where this block
    # RESOLVES `lib.bpf_get_error` — a function the module never calls. Setting
    # restype/argtypes on it is where ctypes looks the symbol up, and libbpf
    # 1.3.0 exports `libbpf_get_error` and not the pre-1.0 alias, so the only
    # caller of the old name was this wiring. The loader's own comment thirty
    # lines below records exactly this measurement for the call SITE and the
    # wiring above it was missed.
    #
    # THE FIX: bind the getter that EXISTS, and leave the alias alone when the
    # library does not export it. A library's absent symbol must be a named
    # refusal when something needs it, never a crash while wiring up a name
    # nothing calls.
    if hasattr(lib, "libbpf_get_error"):
        lib.libbpf_get_error.restype = ctypes.c_long
        lib.libbpf_get_error.argtypes = [ctypes.c_void_p]
    if not hasattr(lib, "libbpf_get_error") and not hasattr(lib, "bpf_get_error"):
        raise RuntimeError(
            "this host's libbpf exports NEITHER libbpf_get_error nor "
            "bpf_get_error, so an error this loader needs to report would come "
            "back as a raw pointer with no sentence. That is not a state to "
            "run a kernel camera in. Install libbpf1 from your distribution.")
    lib.ring_buffer__poll.restype = ctypes.c_int
    lib.ring_buffer__poll.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ring_buffer__free.argtypes = [ctypes.c_void_p]
    _LIBBPF = lib
    return lib


# THE RUN LOOP

_PIDFILE = Path("/run/agental_sec_ebpf.pid")
_STOP = {"asked": False}


def _already_running() -> int | None:
    """
    The holder's pid, or None.

    TWO COPIES WOULD DOUBLE EVERY EVENT AND FIGHT OVER THE FILE, so this is a
    refusal rather than a warning. A stale pidfile (the pid is gone, or belongs
    to something else) is cleaned up and reported.
    """
    try:
        content = _PIDFILE.read_text().strip()
        pid = int(content)
    except (OSError, ValueError):
        return None
    if pid == os.getpid():
        return None
    try:
        os.kill(pid, 0)
    except OSError:
        return None
    # The pid exists; is it us?
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().decode(
            "utf-8", "replace")
        if "ebpf_monitor" not in cmdline:
            return None
    except OSError:
        return None
    return pid


def run(args) -> int:
    if os.geteuid() != 0:
        print(
            f"ERROR: this program must run as root, because loading a BPF "
            f"program on this host requires it (MEASURED: "
            f"kernel.unprivileged_bpf_disabled=2, perf_event_paranoid=4, and "
            f"/sys/kernel/tracing is mode 700).\n"
            f"ERROR: NOTHING WAS LOADED AND NOTHING WAS RECORDED. This is a "
            f"refusal, not an empty window.\n"
            f"ERROR: run it as: sudo python3 {Path(__file__).name} --out "
            f"{args.out}", file=sys.stderr)
        return 3

    support = check_support()
    if not support["ok"]:
        print("ERROR: this host cannot run the camera:", file=sys.stderr)
        for problem in support["problems"]:
            print(f"ERROR:   - {problem}", file=sys.stderr)
        print("ERROR: NOTHING WAS LOADED AND NOTHING WAS RECORDED.",
              file=sys.stderr)
        return 2

    holder = _already_running()
    if holder:
        print(
            f"ERROR: ebpf_monitor is ALREADY RUNNING as pid {holder}.\n"
            f"ERROR: Two copies would attach the same tracepoints twice and "
            f"double every event, so this one refuses.\n"
            f"ERROR: Stop the other one (kill {holder}) or use its output.",
            file=sys.stderr)
        return 4

    obj = Path(args.object) if args.object else (HERE / "ebpf_monitor.bpf.o")
    if not obj.exists():
        print(
            f"ERROR: {obj} does not exist, so there is nothing to load.\n"
            f"ERROR: Build it first: bash {HERE / 'build.sh'}\n"
            f"ERROR: NOTHING WAS LOADED AND NOTHING WAS RECORDED.",
            file=sys.stderr)
        return 5

    sink = EventSink(Path(args.out))
    ring = RingBuffer(obj)
    ring.sink = sink

    try:
        ring.load()
        ring.attach()
        ring.create_ring(ctypes)
    except Exception as e:                              # noqa: BLE001
        print(f"ERROR: {e}", file=sys.stderr)
        print("ERROR: NOTHING WAS RECORDED. This is a failure to LOOK, which "
              "is not the same as a quiet machine.", file=sys.stderr)
        sink.record_health(-1, -1, note=f"failed to start: {e}")
        sink.close()
        return 6

    _PIDFILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        _PIDFILE.write_text(str(os.getpid()))
    except OSError:
        pass

    # THE PIDFILE IS CLEARED WHEN THE PROCESS EXITS, INCLUDING WHEN IT DIES,
    # and that is not belt-and-braces: the run loop's own unlink only happens
    # when `finally` is reached, and a SIGKILL skips it entirely. A stale
    # pidfile whose pid has been REUSED by another process called "python3
    # .../ebpf_monitor.py" makes the next camera refuse to start -- the
    # operator's remedy then is to find and delete a file the owner has never heard
    # of. E-8. The guard's own reading of the file is unchanged and still
    # checks that the holder is a camera; this only makes the file's lifetime
    # the process's lifetime.
    import atexit

    def _clear_pidfile():
        try:
            if _PIDFILE.read_text().strip() == str(os.getpid()):
                _PIDFILE.unlink()
        except OSError:
            pass

    atexit.register(_clear_pidfile)

    def _stop(signum, frame):                           # noqa: ARG001
        _STOP["asked"] = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    lib = _libbpf()
    started = time.time()
    last_flush = started
    last_health = started
    last_size_check = 0.0
    rc = 0

    print(f"ebpf_monitor: attached to sched/sched_process_exec and "
          f"syscalls/sys_enter_connect; writing {args.out}", flush=True)

    try:
        while not _STOP["asked"]:
            # A 200 ms poll keeps the loop responsive to SIGTERM while costing
            # nothing measurable; the kernel writes into the ring regardless.
            n = lib.ring_buffer__poll(ring.ring, 200)
            if n < 0:
                print(f"ERROR: the ring buffer poll failed (libbpf error "
                      f"{n}). EVENTS ARE BEING LOST FROM HERE ON.", 
                      file=sys.stderr)
                rc = 7
                break

            now = time.time()
            if now - last_flush >= 1.0:
                # FLUSHED ONCE A SECOND RATHER THAN PER EVENT. The app reads
                # this file from another process; committing per event would
                # multiply the fsync count by the event rate for no reader
                # benefit, and batching is what makes a 10k/s exec storm (a
                # build) affordable.
                sink.commit()
                last_flush = now

            if now - last_size_check >= 60.0:
                sink.wipe_if_over(int(args.max_mb * 1024 * 1024))
                last_size_check = now

            if now - last_health >= 10.0:
                health = ring.dropped_counts()
                de, dc = health.get("exec"), health.get("connect")
                # E-7: what the READER could not decode, which used to be
                # written into an attribute and never read.
                sink.callback_errors = ring._cb_errors
                if health.get("error"):
                    # SAID OUT LOUD, once per health check, because a counter
                    # nobody can read must not be recorded as a zero.
                    print(f"ERROR: {health['error']}", file=sys.stderr)
                if ring._cb_error:
                    print(f"ERROR: {ring._cb_error} -- "
                          f"{ring._cb_errors} record(s) were NOT decoded and "
                          f"are NOT in the database. THIS IS LOSS, not a quiet "
                          f"moment.", file=sys.stderr)
                if (de or 0) > 0 or (dc or 0) > 0 or health.get("error") \
                        or ring._cb_errors:
                    sink.record_health(de if de is not None else -1,
                                       dc if dc is not None else -1,
                                       note=health.get("error"))
                last_health = now

            if args.duration and (now - started) >= args.duration:
                break
    finally:
        health = ring.dropped_counts()
        de, dc = health.get("exec"), health.get("connect")
        sink.callback_errors = ring._cb_errors
        sink.commit()
        sink.record_health(de if de is not None else -1,
                           dc if dc is not None else -1,
                           note=(health.get("error")
                                 or (ring._cb_error if ring._cb_error else None)
                                 or ("stopped cleanly" if rc == 0
                                     else f"stopped after an error (rc {rc})")))
        print(f"ebpf_monitor: wrote {sink.written} event(s); dropped "
              f"exec={de if de is not None else 'UNKNOWN'} "
              f"connect={dc if dc is not None else 'UNKNOWN'}; "
              f"undecodable={ring._cb_errors}.", flush=True)
        if health.get("error"):
            print(f"ERROR: {health['error']}", file=sys.stderr)
        if ring._cb_error:
            print(f"ERROR: {ring._cb_error}", file=sys.stderr)
        sink.close()
        try:
            _PIDFILE.unlink()
        except OSError:
            pass

    return rc


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="AgentalSec's kernel camera: exec and connect events into "
                    "a SQLite sidecar file. Runs as root.")
    p.add_argument("--out", default=None,
                   help="where to write events (required unless --check)")
    p.add_argument("--object", default=None,
                   help="the compiled .bpf.o (default: beside this file)")
    p.add_argument("--duration", type=float, default=0.0,
                   help="seconds to run; 0 means until SIGTERM")
    p.add_argument("--max-mb", type=float, default=250.0,
                   help="empty the event table when the file reaches this "
                        "size; 0 means never")
    p.add_argument("--json", action="store_true",
                   help="with --check, print the report as JSON")
    p.add_argument("--check", action="store_true",
                   help="report what this host supports and exit")
    args = p.parse_args(argv)

    if args.check:
        report = check_support()
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"euid            : {report['euid']}"
                  + ("  (root: enough to load)" if report["euid"] == 0
                     else "  (NOT root: loading will be refused)"))
            for key in ("kernel", "btf_present", "unprivileged_bpf_disabled",
                        "perf_event_paranoid", "lockdown", "object_present",
                        "tracepoints_present", "tracepoints_unverifiable"):
                if key in report:
                    print(f"{key:24}: {report[key]}")
            print(f"{'CAN RUN':24}: {report['ok']}")
            for problem in report["problems"]:
                print(f"  PROBLEM: {problem}")
            for note in report["notes"]:
                print(f"  note: {note}")
        return 0 if report["ok"] else 2

    if not args.out:
        p.error("--out is required unless --check is given")

    return run(args)


if __name__ == "__main__":
    sys.exit(main())
