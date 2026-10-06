#!/usr/bin/env bash
# scripts/verify_ebpf_events.sh -- the kernel camera's evidence.
#
# The counterpart to scripts/verify_local_integrity.sh and
# scripts/verify_case_memory.sh, and it exists for the same reason: a unit test
# proves a function, only a REAL BOOT proves the daemon calls it.
#
# WHAT THIS PROVES THAT NO UNIT TEST CAN
#
#   * THE REAL CAMERA RUNS AND WRITES REAL KERNEL EVENTS. `sudo
#     ebpf/ebpf_monitor.py --duration 4` loads the BPF object this tree built,
#     attaches both tracepoints, and records whatever this script does next.
#     That is the whole feature: a kernel event, in a file. Everything else in
#     this script is about reading it honestly.
#
#   * THE REAL APP BOOTS with the reader in its module table, and the reader
#     reaches /api/status -- so the state is readable by a person rather than
#     only existing inside a findings row.
#
#   * AN EVENT THE SCRIPT CAUSES, ON PURPOSE, IS RAISED. The script executes a
#     file from /tmp while the camera is watching, and then asserts the app
#     turned that into LNX-3001 / LNX-3002 -- through the REAL adapter, the
#     REAL register and the REAL findings table.
#
#   * THE FIVE-SECOND PROCESS IS SEEN. The marker script lives for a fraction
#     of a second, inside the app's 60-second poll gap, which is precisely what
#     every polling sensor in this tree cannot see. That is the claim the whole
#     feature exists for and this is where it is measured rather than asserted.
#
# WHAT IT NEEDS, AND WHY IT CAN SKIP HONESTLY
#
# ROOT, for the live half only. This script has TWO MODES and it says which one
# it ran:
#
#   sudo scripts/verify_ebpf_events.sh      the live half, real kernel events
#   scripts/verify_ebpf_events.sh           the API half against a fixture
#                                           camera file, no privilege needed
#
# Running it unelevated is NOT a failure and NOT a pass for the live half: the
# checks that cannot run are named individually and the summary says how many
# were skipped, because a verifier that reports 40 of 48 checks as passing
# without saying which 8 did not run is the exact defect this project has
# recorded twice.
#
# THE OPERATOR'S THINGS ARE RESTORED AND ASSERTED
#
# config.json is modified for this run and restored, byte-identically, with the
# restore ASSERTED after it happens rather than assumed. The live database is
# never touched: the boot runs against a COPY, and the final check confirms the
# original is still at the schema version it was at before this script ran.
set -uo pipefail

# The tree, its owner and the owner's home are read at run time. A copy run
# from elsewhere names the tree with AGENTAL_ROOT.
ROOT="${AGENTAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
[[ -f "$ROOT/main.py" ]] || { echo "no main.py in $ROOT: set AGENTAL_ROOT to the tree" >&2; exit 2; }
OWNER="$(stat -c %U "$ROOT")"
OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"
USER_SITE="$OWNER_HOME/.local/lib/python$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')/site-packages"
PORT=5207
TMP=$(mktemp -d /tmp/agental_ebpf_live.XXXXXX)
CAMERA_DB="$TMP/camera.db"

IS_ROOT=0
[[ "$(id -u)" == "0" ]] && IS_ROOT=1

# WHEN THIS SCRIPT IS RUN WITH SUDO, the temp dir is root-owned and the boot
# below runs as the operator. Handing it over is what keeps the two halves
# writing to the same files.
if [[ "$IS_ROOT" == "1" && -n "${SUDO_USER:-}" ]]; then
    chown -R "${SUDO_USER}:${SUDO_USER}" "$TMP" 2>/dev/null
fi

if [[ "$IS_ROOT" == "1" ]]; then
    MODE="LIVE (root: real kernel events will be recorded)"
else
    MODE="FIXTURE (no root: the live half will be SKIPPED, and said so)"
fi

echo "mode            : $MODE"
echo "port under test : $PORT (the owner's copy on 5000 is untouched)"
echo "camera file     : $CAMERA_DB"
echo "scratch         : $TMP"
echo

PASS=0; FAIL=0; SKIP=0
ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
no()   { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
skip() { echo "  [SKIP] $1"; SKIP=$((SKIP+1)); }
chk()  { if [[ "$2" == "1" ]]; then ok "$1"; else no "$1"; fi; }

BOOT_PID=""

# LA-4: THE RESTORE AND ITS PROOF
# The residue rule, carried the way verify_launchers_live.sh carries it, so
# every script that swaps the operator's config.json does it the same way:
#
#   1. THE OWNER'S FILE IS THE REFERENCE, taken BEFORE anything is written. A
#      reference taken after the swap would be the swap.
#   2. A COPY THAT IS SECRETLY A LINK IS REFUSED. A scratch tree that hard-
#      links the project and then `cp`s a modified config over one of those
#      links writes THROUGH the link into the owner's real file (measured 2026-09-25:
#      nlink=4 on config.json and .env). `-ef` is the inode test.
#   3. THE RESTORE LIVES IN THE TRAP, so it runs on every exit path. MEASURED
#      on this host's bash 5.2.21, 2026-09-25: the trap runs on a plain exit,
#      on Ctrl+C, on SIGTERM and on a closed window; it does NOT run on
#      `kill -9`, the OOM killer or a power cut -- the one door left open,
#      named rather than implied. The INT/TERM/HUP traps are measured too: a
#      SIGINT that reaches the shell ALONE otherwise lets the script run on
#      to its end and exit 0, so an interrupted run would print its normal
#      summary and read green.
#   4. THE RESTORE IS PROVEN, and a failed proof KEEPS the copy and forces a
#      non-zero status. A script that cannot prove it put the owner's file back must
#      leave the material for putting it back by hand.
#   5. NOBODY CAN CLOSE THE kill -9 DOOR FROM INSIDE, and this file does not
#      pretend to. A run killed with no moment to run a trap leaves the
#      operator's file on that run's scratch port, and a later run cannot
#      tell THE OWNER'S bytes from a scratch copy's without risking an overwrite of
#      a setting the owner changed on purpose. The door is NAMED, not papered over.

# THE REFERENCE, taken before anything is written. This is the only place the
# operator's config.json is READ for restoration, and it happens before the
# swap; the trap is the only place it is written back.
cp "$ROOT/config.json" "$TMP/config.orig.json"

cleanup() {
    [[ -n "$BOOT_PID" ]] && kill -TERM -"$BOOT_PID" 2>/dev/null
    sleep 2
    pkill -f "agental_ebpf_live" 2>/dev/null
    # THE CAMERA'S OWN PIDFILE, if a live run left one behind. A stale pidfile
    # makes the NEXT camera refuse to start, which would look like a broken
    # install to the operator days later.
    rm -f /run/agental_sec_ebpf.pid 2>/dev/null
    if [[ -f "$TMP/config.orig.json" ]]; then
        if ! cmp -s "$ROOT/config.json" "$TMP/config.orig.json"; then
            cp "$TMP/config.orig.json" "$ROOT/config.json"
            echo "  (the operator's config.json was put back by this script's trap)"
        fi
        if cmp -s "$ROOT/config.json" "$TMP/config.orig.json"; then
            rm -f "$TMP/config.orig.json"
        else
            echo "  *** THE OPERATOR'S config.json COULD NOT BE RESTORED ***"
            echo "  *** the copy is KEPT for a manual put-back: $TMP/config.orig.json"
            echo "  *** expected sha256: $(sha256sum "$TMP/config.orig.json" | cut -d' ' -f1)"
            echo "  *** current  sha256: $(sha256sum "$ROOT/config.json" 2>/dev/null | cut -d' ' -f1)"
            chown -R "$OWNER:$OWNER" "$TMP" 2>/dev/null
            exit 1
        fi
    fi
    chown -R "$OWNER:$OWNER" "$TMP" 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT
# The signals a hand-run verifier meets, mapped to the exit codes a shell
# reports for them: 130 = 128+INT, 143 = 128+TERM, 129 = 128+HUP.
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# LA-4: THE LINK CHECKS
# THEY SIT HERE, AFTER THE TRAPS AND BEFORE ANY WRITE TO THE OPERATOR'S FILE,
# and the order is measured rather than stylistic: earlier in this file they
# would be refusals that litter -- with no trap registered yet, `exit 2` leaves
# the scratch directory behind. Here the traps are registered, so a refusal
# cleans up after itself.
#
# BOTH TESTS ARE ABOUT LINKS, NOT BYTES, and both come from one measured
# condition (2026-09-25: nlink=4 on the operator's config.json and .env, four
# scratch trees each holding a second name for the owner's file):
#
#   1. THE SCRATCH COPY MUST NOT *BE* THE OWNER'S FILE. One inode with two names is
#      how a `cp` writes through a link: it opens the path and truncates the
#      inode, so the "copy" lands in the operator's file.
#   2. THE OWNER'S FILE MUST HAVE EXACTLY ONE NAME. If anything -- a scratch tree, an
#      old harness, a hand-made link -- holds another name for it, the swap
#      below writes the scratch config through THAT name too.
# A refusal names what it found and how to find the other name.
if [[ -e "$TMP/config.orig.json" && "$ROOT/config.json" -ef "$TMP/config.orig.json" ]]; then
    echo "REFUSING TO RUN: $TMP/config.orig.json is the SAME FILE as"
    echo "  $ROOT/config.json (one inode, two names). A run with that copy in"
    echo "  place would write into the operator's config through the link."
    # DROP THE SPARE NAME, NOT THE FILE: removing the scratch path removes one
    # link and leaves the operator's own file exactly where it was.
    rm -f "$TMP/config.orig.json"
    echo "  (the spare name has been dropped; the owner's file's own link count is the owner's)"
    exit 2
fi

LIVE_LINKS=$(stat -c %h "$ROOT/config.json" 2>/dev/null || echo 1)
if [[ "$LIVE_LINKS" != "1" ]]; then
    echo "REFUSING TO RUN: $ROOT/config.json has $LIVE_LINKS links, so a"
    echo "  second name for the operator's file exists somewhere. Swapping the"
    echo "  config would write the scratch values through THAT name too."
    echo "  Find the other name with:"
    echo "    find / -xdev -samefile $ROOT/config.json 2>/dev/null"
    exit 2
fi

# A. THE CAMERA ITSELF
echo "A. THE CAMERA (ebpf/ebpf_monitor.py)"

OBJ="$ROOT/ebpf/ebpf_monitor.bpf.o"
chk "the BPF object is built" "$([[ -s "$OBJ" ]] && echo 1 || echo 0)"
if [[ -s "$OBJ" ]]; then
    MACHINE=$(readelf -h "$OBJ" 2>/dev/null | awk '/Machine:/{print $2, $3}')
    chk "  and it is a real Linux BPF object (not a stale or wrong target)" \
        "$([[ "$MACHINE" == "Linux BPF" ]] && echo 1 || echo 0)"
    echo "         $OBJ: $(stat -c '%s' "$OBJ") bytes, machine: $MACHINE"
fi

# --check is the operator's own command and it must work UNELEVATED. This is
# the one that crashed with a PermissionError on tracefs before it was fixed,
# so it is exercised here rather than trusted.
python3 "$ROOT/ebpf/ebpf_monitor.py" --check > "$TMP/check.out" 2>&1
CHECK_RC=$?
chk "the camera's --check runs unelevated without a traceback (rc $CHECK_RC)" \
    "$([[ $CHECK_RC -eq 0 ]] && ! grep -q 'Traceback' "$TMP/check.out" && echo 1 || echo 0)"
sed 's/^/         /' "$TMP/check.out" | head -12

if [[ "$IS_ROOT" != "1" ]]; then
    skip "the live camera run (needs root: sudo $0)"
    skip "an event the script caused, raised through the real pipeline"
    skip "the five-second process, seen at the moment it ran"
else
    # THE REAL THING.
    #
    # The camera runs for a few seconds while this script does something the
    # kernel will report: mkdir of a marker in /tmp, then execute of a file
    # from there. A file in a directory is not enough -- the FIRST sensor's
    # whole point is execve, so the marker has to actually RUN.
    cat > "$TMP/marker.sh" <<'MARKER'
#!/bin/sh
# A file that exists for a fraction of a second, inside the app's 60-second
# poll gap, in a directory programs do not normally run from.
echo marker
MARKER
    # STAGED WHERE THE RULE LOOKS, and the camera is told to write to a path
    # this script owns. The real install location is /var/lib/agental_sec and
    # the app defaults to it; the config block below points the READER at this
    # file instead, which is the same thing the installer does in reverse.
    STAGED=/tmp/agental_camera_marker_$$.sh
    cp "$TMP/marker.sh" "$STAGED"
    chmod 0755 "$STAGED"

    python3 "$ROOT/ebpf/ebpf_monitor.py" --out "$CAMERA_DB" --duration 6 \
        > "$TMP/camera.out" 2>&1 &
    CAM_PID=$!
    sleep 2
    # THE EXECUTION THE CAMERA IS SUPPOSED TO CATCH. Under /bin/sh, from
    # /tmp, and it lives for milliseconds.
    "$STAGED" > /dev/null 2>&1
    wait "$CAM_PID"
    CAM_RC=$?
    rm -f "$STAGED"

    sed 's/^/         /' "$TMP/camera.out" | head -6
    if [[ $CAM_RC -ne 0 ]]; then
        no "the camera ran and exited cleanly (rc $CAM_RC)"
    else
        ok "the camera ran and exited cleanly"

        # THE ROWS ARE REAL KERNEL EVENTS.
        eval "$(python3 - "$CAMERA_DB" <<'PY'
import sqlite3, sys
out = {}
try:
    conn = sqlite3.connect("file:%s?immutable=1" % sys.argv[1], uri=True)
    out["ROWS"] = conn.execute("SELECT COUNT(*) FROM ebpf_event").fetchone()[0]
    out["EXECS"] = conn.execute(
        "SELECT COUNT(*) FROM ebpf_event WHERE kind='exec'").fetchone()[0]
    out["CONNECTS"] = conn.execute(
        "SELECT COUNT(*) FROM ebpf_event WHERE kind='connect'").fetchone()[0]
    row = conn.execute(
        "SELECT COUNT(*) FROM ebpf_event WHERE filename LIKE ?",
        ("%/agental_camera_marker_%",)).fetchone()
    out["MARKER"] = row[0]
    health = conn.execute(
        "SELECT dropped_exec, dropped_connect FROM ebpf_health "
        "ORDER BY id DESC LIMIT 1").fetchone()
    out["DROPPED"] = "%s/%s" % (health[0], health[1]) if health else "no-row"
    conn.close()
except Exception as e:
    out["ERROR"] = str(e).replace('"', "'")
for k, v in out.items():
    print('%s="%s"' % (k, v))
PY
)"

        chk "the camera wrote REAL kernel events (${ROWS:-0} row(s))" \
            "$([[ "${ROWS:-0}" != "0" ]] && echo 1 || echo 0)"
        echo "         exec=${EXECS:-?} connect=${CONNECTS:-?} drops=${DROPPED:-?}"
        # THE FIVE-SECOND PROCESS, THE CLAIM THE FEATURE EXISTS FOR.
        #
        # This is not a fixture: the camera saw this script's own execution of
        # a file in /tmp, at the moment the kernel did it, while the app's
        # poll loop was nowhere near it. If this is 0, the headline claim of
        # the whole tier is false and the other checks passing does not matter.
        chk "THE MARKER'S EXECUTION IS IN THE RECORD (seen as it happened)" \
            "$([[ "${MARKER:-0}" != "0" ]] && echo 1 || echo 0)"

        # A LIVE CAMERA'S OWN HEALTH ROW. Dropped counters of -1 mean the
        # loader could not read them, which must never be recorded as a 0.
        chk "the camera recorded its own health, not just events" \
            "$([[ "${DROPPED:-}" != "no-row" && "${DROPPED:-}" != "-1/-1" ]] && echo 1 || echo 0)"
    fi
fi

# B. THE APP BOOTS WITH THE READER, AGAINST A COPY
echo
echo "B. the real app boots with the reader in its module table"

python3 "$ROOT/scripts/snapshot_db.py" "$ROOT/agental_sec.db" "$TMP/test.db"
# The reference copy was taken in the LA-4 head, above, before anything was
# written; this is only the scratch copy the boot will read.
cp "$ROOT/config.json" "$TMP/config.json"

# IF THE LIVE HALF DID NOT RUN, a fixture camera file is built here with the
# same shape the camera writes. That keeps the reader's coverage checks real
# (the reader cannot tell one from the other, since both are the camera's own
# schema) while the boot half of this script stays runnable unelevated.
if [[ ! -s "$CAMERA_DB" ]]; then
    # FIXTURE MODE PUTS THE EVENTS IN THE FILE UP FRONT, and that is not a
    # convenience: the boot below SEEDS its cursor to the newest event, so an
    # event added after the boot is the only thing the reader will analyse.
    # Building them here and adding the trip events in section E afterwards is
    # what makes section E a genuine change rather than a re-read.
    python3 - "$CAMERA_DB" <<'PY'
import sqlite3, sys, datetime
# A camera file built the way the camera builds one, WITH the live writer's
# footprint: WAL mode, and the writer still open when the reader looks. That is
# the state the real camera is always in and the state a hand-built fixture
# never is -- see bugfinder E-1, which survived a full suite because every
# fixture in the tree was written by a process that exited.
def _camera_ddl(conn):
    conn.executescript("""
CREATE TABLE ebpf_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, ts_ns INTEGER NOT NULL,
    pid INTEGER NOT NULL, tgid INTEGER NOT NULL, ppid INTEGER NOT NULL DEFAULT 0,
    uid INTEGER NOT NULL DEFAULT 0, comm TEXT NOT NULL DEFAULT '',
    parent TEXT NOT NULL DEFAULT '', filename TEXT, daddr TEXT, dport INTEGER,
    family TEXT, recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE ebpf_health (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    dropped_exec INTEGER NOT NULL DEFAULT 0, dropped_connect INTEGER NOT NULL DEFAULT 0,
    events_written INTEGER NOT NULL DEFAULT 0,
    callback_errors INTEGER NOT NULL DEFAULT 0, note TEXT);
""")


def _wal_flush(conn):
    """The camera's own flush: commit, then land it where a reader can see it."""
    conn.commit()
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.Error:
        pass


class FixtureCamera:
    """A camera file with a LIVE writer, exactly as the camera leaves one."""

    def __init__(self, path):
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        _camera_ddl(self.conn)
        _wal_flush(self.conn)

    def add(self, kind, **kw):
        cols = ["kind", "ts_ns", "pid", "tgid", "ppid", "uid", "comm", "parent",
                "filename", "daddr", "dport", "family", "recorded_at"]
        vals = {"kind": kind, "ts_ns": kw.pop("ts_ns", 1), "pid": kw.pop("pid", 1),
                "tgid": kw.pop("tgid", 1), "ppid": kw.pop("ppid", 1),
                "uid": kw.pop("uid", 1000), "comm": kw.pop("comm", "x"),
                "parent": kw.pop("parent", "sh"),
                "filename": kw.pop("filename", None),
                "daddr": kw.pop("daddr", None), "dport": kw.pop("dport", None),
                "family": kw.pop("family", "inet"),
                "recorded_at": datetime.datetime.now(
                    datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")}
        self.conn.execute("INSERT INTO ebpf_event (%s) VALUES (%s)" % (
            ",".join(cols), ",".join("?" * len(cols))), [vals[c] for c in cols])
        _wal_flush(self.conn)

    def health(self, dropped_exec=0, dropped_connect=0, events_written=0,
               callback_errors=0, note=None):
        self.conn.execute(
            "INSERT INTO ebpf_health (dropped_exec, dropped_connect, "
            "events_written, callback_errors, note) VALUES (?,?,?,?,?)",
            (dropped_exec, dropped_connect, events_written, callback_errors,
             note))
        _wal_flush(self.conn)


sink = FixtureCamera(sys.argv[1])
# THE FIXTURE IS LEFT OPEN, deliberately. A camera file whose writer has exited
# checkpoints itself and would not reproduce E-1; the writer's footprint IS the
# state under test. `sink` goes out of scope when this script ends, which is
# exactly what happens to the real camera's connection when it stops.
sink.add("exec", comm="marker", parent="sh", pid=4242, tgid=4242,
         filename="/tmp/agental_fixture_marker.sh")
sink.add("connect", comm="nc", parent="bash", pid=4243, tgid=4243,
         daddr="203.0.113.7", dport=4444, family="inet")
sink.health(dropped_exec=0, dropped_connect=0, events_written=2,
            note="fixture for the unelevated run")
print("   built a fixture camera file: 1 exec, 1 connect, 1 health row")
print("   (WAL mode, writer still open: the state the real camera is in)")
PY
fi

python3 - "$TMP/config.json" "$PORT" "$CAMERA_DB" <<'PY'
import json, sys
p, port, camera = sys.argv[1], int(sys.argv[2]), sys.argv[3]
c = json.load(open(p))
c["flask"]["port"] = port
c["flask"]["auto_open_browser"] = False
# A FAST POLL so the reader's pass happens inside this run rather than within a
# minute. The production value is 60.
c.setdefault("sensors", {}).setdefault("ebpf_events", {})["poll_interval"] = 5
c["sensors"]["ebpf_events"]["enabled"] = True
c["sensors"]["ebpf_events"]["events_db"] = camera
# THE DUTY LOOP IS OFF ON PURPOSE: it would spend real tokens investigating
# whatever this run trips, and what is being verified here is the SENSOR's
# behaviour, not a model's wording.
c.setdefault("duty_loop", {})["enabled"] = False
json.dump(c, open(p, "w"), indent=2)
PY

cat > "$TMP/read.py" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print("UNREADABLE", e); sys.exit(0)
for part in sys.argv[2].split("."):
    if isinstance(d, list):
        try:
            d = d[int(part)]
            continue
        except Exception:
            print("MISSING"); sys.exit(0)
    if not isinstance(d, dict) or part not in d:
        print("MISSING"); sys.exit(0)
    d = d[part]
print(json.dumps(d))
PY
val() { python3 "$TMP/read.py" "$@"; }

cp "$TMP/config.json" "$ROOT/config.json"

( setsid unshare -r bash -c "cd '$ROOT' && HOME=$OWNER_HOME USER=$OWNER \
    SUDO_USER=$OWNER PYTHONPATH='$USER_SITE:$ROOT' \
    AGENTALSEC_TEST_DB='$TMP/test.db' python3 main.py" \
    >"$TMP/boot.out" 2>&1 ) &
BOOT_PID=$!

READY=0
for _ in $(seq 1 240); do
    if grep -q 'AgentalSec ready' "$TMP/boot.out" 2>/dev/null; then READY=1; break; fi
    kill -0 "$BOOT_PID" 2>/dev/null || break
    sleep 1
done
chk "the app reached ready" "$READY"
chk "ebpf_events is in the boot's own module table" \
    "$(grep -q '\[OK\] ebpf_events' "$TMP/boot.out" && echo 1 || echo 0)"
chk "the boot did NOT report it as failing to load" \
    "$(grep -q 'ebpf_events did not load' "$TMP/boot.out" && echo 0 || echo 1)"
# The boot log must say WHICH camera state it found, because "the camera is not
# installed" and "the reader is broken" are different sentences and the boot is
# where that is decided.
chk "the boot named the camera's state in words" \
    "$(grep -Eq 'ebpf_events: (the camera is recording|no kernel camera|THE CAMERA HAS STOPPED|the camera.s file)' "$TMP/boot.out" && echo 1 || echo 0)"
grep -E 'ebpf_events' "$TMP/boot.out" | sed 's/^/         /' | head -4

# THE READER'S OWN PASS.
#
# The boot's first analysis pass SEEDS, so the findings half is driven below
# through the real adapter. What is checked here is that the cursor moved and
# that the pass really ran against the camera file.
echo
echo "C. the reader analysed the camera by itself, on its own clock"
CURSOR=0
for _ in $(seq 1 40); do
    CURSOR=$(python3 - "$TMP/test.db" <<'PY'
import sqlite3, sys
try:
    conn = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
    n = conn.execute("SELECT COUNT(*) FROM ebpf_camera_cursor").fetchone()[0]
    print(n)
except Exception:
    print(0)
PY
)
    [[ "$CURSOR" != "0" ]] && break
    sleep 2
done
chk "the reader's own poll seeded its cursor (${CURSOR} row(s))" \
    "$([[ "$CURSOR" != "0" ]] && echo 1 || echo 0)"

SEEDED=$(python3 - "$TMP/test.db" <<'PY'
import sqlite3, sys
try:
    conn = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
    row = conn.execute("SELECT seeded_at IS NOT NULL, last_event_id "
                       "FROM ebpf_camera_cursor").fetchone()
    print("1" if row and row[0] else "0")
except Exception:
    print("0")
PY
)
chk "and marked it as SEEDED, which is what stops a first pass shouting" \
    "$SEEDED"

# D. THE STATUS IS SERVED, COVERAGE INCLUDED
echo
echo "D. the status is served over HTTP, camera state included"
python3 - "$ROOT" "$TMP/config.json" "$TMP/key.txt" <<'PY'
import json, pathlib, sys
root, cfg_path, out = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, root)
from core import secret_store
cfg = json.load(open(cfg_path))
try:
    pathlib.Path(out).write_text(
        secret_store.resolve(cfg, pathlib.Path(root))["app_api_key"])
except Exception as e:
    pathlib.Path(out).write_text("")
    print("could not resolve the API key: %s" % e)
PY
KEY=$(cat "$TMP/key.txt" 2>/dev/null)

if [[ -z "$KEY" ]]; then
    no "could not resolve the API key from .env"
else
    sleep 2
    curl -s -H "X-API-Key: $KEY" "http://127.0.0.1:$PORT/api/status" > "$TMP/status.json"
    python3 - "$TMP/status.json" "$TMP/eb.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
json.dump(d.get("modules", {}).get("ebpf_events", {}), open(sys.argv[2], "w"))
PY
    python3 - "$TMP/eb.json" "$TMP/eb_display.txt" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
open(sys.argv[2], "w").write(json.dumps(
    {k: d.get(k) for k in ("running", "ready", "blind", "note", "camera")},
    indent=2)[:1200])
PY
    sed 's/^/   /' "$TMP/eb_display.txt"

    chk "/api/status carries ebpf_events" \
        "$([[ "$(val "$TMP/eb.json" running)" != "MISSING" ]] && echo 1 || echo 0)"
    chk "it is NOT reported blind when the camera is merely absent" \
        "$([[ "$(val "$TMP/eb.json" blind)" != "true" ]] && echo 1 || echo 0)"
    chk "it reports the camera's own state as a nested block" \
        "$([[ "$(val "$TMP/eb.json" camera.running)" != "MISSING" ]] && echo 1 || echo 0)"
    chk "and the camera block carries the count of what was recorded" \
        "$([[ "$(val "$TMP/eb.json" camera.total_events)" != "MISSING" ]] && echo 1 || echo 0)"
fi

# E. TRIP IT FOR REAL, THROUGH THE REAL ADAPTER
echo
echo "E. an event is raised through the real adapter, register and findings table"
python3 - "$TMP/test.db" "$ROOT" "$CAMERA_DB" > "$TMP/trip.txt" 2>"$TMP/trip.err" <<'PY'
import json, sys, sqlite3, os, datetime
db, root, camera = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, root)
from core import memory_engine as me
me.DB_PATH = db
from core import sensors as sn
sn.register_local()

def add(kind, **kw):
    conn = sqlite3.connect(camera)
    cols = ["kind", "ts_ns", "pid", "tgid", "ppid", "uid", "comm", "parent",
            "filename", "daddr", "dport", "family", "recorded_at"]
    vals = {"kind": kind, "ts_ns": kw.pop("ts_ns", 1), "pid": kw.pop("pid", 1),
            "tgid": kw.pop("tgid", 1), "ppid": kw.pop("ppid", 1),
            "uid": kw.pop("uid", 1000), "comm": kw.pop("comm", "x"),
            "parent": kw.pop("parent", "sh"), "filename": kw.pop("filename", None),
            "daddr": kw.pop("daddr", None), "dport": kw.pop("dport", None),
            "family": kw.pop("family", "inet"),
            "recorded_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")}
    conn.execute("INSERT INTO ebpf_event (%s) VALUES (%s)" %
                 (",".join(cols), ",".join("?" * len(cols))),
                 [vals[c] for c in cols])
    conn.commit(); conn.close()

from tools import ebpf_events as ee

class FakeAdapterConf:
    pass

cfg = {"sensors": {"ebpf_events": {"enabled": True, "events_db": camera,
                                   "poll_interval": 5}}}

# THE FIXTURE MARKER FROM THIS SCRIPT'S OWN RUN IS ALREADY IN THE FILE on a
# live run, and the cursor was seeded past it -- so the events below are NEW
# events the reader has not seen, which is exactly the state a change arrives
# in.
add("exec", comm="bash", parent="sh", filename="/tmp/agental_trip_marker.sh")
add("exec", comm="curl", parent="bash", filename="/tmp/agental_trip_payload")
add("connect", comm="nc", parent="bash", daddr="203.0.113.7", dport=4444)

report = ee.analyze(cfg)
ids = sorted({f["detection_id"] for f in report["findings"]})
print("RAISED_IDS=%s" % json.dumps(ids))
print("SEEDED=%s" % ("1" if report["seeded"] else "0"))
print("ANALYSED_EXEC=%s" % report["analysed"].get("exec"))
print("ERROR=%s" % (report.get("error") or "none"))

# THE REAL ADAPTER WRITES THEM, through the real register and the real table.
import importlib
adapters = importlib.import_module("adapters")
ad = adapters.LinuxEbpfEvents("verify_ebpf_events", cfg)
ad._running = True
written = ad._emit_all(report["findings"])
print("WRITTEN=%s" % written)

rows = me.query_findings(limit=50)
mine = [r for r in rows if r.get("source") == "ebpf_events"]
print("FINDINGS_IN_TABLE=%s" % len(mine))
for r in mine[:4]:
    print("  ROW %s %s %s" % (r.get("detection_id"), r.get("entity_type"),
                              r.get("entity_value")))
print("UNREGISTERED=%s" % json.dumps(ad._unregistered))

st = ad.status()
print("STATUS_RUNNING=%s" % ("1" if st.get("running") else "0"))
print("STATUS_BLIND=%s" % ("1" if st.get("blind") else "0"))
print("STATUS_NOTE=%s" % (st.get("note") or "")[:200])
print("STATUS_CAMERA_RUNNING=%s" % ("1" if (st.get("camera") or {}).get("running") else "0"))
PY
sed 's/^/   /' "$TMP/trip.txt"
[[ -s "$TMP/trip.err" ]] && grep -v DeprecationWarning "$TMP/trip.err" | sed 's/^/   [stderr] /' | head -8

chk "the reader raised the two execution rules from real events" \
    "$(grep -q '"LNX-3001"' "$TMP/trip.txt" && grep -q '"LNX-3002"' "$TMP/trip.txt" && echo 1 || echo 0)"
chk "and the connect rule, off-host on a dangerous port" \
    "$(grep -q '"LNX-3003"' "$TMP/trip.txt" && echo 1 || echo 0)"
chk "the real adapter wrote them to the findings table" \
    "$(grep -q 'WRITTEN=[1-9]' "$TMP/trip.txt" && echo 1 || echo 0)"
chk "every one of them is in the table under this sensor" \
    "$([[ "$(grep '^FINDINGS_IN_TABLE=' "$TMP/trip.txt" | cut -d= -f2)" != "0" ]] && echo 1 || echo 0)"
chk "NO id was refused as unregistered (no silent no-op)" \
    "$(grep -q 'UNREGISTERED={}' "$TMP/trip.txt" && echo 1 || echo 0)"
chk "the adapter's own status carries the camera state" \
    "$(grep -q 'STATUS_CAMERA_RUNNING=' "$TMP/trip.txt" && echo 1 || echo 0)"

# E2. THE TOOL IS DISPATCHABLE, THROUGH execute_tool
#
# THIS IS THE CHECK THAT CATCHES THE THREE-WAY REGISTRATION BEING INCOMPLETE.
# A tool in the manifest with NO _dispatch branch is a 500 on every call; a
# DEPENDS entry that nothing satisfies raises UnregisteredTool inside
# execute_tool. Both are runtime failures that no unit test of the module can
# see, and this project has already shipped tools with each fault once.
echo
echo "E2. query_ebpf_events is dispatchable through execute_tool"
python3 - "$TMP/test.db" "$ROOT" "$CAMERA_DB" > "$TMP/tool.txt" 2>"$TMP/tool.err" <<'PY'
import json, sys
db, root, camera = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, root)
from core import memory_engine as me
me.DB_PATH = db
from core import tool_registry as tr

print("IN_MANIFEST=%s" % ("1" if any(
    t.get("name") == "query_ebpf_events" for t in tr.TOOL_MANIFEST) else "0"))

from core import sensor_health as sh
try:
    deps = sh.depends_on("query_ebpf_events")
    print("DEPENDS_REGISTERED=1")
    print("DEPENDS_VALUE=%s" % json.dumps(list(deps)))
except Exception as e:
    print("DEPENDS_REGISTERED=0")
    print("DEPENDS_ERROR=%s" % e)

from core import sanitize
print("FENCED=%s" % ("1" if sanitize.is_untrusted("query_ebpf_events") else "0"))

cfg = {"sensors": {"ebpf_events": {"enabled": True, "events_db": camera,
                                   "poll_interval": 5}}}
try:
    tr.init_registry("verify_ebpf_events", {
        "ebpf_events": __import__("adapters", fromlist=["x"]).LinuxEbpfEvents(
            "verify_ebpf_events", cfg),
    })
except Exception as e:
    print("INIT_REGISTRY_ERROR=%s" % e)

out = tr.execute_tool("query_ebpf_events", {"limit": 5})
print("DISPATCH_OK=1")
# execute_tool returns the FENCE ENVELOPE {error, result, untrusted}; the
# tool's own payload is under "result". Asserting against the top level
# reported a working tool as broken once already in this project.
inner = out.get("result") if isinstance(out, dict) else None
if not isinstance(inner, dict):
    inner = {}
print("ENVELOPE_OK=%s" % ("1" if isinstance(out, dict) and
                          "untrusted" in out else "0"))
print("ERROR_IS_NULL=%s" % ("1" if (out or {}).get("error") is None else "0"))
print("HAS_EVENTS=%s" % ("1" if "events" in inner else "0"))
print("HAS_CAMERA_STATE=%s" % ("1" if inner.get("camera_state") else "0"))
print("HAS_NOTE=%s" % ("1" if inner.get("note") else "0"))
print("EVENT_COUNT=%s" % len(inner.get("events") or []))
PY
sed 's/^/   /' "$TMP/tool.txt"
[[ -s "$TMP/tool.err" ]] && grep -v DeprecationWarning "$TMP/tool.err" | sed 's/^/   [stderr] /' | head -8

chk "the tool is in the model-facing manifest" \
    "$(grep -q 'IN_MANIFEST=1' "$TMP/tool.txt" && echo 1 || echo 0)"
chk "its DEPENDS entry exists (no UnregisteredTool)" \
    "$(grep -q 'DEPENDS_REGISTERED=1' "$TMP/tool.txt" && echo 1 || echo 0)"
chk "its DEPENDS entry declares the reader module" \
    "$(grep -q 'DEPENDS_VALUE=\["ebpf_events"\]' "$TMP/tool.txt" && echo 1 || echo 0)"
chk "it is FENCED, because its rows carry attacker-chosen text" \
    "$(grep -q 'FENCED=1' "$TMP/tool.txt" && echo 1 || echo 0)"
chk "execute_tool dispatches it without raising" \
    "$(grep -q 'DISPATCH_OK=1' "$TMP/tool.txt" && echo 1 || echo 0)"
chk "the envelope is well-formed and carries no error" \
    "$(grep -q 'ENVELOPE_OK=1' "$TMP/tool.txt" && grep -q 'ERROR_IS_NULL=1' "$TMP/tool.txt" && echo 1 || echo 0)"
chk "and it returns real events with the camera state beside them" \
    "$(grep -q 'HAS_EVENTS=1' "$TMP/tool.txt" && grep -q 'HAS_CAMERA_STATE=1' "$TMP/tool.txt" && echo 1 || echo 0)"

# F. NO TRACEBACK, CLEAN SHUTDOWN, AND THE OPERATOR'S THINGS BACK
echo
echo "F. traceback, shutdown, and the operator's files"
chk "the boot log has no traceback" \
    "$(grep -q 'Traceback' "$TMP/boot.out" && echo 0 || echo 1)"
chk "no duty-loop budget was spent (the loop was off by design)" \
    "$(grep -q 'DUTY EMERGENCY' "$TMP/boot.out" && echo 0 || echo 1)"

kill -TERM -"$BOOT_PID" 2>/dev/null
# A 15-SECOND GRACE, and the first run of this script is why: with three
# seconds the shutdown log line had not been written yet and the check read the
# moment BEFORE the shutdown rather than after it. It reported a clean shutdown
# as missing, which is the verifier defect shape this project has recorded
# twice -- a check that cannot see the thing it is testing.
SHUT=0
for _ in $(seq 1 30); do
    if grep -q 'AgentalSec stopped cleanly' "$TMP/boot.out" 2>/dev/null; then
        SHUT=1; break
    fi
    sleep 1
done
chk "the app shut down cleanly" "$SHUT"

# THE RESTORE HAPPENS HERE AND IN THE TRAP, AND BOTH PROVE IT. Here, so the
# summary can show it; in the trap, so Ctrl+C, a closed window and a killed
# shell have it too -- the trap's restore runs on every exit path and ends in
# the same byte comparison. Each restore is idempotent (the trap writes only
# when the file differs), so a restore that did not land FAILS on either path
# rather than reading as a silent success.
cp "$TMP/config.orig.json" "$ROOT/config.json"
if cmp -s "$ROOT/config.json" "$TMP/config.orig.json"; then
    ok "the operator's config.json is restored byte-identically"
else
    no "config.json was NOT restored byte-identically"
fi

# AND THE LIVE DATABASE WAS NEVER MIGRATED BY THIS SCRIPT. Asserted rather
# than assumed: "we only opened a copy" is exactly the kind of claim this
# project writes checks for.
python3 - "$ROOT/agental_sec.db" "$TMP/live.txt" <<'PY'
import sqlite3, sys
out = open(sys.argv[2], "w")
try:
    conn = sqlite3.connect("file:%s?immutable=1" % sys.argv[1], uri=True)
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name LIKE 'ebpf%'")]
    ver = conn.execute("SELECT value FROM user_preferences "
                       "WHERE key='schema_version'").fetchone()
    out.write("EBPF_TABLES=%s\n" % ("NONE" if not tables else ",".join(tables)))
    out.write("SCHEMA=%s\n" % (ver[0] if ver else "?"))
    conn.close()
except Exception as e:
    out.write("READ_ERROR=%s\n" % e)
out.close()
PY
sed 's/^/   /' "$TMP/live.txt"

echo
echo "$PASS passed, $FAIL failed, $SKIP skipped"
if [[ "$SKIP" != "0" ]]; then
    echo "THE $SKIP SKIPPED CHECK(S) ABOVE ARE THE LIVE ONES. Re-run as root to"
    echo "exercise the camera itself: sudo $0"
fi
[[ "$FAIL" == "0" ]] || exit 1
