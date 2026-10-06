#!/usr/bin/env bash
# /tmp/verify_port_fix.sh — proof for T4 Defect 7: the privileged launcher's
# "exited with code 1", whose cause was the dashboard port being held by a
# stale instance while the boot announced "AgentalSec ready." and then died
# inside waitress's own bind, with the failure reaching stderr only.
#
# WHAT THIS PROVES, in the same order the failure was found:
#   A. the occupant detector names the right thing (free / ours / someone else)
#   B. with the port held, the app refuses BY NAME, writes it to the durable
#      log, exits 1, and NEVER says "ready" and never prints a bare traceback
#   C. with the port free, the app still serves — the negative control, so
#      section B is not passing because the app simply stopped booting
#
# It runs everything as real uid 0 via `unshare -r` (no sudo, no password, no
# on-disk ownership change), on a COPY of the database, on the REAL port.
set -uo pipefail

# The tree, its owner and the owner's home are read at run time. A copy run
# from elsewhere names the tree with AGENTAL_ROOT.
ROOT="${AGENTAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
[[ -f "$ROOT/main.py" ]] || { echo "no main.py in $ROOT: set AGENTAL_ROOT to the tree" >&2; exit 2; }
OWNER="$(stat -c %U "$ROOT")"
OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"
USER_SITE="$OWNER_HOME/.local/lib/python$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')/site-packages"
LOGFILE="$ROOT/logs/agental_sec_linux.log"

KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1

TMP=$(mktemp -d /tmp/agental_port_verify.XXXXXX)
PORT=$(python3 -c "import json;print(json.load(open('$ROOT/config.json'))['flask']['port'])")
python3 "$ROOT/scripts/snapshot_db.py" "$ROOT/agental_sec.db" "$TMP/test.db"

PASS=0; FAIL=0
ok() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
no() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
chk() { if [[ "$2" == "1" ]]; then ok "$1"; else no "$1"; fi; }

echo "port under test : $PORT"
echo "scratch         : $TMP"
echo "database        : $TMP/test.db  (a copy; the real one is not touched)"
echo

OCC_PID=""
cleanup() {
    [[ -n "$OCC_PID" ]] && kill -TERM "$OCC_PID" 2>/dev/null
    chown -R "$OWNER:$OWNER" "$TMP" 2>/dev/null
    if [[ "$KEEP" == "1" ]]; then
        echo
        echo "kept: $TMP"
    else
        rm -rf "$TMP"
    fi
}
trap cleanup EXIT

# occupier
# A live LISTEN socket on the port. SO_REUSEADDR only — SO_REUSEPORT is what
# would let the app bind alongside it, and using it would make this test
# prove nothing.
occupy() {  # $1 = cwd, $2 = output file
    ( cd "$1" && exec python3 -c '
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(5)
print("OCCUPIER_READY", flush=True)
time.sleep(120)
' "$PORT" ) >"$2" 2>&1 &
    OCC_PID=$!
    for _ in $(seq 1 40); do
        grep -q OCCUPIER_READY "$2" 2>/dev/null && return 0
        sleep 0.25
    done
    return 1
}
release_occupier() {
    [[ -n "$OCC_PID" ]] || return 0
    kill -TERM "$OCC_PID" 2>/dev/null
    wait "$OCC_PID" 2>/dev/null
    OCC_PID=""
}

# probe
holder_json() {  # prints _port_holder's answer, in process, no boot
    ( cd "$ROOT" && HOME=$OWNER_HOME \
      PYTHONPATH="$USER_SITE:$ROOT" \
      python3 -c "
import json, sys
sys.path.insert(0, '$ROOT')
import main
print(json.dumps(main._port_holder('127.0.0.1', $PORT)))
" )
}

echo "A. the occupant detector"
H=$(holder_json)
echo "   free        : $H"
chk "a free port reads as free" "$([[ "$H" == *'"taken": false'* ]] && echo 1 || echo 0)"

occupy "$ROOT" "$TMP/occ_ours.out" || no "could not start the occupier"
H=$(holder_json)
echo "   ours        : $H"
chk "an AgentalSec-shaped holder is recognised as OURS" \
    "$([[ "$H" == *'"ours": true'* ]] && echo 1 || echo 0)"
chk "and it is named with its pid" "$([[ "$H" == *'"pid": '* ]] && echo 1 || echo 0)"
release_occupier

occupy /tmp "$TMP/occ_other.out" || no "could not start the foreign occupier"
H=$(holder_json)
echo "   someone else: $H"
chk "a foreign holder is taken but NOT ours" \
    "$([[ "$H" == *'"taken": true'* && "$H" == *'"ours": false'* ]] && echo 1 || echo 0)"

# B. the boot with the port held
echo
echo "B. full boot with the port held (this is the reported failure)"
LOG_LINES_BEFORE=$(wc -l < "$LOGFILE")
( setsid unshare -r bash -c "cd '$ROOT' && HOME=$OWNER_HOME USER=$OWNER \
    SUDO_USER=$OWNER PYTHONPATH='$USER_SITE:$ROOT' \
    AGENTALSEC_TEST_DB='$TMP/test.db' python3 main.py" \
    >"$TMP/busy.out" 2>&1 ) &
BOOT_PID=$!

# It has to get far enough to try the port, which is after the module table.
BINDS=0
for _ in $(seq 1 240); do
    grep -q 'is ALREADY IN USE\|is ALREADY RUNNING' "$TMP/busy.out" 2>/dev/null && BINDS=1 && break
    kill -0 "$BOOT_PID" 2>/dev/null || break
    sleep 1
done
chk "the app reached the port and refused it" "$BINDS"

wait "$BOOT_PID"; BOOT_RC=$?
chk "exit code is 1 (what the launcher reported)" "$([[ $BOOT_RC -eq 1 ]] && echo 1 || echo 0)"
chk "the refusal NAMES the holder" \
    "$(grep -q 'ALREADY IN USE\|ALREADY RUNNING' "$TMP/busy.out" && echo 1 || echo 0)"
chk "it never claimed to be ready" \
    "$(! grep -q 'AgentalSec ready' "$TMP/busy.out" && echo 1 || echo 0)"
chk "no bare Python traceback reaches the operator" \
    "$(! grep -q 'Traceback (most recent call last)' "$TMP/busy.out" && echo 1 || echo 0)"
chk "the failure is in the DURABLE log, not only the console" \
    "$(tail -n +$((LOG_LINES_BEFORE+1)) "$LOGFILE" | grep -q 'ALREADY IN USE\|ALREADY RUNNING' && echo 1 || echo 0)"
echo "   --- the operator's window said: ---"
sed -n '/ERROR: Port\|ERROR: AgentalSec is ALREADY/,$p' "$TMP/busy.out" | head -6 | sed 's/^/   /'

release_occupier
sleep 2

# C. negative control: the port free
echo
echo "C. negative control — same boot, port free"
LOG_LINES_BEFORE=$(wc -l < "$LOGFILE")
( setsid unshare -r bash -c "cd '$ROOT' && HOME=$OWNER_HOME USER=$OWNER \
    SUDO_USER=$OWNER PYTHONPATH='$USER_SITE:$ROOT' \
    AGENTALSEC_TEST_DB='$TMP/test.db' python3 main.py" \
    >"$TMP/free.out" 2>&1 ) &
BOOT_PID=$!

READY=0
for _ in $(seq 1 240); do
    if grep -q 'AgentalSec ready' "$TMP/free.out" 2>/dev/null; then READY=1; break; fi
    kill -0 "$BOOT_PID" 2>/dev/null || break
    sleep 1
done
chk "the app boots and announces ready when the port is free" "$READY"
LISTENING=0
ss -ltn | grep -q "127.0.0.1:$PORT" && LISTENING=1
chk "something is listening on the port" "$LISTENING"
chk "waitress reports it is serving on the socket it was given" \
    "$(grep -q "Serving on http://127.0.0.1:$PORT" "$TMP/free.out" && echo 1 || echo 0)"
chk "no traceback in a healthy boot" \
    "$(! grep -q 'Traceback (most recent call last)' "$TMP/free.out" && echo 1 || echo 0)"

kill -TERM -"$BOOT_PID" 2>/dev/null
for _ in $(seq 1 30); do
    kill -0 "$BOOT_PID" 2>/dev/null || break
    sleep 1
done
chk "Ctrl+C/SIGTERM still shuts down cleanly" \
    "$(grep -q 'AgentalSec stopped cleanly' "$TMP/free.out" && echo 1 || echo 0)"
chk "the port is free again after the shutdown" \
    "$(! ss -ltn | grep -q "127.0.0.1:$PORT" && echo 1 || echo 0)"

echo
echo "======================================================================"
echo "  $PASS passed, $FAIL failed"
[[ $FAIL -gt 0 ]] && { echo "  FAILED SECTIONS — read $TMP before it is removed"; KEEP=1; }
echo "======================================================================"
exit $(( FAIL > 0 ))
