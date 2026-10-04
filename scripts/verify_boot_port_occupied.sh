#!/usr/bin/env bash
# /tmp/verify_port_ours_root.sh — the "AgentalSec is ALREADY RUNNING" branch as
# the OPERATOR meets it: real uid 0, real /proc, real ss. The `unshare -r`
# harness in verify_port_fix.sh deliberately does NOT cover this, because a
# child user namespace is refused ptrace access to the holder and cannot name
# its pid — measured, not assumed (see the note in main._socket_inodes_for_port).
#
# RUN THIS AS ROOT:  sudo AGENTAL_ROOT=<tree> bash /tmp/verify_port_ours_root.sh
set -uo pipefail

# The tree, its owner and the owner's home are read at run time. A copy run
# from elsewhere names the tree with AGENTAL_ROOT.
ROOT="${AGENTAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
[[ -f "$ROOT/main.py" ]] || { echo "no main.py in $ROOT: set AGENTAL_ROOT to the tree" >&2; exit 2; }
OWNER="$(stat -c %U "$ROOT")"
OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"
USER_SITE="$OWNER_HOME/.local/lib/python$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')/site-packages"
LOGFILE="$ROOT/logs/agental_sec_linux.log"
TMP=$(mktemp -d /tmp/agental_port_ours_root.XXXXXX)
PORT=$(python3 -c "import json;print(json.load(open('$ROOT/config.json'))['flask']['port'])")
cp "$ROOT/agental_sec.db" "$TMP/test.db"
chown -R "$OWNER:$OWNER" "$TMP"

PASS=0; FAIL=0
ok() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
no() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
chk() { if [[ "$2" == "1" ]]; then ok "$1"; else no "$1"; fi; }

if [[ "$EUID" -ne 0 ]]; then
    echo "This one needs real root: sudo bash $0"
    exit 2
fi

echo "port under test : $PORT   (real root, real /proc)"
echo "database        : $TMP/test.db (a copy)"
echo

OCC_PID=""
cleanup() {
    [[ -n "$OCC_PID" ]] && kill -TERM "$OCC_PID" 2>/dev/null
    chown -R "$OWNER:$OWNER" "$TMP" 2>/dev/null
    echo "kept: $TMP"
}
trap cleanup EXIT

# The occupant: an AgentalSec-shaped listener — same interpreter, cwd set to
# the project root, which is exactly what a running copy of this app looks
# like from the outside.
( cd "$ROOT" && exec runuser -u "$OWNER" -- python3 -c '
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(5)
print("OCCUPIER_READY", flush=True)
time.sleep(180)
' "$PORT" ) >"$TMP/occ.out" 2>&1 &
OCC_PID=$!
for _ in $(seq 1 40); do
    grep -q OCCUPIER_READY "$TMP/occ.out" 2>/dev/null && break
    sleep 0.25
done
OCC_REAL=$(pgrep -u "$OWNER" -f "import socket, sys, time" | head -1)
echo "occupier: $OWNER's python, cwd $ROOT, listening on $PORT (pid $OCC_REAL)"

LOG_BEFORE=$(wc -l < "$LOGFILE")
( cd "$ROOT" && HOME=$OWNER_HOME USER=$OWNER SUDO_USER=$OWNER \
    PYTHONPATH="$USER_SITE:$ROOT" AGENTALSEC_TEST_DB="$TMP/test.db" \
    python3 main.py >"$TMP/busy.out" 2>&1 ) &
BOOT_PID=$!

SEEN=0
for _ in $(seq 1 240); do
    grep -q 'ALREADY RUNNING\|ALREADY IN USE' "$TMP/busy.out" 2>/dev/null && SEEN=1 && break
    kill -0 "$BOOT_PID" 2>/dev/null || break
    sleep 1
done
wait "$BOOT_PID"; RC=$?

chk "the app refused the port" "$SEEN"
chk "exit code 1" "$([[ $RC -eq 1 ]] && echo 1 || echo 0)"
chk "it says AGENTALSEC IS ALREADY RUNNING (not a generic collision)" \
    "$(grep -q 'AgentalSec is ALREADY RUNNING' "$TMP/busy.out" && echo 1 || echo 0)"
chk "it names the pid" \
    "$(grep -qE "pid [0-9]+" "$TMP/busy.out" && echo 1 || echo 0)"
chk "it tells the operator what to do instead" \
    "$(grep -q 'Stop button' "$TMP/busy.out" && echo 1 || echo 0)"
chk "nothing claimed to be ready" \
    "$(! grep -q 'AgentalSec ready' "$TMP/busy.out" && echo 1 || echo 0)"
chk "no bare Python traceback reaches the operator" \
    "$(! grep -q 'Traceback (most recent call last)' "$TMP/busy.out" && echo 1 || echo 0)"
chk "the same sentence is in the durable log" \
    "$(tail -n +$((LOG_BEFORE+1)) "$LOGFILE" | grep -q 'AgentalSec is ALREADY RUNNING' && echo 1 || echo 0)"

echo "   --- what the operator's terminal shows: ---"
sed -n '/ERROR: AgentalSec is ALREADY RUNNING/,+3p' "$TMP/busy.out" | sed 's/^/   /'

echo
echo "======================================================================"
echo "  $PASS passed, $FAIL failed"
echo "======================================================================"
exit $(( FAIL > 0 ))
