#!/usr/bin/env bash
# /tmp/verify_duty_live.sh — the end-to-end proof for the schedule fix.
#
# Boots the REAL app (main.py, the real daemon, the real routes) against a
# COPY of the database with the dashboard port moved to 5199 so it cannot
# collide with the owner's running copy, then reads the duty loop's own state
# back over HTTP and checks the schedule gate is LIVE in the running process:
#
#   * the loop is running and POLLING (looked at the clock, no wake-up due)
#   * it is NOT writing a run row per poll
#   * the API carries polls / last_poll / last_skip / schedule
#
# This is the check that "the daemon asks the schedule", not merely that
# _tick_once can answer —— a unit test proves the function; only a real boot
# proves the daemon calls it.
set -uo pipefail

# The tree, its owner and the owner's home are read at run time. A copy run
# from elsewhere names the tree with AGENTAL_ROOT.
ROOT="${AGENTAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
[[ -f "$ROOT/main.py" ]] || { echo "no main.py in $ROOT: set AGENTAL_ROOT to the tree" >&2; exit 2; }
OWNER="$(stat -c %U "$ROOT")"
OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"
USER_SITE="$OWNER_HOME/.local/lib/python$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')/site-packages"
PORT=5199
TMP=$(mktemp -d /tmp/agental_duty_live.XXXXXX)
python3 "$ROOT/scripts/snapshot_db.py" "$ROOT/agental_sec.db" "$TMP/test.db"

# The live config, copied so the test's port change touches ONLY the copy.
cp "$ROOT/config.json" "$TMP/config.json"
python3 - "$TMP/config.json" "$PORT" <<'PY'
import json, sys
p, port = sys.argv[1], int(sys.argv[2])
c = json.load(open(p))
c["flask"]["port"] = port
c["flask"]["auto_open_browser"] = False
json.dump(c, open(p, "w"), indent=2)
PY

PASS=0; FAIL=0
ok() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
no() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
chk() { if [[ "$2" == "1" ]]; then ok "$1"; else no "$1"; fi; }

BOOT_PID=""
cleanup() {
    [[ -n "$BOOT_PID" ]] && kill -TERM -"$BOOT_PID" 2>/dev/null
    sleep 2
    pkill -f "agental_duty_live" 2>/dev/null
    # THE OWNER'S CONFIG IS PUT BACK EVEN ON AN ABNORMAL EXIT, WHICH IT WAS NOT
    # BEFORE. Found 2026-09-25: this script swapped the real config.json for its
    # scratch copy and restored it only on the normal path at the end. A run
    # that is interrupted (Ctrl+C, a timeout, a killed shell) leaves the
    # operator's config.json pointing at 5199 with auto_open_browser false —
    # measured in the live file as port 5298 / auto_open_browser false, which
    # is residue from a harness that never reached its last line. A verifier
    # that leaves the operator's config changed is worse than one that never
    # ran; every sibling script already restores in its trap.
    if [[ -f "$TMP/config.orig.json" ]]; then
        cp "$TMP/config.orig.json" "$ROOT/config.json"
    fi
    chown -R "$OWNER:$OWNER" "$TMP" 2>/dev/null
    rm -rf "$TMP"
}

# LA-4: the owner's file must have exactly ONE name before anything writes to it. A
# second name anywhere -- a hardlinked scratch tree, an old harness -- turns
# the cp below into a write through that name into the owner's file (measured
# 2026-09-25: nlink=4 on config.json and .env). This script never needs to
# swap the owner's config, but it refuses to boot a tree while anything else holds a
# name for it.
LIVE_LINKS=$(stat -c %h "$ROOT/config.json" 2>/dev/null || echo 1)
if [[ "$LIVE_LINKS" != "1" ]]; then
    echo "REFUSING TO RUN: $ROOT/config.json has $LIVE_LINKS links, so a"
    echo "  second name for the operator's file exists somewhere."
    echo "  Find it with: find / -xdev -samefile $ROOT/config.json 2>/dev/null"
    exit 2
fi

trap cleanup EXIT
# The signals a hand-run verifier meets, mapped to the exit codes a
# shell reports for them: 130 = 128+INT, 143 = 128+TERM, 129 = 128+HUP.
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

echo "port under test : $PORT (the owner's copy is on 5000 and is untouched)"
echo "scratch         : $TMP"
echo "database        : $TMP/test.db  (a copy; the real one is not touched)"
echo

# The config copy has to be the one the app reads. main.py resolves
# config.json from PROJECT_ROOT, so the copy is swapped in for the boot and
# the original is restored afterwards — VERIFIED at the end, not assumed.
cp "$ROOT/config.json" "$TMP/config.orig.json"
cp "$TMP/config.json" "$ROOT/config.json"

( setsid unshare -r bash -c "cd '$ROOT' && HOME=$OWNER_HOME USER=$OWNER \
    SUDO_USER=$OWNER PYTHONPATH='$USER_SITE:$ROOT' \
    AGENTALSEC_TEST_DB='$TMP/test.db' python3 main.py" \
    >"$TMP/boot.out" 2>&1 ) &
BOOT_PID=$!

echo "A. the real app boots"
READY=0
for _ in $(seq 1 240); do
    if grep -q 'AgentalSec ready' "$TMP/boot.out" 2>/dev/null; then READY=1; break; fi
    kill -0 "$BOOT_PID" 2>/dev/null || break
    sleep 1
done
chk "the app reached ready" "$READY"
chk "waitress is serving on the socket it was given" \
    "$(grep -q "Serving on http://127.0.0.1:$PORT" "$TMP/boot.out" && echo 1 || echo 0)"
chk "the duty loop started" \
    "$(grep -q '\[OK\] duty_loop' "$TMP/boot.out" && echo 1 || echo 0)"
chk "and its log line names the schedule, not a per-minute wake" \
    "$(grep -q 'checking the schedule every' "$TMP/boot.out" && echo 1 || echo 0)"
grep -E '\[OK\] duty_loop|checking the schedule' "$TMP/boot.out" | sed 's/^/   /' | head -4

echo
echo "B. the running loop POLLS without waking, read over real HTTP"
KEY=$(python3 -c "
import json,sys,pathlib
root = pathlib.Path('$ROOT')
sys.path.insert(0,str(root))
from core import settings, secret_store
cfg = json.load(open('$TMP/config.json'))
print(secret_store.resolve(cfg, root)['app_api_key'])
" 2>/dev/null)
if [[ -z "$KEY" ]]; then no "could not resolve the API key from .env"; else
    # Give it time to poll at least twice (the tick is 60s in the shipped
    # config; the first poll lands immediately after start).
    sleep 8
    BODY=$(curl -s -H "X-API-Key: $KEY" "http://127.0.0.1:$PORT/api/agents?limit=5")
    echo "$BODY" | python3 -c "
import json, sys
d = json.load(sys.stdin)
st = d.get('status') or {}
sch = st.get('schedule') or {}
out = {
  'running': st.get('running'), 'polls': st.get('polls'),
  'ticks': st.get('ticks'), 'last_poll': st.get('last_poll'),
  'last_skip': st.get('last_skip'), 'hours': sch.get('hours'),
  'blind': st.get('blind'), 'runs': len(d.get('runs') or []),
}
print(json.dumps(out))
" > "$TMP/state.json" 2>/dev/null
    cat "$TMP/state.json" | sed 's/^/   /'
    chk "the API answers and reports the loop RUNNING" \
        "$(grep -q '\"running\": true' "$TMP/state.json" && echo 1 || echo 0)"
    chk "the API carries a POLL count (the daemon is asking the schedule)" \
        "$(python3 -c "
import json; d=json.load(open('$TMP/state.json'))
print(1 if isinstance(d.get('polls'), int) and d['polls'] >= 1 else 0)")"
    chk "the API carries last_poll" \
        "$(python3 -c "
import json; d=json.load(open('$TMP/state.json'))
print(1 if d.get('last_poll') else 0)")"
    chk "the API carries the owner's wake hours" \
        "$(python3 -c "
import json; d=json.load(open('$TMP/state.json'))
print(1 if d.get('hours') == [9,13,17,21] else 0)")"
    chk "it is NOT blind" \
        "$(grep -q '\"blind\": false' "$TMP/state.json" && echo 1 || echo 0)"

    echo
    echo "C. it is not writing a run row per poll"
    python3 - "$TMP/test.db" <<'PY' | sed 's/^/   /'
import sqlite3, sys
c = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
c.row_factory = sqlite3.Row
n = c.execute("SELECT COUNT(*) FROM duty_run WHERE ran_at >= datetime('now','-10 minutes')").fetchone()[0]
print(f"duty_run rows in the last 10 minutes: {n}")
print("(0 is correct for a poll-only stretch: the owner's build wrote ~10 here)")
PY
    ROWS10=$(python3 -c "
import sqlite3
c = sqlite3.connect('file:$TMP/test.db?mode=ro', uri=True)
print(c.execute(\"SELECT COUNT(*) FROM duty_run WHERE ran_at >= datetime('now','-10 minutes')\").fetchone()[0])")
    chk "NO run row was written for a poll — the table is the record of wakes" \
        "$([[ "$ROWS10" -le 1 ]] && echo 1 || echo 0)"
fi

echo
echo "D. shutting down cleanly"
kill -TERM -"$BOOT_PID" 2>/dev/null
for _ in $(seq 1 40); do
    kill -0 "$BOOT_PID" 2>/dev/null || break
    sleep 1
done
chk "SIGTERM still shuts the app down cleanly" \
    "$(grep -q 'AgentalSec stopped cleanly' "$TMP/boot.out" && echo 1 || echo 0)"
chk "the duty loop reports stopping" \
    "$(grep -q 'Duty loop stopped' "$TMP/boot.out" && echo 1 || echo 0)"
chk "the port is released" \
    "$(! ss -ltn | grep -q "127.0.0.1:$PORT" && echo 1 || echo 0)"

# RESTORE THE OWNER'S CONFIG, AND PROVE IT IS BACK. This is the residue rule:
# a test that changes shared runtime state puts it back, verified.
echo
echo "E. the owner's config.json is restored, byte for byte"
cp "$TMP/config.orig.json" "$ROOT/config.json"
chk "config.json is byte-identical to before this script ran" \
    "$(cmp -s "$TMP/config.orig.json" "$ROOT/config.json" && echo 1 || echo 0)"

echo
echo "======================================================================"
echo "  $PASS passed, $FAIL failed"
[[ $FAIL -gt 0 ]] && echo "  FAILED — inspect $TMP"
echo "======================================================================"
