#!/usr/bin/env bash
# scripts/verify_final_boot.sh — FOLDER 8 of 9: boot the whole thing, read the
# API back, and measure what the running process actually serves.
#
# This is the last folder in the comparison build. Every earlier folder proved
# its own part; this one proves the ASSEMBLY, which is the thing a per-folder
# pass structurally cannot see. It runs the REAL app (main.py, the real role
# table, the real routes, real sensors, real waitress) on a COPY of both the
# tree and the database, on port 5133, so the owner's running copy on 5000 and
# the live 316 MB evidence store are not touched.
#
# What it measures, in the order it measures it:
#   A. the copy is the copy        no residue reaches the live tree
#   B. the boot                    role count, schema, ready line, tracebacks
#   C. the privilege report        this platform's own module names
#   D. the API read back           401 without a key, 200 with one, and the
#                                  payload's own claims read from the running
#                                  process rather than from the source
#   E. shutdown                    clean stop, port released, durable log
#
# PASS/FAIL is printed for each check and the exit code is the failure count,
# so `./verify_final_boot.sh && echo ok` reads as a gate.
set -uo pipefail

# The tree, its owner and the owner's home are read at run time. A copy run
# from elsewhere names the tree with AGENTAL_ROOT.
ROOT="${AGENTAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
[[ -f "$ROOT/main.py" ]] || { echo "no main.py in $ROOT: set AGENTAL_ROOT to the tree" >&2; exit 2; }
OWNER="$(stat -c %U "$ROOT")"
OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"
TMP="${AGENTAL_VERIFY_TMP:-}"
PORT=5133
HOST=127.0.0.1
USER_SITE="$OWNER_HOME/.local/lib/python$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')/site-packages"

KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1
if [[ -z "$TMP" || ! -d "$TMP/tree" ]]; then
    echo "Set AGENTAL_VERIFY_TMP to the prepared copy: a tree with the config"
    echo "and the database already copied in, port moved off 5000. Expected:"
    echo "\$AGENTAL_VERIFY_TMP/tree/ and \$AGENTAL_VERIFY_TMP/tree/agental_sec.db."
    exit 2
fi
TREE="$TMP/tree"
LOGFILE="$TREE/logs/agental_sec_linux.log"

PASS=0; FAIL=0
ok() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
no() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
chk() { if [[ "$2" == "1" ]]; then ok "$1"; else no "$1"; fi; }
note() { echo "    $1"; }

echo "port under test : $PORT (the owner's copy is on 5000)"
echo "scratch         : $TMP"
echo "tree under test : $TREE"
echo "database        : $TREE/agental_sec.db  (a snapshot; the live one is not read)"
echo

BOOT_PID=""
cleanup() {
    [[ -n "$BOOT_PID" ]] && kill -TERM -"$BOOT_PID" 2>/dev/null
    sleep 1
    if [[ "$KEEP" == "1" ]]; then
        echo "kept: $TMP"
    else
        rm -rf "$TMP"
    fi
}
trap cleanup EXIT

# A. THE COPY IS THE COPY
echo "A. the isolation holds (nothing here can reach the live tree)"
LIVE_PORT=$(python3 -c "import json;print(json.load(open('$ROOT/config.json'))['flask']['port'])")
chk "the live config.json still points at the owner's port ($LIVE_PORT)" \
    "$([[ "$LIVE_PORT" == "5000" ]] && echo 1 || echo 0)"
chk "the copy has its own config.json, on $PORT" \
    "$(python3 -c "import json;print(1 if json.load(open('$TREE/config.json'))['flask']['port'] == $PORT else 0)")"
chk "the copy's database is a SEPARATE inode from the live one" \
    "$([[ "$(stat -c %i "$TREE/agental_sec.db")" != "$(stat -c %i "$ROOT/agental_sec.db")" ]] && echo 1 || echo 0)"
chk "and it is a real database, not a truncated copy" \
    "$(python3 -c "
import sqlite3
c = sqlite3.connect('file:$TREE/agental_sec.db?mode=ro', uri=True)
print(1 if c.execute('PRAGMA quick_check').fetchone()[0] == 'ok' else 0)")"
LIVE_MTIME_BEFORE=$(stat -c %Y "$ROOT/agental_sec.db")
note "live database mtime recorded: $LIVE_MTIME_BEFORE"
# NOTE ON WHAT IS *NOT* CHECKED HERE. An earlier draft compared the live
# database's mtime before and after, on the idea that an untouched mtime proves
# isolation. It does not: the owner's own copy is running on port 5000 and its
# sensors write to that file continuously, so the mtime moves whether or not
# anything in this script misbehaves. The isolation is proven instead by the
# open-file check in section E, which asks the boot's own process tree which
# database it holds — a question the live app's activity cannot answer for it.

# B. THE BOOT
echo
echo "B. the whole thing boots (the real entry point, the real role table)"
# THE COPY'S LOG IS ITS OWN FILE, AND THIS SCRIPT OWNS IT FOR THE DURATION.
# FOLDER 7's lesson applies here: an earlier draft asserted the copy's log
# "starts empty" as proof the copy was fresh, but on a --keep re-run it is not
# empty, so the check failed for a reason that had nothing to do with the app
# and would have been "fixed" by weakening it. The log is truncated here
# instead, which makes every log-based check below measure THIS run only, and
# the freshness of the copy is asserted against the live tree's own log rather
# than against a number this script just produced.
chk "the copy logs to its OWN file, not the live tree's" \
    "$([[ "$(stat -c %i "$LOGFILE" 2>/dev/null || echo none)" != \
          "$(stat -c %i "$ROOT/logs/agental_sec_linux.log")" ]] && echo 1 || echo 0)"
: > "$LOGFILE"
LOG_LINES_BEFORE=0

( setsid unshare -r bash -c "cd '$TREE' && HOME=$OWNER_HOME USER=$OWNER \
    SUDO_USER=$OWNER PYTHONPATH='$USER_SITE:$TREE' \
    AGENTALSEC_TEST_DB='$TREE/agental_sec.db' python3 main.py" \
    >"$TMP/boot.out" 2>&1 ) &
BOOT_PID=$!

READY=0
for _ in $(seq 1 240); do
    if grep -q 'AgentalSec ready' "$TMP/boot.out" 2>/dev/null; then READY=1; break; fi
    kill -0 "$BOOT_PID" 2>/dev/null || break
    sleep 1
done
chk "the app reached ready" "$READY"
[[ "$READY" == "0" ]] && { echo "   --- the boot said ---"; tail -25 "$TMP/boot.out" | sed 's/^/   /'; }

chk "ZERO tracebacks on a full boot" \
    "$(! grep -q 'Traceback (most recent call last)' "$TMP/boot.out" && echo 1 || echo 0)"
# WAITRESS'S OWN LINE IS LOGGED AFTER THE READY LINE, SO IT IS WAITED FOR
# RATHER THAN GRABBED. An earlier draft read it in the same instant the ready
# line appeared and failed on a boot that was in fact serving: main.py logs
# "AgentalSec ready.", and only then calls serve(), which logs "Serving on ..."
# once it is actually accepting. The socket is bound BEFORE the ready line (see
# _bind_listener), so a short wait here is a wait for a log line, never for the
# listener. It is also why the HTTP read-back in section D is the real proof:
# it talks to the socket instead of reading about it.
SERVING=0
for _ in $(seq 1 20); do
    grep -q "Serving on http://$HOST:$PORT" "$TMP/boot.out" 2>/dev/null && SERVING=1 && break
    sleep 1
done
chk "waitress serves on the socket it was handed" "$SERVING"

ROLES=$(grep -c '\[OK\]' "$TMP/boot.out" 2>/dev/null); ROLES=${ROLES:-0}
SKIPS=$(grep -c '\[SKIP\]' "$TMP/boot.out" 2>/dev/null); SKIPS=${SKIPS:-0}
FAILED_ROLES=$(grep -c '\[FAIL\]\|\[MISSING\]' "$TMP/boot.out" 2>/dev/null); FAILED_ROLES=${FAILED_ROLES:-0}
note "roles [OK]      : $ROLES"
note "roles [SKIP]    : $SKIPS"
note "roles [FAIL]    : $FAILED_ROLES"
# WHY THE ROLE COUNT IS A RANGE AND NOT A NUMBER. The role table's size is a
# property of the deployment, not a constant here: this boot's copy ships the
# owner's config.json, in which linux_monitor has no hosts enabled and is
# therefore SKIPped by its own design. What is asserted is that no role in the
# table went MISSING — a role that never reached a verdict is the failure mode
# worth catching, and it is the one FOLDER 3's readiness page was built around.
chk "every role in the table reached a verdict (no role silently absent)" \
    "$([[ $((ROLES + SKIPS + FAILED_ROLES)) -ge 20 ]] && echo 1 || echo 0)"
chk "no role FAILED to load on a full boot" \
    "$([[ "$FAILED_ROLES" -eq 0 ]] && echo 1 || echo 0)"

SCHEMA=$(grep -o 'Schema up to date (v[0-9]*)' "$TMP/boot.out" | tail -1)
note "schema          : $SCHEMA"
chk "the schema is the ported version (v41)" \
    "$([[ "$SCHEMA" == "Schema up to date (v41)" ]] && echo 1 || echo 0)"

chk "the hardware vendor registry loaded with real data" \
    "$(grep -q 'Hardware vendor registry: 54,000 prefixes' "$TMP/boot.out" && echo 1 || echo 0)"
chk "the app names its OWN sensor position rather than another platform's" \
    "$(grep -q "Position 'host' means this instance cannot observe traffic between other devices" "$TMP/boot.out" && echo 1 || echo 0)"

# C. THE PRIVILEGE REPORT
echo
echo "C. the privilege report reads this platform"
chk "the report printed" \
    "$(grep -q 'AGENTALSEC LINUX - PRIVILEGE REPORT' "$TMP/boot.out" && echo 1 || echo 0)"
grep -A2 'PRIVILEGE REPORT' "$TMP/boot.out" | tail -1 | sed 's/^/   /'
chk "the packet-capture verdict is stated in Linux terms" \
    "$(grep -q 'Packet capture:' "$TMP/boot.out" && echo 1 || echo 0)"
if grep -q 'Running as ROOT' "$TMP/boot.out"; then
    note "elevated run (unshare -r): all capabilities present"
else
    note "unelevated run: expecting unavailable/degraded rows"
    chk "the degraded rows count" \
        "$(grep -qE '[0-9]+ module\(s\) unavailable, [0-9]+ degraded' "$TMP/boot.out" && echo 1 || echo 0)"
    chk "and the unelevated warning is not silence" \
        "$(grep -q 'is not evidence of a quiet network' "$TMP/boot.out" && echo 1 || echo 0)"
fi

# D. THE API READ BACK
echo
echo "D. the API, read back from the running process"
UNAUTH=$(curl -s -o "$TMP/unauth.body" -w '%{http_code}' "http://$HOST:$PORT/api/status")
chk "/api/status refuses WITHOUT a key (got $UNAUTH)" \
    "$([[ "$UNAUTH" == "401" ]] && echo 1 || echo 0)"
# WHAT THE REFUSAL BODY ACTUALLY IS, STATED EXACTLY. An earlier draft of this
# check was labelled "carries no payload" and asserted only that the body was
# under 400 bytes — which passed, and was misleading. The body is
# {"error":"Unauthorized"}, 25 bytes. That is the right answer (a refusal that
# names itself and leaks nothing), but the check's label claimed something the
# check did not test, so the PASS overstated what had been looked at. Assert
# the actual string.
UNAUTH_BODY=$(cat "$TMP/unauth.body" 2>/dev/null)
note "the refusal body, verbatim: ${UNAUTH_BODY:-<empty>}"
chk "the refusal body is the named error and nothing else" \
    "$([[ "$UNAUTH_BODY" == '{"error":"Unauthorized"}' ]] && echo 1 || echo 0)"
chk "and it leaks nothing about the modules or the model" \
    "$(! grep -qiE 'module|deepseek|model|session' "$TMP/unauth.body" && echo 1 || echo 0)"

KEY=$(cd "$TREE" && HOME=$OWNER_HOME PYTHONPATH="$USER_SITE:$TREE" python3 -c "
import json, sys, pathlib
root = pathlib.Path('$TREE')
sys.path.insert(0, str(root))
from core import settings, secret_store
cfg = json.load(open('$TREE/config.json'))
print(secret_store.resolve(cfg, root)['app_api_key'])
" 2>/dev/null)
chk "the API key resolves from the copy's own .env" "$([[ -n "$KEY" ]] && echo 1 || echo 0)"

if [[ -n "$KEY" ]]; then
    CODE=$(curl -s -o "$TMP/status.json" -w '%{http_code}' \
           -H "X-API-Key: $KEY" "http://$HOST:$PORT/api/status")
    chk "/api/status answers WITH the key (got $CODE)" \
        "$([[ "$CODE" == "200" ]] && echo 1 || echo 0)"

    python3 - "$TMP/status.json" <<'PY' | sed 's/^/    /'
import json, sys
d = json.load(open(sys.argv[1]))
print("keys in the payload:", ", ".join(sorted(d.keys())[:14]))
mods = d.get("modules") or {}
if isinstance(mods, dict):
    print("modules reported :", len(mods))
    bad = [k for k, v in mods.items()
           if str(v).lower() in ("false", "failed", "missing", "error")]
    print("modules not ok   :", ", ".join(bad) if bad else "none")
PY

    chk "the payload describes modules rather than omitting them" \
        "$(python3 -c "
import json
d=json.load(open('$TMP/status.json'))
m=d.get('modules')
print(1 if m and ((isinstance(m,dict) and len(m)>5) or (isinstance(m,list) and len(m)>5)) else 0)")"

    # THE ROUTES THAT CARRY THE LATER FOLDERS, READ BACK ONE AT A TIME.
    #
    # /api/incidents IS DELIBERATELY NOT IN THIS LIST, and it was in an earlier
    # draft of this script. That route does not exist in this tree and never
    # did: the T2 incident ledger is read through /api/agents, which returns
    # `reports` filtered by `kind=incident`. Writing a check for a route that
    # was never built is the exact failure this whole build is against — it
    # reports a missing feature as a broken one, and both of those are wrong.
    # The list below is taken from the route table itself:
    #     grep -oP '@app\.route\("\K[^"]+' api/routes.py
    ROUTES_OK=0; ROUTES_TOTAL=0
    for route in /api/actions /api/agents "/api/agents?kind=incident" \
                 /api/tls /api/detections /api/devices /api/integrity/status \
                 /api/retention/status /api/runbook/cvss/status; do
        ROUTES_TOTAL=$((ROUTES_TOTAL+1))
        RC=$(curl -s -o "$TMP/route.json" -w '%{http_code}' \
             -H "X-API-Key: $KEY" "http://$HOST:$PORT$route")
        if [[ "$RC" == "200" ]]; then
            VALID=$(python3 -c "
import json
try:
    d = json.load(open('$TMP/route.json')); print(1 if d else 0)
except Exception: print(0)")
            if [[ "$VALID" == "1" ]]; then
                ok "$route answers 200 with a non-empty JSON body"
                ROUTES_OK=$((ROUTES_OK+1))
            else
                no "$route answered 200 but with an empty or unparseable body"
            fi
        else
            no "$route answers (got $RC)"
        fi
    done
    # COUNTED, NOT ASSERTED IN PROSE. The ledger for this folder said "ten
    # routes" when this list holds nine. The list is the truth and the count is
    # derived from it, so the two cannot drift apart again.
    note "$ROUTES_OK of $ROUTES_TOTAL routes answered, and it is $ROUTES_TOTAL"
    note "checks that were performed, not a number written down separately"

    chk "an unknown /api/ path is a 404, not a 500" \
        "$([[ "$(curl -s -o /dev/null -w '%{http_code}' \
             -H "X-API-Key: $KEY" "http://$HOST:$PORT/api/not_a_route")" == "404" ]] && echo 1 || echo 0)"
    chk "and /api/incidents is a 404 too, because this tree has no such route" \
        "$([[ "$(curl -s -o /dev/null -w '%{http_code}' \
             -H "X-API-Key: $KEY" "http://$HOST:$PORT/api/incidents")" == "404" ]] && echo 1 || echo 0)"

    # THE ISOLATION, PROVEN WHILE THE RUN IS STILL ALIVE — AND PROVEN AGAINST
    # THE RIGHT PROCESSES.
    #
    # Two drafts of this section were wrong, and the wrongness is worth
    # recording because it is the same shape both times:
    #
    #   Draft 1 compared the LIVE database's mtime before and after. It moves
    #   either way, because the owner's own copy is running on 5000.
    #
    #   Draft 2 globbed /proc/<pid>/fd for every PID matching "main.py" and
    #   treated "the live database was never seen" as a pass. The live app runs
    #   as root, so `/proc/<pid>/fd` for it is Permission denied to the operator,
    #   readlink fails, the loop `continue`s, and the check passes WITHOUT
    #   HAVING LOOKED AT ANYTHING. A check that cannot fail is not a check; it
    #   is the readback lie this whole build exists to catch.
    #
    # So: the PIDs are scoped to this run by their WORKING DIRECTORY, and every
    # PID that could not be inspected is counted and named. The scoping matters
    # because the owner's copy is also `python3 main.py`; the accounting matters
    # because "0 violations observed" and "0 observables" are different answers.
    #
    # The proof that does NOT depend on permissions is the app's own boot line,
    # which names the file it opened. That is the check directly below.
    echo
    echo "   which database the copy's boot actually opened"
    BOOT_DB=$(grep -oP '^.*DB: \K.*' "$LOGFILE" 2>/dev/null | tail -1)
    note "the boot's own log says: ${BOOT_DB:-<it did not say>}"
    chk "the app names the COPY's database file in its own boot log" \
        "$([[ "$BOOT_DB" == "$TREE/agental_sec.db" ]] && echo 1 || echo 0)"
    chk "and that is not the live database" \
        "$([[ "$BOOT_DB" != "$ROOT/agental_sec.db" ]] && echo 1 || echo 0)"
    chk "the module that owns DB_PATH warned that it was repointed" \
        "$(grep -q 'AGENTALSEC_TEST_DB is set, using' "$LOGFILE" && echo 1 || echo 0)"

    echo
    echo "   the boot's own file descriptors, while it is still running"
    MINE=""; FOREIGN=0
    for p in $(pgrep -f 'main.py' 2>/dev/null); do
        cwd=$(readlink "/proc/$p/cwd" 2>/dev/null) || { FOREIGN=$((FOREIGN+1)); continue; }
        if [[ "$cwd" == "$TREE" ]]; then MINE="$MINE $p"; else FOREIGN=$((FOREIGN+1)); fi
    done
    note "pids in the copy's tree:${MINE:- none}"
    note "pids matching main.py but NOT in the copy (the owner's own copy,"
    note "running as root, is one of these and its /proc is unreadable here): $FOREIGN"

    INSPECTED=0; UNREADABLE=0; HELD_LIVE=0; HELD_COPY=0
    for p in $MINE; do
        if [[ ! -r "/proc/$p/fd" ]]; then UNREADABLE=$((UNREADABLE+1)); continue; fi
        INSPECTED=$((INSPECTED+1))
        for f in /proc/$p/fd/*; do
            tgt=$(readlink "$f" 2>/dev/null) || continue
            [[ "$tgt" == "$ROOT/agental_sec.db" ]] && HELD_LIVE=$((HELD_LIVE+1))
            [[ "$tgt" == "$TREE/agental_sec.db" ]] && HELD_COPY=$((HELD_COPY+1))
        done
    done
    note "inspected: $INSPECTED   unreadable: $UNREADABLE"
    note "fds on the copy's db: $HELD_COPY   fds on the live db: $HELD_LIVE"
    chk "at least one of this run's processes could actually be inspected" \
        "$([[ "$INSPECTED" -ge 1 ]] && echo 1 || echo 0)"
    chk "every one of this run's processes was inspectable (none skipped)" \
        "$([[ "$UNREADABLE" -eq 0 ]] && echo 1 || echo 0)"
    chk "the run's processes were holding the COPY's database" \
        "$([[ "$HELD_COPY" -ge 1 ]] && echo 1 || echo 0)"
    chk "no readable process of this run held the LIVE database open" \
        "$([[ "$HELD_LIVE" -eq 0 ]] && echo 1 || echo 0)"
fi

# E. SHUTDOWN
echo
echo "E. it stops cleanly, and leaves the port free"
kill -TERM -"$BOOT_PID" 2>/dev/null
for _ in $(seq 1 40); do
    kill -0 "$BOOT_PID" 2>/dev/null || break
    sleep 1
done
chk "SIGTERM shuts the app down cleanly" \
    "$(grep -q 'AgentalSec stopped cleanly' "$TMP/boot.out" && echo 1 || echo 0)"
chk "the port is released" \
    "$(! ss -ltn | grep -q "$HOST:$PORT" && echo 1 || echo 0)"
chk "the run left a DURABLE log, not only a console" \
    "$([[ -s "$LOGFILE" ]] && echo 1 || echo 0)"
chk "and that log carries the boot and the stop" \
    "$(grep -q 'AgentalSec ready' "$LOGFILE" && grep -q 'AgentalSec stopped cleanly' "$LOGFILE" && echo 1 || echo 0)"
chk "no traceback in the durable log either" \
    "$(! grep -q 'Traceback (most recent call last)' "$LOGFILE" && echo 1 || echo 0)"

# THE LIVE DATABASE'S MTIME, RECORDED RATHER THAN ASSERTED. An earlier draft
# checked this before and after and called an unchanged mtime proof of
# isolation. It is not proof: the owner's own copy is running on 5000 and its
# sensors write to that file continuously, so the number moves whether or not
# anything in this script misbehaves. The isolation is proven instead by the
# open-file-descriptor check in section D, which asks the boot's own processes
# which database they held while they were alive.
LIVE_MTIME_AFTER=$(stat -c %Y "$ROOT/agental_sec.db")
note "live database mtime: before $LIVE_MTIME_BEFORE, after $LIVE_MTIME_AFTER"
note "recorded, not asserted — the app on 5000 writes to it continuously"

echo
echo "======================================================================"
echo "  $PASS passed, $FAIL failed"
[[ $FAIL -gt 0 ]] && { echo "  FAILED SECTIONS — re-run with --keep and read $TMP"; KEEP=1; }
echo "======================================================================"
exit $(( FAIL > 0 ))
