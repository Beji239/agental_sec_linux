#!/usr/bin/env bash
# /tmp/verify_t9_live.sh — the end-to-end proof for the T9 round, against a
# REAL BOOT of the app.
#
# The unit test proves the functions. ONLY A REAL BOOT PROVES THE DAEMON CALLS
# THEM, and that is what this script exists for. It boots main.py with the real
# adapters, the real routes and the real duty loop against a COPY of the
# database, on port 5299 so it cannot collide with the owner's running copy on
# 5000, and then:
#
#   A. the app boots and the PORT OWNER SWEEPER THREAD STARTED, with a first
#      pass that seeded (the log line says so)
#   B. a sweep row exists in the store, written BY THE THREAD, with the
#      coverage sentence naming this host's own unreadable count
#   C. the API answers, and its last_sweep comes from the RECORD
#   D. GET /api/ports/owners?sweep=true takes a FRESH pass and says it did,
#      and the sweep count goes UP BY ONE
#   E. THE ROUTES REFUSE TO GUESS, driven over real HTTP: an unparseable body,
#      a non-object body, a wrong-typed all_open, a non-list report_ids, a
#      request naming neither ids nor all, and a bad `show` — each refused, and
#      THE STORE IS UNCHANGED after every one of them (a refusal that dismissed
#      something anyway would pass a status-code check and fail this one)
#   F. a real dismissal over HTTP, then a real restore: the count is named, the
#      row survives, and the dismissal is journalled
#   G. shutting down cleanly, and the owner's config restored byte for byte
#
# The owner's store is COPIED, never opened: agental_sec.db is read to make the
# copy and is never written. config.json is swapped for the boot and restored,
# and the restoration is VERIFIED with cmp rather than assumed.
set -uo pipefail

# The tree, its owner and the owner's home are read at run time. A copy run
# from elsewhere names the tree with AGENTAL_ROOT.
ROOT="${AGENTAL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
[[ -f "$ROOT/main.py" ]] || { echo "no main.py in $ROOT: set AGENTAL_ROOT to the tree" >&2; exit 2; }
OWNER="$(stat -c %U "$ROOT")"
OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"
USER_SITE="$OWNER_HOME/.local/lib/python$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')/site-packages"
PORT=5299
TMP=$(mktemp -d /tmp/agental_t9_live.XXXXXX)
cp "$ROOT/agental_sec.db" "$TMP/test.db"

# THE COPY'S OWN FIXTURE IS MADE FRESH, AND THIS IS A FIX.
#
# Same defect class the L3 and case-memory verifiers each found in their first
# run, and this script had it in the two seed assertions: the operator's LIVE
# store already holds port_owner_change rows (57 of them, measured 2026-09-25),
# written by the owner's own running app. So "the seed wrote no arrival" was asserted
# against a table that already had arrivals in it and could never pass --
# a check that cannot pass is as useless as one that cannot fail, and it was
# reported as a defect in the sensor both times this script was run whole.
#
# The fixture is cleared IN THE COPY (never the original, which this script
# does not touch), so the boot below is a genuine seed on a still machine.
# BOTH TABLES GO, and the reason is tools/port_owner.py's own seed rule:
# seeding is `prior == 0` counted on port_owner_sweep, so a copy carrying the
# operator's 92 sweep rows makes the boot's first pass a NORMAL pass -- it logs
# a plain sweep line with no SEED marker, and the two seed assertions below
# then report a correct sensor as broken. MEASURED 2026-09-25: that is exactly
# what happened on the first whole-file run of this script, and the same
# 29-passed/4-failed result came back from the ORIGINAL, unmodified file, so
# the defect is the fixture and not this round's change. Clearing the copy is
# the same fix the L3 and case-memory verifiers already carry for their own
# first-run assertions (local_integrity_baseline, case_index).
python3 - "$TMP/test.db" <<'FIXTURE'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
try:
    n_sweep = conn.execute("SELECT COUNT(*) FROM port_owner_sweep").fetchone()[0]
    n_change = conn.execute("SELECT COUNT(*) FROM port_owner_change").fetchone()[0]
    conn.execute("DELETE FROM port_owner_change")
    conn.execute("DELETE FROM port_owner_sweep")
    conn.commit()
    print("   cleared %d sweep and %d change row(s) IN THE COPY, so the boot "
          "below is a genuine first pass and the seed checks are real"
          % (n_sweep, n_change))
except sqlite3.OperationalError as e:
    print("   port_owner tables not in the copy yet (%s); the boot will seed" % e)
finally:
    conn.close()
FIXTURE

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
    pkill -f "agental_t9_live" 2>/dev/null
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
    # A FAILED RUN KEEPS ITS SCRATCH DIR. The epilogue below tells the reader
    # to inspect it, and an instruction that cannot be followed is worse than
    # none: the first version deleted the directory and then pointed at it.
    if [[ "${FAIL:-0}" -gt 0 ]]; then
        echo "  (scratch kept for inspection, see below)"
    else
        rm -rf "$TMP"
    fi
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

echo "port under test : $PORT (the owner's copy is on 5000 and is untouched)"
echo "scratch         : $TMP"
echo "database        : $TMP/test.db  (a COPY; the real one is not written)"
echo

# The reference copy was taken in the LA-4 head, above, before anything was
# written; this is only the swap that points the boot at the scratch copy.
cp "$TMP/config.json" "$ROOT/config.json"

( setsid unshare -r bash -c "cd '$ROOT' && HOME=$OWNER_HOME USER=$OWNER \
    SUDO_USER=$OWNER PYTHONPATH='$USER_SITE:$ROOT' \
    AGENTALSEC_TEST_DB='$TMP/test.db' python3 main.py" \
    >"$TMP/boot.out" 2>&1 ) &
BOOT_PID=$!

echo "A. the real app boots, and the sweeper thread starts"
READY=0
for _ in $(seq 1 240); do
    if grep -q 'AgentalSec ready' "$TMP/boot.out" 2>/dev/null; then READY=1; break; fi
    kill -0 "$BOOT_PID" 2>/dev/null || break
    sleep 1
done
chk "the app reached ready" "$READY"
# WAIT FOR THE SWEEP LINES RATHER THAN READING THE FILE ONCE. This is the same
# race the other live verifier had to solve: "AgentalSec ready" is printed by
# the boot path while waitress finishes binding and the sweeper thread takes
# its first pass, so grepping the instant `ready` appears reads a log that is
# still being written. MEASURED: the first run of this script passed and the
# second failed the waitress line — a check whose answer depends on which of
# two asynchronous lines won a race, which is the definition of a flaky test.
# It now waits up to 30 s for all three lines and reports what it saw.
for _ in $(seq 1 30); do
    if grep -q "Serving on http://127.0.0.1:$PORT" "$TMP/boot.out" 2>/dev/null \
       && grep -q 'Port ownership sweeper started' "$TMP/boot.out" 2>/dev/null \
       && grep -q 'SEED: state recorded, no arrivals reported' "$TMP/boot.out" 2>/dev/null; then
        break
    fi
    sleep 1
done
chk "waitress is serving on the socket it was given" \
    "$(grep -q "Serving on http://127.0.0.1:$PORT" "$TMP/boot.out" && echo 1 || echo 0)"
chk "THE PORT OWNER SWEEPER THREAD STARTED" \
    "$(grep -q 'Port ownership sweeper started' "$TMP/boot.out" && echo 1 || echo 0)"
chk "and its log line says the first pass seeds rather than reporting arrivals" \
    "$(grep -q 'First pass runs now and seeds the record without reporting arrivals' \
        "$TMP/boot.out" && echo 1 || echo 0)"
chk "AND THE SEED PASS RAN: no arrival was reported for a machine that had not changed" \
    "$(grep -q 'SEED: state recorded, no arrivals reported' "$TMP/boot.out" && echo 1 || echo 0)"
grep -E 'Port ownership sweeper|SEED: state recorded' "$TMP/boot.out" | sed 's/^/   /' | head -4

echo
echo "B. the thread WROTE a sweep row, and it carries this host's coverage"
# NOTE ON WHAT "0 OWNED" MEANS HERE, because it looks alarming and is not: this
# script boots the app inside `unshare -r`, which is how the OTHER live verifiers
# in this tree boot it (see verify_duty_live.sh). Inside that user namespace the
# app cannot read the host's other processes' fd tables, so it attributes FEWER
# listeners than the same code run from a plain shell — measured side by side on
# this host: 3 owned / 14 unreadable outside, 0 owned / 17 unreadable inside.
# That is the module working: it says "an account this run cannot read" and never
# "nobody owns them". The check below asserts THE SENTENCE, not the count.
python3 - "$TMP/test.db" <<'PY' | sed 's/^/   /'
import sqlite3, sys
c = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
c.row_factory = sqlite3.Row
n = c.execute("SELECT COUNT(*) FROM port_owner_sweep").fetchone()[0]
print(f"sweep rows written by the thread: {n}")
if n:
    r = dict(c.execute("SELECT * FROM port_owner_sweep ORDER BY id DESC LIMIT 1").fetchone())
    print(f"  listeners={r['listeners']} with_owner={r['listeners_with_owner']} "
          f"unreadable={r['listeners_unreadable']} established={r['established']} "
          f"duration_ms={r['duration_ms']}")
    print(f"  note: {(r['note'] or '')[:150]}")
PY
SWEEPS0=$(python3 -c "
import sqlite3
c = sqlite3.connect('file:$TMP/test.db?mode=ro', uri=True)
print(c.execute('SELECT COUNT(*) FROM port_owner_sweep').fetchone()[0])")
chk "THE THREAD RECORDED A SWEEP (not zero rows)" \
    "$([[ "$SWEEPS0" -ge 1 ]] && echo 1 || echo 0)"
chk "and it found this host's own listening sockets" \
    "$(python3 -c "
import sqlite3
c = sqlite3.connect('file:$TMP/test.db?mode=ro', uri=True)
n = c.execute('SELECT listeners FROM port_owner_sweep ORDER BY id DESC LIMIT 1').fetchone()[0]
print(1 if n >= 1 else 0)")"
chk "THE COVERAGE SENTENCE NAMES THE UNREADABLE COUNT rather than letting an empty answer read as a machine with nothing open" \
    "$(python3 -c "
import sqlite3
c = sqlite3.connect('file:$TMP/test.db?mode=ro', uri=True)
note = c.execute('SELECT note FROM port_owner_sweep ORDER BY id DESC LIMIT 1').fetchone()[0] or ''
print(1 if ('cannot read' in note or 'matched to a' in note) else 0)")"
chk "and no change row was written for the seed" \
    "$(python3 -c "
import sqlite3
c = sqlite3.connect('file:$TMP/test.db?mode=ro', uri=True)
n = c.execute('SELECT COUNT(*) FROM port_owner_change').fetchone()[0]
print(1 if n == 0 else 0)")"

echo
echo "C. the API answers, and its last_sweep comes from the RECORD"
sleep 3
AUTHHDR=$(python3 -c "
import json,sys,pathlib
root = pathlib.Path('$ROOT')
sys.path.insert(0,str(root))
from core import secret_store
cfg = json.load(open('$TMP/config.json'))
print('X-API-Key: ' + secret_store.resolve(cfg, root)['app_api_key'])
" 2>/dev/null)
if [[ -z "$AUTHHDR" ]]; then no "could not resolve the API key from .env"; else
    curl -s -H "$AUTHHDR" "http://127.0.0.1:$PORT/api/ports/owners" \
        > "$TMP/owners.json"
    python3 - "$TMP/owners.json" <<'PY' | sed 's/^/   /'
import json, sys
d = json.load(open(sys.argv[1]))
ls = d.get("last_sweep") or {}
mod = d.get("module") or {}
print(f"available={d.get('available')} listeners={len(d.get('listeners') or [])} "
      f"last_sweep.taken_at={ls.get('taken_at')}")
print(f"coverage={str(d.get('coverage'))[:120]}")
print(f"module.last_sweep_at={mod.get('last_sweep_at')} "
      f"module.blind={mod.get('blind')}")
PY
    chk "the route answers and reports the record as available" \
        "$(python3 -c "
import json; d=json.load(open('$TMP/owners.json'))
print(1 if d.get('available') is True else 0)")"
    chk "IT KNOWS WHEN THE LAST SWEEP WAS — not null beside a populated list" \
        "$(python3 -c "
import json; d=json.load(open('$TMP/owners.json'))
print(1 if (d.get('last_sweep') or {}).get('taken_at') else 0)")"
    chk "AND module.status() AGREES — one source for the timestamp, not two" \
        "$(python3 -c "
import json; d=json.load(open('$TMP/owners.json'))
a=(d.get('last_sweep') or {}).get('taken_at'); b=(d.get('module') or {}).get('last_sweep_at')
print(1 if a and a == b else 0)")"
    chk "the coverage sentence travels in the same payload, never a second call" \
        "$(python3 -c "
import json; d=json.load(open('$TMP/owners.json'))
print(1 if d.get('coverage') else 0)")"

    echo
    echo "D. an ON-DEMAND sweep, over HTTP, as the agent's own tool would take it"
    curl -s -H "$AUTHHDR" "http://127.0.0.1:$PORT/api/ports/owners?sweep=true" \
        > "$TMP/fresh.json"
    chk "the route reports it took a FRESH pass" \
        "$(python3 -c "
import json; d=json.load(open('$TMP/fresh.json'))
print(1 if d.get('fresh_sweep_taken') is True else 0)")"
    SWEEPS1=$(python3 -c "
import sqlite3
c = sqlite3.connect('file:$TMP/test.db?mode=ro', uri=True)
print(c.execute('SELECT COUNT(*) FROM port_owner_sweep').fetchone()[0])")
    chk "AND A NEW SWEEP ROW EXISTS: the count went up by exactly one" \
        "$([[ "$SWEEPS1" -eq $((SWEEPS0 + 1)) ]] && echo 1 || echo 0)"
    chk "the sweep argument is VALIDATED rather than coerced" \
        "$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTHHDR" \
            "http://127.0.0.1:$PORT/api/ports/owners?sweep=maybe" | \
            grep -q '^400$' && echo 1 || echo 0)"

    echo
    echo "E. THE ROUTES REFUSE TO GUESS — driven over real HTTP, and the store is watched"
    DISMISSED_BEFORE=$(python3 -c "
import sqlite3
c = sqlite3.connect('file:$TMP/test.db?mode=ro', uri=True)
print(c.execute('SELECT COUNT(*) FROM duty_report WHERE dismissed_at IS NOT NULL').fetchone()[0])")

    refuse() {   # refuse <label> <expected-code> <curl args...>
        local label="$1" want="$2"; shift 2
        local code body
        code=$(curl -s -o "$TMP/refuse.json" -w '%{http_code}' -H "$AUTHHDR" "$@")
        body=$(head -c 200 "$TMP/refuse.json")
        if [[ "$code" == "$want" ]]; then
            ok "$label (HTTP $code) — $body"
        else
            no "$label (got HTTP $code, wanted $want) — $body"
        fi
    }
    refuse "an UNPARSEABLE body is refused" 400 \
        -X POST -H 'Content-Type: application/json' \
        --data '{not json' "http://127.0.0.1:$PORT/api/agents/dismiss"
    refuse "a NON-OBJECT body is refused" 400 \
        -X POST -H 'Content-Type: application/json' \
        --data '[1,2,3]' "http://127.0.0.1:$PORT/api/agents/dismiss"
    refuse "a WRONG-TYPED all_open is refused" 400 \
        -X POST -H 'Content-Type: application/json' \
        --data '{"all_open":"false"}' "http://127.0.0.1:$PORT/api/agents/dismiss"
    refuse "a NON-LIST report_ids is refused" 400 \
        -X POST -H 'Content-Type: application/json' \
        --data '{"report_ids":"3"}' "http://127.0.0.1:$PORT/api/agents/dismiss"
    refuse "a request naming NEITHER ids NOR all is refused rather than treated as dismiss-all" 400 \
        -X POST -H 'Content-Type: application/json' \
        --data '{}' "http://127.0.0.1:$PORT/api/agents/dismiss"
    refuse "a bad show filter is refused rather than passed through" 400 \
        "http://127.0.0.1:$PORT/api/agents?show=everything"

    DISMISSED_AFTER=$(python3 -c "
import sqlite3
c = sqlite3.connect('file:$TMP/test.db?mode=ro', uri=True)
print(c.execute('SELECT COUNT(*) FROM duty_report WHERE dismissed_at IS NOT NULL').fetchone()[0])")
    chk "AND NOTHING WAS DISMISSED BY ANY OF THOSE REFUSALS" \
        "$([[ "$DISMISSED_BEFORE" -eq "$DISMISSED_AFTER" ]] && echo 1 || echo 0)"

    echo
    echo "F. a real dismissal, and a real undo"
    RID=$(python3 -c "
import sqlite3
c = sqlite3.connect('file:$TMP/test.db?mode=ro', uri=True)
r = c.execute('SELECT id FROM duty_report ORDER BY id DESC LIMIT 1').fetchone()
print(r[0] if r else '')")
    if [[ -z "$RID" ]]; then
        echo "   (no report in the copied store to dismiss — the dismissal half is"
        echo "    proven by the unit test and by /api/agents answering above)"
    else
        curl -s -H "$AUTHHDR" -X POST -H 'Content-Type: application/json' \
            --data "{\"report_ids\":[$RID],\"note\":\"live verifier\"}" \
            "http://127.0.0.1:$PORT/api/agents/dismiss" > "$TMP/dismiss.json"
        python3 - "$TMP/dismiss.json" <<'PY' | sed 's/^/   /'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"dismissed={d.get('dismissed')} report_ids={d.get('report_ids')}")
print(f"note: {str(d.get('note'))[:110]}")
PY
        chk "the dismissal names the COUNT rather than a bare success" \
            "$(python3 -c "
import json; d=json.load(open('$TMP/dismiss.json'))
print(1 if d.get('dismissed') == 1 else 0)")"
        chk "and the response says nothing was deleted" \
            "$(python3 -c "
import json; d=json.load(open('$TMP/dismiss.json'))
print(1 if 'Nothing was deleted' in (d.get('note') or '') else 0)")"
        chk "THE ROW IS STILL IN THE STORE — dismissed, not deleted" \
            "$(python3 -c "
import sqlite3
c = sqlite3.connect('file:$TMP/test.db?mode=ro', uri=True)
r = c.execute('SELECT dismissed_at FROM duty_report WHERE id = ?', ($RID,)).fetchone()
print(1 if (r and r[0]) else 0)")"
        # BOTH JOURNAL CHECKS GO THROUGH ONE PYTHON BLOCK ON STDIN. The first
        # draft nested $(python3 -c "...") inside a "$(...)" inside a chk, and
        # three layers of quoting mangled the backslash-escapes until the file
        # did not even parse (bash -n: unexpected EOF). A heredoc has NO
        # quoting layers to get wrong, and the two answers come back as words.
        #
        # THE ENTRY-TYPE COLUMN IS `operation`, NOT event_type: that is what
        # core/integrity.record writes. The first draft guessed three table
        # names and searched for a column that does not exist, which would have
        # reported a working journal as broken -- a check that cannot pass is
        # exactly as useless as one that cannot fail.
        python3 - "$TMP/test.db" "$RID" <<'PY' > "$TMP/journal.txt"
import sqlite3, sys
c = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
rid = int(sys.argv[2])
n = c.execute("SELECT COUNT(*) FROM integrity_journal "
              "WHERE operation='report_dismissed'").fetchone()[0]
r = c.execute("SELECT row_ref FROM integrity_journal "
              "WHERE operation='report_dismissed' ORDER BY id DESC LIMIT 1").fetchone()
print("JOURNALLED" if n >= 1 else "NOT_JOURNALLED")
print("NAMES_REPORT" if (r and str(r[0]) == str(rid)) else "NAMES_NOTHING")
PY
        chk "and the dismissal is JOURNALLED, so who hid it is answerable" \
            "$(grep -q '^JOURNALLED$' "$TMP/journal.txt" && echo 1 || echo 0)"
        chk "and the journal entry NAMES the report that was hidden" \
            "$(grep -q '^NAMES_REPORT$' "$TMP/journal.txt" && echo 1 || echo 0)"
        curl -s -H "$AUTHHDR" -X POST \
            "http://127.0.0.1:$PORT/api/agents/$RID/restore" > "$TMP/restore.json"
        chk "the UNDO is ungated and puts it back" \
            "$(python3 -c "
import json; d=json.load(open('$TMP/restore.json'))
print(1 if d.get('restored') is True else 0)")"
        chk "and the row reads as never dismissed" \
            "$(python3 -c "
import sqlite3
c = sqlite3.connect('file:$TMP/test.db?mode=ro', uri=True)
r = c.execute('SELECT dismissed_at FROM duty_report WHERE id = ?', ($RID,)).fetchone()
print(1 if (r and not r[0]) else 0)")"
    fi
fi

echo
echo "G. shutting down cleanly"
kill -TERM -"$BOOT_PID" 2>/dev/null
for _ in $(seq 1 40); do
    kill -0 "$BOOT_PID" 2>/dev/null || break
    sleep 1
done
chk "SIGTERM still shuts the app down cleanly" \
    "$(grep -q 'AgentalSec stopped cleanly' "$TMP/boot.out" && echo 1 || echo 0)"
chk "the port is released" \
    "$(! ss -ltn | grep -q "127.0.0.1:$PORT" && echo 1 || echo 0)"

echo
echo "H. the owner's config.json is restored, byte for byte"
# THE RESTORE HAPPENS HERE AND IN THE TRAP, AND BOTH PROVE IT. Here, so the
# summary can show it; in the trap, so Ctrl+C, a closed window and a killed
# shell have it too.
cp "$TMP/config.orig.json" "$ROOT/config.json"
chk "config.json is byte-identical to before this script ran" \
    "$(cmp -s "$TMP/config.orig.json" "$ROOT/config.json" && echo 1 || echo 0)"

echo
echo "======================================================================"
echo "  $PASS passed, $FAIL failed"
[[ $FAIL -gt 0 ]] && echo "  FAILED — inspect $TMP"
echo "======================================================================"
[[ $FAIL -gt 0 ]] && exit 1
exit 0
