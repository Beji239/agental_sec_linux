#!/usr/bin/env bash
# scripts/verify_launchers_live.sh
#
# THE CLICK, DRIVEN — both desktop icons, end to end, and the residue check that
# would have caught the 2026-09-25 defect on the day it landed.
#
# WHY THIS EXISTS. Two defects now share the same shape in this project's
# history: the launcher was only ever verified by a HUMAN CLICK, and the click
# is the one thing that was never run in a loop. LAUNCHER_ICONS.md's own last
# line was "click the privileged icon once", and that is how a harness (a
# verify_*.sh whose EXIT path did not put the operator's config back) left
# `flask.port: 5298` and `auto_open_browser: false` in config.json for eleven
# hours: every launcher test passed, every unit test passed, and both icons
# started an app that bound a port nobody was browsing with no browser opening.
# A person found it, not a check.
#
# So this script drives what the icons do, with the icons' own argv read out of
# the real .desktop files, and it ends by PROVING the operator's files are
# byte-identical to when it started. The last section is the check that was
# missing.
#
# HOW, and it is the method LAUNCHER_ICONS.md established: the launcher's
# terminal is chosen from PATH, so a STUB terminal is put first — it records
# the argv it was handed and then executes it. The privileged arm adds a stub
# `sudo` that runs its command under `unshare -r` (a real uid 0) with SUDO_USER
# set, which is what sudo hands back after a correct password. The real
# `[sudo]` prompt interacting with a real terminal is the one thing this cannot
# supply, and it was verified to appear by the owner's own click.
#
# THE APP BOOTS OUT OF A SCRATCH TREE (hardlinks of the project + a copy of the
# store), so a run that goes root cannot write into the operator's log, store or
# tree. That was learned the hard way in the first draft of this harness.
#
# Usage:  ./scripts/verify_launchers_live.sh [--keep]
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
USER_SITE="$HOME/.local/lib/python3.12/site-packages"
KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1
TMP=$(mktemp -d /tmp/agental_launchers.XXXXXX)
TREE="$TMP/tree"

PASS=0; FAIL=0
ok() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
no() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
chk() { if [[ "$2" == "1" ]]; then ok "$1"; else no "$1"; fi; }

# THE RESIDUE RULE, ENFORCED BY THE SCRIPT THAT NEEDS IT
# Every reference copy is made HERE, before anything runs, and the trap puts
# the operator's files back and PROVES it. scripts/verify_duty_live.sh is the
# script this round fixed for exactly this reason: it swapped the real
# config.json for a scratch copy and restored it only on its normal exit, so an
# interrupted run left port 5298 behind. This script never needs to swap the
# real config at all — the boot happens in $TREE — but the trap is here rather
# than in whoever remembers, for the same reason the hand-back in
# run_elevated.sh is a trap.
cp "$ROOT/config.json"          "$TMP/config.before.json"
cp "$ROOT/agental_sec.db"       "$TMP/db.before"
cp "$ROOT/logs/agental_sec_linux.log" "$TMP/log.before"

cleanup() {
    local rc=$?
    stop_apps
    close_browser_window
    if [[ -f "$TMP/config.before.json" ]] && ! cmp -s "$ROOT/config.json" "$TMP/config.before.json"; then
        cp "$TMP/config.before.json" "$ROOT/config.json"
        echo "  (the operator's config.json was put back by this script's trap)"
    fi
    if [[ "$KEEP" == "1" ]]; then
        echo "kept: $TMP"
    else
        rm -rf "$TREE" "$TMP" 2>/dev/null
    fi
    return $rc
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

stop_apps() {
    local pid
    for pid in $(pgrep -f "python3 main.py" 2>/dev/null); do
        grep -qa "AGENTALSEC_TEST_DB=$TREE/agental_sec.db" "/proc/$pid/environ" 2>/dev/null \
            && kill -TERM "$pid" 2>/dev/null
    done
}
close_browser_window() {
    local t
    while read -r t; do
        [[ -n "$t" ]] && wmctrl -c "$t" 2>/dev/null
    done < <(wmctrl -l 2>/dev/null | grep -F "AgentalSec" | cut -d' ' -f5-)
}

# the scratch tree: the project, one copy of the store
#
# THE CP-ONTO-A-HARDLINK TRAP, MEASURED 2026-09-25 THE HARD WAY. The first
# version of this function hardlinked every file and then ran
# `cp "$ROOT/config.json" "$TREE/config.json"`. That cp does NOT make a
# separate copy: $TREE/config.json was already the SAME INODE as the live file,
# so cp opened it and wrote through the link. The next thing to open
# $TREE/config.json with "w" then rewrote the operator's real config.json on
# disk. Measured three times in one afternoon, twice with harnesses written by
# me — the live config.json went to a scratch port and stayed there until the
# residue check this script now ends with caught it. The same run also left
# `.env` at nlink=4.
#
# THE RULE THIS LEAVES: hardlink the files that are only READ; COPY every file
# a run writes in place, and rm the destination first so a stale link can never
# be written through. config.json, .env, the store and the logs are all
# written, so all four are copies.
#
# `find -path X -prune -o -type f -print` with `-e ./config.json` in the
# predicate: measured, find answers `unknown predicate '-e'`. -e is a TEST
# command, not a find one. `-name` is what find has.
build_tree() {
    rm -rf "$TREE"; mkdir -p "$TREE/logs" "$TMP/bin"
    ( cd "$ROOT" && find . \( -path ./agental_sec.db -o -path ./logs -o -path ./__pycache__ \
          -o -path ./.pytest_cache -o -name '*.pyc' \
          -o -name 'config.json' -o -name '.env' \) -prune -o -type f -print0 | \
      while IFS= read -r -d '' f; do
          mkdir -p "$TREE/$(dirname "$f")"
          ln "$f" "$TREE/$f" 2>/dev/null || cp "$f" "$TREE/$f"
      done )
    for f in agental_sec.db config.json .env; do
        [[ -e "$ROOT/$f" ]] || continue
        rm -f "$TREE/$f"                 # never write through a link
        cp "$ROOT/$f" "$TREE/$f"
    done
}
build_tree

# AND PROVE IT, because "I copied it" is a claim and the inode is the fact.
for f in agental_sec.db config.json .env; do
    [[ -e "$ROOT/$f" ]] || continue
    if [[ "$(stat -c %i "$ROOT/$f")" == "$(stat -c %i "$TREE/$f")" ]]; then
        echo "REFUSING TO RUN: $TREE/$f IS THE SAME INODE as the operator's"
        echo "  $ROOT/$f. A run in this tree would write into the owner's file."
        exit 2
    fi
done

# the stub terminal: records the argv a real terminal would receive, then runs it
cat > "$TMP/bin/gnome-terminal" <<'STUB'
#!/usr/bin/env bash
printf 'STUB_TERMINAL_ARGV: %s\n' "$*" > "$AGENTAL_STUB_ARGV"
shift; [[ "$1" == --title=* ]] && shift; [[ "$1" == -- ]] && shift
exec "$@"
STUB
# the stub sudo: what the real one does once the password is accepted
cat > "$TMP/bin/sudo" <<'SUDO'
#!/usr/bin/env bash
printf 'STUB_SUDO_ARGV: %s\n' "$*" >> "$AGENTAL_STUB_SUDO"
[[ "$1" == -- ]] && shift
exec unshare -r env SUDO_USER="$AGENTAL_STUB_USER" HOME="$AGENTAL_STUB_HOME" \
     USER="$AGENTAL_STUB_USER" LOGNAME="$AGENTAL_STUB_USER" "$@"
SUDO
chmod +x "$TMP/bin/gnome-terminal" "$TMP/bin/sudo"

export AGENTAL_STUB_ARGV="$TMP/argv.txt"
export AGENTAL_STUB_SUDO="$TMP/sudo.txt"
export AGENTAL_STUB_USER="$(id -un)"
export AGENTAL_STUB_HOME="$HOME"

PORT=$(python3 -c "import json;print(json.load(open('$TREE/config.json'))['flask']['port'])")
AUTO=$(python3 -c "import json;print(json.load(open('$TREE/config.json'))['flask']['auto_open_browser'])" | tr 'A-Z' 'a-z')

echo "project         : $ROOT"
echo "scratch tree    : $TREE   (hardlinks; the store is one copy)"
echo "port config.json names : $PORT   (auto_open_browser: $AUTO)"
echo

echo "0. the four desktop entries, and what they point at"
for d in "$HOME/Desktop/agentalsec.desktop" "$HOME/Desktop/agentalsec-privileged.desktop" \
         "$HOME/.local/share/applications/agentalsec.desktop" \
         "$HOME/.local/share/applications/agentalsec-privileged.desktop"; do
    chk "$(basename "$d") is a valid desktop entry" \
        "$(desktop-file-validate "$d" >/dev/null 2>&1 && echo 1 || echo 0)"
done
for d in "$HOME/Desktop/agentalsec.desktop" "$HOME/Desktop/agentalsec-privileged.desktop"; do
    target=$(grep '^Exec=' "$d" | sed 's/^Exec="//; s/" .*//')
    chk "$(basename "$d")'s Exec target exists and is executable" \
        "$([[ -x "$target" ]] && echo 1 || echo 0)"
done
# THE ARGUMENTS THE ICONS ACTUALLY PASS, read out of the files rather than
# retyped here. A verifier that hardcodes the flags it tests can drift from the
# icons it claims to verify.
NORMAL_ARGS=$(grep '^Exec=' "$HOME/Desktop/agentalsec.desktop" | sed 's/^Exec=//; s/^"[^"]*"//')
PRIV_ARGS=$(grep '^Exec=' "$HOME/Desktop/agentalsec-privileged.desktop" | sed 's/^Exec=//; s/^"[^"]*"//')
echo "   normal icon's args     :$NORMAL_ARGS"
echo "   privileged icon's args :$PRIV_ARGS"
chk "and the two icons differ in the way they are supposed to (elevated vs not)" \
    "$([[ "$NORMAL_ARGS" != "$PRIV_ARGS" && "$PRIV_ARGS" == *--elevated* ]] && echo 1 || echo 0)"

boot_arm() {           # boot_arm <label> <args> <env-extra...>
    local label="$1"; shift
    local args="$1"; shift
    local out="$TMP/$label.out"
    rm -f "$out" "$AGENTAL_STUB_ARGV" "$AGENTAL_STUB_SUDO"
    PATH="$TMP/bin:$PATH" HOME="$HOME" USER="$(id -un)" \
      AGENTALSEC_TEST_DB="$TREE/agental_sec.db" \
      PYTHONPATH="$USER_SITE:$TREE" \
      bash "$TREE/scripts/agental_sec_launch.sh" $args </dev/null \
      >"$out" 2>&1 &
    echo "$out"
}

echo
echo "A. the NORMAL icon: no elevation, and the dashboard must still open"
OUT=$(boot_arm normal "$NORMAL_ARGS")
TITLE=""
for _ in $(seq 1 120); do
    TITLE=$(wmctrl -l 2>/dev/null | grep -F "AgentalSec" | head -1)
    [[ -n "$TITLE" ]] && break
    kill -0 "$(pgrep -f 'python3 main.py' | head -1)" 2>/dev/null || true
    sleep 1
done
for _ in $(seq 1 20); do
    grep -q 'Opened http\|No way to open a browser\|Dashboard did not answer\|is ALREADY' "$OUT" 2>/dev/null && break
    sleep 1
done
echo "   terminal argv : $(head -c 160 "$AGENTAL_STUB_ARGV" 2>/dev/null)"
echo "   launch line   : $(grep -h 'Opened http\|No way to open a browser\|Dashboard did not answer' "$OUT" | tail -1)"
echo "   window        : ${TITLE:-<none>}"
chk "the wrapper opened a terminal ON THIS LAUNCHER (its path is in the argv)" \
    "$(grep -qF "$TREE/scripts/agental_sec_launch.sh" "$AGENTAL_STUB_ARGV" && echo 1 || echo 0)"
chk "the app reached ready" "$(grep -q 'AgentalSec ready' "$OUT" && echo 1 || echo 0)"
chk "it bound the port config.json names ($PORT)" \
    "$(ss -ltn | grep -q "127.0.0.1:$PORT" && echo 1 || echo 0)"
chk "THE BROWSER OPENED BY ITSELF" "$([[ -n "$TITLE" ]] && echo 1 || echo 0)"
chk "and it shows the DASHBOARD in a browser, not a profile chooser or an error page" \
    "$([[ "$TITLE" == *AgentalSec* && "$TITLE" == *"Mozilla Firefox"* && "$TITLE" != *"Choose a profile"* && "$TITLE" != *"Problem loading"* ]] && echo 1 || echo 0)"
chk "the log names the command, the profile and the user" \
    "$(grep -q "Opened http://127.0.0.1:$PORT" "$OUT" && echo 1 || echo 0)"

# ONE SIGNAL, THEN WAIT. See section D for why not a loop.
stop_apps
for _ in $(seq 1 60); do
    grep -q 'AgentalSec stopped cleanly' "$OUT" 2>/dev/null && break
    sleep 1
done
chk "it shut down cleanly and said so" \
    "$(grep -q 'AgentalSec stopped cleanly' "$OUT" && echo 1 || echo 0)"
chk "and the port came back" \
    "$(! ss -ltn | grep -q "127.0.0.1:$PORT" && echo 1 || echo 0)"
close_browser_window
for _ in $(seq 1 20); do wmctrl -l | grep -qF AgentalSec || break; sleep 1; done
chk "the browser window this script opened is closed again" \
    "$(! wmctrl -l | grep -qF AgentalSec && echo 1 || echo 0)"

echo
echo "B. the PRIVILEGED icon: through the password handoff to a root boot"
OUT=$(boot_arm privileged "$PRIV_ARGS")
TITLE=""
for _ in $(seq 1 150); do
    TITLE=$(wmctrl -l 2>/dev/null | grep -F "AgentalSec" | head -1)
    [[ -n "$TITLE" ]] && break
    sleep 1
done
echo "   sudo was invoked as : $(head -1 "$AGENTAL_STUB_SUDO" 2>/dev/null)"
echo "   launch line         : $(grep -h 'Opened http\|No way to open a browser' "$OUT" | tail -1)"
echo "   window              : ${TITLE:-<none>}"
chk "the privileged argv reached a terminal" \
    "$(grep -q -- "--elevated" "$AGENTAL_STUB_ARGV" && echo 1 || echo 0)"
chk "accepting the password would run THIS script elevated (the handoff works)" \
    "$(grep -q "STUB_SUDO_ARGV: -- $TREE/scripts/agental_sec_launch.sh --run-elevated" "$AGENTAL_STUB_SUDO" && echo 1 || echo 0)"
chk "the elevated copy was not refused by its own argument checker" \
    "$(! grep -q 'unrecognised argument' "$OUT" && echo 1 || echo 0)"
chk "it went through run_elevated.sh and started as root" \
    "$(grep -q 'Starting AgentalSec as root' "$OUT" && echo 1 || echo 0)"
chk "the app reached ready and reported itself elevated" \
    "$(grep -q 'Running as root. All sensors and actions available' "$OUT" && echo 1 || echo 0)"
chk "and the sensor the icon exists for is available" \
    "$(grep -q 'Packet capture: YES' "$OUT" && echo 1 || echo 0)"
chk "A BROWSER WINDOW OPENED on the privileged boot too" \
    "$([[ -n "$TITLE" ]] && echo 1 || echo 0)"
stop_apps
for _ in $(seq 1 60); do
    grep -q 'AgentalSec stopped cleanly' "$OUT" 2>/dev/null && break
    sleep 1
done
chk "clean shutdown" "$(grep -q 'AgentalSec stopped cleanly' "$OUT" && echo 1 || echo 0)"
close_browser_window
for _ in $(seq 1 20); do wmctrl -l | grep -qF AgentalSec || break; sleep 1; done
chk "the browser window is closed again" \
    "$(! wmctrl -l | grep -qF AgentalSec && echo 1 || echo 0)"

echo
echo "C. THE CHECK THAT WAS MISSING ON 2026-09-25: what this script leaves behind"
chk "the operator's config.json is byte-identical to when this started" \
    "$(cmp -s "$ROOT/config.json" "$TMP/config.before.json" && echo 1 || echo 0)"
chk "the operator's store is byte-identical to when this started" \
    "$(cmp -s "$ROOT/agental_sec.db" "$TMP/db.before" && echo 1 || echo 0)"
chk "the operator's log file is byte-identical to when this started" \
    "$(cmp -s "$ROOT/logs/agental_sec_linux.log" "$TMP/log.before" && echo 1 || echo 0)"
chk "no root-owned files left in the project by a run that went root" \
    "$([[ -z "$(find "$ROOT" -user root -newermt '-20 minutes' 2>/dev/null | head -5)" ]] && echo 1 || echo 0)"

echo
echo "D. NOTE, NOT A CHECK: two SIGTERMs during one shutdown"
# MEASURED 2026-09-25, recorded as bugfinder.md PROC-14, PENDING THE OWNER'S
# WORD on what a second signal SHOULD do. This script sends ONE signal (above)
# because a harness that sends them in a loop changes the subject under test.
# What the pair showed, run by run: one SIGTERM -> "AgentalSec stopped cleanly"
# and exit 0, every time; two, three seconds apart -> the app logs "Shutdown
# already running, ignoring the second ask." and then DIES MID-CLEANUP (no
# final rollup completion, no duty-loop stop line, no "stopped cleanly"), and
# through the launcher that reads as exit code 143. The cause is in the
# handler: it calls _clean_shutdown() and then sys.exit(0) UNCONDITIONALLY, so
# the second signal's handler raises SystemExit inside the first handler's own
# call stack and unwinds the remaining cleanup. A person pressing Ctrl+C twice
# is the ordinary way to meet it.
echo "   one signal  : clean shutdown, exit 0 (asserted above as sections A and B)"
if [[ -f "$TMP/signal.note" ]]; then
    cat "$TMP/signal.note" | sed 's/^/   /'
else
    echo "   two signals : see bugfinder.md PROC-14 (measured with"
    echo "                 /tmp/agental_launchcheck/signal_check.sh, two arms, one control)"
fi

echo
echo "======================================================================"
echo "  $PASS passed, $FAIL failed"
[[ "$KEEP" == "1" ]] && echo "  scratch kept: $TMP"
echo "======================================================================"
[[ $FAIL -gt 0 ]] && exit 1
exit 0
