#!/usr/bin/env bash
# scripts/run_elevated.sh
# Start AgentalSec with the privileges its sensors need, without leaving the
# project directory owned by root.
#
# WHY THIS IS A SCRIPT AND NOT A LINE IN A README
#
# Plain `sudo python3 main.py` FAILS on this machine, and it fails in a way
# that looks like a broken install:
#
#   1. ROOT'S PYTHON CANNOT SEE YOUR PACKAGES. flask, waitress, scapy and
#      httpx are installed under ~/.local/lib/python3.x. Python
#      resolves that directory from $HOME, so under sudo (HOME=/root) it
#      looks in /root/.local instead, finds nothing, and the boot stops at
#      "MISSING CRITICAL DEPENDENCIES: flask, flask-cors, ...". Measured
#      2026-09-17: `HOME=/root python3 -c "import scapy"` -> ModuleNotFoundError.
#      The fix is an explicit PYTHONPATH, which is what this script sets.
#
#   2. THE RUN IS ROOT, SO THE FILES IT TOUCHES BECOME ROOT-OWNED. This has
#      already bitten once: an earlier `sudo python3 main.py` left
#      logs/agental_sec_linux.log owned by root, and every unelevated boot
#      since then has fallen back to a per-run log file and left no durable
#      record at the usual path. The app now works around that and says so,
#      but the clean answer is to hand the files back when the run ends,
#      which is what this script's exit trap does.
#
#      Ownership is restored for: logs/, agental_sec.db and its -wal/-shm
#      side files, config.json and .env. Nothing else in the tree is touched
#      by a normal run, and if that ever changes, add it to OWN_BACK below.
#
#   3. HOME IS PRESERVED, deliberately. The app decides where quarantine
#      lives with Path.home() ("~/Desktop/AgentalSec_Quarantine"), so a run
#      with HOME=/root would put quarantined files somewhere you would never
#      look for them. Preserving your HOME keeps elevated and unelevated runs
#      behaving identically apart from privilege.
#
# WHAT YOU GET WHEN THIS RUNS ELEVATED
#
#   packet_sniffer    raw capture (AF_PACKET), so there ARE packet rows, the
#                     beacon analysis runs and the threat map has arcs
#   event_monitor     full journald access, not just your own log entries
#   remediation       ufw rules can actually be written and removed
#   process_monitor   command lines for other users' processes are readable
#   port ownership    every listening socket's OWNER is named. Unelevated,
#                     a port held by a service running as another account is
#                     reported unreadable_as_user: what is listening is
#                     visible and who holds it is not. Measured on this
#                     host: 0 of 13 listeners matched unelevated, 142 of 216
#                     processes' fd directories refused. Added 2026-09-25,
#                     register PS-13 -- this list did not mention it.
#   port_scanner      the TCP pass sends real SYNs, so a CLOSED port and a
#                     FILTERED one are told apart. Unelevated it falls back
#                     to a connect test, which cannot make that separation.
#
# Unelevated, all six degrade and each says so in its own words. Neither is
# wrong; they answer different questions, and the app is careful to say which
# one you are reading.
#
# Usage:
#     ./scripts/run_elevated.sh            # diagnose, change nothing
#     sudo ./scripts/run_elevated.sh       # actually start the app as root
#     sudo ./scripts/run_elevated.sh --check   # same diagnosis, as root

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Defined before the argument loop rather than after it, because the loop now
# calls die () on an unrecognised flag. With the definitions below the loop,
# that call would have been "command not found" — exit 127 from the subshell,
# the loop carrying on, and the app starting as root anyway, which is the
# exact bug the refusal was added to stop.
say()  { printf '%s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

CHECK_ONLY=0
RUN_NOW=0
for arg in "$@"; do
    case "$arg" in
        --check)        CHECK_ONLY=1 ;;
        # --run-elevated: skip the diagnosis and start immediately. This is
        # what scripts/agental_sec_launch.sh calls, and the diagnosis is
        # skipped for a reason rather than for speed: that path has already
        # shown the operator what is about to happen and taken a password for
        # it, so printing twenty more lines of report between the password
        # and the app is noise at the worst possible moment. Running this
        # script BY HAND (no flags) still prints the whole picture, which is
        # the way it is meant to be read.
        --run-elevated) RUN_NOW=1 ;;
        # AN UNRECOGNISED ARGUMENT IS REFUSED, NOT IGNORED. 2026-09-18
        #
        # This one was found by looking at this loop rather than by watching
        # it fail, and it is the same class as the defect that made the
        # privileged launcher exit 1: `sudo ./run_elevated.sh --diganose` (a
        # typo) fell through the case and STARTED THE APP AS ROOT, because
        # ignoring a flag here means "no --check, no --run-elevated" and the
        # root path below runs anyway. Starting a monitoring run by accident
        # is silent, because starting the app is a perfectly normal thing to
        # do — the same sentence agental_sec_launch.sh already lives by.
        *) die "unrecognised argument '$arg'.
Nothing was started. Known arguments: (none), --check, --run-elevated." ;;
    esac
done

# who is the real user
#
# SUDO_USER is the person who ran sudo. It is EMPTY when the script is run
# from a root shell, which is a real case worth handling rather than guessing
# at: the answer then is whoever owns the project directory, because that is
# the account whose files are about to be written to.
REAL_USER="${SUDO_USER:-}"
if [[ -z "$REAL_USER" ]]; then
    REAL_USER="$(stat -c '%U' "$PROJECT_ROOT" 2>/dev/null || echo root)"
fi
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
[[ -n "$REAL_HOME" ]] || REAL_HOME="$PROJECT_ROOT"

PY_MINOR="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
USER_SITE="$REAL_HOME/.local/lib/python${PY_MINOR}/site-packages"

# what this run would do
#
# Skipped entirely under --run-elevated. See the flag note at the top: that
# path has already shown the operator what is happening and taken a password
# for it, so a report here would be printed between the password and the app.

if [[ "$RUN_NOW" != "1" ]]; then

say "AgentalSec elevated launcher"
say "  project root : $PROJECT_ROOT"
say "  python       : $(command -v python3)  ($(python3 --version 2>&1))"
say "  real user    : $REAL_USER  (home: $REAL_HOME)"
say "  user site    : $USER_SITE"
say "  HOME kept as : $REAL_HOME"
say ""

# The dependency question, answered the way root will actually see it.
MISSING=""
for mod in flask flask_cors waitress httpx psutil scapy; do
    if ! PYTHONPATH="$USER_SITE" python3 -c "import $mod" 2>/dev/null; then
        MISSING="$MISSING $mod"
    fi
done
if [[ -n "$MISSING" ]]; then
    say "  !! these do not import even WITH the PYTHONPATH set:$MISSING"
    say "     Run: pip install -r requirements.txt  (or --break-system-packages)"
else
    say "  packages     : flask, flask_cors, waitress, httpx, psutil, scapy all import"
fi
say ""

# Would root's python find them WITHOUT the help? Worth showing, because it is
# the exact thing that makes a bare sudo run look like a broken install.
if HOME=/root python3 -c "import scapy" 2>/dev/null; then
    say "  note: root's python finds scapy on its own here, so PYTHONPATH is"
    say "        belt-and-braces rather than load-bearing on this machine."
else
    say "  note: root's python does NOT find scapy without PYTHONPATH — which is"
    say "        exactly why a bare 'sudo python3 main.py' fails here."
fi
say ""

# the ownership that will need handing back

say "  files this script hands back to $REAL_USER when the app exits:"
for path in "$PROJECT_ROOT/logs" "$PROJECT_ROOT/agental_sec.db" \
            "$PROJECT_ROOT/config.json" "$PROJECT_ROOT/.env"; do
    if [[ -e "$path" ]]; then
        say "    $(stat -c '%A %U:%G' "$path")  ${path#$PROJECT_ROOT/}"
    else
        say "    (absent)  ${path#$PROJECT_ROOT/}"
    fi
done
say ""

fi  # end of the skipped diagnosis block

if [[ "$CHECK_ONLY" == "1" || ( "$EUID" -ne 0 && "$RUN_NOW" != "1" ) ]]; then
    say "This was a diagnosis. Nothing was started and nothing was changed."
    if [[ "$EUID" -ne 0 ]]; then
        say ""
        say "To actually run the app elevated:"
        say "    cd $PROJECT_ROOT && sudo ./scripts/run_elevated.sh"
        say ""
        say "Or use the privileged launcher icon, which does all of the above"
        say "for you: agental_sec_launch.sh --elevated"
    fi
    exit 0
fi

if [[ "$EUID" -ne 0 ]]; then
    # --run-elevated but NOT root. The launcher only passes this flag to the
    # sudo'd copy of itself, so reaching here means something invoked the
    # script directly with the flag and no privilege. Refusing is the whole
    # point: silently starting unelevated would give a window that says
    # "privileged boot" and a capture sensor that is blind.
    say "ERROR: --run-elevated was asked for but this process is not root" >&2
    say "       (EUID=$EUID). Nothing was started, because starting" >&2
    say "       unelevated under that flag is the exact confusion this" >&2
    say "       launcher exists to prevent." >&2
    exit 1
fi

# hand-back on any exit, AND ON THE SIGNALS THAT DO NOT UNWIND
#
# Runs on a clean Ctrl+C as well as on a crash, because the failure this
# guards against does not care which one happened. chown is silent about
# paths that do not exist, and the whole thing is best-effort: a failure to
# tidy up must not replace whatever the app was doing.
#
# THE TRAP NOW HANDLES TERM/INT ITSELF RATHER THAN LETTING THE SHELL ACT ON
# IT. 2026-09-18: the privileged boot that died on a held port left
# logs/agental_sec_linux.log owned by root, and the reason was not the app —
# bash runs the EXIT trap only after a trapped signal has been handled, and a
# run killed through a launcher-owned terminal does not always get that far.
# Trapping the signal, doing the hand-back and then re-raising the same
# signal keeps the exit code the launcher reports (`128+n`) while making the
# ownership hand-back unconditional.
_handed_back=0
cleanup() {
    local rc=$?
    if [[ "$_handed_back" == "1" ]]; then
        return
    fi
    _handed_back=1
    say ""
    say "Handing ownership back to $REAL_USER..."
    for path in "$PROJECT_ROOT/logs" \
                "$PROJECT_ROOT/logs/agental_sec_linux.log" \
                "$PROJECT_ROOT/agental_sec.db" \
                "$PROJECT_ROOT/agental_sec.db-wal" \
                "$PROJECT_ROOT/agental_sec.db-shm" \
                "$PROJECT_ROOT/config.json" \
                "$PROJECT_ROOT/.env"; do
        [[ -e "$path" ]] || continue
        if [[ "$(stat -c '%U' "$path")" == "root" ]]; then
            chown "$REAL_USER":"$(id -gn "$REAL_USER")" "$path" 2>/dev/null \
                && say "  returned: ${path#$PROJECT_ROOT/}"
        fi
    done
    say "Done. The next unelevated run will use the usual log file."
    return $rc
}

_on_signal() {
    local sig="$1"
    cleanup
    trap - "$sig"
    kill -s "$sig" $$
}

trap cleanup EXIT
trap '_on_signal INT'  INT
trap '_on_signal TERM' TERM

# run it

say "Starting AgentalSec as root (Ctrl+C to stop)..."
say ""

cd "$PROJECT_ROOT" || die "could not cd to $PROJECT_ROOT"

HOME="$REAL_HOME" \
PYTHONPATH="$USER_SITE:$PROJECT_ROOT" \
python3 main.py
