#!/usr/bin/env bash
# scripts/agental_sec_launch.sh
# The one entry point both desktop launchers call.
#
# WHY THIS EXISTS
#
# There are two launcher icons: AgentalSec and AgentalSec (privileged). They
# are the same application started two ways, and everything that differs
# between those two ways is in this file rather than in two .desktop files
# that would drift apart the first time one of them was edited.
#
#   agental_sec_launch.sh              normal boot, as you
#   agental_sec_launch.sh --elevated   privileged boot, via sudo
#
# THREE THINGS THIS FILE DECIDES, EACH BECAUSE THE ALTERNATIVE FAILED HERE
#
# 1. WHY SUDO AND NOT pkexec. pkexec is the "modern" way to ask for a
#    password and it is the wrong answer on THIS machine, measured rather
#    than assumed: there is no polkit AUTHENTICATION AGENT running here
#    (`ps` shows polkitd, which is the daemon, and no
#    *authentication-agent* process). pkexec with no agent does not fail
#    cleanly — it HANGS, waiting for an agent that will never answer. A
#    launcher that hangs on double-click with no window and no error is worse
#    than one that opens a terminal and asks for a password the ordinary way.
#    Re-check with:  ps -eo args | grep authentication-agent
#
# 2. WHY A TERMINAL WINDOW. Three reasons, and the third is the real one.
#      - sudo needs somewhere to type the password.
#      - the app logs to a console and that output is the first thing you
#        want when something is wrong; with no terminal it goes nowhere.
#      - WHEN THE APP STOPS, YOU SEE WHY. A launcher that silently exits
#        leaves a window that appeared and vanished, and the single most
#        common cause here is the password prompt being declined.
#    The window stays open afterwards only if the run was NOT clean, so a
#    normal quit does not leave a terminal sitting there.
#
# 3. WHY THE ELEVATED PATH RE-EXECS ITSELF UNDER SUDO rather than asking the
#    .desktop file to run `sudo`. A .desktop file cannot contain a pipeline
#    and cannot prompt; making it run `sudo script` would put the password
#    prompt in a process with no terminal to prompt on. So the .desktop calls
#    this script, the script opens a terminal, and the script elevates from
#    inside that terminal where there is somewhere to type.
#
# WHAT ELEVATION ACTUALLY BUYS (so the icon is not a promise it cannot keep)
#
#   packet_sniffer    raw capture, so there ARE packet rows and the threat
#                     map has arcs. Unelevated this sensor is BLIND and says
#                     so on every tool result that depends on it.
#   event_monitor     full journald, not just your own entries
#   remediation       ufw rules can actually be written and removed
#   process_monitor   other users' command lines are readable
#   port ownership    every listener's OWNER is named. Unelevated, a port
#                     held by a service running as another account reports
#                     unreadable_as_user: what is listening is visible and
#                     who holds it is not. (Added 2026-09-25, register
#                     PS-13 -- it was missing from this list, from
#                     run_elevated.sh's and from HOW_TO_START.txt.)
#   port_scanner      the TCP pass sends real SYNs, so a CLOSED port and a
#                     FILTERED one are told apart. Unelevated it falls back
#                     to a connect test, which cannot.
#
# Neither mode is wrong. They answer different questions and the app is
# careful to say which one you are reading.

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
ELEVATED=0
VERBOSE=""

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# the terminal wrapper, AND IT RUNS FIRST
#
# Called by the .desktop file, which passes `--in-terminal` plus whichever
# mode flag it wants. Opens a terminal running this script in its ordinary
# mode.
#
# THREE THINGS HERE WERE WRONG IN THE FIRST VERSION. All three were found by
# running it against a stub terminal and reading the argv it actually
# received, not by clicking the icon and hoping:
#
#   1. THE FLAG ORDER. The desktop entries write `--elevated --in-terminal`,
#      but this branch originally required --in-terminal to be "$1", so the
#      privileged icon fell through to the argument checker and was refused.
#      The mode is now detected by scanning the whole argument list.
#
#   2. THE QUOTING. `"$0" "$@"` sat inside single quotes for `bash -c`, so the
#      inner shell received those characters literally. bash -c takes $0 from
#      its first extra argument, which is not where a script path belongs. The
#      path is now passed as an explicit positional parameter.
#
#   3. THE TERMINAL'S INTERFACE, which is the one that mattered most.
#      On this machine `x-terminal-emulator` is a PERL SHIM, not a terminal
#      (see /usr/bin/x-terminal-emulator). It understands xterm flags ONLY and
#      silently DISCARDS anything else before exec'ing gnome-terminal — so
#      `--wait`, `--title=` and even the `--` separator were dropped on the
#      floor and the command never ran. Every terminal gets its own branch
#      below, chosen by how that binary actually parses, because a launcher
#      that builds a command line nobody accepts fails silently and looks
#      like a broken app.
#
# The rule this leaves behind: a launcher's command line is not correct
# because it looks correct. Test it against a stub that prints its argv.

# Which terminal, and what it is really called. x-terminal-emulator is tried
# LAST despite existing here, because it is a shim whose behaviour depends on
# which real terminal it execs — asking for the real one is more honest.
TERM_PICK=""
for t in gnome-terminal xfce4-terminal konsole alacritty kitty xterm \
         x-terminal-emulator; do
    if command -v "$t" >/dev/null 2>&1; then TERM_PICK="$t"; break; fi
done

if [[ " $* " == *" --in-terminal "* ]]; then
    [[ -n "$TERM_PICK" ]] || die "No terminal emulator found. Install one, or
run the app directly:  cd $PROJECT_ROOT && python3 main.py"

    # Everything except --in-terminal, which must not be passed on or the
    # inner run would open a terminal inside a terminal forever.
    MODE_ARGS=()
    for a in "$@"; do
        [[ "$a" == "--in-terminal" ]] && continue
        MODE_ARGS+=("$a")
    done

    TITLE="AgentalSec"
    for a in ${MODE_ARGS[@]+"${MODE_ARGS[@]}"}; do
        [[ "$a" == "--elevated" || "$a" == "-e" ]] && TITLE="AgentalSec — privileged"
    done

    # Run the launcher, then hold the window open ONLY on failure, so the
    # reason survives the window closing. A clean quit closes its own window,
    # which is what a launcher is supposed to do.
    #
    # "$1" is the path we hand in as a positional parameter; "${@:2}" is the
    # mode flags. Neither depends on how the terminal assigns $0.
    INNER='rc=0; "$1" "${@:2}" || rc=$?; \
if [ "$rc" -ne 0 ]; then \
  echo; echo "AgentalSec launcher exited with code $rc."; \
  echo "Press Enter to close this window."; read -r _ || true; fi'

    case "$(basename "$TERM_PICK")" in
        gnome-terminal|xfce4-terminal)
            # Both accept `--` followed by the command, and both accept a
            # title flag. `--wait` keeps the caller alive until the window
            # closes, which is what makes the exit-code handling work.
            exec "$TERM_PICK" --wait --title="$TITLE" -- \
                 bash -c "$INNER" _ "$SELF" "${MODE_ARGS[@]+"${MODE_ARGS[@]}"}" ;;
        konsole)
            exec "$TERM_PICK" --hold -p "tabtitle=$TITLE" -e \
                 bash -c "$INNER" _ "$SELF" "${MODE_ARGS[@]+"${MODE_ARGS[@]}"}" ;;
        *)
            # xterm-family and the rest: -title and -e, which is the
            # spelling they actually parse.
            exec "$TERM_PICK" -title "$TITLE" -e \
                 bash -c "$INNER" _ "$SELF" "${MODE_ARGS[@]+"${MODE_ARGS[@]}"}" ;;
    esac
fi

for arg in "$@"; do
    # --in-terminal never reaches here in practice (the wrapper above consumes
    # it), but it is accepted rather than refused so that a future caller
    # cannot be broken by the ordering of this file.
    case "$arg" in
        --elevated|-e)  ELEVATED=1 ;;
        # --run-elevated: THE FLAG THIS SCRIPT SENDS TO ITS OWN SUDO'D
        # COPY, AND THE ONE ARGUMENT IT USED TO REFUSE. 2026-09-18
        #
        # Found by reproducing the click, not by reading: the privileged icon
        # asked for the password, sudo accepted it, and the root copy then
        # hit the `*)` arm below, refused `--run-elevated` as an
        # unrecognised argument, and exited 1. The password worked and
        # nothing started.
        #
        # The reason it survived every earlier test is the shape of the gap:
        # this argv only exists AFTER a successful password, and a password
        # is the one thing a test cannot supply. The wrapper, the icon
        # argv, the sudo prompt and `run_elevated.sh --run-elevated` were
        # each verified; the single line between the prompt and the
        # elevator was not.
        #
        # It is an ALIAS FOR --elevated and not a no-op, deliberately. Every
        # other flag in this file is answered by EUID rather than by itself,
        # and this one is no different: a root copy skips the handoff below
        # and goes straight through run_elevated.sh; an unelevated copy gets
        # the ordinary sudo prompt. A no-op would instead let an unelevated
        # `--run-elevated` fall all the way through and start the LESS safe
        # mode while looking like a privileged boot, which is the exact
        # failure this file was written to prevent.
        --run-elevated) ELEVATED=1 ;;
        --help|-h)      VERBOSE=help ;;
        --in-terminal)  ;;
        # ANY OTHER ARGUMENT IS REFUSED RATHER THAN IGNORED. This was found
        # by running it: `--help` fell through to main() and STARTED THE APP.
        # A launcher that treats an unrecognised flag as "go" is a launcher
        # where every typo is a live monitoring run, and the failure is
        # silent because starting the app is a perfectly normal thing to do.
        *) VERBOSE="unknown:$arg" ;;
    esac
done

if [[ "$VERBOSE" == "help" ]]; then
    cat <<'EOF'
agental_sec_launch.sh — start AgentalSec.

  (no arguments)     normal boot, running as you
  --elevated, -e     privileged boot, via sudo (asks for your password)
  --in-terminal      what the desktop icons use: opens a terminal first

Nothing above was started. Run it with no arguments to launch the app.
EOF
    exit 0
fi

if [[ "$VERBOSE" == unknown:* ]]; then
    die "unrecognised argument '${VERBOSE#unknown:}'.
Nothing was started. Known arguments: --elevated, --in-terminal, --help.
A launcher that ignores an argument it does not understand is a launcher
where a typo starts a monitoring run by accident."
fi

# am I already elevated?
#
# The check is EUID, not "did I pass --elevated". A run started by hand as
# root should behave exactly like one started by the privileged icon; the
# privilege is the fact, the flag is only how you asked for it.
IS_ROOT=0
[[ "$EUID" -eq 0 ]] && IS_ROOT=1

# The person, not the account. Under sudo these differ, and every one of them
# matters: HOME decides where quarantine lands, and the log/DB ownership has
# to go back to the human.
REAL_USER="${SUDO_USER:-$(id -un)}"
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
[[ -n "$REAL_HOME" ]] || REAL_HOME="$PROJECT_ROOT"

main() {
    cd "$PROJECT_ROOT" || die "could not enter $PROJECT_ROOT"

    if [[ ! -f main.py ]]; then
        die "main.py is not in $PROJECT_ROOT. This launcher has been moved or
the project folder was, and it is not going to guess which."
    fi

    local python
    python="$(command -v python3)" || die "python3 not found on PATH"

    if [[ "$ELEVATED" == "1" && "$IS_ROOT" == "0" ]]; then
        # Hand off to sudo, and say what is about to happen BEFORE the prompt
        # appears, so a password box that comes out of nowhere is never a
        # surprise and a mistyped icon is never a mystery.
        say "AgentalSec — privileged boot"
        say ""
        say "  This will ask for your password, then start the app as root so"
        say "  the sensors that need raw access can actually work:"
        say "      packet capture, full journald, firewall changes,"
        say "      other users' command lines, port ownership (naming the"
        say "      process behind every open port), and the raw SYN scan"
        say "      (which tells a CLOSED port apart from a FILTERED one)."
        say ""
        say "  Same app, same database, same log. The only difference is"
        say "  privilege, and the app reports which mode it is in."
        say ""
        say "  Nothing is started until you authenticate. Ctrl+C to cancel."
        say ""
        read -r -p "Press Enter to continue, or Ctrl+C to cancel... " _ || true
        say ""
        exec sudo -- "$0" --run-elevated
    fi

    if [[ "$IS_ROOT" == "1" ]]; then
        exec "$PROJECT_ROOT/scripts/run_elevated.sh" --run-elevated
    fi

    say "AgentalSec — normal boot"
    say "  Running as $REAL_USER, without elevation."
    say "  Sensors that need raw access will report themselves as blind"
    say "  rather than pretending. Use the privileged launcher for those."
    say ""
    exec "$python" main.py
}

main "$@"
