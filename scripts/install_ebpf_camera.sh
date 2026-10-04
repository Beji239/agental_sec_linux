#!/usr/bin/env bash
# scripts/install_ebpf_camera.sh
# Install the kernel camera as a service, and the ONE thing that makes it
# available to the app. T6, 2026-09-22.
#
# THIS SCRIPT IS THE OPERATIONAL CHANGE. IT NEEDS ROOT AND IT INSTALLS A
# LONG-RUNNING PRIVILEGED PROCESS.
#
# It is written the way scripts/install_read_helper.sh is written, and for the
# same reasons: it PRINTS WHAT IT WILL DO and does it only when asked, it
# validates before it trusts, and it says how to undo the whole thing. A
# security monitor that quietly starts a root daemon is the worst thing this
# project could ship.
#
# Usage:
#     ./scripts/install_ebpf_camera.sh            # show what would change
#     sudo ./scripts/install_ebpf_camera.sh --apply
#     sudo ./scripts/install_ebpf_camera.sh --uninstall
#     ./scripts/install_ebpf_camera.sh --verify   # test the installed camera
#
# WHY THE CAMERA IS INSTALLED OUT OF THE PROJECT TREE
#
# The same argument install_read_helper.sh makes, applied to a bigger
# privilege: the project directory is owned by the operator and is writable by
# them, so a service that runs ROOT out of that directory is a service any
# account which can write the tree can replace. The camera's own code is
# copied into /usr/local/lib/agentalsec/ebpf/, root-owned, mode 0755, and the
# unit runs THAT copy. The tree keeps the source; the machine runs the
# installed one, and `--verify` asserts the two are the same file so an edit
# in the tree cannot silently disagree with what is running.
#
# WHY IT IS A SYSTEMD UNIT AND NOT A LINE IN SOMEBODY'S STARTUP SCRIPT
#
# The whole value of this sensor is that it is watching when nothing else is.
# A camera started by hand, or started by the app, is off whenever the app is
# off -- and it is off exactly when nothing is watching, which is when it
# matters. Restart=always is the load-bearing line: the camera is meant to
# outlive every session, every crash and every reboot.
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAMERA_SRC="$PROJECT_ROOT/ebpf/ebpf_monitor.py"
OBJECT_SRC="$PROJECT_ROOT/ebpf/ebpf_monitor.bpf.o"

INSTALL_DIR="/usr/local/lib/agentalsec/ebpf"
CAMERA_DST="$INSTALL_DIR/ebpf_monitor.py"
OBJECT_DST="$INSTALL_DIR/ebpf_monitor.bpf.o"
UNIT_NAME="agentalsec-ebpf-camera.service"
UNIT_PATH="/etc/systemd/system/$UNIT_NAME"
DATA_DIR="/var/lib/agental_sec"
EVENTS_DB="$DATA_DIR/ebpf_events.db"

REAL_USER="${SUDO_USER:-}"
if [[ -z "$REAL_USER" ]]; then
    REAL_USER="$(stat -c '%U' "$PROJECT_ROOT" 2>/dev/null || echo root)"
fi

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

MODE=""
case "${1:-}" in
    --apply)     MODE=apply ;;
    --uninstall) MODE=uninstall ;;
    --verify)    MODE=verify ;;
    "")          MODE=plan ;;
    *)           die "unrecognised argument '${1}'. Known: (none), --apply, --uninstall, --verify." ;;
esac

say "AgentalSec kernel camera, T6"
say "  project root   : $PROJECT_ROOT"
say "  camera source  : $CAMERA_SRC"
say "  installs to    : $CAMERA_DST   (root-owned, mode 0755)"
say "  object         : $OBJECT_DST"
say "  systemd unit   : $UNIT_PATH"
say "  events file    : $EVENTS_DB  (root writes; $REAL_USER reads)"
say "  real user      : $REAL_USER"
say ""

if [[ ! -f "$CAMERA_SRC" ]]; then
    die "$CAMERA_SRC does not exist, so there is nothing to install."
fi
if [[ ! -s "$OBJECT_SRC" ]]; then
    die "$OBJECT_SRC does not exist or is empty. Build it first:
    bash $PROJECT_ROOT/ebpf/build.sh
The camera cannot load without it, and installing a service that fails at
startup is worse than installing nothing."
fi

# the unit's content, and the lines that matter
#
# A NOTE ON HARDENING, since a reader will ask why there is not more of it. The
# camera's whole job is to load BPF programs and read kernel tracepoints, which
# needs CAP_BPF and CAP_PERFMON (or CAP_SYS_ADMIN on an older kernel) -- so it
# must run as root and cannot be dropped into a sandbox that takes those away.
# What IS taken away is everything else that is cheap to take: no new
# privileges, a read-only system except for its own data directory, no access to
# the operator's home, and no device nodes beyond the ones the kernel itself
# provides. The honest statement is that this is a root process with a narrow
# job, and the reason it is safe to have one is that its only inputs are kernel
# structs and its only output is a SQLite file -- see the camera's own header.
UNIT_CONTENT="$(cat <<EOF
# AgentalSec kernel camera. Installed $(date -u +%Y-%m-%dT%H:%M:%SZ) by
# scripts/install_ebpf_camera.sh.
#
# WHAT THIS IS: ebpf/ebpf_monitor.py, a root-confined process that attaches
# sched_process_exec and sys_enter_connect and writes every event to
# $EVENTS_DB, a file of its own that the app READS. Nothing running as root
# ever opens the app's database -- that one-way street is the whole design.
#
# WHY IT MUST KEEP RUNNING: it is the only sensor in this app that sees an
# execution AT THE MOMENT IT HAPPENS. Every other sensor polls, and a program
# that starts, acts and exits between two polls is invisible to all of them.
# Restart=always is therefore the load-bearing line here.
#
# TO UNDO: sudo $PROJECT_ROOT/scripts/install_ebpf_camera.sh --uninstall
[Unit]
Description=AgentalSec kernel camera (exec and connect events)
Documentation=file:$CAMERA_DST
After=local-fs.target
# A camera that has died repeatedly is restarted no more than this often. It is
# not a rate limit; it is what stops a broken camera from filling the journal
# with one failure every second and burying everything else. THESE TWO BELONG
# IN [Unit] ON MODERN SYSTEMD -- in [Service] they are ignored with a warning,
# which would leave the limit silently not applied.
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/bin/env python3 $CAMERA_DST --out $EVENTS_DB
Restart=always
RestartSec=5

# hardening that does not take away the job
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=$DATA_DIR
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
# NOT set, deliberately, and each for a reason a reader can check:
#   ProtectKernelTunables  would hide /sys/kernel/tracing and stop the attach
#   RestrictAddressFamilies would block the AF_INET sockets the connect event
#                          reports on (the tracepoint itself would still fire,
#                          but the kernel's own accounting would be affected)
#   MemoryDenyWriteExecute would break libbpf's JIT handling
# The honest summary: this needs real privilege, and the design confines that
# privilege to a process whose only inputs are kernel structs and whose only
# output is a SQLite file with bound parameters.

[Install]
WantedBy=multi-user.target
EOF
)"

show_plan() {
    say "WHAT WOULD CHANGE"
    say ""
    say "1. create $INSTALL_DIR (root:root, 0755) and install:"
    say "     $CAMERA_DST   <- $CAMERA_SRC"
    say "     $OBJECT_DST   <- $OBJECT_SRC"
    say "   root-owned, mode 0755, so the service does not run out of a"
    say "   directory the operator can write."
    say ""
    say "2. create $DATA_DIR (root:root, 0755) for the events file. The"
    say "   operator can READ it -- the app does -- and cannot write it."
    say ""
    say "3. create $UNIT_PATH with this content:"
    say ""
    printf '%s\n' "$UNIT_CONTENT" | sed 's/^/     /'
    say ""
    say "4. systemd-analyze verify the unit BEFORE it is trusted, then"
    say "   daemon-reload, enable and start it."
    say ""
    say "5. run the camera's own --check as root and report what it says."
    say "   That is the step that proves this machine can load a BPF program"
    say "   at all, before a service is left running against it."
    say ""
    say "NOTHING ABOVE HAS HAPPENED. Run with --apply as root to do it."
    say ""
    say "ONE THING TO KNOW FIRST: this starts a ROOT PROCESS that keeps"
    say "running after this script exits and after every reboot. That is the"
    say "point of it -- a camera that only watches while somebody is logged in"
    say "is a camera that is off exactly when it matters -- and it is also the"
    say "reason this is a deliberate, printed, undoable step rather than"
    say "something the app does for itself."
}

verify() {
    say "VERIFYING THE INSTALLED CAMERA"
    say ""
    local fails=0

    for f in "$CAMERA_DST" "$OBJECT_DST"; do
        if [[ ! -f "$f" ]]; then
            say "  [FAIL] $f does not exist"
            fails=$((fails+1))
        else
            say "  [PASS] $f is installed ($(stat -c '%s' "$f") bytes)"
        fi
    done
    [[ "$fails" == "0" ]] || { say ""; say "$fails CHECK(S) FAILED."; return 1; }

    # THE INSTALLED COPY MUST BE THE TREE'S COPY. An edit in the project tree
    # that was never re-installed is the shape of a fix that did not take, and
    # it is invisible: the service runs the old file and nothing says so.
    if cmp -s "$CAMERA_SRC" "$CAMERA_DST"; then
        say "  [PASS] the installed camera is byte-identical to the tree's copy"
    else
        say "  [FAIL] the installed camera DIFFERS from $CAMERA_SRC."
        say "         The service is running an older file. Re-run: sudo $0 --apply"
        fails=$((fails+1))
    fi
    if cmp -s "$OBJECT_SRC" "$OBJECT_DST"; then
        say "  [PASS] the installed BPF object is byte-identical too"
    else
        say "  [FAIL] the installed .bpf.o DIFFERS from the built one"
        fails=$((fails+1))
    fi

    local owner mode
    owner="$(stat -c '%U' "$CAMERA_DST")"
    mode="$(stat -c '%a' "$CAMERA_DST")"
    [[ "$owner" == "root" ]] && say "  [PASS] owned by root" \
        || { say "  [FAIL] owned by $owner, not root"; fails=$((fails+1)); }
    if (( (8#$mode & 8#022) == 0 )); then
        say "  [PASS] mode $mode is not group- or world-writable"
    else
        say "  [FAIL] mode $mode IS group- or world-writable, which makes the"
        say "         root service replaceable by a non-root account"
        fails=$((fails+1))
    fi

    say ""
    say "  systemd's own view:"
    if systemctl is-enabled "$UNIT_NAME" >/dev/null 2>&1; then
        say "  [PASS] the unit is enabled (it comes back after a reboot)"
    else
        say "  [FAIL] the unit is NOT enabled: it will not survive a reboot,"
        say "         which for this sensor is the same as not being installed"
        fails=$((fails+1))
    fi
    if systemctl is-active "$UNIT_NAME" >/dev/null 2>&1; then
        say "  [PASS] the unit is ACTIVE (the camera is running now)"
    else
        say "  [FAIL] the unit is NOT active. The app will report no kernel"
        say "         event being collected, which is true and is bad news."
        say "         Look at: journalctl -u $UNIT_NAME -n 30"
        fails=$((fails+1))
    fi

    say ""
    say "  the camera's own report, as root:"
    local out
    # PM-10, 2026-09-23. `sudo -n` ON A HOST WITH NO PASSWORDLESS SUDO returns
    # "sudo: a password is required" and this step reported a FAIL about the
    # camera for a reason that is about sudo. That is the shape this project
    # keeps digging out of itself: a check that fails for its own reason.
    # It falls back to the UNELEVATED --check, which verifies everything
    # except the euid line, and SAYS that is what it did.
    if out="$(sudo -n python3 "$CAMERA_DST" --check 2>&1)"; then
        if printf '%s' "$out" | grep -q 'CAN RUN.*True'; then
            say "  [PASS] the camera says this host CAN RUN it:"
            printf '%s\n' "$out" | sed 's/^/        /' | head -12
        else
            say "  [FAIL] the camera's own --check does not say this host can run:"
            printf '%s\n' "$out" | sed 's/^/        /' | head -12
            fails=$((fails+1))
        fi
    else
        say "  [NOTE] sudo needs a password on this host, so the as-root check"
        say "         cannot run from here. Running the unelevated --check"
        say "         instead: it verifies the kernel, BTF, the sysctls and the"
        say "         object, and it cannot verify the euid line. That is a"
        say "         limitation of this verification, not a fault in the camera."
        out="$(python3 "$CAMERA_DST" --check 2>&1)"
        if printf '%s' "$out" | grep -q 'CAN RUN.*True'; then
            say "  [PASS] (unelevated) the camera says this host CAN RUN it:"
            printf '%s\n' "$out" | sed 's/^/        /' | head -12
        else
            say "  [FAIL] (unelevated) the camera's --check does not say this host can run:"
            printf '%s\n' "$out" | sed 's/^/        /' | head -12
            fails=$((fails+1))
        fi
    fi

    say ""
    say "  THE EVENTS FILE, AND WHETHER WHAT IS BEING WRITTEN IS REAL:"
    if [[ ! -f "$EVENTS_DB" ]]; then
        say "  [FAIL] $EVENTS_DB does not exist. The service may have just"
        say "         started; give it a few seconds and re-run --verify."
        fails=$((fails+1))
    else
        python3 - "$EVENTS_DB" <<'PY'
import sqlite3, sys, time
from datetime import datetime, timezone
path = sys.argv[1]
try:
    conn = sqlite3.connect("file:%s?immutable=1" % path, uri=True)
    total = conn.execute("SELECT COUNT(*) FROM ebpf_event").fetchone()[0]
    newest = conn.execute(
        "SELECT MAX(recorded_at) FROM ebpf_event").fetchone()[0]
    # THE HEALTH COLUMNS ARE READ OFF THE TABLE, not named in the query, for
    # AD10's reason: a camera file written before a column existed would raise
    # on the SELECT and this step would report "could not read the events file"
    # for a file that is fine. `callback_errors` is the column that arrived
    # with the decode-failure count, and it is reported when it is there.
    have = {r[1] for r in conn.execute("PRAGMA table_info(ebpf_health)")}
    wanted = [c for c in ("at", "dropped_exec", "dropped_connect",
                          "callback_errors") if c in have]
    health = None
    if wanted:
        health = conn.execute(
            "SELECT %s FROM ebpf_health ORDER BY id DESC LIMIT 1"
            % ", ".join(wanted)).fetchone()
    print("        events on file : %d" % total)
    print("        newest event   : %s" % newest)
    if health:
        got = dict(zip(wanted, health))
        line = ("        last health row: %s (dropped exec=%s connect=%s"
                % (got.get("at"), got.get("dropped_exec"),
                   got.get("dropped_connect")))
        if "callback_errors" in got:
            line += ", undecodable=%s" % got["callback_errors"]
        print(line + ")")
    conn.close()
except Exception as e:
    print("        could not read the events file: %s" % e)
PY
    fi

    say ""
    if (( fails == 0 )); then
        say "ALL CHECKS PASSED. Nothing was changed by this verification."
    else
        say "$fails CHECK(S) FAILED."
    fi
    return $(( fails > 0 ? 1 : 0 ))
}

apply() {
    [[ "$(id -u)" == "0" ]] || die "--apply must run as root: sudo $0 --apply"

    say "INSTALLING"

    # VALIDATE THE UNIT BEFORE IT IS TRUSTED.
    #
    # Same ordering as the sudoers drop-in, for a weaker version of the same
    # reason: a malformed unit is not dangerous, it is simply a service that
    # never starts, and the operator would find out by noticing that nothing
    # was being recorded -- which is the failure this whole sensor exists to
    # make impossible to miss.
    local tmp
    tmp="$(mktemp)" || die "mktemp failed"
    printf '%s\n' "$UNIT_CONTENT" > "$tmp"
    if command -v systemd-analyze >/dev/null 2>&1; then
        local check
        check="$(systemd-analyze verify "$tmp" 2>&1)"
        if printf '%s' "$check" | grep -qi 'error'; then
            rm -f "$tmp"
            die "systemd-analyze refused the unit, so nothing was installed.
It said: $check"
        fi
        say "  systemd-analyze accepts the unit"
    else
        say "  systemd-analyze is not installed; skipping the unit pre-check"
    fi

    # THE CAMERA'S OWN --check AS ROOT, BEFORE ANYTHING IS INSTALLED. This is
    # the one command that answers "can this machine load a BPF program at
    # all" -- BPF disabled in the kernel, no BTF, a lockdown policy -- and
    # finding out now costs nothing. Finding out later costs a service that
    # restarts forever.
    say ""
    say "  asking the camera whether this host can run it (as root):"
    local out
    out="$(python3 "$CAMERA_SRC" --check 2>&1)"
    printf '%s\n' "$out" | sed 's/^/      /' | head -14
    if ! printf '%s' "$out" | grep -q 'CAN RUN.*True'; then
        rm -f "$tmp"
        die "the camera says this host CANNOT run it, so nothing was installed.
The lines above name why. Installing a service that cannot start would leave a
restart loop in the journal and no events, which reads as a quiet machine."
    fi
    say "  it says this host can run the camera."

    install -d -o root -g root -m 0755 "$INSTALL_DIR" || die "could not create $INSTALL_DIR"
    install -o root -g root -m 0755 "$CAMERA_SRC" "$CAMERA_DST" || die "could not install the camera"
    say "  installed $CAMERA_DST (root:root, 0755)"
    install -o root -g root -m 0644 "$OBJECT_SRC" "$OBJECT_DST" || die "could not install the object"
    say "  installed $OBJECT_DST ($(stat -c '%s' "$OBJECT_DST") bytes, root:root, 0644)"

    # THE DATA DIRECTORY IS WORLD-READABLE AND ROOT-WRITABLE, deliberately. The
    # app runs as the operator and must be able to READ the events; only root
    # writes them.
    install -d -o root -g root -m 0755 "$DATA_DIR" || die "could not create $DATA_DIR"
    say "  created/confirmed $DATA_DIR (root:root, 0755 -- readable by $REAL_USER)"

    install -o root -g root -m 0644 "$tmp" "$UNIT_PATH" || die "could not install the unit"
    rm -f "$tmp"
    say "  installed $UNIT_PATH"

    systemctl daemon-reload || die "systemctl daemon-reload failed"
    systemctl enable "$UNIT_NAME" >/dev/null 2>&1 \
        && say "  enabled $UNIT_NAME (it will start on boot)" \
        || say "  WARNING: could not enable the unit; it will not survive a reboot"
    systemctl restart "$UNIT_NAME" || die "could not start the unit"

    say "  started. Waiting a few seconds for events to appear..."
    sleep 6

    # PM-10, 2026-09-23. A CRASH-LOOPING CAMERA MUST NOT BE LEFT
    # INSTALLED AND CALLED DONE.
    #
    # MEASURED on this host: the unit was installed, enabled and FAILED — five
    # restarts, then "Start request repeated too quickly". The install script
    # printed a status block and moved on, so the machine was left with
    # `enabled` + `failed`, no events, and an app that reads no events. That
    # state is indistinguishable, from the dashboard, from a quiet machine,
    # which is the one failure this whole sensor exists to prevent.
    #
    # The cause was a name: `_libbpf()` wired up `bpf_get_error`, which libbpf
    # 1.3.0 does not export, so the process died before it could even say why.
    # FIXED in ebpf/ebpf_monitor.py. This is the check that would have caught
    # it at install time instead of at the next dashboard read.
    if ! systemctl is-active "$UNIT_NAME" >/dev/null 2>&1; then
        say ""
        say "  [FAIL] the unit is NOT active after being started. It is"
        say "         installed and enabled, and it is not recording anything."
        say ""
        say "  the last lines of its journal:"
        journalctl -u "$UNIT_NAME" -n 12 --no-pager 2>/dev/null | sed 's/^/      /' \
            || say "      (journalctl could not be read)"
        say ""
        say "  THE UNIT HAS BEEN LEFT RUNNING (systemd will keep retrying), because"
        say "  removing it is the operator's call and the journal above is the"
        say "  evidence. To remove it:  sudo $0 --uninstall"
        die "the camera did not start, so this install is NOT verified."
    fi
    say "  [PASS] the unit is active."

    say ""
    say "WHAT IS HAPPENING NOW"
    systemctl status "$UNIT_NAME" --no-pager -n 8 2>/dev/null | sed 's/^/  /' || true
    say ""
    say "The camera writes: $EVENTS_DB"
    say "The app reads it as $REAL_USER. Nothing running as root opens the"
    say "app's own database; that one-way street is the design."
    say ""
    say "TO UNDO EVERYTHING:  sudo $0 --uninstall"
    say "Run '$0 --verify' to test it, including whether events are arriving."
}

uninstall() {
    [[ "$(id -u)" == "0" ]] || die "--uninstall must run as root"
    say "REMOVING"
    if systemctl is-active "$UNIT_NAME" >/dev/null 2>&1; then
        systemctl stop "$UNIT_NAME" && say "  stopped $UNIT_NAME"
    fi
    if systemctl is-enabled "$UNIT_NAME" >/dev/null 2>&1; then
        systemctl disable "$UNIT_NAME" >/dev/null 2>&1 && say "  disabled $UNIT_NAME"
    fi
    [[ -f "$UNIT_PATH" ]] && rm -f "$UNIT_PATH" && say "  removed $UNIT_PATH"
    systemctl daemon-reload 2>/dev/null

    for f in "$CAMERA_DST" "$OBJECT_DST"; do
        [[ -f "$f" ]] && rm -f "$f" && say "  removed $f"
    done
    rmdir "$INSTALL_DIR" 2>/dev/null && say "  removed $INSTALL_DIR" \
        || say "  left $INSTALL_DIR in place (not empty)"

    say ""
    say "THE EVENTS FILE IS LEFT ALONE, deliberately: $EVENTS_DB holds the"
    say "kernel record of what this machine did while the camera was running,"
    say "and deleting evidence is not this script's job."
    say ""
    say "The app now reports that no camera is installed. It does NOT report"
    say "blind, and it does not fail: it says in words that nothing is"
    say "recorded at the moment it happens, which is a limit of the machine"
    say "rather than a fault in the app."
}

case "$MODE" in
    plan)      show_plan ;;
    apply)     apply ;;
    uninstall) uninstall ;;
    verify)    verify ;;
esac
