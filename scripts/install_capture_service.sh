#!/usr/bin/env bash
# scripts/install_capture_service.sh
# Install the capture service and the names helper, so the app runs without
# root. After this, start AgentalSec with the normal launcher: the dashboard,
# the analyst and the database run as you, with no special rights.
#
#   agentalsec-capture.service  the packet sensor and the LAN checks. Runs as
#                               you, with only the two network capture rights.
#   agentalsec-names.service    the names helper. Runs as root, reads the
#                               kernel's socket tables and writes which program
#                               owns each connection to one file. It accepts
#                               nothing and never sees a packet. Installed as
#                               a root-owned copy, like the kernel camera.
#
# Neither starts at boot. The app starts them when it opens and stops them
# when it quits, through a polkit rule that allows only that.
#
# Usage:
#     ./scripts/install_capture_service.sh             # show what would change
#     sudo ./scripts/install_capture_service.sh --apply
#     sudo ./scripts/install_capture_service.sh --uninstall
#     ./scripts/install_capture_service.sh --verify    # check what is installed
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMES_SRC="$PROJECT_ROOT/tools/names_helper.py"
INSTALL_DIR="/usr/local/lib/agentalsec"
NAMES_DST="$INSTALL_DIR/names_helper.py"
DATA_DIR="/var/lib/agental_sec"
NAMES_FILE="$DATA_DIR/names.json"
CAPTURE_UNIT="agentalsec-capture.service"
NAMES_UNIT="agentalsec-names.service"
UNIT_DIR="/etc/systemd/system"
RULE_FILE="/etc/polkit-1/rules.d/50-agentalsec-capture.rules"
PYTHON="$(command -v python3 || echo /usr/bin/python3)"

REAL_USER="${SUDO_USER:-}"
if [[ -z "$REAL_USER" ]]; then
    REAL_USER="$(stat -c '%U' "$PROJECT_ROOT" 2>/dev/null || echo root)"
fi
REAL_GROUP="$(id -gn "$REAL_USER" 2>/dev/null || echo "$REAL_USER")"

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

[[ -f "$NAMES_SRC" ]] || die "$NAMES_SRC does not exist."
[[ "$REAL_USER" != "root" ]] || die "could not tell who owns the project; run it with sudo from your own account."

NAMES_UNIT_CONTENT="$(cat <<EOF
# AgentalSec names helper. Installed by scripts/install_capture_service.sh.
# Reads the kernel's socket tables every second and writes which program owns
# each connection to $NAMES_FILE, so the capture service, which runs without
# root, still names root's programs. It accepts no input and has no network.
# The app starts it when it opens and stops it when it quits.
# To undo: sudo $PROJECT_ROOT/scripts/install_capture_service.sh --uninstall
[Unit]
Description=AgentalSec names helper (which program owns each connection)
After=local-fs.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/bin/python3 $NAMES_DST --out $NAMES_FILE
Restart=always
RestartSec=2
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$DATA_DIR
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX
IPAddressDeny=any
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
UMask=0027
# Not set, on purpose: PrivateNetwork, which would show the helper its own
# empty network instead of this machine's connections.

[Install]
WantedBy=multi-user.target
EOF
)"

CAPTURE_UNIT_CONTENT="$(cat <<EOF
# AgentalSec capture service. Installed by scripts/install_capture_service.sh.
# The packet sensor and the LAN checks, run as $REAL_USER with only the two
# network capture rights. It reads hostile bytes off the wire, which is why it
# holds nothing else. The dashboard and the analyst run separately, as you.
# The app starts it when it opens and stops it when it quits.
# To undo: sudo $PROJECT_ROOT/scripts/install_capture_service.sh --uninstall
[Unit]
Description=AgentalSec capture service (packets and LAN checks)
After=network-online.target $NAMES_UNIT
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
User=$REAL_USER
Group=$REAL_GROUP
WorkingDirectory=$PROJECT_ROOT
ExecStart=$PYTHON $PROJECT_ROOT/main.py --capture
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$PROJECT_ROOT
PrivateTmp=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
)"

# Lets the app start and stop these two units without a password. Only these
# units, only start and stop, only this account.
RULE_CONTENT="$(cat <<EOF
// AgentalSec, installed by scripts/install_capture_service.sh.
// $REAL_USER may start and stop the names helper and the capture service.
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units" &&
        subject.user == "$REAL_USER" &&
        (action.lookup("unit") == "$NAMES_UNIT" ||
         action.lookup("unit") == "$CAPTURE_UNIT") &&
        (action.lookup("verb") == "start" ||
         action.lookup("verb") == "stop")) {
        return polkit.Result.YES;
    }
});
EOF
)"

show_plan() {
    say "AgentalSec capture service and names helper"
    say "  project      : $PROJECT_ROOT"
    say "  runs as      : $REAL_USER (capture), root (names helper)"
    say ""
    say "WHAT WOULD CHANGE"
    say "1. files in the project owned by root are handed back to $REAL_USER, so"
    say "   the dashboard can run as you"
    say "2. $NAMES_DST  <- $NAMES_SRC  (root-owned, 0755)"
    say "3. $UNIT_DIR/$NAMES_UNIT:"
    printf '%s\n' "$NAMES_UNIT_CONTENT" | sed 's/^/     /'
    say "4. $UNIT_DIR/$CAPTURE_UNIT:"
    printf '%s\n' "$CAPTURE_UNIT_CONTENT" | sed 's/^/     /'
    say "5. $RULE_FILE, so the app can start and stop them:"
    printf '%s\n' "$RULE_CONTENT" | sed 's/^/     /'
    say "6. both units checked with systemd-analyze verify, taken off the boot"
    say "   list, and the names helper's own --check run as root. They start"
    say "   with the app, not at boot."
    say ""
    say "NOTHING ABOVE HAS HAPPENED. Run with sudo and --apply to do it."
}

do_apply() {
    [[ "$(id -u)" -eq 0 ]] || die "--apply needs root: sudo $0 --apply"
    find "$PROJECT_ROOT" -xdev -user root -exec chown "$REAL_USER:$REAL_GROUP" {} + \
        || die "could not hand the project's files back to $REAL_USER"
    install -d -o root -g root -m 0755 "$INSTALL_DIR" || die "mkdir failed"
    # The setgid bit gives names.json the app's group; no other account reads it.
    install -d -o root -g "$REAL_GROUP" -m 2750 "$DATA_DIR" || die "mkdir failed"
    [[ -e "$NAMES_FILE" ]] && { chgrp "$REAL_GROUP" "$NAMES_FILE"; chmod 0640 "$NAMES_FILE"; }
    install -o root -g root -m 0755 "$NAMES_SRC" "$NAMES_DST" || die "copy failed"
    printf '%s\n' "$NAMES_UNIT_CONTENT" > "$UNIT_DIR/$NAMES_UNIT" || die "unit write failed"
    printf '%s\n' "$CAPTURE_UNIT_CONTENT" > "$UNIT_DIR/$CAPTURE_UNIT" || die "unit write failed"
    chmod 0644 "$UNIT_DIR/$NAMES_UNIT" "$UNIT_DIR/$CAPTURE_UNIT"
    if command -v systemd-analyze >/dev/null; then
        systemd-analyze verify "$UNIT_DIR/$NAMES_UNIT" "$UNIT_DIR/$CAPTURE_UNIT" \
            || die "systemd-analyze refused a unit; nothing was started"
    fi
    say "names helper, as root:"
    /usr/bin/python3 "$NAMES_DST" --check || die "the names helper could not read the socket tables"
    printf '%s\n' "$RULE_CONTENT" > "$RULE_FILE" || die "could not write $RULE_FILE"
    chown root:root "$RULE_FILE"
    chmod 0644 "$RULE_FILE"
    systemctl daemon-reload
    # Off the boot list; the app starts them. One already running gets the
    # new code now.
    systemctl disable "$NAMES_UNIT" "$CAPTURE_UNIT" >/dev/null 2>&1
    if systemctl is-active --quiet "$NAMES_UNIT"; then
        systemctl restart "$NAMES_UNIT" || die "the names helper did not start"
    fi
    if systemctl is-active --quiet "$CAPTURE_UNIT"; then
        systemctl restart "$CAPTURE_UNIT" || die "the capture service did not start"
    fi
    say ""
    say "Installed. Both start when AgentalSec opens and stop when it quits."
    say "Check any time with:"
    say "  $0 --verify"
}

do_uninstall() {
    [[ "$(id -u)" -eq 0 ]] || die "--uninstall needs root: sudo $0 --uninstall"
    for u in "$CAPTURE_UNIT" "$NAMES_UNIT"; do
        systemctl disable --now "$u" 2>/dev/null
        rm -f "$UNIT_DIR/$u"
    done
    rm -f "$NAMES_DST" "$NAMES_FILE" "$RULE_FILE"
    systemctl daemon-reload
    say "Removed. Start AgentalSec with the privileged launcher to capture again."
}

do_verify() {
    local ok=0
    for u in "$NAMES_UNIT" "$CAPTURE_UNIT"; do
        if [[ ! -f "$UNIT_DIR/$u" ]]; then
            say "$u: not installed"; ok=1; continue
        fi
        state="$(systemctl is-active "$u" 2>/dev/null)"
        say "$u: $state (it runs while the app is open)"
        if systemctl is-enabled --quiet "$u" 2>/dev/null; then
            say "  still set to start at boot; run --apply again"; ok=1
        fi
    done
    if [[ -f "$NAMES_DST" ]] && cmp -s "$NAMES_SRC" "$NAMES_DST"; then
        say "names helper: the installed copy matches the project"
    else
        say "names helper: the installed copy is OUT OF DATE or missing; run --apply again"
        ok=1
    fi
    if [[ -f "$NAMES_FILE" ]]; then
        age=$(( $(date +%s) - $(stat -c %Y "$NAMES_FILE") ))
        say "names file: written ${age} s ago"
        if systemctl is-active --quiet "$NAMES_UNIT" && (( age > 5 )); then
            ok=1
        fi
    else
        say "names file: missing"; ok=1
    fi
    return $ok
}

case "$MODE" in
    plan)      show_plan ;;
    apply)     do_apply ;;
    uninstall) do_uninstall ;;
    verify)    do_verify ;;
esac
