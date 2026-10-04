#!/usr/bin/env bash
# scripts/install_action_helper.sh
# Install the root action helper and the polkit policy that lets the app start
# it with the operator's password.
#
# Usage:
#     ./scripts/install_action_helper.sh            # show what would change
#     sudo ./scripts/install_action_helper.sh --apply
#     sudo ./scripts/install_action_helper.sh --uninstall
#     ./scripts/install_action_helper.sh --verify   # check the install
#     ./scripts/install_action_helper.sh --verify-live
#                                                   # also open a real session
#                                                   # (asks for the password)
#
# NO SUDOERS RULE IS WRITTEN. The helper is started through pkexec, which asks
# for the password; the app then keeps that one session until it exits. So a
# process running as the operator cannot use the helper without the password.
#
# The helper lives under /usr/local/lib/agentalsec, root-owned, for the same
# reason as the read helper: the project tree is writable by the operator, and
# a policy that named a path inside it would grant root to whoever edits it.
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER_SRC="$PROJECT_ROOT/tools/action_helper.py"
HELPER_DIR="/usr/local/lib/agentalsec"
HELPER_DST="$HELPER_DIR/action_helper.py"
POLICY_FILE="/usr/share/polkit-1/actions/org.agentalsec.action-helper.policy"
LOG_DIR="/var/log/agentalsec"
VAULT_DIR="/var/lib/agental_sec/quarantine"

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

case "${1:-}" in
    --apply) MODE=apply ;;
    --uninstall) MODE=uninstall ;;
    --verify) MODE=verify ;;
    --verify-live) MODE=verify_live ;;
    "") MODE=plan ;;
    *) die "unrecognised argument '${1}'. Known: (none), --apply, --uninstall, --verify, --verify-live." ;;
esac

[[ -f "$HELPER_SRC" ]] || die "$HELPER_SRC does not exist."

POLICY_CONTENT="$(cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<!-- Installed by scripts/install_action_helper.sh. To revoke:
     sudo $0 --uninstall -->
<policyconfig>
  <vendor>AgentalSec</vendor>
  <action id="org.agentalsec.action-helper">
    <description>Carry out actions approved in AgentalSec</description>
    <message>AgentalSec needs your password to carry out actions you approve: block an address, stop a service, end a process or quarantine a file. It is asked once per run of the app.</message>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>auth_admin</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">$HELPER_DST</annotate>
  </action>
</policyconfig>
EOF
)"

plan() {
    say "AgentalSec root action helper"
    say ""
    say "WHAT WOULD CHANGE"
    say "1. install $HELPER_DST (root:root, 0755)"
    say "2. create $POLICY_FILE:"
    printf '%s\n' "$POLICY_CONTENT" | sed 's/^/     /'
    say "3. create $LOG_DIR and $VAULT_DIR (root:root, 0700)"
    say ""
    say "WHAT IT GRANTS: the app may start that one file as root after you type"
    say "your password, once per run. Only on the local desktop session: the"
    say "policy says no for remote and inactive sessions. No sudoers change."
    say ""
    say "NOTHING ABOVE HAS HAPPENED. Run with --apply as root to do it."
}

apply() {
    [[ "$(id -u)" == "0" ]] || die "--apply must run as root: sudo $0 --apply"
    install -d -o root -g root -m 0755 "$HELPER_DIR" || die "could not create $HELPER_DIR"
    install -o root -g root -m 0755 "$HELPER_SRC" "$HELPER_DST" || die "could not install the helper"
    say "  installed $HELPER_DST"
    install -d -o root -g root -m 0700 "$LOG_DIR" "$VAULT_DIR" || die "could not create $LOG_DIR or $VAULT_DIR"
    say "  created $LOG_DIR and $VAULT_DIR"
    local tmp
    tmp="$(mktemp)" || die "mktemp failed"
    printf '%s\n' "$POLICY_CONTENT" > "$tmp"
    if command -v xmllint >/dev/null && ! xmllint --noout "$tmp" 2>/dev/null; then
        rm -f "$tmp"
        die "the policy is not well-formed XML, so nothing was installed"
    fi
    install -o root -g root -m 0644 "$tmp" "$POLICY_FILE" || { rm -f "$tmp"; die "could not install the policy"; }
    rm -f "$tmp"
    say "  installed $POLICY_FILE"
    say ""
    say "TO UNDO: sudo $0 --uninstall"
    say "Run '$0 --verify' to check it."
}

uninstall() {
    [[ "$(id -u)" == "0" ]] || die "--uninstall must run as root"
    rm -f "$POLICY_FILE" && say "  removed $POLICY_FILE"
    rm -f "$HELPER_DST" && say "  removed $HELPER_DST"
    say "  left $LOG_DIR and $VAULT_DIR: they hold the record and any"
    say "  quarantined files. Remove them by hand once nothing in them is needed."
    say "  Blocks the helper made stay until reboot, or: sudo nft delete table inet agentalsec_helper"
}

verify() {
    local fails=0
    for f in "$HELPER_DST" "$POLICY_FILE"; do
        if [[ ! -f "$f" ]]; then
            say "  [FAIL] $f is not installed"; fails=$((fails+1)); continue
        fi
        local owner mode
        owner="$(stat -c '%U' "$f")"; mode="$(stat -c '%a' "$f")"
        if [[ "$owner" == "root" ]] && (( (8#$mode & 8#022) == 0 )); then
            say "  [PASS] $f is root-owned, mode $mode"
        else
            say "  [FAIL] $f is $owner, mode $mode"; fails=$((fails+1))
        fi
    done
    if cmp -s "$HELPER_SRC" "$HELPER_DST"; then
        say "  [PASS] the installed helper matches the source"
    else
        say "  [FAIL] the installed helper differs from $HELPER_SRC; run --apply again"
        fails=$((fails+1))
    fi
    local dir="$HELPER_DIR"
    while [[ "$dir" != "/" ]]; do
        local m; m="$(stat -c '%a' "$dir")"
        if [[ "$(stat -c '%U' "$dir")" == "root" ]] && (( (8#$m & 8#022) == 0 )); then
            say "  [PASS] $dir is root-owned and not writable by others"
        else
            say "  [FAIL] $dir can be written by a non-root account"; fails=$((fails+1))
        fi
        dir="$(dirname "$dir")"
    done
    local out
    out="$("$HELPER_DST" block_ip 203.0.113.9 2>&1)"
    if printf '%s' "$out" | grep -q '"ok": false'; then
        say "  [PASS] run without pkexec, it refuses and changes nothing"
    else
        say "  [FAIL] run without pkexec it did not refuse: $out"; fails=$((fails+1))
    fi
    return $fails
}

verify_live() {
    verify; local fails=$?
    say ""
    say "  opening a real session the way the app does (your password is asked):"
    local out
    out="$(printf '%s\n' '{"id":1,"verb":"list_blocks","args":[]}' \
        | pkexec "$HELPER_DST" serve --max-age-hours 0.01 2>&1)"
    if printf '%s' "$out" | grep -q '"ready": true' && printf '%s' "$out" | grep -q '"ok": true'; then
        say "  [PASS] the session opened and answered list_blocks"
    else
        say "  [FAIL] $out"; fails=$((fails+1))
    fi
    return $fails
}

case "$MODE" in
    plan) plan ;;
    apply) apply ;;
    uninstall) uninstall ;;
    verify) verify; r=$?; (( r == 0 )) && say "ALL CHECKS PASSED." || say "$r CHECK(S) FAILED."; exit $r ;;
    verify_live) verify_live; r=$?; (( r == 0 )) && say "ALL CHECKS PASSED." || say "$r CHECK(S) FAILED."; exit $r ;;
esac
