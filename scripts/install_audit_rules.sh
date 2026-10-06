#!/usr/bin/env bash
# scripts/install_audit_rules.sh
# Kernel audit watches on the files an intruder changes to stay: accounts,
# sudoers, SSH keys and config, cron, systemd units, PAM, the preload list,
# the audit setup itself and AgentalSec's own helper. Each records writes and
# attribute changes, never reads, with the identity of whoever made them. The
# app reads them as AUD-1002.
#
# Usage:
#     ./scripts/install_audit_rules.sh            # show the rules, change nothing
#     sudo ./scripts/install_audit_rules.sh --apply
#     sudo ./scripts/install_audit_rules.sh --uninstall
#     ./scripts/install_audit_rules.sh --verify   # read the audit log for the load
set -uo pipefail

RULES_FILE="/etc/audit/rules.d/agentalsec.rules"
KEY="agentalsec"
AUDIT_LOG="/var/log/audit/audit.log"

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

case "${1:-}" in
    --apply) MODE=apply ;;
    --uninstall) MODE=uninstall ;;
    --verify) MODE=verify ;;
    "") MODE=plan ;;
    *) die "unrecognised argument '${1}'. Known: (none), --apply, --uninstall, --verify." ;;
esac

# A path gets a rule when it or its directory exists. The kernel watches a
# missing file through its directory, so /etc/ld.so.preload appearing is seen;
# a missing directory is refused, and one bad line stops the whole file.
WATCHES=(
    /etc/passwd /etc/group /etc/shadow /etc/gshadow
    /etc/sudoers /etc/sudoers.d
    /etc/ssh/sshd_config /etc/ssh/sshd_config.d
    /etc/crontab /etc/cron.d /var/spool/cron/crontabs
    /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
    /etc/systemd/system /etc/ld.so.preload /etc/pam.d /etc/rc.local
    /etc/audit /usr/local/lib/agentalsec
    /root/.ssh
)

rules() {
    say "# Installed by scripts/install_audit_rules.sh. Remove with --uninstall."
    say "# Writes and attribute changes only (-p wa), keyed $KEY."
    local p
    for p in "${WATCHES[@]}"; do
        [[ -e "$p" || -d "$(dirname "$p")" ]] && say "-w $p -p wa -k $KEY"
    done
    # Every real account's .ssh folder, where a planted key goes.
    while IFS=: read -r _ _ uid _ _ home _; do
        (( uid >= 1000 && uid < 60000 )) || continue
        [[ -d "$home/.ssh" ]] && say "-w $home/.ssh -p wa -k $KEY"
    done < /etc/passwd
}

plan() {
    say "AgentalSec audit watches"
    say ""
    say "WOULD WRITE $RULES_FILE:"
    rules | sed 's/^/     /'
    say ""
    say "and load it with augenrules --load. A path whose directory is missing"
    say "is left out. Nothing above has happened. Run with --apply as root to do it."
}

apply() {
    [[ "$(id -u)" == "0" ]] || die "--apply must run as root: sudo $0 --apply"
    command -v augenrules >/dev/null || die "augenrules is not installed (sudo apt install auditd)"
    local tmp
    tmp="$(mktemp)" || die "mktemp failed"
    rules > "$tmp"
    install -o root -g root -m 0640 "$tmp" "$RULES_FILE" || { rm -f "$tmp"; die "could not write $RULES_FILE"; }
    rm -f "$tmp"
    say "  wrote $RULES_FILE ($(grep -c '^-w' "$RULES_FILE") watches)"
    if ! augenrules --load; then
        die "augenrules could not load the rules. If the kernel rules are locked (-e 2), they load at the next boot."
    fi
    local loaded
    loaded="$(auditctl -l 2>/dev/null | grep -c "key=$KEY")"
    say "  the kernel now holds $loaded rule(s) keyed $KEY"
    (( loaded > 0 )) || die "no rule keyed $KEY is in force after the load"
    say ""
    say "TO UNDO: sudo $0 --uninstall"
}

uninstall() {
    [[ "$(id -u)" == "0" ]] || die "--uninstall must run as root"
    rm -f "$RULES_FILE" && say "  removed $RULES_FILE"
    augenrules --load >/dev/null 2>&1 && say "  reloaded the remaining rules"
    say "  the kernel now holds $(auditctl -l 2>/dev/null | grep -c "key=$KEY") rule(s) keyed $KEY"
}

# Readable without root when the account is in the adm group: the load writes
# a CONFIG_CHANGE record for each rule it adds.
verify() {
    [[ -r "$AUDIT_LOG" ]] || die "$AUDIT_LOG is not readable by this account (it needs the adm group, or root)."
    local added hits
    added="$(grep -c "op=add_rule key=\"$KEY\"" "$AUDIT_LOG")"
    hits="$(grep -c "key=\"$KEY\"" "$AUDIT_LOG")"
    if (( added > 0 )); then
        say "  [PASS] the audit log records $added rule(s) keyed $KEY being added"
        say "  $((hits - added)) watch record(s) keyed $KEY so far"
        return 0
    fi
    say "  [FAIL] no rule keyed $KEY has been added since $AUDIT_LOG began"
    return 1
}

case "$MODE" in
    plan) plan ;;
    apply) apply ;;
    uninstall) uninstall ;;
    verify) verify; r=$?; (( r == 0 )) && say "ALL CHECKS PASSED." || say "CHECK FAILED."; exit $r ;;
esac
