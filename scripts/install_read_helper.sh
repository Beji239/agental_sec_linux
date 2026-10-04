#!/usr/bin/env bash
# scripts/install_read_helper.sh
# Install the read-only helper, and the ONE sudoers drop-in that lets the
# sensor call it. Tier D, 2026-09-22.
#
# THIS SCRIPT IS THE OPERATIONAL CHANGE. IT NEEDS ROOT AND IT CHANGES
# /etc. It is written as a script that PRINTS WHAT IT WILL DO and then does
# it only when asked, because a security monitor that quietly edits sudoers
# is the worst possible thing to ship.
#
# Usage:
#     ./scripts/install_read_helper.sh            # show what would change
#     sudo ./scripts/install_read_helper.sh --apply
#     sudo ./scripts/install_read_helper.sh --uninstall
#     ./scripts/install_read_helper.sh --verify   # test the installed one
#
# WHY THE HELPER LIVES UNDER /usr/local/lib/agentalsec AND NOT IN THE PROJECT
# DIRECTORY: the sudoers rule below grants root to a PATH. The project tree is
# owned by the operator and is group-writable, so a rule naming a path inside it
# would grant root to any account that can write the tree -- which is exactly
# what the helper's own self-check refuses to run from. Installing it into a
# root-owned directory is what makes the allowlist real.
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER_SRC="$PROJECT_ROOT/tools/read_helper.py"

HELPER_DIR="/usr/local/lib/agentalsec"
HELPER_DST="$HELPER_DIR/read_helper.py"
SUDOERS_FILE="/etc/sudoers.d/agentalsec-read-helper"

REAL_USER="${SUDO_USER:-}"
if [[ -z "$REAL_USER" ]]; then
    REAL_USER="$(stat -c '%U' "$PROJECT_ROOT" 2>/dev/null || echo root)"
fi

say()  { printf '%s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

MODE=""
case "${1:-}" in
    --apply)     MODE=apply ;;
    --uninstall) MODE=uninstall ;;
    --verify)    MODE=verify ;;
    "")          MODE=plan ;;
    *)           die "unrecognised argument '${1}'. Known: (none), --apply, --uninstall, --verify." ;;
esac

say "AgentalSec read-only helper, tier D"
say "  project root : $PROJECT_ROOT"
say "  helper source: $HELPER_SRC"
say "  installs to  : $HELPER_DST   (root-owned, mode 755)"
say "  sudoers drop-in: $SUDOERS_FILE"
say "  real user    : $REAL_USER"
say ""

if [[ ! -f "$HELPER_SRC" ]]; then
    die "$HELPER_SRC does not exist, so there is nothing to install."
fi

# the drop-in's content, and the ONE line in it that matters
#
# A single user, a single command, NOPASSWD, and NO ARGUMENT WILDCARD. The
# classic sudoers hole is a rule like:
#
#     <user> ALL=(root) NOPASSWD: /usr/local/lib/agentalsec/read_helper.py *
#
# -- the trailing `*` lets the caller pass ANY argument, which for a script
# that took a path would be `sudo cat`. This rule names the script and the
# verb table, and the helper REFUSES extra arguments in its own code as well,
# so there are two independent refusals rather than one.
#
# The verbs are spelled out for the same reason a rule with no arguments at
# all would also work: naming them documents exactly what the machine has
# granted, so a reader auditing sudoers does not have to trust the script.
DROP_IN_CONTENT="$(cat <<EOF
# AgentalSec read-only helper. Installed $(date -u +%Y-%m-%dT%H:%M:%SZ) by
# scripts/install_read_helper.sh.
#
# WHAT THIS GRANTS: the account below may run ONE script, as root, with NO
# password, with one of five fixed words (or --verbs, which reads nothing).
# It cannot read an arbitrary file, it cannot run an arbitrary command, and
# it cannot pass a path.
#
# WHAT IT IS FOR: the local integrity sensor cannot read /etc/sudoers, the
# CONTENTS of /etc/sudoers.d or root's authorized_keys, so those are watched
# for name, mode, owner, size and mtime only. This lets it hash them.
# proc_exe lets the process sensor see which file another account's
# process is running.
#
# TO REVOKE: sudo rm $SUDOERS_FILE   (and $HELPER_DST)
#
# The helper refuses to run at all unless its own installed path is
# root-owned and not group- or world-writable, so do not move it somewhere
# the account below can write.
$REAL_USER ALL=(root) NOPASSWD: $HELPER_DST sudoers, \\
    $HELPER_DST sudoers_d, \\
    $HELPER_DST root_ssh, \\
    $HELPER_DST dpkg_verify, \\
    $HELPER_DST proc_exe, \\
    $HELPER_DST --verbs
EOF
)"

show_plan() {
    say "WHAT WOULD CHANGE"
    say ""
    say "1. install $HELPER_DST"
    say "     root:root, mode 0755, directory $HELPER_DIR root:root mode 0755"
    say ""
    say "2. create $SUDOERS_FILE with this content:"
    say ""
    printf '%s\n' "$DROP_IN_CONTENT" | sed 's/^/     /'
    say ""
    say "3. validate it with visudo -c BEFORE it is trusted, and remove it"
    say "   again if the check fails. A syntax error in a sudoers drop-in can"
    say "   lock sudo out of the machine, which is a much worse outcome than"
    say "   not having the helper."
    say ""
    say "NOTHING ABOVE HAS HAPPENED. Run with --apply as root to do it."
}

verify() {
    say "VERIFYING THE INSTALLED HELPER"
    say ""
    local fails=0
    if [[ ! -f "$HELPER_DST" ]]; then
        say "  [FAIL] $HELPER_DST does not exist"
        return 1
    fi
    say "  [PASS] the helper is installed at $HELPER_DST"
    local owner mode
    owner="$(stat -c '%U' "$HELPER_DST")"
    mode="$(stat -c '%a' "$HELPER_DST")"
    [[ "$owner" == "root" ]] && say "  [PASS] owned by root" \
        || { say "  [FAIL] owned by $owner, not root"; fails=$((fails+1)); }
    if (( (8#$mode & 8#022) == 0 )); then
        say "  [PASS] mode $mode is not group- or world-writable"
    else
        say "  [FAIL] mode $mode is group- or world-writable"
        fails=$((fails+1))
    fi
    local dir mode2
    dir="$(dirname "$HELPER_DST")"
    while [[ "$dir" != "/" ]]; do
        mode2="$(stat -c '%a' "$dir" 2>/dev/null || echo 000)"
        if (( (8#$mode2 & 8#022) == 0 )); then
            say "  [PASS] $dir (mode $mode2) is not group- or world-writable"
        else
            say "  [FAIL] $dir (mode $mode2) IS writable by non-root"
            fails=$((fails+1))
        fi
        dir="$(dirname "$dir")"
    done

    say ""
    say "  calling it the way the sensor does: sudo -n ... --verbs"
    local out rc
    out="$(sudo -n "$HELPER_DST" --verbs 2>&1)"; rc=$?
    if [[ $rc -ne 0 ]]; then
        say "  [FAIL] exit $rc: $(printf '%s' "$out" | tail -1)"
        say "         the drop-in is not in place, or sudo would ask for a"
        say "         password, which a sensor can never supply."
        fails=$((fails+1))
    else
        say "  [PASS] it runs unelevated with no password and lists its table:"
        printf '%s\n' "$out" | sed 's/^/        /' | head -20
    fi

    say ""
    say "  reading the three file sets it exists for:"
    for verb in sudoers sudoers_d root_ssh proc_exe; do
        local res
        res="$(sudo -n "$HELPER_DST" "$verb" 2>&1)"
        if printf '%s' "$res" | grep -q '"ok": true'; then
            local size
            size="$(printf '%s' "$res" | wc -c)"
            say "  [PASS] $verb returned $size bytes of JSON"
        else
            say "  [FAIL] $verb: $(printf '%s' "$res" | tail -1)"
            fails=$((fails+1))
        fi
    done

    say ""
    say "  and refusing what it must:"
    local r
    r="$(sudo -n "$HELPER_DST" /etc/shadow 2>&1)"
    if printf '%s' "$r" | grep -q '"ok": false'; then
        say "  [PASS] a path is refused (it is not a verb)"
    else
        say "  [FAIL] it did not refuse a path: $r"
        fails=$((fails+1))
    fi
    r="$(sudo -n "$HELPER_DST" sudoers /etc/shadow 2>&1)"
    if printf '%s' "$r" | grep -q '"ok": false'; then
        say "  [PASS] an extra argument is refused"
    else
        say "  [FAIL] it accepted an extra argument: $r"
        fails=$((fails+1))
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
    install -d -o root -g root -m 0755 "$HELPER_DIR" || die "could not create $HELPER_DIR"
    say "  created/confirmed $HELPER_DIR (root:root, 0755)"

    # 0755: the sudoers rule runs the file directly, so it must be executable.
    install -o root -g root -m 0755 "$HELPER_SRC" "$HELPER_DST" \
        || die "could not install the helper"
    say "  installed $HELPER_DST (root:root, 0755)"

    # VALIDATE BEFORE TRUSTING.
    #
    # Written to a temp file, checked with visudo, and moved into place only
    # if visudo accepts it. A sudoers drop-in with a syntax error can break
    # sudo for every account on the machine including root's own recovery
    # path, and the fix needs a rescue shell. This ordering is the entire
    # reason this part is a script rather than three lines in a README.
    local tmp
    tmp="$(mktemp /etc/sudoers.d/.agentalsec-check.XXXXXX)" || die "mktemp failed"
    printf '%s\n' "$DROP_IN_CONTENT" > "$tmp"
    chmod 0440 "$tmp"
    chown root:root "$tmp"

    local check
    check="$(visudo -c -f "$tmp" 2>&1)"
    if [[ $? -ne 0 ]]; then
        rm -f "$tmp"
        die "visudo refused the drop-in, so it was NOT installed and sudo is
unchanged. visudo said: $check"
    fi
    if ! visudo -c 2>&1 | grep -q "parsed OK"; then
        rm -f "$tmp"
        die "visudo -c over the whole sudoers set does not report 'parsed OK',
so nothing was changed. Run 'sudo visudo -c' yourself to see why."
    fi
    say "  visudo accepts the drop-in and the whole sudoers set parses"

    mv "$tmp" "$SUDOERS_FILE" || die "could not move the drop-in into place"
    say "  installed $SUDOERS_FILE (root:root, 0440)"

    say ""
    say "A note on what just happened and how to undo it:"
    say "  the account $REAL_USER may now run ONE script as root, without a"
    say "  password, with one of five fixed words and no other argument. That"
    say "  is the whole grant."
    say "  TO UNDO:  sudo rm $SUDOERS_FILE $HELPER_DST"
    say ""
    say "Run '$0 --verify' to test it the way the sensor calls it."
}

uninstall() {
    [[ "$(id -u)" == "0" ]] || die "--uninstall must run as root"
    say "REMOVING"
    if [[ -f "$SUDOERS_FILE" ]]; then
        rm -f "$SUDOERS_FILE" && say "  removed $SUDOERS_FILE"
    else
        say "  $SUDOERS_FILE was not there"
    fi
    if [[ -f "$HELPER_DST" ]]; then
        rm -f "$HELPER_DST" && say "  removed $HELPER_DST"
    else
        say "  $HELPER_DST was not there"
    fi
    rmdir "$HELPER_DIR" 2>/dev/null && say "  removed $HELPER_DIR" \
        || say "  left $HELPER_DIR in place (not empty)"
    say ""
    say "The sensor now reports /etc/sudoers, /etc/sudoers.d and root's"
    say "authorized_keys as metadata-only again, in its coverage block. It does"
    say "not fail; it says what it cannot see."
}

case "$MODE" in
    plan)      show_plan ;;
    apply)     apply ;;
    uninstall) uninstall ;;
    verify)    verify ;;
esac
