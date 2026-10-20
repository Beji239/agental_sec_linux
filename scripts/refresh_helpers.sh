#!/usr/bin/env bash
# scripts/refresh_helpers.sh
# Brings the root-installed copies of the app's helpers, services and sudoers
# file level with the project, with one password. Root runs its own copies
# outside the project folder, so an edit or update here only reaches them
# through their installers; this runs just the installers that are behind.
#
#     ./scripts/refresh_helpers.sh            say what is out of date
#     sudo ./scripts/refresh_helpers.sh --apply   reinstall those
#     sudo ./scripts/refresh_helpers.sh --apply --audit
#                                             also reload the audit watches,
#                                             when they were installed before

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

MODE=plan
AUDIT=0
for arg in "$@"; do
    case "$arg" in
        --apply) MODE=apply ;;
        --audit) AUDIT=1 ;;
        *) die "unrecognised argument '${arg}'. Known: (none), --apply, --audit." ;;
    esac
done
AUDIT_RULES="/etc/audit/rules.d/agentalsec.rules"

# Run as root this also reads the sudoers file, which only root can.
stale="$(python3 -I - "$PROJECT_ROOT" <<'EOF'
import sys
sys.path.insert(0, sys.argv[1])
from core import own_install
for name, paths in own_install.stale().items():
    print(name + "\t" + ", ".join(paths))
EOF
)" || die "could not compare the installed files with the project."

if [[ -z "$stale" && "$AUDIT" == 0 ]]; then
    say "Every installed helper matches the project. Nothing to do."
    exit 0
fi

if [[ -n "$stale" ]]; then
    say "Out of date:"
    while IFS=$'\t' read -r name paths; do
        say "  $name: $paths"
    done <<<"$stale"
else
    say "Every installed helper matches the project."
fi

if [[ "$MODE" == plan ]]; then
    say ""
    say "Run: sudo $0 --apply"
    exit 0
fi
[[ "$(id -u)" == "0" ]] || die "--apply must run as root: sudo $0 --apply"

failed=0
if [[ -n "$stale" ]]; then
    while IFS=$'\t' read -r -u 3 name _; do
        say ""
        say "Running $name --apply"
        "$PROJECT_ROOT/scripts/$name" --apply || { say "  $name failed"; failed=1; }
    done 3<<<"$stale"
fi

# Reloaded only where they were installed before, never added unasked.
if [[ "$AUDIT" == 1 ]]; then
    say ""
    if [[ -f "$AUDIT_RULES" ]]; then
        say "Running install_audit_rules.sh --apply"
        "$PROJECT_ROOT/scripts/install_audit_rules.sh" --apply \
            || { say "  install_audit_rules.sh failed"; failed=1; }
    else
        say "The audit watches are not installed here, so they were left alone."
    fi
fi

say ""
[[ "$failed" == 0 ]] && say "Done. Restart AgentalSec so it sees the new copies." \
    || die "one or more installers failed; their messages are above."
