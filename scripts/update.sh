#!/usr/bin/env bash
# scripts/update.sh
# Bring an existing install up to date: fetch the latest code, reinstall the
# Python packages, list what changed and say what else to run. The database
# updates itself at the next start. Run it as your own user.
#
#     ./scripts/update.sh            update to the latest code
#     ./scripts/update.sh --check    only show whether an update is waiting

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${AGENTAL_CONFIG:-$PROJECT_ROOT/config.json}"

MODE=update
case "${1:-}" in
    "") ;;
    --check) MODE=check ;;
    -h|--help) sed -n '3,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
esac

die() { echo "update: $*" >&2; exit 1; }

cd "$PROJECT_ROOT" || die "cannot open $PROJECT_ROOT"
command -v git >/dev/null || die "git is not installed: sudo apt install git"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || die "this folder is not a git clone, so it cannot be updated this way. Clone the repository again (SETUP.md step 2) and move config.json, .env and agental_sec.db into the new folder."

if [[ "$MODE" == update && "$(id -u)" -eq 0 ]]; then
    die "run this as your own user, not with sudo: the Python packages live in your ~/.local."
fi

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    git status --short --untracked-files=no
    die "the files above were changed in this folder, so nothing was updated. Run 'git stash', then this script again, then 'git stash pop' to put your changes back."
fi

branch="$(git rev-parse --abbrev-ref HEAD)"
before="$(git rev-parse HEAD)"
echo "Looking for updates on $branch..."
git fetch --tags --quiet origin || die "could not reach the repository. Check the network and try again."
upstream="$(git rev-parse '@{u}' 2>/dev/null)" \
    || die "this branch follows nothing. Run: git branch --set-upstream-to=origin/$branch"

if [[ "$before" == "$upstream" ]]; then
    echo "Already up to date ($(git describe --tags --always))."
    exit 0
fi
if ! git merge-base --is-ancestor "$before" "$upstream"; then
    die "this folder has commits of its own, so the update cannot be applied by itself. Nothing was changed. See: git status"
fi

echo
echo "Waiting to be installed:"
git log --no-decorate --format='  %s' "$before..$upstream"
[[ "$MODE" == check ]] && { echo; echo "Run ./scripts/update.sh to install it."; exit 0; }

echo
git merge --ff-only --quiet "$upstream" || die "the update could not be applied. Nothing was changed."
echo "Code updated to $(git describe --tags --always)."

echo "Installing the Python packages..."
if ! pip install --user --break-system-packages --quiet -r requirements.txt; then
    die "pip failed. The code is updated; run the pip command in SETUP.md step 3 and read its error."
fi

changed="$(git diff --name-only "$before" HEAD)"
touched() { grep -qxE "$1" <<<"$changed"; }
todo=()

if touched 'scripts/install_launchers.sh|scripts/agental_sec_launch.sh|assets/logo/.*'; then
    todo+=("The launchers changed. Run: ./scripts/install_launchers.sh")
fi
if touched 'tools/action_helper.py|scripts/install_action_helper.sh'; then
    todo+=("The root helper changed. Run: sudo ./scripts/install_action_helper.sh --apply")
fi
if touched 'tools/read_helper.py|scripts/install_read_helper.sh'; then
    todo+=("The read helper changed. Run: sudo ./scripts/install_read_helper.sh --apply")
fi
if [[ -f /etc/systemd/system/agentalsec-ebpf-camera.service ]] \
        && touched 'ebpf/ebpf_monitor.py|scripts/install_ebpf_camera.sh'; then
    todo+=("The kernel camera changed. Run: sudo ./scripts/install_ebpf_camera.sh --apply")
fi
# The security test tools, only when they were installed before.
tools_home="${AGENTAL_TEST_TOOLS:-${XDG_DATA_HOME:-$HOME/.local/share}/agentalsec-test-tools}"
if [[ -d "$tools_home" ]] && touched 'scripts/install_test_tools.sh'; then
    echo "Updating the security test tools..."
    ./scripts/install_test_tools.sh --skip-system \
        || todo+=("The security test tools did not update. Run: ./scripts/install_test_tools.sh")
fi
if touched 'scripts/install_audit_rules.sh'; then
    todo+=("The audit watches changed. Run: sudo ./scripts/install_audit_rules.sh --apply")
fi
if touched 'tools/gateway_agent.sh|scripts/install_gateway_agent.sh'; then
    router="$(python3 - "$CONFIG" <<'PY' 2>/dev/null
import json, sys
try:
    g = json.load(open(sys.argv[1])).get("gateway") or {}
except (OSError, ValueError):
    g = {}
if g.get("enabled") and g.get("host"):
    print(g["host"])
PY
)"
    if [[ -n "$router" ]]; then
        todo+=("The router agent changed. Run: ./scripts/install_gateway_agent.sh --enroll $router")
    fi
fi

# Running from this folder, by its working directory or its command line.
running() {
    local pid
    for pid in $(pgrep -f 'main\.py' 2>/dev/null); do
        [[ "$(readlink "/proc/$pid/cwd" 2>/dev/null)" == "$PROJECT_ROOT" ]] && return 0
        tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null \
            | grep -qF "$PROJECT_ROOT/main.py" && return 0
    done
    return 1
}

echo
echo "Done. What is left:"
if running || systemctl is-active --quiet agental-sec 2>/dev/null; then
    if systemctl is-active --quiet agental-sec 2>/dev/null; then
        echo "  - Restart AgentalSec: sudo systemctl restart agental-sec"
    else
        echo "  - Restart AgentalSec: close it, then start it again from its icon."
    fi
else
    echo "  - Start AgentalSec from its icon."
fi
echo "    The database updates itself at that start."
for line in "${todo[@]}"; do
    echo "  - $line"
done
echo "  Your config.json is not changed: a new setting keeps its default until you change it in Settings."
