#!/usr/bin/env bash
# scripts/install_test_tools.sh
# Install the tools the security tests use: Bandit, Semgrep, pip-audit,
# ShellCheck, gitleaks and Trivy. Only needed to run those tests, the app
# itself never uses them. They go in their own folder, apart from the app's
# Python packages. Run it as your own user; it asks for sudo once, for apt.
#
#     ./scripts/install_test_tools.sh               install or bring up to date
#     ./scripts/install_test_tools.sh --skip-system do not run apt
#     ./scripts/install_test_tools.sh --verify      only check what is installed
#     ./scripts/install_test_tools.sh --remove      delete the tools folder
#
# The folder is AGENTAL_TEST_TOOLS when set, otherwise
# ~/.local/share/agentalsec-test-tools. Without the tools, each security test
# reports a skip that names this script.

set -uo pipefail

TOOLS_HOME="${AGENTAL_TEST_TOOLS:-${XDG_DATA_HOME:-$HOME/.local/share}/agentalsec-test-tools}"

# Pinned versions; raise them here and run the script again.
BANDIT_VERSION=1.9.4
SEMGREP_VERSION=1.177.0
PIP_AUDIT_VERSION=2.10.1
GITLEAKS_VERSION=8.30.1
TRIVY_VERSION=0.74.0

MODE=install SYSTEM=1
for arg in "$@"; do
    case "$arg" in
        --skip-system) SYSTEM=0 ;;
        --verify) MODE=verify ;;
        --remove) MODE=remove ;;
        -h|--help) sed -n '3,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
    esac
done

die() { echo "test tools: $*" >&2; exit 1; }
ok()  { echo "      done: $*"; }

# Prints each tool's version; returns 1 when any is missing.
verify() {
    local missing=0 name path
    for name in bandit semgrep pip-audit; do
        path="$TOOLS_HOME/venv/bin/$name"
        if [[ -x "$path" ]]; then
            echo "  $name: $("$path" --version 2>/dev/null | head -n1)"
        else
            echo "  $name: missing"; missing=1
        fi
    done
    for name in gitleaks trivy; do
        path="$TOOLS_HOME/bin/$name"
        if [[ -x "$path" ]]; then
            echo "  $name: $("$path" version 2>/dev/null | head -n1)"
        else
            echo "  $name: missing"; missing=1
        fi
    done
    if command -v shellcheck >/dev/null 2>&1; then
        echo "  shellcheck: $(shellcheck --version | sed -n 's/^version: //p')"
    else
        echo "  shellcheck: missing"; missing=1
    fi
    return "$missing"
}

if [[ "$MODE" == verify ]]; then
    echo "Security test tools in $TOOLS_HOME"
    verify && { echo "All present."; exit 0; }
    echo "Some are missing. Run: ./scripts/install_test_tools.sh"
    exit 1
fi

if [[ "$MODE" == remove ]]; then
    [[ -d "$TOOLS_HOME" ]] || { echo "Nothing to remove at $TOOLS_HOME"; exit 0; }
    rm -rf -- "$TOOLS_HOME" && echo "Removed $TOOLS_HOME (ShellCheck stays, it came from apt)."
    exit 0
fi

[[ "$(id -u)" -ne 0 ]] || die "run this as your own user, not as root or with sudo."
[[ "$(uname -s)" == Linux ]] || die "this script is for Linux."
case "$(uname -m)" in
    x86_64) GL_ARCH=x64 TV_ARCH=64bit ;;
    aarch64|arm64) GL_ARCH=arm64 TV_ARCH=ARM64 ;;
    *) die "no gitleaks and Trivy builds are set up here for $(uname -m)." ;;
esac
for cmd in python3 curl tar sha256sum; do
    command -v "$cmd" >/dev/null 2>&1 || die "$cmd is not installed."
done

echo "Installing the security test tools into $TOOLS_HOME"

# ShellCheck and the venv module come from apt, which checks signatures.
need=()
python3 -m venv --help >/dev/null 2>&1 && python3 -c 'import ensurepip' 2>/dev/null \
    || need+=(python3-venv)
command -v shellcheck >/dev/null 2>&1 || need+=(shellcheck)
if [[ ${#need[@]} -gt 0 ]]; then
    if [[ "$SYSTEM" == 0 ]]; then
        die "these system packages are missing: ${need[*]}. Install them (sudo apt install ${need[*]}) or run without --skip-system."
    fi
    command -v apt-get >/dev/null 2>&1 || die "apt-get was not found. Install ${need[*]} yourself, then run this with --skip-system."
    echo "      sudo will ask for your password once, for apt only."
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${need[@]}" </dev/null \
        || die "apt could not install ${need[*]}."
fi
ok "ShellCheck and python3-venv"

mkdir -p "$TOOLS_HOME/bin" || die "cannot create $TOOLS_HOME"
chmod 700 "$TOOLS_HOME"

# Python tools, in a virtual environment of their own.
if [[ ! -x "$TOOLS_HOME/venv/bin/python" ]]; then
    python3 -m venv "$TOOLS_HOME/venv" || die "could not create the virtual environment."
fi
"$TOOLS_HOME/venv/bin/python" -m pip install --quiet --disable-pip-version-check \
    "bandit==$BANDIT_VERSION" "semgrep==$SEMGREP_VERSION" "pip-audit==$PIP_AUDIT_VERSION" </dev/null \
    || die "pip could not install Bandit, Semgrep and pip-audit. Its error is above."
ok "Bandit $BANDIT_VERSION, Semgrep $SEMGREP_VERSION, pip-audit $PIP_AUDIT_VERSION"

WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

# Downloads a release archive and its checksum list, checks the archive
# against the list, then unpacks one binary into bin/.
fetch_binary() {          # fetch_binary NAME BASE_URL ARCHIVE SUMS VERSION
    local name="$1" base="$2" archive="$3" sums="$4" version="$5"
    if [[ -x "$TOOLS_HOME/bin/$name" ]] \
       && [[ "$(cat "$TOOLS_HOME/bin/.$name.version" 2>/dev/null)" == "$version" ]]; then
        ok "$name $version already present"; return 0
    fi
    curl -fsSL --proto '=https' -o "$WORK/$archive" "$base/$archive" \
        && curl -fsSL --proto '=https' -o "$WORK/$sums" "$base/$sums" \
        || die "could not download $name $version from $base"
    (cd "$WORK" && grep -E "  $archive\$" "$sums" | sha256sum -c --status) \
        || die "$archive does not match its published checksum; nothing was installed."
    tar -xzf "$WORK/$archive" -C "$WORK" "$name" || die "could not unpack $archive"
    install -m 755 "$WORK/$name" "$TOOLS_HOME/bin/$name" || die "could not install $name"
    echo "$version" >"$TOOLS_HOME/bin/.$name.version"
    ok "$name $version, checksum verified"
}

fetch_binary gitleaks \
    "https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION" \
    "gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" \
    "gitleaks_${GITLEAKS_VERSION}_checksums.txt" "$GITLEAKS_VERSION"
fetch_binary trivy \
    "https://github.com/aquasecurity/trivy/releases/download/v$TRIVY_VERSION" \
    "trivy_${TRIVY_VERSION}_Linux-${TV_ARCH}.tar.gz" \
    "trivy_${TRIVY_VERSION}_checksums.txt" "$TRIVY_VERSION"

echo
verify || die "some tools are still missing, see above."
echo "Installed. The security tests find them here by themselves:"
echo "    python3 scripts/run_tests.py"
echo "To remove them: ./scripts/install_test_tools.sh --remove"
