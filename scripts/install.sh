#!/usr/bin/env bash
# scripts/install.sh
# Install AgentalSec in one command: SETUP.md steps 1 to 9. Run it from the
# cloned folder as your own user; it asks for sudo once, for the system
# packages. Safe to run again: existing config.json and .env are kept.
#
#     ./scripts/install.sh                  install, asking a few questions
#     ./scripts/install.sh --yes            no questions, defaults only
#     ./scripts/install.sh --with-clamav    also install ClamAV (step 11)
#     ./scripts/install.sh --with-ebpf      also install the eBPF build tools
#     ./scripts/install.sh --skip-system    do not run apt (packages are there)
#     ./scripts/install.sh --with-test-tools  also install the security test
#                                           tools (developers only)
#
# Without questions, the model settings come from the environment when set:
# AGENTAL_PROVIDER_URL, AGENTAL_MODEL and AGENTAL_API_KEY.

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT" || { echo "install: cannot open $PROJECT_ROOT" >&2; exit 1; }

ASK=1 CLAMAV=ask EBPF=ask SYSTEM=1 TESTTOOLS=ask
for arg in "$@"; do
    case "$arg" in
        --yes|-y) ASK=0 ;;
        --with-clamav) CLAMAV=yes ;;
        --with-ebpf) EBPF=yes ;;
        --skip-system) SYSTEM=0 ;;
        --with-test-tools) TESTTOOLS=yes ;;
        -h|--help) sed -n '3,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
    esac
done
[[ -t 0 ]] || ASK=0
[[ "$CLAMAV" == ask && "$ASK" == 0 ]] && CLAMAV=no
[[ "$EBPF" == ask && "$ASK" == 0 ]] && EBPF=no
[[ "$TESTTOOLS" == ask && "$ASK" == 0 ]] && TESTTOOLS=no

STEP=0
WARNINGS=()
step() { STEP=$((STEP + 1)); echo; echo "[$STEP/9] $*"; }
ok()   { echo "      done: $*"; }
warn() { echo "      NOTE: $*"; WARNINGS+=("$*"); }
die()  { echo; echo "install stopped: $*" >&2; exit 1; }

yes_no() {          # yes_no "question" default(y/n)
    local reply
    if [[ "$ASK" == 0 ]]; then [[ "$2" == y ]]; return; fi
    read -r -p "      $1 [$([[ $2 == y ]] && echo Y/n || echo y/N)] " reply
    reply="${reply:-$2}"
    [[ "${reply,,}" == y* ]]
}

echo "AgentalSec install, in $PROJECT_ROOT"

# Checks before anything changes.
[[ "$(id -u)" -ne 0 ]] || die "run this as your own user, not as root or with sudo. It asks for sudo itself, only for the system packages; the app, its packages and its launchers belong to your account."
[[ "$(uname -s)" == Linux ]] || die "this installer is for Linux."
[[ -f main.py && -f config.linux.example.json ]] || die "this does not look like the AgentalSec folder. Clone it first (SETUP.md step 2) and run the script from there."

# Every question is asked here, before any work, so the rest runs on its own.
read_provider() {
    [[ -f config.json ]] || { echo ""; return; }
    python3 -c 'import json,sys; print((json.load(open("config.json")).get("provider") or {}).get(sys.argv[1]) or "")' "$1" 2>/dev/null
}
env_get() { grep -m1 "^$1=" .env 2>/dev/null | cut -d= -f2-; }
NEW_KEY="${AGENTAL_API_KEY:-}" NEW_URL="${AGENTAL_PROVIDER_URL:-}" NEW_MODEL="${AGENTAL_MODEL:-}"
if [[ "$ASK" == 1 ]]; then
    echo
    echo "A few questions first; after them the install runs on its own."
    if [[ "$SYSTEM" == 1 && "$CLAMAV" == ask ]]; then
        yes_no "Install ClamAV for malware scanning (about 250 MB with its signatures)?" n && CLAMAV=yes || CLAMAV=no
    fi
    if [[ "$SYSTEM" == 1 && "$EBPF" == ask ]]; then
        yes_no "Install the build tools for the optional eBPF kernel camera?" n && EBPF=yes || EBPF=no
    fi
    if [[ "$TESTTOOLS" == ask ]]; then
        echo "      The security test tools are only for running the security"
        echo "      tests; the app does not need them."
        yes_no "Install the security test tools (about 400 MB)?" n && TESTTOOLS=yes || TESTTOOLS=no
    fi
    if [[ -z "$(env_get AGENTAL_API_KEY)" && -z "$NEW_KEY" ]]; then
        echo "      The AI analyst needs your model provider's API key. A local"
        echo "      model server needs any placeholder, such as local. Leave it"
        echo "      empty to skip; the rest of the app works without it."
        read -r -s -p "      Provider API key (hidden): " NEW_KEY; echo
    fi
    if [[ -z "$(read_provider api_url)" && -z "$NEW_URL" ]]; then
        echo "      The chat endpoint is either OpenAI-style (ending in"
        echo "      /v1/chat/completions) or Anthropic-style (ending in /v1/messages)."
        echo "      A model server on this computer looks like"
        echo "      http://localhost:1234/v1/chat/completions. Leave empty to set it"
        echo "      later on the Settings tab."
        read -r -p "      Chat endpoint URL: " NEW_URL
    fi
    if [[ -z "$(read_provider model)" && -z "$NEW_MODEL" ]]; then
        read -r -p "      Model id at that provider: " NEW_MODEL
    fi
fi
[[ "$CLAMAV" == ask ]] && CLAMAV=no
[[ "$EBPF" == ask ]] && EBPF=no
[[ "$TESTTOOLS" == ask ]] && TESTTOOLS=no

# 1. System packages
step "System packages"
BASE=(git python3 python3-pip libpcap0.8 iproute2 net-tools nftables iptables
      iputils-ping openssh-client pkexec libnotify-bin auditd)
if [[ "$SYSTEM" == 0 ]]; then
    ok "skipped (--skip-system)"
else
    command -v apt-get >/dev/null 2>&1 || die "apt-get was not found. On a system without apt, install the packages in SETUP.md step 1 yourself and run this again with --skip-system."
    command -v sudo >/dev/null 2>&1 || die "sudo is not installed. Install the packages in SETUP.md step 1 as root, then run this again with --skip-system."
    echo "      sudo will ask for your password once, for apt only."
    APT_LOG="$(mktemp)"
    apt_install() {
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" \
            </dev/null >>"$APT_LOG" 2>&1
    }
    # The launchers open the app in a terminal window; add one if none is here.
    term=""
    for t in gnome-terminal xfce4-terminal konsole alacritty kitty xterm x-terminal-emulator; do
        command -v "$t" >/dev/null 2>&1 && { term="$t"; break; }
    done
    [[ -n "$term" ]] || BASE+=(xterm)
    [[ "$TESTTOOLS" == yes ]] && BASE+=(python3-venv shellcheck)
    sudo apt-get update -q </dev/null >>"$APT_LOG" 2>&1 \
        || { tail -n 15 "$APT_LOG"; die "apt-get update failed, see above. Check the network and the apt sources, then run this again."; }
    apt_install "${BASE[@]}" \
        || { tail -n 20 "$APT_LOG"; die "the system packages could not be installed, see above. Fix it and run this again."; }
    ok "${BASE[*]}"

    if [[ "$CLAMAV" == yes ]]; then
        if apt_install clamav clamav-daemon; then
            ok "ClamAV, its own service keeps the signatures current"
        else
            warn "ClamAV could not be installed; malware scanning stays off. Later: sudo apt install clamav clamav-daemon"
        fi
    fi

    if [[ "$EBPF" == yes ]]; then
        missing=()
        for pkg in clang llvm libbpf-dev libbpf1; do
            apt_install "$pkg" || missing+=("$pkg")
        done
        # Ubuntu ships bpftool in linux-tools, Debian as its own package.
        if ! apt_install linux-tools-common "linux-tools-$(uname -r)"; then
            apt_install bpftool || missing+=("bpftool")
        fi
        if [[ ${#missing[@]} -eq 0 ]]; then
            ok "eBPF build tools; build the camera later with ./ebpf/build.sh (SETUP.md step 10)"
        else
            warn "these eBPF packages could not be installed: ${missing[*]}. The camera is optional and the rest works without it."
        fi
    fi
fi

# 2. The code is this folder.
step "Code"
ok "$PROJECT_ROOT"

# 3. Python packages, for this user, with no virtual environment (SETUP.md).
step "Python packages"
command -v python3 >/dev/null 2>&1 || die "python3 is not installed."
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
    || die "Python 3.10 or newer is needed, this is $(python3 -V 2>&1)."
python3 -m pip --version >/dev/null 2>&1 || die "pip is not installed (sudo apt install python3-pip)."
PIP_FLAGS=(--user --quiet --disable-pip-version-check)
python3 -m pip install --help 2>/dev/null | grep -q -- --break-system-packages \
    && PIP_FLAGS+=(--break-system-packages)
python3 -m pip install "${PIP_FLAGS[@]}" -r requirements.txt </dev/null \
    || die "pip could not install requirements.txt. Its error is above."
python3 - <<'PY' || die "the Python packages installed but do not import. The error is above."
import flask, flask_cors, waitress, httpx, requests, psutil, scapy, paramiko, cryptography, maxminddb
PY
ok "requirements.txt, in ~/.local"

# 4. Config files. Never overwritten.
step "Config files"
for pair in "config.linux.example.json:config.json" ".env.example:.env"; do
    src="${pair%%:*}" dst="${pair##*:}"
    if [[ -f "$dst" ]]; then
        ok "$dst already exists, kept as it is"
    else
        cp "$src" "$dst" && ok "$dst created from $src"
    fi
    chmod 600 "$dst"
done
python3 -c 'import json; json.load(open("config.json"))' \
    || die "config.json is not valid JSON. Fix it, or move it aside and run this again."

# Writes one KEY=value line in .env.
env_set() {          # env_set KEY VALUE; the value travels in the environment
    ENV_VALUE="$2" python3 - "$1" <<'PY'
import os, sys
key, value = sys.argv[1], os.environ["ENV_VALUE"].strip()
lines = open(".env").read().splitlines()
for i, line in enumerate(lines):
    if line.startswith(key + "="):
        lines[i] = f"{key}={value}"
        break
else:
    lines.append(f"{key}={value}")
open(".env", "w").write("\n".join(lines) + "\n")
PY
}

# 5. Keys in .env
step "Keys"
if [[ -n "$(env_get AGENTAL_APP_API_KEY)" ]]; then
    ok "dashboard key already set, kept"
else
    env_set AGENTAL_APP_API_KEY "$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    ok "dashboard key generated (AGENTAL_APP_API_KEY)"
fi
if [[ -n "$(env_get AGENTAL_API_KEY)" ]]; then
    ok "model provider key already set, kept"
else
    key="$NEW_KEY"
    if [[ -n "$key" ]]; then
        env_set AGENTAL_API_KEY "$key"
        ok "model provider key saved in .env"
    else
        warn "no model provider key yet. Add AGENTAL_API_KEY to .env later to turn on the analyst."
    fi
fi
chmod 600 .env

# 6. Model provider, in config.json
step "Model provider"
url="$(read_provider api_url)" model="$(read_provider model)"
if [[ -n "$url" && -n "$model" ]]; then
    ok "already set: $model at $url"
else
    python3 - "${NEW_URL:-$url}" "${NEW_MODEL:-$model}" <<'PY'
import json, sys
url, model = sys.argv[1].strip(), sys.argv[2].strip()
cfg = json.load(open("config.json"))
p = cfg.setdefault("provider", {})
before = dict(p)
if url:
    p["api_url"] = url
if model:
    p["model"] = model
if p != before:
    with open("config.json", "w") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
PY
    url="$(read_provider api_url)" model="$(read_provider model)"
    if [[ -n "$url" && -n "$model" ]]; then
        ok "$model at $url"
    else
        warn "the model endpoint or model id is not set yet. Set both on the Settings tab, or under provider in config.json."
    fi
fi

# 7. Data files. Skipped when present, so a re-run downloads nothing.
step "Data files"
if ls geoip/dbip-city-lite.mmdb >/dev/null 2>&1; then
    ok "threat map database already present"
elif python3 scripts/fetch_geoip.py </dev/null; then
    ok "threat map database"
else
    warn "the threat map database could not be downloaded. Later: python3 scripts/fetch_geoip.py"
fi
if ls geoip/dbip-asn-lite.mmdb >/dev/null 2>&1; then
    ok "network owner database already present"
elif python3 scripts/fetch_geoip.py --asn </dev/null; then
    ok "network owner database"
else
    warn "the network owner database could not be downloaded. Later: python3 scripts/fetch_geoip.py --asn"
fi
if python3 scripts/update_oui.py </dev/null; then
    ok "device vendor names"
else
    warn "the vendor list could not be downloaded. Later: python3 scripts/update_oui.py"
fi

# 8. Check
step "Check"
check_out="$(mktemp)"
if python3 main.py --check </dev/null >"$check_out" 2>&1; then
    ok "python3 main.py --check passed"
else
    tail -n 15 "$check_out" | sed 's/^/      /'
    warn "python3 main.py --check found problems, shown above."
fi
rm -f "$check_out"

# 9. Launchers
step "Launchers"
launch_out="$(mktemp)"
./scripts/install_launchers.sh </dev/null >"$launch_out" 2>&1
# Both launchers, in all three places, each pointing at this folder.
missing=()
for f in "$HOME/.local/share/applications/agentalsec.desktop" \
         "$HOME/.local/share/applications/agentalsec-privileged.desktop" \
         "$HOME/Desktop/agentalsec.desktop" \
         "$HOME/Desktop/agentalsec-privileged.desktop" \
         "$PROJECT_ROOT/agental_sec.desktop" \
         "$PROJECT_ROOT/agental_sec-privileged.desktop"; do
    grep -qF "$PROJECT_ROOT/scripts/agental_sec_launch.sh" "$f" 2>/dev/null || missing+=("$f")
done
if [[ ${#missing[@]} -eq 0 ]]; then
    ok "AgentalSec (normal) and AgentalSec (privileged), each in the app menu, on the desktop and in this folder"
else
    tail -n 10 "$launch_out" | sed 's/^/      /'
    warn "these launchers are missing: ${missing[*]}. Run ./scripts/install_launchers.sh to see why."
fi
rm -f "$launch_out"

# Optional: the security test tools, in their own folder.
if [[ "$TESTTOOLS" == yes ]]; then
    echo
    echo "[+] Security test tools"
    if ./scripts/install_test_tools.sh --skip-system </dev/null; then
        ok "Bandit, Semgrep, pip-audit, ShellCheck, gitleaks and Trivy"
    else
        warn "the security test tools did not all install, see above. Later: ./scripts/install_test_tools.sh"
    fi
fi

echo
echo "Installed AgentalSec $(cat "$PROJECT_ROOT/VERSION" 2>/dev/null || echo "(version unknown)")."
echo
echo "Start it from the AgentalSec icon in your app menu, or here with:"
echo "    python3 main.py"
echo "Then open http://127.0.0.1:5000 and enter the dashboard key:"
echo "    $(env_get AGENTAL_APP_API_KEY)"
echo "It is kept in .env as AGENTAL_APP_API_KEY."
echo "AgentalSec (privileged) asks for your password and turns on packet"
echo "capture and firewall changes."
if [[ ${#WARNINGS[@]} -gt 0 ]]; then
    echo
    echo "Still to do:"
    for w in "${WARNINGS[@]}"; do echo "  - $w"; done
fi
echo
echo "Optional, see SETUP.md steps 10 to 12:"
echo "  - root action helper:  sudo ./scripts/install_action_helper.sh --apply"
echo "  - read helper:         sudo ./scripts/install_read_helper.sh --apply"
echo "  - your router:         ./scripts/install_gateway_agent.sh --enroll ROUTER_ADDRESS"
echo "  - start on boot:       SETUP.md step 12"
echo "  - security test tools: ./scripts/install_test_tools.sh (developers only)"
echo "To update later: ./scripts/update.sh"
