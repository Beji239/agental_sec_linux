#!/usr/bin/env bash
# scripts/install_gateway_agent.sh
# Enroll a router: put the AgentalSec agent on it and give this app one SSH
# key that can run that agent and nothing else. Brand-free: any router with
# an SSH server, a root shell and a POSIX sh (OpenWrt, a Linux router, a
# pf-based firewall) is enrolled the same way; what it can do is reported by
# the agent's probe at the end.
#
# Usage (as your own user, not root):
#     ./scripts/install_gateway_agent.sh                       # show the plan
#     ./scripts/install_gateway_agent.sh --enroll HOST [--user root] [--port 22]
#     ./scripts/install_gateway_agent.sh --verify HOST [--user root] [--port 22]
#     ./scripts/install_gateway_agent.sh --remove HOST [--user root] [--port 22]
#
# --enroll logs in to the router ONCE as its administrator (you type the
# router's password, or your own key is used if the router already has it).
# On OpenWrt it also turns on dnsmasq's query log, which the DNS reader needs.
# It then switches the gateway block on in config.json; --remove switches it
# off and puts the query log setting back if enroll changed it.
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${AGENTAL_CONFIG:-$PROJECT_ROOT/config.json}"
AGENT_SRC="$PROJECT_ROOT/tools/gateway_agent.sh"
CONF_DIR="$HOME/.config/agental_sec"
KEY="$CONF_DIR/gateway_ed25519"
KNOWN="$CONF_DIR/gateway_known_hosts"
TAG="agentalsec-gateway"
# Each enrolled computer has its own line, found by its own key or this tag,
# so enrolling one never removes another's key.
HOST_TAG="$TAG-$(hostname -s 2>/dev/null | tr -cd 'A-Za-z0-9_-' || echo host)"

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

MODE=plan HOST="" USER_NAME=root PORT=22
case "${1:-}" in
    --enroll) MODE=enroll ;;
    --verify) MODE=verify ;;
    --remove) MODE=remove ;;
    "") MODE=plan ;;
    *) die "unrecognised argument '${1}'" ;;
esac
shift || true
if [[ "$MODE" != plan ]]; then
    HOST="${1:-}"; shift || true
    [[ -n "$HOST" ]] || die "name the router's address: $0 --$MODE HOST"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --user) USER_NAME="$2"; shift 2 ;;
            --port) PORT="$2"; shift 2 ;;
            *) die "unrecognised option '$1'" ;;
        esac
    done
fi
# In the Docker image the app itself runs as root, so root is the app's account.
if [[ "$(id -u)" == "0" && "${AGENTAL_IN_CONTAINER:-}" != "1" ]]; then
    die "run this as your own user, not root: the key belongs to the app's account"
fi
[[ -f "$AGENT_SRC" ]] || die "$AGENT_SRC does not exist"

PINNED=(-o UserKnownHostsFile="$KNOWN" -o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null -p "$PORT")

plan() {
    say "Enroll a router with the AgentalSec agent"
    say ""
    say "  1. create $KEY (ed25519, only for this), if it does not exist"
    say "  2. read the router's SSH host key, show its fingerprint for you to"
    say "     confirm against the router's own console or web page, and pin it"
    say "     in $KNOWN"
    say "  3. log in ONCE as the router's administrator and:"
    say "       install the agent as agentalsec-gw (root-only, mode 700)"
    say "       add the key to authorized_keys with command= forcing the agent,"
    say "       and no port forwarding, agent forwarding, X11 or terminal"
    say "     on OpenWrt, turn on dnsmasq's query log (log-queries) so the"
    say "     router's DNS lookups can be read"
    say "  4. run the agent's probe and print what this router can do"
    say "  5. switch the gateway block on in $CONFIG"
    say ""
    say "Run: $0 --enroll <router address>"
}

remote_install_script() {
    local pub="$1" body="$(printf '%s' "$1" | cut -d' ' -f2)" delim="AGENTALSEC_GW_$(date +%s)_$$"
    cat <<EOF
set -e
umask 077
DEST=""
for d in /usr/local/sbin /usr/sbin /root; do
    if [ -d "\$d" ] && [ -w "\$d" ]; then DEST="\$d/agentalsec-gw"; break; fi
done
[ -n "\$DEST" ] || { echo "ERR no writable directory for the agent"; exit 1; }
cat > "\$DEST.new" <<'$delim'
$(cat "$AGENT_SRC")
$delim
chmod 700 "\$DEST.new"
mv "\$DEST.new" "\$DEST"
BOOT=none
if [ -f /etc/rc.common ] && [ -d /etc/init.d ]; then
    cat > /etc/init.d/agentalsec-gw <<BOOT_EOF
#!/bin/sh /etc/rc.common
# Puts AgentalSec's saved router blocks back after a reboot.
START=99
start() { "\$DEST" restore >/dev/null 2>&1; }
BOOT_EOF
    chmod 755 /etc/init.d/agentalsec-gw
    /etc/init.d/agentalsec-gw enable && BOOT=/etc/init.d/agentalsec-gw
fi
if [ -d /etc/dropbear ] && { pidof dropbear >/dev/null 2>&1 || [ -f /etc/dropbear/authorized_keys ]; }; then
    AK=/etc/dropbear/authorized_keys
else
    AK="\$HOME/.ssh/authorized_keys"; mkdir -p "\$HOME/.ssh"; chmod 700 "\$HOME/.ssh"
fi
touch "\$AK"; chmod 600 "\$AK"
grep -vF "$body" "\$AK" | grep -v " $HOST_TAG\$" > "\$AK.new" || true
printf '%s\n' "command=\"\$DEST\",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty $pub" >> "\$AK.new"
mv "\$AK.new" "\$AK"
DNSLOG=unsupported
if command -v uci >/dev/null 2>&1 && uci -q get dhcp.@dnsmasq[0] >/dev/null; then
    if [ "\$(uci -q get dhcp.@dnsmasq[0].logqueries)" = "1" ]; then
        DNSLOG=already-on
    else
        uci set dhcp.@dnsmasq[0].logqueries=1
        SIZE="\$(uci -q get system.@system[0].log_size)"
        mkdir -p /etc/agentalsec
        printf 'log_size=%s\n' "\$SIZE" > /etc/agentalsec/dnslog_enabled_by_agent
        if [ -z "\$SIZE" ] || [ "\$SIZE" -lt 1024 ]; then
            uci set system.@system[0].log_size=1024
        fi
        uci commit dhcp; uci commit system
        /etc/init.d/dnsmasq restart >/dev/null 2>&1
        /etc/init.d/log restart >/dev/null 2>&1
        DNSLOG=turned-on
    fi
fi
echo "INSTALLED agent=\$DEST authorized_keys=\$AK boot=\$BOOT dnslog=\$DNSLOG"
EOF
}

# Sets the gateway block in config.json; the rest of the file is kept.
set_config() {
    local enabled="$1"
    if [[ ! -f "$CONFIG" ]]; then
        say "  $CONFIG does not exist yet; copy config.linux.example.json to it,"
        say "  then run this again or set the gateway block in Settings."
        return 1
    fi
    python3 - "$CONFIG" "$enabled" "$HOST" "$PORT" "$USER_NAME" <<'PY' || return 1
import json, os, sys, tempfile
path, enabled, host, port, user = sys.argv[1:6]
with open(path, encoding="utf-8") as f:
    cfg = json.load(f)
gw = cfg.get("gateway") or {}
if enabled == "1":
    gw.update(enabled=True, host=host, port=int(port), user=user)
    gw.setdefault("interval_minutes", 5)
    dns = cfg.setdefault("dns_monitor", {})
    # A resolver file the owner set up on purpose is left alone.
    if not (dns.get("enabled") and dns.get("source") in ("pihole", "adguard")
            and dns.get("path")):
        dns.update(enabled=True, source="auto")
elif gw.get("host") == host:
    gw["enabled"] = False
else:
    print("  config.json names another router, so it was left as it is")
    sys.exit(0)
cfg["gateway"] = gw
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)))
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
os.chmod(tmp, os.stat(path).st_mode & 0o777)
os.replace(tmp, path)
PY
    if [[ "$enabled" == 1 ]]; then
        say "  config.json: gateway switched on for $HOST, DNS source auto"
    else
        say "  config.json: gateway switched off"
    fi
}

agent_call() {
    ssh -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes "${PINNED[@]}" \
        "$USER_NAME@$HOST" "$@"
}

enroll() {
    mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
    if [[ ! -f "$KEY" ]]; then
        ssh-keygen -q -t ed25519 -N "" -C "$TAG" -f "$KEY" || die "ssh-keygen failed"
        say "  created $KEY"
    fi
    chmod 600 "$KEY"

    local scan
    scan="$(ssh-keyscan -p "$PORT" -T 10 "$HOST" 2>/dev/null)"
    [[ -n "$scan" ]] || die "no SSH server answered at $HOST:$PORT. Turn SSH on in the router's settings first."
    say ""
    say "The router at $HOST presents these host keys:"
    printf '%s\n' "$scan" | ssh-keygen -lf - | sed 's/^/    /'
    say ""
    say "Check one of these against the router itself (its console, or its"
    say "web page's SSH section) before going on. If they do not match,"
    say "something else is answering at that address."
    read -r -p "Type yes if they match: " answer
    [[ "$answer" == "yes" ]] || die "not confirmed, so nothing was pinned or installed"
    grep -v "^\[\?$HOST\]\?[: ]" "$KNOWN" 2>/dev/null > "$KNOWN.new" || true
    printf '%s\n' "$scan" >> "$KNOWN.new"
    mv "$KNOWN.new" "$KNOWN"; chmod 600 "$KNOWN"
    say "  pinned in $KNOWN"

    say ""
    say "Logging in to $HOST as $USER_NAME to install the agent (the router's"
    say "password is asked once if this account has no key there):"
    local pub out
    pub="$(cut -d' ' -f1-2 "$KEY.pub") $HOST_TAG"
    out="$(remote_install_script "$pub" | ssh "${PINNED[@]}" "$USER_NAME@$HOST" 'sh -s' 2>&1)"
    printf '%s\n' "$out" | grep -q '^INSTALLED' || die "the install did not finish: $out"
    say "  $(printf '%s\n' "$out" | grep '^INSTALLED')"
    case "$out" in
        *dnslog=turned-on*) say "  dnsmasq query logging was off and is now on" ;;
        *dnslog=unsupported*) say "  not OpenWrt: turn on DNS query logging in the router yourself if it has it" ;;
    esac
    verify
    say ""
    if set_config 1; then
        say "Restart AgentalSec to start reading the router."
    else
        say "Set by hand in config.json, then restart the app:"
        say "  \"gateway\": {\"enabled\": true, \"host\": \"$HOST\", \"port\": $PORT, \"user\": \"$USER_NAME\"}"
    fi
}

verify() {
    say ""
    say "Asking the agent with the app's key:"
    local out
    out="$(agent_call probe 2>&1)"
    if ! printf '%s\n' "$out" | head -1 | grep -q '^OK probe'; then
        die "the agent did not answer: $out"
    fi
    printf '%s\n' "$out" | sed 's/^/    /'
    say ""
    say "Capabilities: $(printf '%s\n' "$out" | sed -n 's/^cap=//p' | tr '\n' ' ')"
    local forced
    forced="$(agent_call 'id' 2>&1 | head -1)"
    if printf '%s' "$forced" | grep -q '^ERR'; then
        say "  [PASS] the key runs the agent and nothing else ('id' was refused by it)"
    else
        say "  [FAIL] the key ran something other than the agent: $forced"
    fi
    if ! printf '%s\n' "$out" | grep -q '^cap=dnslog'; then
        say "  [NOTE] no DNS query lines in the router's log yet, so DNS names"
        say "         are not read. They appear once a device looks something up."
    fi
}

remove() {
    say "Logging in to $HOST as $USER_NAME to remove the agent and its key:"
    ssh "${PINNED[@]}" "$USER_NAME@$HOST" 'sh -s' <<EOF
for d in /usr/local/sbin /usr/sbin /root; do rm -f "\$d/agentalsec-gw"; done
[ -x /etc/init.d/agentalsec-gw ] && /etc/init.d/agentalsec-gw disable
rm -f /etc/init.d/agentalsec-gw
if [ -f /etc/agentalsec/dnslog_enabled_by_agent ] && command -v uci >/dev/null 2>&1; then
    uci set dhcp.@dnsmasq[0].logqueries=0
    SIZE="\$(sed -n 's/^log_size=//p' /etc/agentalsec/dnslog_enabled_by_agent)"
    if [ -n "\$SIZE" ]; then uci set system.@system[0].log_size="\$SIZE"; else uci -q delete system.@system[0].log_size; fi
    uci commit dhcp; uci commit system
    /etc/init.d/dnsmasq restart >/dev/null 2>&1; /etc/init.d/log restart >/dev/null 2>&1
fi
rm -rf /etc/agentalsec
nft delete table inet agentalsec_gw 2>/dev/null
for ak in /etc/dropbear/authorized_keys "\$HOME/.ssh/authorized_keys"; do
    [ -f "\$ak" ] && { grep -vF "$(cut -d' ' -f2 "$KEY.pub")" "\$ak" | grep -v " $HOST_TAG\$" > "\$ak.new"; mv "\$ak.new" "\$ak"; }
done
echo REMOVED
EOF
    say "Its blocks were lifted and its saved state removed. Sinkholes stay"
    say "until the router reboots."
    set_config 0 || true
    say "Delete $KEY if nothing else uses it, and restart the app."
}

case "$MODE" in
    plan) plan ;;
    enroll) enroll ;;
    verify) verify ;;
    remove) remove ;;
esac
