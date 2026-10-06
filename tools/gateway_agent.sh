#!/bin/sh
# tools/gateway_agent.sh
# AgentalSec's agent on a router. Installed on the router and reached only
# through an SSH key whose authorized_keys line forces this script, so that
# key can run these verbs and nothing else.
#
# No brand is assumed. The script finds what the box offers and says so in
# `probe`; the app offers only what `probe` reported. It needs a POSIX shell,
# and for each capability one of:
#   block      nft, or iptables, or pf with a rule that uses <agentalsec_block>
#   sinkhole   dnsmasq with a conf-dir, or unbound with unbound-control
#   leases     a dnsmasq lease file or a Kea CSV lease file
#   neighbors  ip neigh, or arp and ndp
#   conntrack  /proc/net/nf_conntrack, conntrack, or pfctl -ss
#   log        logread, journalctl, or a syslog file
#   dnslog     dnsmasq query lines in that log (log-queries must be on)
#   appblock   nft, and dnsmasq built with nftset or logging its answers
#   message    nft with nat, and uhttpd for the page
#
# Verbs:
#   probe, version
#   leases, neighbors, conntrack [ip], log [n], dnslog [n]
#   blocks, block <ip>, unblock <ip>, blockmac <mac>, unblockmac <mac>
#   counters, restore
#   sinkholes, sinkhole <domain>, unsinkhole <domain>
#   apps, blockapp <mac> <app>, unblockapp <mac> <app>, apprefresh
#   messages, message <mac or all> <hex>, messagekeep <mac> <hex>
#   unmessage <mac or all>, replies, clearreply <id>
#
# Reply: the first line is "OK <verb>" or "ERR <reason>", then the body.
# With nft, blocks are kept in STATE_FILE and put back by `restore`, which
# the boot script and the first `counters` after a reboot both run.
# App blocks are kept there too. Sinkholes last until the router reboots.
# Messages are kept in MSG_DIR and come back with `restore` as well.

set -f
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
export PATH LC_ALL=C

VERSION=8
NFT_TABLE=agentalsec_gw
IPT_CHAIN=AGENTALSEC_GW
PF_TABLE=agentalsec_block
SINKHOLE_FILE_NAME=agentalsec-sinkhole.conf
APPS_FILE_NAME=agentalsec-apps.conf
STATE_DIR=/etc/agentalsec
STATE_FILE=$STATE_DIR/blocks
MAC_ERROR_FILE=$STATE_DIR/mac_rules_error
MAX_COUNTED=256
MAX_BLOCKS=512
MAX_APP_BLOCKS=256
MAX_LINES=2000
PORTAL_PORT=2050
PORTAL_WWW=$STATE_DIR/portal
MSG_DIR=$STATE_DIR/messages
REPLY_DIR=$STATE_DIR/replies
PORTAL_IP_FILE=$STATE_DIR/portal_ip
MAX_MSG_BYTES=600
MAX_REPLIES=200
LEASE_FILES="/tmp/dhcp.leases /var/lib/misc/dnsmasq.leases /var/lib/dnsmasq/dnsmasq.leases /var/db/dnsmasq.leases /var/lib/kea/kea-leases4.csv /var/db/kea/kea-leases4.csv"
LOG_FILES="/var/log/messages /var/log/syslog /var/log/system/latest.log"

have() { command -v "$1" >/dev/null 2>&1; }
ok() { printf 'OK %s\n' "$1"; }
fail() { printf 'ERR %s\n' "$*"; record "refused: $*"; exit 1; }
record() {
    have logger && logger -t agentalsec-gw "${CALLER:-?} ${VERB:-?} ${ARG1:-}: $*" 2>/dev/null
    return 0
}

CALLER=$(printf '%s' "${SSH_CLIENT:-}" | cut -d' ' -f1)

# THE REQUEST. Only letters, digits and . : - _ and single spaces pass, so
# nothing the caller sends is ever a glob, a redirect or a second command.
REQ=${SSH_ORIGINAL_COMMAND:-$*}
case "$REQ" in
    *[!A-Za-z0-9.:_\ -]*) VERB=invalid; fail "the request holds a character this agent does not accept" ;;
esac
set -- $REQ
VERB=${1:-}
ARG1=${2:-}
ARG2=${3:-}
[ $# -le 3 ] || fail "too many arguments"
case "$VERB" in
    blockapp|unblockapp|message|messagekeep) ;;
    *) [ -z "$ARG2" ] || fail "too many arguments" ;;
esac

# FIREWALL BACKEND
fw_backend() {
    if have nft && nft list tables >/dev/null 2>&1; then echo nft
    elif have iptables && iptables -S >/dev/null 2>&1; then echo iptables
    elif have pfctl && pfctl -sr 2>/dev/null | grep -q "<$PF_TABLE>"; then echo pf
    elif have pfctl; then echo pf_unreferenced
    else echo none; fi
}

# ADDRESSES
is_v4() {
    printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || return 1
    for o in $(printf '%s' "$1" | tr '.' ' '); do [ "$o" -le 255 ] || return 1; done
}
is_v6() { printf '%s' "$1" | grep -Eq '^[0-9A-Fa-f:]+$' && printf '%s' "$1" | grep -q ':.*:'; }
is_mac() { printf '%s' "$1" | grep -Eq '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'; }
is_lan_v4() { is_v4 "$1" && printf '%s' "$1" | grep -Eq '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)'; }

own_addresses() {
    if have ip; then
        ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1
        ip route show default 2>/dev/null | awk '/via/{print $3}'
        ip -6 route show default 2>/dev/null | awk '/via/{print $3}'
    else
        ifconfig 2>/dev/null | awk '$1=="inet"||$1=="inet6"{print $2}' | cut -d% -f1
        route -n get default 2>/dev/null | awk '/gateway/{print $2}'
    fi
}

check_ip() {
    ip=$1
    is_v4 "$ip" || is_v6 "$ip" || fail "'$ip' is not one address"
    case "$ip" in
        127.*|0.*|169.254.*|255.255.255.255|22[4-9].*|23[0-9].*|::|::1|[Ff][Ee]80:*|[Ff][Ff]*)
            fail "$ip is loopback, link-local, multicast or unspecified" ;;
    esac
    [ "$ip" = "$CALLER" ] && fail "$ip is the AgentalSec host that is asking"
    for own in $(own_addresses); do
        [ "$own" = "$ip" ] && fail "$ip is this router or its upstream gateway"
    done
    return 0
}

own_macs() {
    if have ip; then ip -o link show 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="link/ether") print $(i+1)}'
    else ifconfig 2>/dev/null | awk '$1=="ether"||$(NF-1)=="HWaddr"{print $NF}'; fi
}
caller_mac() { have ip && ip neigh show "$CALLER" 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="lladdr") print $(i+1)}'; }

check_mac() {
    is_mac "$1" || fail "'$1' is not one hardware address in lower case"
    case "$1" in
        ff:ff:ff:ff:ff:ff|00:00:00:00:00:00) fail "$1 is broadcast or empty" ;;
    esac
    [ "$1" = "$(caller_mac)" ] && fail "$1 is the AgentalSec host that is asking"
    for own in $(own_macs); do
        [ "$own" = "$1" ] && fail "$1 is one of this router's own interfaces"
    done
    return 0
}

# BLOCKS
# Returns 0 when the table was already there, 2 when it was just made, and
# the caller refills a new table from the state file. Built in two steps so
# a router whose nft refuses the hardware address rules still gets IP blocks
# and counters; that refusal is kept in MAC_ERROR_FILE and reported.
nft_err() { printf '%s' "$1" | tr '\n' ' ' | cut -c1-300; }

# Loads a ruleset from stdin through a file: some routers have no
# /dev/stdin, so `nft -f -` cannot open its input there.
nft_load() {
    f=$(mktemp /tmp/agentalsec-nft.XXXXXX) || { echo "mktemp failed"; return 1; }
    cat > "$f"
    nft -f "$f" 2>&1; rc=$?
    rm -f "$f"
    return $rc
}

nft_ensure() {
    if nft list table inet $NFT_TABLE >/dev/null 2>&1; then
        if nft list chain inet $NFT_TABLE devcount >/dev/null 2>&1; then
            mac_rules_ok || nft_mac_rules
            return 0
        fi
        nft delete table inet $NFT_TABLE 2>/dev/null
    fi
    err=$(nft_load <<EOF
table inet $NFT_TABLE {
    set blocked4 { type ipv4_addr; }
    set blocked6 { type ipv6_addr; }
    set blockedmac { type ether_addr; }
    chain forward {
        type filter hook forward priority -5; policy accept;
        ip saddr @blocked4 drop
        ip daddr @blocked4 drop
        ip6 saddr @blocked6 drop
        ip6 daddr @blocked6 drop
    }
    chain input {
        type filter hook input priority -5; policy accept;
        ip saddr @blocked4 drop
        ip6 saddr @blocked6 drop
    }
    chain devcount {
        type filter hook forward priority 5; policy accept;
    }
}
EOF
) || fail "nft refused to create table $NFT_TABLE: $(nft_err "$err")"
    nft_mac_rules
    return 2
}

# The hardware address rules, apart, so a router that refuses them keeps
# IP blocks and counters, and so they are retried while they are missing.
nft_mac_rules() {
    mkdir -p "$STATE_DIR" 2>/dev/null
    err=$(nft_load <<EOF
table inet $NFT_TABLE {
    set blockedmac { type ether_addr; }
    chain prerouting {
        type filter hook prerouting priority -5; policy accept;
        ether saddr @blockedmac udp dport { 53, 67 } accept
        ether saddr @blockedmac tcp dport 53 accept
        ether saddr @blockedmac drop
    }
}
EOF
)
    if [ $? -eq 0 ]; then rm -f "$MAC_ERROR_FILE"
    else nft_err "$err" > "$MAC_ERROR_FILE"; nft delete chain inet $NFT_TABLE prerouting 2>/dev/null; fi
}

mac_rules_ok() { nft list chain inet $NFT_TABLE prerouting >/dev/null 2>&1; }

state_add() {
    mkdir -p "$STATE_DIR" 2>/dev/null
    grep -qxF "$1 $2" "$STATE_FILE" 2>/dev/null || printf '%s %s\n' "$1" "$2" >> "$STATE_FILE"
}

state_del() {
    [ -f "$STATE_FILE" ] || return 0
    grep -vxF "$1 $2" "$STATE_FILE" > "$STATE_FILE.new"; mv "$STATE_FILE.new" "$STATE_FILE"
}

# Puts every saved block back. A saved entry that is no longer a valid
# address is counted as skipped, never applied.
restore_state() {
    n=0; bad=0; apps=""
    if [ -f "$STATE_FILE" ]; then
        while read -r kind value; do
            case $kind in
                ip) if is_v6 "$value"; then s=blocked6; else s=blocked4; fi
                    if { is_v4 "$value" || is_v6 "$value"; } && \
                        nft add element inet $NFT_TABLE $s "{ $value }" 2>/dev/null; then
                        n=$((n+1)); else bad=$((bad+1)); fi ;;
                mac) if is_mac "$value" && \
                        nft add element inet $NFT_TABLE blockedmac "{ $value }" 2>/dev/null; then
                        n=$((n+1)); else bad=$((bad+1)); fi ;;
                app) m=${value%% *}; a=${value#* }
                    if is_mac "$m" && is_app "$a" && app_apply "$m" "$a"; then
                        n=$((n+1)); apps="$apps $a"; else bad=$((bad+1)); fi ;;
                *) bad=$((bad+1)) ;;
            esac
        done < "$STATE_FILE"
    fi
    RESTORED=$n; SKIPPED=$bad
    portal_restore
    # The resolver's app list lives in a directory a reboot clears.
    if [ -n "$apps" ]; then
        apps_conf_write || record "$APPS_CONF_ERR"
        for a in $(printf '%s\n' $apps | sort -u); do
            app_seed "$a" </dev/null >/dev/null 2>&1 &
        done
    fi
}

do_restore() {
    [ "$(fw_backend)" = nft ] || fail "restore needs nft"
    nft_ensure
    restore_state
    record "restored $RESTORED"
    ok restore; echo "restored=$RESTORED"; echo "skipped=$SKIPPED"
}

nft_list() {
    for s in blocked4 blocked6 blockedmac; do
        nft list set inet $NFT_TABLE $s 2>/dev/null | tr -d '{},;' | \
            awk '/elements/{f=1; sub(/.*=/,"")} f{for(i=1;i<=NF;i++) print $i} /}/{f=0}'
    done | grep -v '^$'
}

ipt_for() { if is_v6 "$1"; then echo ip6tables; else echo iptables; fi; }

ipt_ensure() {
    for t in iptables ip6tables; do
        have $t || continue
        $t -N $IPT_CHAIN 2>/dev/null
        for hook in FORWARD INPUT; do
            $t -C $hook -j $IPT_CHAIN 2>/dev/null || $t -I $hook 1 -j $IPT_CHAIN
        done
    done
}

ipt_list() {
    for t in iptables ip6tables; do
        have $t && $t -S $IPT_CHAIN 2>/dev/null | awk '$3=="-s"{print $4}' | cut -d/ -f1
    done
}

list_blocks() {
    case $(fw_backend) in
        nft) nft list table inet $NFT_TABLE >/dev/null 2>&1 && nft_list ;;
        iptables) ipt_list ;;
        pf) pfctl -t $PF_TABLE -T show 2>/dev/null | tr -d ' ' ;;
    esac
}

is_blocked() { list_blocks | grep -qxF "$1"; }

do_block() {
    check_ip "$1"
    backend=$(fw_backend)
    case $backend in
        none) fail "no packet filter this agent can drive (nft, iptables or pf)" ;;
        pf_unreferenced) fail "pf is present but no rule uses the table <$PF_TABLE>; add a block rule for it first" ;;
    esac
    if is_blocked "$1"; then ok block; echo "ip=$1"; echo "already=yes"; echo "backend=$backend"; return; fi
    [ "$(list_blocks | wc -l)" -lt $MAX_BLOCKS ] || fail "already $MAX_BLOCKS blocks, the cap"
    case $backend in
        nft)
            nft_ensure; [ $? -eq 2 ] && restore_state
            if is_v6 "$1"; then s=blocked6; else s=blocked4; fi
            nft add element inet $NFT_TABLE $s "{ $1 }" || fail "nft refused to add $1"
            state_add ip "$1" ;;
        iptables)
            ipt_ensure
            t=$(ipt_for "$1")
            $t -A $IPT_CHAIN -s "$1" -j DROP && $t -A $IPT_CHAIN -d "$1" -j DROP \
                || fail "$t refused to add $1" ;;
        pf)
            pfctl -t $PF_TABLE -T add "$1" >/dev/null 2>&1 || fail "pfctl refused to add $1"
            pfctl -k "$1" >/dev/null 2>&1 ;;
    esac
    is_blocked "$1" || fail "the filter reported success but $1 is not there when read back; treat it as NOT blocked"
    record "blocked"
    ok block; echo "ip=$1"; echo "already=no"; echo "backend=$backend"; echo "verified=read_back"
}

do_unblock() {
    is_v4 "$1" || is_v6 "$1" || fail "'$1' is not one address"
    backend=$(fw_backend)
    state_del ip "$1"
    if ! is_blocked "$1"; then ok unblock; echo "ip=$1"; echo "was_blocked=no"; return; fi
    case $backend in
        nft) if is_v6 "$1"; then s=blocked6; else s=blocked4; fi
             nft delete element inet $NFT_TABLE $s "{ $1 }" ;;
        iptables) t=$(ipt_for "$1")
             while $t -D $IPT_CHAIN -s "$1" -j DROP 2>/dev/null; do :; done
             while $t -D $IPT_CHAIN -d "$1" -j DROP 2>/dev/null; do :; done ;;
        pf) pfctl -t $PF_TABLE -T delete "$1" >/dev/null 2>&1 ;;
    esac
    is_blocked "$1" && fail "$1 is still blocked after the delete"
    record "unblocked"
    ok unblock; echo "ip=$1"; echo "was_blocked=yes"; echo "verified=read_back"
}

do_blockmac() {
    check_mac "$1"
    [ "$(fw_backend)" = nft ] || fail "blocking by hardware address needs nft"
    nft_ensure; [ $? -eq 2 ] && restore_state
    mac_rules_ok || fail "this router's nft refused the hardware address rules: $(cat "$MAC_ERROR_FILE" 2>/dev/null)"
    if is_blocked "$1"; then state_add mac "$1"; ok blockmac; echo "mac=$1"; echo "already=yes"; return; fi
    [ "$(list_blocks | wc -l)" -lt $MAX_BLOCKS ] || fail "already $MAX_BLOCKS blocks, the cap"
    nft add element inet $NFT_TABLE blockedmac "{ $1 }" || fail "nft refused to add $1"
    state_add mac "$1"
    is_blocked "$1" || fail "nft reported success but $1 is not there when read back; treat it as NOT blocked"
    record "blocked"
    ok blockmac; echo "mac=$1"; echo "already=no"; echo "verified=read_back"
}

do_unblockmac() {
    is_mac "$1" || fail "'$1' is not one hardware address in lower case"
    state_del mac "$1"
    if ! is_blocked "$1"; then ok unblockmac; echo "mac=$1"; echo "was_blocked=no"; return; fi
    nft delete element inet $NFT_TABLE blockedmac "{ $1 }"
    is_blocked "$1" && fail "$1 is still blocked after the delete"
    record "unblocked"
    ok unblockmac; echo "mac=$1"; echo "was_blocked=yes"; echo "verified=read_back"
}

# COUNTERS
# One plain counter rule each way per private IPv4 address the router has a
# lease or neighbour entry for, in a forward chain after the blocks, so
# traffic to the router itself and dropped traffic are not counted.
# Body lines: ip up_packets up_bytes down_packets down_bytes
lan_addresses() {
    { f=$(lease_file); [ -n "$f" ] && awk '{print $3}' "$f"
      have ip && ip -4 neigh show 2>/dev/null | awk '{print $1}'; } | sort -u | \
    while read -r a; do is_lan_v4 "$a" && echo "$a"; done | head -n $MAX_COUNTED
}

do_counters() {
    [ "$(fw_backend)" = nft ] || fail "counters need nft"
    restored=no
    nft_ensure; [ $? -eq 2 ] && { restore_state; restored=yes; }
    known=$(nft list chain inet $NFT_TABLE devcount 2>/dev/null | awk '$2=="saddr"{print $3}')
    for a in $(lan_addresses); do
        printf '%s\n' "$known" | grep -qxF "$a" && continue
        nft add rule inet $NFT_TABLE devcount ip saddr "$a" counter 2>/dev/null
        nft add rule inet $NFT_TABLE devcount ip daddr "$a" counter 2>/dev/null
    done
    # The page could not start at boot before the address was up.
    [ -n "$(msg_targets)" ] && [ -z "$(portal_pids)" ] && portal_restore
    ok counters; echo "restored=$restored"; echo "mac_rules=$(mac_rules_ok && echo yes || echo no)"; echo "--"
    nft list chain inet $NFT_TABLE devcount 2>/dev/null | awk '
        $1=="ip" && ($2=="saddr" || $2=="daddr") {
            for (i=1; i<NF; i++) { if ($i=="packets") p=$(i+1); if ($i=="bytes") b=$(i+1) }
            if ($2=="saddr") up[$3]=p " " b; else dn[$3]=p " " b
            seen[$3]=1
        }
        END { for (ip in seen) print ip, (ip in up ? up[ip] : "0 0"), (ip in dn ? dn[ip] : "0 0") }'
}

portal_tools() {
    t=""
    have uhttpd && t="$t uhttpd"
    have nginx && t="$t nginx"
    busybox --list 2>/dev/null | grep -qx httpd && t="$t busybox_httpd"
    have lua && t="$t lua"
    have ucode && t="$t ucode"
    echo "${t# }"
}

# SINKHOLES
dnsmasq_confdir() {
    for pid in $(pidof dnsmasq 2>/dev/null); do
        conf=$(tr '\0' '\n' < /proc/$pid/cmdline 2>/dev/null | \
            awk 'p{print; exit} $0=="-C"||$0=="--conf-file"{p=1} /^--conf-file=/{sub(/^--conf-file=/,""); print; exit}')
        [ -n "$conf" ] || conf=/etc/dnsmasq.conf
        dir=$(awk -F= '/^conf-dir=/{print $2; exit}' "$conf" 2>/dev/null | cut -d, -f1)
        [ -n "$dir" ] && [ -d "$dir" ] && { echo "$dir"; return; }
    done
    [ -d /etc/dnsmasq.d ] && have dnsmasq && echo /etc/dnsmasq.d
}

dns_backend() {
    if [ -n "$(dnsmasq_confdir)" ]; then echo dnsmasq
    elif have unbound-control && unbound-control status >/dev/null 2>&1; then echo unbound
    else echo none; fi
}

check_domain() {
    printf '%s' "$1" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)+[A-Za-z0-9-]{2,63}$' \
        || fail "'$1' is not a domain name"
    [ ${#1} -le 253 ] || fail "'$1' is too long"
}

restart_dnsmasq() {
    if [ -x /etc/init.d/dnsmasq ]; then /etc/init.d/dnsmasq restart >/dev/null 2>&1
    elif have systemctl; then systemctl restart dnsmasq >/dev/null 2>&1
    elif have service; then service dnsmasq restart >/dev/null 2>&1
    else return 1; fi
}

list_sinkholes() {
    case $(dns_backend) in
        dnsmasq) f="$(dnsmasq_confdir)/$SINKHOLE_FILE_NAME"
                 [ -f "$f" ] && awk -F/ '/^address=\//{print $2}' "$f" | sort -u ;;
        unbound) unbound-control list_local_zones 2>/dev/null | awk '$2=="always_nxdomain"{sub(/\.$/,"",$1); print $1}' ;;
    esac
}

do_sinkhole() {
    check_domain "$1"
    backend=$(dns_backend)
    [ "$backend" = none ] && fail "no resolver this agent can drive (dnsmasq with a conf-dir, or unbound-control)"
    if list_sinkholes | grep -qxF "$1"; then ok sinkhole; echo "domain=$1"; echo "already=yes"; return; fi
    case $backend in
        dnsmasq)
            f="$(dnsmasq_confdir)/$SINKHOLE_FILE_NAME"
            printf 'address=/%s/0.0.0.0\naddress=/%s/::\n' "$1" "$1" >> "$f" || fail "could not write $f"
            restart_dnsmasq || fail "the entry was written but dnsmasq could not be restarted, so it is NOT in force" ;;
        unbound)
            unbound-control local_zone "$1" always_nxdomain >/dev/null 2>&1 || fail "unbound-control refused $1" ;;
    esac
    list_sinkholes | grep -qxF "$1" || fail "$1 is not in the resolver's list when read back"
    record "sinkholed"
    ok sinkhole; echo "domain=$1"; echo "already=no"; echo "backend=$backend"
}

do_unsinkhole() {
    check_domain "$1"
    if ! list_sinkholes | grep -qxF "$1"; then ok unsinkhole; echo "domain=$1"; echo "was_sinkholed=no"; return; fi
    case $(dns_backend) in
        dnsmasq)
            f="$(dnsmasq_confdir)/$SINKHOLE_FILE_NAME"
            grep -vF "/$1/" "$f" > "$f.new"; mv "$f.new" "$f"
            restart_dnsmasq ;;
        unbound) unbound-control local_zone_remove "$1" >/dev/null 2>&1 ;;
    esac
    list_sinkholes | grep -qxF "$1" && fail "$1 is still sinkholed after the removal"
    record "unsinkholed"
    ok unsinkhole; echo "domain=$1"; echo "was_sinkholed=yes"
}

# APPS ON ONE DEVICE
# Each app is a list of domains, plus fixed networks for an app that can
# connect without DNS. The router's resolver puts every address those
# domains resolve to into the app's sets (dnsmasq nftset); `apprefresh`
# also copies them from the query log, which is all a dnsmasq without
# nftset gets. One rule per device and app drops that device's traffic to
# the sets and leaves every other device alone. A device with an app
# blocked also loses DNS over TLS (853), so its lookups use the router.
APPS="whatsapp facebook instagram tiktok youtube snapchat telegram discord netflix twitch roblox fortnite x steam reddit signal"

app_domains() {
    case $1 in
        whatsapp) echo "whatsapp.com whatsapp.net wa.me" ;;
        facebook) echo "facebook.com facebook.net fbcdn.net fb.com fb.me fbsbx.com messenger.com" ;;
        instagram) echo "instagram.com cdninstagram.com ig.me" ;;
        tiktok) echo "tiktok.com tiktokv.com tiktokcdn.com tiktokcdn-us.com byteoversea.com ibytedtos.com musical.ly" ;;
        youtube) echo "youtube.com youtu.be googlevideo.com ytimg.com youtube-nocookie.com youtubei.googleapis.com" ;;
        snapchat) echo "snapchat.com snapkit.com sc-cdn.net sc-static.net snap-dev.net" ;;
        telegram) echo "telegram.org t.me telegram.me telesco.pe" ;;
        discord) echo "discord.com discord.gg discordapp.com discordapp.net discord.media" ;;
        netflix) echo "netflix.com netflix.net nflxvideo.net nflximg.net nflxext.com nflxso.net" ;;
        twitch) echo "twitch.tv ttvnw.net jtvnw.net twitchcdn.net" ;;
        roblox) echo "roblox.com rbxcdn.com" ;;
        fortnite) echo "fortnite.com epicgames.com epicgames.dev" ;;
        x) echo "x.com twitter.com twimg.com t.co" ;;
        steam) echo "steampowered.com steamcommunity.com steamstatic.com steamcontent.com steamserver.net" ;;
        reddit) echo "reddit.com redd.it redditmedia.com redditstatic.com" ;;
        signal) echo "signal.org whispersystems.org signal.group" ;;
    esac
}

# Telegram's published ranges; its apps fall back to them without DNS.
app_nets4() {
    case $1 in
        telegram) echo "91.105.192.0/23, 91.108.4.0/22, 91.108.8.0/22, 91.108.12.0/22, 91.108.16.0/22, 91.108.20.0/22, 91.108.56.0/22, 149.154.160.0/20, 185.76.151.0/24" ;;
    esac
}
app_nets6() {
    case $1 in
        telegram) echo "2001:67c:4e8::/48, 2001:b28:f23c::/48, 2001:b28:f23d::/48, 2001:b28:f23f::/48, 2a0a:f280::/32" ;;
    esac
}

is_app() {
    case " $APPS " in *" $1 "*) return 0 ;; esac
    return 1
}

dnsmasq_nftset() {
    have dnsmasq && dnsmasq --version 2>/dev/null | grep -Eq '(^|[ ])nftset([ ]|$)'
}

app_mode() {
    [ "$(fw_backend)" = nft ] || { echo none; return; }
    if [ "$(dns_backend)" = dnsmasq ] && dnsmasq_nftset; then echo nftset
    elif [ "$(log_source)" != none ] && read_log $MAX_LINES | grep -q 'dnsmasq.* reply '; then echo log
    else echo none; fi
}

app_ensure() {
    a=$1
    if nft list set inet $NFT_TABLE "app_${a}4" >/dev/null 2>&1 && \
        nft list chain inet $NFT_TABLE appblock >/dev/null 2>&1; then return 0; fi
    n4=$(app_nets4 "$a"); n6=$(app_nets6 "$a")
    err=$( {
        echo "table inet $NFT_TABLE {"
        echo "    set app_${a}4 { type ipv4_addr; flags timeout; timeout 1d; }"
        echo "    set app_${a}6 { type ipv6_addr; flags timeout; timeout 1d; }"
        [ -n "$n4" ] && echo "    set appnet_${a}4 { type ipv4_addr; flags interval; elements = { $n4 }; }"
        [ -n "$n6" ] && echo "    set appnet_${a}6 { type ipv6_addr; flags interval; elements = { $n6 }; }"
        echo "    chain appblock { type filter hook prerouting priority -4; policy accept; }"
        echo "}"
    } | nft_load ) || { APP_ERR="nft refused the sets for $a: $(nft_err "$err")"; return 1; }
}

app_rule_handles() {
    nft -a list chain inet $NFT_TABLE appblock 2>/dev/null | grep -F "comment \"$1\"" | awk '{print $NF}'
}

app_rules_del() {
    for h in $(app_rule_handles "$1"); do
        nft delete rule inet $NFT_TABLE appblock handle "$h" 2>/dev/null
    done
}

# Sets APP_ERR and returns 1 on a refusal, so restore can go on past it.
app_apply() {
    m=$1; a=$2; c="app $m $a"
    app_ensure "$a" || return 1
    if [ -z "$(app_rule_handles "dot $m")" ]; then
        err=$(printf 'add rule inet %s appblock ether saddr %s tcp dport 853 drop comment "dot %s"\nadd rule inet %s appblock ether saddr %s udp dport 853 drop comment "dot %s"\n' \
            $NFT_TABLE "$m" "$m" $NFT_TABLE "$m" "$m" | nft_load) || { APP_ERR="nft refused the DNS over TLS rule for $m: $(nft_err "$err")"; return 1; }
    fi
    [ -n "$(app_rule_handles "$c")" ] && return 0
    err=$( {
        echo "add rule inet $NFT_TABLE appblock ether saddr $m ip daddr @app_${a}4 drop comment \"$c\""
        echo "add rule inet $NFT_TABLE appblock ether saddr $m ip6 daddr @app_${a}6 drop comment \"$c\""
        [ -n "$(app_nets4 "$a")" ] && echo "add rule inet $NFT_TABLE appblock ether saddr $m ip daddr @appnet_${a}4 drop comment \"$c\""
        [ -n "$(app_nets6 "$a")" ] && echo "add rule inet $NFT_TABLE appblock ether saddr $m ip6 daddr @appnet_${a}6 drop comment \"$c\""
    } | nft_load ) || { APP_ERR="nft refused the rules for $a on $m: $(nft_err "$err")"; return 1; }
}

# Body lines: mac app, read from the rules themselves.
list_app_blocks() {
    nft list chain inet $NFT_TABLE appblock 2>/dev/null | \
        sed -n 's/.*comment "app \([0-9a-f:]*\) \([a-z0-9]*\)".*/\1 \2/p' | sort -u
}

blocked_apps() { list_app_blocks | awk '{print $2}' | sort -u; }

app_learned() {
    for f in 4 6; do nft list set inet $NFT_TABLE "app_${1}$f" 2>/dev/null; done | tr -d '{},;' | \
        awk '/elements/{f=1; sub(/.*=/,"")} f{for(i=1;i<=NF;i++) if ($i ~ /^[0-9a-f.:]+$/ && $i ~ /[.:]/) n++} END{print n+0}'
}

# The resolver's list of app domains, rewritten from the rules in force.
# Sets APPS_CONF_ERR and returns 1 when it could not be put in force.
apps_conf_write() {
    [ "$(app_mode)" = nftset ] || return 0
    dir=$(dnsmasq_confdir); [ -n "$dir" ] || return 0
    f="$dir/$APPS_FILE_NAME"
    new=$(for a in $(blocked_apps); do
        printf 'nftset=/%s/4#inet#%s#app_%s4,6#inet#%s#app_%s6\n' \
            "$(app_domains "$a" | tr ' ' '/')" $NFT_TABLE "$a" $NFT_TABLE "$a"
    done)
    old=$(cat "$f" 2>/dev/null)
    [ "$new" = "$old" ] && return 0
    if [ -n "$new" ]; then
        printf '%s\n' "$new" > "$f" || { APPS_CONF_ERR="could not write $f"; return 1; }
    else rm -f "$f"; fi
    restart_dnsmasq || { APPS_CONF_ERR="the app list was written but dnsmasq could not be restarted, so it is NOT in force"; return 1; }
}

# Looks each domain up through the router's own resolver, which fills the
# sets as it answers. Run in the background: a lookup can take seconds.
app_seed() {
    for d in $(app_domains "$1"); do
        if have timeout; then timeout 3 nslookup "$d" 127.0.0.1
        else nslookup "$d" 127.0.0.1; fi
    done
}

# Copies answers for blocked apps' domains from the query log into the
# sets. Sets ADDED to the addresses it put in.
app_harvest() {
    ADDED=0
    apps_now=$(blocked_apps)
    [ -n "$apps_now" ] && [ "$(log_source)" != none ] || return 0
    pairs=$(read_log $MAX_LINES | awk '/dnsmasq/ { for (i=1; i<NF-1; i++) if (($i=="reply" || $i=="cached") && $(i+2)=="is") print $(i+1), $(i+3) }' | sort -u)
    [ -n "$pairs" ] || return 0
    for a in $apps_now; do
        ips=$(for d in $(app_domains "$a"); do
            printf '%s\n' "$pairs" | awk -v d="$d" '{ n=$1; if (n==d || substr(n, length(n)-length(d)) == "." d) print $2 }'
        done | sort -u)
        for ip in $ips; do
            case $ip in 0.0.0.0|::|127.*) continue ;; esac
            if is_v4 "$ip"; then s="app_${a}4"; elif is_v6 "$ip"; then s="app_${a}6"; else continue; fi
            nft add element inet $NFT_TABLE "$s" "{ $ip }" 2>/dev/null && ADDED=$((ADDED+1))
        done
    done
}

do_apps() {
    [ "$(fw_backend)" = nft ] || fail "app blocks need nft"
    ok apps; echo "mode=$(app_mode)"; echo "known=$APPS"
    for a in $(blocked_apps); do echo "learned_$a=$(app_learned "$a")"; done
    echo "--"; list_app_blocks
}

do_blockapp() {
    m=$1; a=$2
    check_mac "$m"
    is_app "$a" || fail "'$a' is not an app this agent knows. It knows: $APPS"
    mode=$(app_mode)
    [ "$mode" = none ] && fail "blocking an app needs nft, and dnsmasq built with nftset or logging its queries"
    nft_ensure; [ $? -eq 2 ] && restore_state
    if list_app_blocks | grep -qxF "$m $a"; then
        state_add app "$m $a"; ok blockapp; echo "mac=$m"; echo "app=$a"; echo "already=yes"; return
    fi
    [ "$(list_app_blocks | wc -l)" -lt $MAX_APP_BLOCKS ] || fail "already $MAX_APP_BLOCKS app blocks, the cap"
    app_apply "$m" "$a" || fail "$APP_ERR"
    state_add app "$m $a"
    list_app_blocks | grep -qxF "$m $a" || fail "nft reported success but the rule for $a on $m is not there when read back; treat it as NOT blocked"
    apps_conf_write || fail "$APPS_CONF_ERR"
    app_harvest
    app_seed "$a" </dev/null >/dev/null 2>&1 &
    record "blocked app $a"
    ok blockapp; echo "mac=$m"; echo "app=$a"; echo "already=no"; echo "mode=$mode"
    echo "addresses=$ADDED"; echo "verified=read_back"
}

do_unblockapp() {
    m=$1; a=$2
    is_mac "$m" || fail "'$m' is not one hardware address in lower case"
    is_app "$a" || fail "'$a' is not an app this agent knows. It knows: $APPS"
    state_del app "$m $a"
    if ! list_app_blocks | grep -qxF "$m $a"; then
        ok unblockapp; echo "mac=$m"; echo "app=$a"; echo "was_blocked=no"; return
    fi
    app_rules_del "app $m $a"
    list_app_blocks | grep -q "^$m " || app_rules_del "dot $m"
    list_app_blocks | grep -qxF "$m $a" && fail "the rule for $a on $m is still there after the delete"
    apps_conf_write || fail "$APPS_CONF_ERR"
    if ! blocked_apps | grep -qxF "$a"; then
        for s in "app_${a}4" "app_${a}6" "appnet_${a}4" "appnet_${a}6"; do
            nft delete set inet $NFT_TABLE "$s" 2>/dev/null
        done
    fi
    record "unblocked app $a"
    ok unblockapp; echo "mac=$m"; echo "app=$a"; echo "was_blocked=yes"; echo "verified=read_back"
}

do_apprefresh() {
    [ "$(fw_backend)" = nft ] || fail "app blocks need nft"
    app_harvest
    ok apprefresh; echo "addresses=$ADDED"
}

# MESSAGES TO ONE DEVICE OR EVERY DEVICE
# A device's plain web requests (port 80) are sent to a page on this router
# that shows the owner's message with an OK button and a reply box. Phones
# open that page by themselves when they check for a captive portal. A
# message made with messagekeep stays after OK, which is what a cut off
# device is shown; the hardware address block lets that page through.
# The text arrives as hex, since the request takes no punctuation, and the
# page decodes and escapes it.

portal_ip() {
    ip=$(printf '%s' "${SSH_CONNECTION:-}" | awk '{print $3}')
    if is_v4 "$ip"; then
        mkdir -p "$STATE_DIR"
        [ "$(cat "$PORTAL_IP_FILE" 2>/dev/null)" = "$ip" ] || echo "$ip" > "$PORTAL_IP_FILE"
        echo "$ip"; return
    fi
    ip=$(cat "$PORTAL_IP_FILE" 2>/dev/null)
    is_v4 "$ip" && echo "$ip"
}

portal_iface() {
    have ip && ip -o -4 addr show 2>/dev/null | awk -v a="$1" '{split($4, p, "/"); if (p[1] == a) {print $2; exit}}'
}

uhttpd_ok() { have uhttpd && uhttpd -h 2>&1 | grep -q -- '-E'; }

portal_pids() {
    for p in $(pidof uhttpd 2>/dev/null); do
        tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | grep -q -- "$PORTAL_WWW" && echo "$p"
    done
}

portal_page_write() {
    mkdir -p "$PORTAL_WWW/cgi-bin" "$MSG_DIR" "$REPLY_DIR" || return 1
    cat > "$PORTAL_WWW/cgi-bin/msg.new" <<'PAGE_EOF'
#!/bin/sh
# The page a messaged device is shown, written by the AgentalSec agent.
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
D=/etc/agentalsec
T=agentalsec_gw
mac=$(ip neigh show "$REMOTE_ADDR" 2>/dev/null | awk '{for (i=1; i<NF; i++) if ($i == "lladdr") {print $(i+1); exit}}')
printf '%s' "$mac" | grep -Eq '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' || mac=""
f=""
[ -n "$mac" ] && [ -f "$D/messages/$mac.hex" ] && f="$D/messages/$mac.hex"
[ -z "$f" ] && [ -f "$D/messages/all.hex" ] && f="$D/messages/all.hex"

text() {
    awk 'BEGIN { for (i = 0; i < 256; i++) h[sprintf("%02x", i)] = i }
    { for (i = 1; i < length($0); i += 2) { c = h[substr($0, i, 2)]
        if (c == 38) printf "&amp;"; else if (c == 60) printf "&lt;"
        else if (c == 62) printf "&gt;"; else if (c == 34) printf "&quot;"
        else if (c == 39) printf "&#39;"; else if (c == 10) printf "<br>"
        else if (c >= 32) printf "%c", c } }' "$1"
}

head_out() {
    printf 'Status: 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\n\r\n'
    printf '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>A message for you</title>'
    printf '<style>body{font-family:sans-serif;max-width:32em;margin:2em auto;padding:0 1em;line-height:1.5}p.m{font-size:1.2em;padding:1em;border:1px solid #888;border-radius:8px}textarea{width:100%%;min-height:5em;box-sizing:border-box}button{font-size:1.1em;padding:.5em 1.4em;margin:.4em .4em 0 0}</style></head><body>'
}

if [ "$REQUEST_METHOD" = POST ] && [ -n "$mac" ]; then
    n=${CONTENT_LENGTH:-0}
    case $n in ''|*[!0-9]*) n=0 ;; esac
    [ "$n" -le 2000 ] || n=2000
    body=$(head -c "$n" | tr -cd 'A-Za-z0-9%+._=&*-')
    if [ "$(ls "$D/replies" 2>/dev/null | wc -l)" -lt 200 ]; then
        printf '%s\n' "$body" > "$D/replies/$(date +%s)-$(printf '%s' "$mac" | tr ':' '-')-$$"
    fi
    case "&$body&" in
        *"&action=ok&"*)
            if [ "$f" = "$D/messages/$mac.hex" ] && [ ! -f "$D/messages/$mac.keep" ]; then
                nft delete element inet $T msgmac "{ $mac }" 2>/dev/null
                rm -f "$D/messages/${mac:?}.hex"
            elif [ "$f" = "$D/messages/all.hex" ]; then
                nft add element inet $T msgdone "{ $mac }" 2>/dev/null
                grep -qxF "$mac" "$D/messages/all.done" 2>/dev/null || echo "$mac" >> "$D/messages/all.done"
            fi ;;
    esac
    head_out
    printf '<h1>Thank you</h1><p>Your answer was sent.</p></body></html>\n'
    exit 0
fi

head_out
if [ -n "$f" ]; then
    printf '<h1>A message for you</h1><p class="m">'
    text "$f"
    printf '</p><form method="post" action="/cgi-bin/msg"><input type="hidden" name="action" value="ok"><button type="submit">OK</button></form>'
    printf '<form method="post" action="/cgi-bin/msg"><input type="hidden" name="action" value="reply"><p><label for="r">Reply</label></p><textarea id="r" name="reply" maxlength="500"></textarea><br><button type="submit">Send</button></form>'
else
    printf '<h1>No message</h1><p>There is nothing for this device right now.</p>'
fi
printf '</body></html>\n'
PAGE_EOF
    chmod 755 "$PORTAL_WWW/cgi-bin/msg.new" && mv "$PORTAL_WWW/cgi-bin/msg.new" "$PORTAL_WWW/cgi-bin/msg"
}

# Sets PORTAL_ERR and returns 1 when the redirect could not be put in place.
portal_nft() {
    a=$1
    err=$(nft_load <<EOF
table inet $NFT_TABLE {
    set msgmac { type ether_addr; }
    set msgdone { type ether_addr; }
    set portalip { type ipv4_addr; }
    chain portal { type nat hook prerouting priority -101; policy accept; }
}
EOF
) || { PORTAL_ERR="nft refused the message redirect: $(nft_err "$err")"; return 1; }
    nft add element inet $NFT_TABLE portalip "{ $a }" 2>/dev/null
    if ! nft list chain inet $NFT_TABLE portal 2>/dev/null | grep -q 'comment "msg"'; then
        err=$(nft add rule inet $NFT_TABLE portal ether saddr @msgmac meta nfproto ipv4 tcp dport 80 dnat ip to "$a:$PORTAL_PORT" comment '"msg"' 2>&1) \
            || { PORTAL_ERR="nft refused the message redirect: $(nft_err "$err")"; return 1; }
    fi
    # A device blocked by hardware address may still reach the page.
    if mac_rules_ok && ! nft list chain inet $NFT_TABLE prerouting 2>/dev/null | grep -q '@portalip'; then
        nft insert rule inet $NFT_TABLE prerouting ether saddr @blockedmac ip daddr @portalip tcp dport $PORTAL_PORT accept 2>/dev/null
    fi
    return 0
}

portal_all_rule() {
    a=$1; dev=$(portal_iface "$a")
    nft -a list chain inet $NFT_TABLE portal 2>/dev/null | grep -q 'comment "msgall"' && return 0
    [ -n "$dev" ] || { PORTAL_ERR="no interface holds $a"; return 1; }
    err=$(nft add rule inet $NFT_TABLE portal iifname "$dev" ether saddr != @msgdone meta nfproto ipv4 ip daddr != @portalip tcp dport 80 dnat ip to "$a:$PORTAL_PORT" comment '"msgall"' 2>&1) \
        || { PORTAL_ERR="nft refused the redirect for every device: $(nft_err "$err")"; return 1; }
}

portal_all_del() {
    for h in $(nft -a list chain inet $NFT_TABLE portal 2>/dev/null | grep 'comment "msgall"' | awk '{print $NF}'); do
        nft delete rule inet $NFT_TABLE portal handle "$h" 2>/dev/null
    done
}

portal_server() {
    a=$1
    [ -n "$(portal_pids)" ] && return 0
    uhttpd -p "$a:$PORTAL_PORT" -h "$PORTAL_WWW" -x /cgi-bin -E /cgi-bin/msg -t 15 -T 15 >/dev/null 2>&1
    sleep 1
    [ -n "$(portal_pids)" ] || { PORTAL_ERR="uhttpd did not stay running on $a:$PORTAL_PORT"; return 1; }
}

# Everything a message needs. Sets PORTAL_ERR and returns 1 on a refusal.
portal_ensure() {
    PORTAL_ERR=""
    [ "$(fw_backend)" = nft ] || { PORTAL_ERR="messages need nft"; return 1; }
    uhttpd_ok || { PORTAL_ERR="messages need uhttpd"; return 1; }
    a=$(portal_ip); [ -n "$a" ] || { PORTAL_ERR="this router's own address could not be told"; return 1; }
    nft_ensure; [ $? -eq 2 ] && restore_state
    portal_page_write || { PORTAL_ERR="could not write the page under $PORTAL_WWW"; return 1; }
    portal_nft "$a" || return 1
    portal_server "$a"
}

msg_targets() { ls "$MSG_DIR" 2>/dev/null | sed -n 's/\.hex$//p'; }

portal_restore() {
    [ -n "$(msg_targets)" ] || return 0
    portal_ensure || { record "$PORTAL_ERR"; return 1; }
    for t in $(msg_targets); do
        if [ "$t" = all ]; then portal_all_rule "$(portal_ip)"
        elif is_mac "$t"; then nft add element inet $NFT_TABLE msgmac "{ $t }" 2>/dev/null; fi
    done
    while read -r m; do
        is_mac "$m" && nft add element inet $NFT_TABLE msgdone "{ $m }" 2>/dev/null
    done < "$MSG_DIR/all.done" 2>/dev/null
    return 0
}

in_set() { nft list set inet $NFT_TABLE "$1" 2>/dev/null | tr -d '{},;' | grep -qw "$2"; }

do_message() {
    target=$1; hex=$2; keep=$3
    [ "$target" = all ] || check_mac "$target"
    [ "$target" = all ] && [ "$keep" = yes ] && fail "messagekeep is for one device"
    printf '%s' "$hex" | grep -Eq '^([0-9a-f][0-9a-f])+$' || fail "the message must be hex"
    [ ${#hex} -le $((MAX_MSG_BYTES * 2)) ] || fail "the message is longer than $MAX_MSG_BYTES bytes"
    portal_ensure || fail "$PORTAL_ERR"
    printf '%s\n' "$hex" > "$MSG_DIR/$target.hex" || fail "could not write the message"
    if [ "$target" = all ]; then
        nft flush set inet $NFT_TABLE msgdone 2>/dev/null
        : > "$MSG_DIR/all.done"
        c=$(caller_mac); [ -n "$c" ] && { nft add element inet $NFT_TABLE msgdone "{ $c }"; echo "$c" > "$MSG_DIR/all.done"; }
        portal_all_rule "$(portal_ip)" || fail "$PORTAL_ERR"
        nft list chain inet $NFT_TABLE portal 2>/dev/null | grep -q 'comment "msgall"' || fail "the redirect is not there when read back"
    else
        if [ "$keep" = yes ]; then : > "$MSG_DIR/$target.keep"; else rm -f "${MSG_DIR:?}/${target:?}.keep"; fi
        nft add element inet $NFT_TABLE msgmac "{ $target }" || fail "nft refused to add $target"
        in_set msgmac "$target" || fail "$target is not in the redirect set when read back"
    fi
    record "message to $target"
    ok "$VERB"; echo "target=$target"; echo "keep=${keep:-no}"; echo "port=$PORTAL_PORT"
    echo "server=$([ -n "$(portal_pids)" ] && echo running || echo stopped)"; echo "verified=read_back"
}

do_unmessage() {
    target=$1
    [ "$target" = all ] || is_mac "$target" || fail "'$target' is not one hardware address or all"
    [ -f "$MSG_DIR/$target.hex" ] || { ok unmessage; echo "target=$target"; echo "was_set=no"; return; }
    rm -f "${MSG_DIR:?}/${target:?}.hex" "${MSG_DIR:?}/${target:?}.keep"
    if [ "$target" = all ]; then
        portal_all_del; rm -f "${MSG_DIR:?}/all.done"; nft flush set inet $NFT_TABLE msgdone 2>/dev/null
    else
        nft delete element inet $NFT_TABLE msgmac "{ $target }" 2>/dev/null
        in_set msgmac "$target" && fail "$target is still redirected after the delete"
    fi
    if [ -z "$(msg_targets)" ]; then
        for p in $(portal_pids); do kill "$p" 2>/dev/null; done
    fi
    record "message removed from $target"
    ok unmessage; echo "target=$target"; echo "was_set=yes"; echo "verified=read_back"
}

# Body lines: target, keep or once, how many said OK, hex
do_messages() {
    ok messages; echo "port=$PORTAL_PORT"
    echo "server=$([ -n "$(portal_pids)" ] && echo running || echo stopped)"; echo "--"
    for t in $(msg_targets); do
        k=once; [ -f "$MSG_DIR/$t.keep" ] && k=keep
        d=0; [ "$t" = all ] && d=$(grep -c . "$MSG_DIR/all.done" 2>/dev/null)
        printf '%s %s %s %s\n' "$t" "$k" "${d:-0}" "$(head -c $((MAX_MSG_BYTES * 2)) "$MSG_DIR/$t.hex")"
    done
}

# Body lines: id body, the body as the page received it, url encoded.
do_replies() {
    ok replies; echo "--"
    for f in $(ls "$REPLY_DIR" 2>/dev/null | head -n $MAX_REPLIES); do
        printf '%s %s\n' "$f" "$(head -c 2000 "$REPLY_DIR/$f" | tr -cd 'A-Za-z0-9%+._=&*-')"
    done
}

do_clearreply() {
    printf '%s' "$1" | grep -Eq '^[0-9]+-[0-9a-f-]+-[0-9]+$' || fail "'$1' is not a reply id"
    rm -f "${REPLY_DIR:?}/${1:?}"
    [ -e "$REPLY_DIR/$1" ] && fail "the reply is still there after the delete"
    ok clearreply; echo "id=$1"
}

# READS
lease_file() { for f in $LEASE_FILES; do [ -r "$f" ] && { echo "$f"; return; }; done; }

log_source() {
    if have logread; then echo logread
    elif have journalctl; then echo journalctl
    else for f in $LOG_FILES; do [ -r "$f" ] && { echo "$f"; return; }; done; echo none; fi
}

read_log() {
    n=$1
    case $(log_source) in
        logread) logread -l "$n" 2>/dev/null || logread 2>/dev/null | tail -n "$n" ;;
        journalctl) journalctl -n "$n" --no-pager -o short 2>/dev/null ;;
        none) return 1 ;;
        *) tail -n "$n" "$(log_source)" ;;
    esac
}

# Sets N. Not called in $(...), so its refusal ends the script.
set_count() {
    N=${1:-200}
    printf '%s' "$N" | grep -Eq '^[0-9]{1,5}$' || fail "the line count must be a number"
    [ "$N" -le $MAX_LINES ] || N=$MAX_LINES
}

do_probe() {
    ok probe
    echo "agent_version=$VERSION"
    if [ -r /etc/openwrt_release ]; then
        echo "os=openwrt"; . /etc/openwrt_release 2>/dev/null; echo "os_release=${DISTRIB_DESCRIPTION:-}"
    elif [ -r /etc/os-release ]; then
        . /etc/os-release 2>/dev/null; echo "os=${ID:-linux}"; echo "os_release=${PRETTY_NAME:-}"
    else echo "os=$(uname -s 2>/dev/null)"; echo "os_release=$(uname -r 2>/dev/null)"; fi
    echo "kernel=$(uname -sr 2>/dev/null)"
    fw=$(fw_backend); echo "firewall=$fw"
    case $fw in nft|iptables|pf) echo "cap=block" ;; esac
    [ "$fw" = nft ] && { echo "cap=blockmac"; echo "cap=counters"; echo "cap=persist"; }
    dns=$(dns_backend); echo "dns=$dns"
    [ "$dns" != none ] && echo "cap=sinkhole"
    lf=$(lease_file); [ -n "$lf" ] && { echo "cap=leases"; echo "lease_file=$lf"; }
    if have ip || have arp; then echo "cap=neighbors"; fi
    if [ -r /proc/net/nf_conntrack ] || have conntrack || have pfctl; then echo "cap=conntrack"; fi
    ls=$(log_source); echo "log_source=$ls"
    if [ "$ls" != none ]; then
        echo "cap=log"
        read_log 2000 | grep -q 'dnsmasq.*query\[' && echo "cap=dnslog"
    fi
    am=$(app_mode); echo "appblock=$am"
    [ "$am" != none ] && echo "cap=appblock"
    echo "apps=$APPS"
    echo "caller=$CALLER"
    echo "portal_tools=$(portal_tools)"
    [ "$fw" = nft ] && uhttpd_ok && { echo "cap=message"; echo "portal_port=$PORTAL_PORT"; }
}

case "$VERB" in
    version) ok version; echo "agent_version=$VERSION" ;;
    probe) do_probe ;;
    leases)
        f=$(lease_file); [ -n "$f" ] || fail "no lease file this agent knows"
        ok leases; echo "lease_file=$f"; echo "--"; head -n 5000 "$f" ;;
    neighbors)
        ok neighbors
        if have ip; then echo "format=ip"; echo "--"; ip neigh show 2>/dev/null | head -n 5000
        else echo "format=bsd"; echo "--"; arp -an 2>/dev/null | head -n 5000; have ndp && ndp -an 2>/dev/null | head -n 5000; fi ;;
    conntrack)
        [ -z "$ARG1" ] || is_v4 "$ARG1" || is_v6 "$ARG1" || fail "'$ARG1' is not one address"
        if [ -r /proc/net/nf_conntrack ]; then src="cat /proc/net/nf_conntrack"; fmt=nf
        elif have conntrack; then src="conntrack -L"; fmt=nf
        elif have pfctl; then src="pfctl -ss"; fmt=pf
        else fail "no connection table this agent can read"; fi
        ok conntrack; echo "format=$fmt"; echo "--"
        if [ -n "$ARG1" ]; then $src 2>/dev/null | grep -F "$ARG1" | head -n 20000
        else $src 2>/dev/null | head -n 20000; fi ;;
    log)
        set_count "$ARG1"; [ "$(log_source)" = none ] && fail "no log this agent can read"
        ok log; echo "log_source=$(log_source)"; echo "--"; read_log "$N" ;;
    dnslog)
        set_count "$ARG1"; [ "$(log_source)" = none ] && fail "no log this agent can read"
        ok dnslog; echo "--"; read_log $MAX_LINES | grep 'dnsmasq' | grep -E 'query\[|reply |forwarded |cached |config ' | tail -n "$N" ;;
    blocks) ok blocks; echo "backend=$(fw_backend)"; echo "--"; list_blocks ;;
    block) [ -n "$ARG1" ] || fail "block needs an address"; do_block "$ARG1" ;;
    unblock) [ -n "$ARG1" ] || fail "unblock needs an address"; do_unblock "$ARG1" ;;
    blockmac) [ -n "$ARG1" ] || fail "blockmac needs a hardware address"; do_blockmac "$ARG1" ;;
    unblockmac) [ -n "$ARG1" ] || fail "unblockmac needs a hardware address"; do_unblockmac "$ARG1" ;;
    counters) do_counters ;;
    restore) do_restore ;;
    sinkholes) ok sinkholes; echo "backend=$(dns_backend)"; echo "--"; list_sinkholes ;;
    sinkhole) [ -n "$ARG1" ] || fail "sinkhole needs a domain"; do_sinkhole "$ARG1" ;;
    unsinkhole) [ -n "$ARG1" ] || fail "unsinkhole needs a domain"; do_unsinkhole "$ARG1" ;;
    apps) do_apps ;;
    blockapp) [ -n "$ARG2" ] || fail "blockapp needs a hardware address and an app"; do_blockapp "$ARG1" "$ARG2" ;;
    unblockapp) [ -n "$ARG2" ] || fail "unblockapp needs a hardware address and an app"; do_unblockapp "$ARG1" "$ARG2" ;;
    apprefresh) do_apprefresh ;;
    messages) do_messages ;;
    message) [ -n "$ARG2" ] || fail "message needs a hardware address or all, and the text"; do_message "$ARG1" "$ARG2" no ;;
    messagekeep) [ -n "$ARG2" ] || fail "messagekeep needs a hardware address and the text"; do_message "$ARG1" "$ARG2" yes ;;
    unmessage) [ -n "$ARG1" ] || fail "unmessage needs a hardware address or all"; do_unmessage "$ARG1" ;;
    replies) do_replies ;;
    clearreply) [ -n "$ARG1" ] || fail "clearreply needs an id"; do_clearreply "$ARG1" ;;
    *) fail "no verb named '$VERB'" ;;
esac
