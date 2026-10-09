# Router, DNS and remote hosts

A sensor on one machine sees that machine's traffic. These three additions
let AgentalSec see further: your router, your DNS resolver, and your other
Linux machines. All are optional and off by default. Restart the app after
changing `config.json`.

[Back to the README](../README.md)

## The router agent

The most useful addition. A small shell script on your router answers
AgentalSec's questions over SSH and, with your approval, carries out blocks
there. It fills the Live LAN tab and the router view on the Network tab.

### Which routers work

Any router that lets you log in over SSH with a root shell and a standard
`sh`. No brand is assumed. That includes:

- routers running **OpenWrt**, and similar open firmware;
- a **Raspberry Pi or any Linux box** set up as your router (with nftables or
  iptables, and dnsmasq for DHCP and DNS if you want leases, the DNS log and
  domain sinkholes);
- **pf based firewalls**;
- any other router with an SSH server and a root shell.

### Modem or router?

The box from your internet provider is usually a modem and a router in one,
and most of those do not allow SSH. That is fine: put your own router behind
it. Connect an OpenWrt router, or a Linux box acting as one, to the
provider's box, and connect all your devices to your router. The provider's
box then only brings the internet in, and your router runs your network,
where AgentalSec can see it.

If your provider's box offers a "bridge" or "modem only" mode, turning it on
gives your router the internet connection directly. Without it, the two
routers still work together.

### What the agent can do

The agent checks what the router offers and reports it, and the app offers
only what was reported:

- **block**, block an address: nft, iptables, or pf
- **blockmac**, block a device by hardware address
- **sinkhole**, make a domain unresolvable for the whole network: dnsmasq or
  unbound
- **leases**, DHCP leases: dnsmasq or Kea
- **neighbors**, the neighbour table: `ip neigh`, or arp and ndp
- **conntrack**, the router's connection table: who talks to what
- **counters**, traffic per device
- **log** and **dnslog**, the system log and dnsmasq's query log (with
  `log-queries` on)
- **appblock**, block an app for one device: nft plus dnsmasq built with
  nftset support, or a fallback that follows the query log
- **persist**, blocks that survive a router reboot (with nft)
- **message**, show a message on one device or every device, with an OK
  button and a reply box: nft, uhttpd for the page, and nat from nft or,
  where nft has none (older OpenWrt), from iptables

Sinkholes last until the router reboots.

### Enrolling a router

Run as your own user, not root, from the project folder:

```bash
./scripts/install_gateway_agent.sh
```

With no arguments it shows the plan and changes nothing. Then:

```bash
./scripts/install_gateway_agent.sh --enroll ROUTER_ADDRESS
```

This logs in to the router once as its administrator (you type the router's
password, or your own key is used), copies the agent there, and gives
AgentalSec its own SSH key. That key's line in the router's
`authorized_keys` forces the agent, so it can run the agent's commands and
nothing else: no shell, no port forwarding. Each enrolled computer gets its
own line, so enrolling one never removes another.

On OpenWrt it also turns on dnsmasq's query log (`log-queries`), which the
DNS reader needs, and raises the router's log size if it is small. Then it
switches the `gateway` block on in `config.json` for you:

```json
"gateway": {"enabled": true, "host": "ROUTER_ADDRESS", "port": 22, "user": "root"}
```

Restart AgentalSec to start reading the router. DNS reading is on by default
with source `auto`, so the router's lookups arrive with no further setup.

Use `--user` and `--port` if your router's SSH is not root on port 22. Check
it, or remove it again, with:

```bash
./scripts/install_gateway_agent.sh --verify ROUTER_ADDRESS
./scripts/install_gateway_agent.sh --remove ROUTER_ADDRESS
```

`--remove` takes the agent off the router, puts the query log setting back if
enrolling turned it on, and switches the `gateway` block off again.

### Updating the agent

The agent on the router does not update itself, because AgentalSec's key can
only run it. After you update AgentalSec, install the new agent the same way:

```bash
./scripts/install_gateway_agent.sh --enroll ROUTER_ADDRESS
```

It replaces the agent, keeps the key, and ends with the router's report,
which shows the agent version and what it can now do. The app needs no
restart for this.

### What it adds

- **Live LAN tab.** Every device's upload and download right now, its
  destinations, DNS lookups and finished connections.
- **Router view** on the Network tab: what the router says is on the network,
  including devices this machine never sees, marked NOT SEEN HERE.
- **Router settings:** DNS, DHCP and gateway settings, with changes flagged.
- **Actions on the router**, each needing your approval: block or unblock a
  device, block an app for one device, sinkhole a domain.

### What it covers

The router's connection table shows every device's traffic to and from the
internet, which is where calls home, data leaving and unwanted downloads
happen. Traffic between two devices inside your LAN goes straight through the
switch, not the router's firewall, so it stays between those two devices.

## The SNMP router monitor

For a router without a shell, AgentalSec can read its tables over SNMP,
read-only. It never writes over SNMP.

```json
"router_monitor": {"enabled": true, "backend": "snmp", "host": "ROUTER_ADDRESS", "port": 161}
```

Put a **read-only** community string in `.env` as `AGENTAL_ROUTER_COMMUNITY`.

## Pi-hole and AdGuard Home

If you run Pi-hole or AdGuard Home, AgentalSec can read its query log: every
DNS lookup of every device that uses it, including the ones that were
blocked. It reads Pi-hole's `pihole-FTL.db` or AdGuard Home's
`querylog.json`, read-only, so the file has to be reachable from this
machine.

```json
"dns_monitor": {"enabled": true, "source": "auto", "path": "/path/to/pihole-FTL.db", "interval_minutes": 15}
```

With source `auto`, a `.json` file is read as AdGuard Home's `querylog.json`
and anything else as Pi-hole's database. `"source": "pihole"` or
`"adguard"` names it outright. With no path and no router agent, DNS reading
waits and says so on the Settings tab.

## Other Linux machines over SSH

AgentalSec can read logins, failed logins, processes and startup entries on
other Linux machines over SSH.

Create a key for it and copy it to each machine:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/agental_sec
ssh-copy-id -i ~/.ssh/agental_sec.pub user@remote-host
```

Set `AGENTAL_SSH_KEY_PATH=~/.ssh/agental_sec` in `.env`, and list the
machines in `config.json`:

```json
"linux_monitor": {
  "enabled": true,
  "strict_host_key": false,
  "hosts": [
    {"label": "file server", "host": "192.0.2.20", "user": "monitor", "port": 22}
  ]
}
```

Each entry needs `host` and `user`; `label`, `port` and `key_path` are
optional. An entry without `host` is skipped.

The first connection to each machine trusts its host key and remembers it.
Once all your machines are known, set `strict_host_key` to `true`, so a
changed host key is refused instead of trusted.
