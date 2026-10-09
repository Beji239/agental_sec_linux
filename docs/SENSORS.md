# Sensors

Every sensor in AgentalSec: what it watches, what it needs, what it reports
when it is missing something, and where it is configured. Settings live in
`config.json` (copied from `config.linux.example.json`). Restart the app after
changing it.

Each sensor's state is on the Dashboard tab and on the Settings tab. A sensor
that is off, missing a tool or missing a privilege says which, by name.

[Back to the README](../README.md)

## Privilege, in one place

The app runs as you by default. These are the things that need more:

- **Packet capture** needs root or `CAP_NET_RAW`. The privileged launcher
  gives it.
- **Firewall changes and ending other users' processes** need root. The root
  action helper (see [SETUP.md](../SETUP.md)) carries out approved actions so
  the app itself can stay unprivileged.
- **Files only root can read**, such as the audit log, need root or the read
  helper.
- **Other users' journal entries** need the `systemd-journal` group or root.
- **Other users' process details** (command line, executable path) need root.
  The processes still appear, with those fields empty.
- **The SYN port scan and ARP discovery** need a raw socket. Without one the
  scanner falls back to a connect test and other discovery paths, and says
  which method ran.

## Network sensors

### Packet sniffer

Captures every packet on the link that carries the default route, with the
owning process where the kernel can say. Feeds most of the detectors below.

- Needs: root or `CAP_NET_RAW`, libpcap.
- If it lacks something: start AgentalSec with the privileged launcher.
  Until then the dashboard says plainly that capture is off, so a quiet
  network and an unwatched one never look alike. If the kernel drops frames
  because the sensor fell behind, that is raised as a finding of its own.
- Config: `sensors.packet_sniffer` (`interface`, `promiscuous`, `filter`,
  `rcvbuf`).

### Detectors on the captured traffic

These read the packet sniffer's stream and need nothing else.

- **Beacons.** Contacts that repeat at least eight times, under sixty seconds
  apart on average, with less than a quarter of that average in variation.
  Every repeated conversation is kept with its timing either way.
- **Volume.** One source sending far more than usual in a window.
- **Signatures.** Metasploit payload bytes, SQL injection and cross-site
  scripting strings in plaintext, inbound reach for ports that should not be
  exposed, outbound contact with dangerous ports.
- **ICMP oddities.** Routing changes from addresses not on this network, and
  messages whose source contradicts their own contents.
- **TLS and QUIC.** The server name and JA3 fingerprint from the first packet
  of each handshake, including QUIC, whose first packet any observer can
  decrypt.
- **DNS inspection.** Machine generated domain names (DGA) and DNS used as a
  beacon channel.
- **LAN protocol abuse.** ARP spoofing, a change of the gateway's hardware
  address, rogue DHCP servers, LLMNR and NBT-NS poisoning.
- **Announcements.** Device names and types from mDNS and SSDP traffic that is
  addressed to everybody, which identifies devices that never talk to this
  machine directly.
- **Payload ring.** A small capped buffer in memory with the last bytes of
  traffic, so the bytes that caused an alert can be read. Saving payloads for
  one target is an action that needs approval.

### Presence sweep and network scanner

Finds the devices on your network by sweeping the local /24 around this
machine's address, and keeps who was present when.

- Needs: `iputils-ping`. ARP based discovery needs a raw socket.
- If it lacks something: install `iputils-ping`. Until then the sweep says
  that no address was probed, so an empty result is never mistaken for an
  empty network.
- Config: `presence_sweep` (`interval_minutes`), `sensors.network_scanner`.

### Device probe

The slow, careful half of device identity: every few weeks it looks at each
known device more closely, paced and capped, and records drift, such as a
device that changed what it answers on.

- Config: `probe` (`interval_days`, `max_hosts_per_pass`, `pacing_seconds`,
  `exclusion_list` for devices that must never be probed).

### Port scanner

TCP and UDP scans. TCP uses SYN probes with a raw socket and a connect test
without one. UDP asks a fixed list of real services (DNS, NTP, SNMP, NetBIOS,
SSDP, mDNS, LLMNR) with a proper request each. A background pass scans this
machine every ten minutes so the record keeps moving.

- Config: `sensors.port_scanner` (`poll_interval`, `enabled: false` also stops
  on-demand scans), `port_scan` (`default_set`, `tcp_method`: `auto`, `syn`
  refuses rather than falling back, `connect` never uses a raw socket).

### Port owner and listener census

Which process holds each listening port, and every socket the kernel says is
bound, on any address, with whether the firewall lets the outside reach it.

- Needs: root to resolve ports owned by root or other users. Unresolved owners
  are reported as unreadable, not as empty.

### VPN state

Whether traffic leaves through a tunnel interface, such as WireGuard or
OpenVPN. It recognises VPNs by their tunnel interface; proxy style VPNs that
use none are outside what it checks.

- Config: `vpn.interface_patterns` for tunnel names it does not know.

### Place learning

Learns which countries and networks each program on this machine and each
device on the network normally reaches. After a learning period, a first
contact with a new country raises GEO-1001 (medium when nothing in the home
had reached that country before) and a new network raises GEO-1002. A new
place is a prompt to look, not a verdict: cloud and CDN addresses move.

- Needs: the geolocation database. Networks also need the optional ASN
  database (`scripts/fetch_geoip.py --asn`); without it only countries are
  learned. Devices need the router agent; without it only this machine's
  programs are learned.
- Config: `place_watch` (`learn_hours`, by default 72, `interval_seconds`,
  `max_alerts_per_pass`).

## Host sensors

### Process monitor

Everything running, from the kernel's process table. Each executable is
checked against the digest its package recorded at install time, and the
systemd unit that owns a process is recorded, so the analyst knows when
ending a process would only make systemd restart it.

- Needs: root for other users' command lines and paths.
- Config: `sensors.process_monitor.poll_interval`.

### Event monitor

The systemd journal, syslog and the auth log: logins, failed logins, sudo,
service failures.

- Needs: the `systemd-journal` group or root for entries beyond your own.
- If it lacks something: add yourself to the `systemd-journal` group or use
  the privileged launcher. Until then the monitor says the journal is
  unreadable instead of reporting a quiet log.
- Config: `sensors.event_monitor.sources`, `linux.log_sources`.

### auditd

The Linux audit log, for the system calls and file access your audit rules
record, which the journal does not. AgentalSec reads the log; it does not
install rules of its own.

- Needs: the `auditd` package, and root or the read helper to read the log.
  Without them it reports "not installed", with the install command, and
  carries on.
- Config: `sensors.auditd` (`log_path`).

### eBPF camera

A small kernel program that records every process start and every outbound
connection as it happens, including programs that live for less than a
second. It also watches staging directories such as `/tmp` and connections
to dangerous ports.

- Needs: a one time build and install (`ebpf/build.sh`, then
  `scripts/install_ebpf_camera.sh --apply`), a kernel with BTF, clang and
  bpftool. It runs as its own service and the app reads what it recorded.
- If it lacks something: if the camera stops writing for longer than
  `stale_after_seconds`, the dashboard marks it stale, so you know to check
  its service.
- Config: `sensors.ebpf_events`.

### File integrity

Two tiers. Every minute: important system files (passwd, sudoers, cron and
others), hashed directory sets, and every user's SSH keys and settings. Every
hour: a sweep of the whole disk for programs with setuid, setgid or file
capabilities. Every three hours: installed package files checked against
their package digests.

- Config: `sensors.local_integrity` (`poll_interval`,
  `sweep_interval_seconds`, `dpkg_interval_seconds`).

### Startup entries

systemd units and timers, cron jobs, init scripts and shell startup files,
compared with a baseline so a new or changed entry stands out.

- Config: `sensors.autorun_monitor`, `linux.autorun_paths`.

### Software inventory and host info

What is installed and at which version, and the basics of this machine:
kernel, distribution, interfaces, uptime.

### Background apps

Services, timers and login apps worth acting on, from AgentalSec's own
list, with a tier for each: safe to disable, or block its network only.
Disabling and blocking are actions that need approval, and each has an undo.

## Beyond this machine

The router agent, the SNMP router monitor, Pi-hole and AdGuard Home, and
remote Linux hosts over SSH are described in [ROUTER.md](ROUTER.md).

## Threat feeds and enrichment

- **Threat feeds.** ThreatFox, URLhaus, Feodo Tracker, AlienVault OTX and the
  CIRCL MISP feed, refreshed every six hours and matched against observed
  traffic every five minutes. Config: `threat_feeds` (`feeds`,
  `refresh_hours`). Keys, where needed, go in `.env`: `AGENTAL_ABUSECH_KEY`
  for URLhaus and Feodo, `AGENTAL_OTX_KEY` for OTX.
- **Enrichment.** RDAP, CIRCL, NVD, ip-api, the IEEE vendor registry and
  LOLBAS without a key. With keys in `.env`: AbuseIPDB
  (`AGENTAL_ABUSEIPDB_KEY`), MalwareBazaar and URLhaus
  (`AGENTAL_ABUSECH_KEY`), GreyNoise (`AGENTAL_GREYNOISE_KEY`), and a higher
  NVD rate limit (`AGENTAL_NVD_API_KEY`). A blank key turns that source off,
  and it is listed as off.
- **CISA KEV.** The known exploited vulnerabilities catalogue, with CVSS
  scores from NVD and CIRCL, on the Runbook tab.

## When a sensor goes quiet

Once a minute AgentalSec checks every sensor that runs on its own: whether it
can see, whether it is still running, and whether its last good reading is
recent for how often it reads. The header shows **All sensors OK** or how
many are quiet; click it for the names and reasons above the Dashboard tiles.

- A sensor that was collecting and stops raises **SYS-1001**, a high alert,
  so you get a desktop notice and the agent looks at it. Its return raises
  **SYS-1002**.
- A sensor switched off in Settings, or one waiting for a router or a
  resolver it has not been given, is shown as off with the reason, not as a
  fault.
- The **Timeline** has a bar across its window: green while every sensor was
  collecting, amber where one was quiet, grey while AgentalSec was not
  running, striped before the check existed. A quiet stretch on a green part
  is a calm one.

## Data the sensors keep, and for how long

- Packets 7 days, events 30 days, findings 90 days, baselines a year. Config:
  `retention`.
- Hourly rollups keep traffic totals after the raw packets are pruned.
- `python3 scripts/prune_db.py --status` shows the database size.
