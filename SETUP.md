# AgentalSec Linux setup

For Ubuntu, Debian and Linux Mint (tested on an Ubuntu 24.04 base, Python
3.12). Run every command from the project folder unless it says otherwise.

Steps 1 to 9 are the install. **Step 9, the launchers, is required**: the app
does not create its desktop and menu icons by itself. Steps 10 to 12 are
optional. For the full network view, pair AgentalSec with a router it can
talk to, see "Best setup" in the [README](README.md#best-setup).

## 1. System packages

```bash
sudo apt update
sudo apt install -y git python3 python3-pip libpcap0.8 iproute2 net-tools \
    nftables iptables iputils-ping openssh-client pkexec libnotify-bin auditd
```

Optional, only for the eBPF kernel camera (step 10):

```bash
sudo apt install -y clang llvm libbpf1 libbpf-dev linux-tools-common linux-tools-$(uname -r)
```

On Debian, install `bpftool` in place of the two `linux-tools` packages.

## 2. Get the code

```bash
git clone <repository-url> agental_sec_linux
cd agental_sec_linux
```

## 3. Python packages

Install them for your user. The launchers and the privileged mode load
packages from `~/.local`, so do not use a virtual environment.

```bash
pip install --user --break-system-packages -r requirements.txt
```

`--break-system-packages` is required on Ubuntu 23.04+ and Debian 12+. It only
writes to `~/.local`, the system Python is not touched.

## 4. Config files

```bash
cp config.linux.example.json config.json
cp .env.example .env
chmod 600 config.json .env
```

## 5. Keys in `.env`

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

- `AGENTAL_APP_API_KEY`: paste the value printed above. The dashboard asks for it.
- `AGENTAL_API_KEY`: your model provider's key, needed for the AI analyst.
- Everything else in `.env` is optional. A blank key turns that source off.

## 6. Model provider

In `config.json`, under `provider`:

- `api_url`: the provider's chat endpoint, OpenAI-style
  (`.../v1/chat/completions`) or Anthropic-style (`.../v1/messages`).
- `model`: the model id at that provider.

You can also set both later on the dashboard's Settings tab.

## 7. Data files

```bash
python3 scripts/fetch_geoip.py     # threat map database
python3 scripts/fetch_geoip.py --asn   # optional, network owner names on the map
python3 scripts/update_oui.py      # device vendor names
```

## 8. First run

```bash
python3 main.py --check            # should end with "Check complete: OK"
python3 main.py
```

Open http://127.0.0.1:5000 and enter `AGENTAL_APP_API_KEY`. Stop with Ctrl+C.

Both commands print a reminder that the launchers are not installed yet. That
is expected at this point; step 9 installs them.

## 9. Install the launchers (required)

The app does not create its launchers by itself. Run this once, from the
project folder, as your own user. Do not use sudo: the launchers belong to
your account.

```bash
./scripts/install_launchers.sh
```

This adds two launchers, each in three places: your app menu, your desktop
and the project folder.

- **AgentalSec**: runs as you. Packet capture and firewall changes are off.
- **AgentalSec (privileged)**: asks for your password and runs as root, with
  every sensor working.

Use these to start the app from now on. If a desktop icon says "untrusted",
right-click it and choose "Allow launching". If you move or rename the project
folder, run the script again: the app warns you when its launchers point at a
different folder.

Check it worked: `python3 main.py --check` now says "Launchers are installed
for this folder".

## 10. Optional helpers

Root action helper, which runs approved actions (block, kill, quarantine) while
the app stays unprivileged:

```bash
sudo ./scripts/install_action_helper.sh --apply
./scripts/install_action_helper.sh --verify-live
```

Read helper, for files only root can read:

```bash
sudo ./scripts/install_read_helper.sh --apply
./scripts/install_read_helper.sh --verify
```

eBPF kernel camera, needs the step 1 extras:

```bash
./ebpf/build.sh
sudo ./scripts/install_ebpf_camera.sh --apply
./scripts/install_ebpf_camera.sh --verify
```

Each script run without arguments shows what it would change. `--uninstall`
removes it.

## 11. Optional sensors

Malware scanning with ClamAV. Its own service keeps the signatures current:

```bash
sudo apt install clamav clamav-daemon
```

Remote Linux hosts over SSH:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/agental_sec
ssh-copy-id -i ~/.ssh/agental_sec.pub user@remote-host
```

Set `AGENTAL_SSH_KEY_PATH` in `.env` and add the host under
`linux_monitor.hosts` in `config.json`.

Router, for the full network view. Any router that allows SSH with a root
shell works: OpenWrt and similar firmware, a Raspberry Pi or Linux box set up
as your router, or a pf based firewall. The full guide, including modem
versus router, is [docs/ROUTER.md](docs/ROUTER.md).

```bash
./scripts/install_gateway_agent.sh --enroll ROUTER_ADDRESS
```

Add the `gateway` block the script prints to `config.json`.
Run the same command again after updating AgentalSec, to put the new agent
on the router.

Pi-hole or AdGuard Home: enable `dns_monitor` in `config.json`.

Restart the app after any `config.json` change.

## 12. Optional: start on boot

```bash
sudo tee /etc/systemd/system/agental-sec.service > /dev/null <<'EOF'
[Unit]
Description=AgentalSec Linux
After=network-online.target
Wants=network-online.target

[Service]
User=YOUR_USER
WorkingDirectory=/path/to/agental_sec_linux
ExecStart=/usr/bin/python3 main.py
Restart=on-failure
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now agental-sec
```

Replace `YOUR_USER` and the path first, and set `flask.auto_open_browser` to
`false` in `config.json`.

## 13. Verify

```bash
python3 main.py --check
python3 scripts/run_tests.py
```

## Maintenance

```bash
python3 scripts/fetch_geoip.py                                       # refresh map data
python3 scripts/fetch_geoip.py --asn                                 # refresh network owners
python3 scripts/update_oui.py                                        # refresh vendor names
python3 scripts/prune_db.py --status                                 # database size
pip install --user --break-system-packages --upgrade -r requirements.txt
```

## Troubleshooting

- **No AgentalSec icon in the app menu or on the desktop**: the launchers
  are not installed. Run `./scripts/install_launchers.sh` from the project
  folder, as your own user (step 9).
- **A launcher starts nothing, or an old copy**: the project folder was moved
  or renamed. Run `./scripts/install_launchers.sh` again.
- **Missing dependencies at start**: step 3 was skipped or run as another user.
- **Packet capture off**: use the privileged launcher.
- **Analyst unavailable**: `AGENTAL_API_KEY`, `provider.api_url` or
  `provider.model` is empty.
- **Threat map empty**: run `scripts/fetch_geoip.py`.
- **"database is locked"**: another copy is already running.
- **Dashboard from another machine**: use an SSH tunnel, which keeps the
  dashboard on loopback: `ssh -L 5000:127.0.0.1:5000 user@this-machine`, then
  open http://127.0.0.1:5000 there. Setting `flask.host` to `0.0.0.0` (plus the
  address under `flask.allowed_hosts`) also works, but exposes the dashboard
  to your whole network.
