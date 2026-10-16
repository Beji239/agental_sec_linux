# AgentalSec Linux setup

For Ubuntu, Debian and Linux Mint (the install is tested on Ubuntu 24.04 and
22.04 and Debian 12, Python 3.10 to 3.12). Run every command from the project
folder unless it says otherwise.

## Automatic install

**The install is now automatic.** Steps 1 to 9 below are done by one script:

```bash
git clone <repository-url> agental_sec_linux
cd agental_sec_linux
./scripts/install.sh
```

`<repository-url>` is the address under the green Code button on the
repository's GitHub page. Run it as your own user; it asks for your
password once, for the system packages. It asks for the model provider's chat address, model and key, and
each can be left empty. `./scripts/install.sh --help` lists its options,
such as `--with-clamav` for malware scanning and `--yes` for no questions.
Running it again keeps everything already set up. The steps below are what it
does, for doing it by hand, and steps 10 to 12 stay optional.

## By hand

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

`requirements.lock` holds the exact versions this release was checked with,
each file hashed. To install those instead, use `--require-hashes -r
requirements.lock` in place of `-r requirements.txt`.

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

The script switches the `gateway` block on in `config.json` itself, and on
OpenWrt it turns on the router's DNS query log. DNS reading is on by default
with source `auto`, so the router's lookups are read from the next start.
Run the same command again after updating AgentalSec, to put the new agent
on the router.

Pi-hole or AdGuard Home instead of a router: set `dns_monitor.path` in
`config.json` to its query log.

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

For a coverage report, line and branch, run
`python3 scripts/run_tests.py --coverage`. It needs the `coverage` package
(`pip install --user coverage`) and writes `coverage/html/index.html`.

### Security test tools (developers only)

Some tests scan the code with outside tools: Bandit, Semgrep, pip-audit,
ShellCheck, gitleaks and Trivy. **The app does not need them, and a normal
install leaves them out.** Without them, those tests report a skip that names
the script below, and the rest of the suite runs as usual.

To install them, run `./scripts/install.sh --with-test-tools`, answer yes when
the installer asks, or run the script on its own at any time:

```bash
./scripts/install_test_tools.sh
```

It installs ShellCheck with apt and puts the rest in their own folder,
`~/.local/share/agentalsec-test-tools`, apart from the app's Python packages.
The versions are pinned in the script, and the gitleaks and Trivy downloads
are checked against their published checksums. It is safe to run again.
`./scripts/update.sh` updates the tools when a new version of the script
arrives, but only if they were installed before. `--verify` shows what is
installed, and `--remove` deletes the folder.

When a scan test fails on something new, fix it, or check it and run
`python3 scripts/security_review.py`, then write why it is fine next to it in
`tests/security_reviewed.json`. An entry without a reason fails the suite.

## Updating

```bash
./scripts/update.sh
```

It fetches the latest code, reinstalls the Python packages, lists what
changed and names anything else to run. Then restart AgentalSec; the database
updates itself at that start. `./scripts/update.sh --check` only shows whether
an update is waiting.

The same by hand:

```bash
git pull
pip install --user --break-system-packages -r requirements.txt
```

Then restart the app. With a router enrolled, run
`./scripts/install_gateway_agent.sh --enroll <router address>` again when the
router agent changed. Your `config.json` is never overwritten, so a new
setting keeps its default until you change it in Settings. What each version
changed is on the repository's Releases page.

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
