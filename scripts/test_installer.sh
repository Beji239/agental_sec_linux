#!/usr/bin/env bash
# scripts/test_installer.sh
# Installs the AgentalSec installer in a throwaway Ubuntu 24.04 container with
# systemd, as a person would, and checks what it leaves: the person's copy, the
# libraries, the helpers, the icon, the app starting without a terminal, a
# second start opening the same app, stopping, an update keeping the person's
# data, and removing it leaving nothing running. The container is removed at
# the end whatever happens.
#
#     ./scripts/test_installer.sh RUN_FOLDER     (after build_installer.sh RUN_FOLDER)
set -uo pipefail

RUN="${1:?give the folder build_installer.sh built in}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(cat "$ROOT/VERSION")"
DEB="$RUN/AgentalSec-Setup-$VERSION-amd64.deb"
IMAGE="${IMAGE:-tessera-test:24.04}"
c="agentalsec-install-test-$$"
pass=0 fail=0

# Something listening on port 5000 (0x1388), not a closed connection lingering.
# Defined in the container's shell before each check.
LISTENING='listening() { awk '"'"'$2 ~ /:1388$/ && $4 == "0A" {f=1} END {exit !f}'"'"' /proc/net/tcp; }; '
ok() {
    if docker exec "$c" bash -c "$LISTENING$1" >/dev/null 2>&1; then
        echo "  PASS  $2"; pass=$((pass + 1))
    else
        echo "  FAIL  $2"; fail=$((fail + 1))
    fi
}
x() { docker exec "$c" bash -c "$LISTENING$1"; }
as_sam() { docker exec -u sam -e HOME=/home/sam "$c" bash -c "$1"; }
cleanup() { docker rm -f "$c" >/dev/null 2>&1 || true; }
trap cleanup EXIT

[ -f "$DEB" ] || { echo "No installer at $DEB; run build_installer.sh first." >&2; exit 1; }

docker run -d --name "$c" --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
    "$IMAGE" >/dev/null || { echo "The test container could not start." >&2; exit 1; }
up=no
for _ in $(seq 60); do
    if x 'systemctl is-system-running 2>/dev/null | grep -q -E "running|degraded"' 2>/dev/null; then up=yes; break; fi
    sleep 1
done
[ "$up" = yes ] || { echo "The test container did not come up; nothing was tested." >&2; docker logs "$c" 2>&1 | tail -5 >&2; exit 1; }
x 'id sam >/dev/null 2>&1 || useradd -m -s /bin/bash sam; mkdir -p /home/sam/Desktop && chown sam: /home/sam/Desktop'
docker cp "$DEB" "$c:/tmp/setup.deb"

echo "installing, as sam would"
x 'apt-get update -qq >/dev/null 2>&1'
ok 'SUDO_USER=sam DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /tmp/setup.deb > /tmp/install.out 2>&1' "the installer installs, with what it needs"
ok '[ -x /usr/bin/agentalsec ] && [ -f /usr/share/applications/agentalsec.desktop ]' "the launcher and the menu entry are in place"
ok '[ -f /usr/share/icons/hicolor/256x256/apps/agentalsec.png ]' "and the icon"
ok '[ "$(cat /var/lib/agentalsec/owner)" = sam ]' "it was installed for the person installing"
ok '[ -f /home/sam/.local/share/agentalsec/main.py ] && [ "$(stat -c %U:%a /home/sam/.local/share/agentalsec)" = sam:700 ]' "sam has a copy of their own, theirs alone"
ok 'runuser -u sam -- python3 -c "import flask, scapy, cryptography, httpx, maxminddb"' "the libraries came with the installer"
ok '[ -f /home/sam/Desktop/agentalsec.desktop ] && grep -q "^Exec=/usr/bin/agentalsec$" /home/sam/Desktop/agentalsec.desktop' "the icon is on sam's desktop"
ok '! grep -q "Terminal=true" /usr/share/applications/agentalsec.desktop' "and it opens no terminal"
ok 'systemctl cat agentalsec-capture.service agentalsec-names.service >/dev/null' "the capture helper is installed"
ok 'ls /etc/sudoers.d | grep -q agentalsec' "the read helper is installed"
ok '[ -f /usr/share/polkit-1/actions/org.agentalsec.action-helper.policy ] || ls /usr/share/polkit-1/actions | grep -q agentalsec' "the action helper is installed"
x 'cat /var/log/agentalsec-install.log' | sed 's/^/        /' | tail -8

echo "opening AgentalSec, as a click on the icon"
as_sam 'agentalsec'
for _ in $(seq 90); do x listening && break; sleep 1; done
ok listening "it starts, and its dashboard answers on this computer"
key=$(x 'sed -n "s/^AGENTAL_APP_API_KEY=//p" /home/sam/.local/share/agentalsec/.env' | tr -d '"\r')
ok "curl -sf -H 'X-API-Key: $key' http://127.0.0.1:5000/api/features | grep -q process" "the dashboard answers with sam's own key"
ok '[ "$(stat -c %a /home/sam/.local/share/agentalsec/.env)" = 600 ] && [ "$(stat -c %a /home/sam/.local/share/agentalsec/agental_sec.db)" = 600 ]' "its keys and database are sam's alone"
n1=$(x 'pgrep -u sam -x python3 | wc -l')
as_sam 'agentalsec'
sleep 5
n2=$(x 'pgrep -u sam -x python3 | wc -l')
ok "[ '$n1' = '$n2' ]" "a second click opens the same AgentalSec, not another"

echo "stopping"
as_sam 'agentalsec --stop'
for _ in $(seq 120); do x listening || break; sleep 1; done
ok '! listening && ! pgrep -u sam -x python3' "it stops, with nothing left running"

echo "an update keeps sam's data"
before=$(x 'sha256sum /home/sam/.local/share/agentalsec/.env | cut -c1-64')
x 'rm -rf /tmp/up && mkdir /tmp/up && dpkg-deb -R /tmp/setup.deb /tmp/up && echo 9.9.9 > /tmp/up/opt/agentalsec/app/VERSION && sed -i "s/^Version: .*/Version: 9.9.9/" /tmp/up/DEBIAN/control && dpkg-deb --root-owner-group -b /tmp/up /tmp/update.deb >/dev/null'
ok 'SUDO_USER=sam DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /tmp/update.deb > /tmp/update.out 2>&1' "the next installer installs over it"
ok '[ "$(cat /home/sam/.local/share/agentalsec/VERSION)" = 9.9.9 ]' "sam's copy is the new version"
ok "[ \"\$(sha256sum /home/sam/.local/share/agentalsec/.env | cut -c1-64)\" = '$before' ] && [ -s /home/sam/.local/share/agentalsec/agental_sec.db ]" "and keeps sam's keys and database"

echo "removing"
as_sam 'agentalsec' ; for _ in $(seq 90); do x listening && break; sleep 1; done
ok 'DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq agentalsec > /tmp/remove.out 2>&1' "it removes"
ok '! pgrep -u sam -x python3 && ! listening' "the running app was stopped"
ok '! systemctl cat agentalsec-capture.service >/dev/null 2>&1 && ! ls /etc/sudoers.d | grep -q agentalsec' "the helpers are gone"
ok '! systemctl list-units --all | grep -q agentalsec' "nothing of it is left to run"
ok '[ ! -e /home/sam/Desktop/agentalsec.desktop ] && [ ! -e /usr/bin/agentalsec ]' "the icon and the launcher are gone"
ok '[ -s /home/sam/.local/share/agentalsec/.env ]' "sam's data stays for a reinstall"
ok 'DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq agentalsec > /tmp/purge.out 2>&1 && [ ! -e /home/sam/.local/share/agentalsec ]' "removing it completely deletes sam's AgentalSec folder"

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
