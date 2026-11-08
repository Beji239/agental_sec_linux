#!/usr/bin/env bash
# scripts/build_installer.sh
# Builds the AgentalSec installer for Linux: one AgentalSec-Setup-VERSION-amd64.deb
# that a person downloads and double-clicks. Mint, Ubuntu and Debian open it in
# their package installer; Install asks for the password once and ends with
# AgentalSec working, its icon on the desktop and the dashboard open.
#
# It carries the committed code (git archive of HEAD, so only what is in git),
# the Python libraries as ready-built files for this Python, the launcher, the
# menu entry and the icons. The build happens in RUN_FOLDER, never in here.
#
#     ./scripts/build_installer.sh RUN_FOLDER
set -euo pipefail

RUN="${1:?give the folder to build in}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(cat "$ROOT/VERSION")"
PKG="$RUN/pkg"
OUT="$RUN/AgentalSec-Setup-$VERSION-amd64.deb"

cd "$ROOT"
if [ -n "$(git status --porcelain -- . ':!*.desktop')" ]; then
    echo "There are changes not committed; the installer carries HEAD only." >&2
    git status --short >&2
fi

rm -rf "$PKG"
mkdir -p "$PKG/DEBIAN" "$PKG/opt/agentalsec/app" "$PKG/usr/bin" "$PKG/usr/share/applications"

echo "== the code, as committed"
git archive HEAD | tar -x -C "$PKG/opt/agentalsec/app"

echo "== the libraries"
mkdir -p "$RUN/wheels"
python3 -m pip download -q --only-binary=:all: --python-version 3.12 --implementation cp \
    --platform manylinux2014_x86_64 --platform manylinux_2_17_x86_64 --platform manylinux_2_28_x86_64 \
    -r requirements.lock -d "$RUN/wheels"
cp -r "$RUN/wheels" "$PKG/opt/agentalsec/wheels"

echo "== the launcher, the menu entry and the icons"
install -m 755 packaging/linux/agentalsec "$PKG/usr/bin/agentalsec"
install -m 644 packaging/linux/agentalsec.desktop "$PKG/usr/share/applications/agentalsec.desktop"
for n in 16 22 24 32 36 48 64 128 256; do
    install -D -m 644 "assets/logo/png/orca_tile_ink_$n.png" \
        "$PKG/usr/share/icons/hicolor/${n}x${n}/apps/agentalsec.png"
done
for s in postinst prerm postrm; do
    install -m 755 "packaging/linux/$s" "$PKG/DEBIAN/$s"
done

size=$(du -sk --exclude=DEBIAN "$PKG" | cut -f1)
cat > "$PKG/DEBIAN/control" <<EOF
Package: agentalsec
Version: $VERSION
Architecture: amd64
Maintainer: AgentalSec <274306789+Beji239@users.noreply.github.com>
Installed-Size: $size
Depends: python3 (>= 3.12), python3 (<< 3.13), python3-pip, rsync, libpcap0.8, iproute2, net-tools, nftables, iptables, iputils-ping, openssh-client, pkexec | policykit-1, libnotify-bin, zenity, xdg-utils, procps, systemd
Recommends: auditd
Section: net
Priority: optional
Homepage: https://github.com/Beji239/agental_sec_linux
Description: Security for this computer and your home network
 AgentalSec watches this computer and the devices on your home network,
 explains what it sees in plain words, and lets you act on it from the
 dashboard or from your phone. Open it from the menu or the desktop icon.
EOF

dpkg-deb --root-owner-group -Zxz --build "$PKG" "$OUT" >/dev/null
echo "$OUT ($(du -h "$OUT" | cut -f1))"
