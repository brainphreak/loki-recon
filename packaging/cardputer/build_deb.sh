#!/usr/bin/env bash
# Build the CardputerZero APPLaunch .deb for Loki (arm64).
#
# Layout installed by the package:
#   /opt/loki/                         the Loki app tree (this repo, minus dev cruft)
#   /usr/share/APPLaunch/bin/loki_launcher
#   /usr/share/APPLaunch/applications/loki.desktop
#   /usr/share/APPLaunch/share/images/loki.png
#
# postinst builds the Python venv at /opt/loki/.venv (needs network on-device).
# System deps (nmap/smbclient/freerdp) come from apt via Depends.
#
# Usage:  packaging/cardputer/build_deb.sh [version]
# Output: dist/loki_<version>_arm64.deb
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PKG="packaging/cardputer"
VERSION="${1:-$(python3 -c "import json;print(json.load(open('$REPO/$PKG/app-builder.json'))['version'])")}"
ARCH="arm64"
STAGE="$(mktemp -d)"
NAME="loki_${VERSION}_${ARCH}"

echo "[build] staging $NAME in $STAGE"
mkdir -p "$STAGE/opt/loki" \
         "$STAGE/usr/share/APPLaunch/bin" \
         "$STAGE/usr/share/APPLaunch/applications" \
         "$STAGE/usr/share/APPLaunch/share/images" \
         "$STAGE/DEBIAN"

# App tree (exclude dev/runtime cruft; venv is rebuilt by postinst).
rsync -a \
  --exclude '.git' --exclude '.venv' --exclude 'screenshots' --exclude 'test_targets' \
  --exclude 'archive' --exclude '__pycache__' --exclude '*.pyc' --exclude '.DS_Store' \
  --exclude 'packaging' --exclude 'dist' \
  "$REPO/" "$STAGE/opt/loki/"

install -m0755 "$REPO/$PKG/loki_launcher" "$STAGE/usr/share/APPLaunch/bin/loki_launcher"
install -m0644 "$REPO/$PKG/loki.desktop"  "$STAGE/usr/share/APPLaunch/applications/loki.desktop"
install -m0644 "$REPO/$PKG/loki.png"      "$STAGE/usr/share/APPLaunch/share/images/loki.png"

INSTALLED_SIZE=$(du -sk "$STAGE/opt" "$STAGE/usr" | awk '{s+=$1} END{print s}')
cat > "$STAGE/DEBIAN/control" <<CTRL
Package: loki
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: brAinphreAk <brainphreak@users.noreply.github.com>
Installed-Size: ${INSTALLED_SIZE}
Depends: python3, python3-venv, python3-pip, python3-pil, python3-numpy, nmap, smbclient
Recommends: freerdp2-x11 | freerdp3-x11
Section: utils
Priority: optional
Description: Loki — LAN Orchestrated Key Infiltrator (CardputerZero)
 Autonomous network-recon companion: host discovery, nmap port + vuln scans,
 credential brute force, and file/SQL exfiltration, with an animated themed
 character on the CardputerZero LCD and a web UI/JSON API over Wi-Fi.
 Authorized-use only.
CTRL

cat > "$STAGE/DEBIAN/postinst" <<'POST'
#!/bin/sh
set -e
APP=/opt/loki
if [ ! -x "$APP/.venv/bin/python" ]; then
    python3 -m venv --system-site-packages "$APP/.venv" || true
fi
if [ -x "$APP/.venv/bin/pip" ]; then
    "$APP/.venv/bin/pip" install --upgrade pip >/dev/null 2>&1 || true
    "$APP/.venv/bin/pip" install -r "$APP/requirements.txt" || true
fi
chmod +x /usr/share/APPLaunch/bin/loki_launcher || true
# Refresh the launcher so Loki appears (user service; ignore if not running).
if command -v systemctl >/dev/null 2>&1; then
    systemctl --user restart APPLaunch.service >/dev/null 2>&1 || true
fi
exit 0
POST
chmod 0755 "$STAGE/DEBIAN/postinst"

cat > "$STAGE/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
rm -rf /opt/loki/.venv 2>/dev/null || true
exit 0
PRERM
chmod 0755 "$STAGE/DEBIAN/prerm"

mkdir -p "$REPO/dist"
dpkg-deb --build --root-owner-group "$STAGE" "$REPO/dist/${NAME}.deb"
rm -rf "$STAGE"
echo "[build] dist/${NAME}.deb"
