#!/usr/bin/env bash
# install.sh — set up loki-recon on any Linux box.
#
# Auto-detects apt/dnf/pacman/zypper, installs native scanners (nmap,
# smbclient, freerdp), creates a Python venv, installs Python deps from
# PyPI (auto-resolved per architecture: arm64 / armv7 / armv6 / x86_64).
# No vendored binaries.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
RESET='\033[0m'

log()  { echo -e "${GREEN}[loki-recon]${RESET} $*"; }
warn() { echo -e "${YELLOW}[loki-recon]${RESET} $*"; }
die()  { echo -e "${RED}[loki-recon]${RESET} $*" >&2; exit 1; }

# --- 1. Detect distro / package manager ---
PM=""
if   command -v apt-get &>/dev/null; then PM=apt
elif command -v dnf     &>/dev/null; then PM=dnf
elif command -v pacman  &>/dev/null; then PM=pacman
elif command -v zypper  &>/dev/null; then PM=zypper
fi

if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    log "Detected $PRETTY_NAME (package manager: ${PM:-unknown})"
fi

if [[ -z "$PM" ]]; then
    die "No supported package manager found (apt, dnf, pacman, zypper). Install nmap, smbclient, freerdp, and python3-venv manually, then re-run."
fi

# --- 2. Install system packages ---
install_apt() {
    local freerdp_pkg=""
    if apt-cache show freerdp2-x11 &>/dev/null; then
        freerdp_pkg="freerdp2-x11"
    elif apt-cache show freerdp3-x11 &>/dev/null; then
        freerdp_pkg="freerdp3-x11"
    fi
    sudo apt-get update
    # shellcheck disable=SC2086
    sudo apt-get install -y \
        nmap smbclient \
        python3 python3-pip python3-venv \
        iproute2 net-tools iputils-ping wireless-tools \
        ${freerdp_pkg}
}

install_dnf() {
    sudo dnf install -y \
        nmap samba-client freerdp \
        python3 python3-pip python3-virtualenv \
        iproute net-tools iputils wireless-tools
}

install_pacman() {
    sudo pacman -Sy --needed --noconfirm \
        nmap smbclient freerdp \
        python python-pip \
        iproute2 net-tools iputils wireless_tools
}

install_zypper() {
    sudo zypper --non-interactive install \
        nmap samba-client freerdp \
        python3 python3-pip python3-virtualenv \
        iproute2 net-tools iputils wireless-tools
}

log "Installing system packages via $PM…"
case "$PM" in
    apt)    install_apt ;;
    dnf)    install_dnf ;;
    pacman) install_pacman ;;
    zypper) install_zypper ;;
esac

# --- 2b. Optional: Nuclei (ProjectDiscovery's templated vuln scanner) ---
if ! command -v nuclei &>/dev/null; then
    log "Installing nuclei (templated vuln scanner)…"
    NUCLEI_VERSION="${NUCLEI_VERSION:-3.3.5}"
    arch="$(uname -m)"
    case "$arch" in
        x86_64)         nuclei_arch="linux_amd64" ;;
        aarch64|arm64)  nuclei_arch="linux_arm64" ;;
        armv7l)         nuclei_arch="linux_armv7" ;;
        armv6l)         nuclei_arch="linux_armv6" ;;
        *)              nuclei_arch="" ;;
    esac
    if [[ -n "$nuclei_arch" ]]; then
        url="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_${nuclei_arch}.zip"
        tmp="$(mktemp -d)"
        if curl -fsSL -o "$tmp/n.zip" "$url" \
            && (cd "$tmp" && unzip -q n.zip nuclei) \
            && sudo install -m 0755 "$tmp/nuclei" /usr/local/bin/nuclei; then
            log "nuclei installed: $(/usr/local/bin/nuclei -version 2>&1 | head -1)"
        else
            warn "nuclei download failed; you can install manually later"
        fi
        rm -rf "$tmp"
    else
        warn "Unsupported arch ($arch) for nuclei; skipping"
    fi
else
    log "nuclei already installed: $(nuclei -version 2>&1 | head -1)"
fi

# --- 3. Python venv ---
log "Creating Python virtualenv at .venv/"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip wheel
pip install -r requirements.txt

# --- 4. Data directory ---
LOKI_DATA_DIR="${LOKI_DATA_DIR:-$HOME/.loki/data}"
mkdir -p "$LOKI_DATA_DIR"/{loot/{stolen,credentials,vulnerabilities,zombies},scans,state,logs,archives}
log "Data directory: $LOKI_DATA_DIR"

# --- 5. Print run instructions ---
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost')"
cat <<EOF

${GREEN}loki-recon installed.${RESET}

Run:
    source .venv/bin/activate
    python3 loki.py

Then open the web UI at:
    http://${HOST_IP}:8000/

Common flags:
    python3 loki.py --port 8080
    python3 loki.py --data-dir /var/lib/loki-recon
    python3 loki.py --no-web              # headless, no web UI

The data directory can also be changed at runtime via the Config tab.
EOF
