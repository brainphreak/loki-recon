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

# --- 0. Install log ---
# Mirror everything (this script + all child commands' stdout/stderr) to a log
# file so failed installs can be debugged after the fact. Path is predictable:
# users can attach it to bug reports without hunting for it.
INSTALL_LOG="${LOKI_INSTALL_LOG:-$REPO_ROOT/install.log}"
: > "$INSTALL_LOG"   # truncate previous run
exec > >(tee -a "$INSTALL_LOG") 2>&1

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
RESET='\033[0m'

log()  { echo -e "${GREEN}[loki-recon]${RESET} $*"; }
warn() { echo -e "${YELLOW}[loki-recon]${RESET} $*"; }
die()  { echo -e "${RED}[loki-recon]${RESET} $*" >&2; exit 1; }

# Print where the log lives on every exit (success OR failure) so the user
# always knows what to attach if they need help.
on_exit() {
    local rc=$?
    if [[ $rc -eq 0 ]]; then
        log "Install log saved to: $INSTALL_LOG"
    else
        warn "Install failed (exit $rc). Full log at: $INSTALL_LOG"
        warn "If reporting a bug, attach that file."
    fi
}
trap on_exit EXIT

# --- 0a. Capture environment up-front (helps remote debugging) ---
{
    echo "===== loki-recon install — $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
    echo "uname: $(uname -a 2>/dev/null || echo n/a)"
    echo "arch: $(uname -m 2>/dev/null || echo n/a)"
    if [[ -f /etc/os-release ]]; then
        echo "os-release:"
        sed 's/^/  /' /etc/os-release
    fi
    echo "python3: $(command -v python3 || echo missing) $(python3 --version 2>&1 || true)"
    echo "pip3: $(command -v pip3 || echo missing) $(pip3 --version 2>&1 || true)"
    echo "memory:"
    free -h 2>/dev/null | sed 's/^/  /' || echo "  (free unavailable)"
    echo "disk (repo root):"
    df -h "$REPO_ROOT" 2>/dev/null | sed 's/^/  /' || true
    echo "================================================================"
} >> "$INSTALL_LOG"

# --- 1. Detect distro / package manager ---
PM=""
IS_MAC=0
case "$(uname -s)" in
    Darwin) IS_MAC=1 ;;
esac

if [[ "$IS_MAC" -eq 1 ]]; then
    if command -v brew &>/dev/null; then
        PM=brew
    else
        die "macOS detected but Homebrew not installed. Install it from https://brew.sh then re-run."
    fi
elif command -v apt-get &>/dev/null; then PM=apt
elif command -v dnf     &>/dev/null; then PM=dnf
elif command -v pacman  &>/dev/null; then PM=pacman
elif command -v zypper  &>/dev/null; then PM=zypper
fi

if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    log "Detected $PRETTY_NAME (package manager: ${PM:-unknown})"
elif [[ "$IS_MAC" -eq 1 ]]; then
    log "Detected macOS $(sw_vers -productVersion 2>/dev/null || echo) (package manager: $PM)"
fi

if [[ -z "$PM" ]]; then
    die "No supported package manager found (brew, apt, dnf, pacman, zypper). Install nmap, smbclient, freerdp, and python3-venv manually, then re-run."
fi

# Where third-party binaries (nuclei, searchsploit, testssl) get symlinked.
# /usr/local/bin works for Linux + Intel Macs; Apple Silicon brew uses /opt/homebrew/bin.
BIN_PREFIX="/usr/local/bin"
if [[ "$IS_MAC" -eq 1 ]]; then
    BIN_PREFIX="$(brew --prefix)/bin"
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
        libjpeg-dev zlib1g-dev libfreetype6-dev libtiff5-dev liblcms2-dev libwebp-dev \
        libssl-dev libffi-dev build-essential \
        ${freerdp_pkg}
}

install_dnf() {
    sudo dnf install -y \
        nmap samba-client freerdp \
        python3 python3-pip python3-virtualenv \
        iproute net-tools iputils wireless-tools \
        libjpeg-turbo-devel zlib-devel freetype-devel libtiff-devel lcms2-devel libwebp-devel \
        openssl-devel libffi-devel gcc gcc-c++ make
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

install_brew() {
    # macOS: brew handles its own paths; no sudo. Pillow has prebuilt wheels
    # on darwin-arm64 / darwin-x86_64, so no native -dev packages needed.
    # 'samba' provides smbclient. 'freerdp' is a top-level formula on macOS
    # (not the Linux freerdp2-x11 package). nuclei/testssl have brew formulas
    # so we don't have to manually download tarballs further down.
    brew update
    brew install python@3.11 nmap samba freerdp nuclei testssl || true
    # Make sure 'python3' resolves to a brew Python with venv support.
    if ! command -v python3 &>/dev/null; then
        die "python3 not on PATH after brew install. Open a new shell and re-run."
    fi
}

log "Installing system packages via $PM…"
case "$PM" in
    apt)    install_apt ;;
    dnf)    install_dnf ;;
    pacman) install_pacman ;;
    zypper) install_zypper ;;
    brew)   install_brew ;;
esac

# --- 2b. Optional: Nuclei (ProjectDiscovery's templated vuln scanner) ---
if ! command -v nuclei &>/dev/null; then
    log "Installing nuclei (templated vuln scanner)…"
    NUCLEI_VERSION="${NUCLEI_VERSION:-3.3.5}"
    arch="$(uname -m)"
    # ProjectDiscovery ships only: linux_386, linux_amd64, linux_arm, linux_arm64.
    # The single linux_arm artifact is a Go ARM build that runs on armv6+ (Pi Zero, Pi 1/2/3 32-bit, Pi 4 32-bit).
    case "$arch" in
        x86_64)                          nuclei_arch="linux_amd64" ;;
        aarch64|arm64)                   nuclei_arch="linux_arm64" ;;
        armv6l|armv7l|armhf|arm)         nuclei_arch="linux_arm" ;;
        i386|i686)                       nuclei_arch="linux_386" ;;
        *)                               nuclei_arch="" ;;
    esac
    if [[ -n "$nuclei_arch" ]]; then
        url="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_${nuclei_arch}.zip"
        tmp="$(mktemp -d)"
        if curl -fsSL -o "$tmp/n.zip" "$url" \
            && (cd "$tmp" && unzip -q n.zip nuclei) \
            && sudo install -m 0755 "$tmp/nuclei" "$BIN_PREFIX/nuclei"; then
            log "nuclei installed: $("$BIN_PREFIX/nuclei" -version 2>&1 | head -1)"
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

# --- 2c. Optional: searchsploit (Exploit-DB CLI for CVE → exploit mapping) ---
# No brew formula — clone on every platform. Use $HOME on macOS to avoid sudo.
if ! command -v searchsploit &>/dev/null; then
    log "Installing searchsploit (Exploit-DB CLI)…"
    if [[ "$IS_MAC" -eq 1 ]]; then
        ESDB_DIR="$HOME/.local/share/exploitdb"
        mkdir -p "$(dirname "$ESDB_DIR")"
        [[ ! -d "$ESDB_DIR" ]] && git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git "$ESDB_DIR" || true
        [[ -f "$ESDB_DIR/searchsploit" ]] && ln -sf "$ESDB_DIR/searchsploit" "$BIN_PREFIX/searchsploit"
    else
        if [[ ! -d /opt/exploitdb ]]; then
            sudo git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb || warn "searchsploit clone failed"
        fi
        [[ -f /opt/exploitdb/searchsploit ]] && sudo ln -sf /opt/exploitdb/searchsploit "$BIN_PREFIX/searchsploit"
    fi
fi

# --- 2d. Optional: testssl.sh (TLS audit) ---
# Brew already installs it on macOS via install_brew. Linux: clone manually.
if ! command -v testssl.sh &>/dev/null && [[ "$IS_MAC" -ne 1 ]]; then
    log "Installing testssl.sh (TLS audit)…"
    if [[ ! -d /opt/testssl ]]; then
        sudo git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl || warn "testssl.sh clone failed"
    fi
    [[ -f /opt/testssl/testssl.sh ]] && sudo ln -sf /opt/testssl/testssl.sh "$BIN_PREFIX/testssl.sh" && sudo chmod +x /opt/testssl/testssl.sh
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
