# loki-recon

**LAN Orchestrated Key Infiltrator** — autonomous network recon companion for Linux. Headless web UI with themes, JSON API, live LCD-style scene renderer, and a one-command multi-distro installer. Tested on Raspberry Pi (Zero 2 W, 4, 5) and any Debian / Fedora / Arch / openSUSE host. Inspired by Bjorn.

> **Authorized use only.** This tool runs network scans, brute-force credential checks, and file exfiltration against discovered services. Run it only against networks and hosts you own or have explicit written permission to test (your home lab, CTF environments, sanctioned engagements).

## Features

- **Network discovery** — ARP scan with ICMP fallback, hostname resolution (rDNS / NetBIOS / mDNS / nmap)
- **Port scan** — configurable port list, nmap integration
- **Vulnerability scan** — nmap NSE scripts (`vuln` category by default, full-category mode optional) plus optional [Nuclei](https://github.com/projectdiscovery/nuclei) for templated HTTP/HTTPS coverage (~13k templates)
- **CVE correlation** — offline CISA KEV catalog ships with the project; optional online NVD lookup for CVSS scores
- **Credential brute force** — FTP, SSH, Telnet, SMB, MySQL, RDP — with selectable wordlists (default 220 combos / aggressive 10,800 combos / custom)
- **File exfiltration** — pulls sensitive files from FTP/SSH/SMB/Telnet hosts where credentials succeeded
- **SQL data theft** — dumps databases from MySQL with cracked credentials
- **Web UI** — themed, real-time control panel + log feed at `http://<host>:8000/`
- **JSON API** — versioned `/api/v1/*` endpoints with bearer-token auth for scripts and future native apps
- **Themes** — six built-in themes (loki, loki_dark, bjorn, knight, pirate, clown) with custom character animations, dialogue, and stats layouts
- **PWA** — install the web UI to a phone home screen for an app-like experience

## Quick start (Raspberry Pi or any Debian/Fedora/Arch box)

```bash
git clone https://github.com/brainphreak/loki-recon.git
cd loki-recon
./install.sh
source .venv/bin/activate
python3 loki.py
```

Open `http://<host-ip>:8000/` in a browser.

`install.sh` auto-detects `apt` / `dnf` / `pacman` / `zypper` and installs:
- `nmap`, `smbclient`, `freerdp` (`freerdp2-x11` or `freerdp3-x11`)
- Python 3.11+ with `paramiko`, `pysmb`, `python-nmap`, `cryptography`, `Pillow`, etc.
- Nuclei binary (matched to your CPU arch)

## Develop without a Pi (Docker)

The repo ships a vulnerable test rig at `test_targets/` that brings up FTP/SSH/Telnet/SMB/MySQL/HTTP/RDP services with weak credentials, all on `172.16.52.0/24`. Loki dev container joins the same bridge.

```bash
# 1. start the vulnerable rig
cd test_targets && docker compose up -d && cd ..

# 2. start Loki on linux/arm64 (emulates Pi Zero 2 W on Apple Silicon / Intel)
docker compose up --build

# 3. open http://localhost:8000/
```

The Loki container's API token is written to `state/api_token.json` inside the data volume and printed to container stdout on first run.

## CLI flags

```
python3 loki.py [--bind 0.0.0.0] [--port 8000] [--data-dir /var/lib/loki-recon]
                [--no-web] [--log-level INFO|DEBUG|WARNING|ERROR]
```

Env-var equivalents: `LOKI_BIND`, `LOKI_PORT`, `LOKI_DATA_DIR`, `LOKI_LOG_LEVEL`.

## Data layout

```
~/.loki/data/                       (or whatever LOKI_DATA_DIR points to)
├── loot/
│   ├── stolen/                     exfiltrated files (FTP/SSH/SMB/Telnet)
│   ├── credentials/                cracked CSVs (ssh.csv, smb.csv, …)
│   ├── vulnerabilities/            vuln_summary.csv (NSE + Nuclei findings)
│   └── zombies/                    open-anonymous services
├── scans/                          per-host nmap output
├── state/                          netkb.csv, livestatus.csv, api_token.json, attacks_count.json
├── logs/                           per-module .log files
└── archives/                       backup zips
```

The location is configurable from the **Config** tab (or `LOKI_DATA_DIR` env var).

## Supported attack matrix

| Service | Port | Brute force | File / data theft |
|---|---|---|---|
| FTP    | 21   | yes | yes |
| SSH    | 22   | yes | yes |
| Telnet | 23   | yes | yes |
| SMB    | 445  | yes | yes |
| MySQL  | 3306 | yes | yes (DB dump) |
| RDP    | 3389 | yes | n/a |

## Documentation

- [WEBUI_README.md](WEBUI_README.md) — web UI routes, JSON API, SSE event stream, auth
- [THEME_README.md](THEME_README.md) — theme.json schema, layout coordinates, custom themes
- [TEST_TARGETS.md](TEST_TARGETS.md) — vulnerable Docker test rig

## Lineage

Forked architecturally from the [WiFi Pineapple Pager edition of Loki](https://github.com/pineapple-pager-projects/pineapple_pager_loki), itself inspired by [Bjorn](https://github.com/infinition/Bjorn). The Pi port replaces all pager-specific hardware code and MIPS-compiled binaries with Linux-native tooling.

## License

See [LICENSE](LICENSE).
