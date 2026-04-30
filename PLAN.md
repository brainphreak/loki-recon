# Loki-Pi Port Plan

Porting `pineapple_pager_loki` from the WiFi Pineapple Pager (MIPS, custom hardware)
to Raspberry Pi (ARM Linux, headless, web UI only).

## Goals

- **Primary target:** Raspberry Pi Zero 2 W (arm64, 512 MB RAM, 1 GHz quad-core)
- **Secondary target:** Raspberry Pi 5 (arm64, faster — used as dev/test box)
- **Headless:** no LCD, no buttons. Web UI is the only display surface.
- **No vendored binaries:** all native tools come from `apt`, all Python deps from `pip`
  (PyPI auto-resolves the right wheel per architecture).
- **JSON API:** `/api/v1/*` endpoints alongside the HTML web UI, so a future
  native phone app can connect without backend changes.
- **PWA web UI:** installable, full-screen, home-screen-icon — no native app required for v1.
- **Cross-platform dev:** runs in Docker `linux/arm64` on Mac/Linux/Windows so contributors
  can develop without owning a Pi.

## Architecture overview

```
┌────────────────────────────────────────────────────────┐
│  Loki orchestrator (Python)                            │
│   Loki.py → actions/*.py                               │
│   Calls: nmap, smbclient, freerdp (via $PATH)          │
│   Calls: paramiko, impacket, cryptography (pip)        │
└──────────────┬─────────────────────────────────────────┘
               │ events
               ▼
┌────────────────────────────────────────────────────────┐
│  display.py (rewritten as event broker)                │
│   - HeadlessDisplay: same public API as old display    │
│   - Ring buffer (last 200 events)                      │
│   - subscribe() returns a queue                        │
└──────────────┬─────────────────────────────────────────┘
               │
       ┌───────┴────────┐
       ▼                ▼
┌──────────────┐  ┌──────────────────────────────────┐
│ logging      │  │ Web server (existing :8000)      │
│ (file/syslog)│  │  /                HTML UI (PWA)  │
└──────────────┘  │  /events          SSE stream     │
                  │  /api/v1/status   JSON           │
                  │  /api/v1/scan     JSON (POST)    │
                  │  /api/v1/targets  JSON           │
                  │  /api/v1/events   SSE (versioned)│
                  │  Auth: Bearer token              │
                  └──────────────────────────────────┘
```

## Phases

### Phase 0 — Environment setup

**Goal:** working dev environment on Mac before touching code.

- [ ] 0.1 Clone `pineapple-pager-projects/pineapple_pager_loki` into `/Users/brainphreak/loki-pi/`
- [ ] 0.2 Create Python venv: `python3 -m venv .venv && source .venv/bin/activate`
- [ ] 0.3 Install dev tooling: `pip install --upgrade pip wheel`
- [ ] 0.4 Install Docker Desktop if not present, verify `docker buildx ls` shows `linux/arm64`
- [ ] 0.5 Register QEMU binfmt handlers: `docker run --privileged --rm tonistiigi/binfmt --install arm64,arm`
- [ ] 0.6 Sanity test: `docker run --rm --platform=linux/arm64 debian:bookworm uname -m` → `aarch64`
- [ ] 0.7 Create `.gitignore` additions for `.venv/`, `__pycache__/`, `*.pyc`, `data/exfil/`

### Phase 1 — Strip vendored MIPS artifacts

**Goal:** delete everything that won't run on a Pi anyway.

- [ ] 1.1 Delete `payloads/user/reconnaissance/loki/bin/` (MIPS `nmap`, `sfreerdp`, `smb2-*`, `legacy.so`)
- [ ] 1.2 Delete `payloads/user/reconnaissance/loki/lib/` (MIPS `.so` files + bundled `.pyc` for `cffi`, `bcrypt`, `cryptography`, etc.)
- [ ] 1.3 Verify nothing else references files inside `bin/` or `lib/` by absolute path
- [ ] 1.4 Commit: "rip out vendored MIPS binaries and python deps"

### Phase 2 — Build requirements.txt from imports

**Goal:** declarative Python deps, installed per-arch by pip from PyPI.

- [ ] 2.1 Grep all `import` and `from X import Y` statements across `*.py`
- [ ] 2.2 Subtract stdlib modules; map third-party imports to PyPI package names
- [ ] 2.3 Likely set: `paramiko`, `cryptography`, `bcrypt`, `cffi`, `pysmb` or `smbprotocol`, `impacket`, `pymysql`, `pyftpdlib`, `python-nmap`, `requests`, `flask` or `fastapi` (whichever the web UI uses)
- [ ] 2.4 Pin versions known to ship arm64 wheels (avoid sdist-only on Pi Zero 2 W)
- [ ] 2.5 Write `requirements.txt`
- [ ] 2.6 Test install in venv on Mac: `pip install -r requirements.txt`

### Phase 3 — Replace hardcoded binary paths

**Goal:** use `$PATH`-resolved tools so apt-installed versions work.

- [ ] 3.1 Grep for `bin/nmap`, `bin/sfreerdp`, `bin/smb2-cat`, `bin/smb2-find`, `bin/smb2-share-enum`, `bin/xfreerdp`, `bin/legacy.so`
- [ ] 3.2 Replace each with bare command name (`nmap`, `xfreerdp`, `smbclient`, etc.)
- [ ] 3.3 Investigate `legacy.so` — what calls it, can we drop entirely or replace with a Python lib?
- [ ] 3.4 Add startup check: warn if `nmap`/`smbclient`/`xfreerdp` not on `$PATH`
- [ ] 3.5 Decide whether to replace `smb2-*` shell-outs with native Python via `smbprotocol` (cleaner) or keep `smbclient` invocation (closer to current code)

### Phase 4 — Rewrite display.py as event broker

**Goal:** orchestrator code unchanged; LCD calls now feed the web UI.

- [ ] 4.1 Inventory the public API of current `display.py` — every method `Loki.py` and `actions/*.py` call
- [ ] 4.2 Create new `display.py` with `HeadlessDisplay` class:
  - Same method signatures
  - Each call emits a typed event dict to subscribers
  - Each call also goes through `logging.getLogger("loki.display")`
  - Internal `deque(maxlen=200)` ring buffer for replay-on-connect
  - `subscribe()` returns a `queue.Queue`, `unsubscribe(q)` cleans up
- [ ] 4.3 No-op the LCD/font/framebuffer/theme animation code paths
- [ ] 4.4 Drop button/input handling entirely (web UI controls everything)
- [ ] 4.5 Sanity-run: `python3 -c "from display import HeadlessDisplay; d=HeadlessDisplay(); d.show_status('hello')"`

### Phase 5 — Server-Sent Events endpoint

**Goal:** push display events to the browser in real time.

- [ ] 5.1 Identify the existing web framework (Flask vs FastAPI vs stdlib `http.server`)
- [ ] 5.2 Add `/events` SSE route that:
  - Calls `display.subscribe()` to get a queue
  - Drains the ring buffer first (replay history)
  - Then streams live events as `data: {json}\n\n`
  - Cleans up on client disconnect
- [ ] 5.3 Test with `curl -N http://localhost:8000/events` while emitting events
- [ ] 5.4 Add reconnect-friendly `event:` and `id:` fields so browsers auto-resume

### Phase 6 — Wire the web UI to SSE

**Goal:** browser shows live status without polling.

- [ ] 6.1 Add `EventSource("/events")` in the existing JS
- [ ] 6.2 Render incoming events into the existing status/host/log panels
- [ ] 6.3 Make sure the visual elements that used to mirror the LCD (character animation, status text, scan progress) still appear
- [ ] 6.4 Handle reconnect on navigation / network blip
- [ ] 6.5 Mobile-friendly CSS audit — touch targets ≥ 44 px, viewport meta tag

### Phase 7 — JSON API

**Goal:** stable, versioned, documented API surface for scripts and a future phone app.

- [ ] 7.1 `GET  /api/v1/status` — scan state, current target, counts (creds found, files stolen, etc.)
- [ ] 7.2 `POST /api/v1/scan` — body `{"action":"start"|"stop"|"pause"}`
- [ ] 7.3 `GET  /api/v1/targets` — list known hosts + per-host state
- [ ] 7.4 `POST /api/v1/targets` — add IP/hostname/range
- [ ] 7.5 `DELETE /api/v1/targets/<id>`
- [ ] 7.6 `GET  /api/v1/credentials` — discovered creds (gated by auth)
- [ ] 7.7 `GET  /api/v1/exfil` — list of exfiltrated files (metadata, not contents)
- [ ] 7.8 `GET  /api/v1/events` — same SSE stream as `/events`, versioned path
- [ ] 7.9 Document everything in `API.md` (OpenAPI-ish, but keep it short)

### Phase 8 — Bearer token auth

**Goal:** API and sensitive UI routes require a token.

- [ ] 8.1 On first run, generate `config/api_token.json` with a random 32-byte token if absent
- [ ] 8.2 Print the token to stdout on startup so the user can copy it
- [ ] 8.3 Middleware: require `Authorization: Bearer <token>` for `/api/v1/*` and any state-mutating UI route
- [ ] 8.4 The HTML UI either prompts for the token on first load and stores it in `localStorage`, or accepts it in the URL once and sets a session cookie
- [ ] 8.5 `/events` and read-only status routes can be public OR require auth — pick one (default: require auth)

### Phase 9 — PWA manifest + service worker

**Goal:** "add to home screen" on iOS/Android, full-screen, app-like.

- [ ] 9.1 `static/manifest.json` — name, short_name, icons (192/512), start_url, display: standalone, theme_color
- [ ] 9.2 Add `<link rel="manifest">` and Apple-specific meta tags to base template
- [ ] 9.3 Minimal `static/sw.js` service worker — cache the shell, network-first for `/api/*` and `/events`
- [ ] 9.4 Generate icon set from `loki.png`
- [ ] 9.5 Test "Add to Home Screen" on iOS Safari and Android Chrome

### Phase 10 — `--headless` flag and entry point

**Goal:** clean CLI, sane defaults.

- [ ] 10.1 Add `argparse` to `Loki.py`: `--headless` (default true), `--bind 0.0.0.0`, `--port 8000`, `--config <path>`, `--log-level`
- [ ] 10.2 Rename launcher: `launch_pagergotchi.sh` → `loki.sh` (or just drop, use Python entry point)
- [ ] 10.3 Make the package executable via `python3 -m loki`

### Phase 11 — install.sh

**Goal:** end users on a Pi run one command.

- [ ] 11.1 Detect distro (`/etc/os-release`)
- [ ] 11.2 `apt update && apt install -y nmap smbclient freerdp2-x11 python3 python3-pip python3-venv` (handle `freerdp3-x11` fallback for newer Debian)
- [ ] 11.3 Create venv, `pip install -r requirements.txt`
- [ ] 11.4 Print the API token, the URL (`http://<pi-ip>:8000`), and the systemd-unit option
- [ ] 11.5 (optional) Install a `loki.service` systemd unit so it starts on boot

### Phase 12 — Dockerfile + docker-compose.yml

**Goal:** "develop on Mac, run as if on Pi Zero 2 W, with the existing vulnerable test rig as the target."

- [ ] 12.1 `Dockerfile` for the Loki dev container — `--platform=linux/arm64 debian:bookworm`
- [ ] 12.2 Mirrors the same `apt install` + `pip install` from `install.sh`
- [ ] 12.3 Top-level `docker-compose.yml` that:
  - Builds the loki-dev container
  - Mounts source as a volume for live edit
  - Exposes 8000 to the Mac host
  - Joins the `bjorn-testnet` bridge (the existing 172.16.52.0/24 network from `test_targets/`)
  - Assigns Loki a static IP on that subnet (e.g. 172.16.52.10)
- [ ] 12.4 Single dev command: `docker compose -f test_targets/docker-compose.yml -f docker-compose.yml up -d` brings up vulnerable rig + Loki together
- [ ] 12.5 README section: "Develop without a Pi"

### Phase 12.5 — arm64 compatibility audit of test_targets

**Goal:** make sure the existing vulnerable rig still builds and runs on arm64 (so dev on Mac with Apple Silicon works the same as dev on a real Pi).

- [ ] 12.5.1 `docker buildx imagetools inspect fauria/vsftpd` — check arm64 manifest. If x86-only, swap for `delfer/alpine-ftp-server` or build a tiny arm64 vsftpd Alpine image
- [ ] 12.5.2 Verify `dperson/samba`, `mariadb:10.6` have arm64 — both should
- [ ] 12.5.3 Build the custom Alpine images (`ssh/`, `telnet/`, `http/`, `rdp/`) on arm64 explicitly: `docker buildx build --platform=linux/arm64 ...`
- [ ] 12.5.4 If anything fails, document the swap in `test_targets/README.md` (don't modify upstream behavior unless required)

### Phase 13 — README + docs

**Goal:** someone unfamiliar with the project can install and run.

- [ ] 13.1 Rewrite top section: "Loki-Pi: a Pi port of pineapple_pager_loki"
- [ ] 13.2 Quickstart for Pi Zero 2 W
- [ ] 13.3 Quickstart for Pi 5
- [ ] 13.4 Develop-in-Docker section
- [ ] 13.5 Authorized-use disclaimer near the top
- [ ] 13.6 Move pager-specific docs (theme, LCD) into a separate file or remove
- [ ] 13.7 Link to `API.md` for the JSON API

### Phase 14 — End-to-end attack smoke test in Docker arm64

**Goal:** prove the full attack chain runs on arm64 before touching real Pi hardware.

- [ ] 14.1 Bring up vulnerable rig: `cd test_targets && docker compose up -d`
- [ ] 14.2 Bring up Loki dev container, joined to `bjorn-testnet`: `docker compose up --build`
- [ ] 14.3 Open `http://localhost:8000`, confirm UI loads and SSE stream connects
- [ ] 14.4 In the UI, add target range `172.16.52.0/24` and start a scan
- [ ] 14.5 Confirm events flow to the UI: host discovered (172.16.52.228), ports open, services identified
- [ ] 14.6 Confirm brute force succeeds against SSH/FTP/SMB/MySQL/Telnet/RDP using the planted weak creds
- [ ] 14.7 Confirm file exfil pulls planted files (`.env`, `.flag`, etc.) into the mounted volume
- [ ] 14.8 Confirm SQL dump from MariaDB works
- [ ] 14.9 Verify all this within Loki's web UI in the browser (no LCD code path executed)
- [ ] 14.10 Sanity: `docker exec loki-dev python -c "import nmap, paramiko, smbprotocol, cryptography"` succeeds

### Phase 15 — Real-hardware validation (you, after I hand off)

**Goal:** confirm the Docker behavior matches an actual Pi.

- [ ] 15.1 Flash Raspberry Pi OS Lite (64-bit) onto an SD card for whichever Pi you own
- [ ] 15.2 `git clone` your fork, run `./install.sh`
- [ ] 15.3 Open the web UI from your phone over the LAN
- [ ] 15.4 Run a scan against your lab, verify behavior matches Docker
- [ ] 15.5 (later, when you get a Zero 2 W) repeat on the actual target hardware

## What I do vs what you do

**I do (in this conversation):** Phases 0 through 14 — code changes, Dockerfile, install.sh, README,
smoke-tested inside Docker `linux/arm64` on your Mac.

**You do (after handoff):** Phase 15 — flash a real Pi, run install.sh, validate against your lab.
Provide me feedback on anything that broke and I'll patch.

## Open questions before we start

1. **Docker Desktop on Mac, host networking** — Docker Desktop on macOS has limitations with
   `network_mode: host`. Acceptable workarounds: (a) use a macvlan network on Docker, (b) accept
   that the Docker dev env can scan the *host* and other containers but not arbitrary LAN devices,
   and rely on real-Pi testing for full LAN scans. Which do you prefer?
2. **`smb2-*` shell-outs:** keep as `smbclient` calls (smaller change), or rewrite as native
   Python via `smbprotocol` (cleaner, fewer subprocess parsing bugs)? My vote: rewrite, but it adds
   ~half a day.
3. **Web framework:** I'll discover what the existing UI uses in Phase 5. If it's stdlib `http.server`,
   I'd like to migrate to Flask or FastAPI for the SSE/API work — much cleaner. OK?
4. **Auth scope:** require the bearer token for *everything*, or leave the read-only event stream
   and status page public on the LAN? I lean toward "require for everything" — friction is low and
   you don't want random LAN guests reading your scan output.
