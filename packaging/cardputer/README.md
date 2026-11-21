# Loki on the M5Stack CardputerZero

The CardputerZero is a Raspberry Pi Compute Module Zero (CM0) running Raspberry
Pi OS (Debian, arm64), so Loki runs as the ordinary Linux/Pi build — the recon
engine, web UI, themes and JSON API are unchanged. This directory adds what
makes it a **CardputerZero app**: it draws the scene on the built-in 320×170 LCD
and reads the built-in keyboard, and it installs as a one-click APPLaunch app.

## How it works on the device

- **Display** — the onboard ST7789v3 LCD is a Linux framebuffer at `/dev/fb0`
  (320×170, RGB565). `loki/cardputer_display.py` renders the scene with
  `lcd_renderer` and blits RGB565 straight to the framebuffer.
- **Keyboard** — the TCA8418 matrix is a standard evdev device
  (`/dev/input/cardputer-zero-internal`). `loki/cardputer_input.py` reads it and
  drives the on-device menu (`loki/cardputer_menu.py`). The CardputerZero has no
  arrow keys, so navigation is **F = up, X = down, Z = left, C = right,
  Enter = select, Esc = back**. The menu covers Start/Pause, theme switching,
  Mode (Auto/Manual), Web UI on/off, and Reset Data (clear hosts / loot /
  counters / everything, each with a confirm), plus Exit back to the launcher.
- **Launcher integration** — Loki is started by M5's APPLaunch, which suspends
  its own UI + keyboard while an app runs (so the launcher's menu/status bar do
  not draw over Loki). `loki.desktop` sets `Sysplause=true` like the other
  security apps (Bruce, ZClaw).
- Enable the onboard hardware with `loki.py --cardputer` (or `LOKI_HW=cardputer`).

Environment overrides (normally injected by APPLaunch, else auto-detected):
`APPLAUNCH_LINUX_FBDEV_DEVICE`, `APPLAUNCH_LINUX_KEYBOARD_DEVICE`,
`LOKI_FB_DEVICE`, `LOKI_FB_FPS`, `LOKI_FB_SCALE`, `LOKI_FB_ROTATE`,
`LOKI_INPUT_DEVICE`, `LOKI_INPUT_KEYMAP`.

## Files

| File | Purpose |
| --- | --- |
| `loki_launcher` | APPLaunch entry point → `/usr/share/APPLaunch/bin/` |
| `loki.desktop` | APPLaunch menu entry → `/usr/share/APPLaunch/applications/` |
| `loki.png` | 256×256 store/launcher icon → `/usr/share/APPLaunch/share/images/` |
| `app-builder.json` | CardputerZero Hub store metadata |
| `build_deb.sh` | Builds the arm64 `.deb` |

## Build the package

```bash
packaging/cardputer/build_deb.sh            # -> dist/loki_<version>_arm64.deb
```

Install on the device:

```bash
sudo apt install ./loki_<version>_arm64.deb   # pulls nmap/smbclient/freerdp,
                                              # postinst builds the venv
```

Loki then appears in the CardputerZero launcher. The app also serves the web UI
on `http://<device-ip>:8000/`.

## Publishing to the CardputerZero Hub store

Two channels, both land in the same store (CardputerZero/packages):

- **CLI (`czdev`)** — from the AppBuilder repo. Upserts the `.deb` as a release
  asset in your fork, then opens a metadata PR. Run it from *this* directory
  (the one holding `app-builder.json`):
  ```bash
  git clone https://github.com/CardputerZero/AppBuilder.git
  cd AppBuilder && ./czdev login          # one-time GitHub device-flow login
  cd /path/to/loki-recon/packaging/cardputer
  /path/to/AppBuilder/czdev publish --deb /path/to/dist/loki_1.0.0_arm64.deb
  ```
- **Web portal** — `https://dev.cardputer.cc`, sign in with GitHub, upload the
  `.deb`. (Full store listing metadata — summary/screenshots/categories — comes
  from the `app-builder.json` PR, so the CLI path is the complete one.)

**First release is NOT auto-merged**: after the PR opens you must post a short
video of Loki running on a real CardputerZero in the PR; a maintainer merges it.
Later version bumps auto-merge once validation passes.

Store requirements (already set in `app-builder.json`):
- `store.share_code` — a unique 4-char code, currently `loki`. It's claimed on
  first publish; **do not change it after.** If the store rejects it as taken,
  pick another 4-char code.
- `store.screenshots` — 1–6 PNGs at **320×170** (two are in `screenshots/`).
- `store.icon` — square PNG 128–512 px (ours is 256×256).
- `store.categories` — 1–2 from the store enum; Loki uses `Security`.
- `store.license` — SPDX id (`MIT`).
- `store.permissions` — exactly 7 booleans; Loki sets `network`,
  `additional_hardware` (framebuffer/evdev) and `background_service` (web UI).
- The `.deb` `Maintainer` must not be the template default (ours is the real
  GitHub no-reply address) and the app must not run a root systemd service
  (Loki has no service — APPLaunch launches it as the logged-in user).

See <https://github.com/CardputerZero/AppBuilder> (czdev + `app-builder.json`
spec) and <https://github.com/CardputerZero/packages> (the store repo).
