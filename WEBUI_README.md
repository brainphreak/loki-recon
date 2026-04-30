# Web UI & JSON API

The web UI lives at `http://<host>:8000/` and is served by `loki/webapp.py` (stdlib `http.server`). It's a single-page app: `index.html` + JS in `loki/web/scripts/` consumes the JSON endpoints below.

## Tabs

| Tab | What it shows |
|---|---|
| **Dashboard** | Live counters (hosts, ports, vulns, creds, files, attacks, score, level) + current orchestrator status |
| **Hosts** | netkb.csv — discovered hosts, open ports, per-host attack history |
| **Attacks** | Manual mode: pick a target/port/action and execute. Always-on log feed of orchestrator activity below the controls. |
| **Loot** | Cracked credentials, stolen files, vuln findings, SQL dumps |
| **Config** | All config keys grouped into sections; theme + orientation pickers; reset buttons |
| **Terminal** | Live tail of all module logs |
| **Display** | Server-side render of the LCD scene (`/screen.png`), so you see what the pager LCD *would* be drawing |

## Public (no-auth) routes

These mirror the original web UI; the existing JS uses these:

| Route | Method | Returns |
|---|---|---|
| `/` (and `/dashboard`, `/hosts`, …) | GET | SPA shell (`index.html`) |
| `/api/stats` | GET | dashboard counters + status as JSON |
| `/api/theme` | GET | active theme palette + web title |
| `/api/themes` | GET | list of available themes |
| `/api/theme_font` | GET | theme title font (TTF) |
| `/api/theme` | POST `{theme}` | switch active theme, reload assets, bust the LCD render cache |
| `/load_config` | GET | current config (defaults merged with overrides) |
| `/save_config` | POST `{key:value...}` | save config; triggers `load_theme` + dictionary reload + LCD cache bust |
| `/restore_default_config` | GET | reset config.json to defaults |
| `/get_networks` | GET | local non-loopback IPv4 interfaces with /CIDR |
| `/network_data` | GET | HTML table view of netkb |
| `/netkb_data_json` | GET | netkb.csv as JSON (ips + ports + actions) |
| `/get_logs[?current=1]` | GET | aggregated logs across modules; `current=1` = since the last action started |
| `/list_credentials` | GET | discovered creds across services |
| `/list_files[?…]` | GET | exfiltrated file metadata |
| `/download_file?…` | GET | download a stolen file |
| `/api/host_loot_summary/<ip>` | GET | per-host loot rollup |
| `/api/vulnerabilities[/<ip>]` | GET | vuln summary, optionally filtered |
| `/screen.png` | GET | LCD scene render (PNG, 480×222 landscape or 222×480 portrait) |
| `/manifest.json` | GET | PWA manifest (installable to home screen) |
| `/clear_hosts` | POST | wipe netkb so hosts are rediscovered |
| `/clear_scan_logs` | POST | truncate logs + wipe scan results + livestatus |
| `/clear_stats` | POST | zero the persisted attacks counter |
| `/clear_stolen_files` | POST | wipe stolen-files dir |
| `/clear_credentials` | POST | wipe cracked-credentials dir |
| `/clear_all` | POST | nuke everything except the config file |
| `/start_orchestrator`, `/stop_orchestrator` | POST | toggle auto-mode |
| `/execute_manual_attack` | POST | run one attack (manual mode) |
| `/stop_manual_attack` | POST | stop the running manual attack |
| `/events` | GET (SSE) | stream of state-change events from `display.broker` |

## `/api/v1/*` — versioned JSON namespace (bearer-token auth)

All endpoints under `/api/v1/` require an `Authorization: Bearer <token>` header. `/api/v1/events` also accepts `?token=<token>` for `EventSource`. The token is auto-generated on first run and saved to `state/api_token.json` (also printed to stdout on container start).

| Route | Method | Returns |
|---|---|---|
| `/api/v1/status` | GET | current state JSON (alias of `/api/stats`) |
| `/api/v1/targets` | GET | netkb hosts + ports |
| `/api/v1/targets/clear` | POST | wipe netkb |
| `/api/v1/credentials` | GET | discovered creds |
| `/api/v1/exfil` | GET | stolen files list |
| `/api/v1/networks` | GET | local interfaces |
| `/api/v1/themes` | GET | theme list + active |
| `/api/v1/theme` | POST `{theme}` | switch theme |
| `/api/v1/scan` | POST `{action}` | `start` / `stop` / `pause` orchestrator |
| `/api/v1/events` | GET (SSE) | versioned event stream |

Example:

```bash
TOKEN=$(curl -s http://host:8000/state/api_token.json ...)  # or read from disk
curl -H "Authorization: Bearer $TOKEN" http://host:8000/api/v1/status
```

## Server-Sent Events

`/events` (and `/api/v1/events`) emits one event per state change with `id:`, `event:`, and `data:` fields. The display loop polls `shared_data` every 250 ms and broadcasts deltas to all subscribers. A 200-event ring buffer is replayed on connect.

Event types:

| `event` | `data` |
|---|---|
| `display_started` / `display_stopped` | lifecycle |
| `state` | `{field, value}` — one of `lokiorch_status`, `lokisay`, `lokistatustext`, `lokistatusimage_path`, `current_image_path`, `manual_mode`, `battery_level`, counters, theme name |
| `loading` | `{message}` — startup loading text |

```javascript
const es = new EventSource('/events');
es.addEventListener('state', (e) => {
    const ev = JSON.parse(e.data);
    console.log('changed:', ev.field, '→', ev.value);
});
```

## Auth

- Original UI routes are open (no token required) so existing JS keeps working unchanged.
- `/api/v1/*` requires the bearer token — bind to `0.0.0.0` and you can safely expose the API to scripts on the same host without exposing the legacy UI publicly.
- For a hardened deployment, run loki behind nginx with HTTPS and IP-allowlist the legacy routes too.

## PWA install

`manifest.json` is linked from `index.html`. iOS Safari → Share → Add to Home Screen. Android Chrome → menu → Install app. The web UI then opens in standalone mode on the home screen.

## Development

The web UI source lives in `loki/web/`:

```
loki/web/
├── index.html
├── manifest.json
├── css/loki.css
└── scripts/
    ├── app.js              router, theme loader, App.api/post helpers
    ├── dashboard.js        dashboard counters + live status
    ├── network.js          host list
    ├── attacks.js          manual mode + always-on log panel
    ├── loot.js             credentials / files / vulns
    ├── config.js           Config tab (auto-renders all keys from /load_config)
    ├── loki.js             Display tab (LCD scene mirror + theme/orientation pickers)
    ├── terminal.js         multi-module log tail
    └── console.js          shared log rendering
```

Volume-mount the source in dev so JS edits are live without rebuilds:

```yaml
# docker-compose.yml
volumes:
  - ./loki:/app/loki
```

Hard-refresh the browser (`Cmd/Ctrl+Shift+R`) after editing JS.
