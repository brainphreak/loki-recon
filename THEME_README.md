# Themes

A theme is a directory under `loki/themes/<name>/` containing a single background image (with header / icons / decorative elements baked in), per-status character animation frames, fonts, and a `theme.json` describing where to draw the dynamic elements (status text, dialogue, stats numbers, etc.).

The renderer (`loki/lcd_renderer.py`) composes the LCD scene by drawing the bg image at full size, then overlaying the *dynamic* elements at the exact pixel coordinates the theme specifies. Static elements (title text, icon labels, decorative borders) are part of the bg image — the renderer never draws them.

## Directory layout

```
loki/themes/<theme>/
├── theme.json
├── images/
│   ├── main_bg.png              landscape (480×222)
│   ├── main_bg_portrait.png     portrait (222×480)
│   ├── menu_bg.png              menu screen
│   ├── pause_bg.png             pause overlay
│   ├── settings_bg.png          settings screen
│   └── status/
│       ├── IDLE/IDLE1.png  IDLE2.png  …       animation frames
│       ├── FTPBruteforce/FTPBruteforce1.png  …
│       ├── SSHBruteforce/…
│       └── (one folder per orchestrator action, with N animation frames)
├── fonts/
│   └── title.TTF                title typeface (referenced by theme.json)
└── comments/
    └── comments.json            per-status dialogue lines
```

The renderer auto-detects the active theme from `config["theme"]` and reloads on theme switch.

## `theme.json` schema

```jsonc
{
    "theme_name": "Loki (Dark)",          // shown in UI title
    "web_title": "LOKI",                  // browser tab title

    "text_color":   [0, 200, 60],         // [r,g,b] 0-255 — body text
    "accent_color": [0, 140, 40],         // [r,g,b] 0-255 — emphasis (status / stats numbers)

    "animation_mode": "sequential",       // "sequential" or "random"
    "image_display_delaymin": 1.5,        // seconds between frames
    "image_display_delaymax": 2.0,
    "comment_delaymin": 15,               // seconds between dialogue refreshes
    "comment_delaymax": 30,

    "moods": { "target": "Vendetta", "swarm": "Chaotic", "recon": "Slither" },
    "menu_colors":       { …palette for the menu screen… },
    "pause_menu_colors": { …palette for the pause overlay… },

    "web": {                              // colors used by the web UI (CSS vars)
        "bg_dark":    "#000000",
        "bg_surface": "#0a1a0a",
        "bg_elevated":"#122512",
        "accent":     "#00c83c",
        "text_primary": "#e6f5e6",
        …
        "font_title": "'Viking', 'Georgia', serif",
        "nav_label_display": "Display"
    },

    "skin_layout_landscape": { …see below… },
    "skin_layout_portrait":  { …see below… }
}
```

### Layout sections (`skin_layout_landscape` / `skin_layout_portrait`)

Each layout section places dynamic elements in pixel coordinates. The bg is 480×222 landscape or 222×480 portrait.

#### `character` — animated character image

```json
"character": {
    "x": 31, "y": 49,
    "w": 170, "h": 170,
    "align": "left"
}
```

The renderer pulls `current_image_path` (cycled through the active status's animation frames) and draws it at this rect. `align`: `left` (x is left edge), `center` (x is center), `right` (x is right edge).

#### `status` — current orchestrator status (text + small icon)

```json
"status": {
    "icon_x": 257, "icon_y": 79,
    "icon_size": 46,                 // status icon (lokistatusimage_path) drawn here
    "text_x": 310, "text_y": 80,
    "main_font_size": 23,
    "sub_font_size": 19,
    "sub_text_y": 105,
    "max_text_w": 166,               // text auto-shrinks to fit this width
    "align": "left"
}
```

`text_x/text_y` is the main status string; `sub_text_y` is the secondary line (currently `lokistatustext2`, e.g. the target IP).

#### `dialogue` — Loki's commentary

```json
"dialogue": {
    "x": 257, "y": 133,
    "max_w": 219,
    "max_lines": 4,
    "line_height": 21,
    "font_size": 23,
    "margin": 4,
    "align": "left"
}
```

Word-wrapped at `max_w`, truncated to `max_lines` (last line gets `…` if overflowing).

#### `stats` — counter grid

```json
"stats": {
    "align": "left",
    "font_size": 23,
    "target":    {"x": 293, "y":   7},
    "port":      {"x": 368, "y":   7},
    "vuln":      {"x": 443, "y":   7},
    "cred":      {"x": 293, "y":  45},
    "zombie":    {"x": 368, "y":  45},
    "data":      {"x": 443, "y":  45},
    "gold":      {"x":   4, "y":  77},
    "networkkb": {"x": 201, "y":  77},
    "level":     {"x":   4, "y": 197},
    "attacks":   {"x": 201, "y": 197}
}
```

Each cell is one of `target`, `port`, `vuln`, `cred`, `zombie`, `data`, `gold`, `level`, `networkkb`, `attacks`. Per-cell `align`, `font`, `font_size`, and `color` overrides are supported.

#### `battery` — battery indicator

```json
"battery": {
    "x": 209, "y": 11,
    "font_size": 18,
    "align": "center",
    "enabled": false,                // Pi has no pager battery — disable per theme
    "color": [200, 200, 200]
}
```

Set `"enabled": false` to suppress drawing the battery percentage. The battery icon shape itself lives in the bg image, so on the Pi port we either ship bg images without the battery icon or accept it as a static visual.

## Comments file

`loki/themes/<theme>/comments/comments.json` is a JSON object: top-level keys are orchestrator status names (`IDLE`, `NetworkScanner`, `FTPBruteforce`, `SSHBruteforce`, …), each value is a list of strings the renderer cycles through as the dialogue text.

```json
{
    "IDLE": [
        "Hacking away…",
        "Just sniffin' the breeze.",
        "Looking for trouble."
    ],
    "FTPBruteforce": [
        "FTP? In this economy?",
        "Old protocol, fresh meat."
    ]
}
```

The display loop pulls a random comment for the current `lokiorch_status` every 15-30 seconds (configurable via `comment_delaymin`/`comment_delaymax`).

## Color formats

The renderer accepts:
- `[r, g, b]` — list of integers 0-255
- `"#rrggbb"` or `"#rgb"` — hex strings

## Tips for designing a theme

1. **Bake static elements into the bg.** The renderer only overlays dynamic elements (character, status text, stats numbers, dialogue, battery). Header titles, icons, decorative borders, and labels for stats should already be drawn into `main_bg.png`.
2. **Lay out the stats grid before drawing the bg.** Sketch where each stat number sits, draw the corresponding icon next to/above it in the bg image, then write the matching `(x, y)` into `theme.json`.
3. **Test orientation switching** — render at both 480×222 and 222×480 by toggling Config → Orientation. Each orientation gets its own bg + layout.
4. **Use `align: center`** if the bg places the icon centered above the number — it's cleaner than fudging x for left-anchored text.
5. **Keep `max_text_w` honest** — long status names like `NmapVulnScanner` will overflow if you give them too narrow a box; the renderer auto-shrinks the font to fit.

## Switching themes at runtime

UI: **Display** tab → Theme dropdown (or **Config** tab → `theme` dropdown).

API:

```bash
curl -X POST http://host:8000/api/theme \
     -H 'Content-Type: application/json' \
     -d '{"theme":"pirate"}'
```

The server saves the config, calls `load_fonts()` → `load_images()` → `load_theme()` (in that order so theme overrides win), rebuilds `Commentaireia` so the new comments file kicks in immediately, forces an animation tick, and busts the LCD render cache so the next `/screen.png` reflects the change.
