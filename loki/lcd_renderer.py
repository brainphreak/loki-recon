"""
lcd_renderer.py — server-side LCD scene composer.

Renders the same scene the pager LCD would display, using the active
theme's `skin_bg_*` background and the exact pixel coordinates from
`skin_layout_landscape` / `skin_layout_portrait` in theme.json.

The bg image already bakes in headers, icons, and labels — this renderer
only draws the *dynamic* elements (animated character, status text,
dialogue, stat counts, battery) at theme-defined positions.

A future real-display backend (HDMI / SPI / framebuffer) can call
render_frame() to get a PIL.Image and push it to whatever output sink
is attached.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from io import BytesIO

try:
    from PIL import Image, ImageDraw, ImageFont
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False

logger = logging.getLogger(__name__)

# Pager LCD physical resolutions.
LANDSCAPE_W, LANDSCAPE_H = 480, 222
PORTRAIT_W, PORTRAIT_H = 222, 480

# Cache the last-rendered frame for ~250 ms so back-to-back HTTP polls
# don't re-render needlessly.
_CACHE_TTL = 0.25
_cache_lock = threading.Lock()
_cache_frame: bytes | None = None
_cache_at: float = 0.0


# ----- helpers -----

def _is_landscape(shared_data) -> bool:
    # Prefer config dict (live) over the attribute (set once at init).
    cfg = getattr(shared_data, 'config', {}) or {}
    rot = int(cfg.get('screen_rotation', getattr(shared_data, 'screen_rotation', 270)) or 0)
    return rot in (90, 270)


def _coerce_color(value, default=(255, 255, 255)):
    """Accept [r,g,b] list, '#rrggbb', or None."""
    if value is None:
        return default
    if isinstance(value, (list, tuple)) and len(value) == 3:
        try:
            return (int(value[0]), int(value[1]), int(value[2]))
        except (TypeError, ValueError):
            return default
    if isinstance(value, str):
        s = value.strip().lstrip('#')
        if len(s) == 3:
            s = ''.join(c * 2 for c in s)
        if len(s) == 6:
            try:
                return tuple(int(s[i:i + 2], 16) for i in (0, 2, 4))
            except ValueError:
                return default
    return default


def _resolve_font_path(shared_data, font_name: str | None) -> str | None:
    """Resolve a font name from the layout against theme/font dirs."""
    if not font_name:
        return None
    # Already absolute / exists?
    if os.path.isabs(font_name) and os.path.isfile(font_name):
        return font_name
    theme_name = shared_data.config.get('theme', '') if hasattr(shared_data, 'config') else ''
    candidates = [
        os.path.join(shared_data.currentdir, 'themes', theme_name, 'fonts', font_name),
        os.path.join(getattr(shared_data, 'fontdir', ''), font_name),
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def _load_font(path: str | None, size: int):
    if path and os.path.isfile(path):
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            pass
    try:
        return ImageFont.load_default()
    except Exception:
        return None


def _safe_open(path: str | None):
    if not path or not os.path.exists(path):
        return None
    try:
        return Image.open(path).convert('RGBA')
    except Exception as e:
        logger.debug(f"Could not open {path}: {e}")
        return None


def _anchor_for(align: str, vertical: str = 't') -> str:
    a = (align or 'left').lower()
    horiz = {'left': 'l', 'center': 'm', 'right': 'r'}.get(a, 'l')
    return horiz + vertical


def _draw_text(draw, xy, text, font, fill, align='left'):
    if text is None or text == '':
        return
    anchor = _anchor_for(align, 't')
    try:
        draw.text(xy, str(text), font=font, fill=fill, anchor=anchor)
    except TypeError:
        # Pre-anchor PIL: emulate left/center/right manually.
        x, y = xy
        if anchor.startswith('m'):
            try:
                w = draw.textlength(str(text), font=font)
                x -= int(w / 2)
            except Exception:
                pass
        elif anchor.startswith('r'):
            try:
                w = draw.textlength(str(text), font=font)
                x -= int(w)
            except Exception:
                pass
        draw.text((x, y), str(text), font=font, fill=fill)


def _fit_font(shared_data, section: dict, default_size: int, text: str, max_w: int):
    """Shrink the font until str(text) fits in max_w, mirroring the original
    pager's _fit_font_size binary search."""
    fname = (section or {}).get('font') if section else None
    path = _resolve_font_path(shared_data, fname) if fname else getattr(shared_data, 'font_arial_path', None)
    target = max(8, int(default_size))
    # Quick path: try the desired size first.
    f = _load_font(path, target)
    if f is None:
        return f, target
    if not text or max_w <= 0:
        return f, target
    try:
        tmp_img = Image.new('RGB', (1, 1))
        tmp_draw = ImageDraw.Draw(tmp_img)
        if tmp_draw.textlength(str(text), font=f) <= max_w:
            return f, target
    except Exception:
        return f, target
    lo, hi = 8, target
    best_size = lo
    best_font = _load_font(path, lo)
    while lo <= hi:
        mid = (lo + hi) // 2
        candidate = _load_font(path, mid)
        if candidate is None:
            break
        try:
            w = tmp_draw.textlength(str(text), font=candidate)
        except Exception:
            break
        if w <= max_w:
            best_size = mid
            best_font = candidate
            lo = mid + 1
        else:
            hi = mid - 1
    return best_font, best_size


def _wrap_lines(draw, text: str, font, max_w: int, max_lines: int) -> list[str]:
    if not text:
        return []
    words = str(text).split()
    lines: list[str] = []
    cur = ''
    for word in words:
        candidate = (cur + ' ' + word).strip()
        try:
            w = draw.textlength(candidate, font=font)
        except Exception:
            w = len(candidate) * 8
        if w <= max_w or not cur:
            cur = candidate
        else:
            lines.append(cur)
            cur = word
            if len(lines) >= max_lines:
                break
    if cur and len(lines) < max_lines:
        lines.append(cur)
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        if lines:
            lines[-1] = lines[-1].rstrip() + '…'
    return lines


# ----- main render -----

def render_frame(shared_data) -> 'Image.Image':
    """Compose the LCD scene for the current theme + state."""
    if not _PIL_AVAILABLE:
        raise RuntimeError("Pillow not installed; cannot render LCD frame")

    landscape = _is_landscape(shared_data)
    if landscape:
        canvas_w, canvas_h = LANDSCAPE_W, LANDSCAPE_H
        layout = getattr(shared_data, 'skin_layout_landscape', {}) or {}
        bg_path = getattr(shared_data, 'skin_bg_landscape', None)
    else:
        canvas_w, canvas_h = PORTRAIT_W, PORTRAIT_H
        layout = getattr(shared_data, 'skin_layout_portrait', {}) or {}
        bg_path = getattr(shared_data, 'skin_bg_portrait', None) or getattr(shared_data, 'skin_bg_landscape', None)

    text_color = _coerce_color(getattr(shared_data, 'theme_text_color', None), (255, 255, 255))
    accent_color = _coerce_color(getattr(shared_data, 'theme_accent_color', None), text_color)

    # Default background = solid black with bg image stretched to fit.
    canvas = Image.new('RGB', (canvas_w, canvas_h), (0, 0, 0))
    bg = _safe_open(bg_path)
    if bg is not None:
        bg = bg.resize((canvas_w, canvas_h), Image.LANCZOS)
        canvas.paste(bg, (0, 0), bg)

    draw = ImageDraw.Draw(canvas, 'RGBA')

    arial = getattr(shared_data, 'font_arial_path', None)

    def section_color(section: dict, default):
        return _coerce_color(section.get('color'), default) if section else default

    def section_font(section: dict, default_size: int):
        fname = (section or {}).get('font')
        size = int((section or {}).get('font_size', default_size))
        path = _resolve_font_path(shared_data, fname) if fname else arial
        return _load_font(path, size)

    # ----- Character (animated) -----
    char_cfg = layout.get('character') or {}
    char_path = (
        getattr(shared_data, 'current_image_path', None)
        or getattr(shared_data, 'lokistatusimage_path', None)
    )
    char_img = _safe_open(char_path)
    if char_img is not None and char_cfg:
        cw = int(char_cfg.get('w', 170))
        ch = int(char_cfg.get('h', 170))
        cx = int(char_cfg.get('x', 0))
        cy = int(char_cfg.get('y', 0))
        align = char_cfg.get('align', 'left')
        scaled = char_img.resize((cw, ch), Image.LANCZOS)
        if align == 'center':
            cx -= cw // 2
        elif align == 'right':
            cx -= cw
        canvas.paste(scaled, (cx, cy), scaled)

    # ----- Status (text + sub_text + icon) -----
    status_cfg = layout.get('status') or {}
    if status_cfg:
        # Status icon (the per-action image, e.g. key icon for brute force).
        icon_path = getattr(shared_data, 'lokistatusimage_path', None)
        if icon_path and 'icon_x' in status_cfg and 'icon_y' in status_cfg:
            icon_img = _safe_open(icon_path)
            if icon_img is not None:
                isz = int(status_cfg.get('icon_size', 46))
                icon_img = icon_img.resize((isz, isz), Image.LANCZOS)
                canvas.paste(icon_img, (int(status_cfg['icon_x']), int(status_cfg['icon_y'])), icon_img)
        # Main status string — shrink to fit max_text_w.
        text_x = int(status_cfg.get('text_x', 0))
        text_y = int(status_cfg.get('text_y', 0))
        max_text_w = int(status_cfg.get('max_text_w', canvas_w - text_x - 4))
        align = status_cfg.get('align', 'left')
        s_color = section_color(status_cfg, accent_color)
        main_text = getattr(shared_data, 'lokistatustext', '') or getattr(shared_data, 'lokiorch_status', '')
        sub_text = getattr(shared_data, 'lokistatustext2', '') or ''
        main_font, _ = _fit_font(shared_data, status_cfg, status_cfg.get('main_font_size', 23), main_text, max_text_w)
        sub_font, _ = _fit_font(shared_data, status_cfg, status_cfg.get('sub_font_size', 19), sub_text, max_text_w)
        _draw_text(draw, (text_x, text_y), main_text, main_font, s_color + (255,), align)
        if sub_text:
            sub_y = int(status_cfg.get('sub_text_y', text_y + 25))
            _draw_text(draw, (text_x, sub_y), sub_text, sub_font, text_color + (255,), align)

    # ----- Dialogue -----
    dlg_cfg = layout.get('dialogue') or {}
    say = getattr(shared_data, 'lokisay', '') or ''
    if dlg_cfg and say:
        dx = int(dlg_cfg.get('x', 0))
        dy = int(dlg_cfg.get('y', 0))
        max_w = int(dlg_cfg.get('max_w', canvas_w - dx - 4))
        max_lines = int(dlg_cfg.get('max_lines', 4))
        line_h = int(dlg_cfg.get('line_height', 21))
        align = dlg_cfg.get('align', 'left')
        font = section_font(dlg_cfg, dlg_cfg.get('font_size', 23))
        d_color = section_color(dlg_cfg, text_color)
        for i, line in enumerate(_wrap_lines(draw, say, font, max_w, max_lines)):
            _draw_text(draw, (dx, dy + i * line_h), line, font, d_color + (255,), align)

    # ----- Stats grid -----
    stats_cfg = layout.get('stats') or {}
    if stats_cfg:
        default_size = int(stats_cfg.get('font_size', 23))
        stats_font = section_font(stats_cfg, default_size)
        stats_color = section_color(stats_cfg, accent_color)
        stats_align = stats_cfg.get('align', 'left')
        all_stats = (
            ('target', getattr(shared_data, 'targetnbr', 0)),
            ('port', getattr(shared_data, 'portnbr', 0)),
            ('vuln', getattr(shared_data, 'vulnnbr', 0)),
            ('cred', getattr(shared_data, 'crednbr', 0)),
            ('zombie', getattr(shared_data, 'zombiesnbr', 0)),
            ('data', getattr(shared_data, 'datanbr', 0)),
            ('gold', getattr(shared_data, 'coinnbr', 0)),
            ('level', getattr(shared_data, 'levelnbr', 0)),
            ('networkkb', getattr(shared_data, 'networkkbnbr', 0)),
            ('attacks', getattr(shared_data, 'attacksnbr', 0)),
        )
        for name, value in all_stats:
            cell = stats_cfg.get(name)
            if not cell or 'x' not in cell or 'y' not in cell:
                continue
            cell_font = section_font(cell, cell.get('font_size', default_size))
            cell_color = section_color(cell, stats_color)
            cell_align = cell.get('align', stats_align)
            _draw_text(
                draw,
                (int(cell['x']), int(cell['y'])),
                str(value),
                cell_font,
                cell_color + (255,),
                cell_align,
            )

    # ----- Battery -----
    # Themes opt out via `battery.enabled = false` (Pi has no pager battery).
    bat_cfg = layout.get('battery') or {}
    bat_level = getattr(shared_data, 'battery_level', None)
    bat_enabled = bool(bat_cfg.get('enabled', False)) if bat_cfg else False
    if bat_enabled and bat_cfg and bat_level is not None:
        bx = int(bat_cfg.get('x', canvas_w - 30))
        by = int(bat_cfg.get('y', 8))
        bat_font = section_font(bat_cfg, bat_cfg.get('font_size', 18))
        bat_color = section_color(bat_cfg, text_color)
        align = bat_cfg.get('align', 'left')
        suffix = '⚡' if getattr(shared_data, 'battery_charging', False) else ''
        _draw_text(draw, (bx, by), f"{int(bat_level)}%{suffix}", bat_font, bat_color + (255,), align)

    return canvas


def render_png_bytes(shared_data) -> bytes:
    """Render to PNG bytes, with a short TTL cache to coalesce concurrent polls."""
    global _cache_frame, _cache_at
    now = time.time()
    with _cache_lock:
        if _cache_frame is not None and (now - _cache_at) < _CACHE_TTL:
            return _cache_frame

    img = render_frame(shared_data)
    buf = BytesIO()
    img.convert('RGB').save(buf, format='PNG', optimize=False, compress_level=1)
    data = buf.getvalue()

    with _cache_lock:
        _cache_frame = data
        _cache_at = time.time()
    return data
