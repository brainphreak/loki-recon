"""
cardputer_menu.py — on-device menu for Loki on the M5Stack CardputerZero.

loki-recon's menu/settings normally live in the web UI; the pager's loki_menu.py
needs the pager's native `pagerctl` library, which does not exist here. This is a
small native menu rendered to the 320x170 LCD and driven by the keyboard:

    Start menu  (on launch):  Start · Theme · Settings · Exit
    Pause menu  (while running): Resume · Theme · Settings · Exit
    Settings:   Mode (Auto/Manual) · Web UI (On/Off) · Back

Navigation: Up/Down move, Left/Right change a value (theme/toggle), Enter
selects, Esc goes back (and exits from the start menu). While the scene is
running, any of Enter/Esc opens the pause menu.

The display backend renders `menu.render()` whenever `menu.active()` is true,
otherwise it renders the live scene.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

try:
    from PIL import Image, ImageDraw, ImageFont
    _PIL = True
except ImportError:
    _PIL = False

# Reuse the theme-switch + theme-list helpers from the input backend.
try:
    from cardputer_input import _apply_theme, _list_themes
except Exception:  # pragma: no cover - fallback if import order differs
    def _list_themes(sd):
        root = os.path.join(getattr(sd, "currentdir", "."), "themes")
        try:
            return sorted(d for d in os.listdir(root)
                          if os.path.isfile(os.path.join(root, d, "theme.json")))
        except OSError:
            return []

    def _apply_theme(sd, name):
        sd.config["theme"] = name

# Palette (RGB).
C_BG = (18, 18, 26)
C_TITLE = (120, 200, 255)
C_SEL = (60, 210, 90)
C_UNSEL = (235, 235, 235)
C_VALUE = (120, 200, 255)
C_HINT = (130, 130, 140)
C_SEL_BAR = (40, 70, 45)

WIDTH, HEIGHT = 320, 170


class _NullHandler:
    """Swallows the HTTP response that WebUtils.clear_* methods try to write, so
    we can reuse that exact clear logic from the on-device menu."""

    class _Sink:
        def write(self, *a, **k):
            return None

    def __init__(self):
        self.wfile = self._Sink()

    def send_response(self, *a, **k):
        return None

    def send_header(self, *a, **k):
        return None

    def end_headers(self, *a, **k):
        return None


class CardputerMenu:
    def __init__(self, shared_data):
        self.sd = shared_data
        # start | running | pause | settings | reset | confirm
        self.screen = "start"
        self._settings_from = "start"  # where Settings was entered from
        self.sel = 0
        self._font_cache: dict[int, object] = {}
        self._confirm_id = None        # pending reset id while on the confirm screen
        self._confirm_label = ""       # human label for the confirm prompt
        self._toast = ""               # transient result message ("Hosts cleared")
        self._toast_until = 0.0        # monotonic time the toast expires

    # ----- state -----

    def active(self) -> bool:
        """True when a menu (not the live scene) should be shown."""
        return self.screen != "running"

    def _theme_display(self) -> str:
        name = self.sd.config.get("theme", "loki")
        try:
            import json
            tj = os.path.join(self.sd.currentdir, "themes", name, "theme.json")
            disp = json.load(open(tj)).get("theme_name")
            if disp:
                return disp
        except Exception:
            pass
        return name

    def _mode_value(self) -> str:
        return "Manual" if getattr(self.sd, "manual_mode", True) else "Auto"

    def _webui_value(self) -> str:
        return "Off" if os.environ.get("BJORN_WEB_UI", "on").lower() == "off" else "On"

    def _items(self):
        if self.screen == "start":
            return [
                {"id": "start", "label": "Start"},
                {"id": "theme", "label": "Theme", "value": self._theme_display()},
                {"id": "settings", "label": "Settings"},
                {"id": "exit", "label": "Exit"},
            ]
        if self.screen == "pause":
            return [
                {"id": "resume", "label": "Resume"},
                {"id": "theme", "label": "Theme", "value": self._theme_display()},
                {"id": "settings", "label": "Settings"},
                {"id": "exit", "label": "Exit"},
            ]
        if self.screen == "settings":
            return [
                {"id": "mode", "label": "Mode", "value": self._mode_value()},
                {"id": "webui", "label": "Web UI", "value": self._webui_value()},
                {"id": "reset", "label": "Reset Data"},
                {"id": "back", "label": "Back"},
            ]
        if self.screen == "reset":
            return [
                {"id": "reset_hosts", "label": "Clear Hosts"},
                {"id": "reset_loot", "label": "Clear Loot"},
                {"id": "reset_counters", "label": "Clear Counters"},
                {"id": "reset_all", "label": "Clear Everything"},
                {"id": "back", "label": "Back"},
            ]
        return []

    def _title(self) -> str:
        return {
            "start": "LOKI", "pause": "Paused", "settings": "Settings",
            "reset": "Reset Data", "confirm": "Confirm",
        }.get(self.screen, "LOKI")

    # ----- input -----

    def open_pause(self):
        self.screen = "pause"
        self.sel = 0

    def on_key(self, action: str) -> None:
        # Running scene: any nav/select/back opens the pause menu.
        if self.screen == "running":
            if action in ("select", "back", "up", "down"):
                self.open_pause()
            return

        # Confirm screen: destructive reset waits for an explicit yes/no.
        if self.screen == "confirm":
            if action == "select":
                self._do_confirmed_reset()
            elif action in ("back", "left"):
                self.screen = "reset"
                self.sel = 0
            return

        items = self._items()
        if not items:
            return
        if action == "up":
            self.sel = (self.sel - 1) % len(items)
        elif action == "down":
            self.sel = (self.sel + 1) % len(items)
        elif action in ("left", "right"):
            self._adjust(items[self.sel], action)
        elif action == "select":
            self._activate(items[self.sel])
        elif action == "back":
            self._back()

    def _cycle_theme(self, step: int):
        themes = _list_themes(self.sd)
        if not themes:
            return
        cur = self.sd.config.get("theme", themes[0])
        try:
            idx = themes.index(cur)
        except ValueError:
            idx = 0
        _apply_theme(self.sd, themes[(idx + step) % len(themes)])

    def _adjust(self, item, action):
        step = 1 if action == "right" else -1
        if item["id"] == "theme":
            self._cycle_theme(step)
        elif item["id"] == "mode":
            self._toggle_mode()
        elif item["id"] == "webui":
            self._toggle_webui()

    def _activate(self, item):
        iid = item["id"]
        if iid == "start" or iid == "resume":
            # begin / resume the live scene
            if iid == "start":
                self._set_mode(auto=True)   # Start kicks off scanning
            self.screen = "running"
        elif iid == "theme":
            self._cycle_theme(1)
        elif iid == "settings":
            self._settings_from = self.screen
            self.screen = "settings"
            self.sel = 0
        elif iid == "mode":
            self._toggle_mode()
        elif iid == "webui":
            self._toggle_webui()
        elif iid == "reset":
            self.screen = "reset"
            self.sel = 0
        elif iid in ("reset_hosts", "reset_loot", "reset_counters", "reset_all"):
            self._confirm_id = iid
            self._confirm_label = item["label"]
            self.screen = "confirm"
        elif iid == "back":
            if self.screen == "reset":
                self.screen = "settings"
            else:
                self.screen = self._settings_from
            self.sel = 0
        elif iid == "exit":
            self._quit()

    def _back(self):
        if self.screen == "settings":
            self.screen = self._settings_from
            self.sel = 0
        elif self.screen == "reset":
            self.screen = "settings"
            self.sel = 0
        elif self.screen == "pause":
            self.screen = "running"
        elif self.screen == "start":
            self._quit()

    # ----- actions -----

    def _set_mode(self, auto: bool):
        self.sd.manual_mode = not auto
        try:
            self.sd.config["manual_mode"] = self.sd.manual_mode
            self.sd.save_config()
        except Exception:
            pass

    def _toggle_mode(self):
        self._set_mode(auto=(self._mode_value() == "Manual"))

    def _toggle_webui(self):
        cur = os.environ.get("BJORN_WEB_UI", "on").lower()
        os.environ["BJORN_WEB_UI"] = "off" if cur != "off" else "on"
        # Note: takes effect on next launch (the server thread starts at boot).

    # ----- data reset -----
    #
    # These reuse the EXACT clear logic the web UI already ships (WebUtils) so
    # the two paths never drift. The web methods write an HTTP response; we feed
    # them a tiny no-op handler that swallows those calls. The display broker
    # (display.py) recomputes host/loot/vuln counters live from the files on
    # disk, so clearing the files is all that's needed to zero those counts —
    # only the attacks counter is persisted separately (clear_stats handles it).

    def _web_utils(self):
        from utils import WebUtils  # noqa: PLC0415
        return WebUtils(self.sd, logger)

    def _do_confirmed_reset(self):
        kind = self._confirm_id
        label = self._confirm_label or "Data"
        ok = True
        try:
            wu = self._web_utils()
            h = _NullHandler()
            if kind == "reset_hosts":
                wu.clear_hosts(h)
            elif kind == "reset_loot":
                wu.clear_stolen_files(h)
                wu.clear_credentials(h)
            elif kind == "reset_counters":
                wu.clear_stats(h)
            elif kind == "reset_all":
                wu.clear_all(h)
            else:
                ok = False
        except Exception as e:
            logger.error("reset %s failed: %s", kind, e)
            ok = False
        self._confirm_id = None
        self.screen = "reset"
        self.sel = 0
        import time as _t
        self._toast = (f"{label}: done" if ok else f"{label}: failed")
        self._toast_until = _t.monotonic() + 1.6

    def _quit(self):
        logger.info("menu: exit requested — terminating Loki so APPLaunch resumes")
        self.sd.display_should_exit = True
        for attr in ("should_exit", "orchestrator_should_exit", "webapp_should_exit"):
            try:
                setattr(self.sd, attr, True)
            except Exception:
                pass
        # Actually end the process. The cardputer backends are daemon threads;
        # just stopping them leaves the orchestrator + web server running, so
        # loki_launcher never returns and APPLaunch stays stuck on Loki. Send
        # SIGTERM to trigger Loki.py's handle_exit (clean join + sys.exit); the
        # os._exit fallback guarantees the process dies if the handler stalls.
        import os as _os
        import signal as _signal
        import threading as _threading

        try:
            _os.kill(_os.getpid(), _signal.SIGTERM)
        except Exception:
            pass

        def _hard_exit():
            import time
            time.sleep(4)
            _os._exit(0)

        _threading.Thread(target=_hard_exit, daemon=True).start()

    # ----- render -----

    def _font(self, size):
        f = self._font_cache.get(size)
        if f is not None:
            return f
        path = getattr(self.sd, "font_arial_path", None)
        if not path or not os.path.isfile(path):
            cand = os.path.join(getattr(self.sd, "currentdir", "."),
                                "themes", "loki", "fonts", "Arial.ttf")
            path = cand if os.path.isfile(cand) else None
        try:
            f = ImageFont.truetype(path, size) if path else ImageFont.load_default()
        except Exception:
            f = ImageFont.load_default()
        self._font_cache[size] = f
        return f

    def _bg(self):
        name = self.sd.config.get("theme", "loki")
        for cand in (
            os.path.join(self.sd.currentdir, "themes", name, "images", "menu_bg.png"),
            os.path.join(self.sd.currentdir, "themes", "loki", "images", "menu_bg.png"),
        ):
            if os.path.isfile(cand):
                try:
                    return Image.open(cand).convert("RGB").resize((WIDTH, HEIGHT), Image.LANCZOS)
                except Exception:
                    pass
        return Image.new("RGB", (WIDTH, HEIGHT), C_BG)

    def _center(self, draw, y, text, font, fill):
        try:
            w = draw.textlength(text, font=font)
        except Exception:
            w = len(text) * 8
        draw.text(((WIDTH - w) // 2, y), text, font=font, fill=fill)

    def render(self, width=WIDTH, height=HEIGHT):
        if not _PIL:
            return None
        img = self._bg()
        # dim overlay so text reads on busy backgrounds
        overlay = Image.new("RGB", (WIDTH, HEIGHT), (0, 0, 0))
        img = Image.blend(img, overlay, 0.45)
        draw = ImageDraw.Draw(img)

        item_f = self._font(20)
        hint_f = self._font(12)

        # Confirm screen: a full-screen yes/no for a destructive reset.
        if self.screen == "confirm":
            self._center(draw, 40, (self._confirm_label or "Clear data") + "?",
                         self._font(22), (255, 180, 90))
            self._center(draw, 74, "This cannot be undone.", item_f, C_UNSEL)
            self._center(draw, 118, "ENTER = yes      ESC = no", item_f, C_VALUE)
            return img

        # The theme title ("LOKI") is already baked into menu_bg.png, so we do
        # not draw our own title text (it would overlap / duplicate it).

        items = self._items()
        n = max(len(items), 1)
        # Adaptive vertical layout so longer lists (Reset Data) still fit below
        # the baked title band and above the hint footer.
        top_lim, bot_lim = 46, 150
        row_h = min(26, (bot_lim - top_lim) // n)
        block_h = n * row_h
        top = top_lim + max(0, (bot_lim - top_lim - block_h) // 2)
        for i, it in enumerate(items):
            y = top + i * row_h
            selected = (i == self.sel)
            if selected:
                draw.rectangle([(16, y - 2), (WIDTH - 16, y + row_h - 4)], fill=C_SEL_BAR)
            label = it["label"]
            color = C_SEL if selected else C_UNSEL
            prefix = "> " if selected else "  "
            draw.text((28, y), prefix + label, font=item_f, fill=color)
            if it.get("value") is not None:
                val = str(it["value"])
                try:
                    w = draw.textlength(val, font=item_f)
                except Exception:
                    w = len(val) * 10
                draw.text((WIDTH - 28 - w, y), val, font=item_f, fill=C_VALUE)

        # Transient result toast after a reset, else the key hint.
        import time as _t
        if self._toast and _t.monotonic() < self._toast_until:
            tw = 0
            try:
                tw = int(draw.textlength(self._toast, font=item_f))
            except Exception:
                tw = len(self._toast) * 10
            draw.rectangle([((WIDTH - tw) // 2 - 10, HEIGHT - 30),
                            ((WIDTH + tw) // 2 + 10, HEIGHT - 2)], fill=(20, 90, 40))
            self._center(draw, HEIGHT - 27, self._toast, item_f, (255, 255, 255))
        else:
            self._center(draw, HEIGHT - 18,
                         "F/X move   Z/C change   ENTER select   ESC back",
                         hint_f, C_HINT)
        return img
