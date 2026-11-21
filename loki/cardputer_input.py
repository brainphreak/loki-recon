"""
cardputer_input.py — M5Stack CardputerZero keyboard backend.

The CardputerZero's 46-key matrix is driven by a TCA8418 controller that the
Linux kernel exposes as a standard evdev device (/dev/input/event*). M5Stack's
own app template reads it the same way (APP_KEY_INPUT_DEVICE, auto-scanning
/dev/input/event*), so we read raw input_event structs — no python-evdev
dependency required.

On-device, this backend gives Loki a usable UI without the web browser:

    key / default         action
    ------------------    --------------------------------------------
    ENTER  (or '5')       toggle scanning  (manual_mode: pause <-> run)
    LEFT   (or '4')       previous theme
    RIGHT  (or '6')       next theme
    ESC                   exit the app (return to the launcher)

Exact CardputerZero keycodes are not published; confirm with `evtest` on the
device and override via LOKI_INPUT_KEYMAP (a JSON object mapping action name ->
list of Linux keycodes). The defaults cover both a normal keyboard (arrows +
Enter + Esc) and M5's launcher convention (number keys 4/5/6).

Environment knobs:
    LOKI_INPUT_DEVICE   evdev path (default: auto-scan /dev/input/event*)
    LOKI_INPUT_KEYMAP   JSON overriding the action -> [keycodes] map
    LOKI_INPUT_NO_EXIT  if set, ESC does nothing (don't let a stray key quit)
"""

from __future__ import annotations

import glob
import json
import logging
import os
import struct
import threading
import time

logger = logging.getLogger(__name__)

# Linux evdev constants.
EV_KEY = 0x01
# input_event struct: sized natively (24 bytes on 64-bit, 16 on 32-bit).
_EV_FMT = "llHHi"
_EV_SIZE = struct.calcsize(_EV_FMT)

# Common Linux keycodes (include/uapi/linux/input-event-codes.h).
_KC = {
    "ESC": 1, "ENTER": 28, "LEFT": 105, "RIGHT": 106, "UP": 103, "DOWN": 108,
    "SPACE": 57, "KP_ENTER": 96,
    "1": 2, "2": 3, "3": 4, "4": 5, "5": 6, "6": 7, "7": 8, "8": 9,
    # Letter keys — the CardputerZero's compact keyboard has NO arrow keys, so
    # navigation uses letters: F=up, X=down, Z=left, C=right (user-confirmed).
    "F": 33, "X": 45, "Z": 44, "C": 46,
}

# action -> candidate keycodes (first match wins; multiple allowed). These drive
# the on-device menu (cardputer_menu): up/down move, left/right change a value,
# select activates, back goes back (and opens the pause menu from the scene).
# The CardputerZero keyboard lacks dedicated arrow keys, so the primary nav keys
# are the letters F/X/Z/C; real arrows + number keys are kept as fallbacks for
# any attached USB keyboard.
_DEFAULT_KEYMAP = {
    "up":     [_KC["F"], _KC["UP"], _KC["8"]],
    "down":   [_KC["X"], _KC["DOWN"], _KC["2"]],
    "left":   [_KC["Z"], _KC["LEFT"], _KC["4"]],
    "right":  [_KC["C"], _KC["RIGHT"], _KC["6"]],
    "select": [_KC["ENTER"], _KC["KP_ENTER"], _KC["SPACE"], _KC["5"]],
    "back":   [_KC["ESC"]],
}


def _device_name(event_path: str) -> str:
    name = os.path.basename(event_path)
    for p in (
        f"/sys/class/input/{name}/device/name",
        f"/sys/class/input/{name}/name",
    ):
        try:
            with open(p, "r") as f:
                return f.read().strip()
        except OSError:
            continue
    return ""


def find_keyboard_device() -> str | None:
    """Pick the keypad evdev node. LOKI_INPUT_DEVICE wins; otherwise score the
    nodes by name (TCA8418 / keyboard / matrix / keys)."""
    env = (
        os.environ.get("LOKI_INPUT_DEVICE")
        or os.environ.get("APPLAUNCH_LINUX_KEYBOARD_DEVICE")
    )
    if env and os.path.exists(env):
        return env
    # Stable nodes the CardputerZero image provides for the TCA8418 keypad.
    for stable in (
        "/dev/input/cardputer-zero-internal",
        "/dev/input/by-path/platform-3f804000.i2c-event",
    ):
        if os.path.exists(stable):
            logger.info("CardputerZero keyboard: %s", stable)
            return stable
    candidates = sorted(glob.glob("/dev/input/event*"))
    best = None
    for path in candidates:
        n = _device_name(path).lower()
        if any(k in n for k in ("tca8418", "keyboard", "matrix", "keypad", "keys", "m5", "cardputer")):
            logger.info("CardputerZero keyboard: %s (%s)", path, n or "?")
            return path
        if best is None:
            best = path
    if best:
        logger.info("CardputerZero keyboard: falling back to %s (%s)",
                    best, _device_name(best) or "?")
    return best


def _load_keymap() -> dict[str, list[int]]:
    km = {k: list(v) for k, v in _DEFAULT_KEYMAP.items()}
    override = os.environ.get("LOKI_INPUT_KEYMAP")
    if override:
        try:
            data = json.loads(override)
            for action, codes in data.items():
                if action in km and isinstance(codes, list):
                    km[action] = [int(c) for c in codes]
        except Exception as e:
            logger.warning("LOKI_INPUT_KEYMAP ignored (%s)", e)
    return km


def _list_themes(shared_data) -> list[str]:
    root = os.path.join(getattr(shared_data, "currentdir", "."), "themes")
    try:
        return sorted(
            d for d in os.listdir(root)
            if os.path.isfile(os.path.join(root, d, "theme.json"))
        )
    except OSError:
        return []


def _apply_theme(shared_data, new_theme: str) -> None:
    """Switch theme + reload assets (standalone port of utils.set_theme)."""
    shared_data.config["theme"] = new_theme
    try:
        shared_data.save_config()
    except Exception as e:
        logger.debug("save_config: %s", e)
    for fn in ("load_fonts", "load_images", "load_theme"):
        try:
            getattr(shared_data, fn)()
        except Exception as e:
            logger.debug("%s after theme switch: %s", fn, e)
    try:
        loki = getattr(shared_data, "loki_instance", None)
        if loki is not None:
            from comment import Commentaireia  # noqa: PLC0415
            loki.commentaire_ia = Commentaireia()
    except Exception as e:
        logger.debug("Commentaireia rebuild: %s", e)
    try:
        shared_data.update_image_randomizer()
    except Exception:
        pass
    try:
        import lcd_renderer  # noqa: PLC0415
        lcd_renderer._cache_frame = None  # type: ignore[attr-defined]
        lcd_renderer._cache_at = 0.0      # type: ignore[attr-defined]
    except Exception:
        pass


class CardputerInput:
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.device = find_keyboard_device()
        self.keymap = _load_keymap()
        self.allow_exit = not os.environ.get("LOKI_INPUT_NO_EXIT")
        self._code_to_action = {}
        for action, codes in self.keymap.items():
            for c in codes:
                self._code_to_action.setdefault(c, action)
        self._fd = None
        self._stop = False

    # ----- actions -----

    def _dispatch(self, action: str) -> None:
        """Route a navigation action (up/down/left/right/select/back) to the
        on-device menu."""
        menu = getattr(self.shared_data, "cardputer_menu", None)
        if menu is not None:
            menu.on_key(action)

    # ----- loop -----

    def run(self) -> None:
        if not self.device:
            logger.error("CardputerZero input disabled (no evdev device found).")
            return
        try:
            self._fd = open(self.device, "rb", buffering=0)
        except OSError as e:
            logger.error("Cannot open input device %s: %s", self.device, e)
            return
        logger.info("CardputerZero input loop started on %s", self.device)
        while not self._stop and not getattr(
            self.shared_data, "display_should_exit", False
        ):
            try:
                data = self._fd.read(_EV_SIZE)
            except OSError:
                break
            if not data or len(data) < _EV_SIZE:
                time.sleep(0.02)
                continue
            _s, _us, etype, code, value = struct.unpack(_EV_FMT, data)
            if etype != EV_KEY or value != 1:  # key-press (down) only
                continue
            action = self._code_to_action.get(code)
            if action:
                try:
                    self._dispatch(action)
                except Exception as e:
                    logger.debug("action %s failed: %s", action, e)
            else:
                logger.debug("unmapped keycode %d", code)
        self.cleanup()

    def stop(self) -> None:
        self._stop = True

    def cleanup(self) -> None:
        if self._fd is not None:
            try:
                self._fd.close()
            except OSError:
                pass
            self._fd = None


def start(shared_data) -> "CardputerInput | None":
    try:
        inp = CardputerInput(shared_data)
    except Exception as e:
        logger.error("CardputerZero input init failed: %s", e)
        return None
    t = threading.Thread(target=inp.run, name="cardputer-input", daemon=True)
    t.start()
    inp._thread = t  # type: ignore[attr-defined]
    return inp
