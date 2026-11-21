"""
cardputer_display.py — M5Stack CardputerZero onboard-LCD backend.

The CardputerZero is a Raspberry Pi Compute Module Zero (CM0) running
Raspberry Pi OS (aarch64). Its 1.9" ST7789v3 LCD (320x170, RGB565) is
exposed to Linux as a standard framebuffer device (default /dev/fb0), so we
can push pixels to it exactly like any Linux framebuffer — no SPI library
required (confirmed by M5Stack's own app template, which defaults
APP_FRAMEBUFFER_DEVICE to /dev/fb0).

This backend runs ALONGSIDE the headless `display.Display` broker: that broker
owns scene *state* (animation frames, counters, comments, SSE events for the
web UI); this backend owns scene *pixels*. It polls the same shared_data,
renders via lcd_renderer, and blits to the framebuffer.

The plain Raspberry Pi / x86 path never imports this module, so it is purely
additive — a hardware profile, not a fork.

Environment knobs (so install.sh / systemd can configure without code edits):
    LOKI_FB_DEVICE   framebuffer path (default: /dev/fb0)
    LOKI_FB_FPS      frame rate (default: 10 — plenty for this UI, kind to the
                     CM0's cores which are busy scanning)
    LOKI_FB_SCALE    'fill' (stretch, default) or 'fit' (letterbox)
    LOKI_FB_ROTATE   0 / 90 / 180 / 270 — correct panel orientation if the
                     framebuffer's native orientation differs (verify on device)
    LOKI_FB_FAKE     if set to a path, write frames there instead of a real fb
                     (off-device testing). '<path>.png' gets a decoded preview.
"""

from __future__ import annotations

import logging
import os
import struct
import threading
import time

logger = logging.getLogger(__name__)

try:
    import numpy as _np
    _NUMPY = True
except ImportError:
    _NUMPY = False

from lcd_renderer import (  # noqa: E402
    CARDPUTER_W,
    CARDPUTER_H,
    render_panel_image,
)


def _read_sysfs(path: str) -> str | None:
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except OSError:
        return None


def detect_fb_geometry(fb_device: str) -> tuple[int, int, int, int]:
    """Return (width, height, bits_per_pixel, line_length) for a framebuffer.

    Reads /sys/class/graphics/fbN/{virtual_size,bits_per_pixel,stride} when
    available; falls back to the CardputerZero panel's known geometry.
    """
    name = os.path.basename(fb_device)  # e.g. 'fb0'
    base = f"/sys/class/graphics/{name}"
    w = h = bpp = line = None

    vs = _read_sysfs(f"{base}/virtual_size")
    if vs and "," in vs:
        try:
            w_s, h_s = vs.split(",")[:2]
            w, h = int(w_s), int(h_s)
        except ValueError:
            pass
    bpp_s = _read_sysfs(f"{base}/bits_per_pixel")
    if bpp_s:
        try:
            bpp = int(bpp_s)
        except ValueError:
            pass
    stride_s = _read_sysfs(f"{base}/stride")
    if stride_s:
        try:
            line = int(stride_s)
        except ValueError:
            pass

    w = w or CARDPUTER_W
    h = h or CARDPUTER_H
    bpp = bpp or 16
    line = line or (w * (bpp // 8))
    return w, h, bpp, line


def _to_rgb565_bytes(img, width: int, height: int, line_length: int) -> bytes:
    """Convert a PIL RGB image (already width x height) to a framebuffer blob.

    Produces RGB565 little-endian, padded to line_length per row when the
    framebuffer stride exceeds width*2.
    """
    row_px = width * 2
    if _NUMPY:
        arr = _np.asarray(img, dtype=_np.uint16)  # H x W x 3
        r = (arr[:, :, 0] >> 3) & 0x1F
        g = (arr[:, :, 1] >> 2) & 0x3F
        b = (arr[:, :, 2] >> 3) & 0x1F
        rgb565 = (r << 11) | (g << 5) | b  # H x W uint16
        if line_length == row_px:
            return rgb565.astype("<u2").tobytes()
        # Pad each row up to the stride.
        pad = (line_length - row_px) // 2
        padded = _np.zeros((height, width + pad), dtype="<u2")
        padded[:, :width] = rgb565.astype("<u2")
        return padded.tobytes()

    # Pure-Python fallback (slow; device should have numpy via apt).
    px = img.load()
    out = bytearray(line_length * height)
    for y in range(height):
        row_off = y * line_length
        o = row_off
        for x in range(width):
            r, g, b = px[x, y][:3]
            v = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
            out[o] = v & 0xFF
            out[o + 1] = (v >> 8) & 0xFF
            o += 2
    return bytes(out)


class CardputerDisplay:
    """Framebuffer render loop for the CardputerZero onboard LCD."""

    def __init__(self, shared_data):
        self.shared_data = shared_data
        # Device precedence: our override, then the var APPLaunch injects when
        # it starts an app, then the stable symlink, then /dev/fb0.
        self.fb_device = (
            os.environ.get("LOKI_FB_DEVICE")
            or os.environ.get("APPLAUNCH_LINUX_FBDEV_DEVICE")
            or ("/dev/fb_lcd" if os.path.exists("/dev/fb_lcd") else "/dev/fb0")
        )
        self.fps = float(os.environ.get("LOKI_FB_FPS", "10") or 10)
        self.scale_mode = os.environ.get("LOKI_FB_SCALE", "fill").lower()
        try:
            self.rotate = int(os.environ.get("LOKI_FB_ROTATE", "0") or 0) % 360
        except ValueError:
            self.rotate = 0
        self.fake_path = os.environ.get("LOKI_FB_FAKE") or None

        self._fb = None
        self._cleaned_up = False
        self._stop = False

        # The panel is physically landscape; make sure the scene composes in
        # landscape no matter what screen_rotation the config carries.
        try:
            if isinstance(getattr(shared_data, "config", None), dict):
                shared_data.config.setdefault("screen_rotation", 270)
                if shared_data.config.get("screen_rotation") in (0, 180):
                    shared_data.config["screen_rotation"] = 270
        except Exception:
            pass

        if self.fake_path:
            self.width, self.height = CARDPUTER_W, CARDPUTER_H
            self.bpp, self.line_length = 16, CARDPUTER_W * 2
        else:
            self.width, self.height, self.bpp, self.line_length = detect_fb_geometry(
                self.fb_device
            )
        logger.info(
            "CardputerZero display: %s %dx%d %dbpp stride=%d fps=%.0f scale=%s rotate=%d%s",
            self.fb_device, self.width, self.height, self.bpp, self.line_length,
            self.fps, self.scale_mode, self.rotate,
            " (FAKE)" if self.fake_path else "",
        )
        if self.bpp != 16:
            logger.warning(
                "Framebuffer is %dbpp; this backend writes RGB565 (16bpp). "
                "Verify the panel format on device.", self.bpp
            )

    # ----- framebuffer I/O -----

    def _open_fb(self):
        if self.fake_path:
            return
        try:
            self._fb = open(self.fb_device, "r+b", buffering=0)
        except OSError as e:
            logger.error("Cannot open framebuffer %s: %s", self.fb_device, e)
            self._fb = None

    def _write_frame(self, blob: bytes) -> None:
        if self.fake_path:
            try:
                with open(self.fake_path, "wb") as f:
                    f.write(blob)
            except OSError as e:
                logger.debug("fake fb write failed: %s", e)
            return
        if self._fb is None:
            return
        try:
            self._fb.seek(0)
            self._fb.write(blob)
        except OSError as e:
            logger.debug("framebuffer write failed: %s", e)

    # ----- render -----

    def _render_blob(self) -> bytes | None:
        """Compose the scene, orient to the panel, pack to RGB565."""
        # Panel pixel size, accounting for a 90/270 rotation swap.
        if self.rotate in (90, 270):
            panel_w, panel_h = self.height, self.width
        else:
            panel_w, panel_h = self.width, self.height
        try:
            menu = getattr(self.shared_data, "cardputer_menu", None)
            if menu is not None and menu.active():
                img = menu.render(panel_w, panel_h)
                if img is None:
                    return None
                if img.size != (panel_w, panel_h):
                    from PIL import Image  # noqa: PLC0415
                    img = img.resize((panel_w, panel_h), Image.LANCZOS)
            else:
                img = render_panel_image(
                    self.shared_data, panel_w, panel_h, self.scale_mode
                )
        except Exception as e:
            logger.debug("render failed: %s", e)
            return None
        if self.rotate:
            # PIL rotate is counter-clockwise; expand=True keeps all pixels and
            # yields the framebuffer's (width x height).
            from PIL import Image  # noqa: PLC0415
            img = img.rotate(-self.rotate, expand=True)
            if img.size != (self.width, self.height):
                img = img.resize((self.width, self.height), Image.LANCZOS)
        return _to_rgb565_bytes(img, self.width, self.height, self.line_length)

    # ----- lifecycle -----

    def run(self) -> None:
        self._open_fb()
        if self._fb is None and not self.fake_path:
            logger.error("CardputerZero display disabled (no framebuffer).")
            return
        logger.info("CardputerZero display loop started")
        period = 1.0 / self.fps if self.fps > 0 else 0.1
        while not self._stop and not getattr(
            self.shared_data, "display_should_exit", False
        ):
            t0 = time.time()
            blob = self._render_blob()
            if blob is not None:
                self._write_frame(blob)
            dt = time.time() - t0
            if period - dt > 0:
                time.sleep(period - dt)
        self.cleanup()

    def stop(self) -> None:
        self._stop = True

    def cleanup(self) -> None:
        if self._cleaned_up:
            return
        self._cleaned_up = True
        if self._fb is not None:
            try:
                # Blank the panel on exit so we don't leave a frozen frame.
                self._fb.seek(0)
                self._fb.write(b"\x00" * (self.line_length * self.height))
            except OSError:
                pass
            try:
                self._fb.close()
            except OSError:
                pass
            self._fb = None
        logger.info("CardputerZero display cleaned up")


def start(shared_data) -> "CardputerDisplay | None":
    """Start the framebuffer render loop in a daemon thread. Returns the
    CardputerDisplay (or None if PIL is unavailable)."""
    try:
        disp = CardputerDisplay(shared_data)
    except Exception as e:
        logger.error("CardputerZero display init failed: %s", e)
        return None
    t = threading.Thread(target=disp.run, name="cardputer-fb", daemon=True)
    t.start()
    disp._thread = t  # type: ignore[attr-defined]
    return disp


if __name__ == "__main__":
    # Standalone smoke test: render a few frames to a fake framebuffer.
    logging.basicConfig(level=logging.INFO)

    class _Fake:
        config = {"screen_rotation": 270}
        display_should_exit = False

    os.environ.setdefault("LOKI_FB_FAKE", "/tmp/loki_cardputer_fb.raw")
    d = CardputerDisplay(_Fake())
    blob = d._render_blob()
    print("rendered blob bytes:", len(blob) if blob else None)
