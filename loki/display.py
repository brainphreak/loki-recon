"""
display.py — headless event broker.

Replaces the original pager LCD-rendering Display with a no-op renderer
that broadcasts state-change events to subscribers (the web UI consumes
these via Server-Sent Events).

Public API preserved so Loki.py is unchanged:
    - class Display(shared_data)
    - Display.run()
    - Display.cleanup()
    - handle_exit_display(signum, frame, display_instance)
"""

import csv
import glob
import json
import logging
import os
import sys
import threading
import time
from collections import deque
from queue import Queue

from logger import Logger

logger = Logger(name="display.py", level=logging.INFO)

# State fields polled out of shared_data and emitted as events on change.
# Counters and status strings — anything the original LCD rendered.
_TRACKED_FIELDS = (
    "lokiorch_status",
    "lokisay",
    "lokistatustext",
    "lokistatusimage_path",
    "current_image_path",
    "manual_mode",
    "battery_level",
    "battery_charging",
    "attacksnbr",
    "coinnbr",
    "crednbr",
    "datanbr",
    "levelnbr",
    "networkkbnbr",
    "portnbr",
    "targetnbr",
    "vulnnbr",
    "theme_name_display",
)


class _Broker:
    """Thread-safe pub/sub broker with a ring buffer for replay-on-connect."""

    def __init__(self, history_size: int = 200):
        self._lock = threading.Lock()
        self._subscribers: list[Queue] = []
        self._history: deque = deque(maxlen=history_size)
        self._next_id = 0

    def publish(self, event: dict) -> None:
        with self._lock:
            event = dict(event)
            event["id"] = self._next_id
            event["ts"] = time.time()
            self._next_id += 1
            self._history.append(event)
            for q in list(self._subscribers):
                try:
                    q.put_nowait(event)
                except Exception:
                    pass

    def subscribe(self) -> Queue:
        """Returns a queue. Call drain_history() first to replay buffered events."""
        q: Queue = Queue()
        with self._lock:
            for past in self._history:
                q.put_nowait(past)
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: Queue) -> None:
        with self._lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass


# Module-level singleton: the webapp's SSE endpoint imports this directly.
broker = _Broker()


class Display:
    """Headless display: polls shared_data and emits change events to the broker."""

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self._cleaned_up = False
        self._last: dict = {}
        # Poll cadence — fast enough for live UI updates, slow enough not to
        # burn the Pi Zero 2 W's single core.
        self._poll_interval = 0.25
        self._next_anim_at = 0.0
        # Same semaphore the original used to serialize file reads.
        self._counter_lock = threading.Semaphore(1)
        # Lazy-resolved Commentaireia — pulls fresh comments per orchestrator
        # status from the active theme's comments.json.
        self._commentaire = None
        self._next_comment_at = 0.0
        logger.info("Headless Display initialized — events broadcast to web UI")

    def _get_commentaireia(self):
        """Re-use Loki's Commentaireia if available (so theme switches that
        rebuild it propagate); fall back to our own instance."""
        try:
            loki = getattr(self.shared_data, 'loki_instance', None)
            if loki is not None and getattr(loki, 'commentaire_ia', None) is not None:
                return loki.commentaire_ia
        except Exception:
            pass
        if self._commentaire is None:
            try:
                from comment import Commentaireia  # noqa: PLC0415
                self._commentaire = Commentaireia()
            except Exception as e:
                logger.debug(f"Commentaireia init: {e}")
        return self._commentaire

    def _refresh_comment(self) -> None:
        """Periodically pull a new themed comment for the current status."""
        now = time.time()
        if now < self._next_comment_at:
            return
        cia = self._get_commentaireia()
        if cia is None:
            return
        try:
            status = getattr(self.shared_data, 'lokiorch_status', 'IDLE') or 'IDLE'
            new_say = cia.get_commentaire(status)
            if new_say:
                self.shared_data.lokisay = new_say
        except Exception as e:
            logger.debug(f"comment refresh: {e}")
        try:
            cmin, cmax = self.shared_data.get_effective_comment_delays()
        except Exception:
            cmin, cmax = 15, 30
        # Same cadence model as the orig: pick a random delay in [min, max].
        import random as _r
        self._next_comment_at = now + max(2, _r.randint(int(cmin), int(cmax)))

    # ----- main loop -----

    def run(self) -> None:
        logger.debug("Starting headless display loop")
        broker.publish({"type": "display_started"})
        # Background counter refreshers — same cadence as the pager-original.
        threading.Thread(target=self._loop_update_counters, daemon=True).start()
        threading.Thread(target=self._loop_update_vuln_count, daemon=True).start()
        while not self.shared_data.display_should_exit:
            try:
                self.shared_data.update_lokistatus()
                self._refresh_comment()
                self._advance_animation_frame()
                self._emit_changes()
                time.sleep(self._poll_interval)
            except Exception as e:
                logger.error(f"Error in display loop: {e}")
                time.sleep(0.5)
        logger.info("Display loop exiting")
        self.cleanup()

    # ----- counter refreshers (ported from original Display) -----

    def _loop_update_counters(self) -> None:
        """Every 25 s: re-read netkb live status + cracked pw + stolen + zombies dirs."""
        # Restore persisted attacksnbr once at start so the dashboard reflects
        # work done across restarts.
        self._load_persisted_attacks()
        while not self.shared_data.display_should_exit:
            self._update_counters_once()
            self._persist_attacks()
            time.sleep(25)

    def _loop_update_vuln_count(self) -> None:
        """Every 30 s: re-read the vuln summary CSV."""
        while not self.shared_data.display_should_exit:
            self._update_vuln_count_once()
            time.sleep(30)

    @property
    def _attacks_state_file(self) -> str:
        base = getattr(self.shared_data, 'state_dir', None) or getattr(self.shared_data, 'datadir', '.')
        return os.path.join(base, 'attacks_count.json')

    def _load_persisted_attacks(self) -> None:
        path = self._attacks_state_file
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    data = json.load(f)
                val = int(data.get('attacksnbr', 0))
                # Only use the persisted value if it's > current (so a fresh
                # boot picks it up but a running session never gets clobbered).
                if val > getattr(self.shared_data, 'attacksnbr', 0):
                    self.shared_data.attacksnbr = val
        except Exception as e:
            logger.debug(f"attacks restore: {e}")

    def _persist_attacks(self) -> None:
        path = self._attacks_state_file
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as f:
                json.dump({'attacksnbr': int(getattr(self.shared_data, 'attacksnbr', 0))}, f)
        except Exception as e:
            logger.debug(f"attacks persist: {e}")

    def _update_counters_once(self) -> None:
        with self._counter_lock:
            sd = self.shared_data
            try:
                live = getattr(sd, 'livestatusfile', None)
                if live and os.path.exists(live):
                    with open(live, 'r') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            sd.portnbr = int(row.get('Total Open Ports', 0) or 0)
                            sd.targetnbr = int(row.get('Alive Hosts Count', 0) or 0)
                            sd.networkkbnbr = int(row.get('All Known Hosts Count', 0) or 0)
                            break

                cracked_dir = getattr(sd, 'crackedpwddir', None)
                if cracked_dir:
                    total = 0
                    for path in glob.glob(os.path.join(cracked_dir, '*.csv')):
                        try:
                            with open(path, 'r') as f:
                                reader = csv.reader(f)
                                next(reader, None)
                                total += sum(1 for _ in reader)
                        except Exception:
                            pass
                    sd.crednbr = total

                stolen_dir = getattr(sd, 'datastolendir', None)
                if stolen_dir and os.path.isdir(stolen_dir):
                    sd.datanbr = sum(len(files) for _, _, files in os.walk(stolen_dir))

                zombies_dir = getattr(sd, 'zombiesdir', None)
                if zombies_dir and os.path.isdir(zombies_dir):
                    sd.zombiesnbr = sum(len(files) for _, _, files in os.walk(zombies_dir))

                sd.update_stats()
            except FileNotFoundError as e:
                logger.debug(f"Counter file not ready: {e}")
            except Exception as e:
                logger.error(f"Counter update error: {e}")

    def _update_vuln_count_once(self) -> None:
        with self._counter_lock:
            sd = self.shared_data
            try:
                vuln_file = getattr(sd, 'vuln_summary_file', None)
                if not vuln_file:
                    return
                if not os.path.exists(vuln_file):
                    sd.vulnnbr = 0
                    return
                total = 0
                with open(vuln_file, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        v = row.get("Vulnerabilities", "").strip()
                        if v:
                            total += len([x for x in v.split("; ") if x.strip()])
                sd.vulnnbr = total
            except Exception as e:
                logger.error(f"Vuln count error: {e}")

    def _advance_animation_frame(self) -> None:
        """Drive shared_data.current_image_path through the per-status frame list."""
        now = time.time()
        if now < self._next_anim_at:
            return
        try:
            self.shared_data.update_image_randomizer()
        except Exception as e:
            logger.debug(f"animation tick error: {e}")
            return
        try:
            d_min, d_max = self.shared_data.get_effective_delays()
        except Exception:
            d_min, d_max = 1.0, 2.0
        # Sequential mode → use the min delay; random → midpoint.
        if getattr(self.shared_data, 'animation_mode', 'random') == 'sequential':
            self._next_anim_at = now + max(0.1, float(d_min))
        else:
            self._next_anim_at = now + max(0.1, (float(d_min) + float(d_max)) / 2.0)

    def _emit_changes(self) -> None:
        for field in _TRACKED_FIELDS:
            value = getattr(self.shared_data, field, None)
            if self._last.get(field, _SENTINEL) != value:
                self._last[field] = value
                broker.publish({"type": "state", "field": field, "value": value})

    # ----- lifecycle -----

    def cleanup(self) -> None:
        if self._cleaned_up:
            return
        self._cleaned_up = True
        broker.publish({"type": "display_stopped"})
        logger.info("Headless display cleaned up")


_SENTINEL = object()


def handle_exit_display(signum, frame, display_instance=None) -> None:
    logger.info("Exit signal received")
    try:
        from init_shared import shared_data
        shared_data.display_should_exit = True
        shared_data.should_exit = True
    except Exception:
        pass
    if display_instance is not None:
        try:
            if hasattr(display_instance, "cleanup"):
                display_instance.cleanup()
            elif hasattr(display_instance, "is_alive"):
                # Loki.py also passes the thread itself in some paths.
                pass
        except Exception as e:
            logger.error(f"Error during display cleanup: {e}")
    sys.exit(0)
