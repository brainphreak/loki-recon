#!/usr/bin/env python3
"""
loki-pi entry point — runs Loki on a Raspberry Pi (or any Linux box) headless.

The original pager launcher (payload.sh) is replaced by this script.
All knobs are CLI flags or LOKI_* env vars so install.sh and Docker can
configure cleanly without editing source.
"""

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
PAYLOAD_DIR = REPO_ROOT / "loki"


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="loki-pi",
        description="LAN Orchestrated Key Infiltrator — Raspberry Pi port.",
    )
    parser.add_argument(
        "--bind",
        default=os.environ.get("LOKI_BIND", "0.0.0.0"),
        help="Web UI bind address (default: 0.0.0.0, env: LOKI_BIND)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("LOKI_PORT", "8000")),
        help="Web UI port (default: 8000, env: LOKI_PORT)",
    )
    parser.add_argument(
        "--data-dir",
        default=os.environ.get(
            "LOKI_DATA_DIR",
            str(Path.home() / ".loki" / "data"),
        ),
        help="Persistent data directory (env: LOKI_DATA_DIR)",
    )
    parser.add_argument(
        "--no-web",
        action="store_true",
        help="Disable the web UI (useful for headless cron-style runs)",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        default=True,
        help="Run without LCD/buttons (always true on Pi; flag kept for clarity)",
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("LOKI_LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level (env: LOKI_LOG_LEVEL)",
    )
    args = parser.parse_args()

    # Push CLI args into the env where shared.py / logger.py / webapp.py read them.
    os.environ["LOKI_DATA_DIR"] = args.data_dir
    os.environ["LOKI_BIND"] = args.bind
    os.environ["LOKI_PORT"] = str(args.port)
    os.environ["LOKI_LOG_LEVEL"] = args.log_level
    os.environ["BJORN_WEB_UI"] = "off" if args.no_web else "on"

    # Make the payload package importable.
    sys.path.insert(0, str(PAYLOAD_DIR))
    sys.path.insert(0, str(PAYLOAD_DIR / "actions"))

    # Ensure data directory exists before any logger touches it.
    Path(args.data_dir).mkdir(parents=True, exist_ok=True)
    (Path(args.data_dir) / "logs").mkdir(parents=True, exist_ok=True)

    print(f"loki-pi starting — web UI on http://{args.bind}:{args.port}/")
    print(f"           data dir: {args.data_dir}")

    # Hand control to the original Loki.py main flow.
    os.chdir(PAYLOAD_DIR)
    runpy_target = str(PAYLOAD_DIR / "Loki.py")
    import runpy
    runpy.run_path(runpy_target, run_name="__main__")
    return 0


if __name__ == "__main__":
    sys.exit(main())
