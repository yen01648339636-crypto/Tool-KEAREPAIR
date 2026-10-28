"""Cooperative Studio pause gates at operation boundaries; batch runs are unchanged."""

import json
import os
from pathlib import Path
import threading
import time

from utils.experiment_manifest import write_json_atomic

_gate = threading.RLock()
_paused_seconds = 0.0


def paused_seconds():
    return _paused_seconds


def active_monotonic():
    return time.monotonic() - paused_seconds()


def wait_if_paused():
    location = os.environ.get("KEA_STUDIO_CONTROL")
    if not location:
        return
    path = Path(location)
    global _paused_seconds
    with _gate:
        started = None
        acknowledged = None
        try:
            while True:
                try:
                    value = json.loads(path.read_text(encoding="utf-8"))
                except FileNotFoundError:
                    return
                if value.get("cancelled"):
                    raise SystemExit("The Studio task was stopped")
                if not value.get("requested"):
                    return
                if started is None:
                    started = time.monotonic()
                if acknowledged != value["request_id"]:
                    from datetime import datetime, timezone
                    write_json_atomic(path.with_name("pause_ack.json"), {
                        "request_id": value["request_id"],
                        "execution_id": os.environ.get("KEA_STUDIO_EXECUTION_ID"),
                        "paused_at": datetime.now(timezone.utc).isoformat(),
                    })
                    acknowledged = value["request_id"]
                time.sleep(.05)
        finally:
            if started is not None:
                _paused_seconds += time.monotonic() - started
