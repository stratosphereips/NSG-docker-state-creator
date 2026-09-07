"""Small, dependency-free JSON Lines writer shared by observer processes."""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from pathlib import Path
from typing import Any


class JsonLog:
    def __init__(self, filename: str, source: str):
        output = Path(os.environ.get("OBS_OUTPUT_DIR", "/observation"))
        output.mkdir(parents=True, exist_ok=True)
        self.path = output / filename
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.source = source
        self.hostname = socket.gethostname()
        self._lock = threading.Lock()

    def write(self, event: str, **fields: Any) -> None:
        record = {
            "ts": time.time_ns() / 1_000_000_000,
            "time_ns": time.time_ns(),
            "source": self.source,
            "event": event,
            "container_hostname": self.hostname,
            **fields,
        }
        line = json.dumps(record, separators=(",", ":"), sort_keys=True, default=str)
        with self._lock:
            with self.path.open("a", encoding="utf-8", buffering=1) as handle:
                handle.write(line + "\n")


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def observer_exclusions() -> list[Path]:
    configured = os.environ.get("OBS_EXCLUDE_PATHS", "")
    output = os.environ.get("OBS_OUTPUT_DIR", "/observation")
    defaults = [output, "/proc", "/sys", "/dev", "/run"]
    return [Path(item).resolve() for item in defaults + configured.split(":") if item]
