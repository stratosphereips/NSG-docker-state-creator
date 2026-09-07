"""JSON Lines helpers shared by the observer collectors.

Every collector writes one JSON object per line into a file below the
observation directory (``OBS_OUTPUT_DIR``, default ``/observation``).  Each
line carries the envelope keys ``event`` (event name), ``timestamp`` (epoch
seconds) and ``source`` (collector name) merged with the event's own fields.
Values must be JSON-serializable; tuples are written as arrays.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

DEFAULT_OUTPUT_DIR = "/observation"

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off", ""}

# Filesystem subtrees the observers must never watch or hash: virtual trees,
# volatile runtime state, and the observation output itself (watching it would
# make every recorded event generate new events recursively).
_FIXED_EXCLUSIONS = ("/proc", "/sys", "/dev", "/run")


def output_dir() -> Path:
    """Return the configured observation directory."""
    return Path(os.environ.get("OBS_OUTPUT_DIR", DEFAULT_OUTPUT_DIR))


def env_bool(name: str, default: bool) -> bool:
    """Read a boolean switch from the environment.

    Accepts the usual truthy/falsy spellings (1/0, true/false, yes/no,
    on/off, case-insensitive).  Unset or unrecognized values fall back to
    ``default``.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    return default


def observer_exclusions() -> list[Path]:
    """Return resolved paths the observers must exclude from watching.

    The list combines the fixed virtual trees, the configured observation
    directory and the colon-separated ``OBS_EXCLUDE_PATHS`` entries, each
    resolved so comparisons against ``Path.resolve()`` results succeed.
    """
    raw = [output_dir(), *(Path(item) for item in _FIXED_EXCLUSIONS)]
    extra = os.environ.get("OBS_EXCLUDE_PATHS", "")
    raw.extend(Path(item) for item in extra.split(":") if item)
    excluded: list[Path] = []
    for path in raw:
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if resolved not in excluded:
            excluded.append(resolved)
    return excluded


class JsonLog:
    """Append-only JSON Lines writer for one collector stream."""

    def __init__(self, relative_path: str, source: str) -> None:
        self.path = output_dir() / relative_path
        self.source = source
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("a", encoding="utf-8")

    def write(self, event: str, **fields) -> None:
        """Append one envelope line and flush it for post-crash durability."""
        record = {
            "event": event,
            "timestamp": time.time(),
            "source": self.source,
            **fields,
        }
        self._handle.write(json.dumps(record, sort_keys=True) + "\n")
        self._handle.flush()
