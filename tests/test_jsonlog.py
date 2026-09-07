"""Smoke for the shared observer/lib/jsonlog.py library.

Run with: python3.12 -m pytest tests/test_jsonlog.py -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "observer" / "lib"))

from jsonlog import JsonLog, env_bool, observer_exclusions  # noqa: E402


def test_jsonlog_writes_envelope_lines(tmp_path, monkeypatch):
    monkeypatch.setenv("OBS_OUTPUT_DIR", str(tmp_path))
    log = JsonLog("files/events.jsonl", "filesystem-monitor")
    log.write("monitor_started", roots=["/etc"], command=["inotifywait"])
    log.write("filesystem_event", kernel_time="1757000000",
              path="/tmp/x", operations=["create"], move_cookie="0")

    lines = (tmp_path / "files" / "events.jsonl").read_text(
        encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["event"] == "monitor_started"
    assert first["source"] == "filesystem-monitor"
    assert isinstance(first["timestamp"], float)
    assert first["roots"] == ["/etc"]
    second = json.loads(lines[1])
    assert second["operations"] == ["create"]


def test_env_bool_parsing(monkeypatch):
    monkeypatch.delenv("OBS_MISSING", raising=False)
    assert env_bool("OBS_MISSING", True) is True
    assert env_bool("OBS_MISSING", False) is False
    for true_value in ("1", "true", "YES", "On"):
        monkeypatch.setenv("OBS_FLAG", true_value)
        assert env_bool("OBS_FLAG", False) is True
    for false_value in ("0", "false", "NO", "off", ""):
        monkeypatch.setenv("OBS_FLAG", false_value)
        assert env_bool("OBS_FLAG", True) is False
    monkeypatch.setenv("OBS_FLAG", "maybe")
    assert env_bool("OBS_FLAG", True) is True


def test_observer_exclusions(tmp_path, monkeypatch):
    monkeypatch.setenv("OBS_OUTPUT_DIR", str(tmp_path / "observation"))
    monkeypatch.setenv("OBS_EXCLUDE_PATHS", f"/srv/data:{tmp_path}/extra")
    excluded = observer_exclusions()
    assert Path("/proc") in excluded and Path("/sys") in excluded
    assert Path("/dev") in excluded and Path("/run") in excluded
    assert (tmp_path / "observation").resolve() in excluded
    assert (tmp_path / "extra").resolve() in excluded
    assert Path("/srv/data").resolve() in excluded
    # observation self-exclusion is what keeps inotify/reconciliation from
    # seeing evidence edits (declared residual in the trust model)
    assert len(excluded) == len(set(excluded))
