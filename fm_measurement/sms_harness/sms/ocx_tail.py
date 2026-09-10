"""Real-mode S8: tail opencode SSE/HTTP event stream into ocx records.

v1 only needs schema compatibility (test mode writes scripted records in the
same schema); this module is not exercised by the no-LLM tests.
"""
import json
import os
import time
import urllib.request

from . import common

OCX_PATH = "ocx_defender.jsonl"


def _get_json(url, timeout=5):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8")), None
    except Exception as exc:  # noqa: BLE001 - probe must never raise
        return None, str(exc)


def poll_host(archive, host, ip, seen_calls, actor="defender"):
    """Poll /session and /message on <ip>:4096, emit ocx records for new
    tool_use bash events. Idempotent via `seen_calls` set of callIDs."""
    out = []
    for endpoint in ("/session", "/message"):
        data, err = _get_json("http://%s:4096%s" % (ip, endpoint))
        if data is None:
            continue
        items = data if isinstance(data, list) else data.get("messages", []) or []
        for item in items:
            if not isinstance(item, dict):
                continue
            parts = item.get("parts", [])
            for part in parts:
                if not isinstance(part, dict):
                    continue
                if part.get("type") != "tool" or item.get("tool") != "bash":
                    continue
                call_id = part.get("callID") or item.get("id")
                if not call_id or call_id in seen_calls:
                    continue
                seen_calls.add(call_id)
                rec = {
                    "ts": item.get("createdAt", time.time()) / 1000.0
                    if item.get("createdAt") else common.now(),
                    "ts_completed": common.now(),
                    "run": os.path.basename(os.path.normpath(archive)),
                    "sessionID": item.get("sessionID", ""),
                    "tool": "bash",
                    "callID": call_id,
                    "input": {"command": part.get("state", {}).get("input", "")},
                    "state": "completed",
                    "actor": actor,
                }
                common.append_jsonl(os.path.join(archive, OCX_PATH), rec)
                out.append(rec)
    return out
