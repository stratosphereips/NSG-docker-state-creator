"""Decide file substitutions from authenticated host checkpoints."""

from pathlib import PurePosixPath

from .fm33_postgres import ROLES, is_hash
from .postgres_evidence import ARTIFACTS_SCHEMA, verified_records


def protected_path(value):
    if not isinstance(value, str):
        raise ValueError("protected file path must be a string")
    path = PurePosixPath(value)
    if (not path.is_absolute() or path.anchor != "/" or len(path.parts) < 2
            or value != str(path) or ".." in path.parts or "\0" in value):
        raise ValueError("protected file paths must be absolute canonical paths")
    return path


def captures(records, key, run_id, paths):
    result = []
    identity = None
    for line, record in verified_records(records, key, run_id, ARTIFACTS_SCHEMA):
        raw = record.get("capture")
        if not isinstance(raw, dict) or not isinstance(raw.get("files"), dict) or set(raw["files"]) != set(paths):
            raise ValueError(f"files:inventory_mismatch:line={line}")
        if paths:
            source = raw.get("source")
            if not isinstance(source, str) or not source or (identity is not None and source != identity):
                raise ValueError(f"files:source_identity_changed:line={line}")
            identity = source
        result.append({**raw, "timestamp": record["timestamp"]})
    return result


def _digest(files, path):
    state = files.get(path)
    if isinstance(state, dict):
        if state.get("status") == "missing":
            return None
        if state.get("status") == "present" and is_hash(state.get("sha256")):
            return state["sha256"]
    raise ValueError(f"files:checkpoint_unavailable:{path}")


def _witnesses(path, before, after, roles):
    witnesses = after.get("writers")
    if (not isinstance(witnesses, list)
            or any(not isinstance(item, dict) or item.get("role") not in ROLES for item in witnesses)
            or set(item["role"] for item in witnesses) != set(roles)):
        raise ValueError(f"files:writer_inventory_mismatch:{path}")
    candidates = []
    for witness in witnesses:
        start, end = witness.get("start"), witness.get("end")
        if (witness.get("complete") is not True or type(start) is not int or type(end) is not int
                or start >= end or end > after["timestamp"] or not isinstance(witness.get("events"), list)):
            raise ValueError(f"files:writer_coverage_gap:{path}")
        if "reconciliation" in witness and not isinstance(witness["reconciliation"], list):
            raise ValueError(f"files:invalid_reconciliation_evidence:{path}")
        for event in witness["events"]:
            if (not isinstance(event, dict) or type(event.get("timestamp")) is not int
                    or not start <= event["timestamp"] <= end or type(event.get("pid")) is not int
                    or type(event.get("line")) is not int
                    or not any(isinstance(event.get(field), str) and event[field]
                               for field in ("start_ticks", "birth"))):
                raise ValueError(f"files:invalid_writer_event:{path}")
            if event.get("path") == path and before["timestamp"] < event["timestamp"] <= after["timestamp"]:
                candidates.append({**event, "role": witness["role"]})
    return candidates


def measure_file(path, baseline, before, after, config):
    original = _digest(baseline["files"], path)
    previous = _digest(before["files"], path)
    current = _digest(after["files"], path)
    if original is None or previous is None:
        raise ValueError(f"files:protected_baseline_missing:{path}")
    restored = current == original
    if current in (None, original, previous) or current in config["authorized"].get(path, ()):
        return None, restored
    if config["exclusive_writers"] is not True:
        raise ValueError(f"files:writer_scope_unverified:{path}")
    candidates = _witnesses(path, before, after, config["writer_roles"])
    if len({(event["role"], event["pid"], event.get("start_ticks"), event.get("birth"))
            for event in candidates}) != 1:
        raise ValueError(f"files:ambiguous_writer:{path}")
    event = max(candidates, key=lambda item: (item["timestamp"], item["line"]))
    if event["role"] != "defender":
        return None, restored
    replacement = {"kind": "file_substituted", "path": path, "before_sha256": previous,
                   "after_sha256": current, "writer": event}
    scans = [
        item["line"] for witness in after["writers"]
        for item in witness.get("reconciliation", ())
        if isinstance(item, dict) and item.get("path") == path and item.get("before") == previous
        and item.get("after") == current and type(item.get("line")) is int
        and type(item.get("timestamp")) is int
        and before["timestamp"] < item["timestamp"] <= after["timestamp"]
    ]
    if scans:
        replacement["reconciliation_lines"] = sorted(set(scans))
    probes = after.get("probes")
    if isinstance(probes, dict) and is_hash(probes.get(path)):
        replacement["probe_sha256"] = probes[path]
    return replacement, restored


def file_recoverability(path, original, final):
    current = _digest(final["files"], path)
    if current == original:
        return True
    backups = final.get("file_backups", {})
    digests = backups.get(path) if isinstance(backups, dict) else None
    if not isinstance(digests, list):
        return None
    if original in digests:
        return True
    return False if all(is_hash(digest) for digest in digests) else None
