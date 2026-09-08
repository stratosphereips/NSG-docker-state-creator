"""Resolve trajectory indexes into compact state/action/state transitions."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any, Iterable


def read_json(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def limited(values: Iterable[Any], maximum: int) -> list[Any]:
    result = list(values)
    return result if maximum <= 0 else result[:maximum]


def host_label(item: dict[str, Any]) -> str:
    return str(item.get("label") or next(iter(item.get("addresses", [])), item.get("id", "unknown")))


def compact_state(root: Path, state_id: str, maximum: int = 8) -> dict[str, Any]:
    state_dir = root / "states" / state_id
    manifest = read_json(state_dir / "manifest.json")
    summary = read_json(state_dir / "summary.json")
    hosts = {
        str(item.get("id")): host_label(item)
        for item in summary.get("known_hosts", []) + summary.get("controlled_hosts", [])
        if isinstance(item, dict)
    }

    networks = []
    for item in summary.get("known_networks", []):
        if not isinstance(item, dict):
            continue
        networks.append({
            "cidr": item.get("cidr"),
            "inferred": bool(item.get("inferred", False)),
            "confidence": item.get("confidence"),
        })

    data = []
    for owner, items in summary.get("known_data", {}).items():
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict):
                data.append({"host": hosts.get(owner, owner), "locator": item.get("locator")})

    services = []
    for owner, items in summary.get("known_services", {}).items():
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict):
                services.append({
                    "host": hosts.get(owner, owner), "protocol": item.get("protocol"),
                    "port": item.get("port"), "name": item.get("service_name"),
                    "status": item.get("status"),
                })

    blocks = []
    for item in summary.get("known_blocks", []):
        if isinstance(item, dict):
            blocks.append({
                "reason": item.get("reason"), "target": item.get("target_id"),
                "confidence": item.get("confidence"),
            })

    return {
        "id": state_id,
        "recorded_at": manifest.get("recorded_at"),
        "reason": manifest.get("reason"),
        "counts": summary.get("counts", {}),
        "known_networks": limited(networks, maximum),
        "known_hosts": limited((host_label(item) for item in summary.get("known_hosts", [])
                                if isinstance(item, dict)), maximum),
        "controlled_hosts": limited((host_label(item) for item in summary.get("controlled_hosts", [])
                                     if isinstance(item, dict)), maximum),
        "known_data": limited(data, maximum),
        "known_services": limited(services, maximum),
        "known_blocks": limited(blocks, maximum),
    }


def command_text(action: dict[str, Any]) -> str | None:
    command = action.get("command")
    if not isinstance(command, dict):
        return str(command) if command else None
    if command.get("shell_text"):
        return str(command["shell_text"])
    argv = command.get("argv")
    if isinstance(argv, list) and argv:
        return shlex.join(str(value) for value in argv)
    return str(command.get("executable")) if command.get("executable") else None


def compact_action(root: Path, index: dict[str, Any], maximum: int = 8) -> dict[str, Any]:
    action = read_json(root / str(index.get("record", "")))
    if not action:
        action = dict(index)
    actor = action.get("actor", {}) if isinstance(action.get("actor"), dict) else {}
    delta = read_json(root / str(action.get("delta", ""))) if action.get("delta") else {}
    delta_counts = {
        key: len(delta.get(key, []))
        for key in ("nodes_added", "nodes_removed", "nodes_changed",
                    "edges_added", "edges_removed", "edges_changed")
        if delta.get(key)
    }
    return {
        "id": action.get("id", index.get("id")),
        "type": action.get("type", index.get("action_type")),
        "scope": action.get("scope"),
        "source": action.get("source"),
        "started_at": action.get("started_at", index.get("started_at")),
        "ended_at": action.get("ended_at", index.get("ended_at")),
        "recorded_at": action.get("recorded_at"),
        "command": command_text(action),
        "actor": {key: actor.get(key) for key in
                  ("username", "uid", "pid", "host_pid", "tty", "root_command")
                  if actor.get(key) is not None},
        "targets": limited(action.get("targets", []), maximum),
        "paths": limited(action.get("paths", []), maximum),
        "effects": limited(action.get("effects", []), maximum),
        "exit_status": action.get("exit_status"),
        "completion": action.get("completion"),
        "confidence": action.get("confidence"),
        "state_changed": action.get("state_changed", index.get("state_changed", False)),
        "changed_domains": action.get("changed_domains", []),
        "delta_counts": delta_counts,
    }


def transitions(root: Path, limit: int = 10, maximum: int = 8,
                changed_only: bool = False, exclude_generic: bool = False) -> list[dict[str, Any]]:
    indexes: list[dict[str, Any]] = []
    try:
        handle = (root / "sequence.jsonl").open(encoding="utf-8", errors="replace")
    except OSError:
        return []
    with handle:
        for raw in handle:
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict) or item.get("kind") != "action":
                continue
            if changed_only and not item.get("state_changed"):
                continue
            if exclude_generic and item.get("action_type") == "generic_command":
                continue
            indexes.append(item)
    if limit > 0:
        indexes = indexes[-limit:]

    cache: dict[str, dict[str, Any]] = {}

    def state(state_id: str) -> dict[str, Any]:
        if state_id not in cache:
            cache[state_id] = compact_state(root, state_id, maximum)
        return cache[state_id]

    return [{
        "schema_version": "nsg-trajectory-transition/1.0",
        "sequence": item.get("sequence"),
        "state_before": state(str(item.get("state_before", ""))),
        "action": compact_action(root, item, maximum),
        "state_after": state(str(item.get("state_after", ""))),
    } for item in indexes]


def one_line(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def render_state(state: dict[str, Any], label: str) -> list[str]:
    return [
        f"{label} {state.get('id')} @ {state.get('recorded_at') or 'unknown'}",
        f"  counts: {one_line(state.get('counts', {}))}",
        f"  networks: {one_line(state.get('known_networks', []))}",
        f"  hosts: {one_line(state.get('known_hosts', []))}",
        f"  controlled: {one_line(state.get('controlled_hosts', []))}",
        f"  data: {one_line(state.get('known_data', []))}",
        f"  services: {one_line(state.get('known_services', []))}",
        f"  blocks: {one_line(state.get('known_blocks', []))}",
    ]


def render_text(transition: dict[str, Any]) -> str:
    action = transition["action"]
    lines = [f"=== TRANSITION sequence={transition.get('sequence')} ==="]
    lines.extend(render_state(transition["state_before"], "STATE BEFORE"))
    lines.extend([
        f"ACTION {action.get('type')} ({action.get('id')})",
        f"  time: {action.get('started_at')} -> {action.get('ended_at')}",
        f"  command: {action.get('command') or '<not available>'}",
        f"  actor: {one_line(action.get('actor', {}))}",
        f"  scope/result: {action.get('scope')} exit={action.get('exit_status')} "
        f"completion={action.get('completion')}",
        f"  targets: {one_line(action.get('targets', []))}",
        f"  paths: {one_line(action.get('paths', []))}",
        f"  effects: {one_line(action.get('effects', []))}",
        f"  state_changed: {str(bool(action.get('state_changed'))).lower()} "
        f"domains={one_line(action.get('changed_domains', []))} "
        f"delta={one_line(action.get('delta_counts', {}))}",
    ])
    lines.extend(render_state(transition["state_after"], "STATE AFTER"))
    return "\n".join(lines)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Show resolved state -> action -> state trajectory summaries"
    )
    default = Path(os.environ.get("OBS_OUTPUT_DIR", "/observation")) / "trajectory"
    parser.add_argument("--input", type=Path, default=default,
                        help="trajectory directory containing sequence.jsonl")
    parser.add_argument("--limit", type=int, default=10,
                        help="show the latest N matching actions; 0 means all")
    parser.add_argument("--max-items", type=int, default=8,
                        help="maximum entries shown for each state/action category; 0 means all")
    parser.add_argument("--changed-only", action="store_true",
                        help="show only actions that produced a new material state")
    parser.add_argument("--exclude-generic", action="store_true",
                        help="hide generic low-level process/eBPF actions")
    parser.add_argument("--format", choices=("text", "jsonl"), default="text")
    return parser.parse_args()


def main() -> int:
    args = arguments()
    values = transitions(args.input.resolve(), args.limit, args.max_items,
                         args.changed_only, args.exclude_generic)
    if not values:
        print("No matching action transitions found.", file=sys.stderr)
        return 1
    for value in values:
        print(one_line(value) if args.format == "jsonl" else render_text(value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
