"""Passive action inference and material state/action trajectory construction."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shlex
import signal
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from stategraph import StateCompiler, json_key, load_config, write_outputs


CORE_DOMAINS = (
    "known_networks", "known_hosts", "controlled_hosts",
    "known_data", "known_services", "known_blocks",
)


def utc_iso(time_ns: int) -> str:
    return datetime.fromtimestamp(time_ns / 1_000_000_000, timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def ns_from_record(record: dict[str, Any], fallback: int | None = None) -> int:
    if record.get("time_ns") is not None:
        try:
            return int(record["time_ns"])
        except (TypeError, ValueError):
            pass
    if record.get("ts") is not None:
        try:
            return int(float(record["ts"]) * 1_000_000_000)
        except (TypeError, ValueError):
            pass
    return fallback if fallback is not None else time.time_ns()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.tmp"
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, indent=2, default=str)
        handle.write("\n")
    os.replace(temporary, path)


def hash_id(prefix: str, value: str) -> str:
    return f"{prefix}:{hashlib.sha256(value.encode('utf-8', 'replace')).hexdigest()[:20]}"


def command_parts(command: str) -> tuple[str, list[str]]:
    try:
        argv = shlex.split(command)
    except ValueError:
        argv = command.split()
    return (argv[0] if argv else "", argv)


class IncrementalFiles:
    """Read complete newly appended lines and persist byte offsets."""

    def __init__(self, root: Path, cursor_path: Path):
        self.root = root
        self.cursor_path = cursor_path
        try:
            self.offsets = json.loads(cursor_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self.offsets: dict[str, int] = {}

    def lines(self, path: Path) -> Iterable[tuple[int, str]]:
        try:
            relative = str(path.relative_to(self.root))
            size = path.stat().st_size
        except OSError:
            return
        offset = int(self.offsets.get(relative, 0))
        if size < offset:
            offset = 0
        try:
            handle = path.open("rb")
        except OSError:
            return
        with handle:
            handle.seek(offset)
            while True:
                line_offset = handle.tell()
                raw = handle.readline()
                if not raw:
                    break
                if not raw.endswith(b"\n"):
                    handle.seek(line_offset)
                    break
                offset = handle.tell()
                yield line_offset, raw.decode("utf-8", "replace").rstrip("\n")
        self.offsets[relative] = offset

    def save(self) -> None:
        atomic_json(self.cursor_path, self.offsets)


class TrajectoryStore:
    def __init__(self, input_dir: Path, output_dir: Path, level: str,
                 config_path: Path | None, sensitivity: str):
        self.input = input_dir
        self.output = output_dir
        self.level = level
        self.config_path = config_path
        self.config = load_config(config_path)
        self.settings = self.config["trajectory"]
        self.sensitivity = sensitivity
        self.output.mkdir(parents=True, exist_ok=True)
        for name in ("actions", "actors", "deltas", "states"):
            (self.output / name).mkdir(exist_ok=True)
        self.sequence_path = self.output / "sequence.jsonl"
        self.current_state: dict[str, Any] | None = None
        self.current_graph: dict[str, Any] | None = None
        self.state_number = 0
        self.action_ids: set[str] = set()
        self._recover()
        if self.current_state is None:
            graph = StateCompiler(self.input, self.level, self.config_path).compile()
            self.current_state = self._write_state(graph, [], "initial")
            self.current_graph = graph
            self._append_sequence(self._state_sequence(self.current_state))

    def _recover(self) -> None:
        if not self.sequence_path.exists():
            return
        try:
            lines = self.sequence_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return
        for raw in lines:
            try:
                record = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if record.get("kind") == "action":
                self.action_ids.add(str(record.get("id")))
            elif record.get("kind") == "state":
                state_id = str(record.get("id", ""))
                match = re.search(r"(\d+)$", state_id)
                if match:
                    self.state_number = max(self.state_number, int(match.group(1)))
                manifest_path = self.output / str(record.get("manifest", ""))
                graph_path = self.output / str(record.get("graph", ""))
                try:
                    self.current_state = json.loads(manifest_path.read_text(encoding="utf-8"))
                    self.current_graph = json.loads(graph_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    pass

    def _append_sequence(self, record: dict[str, Any]) -> None:
        with self.sequence_path.open("a", encoding="utf-8", buffering=1) as handle:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")

    def _normalized(self, value: Any) -> Any:
        ignored = set(self.settings.get("ignore_fields", []))
        bucket = float(self.settings.get("confidence_bucket", 0.1))
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if key in ignored or key == "counts":
                    continue
                if key == "confidence" and isinstance(item, (int, float)) and bucket > 0:
                    item = round(round(float(item) / bucket) * bucket, 6)
                result[key] = self._normalized(item)
            return result
        if isinstance(value, list):
            normalized = [self._normalized(item) for item in value]
            return sorted(normalized, key=json_key)
        return value

    def semantic_projection(self, graph: dict[str, Any]) -> dict[str, Any]:
        summary = graph["summary"]
        domains = self.settings.get("watched_domains", list(CORE_DOMAINS))
        if self.sensitivity == "critical":
            domains = self.settings.get("critical_domains", domains)
        return {domain: self._normalized(summary.get(domain, {})) for domain in domains}

    def semantic_hash(self, graph: dict[str, Any]) -> str:
        return hashlib.sha256(json_key(self.semantic_projection(graph)).encode()).hexdigest()

    def _write_state(self, graph: dict[str, Any], trigger_actions: list[str], reason: str,
                     forced_number: int | None = None) -> dict[str, Any]:
        if forced_number is None:
            number = self.state_number
        else:
            number = forced_number
        state_id = f"state-{number:06d}"
        state_dir = self.output / "states" / state_id
        write_outputs(graph, state_dir)
        recorded_ns = time.time_ns()
        manifest = {
            "schema_version": "nsg-trajectory-state/1.0",
            "id": state_id,
            "detail_level": self.level,
            "snapshot_policy": self.sensitivity,
            "reason": reason,
            "trigger_action_ids": trigger_actions,
            "event_time_cutoff_ns": recorded_ns,
            "event_time_cutoff": utc_iso(recorded_ns),
            "recorded_time_ns": recorded_ns,
            "recorded_at": utc_iso(recorded_ns),
            "semantic_sha256": self.semantic_hash(graph),
            "graph_sha256": hashlib.sha256(json_key(graph).encode()).hexdigest(),
            "graph": f"states/{state_id}/graph.json",
            "summary": f"states/{state_id}/summary.json",
            "embedding": f"states/{state_id}/embedding.jsonl",
        }
        atomic_json(state_dir / "manifest.json", manifest)
        atomic_json(self.output / "current.json", manifest)
        return manifest

    def _state_sequence(self, state: dict[str, Any]) -> dict[str, Any]:
        return {
            "sequence": self._next_sequence(), "kind": "state", "id": state["id"],
            "recorded_at": state["recorded_at"], "recorded_time_ns": state["recorded_time_ns"],
            "reason": state["reason"], "trigger_action_ids": state["trigger_action_ids"],
            "manifest": f"states/{state['id']}/manifest.json", "graph": state["graph"],
        }

    def _next_sequence(self) -> int:
        if not self.sequence_path.exists():
            return 0
        last = -1
        try:
            with self.sequence_path.open(encoding="utf-8", errors="replace") as handle:
                for raw in handle:
                    try:
                        last = max(last, int(json.loads(raw).get("sequence", -1)))
                    except (json.JSONDecodeError, TypeError, ValueError):
                        continue
        except OSError:
            pass
        return last + 1

    def _delta(self, before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
        before_nodes = {item["id"]: item for item in before.get("nodes", [])}
        after_nodes = {item["id"]: item for item in after.get("nodes", [])}
        before_edges = {item["id"]: item for item in before.get("edges", [])}
        after_edges = {item["id"]: item for item in after.get("edges", [])}
        changed_nodes = sorted(
            key for key in before_nodes.keys() & after_nodes.keys()
            if self._normalized(before_nodes[key]) != self._normalized(after_nodes[key])
        )
        changed_edges = sorted(
            key for key in before_edges.keys() & after_edges.keys()
            if self._normalized(before_edges[key]) != self._normalized(after_edges[key])
        )
        before_projection = self.semantic_projection(before)
        after_projection = self.semantic_projection(after)
        changed_domains = sorted(
            key for key in set(before_projection) | set(after_projection)
            if before_projection.get(key) != after_projection.get(key)
        )
        return {
            "nodes_added": sorted(after_nodes.keys() - before_nodes.keys()),
            "nodes_removed": sorted(before_nodes.keys() - after_nodes.keys()),
            "nodes_changed": changed_nodes,
            "edges_added": sorted(after_edges.keys() - before_edges.keys()),
            "edges_removed": sorted(before_edges.keys() - after_edges.keys()),
            "edges_changed": changed_edges,
            "changed_domains": changed_domains,
        }

    def commit_actions(self, actions: list[dict[str, Any]]) -> None:
        actions = [item for item in actions if item["id"] not in self.action_ids]
        if not actions:
            return
        actions.sort(key=lambda item: (item["ended_time_ns"], item["started_time_ns"], item["id"]))
        before_graph = self.current_graph
        assert before_graph is not None and self.current_state is not None
        candidate = StateCompiler(self.input, self.level, self.config_path).compile()
        changed = self.semantic_hash(candidate) != self.current_state["semantic_sha256"]
        if self.sensitivity == "always":
            changed = True
        next_state = self.current_state
        delta = self._delta(before_graph, candidate)
        if changed:
            self.state_number += 1
            next_state = self._write_state(candidate, [item["id"] for item in actions],
                                           "material-action-change", self.state_number)

        intervals = [(item["id"], item["started_time_ns"], item["ended_time_ns"])
                     for item in actions]
        for action in actions:
            concurrent = sorted(action_id for action_id, started, ended in intervals
                                if action_id != action["id"]
                                and started <= action["ended_time_ns"]
                                and ended >= action["started_time_ns"])
            action["concurrent_action_ids"] = sorted(set(action.get("concurrent_action_ids", []))
                                                      | set(concurrent))
            action["state_before"] = action.get("state_before") or self.current_state["id"]
            action["state_after"] = next_state["id"]
            action["state_changed"] = next_state["id"] != action["state_before"]
            action["changed_domains"] = delta["changed_domains"] if changed else []
            action["recorded_time_ns"] = time.time_ns()
            action["recorded_at"] = utc_iso(action["recorded_time_ns"])
            filename = hashlib.sha256(action["id"].encode()).hexdigest()[:24] + ".json"
            relative = f"actions/{filename}"
            action["record"] = relative
            if changed:
                delta_record = {
                    "schema_version": "nsg-trajectory-delta/1.0",
                    "action_id": action["id"],
                    "state_before": action["state_before"],
                    "state_after": next_state["id"],
                    "causal_isolation": not bool(action["concurrent_action_ids"]),
                    "contributing_action_ids": [item["id"] for item in actions],
                    **delta,
                }
                delta_name = hashlib.sha256(action["id"].encode()).hexdigest()[:24] + ".json"
                atomic_json(self.output / "deltas" / delta_name, delta_record)
                action["delta"] = f"deltas/{delta_name}"
            atomic_json(self.output / relative, action)
            self._append_sequence({
                "sequence": self._next_sequence(), "kind": "action", "id": action["id"],
                "actor_id": action["actor_id"], "action_type": action["type"],
                "started_at": action["started_at"], "ended_at": action["ended_at"],
                "state_before": action["state_before"], "state_after": action["state_after"],
                "state_changed": action["state_changed"], "record": relative,
            })
            self.action_ids.add(action["id"])
            actor_name = hashlib.sha256(action["actor_id"].encode()).hexdigest()[:20] + ".jsonl"
            with (self.output / "actors" / actor_name).open("a", encoding="utf-8", buffering=1) as handle:
                handle.write(json.dumps({
                    "id": action["id"], "record": relative,
                    "started_at": action["started_at"], "ended_at": action["ended_at"],
                    "state_before": action["state_before"], "state_after": action["state_after"],
                }, sort_keys=True, separators=(",", ":")) + "\n")
        if changed:
            self.current_graph = candidate
            self.current_state = next_state
            self._append_sequence(self._state_sequence(next_state))


class PassiveTrajectoryMonitor:
    def __init__(self, input_dir: Path, output_dir: Path, level: str = "operational",
                 config_path: Path | None = None, sensitivity: str = "material"):
        self.input = input_dir.resolve()
        self.output = output_dir.resolve()
        self.config = load_config(config_path)
        if sensitivity not in {"always", "material", "critical"}:
            raise ValueError("sensitivity must be always, material, or critical")
        self.store = TrajectoryStore(self.input, self.output, level, config_path, sensitivity)
        self.settings = self.config["trajectory"]
        self.reader = IncrementalFiles(self.input, self.output / "runtime-cursor.json")
        self.processes: dict[int, dict[str, Any]] = {}
        self.host_to_pid: dict[int, int] = {}
        self.have_host_pid_mapping = False
        self.observer_pids: set[int] = set()
        self.observer_host_pids: set[int] = set()
        self.actor_pids: dict[int, str] = {}
        self.process_action: dict[int, str] = {}
        self.pending: dict[str, dict[str, Any]] = {}
        self.shell_actions: dict[int, str] = {}
        self.inferred_actions: dict[tuple[int, str], str] = {}
        self.completed: list[dict[str, Any]] = []
        self.seen_commands: list[tuple[int, str]] = []
        observer_pattern = self.config["observer_process_regex"]
        self.observer_re = re.compile(observer_pattern, re.IGNORECASE)
        self.rules = [(re.compile(item["regex"], re.IGNORECASE), item)
                      for item in self.settings.get("command_rules", [])]
        self.stopping = False

    def _classify(self, command: str) -> tuple[str, str]:
        for pattern, rule in self.rules:
            if pattern.search(command):
                return str(rule["type"]), str(rule["scope"])
        return "generic_command", "unknown"

    def _targets(self, command: str, scope: str) -> tuple[list[str], list[str]]:
        _executable, argv = command_parts(command)
        targets: set[str] = set()
        paths: set[str] = set()
        for token in argv[1:]:
            candidate = token.strip("[](),;'\"")
            if candidate.startswith(("http://", "https://")):
                parsed = urlsplit(candidate)
                if parsed.hostname:
                    targets.add(parsed.hostname)
                continue
            remote = candidate.rsplit("@", 1)[-1]
            if ":" in remote and not remote.startswith("/"):
                possible_host = remote.split(":", 1)[0]
            else:
                possible_host = remote
            try:
                if "/" in possible_host:
                    targets.add(str(ipaddress.ip_network(possible_host, strict=False)))
                else:
                    targets.add(str(ipaddress.ip_address(possible_host)))
                continue
            except ValueError:
                pass
            if candidate.startswith("/"):
                paths.add(candidate)
            elif scope == "network" and re.fullmatch(
                r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",
                possible_host,
            ):
                targets.add(possible_host.lower())
        return sorted(targets), sorted(paths)

    def _actor(self, pid: int, record: dict[str, Any] | None = None) -> tuple[str, dict[str, Any]]:
        info = record or self.processes.get(pid, {})
        tty = str(info.get("tty") or info.get("tty_nr") or "")
        if tty and tty not in {"0", ""}:
            actor_id = hash_id("actor:tty", f"{tty}\0{pid}")
        else:
            start = str(info.get("start_ticks", "unknown"))
            actor_id = hash_id("actor:process", f"{pid}\0{start}")
        actor = {
            "pid": pid,
            "host_pid": info.get("host_pid"),
            "uid": info.get("uid"),
            "username": info.get("username"),
            "loginuid": info.get("loginuid"),
            "sessionid": info.get("sessionid"),
            "tty": info.get("tty", info.get("tty_nr")),
            "root_command": info.get("cmdline"),
        }
        return actor_id, actor

    def _new_action(self, action_id: str, source: str, confidence: float, command: str,
                    actor_pid: int, start_ns: int, evidence: dict[str, Any],
                    actor_record: dict[str, Any] | None = None) -> dict[str, Any]:
        action_type, scope = self._classify(command)
        executable, argv = command_parts(command)
        targets, paths = self._targets(command, scope)
        actor_id, actor = self._actor(actor_pid, actor_record)
        detected_ns = time.time_ns()
        return {
            "schema_version": "nsg-action/1.0",
            "id": action_id,
            "actor_id": actor_id,
            "type": action_type,
            "scope": scope,
            "source": source,
            "confidence": confidence,
            "command": {"executable": executable, "argv": argv, "shell_text": command},
            "actor": actor,
            "targets": targets,
            "paths": paths,
            "child_processes": [],
            "effects": [],
            "evidence": [evidence],
            "started_time_ns": start_ns,
            "started_at": utc_iso(start_ns),
            "detected_time_ns": detected_ns,
            "detected_at": utc_iso(detected_ns),
            "state_before": self.store.current_state["id"] if self.store.current_state else None,
            "last_activity_ns": start_ns,
        }

    def _finish(self, action_id: str, end_ns: int, exit_status: int | None = None,
                completion: str = "observed") -> None:
        action = self.pending.get(action_id)
        if not action or action_id in self.store.action_ids:
            return
        concurrent = {
            other_id for other_id, other in self.pending.items()
            if other_id != action_id and other["started_time_ns"] <= end_ns
        }
        action["concurrent_action_ids"] = sorted(
            set(action.get("concurrent_action_ids", [])) | concurrent
        )
        self.pending.pop(action_id, None)
        action["ended_time_ns"] = max(end_ns, action["started_time_ns"])
        action["ended_at"] = utc_iso(action["ended_time_ns"])
        action["duration_seconds"] = round(
            (action["ended_time_ns"] - action["started_time_ns"]) / 1_000_000_000, 9
        )
        action["exit_status"] = exit_status
        action["completion"] = completion
        action.pop("last_activity_ns", None)
        self.completed.append(action)
        for pid, pending_id in list(self.process_action.items()):
            if pending_id == action_id:
                del self.process_action[pid]
        for pid, pending_id in list(self.shell_actions.items()):
            if pending_id == action_id:
                del self.shell_actions[pid]
        for key, pending_id in list(self.inferred_actions.items()):
            if pending_id == action_id:
                del self.inferred_actions[key]

    def _json_records(self, path: Path) -> Iterable[tuple[int, dict[str, Any]]]:
        for offset, raw in self.reader.lines(path):
            try:
                record = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                yield offset, record

    def _poll_commands(self) -> None:
        tty = self.input / "tty"
        if not tty.exists():
            return
        for path in sorted(tty.glob("commands*.jsonl")):
            relative = str(path.relative_to(self.input))
            for offset, record in self._json_records(path):
                event = record.get("event")
                action_id = str(record.get("action_id") or hash_id(
                    "action:bash", f"{relative}\0{record.get('pid')}\0{record.get('sequence')}"
                ))
                pid = int(record.get("pid", -1))
                timestamp = ns_from_record(record)
                evidence = {"source": relative, "offset": offset, "event": event}
                if event == "action_started":
                    if action_id in self.store.action_ids or action_id in self.pending:
                        continue
                    action = self._new_action(action_id, "bash-command", 0.995,
                                              str(record.get("command", "")), pid,
                                              timestamp, evidence, record)
                    self.pending[action_id] = action
                    self.shell_actions[pid] = action_id
                elif event == "command_completed":
                    if action_id not in self.pending and action_id not in self.store.action_ids:
                        self.pending[action_id] = self._new_action(
                            action_id, "bash-command-completion", 0.98,
                            str(record.get("command", "")), pid, timestamp, evidence, record
                        )
                    if action_id in self.pending:
                        self.pending[action_id]["evidence"].append(evidence)
                        try:
                            status = int(record.get("exit_status"))
                        except (TypeError, ValueError):
                            status = None
                        self._finish(action_id, timestamp, status, "shell-prompt")

    def _is_observer(self, command: str) -> bool:
        return bool(self.observer_re.search(command))

    def _ancestor_actor(self, pid: int) -> tuple[int | None, str | None]:
        visited: set[int] = set()
        current = pid
        while current > 0 and current not in visited:
            visited.add(current)
            if current in self.actor_pids:
                return current, self.actor_pids[current]
            info = self.processes.get(current)
            if not info:
                break
            current = int(info.get("ppid", 0) or 0)
        return None, None

    def _action_for_pid(self, pid: int) -> dict[str, Any] | None:
        visited: set[int] = set()
        current = pid
        while current > 0 and current not in visited:
            visited.add(current)
            action_id = self.process_action.get(current) or self.shell_actions.get(current)
            if action_id and action_id in self.pending:
                return self.pending[action_id]
            info = self.processes.get(current)
            if not info:
                break
            current = int(info.get("ppid", 0) or 0)
        return None

    def _root_actor(self, record: dict[str, Any]) -> bool:
        pid = int(record.get("pid", -1))
        ppid = int(record.get("ppid", 0) or 0)
        name = str(record.get("name", ""))
        tty = str(record.get("tty_nr", "0"))
        if name in {"bash", "sh", "zsh", "fish"} and tty not in {"", "0"}:
            return True
        if ppid in {0, 1}:
            return True
        parent = self.processes.get(ppid)
        if parent and self._is_observer(str(parent.get("cmdline", ""))):
            return str(parent.get("name", "")) in {"strace", "python3", "observe-entrypoint"}
        return pid == 1

    def _poll_processes(self) -> None:
        path = self.input / "processes.jsonl"
        if not path.exists():
            return
        relative = str(path.relative_to(self.input))
        for offset, record in self._json_records(path):
            event = record.get("event")
            if event not in {"process_seen", "process_changed", "process_gone"}:
                continue
            pid = int(record.get("pid", -1))
            timestamp = ns_from_record(record)
            evidence = {"source": relative, "offset": offset, "event": event, "pid": pid}
            if event in {"process_seen", "process_changed"}:
                previous = self.processes.get(pid, {})
                info = {**previous, **record}
                self.processes[pid] = info
                host_pid = int(info.get("host_pid", pid) or pid)
                self.host_to_pid[host_pid] = pid
                if info.get("namespace_pids"):
                    self.have_host_pid_mapping = True
                command = str(info.get("cmdline", ""))
                if self._is_observer(command):
                    self.observer_pids.add(pid)
                    self.observer_host_pids.add(host_pid)
                    continue
                fingerprint = " ".join(command_parts(command)[1])
                self.seen_commands.append((timestamp, fingerprint))
                self.seen_commands = self.seen_commands[-5000:]
                if self._root_actor(info):
                    actor_id, _actor = self._actor(pid, info)
                    self.actor_pids[pid] = actor_id
                    continue
                actor_pid, actor_id = self._ancestor_actor(int(info.get("ppid", 0) or 0))
                if actor_pid is None or actor_id is None:
                    continue
                parent_action = self._action_for_pid(int(info.get("ppid", 0) or 0))
                child = {
                    "pid": pid, "host_pid": host_pid, "ppid": info.get("ppid"),
                    "command": command, "started_at": utc_iso(timestamp),
                }
                if parent_action:
                    if child not in parent_action["child_processes"]:
                        parent_action["child_processes"].append(child)
                    self.process_action[pid] = parent_action["id"]
                    continue
                action_id = hash_id("action:process", f"{pid}\0{info.get('start_ticks')}\0{command}")
                if action_id in self.store.action_ids or action_id in self.pending:
                    continue
                action = self._new_action(action_id, "process-lifecycle", 0.94, command,
                                          actor_pid, timestamp, evidence,
                                          self.processes.get(actor_pid))
                action["process"] = child
                self.pending[action_id] = action
                self.process_action[pid] = action_id
            else:
                info = self.processes.get(pid, record)
                action_id = self.process_action.get(pid)
                if action_id:
                    action = self.pending.get(action_id)
                    if action:
                        action["process_exit_observed_ns"] = timestamp
                        action["last_activity_ns"] = max(action["last_activity_ns"], timestamp)
                if pid in self.actor_pids:
                    for shell_pid, shell_action in list(self.shell_actions.items()):
                        if shell_pid == pid:
                            self._finish(shell_action, timestamp, None, "shell-exited")
                    del self.actor_pids[pid]
                host_pid = int(info.get("host_pid", pid) or pid)
                self.host_to_pid.pop(host_pid, None)

    def _inferred(self, pid: int, kind: str, timestamp: int, detail: dict[str, Any],
                  evidence: dict[str, Any]) -> None:
        attached = self._action_for_pid(pid)
        if attached:
            attached["effects"].append(detail)
            attached["evidence"].append(evidence)
            attached["last_activity_ns"] = max(attached["last_activity_ns"], timestamp)
            if detail.get("target") and detail["target"] not in attached["targets"]:
                attached["targets"].append(detail["target"])
            if detail.get("path") and detail["path"] not in attached["paths"]:
                attached["paths"].append(detail["path"])
            return
        key = (pid, kind)
        action_id = self.inferred_actions.get(key)
        if not action_id or action_id not in self.pending:
            info = self.processes.get(pid, {})
            actor_pid, _actor_id = self._ancestor_actor(pid)
            actor_pid = actor_pid if actor_pid is not None else pid
            command = str(info.get("cmdline") or f"in-process {kind} activity by pid {pid}")
            action_id = hash_id("action:inferred", f"{pid}\0{kind}\0{timestamp}")
            action = self._new_action(action_id, f"syscall-{kind}-inference", 0.75,
                                      command, actor_pid, timestamp, evidence,
                                      self.processes.get(actor_pid))
            action["type"] = "network_activity" if kind == "network" else "file_activity"
            action["scope"] = "network" if kind == "network" else "local"
            action["inference"] = True
            self.pending[action_id] = action
            self.inferred_actions[key] = action_id
        action = self.pending[action_id]
        action["last_activity_ns"] = max(action["last_activity_ns"], timestamp)
        action["effects"].append(detail)
        if detail.get("target") and detail["target"] not in action["targets"]:
            action["targets"].append(detail["target"])
        if detail.get("path") and detail["path"] not in action["paths"]:
            action["paths"].append(detail["path"])

    def _poll_syscalls(self) -> None:
        directory = self.input / "syscalls"
        if not directory.exists():
            return
        connect_v4 = re.compile(r'sin_port=htons\((\d+)\).*?sin_addr=inet_addr\("([^"]+)"\)')
        connect_v6 = re.compile(r'sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6, "([^"]+)"')
        mutation = re.compile(
            r"^[0-9.]+ (rename|renameat|renameat2|unlink|unlinkat|mkdir|mkdirat|rmdir|chmod|fchmodat|chown|truncate)\(.*?\"((?:\\.|[^\"\\])*)\""
        )
        write_open = re.compile(
            r"^[0-9.]+ (?:open|openat|openat2)\(.*?\"((?:\\.|[^\"\\])*)\".*?"
            r"(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)"
        )
        process_exit = re.compile(r"^[0-9.]+ \+\+\+ exited with (\d+) \+\+\+")
        for path in sorted(directory.glob("trace.*")):
            try:
                pid = int(path.name.rsplit(".", 1)[-1])
            except ValueError:
                continue
            relative = str(path.relative_to(self.input))
            for offset, line in self.reader.lines(path):
                try:
                    timestamp = int(float(line.split(" ", 1)[0]) * 1_000_000_000)
                except (ValueError, IndexError):
                    timestamp = time.time_ns()
                evidence = {"source": relative, "offset": offset, "event": "syscall", "pid": pid}
                exit_match = process_exit.search(line)
                if exit_match:
                    action_id = self.process_action.get(pid)
                    action = self.pending.get(action_id) if action_id else None
                    if action and action.get("source") == "process-lifecycle" \
                            and action.get("process", {}).get("pid") == pid:
                        self._finish(action_id, timestamp, int(exit_match.group(1)), "strace-exit")
                    continue
                if " connect(" in line and "AF_UNIX" not in line:
                    match = connect_v4.search(line) or connect_v6.search(line)
                    if match:
                        port, address = int(match.group(1)), match.group(2)
                        self._inferred(pid, "network", timestamp, {
                            "kind": "connect", "target": address, "port": port,
                            "result": line.split(" = ", 1)[-1].split(" <", 1)[0],
                        }, evidence)
                match = mutation.search(line)
                if match:
                    operation, raw_path = match.groups()
                    try:
                        locator = json.loads(f'"{raw_path}"')
                    except json.JSONDecodeError:
                        locator = raw_path
                    self._inferred(pid, "file", timestamp, {
                        "kind": "file-mutation", "operation": operation, "path": locator,
                        "result": line.split(" = ", 1)[-1].split(" <", 1)[0],
                    }, evidence)
                    continue
                open_match = write_open.search(line)
                if open_match:
                    raw_path, flag = open_match.groups()
                    try:
                        locator = json.loads(f'"{raw_path}"')
                    except json.JSONDecodeError:
                        locator = raw_path
                    self._inferred(pid, "file", timestamp, {
                        "kind": "file-write-open", "operation": flag, "path": locator,
                        "result": line.split(" = ", 1)[-1].split(" <", 1)[0],
                    }, evidence)

    def _poll_bcc_exec(self) -> None:
        path = self.input / "bcc" / "execsnoop.log"
        # BCC reports host namespace PIDs.  Only use it as an exec fallback
        # after the process collector has supplied NSpid mappings; otherwise
        # observer processes cannot be separated reliably from workload
        # processes.  This also prevents noisy guesses when replaying logs
        # produced by an older collector without host_pid fields.
        if (not self.settings.get("use_bcc_exec_fallback", True)
                or not self.have_host_pid_mapping or not path.exists()):
            return
        relative = str(path.relative_to(self.input))
        pattern = re.compile(r"^(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(-?\d+)\s+(.*)$")
        for offset, line in self.reader.lines(path):
            match = pattern.match(line.strip())
            if not match:
                continue
            _clock, uid, process, host_pid_text, host_ppid_text, result, args = match.groups()
            if result != "0" or self._is_observer(args):
                continue
            host_pid, host_ppid = int(host_pid_text), int(host_ppid_text)
            if (host_pid in self.host_to_pid or host_ppid in self.observer_host_pids):
                continue
            fingerprint = " ".join(command_parts(args)[1])
            now = time.time_ns()
            if any(fingerprint == seen for _seen_ns, seen in self.seen_commands[-1000:]):
                continue
            container_parent = self.host_to_pid.get(host_ppid)
            if container_parent is not None:
                attached = self._action_for_pid(container_parent)
                if attached:
                    attached["child_processes"].append({
                        "host_pid": host_pid, "host_ppid": host_ppid, "command": args,
                        "source": "ebpf-exec",
                    })
                    continue
            actor_pid = container_parent if container_parent is not None else host_ppid
            action_id = hash_id("action:ebpf", f"{host_pid}\0{args}")
            if action_id in self.pending or action_id in self.store.action_ids:
                continue
            evidence = {"source": relative, "offset": offset, "event": "exec", "host_pid": host_pid}
            action = self._new_action(action_id, "ebpf-exec-fallback", 0.8, args,
                                      actor_pid, now, evidence,
                                      self.processes.get(actor_pid))
            action["process"] = {"host_pid": host_pid, "host_ppid": host_ppid,
                                 "uid": int(uid), "name": process}
            self.pending[action_id] = action
            action["last_activity_ns"] = now

    def _expire(self, force: bool = False) -> None:
        now = time.time_ns()
        idle = int(float(self.settings.get("inferred_idle_seconds", 1.0)) * 1_000_000_000)
        maximum = int(float(self.settings.get("maximum_action_seconds", 3600)) * 1_000_000_000)
        for action_id, action in list(self.pending.items()):
            age = now - action["started_time_ns"]
            inactive = now - action.get("last_activity_ns", action["started_time_ns"])
            inferred = action.get("inference") or action["source"] == "ebpf-exec-fallback"
            process_gone = action.get("process_exit_observed_ns") is not None and inactive >= 250_000_000
            if force or age >= maximum or process_gone or (inferred and inactive >= idle):
                completion = "monitor-shutdown" if force else "process-exit-observed" if process_gone \
                    else "idle-window" if inferred else "maximum-duration"
                end_ns = now
                if process_gone:
                    end_ns = int(action["process_exit_observed_ns"])
                elif force and (inferred or action["source"] == "process-lifecycle"):
                    end_ns = int(action.get("last_activity_ns", now))
                self._finish(action_id, end_ns, None, completion)

    def poll(self) -> None:
        # Shell events come first so child process observations attach to the
        # complete typed command instead of becoming duplicate actions.
        self._poll_commands()
        self._poll_processes()
        self._poll_syscalls()
        self._poll_bcc_exec()
        self._expire()
        self.reader.save()

    def flush_completed(self, force: bool = False) -> None:
        if force:
            self._expire(True)
        if not self.completed:
            return
        if not force:
            settle = float(os.environ.get(
                "OBS_TRAJECTORY_SETTLE_SECONDS", self.settings.get("settle_seconds", 2.0)
            ))
            newest = max(item["ended_time_ns"] for item in self.completed)
            oldest = min(item["ended_time_ns"] for item in self.completed)
            maximum_batch = float(self.settings.get("maximum_batch_seconds", 5.0))
            if (time.time_ns() - newest < int(settle * 1_000_000_000)
                    and time.time_ns() - oldest < int(maximum_batch * 1_000_000_000)):
                return
        batch, self.completed = self.completed, []
        self.store.commit_actions(batch)

    def run(self, once: bool = False) -> None:
        def stop(_signum: int, _frame: Any) -> None:
            self.stopping = True

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        interval = float(os.environ.get(
            "OBS_TRAJECTORY_POLL_INTERVAL", self.settings.get("poll_interval_seconds", 0.2)
        ))
        while True:
            self.poll()
            self.flush_completed(force=once or self.stopping)
            if once or self.stopping:
                return
            time.sleep(interval)
