"""Compile NSG observation artifacts into a confidence-bearing state graph."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shlex
import signal
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit


DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "etc" / "state-graph.json"
AGENT_ID = "agent:observed"
LOCAL_HOST_ID = "host:local"
SESSION_ID = "observation:session"


def deep_update(base: dict[str, Any], update: dict[str, Any]) -> dict[str, Any]:
    for key, value in update.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_update(base[key], value)
        else:
            base[key] = value
    return base


def load_config(path: Path | None = None) -> dict[str, Any]:
    with DEFAULT_CONFIG.open(encoding="utf-8") as handle:
        result = json.load(handle)
    if path and path.resolve() != DEFAULT_CONFIG.resolve():
        with path.open(encoding="utf-8") as handle:
            deep_update(result, json.load(handle))
    return result


def stable_id(kind: str, key: str) -> str:
    digest = hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:20]
    return f"{kind}:{digest}"


def json_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def merge_value(old: Any, new: Any) -> Any:
    if new is None or new == "":
        return old
    if old is None or old == "":
        return new
    if old == new:
        return old
    if isinstance(old, list):
        values = list(old)
    else:
        values = [old]
    incoming = new if isinstance(new, list) else [new]
    seen = {json_key(item) for item in values}
    for item in incoming:
        marker = json_key(item)
        if marker not in seen:
            values.append(item)
            seen.add(marker)
    return values


def endpoint(value: str) -> tuple[str, int | None]:
    value = value.strip()
    if value.startswith("[") and "]:" in value:
        address, port = value[1:].rsplit("]:", 1)
    elif ":" in value:
        address, port = value.rsplit(":", 1)
    else:
        return value, None
    address = address.split("%", 1)[0]
    try:
        return address, int(port)
    except ValueError:
        return address, None


class StateGraph:
    def __init__(self, profile: dict[str, Any]):
        self.profile = profile
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}

    def evidence(self, source: str, line: int, record: dict[str, Any] | None = None,
                 kind: str = "", ts: float | None = None) -> dict[str, Any]:
        item: dict[str, Any] = {"source": source, "line": line}
        if kind:
            item["kind"] = kind
        if ts is not None:
            item["ts"] = ts
        if self.profile["evidence_mode"] == "full" and record is not None:
            item["record"] = record
        return item

    def _merge_evidence(self, entity: dict[str, Any], evidence: dict[str, Any] | None) -> None:
        if not evidence:
            return
        entity["evidence_count"] = entity.get("evidence_count", 0) + 1
        source = evidence["source"]
        entity["evidence_sources"] = sorted(set(entity.get("evidence_sources", [])) | {source})
        maximum = int(self.profile.get("max_evidence_per_entity", 0))
        if self.profile["evidence_mode"] == "counts" or maximum == 0:
            return
        values = entity.setdefault("evidence", [])
        reference = dict(evidence)
        marker = json_key(reference)
        if len(values) < maximum and all(json_key(item) != marker for item in values):
            values.append(reference)

    def node(self, entity_id: str, kind: str, label: str, attributes: dict[str, Any] | None = None,
             confidence: float = 1.0, evidence: dict[str, Any] | None = None,
             ts: float | None = None) -> str:
        item = self.nodes.setdefault(entity_id, {
            "id": entity_id,
            "type": kind,
            "label": label,
            "confidence": round(confidence, 3),
            "attributes": {},
            "evidence_count": 0,
            "evidence_sources": [],
        })
        item["confidence"] = round(max(float(item["confidence"]), confidence), 3)
        if label and (not item.get("label") or item["label"] == entity_id):
            item["label"] = label
        for key, value in (attributes or {}).items():
            item["attributes"][key] = merge_value(item["attributes"].get(key), value)
        if ts is not None:
            item["first_seen"] = min(item.get("first_seen", ts), ts)
            item["last_seen"] = max(item.get("last_seen", ts), ts)
        self._merge_evidence(item, evidence)
        return entity_id

    def edge(self, source: str, relation: str, target: str,
             attributes: dict[str, Any] | None = None, confidence: float = 1.0,
             evidence: dict[str, Any] | None = None, ts: float | None = None) -> str:
        edge_id = stable_id("edge", f"{source}\0{relation}\0{target}")
        item = self.edges.setdefault(edge_id, {
            "id": edge_id,
            "type": relation,
            "source": source,
            "target": target,
            "directed": True,
            "confidence": round(confidence, 3),
            "attributes": {},
            "evidence_count": 0,
            "evidence_sources": [],
        })
        item["confidence"] = round(max(float(item["confidence"]), confidence), 3)
        item["attributes"]["observations"] = int(item["attributes"].get("observations", 0)) + 1
        for key, value in (attributes or {}).items():
            item["attributes"][key] = merge_value(item["attributes"].get(key), value)
        if ts is not None:
            item["first_seen"] = min(item.get("first_seen", ts), ts)
            item["last_seen"] = max(item.get("last_seen", ts), ts)
        self._merge_evidence(item, evidence)
        return edge_id

    def export(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        return (
            [self.nodes[key] for key in sorted(self.nodes)],
            [self.edges[key] for key in sorted(self.edges)],
        )


class StateCompiler:
    """Extract entities and epistemic relationships from one observation tree."""

    def __init__(self, input_dir: Path, level: str = "operational",
                 config_path: Path | None = None):
        self.input = input_dir.resolve()
        self.config = load_config(config_path)
        if level not in self.config["profiles"]:
            raise ValueError(f"unknown level {level!r}; choose from {sorted(self.config['profiles'])}")
        self.level = level
        self.profile = self.config["profiles"][level]
        self.graph = StateGraph(self.profile)
        self.files_read: Counter[str] = Counter()
        self.records_read: Counter[str] = Counter()
        self.parse_errors: list[dict[str, Any]] = []
        self.local_ips = {"127.0.0.1", "::1"}
        self.local_hostname = "local-container"
        self.process_nodes: dict[int, str] = {}
        self.data_counts: Counter[str] = Counter()
        self.data_seen: set[tuple[str, str]] = set()
        self.http_files: dict[str, tuple[str, str]] = {}
        self.health: dict[str, Any] | None = None
        self.observer_re = re.compile(self.config["observer_process_regex"], re.IGNORECASE)
        data = self.config["data"]
        self.data_include = [re.compile(value, re.IGNORECASE) for value in data["include_regex"]]
        self.data_important = [re.compile(value, re.IGNORECASE) for value in data["important_regex"]]
        self.data_exclude = [re.compile(value, re.IGNORECASE) for value in data["exclude_regex"]]

    def _records(self, path: Path) -> Iterable[tuple[int, dict[str, Any], dict[str, Any]]]:
        relative = str(path.relative_to(self.input))
        try:
            handle = path.open(encoding="utf-8", errors="replace")
        except OSError as exc:
            self.parse_errors.append({"source": relative, "error": repr(exc)})
            return
        self.files_read[relative] += 1
        with handle:
            for number, raw in enumerate(handle, 1):
                if not raw.strip():
                    continue
                try:
                    record = json.loads(raw)
                    if not isinstance(record, dict):
                        raise ValueError("record is not a JSON object")
                except (json.JSONDecodeError, ValueError) as exc:
                    self.parse_errors.append({"source": relative, "line": number, "error": str(exc)})
                    continue
                self.records_read[relative] += 1
                ts = record.get("ts")
                try:
                    ts = float(ts) if ts is not None else None
                except (TypeError, ValueError):
                    ts = None
                evidence = self.graph.evidence(
                    relative, number, record, str(record.get("event", "record")), ts
                )
                yield number, record, evidence

    def _single_json(self, path: Path) -> dict[str, Any] | None:
        relative = str(path.relative_to(self.input))
        try:
            with path.open(encoding="utf-8", errors="replace") as handle:
                value = json.load(handle)
            self.files_read[relative] += 1
            self.records_read[relative] += 1
            return value if isinstance(value, dict) else {"value": value}
        except (OSError, json.JSONDecodeError) as exc:
            self.parse_errors.append({"source": relative, "error": repr(exc)})
            return None

    def _ts(self, record: dict[str, Any]) -> float | None:
        try:
            return float(record["ts"])
        except (KeyError, TypeError, ValueError):
            return None

    def _knowledge(self, target: str, relation: str, confidence: float,
                   evidence: dict[str, Any] | None, ts: float | None = None) -> None:
        self.graph.edge(AGENT_ID, relation, target, confidence=confidence, evidence=evidence, ts=ts)

    def _network(self, cidr: str, source: str, confidence: float,
                 evidence: dict[str, Any] | None = None, **attributes: Any) -> str | None:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return None
        canonical = str(network)
        node_id = f"network:{canonical}"
        attrs = {"cidr": canonical, "version": network.version, "knowledge_source": source, **attributes}
        self.graph.node(node_id, "network", canonical, attrs, confidence, evidence)
        self._knowledge(node_id, "KNOWS_NETWORK", confidence, evidence)
        return node_id

    def _host(self, value: str, source: str, confidence: float = 0.9,
              evidence: dict[str, Any] | None = None, local_hint: bool = False,
              **attributes: Any) -> str | None:
        value = value.strip().strip("[]")
        if not value or value in {"*", "0.0.0.0", "::"}:
            return None
        try:
            address = ipaddress.ip_address(value.split("%", 1)[0])
            canonical = str(address)
            if local_hint or canonical in self.local_ips or address.is_loopback:
                node_id = LOCAL_HOST_ID
                self.local_ips.add(canonical)
                label = self.local_hostname
                attrs = {"addresses": [canonical], "local": True, "knowledge_source": source}
            else:
                if address.is_multicast and self.level != "forensic":
                    return None
                node_id = f"host:ip:{canonical}"
                label = canonical
                attrs = {
                    "addresses": [canonical],
                    "local": False,
                    "address_type": "multicast" if address.is_multicast else "unicast",
                    "knowledge_source": source,
                }
                containing: list[tuple[int, str]] = []
                for candidate_id, candidate in self.graph.nodes.items():
                    if candidate.get("type") != "network":
                        continue
                    try:
                        candidate_network = ipaddress.ip_network(
                            candidate.get("attributes", {}).get("cidr", ""), strict=False
                        )
                    except ValueError:
                        continue
                    if candidate_network.prefixlen > 0 and address in candidate_network:
                        containing.append((candidate_network.prefixlen, candidate_id))
                if containing:
                    network_id = max(containing)[1]
                else:
                    host_route = f"{canonical}/{32 if address.version == 4 else 128}"
                    network_id = self._network(host_route, "observed-host", confidence * 0.75, evidence)
                if network_id:
                    self.graph.edge(node_id, "MEMBER_OF", network_id, confidence=confidence * 0.75,
                                    evidence=evidence)
            attrs.update(attributes)
        except ValueError:
            canonical = value.rstrip(".").lower()
            if not canonical:
                return None
            node_id = f"host:name:{canonical}"
            label = canonical
            attrs = {"names": [canonical], "local": False, "knowledge_source": source, **attributes}
        self.graph.node(node_id, "host", label, attrs, confidence, evidence)
        self._knowledge(node_id, "KNOWS_HOST", confidence, evidence)
        return node_id

    def _service(self, host_id: str | None, protocol: str, port: int | None,
                 name: str | None, status: str, confidence: float,
                 evidence: dict[str, Any] | None = None, **attributes: Any) -> str | None:
        if not host_id or port is None or port < 0:
            return None
        protocol = (protocol or "unknown").lower()
        configured_name = self.config["service_names"].get(str(port))
        service_name = name or configured_name or "unknown"
        node_id = stable_id("service", f"{host_id}\0{protocol}\0{port}")
        label = f"{service_name} {protocol}/{port} on {self.graph.nodes[host_id]['label']}"
        attrs = {
            "host_id": host_id, "protocol": protocol, "port": port,
            "service_name": service_name, "status": status, **attributes,
        }
        self.graph.node(node_id, "service", label, attrs, confidence, evidence)
        self.graph.edge(host_id, "HOSTS_SERVICE", node_id, confidence=confidence, evidence=evidence)
        self._knowledge(node_id, "KNOWS_SERVICE", confidence, evidence)
        return node_id

    def _data_allowed(self, locator: str) -> bool:
        if any(pattern.search(locator) for pattern in self.data_exclude):
            return False
        mode = self.profile["data_mode"]
        if mode == "all":
            return True
        patterns = self.data_important if mode == "important" else self.data_include
        return any(pattern.search(locator) for pattern in patterns)

    def _data(self, host_id: str, locator: str, source: str, confidence: float,
              evidence: dict[str, Any] | None = None, **attributes: Any) -> str | None:
        if not locator or not self._data_allowed(locator):
            return None
        key = (host_id, locator)
        maximum = int(self.profile.get("max_data_per_host", 0))
        if key not in self.data_seen and maximum and self.data_counts[host_id] >= maximum:
            return None
        if key not in self.data_seen:
            self.data_seen.add(key)
            self.data_counts[host_id] += 1
        node_id = stable_id("data", f"{host_id}\0{locator}")
        attrs = {"host_id": host_id, "locator": locator, "knowledge_source": source, **attributes}
        self.graph.node(node_id, "data", locator, attrs, confidence, evidence)
        self.graph.edge(host_id, "STORES_DATA", node_id, confidence=confidence, evidence=evidence)
        self._knowledge(node_id, "KNOWS_DATA", confidence, evidence)
        return node_id

    def _control(self, host_id: str | None, mechanism: str, confidence: float,
                 evidence: dict[str, Any] | None = None, **attributes: Any) -> None:
        if not host_id:
            return
        threshold = float(self.config["control_inference"]["minimum_confidence"])
        relation = "CONTROLS" if confidence >= threshold else "POSSIBLE_ACCESS"
        self.graph.edge(AGENT_ID, relation, host_id, {"mechanism": mechanism, **attributes},
                        confidence, evidence)
        if confidence >= threshold:
            self.graph.node(host_id, "host", self.graph.nodes[host_id]["label"],
                            {"controlled": True, "control_mechanism": mechanism},
                            confidence, evidence)

    def _block(self, target_id: str, reason: str, confidence: float,
               evidence: dict[str, Any] | None = None, **attributes: Any) -> str | None:
        minimum = float(self.config["block_inference"]["minimum_confidence"])
        if confidence < minimum:
            return None
        node_id = stable_id("block", f"{target_id}\0{reason}")
        label = f"possible block: {self.graph.nodes.get(target_id, {}).get('label', target_id)}"
        attrs = {"target_id": target_id, "reason": reason, "hypothesis": confidence < 0.95,
                 **attributes}
        self.graph.node(node_id, "block", label, attrs, confidence, evidence)
        self.graph.edge(node_id, "MAY_BLOCK", target_id, attrs, confidence, evidence)
        self._knowledge(node_id, "KNOWS_BLOCK", confidence, evidence)
        return node_id

    def _is_observer(self, command: str) -> bool:
        return bool(self.observer_re.search(command))

    def _extract_command(self, command: str, evidence: dict[str, Any] | None,
                         exit_status: int | None = None) -> None:
        if not command or self._is_observer(command):
            return
        # URLs encode host, service, and remote data knowledge in one argument.
        for raw_url in re.findall(r"https?://[^\s'\"<>]+", command, re.IGNORECASE):
            parsed = urlsplit(raw_url.rstrip(",);"))
            if not parsed.hostname:
                continue
            host_id = self._host(parsed.hostname, "command-url", 0.9, evidence)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            self._service(host_id, "tcp", port, parsed.scheme, "targeted", 0.85, evidence)
            if host_id:
                self._data(host_id, raw_url, "command-url", 0.9, evidence,
                           resource_type="url", path=parsed.path or "/")

        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = command.split()
        for token in tokens[1:]:
            candidate = token.strip("[](),;'")
            try:
                ipaddress.ip_address(candidate.split("%", 1)[0])
                self._host(candidate, "command-argument", 0.85, evidence)
            except ValueError:
                if candidate.startswith("/"):
                    self._data(LOCAL_HOST_ID, candidate, "command-argument", 0.75, evidence,
                               existence="unknown")

        commands = set(self.config["control_inference"]["successful_commands"])
        command_index = next((i for i, token in enumerate(tokens)
                              if Path(token).name in commands), None)
        if command_index is None:
            return
        tool = Path(tokens[command_index]).name
        remaining = tokens[command_index + 1:]
        port = 22
        targets: list[str] = []
        consumes = {"-b", "-c", "-D", "-E", "-e", "-F", "-i", "-J", "-L", "-l",
                    "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w"}
        index = 0
        while index < len(remaining):
            token = remaining[index]
            if token == "--":
                targets.extend(remaining[index + 1:])
                break
            if token in consumes:
                if token == "-p" and index + 1 < len(remaining):
                    try:
                        port = int(remaining[index + 1])
                    except ValueError:
                        pass
                index += 2
                continue
            if token.startswith("-"):
                index += 1
                continue
            targets.append(token)
            if tool == "ssh":
                break
            index += 1
        for target in targets:
            remote_path = ""
            if ":" in target and not target.startswith("/"):
                target, remote_path = target.split(":", 1)
            hostname = target.rsplit("@", 1)[-1]
            if not hostname or "/" in hostname:
                continue
            host_id = self._host(hostname, f"{tool}-command", 0.95, evidence)
            self._service(host_id, "tcp", port, "ssh", "targeted", 0.9, evidence)
            if host_id and remote_path:
                self._data(host_id, remote_path, f"{tool}-command", 0.9, evidence)
            if exit_status == 0:
                self._control(host_id, f"successful-{tool}", 0.95, evidence,
                              command_exit_status=exit_status)

    def _prepare(self) -> None:
        # Learn the local hostname before assigning labels to host observations.
        process_path = self.input / "processes.jsonl"
        if process_path.exists():
            try:
                with process_path.open(encoding="utf-8", errors="replace") as handle:
                    for raw in handle:
                        try:
                            record = json.loads(raw)
                        except json.JSONDecodeError:
                            continue
                        if record.get("container_hostname"):
                            self.local_hostname = str(record["container_hostname"])
                            break
            except OSError:
                pass
        self.graph.node(AGENT_ID, "agent", "observed agent",
                        {"agent_kind": "human-or-program", "observation_scope": "container"}, 1.0)
        self.graph.node(LOCAL_HOST_ID, "host", self.local_hostname,
                        {"local": True, "controlled": True, "names": [self.local_hostname]}, 1.0)
        self._knowledge(LOCAL_HOST_ID, "KNOWS_HOST", 1.0, None)
        self.graph.edge(AGENT_ID, "RUNS_ON", LOCAL_HOST_ID, confidence=1.0)
        self._control(LOCAL_HOST_ID, "local-container", 1.0)

    def _session(self) -> None:
        self.graph.node(SESSION_ID, "observation", "observation session",
                        {"input_root": str(self.input)}, 1.0)
        self.graph.edge(SESSION_ID, "OBSERVES", AGENT_ID, confidence=1.0)
        supervisor = self.input / "supervisor.jsonl"
        if supervisor.exists():
            for _line, record, evidence in self._records(supervisor):
                event = str(record.get("event", ""))
                attrs: dict[str, Any] = {"supervisor_events": [event]}
                if event == "sensor_started":
                    attrs["sensors"] = [record.get("name")]
                elif event == "workload_started":
                    attrs["workload_requested_argv"] = record.get("requested_argv")
                    attrs["workload_effective_argv"] = record.get("effective_argv")
                    attrs["workload_pid"] = record.get("pid")
                elif event == "workload_exited":
                    attrs["workload_returncode"] = record.get("returncode")
                elif event in {"sensor_start_failed", "sensor_exited"}:
                    attrs["sensor_failures"] = [{
                        "name": record.get("name"), "event": event,
                        "returncode": record.get("returncode"), "error": record.get("error"),
                    }]
                self.graph.node(SESSION_ID, "observation", "observation session", attrs,
                                1.0, evidence, self._ts(record))
        bcc_status = self.input / "bcc" / "status.jsonl"
        if bcc_status.exists():
            for _line, record, evidence in self._records(bcc_status):
                event = str(record.get("event", ""))
                attrs = {"bcc_events": [event]}
                if event in {"tool_failed", "tool_exited", "filter_failed", "mount_failed"}:
                    attrs["bcc_failures"] = [{key: record.get(key) for key in
                                               ("event", "name", "error", "returncode")
                                               if key in record}]
                self.graph.node(SESSION_ID, "observation", "observation session", attrs,
                                0.98, evidence, self._ts(record))
        health_path = self.input / "health.json"
        if health_path.exists():
            self.health = self._single_json(health_path)
            if self.health:
                evidence = self.graph.evidence("health.json", 1, self.health, "collector-health",
                                               float(self.health.get("timestamp", 0) or 0))
                self.graph.node(SESSION_ID, "observation", "observation session",
                                {"health": self.health}, 1.0, evidence,
                                float(self.health.get("timestamp", 0) or 0))

    def _topology(self) -> None:
        path = self.input / "network" / "topology.jsonl"
        if not path.exists():
            return
        latest: tuple[dict[str, Any], dict[str, Any]] | None = None
        for _line, record, evidence in self._records(path):
            if record.get("event") == "topology_snapshot":
                latest = record, evidence
        if not latest:
            return
        record, evidence = latest

        def payload(name: str) -> Any:
            value = record.get(name, {})
            return value.get("data", []) if isinstance(value, dict) and value.get("ok") else []

        for interface in payload("addresses"):
            ifname = interface.get("ifname", "")
            for address in interface.get("addr_info", []):
                local = str(address.get("local", ""))
                prefix = address.get("prefixlen")
                if not local or prefix is None:
                    continue
                self.local_ips.add(local)
                self._host(local, "interface", 1.0, evidence, local_hint=True,
                           interfaces=[ifname], scope=address.get("scope"))
                network_id = self._network(f"{local}/{prefix}", "interface", 1.0, evidence,
                                           interfaces=[ifname], scope=address.get("scope"))
                if network_id:
                    self.graph.edge(LOCAL_HOST_ID, "MEMBER_OF", network_id,
                                    {"interface": ifname, "address": local}, 1.0, evidence)

        for family in ("routes_v4", "routes_v6"):
            for route in payload(family):
                destination = route.get("dst", "default")
                if destination == "default":
                    destination = "0.0.0.0/0" if family == "routes_v4" else "::/0"
                network_id = self._network(str(destination), "route", 0.98, evidence,
                                           route_type=route.get("type", "unicast"))
                gateway = route.get("gateway")
                gateway_id = self._host(str(gateway), "route-gateway", 0.98, evidence) if gateway else None
                if network_id:
                    self.graph.edge(LOCAL_HOST_ID, "HAS_ROUTE_TO", network_id,
                                    {"gateway": gateway, "interface": route.get("dev"),
                                     "metric": route.get("metric"), "table": route.get("table")},
                                    0.98, evidence)
                if gateway_id and network_id:
                    self.graph.edge(network_id, "VIA", gateway_id, confidence=0.98, evidence=evidence)

        for neighbor in payload("neighbors"):
            host_id = self._host(str(neighbor.get("dst", "")), "neighbor-table", 0.98, evidence,
                                 mac=neighbor.get("lladdr"), neighbor_state=neighbor.get("state"),
                                 interface=neighbor.get("dev"))
            if host_id:
                self.graph.edge(LOCAL_HOST_ID, "HAS_NEIGHBOR", host_id,
                                {"interface": neighbor.get("dev")}, 0.98, evidence)

        for family in ("iptables_v4", "iptables_v6"):
            raw = payload(family)
            if isinstance(raw, str):
                self._iptables(raw, family, evidence)
        nft = payload("nftables")
        if isinstance(nft, dict):
            self._nftables(nft, evidence)

    def _iptables(self, raw: str, family: str, evidence: dict[str, Any]) -> None:
        table = ""
        for line in raw.splitlines():
            if line.startswith("*"):
                table = line[1:]
                continue
            verdict = re.search(r"(?:^| )-j (DROP|REJECT)(?: |$)", line)
            if not line.startswith("-A ") or not verdict:
                continue
            chain_match = re.match(r"-A (\S+)", line)
            target_match = re.search(r"(?:^| )-d (\S+)", line)
            port_match = re.search(r"(?:^| )--dport (\S+)", line)
            protocol_match = re.search(r"(?:^| )-p (\S+)", line)
            target = target_match.group(1) if target_match else ("0.0.0.0/0" if family.endswith("v4") else "::/0")
            target_id = self._network(target, "local-firewall", 0.99, evidence)
            if not target_id:
                continue
            attrs = {
                "verdict": verdict.group(1), "chain": chain_match.group(1) if chain_match else "",
                "table": table, "protocol": protocol_match.group(1) if protocol_match else "all",
                "destination_port": port_match.group(1) if port_match else "any", "rule": line,
            }
            if self.profile.get("include_firewall_rules"):
                rule_id = stable_id("firewall_rule", f"{family}\0{table}\0{line}")
                self.graph.node(rule_id, "firewall_rule", line, attrs, 0.99, evidence)
                self.graph.edge(LOCAL_HOST_ID, "DECLARES_FIREWALL_RULE", rule_id,
                                confidence=0.99, evidence=evidence)
                self.graph.edge(rule_id, "BLOCKS", target_id, attrs, 0.99, evidence)
            self._block(target_id, "local-firewall-rule", 0.99, evidence, **attrs)

    def _nftables(self, raw: dict[str, Any], evidence: dict[str, Any]) -> None:
        for wrapper in raw.get("nftables", []):
            rule = wrapper.get("rule") if isinstance(wrapper, dict) else None
            if not isinstance(rule, dict):
                continue
            rendered = json_key(rule)
            verdict = "DROP" if '"drop"' in rendered else "REJECT" if '"reject"' in rendered else ""
            if not verdict:
                continue
            attrs = {"verdict": verdict, "family": rule.get("family"), "table": rule.get("table"),
                     "chain": rule.get("chain"), "rule": rule}
            if self.profile.get("include_firewall_rules"):
                rule_id = stable_id("firewall_rule", rendered)
                self.graph.node(rule_id, "firewall_rule", f"nft {rule.get('chain', '')} {verdict}",
                                attrs, 0.99, evidence)
                self.graph.edge(LOCAL_HOST_ID, "DECLARES_FIREWALL_RULE", rule_id,
                                confidence=0.99, evidence=evidence)
            self._block(LOCAL_HOST_ID, "local-nftables-rule", 0.99, evidence, **attrs)

    def _processes(self) -> None:
        path = self.input / "processes.jsonl"
        if not path.exists():
            return
        pending_parents: list[tuple[str, int, dict[str, Any]]] = []
        for _line, record, evidence in self._records(path):
            event = record.get("event")
            if event not in {"process_seen", "process_changed", "process_gone"}:
                continue
            command = str(record.get("cmdline", ""))
            if self._is_observer(command):
                continue
            ts = self._ts(record)
            pid = int(record.get("pid", -1))
            self._extract_command(command, evidence)
            username = str(record.get("username", record.get("uid", ["unknown"])[0]))
            uid_value = record.get("uid", ["unknown"])
            uid = uid_value[0] if isinstance(uid_value, list) and uid_value else uid_value
            user_id = f"user:{uid}"
            self.graph.node(user_id, "user", username, {"uid": uid, "username": username},
                            0.95, evidence, ts)
            self.graph.edge(user_id, "USES", LOCAL_HOST_ID, confidence=0.95, evidence=evidence, ts=ts)
            mode = self.profile["process_mode"]
            if mode == "none":
                continue
            if mode == "instance":
                start = str(record.get("start_ticks", "unknown"))
                node_id = f"process:{pid}:{start}"
                attrs = {key: value for key, value in record.items()
                         if key not in {"source", "event", "container_hostname", "ts", "time_ns"}}
                attrs["lifecycle"] = "gone" if event == "process_gone" else "seen"
                label = command or str(record.get("name", f"pid {pid}"))
                self.graph.node(node_id, "process", label, attrs, 0.95, evidence, ts)
                self.process_nodes[pid] = node_id
                pending_parents.append((node_id, int(record.get("ppid", 0) or 0), evidence))
            else:
                executable = str(record.get("exe") or record.get("name") or command.split(" ", 1)[0])
                node_id = stable_id("program", executable)
                self.graph.node(node_id, "program", Path(executable).name or executable,
                                {"executable": executable, "commands": [command] if command else []},
                                0.9, evidence, ts)
            self.graph.edge(user_id, "EXECUTED", node_id, confidence=0.9, evidence=evidence, ts=ts)
            self.graph.edge(AGENT_ID, "USED_PROGRAM", node_id, confidence=0.85, evidence=evidence, ts=ts)
        if self.profile["process_mode"] == "instance":
            for child, ppid, evidence in pending_parents:
                parent = self.process_nodes.get(ppid)
                if parent:
                    self.graph.edge(parent, "SPAWNED", child, confidence=0.95, evidence=evidence)

    def _sockets(self) -> None:
        path = self.input / "sockets" / "sockets.jsonl"
        if not path.exists():
            return
        for _line, record, evidence in self._records(path):
            if record.get("event") not in {"connection_seen", "listener_seen"}:
                continue
            raw = str(record.get("socket", ""))
            parts = re.split(r"\s+", raw.strip(), maxsplit=6)
            if len(parts) < 6:
                continue
            protocol, state, _recvq, _sendq, local_raw, peer_raw = parts[:6]
            local_address, local_port = endpoint(local_raw)
            peer_address, peer_port = endpoint(peer_raw)
            ts = self._ts(record)
            if state.upper() in {"LISTEN", "UNCONN"} or record.get("event") == "listener_seen":
                service = self._service(LOCAL_HOST_ID, protocol, local_port, None, "listening", 0.98,
                                        evidence, socket_state=state)
                if service:
                    self.graph.edge(LOCAL_HOST_ID, "LISTENS_ON", service, confidence=0.98,
                                    evidence=evidence, ts=ts)
                continue
            remote_id = self._host(peer_address, "socket", 0.95, evidence)
            if not remote_id or remote_id == LOCAL_HOST_ID:
                remote_id = self._host(local_address, "socket", 0.95, evidence, local_hint=True)
            service = self._service(remote_id, protocol, peer_port, None, "observed", 0.9, evidence,
                                    socket_state=state)
            if self.profile["include_flows"] and remote_id:
                self.graph.edge(LOCAL_HOST_ID, "CONNECTED_TO", remote_id,
                                {"protocol": protocol, "local_port": local_port,
                                 "remote_port": peer_port, "socket_state": state,
                                 "service_id": service}, 0.9, evidence, ts)

    def _files(self) -> None:
        paths = [self.input / "files" / "events.jsonl", self.input / "files" / "reconciliation.jsonl"]
        for path in paths:
            if not path.exists():
                continue
            for _line, record, evidence in self._records(path):
                event = str(record.get("event", ""))
                locator = str(record.get("path", ""))
                if not locator or event in {"monitor_started", "baseline_complete", "scan_complete"}:
                    continue
                attrs: dict[str, Any] = {"event_types": [event]}
                if record.get("operations"):
                    attrs["operations"] = record["operations"]
                state = record.get("state")
                if isinstance(state, list) and len(state) >= 7:
                    attrs.update({"mode": state[0], "uid": state[1], "gid": state[2], "size": state[3],
                                  "mtime_ns": state[4], "ctime_ns": state[5], "sha256": state[6]})
                if event in {"file_deleted"} or "DELETE" in record.get("operations", []):
                    attrs["exists"] = False
                elif event.startswith("file_") or record.get("operations"):
                    attrs["exists"] = True
                data_id = self._data(LOCAL_HOST_ID, locator, "filesystem", 0.92, evidence, **attrs)
                if data_id and (event in {"file_added", "file_changed", "file_deleted"}
                                or record.get("operations")):
                    self.graph.edge(AGENT_ID, "CHANGED_DATA", data_id,
                                    {"event_type": event, "operations": record.get("operations", [])},
                                    0.8, evidence, self._ts(record))

    def _zeek(self) -> None:
        directory = self.input / "zeek"
        if not directory.exists():
            return
        for path in sorted(directory.glob("*.log")):
            kind = path.name.split(".", 1)[0]
            handler = getattr(self, f"_zeek_{kind}", None)
            if not handler:
                # Unknown JSON Zeek logs are still represented in source inventory.
                for _line, _record, _evidence in self._records(path):
                    pass
                continue
            for _line, record, evidence in self._records(path):
                handler(record, evidence)

    def _zeek_conn(self, record: dict[str, Any], evidence: dict[str, Any]) -> None:
        origin = str(record.get("id.orig_h", ""))
        responder = str(record.get("id.resp_h", ""))
        origin_id = self._host(origin, "zeek-flow", 0.95, evidence,
                               local_hint=bool(record.get("local_orig")))
        responder_id = self._host(responder, "zeek-flow", 0.95, evidence,
                                  local_hint=bool(record.get("local_resp")))
        if not origin_id or not responder_id:
            return
        protocol = str(record.get("proto", "unknown"))
        try:
            port = int(record.get("id.resp_p"))
        except (TypeError, ValueError):
            port = None
        service_field = record.get("service")
        if isinstance(service_field, list):
            service_name = ",".join(map(str, service_field))
        else:
            service_name = str(service_field) if service_field else None
        responded = int(record.get("resp_pkts", 0) or 0) > 0 or record.get("conn_state") == "SF"
        service_id = self._service(responder_id, protocol, port, service_name,
                                   "open" if responded else "attempted", 0.95 if responded else 0.7,
                                   evidence, zeek_state=record.get("conn_state"))
        ts = self._ts(record)
        if self.profile["include_flows"]:
            attrs = {key: record.get(key) for key in (
                "proto", "id.orig_p", "id.resp_p", "service", "duration", "orig_bytes",
                "resp_bytes", "conn_state", "orig_pkts", "resp_pkts", "missed_bytes"
            ) if key in record}
            attrs["service_id"] = service_id
            self.graph.edge(origin_id, "NETWORK_FLOW", responder_id, attrs, 0.95, evidence, ts)

        if origin_id != LOCAL_HOST_ID:
            return
        state = str(record.get("conn_state", ""))
        origin_packets = int(record.get("orig_pkts", 0) or 0)
        block_config = self.config["block_inference"]
        if origin_packets < int(block_config["minimum_origin_packets"]):
            return
        if state in block_config["zeek_no_reply_states"]:
            target = service_id or responder_id
            self._block(target, "network-no-reply", 0.78, evidence, zeek_state=state,
                        origin_packets=origin_packets, response_packets=record.get("resp_pkts", 0))
        elif state in block_config["zeek_rejected_states"]:
            target = service_id or responder_id
            self._block(target, "network-rejected-or-reset", 0.55, evidence, zeek_state=state)

    def _zeek_dns(self, record: dict[str, Any], evidence: dict[str, Any]) -> None:
        responder = self._host(str(record.get("id.resp_h", "")), "dns-flow", 0.95, evidence,
                               local_hint=bool(record.get("local_resp")))
        self._service(responder, str(record.get("proto", "udp")),
                      int(record.get("id.resp_p", 53) or 53), "dns", "observed", 0.95, evidence)
        query = str(record.get("query", "")).rstrip(".")
        query_id = self._host(query, "dns-query", 0.9, evidence) if query else None
        for answer in record.get("answers", []) or []:
            answer_id = self._host(str(answer), "dns-answer", 0.95, evidence)
            if query_id and answer_id and query_id != answer_id:
                relation = "RESOLVES_TO" if answer_id.startswith("host:ip:") else "ALIASES_TO"
                self.graph.edge(query_id, relation, answer_id, confidence=0.95, evidence=evidence,
                                ts=self._ts(record))

    def _zeek_http(self, record: dict[str, Any], evidence: dict[str, Any]) -> None:
        responder = self._host(str(record.get("id.resp_h", "")), "http-flow", 0.98, evidence,
                               local_hint=bool(record.get("local_resp")))
        try:
            port = int(record.get("id.resp_p", 80))
        except (TypeError, ValueError):
            port = 80
        service = self._service(responder, "tcp", port, "http", "open", 0.98, evidence,
                                status_code=record.get("status_code"))
        if not responder:
            return
        host = str(record.get("host") or self.graph.nodes[responder]["label"])
        uri = str(record.get("uri", "/"))
        locator = f"http://{host}{uri}"
        data_id = self._data(responder, locator, "zeek-http", 0.98, evidence,
                             resource_type="http", method=record.get("method"),
                             status_code=record.get("status_code"),
                             mime_types=record.get("resp_mime_types"),
                             response_body_len=record.get("response_body_len"))
        for fuid in record.get("resp_fuids", []) or []:
            self.http_files[str(fuid)] = (responder, locator)
        if data_id and service:
            self.graph.edge(service, "SERVED_DATA", data_id, confidence=0.98, evidence=evidence)

    def _zeek_files(self, record: dict[str, Any], evidence: dict[str, Any]) -> None:
        fuid = str(record.get("fuid", ""))
        mapped = self.http_files.get(fuid)
        if mapped:
            host_id, locator = mapped
        else:
            address_key = "id.orig_h" if record.get("is_orig") else "id.resp_h"
            host_id = self._host(str(record.get(address_key, "")), "zeek-file", 0.9, evidence,
                                 local_hint=bool(record.get("local_orig") and record.get("is_orig")))
            locator = str(record.get("filename") or f"zeek-file:{fuid}")
        if host_id:
            self._data(host_id, locator, "zeek-file", 0.92, evidence,
                       fuid=fuid, mime_type=record.get("mime_type"), source_protocol=record.get("source"),
                       seen_bytes=record.get("seen_bytes"), total_bytes=record.get("total_bytes"),
                       sha1=record.get("sha1"), sha256=record.get("sha256"))

    def _zeek_ssh(self, record: dict[str, Any], evidence: dict[str, Any]) -> None:
        responder = self._host(str(record.get("id.resp_h", "")), "zeek-ssh", 0.99, evidence,
                               local_hint=bool(record.get("local_resp")))
        service = self._service(responder, "tcp", int(record.get("id.resp_p", 22) or 22),
                                "ssh", "open", 0.99, evidence,
                                server=record.get("server"), version=record.get("version"))
        if record.get("auth_success") is True and not record.get("local_resp"):
            self._control(responder, "zeek-ssh-auth-success", 0.99, evidence,
                          auth_attempts=record.get("auth_attempts"), service_id=service)

    def _zeek_known_hosts(self, record: dict[str, Any], evidence: dict[str, Any]) -> None:
        self._host(str(record.get("host", "")), "zeek-known-host", 0.9, evidence)

    def _zeek_known_services(self, record: dict[str, Any], evidence: dict[str, Any]) -> None:
        host_id = self._host(str(record.get("host", "")), "zeek-known-service", 0.95, evidence)
        port_value = record.get("port_num", record.get("port"))
        try:
            port = int(port_value)
        except (TypeError, ValueError):
            port = None
        self._service(host_id, str(record.get("port_proto", "tcp")), port,
                      str(record.get("service", "")) or None, "observed", 0.95, evidence)

    def _command_audit(self) -> None:
        tty = self.input / "tty"
        if not tty.exists():
            return
        for path in sorted(tty.glob("commands*.jsonl")):
            for _line, record, evidence in self._records(path):
                if record.get("event") != "command_completed":
                    continue
                try:
                    status = int(record.get("exit_status"))
                except (TypeError, ValueError):
                    status = None
                command = str(record.get("command", ""))
                self._extract_command(command, evidence, status)
                if self.profile["process_mode"] != "none" and command:
                    node_id = stable_id("command", f"{record.get('pid')}\0{record.get('sequence')}\0{command}")
                    self.graph.node(node_id, "command", command,
                                    {"command": command, "exit_status": status, "cwd": record.get("cwd"),
                                     "uid": record.get("uid"), "tty": record.get("tty")},
                                    0.99, evidence, self._ts(record))
                    self.graph.edge(AGENT_ID, "ISSUED_COMMAND", node_id,
                                    confidence=0.99, evidence=evidence, ts=self._ts(record))

    def _syscalls(self) -> None:
        directory = self.input / "syscalls"
        if not directory.exists():
            return
        quoted = r'"((?:\\.|[^"\\])*)"'
        path_call = re.compile(rf"^[0-9.]+ (?:open|openat|openat2|stat|lstat|newfstatat|access|readlink|execve)\([^\n]*?{quoted}")
        connect_v4 = re.compile(r'sin_port=htons\((\d+)\).*?sin_addr=inet_addr\("([^"]+)"\)')
        connect_v6 = re.compile(r'sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6, "([^"]+)"')
        for path in sorted(directory.glob("trace.*")):
            relative = str(path.relative_to(self.input))
            self.files_read[relative] += 1
            try:
                pid = int(path.name.rsplit(".", 1)[-1])
            except ValueError:
                pid = -1
            try:
                handle = path.open(encoding="utf-8", errors="replace")
            except OSError as exc:
                self.parse_errors.append({"source": relative, "error": repr(exc)})
                continue
            with handle:
                for number, line in enumerate(handle, 1):
                    self.records_read[relative] += 1
                    try:
                        ts = float(line.split(" ", 1)[0])
                    except (ValueError, IndexError):
                        ts = None
                    evidence = self.graph.evidence(relative, number, None, "syscall", ts)
                    match = path_call.search(line)
                    if match:
                        try:
                            locator = json.loads(f'"{match.group(1)}"')
                        except json.JSONDecodeError:
                            locator = match.group(1)
                        success = " = -1 " not in line
                        data_id = self._data(LOCAL_HOST_ID, locator, "workload-syscall",
                                             0.99 if success else 0.75, evidence,
                                             accessed_by_pid=pid, access_succeeded=success)
                        if data_id:
                            self.graph.edge(AGENT_ID, "ACCESSED_DATA", data_id,
                                            {"pid": pid, "succeeded": success},
                                            0.99 if success else 0.75, evidence, ts)
                        if " execve(" in line and success:
                            self._extract_command(locator, evidence)
                    if " connect(" not in line or "AF_UNIX" in line:
                        continue
                    connection = connect_v4.search(line) or connect_v6.search(line)
                    if not connection:
                        continue
                    port = int(connection.group(1))
                    address = connection.group(2)
                    host_id = self._host(address, "connect-syscall", 0.98, evidence)
                    service = self._service(host_id, "tcp-or-udp", port, None,
                                            "targeted", 0.9, evidence)
                    errors = {
                        "ETIMEDOUT": ("connect-timeout", 0.82),
                        "EHOSTUNREACH": ("host-unreachable", 0.55),
                        "ENETUNREACH": ("network-unreachable", 0.5),
                        "EACCES": ("connect-denied", 0.9),
                    }
                    for errno, (reason, confidence) in errors.items():
                        if f" {errno} " in line and (service or host_id):
                            self._block(service or host_id, reason, confidence, evidence,
                                        errno=errno, destination=address, port=port)
                            break

    def _bcc_exec(self) -> None:
        path = self.input / "bcc" / "execsnoop.log"
        if not path.exists() or self.profile["process_mode"] == "none":
            return
        relative = str(path.relative_to(self.input))
        self.files_read[relative] += 1
        pattern = re.compile(r"^(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(-?\d+)\s+(.*)$")
        with path.open(encoding="utf-8", errors="replace") as handle:
            for number, line in enumerate(handle, 1):
                match = pattern.match(line.strip())
                if not match:
                    continue
                self.records_read[relative] += 1
                _clock, uid, process, pid, ppid, result, args = match.groups()
                if result != "0" or self._is_observer(args):
                    continue
                evidence = self.graph.evidence(relative, number, None, "exec", None)
                self._extract_command(args, evidence)
                executable = ""
                try:
                    parsed_args = shlex.split(args)
                    executable = parsed_args[0] if parsed_args else process
                except ValueError:
                    executable = process
                if self.profile["process_mode"] == "instance":
                    node_id = f"process:hostpid:{pid}"
                    kind = "process"
                else:
                    node_id = stable_id("program", executable)
                    kind = "program"
                self.graph.node(node_id, kind, process,
                                {"executable": executable, "arguments": args, "host_pid": int(pid),
                                 "host_ppid": int(ppid), "uid": int(uid)}, 0.98, evidence)
                self.graph.edge(AGENT_ID, "USED_PROGRAM", node_id, confidence=0.98, evidence=evidence)

    def _assertions(self) -> None:
        path = self.input / "state-assertions.jsonl"
        if not path.exists():
            return
        for _line, record, evidence in self._records(path):
            kind = record.get("type")
            confidence = float(record.get("confidence", 1.0))
            host_id = self._host(str(record.get("host", "")), "operator-assertion", confidence, evidence)
            if kind == "controlled_host":
                self._control(host_id, str(record.get("mechanism", "operator-assertion")),
                              confidence, evidence, note=record.get("note"))
            elif kind == "known_file" and host_id:
                self._data(host_id, str(record.get("path", "")), "operator-assertion",
                           confidence, evidence, note=record.get("note"))
            elif kind == "known_service" and host_id:
                self._service(host_id, str(record.get("protocol", "tcp")),
                              int(record.get("port")), record.get("service"),
                              str(record.get("status", "known")), confidence, evidence)

    def compile(self) -> dict[str, Any]:
        self._prepare()
        self._session()
        self._topology()
        self._processes()
        self._sockets()
        self._files()
        self._command_audit()
        self._zeek()
        self._syscalls()
        self._bcc_exec()
        self._assertions()
        nodes, edges = self.graph.export()
        summary = self._summary(nodes, edges)
        return {
            "schema_version": self.config["schema_version"],
            "graph_model": "directed-property-graph",
            "detail_level": self.level,
            "detail_description": self.profile["description"],
            "generated_at": time.time(),
            "observation_root": str(self.input),
            "agent_id": AGENT_ID,
            "local_host_id": LOCAL_HOST_ID,
            "summary": summary,
            "nodes": nodes,
            "edges": edges,
            "provenance": {
                "files_read": dict(sorted(self.files_read.items())),
                "records_read": dict(sorted(self.records_read.items())),
                "parse_errors": self.parse_errors[:1000],
                "parse_error_count": len(self.parse_errors),
                "collector_health": self.health,
            },
        }

    def _summary(self, nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
        by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for node in nodes:
            by_type[node["type"]].append(node)
        controls = {edge["target"]: edge for edge in edges if edge["type"] == "CONTROLS"}

        def compact(node: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
            attrs = node["attributes"]
            item = {"id": node["id"], "label": node["label"],
                    "confidence": node["confidence"]}
            item.update({key: attrs[key] for key in fields if key in attrs})
            return item

        hosts = [node for node in by_type["host"]
                 if node["attributes"].get("address_type") != "multicast"]
        networks = [compact(node, ("cidr", "knowledge_source", "interfaces", "scope"))
                    for node in by_type["network"]]
        known_hosts = [compact(node, ("addresses", "names", "local", "mac", "knowledge_source"))
                       for node in hosts]
        controlled = []
        for node in hosts:
            edge = controls.get(node["id"])
            if not edge:
                continue
            item = compact(node, ("addresses", "names", "local", "control_mechanism"))
            item["access"] = edge["attributes"]
            controlled.append(item)
        data_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for node in by_type["data"]:
            host_id = str(node["attributes"].get("host_id", "unknown"))
            data_by_host[host_id].append(compact(
                node, ("locator", "exists", "sha256", "size", "mime_type", "status_code",
                       "knowledge_source", "event_types")
            ))
        services_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for node in by_type["service"]:
            host_id = str(node["attributes"].get("host_id", "unknown"))
            services_by_host[host_id].append(compact(
                node, ("protocol", "port", "service_name", "status", "knowledge_source")
            ))
        blocks = [compact(node, ("target_id", "reason", "hypothesis", "verdict", "protocol",
                                         "destination_port", "zeek_state", "errno"))
                  for node in by_type["block"]]
        return {
            "known_networks": networks,
            "known_hosts": known_hosts,
            "controlled_hosts": controlled,
            "known_data": dict(sorted(data_by_host.items())),
            "known_services": dict(sorted(services_by_host.items())),
            "known_blocks": blocks,
            "counts": {
                "nodes": len(nodes), "edges": len(edges),
                "known_networks": len(networks), "known_hosts": len(known_hosts),
                "controlled_hosts": len(controlled),
                "known_data": sum(map(len, data_by_host.values())),
                "known_services": sum(map(len, services_by_host.values())),
                "known_blocks": len(blocks),
            },
        }


def write_outputs(graph: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, value in (("graph.json", graph), ("summary.json", graph["summary"])):
        temporary = output_dir / f".{name}.tmp"
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, indent=2, default=str)
            handle.write("\n")
        os.replace(temporary, output_dir / name)

    temporary = output_dir / ".embedding.jsonl.tmp"
    with temporary.open("w", encoding="utf-8") as handle:
        for node in graph["nodes"]:
            document = {
                "id": node["id"], "kind": "node", "type": node["type"],
                "text": f"{node['type']} {node['label']} {json_key(node['attributes'])}",
                "metadata": {"confidence": node["confidence"],
                             "evidence_count": node["evidence_count"]},
            }
            handle.write(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
        for edge in graph["edges"]:
            source = graph_node_label(graph, edge["source"])
            target = graph_node_label(graph, edge["target"])
            document = {
                "id": edge["id"], "kind": "edge", "type": edge["type"],
                "text": f"{source} {edge['type']} {target} {json_key(edge['attributes'])}",
                "metadata": {"source": edge["source"], "target": edge["target"],
                             "confidence": edge["confidence"],
                             "evidence_count": edge["evidence_count"]},
            }
            handle.write(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    os.replace(temporary, output_dir / "embedding.jsonl")


def graph_node_label(graph: dict[str, Any], node_id: str) -> str:
    for node in graph["nodes"]:
        if node["id"] == node_id:
            return str(node["label"])
    return node_id


def watch(input_dir: Path, output_dir: Path, level: str, config_path: Path | None,
          interval: float) -> None:
    stopping = False

    def stop(_signum: int, _frame: Any) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while True:
        graph = StateCompiler(input_dir, level, config_path).compile()
        write_outputs(graph, output_dir)
        if stopping:
            return
        deadline = time.monotonic() + interval
        while time.monotonic() < deadline and not stopping:
            time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
        if stopping:
            # Compile once more after SIGTERM to include the last collector writes.
            graph = StateCompiler(input_dir, level, config_path).compile()
            write_outputs(graph, output_dir)
            return
