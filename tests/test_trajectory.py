#!/usr/bin/env python3
"""Tests for passive action detection and material trajectory snapshots."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "observer" / "lib"))

from trajectory import PassiveTrajectoryMonitor  # noqa: E402


class TrajectoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for name in ("bcc", "files", "network", "sockets", "syscalls", "tty", "zeek"):
            (self.root / name).mkdir()
        self.append("processes.jsonl", {
            "ts": 1, "event": "monitor_started", "container_hostname": "test-container"
        })
        self.append("network/topology.jsonl", {
            "ts": 1, "event": "topology_snapshot",
            "addresses": {"ok": True, "data": [{"ifname": "eth0", "addr_info": [
                {"local": "10.10.0.2", "prefixlen": 24, "scope": "global"}
            ]}]},
            "routes_v4": {"ok": True, "data": [{"dst": "10.10.0.0/24", "dev": "eth0"}]},
            "routes_v6": {"ok": True, "data": []},
            "neighbors": {"ok": True, "data": []},
            "iptables_v4": {"ok": True, "data": ""},
            "iptables_v6": {"ok": True, "data": ""},
            "nftables": {"ok": True, "data": {"nftables": []}}
        })

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def append(self, relative: str, record: dict) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")

    def records(self, output: Path, kind: str) -> list[dict]:
        result = []
        for raw in (output / "sequence.jsonl").read_text(encoding="utf-8").splitlines():
            record = json.loads(raw)
            if record["kind"] == kind:
                result.append(record)
        return result

    def actions(self, output: Path) -> list[dict]:
        return [json.loads(path.read_text(encoding="utf-8"))
                for path in sorted((output / "actions").glob("*.json"))]

    def test_material_policy_reuses_state_until_knowledge_changes(self) -> None:
        output = self.root / "trajectory"
        monitor = PassiveTrajectoryMonitor(self.root, output, "strategic", sensitivity="material")
        self.append("tty/commands-0-1-10.jsonl", {
            "ts": 2, "event": "action_started", "action_id": "bash:test:10:1",
            "uid": 0, "pid": 10, "ppid": 1, "tty": "/dev/pts/0",
            "cwd": "/work", "sequence": 1, "command": "date"
        })
        self.append("tty/commands-0-1-10.jsonl", {
            "ts": 2.1, "event": "command_completed", "action_id": "bash:test:10:1",
            "uid": 0, "pid": 10, "ppid": 1, "tty": "/dev/pts/0",
            "cwd": "/work", "sequence": 1, "exit_status": 0, "command": "date"
        })
        monitor.run(once=True)
        first = self.actions(output)[0]
        self.assertFalse(first["state_changed"])
        self.assertEqual(first["state_before"], first["state_after"])
        self.assertEqual(len(self.records(output, "state")), 1)

        self.append("tty/commands-0-1-10.jsonl", {
            "ts": 3, "event": "action_started", "action_id": "bash:test:10:2",
            "uid": 0, "pid": 10, "ppid": 1, "tty": "/dev/pts/0",
            "cwd": "/work", "sequence": 2, "command": "nmap -sV 10.10.0.25"
        })
        self.append("tty/commands-0-1-10.jsonl", {
            "ts": 4, "event": "command_completed", "action_id": "bash:test:10:2",
            "uid": 0, "pid": 10, "ppid": 1, "tty": "/dev/pts/0",
            "cwd": "/work", "sequence": 2, "exit_status": 0,
            "command": "nmap -sV 10.10.0.25"
        })
        self.append("zeek/conn.log", {
            "ts": 3.5, "id.orig_h": "10.10.0.2", "id.orig_p": 50000,
            "id.resp_h": "10.10.0.25", "id.resp_p": 22, "proto": "tcp",
            "service": "ssh", "conn_state": "SF", "orig_pkts": 4, "resp_pkts": 4,
            "local_orig": True, "local_resp": False
        })
        restarted = PassiveTrajectoryMonitor(self.root, output, "strategic", sensitivity="material")
        restarted.run(once=True)
        actions = {item["id"]: item for item in self.actions(output)}
        second = actions["bash:test:10:2"]
        self.assertTrue(second["state_changed"])
        self.assertNotEqual(second["state_before"], second["state_after"])
        self.assertIn("known_hosts", second["changed_domains"])
        self.assertEqual(len(self.records(output, "state")), 2)

    def test_always_policy_stores_state_for_small_action(self) -> None:
        output = self.root / "trajectory-always"
        monitor = PassiveTrajectoryMonitor(self.root, output, "strategic", sensitivity="always")
        self.append("tty/commands-always.jsonl", {
            "ts": 5, "event": "command_completed", "action_id": "bash:test:20:1",
            "uid": 0, "pid": 20, "ppid": 1, "tty": "/dev/pts/1", "cwd": "/",
            "sequence": 1, "exit_status": 0, "command": "true"
        })
        monitor.run(once=True)
        action = self.actions(output)[0]
        self.assertTrue(action["state_changed"])
        self.assertEqual(len(self.records(output, "state")), 2)

    def test_process_tree_child_becomes_action_without_agent_cooperation(self) -> None:
        output = self.root / "trajectory-process"
        monitor = PassiveTrajectoryMonitor(self.root, output, "strategic", sensitivity="material")
        self.append("processes.jsonl", {
            "ts": 6, "event": "process_seen", "container_hostname": "test-container",
            "pid": 50, "host_pid": 500, "ppid": 1, "start_ticks": "100",
            "name": "python3", "cmdline": "python3 /work/agent.py", "uid": ["1000"],
            "username": "agent", "tty_nr": "0"
        })
        self.append("processes.jsonl", {
            "ts": 7, "event": "process_seen", "container_hostname": "test-container",
            "pid": 51, "host_pid": 501, "ppid": 50, "start_ticks": "101",
            "name": "nmap", "cmdline": "nmap -sV 10.10.0.0/24", "uid": ["1000"],
            "username": "agent", "tty_nr": "0"
        })
        self.append("processes.jsonl", {
            "ts": 8, "event": "process_gone", "container_hostname": "test-container",
            "pid": 51, "start_ticks": "101", "name": "nmap",
            "cmdline": "nmap -sV 10.10.0.0/24", "uid": ["1000"]
        })
        monitor.run(once=True)
        action = self.actions(output)[0]
        self.assertEqual(action["type"], "network_scan")
        self.assertEqual(action["source"], "process-lifecycle")
        self.assertEqual(action["command"]["argv"], ["nmap", "-sV", "10.10.0.0/24"])
        self.assertEqual(action["targets"], ["10.10.0.0/24"])

    def test_process_exit_status_is_preserved_on_remote_action(self) -> None:
        output = self.root / "trajectory-remote-exit"
        monitor = PassiveTrajectoryMonitor(self.root, output, "strategic", sensitivity="material")
        self.append("processes.jsonl", {
            "ts": 6, "event": "process_seen", "container_hostname": "test-container",
            "pid": 60, "host_pid": 600, "ppid": 1, "start_ticks": "110",
            "name": "python3", "cmdline": "python3 /work/agent.py", "uid": ["1000"],
            "username": "agent", "tty_nr": "0"
        })
        self.append("processes.jsonl", {
            "ts": 7, "event": "process_seen", "container_hostname": "test-container",
            "pid": 61, "host_pid": 601, "ppid": 60, "start_ticks": "111",
            "name": "ssh", "cmdline": "ssh labuser@10.77.2.13 'cat /etc/hostname'",
            "uid": ["1000"], "username": "agent", "tty_nr": "0"
        })
        self.append("processes.jsonl", {
            "ts": 8, "event": "process_gone", "container_hostname": "test-container",
            "pid": 61, "start_ticks": "111", "name": "ssh",
            "cmdline": "ssh labuser@10.77.2.13 'cat /etc/hostname'",
            "exit_status": 0, "uid": ["1000"]
        })

        monitor.run(once=True)
        action = self.actions(output)[0]
        self.assertEqual(action["type"], "remote_access")
        self.assertEqual(action["exit_status"], 0)
        self.assertIn("10.77.2.13", [item.get("address") for item in action["execution_hosts"]])
        self.assertIn("controlled_hosts", action["changed_domains"])

    def test_actions_record_local_remote_and_chained_host_context(self) -> None:
        output = self.root / "trajectory-host-context"
        monitor = PassiveTrajectoryMonitor(self.root, output, "strategic", sensitivity="material")
        self.append("tty/commands-hosts.jsonl", {
            "ts": 10, "event": "command_completed", "action_id": "bash:hosts:1",
            "container_hostname": "bastion", "ssh_connection": "",
            "uid": 0, "pid": 80, "ppid": 1, "tty": "/dev/pts/2", "cwd": "/",
            "sequence": 1, "exit_status": 0, "command": "id",
        })
        self.append("tty/commands-hosts.jsonl", {
            "ts": 11, "event": "command_completed", "action_id": "bash:hosts:2",
            "container_hostname": "bastion",
            "ssh_connection": "10.10.0.5 50000 10.10.0.2 22",
            "uid": 0, "pid": 81, "ppid": 1, "tty": "/dev/pts/3", "cwd": "/",
            "sequence": 2, "exit_status": 0, "command": "cat /etc/hostname",
        })
        self.append("tty/commands-hosts.jsonl", {
            "ts": 12, "event": "command_completed", "action_id": "bash:hosts:3",
            "container_hostname": "bastion",
            "ssh_connection": "10.10.0.5 50000 10.10.0.2 22",
            "uid": 0, "pid": 81, "ppid": 1, "tty": "/dev/pts/3", "cwd": "/",
            "sequence": 3, "exit_status": 0,
            "command": "ssh root@10.10.0.25 'touch /tmp/pivoted'",
        })

        monitor.run(once=True)
        actions = {item["id"]: item for item in self.actions(output)}

        local = actions["bash:hosts:1"]
        self.assertEqual(local["source_host"]["hostname"], "bastion")
        self.assertEqual(local["execution_host"]["hostname"], "bastion")
        self.assertEqual(len(local["host_chain"]), 1)

        inbound = actions["bash:hosts:2"]
        self.assertEqual(inbound["agent_origin_host"]["address"], "10.10.0.5")
        self.assertEqual(inbound["source_host"]["hostname"], "bastion")
        self.assertEqual(inbound["execution_host"]["hostname"], "bastion")
        self.assertEqual([item["host"] for item in inbound["host_chain"]],
                         ["10.10.0.5", "bastion"])

        pivot = actions["bash:hosts:3"]
        self.assertEqual(pivot["agent_origin_host"]["address"], "10.10.0.5")
        self.assertEqual(pivot["source_host"]["hostname"], "bastion")
        self.assertEqual(pivot["execution_host"]["address"], "10.10.0.25")
        self.assertEqual([item["host"] for item in pivot["host_chain"]],
                         ["10.10.0.5", "bastion", "10.10.0.25"])
        self.assertEqual(pivot["remote_session"]["server_host"]["address"], "10.10.0.2")

    def test_remote_access_accepts_short_names_and_proxy_jump_chain(self) -> None:
        output = self.root / "trajectory-proxy-jump"
        monitor = PassiveTrajectoryMonitor(self.root, output, "strategic", sensitivity="material")
        self.append("tty/commands-proxy.jsonl", {
            "ts": 20, "event": "command_completed", "action_id": "bash:proxy:1",
            "container_hostname": "workstation", "uid": 0, "pid": 90, "ppid": 1,
            "tty": "/dev/pts/4", "cwd": "/", "sequence": 1, "exit_status": 0,
            "command": "ssh -J user@bastion root@database hostname",
        })

        monitor.run(once=True)
        action = self.actions(output)[0]

        self.assertEqual([item["hostname"] for item in action["execution_hosts"]],
                         ["bastion", "database"])
        self.assertEqual([item["host"] for item in action["host_chain"]],
                         ["workstation", "bastion", "database"])

        self.assertEqual(monitor._remote_targets(
            "scp local-report.txt root@fileserver:/srv/report.txt"
        ), ["fileserver"])

    def test_noninteractive_ssh_child_keeps_inbound_source(self) -> None:
        output = self.root / "trajectory-noninteractive-ssh"
        monitor = PassiveTrajectoryMonitor(self.root, output, "strategic", sensitivity="material")
        self.append("processes.jsonl", {
            "ts": 30, "event": "process_seen", "container_hostname": "database",
            "pid": 100, "host_pid": 1000, "ppid": 1, "start_ticks": "200",
            "name": "sshd", "cmdline": "sshd: root@notty", "uid": ["0"],
            "username": "root", "tty_nr": "0",
        })
        self.append("processes.jsonl", {
            "ts": 31, "event": "process_seen", "container_hostname": "database",
            "pid": 101, "host_pid": 1001, "ppid": 100, "start_ticks": "201",
            "name": "touch", "cmdline": "touch /tmp/from-bastion", "uid": ["0"],
            "username": "root", "tty_nr": "0",
            "remote_session": {
                "ssh_connection": "10.10.0.2 51000 10.10.0.25 22",
                "ssh_client": "10.10.0.2 51000 22",
            },
        })
        self.append("processes.jsonl", {
            "ts": 32, "event": "process_gone", "container_hostname": "database",
            "pid": 101, "start_ticks": "201", "name": "touch",
            "cmdline": "touch /tmp/from-bastion", "uid": ["0"],
        })

        monitor.run(once=True)
        action = self.actions(output)[0]

        self.assertEqual(action["agent_origin_host"]["address"], "10.10.0.2")
        self.assertEqual(action["source_host"]["hostname"], "database")
        self.assertEqual(action["execution_host"]["hostname"], "database")
        self.assertEqual([item["host"] for item in action["host_chain"]],
                         ["10.10.0.2", "database"])


if __name__ == "__main__":
    unittest.main()
