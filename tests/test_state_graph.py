#!/usr/bin/env python3
"""Deterministic extraction tests for the state graph compiler."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "observer" / "lib"))

from stategraph import StateCompiler, write_outputs  # noqa: E402


class StateGraphTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for name in ("network", "files", "sockets", "zeek", "syscalls", "tty", "bcc"):
            (self.root / name).mkdir()

        self.jsonl("processes.jsonl", [
            {"ts": 1, "event": "process_seen", "container_hostname": "agent-box",
             "pid": 1, "ppid": 0, "start_ticks": "10", "name": "python3",
             "cmdline": "python3 /work/agent.py", "exe": "/usr/bin/python3", "cwd": "/work",
             "uid": ["1000", "1000"], "username": "agent"}
        ])
        topology = {
            "ts": 1, "event": "topology_snapshot",
            "addresses": {"ok": True, "data": [{"ifname": "eth0", "addr_info": [
                {"family": "inet", "local": "10.0.0.2", "prefixlen": 24, "scope": "global"}
            ]}]},
            "routes_v4": {"ok": True, "data": [
                {"dst": "default", "gateway": "10.0.0.1", "dev": "eth0"},
                {"dst": "10.0.0.0/24", "dev": "eth0", "scope": "link"}
            ]},
            "routes_v6": {"ok": True, "data": []},
            "neighbors": {"ok": True, "data": [
                {"dst": "10.0.0.1", "lladdr": "00:11:22:33:44:55", "state": ["REACHABLE"],
                 "dev": "eth0"}
            ]},
            "iptables_v4": {"ok": True, "data": "*filter\n-A OUTPUT -d 10.0.0.30/32 -p tcp --dport 443 -j DROP\nCOMMIT\n"},
            "iptables_v6": {"ok": True, "data": ""},
            "nftables": {"ok": True, "data": {"nftables": []}}
        }
        self.jsonl("network/topology.jsonl", [topology])
        self.jsonl("files/events.jsonl", [
            {"ts": 2, "event": "filesystem_event", "path": "/tmp/report.json",
             "operations": ["CREATE", "CLOSE_WRITE"]},
            {"ts": 2.1, "event": "filesystem_event", "path": "/usr/lib/noisy.so",
             "operations": ["OPEN"]}
        ])
        self.jsonl("files/reconciliation.jsonl", [
            {"ts": 3, "event": "file_changed", "path": "/etc/hosts",
             "state": [33188, 0, 0, 42, 1, 1, "abc123"]}
        ])
        self.jsonl("sockets/sockets.jsonl", [
            {"ts": 4, "event": "listener_seen",
             "socket": "tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:((\"python3\",pid=1,fd=3))"}
        ])
        self.jsonl("zeek/conn.log", [
            {"ts": 5, "id.orig_h": "10.0.0.2", "id.orig_p": 40100,
             "id.resp_h": "10.0.0.20", "id.resp_p": 22, "proto": "tcp", "service": "ssh",
             "conn_state": "SF", "orig_pkts": 10, "resp_pkts": 9,
             "local_orig": True, "local_resp": False},
            {"ts": 6, "id.orig_h": "10.0.0.2", "id.orig_p": 40101,
             "id.resp_h": "10.0.0.30", "id.resp_p": 443, "proto": "tcp",
             "conn_state": "S0", "orig_pkts": 3, "resp_pkts": 0,
             "local_orig": True, "local_resp": False},
            {"ts": 6.5, "id.orig_h": "10.0.0.2", "id.orig_p": 0,
             "id.resp_h": "1.1.1.1", "id.resp_p": 0, "proto": "icmp",
             "conn_state": "OTH", "orig_pkts": 1, "resp_pkts": 1,
             "local_orig": True, "local_resp": False}
        ])
        self.jsonl("zeek/ssh.log", [
            {"ts": 5.5, "id.orig_h": "10.0.0.2", "id.orig_p": 40100,
             "id.resp_h": "10.0.0.20", "id.resp_p": 22,
             "auth_success": True, "auth_attempts": 1, "client": "OpenSSH", "server": "OpenSSH",
             "local_orig": True, "local_resp": False}
        ])
        self.jsonl("zeek/dns.log", [
            {"ts": 7, "id.orig_h": "10.0.0.2", "id.orig_p": 45000,
             "id.resp_h": "10.0.0.53", "id.resp_p": 53, "proto": "udp",
             "query": "db.internal", "answers": ["10.0.0.40"], "local_orig": True}
        ])
        self.jsonl("zeek/http.log", [
            {"ts": 8, "uid": "http-1", "id.orig_h": "10.0.0.2", "id.orig_p": 45001,
             "id.resp_h": "10.0.0.20", "id.resp_p": 8080, "method": "GET",
             "host": "10.0.0.20:8080", "uri": "/loot.json", "status_code": 200,
             "response_body_len": 12, "resp_mime_types": ["application/json"],
             "resp_fuids": ["file-1"], "local_orig": True}
        ])
        self.jsonl("tty/commands-1000-1-2.jsonl", [
            {"ts": 9, "event": "command_completed", "uid": 1000, "pid": 2, "sequence": 3,
             "cwd": "/work", "tty": "/dev/pts/0", "exit_status": 0,
             "command": "scp 10.0.0.20:/var/tmp/loot.json /tmp/loot.json"}
        ])
        (self.root / "syscalls" / "trace.1").write_text(
            '10.0 openat(AT_FDCWD</work>, "/tmp/report.json", O_RDONLY) = 3</tmp/report.json> <0.1>\n'
            '10.1 connect(4<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("10.0.0.30")}, 16) = -1 ETIMEDOUT (Connection timed out) <1.0>\n',
            encoding="utf-8"
        )
        self.jsonl("state-assertions.jsonl", [
            {"ts": 11, "type": "known_file", "host": "10.0.0.20",
             "path": "/var/tmp/manual-secret.json", "confidence": 1.0}
        ])

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def jsonl(self, relative: str, records: list[dict]) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")

    def test_operational_extracts_required_state(self) -> None:
        graph = StateCompiler(self.root, "operational").compile()
        summary = graph["summary"]
        self.assertEqual(
            {"known_networks", "known_hosts", "controlled_hosts", "known_data",
             "known_services", "known_blocks", "counts"},
            set(summary)
        )
        self.assertTrue(any(item.get("cidr") == "10.0.0.0/24"
                            for item in summary["known_networks"]))
        self.assertFalse(any(item.get("cidr", "").endswith(("/32", "/128"))
                             for item in summary["known_networks"]))
        self.assertTrue(any(item.get("cidr") == "1.1.1.0/24" and item.get("inferred") is True
                            for item in summary["known_networks"]))
        self.assertTrue(any("1.1.1.1" in item.get("addresses", [])
                            for item in summary["known_hosts"]))
        self.assertTrue(any("10.0.0.20" in item.get("addresses", [])
                            for item in summary["controlled_hosts"]))
        all_data = [item for values in summary["known_data"].values() for item in values]
        self.assertTrue(any(item.get("locator") == "/tmp/report.json" for item in all_data))
        self.assertTrue(any(item.get("locator") == "/var/tmp/manual-secret.json" for item in all_data))
        services = [item for values in summary["known_services"].values() for item in values]
        self.assertTrue(any(item.get("port") == 22 and item.get("service_name") == "ssh"
                            for item in services))
        self.assertTrue(all(item.get("protocol") in {"tcp", "udp", "sctp"}
                            for item in services))
        self.assertFalse(any(item.get("protocol") == "icmp" for item in services))
        self.assertTrue(any(item.get("reason") == "network-no-reply"
                            for item in summary["known_blocks"]))
        self.assertTrue(any(item.get("reason") == "local-firewall-rule"
                            for item in summary["known_blocks"]))

    def test_levels_reduce_graph_and_outputs_are_embedding_ready(self) -> None:
        graphs = {level: StateCompiler(self.root, level).compile()
                  for level in ("forensic", "operational", "strategic")}
        self.assertGreater(len(graphs["forensic"]["nodes"]), len(graphs["strategic"]["nodes"]))
        self.assertGreater(len(graphs["operational"]["nodes"]), len(graphs["strategic"]["nodes"]))
        self.assertIn("record", next(
            evidence for node in graphs["forensic"]["nodes"]
            for evidence in node.get("evidence", []) if "record" in evidence
        ))
        output = self.root / "state"
        write_outputs(graphs["operational"], output)
        self.assertTrue((output / "graph.json").is_file())
        self.assertTrue((output / "summary.json").is_file())
        documents = [json.loads(line) for line in (output / "embedding.jsonl").read_text().splitlines()]
        self.assertEqual(len(documents), len(graphs["operational"]["nodes"])
                         + len(graphs["operational"]["edges"]))
        self.assertTrue(all(item.get("text") for item in documents))


if __name__ == "__main__":
    unittest.main()
