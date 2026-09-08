#!/usr/bin/env python3
"""Tests for resolved state/action/state trajectory summaries."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "observer" / "lib"))

from trajectory_view import transitions  # noqa: E402


class TrajectoryViewTest(unittest.TestCase):
    def write_json(self, path: Path, value: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_resolves_compact_transition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for number, hosts in ((0, ["10.0.0.1"]), (1, ["10.0.0.1", "10.0.0.2"])):
                state_id = f"state-{number:06d}"
                state = root / "states" / state_id
                self.write_json(state / "manifest.json", {
                    "id": state_id, "recorded_at": f"2026-01-01T00:00:0{number}Z",
                    "reason": "initial" if number == 0 else "material-action-change",
                })
                self.write_json(state / "summary.json", {
                    "counts": {"known_hosts": len(hosts)},
                    "known_networks": [{"cidr": "10.0.0.0/24", "confidence": 1.0}],
                    "known_hosts": [{"id": f"host:{host}", "label": host} for host in hosts],
                    "controlled_hosts": [], "known_data": {}, "known_services": {},
                    "known_blocks": [],
                })
            self.write_json(root / "actions" / "scan.json", {
                "id": "action:scan", "type": "network_scan", "scope": "network",
                "started_at": "2026-01-01T00:00:00.1Z",
                "ended_at": "2026-01-01T00:00:00.9Z",
                "command": {"shell_text": "nmap 10.0.0.0/24"},
                "actor": {"pid": 42, "username": "agent"},
                "targets": ["10.0.0.0/24"], "state_changed": True,
                "changed_domains": ["known_hosts"], "exit_status": 0,
            })
            sequence = {
                "sequence": 1, "kind": "action", "id": "action:scan",
                "action_type": "network_scan", "record": "actions/scan.json",
                "state_before": "state-000000", "state_after": "state-000001",
                "state_changed": True,
            }
            (root / "sequence.jsonl").write_text(json.dumps(sequence) + "\n", encoding="utf-8")

            result = transitions(root, limit=10, maximum=8)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["state_before"]["counts"]["known_hosts"], 1)
            self.assertEqual(result[0]["action"]["command"], "nmap 10.0.0.0/24")
            self.assertEqual(result[0]["state_after"]["counts"]["known_hosts"], 2)


if __name__ == "__main__":
    unittest.main()
