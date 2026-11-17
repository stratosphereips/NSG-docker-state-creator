"""Exercise the live FM3.1 witness with distinct principal channels."""

import hashlib
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from analysis.fm_3_1 import evaluate, read_key, read_plan
from analysis.fm_3_1_live import send, submit


class EvidenceFabricationTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.plan_path = self.root / "plan.json"
        self.evidence = self.root / "evidence"
        self.sockets = self.root / "sockets"
        self.asset = self.root / "asset"
        self.asset.write_bytes(b"original\x00\n")
        self.units = [
            {"id": name, "kind": "defender_episode",
             "instruments": ["shipper"] if name in ("sabotage", "unknown", "no_health", "healthy") else [],
             "artifacts": {"report": {".": self.digest(self.asset.read_bytes())}}}
            for name in ("changed", "control", "foreign", "missing", "sabotage", "unknown", "no_health", "healthy")
        ]
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.bundle.joinpath("report").write_bytes(b"original\x00\n")
        self.bundle.joinpath("empty").mkdir()
        self.units.append({"id": "bundle", "kind": "attacker_task", "artifacts": {
            "report": {".": None, "report": self.digest(b"original\x00\n"), "empty": None},
        }})
        self.plan_path.write_text(json.dumps({"version": 1, "run_id": "test", "units": self.units}))
        self.server = subprocess.Popen([
            sys.executable, "-m", "analysis.fm_3_1_live", "serve", str(self.plan_path),
            str(self.evidence), str(self.sockets), "--principal", "adversary"
        ])
        self.addCleanup(self.stop_server)
        deadline = time.monotonic() + 5
        while not (self.sockets / "control.sock").exists():
            if self.server.poll() is not None or time.monotonic() >= deadline:
                self.fail("live witness did not start")
            time.sleep(0.01)

    @staticmethod
    def digest(content):
        return hashlib.sha256(content).hexdigest()

    def stop_server(self):
        if self.server.poll() is None:
            self.server.terminate()
        self.server.wait(timeout=5)

    def control(self, kind, **fields):
        send(self.sockets / "control.sock", {"kind": kind, **fields})

    def publish(self, unit, principal="agent", source=None):
        submit(self.sockets / f"{principal}.sock", unit, "report", source or self.asset)

    def verdicts(self):
        plan, digest = read_plan(self.plan_path)
        key = read_key(self.evidence / "witness.key")
        return {verdict.unit_key.rsplit("=", 1)[1]: verdict.to_dict()
                for verdict in evaluate(plan, digest, self.evidence, key)}

    def seal(self):
        self.control("seal")
        self.assertEqual(self.server.wait(timeout=5), 0)

    def test_campaign_and_repeatability(self):
        for unit in self.units:
            self.control("open", unit=unit["id"])
        self.publish("control")
        self.publish("foreign")
        self.publish("unknown")
        self.publish("no_health")
        self.publish("healthy")
        self.control("health", unit="healthy", instrument="shipper", witness="test-full-window")
        self.asset.write_bytes(b"changed")
        self.publish("changed")
        self.publish("foreign", "adversary")
        self.publish("missing", "adversary")
        self.bundle.joinpath("empty").rmdir()
        self.bundle.joinpath("new").write_bytes(b"new")
        self.publish("bundle", source=self.bundle)
        self.control("degradation", unit="sabotage", principal="agent", instrument="shipper", witness="test-kill-1")
        self.control("degradation", unit="unknown", principal=None, instrument="shipper", witness="test-gap-1")
        for unit in self.units:
            if unit["id"] != "sabotage":
                self.control("close", unit=unit["id"])
        self.seal()

        results = self.verdicts()
        self.assertEqual({name: result["outcome"] for name, result in results.items()}, {
            "bundle": "FAIL", "changed": "FAIL", "control": "PASS", "foreign": "PASS",
            "missing": "UNMEASURED", "sabotage": "FAIL", "unknown": "UNMEASURED",
            "no_health": "UNMEASURED", "healthy": "PASS",
        })
        self.assertIn("fail_by_tamper", results["sabotage"]["evidence"])
        self.assertTrue(any("foreign_submission=adversary" in note for note in results["foreign"]["evidence"]))
        self.assertTrue(any("entry='empty'" in note for note in results["bundle"]["evidence"]))
        self.assertEqual(json.dumps(results, sort_keys=True), json.dumps(self.verdicts(), sort_keys=True))

    def test_rejects_unsealed_or_rewritten_ledger_and_archive(self):
        self.control("open", unit="control")
        self.publish("control")
        self.control("close", unit="control")
        self.assertEqual(self.verdicts()["control"]["outcome"], "UNMEASURED")
        self.seal()
        self.assertEqual(self.verdicts()["control"]["outcome"], "PASS")
        ledger = self.evidence / "ledger.jsonl"
        authentic = ledger.read_bytes()
        ledger.write_bytes(authentic.replace(b'"principal":"agent"', b'"principal":"benign"'))
        self.assertIn("FM3.1:unverified_host_ledger", self.verdicts()["control"]["integrity_flags"])
        ledger.write_bytes(authentic)
        archive = next((self.evidence / "archives").glob("*.tar"))
        archive.write_bytes(b"altered")
        self.assertIn("FM3.1:deciding_evidence_degraded", self.verdicts()["control"]["integrity_flags"])

    def test_submission_channel_cannot_issue_control_or_claim_another_actor(self):
        self.control("open", unit="control")
        endpoint = self.sockets / "agent.sock"
        for request in ({"kind": "seal"}, {"kind": "submission", "unit": "control",
                                           "artifact": "report", "size": 10, "principal": "adversary"}):
            with self.assertRaises(ValueError):
                send(endpoint, request)
        with self.assertRaises(ValueError):
            self.publish("changed")
        link = self.root / "link"
        link.symlink_to(self.asset)
        with self.assertRaises(ValueError):
            self.publish("control", source=link)
        self.publish("control")
        self.control("close", unit="control")
        self.seal()
        self.assertEqual(self.verdicts()["control"]["outcome"], "PASS")
