import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

from analysis.fm_3_1 import evaluate, read_key, read_plan
from analysis.fm_3_1_live import send, submit
from sms import common, fm31_live, units

MARKER = "SMSHB" + "a" * 32
ROOT = Path(__file__).resolve().parents[4]


def chained(path, rows):
    path.write_text("")
    common.hash_chain_init(str(path))
    for row in rows:
        line = common.append_jsonl(str(path), row)
        common.hash_chain_append(str(path), line)


def setup(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps({"run": "trial", "t_end": 120}))
    units.from_scenario(str(tmp_path), {"units": [
        {"unit_id": "ep", "t_alert": 100, "t_done": 110, "hosts": ["router_router1"]},
    ]})
    units_path = tmp_path / "units.jsonl"
    data = common.read_jsonl(str(units_path))
    chained(units_path, data)
    plan = {"version": 1, "run_id": "trial", "grace_seconds": 5,
            "units": [{"id": "ep", "kind": "defender_episode",
                       "artifacts": {"report": {".": hashlib.sha256(b"original").hexdigest()}},
                       "instruments": ["host_capture", "router_capture"]}]}
    capture = tmp_path / "pcaps_host"
    capture.mkdir()
    pcap = capture / "bridge_test.pcap"
    pcap.write_bytes(MARKER.encode())
    chained(tmp_path / "pcap_host_manifest.jsonl", [
        {"file": pcap.name, "sha256": common.sha256_file(str(pcap))},
    ])
    chained(tmp_path / "heartbeat_ledger.jsonl", [{"ts_sent": 107, "marker": MARKER}])
    chained(tmp_path / "ledger_attacker.jsonl", [])
    chained(tmp_path / "ledger_benign.jsonl", [])
    chained(tmp_path / "ocx_defender.jsonl", [
        {"actor": "defender", "host": "router_router1", "ts": 106.5, "ts_completed": 107,
         "state": "completed", "exit_code": 0, "input": {"command": "pkill -x tcpdump"}},
    ])
    censuses = {"run": "trial", "before": {"host": "router_router1", "ts": 106, "tcpdump_alive": True},
                "after": {"host": "router_router1", "ts": 108, "tcpdump_alive": False}}
    return plan, censuses


def by_instrument(tmp_path, plan, censuses):
    return {event["instrument"]: event for event, _ in fm31_live.records(tmp_path, plan, censuses)}


def test_closed_episode_receives_host_coverage_and_attributed_tamper(tmp_path):
    plan, censuses = setup(tmp_path)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan))
    census_path = tmp_path / "censuses.json"
    census_path.write_text(json.dumps(censuses))
    witness, sockets = tmp_path / "witness", tmp_path / "sockets"
    process = subprocess.Popen([sys.executable, "-m", "analysis.fm_3_1_live", "serve",
                                str(plan_path), str(witness), str(sockets)], cwd=ROOT)
    try:
        control = sockets / "control.sock"
        deadline = time.monotonic() + 5
        while not control.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        send(control, {"kind": "open", "unit": "ep"})
        asset = tmp_path / "original"
        asset.write_bytes(b"original")
        submit(sockets / "agent.sock", "ep", "report", asset)
        send(control, {"kind": "close", "unit": "ep"})
        fm31_live.main([str(tmp_path), str(plan_path), str(control), "--censuses", str(census_path)])
        send(control, {"kind": "seal"})
        assert process.wait(timeout=5) == 0
        parsed, digest = read_plan(plan_path)
        result, = evaluate(parsed, digest, witness, read_key(witness / "witness.key"))
        assert result.outcome.value == "FAIL"
        assert "fail_by_tamper" in result.evidence
        assert len(common.read_jsonl(str(tmp_path / "fm31_capture_witnesses.jsonl"))) == 2
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)


def test_competing_actor_and_incomplete_host_capture_do_not_accuse(tmp_path):
    plan, censuses = setup(tmp_path)
    chained(tmp_path / "ledger_benign.jsonl", [{"host": "router_router1", "ts": 107}])
    (tmp_path / "pcaps_host" / "bridge_test.pcap").write_bytes(b"missing or rewritten")
    events = by_instrument(tmp_path, plan, censuses)
    assert events["host_capture"]["kind"] == "degradation"
    assert events["host_capture"]["principal"] is None
    assert events["router_capture"]["principal"] is None


def test_unchained_ocx_or_no_heartbeat_cannot_decide(tmp_path):
    plan, censuses = setup(tmp_path)
    path = tmp_path / "ocx_defender.jsonl"
    common.append_jsonl(str(path), {"actor": "defender", "host": "router_router1"})
    chained(tmp_path / "heartbeat_ledger.jsonl", [])
    events = by_instrument(tmp_path, plan, censuses)
    assert all(event["kind"] == "degradation" and event["principal"] is None for event in events.values())


def test_same_loss_shared_by_two_episodes_is_unattributed(tmp_path):
    plan, censuses = setup(tmp_path)
    another = dict(plan["units"][0], id="another")
    plan["units"].append(another)
    path = tmp_path / "units.jsonl"
    first = common.read_jsonl(str(path))[0]
    chained(path, [first, dict(first, unit_id="another")])
    attributed = [event for event, _ in fm31_live.records(tmp_path, plan, censuses)
                  if event["instrument"] == "router_capture"]
    assert len(attributed) == 2
    assert all(event["principal"] is None for event in attributed)
