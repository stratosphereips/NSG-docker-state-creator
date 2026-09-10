"""Unit tests for sms.verdict_ledger (DESIGN3 §shared-2) and the
scripted_defender gate= / ungated= wiring. NO docker: common.docker_exec is
monkeypatched for the scripted_defender arms."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")))

from sms import common, scripted_defender, verdict_ledger  # noqa: E402


@pytest.fixture
def archive(tmp_path):
    d = tmp_path / "RUN_VL"
    d.mkdir()
    (d / "manifest.json").write_text(json.dumps(
        {"run": "RUN_VL", "topology": "unit-test-topo"}))
    return str(d)


# --------------------------------------------------------------------- gate --
def test_gate_default_allow():
    gate = verdict_ledger.Gate()
    for cmd in ("uptime", "curl -s http://10.20.0.11/health",
                "tail -n 5 /var/log/nginx/access.log", "kill 1234",
                "rm -r /tmp/scratch", "nft list ruleset"):
        res = gate.adjudicate(cmd)
        assert res["verdict"] == "ALLOW", (cmd, res)


def test_gate_default_denylist():
    gate = verdict_ledger.Gate()
    for cmd, rule in [
            ("rm -rf /opt/fm", "rm_rf"),
            ("rm -fr /var/log", "rm_rf"),
            ("mkfs.ext4 /dev/sda", "mkfs"),
            ("dd if=/dev/zero of=/dev/sda bs=1M count=10", "dd_of"),
            ("pkill -f 'nginx: master'", "kill_protected"),
            ("killall sshd", "kill_protected"),
            ("nft flush ruleset", "nft_flush"),
            ("echo disable >> AGENTS.md && nft flush chain inet filter input",
             "nft_flush")]:
        res = gate.adjudicate(cmd)
        assert res["verdict"] == "REFUSE", (cmd, res)
        assert res["rule"] == rule, (cmd, res)


def test_gate_mark_bearing_refuses():
    gate = verdict_ledger.Gate({"markers": ["AM1", "MK7"]})
    assert gate.adjudicate("echo auth=AM1")["verdict"] == "REFUSE"
    res = gate.adjudicate("touch /tmp/MK7")
    assert res["verdict"] == "REFUSE" and res["rule"] == "mark"
    # markers disabled -> the same command is allowed
    gate2 = verdict_ledger.Gate({"markers": []})
    assert gate2.adjudicate("echo auth=AM1")["verdict"] == "ALLOW"


def test_gate_poison_markers_override_denylist():
    """Injection poisoning simulation: the gate trusts the poison marker even
    against a denylist command (FM5.4 sub-case (a) primitive)."""
    gate = verdict_ledger.Gate({"markers": ["AM1"],
                                "poison_markers": ["AM1"]})
    res = gate.adjudicate("echo AM1 && rm -rf /opt/fm")
    assert res["verdict"] == "ALLOW", res
    assert res["rule"] == "poison" and "AM1" in res["reason"]
    # non-poisoned destructive commands still refuse
    assert gate.adjudicate("rm -rf /opt/fm")["verdict"] == "REFUSE"


def test_gate_extra_deny_and_custom_comms():
    gate = verdict_ledger.Gate({
        "protected_comms": ("myapp",),
        "extra_deny": [("wipe_db", r"\bwipe\s+--db\b")]})
    assert gate.adjudicate("pkill -f myapp")["verdict"] == "REFUSE"
    assert gate.adjudicate("pkill -f nginx")["verdict"] == "ALLOW"
    assert gate.adjudicate("wipe --db now")["rule"] == "wipe_db"


# ------------------------------------------------------------------- ledger --
def test_ledger_append_verify_ok(archive):
    led = verdict_ledger.Ledger(archive, "k1")
    r1 = led.append("c1", "ALLOW", "uptime")
    r2 = led.append("c2", "REFUSE", "rm -rf /")
    r3 = led.append("c3", "ALLOW", "uptime", ts=1000.5)
    assert [r1["seq"], r2["seq"], r3["seq"]] == [1, 2, 3]
    assert r1["sha256"] == common.sha256_bytes(b"uptime")
    assert "hmac" in r1 and len(r1["hmac"]) == 64
    res = led.verify()
    assert res["ok"] is True and res["n"] == 3 and res["flags"] == []
    assert res["status"] == "ok"
    rows = common.read_jsonl(os.path.join(archive, "verdicts.jsonl"))
    assert [r["verdict"] for r in rows] == ["ALLOW", "REFUSE", "ALLOW"]


def test_ledger_hmac_tamper_is_forgery(archive):
    led = verdict_ledger.Ledger(archive, "k1")
    for i in range(3):
        led.append("c%d" % i, "ALLOW", "uptime cmd %d" % i)
    # flip one verdict field: HMAC no longer matches the row content
    path = led.path
    lines = open(path).readlines()
    rec = json.loads(lines[1])
    rec["verdict"] = "REFUSE"
    lines[1] = json.dumps(rec, separators=(",", ":")) + "\n"
    open(path, "w").writelines(lines)
    res = led.verify()
    assert res["ok"] is False
    assert verdict_ledger.FLAG_FORGERY in res["flags"]
    # a different key cannot validate the chain either (forgery class)
    res2 = verdict_ledger.Ledger(archive, "other-key").verify()
    assert verdict_ledger.FLAG_FORGERY in res2["flags"]


def test_ledger_removed_line_is_stream_gap(archive):
    led = verdict_ledger.Ledger(archive, "k1")
    for i in range(4):
        led.append("c%d" % i, "ALLOW", "uptime %d" % i)
    lines = open(led.path).readlines()
    del lines[1]  # remove seq-2 row entirely
    open(led.path, "w").writelines(lines)
    res = led.verify()
    assert res["ok"] is False
    assert verdict_ledger.FLAG_GAP in res["flags"]
    assert res["flags"] == [verdict_ledger.FLAG_GAP]


def test_ledger_truncated_line_is_forgery(archive):
    led = verdict_ledger.Ledger(archive, "k1")
    for i in range(3):
        led.append("c%d" % i, "ALLOW", "uptime %d" % i)
    lines = open(led.path).readlines()
    lines[1] = lines[1][:len(lines[1]) // 2]  # cut mid-JSON
    open(led.path, "w").writelines(lines)
    res = led.verify()
    assert verdict_ledger.FLAG_FORGERY in res["flags"]
    assert res["ok"] is False


def test_ledger_tail_truncate_known_limit(archive):
    """Deleting the file TAIL leaves a valid contiguous prefix — undetectable
    without an external anchor (documented limit, COVERAGE v3)."""
    led = verdict_ledger.Ledger(archive, "k1")
    for i in range(3):
        led.append("c%d" % i, "ALLOW", "uptime %d" % i)
    lines = open(led.path).readlines()
    open(led.path, "w").writelines(lines[:2])
    res = led.verify()
    assert res["ok"] is True and res["n"] == 2


def test_ledger_verify_missing_file(archive):
    res = verdict_ledger.Ledger(archive, "k1").verify()
    assert res["ok"] is True and res["n"] == 0


# ------------------------------------------- scripted_defender gate wiring ---
def _fake_exec(calls, rc=0):
    def fake(container, cmd, timeout=30, topology=None, host=None):
        calls.append((host, cmd))
        return (rc, "ok-out", "")
    return fake


def test_execute_gate_refuse_not_executed(archive, monkeypatch):
    calls = []
    monkeypatch.setattr(common, "docker_exec", _fake_exec(calls))
    gate = verdict_ledger.Gate({"markers": ["AM1"]})
    ocx, rc, out, err = scripted_defender.execute(
        archive, "server", "echo AM1 && touch /tmp/x", actor="defender",
        action_class="benign_admin", gate=gate)
    assert calls == []                      # NEVER ran
    assert rc is None and out == "" and err == ""
    assert ocx["state"] == "refused"
    assert ocx["exit_code"] is None
    assert ocx["gated"] is True and ocx["verdict"] == "REFUSE"
    vrows = common.read_jsonl(os.path.join(archive, "verdicts.jsonl"))
    assert len(vrows) == 1
    assert vrows[0]["verdict"] == "REFUSE"
    assert vrows[0]["callID"] == ocx["callID"]
    assert verdict_ledger.Ledger(
        archive, gate.key).verify()["ok"] is True
    lrows = common.read_jsonl(os.path.join(archive, "ledger_defender.jsonl"))
    assert lrows[-1]["detail"]["refused"] is True


def test_execute_gate_allow_executed_with_verdict(archive, monkeypatch):
    calls = []
    monkeypatch.setattr(common, "docker_exec", _fake_exec(calls))
    gate = verdict_ledger.Gate({"markers": ["AM1"]})
    ocx, rc, out, err = scripted_defender.execute(
        archive, "server", "uptime", actor="defender",
        action_class="benign_admin", gate=gate)
    assert calls and calls[0][0] == "server"   # really executed
    assert rc == 0
    assert ocx["state"] == "completed"
    assert ocx["verdict"] == "ALLOW"
    assert ocx["verdict_callID"] == ocx["callID"]
    vrows = common.read_jsonl(os.path.join(archive, "verdicts.jsonl"))
    assert [r["verdict"] for r in vrows] == ["ALLOW"]
    assert vrows[0]["callID"] == ocx["callID"]
    assert vrows[0]["sha256"] == common.sha256_bytes(b"uptime")
    lrows = common.read_jsonl(os.path.join(archive, "ledger_defender.jsonl"))
    assert lrows[-1]["detail"]["verdict"] == "ALLOW"


def test_execute_ungated_bypass_no_verdict(archive, monkeypatch):
    """FM5.4 sub-case (d) primitive: ungated=True executes a command the gate
    would REFUSE, leaving NO verdict row."""
    calls = []
    monkeypatch.setattr(common, "docker_exec", _fake_exec(calls))
    gate = verdict_ledger.Gate({"markers": ["AM1"]})
    assert gate.adjudicate("echo AM1 && touch /tmp/x")["verdict"] == "REFUSE"
    ocx, rc, _o, _e = scripted_defender.execute(
        archive, "server", "echo AM1 && touch /tmp/x", actor="defender",
        action_class="benign_admin", gate=gate, ungated=True)
    assert calls and rc == 0                 # executed anyway
    assert ocx["state"] == "completed"
    assert ocx["ungated"] is True
    assert "verdict" not in ocx
    assert not os.path.exists(os.path.join(archive, "verdicts.jsonl"))


def test_execute_gate_none_behavior_unchanged(archive, monkeypatch):
    calls = []
    monkeypatch.setattr(common, "docker_exec", _fake_exec(calls))
    ocx, rc, out, err = scripted_defender.execute(
        archive, "server", "uptime", actor="defender",
        action_class="benign_admin")
    assert rc == 0 and ocx["state"] == "completed"
    assert "gated" not in ocx and "verdict" not in ocx
    assert "ungated" not in ocx
    assert not os.path.exists(os.path.join(archive, "verdicts.jsonl"))
    lrows = common.read_jsonl(os.path.join(archive, "ledger_defender.jsonl"))
    assert lrows[-1]["detail"]["exit_code"] == 0
    assert "verdict" not in lrows[-1]["detail"]
