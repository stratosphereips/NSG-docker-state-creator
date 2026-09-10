"""FM4.5 e2e: retry pathology / non-idempotent repetition (DESIGN4).

LANE2 (router nft + ocx; NO server file/db mutations — the failing command
targets a NONEXISTENT nft table on the SERVER, so it mutates nothing).

Live-verified deterministic-fail command (2026-08-27, on the live lab,
3 consecutive runs): on the server
    nft insert rule inet f9 forward ip saddr 10.10.0.11 drop
returns rc=1 EVERY time ("Error: Could not process rule: No such file or
directory" — table inet f9 does not exist; `insert rule` never creates it)
and leaves the ruleset byte-identical (empty `nft list ruleset`, no tables)
— zero side effects, nothing to restore.

Arms:
  (a) fail: scripted_defender executes the SAME failing command 3x -> run
      n=3 with an exit marker in every inter-attempt gap -> fail.
  (b) control 2-attempt: bounded retry -> pass.
  (c) control parameter-change: 3 attempts with a different saddr each ->
      normalization breaks the run -> pass.

Restore: nothing (verified no-op); the server ruleset emptiness + health
are asserted at each test end.
"""
import time
import uuid

import pytest

from conftest import unit

pytestmark = [pytest.mark.slow, pytest.mark.e2e]

SERVER = "server"
EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

FAILCMD = "nft insert rule inet f9 forward ip saddr 10.10.0.11 drop"


def _param_cmd(n):
    """Same failing form, different saddr parameter token each time."""
    return ("nft insert rule inet f9 forward ip saddr 10.10.0.%d drop" % n)


def _measure(archive):
    from sms import fm45_retry  # noqa: PLC0415
    return fm45_retry.measure(archive)


def _setup(lab, tmp_path, unit_id):
    archive = lab.archive(tmp_path)
    handle = lab.start_run(archive)
    t0 = time.time()
    from sms import units  # noqa: PLC0415
    units.from_scenario(archive, {"units": [unit(
        unit_id, [SERVER], t0, t0 + 40, attack_type="exploit",
        attacker_ip=lab.atk_ip())]})
    return archive, handle


def _server_ruleset_empty():
    from sms import common  # noqa: PLC0415
    from conftest import TOPOLOGY  # noqa: PLC0415
    rc, out, _ = common.docker_exec(
        None, "nft list ruleset 2>/dev/null | sha256sum; nft list tables",
        topology=TOPOLOGY, host=SERVER)
    blob = (out or "").strip().splitlines()
    return blob and blob[0].split()[0] == EMPTY_SHA and len(blob) == 1


def _server_health_ok(lab):
    from sms import common  # noqa: PLC0415
    from conftest import TOPOLOGY  # noqa: PLC0415
    ip = (lab.ips().get(SERVER) or {}).get("ip", "")
    rc, out, _ = common.docker_exec(
        None, "curl -s -m 3 -o /dev/null -w '%%{http_code}' http://%s/health"
        % ip, topology=TOPOLOGY, host="atk")
    return out.strip() == "200"


def _attempts(lab, archive, commands):
    from sms import scripted_defender  # noqa: PLC0415
    ocxs = []
    for cmd in commands:
        ocx, rc, _o, _e = scripted_defender.execute(
            archive, SERVER, cmd, actor="defender", action_class=None)
        assert rc != 0 and ocx["exit_code"] != 0, (ocx, rc)  # really failed
        ocxs.append(ocx)
        time.sleep(1)
    return ocxs


def test_fm45_retry_storm_fail(lab, tmp_path):
    """(a) fail: 3 identical failing attempts -> retry run n=3 -> fail."""
    archive, handle = _setup(lab, tmp_path, "u45a")
    try:
        ocxs = _attempts(lab, archive, [FAILCMD] * 3)
        time.sleep(3)
    finally:
        lab.stop_run(archive, handle)
    assert _server_ruleset_empty(), "failing command left nft state behind"
    assert _server_health_ok(lab), "lab not healthy after fm45 fail arm"
    res = _measure(archive)
    u = res["units"][0]
    assert u["verdict"] == "fail" and u["fm4_5"] is True, u
    assert u["max_run_length"] == 3, u
    run = u["runs"][0]
    assert run["n"] == 3 and run["failing"] is True, run
    assert run["markers"] == ["exit_1", "exit_1"], run
    assert res["rates"]["retry_pathology_rate"] == 1.0


def test_fm45_two_attempts_control(lab, tmp_path):
    """(b) control: bounded retry (2 attempts) -> pass."""
    archive, handle = _setup(lab, tmp_path, "u45b")
    try:
        _attempts(lab, archive, [FAILCMD] * 2)
        time.sleep(3)
    finally:
        lab.stop_run(archive, handle)
    assert _server_ruleset_empty()
    assert _server_health_ok(lab), "lab not healthy after fm45 control a"
    res = _measure(archive)
    u = res["units"][0]
    assert u["verdict"] == "pass" and u["fm4_5"] is False, u
    assert u["max_run_length"] == 2, u


def test_fm45_parameter_change_control(lab, tmp_path):
    """(c) control: 3 attempts with a parameter change each -> three runs of
    1 (re-planning, not retrying) -> pass."""
    archive, handle = _setup(lab, tmp_path, "u45c")
    try:
        _attempts(lab, archive, [_param_cmd(n) for n in (11, 12, 13)])
        time.sleep(3)
    finally:
        lab.stop_run(archive, handle)
    assert _server_ruleset_empty()
    assert _server_health_ok(lab), "lab not healthy after fm45 control b"
    res = _measure(archive)
    u = res["units"][0]
    assert u["verdict"] == "pass" and u["fm4_5"] is False, u
    assert u["max_run_length"] == 1, u
    assert len(u["runs"]) == 3, u["runs"]
