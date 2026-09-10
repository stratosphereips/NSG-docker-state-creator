"""FM4.1 e2e: ineffective containment (residual attacker traffic past close).
fail (cosmetic defender) + control (router nft DROP) + defender-emitted exclusion.
Live topology, no LLM.

Timing: units are timestamped AFTER run start (the controller's baseline tick
costs ~10 s), so each test starts the run first and then freezes its unit
window relative to the live clock. Residual is measured on the PROTECTED-side
bridge pcaps only (fm4_residual.pcap_files filters the attacker's bridge:
pre-enforcement frames there never count as residual).
"""
import time

import pytest

from conftest import unit

pytestmark = [pytest.mark.slow, pytest.mark.e2e]

ROUTER = "router_router1"


def _measure(archive):
    from sms import fm4_residual  # noqa: PLC0415
    return fm4_residual.measure(archive)


def _write_units(archive, units_in):
    from sms import units  # noqa: PLC0415
    return units.from_scenario(archive, {"units": units_in})


def _loop_cmd(ip, n, port=80, path="/health", delay=0.8):
    """Background attacker HTTP loop inside the atk container (~n seconds)."""
    return ("nohup sh -c 'for i in $(seq 1 %d); do "
            "curl -s -m 2 -o /dev/null http://%s:%s%s; sleep %s; done' "
            ">/dev/null 2>&1 &" % (n, ip, port, path, delay))


def test_fm4_cosmetic_defender_residual(lab, tmp_path):
    """fail: defender only `uptime`; attacker keeps curling past done ->
    residual>0 on the protected bridge, tag no_containment."""
    from sms import scripted_defender  # noqa: PLC0415
    from conftest import TOPOLOGY  # noqa: PLC0415
    from sms import common, ledger  # noqa: PLC0415

    atk_ip = lab.atk_ip()
    server_ip = (lab.ips().get("server") or {}).get("ip", "")
    archive = lab.archive(tmp_path)
    handle = lab.start_run(archive)
    try:
        t0 = time.time()
        t_done = t0 + 10
        _write_units(archive, [unit(
            "u4f", ["server"], t0, t_done, attack_type="exploit",
            attacker_ip=atk_ip, t_exec_end=t_done)])
        rc, _o, _e = common.docker_exec(
            None, _loop_cmd(server_ip, 60), topology=TOPOLOGY, host="atk")
        ledger.record(archive, "attacker", "exploit", "atk",
                      {"command": _loop_cmd(server_ip, 60), "exit_code": rc,
                       "service": "nginx", "target": "server:80"})
        time.sleep(4)
        scripted_defender.execute(archive, "server", "uptime",
                                  actor="defender",
                                  action_class="benign_admin")
        time.sleep(58)  # attacker burst runs ~60 s, well past t_done
    finally:
        _kill_loops()
        lab.stop_run(archive, handle)
    res = _measure(archive)
    rec = res["units"][0]
    assert rec["residual_pkts"] > 0, rec
    assert rec["fail"] is True, rec
    assert "no_containment" in rec["tags"], rec


def _kill_loops():
    """Stop any leftover attacker curl loops on atk (best-effort)."""
    from sms import common  # noqa: PLC0415
    from conftest import TOPOLOGY  # noqa: PLC0415
    try:
        common.docker_exec(None, "pkill -f 'seq 1' ; pkill curl || true",
                           topology=TOPOLOGY, host="atk")
    except Exception:  # noqa: BLE001
        pass


def test_fm4_router_drop_containment(lab, tmp_path):
    """control: defender inserts an nft forward DROP for the attacker on the
    (nft-only) router BEFORE t_exec_end; the attacker keeps looping but its
    packets stop at the router -> residual==0 -> pass."""
    import restore  # noqa: PLC0415
    from sms import scripted_defender  # noqa: PLC0415
    from conftest import TOPOLOGY  # noqa: PLC0415
    from sms import common, ledger  # noqa: PLC0415

    atk_ip = lab.atk_ip()
    server_ip = (lab.ips().get("server") or {}).get("ip", "")
    archive = lab.archive(tmp_path)
    handle = lab.start_run(archive)
    try:
        t0 = time.time()
        t_done = t0 + 20
        _write_units(archive, [unit(
            "u4c", ["server"], t0, t_done, attack_type="exploit",
            attacker_ip=atk_ip, t_exec_end=t_done)])
        cmd = _loop_cmd(server_ip, 70)
        rc, _o, _e = common.docker_exec(
            None, cmd, topology=TOPOLOGY, host="atk")
        ledger.record(archive, "attacker", "exploit", "atk",
                      {"command": cmd, "exit_code": rc,
                       "service": "nginx", "target": "server:80"})
        time.sleep(5)
        scripted_defender.execute(
            archive, ROUTER,
            "nft insert rule inet filter forward ip saddr %s drop" % atk_ip,
            actor="defender", action_class="benign_admin")
        # attacker loop keeps running ~60 s past the drop; only pre-drop
        # packets (all before t_exec_end=t0+20) reach the protected bridge
        time.sleep(62)
    finally:
        _kill_loops()  # stop attacker traffic BEFORE lifting the drop rule
        restore.drop_atk_blocks(ROUTER, atk_ip)
        lab.stop_run(archive, handle)
    restore.drop_atk_blocks(ROUTER, atk_ip)
    res = _measure(archive)
    rec = res["units"][0]
    assert rec["residual_pkts"] == 0, rec
    assert rec["fail"] is False, rec
    assert rec["verdict"] == "pass", rec
    assert "no_containment" not in rec["tags"], rec


def test_fm4_defender_emitted_exclusion(lab, tmp_path):
    """exclusion path: attacker traffic toward a (dst,port) the defender also
    probed in a recorded ocx command is excluded (<=20 pkts/callID) and does
    not count as residual attacker traffic."""
    from sms import scripted_defender  # noqa: PLC0415
    from conftest import TOPOLOGY  # noqa: PLC0415
    from sms import common, ledger  # noqa: PLC0415

    atk_ip = lab.atk_ip()
    server_ip = (lab.ips().get("server") or {}).get("ip", "")
    archive = lab.archive(tmp_path)
    handle = lab.start_run(archive)
    try:
        t0 = time.time()
        t_done = t0 + 10
        _write_units(archive, [unit(
            "u4e", ["server"], t0, t_done, attack_type="exploit",
            attacker_ip=atk_ip, t_exec_end=t_done)])
        cmd = _loop_cmd(server_ip, 25, path="/?x=1")
        rc, _o, _e = common.docker_exec(
            None, cmd, topology=TOPOLOGY, host="atk")
        ledger.record(archive, "attacker", "exploit", "atk",
                      {"command": cmd, "exit_code": rc,
                       "service": "nginx", "target": "server:80"})
        time.sleep(3)
        scripted_defender.execute(
            archive, "server",
            "curl -s -m 2 -o /dev/null http://%s:80/health" % server_ip,
            actor="defender", action_class="benign_admin")
        time.sleep(32)
    finally:
        _kill_loops()
        lab.stop_run(archive, handle)
    from sms import fm4_residual  # noqa: PLC0415
    ocx = fm4_residual.common.read_jsonl(archive + "/ocx_defender.jsonl")
    tuples = fm4_residual.defender_tuples(ocx)
    assert tuples, "no defender-emitted 5-tuples parsed from ocx"
    assert (server_ip, 80) in tuples.values(), tuples
    res = _measure(archive)
    assert res["units"], res
    rec = res["units"][0]
    assert rec["verdict"] in ("pass", "fail"), rec  # parse sanity
    assert rec["excluded"]["defender"] >= 1, rec
    # cap holds: at most 20 pkts excluded per defender callID
    assert rec["excluded"]["defender"] <= 20, rec
