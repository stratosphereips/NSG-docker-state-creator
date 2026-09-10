"""FM6.1 e2e: response refusal. executor_refusal (channel live, no
containment) + control (router DROP -> not_refused) + P1 planner_refusal.
Live topology, no LLM."""
import time

import pytest

from conftest import planner_ok, unit

pytestmark = [pytest.mark.slow, pytest.mark.e2e]

ROUTER = "router_router1"


def _measure(archive):
    from sms import fm61_refusal  # noqa: PLC0415
    return fm61_refusal.measure(archive)


def _brute_burst(lab, attacker_action, n=12):
    """Real atk->server:22 connection bursts (nc connects; hydra-ish shape)."""
    server_ip = (lab.ips().get("server") or {}).get("ip", "")
    attacker_action(
        "for i in $(seq 1 %d); do (echo > /dev/tcp/%s/22) 2>/dev/null; "
        "sleep 0.2; done" % (n, server_ip),
        archive=None, action_class="brute_force", detail={"target": "server:22"})


def _send_markers(lab, marker):
    """3 marker re-probes atk->server:80 after exec_end; record them in
    fm6_marker_probes.jsonl (probe rows carry the marker strings; channel_live
    byte-greps them in the trusted pcaps)."""
    from sms import common  # noqa: PLC0415
    server_ip = (lab.ips().get("server") or {}).get("ip", "")
    probes = []
    for suffix in ("a", "b", "c"):
        mark = "%s%s" % (marker, suffix)
        common.docker_exec(
            None, "curl -s -m 3 -o /dev/null http://%s/nonce?m=%s"
            % (server_ip, mark), topology="fm-defender-lab", host="atk")
        probes.append({"ts": time.time(), "host": "atk", "markers": [mark]})
    return probes


def test_fm61_executor_refusal(lab, scenario, defender, attacker_action):
    """refused=true subtype executor_refusal: unit complete, planner healthy,
    defender read-only, marker channel live in pcaps."""
    t0 = time.time()
    unit_in = unit("u61f", ["server"], t0, t0 + 26,
                   attack_type="brute_force", attacker_ip=lab.atk_ip())
    archive, _ = scenario([unit_in], planner_health=[planner_ok(t0 + 1)])
    handle = lab.start_run(archive)
    res = None
    try:
        _brute_burst(lab, attacker_action)
        from sms import ledger  # noqa: PLC0415
        ledger.record(archive, "attacker", "brute_force", "atk",
                      {"target": "server:22", "detail": "ssh burst"})
        time.sleep(2)
        defender(archive, "server", "uptime", actor="defender",
                 action_class="benign_admin")
        marker = "FM6M%x" % (int(time.time()) % 0xFFFFFFF)
        probes = _send_markers(lab, marker)
        import json  # noqa: PLC0415
        with open(archive + "/fm6_marker_probes.jsonl", "w",
                  encoding="utf-8") as fh:
            for p in probes:
                fh.write(json.dumps(p) + "\n")
        time.sleep(4)
        unit_in["t_done"] = time.time() + 2
        from sms import units  # noqa: PLC0415
        units.from_scenario(archive, {"units": [unit_in]})
        time.sleep(2)
        lab.stop_run(archive, handle)
        handle = None
        res = _measure(archive)
    finally:
        if handle is not None:
            lab.stop_run(archive, handle)
    rec = res["units"][0]
    assert rec["eligible"] is True, rec
    assert rec["refused"] is True, rec
    assert rec["subtype"] == "executor_refusal", rec


def test_fm61_router_drop_control(lab, scenario, defender, attacker_action):
    """control: defender adds router DROP -> refused=false (contained)."""
    import restore  # noqa: PLC0415
    atk_ip = lab.atk_ip()
    t0 = time.time()
    unit_in = unit("u61c", ["server"], t0, t0 + 26,
                   attack_type="brute_force", attacker_ip=atk_ip)
    archive, _ = scenario([unit_in], planner_health=[planner_ok(t0 + 1)])
    handle = lab.start_run(archive)
    res = None
    try:
        _brute_burst(lab, attacker_action)
        from sms import ledger  # noqa: PLC0415
        ledger.record(archive, "attacker", "brute_force", "atk",
                      {"target": "server:22", "detail": "ssh burst"})
        time.sleep(2)
        defender(archive, ROUTER,
                 "nft insert rule inet filter forward ip saddr %s drop" % atk_ip,
                 actor="defender", action_class="benign_admin")
        marker = "FM6C%x" % (int(time.time()) % 0xFFFFFFF)
        probes = _send_markers(lab, marker)
        import json  # noqa: PLC0415
        with open(archive + "/fm6_marker_probes.jsonl", "w",
                  encoding="utf-8") as fh:
            for p in probes:
                fh.write(json.dumps(p) + "\n")
        time.sleep(4)
        unit_in["t_done"] = time.time() + 2
        from sms import units  # noqa: PLC0415
        units.from_scenario(archive, {"units": [unit_in]})
        time.sleep(2)
        lab.stop_run(archive, handle)
        handle = None
        res = _measure(archive)
    finally:
        if handle is not None:
            lab.stop_run(archive, handle)
        restore.drop_atk_blocks(ROUTER, atk_ip)
    rec = res["units"][0]
    assert rec["refused"] is False, rec
    assert rec["subtype"] in ("rule_added", "source_side_containment"), rec


def test_fm61_planner_refusal(lab, scenario, defender):
    """P1: unit alert_only + healthy planner -> planner_refusal."""
    t0 = time.time()
    unit_in = unit("u61p", ["server"], t0, t0 + 20, status="alert_only",
                   attack_type="exploit", attacker_ip=lab.atk_ip(),
                   t_plan=None, t_exec_start=None, t_exec_end=None)
    archive, _ = scenario([unit_in], planner_health=[planner_ok(t0 + 1)])
    handle = lab.start_run(archive)
    res = None
    try:
        # eligibility: real attacker ledger action within +-120 s of t_alert
        from sms import ledger  # noqa: PLC0415
        ledger.record(archive, "attacker", "exploit", "atk",
                      {"target": "server", "detail": "sqli probe"})
        time.sleep(4)
        lab.stop_run(archive, handle)
        handle = None
        res = _measure(archive)
    finally:
        if handle is not None:
            lab.stop_run(archive, handle)
    rec = res["units"][0]
    assert rec["refused"] is True, rec
    assert rec["subtype"] == "planner_refusal", rec
