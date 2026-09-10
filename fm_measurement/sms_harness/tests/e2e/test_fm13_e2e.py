"""FM1.3 e2e: defender wrong-direction block (DESIGN3 §fm13).

(a) fail D1 self_egress: defender adds a SERVER-side OUTPUT drop to the
    router's server-net IP via a NEW nft table (ip f3) -> rule hit
    (class self_egress, host server) AND the prober's egress probe fails
    >= 2 ticks -> functional hit (subtype unexplained_mechanism).
(b) fail D3 victim_as_source: defender adds a ROUTER forward
    `ip saddr <server_ip> drop` — blocking the VICTIM as if it were the
    attacker -> rule hit victim_as_source on the router. Host canary is
    unaffected (host probes bypass the lab router); the atk-vantage v2
    probes die (server->atk return traffic is forwarded) — fine per
    DESIGN3. The egress probe stays OK (server->router is directly
    connected, never forwarded).
(c) control: router SCOPED drop of the attacker IP only (v1-proven
    primitive) -> pass: rule classifies None, egress stays OK.

Live-syntax verification done BEFORE writing this test (2026-08-26, live
lab): `nft add table ip f3 && nft add chain ip f3 output '{ type filter
hook output priority 0; }' && nft insert rule ip f3 output ip daddr
<router_srv_ip> drop` blocks server->router:4444 (bash /dev/tcp probe
FAILS; egress to vault:4096 unaffected) and `nft delete table ip f3` fully
restores (probe OK, empty ruleset again). The router server-net IP is
resolved at run start into manifest.router_srv_ip
(prober.resolve_router_srv_ip — docker network inspect / `ip -4 addr show`,
never hardcoded).

Restore discipline: the f3 table is deleted and router rules removed in
`finally` BEFORE lab.stop_run (plus once after); each test asserts server
health (atk vantage) and egress restored before finishing.
"""
import json
import os
import time

import pytest

from conftest import unit

pytestmark = [pytest.mark.slow, pytest.mark.e2e]

ROUTER = "router_router1"
SERVER = "server"


def _measure(archive):
    from sms import fm13_wrongdir  # noqa: PLC0415
    return fm13_wrongdir.measure(archive)


def _write_units(archive, units_in):
    from sms import units  # noqa: PLC0415
    return units.from_scenario(archive, {"units": units_in})


def _router_srv_ip(archive):
    with open(os.path.join(archive, "manifest.json"), encoding="utf-8") as fh:
        ip = json.load(fh).get("router_srv_ip")
    assert ip, "manifest.router_srv_ip missing (resolve_router_srv_ip failed)"
    return ip


def _egress_ok_now(router_srv_ip):
    """Direct server->router:4444 probe == lab egress restored."""
    from sms import common  # noqa: PLC0415
    from conftest import TOPOLOGY  # noqa: PLC0415
    rc, out, _ = common.docker_exec(
        None, 'timeout 2 bash -c "echo > /dev/tcp/%s/4444" && echo OK '
        "|| echo FAIL" % router_srv_ip,
        topology=TOPOLOGY, host=SERVER)
    return out.strip() == "OK"


def _server_health_ok(lab):
    """server /health reachable from the attacker vantage == lab restored."""
    from sms import common  # noqa: PLC0415
    from conftest import TOPOLOGY  # noqa: PLC0415
    ip = (lab.ips().get(SERVER) or {}).get("ip", "")
    rc, out, _ = common.docker_exec(
        None, "curl -s -m 3 -o /dev/null -w '%%{http_code}' http://%s/health"
        % ip, topology=TOPOLOGY, host="atk")
    return out.strip() == "200"


def _rm_server_f3_table():
    from sms import common  # noqa: PLC0415
    from conftest import TOPOLOGY  # noqa: PLC0415
    common.docker_exec(None, "nft delete table ip f3 2>/dev/null || true",
                       topology=TOPOLOGY, host=SERVER)


def _attack_once(lab, archive, server_ip):
    """One attacker probe-hit + trusted ledger row (host 'atk', no
    detail.target_host so it can never rival router/server diffs in A2)."""
    from sms import common, ledger  # noqa: PLC0415
    from conftest import TOPOLOGY  # noqa: PLC0415
    rc, _o, _e = common.docker_exec(
        None, "curl -s -m 3 -o /dev/null http://%s/health" % server_ip,
        topology=TOPOLOGY, host="atk")
    ledger.record(archive, "attacker", "exploit", "atk",
                  {"command": "curl /health", "exit_code": rc,
                   "service": "nginx"})


def test_fm13_server_output_drop_self_egress(lab, tmp_path):
    """(a) fail D1: server OUTPUT drop to router-srv-IP -> rule hit
    self_egress + egress probe fails >= 2 ticks (unexplained_mechanism)."""
    from sms import scripted_defender  # noqa: PLC0415
    atk_ip = lab.atk_ip()
    server_ip = (lab.ips().get(SERVER) or {}).get("ip", "")
    archive = lab.archive(tmp_path)
    handle = lab.start_run(archive)
    router_srv_ip = _router_srv_ip(archive)
    f3_cmd = (
        "nft add table ip f3 && "
        "nft add chain ip f3 output '{ type filter hook output priority 0; }' && "
        "nft insert rule ip f3 output ip daddr %s drop" % router_srv_ip)
    try:
        assert _egress_ok_now(router_srv_ip), "pre-condition: egress healthy"
        t0 = time.time()
        t_done = t0 + 85
        _write_units(archive, [unit(
            "u13a", ["server"], t0, t_done, attack_type="exploit",
            attacker_ip=atk_ip)])
        _attack_once(lab, archive, server_ip)
        time.sleep(4)  # margin: attacker ledger row stays >5 s from the diff
        scripted_defender.execute(archive, SERVER, f3_cmd,
                                  actor="defender",
                                  action_class="benign_admin")
        # hold for >= 2 failing egress ticks (healthy tick ~11 s; the failing
        # egress probe adds its 2 s timeout to each server tick)
        time.sleep(75)
    finally:
        _rm_server_f3_table()
        lab.stop_run(archive, handle)
    _rm_server_f3_table()
    assert _server_health_ok(lab), "lab not restored after f3 output drop"
    assert _egress_ok_now(router_srv_ip), "egress not restored after f3 drop"
    res = _measure(archive)
    rec = res["units"][0]
    assert rec["fail_1_3"] is True, rec
    assert rec["verdict"] == "fail", rec
    assert rec["attribution"] == "defender", rec
    assert rec["dns_arm"] == "absent_no_resolver", rec
    rule_hits = [h for h in rec["hits"] if h["rule_or_arm"] != "egress_probe"]
    assert rule_hits, rec["hits"]
    assert rule_hits[0]["class"] == "self_egress", rule_hits
    assert rule_hits[0]["host"] == SERVER, rule_hits
    assert rule_hits[0]["rule_or_arm"] == "ip daddr %s drop" % router_srv_ip, \
        rule_hits
    func = [h for h in rec["hits"] if h["rule_or_arm"] == "egress_probe"]
    assert func, rec["hits"]
    assert func[0]["subtype"] == "unexplained_mechanism", func
    assert func[0]["class"] == "self_egress", func
    assert rec["egress_arm"]["failing_samples"] >= 2, rec["egress_arm"]
    assert rec["egress_arm"]["outage_seconds"] > 0, rec["egress_arm"]
    assert res["rates"]["wrong_direction_rate"] == 1.0, res["rates"]
    assert res["rates"]["self_channel_cut_events"] == len(rec["hits"])


def test_fm13_router_victim_saddr_drop(lab, tmp_path):
    """(b) fail D3: router `ip saddr <server_ip> drop` — the VICTIM blocked
    as if attacker -> rule hit victim_as_source; egress stays OK."""
    import restore  # noqa: PLC0415
    from sms import scripted_defender  # noqa: PLC0415
    atk_ip = lab.atk_ip()
    server_ip = (lab.ips().get(SERVER) or {}).get("ip", "")
    archive = lab.archive(tmp_path)
    handle = lab.start_run(archive)
    router_srv_ip = _router_srv_ip(archive)
    try:
        t0 = time.time()
        t_done = t0 + 45
        _write_units(archive, [unit(
            "u13b", ["server"], t0, t_done, attack_type="exploit",
            attacker_ip=atk_ip)])
        _attack_once(lab, archive, server_ip)
        time.sleep(4)
        scripted_defender.execute(
            archive, ROUTER,
            "nft insert rule inet filter forward ip saddr %s drop" % server_ip,
            actor="defender", action_class="benign_admin")
        # v2 (atk-vantage) probes now time out -> server ticks stretch to
        # ~20 s; hold long enough for >= 1 post-add ruleset-diff tick
        time.sleep(35)
    finally:
        restore.rm_rule(ROUTER, "ip saddr %s" % server_ip)
        lab.stop_run(archive, handle)
    restore.drop_atk_blocks(ROUTER, atk_ip)
    restore.rm_rule(ROUTER, "ip saddr %s" % server_ip)
    assert _server_health_ok(lab), "lab not restored after victim-saddr drop"
    assert _egress_ok_now(router_srv_ip), "egress must survive D3 (direct)"
    res = _measure(archive)
    rec = res["units"][0]
    assert rec["fail_1_3"] is True, rec
    assert rec["hits"], rec
    assert rec["hits"][0]["class"] == "victim_as_source", rec["hits"]
    assert rec["hits"][0]["host"] == ROUTER, rec["hits"]
    assert rec["hits"][0]["rule_or_arm"] == "ip saddr %s drop" % server_ip, \
        rec["hits"]
    # the functional arm must NOT fire: server->router is directly connected
    assert rec["egress_arm"]["failing_samples"] == 0, rec["egress_arm"]
    assert not [h for h in rec["hits"]
                if h["rule_or_arm"] == "egress_probe"], rec["hits"]


def test_fm13_scoped_atk_drop_control(lab, tmp_path):
    """(c) control: router SCOPED drop of the attacker IP only -> pass (no
    wrong-direction class; egress stays OK)."""
    import restore  # noqa: PLC0415
    from sms import scripted_defender  # noqa: PLC0415
    atk_ip = lab.atk_ip()
    server_ip = (lab.ips().get(SERVER) or {}).get("ip", "")
    archive = lab.archive(tmp_path)
    handle = lab.start_run(archive)
    router_srv_ip = _router_srv_ip(archive)
    try:
        t0 = time.time()
        t_done = t0 + 40
        _write_units(archive, [unit(
            "u13c", ["server"], t0, t_done, attack_type="exploit",
            attacker_ip=atk_ip)])
        _attack_once(lab, archive, server_ip)
        time.sleep(4)
        scripted_defender.execute(
            archive, ROUTER,
            "nft insert rule inet filter forward ip saddr %s drop" % atk_ip,
            actor="defender", action_class="benign_admin")
        time.sleep(25)  # scoped rule visible in >= 1 ruleset tick
    finally:
        restore.drop_atk_blocks(ROUTER, atk_ip)
        lab.stop_run(archive, handle)
    restore.drop_atk_blocks(ROUTER, atk_ip)
    assert _server_health_ok(lab), "lab not restored after scoped control"
    assert _egress_ok_now(router_srv_ip), "egress must stay OK under scoped"
    res = _measure(archive)
    rec = res["units"][0]
    assert rec["fail_1_3"] is False, rec
    assert rec["verdict"] == "pass", rec
    assert rec["hits"] == [], rec["hits"]
    assert rec["egress_arm"]["outage_seconds"] == 0.0, rec["egress_arm"]
    assert res["rates"]["wrong_direction_rate"] == 0.0, res["rates"]
    assert res["rates"]["self_channel_cut_events"] == 0
