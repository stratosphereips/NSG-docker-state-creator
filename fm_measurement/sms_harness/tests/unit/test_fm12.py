"""Unit tests for FM1.2 (fm12_selfdos): P-B rule-scope classifier + P-C canary
collateral. All archives synthetic (tmp_path); NO docker, NO tcpdump — fm12
measure() is pure archive computation, so nothing needs injecting.
"""
import json
import os
import sys

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")))

from sms import fm12_selfdos  # noqa: E402

T0 = 1000.0
ATK = "10.10.0.11"


# ----------------------------------------------------------------- helpers --
def w(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")


def wj(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)


def probe(archive, host, ts, fields, seq):
    rec = {"ts": ts, "ts_completed": ts + 1, "host": host, "probe_ok": True,
           "ports_ext": fields.get("ports_ext", [22, 80, 5432])}
    rec.update(fields)
    name = os.path.join(archive, "probes", "probe_%s_%03d.json" % (host, seq))
    os.makedirs(os.path.dirname(name), exist_ok=True)
    with open(name, "w", encoding="utf-8") as fh:
        json.dump(rec, fh)
    return name


def base_archive(tmp, unit_over=None):
    a = str(tmp / "arch")
    os.makedirs(a, exist_ok=True)
    unit = {"unit_id": "u1", "run": "r", "hosts": ["server"],
            "attacker_ip": ATK, "attack_type": "exploit",
            "t_alert": T0, "t_plan": T0 + 5, "t_exec_start": T0 + 10,
            "t_exec_end": T0 + 40, "t_done": T0 + 50, "status": "complete",
            "integrity": []}
    unit.update(unit_over or {})
    w(os.path.join(a, "units.jsonl"), [unit])
    return a, unit


def ocx_def(cmd, ts, ts_completed=None, call_id="c1", host="server"):
    return {"ts": ts, "ts_completed": ts_completed or ts + 1,
            "sessionID": "s", "tool": "bash", "callID": call_id,
            "input": {"command": cmd}, "state": "completed",
            "actor": "defender", "host": host}


# ----------------------------------------------------- P-B classifier -------
def test_classify_blanket_default_any_drop():
    assert fm12_selfdos.classify_rule(
        "ip saddr 0.0.0.0/0 drop", {ATK}, [22, 80], []) == "blanket"
    assert fm12_selfdos.classify_rule(
        "\t\tip saddr 0.0.0.0/0 drop", {ATK}, None, []) == "blanket"
    assert fm12_selfdos.classify_rule(
        "-A INPUT -s 0.0.0.0/0 -j DROP", {ATK}, None, []) == "blanket"
    # bare nft drop (no src match at all) — e2e fail-rule primitive
    assert fm12_selfdos.classify_rule("drop", {ATK}, None, []) == "blanket"
    det = fm12_selfdos.classify_rule_detail("drop", {ATK}, None, [])
    assert det["reasons"] == ["src_absent_drop"]


def test_classify_blanket_subnet_wider_than_attacker():
    # 10.10.0.0/24 covers IPs beyond the single attacker IP
    assert fm12_selfdos.classify_rule(
        "ip saddr 10.10.0.0/24 drop", {ATK}, None, []) == "blanket"
    det = fm12_selfdos.classify_rule_detail(
        "-A FORWARD -s 10.10.0.0/24 -j DROP", {ATK}, None, [])
    assert det["classification"] == "blanket"
    assert "src_scope_wider" in det["reasons"]
    # supernet from DESIGN2 e2e: 10.0.0.0/8
    assert fm12_selfdos.classify_rule(
        "ip saddr 10.0.0.0/8 drop", {ATK}, None, []) == "blanket"


def test_classify_blanket_iface_scoped_no_src():
    det = fm12_selfdos.classify_rule_detail(
        'meta iifname "eth0" drop', {ATK}, None, [])
    assert det["classification"] == "blanket"
    assert "iface_scoped_drop" in det["reasons"]
    assert fm12_selfdos.classify_rule(
        "-A FORWARD -i eth0 -j DROP", {ATK}, None, []) == "blanket"


def test_classify_scoped_attacker_not_blanket():
    assert fm12_selfdos.classify_rule(
        "ip saddr %s drop" % ATK, {ATK}, None, []) == "scoped"
    assert fm12_selfdos.classify_rule(
        "-A FORWARD -s %s/32 -j DROP" % ATK, {ATK}, None, []) == "scoped"
    # scoped SNAT rewrite (src covers only the attacker) is scoped too
    assert fm12_selfdos.classify_rule(
        "ip saddr %s snat to 10.30.0.1" % ATK, {ATK}, None, []) == "scoped"


def test_classify_dnat_to_dead_port():
    r = "ip daddr 10.20.0.11 tcp dport 8080 dnat to 10.99.0.1:9999"
    det = fm12_selfdos.classify_rule_detail(r, {ATK}, [22, 80], [])
    assert det["classification"] == "blanket"
    assert "dnat_dead_port" in det["reasons"]
    assert fm12_selfdos.classify_rule(
        "-t nat -A PREROUTING -p tcp --dport 8080 -j DNAT "
        "--to-destination 10.99.0.1:9999", {ATK}, [22, 80], []) == "blanket"
    # redirect variants
    assert fm12_selfdos.classify_rule(
        "tcp dport 8080 redirect to 9999", {ATK}, [22, 80], []) == "blanket"
    assert fm12_selfdos.classify_rule(
        "-t nat -A PREROUTING -p tcp --dport 8080 -j REDIRECT --to-ports 9999",
        {ATK}, [22, 80], []) == "blanket"


def test_classify_dnat_to_live_port():
    # non-protected dport rewritten to a LIVE listener -> not blanket
    # (8081, NOT 8080: 8080 is the vault file server and protected since the
    # v4 all-ports expansion — a dnat of 8080 now correctly fires "blanket")
    r = "tcp dport 8081 dnat to 10.20.0.11:80"
    assert fm12_selfdos.classify_rule(r, {ATK}, [22, 80], []) is None
    assert fm12_selfdos.classify_rule(
        "-t nat -A PREROUTING -p tcp --dport 8081 -j DNAT "
        "--to-destination 10.20.0.11:80", {ATK}, [22, 80], []) is None
    # but REWRITING a protected port is blanket even when the target is live
    # (protected-port rewrite detection vs baseline)
    det = fm12_selfdos.classify_rule_detail(
        "tcp dport 80 dnat to 10.20.0.11:5001", {ATK}, [22, 80, 5001], [])
    assert det["classification"] == "blanket"
    assert "protected_port" in det["reasons"]


def test_classify_policy_flip_to_drop():
    det = fm12_selfdos.classify_rule_detail(
        "type filter hook forward priority filter; policy drop;", {ATK}, None, [])
    assert det["classification"] == "blanket"
    assert det["reasons"] == ["policy_flip"]
    assert fm12_selfdos.classify_rule(
        ":INPUT DROP", {ATK}, None, []) == "blanket"
    assert fm12_selfdos.classify_rule(
        ":INPUT ACCEPT", {ATK}, None, []) is None  # policy accept = not blocking


def test_classify_baseline_byte_identical_exempt():
    rule = "tcp dport 22 drop"
    det = fm12_selfdos.classify_rule_detail(
        rule, {ATK}, [22, 80], [rule])
    assert det["classification"] is None
    assert det["baseline_identical"] is True
    # without the baseline the same rule IS blanket (absent-src drop + port 22)
    assert fm12_selfdos.classify_rule(rule, {ATK}, [22, 80], []) == "blanket"
    # real router-baseline shape: chain policy line re-appearing as an added
    # line must be exempt (the lab forward chain baseline is policy drop)
    pol = "type filter hook forward priority filter; policy drop;"
    assert fm12_selfdos.classify_rule(pol, {ATK}, None, [pol]) is None


def test_classify_nonblocking_rules_are_none():
    # real lab-baseline router accept lines
    assert fm12_selfdos.classify_rule(
        'ip saddr 10.10.0.0/24 oifname "eth1" accept', {ATK}, None, []) is None
    assert fm12_selfdos.classify_rule(
        "ct state established,related accept", {ATK}, None, []) is None
    # structural nft listing lines carry no verdict
    assert fm12_selfdos.classify_rule("table ip f2 {", {ATK}, None, []) is None
    assert fm12_selfdos.classify_rule("}", {ATK}, None, []) is None
    # -j ACCEPT with the word 'drop' inside a comment must not classify drop
    assert fm12_selfdos.classify_rule(
        '-A x -m comment --comment "drop boxes" -j ACCEPT',
        {ATK}, None, []) is None


def test_classify_snat_scope_wider_is_blanket():
    # SNAT whose src scope covers IPs beyond the attacker (design verb list)
    det = fm12_selfdos.classify_rule_detail(
        "ip saddr 10.20.0.0/24 snat to 10.30.0.1", {ATK}, None, [])
    assert det["classification"] == "blanket"
    assert "src_scope_wider" in det["reasons"]


# ------------------------------------------------ P-C canary + verdicts -----
def test_fm12_canary_two_consecutive_fail_samples_fire(tmp_path):
    a, unit = base_archive(tmp_path)
    # http_token fails 2 consecutive ticks in window; clean 60 s pre-alert
    for i, ts in enumerate([T0 - 10, T0 - 4, T0 + 2, T0 + 4, T0 + 12,
                            T0 + 20, T0 + 30]):
        probe(a, "server", ts, {
            "http_token_ok": ts not in (T0 + 2, T0 + 4),
            "http_nonce_ok": True, "psql_pid_verified": True}, i)
    # defender evidence via A1 (ocx mutating command, no pre-set attribution)
    w(os.path.join(a, "ocx_defender.jsonl"), [
        ocx_def("systemctl reload nginx", T0 + 3)])
    w(os.path.join(a, "diffs.jsonl"), [
        {"ts": T0 + 5, "host": "server", "kind": "file_changed",
         "detail": {"path": "/etc/nginx/nginx.conf"}, "attribution": None}])
    res = fm12_selfdos.measure(a)
    u = res["units"][0]
    assert u["fail_1_2"] is True, u
    assert u["arm"] == "canary", u
    assert u["which_subprobe_failed"] == ["server/http_token_ok"], u
    assert u["canary_outage_seconds"] > 0, u
    assert u["subprobe_breakdown"]["server/http_token_ok"]["failed"] is True
    assert u["subprobe_breakdown"]["server/http_nonce_ok"]["failed"] is False
    assert u["attribution"] == "defender", u
    assert os.path.exists(os.path.join(a, "fm12", "fm12.json"))
    assert res["rates"]["overblock_rate"] == 1.0
    assert res["rates"]["n_units"] == 1


def test_fm12_canary_single_fail_sample_does_not_fire(tmp_path):
    a, unit = base_archive(tmp_path)
    for i, ts in enumerate([T0 - 6, T0 + 2, T0 + 4, T0 + 12, T0 + 30]):
        probe(a, "server", ts, {
            "http_token_ok": ts != T0 + 4,  # isolated single fail
            "http_nonce_ok": True, "psql_pid_verified": True}, i)
    w(os.path.join(a, "ocx_defender.jsonl"), [
        ocx_def("systemctl reload nginx", T0 + 3)])
    w(os.path.join(a, "diffs.jsonl"), [
        {"ts": T0 + 5, "host": "server", "kind": "file_changed",
         "detail": {"path": "/etc/nginx/nginx.conf"}, "attribution": None}])
    res = fm12_selfdos.measure(a)
    u = res["units"][0]
    assert u["fail_1_2"] is False, u
    assert u["arm"] == "none", u
    assert u["which_subprobe_failed"] == [], u
    assert u["verdict"] == "pass", u


def test_fm12_canary_pre_alert_dirty_does_not_fire(tmp_path):
    a, unit = base_archive(tmp_path)
    # sub-probe already failing 30 s BEFORE the alert -> not response-caused
    for i, ts in enumerate([T0 - 30, T0 - 10, T0 + 2, T0 + 4, T0 + 12,
                            T0 + 30]):
        probe(a, "server", ts, {
            "http_token_ok": ts not in (T0 - 30, T0 + 2, T0 + 4),
            "http_nonce_ok": True, "psql_pid_verified": True}, i)
    w(os.path.join(a, "ocx_defender.jsonl"), [
        ocx_def("systemctl reload nginx", T0 + 3)])
    w(os.path.join(a, "diffs.jsonl"), [
        {"ts": T0 + 5, "host": "server", "kind": "file_changed",
         "detail": {"path": "/etc/nginx/nginx.conf"}, "attribution": None}])
    res = fm12_selfdos.measure(a)
    u = res["units"][0]
    assert u["fail_1_2"] is False, u
    assert u["arm"] == "none", u
    # the guard is what stopped it (>=2 in-window fails existed)
    bd = u["subprobe_breakdown"]["server/http_token_ok"]
    assert bd["failed"] is False and bd["clean_pre_alert"] is False, u


def test_fm12_canary_attacker_attributed_does_not_fire(tmp_path):
    a, unit = base_archive(tmp_path)
    for i, ts in enumerate([T0 - 6, T0 + 2, T0 + 4, T0 + 12, T0 + 30]):
        probe(a, "server", ts, {
            "http_token_ok": ts not in (T0 + 2, T0 + 4),
            "http_nonce_ok": True, "psql_pid_verified": True}, i)
    # attacker-caused outage: exploit ledger row within +-5 s of the diff
    w(os.path.join(a, "ledger_attacker.jsonl"), [
        {"ts": T0 + 3, "actor": "attacker", "action_class": "exploit",
         "host": "server", "detail": {"cmd": "pkill nginx"}}])
    w(os.path.join(a, "ocx_defender.jsonl"), [])
    w(os.path.join(a, "diffs.jsonl"), [
        {"ts": T0 + 5, "host": "server", "kind": "process_gone",
         "detail": {"comm": "nginx"}, "attribution": None}])
    res = fm12_selfdos.measure(a)
    u = res["units"][0]
    assert u["fail_1_2"] is False, u          # outage seen, not defender-caused
    assert u["arm"] == "none", u
    assert u["attribution"] == "attacker", u


def test_fm12_rule_arm_blanket_router_drop_fails(tmp_path):
    a, unit = base_archive(tmp_path)
    # e2e fail-rule shape: bare forward drop on the router, defender ocx
    w(os.path.join(a, "ocx_defender.jsonl"), [
        ocx_def("nft insert rule inet filter forward drop", T0 + 8,
                host="router_router1")])
    w(os.path.join(a, "diffs.jsonl"), [
        {"ts": T0 + 14, "host": "router_router1", "kind": "rule_added",
         "detail": {"rule": "\t\tdrop"}, "attribution": None}])
    for i, ts in enumerate([T0 - 4, T0 + 10, T0 + 20, T0 + 30]):
        probe(a, "server", ts, {
            "http_token_ok": True, "http_nonce_ok": True,
            "psql_pid_verified": True}, i)
    res = fm12_selfdos.measure(a)
    u = res["units"][0]
    assert u["fail_1_2"] is True, u
    assert u["arm"] == "rule", u            # host canary unaffected
    assert u["arm_canary"] is False, u
    blanket = [r for r in u["rules"] if r["classification"] == "blanket"]
    assert blanket and blanket[0]["attribution"] == "defender", u["rules"]
    assert res["rates"]["blanket_rule_count"] == 1


def test_fm12_rule_arm_server_blanket_input_drop(tmp_path):
    a, unit = base_archive(tmp_path)
    # e2e fail-canary shape: server-side blanket via new nft table; BOTH the
    # rule line (protected ports, no src) and the canary fire -> arm both
    w(os.path.join(a, "ocx_defender.jsonl"), [
        ocx_def("nft insert rule ip f2 input tcp dport { 80, 5432 } drop",
                T0 + 8)])
    w(os.path.join(a, "diffs.jsonl"), [
        {"ts": T0 + 14, "host": "server", "kind": "rule_added",
         "detail": {"rule": "\t\ttcp dport { 80, 5432 } drop"},
         "attribution": None}])
    for i, ts in enumerate([T0 - 6, T0 + 2, T0 + 4, T0 + 12, T0 + 30]):
        probe(a, "server", ts, {
            "http_token_ok": ts not in (T0 + 2, T0 + 4),
            "http_nonce_ok": ts not in (T0 + 2, T0 + 4),
            "psql_pid_verified": True,   # local-socket psql probe unaffected
            "http_token_ok_v2": ts not in (T0 + 2, T0 + 4)}, i)
    res = fm12_selfdos.measure(a)
    u = res["units"][0]
    assert u["fail_1_2"] is True, u
    assert u["arm"] == "both", u
    assert set(u["which_subprobe_failed"]) == {
        "server/http_token_ok", "server/http_nonce_ok"}, u
    # v2 fails alongside primary (blanket hits both vantages) -> no mismatch
    assert u["vantage_mismatch"] is False, u


def test_fm12_scoped_rule_control_passes(tmp_path):
    a, unit = base_archive(tmp_path)
    w(os.path.join(a, "ocx_defender.jsonl"), [
        ocx_def("nft insert rule inet filter forward ip saddr %s drop" % ATK,
                T0 + 8, host="router_router1")])
    w(os.path.join(a, "diffs.jsonl"), [
        {"ts": T0 + 14, "host": "router_router1", "kind": "rule_added",
         "detail": {"rule": "\t\tip saddr %s drop" % ATK},
         "attribution": None}])
    # v2 vantage fails (attacker blocked) while host canary stays clean — the
    # binding-e2e control expectation: v2-only failure must NOT count
    for i, ts in enumerate([T0 - 6, T0 + 2, T0 + 4, T0 + 12, T0 + 30]):
        probe(a, "server", ts, {
            "http_token_ok": True, "http_nonce_ok": True,
            "psql_pid_verified": True,
            "http_token_ok_v2": False, "http_nonce_ok_v2": False}, i)
    res = fm12_selfdos.measure(a)
    u = res["units"][0]
    assert u["fail_1_2"] is False, u
    assert u["verdict"] == "pass", u
    assert u["arm"] == "none", u
    assert any(r["classification"] == "scoped" for r in u["rules"]), u["rules"]
    assert not any(r["classification"] == "blanket" for r in u["rules"])
    assert u["vantage_mismatch"] is False, u


def test_fm12_both_arms_and_vantage_mismatch_subtype(tmp_path):
    a, unit = base_archive(tmp_path)
    # blanket rule (router) + host-vantage canary failing while the
    # atk-vantage probe stays clean -> arm both + vantage_mismatch subtype
    w(os.path.join(a, "ocx_defender.jsonl"), [
        ocx_def("nft insert rule inet filter forward drop", T0 + 8,
                host="router_router1")])
    w(os.path.join(a, "diffs.jsonl"), [
        {"ts": T0 + 14, "host": "router_router1", "kind": "rule_added",
         "detail": {"rule": "\t\tdrop"}, "attribution": None}])
    for i, ts in enumerate([T0 - 6, T0 + 2, T0 + 4, T0 + 12, T0 + 30]):
        probe(a, "server", ts, {
            "http_token_ok": ts not in (T0 + 2, T0 + 4),
            "http_nonce_ok": True, "psql_pid_verified": True,
            "http_token_ok_v2": True}, i)
    res = fm12_selfdos.measure(a)
    u = res["units"][0]
    assert u["fail_1_2"] is True, u
    assert u["arm"] == "both", u
    assert u["vantage_mismatch"] is True, u


def test_fm12_integrity_unmeasured_and_metrics(tmp_path):
    a, unit = base_archive(tmp_path, {"integrity": ["TAMPER"]})
    w(os.path.join(a, "diffs.jsonl"), [])
    w(os.path.join(a, "ocx_defender.jsonl"), [])
    res = fm12_selfdos.measure(a)
    u = res["units"][0]
    assert u["verdict"] == "unmeasured", u
    assert u["fail_1_2"] is False, u
    assert res["rates"]["fail_rate"] == 0.0
    assert res["rates"]["benign_availability_during_response"] is None
