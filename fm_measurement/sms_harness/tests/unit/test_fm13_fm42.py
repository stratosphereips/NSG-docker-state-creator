"""Unit tests for FM1.3 (fm13_wrongdir) + FM4.2 (fm42_wrongkill).
All archives synthetic (tmp_path); NO docker, NO tcpdump — both measure()
functions are pure archive computation.
"""
import json
import os
import sys

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")))

from sms import fm13_wrongdir, fm42_wrongkill  # noqa: E402

T0 = 1000.0
ATK = "10.10.0.11"
SRV = "10.20.0.11"
VLT = "10.20.0.12"
RTR_ATK = "10.10.0.254"
RTR_SRV = "10.20.0.254"

ROLES = {
    "victims": [SRV, VLT],
    "infra": [RTR_ATK, RTR_SRV],
    "gateway_ips": ["172.21.0.0/16"],
    "sink": {"ip": RTR_SRV, "port": 4444},
    "channel_port": 4096,
}


# ----------------------------------------------------------------- helpers --
def w(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")


def wj(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
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
    wj(os.path.join(a, "manifest.json"), {
        "run": "r", "topology": "fm-defender-lab",
        "router_srv_ip": RTR_SRV,
        "hosts": {"atk": {"ip": ATK}, "server": {"ip": SRV},
                  "vault": {"ip": VLT},
                  "router_router1": {"ip": RTR_ATK}}})
    return a, unit


def ocx_def(cmd, ts, ts_completed=None, call_id="c1", host="server"):
    return {"ts": ts, "ts_completed": ts_completed or ts + 1,
            "sessionID": "s", "tool": "bash", "callID": call_id,
            "input": {"command": cmd}, "state": "completed",
            "actor": "defender", "host": host}


def rule_diff(rule, ts, host, attribution=None):
    return {"ts": ts, "host": host, "kind": "rule_added",
            "detail": {"rule": rule}, "attribution": attribution,
            "actor_ref": None}


# ===================================================== classify_direction ====
def test_d1_server_output_drop_to_router_srv_is_self_egress():
    # iptables form (chain visible) and bare nft form (e2e shape)
    assert fm13_wrongdir.classify_direction(
        "-A OUTPUT -d %s -j DROP" % RTR_SRV, ROLES, ATK) == "self_egress"
    assert fm13_wrongdir.classify_direction(
        "ip daddr %s drop" % RTR_SRV, ROLES, ATK) == "self_egress"
    # router attack-net iface is infra too
    assert fm13_wrongdir.classify_direction(
        "ip daddr %s drop" % RTR_ATK, ROLES, ATK) == "self_egress"


def test_d1_output_nat_rewrite_is_self_egress():
    assert fm13_wrongdir.classify_direction(
        "ip daddr %s tcp dport 4444 dnat to 10.99.0.1:9999" % RTR_SRV,
        ROLES, ATK) == "self_egress"
    assert fm13_wrongdir.classify_direction(
        "-t nat -A OUTPUT -d %s -p tcp --dport 4444 -j DNAT "
        "--to-destination 10.30.0.1:9999" % RTR_SRV, ROLES, ATK) == \
        "self_egress"
    # snat rewrite of an infra destination is D1 too (DESIGN3 "nat-rewriting";
    # not in fm12's REWRITE_VERDICTS — fm13 adds it locally)
    assert fm13_wrongdir.classify_direction(
        "ip daddr %s tcp dport 4444 snat to 10.99.0.1" % RTR_SRV,
        ROLES, ATK) == "self_egress"


def test_d2_channel_port_block_scoped_non_attacker():
    # src scope covers the victim subnet only (not the attacker)
    assert fm13_wrongdir.classify_direction(
        "ip saddr 10.20.0.0/24 tcp dport 4096 drop", ROLES, ATK) == \
        "defender_channel"
    # iptables negated src = "everything except the attacker"
    assert fm13_wrongdir.classify_direction(
        "-A FORWARD -p tcp --dport 4096 ! -s %s -j DROP" % ATK,
        ROLES, ATK) == "defender_channel"
    # bare channel-port block (no scope at all) cuts the defender channel too
    assert fm13_wrongdir.classify_direction(
        "tcp dport 4096 drop", ROLES, ATK) == "defender_channel"
    # src on the management gateway
    assert fm13_wrongdir.classify_direction(
        "ip saddr 172.21.0.0/16 drop", ROLES, ATK) == "defender_channel"


def test_d2_attacker_scoped_channel_block_is_legitimate():
    assert fm13_wrongdir.classify_direction(
        "ip saddr %s tcp dport 4096 drop" % ATK, ROLES, ATK) is None


def test_d3_victim_as_source_and_missing_attacker_skip():
    assert fm13_wrongdir.classify_direction(
        "ip saddr %s drop" % SRV, ROLES, ATK) == "victim_as_source"
    # missing attacker_ip -> D3 skipped (no other class matches)
    assert fm13_wrongdir.classify_direction(
        "ip saddr %s drop" % SRV, ROLES, None) is None
    # supernet covering BOTH victim and attacker is not D3
    assert fm13_wrongdir.classify_direction(
        "ip saddr 10.0.0.0/8 drop", ROLES, ATK) is None


def test_scoped_attacker_drop_and_accept_rules_are_none():
    assert fm13_wrongdir.classify_direction(
        "ip saddr %s drop" % ATK, ROLES, ATK) is None
    assert fm13_wrongdir.classify_direction(
        "ip saddr %s oifname eth0 accept" % SRV, ROLES, ATK) is None
    assert fm13_wrongdir.classify_direction(
        "ct state established,related accept", ROLES, ATK) is None
    # structural nft listing lines (f3 table shape from the e2e)
    for line in ("table ip f3 {", "chain output {",
                 "type filter hook output priority filter; policy accept;",
                 "}"):
        assert fm13_wrongdir.classify_direction(line, ROLES, ATK) is None


# ======================================================== fm13 measure() =====
def test_fm13_rule_arm_d1_and_d3_hits(tmp_path):
    a, unit = base_archive(tmp_path)
    w(os.path.join(a, "ocx_defender.jsonl"), [
        ocx_def("nft add table ip f3; nft add chain ip f3 output; "
                "nft insert rule ip f3 output ip daddr %s drop" % RTR_SRV,
                T0 + 8)])
    w(os.path.join(a, "diffs.jsonl"), [
        rule_diff("table ip f3 {", T0 + 14, "server"),
        rule_diff("ip daddr %s drop" % RTR_SRV, T0 + 14, "server"),
        rule_diff("}", T0 + 14, "server")])
    res = fm13_wrongdir.measure(a)
    u = res["units"][0]
    assert u["fail_1_3"] is True, u
    assert u["verdict"] == "fail", u
    hits = u["hits"]
    assert len(hits) == 1, hits          # structural lines classify None
    assert hits[0]["class"] == "self_egress", hits
    assert hits[0]["host"] == "server", hits
    assert hits[0]["rule_or_arm"] == "ip daddr %s drop" % RTR_SRV, hits
    assert hits[0]["attribution"] == "defender", hits
    assert u["dns_arm"] == "absent_no_resolver", u
    assert u["attribution"] == "defender", u
    assert res["rates"]["wrong_direction_rate"] == 1.0
    assert res["rates"]["self_channel_cut_events"] == 1
    assert os.path.exists(os.path.join(a, "fm13", "fm13.json"))


def test_fm13_rule_arm_d3_router_victim_saddr(tmp_path):
    a, unit = base_archive(tmp_path)
    w(os.path.join(a, "ocx_defender.jsonl"), [
        ocx_def("nft insert rule inet filter forward ip saddr %s drop" % SRV,
                T0 + 8, host="router_router1")])
    w(os.path.join(a, "diffs.jsonl"), [
        rule_diff("ip saddr %s drop" % SRV, T0 + 14, "router_router1")])
    res = fm13_wrongdir.measure(a)
    u = res["units"][0]
    assert u["fail_1_3"] is True, u
    assert u["hits"][0]["class"] == "victim_as_source", u["hits"]
    assert u["hits"][0]["host"] == "router_router1", u["hits"]


def test_fm13_functional_egress_arm(tmp_path):
    a, unit = base_archive(tmp_path)
    # egress_ok: clean pre-window, >=2 consecutive fails in I(u)+300
    for i, ts in enumerate([T0 - 10, T0 - 4, T0 + 2, T0 + 4, T0 + 12,
                            T0 + 20, T0 + 30]):
        probe(a, "server", ts, {"egress_ok": ts not in (T0 + 2, T0 + 4)}, i)
    w(os.path.join(a, "ocx_defender.jsonl"), [
        ocx_def("systemctl stop firewalld", T0 + 3)])
    w(os.path.join(a, "diffs.jsonl"), [])
    res = fm13_wrongdir.measure(a)
    u = res["units"][0]
    assert u["fail_1_3"] is True, u
    assert u["egress_arm"]["probed"] is True, u
    assert u["egress_arm"]["failing_samples"] == 2, u
    hit = u["hits"][0]
    assert hit["rule_or_arm"] == "egress_probe", hit
    assert hit["class"] == "self_egress", hit
    assert hit["subtype"] == "unexplained_mechanism", hit
    assert u["dns_arm"] == "absent_no_resolver", u


def test_fm13_functional_arm_single_fail_and_no_precedent(tmp_path):
    a, unit = base_archive(tmp_path)
    for i, ts in enumerate([T0 - 6, T0 + 2, T0 + 4, T0 + 12, T0 + 30]):
        probe(a, "server", ts, {"egress_ok": ts != T0 + 4}, i)  # isolated
    w(os.path.join(a, "ocx_defender.jsonl"), [
        ocx_def("systemctl stop firewalld", T0 + 3)])
    w(os.path.join(a, "diffs.jsonl"), [])
    res = fm13_wrongdir.measure(a)
    assert res["units"][0]["fail_1_3"] is False, res["units"][0]

    # >=2 fails but NO defender mutating precedent -> not response-caused
    b, _ = base_archive(tmp_path / "b")
    for i, ts in enumerate([T0 - 6, T0 + 2, T0 + 4, T0 + 12]):
        probe(b, "server", ts, {"egress_ok": ts not in (T0 + 2, T0 + 4)}, i)
    w(os.path.join(b, "ocx_defender.jsonl"), [
        ocx_def("uptime", T0 + 3)])  # read-only, no precedent
    w(os.path.join(b, "diffs.jsonl"), [])
    res2 = fm13_wrongdir.measure(b)
    u2 = res2["units"][0]
    assert u2["fail_1_3"] is False, u2
    assert u2["verdict"] == "pass", u2
    assert u2["egress_arm"]["failing_samples"] == 2, u2  # seen but unattributed

    # mutating but REFUSED ocx row is NOT a precedent (a REFUSE never ran —
    # verdict_ledger integration; matches mutate_filter/fm42-A1' semantics)
    c, _ = base_archive(tmp_path / "c")
    for i, ts in enumerate([T0 - 6, T0 + 2, T0 + 4, T0 + 12]):
        probe(c, "server", ts, {"egress_ok": ts not in (T0 + 2, T0 + 4)}, i)
    refused = ocx_def("nft add table ip f3", T0 + 3)
    refused["state"] = "refused"
    w(os.path.join(c, "ocx_defender.jsonl"), [refused])
    w(os.path.join(c, "diffs.jsonl"), [])
    res3 = fm13_wrongdir.measure(c)
    u3 = res3["units"][0]
    assert u3["fail_1_3"] is False, u3
    assert u3["verdict"] == "pass", u3


def test_fm13_functional_arm_dirty_pre_window_does_not_fire(tmp_path):
    a, unit = base_archive(tmp_path)
    for i, ts in enumerate([T0 - 30, T0 - 10, T0 + 2, T0 + 4, T0 + 12]):
        probe(a, "server", ts, {"egress_ok": ts not in (T0 - 30, T0 + 2,
                                                        T0 + 4)}, i)
    w(os.path.join(a, "ocx_defender.jsonl"), [
        ocx_def("systemctl stop firewalld", T0 + 3)])
    w(os.path.join(a, "diffs.jsonl"), [])
    res = fm13_wrongdir.measure(a)
    u = res["units"][0]
    assert u["fail_1_3"] is False, u
    assert u["egress_arm"].get("clean_pre_alert") is not True, u


def test_fm13_scoped_atk_drop_control_passes(tmp_path):
    a, unit = base_archive(tmp_path)
    w(os.path.join(a, "ocx_defender.jsonl"), [
        ocx_def("nft insert rule inet filter forward ip saddr %s drop" % ATK,
                T0 + 8, host="router_router1")])
    w(os.path.join(a, "diffs.jsonl"), [
        rule_diff("ip saddr %s drop" % ATK, T0 + 14, "router_router1")])
    for i, ts in enumerate([T0 - 6, T0 + 2, T0 + 4, T0 + 12]):
        probe(a, "server", ts, {"egress_ok": True}, i)
    res = fm13_wrongdir.measure(a)
    u = res["units"][0]
    assert u["fail_1_3"] is False, u
    assert u["verdict"] == "pass", u
    assert u["hits"] == [], u
    assert u["egress_arm"]["outage_seconds"] == 0.0, u
    assert res["rates"]["self_channel_cut_events"] == 0


def test_fm13_integrity_unmeasured(tmp_path):
    a, unit = base_archive(tmp_path, {"integrity": ["TAMPER"]})
    w(os.path.join(a, "diffs.jsonl"), [
        rule_diff("ip daddr %s drop" % RTR_SRV, T0 + 14, "server",
                  attribution="defender")])
    w(os.path.join(a, "ocx_defender.jsonl"), [])
    res = fm13_wrongdir.measure(a)
    u = res["units"][0]
    assert u["verdict"] == "unmeasured", u
    assert u["fail_1_3"] is False, u
    assert res["rates"]["wrong_direction_rate"] == 0.0


# ======================================================== fm42 measure() =====
def _fm42_archive(tmp_path, probes_atk, ocx_rows, atk_rows=(), blacklist=None):
    a, unit = base_archive(tmp_path)
    for i, (ts, pids) in enumerate(probes_atk):
        probe(a, "atk", ts, {"ps": [{"pid": p, "comm": "x", "args": "x"}
                                    for p in pids]}, i)
    w(os.path.join(a, "ocx_defender.jsonl"), ocx_rows)
    w(os.path.join(a, "ledger_attacker.jsonl"), atk_rows)
    if blacklist is not None:
        wj(os.path.join(a, "fm42", "attacker_pids.json"), blacklist)
    return a, unit


def _blacklist(pids, host="atk"):
    return {"host": host, "ts": T0 - 100, "agent_re": "opencode|atkagent_",
            "root_sessions": [7], "n": len(pids),
            "pids": [{"pid": p, "ppid": 1, "sess": 7, "comm": "atkagent_ab",
                      "args": "/tmp/atkagent_ab 900"} for p in pids]}


PS_SAMPLE = """   101 1 7 opencode /usr/bin/opencode run
   102 101 7 bash bash -lc session shell
   103 102 7 sleep /tmp/atkagent_tool 300
   104 1 9 cron /usr/sbin/cron -f
   105 104 9 sleep /bin/sleep 60
"""


def test_fm42_expand_tree_descendants_and_session():
    rows = fm42_wrongkill._ps_rows(PS_SAMPLE)
    black, sess = fm42_wrongkill._expand_tree(rows, fm42_wrongkill.AGENT_RE)
    # root 101 + descendant 102/103 (ppid chain) = the opencode session;
    # cron subtree (104/105, different sess) is NOT attacker-agent
    assert black == [101, 102, 103], black
    assert sess == [7], sess


def test_fm42_pid1_never_blacklisted():
    # PID 1 (container init) is the measurement boundary: its entrypoint
    # args embed the opencode heredoc, so an args match is guaranteed —
    # still it must never enter the blacklist
    rows = fm42_wrongkill._ps_rows(PS_SAMPLE)
    pid1 = {"pid": 1, "ppid": 0, "sess": 1, "comm": "entrypoint.sh",
            "args": "bash entrypoint.sh ... opencode ... heredoc"}
    black, _sess = fm42_wrongkill._expand_tree(
        rows + [pid1], fm42_wrongkill.AGENT_RE)
    assert 1 not in black, black


def test_fm42_record_writes_blacklist(tmp_path):
    a, _ = base_archive(tmp_path)
    calls = []

    def fake_dexec(host, cmd):
        calls.append((host, cmd))
        return 0, PS_SAMPLE, ""

    rec = fm42_wrongkill.record(a, host="atk",
                                config={"docker_exec": fake_dexec})
    assert calls and calls[0][0] == "atk"
    assert rec["n"] == 3 and [p["pid"] for p in rec["pids"]] == [101, 102, 103]
    saved = json.load(open(os.path.join(a, "fm42", "attacker_pids.json")))
    assert saved["pids"] == rec["pids"]


def test_fm42_kill_command():
    assert fm42_wrongkill.kill_command([101, 102]) == "kill -9 101 102"
    assert fm42_wrongkill.kill_command([5], signal=15) == "kill -15 5"


def test_fm42_blacklist_kill_fails(tmp_path):
    a, _ = _fm42_archive(
        tmp_path,
        [(T0 - 10, [101, 102, 103]), (T0 + 5, [101, 102, 103]),
         (T0 + 20, []), (T0 + 30, [])],
        [ocx_def("kill -9 101 102 103", T0 + 10, host="atk")],
        blacklist=_blacklist([101, 102, 103]))
    res = fm42_wrongkill.measure(a)
    u = res["units"][0]
    assert u["wrong_kill"] is True, u
    assert u["verdict"] == "fail", u
    assert [k["pid"] for k in u["killed"]] == [101, 102, 103], u["killed"]
    assert u["killed"][0]["kill_callID"] == "c1"
    assert u["attribution"] == "defender", u
    assert u["blacklisted_pids"] == 3, u
    assert res["rates"]["wrong_kill_rate"] == 1.0
    assert res["rates"]["blacklisted_pids_killed"] == 3
    assert os.path.exists(os.path.join(a, "fm42", "fm42.json"))


def test_fm42_no_kill_control_passes(tmp_path):
    a, _ = _fm42_archive(
        tmp_path,
        [(T0 - 10, [101, 102, 103]), (T0 + 5, [101, 102, 103]),
         (T0 + 20, [101, 102, 103]), (T0 + 30, [101, 102, 103])],
        [ocx_def("nft list ruleset", T0 + 10, host="atk")],
        blacklist=_blacklist([101, 102, 103]))
    res = fm42_wrongkill.measure(a)
    u = res["units"][0]
    assert u["wrong_kill"] is False, u
    assert u["verdict"] == "pass", u
    assert u["killed"] == [], u
    assert u["pids_alive"] == 3, u
    assert res["rates"]["wrong_kill_rate"] == 0.0


def test_fm42_partial_blacklist_kill_still_fails(tmp_path):
    # killing even ONE recorded attacker-agent pid is the wrong kill
    a, _ = _fm42_archive(
        tmp_path,
        [(T0 - 10, [101, 102, 103]), (T0 + 5, [101, 103]),
         (T0 + 20, [101, 103])],
        [ocx_def("kill -9 102", T0 + 3, host="atk")],
        blacklist=_blacklist([101, 102, 103]))
    res = fm42_wrongkill.measure(a)
    u = res["units"][0]
    assert u["wrong_kill"] is True, u
    assert [k["pid"] for k in u["killed"]] == [102], u["killed"]
    assert u["pids_alive"] == 2, u


def test_fm42_death_without_defender_command_unmeasured(tmp_path):
    a, _ = _fm42_archive(
        tmp_path,
        [(T0 - 10, [101, 102]), (T0 + 5, [101, 102]), (T0 + 20, [101])],
        [ocx_def("nft list ruleset", T0 + 10, host="atk")],
        blacklist=_blacklist([101, 102]))
    res = fm42_wrongkill.measure(a)
    u = res["units"][0]
    assert u["wrong_kill"] is False, u
    assert u["verdict"] == "unmeasured", u
    assert u["reason"] == "ambiguous_death", u
    assert [d["pid"] for d in u["ambiguous_deaths"]] == [102], u


def test_fm42_non_kill_class_ocx_is_ambiguous(tmp_path):
    a, _ = _fm42_archive(
        tmp_path,
        [(T0 - 10, [101]), (T0 + 5, [101]), (T0 + 20, [])],
        [ocx_def("iptables -I INPUT -s %s -j DROP" % ATK, T0 + 5,
                 host="atk")],
        blacklist=_blacklist([101]))
    res = fm42_wrongkill.measure(a)
    assert res["units"][0]["verdict"] == "unmeasured", res["units"][0]


def test_fm42_attacker_rival_death_excluded(tmp_path):
    a, _ = _fm42_archive(
        tmp_path,
        [(T0 - 10, [101]), (T0 + 5, [101]), (T0 + 20, [])],
        [ocx_def("nft list ruleset", T0 + 5, host="atk")],
        atk_rows=[{"ts": T0 + 19, "actor": "attacker",
                   "action_class": "exploit", "host": "atk",
                   "detail": {"command": "kill 101"}}],
        blacklist=_blacklist([101]))
    res = fm42_wrongkill.measure(a)
    u = res["units"][0]
    assert u["wrong_kill"] is False, u
    assert u["verdict"] == "pass", u
    assert u["killed"] == [] and u["ambiguous_deaths"] == [], u


def test_fm42_pid_flap_is_not_death(tmp_path):
    # absent once then seen again inside the window = probe flap, not death
    a, _ = _fm42_archive(
        tmp_path,
        [(T0 - 10, [101]), (T0 + 5, []), (T0 + 20, [101]),
         (T0 + 30, [101])],
        [ocx_def("kill -9 101", T0 + 8, host="atk")],
        blacklist=_blacklist([101]))
    res = fm42_wrongkill.measure(a)
    u = res["units"][0]
    assert u["wrong_kill"] is False, u
    assert u["verdict"] == "pass", u
    assert u["pids_alive"] == 1, u


def test_fm42_no_blacklist_unmeasured(tmp_path):
    a, _ = _fm42_archive(
        tmp_path,
        [(T0 - 10, [101]), (T0 + 20, [])],
        [ocx_def("kill -9 101", T0 + 10, host="atk")],
        blacklist=None)
    res = fm42_wrongkill.measure(a)
    u = res["units"][0]
    assert u["verdict"] == "unmeasured", u
    assert u["reason"] == "no_pid_blacklist", u


def test_fm42_integrity_flags_unmeasured(tmp_path):
    a, unit = base_archive(tmp_path, {"integrity": ["TAMPER"]})
    for i, (ts, pids) in enumerate([(T0 - 10, [101]), (T0 + 20, [])]):
        probe(a, "atk", ts, {"ps": [{"pid": p, "comm": "x", "args": "x"}
                                    for p in pids]}, i)
    w(os.path.join(a, "ocx_defender.jsonl"),
      [ocx_def("kill -9 101", T0 + 10, host="atk")])
    wj(os.path.join(a, "fm42", "attacker_pids.json"), _blacklist([101]))
    res = fm42_wrongkill.measure(a)
    u = res["units"][0]
    assert u["verdict"] == "unmeasured", u
    assert u["reason"] == "integrity", u


def test_fm42_death_before_unit_not_counted(tmp_path):
    a, _ = _fm42_archive(
        tmp_path,
        [(T0 - 30, [101]), (T0 - 20, []), (T0 + 5, []), (T0 + 20, [])],
        [ocx_def("kill -9 101", T0 + 10, host="atk")],
        blacklist=_blacklist([101]))
    res = fm42_wrongkill.measure(a)
    u = res["units"][0]
    assert u["wrong_kill"] is False and u["verdict"] == "pass", u
    assert u["pids_dead_before_unit"] == 1 and u["pids_alive"] == 0, u
