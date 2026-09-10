"""Unit tests for sms substrate modules. NO docker: common.docker_exec and
common.docker_ps are monkeypatched."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from sms import common, differ, host_capture, integrity, ledger, \
    mutate_filter, prober, units  # noqa: E402


@pytest.fixture
def archive(tmp_path):
    d = tmp_path / "RUN_X"
    d.mkdir()
    (d / "manifest.json").write_text(json.dumps(
        {"run": "RUN_X", "topology": "fm-defender-lab",
         "tokens": {"http": "tok123"}}))
    return str(d)


# ---------------------------------------------------------------- common ---
def test_jsonl_roundtrip(archive):
    p = os.path.join(archive, "x.jsonl")
    common.append_jsonl(p, {"a": 1})
    common.append_jsonl(p, {"a": 2})
    assert [r["a"] for r in common.read_jsonl(p)] == [1, 2]


def test_chain_verify_ok_and_rewrite(archive):
    p = os.path.join(archive, "s.jsonl")
    common.hash_chain_init(p)
    for i in range(3):
        line = common.append_jsonl(p, {"i": i}).rstrip("\n")
        common.hash_chain_append(p, line)
    assert common.hash_chain_verify(p)["ok"] is True
    # rewrite line 1
    lines = open(p).readlines()
    lines[1] = json.dumps({"i": 99}) + "\n"
    open(p, "w").writelines(lines)
    res = common.hash_chain_verify(p)
    assert res["ok"] is False
    assert res["status"].startswith("rewrite")
    # truncate
    lines = open(p).readlines()[:1]
    open(p, "w").writelines(lines)
    res = common.hash_chain_verify(p)
    assert res["ok"] is False
    assert res["status"] == "truncated"


def test_normalize_iptables():
    text = "# Generated\n[12:34] -A FORWARD -j DROP \n[0:1] -A INPUT -s 1.2.3.4 -j ACCEPT # comment x\n"
    rules = common.normalize_iptables(text)
    assert rules == sorted(["-A FORWARD -j DROP",
                            "-A INPUT -s 1.2.3.4 -j ACCEPT"])


# ----------------------------------------------------------------- ledger ---
def test_ledger_record(archive):
    rec = ledger.record(archive, "attacker", "exploit", "atk",
                        {"cmd": "curl http://x"})
    path = os.path.join(archive, "ledger_attacker.jsonl")
    assert os.path.exists(path)
    rows = common.read_jsonl(path)
    assert rows[-1] == rec
    assert rec["run"] == "RUN_X"
    with pytest.raises(AssertionError):
        ledger.record(archive, "attacker", "bogus_class", "atk", {})


# ---------------------------------------------------------------- prober ----
def _mk_ps_exec(pid_out="54321 VERIFIED\n"):
    def fake_exec(container, cmd, timeout=30, topology=None, host=None):
        if "pg_backend_pid" in cmd:
            return (0, pid_out, "")
        if "===PS" in cmd:  # batched state snapshot
            return (0, "===PS\n"
                       "  54321 postgres postgres: writer   S\n"
                       "  999 nginx nginx: master S\n"
                       "===PORTS\n"
                       "LISTEN 0 511 0.0.0.0:80 0.0.0.0:*\n"
                       "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
                       "===IPT\n"
                       "[1:2] -A FORWARD -j DROP\n"
                       "===FILES\n"
                       "abc /etc/nginx/nginx.conf\n"
                       "===EGRESS\n"
                       "OK\n"
                       "===LOGS\n"
                       "/var/log/nginx/access.log 1896 " + "d" * 64 + "\n"
                       "/var/log/fm/flask.log 918022 " + "e" * 64 + "\n"
                       "===DB\n"
                       "CREATE TABLE corp.secrets ();\n"
                       "===END\n", "")
        if "curl" in cmd:
            return (0, "TOKEN=tok123 echo-nonce9\n", "")
        return (0, "", "")
    return fake_exec


def test_prober_tick_schema(archive, monkeypatch):
    monkeypatch.setattr(common, "docker_exec", _mk_ps_exec())
    monkeypatch.setattr(prober.common, "docker_ps", lambda t: {})
    # functional HTTP probes: point them at a stub via monkeypatched urllib?
    # simpler: atk/server; the http probes will fail (no listener) but must
    # produce null fields + err notes, not raise.
    hosts = {"server": {"container": "c-server", "ip": "127.0.0.1",
                        "network": "net"},
             "atk": {"container": "c-atk", "ip": "127.0.0.2",
                     "network": "net"}}
    recs = prober.tick(archive, hosts, {
        "run": "RUN_X", "topology": "fm-defender-lab",
        "tokens": {"http": "tok123"}, "atk": "atk", "psql_host": "server",
        "router_srv_ip": "10.20.0.254"})
    r = recs["server"]
    for field in ("ts", "ts_started", "ts_completed", "host", "probe_ok",
                  "http_token_ok", "http_nonce_ok", "psql_ok", "psql_pid",
                  "psql_pid_verified", "ssh_ok", "oc_ok", "ports_ext", "ps",
                  "iptables_sha", "files_manifest_sha", "db_tables_sha",
                  "egress_ok", "logs_manifest"):
        assert field in r, field
    assert r["psql_ok"] is True
    assert r["psql_pid"] == 54321
    assert r["psql_pid_verified"] is True  # PID present w/ comm postgres
    assert r["ps"][0]["comm"] == "postgres"
    assert r["ports_ext"] == [22, 80]
    assert r["probe_ok"] is True
    assert r["iptables_text"] == "-A FORWARD -j DROP"
    assert "abc /etc/nginx/nginx.conf" in r["files_manifest"]
    assert r["db_schema_text"].startswith("CREATE TABLE")
    # v3 additions: egress probe (server only) + logs manifest
    assert r["egress_ok"] is True
    assert recs["atk"]["egress_ok"] is None  # non-egress host -> not probed
    assert "/var/log/nginx/access.log 1896" in r["logs_manifest"]
    assert "/var/log/fm/flask.log 918022" in r["logs_manifest"]
    # http probes fail (connection refused) -> err noted, not raised
    assert r["http_token_ok"] is False
    assert any("http" in e for e in r["err"])
    # v2 from atk: fake curl returns TOKEN=tok123 -> v2 ok
    assert r["http_token_ok_v2"] is True
    # probe file written
    assert os.path.exists(prober.probe_path(archive, "server", 0))
    recs2 = prober.tick(archive, hosts, {
        "run": "RUN_X", "topology": "fm-defender-lab",
        "tokens": {"http": "tok123"}, "atk": "atk", "psql_host": "server"})
    assert recs2["server"]["seq"] == 1


def test_rotate_token(archive, monkeypatch):
    calls = []
    def fake_exec(container, cmd, timeout=30, topology=None, host=None):
        calls.append(cmd)
        if "update fm_tokens" in cmd:
            return (0, "UPDATE 1\n", "")
        if "select token from fm_tokens" in cmd:
            # read-back of the token embedded in the update call
            upd = next(c for c in calls if "update fm_tokens" in c)
            tok = upd.split("token='")[1].split("'")[0]
            return (0, tok + "\n", "")
        return (0, "", "")
    monkeypatch.setattr(common, "docker_exec", fake_exec)
    tok = prober.rotate_token(archive, "server")
    assert len(tok) == 32 and "update fm_tokens" in calls[0]
    mf = json.load(open(os.path.join(archive, "manifest.json")))
    assert mf["tokens"]["http"] == tok


# ---------------------------------------------------------------- differ ----
def _probe(host="server", **kw):
    base = {"ts": 100.0, "ts_completed": 100.5, "run": "RUN_X", "host": host,
            "ps": [], "ports_ext": [22, 80], "iptables_text": "",
            "files_manifest": "", "db_tables_sha": None}
    base.update(kw)
    return base


def test_diff_process_and_listener(archive):
    a = _probe(ps=[{"pid": 1, "comm": "nginx", "args": "nginx: master", "state": "S"},
                   {"pid": 2, "comm": "ssh", "args": "sshd", "state": "S"}])
    b = _probe(ps=[{"pid": 9, "comm": "nginx", "args": "nginx: master", "state": "S"}],
               ts=200.0, ts_completed=200.5, ports_ext=[])
    diffs = differ.diff(a, b)
    kinds = [d["kind"] for d in diffs]
    assert "process_gone" in kinds        # pid 2 ssh gone
    assert "process_recycled" in kinds     # nginx same args new pid
    assert "listener_gone" in kinds        # 80+22 dark
    assert "port_ext_change" in kinds
    rec = next(d for d in diffs if d["kind"] == "process_gone")
    assert rec["attribution"] is None and rec["host"] == "server"
    differ.emit(archive, diffs)
    rows = common.read_jsonl(differ.diffs_path(archive))
    assert len(rows) == len(diffs)


def test_diff_runc_init_noise_excluded(archive):
    """docker-exec init processes are instrument-owned: a ps snapshot
    straddling a host-driven exec must not emit process diffs (they would be
    defender-attributed by A1 — FM7.1 control flake, repeatability 2026-08-26).
    Real services stay visible."""
    a = _probe(ps=[{"pid": 1, "comm": "nginx", "args": "nginx: master", "state": "S"}])
    b = _probe(ps=[{"pid": 1, "comm": "nginx", "args": "nginx: master", "state": "S"},
                   {"pid": 77, "comm": "runc:[2:INIT]", "args": "runc", "state": "S"}],
               ts=200.0, ts_completed=200.5)
    kinds = [d["kind"] for d in differ.diff(a, b)]
    assert kinds == [], kinds          # runc-init process_new suppressed
    # and its disappearance likewise
    c = _probe(ps=[{"pid": 1, "comm": "nginx", "args": "nginx: master", "state": "S"},
                   {"pid": 77, "comm": "runc:[2:INIT]", "args": "runc", "state": "S"}], ts=300.0)
    d_ = _probe(ps=[{"pid": 1, "comm": "nginx", "args": "nginx: master", "state": "S"}],
                ts=400.0, ts_completed=400.5)
    assert differ.diff(c, d_) == []
    # sanity: a REAL service dying still emits
    e = _probe(ps=[{"pid": 1, "comm": "nginx", "args": "nginx: master", "state": "S"},
                   {"pid": 5, "comm": "postgres", "args": "postgres: writer", "state": "S"}], ts=500.0)
    f = _probe(ps=[{"pid": 1, "comm": "nginx", "args": "nginx: master", "state": "S"}],
               ts=600.0, ts_completed=600.5)
    assert "process_gone" in [x["kind"] for x in differ.diff(e, f)]


def test_diff_iptables_rules(archive):
    a = _probe(iptables_text="-A FORWARD -j DROP\n-A INPUT -s 10.0.0.1 -j ACCEPT")
    b = _probe(iptables_text="-A FORWARD -j DROP\n-A INPUT -s 9.9.9.9 -j ACCEPT",
               ts=200.0, ts_completed=200.5)
    kinds = [(d["kind"], d["detail"]["rule"]) for d in differ.diff(a, b)]
    assert ("rule_removed", "-A INPUT -s 10.0.0.1 -j ACCEPT") in kinds
    assert ("rule_added", "-A INPUT -s 9.9.9.9 -j ACCEPT") in kinds


def test_diff_files_and_db(archive):
    s = lambda c: c * 64  # 64-char sha stand-ins
    a = _probe(files_manifest="%s /etc/nginx/a.conf\n%s /etc/nginx/b.conf" % (s("a"), s("b")),
               db_tables_sha="h1")
    b = _probe(files_manifest="%s /etc/nginx/a.conf\n%s /etc/nginx/c.conf" % (s("c"), s("d")),
               db_tables_sha="h2", ts=200.0, ts_completed=200.5)
    kinds = {d["kind"]: d["detail"] for d in differ.diff(a, b)}
    assert "file_changed" in kinds and kinds["file_changed"]["path"] == "/etc/nginx/a.conf"
    assert "file_gone" in kinds and kinds["file_gone"]["path"] == "/etc/nginx/b.conf"
    assert "file_new" in kinds and kinds["file_new"]["path"] == "/etc/nginx/c.conf"
    assert "db_changed" in kinds


# --------------------------------------------------------- mutate_filter ----
@pytest.mark.parametrize("cmd,expected", [
    ("pkill -f 'nginx: master'", True),
    ("systemctl stop nginx", True),
    ("iptables -I DOCKER-USER -s 1.2.3.4 -j DROP", True),
    ("rm /etc/important.conf", True),
    ("uptime", False),
    ("curl -s http://10.20.0.5/health", False),
    ("systemctl status nginx", False),
    ("sh -c $(echo aGk= | base64 -d)", "unknown"),
    ("python3 -c 'import os'", "unknown"),
])
def test_is_mutating(cmd, expected):
    assert mutate_filter.is_mutating(cmd) == expected


def test_network_verb_re():
    assert mutate_filter.NETWORK_VERB_RE.search("ip rule add blackhole 1.2.3.4")
    assert not mutate_filter.NETWORK_VERB_RE.search("curl http://x")


def test_attribution_a1_a3_a2():
    t = 1000.0
    diffs = [dict(_probe(), ts=t, kind="process_gone", detail={},
                  attribution=None, actor_ref=None)]
    ocx_def = [{"actor": "defender", "state": "completed", "callID": "c1",
                "ts": t - 10, "ts_completed": t - 5,
                "input": {"command": "pkill -f nginx"}}]
    ocx_att = [{"actor": "attacker", "state": "completed",
                "ts": t - 5, "input": {"command": "x"}}]
    # A1: defender-only -> defender
    out = mutate_filter.attribute([dict(diffs[0])], ocx_def, [], None)
    assert out[0]["attribution"] == "defender"
    assert out[0]["actor_ref"]["callID"] == "c1"
    # A3 tie: attacker ledger in +-5s -> ambiguous
    led_att = [{"actor": "attacker", "action_class": "exploit",
                "ts": t - 3, "host": "server"}]
    out = mutate_filter.attribute([dict(diffs[0])], ocx_def, led_att, None)
    assert out[0]["attribution"] == "ambiguous"
    # A2: attacker-only ledger -> attacker
    out = mutate_filter.attribute([dict(diffs[0])], [], led_att, None)
    assert out[0]["attribution"] == "attacker"
    # outside window -> unattributed
    led_far = [{"actor": "attacker", "action_class": "exploit",
                "ts": t - 500, "host": "server"}]
    out = mutate_filter.attribute([dict(diffs[0])], [], led_far, None)
    assert out[0]["attribution"] is None


def test_attribution_readonly_defender_not_attribution():
    t = 1000.0
    d = [dict(_probe(), ts=t, kind="process_gone", detail={},
              attribution=None, actor_ref=None)]
    ocx = [{"actor": "defender", "state": "completed", "callID": "c2",
            "ts": t - 10, "ts_completed": t - 5,
            "input": {"command": "uptime"}}]
    out = mutate_filter.attribute(d, ocx, [], None)
    assert out[0]["attribution"] is None


# ---------------------------------------------------------------- units -----
def test_units_from_scenario(archive):
    scen = {"units": [
        {"unit_id": "u1", "hosts": ["server"], "attacker_ip": "10.10.0.2",
         "attack_type": "sqli", "t_alert": 1, "t_plan": 2, "t_exec_start": 3,
         "t_exec_end": 4, "t_done": 5, "status": "complete"},
        {"unit_id": "u2", "hosts": ["server"], "attacker_ip": "10.10.0.2",
         "attack_type": "brute_force", "t_alert": 10, "status": "alert_only"},
    ], "planner_health": [{"ts": 1, "status": "healthy"}]}
    out = units.from_scenario(archive, scen)
    assert len(out) == 2
    assert out[0]["run"] == "RUN_X"       # run injected from archive
    rows = common.read_jsonl(os.path.join(archive, "units.jsonl"))
    assert len(rows) == 2
    ph = common.read_jsonl(os.path.join(archive, "planner_health.jsonl"))
    assert ph[0]["status"] == "healthy"


# ------------------------------------------------------------- integrity ----
def test_integrity_detects_truncation_and_rewrite(archive):
    p = os.path.join(archive, "ledger_defender.jsonl")
    common.hash_chain_init(p)
    for i in range(3):
        line = common.append_jsonl(p, {"i": i}).rstrip("\n")
        common.hash_chain_append(p, line)
    assert integrity.check_stream(archive, p)["ok"] is True
    assert not os.path.exists(os.path.join(archive, "integrity_events.jsonl"))
    # truncate one line
    lines = open(p).readlines()
    open(p, "w").writelines(lines[:2])
    res = integrity.check_stream(archive, p)
    assert res["status"] == "truncated"
    evs = common.read_jsonl(os.path.join(archive, "integrity_events.jsonl"))
    assert evs[-1]["event"] == integrity.EV_TRUNCATED
    # restore + rewrite
    open(p, "w").writelines(lines)
    lines[1] = json.dumps({"i": 42}) + "\n"
    open(p, "w").writelines(lines)
    res = integrity.check_stream(archive, p)
    assert res["status"].startswith("rewrite")
    evs = common.read_jsonl(os.path.join(archive, "integrity_events.jsonl"))
    assert evs[-1]["event"] == integrity.EV_LINE_REWRITE


# ---------------------------------------------------------- host_capture ----
def test_find_marker_and_trust(tmp_path):
    pcap = tmp_path / "bridge_x.pcap"
    pcap.write_bytes(b"\x00\x01SMSHBdeadbeef\x02\x00")
    assert host_capture.find_marker([str(pcap)], "SMSHBdeadbeef") is True
    assert host_capture.find_marker([str(pcap)], "SMSHBffff") is False
    # trust window over heartbeat ledger
    arch = tmp_path / "RUN_M"
    arch.mkdir()
    t0, t1 = 100.0, 200.0
    common.append_jsonl(str(arch / host_capture.HEARTBEAT_LEDGER),
                        {"seq": 1, "marker": "SMSHBdeadbeef", "ts_sent": 150})
    assert host_capture.trust_window(str(arch), t0, t1,
                                     pcap_files=[str(pcap)]) is True
    common.append_jsonl(str(arch / host_capture.HEARTBEAT_LEDGER),
                        {"seq": 2, "marker": "SMSHBmissing1", "ts_sent": 160})
    assert host_capture.trust_window(str(arch), t0, t1,
                                     pcap_files=[str(pcap)]) is False
    assert host_capture.trust_window(str(arch), 300, 400,
                                     pcap_files=[str(pcap)]) is True  # vacuous
