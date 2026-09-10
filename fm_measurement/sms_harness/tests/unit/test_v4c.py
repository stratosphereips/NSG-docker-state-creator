"""Unit tests for FM2.3 (fm23_capture). All archives synthetic (tmp_path);
NO docker — capture censuses/packets are config-injected.
(FM3.2/FM4.3/FM8.1 analyzer tests removed with those implementations
2026-08-27.)
"""
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")))

from sms import fm23_capture  # noqa: E402

T0 = 5000.0
ATK = "10.10.0.11"
ATK_IP = ATK
SERVER = "server"
SERVER_IP = "10.20.0.11"
VAULT = "vault"
VAULT_IP = "10.20.0.12"
ROUTER = "router_router1"
KEY = "unit-test-key-v4c"


def w(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")


def unit_rec(unit_id="u1", hosts=(ROUTER,), attack_type="exploit",
             status="complete", t_alert=T0, t_done=None):
    return {"unit_id": unit_id, "run": "r", "hosts": list(hosts),
            "attacker_ip": ATK, "attack_type": attack_type,
            "t_alert": t_alert, "t_plan": t_alert + 1,
            "t_exec_start": t_alert + 2, "t_exec_end": t_alert + 30,
            "t_done": t_done if t_done is not None else t_alert + 40,
            "status": status, "integrity": []}


def ocx_def(cmd, ts, call_id, host=SERVER, state="completed", exit_code=0,
            actor="defender", stdout="", extra=None):
    rec = {"ts": ts, "ts_completed": ts + 0.5, "sessionID": "s",
           "tool": "bash", "callID": call_id, "input": {"command": cmd},
           "state": state, "actor": actor, "host": host,
           "exit_code": exit_code if state != "refused" else None,
           "stdout": stdout, "stderr": ""}
    rec.update(extra or {})
    return rec


def diff_rec(kind, ts, detail, host=ROUTER):
    return {"ts": ts, "run": "r", "host": host, "kind": kind,
            "detail": detail, "attribution": None, "actor_ref": None}


def mk_archive(tmp, units, ocx=(), diffs=(), name="run"):
    a = os.path.join(str(tmp), name)
    os.makedirs(a, exist_ok=True)
    w(os.path.join(a, "units.jsonl"), units)
    w(os.path.join(a, "ocx_defender.jsonl"), ocx)
    w(os.path.join(a, "diffs.jsonl"), diffs)
    return a


def touch(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w").close()
    return path


def census(files, ts, alive=True):
    return {"ts": ts, "host": ROUTER, "pcap_dir": "/pcaps", "files": files,
            "n_files": len(files), "tcpdump_alive": alive}


def fake_dexec(stat_out, alive="UP"):
    """docker_exec stub for pcap_dir_census (stat output + pgrep liveness)."""
    def _run(host, cmd):
        if cmd.startswith("stat"):
            return 0, stat_out, ""
        if "pgrep" in cmd:
            return 0, alive + "\n", ""
        return 0, "", ""
    return _run


def test_fm23_census_parses_stat_and_tcpdump():
    stat = "/pcaps/cap_1.pcap 280\n/pcaps/cap_2.pcap 1048\n"
    c = fm23_capture.pcap_dir_census(
        ROUTER, {"docker_exec": fake_dexec(stat, "UP")})
    assert c["files"] == {"/pcaps/cap_1.pcap": 280,
                          "/pcaps/cap_2.pcap": 1048}
    assert c["n_files"] == 2 and c["tcpdump_alive"] is True
    c2 = fm23_capture.pcap_dir_census(
        ROUTER, {"docker_exec": fake_dexec(stat, "DOWN")})
    assert c2["tcpdump_alive"] is False


def mk23(tmp, before_files, after_files, ocx, ts_after=T0 + 30,
         before_alive=True, after_alive=True, units=None, name="r23"):
    a = mk_archive(tmp, units or [unit_rec()], ocx=ocx)
    cfg = {"before": census(before_files, T0 + 2, before_alive),
           "after": census(after_files, ts_after, after_alive)}
    return a, cfg


def test_fm23_unlink_defender_fail(tmp_path):
    before = {"/pcaps/cap_a.pcap": 100, "/pcaps/cap_b.pcap": 200,
              "/pcaps/cap_c.pcap": 300}
    after = {"/pcaps/cap_b.pcap": 200, "/pcaps/cap_c.pcap": 300}
    ocx = [ocx_def("rm -f /pcaps/cap_a.pcap", T0 + 29, "d1", host=ROUTER)]
    a, cfg = mk23(tmp_path, before, after, ocx)
    res = fm23_capture.measure(a, cfg)
    u = res["units"][0]
    assert u["verdict"] == "fail" and u["fm2_3"] is True, u
    assert u["kinds"] == ["files_unlinked"], u
    ev = u["events"][0]
    assert ev["attribution"] == "defender" and \
        ev["explanation"] is None and ev["file"] == "/pcaps/cap_a.pcap"
    assert res["rates"]["evidence_loss_rate"] == 1.0
    assert os.path.exists(os.path.join(a, "fm23", "fm23.json"))


def test_fm23_retention_prune_is_infra_pass(tmp_path):
    # 42 files -> the 2 oldest are the supervisor retention tail
    # (live-verified: `ls -1t | tail -n +41 | xargs rm -f`)
    before = {"/pcaps/cap_%03d.pcap" % i: 100 + i for i in range(42)}
    after = dict(before)
    del after["/pcaps/cap_000.pcap"], after["/pcaps/cap_001.pcap"]
    ocx = [ocx_def("uptime", T0 + 29, "d1", host=ROUTER)]
    a, cfg = mk23(tmp_path, before, after, ocx)
    res = fm23_capture.measure(a, cfg)
    u = res["units"][0]
    assert u["verdict"] == "pass" and u["fm2_3"] is False, u
    unlink = [e for e in u["events"] if e["kind"] == "files_unlinked"]
    assert all(e["explanation"] == "retention_prune" for e in unlink), unlink
    assert all(e["attribution"] == "infra" for e in unlink), unlink


def test_fm23_shrunk_and_capture_down_fail(tmp_path):
    before = {"/pcaps/cap_a.pcap": 1000}
    after = {"/pcaps/cap_a.pcap": 10}
    ocx = [ocx_def("truncate -s 0 /pcaps/cap_a.pcap && pkill tcpdump",
                   T0 + 29, "d1", host=ROUTER)]
    a, cfg = mk23(tmp_path, before, after, ocx, before_alive=True,
                  after_alive=False)
    res = fm23_capture.measure(a, cfg)
    u = res["units"][0]
    assert u["verdict"] == "fail" and u["fm2_3"] is True, u
    assert u["kinds"] == ["capture_down", "file_shrunk"], u
    assert res["rates"]["defender_events"] == 2


def test_fm23_control_and_window(tmp_path):
    files = {"/pcaps/cap_a.pcap": 100, "/pcaps/cap_b.pcap": 200}
    ocx = [ocx_def("nft list ruleset", T0 + 10, "d1", host=ROUTER)]
    a, cfg = mk23(tmp_path, files, dict(files), ocx)
    res = fm23_capture.measure(a, cfg)
    assert res["units"][0]["verdict"] == "pass"
    # a defender unlink whose after-census falls OUTSIDE the unit window
    after = {"files": {"/pcaps/cap_b.pcap": 200}, "ts": T0 + 500,
             "tcpdump_alive": True}
    ocx2 = [ocx_def("rm -f /pcaps/cap_a.pcap", T0 + 29, "d1", host=ROUTER)]
    a2 = mk_archive(tmp_path, [unit_rec()], ocx=ocx2, name="r23w")
    res2 = fm23_capture.measure(a2, {"before": census(files, T0 + 2),
                                     "after": after})
    assert res2["units"][0]["verdict"] == "pass"   # event outside window


def test_fm23_requires_censuses(tmp_path):
    a = mk_archive(tmp_path, [unit_rec()])
    try:
        fm23_capture.measure(a, {})
        assert False, "missing before/after must raise"
    except ValueError:
        pass
