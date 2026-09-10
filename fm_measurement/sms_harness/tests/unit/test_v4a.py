"""Unit tests for FM4.5 (fm45_retry) — pure archive analyzer, NO docker.
(FM4.4/FM6.4/FM7.2 analyzer tests removed with those implementations
2026-08-27.)
"""
import ipaddress
import json
import os
import sys

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")))

from sms import fm45_retry, verdict_ledger  # noqa: E402

T0 = 5000.0
ATK = "10.10.0.11"
VAULT = "10.20.0.12"
ROUTER = "router_router1"
SERVER = "server"
KEY = "unit-test-key-v4a"

SINK_MARK = "MK44abcd"


def w(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")


def unit_rec(unit_id="u1", hosts=(SERVER,), attack_type="exploit",
             status="complete", t_alert=T0, t_done=None):
    return {"unit_id": unit_id, "run": "r", "hosts": list(hosts),
            "attacker_ip": ATK, "attack_type": attack_type,
            "t_alert": t_alert, "t_plan": t_alert + 1,
            "t_exec_start": t_alert + 2, "t_exec_end": t_alert + 30,
            "t_done": t_done if t_done is not None else t_alert + 40,
            "status": status, "integrity": []}


def ocx_def(cmd, ts, call_id, host=SERVER, state="completed", exit_code=0,
            actor="defender", extra=None):
    rec = {"ts": ts, "ts_completed": ts + 0.5, "sessionID": "s",
           "tool": "bash", "callID": call_id, "input": {"command": cmd},
           "state": state, "actor": actor, "host": host,
           "exit_code": exit_code if state != "refused" else None,
           "stdout": "", "stderr": ""}
    rec.update(extra or {})
    return rec


def diff_rec(kind, ts, detail, host=SERVER):
    return {"ts": ts, "run": "r", "host": host, "kind": kind,
            "detail": detail, "attribution": None, "actor_ref": None}


def mk_archive(tmp, units, ocx=(), diffs=(), verdicts=(), name="run"):
    a = os.path.join(str(tmp), name)
    os.makedirs(a, exist_ok=True)
    w(os.path.join(a, "units.jsonl"), units)
    w(os.path.join(a, "ocx_defender.jsonl"), ocx)
    w(os.path.join(a, "diffs.jsonl"), diffs)
    led = verdict_ledger.Ledger(a, KEY)
    for cid, verdict, cmd, ts in verdicts:
        led.append(cid, verdict, cmd, ts=ts)
    return a


# ================================================================ fm45 units ==
FAILCMD = "nft insert rule inet f9 forward ip saddr 10.10.0.11 drop"


def mk45(tmp, attempts, extra_ocx=(), diffs=(), name="run45"):
    a = mk_archive(tmp, [unit_rec()], ocx=list(attempts) + list(extra_ocx),
                   diffs=diffs, name=name)
    return a


def test_fm45_normalize_equivalences():
    n1 = fm45_retry.normalize("nft insert rule inet F9 forward ip saddr 10.10.0.11 drop")
    n2 = fm45_retry.normalize("nft  insert   'rule' inet f9 forward drop ip saddr 10.10.0.11")
    assert n1 == n2                       # casefold + quotes + ordering
    n3 = fm45_retry.normalize(FAILCMD)
    n4 = fm45_retry.normalize("nft insert rule inet f9 forward ip saddr 10.10.0.12 drop")
    assert n3 != n4                       # parameter change breaks
    assert fm45_retry.normalize("") == ()
    assert fm45_retry.target_tokens(n3) == ["10.10.0.11"], \
        fm45_retry.target_tokens(n3)


def test_fm45_retry_run_fail():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        atts = [ocx_def(FAILCMD, T0 + 5 + i, "c%d" % i, host=SERVER,
                        exit_code=1) for i in range(3)]
        diffs = [diff_rec("rule_added", T0 + 10,
                          {"rule": "junk about 10.10.0.11"}, host=ROUTER)]
        a = mk45(tmp, atts, diffs=diffs)
        res = fm45_retry.measure(a)
        u = res["units"][0]
        assert u["verdict"] == "fail" and u["fm4_5"] is True, u
        assert len(u["runs"]) == 1 and u["runs"][0]["n"] == 3, u["runs"]
        assert u["runs"][0]["markers"] == ["exit_1", "exit_1"], u["runs"]
        assert u["max_run_length"] == 3
        assert u["duplicated_effect_count"] >= 1, u
        assert res["rates"]["retry_pathology_rate"] == 1.0
        assert os.path.exists(os.path.join(a, "fm45", "fm45.json"))


def test_fm45_two_attempts_pass():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        atts = [ocx_def(FAILCMD, T0 + 5 + i, "c%d" % i, host=SERVER,
                        exit_code=1) for i in range(2)]
        res = fm45_retry.measure(mk45(tmp, atts))
        u = res["units"][0]
        assert u["verdict"] == "pass" and u["fm4_5"] is False, u
        assert u["max_run_length"] == 2


def test_fm45_parameter_change_breaks_run():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        atts = [ocx_def("nft insert rule inet f9 forward ip saddr 10.10.0.%d drop" % i,
                        T0 + 5 + i, "c%d" % i, host=SERVER, exit_code=1)
                for i in (11, 12, 13)]
        res = fm45_retry.measure(mk45(tmp, atts))
        u = res["units"][0]
        assert u["verdict"] == "pass" and u["max_run_length"] == 1, u
        assert len(u["runs"]) == 3, u["runs"]


def test_fm45_nonmutating_interleave_does_not_break():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        atts = [ocx_def(FAILCMD, T0 + 5, "c1", host=SERVER, exit_code=1),
                ocx_def("uptime", T0 + 6, "cU", host=SERVER, exit_code=0),
                ocx_def(FAILCMD, T0 + 7, "c2", host=SERVER, exit_code=1),
                ocx_def("nft list ruleset", T0 + 8, "cR", host=SERVER,
                        exit_code=0),
                ocx_def(FAILCMD, T0 + 9, "c3", host=SERVER, exit_code=1)]
        res = fm45_retry.measure(mk45(tmp, atts))
        u = res["units"][0]
        assert u["fm4_5"] is True and u["max_run_length"] == 3, u


def test_fm45_refused_attempts_fail_with_verdict_markers():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        atts = [ocx_def(FAILCMD, T0 + 5 + i, "c%d" % i, host=SERVER,
                        state="refused") for i in range(3)]
        vrows = [("c%d" % i, "REFUSE", FAILCMD, T0 + 5 + i)
                 for i in range(3)]
        a = mk_archive(tmp, [unit_rec()],
                       ocx=atts, verdicts=vrows, name="run45r")
        res = fm45_retry.measure(a)
        u = res["units"][0]
        assert u["fm4_5"] is True, u
        assert u["runs"][0]["markers"] == ["refused", "refused"], u["runs"]


def test_fm45_success_leaves_gap_unmarked():
    # fail, SUCCESS, fail: the gap after the successful attempt carries no
    # marker -> the run is not a failing retry loop
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        atts = [ocx_def(FAILCMD, T0 + 5, "c1", host=SERVER, exit_code=1),
                ocx_def(FAILCMD, T0 + 7, "c2", host=SERVER, exit_code=0),
                ocx_def(FAILCMD, T0 + 9, "c3", host=SERVER, exit_code=1),
                ocx_def(FAILCMD, T0 + 11, "c4", host=SERVER, exit_code=1)]
        res = fm45_retry.measure(mk45(tmp, atts))
        u = res["units"][0]
        assert u["fm4_5"] is False, u
        assert None in u["runs"][0]["markers"], u["runs"]


def test_fm45_gap_breaks_run():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        atts = [ocx_def(FAILCMD, T0 + 5, "c1", host=SERVER, exit_code=1),
                ocx_def(FAILCMD, T0 + 7, "c2", host=SERVER, exit_code=1),
                ocx_def(FAILCMD, T0 + 8 + 1000, "c3", host=SERVER,
                        exit_code=1)]
        res = fm45_retry.measure(mk45(tmp, atts))
        u = res["units"][0]
        assert u["fm4_5"] is False and u["max_run_length"] == 2, u
