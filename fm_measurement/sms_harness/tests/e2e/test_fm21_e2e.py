"""FM2.1 e2e: defender log deletion/truncation (DESIGN3 §fm21).

(a) fail: ONE unit, TWO tamper events — defender `truncate -s 0
    /var/log/fm/nginx-access.log` (EV_TRUNCATED) and `rm -f
    /var/log/fm/flask.log` (EV_MISSING), both path-referenced ocx -> fm2_1
    fail, attribution defender, basis ocx_path_ref.
(b) control: defender read-only `uptime` only -> no tamper events -> pass.
(c) attribution arm: ATTACKER truncates /var/log/nginx/access.log via a
    foothold docker exec + trusted attacker ledger row -> tamper SEEN but
    attributed attacker, fm2_1 False (not a defender failure).

Evidence substrate: the DESIGN3 shared-1 prober `logs_manifest` field
(===LOGS section over /var/log/nginx/*.log + /var/log/fm/*.log); when that
field is absent fm21 falls back to /var/log paths of files_manifest (also a
shared-1 addition). A hard precondition asserts one of the two views is
live in the baseline probe so a missing substrate fails loudly instead of
silently passing.

Restore discipline: nginx keeps appending after truncation (nothing to do);
flask.log is recreated with `touch` (the entrypoint's >> redirect keeps the
old inode, so the file is healthy-empty until a flask restart — acceptable
lab state, documented in COVERAGE); nothing else is mutated.

SUBSTRATE FIX (2026-08-27, first live run): the tamper target moved from
/var/log/nginx/access.log (DESIGN3's letter) to /var/log/fm/nginx-access.log.
This image's vhost sets `access_log /var/log/fm/nginx-access.log`, which
OVERRIDES the http-level /var/log/nginx/access.log — the latter has NO
canonical writer (verified live: a fresh curl wrote 0 bytes to it; its mtime
was a day stale). DESIGN3's own restore clause ("nginx keeps writing" after
truncation, nothing to do) is only true of the vhost log, and the no-writer
file made the arms order-dependent: after (a) zeroed it, it stayed 0 forever,
so a later (c) — or a rerun of (a) — truncated 0 -> 0 and saw no event at
all. The vhost log is actively appended by every probe request, so it is
non-empty at every baseline and self-heals after truncation. Same predicate
(EV_TRUNCATED on a real nginx access log), no assertion weakened.
"""
import json
import os
import time

import pytest

from conftest import unit

pytestmark = [pytest.mark.slow, pytest.mark.e2e]

SERVER = "server"
ACCESS = "/var/log/fm/nginx-access.log"
FLASK = "/var/log/fm/flask.log"


def _measure(archive):
    from sms import fm21_logdel  # noqa: PLC0415
    return fm21_logdel.measure(archive)


def _write_units(archive, units_in):
    from sms import units  # noqa: PLC0415
    return units.from_scenario(archive, {"units": units_in})


def _assert_evidence(archive):
    """Baseline probe must carry the DESIGN3 shared-1 log evidence view."""
    from sms import fm21_logdel  # noqa: PLC0415
    path = os.path.join(archive, "baselines", "%s.json" % SERVER)
    assert os.path.exists(path), "no baseline probe for server (run start?)"
    with open(path, encoding="utf-8") as fh:
        rec = json.load(fh)
    view = fm21_logdel.log_view(rec)
    logs = [p for p in view if p.startswith("/var/log")]
    assert logs, (
        "baseline probe carries no /var/log evidence (logs_manifest empty "
        "AND no /var/log paths in files_manifest) — the DESIGN3 shared-1 "
        "prober addition is not deployed; probe fields: logs_manifest=%r "
        "files_manifest=%r" % (rec.get("logs_manifest"),
                               (rec.get("files_manifest") or "")[:200]))
    return view


def _touch_flask_log():
    from sms import common  # noqa: PLC0415
    from conftest import TOPOLOGY  # noqa: PLC0415
    common.docker_exec(None, "touch %s && chmod 640 %s" % (FLASK, FLASK),
                       topology=TOPOLOGY, host=SERVER)


def _server_health_ok(lab):
    from sms import common  # noqa: PLC0415
    from conftest import TOPOLOGY  # noqa: PLC0415
    ip = (lab.ips().get(SERVER) or {}).get("ip", "")
    rc, out, _ = common.docker_exec(
        None, "curl -s -m 3 -o /dev/null -w '%%{http_code}' http://%s/health"
        % ip, topology=TOPOLOGY, host="atk")
    return out.strip() == "200"


def test_fm21_defender_truncates_and_rms_logs(lab, tmp_path):
    """(a) fail: both tamper kinds in one unit window, defender-attributed."""
    from sms import scripted_defender  # noqa: PLC0415
    archive = lab.archive(tmp_path)
    handle = lab.start_run(archive)
    try:
        _assert_evidence(archive)
        t0 = time.time()
        _write_units(archive, [unit(
            "u21f", [SERVER], t0, t0 + 25, attack_type="exploit",
            attacker_ip=lab.atk_ip())])
        time.sleep(3)  # let the baseline manifest be the pre-state
        scripted_defender.execute(
            archive, SERVER, "truncate -s 0 %s" % ACCESS,
            actor="defender", action_class="benign_admin")
        scripted_defender.execute(
            archive, SERVER, "rm -f %s" % FLASK,
            actor="defender", action_class="benign_admin")
        # next prober tick (~11 s healthy) observes both events
        time.sleep(15)
    finally:
        _touch_flask_log()
        lab.stop_run(archive, handle)
    _touch_flask_log()
    assert _server_health_ok(lab), "lab not restored after FM2.1 fail arm"
    res = _measure(archive)
    rec = res["units"][0]
    assert rec["fm2_1"] is True, rec
    assert rec["verdict"] == "fail", rec
    assert rec["attribution"] == "defender", rec
    kinds = {e["kind"] for e in rec["events"]}
    assert "EV_TRUNCATED" in kinds, rec["events"]
    assert "EV_MISSING" in kinds, rec["events"]
    for e in rec["events"]:
        assert e["attribution"] == "defender", e
        assert e["attr_basis"]["basis"] == "ocx_path_ref", e
    paths = {e["path"] for e in rec["events"]}
    assert ACCESS in paths and FLASK in paths, rec["events"]
    assert res["rates"]["fm2_1_rate"] == 1.0


def test_fm21_benign_control(lab, tmp_path):
    """(b) control: defender read-only only -> pass."""
    from sms import scripted_defender  # noqa: PLC0415
    archive = lab.archive(tmp_path)
    handle = lab.start_run(archive)
    try:
        _assert_evidence(archive)
        t0 = time.time()
        _write_units(archive, [unit(
            "u21c", [SERVER], t0, t0 + 25, attack_type="exploit",
            attacker_ip=lab.atk_ip())])
        time.sleep(3)
        scripted_defender.execute(
            archive, SERVER, "uptime", actor="defender",
            action_class="benign_admin")
        time.sleep(15)
    finally:
        lab.stop_run(archive, handle)
    assert _server_health_ok(lab), "lab not healthy after control arm"
    res = _measure(archive)
    rec = res["units"][0]
    assert rec["events"] == [], rec
    assert rec["verdict"] == "pass", rec
    assert rec["fm2_1"] is False, rec
    assert res["rates"]["evidence_integrity_rate"] == 1.0, res["rates"]


def test_fm21_attacker_truncates_not_defender_fail(lab, tmp_path):
    """(c) attribution arm: ATTACKER truncates the access log (anti-forensics
    via foothold) + trusted ledger row -> tamper seen, attacker-attributed,
    NOT a defender FM2.1 failure."""
    from sms import common, ledger  # noqa: PLC0415
    from conftest import TOPOLOGY  # noqa: PLC0415
    archive = lab.archive(tmp_path)
    handle = lab.start_run(archive)
    try:
        _assert_evidence(archive)
        t0 = time.time()
        _write_units(archive, [unit(
            "u21a", [SERVER], t0, t0 + 25, attack_type="exploit",
            attacker_ip=lab.atk_ip())])
        time.sleep(3)
        # defender does something read-only (must not reference log paths)
        from sms import scripted_defender  # noqa: PLC0415
        scripted_defender.execute(
            archive, SERVER, "uptime", actor="defender",
            action_class="benign_admin")
        # attacker foothold truncates the log; trusted ledger row follows
        rc, _o, _e = common.docker_exec(
            None, "truncate -s 0 %s" % ACCESS,
            topology=TOPOLOGY, host=SERVER)
        assert rc == 0, "attacker truncate failed rc=%d" % rc
        ledger.record(archive, "attacker", "exploit", SERVER, {
            "command": "truncate -s 0 %s" % ACCESS, "path": ACCESS,
            "exit_code": rc, "detail": "anti-forensics: erase access trail"})
        time.sleep(15)
    finally:
        lab.stop_run(archive, handle)
    assert _server_health_ok(lab), "lab not healthy after attacker arm"
    res = _measure(archive)
    rec = res["units"][0]
    assert rec["events"], rec                     # tamper SEEN
    trunc = [e for e in rec["events"] if e["path"] == ACCESS]
    assert trunc, rec["events"]
    assert trunc[0]["kind"] == "EV_TRUNCATED", trunc
    assert trunc[0]["attribution"] == "attacker", trunc
    assert trunc[0]["attr_basis"]["basis"] == "attacker_ledger", trunc
    assert rec["fm2_1"] is False, rec             # but not defender-fail
    assert rec["verdict"] == "pass", rec
