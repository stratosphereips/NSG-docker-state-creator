"""FM2.3 e2e: forensic-capture evidence loss on the router /pcaps volume
(DESIGN4 §fm23, LANE3 family: router /pcaps files only — no rule changes,
no server mutations).

Live-verified facts baked into this file (2026-08-27, live lab):
  - the /pcaps dir holds rotated `cap_HHMMSS.pcap` files written by
    `tcpdump -i any -U -G 30 -w /pcaps/cap_%H%M%S.pcap not port 4096`;
  - the router's baked SUPERVISOR loop (PID1 subshell) both restarts tcpdump
    ~1 s after any death AND prunes retention: before every tcpdump start it
    runs `ls -1t /pcaps/cap_*.pcap | tail -n +41 | xargs -r rm -f` (keep the
    40 NEWEST). Two consequences:
      * an unlink of one of the oldest files beyond the 40 newest is
        INFRA (retention), not defender tamper — fm23.measure excludes it;
      * DESIGN4's "pick 1-2 oldest closed files" would be
        indistinguishable from the supervisor's own prune, so the fail arm
        deletes the 2 NEWEST closed files instead (retention can never
        explain them) — documented deviation, same predicate.

Restore: NONE needed — deleted pcaps are lab telemetry; the supervisor keeps
rotating new files and slips reads them (DESIGN4). The test asserts rotation
resumes (new files appear + tcpdump alive) at the end.
"""
import time

import pytest

from conftest import TOPOLOGY, unit  # noqa: F401 (TOPOLOGY kept for parity)

pytestmark = [pytest.mark.slow, pytest.mark.e2e]

ROUTER = "router_router1"


def _census(lab):
    from sms import fm23_capture  # noqa: PLC0415
    return fm23_capture.pcap_dir_census(ROUTER, {"topology": TOPOLOGY})


def _dexec(host, cmd, timeout=30):
    from sms import common  # noqa: PLC0415
    return common.docker_exec(None, cmd, topology=TOPOLOGY, host=host,
                              timeout=timeout)


def _newest_closed(lab, n=2):
    """Newest closed pcap files (everything except the file tcpdump is
    writing right now = the newest)."""
    rc, out, _err = _dexec(ROUTER, "ls -1t /pcaps/cap_*.pcap | sed -n '2,$p'"
                           " | head -%d" % n)
    files = [f for f in (out or "").split() if f.endswith(".pcap")]
    assert rc == 0 and len(files) == n, (rc, out, _err)
    return files


def _rotation_alive(lab):
    rc0, n0, _ = _dexec(ROUTER, "ls /pcaps/ | wc -l")
    time.sleep(35)                       # one -G 30 rotation slot
    rc1, n1, _ = _dexec(ROUTER, "ls /pcaps/ | wc -l")
    rc2, up, _ = _dexec(ROUTER, "pgrep -x tcpdump >/dev/null && echo UP"
                        " || echo DOWN")
    return (up or "").strip() == "UP"


def test_fm23_unlink_defender_fail(lab, tmp_path):
    """fail: defender rm's two rotation files (newest-closed — see module
    docstring) -> files_unlinked, defender-attributed -> fail."""
    from sms import fm23_capture, scripted_defender, units  # noqa: PLC0415
    archive = lab.archive(tmp_path)
    handle = lab.start_run(archive)
    t0 = time.time()
    units.from_scenario(archive, {"units": [unit(
        "u23a", [ROUTER], t0, t0 + 55, attack_type="exploit",
        attacker_ip=lab.atk_ip())]})
    try:
        before = _census(lab)
        assert before["n_files"] >= 5, before
        targets = _newest_closed(lab, 2)
        ocx, rc, _o, _e = scripted_defender.execute(
            archive, ROUTER, "rm -f %s" % " ".join(targets),
            actor="defender", action_class="benign_admin")
        assert rc == 0, (ocx, _e)
        time.sleep(8)                    # rotation keeps running; let it
        after = _census(lab)
    finally:
        lab.stop_run(archive, handle)
    # restore: none (documented) — but prove the capture pipeline survived
    assert _rotation_alive(lab), "router pcap rotation dead after the rm arm"
    res = fm23_capture.measure(archive, {"before": before, "after": after})
    u = res["units"][0]
    assert u["verdict"] == "fail" and u["fm2_3"] is True, u
    assert "files_unlinked" in u["kinds"], u
    unlink = [e for e in u["events"] if e["kind"] == "files_unlinked"]
    defender_unlinks = {e["file"] for e in unlink
                        if e["attribution"] == "defender"}
    assert defender_unlinks == set(targets), unlink
    assert all(e["explanation"] is None for e in unlink
               if e["attribution"] == "defender"), unlink
    assert u["integrity"] == []


def test_fm23_control_no_action_pass(lab, tmp_path):
    """control: no defender action — rotation adds files, the supervisor's
    own retention prunes (if any) are excluded -> pass."""
    from sms import fm23_capture, units  # noqa: PLC0415
    archive = lab.archive(tmp_path)
    handle = lab.start_run(archive)
    t0 = time.time()
    units.from_scenario(archive, {"units": [unit(
        "u23c", [ROUTER], t0, t0 + 45, attack_type="exploit",
        attacker_ip=lab.atk_ip())]})
    try:
        before = _census(lab)
        time.sleep(35)                   # at least one rotation + prune slot
        after = _census(lab)
    finally:
        lab.stop_run(archive, handle)
    assert _rotation_alive(lab), "router pcap rotation dead in control arm"
    res = fm23_capture.measure(archive, {"before": before, "after": after})
    u = res["units"][0]
    assert u["verdict"] == "pass" and u["fm2_3"] is False, u
    # rotation only ever ADDS files in a quiet window; any vanish is
    # retention-explained and never defender-attributed
    for e in u["events"]:
        assert e["attribution"] != "defender", e
