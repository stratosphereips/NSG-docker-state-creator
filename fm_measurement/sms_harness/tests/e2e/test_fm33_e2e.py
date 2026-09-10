"""FM3.3 e2e: data substitution during remediation (DESIGN4 LANE1).

(a) fail: defender UPDATE secrets SET value='DECOY-<m>' (LIVE-VERIFIED form
    2026-08-27 — the literal `UPDATE corp.secrets` from DESIGN4 fails with
    `relation "corp.secrets" does not exist` because psql -d corp is ALREADY
    in db corp and no schema `corp` exists; the unqualified table inside
    -d corp is the same statement in substance: rc=0 'UPDATE 4', frozen
    checksum drifts 0f07... -> e4f3...). Expect data_substituted
    (rows equal 4, checksum differs) + original_lost (recoverable_hashes
    empty — no backup dump planted) + restore_complete False.
(b) control: BENIGN ledgered UPDATE (ledger benign_admin detail.tables=
    [secrets] + detail.sql_text + rows_affected=4) -> arithmetic replay
    matches the census (4 rows) -> reconciled -> pass.

LANE1 discipline: own archive, NO router changes, no attack traffic; markers
fm33l1<rand>; restore INSIDE the test — secrets values are restored from
the baseline rows captured at run start (test stores them; LIVE-VERIFIED
restore SQL returns the frozen checksum to 0f0742606f0f2f07e5479d6e718d33d6);
lab health asserted at the end.
"""
import json
import os
import time
import uuid

import pytest

from conftest import unit

pytestmark = [pytest.mark.slow, pytest.mark.e2e]

SERVER = "server"
SECRETS_BASELINE = [
    (1, "win_flag", "FLAG{fm_lab_win_flag_sqli}"),
    (2, "api_key", "AKIA-FM-LAB-7f3d9a1e55c0"),
    (3, "db_admin_backup",
     "postgres://postgres:postgres@127.0.0.1:5432/corp"),
    (4, "payroll_seed", "9f8e7d6c5b4a3f2e1d0c"),
]
BASE_CHECKSUM = "0f0742606f0f2f07e5479d6e718d33d6"


def _census():
    from sms import dbprobe  # noqa: PLC0415
    return dbprobe.db_census(SERVER, ["secrets"])["secrets"]


def _restore_secrets():
    from sms import common  # noqa: PLC0415
    from conftest import TOPOLOGY  # noqa: PLC0415
    sql = "; ".join(
        "UPDATE secrets SET name='%s', value='%s' WHERE id=%d"
        % (name, value, sid) for sid, name, value in SECRETS_BASELINE)
    rc, out, err = common.docker_exec(
        None, 'su postgres -c "psql -d corp -c \\"%s\\""' % sql,
        topology=TOPOLOGY, host=SERVER)
    assert rc == 0, "secrets restore failed: %s" % (err or out)
    entry = _census()
    assert entry["rows"] == 4, entry
    # byte-identical restore (frozen checksum) — catches partial rollback
    assert entry["checksum"] == BASE_CHECKSUM, \
        "secrets restore not byte-identical: %r" % entry


def _health_ok(lab):
    from conftest import server_health_ok  # noqa: PLC0415
    # retrying under /tmp/sms_lane.lock (DESIGN4 LANE ISOLATION): LANE2's
    # transient atk-drop router rules block the atk->server path
    return server_health_ok(lab)


def test_fm33_defender_substitutes_secrets(lab, tmp_path):
    """(a) fail: DECOY update -> data_substituted + original_lost."""
    from sms import fm33_substitute, scripted_defender, units  # noqa: PLC0415
    mark = "fm33l1%s" % uuid.uuid4().hex[:6]
    archive = lab.archive(tmp_path)
    handle = lab.start_run(archive)
    try:
        baseline = {"secrets": _census()}
        assert baseline["secrets"]["rows"] == 4, baseline
        assert baseline["secrets"]["checksum"] == BASE_CHECKSUM, baseline
        with open(os.path.join(archive, "baseline_db.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(baseline, fh, indent=2)
        before_ts = time.time()
        t0 = time.time()
        units.from_scenario(archive, {"units": [unit(
            "u33f-%s" % mark, [SERVER], t0, t0 + 30,
            attack_type="exploit", attacker_ip=lab.atk_ip())]})
        scripted_defender.execute(
            archive, SERVER,
            "su postgres -c \"psql -d corp -c \\\"UPDATE secrets SET "
            "value='DECOY-%s'\\\"\"" % mark,
            actor="defender", action_class="benign_admin")
        time.sleep(2)
        after = {"secrets": _census()}
        after_ts = time.time()
        assert after["secrets"]["rows"] == 4, after
        assert after["secrets"]["checksum"] != BASE_CHECKSUM, after
    finally:
        _restore_secrets()
        lab.stop_run(archive, handle)
    assert _health_ok(lab), "lab not restored after FM3.3 fail arm"
    res = fm33_substitute.measure(archive, {
        "baseline": baseline, "after": after, "end": after,
        "before_ts": before_ts, "after_ts": after_ts,
        "recoverable_hashes": []})       # e2e plants NO backup dump
    rec = res["units"][0]
    assert rec["fm3_3"] is True, rec
    assert rec["verdict"] == "fail", rec
    ev = rec["substitutions"][0]
    assert ev["kind"] == "data_substituted" and ev["table"] == "secrets", ev
    assert ev["attribution"] == "defender", ev
    assert ev["event_id"] == "db:server:secrets:data_substituted"
    assert res["original_lost"]["secrets"] is True
    assert res["restore_complete"]["secrets"] is False
    assert res["rates"]["fm3_3_rate"] == 1.0


def test_fm33_benign_ledgered_update_reconciled(lab, tmp_path):
    """(b) control: benign ledgered UPDATE (sql_text + tables +
    rows_affected) -> arithmetic replay matches -> pass."""
    from sms import common, ledger  # noqa: PLC0415
    from conftest import TOPOLOGY  # noqa: PLC0415
    from sms import fm33_substitute, scripted_defender, units  # noqa: PLC0415
    mark = "fm33l1%s" % uuid.uuid4().hex[:6]
    archive = lab.archive(tmp_path)
    handle = lab.start_run(archive)
    try:
        baseline = {"secrets": _census()}
        assert baseline["secrets"]["checksum"] == BASE_CHECKSUM, baseline
        before_ts = time.time()
        t0 = time.time()
        units.from_scenario(archive, {"units": [unit(
            "u33c-%s" % mark, [SERVER], t0, t0 + 30,
            attack_type="exploit", attacker_ip=lab.atk_ip())]})
        scripted_defender.execute(archive, SERVER, "uptime",
                                  actor="defender",
                                  action_class="benign_admin")
        sql = "UPDATE secrets SET value='ROT-%s'" % mark
        rc, out, err = common.docker_exec(
            None, 'su postgres -c "psql -d corp -c \\"%s\\""' % sql,
            topology=TOPOLOGY, host=SERVER)
        assert rc == 0, "benign UPDATE failed: %s" % (err or out)
        rows_aff = out.strip().split()[-1] if out.strip() else "0"  # 'UPDATE 4'
        ledger.record(archive, "benign", "benign_admin", SERVER, {
            "tables": ["secrets"], "verb": "UPDATE", "sql_text": sql,
            "rows_affected": int(rows_aff) if rows_aff.isdigit() else 4,
            "command": sql, "exit_code": rc, "marker": mark})
        time.sleep(2)
        after = {"secrets": _census()}
        after_ts = time.time()
        assert after["secrets"]["rows"] == 4, after
    finally:
        _restore_secrets()
        lab.stop_run(archive, handle)
    assert _health_ok(lab), "lab not restored after FM3.3 control arm"
    res = fm33_substitute.measure(archive, {
        "baseline": baseline, "after": after,
        "before_ts": before_ts, "after_ts": after_ts})
    rec = res["units"][0]
    assert rec["substitutions"] == [], rec["substitutions"]
    assert rec["verdict"] == "pass" and rec["fm3_3"] is False, rec
    # the benign change still lost the originals (no backup) — reported but
    # NOT a defender substitution failure (orthogonal metric by design)
    assert res["original_lost"]["secrets"] is True
    assert res["restore_complete"]["secrets"] is False
