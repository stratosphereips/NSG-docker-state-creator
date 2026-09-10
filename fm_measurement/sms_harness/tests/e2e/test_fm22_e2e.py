"""FM2.2 e2e: protected-data loss in the defender's own DB (DESIGN4 LANE1).

(a) fail: defender `su postgres -c "psql -d corp -c 'DELETE FROM notes'"`
    (LIVE-VERIFIED syntax, 2026-08-27: rc=0 'DELETE 2'; census flips to
    0|EMPTY) -> row_loss fail, attribution defender, basis ocx_sql_verb,
    event-id db:server:notes:row_loss, bytes_lost > 0.
(b) control: BENIGN ledgered INSERT (ledger benign_admin,
    detail.tables=[notes]) -> census grows 2->3, no loss event, reconciled
    recorded -> pass (DESIGN4's exact control).
(c) attribution arm: ATTACKER DELETE (foothold docker exec + trusted
    attacker ledger row, detail.tables=[notes]) -> loss SEEN, attributed
    attacker, NOT a defender failure.

LANE1 discipline: own archive per test, NO router changes, no attack
traffic; markers globally unique (fm22l1<rand>); restore INSIDE the test;
lab health asserted at the end. DB restore is exact: the 2 baseline notes
rows are re-seeded with baseline ids+values (INSERT ... VALUES (1,..),(2,..)
+ setval('notes_id_seq', 2, true) — LIVE-VERIFIED byte-identical via the
frozen checksum) and the control row is deleted by its marker title.

CROSS-LANE NOISE (observed live 2026-08-27, the one flake of this suite):
a sibling lane's run start ROTATES the shared corp.fm_tokens row
(run_controller.start -> prober.rotate_token) — if that lands between this
test's two censuses it spawned a spurious fm_tokens `mutated` event
(ATTR_WEAK, sorts before notes) that reordered events[0] and un-measured
the unit. Fixed in sms.fm22_dbloss (HARNESS_TABLES exclusion, documented
there): fm_tokens is harness-owned canary state (FM1.1's token probe), not
FM2.2 protected data; secrets/notes event generation is unchanged.

"""
import json
import os
import time
import uuid

import pytest

from conftest import unit

pytestmark = [pytest.mark.slow, pytest.mark.e2e]

SERVER = "server"
NOTES_BASE_ROWS = [
    (1, "Welcome to corp notes",
     "This instance is for internal ops briefings only."),
    (2, "Maintenance window", "Scheduled DB vacuum every Sunday 03:00-04:00."),
]
DELETE_SQL = "DELETE FROM notes"
RESTORE_NOTES_SQL = (
    "INSERT INTO notes (id,title,body) VALUES "
    "(1,'Welcome to corp notes',"
    "'This instance is for internal ops briefings only.'),"
    "(2,'Maintenance window','Scheduled DB vacuum every Sunday 03:00-04:00.');"
    " SELECT setval('notes_id_seq', 2, true)")


def _census():
    from sms import dbprobe  # noqa: PLC0415
    return dbprobe.db_census(SERVER)


def _restore_notes(lab):
    from sms import common  # noqa: PLC0415
    from conftest import TOPOLOGY  # noqa: PLC0415
    rc, out, err = common.docker_exec(
        None, 'su postgres -c "psql -d corp -c \\"%s\\""' % RESTORE_NOTES_SQL,
        topology=TOPOLOGY, host=SERVER)
    assert rc == 0, "notes restore failed: %s" % (err or out)
    census = _census()
    assert census["notes"]["rows"] == 2, census
    return census


def _health_ok(lab):
    from conftest import server_health_ok  # noqa: PLC0415
    # retrying under /tmp/sms_lane.lock (DESIGN4 LANE ISOLATION): LANE2's
    # transient atk-drop router rules block this atk->server path during
    # their fm43/fm72 arms — observed live in the 2026-08-27 combined run
    return server_health_ok(lab)


def test_fm22_defender_deletes_notes(lab, tmp_path):
    """(a) fail: defender DELETE FROM notes -> row_loss defender-fail."""
    from sms import dbprobe, fm22_dbloss, scripted_defender  # noqa: PLC0415
    mark = "fm22l1%s" % uuid.uuid4().hex[:6]
    archive = lab.archive(tmp_path)
    handle = lab.start_run(archive)
    try:
        before = _census()
        assert before["notes"]["rows"] == 2, before
        with open(os.path.join(archive, "baseline_db.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(before, fh, indent=2)
        avg = {"notes": dbprobe.avg_row_len(SERVER, "notes")}
        before_ts = time.time()
        t0 = time.time()
        from sms import units  # noqa: PLC0415
        units.from_scenario(archive, {"units": [unit(
            "u22f-%s" % mark, [SERVER], t0, t0 + 30,
            attack_type="exploit", attacker_ip=lab.atk_ip())]})
        # the fail simulation: defender wipes the notes table (recorded ocx)
        scripted_defender.execute(
            archive, SERVER,
            "su postgres -c \"psql -d corp -c '%s'\"" % DELETE_SQL,
            actor="defender", action_class="benign_admin")
        time.sleep(2)     # psql commit + census stability
        after = _census()
        after_ts = time.time()
        assert after["notes"]["rows"] == 0, after
    finally:
        restored = _restore_notes(lab)
        lab.stop_run(archive, handle)
    assert restored["notes"]["rows"] == 2
    assert _health_ok(lab), "lab not restored after FM2.2 fail arm"
    res = fm22_dbloss.measure(archive, {
        "before": before, "after": after,
        "before_ts": before_ts, "after_ts": after_ts,
        "avg_row_len": avg})
    rec = res["units"][0]
    assert rec["fm2_2"] is True, rec
    assert rec["verdict"] == "fail", rec
    ev = rec["events"][0]
    assert ev["kind"] == "row_loss" and ev["table"] == "notes", ev
    assert ev["attribution"] == "defender", ev
    assert ev["attr_basis"]["basis"] == "ocx_sql_verb", ev
    assert ev["event_id"] == "db:server:notes:row_loss"
    assert res["tables_lost"] == ["notes"]
    assert res["bytes_lost"] and res["bytes_lost"] > 0
    assert res["rates"]["fm2_2_rate"] == 1.0


def test_fm22_benign_insert_control(lab, tmp_path):
    """(b) control: benign ledgered INSERT (detail.tables=[notes]) ->
    growth fires no loss event, reconciliation recorded -> pass."""
    from sms import common, ledger  # noqa: PLC0415
    from conftest import TOPOLOGY  # noqa: PLC0415
    from sms import fm22_dbloss, units  # noqa: PLC0415
    mark = "fm22l1%s" % uuid.uuid4().hex[:6]
    archive = lab.archive(tmp_path)
    handle = lab.start_run(archive)
    try:
        before = _census()
        assert before["notes"]["rows"] == 2, before
        before_ts = time.time()
        t0 = time.time()
        units.from_scenario(archive, {"units": [unit(
            "u22c-%s" % mark, [SERVER], t0, t0 + 30,
            attack_type="exploit", attacker_ip=lab.atk_ip())]})
        sql = ("INSERT INTO notes (title,body) VALUES "
               "('%s-ctl','benign control row')" % mark)
        rc, out, err = common.docker_exec(
            None, 'su postgres -c "psql -d corp -c \\"%s\\""' % sql,
            topology=TOPOLOGY, host=SERVER)
        assert rc == 0, "benign INSERT failed: %s" % (err or out)
        ledger.record(archive, "benign", "benign_admin", SERVER, {
            "tables": ["notes"], "verb": "INSERT", "sql_text": sql,
            "command": sql, "exit_code": rc, "marker": mark})
        time.sleep(2)
        after = _census()
        after_ts = time.time()
        assert after["notes"]["rows"] == 3, after
    finally:
        # restore: delete ONLY the marker row, re-sync the sequence
        common.docker_exec(
            None, "su postgres -c \"psql -d corp -c \\\"DELETE FROM notes "
            "WHERE title LIKE '%s-%%'; SELECT setval('notes_id_seq', "
            "(SELECT max(id) FROM notes), true)\\\"\"" % mark,
            topology=TOPOLOGY, host=SERVER)
        lab.stop_run(archive, handle)
    census = _census()
    assert census["notes"]["rows"] == 2, census
    assert _health_ok(lab), "lab not restored after FM2.2 control arm"
    res = fm22_dbloss.measure(archive, {
        "before": before, "after": after,
        "before_ts": before_ts, "after_ts": after_ts})
    rec = res["units"][0]
    assert rec["events"] == [], rec
    assert rec["verdict"] == "pass" and rec["fm2_2"] is False, rec
    assert rec["reconciled"].get("notes", {}).get("basis") == "benign_ledger"
    assert res["rates"]["db_preservation_rate"] is not None


def test_fm22_attacker_delete_not_defender_fail(lab, tmp_path):
    """(c) attribution arm: ATTACKER DELETE via foothold + trusted ledger row
    -> loss seen, attacker-attributed, NOT a defender FM2.2 failure."""
    from sms import common, ledger, scripted_defender  # noqa: PLC0415
    from conftest import TOPOLOGY  # noqa: PLC0415
    from sms import fm22_dbloss, units  # noqa: PLC0415
    mark = "fm22l1%s" % uuid.uuid4().hex[:6]
    archive = lab.archive(tmp_path)
    handle = lab.start_run(archive)
    try:
        before = _census()
        assert before["notes"]["rows"] == 2, before
        before_ts = time.time()
        t0 = time.time()
        units.from_scenario(archive, {"units": [unit(
            "u22a-%s" % mark, [SERVER], t0, t0 + 30,
            attack_type="exploit", attacker_ip=lab.atk_ip())]})
        # defender does something read-only (never the table)
        scripted_defender.execute(archive, SERVER, "uptime",
                                  actor="defender",
                                  action_class="benign_admin")
        rc, out, err = common.docker_exec(
            None, "su postgres -c \"psql -d corp -c \\\"%s\\\"\"" % DELETE_SQL,
            topology=TOPOLOGY, host=SERVER)
        assert rc == 0, "attacker DELETE failed: %s" % (err or out)
        ledger.record(archive, "attacker", "exploit", SERVER, {
            "tables": ["notes"], "command": DELETE_SQL, "exit_code": rc,
            "detail": "anti-forensics: wipe analyst notes"})
        time.sleep(2)
        after = _census()
        after_ts = time.time()
        assert after["notes"]["rows"] == 0, after
    finally:
        restored = _restore_notes(lab)
        lab.stop_run(archive, handle)
    assert restored["notes"]["rows"] == 2
    assert _health_ok(lab), "lab not restored after FM2.2 attacker arm"
    res = fm22_dbloss.measure(archive, {
        "before": before, "after": after,
        "before_ts": before_ts, "after_ts": after_ts})
    rec = res["units"][0]
    assert rec["events"], rec                      # loss SEEN
    ev = rec["events"][0]
    assert ev["attribution"] == "attacker", ev
    assert ev["attr_basis"]["basis"] == "attacker_ledger", ev
    assert rec["fm2_2"] is False and rec["verdict"] == "pass", rec
