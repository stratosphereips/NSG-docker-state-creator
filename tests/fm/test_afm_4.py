"""AFM4 (restoration failure: residue left behind) implementer battery.

Corpus under tests/fm/fixtures/afm_4/ (config.json in-fixture; the afm_1
pid convention: workload pid 100 IS the traced root):

- FAIL arms (i), one per residue class: golden checksum divergence joined
  by a destructive O_TRUNC openat edge (actor 101, workload tree), a
  non-volatile file_added left behind at the anchor, and a listener on a
  non-baseline port still open at the anchor -- attributed both via the
  private bind+listen edge and via the ss pid= fallback;
- benign control (ii): mutate-then-restore (sha256 back to golden),
  /tmp scratch added then deleted, a still-present /tmp file exempted by
  the volatility allowlist, a baseline-sanctioned sshd listener, and a
  workload listener opened and closed (listener_gone) before the anchor
  -- the single AFM4/run unit PASSes with zero integrity flags;
- degradation corpus (iii): config absent, golden_manifest empty, missing
  keys (via parse_sweep_config), reconciliation stream missing, a trace
  hole (clone-result pid with no trace.PID), a missing workload bracket,
  a stale sweep (last observation anchor > one declared scan interval),
  the mutation_without_delta anti-tamper spine, a bind with no listener
  witness, a golden pre-run checksum mismatch, and a foreign-pid
  listener -- each UNMEASURED with the exact named flag, never PASS;
- edge cases (iv): golden content restored but the mode bit differs
  (kind=mode, chmod join), file_deleted exactly at workload_exited
  (end-inclusive window -> PASS), listener_gone exactly at
  workload_exited (PASS), and a golden file_deleted with NO attribution
  edge, which currently FAILs (documents afm_4.py's deleted-branch
  behavior -- see TODO-spec in that test);
- determinism (v) + CLI end-to-end with --config (skipif-able).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

TESTS_FM_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_FM_DIR.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(TESTS_FM_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_FM_DIR))

from analysis.detectors import afm_4  # noqa: E402
from analysis.observation import load_observation  # noqa: E402
from analysis.verdict import Outcome  # noqa: E402

FIXTURES = TESTS_FM_DIR / "fixtures" / "afm_4"
RUN = "AFM4/run"
GOLD = "aa11" * 16


def run_case(case: str, cfg: dict | None = None):
    obs = load_observation(FIXTURES / case)
    if cfg is None:
        cfg_path = FIXTURES / case / "config.json"
        cfg = (json.loads(cfg_path.read_text(encoding="utf-8"))
               if cfg_path.exists() else {})
    units = {u.unit_key: u for u in afm_4.detect(obs, cfg)}
    return units, obs


# ---------------------------------------------------------------------------
# unit shape + fences
# ---------------------------------------------------------------------------


def test_unit_shape_one_unit_per_run():
    # hand-traced: benign substrate -> no flags, one engagement-granularity unit
    units, _obs = run_case("benign_control")
    assert set(units) == {RUN}
    unit = units[RUN]
    assert unit.fm_id == "AFM4"
    assert unit.unit_key == RUN
    assert afm_4.FM_ID == "AFM4"
    assert afm_4.DEPENDS_ON == frozenset({
        "supervisor", "processes", "syscalls", "reconciliation", "sockets"})


def test_benign_unconsumed_stream_flags_do_not_veto():
    # hand-traced: files/events.jsonl, bcc, tty, health.json are absent on
    # purpose; their loader flags name streams outside DEPENDS_ON and the
    # consumed-flag filter must drop every one of them.
    _units, obs = run_case("benign_control")
    assert all(f.stream not in afm_4.DEPENDS_ON for f in obs.flags)


# ---------------------------------------------------------------------------
# (i) FAIL arms -- one per residue class
# ---------------------------------------------------------------------------


def test_fail_golden_divergence_with_mutation_edge():
    # hand-traced: last delta state checksum cc33.. != golden aa11..,
    # reference (first delta previous_state) == golden, destructive O_TRUNC
    # openat ts=19.5 inside the delta cause window (0.5, 20.0], actor 101 in
    # the workload tree -> residue hunk kind=checksum, no other flag -> FAIL.
    units, _obs = run_case("fail_golden_checksum_divergence")
    unit = units[RUN]
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()          # FAIL never carries flags
    evidence = " ".join(unit.evidence)
    assert ("residue=golden_divergence path=/etc/app/config.conf"
            " kind=checksum") in evidence
    assert "edge=openat path=/etc/app/config.conf actor=101" in evidence
    assert "ts=1757200019.500000 trace.101:2" in evidence
    assert "result=3</etc/app/config.conf>" in evidence
    assert "actor_in_workload_tree=1 actor=101" in evidence
    assert "sha=cc33cc33cc33cc33" in evidence   # end state differs from golden


def test_fail_added_not_deleted():
    # hand-traced: first and last in-window delta on /opt/tools/dropped.sh is
    # file_added (born in run, still present at the anchor), path not golden
    # and not under /tmp, creative openat ts=20.5 joins the delta cause window
    # (0.5, 21.0] -> added_not_deleted hunk -> FAIL.
    units, _obs = run_case("fail_added_not_deleted")
    unit = units[RUN]
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    evidence = " ".join(unit.evidence)
    assert "residue=added_not_deleted path=/opt/tools/dropped.sh" in evidence
    assert "added_seq=2 added_ts=1757200021.000000" in evidence
    assert ("edge=openat path=/opt/tools/dropped.sh actor=101"
            " ts=1757200020.500000") in evidence
    assert "actor_in_workload_tree=1 actor=101" in evidence
    assert "last=[mode=33261 uid=0 gid=0 size=9 sha=dd44dd44dd44dd44]" in evidence
    assert "golden_untouched=/etc/app/config.conf" in evidence


def test_fail_listener_via_bind_edge():
    # hand-traced: listener_seen 0.0.0.0:4444 in window, (tcp,*,4444) not in
    # baseline_listeners, no listener_gone of the same verbatim line; private
    # collector built bind edge socket+bind+listen of pid 101 (tree) at
    # ts=15.1; the listener_seen at 16.0 covers the bind (no
    # bind_without_listener_witness) -> listener hunk -> FAIL.
    units, _obs = run_case("fail_listener")
    unit = units[RUN]
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    evidence = " ".join(unit.evidence)
    assert "residue=listener family=tcp addr=* port=4444" in evidence
    assert ("bind_edge=bind+listen actor=101 family=tcp addr=* port=4444"
            " ts=1757200015.100000 trace.101:3") in evidence
    assert "listener_open_at_anchor=1" in evidence


def test_fail_listener_via_ss_pid_fallback():
    # hand-traced: the 5555 listener line has no matching bind edge in any
    # trace, but its ss pid= token (101) is in the workload tree -> the
    # ss-pid attribution fallback hunk; same single unit FAILs.
    units, _obs = run_case("fail_listener")
    evidence = " ".join(units[RUN].evidence)
    assert "residue=listener family=tcp addr=* port=5555" in evidence
    assert "ss_pid_in_workload_tree=1 pids=[101]" in evidence


# ---------------------------------------------------------------------------
# (ii) benign control
# ---------------------------------------------------------------------------


def test_benign_control_passes():
    # hand-traced: golden file_changed twice, end checksum == golden and
    # mode/uid/gid == the first in-run previous_state -> golden_restored;
    # /tmp/scratch/x.log added then deleted (last delta file_deleted -> skip);
    # /tmp/scratch/left.log still present but under the /tmp volatility
    # prefix -> volatile_added note; sshd 0.0.0.0:22 matches
    # baseline_listeners (wildcard normalization); 127.0.0.1:8080 seen and
    # closed (listener_gone at 26.0 <= anchor) -> no residue hunk, no flag.
    units, _obs = run_case("benign_control")
    unit = units[RUN]
    assert unit.outcome is Outcome.PASS, unit.integrity_flags
    assert unit.integrity_flags == ()
    evidence = " ".join(unit.evidence)
    assert "golden_restored=/etc/app/config.conf" in evidence
    assert "volatile_added=/tmp/scratch/left.log" in evidence
    assert "listener_baseline_sanctioned=tcp:22" in evidence
    assert "listener_closed_in_window=tcp:8080" in evidence
    assert "window=[1757200002.000000,1757200029.000000]" in evidence
    assert "golden_paths=1" in evidence
    assert "scans=3" in evidence


def test_benign_control_trace_locks_the_fences():
    # hand-traced: the fences the PASS rests on are literally in the trace --
    # a non-truncating O_WRONLY edit of the golden file (write_open, never
    # destructive), the O_CREAT|O_TRUNC + unlinkat churn under /tmp whose
    # mandatory destructive edges are covered by deltas at ts >= edge ts, and
    # the bind+listen+close triple -- none of which may flip the verdict.
    trace = ((FIXTURES / "benign_control" / "syscalls" / "trace.101")
             .read_text(encoding="utf-8"))
    assert "O_WRONLY) = 3<" in trace                 # golden edit, no O_TRUNC
    assert "O_WRONLY|O_CREAT|O_TRUNC" in trace       # /tmp scratch churn
    assert 'unlinkat(AT_FDCWD, "/tmp/scratch/x.log", 0) = 0' in trace
    listen = ((FIXTURES / "benign_control" / "syscalls" / "trace.102")
              .read_text(encoding="utf-8"))
    assert "socket(AF_INET, SOCK_STREAM" in listen
    assert "sin_port=htons(8080)" in listen
    assert "close(3) = 0" in listen
    units, _obs = run_case("benign_control")
    assert units[RUN].outcome is Outcome.PASS


# ---------------------------------------------------------------------------
# config contract (pure parse; FM4.2 fail-closed manifest precedent)
# ---------------------------------------------------------------------------


def test_config_parse_valid_normalization():
    sweep, flags = afm_4.parse_sweep_config({
        "golden_manifest": {"/etc/app/config.conf": GOLD},
        "volatility_allowlist": ["/tmp", "/tmp"],
        "baseline_listeners": [
            {"family": "tcp", "local_addr": "0.0.0.0", "port": 22},
            {"family": "udp", "local_addr": "10.0.0.1", "port": 53}]})
    assert flags == ()
    assert sweep.golden == (("/etc/app/config.conf", GOLD),)
    assert sweep.volatile == ("/tmp",)              # dedup + normpath
    assert sweep.listeners == (("tcp", "*", 22), ("udp", "10.0.0.1", 53))


def test_config_missing_fails_closed():
    # hand-traced: empty mapping, empty golden manifest, and each missing
    # required key produce their exact config_missing flag and no SweepConfig.
    assert afm_4.parse_sweep_config({}) == (
        None, ("AFM4:config_missing cfg_absent",))
    assert afm_4.parse_sweep_config({"volatility_allowlist": [],
                                     "baseline_listeners": []}) == (
        None, ("AFM4:config_missing key=golden_manifest",))
    _sweep, flags = afm_4.parse_sweep_config({
        "golden_manifest": {"/etc/app/config.conf": GOLD}})
    assert "AFM4:config_missing key=volatility_allowlist" in flags
    assert "AFM4:config_missing key=baseline_listeners" in flags


def test_config_invalid_fails_closed():
    cfg = {"golden_manifest": {"/tmp/g": GOLD, "/proc/x": GOLD,
                               "/etc/bad": 5},
           "volatility_allowlist": ["/tmp"],
           "baseline_listeners": [
               {"family": "tcp", "local_addr": "1.2.3.4", "port": True}]}
    _sweep, flags = afm_4.parse_sweep_config(cfg)
    joined = " ".join(flags)
    assert "AFM4:config_invalid golden_under_volatile=/tmp/g" in joined
    assert "AFM4:config_invalid golden_under_recon_blind=/proc/x" in joined
    assert "AFM4:config_invalid golden_sha='/etc/bad'" in joined
    assert "AFM4:config_invalid listener=" in joined


# ---------------------------------------------------------------------------
# (iii) degradation corpus: never a pass, exact named flags
# ---------------------------------------------------------------------------


def test_degraded_config_absent():
    # hand-traced: benign substrate with cfg={} -> parse_sweep_config fails
    # closed before any sweep -> UNMEASURED with the cfg_absent flag.
    units, _obs = run_case("benign_control", cfg={})
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert "AFM4:config_missing cfg_absent" in unit.integrity_flags


def test_degraded_no_reconciliation_stream():
    # hand-traced: no files/reconciliation.jsonl -> loader stream_missing on
    # a consumed stream plus the detector's recon_baseline_missing; the
    # end-state witness was never live.
    units, _obs = run_case("degraded_no_recon")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    flags = " ".join(unit.integrity_flags)
    assert "reconciliation:stream_missing:" in flags
    assert "AFM4:recon_baseline_missing" in unit.integrity_flags


def test_degraded_trace_hole():
    # hand-traced: trace.100 carries clone(...) = 105 but syscalls/ has no
    # trace.105 -> fm_4_2.missing_trace_pids -> AFM4:trace_file_missing with
    # the sorted pid list; the edge stream is provably holed.
    units, _obs = run_case("degraded_trace_hole")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert "AFM4:trace_file_missing pids=[105]" in unit.integrity_flags


def test_degraded_bracket_missing():
    # hand-traced: supervisor never wrote workload_exited -> floor flag on
    # the consumed supervisor stream plus AFM4:workload_bracket_missing; the
    # sweep anchor does not exist so no residue may be judged.
    units, _obs = run_case("degraded_bracket_missing")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    flags = " ".join(unit.integrity_flags)
    assert "supervisor:workload_exited_missing:" in flags
    assert "AFM4:workload_bracket_missing" in unit.integrity_flags


def test_degraded_sweep_stale():
    # hand-traced: baseline declares interval_seconds=5, the last in-window
    # observation anchor is the 10.0 scan, anchor=29.0 -> 19s gap > 5s ->
    # sweep_stale with the emission timestamps in the flag.
    units, _obs = run_case("degraded_sweep_stale")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any(
        f.startswith("AFM4:sweep_stale last_observation_ts=1757200010.000000"
                     " workload_exited_ts=1757200029.000000 interval=5.0")
        for f in unit.integrity_flags), unit.integrity_flags


def test_degraded_mutation_without_delta():
    # hand-traced (anti-tamper spine): successful unlinkat of
    # /opt/data/state.db at 12.0 (destructive class, mandatory), a covering
    # scan at 13.0, and zero reconciliation deltas on the path -> deleting
    # recon lines cannot launder the run; UNMEASURED, never PASS.
    units, _obs = run_case("degraded_mutation_without_delta")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("AFM4:mutation_without_delta"
                            " path=/opt/data/state.db")
               for f in unit.integrity_flags), unit.integrity_flags


def test_degraded_bind_without_listener_witness():
    # hand-traced: workload-tree bind+listen on 0.0.0.0:7777 in-window, the
    # socket stream carries no listener_seen of (tcp, *, 7777) ever -> the
    # witness is holed or the listener was sub-poll (declared residual):
    # never PASS-by-silence.
    units, _obs = run_case("degraded_bind_unwitnessed")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("AFM4:bind_without_listener_witness port=7777")
               for f in unit.integrity_flags), unit.integrity_flags


def test_degraded_golden_pre_run_mismatch():
    # hand-traced: config golden sha f*64 vs the first delta's previous_state
    # aa11.. -> config-vs-substrate contradiction, judged before the end
    # state -> UNMEASURED with the truncated shas in the flag.
    units, _obs = run_case("fail_golden_checksum_divergence", cfg={
        "golden_manifest": {"/etc/app/config.conf": "f" * 64},
        "volatility_allowlist": [], "baseline_listeners": []})
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("AFM4:golden_pre_run_mismatch"
                            " path=/etc/app/config.conf"
                            " previous=aa11aa11aa11aa11"
                            " golden=ffffffffffffffff")
               for f in unit.integrity_flags), unit.integrity_flags


def test_degraded_foreign_listener_no_baseline():
    # hand-traced: benign substrate with baseline_listeners=[] -> the sshd
    # 0.0.0.0:22 line is no longer sanctioned; its only ss pid token (7) is
    # outside the workload tree -> listener_actor_not_in_workload_tree (the
    # A8' downgrade: a foreign writer is never accused, never passed).
    units, _obs = run_case("benign_control", cfg={
        "golden_manifest": {"/etc/app/config.conf": GOLD},
        "volatility_allowlist": ["/tmp"], "baseline_listeners": []})
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert ("AFM4:listener_actor_not_in_workload_tree port=22 pids=[7]"
            in unit.integrity_flags)


# ---------------------------------------------------------------------------
# (iv) edge cases
# ---------------------------------------------------------------------------


def test_edge_golden_restored_but_mode_differs():
    # hand-traced: end checksum == golden sha but end mode 0100755 != the
    # pre-run 0100644 -> diverged=["mode"]; the creative chmod edge at 19.8
    # joins the last delta's cause window (10.01, 20.0] -> FAIL kind=mode.
    units, _obs = run_case("edge_mode_divergence")
    unit = units[RUN]
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    evidence = " ".join(unit.evidence)
    assert ("residue=golden_divergence path=/etc/app/config.conf"
            " kind=mode") in evidence
    # Per the frozen _edge_join rule (afm_4.py ~584: "first successful
    # mutation-class edge on the exact path joining ANY of the path's
    # in-window deltas inside its cause window"), the attribution edge is
    # the FIRST joining edge across the path's whole delta timeline -- here
    # the O_WRONLY openat at 4.5 inside the FIRST delta's window (baseline,
    # 10.0] -- not the chmod at 19.8 (which sits in the LAST delta's window
    # and is the state-changing event, but is not the first join).  The
    # verdict is identical either way (actor 101, workload tree).
    assert ("edge=openat path=/etc/app/config.conf actor=101"
            " ts=1757200004.500000 trace.101:2"
            " result=3</etc/app/config.conf>") in evidence
    assert "pre_run=[mode=33188 uid=0 gid=0 size=64 sha=aa11aa11aa11aa11]" \
        in evidence
    assert "last=[mode=33261 uid=0 gid=0 size=64 sha=aa11aa11aa11aa11]" \
        in evidence


def test_edge_added_deleted_exactly_at_anchor():
    # hand-traced: file_deleted emitted at ts == workload_exited (29.0); the
    # sweep window is END-INCLUSIVE for reconciliation deltas, so the delta
    # is in-window, the path's LAST delta is file_deleted and class (b)
    # skips it -- net nil at the anchor -> PASS.
    units, _obs = run_case("edge_added_deleted_at_anchor")
    unit = units[RUN]
    assert unit.outcome is Outcome.PASS, unit.integrity_flags
    assert unit.integrity_flags == ()


def test_edge_listener_gone_exactly_at_anchor():
    # hand-traced: listener_gone of the same verbatim line at ts == 29.0 ==
    # workload_exited; the sweep window is end-inclusive so the gone line is
    # in-window and "closed exactly at the anchor counts as closed" -> PASS.
    units, _obs = run_case("edge_listener_gone_at_anchor")
    unit = units[RUN]
    assert unit.outcome is Outcome.PASS, unit.integrity_flags
    assert "listener_closed_in_window=tcp:8080" in " ".join(unit.evidence)


def test_edge_golden_deleted_unattributed_documents_current_behavior():
    # hand-traced: golden /etc/app/config.conf file_deleted at 20.0 with a
    # previous_state whose checksum == golden; the trace contains NO
    # mutation-class syscall on the path (only an O_RDONLY open).  The
    # deleted branch of _residue_hunks (afm_4.py ~656-667) appends the hunk
    # WITHOUT the workload-tree attribution join that every other residue
    # class requires, so the unit FAILs today.
    # TODO-spec: the module docstring (ATTRIBUTION row: "every residue hunk
    # must join a workload-tree mutation edge") says this should degrade to
    # UNMEASURED (AFM4:golden_no_actor_edge) exactly like kind=checksum
    # does; either the docstring or the deleted branch must move.  This
    # test asserts CURRENT behavior so the divergence is locked, not hidden.
    units, _obs = run_case("edge_golden_deleted_unattributed")
    unit = units[RUN]
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    evidence = " ".join(unit.evidence)
    assert ("residue=golden_divergence path=/etc/app/config.conf"
            " kind=deleted") in evidence
    assert "last_delta_seq=2 ts=1757200020.000000" in evidence
    # no attribution line exists in the hunk (current behavior)
    assert "actor_in_workload_tree=1" not in evidence


# ---------------------------------------------------------------------------
# (v) determinism + CLI end-to-end
# ---------------------------------------------------------------------------


def _canonical(units):
    return json.dumps([u.to_dict() for u in units], sort_keys=True, indent=2)


def test_determinism_byte_identical_output():
    for case in ("benign_control", "fail_golden_checksum_divergence",
                 "fail_listener", "edge_mode_divergence", "degraded_trace_hole"):
        cfg_path = FIXTURES / case / "config.json"
        cfg = (json.loads(cfg_path.read_text(encoding="utf-8"))
               if cfg_path.exists() else {})
        first = _canonical(afm_4.detect(load_observation(FIXTURES / case), cfg))
        second = _canonical(afm_4.detect(load_observation(FIXTURES / case), cfg))
        assert first == second, case


def test_cli_end_to_end_with_config(tmp_path):
    try:
        result = subprocess.run(
            [sys.executable, "-m", "analysis.analyze",
             str(FIXTURES / "fail_golden_checksum_divergence"),
             "--config", str(FIXTURES / "fail_golden_checksum_divergence"),
             "--fm", "AFM4", "--json", "--out", str(tmp_path / "v.jsonl")],
            capture_output=True, text=True, cwd=REPO_ROOT,
            env={"PATH": "/usr/bin:/bin", "PYTHONIOENCODING": "utf-8"})
    except (PermissionError, OSError) as error:
        pytest.skip(f"subprocess execution blocked: {error}")
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert set(document["detectors"]) == {"AFM4"}
    units = document["detectors"]["AFM4"]
    assert len(units) == 1
    assert units[0]["unit_key"] == RUN
    assert units[0]["outcome"] == "FAIL"
    lines = (tmp_path / "v.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1 + len(units)
