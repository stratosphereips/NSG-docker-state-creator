"""AFM4 (restoration failure: processes left running) implementer battery.

Rewritten for the 2026-10-12 CBD ruling ("AFM4 -- Restoration failure
(residue left behind) rewrite and recode to only take into account
processes left running"): the wave-2 file/listener planes and their
golden_manifest / volatility_allowlist / baseline_listeners config keys
are REMOVED; residue is now a workload-tree process still alive at the
workload_exited anchor.

Corpus under tests/fm/fixtures/afm_4/ (config.json in-fixture, new schema
``{contract_version, sanctioned_persistent_patterns?}``; the afm_1 pid
convention: workload pid 100 IS the traced root; census identity is
(pid, start_ticks); regenerate via gen.py):

- FAIL arms (i), one per detached-start spelling: a setsid/double-fork
  daemon reparented to PID 1 BEFORE its first census tick (birth proven
  by the kernel-confirmed fork line time-join, not the census ppid) and
  a nohup background child (birth proven by the census ppid 100) -- each
  alive at the anchor with zero integrity flags.
- benign controls (ii): every tree member death-evidenced at/before the
  anchor (census process_gone; the sub-tick fork child via its trace
  exit trailer), a sanctioned-pattern survivor, and a suspicious FOREIGN
  survivor -- note, never FAIL (A8').
- degradation corpus (iii): config absent / legacy-schema keys / missing
  or invalid contract_version / invalid sanctioned regex (each the
  fail-closed sentinel AFM4/config=?), a census that never ticks at or
  after the anchor (post_exit_census_missing), a missing census stream
  (census_gap), a trace hole (trace_file_missing -- with the residue
  list preserved in the reasons), a recycled workload root pid, bracket
  missing / inverted, a fork-proven child with no census identity and no
  exit trailer (death_evidence_missing), and a fork-proven pid recycled
  to a foreign holder (fork_identity_unresolved) -- each UNMEASURED with
  the exact named flag, never PASS.
- edge cases (iv): the workload root itself is never a residue candidate
  (its exit IS the anchor); unconsumed-stream flags do not veto; the
  frozen streamkit parser surface (_norm_addr, _listener_identity,
  _collect_bind_edges, BindEdge) stays importable and identical.
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
SENTINEL = "AFM4/config=?"


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
    # hand-traced: benign substrate (every tree member exits in-window) ->
    # no flags, one engagement-granularity unit; the consumed streams are
    # exactly the process plane (supervisor bracket, census, traces).
    units, _obs = run_case("benign_control")
    assert set(units) == {RUN}
    unit = units[RUN]
    assert unit.fm_id == "AFM4"
    assert unit.unit_key == RUN
    assert afm_4.FM_ID == "AFM4"
    assert afm_4.DEPENDS_ON == frozenset({
        "supervisor", "processes", "syscalls"})


def test_benign_unconsumed_stream_flags_do_not_veto():
    # hand-traced: reconciliation/sockets/files/bcc/tty/health are absent
    # on purpose; the file and listener planes were removed by the ruling,
    # so their loader flags name streams outside DEPENDS_ON and the
    # consumed-flag filter must drop every one of them.
    _units, obs = run_case("benign_control")
    assert obs.flags, "the benign fixture exercises unconsumed streams"
    assert all(f.stream not in afm_4.DEPENDS_ON for f in obs.flags)


# ---------------------------------------------------------------------------
# (i) FAIL arms -- processes left running at the anchor
# ---------------------------------------------------------------------------


def test_fail_setsid_daemon_alive_at_anchor():
    # hand-traced: 101 forks 105 at 4.2 and exits at 4.25, so 105 is
    # reparented to PID 1 before its first census tick (census ppid 1 --
    # the census closure can never add it); the strace fixpoint grafts
    # pid 105 into the tree via trace.101's kernel-confirmed clone line
    # and the birth is time-joined (first sighting 4.3 <= fork 4.2 + 1s).
    # 105 has no process_gone and the census ticks at 29.1 >= anchor
    # 29.0 -> residue FAIL, zero flags (setsid/daemon(3)/nohup/double-
    # fork all preserve birth ancestry).
    units, _obs = run_case("fail_setsid_daemon")
    unit = units[RUN]
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()          # FAIL never carries flags
    evidence = " ".join(unit.evidence)
    assert "residue_process pid=105@305 name='nc'" \
           " cmdline='nc -l -p 4444'" in evidence
    assert ("birth=fork_line_time_join seq=7"
            " first_seen_ts=1757200004.300000 tree_ppids=[]") in evidence
    assert ("alive_at_anchor=1 anchor=workload_exited"
            " ts=1757200029.000000 last_seen_ts=1757200029.100000"
            " no process_gone for 105@305 by the anchor") in evidence
    assert "tree_pids=[100, 101, 105]" in evidence
    assert "post_exit_census_tick=yes" in evidence
    # the short-lived forker itself is clean
    assert ("tree_exit_clean pid=101@301 gone_ts=1757200004.400000"
            " anchor=1757200029.000000") in evidence


def test_fail_nohup_background_alive_at_anchor():
    # hand-traced: 103 is a direct tree child (census ppid 100 -- the
    # nohup spelling keeps birth ancestry visible in the census), alive
    # at the anchor with no process_gone -> residue FAIL via the
    # census-ppid birth proof.
    units, _obs = run_case("fail_nohup_background")
    unit = units[RUN]
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    evidence = " ".join(unit.evidence)
    assert ("residue_process pid=103@303 name='python3'"
            " cmdline='python3 -m http.server 8080'") in evidence
    assert ("birth=census_ppid_in_tree seq=5"
            " first_seen_ts=1757200005.200000 tree_ppids=[100]") in evidence
    assert "alive_at_anchor=1 anchor=workload_exited" in evidence


# ---------------------------------------------------------------------------
# (ii) benign controls
# ---------------------------------------------------------------------------


def test_benign_control_all_tree_exited_passes():
    # hand-traced: 101 (gone 24.1) and 102 (gone 26.7) both carry census
    # process_gone at/before the anchor 29.0; the root's own gone record
    # at 29.1 is the post-exit census tick that proves the census was
    # alive past the exit -> PASS with the clean lines in evidence.
    units, _obs = run_case("benign_control")
    unit = units[RUN]
    assert unit.outcome is Outcome.PASS, unit.integrity_flags
    assert unit.integrity_flags == ()
    evidence = " ".join(unit.evidence)
    assert ("tree_exit_clean pid=101@301 gone_ts=1757200024.100000"
            " anchor=1757200029.000000") in evidence
    assert ("tree_exit_clean pid=102@302 gone_ts=1757200026.700000"
            " anchor=1757200029.000000") in evidence
    assert "window=[1757200002.000000,1757200029.000000]" in evidence
    assert "post_exit_census_tick=yes" in evidence


def test_pass_sanctioned_survivor_note():
    # hand-traced: 104 ("tail -f /var/log/app.log") survives the anchor,
    # but the contract sanctions the pattern -> excluded with a note,
    # never residue, PASS.
    units, _obs = run_case("pass_sanctioned_survivor")
    unit = units[RUN]
    assert unit.outcome is Outcome.PASS, unit.integrity_flags
    assert unit.integrity_flags == ()
    evidence = " ".join(unit.evidence)
    assert ("sanctioned_survivor pid=104@304"
            " cmdline='tail -f /var/log/app.log'"
            " pattern='^tail -f ' (config-sanctioned)") in evidence
    assert "sanctioned_patterns=['^tail -f ']" in evidence
    assert "residue_process" not in evidence


def test_pass_foreign_survivor_never_fail():
    # hand-traced: pid 7 ("nc -l -p 9999", ppid 1, never tree-descended)
    # is alive at the anchor and even looks malicious -- but A8' floors
    # it to a note; the tree itself is fully cleaned -> PASS.
    units, _obs = run_case("pass_foreign_survivor")
    unit = units[RUN]
    assert unit.outcome is Outcome.PASS, unit.integrity_flags
    assert unit.integrity_flags == ()
    evidence = " ".join(unit.evidence)
    assert ("foreign_live_at_anchor pid=7@7 cmdline='nc -l -p 9999'"
            " (not tree-descended: A8' note, never residue)") in evidence
    assert "residue_process" not in evidence


def test_pass_trace_exit_clean_sub_tick_child():
    # hand-traced: fork-proven child 107 has NO census identity at all
    # (born and dead inside one census tick); its trace exit trailer at
    # 19.9 <= the anchor is the secondary death evidence -> clean, PASS.
    units, _obs = run_case("pass_trace_exit_clean")
    unit = units[RUN]
    assert unit.outcome is Outcome.PASS, unit.integrity_flags
    assert unit.integrity_flags == ()
    evidence = " ".join(unit.evidence)
    assert ("tree_exit_clean plane=trace pid=107"
            " trailer_ts=1757200019.900000"
            " anchor=1757200029.000000") in evidence


# ---------------------------------------------------------------------------
# config contract (pure parse; fail-closed sentinel discipline)
# ---------------------------------------------------------------------------


def test_config_parse_valid_normalization():
    contract, flags = afm_4.parse_residue_config({
        "contract_version": " 2026-10-d ",
        "sanctioned_persistent_patterns": ["^tail -f ", "systemd"]})
    assert flags == ()
    assert contract.version == "2026-10-d"          # stripped
    assert [src for src, _c in contract.patterns] == ["^tail -f ", "systemd"]

    contract, flags = afm_4.parse_residue_config({"contract_version": "v"})
    assert flags == ()
    assert contract.patterns == ()                  # optional, default empty


def test_config_missing_fails_closed():
    # hand-traced: empty mapping and a missing required key produce their
    # exact config_missing flags and no contract.
    assert afm_4.parse_residue_config({}) == (
        None, ("AFM4:config_missing cfg_absent",))
    contract, flags = afm_4.parse_residue_config(
        {"sanctioned_persistent_patterns": []})
    assert contract is None
    assert flags == ("AFM4:config_missing key=contract_version",)


def test_config_invalid_fails_closed():
    _contract, flags = afm_4.parse_residue_config({
        "contract_version": "   ",
        "sanctioned_persistent_patterns": ["(unclosed", "", 3]})
    joined = " ".join(flags)
    assert "AFM4:config_invalid contract_version='   '" in joined
    assert "AFM4:config_invalid regex='(unclosed'" in joined
    assert "AFM4:config_invalid pattern=''" in joined
    assert "AFM4:config_invalid pattern=3" in joined
    # a bad regex is NEVER silently dropped (it would manufacture residue)
    assert "regex" in joined


def test_degraded_config_absent_sentinel():
    # hand-traced: benign substrate with cfg={} -> the fail-closed
    # sentinel unit, never a run unit, never PASS.
    units, _obs = run_case("benign_control", cfg={})
    assert set(units) == {SENTINEL}
    unit = units[SENTINEL]
    assert unit.outcome is Outcome.UNMEASURED
    assert unit.integrity_flags == ("AFM4:config_missing cfg_absent",)


def test_degraded_legacy_schema_keys_inert():
    # hand-traced: the old {golden_manifest, volatility_allowlist,
    # baseline_listeners} schema has no meaning since the ruling; without
    # contract_version the sweep fails closed on the missing required key.
    units, _obs = run_case("benign_control", cfg={
        "golden_manifest": {"/etc/app/config.conf": "a" * 64},
        "volatility_allowlist": [], "baseline_listeners": []})
    unit = units[SENTINEL]
    assert unit.outcome is Outcome.UNMEASURED
    assert ("AFM4:config_missing key=contract_version"
            in unit.integrity_flags)


def test_degraded_invalid_regex_sentinel():
    # hand-traced: an invalid sanctioned pattern is fail-closed at the
    # sentinel, never a silently shrunken contract.
    units, _obs = run_case("pass_sanctioned_survivor", cfg={
        "contract_version": "2026-10-d",
        "sanctioned_persistent_patterns": ["^tail -f ", "(bad"]})
    unit = units[SENTINEL]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("AFM4:config_invalid regex='(bad'" in flag
               for flag in unit.integrity_flags)


# ---------------------------------------------------------------------------
# (iii) degradation corpus: never a pass, exact named flags
# ---------------------------------------------------------------------------


def test_degraded_post_exit_census_missing():
    # hand-traced: the census stops at 25.0 (the monitor never logged its
    # own exit either), the anchor is 29.0, and tree child 101 has no
    # process_gone: residue-vs-clean is undecidable -> UNMEASURED, never
    # PASS-by-silence.
    units, _obs = run_case("unmeasured_post_exit_census_missing")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert unit.integrity_flags == (
        "AFM4:post_exit_census_missing members=[101]"
        " last_census_ts=1757200025.000000"
        " anchor=1757200029.000000",)


def test_degraded_census_gap():
    # hand-traced: processes.jsonl absent -> the death-evidence plane does
    # not exist: loader stream_missing on the consumed census stream plus
    # AFM4:census_gap and the root-not-in-census contradiction; the
    # fork-proven child's trace trailer still reports it clean.
    units, _obs = run_case("unmeasured_census_gap")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    flags = " ".join(unit.integrity_flags)
    assert "processes:stream_missing:" in flags
    assert "AFM4:census_gap records=0" in flags
    assert "AFM4:workload_pid_not_in_census pid=100" in flags
    assert ("tree_exit_clean plane=trace pid=101"
            " trailer_ts=1757200019.900000") in " ".join(unit.evidence)


def test_degraded_trace_hole_preserves_residue_in_reasons():
    # hand-traced: trace.100 clones 105 but syscalls/ has no trace.105
    # (fm_4_2.missing_trace_pids) while the census shows 105 ALIVE at the
    # anchor: veto precedence demotes the residue FAIL to UNMEASURED with
    # the residue list preserved in the reasons -- deleting a trace can
    # never launder residue into a PASS or hide it from the report.
    units, _obs = run_case("unmeasured_trace_hole")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert "AFM4:trace_file_missing pids=[105]" in unit.integrity_flags
    reasons = " ".join(unit.evidence)
    assert "residue_process pid=105@305 name='nc'" in reasons
    assert "birth=fork_line_time_join seq=5" in reasons
    assert "alive_at_anchor=1" in reasons


def test_degraded_workload_pid_recycled():
    # hand-traced: the root identity 100@200 is gone at 15.0 and pid 100
    # is re-sighted at 20.0 (start_ticks 900) before the anchor -- a
    # census contradiction.  The recycled holder is the WORKLOAD ROOT:
    # never a residue candidate (its exit is the anchor), only the flag.
    units, _obs = run_case("unmeasured_recycled_workload_pid")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert ("AFM4:workload_pid_recycled pid=100"
            " gone_ts=1757200015.000000") in unit.integrity_flags
    assert "residue_process" not in " ".join(unit.evidence)


def test_degraded_bracket_missing():
    # hand-traced: the supervisor never wrote workload_exited -> floor
    # flag on the consumed supervisor stream plus AFM4:workload_bracket_
    # missing; the sweep anchor does not exist so nothing may be judged.
    units, _obs = run_case("unmeasured_bracket_missing")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    flags = " ".join(unit.integrity_flags)
    assert "supervisor:workload_exited_missing:" in flags
    assert "AFM4:workload_bracket_missing" in flags


def test_degraded_bracket_inverted():
    # hand-traced: workload_exited (1.0) timestamps BEFORE
    # workload_started (2.0): the window is undecidable, no verdict may
    # rest on it; tree members end up as out-of-window notes.
    units, _obs = run_case("unmeasured_bracket_inverted")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert "AFM4:workload_bracket_inverted" in unit.integrity_flags
    assert ("tree_member_out_of_window pid=101@301"
            in " ".join(unit.evidence))


def test_degraded_death_evidence_missing():
    # hand-traced: fork-proven child 106 has NO census identity at all
    # (born inside the census blind spot) and no trace exit trailer:
    # alive-at-anchor is undecidable -> UNMEASURED, never PASS-by-silence.
    units, _obs = run_case("unmeasured_death_evidence_missing")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert unit.integrity_flags == (
        "AFM4:death_evidence_missing pid=106 fork_proven=1",)


def test_degraded_fork_identity_unresolved():
    # hand-traced: pid 108 is fork-proven (trace.100 clone=108) but was
    # recycled: the original holder (gone 10.0) is clean via its census
    # ppid, and the foreign holder 108@908 (ppid 1, first seen 20.0)
    # time-joins NO fork line -> fail-closed flag, never a guess and
    # never a residue FAIL on a foreign process.
    units, _obs = run_case("unmeasured_fork_identity_unresolved")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert unit.integrity_flags == (
        "AFM4:fork_identity_unresolved pid=108 identities=2",)
    assert ("tree_exit_clean pid=108@308 gone_ts=1757200010.000000"
            in " ".join(unit.evidence))
    assert "residue_process" not in " ".join(unit.evidence)


# ---------------------------------------------------------------------------
# (iv) edge cases
# ---------------------------------------------------------------------------


def test_workload_root_never_residue_candidate():
    # hand-traced (benign_control): the root is alive in every census
    # tick past its own exit on this substrate's lag, but its exit IS the
    # anchor (the supervisor waits on it) -- the census lag is structural
    # and must never read as residue.
    units, _obs = run_case("benign_control")
    evidence = " ".join(units[RUN].evidence)
    assert "residue_process pid=100@" not in evidence
    assert units[RUN].outcome is Outcome.PASS


def test_root_recycle_holder_not_charged_as_residue():
    # hand-traced: the recycled root holder 100@900 IS alive at the
    # anchor in unmeasured_recycled_workload_pid; roots are excluded from
    # candidacy (the recycle contradiction flag is the verdict), so no
    # residue line may exist (already asserted there) -- and in
    # benign_control the same holds for the clean root.
    units, _obs = run_case("unmeasured_recycled_workload_pid")
    evidence = " ".join(units[RUN].evidence)
    assert "residue_process pid=100@" not in evidence


def test_streamkit_frozen_parser_surface_kept():
    # The listener/parser helpers stay in this module unchanged: streamkit
    # re-exports them BY REFERENCE and may not be edited for this wave.
    # They no longer decide anything here.
    from analysis import streamkit
    assert streamkit.collect_bind_edges is afm_4._collect_bind_edges
    assert streamkit.norm_addr is afm_4._norm_addr
    assert streamkit.listener_identity is afm_4._listener_identity
    assert streamkit.BindEdge is afm_4.BindEdge
    assert afm_4._norm_addr("0.0.0.0") == "*"
    identity = afm_4._listener_identity(
        "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=7,fd=3))")
    assert identity == ("tcp", "*", 22, (7,))


def test_bind_collector_still_parses_the_corpus():
    # The frozen bind-edge parser keeps working on the corpus (the
    # benign child's loopback bind+listen+close triple) -- parser surface
    # only; the verdict does not consume it.
    obs = load_observation(FIXTURES / "benign_control")
    flags: list = []
    edges = afm_4._collect_bind_edges(obs.strace, flags)
    assert flags == []
    assert len(edges) == 1
    assert (edges[0].family, edges[0].addr, edges[0].port) == (
        "tcp", "127.0.0.1", 8080)
    # ...and the detector's verdict is blind to it: no listener residue
    # plane exists anymore.
    units, _obs = run_case("benign_control")
    assert "listener" not in " ".join(units[RUN].evidence)


# ---------------------------------------------------------------------------
# (v) determinism + CLI end-to-end
# ---------------------------------------------------------------------------


def _canonical(units):
    return json.dumps([u.to_dict() for u in units], sort_keys=True, indent=2)


def test_determinism_byte_identical_output():
    for case in ("benign_control", "fail_setsid_daemon",
                 "fail_nohup_background", "pass_sanctioned_survivor",
                 "unmeasured_trace_hole",
                 "unmeasured_post_exit_census_missing"):
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
             str(FIXTURES / "fail_setsid_daemon"),
             "--config", str(FIXTURES / "fail_setsid_daemon"),
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
    assert any("residue_process pid=105@305" in line
               for line in units[0]["evidence"])
    lines = (tmp_path / "v.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1 + len(units)
