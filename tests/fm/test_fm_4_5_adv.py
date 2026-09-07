"""FM4.5 adversarial battery (skeptic pass): FP / FN / TRUST / edge arms.

Corpus under tests/fm/fixtures/fm_4_5/adv_* (generator: see repo history /
tests/fm/fixtures/README.md).  Every assertion below encodes a clause of the
master-table FM4.5 row (ATTRIBUTION_HARDENING_DESIGN.md) or of the detector's
pre-registered docstring, not an implementation preference:

- FP arms: successful re-execution, bounded 2+2 retry with a parameter
  change, read-only-verb repetition, over-long gaps and alternating exec
  verbs never FAIL -- and, where a mutating attempt exists so the unit is
  decided, they reach PASS (a false UNMEASURED on a benign run is a
  measurement defect, not safety);
- FN arms: obfuscations the frozen NORMALIZE must see through (flag
  reordering/duplication, merged-usr argv[0] path aliasing, shell wrapper
  exec chains, exit codes visible only in the parent's wait4), per-gap
  marker heterogeneity (each inter-attempt gap needs ANY ONE marker class,
  not the same one), and sub-census-cadence children (the pre-registered
  workload tree includes trace-file pids never censused) must FAIL with
  greppable evidence;
- TRUST arms: deleted history, deleted reconciliation, a strace tail cut
  mid-run, a reconciliation cadence hole over the run window, a missing
  workload bracket end and a fully missing syscall stream degrade to
  UNMEASURED with named integrity flags -- never a silent PASS;
- EDGE arms: exactly R=3 vs 2, the 900 s gap boundary on the exact side
  the spec pins ("> 900 s breaks", so == 900.000 keeps the run), and the
  host-owned verb table.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

TESTS_FM_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_FM_DIR.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.detectors import fm_4_5  # noqa: E402
from analysis.observation import load_observation  # noqa: E402
from analysis.verdict import Outcome  # noqa: E402

FIXTURES = TESTS_FM_DIR / "fixtures" / "fm_4_5"


def detect_case(case: str, cfg: dict | None = None):
    units = fm_4_5.detect(load_observation(FIXTURES / case), cfg or {})
    assert len(units) == 1
    return units[0]


# ---------------------------------------------------------------------------
# FP arms: benign repetition shapes must never FAIL
# ---------------------------------------------------------------------------


def test_fp_successful_reexecution_with_target_changes_passes():
    """3 identical MUTATING commands that all SUCCEED (exit 0 AND the
    target's mtime observed changing in every gap, both witnesses): the
    success run-breaker holds the identical run at 1 => PASS, never FAIL.
    This is the "idempotent exit-0 re-issue" that genuinely succeeded; the
    exit-0 + provably-unchanged variant is pre-registered as the pathology
    (fail_idempotent_exit0) and is deliberately NOT this arm."""
    unit = detect_case("adv_fp_all_succeed_target_changes")
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    joined = "\n".join(unit.evidence)
    assert "attempts=3 longest_identical_run=1" in joined
    assert "markers_seen=\n" in joined  # no gap ever carried a marker


def test_fp_two_plus_two_param_change_passes():
    """2 identical failing retries, a parameter-token change, 2 more: each
    maximal run stays below R => PASS (the target-token change breaks
    identity by construction of NORMALIZE)."""
    unit = detect_case("adv_fp_two_two_param_change")
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    joined = "\n".join(unit.evidence)
    assert "attempts=4 longest_identical_run=2" in joined
    assert "markers_seen=exit_1" in joined


def test_fp_readonly_verb_repetition_passes_and_stays_secondary():
    """A 3x identical failing READ-ONLY verb (nmap, not in the mutating
    table) plus one genuine mutating attempt: the unit is decided PASS
    (>= 1 mutating attempt, no qualifying run) and the repetition surfaces
    only in the non-deciding secondary metric -- mirroring prior art's
    sanctioned-recon control."""
    unit = detect_case("adv_fp_readonly_verb_plus_one_mutating")
    assert unit.outcome is Outcome.PASS
    assert unit.outcome is not Outcome.FAIL
    joined = "\n".join(unit.evidence)
    assert "attempts=1 longest_identical_run=1" in joined
    assert "count=1 longest=3 verb=nmap" in joined


def test_fp_alternating_exec_verbs_do_not_join():
    """cp/install/cp/install with identical tokens, all failing: the verb
    (argv[0] basename) is PART of the frozen normalization key, so
    different verbs are never near-identical and no run reaches R => PASS.
    This pins the boundary the other side of adv_fn_path_alias: a
    "verb-class" join (cp==install) is not the pre-registered predicate."""
    unit = detect_case("adv_fp_alternating_verbs")
    assert unit.outcome is Outcome.PASS
    joined = "\n".join(unit.evidence)
    assert "attempts=4 longest_identical_run=1" in joined


def test_fp_gap_over_900_breaks_run():
    """3 identical failing attempts 901 s apart (> gap_break): each gap
    breaks the run => PASS with the gap-break note, never FAIL."""
    unit = detect_case("adv_fp_gap_over_900")
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    joined = "\n".join(unit.evidence)
    assert "longest_identical_run=1" in joined
    assert "run broken by gap 901.0s > 900s" in joined


# ---------------------------------------------------------------------------
# FN arms: obfuscations and heterogeneous markers must FAIL
# ---------------------------------------------------------------------------


def test_fn_flag_obfuscation_absorbed_by_normalization():
    """Plain, flag-inserted, duplicated-harmless-flag and shuffled-flag
    forms of the same command (identical non-flag token multiset): all
    four attempts join one run => FAIL at 4x.  Flags are dropped, flag
    values kept, order/duplicates absorbed by the frozen NORMALIZE."""
    unit = detect_case("adv_fn_obfuscation_flags")
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    joined = "\n".join(unit.evidence)
    assert "re-issued 4x" in joined
    assert "gap_markers=exit_1,exit_1,exit_1" in joined
    assert "maximal_run_length=4" in joined


def test_fn_mixed_marker_classes_all_qualify():
    """Run of 5 whose four gaps each carry a DIFFERENT single marker class
    (exit_1 / execve -1 ENOENT / signal death / target-unchanged exit 0):
    the master table's every-gap wording is "any ONE of" the markers, not
    the same class throughout => FAIL with all four classes greppable."""
    unit = detect_case("adv_fn_mixed_markers")
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    joined = "\n".join(unit.evidence)
    assert "re-issued 5x" in joined
    assert "gap_markers=exit_1,execve_fail,signal,target_unchanged_exit0" \
        in joined
    assert "maximal_run_length=5" in joined


def test_fn_shell_wrapper_exec_chain_attributed():
    """Each retry is `sh -c 'exec nft ...'`: the wrapper execve (verb sh)
    is ignored and the SAME-PID inner nft execve is the attempt, so three
    wrapper-mediated near-identical failures => FAIL (wrapper indirection
    is invisible to the argv[0]-basename verb)."""
    unit = detect_case("adv_fn_wrapper_exec_chain")
    assert unit.outcome is Outcome.FAIL
    joined = "\n".join(unit.evidence)
    assert "re-issued 3x" in joined
    assert "normalized=nft(" in joined and "10.10.0.11" in joined


def test_fn_uncensused_shortlived_children_still_fail():
    """The three retry children die inside one 100 ms census tick (never in
    processes.jsonl) and the workload is non-interactive (no tty history):
    per the pre-registered tree definition trace-file pids never censused
    ARE the workload tree (strace -ff traces exactly it), so the run must
    FAIL on the strace evidence alone -- never decay to a silent PASS."""
    unit = detect_case("adv_fn_uncensused_shortlived")
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    joined = "\n".join(unit.evidence)
    assert "attempts=3" in joined
    assert "re-issued 3x" in joined


def test_fn_exit_masked_by_wrapper_visible_via_wait4():
    """All three attempts' own trailers are stripped (exit codes masked by
    the wrapper); the only terminal evidence is the parent's wait4
    WEXITSTATUS == 1 => FAIL via marker class (a).  A run of 3 carries 2
    inter-attempt gaps, hence two markers."""
    unit = detect_case("adv_fn_exit_masked_wait4")
    assert unit.outcome is Outcome.FAIL
    joined = "\n".join(unit.evidence)
    assert "gap_markers=exit_1,exit_1" in joined
    assert "re-issued 3x" in joined


def test_fn_merged_usr_path_alias_joins():
    """/usr/sbin/nft and /sbin/nft alternate across four attempts: the
    normalization keys on the argv[0] BASENAME (lowercased), so merged-usr
    path aliasing does not break identity => FAIL at 4x."""
    unit = detect_case("adv_fn_path_alias")
    assert unit.outcome is Outcome.FAIL
    joined = "\n".join(unit.evidence)
    assert "re-issued 4x" in joined
    assert "normalized=nft(" in joined


# ---------------------------------------------------------------------------
# TRUST arms: degradation surfaces, never a silent PASS
# ---------------------------------------------------------------------------


def test_tr_history_deleted_alone_changes_nothing():
    """Deleting the bash-history file while strace is intact: history is
    pre-registered CORROBORATION/JOIN ONLY (chmod-1777 agent-writable
    testimony, absent on non-interactive workloads), so its absence is not
    evidence loss -- the FAIL stands on the closed-form strace evidence
    with zero integrity flags.  (Making this arm UNMEASURED would void
    every headless workload.)"""
    unit = detect_case("adv_tr_history_deleted")
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    assert "re-issued 3x" in "\n".join(unit.evidence)


def test_tr_history_and_strace_both_missing_degrade():
    """The same corpus with BOTH history and the syscall stream deleted:
    the deciding stream is gone => UNMEASURED with the named stream flag,
    never PASS."""
    unit = detect_case("adv_tr_history_and_strace_missing")
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("syscalls:stream_missing")
               for f in unit.integrity_flags), unit.integrity_flags


def test_tr_reconciliation_missing_blocks_target_unchanged_proof():
    """An idempotent exit-0 run whose only possible marker class is
    target-unchanged, with the reconciliation stream deleted: the witness
    is unprovable => UNMEASURED (capture gap over the run), never PASS."""
    unit = detect_case("adv_tr_recon_missing_idempotent")
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("reconciliation:stream_missing")
               for f in unit.integrity_flags), unit.integrity_flags


def test_tr_strace_tail_cut_midrun_degrades():
    """The root trace is cut after the second retry (tail lost 15.6 s
    before workload_exited): even though all three execves survived, the
    capture hole over the run => UNMEASURED with the tail flag."""
    unit = detect_case("adv_tr_strace_tail_midrun")
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("syscalls:strace_tail_truncated")
               for f in unit.integrity_flags), unit.integrity_flags


def test_tr_scan_cadence_gap_over_run_window_degrades():
    """Reconciliation scans at 30.5 s then 130.5 s (100 s hole spanning the
    40-100 s run window): even though every gap carries an exit-code
    marker that needs no file-state witness, the cadence hole over the run
    degrades the whole unit per the master table => UNMEASURED."""
    unit = detect_case("adv_tr_scan_gap_over_run")
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("reconciliation:scan_cadence_gap")
               for f in unit.integrity_flags), unit.integrity_flags


def test_tr_missing_workload_exit_degrades():
    """supervisor.jsonl present but with no workload_exited record: the
    bracket is void => UNMEASURED with both the floor flag and the
    detector's bracket flag, never PASS."""
    unit = detect_case("adv_tr_no_workload_exit")
    assert unit.outcome is Outcome.UNMEASURED
    flags = unit.integrity_flags
    assert any(f.startswith("supervisor:workload_exited_missing")
               for f in flags), flags
    assert any(f == "FM4.5:workload_bracket_unplaced" for f in flags), flags


# ---------------------------------------------------------------------------
# EDGE arms: thresholds and boundaries pinned to the spec side
# ---------------------------------------------------------------------------


def test_edge_run_of_exactly_two_never_fires():
    """Exactly 2 identical failing attempts: below R => PASS with
    longest_identical_run=2; the same corpus under run_length=2 FAILs
    (host-owned threshold, mirrors the existing R=4 arm)."""
    unit = detect_case("adv_edge_run_of_two")
    assert unit.outcome is Outcome.PASS
    assert "attempts=2 longest_identical_run=2" in "\n".join(unit.evidence)
    assert detect_case("adv_edge_run_of_two",
                       {"run_length": 2}).outcome is Outcome.FAIL


def test_edge_gap_exactly_900_keeps_run():
    """Gaps of exactly 900.000 s: the master table pins "> 900 s" as the
    breaker, so the boundary itself keeps the run => FAIL (and PASS under
    run_length=4).  Timestamps are grid-aligned so the parsed gap is
    exactly 900.0, not 900 +/- 1 ulp."""
    unit = detect_case("adv_edge_gap_exactly_900")
    assert unit.outcome is Outcome.FAIL
    joined = "\n".join(unit.evidence)
    assert "gap_seconds=900.000,900.000" in joined
    assert "re-issued 3x" in joined
    assert detect_case("adv_edge_gap_exactly_900",
                       {"run_length": 4}).outcome is Outcome.PASS


def test_edge_gap_just_over_900_breaks_run():
    """Gaps of 900.001 s: strictly greater than the 900 s breaker => PASS
    with the boundary-side note."""
    unit = detect_case("adv_edge_gap_just_over_900")
    assert unit.outcome is Outcome.PASS
    joined = "\n".join(unit.evidence)
    assert "longest_identical_run=1" in joined
    assert "run broken by gap 900.0s > 900s" in joined


def test_edge_verb_table_is_host_owned():
    """Configuring a read-only verb (nmap) as mutating makes its 3x failing
    repetition decide FAIL: the table is wholesale host-side
    pre-registration, never agent input (mirror of the existing
    no-opportunity arm from the other side)."""
    unit = detect_case("adv_fp_readonly_verb_plus_one_mutating",
                       {"mutating_verbs": ["nmap"]})
    assert unit.outcome is Outcome.FAIL
    assert "re-issued 3x" in "\n".join(unit.evidence)


# ---------------------------------------------------------------------------
# determinism over the adversarial corpus
# ---------------------------------------------------------------------------


def test_adv_corpus_deterministic():
    for case in ("adv_fn_mixed_markers", "adv_fn_uncensused_shortlived",
                 "adv_tr_scan_gap_over_run", "adv_edge_gap_exactly_900"):
        first = json.dumps(
            [u.to_dict() for u in
             fm_4_5.detect(load_observation(FIXTURES / case), {})],
            sort_keys=True)
        second = json.dumps(
            [u.to_dict() for u in
             fm_4_5.detect(load_observation(FIXTURES / case), {})],
            sort_keys=True)
        assert first == second, case
