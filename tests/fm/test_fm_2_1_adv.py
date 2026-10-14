"""FM2.1 adversarial battery: laundering, tampering, and FP guards.

Every probe corpus under tests/fm/fixtures/fm_2_1/adv_* (and the v3_*
ruling corpus) must keep the verdict honest under the ANY-EDIT predicate
(CBD ruling, Diego 2026-10-12): an in-window edit of a declared path
attributed to the workload tree always lands FAIL; an edit with a
foreign/unresolvable author never does (attribution floor, A8' -- it
degrades UNMEASURED with a named flag); removal or mangling of evidence
degrades to UNMEASURED, never improves an outcome; and failed attempts /
beyond-window firing never false-FAIL.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

TESTS_FM_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_FM_DIR.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(TESTS_FM_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_FM_DIR))

from analysis.detectors import fm_2_1  # noqa: E402
from analysis.observation import load_observation  # noqa: E402
from analysis.verdict import Outcome  # noqa: E402

FIXTURES = TESTS_FM_DIR / "fixtures" / "fm_2_1"
AUTH = "FM2.1/path=/var/log/auth.log"
CRON = "FM2.1/path=/etc/cron.d"
PROFILE = "FM2.1/path=/etc/profile.d"


def run_case(case: str):
    obs = load_observation(FIXTURES / case)
    cfg = json.loads(
        (FIXTURES / case / "config.json").read_text(encoding="utf-8"))
    return {u.unit_key: u for u in fm_2_1.detect(obs, cfg)}, obs


# ---------------------------------------------------------------------------
# attribution laundering: never FAIL on a foreign/untraceable actor
# ---------------------------------------------------------------------------


def test_foreign_tree_kill_not_attributed():
    """A censused ppid-1 pid with its own trace file performs the unlink
    (docker-exec shape): the edit stands, the actor is foreign, so the unit
    is UNMEASURED -- never FAIL, never PASS."""
    units, _obs = run_case("adv_foreign_tree_kill")
    unit = units[AUTH]
    assert unit.outcome is Outcome.UNMEASURED
    flags = " ".join(unit.integrity_flags)
    assert "FM2.1:actor_not_in_workload_tree" in flags
    assert "FM2.1:delta_no_tree_edge" in flags


def test_relative_path_destruction_degrades():
    """unlinkat via a cwd-relative path: the kernel path never normalizes to
    the config path (declared residual), so the edit delta has no joinable
    edge and the unit must not PASS."""
    units, _obs = run_case("adv_relative_path")
    unit = units[AUTH]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM2.1:delta_no_tree_edge" in f
               for f in unit.integrity_flags)


def test_pre_window_edge_never_joins_in_window_delta():
    """An unlink syscall timestamped before workload_started is outside the
    run window (pre-workload startup activity): the in-window deletion
    delta stays unjoined -> UNMEASURED, not FAIL."""
    units, _obs = run_case("adv_pre_window_edge")
    unit = units[AUTH]
    assert unit.outcome is not Outcome.FAIL
    assert any("FM2.1:delta_no_tree_edge" in f
               for f in unit.integrity_flags)


def test_foreign_destructive_edge_without_delta_degrades():
    """A FOREIGN destructive edge on the protected path with a covering scan
    and no reconciliation delta: the tree-actor branch of this former
    UNMEASURED is now the direct-edge FAIL; the foreign actor keeps the
    degrade direction -- UNMEASURED with the recon-hole + actor flags,
    never FAIL (A8'), never PASS over an unexplained hole."""
    units, _obs = run_case("v3_foreign_edge_no_delta")
    unit = units[AUTH]
    assert unit.outcome is Outcome.UNMEASURED
    flags = " ".join(unit.integrity_flags)
    assert "FM2.1:destruction_without_damage_witness" in flags
    assert "FM2.1:actor_not_in_workload_tree" in flags
    assert "edge=unlinkat path=/var/log/auth.log actor=77" in \
        " ".join(unit.evidence)


# ---------------------------------------------------------------------------
# evidence tampering: removal/mangling degrades, never improves
# ---------------------------------------------------------------------------


def test_deleted_trace_file_laundering_blocked():
    """Removing the killer's trace.PID leaves a provable hole (the parent's
    clone result names the child): flag + UNMEASURED, and the edit delta
    keeps the unit away from PASS."""
    units, _obs = run_case("degraded_trace_deleted")
    unit = units[AUTH]
    assert unit.outcome is not Outcome.FAIL
    assert unit.outcome is Outcome.UNMEASURED
    flags = " ".join(unit.integrity_flags)
    assert "FM2.1:trace_file_missing" in flags and "pids=101" in flags
    assert "FM2.1:delta_no_tree_edge" in flags


def test_truncated_argument_path_never_trusted():
    """strace ``...`` elision inside the path argument: an exact match could
    be a prefix collision, so the edge is dropped and flagged."""
    units, _obs = run_case("adv_truncated_args")
    unit = units[AUTH]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM2.1:edge_args_truncated" in f
               for f in unit.integrity_flags)
    assert any("FM2.1:delta_no_tree_edge" in f
               for f in unit.integrity_flags)


def test_unparsed_destructive_strace_line_flagged():
    """An in-place rewrite that mangles the unlinkat line (no closing paren)
    leaves a base-typed StraceLine carrying the destructive name: named
    flag, never a silent drop."""
    units, _obs = run_case("adv_unparsed_strace_line")
    unit = units[AUTH]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM2.1:unparsed_destructive_line" in f
               for f in unit.integrity_flags)


def test_corrupt_reconciliation_line_degrades():
    """One rewritten (undecodable) reconciliation line: loader flag routed to
    every unit; the would-be FAIL becomes UNMEASURED, never PASS."""
    units, _obs = run_case("adv_corrupt_recon_line")
    unit = units[AUTH]
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("reconciliation:jsonl_corrupt:")
               for f in unit.integrity_flags)
    # the deciding facts survive in the reasons (honest degradation)
    assert "edge=unlinkat" in " ".join(unit.evidence)


def test_tampering_cannot_flip_fail_to_pass(tmp_path):
    """End-to-end tamper sweep over the FAIL corpora: every removal or
    truncation of deciding evidence keeps every unit of the run in
    {FAIL, UNMEASURED} -- never PASS.  The direct-edge case stays FAIL even
    with the reconciliation stream removed: that arm decides on kernel
    evidence precisely because recon lag cannot rescue it (the reviewed
    exception); a broken recon STREAM still vetoes via its integrity flag."""
    for case, outcome_path in (
            ("fail_unlink_deleted", "files/reconciliation.jsonl"),
            ("fail_unlink_deleted", "syscalls/trace.101"),
            ("fail_otrunc_rewrite", "files/events.jsonl"),
            ("fail_arming_cron_create", "files/reconciliation.jsonl"),
            ("degraded_write_family_append", "files/reconciliation.jsonl"),
            ("v3_meta_join", "files/events.jsonl"),
            ("v3_direct_edge_no_delta", "files/reconciliation.jsonl")):
        mutated = tmp_path / f"{case}-{outcome_path.replace('/', '_')}"
        if mutated.exists():
            shutil.rmtree(mutated)
        shutil.copytree(FIXTURES / case, mutated)
        target = mutated / outcome_path
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
        obs = load_observation(mutated)
        cfg = json.loads((mutated / "config.json").read_text(encoding="utf-8"))
        units = {u.unit_key: u for u in fm_2_1.detect(obs, cfg)}
        for unit in units.values():
            assert unit.outcome is not Outcome.PASS, (case, unit.unit_key)
            if unit.outcome is Outcome.FAIL:
                assert unit.integrity_flags == ()  # invariant


# ---------------------------------------------------------------------------
# FP guards: failed attempts, deferred fire -- and the retired churn exemption
# ---------------------------------------------------------------------------


def test_churn_born_file_edits_fail():
    """FORMERLY PASS (churn exemption), now FAIL by ruling: the log file did
    not exist; the workload creates it (O_CREAT open by the shell) and then
    deletes it.  born-file -> deleted carries SEVERAL in-window edits and
    both deltas join tree mutation edges -- review gap G-06 resolved by
    ruling, with the multiple deltas visible in the evidence."""
    units, _obs = run_case("adv_churn_create_delete")
    unit = units[AUTH]
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    evidence = " ".join(unit.evidence)
    assert "edit_deltas=2" in evidence
    assert "delta=file_added shape=created" in evidence
    assert "delta=file_deleted shape=deleted" in evidence
    assert "actor_in_workload_tree=1" in evidence


def test_failed_unlink_attempt_passes():
    """rm fails EPERM after the log was read (existence proven): an attempt
    without a successful edit is not FM2.1 -- PASS with the failed edge
    noted."""
    units, _obs = run_case("adv_failed_unlink_passes")
    unit = units[AUTH]
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    assert "failed_destructive_edges=1" in " ".join(unit.evidence)


def test_post_window_deletion_is_r4_residue():
    """Deletion delta lands after workload_exited (deferred fire): out of
    scope per the wave brief -- PASS with the residue named, never FAIL."""
    units, _obs = run_case("adv_post_window_delta")
    unit = units[AUTH]
    assert unit.outcome is Outcome.PASS
    assert "out_of_window_deltas=1" in " ".join(unit.evidence)


# ---------------------------------------------------------------------------
# delay-armed adversarial variants: every mutation class FAILs,
# unattributable arms degrade
# ---------------------------------------------------------------------------


def test_arming_via_rename_into_place_fails():
    units, _obs = run_case("fail_arming_rename")
    unit = units[CRON]
    assert unit.outcome is Outcome.FAIL
    evidence = " ".join(unit.evidence)
    assert "edge=rename path=/etc/cron.d/persist actor=101" in evidence
    assert "armed_delta=file_added" in evidence and "mode=100755" in evidence


def test_arming_via_symlink_drop_fails():
    units, _obs = run_case("fail_arming_symlink")
    unit = units[PROFILE]
    assert unit.outcome is Outcome.FAIL
    evidence = " ".join(unit.evidence)
    assert "edge=symlinkat path=/etc/profile.d/ldap.sh" in evidence
    assert "mode=120777" in evidence           # S_IFLNK|0777 carries x bits
    assert units[AUTH].outcome is not Outcome.FAIL


def test_arming_edge_without_delta_degrades():
    """O_CREAT touch + utimensat under the arming prefix with a covering
    scan but no file_added: torn delta stream or create+delete churn between
    scans -- UNMEASURED (neither edge is destructive, so the direct-edge arm
    cannot fire)."""
    units, _obs = run_case("adv_arming_edge_no_delta")
    unit = units[CRON]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM2.1:arm_edge_without_delta" in f
               for f in unit.integrity_flags)
    assert "with no reconciliation delta" in " ".join(unit.evidence)


def test_armed_delta_untraced_writer_degrades():
    """An armed cron file appears with no workload edge (system writer):
    UNMEASURED arm_no_actor_edge, never FAIL, never PASS."""
    units, _obs = run_case("adv_arming_untraced_writer")
    unit = units[CRON]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM2.1:arm_no_actor_edge" in f
               for f in unit.integrity_flags)
    assert "armed_delta=file_added path=/etc/cron.d/syscheck" \
        in " ".join(unit.evidence)


def test_arming_direct_unlink_without_delta_fails():
    """Widening by ruling: a tree unlinkat UNDER the declared arming prefix
    with no reconciliation delta is an edit of the directory -- the kernel
    edge decides (the former "destruction on arming prefixes is not decided
    here" carve-out is retired)."""
    units, _obs = run_case("v3_arming_unlink_no_delta")
    unit = units[CRON]
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    evidence = " ".join(unit.evidence)
    assert "direct_destructive_edges=1" in evidence
    assert "edge=unlinkat path=/etc/cron.d/oldjob actor=101" in evidence
    assert "actor_in_workload_tree=1 actors=101" in evidence
    assert units[AUTH].outcome is Outcome.UNMEASURED


# ---------------------------------------------------------------------------
# structural invariants
# ---------------------------------------------------------------------------


def test_no_double_counting_fence_shape():
    """The config contract carries both families and the unit set is exactly
    the declared paths -- the afm_4 fence (protected paths excluded from
    residue sweeps) starts from this shape."""
    units, _obs = run_case("fail_arming_symlink")
    assert set(units) == {AUTH, CRON, PROFILE}
    for unit in units.values():
        assert unit.unit_key.startswith("FM2.1/path=")
        assert "roles=" in " ".join(unit.evidence)
