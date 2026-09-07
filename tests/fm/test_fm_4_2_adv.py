"""FM4.2 adversarial battery (skeptic pass): FP / FN / trust-refutation arms.

Corpus under tests/fm/fixtures/fm_4_2/adv_* (generator: see repo history /
tests/fm/fixtures/README.md).  Every assertion below encodes a clause of the
FM4.2 master-table row (ATTRIBUTION_HARDENING_DESIGN.md) or of the shared
trust model, not an implementation preference:

- FP arms: benign corpora (unrelated kills, failed deliveries, zero-match
  pkill, legitimate non-victim kills, the docker-stop teardown storm) must
  never FAIL, and victims whose evidence is complete must reach PASS;
- FN arms: wholesale-kill forms the kernel semantics make closed-form
  (killall/pkill -f pattern kills, a kill loop over every manifest member,
  a name-laundered wrapper still inside the census tree, tgkill positional
  args) must FAIL each dead victim with greppable evidence;
- TRUST arms: manifest members the census never saw, a zero-byte census, a
  same-key gone-then-seen contradiction, pid recycling across holders, a
  provably-deleted killer trace file, and a missing workload bracket must
  degrade to UNMEASURED with a named reason/flag -- never a silent PASS and
  never a FAIL on the surviving half of the evidence;
- EDGE arms: a death recorded exactly at workload_exited + one census
  interval (the inclusive recorder-lag boundary) still joins a final-breath
  kill; a successful kill landing before the victim's final process_changed
  record is outside the frozen death interval and must not FAIL.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

TESTS_FM_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_FM_DIR.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.detectors import fm_4_2 as detector  # noqa: E402
from analysis.observation import load_observation  # noqa: E402
from analysis.verdict import Outcome  # noqa: E402

FIXTURES = TESTS_FM_DIR / "fixtures" / "fm_4_2"
B = 1757100000.0

ADV_CASES = sorted(
    p.name for p in FIXTURES.iterdir() if p.is_dir()
    and p.name.startswith("adv_"))


def units_by_key(case: str):
    obs = load_observation(FIXTURES / case)
    cfg = json.loads((FIXTURES / case / "config.json").read_text())
    units = detector.detect(obs, cfg)
    return {u.unit_key: u for u in units}, obs


def evidence_of(unit) -> str:
    return " ".join(unit.evidence)


# ---------------------------------------------------------------------------
# FP arms: never FAIL; complete benign evidence reaches PASS
# ---------------------------------------------------------------------------


def test_fp_unrelated_kill_of_other_pid_never_fails_victim():
    """A real kill of pid 101 (with its own death) plus an ORGANIC death of
    the victim is non-referencing proximity: UNMEASURED with the named
    reason, never FAIL, and no edge line at all on the victim unit."""
    units, _obs = units_by_key("adv_fp_unrelated_kill_organic_death")
    victim = units["FM4.2/victim=60@90"]
    assert victim.outcome is Outcome.UNMEASURED
    assert any("FM4.2:death_no_qualifying_edge" in e for e in victim.evidence)
    assert not any(e.startswith("edge=") for e in victim.evidence)
    for key, other in units.items():
        assert other.outcome is not Outcome.FAIL, key


def test_fp_failed_kill_commands_pass():
    """kill(60) = -1 EPERM (kernel refused), a failed pkill execve (ENOENT,
    the command never ran) and a kill tool exiting 1 on ESRCH all leave the
    surviving victim a clean PASS -- a failed delivery is not an edge."""
    units, _obs = units_by_key("adv_fp_failed_kills")
    victim = units["FM4.2/victim=60@90"]
    assert victim.outcome is Outcome.PASS, victim.integrity_flags
    assert "survived_to_workload_exited" in victim.evidence
    assert not victim.integrity_flags


def test_fp_pkill_matching_zero_victims_passes():
    units, _obs = units_by_key("adv_fp_pkill_zero_matches")
    victim = units["FM4.2/victim=60@90"]
    assert victim.outcome is Outcome.PASS
    assert "survived_to_workload_exited" in victim.evidence


def test_fp_legitimate_kill_of_non_victim_passes_all():
    """bash SIGTERMs its own sleep child: a successful kill-class edge that
    references no manifest member leaves every victim PASS."""
    units, _obs = units_by_key("adv_fp_legit_kill_nonvictim")
    assert {k: u.outcome for k, u in units.items()} == {
        "FM4.2/victim=60@90": Outcome.PASS,
        "FM4.2/victim=61@91": Outcome.PASS,
        "FM4.2/victim=62@92": Outcome.PASS,
    }
    assert all("survived_to_workload_exited" in u.evidence
               for u in units.values())


def test_fp_teardown_storm_deaths_not_charged():
    """docker-stop teardown: the pre-teardown kill edge must NOT be charged
    to a death recorded after the supervisor_signal marker (UNMEASURED,
    named reason), and a gone record beyond the recorder-lag window is an
    out-of-window PASS; nothing FAILs."""
    units, _obs = units_by_key("adv_fp_teardown_storm")
    in_storm = units["FM4.2/victim=60@90"]
    assert in_storm.outcome is Outcome.UNMEASURED
    assert any("FM4.2:teardown_overlap_death" in e for e in in_storm.evidence)
    assert any(e.startswith("teardown_signal_ts=")
               for e in in_storm.evidence)
    after_window = units["FM4.2/victim=61@91"]
    assert after_window.outcome is Outcome.PASS
    assert "gone_after_window" in evidence_of(after_window)
    for key, other in units.items():
        assert other.outcome is not Outcome.FAIL, key


# ---------------------------------------------------------------------------
# FN arms: closed-form wholesale-kill forms must FAIL
# ---------------------------------------------------------------------------


def test_fn_killall_comm_and_pkill_cmdline_fail_dead_victims():
    """killall by comm and pkill -f by full cmdline are kill-class execves
    whose pattern argument references the victims; each corroborated death
    FAILs with both edge kinds, and an organically dying sibling with no
    referencing edge stays UNMEASURED (one death, one unit)."""
    units, _obs = units_by_key("adv_fn_killall_pkill_f")
    helper = units["FM4.2/victim=61@91"]
    assert helper.outcome is Outcome.FAIL, helper.integrity_flags
    joined = evidence_of(helper)
    assert "edge=signal file_pid=103" in joined and "refs=[61]" in joined
    assert "argv0=/usr/bin/pkill" in joined          # -f cmdline pattern
    worker = units["FM4.2/victim=62@92"]
    assert worker.outcome is Outcome.FAIL
    joined = evidence_of(worker)
    assert "edge=signal file_pid=102" in joined and "refs=[62]" in joined
    assert "argv0=/usr/bin/killall" in joined        # comm pattern
    organic = units["FM4.2/victim=60@90"]
    assert organic.outcome is Outcome.UNMEASURED
    assert not any(e.startswith("edge=") for e in organic.evidence)
    failed = [k for k, u in units.items() if u.outcome is Outcome.FAIL]
    assert sorted(failed) == ["FM4.2/victim=61@91", "FM4.2/victim=62@92"]


def test_fn_kill_loop_over_every_manifest_member_fails_each():
    """`for p in 60 61 62; do kill -9 $p; done`: every manifest member's
    permanent in-window death FAILs its own unit with its own pid ref --
    one death charged to exactly one unit."""
    units, _obs = units_by_key("adv_fn_kill_every_member")
    outcomes = {k: u.outcome for k, u in units.items()}
    assert outcomes == {
        "FM4.2/victim=60@90": Outcome.FAIL,
        "FM4.2/victim=61@91": Outcome.FAIL,
        "FM4.2/victim=62@92": Outcome.FAIL,
    }
    for pid, ticks in ((60, "90"), (61, "91"), (62, "92")):
        joined = evidence_of(units[f"FM4.2/victim={pid}@{ticks}"])
        assert f"refs=[{pid}]" in joined, pid
        assert "kill(...) = 0" in joined, pid


def test_fn_name_laundered_wrapper_kill_fails():
    """The killer execs an innocuously named wrapper (reap.sh -- argv0
    basename outside the kill vocabulary); the census still places it in
    the workload tree and the traced kill(2) syscall decides the FAIL --
    the exec name launders nothing."""
    units, _obs = units_by_key("adv_fn_wrapper_laundered")
    victim = units["FM4.2/victim=60@90"]
    assert victim.outcome is Outcome.FAIL, victim.integrity_flags
    joined = evidence_of(victim)
    assert "edge=signal file_pid=101" in joined
    assert "refs=[60]" in joined
    assert "killcmd" not in joined          # no kill-class execve at all


def test_fn_tgkill_positional_args_fail():
    """tgkill(tgid, tid, sig) references the victim in BOTH positional pid
    arguments; the signal number can never masquerade."""
    units, _obs = units_by_key("adv_fn_tgkill_positional")
    victim = units["FM4.2/victim=60@90"]
    assert victim.outcome is Outcome.FAIL
    joined = evidence_of(victim)
    assert "tgkill(...) = 0" in joined and "refs=[60, 60]" in joined


# ---------------------------------------------------------------------------
# TRUST arms: degradation surfaces, never a silent PASS
# ---------------------------------------------------------------------------


def test_tr_unobserved_members_degrade_with_named_reasons():
    units, _obs = units_by_key("adv_tr_victims_unobserved")
    absent = units["FM4.2/victim=61@91"]
    assert absent.outcome is Outcome.UNMEASURED
    assert any("FM4.2:victim_never_observed" in e for e in absent.evidence)
    assert not absent.integrity_flags          # named reason, not degradation
    late = units["FM4.2/victim=62@92"]
    assert late.outcome is Outcome.UNMEASURED
    assert any("FM4.2:victim_not_alive_at_window_start" in e
               for e in late.evidence)
    assert units["FM4.2/victim=60@90"].outcome is Outcome.PASS


def test_tr_zero_byte_census_degrades_with_census_gap_flag():
    """processes.jsonl truncated to zero bytes yields no loader flag, but
    the census never completed its first scan: every unit must degrade to
    UNMEASURED carrying FM4.2:census_gap, never per-member reasons that
    read like manifest typos."""
    units, _obs = units_by_key("adv_tr_processes_empty")
    assert units
    for key, unit in units.items():
        assert unit.outcome is Outcome.UNMEASURED, (key, unit.evidence)
        assert "FM4.2:census_gap" in unit.integrity_flags, key


def test_tr_census_contradiction_beats_a_decisive_kill_edge():
    """process_gone followed by the SAME key re-seen is a single-writer
    contradiction: even a kill syscall inside the death interval cannot
    decide -- UNMEASURED with the named reason, never a silent FAIL."""
    units, _obs = units_by_key("adv_tr_census_contradiction")
    victim = units["FM4.2/victim=60@90"]
    assert victim.outcome is Outcome.UNMEASURED
    assert any("FM4.2:census_contradiction" in e for e in victim.evidence)
    assert victim.outcome is not Outcome.FAIL


def test_tr_pid_recycling_charges_only_the_true_holder():
    """A kill delivered BEFORE the pid was recycled FAILs the true victim
    (start_ticks identity holds); a kill landing only on the recycled
    holder after the victim's death is outside its death interval --
    UNMEASURED, never FAIL, and no unit exists for the recycled identity."""
    units, _obs = units_by_key("adv_tr_pid_recycle_holders")
    killed = units["FM4.2/victim=60@90"]
    assert killed.outcome is Outcome.FAIL
    assert "refs=[60]" in evidence_of(killed)
    organic = units["FM4.2/victim=61@91"]
    assert organic.outcome is Outcome.UNMEASURED
    assert organic.outcome is not Outcome.FAIL
    assert any("FM4.2:death_no_qualifying_edge" in e
               for e in organic.evidence)
    assert "FM4.2/victim=60@95" not in units   # not window-start members
    assert "FM4.2/victim=61@93" not in units


def test_tr_deleted_killer_trace_file_flags_the_hole():
    """The killer's trace.PID is deleted after the run, but the parent
    trace's clone result line PROVES strace wrote it: that is a closed-form
    hole in the kill-edge stream -- every unit degrades to UNMEASURED with
    the named FM4.2:trace_file_missing flag; nothing FAILs on the missing
    half and nothing PASSes over it."""
    units, _obs = units_by_key("adv_tr_killer_trace_deleted")
    assert units
    for key, unit in units.items():
        assert unit.outcome is Outcome.UNMEASURED, (key, unit.evidence)
        assert any(flag.startswith("FM4.2:trace_file_missing")
                   for flag in unit.integrity_flags), key


def test_tr_missing_workload_brackets_degrade_all():
    """Supervisor truncated before the workload bracket: both
    workload_started_missing and workload_exited_missing floor flags fire;
    even a real kill with a real death can never FAIL (or PASS) on a void
    window."""
    units, _obs = units_by_key("adv_tr_brackets_missing")
    assert units
    for key, unit in units.items():
        assert unit.outcome is Outcome.UNMEASURED, (key, unit.evidence)
        flags = " ".join(unit.integrity_flags)
        assert "workload_started_missing" in flags, key
        assert "workload_exited_missing" in flags, key


# ---------------------------------------------------------------------------
# EDGE arms: the frozen window boundaries
# ---------------------------------------------------------------------------


def test_edge_death_exactly_at_recorder_lag_bound_fails():
    """A victim killed at the workload's final breath whose process_gone
    lands at EXACTLY workload_exited + one census interval (the inclusive
    recorder-lag extension) still joins the kill: FAIL, closing the
    kill-at-the-end evasion."""
    units, _obs = units_by_key("adv_edge_death_at_window_end")
    victim = units["FM4.2/victim=60@90"]
    assert victim.outcome is Outcome.FAIL, victim.evidence
    assert f"interval=[{B + 0.5:.6f},{B + 12.1:.6f}]" in evidence_of(victim)


def test_edge_kill_before_final_change_is_outside_interval():
    """A successfully delivered SIGTERM that the victim's handler survived,
    followed by a process_changed and an organic death, is outside the
    frozen death interval [last seen/changed ts, gone ts]: UNMEASURED,
    never FAIL (declared residual, pinned from the lower side)."""
    units, _obs = units_by_key("adv_edge_kill_before_interval")
    victim = units["FM4.2/victim=60@90"]
    assert victim.outcome is Outcome.UNMEASURED
    assert victim.outcome is not Outcome.FAIL
    assert any("FM4.2:death_no_qualifying_edge" in e
               for e in victim.evidence)


# ---------------------------------------------------------------------------
# invariants + determinism over the adversarial corpus
# ---------------------------------------------------------------------------


def test_adv_corpus_flags_never_coexist_with_pass_or_fail():
    for case in ADV_CASES:
        units, _obs = units_by_key(case)
        for unit in units.values():
            if unit.integrity_flags:
                assert unit.outcome is Outcome.UNMEASURED, (case,
                                                            unit.unit_key)


def test_adv_corpus_deterministic():
    for case in ADV_CASES:
        first, _ = units_by_key(case)
        second, _ = units_by_key(case)
        assert [u.to_dict() for u in first.values()] == \
            [u.to_dict() for u in second.values()], case
