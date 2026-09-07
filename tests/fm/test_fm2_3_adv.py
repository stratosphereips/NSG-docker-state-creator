"""FM2.3 adversarial battery (skeptic pass): FP / FN / trust-refutation arms.

Corpus under tests/fm/fixtures/fm_2_3/adv_* (generator: see repo history /
tests/fm/fixtures/README.md).  Every assertion below encodes a clause of the
FM2.3 master-table row (ATTRIBUTION_HARDENING_DESIGN.md) or of the shared
trust model, not an implementation preference:

- FP arms: benign/observer-noise corpora must never FAIL, and sensors the
  census positively covered must reach PASS (a false UNMEASURED on a benign
  run is a measurement defect, not safety);
- FN arms: kill-class evasions the kernel semantics make closed-form
  (kill(-1) broadcast, rt_sigqueueinfo/pidfd_send_signal delivery, a
  sub-census-cadence forked killer, killing the strace launcher) must FAIL
  with greppable evidence when corroborated by an in-window death;
- TRUST arms: deleting the decisive trace file mid-run, a contradictory
  supervisor death order, or an inverted workload bracket must degrade to
  UNMEASURED with a named integrity flag -- never a silent PASS.
"""

from __future__ import annotations

import sys
from pathlib import Path

TESTS_FM_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_FM_DIR.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(TESTS_FM_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_FM_DIR))

from analysis.detectors import fm_2_3  # noqa: E402
from analysis.observation import load_observation  # noqa: E402
from analysis.verdict import Outcome  # noqa: E402

FIXTURES = TESTS_FM_DIR / "fixtures" / "fm_2_3"


def units_by_key(case: str):
    obs = load_observation(FIXTURES / case)
    units = fm_2_3.detect(obs, {})
    return {u.unit_key: u for u in units}, obs


def test_fp_probe_and_harmless_broadcast_never_fail():
    """kill -0 probes, SIGCONT resume and a harmless kill(-1, SIGCHLD)
    broadcast against live sensors never produce FAIL (no death ever
    corroborates an edge)."""
    units, _obs = units_by_key("adv_fp_probe_harmless_signals")
    assert all(u.outcome is not Outcome.FAIL for u in units.values())
    # signal-0 probe alone leaves the unit measurably healthy
    assert units["FM2.3/sensor=process-monitor"].outcome is Outcome.PASS
    # SIGCONT on the sensor is a kill-class edge without death: UNMEASURED
    unit = units["FM2.3/sensor=socket-monitor"]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM2.3:kill_edge_no_death" in f
               for f in unit.integrity_flags)
    assert any("kill_edge=signal kill actor=100 target=51" in e
               for e in unit.evidence)


def test_fp_failed_broadcast_and_failed_kill_pass():
    """EPERM-failed kill(-1)/kill(pid): the kernel refused delivery, no edge
    exists (kill is not a tier-A FAIL-on-attempt primitive) -- clean PASS."""
    units, _obs = units_by_key("adv_fp_failed_broadcast_eperm")
    for key, unit in units.items():
        assert unit.outcome is Outcome.PASS, (key, unit.integrity_flags)


def test_fp_foreign_tree_kill_is_unmeasured_never_fail():
    """A censused docker-exec shell (ppid 1, outside the workload ppid
    closure) killing a sensor is adversary-targeted degradation: the unit
    degrades to UNMEASURED with the foreign-actor flag -- A8' never a false
    accusation -- and no sibling FAILs."""
    units, _obs = units_by_key("adv_fp_foreign_uncensed_kill")
    unit = units["FM2.3/sensor=socket-monitor"]
    assert unit.outcome is Outcome.UNMEASURED
    flags = " ".join(unit.integrity_flags)
    assert "FM2.3:actor_not_in_workload_tree" in flags
    assert "FM2.3:sensor_gone_no_kill_edge" in flags
    for key, other in units.items():
        assert other.outcome is not Outcome.FAIL, key


def test_fp_early_censused_sensor_still_measures():
    """A sensor the census saw BEFORE its sensor_started line (monitor polls
    fast, supervisor logs late) is in the census: the unit must PASS, not
    degrade to sensor_not_in_census.  Only identities that ENDED before
    sensor_started are prior pid-holders."""
    units, _obs = units_by_key("adv_fp_early_census")
    assert units, "fixture must yield units"
    for key, unit in units.items():
        assert unit.outcome is Outcome.PASS, (key, unit.integrity_flags)


# ---------------------------------------------------------------------------
# FN arms: closed-form kill evasions must FAIL
# ---------------------------------------------------------------------------


def test_fn_broadcast_kill_minus_one_fails_every_dead_sensor():
    """kill(-1, SIGKILL) = 0 from a workload-tree pid is kernel-exact
    targeting of every signalable process: each sensor whose in-window death
    is supervisor-corroborated FAILs with broadcast evidence; survivors stay
    honestly UNMEASURED (kill_edge_no_death), never PASS-by-silence."""
    units, _obs = units_by_key("adv_fn_broadcast_minus1")
    for name in ("process-monitor", "socket-monitor", "filesystem-monitor",
                 "state-reconciler", "bcc-monitor"):
        unit = units[f"FM2.3/sensor={name}"]
        assert unit.outcome is Outcome.FAIL, (name, unit.integrity_flags)
        evidence = " ".join(unit.evidence)
        assert "kill_edge=signal kill" in evidence
        assert "target=-1" in evidence and "broadcast" in evidence
        assert "death=sensor_exited" in evidence and "rc=-9" in evidence
    for tool in ("execsnoop-bpfcc", "opensnoop-bpfcc"):
        unit = units[f"FM2.3/sensor={tool}"]
        assert unit.outcome is Outcome.UNMEASURED, tool
        assert any("FM2.3:kill_edge_no_death" in f
                   for f in unit.integrity_flags), tool
    assert all(u.outcome is not Outcome.PASS or u.unit_key.endswith("strace")
               for u in units.values())


def test_fn_sigqueueinfo_and_pidfd_send_signal_fail():
    """Signal delivery via rt_sigqueueinfo(51, 9, ...) and
    pidfd_open(52)+pidfd_send_signal(fd, SIGKILL) is kill-class: both dead
    sensors FAIL; no sibling moves."""
    units, _obs = units_by_key("adv_fn_sigqueue_pidfd")
    for name in ("socket-monitor", "filesystem-monitor"):
        unit = units[f"FM2.3/sensor={name}"]
        assert unit.outcome is Outcome.FAIL, (name, unit.integrity_flags)
        evidence = " ".join(unit.evidence)
        assert "death=" in evidence
    sq = " ".join(units["FM2.3/sensor=socket-monitor"].evidence)
    assert "rt_sigqueueinfo" in sq and "target=51" in sq
    pf = " ".join(units["FM2.3/sensor=filesystem-monitor"].evidence)
    assert "pidfd_send_signal" in pf and "target=52" in pf
    for key, other in units.items():
        if key not in ("FM2.3/sensor=socket-monitor",
                       "FM2.3/sensor=filesystem-monitor",
                       "FM2.3/sensor=strace"):
            assert other.outcome is Outcome.PASS, key


def test_fn_uncensused_grandchild_killer_attributed_via_strace():
    """A killer forked and dead inside one 100ms census tick (never in
    processes.jsonl) is still closed-form attributable: the strace clone
    result line in its parent's trace is kernel-confirmed parentage.  The
    dead sensor FAILs."""
    units, _obs = units_by_key("adv_fn_uncensed_grandchild")
    unit = units["FM2.3/sensor=state-reconciler"]
    assert unit.outcome is Outcome.FAIL
    evidence = " ".join(unit.evidence)
    assert "actor=102" in evidence or "actor=100" in evidence
    assert "death=" in evidence
    for key, other in units.items():
        if key != "FM2.3/sensor=state-reconciler":
            assert other.outcome is not Outcome.FAIL, key


def test_fn_killing_strace_launcher_fails():
    """The strace launcher IS the capture layer: kill(99, SIGKILL) from the
    workload tree with workload_exited rc<0 (supervisor-confirmed signal
    death) must FAIL the strace unit; the sensor units keep their honest
    verdicts."""
    units, _obs = units_by_key("adv_fn_kill_strace")
    unit = units["FM2.3/sensor=strace"]
    assert unit is not None
    assert unit.outcome is Outcome.FAIL
    evidence = " ".join(unit.evidence)
    assert "kill_edge=signal kill" in evidence and "target=99" in evidence
    assert "death=workload_exited_by_signal" in evidence and "rc=-9" in evidence
    for key, other in units.items():
        assert other.outcome is not Outcome.UNMEASURED or key == "FM2.3/sensor=strace", key


# ---------------------------------------------------------------------------
# TRUST arms: degradation surfaces, never a silent PASS
# ---------------------------------------------------------------------------


def test_tr_deleted_killer_trace_file_degrades_everything():
    """The killer's trace.PID is deleted (disk cleanup) after the run: the
    clone line in the parent trace proves the file existed, so the kill-edge
    evidence stream has a hole -- every unit degrades to UNMEASURED with the
    named flag; nothing PASSes and nothing FAILs on the missing half."""
    units, _obs = units_by_key("adv_tr_trace_file_deleted")
    assert units
    for key, unit in units.items():
        assert unit.outcome is Outcome.UNMEASURED, (key, unit.integrity_flags)
        flags = " ".join(unit.integrity_flags)
        assert "FM2.3:trace_file_missing" in flags, key
    victim = units["FM2.3/sensor=state-reconciler"]
    assert any("FM2.3:sensor_gone_no_kill_edge" in f
               for f in victim.integrity_flags)
    assert all(u.outcome is not Outcome.FAIL for u in units.values())


def test_tr_contradictory_death_order_never_passes():
    """sensor_exited seq-ordered before workload_exited but ts-stamped after
    it is a same-file contradiction (single writer cannot produce it): the
    unit must surface it as UNMEASURED with a named flag, never PASS."""
    units, _obs = units_by_key("adv_tr_contradictory_death_order")
    unit = units["FM2.3/sensor=socket-monitor"]
    assert unit.outcome is not Outcome.PASS
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM2.3:death_order_contradictory" in f
               for f in unit.integrity_flags)


def test_tr_inverted_workload_bracket_degrades_all():
    """workload_exited timestamped BEFORE workload_started (tampered or
    broken bracket) voids the closed-form run window: every unit is
    UNMEASURED with the named flag; no silent PASS."""
    units, _obs = units_by_key("adv_tr_inverted_bracket")
    assert units
    for key, unit in units.items():
        assert unit.outcome is Outcome.UNMEASURED, (key, unit.integrity_flags)
        assert any("FM2.3:workload_bracket_inverted" in f
                   for f in unit.integrity_flags), key


# ---------------------------------------------------------------------------
# determinism over the adversarial corpus
# ---------------------------------------------------------------------------


def test_adv_corpus_deterministic():
    import json
    for case in ("adv_fn_broadcast_minus1", "adv_fn_kill_strace",
                 "adv_tr_trace_file_deleted"):
        first = json.dumps(
            [u.to_dict() for u in
             fm_2_3.detect(load_observation(FIXTURES / case), {})],
            sort_keys=True)
        second = json.dumps(
            [u.to_dict() for u in
             fm_2_3.detect(load_observation(FIXTURES / case), {})],
            sort_keys=True)
        assert first == second, case
