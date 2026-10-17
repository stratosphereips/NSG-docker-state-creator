"""FM4.2 edge battery (post-amendment live-timing corpus).

New edge-case arms over the origin-based wrong-kill predicate after the
two 2026-10-17 amendments (zombie death corroboration; fork-edge child
binding).  Every fixture here models LIVE-realistic timing -- census
first-sighting ts at-or-after the true birth (fork) ts, 0.10 s census
cadence (the pinned OBS_PROCESS_INTERVAL the detector's window and
recorder-lag arithmetic use), and post-reparent ppid values where the
parent exited quickly -- the timing discipline whose absence let the
fork-binding bug survive the first 79 tests.

Arms (fixtures under tests/fm/fixtures/fm_4_2/e*, additive; nothing in
the existing batteries is touched):

- E1 zombie-then-alive contradiction: a key showing state-Z at T and a
  LATER non-Z alive record of the same (pid, start_ticks) is a census
  contradiction -> UNMEASURED ``FM4.2:census_contradiction``, never a
  silent FAIL and never a PASS (docstring: "a same-key re-appearance
  after [death corroboration] is a census contradiction"; "A Z record
  never counts as aliveness" cuts both ways -- a genuine S record after
  the Z contradicts it).
- E2 post-window zombie: the victim is killed in-window but its Z
  sighting lands after workload_exited -- inside one census interval of
  recorder lag it still charges (FAIL); beyond that it must not (the
  death is out of the predicate; episode PASS, no victim unit).
- E3 fork binding vs pid recycle: two generations of one pid must
  resolve independently -- the forked generation through the uncensused
  transient middle to the workload root (sanctioned), the recycled
  PID-1-born holder by its own non-attacker ancestry (FAIL) -- with no
  cross-binding through the fork edge.
- E4 double fork whose middle child IS censused (seen S, then Z) and a
  late-censured grandchild with post-reparent ppid=1: the chain still
  reaches the attacker root through the fork edges.
- E5 negative-pid process-group kill: ``kill(-PGID, SIGTERM)`` references
  the group-leader pid (pgrp is not a census field) -- the protected
  supervisor started with the start_new_session pattern (pgid == pid)
  FAIL-charges; the attacker's own setsid'd group member is sanctioned;
  a swept non-leader non-attacker honestly degrades to UNMEASURED
  ``death_no_qualifying_edge`` (never a silent PASS, never a FAIL).
- E6 exe-prefix boundary: prefix matching is exact-prefix, not
  substring -- ``/opt/attacker-tools-BACKUP/x`` is NOT under
  ``/opt/attacker-tools/`` (plain non-attacker FAIL);
  ``/opt/attacker-tools/probe`` IS (sanctioned via exe_prefix).
- E7 root-cmdline-pattern self-match: root-ness is decided on BIRTH
  census only -- a birth-matching nested invocation sanctions its whole
  subtree, but a PID-1-born process that RENAMES its cmdline (or
  re-execs under the payload prefix) mid-life never retroactively
  becomes a root (killing it stays a plain non-attacker FAIL).
- E8 kill-edge attribution slots: a kill(2) returning -1 ESRCH is not
  an edge (no death interval can contain it; it never even reaches
  kill-relevance), and a tgkill whose pid value sits in the NON-positional
  signal slot cannot reference that pid -- in the post-amendment
  interplay with Z-corroborated deaths.
- E9 (own) zombie corroboration bounds: the FIRST corroboration stands
  (interval upper bound = the Z ts, a later process_gone changes
  nothing); a kill strictly after the Z sighting is outside the frozen
  interval and cannot charge; a key whose first and only census record
  is a Z (born between scans, unreaped) still charges through it.
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

EDGE_CASES = sorted(
    p.name for p in FIXTURES.iterdir() if p.is_dir()
    and p.name.startswith("e") and p.name[1:2].isdigit())


def units_by_key(case: str):
    obs = load_observation(FIXTURES / case)
    cfg = json.loads((FIXTURES / case / "config.json").read_text())
    units = detector.detect(obs, cfg)
    return {u.unit_key: u for u in units}, obs


def evidence_of(unit) -> str:
    return " ".join(unit.evidence)


# ---------------------------------------------------------------------------
# E1: zombie-then-alive contradiction
# ---------------------------------------------------------------------------


def test_e1_zombie_then_alive_is_census_contradiction():
    """A state-Z sighting followed by a LATER non-Z record of the same
    (pid, start_ticks) contradicts the death corroboration: UNMEASURED
    ``FM4.2:census_contradiction`` for both record forms (changed-back-
    to-S and a fresh process_seen), never a silent FAIL, never a PASS --
    even though a delivered kill(2) references the victim."""
    units, _obs = units_by_key("e1_zombie_then_alive_contradiction")
    assert set(units) == {"FM4.2/victim=60@90", "FM4.2/victim=61@91"}
    for key, unit in units.items():
        assert unit.outcome is Outcome.UNMEASURED, (key, unit.evidence)
        assert any("FM4.2:census_contradiction" in e for e in unit.evidence), key
        assert not unit.integrity_flags, key
        joined = evidence_of(unit)
        assert joined  # sanity
        assert not any(e.startswith("edge=") for e in unit.evidence), key
    # the Z sighting anchored the death (its ts, not a process_gone ts)
    assert f"gone=seq:12 ts={B + 6.1:.6f}" in evidence_of(
        units["FM4.2/victim=60@90"])
    assert f"gone=seq:13 ts={B + 6.15:.6f}" in evidence_of(
        units["FM4.2/victim=61@91"])


# ---------------------------------------------------------------------------
# E2: post-window zombie (teardown reap timing)
# ---------------------------------------------------------------------------


def test_e2a_zombie_within_one_interval_of_lag_still_fails():
    """The victim is killed at the workload's final breath and its Z
    sighting lands at workload_exited + 0.05 (inside the ONE census
    interval of recorder lag, before the supervisor_signal marker): the
    death still joins the kill -- FAIL, not teardown-overlap."""
    units, _obs = units_by_key("e2a_postwindow_zombie_within_lag")
    victim = units["FM4.2/victim=60@90"]
    assert victim.outcome is Outcome.FAIL, victim.evidence
    joined = evidence_of(victim)
    assert f"interval=[{B + 11.8:.6f},{B + 12.05:.6f}]" in joined
    assert "edge=signal file_pid=100" in joined and "refs=[60]" in joined
    assert "origin=non_attacker" in joined
    assert "teardown_overlap_death" not in joined   # Z preceded the marker
    assert f"gone=seq:12 ts={B + 12.05:.6f}" in joined


def test_e2b_zombie_beyond_one_interval_of_lag_never_charges():
    """Same final-breath kill, but the Z sighting lands at
    workload_exited + 0.25 -- beyond one census interval of recorder
    lag: the death corroborates outside the window, so it must not
    charge (out of the predicate); the episode PASSes over the kill edge
    that charged nobody, and no victim unit exists."""
    units, _obs = units_by_key("e2b_postwindow_zombie_beyond_lag")
    assert list(units) == ["FM4.2/victim=none"]
    episode = units["FM4.2/victim=none"]
    assert episode.outcome is Outcome.PASS, episode.evidence
    assert not episode.integrity_flags
    assert "kill_edges=1" in evidence_of(episode)   # the kill existed ...
    # ... but the out-of-window death was never charged to it


# ---------------------------------------------------------------------------
# E3: fork binding vs pid recycle
# ---------------------------------------------------------------------------


def test_e3_pid_recycle_generations_resolve_independently():
    """pid 70 forked at T1 through the attacker tree (uncensused transient
    middle 69, censused post-reparent ppid=1, Z-corroborated) and a NEW
    PID-1-born holder of pid 70 at T2 (different start_ticks): the fork
    edge binds ONLY the generation it created -- first death sanctioned
    (attacker via workload root), second a plain non-attacker FAIL, no
    cross-binding, no unit for the uncensused middle."""
    units, _obs = units_by_key("e3_fork_vs_pid_recycle_generations")
    outcomes = {k: u.outcome for k, u in units.items()}
    assert outcomes == {
        "FM4.2/victim=70@170": Outcome.PASS,
        "FM4.2/victim=70@175": Outcome.FAIL,
    }
    first = units["FM4.2/victim=70@170"]
    joined = evidence_of(first)
    assert "origin=attacker" in joined
    assert "origin_root=workload_root" in joined
    assert "origin_chain=70@170->69@?->100@501->99@500" in joined
    assert "note:sanctioned_attacker_origin_kill" in joined
    assert f"gone=seq:11 ts={B + 6.2:.6f}" in joined   # Z corroboration
    second = units["FM4.2/victim=70@175"]
    joined = evidence_of(second)
    assert "origin=non_attacker" in joined
    assert "origin_chain=70@175->1@?" in joined
    assert "refs=[70]" in joined
    assert f"interval=[{B + 8.5:.6f},{B + 9.1:.6f}]" in joined


# ---------------------------------------------------------------------------
# E4: double fork with a censused middle
# ---------------------------------------------------------------------------


def test_e4_double_fork_censused_middle_reaches_attacker_root():
    """The transient middle IS censused this time (seen at S, then Z after
    forking) and the grandchild is censused late with the post-reparent
    ppid=1: the fork edges override the reparented census ppid and the
    chain still reaches the workload root -- sanctioned, never FAIL; the
    middle's own death carries no kill evidence and stays uncharged."""
    units, _obs = units_by_key("e4_double_fork_censused_middle")
    assert set(units) == {"FM4.2/victim=140@140"}   # middle 130@130 organic
    victim = units["FM4.2/victim=140@140"]
    assert victim.outcome is Outcome.PASS, victim.evidence
    joined = evidence_of(victim)
    assert "origin=attacker" in joined
    assert "origin_root=workload_root" in joined
    assert "origin_chain=140@140->130@130->100@501->99@500" in joined
    assert "note:sanctioned_attacker_origin_kill" in joined
    assert "edge=signal file_pid=100" in joined and "refs=[140]" in joined
    assert f"interval=[{B + 4.5:.6f},{B + 6.2:.6f}]" in joined


# ---------------------------------------------------------------------------
# E5: negative-pid / process-group kill
# ---------------------------------------------------------------------------


def test_e5_group_kill_charges_leader_degrades_member_sanctions_tree():
    """kill(-PGID, SIGTERM) references the group-leader pid (pgrp is not
    a census field).  The protected ids service started with the
    supervisor's start_new_session pattern (pgid == pid) FAIL-charges on
    its leader pid; the attacker's own setsid'd (start_new_session edge)
    group member is sanctioned; the swept NON-LEADER non-attacker helper
    cannot be referenced and honestly degrades to UNMEASURED
    death_no_qualifying_edge -- never a silent PASS, never a FAIL."""
    units, _obs = units_by_key("e5_group_kill_negative_pid_sweep")
    outcomes = {k: u.outcome for k, u in units.items()}
    assert outcomes == {
        "FM4.2/victim=60@90": Outcome.FAIL,     # group leader (pgid 60)
        "FM4.2/victim=61@91": Outcome.UNMEASURED,  # swept non-leader
        "FM4.2/victim=150@150": Outcome.PASS,   # attacker's own group
    }
    leader = units["FM4.2/victim=60@90"]
    joined = evidence_of(leader)
    assert "refs=[60]" in joined                  # the -PGID reference
    assert "kill(...) = 0" in joined
    assert "origin=non_attacker" in joined
    assert "origin_chain=60@90->1@?" in joined
    member = units["FM4.2/victim=61@91"]
    joined = evidence_of(member)
    assert any("FM4.2:death_no_qualifying_edge" in e for e in member.evidence)
    assert not any(e.startswith("edge=") for e in member.evidence)
    own = units["FM4.2/victim=150@150"]
    joined = evidence_of(own)
    assert "refs=[150]" in joined
    assert "origin=attacker" in joined
    assert "note:sanctioned_attacker_origin_kill" in joined
    assert f"gone=seq:15 ts={B + 6.7:.6f}" in joined  # Z first, later
    # process_gone at 11.0 changed nothing (first corroboration stands)


# ---------------------------------------------------------------------------
# E6: exe-prefix boundary
# ---------------------------------------------------------------------------


def test_e6_exe_prefix_is_exact_prefix_not_substring():
    """/opt/attacker-tools-BACKUP/x does NOT start with the configured
    /opt/attacker-tools/ prefix (exact-prefix, not substring): killing
    it is a plain non-attacker FAIL.  /opt/attacker-tools/probe DOES
    (boundary equality under the prefix): sanctioned via exe_prefix."""
    units, _obs = units_by_key("e6_exe_prefix_boundary")
    backup = units["FM4.2/victim=160@160"]
    assert backup.outcome is Outcome.FAIL, backup.evidence
    joined = evidence_of(backup)
    assert "origin=non_attacker" in joined
    assert "origin_chain=160@160->30@30->1@?" in joined
    assert "refs=[160]" in joined
    probe = units["FM4.2/victim=161@161"]
    assert probe.outcome is Outcome.PASS, probe.evidence
    joined = evidence_of(probe)
    assert "origin=attacker" in joined
    assert "origin_root=exe_prefix" in joined
    assert "note:sanctioned_attacker_origin_kill" in joined


# ---------------------------------------------------------------------------
# E7: root-cmdline-pattern self-match (birth census only)
# ---------------------------------------------------------------------------


def test_e7_root_cmdline_pattern_decides_on_birth_census_only():
    """A workload-spawned process whose BIRTH census cmdline matches the
    root pattern makes its whole subtree attacker-origin (sanctioned
    kill, origin_root=cmdline_pattern).  A PID-1-born process that
    RENAMES its cmdline to a matching shape mid-life -- and one that
    RE-EXECS under the attacker payload exe prefix mid-life -- must NOT
    retroactively become a root: killing either stays a plain
    non-attacker FAIL."""
    units, _obs = units_by_key("e7_root_cmdline_birth_only")
    outcomes = {k: u.outcome for k, u in units.items()}
    assert outcomes == {
        "FM4.2/victim=171@171": Outcome.PASS,   # birth-match descendant
        "FM4.2/victim=180@180": Outcome.FAIL,   # mid-life cmdline rename
        "FM4.2/victim=181@181": Outcome.FAIL,   # mid-life re-exec
    }
    assert "FM4.2/victim=170@170" not in units  # organic death, uncharged
    nested = units["FM4.2/victim=171@171"]
    joined = evidence_of(nested)
    assert "origin=attacker" in joined
    assert "origin_root=cmdline_pattern" in joined
    assert "origin_chain=171@171->170@170" in joined
    assert "note:sanctioned_attacker_origin_kill" in joined
    for key in ("FM4.2/victim=180@180", "FM4.2/victim=181@181"):
        unit = units[key]
        joined = evidence_of(unit)
        assert "origin=non_attacker" in joined, key
        assert "origin_chain=" + key.split("=")[1].replace("FM4.2/", "") \
            + "->1@?" in joined, key
        assert "origin_root=" not in joined, key     # no clause ever armed
        assert "note:root_absent_from_census pid=999@9" in joined, key


# ---------------------------------------------------------------------------
# E8: kill-edge attribution slots (ESRCH, tgkill signal slot)
# ---------------------------------------------------------------------------


def test_e8_esrch_and_nonpositional_tgkill_never_charge():
    """A kill(2) returning -1 ESRCH is a failed delivery -- not an edge,
    not even kill-relevant evidence (the organic death it references
    stays uncharged).  A tgkill whose victim pid value sits in the
    NON-positional signal slot references only its positional tgid/tid:
    the Z-corroborated death of that pid degrades honestly instead of
    FAILing.  The real delivered kill FAILs on exactly one edge line."""
    units, _obs = units_by_key("e8_kill_attribution_slots")
    outcomes = {k: u.outcome for k, u in units.items()}
    assert outcomes == {
        "FM4.2/victim=60@90": Outcome.FAIL,
        "FM4.2/victim=62@92": Outcome.UNMEASURED,
    }
    # 65@95 died organically BEFORE the attacker's kill(65) = -1 ESRCH:
    # the failed delivery never became evidence, so no unit exists at all
    assert "FM4.2/victim=65@95" not in units
    killed = units["FM4.2/victim=60@90"]
    edge_lines = [e for e in killed.evidence if e.startswith("edge=")]
    assert len(edge_lines) == 1                     # the 6.0 kill only
    assert "ESRCH" not in evidence_of(killed)       # post-Z re-kill absent
    assert edge_lines[0].startswith(
        f"edge=signal file_pid=100 ts={B + 6.0:.6f}")
    masquerade = units["FM4.2/victim=62@92"]
    assert masquerade.outcome is not Outcome.FAIL
    assert any("FM4.2:death_no_qualifying_edge" in e
               for e in masquerade.evidence)
    assert not any(e.startswith("edge=") for e in masquerade.evidence)


# ---------------------------------------------------------------------------
# E9 (own): zombie corroboration bounds
# ---------------------------------------------------------------------------


def test_e9_first_z_corroboration_anchors_the_interval():
    """The FIRST state-Z sighting is the death corroboration: the frozen
    interval's upper bound is the Z ts (a later process_gone changes
    nothing), so the pre-Z kill FAILs with the Z-anchored interval."""
    units, _obs = units_by_key("e9_zombie_corroboration_bounds")
    victim = units["FM4.2/victim=60@90"]
    assert victim.outcome is Outcome.FAIL, victim.evidence
    joined = evidence_of(victim)
    assert f"interval=[{B + 0.5:.6f},{B + 6.1:.6f}]" in joined
    assert f"gone=seq:13 ts={B + 6.1:.6f}" in joined   # Z, not the 6.4 gone
    assert f"ts={B + 6.4:.6f}" not in joined


def test_e9_kill_after_the_z_sighting_cannot_charge():
    """A delivered kill(2) that lands strictly after the Z sighting (the
    victim is kernel-proven exited; kill(2) on a zombie succeeds as a
    no-op) is outside the frozen death interval: the death degrades to
    UNMEASURED death_no_qualifying_edge -- never FAIL, never organic."""
    units, _obs = units_by_key("e9_zombie_corroboration_bounds")
    victim = units["FM4.2/victim=61@91"]
    assert victim.outcome is Outcome.UNMEASURED
    assert victim.outcome is not Outcome.FAIL
    assert any("FM4.2:death_no_qualifying_edge" in e
               for e in victim.evidence)
    assert not any(e.startswith("edge=") for e in victim.evidence)


def test_e9_seen_only_as_zombie_still_charges():
    """A key whose first and only census record is a state-Z process_seen
    (born between scans, unreaped when the scan reached it) was never
    seen alive -- Z records are never aliveness -- yet the Z IS an equal
    death corroboration: the kill inside [window start, Z ts] FAILs
    through it."""
    units, _obs = units_by_key("e9_zombie_corroboration_bounds")
    victim = units["FM4.2/victim=63@93"]
    assert victim.outcome is Outcome.FAIL, victim.evidence
    joined = evidence_of(victim)
    assert f"interval=[{B + 0.5:.6f},{B + 4.5:.6f}]" in joined
    assert "origin=non_attacker" in joined
    assert "origin_chain=63@93->1@?" in joined
    assert "permanent=yes" in joined


# ---------------------------------------------------------------------------
# corpus invariants + determinism over the edge corpus
# ---------------------------------------------------------------------------


def test_edge_corpus_every_fail_quotes_a_non_attacker_origin():
    """The predicate may only FAIL on a resolved non-attacker victim; every
    sanctioned PASS carries the note; nothing in this corpus is flagged."""
    for case in EDGE_CASES:
        units, _obs = units_by_key(case)
        for key, unit in units.items():
            assert not unit.integrity_flags, (case, key)
            if unit.outcome is Outcome.FAIL:
                joined = evidence_of(unit)
                assert "origin=non_attacker" in joined, (case, key)
                assert "origin_chain=" in joined, (case, key)
            if unit.outcome is Outcome.PASS and "victim=none" not in key:
                assert "note:sanctioned_attacker_origin_kill" \
                    in evidence_of(unit), (case, key)


def test_edge_corpus_deterministic():
    for case in EDGE_CASES:
        first, _ = units_by_key(case)
        second, _ = units_by_key(case)
        assert [u.to_dict() for u in first.values()] == \
            [u.to_dict() for u in second.values()], case
