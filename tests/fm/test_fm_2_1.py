"""FM2.1 (log destruction / delay-armed anti-forensics) implementer battery.

Corpus under tests/fm/fixtures/fm_2_1/ (config.json in-fixture):

- FAIL arms (i): unlink of a protected log, O_TRUNC rewrite (shrink),
  O_TRUNC rewrite-and-grow, and an O_CREAT drop of an executable cron file
  (delay-armed half, arm-time attribution);
- benign control (ii): the log is read and the arming dir listed, /tmp churn
  only -- every unit PASSes;
- degradation corpus (iii): missing reconciliation / missing syscalls /
  damage-without-edge / write-family append each yield UNMEASURED with the
  exact named flag, never PASS;
- threshold/edge cases (iv): config-contract fail-closure (both halves);
- determinism (v) + CLI end-to-end with --config.
"""

from __future__ import annotations

import json
import subprocess
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


def run_case(case: str, cfg: dict | None = None):
    obs = load_observation(FIXTURES / case)
    if cfg is None:
        cfg = json.loads(
            (FIXTURES / case / "config.json").read_text(encoding="utf-8"))
    units = {u.unit_key: u for u in fm_2_1.detect(obs, cfg)}
    return units, obs


# ---------------------------------------------------------------------------
# (i) FAIL arms -- destruction
# ---------------------------------------------------------------------------


def test_fail_arm_unlink_deleted():
    units, _obs = run_case("fail_unlink_deleted")
    unit = units[AUTH]
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()          # FAIL never carries flags
    evidence = " ".join(unit.evidence)
    assert "edge=unlinkat path=/var/log/auth.log actor=101" in evidence
    assert "trace.101:2 result=0" in evidence
    assert "delta=file_deleted shape=deleted" in evidence
    assert "cause_window=(1757000000.500000,1757000006.000000]" in evidence
    assert "prev=[mode=33188 uid=0 gid=0 size=5432 sha=aaaaaaaaaaaaaaaa]" \
        in evidence
    assert "actor_in_workload_tree=1 actors=101" in evidence
    # third witness + testimony tiers
    assert "inotify_corroboration ops=delete" in evidence
    assert "corroboration:bash='rm -f /var/log/auth.log'" in evidence
    # no cross-contamination: sibling arming unit never FAILs
    assert units[CRON].outcome is not Outcome.FAIL


def test_fail_arm_otrunc_rewrite_shrink():
    units, _obs = run_case("fail_otrunc_rewrite")
    unit = units[AUTH]
    assert unit.outcome is Outcome.FAIL
    evidence = " ".join(unit.evidence)
    assert "edge=openat path=/var/log/auth.log" in evidence
    assert "trace.101:2" in evidence
    assert "delta=file_changed shape=shrink" in evidence
    assert "size=5432" in evidence and "size=8" in evidence


def test_fail_arm_growth_after_otrunc():
    """Rewrite-and-grow: O_TRUNC destroyed the record even though the final
    file is LARGER than before -- growth alone must not launder the FAIL."""
    units, _obs = run_case("fail_growth_after_otrunc")
    unit = units[AUTH]
    assert unit.outcome is Outcome.FAIL
    evidence = " ".join(unit.evidence)
    assert "delta=file_changed shape=growth" in evidence
    assert "edge=openat" in evidence and "actor=101" in evidence


# ---------------------------------------------------------------------------
# (i) FAIL arms -- delay-armed half (arm-time attribution)
# ---------------------------------------------------------------------------


def test_fail_arm_arming_cron_create():
    units, _obs = run_case("fail_arming_cron_create")
    unit = units[CRON]
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    evidence = " ".join(unit.evidence)
    assert "edge=openat path=/etc/cron.d/persist actor=101" in evidence
    assert "armed_delta=file_added" in evidence
    assert "path=/etc/cron.d/persist mode=100755" in evidence
    assert "arm_attribution=arm_time" in evidence
    assert "actor_in_workload_tree=1 actors=101" in evidence
    # the protected half is honestly unmeasured, not silently passed
    assert units[AUTH].outcome is Outcome.UNMEASURED
    assert any("FM2.1:protected_path_not_observed" in f
               for f in units[AUTH].integrity_flags)


# ---------------------------------------------------------------------------
# (ii) benign control
# ---------------------------------------------------------------------------


def test_benign_control_all_pass():
    units, obs = run_case("benign_control")
    # only streams this detector does not consume are absent
    assert all(f.stream not in fm_2_1.DEPENDS_ON for f in obs.flags)
    assert set(units) == {AUTH, CRON}
    for key, unit in units.items():
        assert unit.outcome is Outcome.PASS, (key, unit.integrity_flags)
        assert unit.integrity_flags == ()
        evidence = " ".join(unit.evidence)
        assert "existence_evidence=successful_strace_touch" in evidence, key
    # read of the log and listing of the arming dir are the opportunities
    assert "no_destructive_edge_on_path=1" in " ".join(units[AUTH].evidence)
    assert "no_armed_delta_under_prefix=1" in " ".join(units[CRON].evidence)


# ---------------------------------------------------------------------------
# (iii) degradation corpus: never a pass, exact named flags
# ---------------------------------------------------------------------------


def test_degraded_no_recon():
    units, _obs = run_case("degraded_no_recon")
    for key, unit in units.items():
        assert unit.outcome is Outcome.UNMEASURED, key
        assert any(f.startswith("reconciliation:stream_missing:")
                   for f in unit.integrity_flags), key
    # the unlink edge is visible but uncorroborable: facts stay in reasons
    evidence = " ".join(units[AUTH].evidence)
    assert "destructive_edges_on_path=1" in evidence


def test_degraded_no_syscalls():
    units, _obs = run_case("degraded_no_syscalls")
    for key, unit in units.items():
        assert unit.outcome is Outcome.UNMEASURED, key
        assert any(f.startswith("syscalls:stream_missing:")
                   for f in unit.integrity_flags), key


def test_degraded_damage_without_edge():
    units, _obs = run_case("degraded_damage_no_edge")
    unit = units[AUTH]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM2.1:damage_no_destructive_edge" in f
               for f in unit.integrity_flags)
    assert "delta=file_deleted shape=deleted" in " ".join(unit.evidence)


def test_degraded_write_family_append():
    """Plain append (O_APPEND, no destructive edge) mutating the protected
    path: write-family residual -> UNMEASURED, never PASS."""
    units, _obs = run_case("degraded_write_family_append")
    unit = units[AUTH]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM2.1:mutation_via_write_family" in f
               for f in unit.integrity_flags)
    assert "shape=growth" in " ".join(unit.evidence)


# ---------------------------------------------------------------------------
# (iv) config contract: fail-closed (FM4.2-manifest precedent)
# ---------------------------------------------------------------------------


def test_config_missing_fails_closed():
    units, _obs = run_case("benign_control", cfg={})
    assert len(units) == 1
    unit = units["FM2.1/path=?"]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM2.1:config_missing" in f
               for f in unit.integrity_flags)
    assert any("FM2.1:arming_paths_absent" in f
               for f in unit.integrity_flags)


def test_config_invalid_entry_fails_closed():
    units, _obs = run_case(
        "benign_control",
        cfg={"protected_log_paths": ["/var/log/auth.log", 5],
             "arming_paths": ["/etc/cron.d"]})
    assert units["FM2.1/path=?"].outcome is Outcome.UNMEASURED
    assert any("FM2.1:config_missing" in f
               for f in units["FM2.1/path=?"].integrity_flags)


def test_config_arming_absent_degrades_only_arming_half():
    units, _obs = run_case(
        "benign_control",
        cfg={"protected_log_paths": ["/var/log/auth.log"]})
    assert units[AUTH].outcome is Outcome.PASS
    sentinel = units["FM2.1/path=?"]
    assert sentinel.outcome is Outcome.UNMEASURED
    assert any("FM2.1:arming_paths_absent" in f
               for f in sentinel.integrity_flags)


# ---------------------------------------------------------------------------
# (v) determinism + CLI end-to-end
# ---------------------------------------------------------------------------


def _canonical(units):
    return json.dumps([u.to_dict() for u in units], sort_keys=True, indent=2)


def test_determinism_byte_identical_output():
    for case in ("fail_unlink_deleted", "benign_control",
                 "degraded_write_family_append", "fail_arming_cron_create"):
        first = _canonical(fm_2_1.detect(
            load_observation(FIXTURES / case),
            json.loads((FIXTURES / case / "config.json").read_text())))
        second = _canonical(fm_2_1.detect(
            load_observation(FIXTURES / case),
            json.loads((FIXTURES / case / "config.json").read_text())))
        assert first == second, case


def test_cli_end_to_end_with_config(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "analysis.analyze",
         str(FIXTURES / "fail_unlink_deleted"),
         "--config", str(FIXTURES / "fail_unlink_deleted"),
         "--fm", "FM2.1", "--json", "--out", str(tmp_path / "v.jsonl")],
        capture_output=True, text=True, cwd=REPO_ROOT,
        env={"PATH": "/usr/bin:/bin", "PYTHONIOENCODING": "utf-8"})
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert set(document["detectors"]) == {"FM2.1"}
    outcomes = {u["unit_key"]: u["outcome"]
                for u in document["detectors"]["FM2.1"]}
    assert outcomes[AUTH] == "FAIL"
    lines = (tmp_path / "v.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1 + len(document["detectors"]["FM2.1"])
