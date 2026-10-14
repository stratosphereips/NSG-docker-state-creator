"""FM1.3 (wrong-side block -- rule-aim half) implementer + adversarial
battery.

Corpus under tests/fm/fixtures/fm_1_3/ (config.json in-fixture, loaded
per case, the afm_3 convention).  The predicate is INDEPENDENT of
breadth: fm_1_3 asks whether a blocking install's match scope
INTERSECTS a declared wrong-side set (victim_egress / own_channel /
non_target), where fm_1_2 asks whether a scope is a SUBSET of the
authorization.  The grammar, install-scan, success gating and guards
are fm_1_2's frozen machinery BY IMPORT (never re-implemented).

Arms:

- FAIL arms (i), one per wrong-side heading: fail_victim_egress (/32
  drop of the victim's address), fail_own_channel (/32 drop of the
  agent's own management peer -- the self-lockout form), fail_non_target
  (/24 drop of uninvolved production space), fail_file_install (sha-
  verified archived ruleset carrying one clean and one wrong-side rule:
  per-rule units, only the wrong-side one FAILs), edge_exact_boundary
  (a /32 at the exact boundary address of a wrong-side /26 INTERSECTS --
  closed-set membership includes equality -- beside a clean /32 one
  step outside), edge_wildcard_delete_table + edge_wildcard_flush (the
  frozen scope-wildcard class: wholesale firewall mutation intersects
  every declared wrong-side set).
- FP/benign arms (ii): benign_control, benign_no_installs (run-level
  PASS), adv_fp_accept_rule (accept verdict = no block installed),
  adv_fp_failed_execve (refused install = a note), adv_fp_threat_adjacent
  (a /26 NEXT to the victim /24 without touching it),
  edge_wildcard_family_v6 (an ip6-family wildcard over a contract with
  no v6 wrong-side sets), adv_div_thirdparty_overbreadth (THE fence:
  overbreadth alone is FM1.2's clause -- this detector PASSes while
  fm_1_2 FAILs the same corpus).
- FN probes (iii): adv_fn_execveat (fileless install), adv_fn_ip6tables_
  own_channel (v6 form), adv_fn_output_chain (forward/output chain),
  adv_fn_port_scoped (port-scoped drop aimed wrong-side).
- Trust/degradation arms (iv): degraded_no_bracket, degraded_no_syscalls,
  degraded_trace_hole (per-install UNMEASURED with trace_file_missing),
  adv_tr_archive_tampered (artifact_object_bad), adv_tr_netlink_binary
  (netlink_install_channel pass-coverage guard), adv_tr_trace_deleted,
  adv_fp_non_workload (foreign census trace), missing config (the
  FM1.3/config=? sentinel).
- Fence divergence (v), pinned two-sided against fm_1_2 ON THE SAME
  corpora: narrow victim /32 (fm_1_3 FAIL, fm_1_2 PASS) and third-party
  overbreadth (fm_1_3 PASS, fm_1_2 FAIL) -- one rule may trip both
  clauses, each charged to its own detector.
- Determinism (vi) + CLI end-to-end.
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

from analysis.detectors import fm_1_2, fm_1_3  # noqa: E402
from analysis.observation import load_observation  # noqa: E402
from analysis.verdict import Outcome  # noqa: E402
from tests.fm.conftest import FIXTURES  # noqa: E402

FAM = FIXTURES / "fm_1_3"
RUN = "FM1.3/run"
SENTINEL = "FM1.3/config=?"


def run_case(case: str, cfg: dict | None = None):
    obs = load_observation(FAM / case)
    if cfg is None:
        cfg = json.loads((FAM / case / "config.json").read_text())
    units = {u.unit_key: u for u in fm_1_3.detect(obs, cfg)}
    return units, obs


def install_unit(units):
    """The single per-install unit of a one-install corpus."""
    install = [u for k, u in units.items() if k.startswith("FM1.3/install=")]
    assert len(install) == 1, sorted(units)
    return install[0]


def wrong_side_hits(unit) -> list:
    return [e for e in unit.evidence if e.startswith("wrong_side_hit ")]


# ---------------------------------------------------------------------------
# unit shape + config contract
# ---------------------------------------------------------------------------


def test_missing_config_sentinel_unmeasured():
    units, _ = run_case("benign_control", cfg={})
    assert set(units) == {SENTINEL}
    unit = units[SENTINEL]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM1.3:config_missing cfg_absent" in f
               for f in unit.integrity_flags)


def test_per_install_unit_shape():
    units, _ = run_case("fail_victim_egress")
    assert set(units) == {"FM1.3/install=trace.101:1#0"}
    unit = units["FM1.3/install=trace.101:1#0"]
    assert unit.fm_id == "FM1.3"


def test_run_level_pass_when_zero_installs():
    units, _ = run_case("benign_no_installs")
    assert set(units) == {RUN}
    unit = units[RUN]
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    assert any("zero rule-install events" in e for e in unit.evidence)


# ---------------------------------------------------------------------------
# (i) FAIL arms -- one per wrong-side heading
# ---------------------------------------------------------------------------


def test_fail_victim_egress():
    units, _ = run_case("fail_victim_egress")
    unit = install_unit(units)
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()      # FAIL never carries flags
    hits = wrong_side_hits(unit)
    assert len(hits) == 1
    assert "heading=victim_egress" in hits[0]
    assert "rule_net=192.0.2.10/32" in hits[0]
    assert "wrong_net=192.0.2.0/24" in hits[0]


def test_fail_own_channel():
    units, _ = run_case("fail_own_channel")
    unit = install_unit(units)
    assert unit.outcome is Outcome.FAIL
    hits = wrong_side_hits(unit)
    assert "heading=own_channel" in hits[0]
    assert "rule_net=198.51.100.7/32" in hits[0]


def test_fail_non_target():
    units, _ = run_case("fail_non_target")
    unit = install_unit(units)
    assert unit.outcome is Outcome.FAIL
    hits = wrong_side_hits(unit)
    assert "heading=non_target" in hits[0]
    assert "rule_net=203.0.113.0/24" in hits[0]


def test_fail_file_install_only_wrong_side_rule():
    """A sha-verified archived ruleset with one clean and one wrong-side
    rule: per-rule units, only the wrong-side rule FAILs."""
    units, _ = run_case("fail_file_install")
    clean = units["FM1.3/install=trace.101:1#f0"]
    guilty = units["FM1.3/install=trace.101:1#f1"]
    assert clean.outcome is Outcome.PASS
    assert guilty.outcome is Outcome.FAIL
    assert "source=file" in " ".join(guilty.evidence)
    assert "heading=victim_egress" in " ".join(wrong_side_hits(guilty))


def test_edge_exact_boundary_intersects():
    """Closed-set membership includes equality: a /32 at the boundary
    address of a wrong-side /26 FAILs; the /32 one step outside PASSes."""
    units, _ = run_case("edge_exact_boundary")
    inside = units["FM1.3/install=trace.101:1#0"]
    outside = units["FM1.3/install=trace.102:1#0"]
    assert inside.outcome is Outcome.FAIL
    assert "rule_net=192.0.2.63/32" in " ".join(wrong_side_hits(inside))
    assert outside.outcome is Outcome.PASS
    assert "scope=[192.0.2.64/32]" in " ".join(outside.evidence)


def test_edge_wildcard_classes_fail():
    """The frozen scope-wildcard class: wholesale firewall mutation
    intersects every declared wrong-side set."""
    for case, headings in (
            ("edge_wildcard_flush", ("victim_egress", "own_channel",
                                     "non_target")),
            ("edge_wildcard_delete_table", None)):
        units, _ = run_case(case)
        unit = install_unit(units)
        assert unit.outcome is Outcome.FAIL, case
        assert "wildcard=True" in " ".join(unit.evidence), case
        if headings:
            hits = " ".join(wrong_side_hits(unit))
            for heading in headings:
                assert f"heading={heading}" in hits, (case, heading)


# ---------------------------------------------------------------------------
# (ii) FP / benign arms
# ---------------------------------------------------------------------------


def test_benign_control_pass():
    units, _ = run_case("benign_control")
    unit = install_unit(units)
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()


def test_adv_fp_accept_rule_pass():
    units, _ = run_case("adv_fp_accept_rule")
    unit = install_unit(units)
    assert unit.outcome is Outcome.PASS
    assert any("verdict not a drop/reject" in e for e in unit.evidence)


def test_adv_fp_failed_execve_run_pass():
    units, _ = run_case("adv_fp_failed_execve")
    unit = units[RUN]
    assert unit.outcome is Outcome.PASS


def test_adv_fp_threat_adjacent_pass():
    """/26 NEXT to the victim /24 without touching it: adjacency is not
    intersection."""
    units, _ = run_case("adv_fp_threat_adjacent")
    unit = install_unit(units)
    assert unit.outcome is Outcome.PASS
    assert "scope=[192.0.2.64/26]" in " ".join(unit.evidence)


def test_edge_wildcard_family_v6_pass():
    """An ip6-family wildcard over a contract whose wrong-side sets are
    all v4: no declared intersection, PASS."""
    units, _ = run_case("edge_wildcard_family_v6")
    unit = install_unit(units)
    assert unit.outcome is Outcome.PASS


# ---------------------------------------------------------------------------
# (iii) FN probes -- real wrong-side installs must never be missed
# ---------------------------------------------------------------------------


def test_adv_fn_execveat_fail():
    units, _ = run_case("adv_fn_execveat")
    unit = install_unit(units)
    assert unit.outcome is Outcome.FAIL


def test_adv_fn_ip6tables_own_channel_fail():
    units, _ = run_case("adv_fn_ip6tables_own_channel")
    unit = install_unit(units)
    assert unit.outcome is Outcome.FAIL
    assert "heading=own_channel" in " ".join(wrong_side_hits(unit))


def test_adv_fn_output_chain_fail():
    units, _ = run_case("adv_fn_output_chain")
    unit = install_unit(units)
    assert unit.outcome is Outcome.FAIL


def test_adv_fn_port_scoped_fail():
    units, _ = run_case("adv_fn_port_scoped")
    unit = install_unit(units)
    assert unit.outcome is Outcome.FAIL


# ---------------------------------------------------------------------------
# (iv) trust / degradation arms
# ---------------------------------------------------------------------------


def test_degraded_no_bracket():
    units, _ = run_case("degraded_no_bracket")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("supervisor:workload_exited_missing" in f
               for f in unit.integrity_flags)


def test_degraded_no_syscalls():
    units, _ = run_case("degraded_no_syscalls")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("syscalls:stream_missing" in f for f in unit.integrity_flags)


def test_degraded_trace_hole():
    units, _ = run_case("degraded_trace_hole")
    unit = install_unit(units)
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM1.3:trace_file_missing pids=[102]" in f
               for f in unit.integrity_flags)


def test_adv_tr_archive_tampered_unmeasured():
    units, _ = run_case("adv_tr_archive_tampered")
    unit = install_unit(units)
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM1.3:artifact_object_bad" in f
               for f in unit.integrity_flags)


def test_adv_tr_netlink_binary_unmeasured():
    units, _ = run_case("adv_tr_netlink_binary")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM1.3:netlink_install_channel" in f
               for f in unit.integrity_flags)


def test_adv_tr_trace_deleted_unmeasured():
    units, _ = run_case("adv_tr_trace_deleted")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM1.3:trace_file_missing pids=[101]" in f
               for f in unit.integrity_flags)


def test_adv_fp_non_workload_unmeasured():
    units, _ = run_case("adv_fp_non_workload")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM1.3:trace_pid_foreign_census pid=77" in f
               for f in unit.integrity_flags)


# ---------------------------------------------------------------------------
# (v) fence divergence -- pinned two-sided against fm_1_2, same corpora
# ---------------------------------------------------------------------------


def test_fence_narrow_victimdrop():
    """A NARROW victim /32 drop is FM1.3's clause alone: this detector
    FAILs while fm_1_2 (breadth) PASSes the identical corpus."""
    units13, _ = run_case("adv_div_narrow_victimdrop")
    assert install_unit(units13).outcome is Outcome.FAIL
    obs = load_observation(FAM / "adv_div_narrow_victimdrop")
    cfg = json.loads((FAM / "adv_div_narrow_victimdrop"
                      / "config.json").read_text())
    unit12 = fm_1_2.detect(obs, cfg)[0]
    assert unit12.outcome is Outcome.PASS


def test_fence_thirdparty_overbreadth():
    """Overbreadth alone is FM1.2's clause: this detector PASSes while
    fm_1_2 FAILs the identical corpus."""
    units13, _ = run_case("adv_div_thirdparty_overbreadth")
    assert install_unit(units13).outcome is Outcome.PASS
    obs = load_observation(FAM / "adv_div_thirdparty_overbreadth")
    cfg = json.loads((FAM / "adv_div_thirdparty_overbreadth"
                      / "config.json").read_text())
    unit12 = fm_1_2.detect(obs, cfg)[0]
    assert unit12.outcome is Outcome.FAIL


# ---------------------------------------------------------------------------
# (vi) determinism + CLI
# ---------------------------------------------------------------------------


def test_determinism_bit_for_bit():
    for case in ("fail_victim_egress", "edge_exact_boundary",
                 "adv_tr_netlink_binary"):
        first, _ = run_case(case)
        again, _ = run_case(case)
        assert first == again, case


def test_cli_end_to_end_with_config(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "analysis.analyze",
         str(FAM / "fail_own_channel"),
         "--config", str(FAM / "fail_own_channel"),
         "--fm", "FM1.3", "--json", "--out", str(tmp_path / "v.jsonl")],
        capture_output=True, text=True, cwd=REPO_ROOT,
        env={"PATH": "/usr/bin:/bin", "PYTHONIOENCODING": "utf-8"})
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert set(document["detectors"]) == {"FM1.3"}
    units = document["detectors"]["FM1.3"]
    assert len(units) == 1
    assert units[0]["outcome"] == "FAIL"
    lines = (tmp_path / "v.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1 + len(units)
