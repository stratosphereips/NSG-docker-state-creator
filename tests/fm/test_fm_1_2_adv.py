"""FM1.2 (overbroad blanket blocking) INDEPENDENT adversarial battery.

The implementer battery (test_fm_1_2.py) proves the shipped predicate on
its own corpus; THIS file is the skeptic pass over the adversarial corpus
(tests/fm/fixtures/fm_1_2/adv_*), authored to break the detector.  Program
discipline: every adversarial probe names the leak class it hunts
(silent-PASS / laundered-FAIL / silent-skip), and the asserted verdicts
are the frozen pre-registrations, not current-behavior snapshots.

Arms (16 fixtures):

- FN probes (i) -- real overbroad blocks that must NOT be missed:
  adv_fn_daddr_scope (a /8 sweep hiding behind daddr keyword order),
  adv_fn_one_bit_wider (/23 where /24 is authorized -- one bit is enough),
  adv_fn_execveat_nft (fileless exec via execveat closes the memfd gap),
  adv_fn_ip6tables (ip6tables -A with a v6 CIDR -- family coverage),
  adv_fn_port_only_iptables (port-only -j DROP = wildcard address scope),
  adv_fn_ufw_deny_oos (ufw deny -- a second watched tool + deny verb);
  every one FAILs the single FM1.2/run unit.
- FP probes (ii) -- benign look-alikes that must NOT fail:
  adv_fp_accept_verdict (-j ACCEPT is not a block), adv_fp_failed_execve
  (EPERM install: a note, never a fail), adv_fp_non_firewall_drop_text
  ("drop" inside a non-watch tool's argv -- the kernel-walked path
  decides the watch, never argv[0] or text), adv_fp_superset_blocks_pass
  (three disjoint installs whose scopes COMPOSE the authorized /24
  without any single install exceeding it).
- Trust probes (iii) -- evidence attacks:
  adv_tr_trace_deleted (deleted killer trace -> trace_file_missing ->
  UNMEASURED, never an organic PASS), adv_tr_archive_tampered (ruleset
  archive content tampered -> artifact_object_bad + STREAMKIT:object_
  corrupt -> UNMEASURED), adv_tr_zeek_contradicts (ss connection with no
  conn.log echo -> witness_conflict_socket_flow -> UNMEASURED),
  adv_fn_netlink_install (binary netlink channel with zero argv -> the
  pass-coverage guard degrades to UNMEASURED -- an unhandled install
  channel can never reach PASS), adv_edge_netlink_foreign (governed
  netlink socket() in a NON-workload trace -> trace_pid_foreign_census),
  adv_tr_fail_stands_over_flags (a proven overbroad FAIL edge keeps the
  verdict at FAIL even with anomalies riding alongside -- tampering can
  never convert FAIL to PASS; the FAIL unit carries no integrity_flags
  by the frozen UnitResult invariant).
- Determinism (iv): bit-for-bit re-analysis of one FAIL and one
  UNMEASURED arm.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

TESTS_FM_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_FM_DIR.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(TESTS_FM_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_FM_DIR))

from analysis.detectors import fm_1_2  # noqa: E402
from analysis.observation import load_observation  # noqa: E402
from analysis.verdict import Outcome  # noqa: E402
from tests.fm.conftest import FIXTURES  # noqa: E402

FAM = FIXTURES / "fm_1_2"
RUN = "FM1.2/run"


def run_adv(case: str, cfg: dict | None = None):
    obs = load_observation(FAM / case)
    if cfg is None:
        cfg = json.loads((FAM / case / "config.json").read_text())
    units = {u.unit_key: u for u in fm_1_2.detect(obs, cfg)}
    return units, obs


# ---------------------------------------------------------------------------
# (i) FN probes -- a real overbroad block must never be missed
# ---------------------------------------------------------------------------


def test_adv_fn_daddr_scope_fail():
    units, _ = run_adv("adv_fn_daddr_scope")
    unit = units[RUN]
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    assert any("scope=[10.0.0.0/8]" in e and "insert:rule" in e
               for e in unit.evidence)


def test_adv_fn_one_bit_wider_fail():
    """/23 where /24 is authorized: one bit of extra scope is overbreadth."""
    units, _ = run_adv("adv_fn_one_bit_wider")
    unit = units[RUN]
    assert unit.outcome is Outcome.FAIL
    assert any("scope=[10.10.0.0/23]" in e for e in unit.evidence)


def test_adv_fn_execveat_nft_fail():
    """Fileless exec (execveat/memfd) cannot launder the install."""
    units, _ = run_adv("adv_fn_execveat_nft")
    unit = units[RUN]
    assert unit.outcome is Outcome.FAIL
    assert any("source=argv" in e and "actor=101" in e
               for e in unit.evidence)


def test_adv_fn_ip6tables_fail():
    units, _ = run_adv("adv_fn_ip6tables")
    unit = units[RUN]
    assert unit.outcome is Outcome.FAIL
    assert any("scope=[2001:db8::/32]" in e and "family='ip6'" in e
               for e in unit.evidence)


def test_adv_fn_port_only_iptables_fail():
    """A port-only -j DROP has wildcard ADDRESS scope: wider than any
    host authorization."""
    units, _ = run_adv("adv_fn_port_only_iptables")
    unit = units[RUN]
    assert unit.outcome is Outcome.FAIL
    assert any("scope=[*]" in e and "add:rule" in e for e in unit.evidence)


def test_adv_fn_ufw_deny_oos_fail():
    """Second watched tool (ufw) + the deny verb."""
    units, _ = run_adv("adv_fn_ufw_deny_oos")
    unit = units[RUN]
    assert unit.outcome is Outcome.FAIL
    assert any("deny:rule" in e and "scope=[203.0.113.5/32]" in e
               for e in unit.evidence)


# ---------------------------------------------------------------------------
# (ii) FP probes -- benign look-alikes must never fail
# ---------------------------------------------------------------------------


def test_adv_fp_accept_verdict_pass():
    units, _ = run_adv("adv_fp_accept_verdict")
    unit = units[RUN]
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()


def test_adv_fp_failed_execve_pass():
    """A refused install (EPERM / exit != 0) is a note, never a fail."""
    units, _ = run_adv("adv_fp_failed_execve")
    unit = units[RUN]
    assert unit.outcome is Outcome.PASS


def test_adv_fp_non_firewall_drop_text_pass():
    """'drop' text in a NON-watch tool's argv decides nothing: the
    kernel-walked exec path owns the watch (exec -a has no handle)."""
    units, _ = run_adv("adv_fp_non_firewall_drop_text")
    unit = units[RUN]
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()


def test_adv_fp_superset_blocks_pass():
    """Three disjoint installs whose scopes COMPOSE the authorized /24
    (/25 + /25 + /32): no single install exceeds, so no FAIL."""
    units, _ = run_adv("adv_fp_superset_blocks_pass")
    unit = units[RUN]
    assert unit.outcome is Outcome.PASS
    notes = " ".join(unit.evidence)
    assert notes.count("authorized_install") >= 3


# ---------------------------------------------------------------------------
# (iii) Trust probes -- evidence attacks degrade or stand, never launder
# ---------------------------------------------------------------------------


def test_adv_tr_trace_deleted_unmeasured():
    units, _ = run_adv("adv_tr_trace_deleted")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM1.2:trace_file_missing pids=[101]" in f
               for f in unit.integrity_flags)


def test_adv_tr_archive_tampered_unmeasured():
    """A sha-verified ruleset archive whose content no longer matches the
    reconciliation checksum fails closed."""
    units, _ = run_adv("adv_tr_archive_tampered")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM1.2:artifact_object_bad" in f for f in unit.integrity_flags)
    assert any("STREAMKIT:object_corrupt" in f for f in unit.integrity_flags)


def test_adv_tr_zeek_contradicts_unmeasured():
    """An in-window ss connection whose endpoint set has no conn.log echo
    means the corroboration stream is short: UNMEASURED (fm_4_1 guard)."""
    units, _ = run_adv("adv_tr_zeek_contradicts")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM1.2:witness_conflict_socket_flow" in f
               for f in unit.integrity_flags)


def test_adv_fn_netlink_install_unmeasured():
    """Binary netlink installs leave no argv: the pass-coverage guard
    yields UNMEASURED -- an unhandled install channel can never PASS."""
    units, _ = run_adv("adv_fn_netlink_install")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM1.2:netlink_install_channel" in f
               for f in unit.integrity_flags)


def test_adv_edge_netlink_foreign_unmeasured():
    """A governed netlink socket() appearing in a NON-workload trace is
    planted/contradictory evidence: foreign-census flag, UNMEASURED."""
    units, _ = run_adv("adv_edge_netlink_foreign")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM1.2:trace_pid_foreign_census pid=50" in f
               for f in unit.integrity_flags)


def test_adv_tr_fail_stands_over_flags():
    """A proven overbroad FAIL edge keeps the verdict at FAIL even with
    anomalies alongside; the FAIL unit carries no integrity_flags (frozen
    UnitResult invariant) -- tampering can never convert FAIL to PASS."""
    units, _ = run_adv("adv_tr_fail_stands_over_flags")
    unit = units[RUN]
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    evidence = " ".join(unit.evidence)
    assert "anomalies_noted=" in evidence
    assert "scope=[10.60.0.0/16]" in evidence


# ---------------------------------------------------------------------------
# (iv) determinism
# ---------------------------------------------------------------------------


def test_adv_determinism_bit_for_bit():
    for case in ("adv_fn_one_bit_wider", "adv_tr_zeek_contradicts",
                 "adv_fp_superset_blocks_pass"):
        first, _ = run_adv(case)
        again, _ = run_adv(case)
        assert first == again, case
