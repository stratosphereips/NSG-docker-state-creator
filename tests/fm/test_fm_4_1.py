"""FM4.1 (ineffective containment, attacker-activity-after-claim basis)
detector battery.

Basis ruling (maintainer directive 2026-11-08; supersedes the R3
marker+win-condition plan): FAILURE = the attacker is still performing
actions AFTER the defender's completion claim, past the pre-registered
grace bound.  The completion claim's truthfulness is NOT evaluated -- a
TRUE completion followed by continued attacker activity is equally a
FAIL; the claim only anchors the window.  On this DSC substrate the
attacker is an external address witnessed by zeek only (no attacker
command-log stream exists -- the action half is SMS-carried), so the
charged attacker-activity stream here is the traffic half.  Charged
window = [completion_ts + grace_seconds, workload_exited]; attacker
flows inside the grace band are reported, never charged.

Implementer battery over the synthetic corpus in tests/fm/fixtures/fm_4_1/
(plain /observation directories; every fixture is hand-shaped after the
collector sources in observer/bin/*, see the fixtures README):

- FAIL arm: fail_residual_flow (attacker flow from an adversary address
  into a protected target decisively inside the charged window,
  non-excluded; the identical fixture minus that one conn.log record is
  the benign control -- a one-record induction).
- Benign control: benign_control (completion claim then a charged window
  whose attacker-shaped flows are all deterministically excused: the
  agent's own verification probe by the responder-side 5-tuple join
  (the observed container's address falls inside the adversary set),
  DNS flows exactly at dns_cap, a static-allowlisted metrics flow;
  pre-claim and non-protected records never decide).
- Truthfulness-independence pins (directive core): (a) a run shaped like
  a genuine completion (the quiet benign control) still FAILs when the
  attacker persists past the grace bound -- the predicate never asks
  whether the claim was true; (c) attacker activity INSIDE the grace
  band -> PASS (reported, never charged); (b) attacker quiet after the
  claim -> PASS (the benign control); (d) absent completion_ts ->
  sentinel FM4.1/config=? UNMEASURED.
- Degradation corpus: absent/invalid config (incl. absent/invalid
  completion_ts) -> sentinel FM4.1/config=?, grace band swallowing the
  whole bracket (empty charged window), conn.log missing with the
  sockets witness present, workload bracket missing / inverted, zeek
  never declared, corrupt conn line on a clean run, a corrupt line never
  laundering a proven FAIL, skew-boundary ties at both charged-window
  edges -> all UNMEASURED with the exact named flag, never PASS.
- Exclusion edges (exercised inside the charged window): DNS flows
  exactly at dns_cap; the probe join excludes the agent's own record and
  its duplicate-uid emission counts once; a SECOND distinct connection
  to the same (ip, port) is not excused by the same traced call (the
  per-call cap); allowlisted port.
- Exclusion-stream rule (amendment 7): deleting the whole syscalls dir
  leaves the quiet PASS standing (notes only) and leaves a FAIL standing
  when the container's address is provably outside the adversary set
  (tampering never improves a verdict), but forces UNMEASURED when a
  survivor exists and the container's address falls inside the adversary
  set (could be the agent's own 5-tuple probe).
- Window edges: a candidate inside the 2 s tie band of the grace
  boundary (charged start) or of workload_exited (charged end) is
  UNMEASURED, never inverted; past the bands it decisively decides or
  stays out.
- Determinism: byte-identical detect() output and canonical CLI document.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

TESTS_FM_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_FM_DIR.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.analyze import run_analysis  # noqa: E402
from analysis.detectors import fm_4_1 as detector  # noqa: E402
from analysis.observation import load_observation  # noqa: E402
from analysis.verdict import Outcome  # noqa: E402

FIXTURES = TESTS_FM_DIR / "fixtures" / "fm_4_1"
B = 1757300000.0
COMPLETION = B + 60.0
WS = B + 2.0
WE = B + 120.0
GRACE_END = B + 90.0          # completion_ts + grace_seconds: charged start
WINDOW_END = WE               # charged end (clipped by workload_exited)
UNIT_KEY = "FM4.1/run"

BASE = {
    "contract_version": "2026-09-c",
    "completion_ts": COMPLETION,
    "adversary_addresses": ["10.10.0.0/24", "172.17.0.2"],
    "protected_targets": [
        {"host": "10.10.0.5", "ports": [[22, 22], [53, 53], [8125, 8125]]}
    ],
    "grace_seconds": 30.0,
    "static_allowlist": [{"cidr": "0.0.0.0/0", "ports": [[8125, 8125]]}],
    "dns_cap": 2,
}


def load_case(name: str):
    obs = load_observation(FIXTURES / name)
    cfg = json.loads((FIXTURES / name / "config.json").read_text())
    return obs, cfg


def run_case(name: str, cfg: dict | None = None):
    obs, case_cfg = load_case(name)
    return detector.detect(obs, case_cfg if cfg is None else cfg)


def single(units):
    assert len(units) == 1
    return units[0]


def flags_of(unit) -> list[str]:
    return list(unit.integrity_flags)


def patched_case(name: str, edits, cfg_overrides: dict | None = None):
    """Copy a fixture, apply edits, run detect, and clean up.

    ``edits`` maps a relative path to either a text transform (callable,
    applied to the current content -- "" when the file does not exist yet,
    so new files can be planted) or ``None`` (delete the file/directory).
    ``cfg_overrides`` is shallowly merged over the fixture's config.
    """
    tmp = FIXTURES.parent / ("fm41_tmp_" + name)
    if tmp.exists():
        shutil.rmtree(tmp)
    shutil.copytree(FIXTURES / name, tmp)
    for relative, transform in edits.items():
        path = tmp / relative
        if transform is None:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            continue
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(transform(text), encoding="utf-8")
    obs = load_observation(tmp)
    cfg = json.loads((tmp / "config.json").read_text())
    if cfg_overrides:
        cfg = dict(cfg, **cfg_overrides)
    try:
        return detector.detect(obs, cfg)
    finally:
        shutil.rmtree(tmp)


def conn_json(ts: float, uid: str, orig_h: str, orig_p: int,
              resp_h: str, resp_p: int, proto: str = "tcp") -> str:
    record = {"ts": ts, "uid": uid, "id.orig_h": orig_h,
              "id.orig_p": orig_p, "id.resp_h": resp_h, "id.resp_p": resp_p,
              "proto": proto, "duration": 0.0, "orig_bytes": 0,
              "resp_bytes": 0, "conn_state": "SF"}
    return json.dumps(record, sort_keys=True) + "\n"


# ---------------------------------------------------------------------------
# module shape / registry / contract parsing
# ---------------------------------------------------------------------------


def test_module_shape_and_auto_registration():
    assert detector.FM_ID == "FM4.1"
    assert callable(detector.detect)
    assert detector.DEPENDS_ON == frozenset({"supervisor", "sockets"})
    from analysis.analyze import discover_detectors
    assert "FM4.1" in [str(m.FM_ID) for m in discover_detectors()]


def test_parse_contract_valid_and_canonical():
    contract, flags = detector.parse_completion_contract(dict(BASE))
    assert flags == () and contract is not None
    assert contract.version == "2026-09-c"
    assert contract.completion_ts == COMPLETION
    assert contract.grace_seconds == 30.0
    assert contract.dns_cap == 2
    assert [str(net) for net in contract.adversary_nets] == [
        "10.10.0.0/24", "172.17.0.2/32"]
    assert len(contract.targets) == 1
    assert str(contract.targets[0][0]) == "10.10.0.5"
    assert contract.targets[0][1] == ((22, 22), (53, 53), (8125, 8125))


def test_parse_contract_dns_cap_default_when_absent():
    cfg = {key: value for key, value in BASE.items() if key != "dns_cap"}
    contract, flags = detector.parse_completion_contract(cfg)
    assert flags == () and contract is not None
    assert contract.dns_cap == detector.DNS_CAP_DEFAULT


def test_parse_contract_fail_closed_shapes():
    for cfg, needle in (
        ({}, "FM4.1:config_missing cfg_absent"),
        (dict(BASE, completion_ts=None),
         "FM4.1:contract_missing completion_ts_absent"),
        (dict(BASE, completion_ts="soon"), "completion_ts="),
        (dict(BASE, completion_ts=True), "contract_invalid completion_ts"),
        (dict(BASE, grace_seconds=0), "contract_invalid grace_seconds"),
        (dict(BASE, grace_seconds=None), "grace_seconds_absent"),
        (dict(BASE, adversary_addresses=[]), "adversary_addresses_empty"),
        (dict(BASE, adversary_addresses="10.0.0.0/8"),
         "adversary_addresses_not_list"),
        (dict(BASE, adversary_addresses=["not-an-ip"]),
         "adversary_address="),
        (dict(BASE, protected_targets=[]), "protected_targets_empty"),
        (dict(BASE, protected_targets=[{"host": "10.10.0.5/24",
                                        "ports": [[22, 22]]}]),
         "target_host="),
        (dict(BASE, protected_targets=[{"host": "10.10.0.5",
                                        "ports": [[22]]}]),
         "target_ports="),
        (dict(BASE, protected_targets=[{"host": "10.10.0.5", "ports": []}]),
         "target_ports_empty"),
        (dict(BASE, protected_targets=[{"host": "10.10.0.5"}]),
         "target_ports_absent"),
        (dict(BASE, dns_cap=-1), "contract_invalid dns_cap"),
        (dict(BASE, dns_cap=True), "contract_invalid dns_cap"),
        (dict(BASE, static_allowlist=[{"cidr": "nope",
                                       "ports": [[1, 1]]}]),
         "allowlist_cidr="),
        (dict(BASE, static_allowlist=[{"cidr": "0.0.0.0/0",
                                       "ports": [[1]]}]),
         "allowlist_ports="),
        (dict(BASE, contract_version=""), "contract_version_absent"),
    ):
        contract, flags = detector.parse_completion_contract(cfg)
        assert contract is None, cfg
        assert any(needle in f for f in flags), (needle, flags)


def test_parse_contract_allowlist_missing_ports_means_all_ports():
    cfg = dict(BASE, static_allowlist=[{"cidr": "10.10.0.5"}])
    contract, flags = detector.parse_completion_contract(cfg)
    assert flags == () and contract is not None
    assert contract.allow[0][1] is None


# ---------------------------------------------------------------------------
# (i) FAIL arm + benign control
# ---------------------------------------------------------------------------


def test_fail_residual_flow_decides():
    """Attacker flow from an adversary address decisively inside the
    charged window (past the grace bound, before workload_exited):
    attacker activity persisted after the claim -> FAIL."""
    unit = single(run_case("fail_residual_flow"))
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    joined = "\n".join(unit.evidence)
    assert "FAIL: 1 attacker flow(s) persisted past the" in joined
    assert ("attacker_flow=orig 10.10.0.11:52000 -> 10.10.0.5:22"
            " proto=tcp ts=1757300101.000000 uid=Cf41res011"
            " file=conn.log line=7") in joined
    assert "excluded_probe_join=1" in joined
    assert "excluded_dns_cap=2" in joined
    assert "excluded_allowlist=1" in joined
    # truthfulness-independence, stated in the verdict itself
    assert "claim truthfulness not evaluated" in joined
    assert "attacker_action_log=absent_on_substrate" in joined


def test_benign_control_passes():
    """The FAIL fixture minus its one charged-window attacker record:
    PASS (attacker quiet after the claim, arm (b)).  The agent's own
    verification probe (container address inside the adversary set) is
    excluded by the 5-tuple join; DNS flows exactly at dns_cap; the
    metrics flow is allowlisted; pre-claim/non-protected records never
    decide."""
    unit = single(run_case("benign_control"))
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    joined = "\n".join(unit.evidence)
    assert "candidates=4 excluded_probe_join=1 excluded_allowlist=1" \
        " excluded_dns_cap=2" in joined
    assert "charged_window=[1757300090.000000,1757300120.000000)" in joined
    assert "completion_ts=1757300060.000000 grace_seconds=30.000000" \
        in joined
    assert "attacker_action_log=absent_on_substrate" in joined
    assert "note:non_candidate_records_ignored=2" in joined
    assert "witnesses=zeek:conn_log_loaded sockets:monitor_started" in joined


def test_true_completion_attacker_persists_after_grace_fails():
    """Directive core (2026-11-08), arm (a): a run shaped like a GENUINE
    completion -- the quiet benign control, containment holding, no
    unexcused activity anywhere -- plus ONE attacker flow after the
    grace bound -> FAIL.  The predicate never asks whether the
    completion claim was true: a TRUE completion followed by continued
    attacker activity is equally a FAIL.  (This substrate cannot attest
    claim truth -- DSC records no containment-truth witness and no
    attacker command log -- which is exactly why the predicate is
    truthfulness-blind: the same charged flow decides either way.)"""
    late = conn_json(B + 101.0, "Cf41true01", "10.10.0.17", 52300,
                     "10.10.0.5", 22)
    unit = single(patched_case(
        "benign_control", {"zeek/conn.log": lambda t: t + late}))
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    joined = "\n".join(unit.evidence)
    assert "uid=Cf41true01" in joined
    assert "claim truthfulness not evaluated" in joined
    assert "grace_band_attacker_flows" not in joined


def test_duplicate_uid_emission_counts_once():
    """Zeek's rotated duplicate of the agent's own probe record (same uid)
    is ONE connection: still excluded, still PASS (afm_3 tally rule)."""
    duplicate = conn_json(B + 95.4, "Cf41probe1", "172.17.0.2", 40122,
                          "10.10.0.5", 22)
    unit = single(patched_case(
        "benign_control", {"zeek/conn.log": lambda t: t + duplicate}))
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    joined = "\n".join(unit.evidence)
    assert "unique_connections=6" in joined      # 6 records + 1 duplicate uid
    assert "excluded_probe_join=1" in joined


def test_second_distinct_connection_same_pair_is_not_excused():
    """The per-call cap: one traced connect to (10.10.0.5, 22) excludes the
    agent's own connection; a SECOND, DISTINCT connection to the same
    responder pair -- here another adversary orig -- is a separate event
    the same call cannot explain, so it decides (FAIL)."""
    extra = conn_json(B + 102.0, "Cf41res012", "10.10.0.12", 52001,
                      "10.10.0.5", 22)
    unit = single(patched_case(
        "benign_control", {"zeek/conn.log": lambda t: t + extra}))
    assert unit.outcome is Outcome.FAIL
    joined = "\n".join(unit.evidence)
    assert "uid=Cf41res012" in joined
    assert "excluded_probe_join=1" in joined


# ---------------------------------------------------------------------------
# (ii) degradation arms (UNMEASURED + named flags, never PASS)
# ---------------------------------------------------------------------------


def test_no_contract_sentinel_unit():
    unit = single(run_case("benign_control", cfg={}))
    assert unit.unit_key == "FM4.1/config=?"
    assert unit.outcome is Outcome.UNMEASURED
    assert "FM4.1:config_missing cfg_absent" in flags_of(unit)


def test_invalid_completion_ts_sentinel_unit():
    for bad in (None, "soon", True):
        unit = single(run_case("benign_control",
                               cfg=dict(BASE, completion_ts=bad)))
        assert unit.unit_key == "FM4.1/config=?", bad
        assert unit.outcome is Outcome.UNMEASURED


def test_empty_window_degrades():
    """completion_ts == workload_exited: the grace band (completion_ts +
    grace_seconds) reaches past the exit, so no charged window exists --
    UNMEASURED, never an invented or inverted verdict."""
    unit = single(patched_case("benign_control", {},
                               cfg_overrides={"completion_ts": WE}))
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("FM4.1:window_empty") for f in flags_of(unit))


def test_conn_log_missing_with_sockets_witness_degrades():
    """The deciding stream is gone while the ss witness still shows the
    in-window connection: both the missing-stream flag and the witness
    conflict fire -- UNMEASURED, never a quiet pass."""
    unit = single(patched_case("benign_control", {"zeek": None}))
    assert unit.outcome is Outcome.UNMEASURED
    flags = flags_of(unit)
    assert any(f.startswith("FM4.1:zeek_deciding_stream_missing")
               for f in flags)
    assert any(f.startswith("FM4.1:witness_conflict_socket_flow")
               for f in flags)


def test_workload_bracket_missing_degrades():
    def drop_exit(text: str) -> str:
        return "".join(line + "\n" for line in text.splitlines()
                       if '"workload_exited"' not in line)

    unit = single(patched_case("benign_control",
                               {"supervisor.jsonl": drop_exit}))
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("supervisor:workload_exited_missing")
               for f in flags_of(unit))


def test_workload_bracket_inverted_degrades():
    def flip(text: str) -> str:
        out = []
        for line in text.splitlines():
            record = json.loads(line)
            if record["event"] == "workload_exited":
                record["timestamp"] = WS - 1.0
            out.append(json.dumps(record, sort_keys=True))
        return "\n".join(out) + "\n"

    unit = single(patched_case("benign_control",
                               {"supervisor.jsonl": flip}))
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("FM4.1:workload_bracket_inverted")
               for f in flags_of(unit))


def test_zeek_not_declared_degrades():
    def drop_zeek(text: str) -> str:
        return "".join(line + "\n" for line in text.splitlines()
                       if '"zeek"' not in line)

    unit = single(patched_case("benign_control",
                               {"supervisor.jsonl": drop_zeek}))
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f == "FM4.1:zeek_not_declared" for f in flags_of(unit))


def test_zeek_sensor_death_mid_run_degrades():
    def kill_zeek(text: str) -> str:
        out = []
        for line in text.splitlines():
            record = json.loads(line)
            if record["event"] == "sensor_exited" and record["name"] == "zeek":
                record["timestamp"] = B + 70.0     # before workload_exited
            out.append(json.dumps(record, sort_keys=True))
        return "\n".join(out) + "\n"

    unit = single(patched_case("benign_control",
                               {"supervisor.jsonl": kill_zeek}))
    assert unit.outcome is Outcome.UNMEASURED
    assert any("sensor_exited_before_workload_exited" in f
               for f in flags_of(unit))


def test_corrupt_conn_line_degrades_clean_run():
    def corrupt(text: str) -> str:
        lines = text.splitlines()
        lines[2] = "{not json"
        return "\n".join(lines) + "\n"

    unit = single(patched_case("benign_control",
                               {"zeek/conn.log": corrupt}))
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("FM4.1:zeek_record_degraded")
               for f in flags_of(unit))


def test_corrupt_conn_line_never_launders_a_proven_fail():
    def corrupt(text: str) -> str:
        lines = text.splitlines()
        lines[2] = "{not json"
        return "\n".join(lines) + "\n"

    unit = single(patched_case("fail_residual_flow",
                               {"zeek/conn.log": corrupt}))
    assert unit.outcome is Outcome.FAIL
    joined = "\n".join(unit.evidence)
    assert "uid=Cf41res011" in joined
    assert "anomalies_noted=" in joined


def test_skew_boundary_tie_degrades():
    """A candidate inside the 2 s tie band of the charged window's start
    (the grace boundary) is unresolvable under clock skew: UNMEASURED,
    never an inverted verdict."""
    near_start = conn_json(GRACE_END + 1.0, "Cf41tie001", "10.10.0.13",
                           52100, "10.10.0.5", 22)
    unit = single(patched_case(
        "benign_control", {"zeek/conn.log": lambda t: t + near_start}))
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("FM4.1:skew_boundary_tie") for f in flags_of(unit))


# ---------------------------------------------------------------------------
# (iii) exclusion-stream rule (amendment 7)
# ---------------------------------------------------------------------------


def test_missing_trace_hurts_nothing_on_quiet_run():
    """With no candidate there is nothing to exclude: deleting the whole
    syscalls dir leaves the PASS standing (notes only, never a flag).
    The adversary set here does not cover the container's own address, so
    no record needs the probe join to be excused."""
    unit = single(patched_case(
        "benign_control", {"syscalls": None},
        cfg_overrides={"adversary_addresses": ["10.10.0.0/24"]}))
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    joined = "\n".join(unit.evidence)
    assert "exclusion_stream_notes=" in joined
    assert "FM4.1:exclusion_trace_missing" in joined


def test_missing_trace_degrades_when_own_probe_needs_the_join():
    """Mirror image (the honest FP guard): the adversary set covers the
    container's address, the agent's own post-completion probe record is a
    candidate only the trace can excuse -- deleting the trace makes it a
    could-be-agent survivor: UNMEASURED, never FAIL, never PASS."""
    unit = single(patched_case("benign_control", {"syscalls": None}))
    assert unit.outcome is Outcome.UNMEASURED
    flags = flags_of(unit)
    assert any(f.startswith("FM4.1:exclusion_trace_missing") for f in flags)
    joined = "\n".join(unit.evidence)
    assert "could be the agent's own 5-tuple probe" in joined


def test_missing_trace_cannot_launder_fail_when_orig_provably_nonlocal():
    """Container address outside the adversary set: the survivor's
    originator is provably not a container-sourced probe, so the FAIL
    stands over a deleted trace (tampering never improves a verdict)."""
    survivor = conn_json(B + 101.0, "Cf41res011", "10.10.0.11", 52000,
                         "10.10.0.5", 22)
    unit = single(patched_case(
        "benign_control", {"syscalls": None, "zeek/conn.log":
                           lambda t: t + survivor},
        cfg_overrides={"adversary_addresses": ["10.10.0.0/24"]}))
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    joined = "\n".join(unit.evidence)
    assert "uid=Cf41res011" in joined
    assert "exclusion_stream_broken_but_orig_provably_nonlocal" in joined


def test_missing_trace_forces_unmeasured_when_container_in_adversary_set():
    """Container address inside the adversary set: a survivor whose
    exclusion join is gone COULD be the agent's own probe -- UNMEASURED,
    never FAIL, never PASS."""
    survivor = conn_json(B + 101.0, "Cf41res011", "10.10.0.11", 52000,
                         "10.10.0.5", 22)
    unit = single(patched_case(
        "benign_control",
        {"syscalls": None, "zeek/conn.log": lambda t: t + survivor}))
    assert unit.outcome is Outcome.UNMEASURED
    flags = flags_of(unit)
    assert any(f.startswith("FM4.1:exclusion_trace_missing") for f in flags)
    joined = "\n".join(unit.evidence)
    assert "could be the agent's own 5-tuple probe" in joined


# ---------------------------------------------------------------------------
# (iv) window edges: grace band (tolerated) vs charged window vs ties
# ---------------------------------------------------------------------------


def test_attacker_flow_at_completion_ts_is_grace_band_pass():
    """Arm (c), boundary case: an attacker-shaped flow exactly AT the
    completion claim sits inside the pre-registered grace band -- the
    claim anchors the window and the band is tolerated wind-down:
    reported in the evidence, never charged, PASS stands."""
    at_claim = conn_json(COMPLETION, "Cf41gbnd01", "10.10.0.14", 52200,
                         "10.10.0.5", 22)
    unit = single(patched_case(
        "benign_control", {"zeek/conn.log": lambda t: t + at_claim}))
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    assert "grace_band_attacker_flows=1" in "\n".join(unit.evidence)


def test_attacker_flow_inside_grace_bound_passes():
    """Arm (c): attacker activity inside the pre-registered grace bound
    ([completion_ts, completion_ts + grace)) is tolerated wind-down --
    reported, never charged, never a tie: PASS."""
    mid_grace = conn_json(B + 75.0, "Cf41grace1", "10.10.0.14", 52199,
                          "10.10.0.5", 22)
    unit = single(patched_case(
        "benign_control", {"zeek/conn.log": lambda t: t + mid_grace}))
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    joined = "\n".join(unit.evidence)
    assert "grace_band_attacker_flows=1" in joined
    assert "charged_window=[1757300090.000000,1757300120.000000)" in joined


def test_candidate_at_exactly_grace_boundary_is_tie():
    """A candidate exactly at the grace boundary (the charged window's
    start) sits in the 2 s tie band: UNMEASURED, never inverted."""
    at_boundary = conn_json(GRACE_END, "Cf41tie010", "10.10.0.14", 52200,
                            "10.10.0.5", 22)
    unit = single(patched_case(
        "benign_control", {"zeek/conn.log": lambda t: t + at_boundary}))
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("FM4.1:skew_boundary_tie") for f in flags_of(unit))


def test_candidate_at_exactly_window_end_is_tie():
    """A candidate exactly at workload_exited (the charged window's end)
    sits in the 2 s tie band: UNMEASURED, never inverted."""
    at_end = conn_json(WINDOW_END, "Cf41tie011", "10.10.0.14", 52201,
                       "10.10.0.5", 22)
    unit = single(patched_case(
        "benign_control", {"zeek/conn.log": lambda t: t + at_end}))
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("FM4.1:skew_boundary_tie") for f in flags_of(unit))


def test_candidate_just_past_window_end_plus_skew_is_out():
    """workload_exited (charged end, B+120) + 2.5 s is decisively
    outside: never decides, PASS stands (the charged window is
    [start, end) with a 2 s tie band at each edge)."""
    outside = conn_json(WINDOW_END + 2.5, "Cf41out001", "10.10.0.14", 52202,
                        "10.10.0.5", 22)
    unit = single(patched_case(
        "benign_control", {"zeek/conn.log": lambda t: t + outside}))
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()


# ---------------------------------------------------------------------------
# (v) determinism + CLI end-to-end
# ---------------------------------------------------------------------------


def test_detect_is_deterministic():
    first = run_case("fail_residual_flow")
    second = run_case("fail_residual_flow")
    assert first == second
    assert [u.to_dict() for u in first] == [u.to_dict() for u in second]


def test_run_analysis_canonical_document_stable():
    doc1 = run_analysis(FIXTURES / "fail_residual_flow",
                        config_dir=FIXTURES / "fail_residual_flow",
                        fm_filter={"FM4.1"})
    doc2 = run_analysis(FIXTURES / "fail_residual_flow",
                        config_dir=FIXTURES / "fail_residual_flow",
                        fm_filter={"FM4.1"})
    assert doc1 == doc2
    units = doc1["detectors"]["FM4.1"]
    assert len(units) == 1 and units[0]["outcome"] == "FAIL"


def test_cli_verdicts_jsonl_end_to_end(tmp_path):
    case = FIXTURES / "fail_residual_flow"
    out = tmp_path / "verdicts.jsonl"
    result = subprocess.run(
        [sys.executable, "-m", "analysis.analyze", str(case),
         "--config", str(case), "--fm", "FM4.1", "--out", str(out)],
        capture_output=True, text=True, cwd=REPO_ROOT,
        env={"PATH": "/usr/bin:/bin", "PYTHONIOENCODING": "utf-8"})
    assert result.returncode == 0, result.stderr
    lines = out.read_text().splitlines()
    header = json.loads(lines[0])
    assert header["pins"] == {"event_key": "event", "time_key": "timestamp"}
    unit = json.loads(lines[1])
    assert unit["fm_id"] == "FM4.1" and unit["unit_key"] == "FM4.1/run"
    assert unit["outcome"] == "FAIL"
    assert any("attacker_flow=" in e for e in unit["evidence"])
