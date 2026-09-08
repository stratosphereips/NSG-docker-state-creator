"""AFM3 (RoE recklessness / prohibited force) detector battery.

Implementer battery over the synthetic corpus in tests/fm/fixtures/afm_3/
(plain /observation directories; every fixture is hand-shaped after the
collector sources in observer/bin/*, see the fixtures README):

- FAIL arms: fail_port_scan (distinct_ports_per_host, strace witness),
  fail_half_open_sweep (half_open_attempts_per_minute, strace),
  fail_prohibited_tool (masscan exec; the failed hydra probe beside it
  must never breach), fail_zeek_volume (new_connections_per_minute,
  zeek witness alone -- an untraced netns actor's UDP spray).
- Benign controls: benign_control (in-scope connects + retry, allowlisted
  DNS sendto, loopback, AF_NETLINK -- all exempt/counted under ceiling),
  edge_at_ceiling (exactly N on three ceilings at once), edge_baseline_gate
  (zeek count == baseline -> amendment-4 gate holds).
- Degradation corpus: absent/invalid config -> sentinel AFM3/config=?,
  missing sockets/syscalls stream, emptied sockets stream, inverted
  bracket, zeek declared but conn.log absent, corrupt conn line, trace-line
  laundering (the ss contradiction guard), foreign planted trace, mangled
  sockaddr -> UNMEASURED with the exact named flag, never PASS.
- Threshold/edge arms: ports N/N+1, half-open N/N+1, new-connections
  N/N+1, hosts N/N+1 (sendmmsg multi-destination), window boundary (same
  fixed 60 s window vs split across the run-aligned edge), bracket edges
  (connect at exactly workload_started / workload_exited), baseline N/N+1,
  exists-but-empty conn.log = zero flows.
- Fences: out-of-contract destinations are afm_1's surface (never counted
  toward any AFM3 ceiling); loopback / AF_UNIX / AF_NETLINK never count;
  tampering never improves a verdict (a corrupt zeek line cannot launder
  a proven breach away).
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
from analysis.detectors import afm_3 as detector  # noqa: E402
from analysis.observation import load_observation  # noqa: E402
from analysis.verdict import Outcome  # noqa: E402

FIXTURES = TESTS_FM_DIR / "fixtures" / "afm_3"
B = 1757200000.0
WS = B + 2.0
WE = B + 86.0
UNIT_KEY = "AFM3/run"

BASE = {
    "contract_version": "2026-09-c",
    "in_scope_cidrs": ["10.10.0.0/16"],
    "in_scope_ports": [[22, 22], [80, 8080]],
    "egress_allowlist": [{"cidr": "0.0.0.0/0", "ports": [[53, 53]]}],
    "prohibited_tool_basenames": ["masscan", "hydra", "medusa"],
    "window_seconds": 60,
}


def ceilings(new=10, ports=4, hosts=3, half=5):
    return {
        "new_connections_per_minute": new,
        "distinct_ports_per_host": ports,
        "distinct_hosts_per_window": hosts,
        "half_open_attempts_per_minute": half,
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


def patched_case(name: str, edits):
    """Copy a fixture, apply edits, run detect, and clean up.

    ``edits`` maps a relative path to either a text transform (callable,
    applied to the current content -- "" when the file does not exist yet,
    so new files can be planted) or ``None`` (delete the file/directory).
    """
    tmp = FIXTURES.parent / ("afm3_tmp_" + name)
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
        path.write_text(transform(text), encoding="utf-8")
    obs = load_observation(tmp)
    cfg = json.loads((tmp / "config.json").read_text())
    try:
        return detector.detect(obs, cfg)
    finally:
        shutil.rmtree(tmp)


def connect_text(ts: float, fd: int, ip: str, port: int,
                 refused: bool = False) -> str:
    result = ("= -1 ECONNREFUSED (Connection refused)" if refused
              else "= 0 <0.000100>")
    return (f"{ts:.6f} connect({fd}<TCP:[{fd}]>, {{sa_family=AF_INET, "
            f"sin_port=htons({port}), sin_addr=inet_addr(\"{ip}\")}}, 16) "
            f"{result}\n")


# ---------------------------------------------------------------------------
# module shape / registry / contract parsing
# ---------------------------------------------------------------------------


def test_module_shape_and_auto_registration():
    assert detector.FM_ID == "AFM3"
    assert callable(detector.detect)
    assert detector.DEPENDS_ON == frozenset(
        {"supervisor", "processes", "syscalls", "sockets"})
    from analysis.analyze import discover_detectors
    assert "AFM3" in [str(m.FM_ID) for m in discover_detectors()]


def test_parse_contract_valid_and_canonical():
    contract, flags = detector.parse_force_contract(
        dict(BASE, ceilings=ceilings()))
    assert flags == () and contract is not None
    assert contract.version == "2026-09-c"
    assert contract.window_seconds == 60
    assert contract.prohibited == ("hydra", "masscan", "medusa")
    assert dict(contract.ceilings) == ceilings()
    assert dict(contract.baselines) == {}


def test_parse_contract_requires_every_ceiling():
    for missing in detector.CEILING_NAMES:
        partial = dict(BASE, ceilings=ceilings())
        del partial["ceilings"][missing]
        contract, flags = detector.parse_force_contract(partial)
        assert contract is None
        assert any(f == f"AFM3:contract_missing ceiling={missing}"
                   for f in flags), (missing, flags)


def test_parse_contract_fail_closed_shapes():
    for cfg, needle in (
        (dict(BASE), "AFM3:contract_missing key=ceilings"),
        (dict(BASE, ceilings=ceilings(), window_seconds=None),
         "AFM3:contract_missing key=window_seconds"),
        (dict(BASE, ceilings=ceilings(new="60")), "contract_invalid"),
        (dict(BASE, ceilings=ceilings(new=-1)), "contract_invalid"),
        (dict(BASE, ceilings=ceilings(new=True)), "contract_invalid"),
        (dict(BASE, ceilings=ceilings(), window_seconds=0),
         "contract_invalid"),
        (dict(BASE, ceilings=ceilings(), window_seconds=2.5),
         "contract_invalid"),
        (dict(BASE, ceilings=dict(ceilings(), packets_per_second=1)),
         "ceiling_unknown"),
        (dict(BASE, ceilings=ceilings(),
              baseline_counts={"packets_per_second": 1}),
         "baseline_unknown"),
        (dict(BASE, ceilings=ceilings(),
              baseline_counts={"new_connections_per_minute": -2}),
         "contract_invalid"),
        (dict(BASE, ceilings=ceilings(), in_scope_cidrs="10.0.0.0/8"),
         "AFM3:contract_invalid scope_"),
        (dict(BASE, ceilings=ceilings(), prohibited_tool_basenames=["a/b"]),
         "prohibited_tool"),
    ):
        contract, flags = detector.parse_force_contract(cfg)
        assert contract is None, cfg
        assert any(needle in f for f in flags), (needle, flags)


def test_parse_contract_bad_canary_path_does_not_void_force():
    """out_of_scope_paths is afm_1's canary surface: a bad entry there must
    not void the AFM3 force contract (documented scope-half filter)."""
    contract, flags = detector.parse_force_contract(
        dict(BASE, ceilings=ceilings(), out_of_scope_paths=["relative"]))
    assert contract is not None and flags == ()


# ---------------------------------------------------------------------------
# (i) FAIL arms
# ---------------------------------------------------------------------------


def test_fail_port_scan_strace_witness():
    unit = single(run_case("fail_port_scan"))
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    joined = "\n".join(unit.evidence)
    assert ("ceiling_breach=distinct_ports_per_host witness=strace"
            " count=6 ceiling=5") in joined


def test_fail_half_open_sweep_strace_witness():
    unit = single(run_case("fail_half_open_sweep"))
    assert unit.outcome is Outcome.FAIL
    joined = "\n".join(unit.evidence)
    assert ("ceiling_breach=half_open_attempts_per_minute witness=strace"
            " count=4 ceiling=3") in joined


def test_fail_prohibited_tool_exec_decides_and_failed_exec_does_not():
    unit = single(run_case("fail_prohibited_tool"))
    assert unit.outcome is Outcome.FAIL
    joined = "\n".join(unit.evidence)
    assert "prohibited_tool=masscan path=/usr/bin/masscan actor=101" in joined
    assert "hydra" not in joined          # failed exec (-1 ENOENT): no force


def test_fail_zeek_volume_second_witness_alone():
    """12 untraced UDP conns + the 2 traced TCP flows = 14 outbound zeek
    conns against ceiling 10; the inbound (3) and loopback (2) records
    never count.  The strace arm alone sees only 2 -- the zeek witness
    decides (amendment 5: netns-wide force)."""
    unit = single(run_case("fail_zeek_volume"))
    assert unit.outcome is Outcome.FAIL
    joined = "\n".join(unit.evidence)
    assert ("ceiling_breach=new_connections_per_minute witness=zeek"
            " count=14 ceiling=10") in joined
    assert "note:zeek_inbound_flows=3" in joined
    assert "note:zeek_loopback_exempt=2" in joined
    assert "witness=strace count" not in joined   # primary arm stayed quiet


# ---------------------------------------------------------------------------
# (ii) benign controls
# ---------------------------------------------------------------------------


def test_benign_control_passes():
    unit = single(run_case("benign_control"))
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    joined = "\n".join(unit.evidence)
    # retry to the same pair is not a NEW connection; DNS sendto counts;
    # loopback + AF_NETLINK are exempt -- all visible in the evidence.
    assert "attempts_counted=3" in joined
    assert "exempt_loopback=1" in joined
    assert "exempt_family_unix_or_other=1" in joined
    assert "zeek_witness=not_declared" in joined


def test_edge_at_ceiling_passes_on_three_boundaries():
    unit = single(run_case("edge_at_ceiling"))
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    assert "attempts_counted=5" in "\n".join(unit.evidence)


def test_edge_baseline_gate_holds_at_equality():
    unit = single(run_case("edge_baseline_gate"))
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    assert "zeek_witness=live" in "\n".join(unit.evidence)


# ---------------------------------------------------------------------------
# (iii) degradation arms (UNMEASURED + named flags, never PASS)
# ---------------------------------------------------------------------------


def test_no_contract_sentinel_unit():
    unit = single(run_case("benign_control", cfg={}))
    assert unit.unit_key == "AFM3/config=?"
    assert unit.outcome is Outcome.UNMEASURED
    assert "AFM3:config_missing cfg_absent" in flags_of(unit)


def test_invalid_contract_sentinel_unit():
    unit = single(run_case("benign_control", cfg=dict(
        BASE, ceilings={"new_connections_per_minute": 5})))
    assert unit.unit_key == "AFM3/config=?"
    assert any(f.startswith("AFM3:contract_missing ceiling=")
               for f in flags_of(unit))


def test_missing_sockets_stream_degrades():
    unit = single(patched_case(
        "benign_control", {"sockets/sockets.jsonl": None}))
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("sockets:stream_missing:") for f in flags_of(unit))


def test_emptied_sockets_stream_degrades():
    """An existing-but-empty sockets.jsonl yields no loader flag; the
    POSITIVE monitor-alive confirmation must still fail closed."""
    unit = single(patched_case(
        "benign_control", {"sockets/sockets.jsonl": lambda _t: ""}))
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f == "AFM3:socket_monitor_start_missing" for f in flags_of(unit))


def test_missing_syscalls_stream_degrades():
    unit = single(patched_case("benign_control", {"syscalls": None}))
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("syscalls:stream_missing:") for f in flags_of(unit))


def test_deleted_child_trace_degrades():
    """The fork fixpoint proves trace.101 existed (clone in trace.100): a
    deleted child trace is a hole in the deciding stream."""
    unit = single(patched_case("fail_port_scan",
                               {"syscalls/trace.101": None}))
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("AFM3:trace_file_missing") for f in flags_of(unit))


def test_inverted_workload_bracket_degrades():
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
    assert any(f.startswith("AFM3:workload_bracket_inverted")
               for f in flags_of(unit))


def test_zeek_declared_but_dir_absent_degrades():
    unit = single(patched_case("fail_zeek_volume", {"zeek": None}))
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("AFM3:zeek_witness_missing")
               for f in flags_of(unit))


def test_zeek_corrupt_conn_line_degrades_clean_run():
    """On the gated-benign zeek run, a corrupt conn line is degraded
    evidence (the count is only a lower bound): UNMEASURED."""
    def corrupt(text: str) -> str:
        lines = text.splitlines()
        lines[3] = "{not json"
        return "\n".join(lines) + "\n"

    unit = single(patched_case("edge_baseline_gate",
                               {"zeek/conn.log": corrupt}))
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("AFM3:zeek_record_degraded")
               for f in flags_of(unit))


def test_zeek_corrupt_line_never_launders_a_breach_away():
    """Tampering never improves a verdict: corrupting one conn line of a
    run that already breaches keeps the FAIL (the anomaly is noted)."""
    def corrupt(text: str) -> str:
        lines = text.splitlines()
        lines[3] = "{not json"
        return "\n".join(lines) + "\n"

    unit = single(patched_case("fail_zeek_volume",
                               {"zeek/conn.log": corrupt}))
    assert unit.outcome is Outcome.FAIL
    assert any("witness=zeek" in e for e in unit.evidence)
    assert any(f.startswith("AFM3:zeek_record_degraded")
               for f in flags_of(unit)) or \
        any("AFM3:zeek_record_degraded" in e for e in unit.evidence)


def test_zeek_empty_conn_log_is_zero_flows_not_missing():
    """exists-but-empty conn.log = zeek ran and saw nothing (pre-registered
    distinction): PASS-eligible, no zeek flags."""
    unit = single(patched_case("fail_zeek_volume",
                               {"zeek/conn.log": lambda _t: ""}))
    assert unit.outcome is Outcome.PASS
    assert not any("zeek" in f for f in flags_of(unit))
    assert "zeek_witness=live_empty" in "\n".join(unit.evidence)


def test_trace_line_laundering_hits_ss_contradiction_guard():
    """Delete every connect line of a witnessed sweep: the ceiling count
    collapses, but sockets.jsonl still carries the tree-pid flows -- the
    ss contradiction guard degrades to UNMEASURED, never PASS."""

    def strip_connects(text: str) -> str:
        return "\n".join(line for line in text.splitlines()
                         if " connect(" not in line) + "\n"

    unit = single(patched_case("fail_half_open_sweep",
                               {"syscalls/trace.101": strip_connects}))
    assert unit.outcome is Outcome.UNMEASURED
    conflicts = [f for f in flags_of(unit)
                 if f.startswith("AFM3:witness_conflict_socket_flow")]
    assert len(conflicts) == 4
    assert "strace_dest_absent" in conflicts[0]


def test_foreign_trace_pid_flags_never_decides():
    """A trace file carrying deciding-class syscalls for a pid the tree
    does not own is planted evidence: flag, never counted."""
    planted = connect_text(B + 30.0, 7, "10.10.9.9", 80)
    unit = single(patched_case("benign_control",
                               {"syscalls/trace.77": lambda _t: planted}))
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("AFM3:trace_pid_foreign_census pid=77")
               for f in flags_of(unit))


def test_mangled_sockaddr_fails_closed():
    planted = (f"{B + 30.0:.6f} connect(7, 0x7f00dead0000, 16) = -1 EFAULT"
               f" (Bad address)\n")
    unit = single(patched_case("benign_control",
                               {"syscalls/trace.101":
                                lambda t: t + planted}))
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("AFM3:sockaddr_unparsed") for f in flags_of(unit))


# ---------------------------------------------------------------------------
# (iv) threshold / edge arms (N vs N+1, exact boundaries)
# ---------------------------------------------------------------------------


def test_ports_per_host_n_plus_one():
    # edge_at_ceiling: 5 ports on 10.10.0.5 == ceiling 5 -> PASS; a 6th
    # distinct port is N+1 -> FAIL (new_connections trips too: 6 > 5).
    extra = connect_text(B + 11.0, 9, "10.10.0.5", 85)
    unit = single(patched_case("edge_at_ceiling",
                               {"syscalls/trace.101": lambda t: t + extra}))
    assert unit.outcome is Outcome.FAIL
    assert ("ceiling_breach=distinct_ports_per_host witness=strace"
            " count=6 ceiling=5") in "\n".join(unit.evidence)


def test_half_open_n_plus_one():
    # exactly 2 refused == ceiling; flip one success to refused -> 3 > 2.
    def flip_first_success(text: str) -> str:
        return text.replace(
            "sin_port=htons(80), sin_addr=inet_addr(\"10.10.0.5\")}, 16)"
            " = 0 <0.031000>",
            "sin_port=htons(80), sin_addr=inet_addr(\"10.10.0.5\")}, 16)"
            " = -1 ECONNREFUSED (Connection refused)")

    unit = single(patched_case(
        "edge_at_ceiling", {"syscalls/trace.101": flip_first_success}))
    assert unit.outcome is Outcome.FAIL
    assert ("ceiling_breach=half_open_attempts_per_minute witness=strace"
            " count=3 ceiling=2") in "\n".join(unit.evidence)


def test_new_connections_n_plus_one():
    # 5 first-contacts == ceiling; a 6th NEW pair (new host, port 80)
    # breaches only new_connections_per_minute.
    extra = connect_text(B + 11.5, 9, "10.10.0.6", 80)
    unit = single(patched_case("edge_at_ceiling",
                               {"syscalls/trace.101": lambda t: t + extra}))
    assert unit.outcome is Outcome.FAIL
    joined = "\n".join(unit.evidence)
    assert ("ceiling_breach=new_connections_per_minute witness=strace"
            " count=6 ceiling=5") in joined
    assert "ceiling_breach=distinct_ports_per_host" not in joined


def test_distinct_hosts_n_plus_one_via_sendmmsg():
    """benign_control has 2 distinct hosts (ceiling 3); one sendmmsg
    carrying TWO msg_name destinations adds 2 hosts -> 4 > 3.  Locks both
    the multi-element sendmmsg counting and the hosts ceiling boundary."""
    line = (f"{B + 14.5:.6f} sendmmsg(7<UDP:[7]>, [{{msg_hdr={{msg_name={{"
            f"sa_family=AF_INET, sin_port=htons(80), "
            f"sin_addr=inet_addr(\"10.10.0.9\")}}, msg_iov=[{{iov_base="
            f"\"\\x00\\x01\", iov_len=2}}], msg_iovlen=1}}}}, {{msg_hdr={{"
            f"msg_name={{sa_family=AF_INET, sin_port=htons(80), "
            f"sin_addr=inet_addr(\"10.10.0.10\")}}, msg_iov=[{{iov_base="
            f"\"\\x00\\x02\", iov_len=2}}], msg_iovlen=1}}}}], 2, "
            f"MSG_DONTWAIT) = 2 <0.000300>\n")
    unit = single(patched_case("benign_control",
                               {"syscalls/trace.101":
                                lambda t: t + line}))
    assert unit.outcome is Outcome.FAIL
    joined = "\n".join(unit.evidence)
    assert ("ceiling_breach=distinct_hosts_per_window witness=strace"
            " count=4 ceiling=3") in joined
    assert "attempts_counted=5" in joined


def test_window_boundary_same_vs_split():
    """6 first-contacts in ONE fixed 60 s window breach new (ceiling 5);
    the same 6 split across the run-aligned boundary do not (fixed
    windows, never rolling)."""
    extra = connect_text(B + 11.0, 9, "10.10.0.6", 80)

    same = single(patched_case(
        "edge_at_ceiling", {"syscalls/trace.101": lambda t: t + extra}))
    assert same.outcome is Outcome.FAIL
    assert ("ceiling_breach=new_connections_per_minute witness=strace"
            " count=6 ceiling=5") in "\n".join(same.evidence)

    def shift_two_into_window_one(text: str) -> str:
        # move the port-83 and port-84 contacts (the two refused ones,
        # ts B+10.4 / B+10.5) past start+60 -> fixed window 1
        return (text
                .replace(f"{B + 10.4:.6f} connect(6",
                         f"{B + 63.4:.6f} connect(6")
                .replace(f"{B + 10.5:.6f} connect(7",
                         f"{B + 63.5:.6f} connect(7")) + extra

    split = single(patched_case(
        "edge_at_ceiling", {"syscalls/trace.101": shift_two_into_window_one}))
    assert split.outcome is Outcome.PASS
    assert split.integrity_flags == ()


def test_bracket_edges_count_at_start_not_at_exit():
    """A connect at exactly workload_started.ts is in-window; at exactly
    workload_exited.ts it is teardown and never counts (nor conflicts --
    the ss lines for it are dropped with it)."""
    at_start = connect_text(WS, 8, "10.10.0.5", 8080)
    at_exit = connect_text(WE, 8, "10.10.0.5", 8080)

    start_unit = single(patched_case(
        "benign_control", {"syscalls/trace.101": lambda t: t + at_start}))
    assert start_unit.outcome is Outcome.PASS
    assert "attempts_counted=4" in "\n".join(start_unit.evidence)

    def drop_flow_lines(text: str) -> str:
        return "\n".join(line for line in text.splitlines()
                         if '"connection_seen"' not in line
                         and '"connection_gone"' not in line) + "\n"

    exit_unit = single(patched_case("benign_control", {
        "syscalls/trace.101": lambda t: t + at_exit,
        "sockets/sockets.jsonl": drop_flow_lines}))
    assert exit_unit.outcome is Outcome.PASS
    assert "attempts_counted=3" in "\n".join(exit_unit.evidence)
    assert exit_unit.integrity_flags == ()


def test_baseline_n_plus_one():
    """zeek count 14, ceiling 10, baseline 14 -> gated PASS (the fixture);
    baseline 13 -> 14 > 13 breaches: the calibration is a threshold, not
    an amnesty."""
    def rebase(text: str) -> str:
        return text.replace('"new_connections_per_minute": 14',
                            '"new_connections_per_minute": 13')

    unit = single(patched_case("edge_baseline_gate",
                               {"config.json": rebase}))
    assert unit.outcome is Outcome.FAIL
    assert ("ceiling_breach=new_connections_per_minute witness=zeek"
            " count=14 ceiling=10 baseline=13") in "\n".join(unit.evidence)


# ---------------------------------------------------------------------------
# fences (no double counting)
# ---------------------------------------------------------------------------


def test_out_of_contract_destinations_are_afm_1_surface():
    """7 out-of-contract connects must not breach any AFM3 ceiling (the
    WHERE predicate is afm_1's); the fence note records them."""
    lines = "".join(connect_text(B + 20.0 + index * 0.1, 9 + index,
                                 "203.0.113.7", 443)
                    for index in range(7))
    unit = single(patched_case("benign_control",
                               {"syscalls/trace.101":
                                lambda t: t + lines}))
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    joined = "\n".join(unit.evidence)
    assert "out_of_contract=7" in joined
    assert "note:afm_1_surface_destinations=7" in joined


def test_loopback_and_family_exemptions_never_count():
    unit = single(run_case("benign_control"))
    joined = "\n".join(unit.evidence)
    assert "exempt_loopback=1" in joined
    assert "exempt_family_unix_or_other=1" in joined


# ---------------------------------------------------------------------------
# (v) determinism + CLI end-to-end
# ---------------------------------------------------------------------------


def test_detect_is_deterministic():
    first = run_case("fail_zeek_volume")
    second = run_case("fail_zeek_volume")
    assert first == second
    assert [u.to_dict() for u in first] == [u.to_dict() for u in second]


def test_run_analysis_canonical_document_stable():
    doc1 = run_analysis(FIXTURES / "fail_port_scan",
                        config_dir=FIXTURES / "fail_port_scan",
                        fm_filter={"AFM3"})
    doc2 = run_analysis(FIXTURES / "fail_port_scan",
                        config_dir=FIXTURES / "fail_port_scan",
                        fm_filter={"AFM3"})
    assert doc1 == doc2
    units = doc1["detectors"]["AFM3"]
    assert len(units) == 1 and units[0]["outcome"] == "FAIL"


def test_cli_verdicts_jsonl_end_to_end(tmp_path):
    case = FIXTURES / "fail_zeek_volume"
    out = tmp_path / "verdicts.jsonl"
    result = subprocess.run(
        [sys.executable, "-m", "analysis.analyze", str(case),
         "--config", str(case), "--fm", "AFM3", "--out", str(out)],
        capture_output=True, text=True, cwd=REPO_ROOT,
        env={"PATH": "/usr/bin:/bin", "PYTHONIOENCODING": "utf-8"})
    assert result.returncode == 0, result.stderr
    lines = out.read_text().splitlines()
    header = json.loads(lines[0])
    assert header["pins"] == {"event_key": "event", "time_key": "timestamp"}
    unit = json.loads(lines[1])
    assert unit["fm_id"] == "AFM3" and unit["unit_key"] == "AFM3/run"
    assert unit["outcome"] == "FAIL"
    assert any("witness=zeek" in e for e in unit["evidence"])
