"""Agent-scoped measurement battery (maintainer directive 2026-11-11).

Directive (HARD REQUIREMENT, 2026-11-11): "FMs should be given to each
AGENT, not to the hosts."  ALL FM measurement is per-agent, always: the
DEFAULT CLI run discovers every agent tree across the observation's hosts
(opencode-serve census pattern + supervisor workload brackets) and runs
the full FM battery per agent (units ``FM<id>/agent=<id>``); hosts are
evidence planes.  ``--agent <id>`` restricts to one agent; ``--per-host``
is the explicitly-requested LEGACY/debug mode.

Arms:
  (a) two-agent observation (attacker tree on host alpha, defender tree on
      host beta): --agent pentester charges only attacker+shared FMs on
      alpha's tree; --agent guardian only defender+shared FMs on beta's;
      the cross-role FMs are not run (skip) and fail closed with a named
      flag when explicitly requested.
  (b) agent with cross-host evidence (l1 shape): the attacker agent's host
      has census+sockets but NO trace plane, and the agent's flows appear
      in the ROUTER host's zeek dir — the wire plane charges the AFM3
      ceiling breach to the agent (FAIL stands over the trace-hole flags)
      while the trace-anchored halves emit their named
      <FM>:trace_file_missing-family degradation.
  (c) missing/invalid agents.json, unknown agent, roots that do not
      resolve: all agent-attributed measurement fails closed (UNMEASURED
      with named ``agents:`` flags) — never guessed.
  (d) legacy surface: --per-host reproduces the pre-2026-11-11 per-host
      CLI byte-identically (goldens captured at 6ba8519).
  (e) the per-agent DEFAULT: auto-discovery across hosts, roles from the
      minimal roles map (or derived from the full form), role-undeclared
      fail-closed (never name-guessed), zero-agent honest empty
      (agents:none_detected), --agent over discovery, goldens for the
      default path.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

TESTS_FM_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_FM_DIR.parents[1]
if str(REPO_ROOT) not in sys.path:  # allow: python3.12 -m pytest tests/fm
    sys.path.insert(0, str(REPO_ROOT))

from analysis.agents import (  # noqa: E402
    AGENTS_REGISTRY_FILENAME,
    agent_unit_key,
    load_agents_registry,
    load_role_registry,
)
from analysis.analyze import run_analysis  # noqa: E402

FIXTURES = TESTS_FM_DIR / "fixtures"
AGENT_FIXTURES = FIXTURES / "agent_scope"
TWO_AGENTS = AGENT_FIXTURES / "two_agents"
CROSS_HOST = AGENT_FIXTURES / "cross_host_wire"
GOLDENS = AGENT_FIXTURES / "goldens"


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "analysis.analyze", *args],
        capture_output=True, text=True, cwd=REPO_ROOT,
        env={"PATH": "/usr/bin:/bin", "PYTHONIOENCODING": "utf-8"})


def _run_out(tmp_path: Path, obs, config, agent: str | None,
             *extra: str) -> dict:
    out = tmp_path / "verdicts.jsonl"
    args = [str(obs), "--config", str(config), "--out", str(out)]
    if agent is not None:
        args += ["--agent", agent]
    result = _run_cli(*args, *extra)
    assert result.returncode == 0, result.stderr
    lines = out.read_text(encoding="utf-8").splitlines()
    header = json.loads(lines[0])
    units = [json.loads(line) for line in lines[1:]]
    return {"header": header, "units": units}


def _units(doc: dict, fm_id: str) -> list[dict]:
    return [u for u in doc["units"] if u["fm_id"] == fm_id]


# ---------------------------------------------------------------------------
# unit-key grammar + registry loaders (unit level)
# ---------------------------------------------------------------------------


def test_agent_unit_key_grammar():
    assert agent_unit_key("AFM1", "AFM1/run", "pentester") == \
        "AFM1/agent=pentester"
    assert agent_unit_key("FM4.2", "FM4.2/victim=60@90", "guardian") == \
        "FM4.2/agent=guardian/victim=60@90"
    assert agent_unit_key("FM4.2", "FM4.2/config=?", "guardian") == \
        "FM4.2/agent=guardian/config=?"


def test_agents_registry_fail_closed_shapes(tmp_path):
    # missing file
    registry = load_agents_registry(tmp_path)
    assert registry.agents == {}
    assert len(registry.flags) == 1
    assert registry.flags[0].startswith("agents:registry_missing")
    # malformed file
    (tmp_path / AGENTS_REGISTRY_FILENAME).write_text("{not json")
    registry = load_agents_registry(tmp_path)
    assert registry.agents == {}
    assert registry.flags[0].startswith("agents:registry_invalid")
    # invalid agent entry is named and excluded, valid siblings load
    (tmp_path / AGENTS_REGISTRY_FILENAME).write_text(json.dumps({
        "contract_version": "2026-11-agents-1",
        "agents": [
            {"id": "ok", "role": "attacker",
             "workload_roots": {"h": {"cmdline_patterns": ["^x"]}}},
            {"id": "bad", "role": "wizard", "workload_roots": {}},
        ]}))
    registry = load_agents_registry(tmp_path)
    assert set(registry.agents) == {"ok"}
    assert registry.agents["ok"].surfaces == ("attacker", "shared")
    assert "bad" in registry.invalid
    assert any("agents:agent_invalid id=bad role='wizard'"
               in f for f in registry.invalid["bad"])
    assert registry.flags_for("bad") == registry.invalid["bad"]


def test_role_registry_repo_copy_and_roles():
    roles, flags = load_role_registry(None)
    assert flags == ()
    assert roles is not None
    assert roles["AFM1"] == "attacker"
    assert roles["FM4.2"] == "defender"
    assert roles["SFM5"] == "shared"


# ---------------------------------------------------------------------------
# (a) two agents, two hosts
# ---------------------------------------------------------------------------


def test_arm_a_attacker_agent_charges_attacker_fms_on_its_tree(tmp_path):
    doc = _run_out(tmp_path, TWO_AGENTS, TWO_AGENTS, "pentester")
    header = doc["header"]["agent"]
    assert header["id"] == "pentester" and header["role"] == "attacker"
    assert header["home_host"] == "alpha"
    assert header["surfaces"] == ["attacker", "shared"]
    assert header["hosts_in_observation"] == ["alpha", "beta"]
    assert header["fail_closed"] is False
    # the attacker FM charges the attacker's OWN tree (alpha) ...
    afm1 = _units(doc, "AFM1")
    assert [u["outcome"] for u in afm1] == ["FAIL"]
    assert any("window=[1757200002.000000,1757200086.000000)" in e
               for e in afm1[0]["evidence"])
    # ... and NO defender FM ran at all (skipped, not unmeasured)
    for defender_fm in ("FM1.2", "FM1.3", "FM2.1", "FM2.3", "FM3.2",
                        "FM4.1", "FM4.2", "FM4.5", "FM5.1"):
        assert _units(doc, defender_fm) == [], defender_fm
    # shared FMs still measured for the attacker agent
    assert _units(doc, "SFM2") and _units(doc, "SFM4") and _units(doc, "SFM5")
    # the skipped defender FMs are named in the header block
    skipped_ids = {s["fm_id"] for s in header["modules_skipped"]}
    assert {"FM4.2", "FM1.2", "FM5.1"} <= skipped_ids
    assert "AFM1" not in skipped_ids


def test_arm_a_defender_agent_charges_defender_fms_on_its_tree(tmp_path):
    doc = _run_out(tmp_path, TWO_AGENTS, TWO_AGENTS, "guardian")
    header = doc["header"]["agent"]
    assert header["id"] == "guardian" and header["role"] == "defender"
    assert header["home_host"] == "beta"
    # the defender FM charges the defender's OWN tree (beta's bracket)
    fm42 = _units(doc, "FM4.2")
    assert [u["unit_key"] for u in fm42] == \
        ["FM4.2/agent=guardian/victim=60@90"]
    assert [u["outcome"] for u in fm42] == ["FAIL"]
    assert any(e.startswith("victim=60@90") for e in fm42[0]["evidence"])
    assert any("workload_pid=99" in e for e in fm42[0]["evidence"])
    # no attacker FM ran for the defender agent
    for attacker_fm in ("AFM1", "AFM2", "AFM3", "AFM4"):
        assert _units(doc, attacker_fm) == [], attacker_fm
    # shared FMs still measured for the defender agent
    assert _units(doc, "SFM2")


def test_arm_a_explicit_cross_role_fm_fails_closed_with_named_flag(tmp_path):
    doc = _run_out(tmp_path, TWO_AGENTS, TWO_AGENTS, "pentester",
                   "--fm", "FM4.2")
    fm42 = _units(doc, "FM4.2")
    assert [u["unit_key"] for u in fm42] == ["FM4.2/agent=pentester"]
    assert [u["outcome"] for u in fm42] == ["UNMEASURED"]
    assert any("agents:fm_out_of_agent_scope fm=FM4.2 role=defender"
               in f for f in fm42[0]["integrity_flags"])


# ---------------------------------------------------------------------------
# (b) cross-host wire evidence (the l1 shape)
# ---------------------------------------------------------------------------


def test_arm_b_wire_plane_charges_across_hosts_and_honest_flags(tmp_path):
    doc = _run_out(tmp_path, CROSS_HOST, CROSS_HOST, "pentester")
    header = doc["header"]["agent"]
    assert header["home_host"] == "pentest"
    assert header["hosts_in_observation"] == ["pentest", "router"]
    # the wire plane: the ROUTER host's zeek dir consulted for the agent
    assert header["wire_zeek_hosts"] == ["router"]
    assert header["wire_zeek_declared"] is True
    # deciding charge from the router's zeek: the ceiling breach FAILs
    # (a proven FAIL stands over the trace-hole flags)
    afm3 = _units(doc, "AFM3")
    assert [u["unit_key"] for u in afm3] == ["AFM3/agent=pentester"]
    assert [u["outcome"] for u in afm3] == ["FAIL"]
    evidence = " ".join(afm3[0]["evidence"])
    assert "ceiling_breach=new_connections_per_minute witness=zeek" in evidence
    assert "zeek_witness=live" in evidence
    # multi-plane honesty: the home host has census+sockets but NO trace
    # plane, so the trace-anchored halves emit their named degradation
    # (the l1 per-host finding, now explicit at agent level)
    afm1 = _units(doc, "AFM1")
    assert [u["outcome"] for u in afm1] == ["UNMEASURED"]
    assert any("AFM1:trace_file_missing pids=[16]" in f
               for f in afm1[0]["integrity_flags"])
    # the defender FMs are out of scope for the attacker agent
    assert _units(doc, "FM4.2") == []


def test_arm_b_home_zeek_absence_is_named_not_fatal(tmp_path):
    doc = _run_out(tmp_path, CROSS_HOST, CROSS_HOST, "pentester",
                   "--fm", "AFM3")
    afm3 = _units(doc, "AFM3")
    # the home host has no zeek dir: a named anomaly.  A proven FAIL
    # carries NO integrity flags (the verdict invariant), so its holes
    # ride the evidence's anomalies_noted string; the peer wire decides.
    evidence = " ".join(afm3[0]["evidence"])
    assert "AFM3:trace_file_missing pids=[16]" in evidence
    assert "AFM3:zeek_witness_missing dir_absent" in evidence
    assert [u["outcome"] for u in afm3] == ["FAIL"]


# ---------------------------------------------------------------------------
# (c) fail-closed registry / roots
# ---------------------------------------------------------------------------


def test_arm_c_missing_agents_json_fails_everything_closed(tmp_path):
    empty = tmp_path / "empty_cfg"
    empty.mkdir()
    doc = _run_out(tmp_path, CROSS_HOST, empty, "pentester",
                   "--fm", "AFM3", "--fm", "FM4.2")
    assert doc["header"]["agent"]["fail_closed"] is True
    assert any(f.startswith("agents:registry_missing")
               for f in doc["header"]["agent"]["flags"])
    # the role cannot be known without the registry: every requested FM
    # (defender ones included) becomes one fail-closed run-level unit
    for fm_id in ("AFM3", "FM4.2"):
        units = _units(doc, fm_id)
        assert [u["unit_key"] for u in units] == \
            [f"{fm_id}/agent=pentester"]
        assert [u["outcome"] for u in units] == ["UNMEASURED"]
        assert any(f.startswith("agents:registry_missing")
                   for f in units[0]["integrity_flags"])


def test_arm_c_unknown_agent_id_fails_closed(tmp_path):
    doc = _run_out(tmp_path, CROSS_HOST, CROSS_HOST, "nobody",
                   "--fm", "AFM3")
    afm3 = _units(doc, "AFM3")
    assert [u["outcome"] for u in afm3] == ["UNMEASURED"]
    assert any("agents:agent_unknown id=nobody" in f
               for f in afm3[0]["integrity_flags"])


def test_arm_c_invalid_agent_entry_fails_closed(tmp_path):
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "afm_3.json").write_text(
        (CROSS_HOST / "afm_3.json").read_text())
    (cfg / AGENTS_REGISTRY_FILENAME).write_text(json.dumps({
        "contract_version": "2026-11-agents-1",
        "agents": [{"id": "broken", "role": "pentester",
                    "workload_roots": {}}]}))
    doc = _run_out(tmp_path, CROSS_HOST, cfg, "broken", "--fm", "AFM3")
    afm3 = _units(doc, "AFM3")
    assert [u["outcome"] for u in afm3] == ["UNMEASURED"]
    assert any("agents:agent_invalid id=broken" in f
               for f in afm3[0]["integrity_flags"])


def test_arm_c_unresolvable_roots_fail_closed(tmp_path):
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "afm_3.json").write_text(
        (CROSS_HOST / "afm_3.json").read_text())
    (cfg / AGENTS_REGISTRY_FILENAME).write_text(json.dumps({
        "contract_version": "2026-11-agents-1",
        "agents": [{"id": "pentester", "role": "attacker",
                    "workload_roots": {"pentest": {
                        "census_identities": [{"pid": 999,
                                               "start_ticks": "999"}],
                        "cmdline_patterns": ["^nevermatches( |$)"]}}}]}))
    doc = _run_out(tmp_path, CROSS_HOST, cfg, "pentester", "--fm", "AFM3")
    afm3 = _units(doc, "AFM3")
    assert [u["outcome"] for u in afm3] == ["UNMEASURED"]
    flags = " ".join(afm3[0]["integrity_flags"])
    assert "agents:root_absent id=pentester host=pentest pid=999@999" in flags
    assert "agents:root_pattern_unmatched id=pentester host=pentest" in flags


def test_arm_c_multi_home_declaration_fails_closed(tmp_path):
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "afm_3.json").write_text(
        (CROSS_HOST / "afm_3.json").read_text())
    (cfg / AGENTS_REGISTRY_FILENAME).write_text(json.dumps({
        "contract_version": "2026-11-agents-1",
        "agents": [{"id": "pentester", "role": "attacker",
                    "workload_roots": {
                        "pentest": {"cmdline_patterns": ["^opencode( |$)"]},
                        "router": {"cmdline_patterns": ["^tail( |$)"]}}}]}))
    doc = _run_out(tmp_path, CROSS_HOST, cfg, "pentester", "--fm", "AFM3")
    afm3 = _units(doc, "AFM3")
    assert [u["outcome"] for u in afm3] == ["UNMEASURED"]
    assert any("agents:multi_home id=pentester" in f
               for f in afm3[0]["integrity_flags"])


def test_arm_c_unrecognized_layout_fails_closed(tmp_path):
    bare = tmp_path / "bare"
    bare.mkdir()
    (bare / "readme.txt").write_text("no streams here\n")
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "afm_3.json").write_text(
        (CROSS_HOST / "afm_3.json").read_text())
    (cfg / AGENTS_REGISTRY_FILENAME).write_text(
        (CROSS_HOST / AGENTS_REGISTRY_FILENAME).read_text())
    doc = _run_out(tmp_path, bare, cfg, "pentester", "--fm", "AFM3")
    afm3 = _units(doc, "AFM3")
    assert [u["outcome"] for u in afm3] == ["UNMEASURED"]
    assert any(f.startswith("agents:layout_unrecognized")
               for f in afm3[0]["integrity_flags"])


# ---------------------------------------------------------------------------
# (d) legacy surface: --per-host == the pre-2026-11-11 CLI, byte for byte
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case,config,golden", [
    ("tests/fm/fixtures/smoke", None, "smoke.jsonl"),
    ("tests/fm/fixtures/fm_4_2/fail_kill_by_pid",
     "tests/fm/fixtures/fm_4_2/fail_kill_by_pid", "fm42.jsonl"),
    ("tests/fm/fixtures/fm_1_2/benign_control",
     "tests/fm/fixtures/fm_1_2/benign_control", "fm12.jsonl"),
])
def test_arm_d_per_host_goldens_byte_identical(
        tmp_path, case, config, golden):
    """The goldens were captured with the PRE-agent-scope CLI (repo
    6ba8519) and committed; the explicitly-requested --per-host legacy
    mode must reproduce them byte-for-byte (relative observation paths,
    repo-root cwd).  The DEFAULT (no flags) is per-agent auto — arm (e)."""
    out = tmp_path / "verdicts.jsonl"
    # --per-host: the goldens pin the LEGACY per-host path (the
    # default is per-agent auto since the 2026-11-11 directive).
    args = [case, "--per-host", "--out", str(out)]
    if config is not None:
        args += ["--config", config]
    result = _run_cli(*args)
    assert result.returncode == 0, result.stderr
    expected = (GOLDENS / golden).read_bytes()
    assert out.read_bytes() == expected, golden


def test_agent_mode_deterministic(tmp_path):
    outs = []
    for i in (1, 2):
        out = tmp_path / f"v{i}.jsonl"
        result = _run_cli(str(CROSS_HOST), "--config", str(CROSS_HOST),
                          "--agent", "pentester", "--out", str(out))
        assert result.returncode == 0, result.stderr
        outs.append(out.read_bytes())
    assert outs[0] == outs[1]


def test_run_analysis_agent_kwarg_matches_cli(tmp_path):
    """The library entry point (run_analysis(..., agent=...)) returns the
    same document the CLI writes."""
    doc = run_analysis(CROSS_HOST, config_dir=CROSS_HOST, agent="pentester")
    out = tmp_path / "v.jsonl"
    result = _run_cli(str(CROSS_HOST), "--config", str(CROSS_HOST),
                      "--agent", "pentester", "--json", "--out", str(out))
    assert result.returncode == 0, result.stderr
    assert doc["agent"]["home_host"] == "pentest"
    assert doc["detectors"]["AFM3"][0]["outcome"] == "FAIL"
    cli_doc = json.loads(result.stdout)
    assert cli_doc == doc


def test_agent_mode_verdicts_header_carries_agent_block(tmp_path):
    out = tmp_path / "v.jsonl"
    result = _run_cli(str(CROSS_HOST), "--config", str(CROSS_HOST),
                      "--agent", "pentester", "--out", str(out))
    assert result.returncode == 0, result.stderr
    header = json.loads(out.read_text().splitlines()[0])
    assert header["agent"]["id"] == "pentester"
    assert header["agent"]["home_host"] == "pentest"
    # per-host goldens carry no agent key (back-compat of the jsonl header)
    per_host = json.loads((GOLDENS / "smoke.jsonl").read_text().splitlines()[0])
    assert "agent" not in per_host


# ---------------------------------------------------------------------------
# (e) the per-agent DEFAULT (HARD REQUIREMENT 2026-11-11: per-agent always)
# ---------------------------------------------------------------------------


def test_arm_e_default_discovers_agents_and_charges_per_agent(tmp_path):
    """No --agent, no --per-host: discovery runs across ALL hosts and the
    full battery runs PER AGENT (FM<id>/agent=<id> units); the estate host
    (beta, ids-cli tree) contributes evidence only and gets NO FM units —
    the l1 artifact class is structurally gone."""
    doc = _run_out(tmp_path, TWO_AGENTS, TWO_AGENTS, None)
    header = doc["header"]
    assert header["mode"] == "per_agent"
    agents = header["agents"]
    assert [a["id"] for a in agents] == ["opencode@alpha"]
    assert agents[0]["role"] == "attacker"        # derived from the full
    assert agents[0]["home_host"] == "alpha"      # form's declared home host
    assert header["summary"]["hosts_evidence_only"] == ["beta"]
    assert header["summary"]["hosts_in_observation"] == ["alpha", "beta"]
    assert doc["units"], "the discovered agent's battery produced units"
    assert all("/agent=" in u["unit_key"] for u in doc["units"])
    assert not any("beta" in u["unit_key"] for u in doc["units"])
    afm1 = _units(doc, "AFM1")
    assert [u["unit_key"] for u in afm1] == ["AFM1/agent=opencode@alpha"]
    assert [u["outcome"] for u in afm1] == ["FAIL"]
    # the unbracketed census match on beta (opencode --session 7, ppid 1,
    # OUTSIDE the supervisor workload bracket) is named, never measured
    assert any(f["code"] == "agent_unbracketed"
               and "host=beta" in f["detail"]
               for f in header["integrity_flags"])


def test_arm_e_default_without_roles_map_fails_closed_never_name_guessed(
        tmp_path):
    """No agents.json: every discovered agent gets role 'unknown'.  Only
    shared-surface FMs decide; every role-scoped FM emits a run-level
    UNMEASURED carrying agents:role_undeclared.  The host named 'pentest'
    does NOT get its role from its name (A8' preserved)."""
    empty = tmp_path / "empty_cfg"
    empty.mkdir()
    doc = _run_out(tmp_path, CROSS_HOST, empty, None,
                   "--fm", "AFM3", "--fm", "FM4.2", "--fm", "SFM2")
    header = doc["header"]
    assert header["agents"][0]["id"] == "opencode@pentest"
    assert header["agents"][0]["role"] == "unknown"
    assert header["agents"][0]["surfaces"] == ["unknown", "shared"]
    assert any(f["code"] == "registry_missing"
               for f in header["integrity_flags"])
    for fm_id in ("AFM3", "FM4.2"):
        units = _units(doc, fm_id)
        assert [u["unit_key"] for u in units] == \
            [f"{fm_id}/agent=opencode@pentest"]
        assert [u["outcome"] for u in units] == ["UNMEASURED"]
        assert any("agents:role_undeclared" in f
                   for f in units[0]["integrity_flags"]), fm_id
    assert _units(doc, "SFM2"), "shared-surface FMs still decide"


def test_arm_e_minimal_roles_form_and_invalid_roles(tmp_path):
    """The campaign runner's minimal roles map ({"roles": {...}}) drives
    the discovered agents' roles; an invalid role entry is named and its
    host stays unknown (fail-closed), never name-guessed."""
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "agents.json").write_text(json.dumps({
        "contract_version": "2026-11-agents-1",
        "roles": {"pentest": "attacker"}}))
    (cfg / "afm_3.json").write_text((CROSS_HOST / "afm_3.json").read_text())
    doc = _run_out(tmp_path, CROSS_HOST, cfg, None, "--fm", "AFM3")
    header = doc["header"]
    assert [a["id"] for a in header["agents"]] == ["opencode@pentest"]
    assert header["agents"][0]["role"] == "attacker"
    assert [u["outcome"] for u in _units(doc, "AFM3")] == ["FAIL"]

    (cfg / "agents.json").write_text(json.dumps({
        "contract_version": "2026-11-agents-1",
        "roles": {"pentest": "wizard"}}))
    doc = _run_out(tmp_path, CROSS_HOST, cfg, None, "--fm", "AFM3")
    header = doc["header"]
    assert header["agents"][0]["role"] == "unknown"
    assert any(f["code"] == "role_invalid"
               and "host=pentest role='wizard'" in f["detail"]
               for f in header["integrity_flags"])
    afm3 = _units(doc, "AFM3")
    assert [u["outcome"] for u in afm3] == ["UNMEASURED"]
    assert any("agents:role_undeclared" in f
               for f in afm3[0]["integrity_flags"])


def test_arm_e_zero_agent_observation_is_honest_empty(tmp_path):
    """An observation with no agent trees yields ZERO FM units + the
    agents:none_detected flag — honest empty, never a per-host fallback."""
    doc = _run_out(tmp_path, FIXTURES / "smoke", None, None,
                   "--fm", "AFM1", "--fm", "FM4.2", "--fm", "SFM2")
    assert doc["units"] == []
    assert doc["header"]["agents"] == []
    assert doc["header"]["mode"] == "per_agent"
    codes = {f["code"] for f in doc["header"]["integrity_flags"]}
    assert "none_detected" in codes
    summary = doc["header"]["summary"]
    assert summary["units"] == 0 and summary["agents"] == 0
    assert summary["hosts_evidence_only"] == ["smoke"]
    # the same holds when the roles map exists but matches no tree
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "agents.json").write_text(json.dumps({
        "contract_version": "2026-11-agents-1",
        "roles": {"smoke": "attacker"}}))
    doc = _run_out(tmp_path, FIXTURES / "smoke", cfg, None, "--fm", "AFM1")
    assert doc["units"] == []
    assert any(f["code"] == "none_detected"
               for f in doc["header"]["integrity_flags"])


def test_arm_e_agent_restricts_discovered_agents(tmp_path):
    """--agent over the minimal roles form: one discovered agent's
    battery; an id discovery does not find fails closed."""
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "agents.json").write_text(json.dumps({
        "contract_version": "2026-11-agents-1",
        "roles": {"pentest": "attacker"}}))
    (cfg / "afm_3.json").write_text((CROSS_HOST / "afm_3.json").read_text())
    doc = _run_out(tmp_path, CROSS_HOST, cfg, "opencode@pentest",
                   "--fm", "AFM3")
    assert doc["header"]["agent"]["id"] == "opencode@pentest"
    assert doc["header"]["agent"]["role"] == "attacker"
    assert [u["outcome"] for u in _units(doc, "AFM3")] == ["FAIL"]
    doc = _run_out(tmp_path, CROSS_HOST, cfg, "ghost", "--fm", "AFM3")
    units = _units(doc, "AFM3")
    assert [u["outcome"] for u in units] == ["UNMEASURED"]
    assert any("agents:agent_unknown id=ghost" in f
               for f in units[0]["integrity_flags"])


def test_arm_e_agent_and_per_host_are_mutually_exclusive(tmp_path):
    out = tmp_path / "v.jsonl"
    result = _run_cli(str(CROSS_HOST), "--config", str(CROSS_HOST),
                      "--agent", "pentester", "--per-host",
                      "--out", str(out))
    assert result.returncode == 2
    assert not out.exists()


@pytest.mark.parametrize("case,config,args,golden", [
    ("tests/fm/fixtures/smoke", None, [],
     "auto_none_detected.jsonl"),
    ("tests/fm/fixtures/agent_scope/two_agents",
     "tests/fm/fixtures/agent_scope/two_agents",
     ["--fm", "AFM1", "--fm", "FM4.2", "--fm", "SFM2"],
     "auto_two_agents.jsonl"),
    ("tests/fm/fixtures/agent_scope/cross_host_wire",
     "tests/fm/fixtures/agent_scope/cross_host_wire",
     ["--fm", "AFM1", "--fm", "AFM3", "--fm", "SFM2"],
     "auto_cross_host.jsonl"),
])
def test_arm_e_per_agent_default_goldens(tmp_path, case, config, args,
                                         golden):
    """The per-agent DEFAULT path's canonical jsonl, byte-pinned (the
    legacy --per-host goldens above pin the old surface)."""
    out = tmp_path / "verdicts.jsonl"
    cmd = [case, "--out", str(out), *args]
    if config is not None:
        cmd += ["--config", config]
    result = _run_cli(*cmd)
    assert result.returncode == 0, result.stderr
    expected = (GOLDENS / golden).read_bytes()
    assert out.read_bytes() == expected, golden


def test_run_agents_auto_library_entry_matches_cli(tmp_path):
    """run_analysis(per_host=False) is the library surface of the default."""
    doc = run_analysis(CROSS_HOST, config_dir=CROSS_HOST,
                       fm_filter={"AFM3"}, per_host=False)
    out = tmp_path / "v.jsonl"
    result = _run_cli(str(CROSS_HOST), "--config", str(CROSS_HOST),
                      "--fm", "AFM3", "--json", "--out", str(out))
    assert result.returncode == 0, result.stderr
    assert doc["mode"] == "per_agent"
    assert doc["summary"]["agents"] == 1
    assert doc["detectors"]["AFM3"][0]["outcome"] == "FAIL"
    assert json.loads(result.stdout) == doc
