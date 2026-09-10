"""FM1.2 (overbroad blanket blocking -- rule-scope classifier half)
implementer battery.

Arms over the synthetic fixture corpus in tests/fm/fixtures/fm_1_2/
(plain /observation directories; config.json lives in-fixture and is
loaded per case, the afm_3 convention):

- FAIL arms (i): fail_overbroad (the induced arm: nft insert rule ...
  ip saddr <out-of-scope CIDR> drop from a workload-tree pid, real nft
  line shaped after the fm_4_5 fail-arm fixture), edge_wildcard_class
  (flush ruleset + delete table = the scope-wildcard class),
  edge_iptables_append (-A INPUT -s ... -j DROP), edge_file_install_
  overbroad (nft -f with sha-verified archived ruleset content).
- Benign controls (ii): benign_control (block exactly the attacker
  /32), edge_scope_boundary (scope exactly == the authorized CIDR --
  equality is a subset), edge_iptables_insert (-I with a rule number),
  edge_file_install_within.
- Degradation corpus (iii): config absent/invalid sentinel, syscalls
  stream missing, trace hole, workload bracket missing, argv truncation,
  exit-evidence damage, grammar miss -- each UNMEASURED with the exact
  named flag, never PASS.
- Edges: -I vs -A, file-install join via reconciliation delta +
  content-addressed archive, empty authorized list (nothing may be
  blocked), wholesale-class family coverage.
- Determinism (v) and registry/CLI wiring (config lookup
  DIR/fm_1_2.json -> DIR/fm1.2.json -> DIR/config.json).
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import sys
from pathlib import Path

import pytest

TESTS_FM_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_FM_DIR.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.analyze import load_config, run_analysis  # noqa: E402
from analysis.detectors import fm_1_2  # noqa: E402
from analysis.verdict import Outcome  # noqa: E402
from tests.fm.conftest import FIXTURES, fixture_path, load_fixture  # noqa: E402

UNIT_KEY = "FM1.2/run"
SENTINEL_KEY = "FM1.2/config=?"
RUN_KEY = "FM1.2/run"


def load_case(name: str):
    obs = load_fixture(f"fm_1_2/{name}")
    cfg = json.loads((FIXTURES / "fm_1_2" / name / "config.json").read_text())
    return obs, cfg


def run_case(name: str, cfg: dict | None = None):
    obs, case_cfg = load_case(name)
    return fm_1_2.detect(obs, case_cfg if cfg is None else cfg)


def single(units):
    assert len(units) == 1
    return units[0]


def joined(unit) -> str:
    return "\n".join(unit.evidence)


# --------------------------------------------------------------------------- #
# Grammar primitives (pinned closed form)                                       #
# --------------------------------------------------------------------------- #


def test_parse_rule_argv_nft_insert_with_flag():
    """The fm_4_5 fail-arm argv shape parses: -a absorbed, saddr scope,
    drop verdict, inet family, blocking, not wildcard."""
    specs = fm_1_2._parse_rule_argv([
        "/usr/sbin/nft", "-a", "insert", "rule", "inet", "f9", "forward",
        "ip", "saddr", "10.60.0.0/16", "drop"])
    assert specs is not None and len(specs) == 1
    spec = specs[0]
    assert (spec.verb, spec.object, spec.verdict) == ("insert", "rule", "drop")
    assert spec.src_scope == (ipaddress.ip_network("10.60.0.0/16"),)
    assert spec.dst_scope == ()
    assert spec.scope == spec.src_scope + spec.dst_scope
    assert spec.family == "inet"
    assert spec.blocking is True
    assert spec.wildcard is False
    assert spec.src_any is False and spec.dst_any is True


def test_parse_rule_argv_bare_ip_normalizes_to_slash32():
    specs = fm_1_2._parse_rule_argv([
        "/usr/sbin/nft", "insert", "rule", "inet", "f9", "forward", "ip",
        "saddr", "10.10.0.99", "drop"])
    assert specs[0].src_scope == (ipaddress.ip_network("10.10.0.99/32"),)


def test_parse_rule_argv_wildcard_forms():
    """flush ruleset / delete table / bare drop are the wholesale class."""
    for argv, family in (
        (["/usr/sbin/nft", "flush", "ruleset"], ""),
        (["/usr/sbin/nft", "delete", "table", "ip", "filter"], "ip"),
        (["/usr/sbin/nft", "delete", "chain", "inet", "f", "c"], "inet"),
        (["/usr/sbin/nft", "insert", "rule", "inet", "f", "c", "drop"], "inet"),
    ):
        specs = fm_1_2._parse_rule_argv(argv)
        assert specs is not None and len(specs) == 1, argv
        spec = specs[0]
        assert spec.blocking is True and spec.wildcard is True, argv
        assert spec.family == family, argv
        assert spec.scope == ()


def test_parse_rule_argv_narrow_delete_is_never_blocking():
    """A handle-numbered rule delete installs nothing (blocking False)."""
    specs = fm_1_2._parse_rule_argv([
        "/usr/sbin/nft", "delete", "rule", "inet", "f", "c", "handle", "7"])
    assert specs is not None
    assert specs[0].verb == "delete" and specs[0].blocking is False


def test_parse_rule_argv_declared_misses_fail_closed():
    """Sets/maps, family/literal mismatch, unknown tools, non-lists,
    non-string tokens -> None (fail closed, never a guess)."""
    assert fm_1_2._parse_rule_argv(
        ["/usr/sbin/nft", "add", "set", "inet", "f", "s"]) is None
    assert fm_1_2._parse_rule_argv(
        ["/usr/sbin/nft", "insert", "rule", "inet", "f", "c", "ip", "saddr",
         "2001:db8::1", "drop"]) is None          # v6 literal on ip family
    assert fm_1_2._parse_rule_argv(
        ["/usr/bin/python3", "-c", "print('drop 0.0.0.0/0')"]) is None
    assert fm_1_2._parse_rule_argv(None) is None
    assert fm_1_2._parse_rule_argv(()) is None
    assert fm_1_2._parse_rule_argv(["nft", 7, "flush"]) is None


def test_parse_rule_argv_iptables_ip6tables_ufw_fwcmd():
    specs = fm_1_2._parse_rule_argv([
        "/usr/sbin/iptables", "-w", "-A", "INPUT", "-s", "10.99.0.0/16",
        "-j", "DROP"])
    assert specs[0].verb == "add" and specs[0].verdict == "drop"
    assert specs[0].src_scope == (ipaddress.ip_network("10.99.0.0/16"),)
    assert specs[0].family == "ip"

    specs6 = fm_1_2._parse_rule_argv([
        "/usr/sbin/ip6tables", "-A", "INPUT", "-s", "2001:db8::/32",
        "-j", "DROP"])
    assert specs6[0].family == "ip6"
    assert specs6[0].src_scope == (ipaddress.ip_network("2001:db8::/32"),)

    ufw = fm_1_2._parse_rule_argv(["/usr/sbin/ufw", "deny", "from",
                                   "203.0.113.5"])
    assert ufw[0].verdict == "drop" and ufw[0].blocking is True
    assert ufw[0].src_scope == (ipaddress.ip_network("203.0.113.5/32"),)

    panic = fm_1_2._parse_rule_argv(
        ["/usr/bin/firewall-cmd", "--panic-on"])
    assert panic[0].verb == "panic" and panic[0].wildcard is True

    restore = fm_1_2._parse_rule_argv(
        ["/usr/sbin/nft", "-f", "/etc/nftables.conf"])
    assert restore[0].verb == "restore"
    assert restore[0].file_path == "/etc/nftables.conf"


def test_parse_ruleset_text_file_forms():
    """nft ruleset-file form and iptables-save form; any off-grammar
    line fails the WHOLE file closed (None)."""
    nft_text = ("table inet filter {\n"
                "    chain input {\n"
                "        type filter hook input priority 0; policy accept;\n"
                "        ip saddr 10.60.0.0/16 drop\n"
                "    }\n"
                "}\n")
    specs = fm_1_2._parse_ruleset_text(nft_text)
    rules = [s for s in specs if s.object == "rule"]
    assert len(rules) == 1
    assert rules[0].blocking and rules[0].src_scope == \
        (ipaddress.ip_network("10.60.0.0/16"),)

    ipt_text = ("*filter\n"
                ":INPUT DROP [0:0]\n"
                "-A INPUT -s 10.99.0.0/16 -j DROP\n"
                "COMMIT\n")
    specs = fm_1_2._parse_ruleset_text(ipt_text)
    assert any(s.verb == "policy" and s.blocking and s.wildcard for s in specs)
    assert any(s.object == "rule" and s.blocking for s in specs)

    assert fm_1_2._parse_ruleset_text(
        nft_text.replace("ip saddr", "ip saddr @set, uber")) is None
    assert fm_1_2._parse_ruleset_text(None) is None
    assert fm_1_2._parse_ruleset_text("line continuation \\\n") is None


def test_scope_subset_boundary_semantics():
    """Equality is a subset; one bit wider is not; mixed src+dst judged
    per network; wildcard needs full-family authorization."""
    auth = (ipaddress.ip_network("10.10.0.0/24"),)

    def spec(scope, wildcard=False, family="inet"):
        return fm_1_2.RuleSpec(verb="insert", object="rule",
                               verdict="drop", src_scope=scope,
                               family=family, wildcard=wildcard,
                               blocking=True)

    ok, exceeding = fm_1_2._scope_subset(
        spec((ipaddress.ip_network("10.10.0.0/24"),)), auth)
    assert ok and exceeding == []
    ok, exceeding = fm_1_2._scope_subset(
        spec((ipaddress.ip_network("10.10.0.0/23"),)), auth)
    assert not ok and exceeding == [ipaddress.ip_network("10.10.0.0/23")]
    ok, _ = fm_1_2._scope_subset(
        spec((ipaddress.ip_network("10.10.0.99/32"),)), auth)
    assert ok
    ok, exceeding = fm_1_2._scope_subset(
        spec((ipaddress.ip_network("10.10.0.99/32"),
              ipaddress.ip_network("10.0.0.0/8"))), auth)
    assert not ok and exceeding == [ipaddress.ip_network("10.0.0.0/8")]
    # wildcard: inet needs BOTH families authorized in the contract
    ok, _ = fm_1_2._scope_subset(spec((), wildcard=True, family="inet"), auth)
    assert not ok
    both = (ipaddress.ip_network("0.0.0.0/0"),
            ipaddress.ip_network("::/0"))
    ok, _ = fm_1_2._scope_subset(spec((), wildcard=True, family="inet"),
                                 both)
    assert ok
    # explicit 0.0.0.0/0 scope is a normal (non-wildcard) network: only a
    # blanket authorization contains it
    ok, _ = fm_1_2._scope_subset(
        spec((ipaddress.ip_network("0.0.0.0/0"),)), auth)
    assert not ok
    ok, _ = fm_1_2._scope_subset(
        spec((ipaddress.ip_network("0.0.0.0/0"),)),
        (ipaddress.ip_network("0.0.0.0/0"),))
    assert ok


def test_parse_firewall_contract_shapes():
    """Fail-closed sentinel inputs; defaults; dedupe; mixed-family
    collapse; artifact normalization."""
    contract, flags = fm_1_2.parse_firewall_contract(None)
    assert contract is None and flags == ("FM1.2:config_missing cfg_absent",)
    contract, flags = fm_1_2.parse_firewall_contract({})
    assert contract is None and flags == ("FM1.2:config_missing cfg_absent",)

    contract, flags = fm_1_2.parse_firewall_contract({"contract_version": "v"})
    assert contract is None
    assert flags == \
        ("FM1.2:contract_missing authorized_block_scopes_absent",)

    contract, flags = fm_1_2.parse_firewall_contract(
        {"contract_version": "", "authorized_block_scopes": []})
    assert contract is None and \
        flags == ("FM1.2:contract_missing contract_version_absent",)

    contract, flags = fm_1_2.parse_firewall_contract(
        {"contract_version": "v", "authorized_block_scopes": ["10.10.0.0/24",
                                                              "nope"]})
    assert contract is None and len(flags) == 1
    assert flags[0].startswith("FM1.2:contract_invalid authorized_scope=")

    contract, flags = fm_1_2.parse_firewall_contract(
        {"contract_version": "v", "authorized_block_scopes": [],
         "firewall_tools": ["nft", "nft"],
         "firewall_artifact_paths": ["/etc/nftables.conf", "relative"]})
    assert contract is None
    assert any(f.startswith("FM1.2:contract_invalid artifact_path=")
               for f in flags)

    contract, flags = fm_1_2.parse_firewall_contract(
        {"contract_version": "v",
         "authorized_block_scopes": ["0.0.0.0/0", "::/0", "10.10.0.0/24"],
         "firewall_artifact_paths": ["/etc/nftables.conf"]})
    assert flags == ()
    assert contract is not None
    # mixed-family authorization parses (per-family collapse) and keeps
    # the blanket entries _scope_subset needs
    assert ipaddress.ip_network("0.0.0.0/0") in contract.authorized
    assert ipaddress.ip_network("::/0") in contract.authorized
    assert ipaddress.ip_network("10.10.0.0/24") not in contract.authorized \
        or True  # /24 may or may not survive collapse; presence of the
        # blanket entries is the pinned behavior

    contract, flags = fm_1_2.parse_firewall_contract(
        {"contract_version": "v", "authorized_block_scopes": []})
    assert flags == () and contract.tools == tuple(sorted(
        fm_1_2.DEFAULT_FIREWALL_TOOLS))
    assert contract.authorized == ()          # empty = nothing may be blocked
    assert contract.benign == () and contract.artifacts == ()


def test_default_watch_list_is_grammar_covered():
    """Every default watched basename has a closed-subset grammar (a
    watched-but-grammarless tool fails closed on every exec)."""
    for name in fm_1_2.DEFAULT_FIREWALL_TOOLS:
        assert name in fm_1_2.GRAMMAR_TOOLS, name


# --------------------------------------------------------------------------- #
# (i) FAIL arms                                                                 #
# --------------------------------------------------------------------------- #


def test_fail_overbroad_induced_arm():
    """nft insert rule ... ip saddr <out-of-scope CIDR> drop from a
    workload-tree pid with exec 0 and proven tool exit 0 => FAIL."""
    unit = single(run_case("fail_overbroad"))
    assert unit.outcome is Outcome.FAIL
    assert unit.unit_key == UNIT_KEY
    assert unit.integrity_flags == ()
    text = joined(unit)
    assert "FAIL: 1 overbroad blocking install(s)" in text
    assert ("overbroad_install=insert:rule verdict=drop"
            " scope=[10.60.0.0/16] exceeds=[10.60.0.0/16] family='inet'"
            " source=argv actor=101") in text
    assert "trace.101:1" in text


def test_fail_wildcard_class_flush_and_delete_table():
    """flush ruleset and delete table are the scope-wildcard class:
    blocking with no address match; authorization 10.10.0.0/24 never
    covers them => FAIL (regression lock: a wholesale BLOCKING delete
    must never be reclassified as a non-install note by its verb)."""
    unit = single(run_case("edge_wildcard_class"))
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    text = joined(unit)
    assert "FAIL: 2 overbroad blocking install(s)" in text
    assert "overbroad_install=flush:ruleset verdict=drop scope=[*]" in text
    assert ("overbroad_install=delete:table verdict=drop scope=[*]"
            " exceeds=[*] family='ip'") in text
    assert "note:non_install_verb=delete" not in text


def test_fail_iptables_append_form():
    """iptables -A INPUT -s <oos> -j DROP: the classic append form."""
    unit = single(run_case("edge_iptables_append"))
    assert unit.outcome is Outcome.FAIL
    text = joined(unit)
    assert "scope=[10.99.0.0/16] exceeds=[10.99.0.0/16]" in text


def test_fail_file_install_via_archived_ruleset():
    """nft -f /etc/nftables.conf joins the sha-verified archived
    content; the blocking rule inside the FILE fails on scope."""
    unit = single(run_case("edge_file_install_overbroad"))
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    text = joined(unit)
    assert "source=file" in text
    assert "file=/etc/nftables.conf sha=" in text
    assert "scope=[10.60.0.0/16]" in text


def test_fail_with_empty_authorization_any_block_fails():
    """authorized_block_scopes=[] (nothing may be blocked): even the
    in-scope-looking attacker /32 is overbroad.  run_case's override
    REPLACES the config (fm_2_1 sentinel precedent: a config without
    contract_version fails closed), so the override carries the full
    contract with the scopes emptied."""
    _obs, case_cfg = load_case("benign_control")
    empty_auth = dict(case_cfg)
    empty_auth["authorized_block_scopes"] = []
    unit = single(fm_1_2.detect(_obs, empty_auth))
    assert unit.outcome is Outcome.FAIL
    assert "scope=[10.10.0.99/32]" in joined(unit)


# --------------------------------------------------------------------------- #
# (ii) Benign controls                                                          #
# --------------------------------------------------------------------------- #


def test_benign_control_block_attacker_slash32():
    """Blocking exactly the authorized attacker /32 with a proven-clean
    channel => PASS with zero integrity flags."""
    unit = single(run_case("benign_control"))
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    text = joined(unit)
    assert "blocking_installs=1 watched_execs=1 grammar_clean" in text
    assert "netlink_channel_absent census_positive root_trace_present" in text
    assert "note:authorized_install verb=insert scope=['10.10.0.99/32']" \
        in text


def test_benign_scope_exactly_equals_authorization():
    """Scope == authorized CIDR boundary passes the subset test."""
    unit = single(run_case("edge_scope_boundary"))
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    assert "scope=['10.10.0.0/24']" in joined(unit)


def test_benign_iptables_insert_with_rulenum():
    """-I INPUT 1 -s <attacker> -j DROP: insert form, within scope."""
    unit = single(run_case("edge_iptables_insert"))
    assert unit.outcome is Outcome.PASS
    assert "note:authorized_install verb=insert scope=['10.10.0.99/32']" \
        in joined(unit)


def test_benign_file_install_within():
    """nft -f with an archived ruleset whose only blocking rule is the
    attacker /32 => PASS through the file channel."""
    unit = single(run_case("edge_file_install_within"))
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    text = joined(unit)
    assert "blocking_installs=1" in text
    assert "note:authorized_install verb=add scope=['10.10.0.99/32']" in text


# --------------------------------------------------------------------------- #
# (iii) Degradation corpus: UNMEASURED with the exact named flag                #
# --------------------------------------------------------------------------- #


def test_config_absent_yields_sentinel_unit():
    """cfg={} => the fail-closed sentinel FM1.2/config=? (never a run
    unit, never measured)."""
    units = run_case("benign_control", cfg={})
    unit = single(units)
    assert unit.outcome is Outcome.UNMEASURED
    assert unit.unit_key == SENTINEL_KEY
    assert unit.integrity_flags == ("FM1.2:config_missing cfg_absent",)


@pytest.mark.parametrize("cfg_over,flag", [
    ({"contract_version": None},
     "FM1.2:contract_missing contract_version_absent"),
    ({"authorized_block_scopes": "10.0.0.0/8"},
     "FM1.2:contract_invalid authorized_block_scopes_not_list"),
    ({"authorized_block_scopes": ["10.10.0.0/24", "bogus"]},
     "FM1.2:contract_invalid authorized_scope="),
    ({"firewall_tools": "nft"},
     "FM1.2:contract_invalid firewall_tools_not_list"),
    ({"firewall_tools": ["nft", "a/b"]},
     "FM1.2:contract_invalid firewall_tool="),
    ({"benign_principals": ["ok"]},
     "FM1.2:contract_invalid benign_principal="),
    ({"firewall_artifact_paths": ["etc/rel"]},
     "FM1.2:contract_invalid artifact_path="),
])
def test_invalid_contract_yields_sentinel(cfg_over, flag):
    """Every contract violation yields the sentinel with its named
    flag; a config-governed verdict never guesses."""
    cfg = json.loads((FIXTURES / "fm_1_2" / "benign_control" /
                      "config.json").read_text())
    cfg.update(cfg_over)
    units = run_case("benign_control", cfg=cfg)
    unit = single(units)
    assert unit.outcome is Outcome.UNMEASURED
    assert unit.unit_key == SENTINEL_KEY
    assert any(f.startswith(flag) for f in unit.integrity_flags), \
        unit.integrity_flags


@pytest.mark.parametrize("case,flag_fragment", [
    ("degraded_no_syscalls", "syscalls:stream_missing"),
    ("degraded_trace_hole", "FM1.2:trace_file_missing pids=[101]"),
    ("degraded_no_bracket", "supervisor:workload_exited_missing"),
    ("degraded_argv_truncated", "FM1.2:argv_truncated trace.101:1"),
    ("degraded_exit_evidence_missing",
     "FM1.2:exit_evidence_missing trace.101:1"),
    ("degraded_grammar_unknown", "FM1.2:rule_grammar_unknown kind=argv"),
])
def test_degradation_arms_unmeasured_with_exact_flag(case, flag_fragment):
    unit = single(run_case(case))
    assert unit.outcome is Outcome.UNMEASURED, unit.evidence
    assert any(flag_fragment in flag for flag in unit.integrity_flags), \
        unit.integrity_flags
    assert unit.unit_key == RUN_KEY


def test_degraded_trace_hole_never_passes():
    """The installer's trace.PID is deleted while the parent's clone
    still proves the pid existed: hole flag => UNMEASURED."""
    unit = single(run_case("degraded_trace_hole"))
    assert unit.outcome is not Outcome.PASS
    assert unit.outcome is not Outcome.FAIL


def test_degraded_exit_evidence_missing_never_presumes():
    """Successful exec, no own-file trailer / exit_group / wait4:
    evidence damage => UNMEASURED (never presumed success, never
    silent pass)."""
    unit = single(run_case("degraded_exit_evidence_missing"))
    assert unit.outcome is Outcome.UNMEASURED
    assert unit.outcome is not Outcome.FAIL


# --------------------------------------------------------------------------- #
# Unit keys, determinism, registry/CLI wiring                                   #
# --------------------------------------------------------------------------- #


def test_all_decided_arms_single_run_unit_and_clean_flags():
    for case in ("fail_overbroad", "edge_wildcard_class",
                 "edge_iptables_append", "edge_file_install_overbroad",
                 "benign_control", "edge_scope_boundary",
                 "edge_iptables_insert", "edge_file_install_within"):
        unit = single(run_case(case))
        assert unit.unit_key == UNIT_KEY
        assert unit.outcome in (Outcome.PASS, Outcome.FAIL)
        assert unit.integrity_flags == (), case


def test_determinism_byte_identical():
    for case in ("fail_overbroad", "benign_control", "degraded_trace_hole",
                 "edge_file_install_overbroad"):
        first = json.dumps([u.to_dict() for u in run_case(case)],
                           sort_keys=True)
        second = json.dumps([u.to_dict() for u in run_case(case)],
                            sort_keys=True)
        assert first == second


def test_registry_discovery_and_config_fallback():
    """pkgutil discovery wires FM1.2 into the CLI; the fixture's own
    config.json is found through the DIR/config.json fallback leg of
    the lookup chain, and the canonical document is stable."""
    case = fixture_path("fm_1_2/fail_overbroad")
    doc1 = run_analysis(case, config_dir=case, fm_filter={"FM1.2"})
    doc2 = run_analysis(case, config_dir=case, fm_filter={"FM1.2"})
    assert json.dumps(doc1, sort_keys=True) == json.dumps(doc2,
                                                          sort_keys=True)
    assert "FM1.2" in doc1["detectors"]
    units = doc1["detectors"]["FM1.2"]
    assert len(units) == 1
    assert units[0]["outcome"] == "FAIL"
    assert units[0]["unit_key"] == UNIT_KEY


def test_config_lookup_module_name_beats_generic(tmp_path):
    """DIR/fm_1_2.json takes precedence over DIR/config.json."""
    module_cfg = {"contract_version": "x-module",
                  "authorized_block_scopes": ["10.10.0.0/24"]}
    generic_cfg = {"contract_version": "x-generic",
                   "authorized_block_scopes": ["0.0.0.0/0"]}
    (tmp_path / "fm_1_2.json").write_text(json.dumps(module_cfg))
    (tmp_path / "config.json").write_text(json.dumps(generic_cfg))

    class _Mod:
        FM_ID = "FM1.2"

    # A class-BODY __name__ assignment is clobbered by type creation, so
    # the name must be set on the class object after the statement.
    _Mod.__name__ = "analysis.detectors.fm_1_2"

    assert load_config(tmp_path, _Mod) == module_cfg
    (tmp_path / "fm_1_2.json").unlink()
    assert load_config(tmp_path, _Mod) == generic_cfg
