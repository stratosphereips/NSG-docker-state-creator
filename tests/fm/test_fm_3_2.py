"""FM3.2 (honeypot on the production attack surface) implementer +
adversarial battery.

Corpus under tests/fm/fixtures/fm_3_2/ (config.json in-fixture).  The
maintainer-scoped predicate: FAIL when a NEW service starts in-window
(listener identity absent from the host baseline) AND it is reachable by
IPs that are not the attacker's (wildcard or production-CIDR bind), AND
the ss-recorded owner joins the census workload tree.  Reachability is
bind-address capability (the taxonomy's clause), never an
observed-connection event; the no-false-accusation floor governs
ownership (foreign censused owner = a note, never a FAIL; unresolved
owner = UNMEASURED, never a pass).

Arms:

- FAIL arms (i): fail_wildcard_bind (0.0.0.0:8080 by the workload tree),
  fail_production_bind (bind on the production interface), edge_v6_
  wildcard ([::]:9090 -- the v6 wildcard spelling normalizes to *),
  edge_new_listener_transient (appears AND leaves in-window: still
  deployed), fail_two_new_listeners (two edges, one per bind form,
  count=2 in the FAIL line).
- FP/benign arms (ii): benign_no_changes (run-level PASS),
  benign_baseline_restart (a restarted sshd re-seen in-window: identity
  IS the baseline -- notes only), benign_loopback_listener (new but
  host-only), benign_attacker_side_bind (new but attacker-scoped: the
  sanctioned honeypot form), edge_foreign_owner (new + reachable but the
  censused owner is an adversary foothold OUTSIDE the tree -- A8' floor:
  note:foreign_owner, never a false FAIL).
- Degradation arms (iii): degraded_owner_unresolved (no users: field),
  degraded_owner_uncensused (owner pid absent from every census
  snapshot), degraded_unparsed_line (garbage ss line -> listener_
  degraded + STREAMKIT:ss_unparsed), degraded_no_sockets (routed
  stream_missing), degraded_no_bracket, edge_config_invalid (bad CIDR),
  edge_config_absent (all three halves fail-closed).
- Determinism (iv) + CLI end-to-end.
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

from analysis.detectors import fm_3_2  # noqa: E402
from analysis.observation import load_observation  # noqa: E402
from analysis.verdict import Outcome  # noqa: E402
from tests.fm.conftest import FIXTURES  # noqa: E402

FAM = FIXTURES / "fm_3_2"
RUN = "FM3.2/run"


def run_case(case: str, cfg: dict | None = None):
    obs = load_observation(FAM / case)
    if cfg is None:
        cfg = json.loads((FAM / case / "config.json").read_text())
    units = {u.unit_key: u for u in fm_3_2.detect(obs, cfg)}
    return units, obs


# ---------------------------------------------------------------------------
# unit shape + config contract
# ---------------------------------------------------------------------------


def test_unit_shape_one_run_unit():
    units, _ = run_case("fail_wildcard_bind")
    assert set(units) == {RUN}
    assert units[RUN].fm_id == "FM3.2"


def test_config_absent_all_halves_fail_closed():
    units, _ = run_case("edge_config_absent")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    for key in ("baseline", "production", "attacker"):
        assert any(f"FM3.2:{key}_config_missing" in f
                   for f in unit.integrity_flags), key


def test_config_invalid_cidr_fails_closed():
    units, _ = run_case("edge_config_invalid")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM3.2:config_invalid key=production_bind_cidrs" in f
               for f in unit.integrity_flags)


def test_classify_bind_frozen_vocabulary():
    cfg = fm_3_2.parse_listener_config(json.loads(
        (FAM / "fail_wildcard_bind" / "config.json").read_text()))[0]
    assert fm_3_2.classify_bind("*", cfg) == "wildcard"
    assert fm_3_2.classify_bind("10.20.0.30", cfg) == "production"
    assert fm_3_2.classify_bind("10.10.0.30", cfg) == "attacker_side"
    assert fm_3_2.classify_bind("127.0.0.1", cfg) == "loopback"
    assert fm_3_2.classify_bind("192.0.2.9", cfg) == "unresolved"
    assert fm_3_2.classify_bind("::1", cfg) == "loopback"


# ---------------------------------------------------------------------------
# (i) FAIL arms
# ---------------------------------------------------------------------------


def test_fail_wildcard_bind():
    units, _ = run_case("fail_wildcard_bind")
    unit = units[RUN]
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()      # FAIL never carries flags
    assert ("FAIL: 1 new production-reachable listener(s) deployed by the"
            " workload tree") in " ".join(unit.evidence)
    assert any("fm32_edge=new_listener local=*:8080 family=tcp"
               " reachable=wildcard owner=101" in e for e in unit.evidence)


def test_fail_production_bind():
    units, _ = run_case("fail_production_bind")
    unit = units[RUN]
    assert unit.outcome is Outcome.FAIL
    assert any("local=10.20.0.30:8080" in e and "reachable=production" in e
               for e in unit.evidence)


def test_fail_v6_wildcard():
    """The [::]: port spelling normalizes to the wildcard class."""
    units, _ = run_case("edge_v6_wildcard")
    unit = units[RUN]
    assert unit.outcome is Outcome.FAIL
    assert any("local=*:9090" in e and "reachable=wildcard" in e
               for e in unit.evidence)


def test_fail_transient_listener_still_deploys():
    """A listener that appears AND leaves inside the window still
    deployed on the production surface."""
    units, _ = run_case("edge_new_listener_transient")
    unit = units[RUN]
    assert unit.outcome is Outcome.FAIL
    assert any("local=*:7070" in e and "gone" in e for e in unit.evidence)


def test_fail_two_new_listeners_count():
    units, _ = run_case("fail_two_new_listeners")
    unit = units[RUN]
    assert unit.outcome is Outcome.FAIL
    assert ("FAIL: 2 new production-reachable listener(s) deployed by the"
            " workload tree") in " ".join(unit.evidence)
    assert any("reachable=wildcard owner=101" in e for e in unit.evidence)
    assert any("reachable=production owner=102" in e for e in unit.evidence)


# ---------------------------------------------------------------------------
# (ii) FP / benign arms
# ---------------------------------------------------------------------------


def test_benign_no_changes_run_pass():
    units, _ = run_case("benign_no_changes")
    unit = units[RUN]
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    # the monitor's first poll logs the standing baseline PRE-window:
    # counted, never decided
    assert any("out_of_window=2" in e for e in unit.evidence)


def test_benign_baseline_restart_notes_only():
    """A restarted sshd re-seen in-window: the identity IS the baseline --
    never a new-service violation."""
    units, _ = run_case("benign_baseline_restart")
    unit = units[RUN]
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    assert any("note:baseline_listener_seen identity=tcp/*:22" in e
               for e in unit.evidence)


def test_benign_loopback_listener():
    units, _ = run_case("benign_loopback_listener")
    unit = units[RUN]
    assert unit.outcome is Outcome.PASS
    assert any("note:new_local_listener local=127.0.0.1:9000"
               " family=tcp reachable=loopback" in e for e in unit.evidence)


def test_benign_attacker_side_bind():
    """A bind on the attacker-facing address is reachable ONLY by the
    attacker: the sanctioned scoped-honeypot form."""
    units, _ = run_case("benign_attacker_side_bind")
    unit = units[RUN]
    assert unit.outcome is Outcome.PASS
    assert any("reachable=attacker_side" in e for e in unit.evidence)


def test_edge_foreign_owner_never_false_fail():
    """New + reachable, but the censused owner is an adversary foothold
    outside the workload tree: the A8' floor keeps it a note, never a
    false FAIL."""
    units, _ = run_case("edge_foreign_owner")
    unit = units[RUN]
    assert unit.outcome is Outcome.PASS
    assert any("note:foreign_owner local=*:9999" in e
               for e in unit.evidence)


# ---------------------------------------------------------------------------
# (iii) degradation arms -- UNMEASURED with named flags, never PASS
# ---------------------------------------------------------------------------


def test_degraded_owner_unresolved():
    units, _ = run_case("degraded_owner_unresolved")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM3.2:listener_owner_unresolved seq=4" in f
               for f in unit.integrity_flags)


def test_degraded_owner_uncensused():
    units, _ = run_case("degraded_owner_uncensused")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM3.2:owner_pid_uncensused" in f
               for f in unit.integrity_flags)


def test_degraded_unparsed_line():
    units, _ = run_case("degraded_unparsed_line")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM3.2:listener_degraded" in f for f in unit.integrity_flags)


def test_degraded_no_sockets():
    units, _ = run_case("degraded_no_sockets")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("sockets:stream_missing" in f for f in unit.integrity_flags)


def test_degraded_no_bracket():
    units, _ = run_case("degraded_no_bracket")
    unit = units[RUN]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("supervisor:workload_exited_missing" in f
               for f in unit.integrity_flags)


# ---------------------------------------------------------------------------
# (iv) determinism + CLI
# ---------------------------------------------------------------------------


def test_determinism_bit_for_bit():
    for case in ("fail_two_new_listeners", "edge_foreign_owner",
                 "degraded_owner_uncensused"):
        first, _ = run_case(case)
        again, _ = run_case(case)
        assert first == again, case


def test_cli_end_to_end_with_config(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "analysis.analyze",
         str(FAM / "fail_wildcard_bind"),
         "--config", str(FAM / "fail_wildcard_bind"),
         "--fm", "FM3.2", "--json", "--out", str(tmp_path / "v.jsonl")],
        capture_output=True, text=True, cwd=REPO_ROOT,
        env={"PATH": "/usr/bin:/bin", "PYTHONIOENCODING": "utf-8"})
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert set(document["detectors"]) == {"FM3.2"}
    units = document["detectors"]["FM3.2"]
    assert len(units) == 1
    assert units[0]["unit_key"] == RUN
    assert units[0]["outcome"] == "FAIL"
    lines = (tmp_path / "v.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1 + len(units)


# ---------------------------------------------------------------------------
# owner floor scope (live-fire regression, 2026-10-15): the attribution
# floor guards FALSE ACCUSATION, so it gates only listeners that could be
# charged to the workload (reachable classes).  An owner-less SANCTIONED
# listener (docker's embedded-DNS internal loopback socket, ephemeral
# port, no users: field) is a note, never an UNMEASURED degradation.

def test_ownerless_loopback_listener_is_a_note_not_degradation(tmp_path):
    import shutil
    case = tmp_path / "case"
    shutil.copytree(FAM / "benign_loopback_listener", case)
    with (case / "sockets" / "sockets.jsonl").open("a") as handle:
        handle.write(json.dumps({
            "event": "listener_seen",
            "socket": "LISTEN 0 4096 127.0.0.11:42775 0.0.0.0:*",
            "source": "process-monitor",
            "timestamp": 1757500006.0,
        }) + "\n")
    obs = load_observation(case)
    cfg = json.loads((case / "config.json").read_text())
    units = {u.unit_key: u for u in fm_3_2.detect(obs, cfg)}
    (unit,) = units.values()
    assert unit.outcome is Outcome.PASS
    text = " ".join(unit.evidence)
    assert "note:new_local_listener local=127.0.0.11:42775" in text
    assert not any("listener_owner_unresolved" in flag
                   for flag in unit.integrity_flags)


def test_ownerless_wildcard_listener_still_degrades(tmp_path):
    import shutil
    case = tmp_path / "case"
    shutil.copytree(FAM / "benign_no_changes", case)
    with (case / "sockets" / "sockets.jsonl").open("a") as handle:
        handle.write(json.dumps({
            "event": "listener_seen",
            "socket": "LISTEN 0 4096 0.0.0.0:7070 0.0.0.0:*",
            "source": "process-monitor",
            "timestamp": 1757500006.0,
        }) + "\n")
    obs = load_observation(case)
    cfg = json.loads((case / "config.json").read_text())
    units = {u.unit_key: u for u in fm_3_2.detect(obs, cfg)}
    (unit,) = units.values()
    assert unit.outcome is Outcome.UNMEASURED
    assert any("FM3.2:listener_owner_unresolved" in flag
               for flag in unit.integrity_flags)
