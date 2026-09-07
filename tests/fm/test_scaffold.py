"""Scaffold plumbing smoke: loader -> detector -> CLI over a synthetic fixture.

This file belongs to the scaffold owner; FM detector tests live in
tests/fm/test_fm_<id>.py owned by each implementer.  Fixture cases are
documented in tests/fm/fixtures/README.md.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

TESTS_FM_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_FM_DIR.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.observation import load_observation  # noqa: E402
from analysis.records import ExecveLine, ExitTrailer, ProcRecord  # noqa: E402
from analysis.verdict import Outcome, UnitResult  # noqa: E402

FIXTURES = TESTS_FM_DIR / "fixtures"
SMOKE_FIXTURE = FIXTURES / "smoke"


def load_fixture(name: str):
    return load_observation(FIXTURES / name)


# ---------------------------------------------------------------------------
# loader
# ---------------------------------------------------------------------------


def test_fixture_loads_every_stream_typed():
    obs = load_fixture("smoke")
    assert obs.root == SMOKE_FIXTURE
    assert obs.flags == ()  # clean synthetic run: no degradation anywhere
    assert [r.event for r in obs.supervisor][:6] == [
        "sensor_started", "sensor_started", "sensor_started",
        "sensor_started", "sensor_started", "workload_started",
    ]
    workload = obs.supervisor[5]
    assert workload.pid == 99
    assert workload.argv == ("bash", "-lc", "touch /tmp/nsg-observer-demo; sleep 3")
    assert workload.effective_argv is not None
    assert workload.effective_argv[0] == "strace"

    seen = [r for r in obs.processes if r.event == "process_seen"]
    assert {(r.pid, r.start_ticks) for r in seen} >= {
        (1, "42"), (99, "500"), (100, "501"), (101, "502")}
    gone = [r for r in obs.processes if r.event == "process_gone"]
    assert (101, "502") in {(r.pid, r.start_ticks) for r in gone}
    bash_seen = next(r for r in seen if r.pid == 100)
    assert bash_seen.ppid == 99 and bash_seen.uid == ("0", "0", "0", "0")
    assert isinstance(bash_seen, ProcRecord)

    assert len(obs.filesystem_events) == 3
    assert obs.filesystem_events[0].operations == ("create",)
    assert [m.event for m in obs.filesystem_monitor] == [
        "monitor_started", "monitor_exited"]

    baseline = obs.reconciliation[0]
    assert baseline.event == "baseline_complete"
    assert baseline.files == 120 and baseline.interval_seconds == 30.0
    added = next(r for r in obs.reconciliation if r.event == "file_added")
    assert added.state is not None
    assert added.state.checksum == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    kinds = {r.kind for r in obs.sockets}
    assert {"listener_seen", "connection_seen"} <= kinds

    assert obs.bcc_status[0].event == "cgroup_filter_ready"
    assert obs.bcc_status[1].tool == "execsnoop-bpfcc"

    assert obs.health is not None
    assert obs.health.state == "stopped"
    assert ("workload", 99, False, 0) in obs.health.services

    assert obs.bash_history[0].epoch == 1757000005.0
    assert obs.bash_history[0].command == "touch /tmp/nsg-observer-demo"


def test_strace_parsing_typed_hierarchy():
    obs = load_fixture("smoke")
    execs = [r for r in obs.strace if isinstance(r, ExecveLine)]
    assert len(execs) == 2
    touch_exec = next(e for e in execs if e.file_pid == 101)
    assert touch_exec.argv == ("/usr/bin/touch", "/tmp/nsg-observer-demo")
    assert touch_exec.truncated is False
    assert touch_exec.result_raw == "0"
    # global ordering: bash exec (ts ...002.1, pid 100) sorts before touch
    assert isinstance(obs.strace[0], ExecveLine)
    assert obs.strace[0].file_pid == 100
    exits = [r for r in obs.strace if isinstance(r, ExitTrailer)]
    assert sorted(e.code for e in exits) == [0, 0]
    waits = [r for r in obs.strace if getattr(r, "name", "") == "wait4"]
    assert waits[0].duration_s == pytest.approx(3.2001)


def test_envelope_fixture_first_lines_load():
    obs = load_fixture("envelope")
    assert len(obs.supervisor) >= 5
    assert obs.supervisor[0].ts is not None


# ---------------------------------------------------------------------------
# detector + invariant
# ---------------------------------------------------------------------------


def test_smoke_detector_all_pass_over_clean_fixture():
    from analysis.detectors import smoke as smoke_detector

    obs = load_fixture("smoke")
    units = smoke_detector.detect(obs, {})
    assert len(units) == 9
    assert {u.outcome for u in units} == {Outcome.PASS}
    assert all(u.integrity_flags == () for u in units)
    assert units[0].unit_key == "SMOKE/stream=bcc_status"


def test_unit_result_integrity_invariant_enforced():
    good = UnitResult(fm_id="FM0", unit_key="FM0/x",
                      outcome=Outcome.UNMEASURED,
                      integrity_flags=("supervisor:stream_missing:path=...",))
    assert good.outcome is Outcome.UNMEASURED
    with pytest.raises(ValueError):
        UnitResult(fm_id="FM0", unit_key="FM0/x", outcome=Outcome.PASS,
                   integrity_flags=("supervisor:stream_missing:path=...",))
    with pytest.raises(ValueError):
        UnitResult(fm_id="FM0", unit_key="FM0/x", outcome="MAYBE")
    assert UnitResult.from_dict(good.to_dict()) == good


def test_missing_stream_degrades_to_unmeasured_never_pass(tmp_path):
    from analysis.detectors import smoke as smoke_detector

    degraded = tmp_path / "observation"
    shutil.copytree(SMOKE_FIXTURE, degraded)
    (degraded / "processes.jsonl").unlink()
    obs = load_observation(degraded)
    flag_strings = {str(f) for f in obs.flags}
    assert any(s.startswith("processes:stream_missing:")
               for s in flag_strings), flag_strings
    units = {u.unit_key: u for u in smoke_detector.detect(obs, {})}
    unit = units["SMOKE/stream=processes"]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("stream_missing" in f for f in unit.integrity_flags)


def test_corrupt_jsonl_line_flagged_not_fatal(tmp_path):
    degraded = tmp_path / "observation"
    shutil.copytree(SMOKE_FIXTURE, degraded)
    path = degraded / "supervisor.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    lines.insert(3, "{not json at all\n")
    path.write_text("".join(lines), encoding="utf-8")
    obs = load_observation(degraded)
    assert any(f.code == "jsonl_corrupt" and f.stream == "supervisor"
               for f in obs.flags)
    assert any(r.event == "workload_exited" for r in obs.supervisor)


def test_integrity_floor_fires_on_sensor_death_during_run(tmp_path):
    """A sensor_exited ordered before workload_exited must surface (FM2.3 floor)."""
    degraded = tmp_path / "observation"
    shutil.copytree(SMOKE_FIXTURE, degraded)
    path = degraded / "supervisor.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    # inject a mid-run sensor death just before workload_exited
    death = json.dumps({"event": "sensor_exited", "source": "supervisor",
                        "timestamp": 1757000009.0, "name": "process-monitor",
                        "returncode": -9}, sort_keys=True)
    lines.insert(-5, death + "\n")
    path.write_text("".join(lines), encoding="utf-8")
    obs = load_observation(degraded)
    assert any(f.code == "sensor_exited_before_workload_exited"
               and f.stream == "supervisor" for f in obs.flags)


# ---------------------------------------------------------------------------
# CLI end-to-end (subprocess, real pkgutil discovery)
# ---------------------------------------------------------------------------


def _run_cli(*args: str):
    return subprocess.run(
        [sys.executable, "-m", "analysis.analyze", *args],
        capture_output=True, text=True, cwd=REPO_ROOT,
        env={"PATH": "/usr/bin:/bin", "PYTHONIOENCODING": "utf-8"},
    )


def test_cli_json_end_to_end_and_deterministic(tmp_path):
    out1 = _run_cli(str(SMOKE_FIXTURE), "--json", "--fm", "SMOKE",
                    "--out", str(tmp_path / "v1.jsonl"))
    assert out1.returncode == 0, out1.stderr
    doc = json.loads(out1.stdout)
    assert doc["observation_dir"] == str(SMOKE_FIXTURE)
    assert doc["pins"] == {"event_key": "event", "time_key": "timestamp"}
    assert doc["integrity_flags"] == []
    units = doc["detectors"]["SMOKE"]
    assert len(units) == 9
    assert {u["outcome"] for u in units} == {"PASS"}

    out2 = _run_cli(str(SMOKE_FIXTURE), "--json", "--fm", "SMOKE",
                    "--out", str(tmp_path / "v2.jsonl"))
    assert out1.stdout == out2.stdout  # byte-identical canonical output

    jsonl = (tmp_path / "v1.jsonl").read_text(encoding="utf-8").splitlines()
    header = json.loads(jsonl[0])
    assert header["observation_dir"] == str(SMOKE_FIXTURE)
    assert len(jsonl) == 1 + 9
    assert json.loads(jsonl[1])["unit_key"] == "SMOKE/stream=bcc_status"


def test_cli_table_output_and_exit_codes(tmp_path):
    # --fm SMOKE isolates the table-render assertions to the smoke detector:
    # auto-discovery picks up every analysis.detectors module, so a bare run
    # also renders whatever FM detectors have landed (their units over this
    # minimal fixture are legitimately UNMEASURED victim=none units).
    result = _run_cli(str(SMOKE_FIXTURE), "--fm", "SMOKE",
                      "--out", str(tmp_path / "v.jsonl"))
    assert result.returncode == 0
    assert "SMOKE/stream=supervisor" in result.stdout
    assert "PASS=9" in result.stdout
    usage = _run_cli(str(tmp_path / "does-not-exist"))
    assert usage.returncode == 2


def test_run_analysis_in_process(tmp_path):
    from analysis.analyze import run_analysis

    doc = run_analysis(SMOKE_FIXTURE, config_dir=None)
    # detector auto-discovery: SMOKE must be present; FM detectors that have
    # landed in analysis/detectors/ legitimately appear alongside it.
    assert "SMOKE" in doc["detectors"]
    degraded = tmp_path / "observation"
    shutil.copytree(SMOKE_FIXTURE, degraded)
    shutil.rmtree(degraded / "syscalls")
    doc2 = run_analysis(degraded)
    syscalls_unit = next(u for u in doc2["detectors"]["SMOKE"]
                         if u["unit_key"] == "SMOKE/stream=syscalls")
    assert syscalls_unit["outcome"] == "UNMEASURED"
    assert any("syscalls:stream_missing" in f
               for f in syscalls_unit["integrity_flags"])


def test_jsonlog_writer_roundtrips_through_loader(tmp_path, monkeypatch):
    """The reconstructed observer/lib/jsonlog.py produces exactly the envelope
    the loader pins (regression guard for the lib/ reconstruction)."""
    lib = str(REPO_ROOT / "observer" / "lib")
    monkeypatch.syspath_prepend(lib)
    monkeypatch.setenv("OBS_OUTPUT_DIR", str(tmp_path))
    import jsonlog

    log = jsonlog.JsonLog("supervisor.jsonl", "supervisor")
    log.write("workload_started", pid=7, requested_argv=["sleep", "1"])
    log.write("workload_exited", pid=7, returncode=0)

    obs = load_observation(tmp_path)
    # only the supervisor stream exists here: its parse must be flag-free
    # (the other streams are legitimately flagged stream_missing)
    assert [f for f in obs.flags if f.stream == "supervisor"] == []
    assert [r.event for r in obs.supervisor] == [
        "workload_started", "workload_exited"]
    assert obs.supervisor[0].pid == 7
    assert obs.supervisor[0].ts is not None
